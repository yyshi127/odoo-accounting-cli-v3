"""Linux Unix-domain HTTP transport for the trusted Pi broker.

This module intentionally knows nothing about the broker's session resolver,
approval authority, historical release router, or receipt verifier.  A trusted
dispatcher is injected and must perform those checks.  The transport only:

* accepts the seven fixed POST routes over one filesystem UDS;
* obtains route/protocol and authority bindings from five fixed HTTP headers;
* admits one configured client UID using Linux ``SO_PEERCRED``; and
* adds the broker-authority response header only when the dispatcher confirms
  that it authenticated the request.

The dispatcher receives an absolute monotonic deadline.  It must enforce that
deadline in its own Odoo/child-process calls; this transport never pretends it
can safely cancel an accounting operation that may already have started.

Systemd service/socket units, the external authenticated-session resolver, and
receipt cryptographic verification are deliberately outside this transport.
"""

from __future__ import annotations

import errno
import http.client
import json
import math
import os
import re
import socket
import socketserver
import stat
import struct
import sys
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import PurePosixPath
from time import monotonic
from typing import Any, Callable, Final

from .monotonic_deadline import monotonic_deadline_scope


BROKER_AUTHORITY_HEADER: Final = "X-Odoo-V3-Broker-Authority"
BROKER_ACTION_HEADER: Final = "X-Odoo-V3-Broker-Action"
BROKER_PROTOCOL_HEADER: Final = "X-Odoo-V3-Broker-Protocol"
BROKER_SESSION_HEADER: Final = "X-Odoo-V3-Broker-Session"
BROKER_PROTOCOL: Final = "pi-broker-v1"
EXECUTED_REGISTRY_DIGEST_HEADER: Final = (
    "X-Odoo-V3-Executed-Registry-Digest"
)
EXECUTED_RELEASE_DIGEST_HEADER: Final = "X-Odoo-V3-Executed-Release-Digest"
REGISTRY_DIGEST_HEADER: Final = "X-Odoo-V3-Registry-Digest"
RELEASE_DIGEST_HEADER: Final = "X-Odoo-V3-Release-Digest"

BROKER_ACTION_PATHS: Final[dict[str, str]] = {
    "/v1/read": "read",
    "/v1/operation/prepare": "operation.prepare",
    "/v1/operation/preview": "operation.preview",
    "/v1/operation/approve-execute": "operation.approve_execute",
    "/v1/operation/status": "operation.status",
    "/v1/operation/result": "operation.result",
    "/v1/operation/recover": "operation.recover",
}

_SESSION_HANDLE = re.compile(r"[A-Za-z0-9._~-]{32,512}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SOCKET_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")
_SOCKET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.sock\Z")
_CONTENT_LENGTH = re.compile(r"(?:0|[1-9][0-9]{0,7})\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_ALLOWED_CONTENT_TYPES: Final = frozenset(
    {"application/json", "application/json; charset=utf-8"}
)
_RESERVED_AUTHORITY_KEYS = frozenset(
    {
        "broker_session_handle",
        "registry_digest",
        "release_digest",
        "session_handle",
        "x_odoo_v3_broker_session",
        "x_odoo_v3_registry_digest",
        "x_odoo_v3_release_digest",
    }
)
_MAX_JSON_DEPTH: Final = 64
_PEER_CREDENTIAL_FORMAT: Final = "iII"
_PEER_CREDENTIAL_SIZE = struct.calcsize(_PEER_CREDENTIAL_FORMAT)
_MAX_LINUX_ID: Final = 2**32 - 2


class TrustedBrokerUdsError(RuntimeError):
    """The UDS broker boundary rejected configuration or runtime state."""


@dataclass(frozen=True, slots=True)
class TrustedBrokerUdsConfig:
    """Immutable transport configuration supplied by the root-owned launcher."""

    socket_path: str
    allowed_client_uid: int
    socket_group_gid: int
    max_inflight_requests: int
    socket_mode: int = 0o660
    max_body_bytes: int = 1024 * 1024
    max_response_bytes: int = 1024 * 1024
    max_header_bytes: int = 8192
    max_header_count: int = 16
    request_timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not isinstance(self.socket_path, str):
            raise TrustedBrokerUdsError("broker socket path must be a string")
        if (
            not _SOCKET_PATH.fullmatch(self.socket_path)
            or "\x00" in self.socket_path
            or not self.socket_path.isascii()
        ):
            raise TrustedBrokerUdsError(
                "broker socket path must be an absolute ASCII POSIX path"
            )
        parsed = PurePosixPath(self.socket_path)
        if (
            self.socket_path.startswith("//")
            or not parsed.is_absolute()
            or str(parsed) != self.socket_path
            or any(part in {".", ".."} for part in parsed.parts)
            or not _SOCKET_NAME.fullmatch(parsed.name)
            or len(self.socket_path.encode("ascii")) > 107
        ):
            raise TrustedBrokerUdsError("broker socket path is not canonical")
        for value, label in (
            (self.allowed_client_uid, "allowed client UID"),
            (self.socket_group_gid, "socket group GID"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= _MAX_LINUX_ID
            ):
                raise TrustedBrokerUdsError(f"{label} must be a valid Linux ID")
        if (
            isinstance(self.socket_mode, bool)
            or not isinstance(self.socket_mode, int)
            or self.socket_mode & ~0o777
            or self.socket_mode & 0o007
            or self.socket_mode & 0o600 != 0o600
        ):
            raise TrustedBrokerUdsError(
                "socket mode must grant owner read/write and no world access"
            )
        if (
            isinstance(self.max_body_bytes, bool)
            or not isinstance(self.max_body_bytes, int)
            or not 2 <= self.max_body_bytes <= 16 * 1024 * 1024
        ):
            raise TrustedBrokerUdsError("request body limit is outside the safe range")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 512 <= self.max_response_bytes <= 16 * 1024 * 1024
        ):
            raise TrustedBrokerUdsError(
                "response body limit is outside the safe range"
            )
        if (
            isinstance(self.max_header_bytes, bool)
            or not isinstance(self.max_header_bytes, int)
            or not 1024 <= self.max_header_bytes <= 64 * 1024
        ):
            raise TrustedBrokerUdsError("request header byte limit is outside the safe range")
        if (
            isinstance(self.max_header_count, bool)
            or not isinstance(self.max_header_count, int)
            or not 8 <= self.max_header_count <= 64
        ):
            raise TrustedBrokerUdsError("request header count limit is outside the safe range")
        if (
            isinstance(self.max_inflight_requests, bool)
            or not isinstance(self.max_inflight_requests, int)
            or not 1 <= self.max_inflight_requests <= 32
        ):
            raise TrustedBrokerUdsError(
                "in-flight broker request limit is outside the safe range"
            )
        if (
            isinstance(self.request_timeout_seconds, bool)
            or not isinstance(self.request_timeout_seconds, (int, float))
            or not 0.05 <= float(self.request_timeout_seconds) <= 119.0
        ):
            raise TrustedBrokerUdsError("request timeout is outside the safe range")


@dataclass(frozen=True, slots=True)
class BrokerDispatchRequest:
    """One parsed request passed to the injected trusted dispatcher.

    ``observed_peer_pid`` is diagnostic only.  The Linux PID is explicitly not
    an authentication input; only ``peer_uid`` has been checked against the
    configured allowed UID before this object can be created.
    """

    action: str
    payload: dict[str, Any]
    session_handle: str
    release_digest: str
    registry_digest: str
    peer_uid: int
    observed_peer_pid: int
    deadline_monotonic: float
    observed_peer_gid: int | None = None


@dataclass(frozen=True, slots=True)
class BrokerDispatchResult:
    """Strict response contract returned by the injected trusted dispatcher."""

    status_code: int
    body: dict[str, Any]
    authority_verified: bool
    executed_release_digest: str | None = None
    executed_registry_digest: str | None = None


BrokerDispatcher = Callable[[BrokerDispatchRequest], BrokerDispatchResult]


@dataclass(frozen=True, slots=True)
class _PeerCredentials:
    pid: int
    uid: int
    gid: int


class _DuplicateJsonKey(ValueError):
    pass


class _HeaderLimitedReader:
    """Bound header parsing before ``http.client`` can buffer oversized input."""

    def __init__(self, raw: Any, *, max_bytes: int, max_count: int) -> None:
        self._raw = raw
        self._max_bytes = max_bytes
        self._max_count = max_count
        self._bytes_read = 0
        self._lines_read = 0
        self._complete = False

    def readline(self, limit: int = -1) -> bytes:
        if self._complete:
            return self._raw.readline(limit)
        remaining = self._max_bytes - self._bytes_read
        if remaining <= 0:
            raise http.client.LineTooLong("broker request headers")
        bounded_limit = remaining + 1
        if limit >= 0:
            bounded_limit = min(bounded_limit, limit)
        line = self._raw.readline(bounded_limit)
        self._bytes_read += len(line)
        if self._bytes_read > self._max_bytes:
            raise http.client.LineTooLong("broker request headers")
        if line in {b"\r\n", b"\n", b""}:
            self._complete = True
            return line
        self._lines_read += 1
        if self._lines_read > self._max_count:
            raise http.client.HTTPException("too many broker request headers")
        return line


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey("duplicate JSON member")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON number")


def _contains_forbidden_json_value(value: Any) -> bool:
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > _MAX_JSON_DEPTH:
            return True
        if isinstance(current, dict):
            for key, child in current.items():
                normalized = key.lower().replace("-", "_")
                if normalized in _RESERVED_AUTHORITY_KEYS:
                    return True
                pending.append((child, depth + 1))
        elif isinstance(current, list):
            pending.extend((child, depth + 1) for child in current)
        elif isinstance(current, float) and not math.isfinite(current):
            return True
    return False


def _decode_request_object(body: bytes) -> dict[str, Any]:
    try:
        decoded = body.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise TrustedBrokerUdsError("request body is not strict JSON") from exc
    if not isinstance(value, dict):
        raise TrustedBrokerUdsError("request JSON must be an object")
    if _contains_forbidden_json_value(value):
        raise TrustedBrokerUdsError(
            "request JSON contains forbidden authority, numeric, or nesting data"
        )
    return value


def _one_header(headers: Any, name: str) -> str:
    values = headers.get_all(name, failobj=[])
    if len(values) != 1 or not isinstance(values[0], str):
        raise TrustedBrokerUdsError("required broker header is missing or duplicated")
    return values[0]


def _validate_header_limits(headers: Any, config: TrustedBrokerUdsConfig) -> None:
    try:
        raw_items = list(headers.raw_items())
    except (AttributeError, TypeError, ValueError) as exc:
        raise TrustedBrokerUdsError("request headers are unavailable") from exc
    if len(raw_items) > config.max_header_count:
        raise TrustedBrokerUdsError("request header count exceeds the limit")
    encoded_size = 2
    for name, value in raw_items:
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not name.isascii()
            or not _HEADER_NAME.fullmatch(name)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise TrustedBrokerUdsError("request header syntax is invalid")
        try:
            encoded_size += len(name.encode("ascii")) + len(value.encode("latin-1")) + 4
        except UnicodeEncodeError as exc:
            raise TrustedBrokerUdsError("request header encoding is invalid") from exc
    if encoded_size > config.max_header_bytes:
        raise TrustedBrokerUdsError("request headers exceed the byte limit")


def _read_transport_headers(
    headers: Any,
    *,
    expected_action: str,
) -> tuple[str, str, str]:
    action = _one_header(headers, BROKER_ACTION_HEADER)
    protocol = _one_header(headers, BROKER_PROTOCOL_HEADER)
    session_handle = _one_header(headers, BROKER_SESSION_HEADER)
    release_digest = _one_header(headers, RELEASE_DIGEST_HEADER)
    registry_digest = _one_header(headers, REGISTRY_DIGEST_HEADER)
    if action != expected_action:
        raise TrustedBrokerUdsError("broker action header does not match the route")
    if protocol != BROKER_PROTOCOL:
        raise TrustedBrokerUdsError("broker protocol header is invalid")
    if not _SESSION_HANDLE.fullmatch(session_handle):
        raise TrustedBrokerUdsError("broker session header is invalid")
    if not _SHA256.fullmatch(release_digest):
        raise TrustedBrokerUdsError("release digest header is invalid")
    if not _SHA256.fullmatch(registry_digest):
        raise TrustedBrokerUdsError("registry digest header is invalid")
    allowed_v3_headers = {
        BROKER_ACTION_HEADER.lower(),
        BROKER_PROTOCOL_HEADER.lower(),
        BROKER_SESSION_HEADER.lower(),
        REGISTRY_DIGEST_HEADER.lower(),
        RELEASE_DIGEST_HEADER.lower(),
    }
    for name, _value in headers.raw_items():
        lowered = name.lower()
        if lowered.startswith("x-odoo-v3-") and lowered not in allowed_v3_headers:
            raise TrustedBrokerUdsError("unrecognized V3 broker header")
    return session_handle, release_digest, registry_digest


def _validated_executed_identity(
    result: BrokerDispatchResult,
    request: BrokerDispatchRequest,
) -> tuple[str | None, str | None]:
    release_digest = result.executed_release_digest
    registry_digest = result.executed_registry_digest
    if not result.authority_verified:
        if release_digest is not None or registry_digest is not None:
            raise TrustedBrokerUdsError(
                "unverified dispatcher response supplied executed identity"
            )
        return None, None
    if result.status_code != 200 or not isinstance(result.body.get("ok"), bool):
        raise TrustedBrokerUdsError("authenticated dispatcher response is invalid")
    if (release_digest is None) != (registry_digest is None):
        raise TrustedBrokerUdsError("executed identity must be supplied as a pair")
    if release_digest is None:
        if result.body["ok"]:
            raise TrustedBrokerUdsError("successful response has no executed identity")
        return None, None
    if (
        not isinstance(release_digest, str)
        or not _SHA256.fullmatch(release_digest)
        or not isinstance(registry_digest, str)
        or not _SHA256.fullmatch(registry_digest)
    ):
        raise TrustedBrokerUdsError("executed identity is invalid")
    if request.action in {"read", "operation.prepare"} and (
        release_digest != request.release_digest
        or registry_digest != request.registry_digest
    ):
        raise TrustedBrokerUdsError(
            "current-release action returned a different executed identity"
        )
    return release_digest, registry_digest


def _safe_error(
    code: str,
    *,
    odoo_effect: str = "none",
    retryable: bool = False,
) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": "The trusted V3 broker rejected the local request.",
            "odoo_effect": odoo_effect,
            "retryable": retryable,
        },
    }


def _capacity_response() -> bytes:
    body = json.dumps(
        _safe_error("broker_capacity_exhausted", retryable=True),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Cache-Control: no-store\r\n"
        b"Connection: close\r\n\r\n"
        + body
    )


def _peer_credentials(connection: socket.socket) -> _PeerCredentials:
    if not hasattr(socket, "SO_PEERCRED"):
        raise TrustedBrokerUdsError("Linux SO_PEERCRED is unavailable")
    raw = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        _PEER_CREDENTIAL_SIZE,
    )
    if len(raw) != _PEER_CREDENTIAL_SIZE:
        raise TrustedBrokerUdsError("Linux peer credentials are incomplete")
    pid, uid, gid = struct.unpack(_PEER_CREDENTIAL_FORMAT, raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise TrustedBrokerUdsError("Linux peer credentials are invalid")
    return _PeerCredentials(pid=pid, uid=uid, gid=gid)


class _BrokerRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OdooAccountingV3Broker"
    sys_version = ""

    def setup(self) -> None:
        self._response_sent = False
        self._io_expired = False
        self._io_timer: threading.Timer | None = None
        super().setup()
        self.connection.settimeout(self.server.config.request_timeout_seconds)
        self._accepted_at = monotonic()
        self._peer = self.server.take_peer_credentials(self.connection)
        timer = threading.Timer(
            self.server.config.request_timeout_seconds,
            self._expire_io,
        )
        timer.daemon = True
        self._io_timer = timer
        timer.start()

    def finish(self) -> None:
        self._cancel_io_timer()
        super().finish()

    def _expire_io(self) -> None:
        self._io_expired = True
        try:
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def _cancel_io_timer(self) -> None:
        timer = self._io_timer
        self._io_timer = None
        if timer is not None:
            timer.cancel()

    def log_message(self, _format: str, *args: Any) -> None:
        # Deliberately no access log: authority headers must never be logged.
        return None

    def parse_request(self) -> bool:
        original = self.rfile
        self.rfile = _HeaderLimitedReader(
            original,
            max_bytes=self.server.config.max_header_bytes,
            max_count=self.server.config.max_header_count,
        )
        try:
            return super().parse_request()
        finally:
            self.rfile = original

    def handle_expect_100(self) -> bool:
        self._send_json(417, _safe_error("broker_expectation_rejected"))
        return False

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        del message, explain
        self._send_json(code, _safe_error("broker_http_request_rejected"))

    def _send_json(
        self,
        status_code: int,
        value: dict[str, Any],
        *,
        authority_verified: bool = False,
        executed_release_digest: str | None = None,
        executed_registry_digest: str | None = None,
    ) -> None:
        if self._response_sent:
            self.close_connection = True
            return
        self._response_sent = True
        self.close_connection = True
        self._cancel_io_timer()
        identity_is_paired = (executed_release_digest is None) == (
            executed_registry_digest is None
        )
        identity_is_valid = (
            executed_release_digest is None
            or (
                isinstance(executed_release_digest, str)
                and _SHA256.fullmatch(executed_release_digest) is not None
                and isinstance(executed_registry_digest, str)
                and _SHA256.fullmatch(executed_registry_digest) is not None
            )
        )
        if (
            not identity_is_paired
            or not identity_is_valid
            or (not authority_verified and executed_release_digest is not None)
        ):
            status_code = 500
            value = _safe_error("broker_dispatch_response_rejected")
            authority_verified = False
            executed_release_digest = None
            executed_registry_digest = None
        try:
            body = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (RecursionError, TypeError, ValueError, UnicodeError):
            status_code = 500
            authority_verified = False
            executed_release_digest = None
            executed_registry_digest = None
            body = json.dumps(
                _safe_error("broker_dispatch_response_rejected"),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        if len(body) > self.server.config.max_response_bytes:
            status_code = 500
            authority_verified = False
            executed_release_digest = None
            executed_registry_digest = None
            body = json.dumps(
                _safe_error("broker_dispatch_response_rejected"),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        self.send_response_only(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if authority_verified:
            self.send_header(BROKER_AUTHORITY_HEADER, "verified-v1")
            if executed_release_digest is not None:
                self.send_header(
                    EXECUTED_RELEASE_DIGEST_HEADER,
                    executed_release_digest,
                )
                self.send_header(
                    EXECUTED_REGISTRY_DIGEST_HEADER,
                    executed_registry_digest,
                )
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionError, OSError):
            pass

    def _reject(
        self,
        status_code: int,
        code: str,
        *,
        odoo_effect: str = "none",
    ) -> None:
        self._send_json(status_code, _safe_error(code, odoo_effect=odoo_effect))

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        action = BROKER_ACTION_PATHS.get(self.path)
        if action is None:
            self._reject(404, "broker_route_rejected")
            return
        try:
            _validate_header_limits(self.headers, self.server.config)
        except TrustedBrokerUdsError:
            self._reject(431, "broker_headers_rejected")
            return
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            self._reject(400, "broker_transfer_encoding_rejected")
            return
        if self.headers.get_all("Content-Encoding", failobj=[]):
            self._reject(415, "broker_content_encoding_rejected")
            return
        if self.headers.get_all("Expect", failobj=[]):
            self._reject(417, "broker_expectation_rejected")
            return
        content_types = self.headers.get_all("Content-Type", failobj=[])
        if len(content_types) != 1 or content_types[0] not in _ALLOWED_CONTENT_TYPES:
            self._reject(415, "broker_content_type_rejected")
            return
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        if (
            len(content_lengths) != 1
            or not isinstance(content_lengths[0], str)
            or not _CONTENT_LENGTH.fullmatch(content_lengths[0])
        ):
            self._reject(411, "broker_content_length_rejected")
            return
        content_length = int(content_lengths[0])
        if content_length > self.server.config.max_body_bytes:
            self._reject(413, "broker_request_too_large")
            return
        if content_length < 2:
            self._reject(400, "broker_json_object_required")
            return
        try:
            session_handle, release_digest, registry_digest = (
                _read_transport_headers(self.headers, expected_action=action)
            )
        except TrustedBrokerUdsError:
            self._reject(401, "broker_authority_headers_rejected")
            return
        try:
            body = self.rfile.read(content_length)
        except (TimeoutError, socket.timeout, OSError):
            self._reject(408, "broker_request_timeout")
            return
        if self._io_expired:
            self._reject(408, "broker_request_timeout")
            return
        if len(body) != content_length:
            self._reject(400, "broker_request_body_incomplete")
            return
        try:
            payload = _decode_request_object(body)
        except TrustedBrokerUdsError:
            self._reject(400, "broker_json_object_rejected")
            return
        deadline = self._accepted_at + self.server.config.request_timeout_seconds
        if monotonic() >= deadline:
            self._reject(408, "broker_request_timeout")
            return
        self._cancel_io_timer()
        request = BrokerDispatchRequest(
            action=action,
            payload=payload,
            session_handle=session_handle,
            release_digest=release_digest,
            registry_digest=registry_digest,
            peer_uid=self._peer.uid,
            observed_peer_pid=self._peer.pid,
            deadline_monotonic=deadline,
            observed_peer_gid=self._peer.gid,
        )
        dispatch_may_have_written = action in {
            "operation.approve_execute",
            "operation.recover",
        }
        try:
            with monotonic_deadline_scope(deadline):
                result = self.server.dispatcher(request)
            if (
                not isinstance(result, BrokerDispatchResult)
                or isinstance(result.status_code, bool)
                or not isinstance(result.status_code, int)
                or not 200 <= result.status_code <= 599
                or not isinstance(result.body, dict)
                or not isinstance(result.authority_verified, bool)
            ):
                raise TrustedBrokerUdsError("dispatcher response is invalid")
            executed_release_digest, executed_registry_digest = (
                _validated_executed_identity(result, request)
            )
            serialized = json.dumps(
                result.body,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if session_handle.encode("ascii") in serialized:
                raise TrustedBrokerUdsError("dispatcher echoed the session handle")
            if monotonic() >= deadline:
                raise TrustedBrokerUdsError("dispatcher exceeded its deadline")
        except Exception:
            self._reject(
                500,
                "broker_dispatch_failed",
                odoo_effect="unknown" if dispatch_may_have_written else "none",
            )
            return
        self._send_json(
            result.status_code,
            result.body,
            authority_verified=result.authority_verified,
            executed_release_digest=executed_release_digest,
            executed_registry_digest=executed_registry_digest,
        )

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._reject(405, "broker_method_rejected")

    do_DELETE = do_GET
    do_HEAD = do_GET
    do_OPTIONS = do_GET
    do_PATCH = do_GET
    do_PUT = do_GET


if hasattr(socketserver, "UnixStreamServer"):

    class _TrustedUnixHTTPServer(
        socketserver.ThreadingMixIn,
        socketserver.UnixStreamServer,
    ):
        # ``server_close`` must drain every accepted accounting request before
        # the dedicated service process is allowed to exit.
        daemon_threads = False
        block_on_close = True
        allow_reuse_address = False
        request_queue_size = 16

        def __init__(
            self,
            config: TrustedBrokerUdsConfig,
            dispatcher: BrokerDispatcher,
            *,
            bind_and_activate: bool,
        ) -> None:
            self.config = config
            self.dispatcher = dispatcher
            self._handler_slots = threading.BoundedSemaphore(
                config.max_inflight_requests
            )
            self._credential_lock = threading.Lock()
            self._credentials: dict[int, _PeerCredentials] = {}
            self._cleanup_parent_fd: int | None = None
            self._bound_identity: tuple[int, int] | None = None
            super().__init__(
                config.socket_path,
                _BrokerRequestHandler,
                bind_and_activate=bind_and_activate,
            )

        def verify_request(self, request: socket.socket, client_address: Any) -> bool:
            del client_address
            try:
                credentials = _peer_credentials(request)
            except (OSError, TrustedBrokerUdsError):
                return False
            if credentials.uid != self.config.allowed_client_uid:
                return False
            with self._credential_lock:
                self._credentials[id(request)] = credentials
            return True

        def take_peer_credentials(self, request: socket.socket) -> _PeerCredentials:
            with self._credential_lock:
                try:
                    return self._credentials.pop(id(request))
                except KeyError as exc:
                    raise TrustedBrokerUdsError(
                        "verified peer credentials are unavailable"
                    ) from exc

        def process_request(self, request: socket.socket, client_address: Any) -> None:
            """Bound every accepted handler, including slow pre-body clients."""

            if not self._handler_slots.acquire(blocking=False):
                with self._credential_lock:
                    self._credentials.pop(id(request), None)
                try:
                    request.settimeout(
                        min(float(self.config.request_timeout_seconds), 0.05)
                    )
                    request.sendall(_capacity_response())
                except (TimeoutError, socket.timeout, OSError):
                    pass
                finally:
                    self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._handler_slots.release()
                raise

        def process_request_thread(
            self, request: socket.socket, client_address: Any
        ) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                self._handler_slots.release()

        def shutdown_request(self, request: socket.socket) -> None:
            with self._credential_lock:
                self._credentials.pop(id(request), None)
            super().shutdown_request(request)

        def handle_error(self, request: Any, client_address: Any) -> None:
            del request, client_address
            # Fail closed without logging headers, request bodies, or tracebacks.

        def attach_secure_path(
            self,
            parent_fd: int,
            bound_identity: tuple[int, int],
        ) -> None:
            self._cleanup_parent_fd = parent_fd
            self._bound_identity = bound_identity

        def server_close(self) -> None:
            super().server_close()
            parent_fd = self._cleanup_parent_fd
            identity = self._bound_identity
            self._cleanup_parent_fd = None
            self._bound_identity = None
            if parent_fd is None:
                return
            try:
                if identity is not None:
                    name = PurePosixPath(self.config.socket_path).name
                    try:
                        current = _stat_socket_at(parent_fd, name)
                    except FileNotFoundError:
                        current = None
                    if (
                        current is not None
                        and stat.S_ISSOCK(current.st_mode)
                        and (current.st_dev, current.st_ino) == identity
                    ):
                        _unlink_socket_at(parent_fd, name)
            finally:
                os.close(parent_fd)

else:  # pragma: no cover - exercised by Windows platform guards
    _TrustedUnixHTTPServer = None  # type: ignore[assignment,misc]


def _require_linux() -> None:
    if (
        sys.platform != "linux"
        or os.name != "posix"
        or _TrustedUnixHTTPServer is None
        or not hasattr(socket, "SO_PEERCRED")
    ):
        raise TrustedBrokerUdsError(
            "trusted broker UDS transport is supported only on Linux"
        )


def _validate_parent_stat(value: os.stat_result) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or mode & 0o700 != 0o700
        or mode & 0o027
    ):
        raise TrustedBrokerUdsError(
            "broker socket parent must be a private root-owned real directory"
        )


def _validate_ancestor_stat(value: os.stat_result) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or mode & 0o022
    ):
        raise TrustedBrokerUdsError(
            "broker socket ancestors must be root-owned real directories "
            "without group/world write access"
        )


def _open_secure_parent(config: TrustedBrokerUdsConfig) -> int:
    parent = PurePosixPath(config.socket_path).parent
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = -1
    try:
        current_fd = os.open("/", flags)
        _validate_ancestor_stat(os.fstat(current_fd))
        parts = parent.parts[1:]
        for index, component in enumerate(parts):
            next_fd = os.open(component, flags, dir_fd=current_fd)
            try:
                value = os.fstat(next_fd)
                if index == len(parts) - 1:
                    _validate_parent_stat(value)
                else:
                    _validate_ancestor_stat(value)
            except Exception:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        if not parts:
            _validate_parent_stat(os.fstat(current_fd))
        return current_fd
    except Exception as exc:
        if current_fd >= 0:
            os.close(current_fd)
        if isinstance(exc, OSError):
            raise TrustedBrokerUdsError(
                "broker socket parent is unavailable"
            ) from exc
        raise


def _validate_socket_stat(
    value: os.stat_result,
    config: TrustedBrokerUdsConfig,
) -> None:
    if (
        not stat.S_ISSOCK(value.st_mode)
        or value.st_uid != 0
        or value.st_gid != config.socket_group_gid
        or stat.S_IMODE(value.st_mode) != config.socket_mode
    ):
        raise TrustedBrokerUdsError(
            "existing broker socket has untrusted owner, group, mode, or type"
        )


def _stat_socket_at(parent_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def _unlink_socket_at(parent_fd: int, name: str) -> None:
    os.unlink(name, dir_fd=parent_fd)


def _new_stale_socket_probe() -> socket.socket:
    return socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)


def _remove_verified_stale_socket(
    parent_fd: int,
    config: TrustedBrokerUdsConfig,
) -> None:
    name = PurePosixPath(config.socket_path).name
    try:
        initial = _stat_socket_at(parent_fd, name)
    except FileNotFoundError:
        return
    _validate_socket_stat(initial, config)
    probe = _new_stale_socket_probe()
    try:
        probe.settimeout(min(float(config.request_timeout_seconds), 0.25))
        try:
            probe.connect(config.socket_path)
        except OSError as exc:
            if exc.errno != errno.ECONNREFUSED:
                raise TrustedBrokerUdsError(
                    "existing broker socket could not be proven stale"
                ) from exc
        else:
            raise TrustedBrokerUdsError("another trusted broker is already active")
    finally:
        probe.close()
    try:
        current = _stat_socket_at(parent_fd, name)
    except FileNotFoundError as exc:
        raise TrustedBrokerUdsError(
            "broker socket changed during stale-socket verification"
        ) from exc
    _validate_socket_stat(current, config)
    if (initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino):
        raise TrustedBrokerUdsError(
            "broker socket changed during stale-socket verification"
        )
    _unlink_socket_at(parent_fd, name)


def _configure_bound_socket(
    parent_fd: int,
    config: TrustedBrokerUdsConfig,
) -> tuple[int, int]:
    name = PurePosixPath(config.socket_path).name
    created = _stat_socket_at(parent_fd, name)
    if not stat.S_ISSOCK(created.st_mode) or created.st_uid != 0:
        raise TrustedBrokerUdsError("bound broker path is not a root-owned socket")
    identity = (created.st_dev, created.st_ino)
    os.chown(
        name,
        0,
        config.socket_group_gid,
        dir_fd=parent_fd,
        follow_symlinks=False,
    )
    os.chmod(name, config.socket_mode, dir_fd=parent_fd)
    secured = _stat_socket_at(parent_fd, name)
    _validate_socket_stat(secured, config)
    if (secured.st_dev, secured.st_ino) != identity:
        raise TrustedBrokerUdsError("bound broker socket changed during setup")
    return identity


def create_trusted_broker_uds_server(
    config: TrustedBrokerUdsConfig,
    dispatcher: BrokerDispatcher,
) -> Any:
    """Bind, validate, and activate the root-controlled Linux UDS server."""

    _require_linux()
    if os.geteuid() != 0:
        raise TrustedBrokerUdsError("trusted broker UDS binding requires root")
    if not callable(dispatcher):
        raise TrustedBrokerUdsError("trusted broker dispatcher must be callable")
    parent_fd = _open_secure_parent(config)
    server: Any | None = None
    try:
        _remove_verified_stale_socket(parent_fd, config)
        server = _TrustedUnixHTTPServer(
            config,
            dispatcher,
            bind_and_activate=False,
        )
        server.server_bind()
        name = PurePosixPath(config.socket_path).name
        created = _stat_socket_at(parent_fd, name)
        if not stat.S_ISSOCK(created.st_mode):
            raise TrustedBrokerUdsError("broker bind did not create a Unix socket")
        server.attach_secure_path(
            parent_fd,
            (created.st_dev, created.st_ino),
        )
        parent_fd = -1
        identity = _configure_bound_socket(
            server._cleanup_parent_fd,
            config,
        )
        server._bound_identity = identity
        server.server_activate()
        return server
    except Exception:
        if server is not None:
            server.server_close()
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def create_trusted_broker_uds_server_from_fd(
    config: TrustedBrokerUdsConfig,
    dispatcher: BrokerDispatcher,
    descriptor: int,
) -> Any:
    """Adopt one root-created systemd socket while running as non-root."""

    _require_linux()
    if os.geteuid() == 0:
        raise TrustedBrokerUdsError(
            "activated broker server must run under a dedicated non-root UID"
        )
    if not callable(dispatcher):
        raise TrustedBrokerUdsError("trusted broker dispatcher must be callable")
    server = _TrustedUnixHTTPServer(
        config,
        dispatcher,
        bind_and_activate=False,
    )
    try:
        from .systemd_activation import adopt_activated_unix_server

        adopt_activated_unix_server(
            server,
            descriptor,
            socket_path=config.socket_path,
            expected_owner_uid=0,
            expected_group_gid=config.socket_group_gid,
            expected_mode=config.socket_mode,
        )
        return server
    except Exception as exc:
        server.server_close()
        raise TrustedBrokerUdsError(
            "activated broker socket was rejected"
        ) from exc


def serve_trusted_broker_uds(
    config: TrustedBrokerUdsConfig,
    dispatcher: BrokerDispatcher,
) -> None:
    """Serve until interrupted; callers should normally supervise with systemd."""

    server = create_trusted_broker_uds_server(config, dispatcher)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


__all__ = [
    "BROKER_ACTION_HEADER",
    "BROKER_ACTION_PATHS",
    "BROKER_AUTHORITY_HEADER",
    "BROKER_PROTOCOL",
    "BROKER_PROTOCOL_HEADER",
    "BROKER_SESSION_HEADER",
    "BrokerDispatchRequest",
    "BrokerDispatchResult",
    "BrokerDispatcher",
    "EXECUTED_REGISTRY_DIGEST_HEADER",
    "EXECUTED_RELEASE_DIGEST_HEADER",
    "REGISTRY_DIGEST_HEADER",
    "RELEASE_DIGEST_HEADER",
    "TrustedBrokerUdsConfig",
    "TrustedBrokerUdsError",
    "create_trusted_broker_uds_server",
    "create_trusted_broker_uds_server_from_fd",
    "serve_trusted_broker_uds",
]

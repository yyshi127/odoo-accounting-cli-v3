"""Root-configured Linux UDS boundary for trusted-session minting.

Exactly two routes are exposed: ``POST /v1/trusted-session/mint`` and
``POST /v1/trusted-session/revoke``.  Linux ``SO_PEERCRED`` admits only the
configured Odoo issuer UID.  The mint body contains only a server-established
Odoo identity; session TTL and use budget come exclusively from immutable
root-owned launcher configuration.  Revoke accepts only the opaque handle and
never returns it.

``SO_PEERCRED`` authenticates a Unix UID, not an Odoo request or Python worker.
It cannot distinguish a legitimate Odoo worker from malicious code running as
the same UID.  Therefore Pi Bridge must use a different Unix UID, must not be
able to execute as the Odoo issuer UID, and should not belong to the socket
group.  The issuer UID itself remains a privileged credential-minting boundary.

This module provides no TCP listener and deliberately emits no access log,
request body, exception traceback, secret, or opaque handle to logs.
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
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from pathlib import PurePosixPath
from time import monotonic
from typing import Any, Final

from .monotonic_deadline import (
    MonotonicDeadlineExceeded,
    monotonic_deadline_scope,
)
from .trusted_session_sqlite import (
    IssuedTrustedSession,
    SQLiteTrustedSessionStore,
    TrustedSessionIdentity,
    TrustedSessionStoreError,
)


MINT_PATH: Final = "/v1/trusted-session/mint"
REVOKE_PATH: Final = "/v1/trusted-session/revoke"
SAME_UID_THREAT: Final = (
    "Linux SO_PEERCRED cannot distinguish processes that share the Odoo issuer "
    "UID. Pi Bridge must run under a different Unix UID and must not be able to "
    "execute code as, switch to, or inject into the Odoo issuer UID."
)

_IDENTITY_FIELDS: Final = frozenset(
    {
        "principal",
        "odoo_instance_id",
        "database_name",
        "database_uuid",
        "user_id",
        "company_id",
        "allowed_company_ids",
        "environment",
    }
)
_ALLOWED_HEADERS: Final = frozenset(
    {"host", "content-type", "content-length", "connection"}
)
_ALLOWED_CONTENT_TYPES: Final = frozenset(
    {"application/json", "application/json; charset=utf-8"}
)
_CONTENT_LENGTH = re.compile(r"(?:0|[1-9][0-9]{0,5})\Z")
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_SOCKET_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")
_SOCKET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.sock\Z")
_PEER_CREDENTIAL_FORMAT: Final = "iII"
_PEER_CREDENTIAL_SIZE: Final = struct.calcsize(_PEER_CREDENTIAL_FORMAT)
_MAX_LINUX_ID: Final = 2**32 - 2


class TrustedSessionMintUdsError(RuntimeError):
    """The session-mint boundary rejected configuration or request state."""


@dataclass(frozen=True, slots=True)
class TrustedSessionMintUdsConfig:
    """Immutable settings supplied by the root-owned mint service launcher."""

    socket_path: str
    odoo_issuer_uid: int
    pi_bridge_uid: int
    socket_group_gid: int
    max_inflight_requests: int
    session_ttl_seconds: int = 60
    session_max_uses: int = 32
    socket_mode: int = 0o660
    max_body_bytes: int = 8192
    max_response_bytes: int = 4096
    max_header_bytes: int = 4096
    max_header_count: int = 8
    request_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not isinstance(self.socket_path, str):
            raise TrustedSessionMintUdsError("mint socket path must be a string")
        if (
            not _SOCKET_PATH.fullmatch(self.socket_path)
            or "\x00" in self.socket_path
            or not self.socket_path.isascii()
        ):
            raise TrustedSessionMintUdsError(
                "mint socket path must be an absolute ASCII POSIX path"
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
            raise TrustedSessionMintUdsError("mint socket path is not canonical")
        for value, label in (
            (self.odoo_issuer_uid, "Odoo issuer UID"),
            (self.pi_bridge_uid, "Pi Bridge UID"),
            (self.socket_group_gid, "socket group GID"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= _MAX_LINUX_ID
            ):
                raise TrustedSessionMintUdsError(f"{label} is not a valid Linux ID")
        if self.pi_bridge_uid == self.odoo_issuer_uid:
            raise TrustedSessionMintUdsError(
                "Pi Bridge must run under a different UID from the Odoo issuer; "
                "same-UID processes cannot be distinguished by SO_PEERCRED"
            )
        if (
            isinstance(self.session_ttl_seconds, bool)
            or not isinstance(self.session_ttl_seconds, int)
            or not 1 <= self.session_ttl_seconds <= 3600
        ):
            raise TrustedSessionMintUdsError(
                "root-configured session TTL is outside the safe range"
            )
        if (
            isinstance(self.session_max_uses, bool)
            or not isinstance(self.session_max_uses, int)
            or not 16 <= self.session_max_uses <= 64
        ):
            raise TrustedSessionMintUdsError(
                "root-configured session use budget is outside the safe range"
            )
        if (
            isinstance(self.socket_mode, bool)
            or not isinstance(self.socket_mode, int)
            or self.socket_mode & ~0o777
            or self.socket_mode & 0o007
            or self.socket_mode & 0o600 != 0o600
        ):
            raise TrustedSessionMintUdsError(
                "mint socket mode must grant owner read/write and no world access"
            )
        if (
            isinstance(self.max_body_bytes, bool)
            or not isinstance(self.max_body_bytes, int)
            or not 256 <= self.max_body_bytes <= 64 * 1024
        ):
            raise TrustedSessionMintUdsError(
                "mint request body limit is outside the safe range"
            )
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 512 <= self.max_response_bytes <= 64 * 1024
        ):
            raise TrustedSessionMintUdsError(
                "mint response body limit is outside the safe range"
            )
        if (
            isinstance(self.max_header_bytes, bool)
            or not isinstance(self.max_header_bytes, int)
            or not 1024 <= self.max_header_bytes <= 32 * 1024
        ):
            raise TrustedSessionMintUdsError(
                "mint request header byte limit is outside the safe range"
            )
        if (
            isinstance(self.max_header_count, bool)
            or not isinstance(self.max_header_count, int)
            or not 4 <= self.max_header_count <= 32
        ):
            raise TrustedSessionMintUdsError(
                "mint request header count is outside the safe range"
            )
        if (
            isinstance(self.max_inflight_requests, bool)
            or not isinstance(self.max_inflight_requests, int)
            or not 1 <= self.max_inflight_requests <= 32
        ):
            raise TrustedSessionMintUdsError(
                "mint in-flight request limit is outside the safe range"
            )
        if (
            isinstance(self.request_timeout_seconds, bool)
            or not isinstance(self.request_timeout_seconds, (int, float))
            or not 0.05 <= float(self.request_timeout_seconds) <= 30.0
        ):
            raise TrustedSessionMintUdsError(
                "mint request timeout is outside the safe range"
            )


@dataclass(frozen=True, slots=True)
class _PeerCredentials:
    pid: int
    uid: int
    gid: int


class _DuplicateJsonKey(ValueError):
    pass


class _HeaderLimitedReader:
    """Bound header parsing before ``http.client`` can buffer the input."""

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
            raise http.client.LineTooLong("session mint request headers")
        bounded_limit = remaining + 1
        if limit >= 0:
            bounded_limit = min(bounded_limit, limit)
        line = self._raw.readline(bounded_limit)
        self._bytes_read += len(line)
        if self._bytes_read > self._max_bytes:
            raise http.client.LineTooLong("session mint request headers")
        if line in {b"\r\n", b"\n", b""}:
            self._complete = True
            return line
        self._lines_read += 1
        if self._lines_read > self._max_count:
            raise http.client.HTTPException("too many session mint request headers")
        return line


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise _DuplicateJsonKey("duplicate JSON member")
        value[key] = child
    return value


def _reject_json_constant(_value: str) -> Any:
    raise ValueError("non-finite JSON number")


def _decode_identity_request(body: bytes) -> TrustedSessionIdentity:
    """Decode the exact server identity contract; no authority knobs exist."""

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
        raise TrustedSessionMintUdsError(
            "mint request body is not strict JSON"
        ) from exc
    if not isinstance(value, dict) or set(value) != _IDENTITY_FIELDS:
        raise TrustedSessionMintUdsError(
            "mint request must contain the exact Odoo identity fields"
        )
    if any(isinstance(child, float) and not math.isfinite(child) for child in value.values()):
        raise TrustedSessionMintUdsError("mint identity contains invalid numeric data")
    database_uuid = value["database_uuid"]
    try:
        normalized_uuid = str(uuid.UUID(database_uuid))
    except (AttributeError, TypeError, ValueError) as exc:
        raise TrustedSessionMintUdsError(
            "mint Odoo identity is invalid"
        ) from exc
    if database_uuid != normalized_uuid:
        raise TrustedSessionMintUdsError("mint database UUID is not canonical")
    allowed = value["allowed_company_ids"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or any(type(company_id) is not int or company_id <= 0 for company_id in allowed)
        or allowed != sorted(set(allowed))
    ):
        raise TrustedSessionMintUdsError(
            "mint allowed companies must be a sorted unique positive integer list"
        )
    try:
        return TrustedSessionIdentity(
            principal=value["principal"],
            odoo_instance_id=value["odoo_instance_id"],
            database_name=value["database_name"],
            database_uuid=database_uuid,
            user_id=value["user_id"],
            company_id=value["company_id"],
            allowed_company_ids=frozenset(allowed),
            environment=value["environment"],
        )
    except (TrustedSessionStoreError, TypeError, ValueError) as exc:
        raise TrustedSessionMintUdsError("mint Odoo identity is invalid") from exc


def _decode_revoke_request(body: bytes) -> str:
    """Decode exactly ``{"handle": ...}`` without accepting a caller reason."""

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
        raise TrustedSessionMintUdsError(
            "revoke request body is not strict JSON"
        ) from exc
    if not isinstance(value, dict) or set(value) != {"handle"}:
        raise TrustedSessionMintUdsError(
            "revoke request must contain exactly one handle"
        )
    handle = value["handle"]
    if (
        not isinstance(handle, str)
        or not handle
        or len(handle) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in handle)
    ):
        raise TrustedSessionMintUdsError("revoke handle is invalid")
    return handle


def _issue_session(
    store: SQLiteTrustedSessionStore,
    config: TrustedSessionMintUdsConfig,
    identity: TrustedSessionIdentity,
) -> IssuedTrustedSession:
    """Call the durable issuer with only root-configured credential limits."""

    if not isinstance(store, SQLiteTrustedSessionStore):
        raise TrustedSessionMintUdsError("trusted session store is invalid")
    if type(identity) is not TrustedSessionIdentity:
        raise TrustedSessionMintUdsError("server-established identity is invalid")
    try:
        return store.issue(
            identity,
            ttl_seconds=config.session_ttl_seconds,
            max_uses=config.session_max_uses,
        )
    except TrustedSessionStoreError as exc:
        raise TrustedSessionMintUdsError("durable session mint failed") from exc


def _revoke_session(store: SQLiteTrustedSessionStore, handle: str) -> bool:
    """Revoke with the fixed server reason; callers cannot select audit text."""

    if not isinstance(store, SQLiteTrustedSessionStore):
        raise TrustedSessionMintUdsError("trusted session store is invalid")
    try:
        return store.revoke(handle, reason="odoo_request_completed")
    except TrustedSessionStoreError as exc:
        raise TrustedSessionMintUdsError("durable session revoke failed") from exc


def _safe_error(code: str, *, retryable: bool = False) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": code,
            "message": "The trusted session mint rejected the local request.",
            "retryable": retryable,
        },
    }


def _capacity_response() -> bytes:
    body = json.dumps(
        _safe_error("session_mint_capacity_exhausted", retryable=True),
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
        raise TrustedSessionMintUdsError("Linux SO_PEERCRED is unavailable")
    raw = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        _PEER_CREDENTIAL_SIZE,
    )
    if len(raw) != _PEER_CREDENTIAL_SIZE:
        raise TrustedSessionMintUdsError("Linux peer credentials are incomplete")
    pid, uid, gid = struct.unpack(_PEER_CREDENTIAL_FORMAT, raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise TrustedSessionMintUdsError("Linux peer credentials are invalid")
    return _PeerCredentials(pid=pid, uid=uid, gid=gid)


def _peer_is_allowed(
    credentials: _PeerCredentials,
    config: TrustedSessionMintUdsConfig,
) -> bool:
    """UID is the sole peer admission fact; PID/GID are diagnostic only."""

    return credentials.uid == config.odoo_issuer_uid


def _validate_headers(headers: Any, config: TrustedSessionMintUdsConfig) -> None:
    try:
        raw_items = list(headers.raw_items())
    except (AttributeError, TypeError, ValueError) as exc:
        raise TrustedSessionMintUdsError("mint request headers are unavailable") from exc
    if len(raw_items) > config.max_header_count:
        raise TrustedSessionMintUdsError("mint request header count exceeds the limit")
    encoded_size = 2
    for name, value in raw_items:
        if (
            not isinstance(name, str)
            or not isinstance(value, str)
            or not name.isascii()
            or not _HEADER_NAME.fullmatch(name)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or name.lower() not in _ALLOWED_HEADERS
        ):
            raise TrustedSessionMintUdsError("mint request header is not allowed")
        try:
            encoded_size += len(name.encode("ascii")) + len(value.encode("latin-1")) + 4
        except UnicodeEncodeError as exc:
            raise TrustedSessionMintUdsError(
                "mint request header encoding is invalid"
            ) from exc
    if encoded_size > config.max_header_bytes:
        raise TrustedSessionMintUdsError("mint request headers exceed the byte limit")
    hosts = headers.get_all("Host", failobj=[])
    connections = headers.get_all("Connection", failobj=[])
    if (
        len(hosts) != 1
        or not isinstance(hosts[0], str)
        or _HOST.fullmatch(hosts[0]) is None
        or len(connections) != 1
        or connections[0] != "close"
    ):
        raise TrustedSessionMintUdsError("mint HTTP authority headers are invalid")


class _MintRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OdooAccountingV3SessionMint"
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
        del args
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
        self._send_json(417, _safe_error("session_mint_expectation_rejected"))
        return False

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        del message, explain
        self._send_json(code, _safe_error("session_mint_http_request_rejected"))

    def _send_json(self, status_code: int, value: dict[str, Any]) -> None:
        if self._response_sent:
            self.close_connection = True
            return
        self._response_sent = True
        self.close_connection = True
        self._cancel_io_timer()
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
            body = json.dumps(
                _safe_error("session_mint_response_rejected"),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        if len(body) > self.server.config.max_response_bytes:
            status_code = 500
            body = json.dumps(
                _safe_error("session_mint_response_rejected"),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        self.send_response_only(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionError, OSError):
            pass

    def _reject(self, status_code: int, code: str) -> None:
        self._send_json(status_code, _safe_error(code))

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path not in {MINT_PATH, REVOKE_PATH}:
            self._reject(404, "session_mint_route_rejected")
            return
        if self.request_version != "HTTP/1.1":
            self._reject(400, "session_mint_http_version_rejected")
            return
        try:
            _validate_headers(self.headers, self.server.config)
        except TrustedSessionMintUdsError:
            self._reject(400, "session_mint_headers_rejected")
            return
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            self._reject(400, "session_mint_transfer_encoding_rejected")
            return
        if self.headers.get_all("Content-Encoding", failobj=[]):
            self._reject(415, "session_mint_content_encoding_rejected")
            return
        if self.headers.get_all("Expect", failobj=[]):
            self._reject(417, "session_mint_expectation_rejected")
            return
        content_types = self.headers.get_all("Content-Type", failobj=[])
        if len(content_types) != 1 or content_types[0] not in _ALLOWED_CONTENT_TYPES:
            self._reject(415, "session_mint_content_type_rejected")
            return
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        if (
            len(content_lengths) != 1
            or not isinstance(content_lengths[0], str)
            or not _CONTENT_LENGTH.fullmatch(content_lengths[0])
        ):
            self._reject(411, "session_mint_content_length_rejected")
            return
        content_length = int(content_lengths[0])
        if content_length > self.server.config.max_body_bytes:
            self._reject(413, "session_mint_request_too_large")
            return
        if content_length < 2:
            self._reject(400, "session_mint_json_object_required")
            return
        try:
            body = self.rfile.read(content_length)
        except (TimeoutError, socket.timeout, OSError):
            self._reject(408, "session_mint_request_timeout")
            return
        if self._io_expired:
            self._reject(408, "session_mint_request_timeout")
            return
        if len(body) != content_length:
            self._reject(400, "session_mint_request_body_incomplete")
            return
        deadline = self._accepted_at + self.server.config.request_timeout_seconds
        if monotonic() >= deadline:
            self._reject(408, "session_mint_request_timeout")
            return
        self._cancel_io_timer()
        with monotonic_deadline_scope(deadline):
            if self.path == REVOKE_PATH:
                try:
                    handle = _decode_revoke_request(body)
                    revoked = _revoke_session(self.server.store, handle)
                except MonotonicDeadlineExceeded:
                    self._reject(408, "session_revoke_request_timeout")
                    return
                except TrustedSessionMintUdsError:
                    self._reject(400, "session_revoke_request_rejected")
                    return
                if monotonic() >= deadline:
                    self._reject(408, "session_revoke_request_timeout")
                    return
                if not revoked:
                    self._reject(404, "session_revoke_rejected")
                    return
                self._send_json(200, {"ok": True, "revoked": True})
                return
            try:
                identity = _decode_identity_request(body)
            except TrustedSessionMintUdsError:
                self._reject(400, "session_mint_identity_rejected")
                return
            try:
                issued = _issue_session(self.server.store, self.server.config, identity)
            except MonotonicDeadlineExceeded:
                self._reject(408, "session_mint_request_timeout")
                return
            except Exception:
                self._reject(503, "session_mint_failed")
                return
        if monotonic() >= deadline:
            try:
                self.server.store.revoke_session(
                    issued.session.session_id,
                    reason="mint response deadline exceeded",
                )
            except Exception:
                pass
            self._reject(408, "session_mint_request_timeout")
            return
        self._send_json(
            201,
            {
                "ok": True,
                "session": {
                    "handle": issued.handle,
                    "session_id": issued.session.session_id,
                    "issued_at": issued.session.issued_at.isoformat(
                        timespec="microseconds"
                    ),
                    "expires_at": issued.session.expires_at.isoformat(
                        timespec="microseconds"
                    ),
                    "max_uses": issued.max_uses,
                },
            },
        )

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._reject(405, "session_mint_method_rejected")

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
        # Keep accepted mint/revoke requests joinable during service shutdown.
        daemon_threads = False
        block_on_close = True
        allow_reuse_address = False
        request_queue_size = 8

        def __init__(
            self,
            config: TrustedSessionMintUdsConfig,
            store: SQLiteTrustedSessionStore,
            *,
            bind_and_activate: bool,
        ) -> None:
            if not isinstance(store, SQLiteTrustedSessionStore):
                raise TrustedSessionMintUdsError("trusted session store is invalid")
            self.config = config
            self.store = store
            self._handler_slots = threading.BoundedSemaphore(
                config.max_inflight_requests
            )
            self._credential_lock = threading.Lock()
            self._credentials: dict[int, _PeerCredentials] = {}
            self._cleanup_parent_fd: int | None = None
            self._bound_identity: tuple[int, int] | None = None
            super().__init__(
                config.socket_path,
                _MintRequestHandler,
                bind_and_activate=bind_and_activate,
            )

        def verify_request(self, request: socket.socket, client_address: Any) -> bool:
            del client_address
            try:
                credentials = _peer_credentials(request)
            except (OSError, TrustedSessionMintUdsError):
                return False
            if not _peer_is_allowed(credentials, self.config):
                return False
            with self._credential_lock:
                self._credentials[id(request)] = credentials
            return True

        def take_peer_credentials(self, request: socket.socket) -> _PeerCredentials:
            with self._credential_lock:
                try:
                    return self._credentials.pop(id(request))
                except KeyError as exc:
                    raise TrustedSessionMintUdsError(
                        "verified Odoo issuer credentials are unavailable"
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
            # Fail closed without logging request bodies, handles, or tracebacks.

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
        raise TrustedSessionMintUdsError(
            "trusted session mint transport is supported only on Linux UDS"
        )


def _validate_parent_stat(value: os.stat_result) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or mode & 0o700 != 0o700
        or mode & 0o027
    ):
        raise TrustedSessionMintUdsError(
            "mint socket parent must be a private root-owned real directory"
        )


def _validate_ancestor_stat(value: os.stat_result) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or mode & 0o022
    ):
        raise TrustedSessionMintUdsError(
            "mint socket ancestors must be root-owned real directories without "
            "group/world write access"
        )


def _open_secure_parent(config: TrustedSessionMintUdsConfig) -> int:
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
                metadata = os.fstat(next_fd)
                if index == len(parts) - 1:
                    _validate_parent_stat(metadata)
                else:
                    _validate_ancestor_stat(metadata)
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
            raise TrustedSessionMintUdsError(
                "mint socket parent is unavailable"
            ) from exc
        raise


def _validate_socket_stat(
    value: os.stat_result,
    config: TrustedSessionMintUdsConfig,
) -> None:
    if (
        not stat.S_ISSOCK(value.st_mode)
        or value.st_uid != 0
        or value.st_gid != config.socket_group_gid
        or stat.S_IMODE(value.st_mode) != config.socket_mode
    ):
        raise TrustedSessionMintUdsError(
            "mint socket has untrusted owner, group, mode, or type"
        )


def _stat_socket_at(parent_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def _unlink_socket_at(parent_fd: int, name: str) -> None:
    os.unlink(name, dir_fd=parent_fd)


def _remove_verified_stale_socket(
    parent_fd: int,
    config: TrustedSessionMintUdsConfig,
) -> None:
    name = PurePosixPath(config.socket_path).name
    try:
        initial = _stat_socket_at(parent_fd, name)
    except FileNotFoundError:
        return
    _validate_socket_stat(initial, config)
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(min(float(config.request_timeout_seconds), 0.25))
        try:
            probe.connect(config.socket_path)
        except OSError as exc:
            if exc.errno != errno.ECONNREFUSED:
                raise TrustedSessionMintUdsError(
                    "existing mint socket could not be proven stale"
                ) from exc
        else:
            raise TrustedSessionMintUdsError(
                "another trusted session mint server is active"
            )
    finally:
        probe.close()
    try:
        current = _stat_socket_at(parent_fd, name)
    except FileNotFoundError as exc:
        raise TrustedSessionMintUdsError(
            "mint socket changed during stale-socket verification"
        ) from exc
    _validate_socket_stat(current, config)
    if (initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino):
        raise TrustedSessionMintUdsError(
            "mint socket changed during stale-socket verification"
        )
    _unlink_socket_at(parent_fd, name)


def _configure_bound_socket(
    parent_fd: int,
    config: TrustedSessionMintUdsConfig,
) -> tuple[int, int]:
    name = PurePosixPath(config.socket_path).name
    created = _stat_socket_at(parent_fd, name)
    if not stat.S_ISSOCK(created.st_mode) or created.st_uid != 0:
        raise TrustedSessionMintUdsError(
            "mint bind did not create a root-owned Unix socket"
        )
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
        raise TrustedSessionMintUdsError(
            "mint socket changed during secure setup"
        )
    return identity


def create_trusted_session_mint_uds_server(
    config: TrustedSessionMintUdsConfig,
    store: SQLiteTrustedSessionStore,
) -> Any:
    """Bind and activate the root-controlled, UDS-only mint service."""

    _require_linux()
    if os.geteuid() != 0:
        raise TrustedSessionMintUdsError(
            "trusted session mint UDS binding requires root"
        )
    if not isinstance(config, TrustedSessionMintUdsConfig):
        raise TrustedSessionMintUdsError("trusted session mint config is invalid")
    if not isinstance(store, SQLiteTrustedSessionStore):
        raise TrustedSessionMintUdsError("trusted session store is invalid")
    if (
        config.session_ttl_seconds > store.max_ttl_seconds
        or config.session_max_uses > store.max_session_uses
    ):
        raise TrustedSessionMintUdsError(
            "root mint limits exceed the durable session store limits"
        )
    parent_fd = _open_secure_parent(config)
    server: Any | None = None
    try:
        _remove_verified_stale_socket(parent_fd, config)
        server = _TrustedUnixHTTPServer(
            config,
            store,
            bind_and_activate=False,
        )
        server.server_bind()
        name = PurePosixPath(config.socket_path).name
        created = _stat_socket_at(parent_fd, name)
        if not stat.S_ISSOCK(created.st_mode):
            raise TrustedSessionMintUdsError(
                "mint bind did not create a Unix socket"
            )
        server.attach_secure_path(
            parent_fd,
            (created.st_dev, created.st_ino),
        )
        parent_fd = -1
        identity = _configure_bound_socket(server._cleanup_parent_fd, config)
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


def create_trusted_session_mint_uds_server_from_fd(
    config: TrustedSessionMintUdsConfig,
    store: SQLiteTrustedSessionStore,
    descriptor: int,
) -> Any:
    """Adopt one root-created systemd socket while running as non-root."""

    _require_linux()
    if os.geteuid() == 0:
        raise TrustedSessionMintUdsError(
            "activated session mint server must run under a dedicated non-root UID"
        )
    if not isinstance(store, SQLiteTrustedSessionStore):
        raise TrustedSessionMintUdsError("trusted session store is invalid")
    if (
        config.session_ttl_seconds > store.max_ttl_seconds
        or config.session_max_uses > store.max_session_uses
    ):
        raise TrustedSessionMintUdsError(
            "root mint limits exceed the durable session store limits"
        )
    server = _TrustedUnixHTTPServer(
        config,
        store,
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
        raise TrustedSessionMintUdsError(
            "activated session mint socket was rejected"
        ) from exc


def serve_trusted_session_mint_uds(
    config: TrustedSessionMintUdsConfig,
    store: SQLiteTrustedSessionStore,
) -> None:
    """Serve until interrupted; production callers should use systemd."""

    server = create_trusted_session_mint_uds_server(config, store)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


__all__ = [
    "MINT_PATH",
    "REVOKE_PATH",
    "SAME_UID_THREAT",
    "TrustedSessionMintUdsConfig",
    "TrustedSessionMintUdsError",
    "create_trusted_session_mint_uds_server",
    "create_trusted_session_mint_uds_server_from_fd",
    "serve_trusted_session_mint_uds",
]

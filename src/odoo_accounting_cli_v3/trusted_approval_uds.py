"""Root-configured Linux UDS boundary for independent Odoo approval calls.

Exactly three routes are exposed: ``POST /v1/approval/request``,
``POST /v1/approval/inspect``, and ``POST /v1/approval/decide``.  Linux
``SO_PEERCRED`` admits only the Odoo client UID selected by the root-owned
launcher.  Pi Bridge must use a different Unix UID and cannot use this channel
directly.

The request contract contains only an opaque trusted-session handle and the
business operation/challenge decision fields.  User, company, release,
registry, runtime, and signing authority are resolved by the injected trusted
broker.  Broker results are reconstructed as an exact, unsigned challenge
view; an unexpected field (including any approval or signature) rejects the
whole response.

``SO_PEERCRED`` authenticates a Unix UID, not an Odoo worker or PID.  Processes
sharing the configured Odoo UID cannot be distinguished.  UID, PID, and GID
are passed to the broker as transport-observed immutable audit facts; PID and
GID never participate in authorization.

This module provides no TCP listener and emits no access log, request body,
opaque handle, backend exception, or approval material.
"""

from __future__ import annotations

import errno
import hashlib
import http.client
import hmac
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
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler
from pathlib import PurePosixPath
from time import monotonic
from typing import Any, Final, Protocol

from .monotonic_deadline import (
    copy_monotonic_deadline_context,
    monotonic_deadline_scope,
)
from .operations import MAX_APPROVAL_TTL, State, canonical_json, operation_digest
from .trusted_authority import ApprovalDecision
from .trusted_broker import TrustedBrokerError


APPROVAL_REQUEST_PATH: Final = "/v1/approval/request"
APPROVAL_INSPECT_PATH: Final = "/v1/approval/inspect"
APPROVAL_DECIDE_PATH: Final = "/v1/approval/decide"
SAME_UID_THREAT: Final = (
    "Linux SO_PEERCRED cannot distinguish processes that share the configured "
    "Odoo client UID. Odoo and Pi Bridge must run under different Unix UIDs and "
    "both must be unprivileged; Pi Bridge must not retain CAP_SETUID or be able "
    "to execute code as, switch to, or inject into the Odoo UID."
)

_ACTION_BY_PATH: Final = {
    APPROVAL_REQUEST_PATH: "approval.request",
    APPROVAL_INSPECT_PATH: "approval.inspect",
    APPROVAL_DECIDE_PATH: "approval.decide",
}
_REQUEST_FIELDS: Final = frozenset({"session_handle", "operation_id"})
_INSPECT_FIELDS: Final = frozenset({"session_handle", "challenge_id"})
_DECIDE_FIELDS: Final = frozenset(
    {"session_handle", "challenge_id", "decision", "reason"}
)
_CHALLENGE_VIEW_FIELDS: Final = frozenset(
    {
        "capability_id",
        "challenge_id",
        "company_id",
        "expires_at",
        "issued_at",
        "operation_digest",
        "operation_id",
        "precheck_digest",
        "requester_user_id",
        "state",
    }
)
_CHALLENGE_STATES: Final = frozenset(
    {"pending", "approved", "denied", "expired", "stale"}
)
_INSPECTION_FIELDS: Final = frozenset(
    {
        "schema_version",
        "challenge",
        "operation",
        "summary",
        "preview_digest",
        "precheck",
        "inspection_digest",
    }
)
_INSPECTION_CHALLENGE_FIELDS: Final = frozenset(
    {
        "challenge_id",
        "binding_digest",
        "issued_at",
        "expires_at",
        "ttl_seconds",
        "state",
        "version",
    }
)
_INSPECTION_OPERATION_FIELDS: Final = frozenset(
    {
        "operation_id",
        "request_id",
        "capability_id",
        "parameters",
        "parameters_digest",
        "principal",
        "user_id",
        "company_id",
        "idempotency_key",
        "odoo_instance_id",
        "database_name",
        "database_uuid",
        "environment",
        "registry_digest",
        "release_digest",
        "operation_digest",
        "precheck_digest",
        "state",
        "revision",
        "protocol_version",
    }
)
_INSPECTION_SUMMARY_FIELDS: Final = frozenset(
    {
        "binding_digest",
        "capability_id",
        "challenge_id",
        "company_id",
        "operation_digest",
        "operation_id",
        "parameters_digest",
        "precheck_digest",
        "requester_principal",
        "requester_user_id",
    }
)
_INSPECTION_PRECHECK_FIELDS: Final = frozenset(
    {
        "operation_id",
        "request_id",
        "operation_digest",
        "operation_revision",
        "source_operation_revision",
        "principal",
        "user_id",
        "company_id",
        "evidence_digest",
        "occurred_at",
        "evidence",
    }
)
_FORBIDDEN_INSPECTION_KEYS: Final = frozenset(
    {
        "approval",
        "approval_nonce_digest",
        "approval_signature",
        "approver_user_id",
        "auth_key_id",
        "auth_signature",
        "auth_token_id",
        "deadline_monotonic",
        "nonce",
        "session_handle",
        "signature",
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
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SESSION_HANDLE = re.compile(r"[A-Za-z0-9._~-]{32,512}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SOCKET_PATH = re.compile(r"/[A-Za-z0-9._/-]+\Z")
_SOCKET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.sock\Z")
_PEER_CREDENTIAL_FORMAT: Final = "iII"
_PEER_CREDENTIAL_SIZE: Final = struct.calcsize(_PEER_CREDENTIAL_FORMAT)
_MAX_LINUX_ID: Final = 2**32 - 2


class TrustedApprovalUdsError(RuntimeError):
    """The approval UDS boundary rejected configuration or request state."""


_BROKER_RECONCILIATION_CODES: Final = {
    "broker_session_reconciliation_required": (
        "approval_session_reconciliation_required"
    ),
    "broker_authority_reconciliation_required": (
        "approval_authority_reconciliation_required"
    ),
}
_APPROVAL_RECONCILIATION_CODES: Final = frozenset(
    {
        *_BROKER_RECONCILIATION_CODES.values(),
        "approval_broker_outcome_unknown",
    }
)
_SAFE_BROKER_REJECTIONS_BY_ACTION: Final = {
    "approval.request": frozenset(
        {
            "broker_approval_peer_rejected",
            "broker_approval_rejected",
            "broker_session_rejected",
        }
    ),
    "approval.inspect": frozenset(
        {
            "broker_approval_challenge_rejected",
            "broker_approval_peer_rejected",
            "broker_approval_precheck_rejected",
            "broker_approval_preview_rejected",
            "broker_approval_rejected",
            "broker_session_rejected",
        }
    ),
    "approval.decide": frozenset(
        {
            "broker_approval_challenge_rejected",
            "broker_approval_peer_rejected",
            "broker_approval_rejected",
            "broker_session_rejected",
        }
    ),
}


class _TrustedApprovalReconciliationRequired(TrustedApprovalUdsError):
    """The broker consumed trusted state with a non-replayable outcome."""

    def __init__(self, code: str) -> None:
        if code not in _APPROVAL_RECONCILIATION_CODES:
            code = "approval_broker_outcome_unknown"
        super().__init__("trusted approval broker rejected request")
        self.code = code


class _TrustedApprovalBrokerRejected(TrustedApprovalUdsError):
    """The broker authoritatively rejected a request without a durable effect."""

    def __init__(self) -> None:
        super().__init__("trusted approval broker rejected request")


class TrustedApprovalBroker(Protocol):
    """Only the three unsigned approval methods exposed by ``TrustedBroker``."""

    def request_approval(
        self,
        *,
        session_handle: str,
        operation_id: str,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]: ...

    def decide_approval(
        self,
        *,
        session_handle: str,
        challenge_id: str,
        decision: ApprovalDecision,
        reason: str | None = None,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]: ...

    def inspect_approval(
        self,
        *,
        session_handle: str,
        challenge_id: str,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class TrustedApprovalUdsConfig:
    """Immutable settings supplied by the root-owned approval launcher."""

    socket_path: str
    odoo_client_uid: int
    pi_bridge_uid: int
    socket_group_gid: int
    socket_mode: int = 0o660
    max_body_bytes: int = 8192
    max_response_bytes: int = 1024 * 1024
    max_header_bytes: int = 4096
    max_header_count: int = 8
    max_inflight_broker_calls: int = 4
    request_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not isinstance(self.socket_path, str):
            raise TrustedApprovalUdsError("approval socket path must be a string")
        if (
            not _SOCKET_PATH.fullmatch(self.socket_path)
            or "\x00" in self.socket_path
            or not self.socket_path.isascii()
        ):
            raise TrustedApprovalUdsError(
                "approval socket path must be an absolute ASCII POSIX path"
            )
        parsed = PurePosixPath(self.socket_path)
        if (
            not parsed.is_absolute()
            or self.socket_path.startswith("//")
            or str(parsed) != self.socket_path
            or any(part in {".", ".."} for part in parsed.parts)
            or not _SOCKET_NAME.fullmatch(parsed.name)
            or len(self.socket_path.encode("ascii")) > 107
        ):
            raise TrustedApprovalUdsError("approval socket path is not canonical")
        for value, label in (
            (self.odoo_client_uid, "Odoo client UID"),
            (self.pi_bridge_uid, "Pi Bridge UID"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= _MAX_LINUX_ID
            ):
                raise TrustedApprovalUdsError(
                    f"{label} must be an unprivileged Linux UID"
                )
        if (
            isinstance(self.socket_group_gid, bool)
            or not isinstance(self.socket_group_gid, int)
            or not 0 <= self.socket_group_gid <= _MAX_LINUX_ID
        ):
            raise TrustedApprovalUdsError(
                "socket group GID is not a valid Linux ID"
            )
        if self.pi_bridge_uid == self.odoo_client_uid:
            raise TrustedApprovalUdsError(
                "Pi Bridge must run under a different UID from the Odoo client; "
                "same-UID processes cannot be distinguished by SO_PEERCRED"
            )
        if (
            isinstance(self.socket_mode, bool)
            or not isinstance(self.socket_mode, int)
            or self.socket_mode & ~0o777
            or self.socket_mode & 0o007
            or self.socket_mode & 0o600 != 0o600
        ):
            raise TrustedApprovalUdsError(
                "approval socket mode must grant owner read/write and no world access"
            )
        if (
            isinstance(self.max_body_bytes, bool)
            or not isinstance(self.max_body_bytes, int)
            or not 256 <= self.max_body_bytes <= 64 * 1024
        ):
            raise TrustedApprovalUdsError(
                "approval request body limit is outside the safe range"
            )
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 512 <= self.max_response_bytes <= 4 * 1024 * 1024
        ):
            raise TrustedApprovalUdsError(
                "approval response limit is outside the safe range"
            )
        if (
            isinstance(self.max_header_bytes, bool)
            or not isinstance(self.max_header_bytes, int)
            or not 1024 <= self.max_header_bytes <= 32 * 1024
        ):
            raise TrustedApprovalUdsError(
                "approval request header byte limit is outside the safe range"
            )
        if (
            isinstance(self.max_header_count, bool)
            or not isinstance(self.max_header_count, int)
            or not 4 <= self.max_header_count <= 32
        ):
            raise TrustedApprovalUdsError(
                "approval request header count is outside the safe range"
            )
        if (
            isinstance(self.max_inflight_broker_calls, bool)
            or not isinstance(self.max_inflight_broker_calls, int)
            or not 1 <= self.max_inflight_broker_calls <= 32
        ):
            raise TrustedApprovalUdsError(
                "approval in-flight broker call limit is outside the safe range"
            )
        if (
            isinstance(self.request_timeout_seconds, bool)
            or not isinstance(self.request_timeout_seconds, (int, float))
            or not math.isfinite(float(self.request_timeout_seconds))
            or not 0.05 <= float(self.request_timeout_seconds) <= 30.0
        ):
            raise TrustedApprovalUdsError(
                "approval request timeout is outside the safe range"
            )


@dataclass(frozen=True, slots=True, repr=False)
class _ApprovalCall:
    action: str
    session_handle: str
    operation_id: str | None = None
    challenge_id: str | None = None
    decision: ApprovalDecision | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class _PeerCredentials:
    pid: int
    uid: int
    gid: int


class _DuplicateJsonKey(ValueError):
    pass


class _RequestLineLimitedReader:
    """Limit the request line before ``BaseHTTPRequestHandler`` can read 64 KiB."""

    def __init__(self, raw: Any, *, max_bytes: int) -> None:
        self._raw = raw
        self._max_bytes = max_bytes
        self._first_line = True

    def readline(self, limit: int = -1) -> bytes:
        if not self._first_line:
            return self._raw.readline(limit)
        self._first_line = False
        bounded_limit = self._max_bytes + 1
        if limit >= 0:
            bounded_limit = min(bounded_limit, limit)
        return self._raw.readline(bounded_limit)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


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
            raise http.client.LineTooLong("trusted approval request headers")
        bounded_limit = remaining + 1
        if limit >= 0:
            bounded_limit = min(bounded_limit, limit)
        line = self._raw.readline(bounded_limit)
        self._bytes_read += len(line)
        if self._bytes_read > self._max_bytes:
            raise http.client.LineTooLong("trusted approval request headers")
        if line in {b"\r\n", b"\n", b""}:
            self._complete = True
            return line
        self._lines_read += 1
        if self._lines_read > self._max_count:
            raise http.client.HTTPException(
                "too many trusted approval request headers"
            )
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


def _decode_json_object(body: bytes) -> dict[str, Any]:
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
        raise TrustedApprovalUdsError(
            "approval request body is not strict JSON"
        ) from exc
    if type(value) is not dict:
        raise TrustedApprovalUdsError("approval request body must be a JSON object")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise TrustedApprovalUdsError(f"approval {label} is invalid")
    return value


def _session_handle(value: object) -> str:
    if not isinstance(value, str) or _SESSION_HANDLE.fullmatch(value) is None:
        raise TrustedApprovalUdsError("opaque trusted-session handle is invalid")
    return value


def _denial_reason(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TrustedApprovalUdsError("approval denial reason is invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise TrustedApprovalUdsError("approval denial reason is invalid") from exc
    if len(encoded) > 2048:
        raise TrustedApprovalUdsError("approval denial reason is invalid")
    return value


def _decode_call(path: str, body: bytes) -> _ApprovalCall:
    """Decode one exact business-only approval call."""

    action = _ACTION_BY_PATH.get(path)
    if action is None:
        raise TrustedApprovalUdsError("approval route is invalid")
    value = _decode_json_object(body)
    expected = {
        "approval.request": _REQUEST_FIELDS,
        "approval.inspect": _INSPECT_FIELDS,
        "approval.decide": _DECIDE_FIELDS,
    }[action]
    if set(value) != expected:
        raise TrustedApprovalUdsError(
            "approval request must contain the exact approval request fields"
        )
    handle = _session_handle(value["session_handle"])
    if action == "approval.request":
        return _ApprovalCall(
            action=action,
            session_handle=handle,
            operation_id=_identifier(value["operation_id"], "operation ID"),
        )
    if action == "approval.inspect":
        return _ApprovalCall(
            action=action,
            session_handle=handle,
            challenge_id=_identifier(value["challenge_id"], "challenge ID"),
        )
    challenge_id = _identifier(value["challenge_id"], "challenge ID")
    raw_decision = value["decision"]
    try:
        decision = ApprovalDecision(raw_decision)
    except (TypeError, ValueError) as exc:
        raise TrustedApprovalUdsError("approval decision is invalid") from exc
    raw_reason = value["reason"]
    if decision is ApprovalDecision.APPROVE:
        if raw_reason is not None:
            raise TrustedApprovalUdsError(
                "approval reason is only valid for denial"
            )
        reason = None
    else:
        reason = _denial_reason(raw_reason)
    return _ApprovalCall(
        action=action,
        session_handle=handle,
        challenge_id=challenge_id,
        decision=decision,
        reason=reason,
    )


def _utc_timestamp(value: object, label: str) -> tuple[str, datetime]:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not 20 <= len(value) <= 40
    ):
        raise TrustedApprovalUdsError(f"approval {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TrustedApprovalUdsError(f"approval {label} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timedelta(0)
        or parsed.isoformat() != value
    ):
        raise TrustedApprovalUdsError(f"approval {label} is invalid")
    return value, parsed


def _sanitize_challenge_view(value: object) -> dict[str, Any]:
    """Reconstruct the exact unsigned broker view; never filter-and-forward."""

    if type(value) is not dict or set(value) != _CHALLENGE_VIEW_FIELDS:
        raise TrustedApprovalUdsError("trusted approval broker view is invalid")
    capability_id = _identifier(value["capability_id"], "capability ID")
    challenge_id = _identifier(value["challenge_id"], "challenge ID")
    operation_id = _identifier(value["operation_id"], "operation ID")
    for field in ("company_id", "requester_user_id"):
        if type(value[field]) is not int or value[field] <= 0:
            raise TrustedApprovalUdsError("trusted approval broker view is invalid")
    for field in ("operation_digest", "precheck_digest"):
        if not isinstance(value[field], str) or _SHA256.fullmatch(value[field]) is None:
            raise TrustedApprovalUdsError("trusted approval broker view is invalid")
    issued_at, issued = _utc_timestamp(value["issued_at"], "issued time")
    expires_at, expires = _utc_timestamp(value["expires_at"], "expiry time")
    if expires <= issued:
        raise TrustedApprovalUdsError("trusted approval broker view is invalid")
    state = value["state"]
    if not isinstance(state, str) or state not in _CHALLENGE_STATES:
        raise TrustedApprovalUdsError("trusted approval broker view is invalid")
    return {
        "capability_id": capability_id,
        "challenge_id": challenge_id,
        "company_id": value["company_id"],
        "expires_at": expires_at,
        "issued_at": issued_at,
        "operation_digest": value["operation_digest"],
        "operation_id": operation_id,
        "precheck_digest": value["precheck_digest"],
        "requester_user_id": value["requester_user_id"],
        "state": state,
    }


def _inspection_rejected() -> None:
    raise TrustedApprovalUdsError("trusted approval inspection is invalid")


def _inspection_text(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _inspection_rejected()
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        _inspection_rejected()
    if len(encoded) > 2048:
        _inspection_rejected()
    return value


def _inspection_identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _inspection_rejected()
    return value


def _inspection_sha256(value: object) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _inspection_rejected()
    return value


def _inspection_digest(value: object) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (RecursionError, TypeError, ValueError, UnicodeError):
        _inspection_rejected()


def _inspection_contains_authority(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                isinstance(key, str)
                and key.lower().replace("-", "_") in _FORBIDDEN_INSPECTION_KEYS
            ):
                return True
            if _inspection_contains_authority(child):
                return True
    elif isinstance(value, list):
        return any(_inspection_contains_authority(child) for child in value)
    return False


def _canonical_inspection(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        _inspection_rejected()
    try:
        detached = json.loads(canonical_json(value))
    except (
        RecursionError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ):
        _inspection_rejected()
    if (
        type(detached) is not dict
        or detached != value
        or _inspection_contains_authority(detached)
    ):
        _inspection_rejected()
    return detached


def _sanitize_inspection(value: object) -> dict[str, Any]:
    """Rebuild and independently verify one complete authoritative preview."""

    inspection = _canonical_inspection(value)
    if set(inspection) != _INSPECTION_FIELDS or inspection["schema_version"] != 1:
        _inspection_rejected()
    challenge = inspection["challenge"]
    operation = inspection["operation"]
    summary = inspection["summary"]
    precheck = inspection["precheck"]
    if (
        type(challenge) is not dict
        or set(challenge) != _INSPECTION_CHALLENGE_FIELDS
        or type(operation) is not dict
        or set(operation) != _INSPECTION_OPERATION_FIELDS
        or type(summary) is not dict
        or set(summary) != _INSPECTION_SUMMARY_FIELDS
        or type(precheck) is not dict
        or set(precheck) != _INSPECTION_PRECHECK_FIELDS
    ):
        _inspection_rejected()

    challenge_id = _inspection_identifier(challenge["challenge_id"])
    binding_digest = _inspection_sha256(challenge["binding_digest"])
    try:
        issued_at, issued = _utc_timestamp(challenge["issued_at"], "issued time")
        expires_at, expires = _utc_timestamp(
            challenge["expires_at"], "expiry time"
        )
    except TrustedApprovalUdsError:
        _inspection_rejected()
    ttl_seconds = challenge["ttl_seconds"]
    version = challenge["version"]
    state = challenge["state"]
    if (
        type(ttl_seconds) is not int
        or not 1 <= ttl_seconds <= int(MAX_APPROVAL_TTL.total_seconds())
        or expires <= issued
        or expires - issued > timedelta(seconds=ttl_seconds)
        or type(version) is not int
        or version < 0
        or not isinstance(state, str)
        or state not in _CHALLENGE_STATES
    ):
        _inspection_rejected()
    rebuilt_challenge = {
        "challenge_id": challenge_id,
        "binding_digest": binding_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "ttl_seconds": ttl_seconds,
        "state": state,
        "version": version,
    }

    operation_id = _inspection_identifier(operation["operation_id"])
    request_id = _inspection_identifier(operation["request_id"])
    capability_id = _inspection_identifier(operation["capability_id"])
    idempotency_key = _inspection_identifier(operation["idempotency_key"])
    principal = _inspection_text(operation["principal"])
    odoo_instance_id = _inspection_text(operation["odoo_instance_id"])
    database_name = _inspection_text(operation["database_name"])
    database_uuid = _inspection_text(operation["database_uuid"])
    try:
        if str(uuid.UUID(database_uuid)) != database_uuid:
            _inspection_rejected()
    except (AttributeError, TypeError, ValueError):
        _inspection_rejected()
    environment = operation["environment"]
    parameters = operation["parameters"]
    user_id = operation["user_id"]
    company_id = operation["company_id"]
    revision = operation["revision"]
    protocol_version = operation["protocol_version"]
    operation_state = operation["state"]
    if (
        type(parameters) is not dict
        or type(user_id) is not int
        or user_id <= 0
        or type(company_id) is not int
        or company_id <= 0
        or type(revision) is not int
        or revision < 2
        or protocol_version != 4
        or operation_state != State.AWAITING_APPROVAL.value
        or environment not in {"test", "sandbox", "production"}
    ):
        _inspection_rejected()
    parameters_digest = _inspection_sha256(operation["parameters_digest"])
    registry_digest = _inspection_sha256(operation["registry_digest"])
    release_digest = _inspection_sha256(operation["release_digest"])
    trusted_operation_digest = _inspection_sha256(operation["operation_digest"])
    precheck_digest = _inspection_sha256(operation["precheck_digest"])
    expected_parameters_digest = _inspection_digest(parameters)
    try:
        expected_operation_digest = operation_digest(
            capability_id=capability_id,
            parameters=parameters,
            principal=principal,
            user_id=user_id,
            company_id=company_id,
            idempotency_key=idempotency_key,
            odoo_instance_id=odoo_instance_id,
            database_name=database_name,
            database_uuid=database_uuid,
            environment=environment,
            registry_digest=registry_digest,
            release_digest=release_digest,
        )
    except Exception:
        _inspection_rejected()
    if not (
        hmac.compare_digest(parameters_digest, expected_parameters_digest)
        and hmac.compare_digest(
            trusted_operation_digest, expected_operation_digest
        )
    ):
        _inspection_rejected()
    rebuilt_operation = {
        "operation_id": operation_id,
        "request_id": request_id,
        "capability_id": capability_id,
        "parameters": parameters,
        "parameters_digest": parameters_digest,
        "principal": principal,
        "user_id": user_id,
        "company_id": company_id,
        "idempotency_key": idempotency_key,
        "odoo_instance_id": odoo_instance_id,
        "database_name": database_name,
        "database_uuid": database_uuid,
        "environment": environment,
        "registry_digest": registry_digest,
        "release_digest": release_digest,
        "operation_digest": trusted_operation_digest,
        "precheck_digest": precheck_digest,
        "state": operation_state,
        "revision": revision,
        "protocol_version": protocol_version,
    }

    expected_binding_digest = _inspection_digest(
        {
            "company_id": company_id,
            "database_name": database_name,
            "database_uuid": database_uuid,
            "environment": environment,
            "odoo_instance_id": odoo_instance_id,
            "operation_digest": trusted_operation_digest,
            "operation_id": operation_id,
            "operation_revision": revision,
            "precheck_digest": precheck_digest,
            "principal": principal,
            "request_id": request_id,
            "user_id": user_id,
        }
    )
    expected_summary = {
        "binding_digest": binding_digest,
        "capability_id": capability_id,
        "challenge_id": challenge_id,
        "company_id": company_id,
        "operation_digest": trusted_operation_digest,
        "operation_id": operation_id,
        "parameters_digest": parameters_digest,
        "precheck_digest": precheck_digest,
        "requester_principal": principal,
        "requester_user_id": user_id,
    }
    if not hmac.compare_digest(
        binding_digest, expected_binding_digest
    ) or summary != expected_summary:
        _inspection_rejected()
    rebuilt_summary = dict(expected_summary)
    preview_core = {
        "schema_version": 1,
        "challenge": rebuilt_challenge,
        "operation": rebuilt_operation,
        "summary": rebuilt_summary,
    }
    preview_digest = _inspection_sha256(inspection["preview_digest"])
    if not hmac.compare_digest(preview_digest, _inspection_digest(preview_core)):
        _inspection_rejected()

    evidence = precheck["evidence"]
    if type(evidence) is not dict:
        _inspection_rejected()
    evidence_digest = _inspection_sha256(precheck["evidence_digest"])
    if not (
        precheck["operation_id"] == operation_id
        and precheck["request_id"] == request_id
        and precheck["operation_digest"] == trusted_operation_digest
        and type(precheck["operation_revision"]) is int
        and precheck["operation_revision"] == revision
        and type(precheck["source_operation_revision"]) is int
        and precheck["source_operation_revision"] == revision - 2
        and precheck["principal"] == principal
        and precheck["user_id"] == user_id
        and precheck["company_id"] == company_id
        and hmac.compare_digest(evidence_digest, precheck_digest)
        and hmac.compare_digest(evidence_digest, _inspection_digest(evidence))
    ):
        _inspection_rejected()
    try:
        occurred_at, occurred = _utc_timestamp(
            precheck["occurred_at"], "precheck time"
        )
    except TrustedApprovalUdsError:
        _inspection_rejected()
    if occurred > issued:
        _inspection_rejected()

    evidence_core_fields = {"capability_id", "company_id", "parameters_digest"}
    present_core_fields = set(evidence).intersection(evidence_core_fields)
    if present_core_fields and (
        present_core_fields != evidence_core_fields
        or evidence["capability_id"] != capability_id
        or evidence["company_id"] != company_id
        or evidence["parameters_digest"] != parameters_digest
    ):
        _inspection_rejected()
    evidence_release_fields = {"release_digest", "registry_digest"}
    present_release_fields = set(evidence).intersection(evidence_release_fields)
    if present_release_fields and (
        present_release_fields != evidence_release_fields
        or evidence["release_digest"] != release_digest
        or evidence["registry_digest"] != registry_digest
    ):
        _inspection_rejected()
    if "runtime_binding" in evidence:
        runtime_binding = evidence["runtime_binding"]
        expected_runtime = {
            "user_id": user_id,
            "odoo_instance_id": odoo_instance_id,
            "database_name": database_name,
            "database_uuid": database_uuid,
            "environment": environment,
        }
        if type(runtime_binding) is not dict or any(
            runtime_binding.get(field) != expected
            for field, expected in expected_runtime.items()
        ):
            _inspection_rejected()

    rebuilt_precheck = {
        "operation_id": operation_id,
        "request_id": request_id,
        "operation_digest": trusted_operation_digest,
        "operation_revision": revision,
        "source_operation_revision": revision - 2,
        "principal": principal,
        "user_id": user_id,
        "company_id": company_id,
        "evidence_digest": evidence_digest,
        "occurred_at": occurred_at,
        "evidence": evidence,
    }
    unsigned_inspection = {
        **preview_core,
        "preview_digest": preview_digest,
        "precheck": rebuilt_precheck,
    }
    inspection_digest = _inspection_sha256(inspection["inspection_digest"])
    if not hmac.compare_digest(
        inspection_digest, _inspection_digest(unsigned_inspection)
    ):
        _inspection_rejected()
    rebuilt = {**unsigned_inspection, "inspection_digest": inspection_digest}
    return json.loads(canonical_json(rebuilt))


def _broker_contract_is_valid(broker: object) -> bool:
    return (
        callable(getattr(broker, "request_approval", None))
        and callable(getattr(broker, "inspect_approval", None))
        and callable(getattr(broker, "decide_approval", None))
    )


def _invoke_broker(
    broker: TrustedApprovalBroker,
    call: _ApprovalCall,
    *,
    peer: _PeerCredentials | None = None,
) -> dict[str, Any]:
    """Invoke only the fixed broker methods and erase every backend failure."""

    view: dict[str, Any] | None = None
    known_rejection = False
    reconciliation_code: str | None = None
    try:
        if not _broker_contract_is_valid(broker):
            raise TypeError("invalid trusted approval broker")
        peer_kwargs: dict[str, int] = {}
        if peer is not None:
            trusted_peer = _validated_peer_credentials(peer)
            peer_kwargs = {
                "peer_uid": trusted_peer.uid,
                "peer_gid": trusted_peer.gid,
                "peer_pid": trusted_peer.pid,
            }
        if call.action == "approval.request":
            if call.operation_id is None:
                raise TypeError("invalid approval request")
            raw = broker.request_approval(
                session_handle=call.session_handle,
                operation_id=call.operation_id,
                **peer_kwargs,
            )
        elif call.action == "approval.inspect":
            if call.challenge_id is None:
                raise TypeError("invalid approval inspection")
            raw = broker.inspect_approval(
                session_handle=call.session_handle,
                challenge_id=call.challenge_id,
                **peer_kwargs,
            )
        elif call.action == "approval.decide":
            if call.challenge_id is None or call.decision is None:
                raise TypeError("invalid approval decision")
            raw = broker.decide_approval(
                session_handle=call.session_handle,
                challenge_id=call.challenge_id,
                decision=call.decision,
                reason=call.reason,
                **peer_kwargs,
            )
        else:
            raise TypeError("invalid approval action")
        if call.action == "approval.inspect":
            view = _sanitize_inspection(raw)
            if view["challenge"]["challenge_id"] != call.challenge_id:
                raise ValueError("approval response inspection mismatch")
        else:
            view = _sanitize_challenge_view(raw)
        if call.action == "approval.request":
            if view["operation_id"] != call.operation_id:
                raise ValueError("approval response operation mismatch")
        elif call.action == "approval.decide":
            expected_state = (
                "approved"
                if call.decision is ApprovalDecision.APPROVE
                else "denied"
            )
            if (
                view["challenge_id"] != call.challenge_id
                or view["state"] != expected_state
            ):
                raise ValueError("approval response decision mismatch")
    except TrustedBrokerError as exc:
        if (
            exc.reconciliation_required is True
            and exc.retryable is False
            and exc.odoo_effect == "none"
        ):
            reconciliation_code = _BROKER_RECONCILIATION_CODES.get(
                exc.code, "approval_broker_outcome_unknown"
            )
        elif (
            exc.odoo_effect == "none"
            and exc.retryable is False
            and exc.code in _SAFE_BROKER_REJECTIONS_BY_ACTION[call.action]
        ):
            known_rejection = True
        else:
            reconciliation_code = "approval_broker_outcome_unknown"
    except Exception:
        reconciliation_code = "approval_broker_outcome_unknown"
    if reconciliation_code is not None:
        raise _TrustedApprovalReconciliationRequired(
            reconciliation_code
        ) from None
    if known_rejection:
        raise _TrustedApprovalBrokerRejected from None
    if view is None:
        raise _TrustedApprovalReconciliationRequired(
            "approval_broker_outcome_unknown"
        ) from None
    return view


@dataclass(frozen=True, slots=True)
class _BrokerInvocation:
    status: str
    view: dict[str, Any] | None
    reconciliation_code: str | None = None


class _BoundedBrokerInvoker:
    """Run broker calls behind a hard concurrency and absolute-time boundary.

    Python cannot safely kill a thread that is already inside durable broker
    code.  A timed-out call may therefore finish later, but at most
    ``max_inflight`` such calls can exist.  No timed-out call is ever reported
    as successful and no queued call is allowed to start after its deadline.
    """

    def __init__(self, broker: TrustedApprovalBroker, *, max_inflight: int) -> None:
        if not _broker_contract_is_valid(broker):
            raise TrustedApprovalUdsError("trusted approval broker is invalid")
        if (
            isinstance(max_inflight, bool)
            or not isinstance(max_inflight, int)
            or not 1 <= max_inflight <= 32
        ):
            raise TrustedApprovalUdsError(
                "approval in-flight broker call limit is invalid"
            )
        self._broker = broker
        self._slots = threading.BoundedSemaphore(max_inflight)
        self._worker_condition = threading.Condition()
        self._workers: set[threading.Thread] = set()

    def wait_for_drain(self) -> None:
        """Wait until every broker call admitted before shutdown has finished."""

        with self._worker_condition:
            while self._workers:
                self._worker_condition.wait()

    def invoke(
        self,
        call: _ApprovalCall,
        *,
        peer: _PeerCredentials | None = None,
        deadline_monotonic: float,
    ) -> _BrokerInvocation:
        if peer is not None:
            try:
                peer = _validated_peer_credentials(peer)
            except TrustedApprovalUdsError:
                return _BrokerInvocation(status="rejected", view=None)
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or not math.isfinite(float(deadline_monotonic))
        ):
            return _BrokerInvocation(status="timeout", view=None)
        with monotonic_deadline_scope(float(deadline_monotonic)) as effective_deadline:
            if effective_deadline is None:
                return _BrokerInvocation(status="timeout", view=None)
            worker_context = copy_monotonic_deadline_context()
        remaining = effective_deadline - monotonic()
        if remaining <= 0:
            return _BrokerInvocation(status="timeout", view=None)
        if not self._slots.acquire(blocking=False):
            return _BrokerInvocation(status="unavailable", view=None)

        done = threading.Event()
        dispatch_lock = threading.Lock()
        dispatch_state = {"phase": "queued"}
        result: dict[str, Any] = {"status": "rejected", "view": None}

        def worker() -> None:
            try:
                with dispatch_lock:
                    if dispatch_state["phase"] == "cancelled":
                        result["status"] = "timeout"
                        return
                    if monotonic() >= effective_deadline:
                        result["status"] = "timeout"
                        return
                    dispatch_state["phase"] = "started"
                result["view"] = _invoke_broker(
                    self._broker,
                    call,
                    peer=peer,
                )
                result["status"] = "ok"
            except _TrustedApprovalReconciliationRequired as exc:
                result["status"] = "reconciliation_required"
                result["reconciliation_code"] = exc.code
            except _TrustedApprovalBrokerRejected:
                result["status"] = "rejected"
            except BaseException:
                # Never let threading.excepthook print a handle/backend traceback.
                result["status"] = "reconciliation_required"
                result["reconciliation_code"] = (
                    "approval_broker_outcome_unknown"
                )
            finally:
                with dispatch_lock:
                    dispatch_state["phase"] = "finished"
                self._slots.release()
                with self._worker_condition:
                    self._workers.discard(thread)
                    self._worker_condition.notify_all()
                done.set()

        def run_worker() -> None:
            worker_context.run(worker)

        thread = threading.Thread(
            target=run_worker,
            name="odoo-v3-approval-broker",
            daemon=False,
        )
        with self._worker_condition:
            self._workers.add(thread)
        try:
            thread.start()
        except BaseException:
            with self._worker_condition:
                self._workers.discard(thread)
                self._worker_condition.notify_all()
            self._slots.release()
            return _BrokerInvocation(status="unavailable", view=None)

        remaining = max(0.0, effective_deadline - monotonic())
        completed = done.wait(remaining)
        expired = monotonic() >= effective_deadline
        if not completed or expired:
            with dispatch_lock:
                phase = dispatch_state["phase"]
                if phase == "queued":
                    dispatch_state["phase"] = "cancelled"
                    return _BrokerInvocation(status="timeout", view=None)
            if (
                phase == "finished"
                and result["status"] == "reconciliation_required"
            ):
                code = result.get("reconciliation_code")
                return _BrokerInvocation(
                    status="reconciliation_required",
                    view=None,
                    reconciliation_code=(
                        code
                        if code in _APPROVAL_RECONCILIATION_CODES
                        else "approval_broker_outcome_unknown"
                    ),
                )
            if phase == "finished" and result["status"] == "timeout":
                return _BrokerInvocation(status="timeout", view=None)
            return _BrokerInvocation(
                status="reconciliation_required",
                view=None,
                reconciliation_code="approval_broker_outcome_unknown",
            )
        status = result["status"]
        view = result["view"]
        if status == "timeout":
            return _BrokerInvocation(status="timeout", view=None)
        if status == "reconciliation_required":
            code = result.get("reconciliation_code")
            return _BrokerInvocation(
                status="reconciliation_required",
                view=None,
                reconciliation_code=(
                    code
                    if code in _APPROVAL_RECONCILIATION_CODES
                    else "approval_broker_outcome_unknown"
                ),
            )
        if status != "ok" or type(view) is not dict:
            return _BrokerInvocation(status="rejected", view=None)
        return _BrokerInvocation(status="ok", view=view)


def _safe_error(
    code: str,
    *,
    retryable: bool = False,
    reconciliation_required: bool = False,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code": code,
        "message": "The trusted approval service rejected the local request.",
        "retryable": retryable,
    }
    if reconciliation_required:
        error["reconciliation_required"] = True
    return {
        "ok": False,
        "error": error,
    }


def _capacity_response() -> bytes:
    body = json.dumps(
        _safe_error("approval_broker_unavailable", retryable=True),
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
        raise TrustedApprovalUdsError("Linux SO_PEERCRED is unavailable")
    raw = connection.getsockopt(
        socket.SOL_SOCKET,
        socket.SO_PEERCRED,
        _PEER_CREDENTIAL_SIZE,
    )
    if len(raw) != _PEER_CREDENTIAL_SIZE:
        raise TrustedApprovalUdsError("Linux peer credentials are incomplete")
    pid, uid, gid = struct.unpack(_PEER_CREDENTIAL_FORMAT, raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise TrustedApprovalUdsError("Linux peer credentials are invalid")
    return _PeerCredentials(pid=pid, uid=uid, gid=gid)


def _peer_is_allowed(
    credentials: _PeerCredentials, config: TrustedApprovalUdsConfig
) -> bool:
    """UID is the sole peer admission fact; PID/GID are diagnostic only."""

    return credentials.uid == config.odoo_client_uid


def _validated_peer_credentials(value: object) -> _PeerCredentials:
    if (
        not isinstance(value, _PeerCredentials)
        or type(value.pid) is not int
        or not 1 <= value.pid <= 2**31 - 1
        or type(value.uid) is not int
        or not 0 <= value.uid <= _MAX_LINUX_ID
        or type(value.gid) is not int
        or not 0 <= value.gid <= _MAX_LINUX_ID
    ):
        raise TrustedApprovalUdsError(
            "Linux peer credentials are invalid"
        )
    return value


def _validate_headers(headers: Any, config: TrustedApprovalUdsConfig) -> None:
    try:
        raw_items = list(headers.raw_items())
    except (AttributeError, TypeError, ValueError) as exc:
        raise TrustedApprovalUdsError(
            "approval request headers are unavailable"
        ) from exc
    if len(raw_items) > config.max_header_count:
        raise TrustedApprovalUdsError(
            "approval request header count exceeds the limit"
        )
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
            raise TrustedApprovalUdsError("approval request header is not allowed")
        try:
            encoded_size += len(name.encode("ascii")) + len(value.encode("latin-1")) + 4
        except UnicodeEncodeError as exc:
            raise TrustedApprovalUdsError(
                "approval request header encoding is invalid"
            ) from exc
    if encoded_size > config.max_header_bytes:
        raise TrustedApprovalUdsError(
            "approval request headers exceed the byte limit"
        )
    hosts = headers.get_all("Host", failobj=[])
    connections = headers.get_all("Connection", failobj=[])
    if (
        len(hosts) != 1
        or not isinstance(hosts[0], str)
        or _HOST.fullmatch(hosts[0]) is None
        or len(connections) != 1
        or connections[0] != "close"
    ):
        raise TrustedApprovalUdsError(
            "approval HTTP authority headers are invalid"
        )


class _ApprovalRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OdooAccountingV3TrustedApproval"
    sys_version = ""

    def setup(self) -> None:
        self._response_sent = False
        self._io_expired = False
        self._io_timer: threading.Timer | None = None
        super().setup()
        self.rfile = _RequestLineLimitedReader(
            self.rfile,
            max_bytes=self.server.config.max_header_bytes,
        )
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
        remaining_header_bytes = (
            self.server.config.max_header_bytes - len(self.raw_requestline)
        )
        if remaining_header_bytes <= 0:
            self.request_version = "HTTP/1.1"
            self.close_connection = True
            self._send_json(
                431,
                _safe_error("approval_headers_rejected"),
            )
            return False
        self.rfile = _HeaderLimitedReader(
            original,
            max_bytes=remaining_header_bytes,
            max_count=self.server.config.max_header_count,
        )
        try:
            return super().parse_request()
        finally:
            self.rfile = original

    def handle_expect_100(self) -> bool:
        self._send_json(417, _safe_error("approval_expectation_rejected"))
        return False

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        del message, explain
        if getattr(self, "request_version", "HTTP/0.9") == "HTTP/0.9":
            self.request_version = "HTTP/1.1"
        self._send_json(code, _safe_error("approval_http_request_rejected"))

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
                _safe_error("approval_response_rejected"),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        if len(body) > self.server.config.max_response_bytes:
            status_code = 500
            body = json.dumps(
                _safe_error("approval_response_rejected"),
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

    def _reject(
        self, status_code: int, code: str, *, retryable: bool = False
    ) -> None:
        self._send_json(status_code, _safe_error(code, retryable=retryable))

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path not in _ACTION_BY_PATH:
            self._reject(404, "approval_route_rejected")
            return
        if self.request_version != "HTTP/1.1":
            self._reject(400, "approval_http_version_rejected")
            return
        try:
            _validate_headers(self.headers, self.server.config)
        except TrustedApprovalUdsError:
            self._reject(400, "approval_headers_rejected")
            return
        if self.headers.get_all("Transfer-Encoding", failobj=[]):
            self._reject(400, "approval_transfer_encoding_rejected")
            return
        if self.headers.get_all("Content-Encoding", failobj=[]):
            self._reject(415, "approval_content_encoding_rejected")
            return
        if self.headers.get_all("Expect", failobj=[]):
            self._reject(417, "approval_expectation_rejected")
            return
        content_types = self.headers.get_all("Content-Type", failobj=[])
        if len(content_types) != 1 or content_types[0] not in _ALLOWED_CONTENT_TYPES:
            self._reject(415, "approval_content_type_rejected")
            return
        content_lengths = self.headers.get_all("Content-Length", failobj=[])
        if (
            len(content_lengths) != 1
            or not isinstance(content_lengths[0], str)
            or not _CONTENT_LENGTH.fullmatch(content_lengths[0])
        ):
            self._reject(411, "approval_content_length_rejected")
            return
        content_length = int(content_lengths[0])
        if content_length > self.server.config.max_body_bytes:
            self._reject(413, "approval_request_too_large")
            return
        if content_length < 2:
            self._reject(400, "approval_json_object_required")
            return
        try:
            body = self.rfile.read(content_length)
        except (TimeoutError, socket.timeout, OSError):
            self._reject(408, "approval_request_timeout", retryable=True)
            return
        if self._io_expired:
            self._reject(408, "approval_request_timeout", retryable=True)
            return
        if len(body) != content_length:
            self._reject(400, "approval_request_body_incomplete")
            return
        try:
            call = _decode_call(self.path, body)
        except TrustedApprovalUdsError:
            self._reject(400, "approval_business_request_rejected")
            return
        deadline = self._accepted_at + self.server.config.request_timeout_seconds
        if monotonic() >= deadline:
            self._reject(408, "approval_request_timeout", retryable=True)
            return
        invocation = self.server.broker_invoker.invoke(
            call,
            peer=self._peer,
            deadline_monotonic=deadline,
        )
        if invocation.status == "timeout":
            self._reject(504, "approval_request_timeout", retryable=True)
            return
        if invocation.status == "unavailable":
            self._send_json(
                503,
                _safe_error("approval_broker_unavailable", retryable=True),
            )
            return
        if invocation.status == "reconciliation_required":
            self._send_json(
                503,
                _safe_error(
                    (
                        invocation.reconciliation_code
                        if invocation.reconciliation_code
                        in _APPROVAL_RECONCILIATION_CODES
                        else "approval_broker_outcome_unknown"
                    ),
                    reconciliation_required=True,
                ),
            )
            return
        if invocation.status != "ok" or invocation.view is None:
            self._reject(403, "approval_broker_rejected")
            return
        if self._io_expired or monotonic() >= deadline:
            self._send_json(
                503,
                _safe_error(
                    "approval_broker_outcome_unknown",
                    reconciliation_required=True,
                ),
            )
            return
        response_field = {
            "approval.request": "challenge",
            "approval.inspect": "inspection",
            "approval.decide": "decision",
        }[call.action]
        self._send_json(200, {"ok": True, response_field: invocation.view})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self._reject(405, "approval_method_rejected")

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
        # ``server_close`` joins every accepted approval handler; timed-out
        # broker workers are drained explicitly below as well.
        daemon_threads = False
        block_on_close = True
        allow_reuse_address = False
        request_queue_size = 8

        def __init__(
            self,
            config: TrustedApprovalUdsConfig,
            broker: TrustedApprovalBroker,
            *,
            bind_and_activate: bool,
        ) -> None:
            if not isinstance(config, TrustedApprovalUdsConfig):
                raise TrustedApprovalUdsError(
                    "trusted approval config is invalid"
                )
            if not _broker_contract_is_valid(broker):
                raise TrustedApprovalUdsError(
                    "trusted approval broker is invalid"
                )
            self.config = config
            self.broker = broker
            self.broker_invoker = _BoundedBrokerInvoker(
                broker,
                max_inflight=config.max_inflight_broker_calls,
            )
            self._handler_slots = threading.BoundedSemaphore(
                config.max_inflight_broker_calls
            )
            self._credential_lock = threading.Lock()
            self._credentials: dict[int, _PeerCredentials] = {}
            self._cleanup_parent_fd: int | None = None
            self._bound_identity: tuple[int, int] | None = None
            super().__init__(
                config.socket_path,
                _ApprovalRequestHandler,
                bind_and_activate=bind_and_activate,
            )

        def verify_request(self, request: socket.socket, client_address: Any) -> bool:
            del client_address
            try:
                credentials = _peer_credentials(request)
            except (OSError, TrustedApprovalUdsError):
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
                    raise TrustedApprovalUdsError(
                        "verified Odoo client credentials are unavailable"
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
            # Fail closed without logging handles, bodies, or tracebacks.

        def attach_secure_path(
            self, parent_fd: int, bound_identity: tuple[int, int]
        ) -> None:
            self._cleanup_parent_fd = parent_fd
            self._bound_identity = bound_identity

        def server_close(self) -> None:
            try:
                try:
                    super().server_close()
                finally:
                    self.broker_invoker.wait_for_drain()
            finally:
                parent_fd = self._cleanup_parent_fd
                identity = self._bound_identity
                self._cleanup_parent_fd = None
                self._bound_identity = None
                if parent_fd is not None:
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
        or not hasattr(socket, "AF_UNIX")
        or _TrustedUnixHTTPServer is None
        or not hasattr(socket, "SO_PEERCRED")
    ):
        raise TrustedApprovalUdsError(
            "trusted approval transport is supported only on Linux UDS"
        )


def _validate_parent_stat(value: os.stat_result) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or mode & 0o700 != 0o700
        or mode & 0o027
    ):
        raise TrustedApprovalUdsError(
            "approval socket parent must be a private root-owned real directory"
        )


def _validate_ancestor_stat(value: os.stat_result) -> None:
    mode = stat.S_IMODE(value.st_mode)
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != 0
        or mode & 0o022
    ):
        raise TrustedApprovalUdsError(
            "approval socket ancestors must be root-owned real directories without "
            "group/world write access"
        )


def _open_secure_parent(config: TrustedApprovalUdsConfig) -> int:
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
            raise TrustedApprovalUdsError(
                "approval socket parent is unavailable"
            ) from exc
        raise


def _validate_socket_stat(
    value: os.stat_result, config: TrustedApprovalUdsConfig
) -> None:
    if (
        not stat.S_ISSOCK(value.st_mode)
        or value.st_uid != 0
        or value.st_gid != config.socket_group_gid
        or stat.S_IMODE(value.st_mode) != config.socket_mode
    ):
        raise TrustedApprovalUdsError(
            "approval socket has untrusted owner, group, mode, or type"
        )


def _stat_socket_at(parent_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def _unlink_socket_at(parent_fd: int, name: str) -> None:
    os.unlink(name, dir_fd=parent_fd)


def _remove_verified_stale_socket(
    parent_fd: int, config: TrustedApprovalUdsConfig
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
                raise TrustedApprovalUdsError(
                    "existing approval socket could not be proven stale"
                ) from exc
        else:
            raise TrustedApprovalUdsError(
                "another trusted approval server is active"
            )
    finally:
        probe.close()
    try:
        current = _stat_socket_at(parent_fd, name)
    except FileNotFoundError as exc:
        raise TrustedApprovalUdsError(
            "approval socket changed during stale-socket verification"
        ) from exc
    _validate_socket_stat(current, config)
    if (initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino):
        raise TrustedApprovalUdsError(
            "approval socket changed during stale-socket verification"
        )
    _unlink_socket_at(parent_fd, name)


def _configure_bound_socket(
    parent_fd: int, config: TrustedApprovalUdsConfig
) -> tuple[int, int]:
    name = PurePosixPath(config.socket_path).name
    created = _stat_socket_at(parent_fd, name)
    if not stat.S_ISSOCK(created.st_mode) or created.st_uid != 0:
        raise TrustedApprovalUdsError(
            "approval bind did not create a root-owned Unix socket"
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
        raise TrustedApprovalUdsError(
            "approval socket changed during secure setup"
        )
    return identity


def create_trusted_approval_uds_server(
    config: TrustedApprovalUdsConfig, broker: TrustedApprovalBroker
) -> Any:
    """Bind and activate the root-controlled, Odoo-only approval service."""

    _require_linux()
    if os.geteuid() != 0:
        raise TrustedApprovalUdsError(
            "trusted approval UDS binding requires root"
        )
    if not isinstance(config, TrustedApprovalUdsConfig):
        raise TrustedApprovalUdsError("trusted approval config is invalid")
    if not _broker_contract_is_valid(broker):
        raise TrustedApprovalUdsError("trusted approval broker is invalid")
    parent_fd = _open_secure_parent(config)
    server: Any | None = None
    try:
        _remove_verified_stale_socket(parent_fd, config)
        server = _TrustedUnixHTTPServer(
            config,
            broker,
            bind_and_activate=False,
        )
        server.server_bind()
        name = PurePosixPath(config.socket_path).name
        created = _stat_socket_at(parent_fd, name)
        if not stat.S_ISSOCK(created.st_mode):
            raise TrustedApprovalUdsError(
                "approval bind did not create a Unix socket"
            )
        server.attach_secure_path(parent_fd, (created.st_dev, created.st_ino))
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


def create_trusted_approval_uds_server_from_fd(
    config: TrustedApprovalUdsConfig,
    broker: TrustedApprovalBroker,
    descriptor: int,
) -> Any:
    """Adopt one root-created systemd socket while running as non-root."""

    _require_linux()
    if os.geteuid() == 0:
        raise TrustedApprovalUdsError(
            "activated approval server must run under a dedicated non-root UID"
        )
    if not isinstance(config, TrustedApprovalUdsConfig):
        raise TrustedApprovalUdsError("trusted approval config is invalid")
    if not _broker_contract_is_valid(broker):
        raise TrustedApprovalUdsError("trusted approval broker is invalid")
    server = _TrustedUnixHTTPServer(
        config,
        broker,
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
        raise TrustedApprovalUdsError(
            "activated approval socket was rejected"
        ) from exc


def serve_trusted_approval_uds(
    config: TrustedApprovalUdsConfig, broker: TrustedApprovalBroker
) -> None:
    """Serve until interrupted; production callers should use systemd."""

    server = create_trusted_approval_uds_server(config, broker)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


__all__ = [
    "APPROVAL_DECIDE_PATH",
    "APPROVAL_INSPECT_PATH",
    "APPROVAL_REQUEST_PATH",
    "SAME_UID_THREAT",
    "TrustedApprovalBroker",
    "TrustedApprovalUdsConfig",
    "TrustedApprovalUdsError",
    "create_trusted_approval_uds_server",
    "create_trusted_approval_uds_server_from_fd",
    "serve_trusted_approval_uds",
]

"""Trusted, business-only Pi broker core.

The model-facing caller supplies only business requests and an opaque upstream
session handle.  This core derives identity, request IDs, approval material,
and historical release routing from trusted dependencies.  In particular, a
caller-provided current release header is only an anti-misconfiguration check;
it is never used to select the authority or executable for an existing
operation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Protocol

from .auth import context_payload
from .broker_audit import (
    BrokerWriteAuditEvent,
    SQLiteBrokerAuditSink,
    canonical_request_digest,
)
from .gateway import RequestContext
from .historical_router import HistoricalRouterError
from .operations import Operation, State, canonical_json, operation_digest
from .trusted_authority import (
    ApprovalChallenge,
    ApprovalDecision,
    AuthorityReconciliationRequiredError,
    AuthorityConcurrentUpdate,
    AuthorityError,
    ChallengeExpired,
    ChallengeTerminal,
    TrustedAuthority,
    TrustedSession,
)
from .trusted_session_sqlite import TrustedSessionReconciliationRequiredError


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SESSION_HANDLE = re.compile(r"[A-Za-z0-9._~-]{32,512}\Z")
_MAX_LINUX_ID = 2**32 - 2
_MAX_LINUX_PID = 2**31 - 1

_BUSINESS_FIELDS: dict[str, frozenset[str]] = {
    "read": frozenset({"capability_id", "parameters"}),
    "operation.prepare": frozenset({"capability_id", "parameters"}),
    "operation.preview": frozenset({"operation_id"}),
    "operation.approve_execute": frozenset({"operation_id"}),
    "operation.status": frozenset({"operation_id"}),
    "operation.result": frozenset({"operation_id"}),
    "operation.recover": frozenset(
        {"origin_operation_id", "recovery_date", "reason", "idempotency_key"}
    ),
}
_WRITE_ACTIONS = frozenset(_BUSINESS_FIELDS) - {"read"}
_TERMINAL_ACTIONS = frozenset(
    {"operation.approve_execute", "operation.result"}
)
_AUTHORITY_FIELDS = frozenset(
    {
        "allowed_company_ids",
        "approval",
        "approval_digest",
        "approval_nonce_digest",
        "approval_signature",
        "approver_user_id",
        "auth_expires_at",
        "auth_issued_at",
        "auth_key_id",
        "auth_request_digest",
        "auth_signature",
        "auth_signature_purpose",
        "auth_signature_version",
        "auth_token_id",
        "broker_session_handle",
        "broker_socket",
        "binary_path",
        "challenge_id",
        "cli_path",
        "config_path",
        "context",
        "database_name",
        "database_uuid",
        "environment",
        "expected_origin_revision",
        "key_id",
        "odoo_instance_id",
        "principal",
        "reconciliation_only",
        "recovery_operation_id",
        "registry_digest",
        "release_digest",
        "request_id",
        "runtime_config_path",
        "runtime_config",
        "session_handle",
        "signature",
        "signing_key_id",
        "user_id",
    }
)


class TrustedBrokerError(ValueError):
    """A broker boundary rejected a request without exposing trusted detail."""

    def __init__(
        self,
        code: str,
        *,
        status_code: int = 403,
        odoo_effect: str = "none",
        retryable: bool = False,
        reconciliation_required: bool = False,
    ) -> None:
        if reconciliation_required:
            status_code = 503
            odoo_effect = "none"
            retryable = False
        super().__init__(code)
        self.code = code
        self.status_code = status_code
        self.odoo_effect = odoo_effect
        self.retryable = retryable
        self.reconciliation_required = reconciliation_required


class HistoricalExecutor(Protocol):
    def dispatch(
        self,
        action: str,
        request: Mapping[str, Any],
        *,
        deadline_monotonic: float | None = None,
    ) -> dict[str, Any]: ...


class ResponseVerifier(Protocol):
    def __call__(
        self,
        action: str,
        response: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> bool: ...


class PrepareIdempotencyResolver(Protocol):
    """Resolve a durable prepare identity without selecting a release from Pi."""

    def __call__(
        self,
        session: TrustedSession,
        capability_id: str,
        parameters: Mapping[str, Any],
    ) -> str | None: ...


class RecoveryIdempotencyResolver(Protocol):
    """Resolve a durable recovery identity after an ambiguous child response."""

    def __call__(
        self,
        session: TrustedSession,
        origin: Operation,
        request: Mapping[str, Any],
    ) -> str | None: ...


class PrecheckResolver(Protocol):
    """Load one durable, integrity-checked precheck record by operation ID."""

    def __call__(self, operation_id: str) -> object: ...


@dataclass(frozen=True, slots=True)
class AuthorizedReadAction:
    """A read request and context returned by a separate trusted authorizer."""

    context: RequestContext
    request: dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.context, RequestContext):
            raise TrustedBrokerError("broker_read_authority_rejected")
        detached = _canonical_object(
            self.request,
            "authorized read request",
            error_code="broker_read_authority_rejected",
            status_code=500,
        )
        if set(detached) != _BUSINESS_FIELDS["read"]:
            raise TrustedBrokerError("broker_read_authority_rejected")
        object.__setattr__(self, "request", detached)


@dataclass(frozen=True, slots=True)
class ReleaseAuthority:
    """One authority whose key material is pinned to one immutable release."""

    release_digest: str
    registry_digest: str
    authority: TrustedAuthority

    def __post_init__(self) -> None:
        if (
            not _is_digest(self.release_digest)
            or not _is_digest(self.registry_digest)
            or not isinstance(self.authority, TrustedAuthority)
        ):
            raise TrustedBrokerError("broker_release_authority_rejected")


@dataclass(frozen=True, slots=True)
class ReleaseResponseVerifier:
    """Cryptographic response verifier pinned to one immutable release."""

    release_digest: str
    registry_digest: str
    verify: ResponseVerifier

    def __post_init__(self) -> None:
        if (
            not _is_digest(self.release_digest)
            or not _is_digest(self.registry_digest)
            or not callable(self.verify)
        ):
            raise TrustedBrokerError("broker_response_verifier_rejected")


@dataclass(frozen=True, slots=True)
class TrustedBrokerResult:
    status_code: int
    body: dict[str, Any]
    authority_verified: bool
    executed_release_digest: str | None = None
    executed_registry_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 200 <= self.status_code <= 599
            or not isinstance(self.body, dict)
            or type(self.authority_verified) is not bool
            or (self.executed_release_digest is None)
            != (self.executed_registry_digest is None)
            or (
                self.executed_release_digest is not None
                and (
                    not _is_digest(self.executed_release_digest)
                    or not _is_digest(self.executed_registry_digest)
                )
            )
        ):
            raise TrustedBrokerError("broker_result_contract_rejected")


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _session_reconciliation_error(
    exc: BaseException,
) -> TrustedBrokerError | None:
    """Classify a non-replayable session-store outcome through safe wrappers."""

    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        if (
            isinstance(current, TrustedSessionReconciliationRequiredError)
            and current.reconciliation_required is True
            and current.retryable is False
        ):
            return TrustedBrokerError(
                "broker_session_reconciliation_required",
                status_code=503,
                odoo_effect="none",
                retryable=False,
                reconciliation_required=True,
            )
        for linked in (current.__cause__, current.__context__):
            if isinstance(linked, BaseException):
                pending.append(linked)
    return None


def _authority_reconciliation_error(
    exc: BaseException,
) -> TrustedBrokerError | None:
    """Classify a non-replayable authority-store outcome through wrappers."""

    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        if (
            isinstance(current, AuthorityReconciliationRequiredError)
            and current.reconciliation_required is True
            and current.retryable is False
        ):
            return TrustedBrokerError(
                "broker_authority_reconciliation_required",
                status_code=503,
                odoo_effect="none",
                retryable=False,
                reconciliation_required=True,
            )
        for linked in (current.__cause__, current.__context__):
            if isinstance(linked, BaseException):
                pending.append(linked)
    return None


def _reconciliation_error(exc: BaseException) -> TrustedBrokerError | None:
    return _authority_reconciliation_error(exc) or _session_reconciliation_error(exc)


def _canonical_object(
    value: object,
    label: str,
    *,
    error_code: str = "broker_business_request_rejected",
    status_code: int = 400,
    odoo_effect: str = "none",
) -> dict[str, Any]:
    del label
    if not isinstance(value, Mapping):
        raise TrustedBrokerError(
            error_code, status_code=status_code, odoo_effect=odoo_effect
        )
    try:
        detached = json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise TrustedBrokerError(
            error_code, status_code=status_code, odoo_effect=odoo_effect
        ) from exc
    if not isinstance(detached, dict):  # pragma: no cover - canonical invariant
        raise TrustedBrokerError(
            error_code, status_code=status_code, odoo_effect=odoo_effect
        )
    return detached


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise TrustedBrokerError("broker_business_request_rejected", status_code=400)
    return value


def _approval_peer_metadata(
    peer_uid: object,
    peer_gid: object,
    peer_pid: object,
) -> tuple[int | None, int | None, int | None]:
    """Validate transport-observed approval peer facts as one atomic tuple."""

    values = (peer_uid, peer_gid, peer_pid)
    if values == (None, None, None):
        return None, None, None
    if any(value is None for value in values):
        raise TrustedBrokerError(
            "broker_approval_peer_rejected", status_code=500
        )
    if (
        type(peer_uid) is not int
        or not 0 <= peer_uid <= _MAX_LINUX_ID
        or type(peer_gid) is not int
        or not 0 <= peer_gid <= _MAX_LINUX_ID
        or type(peer_pid) is not int
        or not 1 <= peer_pid <= _MAX_LINUX_PID
    ):
        raise TrustedBrokerError(
            "broker_approval_peer_rejected", status_code=500
        )
    return peer_uid, peer_gid, peer_pid


def _contains_authority_field(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower().replace("-", "_") in _AUTHORITY_FIELDS:
                return True
            if _contains_authority_field(child):
                return True
    elif isinstance(value, list):
        return any(_contains_authority_field(child) for child in value)
    return False


def _business_request(action: str, value: object) -> dict[str, Any]:
    if not isinstance(action, str) or action not in _BUSINESS_FIELDS:
        raise TrustedBrokerError("broker_action_rejected", status_code=404)
    request = _canonical_object(value, "business request")
    if set(request) != _BUSINESS_FIELDS[action] or _contains_authority_field(request):
        raise TrustedBrokerError(
            "broker_business_request_rejected", status_code=400
        )
    if action in {"read", "operation.prepare"}:
        _identifier(request["capability_id"], "capability_id")
        if not isinstance(request["parameters"], dict):
            raise TrustedBrokerError(
                "broker_business_request_rejected", status_code=400
            )
        if action == "operation.prepare":
            _identifier(
                request["parameters"].get("idempotency_key"),
                "idempotency_key",
            )
    elif action == "operation.recover":
        _identifier(request["origin_operation_id"], "origin_operation_id")
        _identifier(request["idempotency_key"], "idempotency_key")
        try:
            parsed_date = date.fromisoformat(request["recovery_date"])
        except (TypeError, ValueError) as exc:
            raise TrustedBrokerError(
                "broker_business_request_rejected", status_code=400
            ) from exc
        reason = request["reason"]
        if (
            parsed_date.isoformat() != request["recovery_date"]
            or not isinstance(reason, str)
            or reason != reason.strip()
            or not reason
            or len(reason) > 512
        ):
            raise TrustedBrokerError(
                "broker_business_request_rejected", status_code=400
            )
    else:
        _identifier(request["operation_id"], "operation_id")
    return request


def _context_mapping(context: RequestContext) -> dict[str, Any]:
    return {**context_payload(context), "auth_signature": context.auth_signature}


def _challenge_view(challenge: ApprovalChallenge) -> dict[str, Any]:
    operation = challenge.operation
    return {
        "capability_id": operation.capability_id,
        "challenge_id": challenge.challenge_id,
        "company_id": operation.company_id,
        "expires_at": challenge.expires_at.astimezone(timezone.utc).isoformat(),
        "issued_at": challenge.issued_at.astimezone(timezone.utc).isoformat(),
        "operation_digest": operation.digest,
        "operation_id": operation.operation_id,
        "precheck_digest": operation.precheck_digest,
        "requester_user_id": operation.user_id,
        "state": challenge.state.value,
    }


def _inspection_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        )
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.astimezone(timezone.utc).isoformat() != value
    ):
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        )
    return parsed


def _authority_inspection_preview(
    value: object,
    *,
    challenge_id: str,
    route: tuple[str, str],
) -> dict[str, Any]:
    """Validate the Authority's unsigned preview before adding evidence."""

    preview = _canonical_object(
        value,
        "approval inspection preview",
        error_code="broker_approval_preview_rejected",
        status_code=500,
    )
    if set(preview) != {
        "schema_version",
        "challenge",
        "operation",
        "summary",
        "preview_digest",
    } or preview["schema_version"] != 1:
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        )
    challenge = preview["challenge"]
    operation = preview["operation"]
    summary = preview["summary"]
    if (
        not isinstance(challenge, dict)
        or set(challenge)
        != {
            "challenge_id",
            "binding_digest",
            "issued_at",
            "expires_at",
            "ttl_seconds",
            "state",
            "version",
        }
        or not isinstance(operation, dict)
        or set(operation)
        != {
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
        or not isinstance(summary, dict)
    ):
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        )
    issued_at = _inspection_timestamp(challenge["issued_at"])
    expires_at = _inspection_timestamp(challenge["expires_at"])
    if (
        challenge["challenge_id"] != challenge_id
        or not _is_digest(challenge["binding_digest"])
        or challenge["state"]
        not in {"pending", "approved", "denied", "expired", "stale"}
        or type(challenge["ttl_seconds"]) is not int
        or challenge["ttl_seconds"] <= 0
        or type(challenge["version"]) is not int
        or challenge["version"] < 0
        or expires_at <= issued_at
        or expires_at - issued_at
        > timedelta(seconds=challenge["ttl_seconds"])
        or not isinstance(operation["parameters"], dict)
        or type(operation["user_id"]) is not int
        or operation["user_id"] <= 0
        or type(operation["company_id"]) is not int
        or operation["company_id"] <= 0
        or type(operation["revision"]) is not int
        or operation["revision"] < 2
        or operation["protocol_version"] != 4
        or operation["state"] != State.AWAITING_APPROVAL.value
        or not _is_digest(operation["registry_digest"])
        or not _is_digest(operation["release_digest"])
        or not _is_digest(operation["operation_digest"])
        or not _is_digest(operation["precheck_digest"])
        or route
        != (operation["release_digest"], operation["registry_digest"])
    ):
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        )
    required_text = (
        "operation_id",
        "request_id",
        "capability_id",
        "principal",
        "idempotency_key",
        "odoo_instance_id",
        "database_name",
        "database_uuid",
        "environment",
    )
    if any(
        not isinstance(operation[field], str)
        or not operation[field]
        or len(operation[field]) > 512
        for field in required_text
    ):
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        )
    parameters_digest = hashlib.sha256(
        canonical_json(operation["parameters"])
    ).hexdigest()
    expected_operation_digest = operation_digest(
        capability_id=operation["capability_id"],
        parameters=operation["parameters"],
        principal=operation["principal"],
        user_id=operation["user_id"],
        company_id=operation["company_id"],
        idempotency_key=operation["idempotency_key"],
        odoo_instance_id=operation["odoo_instance_id"],
        database_name=operation["database_name"],
        database_uuid=operation["database_uuid"],
        environment=operation["environment"],
        registry_digest=operation["registry_digest"],
        release_digest=operation["release_digest"],
    )
    expected_binding = hashlib.sha256(
        canonical_json(
            {
                "company_id": operation["company_id"],
                "database_name": operation["database_name"],
                "database_uuid": operation["database_uuid"],
                "environment": operation["environment"],
                "odoo_instance_id": operation["odoo_instance_id"],
                "operation_digest": operation["operation_digest"],
                "operation_id": operation["operation_id"],
                "operation_revision": operation["revision"],
                "precheck_digest": operation["precheck_digest"],
                "principal": operation["principal"],
                "request_id": operation["request_id"],
                "user_id": operation["user_id"],
            }
        )
    ).hexdigest()
    expected_summary = {
        "binding_digest": challenge["binding_digest"],
        "capability_id": operation["capability_id"],
        "challenge_id": challenge_id,
        "company_id": operation["company_id"],
        "operation_digest": operation["operation_digest"],
        "operation_id": operation["operation_id"],
        "parameters_digest": parameters_digest,
        "precheck_digest": operation["precheck_digest"],
        "requester_principal": operation["principal"],
        "requester_user_id": operation["user_id"],
    }
    unsigned = {
        key: item for key, item in preview.items() if key != "preview_digest"
    }
    expected_preview_digest = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    if not (
        hmac.compare_digest(operation["parameters_digest"], parameters_digest)
        and hmac.compare_digest(
            operation["operation_digest"], expected_operation_digest
        )
        and hmac.compare_digest(challenge["binding_digest"], expected_binding)
        and summary == expected_summary
        and _is_digest(preview["preview_digest"])
        and hmac.compare_digest(
            preview["preview_digest"], expected_preview_digest
        )
    ):
        raise TrustedBrokerError(
            "broker_approval_preview_rejected", status_code=500
        )
    return preview


def _precheck_record_value(record: object, field: str) -> object:
    try:
        if isinstance(record, Mapping):
            return record[field]
        return getattr(record, field)
    except (AttributeError, KeyError, TypeError) as exc:
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        ) from exc


def _bound_precheck_preview(
    record: object,
    authority_preview: Mapping[str, Any],
) -> dict[str, Any]:
    operation = authority_preview["operation"]
    challenge = authority_preview["challenge"]
    fields = {
        field: _precheck_record_value(record, field)
        for field in (
            "operation_id",
            "request_id",
            "operation_digest",
            "operation_revision",
            "principal",
            "user_id",
            "company_id",
            "evidence_digest",
            "evidence_json",
            "occurred_at",
        )
    }
    occurred_at = fields["occurred_at"]
    if (
        not isinstance(occurred_at, datetime)
        or occurred_at.tzinfo is None
        or occurred_at.utcoffset() is None
    ):
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        )
    try:
        evidence = json.loads(fields["evidence_json"])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        ) from exc
    if not isinstance(evidence, dict):
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        )
    evidence_json = canonical_json(evidence).decode("utf-8")
    evidence_digest = hashlib.sha256(evidence_json.encode("utf-8")).hexdigest()
    issued_at = _inspection_timestamp(challenge["issued_at"])
    if (
        fields["operation_id"] != operation["operation_id"]
        or fields["request_id"] != operation["request_id"]
        or fields["operation_digest"] != operation["operation_digest"]
        or type(fields["operation_revision"]) is not int
        or fields["operation_revision"] != operation["revision"] - 2
        or fields["principal"] != operation["principal"]
        or fields["user_id"] != operation["user_id"]
        or fields["company_id"] != operation["company_id"]
        or not _is_digest(fields["evidence_digest"])
        or not hmac.compare_digest(fields["evidence_digest"], evidence_digest)
        or not hmac.compare_digest(
            fields["evidence_digest"], operation["precheck_digest"]
        )
        or fields["evidence_json"] != evidence_json
        or occurred_at > issued_at
    ):
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        )

    core_fields = {"capability_id", "company_id", "parameters_digest"}
    if (
        not core_fields.issubset(evidence)
        or evidence["capability_id"] != operation["capability_id"]
        or evidence["company_id"] != operation["company_id"]
        or evidence["parameters_digest"] != operation["parameters_digest"]
    ):
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        )
    release_fields = {"release_digest", "registry_digest"}
    if (
        not release_fields.issubset(evidence)
        or evidence["release_digest"] != operation["release_digest"]
        or evidence["registry_digest"] != operation["registry_digest"]
    ):
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        )
    runtime = evidence.get("runtime_binding")
    expected_runtime = {
        "user_id": operation["user_id"],
        "odoo_instance_id": operation["odoo_instance_id"],
        "database_name": operation["database_name"],
        "database_uuid": operation["database_uuid"],
        "environment": operation["environment"],
    }
    if not isinstance(runtime, dict) or any(
        runtime.get(field) != expected for field, expected in expected_runtime.items()
    ):
        raise TrustedBrokerError(
            "broker_approval_precheck_rejected", status_code=500
        )

    preview = {
        "operation_id": operation["operation_id"],
        "request_id": operation["request_id"],
        "operation_digest": operation["operation_digest"],
        "operation_revision": operation["revision"],
        "source_operation_revision": fields["operation_revision"],
        "principal": operation["principal"],
        "user_id": operation["user_id"],
        "company_id": operation["company_id"],
        "evidence_digest": evidence_digest,
        "occurred_at": occurred_at.astimezone(timezone.utc).isoformat(),
        "evidence": evidence,
    }
    return json.loads(canonical_json(preview))


def _inspection_with_precheck(
    authority_preview: Mapping[str, Any], precheck: Mapping[str, Any]
) -> dict[str, Any]:
    unsigned = {**authority_preview, "precheck": precheck}
    inspection = {
        **unsigned,
        "inspection_digest": hashlib.sha256(canonical_json(unsigned)).hexdigest(),
    }
    return json.loads(canonical_json(inspection))


def _safe_error_body(action: str, error: TrustedBrokerError) -> dict[str, Any]:
    safe_error: dict[str, Any] = {
        "code": error.code,
        "message": "The trusted V3 broker rejected the request.",
        "odoo_effect": error.odoo_effect,
        "retryable": error.retryable,
    }
    if error.reconciliation_required:
        safe_error["reconciliation_required"] = True
    return {
        "command": action,
        "error": safe_error,
        "ok": False,
    }


class TrustedBroker:
    """Coordinate read, write, approval, and historical release boundaries."""

    def __init__(
        self,
        *,
        current_release_digest: str,
        current_registry_digest: str,
        session_resolver: Callable[[str], TrustedSession | None],
        authority_resolver: Callable[[str, str], ReleaseAuthority | None],
        challenge_authority_resolver: Callable[[str], ReleaseAuthority | None],
        response_verifier_resolver: Callable[
            [str, str], ReleaseResponseVerifier | None
        ],
        audit_sink: SQLiteBrokerAuditSink,
        prepare_idempotency_resolver: PrepareIdempotencyResolver,
        recovery_idempotency_resolver: RecoveryIdempotencyResolver,
        operation_resolver: Callable[[str], Operation | None],
        historical_executor: HistoricalExecutor,
        read_authorizer: Callable[[str, dict[str, Any]], AuthorizedReadAction],
        read_executor: Callable[[dict[str, Any]], dict[str, Any]],
        operation_id_factory: Callable[[], str],
        request_id_factory: Callable[[], str],
        recovery_operation_id_factory: Callable[[], str],
        monotonic_clock: Callable[[], float] = time.monotonic,
        utc_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        precheck_resolver: PrecheckResolver | None = None,
    ) -> None:
        if not _is_digest(current_release_digest) or not _is_digest(
            current_registry_digest
        ):
            raise TrustedBrokerError("broker_current_identity_rejected")
        for dependency in (
            session_resolver,
            authority_resolver,
            challenge_authority_resolver,
            response_verifier_resolver,
            prepare_idempotency_resolver,
            recovery_idempotency_resolver,
            operation_resolver,
            read_authorizer,
            read_executor,
            operation_id_factory,
            request_id_factory,
            recovery_operation_id_factory,
            monotonic_clock,
            utc_clock,
        ):
            if not callable(dependency):
                raise TrustedBrokerError("broker_dependency_rejected")
        if not callable(getattr(historical_executor, "dispatch", None)):
            raise TrustedBrokerError("broker_historical_executor_rejected")
        if precheck_resolver is not None and not callable(precheck_resolver):
            raise TrustedBrokerError("broker_precheck_resolver_rejected")
        if type(audit_sink) is not SQLiteBrokerAuditSink:
            raise TrustedBrokerError("broker_audit_sink_rejected")
        self._current_release_digest = current_release_digest
        self._current_registry_digest = current_registry_digest
        self._session_resolver = session_resolver
        self._authority_resolver = authority_resolver
        self._challenge_authority_resolver = challenge_authority_resolver
        self._response_verifier_resolver = response_verifier_resolver
        self._audit_sink = audit_sink
        self._prepare_idempotency_resolver = prepare_idempotency_resolver
        self._recovery_idempotency_resolver = recovery_idempotency_resolver
        self._operation_resolver = operation_resolver
        self._historical_executor = historical_executor
        self._read_authorizer = read_authorizer
        self._read_executor = read_executor
        self._operation_id_factory = operation_id_factory
        self._request_id_factory = request_id_factory
        self._recovery_operation_id_factory = recovery_operation_id_factory
        self._monotonic_clock = monotonic_clock
        self._utc_clock = utc_clock
        self._precheck_resolver = precheck_resolver

    @staticmethod
    def _error(
        action: str,
        error: TrustedBrokerError,
        *,
        authority_verified: bool = False,
        executed_identity: tuple[str, str] | None = None,
    ) -> TrustedBrokerResult:
        if (
            action == "operation.approve_execute"
            and error.odoo_effect == "unknown"
            and not error.retryable
        ):
            error = TrustedBrokerError(
                error.code,
                status_code=error.status_code,
                odoo_effect=error.odoo_effect,
                retryable=True,
                reconciliation_required=error.reconciliation_required,
            )
        return TrustedBrokerResult(
            # Once the independent session has been authenticated, failures
            # are application envelopes over a successful local transport.
            # Pi accepts those only with HTTP 200 plus the broker-authority
            # response header.  Pre-authentication failures remain transport
            # errors and never receive that header.
            status_code=200 if authority_verified else error.status_code,
            body=_safe_error_body(action, error),
            authority_verified=authority_verified,
            executed_release_digest=(
                None if executed_identity is None else executed_identity[0]
            ),
            executed_registry_digest=(
                None if executed_identity is None else executed_identity[1]
            ),
        )

    def _assert_current_headers(self, release: object, registry: object) -> None:
        if (
            not _is_digest(release)
            or not _is_digest(registry)
            or not hmac.compare_digest(release, self._current_release_digest)
            or not hmac.compare_digest(registry, self._current_registry_digest)
        ):
            raise TrustedBrokerError(
                "broker_current_identity_mismatch", status_code=409
            )

    def _authenticate_session(self, session_handle: str) -> TrustedSession:
        try:
            now = self._utc_clock()
            session = self._session_resolver(session_handle)
        except Exception as exc:
            reconciliation = _session_reconciliation_error(exc)
            if reconciliation is not None:
                raise reconciliation from None
            raise TrustedBrokerError(
                "broker_session_rejected", status_code=401
            ) from exc
        if (
            not isinstance(session, TrustedSession)
            or not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
            or now < session.issued_at
            or now >= session.expires_at
            or not hmac.compare_digest(
                session.release_digest, self._current_release_digest
            )
            or not hmac.compare_digest(
                session.registry_digest, self._current_registry_digest
            )
        ):
            raise TrustedBrokerError("broker_session_rejected", status_code=401)
        return session

    @staticmethod
    def _context_matches_session(
        context: RequestContext, session: TrustedSession
    ) -> bool:
        return (
            context.principal == session.principal
            and context.odoo_instance_id == session.odoo_instance_id
            and context.database_name == session.database_name
            and context.database_uuid == session.database_uuid
            and context.user_id == session.user_id
            and context.company_id == session.company_id
            and context.allowed_company_ids == session.allowed_company_ids
            and context.environment == session.environment
            and context.auth_issued_at >= session.issued_at
            and context.auth_expires_at <= session.expires_at
        )

    def _operation(self, operation_id: str) -> Operation:
        try:
            operation = self._operation_resolver(operation_id)
            if not isinstance(operation, Operation):
                raise ValueError("operation missing")
            operation.assert_integrity()
            if operation.operation_id != operation_id:
                raise ValueError("operation ID mismatch")
            return operation
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_operation_rejected", status_code=404
            ) from exc

    def _existing_prepare_operation(
        self,
        *,
        session: TrustedSession,
        request: dict[str, Any],
    ) -> Operation | None:
        """Resolve an exact prior prepare before choosing the current release.

        The resolver is a trusted composition seam backed by one durable global
        idempotency index.  It returns only an operation identifier; the broker
        independently reloads and verifies every immutable business and tenant
        binding before that identifier can select a retained release.
        """

        try:
            parameters = json.loads(canonical_json(request["parameters"]))
            resolved_id = self._prepare_idempotency_resolver(
                session, request["capability_id"], parameters
            )
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_prepare_idempotency_resolver_failed",
                status_code=503,
                retryable=True,
            ) from exc
        if resolved_id is None:
            return None
        if (
            not isinstance(resolved_id, str)
            or _IDENTIFIER.fullmatch(resolved_id) is None
        ):
            raise TrustedBrokerError(
                "broker_prepare_idempotency_resolver_failed",
                status_code=503,
                retryable=True,
            )
        try:
            operation = self._operation(resolved_id)
        except TrustedBrokerError as exc:
            raise TrustedBrokerError(
                "broker_prepare_idempotency_resolver_failed",
                status_code=503,
                retryable=True,
            ) from exc
        operation_parameters = operation.parameters
        try:
            parameters_match = hmac.compare_digest(
                canonical_json(operation_parameters),
                canonical_json(request["parameters"]),
            )
        except (TypeError, ValueError, UnicodeError):
            parameters_match = False
        idempotency_key = request["parameters"].get("idempotency_key")
        if not (
            operation.principal == session.principal
            and operation.odoo_instance_id == session.odoo_instance_id
            and operation.database_name == session.database_name
            and operation.database_uuid == session.database_uuid
            and operation.user_id == session.user_id
            and operation.company_id == session.company_id
            and operation.company_id in session.allowed_company_ids
            and operation.environment == session.environment
            and operation.capability_id == request["capability_id"]
            and parameters_match
            and isinstance(idempotency_key, str)
            and operation.idempotency_key == idempotency_key
            and _IDENTIFIER.fullmatch(operation.request_id) is not None
            and _is_digest(operation.release_digest)
            and _is_digest(operation.registry_digest)
        ):
            raise TrustedBrokerError(
                "idempotency_conflict", status_code=409
            )
        return operation

    def _release_authority(self, release: str, registry: str) -> ReleaseAuthority:
        try:
            resolved = self._authority_resolver(release, registry)
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_release_authority_unavailable",
                status_code=503,
                retryable=True,
            ) from exc
        if (
            not isinstance(resolved, ReleaseAuthority)
            or not hmac.compare_digest(resolved.release_digest, release)
            or not hmac.compare_digest(resolved.registry_digest, registry)
        ):
            raise TrustedBrokerError(
                "broker_release_authority_unavailable",
                status_code=503,
                retryable=True,
            )
        return resolved

    def _release_response_verifier(
        self, release: str, registry: str
    ) -> ReleaseResponseVerifier:
        try:
            resolved = self._response_verifier_resolver(release, registry)
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_response_verifier_unavailable",
                status_code=503,
                retryable=True,
            ) from exc
        if (
            not isinstance(resolved, ReleaseResponseVerifier)
            or not hmac.compare_digest(resolved.release_digest, release)
            or not hmac.compare_digest(resolved.registry_digest, registry)
        ):
            raise TrustedBrokerError(
                "broker_response_verifier_unavailable",
                status_code=503,
                retryable=True,
            )
        return resolved

    @staticmethod
    def _verify_response(
        verifier: ReleaseResponseVerifier,
        *,
        action: str,
        response: dict[str, Any],
        request: dict[str, Any],
    ) -> None:
        try:
            verified = verifier.verify(action, response, request)
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_response_verification_failed",
                status_code=502,
                odoo_effect=(
                    "unknown" if action == "operation.approve_execute" else "none"
                ),
            ) from exc
        if verified is not True:
            raise TrustedBrokerError(
                "broker_response_verification_failed",
                status_code=502,
                odoo_effect=(
                    "unknown" if action == "operation.approve_execute" else "none"
                ),
            )

    @staticmethod
    def _authority_error(exc: Exception) -> TrustedBrokerError:
        reconciliation = _reconciliation_error(exc)
        if reconciliation is not None:
            return reconciliation
        if isinstance(exc, (ChallengeExpired, ChallengeTerminal)):
            return TrustedBrokerError("broker_approval_not_executable", status_code=409)
        if isinstance(exc, AuthorityConcurrentUpdate):
            return TrustedBrokerError(
                "broker_authority_concurrent_update",
                status_code=409,
                retryable=True,
            )
        message = str(exc).lower()
        status = 401 if "session" in message else 403
        return TrustedBrokerError("broker_authority_rejected", status_code=status)

    def _generated_identifier(self, factory: Callable[[], str]) -> str:
        try:
            return _identifier(factory(), "generated identifier")
        except Exception as exc:
            if isinstance(exc, TrustedBrokerError):
                raise TrustedBrokerError(
                    "broker_identifier_generation_failed", status_code=500
                ) from exc
            raise TrustedBrokerError(
                "broker_identifier_generation_failed", status_code=500
            ) from exc

    @staticmethod
    def _write_request(
        authorized: Any,
    ) -> dict[str, Any]:
        try:
            request = json.loads(canonical_json(authorized.request))
            return {"context": _context_mapping(authorized.context), **request}
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_authority_response_rejected", status_code=500
            ) from exc

    @staticmethod
    def _identity(
        action: str,
        response: dict[str, Any],
        *,
        operation_id: str | None,
        expected: tuple[str, str],
        request: dict[str, Any],
    ) -> tuple[str, str]:
        terminal = action in _TERMINAL_ACTIONS
        fields = {"business_succeeded", "command", "data", "ok"} if terminal else {
            "command",
            "data",
            "ok",
        }
        if (
            set(response) != fields
            or response.get("ok") is not True
            or response.get("command") != action
            or not isinstance(response.get("data"), dict)
            or (terminal and type(response.get("business_succeeded")) is not bool)
        ):
            raise TrustedBrokerError(
                "broker_executor_response_rejected",
                status_code=502,
                odoo_effect=("unknown" if action == "operation.approve_execute" else "none"),
            )
        data = response["data"]
        if action == "read":
            if data.get("capability_id") != request["capability_id"]:
                raise TrustedBrokerError(
                    "broker_executor_response_rejected", status_code=502
                )
            release_identity = data.get("release_identity")
            result = data.get("result")
            receipt = result.get("receipt") if isinstance(result, dict) else None
            if not isinstance(release_identity, dict) or not isinstance(receipt, dict):
                raise TrustedBrokerError(
                    "broker_executor_response_rejected", status_code=502
                )
            release = release_identity.get("manifest_sha256")
            registry = release_identity.get("registry_digest")
            if (
                release_identity.get("verified") is not True
                or receipt.get("release_digest") != release
                or receipt.get("registry_digest") != registry
            ):
                raise TrustedBrokerError(
                    "broker_executor_response_rejected", status_code=502
                )
        else:
            returned_operation_id = data.get("operation_id")
            if (
                not isinstance(returned_operation_id, str)
                or _IDENTIFIER.fullmatch(returned_operation_id) is None
                or (
                    action not in {"operation.prepare", "operation.recover"}
                    and returned_operation_id != operation_id
                )
            ):
                raise TrustedBrokerError(
                    "broker_executor_response_rejected",
                    status_code=502,
                    odoo_effect=(
                        "unknown" if action == "operation.approve_execute" else "none"
                    ),
                )
            if action == "operation.recover" and (
                data.get("origin_operation_id") != request["origin_operation_id"]
            ):
                raise TrustedBrokerError(
                    "broker_executor_response_rejected", status_code=502
                )
            if action in {"operation.prepare", "operation.status", "operation.recover"}:
                identity = data.get("operation")
            elif action == "operation.preview":
                identity = data.get("precheck_identity")
            else:
                identity = data.get("audit_receipt")
            if (
                not isinstance(identity, dict)
                or identity.get("operation_id") != returned_operation_id
            ):
                raise TrustedBrokerError(
                    "broker_executor_response_rejected", status_code=502
                )
            release = identity.get("release_digest")
            registry = identity.get("registry_digest")
            if terminal:
                state = data.get("operation_state")
                succeeded = response["business_succeeded"]
                if (
                    (succeeded and state not in {"completed", "recovered"})
                    or (not succeeded and state != "failed")
                ):
                    raise TrustedBrokerError(
                        "broker_executor_response_rejected",
                        status_code=502,
                        odoo_effect=(
                            "unknown"
                            if action == "operation.approve_execute"
                            else "none"
                        ),
                    )
            if terminal and not _is_digest(identity.get("signature")):
                raise TrustedBrokerError(
                    "broker_executor_response_rejected",
                    status_code=502,
                    odoo_effect=(
                        "unknown" if action == "operation.approve_execute" else "none"
                    ),
                )
        if (
            not _is_digest(release)
            or not _is_digest(registry)
            or not hmac.compare_digest(release, expected[0])
            or not hmac.compare_digest(registry, expected[1])
        ):
            raise TrustedBrokerError(
                "broker_executor_response_rejected",
                status_code=502,
                odoo_effect=("unknown" if action == "operation.approve_execute" else "none"),
            )
        return release, registry

    def _returned_operation(
        self,
        *,
        action: str,
        request: dict[str, Any],
        response: dict[str, Any],
        route: tuple[str, str],
        context: RequestContext,
    ) -> None:
        if action not in {"operation.prepare", "operation.recover"}:
            return
        returned_id = response["data"]["operation_id"]
        operation = self._operation(returned_id)
        expected_context = (
            operation.principal == context.principal
            and operation.user_id == context.user_id
            and operation.company_id == context.company_id
            and operation.odoo_instance_id == context.odoo_instance_id
            and operation.database_name == context.database_name
            and operation.database_uuid == context.database_uuid
            and operation.environment == context.environment
            and operation.release_digest == route[0]
            and operation.registry_digest == route[1]
        )
        if action == "operation.prepare":
            parameters = request["parameters"]
            expected_business = (
                operation.capability_id == request["capability_id"]
                and operation.parameters == parameters
                and isinstance(parameters.get("idempotency_key"), str)
                and operation.idempotency_key == parameters["idempotency_key"]
            )
            requested_id = request["operation_id"]
        else:
            parameters = operation.parameters
            expected_fields = {
                "company_id",
                "expected_recovery_plan_digest",
                "idempotency_key",
                "origin_operation_id",
                "reason",
                "recovery_date",
            }
            expected_business = (
                operation.capability_id == "acct.recovery.execute.v1"
                and set(parameters) == expected_fields
                and parameters.get("company_id") == context.company_id
                and parameters.get("origin_operation_id")
                == request["origin_operation_id"]
                and _is_digest(parameters.get("expected_recovery_plan_digest"))
                and parameters.get("recovery_date") == request["recovery_date"]
                and parameters.get("reason") == request["reason"]
                and parameters.get("idempotency_key") == request["idempotency_key"]
                and operation.idempotency_key == request["idempotency_key"]
            )
            requested_id = request["recovery_operation_id"]
        if not expected_context or not expected_business:
            raise TrustedBrokerError(
                "broker_idempotent_operation_rejected", status_code=502
            )
        if returned_id != requested_id:
            try:
                unexpected = self._operation_resolver(requested_id)
            except Exception as exc:
                raise TrustedBrokerError(
                    "broker_idempotent_operation_rejected", status_code=502
                ) from exc
            if unexpected is not None:
                raise TrustedBrokerError(
                    "broker_idempotent_operation_rejected", status_code=502
                )

    @staticmethod
    def _historical_error(action: str, exc: HistoricalRouterError) -> TrustedBrokerError:
        return TrustedBrokerError(
            exc.code if isinstance(exc.code, str) and exc.code else "broker_executor_failed",
            status_code=502,
            odoo_effect=exc.odoo_effect,
            retryable=exc.retryable,
        )

    def _deadline(
        self,
        deadline_monotonic: float | None,
        *,
        action: str,
        post_submit: bool = False,
    ) -> None:
        if deadline_monotonic is None:
            return
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or self._monotonic_clock() >= float(deadline_monotonic)
        ):
            raise TrustedBrokerError(
                "broker_deadline_exceeded",
                status_code=504,
                odoo_effect=(
                    "unknown"
                    if action == "operation.approve_execute" and post_submit
                    else "none"
                ),
                retryable=True,
            )

    def _dispatch_read(
        self,
        *,
        request: dict[str, Any],
        session_handle: str,
        trusted_session: TrustedSession,
        deadline_monotonic: float | None,
    ) -> TrustedBrokerResult:
        action = "read"
        try:
            authorized = self._read_authorizer(session_handle, request)
            if (
                not isinstance(authorized, AuthorizedReadAction)
                or authorized.request != request
                or not self._context_matches_session(
                    authorized.context, trusted_session
                )
            ):
                raise TrustedBrokerError("broker_read_authority_rejected")
        except TrustedBrokerError as exc:
            return self._error(action, exc, authority_verified=True)
        except Exception as exc:
            reconciliation = _reconciliation_error(exc)
            if reconciliation is not None:
                return self._error(
                    action, reconciliation, authority_verified=True
                )
            return self._error(
                action,
                TrustedBrokerError("broker_read_authority_rejected", status_code=403),
                authority_verified=True,
            )
        full_request = {
            "context": _context_mapping(authorized.context),
            **authorized.request,
        }
        try:
            response_verifier = self._release_response_verifier(
                self._current_release_digest, self._current_registry_digest
            )
            self._deadline(deadline_monotonic, action=action)
            response = _canonical_object(
                self._read_executor(full_request),
                "read response",
                error_code="broker_executor_response_rejected",
                status_code=502,
            )
            self._deadline(
                deadline_monotonic, action=action, post_submit=True
            )
            identity = self._identity(
                action,
                response,
                operation_id=None,
                expected=(self._current_release_digest, self._current_registry_digest),
                request=request,
            )
            self._verify_response(
                response_verifier,
                action=action,
                response=response,
                request=full_request,
            )
        except TrustedBrokerError as exc:
            return self._error(action, exc, authority_verified=True)
        except Exception:
            return self._error(
                action,
                TrustedBrokerError("broker_read_executor_failed", status_code=502),
                authority_verified=True,
            )
        return TrustedBrokerResult(
            status_code=200,
            body=response,
            authority_verified=True,
            executed_release_digest=identity[0],
            executed_registry_digest=identity[1],
        )

    def _route_for_write(
        self,
        action: str,
        request: dict[str, Any],
        *,
        trusted_session: TrustedSession,
    ) -> tuple[tuple[str, str], Operation | None]:
        if action == "operation.prepare":
            operation = self._existing_prepare_operation(
                session=trusted_session, request=request
            )
            if operation is None:
                return (
                    self._current_release_digest,
                    self._current_registry_digest,
                ), None
            return (
                operation.release_digest,
                operation.registry_digest,
            ), operation
        operation_id = (
            request["origin_operation_id"]
            if action == "operation.recover"
            else request["operation_id"]
        )
        operation = self._operation(operation_id)
        return (operation.release_digest, operation.registry_digest), operation

    def _full_business_write(
        self,
        action: str,
        request: dict[str, Any],
        operation: Operation | None,
    ) -> dict[str, Any]:
        if action == "operation.prepare":
            if operation is not None:
                return {
                    "operation_id": operation.operation_id,
                    "request_id": operation.request_id,
                    **request,
                }
            return {
                "operation_id": self._generated_identifier(self._operation_id_factory),
                "request_id": self._generated_identifier(self._request_id_factory),
                **request,
            }
        if action == "operation.recover":
            if operation is None:  # pragma: no cover - route invariant
                raise TrustedBrokerError("broker_operation_rejected", status_code=404)
            return {
                "origin_operation_id": operation.operation_id,
                "expected_origin_revision": operation.revision,
                "recovery_operation_id": self._generated_identifier(
                    self._recovery_operation_id_factory
                ),
                "request_id": self._generated_identifier(self._request_id_factory),
                "recovery_date": request["recovery_date"],
                "reason": request["reason"],
                "idempotency_key": request["idempotency_key"],
            }
        return request

    def _request_approval(
        self,
        release_authority: ReleaseAuthority,
        *,
        session_handle: str,
        operation_id: str,
    ) -> ApprovalChallenge:
        challenge = release_authority.authority.request_approval(
            session_handle, operation_id
        )
        if (
            challenge.operation.operation_id != operation_id
            or challenge.operation.release_digest != release_authority.release_digest
            or challenge.operation.registry_digest != release_authority.registry_digest
        ):
            raise TrustedBrokerError(
                "broker_approval_route_rejected", status_code=500
            )
        return challenge

    def _refresh_post_submit_audit_identity(
        self,
        *,
        action: str,
        business_request: dict[str, Any],
        trusted_session: TrustedSession,
        routed_operation: Operation | None,
        route: tuple[str, str],
        audit_metadata: dict[str, Any],
    ) -> None:
        """Best-effort durable relookup after a child response becomes ambiguous."""

        try:
            if action == "operation.prepare":
                operation = self._existing_prepare_operation(
                    session=trusted_session,
                    request=business_request,
                )
            elif action == "operation.recover" and routed_operation is not None:
                resolved_id = self._recovery_idempotency_resolver(
                    trusted_session,
                    routed_operation,
                    business_request,
                )
                if (
                    resolved_id is None
                    or not isinstance(resolved_id, str)
                    or _IDENTIFIER.fullmatch(resolved_id) is None
                ):
                    return
                operation = self._operation(resolved_id)
                parameters = operation.parameters
                if not (
                    operation.principal == trusted_session.principal
                    and operation.odoo_instance_id == trusted_session.odoo_instance_id
                    and operation.database_name == trusted_session.database_name
                    and operation.database_uuid == trusted_session.database_uuid
                    and operation.user_id == trusted_session.user_id
                    and operation.company_id == trusted_session.company_id
                    and operation.company_id in trusted_session.allowed_company_ids
                    and operation.environment == trusted_session.environment
                    and operation.capability_id == "acct.recovery.execute.v1"
                    and operation.idempotency_key
                    == business_request["idempotency_key"]
                    and operation.release_digest == route[0]
                    and operation.registry_digest == route[1]
                    and set(parameters)
                    == {
                        "company_id",
                        "expected_recovery_plan_digest",
                        "idempotency_key",
                        "origin_operation_id",
                        "reason",
                        "recovery_date",
                    }
                    and parameters.get("company_id") == trusted_session.company_id
                    and parameters.get("origin_operation_id")
                    == routed_operation.operation_id
                    and parameters.get("recovery_date")
                    == business_request["recovery_date"]
                    and parameters.get("reason") == business_request["reason"]
                    and parameters.get("idempotency_key")
                    == business_request["idempotency_key"]
                    and _is_digest(parameters.get("expected_recovery_plan_digest"))
                    and _IDENTIFIER.fullmatch(operation.request_id) is not None
                ):
                    return
            else:
                return
            if (
                operation is None
                or operation.release_digest != route[0]
                or operation.registry_digest != route[1]
            ):
                return
            audit_metadata["operation_id"] = operation.operation_id
            audit_metadata["request_id"] = operation.request_id
            audit_metadata["selected_release_digest"] = route[0]
            audit_metadata["selected_registry_digest"] = route[1]
        except Exception:
            # The original safe child error remains authoritative.  Failure to
            # re-resolve must never replace it or invent a different identity.
            return

    def _dispatch_write(
        self,
        *,
        action: str,
        business_request: dict[str, Any],
        session_handle: str,
        trusted_session: TrustedSession,
        deadline_monotonic: float | None,
        audit_metadata: dict[str, Any],
    ) -> TrustedBrokerResult:
        try:
            route, operation = self._route_for_write(
                action,
                business_request,
                trusted_session=trusted_session,
            )
            audit_metadata["selected_release_digest"] = route[0]
            audit_metadata["selected_registry_digest"] = route[1]
            if operation is not None:
                audit_metadata["operation_id"] = operation.operation_id
                audit_metadata["request_id"] = operation.request_id
            release_authority = self._release_authority(*route)
            response_verifier = self._release_response_verifier(*route)
            request = self._full_business_write(action, business_request, operation)
            audit_metadata["operation_id"] = (
                request["recovery_operation_id"]
                if action == "operation.recover"
                else request["operation_id"]
            )
            if isinstance(request.get("request_id"), str):
                audit_metadata["request_id"] = request["request_id"]
        except TrustedBrokerError as exc:
            return self._error(action, exc, authority_verified=True)
        try:
            if action == "operation.approve_execute":
                authorized = (
                    release_authority.authority.issue_approved_execute_for_operation(
                        session_handle, request["operation_id"]
                    )
                )
            else:
                authorized = release_authority.authority.issue_write_action(
                    session_handle, action, request
                )
            if not self._context_matches_session(
                authorized.context, trusted_session
            ):
                raise TrustedBrokerError(
                    "broker_authority_session_mismatch", status_code=500
                )
            full_request = self._write_request(authorized)
        except AuthorityError as exc:
            return self._error(
                action, self._authority_error(exc), authority_verified=True
            )
        except TrustedBrokerError as exc:
            return self._error(action, exc, authority_verified=True)
        except Exception as exc:
            reconciliation = _reconciliation_error(exc)
            if reconciliation is not None:
                return self._error(
                    action, reconciliation, authority_verified=True
                )
            raise
        try:
            self._deadline(deadline_monotonic, action=action)
            response = _canonical_object(
                self._historical_executor.dispatch(
                    action,
                    full_request,
                    deadline_monotonic=deadline_monotonic,
                ),
                "historical executor response",
                error_code="broker_executor_response_rejected",
                status_code=502,
                odoo_effect=(
                    "unknown" if action == "operation.approve_execute" else "none"
                ),
            )
            self._deadline(
                deadline_monotonic, action=action, post_submit=True
            )
            operation_id = (
                request["recovery_operation_id"]
                if action == "operation.recover"
                else request["operation_id"]
            )
            identity = self._identity(
                action,
                response,
                operation_id=operation_id,
                expected=route,
                request=request,
            )
            self._returned_operation(
                action=action,
                request=request,
                response=response,
                route=route,
                context=authorized.context,
            )
            self._verify_response(
                response_verifier,
                action=action,
                response=response,
                request=full_request,
            )
        except HistoricalRouterError as exc:
            self._refresh_post_submit_audit_identity(
                action=action,
                business_request=business_request,
                trusted_session=trusted_session,
                routed_operation=operation,
                route=route,
                audit_metadata=audit_metadata,
            )
            return self._error(
                action,
                self._historical_error(action, exc),
                authority_verified=True,
            )
        except TrustedBrokerError as exc:
            self._refresh_post_submit_audit_identity(
                action=action,
                business_request=business_request,
                trusted_session=trusted_session,
                routed_operation=operation,
                route=route,
                audit_metadata=audit_metadata,
            )
            if (
                action in {"operation.prepare", "operation.recover"}
                and not exc.retryable
                and not exc.reconciliation_required
            ):
                exc = TrustedBrokerError(
                    exc.code,
                    status_code=exc.status_code,
                    odoo_effect=exc.odoo_effect,
                    retryable=True,
                )
            return self._error(action, exc, authority_verified=True)
        except Exception:
            self._refresh_post_submit_audit_identity(
                action=action,
                business_request=business_request,
                trusted_session=trusted_session,
                routed_operation=operation,
                route=route,
                audit_metadata=audit_metadata,
            )
            return self._error(
                action,
                TrustedBrokerError(
                    "broker_executor_failed",
                    status_code=502,
                    odoo_effect=(
                        "unknown" if action == "operation.approve_execute" else "none"
                    ),
                    retryable=action in {"operation.prepare", "operation.recover"},
                ),
                authority_verified=True,
            )
        if action == "operation.preview":
            try:
                challenge = self._request_approval(
                    release_authority,
                    session_handle=session_handle,
                    operation_id=request["operation_id"],
                )
                response["data"]["approval_challenge"] = _challenge_view(challenge)
                audit_metadata["challenge_id"] = challenge.challenge_id
            except (AuthorityError, TrustedBrokerError) as exc:
                error = (
                    exc
                    if isinstance(exc, TrustedBrokerError)
                    else self._authority_error(exc)
                )
                return self._error(
                    action,
                    error,
                    authority_verified=True,
                    executed_identity=identity,
                )
        return TrustedBrokerResult(
            status_code=200,
            body=response,
            authority_verified=True,
            executed_release_digest=identity[0],
            executed_registry_digest=identity[1],
        )

    def _audit_operation(
        self,
        *,
        action: str,
        payload: Mapping[str, Any],
        result: TrustedBrokerResult,
        session: TrustedSession,
        audit_metadata: Mapping[str, Any],
    ) -> tuple[str | None, str | None, Operation | None]:
        data = result.body.get("data")
        returned_id = data.get("operation_id") if isinstance(data, Mapping) else None
        claimed_id: object = returned_id
        if not isinstance(claimed_id, str):
            claimed_id = audit_metadata.get("operation_id")
        if not isinstance(claimed_id, str):
            if action == "operation.recover":
                claimed_id = payload.get("origin_operation_id")
            else:
                claimed_id = payload.get("operation_id")
        operation_id = (
            claimed_id
            if isinstance(claimed_id, str) and _IDENTIFIER.fullmatch(claimed_id)
            else None
        )
        if operation_id is None:
            return None, self._audit_request_id(audit_metadata), None
        try:
            operation = self._operation_resolver(operation_id)
            if not isinstance(operation, Operation):
                return operation_id, self._audit_request_id(audit_metadata), None
            operation.assert_integrity()
        except Exception:
            return operation_id, self._audit_request_id(audit_metadata), None
        if not (
            operation.operation_id == operation_id
            and operation.principal == session.principal
            and operation.odoo_instance_id == session.odoo_instance_id
            and operation.database_name == session.database_name
            and operation.database_uuid == session.database_uuid
            and operation.user_id == session.user_id
            and operation.company_id == session.company_id
            and operation.company_id in session.allowed_company_ids
            and operation.environment == session.environment
        ):
            return operation_id, self._audit_request_id(audit_metadata), None
        return operation_id, operation.request_id, operation

    @staticmethod
    def _audit_request_id(audit_metadata: Mapping[str, Any]) -> str | None:
        request_id = audit_metadata.get("request_id")
        if isinstance(request_id, str) and _IDENTIFIER.fullmatch(request_id):
            return request_id
        return None

    def _record_write_audit(
        self,
        *,
        action: str,
        payload: Mapping[str, Any],
        request_digest: str,
        result: TrustedBrokerResult,
        session: TrustedSession,
        peer_uid: int | None,
        peer_gid: int | None,
        peer_pid: int | None,
        audit_metadata: Mapping[str, Any],
    ) -> None:
        operation_id, request_id, operation = self._audit_operation(
            action=action,
            payload=payload,
            result=result,
            session=session,
            audit_metadata=audit_metadata,
        )
        data = result.body.get("data")
        challenge = (
            data.get("approval_challenge") if isinstance(data, Mapping) else None
        )
        challenge_id = (
            challenge.get("challenge_id") if isinstance(challenge, Mapping) else None
        )
        if not (
            isinstance(challenge_id, str)
            and _IDENTIFIER.fullmatch(challenge_id) is not None
        ):
            metadata_challenge = audit_metadata.get("challenge_id")
            challenge_id = (
                metadata_challenge
                if isinstance(metadata_challenge, str)
                and _IDENTIFIER.fullmatch(metadata_challenge) is not None
                else None
            )

        error = result.body.get("error")
        if isinstance(error, Mapping) and isinstance(error.get("code"), str):
            outcome_code = error["code"]
            odoo_effect = error.get("odoo_effect", "none")
        elif result.body.get("business_succeeded") is True:
            outcome_code = "business_succeeded"
            odoo_effect = (
                "verified" if action == "operation.approve_execute" else "none"
            )
        elif result.body.get("business_succeeded") is False:
            outcome_code = "business_failed"
            odoo_effect = (
                "unknown" if action == "operation.approve_execute" else "none"
            )
        else:
            outcome_code = "ok"
            odoo_effect = "none"

        selected_release = result.executed_release_digest
        selected_registry = result.executed_registry_digest
        if selected_release is None:
            metadata_release = audit_metadata.get("selected_release_digest")
            metadata_registry = audit_metadata.get("selected_registry_digest")
            if _is_digest(metadata_release) and _is_digest(metadata_registry):
                selected_release = metadata_release
                selected_registry = metadata_registry
        if selected_release is None and operation is not None:
            selected_release = operation.release_digest
            selected_registry = operation.registry_digest
        expected = {
            "action": action,
            "request_digest": request_digest,
            "principal": session.principal,
            "user_id": session.user_id,
            "company_id": session.company_id,
            "database_name": session.database_name,
            "database_uuid": session.database_uuid,
            "environment": session.environment,
            "odoo_instance_id": session.odoo_instance_id,
            "current_release_digest": self._current_release_digest,
            "current_registry_digest": self._current_registry_digest,
            "selected_release_digest": selected_release,
            "selected_registry_digest": selected_registry,
            "operation_id": operation_id,
            "challenge_id": challenge_id,
            "request_id": request_id,
            "outcome_code": outcome_code,
            "odoo_effect": odoo_effect,
            "peer_uid": peer_uid,
            "peer_gid": peer_gid,
            "peer_pid": peer_pid,
        }
        event = self._audit_sink.record(**expected)
        if not isinstance(event, BrokerWriteAuditEvent) or any(
            getattr(event, field_name, object()) != value
            for field_name, value in expected.items()
        ):
            raise TrustedBrokerError("broker_audit_append_rejected", status_code=500)

    def _record_approval_audit(
        self,
        *,
        action: str,
        request_digest: str,
        session: TrustedSession,
        outcome_code: str,
        challenge_id: str | None,
        operation: Operation | None,
        route: tuple[str, str] | None,
        peer_uid: int | None,
        peer_gid: int | None,
        peer_pid: int | None,
        bound_operation_id: str | None = None,
        bound_request_id: str | None = None,
    ) -> None:
        peer_uid, peer_gid, peer_pid = _approval_peer_metadata(
            peer_uid, peer_gid, peer_pid
        )
        if operation is not None:
            if (
                bound_operation_id is not None
                and bound_operation_id != operation.operation_id
            ) or (
                bound_request_id is not None
                and bound_request_id != operation.request_id
            ):
                raise TrustedBrokerError(
                    "broker_audit_append_rejected", status_code=500
                )
            operation_id = operation.operation_id
            request_id = operation.request_id
        else:
            operation_id = bound_operation_id
            request_id = bound_request_id
        if (
            operation_id is not None
            and (
                not isinstance(operation_id, str)
                or _IDENTIFIER.fullmatch(operation_id) is None
            )
        ) or (
            request_id is not None
            and (
                not isinstance(request_id, str)
                or _IDENTIFIER.fullmatch(request_id) is None
            )
        ):
            raise TrustedBrokerError(
                "broker_audit_append_rejected", status_code=500
            )
        expected = {
            "action": action,
            "request_digest": request_digest,
            "principal": session.principal,
            "user_id": session.user_id,
            "company_id": session.company_id,
            "database_name": session.database_name,
            "database_uuid": session.database_uuid,
            "environment": session.environment,
            "odoo_instance_id": session.odoo_instance_id,
            "current_release_digest": self._current_release_digest,
            "current_registry_digest": self._current_registry_digest,
            "selected_release_digest": None if route is None else route[0],
            "selected_registry_digest": None if route is None else route[1],
            "operation_id": operation_id,
            "challenge_id": challenge_id,
            "request_id": request_id,
            "outcome_code": outcome_code,
            "odoo_effect": "none",
            "peer_uid": peer_uid,
            "peer_gid": peer_gid,
            "peer_pid": peer_pid,
        }
        event = self._audit_sink.record(**expected)
        if not isinstance(event, BrokerWriteAuditEvent) or any(
            getattr(event, field_name, object()) != value
            for field_name, value in expected.items()
        ):
            raise TrustedBrokerError("broker_audit_append_rejected", status_code=500)

    def dispatch(
        self,
        *,
        action: str,
        payload: Mapping[str, Any],
        session_handle: str,
        expected_release_digest: str,
        expected_registry_digest: str,
        deadline_monotonic: float | None = None,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> TrustedBrokerResult:
        """Dispatch one fixed Pi action without accepting authority or route data."""

        safe_action = (
            action
            if isinstance(action, str) and _IDENTIFIER.fullmatch(action) is not None
            else "unknown"
        )
        try:
            self._assert_current_headers(
                expected_release_digest, expected_registry_digest
            )
            if (
                not isinstance(session_handle, str)
                or _SESSION_HANDLE.fullmatch(session_handle) is None
            ):
                raise TrustedBrokerError("broker_session_rejected", status_code=401)
        except TrustedBrokerError as exc:
            return self._error(safe_action, exc)
        try:
            trusted_session = self._authenticate_session(session_handle)
        except TrustedBrokerError as exc:
            return self._error(safe_action, exc)
        audit_metadata: dict[str, Any] = {}
        if action != "read":
            try:
                request_digest = canonical_request_digest(
                    {"action": action, "payload": payload}
                )
            except Exception:
                return self._error(
                    safe_action,
                    TrustedBrokerError(
                        "broker_audit_failed",
                        status_code=503,
                        retryable=True,
                    ),
                    authority_verified=True,
                )

            def audited(result: TrustedBrokerResult) -> TrustedBrokerResult:
                try:
                    self._record_write_audit(
                        action=safe_action,
                        payload=payload,
                        request_digest=request_digest,
                        result=result,
                        session=trusted_session,
                        peer_uid=peer_uid,
                        peer_gid=peer_gid,
                        peer_pid=peer_pid,
                        audit_metadata=audit_metadata,
                    )
                except Exception:
                    result_error = result.body.get("error")
                    if (
                        isinstance(result_error, dict)
                        and result_error.get("reconciliation_required") is True
                        and result_error.get("retryable") is False
                    ):
                        return result
                    return self._error(
                        safe_action,
                        TrustedBrokerError(
                            "broker_audit_failed",
                            status_code=503,
                            odoo_effect=(
                                "unknown"
                                if action == "operation.approve_execute"
                                else "none"
                            ),
                            retryable=True,
                        ),
                        authority_verified=True,
                        executed_identity=(
                            None
                            if result.executed_release_digest is None
                            else (
                                result.executed_release_digest,
                                result.executed_registry_digest,
                            )
                        ),
                    )
                return result

        try:
            request = _business_request(action, payload)
        except TrustedBrokerError as exc:
            result = self._error(safe_action, exc, authority_verified=True)
            return result if action == "read" else audited(result)
        if action == "read":
            return self._dispatch_read(
                request=request,
                session_handle=session_handle,
                trusted_session=trusted_session,
                deadline_monotonic=deadline_monotonic,
            )
        try:
            result = self._dispatch_write(
                action=action,
                business_request=request,
                session_handle=session_handle,
                trusted_session=trusted_session,
                deadline_monotonic=deadline_monotonic,
                audit_metadata=audit_metadata,
            )
        except Exception as exc:
            reconciliation = _reconciliation_error(exc)
            result = self._error(
                safe_action,
                reconciliation
                or TrustedBrokerError(
                    "broker_write_dispatch_failed",
                    status_code=500,
                    odoo_effect=(
                        "unknown"
                        if action == "operation.approve_execute"
                        else "none"
                    ),
                    retryable=True,
                ),
                authority_verified=True,
            )
        return audited(result)

    def request_approval(
        self,
        *,
        session_handle: str,
        operation_id: str,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]:
        """Return/reuse the exact sanitized challenge for a previewed operation."""

        peer_uid, peer_gid, peer_pid = _approval_peer_metadata(
            peer_uid, peer_gid, peer_pid
        )
        session = self._authenticate_session(session_handle)
        try:
            request_digest = canonical_request_digest(
                {"action": "approval.request", "payload": {"operation_id": operation_id}}
            )
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_audit_failed", status_code=503, retryable=True
            ) from exc
        operation: Operation | None = None
        route: tuple[str, str] | None = None
        challenge_id: str | None = None
        try:
            operation_id = _identifier(operation_id, "operation_id")
            operation = self._operation(operation_id)
            route = (operation.release_digest, operation.registry_digest)
            release_authority = self._release_authority(
                operation.release_digest, operation.registry_digest
            )
            challenge = self._request_approval(
                release_authority,
                session_handle=session_handle,
                operation_id=operation_id,
            )
            challenge_id = challenge.challenge_id
        except TrustedBrokerError as exc:
            error = exc
        except AuthorityError as exc:
            error = _reconciliation_error(exc) or TrustedBrokerError(
                "broker_approval_rejected", status_code=403
            )
        except Exception as exc:
            error = _reconciliation_error(exc) or TrustedBrokerError(
                "broker_approval_rejected", status_code=500, retryable=True
            )
        else:
            error = None
        try:
            self._record_approval_audit(
                action="approval.request",
                request_digest=request_digest,
                session=session,
                outcome_code="ok" if error is None else error.code,
                challenge_id=challenge_id,
                operation=operation,
                route=route,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
            )
        except Exception as exc:
            if error is not None and error.reconciliation_required:
                raise error from None
            raise TrustedBrokerError(
                "broker_audit_failed", status_code=503, retryable=True
            ) from exc
        if error is not None:
            raise error
        return _challenge_view(challenge)

    def inspect_approval(
        self,
        *,
        session_handle: str,
        challenge_id: str,
        peer_uid: int | None = None,
        peer_gid: int | None = None,
        peer_pid: int | None = None,
    ) -> dict[str, Any]:
        """Return an approver-only preview bound to durable precheck evidence."""

        peer_uid, peer_gid, peer_pid = _approval_peer_metadata(
            peer_uid, peer_gid, peer_pid
        )
        session = self._authenticate_session(session_handle)
        try:
            request_digest = canonical_request_digest(
                {
                    "action": "approval.inspect",
                    "payload": {"challenge_id": challenge_id},
                }
            )
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_audit_failed", status_code=503, retryable=True
            ) from exc
        route: tuple[str, str] | None = None
        safe_challenge_id: str | None = None
        bound_operation_id: str | None = None
        bound_request_id: str | None = None
        try:
            challenge_id = _identifier(challenge_id, "challenge_id")
            safe_challenge_id = challenge_id
            resolved = self._challenge_authority_resolver(challenge_id)
            if not isinstance(resolved, ReleaseAuthority):
                raise TrustedBrokerError(
                    "broker_approval_challenge_rejected", status_code=404
                )
            route = (resolved.release_digest, resolved.registry_digest)
            raw_preview = resolved.authority.inspect_approval(
                session_handle, challenge_id
            )
            try:
                authority_preview = _authority_inspection_preview(
                    raw_preview,
                    challenge_id=challenge_id,
                    route=route,
                )
            except TrustedBrokerError:
                raise
            except Exception as exc:
                raise TrustedBrokerError(
                    "broker_approval_preview_rejected", status_code=500
                ) from exc
            bound_operation_id = authority_preview["operation"]["operation_id"]
            bound_request_id = authority_preview["operation"]["request_id"]
            if self._precheck_resolver is None:
                raise TrustedBrokerError(
                    "broker_approval_precheck_rejected",
                    status_code=503,
                    retryable=True,
                )
            try:
                precheck_record = self._precheck_resolver(bound_operation_id)
            except Exception as exc:
                raise TrustedBrokerError(
                    "broker_approval_precheck_rejected",
                    status_code=503,
                    retryable=True,
                ) from exc
            if precheck_record is None:
                raise TrustedBrokerError(
                    "broker_approval_precheck_rejected",
                    status_code=503,
                    retryable=True,
                )
            try:
                precheck = _bound_precheck_preview(
                    precheck_record, authority_preview
                )
                inspection = _inspection_with_precheck(
                    authority_preview, precheck
                )
            except TrustedBrokerError:
                raise
            except Exception as exc:
                raise TrustedBrokerError(
                    "broker_approval_precheck_rejected", status_code=500
                ) from exc
        except TrustedBrokerError as exc:
            error = exc
        except AuthorityError as exc:
            error = _reconciliation_error(exc) or TrustedBrokerError(
                "broker_approval_rejected", status_code=403
            )
        except Exception as exc:
            error = _reconciliation_error(exc) or TrustedBrokerError(
                "broker_approval_rejected", status_code=500, retryable=True
            )
        else:
            error = None
        try:
            self._record_approval_audit(
                action="approval.inspect",
                request_digest=request_digest,
                session=session,
                outcome_code="ok" if error is None else error.code,
                challenge_id=safe_challenge_id,
                operation=None,
                route=route,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
                bound_operation_id=bound_operation_id,
                bound_request_id=bound_request_id,
            )
        except Exception as exc:
            if error is not None and error.reconciliation_required:
                raise error from None
            raise TrustedBrokerError(
                "broker_audit_failed", status_code=503, retryable=True
            ) from exc
        if error is not None:
            raise error
        return inspection

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
    ) -> dict[str, Any]:
        """Apply an independent approver decision and expose no signed approval."""

        peer_uid, peer_gid, peer_pid = _approval_peer_metadata(
            peer_uid, peer_gid, peer_pid
        )
        session = self._authenticate_session(session_handle)
        try:
            request_digest = canonical_request_digest(
                {
                    "action": "approval.decide",
                    "payload": {
                        "challenge_id": challenge_id,
                        "decision": decision,
                        "reason": reason,
                    },
                }
            )
        except Exception as exc:
            raise TrustedBrokerError(
                "broker_audit_failed", status_code=503, retryable=True
            ) from exc
        route: tuple[str, str] | None = None
        operation: Operation | None = None
        safe_challenge_id: str | None = None
        try:
            challenge_id = _identifier(challenge_id, "challenge_id")
            safe_challenge_id = challenge_id
            resolved = self._challenge_authority_resolver(challenge_id)
            if not isinstance(resolved, ReleaseAuthority):
                raise TrustedBrokerError(
                    "broker_approval_challenge_rejected", status_code=404
                )
            route = (resolved.release_digest, resolved.registry_digest)
            challenge = resolved.authority.decide_approval(
                session_handle,
                challenge_id,
                decision,
                reason=reason,
            )
            if (
                challenge.operation.release_digest != resolved.release_digest
                or challenge.operation.registry_digest != resolved.registry_digest
            ):
                raise TrustedBrokerError(
                    "broker_approval_route_rejected", status_code=500
                )
            operation = challenge.operation
        except TrustedBrokerError as exc:
            error = exc
        except AuthorityError as exc:
            error = _reconciliation_error(exc) or TrustedBrokerError(
                "broker_approval_rejected", status_code=403
            )
        except Exception as exc:
            error = _reconciliation_error(exc) or TrustedBrokerError(
                "broker_approval_rejected", status_code=403
            )
        else:
            error = None
        try:
            self._record_approval_audit(
                action="approval.decide",
                request_digest=request_digest,
                session=session,
                outcome_code="ok" if error is None else error.code,
                challenge_id=safe_challenge_id,
                operation=operation,
                route=route,
                peer_uid=peer_uid,
                peer_gid=peer_gid,
                peer_pid=peer_pid,
            )
        except Exception as exc:
            if error is not None and error.reconciliation_required:
                raise error from None
            raise TrustedBrokerError(
                "broker_audit_failed", status_code=503, retryable=True
            ) from exc
        if error is not None:
            raise error
        return _challenge_view(challenge)

    def __call__(self, request: Any) -> Any:
        """Adapt the core to :mod:`trusted_broker_uds`'s dispatcher contract."""

        from .trusted_broker_uds import BrokerDispatchRequest, BrokerDispatchResult

        if not isinstance(request, BrokerDispatchRequest):
            raise TrustedBrokerError("broker_transport_request_rejected")
        result = self.dispatch(
            action=request.action,
            payload=request.payload,
            session_handle=request.session_handle,
            expected_release_digest=request.release_digest,
            expected_registry_digest=request.registry_digest,
            deadline_monotonic=request.deadline_monotonic,
            peer_uid=request.peer_uid,
            peer_gid=request.observed_peer_gid,
            peer_pid=request.observed_peer_pid,
        )
        return BrokerDispatchResult(
            status_code=result.status_code,
            body=result.body,
            authority_verified=result.authority_verified,
            executed_release_digest=result.executed_release_digest,
            executed_registry_digest=result.executed_registry_digest,
        )


__all__ = [
    "AuthorizedReadAction",
    "HistoricalExecutor",
    "PrecheckResolver",
    "PrepareIdempotencyResolver",
    "ReleaseAuthority",
    "ReleaseResponseVerifier",
    "ResponseVerifier",
    "TrustedBroker",
    "TrustedBrokerError",
    "TrustedBrokerResult",
]

"""Write-operation state and approval invariants.

Persistence and Odoo execution are deliberately outside this module. This core
only permits valid transitions and produces deterministic operation digests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Callable


class OperationError(ValueError):
    """Base error for rejected operation transitions."""


class ConcurrentUpdate(OperationError):
    pass


class IntegrityRejected(OperationError):
    pass


class ApprovalRejected(OperationError):
    pass


class TrustedResultRejected(OperationError):
    pass


class State(StrEnum):
    PREPARED = "prepared"
    PRECHECKED = "prechecked"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    RECOVERING = "recovering"
    RECOVERED = "recovered"


ALLOWED_TRANSITIONS: dict[State, frozenset[State]] = {
    State.PREPARED: frozenset({State.PRECHECKED, State.FAILED}),
    State.PRECHECKED: frozenset({State.AWAITING_APPROVAL, State.FAILED}),
    State.AWAITING_APPROVAL: frozenset({State.APPROVED, State.FAILED}),
    State.APPROVED: frozenset({State.EXECUTING, State.FAILED}),
    State.EXECUTING: frozenset({State.VERIFYING, State.FAILED}),
    State.VERIFYING: frozenset({State.COMPLETED, State.FAILED}),
    State.COMPLETED: frozenset({State.RECOVERING}),
    State.FAILED: frozenset({State.RECOVERING}),
    State.RECOVERING: frozenset({State.RECOVERED, State.FAILED}),
    State.RECOVERED: frozenset(),
}

MAX_APPROVAL_TTL = timedelta(minutes=15)
MIN_HMAC_SECRET_BYTES = 32
SIGNATURE_VERSION = 1
APPROVAL_PURPOSE = "approval_v1"
EXECUTION_RESULT_PURPOSE = "execution_result_v1"
VERIFICATION_RESULT_PURPOSE = "verification_result_v1"

_GUARDED_TARGETS: dict[State, str] = {
    State.APPROVED: "approve_operation",
    State.EXECUTING: "begin_execution",
    State.VERIFYING: "record_execution_result",
    State.COMPLETED: "complete_operation",
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def operation_digest(
    *,
    capability_id: str,
    parameters: dict[str, Any],
    principal: str,
    user_id: int,
    company_id: int,
    idempotency_key: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    environment: str,
    registry_digest: str,
    release_digest: str,
) -> str:
    envelope = {
        "capability_id": capability_id,
        "company_id": company_id,
        "database_name": database_name,
        "database_uuid": database_uuid,
        "environment": environment,
        "idempotency_key": idempotency_key,
        "odoo_instance_id": odoo_instance_id,
        "parameters": parameters,
        "principal": principal,
        "registry_digest": registry_digest,
        "release_digest": release_digest,
        "user_id": user_id,
    }
    return hashlib.sha256(canonical_json(envelope)).hexdigest()


@dataclass(frozen=True)
class Operation:
    operation_id: str
    request_id: str
    capability_id: str
    parameters_json: str
    principal: str
    user_id: int
    company_id: int
    idempotency_key: str
    odoo_instance_id: str
    database_name: str
    database_uuid: str
    environment: str
    registry_digest: str
    release_digest: str
    digest: str
    state: State = State.PREPARED
    revision: int = 0
    approval_signature: str | None = None
    approval_nonce_digest: str | None = None
    approval_issued_at: datetime | None = None
    approval_expires_at: datetime | None = None
    approval_revision: int | None = None
    approver_user_id: int | None = None
    execution_result_digest: str | None = None
    verification_result_digest: str | None = None

    @property
    def parameters(self) -> dict[str, Any]:
        """Return a detached copy so approved content cannot be mutated."""
        self.assert_integrity()
        return json.loads(self.parameters_json)

    def assert_integrity(self) -> None:
        try:
            parameters = json.loads(self.parameters_json)
            canonical_parameters = canonical_json(parameters).decode("utf-8")
            normalized_database_uuid = str(uuid.UUID(self.database_uuid))
            expected = operation_digest(
                capability_id=self.capability_id,
                parameters=parameters,
                principal=self.principal,
                user_id=self.user_id,
                company_id=self.company_id,
                idempotency_key=self.idempotency_key,
                odoo_instance_id=self.odoo_instance_id,
                database_name=self.database_name,
                database_uuid=normalized_database_uuid,
                environment=self.environment,
                registry_digest=self.registry_digest,
                release_digest=self.release_digest,
            )
        except (AttributeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntegrityRejected("operation immutable content is invalid") from exc
        if (
            not isinstance(parameters, dict)
            or canonical_parameters != self.parameters_json
            or normalized_database_uuid != self.database_uuid
            or not _is_sha256(self.registry_digest)
            or not _is_sha256(self.release_digest)
            or not isinstance(self.digest, str)
            or not hmac.compare_digest(expected, self.digest)
        ):
            raise IntegrityRejected("operation immutable content digest mismatch")

    @classmethod
    def prepare(
        cls,
        *,
        operation_id: str,
        request_id: str,
        capability_id: str,
        parameters: dict[str, Any],
        principal: str,
        user_id: int,
        company_id: int,
        idempotency_key: str,
        odoo_instance_id: str,
        database_name: str,
        database_uuid: str,
        environment: str,
        registry_digest: str,
        release_digest: str,
    ) -> "Operation":
        identifiers = (
            operation_id,
            request_id,
            capability_id,
            idempotency_key,
            principal,
            odoo_instance_id,
            database_name,
        )
        if any(not isinstance(value, str) or not value.strip() for value in identifiers):
            raise OperationError("operation_id, request_id, capability_id, idempotency_key, and principal are required")
        if (
            isinstance(user_id, bool)
            or not isinstance(user_id, int)
            or user_id <= 0
            or isinstance(company_id, bool)
            or not isinstance(company_id, int)
            or company_id <= 0
        ):
            raise OperationError("positive user_id and company_id are required")
        try:
            normalized_database_uuid = str(uuid.UUID(database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise OperationError("database_uuid must be a UUID") from exc
        if environment not in {"test", "sandbox", "production"}:
            raise OperationError("environment is invalid")
        if not _is_sha256(registry_digest) or not _is_sha256(release_digest):
            raise OperationError("registry_digest and release_digest must be SHA-256 digests")
        if not isinstance(parameters, dict):
            raise OperationError("parameters must be an object")
        normalized_parameters = canonical_json(parameters).decode("utf-8")
        digest = operation_digest(
            capability_id=capability_id,
            parameters=json.loads(normalized_parameters),
            principal=principal,
            user_id=user_id,
            company_id=company_id,
            idempotency_key=idempotency_key,
            odoo_instance_id=odoo_instance_id,
            database_name=database_name,
            database_uuid=normalized_database_uuid,
            environment=environment,
            registry_digest=registry_digest,
            release_digest=release_digest,
        )
        return cls(
            operation_id=operation_id,
            request_id=request_id,
            capability_id=capability_id,
            parameters_json=normalized_parameters,
            principal=principal,
            user_id=user_id,
            company_id=company_id,
            idempotency_key=idempotency_key,
            odoo_instance_id=odoo_instance_id,
            database_name=database_name,
            database_uuid=normalized_database_uuid,
            environment=environment,
            registry_digest=registry_digest,
            release_digest=release_digest,
            digest=digest,
        )

    def transition(self, target: State, *, expected_revision: int) -> "Operation":
        self._check_transition(target, expected_revision=expected_revision)
        if target in _GUARDED_TARGETS:
            raise OperationError(
                f"transition to {target} requires {_GUARDED_TARGETS[target]}"
            )
        return self._apply_transition(target)

    def _check_transition(self, target: State, *, expected_revision: int) -> None:
        self.assert_integrity()
        if expected_revision != self.revision:
            raise ConcurrentUpdate("operation revision has changed")
        if target not in ALLOWED_TRANSITIONS[self.state]:
            raise OperationError(f"invalid transition: {self.state} -> {target}")

    def _apply_transition(self, target: State, **changes: Any) -> "Operation":
        return replace(self, state=target, revision=self.revision + 1, **changes)


@dataclass(frozen=True)
class Approval:
    operation_id: str
    operation_digest: str
    user_id: int
    company_id: int
    operation_revision: int
    approver_user_id: int
    nonce: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def payload(self) -> dict[str, Any]:
        return {
            "approver_user_id": self.approver_user_id,
            "company_id": self.company_id,
            "expires_at": self.expires_at.astimezone(timezone.utc).isoformat(),
            "issued_at": self.issued_at.astimezone(timezone.utc).isoformat(),
            "nonce": self.nonce,
            "operation_digest": self.operation_digest,
            "operation_id": self.operation_id,
            "operation_revision": self.operation_revision,
            "purpose": APPROVAL_PURPOSE,
            "user_id": self.user_id,
            "version": SIGNATURE_VERSION,
        }


class ResultKind(StrEnum):
    EXECUTION = "execution"
    VERIFICATION = "verification"


@dataclass(frozen=True)
class TrustedResult:
    kind: ResultKind
    operation_id: str
    operation_digest: str
    operation_revision: int
    company_id: int
    issuer: str
    key_id: str
    succeeded: bool
    evidence_digest: str
    prior_evidence_digest: str | None
    issued_at: datetime
    signature: str

    def payload(self) -> dict[str, Any]:
        purpose = (
            EXECUTION_RESULT_PURPOSE
            if self.kind == ResultKind.EXECUTION
            else VERIFICATION_RESULT_PURPOSE
        )
        return {
            "company_id": self.company_id,
            "evidence_digest": self.evidence_digest,
            "issued_at": self.issued_at.astimezone(timezone.utc).isoformat(),
            "issuer": self.issuer,
            "key_id": self.key_id,
            "kind": self.kind,
            "operation_digest": self.operation_digest,
            "operation_id": self.operation_id,
            "operation_revision": self.operation_revision,
            "prior_evidence_digest": self.prior_evidence_digest,
            "purpose": purpose,
            "succeeded": self.succeeded,
            "version": SIGNATURE_VERSION,
        }


def _is_aware(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _is_sha256(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _is_strong_hmac_secret(value: object) -> bool:
    return isinstance(value, bytes) and len(value) >= MIN_HMAC_SECRET_BYTES


def _validate_approval_ttl(approval: Approval, approval_ttl_seconds: int) -> None:
    maximum_seconds = int(MAX_APPROVAL_TTL.total_seconds())
    if (
        isinstance(approval_ttl_seconds, bool)
        or not isinstance(approval_ttl_seconds, int)
        or not 1 <= approval_ttl_seconds <= maximum_seconds
    ):
        raise ApprovalRejected("approval policy TTL is invalid")
    if approval.expires_at - approval.issued_at > timedelta(seconds=approval_ttl_seconds):
        raise ApprovalRejected("approval validity exceeds capability policy TTL")


def sign_approval(
    *,
    operation: Operation,
    approver_user_id: int,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    approval_ttl_seconds: int,
    secret: bytes,
) -> Approval:
    operation.assert_integrity()
    if operation.state != State.AWAITING_APPROVAL:
        raise ApprovalRejected("operation is not awaiting approval")
    if not _is_strong_hmac_secret(secret):
        raise ApprovalRejected("approval HMAC secret must be bytes of at least 32 bytes")
    if (
        not isinstance(nonce, str)
        or not nonce
        or isinstance(approver_user_id, bool)
        or not isinstance(approver_user_id, int)
        or approver_user_id <= 0
    ):
        raise ApprovalRejected("approval signer, nonce, and secret are required")
    if approver_user_id == operation.user_id:
        raise ApprovalRejected("requester cannot approve their own operation")
    if not _is_aware(issued_at) or not _is_aware(expires_at) or expires_at <= issued_at:
        raise ApprovalRejected("approval timestamps must be timezone-aware and increasing")
    if expires_at - issued_at > MAX_APPROVAL_TTL:
        raise ApprovalRejected("approval validity exceeds maximum TTL")
    unsigned = Approval(
        operation_id=operation.operation_id,
        operation_digest=operation.digest,
        user_id=operation.user_id,
        company_id=operation.company_id,
        operation_revision=operation.revision,
        approver_user_id=approver_user_id,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        signature="",
    )
    _validate_approval_ttl(unsigned, approval_ttl_seconds)
    signature = hmac.new(secret, canonical_json(unsigned.payload()), hashlib.sha256).hexdigest()
    return replace(unsigned, signature=signature)


def approve_operation(
    operation: Operation,
    approval: Approval,
    *,
    now: datetime,
    secret: bytes,
    is_approver_authorized: Callable[[int, int, str], bool],
    consume_nonce: Callable[[str, str, int], bool],
    approval_ttl_seconds: int,
    expected_revision: int,
) -> Operation:
    try:
        operation._check_transition(State.APPROVED, expected_revision=expected_revision)
    except OperationError as exc:
        if isinstance(exc, ConcurrentUpdate):
            raise
        raise ApprovalRejected("operation is not awaiting approval") from exc
    if not _is_aware(now):
        raise ApprovalRejected("current time must be timezone-aware")
    if not _is_strong_hmac_secret(secret):
        raise ApprovalRejected("approval HMAC secret must be bytes of at least 32 bytes")
    if (
        not isinstance(approval.nonce, str)
        or not approval.nonce
        or isinstance(approval.approver_user_id, bool)
        or not isinstance(approval.approver_user_id, int)
        or approval.approver_user_id <= 0
    ):
        raise ApprovalRejected("approval signer, nonce, and secret are required")
    bindings = (
        approval.operation_id == operation.operation_id
        and approval.operation_digest == operation.digest
        and approval.user_id == operation.user_id
        and approval.company_id == operation.company_id
        and approval.operation_revision == operation.revision
    )
    if not bindings:
        raise ApprovalRejected("approval binding mismatch")
    if not _is_aware(approval.issued_at) or not _is_aware(approval.expires_at):
        raise ApprovalRejected("approval timestamps must be timezone-aware")
    if approval.expires_at <= approval.issued_at:
        raise ApprovalRejected("approval timestamps must be increasing")
    if approval.expires_at - approval.issued_at > MAX_APPROVAL_TTL:
        raise ApprovalRejected("approval validity exceeds maximum TTL")
    _validate_approval_ttl(approval, approval_ttl_seconds)
    expected = hmac.new(secret, canonical_json(approval.payload()), hashlib.sha256).hexdigest()
    if not isinstance(approval.signature, str) or not hmac.compare_digest(
        expected, approval.signature
    ):
        raise ApprovalRejected("approval signature mismatch")
    if now < approval.issued_at or now >= approval.expires_at:
        raise ApprovalRejected("approval is not currently valid")
    if approval.approver_user_id == operation.user_id:
        raise ApprovalRejected("requester cannot approve their own operation")
    if not is_approver_authorized(
        approval.approver_user_id, operation.company_id, operation.capability_id
    ):
        raise ApprovalRejected("approver is not authorized")
    if not consume_nonce(approval.nonce, operation.operation_id, expected_revision):
        raise ApprovalRejected("approval nonce was already consumed")
    return operation._apply_transition(
        State.APPROVED,
        approval_signature=approval.signature,
        approval_nonce_digest=hashlib.sha256(approval.nonce.encode("utf-8")).hexdigest(),
        approval_issued_at=approval.issued_at,
        approval_expires_at=approval.expires_at,
        approval_revision=approval.operation_revision,
        approver_user_id=approval.approver_user_id,
    )


def begin_execution(
    operation: Operation,
    approval: Approval,
    *,
    now: datetime,
    secret: bytes,
    is_approver_authorized: Callable[[int, int, str], bool],
    approval_ttl_seconds: int,
    expected_revision: int,
) -> Operation:
    operation._check_transition(State.EXECUTING, expected_revision=expected_revision)
    if not _is_aware(now):
        raise ApprovalRejected("current time must be timezone-aware")
    if not _is_strong_hmac_secret(secret):
        raise ApprovalRejected("approval HMAC secret must be bytes of at least 32 bytes")
    if not isinstance(approval.nonce, str) or not approval.nonce:
        raise ApprovalRejected("approval nonce is invalid")
    if (
        not _is_aware(approval.issued_at)
        or not _is_aware(approval.expires_at)
        or isinstance(approval.approver_user_id, bool)
        or not isinstance(approval.approver_user_id, int)
        or approval.approver_user_id <= 0
    ):
        raise ApprovalRejected("approval content is invalid")
    stored_binding = (
        operation.approval_signature == approval.signature
        and operation.approval_nonce_digest
        == hashlib.sha256(approval.nonce.encode("utf-8")).hexdigest()
        and operation.approval_issued_at == approval.issued_at
        and operation.approval_expires_at == approval.expires_at
        and operation.approval_revision == approval.operation_revision
        and operation.approver_user_id == approval.approver_user_id
    )
    approval_binding = (
        approval.operation_id == operation.operation_id
        and approval.operation_digest == operation.digest
        and approval.user_id == operation.user_id
        and approval.company_id == operation.company_id
    )
    if not stored_binding or not approval_binding:
        raise ApprovalRejected("approved operation binding mismatch")
    expected = hmac.new(secret, canonical_json(approval.payload()), hashlib.sha256).hexdigest()
    if not isinstance(approval.signature, str) or not hmac.compare_digest(
        expected, approval.signature
    ):
        raise ApprovalRejected("approval signature mismatch")
    if now < approval.issued_at or now >= approval.expires_at:
        raise ApprovalRejected("approval expired before execution")
    _validate_approval_ttl(approval, approval_ttl_seconds)
    if not is_approver_authorized(
        approval.approver_user_id, operation.company_id, operation.capability_id
    ):
        raise ApprovalRejected("approver is no longer authorized")
    return operation._apply_transition(State.EXECUTING)


def _sign_result(
    *,
    operation: Operation,
    kind: ResultKind,
    issuer: str,
    key_id: str,
    succeeded: bool,
    evidence_digest: str,
    issued_at: datetime,
    secret: bytes,
) -> TrustedResult:
    operation.assert_integrity()
    expected_state = State.EXECUTING if kind == ResultKind.EXECUTION else State.VERIFYING
    if operation.state != expected_state:
        raise TrustedResultRejected(
            f"operation is not ready for a {kind} result"
        )
    if not _is_strong_hmac_secret(secret):
        raise TrustedResultRejected("result HMAC secret must be bytes of at least 32 bytes")
    if (
        not isinstance(issuer, str)
        or not issuer.strip()
        or not isinstance(key_id, str)
        or not key_id.strip()
    ):
        raise TrustedResultRejected("result issuer and key ID are required")
    if type(succeeded) is not bool:
        raise TrustedResultRejected("result succeeded flag must be boolean")
    if not _is_sha256(evidence_digest):
        raise TrustedResultRejected("evidence_digest must be a SHA-256 digest")
    if not _is_aware(issued_at):
        raise TrustedResultRejected("result timestamp must be timezone-aware")
    prior_digest = (
        operation.execution_result_digest
        if kind == ResultKind.VERIFICATION
        else None
    )
    if kind == ResultKind.VERIFICATION and not prior_digest:
        raise TrustedResultRejected("verification requires an accepted execution result")
    unsigned = TrustedResult(
        kind=kind,
        operation_id=operation.operation_id,
        operation_digest=operation.digest,
        operation_revision=operation.revision,
        company_id=operation.company_id,
        issuer=issuer,
        key_id=key_id,
        succeeded=succeeded,
        evidence_digest=evidence_digest,
        prior_evidence_digest=prior_digest,
        issued_at=issued_at,
        signature="",
    )
    signature = hmac.new(secret, canonical_json(unsigned.payload()), hashlib.sha256).hexdigest()
    return replace(unsigned, signature=signature)


def sign_execution_result(
    *,
    operation: Operation,
    issuer: str,
    key_id: str,
    succeeded: bool,
    evidence_digest: str,
    issued_at: datetime,
    secret: bytes,
) -> TrustedResult:
    return _sign_result(
        operation=operation,
        kind=ResultKind.EXECUTION,
        issuer=issuer,
        key_id=key_id,
        succeeded=succeeded,
        evidence_digest=evidence_digest,
        issued_at=issued_at,
        secret=secret,
    )


def sign_verification_result(
    *,
    operation: Operation,
    issuer: str,
    key_id: str,
    succeeded: bool,
    evidence_digest: str,
    issued_at: datetime,
    secret: bytes,
) -> TrustedResult:
    return _sign_result(
        operation=operation,
        kind=ResultKind.VERIFICATION,
        issuer=issuer,
        key_id=key_id,
        succeeded=succeeded,
        evidence_digest=evidence_digest,
        issued_at=issued_at,
        secret=secret,
    )


def _verify_result(
    *,
    operation: Operation,
    result: TrustedResult,
    kind: ResultKind,
    now: datetime,
    secret: bytes,
    expected_key_id: str,
    allowed_issuers: frozenset[str],
) -> None:
    if not _is_aware(now):
        raise TrustedResultRejected("current time must be timezone-aware")
    if not _is_strong_hmac_secret(secret):
        raise TrustedResultRejected("result HMAC secret must be bytes of at least 32 bytes")
    if not isinstance(expected_key_id, str) or not expected_key_id.strip():
        raise TrustedResultRejected("trusted result expected key ID is required")
    if (
        not isinstance(allowed_issuers, frozenset)
        or not allowed_issuers
        or any(not isinstance(issuer, str) or not issuer.strip() for issuer in allowed_issuers)
    ):
        raise TrustedResultRejected("trusted result issuer allowlist is invalid")
    bindings = (
        result.kind == kind
        and result.operation_id == operation.operation_id
        and result.operation_digest == operation.digest
        and result.operation_revision == operation.revision
        and result.company_id == operation.company_id
    )
    if kind == ResultKind.EXECUTION:
        bindings = bindings and result.prior_evidence_digest is None
    else:
        bindings = (
            bindings
            and operation.execution_result_digest is not None
            and result.prior_evidence_digest == operation.execution_result_digest
        )
    if not bindings:
        raise TrustedResultRejected("trusted result binding mismatch")
    if (
        not isinstance(result.issuer, str)
        or not result.issuer.strip()
        or not isinstance(result.key_id, str)
        or not result.key_id.strip()
        or type(result.succeeded) is not bool
        or not _is_sha256(result.evidence_digest)
        or not isinstance(result.signature, str)
        or not _is_sha256(result.signature)
    ):
        raise TrustedResultRejected("trusted result content is invalid")
    if result.key_id != expected_key_id:
        raise TrustedResultRejected("trusted result key ID mismatch")
    if result.issuer not in allowed_issuers:
        raise TrustedResultRejected("trusted result issuer is not authorized")
    if not _is_aware(result.issued_at) or result.issued_at > now:
        raise TrustedResultRejected("trusted result timestamp is invalid")
    expected = hmac.new(secret, canonical_json(result.payload()), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, result.signature):
        raise TrustedResultRejected("trusted result signature mismatch")


def record_execution_result(
    operation: Operation,
    result: TrustedResult,
    *,
    now: datetime,
    secret: bytes,
    expected_key_id: str,
    allowed_issuers: frozenset[str],
    expected_revision: int,
) -> Operation:
    target = State.VERIFYING if result.succeeded else State.FAILED
    operation._check_transition(target, expected_revision=expected_revision)
    _verify_result(
        operation=operation,
        result=result,
        kind=ResultKind.EXECUTION,
        now=now,
        secret=secret,
        expected_key_id=expected_key_id,
        allowed_issuers=allowed_issuers,
    )
    return operation._apply_transition(
        target, execution_result_digest=result.evidence_digest
    )


def complete_operation(
    operation: Operation,
    result: TrustedResult,
    *,
    now: datetime,
    secret: bytes,
    expected_key_id: str,
    allowed_issuers: frozenset[str],
    expected_revision: int,
) -> Operation:
    target = State.COMPLETED if result.succeeded else State.FAILED
    operation._check_transition(target, expected_revision=expected_revision)
    _verify_result(
        operation=operation,
        result=result,
        kind=ResultKind.VERIFICATION,
        now=now,
        secret=secret,
        expected_key_id=expected_key_id,
        allowed_issuers=allowed_issuers,
    )
    return operation._apply_transition(
        target, verification_result_digest=result.evidence_digest
    )

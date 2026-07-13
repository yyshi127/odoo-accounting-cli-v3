"""Write-operation state and approval invariants.

Persistence and Odoo execution are deliberately outside this module. This core
only permits valid transitions and produces deterministic operation digests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable


class OperationError(ValueError):
    """Base error for rejected operation transitions."""


class ConcurrentUpdate(OperationError):
    pass


class ApprovalRejected(OperationError):
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
    user_id: int,
    company_id: int,
    idempotency_key: str,
) -> str:
    envelope = {
        "capability_id": capability_id,
        "company_id": company_id,
        "idempotency_key": idempotency_key,
        "parameters": parameters,
        "user_id": user_id,
    }
    return hashlib.sha256(canonical_json(envelope)).hexdigest()


@dataclass(frozen=True)
class Operation:
    operation_id: str
    capability_id: str
    parameters_json: str
    user_id: int
    company_id: int
    idempotency_key: str
    digest: str
    state: State = State.PREPARED
    revision: int = 0

    @property
    def parameters(self) -> dict[str, Any]:
        """Return a detached copy so approved content cannot be mutated."""
        return json.loads(self.parameters_json)

    @classmethod
    def prepare(
        cls,
        *,
        operation_id: str,
        capability_id: str,
        parameters: dict[str, Any],
        user_id: int,
        company_id: int,
        idempotency_key: str,
    ) -> "Operation":
        if not operation_id or not capability_id or not idempotency_key:
            raise OperationError("operation_id, capability_id, and idempotency_key are required")
        if user_id <= 0 or company_id <= 0:
            raise OperationError("positive user_id and company_id are required")
        normalized_parameters = canonical_json(parameters).decode("utf-8")
        digest = operation_digest(
            capability_id=capability_id,
            parameters=json.loads(normalized_parameters),
            user_id=user_id,
            company_id=company_id,
            idempotency_key=idempotency_key,
        )
        return cls(
            operation_id=operation_id,
            capability_id=capability_id,
            parameters_json=normalized_parameters,
            user_id=user_id,
            company_id=company_id,
            idempotency_key=idempotency_key,
            digest=digest,
        )

    def transition(self, target: State, *, expected_revision: int) -> "Operation":
        if expected_revision != self.revision:
            raise ConcurrentUpdate("operation revision has changed")
        if target not in ALLOWED_TRANSITIONS[self.state]:
            raise OperationError(f"invalid transition: {self.state} -> {target}")
        return replace(self, state=target, revision=self.revision + 1)


@dataclass(frozen=True)
class Approval:
    operation_id: str
    operation_digest: str
    user_id: int
    company_id: int
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
            "user_id": self.user_id,
        }


def sign_approval(
    *,
    operation: Operation,
    approver_user_id: int,
    nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    secret: bytes,
) -> Approval:
    if operation.state != State.AWAITING_APPROVAL:
        raise ApprovalRejected("operation is not awaiting approval")
    if not secret or not nonce or approver_user_id <= 0:
        raise ApprovalRejected("approval signer, nonce, and secret are required")
    if issued_at.tzinfo is None or expires_at.tzinfo is None or expires_at <= issued_at:
        raise ApprovalRejected("approval timestamps must be timezone-aware and increasing")
    unsigned = Approval(
        operation_id=operation.operation_id,
        operation_digest=operation.digest,
        user_id=operation.user_id,
        company_id=operation.company_id,
        approver_user_id=approver_user_id,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        signature="",
    )
    signature = hmac.new(secret, canonical_json(unsigned.payload()), hashlib.sha256).hexdigest()
    return replace(unsigned, signature=signature)


def approve_operation(
    operation: Operation,
    approval: Approval,
    *,
    now: datetime,
    secret: bytes,
    consume_nonce: Callable[[str], bool],
    expected_revision: int,
) -> Operation:
    if operation.state != State.AWAITING_APPROVAL:
        raise ApprovalRejected("operation is not awaiting approval")
    if now.tzinfo is None:
        raise ApprovalRejected("current time must be timezone-aware")
    bindings = (
        approval.operation_id == operation.operation_id
        and approval.operation_digest == operation.digest
        and approval.user_id == operation.user_id
        and approval.company_id == operation.company_id
    )
    if not bindings:
        raise ApprovalRejected("approval binding mismatch")
    expected = hmac.new(secret, canonical_json(approval.payload()), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, approval.signature):
        raise ApprovalRejected("approval signature mismatch")
    if now < approval.issued_at or now >= approval.expires_at:
        raise ApprovalRejected("approval is not currently valid")
    if not consume_nonce(approval.nonce):
        raise ApprovalRejected("approval nonce was already consumed")
    return operation.transition(State.APPROVED, expected_revision=expected_revision)

"""Tamper-evident audit events and verified Odoo receipts."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Iterable

from .operations import State, canonical_json


class AuditError(ValueError):
    pass


GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class OdooReceipt:
    database: str
    model: str
    record_ids: tuple[int, ...]
    company_id: int
    operation: str
    observed_at: datetime
    record_fingerprint: str

    def validate(self) -> None:
        if not self.database or not self.model or not self.operation:
            raise AuditError("Odoo receipt identity is incomplete")
        if not self.record_ids or any(item <= 0 for item in self.record_ids):
            raise AuditError("Odoo receipt must contain positive record ids")
        if self.company_id <= 0:
            raise AuditError("Odoo receipt company is invalid")
        if self.observed_at.tzinfo is None:
            raise AuditError("Odoo receipt timestamp must be timezone-aware")
        if len(self.record_fingerprint) != 64:
            raise AuditError("Odoo receipt fingerprint must be SHA-256")

    def payload(self) -> dict[str, Any]:
        return {
            "company_id": self.company_id,
            "database": self.database,
            "model": self.model,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
            "operation": self.operation,
            "record_fingerprint": self.record_fingerprint,
            "record_ids": list(self.record_ids),
        }


@dataclass(frozen=True)
class VerificationReceipt:
    method: str
    verified_at: datetime
    passed: bool
    checks: tuple[str, ...]
    evidence_digest: str

    def validate(self) -> None:
        if not self.method or self.verified_at.tzinfo is None:
            raise AuditError("verification receipt identity is incomplete")
        if not self.passed or not self.checks:
            raise AuditError("verification receipt must contain passing checks")
        if len(self.evidence_digest) != 64:
            raise AuditError("verification evidence digest must be SHA-256")

    def payload(self) -> dict[str, Any]:
        return {
            "checks": list(self.checks),
            "evidence_digest": self.evidence_digest,
            "method": self.method,
            "passed": self.passed,
            "verified_at": self.verified_at.astimezone(timezone.utc).isoformat(),
        }


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    event_id: str
    request_id: str
    operation_id: str
    operation_digest: str
    user_id: int
    company_id: int
    state: State
    occurred_at: datetime
    details: dict[str, Any]
    previous_hash: str
    event_hash: str

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "company_id": self.company_id,
            "details": self.details,
            "event_id": self.event_id,
            "occurred_at": self.occurred_at.astimezone(timezone.utc).isoformat(),
            "operation_digest": self.operation_digest,
            "operation_id": self.operation_id,
            "previous_hash": self.previous_hash,
            "request_id": self.request_id,
            "sequence": self.sequence,
            "state": self.state.value,
            "user_id": self.user_id,
        }


def build_event(
    *,
    sequence: int,
    event_id: str,
    request_id: str,
    operation_id: str,
    operation_digest: str,
    user_id: int,
    company_id: int,
    state: State,
    occurred_at: datetime,
    details: dict[str, Any],
    previous_hash: str,
) -> AuditEvent:
    if sequence <= 0 or user_id <= 0 or company_id <= 0:
        raise AuditError("positive sequence, user, and company are required")
    if not event_id or not request_id or not operation_id or len(operation_digest) != 64:
        raise AuditError("audit event identity is incomplete")
    if occurred_at.tzinfo is None or len(previous_hash) != 64:
        raise AuditError("audit event timestamp or previous hash is invalid")
    event = AuditEvent(
        sequence=sequence,
        event_id=event_id,
        request_id=request_id,
        operation_id=operation_id,
        operation_digest=operation_digest,
        user_id=user_id,
        company_id=company_id,
        state=state,
        occurred_at=occurred_at,
        details=details,
        previous_hash=previous_hash,
        event_hash="",
    )
    return replace(event, event_hash=hashlib.sha256(canonical_json(event.unsigned_payload())).hexdigest())


def verify_chain(events: Iterable[AuditEvent]) -> None:
    previous = GENESIS_HASH
    expected_sequence = 1
    operation_binding: tuple[str, str, int, int] | None = None
    for event in events:
        if event.sequence != expected_sequence or event.previous_hash != previous:
            raise AuditError("audit chain sequence or previous hash mismatch")
        expected_hash = hashlib.sha256(canonical_json(event.unsigned_payload())).hexdigest()
        if event.event_hash != expected_hash:
            raise AuditError("audit event hash mismatch")
        binding = (event.operation_id, event.operation_digest, event.user_id, event.company_id)
        if operation_binding is None:
            operation_binding = binding
        elif binding != operation_binding:
            raise AuditError("audit event operation binding mismatch")
        previous = event.event_hash
        expected_sequence += 1


def completion_details(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    odoo_receipt: OdooReceipt,
    verification_receipt: VerificationReceipt,
) -> dict[str, Any]:
    odoo_receipt.validate()
    verification_receipt.validate()
    if before == after:
        raise AuditError("completed write must include a meaningful before/after difference")
    if odoo_receipt.company_id != after.get("company_id"):
        raise AuditError("Odoo receipt company does not match verified result")
    return {
        "before": before,
        "after": after,
        "odoo_receipt": odoo_receipt.payload(),
        "verification_receipt": verification_receipt.payload(),
    }

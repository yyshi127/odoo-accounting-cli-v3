"""Trusted local diagnostics for durable write operations.

The reader stays in the trusted write process.  It reads the canonical SQLite
store and reuses ``WriteService.result`` for terminal signature, receipt, Odoo
read-back, and database-finalization verification.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from .gateway import RequestContext
from .operations import ALLOWED_TRANSITIONS, Operation, State, canonical_json
from .persistence import SQLitePersistence, StoredFinalWriteReceipt
from .write_receipts import (
    WriteReceiptError,
    validate_executable_recovery_plan,
    validate_recovery_plan,
)


TRUSTED_LOCAL_PERSISTENCE_READ_CAPABILITIES = frozenset(
    {"acct.diagnostics.operation_read.v1"}
)


class OperationDiagnosticsError(ValueError):
    """A diagnostic projection could not be built without weakening trust."""


StatusReader = Callable[[RequestContext, str], Operation]
TerminalResultReader = Callable[[RequestContext, str], dict[str, Any]]
RecoveredCompletionReader = Callable[
    [RequestContext, Operation, str], dict[str, Any]
]

_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_FIELDS = {
    "model",
    "record_id",
    "company_id",
    "record_state",
    "record_fingerprint",
}
_RESULT_FIELDS = {
    "operation_id",
    "operation_state",
    "odoo_records",
    "difference",
    "verification",
    "database_finalization",
    "recovery_plan",
}
_RECOVERED_COMPLETION_FIELDS = {
    "completion_evidence_digest",
    "completion_receipt_body_digest",
    "completion_receipt_id",
    "origin_operation_id",
    "recovery_operation_id",
    "recovery_plan_digest",
}


def _digest(value: Any) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OperationDiagnosticsError(
            "diagnostic evidence is not canonical JSON"
        ) from exc


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise OperationDiagnosticsError(f"{field} is not a SHA-256 digest")
    return value


def _validated_odoo_refs(value: Any, company_id: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise OperationDiagnosticsError("verified Odoo references are invalid")
    output = []
    for record in value:
        if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
            raise OperationDiagnosticsError(
                "verified Odoo reference fields are invalid"
            )
        if (
            not isinstance(record["model"], str)
            or not record["model"].strip()
            or isinstance(record["record_id"], bool)
            or not isinstance(record["record_id"], int)
            or record["record_id"] <= 0
            or isinstance(record["company_id"], bool)
            or not isinstance(record["company_id"], int)
            or record["company_id"] != company_id
            or not isinstance(record["record_state"], str)
            or not record["record_state"].strip()
        ):
            raise OperationDiagnosticsError(
                "verified Odoo reference identity is invalid"
            )
        _sha256(record["record_fingerprint"], "Odoo record fingerprint")
        output.append(dict(record))
    return output


def _validated_terminal_result(
    operation: Operation,
    value: Any,
    receipt: StoredFinalWriteReceipt,
) -> dict[str, Any]:
    if not isinstance(value, dict) or not (
        _RESULT_FIELDS | {"audit_receipt"}
    ).issubset(value):
        raise OperationDiagnosticsError("verified terminal result is invalid")
    result_body = {field: value[field] for field in _RESULT_FIELDS}
    if (
        result_body["operation_id"] != operation.operation_id
        or result_body["operation_state"] != operation.state.value
    ):
        raise OperationDiagnosticsError(
            "verified terminal result operation binding changed"
        )
    verification = result_body["verification"]
    if (
        not isinstance(verification, dict)
        or type(verification.get("passed")) is not bool
    ):
        raise OperationDiagnosticsError("verified result status is invalid")
    _sha256(
        verification.get("evidence_digest"),
        "verification evidence digest",
    )
    recovery_plan = result_body["recovery_plan"]
    validate_recovery_plan(recovery_plan)
    if recovery_plan["origin_operation_id"] != operation.operation_id:
        raise OperationDiagnosticsError("recovery plan origin binding changed")

    audit_receipt = value["audit_receipt"]
    if (
        not isinstance(audit_receipt, dict)
        or audit_receipt.get("operation_id") != operation.operation_id
        or audit_receipt.get("company_id") != operation.company_id
        or audit_receipt.get("result_digest") != _digest(result_body)
        or audit_receipt.get("audit_head")
        != receipt.body.get("audit_event_hash")
    ):
        raise OperationDiagnosticsError(
            "verified write audit receipt binding changed"
        )
    write_receipt_id = audit_receipt.get("receipt_id")
    if not isinstance(write_receipt_id, str) or not write_receipt_id.strip():
        raise OperationDiagnosticsError(
            "verified write audit receipt ID is invalid"
        )
    return {
        "verification": verification,
        "odoo_refs": _validated_odoo_refs(
            result_body["odoo_records"], operation.company_id
        ),
        "recovery_plan": recovery_plan,
        "write_receipt_id": write_receipt_id,
        "write_result_digest": audit_receipt["result_digest"],
        "audit_head": audit_receipt["audit_head"],
        "difference_digest": _digest(result_body["difference"]),
        "database_finalization_digest": (
            None
            if result_body["database_finalization"] is None
            else _digest(result_body["database_finalization"])
        ),
    }


def _bound_recovery_operation_ids(
    store: SQLitePersistence,
    events: tuple[Any, ...],
    operation_id: str,
) -> list[str]:
    result = []
    for event in events:
        if (
            event.event_type != "recovery.binding.created"
            or event.payload.get("origin_operation_id") != operation_id
        ):
            continue
        recovery_id = event.payload.get("recovery_operation_id")
        if (
            not isinstance(recovery_id, str)
            or _OPERATION_ID.fullmatch(recovery_id) is None
        ):
            raise OperationDiagnosticsError(
                "recovery operation binding is invalid"
            )
        binding = store.get_recovery_operation_binding(recovery_id)
        if binding.origin_operation_id != operation_id:
            raise OperationDiagnosticsError(
                "recovery operation origin binding changed"
            )
        result.append(recovery_id)
    return sorted(set(result))


@dataclass(frozen=True)
class OperationDiagnosticsReader:
    """Build a strict, non-secret summary for one authenticated operation."""

    store: SQLitePersistence
    status_reader: StatusReader
    terminal_result_reader: TerminalResultReader
    recovered_completion_reader: RecoveredCompletionReader

    def __post_init__(self) -> None:
        if not isinstance(self.store, SQLitePersistence):
            raise OperationDiagnosticsError(
                "operation diagnostics require SQLite persistence"
            )
        if (
            not callable(self.status_reader)
            or not callable(self.terminal_result_reader)
            or not callable(self.recovered_completion_reader)
        ):
            raise OperationDiagnosticsError(
                "operation diagnostics readers must be callable"
            )

    def read(
        self,
        context: RequestContext,
        *,
        company_id: int,
        operation_id: str,
    ) -> dict[str, Any]:
        if not isinstance(context, RequestContext):
            raise OperationDiagnosticsError("request context is invalid")
        if (
            isinstance(company_id, bool)
            or not isinstance(company_id, int)
            or company_id <= 0
            or company_id != context.company_id
        ):
            raise OperationDiagnosticsError(
                "diagnostic company is outside the authenticated context"
            )
        if (
            not isinstance(operation_id, str)
            or _OPERATION_ID.fullmatch(operation_id) is None
        ):
            raise OperationDiagnosticsError("operation_id is invalid")

        operation = self.status_reader(context, operation_id)
        if (
            not isinstance(operation, Operation)
            or operation.operation_id != operation_id
            or operation.company_id != company_id
        ):
            raise OperationDiagnosticsError(
                "authenticated operation status binding changed"
            )
        operation.assert_integrity()
        if self.store.get_operation(operation_id) != operation:
            raise OperationDiagnosticsError(
                "operation status differs from durable state"
            )

        all_events = self.store.audit_events()
        events = tuple(
            event for event in all_events if event.operation_id == operation_id
        )
        results = self.store.get_trusted_result_records(operation_id)
        receipts = self.store.get_final_write_receipts(operation_id)
        recovery_records = self.store.get_recovery_records(operation_id)
        bound_recovery_ids = _bound_recovery_operation_ids(
            self.store, all_events, operation_id
        )
        current_receipts = [
            receipt
            for receipt in receipts
            if receipt.operation_revision == operation.revision
            and receipt.terminal_state == operation.state.value
        ]
        recovered_completion = None
        if operation.state == State.RECOVERED:
            if len(current_receipts) != 1:
                raise OperationDiagnosticsError(
                    "recovered origin has no unique final receipt"
                )
            receipt_details = current_receipts[0].body.get(
                "receipt_details"
            )
            receipt_completion = (
                receipt_details.get("recovery_completion")
                if isinstance(receipt_details, dict)
                else None
            )
            recovery_binding = (
                receipt_completion.get("recovery_operation")
                if isinstance(receipt_completion, dict)
                else None
            )
            recovery_operation_id = (
                recovery_binding.get("operation_id")
                if isinstance(recovery_binding, dict)
                else None
            )
            if (
                not isinstance(recovery_operation_id, str)
                or _OPERATION_ID.fullmatch(recovery_operation_id) is None
                or recovery_operation_id not in bound_recovery_ids
            ):
                raise OperationDiagnosticsError(
                    "recovered receipt points to an unbound recovery operation"
                )
            recovered_completion = self.recovered_completion_reader(
                context,
                operation,
                recovery_operation_id,
            )
            if (
                not isinstance(recovered_completion, dict)
                or set(recovered_completion) != _RECOVERED_COMPLETION_FIELDS
                or recovered_completion["origin_operation_id"]
                != operation.operation_id
                or recovered_completion["recovery_operation_id"]
                != recovery_operation_id
                or len(recovery_records) != 1
                or recovered_completion["recovery_plan_digest"]
                != recovery_records[0].plan_digest
                or recovered_completion["completion_receipt_id"]
                != current_receipts[0].receipt_id
                or recovered_completion["completion_receipt_body_digest"]
                != current_receipts[0].body_digest
            ):
                raise OperationDiagnosticsError(
                    "verified recovery completion binding changed"
                )
            _sha256(
                recovered_completion["completion_evidence_digest"],
                "recovery completion evidence digest",
            )
            _sha256(
                recovered_completion["completion_receipt_body_digest"],
                "recovery completion receipt body digest",
            )
            _sha256(
                recovered_completion["recovery_plan_digest"],
                "recovery completion plan digest",
            )
            if (
                not isinstance(
                    recovered_completion["completion_receipt_id"], str
                )
                or not recovered_completion["completion_receipt_id"].strip()
            ):
                raise OperationDiagnosticsError(
                    "recovery completion receipt ID is invalid"
                )

        projection = None
        current_receipt = None
        if operation.state in {State.COMPLETED, State.FAILED}:
            if len(current_receipts) != 1:
                raise OperationDiagnosticsError(
                    "terminal operation has no unique final receipt"
                )
            current_receipt = current_receipts[0]
            projection = _validated_terminal_result(
                operation,
                self.terminal_result_reader(context, operation_id),
                current_receipt,
            )
            if not any(
                record.result_id == current_receipt.result_id
                for record in results
            ):
                raise OperationDiagnosticsError(
                    "terminal receipt result was not reverified"
                )

        verification = None if projection is None else projection["verification"]
        plan = None if projection is None else projection["recovery_plan"]
        executable_recovery = False
        if plan is not None:
            try:
                validate_executable_recovery_plan(plan)
            except WriteReceiptError:
                pass
            else:
                executable_recovery = True

        result_kind = (
            None if current_receipt is None else current_receipt.result_kind
        )
        business_succeeded = bool(
            operation.state == State.COMPLETED
            and projection is not None
            and verification["passed"] is True
            and current_receipt is not None
            and current_receipt.result_succeeded is True
        )
        output = {
            "operation": {
                "operation_id": operation.operation_id,
                "capability_id": operation.capability_id,
                "company_id": operation.company_id,
                "state": operation.state.value,
                "revision": operation.revision,
                "terminal": operation.state
                in {State.COMPLETED, State.FAILED, State.RECOVERED},
                "business_succeeded": business_succeeded,
                "allowed_next_states": sorted(
                    state.value for state in ALLOWED_TRANSITIONS[operation.state]
                ),
            },
            "audit": {
                "chain_verified": True,
                "event_count": len(events),
                "event_types": [event.event_type for event in events[-1000:]],
                "event_types_offset": max(0, len(events) - 1000),
                "event_types_truncated": len(events) > 1000,
                "last_event_id": None if not events else events[-1].event_id,
                "last_event_hash": None if not events else events[-1].event_hash,
                "global_head_hash": (
                    None if not all_events else all_events[-1].event_hash
                ),
            },
            "verification": {
                "trusted_terminal_result_verified": projection is not None,
                "passed": None if verification is None else verification["passed"],
                "method": None if verification is None else verification["method"],
                "evidence_digest": (
                    None
                    if verification is None
                    else verification["evidence_digest"]
                ),
            },
            "failure": {
                "present": operation.state == State.FAILED,
                "stage": (
                    None
                    if operation.state != State.FAILED
                    else {
                        "execution": "execute",
                        "verification": "verify",
                        "recovery": "recover",
                    }.get(result_kind, "unknown")
                ),
                "result_id": (
                    None
                    if operation.state != State.FAILED
                    or current_receipt is None
                    else current_receipt.result_id
                ),
                "evidence_digest": (
                    None
                    if operation.state != State.FAILED
                    or current_receipt is None
                    else current_receipt.evidence_digest
                ),
            },
            "recovery": {
                "lifecycle_status": (
                    "in_progress"
                    if operation.state == State.RECOVERING
                    else "recovered_verified"
                    if operation.state == State.RECOVERED
                    else "prepared_separately"
                    if bound_recovery_ids
                    else "not_started"
                ),
                "available": executable_recovery,
                "plan_status": None if plan is None else plan["status"],
                "plan_digest": None if plan is None else plan["plan_digest"],
                "recovery_capability_id": (
                    None if plan is None else plan["recovery_capability_id"]
                ),
                "requires_approval": (
                    None if plan is None else plan["requires_approval"]
                ),
                "attempt_count": len(recovery_records),
                "latest_attempt_plan_digest": (
                    None
                    if not recovery_records
                    else recovery_records[-1].plan_digest
                ),
                "bound_operation_ids": bound_recovery_ids,
                "completion_evidence_digest": (
                    None
                    if recovered_completion is None
                    else recovered_completion["completion_evidence_digest"]
                ),
                "completion_receipt_id": (
                    None
                    if recovered_completion is None
                    else recovered_completion["completion_receipt_id"]
                ),
                "completion_receipt_body_digest": (
                    None
                    if recovered_completion is None
                    else recovered_completion[
                        "completion_receipt_body_digest"
                    ]
                ),
            },
            "odoo_refs": [] if projection is None else projection["odoo_refs"],
            "receipts": {
                "unique_final_receipt_verified": projection is not None,
                "current_candidate_count": len(current_receipts),
                "durable_final_receipt_id": (
                    None if projection is None else current_receipt.receipt_id
                ),
                "durable_final_receipt_body_digest": (
                    None if projection is None else current_receipt.body_digest
                ),
                "write_audit_receipt_id": (
                    None if projection is None else projection["write_receipt_id"]
                ),
                "write_audit_result_digest": (
                    None if projection is None else projection["write_result_digest"]
                ),
                "write_audit_head": (
                    None if projection is None else projection["audit_head"]
                ),
                "difference_digest": (
                    None if projection is None else projection["difference_digest"]
                ),
                "database_finalization_digest": (
                    None
                    if projection is None
                    else projection["database_finalization_digest"]
                ),
            },
        }
        return json.loads(canonical_json(output))


__all__ = ["OperationDiagnosticsError", "OperationDiagnosticsReader"]

"""Immutable evidence for completing an incident origin as recovered.

This module performs no I/O and no signature verification.  Its constructor
accepts trusted results and durable receipt material that have already been
verified by their owning components, then binds their exact identities and
digests into one small evidence document.  A caller can rebuild the expected
document from durable state and use the strict validator before signing a
``ResultKind.RECOVERY`` result for the origin operation.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .effect_finalizer import (
    EffectFinalizationError,
    trusted_result_envelope_digest,
    validate_effect_finalization_evidence_shape,
)
from .operations import (
    EXECUTION_RESULT_PURPOSE,
    RESULT_SIGNATURE_VERSION,
    VERIFICATION_RESULT_PURPOSE,
    Operation,
    ResultKind,
    State,
    TrustedResult,
    canonical_json,
)


ORIGIN_RECOVERY_COMPLETION_VERSION = 1
ORIGIN_RECOVERY_COMPLETION_PURPOSE = (
    "odoo_accounting_cli_v3.origin_recovery_completion.v1"
)
RECOVERY_CAPABILITY_ID = "acct.recovery.execute.v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TRUSTED_RESULT_ID = re.compile(r"^trusted-result:[0-9a-f]{64}$")
_FINAL_RECEIPT_ID = re.compile(r"^final-write-receipt:[0-9a-f]{64}$")

_DOCUMENT_FIELDS = frozenset(
    {
        "database_finalization_digest",
        "execution_result",
        "odoo_readback_digest",
        "odoo_records_digest",
        "origin_operation",
        "protocol_version",
        "purpose",
        "recovery_final_receipt",
        "recovery_operation",
        "recovery_plan_digest",
        "verification_result",
    }
)
_OPERATION_FIELDS = frozenset(
    {
        "capability_id",
        "company_id",
        "operation_digest",
        "operation_id",
        "operation_revision",
        "request_id",
        "state",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "envelope_digest",
        "evidence_digest",
        "kind",
        "operation_id",
        "operation_revision",
        "result_id",
    }
)
_FINAL_RECEIPT_FIELDS = frozenset(
    {
        "audit_event_hash",
        "audit_event_id",
        "body_digest",
        "evidence_digest",
        "receipt_id",
        "result_id",
    }
)
_EXECUTION_EVIDENCE_FIELDS = frozenset(
    {
        "capability_id",
        "difference",
        "failure_checks",
        "module_graph",
        "odoo_records",
        "operation_id",
        "recovery_parameters",
        "recovery_plan",
        "succeeded",
    }
)
_VERIFICATION_EVIDENCE_FIELDS = frozenset(
    {
        "capability_id",
        "checks",
        "method",
        "operation_id",
        "passed",
        "readback",
        "verified_at",
    }
)
_READBACK_FIELDS = frozenset(
    {
        "company_id",
        "control_anchor",
        "fresh_snapshots",
        "fresh_snapshots_digest",
        "records",
        "request_parameters_digest",
    }
)
_DURABLE_RECEIPT_BODY_FIELDS = frozenset(
    {
        "audit_event_hash",
        "audit_event_id",
        "audit_sequence",
        "capability_id",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "evidence",
        "evidence_digest",
        "odoo_instance_id",
        "operation_digest",
        "operation_id",
        "operation_revision",
        "precheck_digest",
        "principal",
        "protocol_version",
        "receipt_details",
        "registry_digest",
        "release_digest",
        "request_id",
        "result_id",
        "result_kind",
        "result_record_hash",
        "result_succeeded",
        "schema_version",
        "terminal_state",
        "user_id",
    }
)
_RECEIPT_DETAILS_FIELDS = frozenset(
    {
        "capability_channel",
        "database_finalization",
        "difference",
        "odoo_records",
        "operation_id",
        "operation_state",
        "recovery_plan",
        "verification",
    }
)
_RECEIPT_VERIFICATION_FIELDS = frozenset(
    {"checks", "evidence_digest", "method", "passed", "verified_at"}
)


class OriginRecoveryCompletionError(ValueError):
    """Origin recovery completion evidence failed closed validation."""


@dataclass(frozen=True, slots=True)
class OperationEvidenceBinding:
    operation_id: str
    request_id: str
    capability_id: str
    operation_digest: str
    operation_revision: int
    company_id: int
    state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "request_id": self.request_id,
            "capability_id": self.capability_id,
            "operation_digest": self.operation_digest,
            "operation_revision": self.operation_revision,
            "company_id": self.company_id,
            "state": self.state,
        }


@dataclass(frozen=True, slots=True)
class TrustedResultEvidenceBinding:
    kind: str
    result_id: str
    operation_id: str
    operation_revision: int
    evidence_digest: str
    envelope_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "result_id": self.result_id,
            "operation_id": self.operation_id,
            "operation_revision": self.operation_revision,
            "evidence_digest": self.evidence_digest,
            "envelope_digest": self.envelope_digest,
        }


@dataclass(frozen=True, slots=True)
class FinalReceiptEvidenceBinding:
    receipt_id: str
    body_digest: str
    result_id: str
    evidence_digest: str
    audit_event_id: str
    audit_event_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "body_digest": self.body_digest,
            "result_id": self.result_id,
            "evidence_digest": self.evidence_digest,
            "audit_event_id": self.audit_event_id,
            "audit_event_hash": self.audit_event_hash,
        }


@dataclass(frozen=True, slots=True)
class OriginRecoveryCompletionEvidence:
    protocol_version: int
    purpose: str
    origin_operation: OperationEvidenceBinding
    recovery_operation: OperationEvidenceBinding
    recovery_plan_digest: str
    execution_result: TrustedResultEvidenceBinding
    verification_result: TrustedResultEvidenceBinding
    recovery_final_receipt: FinalReceiptEvidenceBinding
    database_finalization_digest: str
    odoo_records_digest: str
    odoo_readback_digest: str

    def to_dict(self) -> dict[str, Any]:
        """Return a detached canonical-document representation."""

        return {
            "protocol_version": self.protocol_version,
            "purpose": self.purpose,
            "origin_operation": self.origin_operation.to_dict(),
            "recovery_operation": self.recovery_operation.to_dict(),
            "recovery_plan_digest": self.recovery_plan_digest,
            "execution_result": self.execution_result.to_dict(),
            "verification_result": self.verification_result.to_dict(),
            "recovery_final_receipt": self.recovery_final_receipt.to_dict(),
            "database_finalization_digest": (
                self.database_finalization_digest
            ),
            "odoo_records_digest": self.odoo_records_digest,
            "odoo_readback_digest": self.odoo_readback_digest,
        }


def _error(message: str) -> OriginRecoveryCompletionError:
    return OriginRecoveryCompletionError(message)


def _digest(value: Any, field: str) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error(f"{field} is not canonical JSON") from exc


def _strict_object(
    value: Any,
    fields: frozenset[str],
    field: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise _error(f"{field} must be an object")
    actual = frozenset(value)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        raise _error(
            f"{field} fields differ: missing={missing}, extra={extra}"
        )
    return value


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _error(f"{field} is invalid")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _error(f"{field} must be a lowercase SHA-256 digest")
    return value


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise _error(f"{field} must be a positive integer")
    return value


def _nonnegative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _error(f"{field} must be a non-negative integer")
    return value


def _result_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _TRUSTED_RESULT_ID.fullmatch(value) is None:
        raise _error(f"{field} is invalid")
    return value


def _receipt_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _FINAL_RECEIPT_ID.fullmatch(value) is None:
        raise _error(f"{field} is invalid")
    return value


def _operation_binding(
    operation: Operation,
) -> OperationEvidenceBinding:
    return OperationEvidenceBinding(
        operation_id=operation.operation_id,
        request_id=operation.request_id,
        capability_id=operation.capability_id,
        operation_digest=operation.digest,
        operation_revision=operation.revision,
        company_id=operation.company_id,
        state=operation.state.value,
    )


def _trusted_result_id(result: TrustedResult) -> str:
    return "trusted-result:" + _digest(result.payload(), "trusted result")


def _expected_final_receipt_id(
    operation: Operation,
    *,
    result_id: str,
    body_digest: str,
) -> str:
    return "final-write-receipt:" + _digest(
        {
            "body_digest": body_digest,
            "operation_id": operation.operation_id,
            "operation_revision": operation.revision,
            "result_id": result_id,
        },
        "final receipt identity",
    )


def _validate_operation_sources(
    origin: Any,
    recovery: Any,
    *,
    plan_digest: str,
) -> None:
    if not isinstance(origin, Operation):
        raise _error("origin operation is invalid")
    if not isinstance(recovery, Operation):
        raise _error("recovery operation is invalid")
    try:
        origin.assert_integrity()
    except Exception as exc:
        raise _error("origin operation immutable content is invalid") from exc
    try:
        recovery.assert_integrity()
    except Exception as exc:
        raise _error("recovery operation immutable content is invalid") from exc
    if origin.state != State.FAILED:
        raise _error("origin operation must be failed")
    if (
        recovery.state != State.COMPLETED
        or recovery.capability_id != RECOVERY_CAPABILITY_ID
    ):
        raise _error("recovery operation must be a completed recovery execution")
    if origin.operation_id == recovery.operation_id:
        raise _error("origin and recovery operation identities must differ")
    runtime_fields = (
        "principal",
        "user_id",
        "company_id",
        "odoo_instance_id",
        "database_name",
        "database_uuid",
        "environment",
        "registry_digest",
        "release_digest",
    )
    if any(
        getattr(origin, field) != getattr(recovery, field)
        for field in runtime_fields
    ):
        raise _error("origin and recovery operation runtime bindings differ")
    parameters = recovery.parameters
    if (
        parameters.get("origin_operation_id") != origin.operation_id
        or parameters.get("expected_recovery_plan_digest") != plan_digest
        or parameters.get("company_id") != origin.company_id
    ):
        raise _error("recovery operation parameters do not bind the origin plan")


def _validate_result_source(
    *,
    label: str,
    operation: Operation,
    result: Any,
    evidence: Any,
    expected_kind: ResultKind,
    expected_revision: int,
    expected_prior_digest: str | None,
) -> tuple[str, str]:
    if not isinstance(result, TrustedResult):
        raise _error(f"{label} result is invalid")
    evidence_fields = (
        _EXECUTION_EVIDENCE_FIELDS
        if expected_kind == ResultKind.EXECUTION
        else _VERIFICATION_EVIDENCE_FIELDS
    )
    document = _strict_object(
        evidence,
        evidence_fields,
        f"{label} evidence",
    )
    evidence_digest = _digest(document, f"{label} evidence")
    if (
        isinstance(result, TrustedResult)
        and result.evidence_digest != evidence_digest
    ):
        raise _error(f"{label} evidence digest differs from its result")
    expected_purpose = (
        EXECUTION_RESULT_PURPOSE
        if expected_kind == ResultKind.EXECUTION
        else VERIFICATION_RESULT_PURPOSE
    )
    _sha256(
        result.operation_state_digest,
        f"{label} operation state digest",
    )
    _sha256(result.signature, f"{label} signature")
    if (
        type(result.kind) is not ResultKind
        or result.kind != expected_kind
        or result.succeeded is not True
        or result.operation_id != operation.operation_id
        or result.request_id != operation.request_id
        or result.operation_digest != operation.digest
        or result.company_id != operation.company_id
        or result.operation_revision != expected_revision
        or result.prior_evidence_digest != expected_prior_digest
        or result.signature_version != RESULT_SIGNATURE_VERSION
        or result.signature_purpose != expected_purpose
        or not isinstance(result.issued_at, datetime)
        or result.issued_at.tzinfo is None
        or result.issued_at.utcoffset() is None
        or not isinstance(result.issuer, str)
        or not result.issuer.strip()
        or not isinstance(result.key_id, str)
        or not result.key_id.strip()
    ):
        raise _error(f"{label} result binding is invalid")
    try:
        envelope_digest = trusted_result_envelope_digest(result, operation)
    except EffectFinalizationError as exc:
        raise _error(f"{label} result envelope is invalid") from exc
    return _trusted_result_id(result), envelope_digest


def _validate_execution_and_readback(
    *,
    operation: Operation,
    execution_evidence: dict[str, Any],
    verification_evidence: dict[str, Any],
) -> tuple[str, str]:
    if (
        execution_evidence["operation_id"] != operation.operation_id
        or execution_evidence["capability_id"] != operation.capability_id
        or execution_evidence["succeeded"] is not True
        or type(execution_evidence["odoo_records"]) is not list
        or not execution_evidence["odoo_records"]
        or type(execution_evidence["difference"]) is not dict
        or type(execution_evidence["recovery_plan"]) is not dict
        or type(execution_evidence["recovery_parameters"]) is not dict
        or type(execution_evidence["failure_checks"]) is not list
        or execution_evidence["failure_checks"]
    ):
        raise _error("recovery execution evidence binding is invalid")
    if (
        verification_evidence["operation_id"] != operation.operation_id
        or verification_evidence["capability_id"] != operation.capability_id
        or verification_evidence["passed"] is not True
        or not isinstance(verification_evidence["method"], str)
        or not verification_evidence["method"].strip()
        or type(verification_evidence["checks"]) is not list
        or not verification_evidence["checks"]
        or any(
            not isinstance(check, str) or not check.strip()
            for check in verification_evidence["checks"]
        )
        or len(verification_evidence["checks"])
        != len(set(verification_evidence["checks"]))
        or not isinstance(verification_evidence["verified_at"], str)
        or not verification_evidence["verified_at"].strip()
    ):
        raise _error("recovery verification evidence binding is invalid")
    readback = _strict_object(
        verification_evidence["readback"],
        _READBACK_FIELDS,
        "recovery verification readback",
    )
    records = execution_evidence["odoo_records"]
    if (
        readback["company_id"] != operation.company_id
        or type(readback["records"]) is not list
        or canonical_json(readback["records"]) != canonical_json(records)
        or type(readback["fresh_snapshots"]) is not list
        or not readback["fresh_snapshots"]
        or readback["request_parameters_digest"]
        != _digest(operation.parameters, "recovery parameters")
    ):
        raise _error("recovery verification readback binding is invalid")
    fresh_digest = _digest(
        readback["fresh_snapshots"],
        "recovery fresh snapshots",
    )
    if readback["fresh_snapshots_digest"] != fresh_digest:
        raise _error("recovery fresh snapshots digest is invalid")
    return (
        _digest(records, "recovery Odoo records"),
        _digest(readback, "recovery Odoo readback"),
    )


def _validate_database_finalization(
    value: Any,
    *,
    origin: Operation,
    recovery: Operation,
) -> dict[str, Any]:
    try:
        finalization = validate_effect_finalization_evidence_shape(value)
    except EffectFinalizationError as exc:
        raise _error("database finalization evidence is invalid") from exc
    if (
        finalization["operation_id"] != origin.operation_id
        or finalization["resolution_operation_id"] != recovery.operation_id
        or finalization["resolution_kind"] != "recovered"
        or finalization["database_uuid"] != origin.database_uuid
    ):
        raise _error("database finalization operation binding is invalid")
    if finalization["remaining_unresolved_count"] != 0:
        raise _error("database finalization has unresolved control anchors")
    return finalization


def _validate_final_receipt_source(
    *,
    recovery: Operation,
    verification_result: TrustedResult,
    verification_evidence: dict[str, Any],
    odoo_records: list[Any],
    database_finalization: dict[str, Any],
    receipt_id: Any,
    receipt_body: Any,
    receipt_body_digest: Any,
    audit_event_id: Any,
    audit_event_hash: Any,
) -> tuple[str, str]:
    body = _strict_object(
        receipt_body,
        _DURABLE_RECEIPT_BODY_FIELDS,
        "recovery final receipt body",
    )
    body_digest = _sha256(
        receipt_body_digest,
        "recovery final receipt body digest",
    )
    if body_digest != _digest(body, "recovery final receipt body"):
        raise _error("recovery final receipt body digest differs")
    event_id = _text(audit_event_id, "recovery terminal audit event ID")
    event_hash = _sha256(
        audit_event_hash,
        "recovery terminal audit event hash",
    )
    verification_result_id = _trusted_result_id(verification_result)
    _sha256(
        body["result_record_hash"],
        "recovery final receipt result record hash",
    )
    runtime_bindings = {
        "capability_id": recovery.capability_id,
        "company_id": recovery.company_id,
        "database_name": recovery.database_name,
        "database_uuid": recovery.database_uuid,
        "environment": recovery.environment,
        "odoo_instance_id": recovery.odoo_instance_id,
        "operation_digest": recovery.digest,
        "operation_id": recovery.operation_id,
        "operation_revision": recovery.revision,
        "precheck_digest": recovery.precheck_digest,
        "principal": recovery.principal,
        "protocol_version": recovery.protocol_version,
        "registry_digest": recovery.registry_digest,
        "release_digest": recovery.release_digest,
        "request_id": recovery.request_id,
        "user_id": recovery.user_id,
    }
    if any(body[field] != value for field, value in runtime_bindings.items()):
        raise _error("recovery final receipt body operation binding is invalid")
    if (
        body["terminal_state"] != State.COMPLETED.value
        or body["result_kind"] != ResultKind.VERIFICATION.value
        or body["result_succeeded"] is not True
        or body["result_id"] != verification_result_id
        or body["evidence_digest"] != verification_result.evidence_digest
        or canonical_json(body["evidence"])
        != canonical_json(verification_evidence)
        or body["schema_version"] != 4
        or isinstance(body["audit_sequence"], bool)
        or not isinstance(body["audit_sequence"], int)
        or body["audit_sequence"] <= 0
    ):
        raise _error("recovery final receipt body result binding is invalid")
    if (
        body["audit_event_id"] != event_id
        or body["audit_event_hash"] != event_hash
    ):
        raise _error("recovery final receipt audit binding is invalid")

    details = _strict_object(
        body["receipt_details"],
        _RECEIPT_DETAILS_FIELDS,
        "recovery final receipt details",
    )
    verification = _strict_object(
        details["verification"],
        _RECEIPT_VERIFICATION_FIELDS,
        "recovery final receipt verification",
    )
    if (
        details["operation_id"] != recovery.operation_id
        or details["operation_state"] != State.COMPLETED.value
        or details["capability_channel"] not in {"staged", "enabled"}
        or canonical_json(details["odoo_records"])
        != canonical_json(odoo_records)
        or canonical_json(details["database_finalization"])
        != canonical_json(database_finalization)
        or verification["passed"] is not True
        or verification["evidence_digest"]
        != verification_result.evidence_digest
    ):
        raise _error("recovery final receipt details binding is invalid")

    supplied_receipt_id = _receipt_id(
        receipt_id,
        "recovery final receipt ID",
    )
    expected_receipt_id = _expected_final_receipt_id(
        recovery,
        result_id=verification_result_id,
        body_digest=body_digest,
    )
    if not hmac.compare_digest(supplied_receipt_id, expected_receipt_id):
        raise _error("recovery final receipt ID differs")
    return verification_result_id, body_digest


def create_origin_recovery_completion_evidence(
    *,
    origin_operation: Operation,
    recovery_operation: Operation,
    recovery_plan_digest: str,
    recovery_execution_result: TrustedResult,
    recovery_execution_evidence: dict[str, Any],
    recovery_verification_result: TrustedResult,
    recovery_verification_evidence: dict[str, Any],
    recovery_final_receipt_id: str,
    recovery_final_receipt_body: dict[str, Any],
    recovery_final_receipt_body_digest: str,
    terminal_audit_event_id: str,
    terminal_audit_event_hash: str,
    database_finalization: dict[str, Any],
) -> OriginRecoveryCompletionEvidence:
    """Build one deterministic completion proof from already trusted material."""

    plan_digest = _sha256(recovery_plan_digest, "recovery plan digest")
    _validate_operation_sources(
        origin_operation,
        recovery_operation,
        plan_digest=plan_digest,
    )
    execution_result_id, execution_envelope_digest = (
        _validate_result_source(
            label="recovery execution",
            operation=recovery_operation,
            result=recovery_execution_result,
            evidence=recovery_execution_evidence,
            expected_kind=ResultKind.EXECUTION,
            expected_revision=recovery_operation.revision - 2,
            expected_prior_digest=None,
        )
    )
    verification_result_id, verification_envelope_digest = (
        _validate_result_source(
            label="recovery verification",
            operation=recovery_operation,
            result=recovery_verification_result,
            evidence=recovery_verification_evidence,
            expected_kind=ResultKind.VERIFICATION,
            expected_revision=recovery_operation.revision - 1,
            expected_prior_digest=recovery_execution_result.evidence_digest,
        )
    )
    odoo_records_digest, odoo_readback_digest = (
        _validate_execution_and_readback(
            operation=recovery_operation,
            execution_evidence=recovery_execution_evidence,
            verification_evidence=recovery_verification_evidence,
        )
    )
    if (
        recovery_verification_result.issued_at
        < recovery_execution_result.issued_at
        or recovery_operation.execution_result_digest
        != recovery_execution_result.evidence_digest
        or recovery_operation.verification_result_digest
        != recovery_verification_result.evidence_digest
    ):
        raise _error("recovery trusted result sequence is invalid")
    finalization = _validate_database_finalization(
        database_finalization,
        origin=origin_operation,
        recovery=recovery_operation,
    )
    final_receipt_result_id, final_receipt_body_digest = (
        _validate_final_receipt_source(
            recovery=recovery_operation,
            verification_result=recovery_verification_result,
            verification_evidence=recovery_verification_evidence,
            odoo_records=recovery_execution_evidence["odoo_records"],
            database_finalization=finalization,
            receipt_id=recovery_final_receipt_id,
            receipt_body=recovery_final_receipt_body,
            receipt_body_digest=recovery_final_receipt_body_digest,
            audit_event_id=terminal_audit_event_id,
            audit_event_hash=terminal_audit_event_hash,
        )
    )
    if final_receipt_result_id != verification_result_id:
        raise _error("recovery final receipt result binding is invalid")

    evidence = OriginRecoveryCompletionEvidence(
        protocol_version=ORIGIN_RECOVERY_COMPLETION_VERSION,
        purpose=ORIGIN_RECOVERY_COMPLETION_PURPOSE,
        origin_operation=_operation_binding(origin_operation),
        recovery_operation=_operation_binding(recovery_operation),
        recovery_plan_digest=plan_digest,
        execution_result=TrustedResultEvidenceBinding(
            kind=ResultKind.EXECUTION.value,
            result_id=execution_result_id,
            operation_id=recovery_operation.operation_id,
            operation_revision=recovery_execution_result.operation_revision,
            evidence_digest=recovery_execution_result.evidence_digest,
            envelope_digest=execution_envelope_digest,
        ),
        verification_result=TrustedResultEvidenceBinding(
            kind=ResultKind.VERIFICATION.value,
            result_id=verification_result_id,
            operation_id=recovery_operation.operation_id,
            operation_revision=recovery_verification_result.operation_revision,
            evidence_digest=recovery_verification_result.evidence_digest,
            envelope_digest=verification_envelope_digest,
        ),
        recovery_final_receipt=FinalReceiptEvidenceBinding(
            receipt_id=recovery_final_receipt_id,
            body_digest=final_receipt_body_digest,
            result_id=verification_result_id,
            evidence_digest=recovery_verification_result.evidence_digest,
            audit_event_id=terminal_audit_event_id,
            audit_event_hash=terminal_audit_event_hash,
        ),
        database_finalization_digest=_digest(
            finalization,
            "database finalization evidence",
        ),
        odoo_records_digest=odoo_records_digest,
        odoo_readback_digest=odoo_readback_digest,
    )
    return _parse_origin_recovery_completion_evidence(evidence.to_dict())


def _parse_operation_binding(
    value: Any,
    *,
    field: str,
    expected_state: str,
) -> OperationEvidenceBinding:
    document = _strict_object(value, _OPERATION_FIELDS, field)
    state = _text(document["state"], f"{field}.state")
    if state != expected_state:
        raise _error(f"{field}.state is invalid")
    return OperationEvidenceBinding(
        operation_id=_text(
            document["operation_id"],
            f"{field}.operation_id",
        ),
        request_id=_text(document["request_id"], f"{field}.request_id"),
        capability_id=_text(
            document["capability_id"],
            f"{field}.capability_id",
        ),
        operation_digest=_sha256(
            document["operation_digest"],
            f"{field}.operation_digest",
        ),
        operation_revision=_nonnegative_integer(
            document["operation_revision"],
            f"{field}.operation_revision",
        ),
        company_id=_positive_integer(
            document["company_id"],
            f"{field}.company_id",
        ),
        state=state,
    )


def _parse_result_binding(
    value: Any,
    *,
    field: str,
    expected_kind: str,
) -> TrustedResultEvidenceBinding:
    document = _strict_object(value, _RESULT_FIELDS, field)
    kind = _text(document["kind"], f"{field}.kind")
    if kind != expected_kind:
        raise _error(f"{field}.kind is invalid")
    return TrustedResultEvidenceBinding(
        kind=kind,
        result_id=_result_id(document["result_id"], f"{field}.result_id"),
        operation_id=_text(
            document["operation_id"],
            f"{field}.operation_id",
        ),
        operation_revision=_nonnegative_integer(
            document["operation_revision"],
            f"{field}.operation_revision",
        ),
        evidence_digest=_sha256(
            document["evidence_digest"],
            f"{field}.evidence_digest",
        ),
        envelope_digest=_sha256(
            document["envelope_digest"],
            f"{field}.envelope_digest",
        ),
    )


def _parse_final_receipt_binding(
    value: Any,
) -> FinalReceiptEvidenceBinding:
    field = "recovery_final_receipt"
    document = _strict_object(value, _FINAL_RECEIPT_FIELDS, field)
    return FinalReceiptEvidenceBinding(
        receipt_id=_receipt_id(
            document["receipt_id"],
            f"{field}.receipt_id",
        ),
        body_digest=_sha256(
            document["body_digest"],
            f"{field}.body_digest",
        ),
        result_id=_result_id(
            document["result_id"],
            f"{field}.result_id",
        ),
        evidence_digest=_sha256(
            document["evidence_digest"],
            f"{field}.evidence_digest",
        ),
        audit_event_id=_text(
            document["audit_event_id"],
            f"{field}.audit_event_id",
        ),
        audit_event_hash=_sha256(
            document["audit_event_hash"],
            f"{field}.audit_event_hash",
        ),
    )


def _parse_origin_recovery_completion_evidence(
    value: Any,
) -> OriginRecoveryCompletionEvidence:
    document = _strict_object(
        value,
        _DOCUMENT_FIELDS,
        "origin recovery completion evidence",
    )
    if (
        type(document["protocol_version"]) is not int
        or document["protocol_version"] != ORIGIN_RECOVERY_COMPLETION_VERSION
    ):
        raise _error("origin recovery completion protocol_version is invalid")
    if document["purpose"] != ORIGIN_RECOVERY_COMPLETION_PURPOSE:
        raise _error("origin recovery completion purpose is invalid")
    origin = _parse_operation_binding(
        document["origin_operation"],
        field="origin_operation",
        expected_state=State.FAILED.value,
    )
    recovery = _parse_operation_binding(
        document["recovery_operation"],
        field="recovery_operation",
        expected_state=State.COMPLETED.value,
    )
    execution = _parse_result_binding(
        document["execution_result"],
        field="execution_result",
        expected_kind=ResultKind.EXECUTION.value,
    )
    verification = _parse_result_binding(
        document["verification_result"],
        field="verification_result",
        expected_kind=ResultKind.VERIFICATION.value,
    )
    final_receipt = _parse_final_receipt_binding(
        document["recovery_final_receipt"]
    )
    if (
        origin.operation_id == recovery.operation_id
        or origin.company_id != recovery.company_id
        or recovery.capability_id != RECOVERY_CAPABILITY_ID
        or recovery.operation_revision < 2
        or execution.operation_id != recovery.operation_id
        or verification.operation_id != recovery.operation_id
        or execution.operation_revision != recovery.operation_revision - 2
        or verification.operation_revision != recovery.operation_revision - 1
        or final_receipt.result_id != verification.result_id
        or final_receipt.evidence_digest != verification.evidence_digest
    ):
        raise _error("origin recovery completion cross-binding is invalid")
    return OriginRecoveryCompletionEvidence(
        protocol_version=ORIGIN_RECOVERY_COMPLETION_VERSION,
        purpose=ORIGIN_RECOVERY_COMPLETION_PURPOSE,
        origin_operation=origin,
        recovery_operation=recovery,
        recovery_plan_digest=_sha256(
            document["recovery_plan_digest"],
            "recovery_plan_digest",
        ),
        execution_result=execution,
        verification_result=verification,
        recovery_final_receipt=final_receipt,
        database_finalization_digest=_sha256(
            document["database_finalization_digest"],
            "database_finalization_digest",
        ),
        odoo_records_digest=_sha256(
            document["odoo_records_digest"],
            "odoo_records_digest",
        ),
        odoo_readback_digest=_sha256(
            document["odoo_readback_digest"],
            "odoo_readback_digest",
        ),
    )


def validate_origin_recovery_completion_evidence(
    value: Any,
    *,
    expected: OriginRecoveryCompletionEvidence,
) -> OriginRecoveryCompletionEvidence:
    """Validate strict shape and exact equality to freshly rebuilt evidence."""

    if type(expected) is not OriginRecoveryCompletionEvidence:
        raise _error("expected recovery completion evidence is not validated")
    parsed = _parse_origin_recovery_completion_evidence(value)
    actual_bytes = canonical_json(parsed.to_dict())
    expected_bytes = canonical_json(expected.to_dict())
    if (
        not hmac.compare_digest(
            hashlib.sha256(actual_bytes).digest(),
            hashlib.sha256(expected_bytes).digest(),
        )
        or actual_bytes != expected_bytes
    ):
        raise _error(
            "origin recovery completion evidence differs from expected sources"
        )
    return parsed


def origin_recovery_completion_evidence_digest(
    value: OriginRecoveryCompletionEvidence,
) -> str:
    """Return the digest to place in the origin recovery trusted result."""

    if type(value) is not OriginRecoveryCompletionEvidence:
        raise _error("recovery completion evidence must be validated")
    parsed = _parse_origin_recovery_completion_evidence(value.to_dict())
    return _digest(parsed.to_dict(), "origin recovery completion evidence")


__all__ = [
    "ORIGIN_RECOVERY_COMPLETION_PURPOSE",
    "ORIGIN_RECOVERY_COMPLETION_VERSION",
    "FinalReceiptEvidenceBinding",
    "OperationEvidenceBinding",
    "OriginRecoveryCompletionError",
    "OriginRecoveryCompletionEvidence",
    "TrustedResultEvidenceBinding",
    "create_origin_recovery_completion_evidence",
    "origin_recovery_completion_evidence_digest",
    "validate_origin_recovery_completion_evidence",
]

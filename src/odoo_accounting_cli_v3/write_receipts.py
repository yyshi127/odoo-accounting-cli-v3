"""Strict snapshots, recovery plans, and signed receipts for Odoo writes."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .effect_finalizer import (
    EffectFinalizationError,
    validate_effect_finalization_evidence_shape,
)
from .operations import canonical_json


class WriteReceiptError(ValueError):
    pass


SHA256 = re.compile(r"[0-9a-f]{64}")
MODEL = re.compile(r"[a-z][a-z0-9_.]{0,127}")
WRITE_RECEIPT_PURPOSE = "write_audit_receipt_v1"
WRITE_SIGNATURE_VERSION = 1
MIN_HMAC_SECRET_BYTES = 32
ENVIRONMENTS = frozenset({"test", "sandbox", "production"})
CHANNELS = frozenset({"staged", "enabled"})

SNAPSHOT_FIELDS = {
    "exists",
    "model",
    "record_id",
    "record_state",
    "values_digest",
    "values_json",
}
RECORD_REFERENCE_FIELDS = {
    "company_id",
    "model",
    "record_fingerprint",
    "record_id",
}
RECOVERY_TARGET_FIELDS = {*RECORD_REFERENCE_FIELDS, "record_state"}
RECOVERY_GUARD_FIELDS = {*RECOVERY_TARGET_FIELDS, "expected_outcome"}
RECOVERY_GUARD_OUTCOMES = frozenset(
    {"survive_exact", "survive_allowed_delta", "absent", "manual_review"}
)
NON_EXECUTABLE_ORACLES = frozenset(
    {"manual", "manual_escalation", "not_applicable"}
)
DIFFERENCE_FIELDS = {
    "after",
    "after_digest",
    "before",
    "before_digest",
    "changed_fields",
}
RECOVERY_PLAN_FIELDS = {
    "method",
    "origin_operation_id",
    "parameters_digest",
    "plan_digest",
    "recovery_capability_id",
    "requires_approval",
    "status",
    "target_records",
}
RECOVERY_PLAN_V2_FIELDS = {
    "action_targets",
    "guard_graph_digest",
    "guard_records",
    "method",
    "oracle_id",
    "origin_operation_id",
    "parameters_digest",
    "plan_digest",
    "plan_version",
    "recovery_capability_id",
    "requires_approval",
    "status",
}
VERIFICATION_FIELDS = {
    "checks",
    "evidence_digest",
    "method",
    "passed",
    "verified_at",
}
RESULT_BODY_FIELDS = {
    "database_finalization",
    "difference",
    "odoo_records",
    "operation_id",
    "operation_state",
    "recovery_plan",
    "verification",
}
RECEIPT_FIELDS = {
    "approval_digest",
    "approver_user_id",
    "audit_head",
    "capability_channel",
    "capability_id",
    "company_id",
    "database_name",
    "database_uuid",
    "environment",
    "issued_at",
    "odoo_instance_id",
    "operation_digest",
    "operation_id",
    "principal",
    "receipt_id",
    "registry_digest",
    "release_digest",
    "request_digest",
    "request_id",
    "result_digest",
    "signature",
    "signature_purpose",
    "signature_version",
    "signing_key_id",
    "user_id",
    "verification_evidence_digest",
}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WriteReceiptError(f"{field} is invalid")
    return value


def _positive_id(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WriteReceiptError(f"{field} must be a positive integer")
    return value


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise WriteReceiptError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _aware(value: Any, field: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise WriteReceiptError(f"{field} must be timezone-aware")
    return value


def _parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise WriteReceiptError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WriteReceiptError(f"{field} must be an RFC 3339 timestamp") from exc
    return _aware(parsed, field)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _secret(value: Any) -> bytes:
    if not isinstance(value, bytes) or len(value) < MIN_HMAC_SECRET_BYTES:
        raise WriteReceiptError("write receipt HMAC secret must be at least 32 bytes")
    return value


def _runtime_binding(environment: Any, capability_channel: Any) -> None:
    if environment not in ENVIRONMENTS or capability_channel not in CHANNELS:
        raise WriteReceiptError("write receipt runtime binding is invalid")
    if environment == "production" and capability_channel == "staged":
        raise WriteReceiptError("a staged capability cannot emit a production write receipt")


def create_record_snapshot(
    *,
    model: str,
    record_id: int,
    exists: bool,
    record_state: str,
    values: dict[str, Any],
) -> dict[str, Any]:
    if MODEL.fullmatch(_text(model, "snapshot model", maximum=128)) is None:
        raise WriteReceiptError("snapshot model is invalid")
    _positive_id(record_id, "snapshot record_id")
    if type(exists) is not bool:
        raise WriteReceiptError("snapshot exists flag must be boolean")
    _text(record_state, "snapshot record_state", maximum=128)
    if not isinstance(values, dict):
        raise WriteReceiptError("snapshot values must be an object")
    try:
        values_json = canonical_json(values).decode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WriteReceiptError("snapshot values are not canonical JSON") from exc
    return {
        "model": model,
        "record_id": record_id,
        "exists": exists,
        "record_state": record_state,
        "values_json": values_json,
        "values_digest": hashlib.sha256(values_json.encode("utf-8")).hexdigest(),
    }


def _validate_snapshot(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != SNAPSHOT_FIELDS:
        raise WriteReceiptError("record snapshot fields are invalid")
    if MODEL.fullmatch(_text(value["model"], "snapshot model", maximum=128)) is None:
        raise WriteReceiptError("snapshot model is invalid")
    _positive_id(value["record_id"], "snapshot record_id")
    if type(value["exists"]) is not bool:
        raise WriteReceiptError("snapshot exists flag must be boolean")
    _text(value["record_state"], "snapshot record_state", maximum=128)
    if not isinstance(value["values_json"], str):
        raise WriteReceiptError("snapshot values_json is invalid")
    try:
        decoded = json.loads(value["values_json"])
    except json.JSONDecodeError as exc:
        raise WriteReceiptError("snapshot values_json is invalid") from exc
    if (
        not isinstance(decoded, dict)
        or canonical_json(decoded).decode("utf-8") != value["values_json"]
        or _sha(value["values_digest"], "snapshot values_digest")
        != hashlib.sha256(value["values_json"].encode("utf-8")).hexdigest()
    ):
        raise WriteReceiptError("record snapshot content digest is invalid")


def validate_record_snapshot(value: Any) -> None:
    """Validate one canonical Odoo record snapshot used as signed evidence."""

    _validate_snapshot(value)


def _validate_record_reference(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != RECORD_REFERENCE_FIELDS:
        raise WriteReceiptError("Odoo record reference fields are invalid")
    if MODEL.fullmatch(_text(value["model"], "record model", maximum=128)) is None:
        raise WriteReceiptError("record model is invalid")
    _positive_id(value["record_id"], "record_id")
    _positive_id(value["company_id"], "record company_id")
    _sha(value["record_fingerprint"], "record_fingerprint")


def _validate_recovery_target(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != RECOVERY_TARGET_FIELDS:
        raise WriteReceiptError("recovery target record fields are invalid")
    _validate_record_reference({key: value[key] for key in RECORD_REFERENCE_FIELDS})
    _text(value["record_state"], "recovery target record_state", maximum=64)


def _validate_recovery_guard(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != RECOVERY_GUARD_FIELDS:
        raise WriteReceiptError("recovery guard record fields are invalid")
    _validate_recovery_target({key: value[key] for key in RECOVERY_TARGET_FIELDS})
    if (
        not isinstance(value["expected_outcome"], str)
        or value["expected_outcome"] not in RECOVERY_GUARD_OUTCOMES
    ):
        raise WriteReceiptError("recovery guard expected_outcome is invalid")


def _recovery_record_identity(value: dict[str, Any]) -> tuple[str, int]:
    return value["model"], value["record_id"]


def _canonical_recovery_records(
    value: Any,
    *,
    field: str,
    guard: bool,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise WriteReceiptError(f"recovery {field} must be an array")
    records = [dict(record) if isinstance(record, dict) else record for record in value]
    validator = _validate_recovery_guard if guard else _validate_recovery_target
    for record in records:
        validator(record)
    identities = [_recovery_record_identity(record) for record in records]
    if len(identities) != len(set(identities)):
        raise WriteReceiptError(f"recovery {field} contains a duplicate record")
    return sorted(records, key=canonical_json)


def _guard_graph_digest(
    action_targets: list[dict[str, Any]],
    guard_records: list[dict[str, Any]],
    oracle_id: str,
) -> str:
    return _digest(
        {
            "action_targets": action_targets,
            "guard_records": guard_records,
            "oracle_id": oracle_id,
        }
    )


def _validate_recovery_graph_roles(
    action_targets: list[dict[str, Any]], guard_records: list[dict[str, Any]]
) -> None:
    action_identities = {
        _recovery_record_identity(record) for record in action_targets
    }
    guard_identities = {_recovery_record_identity(record) for record in guard_records}
    if action_identities & guard_identities:
        raise WriteReceiptError("a recovery record cannot be both action and guard")


def create_difference(
    *,
    before: list[dict[str, Any]],
    after: list[dict[str, Any]],
    changed_fields: list[str],
) -> dict[str, Any]:
    if not isinstance(before, list) or not isinstance(after, list):
        raise WriteReceiptError("difference snapshots must be arrays")
    for snapshot in (*before, *after):
        _validate_snapshot(snapshot)
    if (
        not isinstance(changed_fields, list)
        or any(not isinstance(item, str) or not item.strip() for item in changed_fields)
        or len(changed_fields) != len(set(changed_fields))
    ):
        raise WriteReceiptError("difference changed_fields must be unique text")
    ordered_fields = sorted(changed_fields)
    return {
        "before": before,
        "after": after,
        "changed_fields": ordered_fields,
        "before_digest": _digest(before),
        "after_digest": _digest(after),
    }


def _validate_difference(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != DIFFERENCE_FIELDS:
        raise WriteReceiptError("difference fields are invalid")
    before = value["before"]
    after = value["after"]
    if not isinstance(before, list) or not isinstance(after, list):
        raise WriteReceiptError("difference snapshots must be arrays")
    for snapshot in (*before, *after):
        _validate_snapshot(snapshot)
    changed = value["changed_fields"]
    if (
        not isinstance(changed, list)
        or changed != sorted(changed)
        or len(changed) != len(set(changed))
        or any(not isinstance(item, str) or not item.strip() for item in changed)
    ):
        raise WriteReceiptError("difference changed_fields are invalid")
    if value["before_digest"] != _digest(before) or value["after_digest"] != _digest(after):
        raise WriteReceiptError("difference snapshot digest mismatch")


def validate_write_difference(value: Any) -> None:
    """Validate a canonical before/after difference before it is persisted."""

    _validate_difference(value)


def create_recovery_plan(
    *,
    origin_operation_id: str,
    recovery_capability_id: str,
    status: str,
    method: str,
    requires_approval: bool,
    target_records: list[dict[str, Any]],
    parameters: dict[str, Any],
) -> dict[str, Any]:
    _text(origin_operation_id, "origin_operation_id")
    if recovery_capability_id != "acct.recovery.execute.v1":
        raise WriteReceiptError("recovery_capability_id is invalid")
    _text(method, "recovery method")
    if status not in {"available", "not_applicable", "manual_escalation"}:
        raise WriteReceiptError("recovery status is invalid")
    if type(requires_approval) is not bool:
        raise WriteReceiptError("recovery approval flag must be boolean")
    if not isinstance(target_records, list):
        raise WriteReceiptError("recovery target_records must be an array")
    for record in target_records:
        _validate_recovery_target(record)
    if status == "available" and not target_records:
        raise WriteReceiptError("available recovery requires target records")
    if not isinstance(parameters, dict):
        raise WriteReceiptError("recovery parameters must be an object")
    parameters_digest = _digest(parameters)
    unsigned = {
        "origin_operation_id": origin_operation_id,
        "recovery_capability_id": recovery_capability_id,
        "status": status,
        "method": method,
        "requires_approval": requires_approval,
        "target_records": target_records,
        "parameters_digest": parameters_digest,
    }
    return {**unsigned, "plan_digest": _digest(unsigned)}


def create_recovery_plan_v2(
    *,
    origin_operation_id: str,
    recovery_capability_id: str,
    status: str,
    method: str,
    requires_approval: bool,
    action_targets: list[dict[str, Any]],
    guard_records: list[dict[str, Any]],
    oracle_id: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Create a canonical role-separated recovery guard graph contract."""

    _text(origin_operation_id, "origin_operation_id")
    if recovery_capability_id != "acct.recovery.execute.v1":
        raise WriteReceiptError("recovery_capability_id is invalid")
    _text(method, "recovery method")
    if not isinstance(status, str) or status not in {
        "available",
        "not_applicable",
        "manual_escalation",
    }:
        raise WriteReceiptError("recovery status is invalid")
    if type(requires_approval) is not bool:
        raise WriteReceiptError("recovery approval flag must be boolean")
    oracle_id = _text(oracle_id, "recovery oracle_id", maximum=128)
    ordered_actions = _canonical_recovery_records(
        action_targets, field="action_targets", guard=False
    )
    ordered_guards = _canonical_recovery_records(
        guard_records, field="guard_records", guard=True
    )
    _validate_recovery_graph_roles(ordered_actions, ordered_guards)
    if status == "available":
        if not requires_approval:
            raise WriteReceiptError("available recovery requires approval")
        if not ordered_actions:
            raise WriteReceiptError("available recovery requires an action target")
        if not ordered_guards:
            raise WriteReceiptError("available recovery requires a guard record")
        if any(
            record["expected_outcome"] == "manual_review"
            for record in ordered_guards
        ):
            raise WriteReceiptError(
                "available recovery cannot contain a manual_review guard"
            )
        if oracle_id in NON_EXECUTABLE_ORACLES:
            raise WriteReceiptError("available recovery requires an executable oracle")
    elif ordered_actions:
        raise WriteReceiptError("non-available recovery action_targets must be empty")
    if not isinstance(parameters, dict):
        raise WriteReceiptError("recovery parameters must be an object")
    try:
        parameters_digest = _digest(parameters)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WriteReceiptError("recovery parameters are not canonical JSON") from exc
    unsigned = {
        "plan_version": 2,
        "origin_operation_id": origin_operation_id,
        "recovery_capability_id": recovery_capability_id,
        "status": status,
        "method": method,
        "requires_approval": requires_approval,
        "action_targets": ordered_actions,
        "guard_records": ordered_guards,
        "oracle_id": oracle_id,
        "guard_graph_digest": _guard_graph_digest(
            ordered_actions, ordered_guards, oracle_id
        ),
        "parameters_digest": parameters_digest,
    }
    return {**unsigned, "plan_digest": _digest(unsigned)}


def _validate_recovery_plan_v1(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != RECOVERY_PLAN_FIELDS:
        raise WriteReceiptError("recovery plan fields are invalid")
    _text(value["origin_operation_id"], "origin_operation_id")
    if value["recovery_capability_id"] != "acct.recovery.execute.v1":
        raise WriteReceiptError("recovery_capability_id is invalid")
    _text(value["method"], "recovery method")
    if not isinstance(value["status"], str) or value["status"] not in {
        "available",
        "not_applicable",
        "manual_escalation",
    }:
        raise WriteReceiptError("recovery plan status is invalid")
    if type(value["requires_approval"]) is not bool or not isinstance(
        value["target_records"], list
    ):
        raise WriteReceiptError("recovery plan content is invalid")
    for record in value["target_records"]:
        _validate_recovery_target(record)
    if value["status"] == "available" and not value["target_records"]:
        raise WriteReceiptError("available recovery requires target records")
    _sha(value["parameters_digest"], "recovery parameters_digest")
    unsigned = {key: value[key] for key in RECOVERY_PLAN_FIELDS if key != "plan_digest"}
    if _sha(value["plan_digest"], "recovery plan_digest") != _digest(unsigned):
        raise WriteReceiptError("recovery plan digest mismatch")


def _validate_recovery_plan_v2(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != RECOVERY_PLAN_V2_FIELDS:
        raise WriteReceiptError("recovery plan V2 fields are invalid")
    if type(value["plan_version"]) is not int or value["plan_version"] != 2:
        raise WriteReceiptError("recovery plan version is invalid")
    _text(value["origin_operation_id"], "origin_operation_id")
    if value["recovery_capability_id"] != "acct.recovery.execute.v1":
        raise WriteReceiptError("recovery_capability_id is invalid")
    _text(value["method"], "recovery method")
    if value["status"] not in {"available", "not_applicable", "manual_escalation"}:
        raise WriteReceiptError("recovery plan status is invalid")
    if type(value["requires_approval"]) is not bool:
        raise WriteReceiptError("recovery approval flag must be boolean")
    oracle_id = _text(value["oracle_id"], "recovery oracle_id", maximum=128)
    ordered_actions = _canonical_recovery_records(
        value["action_targets"], field="action_targets", guard=False
    )
    ordered_guards = _canonical_recovery_records(
        value["guard_records"], field="guard_records", guard=True
    )
    if (
        value["action_targets"] != ordered_actions
        or value["guard_records"] != ordered_guards
    ):
        raise WriteReceiptError("recovery guard graph is not in canonical order")
    _validate_recovery_graph_roles(ordered_actions, ordered_guards)
    if value["status"] == "available":
        if not value["requires_approval"]:
            raise WriteReceiptError("available recovery requires approval")
        if not ordered_actions:
            raise WriteReceiptError("available recovery requires an action target")
        if not ordered_guards:
            raise WriteReceiptError("available recovery requires a guard record")
        if any(
            record["expected_outcome"] == "manual_review"
            for record in ordered_guards
        ):
            raise WriteReceiptError(
                "available recovery cannot contain a manual_review guard"
            )
        if oracle_id in NON_EXECUTABLE_ORACLES:
            raise WriteReceiptError("available recovery requires an executable oracle")
    elif ordered_actions:
        raise WriteReceiptError("non-available recovery action_targets must be empty")
    expected_guard_digest = _guard_graph_digest(
        ordered_actions, ordered_guards, oracle_id
    )
    if (
        _sha(value["guard_graph_digest"], "recovery guard_graph_digest")
        != expected_guard_digest
    ):
        raise WriteReceiptError("recovery guard graph digest mismatch")
    _sha(value["parameters_digest"], "recovery parameters_digest")
    unsigned = {
        key: value[key] for key in RECOVERY_PLAN_V2_FIELDS if key != "plan_digest"
    }
    if _sha(value["plan_digest"], "recovery plan_digest") != _digest(unsigned):
        raise WriteReceiptError("recovery plan digest mismatch")


def _validate_recovery_plan(value: Any) -> None:
    if isinstance(value, dict) and "plan_version" in value:
        _validate_recovery_plan_v2(value)
        return
    _validate_recovery_plan_v1(value)


def validate_recovery_plan(value: Any) -> None:
    """Strictly validate a historical V1 or role-separated V2 recovery plan."""

    _validate_recovery_plan(value)


def validate_executable_recovery_plan(value: Any) -> None:
    """Accept only an approved-by-contract, available V2 recovery plan."""

    if not isinstance(value, dict) or value.get("plan_version") != 2:
        raise WriteReceiptError("recovery execution requires an available V2 plan")
    _validate_recovery_plan_v2(value)
    if value["status"] != "available":
        raise WriteReceiptError("recovery execution requires an available V2 plan")


def index_recovery_guard_graph(
    value: Any, *, expected_company_id: int | None = None
) -> dict[tuple[str, int], dict[str, Any]]:
    """Index V2 action and guard roles, optionally enforcing one company scope."""

    if not isinstance(value, dict) or value.get("plan_version") != 2:
        raise WriteReceiptError("recovery guard graph indexing requires a V2 plan")
    _validate_recovery_plan_v2(value)
    if expected_company_id is not None:
        _positive_id(expected_company_id, "expected recovery company_id")
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for role, field in (("action", "action_targets"), ("guard", "guard_records")):
        for record in value[field]:
            if (
                expected_company_id is not None
                and record["company_id"] != expected_company_id
            ):
                raise WriteReceiptError("recovery guard graph company mismatch")
            indexed[_recovery_record_identity(record)] = {**record, "role": role}
    return indexed


def _validate_result_body(value: Any, operation_id: str) -> None:
    if not isinstance(value, dict) or set(value) != RESULT_BODY_FIELDS:
        raise WriteReceiptError("write result fields are invalid")
    if value["operation_id"] != operation_id:
        raise WriteReceiptError("write result operation binding mismatch")
    state = value["operation_state"]
    if state not in {"completed", "failed", "recovered"}:
        raise WriteReceiptError("write result state is invalid")
    records = value["odoo_records"]
    if not isinstance(records, list):
        raise WriteReceiptError("write result Odoo records must be an array")
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "model",
            "record_id",
            "company_id",
            "record_state",
            "record_fingerprint",
        }:
            raise WriteReceiptError("write result Odoo record fields are invalid")
        _validate_record_reference(
            {key: record[key] for key in RECORD_REFERENCE_FIELDS}
        )
        _text(record["record_state"], "record_state", maximum=128)
    _validate_difference(value["difference"])
    verification = value["verification"]
    if not isinstance(verification, dict) or set(verification) != VERIFICATION_FIELDS:
        raise WriteReceiptError("write verification fields are invalid")
    _text(verification["method"], "verification method")
    if type(verification["passed"]) is not bool:
        raise WriteReceiptError("verification passed flag must be boolean")
    checks = verification["checks"]
    if (
        not isinstance(checks, list)
        or not checks
        or len(checks) != len(set(checks))
        or any(not isinstance(item, str) or not item.strip() for item in checks)
    ):
        raise WriteReceiptError("verification checks are invalid")
    _sha(verification["evidence_digest"], "verification evidence_digest")
    _parse_datetime(verification["verified_at"], "verification verified_at")
    _validate_recovery_plan(value["recovery_plan"])
    database_finalization = value["database_finalization"]
    if state in {"completed", "recovered"}:
        try:
            validate_effect_finalization_evidence_shape(database_finalization)
        except EffectFinalizationError as exc:
            raise WriteReceiptError(
                "successful write requires database effect finalization"
            ) from exc
    elif database_finalization is not None:
        raise WriteReceiptError(
            "failed write cannot contain database effect finalization"
        )
    if state in {"completed", "recovered"} and (
        not verification["passed"] or not records
    ):
        message = (
            "completed write requires a verified Odoo effect"
            if not verification["passed"]
            else "completed write requires an Odoo record"
        )
        raise WriteReceiptError(message)
    if state == "failed" and verification["passed"]:
        raise WriteReceiptError("failed write cannot contain a passing verification")


def validate_write_result_body(value: Any, *, operation_id: str) -> None:
    """Validate the receipt-bound result before entering a terminal state."""

    _validate_result_body(value, operation_id)


def _receipt_bindings(
    *,
    request_id: str,
    operation_id: str,
    capability_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    user_id: int,
    approver_user_id: int,
    company_id: int,
    environment: str,
    capability_channel: str,
    request_digest: str,
    operation_digest: str,
    approval_digest: str,
    registry_digest: str,
    release_digest: str,
    audit_head: str,
) -> dict[str, Any]:
    for field, value in (
        ("request_id", request_id),
        ("operation_id", operation_id),
        ("capability_id", capability_id),
        ("principal", principal),
        ("odoo_instance_id", odoo_instance_id),
        ("database_name", database_name),
    ):
        _text(value, field)
    _positive_id(user_id, "user_id")
    _positive_id(approver_user_id, "approver_user_id")
    _positive_id(company_id, "company_id")
    if approver_user_id == user_id:
        raise WriteReceiptError("requester cannot approve their own write")
    try:
        normalized_uuid = str(uuid.UUID(database_uuid))
    except (AttributeError, TypeError, ValueError) as exc:
        raise WriteReceiptError("database_uuid is invalid") from exc
    _runtime_binding(environment, capability_channel)
    for field, value in (
        ("request_digest", request_digest),
        ("operation_digest", operation_digest),
        ("approval_digest", approval_digest),
        ("registry_digest", registry_digest),
        ("release_digest", release_digest),
        ("audit_head", audit_head),
    ):
        _sha(value, field)
    return {
        "request_id": request_id,
        "operation_id": operation_id,
        "capability_id": capability_id,
        "principal": principal,
        "odoo_instance_id": odoo_instance_id,
        "database_name": database_name,
        "database_uuid": normalized_uuid,
        "user_id": user_id,
        "approver_user_id": approver_user_id,
        "company_id": company_id,
        "environment": environment,
        "capability_channel": capability_channel,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "approval_digest": approval_digest,
        "registry_digest": registry_digest,
        "release_digest": release_digest,
        "audit_head": audit_head,
    }


def create_write_audit_receipt(
    *,
    receipt_id: str,
    request_id: str,
    operation_id: str,
    capability_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    user_id: int,
    approver_user_id: int,
    company_id: int,
    environment: str,
    capability_channel: str,
    request_digest: str,
    operation_digest: str,
    approval_digest: str,
    registry_digest: str,
    release_digest: str,
    audit_head: str,
    result_body: dict[str, Any],
    issued_at: datetime,
    signing_key_id: str,
    secret: bytes,
) -> dict[str, Any]:
    secret = _secret(secret)
    _text(receipt_id, "receipt_id")
    _text(signing_key_id, "signing_key_id")
    issued_at = _aware(issued_at, "issued_at")
    bindings = _receipt_bindings(
        request_id=request_id,
        operation_id=operation_id,
        capability_id=capability_id,
        principal=principal,
        odoo_instance_id=odoo_instance_id,
        database_name=database_name,
        database_uuid=database_uuid,
        user_id=user_id,
        approver_user_id=approver_user_id,
        company_id=company_id,
        environment=environment,
        capability_channel=capability_channel,
        request_digest=request_digest,
        operation_digest=operation_digest,
        approval_digest=approval_digest,
        registry_digest=registry_digest,
        release_digest=release_digest,
        audit_head=audit_head,
    )
    _validate_result_body(result_body, operation_id)
    result_digest = _digest(result_body)
    verification_digest = result_body["verification"]["evidence_digest"]
    unsigned = {
        "receipt_id": receipt_id,
        **bindings,
        "result_digest": result_digest,
        "verification_evidence_digest": verification_digest,
        "issued_at": _utc(issued_at),
        "signature_version": WRITE_SIGNATURE_VERSION,
        "signature_purpose": WRITE_RECEIPT_PURPOSE,
        "signing_key_id": signing_key_id,
    }
    return {
        **unsigned,
        "signature": hmac.new(secret, canonical_json(unsigned), hashlib.sha256).hexdigest(),
    }


def verify_write_audit_receipt(
    receipt: dict[str, Any],
    *,
    request_id: str,
    operation_id: str,
    capability_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    user_id: int,
    approver_user_id: int,
    company_id: int,
    environment: str,
    capability_channel: str,
    request_digest: str,
    operation_digest: str,
    approval_digest: str,
    registry_digest: str,
    release_digest: str,
    audit_head: str,
    result_body: dict[str, Any],
    now: datetime,
    expected_signing_key_id: str,
    secret: bytes,
) -> None:
    secret = _secret(secret)
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise WriteReceiptError("write receipt fields are invalid")
    now = _aware(now, "now")
    _text(expected_signing_key_id, "expected_signing_key_id")
    expected = _receipt_bindings(
        request_id=request_id,
        operation_id=operation_id,
        capability_id=capability_id,
        principal=principal,
        odoo_instance_id=odoo_instance_id,
        database_name=database_name,
        database_uuid=database_uuid,
        user_id=user_id,
        approver_user_id=approver_user_id,
        company_id=company_id,
        environment=environment,
        capability_channel=capability_channel,
        request_digest=request_digest,
        operation_digest=operation_digest,
        approval_digest=approval_digest,
        registry_digest=registry_digest,
        release_digest=release_digest,
        audit_head=audit_head,
    )
    _validate_result_body(result_body, operation_id)
    if type(receipt["signature_version"]) is not int or receipt["signature_version"] != WRITE_SIGNATURE_VERSION:
        raise WriteReceiptError("write receipt signature version mismatch")
    if receipt["signature_purpose"] != WRITE_RECEIPT_PURPOSE:
        raise WriteReceiptError("write receipt signature purpose mismatch")
    if receipt["signing_key_id"] != expected_signing_key_id:
        raise WriteReceiptError("write receipt signing key mismatch")
    for field in ("receipt_id", "signing_key_id"):
        _text(receipt[field], field)
    for field in (
        "request_digest",
        "operation_digest",
        "approval_digest",
        "result_digest",
        "verification_evidence_digest",
        "registry_digest",
        "release_digest",
        "audit_head",
        "signature",
    ):
        _sha(receipt[field], field)
    if any(receipt[field] != value for field, value in expected.items()):
        raise WriteReceiptError("write receipt binding mismatch")
    issued_at = _parse_datetime(receipt["issued_at"], "issued_at")
    if issued_at > now:
        raise WriteReceiptError("write receipt timestamp is in the future")
    if (
        receipt["result_digest"] != _digest(result_body)
        or receipt["verification_evidence_digest"]
        != result_body["verification"]["evidence_digest"]
    ):
        raise WriteReceiptError("write receipt content digest mismatch")
    unsigned = {key: value for key, value in receipt.items() if key != "signature"}
    expected_signature = hmac.new(
        secret, canonical_json(unsigned), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, receipt["signature"]):
        raise WriteReceiptError("write receipt signature mismatch")

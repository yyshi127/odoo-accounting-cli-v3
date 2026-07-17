"""Fail-closed, transaction-owning Odoo shell bootstrap for approved writes.

The outer process supplies signed protocol mappings.  This module is the only
Odoo-side layer that commits.  Business handlers receive a bound non-superuser
environment and never own transaction or privilege boundaries.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable, ContextManager, Iterable, Mapping, Protocol

from ..auth import authentication_request_digest, verify_request_context
from ..contracts import validate_value
from ..draft_invoice_recovery import (
    DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
    DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE,
    classic_read_many2one_id,
    customer_invoice_business_binding,
    customer_invoice_document_binding,
)
from ..domain.write_semantics import validate_write_semantics
from ..gateway import RequestContext
from ..operations import (
    Approval,
    Operation,
    OperationError,
    State,
    TrustedResult,
    begin_execution,
    canonical_json,
    complete_operation,
    record_execution_result,
    sign_execution_result,
    sign_verification_result,
)
from ..registry import Capability, registry_digest
from ..write_protocol import (
    approved_write_authentication_parameters,
    approval_from_mapping,
    operation_from_mapping,
    trusted_result_from_mapping,
    trusted_result_to_mapping,
)
from ..write_receipts import (
    WriteReceiptError,
    create_difference,
    create_record_snapshot,
    create_recovery_plan_v2,
    index_recovery_guard_graph,
    validate_executable_recovery_plan,
)
from ..write_service import write_idempotency_scope
from .bootstrap import (
    bind_non_superuser_environment,
    database_uuid,
    request_context_from_mapping,
)
from .write_precheck import (
    canonical_precheck_evidence,
    run_rollback_only_precheck,
)


class OdooWriteBootstrapError(ValueError):
    """A signed write request or durable Odoo result was rejected."""


class WriteHandler(Protocol):
    def precheck(
        self, capability_id: str, parameters: dict[str, Any]
    ) -> Mapping[str, Any]: ...

    def execute_prechecked(
        self,
        capability_id: str,
        parameters: dict[str, Any],
        checked: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def verify(
        self,
        capability_id: str,
        parameters: dict[str, Any],
        execution: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


class ControlAnchor(Protocol):
    state: str
    execution_evidence_json: Any
    execution_evidence_digest: Any
    execution_result_json: Any
    execution_result_digest: Any
    verification_evidence_json: Any
    verification_evidence_digest: Any
    verification_result_json: Any
    verification_result_digest: Any

    def _acquire_resource_locks(self, resource_digests: list[str]) -> Any: ...

    def _record_execution(self, **values: Any) -> Any: ...

    def _record_verification(self, **values: Any) -> Any: ...

    def _record_committed_verification_from_root(self, **values: Any) -> Any: ...


class ControlStore(Protocol):
    def _lookup_exact(self, **values: Any) -> ControlAnchor | None: ...

    def _claim(self, **values: Any) -> ControlAnchor: ...


REQUEST_FIELDS = frozenset(
    {
        "context",
        "operation",
        "approval",
        "trusted_recovery_plan",
        "reconciliation_only",
    }
)
CHANNELS = frozenset({"staged", "enabled"})
SHA256 = re.compile(r"[0-9a-f]{64}")
ODOO_MODEL = re.compile(r"[a-z][a-z0-9_.]{1,127}")
MAX_AUDIT_RECORDS = 900
MAX_SNAPSHOT_VALUES_JSON_CHARS = 65_536
METADATA_SCOPE_MODULE = (
    "odoo.addons.odoo_accounting_cli_v3_control.models.execution_scope"
)
EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"
APPROVER_GROUP = "odoo_accounting_cli_v3_control.group_approver"
ANCHOR_RESULT_FIELDS = frozenset(
    {
        "capability_id",
        "company_id",
        "evidence_digest",
        "issued_at",
        "issuer",
        "key_id",
        "kind",
        "operation_digest",
        "operation_id",
        "operation_revision",
        "operation_state_digest",
        "prior_evidence_digest",
        "purpose",
        "registry_digest",
        "release_digest",
        "request_id",
        "signature",
        "succeeded",
        "version",
    }
)


def _digest(value: Any) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OdooWriteBootstrapError("write evidence is not canonical JSON") from exc


def _resource_lock_digests(
    capability_id: str,
    company_id: int,
    parameters: Mapping[str, Any],
    trusted_recovery_plan: Mapping[str, Any] | None,
) -> list[str]:
    """Return ordered transaction-lock identities for shared accounting resources."""

    resources: set[str] = set()

    def add(model: str, identity: Any) -> None:
        resources.add(
            _digest(
                {
                    "purpose": "odoo_write_resource_lock_v1",
                    "company_id": company_id,
                    "model": model,
                    "identity": identity,
                }
            )
        )

    if capability_id == "acct.refund.create.v1":
        add("account.move", parameters.get("origin_move_id"))
    elif capability_id == "acct.payment.register.v1":
        for record_id in parameters.get("target_move_ids", []):
            add("account.move", record_id)
    elif capability_id == "acct.bank.statement_import.v1":
        journal_id = parameters.get("journal_id")
        add("account.journal.bank_statement_sequence", journal_id)
        add(
            "account.bank.statement.external_reference",
            [journal_id, parameters.get("external_reference")],
        )
        add(
            "account.bank.statement.source_digest",
            [journal_id, parameters.get("source_digest")],
        )
        for line in parameters.get("lines", []):
            add(
                "account.bank.statement.line.external_transaction_id",
                [journal_id, line.get("external_transaction_id")],
            )
            add(
                "account.bank.statement.line.source_line_digest",
                [journal_id, line.get("source_line_digest")],
            )
    elif capability_id == "acct.reconciliation.apply.v1":
        for record_id in parameters.get("line_ids", []):
            add("account.move.line", record_id)
    elif capability_id == "acct.asset.create.v1":
        add("account.move.line", parameters.get("source_move_line_id"))
    elif capability_id == "acct.depreciation.post.v1":
        add("account.asset", parameters.get("asset_id"))
        add("account.move", parameters.get("depreciation_move_id"))
    elif capability_id == "acct.deferred.create.v1":
        add("account.move.line", parameters.get("source_move_line_id"))
    elif capability_id == "acct.move.reverse.v1":
        add("account.move", parameters.get("move_id"))
    elif capability_id in {
        "acct.invoice.customer_create.v1",
        "acct.accrual.create.v1",
        "acct.period.adjustment_create.v1",
    }:
        add(
            "account.journal.reference",
            [parameters.get("journal_id"), parameters.get("reference")],
        )
    elif capability_id == "acct.bill.vendor_create.v1":
        add(
            "account.journal.vendor_reference",
            [parameters.get("journal_id"), parameters.get("vendor_reference")],
        )

    if capability_id == "acct.recovery.execute.v1" and trusted_recovery_plan:
        try:
            graph = index_recovery_guard_graph(
                trusted_recovery_plan, expected_company_id=company_id
            )
        except WriteReceiptError as exc:
            raise OdooWriteBootstrapError(
                "trusted recovery guard graph is invalid"
            ) from exc
        for model_name, record_id in graph:
            add(model_name, record_id)

    if len(resources) > 2000:
        raise OdooWriteBootstrapError("write request requires too many resource locks")
    return sorted(resources)


def _precheck_lock_targets(
    evidence: Mapping[str, Any], *, company_id: int, exclusive_before: bool = False
) -> list[tuple[str, list[int], bool]]:
    """Extract and validate persistent records bound by a live precheck."""

    details = evidence.get("handler_details")
    if not isinstance(details, Mapping):
        raise OdooWriteBootstrapError("live precheck handler details are invalid")
    targets: dict[tuple[str, int], tuple[str, bool]] = {}
    for field in ("before", "dependencies"):
        snapshots = details.get(field, [])
        if not isinstance(snapshots, list):
            raise OdooWriteBootstrapError(
                f"live precheck {field} snapshots are invalid"
            )
        for snapshot in snapshots:
            if not isinstance(snapshot, Mapping) or set(snapshot) != {
                "model",
                "record_id",
                "company_id",
                "state",
                "values",
                "values_digest",
            }:
                raise OdooWriteBootstrapError(
                    f"live precheck {field} snapshot is invalid"
                )
            model_name = snapshot["model"]
            record_id = snapshot["record_id"]
            values = snapshot["values"]
            values_digest = snapshot["values_digest"]
            if (
                not isinstance(model_name, str)
                or ODOO_MODEL.fullmatch(model_name) is None
                or isinstance(record_id, bool)
                or not isinstance(record_id, int)
                or record_id <= 0
                or snapshot["company_id"] != company_id
                or not isinstance(snapshot["state"], str)
                or not snapshot["state"].strip()
                or not isinstance(values, Mapping)
                or not isinstance(values_digest, str)
                or SHA256.fullmatch(values_digest) is None
                or not hmac.compare_digest(_digest(values), values_digest)
            ):
                raise OdooWriteBootstrapError(
                    f"live precheck {field} snapshot binding is invalid"
                )
            key = (model_name, record_id)
            strict_lock = exclusive_before and field == "before"
            prior = targets.get(key)
            if prior is None:
                targets[key] = (values_digest, strict_lock)
            elif not hmac.compare_digest(prior[0], values_digest):
                raise OdooWriteBootstrapError(
                    "live precheck duplicates a record with different evidence"
                )
            elif strict_lock and not prior[1]:
                targets[key] = (values_digest, True)
    if len(targets) > MAX_AUDIT_RECORDS:
        raise OdooWriteBootstrapError(
            "live precheck requires too many database row locks"
        )
    grouped: dict[tuple[str, bool], list[int]] = {}
    for (model_name, record_id), (_digest_value, strict_lock) in sorted(
        targets.items()
    ):
        grouped.setdefault((model_name, not strict_lock), []).append(record_id)
    return [
        (model_name, record_ids, allow_referencing)
        for (model_name, allow_referencing), record_ids in sorted(grouped.items())
    ]


def _lock_live_precheck_records(
    bound_env: Any,
    evidence: Mapping[str, Any],
    *,
    company_id: int,
    exclusive_before: bool = False,
) -> int:
    """Lock approved precheck records and clear every cached dependency value."""

    grouped = _precheck_lock_targets(
        evidence,
        company_id=company_id,
        exclusive_before=exclusive_before,
    )
    for model_name, record_ids, allow_referencing in grouped:
        model = bound_env[model_name]
        check_access_rights = getattr(model, "check_access_rights", None)
        if not callable(check_access_rights):
            raise OdooWriteBootstrapError(
                f"{model_name} cannot recheck read access before row locking"
            )
        check_access_rights("read")
        records = model.browse(record_ids).exists()
        if sorted(getattr(records, "ids", [])) != record_ids:
            raise OdooWriteBootstrapError(
                f"{model_name} precheck records changed before row locking"
            )
        check_access_rule = getattr(records, "check_access_rule", None)
        lock_for_update = getattr(records, "lock_for_update", None)
        invalidate_recordset = getattr(records, "invalidate_recordset", None)
        if not all(
            callable(method)
            for method in (check_access_rule, lock_for_update, invalidate_recordset)
        ):
            raise OdooWriteBootstrapError(
                f"{model_name} cannot enforce an auditable row lock"
            )
        check_access_rule("read")
        lock_for_update(allow_referencing=allow_referencing)
        invalidate_recordset()
    if grouped:
        invalidate_all = getattr(bound_env, "invalidate_all", None)
        if not callable(invalidate_all):
            raise OdooWriteBootstrapError(
                "bound Odoo environment cannot invalidate dependency caches"
            )
        invalidate_all()
    return sum(len(record_ids) for _model, record_ids, _allow in grouped)


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OdooWriteBootstrapError("write timestamp must include a timezone")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json_object(value: Any, label: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        result = dict(value)
    elif isinstance(value, str) and value:
        try:
            result = json.loads(value)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise OdooWriteBootstrapError(f"stored {label} is not JSON") from exc
    else:
        raise OdooWriteBootstrapError(f"stored {label} is missing")
    if not isinstance(result, dict) or canonical_json(result).decode("utf-8") != (
        canonical_json(result).decode("utf-8") if isinstance(value, Mapping) else value
    ):
        raise OdooWriteBootstrapError(f"stored {label} is not canonical JSON")
    return result


def _validate_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise OdooWriteBootstrapError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _capability(
    capabilities: tuple[Capability, ...],
    operation: Operation,
    context: RequestContext,
    capability_channel: str,
) -> Capability:
    if capability_channel not in CHANNELS:
        raise OdooWriteBootstrapError("capability channel is invalid")
    if context.environment == "production" and capability_channel == "staged":
        raise OdooWriteBootstrapError("staged writes cannot execute in production")
    matches = [item for item in capabilities if item.id == operation.capability_id]
    if len(matches) != 1:
        raise OdooWriteBootstrapError("write capability is unknown or duplicated")
    capability = matches[0]
    data = capability.data
    environment_field = (
        "enabled_environments" if capability_channel == "enabled" else "staged_environments"
    )
    if data["access"] != "write" or context.environment not in data.get(
        environment_field, []
    ):
        raise OdooWriteBootstrapError(
            "write capability is not available in the bound environment and channel"
        )
    validate_value(operation.parameters, data["input_schema"])
    validate_write_semantics(operation.capability_id, operation.parameters)
    if operation.parameters.get("company_id") != operation.company_id:
        raise OdooWriteBootstrapError("write parameter company binding mismatch")
    return capability


def _trusted_recovery_plan(
    value: Any,
    operation: Operation,
    context: RequestContext,
) -> dict[str, Any] | None:
    """Accept only the receipt-derived plan bound by the signed recovery operation."""

    is_recovery = operation.capability_id == "acct.recovery.execute.v1"
    if not is_recovery:
        if value is not None:
            raise OdooWriteBootstrapError(
                "trusted recovery plan must be null for non-recovery writes"
            )
        return None
    if not isinstance(value, Mapping) or not value:
        raise OdooWriteBootstrapError(
            "trusted recovery plan is required for recovery execution"
        )
    try:
        # Sever all caller-owned mutable references before the plan reaches a
        # handler.  Its digest is already bound by authentication and approval.
        plan = json.loads(canonical_json(value).decode("utf-8"))
        validate_executable_recovery_plan(plan)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OdooWriteBootstrapError("trusted recovery plan is invalid") from exc

    parameters = operation.parameters
    if (
        plan["origin_operation_id"] != parameters["origin_operation_id"]
        or plan["plan_digest"] != parameters["expected_recovery_plan_digest"]
        or operation.company_id != context.company_id
    ):
        raise OdooWriteBootstrapError(
            "trusted recovery plan origin, digest, or company binding mismatch"
        )
    try:
        index_recovery_guard_graph(
            plan, expected_company_id=operation.company_id
        )
    except WriteReceiptError as exc:
        raise OdooWriteBootstrapError(
            "trusted recovery plan graph is not uniquely company-bound"
        ) from exc
    return plan


def _assert_operation_context_binding(
    context: RequestContext,
    operation: Operation,
    *,
    actual_database_name: str,
    actual_database_uuid: str,
    odoo_instance_id: str,
    environment: str,
    expected_registry_digest: str,
    release_digest: str,
) -> None:
    bindings = (
        operation.principal == context.principal
        and operation.user_id == context.user_id
        and operation.company_id == context.company_id
        and operation.company_id in context.allowed_company_ids
        and operation.odoo_instance_id == context.odoo_instance_id == odoo_instance_id
        and operation.database_name == context.database_name == actual_database_name
        and operation.database_uuid == context.database_uuid == actual_database_uuid
        and operation.environment == context.environment == environment
        and operation.registry_digest == expected_registry_digest
        and operation.release_digest == release_digest
    )
    if not bindings:
        raise OdooWriteBootstrapError(
            "operation identity, company, database, environment, or release binding mismatch"
        )


def _approver_authorized(
    bound_env: Any, approver_user_id: int, company_id: int
) -> bool:
    try:
        approver = bound_env["res.users"].browse(approver_user_id).exists()
        return bool(
            approver
            and len(approver) == 1
            and approver.active
            and company_id in approver.company_ids.ids
            and approver.has_group(APPROVER_GROUP)
        )
    except (AttributeError, KeyError, TypeError):
        return False


def _verify_approval(
    operation: Operation,
    approval: Approval,
    *,
    bound_env: Any,
    capability: Capability,
    now: datetime,
    approval_secret: bytes,
    approval_key_id: str,
    enforce_current_approver_acl: bool,
    reconciliation_only: bool,
) -> bool:
    if operation.state != State.EXECUTING:
        raise OdooWriteBootstrapError("operation must be in the executing state")
    if operation.revision <= 0:
        raise OdooWriteBootstrapError("executing operation revision is invalid")
    approved = replace(
        operation,
        state=State.APPROVED,
        revision=operation.revision - 1,
    )
    validation_time = approval.issued_at if reconciliation_only else now
    try:
        candidate = begin_execution(
            approved,
            approval,
            now=validation_time,
            secret=approval_secret,
            expected_key_id=approval_key_id,
            is_approver_authorized=lambda user_id, company_id, _capability_id: (
                not enforce_current_approver_acl
                or _approver_authorized(bound_env, user_id, company_id)
            ),
            approval_ttl_seconds=capability.data["approval"]["ttl_seconds"],
            expected_revision=approved.revision,
        )
    except OperationError as exc:
        raise OdooWriteBootstrapError(str(exc)) from exc
    if candidate != operation:
        raise OdooWriteBootstrapError("approved operation binding changed")
    return now >= approval.expires_at


def _anchor_result_mapping(result: TrustedResult, operation: Operation) -> dict[str, Any]:
    payload = dict(result.payload())
    return {
        **payload,
        "capability_id": operation.capability_id,
        "registry_digest": operation.registry_digest,
        "release_digest": operation.release_digest,
        "signature": result.signature,
    }


def _trusted_from_anchor_mapping(
    value: Mapping[str, Any], operation: Operation
) -> TrustedResult:
    if set(value) != ANCHOR_RESULT_FIELDS:
        raise OdooWriteBootstrapError("stored result envelope fields are invalid")
    if (
        value["capability_id"] != operation.capability_id
        or value["registry_digest"] != operation.registry_digest
        or value["release_digest"] != operation.release_digest
    ):
        raise OdooWriteBootstrapError("stored result release binding mismatch")
    issued_at = value["issued_at"]
    if isinstance(issued_at, str) and issued_at.endswith("+00:00"):
        issued_at = f"{issued_at[:-6]}Z"
    return trusted_result_from_mapping(
        {
            "kind": value["kind"],
            "operation_id": value["operation_id"],
            "request_id": value["request_id"],
            "operation_digest": value["operation_digest"],
            "operation_state_digest": value["operation_state_digest"],
            "operation_revision": value["operation_revision"],
            "company_id": value["company_id"],
            "issuer": value["issuer"],
            "key_id": value["key_id"],
            "succeeded": value["succeeded"],
            "evidence_digest": value["evidence_digest"],
            "prior_evidence_digest": value["prior_evidence_digest"],
            "issued_at": issued_at,
            "signature_version": value["version"],
            "signature_purpose": value["purpose"],
            "signature": value["signature"],
        }
    )


def _stored_phase(
    anchor: ControlAnchor, phase: str, operation: Operation
) -> tuple[TrustedResult, dict[str, Any]]:
    evidence_json = getattr(anchor, f"{phase}_evidence_json", None)
    evidence_digest = _validate_digest(
        getattr(anchor, f"{phase}_evidence_digest", None),
        f"stored {phase} evidence digest",
    )
    result_json = getattr(anchor, f"{phase}_result_json", None)
    result_digest = _validate_digest(
        getattr(anchor, f"{phase}_result_digest", None),
        f"stored {phase} result digest",
    )
    evidence = _load_json_object(evidence_json, f"{phase} evidence")
    result_mapping = _load_json_object(result_json, f"{phase} result")
    if _digest(evidence) != evidence_digest or _digest(result_mapping) != result_digest:
        raise OdooWriteBootstrapError(f"stored {phase} digest mismatch")
    result = _trusted_from_anchor_mapping(result_mapping, operation)
    if not hmac.compare_digest(result.evidence_digest, evidence_digest):
        raise OdooWriteBootstrapError(f"stored {phase} evidence binding mismatch")
    return result, evidence


def _raw_snapshot(value: Any, company_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {
        "model",
        "record_id",
        "company_id",
        "state",
        "values",
        "values_digest",
    }:
        raise OdooWriteBootstrapError("handler snapshot must be an object")
    model = value.get("model")
    record_id = value.get("record_id")
    state = value.get("record_state", value.get("state", "unknown"))
    values = value.get("values", {})
    if (
        not isinstance(model, str)
        or not model
        or isinstance(record_id, bool)
        or not isinstance(record_id, int)
        or record_id <= 0
        or value.get("company_id") != company_id
        or not isinstance(state, str)
        or not state
        or not isinstance(values, dict)
        or not isinstance(value.get("values_digest"), str)
        or not hmac.compare_digest(value["values_digest"], _digest(values))
    ):
        raise OdooWriteBootstrapError("handler snapshot binding is invalid")
    if len(canonical_json(values).decode("utf-8")) > MAX_SNAPSHOT_VALUES_JSON_CHARS:
        raise OdooWriteBootstrapError(
            "handler snapshot exceeds the auditable values limit"
        )
    snapshot = create_record_snapshot(
        model=model,
        record_id=record_id,
        exists=True,
        record_state=state,
        values=values,
    )
    reference = {
        "model": model,
        "record_id": record_id,
        "company_id": company_id,
        "record_state": state,
        "record_fingerprint": _digest(snapshot),
    }
    return snapshot, reference


def _difference(
    before_values: Any, after_values: Any, company_id: int
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(before_values, list) or not isinstance(after_values, list):
        raise OdooWriteBootstrapError("handler before/after snapshots must be arrays")
    if (
        len(before_values) > MAX_AUDIT_RECORDS
        or len(after_values) > MAX_AUDIT_RECORDS
    ):
        raise OdooWriteBootstrapError(
            "handler snapshot graph exceeds the auditable record limit"
        )
    before_pairs = [_raw_snapshot(item, company_id) for item in before_values]
    after_pairs = [_raw_snapshot(item, company_id) for item in after_values]
    before_keys = [
        (item["model"], item["record_id"]) for item in before_values
    ]
    after_keys = [
        (item["model"], item["record_id"]) for item in after_values
    ]
    if len(before_keys) != len(set(before_keys)) or len(after_keys) != len(
        set(after_keys)
    ):
        raise OdooWriteBootstrapError("handler snapshots contain a duplicate record")
    omitted_after = set(before_keys) - set(after_keys)
    if omitted_after:
        raise OdooWriteBootstrapError(
            "handler after snapshots omitted a prechecked record; "
            "an explicit company-bound tombstone protocol is required"
        )
    keyed_before = {
        (item["model"], item["record_id"]): item for item in before_values
    }
    before = [item[0] for item in before_pairs]
    before.extend(
        create_record_snapshot(
            model=item["model"],
            record_id=item["record_id"],
            exists=False,
            record_state="absent",
            values={},
        )
        for item in after_values
        if (item["model"], item["record_id"]) not in keyed_before
    )
    after = [item[0] for item in after_pairs]
    references = [item[1] for item in after_pairs]
    changed: set[str] = set()
    for item in after_values:
        key = (item["model"], item["record_id"])
        previous = keyed_before.get(key)
        current_values = item.get("values", {})
        previous_values = previous.get("values", {}) if previous else {}
        changed.update(
            field
            for field in set(previous_values) | set(current_values)
            if _snapshot_field_changed(
                item["model"], field, previous_values, current_values
            )
        )
        if previous is None or previous.get("state") != item.get("state"):
            changed.add("record_state")
    return (
        create_difference(before=before, after=after, changed_fields=sorted(changed)),
        references,
    )


def _snapshot_field_changed(
    model_name: str,
    field: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> bool:
    if field not in before or field not in after:
        return True
    if before[field] == after[field]:
        return False
    if model_name == "account.move.line" and field == "move_id":
        # Odoo includes the parent move's derived display_name in Many2one
        # reads; changing draft -> cancel changes that label, not the relation.
        before_id = classic_read_many2one_id(before[field])
        after_id = classic_read_many2one_id(after[field])
        return before_id is None or before_id != after_id
    return True


def _empty_many2one(values: Mapping[str, Any], field: str) -> bool:
    return field not in values or values[field] is False


def _empty_x2many(values: Mapping[str, Any], field: str) -> bool:
    return field not in values or values[field] == []


def _assert_available_draft_customer_invoice_snapshot(
    operation: Operation,
    *,
    raw_action: Mapping[str, Any] | None,
    raw_by_key: Mapping[tuple[str, int], Mapping[str, Any]],
    action_identity: tuple[str, int],
    guard_identities: list[tuple[str, int]],
) -> None:
    action_values = raw_action.get("values") if raw_action else None
    required_action_fields = {
        "state",
        "move_type",
        "company_id",
        "journal_id",
        "currency_id",
        "partner_id",
        "line_ids",
        "auto_post",
        "posted_before",
        "secure_sequence_number",
        "inalterable_hash",
        "is_manually_modified",
        "payment_ids",
        "matched_payment_ids",
        "reconciled_payment_ids",
        "tax_cash_basis_created_move_ids",
        "reversal_move_ids",
        "adjusting_entry_origin_move_ids",
        "adjusting_entries_move_ids",
        "exchange_diff_partial_ids",
        "odoo_cli_v3_document_binding",
        "odoo_cli_v3_business_binding",
    }
    if (
        not isinstance(action_values, Mapping)
        or not required_action_fields.issubset(action_values)
        or raw_action.get("state") != "draft"
        or action_values.get("state") != "draft"
        or action_values.get("move_type") != "out_invoice"
        or classic_read_many2one_id(action_values.get("company_id"))
        != operation.company_id
        or classic_read_many2one_id(action_values.get("journal_id"))
        != operation.parameters.get("journal_id")
        or classic_read_many2one_id(action_values.get("currency_id"))
        != operation.parameters.get("currency_id")
        or classic_read_many2one_id(action_values.get("partner_id"))
        != operation.parameters.get("partner_id")
        or action_values.get("posted_before") is not False
        or action_values.get("auto_post") != "no"
        or action_values.get("secure_sequence_number") not in {False, 0}
        or action_values.get("inalterable_hash") is not False
        or action_values.get("is_manually_modified") is not False
        or action_values.get("odoo_cli_v3_document_binding")
        != customer_invoice_document_binding(operation.parameters)
        or action_values.get("odoo_cli_v3_business_binding")
        != customer_invoice_business_binding(operation.parameters)
    ):
        raise OdooWriteBootstrapError(
            "available recovery action is not a pristine V3 draft customer invoice"
        )
    singular_links = (
        "auto_post_origin_id",
        "origin_payment_id",
        "payment_id",
        "statement_line_id",
        "statement_id",
        "tax_cash_basis_rec_id",
        "tax_cash_basis_origin_move_id",
        "reversed_entry_id",
        "asset_id",
    )
    plural_links = (
        "payment_ids",
        "matched_payment_ids",
        "reconciled_payment_ids",
        "tax_cash_basis_created_move_ids",
        "reversal_move_ids",
        "adjusting_entry_origin_move_ids",
        "adjusting_entries_move_ids",
        "exchange_diff_partial_ids",
        "deferred_move_ids",
        "deferred_original_move_ids",
        "edi_document_ids",
        "expense_ids",
        "pos_order_ids",
    )
    if (
        action_values.get("need_cancel_request", False) is not False
        or any(
            not _empty_many2one(action_values, field)
            for field in singular_links
        )
        or any(
            not _empty_x2many(action_values, field)
            for field in plural_links
        )
    ):
        raise OdooWriteBootstrapError(
            "available recovery action has payment, posting, or external effects"
        )
    expected_line_ids = {identity[1] for identity in guard_identities}
    raw_line_ids = action_values.get("line_ids")
    if (
        not isinstance(raw_line_ids, list)
        or not raw_line_ids
        or any(
            isinstance(record_id, bool)
            or not isinstance(record_id, int)
            or record_id <= 0
            for record_id in raw_line_ids
        )
        or len(raw_line_ids) != len(set(raw_line_ids))
        or set(raw_line_ids) != expected_line_ids
    ):
        raise OdooWriteBootstrapError(
            "available recovery guards do not cover the complete line graph"
        )
    required_line_fields = {
        "move_id",
        "company_id",
        "reconciled",
        "full_reconcile_id",
        "matched_debit_ids",
        "matched_credit_ids",
        "display_type",
    }
    for identity in guard_identities:
        line_values = raw_by_key[identity].get("values")
        if (
            not isinstance(line_values, Mapping)
            or not required_line_fields.issubset(line_values)
            or classic_read_many2one_id(line_values.get("move_id"))
            != action_identity[1]
            or classic_read_many2one_id(line_values.get("company_id"))
            != operation.company_id
        ):
            raise OdooWriteBootstrapError(
                "available recovery guard is outside the invoice line graph"
            )
        if (
            line_values.get("reconciled") is not False
            or not _empty_many2one(line_values, "full_reconcile_id")
            or not _empty_many2one(line_values, "statement_line_id")
            or not _empty_many2one(line_values, "purchase_line_id")
            or not _empty_many2one(line_values, "expense_id")
            or not _empty_x2many(line_values, "matched_debit_ids")
            or not _empty_x2many(line_values, "matched_credit_ids")
            or not _empty_x2many(line_values, "asset_ids")
            or not _empty_x2many(line_values, "sale_line_ids")
            or line_values.get("deferred_start_date", False) is not False
            or line_values.get("deferred_end_date", False) is not False
            or line_values.get("display_type") == "cogs"
        ):
            raise OdooWriteBootstrapError(
                "available recovery guard graph has reconciliation or external effects"
            )


def _execution_evidence(
    operation: Operation, raw: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise OdooWriteBootstrapError("write handler returned no execution object")
    if (
        raw.get("capability_id") != operation.capability_id
        or raw.get("company_id") != operation.company_id
        or raw.get("parameters_digest") != _digest(operation.parameters)
    ):
        raise OdooWriteBootstrapError("write handler execution binding mismatch")
    raw_after = raw.get("after")
    difference, records = _difference(
        raw.get("before"), raw_after, operation.company_id
    )
    raw_records = raw.get("records")
    if not isinstance(raw_records, list) or {
        (item.get("model"), item.get("record_id"))
        for item in raw_records
        if isinstance(item, Mapping)
    } != {(item["model"], item["record_id"]) for item in records}:
        raise OdooWriteBootstrapError("write handler record receipt is inconsistent")
    recovery = raw.get("recovery")
    if not isinstance(recovery, Mapping):
        raise OdooWriteBootstrapError("write handler recovery result is invalid")
    status = recovery.get("status")
    method = recovery.get("method")
    targets = recovery.get("targets")
    if (
        status not in {"available", "not_applicable", "manual_escalation"}
        or not isinstance(method, str)
        or not method
        or not isinstance(targets, list)
    ):
        raise OdooWriteBootstrapError("write handler recovery result is invalid")
    by_key = {(item["model"], item["record_id"]): item for item in records}
    target_records: list[dict[str, Any]] = []
    for target in targets:
        if not isinstance(target, Mapping):
            raise OdooWriteBootstrapError("write recovery target is invalid")
        reference = by_key.get((target.get("model"), target.get("record_id")))
        if reference is None:
            raise OdooWriteBootstrapError("write recovery target was not read back")
        target_records.append(dict(reference))
    if status == "available":
        if (
            set(recovery) != {
                "status", "method", "targets", "guards", "oracle_id"
            }
            or operation.capability_id != "acct.invoice.customer_create.v1"
            or operation.environment != "sandbox"
            or operation.parameters.get("posting_mode") != "draft"
            or method != DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD
            or recovery.get("oracle_id")
            != DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE
        ):
            raise OdooWriteBootstrapError(
                "available recovery is restricted to a sandbox draft customer invoice"
            )
        guards = recovery.get("guards")
        if (
            len(target_records) != 1
            or target_records[0]["model"] != "account.move"
            or len(targets) != 1
            or not isinstance(targets[0], Mapping)
            or set(targets[0]) != {"model", "record_id"}
            or not isinstance(guards, list)
            or not guards
        ):
            raise OdooWriteBootstrapError(
                "available recovery requires one action and a complete line graph"
            )
        guard_records: list[dict[str, Any]] = []
        guard_identities: list[tuple[str, int]] = []
        for guard in guards:
            if (
                not isinstance(guard, Mapping)
                or set(guard) != {"model", "record_id"}
                or guard.get("model") != "account.move.line"
            ):
                raise OdooWriteBootstrapError(
                    "available recovery guard identity is invalid"
                )
            identity = (guard["model"], guard.get("record_id"))
            reference = by_key.get(identity)
            if reference is None:
                raise OdooWriteBootstrapError(
                    "available recovery guard was not read back"
                )
            guard_identities.append(identity)
            guard_records.append(
                {**reference, "expected_outcome": "survive_exact"}
            )
        if len(guard_identities) != len(set(guard_identities)):
            raise OdooWriteBootstrapError(
                "available recovery guard graph contains a duplicate"
            )
        action_identity = (
            target_records[0]["model"], target_records[0]["record_id"]
        )
        expected_graph = {action_identity, *guard_identities}
        if set(by_key) != expected_graph:
            raise OdooWriteBootstrapError(
                "available recovery guards do not cover the complete line graph"
            )
        raw_by_key = {
            (item["model"], item["record_id"]): item
            for item in raw_after
            if isinstance(item, Mapping)
        }
        raw_action = raw_by_key.get(action_identity)
        _assert_available_draft_customer_invoice_snapshot(
            operation,
            raw_action=raw_action,
            raw_by_key=raw_by_key,
            action_identity=action_identity,
            guard_identities=guard_identities,
        )
        ordered_guard_identities = sorted(guard_identities)
        recovery_parameters = {
            "company_id": operation.company_id,
            "origin_operation_id": operation.operation_id,
            "method": method,
            "action_targets": [
                {"model": action_identity[0], "record_id": action_identity[1]}
            ],
            "guard_records": [
                {"model": model_name, "record_id": record_id}
                for model_name, record_id in ordered_guard_identities
            ],
            "oracle_id": DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE,
        }
        plan = create_recovery_plan_v2(
            origin_operation_id=operation.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="available",
            method=method,
            requires_approval=True,
            action_targets=target_records,
            guard_records=guard_records,
            oracle_id=DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE,
            parameters=recovery_parameters,
        )
        return {
            "operation_id": operation.operation_id,
            "capability_id": operation.capability_id,
            "succeeded": True,
            "odoo_records": records,
            "difference": difference,
            "recovery_plan": plan,
            "recovery_parameters": recovery_parameters,
            "failure_checks": [],
        }
    guard_records = [
        {**item, "expected_outcome": "manual_review"}
        for item in target_records
    ]
    recovery_parameters = {
        "company_id": operation.company_id,
        "origin_operation_id": operation.operation_id,
        "method": method,
        "action_targets": [],
        "guard_records": [
            {"model": item["model"], "record_id": item["record_id"]}
            for item in guard_records
        ],
        "oracle_id": (
            "not_applicable" if status == "not_applicable" else "manual_escalation"
        ),
    }
    plan = create_recovery_plan_v2(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status=status,
        method=method,
        requires_approval=True,
        action_targets=[],
        guard_records=guard_records,
        oracle_id=recovery_parameters["oracle_id"],
        parameters=recovery_parameters,
    )
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": records,
        "difference": difference,
        "recovery_plan": plan,
        "recovery_parameters": recovery_parameters,
        "failure_checks": [],
    }


def _no_effect_failure_evidence(
    operation: Operation, check: str
) -> dict[str, Any]:
    recovery_parameters = {
        "company_id": operation.company_id,
        "origin_operation_id": operation.operation_id,
        "failure_check": check,
    }
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": False,
        "odoo_records": [],
        "difference": create_difference(before=[], after=[], changed_fields=[]),
        "recovery_plan": create_recovery_plan_v2(
            origin_operation_id=operation.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="manual_escalation",
            method="inspect_signed_failed_execution",
            requires_approval=True,
            action_targets=[],
            guard_records=[],
            oracle_id="manual_escalation",
            parameters=recovery_parameters,
        ),
        "recovery_parameters": recovery_parameters,
        "failure_checks": [check],
    }


def _failed_execution_evidence(
    operation: Operation, exception: Exception
) -> dict[str, Any]:
    return _no_effect_failure_evidence(
        operation, f"execution_exception:{type(exception).__name__}"
    )


def _verification_evidence(
    operation: Operation,
    execution_evidence: Mapping[str, Any],
    raw: Mapping[str, Any] | None,
    exception: Exception | None,
    *,
    expected_method: str,
    observed_at: datetime,
) -> dict[str, Any]:
    if not isinstance(expected_method, str) or not expected_method:
        raise OdooWriteBootstrapError("capability verification method is invalid")
    if exception is None:
        if not isinstance(raw, Mapping):
            raise OdooWriteBootstrapError("write verifier returned no result object")
        if set(raw) != {"passed", "method", "checks", "after", "evidence_digest"}:
            raise OdooWriteBootstrapError("write verification result fields are invalid")
        passed = raw.get("passed") is True
        engine_method = raw.get("method")
        checks = raw.get("checks")
        if (
            not passed
            or engine_method != "odoo_public_orm_readback_v1"
            or not isinstance(checks, list)
            or not checks
            or any(not isinstance(item, str) or not item for item in checks)
        ):
            raise OdooWriteBootstrapError("write verification result is invalid")
        normalized_checks = sorted(set(checks))
        raw_after = raw.get("after")
        if (
            not isinstance(raw_after, list)
            or not isinstance(raw.get("evidence_digest"), str)
            or not hmac.compare_digest(raw["evidence_digest"], _digest(raw_after))
        ):
            raise OdooWriteBootstrapError(
                "write verification snapshot digest is invalid"
            )
        fresh_pairs = [_raw_snapshot(item, operation.company_id) for item in raw_after]
        fresh_snapshots = [item[0] for item in fresh_pairs]
        fresh_records = [item[1] for item in fresh_pairs]
        if canonical_json(fresh_records) != canonical_json(
            execution_evidence["odoo_records"]
        ):
            raise OdooWriteBootstrapError(
                "fresh Odoo readback differs from committed execution records"
            )
    else:
        passed = False
        normalized_checks = [f"verification_exception:{type(exception).__name__}"]
        fresh_snapshots = []
        fresh_records = []
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "passed": passed,
        "method": expected_method,
        "checks": normalized_checks,
        "verified_at": _utc(observed_at),
        "readback": {
            "company_id": operation.company_id,
            "records": fresh_records,
            "fresh_snapshots": fresh_snapshots,
            "fresh_snapshots_digest": _digest(fresh_snapshots),
            "request_parameters_digest": _digest(operation.parameters),
            "control_anchor": {
                "operation_id": operation.operation_id,
                "capability_id": operation.capability_id,
                "company_id": operation.company_id,
                "state": "verified" if passed else "failed",
                "execution_evidence_digest": operation.execution_result_digest,
            },
        },
    }


def _response_part(result: TrustedResult, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "result": trusted_result_to_mapping(result),
        "evidence": json.loads(canonical_json(evidence)),
    }


def _record_execution(
    anchor: ControlAnchor,
    operation: Operation,
    evidence: dict[str, Any],
    *,
    succeeded: bool,
    now: datetime,
    issuer: str,
    key_id: str,
    secret: bytes,
) -> tuple[TrustedResult, Operation]:
    evidence_digest = _digest(evidence)
    result = sign_execution_result(
        operation=operation,
        issuer=issuer,
        key_id=key_id,
        succeeded=succeeded,
        evidence_digest=evidence_digest,
        issued_at=now,
        secret=secret,
    )
    accepted = record_execution_result(
        operation,
        result,
        now=now,
        secret=secret,
        expected_key_id=key_id,
        allowed_issuers=frozenset({issuer}),
        expected_revision=operation.revision,
    )
    anchor_mapping = _anchor_result_mapping(result, operation)
    anchor._record_execution(
        evidence=evidence,
        evidence_digest=evidence_digest,
        result=anchor_mapping,
        result_digest=_digest(anchor_mapping),
        succeeded=succeeded,
    )
    return result, accepted


def _record_no_effect_failure(
    root_env: Any,
    anchor: ControlAnchor,
    operation: Operation,
    *,
    check: str,
    now: datetime,
    issuer: str,
    key_id: str,
    secret: bytes,
) -> dict[str, Any]:
    evidence = _no_effect_failure_evidence(operation, check)
    with root_env.cr.savepoint():
        result, failed = _record_execution(
            anchor,
            operation,
            evidence,
            succeeded=False,
            now=now,
            issuer=issuer,
            key_id=key_id,
            secret=secret,
        )
    if failed.state != State.FAILED:
        raise OdooWriteBootstrapError("no-effect failure was not anchored")
    _commit(root_env)
    return {
        "execution": _response_part(result, evidence),
        "verification": None,
    }


def _record_verification(
    anchor: ControlAnchor,
    operation: Operation,
    evidence: dict[str, Any],
    *,
    now: datetime,
    issuer: str,
    key_id: str,
    secret: bytes,
    root_control_plane: bool = False,
) -> tuple[TrustedResult, Operation]:
    passed = evidence["passed"] is True
    evidence_digest = _digest(evidence)
    result = sign_verification_result(
        operation=operation,
        issuer=issuer,
        key_id=key_id,
        succeeded=passed,
        evidence_digest=evidence_digest,
        issued_at=now,
        secret=secret,
    )
    accepted = complete_operation(
        operation,
        result,
        now=now,
        secret=secret,
        expected_key_id=key_id,
        allowed_issuers=frozenset({issuer}),
        expected_revision=operation.revision,
    )
    anchor_mapping = _anchor_result_mapping(result, operation)
    record_verification = (
        anchor._record_committed_verification_from_root
        if root_control_plane
        else anchor._record_verification
    )
    record_verification(
        evidence=evidence,
        evidence_digest=evidence_digest,
        result=anchor_mapping,
        result_digest=_digest(anchor_mapping),
        passed=passed,
    )
    return result, accepted


def _commit(root_env: Any) -> None:
    root_env.cr.commit()


def _default_metadata_execution_scope() -> ContextManager[None]:
    """Load the private addon scope only inside an initialized Odoo registry."""

    try:
        module = importlib.import_module(METADATA_SCOPE_MODULE)
        factory = getattr(module, "_accounting_metadata_execution_scope")
    except (AttributeError, ImportError) as exc:
        raise OdooWriteBootstrapError(
            "trusted accounting metadata scope is unavailable"
        ) from exc
    if not callable(factory):
        raise OdooWriteBootstrapError(
            "trusted accounting metadata scope is unavailable"
        )
    scope = factory()
    if not hasattr(scope, "__enter__") or not hasattr(scope, "__exit__"):
        raise OdooWriteBootstrapError(
            "trusted accounting metadata scope is invalid"
        )
    return scope


def _default_handler_factory(
    bound_env: Any,
    context: RequestContext,
    observed_at: datetime,
    trusted_recovery_plan: Mapping[str, Any] | None,
) -> WriteHandler:
    from .write_handlers import OdooWriteContext, OdooWriteHandlers

    return OdooWriteHandlers(
        OdooWriteContext(
            env=bound_env,
            user_id=context.user_id,
            allowed_company_ids=context.allowed_company_ids,
            today=observed_at.date(),
            environment=context.environment,
            trusted_recovery_plan=trusted_recovery_plan,
        )
    )


def _handler_from_factory(
    handler_factory: Callable[..., WriteHandler] | None,
    bound_env: Any,
    context: RequestContext,
    observed_at: datetime,
    trusted_recovery_plan: Mapping[str, Any] | None,
) -> WriteHandler:
    if handler_factory is None:
        return _default_handler_factory(
            bound_env, context, observed_at, trusted_recovery_plan
        )
    # Existing non-recovery test/runtime factories have a three-argument
    # contract.  Only a recovery factory receives the additional trusted plan;
    # arity is selected from validated request content, never by swallowing a
    # TypeError raised inside the factory.
    if trusted_recovery_plan is None:
        return handler_factory(bound_env, context, observed_at)
    return handler_factory(
        bound_env, context, observed_at, trusted_recovery_plan
    )


def execute_write_from_odoo_shell(
    root_env: Any,
    request: Any,
    *,
    capabilities: Iterable[Capability],
    auth_secret: bytes,
    auth_key_id: str,
    approval_secret: bytes,
    approval_key_id: str,
    execution_secret: bytes,
    execution_key_id: str,
    execution_issuer: str,
    verification_secret: bytes,
    verification_key_id: str,
    verification_issuer: str,
    release_digest: str,
    odoo_instance_id: str,
    environment: str,
    capability_channel: str,
    now: datetime | None = None,
    clock: Callable[[], datetime] | None = None,
    environment_factory: Callable[[Any, int, dict[str, Any]], Any] | None = None,
    handler_factory: Callable[..., WriteHandler] | None = None,
    control_store_factory: Callable[[Any], ControlStore] | None = None,
    control_lookup_factory: Callable[[Any], ControlStore] | None = None,
    metadata_execution_scope_factory: Callable[[], ContextManager[Any]] | None = None,
) -> dict[str, Any]:
    """Execute, commit, read back, and durably anchor one approved write."""

    if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
        raise OdooWriteBootstrapError("write request fields are invalid")
    reconciliation_only = request["reconciliation_only"]
    if type(reconciliation_only) is not bool:
        raise OdooWriteBootstrapError("reconciliation_only must be a boolean")

    def approved_response(value: dict[str, Any]) -> dict[str, Any]:
        return {**value, "reconciliation_only": reconciliation_only}

    fixed_now = now
    metadata_scope_factory = (
        metadata_execution_scope_factory or _default_metadata_execution_scope
    )

    def phase_time() -> datetime:
        value = clock() if clock is not None else (
            fixed_now if fixed_now is not None else datetime.now(timezone.utc)
        )
        if value.tzinfo is None or value.utcoffset() is None:
            raise OdooWriteBootstrapError("current time must include a timezone")
        return value.astimezone(timezone.utc)

    observed_at = phase_time()
    capability_list = tuple(capabilities)
    expected_registry_digest = registry_digest(capability_list)
    _validate_digest(release_digest, "release digest")
    context = request_context_from_mapping(request["context"])
    operation = operation_from_mapping(request["operation"])
    approval = approval_from_mapping(request["approval"])
    operation.assert_integrity()
    if operation.state != State.EXECUTING:
        raise OdooWriteBootstrapError("operation must be in the executing state")
    actual_database_name = getattr(getattr(root_env, "cr", None), "dbname", None)
    actual_database_uuid = database_uuid(root_env)
    _assert_operation_context_binding(
        context,
        operation,
        actual_database_name=actual_database_name,
        actual_database_uuid=actual_database_uuid,
        odoo_instance_id=odoo_instance_id,
        environment=environment,
        expected_registry_digest=expected_registry_digest,
        release_digest=release_digest,
    )
    verify_request_context(
        context,
        now=observed_at,
        secret=auth_secret,
        expected_key_id=auth_key_id,
    )
    expected_request_digest = authentication_request_digest(
        operation.capability_id,
        approved_write_authentication_parameters(
            operation.parameters, reconciliation_only
        ),
    )
    if not hmac.compare_digest(
        context.auth_request_digest, expected_request_digest
    ):
        raise OdooWriteBootstrapError("authenticated write request digest mismatch")
    capability = _capability(
        capability_list, operation, context, capability_channel
    )
    trusted_recovery_plan = _trusted_recovery_plan(
        request["trusted_recovery_plan"], operation, context
    )
    scope = write_idempotency_scope(capability, operation.parameters)
    anchor_binding = {
        "operation_id": operation.operation_id,
        "request_id": operation.request_id,
        "capability_id": operation.capability_id,
        "idempotency_scope": scope,
        "operation_digest": operation.digest,
        "principal": operation.principal,
        "requester_id": operation.user_id,
        "approver_id": approval.approver_user_id,
        "company_id": operation.company_id,
        "environment": operation.environment,
        "capability_channel": capability_channel,
        "registry_digest": operation.registry_digest,
        "release_digest": operation.release_digest,
        "protocol_version": operation.protocol_version,
        "precheck_digest": operation.precheck_digest,
    }
    lookup_store = (
        control_lookup_factory(root_env)
        if control_lookup_factory is not None
        else root_env["odoo.accounting.cli.operation"]
    )
    existing_anchor = lookup_store._lookup_exact(**anchor_binding)
    existing_state = (
        getattr(existing_anchor, "state", None) if existing_anchor else None
    )
    if existing_state not in {None, "claimed", "committed", "verified", "failed"}:
        raise OdooWriteBootstrapError("operation anchor is not executable")
    durable_result_exists = existing_state in {"committed", "verified", "failed"}
    root_verification_finalize = existing_state == "committed"
    if reconciliation_only:
        if not durable_result_exists:
            raise OdooWriteBootstrapError(
                "reconciliation-only request has no committed durable anchor"
            )
    elif observed_at >= approval.expires_at:
        raise OdooWriteBootstrapError(
            "expired approval requires reconciliation-only authority"
        )
    bound_env = bind_non_superuser_environment(
        root_env, context, environment_factory=environment_factory
    )
    user = bound_env.user
    if not durable_result_exists and (
        not user.has_group(EXECUTOR_GROUP)
        or any(
            not user.has_group(xml_id)
            for xml_id in capability.data["odoo_permissions"]
        )
    ):
        raise OdooWriteBootstrapError("bound Odoo executor lacks capability ACL groups")
    approval_expired = _verify_approval(
        operation,
        approval,
        bound_env=bound_env,
        capability=capability,
        now=observed_at,
        approval_secret=approval_secret,
        approval_key_id=approval_key_id,
        enforce_current_approver_acl=not durable_result_exists,
        reconciliation_only=reconciliation_only,
    )
    if durable_result_exists:
        anchor = existing_anchor
    else:
        control_store = (
            control_store_factory(bound_env)
            if control_store_factory is not None
            else bound_env["odoo.accounting.cli.operation"]
        )
        anchor = control_store._claim(**anchor_binding)

    if anchor.state == "claimed":
        resource_locks = _resource_lock_digests(
            operation.capability_id,
            operation.company_id,
            operation.parameters,
            trusted_recovery_plan,
        )
        if resource_locks:
            anchor._acquire_resource_locks(resource_locks)

    if anchor.state == "claimed" and approval_expired:
        return approved_response(_record_no_effect_failure(
            root_env,
            anchor,
            operation,
            check="approval_expired_before_execution",
            now=observed_at,
            issuer=execution_issuer,
            key_id=execution_key_id,
            secret=execution_secret,
        ))

    execution_result: TrustedResult
    execution_evidence: dict[str, Any]
    verifying_operation: Operation
    if anchor.state in {"committed", "verified", "failed"}:
        execution_result, execution_evidence = _stored_phase(
            anchor, "execution", operation
        )
        if (
            execution_result.succeeded
            and execution_result.issued_at >= approval.expires_at
        ):
            raise OdooWriteBootstrapError(
                "stored execution was issued after approval expiry"
            )
        verifying_operation = record_execution_result(
            operation,
            execution_result,
            now=observed_at,
            secret=execution_secret,
            expected_key_id=execution_key_id,
            allowed_issuers=frozenset({execution_issuer}),
            expected_revision=operation.revision,
        )
        if not execution_result.succeeded:
            if anchor.state != "failed":
                raise OdooWriteBootstrapError("failed execution anchor state mismatch")
            return approved_response({
                "execution": _response_part(execution_result, execution_evidence),
                "verification": None,
            })
        if anchor.state in {"verified", "failed"}:
            verification_result, verification_evidence = _stored_phase(
                anchor, "verification", verifying_operation
            )
            final = complete_operation(
                verifying_operation,
                verification_result,
                now=observed_at,
                secret=verification_secret,
                expected_key_id=verification_key_id,
                allowed_issuers=frozenset({verification_issuer}),
                expected_revision=verifying_operation.revision,
            )
            expected_state = State.COMPLETED if anchor.state == "verified" else State.FAILED
            if final.state != expected_state:
                raise OdooWriteBootstrapError("verification anchor state mismatch")
            return approved_response({
                "execution": _response_part(execution_result, execution_evidence),
                "verification": _response_part(
                    verification_result, verification_evidence
                ),
            })
    elif anchor.state != "claimed":
        raise OdooWriteBootstrapError("operation anchor is not executable")
    else:
        handler = _handler_from_factory(
            handler_factory,
            bound_env,
            context,
            observed_at,
            trusted_recovery_plan,
        )
        try:
            live_precheck = run_rollback_only_precheck(
                root_env,
                lambda: canonical_precheck_evidence(
                    handler.precheck(
                        operation.capability_id, operation.parameters
                    ),
                    capability_id=operation.capability_id,
                    company_id=operation.company_id,
                    parameters=operation.parameters,
                    context=context,
                    actual_database_name=actual_database_name,
                    actual_database_uuid=actual_database_uuid,
                    capability_channel=capability_channel,
                    registry_sha256=expected_registry_digest,
                    release_digest=release_digest,
                ),
            )
        except Exception as exc:
            return approved_response(_record_no_effect_failure(
                root_env,
                anchor,
                operation,
                check=f"precheck_exception:{type(exc).__name__}",
                now=phase_time(),
                issuer=execution_issuer,
                key_id=execution_key_id,
                secret=execution_secret,
            ))
        if not hmac.compare_digest(
            _digest(live_precheck), operation.precheck_digest
        ):
            return approved_response(_record_no_effect_failure(
                root_env,
                anchor,
                operation,
                check="precheck_drift_before_execution",
                now=phase_time(),
                issuer=execution_issuer,
                key_id=execution_key_id,
                secret=execution_secret,
            ))
        try:
            locked_precheck_records = _lock_live_precheck_records(
                bound_env,
                live_precheck,
                company_id=operation.company_id,
                exclusive_before=(
                    operation.capability_id == "acct.recovery.execute.v1"
                ),
            )
        except Exception as exc:
            return approved_response(_record_no_effect_failure(
                root_env,
                anchor,
                operation,
                check=(
                    "precheck_dependency_lock_exception:"
                    f"{type(exc).__name__}"
                ),
                now=phase_time(),
                issuer=execution_issuer,
                key_id=execution_key_id,
                secret=execution_secret,
            ))
        if locked_precheck_records:
            try:
                locked_live_precheck = run_rollback_only_precheck(
                    root_env,
                    lambda: canonical_precheck_evidence(
                        handler.precheck(
                            operation.capability_id, operation.parameters
                        ),
                        capability_id=operation.capability_id,
                        company_id=operation.company_id,
                        parameters=operation.parameters,
                        context=context,
                        actual_database_name=actual_database_name,
                        actual_database_uuid=actual_database_uuid,
                        capability_channel=capability_channel,
                        registry_sha256=expected_registry_digest,
                        release_digest=release_digest,
                    ),
                )
            except Exception as exc:
                return approved_response(_record_no_effect_failure(
                    root_env,
                    anchor,
                    operation,
                    check=(
                        "precheck_after_dependency_lock_exception:"
                        f"{type(exc).__name__}"
                    ),
                    now=phase_time(),
                    issuer=execution_issuer,
                    key_id=execution_key_id,
                    secret=execution_secret,
                ))
            if not hmac.compare_digest(
                _digest(locked_live_precheck), operation.precheck_digest
            ):
                return approved_response(_record_no_effect_failure(
                    root_env,
                    anchor,
                    operation,
                    check="precheck_drift_after_dependency_lock",
                    now=phase_time(),
                    issuer=execution_issuer,
                    key_id=execution_key_id,
                    secret=execution_secret,
                ))
            live_precheck = locked_live_precheck
        execution_started_at = phase_time()
        if execution_started_at >= approval.expires_at:
            return approved_response(_record_no_effect_failure(
                root_env,
                anchor,
                operation,
                check="approval_expired_during_precheck",
                now=execution_started_at,
                issuer=execution_issuer,
                key_id=execution_key_id,
                secret=execution_secret,
            ))
        checked = {
            "capability_id": live_precheck["capability_id"],
            "company_id": live_precheck["company_id"],
            "parameters_digest": live_precheck["parameters_digest"],
            "checks": list(live_precheck["checks"]),
            **dict(live_precheck["handler_details"]),
        }
        try:
            with root_env.cr.savepoint():
                with metadata_scope_factory():
                    raw_execution = handler.execute_prechecked(
                        operation.capability_id,
                        operation.parameters,
                        checked,
                    )
                execution_evidence = _execution_evidence(
                    operation, raw_execution
                )
                execution_result, verifying_operation = _record_execution(
                    anchor,
                    operation,
                    execution_evidence,
                    succeeded=True,
                    now=execution_started_at,
                    issuer=execution_issuer,
                    key_id=execution_key_id,
                    secret=execution_secret,
                )
        except Exception as exc:
            execution_evidence = _failed_execution_evidence(operation, exc)
            with root_env.cr.savepoint():
                execution_result, failed = _record_execution(
                    anchor,
                    operation,
                    execution_evidence,
                    succeeded=False,
                    now=execution_started_at,
                    issuer=execution_issuer,
                    key_id=execution_key_id,
                    secret=execution_secret,
                )
            if failed.state != State.FAILED:
                raise OdooWriteBootstrapError("failed execution was not anchored")
            _commit(root_env)
            return approved_response({
                "execution": _response_part(execution_result, execution_evidence),
                "verification": None,
            })
        _commit(root_env)

    verification_started_at = phase_time()
    try:
        def verify_readback() -> tuple[dict[str, Any], datetime]:
            invalidate_all = getattr(bound_env, "invalidate_all", None)
            if not callable(invalidate_all):
                raise OdooWriteBootstrapError(
                    "bound Odoo environment cannot invalidate its read cache"
                )
            invalidate_all()
            verification_env = bind_non_superuser_environment(
                root_env,
                context,
                environment_factory=environment_factory,
            )
            handler = _handler_from_factory(
                handler_factory,
                verification_env,
                context,
                verification_started_at,
                trusted_recovery_plan,
            )
            raw_verification = handler.verify(
                operation.capability_id,
                operation.parameters,
                {
                    "capability_id": operation.capability_id,
                    "company_id": operation.company_id,
                    "parameters_digest": _digest(operation.parameters),
                    "records": [
                        {"model": item["model"], "record_id": item["record_id"]}
                        for item in execution_evidence["odoo_records"]
                    ],
                    "before": execution_evidence["difference"]["before"],
                },
            )
            verification_observed_at = phase_time()
            verification_evidence = _verification_evidence(
                verifying_operation,
                execution_evidence,
                raw_verification,
                None,
                expected_method=capability.data["verification"]["method"],
                observed_at=verification_observed_at,
            )
            return verification_evidence, verification_observed_at

        verification_evidence, verification_observed_at = (
            run_rollback_only_precheck(root_env, verify_readback)
        )
    except Exception as exc:
        verification_observed_at = phase_time()
        verification_evidence = _verification_evidence(
            verifying_operation,
            execution_evidence,
            None,
            exc,
            expected_method=capability.data["verification"]["method"],
            observed_at=verification_observed_at,
        )
    with root_env.cr.savepoint():
        verification_result, _final = _record_verification(
            anchor,
            verifying_operation,
            verification_evidence,
            now=verification_observed_at,
            issuer=verification_issuer,
            key_id=verification_key_id,
            secret=verification_secret,
            root_control_plane=root_verification_finalize,
        )
    _commit(root_env)
    return approved_response({
        "execution": _response_part(execution_result, execution_evidence),
        "verification": _response_part(
            verification_result, verification_evidence
        ),
    })

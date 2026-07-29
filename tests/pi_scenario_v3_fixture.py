from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from odoo_accounting_cli_v3.auth import (
    authentication_request_digest,
    context_payload,
    write_action_request_digest,
)
from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
)
from odoo_accounting_cli_v3.gateway import (
    AUTH_SIGNATURE_PURPOSE,
    AUTH_SIGNATURE_VERSION,
    WRITE_AUTH_SIGNATURE_PURPOSE,
    WRITE_AUTH_SIGNATURE_VERSION,
    RequestContext,
)
from odoo_accounting_cli_v3.operations import (
    ALLOWED_TRANSITIONS,
    Operation,
    State,
    canonical_json,
    record_precheck,
    sign_approval,
)
from odoo_accounting_cli_v3.pi_evidence import PiEvidenceTrust
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.registry import Capability
from odoo_accounting_cli_v3.trusted_response_verifier import (
    ReleaseReceiptVerificationConfig,
)
from odoo_accounting_cli_v3.write_protocol import (
    approval_to_mapping,
    operation_to_mapping,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_record_snapshot,
    create_recovery_plan,
    create_write_audit_receipt,
)


CAPTURED_AT = datetime(2026, 7, 17, 0, 1, tzinfo=timezone.utc)
TRACE_STARTED_AT = datetime(2026, 7, 17, 0, 0, tzinfo=timezone.utc)
TRACE_COMPLETED_AT = datetime(
    2026, 7, 17, 0, 0, 59, tzinfo=timezone.utc
)
DATABASE_UUID = "11111111-2222-4333-8444-555555555555"
READ_RECEIPT_SECRET = b"pi-scenario-read-receipt-secret-v3"
WRITE_RECEIPT_SECRET = b"pi-scenario-write-receipt-secret-v3"
APPROVAL_SECRET = b"pi-scenario-approval-secret-v3-000"
EFFECT_FINALIZER_SECRET = b"pi-scenario-effect-finalizer-v3-00"
READ_RECEIPT_KEY_ID = "pi-scenario-read-v3"
WRITE_RECEIPT_KEY_ID = "pi-scenario-write-v3"
APPROVAL_KEY_ID = "pi-scenario-approval-v3"
CAPABILITY_CHANNEL = "staged"
PRINCIPAL = "pi:xiaojing-test"
USER_ID = 42
APPROVER_USER_ID = 99
ODOO_INSTANCE_ID = "odoo19-test"
DATABASE_NAME = "odoo_v3_sandbox"


@dataclass(frozen=True)
class TrustedEvidenceBundle:
    evidence: dict[str, Any]
    result_body: dict[str, Any]
    result_digest: str
    verification_evidence: dict[str, Any]
    receipt_id: str
    operation_id: str | None
    tool_call_id: str
    executed_at: str
    verified_at: str
    receipt_issued_at: str


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _release_identity(
    *,
    package_sha256: str,
    manifest_sha256: str,
    registry_digest: str,
) -> dict[str, Any]:
    return {
        "commit": "test-pi-scenario-commit",
        "manifest_sha256": manifest_sha256,
        "package_sha256": package_sha256,
        "registry_digest": registry_digest,
        "release": "pi-scenario-v3-test",
        "verified": True,
        "version": "0.1.0.test",
    }


def build_evidence_trust(
    capabilities: tuple[Capability, ...],
    *,
    package_sha256: str,
    manifest_sha256: str,
    registry_digest: str,
) -> PiEvidenceTrust:
    receipt_config = ReleaseReceiptVerificationConfig(
        release_digest=manifest_sha256,
        registry_digest=registry_digest,
        capability_channel=CAPABILITY_CHANNEL,
        read_receipt_key_id=READ_RECEIPT_KEY_ID,
        read_receipt_secret=READ_RECEIPT_SECRET,
        write_receipt_key_id=WRITE_RECEIPT_KEY_ID,
        write_receipt_secret=WRITE_RECEIPT_SECRET,
    )
    approval_ttl_by_capability = {
        capability.id: capability.data["approval"].get("ttl_seconds", 900)
        for capability in capabilities
        if capability.data["access"] == "write"
    }
    return PiEvidenceTrust.from_release_config(
        receipt_config,
        release_identity=_release_identity(
            package_sha256=package_sha256,
            manifest_sha256=manifest_sha256,
            registry_digest=registry_digest,
        ),
        capabilities=capabilities,
        approval_key_id=APPROVAL_KEY_ID,
        approval_secret=APPROVAL_SECRET,
        approval_ttl_resolver=lambda operation: approval_ttl_by_capability[
            operation.capability_id
        ],
    )


def _request_context(
    action: str,
    unsigned: dict[str, Any],
    *,
    company_id: int,
) -> dict[str, Any]:
    if action == "read":
        request_digest = authentication_request_digest(
            unsigned["capability_id"], unsigned["parameters"]
        )
        signature_version = AUTH_SIGNATURE_VERSION
        signature_purpose = AUTH_SIGNATURE_PURPOSE
    else:
        request_digest = write_action_request_digest(action, unsigned)
        signature_version = WRITE_AUTH_SIGNATURE_VERSION
        signature_purpose = WRITE_AUTH_SIGNATURE_PURPOSE
    context = RequestContext(
        audience="odoo-accounting-cli-v3",
        auth_token_id=f"pi-scenario-auth-{company_id}",
        auth_issued_at=TRACE_STARTED_AT - timedelta(minutes=1),
        auth_expires_at=CAPTURED_AT + timedelta(minutes=4),
        auth_signature_version=signature_version,
        auth_signature_purpose=signature_purpose,
        auth_key_id="pi-scenario-request-auth-v3",
        auth_request_digest=request_digest,
        auth_signature=_digest(f"auth:{action}:{request_digest}"),
        principal=PRINCIPAL,
        odoo_instance_id=ODOO_INSTANCE_ID,
        database_name=DATABASE_NAME,
        database_uuid=DATABASE_UUID,
        user_id=USER_ID,
        company_id=company_id,
        allowed_company_ids=frozenset({company_id}),
        environment="sandbox",
    )
    return {
        **context_payload(context),
        "auth_signature": context.auth_signature,
    }


def _pi_result(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    response,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    indent=2,
                ),
            }
        ],
        "details": copy.deepcopy(response),
    }


def _raw_exchange(
    action: str,
    *,
    tool_name: str,
    tool_call_id: str,
    pi_arguments: dict[str, Any],
    request: dict[str, Any],
    response: dict[str, Any],
    operation_before: Operation | None,
    operation_after: Operation | None,
    occurred_at: datetime,
) -> dict[str, Any]:
    return {
        "action": action,
        "tool_name": tool_name,
        "tool_call_id": tool_call_id,
        "pi_arguments": copy.deepcopy(pi_arguments),
        "occurred_at": _timestamp(occurred_at),
        "broker_request": copy.deepcopy(request),
        "broker_dispatched_at": _timestamp(
            occurred_at + timedelta(milliseconds=10)
        ),
        "broker_response": copy.deepcopy(response),
        "broker_responded_at": _timestamp(
            occurred_at + timedelta(milliseconds=20)
        ),
        "pi_result": _pi_result(response),
        "tool_completed_at": _timestamp(
            occurred_at + timedelta(milliseconds=30)
        ),
        "operation_before": (
            None
            if operation_before is None
            else operation_to_mapping(operation_before)
        ),
        "operation_after": (
            None
            if operation_after is None
            else operation_to_mapping(operation_after)
        ),
    }


def _schema_without(schema: dict[str, Any], field: str) -> dict[str, Any]:
    trimmed = copy.deepcopy(schema)
    trimmed["properties"].pop(field)
    trimmed["required"] = [
        required for required in trimmed["required"] if required != field
    ]
    return trimmed


def _string_for_pattern(pattern: str, path: str, seed: int) -> str:
    digest = _digest(f"{path}:{seed}")
    known = {
        r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$": (
            "acct.test.read.v1"
        ),
        r"^[a-z0-9_]+\.[a-z0-9_]+$": "account.group_account_user",
        r"^[0-9a-f]{64}$": digest,
        r"^-?[0-9]+(?:\.[0-9]+)?$": str(seed),
        r"^[0-9]+(?:\.[0-9]+)?$": str(seed),
        r"^.*\S.*$": f"value-{seed}",
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$": "2026-07-17",
        r"^period-[0-9a-f]{64}$": f"period-{digest}",
        r"^(?:0\.(?:0*[1-9][0-9]*)|[1-9][0-9]*(?:\.[0-9]+)?)$": (
            "1"
        ),
        r"^line-[0-9a-f]{64}$": f"line-{digest}",
        r"^(?:0(?:\.[0-9]+)?|[1-9][0-9]*(?:\.[0-9]+)?)$": (
            str(seed)
        ),
        r"^-?(?:0(?:\.[0-9]+)?|[1-9][0-9]*(?:\.[0-9]+)?)$": (
            str(seed)
        ),
        r"^[a-z][a-z0-9_]*$": f"value_{seed}",
        r"^acct\.move\.draft_cancel\.v1$": (
            "acct.move.draft_cancel.v1"
        ),
        r"^odoo_pristine_v3_draft_cancel_eligibility_read$": (
            "odoo_pristine_v3_draft_cancel_eligibility_read"
        ),
        r"^[a-z0-9_]*$": f"value_{seed}",
        r"^(?:[0-9a-f]{64})?$": digest,
        r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$": f"value-{seed}",
        r"^[a-z][a-z0-9_.]{1,127}$": f"model.value_{seed}",
        r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$": f"state-{seed}",
        (
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        ): DATABASE_UUID,
        (
            r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
            r"[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
        ): "2026-07-17T00:00:40Z",
        r"^(?:\{.*\}|\[.*\])$": '{"value":1}',
        r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,255}$": f"field_{seed}",
        r"^[1-9][0-9]*$": str(max(1, seed)),
        r"^[a-z]+$": "value",
        r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$": f"value-{seed}",
        r"^write_audit_receipt_v1$": "write_audit_receipt_v1",
        r"^acct\.recovery\.execute\.v1$": "acct.recovery.execute.v1",
    }
    try:
        return known[pattern]
    except KeyError as exc:
        raise AssertionError(f"unsupported fixture schema pattern: {pattern}") from exc


def _schema_example(
    schema: dict[str, Any],
    *,
    path: str = "$",
    seed: int = 1,
) -> Any:
    if "oneOf" in schema:
        for option_index, option in enumerate(schema["oneOf"], start=1):
            candidate = _schema_example(
                option,
                path=f"{path}.oneOf[{option_index - 1}]",
                seed=seed + option_index,
            )
            try:
                validate_value(candidate, schema)
            except Exception:
                continue
            return candidate
        raise AssertionError(f"no deterministic fixture satisfies {path}.oneOf")

    if "enum" in schema:
        return copy.deepcopy(schema["enum"][0])

    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        choices = [choice for choice in schema_type if choice != "null"]
        schema_type = choices[0] if choices else "null"

    if schema_type == "null":
        return None
    if schema_type == "boolean":
        return True
    if schema_type == "integer":
        minimum = schema.get("minimum", 0)
        maximum = schema.get("maximum")
        value = max(minimum, seed)
        return min(value, maximum) if maximum is not None else value
    if schema_type == "string":
        if schema.get("format") == "date":
            return "2026-07-17"
        if schema.get("format") == "date-time":
            return "2026-07-17T00:00:40Z"
        if "pattern" in schema:
            return _string_for_pattern(schema["pattern"], path, seed)
        minimum = max(1, schema.get("minLength", 1))
        maximum = schema.get("maxLength", max(minimum, 32))
        value = f"value-{seed}"
        if len(value) < minimum:
            value += "x" * (minimum - len(value))
        return value[:maximum]
    if schema_type == "array":
        count = schema.get("minItems", 0)
        return [
            _schema_example(
                schema["items"],
                path=f"{path}[{index}]",
                seed=seed + index + 1,
            )
            for index in range(count)
        ]
    if schema_type == "object":
        properties = schema.get("properties", {})
        return {
            field: _schema_example(
                properties[field],
                path=f"{path}.{field}",
                seed=seed + index + 1,
            )
            for index, field in enumerate(schema.get("required", []))
        }
    raise AssertionError(f"unsupported fixture schema node at {path}: {schema}")


def _registry_body(
    capabilities: tuple[Capability, ...],
) -> dict[str, Any]:
    descriptors = []
    for capability in capabilities:
        data = capability.data
        contract_json = canonical_json(data).decode("utf-8")
        descriptors.append(
            {
                "id": data["id"],
                "domain": data["domain"],
                "business_description": data["business_description"],
                "access": data["access"],
                "risk_level": data["risk_level"],
                "company_scope": data["company_scope"],
                "odoo_permissions": data["odoo_permissions"],
                "approval_required": data["approval"]["required"],
                "idempotency_required": data["idempotency"]["required"],
                "input_schema_json": canonical_json(
                    data["input_schema"]
                ).decode("utf-8"),
                "output_schema_json": canonical_json(
                    data["output_schema"]
                ).decode("utf-8"),
                "contract_digest": hashlib.sha256(
                    contract_json.encode("utf-8")
                ).hexdigest(),
                "evidence_level": data["evidence"]["level"],
                "verification_method": data["verification"]["method"],
                "recovery_method": data["recovery"]["method"],
                "capability_channel": CAPABILITY_CHANNEL,
            }
        )
    descriptors.sort(key=lambda descriptor: descriptor["id"])
    return {
        "capabilities": descriptors,
        "page": {
            "count": len(descriptors),
            "total_count": len(descriptors),
        },
    }


def operation_digest_input_from_exchange(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    mapping = evidence["prepare_exchange"]["operation_after"]
    return {
        field: copy.deepcopy(mapping[field])
        for field in (
            "capability_id",
            "company_id",
            "database_name",
            "database_uuid",
            "environment",
            "idempotency_key",
            "odoo_instance_id",
            "parameters",
            "principal",
            "registry_digest",
            "release_digest",
            "user_id",
        )
    }


def _precheck(
    operation: Operation,
    *,
    scenario_id: str,
) -> dict[str, Any]:
    return {
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "parameters_digest": hashlib.sha256(
            canonical_json(operation.parameters)
        ).hexdigest(),
        "passed": True,
        "checks": [
            {
                "name": "odoo_acl_and_business_precheck",
                "passed": True,
            }
        ],
        "handler_details": {"scenario_id": scenario_id},
        "runtime_binding": {
            "user_id": operation.user_id,
            "odoo_instance_id": operation.odoo_instance_id,
            "database_name": operation.database_name,
            "database_uuid": operation.database_uuid,
            "environment": operation.environment,
            "capability_channel": CAPABILITY_CHANNEL,
        },
        "registry_digest": operation.registry_digest,
        "release_digest": operation.release_digest,
    }


def _awaiting_operation(
    prepared: Operation,
    *,
    scenario_id: str,
) -> tuple[Operation, dict[str, Any]]:
    precheck = _precheck(prepared, scenario_id=scenario_id)
    prechecked = record_precheck(
        prepared,
        precheck_digest=hashlib.sha256(canonical_json(precheck)).hexdigest(),
        expected_revision=prepared.revision,
    )
    return (
        prechecked.transition(
            State.AWAITING_APPROVAL,
            expected_revision=prechecked.revision,
        ),
        precheck,
    )


def _signed_terminal(
    awaiting: Operation,
    *,
    label: str,
    ttl_seconds: int,
    state: State = State.COMPLETED,
) -> tuple[Operation, Any]:
    challenge_issued_at = TRACE_STARTED_AT + timedelta(milliseconds=150)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=APPROVER_USER_ID,
        nonce=f"nonce-{label}",
        issued_at=TRACE_STARTED_AT + timedelta(milliseconds=200),
        expires_at=challenge_issued_at + timedelta(seconds=ttl_seconds),
        approval_ttl_seconds=ttl_seconds,
        key_id=APPROVAL_KEY_ID,
        secret=APPROVAL_SECRET,
    )
    terminal = replace(
        awaiting,
        state=state,
        revision=6,
        approval_signature=approval.signature,
        approval_nonce_digest=hashlib.sha256(
            approval.nonce.encode("utf-8")
        ).hexdigest(),
        approval_issued_at=approval.issued_at,
        approval_expires_at=approval.expires_at,
        approval_revision=approval.operation_revision,
        approver_user_id=approval.approver_user_id,
        execution_result_digest=_digest(f"execution:{label}"),
        verification_result_digest=_digest(f"verification:{label}"),
    )
    terminal.assert_integrity()
    return terminal, approval


def _operation_response(
    operation: Operation,
    *,
    next_action: str,
) -> dict[str, Any]:
    return {
        "operation_id": operation.operation_id,
        "operation_state": operation.state.value,
        "capability_id": operation.capability_id,
        "operation_revision": operation.revision,
        "operation_digest": operation.digest,
        "operation": operation_to_mapping(operation),
        "result_available": operation.state in {State.COMPLETED, State.FAILED},
        "next_action": next_action,
    }


def _preview_response(
    operation: Operation,
    precheck: dict[str, Any],
    capability: Capability,
) -> dict[str, Any]:
    data = capability.data
    challenge_issued_at = TRACE_STARTED_AT + timedelta(milliseconds=150)
    ttl_seconds = data["approval"]["ttl_seconds"]
    return {
        "command": "operation.preview",
        "data": {
            "operation_id": operation.operation_id,
            "operation_state": operation.state.value,
            "capability_id": operation.capability_id,
            "business_description": data["business_description"],
            "parameters": operation.parameters,
            "operation_digest": operation.digest,
            "precheck": copy.deepcopy(precheck),
            "precheck_identity": {
                "operation_id": operation.operation_id,
                "precheck_digest": operation.precheck_digest,
                "registry_digest": operation.registry_digest,
                "release_digest": operation.release_digest,
            },
            "precheck_digest": operation.precheck_digest,
            "risk_level": data["risk_level"],
            "approval": copy.deepcopy(data["approval"]),
            "recovery": copy.deepcopy(data["recovery"]),
            "approval_challenge": {
                "capability_id": operation.capability_id,
                "challenge_id": f"challenge-{operation.operation_id}",
                "company_id": operation.company_id,
                "expires_at": (
                    challenge_issued_at + timedelta(seconds=ttl_seconds)
                ).isoformat(),
                "issued_at": challenge_issued_at.isoformat(),
                "operation_digest": operation.digest,
                "operation_id": operation.operation_id,
                "precheck_digest": operation.precheck_digest,
                "requester_user_id": operation.user_id,
                "state": "pending",
            },
        },
        "ok": True,
    }


def _origin_operation(
    operation_id: str,
    *,
    company_id: int,
    manifest_sha256: str,
    registry_digest: str,
) -> Operation:
    parameters = {
        "company_id": company_id,
        "idempotency_key": f"origin-{_digest(operation_id)[:24]}",
        "posting_date": "2026-07-01",
        "reason": "failed period adjustment",
    }
    prepared = Operation.prepare(
        operation_id=operation_id,
        request_id=f"request-{_digest(operation_id)[:24]}",
        capability_id="acct.period.adjustment_create.v1",
        parameters=parameters,
        principal=PRINCIPAL,
        user_id=USER_ID,
        company_id=company_id,
        idempotency_key=parameters["idempotency_key"],
        odoo_instance_id=ODOO_INSTANCE_ID,
        database_name=DATABASE_NAME,
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest=registry_digest,
        release_digest=manifest_sha256,
    )
    awaiting, _precheck_body = _awaiting_operation(
        prepared,
        scenario_id="pi-v1-origin-failure",
    )
    terminal, _approval = _signed_terminal(
        awaiting,
        label=f"origin-{_digest(operation_id)[:16]}",
        ttl_seconds=600,
        state=State.FAILED,
    )
    return terminal


def _diagnostics_body(operation: Operation) -> dict[str, Any]:
    failure_digest = _digest(f"failure:{operation.operation_id}")
    return {
        "operation": {
            "operation_id": operation.operation_id,
            "capability_id": operation.capability_id,
            "company_id": operation.company_id,
            "state": operation.state.value,
            "revision": operation.revision,
            "terminal": True,
            "business_succeeded": False,
            "allowed_next_states": sorted(
                state.value for state in ALLOWED_TRANSITIONS[operation.state]
            ),
        },
        "audit": {
            "chain_verified": True,
            "event_count": 0,
            "event_types": [],
            "event_types_offset": 0,
            "event_types_truncated": False,
            "last_event_id": None,
            "last_event_hash": None,
            "global_head_hash": None,
        },
        "verification": {
            "trusted_terminal_result_verified": False,
            "passed": None,
            "method": None,
            "evidence_digest": None,
        },
        "failure": {
            "present": True,
            "stage": "verify",
            "result_id": f"failure-{_digest(operation.operation_id)[:16]}",
            "evidence_digest": failure_digest,
        },
        "recovery": {
            "lifecycle_status": "not_started",
            "available": True,
            "plan_status": "available",
            "plan_digest": _digest(f"recovery-plan:{operation.operation_id}"),
            "recovery_capability_id": "acct.recovery.execute.v1",
            "requires_approval": True,
            "attempt_count": 0,
            "latest_attempt_plan_digest": None,
            "bound_operation_ids": [],
            "completion_evidence_digest": None,
            "completion_receipt_body_digest": None,
            "completion_receipt_id": None,
        },
        "odoo_refs": [],
        "receipts": {
            "unique_final_receipt_verified": False,
            "current_candidate_count": 0,
            "durable_final_receipt_id": None,
            "durable_final_receipt_body_digest": None,
            "write_audit_receipt_id": None,
            "write_audit_result_digest": None,
            "write_audit_head": None,
            "difference_digest": None,
            "database_finalization_digest": None,
        },
        "page": {"count": 1, "total_count": 1},
    }


def _database_finalization(
    operation: Operation,
    *,
    verification_digest: str,
) -> dict[str, Any]:
    execution_digest = _digest(
        f"database-execution:{operation.operation_id}"
    )
    intent = EffectFinalizationIntent(
        database_name=operation.database_name,
        database_uuid=operation.database_uuid,
        operation_id=operation.operation_id,
        operation_digest=operation.digest,
        execution_result_digest=execution_digest,
        resolution_operation_id=operation.operation_id,
        resolution_operation_digest=operation.digest,
        resolution_execution_result_digest=execution_digest,
        resolution_result_digest=verification_digest,
        resolution_kind="verified",
    )
    request = EffectFinalizationRequest.from_intent(
        intent,
        verified_at=TRACE_STARTED_AT + timedelta(milliseconds=312),
        expires_at=TRACE_STARTED_AT + timedelta(minutes=3),
    )
    attestation = create_effect_attestation(
        request,
        key_id="pi-scenario-effect-finalizer-v3",
        secret=EFFECT_FINALIZER_SECRET,
    )
    return EffectFinalizationReceipt.from_database_mapping(
        {
            "receipt_attestation_id": attestation.attestation_id,
            "receipt_guard_installation_id": (
                "22222222-2222-4222-8222-222222222222"
            ),
            "receipt_database_oid": 16384,
            "receipt_database_uuid": operation.database_uuid,
            "resolved_operation_id": operation.operation_id,
            "receipt_resolution_operation_id": operation.operation_id,
            "applied_resolution_kind": "verified",
            "resolved_anchor_count": 1,
            "remaining_unresolved_count": 0,
            "guard_epoch": 0,
            "receipt_attestation_digest": attestation.attestation_digest,
            "finalized_at": _timestamp(
                TRACE_STARTED_AT + timedelta(milliseconds=316)
            ),
            "finalized_txid": "9123",
            "replayed": False,
        },
        request=request,
        attestation=attestation,
    ).evidence


def _write_verification_evidence(operation: Operation) -> dict[str, Any]:
    return {
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "operation_id": operation.operation_id,
        "passed": True,
    }


def _write_result_body(operation: Operation) -> dict[str, Any]:
    before = create_record_snapshot(
        model="account.move",
        record_id=880,
        exists=True,
        record_state="draft",
        values={"state": "draft", "amount_total": "125.50"},
    )
    after = create_record_snapshot(
        model="account.move",
        record_id=880,
        exists=True,
        record_state="posted",
        values={"state": "posted", "amount_total": "125.50"},
    )
    recovery_plan = create_recovery_plan(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="reverse_move",
        requires_approval=True,
        target_records=[
            {
                "model": "account.move",
                "record_id": 880,
                "company_id": operation.company_id,
                "record_state": "posted",
                "record_fingerprint": after["values_digest"],
            }
        ],
        parameters={
            "company_id": operation.company_id,
            "move_id": 880,
        },
    )
    verification_evidence = _write_verification_evidence(operation)
    verification_digest = hashlib.sha256(
        canonical_json(verification_evidence)
    ).hexdigest()
    return {
        "operation_id": operation.operation_id,
        "operation_state": operation.state.value,
        "odoo_records": [
            {
                "model": "account.move",
                "record_id": 880,
                "company_id": operation.company_id,
                "record_state": "posted",
                "record_fingerprint": after["values_digest"],
            }
        ],
        "difference": create_difference(
            before=[before],
            after=[after],
            changed_fields=["state"],
        ),
        "verification": {
            "method": "read_back_move",
            "passed": True,
            "checks": ["record_exists", "company_matches"],
            "evidence_digest": verification_digest,
            "verified_at": _timestamp(
                TRACE_STARTED_AT + timedelta(milliseconds=315)
            ),
        },
        "database_finalization": _database_finalization(
            operation,
            verification_digest=verification_digest,
        ),
        "recovery_plan": recovery_plan,
    }


class PiScenarioEvidenceFactory:
    def __init__(
        self,
        capabilities: tuple[Capability, ...],
        *,
        package_sha256: str,
        manifest_sha256: str,
        registry_digest: str,
    ) -> None:
        self.capabilities = capabilities
        self.by_id = {
            capability.id: capability for capability in capabilities
        }
        self.package_sha256 = package_sha256
        self.manifest_sha256 = manifest_sha256
        self.registry_digest = registry_digest
        self.identity = _release_identity(
            package_sha256=package_sha256,
            manifest_sha256=manifest_sha256,
            registry_digest=registry_digest,
        )
        self.receipt_config = ReleaseReceiptVerificationConfig(
            release_digest=manifest_sha256,
            registry_digest=registry_digest,
            capability_channel=CAPABILITY_CHANNEL,
            read_receipt_key_id=READ_RECEIPT_KEY_ID,
            read_receipt_secret=READ_RECEIPT_SECRET,
            write_receipt_key_id=WRITE_RECEIPT_KEY_ID,
            write_receipt_secret=WRITE_RECEIPT_SECRET,
        )
        self.trust = build_evidence_trust(
            capabilities,
            package_sha256=package_sha256,
            manifest_sha256=manifest_sha256,
            registry_digest=registry_digest,
        )

    @staticmethod
    def _company_id(parameters: dict[str, Any]) -> int:
        company_id = parameters.get("company_id")
        if type(company_id) is int and company_id > 0:
            return company_id
        company_ids = parameters.get("company_ids")
        if (
            isinstance(company_ids, list)
            and company_ids
            and type(company_ids[0]) is int
        ):
            return company_ids[0]
        raise AssertionError("scenario fixture has no signed company binding")

    def build(
        self,
        *,
        index: int,
        scenario_id: str,
        capability_id: str,
        parameters: dict[str, Any],
        registry_empty: bool = False,
    ) -> TrustedEvidenceBundle:
        capability = self.by_id[capability_id]
        if capability.data["access"] == "read":
            return self._build_read(
                index=index,
                scenario_id=scenario_id,
                capability=capability,
                parameters=parameters,
                registry_empty=registry_empty,
            )
        return self._build_write(
            index=index,
            scenario_id=scenario_id,
            capability=capability,
            parameters=parameters,
        )

    def _read_receipt(
        self,
        *,
        receipt_id: str,
        capability_id: str,
        parameters: dict[str, Any],
        body: dict[str, Any],
        request: dict[str, Any],
        record_count: int,
    ) -> dict[str, Any]:
        return create_read_receipt(
            receipt_id=receipt_id,
            capability_id=capability_id,
            parameters=parameters,
            result_body=body,
            auth_token_id=request["context"]["auth_token_id"],
            principal=request["context"]["principal"],
            odoo_instance_id=request["context"]["odoo_instance_id"],
            database_name=request["context"]["database_name"],
            database_uuid=request["context"]["database_uuid"],
            company_id=request["context"]["company_id"],
            user_id=request["context"]["user_id"],
            registry_digest=self.registry_digest,
            release_digest=self.manifest_sha256,
            environment=request["context"]["environment"],
            capability_channel=CAPABILITY_CHANNEL,
            record_count=record_count,
            observed_at=TRACE_STARTED_AT + timedelta(milliseconds=315),
            key_id=READ_RECEIPT_KEY_ID,
            secret=READ_RECEIPT_SECRET,
        )

    def _build_read(
        self,
        *,
        index: int,
        scenario_id: str,
        capability: Capability,
        parameters: dict[str, Any],
        registry_empty: bool,
    ) -> TrustedEvidenceBundle:
        company_id = self._company_id(parameters)
        capability_id = capability.id
        receipt_id = f"read-receipt-{index:03d}"
        tool_call_id = f"tool-call-{index:03d}"
        action = "read"
        tool_name = "odoo_v3_read"
        receipt_parameters = copy.deepcopy(parameters)

        if capability_id == "acct.registry.list.v1":
            pi_arguments: dict[str, Any] = {}
            receipt_parameters = {}
            unsigned = {
                "capability_id": capability_id,
                "parameters": {},
            }
            request = {
                "context": _request_context(
                    "read", unsigned, company_id=company_id
                ),
                **unsigned,
            }
            body = (
                {
                    "capabilities": [],
                    "page": {"count": 0, "total_count": 0},
                }
                if registry_empty
                else _registry_body(self.capabilities)
            )
            tool_name = "odoo_v3_capability_list"
            response_kind = "read"
        elif capability_id == "acct.diagnostics.operation_read.v1":
            action = "operation.diagnostics"
            tool_name = "odoo_v3_operation_diagnostics"
            origin = _origin_operation(
                parameters["operation_id"],
                company_id=company_id,
                manifest_sha256=self.manifest_sha256,
                registry_digest=self.registry_digest,
            )
            pi_arguments = {
                "company_id": company_id,
                "operation_id": parameters["operation_id"],
            }
            unsigned = copy.deepcopy(pi_arguments)
            request = {
                "context": _request_context(
                    action, unsigned, company_id=company_id
                ),
                **unsigned,
            }
            body = _diagnostics_body(origin)
            response_kind = "diagnostics"
        else:
            pi_arguments = {
                "capability_id": capability_id,
                "parameters": copy.deepcopy(parameters),
            }
            unsigned = copy.deepcopy(pi_arguments)
            request = {
                "context": _request_context(
                    "read", unsigned, company_id=company_id
                ),
                **unsigned,
            }
            body_schema = _schema_without(
                capability.data["output_schema"], "receipt"
            )
            body = _schema_example(
                body_schema,
                path=f"$.{capability_id}",
                seed=index,
            )
            if isinstance(body.get("page"), dict):
                count = next(
                    (
                        len(value)
                        for key, value in body.items()
                        if key != "page" and isinstance(value, list)
                    ),
                    body["page"].get("count", 0),
                )
                count = max(
                    count,
                    body["page"].get("count", 0),
                    body["page"].get("total_count", 0),
                )
                body["page"]["count"] = count
                body["page"]["total_count"] = count
            response_kind = "read"

        record_count = body.get("page", {}).get("total_count", 0)
        receipt = self._read_receipt(
            receipt_id=receipt_id,
            capability_id=capability_id,
            parameters=receipt_parameters,
            body=body,
            request=request,
            record_count=record_count,
        )
        complete_result = {**copy.deepcopy(body), "receipt": receipt}
        validate_value(complete_result, capability.data["output_schema"])
        if response_kind == "diagnostics":
            response = {
                "command": action,
                "data": complete_result,
                "ok": True,
            }
            operation_before = origin
        else:
            response = {
                "command": "read",
                "data": {
                    "capability_id": capability_id,
                    "release_identity": copy.deepcopy(self.identity),
                    "result": complete_result,
                    "runtime": {
                        "instance_id": ODOO_INSTANCE_ID,
                        "environment": "sandbox",
                        "capability_channel": CAPABILITY_CHANNEL,
                        "database_name": DATABASE_NAME,
                        "database_uuid": DATABASE_UUID,
                    },
                },
                "ok": True,
            }
            operation_before = None
        occurred_at = TRACE_STARTED_AT + timedelta(milliseconds=300)
        evidence = {
            "read_exchange": _raw_exchange(
                action,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                pi_arguments=pi_arguments,
                request=request,
                response=response,
                operation_before=operation_before,
                operation_after=None,
                occurred_at=occurred_at,
            )
        }
        verification_evidence = {
            "scope": "authenticated_odoo_response",
            "capability_id": receipt["capability_id"],
            "receipt_id": receipt["id"],
            "result_digest": receipt["result_digest"],
            "output_schema_verified": True,
            "response_signature_verified": True,
        }
        return TrustedEvidenceBundle(
            evidence=evidence,
            result_body=copy.deepcopy(body),
            result_digest=receipt["result_digest"],
            verification_evidence=verification_evidence,
            receipt_id=receipt_id,
            operation_id=None,
            tool_call_id=tool_call_id,
            executed_at=_timestamp(occurred_at + timedelta(milliseconds=10)),
            verified_at=_timestamp(
                TRACE_STARTED_AT + timedelta(milliseconds=315)
            ),
            receipt_issued_at=receipt["observed_at"],
        )

    def _build_write(
        self,
        *,
        index: int,
        scenario_id: str,
        capability: Capability,
        parameters: dict[str, Any],
    ) -> TrustedEvidenceBundle:
        company_id = self._company_id(parameters)
        operation_id = f"operation-{index:03d}"
        request_id = f"request-{index:03d}"
        prepared = Operation.prepare(
            operation_id=operation_id,
            request_id=request_id,
            capability_id=capability.id,
            parameters=parameters,
            principal=PRINCIPAL,
            user_id=USER_ID,
            company_id=company_id,
            idempotency_key=parameters["idempotency_key"],
            odoo_instance_id=ODOO_INSTANCE_ID,
            database_name=DATABASE_NAME,
            database_uuid=DATABASE_UUID,
            environment="sandbox",
            registry_digest=self.registry_digest,
            release_digest=self.manifest_sha256,
        )
        awaiting, precheck = _awaiting_operation(
            prepared,
            scenario_id=scenario_id,
        )
        terminal, approval = _signed_terminal(
            awaiting,
            label=operation_id,
            ttl_seconds=capability.data["approval"]["ttl_seconds"],
        )

        if capability.id == "acct.recovery.execute.v1":
            origin = _origin_operation(
                parameters["origin_operation_id"],
                company_id=company_id,
                manifest_sha256=self.manifest_sha256,
                registry_digest=self.registry_digest,
            )
            prepare_action = "operation.recover"
            prepare_tool = "odoo_v3_operation_recover"
            prepare_pi_arguments = {
                "origin_operation_id": parameters["origin_operation_id"],
                "recovery_date": parameters["recovery_date"],
                "reason": parameters["reason"],
                "idempotency_key": parameters["idempotency_key"],
            }
            prepare_unsigned = {
                "origin_operation_id": parameters["origin_operation_id"],
                "expected_origin_revision": origin.revision,
                "recovery_operation_id": prepared.operation_id,
                "request_id": prepared.request_id,
                "recovery_date": parameters["recovery_date"],
                "reason": parameters["reason"],
                "idempotency_key": parameters["idempotency_key"],
            }
            prepare_response_data = {
                **_operation_response(
                    prepared, next_action="operation.preview"
                ),
                "origin_operation_id": origin.operation_id,
                "origin_operation_revision": origin.revision,
                "recovery_plan_digest": parameters[
                    "expected_recovery_plan_digest"
                ],
            }
            operation_before = origin
        else:
            prepare_action = "operation.prepare"
            prepare_tool = "odoo_v3_operation_prepare"
            prepare_pi_arguments = {
                "capability_id": capability.id,
                "parameters": copy.deepcopy(parameters),
            }
            prepare_unsigned = {
                "operation_id": prepared.operation_id,
                "request_id": prepared.request_id,
                "capability_id": prepared.capability_id,
                "parameters": prepared.parameters,
            }
            prepare_response_data = _operation_response(
                prepared, next_action="operation.preview"
            )
            operation_before = None
        prepare_request = {
            "context": _request_context(
                prepare_action,
                prepare_unsigned,
                company_id=company_id,
            ),
            **prepare_unsigned,
        }
        prepare_response = {
            "command": prepare_action,
            "data": prepare_response_data,
            "ok": True,
        }

        preview_unsigned = {"operation_id": awaiting.operation_id}
        preview_request = {
            "context": _request_context(
                "operation.preview",
                preview_unsigned,
                company_id=company_id,
            ),
            **preview_unsigned,
        }
        preview_response = _preview_response(
            awaiting, precheck, capability
        )

        execute_unsigned = {
            "operation_id": terminal.operation_id,
            "approval": approval_to_mapping(approval),
            "reconciliation_only": False,
        }
        execute_request = {
            "context": _request_context(
                "operation.approve_execute",
                execute_unsigned,
                company_id=company_id,
            ),
            **execute_unsigned,
        }
        result_body = _write_result_body(terminal)
        receipt_id = f"write-receipt-{index:03d}"
        receipt = create_write_audit_receipt(
            receipt_id=receipt_id,
            request_id=terminal.request_id,
            operation_id=terminal.operation_id,
            capability_id=terminal.capability_id,
            principal=terminal.principal,
            odoo_instance_id=terminal.odoo_instance_id,
            database_name=terminal.database_name,
            database_uuid=terminal.database_uuid,
            user_id=terminal.user_id,
            approver_user_id=terminal.approver_user_id,
            company_id=terminal.company_id,
            environment=terminal.environment,
            capability_channel=CAPABILITY_CHANNEL,
            request_digest=authentication_request_digest(
                terminal.capability_id, terminal.parameters
            ),
            operation_digest=terminal.digest,
            approval_digest=terminal.approval_signature,
            registry_digest=self.registry_digest,
            release_digest=self.manifest_sha256,
            audit_head=_digest(f"audit-head:{operation_id}"),
            result_body=result_body,
            issued_at=TRACE_STARTED_AT + timedelta(milliseconds=318),
            signing_key_id=WRITE_RECEIPT_KEY_ID,
            secret=WRITE_RECEIPT_SECRET,
        )
        complete_result = {
            **copy.deepcopy(result_body),
            "audit_receipt": receipt,
        }
        validate_value(complete_result, capability.data["output_schema"])
        execute_response = {
            "business_succeeded": True,
            "command": "operation.approve_execute",
            "data": complete_result,
            "ok": True,
        }

        final_tool_call_id = f"tool-call-{index:03d}"
        evidence = {
            "prepare_exchange": _raw_exchange(
                prepare_action,
                tool_name=prepare_tool,
                tool_call_id=f"{final_tool_call_id}-prepare",
                pi_arguments=prepare_pi_arguments,
                request=prepare_request,
                response=prepare_response,
                operation_before=operation_before,
                operation_after=prepared,
                occurred_at=TRACE_STARTED_AT
                + timedelta(milliseconds=20),
            ),
            "preview_exchange": _raw_exchange(
                "operation.preview",
                tool_name="odoo_v3_operation_preview",
                tool_call_id=f"{final_tool_call_id}-preview",
                pi_arguments={"operation_id": awaiting.operation_id},
                request=preview_request,
                response=preview_response,
                operation_before=prepared,
                operation_after=awaiting,
                occurred_at=TRACE_STARTED_AT
                + timedelta(milliseconds=140),
            ),
            "approve_execute_exchange": _raw_exchange(
                "operation.approve_execute",
                tool_name="odoo_v3_operation_approve_execute",
                tool_call_id=final_tool_call_id,
                pi_arguments={"operation_id": terminal.operation_id},
                request=execute_request,
                response=execute_response,
                operation_before=awaiting,
                operation_after=terminal,
                occurred_at=TRACE_STARTED_AT
                + timedelta(milliseconds=300),
            ),
        }
        return TrustedEvidenceBundle(
            evidence=evidence,
            result_body=copy.deepcopy(result_body),
            result_digest=receipt["result_digest"],
            verification_evidence=_write_verification_evidence(terminal),
            receipt_id=receipt_id,
            operation_id=operation_id,
            tool_call_id=final_tool_call_id,
            executed_at=_timestamp(
                TRACE_STARTED_AT + timedelta(milliseconds=310)
            ),
            verified_at=_timestamp(
                TRACE_STARTED_AT + timedelta(milliseconds=315)
            ),
            receipt_issued_at=receipt["issued_at"],
        )


__all__ = [
    "CAPTURED_AT",
    "TRACE_COMPLETED_AT",
    "TRACE_STARTED_AT",
    "PiScenarioEvidenceFactory",
    "TrustedEvidenceBundle",
    "build_evidence_trust",
    "operation_digest_input_from_exchange",
]

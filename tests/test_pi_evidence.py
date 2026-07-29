from __future__ import annotations

import copy
import hashlib
import json
import pickle
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.auth import authentication_request_digest
from odoo_accounting_cli_v3.operations import (
    State,
    canonical_json,
    record_precheck,
    sign_approval,
)
from odoo_accounting_cli_v3.pi_evidence import (
    PiEvidenceError,
    PiEvidenceTrust,
    PiEvidenceUniquenessState,
    PiEvidenceVerifier,
)
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.registry import Capability, load_registry
from odoo_accounting_cli_v3.verified_release import VerifiedReleaseRoute
from odoo_accounting_cli_v3.write_protocol import (
    operation_to_mapping,
)
from odoo_accounting_cli_v3.write_runtime import WriteRuntimeSecrets
from odoo_accounting_cli_v3.write_receipts import (
    create_write_audit_receipt,
)
from test_trusted_response_verifier import (
    APPROVAL_SECRET,
    NOW,
    READ_SECRET,
    REGISTRY,
    RELEASE,
    WRITE_SECRET,
    awaiting_operation,
    config,
    context_mapping,
    diagnostics_exchange,
    operation_response,
    prepared_operation,
    read_exchange,
    terminal_exchange,
    terminal_operation,
)


_TOOLS = {
    "read": "odoo_v3_read",
    "operation.prepare": "odoo_v3_operation_prepare",
    "operation.preview": "odoo_v3_operation_preview",
    "operation.approve_execute": "odoo_v3_operation_approve_execute",
    "operation.diagnostics": "odoo_v3_operation_diagnostics",
    "operation.recover": "odoo_v3_operation_recover",
}

_REAL_CAPABILITIES = {
    capability.id: capability
    for capability in load_registry(
        Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
    )
}
_PREVIEW_OCCURRED_AT = NOW - timedelta(minutes=2)
_CHALLENGE_ISSUED_AT = _PREVIEW_OCCURRED_AT + timedelta(seconds=1)
_WRITE_CHALLENGE_EXPIRES_AT = _CHALLENGE_ISSUED_AT + timedelta(
    seconds=900
)
_RECOVERY_CHALLENGE_EXPIRES_AT = _CHALLENGE_ISSUED_AT + timedelta(
    seconds=600
)

_READ_SCHEMA = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "move_id": {"type": "integer", "minimum": 1},
                    "residual": {"type": "string"},
                },
                "required": ["move_id", "residual"],
                "additionalProperties": False,
            },
        },
        "page": {
            "type": "object",
            "properties": {
                "count": {"type": "integer", "minimum": 0},
                "total_count": {"type": "integer", "minimum": 0},
            },
            "required": ["count", "total_count"],
            "additionalProperties": False,
        },
        "receipt": {"type": "object"},
    },
    "required": ["items", "page", "receipt"],
    "additionalProperties": False,
}

_WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "operation_id": {"type": "string"},
        "operation_state": {
            "type": "string",
            "enum": ["completed", "failed"],
        },
        "odoo_records": {"type": "array"},
        "difference": {"type": "object"},
        "verification": {"type": "object"},
        "database_finalization": {"type": ["object", "null"]},
        "audit_receipt": {"type": "object"},
        "recovery_plan": {"type": "object"},
    },
    "required": [
        "operation_id",
        "operation_state",
        "odoo_records",
        "difference",
        "verification",
        "database_finalization",
        "audit_receipt",
        "recovery_plan",
    ],
    "additionalProperties": False,
}


def _capability(
    capability_id: str,
    *,
    access: str,
    output_schema: dict,
) -> Capability:
    approval = (
        {"required": False}
        if access == "read"
        else {"required": True, "policy": "independent", "ttl_seconds": 900}
    )
    document = {
        "id": capability_id,
        "access": access,
        "approval": approval,
        "output_schema": output_schema,
    }
    if access == "write":
        document.update(
            {
                "business_description": (
                    "Create and post a customer invoice"
                ),
                "risk_level": "critical",
                "recovery": {"method": "reverse_move"},
            }
        )
    return Capability.from_dict(document)


def _identity() -> dict:
    _request, response = read_exchange(route=config())
    return response["data"]["release_identity"]


def _route(
    *,
    identity: dict | None = None,
    read_schema: dict | None = None,
    write_schema: dict | None = None,
) -> VerifiedReleaseRoute:
    base_runtime = SimpleNamespace(
        capability_channel="staged",
        receipt_key_id="read-receipt-v2",
    )
    write_runtime = SimpleNamespace(
        base_runtime=base_runtime,
        approval=SimpleNamespace(key_id="approval-v3"),
        write_receipt=SimpleNamespace(key_id="write-receipt-v1"),
    )
    authority_config = SimpleNamespace(write_runtime=write_runtime)
    write_secrets = WriteRuntimeSecrets(
        write_auth=b"write-auth-secret-material-32-bytes",
        approval=APPROVAL_SECRET,
        execution=b"execution-secret-material-32-bytes",
        verification=b"verification-secret-material-32-bytes",
        recovery=b"recovery-secret-material-32-bytes",
        write_receipt=WRITE_SECRET,
    )
    capabilities = (
        _capability(
            "acct.ar.open_items.read.v1",
            access="read",
            output_schema=read_schema or _READ_SCHEMA,
        ),
        _capability(
            "acct.invoice.customer_create.v1",
            access="write",
            output_schema=write_schema or _WRITE_SCHEMA,
        ),
        _REAL_CAPABILITIES["acct.registry.list.v1"],
        _REAL_CAPABILITIES["acct.diagnostics.operation_read.v1"],
        _REAL_CAPABILITIES["acct.recovery.execute.v1"],
    )
    return VerifiedReleaseRoute(
        release_digest=RELEASE,
        registry_digest=REGISTRY,
        authority_config=authority_config,
        release_identity_json=json.dumps(
            identity or _identity(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        capabilities=capabilities,
        read_auth_secret=b"read-auth-secret-material-32-bytes",
        read_receipt_secret=READ_SECRET,
        write_secrets=write_secrets,
    )


def _pi_result(response: dict) -> dict:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    response,
                    ensure_ascii=False,
                    allow_nan=False,
                    indent=2,
                ),
            }
        ],
        "details": copy.deepcopy(response),
    }


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _raw_exchange(
    action: str,
    *,
    pi_arguments: dict,
    request: dict,
    response: dict,
    operation_before,
    operation_after,
    occurred_at: datetime,
    tool_name: str | None = None,
) -> dict:
    return {
        "action": action,
        "tool_name": tool_name or _TOOLS[action],
        "tool_call_id": f"call-{action.replace('.', '-')}-{request.get('operation_id', 'read')}",
        "pi_arguments": copy.deepcopy(pi_arguments),
        "occurred_at": _timestamp(occurred_at),
        "broker_request": copy.deepcopy(request),
        "broker_dispatched_at": _timestamp(occurred_at + timedelta(seconds=1)),
        "broker_response": copy.deepcopy(response),
        "broker_responded_at": _timestamp(occurred_at + timedelta(seconds=2)),
        "pi_result": _pi_result(response),
        "tool_completed_at": _timestamp(occurred_at + timedelta(seconds=3)),
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


def _approval_challenge(
    operation,
    *,
    issued_at: datetime,
    ttl_seconds: int,
    challenge_id: str,
) -> dict:
    return {
        "capability_id": operation.capability_id,
        "challenge_id": challenge_id,
        "company_id": operation.company_id,
        "expires_at": (
            issued_at + timedelta(seconds=ttl_seconds)
        ).astimezone(timezone.utc).isoformat(),
        "issued_at": issued_at.astimezone(timezone.utc).isoformat(),
        "operation_digest": operation.digest,
        "operation_id": operation.operation_id,
        "precheck_digest": operation.precheck_digest,
        "requester_user_id": operation.user_id,
        "state": "pending",
    }


def _terminal_exchange_for_raw_evidence(
    operation,
    approval,
    *,
    verified_at: datetime | None = None,
    receipt_issued_at: datetime | None = None,
):
    request, response = terminal_exchange(operation, approval)
    route = config(
        release=operation.release_digest,
        registry=operation.registry_digest,
    )
    body = {
        key: copy.deepcopy(value)
        for key, value in response["data"].items()
        if key != "audit_receipt"
    }
    body["verification"]["verified_at"] = _timestamp(
        verified_at or NOW - timedelta(milliseconds=1750)
    )
    receipt = create_write_audit_receipt(
        receipt_id=f"receipt-{operation.operation_id}",
        request_id=operation.request_id,
        operation_id=operation.operation_id,
        capability_id=operation.capability_id,
        principal=operation.principal,
        odoo_instance_id=operation.odoo_instance_id,
        database_name=operation.database_name,
        database_uuid=operation.database_uuid,
        user_id=operation.user_id,
        approver_user_id=operation.approver_user_id,
        company_id=operation.company_id,
        environment=operation.environment,
        capability_channel=route.capability_channel,
        request_digest=authentication_request_digest(
            operation.capability_id,
            operation.parameters,
        ),
        operation_digest=operation.digest,
        approval_digest=operation.approval_signature,
        registry_digest=operation.registry_digest,
        release_digest=operation.release_digest,
        audit_head="8" * 64,
        result_body=body,
        issued_at=receipt_issued_at
        or NOW - timedelta(milliseconds=1250),
        signing_key_id=route.write_receipt_key_id,
        secret=route.write_receipt_secret,
    )
    response["data"] = {**body, "audit_receipt": receipt}
    return request, response


def _read_evidence() -> dict:
    request, response = read_exchange(route=config())
    return {
        "read_exchange": _raw_exchange(
            "read",
            pi_arguments={
                "capability_id": request["capability_id"],
                "parameters": request["parameters"],
            },
            request=request,
            response=response,
            operation_before=None,
            operation_after=None,
            occurred_at=NOW - timedelta(seconds=3),
        )
    }


def _signed_read_evidence(
    *,
    capability_id: str,
    parameters: dict,
    body: dict,
    receipt_id: str,
    pi_arguments: dict,
    tool_name: str,
    observed_at: datetime | None = None,
) -> dict:
    route = config()
    unsigned = {
        "capability_id": capability_id,
        "parameters": copy.deepcopy(parameters),
    }
    request = {
        "context": context_mapping("read", unsigned),
        **unsigned,
    }
    receipt = create_read_receipt(
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
        registry_digest=route.registry_digest,
        release_digest=route.release_digest,
        environment=request["context"]["environment"],
        capability_channel=route.capability_channel,
        record_count=body["page"]["total_count"],
        observed_at=observed_at or NOW - timedelta(seconds=1),
        key_id=route.read_receipt_key_id,
        secret=route.read_receipt_secret,
    )
    response = {
        "command": "read",
        "data": {
            "capability_id": capability_id,
            "release_identity": _identity(),
            "result": {**copy.deepcopy(body), "receipt": receipt},
            "runtime": {
                "instance_id": request["context"]["odoo_instance_id"],
                "environment": request["context"]["environment"],
                "capability_channel": route.capability_channel,
                "database_name": request["context"]["database_name"],
                "database_uuid": request["context"]["database_uuid"],
            },
        },
        "ok": True,
    }
    return {
        "read_exchange": _raw_exchange(
            "read",
            pi_arguments=pi_arguments,
            request=request,
            response=response,
            operation_before=None,
            operation_after=None,
            occurred_at=NOW - timedelta(seconds=3),
            tool_name=tool_name,
        )
    }


def _registry_descriptor(capability: Capability) -> dict:
    data = capability.data
    return {
        "id": data["id"],
        "domain": data["domain"],
        "business_description": data["business_description"],
        "access": data["access"],
        "risk_level": data["risk_level"],
        "company_scope": data["company_scope"],
        "odoo_permissions": data["odoo_permissions"],
        "approval_required": data["approval"]["required"],
        "idempotency_required": data["idempotency"]["required"],
        "input_schema_json": canonical_json(data["input_schema"]).decode(
            "utf-8"
        ),
        "output_schema_json": canonical_json(data["output_schema"]).decode(
            "utf-8"
        ),
        "contract_digest": hashlib.sha256(canonical_json(data)).hexdigest(),
        "evidence_level": data["evidence"]["level"],
        "verification_method": data["verification"]["method"],
        "recovery_method": data["recovery"]["method"],
        "capability_channel": "staged",
    }


def _registry_evidence(
    *,
    generic: bool = False,
    empty: bool = False,
) -> dict:
    parameters: dict = {}
    capabilities = (
        []
        if empty
        else [
            _registry_descriptor(
                _REAL_CAPABILITIES["acct.registry.list.v1"]
            )
        ]
    )
    return _signed_read_evidence(
        capability_id="acct.registry.list.v1",
        parameters=parameters,
        body={
            "capabilities": capabilities,
            "page": {
                "count": len(capabilities),
                "total_count": len(capabilities),
            },
        },
        receipt_id=(
            "registry-generic-receipt-1"
            if generic
            else "registry-receipt-1"
        ),
        pi_arguments=(
            {
                "capability_id": "acct.registry.list.v1",
                "parameters": parameters,
            }
            if generic
            else {}
        ),
        tool_name=(
            "odoo_v3_read" if generic else "odoo_v3_capability_list"
        ),
    )


def _diagnostics_evidence(
    operation=None,
    *,
    receipt_id: str = "diagnostics-receipt-1",
) -> tuple[dict, object]:
    operation = operation or prepared_operation("diagnostics-op")
    request, response = diagnostics_exchange(operation)
    response["data"]["operation"]["terminal"] = operation.state in {
        State.COMPLETED,
        State.FAILED,
        State.RECOVERED,
    }
    route = config()
    body = {
        key: copy.deepcopy(value)
        for key, value in response["data"].items()
        if key != "receipt"
    }
    response["data"]["receipt"] = create_read_receipt(
        receipt_id=receipt_id,
        capability_id="acct.diagnostics.operation_read.v1",
        parameters={
            "company_id": operation.company_id,
            "operation_id": operation.operation_id,
        },
        result_body=body,
        auth_token_id=request["context"]["auth_token_id"],
        principal=request["context"]["principal"],
        odoo_instance_id=request["context"]["odoo_instance_id"],
        database_name=request["context"]["database_name"],
        database_uuid=request["context"]["database_uuid"],
        company_id=request["context"]["company_id"],
        user_id=request["context"]["user_id"],
        registry_digest=route.registry_digest,
        release_digest=route.release_digest,
        environment=request["context"]["environment"],
        capability_channel=route.capability_channel,
        record_count=1,
        observed_at=NOW - timedelta(seconds=1),
        key_id=route.read_receipt_key_id,
        secret=route.read_receipt_secret,
    )
    return (
        {
            "read_exchange": _raw_exchange(
                "operation.diagnostics",
                pi_arguments={
                    "company_id": operation.company_id,
                    "operation_id": operation.operation_id,
                },
                request=request,
                response=response,
                operation_before=operation,
                operation_after=None,
                occurred_at=NOW - timedelta(seconds=3),
            )
        },
        operation,
    )


def _generic_diagnostics_read_evidence(operation=None) -> dict:
    operation = operation or prepared_operation("generic-diagnostics-op")
    _request, diagnostics_response = diagnostics_exchange(operation)
    body = {
        key: copy.deepcopy(value)
        for key, value in diagnostics_response["data"].items()
        if key != "receipt"
    }
    parameters = {
        "company_id": operation.company_id,
        "operation_id": operation.operation_id,
    }
    return _signed_read_evidence(
        capability_id="acct.diagnostics.operation_read.v1",
        parameters=parameters,
        body=body,
        receipt_id="generic-diagnostics-receipt-1",
        pi_arguments={
            "capability_id": "acct.diagnostics.operation_read.v1",
            "parameters": parameters,
        },
        tool_name="odoo_v3_read",
    )


def _terminal_with_approval(
    operation_id: str,
    *,
    nonce: str | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
):
    awaiting, _precheck = awaiting_operation(operation_id)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce=nonce or f"nonce-{operation_id}",
        issued_at=issued_at or NOW - timedelta(minutes=1),
        expires_at=expires_at or _WRITE_CHALLENGE_EXPIRES_AT,
        approval_ttl_seconds=900,
        key_id="approval-v3",
        secret=APPROVAL_SECRET,
    )
    terminal = replace(
        awaiting,
        state=State.COMPLETED,
        revision=6,
        approval_signature=approval.signature,
        approval_nonce_digest=hashlib.sha256(
            approval.nonce.encode("utf-8")
        ).hexdigest(),
        approval_issued_at=approval.issued_at,
        approval_expires_at=approval.expires_at,
        approval_revision=approval.operation_revision,
        approver_user_id=approval.approver_user_id,
        execution_result_digest="e" * 64,
        verification_result_digest="f" * 64,
    )
    terminal.assert_integrity()
    return terminal, approval


def _write_evidence(
    operation_id: str = "op-1",
    *,
    terminal_and_approval=None,
) -> dict:
    prepared = prepared_operation(operation_id)
    awaiting, precheck = awaiting_operation(operation_id)
    terminal, approval = terminal_and_approval or _terminal_with_approval(
        operation_id
    )
    assert prepared == prepared_operation(operation_id)
    assert awaiting == awaiting_operation(operation_id)[0]

    prepare_unsigned = {
        "operation_id": prepared.operation_id,
        "request_id": prepared.request_id,
        "capability_id": prepared.capability_id,
        "parameters": prepared.parameters,
    }
    prepare_request = {
        "context": context_mapping("operation.prepare", prepare_unsigned),
        **prepare_unsigned,
    }
    prepare_response = {
        "command": "operation.prepare",
        "data": operation_response(prepared, next_action="operation.preview"),
        "ok": True,
    }

    preview_unsigned = {"operation_id": awaiting.operation_id}
    preview_request = {
        "context": context_mapping("operation.preview", preview_unsigned),
        **preview_unsigned,
    }
    preview_response = {
        "command": "operation.preview",
        "data": {
            "operation_id": awaiting.operation_id,
            "operation_state": awaiting.state.value,
            "capability_id": awaiting.capability_id,
            "business_description": "Create and post a customer invoice",
            "parameters": awaiting.parameters,
            "operation_digest": awaiting.digest,
            "precheck": precheck,
            "precheck_identity": {
                "operation_id": awaiting.operation_id,
                "precheck_digest": awaiting.precheck_digest,
                "registry_digest": awaiting.registry_digest,
                "release_digest": awaiting.release_digest,
            },
            "precheck_digest": awaiting.precheck_digest,
            "risk_level": "critical",
            "approval": {
                "required": True,
                "policy": "independent",
                "ttl_seconds": 900,
            },
            "recovery": {"method": "reverse_move"},
            "approval_challenge": _approval_challenge(
                awaiting,
                issued_at=_CHALLENGE_ISSUED_AT,
                ttl_seconds=900,
                challenge_id=f"challenge-{operation_id}",
            ),
        },
        "ok": True,
    }
    execute_request, execute_response = _terminal_exchange_for_raw_evidence(
        terminal,
        approval,
    )

    return {
        "prepare_exchange": _raw_exchange(
            "operation.prepare",
            pi_arguments={
                "capability_id": prepared.capability_id,
                "parameters": prepared.parameters,
            },
            request=prepare_request,
            response=prepare_response,
            operation_before=None,
            operation_after=prepared,
            occurred_at=NOW - timedelta(minutes=3),
        ),
        "preview_exchange": _raw_exchange(
            "operation.preview",
            pi_arguments={"operation_id": awaiting.operation_id},
            request=preview_request,
            response=preview_response,
            operation_before=prepared,
            operation_after=awaiting,
            occurred_at=_PREVIEW_OCCURRED_AT,
        ),
        "approve_execute_exchange": _raw_exchange(
            "operation.approve_execute",
            pi_arguments={"operation_id": terminal.operation_id},
            request=execute_request,
            response=execute_response,
            operation_before=awaiting,
            operation_after=terminal,
            occurred_at=NOW - timedelta(seconds=3),
        ),
    }


def _awaiting_from_prepared(operation):
    precheck = {
        "checks": ["acl", "company", "period", "recovery_plan"],
        "company_id": operation.company_id,
        "passed": True,
    }
    prechecked = record_precheck(
        operation,
        precheck_digest=hashlib.sha256(
            canonical_json(precheck)
        ).hexdigest(),
        expected_revision=operation.revision,
    )
    return (
        prechecked.transition(
            State.AWAITING_APPROVAL,
            expected_revision=prechecked.revision,
        ),
        precheck,
    )


def _terminal_from_awaiting(operation, *, nonce: str):
    approval = sign_approval(
        operation=operation,
        approver_user_id=99,
        nonce=nonce,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=_RECOVERY_CHALLENGE_EXPIRES_AT,
        approval_ttl_seconds=600,
        key_id="approval-v3",
        secret=APPROVAL_SECRET,
    )
    terminal = replace(
        operation,
        state=State.COMPLETED,
        revision=6,
        approval_signature=approval.signature,
        approval_nonce_digest=hashlib.sha256(
            approval.nonce.encode("utf-8")
        ).hexdigest(),
        approval_issued_at=approval.issued_at,
        approval_expires_at=approval.expires_at,
        approval_revision=approval.operation_revision,
        approver_user_id=approval.approver_user_id,
        execution_result_digest="e" * 64,
        verification_result_digest="f" * 64,
    )
    terminal.assert_integrity()
    return terminal, approval


def _recovery_evidence(*, generic_prepare: bool = False):
    origin, _origin_approval = terminal_operation("origin-recovery-op")
    plan_digest = "6" * 64
    recovery_parameters = {
        "company_id": origin.company_id,
        "expected_recovery_plan_digest": plan_digest,
        "idempotency_key": "recovery-idem-1",
        "origin_operation_id": origin.operation_id,
        "reason": "Correct duplicate posting",
        "recovery_date": "2026-07-15",
    }
    prepared = prepared_operation(
        "recovery-op",
        capability_id="acct.recovery.execute.v1",
        parameters=recovery_parameters,
        request_id="recovery-request-1",
    )
    awaiting, precheck = _awaiting_from_prepared(prepared)
    terminal, approval = _terminal_from_awaiting(
        awaiting,
        nonce="nonce-recovery-op",
    )

    if generic_prepare:
        first_action = "operation.prepare"
        prepare_unsigned = {
            "operation_id": prepared.operation_id,
            "request_id": prepared.request_id,
            "capability_id": prepared.capability_id,
            "parameters": prepared.parameters,
        }
        prepare_request = {
            "context": context_mapping(first_action, prepare_unsigned),
            **prepare_unsigned,
        }
        prepare_response = {
            "command": first_action,
            "data": operation_response(
                prepared,
                next_action="operation.preview",
            ),
            "ok": True,
        }
        pi_arguments = {
            "capability_id": prepared.capability_id,
            "parameters": prepared.parameters,
        }
        operation_before = None
    else:
        first_action = "operation.recover"
        public_arguments = {
            "origin_operation_id": origin.operation_id,
            "recovery_date": recovery_parameters["recovery_date"],
            "reason": recovery_parameters["reason"],
            "idempotency_key": recovery_parameters["idempotency_key"],
        }
        prepare_unsigned = {
            "origin_operation_id": origin.operation_id,
            "expected_origin_revision": origin.revision,
            "recovery_operation_id": prepared.operation_id,
            "request_id": prepared.request_id,
            "recovery_date": recovery_parameters["recovery_date"],
            "reason": recovery_parameters["reason"],
            "idempotency_key": recovery_parameters["idempotency_key"],
        }
        prepare_request = {
            "context": context_mapping(first_action, prepare_unsigned),
            **prepare_unsigned,
        }
        prepare_response = {
            "command": first_action,
            "data": {
                **operation_response(
                    prepared,
                    next_action="operation.preview",
                ),
                "origin_operation_id": origin.operation_id,
                "origin_operation_revision": origin.revision,
                "recovery_plan_digest": plan_digest,
            },
            "ok": True,
        }
        pi_arguments = public_arguments
        operation_before = origin

    preview_unsigned = {"operation_id": awaiting.operation_id}
    preview_request = {
        "context": context_mapping("operation.preview", preview_unsigned),
        **preview_unsigned,
    }
    preview_response = {
        "command": "operation.preview",
        "data": {
            "operation_id": awaiting.operation_id,
            "operation_state": awaiting.state.value,
            "capability_id": awaiting.capability_id,
            "business_description": _REAL_CAPABILITIES[
                "acct.recovery.execute.v1"
            ].data["business_description"],
            "parameters": awaiting.parameters,
            "operation_digest": awaiting.digest,
            "precheck": precheck,
            "precheck_identity": {
                "operation_id": awaiting.operation_id,
                "precheck_digest": awaiting.precheck_digest,
                "registry_digest": awaiting.registry_digest,
                "release_digest": awaiting.release_digest,
            },
            "precheck_digest": awaiting.precheck_digest,
            "risk_level": _REAL_CAPABILITIES[
                "acct.recovery.execute.v1"
            ].data["risk_level"],
            "approval": copy.deepcopy(
                _REAL_CAPABILITIES["acct.recovery.execute.v1"].data[
                    "approval"
                ]
            ),
            "recovery": copy.deepcopy(
                _REAL_CAPABILITIES["acct.recovery.execute.v1"].data[
                    "recovery"
                ]
            ),
            "approval_challenge": _approval_challenge(
                awaiting,
                issued_at=_CHALLENGE_ISSUED_AT,
                ttl_seconds=600,
                challenge_id="challenge-recovery-op",
            ),
        },
        "ok": True,
    }
    execute_request, execute_response = _terminal_exchange_for_raw_evidence(
        terminal,
        approval,
    )

    return (
        {
            "prepare_exchange": _raw_exchange(
                first_action,
                pi_arguments=pi_arguments,
                request=prepare_request,
                response=prepare_response,
                operation_before=operation_before,
                operation_after=prepared,
                occurred_at=NOW - timedelta(minutes=3),
            ),
            "preview_exchange": _raw_exchange(
                "operation.preview",
                pi_arguments={"operation_id": awaiting.operation_id},
                request=preview_request,
                response=preview_response,
                operation_before=prepared,
                operation_after=awaiting,
                occurred_at=_PREVIEW_OCCURRED_AT,
            ),
            "approve_execute_exchange": _raw_exchange(
                "operation.approve_execute",
                pi_arguments={"operation_id": terminal.operation_id},
                request=execute_request,
                response=execute_response,
                operation_before=awaiting,
                operation_after=terminal,
                occurred_at=NOW - timedelta(seconds=3),
            ),
        },
        origin,
    )


def _verifier(
    *,
    route: VerifiedReleaseRoute | None = None,
    state: PiEvidenceUniquenessState | None = None,
    operations: dict | None = None,
) -> PiEvidenceVerifier:
    trust = PiEvidenceTrust.from_verified_release(route or _route())
    resolved_operations = operations or {}
    return PiEvidenceVerifier(
        trust,
        operation_resolver=lambda operation_id: resolved_operations.get(
            operation_id
        ),
        utc_clock=lambda: NOW,
        uniqueness_state=state,
    )


@pytest.mark.parametrize(
    "legacy",
    (
        {"events": [], "self_hash": "a" * 64},
        {
            "read_exchange": {
                "action": "read",
                "verified": True,
                "normalized_summary": {"receipt_id": "fake"},
            }
        },
    ),
)
def test_rejects_legacy_self_hash_and_normalized_summary_as_authority(legacy):
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(legacy, trace_id="trace-legacy")


def test_rejects_read_signature_tamper_and_fake_pi_result():
    evidence = _read_evidence()
    evidence["read_exchange"]["broker_response"]["data"]["result"]["receipt"][
        "signature"
    ] = "0" * 64
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(evidence, trace_id="trace-read")

    evidence = _read_evidence()
    evidence["read_exchange"]["pi_result"]["details"] = {"ok": True}
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(evidence, trace_id="trace-read")


def test_rejects_pi_result_json_type_confusion():
    evidence = _read_evidence()
    exchange = evidence["read_exchange"]
    forged = copy.deepcopy(exchange["broker_response"])
    assert forged["ok"] is True
    forged["ok"] = 1
    exchange["pi_result"] = _pi_result(forged)

    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            evidence,
            trace_id="trace-read-type-confusion",
        )


def test_rejects_pi_argument_number_type_confusion():
    evidence = _read_evidence()
    exchange = evidence["read_exchange"]
    assert exchange["broker_request"]["parameters"]["company_id"] == 7
    exchange["pi_arguments"]["parameters"]["company_id"] = 7.0

    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            evidence,
            trace_id="trace-read-argument-type-confusion",
        )


def test_rejects_signed_receipt_outside_broker_response_window():
    read = _signed_read_evidence(
        capability_id="acct.ar.open_items.read.v1",
        parameters={"company_id": 7},
        body={"items": [], "page": {"count": 0, "total_count": 0}},
        receipt_id="read-receipt-future-window",
        pi_arguments={
            "capability_id": "acct.ar.open_items.read.v1",
            "parameters": {"company_id": 7},
        },
        tool_name="odoo_v3_read",
        observed_at=NOW - timedelta(milliseconds=500),
    )
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            read,
            trace_id="trace-read-receipt-window",
        )

    terminal_and_approval = _terminal_with_approval("write-receipt-window")
    write = _write_evidence(
        "write-receipt-window",
        terminal_and_approval=terminal_and_approval,
    )
    request, response = _terminal_exchange_for_raw_evidence(
        *terminal_and_approval,
        verified_at=NOW - timedelta(milliseconds=500),
        receipt_issued_at=NOW - timedelta(milliseconds=250),
    )
    execute = write["approve_execute_exchange"]
    execute["broker_request"] = request
    execute["broker_response"] = response
    execute["pi_result"] = _pi_result(response)
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            write,
            trace_id="trace-write-receipt-window",
        )


def test_rejects_release_identity_and_output_schema_mismatch():
    wrong_identity = _identity()
    wrong_identity["package_sha256"] = "8" * 64
    with pytest.raises(PiEvidenceError):
        _verifier(route=_route(identity=wrong_identity)).verify_trusted_evidence(
            _read_evidence(),
            trace_id="trace-route",
        )

    wrong_schema = copy.deepcopy(_READ_SCHEMA)
    wrong_schema["properties"]["items"] = {"type": "string"}
    with pytest.raises(PiEvidenceError):
        _verifier(route=_route(read_schema=wrong_schema)).verify_trusted_evidence(
            _read_evidence(),
            trace_id="trace-schema",
        )


def test_registry_list_requires_dedicated_pi_route_and_real_signed_output():
    evidence = _registry_evidence()
    exchange = evidence["read_exchange"]
    assert exchange["pi_arguments"] == {}
    assert exchange["broker_request"]["parameters"] == {}
    assert exchange["broker_request"]["context"]["company_id"] == 7
    assert exchange["broker_response"]["data"]["result"]["receipt"][
        "company_id"
    ] == 7

    summary = _verifier().verify_trusted_evidence(
        evidence,
        trace_id="trace-registry-list",
    )
    assert summary.kind == "read"
    assert summary.verified_actions == ("read",)
    assert summary.capability_id == "acct.registry.list.v1"
    assert summary.operation_id is None
    assert summary.read_receipt_id == "registry-receipt-1"
    assert summary.result_digest == exchange["broker_response"]["data"][
        "result"
    ]["receipt"]["result_digest"]

    invalid_schema = _signed_read_evidence(
        capability_id="acct.registry.list.v1",
        parameters={},
        body={
            "capabilities": "not-an-array",
            "page": {"count": 0, "total_count": 0},
        },
        receipt_id="registry-invalid-schema-receipt-1",
        pi_arguments={},
        tool_name="odoo_v3_capability_list",
    )
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            invalid_schema,
            trace_id="trace-registry-invalid-schema",
        )


def test_registry_list_rejects_a_validly_signed_empty_result():
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            _registry_evidence(empty=True),
            trace_id="trace-registry-empty",
        )


def test_diagnostics_is_signed_read_without_consuming_historical_operation():
    evidence, operation = _diagnostics_evidence()
    state = PiEvidenceUniquenessState()
    verifier = _verifier(
        state=state,
        operations={operation.operation_id: operation},
    )
    summary = verifier.verify_trusted_evidence(
        evidence,
        trace_id="trace-diagnostics",
    )
    assert summary.kind == "read"
    assert summary.verified_actions == ("operation.diagnostics",)
    assert summary.capability_id == "acct.diagnostics.operation_read.v1"
    assert summary.operation_id is None
    assert summary.read_receipt_id == "diagnostics-receipt-1"
    assert summary.result_digest == evidence["read_exchange"][
        "broker_response"
    ]["data"]["receipt"]["result_digest"]

    second, _same_operation = _diagnostics_evidence(
        operation,
        receipt_id="diagnostics-receipt-2",
    )
    second["read_exchange"]["tool_call_id"] = "call-diagnostics-second"
    repeated = verifier.verify_trusted_evidence(
        second,
        trace_id="trace-diagnostics-second",
    )
    assert repeated.operation_id is None
    assert repeated.read_receipt_id == "diagnostics-receipt-2"


def test_recovery_route_binds_only_new_operation_and_keeps_origin_readable():
    evidence, origin = _recovery_evidence()
    first = evidence["prepare_exchange"]
    assert first["action"] == "operation.recover"
    assert first["tool_name"] == "odoo_v3_operation_recover"
    assert set(first["pi_arguments"]) == {
        "origin_operation_id",
        "recovery_date",
        "reason",
        "idempotency_key",
    }
    assert first["operation_before"]["operation_id"] == origin.operation_id
    assert first["operation_after"]["operation_id"] == "recovery-op"
    assert first["operation_after"]["state"] == "prepared"
    assert {
        "context",
        "expected_origin_revision",
        "idempotency_key",
        "origin_operation_id",
        "reason",
        "recovery_date",
        "recovery_operation_id",
        "request_id",
    } == set(first["broker_request"])

    state = PiEvidenceUniquenessState()
    verifier = _verifier(
        state=state,
        operations={origin.operation_id: origin},
    )
    summary = verifier.verify_trusted_evidence(
        evidence,
        trace_id="trace-recovery",
    )
    assert summary.kind == "write"
    assert summary.verified_actions == (
        "operation.recover",
        "operation.preview",
        "operation.approve_execute",
    )
    assert summary.capability_id == "acct.recovery.execute.v1"
    assert summary.operation_id == "recovery-op"
    assert summary.write_receipt_id == "receipt-recovery-op"

    diagnostics, _same_origin = _diagnostics_evidence(origin)
    diagnostics_summary = verifier.verify_trusted_evidence(
        diagnostics,
        trace_id="trace-origin-diagnostics",
    )
    assert diagnostics_summary.operation_id is None
    assert diagnostics_summary.capability_id == (
        "acct.diagnostics.operation_read.v1"
    )


@pytest.mark.parametrize(
    "evidence_factory,operations_factory",
    (
        (
            lambda: _registry_evidence(generic=True),
            lambda: {},
        ),
        (
            lambda: _generic_diagnostics_read_evidence(),
            lambda: {},
        ),
        (
            lambda: _recovery_evidence(generic_prepare=True)[0],
            lambda: {},
        ),
    ),
    ids=(
        "registry-cannot-use-generic-read",
        "diagnostics-cannot-use-generic-read",
        "recovery-cannot-use-generic-prepare",
    ),
)
def test_dedicated_capabilities_reject_generic_route_masquerade(
    evidence_factory,
    operations_factory,
):
    with pytest.raises(PiEvidenceError):
        _verifier(operations=operations_factory()).verify_trusted_evidence(
            evidence_factory(),
            trace_id="trace-special-route-masquerade",
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "approval",
        "operation",
        "audit_receipt",
        "output_schema",
        "continuity",
    ),
)
def test_rejects_incomplete_or_tampered_write_exchange(mutation):
    evidence = _write_evidence()
    execute = evidence["approve_execute_exchange"]
    if mutation == "approval":
        del execute["broker_request"]["approval"]
    elif mutation == "operation":
        execute["operation_after"] = None
    elif mutation == "audit_receipt":
        del execute["broker_response"]["data"]["audit_receipt"]
        execute["pi_result"] = _pi_result(execute["broker_response"])
    elif mutation == "output_schema":
        schema = copy.deepcopy(_WRITE_SCHEMA)
        schema["properties"]["operation_id"] = {"type": "integer"}
        with pytest.raises(PiEvidenceError):
            _verifier(route=_route(write_schema=schema)).verify_trusted_evidence(
                evidence,
                trace_id="trace-write",
            )
        return
    else:
        execute["operation_before"] = copy.deepcopy(
            evidence["prepare_exchange"]["operation_after"]
        )
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(evidence, trace_id="trace-write")


@pytest.mark.parametrize(
    ("field", "forged_value"),
    (
        ("business_description", "Approve an unrelated transfer"),
        ("risk_level", "low"),
        ("approval", {"required": False}),
        ("recovery", {"method": "none"}),
    ),
)
def test_rejects_raw_preview_metadata_that_differs_from_registry(
    field,
    forged_value,
):
    evidence = _write_evidence()
    preview = evidence["preview_exchange"]
    preview["broker_response"]["data"][field] = forged_value
    preview["pi_result"] = _pi_result(preview["broker_response"])

    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            evidence,
            trace_id=f"trace-preview-{field}",
        )


def test_rejects_missing_or_tampered_approval_challenge():
    evidence = _write_evidence()
    preview = evidence["preview_exchange"]
    del preview["broker_response"]["data"]["approval_challenge"]
    preview["pi_result"] = _pi_result(preview["broker_response"])
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            evidence,
            trace_id="trace-preview-no-challenge",
        )

    evidence = _write_evidence()
    preview = evidence["preview_exchange"]
    preview["broker_response"]["data"]["approval_challenge"][
        "operation_digest"
    ] = "0" * 64
    preview["pi_result"] = _pi_result(preview["broker_response"])
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            evidence,
            trace_id="trace-preview-forged-challenge",
        )


@pytest.mark.parametrize(
    "field",
    ("company_id", "requester_user_id"),
)
def test_rejects_approval_challenge_integer_float_type_confusion(field):
    evidence = _write_evidence()
    preview = evidence["preview_exchange"]
    value = preview["broker_response"]["data"]["approval_challenge"][field]
    preview["broker_response"]["data"]["approval_challenge"][field] = float(
        value
    )
    preview["pi_result"] = _pi_result(preview["broker_response"])

    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            evidence,
            trace_id=f"trace-preview-{field}-float",
        )


def test_rejects_approval_issued_before_preview_completed():
    terminal_and_approval = _terminal_with_approval(
        "early-approval-op",
        issued_at=_CHALLENGE_ISSUED_AT + timedelta(seconds=1),
        expires_at=_WRITE_CHALLENGE_EXPIRES_AT,
    )
    evidence = _write_evidence(
        "early-approval-op",
        terminal_and_approval=terminal_and_approval,
    )

    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(
            evidence,
            trace_id="trace-early-approval",
        )


def test_rejects_expired_real_approval():
    terminal_and_approval = _terminal_with_approval(
        "expired-op",
        issued_at=NOW - timedelta(minutes=11),
        expires_at=NOW - timedelta(minutes=1),
    )
    evidence = _write_evidence(
        "expired-op",
        terminal_and_approval=terminal_and_approval,
    )
    with pytest.raises(PiEvidenceError):
        _verifier().verify_trusted_evidence(evidence, trace_id="trace-expired")


def test_rejects_replayed_read_receipt_and_write_corpus():
    state = PiEvidenceUniquenessState()
    verifier = _verifier(state=state)
    verifier.verify_trusted_evidence(_read_evidence(), trace_id="trace-read-1")
    with pytest.raises(PiEvidenceError):
        verifier.verify_trusted_evidence(
            _read_evidence(),
            trace_id="trace-read-2",
        )

    verifier.verify_trusted_evidence(_write_evidence(), trace_id="trace-write-1")
    with pytest.raises(PiEvidenceError):
        verifier.verify_trusted_evidence(
            _write_evidence(),
            trace_id="trace-write-2",
        )


def test_rejects_nonce_reuse_across_distinct_operations():
    state = PiEvidenceUniquenessState()
    verifier = _verifier(state=state)
    first = _terminal_with_approval("nonce-op-1", nonce="shared-nonce")
    second = _terminal_with_approval("nonce-op-2", nonce="shared-nonce")
    verifier.verify_trusted_evidence(
        _write_evidence("nonce-op-1", terminal_and_approval=first),
        trace_id="trace-nonce-1",
    )
    with pytest.raises(PiEvidenceError):
        verifier.verify_trusted_evidence(
            _write_evidence("nonce-op-2", terminal_and_approval=second),
            trace_id="trace-nonce-2",
        )


def test_signed_read_and_write_raw_evidence_return_safe_structured_summaries():
    read_summary = _verifier().verify_trusted_evidence(
        _read_evidence(),
        trace_id="trace-read",
    )
    assert read_summary.kind == "read"
    assert read_summary.verified_actions == ("read",)
    assert read_summary.read_receipt_id == "read-receipt-1"
    assert read_summary.result_digest == _read_evidence()["read_exchange"][
        "broker_response"
    ]["data"]["result"]["receipt"]["result_digest"]
    assert read_summary.authority_signature_verified is False
    assert read_summary.acl_independently_rechecked is False
    assert "secret" not in json.dumps(read_summary.to_dict())

    write_summary = _verifier().verify_trusted_evidence(
        _write_evidence(),
        trace_id="trace-write",
    )
    assert write_summary.kind == "write"
    assert write_summary.verified_actions == (
        "operation.prepare",
        "operation.preview",
        "operation.approve_execute",
    )
    assert write_summary.operation_id == "op-1"
    assert write_summary.write_receipt_id == "receipt-op-1"
    assert write_summary.result_digest == _write_evidence()[
        "approve_execute_exchange"
    ]["broker_response"]["data"]["audit_receipt"]["result_digest"]
    assert write_summary.authority_signature_verified is True
    assert write_summary.acl_independently_rechecked is False


def test_direct_release_config_trust_is_full_write_trust_and_not_serializable():
    route = _route()
    trust = PiEvidenceTrust.from_release_config(
        config(),
        release_identity=route.release_identity,
        capabilities=route.capabilities,
        approval_key_id="approval-v3",
        approval_secret=APPROVAL_SECRET,
        approval_ttl_resolver=lambda _operation: 900,
    )
    verifier = PiEvidenceVerifier(
        trust,
        operation_resolver=lambda _operation_id: None,
        utc_clock=lambda: NOW,
    )
    assert verifier.verify_trusted_evidence(
        _write_evidence(),
        trace_id="trace-direct",
    ).authority_signature_verified is True
    assert "approval-verifier" not in repr(trust)
    with pytest.raises(TypeError):
        pickle.dumps(trust)

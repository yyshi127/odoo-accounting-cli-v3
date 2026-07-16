from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.auth import sign_request_context
from odoo_accounting_cli_v3.operations import canonical_json, record_precheck, sign_approval
from odoo_accounting_cli_v3.operations import Operation, State
from odoo_accounting_cli_v3.write_api import WriteApiError, parse_write_api_request
from odoo_accounting_cli_v3.write_protocol import approval_to_mapping


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
AUTH_SECRET = b"write-api-auth-secret-material-32-bytes"
APPROVAL_SECRET = b"write-api-approval-secret-material-32"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"


def parameters():
    return {
        "company_id": 7,
        "partner_id": 901,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-16",
        "due_date": "2026-08-15",
        "currency_id": 12,
        "journal_id": 5,
        "posting_mode": "post",
        "reference": "PI-FULL-PARAMETERS",
        "lines": [
            {
                "line_reference": "line-1",
                "name": "Vendor service",
                "product_id": None,
                "account_id": 401,
                "quantity": "2.5000",
                "price_unit": "88.90",
                "tax_ids": [31, 32],
            }
        ],
        "idempotency_key": "pi-full-parameters-1",
    }


def context_mapping(bound_parameters=None):
    bound = parameters() if bound_parameters is None else bound_parameters
    context = sign_request_context(
        auth_token_id="token-write-api",
        principal="pi:user-42",
        odoo_instance_id="odoo19@sandbox",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        user_id=42,
        company_id=7,
        allowed_company_ids=frozenset({7}),
        environment="sandbox",
        capability_id="acct.bill.vendor_create.v1",
        parameters=bound,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=4),
        key_id="write-auth-v1",
        secret=AUTH_SECRET,
    )
    from odoo_accounting_cli_v3.auth import context_payload

    value = context_payload(context)
    value["auth_signature"] = context.auth_signature
    value["auth_issued_at"] = context.auth_issued_at.isoformat().replace("+00:00", "Z")
    value["auth_expires_at"] = context.auth_expires_at.isoformat().replace("+00:00", "Z")
    return value


def awaiting_operation():
    value = Operation.prepare(
        operation_id="op-write-api",
        request_id="req-write-api",
        capability_id="acct.bill.vendor_create.v1",
        parameters=parameters(),
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key="pi-full-parameters-1",
        odoo_instance_id="odoo19@sandbox",
        database_name="odoo_v3_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest="c" * 64,
        release_digest="d" * 64,
    )
    value = record_precheck(value, precheck_digest="e" * 64, expected_revision=0)
    return value.transition(State.AWAITING_APPROVAL, expected_revision=1)


def test_prepare_preserves_every_business_parameter_exactly():
    request = {
        "context": context_mapping(),
        "operation_id": "op-write-api",
        "request_id": "req-write-api",
        "capability_id": "acct.bill.vendor_create.v1",
        "parameters": parameters(),
    }

    parsed = parse_write_api_request("operation.prepare", request)

    assert parsed.payload["parameters"] == parameters()
    assert canonical_json(parsed.signed_request) == canonical_json(
        {key: value for key, value in request.items() if key != "context"}
    )
    assert parsed.context.company_id == 7


@pytest.mark.parametrize(
    "action,payload",
    [
        ("operation.preview", {"operation_id": "op-write-api"}),
        ("operation.status", {"operation_id": "op-write-api"}),
        ("operation.result", {"operation_id": "op-write-api"}),
        (
            "operation.recover",
            {
                "origin_operation_id": "op-write-api",
                "expected_origin_revision": 6,
                "recovery_operation_id": "op-write-api-recovery",
                "request_id": "req-write-api-recovery",
                "recovery_date": "2026-07-16",
                "reason": "Reverse the duplicate vendor bill",
                "idempotency_key": "recover-op-write-api",
            },
        ),
    ],
)
def test_lifecycle_requests_use_exact_fields(action, payload):
    request = {"context": context_mapping(), **payload}
    parsed = parse_write_api_request(action, request)
    assert parsed.payload == payload

    with pytest.raises(WriteApiError, match="fields"):
        parse_write_api_request(action, {**request, "unexpected": True})
    missing = copy.deepcopy(request)
    missing.pop(next(iter(payload)))
    with pytest.raises(WriteApiError, match="fields"):
        parse_write_api_request(action, missing)


def test_approve_execute_requires_exact_approval_operation_binding():
    operation = awaiting_operation()
    approval = sign_approval(
        operation=operation,
        approver_user_id=99,
        nonce="write-api-approval",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v3",
        secret=APPROVAL_SECRET,
    )
    request = {
        "context": context_mapping(),
        "operation_id": operation.operation_id,
        "approval": approval_to_mapping(approval),
        "reconciliation_only": False,
    }
    parsed = parse_write_api_request("operation.approve_execute", request)
    assert parsed.approval == approval

    request["operation_id"] = "another-operation"
    with pytest.raises(WriteApiError, match="binding"):
        parse_write_api_request("operation.approve_execute", request)

    request["operation_id"] = operation.operation_id
    request["reconciliation_only"] = "false"
    with pytest.raises(WriteApiError, match="reconciliation_only"):
        parse_write_api_request("operation.approve_execute", request)


def test_recovery_revision_date_and_reason_are_strict():
    base = {
        "context": context_mapping(),
        "origin_operation_id": "op-write-api",
        "expected_origin_revision": 6,
        "recovery_operation_id": "op-write-api-recovery",
        "request_id": "req-write-api-recovery",
        "recovery_date": "2026-07-16",
        "reason": "Approved compensation",
        "idempotency_key": "recover-op-write-api",
    }
    for field, value in (
        ("expected_origin_revision", True),
        ("recovery_date", "2026-02-30"),
        ("reason", " padded "),
    ):
        with pytest.raises(WriteApiError):
            parse_write_api_request(
                "operation.recover", {**base, field: value}
            )

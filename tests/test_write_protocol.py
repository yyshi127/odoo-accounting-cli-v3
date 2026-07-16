from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.operations import (
    IntegrityRejected,
    Operation,
    State,
    record_precheck,
    sign_approval,
    sign_execution_result,
)
from odoo_accounting_cli_v3.write_protocol import (
    approved_write_authentication_parameters,
    approval_from_mapping,
    approval_to_mapping,
    operation_from_mapping,
    operation_to_mapping,
    trusted_result_from_mapping,
    trusted_result_to_mapping,
)


NOW = datetime(2026, 7, 15, 4, 0, tzinfo=timezone.utc)
APPROVAL_SECRET = b"approval-secret-material-at-least-32"
RESULT_SECRET = b"result-secret-material-at-least-32-byte"


def test_approved_write_authentication_binds_exact_boolean_and_detached_parameters():
    parameters = {
        "company_id": 7,
        "lines": [{"name": "Consulting", "amount": "100.00"}],
    }

    execute = approved_write_authentication_parameters(parameters, False)
    reconcile = approved_write_authentication_parameters(parameters, True)
    parameters["lines"][0]["amount"] = "999.00"

    assert execute == {
        "parameters": {
            "company_id": 7,
            "lines": [{"name": "Consulting", "amount": "100.00"}],
        },
        "reconciliation_only": False,
    }
    assert reconcile["reconciliation_only"] is True
    with pytest.raises(ValueError, match="authentication content"):
        approved_write_authentication_parameters(parameters, "true")


def _awaiting_operation() -> Operation:
    operation = Operation.prepare(
        operation_id="op-protocol-1",
        request_id="request-protocol-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "idempotency_key": "protocol-1"},
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key="protocol-1",
        odoo_instance_id="odoo19@sandbox",
        database_name="codex_odoo_accounting_cli_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        environment="sandbox",
        registry_digest="c" * 64,
        release_digest="d" * 64,
    )
    operation = record_precheck(
        operation,
        precheck_digest="f" * 64,
        expected_revision=0,
    )
    return operation.transition(State.AWAITING_APPROVAL, expected_revision=1)


def test_operation_protocol_round_trip_preserves_exact_integrity() -> None:
    original = _awaiting_operation()

    encoded = operation_to_mapping(original)
    decoded = operation_from_mapping(encoded)

    assert decoded == original
    assert encoded["parameters"] == original.parameters
    assert encoded["protocol_version"] == 4
    assert encoded["precheck_digest"] == "f" * 64
    assert encoded["state"] == "awaiting_approval"
    assert encoded["approval"] is None


def test_operation_protocol_rejects_unknown_fields_and_tampered_parameters() -> None:
    encoded = operation_to_mapping(_awaiting_operation())
    with_unknown = {**encoded, "unexpected": True}
    with pytest.raises(ValueError, match="fields"):
        operation_from_mapping(with_unknown)

    tampered = copy.deepcopy(encoded)
    tampered["parameters"]["company_id"] = 8
    with pytest.raises(IntegrityRejected, match="digest"):
        operation_from_mapping(tampered)


def test_approval_protocol_round_trip_uses_canonical_utc_timestamps() -> None:
    operation = _awaiting_operation()
    approval = sign_approval(
        operation=operation,
        approver_user_id=99,
        nonce="protocol-approval-nonce",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )

    encoded = approval_to_mapping(approval)

    assert encoded["issued_at"].endswith("Z")
    assert encoded["expires_at"].endswith("Z")
    assert encoded["precheck_digest"] == operation.precheck_digest
    assert approval_from_mapping(encoded) == approval


def test_trusted_result_protocol_round_trip_and_exact_fields() -> None:
    operation = _awaiting_operation()
    approval = sign_approval(
        operation=operation,
        approver_user_id=99,
        nonce="protocol-result-nonce",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )
    from odoo_accounting_cli_v3.operations import approve_operation, begin_execution

    approved = approve_operation(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda *_: True,
        consume_nonce=lambda *_: True,
        approval_ttl_seconds=600,
        expected_revision=2,
    )
    executing = begin_execution(
        approved,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda *_: True,
        approval_ttl_seconds=600,
        expected_revision=3,
    )
    result = sign_execution_result(
        operation=executing,
        issuer="odoo-write-executor",
        key_id="execution-v1",
        succeeded=True,
        evidence_digest="e" * 64,
        issued_at=NOW,
        secret=RESULT_SECRET,
    )

    encoded = trusted_result_to_mapping(result)

    assert encoded["kind"] == "execution"
    assert encoded["issued_at"].endswith("Z")
    assert trusted_result_from_mapping(encoded) == result
    with pytest.raises(ValueError, match="fields"):
        trusted_result_from_mapping({**encoded, "unexpected": "field"})

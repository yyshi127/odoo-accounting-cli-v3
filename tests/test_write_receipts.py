from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.write_receipts import (
    WriteReceiptError,
    create_difference,
    create_record_snapshot,
    create_recovery_plan,
    create_write_audit_receipt,
    verify_write_audit_receipt,
)


NOW = datetime(2026, 7, 15, 3, 0, tzinfo=timezone.utc)
SECRET = b"write-receipt-secret-material-32-bytes"
DIGESTS = {
    "request_digest": "1" * 64,
    "operation_digest": "2" * 64,
    "approval_digest": "3" * 64,
    "registry_digest": "4" * 64,
    "release_digest": "5" * 64,
    "audit_head": "6" * 64,
}
REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


def snapshot(*, state: str = "draft", amount: str = "125.50") -> dict:
    return create_record_snapshot(
        model="account.move",
        record_id=880,
        exists=True,
        record_state=state,
        values={"amount_total": amount, "name": "INV/2026/0001", "state": state},
    )


def result_body() -> dict:
    before = snapshot(state="draft")
    after = snapshot(state="posted")
    difference = create_difference(
        before=[before], after=[after], changed_fields=["state"]
    )
    plan = create_recovery_plan(
        origin_operation_id="op-1001",
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="reverse_move",
        requires_approval=True,
        target_records=[
            {
                "model": "account.move",
                "record_id": 880,
                "company_id": 7,
                "record_state": "posted",
                "record_fingerprint": after["values_digest"],
            }
        ],
        parameters={"company_id": 7, "move_id": 880},
    )
    return {
        "operation_id": "op-1001",
        "operation_state": "completed",
        "odoo_records": [
            {
                "model": "account.move",
                "record_id": 880,
                "company_id": 7,
                "record_state": "posted",
                "record_fingerprint": after["values_digest"],
            }
        ],
        "difference": difference,
        "verification": {
            "method": "read_back_move",
            "passed": True,
            "checks": ["record_exists", "company_matches", "amount_matches"],
            "evidence_digest": "7" * 64,
            "verified_at": "2026-07-15T03:00:00Z",
        },
        "recovery_plan": plan,
    }


def receipt(result: dict | None = None) -> dict:
    return create_write_audit_receipt(
        receipt_id="write-receipt-1001",
        request_id="request-1001",
        operation_id="op-1001",
        capability_id="acct.invoice.customer_create.v1",
        principal="pi-agent:xiaojing-accountant",
        odoo_instance_id="odoo19-primary",
        database_name="odoo_v3_sandbox",
        database_uuid="19b09656-d10f-11f0-9065-00163e54a5ad",
        user_id=42,
        approver_user_id=43,
        company_id=7,
        environment="sandbox",
        capability_channel="staged",
        result_body=result or result_body(),
        issued_at=NOW,
        signing_key_id="write-key-v1",
        secret=SECRET,
        **DIGESTS,
    )


def verification_arguments(result: dict | None = None) -> dict:
    return {
        "request_id": "request-1001",
        "operation_id": "op-1001",
        "capability_id": "acct.invoice.customer_create.v1",
        "principal": "pi-agent:xiaojing-accountant",
        "odoo_instance_id": "odoo19-primary",
        "database_name": "odoo_v3_sandbox",
        "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        "user_id": 42,
        "approver_user_id": 43,
        "company_id": 7,
        "environment": "sandbox",
        "capability_channel": "staged",
        "result_body": result or result_body(),
        "now": NOW,
        "expected_signing_key_id": "write-key-v1",
        "secret": SECRET,
        **DIGESTS,
    }


def test_record_snapshot_is_canonical_strict_and_content_addressed():
    first = snapshot()
    second = create_record_snapshot(
        model="account.move",
        record_id=880,
        exists=True,
        record_state="draft",
        values={"state": "draft", "name": "INV/2026/0001", "amount_total": "125.50"},
    )

    assert first == second
    assert set(first) == {
        "model",
        "record_id",
        "exists",
        "record_state",
        "values_json",
        "values_digest",
    }
    assert first["values_json"] == '{"amount_total":"125.50","name":"INV/2026/0001","state":"draft"}'


def test_difference_and_recovery_plan_bind_every_effect_reference():
    body = result_body()
    difference = body["difference"]
    plan = body["recovery_plan"]

    assert difference["before_digest"] != difference["after_digest"]
    assert difference["changed_fields"] == ["state"]
    assert plan["parameters_digest"]
    assert plan["plan_digest"]

    changed = create_recovery_plan(
        origin_operation_id="op-1001",
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="reverse_move",
        requires_approval=True,
        target_records=plan["target_records"],
        parameters={"company_id": 7, "move_id": 881},
    )
    assert changed["plan_digest"] != plan["plan_digest"]


def test_write_receipt_verifies_all_identity_approval_and_result_bindings():
    result = result_body()
    signed = receipt(result)

    verify_write_audit_receipt(signed, **verification_arguments(result))

    assert signed["verification_evidence_digest"] == result["verification"]["evidence_digest"]
    assert signed["approver_user_id"] == 43
    assert signed["principal"] == "pi-agent:xiaojing-accountant"
    assert signed["signature_purpose"] == "write_audit_receipt_v1"


def test_generated_result_and_receipt_match_the_registered_write_output_schema():
    result = result_body()
    signed = receipt(result)
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    capability = next(
        item
        for item in registry["capabilities"]
        if item["id"] == "acct.invoice.customer_create.v1"
    )

    validate_value({**result, "audit_receipt": signed}, capability["output_schema"])


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("request_digest", "a" * 64),
        ("operation_digest", "a" * 64),
        ("approval_digest", "a" * 64),
        ("result_digest", "a" * 64),
        ("verification_evidence_digest", "a" * 64),
        ("audit_head", "a" * 64),
        ("user_id", 99),
        ("approver_user_id", 99),
        ("company_id", 99),
        ("environment", "production"),
        ("principal", "someone-else"),
    ),
)
def test_write_receipt_rejects_tampering(field, replacement):
    signed = receipt()
    signed[field] = replacement

    with pytest.raises(WriteReceiptError):
        verify_write_audit_receipt(signed, **verification_arguments())


def test_write_receipt_cannot_report_success_without_verified_odoo_effect():
    result = result_body()
    result["verification"]["passed"] = False
    with pytest.raises(WriteReceiptError, match="verified Odoo effect"):
        receipt(result)

    result = result_body()
    result["odoo_records"] = []
    with pytest.raises(WriteReceiptError, match="Odoo record"):
        receipt(result)


def test_write_receipt_rejects_self_approval_and_production_staged_channel():
    arguments = {
        "receipt_id": "receipt",
        "request_id": "request",
        "operation_id": "operation",
        "capability_id": "acct.invoice.customer_create.v1",
        "principal": "pi-agent",
        "odoo_instance_id": "odoo19-primary",
        "database_name": "odoo_v3_sandbox",
        "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        "user_id": 42,
        "approver_user_id": 42,
        "company_id": 7,
        "environment": "sandbox",
        "capability_channel": "staged",
        "result_body": result_body(),
        "issued_at": NOW,
        "signing_key_id": "write-key-v1",
        "secret": SECRET,
        **DIGESTS,
    }
    with pytest.raises(WriteReceiptError, match="approve their own"):
        create_write_audit_receipt(**arguments)

    arguments["approver_user_id"] = 43
    arguments["environment"] = "production"
    with pytest.raises(WriteReceiptError, match="production"):
        create_write_audit_receipt(**arguments)


def test_unknown_or_extra_receipt_fields_are_rejected():
    signed = receipt()
    signed["unexpected"] = True
    with pytest.raises(WriteReceiptError, match="fields"):
        verify_write_audit_receipt(signed, **verification_arguments())

    signed = receipt()
    signed.pop("audit_head")
    with pytest.raises(WriteReceiptError, match="fields"):
        verify_write_audit_receipt(signed, **verification_arguments())


def test_result_body_tampering_breaks_result_digest_even_with_untouched_receipt():
    result = result_body()
    signed = receipt(result)
    changed = copy.deepcopy(result)
    changed["odoo_records"][0]["record_id"] = 881

    with pytest.raises(WriteReceiptError, match="content digest"):
        verify_write_audit_receipt(signed, **verification_arguments(changed))

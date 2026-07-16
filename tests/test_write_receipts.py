from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.write_receipts import (
    WriteReceiptError,
    create_difference,
    create_record_snapshot,
    create_recovery_plan,
    create_recovery_plan_v2,
    create_write_audit_receipt,
    index_recovery_guard_graph,
    validate_executable_recovery_plan,
    validate_recovery_plan,
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


def recovery_target(
    record_id: int,
    *,
    model: str = "account.move",
    company_id: int = 7,
    state: str = "posted",
) -> dict:
    return {
        "model": model,
        "record_id": record_id,
        "company_id": company_id,
        "record_state": state,
        "record_fingerprint": f"{record_id % 16:x}" * 64,
    }


def recovery_guard(
    record_id: int,
    *,
    expected_outcome: str = "survive_exact",
    model: str = "account.move.line",
    company_id: int = 7,
) -> dict:
    return {
        **recovery_target(record_id, model=model, company_id=company_id),
        "expected_outcome": expected_outcome,
    }


def recovery_plan_v2(**overrides) -> dict:
    arguments = {
        "origin_operation_id": "op-1001",
        "recovery_capability_id": "acct.recovery.execute.v1",
        "status": "available",
        "method": "reverse_move_guarded",
        "requires_approval": True,
        "action_targets": [recovery_target(881), recovery_target(880)],
        "guard_records": [recovery_guard(982), recovery_guard(981)],
        "oracle_id": "acct.oracle.reverse_move_graph.v1",
        "parameters": {"company_id": 7, "move_id": 880},
    }
    arguments.update(overrides)
    return create_recovery_plan_v2(**arguments)


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


def test_recovery_plan_v2_is_canonical_role_bound_and_executable():
    plan = recovery_plan_v2()

    assert set(plan) == {
        "plan_version",
        "origin_operation_id",
        "recovery_capability_id",
        "status",
        "method",
        "requires_approval",
        "action_targets",
        "guard_records",
        "oracle_id",
        "guard_graph_digest",
        "parameters_digest",
        "plan_digest",
    }
    assert plan["plan_version"] == 2
    assert [item["record_id"] for item in plan["action_targets"]] == [880, 881]
    assert [item["record_id"] for item in plan["guard_records"]] == [981, 982]
    graph = {
        "action_targets": plan["action_targets"],
        "guard_records": plan["guard_records"],
        "oracle_id": plan["oracle_id"],
    }
    assert plan["guard_graph_digest"] == hashlib.sha256(
        canonical_json(graph)
    ).hexdigest()

    validate_recovery_plan(plan)
    validate_executable_recovery_plan(plan)

    indexed = index_recovery_guard_graph(plan, expected_company_id=7)
    assert indexed[("account.move", 880)] == {
        **recovery_target(880),
        "role": "action",
    }
    assert indexed[("account.move.line", 981)] == {
        **recovery_guard(981),
        "role": "guard",
    }


def test_recovery_plan_v2_creation_does_not_mutate_caller_records():
    action = recovery_target(880)
    guard = recovery_guard(981)
    plan = recovery_plan_v2(action_targets=[action], guard_records=[guard])

    action["record_id"] = 999
    guard["expected_outcome"] = "manual_review"

    assert plan["action_targets"][0]["record_id"] == 880
    assert plan["guard_records"][0]["expected_outcome"] == "survive_exact"
    validate_executable_recovery_plan(plan)


@pytest.mark.parametrize(
    "overrides,match",
    (
        ({"requires_approval": False}, "approval"),
        ({"action_targets": []}, "action target"),
        ({"guard_records": []}, "guard record"),
        (
            {"guard_records": [recovery_guard(981, expected_outcome="manual_review")]},
            "manual_review",
        ),
        ({"oracle_id": "manual"}, "oracle"),
        ({"oracle_id": "manual_escalation"}, "oracle"),
        ({"oracle_id": "not_applicable"}, "oracle"),
    ),
)
def test_available_recovery_plan_v2_enforces_execution_safety(overrides, match):
    with pytest.raises(WriteReceiptError, match=match):
        recovery_plan_v2(**overrides)


@pytest.mark.parametrize(
    "expected_outcome", ("survive_exact", "survive_allowed_delta", "absent")
)
def test_executable_recovery_plan_v2_accepts_each_automatic_guard_outcome(
    expected_outcome,
):
    plan = recovery_plan_v2(
        guard_records=[recovery_guard(981, expected_outcome=expected_outcome)]
    )
    validate_executable_recovery_plan(plan)


@pytest.mark.parametrize("expected_outcome", ("destroy", 1, None, ["survive_exact"]))
def test_recovery_plan_v2_rejects_unknown_guard_outcomes(expected_outcome):
    with pytest.raises(WriteReceiptError, match="expected_outcome"):
        recovery_plan_v2(
            guard_records=[recovery_guard(981, expected_outcome=expected_outcome)]
        )


@pytest.mark.parametrize("status", ("not_applicable", "manual_escalation"))
def test_non_available_recovery_plan_v2_cannot_publish_action_targets(status):
    with pytest.raises(WriteReceiptError, match="action_targets"):
        recovery_plan_v2(status=status)

    plan = recovery_plan_v2(
        status=status,
        requires_approval=False,
        action_targets=[],
        guard_records=[recovery_guard(981, expected_outcome="manual_review")],
        oracle_id="manual",
    )
    validate_recovery_plan(plan)
    with pytest.raises(WriteReceiptError, match="available V2"):
        validate_executable_recovery_plan(plan)


@pytest.mark.parametrize(
    "field,replacement",
    (
        ("oracle_id", "acct.oracle.different.v1"),
        ("guard_graph_digest", "a" * 64),
        ("parameters_digest", "b" * 64),
        ("requires_approval", False),
    ),
)
def test_recovery_plan_v2_rejects_digest_or_execution_metadata_tampering(
    field, replacement
):
    plan = recovery_plan_v2()
    plan[field] = replacement

    with pytest.raises(WriteReceiptError):
        validate_recovery_plan(plan)


def test_recovery_plan_v2_guard_digest_rejects_role_tampering():
    plan = recovery_plan_v2(
        action_targets=[recovery_target(880)],
        guard_records=[recovery_guard(981)],
    )
    action = plan["action_targets"].pop()
    guard = plan["guard_records"].pop()
    plan["action_targets"].append(
        {key: guard[key] for key in action}
    )
    plan["guard_records"].append({**action, "expected_outcome": "survive_exact"})
    unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
    plan["plan_digest"] = hashlib.sha256(canonical_json(unsigned)).hexdigest()

    with pytest.raises(WriteReceiptError, match="guard graph digest"):
        validate_recovery_plan(plan)


@pytest.mark.parametrize(
    "overrides",
    (
        {"action_targets": [recovery_target(880), recovery_target(880)]},
        {"guard_records": [recovery_guard(981), recovery_guard(981)]},
        {
            "action_targets": [recovery_target(880)],
            "guard_records": [recovery_guard(880, model="account.move")],
        },
        {
            "action_targets": [recovery_target(880)],
            "guard_records": [
                recovery_guard(880, model="account.move", company_id=8)
            ],
        },
    ),
)
def test_recovery_plan_v2_rejects_duplicate_or_overlapping_graph_roles(overrides):
    with pytest.raises(WriteReceiptError, match="duplicate|both action and guard"):
        recovery_plan_v2(**overrides)


def test_recovery_guard_graph_index_can_enforce_the_callers_company_scope():
    plan = recovery_plan_v2(
        action_targets=[recovery_target(880, company_id=7)],
        guard_records=[recovery_guard(981, company_id=8)],
    )
    validate_recovery_plan(plan)

    indexed = index_recovery_guard_graph(plan)
    assert indexed[("account.move", 880)]["company_id"] == 7
    assert indexed[("account.move.line", 981)]["company_id"] == 8
    with pytest.raises(WriteReceiptError, match="company"):
        index_recovery_guard_graph(plan, expected_company_id=7)


def test_recovery_plan_validation_preserves_v1_history_but_execution_requires_v2():
    historical = result_body()["recovery_plan"]
    validate_recovery_plan(historical)

    with pytest.raises(WriteReceiptError, match="available V2"):
        validate_executable_recovery_plan(historical)
    with pytest.raises(WriteReceiptError, match="V2"):
        index_recovery_guard_graph(historical)


def test_recovery_plan_v2_rejects_unknown_fields_versions_and_noncanonical_order():
    plan = recovery_plan_v2()
    plan["unexpected"] = True
    with pytest.raises(WriteReceiptError, match="fields"):
        validate_recovery_plan(plan)

    plan = recovery_plan_v2()
    plan["plan_version"] = 1
    with pytest.raises(WriteReceiptError, match="version"):
        validate_recovery_plan(plan)

    plan = recovery_plan_v2()
    plan["action_targets"].reverse()
    with pytest.raises(WriteReceiptError, match="canonical order"):
        validate_recovery_plan(plan)


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

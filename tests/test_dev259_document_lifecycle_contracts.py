from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.contracts import ContractError, validate_value
from odoo_accounting_cli_v3.registry import load_registry


REGISTRY_PATH = (
    Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
)
SHA256 = "a" * 64
DIGEST_SCHEMA = {
    "type": "string",
    "minLength": 64,
    "maxLength": 64,
    "pattern": "^[0-9a-f]{64}$",
}
TARGET_BINDING_SCHEMA = {
    "type": "string",
    "minLength": 0,
    "maxLength": 256,
    "pattern": "^.*$",
}

DOCUMENT_POST_FIELDS = {
    "company_id",
    "move_id",
    "expected_move_type",
    "expected_document_binding",
    "expected_document_binding_v2",
    "expected_business_binding",
    "expected_partner_id",
    "expected_journal_id",
    "expected_currency_id",
    "expected_payment_term_line_id",
    "expected_payment_term_account_id",
    "expected_invoice_date",
    "expected_accounting_date",
    "expected_due_date",
    "expected_reference",
    "expected_amount_untaxed",
    "expected_amount_tax",
    "expected_amount_total",
    "expected_amount_residual",
    "expected_line_ids",
    "reason",
    "idempotency_key",
}

REFUND_CANCEL_FIELDS = {
    "company_id",
    "move_id",
    "expected_move_type",
    "expected_origin_move_id",
    "expected_document_binding",
    "expected_document_binding_v2",
    "expected_business_binding",
    "expected_origin_document_binding",
    "expected_origin_document_binding_v2",
    "expected_origin_business_binding",
    "expected_partner_id",
    "expected_journal_id",
    "expected_currency_id",
    "expected_refund_date",
    "expected_total_amount",
    "expected_line_ids",
    "expected_origin_line_ids",
    "reason",
    "idempotency_key",
}

DOCUMENT_POST_TARGET_FIELDS = {
    "company_id",
    "move_id",
    "move_type",
    "state",
    "posted_before",
    "payment_state",
    "document_binding",
    "document_binding_v2",
    "business_binding",
    "partner_id",
    "journal_id",
    "currency_id",
    "payment_term_line_id",
    "payment_term_account_id",
    "invoice_date",
    "accounting_date",
    "due_date",
    "reference",
    "amount_untaxed",
    "amount_tax",
    "amount_total",
    "amount_residual",
    "line_ids",
    "invoice_line_ids",
}

REFUND_TARGET_FIELDS = {
    "company_id",
    "move_id",
    "move_type",
    "state",
    "posted_before",
    "payment_state",
    "document_binding",
    "document_binding_v2",
    "business_binding",
    "origin_move_id",
    "partner_id",
    "journal_id",
    "currency_id",
    "refund_date",
    "accounting_date",
    "amount_total",
    "amount_residual",
    "line_ids",
    "reason",
    "invoice_line_ids",
    "source_refund_mode",
}

ORIGIN_TARGET_FIELDS = {
    "company_id",
    "move_id",
    "move_type",
    "state",
    "posted_before",
    "payment_state",
    "document_binding",
    "document_binding_v2",
    "business_binding",
    "partner_id",
    "journal_id",
    "currency_id",
    "amount_total",
    "amount_residual",
    "line_ids",
    "reversal_move_ids",
    "invoice_date",
    "accounting_date",
    "due_date",
    "reference",
    "invoice_line_ids",
    "source_posting_mode",
}

ELIGIBILITY_VERIFICATION_METHODS = {
    "acct.move.document_post_eligibility.v1": (
        "signed_odoo_company_currency_taxless_document_post_eligibility_"
        "with_term_account_binding"
    ),
    "acct.refund.draft_cancel_eligibility.v1": (
        "signed_odoo_canonical_v3_refund_origin_v2_binding_draft_cancel_"
        "eligibility_read_receipt"
    ),
}


def _registry_by_id() -> dict[str, dict[str, object]]:
    return {item.id: item.data for item in load_registry(REGISTRY_PATH)}


def _document_post_parameters(move_type: str) -> dict[str, object]:
    return {
        "company_id": 7,
        "move_id": 101,
        "expected_move_type": move_type,
        "expected_document_binding": SHA256,
        "expected_document_binding_v2": "e" * 64,
        "expected_business_binding": "b" * 64,
        "expected_partner_id": 301,
        "expected_journal_id": 401,
        "expected_currency_id": 1,
        "expected_payment_term_line_id": 1003,
        "expected_payment_term_account_id": 504,
        "expected_invoice_date": "2026-07-30",
        "expected_accounting_date": "2026-07-30",
        "expected_due_date": "2026-08-29",
        "expected_reference": "V3-DRAFT-101",
        "expected_amount_untaxed": "100.00",
        "expected_amount_tax": "0.00",
        "expected_amount_total": "100.00",
        "expected_amount_residual": "100.00",
        "expected_line_ids": [1001, 1002, 1003],
        "reason": "Approved posting of a verified V3 draft",
        "idempotency_key": f"post-{move_type}-101",
    }


def _refund_cancel_parameters(move_type: str = "out_refund") -> dict[str, object]:
    return {
        "company_id": 7,
        "move_id": 201,
        "expected_move_type": move_type,
        "expected_origin_move_id": 101,
        "expected_document_binding": SHA256,
        "expected_document_binding_v2": "e" * 64,
        "expected_business_binding": "b" * 64,
        "expected_origin_document_binding": "c" * 64,
        "expected_origin_document_binding_v2": "f" * 64,
        "expected_origin_business_binding": "d" * 64,
        "expected_partner_id": 301,
        "expected_journal_id": 401,
        "expected_currency_id": 1,
        "expected_refund_date": "2026-07-30",
        "expected_total_amount": "109.00",
        "expected_line_ids": [2001, 2002, 2003],
        "expected_origin_line_ids": [1001, 1002, 1003],
        "reason": "Duplicate unposted credit note",
        "idempotency_key": "cancel-refund-201",
    }


@pytest.mark.parametrize(
    ("capability_id", "move_type", "policy"),
    [
        (
            "acct.invoice.customer_post.v1",
            "out_invoice",
            "customer_invoice_post",
        ),
        ("acct.bill.vendor_post.v1", "in_invoice", "vendor_bill_post"),
    ],
)
def test_document_post_registry_contract_is_complete_and_closed(
    capability_id: str,
    move_type: str,
    policy: str,
) -> None:
    item = _registry_by_id()[capability_id]

    assert item["access"] == "write"
    assert item["risk_level"] == "critical"
    assert item["company_scope"] == "explicit_single_company"
    assert item["odoo_permissions"] == ["account.group_account_invoice"]
    assert item["approval"] == {
        "required": True,
        "policy": policy,
        "ttl_seconds": 600,
    }
    assert item["idempotency"] == {
        "required": True,
        "scope": "company_origin_move",
    }
    assert item["evidence"] == {"level": "declared", "receipts": []}
    assert item.get("staged_environments", []) == []
    assert item["enabled_environments"] == []
    input_schema = item["input_schema"]
    assert set(input_schema["properties"]) == DOCUMENT_POST_FIELDS
    assert set(input_schema["required"]) == DOCUMENT_POST_FIELDS
    assert input_schema["additionalProperties"] is False
    assert input_schema["properties"]["expected_move_type"]["enum"] == [
        move_type
    ]
    for field in (
        "expected_document_binding",
        "expected_document_binding_v2",
        "expected_business_binding",
    ):
        assert input_schema["properties"][field] == DIGEST_SCHEMA
    assert item["verification"] == {
        "method": (
            "read_back_exact_company_currency_taxless_"
            + (
                "customer_invoice"
                if move_type == "out_invoice"
                else "vendor_bill"
            )
            + "_with_term_account_and_allowlisted_delta"
        )
    }
    validate_value(_document_post_parameters(move_type), input_schema)


def test_refund_draft_cancel_registry_contract_is_complete_and_closed() -> None:
    item = _registry_by_id()["acct.refund.draft_cancel.v1"]

    assert item["access"] == "write"
    assert item["risk_level"] == "high"
    assert item["company_scope"] == "explicit_single_company"
    assert item["odoo_permissions"] == ["account.group_account_invoice"]
    assert item["approval"] == {
        "required": True,
        "policy": "refund_draft_cancel",
        "ttl_seconds": 600,
    }
    assert item["idempotency"] == {
        "required": True,
        "scope": "company_origin_move",
    }
    assert item["recovery"] == {
        "method": "not_applicable_unposted_refund_cancel_is_terminal"
    }
    assert item["evidence"] == {"level": "declared", "receipts": []}
    assert item.get("staged_environments", []) == []
    assert item["enabled_environments"] == []
    input_schema = item["input_schema"]
    assert set(input_schema["properties"]) == REFUND_CANCEL_FIELDS
    assert set(input_schema["required"]) == REFUND_CANCEL_FIELDS
    assert input_schema["additionalProperties"] is False
    assert input_schema["properties"]["expected_move_type"]["enum"] == [
        "out_refund",
        "in_refund",
    ]
    for field in (
        "expected_document_binding",
        "expected_document_binding_v2",
        "expected_business_binding",
        "expected_origin_document_binding",
        "expected_origin_document_binding_v2",
        "expected_origin_business_binding",
    ):
        assert input_schema["properties"][field] == DIGEST_SCHEMA
    assert item["verification"] == {
        "method": (
            "read_back_exact_cancelled_refund_and_unchanged_origin_graph_"
            "v1_v2_business_bindings_and_allowlisted_audit_delta_v1"
        )
    }
    validate_value(_refund_cancel_parameters(), input_schema)


@pytest.mark.parametrize(
    ("capability_id", "parameters"),
    [
        (
            "acct.invoice.customer_post.v1",
            _document_post_parameters("out_invoice"),
        ),
        ("acct.bill.vendor_post.v1", _document_post_parameters("in_invoice")),
        ("acct.refund.draft_cancel.v1", _refund_cancel_parameters()),
    ],
)
def test_dev259_write_contracts_reject_missing_extra_and_duplicate_graphs(
    capability_id: str,
    parameters: dict[str, object],
) -> None:
    schema = _registry_by_id()[capability_id]["input_schema"]

    binding_fields = {
        field for field in parameters if "binding" in field
    }
    assert "expected_document_binding" in binding_fields
    assert "expected_document_binding_v2" in binding_fields
    assert "expected_business_binding" in binding_fields
    for field in binding_fields:
        missing = copy.deepcopy(parameters)
        missing.pop(field)
        with pytest.raises(ContractError, match="missing required"):
            validate_value(missing, schema)

        invalid = copy.deepcopy(parameters)
        invalid[field] = "A" * 64
        with pytest.raises(ContractError, match="required pattern"):
            validate_value(invalid, schema)

    extra = copy.deepcopy(parameters)
    extra["approval_signature"] = "caller-controlled"
    with pytest.raises(ContractError, match="unknown fields"):
        validate_value(extra, schema)

    duplicate = copy.deepcopy(parameters)
    duplicate["expected_line_ids"] = [1001, 1001]
    with pytest.raises(ContractError, match="duplicate"):
        validate_value(duplicate, schema)

    float_company = copy.deepcopy(parameters)
    float_company["company_id"] = 7.0
    with pytest.raises(ContractError, match="invalid type"):
        validate_value(float_company, schema)


@pytest.mark.parametrize(
    ("capability_id", "candidate_ids"),
    [
        (
            "acct.move.document_post_eligibility.v1",
            {
                "acct.invoice.customer_post.v1",
                "acct.bill.vendor_post.v1",
            },
        ),
        (
            "acct.refund.draft_cancel_eligibility.v1",
            {"acct.refund.draft_cancel.v1"},
        ),
    ],
)
def test_dev259_eligibility_reads_are_strict_staged_contracts(
    capability_id: str,
    candidate_ids: set[str],
) -> None:
    item = _registry_by_id()[capability_id]

    assert item["access"] == "read"
    assert item["risk_level"] == "medium"
    assert item["company_scope"] == "explicit_single_company"
    assert item["odoo_permissions"] == ["account.group_account_invoice"]
    assert item["approval"] == {"required": False}
    assert item["idempotency"] == {"required": False}
    assert item["evidence"] == {"level": "contract_tested", "receipts": []}
    assert item["staged_environments"] == ["test"]
    assert item["enabled_environments"] == []
    assert item["verification"] == {
        "method": ELIGIBILITY_VERIFICATION_METHODS[capability_id]
    }
    input_schema = item["input_schema"]
    output_schema = item["output_schema"]
    assert set(input_schema["properties"]) == {
        "company_id",
        "move_id",
        "expected_move_type",
    }
    assert set(input_schema["required"]) == {
        "company_id",
        "move_id",
        "expected_move_type",
    }
    assert input_schema["additionalProperties"] is False
    candidate_schema = output_schema["properties"][
        "candidate_write_capability_id"
    ]
    assert set(candidate_schema["enum"]) == candidate_ids
    required_user_parameters = output_schema["properties"][
        "required_user_parameters"
    ]
    assert required_user_parameters["type"] == "array"
    assert set(required_user_parameters["items"]["enum"]) == {
        "idempotency_key",
        "reason",
    }

    write_parameters = next(
        branch
        for branch in output_schema["properties"]["write_parameters"]["oneOf"]
        if branch["type"] == "object"
    )
    expected_write_fields = (
        DOCUMENT_POST_FIELDS
        if capability_id == "acct.move.document_post_eligibility.v1"
        else REFUND_CANCEL_FIELDS
    ) - {"reason", "idempotency_key"}
    assert set(write_parameters["properties"]) == expected_write_fields
    assert set(write_parameters["required"]) == expected_write_fields
    assert write_parameters["additionalProperties"] is False
    by_id = _registry_by_id()
    for field in expected_write_fields - {"expected_move_type"}:
        for candidate_id in candidate_ids:
            assert write_parameters["properties"][field] == by_id[
                candidate_id
            ]["input_schema"]["properties"][field]
    candidate_move_types = {
        move_type
        for candidate_id in candidate_ids
        for move_type in by_id[candidate_id]["input_schema"]["properties"][
            "expected_move_type"
        ]["enum"]
    }
    assert set(
        write_parameters["properties"]["expected_move_type"]["enum"]
    ) == candidate_move_types

    target = output_schema["properties"]["target"]
    if capability_id == "acct.move.document_post_eligibility.v1":
        assert set(target["properties"]) == DOCUMENT_POST_TARGET_FIELDS
        assert set(target["required"]) == DOCUMENT_POST_TARGET_FIELDS
        target_records = (target,)
    else:
        assert set(target["properties"]) == {"refund", "origin"}
        assert set(target["required"]) == {"refund", "origin"}
        refund = target["properties"]["refund"]
        origin = target["properties"]["origin"]
        assert set(refund["properties"]) == REFUND_TARGET_FIELDS
        assert set(refund["required"]) == REFUND_TARGET_FIELDS
        assert set(origin["properties"]) == ORIGIN_TARGET_FIELDS
        assert set(origin["required"]) == ORIGIN_TARGET_FIELDS
        target_records = (refund, origin)
    for target_record in target_records:
        for field in (
            "document_binding",
            "document_binding_v2",
            "business_binding",
        ):
            assert target_record["properties"][field] == TARGET_BINDING_SCHEMA


def test_refund_eligibility_exposes_unique_origin_provenance_and_positive_total() -> None:
    by_id = _registry_by_id()
    read_item = by_id["acct.refund.draft_cancel_eligibility.v1"]
    origin_schema = read_item["output_schema"]["properties"]["target"][
        "properties"
    ]["origin"]
    provenance_schema = origin_schema["properties"]["source_posting_mode"]

    assert "source_posting_mode" in origin_schema["required"]
    assert provenance_schema == {
        "oneOf": [
            {
                "type": "string",
                "minLength": 4,
                "maxLength": 5,
                "pattern": "^(?:draft|post)$",
                "enum": ["draft", "post"],
            },
            {"type": "null"},
        ]
    }
    positive_pattern = (
        "^(?:0\\.(?:0*[1-9][0-9]*)|[1-9][0-9]*(?:\\.[0-9]+)?)$"
    )
    read_parameters = next(
        branch
        for branch in read_item["output_schema"]["properties"][
            "write_parameters"
        ]["oneOf"]
        if branch["type"] == "object"
    )
    assert (
        read_parameters["properties"]["expected_total_amount"]["pattern"]
        == positive_pattern
    )
    assert (
        by_id["acct.refund.draft_cancel.v1"]["input_schema"]["properties"][
            "expected_total_amount"
        ]["pattern"]
        == positive_pattern
    )


def test_dev259_write_output_contract_reuses_the_strict_standard_receipt() -> None:
    by_id = _registry_by_id()
    standard = by_id["acct.move.post.v1"]["output_schema"]

    for capability_id in (
        "acct.invoice.customer_post.v1",
        "acct.bill.vendor_post.v1",
        "acct.refund.draft_cancel.v1",
    ):
        assert by_id[capability_id]["output_schema"] == standard
        assert set(standard["required"]) == {
            "operation_id",
            "operation_state",
            "odoo_records",
            "difference",
            "verification",
            "database_finalization",
            "audit_receipt",
            "recovery_plan",
        }

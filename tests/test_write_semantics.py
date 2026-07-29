from __future__ import annotations

import copy

import pytest

from odoo_accounting_cli_v3.domain.write_semantics import (
    WriteSemanticError,
    validate_write_semantics,
)


def invoice_parameters() -> dict:
    return {
        "company_id": 7,
        "partner_id": 101,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15",
        "due_date": "2026-08-14",
        "currency_id": 12,
        "journal_id": 4,
        "posting_mode": "post",
        "reference": "SO-2026-1001",
        "lines": [
            {
                "line_reference": "1",
                "name": "Consulting",
                "product_id": None,
                "account_id": 400,
                "quantity": "2",
                "price_unit": "125.50",
                "tax_ids": [31],
            }
        ],
        "idempotency_key": "invoice-2026-1001",
    }


def bill_parameters() -> dict:
    result = invoice_parameters()
    result.pop("reference")
    result["vendor_reference"] = "VENDOR-881"
    result["idempotency_key"] = "bill-vendor-881"
    return result


def refund_parameters() -> dict:
    return {
        "company_id": 7,
        "origin_move_id": 880,
        "refund_type": "customer_credit_note",
        "refund_mode": "partial",
        "refund_date": "2026-07-16",
        "journal_id": 4,
        "currency_id": 12,
        "expected_total_amount": "125.50",
        "reason": "Service scope reduced",
        "posting_mode": "post",
        "lines": [
            {
                "line_reference": "refund-1",
                "name": "Partial consulting refund",
                "account_id": 400,
                "quantity": "1",
                "price_unit": "125.50",
                "tax_ids": [],
            }
        ],
        "idempotency_key": "refund-880-partial-1",
    }


def payment_parameters() -> dict:
    return {
        "company_id": 7,
        "target_move_ids": [880, 881],
        "partner_id": 101,
        "partner_type": "customer",
        "direction": "inbound",
        "payment_date": "2026-07-16",
        "currency_id": 12,
        "amount": "251.00",
        "journal_id": 9,
        "payment_method_line_id": 3,
        "memo": "Customer remittance 991",
        "idempotency_key": "payment-remittance-991",
    }


def bank_parameters() -> dict:
    return {
        "company_id": 7,
        "journal_id": 9,
        "statement_date": "2026-07-16",
        "currency_id": 12,
        "external_reference": "BANK-2026-07-16",
        "source_digest": "a" * 64,
        "source_filename": "bank-20260716.csv",
        "opening_balance": "1000.00",
        "closing_balance": "1125.50",
        "lines": [
            {
                "external_transaction_id": "BANK-0001",
                "transaction_date": "2026-07-16",
                "value_date": "2026-07-16",
                "direction": "credit",
                "amount": "125.50",
                "foreign_currency_id": None,
                "foreign_amount": None,
                "summary": "Receipt",
                "partner_id": 101,
                "source_line_digest": "b" * 64,
            }
        ],
        "idempotency_key": "bank-a",
    }


def reconcile_parameters() -> dict:
    return {
        "company_id": 7,
        "line_ids": [1001, 1002],
        "account_id": 22,
        "partner_id": 101,
        "reconciliation_date": "2026-07-16",
        "currency_id": 12,
        "mode": "full",
        "amount": "125.50",
        "tolerance_amount": "0",
        "writeoff_account_id": None,
        "writeoff_journal_id": None,
        "writeoff_label": None,
        "idempotency_key": "reconcile-1001-1002",
    }


def asset_parameters() -> dict:
    return {
        "company_id": 7,
        "source_move_line_id": 1001,
        "asset_model_id": 11,
        "asset_name": "Laptop pool July 2026",
        "acquisition_date": "2026-07-01",
        "currency_id": 12,
        "acquisition_value": "12000.00",
        "posting_mode": "confirm",
        "idempotency_key": "asset-source-1001",
    }


def depreciation_parameters() -> dict:
    return {
        "company_id": 7,
        "asset_id": 51,
        "depreciation_move_id": 71,
        "period_start": "2026-07-01",
        "period_end": "2026-07-31",
        "posting_date": "2026-07-31",
        "journal_id": 4,
        "currency_id": 12,
        "amount": "1000.00",
        "idempotency_key": "depreciation-71",
    }


def journal_lines() -> list[dict]:
    return [
        {
            "line_reference": "debit",
            "account_id": 600,
            "partner_id": None,
            "name": "Accrued service",
            "side": "debit",
            "amount": "100.00",
            "amount_currency": "100.00",
            "currency_id": 12,
            "tax_ids": [],
        },
        {
            "line_reference": "credit",
            "account_id": 700,
            "partner_id": None,
            "name": "Accrued liability",
            "side": "credit",
            "amount": "100.00",
            "amount_currency": "-100.00",
            "currency_id": 12,
            "tax_ids": [],
        },
    ]


def accrual_parameters() -> dict:
    return {
        "company_id": 7,
        "journal_id": 4,
        "posting_date": "2026-07-31",
        "reversal_date": "2026-08-01",
        "currency_id": 12,
        "reference": "July service accrual",
        "posting_mode": "post",
        "lines": journal_lines(),
        "idempotency_key": "accrual-july-service",
    }


def deferred_parameters() -> dict:
    return {
        "company_id": 7,
        "source_move_line_id": 1001,
        "deferred_type": "expense",
        "schedule_start_date": "2026-07-01",
        "schedule_end_date": "2027-06-30",
        "expected_generation_method": "on_validation",
        "amount_computation_method": "month",
        "expected_deferred_account_id": 480,
        "expected_deferred_journal_id": 4,
        "currency_id": 12,
        "total_amount": "12000.00",
        "posting_mode": "post",
        "idempotency_key": "deferred-source-1001",
    }


def adjustment_parameters() -> dict:
    result = {
        "company_id": 7,
        "journal_id": 4,
        "posting_date": "2026-07-31",
        "period_end_date": "2026-07-31",
        "currency_id": 12,
        "reference": "July close adjustment",
        "reason": "Correct expense classification",
        "posting_mode": "post",
        "lines": journal_lines(),
        "idempotency_key": "adjustment-july-1",
    }
    return result


def journal_entry_create_parameters() -> dict:
    return {
        "company_id": 7,
        "journal_id": 4,
        "posting_date": "2026-07-31",
        "currency_id": 12,
        "reference": "Manual reclassification 2026-07",
        "reason": "Approved reclassification",
        "posting_mode": "draft",
        "lines": journal_lines(),
        "idempotency_key": "journal-entry-july-reclassification",
    }


def move_post_parameters() -> dict:
    return {
        "company_id": 7,
        "move_id": 882,
        "expected_move_type": "entry",
        "expected_document_binding": "d" * 64,
        "expected_business_binding": "e" * 64,
        "expected_journal_id": 4,
        "expected_currency_id": 12,
        "expected_posting_date": "2026-07-31",
        "expected_reference": "Manual reclassification 2026-07",
        "expected_total_debit": "100.00",
        "expected_total_credit": "100.00",
        "expected_line_count": 2,
        "reason": "Approved posting",
        "idempotency_key": "post-move-882",
    }


def reversal_parameters() -> dict:
    return {
        "company_id": 7,
        "move_id": 880,
        "reversal_date": "2026-07-16",
        "journal_id": 4,
        "currency_id": 12,
        "expected_total_amount": "251.00",
        "reason": "Approved correction",
        "posting_mode": "post",
        "idempotency_key": "reverse-880",
    }


def draft_cancel_parameters() -> dict:
    return {
        "company_id": 7,
        "move_id": 881,
        "expected_move_type": "out_invoice",
        "expected_document_binding": "a" * 64,
        "expected_business_binding": "b" * 64,
        "reason": "Cancel duplicate pristine draft",
        "idempotency_key": "cancel-draft-881",
    }


def draft_cancel_v2_parameters() -> dict:
    result = draft_cancel_parameters()
    result.update(
        {
            "expected_move_type": "entry",
            "expected_line_ids": [2001, 2002],
            "idempotency_key": "cancel-draft-entry-881",
        }
    )
    return result


def recovery_parameters() -> dict:
    return {
        "company_id": 7,
        "origin_operation_id": "op-1001",
        "expected_recovery_plan_digest": "c" * 64,
        "recovery_date": "2026-07-16",
        "reason": "Approved compensation",
        "idempotency_key": "recover-op-1001",
    }


VALID_CASES = {
    "acct.invoice.customer_create.v1": invoice_parameters,
    "acct.bill.vendor_create.v1": bill_parameters,
    "acct.refund.create.v1": refund_parameters,
    "acct.payment.register.v1": payment_parameters,
    "acct.bank.statement_import.v1": bank_parameters,
    "acct.reconciliation.apply.v1": reconcile_parameters,
    "acct.asset.create.v1": asset_parameters,
    "acct.depreciation.post.v1": depreciation_parameters,
    "acct.accrual.create.v1": accrual_parameters,
    "acct.deferred.create.v1": deferred_parameters,
    "acct.period.adjustment_create.v1": adjustment_parameters,
    "acct.journal.entry_create.v1": journal_entry_create_parameters,
    "acct.move.post.v1": move_post_parameters,
    "acct.move.reverse.v1": reversal_parameters,
    "acct.move.draft_cancel.v1": draft_cancel_parameters,
    "acct.move.draft_cancel.v2": draft_cancel_v2_parameters,
    "acct.recovery.execute.v1": recovery_parameters,
}


@pytest.mark.parametrize(("capability_id", "factory"), VALID_CASES.items())
def test_all_write_capabilities_have_cross_field_semantics(capability_id, factory):
    result = validate_write_semantics(capability_id, factory())

    assert result["capability_id"] == capability_id
    assert result["company_id"] == 7
    assert result["checks"]


def test_invoice_rejects_due_date_before_invoice_date_and_zero_effect():
    parameters = invoice_parameters()
    parameters["due_date"] = "2026-07-14"
    with pytest.raises(WriteSemanticError, match="due_date"):
        validate_write_semantics("acct.invoice.customer_create.v1", parameters)

    parameters = invoice_parameters()
    parameters["lines"][0]["price_unit"] = "0"
    with pytest.raises(WriteSemanticError, match="positive total"):
        validate_write_semantics("acct.invoice.customer_create.v1", parameters)


def test_refund_full_and_partial_line_rules_are_fail_closed():
    full = refund_parameters()
    full["refund_mode"] = "full"
    with pytest.raises(WriteSemanticError, match="full refund"):
        validate_write_semantics("acct.refund.create.v1", full)

    partial = refund_parameters()
    partial["lines"] = []
    with pytest.raises(WriteSemanticError, match="partial refund"):
        validate_write_semantics("acct.refund.create.v1", partial)


def test_bank_balances_foreign_pairs_dates_and_unique_external_ids():
    parameters = bank_parameters()
    parameters["closing_balance"] = "1125.51"
    with pytest.raises(WriteSemanticError, match="closing balance"):
        validate_write_semantics("acct.bank.statement_import.v1", parameters)

    parameters = bank_parameters()
    parameters["lines"][0]["foreign_currency_id"] = 2
    with pytest.raises(WriteSemanticError, match="foreign currency"):
        validate_write_semantics("acct.bank.statement_import.v1", parameters)

    parameters = bank_parameters()
    parameters["lines"][0]["foreign_currency_id"] = 2
    parameters["lines"][0]["foreign_amount"] = "-20.00"
    with pytest.raises(WriteSemanticError, match="sign"):
        validate_write_semantics("acct.bank.statement_import.v1", parameters)

    parameters = bank_parameters()
    parameters["lines"][0].update(
        {
            "direction": "debit",
            "foreign_currency_id": 2,
            "foreign_amount": "-20.00",
        }
    )
    parameters["closing_balance"] = "874.50"
    validate_write_semantics("acct.bank.statement_import.v1", parameters)

    parameters = bank_parameters()
    duplicate = copy.deepcopy(parameters["lines"][0])
    duplicate["source_line_digest"] = "d" * 64
    parameters["lines"].append(duplicate)
    parameters["closing_balance"] = "1251.00"
    with pytest.raises(WriteSemanticError, match="external transaction"):
        validate_write_semantics("acct.bank.statement_import.v1", parameters)


def test_reconciliation_writeoff_and_partial_rules_are_consistent():
    parameters = reconcile_parameters()
    parameters["tolerance_amount"] = "0.01"
    with pytest.raises(WriteSemanticError, match="write-off fields"):
        validate_write_semantics("acct.reconciliation.apply.v1", parameters)

    parameters = reconcile_parameters()
    parameters["mode"] = "partial"
    parameters["writeoff_account_id"] = 99
    parameters["writeoff_journal_id"] = 4
    parameters["writeoff_label"] = "Difference"
    with pytest.raises(WriteSemanticError, match="partial reconciliation"):
        validate_write_semantics("acct.reconciliation.apply.v1", parameters)

    parameters = reconcile_parameters()
    parameters["tolerance_amount"] = "126.00"
    with pytest.raises(WriteSemanticError, match="cannot exceed"):
        validate_write_semantics("acct.reconciliation.apply.v1", parameters)

    parameters = reconcile_parameters()
    parameters["writeoff_account_id"] = 99
    parameters["writeoff_journal_id"] = 4
    parameters["writeoff_label"] = "Unapproved zero write-off"
    with pytest.raises(WriteSemanticError, match="zero tolerance"):
        validate_write_semantics("acct.reconciliation.apply.v1", parameters)


@pytest.mark.parametrize(
    "capability_id,factory",
    (
        ("acct.accrual.create.v1", accrual_parameters),
        ("acct.period.adjustment_create.v1", adjustment_parameters),
        ("acct.journal.entry_create.v1", journal_entry_create_parameters),
    ),
)
def test_manual_entries_require_balanced_company_and_transaction_currency(
    capability_id, factory
):
    parameters = factory()
    parameters["lines"][1]["amount"] = "99.99"
    with pytest.raises(WriteSemanticError, match="company currency"):
        validate_write_semantics(capability_id, parameters)

    parameters = factory()
    parameters["lines"][1]["amount_currency"] = "-99.99"
    with pytest.raises(WriteSemanticError, match="transaction currency"):
        validate_write_semantics(capability_id, parameters)


def test_manual_entries_require_signed_currency_amounts_and_unique_lines():
    parameters = accrual_parameters()
    parameters["lines"][1]["amount_currency"] = "100.00"
    with pytest.raises(WriteSemanticError, match="credit.*negative"):
        validate_write_semantics("acct.accrual.create.v1", parameters)

    parameters = accrual_parameters()
    parameters["lines"][1]["line_reference"] = "debit"
    with pytest.raises(WriteSemanticError, match="line_reference"):
        validate_write_semantics("acct.accrual.create.v1", parameters)


def test_journal_entry_create_is_draft_only_tax_free_and_explicit():
    parameters = journal_entry_create_parameters()
    parameters["posting_mode"] = "post"
    with pytest.raises(WriteSemanticError, match="posting_mode must be draft"):
        validate_write_semantics("acct.journal.entry_create.v1", parameters)

    parameters = journal_entry_create_parameters()
    parameters["lines"][0]["tax_ids"] = [31]
    with pytest.raises(WriteSemanticError, match="tax_ids must be empty"):
        validate_write_semantics("acct.journal.entry_create.v1", parameters)

    parameters = journal_entry_create_parameters()
    parameters["lines"][0]["account_id"] = 0
    with pytest.raises(WriteSemanticError, match=r"lines\[0\]\.account_id"):
        validate_write_semantics("acct.journal.entry_create.v1", parameters)

    parameters = journal_entry_create_parameters()
    parameters["lines"][0]["partner_id"] = 0
    with pytest.raises(WriteSemanticError, match=r"lines\[0\]\.partner_id"):
        validate_write_semantics("acct.journal.entry_create.v1", parameters)

    parameters = journal_entry_create_parameters()
    parameters["reference"] = "   "
    with pytest.raises(WriteSemanticError, match="reference"):
        validate_write_semantics("acct.journal.entry_create.v1", parameters)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        ("move_id", 0, "move_id"),
        ("expected_move_type", "out_invoice", "expected_move_type"),
        ("expected_document_binding", "not-a-digest", "document_binding"),
        ("expected_business_binding", "A" * 64, "business_binding"),
        ("expected_journal_id", 0, "expected_journal_id"),
        ("expected_currency_id", False, "expected_currency_id"),
        ("expected_posting_date", "2026-02-30", "expected_posting_date"),
        ("expected_total_debit", "0", "expected_total_debit"),
        ("expected_total_credit", "1e2", "expected_total_credit"),
        ("expected_line_count", 1, "expected_line_count"),
        ("expected_reference", " ", "expected_reference"),
        ("reason", "", "reason"),
    ),
)
def test_move_post_binds_exact_pristine_manual_entry(field, value, error):
    parameters = move_post_parameters()
    parameters[field] = value
    with pytest.raises(WriteSemanticError, match=error):
        validate_write_semantics("acct.move.post.v1", parameters)


def test_move_post_requires_equal_positive_totals_and_bounded_line_count():
    parameters = move_post_parameters()
    parameters["expected_total_credit"] = "99.99"
    with pytest.raises(WriteSemanticError, match="must equal"):
        validate_write_semantics("acct.move.post.v1", parameters)

    parameters = move_post_parameters()
    parameters["expected_line_count"] = 251
    with pytest.raises(WriteSemanticError, match="expected_line_count"):
        validate_write_semantics("acct.move.post.v1", parameters)

    result = validate_write_semantics("acct.move.post.v1", move_post_parameters())
    assert result["computed"]["expected_total_debit"] == "100.00"
    assert result["computed"]["expected_total_credit"] == "100.00"
    assert result["computed"]["expected_line_count"] == 2


def test_dates_for_accrual_depreciation_deferred_and_period_adjustment():
    parameters = accrual_parameters()
    parameters["reversal_date"] = parameters["posting_date"]
    with pytest.raises(WriteSemanticError, match="reversal_date"):
        validate_write_semantics("acct.accrual.create.v1", parameters)

    parameters = accrual_parameters()
    parameters["posting_mode"] = "draft"
    with pytest.raises(WriteSemanticError, match="posting_mode must be post"):
        validate_write_semantics("acct.accrual.create.v1", parameters)

    parameters = depreciation_parameters()
    parameters["posting_date"] = "2026-08-01"
    with pytest.raises(WriteSemanticError, match="posting_date"):
        validate_write_semantics("acct.depreciation.post.v1", parameters)

    parameters = depreciation_parameters()
    parameters["posting_date"] = parameters["period_start"]
    with pytest.raises(WriteSemanticError, match="period_end"):
        validate_write_semantics("acct.depreciation.post.v1", parameters)

    parameters = deferred_parameters()
    parameters["schedule_end_date"] = "2026-06-30"
    with pytest.raises(WriteSemanticError, match="schedule"):
        validate_write_semantics("acct.deferred.create.v1", parameters)

    parameters = adjustment_parameters()
    parameters["posting_date"] = "2026-07-30"
    with pytest.raises(WriteSemanticError, match="period_end_date"):
        validate_write_semantics("acct.period.adjustment_create.v1", parameters)


def test_reversal_semantics_fail_closed_to_post_only():
    parameters = reversal_parameters()
    parameters["posting_mode"] = "draft"

    with pytest.raises(WriteSemanticError, match="posting_mode must be post"):
        validate_write_semantics("acct.move.reverse.v1", parameters)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        ("move_id", 0, "move_id"),
        ("expected_move_type", "entry", "expected_move_type"),
        ("expected_document_binding", "not-a-digest", "document_binding"),
        ("expected_business_binding", "A" * 64, "business_binding"),
    ),
)
def test_draft_cancel_semantics_bind_exact_pristine_document(
    field, value, error
):
    parameters = draft_cancel_parameters()
    parameters[field] = value
    with pytest.raises(WriteSemanticError, match=error):
        validate_write_semantics("acct.move.draft_cancel.v1", parameters)


@pytest.mark.parametrize("move_type", ("entry", "out_invoice", "in_invoice"))
def test_draft_cancel_v2_accepts_only_supported_pristine_move_types(move_type):
    parameters = draft_cancel_v2_parameters()
    parameters["expected_move_type"] = move_type

    result = validate_write_semantics("acct.move.draft_cancel.v2", parameters)

    assert result["computed"]["expected_move_type"] == move_type
    assert result["computed"]["expected_line_count"] == 2


@pytest.mark.parametrize(
    ("mutate", "error"),
    (
        (
            lambda value: value.update(expected_move_type="out_refund"),
            "expected_move_type",
        ),
        (
            lambda value: value.update(expected_document_binding="not-a-digest"),
            "document_binding",
        ),
        (
            lambda value: value.update(expected_line_ids=[2001]),
            "expected_line_ids",
        ),
        (
            lambda value: value.update(expected_line_ids=[2001, 2001]),
            "expected_line_ids must be unique",
        ),
        (
            lambda value: value.update(expected_line_ids=[2001, 0]),
            "expected_line_ids",
        ),
        (
            lambda value: value.update(expected_line_ids=list(range(1, 1002))),
            "expected_line_ids",
        ),
        (
            lambda value: value.update(reason=" "),
            "reason",
        ),
    ),
)
def test_draft_cancel_v2_requires_exact_bindings_and_line_set(mutate, error):
    parameters = draft_cancel_v2_parameters()
    mutate(parameters)

    with pytest.raises(WriteSemanticError, match=error):
        validate_write_semantics("acct.move.draft_cancel.v2", parameters)


def test_depreciation_requires_real_asset_move_reference():
    parameters = depreciation_parameters()
    parameters.pop("depreciation_move_id")
    parameters["depreciation_line_id"] = 71
    with pytest.raises(WriteSemanticError, match="depreciation_move_id"):
        validate_write_semantics("acct.depreciation.post.v1", parameters)

    parameters = depreciation_parameters()
    parameters["depreciation_move_id"] = 0
    with pytest.raises(WriteSemanticError, match="depreciation_move_id"):
        validate_write_semantics("acct.depreciation.post.v1", parameters)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        ("expected_generation_method", "manual", "on_validation"),
        ("amount_computation_method", "quarter", "amount_computation_method"),
        ("posting_mode", "draft", "posting_mode"),
        ("expected_deferred_account_id", 0, "expected_deferred_account_id"),
        ("expected_deferred_journal_id", 0, "expected_deferred_journal_id"),
    ),
)
def test_deferred_uses_only_odoo19_on_validation_contract(field, value, error):
    parameters = deferred_parameters()
    parameters[field] = value
    with pytest.raises(WriteSemanticError, match=error):
        validate_write_semantics("acct.deferred.create.v1", parameters)


def test_unknown_capability_and_non_object_parameters_are_rejected():
    with pytest.raises(WriteSemanticError, match="unsupported"):
        validate_write_semantics("acct.unknown.write.v1", {})
    with pytest.raises(WriteSemanticError, match="object"):
        validate_write_semantics("acct.invoice.customer_create.v1", [])

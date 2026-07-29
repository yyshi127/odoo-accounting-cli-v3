from __future__ import annotations

import ast
import copy
import hashlib
import json
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import odoo_accounting_cli_v3.odoo.write_bootstrap as write_bootstrap
from odoo_accounting_cli_v3.auth import sign_request_context
from odoo_accounting_cli_v3.gateway import RequestContext
from odoo_accounting_cli_v3.draft_invoice_recovery import (
    customer_invoice_business_binding,
    customer_invoice_document_binding,
    vendor_bill_business_binding,
    vendor_bill_document_binding,
)
from odoo_accounting_cli_v3.odoo.write_bootstrap import (
    OdooWriteBootstrapError,
    _bank_recovery_journal_from_precheck,
    _default_handler_factory,
    _difference,
    _execution_evidence,
    _lock_live_precheck_records,
    _resource_lock_digests,
    execute_write_from_odoo_shell,
)
from odoo_accounting_cli_v3.odoo.write_precheck import (
    canonical_precheck_evidence,
)
from odoo_accounting_cli_v3.odoo.module_graph import (
    OPTIONAL_FIELD_PROVIDERS,
    build_trusted_module_graph,
)
from odoo_accounting_cli_v3.operations import (
    State,
    approve_operation,
    begin_execution,
    canonical_json,
    record_precheck,
    sign_approval,
)
from odoo_accounting_cli_v3.registry import registry_digest, validate_registry
from odoo_accounting_cli_v3.write_protocol import (
    approved_write_authentication_parameters,
    approval_to_mapping,
    operation_to_mapping,
    trusted_result_from_mapping,
)
from odoo_accounting_cli_v3.write_receipts import create_recovery_plan_v2
from odoo_accounting_cli_v3.write_service import _ALLOWED_MODELS


NOW = datetime(2026, 7, 15, 4, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
AUTH_SECRET = b"auth-secret-material-at-least-32-bytes"
APPROVAL_SECRET = b"approval-secret-material-at-least-32"
EXECUTION_SECRET = b"execution-secret-material-at-least-32"
VERIFICATION_SECRET = b"verification-secret-material-32-bytes"
RELEASE_DIGEST = "d" * 64
SOURCE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "odoo_accounting_cli_v3"
    / "odoo"
    / "write_bootstrap.py"
)
_TEST_MODULE_NAMES = {
    "account",
    *(
        module
        for fields in OPTIONAL_FIELD_PROVIDERS.values()
        for providers in fields.values()
        for module in providers
    ),
}
TEST_MODULE_GRAPH = build_trusted_module_graph(
    [
        {"name": name, "latest_version": "19.0.test"}
        for name in sorted(_TEST_MODULE_NAMES)
    ]
)


def test_overlapping_accounting_resources_share_a_stable_advisory_lock():
    first = _resource_lock_digests(
        "acct.reconciliation.apply.v1",
        7,
        {"line_ids": [502, 501]},
        None,
    )
    reordered = _resource_lock_digests(
        "acct.reconciliation.apply.v1",
        7,
        {"line_ids": [501, 502]},
        None,
    )
    overlapping = _resource_lock_digests(
        "acct.reconciliation.apply.v1",
        7,
        {"line_ids": [502, 503]},
        None,
    )

    assert first == reordered
    assert len(first) == 2
    assert len(set(first) & set(overlapping)) == 1
    assert first == sorted(first)
    assert all(len(value) == 64 for value in first)


def test_generic_bank_recovery_combines_graph_and_sequence_locks_once():
    action = {
        "model": "account.bank.statement",
        "record_id": 100,
        "company_id": 7,
        "record_state": "posted",
        "record_fingerprint": "a" * 64,
    }
    guard = {
        "model": "account.bank.statement.line",
        "record_id": 101,
        "company_id": 7,
        "record_state": "posted",
        "record_fingerprint": "b" * 64,
        "expected_outcome": "survive_exact",
    }
    plan = create_recovery_plan_v2(
        origin_operation_id="bank-import-op",
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="post_compensating_bank_statement_v1",
        requires_approval=True,
        action_targets=[action],
        guard_records=[guard],
        oracle_id="post_compensating_bank_statement_exact_v1",
        parameters={"company_id": 7},
    )
    parameters = {
        "company_id": 7,
        "origin_operation_id": "bank-import-op",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "recovery_date": "2026-07-29",
        "reason": "approved compensation",
        "idempotency_key": "bank-recovery-1",
    }
    graph_only = _resource_lock_digests(
        "acct.recovery.execute.v1", 7, parameters, plan
    )
    combined = _resource_lock_digests(
        "acct.recovery.execute.v1",
        7,
        parameters,
        plan,
        bank_statement_journal_id=2,
    )
    specialized = _resource_lock_digests(
        "acct.bank.statement_compensate.v1",
        7,
        {"expected_journal_id": 2},
        plan,
    )

    assert len(graph_only) == 2
    assert combined == specialized
    assert len(combined) == 3
    assert combined == sorted(set(combined))

    def snapshot(model, record_id, values):
        return {
            "model": model,
            "record_id": record_id,
            "company_id": 7,
            "state": "posted",
            "values": values,
            "values_digest": hashlib.sha256(
                canonical_json(values)
            ).hexdigest(),
        }

    evidence = {
        "handler_details": {
            "before": [
                snapshot(
                    "account.bank.statement",
                    100,
                    {"journal_id": [2, "Bank"]},
                ),
                snapshot(
                    "account.bank.statement.line",
                    101,
                    {"journal_id": [2, "Bank"]},
                ),
            ],
            "dependencies": [],
            "strict_dependencies": [
                snapshot(
                    "account.journal",
                    2,
                    {"company_id": [7, "Company"]},
                )
            ],
        }
    }
    assert _bank_recovery_journal_from_precheck(
        evidence, company_id=7, trusted_recovery_plan=plan
    ) == 2

    missing = copy.deepcopy(evidence)
    missing["handler_details"]["strict_dependencies"] = []
    with pytest.raises(
        OdooWriteBootstrapError, match="dependency is not exact"
    ):
        _bank_recovery_journal_from_precheck(
            missing, company_id=7, trusted_recovery_plan=plan
        )

    duplicate = copy.deepcopy(evidence)
    duplicate["handler_details"]["strict_dependencies"].append(
        snapshot(
            "account.journal",
            3,
            {"company_id": [7, "Company"]},
        )
    )
    with pytest.raises(
        OdooWriteBootstrapError, match="dependency is not exact"
    ):
        _bank_recovery_journal_from_precheck(
            duplicate, company_id=7, trusted_recovery_plan=plan
        )

    cross_company = copy.deepcopy(evidence)
    cross_company["handler_details"]["strict_dependencies"][0][
        "company_id"
    ] = 8
    with pytest.raises(
        OdooWriteBootstrapError, match="binding is invalid"
    ):
        _bank_recovery_journal_from_precheck(
            cross_company, company_id=7, trusted_recovery_plan=plan
        )


def test_draft_cancel_uses_the_same_move_resource_lock_as_move_reversal():
    draft_cancel = _resource_lock_digests(
        "acct.move.draft_cancel.v1",
        7,
        {"move_id": 501},
        None,
    )
    reversal = _resource_lock_digests(
        "acct.move.reverse.v1",
        7,
        {"move_id": 501},
        None,
    )

    assert draft_cancel == reversal
    assert len(draft_cancel) == 1


def test_phase_b_move_capabilities_have_exact_move_model_allowlists():
    expected = frozenset({"account.move", "account.move.line"})

    assert _ALLOWED_MODELS["acct.journal.entry_create.v1"] == expected
    assert _ALLOWED_MODELS["acct.move.post.v1"] == expected
    assert _ALLOWED_MODELS["acct.move.draft_cancel.v2"] == expected


def test_payment_cancel_has_exact_models_locks_and_exclusive_before_graph():
    assert _ALLOWED_MODELS["acct.payment.cancel.v1"] == frozenset(
        {"account.payment", "account.move", "account.move.line"}
    )
    parameters = {
        "payment_id": 500,
        "move_id": 501,
        "expected_line_ids": [502, 503],
    }
    locks = _resource_lock_digests(
        "acct.payment.cancel.v1", 7, parameters, None
    )
    reordered = _resource_lock_digests(
        "acct.payment.cancel.v1",
        7,
        {**parameters, "expected_line_ids": [503, 502]},
        None,
    )
    move_lock = _resource_lock_digests(
        "acct.move.reverse.v1", 7, {"move_id": 501}, None
    )

    assert locks == reordered
    assert locks == sorted(locks)
    assert len(locks) == len(set(locks)) == 4
    assert len(set(locks) & set(move_lock)) == 1
    assert (
        "acct.payment.cancel.v1"
        in write_bootstrap.EXCLUSIVE_BEFORE_LOCK_CAPABILITIES
    )


def test_phase_b_journal_entry_create_locks_the_journal_reference():
    parameters = {"journal_id": 5, "reference": "ENTRY-2026-001"}

    phase_b = _resource_lock_digests(
        "acct.journal.entry_create.v1", 7, parameters, None
    )
    existing = _resource_lock_digests(
        "acct.period.adjustment_create.v1", 7, parameters, None
    )

    assert phase_b == existing
    assert len(phase_b) == 1


def test_phase_b_post_and_cancel_share_the_existing_move_resource_lock():
    parameters = {"move_id": 501}
    expected = _resource_lock_digests(
        "acct.move.reverse.v1", 7, parameters, None
    )

    assert _resource_lock_digests(
        "acct.move.post.v1", 7, parameters, None
    ) == expected
    assert _resource_lock_digests(
        "acct.move.draft_cancel.v2", 7, parameters, None
    ) == expected
    assert len(expected) == 1


def test_phase_b_post_and_cancel_require_exclusive_before_graph_locks():
    assert {
        "acct.move.post.v1",
        "acct.move.draft_cancel.v2",
    } <= write_bootstrap.EXCLUSIVE_BEFORE_LOCK_CAPABILITIES


def test_difference_marks_every_created_record_absent_before_it_exists():
    values = {
        "company_id": 7,
        "state": "posted",
        "line_ids": [502, 503],
    }
    raw_after = {
        "model": "account.move",
        "record_id": 501,
        "company_id": 7,
        "state": "posted",
        "values": values,
        "values_digest": hashlib.sha256(canonical_json(values)).hexdigest(),
    }

    difference, records = _difference([], [raw_after], 7)

    assert difference["before"] == [
        {
            "model": "account.move",
            "record_id": 501,
            "exists": False,
            "record_state": "absent",
            "values_json": "{}",
            "values_digest": hashlib.sha256(b"{}").hexdigest(),
        }
    ]
    assert difference["after"][0]["exists"] is True
    assert set(difference["changed_fields"]) == {
        "company_id",
        "line_ids",
        "record_state",
        "state",
    }
    assert records[0]["record_id"] == 501


def test_execution_difference_rejects_a_graph_too_large_for_the_receipt_contract():
    after = []
    for record_id in range(1, 902):
        values = {"company_id": 7, "state": "posted"}
        after.append(
            {
                "model": "account.move.line",
                "record_id": record_id,
                "company_id": 7,
                "state": "posted",
                "values": values,
                "values_digest": hashlib.sha256(
                    canonical_json(values)
                ).hexdigest(),
            }
        )

    with pytest.raises(OdooWriteBootstrapError, match="auditable record limit"):
        _difference([], after, 7)


def test_difference_ignores_only_the_display_label_of_the_same_line_move_relation():
    def line_snapshot(move_id, display_name):
        values = {
            "move_id": [move_id, display_name],
            "company_id": [7, "Sandbox Company"],
        }
        return {
            "model": "account.move.line",
            "record_id": 502,
            "company_id": 7,
            "state": "unknown",
            "values": values,
            "values_digest": hashlib.sha256(canonical_json(values)).hexdigest(),
        }

    difference, _records = _difference(
        [line_snapshot(501, "Draft Invoice INV/1")],
        [line_snapshot(501, "Cancelled Invoice INV/1")],
        7,
    )
    assert difference["changed_fields"] == []

    reparented, _records = _difference(
        [line_snapshot(501, "Draft Invoice INV/1")],
        [line_snapshot(999, "Other Move")],
        7,
    )
    assert reparented["changed_fields"] == ["move_id"]


def _draft_invoice_available_raw(
    operation,
    *,
    guard_record_ids=(502,),
    action_overrides=None,
    line_overrides=None,
):
    vendor = operation.capability_id == "acct.bill.vendor_create.v1"

    def raw_snapshot(model, record_id, state, values):
        return {
            "model": model,
            "record_id": record_id,
            "company_id": operation.company_id,
            "state": state,
            "values": values,
            "values_digest": hashlib.sha256(canonical_json(values)).hexdigest(),
        }

    line_ids = [502, 503]
    after = [
        raw_snapshot(
            "account.move",
            501,
            "draft",
            {
                "state": "draft",
                "name": "/",
                "move_type": "in_invoice" if vendor else "out_invoice",
                "company_id": [7, "Sandbox Company"],
                "journal_id": [
                    operation.parameters["journal_id"],
                    "Purchases" if vendor else "Sales",
                ],
                "currency_id": [operation.parameters["currency_id"], "USD"],
                "partner_id": [
                    operation.parameters["partner_id"],
                    "Vendor" if vendor else "Customer",
                ],
                "date": operation.parameters["accounting_date"],
                "invoice_date": operation.parameters["invoice_date"],
                "invoice_date_due": operation.parameters["due_date"],
                "invoice_line_ids": [502],
                "invoice_payment_term_id": False,
                "ref": operation.parameters.get(
                    "vendor_reference",
                    operation.parameters.get("reference", False),
                ),
                "line_ids": line_ids,
                "journal_line_ids": line_ids,
                "posted_before": False,
                "auto_post": "no",
                "auto_post_until": False,
                "secure_sequence_number": 0,
                "sequence_prefix": False,
                "sequence_number": 0,
                "made_sequence_gap": False,
                "inalterable_hash": False,
                "checked": False,
                "is_manually_modified": False,
                "need_cancel_request": False,
                "auto_post_origin_id": False,
                "origin_payment_id": False,
                "payment_ids": [],
                "matched_payment_ids": [],
                "reconciled_payment_ids": [],
                "statement_line_id": False,
                "statement_id": False,
                "tax_cash_basis_rec_id": False,
                "tax_cash_basis_origin_move_id": False,
                "tax_cash_basis_created_move_ids": [],
                "reversed_entry_id": False,
                "reversal_move_ids": [],
                "adjusting_entry_origin_move_ids": [],
                "adjusting_entries_move_ids": [],
                "exchange_diff_partial_ids": [],
                "statement_line_ids": [],
                "closing_return_id": False,
                "transfer_model_id": False,
                "transaction_ids": [],
                "authorized_transaction_ids": [],
                "purchase_id": False,
                "asset_id": False,
                "asset_ids": [],
                "deferred_move_ids": [],
                "deferred_original_move_ids": [],
                "edi_document_ids": [],
                "expense_ids": [],
                "pos_order_ids": [],
                "stock_move_ids": [],
                "landed_costs_ids": [],
                "debit_note_ids": [],
                "debit_origin_id": False,
                "invoice_pdf_report_id": False,
                "invoice_vendor_bill_id": False,
                "purchase_vendor_bill_id": False,
                "ubl_cii_xml_id": False,
                "l10n_es_edi_facturae_xml_id": False,
                "invoice_pdf_report_file": {"present": False},
                "l10n_es_edi_facturae_xml_file": {"present": False},
                "ubl_cii_xml_file": {"present": False},
                "signature": {"present": False},
                "signing_user": False,
                "is_move_sent": False,
                "sending_data": False,
                "is_being_sent": False,
                "invoice_source_email": False,
                "attachment_ids": [],
                "message_main_attachment_id": False,
                "audit_trail_message_ids": [],
                "activity_ids": [],
                "message_follower_ids": [],
                "message_ids": [],
                "rating_ids": [],
                "website_message_ids": [],
                "access_token": {"present": False},
                "fiscal_position_id": False,
                "invoice_cash_rounding_id": False,
                "invoice_incoterm_id": False,
                "incoterm_location": False,
                "partner_shipping_id": False,
                "partner_bank_id": False,
                "preferred_payment_method_line_id": False,
                "l10n_latam_document_type_id": False,
                "invoice_origin": False,
                "narration": False,
                "quick_edit_total_amount": "0",
                "always_tax_exigible": False,
                "is_storno": False,
                "asset_value_change": False,
                "campaign_id": False,
                "medium_id": False,
                "source_id": False,
                "team_id": False,
                "delivery_date": False,
                "fapiao": False,
                "invoice_currency_rate": "1",
                "invoice_user_id": [42, "V3 Executor"],
                "l10n_es_edi_facturae_reason_code": False,
                "l10n_es_invoicing_period_start_date": False,
                "l10n_es_invoicing_period_end_date": False,
                "l10n_es_is_simplified": False,
                "l10n_es_payment_means": False,
                "payment_reference": False,
                "payment_state_before_switch": False,
                "qr_code_method": False,
                "taxable_supply_date": False,
                "asset_depreciation_beginning_date": False,
                "asset_number_days": 0,
                "depreciation_value": "0",
                "create_uid": [42, "V3 Executor"],
                "create_date": "2026-07-10 09:00:00",
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-10 09:00:00",
                "odoo_cli_v3_document_binding": (
                    vendor_bill_document_binding(operation.parameters)
                    if vendor
                    else customer_invoice_document_binding(operation.parameters)
                ),
                "odoo_cli_v3_business_binding": (
                    vendor_bill_business_binding(operation.parameters)
                    if vendor
                    else customer_invoice_business_binding(operation.parameters)
                ),
                **(action_overrides or {}),
            },
        ),
        raw_snapshot(
            "account.move.line",
            502,
            "unknown",
            {
                "company_id": [7, "Sandbox Company"],
                "move_id": [501, "/"],
                "account_id": [10, "Receivable"],
                "currency_id": [operation.parameters["currency_id"], "USD"],
                "parent_state": "draft",
                "reconciled": False,
                "full_reconcile_id": False,
                "matched_debit_ids": [],
                "matched_credit_ids": [],
                "asset_ids": [],
                "sale_line_ids": [],
                "analytic_distribution": False,
                "analytic_line_ids": [],
                "tax_ids": [],
                "tax_line_id": False,
                "tax_repartition_line_id": False,
                "tax_tag_ids": [],
                "payment_id": False,
                "statement_line_id": False,
                "statement_id": False,
                "purchase_line_id": False,
                "purchase_order_id": False,
                "expense_id": False,
                "group_tax_id": False,
                "distribution_analytic_account_ids": [],
                "reconcile_model_id": False,
                "reconciled_lines_ids": [],
                "reconciled_lines_excluding_exchange_diff_ids": [],
                "parent_id": False,
                "cogs_origin_id": False,
                "is_landed_costs_line": False,
                "deferred_start_date": False,
                "deferred_end_date": False,
                "move_attachment_ids": [],
                "tax_base_amount": "0",
                "extra_tax_data": False,
                "deductible_amount": "0",
                "is_imported": False,
                "is_downpayment": False,
                "is_storno": False,
                "sequence": 10,
                "product_uom_id": False,
                "discount": "0",
                "discount_date": False,
                "discount_amount_currency": "0",
                "discount_balance": "0",
                "l10n_latam_document_type_id": False,
                "no_followup": False,
                "collapse_composition": False,
                "collapse_prices": False,
                "date_maturity": False,
                "matching_number": False,
                "name": "Invoice line",
                "partner_id": [operation.parameters["partner_id"], "Partner"],
                "price_unit": "100",
                "product_id": False,
                "quantity": "1",
                "create_uid": [42, "V3 Executor"],
                "create_date": "2026-07-10 09:00:00",
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-10 09:00:00",
                "display_type": "product",
                "debit": "100",
                "credit": "0",
                "balance": "100",
                "amount_currency": "100",
                "odoo_cli_v3_line_reference": "line-1",
                **(line_overrides or {}),
            },
        ),
        raw_snapshot(
            "account.move.line",
            503,
            "unknown",
            {
                "company_id": [7, "Sandbox Company"],
                "move_id": [501, "/"],
                "account_id": [20, "Revenue"],
                "currency_id": [operation.parameters["currency_id"], "USD"],
                "parent_state": "draft",
                "reconciled": False,
                "full_reconcile_id": False,
                "matched_debit_ids": [],
                "matched_credit_ids": [],
                "asset_ids": [],
                "sale_line_ids": [],
                "analytic_distribution": False,
                "analytic_line_ids": [],
                "tax_ids": [],
                "tax_line_id": False,
                "tax_repartition_line_id": False,
                "tax_tag_ids": [],
                "payment_id": False,
                "statement_line_id": False,
                "statement_id": False,
                "purchase_line_id": False,
                "purchase_order_id": False,
                "expense_id": False,
                "group_tax_id": False,
                "distribution_analytic_account_ids": [],
                "reconcile_model_id": False,
                "reconciled_lines_ids": [],
                "reconciled_lines_excluding_exchange_diff_ids": [],
                "parent_id": False,
                "cogs_origin_id": False,
                "is_landed_costs_line": False,
                "deferred_start_date": False,
                "deferred_end_date": False,
                "move_attachment_ids": [],
                "tax_base_amount": "0",
                "extra_tax_data": False,
                "deductible_amount": "0",
                "is_imported": False,
                "is_downpayment": False,
                "is_storno": False,
                "sequence": 20,
                "product_uom_id": False,
                "discount": "0",
                "discount_date": False,
                "discount_amount_currency": "0",
                "discount_balance": "0",
                "l10n_latam_document_type_id": False,
                "no_followup": False,
                "collapse_composition": False,
                "collapse_prices": False,
                "date_maturity": operation.parameters["due_date"],
                "matching_number": False,
                "name": "Payment term",
                "partner_id": [operation.parameters["partner_id"], "Partner"],
                "price_unit": "0",
                "product_id": False,
                "quantity": "0",
                "create_uid": [42, "V3 Executor"],
                "create_date": "2026-07-10 09:00:00",
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-10 09:00:00",
                "display_type": "payment_term",
                "debit": "0",
                "credit": "100",
                "balance": "-100",
                "amount_currency": "-100",
                "odoo_cli_v3_line_reference": "line-2",
                **(line_overrides or {}),
            },
        ),
    ]
    return {
        "capability_id": operation.capability_id,
        "company_id": operation.company_id,
        "parameters_digest": hashlib.sha256(
            canonical_json(operation.parameters)
        ).hexdigest(),
        "module_graph": TEST_MODULE_GRAPH.evidence,
        "before": [],
        "after": after,
        "records": [
            {"model": item["model"], "record_id": item["record_id"]}
            for item in after
        ],
        "recovery": {
            "status": "available",
            "method": (
                "cancel_pristine_v3_draft_vendor_bill_v1"
                if vendor
                else "cancel_pristine_v3_draft_customer_invoice_v1"
            ),
            "targets": [{"model": "account.move", "record_id": 501}],
            "guards": [
                {"model": "account.move.line", "record_id": record_id}
                for record_id in guard_record_ids
            ],
            "oracle_id": (
                "cancel_pristine_v3_draft_vendor_bill_exact_v1"
                if vendor
                else "cancel_pristine_v3_draft_customer_invoice_exact_v1"
            ),
        },
    }


def test_draft_customer_invoice_descriptor_becomes_receipt_derived_available_v2_plan():
    parameters = {**_parameters(), "posting_mode": "draft"}
    _context_value, operation, _approval = _executing(parameters)

    evidence = _execution_evidence(
        operation, _draft_invoice_available_raw(operation, guard_record_ids=(503, 502))
    )

    plan = evidence["recovery_plan"]
    assert plan["plan_version"] == 2
    assert plan["status"] == "available"
    assert plan["method"] == "cancel_pristine_v3_draft_customer_invoice_v1"
    assert plan["oracle_id"] == (
        "cancel_pristine_v3_draft_customer_invoice_exact_v1"
    )
    assert [(item["model"], item["record_id"]) for item in plan["action_targets"]] == [
        ("account.move", 501)
    ]
    assert {
        (item["model"], item["record_id"])
        for item in plan["guard_records"]
    } == {
        ("account.move.line", 502),
        ("account.move.line", 503),
    }
    assert plan["guard_records"] == sorted(
        plan["guard_records"], key=canonical_json
    )
    assert all(
        item["expected_outcome"] == "survive_allowed_delta"
        for item in plan["guard_records"]
    )
    assert evidence["recovery_parameters"] == {
        "company_id": 7,
        "origin_operation_id": operation.operation_id,
        "module_graph_digest": TEST_MODULE_GRAPH.digest,
        "method": "cancel_pristine_v3_draft_customer_invoice_v1",
        "action_targets": [{"model": "account.move", "record_id": 501}],
        "guard_records": [
            {"model": "account.move.line", "record_id": 502},
            {"model": "account.move.line", "record_id": 503},
        ],
        "oracle_id": "cancel_pristine_v3_draft_customer_invoice_exact_v1",
    }


def test_draft_vendor_bill_descriptor_becomes_receipt_derived_available_v2_plan():
    parameters = {**_vendor_parameters(), "posting_mode": "draft"}
    _context_value, operation, _approval = _executing(
        parameters, capability_id="acct.bill.vendor_create.v1"
    )

    evidence = _execution_evidence(
        operation,
        _draft_invoice_available_raw(operation, guard_record_ids=(503, 502)),
    )

    plan = evidence["recovery_plan"]
    assert plan["status"] == "available"
    assert plan["method"] == "cancel_pristine_v3_draft_vendor_bill_v1"
    assert plan["oracle_id"] == "cancel_pristine_v3_draft_vendor_bill_exact_v1"
    assert evidence["recovery_parameters"] == {
        "company_id": 7,
        "origin_operation_id": operation.operation_id,
        "module_graph_digest": TEST_MODULE_GRAPH.digest,
        "method": "cancel_pristine_v3_draft_vendor_bill_v1",
        "action_targets": [{"model": "account.move", "record_id": 501}],
        "guard_records": [
            {"model": "account.move.line", "record_id": 502},
            {"model": "account.move.line", "record_id": 503},
        ],
        "oracle_id": "cancel_pristine_v3_draft_vendor_bill_exact_v1",
    }


@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_available_recovery_accepts_fields_proven_absent_by_module_graph(
    capability_id,
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )
    absent_modules = _TEST_MODULE_NAMES - {"account"}
    graph = build_trusted_module_graph(
        [
            {"name": name, "latest_version": "19.0.test"}
            for name in sorted(_TEST_MODULE_NAMES - absent_modules)
        ]
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    raw["module_graph"] = graph.evidence
    for snapshot in raw["after"]:
        values = snapshot["values"]
        for field, providers in OPTIONAL_FIELD_PROVIDERS.get(
            snapshot["model"], {}
        ).items():
            if not providers & graph.installed_modules:
                values.pop(field, None)
        snapshot["values_digest"] = hashlib.sha256(
            canonical_json(values)
        ).hexdigest()

    evidence = _execution_evidence(operation, raw)

    assert evidence["module_graph"] == graph.evidence
    assert evidence["recovery_plan"]["status"] == "available"


def test_available_recovery_rejects_field_presence_that_contradicts_module_graph():
    parameters = {**_parameters(), "posting_mode": "draft"}
    _context_value, operation, _approval = _executing(parameters)
    graph = build_trusted_module_graph(
        [
            {"name": name, "latest_version": "19.0.test"}
            for name in sorted(_TEST_MODULE_NAMES - {"point_of_sale"})
        ]
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    raw["module_graph"] = graph.evidence

    with pytest.raises(OdooWriteBootstrapError, match="schema differs"):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize("field", ["stock_move_ids", "landed_costs_ids"])
def test_draft_vendor_bill_descriptor_requires_stock_effect_fields(field):
    parameters = {**_vendor_parameters(), "posting_mode": "draft"}
    _context_value, operation, _approval = _executing(
        parameters, capability_id="acct.bill.vendor_create.v1"
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    action = raw["after"][0]
    action["values"].pop(field)
    action["values_digest"] = hashlib.sha256(
        canonical_json(action["values"])
    ).hexdigest()

    with pytest.raises(
        OdooWriteBootstrapError, match="pristine V3 draft vendor bill"
    ):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize(
    "field",
    [
        "name",
        "auto_post_until",
        "sequence_prefix",
        "sequence_number",
        "made_sequence_gap",
        "checked",
        "statement_line_ids",
        "closing_return_id",
        "transfer_model_id",
        "transaction_ids",
        "authorized_transaction_ids",
        "purchase_id",
        "asset_ids",
        "debit_note_ids",
        "debit_origin_id",
        "invoice_pdf_report_id",
        "invoice_vendor_bill_id",
        "purchase_vendor_bill_id",
        "ubl_cii_xml_id",
        "l10n_es_edi_facturae_xml_id",
        "signature",
        "signing_user",
        "is_move_sent",
        "sending_data",
        "is_being_sent",
        "invoice_source_email",
        "attachment_ids",
        "message_main_attachment_id",
        "audit_trail_message_ids",
        "fiscal_position_id",
        "invoice_cash_rounding_id",
        "invoice_incoterm_id",
        "incoterm_location",
        "partner_shipping_id",
        "partner_bank_id",
        "preferred_payment_method_line_id",
        "l10n_latam_document_type_id",
        "invoice_origin",
        "narration",
        "quick_edit_total_amount",
        "always_tax_exigible",
        "is_storno",
        "create_uid",
        "create_date",
        "write_uid",
        "write_date",
        "date",
    ],
)
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_requires_pristine_external_effect_fields(
    field, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    action = raw["after"][0]
    action["values"].pop(field)
    action["values_digest"] = hashlib.sha256(
        canonical_json(action["values"])
    ).hexdigest()

    with pytest.raises(
        OdooWriteBootstrapError, match="pristine V3 draft"
    ):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "INV/2026/0001"),
        ("auto_post_until", "2026-12-31"),
        ("sequence_prefix", "INV/2026/"),
        ("sequence_number", 1),
        ("made_sequence_gap", True),
        ("checked", True),
    ],
)
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_rejects_non_pristine_sequence_evidence(
    field, value, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )

    with pytest.raises(OdooWriteBootstrapError, match="pristine V3 draft"):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation,
                guard_record_ids=(502, 503),
                action_overrides={field: value},
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("statement_line_ids", [990]),
        ("closing_return_id", [991, "Closing Return"]),
        ("transfer_model_id", [992, "Transfer Model"]),
        ("transaction_ids", [993]),
        ("authorized_transaction_ids", [994]),
        ("purchase_id", [995, "Purchase Order"]),
        ("asset_ids", [996]),
        ("debit_note_ids", [997]),
        ("debit_origin_id", [998, "Debit Origin"]),
        ("invoice_pdf_report_id", [999, "Invoice PDF"]),
        ("invoice_vendor_bill_id", [1000, "Vendor Bill"]),
        ("purchase_vendor_bill_id", [1001, "Purchase Vendor Bill"]),
        ("ubl_cii_xml_id", [1002, "UBL XML"]),
        ("l10n_es_edi_facturae_xml_id", [1003, "Facturae XML"]),
        ("signature", "signed-payload"),
        ("signing_user", [1004, "Signing User"]),
        ("is_move_sent", True),
        ("sending_data", {"mail": "queued"}),
        ("is_being_sent", True),
        ("invoice_source_email", "invoice@example.com"),
        ("attachment_ids", [1005]),
        ("message_main_attachment_id", [1006, "Attachment"]),
    ],
)
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_rejects_extended_move_effects(
    field, value, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )

    with pytest.raises(OdooWriteBootstrapError, match="external effects"):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation,
                guard_record_ids=(502, 503),
                action_overrides={field: value},
            ),
        )


@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_allows_fingerprinted_audit_messages(
    capability_id,
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )

    evidence = _execution_evidence(
        operation,
        _draft_invoice_available_raw(
            operation,
            guard_record_ids=(502, 503),
            action_overrides={"audit_trail_message_ids": [1007]},
        ),
    )

    assert evidence["recovery_plan"]["status"] == "available"


@pytest.mark.parametrize("field", ["cogs_origin_id", "is_landed_costs_line"])
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_requires_stock_effect_line_fields(
    field, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    line = raw["after"][1]
    line["values"].pop(field)
    line["values_digest"] = hashlib.sha256(
        canonical_json(line["values"])
    ).hexdigest()

    with pytest.raises(
        OdooWriteBootstrapError, match="outside the invoice line graph"
    ):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize(
    "field",
    [
        "move_attachment_ids",
        "tax_base_amount",
        "extra_tax_data",
        "deductible_amount",
        "is_imported",
        "is_downpayment",
        "is_storno",
        "sequence",
        "product_uom_id",
        "discount",
        "discount_date",
        "discount_amount_currency",
        "discount_balance",
        "l10n_latam_document_type_id",
        "create_uid",
        "create_date",
        "write_uid",
        "write_date",
        "account_id",
        "currency_id",
        "debit",
        "credit",
        "balance",
        "amount_currency",
        "odoo_cli_v3_line_reference",
    ],
)
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_requires_installed_tax_and_attachment_fields(
    field, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    line = raw["after"][1]
    line["values"].pop(field)
    line["values_digest"] = hashlib.sha256(
        canonical_json(line["values"])
    ).hexdigest()

    with pytest.raises(
        OdooWriteBootstrapError, match="outside the invoice line graph"
    ):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize(
    ("capability_id", "field"),
    [
        ("acct.invoice.customer_create.v1", "analytic_distribution"),
        ("acct.invoice.customer_create.v1", "analytic_line_ids"),
        ("acct.invoice.customer_create.v1", "tax_tag_ids"),
        ("acct.invoice.customer_create.v1", "parent_state"),
        ("acct.invoice.customer_create.v1", "payment_id"),
        ("acct.invoice.customer_create.v1", "statement_id"),
        ("acct.invoice.customer_create.v1", "purchase_order_id"),
        ("acct.invoice.customer_create.v1", "group_tax_id"),
        (
            "acct.invoice.customer_create.v1",
            "distribution_analytic_account_ids",
        ),
        ("acct.invoice.customer_create.v1", "reconcile_model_id"),
        ("acct.invoice.customer_create.v1", "reconciled_lines_ids"),
        (
            "acct.invoice.customer_create.v1",
            "reconciled_lines_excluding_exchange_diff_ids",
        ),
        ("acct.invoice.customer_create.v1", "parent_id"),
        ("acct.bill.vendor_create.v1", "analytic_distribution"),
        ("acct.bill.vendor_create.v1", "analytic_line_ids"),
        ("acct.bill.vendor_create.v1", "tax_tag_ids"),
        ("acct.bill.vendor_create.v1", "parent_state"),
        ("acct.bill.vendor_create.v1", "payment_id"),
        ("acct.bill.vendor_create.v1", "statement_id"),
        ("acct.bill.vendor_create.v1", "purchase_order_id"),
        ("acct.bill.vendor_create.v1", "group_tax_id"),
        (
            "acct.bill.vendor_create.v1",
            "distribution_analytic_account_ids",
        ),
        ("acct.bill.vendor_create.v1", "reconcile_model_id"),
        ("acct.bill.vendor_create.v1", "reconciled_lines_ids"),
        (
            "acct.bill.vendor_create.v1",
            "reconciled_lines_excluding_exchange_diff_ids",
        ),
        ("acct.bill.vendor_create.v1", "parent_id"),
    ],
)
def test_draft_document_descriptor_requires_financial_reporting_line_fields(
    capability_id, field
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    line = raw["after"][1]
    line["values"].pop(field)
    line["values_digest"] = hashlib.sha256(
        canonical_json(line["values"])
    ).hexdigest()

    with pytest.raises(
        OdooWriteBootstrapError, match="outside the invoice line graph"
    ):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("analytic_distribution", {"17": 100}),
        ("analytic_line_ids", [990]),
    ],
)
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_rejects_unapproved_analytic_effects(
    field, value, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )

    with pytest.raises(OdooWriteBootstrapError, match="external effects"):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation,
                guard_record_ids=(502, 503),
                line_overrides={field: value},
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("payment_id", [990, "Payment"]),
        ("statement_id", [991, "Statement"]),
        ("purchase_order_id", [992, "Purchase Order"]),
        ("distribution_analytic_account_ids", [993]),
        ("reconcile_model_id", [994, "Reconcile Model"]),
        ("reconciled_lines_ids", [995]),
        ("reconciled_lines_excluding_exchange_diff_ids", [996]),
        ("move_attachment_ids", [997]),
        ("is_imported", True),
        ("is_downpayment", True),
    ],
)
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_rejects_extended_line_effects(
    field, value, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )

    with pytest.raises(OdooWriteBootstrapError, match="external effects"):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation,
                guard_record_ids=(502, 503),
                line_overrides={field: value},
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cogs_origin_id", [990, "Stock Move"]),
        ("is_landed_costs_line", True),
    ],
)
@pytest.mark.parametrize(
    "capability_id",
    ["acct.invoice.customer_create.v1", "acct.bill.vendor_create.v1"],
)
def test_draft_document_descriptor_rejects_stock_effect_lines(
    field, value, capability_id
):
    parameters = {
        **(
            _vendor_parameters()
            if capability_id == "acct.bill.vendor_create.v1"
            else _parameters()
        ),
        "posting_mode": "draft",
    }
    _context_value, operation, _approval = _executing(
        parameters, capability_id=capability_id
    )

    with pytest.raises(OdooWriteBootstrapError, match="external effects"):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation,
                guard_record_ids=(502, 503),
                line_overrides={field: value},
            ),
        )


@pytest.mark.parametrize(
    "action_overrides",
    [
        {"move_type": "out_invoice"},
        {"odoo_cli_v3_document_binding": "0" * 64},
        {"odoo_cli_v3_business_binding": "0" * 64},
    ],
)
def test_draft_vendor_bill_descriptor_requires_exact_type_and_business_bindings(
    action_overrides,
):
    parameters = {**_vendor_parameters(), "posting_mode": "draft"}
    _context_value, operation, _approval = _executing(
        parameters, capability_id="acct.bill.vendor_create.v1"
    )

    with pytest.raises(
        OdooWriteBootstrapError, match="pristine V3 draft vendor bill"
    ):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation,
                guard_record_ids=(502, 503),
                action_overrides=action_overrides,
            ),
        )


@pytest.mark.parametrize(
    ("method", "oracle_id"),
    [
        (
            "cancel_pristine_v3_draft_vendor_bill_v1",
            "cancel_pristine_v3_draft_customer_invoice_exact_v1",
        ),
        (
            "cancel_pristine_v3_draft_customer_invoice_v1",
            "cancel_pristine_v3_draft_vendor_bill_exact_v1",
        ),
    ],
)
def test_bootstrap_rejects_crossed_customer_vendor_recovery_contract(
    method, oracle_id
):
    parameters = {**_vendor_parameters(), "posting_mode": "draft"}
    _context_value, operation, _approval = _executing(
        parameters, capability_id="acct.bill.vendor_create.v1"
    )
    raw = _draft_invoice_available_raw(
        operation, guard_record_ids=(502, 503)
    )
    raw["recovery"]["method"] = method
    raw["recovery"]["oracle_id"] = oracle_id

    with pytest.raises(
        OdooWriteBootstrapError, match="action contract is invalid"
    ):
        _execution_evidence(operation, raw)


@pytest.mark.parametrize(
    ("parameters_override", "guard_record_ids", "match"),
    [
        ({"posting_mode": "post"}, (502, 503), "draft document recovery graph"),
        ({"posting_mode": "draft"}, (502,), "complete result graph"),
    ],
)
def test_available_recovery_descriptor_rejects_posted_or_incomplete_invoice_graph(
    parameters_override, guard_record_ids, match
):
    parameters = {**_parameters(), **parameters_override}
    _context_value, operation, _approval = _executing(parameters)

    with pytest.raises(OdooWriteBootstrapError, match=match):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation, guard_record_ids=guard_record_ids
            ),
        )


@pytest.mark.parametrize(
    ("action_overrides", "line_overrides", "match"),
    [
        ({"company_id": 7}, {}, "pristine V3 draft"),
        ({"company_id": [True, "x"]}, {}, "pristine V3 draft"),
        ({"company_id": [7]}, {}, "pristine V3 draft"),
        ({"company_id": [7, "x", "extra"]}, {}, "pristine V3 draft"),
        ({"company_id": ["7", "x"]}, {}, "pristine V3 draft"),
        ({"line_ids": [502, True]}, {}, "complete line graph"),
        ({"line_ids": [502, 502, 503]}, {}, "complete line graph"),
        ({"odoo_cli_v3_document_binding": "0" * 64}, {}, "pristine V3 draft"),
        ({"odoo_cli_v3_business_binding": "0" * 64}, {}, "pristine V3 draft"),
        ({"payment_ids": [991]}, {}, "external effects"),
        ({"adjusting_entry_origin_move_ids": [991]}, {}, "external effects"),
        ({"adjusting_entries_move_ids": [991]}, {}, "external effects"),
        ({"exchange_diff_partial_ids": [991]}, {}, "external effects"),
        ({}, {"move_id": 501}, "outside the invoice line graph"),
        ({}, {"reconciled": True}, "external effects"),
    ],
)
def test_available_recovery_descriptor_rejects_ambiguous_relations_or_external_effects(
    action_overrides, line_overrides, match
):
    parameters = {**_parameters(), "posting_mode": "draft"}
    _context_value, operation, _approval = _executing(parameters)

    with pytest.raises(OdooWriteBootstrapError, match=match):
        _execution_evidence(
            operation,
            _draft_invoice_available_raw(
                operation,
                guard_record_ids=(502, 503),
                action_overrides=action_overrides,
                line_overrides=line_overrides,
            ),
        )


def _capabilities():
    document = json.loads(
        (Path(__file__).resolve().parents[1] / "registry" / "capabilities.json").read_text(
            encoding="utf-8"
        )
    )
    selected = []
    for capability_id in (
        "acct.invoice.customer_create.v1",
        "acct.bill.vendor_create.v1",
        "acct.move.draft_cancel.v1",
        "acct.recovery.execute.v1",
    ):
        capability = copy.deepcopy(
            next(
                item
                for item in document["capabilities"]
                if item["id"] == capability_id
            )
        )
        capability["staged_environments"] = ["sandbox"]
        capability["evidence"] = {"level": "contract_tested", "receipts": []}
        selected.append(capability)
    return validate_registry({"schema_version": 1, "capabilities": selected})


CAPABILITIES = _capabilities()
REGISTRY_DIGEST = registry_digest(CAPABILITIES)


def _parameters(*, company_id=7, idempotency_key="invoice-1"):
    return {
        "company_id": company_id,
        "partner_id": 101,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15",
        "due_date": "2026-08-15",
        "currency_id": 12,
        "journal_id": 5,
        "posting_mode": "post",
        "reference": "INV-SANDBOX-1",
        "lines": [
            {
                "line_reference": "line-1",
                "name": "Consulting",
                "product_id": None,
                "account_id": 401,
                "quantity": "1",
                "price_unit": "100.00",
                "tax_ids": [],
            }
        ],
        "idempotency_key": idempotency_key,
    }


def _vendor_parameters(*, company_id=7, idempotency_key="bill-1"):
    parameters = _parameters(
        company_id=company_id, idempotency_key=idempotency_key
    )
    parameters.pop("reference")
    parameters["vendor_reference"] = "BILL-SANDBOX-1"
    return parameters


def _draft_cancel_parameters(
    *, company_id=7, idempotency_key="draft-cancel-501"
):
    return {
        "company_id": company_id,
        "move_id": 501,
        "expected_move_type": "out_invoice",
        "expected_document_binding": "a" * 64,
        "expected_business_binding": "b" * 64,
        "reason": "Cancel duplicate pristine draft",
        "idempotency_key": idempotency_key,
    }


def _recovery_case(
    *,
    company_id=7,
    origin_operation_id="origin-op-1",
    target_record_id=501,
    target_company_id=None,
    idempotency_key="recover-origin-op-1",
):
    target_company_id = target_company_id or company_id
    target = {
        "model": "account.move",
        "record_id": target_record_id,
        "company_id": target_company_id,
        "record_state": "draft",
        "record_fingerprint": hashlib.sha256(
            f"account.move:{target_record_id}:{target_company_id}".encode()
        ).hexdigest(),
    }
    guard = {
        "model": "account.move.line",
        "record_id": target_record_id + 1,
        "company_id": target_company_id,
        "record_state": "unknown",
        "record_fingerprint": hashlib.sha256(
            f"account.move.line:{target_record_id + 1}:{target_company_id}".encode()
        ).hexdigest(),
        "expected_outcome": "survive_allowed_delta",
    }
    plan = create_recovery_plan_v2(
        origin_operation_id=origin_operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="cancel_pristine_v3_draft_customer_invoice_v1",
        requires_approval=True,
        action_targets=[target],
        guard_records=[guard],
        oracle_id="cancel_pristine_v3_draft_customer_invoice_exact_v1",
        parameters={
            "company_id": company_id,
            "origin_operation_id": origin_operation_id,
            "method": "cancel_pristine_v3_draft_customer_invoice_v1",
            "action_targets": [
                {"model": "account.move", "record_id": target_record_id}
            ],
            "guard_records": [
                {
                    "model": "account.move.line",
                    "record_id": target_record_id + 1,
                }
            ],
            "oracle_id": "cancel_pristine_v3_draft_customer_invoice_exact_v1",
        },
    )
    parameters = {
        "company_id": company_id,
        "origin_operation_id": origin_operation_id,
        "expected_recovery_plan_digest": plan["plan_digest"],
        "recovery_date": "2026-07-15",
        "reason": "Approved compensating reversal",
        "idempotency_key": idempotency_key,
    }
    return parameters, plan


def _context(
    parameters,
    *,
    capability_id="acct.invoice.customer_create.v1",
    user_id=42,
    company_id=7,
    allowed=frozenset({7}),
    reconciliation_only=False,
):
    return sign_request_context(
        auth_token_id=f"token-{user_id}-{company_id}",
        principal=f"pi:sandbox:{user_id}",
        odoo_instance_id="odoo19@sandbox",
        database_name="v3_sandbox",
        database_uuid=DATABASE_UUID,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=allowed,
        environment="sandbox",
        capability_id=capability_id,
        parameters=approved_write_authentication_parameters(
            parameters, reconciliation_only
        ),
        issued_at=NOW - timedelta(seconds=30),
        expires_at=NOW + timedelta(minutes=4, seconds=30),
        key_id="auth-v1",
        secret=AUTH_SECRET,
    )


def _reconciliation_context(operation):
    return _context(
        operation.parameters,
        capability_id=operation.capability_id,
        user_id=operation.user_id,
        company_id=operation.company_id,
        allowed=frozenset({operation.company_id}),
        reconciliation_only=True,
    )


def _raw_precheck(capability_id, parameters):
    return {
        "capability_id": capability_id,
        "company_id": parameters["company_id"],
        "parameters_digest": hashlib.sha256(
            canonical_json(parameters)
        ).hexdigest(),
        "checks": ["acl", "company", "parameters"],
        "before": [],
    }


def _preview_digest(context, capability_id, parameters, *, raw_precheck=None):
    evidence = canonical_precheck_evidence(
        raw_precheck or _raw_precheck(capability_id, parameters),
        capability_id=capability_id,
        company_id=parameters["company_id"],
        parameters=parameters,
        context=context,
        actual_database_name="v3_sandbox",
        actual_database_uuid=DATABASE_UUID,
        capability_channel="staged",
        registry_sha256=REGISTRY_DIGEST,
        release_digest=RELEASE_DIGEST,
    )
    return hashlib.sha256(canonical_json(evidence)).hexdigest()


def _executing(
    parameters=None,
    *,
    capability_id="acct.invoice.customer_create.v1",
    company_id=7,
    operation_id="op-1",
    raw_precheck=None,
):
    parameters = parameters or _parameters(company_id=company_id)
    context = _context(
        parameters,
        capability_id=capability_id,
        company_id=company_id,
        allowed=frozenset({company_id}),
    )
    from odoo_accounting_cli_v3.operations import Operation

    capability = next(item for item in CAPABILITIES if item.id == capability_id)
    approval_ttl_seconds = capability.data["approval"]["ttl_seconds"]

    operation = Operation.prepare(
        operation_id=operation_id,
        request_id=f"req-{operation_id}",
        capability_id=capability_id,
        parameters=parameters,
        principal=context.principal,
        user_id=context.user_id,
        company_id=company_id,
        idempotency_key=parameters["idempotency_key"],
        odoo_instance_id=context.odoo_instance_id,
        database_name=context.database_name,
        database_uuid=context.database_uuid,
        environment=context.environment,
        registry_digest=REGISTRY_DIGEST,
        release_digest=RELEASE_DIGEST,
    )
    operation = record_precheck(
        operation,
        precheck_digest=_preview_digest(
            context,
            capability_id,
            parameters,
            raw_precheck=raw_precheck,
        ),
        expected_revision=0,
    )
    operation = operation.transition(State.AWAITING_APPROVAL, expected_revision=1)
    approval = sign_approval(
        operation=operation,
        approver_user_id=77,
        nonce=f"nonce-{operation_id}",
        issued_at=NOW - timedelta(seconds=30),
        expires_at=NOW + timedelta(minutes=4),
        approval_ttl_seconds=approval_ttl_seconds,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )
    operation = approve_operation(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda *_: True,
        consume_nonce=lambda *_: True,
        approval_ttl_seconds=approval_ttl_seconds,
        expected_revision=2,
    )
    operation = begin_execution(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda *_: True,
        approval_ttl_seconds=approval_ttl_seconds,
        expected_revision=3,
    )
    return context, operation, approval


def _context_mapping(context: RequestContext):
    def utc(value):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "allowed_company_ids": sorted(context.allowed_company_ids),
        "audience": context.audience,
        "auth_expires_at": utc(context.auth_expires_at),
        "auth_issued_at": utc(context.auth_issued_at),
        "auth_key_id": context.auth_key_id,
        "auth_request_digest": context.auth_request_digest,
        "auth_signature": context.auth_signature,
        "auth_signature_purpose": context.auth_signature_purpose,
        "auth_signature_version": context.auth_signature_version,
        "auth_token_id": context.auth_token_id,
        "company_id": context.company_id,
        "database_name": context.database_name,
        "database_uuid": context.database_uuid,
        "environment": context.environment,
        "odoo_instance_id": context.odoo_instance_id,
        "principal": context.principal,
        "user_id": context.user_id,
    }


def _request(
    context,
    operation,
    approval,
    *,
    trusted_recovery_plan=None,
    reconciliation_only=False,
):
    return {
        "context": _context_mapping(context),
        "operation": operation_to_mapping(operation),
        "approval": approval_to_mapping(approval),
        "trusted_recovery_plan": trusted_recovery_plan,
        "reconciliation_only": reconciliation_only,
    }


class User:
    def __init__(self, identifier, company_ids, groups):
        self.id = identifier
        self.ids = [identifier]
        self.active = True
        self.company_ids = SimpleNamespace(ids=list(company_ids))
        self._groups = set(groups)

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def exists(self):
        return self

    def has_group(self, group):
        return group in self._groups


class UserModel:
    def __init__(self, users):
        self.users = users

    def browse(self, identifier):
        return self.users[identifier]


class ConfigModel:
    def get_param(self, key):
        assert key == "database.uuid"
        return DATABASE_UUID


class Cursor:
    dbname = "v3_sandbox"

    def __init__(self):
        self.commits = 0
        self.savepoints = 0
        self.rolled_back_savepoints = 0
        self.side_effects = []

    @contextmanager
    def savepoint(self):
        self.savepoints += 1
        side_effects_before = copy.deepcopy(self.side_effects)
        try:
            yield
        except Exception:
            self.side_effects = side_effects_before
            self.rolled_back_savepoints += 1
            raise

    def commit(self):
        self.commits += 1


class BoundEnv:
    def __init__(self, cr, users, anchors, uid=42):
        self.cr = cr
        self.uid = uid
        self.su = False
        self.user = users[uid]
        self.cache_invalidations = 0
        self._models = {
            "res.users": UserModel(users),
            "odoo.accounting.cli.operation": anchors,
        }

    def __getitem__(self, name):
        return self._models[name]

    def invalidate_all(self):
        self.cache_invalidations += 1


class RootEnv:
    def __init__(self, cr):
        self.cr = cr
        self._config = ConfigModel()

    def __getitem__(self, name):
        assert name == "ir.config_parameter"
        return self._config


class Anchor:
    def __init__(self, values):
        for key, value in values.items():
            setattr(self, key, value)
        self.state = "claimed"
        for phase in ("execution", "verification"):
            setattr(self, f"{phase}_evidence_json", False)
            setattr(self, f"{phase}_evidence_digest", False)
            setattr(self, f"{phase}_result_json", False)
            setattr(self, f"{phase}_result_digest", False)
        self.bound_verification_calls = 0
        self.root_verification_calls = 0
        self.resource_locks = []

    def _acquire_resource_locks(self, resource_digests):
        assert self.state == "claimed"
        assert resource_digests == sorted(set(resource_digests))
        self.resource_locks.extend(resource_digests)

    def _record_execution(self, *, evidence, evidence_digest, result, result_digest, succeeded):
        self.execution_evidence_json = canonical_json(evidence).decode()
        self.execution_evidence_digest = evidence_digest
        self.execution_result_json = canonical_json(result).decode()
        self.execution_result_digest = result_digest
        self.state = "committed" if succeeded else "failed"

    def _record_verification(self, *, evidence, evidence_digest, result, result_digest, passed):
        self.bound_verification_calls += 1
        self._store_verification(
            evidence=evidence,
            evidence_digest=evidence_digest,
            result=result,
            result_digest=result_digest,
            passed=passed,
        )

    def _record_committed_verification_from_root(
        self, *, evidence, evidence_digest, result, result_digest, passed
    ):
        self.root_verification_calls += 1
        self._store_verification(
            evidence=evidence,
            evidence_digest=evidence_digest,
            result=result,
            result_digest=result_digest,
            passed=passed,
        )

    def _store_verification(self, *, evidence, evidence_digest, result, result_digest, passed):
        self.verification_evidence_json = canonical_json(evidence).decode()
        self.verification_evidence_digest = evidence_digest
        self.verification_result_json = canonical_json(result).decode()
        self.verification_result_digest = result_digest
        self.state = "verified" if passed else "failed"


class Anchors:
    def __init__(self):
        self.by_scope = {}
        self.claim_calls = 0
        self.lookup_calls = 0

    def _lookup_exact(self, **values):
        self.lookup_calls += 1
        matches = [
            anchor
            for anchor in self.by_scope.values()
            if anchor.operation_id == values["operation_id"]
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise RuntimeError("operation lookup is not unique")
        anchor = matches[0]
        for name, value in values.items():
            if getattr(anchor, name) != value:
                raise RuntimeError("operation lookup immutable binding mismatch")
        return anchor

    def _claim(self, **values):
        self.claim_calls += 1
        key = (values["company_id"], values["capability_id"], values["idempotency_scope"])
        existing = self.by_scope.get(key)
        if existing:
            for name, value in values.items():
                if getattr(existing, name) != value:
                    raise RuntimeError("idempotency scope has different immutable content")
            return existing
        anchor = Anchor(values)
        self.by_scope[key] = anchor
        return anchor


class LockableRecordset:
    def __init__(self, identifier, *, snapshot_state="stable", on_lock=None):
        self.id = identifier
        self.ids = [identifier]
        self.snapshot_state = snapshot_state
        self.on_lock = on_lock
        self.lock_calls = []
        self.invalidations = 0
        self.access_rules = []

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def exists(self):
        return self

    def check_access_rule(self, operation):
        self.access_rules.append(operation)

    def lock_for_update(self, *, allow_referencing=False):
        self.lock_calls.append(allow_referencing)
        if self.on_lock is not None:
            self.on_lock(self)

    def invalidate_recordset(self):
        self.invalidations += 1


class LockableModel:
    def __init__(self, record):
        self.record = record
        self.access = []

    def check_access_rights(self, operation):
        self.access.append(operation)

    def browse(self, identifiers):
        assert list(identifiers) == self.record.ids
        return self.record


class Handler:
    def __init__(self, *, execute_error=None, verify_error=None):
        self.calls = []
        self.precheck_calls = 0
        self.prechecked_executions = []
        self.factory_plans = []
        self.execute_error = execute_error
        self.verify_error = verify_error

    def precheck(self, capability_id, parameters):
        self.precheck_calls += 1
        return _raw_precheck(capability_id, parameters)

    def execute(self, capability_id, parameters):
        self.calls.append("execute")
        if self.execute_error:
            raise self.execute_error
        return {
            "capability_id": capability_id,
            "company_id": parameters["company_id"],
            "parameters_digest": hashlib.sha256(canonical_json(parameters)).hexdigest(),
            "before": [],
            "after": [{
                "model": "account.move", "record_id": 501, "company_id": 7,
                "state": "posted", "values": {"state": "posted", "amount_total": "100.00"},
                "values_digest": hashlib.sha256(
                    canonical_json({"state": "posted", "amount_total": "100.00"})
                ).hexdigest(),
            }],
            "records": [{"model": "account.move", "record_id": 501}],
            "recovery": {
                "status": "manual_escalation",
                "method": "manual_review_move_recovery",
                "targets": [{"model": "account.move", "record_id": 501}],
            },
        }

    def execute_prechecked(self, capability_id, parameters, checked):
        self.prechecked_executions.append(copy.deepcopy(checked))
        return self.execute(capability_id, parameters)

    def verify(self, capability_id, parameters, execution):
        self.calls.append("verify")
        if self.verify_error:
            raise self.verify_error
        after = [{
            "model": "account.move",
            "record_id": 501,
            "company_id": 7,
            "state": "posted",
            "values": {"state": "posted", "amount_total": "100.00"},
            "values_digest": hashlib.sha256(
                canonical_json({"state": "posted", "amount_total": "100.00"})
            ).hexdigest(),
        }]
        return {
            "passed": True,
            "method": "odoo_public_orm_readback_v1",
            "checks": ["record_exists", "state_matches"],
            "after": after,
            "evidence_digest": hashlib.sha256(canonical_json(after)).hexdigest(),
        }


def _dependency_precheck(capability_id, parameters, record):
    result = _raw_precheck(capability_id, parameters)
    values = {"company_id": parameters["company_id"], "state": record.snapshot_state}
    result["dependencies"] = [
        {
            "model": "account.asset",
            "record_id": record.id,
            "company_id": parameters["company_id"],
            "state": record.snapshot_state,
            "values": values,
            "values_digest": hashlib.sha256(canonical_json(values)).hexdigest(),
        }
    ]
    return result


class DependencyHandler(Handler):
    def __init__(self, record):
        super().__init__()
        self.record = record

    def precheck(self, capability_id, parameters):
        self.precheck_calls += 1
        return _dependency_precheck(capability_id, parameters, self.record)

    def execute_prechecked(self, capability_id, parameters, checked):
        assert self.record.lock_calls == [True]
        assert self.record.invalidations == 1
        return super().execute_prechecked(capability_id, parameters, checked)


def _harness(*, handler=None, approver_group=True):
    cr = Cursor()
    anchors = Anchors()
    users = {
        42: User(42, [7, 8], {
            "odoo_accounting_cli_v3_control.group_executor",
            "account.group_account_invoice",
            "account.group_account_manager",
        }),
        77: User(77, [7, 8], {
            "odoo_accounting_cli_v3_control.group_approver" if approver_group else "unrelated.group"
        }),
    }
    bound = BoundEnv(cr, users, anchors)
    anchors.users = users
    anchors.bound_env = bound
    root = RootEnv(cr)
    selected_handler = handler or Handler()
    kwargs = {
        "capabilities": CAPABILITIES,
        "auth_secret": AUTH_SECRET,
        "auth_key_id": "auth-v1",
        "approval_secret": APPROVAL_SECRET,
        "approval_key_id": "approval-v2",
        "execution_secret": EXECUTION_SECRET,
        "execution_key_id": "execution-v2",
        "execution_issuer": "odoo-write-executor",
        "verification_secret": VERIFICATION_SECRET,
        "verification_key_id": "verification-v2",
        "verification_issuer": "odoo-write-verifier",
        "release_digest": RELEASE_DIGEST,
        "odoo_instance_id": "odoo19@sandbox",
        "environment": "sandbox",
        "capability_channel": "staged",
        "now": NOW,
        "environment_factory": lambda _cr, _uid, _context: bound,
        "handler_factory": lambda _env, _context, _now, trusted_plan=None: (
            selected_handler.factory_plans.append(copy.deepcopy(trusted_plan))
            or selected_handler
        ),
        "control_store_factory": lambda _env: anchors,
        "control_lookup_factory": lambda _env: anchors,
        "metadata_execution_scope_factory": nullcontext,
    }
    return root, cr, anchors, selected_handler, kwargs


def test_first_write_commits_atomic_execution_then_verified_readback():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    result = execute_write_from_odoo_shell(root, _request(context, operation, approval), **kwargs)
    assert cr.commits == 2
    assert cr.savepoints == 4
    assert cr.rolled_back_savepoints == 2
    assert handler.calls == ["execute", "verify"]
    assert len(handler.prechecked_executions) == 1
    assert anchors.bound_env.cache_invalidations == 1
    assert len(anchors.by_scope) == 1
    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.state == "verified"
    assert anchor.resource_locks == _resource_lock_digests(
        operation.capability_id,
        operation.company_id,
        operation.parameters,
        None,
    )
    assert anchor.bound_verification_calls == 1
    assert anchor.root_verification_calls == 0
    assert trusted_result_from_mapping(result["execution"]["result"]).succeeded is True
    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded is True
    assert result["verification"]["evidence"]["method"] == (
        CAPABILITIES[0].data["verification"]["method"]
    )
    assert result["execution"]["evidence"]["odoo_records"][0]["record_id"] == 501


def test_generic_bank_recovery_locks_graph_and_sequence_before_row_locks():
    action = {
        "model": "account.bank.statement",
        "record_id": 100,
        "company_id": 7,
        "record_state": "posted",
        "record_fingerprint": "a" * 64,
    }
    guard = {
        "model": "account.bank.statement.line",
        "record_id": 101,
        "company_id": 7,
        "record_state": "posted",
        "record_fingerprint": "b" * 64,
        "expected_outcome": "survive_exact",
    }
    plan = create_recovery_plan_v2(
        origin_operation_id="bank-import-op-lock-order",
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="post_compensating_bank_statement_v1",
        requires_approval=True,
        action_targets=[action],
        guard_records=[guard],
        oracle_id="post_compensating_bank_statement_exact_v1",
        parameters={"company_id": 7},
    )
    parameters = {
        "company_id": 7,
        "origin_operation_id": "bank-import-op-lock-order",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "recovery_date": "2026-07-15",
        "reason": "Approved bank recovery",
        "idempotency_key": "bank-recovery-lock-order",
    }

    def snapshot(model, record_id, values):
        return {
            "model": model,
            "record_id": record_id,
            "company_id": 7,
            "state": "posted",
            "values": values,
            "values_digest": hashlib.sha256(
                canonical_json(values)
            ).hexdigest(),
        }

    raw_precheck = _raw_precheck("acct.recovery.execute.v1", parameters)
    raw_precheck["before"] = [
        snapshot(
            "account.bank.statement",
            100,
            {
                "company_id": [7, "Company"],
                "journal_id": [2, "Bank"],
            },
        ),
        snapshot(
            "account.bank.statement.line",
            101,
            {
                "company_id": [7, "Company"],
                "journal_id": [2, "Bank"],
            },
        ),
    ]
    raw_precheck["strict_dependencies"] = [
        snapshot(
            "account.journal",
            2,
            {"company_id": [7, "Company"]},
        )
    ]
    context, operation, approval = _executing(
        parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="generic-bank-resource-lock-order",
        raw_precheck=raw_precheck,
    )

    class BankHandler(Handler):
        def precheck(self, capability_id, received_parameters):
            assert capability_id == "acct.recovery.execute.v1"
            assert received_parameters == parameters
            self.precheck_calls += 1
            return copy.deepcopy(raw_precheck)

    handler = BankHandler()
    root, _cr, anchors, _selected, kwargs = _harness(handler=handler)
    expected_locks = _resource_lock_digests(
        operation.capability_id,
        operation.company_id,
        operation.parameters,
        plan,
        bank_statement_journal_id=2,
    )

    def assert_resource_locks_precede_rows(_record):
        anchor = next(iter(anchors.by_scope.values()))
        assert anchor.resource_locks == expected_locks

    statement = LockableRecordset(
        100, on_lock=assert_resource_locks_precede_rows
    )
    line = LockableRecordset(
        101, on_lock=assert_resource_locks_precede_rows
    )
    journal = LockableRecordset(
        2, on_lock=assert_resource_locks_precede_rows
    )
    anchors.bound_env._models.update(
        {
            "account.bank.statement": LockableModel(statement),
            "account.bank.statement.line": LockableModel(line),
            "account.journal": LockableModel(journal),
        }
    )

    result = execute_write_from_odoo_shell(
        root,
        _request(
            context,
            operation,
            approval,
            trusted_recovery_plan=plan,
        ),
        **kwargs,
    )

    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.resource_locks == expected_locks
    assert len(anchor.resource_locks) == len(set(anchor.resource_locks)) == 3
    assert statement.lock_calls == [False]
    assert line.lock_calls == [False]
    assert journal.lock_calls == [False]
    assert handler.precheck_calls == 2
    assert trusted_result_from_mapping(
        result["execution"]["result"]
    ).succeeded is True


def test_default_execution_path_locks_reads_and_reverifies_live_module_graph(
    monkeypatch,
):
    parameters = _parameters()
    graph = build_trusted_module_graph(
        [{"name": "account", "latest_version": "19.0.2.0"}]
    )

    class DefaultPathHandler(Handler):
        def __init__(self):
            super().__init__()
            self.module_graph = graph

        def precheck(self, capability_id, values):
            raw = super().precheck(capability_id, values)
            return {
                **raw,
                "module_graph": self.module_graph.evidence,
                "semantic_precheck": {"passed": True},
            }

        def execute(self, capability_id, values):
            return {
                **super().execute(capability_id, values),
                "module_graph": self.module_graph.evidence,
            }

        def verify(self, capability_id, values, execution):
            assert execution["module_graph"] == self.module_graph.evidence
            return super().verify(capability_id, values, execution)

    handler = DefaultPathHandler()
    raw_precheck = handler.precheck(
        "acct.invoice.customer_create.v1", parameters
    )
    context, operation, approval = _executing(
        parameters, raw_precheck=raw_precheck
    )
    _root, cr, anchors, _selected_handler, kwargs = _harness(handler=handler)
    lock_statements = []
    cr.execute = lock_statements.append

    class ModuleRecords:
        def read(self, fields):
            assert fields == ["name", "latest_version", "state"]
            return [
                {
                    "name": "account",
                    "latest_version": "19.0.2.0",
                    "state": "installed",
                }
            ]

    class ModuleModel:
        def with_context(self, **context_values):
            assert context_values == {"active_test": False}
            return self

        def search(self, domain, *, order):
            assert domain == [("state", "=", "installed")]
            assert order == "name, id"
            return ModuleRecords()

    class DefaultRootEnv(RootEnv):
        su = True

        def __getitem__(self, name):
            if name == "ir.module.module":
                return ModuleModel()
            return super().__getitem__(name)

    observed_graphs = []

    def default_factory(
        bound_env,
        _context_value,
        _observed_at,
        _trusted_plan,
        module_graph,
    ):
        assert bound_env.su is False
        observed_graphs.append(module_graph)
        handler.module_graph = module_graph
        return handler

    monkeypatch.setattr(
        write_bootstrap, "_default_handler_factory", default_factory
    )
    kwargs["handler_factory"] = None

    result = execute_write_from_odoo_shell(
        DefaultRootEnv(cr),
        _request(context, operation, approval),
        **kwargs,
    )

    assert [item.digest for item in observed_graphs] == [graph.digest, graph.digest]
    assert lock_statements == [
        "LOCK TABLE ir_module_module IN SHARE MODE",
        "LOCK TABLE ir_module_module IN SHARE MODE",
    ]
    assert handler.calls == ["execute", "verify"]
    assert next(iter(anchors.by_scope.values())).state == "verified"
    assert result["verification"]["evidence"]["passed"] is True
    assert result["verification"]["evidence"]["readback"]["records"] == (
        result["execution"]["evidence"]["odoo_records"]
    )
    assert len(
        result["verification"]["evidence"]["readback"]["fresh_snapshots"]
    ) == 1
    assert set(result["execution"]["evidence"]) == {
        "operation_id", "capability_id", "succeeded", "odoo_records",
        "difference", "recovery_plan", "recovery_parameters", "module_graph",
        "failure_checks",
    }
    assert set(result["verification"]["evidence"]["readback"]) == {
        "company_id",
        "records",
        "fresh_snapshots",
        "fresh_snapshots_digest",
        "request_parameters_digest",
        "control_anchor",
    }


def test_normal_verification_rolls_back_handler_side_effect_before_control_commit():
    context, operation, approval = _executing()

    class WritingVerifier(Handler):
        cursor = None

        def verify(self, capability_id, parameters, execution):
            self.cursor.side_effects.append("forbidden verify ORM write")
            return super().verify(capability_id, parameters, execution)

    writing = WritingVerifier()
    root, cr, anchors, handler, kwargs = _harness(handler=writing)
    writing.cursor = cr

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert result["reconciliation_only"] is False
    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded
    assert cr.side_effects == []
    assert cr.commits == 2
    assert next(iter(anchors.by_scope.values())).state == "verified"


def test_metadata_authority_scope_wraps_only_approved_handler_execution():
    active = False
    observations: list[tuple[str, bool]] = []

    @contextmanager
    def metadata_scope():
        nonlocal active
        assert active is False
        active = True
        try:
            yield
        finally:
            active = False

    class ScopeHandler(Handler):
        def precheck(self, capability_id, parameters):
            observations.append(("precheck", active))
            return super().precheck(capability_id, parameters)

        def execute_prechecked(self, capability_id, parameters, checked):
            observations.append(("execute", active))
            return super().execute_prechecked(capability_id, parameters, checked)

        def verify(self, capability_id, parameters, execution):
            observations.append(("verify", active))
            return super().verify(capability_id, parameters, execution)

    context, operation, approval = _executing()
    root, _cr, _anchors, _handler, kwargs = _harness(handler=ScopeHandler())
    kwargs["metadata_execution_scope_factory"] = metadata_scope

    execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert observations == [
        ("precheck", False),
        ("execute", True),
        ("verify", False),
    ]
    assert active is False


def test_default_metadata_scope_is_lazily_loaded_from_the_odoo_addon(
    monkeypatch: pytest.MonkeyPatch,
):
    active = False
    imported: list[str] = []

    @contextmanager
    def scope():
        nonlocal active
        active = True
        try:
            yield
        finally:
            active = False

    module = SimpleNamespace(_accounting_metadata_execution_scope=scope)

    def import_module(name):
        imported.append(name)
        return module

    monkeypatch.setattr(write_bootstrap.importlib, "import_module", import_module)
    with write_bootstrap._default_metadata_execution_scope():
        assert active is True

    assert active is False
    assert imported == [write_bootstrap.METADATA_SCOPE_MODULE]

    monkeypatch.setattr(
        write_bootstrap.importlib,
        "import_module",
        lambda _name: SimpleNamespace(),
    )
    with pytest.raises(OdooWriteBootstrapError, match="scope is unavailable"):
        write_bootstrap._default_metadata_execution_scope()


def test_verification_rebinds_to_a_new_environment_after_the_business_commit():
    context, operation, approval = _executing()
    root, cr, anchors, _handler, kwargs = _harness()
    events = []
    first_env = anchors.bound_env
    second_env = BoundEnv(cr, anchors.users, anchors)
    original_invalidate = first_env.invalidate_all
    original_commit = cr.commit

    def invalidate_first_env():
        events.append("invalidate:first")
        original_invalidate()

    def commit():
        original_commit()
        events.append(f"commit:{cr.commits}")

    first_env.invalidate_all = invalidate_first_env
    cr.commit = commit
    environments = iter([first_env, second_env])
    kwargs["environment_factory"] = lambda _cr, _uid, _context: next(
        environments
    )

    class PhaseHandler(Handler):
        def __init__(self, label):
            super().__init__()
            self.label = label

        def precheck(self, capability_id, parameters):
            events.append(f"precheck:{self.label}")
            return super().precheck(capability_id, parameters)

        def execute_prechecked(self, capability_id, parameters, checked):
            assert cr.commits == 0
            events.append(f"execute:{self.label}")
            return super().execute_prechecked(capability_id, parameters, checked)

        def verify(self, capability_id, parameters, execution):
            assert cr.commits == 1
            events.append(f"verify:{self.label}")
            return super().verify(capability_id, parameters, execution)

    first_handler = PhaseHandler("first")
    second_handler = PhaseHandler("second")
    kwargs["handler_factory"] = lambda env, *_args: (
        first_handler if env is first_env else second_handler
    )

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded is True
    assert first_handler.calls == ["execute"]
    assert second_handler.calls == ["verify"]
    assert first_env.cache_invalidations == 1
    assert second_env.cache_invalidations == 0
    assert events == [
        "precheck:first",
        "execute:first",
        "commit:1",
        "invalidate:first",
        "verify:second",
        "commit:2",
    ]


def test_same_signed_request_replays_verified_anchor_without_another_write_or_commit():
    context, operation, approval = _executing()
    root, cr, _anchors, handler, kwargs = _harness()
    request = _request(context, operation, approval)
    first = execute_write_from_odoo_shell(root, request, **kwargs)
    second = execute_write_from_odoo_shell(root, request, **kwargs)
    assert second == first
    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 2
    assert _anchors.bound_env.cache_invalidations == 1


def test_verified_anchor_replays_after_executor_and_approver_acl_revocation():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    request = _request(context, operation, approval)
    first = execute_write_from_odoo_shell(root, request, **kwargs)
    anchors.users[42]._groups.clear()
    anchors.users[77]._groups.clear()

    replay = execute_write_from_odoo_shell(root, request, **kwargs)

    assert replay == first
    assert handler.precheck_calls == 1
    assert handler.calls == ["execute", "verify"]
    assert anchors.lookup_calls == 2
    assert anchors.claim_calls == 1
    assert cr.commits == 2


def test_committed_anchor_can_finish_readback_after_write_acl_revocation():
    context, operation, approval = _executing()
    interrupted = Handler(verify_error=SystemExit("response channel lost"))
    root, cr, anchors, handler, kwargs = _harness(handler=interrupted)
    request = _request(context, operation, approval)
    with pytest.raises(SystemExit, match="response channel lost"):
        execute_write_from_odoo_shell(root, request, **kwargs)
    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.state == "committed"

    anchors.users[42]._groups.clear()
    anchors.users[77]._groups.clear()
    interrupted.verify_error = None
    replay = execute_write_from_odoo_shell(root, request, **kwargs)

    assert trusted_result_from_mapping(replay["verification"]["result"]).succeeded is True
    assert handler.precheck_calls == 1
    assert handler.calls == ["execute", "verify", "verify"]
    assert anchors.claim_calls == 1
    assert cr.commits == 2
    assert anchor.bound_verification_calls == 0
    assert anchor.root_verification_calls == 1


def test_response_loss_after_business_commit_retries_from_committed_anchor_only():
    context, operation, approval = _executing()
    interrupted = Handler(verify_error=SystemExit("response channel lost"))
    root, cr, anchors, handler, kwargs = _harness(handler=interrupted)
    request = _request(context, operation, approval)
    with pytest.raises(SystemExit, match="response channel lost"):
        execute_write_from_odoo_shell(root, request, **kwargs)
    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.state == "committed"
    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 1

    interrupted.verify_error = None
    result = execute_write_from_odoo_shell(root, request, **kwargs)
    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded is True
    assert handler.calls == ["execute", "verify", "verify"]
    assert cr.commits == 2
    assert anchor.state == "verified"


@pytest.mark.parametrize("expired_reconciliation", [False, True])
def test_draft_invoice_recovery_response_loss_never_repeats_the_cancel_write(
    expired_reconciliation,
):
    def snapshot(model, record_id, state, values):
        return {
            "model": model,
            "record_id": record_id,
            "company_id": 7,
            "state": state,
            "values": values,
            "values_digest": hashlib.sha256(canonical_json(values)).hexdigest(),
        }

    move_before = snapshot(
        "account.move",
        501,
        "draft",
        {"state": "draft", "company_id": [7, "Sandbox Company"]},
    )
    line_before = snapshot(
        "account.move.line",
        502,
        "unknown",
        {
            "move_id": [501, "/"],
            "company_id": [7, "Sandbox Company"],
        },
    )

    def cancelled_line_snapshot():
        item = copy.deepcopy(line_before)
        item["values"]["move_id"] = [501, "Cancelled Invoice INV/1"]
        item["values_digest"] = hashlib.sha256(
            canonical_json(item["values"])
        ).hexdigest()
        return item

    journal_dependency = snapshot(
        "account.journal",
        5,
        "stable",
        {"company_id": [7, "Sandbox Company"], "state": "stable"},
    )
    raw_precheck = {
        "capability_id": "acct.recovery.execute.v1",
        "company_id": 7,
        "parameters_digest": "pending",
        "checks": ["exact_draft_recovery_graph"],
        "before": [move_before, line_before],
        "dependencies": [journal_dependency],
    }
    parameters, plan = _recovery_case()
    raw_precheck["parameters_digest"] = hashlib.sha256(
        canonical_json(parameters)
    ).hexdigest()
    shared = SimpleNamespace(
        state="draft",
        write_calls=0,
        disconnect_once=True,
    )

    class StatefulRecoveryHandler(Handler):
        def __init__(self, state):
            super().__init__()
            self.shared = state

        def precheck(self, capability_id, received_parameters):
            self.precheck_calls += 1
            assert self.shared.state == "draft"
            return copy.deepcopy(raw_precheck)

        def execute_prechecked(self, capability_id, received_parameters, checked):
            self.prechecked_executions.append(copy.deepcopy(checked))
            self.calls.append("execute")
            assert self.shared.state == "draft"
            self.shared.state = "cancel"
            self.shared.write_calls += 1
            move_after = snapshot(
                "account.move",
                501,
                "cancel",
                {"state": "cancel", "company_id": [7, "Sandbox Company"]},
            )
            return {
                "capability_id": capability_id,
                "company_id": 7,
                "parameters_digest": hashlib.sha256(
                    canonical_json(received_parameters)
                ).hexdigest(),
                "before": copy.deepcopy(checked["before"]),
                "after": [move_after, cancelled_line_snapshot()],
                "records": [
                    {"model": "account.move", "record_id": 501},
                    {"model": "account.move.line", "record_id": 502},
                ],
                "recovery": {
                    "status": "not_applicable",
                    "method": "recovery_completed",
                    "targets": [],
                },
            }

        def verify(self, capability_id, received_parameters, execution):
            self.calls.append("verify")
            assert self.shared.state == "cancel"
            if self.shared.disconnect_once:
                self.shared.disconnect_once = False
                raise SystemExit("recovery readback channel lost")
            after = [
                snapshot(
                    "account.move",
                    501,
                    "cancel",
                    {"state": "cancel", "company_id": [7, "Sandbox Company"]},
                ),
                cancelled_line_snapshot(),
            ]
            return {
                "passed": True,
                "method": "odoo_public_orm_readback_v1",
                "checks": ["cancel_state_matches", "line_guard_survived"],
                "after": after,
                "evidence_digest": hashlib.sha256(
                    canonical_json(after)
                ).hexdigest(),
            }

    context, operation, approval = _executing(
        parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id=(
            "recovery-op-response-loss-expired"
            if expired_reconciliation
            else "recovery-op-response-loss"
        ),
        raw_precheck=raw_precheck,
    )
    root, cr, anchors, _handler, kwargs = _harness()
    handlers = []
    factory_plans = []

    def handler_factory(_env, _context_value, _now, trusted_plan=None):
        handler = StatefulRecoveryHandler(shared)
        handlers.append(handler)
        factory_plans.append(copy.deepcopy(trusted_plan))
        return handler

    kwargs["handler_factory"] = handler_factory
    move_lock = LockableRecordset(501)
    line_lock = LockableRecordset(502)
    journal_lock = LockableRecordset(5)
    anchors.bound_env._models.update({
        "account.move": LockableModel(move_lock),
        "account.move.line": LockableModel(line_lock),
        "account.journal": LockableModel(journal_lock),
    })
    request = _request(
        context,
        operation,
        approval,
        trusted_recovery_plan=plan,
    )

    with pytest.raises(SystemExit, match="recovery readback channel lost"):
        execute_write_from_odoo_shell(root, request, **kwargs)

    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.state == "committed"
    assert shared.state == "cancel"
    assert shared.write_calls == 1
    assert len(handlers) == 2
    assert handlers[0].precheck_calls == 2
    assert handlers[0].calls == ["execute"]
    assert handlers[1].precheck_calls == 0
    assert handlers[1].calls == ["verify"]
    assert move_lock.lock_calls == [False]
    assert line_lock.lock_calls == [False]
    assert journal_lock.lock_calls == [True]
    anchored_execution = (
        anchor.execution_evidence_json,
        anchor.execution_evidence_digest,
        anchor.execution_result_json,
        anchor.execution_result_digest,
    )
    assert json.loads(anchor.execution_evidence_json)["difference"][
        "changed_fields"
    ] == ["record_state", "state"]

    if expired_reconciliation:
        kwargs["now"] = approval.expires_at + timedelta(seconds=1)
        retry_context = _reconciliation_context(operation)
        retry_request = _request(
            retry_context,
            operation,
            approval,
            trusted_recovery_plan=plan,
            reconciliation_only=True,
        )
    else:
        retry_request = request
    result = execute_write_from_odoo_shell(root, retry_request, **kwargs)

    assert trusted_result_from_mapping(
        result["verification"]["result"]
    ).succeeded is True
    assert anchor.state == "verified"
    assert shared.state == "cancel"
    assert shared.write_calls == 1
    assert len(handlers) == 3
    assert handlers[2].precheck_calls == 0
    assert handlers[2].calls == ["verify"]
    assert factory_plans == [plan, plan, plan]
    assert (
        anchor.execution_evidence_json,
        anchor.execution_evidence_digest,
        anchor.execution_result_json,
        anchor.execution_result_digest,
    ) == anchored_execution
    assert result["reconciliation_only"] is expired_reconciliation
    assert anchor.root_verification_calls == 1
    assert anchor.bound_verification_calls == 0
    assert cr.commits == 2


def test_unapproved_operation_is_rejected_before_anchor_or_handler():
    context, operation, approval = _executing()
    request = _request(context, operation, approval)
    request["operation"]["state"] = "awaiting_approval"
    request["operation"]["revision"] = 2
    request["operation"]["approval"] = None
    root, cr, anchors, handler, kwargs = _harness()
    with pytest.raises(OdooWriteBootstrapError, match="executing"):
        execute_write_from_odoo_shell(root, request, **kwargs)
    assert anchors.claim_calls == 0
    assert handler.calls == []
    assert cr.commits == 0


def test_cross_company_binding_and_missing_approver_group_are_rejected():
    context, operation, approval = _executing()
    foreign_context = _context(operation.parameters, company_id=8, allowed=frozenset({7, 8}))
    root, cr, anchors, handler, kwargs = _harness()
    with pytest.raises(OdooWriteBootstrapError, match="binding"):
        execute_write_from_odoo_shell(root, _request(foreign_context, operation, approval), **kwargs)
    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0


def test_expired_execute_mode_without_anchor_is_rejected_without_claim_or_handler():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    kwargs["now"] = NOW + timedelta(minutes=4, seconds=15)
    with pytest.raises(OdooWriteBootstrapError, match="reconciliation-only"):
        execute_write_from_odoo_shell(
            root, _request(context, operation, approval), **kwargs
        )
    assert anchors.by_scope == {}
    assert anchors.claim_calls == 0
    assert handler.precheck_calls == 0
    assert handler.calls == []
    assert cr.commits == 0


def test_expired_reconciliation_without_anchor_is_unknown_and_never_claims():
    context, operation, approval = _executing()
    context = _reconciliation_context(operation)
    root, cr, anchors, handler, kwargs = _harness()
    kwargs["now"] = approval.expires_at
    forbidden = {"control_store": 0, "handler_factory": 0, "metadata_scope": 0}

    def control_store(_env):
        forbidden["control_store"] += 1
        return anchors

    def handler_factory(*_args):
        forbidden["handler_factory"] += 1
        return handler

    def metadata_scope():
        forbidden["metadata_scope"] += 1
        return nullcontext()

    kwargs["control_store_factory"] = control_store
    kwargs["handler_factory"] = handler_factory
    kwargs["metadata_execution_scope_factory"] = metadata_scope

    with pytest.raises(OdooWriteBootstrapError, match="durable anchor"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                reconciliation_only=True,
            ),
            **kwargs,
        )

    assert anchors.by_scope == {}
    assert anchors.claim_calls == 0
    assert handler.precheck_calls == 0
    assert handler.calls == []
    assert forbidden == {
        "control_store": 0,
        "handler_factory": 0,
        "metadata_scope": 0,
    }
    assert cr.commits == 0


def test_unexpired_verifying_reconciliation_without_anchor_never_claims_or_executes():
    context, operation, approval = _executing()
    context = _reconciliation_context(operation)
    root, cr, anchors, handler, kwargs = _harness()

    with pytest.raises(OdooWriteBootstrapError, match="durable anchor"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                reconciliation_only=True,
            ),
            **kwargs,
        )

    assert anchors.by_scope == {}
    assert anchors.claim_calls == 0
    assert handler.precheck_calls == 0
    assert handler.calls == []
    assert cr.commits == 0


def test_reconciliation_mode_bit_flip_is_rejected_before_anchor_lookup():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()

    with pytest.raises(OdooWriteBootstrapError, match="request digest"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                reconciliation_only=True,
            ),
            **kwargs,
        )

    assert anchors.lookup_calls == 0
    assert anchors.claim_calls == 0
    assert handler.precheck_calls == 0
    assert handler.calls == []
    assert cr.commits == 0


def test_exact_anchor_lookup_rejects_immutable_release_tampering_before_replay():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    request = _request(context, operation, approval)
    execute_write_from_odoo_shell(root, request, **kwargs)
    anchor = next(iter(anchors.by_scope.values()))
    anchor.release_digest = "f" * 64

    with pytest.raises(RuntimeError, match="immutable binding mismatch"):
        execute_write_from_odoo_shell(root, request, **kwargs)

    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 2

    wrong_parameters = copy.deepcopy(operation.parameters)
    wrong_parameters["reference"] = "AUTHENTICATED-DIFFERENT-CONTENT"
    wrong_context = _context(wrong_parameters)
    root, cr, anchors, handler, kwargs = _harness()
    with pytest.raises(OdooWriteBootstrapError, match="request digest"):
        execute_write_from_odoo_shell(root, _request(wrong_context, operation, approval), **kwargs)
    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0


def test_expired_approval_replays_verified_anchor_without_new_write():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    request = _request(context, operation, approval)

    first = execute_write_from_odoo_shell(root, request, **kwargs)
    kwargs["now"] = NOW + timedelta(minutes=4, seconds=15)
    reconciliation_context = _reconciliation_context(operation)
    replay = execute_write_from_odoo_shell(
        root,
        _request(
            reconciliation_context,
            operation,
            approval,
            reconciliation_only=True,
        ),
        **kwargs,
    )

    assert replay["execution"] == first["execution"]
    assert replay["verification"] == first["verification"]
    assert first["reconciliation_only"] is False
    assert replay["reconciliation_only"] is True
    assert next(iter(anchors.by_scope.values())).state == "verified"
    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 2


def test_expired_reconciliation_finishes_committed_anchor_without_execute():
    context, operation, approval = _executing()
    interrupted = Handler(verify_error=SystemExit("response channel lost"))
    root, cr, anchors, handler, kwargs = _harness(handler=interrupted)
    with pytest.raises(SystemExit, match="response channel lost"):
        execute_write_from_odoo_shell(
            root, _request(context, operation, approval), **kwargs
        )
    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.state == "committed"
    interrupted.verify_error = None
    kwargs["now"] = approval.expires_at
    reconciliation_context = _reconciliation_context(operation)

    result = execute_write_from_odoo_shell(
        root,
        _request(
            reconciliation_context,
            operation,
            approval,
            reconciliation_only=True,
        ),
        **kwargs,
    )

    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded
    assert handler.calls == ["execute", "verify", "verify"]
    assert anchors.claim_calls == 1
    assert anchor.state == "verified"


def test_committed_reconciliation_rolls_back_verify_side_effect_before_control_commit():
    context, operation, approval = _executing()

    class WritingVerifier(Handler):
        cursor = None

        def verify(self, capability_id, parameters, execution):
            if self.verify_error is None:
                self.cursor.side_effects.append("forbidden reconcile verify ORM write")
            return super().verify(capability_id, parameters, execution)

    writing = WritingVerifier(
        verify_error=SystemExit("response channel lost after commit")
    )
    root, cr, anchors, handler, kwargs = _harness(handler=writing)
    writing.cursor = cr
    with pytest.raises(SystemExit, match="response channel lost"):
        execute_write_from_odoo_shell(
            root, _request(context, operation, approval), **kwargs
        )
    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.state == "committed"
    assert cr.commits == 1
    writing.verify_error = None

    result = execute_write_from_odoo_shell(
        root,
        _request(
            _reconciliation_context(operation),
            operation,
            approval,
            reconciliation_only=True,
        ),
        **kwargs,
    )

    assert result["reconciliation_only"] is True
    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded
    assert handler.calls == ["execute", "verify", "verify"]
    assert cr.side_effects == []
    assert cr.commits == 2
    assert anchor.state == "verified"


def test_expired_reconciliation_rejects_claimed_anchor_without_side_effect():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )
    anchor = next(iter(anchors.by_scope.values()))
    anchor.state = "claimed"
    handler.calls.clear()
    handler.precheck_calls = 0
    commits = cr.commits
    resource_locks = list(anchor.resource_locks)
    kwargs["now"] = approval.expires_at
    reconciliation_context = _reconciliation_context(operation)
    forbidden = {"control_store": 0, "handler_factory": 0, "metadata_scope": 0}

    def control_store(_env):
        forbidden["control_store"] += 1
        return anchors

    def handler_factory(*_args):
        forbidden["handler_factory"] += 1
        return handler

    def metadata_scope():
        forbidden["metadata_scope"] += 1
        return nullcontext()

    kwargs["control_store_factory"] = control_store
    kwargs["handler_factory"] = handler_factory
    kwargs["metadata_execution_scope_factory"] = metadata_scope

    with pytest.raises(OdooWriteBootstrapError, match="durable anchor"):
        execute_write_from_odoo_shell(
            root,
            _request(
                reconciliation_context,
                operation,
                approval,
                reconciliation_only=True,
            ),
            **kwargs,
        )

    assert handler.precheck_calls == 0
    assert handler.calls == []
    assert anchors.claim_calls == 1
    assert anchor.resource_locks == resource_locks
    assert forbidden == {
        "control_store": 0,
        "handler_factory": 0,
        "metadata_scope": 0,
    }
    assert cr.commits == commits

    root, cr, anchors, handler, kwargs = _harness(approver_group=False)
    with pytest.raises(OdooWriteBootstrapError, match="approver"):
        execute_write_from_odoo_shell(root, _request(context, operation, approval), **kwargs)
    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0


def test_expired_reconciliation_replays_failed_anchor_without_handler_or_commit():
    context, operation, approval = _executing()
    failing = Handler(execute_error=RuntimeError("business write failed"))
    root, cr, anchors, handler, kwargs = _harness(handler=failing)
    first = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )
    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.state == "failed"
    commits = cr.commits
    handler.calls.clear()
    handler.precheck_calls = 0
    kwargs["now"] = approval.expires_at

    replay = execute_write_from_odoo_shell(
        root,
        _request(
            _reconciliation_context(operation),
            operation,
            approval,
            reconciliation_only=True,
        ),
        **kwargs,
    )

    assert replay["execution"] == first["execution"]
    assert replay["verification"] is None
    assert replay["reconciliation_only"] is True
    assert handler.precheck_calls == 0
    assert handler.calls == []
    assert anchors.claim_calls == 1
    assert cr.commits == commits


def test_same_idempotency_scope_with_different_signed_content_is_rejected():
    context, operation, approval = _executing()
    root, cr, _anchors, handler, kwargs = _harness()
    execute_write_from_odoo_shell(root, _request(context, operation, approval), **kwargs)
    changed = _parameters(idempotency_key="invoice-1")
    changed["reference"] = "INV-SANDBOX-CHANGED"
    # Same idempotency scope with different approved business content conflicts.
    context2, operation2, approval2 = _executing(changed, operation_id="op-2")
    with pytest.raises(RuntimeError, match="different immutable content"):
        execute_write_from_odoo_shell(root, _request(context2, operation2, approval2), **kwargs)
    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 2


def test_execution_exception_rolls_back_savepoint_and_commits_signed_failure_anchor():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness(
        handler=Handler(execute_error=RuntimeError("business write failed"))
    )
    result = execute_write_from_odoo_shell(root, _request(context, operation, approval), **kwargs)
    execution = trusted_result_from_mapping(result["execution"]["result"])
    assert execution.succeeded is False
    assert result["verification"] is None
    assert result["execution"]["evidence"]["failure_checks"] == ["execution_exception:RuntimeError"]
    assert cr.rolled_back_savepoints == 2
    assert cr.savepoints == 3
    assert cr.commits == 1
    assert next(iter(anchors.by_scope.values())).state == "failed"


def test_changed_live_precheck_is_anchored_as_no_effect_failure_before_execute():
    context, operation, approval = _executing()

    class DriftedPrecheck(Handler):
        def precheck(self, capability_id, parameters):
            result = super().precheck(capability_id, parameters)
            result["checks"] = [*result["checks"], "runtime_drift"]
            return result

    root, cr, anchors, handler, kwargs = _harness(
        handler=DriftedPrecheck()
    )

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    execution = trusted_result_from_mapping(result["execution"]["result"])
    assert execution.succeeded is False
    assert result["verification"] is None
    assert result["execution"]["evidence"]["failure_checks"] == [
        "precheck_drift_before_execution"
    ]
    assert handler.precheck_calls == 1
    assert handler.calls == []
    assert next(iter(anchors.by_scope.values())).state == "failed"
    assert cr.commits == 1


def test_precheck_dependencies_are_row_locked_invalidated_and_rechecked_before_write():
    record = LockableRecordset(901)
    handler = DependencyHandler(record)
    parameters = _parameters()
    raw_precheck = _dependency_precheck(
        "acct.invoice.customer_create.v1", parameters, record
    )
    context, operation, approval = _executing(
        parameters, raw_precheck=raw_precheck
    )
    root, cr, anchors, handler, kwargs = _harness(handler=handler)
    anchors.bound_env._models["account.asset"] = LockableModel(record)

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert trusted_result_from_mapping(result["execution"]["result"]).succeeded is True
    assert handler.precheck_calls == 2
    assert handler.calls == ["execute", "verify"]
    assert record.lock_calls == [True]
    assert record.invalidations == 1
    assert record.access_rules == ["read"]
    assert cr.commits == 2


def test_recovery_precheck_exclusively_locks_action_and_guards_but_not_dependencies():
    def snapshot(model, record_id):
        values = {"company_id": 7, "state": "stable"}
        return {
            "model": model,
            "record_id": record_id,
            "company_id": 7,
            "state": "stable",
            "values": values,
            "values_digest": hashlib.sha256(canonical_json(values)).hexdigest(),
        }

    move = LockableRecordset(501)
    line = LockableRecordset(502)
    journal = LockableRecordset(5)
    cr = Cursor()
    anchors = Anchors()
    env = BoundEnv(
        cr,
        {
            42: User(42, [7], set()),
        },
        anchors,
    )
    env._models.update({
        "account.move": LockableModel(move),
        "account.move.line": LockableModel(line),
        "account.journal": LockableModel(journal),
    })
    evidence = {
        "handler_details": {
            "before": [
                snapshot("account.move", 501),
                snapshot("account.move.line", 502),
            ],
            "dependencies": [snapshot("account.journal", 5)],
        }
    }

    count = _lock_live_precheck_records(
        env,
        evidence,
        company_id=7,
        exclusive_before=True,
    )

    assert count == 3
    assert move.lock_calls == [False]
    assert line.lock_calls == [False]
    assert journal.lock_calls == [True]
    assert env.cache_invalidations == 1


@pytest.mark.parametrize("drift_after_lock", [False, True])
def test_draft_cancel_requires_null_plan_exclusive_graph_lock_and_no_drift(
    drift_after_lock,
):
    parameters = _draft_cancel_parameters()

    def mutate_on_lock(record):
        if drift_after_lock:
            record.snapshot_state = "fingerprint-drift"

    move = LockableRecordset(501, on_lock=mutate_on_lock)
    line = LockableRecordset(502)
    journal = LockableRecordset(5)

    def snapshot(model, record):
        values = {"company_id": 7, "state": record.snapshot_state}
        return {
            "model": model,
            "record_id": record.id,
            "company_id": 7,
            "state": record.snapshot_state,
            "values": values,
            "values_digest": hashlib.sha256(
                canonical_json(values)
            ).hexdigest(),
        }

    class DraftCancelLockHandler(Handler):
        def evidence(self):
            result = _raw_precheck(
                "acct.move.draft_cancel.v1", parameters
            )
            result["before"] = [
                snapshot("account.move", move),
                snapshot("account.move.line", line),
            ]
            result["dependencies"] = [
                snapshot("account.journal", journal)
            ]
            return result

        def precheck(self, capability_id, request_parameters):
            assert capability_id == "acct.move.draft_cancel.v1"
            assert request_parameters == parameters
            self.precheck_calls += 1
            return self.evidence()

        def execute_prechecked(self, capability_id, request_parameters, checked):
            assert move.lock_calls == [False]
            assert line.lock_calls == [False]
            assert journal.lock_calls == [True]
            return super().execute_prechecked(
                capability_id, request_parameters, checked
            )

    handler = DraftCancelLockHandler()
    context, operation, approval = _executing(
        parameters,
        capability_id="acct.move.draft_cancel.v1",
        operation_id=("op-draft-cancel-drift" if drift_after_lock else "op-draft-cancel"),
        raw_precheck=handler.evidence(),
    )
    root, cr, anchors, handler, kwargs = _harness(handler=handler)
    anchors.bound_env._models.update({
        "account.move": LockableModel(move),
        "account.move.line": LockableModel(line),
        "account.journal": LockableModel(journal),
    })

    result = execute_write_from_odoo_shell(
        root,
        _request(
            context,
            operation,
            approval,
            trusted_recovery_plan=None,
        ),
        **kwargs,
    )

    execution = trusted_result_from_mapping(result["execution"]["result"])
    assert handler.factory_plans == [None] + ([] if drift_after_lock else [None])
    assert move.lock_calls == [False]
    assert line.lock_calls == [False]
    assert journal.lock_calls == [True]
    if drift_after_lock:
        assert execution.succeeded is False
        assert result["execution"]["evidence"]["failure_checks"] == [
            "precheck_drift_after_dependency_lock"
        ]
        assert handler.calls == []
        assert cr.commits == 1
    else:
        assert execution.succeeded is True
        assert handler.calls == ["execute", "verify"]
        assert cr.commits == 2
        anchor = next(iter(anchors.by_scope.values()))
        assert anchor.resource_locks == _resource_lock_digests(
            "acct.move.draft_cancel.v1", 7, parameters, None
        )


def test_dependency_drift_after_row_lock_is_anchored_before_any_business_write():
    record = LockableRecordset(
        901,
        on_lock=lambda locked: setattr(locked, "snapshot_state", "changed"),
    )
    handler = DependencyHandler(record)
    parameters = _parameters()
    raw_precheck = _dependency_precheck(
        "acct.invoice.customer_create.v1", parameters, record
    )
    context, operation, approval = _executing(
        parameters, raw_precheck=raw_precheck
    )
    root, cr, anchors, handler, kwargs = _harness(handler=handler)
    anchors.bound_env._models["account.asset"] = LockableModel(record)

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    execution = trusted_result_from_mapping(result["execution"]["result"])
    assert execution.succeeded is False
    assert result["execution"]["evidence"]["failure_checks"] == [
        "precheck_drift_after_dependency_lock"
    ]
    assert handler.precheck_calls == 2
    assert handler.calls == []
    assert next(iter(anchors.by_scope.values())).state == "failed"
    assert cr.commits == 1


def test_dependency_row_lock_failure_is_anchored_before_any_business_write():
    def fail_lock(_record):
        raise RuntimeError("already locked")

    record = LockableRecordset(901, on_lock=fail_lock)
    handler = DependencyHandler(record)
    parameters = _parameters()
    raw_precheck = _dependency_precheck(
        "acct.invoice.customer_create.v1", parameters, record
    )
    context, operation, approval = _executing(
        parameters, raw_precheck=raw_precheck
    )
    root, cr, anchors, handler, kwargs = _harness(handler=handler)
    anchors.bound_env._models["account.asset"] = LockableModel(record)

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert trusted_result_from_mapping(result["execution"]["result"]).succeeded is False
    assert result["execution"]["evidence"]["failure_checks"] == [
        "precheck_dependency_lock_exception:RuntimeError"
    ]
    assert handler.precheck_calls == 1
    assert handler.calls == []
    assert next(iter(anchors.by_scope.values())).state == "failed"
    assert cr.commits == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda snapshot: snapshot.update(values_digest="0" * 64),
        lambda snapshot: snapshot.update(company_id=8),
        lambda snapshot: snapshot.update(model="account.move; DROP TABLE x"),
    ],
)
def test_invalid_precheck_lock_snapshot_is_anchored_before_business_write(mutate):
    record = LockableRecordset(901)
    parameters = _parameters()
    raw_precheck = _dependency_precheck(
        "acct.invoice.customer_create.v1", parameters, record
    )
    mutate(raw_precheck["dependencies"][0])

    class RawDependencyHandler(Handler):
        def precheck(self, capability_id, received_parameters):
            self.precheck_calls += 1
            return copy.deepcopy(raw_precheck)

    handler = RawDependencyHandler()
    context, operation, approval = _executing(
        parameters, raw_precheck=raw_precheck
    )
    root, cr, anchors, handler, kwargs = _harness(handler=handler)

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert trusted_result_from_mapping(result["execution"]["result"]).succeeded is False
    assert result["execution"]["evidence"]["failure_checks"] == [
        "precheck_dependency_lock_exception:OdooWriteBootstrapError"
    ]
    assert handler.calls == []
    assert cr.commits == 1


def test_approval_expiring_during_live_precheck_never_starts_business_execution():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    moments = iter([NOW, approval.expires_at + timedelta(microseconds=1)])
    kwargs.pop("now")
    kwargs["clock"] = lambda: next(moments)

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    execution = trusted_result_from_mapping(result["execution"]["result"])
    assert execution.succeeded is False
    assert result["execution"]["evidence"]["failure_checks"] == [
        "approval_expired_during_precheck"
    ]
    assert handler.precheck_calls == 1
    assert handler.prechecked_executions == []
    assert handler.calls == []
    assert next(iter(anchors.by_scope.values())).state == "failed"
    assert cr.commits == 1
    assert cr.savepoints == 2
    assert cr.rolled_back_savepoints == 1


def test_live_precheck_side_effect_is_rolled_back_before_business_execution():
    context, operation, approval = _executing()

    class SideEffectPrecheck(Handler):
        def precheck(self, capability_id, parameters):
            cr.side_effects.append("unexpected precheck mutation")
            return super().precheck(capability_id, parameters)

    handler = SideEffectPrecheck()
    root, cr, _anchors, handler, kwargs = _harness(handler=handler)

    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert trusted_result_from_mapping(result["execution"]["result"]).succeeded is True
    assert cr.side_effects == []
    assert handler.precheck_calls == 1
    assert len(handler.prechecked_executions) == 1


def test_verification_failure_is_signed_and_never_reported_as_passing():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness(
        handler=Handler(verify_error=RuntimeError("readback mismatch"))
    )
    result = execute_write_from_odoo_shell(root, _request(context, operation, approval), **kwargs)
    verification = trusted_result_from_mapping(result["verification"]["result"])
    assert verification.succeeded is False
    assert result["verification"]["evidence"]["passed"] is False
    assert cr.commits == 2
    assert next(iter(anchors.by_scope.values())).state == "failed"


def test_changed_fresh_snapshot_is_signed_as_failed_verification():
    context, operation, approval = _executing()

    class ChangedReadback(Handler):
        def verify(self, capability_id, parameters, execution):
            result = super().verify(capability_id, parameters, execution)
            values = {"state": "posted", "amount_total": "101.00"}
            result["after"][0]["values"] = values
            result["after"][0]["values_digest"] = hashlib.sha256(
                canonical_json(values)
            ).hexdigest()
            result["evidence_digest"] = hashlib.sha256(
                canonical_json(result["after"])
            ).hexdigest()
            return result

    root, cr, anchors, handler, kwargs = _harness(handler=ChangedReadback())
    result = execute_write_from_odoo_shell(
        root, _request(context, operation, approval), **kwargs
    )

    assert trusted_result_from_mapping(result["execution"]["result"]).succeeded is True
    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded is False
    assert result["verification"]["evidence"]["readback"]["records"] == []
    assert result["verification"]["evidence"]["readback"]["fresh_snapshots"] == []
    assert result["verification"]["evidence"]["checks"] == [
        "verification_exception:OdooWriteBootstrapError"
    ]
    assert handler.calls == ["execute", "verify"]
    assert next(iter(anchors.by_scope.values())).state == "failed"
    assert cr.commits == 2


def test_tampered_stored_result_signature_is_rejected_before_replay():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    request = _request(context, operation, approval)
    execute_write_from_odoo_shell(root, request, **kwargs)
    anchor = next(iter(anchors.by_scope.values()))
    envelope = json.loads(anchor.execution_result_json)
    envelope["signature"] = "0" * 64
    anchor.execution_result_json = canonical_json(envelope).decode()
    anchor.execution_result_digest = hashlib.sha256(
        anchor.execution_result_json.encode()
    ).hexdigest()
    with pytest.raises(Exception, match="signature"):
        execute_write_from_odoo_shell(root, request, **kwargs)
    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 2


def test_request_shape_and_authenticated_content_digest_are_exact():
    context, operation, approval = _executing()
    root, cr, anchors, handler, kwargs = _harness()
    request = _request(context, operation, approval)
    with pytest.raises(OdooWriteBootstrapError, match="fields"):
        execute_write_from_odoo_shell(root, {**request, "extra": True}, **kwargs)
    tampered = copy.deepcopy(request)
    tampered["operation"]["parameters"]["idempotency_key"] = "changed"
    with pytest.raises(Exception, match="digest"):
        execute_write_from_odoo_shell(root, tampered, **kwargs)
    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0


def test_non_recovery_write_rejects_injected_trusted_recovery_plan():
    context, operation, approval = _executing()
    _parameters_for_recovery, plan = _recovery_case()
    root, cr, anchors, handler, kwargs = _harness()

    with pytest.raises(OdooWriteBootstrapError, match="must be null"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                trusted_recovery_plan=plan,
            ),
            **kwargs,
        )

    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0


def test_recovery_requires_separately_supplied_valid_receipt_plan():
    parameters, plan = _recovery_case()
    context, operation, approval = _executing(
        parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-1",
    )
    root, cr, anchors, handler, kwargs = _harness()

    missing = _request(context, operation, approval)
    with pytest.raises(OdooWriteBootstrapError, match="is required"):
        execute_write_from_odoo_shell(root, missing, **kwargs)

    missing_field = _request(
        context, operation, approval, trusted_recovery_plan=plan
    )
    missing_field.pop("trusted_recovery_plan")
    with pytest.raises(OdooWriteBootstrapError, match="fields"):
        execute_write_from_odoo_shell(root, missing_field, **kwargs)

    tampered = copy.deepcopy(plan)
    tampered["action_targets"][0]["record_id"] = 999
    with pytest.raises(OdooWriteBootstrapError, match="plan is invalid"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                trusted_recovery_plan=tampered,
            ),
            **kwargs,
        )

    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0


def test_recovery_plan_origin_digest_and_target_company_are_strictly_bound():
    parameters, plan = _recovery_case()
    wrong_origin_parameters = {
        **parameters,
        "origin_operation_id": "different-origin-op",
    }
    context, operation, approval = _executing(
        wrong_origin_parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-wrong-origin",
    )
    root, cr, anchors, handler, kwargs = _harness()
    with pytest.raises(OdooWriteBootstrapError, match="origin, digest, or company"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                trusted_recovery_plan=plan,
            ),
            **kwargs,
        )
    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0

    wrong_digest_parameters = {
        **parameters,
        "origin_operation_id": plan["origin_operation_id"],
        "expected_recovery_plan_digest": "a" * 64,
    }
    context, operation, approval = _executing(
        wrong_digest_parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-wrong-digest",
    )
    root, cr, anchors, handler, kwargs = _harness()
    with pytest.raises(OdooWriteBootstrapError, match="origin, digest, or company"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                trusted_recovery_plan=plan,
            ),
            **kwargs,
        )
    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0

    parameters, foreign_plan = _recovery_case(target_company_id=8)
    context, operation, approval = _executing(
        parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-foreign-target",
    )
    root, cr, anchors, handler, kwargs = _harness()
    with pytest.raises(OdooWriteBootstrapError, match="company-bound"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context,
                operation,
                approval,
                trusted_recovery_plan=foreign_plan,
            ),
            **kwargs,
        )
    assert anchors.claim_calls == 0 and handler.calls == [] and cr.commits == 0


def test_valid_recovery_plan_reaches_handler_and_is_bound_to_control_anchor():
    parameters, plan = _recovery_case()
    context, operation, approval = _executing(
        parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-valid",
    )
    root, cr, anchors, handler, kwargs = _harness()

    result = execute_write_from_odoo_shell(
        root,
        _request(
            context,
            operation,
            approval,
            trusted_recovery_plan=plan,
        ),
        **kwargs,
    )

    anchor = next(iter(anchors.by_scope.values()))
    assert anchor.operation_digest == operation.digest
    assert operation.parameters["expected_recovery_plan_digest"] == plan["plan_digest"]
    assert handler.factory_plans == [plan, plan]
    assert trusted_result_from_mapping(result["verification"]["result"]).succeeded

    default_handler = _default_handler_factory(
        SimpleNamespace(uid=context.user_id, su=False),
        context,
        NOW,
        plan,
        build_trusted_module_graph(
            [{"name": "account", "latest_version": "19.0.test"}]
        ),
    )
    assert default_handler.context.trusted_recovery_plan == plan


def test_recovery_idempotency_anchor_rejects_a_different_plan_for_same_origin():
    parameters, plan = _recovery_case()
    context, operation, approval = _executing(
        parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-first",
    )
    root, cr, _anchors, handler, kwargs = _harness()
    execute_write_from_odoo_shell(
        root,
        _request(
            context,
            operation,
            approval,
            trusted_recovery_plan=plan,
        ),
        **kwargs,
    )

    other_parameters, other_plan = _recovery_case(
        target_record_id=502,
        idempotency_key="recover-origin-op-1-again",
    )
    context2, operation2, approval2 = _executing(
        other_parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-second",
    )
    with pytest.raises(RuntimeError, match="different immutable content"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context2,
                operation2,
                approval2,
                trusted_recovery_plan=other_plan,
            ),
            **kwargs,
        )

    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 2


def test_recovery_idempotency_anchor_rejects_a_second_operation_for_the_same_plan():
    parameters, plan = _recovery_case()
    context, operation, approval = _executing(
        parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-same-plan-first",
    )
    root, cr, _anchors, handler, kwargs = _harness()
    execute_write_from_odoo_shell(
        root,
        _request(
            context,
            operation,
            approval,
            trusted_recovery_plan=plan,
        ),
        **kwargs,
    )

    other_parameters, same_plan = _recovery_case(
        idempotency_key="recover-origin-op-1-second-operation"
    )
    assert same_plan == plan
    context2, operation2, approval2 = _executing(
        other_parameters,
        capability_id="acct.recovery.execute.v1",
        operation_id="recovery-op-same-plan-second",
    )

    with pytest.raises(RuntimeError, match="different immutable content"):
        execute_write_from_odoo_shell(
            root,
            _request(
                context2,
                operation2,
                approval2,
                trusted_recovery_plan=same_plan,
            ),
            **kwargs,
        )

    assert handler.calls == ["execute", "verify"]
    assert cr.commits == 2


def test_bootstrap_is_the_single_commit_owner_and_has_no_privilege_escape():
    source = SOURCE.read_text(encoding="utf-8")
    assert source.count(".commit(") == 1
    assert ".sudo(" not in source
    assert ".rollback(" not in source
    for private_odoo_call in (
        "._create_payments(",
        "._reverse_moves(",
        "._generate_deferred_entries(",
        "._post(",
    ):
        assert private_odoo_call not in source


def test_bootstrap_uses_only_private_control_anchor_methods():
    source = SOURCE.read_text(encoding="utf-8")
    attributes = {
        node.attr
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Attribute)
    }
    public_control_methods = {
        "lookup_exact",
        "claim",
        "acquire_resource_locks",
        "record_execution",
        "record_verification",
        "record_committed_verification_from_root",
    }
    private_control_methods = {f"_{name}" for name in public_control_methods}

    assert public_control_methods.isdisjoint(attributes)
    assert private_control_methods <= attributes

"""Transaction-local Odoo 19 accounting write handlers.

This module deliberately does not commit, roll back, elevate privileges, or
create audit signatures.  The caller owns the control anchor and transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
from typing import Any, Mapping

from .module_graph import (
    OdooModuleGraphError,
    TrustedModuleGraph,
    conditional_required_fields,
)
from .recovery_actions import (
    RECOVERY_ACTION_METHODS,
    RecoveryActionError,
    execute_recovery_action,
)
from .recovery_verifier import (
    RecoveryVerificationError,
    verify_recovery_action,
)
from ..draft_invoice_recovery import (
    DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
    DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE,
    DRAFT_VENDOR_BILL_RECOVERY_METHOD,
    DRAFT_VENDOR_BILL_RECOVERY_ORACLE,
    classic_read_many2one_id,
    customer_invoice_business_binding,
    customer_invoice_document_binding,
    vendor_bill_business_binding,
    vendor_bill_document_binding,
)
from ..domain.write_semantics import WriteSemanticError, validate_write_semantics
from ..recovery_contracts import (
    EXECUTABLE_RECOVERY_METHODS,
    RECOVERY_ACTION_CONTRACTS,
)
from ..recovery_guard import (
    RecoveryPlanExecutionGuard,
    RecoveryPlanExecutionGuardError,
    validate_recovery_plan_execution,
)
from ..write_receipts import (
    WriteReceiptError,
    create_record_snapshot,
    validate_executable_recovery_plan,
    validate_record_snapshot,
)


class OdooWriteHandlerError(RuntimeError):
    """A fail-closed precondition, execution, or read-back failure."""


@dataclass(frozen=True)
class OdooWriteContext:
    env: Any
    user_id: int
    allowed_company_ids: frozenset[int]
    today: date
    environment: str
    module_graph: TrustedModuleGraph
    trusted_recovery_plan: Mapping[str, Any] | None = None


_CAPABILITIES = frozenset(
    {
        "acct.invoice.customer_create.v1",
        "acct.bill.vendor_create.v1",
        "acct.refund.create.v1",
        "acct.payment.register.v1",
        "acct.payment.cancel.v1",
        "acct.bank.statement_import.v1",
        "acct.reconciliation.apply.v1",
        "acct.asset.create.v1",
        "acct.depreciation.post.v1",
        "acct.accrual.create.v1",
        "acct.deferred.create.v1",
        "acct.period.adjustment_create.v1",
        "acct.journal.entry_create.v1",
        "acct.move.post.v1",
        "acct.move.reverse.v1",
        "acct.move.draft_cancel.v1",
        "acct.move.draft_cancel.v2",
        "acct.recovery.execute.v1",
    }
)

# This dormant implementation is reachable only through a receipt-derived V2
# plan in test or a registry-staged sandbox.  Production remains fail-closed
# even if a plan is replayed there; promotion still requires real Odoo evidence.
_RECOVERY_ACTIONS = frozenset(
    EXECUTABLE_RECOVERY_METHODS
)
_MANUAL_RECOVERY_METHODS = {
    "cancel_and_unreconcile_payment_v1": "manual_review_payment_recovery",
    "cancel_asset_and_reverse_schedule_v1": (
        "manual_review_asset_cancellation_or_disposal"
    ),
    "cancel_draft_period_adjustment_v1": "manual_review_period_adjustment",
    "cancel_draft_refund_v1": "manual_review_refund_recovery",
    DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD: (
        "manual_review_customer_invoice_recovery"
    ),
    DRAFT_VENDOR_BILL_RECOVERY_METHOD: "manual_review_vendor_bill_recovery",
    "cancel_scheduled_and_reverse_accrual_origin_v1": (
        "manual_review_accrual_schedule"
    ),
    "post_compensating_bank_statement_v1": "manual_review_bank_import_recovery",
    "reverse_deferred_source_and_schedule_v1": (
        "manual_review_reverse_deferred_schedule"
    ),
    "reverse_depreciation_and_restore_schedule_v1": (
        "manual_review_reverse_depreciation_and_restore_asset_schedule"
    ),
    "reverse_posted_customer_invoice_v1": (
        "manual_review_customer_invoice_recovery"
    ),
    "reverse_posted_period_adjustment_v1": "manual_review_period_adjustment",
    "reverse_posted_refund_v1": "manual_review_refund_recovery",
    "reverse_posted_vendor_bill_v1": "manual_review_vendor_bill_recovery",
    "reverse_the_reversal_v1": "manual_review_move_reversal",
    "undo_reconciliation_and_reverse_writeoff_v1": (
        "manual_review_reconciliation_recovery"
    ),
}

_SNAPSHOT_FIELDS: dict[str, tuple[str, ...]] = {
    "account.move": (
        "name", "state", "move_type", "company_id", "journal_id", "currency_id",
        "partner_id", "date", "invoice_date", "invoice_date_due", "ref",
        "invoice_payment_term_id",
        "amount_untaxed", "amount_tax", "amount_total", "amount_residual", "payment_state",
        "line_ids", "invoice_line_ids", "reversed_entry_id", "reversal_move_ids",
        "adjusting_entry_origin_move_ids", "adjusting_entries_move_ids",
        "exchange_diff_partial_ids",
        "origin_payment_id", "payment_ids", "matched_payment_ids",
        "reconciled_payment_ids", "statement_line_id", "statement_line_ids",
        "statement_id",
        "tax_cash_basis_rec_id", "tax_cash_basis_origin_move_id",
        "tax_cash_basis_created_move_ids",
        "stock_move_ids", "landed_costs_ids", "closing_return_id",
        "transfer_model_id", "transaction_ids", "authorized_transaction_ids",
        "purchase_id", "asset_ids",
        "posted_before", "sequence_prefix", "sequence_number",
        "secure_sequence_number", "made_sequence_gap", "inalterable_hash",
        "checked", "is_manually_modified", "need_cancel_request",
        "edi_document_ids", "expense_ids", "pos_order_ids",
        "debit_note_ids", "debit_origin_id",
        "invoice_pdf_report_id", "invoice_vendor_bill_id",
        "purchase_vendor_bill_id", "ubl_cii_xml_id",
        "l10n_es_edi_facturae_xml_id", "signature", "signing_user",
        "invoice_pdf_report_file", "ubl_cii_xml_file",
        "l10n_es_edi_facturae_xml_file",
        "is_move_sent", "sending_data", "is_being_sent",
        "invoice_source_email", "attachment_ids",
        "message_main_attachment_id", "audit_trail_message_ids",
        "activity_ids", "message_follower_ids", "message_ids", "rating_ids",
        "website_message_ids", "access_token",
        "fiscal_position_id", "invoice_cash_rounding_id",
        "invoice_incoterm_id", "incoterm_location", "partner_shipping_id",
        "partner_bank_id", "preferred_payment_method_line_id",
        "l10n_latam_document_type_id", "invoice_origin", "narration",
        "quick_edit_total_amount", "always_tax_exigible", "is_storno",
        "asset_value_change", "campaign_id", "medium_id", "source_id",
        "team_id", "delivery_date", "fapiao", "invoice_currency_rate",
        "invoice_user_id", "l10n_es_edi_facturae_reason_code",
        "l10n_es_invoicing_period_start_date",
        "l10n_es_invoicing_period_end_date", "l10n_es_is_simplified",
        "l10n_es_payment_means", "payment_reference",
        "payment_state_before_switch", "qr_code_method",
        "taxable_supply_date", "journal_line_ids",
        "create_uid", "create_date", "write_uid", "write_date",
        "auto_post", "auto_post_until", "auto_post_origin_id", "asset_id",
        "asset_move_type", "asset_number_days",
        "asset_depreciation_beginning_date", "depreciation_value",
        "deferred_move_ids", "deferred_original_move_ids",
        "odoo_cli_v3_reason", "odoo_cli_v3_period_end_date",
        "odoo_cli_v3_document_binding", "odoo_cli_v3_business_binding",
    ),
    "account.move.line": (
        "move_id", "company_id", "parent_state", "name", "ref",
        "account_id", "partner_id",
        "product_id", "quantity", "price_unit", "price_subtotal", "price_total",
        "currency_id", "date",
        "date_maturity", "debit", "credit", "balance", "amount_currency",
        "amount_residual", "amount_residual_currency", "reconciled",
        "full_reconcile_id", "matched_debit_ids", "matched_credit_ids",
        "matching_number", "tax_ids", "tax_line_id", "tax_tag_ids",
        "group_tax_id",
        "display_type",
        "tax_repartition_line_id",
        "analytic_distribution", "analytic_line_ids",
        "distribution_analytic_account_ids",
        "deferred_start_date", "deferred_end_date", "asset_ids",
        "payment_id", "statement_line_id", "statement_id", "sale_line_ids",
        "purchase_line_id", "purchase_order_id", "expense_id",
        "reconcile_model_id", "reconciled_lines_ids",
        "reconciled_lines_excluding_exchange_diff_ids", "parent_id",
        "cogs_origin_id", "is_landed_costs_line",
        "move_attachment_ids", "tax_base_amount", "extra_tax_data",
        "deductible_amount", "is_imported", "is_downpayment", "is_storno",
        "sequence", "product_uom_id", "discount", "discount_date",
        "discount_amount_currency", "discount_balance",
        "l10n_latam_document_type_id",
        "no_followup", "collapse_composition", "collapse_prices",
        "create_uid", "create_date", "write_uid", "write_date",
        "odoo_cli_v3_line_reference",
    ),
    "account.payment": (
        "name", "state", "company_id", "partner_id", "journal_id", "currency_id",
        "date", "amount", "payment_type", "partner_type", "memo",
        "payment_reference", "payment_method_line_id", "destination_account_id",
        "outstanding_account_id", "move_id", "is_sent", "is_reconciled",
        "is_matched", "invoice_ids", "is_internal_transfer",
        "paired_internal_transfer_payment_id", "destination_journal_id",
        "reconciled_invoice_ids", "reconciled_bill_ids",
        "reconciled_statement_line_ids", "payment_transaction_id",
        "payment_token_id", "batch_payment_id", "check_number",
        "odoo_cli_v3_payment_binding",
        "create_uid", "create_date", "write_uid", "write_date",
    ),
    "account.payment.method.line": (
        "name", "active", "company_id", "journal_id", "payment_method_id",
        "payment_type", "payment_account_id",
    ),
    "account.payment.method": ("name", "code", "payment_type"),
    "account.bank.statement.line": (
        "company_id", "journal_id", "date", "amount", "foreign_currency_id",
        "currency_id", "amount_currency", "amount_residual", "partner_id",
        "payment_ref", "ref", "is_reconciled", "move_id", "statement_id",
        "payment_ids", "internal_index", "transaction_details",
        "odoo_cli_v3_external_transaction_id",
        "odoo_cli_v3_source_line_digest", "odoo_cli_v3_value_date",
    ),
    "account.bank.statement": (
        "name", "reference", "company_id", "journal_id", "currency_id",
        "date", "balance_start", "balance_end", "balance_end_real",
        "line_ids", "first_line_index", "is_complete", "is_valid",
        "odoo_cli_v3_external_reference", "odoo_cli_v3_source_digest",
        "odoo_cli_v3_source_filename",
    ),
    "account.asset": (
        "state", "company_id", "model_id", "name", "acquisition_date",
        "original_value", "currency_id", "original_move_line_ids",
        "journal_id", "account_asset_id", "account_depreciation_id",
        "account_depreciation_expense_id", "method", "method_number",
        "method_period", "method_progress_factor", "prorata_computation_type",
        "prorata_date", "salvage_value", "depreciation_move_ids", "value_residual",
        "book_value", "total_depreciable_value", "already_depreciated_amount_import",
    ),
    "account.account": (
        "name", "code", "company_ids", "account_type", "deprecated",
        "reconcile", "create_asset", "multiple_assets_per_line",
    ),
    "account.journal": (
        "name", "code", "company_id", "type", "active", "currency_id",
        "default_account_id", "suspense_account_id",
    ),
    "res.currency": (
        "name", "symbol", "active", "rounding", "decimal_places",
    ),
    "res.partner": (
        "name", "active", "company_id", "company_ids", "commercial_partner_id",
        "property_account_position_id",
        "property_account_receivable_id", "property_account_payable_id",
        "property_payment_term_id", "property_supplier_payment_term_id",
    ),
    "account.tax": (
        "name", "active", "company_id", "type_tax_use", "tax_scope",
        "amount_type", "fiscal_position_ids", "original_tax_ids",
        "replacing_tax_ids",
        "amount", "sequence", "price_include", "include_base_amount",
        "company_price_include", "price_include_override", "is_base_affected",
        "analytic",
        "tax_exigibility", "cash_basis_transition_account_id", "tax_group_id",
        "children_tax_ids",
        "invoice_repartition_line_ids", "refund_repartition_line_ids",
    ),
    "account.tax.repartition.line": (
        "company_id", "tax_id", "factor_percent", "repartition_type",
        "document_type", "account_id", "tag_ids", "sequence",
        "use_in_tax_closing",
    ),
    "product.product": (
        "name", "active", "company_id", "categ_id",
        "property_account_income_id", "property_account_expense_id",
        "taxes_id", "supplier_taxes_id",
    ),
    "product.category": (
        "name", "parent_id", "property_account_income_categ_id",
        "property_account_expense_categ_id", "property_cost_method",
        "property_valuation", "property_stock_journal",
        "property_stock_account_input_categ_id",
        "property_stock_account_output_categ_id",
        "property_stock_valuation_account_id",
    ),
    "res.company": (
        "name", "currency_id", "hard_lock_date", "fiscalyear_lock_date",
        "tax_lock_date", "sale_lock_date", "purchase_lock_date",
        "tax_exigibility",
        "tax_calculation_rounding_method", "account_price_include",
        "anglo_saxon_accounting",
        "generate_deferred_expense_entries_method",
        "deferred_expense_amount_computation_method",
        "deferred_expense_account_id", "deferred_expense_journal_id",
        "generate_deferred_revenue_entries_method",
        "deferred_revenue_amount_computation_method",
        "deferred_revenue_account_id", "deferred_revenue_journal_id",
    ),
    "account.partial.reconcile": (
        "company_id", "debit_move_id", "credit_move_id", "amount",
        "debit_amount_currency", "credit_amount_currency", "full_reconcile_id",
        "company_currency_id", "debit_currency_id", "credit_currency_id",
        "exchange_move_id", "max_date", "draft_caba_move_vals",
    ),
    "account.full.reconcile": (
        "partial_reconcile_ids", "reconciled_line_ids",
    ),
}

_PRESENCE_ONLY_SNAPSHOT_FIELDS = frozenset(
    {
        "access_token",
        "invoice_pdf_report_file",
        "l10n_es_edi_facturae_xml_file",
        "signature",
        "ubl_cii_xml_file",
    }
)

_SHARED_SNAPSHOT_MODELS = frozenset(
    {
        "res.partner",
        "product.product",
        "product.category",
        "account.payment.method",
    }
)

_REQUIRED_SNAPSHOT_FIELDS: dict[str, frozenset[str]] = {
    "account.move": frozenset(
        {
            "state", "move_type", "company_id", "journal_id", "currency_id",
            "partner_id", "date", "line_ids", "odoo_cli_v3_document_binding",
            "odoo_cli_v3_business_binding",
        }
    ),
    "account.move.line": frozenset(
        {
            "move_id", "company_id", "parent_state", "account_id",
            "currency_id", "debit",
            "credit", "balance", "amount_currency", "tax_ids", "tax_line_id",
            "tax_tag_ids", "analytic_distribution", "analytic_line_ids",
            "odoo_cli_v3_line_reference",
        }
    ),
    "account.payment": frozenset(
        {
            "state", "company_id", "partner_id", "journal_id", "currency_id",
            "date", "amount", "move_id", "is_sent", "is_reconciled",
            "is_matched", "invoice_ids",
            "odoo_cli_v3_payment_binding",
        }
    ),
    "account.payment.method.line": frozenset(
        {"company_id", "journal_id", "payment_method_id", "payment_type"}
    ),
    "account.payment.method": frozenset({"name", "code", "payment_type"}),
    "account.bank.statement": frozenset(
        {
            "company_id", "journal_id", "currency_id", "date", "line_ids",
            "odoo_cli_v3_external_reference", "odoo_cli_v3_source_digest",
            "odoo_cli_v3_source_filename",
        }
    ),
    "account.bank.statement.line": frozenset(
        {
            "company_id", "journal_id", "date", "amount", "move_id",
            "odoo_cli_v3_external_transaction_id",
            "odoo_cli_v3_source_line_digest", "odoo_cli_v3_value_date",
        }
    ),
    "account.asset": frozenset(_SNAPSHOT_FIELDS["account.asset"]),
    "account.account": frozenset(
        {
            "name", "code", "company_ids", "account_type", "deprecated",
            "reconcile",
        }
    ),
    "account.journal": frozenset(
        {"name", "code", "company_id", "type", "active", "currency_id"}
    ),
    "res.currency": frozenset({"name", "active", "rounding"}),
    "res.partner": frozenset(
        {
            "name", "active", "commercial_partner_id",
            "property_account_receivable_id", "property_account_payable_id",
        }
    ),
    "account.tax": frozenset(
        {
            "active", "company_id", "type_tax_use", "amount_type", "amount",
            "sequence", "price_include", "price_include_override",
            "include_base_amount", "is_base_affected", "tax_exigibility",
            "children_tax_ids", "invoice_repartition_line_ids",
            "refund_repartition_line_ids",
        }
    ),
    "account.tax.repartition.line": frozenset(
        {
            "company_id", "tax_id", "factor_percent", "repartition_type",
            "document_type", "account_id", "tag_ids", "sequence",
        }
    ),
    "res.company": frozenset(
        {
            "name", "currency_id", "hard_lock_date", "fiscalyear_lock_date",
            "tax_lock_date", "sale_lock_date", "purchase_lock_date",
            "tax_exigibility", "tax_calculation_rounding_method",
            "account_price_include",
        }
    ),
}

_DEFERRED_COMPANY_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    deferred_type: frozenset(
        {
            f"generate_deferred_{deferred_type}_entries_method",
            f"deferred_{deferred_type}_amount_computation_method",
            f"deferred_{deferred_type}_account_id",
            f"deferred_{deferred_type}_journal_id",
        }
    )
    for deferred_type in ("expense", "revenue")
}

_PAYMENT_BINDING_FIELDS = {
    "version",
    "payment_id",
    "payment_move_id",
    "payment_line_ids",
    "target_move_ids",
    "target_before",
    "target_line_before",
    "total_residual",
    "amount",
    "partner_id",
    "partner_type",
    "direction",
    "payment_date",
    "currency_id",
    "journal_id",
    "payment_method_line_id",
    "memo",
}
_PAYMENT_TARGET_FIELDS = {"move_id", "amount_residual"}
_PAYMENT_TARGET_LINE_FIELDS = {
    "line_id",
    "move_id",
    "amount_residual",
    "amount_residual_currency",
    "reconciled",
    "full_reconcile_id",
    "matched_debit_ids",
    "matched_credit_ids",
}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _recovery(
    status: str,
    method: str,
    targets: list[dict[str, Any]],
    **extra: Any,
) -> dict[str, Any]:
    if status == "available" and method not in _RECOVERY_ACTIONS:
        raise OdooWriteHandlerError("available recovery method has no execute allowlist")
    return {"status": status, "method": method, "targets": targets, **extra}


def _record_id(value: Any) -> int | None:
    identifier = getattr(value, "id", value)
    if isinstance(identifier, bool) or not isinstance(identifier, int) or identifier <= 0:
        return None
    return identifier


def _ids(value: Any) -> list[int]:
    identifiers = getattr(value, "ids", None)
    if identifiers is not None:
        return sorted(int(item) for item in identifiers)
    if isinstance(value, (list, tuple)):
        result = [_record_id(item) for item in value]
        return sorted(identifier for identifier in result if identifier is not None)
    identifier = _record_id(value)
    return [identifier] if identifier is not None else []


def _as_date(value: Any, field: str) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise OdooWriteHandlerError(f"{field} is not a valid ISO date") from exc
    raise OdooWriteHandlerError(f"{field} is not a valid ISO date")


def _decimal(value: Any, field: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except Exception as exc:
        raise OdooWriteHandlerError(f"{field} is not a decimal amount") from exc
    if not result.is_finite():
        raise OdooWriteHandlerError(f"{field} is not a finite decimal amount")
    return result


def _canonical_decimal(value: Any, field: str) -> str:
    normalized = _decimal(value, field).normalize()
    result = format(normalized, "f")
    return "0" if result in {"-0", ""} else result


def _primitive(value: Any) -> Any:
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, float):
        return format(Decimal(str(value)), "f")
    if isinstance(value, Mapping):
        return {str(key): _primitive(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_primitive(item) for item in value]
    identifier = _record_id(value)
    if identifier is not None and not isinstance(value, int):
        return identifier
    if value is False or value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)


def _is_present(value: Any) -> bool:
    return (
        value is not False
        and value is not None
        and value != ""
        and value != b""
    )


def _snapshot_primitive(field: str, value: Any) -> Any:
    if field in _PRESENCE_ONLY_SNAPSHOT_FIELDS:
        return {"present": _is_present(value)}
    return _primitive(value)


class OdooWriteHandlers:
    """Public-ORM-only write implementation bound to one non-superuser."""

    def __init__(self, context: OdooWriteContext) -> None:
        self.context = context
        env = context.env
        if getattr(env, "su", False) or getattr(env, "uid", None) != context.user_id:
            raise OdooWriteHandlerError(
                "Odoo environment must be bound to the authenticated non-superuser"
            )
        if isinstance(context.user_id, bool) or context.user_id <= 0:
            raise OdooWriteHandlerError("user_id must be a positive integer")
        if not isinstance(context.module_graph, TrustedModuleGraph):
            raise OdooWriteHandlerError("trusted installed-module graph is required")

    def bound_model(self, model_name: str, company: Any) -> Any:
        return self.context.env[model_name].with_context(
            allowed_company_ids=sorted(self.context.allowed_company_ids)
        ).with_company(company)

    def company(self, company_id: int) -> Any:
        if company_id not in self.context.allowed_company_ids:
            raise OdooWriteHandlerError("company is outside the authenticated company scope")
        model = self.context.env["res.company"].with_context(
            allowed_company_ids=sorted(self.context.allowed_company_ids)
        )
        model.check_access_rights("read")
        company = model.browse(company_id).exists()
        self.require_singleton(company, "res.company", company_id)
        company.check_access_rights("read")
        company.check_access_rule("read")
        return company

    @staticmethod
    def require_singleton(record: Any, model_name: str, record_id: int) -> None:
        if not record or len(record) != 1 or _record_id(record) != record_id:
            raise OdooWriteHandlerError(
                f"{model_name} {record_id} does not exist uniquely or is not visible"
            )

    def record(
        self,
        model_name: str,
        record_id: int,
        company: Any,
        *,
        write: bool = False,
        shared: bool = False,
    ) -> Any:
        model = self.bound_model(model_name, company)
        model.check_access_rights("read")
        record = model.browse(record_id).exists()
        self.require_singleton(record, model_name, record_id)
        record.check_access_rights("read")
        record.check_access_rule("read")
        if write:
            record.check_access_rights("write")
            record.check_access_rule("write")
        if model_name == "account.full.reconcile":
            reconciled_line_ids = _ids(record.reconciled_line_ids)
            if not reconciled_line_ids:
                raise OdooWriteHandlerError(
                    "account.full.reconcile has no company-bound journal items"
                )
            for line_id in reconciled_line_ids:
                self.record("account.move.line", line_id, company, write=write)
        else:
            self.assert_company(
                record, company, model_name=model_name, shared=shared
            )
        return record

    def record_is_absent(
        self,
        model_name: str,
        record_id: int,
        company: Any,
    ) -> bool:
        if (
            not isinstance(model_name, str)
            or not model_name.startswith("account.")
            or isinstance(record_id, bool)
            or not isinstance(record_id, int)
            or record_id <= 0
        ):
            raise OdooWriteHandlerError(
                "recovery absence identity is invalid"
            )
        model = self.bound_model(model_name, company)
        model.check_access_rights("read")
        record = model.browse(record_id).exists()
        if not record:
            return True
        self.require_singleton(record, model_name, record_id)
        record.check_access_rights("read")
        record.check_access_rule("read")
        return False

    @staticmethod
    def assert_company(record: Any, company: Any, *, model_name: str, shared: bool) -> None:
        company_id = _record_id(company)
        record_company = getattr(record, "company_id", None)
        record_company_id = _record_id(record_company)
        if record_company_id is not None:
            if record_company_id != company_id:
                raise OdooWriteHandlerError(f"{model_name} belongs to another company")
            return
        company_ids = _ids(getattr(record, "company_ids", []))
        if company_ids and company_id not in company_ids:
            raise OdooWriteHandlerError(f"{model_name} is not available to the company")
        if not shared and model_name not in {"res.currency", "res.company"} and not company_ids:
            raise OdooWriteHandlerError(f"{model_name} has no verifiable company binding")

    def create_model(self, model_name: str, company: Any, *, context: dict[str, Any] | None = None) -> Any:
        model = self.bound_model(model_name, company)
        if context:
            model = model.with_context(**context)
        model.check_access_rights("create")
        return model

    def search_records(
        self,
        model_name: str,
        domain: list[tuple[str, str, Any]],
        company: Any,
        *,
        limit: int = 1,
    ) -> list[Any]:
        model = self.bound_model(model_name, company)
        model.check_access_rights("read")
        records = model.search(domain, limit=limit)
        result = []
        for record in records:
            record.check_access_rights("read")
            record.check_access_rule("read")
            self.assert_company(
                record, company, model_name=model_name, shared=False
            )
            result.append(record)
        return result

    def assert_open_date(
        self,
        company: Any,
        value: Any,
        field: str,
        *,
        journal: Any | None = None,
        taxes: bool = False,
    ) -> date:
        posting_date = _as_date(value, field)
        if posting_date > self.context.today:
            raise OdooWriteHandlerError(f"{field} is in a future accounting period")
        lock_fields = ["hard_lock_date", "fiscalyear_lock_date"]
        journal_type = str(getattr(journal, "type", "")) if journal else ""
        if taxes:
            lock_fields.append("tax_lock_date")
        if journal_type == "sale":
            lock_fields.append("sale_lock_date")
        if journal_type == "purchase":
            lock_fields.append("purchase_lock_date")
        for lock_field in lock_fields:
            lock_value = getattr(company, lock_field, None)
            if lock_value and posting_date <= _as_date(lock_value, lock_field):
                raise OdooWriteHandlerError(f"{field} violates {lock_field}")
        return posting_date

    def assert_effective_open_date(
        self,
        company: Any,
        value: Any,
        field: str,
        *,
        journal: Any,
        taxes: bool = False,
        move: Any | None = None,
    ) -> date:
        posting_date = _as_date(value, field)
        if posting_date > self.context.today:
            raise OdooWriteHandlerError(
                f"{field} is in a future accounting period"
            )
        if move is None:
            checker = getattr(company, "_get_violated_lock_dates", None)
            checker_args = (posting_date, taxes, journal)
        else:
            tax_checker = getattr(move, "_affect_tax_report", None)
            checker = getattr(move, "_get_violated_lock_dates", None)
            if not callable(tax_checker):
                raise OdooWriteHandlerError(
                    "Odoo move tax-effect API is unavailable"
                )
            try:
                affects_tax_report = tax_checker()
            except Exception as exc:
                raise OdooWriteHandlerError(
                    "Odoo move tax-effect check failed"
                ) from exc
            if (
                not isinstance(affects_tax_report, bool)
                or affects_tax_report is not taxes
            ):
                raise OdooWriteHandlerError(
                    "manual journal entry has an unexpected Odoo tax effect"
                )
            checker_args = (posting_date, affects_tax_report)
        if not callable(checker):
            raise OdooWriteHandlerError(
                "Odoo effective lock-date API is unavailable"
            )
        try:
            violations = checker(*checker_args)
        except Exception as exc:
            raise OdooWriteHandlerError(
                "Odoo effective lock-date check failed"
            ) from exc
        if not isinstance(violations, list):
            raise OdooWriteHandlerError(
                "Odoo effective lock-date result is invalid"
            )
        normalized: list[tuple[date, str]] = []
        for violation in violations:
            if (
                not isinstance(violation, (list, tuple))
                or len(violation) != 2
                or not isinstance(violation[1], str)
                or not violation[1]
            ):
                raise OdooWriteHandlerError(
                    "Odoo effective lock-date result is invalid"
                )
            try:
                lock_date = _as_date(
                    violation[0], f"effective {violation[1]}"
                )
            except OdooWriteHandlerError as exc:
                raise OdooWriteHandlerError(
                    "Odoo effective lock-date result is invalid"
                ) from exc
            normalized.append((lock_date, violation[1]))
        if normalized:
            detail = ", ".join(
                f"{lock_field}={lock_date.isoformat()}"
                for lock_date, lock_field in normalized
            )
            raise OdooWriteHandlerError(
                f"{field} violates effective Odoo lock dates: {detail}"
            )
        return posting_date

    def assert_currency(self, currency_id: int, company: Any, journal: Any | None = None) -> Any:
        currency = self.record("res.currency", currency_id, company, shared=True)
        if getattr(currency, "active", True) is False:
            raise OdooWriteHandlerError("currency is inactive")
        journal_currency_id = _record_id(getattr(journal, "currency_id", None)) if journal else None
        company_currency_id = _record_id(getattr(company, "currency_id", None))
        if journal_currency_id is not None and journal_currency_id != currency_id:
            raise OdooWriteHandlerError("journal currency differs from the requested currency")
        if journal_currency_id is None and company_currency_id is None:
            raise OdooWriteHandlerError("company currency is not configured")
        return currency

    def assert_amount(self, actual: Any, expected: Any, currency: Any, field: str) -> None:
        rounding = _decimal(getattr(currency, "rounding", "0.01"), "currency.rounding")
        if rounding <= 0:
            raise OdooWriteHandlerError("currency rounding is invalid")
        actual_units = (_decimal(actual, field) / rounding).quantize(
            Decimal("1"), rounding=ROUND_HALF_UP
        )
        expected_units = (_decimal(expected, field) / rounding).quantize(
            Decimal("1"), rounding=ROUND_HALF_UP
        )
        if actual_units != expected_units:
            raise OdooWriteHandlerError(f"{field} differs from the approved amount")

    def assert_currency_precision(
        self, value: Any, currency: Any, field: str
    ) -> None:
        rounding = _decimal(
            getattr(currency, "rounding", "0.01"), "currency.rounding"
        )
        if rounding <= 0:
            raise OdooWriteHandlerError("currency rounding is invalid")
        units = _decimal(value, field) / rounding
        if units != units.quantize(Decimal("1")):
            raise OdooWriteHandlerError(
                f"{field} exceeds the approved currency precision"
            )

    def snapshot(
        self,
        model_name: str,
        record: Any,
        company: Any,
        *,
        required_fields: Any = (),
    ) -> dict[str, Any]:
        record_id = _record_id(record)
        if record_id is None:
            raise OdooWriteHandlerError(f"cannot snapshot an unidentified {model_name}")
        visible = self.record(
            model_name,
            record_id,
            company,
            shared=model_name in _SHARED_SNAPSHOT_MODELS,
        )
        fields = _SNAPSHOT_FIELDS.get(model_name, ())
        available = visible.fields_get(list(fields))
        requested = _REQUIRED_SNAPSHOT_FIELDS.get(
            model_name, frozenset()
        ) | frozenset(required_fields)
        try:
            required = conditional_required_fields(
                model_name,
                requested,
                available,
                self.context.module_graph,
            )
        except OdooModuleGraphError as exc:
            raise OdooWriteHandlerError(str(exc)) from exc
        missing = required - set(available)
        if missing:
            raise OdooWriteHandlerError(
                f"{model_name} is missing required auditable fields: "
                + ", ".join(sorted(missing))
            )
        fields = tuple(field for field in fields if field in available)
        values = visible.with_context(bin_size=True).read(list(fields))[0]
        values = {
            key: _snapshot_primitive(key, values[key])
            for key in sorted(values)
            if key != "id"
        }
        return {
            "model": model_name,
            "record_id": record_id,
            "company_id": _record_id(company),
            "state": str(getattr(visible, "state", "unknown") or "unknown"),
            "values": values,
            "values_digest": _digest(values),
        }

    def snapshots(
        self,
        records: list[tuple[str, Any]],
        company: Any,
        *,
        required_fields_by_model: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        required_fields_by_model = required_fields_by_model or {}
        result = [
            self.snapshot(
                model,
                record,
                company,
                required_fields=required_fields_by_model.get(model, ()),
            )
            for model, record in records
        ]
        return sorted(result, key=lambda item: (item["model"], item["record_id"]))

    @staticmethod
    def tombstone_snapshot(
        model_name: str, record_id: int, company: Any
    ) -> dict[str, Any]:
        if (
            not isinstance(model_name, str)
            or not model_name.startswith("account.")
            or isinstance(record_id, bool)
            or not isinstance(record_id, int)
            or record_id <= 0
            or _record_id(company) is None
        ):
            raise OdooWriteHandlerError("recovery tombstone identity is invalid")
        values: dict[str, Any] = {}
        return {
            "model": model_name,
            "record_id": record_id,
            "company_id": _record_id(company),
            "exists": False,
            "state": "absent",
            "values": values,
            "values_digest": _digest(values),
        }

    @staticmethod
    def _recovery_guard_outcome(
        method: str, model_name: str, record: Any
    ) -> str:
        if method in {
            "post_compensating_bank_statement_v1",
            "reverse_deferred_source_and_schedule_v1",
            "reverse_posted_customer_invoice_v1",
            "reverse_posted_refund_v1",
            "reverse_posted_vendor_bill_v1",
        }:
            return "survive_exact"
        if (
            method == "reverse_the_reversal_v1"
            and model_name == "account.move"
        ):
            return "survive_exact"
        if (
            method
            in {
                "cancel_and_unreconcile_payment_v1",
                "undo_reconciliation_and_reverse_writeoff_v1",
            }
            and model_name
            in {"account.partial.reconcile", "account.full.reconcile"}
        ):
            return "absent"
        if method == "cancel_asset_and_reverse_schedule_v1":
            if model_name == "account.move" and str(
                getattr(record, "state", "")
            ) == "draft":
                return "absent"
            if model_name == "account.move.line" and str(
                getattr(record, "parent_state", "")
            ) == "draft":
                return "absent"
        return "survive_allowed_delta"

    def available_recovery(
        self,
        capability_id: str,
        method: str,
        records: list[tuple[str, Any]],
        *,
        action_keys: set[tuple[str, int]],
        guard_outcomes: Mapping[tuple[str, int], str] | None = None,
    ) -> dict[str, Any]:
        contract = RECOVERY_ACTION_CONTRACTS.get(method)
        if (
            contract is None
            or contract.origin_capability_id != capability_id
            or not action_keys
        ):
            raise OdooWriteHandlerError(
                "write recovery action contract is invalid"
            )
        normalized = self.unique_records(records)
        by_key = {
            (model_name, _record_id(record)): record
            for model_name, record in normalized
        }
        if None in {record_id for _model_name, record_id in by_key}:
            raise OdooWriteHandlerError(
                "write recovery graph contains an unidentified record"
            )
        if not action_keys.issubset(by_key):
            raise OdooWriteHandlerError(
                "write recovery action is absent from the result graph"
            )
        if any(
            model_name not in contract.action_models
            for model_name, _record_id_value in action_keys
        ):
            raise OdooWriteHandlerError(
                "write recovery action model is outside its contract"
            )
        guard_keys = set(by_key) - action_keys
        guard_outcomes = guard_outcomes or {}
        if not set(guard_outcomes).issubset(guard_keys):
            raise OdooWriteHandlerError(
                "write recovery outcome override is outside the guard graph"
            )
        manual_method = _MANUAL_RECOVERY_METHODS[method]
        if (
            self.context.environment not in contract.allowed_environments
            or not guard_keys
        ):
            return _recovery(
                "manual_escalation",
                manual_method,
                [
                    {"model": model_name, "record_id": record_id}
                    for model_name, record_id in sorted(action_keys)
                ],
            )
        if any(
            model_name not in contract.guard_models
            for model_name, _record_id_value in guard_keys
        ):
            raise OdooWriteHandlerError(
                "write recovery guard graph is outside its contract"
            )
        guard_entries = []
        for model_name, record_id in sorted(guard_keys):
            outcome = guard_outcomes.get(
                (model_name, record_id),
                self._recovery_guard_outcome(
                    method, model_name, by_key[(model_name, record_id)]
                ),
            )
            if outcome not in contract.allowed_guard_outcomes:
                raise OdooWriteHandlerError(
                    "write recovery guard outcome is outside its contract"
                )
            guard_entries.append(
                {
                    "model": model_name,
                    "record_id": record_id,
                    "expected_outcome": outcome,
                }
            )
        return _recovery(
            "available",
            method,
            [
                {"model": model_name, "record_id": record_id}
                for model_name, record_id in sorted(action_keys)
            ],
            guards=guard_entries,
            oracle_id=contract.oracle_id,
        )

    def assert_approved_record_delta(
        self,
        model_name: str,
        record: Any,
        company: Any,
        approved: Mapping[str, Any] | None,
        *,
        allowed_changed_fields: frozenset[str],
        label: str,
    ) -> dict[str, Any]:
        if not isinstance(approved, Mapping):
            raise OdooWriteHandlerError(f"{label} approval snapshot is missing")
        current = self.snapshot(model_name, record, company)["values"]
        if set(current) != set(approved) or any(
            current[field] != approved[field]
            for field in set(current) - allowed_changed_fields
        ):
            raise OdooWriteHandlerError(
                f"{label} graph changed outside the approved posting allowlist"
            )
        return current

    def assert_controlled_log_access_delta(
        self,
        current: Mapping[str, Any],
        approved: Mapping[str, Any],
        *,
        label: str,
    ) -> datetime:
        required = {"create_uid", "create_date", "write_uid", "write_date"}
        if not required.issubset(current) or not required.issubset(approved):
            raise OdooWriteHandlerError(
                f"{label} log-access audit fields are incomplete"
            )
        if classic_read_many2one_id(current["write_uid"]) != self.context.user_id:
            raise OdooWriteHandlerError(
                f"{label} was not written by the bound execution user"
            )
        try:
            approved_write_date = datetime.fromisoformat(
                str(approved["write_date"])
            )
            current_write_date = datetime.fromisoformat(str(current["write_date"]))
        except (TypeError, ValueError) as exc:
            raise OdooWriteHandlerError(
                f"{label} write_date is not an auditable Odoo datetime"
            ) from exc
        if (
            approved_write_date.tzinfo is not None
            or current_write_date.tzinfo is not None
            or current_write_date < approved_write_date
        ):
            raise OdooWriteHandlerError(
                f"{label} write_date is outside the approved monotonic delta"
            )
        return current_write_date

    def precheck(self, capability_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
        if capability_id not in _CAPABILITIES:
            raise OdooWriteHandlerError("unsupported write capability")
        try:
            semantics = validate_write_semantics(capability_id, parameters)
        except WriteSemanticError as exc:
            raise OdooWriteHandlerError(str(exc)) from exc
        company = self.company(parameters["company_id"])
        method = getattr(self, self.dispatch_name(capability_id, "precheck"))
        detail = method(parameters, company)
        return {
            "capability_id": capability_id,
            "company_id": parameters["company_id"],
            "parameters_digest": _digest(parameters),
            "module_graph": self.context.module_graph.evidence,
            "semantic_precheck": semantics,
            "checks": sorted(set(detail.pop("checks", []))),
            **detail,
        }

    def execute(self, capability_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
        checked = self.precheck(capability_id, parameters)
        return self.execute_prechecked(capability_id, parameters, checked)

    def execute_prechecked(
        self,
        capability_id: str,
        parameters: dict[str, Any],
        checked: Mapping[str, Any],
    ) -> dict[str, Any]:
        if (
            not isinstance(checked, Mapping)
            or checked.get("capability_id") != capability_id
            or checked.get("company_id") != parameters.get("company_id")
            or checked.get("parameters_digest") != _digest(parameters)
            or checked.get("module_graph") != self.context.module_graph.evidence
            or not isinstance(checked.get("checks"), list)
            or not checked.get("checks")
        ):
            raise OdooWriteHandlerError(
                "approved live precheck evidence does not bind this execution"
            )
        company = self.company(parameters["company_id"])
        method = getattr(self, self.dispatch_name(capability_id, "execute"))
        result = method(parameters, company, checked)
        if (
            isinstance(result, tuple)
            and len(result) == 2
        ):
            records, recovery = result
            tombstone_keys: set[tuple[str, int]] = set()
            raw_tombstone_keys: tuple[Any, ...] = ()
        elif (
            capability_id == "acct.recovery.execute.v1"
            and isinstance(result, tuple)
            and len(result) == 3
        ):
            records, recovery, raw_tombstone_keys = result
            try:
                raw_tombstones = list(raw_tombstone_keys)
            except TypeError as exc:
                raise OdooWriteHandlerError(
                    "recovery tombstone graph is invalid"
                ) from exc
            if any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0].startswith("account.")
                or isinstance(item[1], bool)
                or not isinstance(item[1], int)
                or item[1] <= 0
                for item in raw_tombstones
            ):
                raise OdooWriteHandlerError(
                    "recovery tombstone graph is invalid"
                )
            tombstone_keys = set(raw_tombstones)
            if len(tombstone_keys) != len(raw_tombstones):
                raise OdooWriteHandlerError(
                    "recovery tombstone graph contains a duplicate"
                )
        else:
            raise OdooWriteHandlerError(
                "write handler returned an invalid execution tuple"
            )
        normalized_records = [(model, record) for model, record in records]
        record_keys = {
            (model_name, _record_id(record))
            for model_name, record in normalized_records
        }
        before_keys = {
            (item.get("model"), item.get("record_id"))
            for item in checked.get("before", [])
            if isinstance(item, Mapping)
        }
        if (
            record_keys & tombstone_keys
            or not tombstone_keys.issubset(before_keys)
        ):
            raise OdooWriteHandlerError(
                "recovery tombstone graph is not bound to precheck evidence"
            )
        after = [
            *self.snapshots(normalized_records, company),
            *(
                self.tombstone_snapshot(model_name, record_id, company)
                for model_name, record_id in sorted(tombstone_keys)
            ),
        ]
        after = sorted(
            after, key=lambda item: (item["model"], item["record_id"])
        )
        return {
            "capability_id": capability_id,
            "company_id": parameters["company_id"],
            "parameters_digest": checked["parameters_digest"],
            "module_graph": self.context.module_graph.evidence,
            "before": checked.get("before", []),
            "after": after,
            "records": [
                {"model": model, "record_id": _record_id(record)}
                for model, record in normalized_records
            ],
            "recovery": recovery,
        }

    def verify(
        self, capability_id: str, parameters: dict[str, Any], execution: Mapping[str, Any]
    ) -> dict[str, Any]:
        if execution.get("capability_id") != capability_id:
            raise OdooWriteHandlerError("execution capability does not match")
        if execution.get("parameters_digest") != _digest(parameters):
            raise OdooWriteHandlerError("execution parameters were changed")
        if execution.get("module_graph") != self.context.module_graph.evidence:
            raise OdooWriteHandlerError(
                "execution installed-module graph changed before verification"
            )
        company = self.company(parameters["company_id"])
        records: list[tuple[str, Any]] = []
        for reference in execution.get("records", []):
            model_name = str(reference["model"])
            record_id = int(reference["record_id"])
            records.append((model_name, self.record(model_name, record_id, company)))
        method = getattr(self, self.dispatch_name(capability_id, "verify"))
        if capability_id in {
            "acct.refund.create.v1",
            "acct.payment.register.v1",
            "acct.payment.cancel.v1",
            "acct.reconciliation.apply.v1",
            "acct.asset.create.v1",
            "acct.depreciation.post.v1",
            "acct.deferred.create.v1",
            "acct.move.post.v1",
            "acct.move.reverse.v1",
            "acct.move.draft_cancel.v1",
            "acct.move.draft_cancel.v2",
            "acct.recovery.execute.v1",
        }:
            verification_result = method(
                parameters,
                company,
                records,
                self.trusted_before_values(execution, company),
            )
        else:
            verification_result = method(parameters, company, records)
        if (
            capability_id == "acct.recovery.execute.v1"
            and isinstance(verification_result, tuple)
            and len(verification_result) == 2
        ):
            checks, raw_tombstone_keys = verification_result
            try:
                raw_tombstones = list(raw_tombstone_keys)
            except TypeError as exc:
                raise OdooWriteHandlerError(
                    "recovery verification tombstone graph is invalid"
                ) from exc
            if any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0].startswith("account.")
                or isinstance(item[1], bool)
                or not isinstance(item[1], int)
                or item[1] <= 0
                for item in raw_tombstones
            ):
                raise OdooWriteHandlerError(
                    "recovery verification tombstone graph is invalid"
                )
            tombstone_keys = set(raw_tombstones)
            if len(tombstone_keys) != len(raw_tombstones):
                raise OdooWriteHandlerError(
                    "recovery verification tombstone graph contains a duplicate"
                )
        else:
            checks = verification_result
            tombstone_keys = set()
        committed_tombstone_keys = {
            (item.get("model"), item.get("record_id"))
            for item in execution.get("after", [])
            if isinstance(item, Mapping) and item.get("exists") is False
        }
        if tombstone_keys != committed_tombstone_keys:
            raise OdooWriteHandlerError(
                "recovery verification tombstones differ from execution"
            )
        after = [
            *self.snapshots(records, company),
            *(
                self.tombstone_snapshot(model_name, record_id, company)
                for model_name, record_id in sorted(tombstone_keys)
            ),
        ]
        after = sorted(
            after, key=lambda item: (item["model"], item["record_id"])
        )
        return {
            "passed": True,
            "method": "odoo_public_orm_readback_v1",
            "checks": sorted(set(checks)),
            "after": after,
            "evidence_digest": _digest(after),
        }

    def trusted_before_values(
        self, execution: Mapping[str, Any], company: Any
    ) -> dict[tuple[str, int], dict[str, Any]]:
        before = execution.get("before")
        if not isinstance(before, list):
            raise OdooWriteHandlerError("trusted before snapshots are unavailable")
        result: dict[tuple[str, int], dict[str, Any]] = {}
        for item in before:
            if not isinstance(item, dict):
                raise OdooWriteHandlerError("trusted before snapshot is invalid")
            if set(item) == {
                "model", "record_id", "exists", "record_state",
                "values_json", "values_digest",
            }:
                try:
                    validate_record_snapshot(item)
                    values = json.loads(item["values_json"])
                except Exception as exc:
                    raise OdooWriteHandlerError(
                        "trusted before snapshot is invalid"
                    ) from exc
                if item["exists"] is not True:
                    raise OdooWriteHandlerError(
                        "trusted before record did not exist"
                    )
                model_name = item["model"]
                record_id = item["record_id"]
            elif set(item) == {
                "model", "record_id", "company_id", "state", "values",
                "values_digest",
            }:
                model_name = item["model"]
                record_id = item["record_id"]
                values = item["values"]
                if (
                    item["company_id"] != company.id
                    or not isinstance(values, dict)
                    or item["values_digest"] != _digest(values)
                ):
                    raise OdooWriteHandlerError(
                        "trusted before snapshot binding is invalid"
                    )
            else:
                raise OdooWriteHandlerError("trusted before snapshot fields are invalid")
            key = (str(model_name), int(record_id))
            if key in result:
                raise OdooWriteHandlerError("trusted before snapshot is duplicated")
            result[key] = values
        return result

    @staticmethod
    def dispatch_name(capability_id: str, phase: str) -> str:
        key = {
            "acct.invoice.customer_create.v1": "customer_invoice",
            "acct.bill.vendor_create.v1": "vendor_bill",
            "acct.refund.create.v1": "refund",
            "acct.payment.register.v1": "payment",
            "acct.payment.cancel.v1": "payment_cancel",
            "acct.bank.statement_import.v1": "bank",
            "acct.reconciliation.apply.v1": "reconciliation",
            "acct.asset.create.v1": "asset",
            "acct.depreciation.post.v1": "depreciation",
            "acct.accrual.create.v1": "accrual",
            "acct.deferred.create.v1": "deferred",
            "acct.period.adjustment_create.v1": "adjustment",
            "acct.journal.entry_create.v1": "journal_entry_create",
            "acct.move.post.v1": "move_post",
            "acct.move.reverse.v1": "reversal",
            "acct.move.draft_cancel.v1": "draft_cancel",
            "acct.move.draft_cancel.v2": "draft_cancel_v2",
            "acct.recovery.execute.v1": "recovery",
        }[capability_id]
        return f"{phase}_{key}"

    def check_journal(self, parameters: dict[str, Any], company: Any, allowed_types: set[str]) -> Any:
        journal = self.record("account.journal", parameters["journal_id"], company)
        if str(getattr(journal, "type", "")) not in allowed_types:
            raise OdooWriteHandlerError("journal type is not permitted for this capability")
        if getattr(journal, "active", True) is False:
            raise OdooWriteHandlerError("journal is inactive")
        return journal

    def checked_move_lines(self, move: Any, company: Any, *, write: bool = False) -> list[Any]:
        return [
            self.record("account.move.line", line_id, company, write=write)
            for line_id in _ids(getattr(move, "line_ids", []))
        ]

    def move_records(self, move: Any, company: Any) -> list[tuple[str, Any]]:
        return [
            ("account.move", move),
            *(
                ("account.move.line", line)
                for line in self.checked_move_lines(move, company)
            ),
        ]

    def assert_exact_move_graph(
        self,
        records: list[tuple[str, Any]],
        moves: list[Any],
        company: Any,
    ) -> None:
        expected: set[tuple[str, int]] = set()
        for move in moves:
            expected.add(("account.move", move.id))
            expected.update(
                ("account.move.line", line.id)
                for line in self.checked_move_lines(move, company)
            )
        actual = [(model_name, _record_id(record)) for model_name, record in records]
        if (
            any(record_id is None for _, record_id in actual)
            or len(actual) != len(set(actual))
            or set(actual) != expected
        ):
            raise OdooWriteHandlerError("affected record graph differs")

    @staticmethod
    def journal_line_signature(line: Any, *, reversed_amounts: bool = False) -> tuple[Any, ...]:
        debit = _decimal(getattr(line, "debit", 0), "journal line debit")
        credit = _decimal(getattr(line, "credit", 0), "journal line credit")
        balance = _decimal(getattr(line, "balance", debit - credit), "journal line balance")
        amount_currency = _decimal(
            getattr(line, "amount_currency", 0), "journal line amount_currency"
        )
        if reversed_amounts:
            debit, credit = credit, debit
            balance = -balance
            amount_currency = -amount_currency
        return (
            str(getattr(line, "name", "") or ""),
            _record_id(getattr(line, "account_id", None)),
            _record_id(getattr(line, "partner_id", None)),
            _record_id(getattr(line, "currency_id", None)),
            debit,
            credit,
            balance,
            amount_currency,
            tuple(_ids(getattr(line, "tax_ids", []))),
            _record_id(getattr(line, "tax_line_id", None)),
            str(getattr(line, "display_type", "") or ""),
        )

    def assert_linewise_reversal(
        self, origin: Any, reversal: Any, company: Any
    ) -> None:
        origin_lines = self.checked_move_lines(origin, company)
        reversal_lines = self.checked_move_lines(reversal, company)
        expected = sorted(
            repr(self.journal_line_signature(line, reversed_amounts=True))
            for line in origin_lines
        )
        actual = sorted(
            repr(self.journal_line_signature(line)) for line in reversal_lines
        )
        if expected != actual:
            raise OdooWriteHandlerError("journal items are not an exact linewise reversal")
        if any(_record_id(getattr(line, "move_id", None)) != origin.id for line in origin_lines):
            raise OdooWriteHandlerError("origin journal item graph differs")
        if any(
            _record_id(getattr(line, "move_id", None)) != reversal.id
            for line in reversal_lines
        ):
            raise OdooWriteHandlerError("reversal journal item graph differs")

    @staticmethod
    def snapshot_relation_id(value: Any) -> int | None:
        identifiers = _ids(value)
        if len(identifiers) > 1:
            raise OdooWriteHandlerError("approved relation is not singular")
        return identifiers[0] if identifiers else None

    def assert_approved_reversal_origin(
        self,
        origin: Any,
        company: Any,
        trusted_before: Mapping[tuple[str, int], dict[str, Any]] | None,
    ) -> None:
        if not isinstance(trusted_before, Mapping):
            raise OdooWriteHandlerError("approved reversal snapshots are missing")
        origin_lines = self.checked_move_lines(origin, company)
        expected_keys = {
            ("account.move", origin.id),
            *(("account.move.line", line.id) for line in origin_lines),
        }
        if set(trusted_before) != expected_keys:
            raise OdooWriteHandlerError("approved reversal origin graph differs")
        move_before = trusted_before[("account.move", origin.id)]
        if (
            str(move_before.get("state")) != str(origin.state)
            or str(move_before.get("move_type")) != str(origin.move_type)
            or self.snapshot_relation_id(move_before.get("journal_id"))
            != _record_id(origin.journal_id)
            or self.snapshot_relation_id(move_before.get("currency_id"))
            != _record_id(origin.currency_id)
            or set(_ids(move_before.get("line_ids"))) != {line.id for line in origin_lines}
            or _decimal(move_before.get("amount_total"), "approved reversal total")
            != _decimal(origin.amount_total, "reversal origin total")
            or str(move_before.get("date") or "") != str(origin.date or "")
            or str(move_before.get("ref") or "")
            != str(getattr(origin, "ref", "") or "")
            or self.snapshot_relation_id(move_before.get("partner_id"))
            != _record_id(getattr(origin, "partner_id", None))
            or str(move_before.get("odoo_cli_v3_document_binding") or "")
            != str(
                getattr(origin, "odoo_cli_v3_document_binding", "") or ""
            )
        ):
            raise OdooWriteHandlerError("reversal origin changed after approval")
        for line in origin_lines:
            values = trusted_before[("account.move.line", line.id)]
            approved = (
                str(values.get("name") or ""),
                self.snapshot_relation_id(values.get("account_id")),
                self.snapshot_relation_id(values.get("partner_id")),
                self.snapshot_relation_id(values.get("currency_id")),
                _decimal(values.get("debit"), "approved line debit"),
                _decimal(values.get("credit"), "approved line credit"),
                _decimal(values.get("balance"), "approved line balance"),
                _decimal(values.get("amount_currency"), "approved amount_currency"),
                tuple(_ids(values.get("tax_ids"))),
                self.snapshot_relation_id(values.get("tax_line_id")),
                str(values.get("display_type") or ""),
            )
            if (
                approved != self.journal_line_signature(line)
                or str(values.get("odoo_cli_v3_line_reference") or "")
                != str(
                    getattr(line, "odoo_cli_v3_line_reference", "") or ""
                )
                or bool(values.get("reconciled"))
                != bool(getattr(line, "reconciled", False))
                or self.snapshot_relation_id(values.get("full_reconcile_id"))
                != _record_id(getattr(line, "full_reconcile_id", None))
                or set(_ids(values.get("matched_debit_ids")))
                != set(_ids(getattr(line, "matched_debit_ids", [])))
                or set(_ids(values.get("matched_credit_ids")))
                != set(_ids(getattr(line, "matched_credit_ids", [])))
                or set(_ids(values.get("asset_ids")))
                != set(_ids(getattr(line, "asset_ids", [])))
                or str(values.get("deferred_start_date") or "")
                != str(getattr(line, "deferred_start_date", "") or "")
                or str(values.get("deferred_end_date") or "")
                != str(getattr(line, "deferred_end_date", "") or "")
            ):
                raise OdooWriteHandlerError("reversal origin line changed after approval")

    @staticmethod
    def unique_records(
        records: list[tuple[str, Any]],
    ) -> list[tuple[str, Any]]:
        result: list[tuple[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for model_name, record in records:
            record_id = _record_id(record)
            if record_id is None:
                raise OdooWriteHandlerError(
                    f"cannot return an unidentified {model_name} record"
                )
            key = (model_name, record_id)
            if key not in seen:
                seen.add(key)
                result.append((model_name, record))
        return result

    def assert_move_balanced(self, move: Any, company: Any) -> None:
        lines = self.checked_move_lines(move, company)
        if not lines:
            raise OdooWriteHandlerError("accounting move has no readable journal items")
        debit = sum(_decimal(line.debit, "debit") for line in lines)
        credit = sum(_decimal(line.credit, "credit") for line in lines)
        currency = self.assert_currency(_record_id(company.currency_id), company)
        self.assert_amount(debit, credit, currency, "move debit/credit balance")

    def asset_schedule_records(
        self, asset: Any, company: Any
    ) -> list[tuple[str, Any]]:
        records: list[tuple[str, Any]] = []
        move_ids = _ids(getattr(asset, "depreciation_move_ids", []))
        if len(move_ids) > 400:
            raise OdooWriteHandlerError("asset schedule exceeds the auditable record limit")
        for move_id in move_ids:
            move = self.record("account.move", move_id, company)
            records.extend(self.move_records(move, company))
        return records

    def assert_depreciation_accounts(
        self, move: Any, asset: Any, company: Any, currency: Any
    ) -> None:
        lines = self.checked_move_lines(move, company)
        if not lines:
            raise OdooWriteHandlerError("depreciation move has no journal items")
        expense_account_id = _record_id(asset.account_depreciation_expense_id)
        depreciation_account_id = _record_id(asset.account_depreciation_id)
        allowed = {expense_account_id, depreciation_account_id}
        if None in allowed or any(_record_id(line.account_id) not in allowed for line in lines):
            raise OdooWriteHandlerError("depreciation move uses an unexpected account")
        expected = _decimal(move.depreciation_value, "depreciation value")
        expense_balance = sum(
            _decimal(line.balance, "depreciation expense balance")
            for line in lines
            if _record_id(line.account_id) == expense_account_id
        )
        accumulated_balance = sum(
            _decimal(line.balance, "accumulated depreciation balance")
            for line in lines
            if _record_id(line.account_id) == depreciation_account_id
        )
        self.assert_amount(
            expense_balance, expected, currency, "depreciation expense balance"
        )
        self.assert_amount(
            accumulated_balance,
            -expected,
            currency,
            "accumulated depreciation balance",
        )
        self.assert_move_balanced(move, company)

    def check_partner(self, partner_id: int, company: Any) -> Any:
        partner = self.record("res.partner", partner_id, company, shared=True)
        if getattr(partner, "active", True) is False:
            raise OdooWriteHandlerError("partner is inactive")
        return partner

    def check_account(self, account_id: int, company: Any) -> Any:
        account = self.record("account.account", account_id, company)
        if getattr(account, "deprecated", False):
            raise OdooWriteHandlerError("account is deprecated")
        return account

    def check_taxes(
        self, tax_ids: list[int], company: Any, expected_use: str | None = None
    ) -> list[Any]:
        result = []
        for tax_id in tax_ids:
            tax = self.record("account.tax", tax_id, company)
            if getattr(tax, "active", True) is False:
                raise OdooWriteHandlerError("tax is inactive")
            tax_use = str(getattr(tax, "type_tax_use", "none"))
            if expected_use and tax_use not in {expected_use, "none"}:
                raise OdooWriteHandlerError("tax usage is incompatible with the document")
            result.append(tax)
        return result

    def tax_recordset(self, tax_ids: list[int], company: Any) -> Any:
        if not tax_ids:
            raise OdooWriteHandlerError("tax_recordset requires at least one tax")
        model = self.bound_model("account.tax", company)
        model.check_access_rights("read")
        taxes = model.browse(tax_ids).exists()
        if len(taxes) != len(tax_ids) or sorted(_ids(taxes)) != sorted(tax_ids):
            raise OdooWriteHandlerError("tax set is incomplete or ambiguous")
        taxes.check_access_rights("read")
        taxes.check_access_rule("read")
        for tax in taxes:
            self.assert_company(
                tax,
                company,
                model_name="account.tax",
                shared=False,
            )
        return taxes

    def document_tax_dependencies(
        self,
        taxes: list[Any],
        company: Any,
        *,
        expected_use: str,
    ) -> list[tuple[str, Any]]:
        dependencies: list[tuple[str, Any]] = []
        pending = list(taxes)
        seen: set[int] = set()
        while pending:
            tax = pending.pop()
            tax_id = _record_id(tax)
            if tax_id is None or tax_id in seen:
                continue
            if len(seen) >= 64:
                raise OdooWriteHandlerError(
                    "expanded tax graph exceeds the auditable limit"
                )
            seen.add(tax_id)
            dependencies.append(("account.tax", tax))
            child_ids = _ids(getattr(tax, "children_tax_ids", []))
            pending.extend(self.check_taxes(child_ids, company, expected_use))
            repartition_ids = sorted(
                set(
                    _ids(getattr(tax, "invoice_repartition_line_ids", []))
                    + _ids(getattr(tax, "refund_repartition_line_ids", []))
                )
            )
            for repartition_id in repartition_ids:
                repartition = self.record(
                    "account.tax.repartition.line", repartition_id, company
                )
                dependencies.append(
                    ("account.tax.repartition.line", repartition)
                )
                account_id = _record_id(getattr(repartition, "account_id", None))
                if account_id is not None:
                    dependencies.append(
                        ("account.account", self.check_account(account_id, company))
                    )
            transition_id = _record_id(
                getattr(tax, "cash_basis_transition_account_id", None)
            )
            if transition_id is not None:
                dependencies.append(
                    ("account.account", self.check_account(transition_id, company))
                )
        return dependencies

    def document_product_dependencies(
        self, product: Any, company: Any
    ) -> list[tuple[str, Any]]:
        dependencies: list[tuple[str, Any]] = [("product.product", product)]
        for field_name in (
            "property_account_income_id",
            "property_account_expense_id",
        ):
            account_id = _record_id(getattr(product, field_name, None))
            if account_id is not None:
                dependencies.append(
                    ("account.account", self.check_account(account_id, company))
                )
        category_id = _record_id(getattr(product, "categ_id", None))
        if category_id is None:
            return dependencies
        category = self.record(
            "product.category", category_id, company, shared=True
        )
        dependencies.append(("product.category", category))
        for field_name in (
            "property_account_income_categ_id",
            "property_account_expense_categ_id",
            "property_stock_account_input_categ_id",
            "property_stock_account_output_categ_id",
            "property_stock_valuation_account_id",
        ):
            account_id = _record_id(getattr(category, field_name, None))
            if account_id is not None:
                dependencies.append(
                    ("account.account", self.check_account(account_id, company))
                )
        stock_journal_id = _record_id(
            getattr(category, "property_stock_journal", None)
        )
        if stock_journal_id is not None:
            dependencies.append(
                (
                    "account.journal",
                    self.record(
                        "account.journal", stock_journal_id, company
                    ),
                )
            )
        return dependencies

    def document_financial_preview(
        self,
        lines: list[dict[str, Any]],
        company: Any,
        *,
        partner: Any,
        currency: Any,
        is_refund: bool,
    ) -> dict[str, Any]:
        previews: list[dict[str, Any]] = []
        amount_untaxed = Decimal("0")
        amount_total = Decimal("0")
        for line in lines:
            quantity = _decimal(line["quantity"], "quantity")
            price_unit = _decimal(line["price_unit"], "price_unit")
            product = None
            product_id = line.get("product_id")
            if product_id is not None:
                product = self.record(
                    "product.product", product_id, company, shared=True
                )
            if line["tax_ids"]:
                tax_result = self.tax_recordset(
                    line["tax_ids"], company
                ).compute_all(
                    float(price_unit),
                    currency=currency,
                    quantity=float(quantity),
                    product=product,
                    partner=partner,
                    is_refund=is_refund,
                )
                if not isinstance(tax_result, Mapping):
                    raise OdooWriteHandlerError(
                        "Odoo tax preview returned no structured result"
                    )
                excluded = _decimal(
                    tax_result.get("total_excluded"), "tax total_excluded"
                )
                included = _decimal(
                    tax_result.get("total_included"), "tax total_included"
                )
                raw_taxes = tax_result.get("taxes")
                if not isinstance(raw_taxes, list):
                    raise OdooWriteHandlerError(
                        "Odoo tax preview returned no tax breakdown"
                    )
                normalized_taxes = []
                for item in raw_taxes:
                    if not isinstance(item, Mapping):
                        raise OdooWriteHandlerError(
                            "Odoo tax preview item is invalid"
                        )
                    tax_id = item.get("id")
                    if (
                        isinstance(tax_id, bool)
                        or not isinstance(tax_id, int)
                        or tax_id <= 0
                    ):
                        raise OdooWriteHandlerError(
                            "Odoo tax preview identity is invalid"
                        )
                    normalized_taxes.append(
                        {
                            "tax_id": tax_id,
                            "amount": format(
                                _decimal(item.get("amount"), "tax amount"), "f"
                            ),
                        }
                    )
                normalized_taxes.sort(
                    key=lambda item: (item["tax_id"], item["amount"])
                )
                computed_tax = sum(
                    (_decimal(item["amount"], "tax amount") for item in normalized_taxes),
                    Decimal("0"),
                )
                self.assert_amount(
                    computed_tax,
                    included - excluded,
                    currency,
                    "tax breakdown total",
                )
            else:
                excluded = quantity * price_unit
                included = excluded
                normalized_taxes = []
            if excluded < 0 or included < 0:
                raise OdooWriteHandlerError(
                    "document line tax preview cannot be negative"
                )
            line_preview = {
                "line_reference": line["line_reference"],
                "amount_untaxed": format(excluded, "f"),
                "amount_tax": format(included - excluded, "f"),
                "amount_total": format(included, "f"),
                "taxes": normalized_taxes,
            }
            previews.append(line_preview)
            amount_untaxed += excluded
            amount_total += included
        return {
            "amount_untaxed": format(amount_untaxed, "f"),
            "amount_tax": format(amount_total - amount_untaxed, "f"),
            "amount_total": format(amount_total, "f"),
            "lines": previews,
        }

    def check_document_lines(
        self, lines: list[dict[str, Any]], company: Any, *, vendor: bool
    ) -> list[tuple[str, Any]]:
        expected_account_types = (
            {"expense", "expense_depreciation", "expense_direct_cost"}
            if vendor else {"income", "income_other"}
        )
        dependencies: list[tuple[str, Any]] = []
        expected_use = "purchase" if vendor else "sale"
        for line in lines:
            account = self.check_account(line["account_id"], company)
            dependencies.append(("account.account", account))
            account_type = str(getattr(account, "account_type", ""))
            if account_type not in expected_account_types:
                raise OdooWriteHandlerError("invoice line account type is incompatible")
            if line.get("product_id") is not None:
                product = self.record(
                    "product.product",
                    line["product_id"],
                    company,
                    shared=True,
                )
                dependencies.extend(
                    self.document_product_dependencies(product, company)
                )
            taxes = self.check_taxes(line["tax_ids"], company, expected_use)
            dependencies.extend(
                self.document_tax_dependencies(
                    taxes, company, expected_use=expected_use
                )
            )
        return self.unique_records(dependencies)

    def precheck_document(self, parameters: dict[str, Any], company: Any, *, vendor: bool) -> dict[str, Any]:
        partner = self.check_partner(parameters["partner_id"], company)
        journal = self.check_journal(parameters, company, {"purchase" if vendor else "sale"})
        currency = self.assert_currency(parameters["currency_id"], company, journal)
        self.assert_open_date(company, parameters["invoice_date"], "invoice_date", journal=journal)
        self.assert_open_date(
            company, parameters["accounting_date"], "accounting_date",
            journal=journal, taxes=any(line["tax_ids"] for line in parameters["lines"]),
        )
        line_dependencies = self.check_document_lines(
            parameters["lines"], company, vendor=vendor
        )
        kind = "vendor_bill" if vendor else "customer_invoice"
        binding = self.document_binding(kind, parameters)
        business_binding = self.business_binding(kind, parameters)
        move_type = "in_invoice" if vendor else "out_invoice"
        if self.search_records(
            "account.move",
            [
                ("company_id", "=", company.id),
                ("move_type", "=", move_type),
                ("odoo_cli_v3_document_binding", "=", binding),
            ],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "business document already exists for the approved parameters"
            )
        if self.search_records(
            "account.move",
            [
                ("company_id", "=", company.id),
                ("move_type", "=", move_type),
                ("odoo_cli_v3_business_binding", "=", business_binding),
            ],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "business document key already exists in this company"
            )
        financial_preview = self.document_financial_preview(
            parameters["lines"],
            company,
            partner=partner,
            currency=currency,
            is_refund=False,
        )
        computed_tax_ids = {
            item["tax_id"]
            for line in financial_preview["lines"]
            for item in line["taxes"]
        }
        dependency_tax_ids = {
            record.id
            for model_name, record in line_dependencies
            if model_name == "account.tax"
        }
        if not computed_tax_ids.issubset(dependency_tax_ids):
            raise OdooWriteHandlerError(
                "computed tax graph is not fully bound to the preview"
            )
        self.create_model("account.move", company)
        dependencies = self.unique_records(
            [
                ("res.company", company),
                ("res.partner", partner),
                ("account.journal", journal),
                ("res.currency", currency),
                *line_dependencies,
            ]
        )
        return {
            "checks": [
                "acl", "company", "dates", "journal", "currency", "lines",
                "tax_preview", "dependency_graph", "business_identity_unique",
            ],
            "before": [],
            "dependencies": self.snapshots(dependencies, company),
            "financial_preview": financial_preview,
            "document_binding": binding,
            "business_binding": business_binding,
        }

    def precheck_customer_invoice(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        return self.precheck_document(p, company, vendor=False)

    def precheck_vendor_bill(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        return self.precheck_document(p, company, vendor=True)

    @staticmethod
    def document_line_values(lines: list[dict[str, Any]]) -> list[tuple[int, int, dict[str, Any]]]:
        commands = []
        for line in lines:
            values = {
                "name": line["name"],
                "odoo_cli_v3_line_reference": line["line_reference"],
                "account_id": line["account_id"],
                "quantity": float(_decimal(line["quantity"], "quantity")),
                "price_unit": float(_decimal(line["price_unit"], "price_unit")),
                "tax_ids": [(6, 0, list(line["tax_ids"]))],
            }
            if line.get("product_id") is not None:
                values["product_id"] = line["product_id"]
            commands.append((0, 0, values))
        return commands

    def execute_document(
        self, p: dict[str, Any], company: Any, *, vendor: bool
    ) -> tuple[list[tuple[str, Any]], dict[str, Any]]:
        values = {
            "move_type": "in_invoice" if vendor else "out_invoice",
            "company_id": p["company_id"],
            "partner_id": p["partner_id"],
            "invoice_date": p["invoice_date"],
            "date": p["accounting_date"],
            "invoice_date_due": p["due_date"],
            "invoice_payment_term_id": False,
            "currency_id": p["currency_id"],
            "journal_id": p["journal_id"],
            "ref": p["vendor_reference"] if vendor else p["reference"],
            "invoice_line_ids": self.document_line_values(p["lines"]),
            "odoo_cli_v3_document_binding": self.document_binding(
                "vendor_bill" if vendor else "customer_invoice", p
            ),
            "odoo_cli_v3_business_binding": self.business_binding(
                "vendor_bill" if vendor else "customer_invoice", p
            ),
        }
        move = self.create_model("account.move", company).create(values)
        self.require_created(move, "account.move", company)
        if p["posting_mode"] == "post":
            move.action_post()
        records = self.move_records(move, company)
        if (
            p["posting_mode"] == "draft"
            and self.context.environment in {"test", "sandbox"}
        ):
            lines = [
                record
                for model_name, record in records
                if model_name == "account.move.line"
            ]
            self._assert_pristine_draft_document(
                move,
                lines,
                company,
                expected_state="draft",
                vendor=vendor,
            )
        if p["posting_mode"] == "draft":
            recovery_method = (
                DRAFT_VENDOR_BILL_RECOVERY_METHOD
                if vendor
                else DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD
            )
        else:
            recovery_method = (
                "reverse_posted_vendor_bill_v1"
                if vendor
                else "reverse_posted_customer_invoice_v1"
            )
        recovery = self.available_recovery(
            (
                "acct.bill.vendor_create.v1"
                if vendor
                else "acct.invoice.customer_create.v1"
            ),
            recovery_method,
            records,
            action_keys={("account.move", move.id)},
        )
        return records, recovery

    def execute_customer_invoice(self, p: dict[str, Any], company: Any, checked: dict[str, Any]):
        return self.execute_document(p, company, vendor=False)

    def execute_vendor_bill(self, p: dict[str, Any], company: Any, checked: dict[str, Any]):
        return self.execute_document(p, company, vendor=True)

    def verify_document(
        self, p: dict[str, Any], company: Any, records: list[tuple[str, Any]], *, vendor: bool
    ) -> list[str]:
        move = self.only_record(records, "account.move")
        if str(move.move_type) != ("in_invoice" if vendor else "out_invoice"):
            raise OdooWriteHandlerError("read-back document type differs")
        self.require_links(move, p, ("partner_id", "currency_id", "journal_id"))
        expected_state = "posted" if p["posting_mode"] == "post" else "draft"
        if str(move.state) != expected_state:
            raise OdooWriteHandlerError("read-back document state differs")
        if str(move.date) != p["accounting_date"] or str(move.invoice_date) != p["invoice_date"]:
            raise OdooWriteHandlerError("read-back document dates differ")
        if str(move.invoice_date_due) != p["due_date"]:
            raise OdooWriteHandlerError("read-back document due date differs")
        expected_reference = p["vendor_reference"] if vendor else p["reference"]
        if str(move.ref or "") != expected_reference:
            raise OdooWriteHandlerError("read-back document reference differs")
        expected_binding = self.document_binding(
            "vendor_bill" if vendor else "customer_invoice", p
        )
        if (
            str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
            != expected_binding
        ):
            raise OdooWriteHandlerError("read-back document binding differs")
        if (
            str(getattr(move, "odoo_cli_v3_business_binding", "") or "")
            != self.business_binding(
                "vendor_bill" if vendor else "customer_invoice", p
            )
        ):
            raise OdooWriteHandlerError("read-back document business binding differs")
        if _record_id(getattr(move, "invoice_payment_term_id", None)) is not None:
            raise OdooWriteHandlerError(
                "read-back document retained an unapproved payment term"
            )
        partner = self.check_partner(p["partner_id"], company)
        journal = self.check_journal(
            p, company, {"purchase" if vendor else "sale"}
        )
        currency = self.assert_currency(p["currency_id"], company, journal)
        financial_preview = self.document_financial_preview(
            p["lines"],
            company,
            partner=partner,
            currency=currency,
            is_refund=False,
        )
        invoice_lines = [
            self.record("account.move.line", line_id, company)
            for line_id in _ids(move.invoice_line_ids)
        ]
        if len(invoice_lines) != len(p["lines"]):
            raise OdooWriteHandlerError("read-back invoice line count differs")
        unused = list(invoice_lines)
        preview_by_reference = {
            item["line_reference"]: item for item in financial_preview["lines"]
        }
        for approved in p["lines"]:
            matches = [
                line for line in unused
                if str(line.name) == approved["name"]
                and str(getattr(line, "odoo_cli_v3_line_reference", "") or "")
                == approved["line_reference"]
                and _record_id(line.account_id) == approved["account_id"]
                and _record_id(getattr(line, "product_id", None)) == approved["product_id"]
                and _ids(line.tax_ids) == sorted(approved["tax_ids"])
                and _decimal(line.quantity, "quantity") == _decimal(approved["quantity"], "quantity")
                and _decimal(line.price_unit, "price_unit") == _decimal(approved["price_unit"], "price_unit")
            ]
            if len(matches) != 1:
                raise OdooWriteHandlerError("read-back invoice line differs or is ambiguous")
            matched = matches[0]
            preview = preview_by_reference[approved["line_reference"]]
            self.assert_amount(
                matched.price_subtotal,
                preview["amount_untaxed"],
                currency,
                "invoice line untaxed amount",
            )
            self.assert_amount(
                matched.price_total,
                preview["amount_total"],
                currency,
                "invoice line total amount",
            )
            unused.remove(matched)
        if unused:
            raise OdooWriteHandlerError("read-back invoice lines are ambiguous")
        self.assert_amount(
            move.amount_untaxed,
            financial_preview["amount_untaxed"],
            currency,
            "amount_untaxed",
        )
        self.assert_amount(
            move.amount_total,
            financial_preview["amount_total"],
            currency,
            "amount_total",
        )
        self.assert_amount(
            move.amount_tax,
            financial_preview["amount_tax"],
            currency,
            "amount_tax",
        )
        all_lines = self.checked_move_lines(move, company)
        invoice_line_ids = {line.id for line in invoice_lines}
        tax_lines = [
            line
            for line in all_lines
            if line.id not in invoice_line_ids
            and _record_id(getattr(line, "tax_line_id", None)) is not None
        ]
        other_lines = [
            line
            for line in all_lines
            if line.id not in invoice_line_ids and line not in tax_lines
        ]
        expected_term_type = "liability_payable" if vendor else "asset_receivable"
        if len(other_lines) != 1 or str(
            getattr(other_lines[0].account_id, "account_type", "")
        ) != expected_term_type:
            raise OdooWriteHandlerError(
                "read-back payment term account type or graph differs"
            )
        payment_term_line = other_lines[0]
        if (
            str(payment_term_line.date_maturity) != p["due_date"]
            or _record_id(getattr(payment_term_line, "partner_id", None))
            != p["partner_id"]
        ):
            raise OdooWriteHandlerError("read-back payment term due date or partner differs")
        if (
            bool(getattr(payment_term_line, "reconciled", False))
            or _record_id(getattr(payment_term_line, "full_reconcile_id", None))
            is not None
            or _ids(getattr(payment_term_line, "matched_debit_ids", []))
            or _ids(getattr(payment_term_line, "matched_credit_ids", []))
        ):
            raise OdooWriteHandlerError(
                "new document unexpectedly contains reconciliation state"
            )
        expected_tax_amounts: dict[int, Decimal] = {}
        for line_preview in financial_preview["lines"]:
            for item in line_preview["taxes"]:
                expected_tax_amounts[item["tax_id"]] = (
                    expected_tax_amounts.get(item["tax_id"], Decimal("0"))
                    + _decimal(item["amount"], "tax preview amount")
                )
        expected_tax_amounts = {
            tax_id: amount
            for tax_id, amount in expected_tax_amounts.items()
            if amount != 0
        }
        actual_tax_amounts: dict[int, Decimal] = {}
        company_currency_id = _record_id(company.currency_id)
        for line in tax_lines:
            tax_id = _record_id(line.tax_line_id)
            if tax_id is None:
                raise OdooWriteHandlerError("read-back tax line has no tax identity")
            if p["currency_id"] == company_currency_id:
                amount = abs(_decimal(line.balance, "tax line balance"))
            else:
                amount = abs(
                    _decimal(line.amount_currency, "tax line amount_currency")
                )
            actual_tax_amounts[tax_id] = (
                actual_tax_amounts.get(tax_id, Decimal("0")) + amount
            )
        if set(actual_tax_amounts) != set(expected_tax_amounts):
            raise OdooWriteHandlerError("read-back tax line identities differ")
        for tax_id, expected_amount in expected_tax_amounts.items():
            self.assert_amount(
                actual_tax_amounts[tax_id],
                expected_amount,
                currency,
                f"tax line {tax_id} amount",
            )
        self.assert_amount(
            abs(move.amount_residual),
            abs(move.amount_total),
            currency,
            "new document residual",
        )
        if str(getattr(move, "payment_state", "not_paid")) not in {
            "not_paid",
            "partial",
        }:
            raise OdooWriteHandlerError("new document payment state differs")
        self.assert_move_balanced(move, company)
        self.assert_exact_move_graph(records, [move], company)
        return [
            "record_exists", "company_matches", "links_match", "state_matches",
            "dates_match", "due_date_matches", "reference_matches",
            "document_binding_matches", "business_binding_matches",
            "payment_term_override_absent",
            "line_references_match", "lines_match", "line_totals_match_preview",
            "tax_total_matches", "tax_lines_match_preview",
            "document_total_matches", "payment_terms_match",
            "unpaid_residual_matches", "move_balanced", "record_graph_exact",
        ]

    def verify_customer_invoice(self, p, company, records):
        return self.verify_document(p, company, records, vendor=False)

    def verify_vendor_bill(self, p, company, records):
        return self.verify_document(p, company, records, vendor=True)

    def precheck_refund(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        origin = self.record("account.move", p["origin_move_id"], company, write=True)
        expected_type = "out_invoice" if p["refund_type"] == "customer_credit_note" else "in_invoice"
        if origin.state != "posted" or origin.move_type != expected_type:
            raise OdooWriteHandlerError("refund origin is not a compatible posted invoice")
        origin_lines = self.checked_move_lines(origin, company)
        invoice_line_ids = _ids(getattr(origin, "invoice_line_ids", []))
        if not origin_lines or not invoice_line_ids or not set(invoice_line_ids).issubset(
            {line.id for line in origin_lines}
        ):
            raise OdooWriteHandlerError("refund origin invoice graph is incomplete")
        origin_tax_lines = [
            line
            for line in origin_lines
            if line.id not in set(invoice_line_ids)
            and _record_id(getattr(line, "tax_line_id", None)) is not None
        ]
        origin_term_lines = [
            line
            for line in origin_lines
            if line.id not in set(invoice_line_ids) and line not in origin_tax_lines
        ]
        expected_origin_term_type = (
            "asset_receivable"
            if expected_type == "out_invoice"
            else "liability_payable"
        )
        if len(origin_term_lines) != 1 or str(
            getattr(origin_term_lines[0].account_id, "account_type", "")
        ) != expected_origin_term_type:
            raise OdooWriteHandlerError(
                "refund origin must have one auditable payment term line and no extra graph"
            )
        journal = self.check_journal(p, company, {"sale" if expected_type == "out_invoice" else "purchase"})
        currency = self.assert_currency(p["currency_id"], company, journal)
        if _record_id(origin.currency_id) != p["currency_id"]:
            raise OdooWriteHandlerError("refund currency differs from origin")
        if (
            str(getattr(origin.journal_id, "type", ""))
            != ("sale" if expected_type == "out_invoice" else "purchase")
            or getattr(origin.journal_id, "active", True) is False
        ):
            raise OdooWriteHandlerError("refund origin journal is incompatible")
        partner_id = _record_id(getattr(origin, "partner_id", None))
        if partner_id is None:
            raise OdooWriteHandlerError("refund origin partner is unavailable")
        partner = self.check_partner(partner_id, company)
        origin_date = _as_date(
            getattr(origin, "invoice_date", None) or getattr(origin, "date", None),
            "origin invoice date",
        )
        if _as_date(p["refund_date"], "refund_date") < origin_date:
            raise OdooWriteHandlerError("refund_date cannot precede the origin invoice")
        origin_total = abs(_decimal(origin.amount_total, "origin amount_total"))
        origin_residual = abs(
            _decimal(origin.amount_residual, "origin amount_residual")
        )
        self.assert_amount(
            origin_residual,
            origin_total,
            currency,
            "origin unpaid residual",
        )
        if str(getattr(origin, "payment_state", "")) != "not_paid":
            raise OdooWriteHandlerError("refund origin is not fully unpaid")
        unsafe_move_fields = (
            "statement_line_id", "statement_id", "asset_id",
            "deferred_move_ids", "deferred_original_move_ids",
            "tax_cash_basis_rec_id", "tax_cash_basis_origin_move_id",
            "reversed_entry_id", "reversal_move_ids",
        )
        if any(_ids(getattr(origin, field, None)) for field in unsafe_move_fields):
            raise OdooWriteHandlerError(
                "refund origin has existing accounting dependencies"
            )
        for line in origin_lines:
            if (
                bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None)) is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
                or _ids(getattr(line, "asset_ids", []))
                or getattr(line, "deferred_start_date", None)
                or getattr(line, "deferred_end_date", None)
            ):
                raise OdooWriteHandlerError(
                    "refund origin has existing accounting dependencies"
                )
        if self.search_records(
            "account.partial.reconcile",
            [("exchange_move_id", "=", origin.id)],
            company,
            limit=1,
        ) or self.search_records(
            "account.move",
            [("tax_cash_basis_origin_move_id", "=", origin.id)],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "refund origin has exchange or CABA accounting dependencies"
            )
        approved_total = _decimal(p["expected_total_amount"], "expected_total_amount")
        if p["refund_mode"] == "full":
            self.assert_amount(origin_total, approved_total, currency, "expected_total_amount")
            financial_preview = {
                "amount_untaxed": format(
                    abs(_decimal(origin.amount_untaxed, "origin amount_untaxed")),
                    "f",
                ),
                "amount_tax": format(
                    abs(_decimal(origin.amount_tax, "origin amount_tax")), "f"
                ),
                "amount_total": format(origin_total, "f"),
                "lines": [],
                "source": "approved_origin_graph",
            }
        else:
            if approved_total > origin_total:
                raise OdooWriteHandlerError("partial refund exceeds the origin total")
        self.assert_open_date(company, p["refund_date"], "refund_date", journal=journal, taxes=True)
        dependencies: list[tuple[str, Any]] = [
            ("res.company", company),
            ("res.partner", partner),
            ("account.journal", journal),
            ("res.currency", currency),
        ]
        expected_use = "sale" if expected_type == "out_invoice" else "purchase"
        for line_id in invoice_line_ids:
            line = self.record("account.move.line", line_id, company)
            account_id = _record_id(getattr(line, "account_id", None))
            if account_id is None:
                raise OdooWriteHandlerError(
                    "refund origin invoice line account is unavailable"
                )
            dependencies.append(
                ("account.account", self.check_account(account_id, company))
            )
            product_id = _record_id(getattr(line, "product_id", None))
            if product_id is not None:
                product = self.record(
                    "product.product", product_id, company, shared=True
                )
                dependencies.extend(
                    self.document_product_dependencies(product, company)
                )
            taxes = self.check_taxes(
                _ids(getattr(line, "tax_ids", [])), company, expected_use
            )
            dependencies.extend(
                self.document_tax_dependencies(
                    taxes, company, expected_use=expected_use
                )
            )
        if p["refund_mode"] == "partial":
            partial_dependencies = self.check_document_lines(
                p["lines"], company, vendor=p["refund_type"] == "vendor_debit_note"
            )
            dependencies.extend(partial_dependencies)
            financial_preview = self.document_financial_preview(
                p["lines"],
                company,
                partner=partner,
                currency=currency,
                is_refund=True,
            )
            self.assert_amount(
                financial_preview["amount_total"],
                approved_total,
                currency,
                "partial refund total",
            )
        binding = self.document_binding("refund", p)
        business_binding = self.business_binding("refund", p)
        expected_refund_type = (
            "out_refund"
            if p["refund_type"] == "customer_credit_note"
            else "in_refund"
        )
        if self.search_records(
            "account.move",
            [
                ("company_id", "=", company.id),
                ("move_type", "=", expected_refund_type),
                ("odoo_cli_v3_document_binding", "=", binding),
            ],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "business document already exists for the approved refund"
            )
        if self.search_records(
            "account.move",
            [
                ("company_id", "=", company.id),
                ("move_type", "=", expected_refund_type),
                ("odoo_cli_v3_business_binding", "=", business_binding),
            ],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "refund business key already exists in this company"
            )
        self.create_model("account.move.reversal", company)
        return {
            "checks": [
                "origin_posted", "origin_total", "origin_unpaid",
                "origin_dependency_graph_absent", "origin_graph_snapshotted",
                "partial_total_exact", "acl", "company", "date",
                "dependency_graph", "business_identity_unique",
            ],
            "before": self.snapshots(self.move_records(origin, company), company),
            "dependencies": self.snapshots(
                self.unique_records(dependencies), company
            ),
            "financial_preview": financial_preview,
            "document_binding": binding,
            "business_binding": business_binding,
        }

    def execute_refund(self, p, company, checked):
        origin = self.record(
            "account.move", p["origin_move_id"], company, write=True
        )
        wizard = self.create_model(
            "account.move.reversal", company,
            context={"active_model": "account.move", "active_ids": [p["origin_move_id"]]},
        ).create({"date": p["refund_date"], "journal_id": p["journal_id"], "reason": p["reason"]})
        action = wizard.refund_moves()
        refund = self.record_from_action("account.move", action, company, write=True)
        refund_values: dict[str, Any] = {
            "odoo_cli_v3_reason": p["reason"],
            "odoo_cli_v3_document_binding": self.document_binding("refund", p),
            "odoo_cli_v3_business_binding": self.business_binding("refund", p),
            "invoice_payment_term_id": False,
            "invoice_date_due": p["refund_date"],
        }
        if p["refund_mode"] == "partial":
            refund_values["invoice_line_ids"] = [
                (5, 0, 0),
                *self.document_line_values(p["lines"]),
            ]
        refund.write(refund_values)
        if p["posting_mode"] == "post" and refund.state != "posted":
            refund.action_post()
        if p["posting_mode"] == "draft" and refund.state != "draft":
            raise OdooWriteHandlerError(
                "Odoo refund wizard did not preserve the approved draft mode"
            )
        if p["posting_mode"] == "post" and refund.state != "posted":
            raise OdooWriteHandlerError("refund did not reach posted state")
        records = self.unique_records(
            [*self.move_records(origin, company), *self.move_records(refund, company)]
        )
        return records, self.available_recovery(
            "acct.refund.create.v1",
            (
                "cancel_draft_refund_v1"
                if p["posting_mode"] == "draft"
                else "reverse_posted_refund_v1"
            ),
            records,
            action_keys={("account.move", refund.id)},
            guard_outcomes={
                (model_name, record.id): "survive_exact"
                for model_name, record in self.move_records(origin, company)
            },
        )

    def assert_refund_origin_approval(
        self,
        origin: Any,
        refund: Any,
        company: Any,
        trusted_before: Mapping[tuple[str, int], dict[str, Any]] | None,
    ) -> None:
        if not isinstance(trusted_before, Mapping):
            raise OdooWriteHandlerError("approved refund origin snapshots are missing")
        origin_records = self.move_records(origin, company)
        expected_keys = {
            (model_name, record.id) for model_name, record in origin_records
        }
        if set(trusted_before) != expected_keys:
            raise OdooWriteHandlerError("approved refund origin graph differs")
        for model_name, record in origin_records:
            approved = trusted_before[(model_name, record.id)]
            if not isinstance(approved, dict):
                raise OdooWriteHandlerError(
                    "approved refund origin snapshot is invalid"
                )
            current = self.snapshot(model_name, record, company)["values"]
            if model_name == "account.move":
                approved = dict(approved)
                current = dict(current)
                approved_reversals = set(
                    _ids(approved.pop("reversal_move_ids", []))
                )
                current_reversals = set(
                    _ids(current.pop("reversal_move_ids", []))
                )
                if current_reversals != approved_reversals | {refund.id}:
                    raise OdooWriteHandlerError(
                        "refund origin reversal link differs from approval"
                    )
            if current != approved:
                raise OdooWriteHandlerError(
                    "refund origin changed after approval"
                )

    def verify_refund(self, p, company, records, trusted_before=None):
        origin_moves = [
            record
            for model_name, record in records
            if model_name == "account.move" and record.id == p["origin_move_id"]
        ]
        refund_moves = [
            record
            for model_name, record in records
            if model_name == "account.move" and record.id != p["origin_move_id"]
        ]
        if len(origin_moves) != 1 or len(refund_moves) != 1:
            raise OdooWriteHandlerError(
                "refund receipt does not contain one origin and one refund"
            )
        origin = origin_moves[0]
        refund = refund_moves[0]
        expected_type = "out_refund" if p["refund_type"] == "customer_credit_note" else "in_refund"
        if refund.move_type != expected_type:
            raise OdooWriteHandlerError("read-back refund type differs")
        if _record_id(refund.reversed_entry_id) != p["origin_move_id"]:
            raise OdooWriteHandlerError("refund is not linked to its origin")
        self.require_links(refund, p, ("currency_id", "journal_id"))
        if (
            str(refund.date) != p["refund_date"]
            or str(getattr(refund, "invoice_date", "") or "")
            != p["refund_date"]
        ):
            raise OdooWriteHandlerError("read-back refund date differs")
        if str(getattr(refund, "odoo_cli_v3_reason", "") or "") != p["reason"]:
            raise OdooWriteHandlerError("read-back refund reason differs")
        expected_binding = self.document_binding("refund", p)
        if (
            str(getattr(refund, "odoo_cli_v3_document_binding", "") or "")
            != expected_binding
        ):
            raise OdooWriteHandlerError("read-back refund binding differs")
        if (
            str(getattr(refund, "odoo_cli_v3_business_binding", "") or "")
            != self.business_binding("refund", p)
        ):
            raise OdooWriteHandlerError("read-back refund business binding differs")
        if (
            _record_id(getattr(refund, "invoice_payment_term_id", None))
            is not None
            or str(getattr(refund, "invoice_date_due", "") or "")
            != p["refund_date"]
        ):
            raise OdooWriteHandlerError("read-back refund payment term differs")
        journal = self.check_journal(
            p,
            company,
            {"sale" if expected_type == "out_refund" else "purchase"},
        )
        currency = self.assert_currency(p["currency_id"], company, journal)
        self.assert_amount(abs(refund.amount_total), p["expected_total_amount"], currency, "refund total")
        expected_state = "posted" if p["posting_mode"] == "post" else "draft"
        if refund.state != expected_state:
            raise OdooWriteHandlerError("read-back refund state differs")
        if _record_id(getattr(refund, "partner_id", None)) != _record_id(
            getattr(origin, "partner_id", None)
        ):
            raise OdooWriteHandlerError("read-back refund partner differs")
        invoice_lines = [
            self.record("account.move.line", line_id, company)
            for line_id in _ids(refund.invoice_line_ids)
        ]
        if p["refund_mode"] == "partial":
            if len(invoice_lines) != len(p["lines"]):
                raise OdooWriteHandlerError("partial refund line count differs")
            partner = self.check_partner(
                _record_id(refund.partner_id), company
            )
            financial_preview = self.document_financial_preview(
                p["lines"],
                company,
                partner=partner,
                currency=currency,
                is_refund=True,
            )
            unused = list(invoice_lines)
            preview_by_reference = {
                item["line_reference"]: item
                for item in financial_preview["lines"]
            }
            for approved in p["lines"]:
                matches = [
                    line
                    for line in unused
                    if str(line.name) == approved["name"]
                    and str(
                        getattr(line, "odoo_cli_v3_line_reference", "") or ""
                    )
                    == approved["line_reference"]
                    and _record_id(line.account_id) == approved["account_id"]
                    and _ids(line.tax_ids) == sorted(approved["tax_ids"])
                    and _decimal(line.quantity, "quantity")
                    == _decimal(approved["quantity"], "quantity")
                    and _decimal(line.price_unit, "price_unit")
                    == _decimal(approved["price_unit"], "price_unit")
                ]
                if len(matches) != 1:
                    raise OdooWriteHandlerError(
                        "read-back partial refund line differs or is ambiguous"
                    )
                matched = matches[0]
                preview = preview_by_reference[approved["line_reference"]]
                self.assert_amount(
                    matched.price_subtotal,
                    preview["amount_untaxed"],
                    currency,
                    "partial refund line untaxed amount",
                )
                self.assert_amount(
                    matched.price_total,
                    preview["amount_total"],
                    currency,
                    "partial refund line total amount",
                )
                unused.remove(matched)
            if unused:
                raise OdooWriteHandlerError(
                    "read-back partial refund lines are ambiguous"
                )
            self.assert_amount(
                refund.amount_untaxed,
                financial_preview["amount_untaxed"],
                currency,
                "partial refund untaxed amount",
            )
            self.assert_amount(
                refund.amount_tax,
                financial_preview["amount_tax"],
                currency,
                "partial refund tax amount",
            )
            self.assert_amount(
                refund.amount_total,
                financial_preview["amount_total"],
                currency,
                "partial refund total amount",
            )
        else:
            self.assert_linewise_reversal(origin, refund, company)
            if len(invoice_lines) != len(_ids(origin.invoice_line_ids)):
                raise OdooWriteHandlerError(
                    "full refund invoice line graph differs from origin"
                )
        all_refund_lines = self.checked_move_lines(refund, company)
        invoice_line_ids = {line.id for line in invoice_lines}
        tax_lines = [
            line
            for line in all_refund_lines
            if line.id not in invoice_line_ids
            and _record_id(getattr(line, "tax_line_id", None)) is not None
        ]
        term_lines = [
            line
            for line in all_refund_lines
            if line.id not in invoice_line_ids and line not in tax_lines
        ]
        expected_term_type = (
            "asset_receivable"
            if expected_type == "out_refund"
            else "liability_payable"
        )
        if len(term_lines) != 1 or str(
            getattr(term_lines[0].account_id, "account_type", "")
        ) != expected_term_type:
            raise OdooWriteHandlerError(
                "read-back refund payment term account type or graph differs"
            )
        if p["refund_mode"] == "partial":
            expected_tax_amounts: dict[int, Decimal] = {}
            for line_preview in financial_preview["lines"]:
                for item in line_preview["taxes"]:
                    expected_tax_amounts[item["tax_id"]] = (
                        expected_tax_amounts.get(item["tax_id"], Decimal("0"))
                        + _decimal(item["amount"], "refund tax preview amount")
                    )
            expected_tax_amounts = {
                tax_id: amount
                for tax_id, amount in expected_tax_amounts.items()
                if amount != 0
            }
            actual_tax_amounts: dict[int, Decimal] = {}
            company_currency_id = _record_id(company.currency_id)
            for line in tax_lines:
                tax_id = _record_id(line.tax_line_id)
                if tax_id is None:
                    raise OdooWriteHandlerError(
                        "read-back refund tax line has no identity"
                    )
                if p["currency_id"] == company_currency_id:
                    amount = abs(
                        _decimal(line.balance, "refund tax line balance")
                    )
                else:
                    amount = abs(
                        _decimal(
                            line.amount_currency,
                            "refund tax line amount_currency",
                        )
                    )
                actual_tax_amounts[tax_id] = (
                    actual_tax_amounts.get(tax_id, Decimal("0")) + amount
                )
            if set(actual_tax_amounts) != set(expected_tax_amounts):
                raise OdooWriteHandlerError(
                    "read-back refund tax line identities differ"
                )
            for tax_id, expected_amount in expected_tax_amounts.items():
                self.assert_amount(
                    actual_tax_amounts[tax_id],
                    expected_amount,
                    currency,
                    f"refund tax line {tax_id} amount",
                )
        term_line = term_lines[0]
        if (
            str(term_line.date_maturity) != p["refund_date"]
            or _record_id(getattr(term_line, "partner_id", None))
            != _record_id(refund.partner_id)
            or bool(getattr(term_line, "reconciled", False))
            or _record_id(getattr(term_line, "full_reconcile_id", None))
            is not None
            or _ids(getattr(term_line, "matched_debit_ids", []))
            or _ids(getattr(term_line, "matched_credit_ids", []))
        ):
            raise OdooWriteHandlerError(
                "read-back refund payment term or reconciliation differs"
            )
        self.assert_amount(
            abs(refund.amount_residual),
            abs(refund.amount_total),
            currency,
            "new refund residual",
        )
        if str(getattr(refund, "payment_state", "not_paid")) != "not_paid":
            raise OdooWriteHandlerError("new refund payment state differs")
        self.assert_refund_origin_approval(
            origin, refund, company, trusted_before
        )
        self.assert_move_balanced(origin, company)
        self.assert_move_balanced(refund, company)
        self.assert_exact_move_graph(records, [origin, refund], company)
        return [
            "refund_type_matches", "origin_link_matches", "date_matches",
            "journal_matches", "currency_matches", "reason_matches",
            "document_binding_matches", "business_binding_matches",
            "payment_term_matches",
            "total_matches", "state_matches", "partial_lines_match",
            "linewise_full_refund_exact", "unpaid_residual_matches",
            "origin_approval_matches", "move_balanced", "record_graph_exact",
        ]

    @staticmethod
    def payment_target_line_before(line: Any, move_id: int) -> dict[str, Any]:
        return {
            "line_id": line.id,
            "move_id": move_id,
            "amount_residual": format(
                _decimal(line.amount_residual, "amount_residual"), "f"
            ),
            "amount_residual_currency": format(
                _decimal(
                    line.amount_residual_currency,
                    "amount_residual_currency",
                ),
                "f",
            ),
            "reconciled": bool(line.reconciled),
            "full_reconcile_id": _record_id(line.full_reconcile_id),
            "matched_debit_ids": _ids(line.matched_debit_ids),
            "matched_credit_ids": _ids(line.matched_credit_ids),
        }

    def validated_payment_binding(
        self,
        value: Any,
        *,
        parameters: Mapping[str, Any] | None,
        complete: bool,
    ) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != _PAYMENT_BINDING_FIELDS:
            raise OdooWriteHandlerError("payment binding fields are invalid")
        binding = dict(value)

        def id_list(raw: Any, field: str, *, required: bool) -> list[int]:
            if not isinstance(raw, list) or any(
                isinstance(item, bool) or not isinstance(item, int) or item <= 0
                for item in raw
            ):
                raise OdooWriteHandlerError(f"payment binding {field} is invalid")
            if raw != sorted(set(raw)) or (required and not raw):
                raise OdooWriteHandlerError(f"payment binding {field} is invalid")
            return raw

        target_ids = id_list(
            binding["target_move_ids"], "target_move_ids", required=True
        )
        payment_line_ids = id_list(
            binding["payment_line_ids"], "payment_line_ids", required=complete
        )
        if complete:
            for field in ("payment_id", "payment_move_id"):
                identifier = binding[field]
                if (
                    isinstance(identifier, bool)
                    or not isinstance(identifier, int)
                    or identifier <= 0
                ):
                    raise OdooWriteHandlerError(
                        f"payment binding {field} is invalid"
                    )
            if binding["payment_move_id"] in target_ids:
                raise OdooWriteHandlerError("payment move aliases a payment target")
        elif (
            binding["payment_id"] is not None
            or binding["payment_move_id"] is not None
            or payment_line_ids
        ):
            raise OdooWriteHandlerError("precheck payment binding is already completed")

        target_before = binding["target_before"]
        if (
            not isinstance(target_before, list)
            or any(
                not isinstance(item, Mapping)
                or set(item) != _PAYMENT_TARGET_FIELDS
                for item in target_before
            )
            or [item["move_id"] for item in target_before] != target_ids
        ):
            raise OdooWriteHandlerError("payment target residual binding is invalid")
        residual_total = Decimal("0")
        for item in target_before:
            residual = _decimal(item["amount_residual"], "amount_residual")
            if residual <= 0:
                raise OdooWriteHandlerError("payment target residual is invalid")
            residual_total += residual

        line_before = binding["target_line_before"]
        if not isinstance(line_before, list) or not line_before:
            raise OdooWriteHandlerError("payment target line binding is invalid")
        line_ids: list[int] = []
        covered_moves: set[int] = set()
        for item in line_before:
            if not isinstance(item, Mapping) or set(item) != _PAYMENT_TARGET_LINE_FIELDS:
                raise OdooWriteHandlerError("payment target line fields are invalid")
            line_id = item["line_id"]
            move_id = item["move_id"]
            if (
                isinstance(line_id, bool)
                or not isinstance(line_id, int)
                or line_id <= 0
                or move_id not in target_ids
                or type(item["reconciled"]) is not bool
            ):
                raise OdooWriteHandlerError("payment target line identity is invalid")
            _decimal(item["amount_residual"], "amount_residual")
            _decimal(
                item["amount_residual_currency"],
                "amount_residual_currency",
            )
            full_id = item["full_reconcile_id"]
            if full_id is not None and (
                isinstance(full_id, bool)
                or not isinstance(full_id, int)
                or full_id <= 0
            ):
                raise OdooWriteHandlerError("payment full reconcile binding is invalid")
            id_list(item["matched_debit_ids"], "matched_debit_ids", required=False)
            id_list(item["matched_credit_ids"], "matched_credit_ids", required=False)
            line_ids.append(line_id)
            covered_moves.add(move_id)
        if line_ids != sorted(set(line_ids)) or covered_moves != set(target_ids):
            raise OdooWriteHandlerError("payment target line set is invalid")

        total = _decimal(binding["total_residual"], "total_residual")
        amount = _decimal(binding["amount"], "amount")
        if total != residual_total or amount <= 0 or amount > total:
            raise OdooWriteHandlerError("payment amount binding is invalid")
        for field in ("partner_id", "currency_id", "journal_id", "payment_method_line_id"):
            identifier = binding[field]
            if (
                isinstance(identifier, bool)
                or not isinstance(identifier, int)
                or identifier <= 0
            ):
                raise OdooWriteHandlerError(f"payment binding {field} is invalid")
        if binding["version"] != 1:
            raise OdooWriteHandlerError("payment binding version is unsupported")
        if binding["partner_type"] not in {"customer", "supplier"}:
            raise OdooWriteHandlerError("payment partner type binding is invalid")
        if binding["direction"] not in {"inbound", "outbound"}:
            raise OdooWriteHandlerError("payment direction binding is invalid")
        _as_date(binding["payment_date"], "payment_date")
        if not isinstance(binding["memo"], str) or not binding["memo"].strip():
            raise OdooWriteHandlerError("payment memo binding is invalid")

        if parameters is not None:
            expected = {
                "target_move_ids": sorted(parameters["target_move_ids"]),
                "amount": format(_decimal(parameters["amount"], "amount"), "f"),
                "partner_id": parameters["partner_id"],
                "partner_type": parameters["partner_type"],
                "direction": parameters["direction"],
                "payment_date": parameters["payment_date"],
                "currency_id": parameters["currency_id"],
                "journal_id": parameters["journal_id"],
                "payment_method_line_id": parameters["payment_method_line_id"],
                "memo": parameters["memo"],
            }
            if any(binding[field] != expected[field] for field in expected):
                raise OdooWriteHandlerError(
                    "payment binding differs from approved parameters"
                )
        return binding

    def precheck_payment(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        partner = self.check_partner(p["partner_id"], company)
        journal = self.check_journal(p, company, {"bank", "cash", "credit"})
        currency = self.assert_currency(p["currency_id"], company, journal)
        if p["currency_id"] != _record_id(company.currency_id):
            raise OdooWriteHandlerError(
                "foreign-currency payment is disabled until its exchange graph is approved exactly"
            )
        if bool(getattr(company, "tax_exigibility", False)):
            raise OdooWriteHandlerError(
                "cash-basis payment is disabled until its tax graph is approved exactly"
            )
        method = self.record("account.payment.method.line", p["payment_method_line_id"], company)
        if _record_id(method.journal_id) != p["journal_id"]:
            raise OdooWriteHandlerError("payment method does not belong to the journal")
        payment_method_id = _record_id(getattr(method, "payment_method_id", None))
        if payment_method_id is None:
            raise OdooWriteHandlerError(
                "payment method line has no auditable payment method definition"
            )
        payment_method = self.record(
            "account.payment.method", payment_method_id, company, shared=True
        )
        if str(getattr(method, "payment_type", "")) != p["direction"]:
            raise OdooWriteHandlerError(
                "payment method direction differs from the approved payment"
            )
        if str(getattr(payment_method, "payment_type", "")) != p["direction"]:
            raise OdooWriteHandlerError(
                "payment method definition direction differs from the approved payment"
            )
        expected = {
            ("customer", "inbound"): "out_invoice",
            ("customer", "outbound"): "out_refund",
            ("supplier", "outbound"): "in_invoice",
            ("supplier", "inbound"): "in_refund",
        }[(p["partner_type"], p["direction"])]
        moves: list[Any] = []
        move_lines: list[tuple[int, Any]] = []
        target_before: list[dict[str, Any]] = []
        total = Decimal("0")
        for move_id in sorted(p["target_move_ids"]):
            move = self.record("account.move", move_id, company, write=True)
            if move.state != "posted" or move.move_type != expected:
                raise OdooWriteHandlerError("payment target has an incompatible type or state")
            lines = self.checked_move_lines(move, company, write=True)
            if _record_id(move.partner_id) != _record_id(partner) or _record_id(move.currency_id) != p["currency_id"]:
                raise OdooWriteHandlerError("payment targets do not share partner and currency")
            residual = abs(_decimal(move.amount_residual, "amount_residual"))
            if residual == 0:
                raise OdooWriteHandlerError("payment target has no open residual")
            total += residual
            target_before.append(
                {"move_id": move_id, "amount_residual": format(residual, "f")}
            )
            moves.append(move)
            move_lines.extend((move_id, line) for line in lines)
        amount = _decimal(p["amount"], "amount")
        if len(moves) > 1 and amount != total:
            raise OdooWriteHandlerError(
                "multi-target partial payment allocation is not explicit"
            )
        if amount - total >= _decimal(currency.rounding, "currency.rounding"):
            raise OdooWriteHandlerError("payment exceeds the target residual")
        self.assert_open_date(company, p["payment_date"], "payment_date", journal=journal)
        self.create_model("account.payment.register", company)
        binding = {
            "version": 1,
            "payment_id": None,
            "payment_move_id": None,
            "payment_line_ids": [],
            "target_move_ids": sorted(p["target_move_ids"]),
            "target_before": target_before,
            "target_line_before": sorted(
                (
                    self.payment_target_line_before(line, move_id)
                    for move_id, line in move_lines
                ),
                key=lambda item: item["line_id"],
            ),
            "total_residual": format(total, "f"),
            "amount": format(amount, "f"),
            "partner_id": p["partner_id"],
            "partner_type": p["partner_type"],
            "direction": p["direction"],
            "payment_date": p["payment_date"],
            "currency_id": p["currency_id"],
            "journal_id": p["journal_id"],
            "payment_method_line_id": p["payment_method_line_id"],
            "memo": p["memo"],
        }
        self.validated_payment_binding(
            binding, parameters=p, complete=False
        )
        before_records = self.unique_records(
            [("account.move", move) for move in moves]
            + [("account.move.line", line) for _move_id, line in move_lines]
        )
        dependency_records: list[tuple[str, Any]] = [
            ("res.company", company),
            ("res.partner", partner),
            ("account.journal", journal),
            ("res.currency", currency),
            ("account.payment.method.line", method),
            ("account.payment.method", payment_method),
        ]
        dependency_account_ids = {
            account_id
            for _move_id, line in move_lines
            for account_id in [_record_id(getattr(line, "account_id", None))]
            if account_id is not None
        }
        dependency_account_ids.update(
            account_id
            for account_id in [
                _record_id(getattr(journal, "default_account_id", None)),
                _record_id(getattr(method, "payment_account_id", None)),
            ]
            if account_id is not None
        )
        dependency_records.extend(
            ("account.account", self.check_account(account_id, company))
            for account_id in sorted(dependency_account_ids)
        )
        return {
            "checks": ["targets_open", "partner", "currency", "journal", "method", "amount"],
            "before": self.snapshots(before_records, company),
            "dependencies": self.snapshots(
                self.unique_records(dependency_records), company
            ),
            "payment_binding": binding,
        }

    def execute_payment(self, p, company, checked):
        binding = self.validated_payment_binding(
            checked.get("payment_binding"), parameters=p, complete=False
        )
        wizard = self.create_model(
            "account.payment.register", company,
            context={"active_model": "account.move", "active_ids": list(p["target_move_ids"])},
        ).create({
            "group_payment": True,
            "payment_date": p["payment_date"],
            "amount": float(_decimal(p["amount"], "amount")),
            "currency_id": p["currency_id"],
            "journal_id": p["journal_id"],
            "payment_method_line_id": p["payment_method_line_id"],
            "communication": p["memo"],
        })
        self.require_links(wizard, p, ("partner_id", "currency_id", "journal_id", "payment_method_line_id"))
        if wizard.partner_type != p["partner_type"] or wizard.payment_type != p["direction"]:
            raise OdooWriteHandlerError("payment wizard derived a different payment direction")
        action = wizard.action_create_payments()
        payment = self.record_from_action(
            "account.payment", action, company, write=True
        )
        payment_move_id = _record_id(payment.move_id)
        if payment_move_id is None:
            raise OdooWriteHandlerError("payment has no deterministic accounting move")
        payment_move = self.record("account.move", payment_move_id, company)
        payment_lines = self.checked_move_lines(payment_move, company)
        completed_binding = {
            **binding,
            "payment_id": payment.id,
            "payment_move_id": payment_move_id,
            "payment_line_ids": sorted(line.id for line in payment_lines),
        }
        self.validated_payment_binding(
            completed_binding, parameters=p, complete=True
        )
        payment.write({"odoo_cli_v3_payment_binding": completed_binding})

        target_moves = [
            self.record("account.move", move_id, company)
            for move_id in completed_binding["target_move_ids"]
        ]
        target_lines = [
            line
            for move in target_moves
            for line in self.checked_move_lines(move, company)
        ]
        all_lines = self.unique_records(
            [("account.move.line", line) for line in payment_lines + target_lines]
        )
        partial_ids = sorted(
            {
                partial_id
                for _model_name, line in all_lines
                for partial_id in (
                    _ids(line.matched_debit_ids) + _ids(line.matched_credit_ids)
                )
            }
        )
        partials = [
            self.record("account.partial.reconcile", partial_id, company)
            for partial_id in partial_ids
        ]
        if any(
            _record_id(getattr(partial, "exchange_move_id", None)) is not None
            for partial in partials
        ):
            raise OdooWriteHandlerError(
                "payment created an unsupported exchange-difference graph"
            )
        if partial_ids and self.search_records(
            "account.move",
            [("tax_cash_basis_rec_id", "in", partial_ids)],
            company,
            limit=1000,
        ):
            raise OdooWriteHandlerError(
                "payment created an unsupported cash-basis tax graph"
            )
        full_ids = sorted(
            {
                full_id
                for _model_name, line in all_lines
                for full_id in [
                    _record_id(getattr(line, "full_reconcile_id", None))
                ]
                if full_id is not None
            }
            | {
                full_id
                for partial in partials
                for full_id in [
                    _record_id(getattr(partial, "full_reconcile_id", None))
                ]
                if full_id is not None
            }
        )
        fulls = [
            self.record("account.full.reconcile", full_id, company)
            for full_id in full_ids
        ]
        result_records = self.unique_records(
            [("account.payment", payment), ("account.move", payment_move)]
            + [("account.move", move) for move in target_moves]
            + all_lines
            + [("account.partial.reconcile", partial) for partial in partials]
            + [("account.full.reconcile", full) for full in fulls]
        )
        prior_partial_ids = {
            partial_id
            for item in completed_binding["target_line_before"]
            for partial_id in (
                item["matched_debit_ids"] + item["matched_credit_ids"]
            )
        }
        prior_full_ids = {
            item["full_reconcile_id"]
            for item in completed_binding["target_line_before"]
            if item["full_reconcile_id"] is not None
        }
        if prior_partial_ids or prior_full_ids:
            recovery = _recovery(
                "manual_escalation",
                _MANUAL_RECOVERY_METHODS[
                    "cancel_and_unreconcile_payment_v1"
                ],
                [{"model": "account.payment", "record_id": payment.id}],
            )
        else:
            recovery = self.available_recovery(
                "acct.payment.register.v1",
                "cancel_and_unreconcile_payment_v1",
                result_records,
                action_keys={("account.payment", payment.id)},
            )
        return result_records, recovery

    def verify_payment(self, p, company, records, before):
        payment = self.only_record(records, "account.payment")
        binding = self.validated_payment_binding(
            getattr(payment, "odoo_cli_v3_payment_binding", None),
            parameters=p,
            complete=True,
        )
        if binding["payment_id"] != payment.id:
            raise OdooWriteHandlerError("payment binding record identity differs")
        self.require_links(
            payment,
            p,
            ("partner_id", "currency_id", "journal_id", "payment_method_line_id"),
        )
        if payment.partner_type != p["partner_type"] or payment.payment_type != p["direction"]:
            raise OdooWriteHandlerError("read-back payment direction differs")
        if str(payment.date) != p["payment_date"] or str(payment.memo or "") != p["memo"]:
            raise OdooWriteHandlerError("read-back payment date or memo differs")
        if payment.state not in {"in_process", "paid"}:
            raise OdooWriteHandlerError("payment did not reach an accepted posted state")
        currency = self.assert_currency(p["currency_id"], company)
        self.assert_amount(payment.amount, p["amount"], currency, "payment amount")

        keyed: dict[tuple[str, int], Any] = {}
        for model_name, record in records:
            key = (model_name, record.id)
            if key in keyed:
                raise OdooWriteHandlerError("payment read-back record is duplicated")
            keyed[key] = record
        expected_before_keys = {
            *(
                ("account.move", move_id)
                for move_id in binding["target_move_ids"]
            ),
            *(
                ("account.move.line", item["line_id"])
                for item in binding["target_line_before"]
            ),
        }
        if not isinstance(before, Mapping) or set(before) != expected_before_keys:
            raise OdooWriteHandlerError(
                "trusted payment target before graph differs"
            )
        binding_lines = {
            item["line_id"]: item for item in binding["target_line_before"]
        }
        for item in binding["target_before"]:
            approved = before[("account.move", item["move_id"])]
            if (
                str(approved.get("state")) != "posted"
                or abs(
                    _decimal(
                        approved.get("amount_residual"),
                        "approved target residual",
                    )
                )
                != _decimal(item["amount_residual"], "bound target residual")
            ):
                raise OdooWriteHandlerError(
                    "payment target binding differs from trusted approval"
                )
        for line_id, item in binding_lines.items():
            approved = before[("account.move.line", line_id)]
            if (
                _record_id(approved.get("move_id")) != item["move_id"]
                or _decimal(
                    approved.get("amount_residual"),
                    "approved target line residual",
                )
                != _decimal(item["amount_residual"], "bound target line residual")
                or _decimal(
                    approved.get("amount_residual_currency"),
                    "approved target line currency residual",
                )
                != _decimal(
                    item["amount_residual_currency"],
                    "bound target line currency residual",
                )
                or bool(approved.get("reconciled")) != item["reconciled"]
                or _record_id(approved.get("full_reconcile_id"))
                != item["full_reconcile_id"]
                or _ids(approved.get("matched_debit_ids", []))
                != item["matched_debit_ids"]
                or _ids(approved.get("matched_credit_ids", []))
                != item["matched_credit_ids"]
            ):
                raise OdooWriteHandlerError(
                    "payment target line binding differs from trusted approval"
                )
        payment_move = keyed.get(("account.move", binding["payment_move_id"]))
        if payment_move is None or payment_move.state != "posted":
            raise OdooWriteHandlerError("payment accounting move is not posted")
        if _record_id(payment.move_id) != payment_move.id:
            raise OdooWriteHandlerError("payment accounting move link differs")
        if _ids(payment_move.line_ids) != binding["payment_line_ids"]:
            raise OdooWriteHandlerError("payment accounting line set differs")

        target_line_ids_by_move: dict[int, list[int]] = {
            move_id: [] for move_id in binding["target_move_ids"]
        }
        for item in binding["target_line_before"]:
            target_line_ids_by_move[item["move_id"]].append(item["line_id"])
        remaining = Decimal("0")
        for item in binding["target_before"]:
            target = keyed.get(("account.move", item["move_id"]))
            if target is None or target.state != "posted":
                raise OdooWriteHandlerError("payment target read-back is unavailable")
            if _ids(target.line_ids) != target_line_ids_by_move[target.id]:
                raise OdooWriteHandlerError("payment target accounting line set differs")
            self.assert_approved_record_delta(
                "account.move",
                target,
                company,
                before[("account.move", target.id)],
                allowed_changed_fields=frozenset(
                    {"amount_residual", "payment_state"}
                ),
                label="payment target move",
            )
            remaining += abs(_decimal(target.amount_residual, "amount_residual"))
        self.assert_amount(
            _decimal(binding["total_residual"], "total_residual") - remaining,
            p["amount"],
            currency,
            "payment target residual reduction",
        )

        linked = (
            _ids(payment.reconciled_invoice_ids)
            if p["partner_type"] == "customer"
            else _ids(payment.reconciled_bill_ids)
        )
        other_linked = (
            _ids(payment.reconciled_bill_ids)
            if p["partner_type"] == "customer"
            else _ids(payment.reconciled_invoice_ids)
        )
        if linked != binding["target_move_ids"] or other_linked:
            raise OdooWriteHandlerError("payment target document links differ")

        target_line_ids = {
            item["line_id"] for item in binding["target_line_before"]
        }
        payment_line_ids = set(binding["payment_line_ids"])
        bound_line_ids = target_line_ids | payment_line_ids
        bound_lines = {
            line_id: keyed.get(("account.move.line", line_id))
            for line_id in bound_line_ids
        }
        if any(line is None for line in bound_lines.values()):
            raise OdooWriteHandlerError(
                "payment accounting line receipt is missing"
            )
        for line_id in target_line_ids:
            self.assert_approved_record_delta(
                "account.move.line",
                bound_lines[line_id],
                company,
                before[("account.move.line", line_id)],
                allowed_changed_fields=frozenset(
                    {
                        "amount_residual",
                        "amount_residual_currency",
                        "reconciled",
                        "full_reconcile_id",
                        "matched_debit_ids",
                        "matched_credit_ids",
                        "matching_number",
                    }
                ),
                label="payment target journal item",
            )
        matched_amount = Decimal("0")
        cross_partial_ids: set[int] = set()
        company_currency_id = _record_id(company.currency_id)
        partials = [
            record
            for model_name, record in records
            if model_name == "account.partial.reconcile"
        ]
        actual_partial_ids = {partial.id for partial in partials}
        expected_partial_ids = {
            partial_id
            for line in bound_lines.values()
            for partial_id in (
                _ids(line.matched_debit_ids) + _ids(line.matched_credit_ids)
            )
        }
        if actual_partial_ids != expected_partial_ids:
            raise OdooWriteHandlerError(
                "payment partial reconcile record set differs"
            )
        for partial in partials:
            debit_id = _record_id(partial.debit_move_id)
            credit_id = _record_id(partial.credit_move_id)
            if (
                _record_id(partial.company_id) != company.id
                or debit_id not in bound_line_ids
                or credit_id not in bound_line_ids
                or _record_id(partial.debit_currency_id) != p["currency_id"]
                or _record_id(partial.credit_currency_id) != p["currency_id"]
                or _record_id(getattr(partial, "exchange_move_id", None))
                is not None
            ):
                raise OdooWriteHandlerError(
                    "payment partial reconcile graph differs"
                )
            target_is_debit = debit_id in target_line_ids and credit_id in payment_line_ids
            target_is_credit = credit_id in target_line_ids and debit_id in payment_line_ids
            if not target_is_debit and not target_is_credit:
                continue
            cross_partial_ids.add(partial.id)
            if p["currency_id"] == company_currency_id:
                matched_amount += abs(_decimal(partial.amount, "partial amount"))
            elif target_is_debit:
                matched_amount += abs(
                    _decimal(
                        partial.debit_amount_currency,
                        "partial debit amount currency",
                    )
                )
            else:
                matched_amount += abs(
                    _decimal(
                        partial.credit_amount_currency,
                        "partial credit amount currency",
                    )
                )
        if not cross_partial_ids:
            raise OdooWriteHandlerError("payment reconciliation graph is missing")
        self.assert_amount(
            matched_amount, p["amount"], currency, "partial reconcile amount"
        )
        expected_full_ids = {
            full_id
            for line in bound_lines.values()
            for full_id in [
                _record_id(getattr(line, "full_reconcile_id", None))
            ]
            if full_id is not None
        } | {
            full_id
            for partial in partials
            for full_id in [
                _record_id(getattr(partial, "full_reconcile_id", None))
            ]
            if full_id is not None
        }
        fulls = [
            record
            for model_name, record in records
            if model_name == "account.full.reconcile"
        ]
        if {full.id for full in fulls} != expected_full_ids:
            raise OdooWriteHandlerError(
                "payment full reconcile record set differs"
            )
        for full in fulls:
            if (
                set(_ids(full.partial_reconcile_ids))
                != {
                    partial.id
                    for partial in partials
                    if _record_id(partial.full_reconcile_id) == full.id
                }
                or set(_ids(full.reconciled_line_ids))
                != {
                    line_id
                    for line_id, line in bound_lines.items()
                    if _record_id(line.full_reconcile_id) == full.id
                }
            ):
                raise OdooWriteHandlerError(
                    "payment full reconcile graph differs"
                )
        expected_keys = {
            ("account.payment", payment.id),
            ("account.move", binding["payment_move_id"]),
            *(("account.move", move_id) for move_id in binding["target_move_ids"]),
            *(("account.move.line", line_id) for line_id in bound_line_ids),
            *(("account.partial.reconcile", partial_id) for partial_id in expected_partial_ids),
            *(("account.full.reconcile", full_id) for full_id in expected_full_ids),
        }
        if set(keyed) != expected_keys:
            raise OdooWriteHandlerError("payment affected record graph differs")
        self.assert_move_balanced(payment_move, company)
        return [
            "record_exists", "links_match", "direction_matches",
            "date_matches", "memo_matches", "method_matches",
            "amount_matches", "posted_state", "payment_move_posted",
            "payment_move_balanced", "target_links_match",
            "target_residual_reduction_matches",
            "trusted_target_before_graph_matches",
            "partial_reconcile_amount_matches", "payment_binding_matches",
            "full_reconcile_graph_exact", "record_graph_exact",
        ]

    def _payment_cancel_records(
        self,
        p: Mapping[str, Any],
        company: Any,
        *,
        write: bool,
    ) -> tuple[Any, Any, list[Any], list[tuple[str, Any]]]:
        if self.context.trusted_recovery_plan is not None:
            raise OdooWriteHandlerError(
                "trusted recovery plan must be null for payment cancellation"
            )
        payment = self.record(
            "account.payment", p["payment_id"], company, write=write
        )
        if _record_id(getattr(payment, "move_id", None)) != p["move_id"]:
            raise OdooWriteHandlerError(
                "payment accounting move differs from the approved move"
            )
        move = self.record("account.move", p["move_id"], company, write=write)
        line_ids = _ids(getattr(move, "line_ids", []))
        if (
            line_ids != sorted(p["expected_line_ids"])
            or len(line_ids) != 2
        ):
            raise OdooWriteHandlerError(
                "payment journal-item graph differs from the approved IDs"
            )
        lines = [
            self.record("account.move.line", line_id, company, write=write)
            for line_id in line_ids
        ]
        records = [
            ("account.payment", payment),
            ("account.move", move),
            *(("account.move.line", line) for line in lines),
        ]
        return payment, move, lines, records

    def _assert_unreconciled_payment_cancel_source(
        self,
        p: Mapping[str, Any],
        company: Any,
        payment: Any,
        move: Any,
        lines: list[Any],
    ) -> list[tuple[str, Any]]:
        if (
            str(getattr(payment, "state", "")) != p["expected_payment_state"]
            or p["expected_payment_state"] != "in_process"
            or str(getattr(move, "state", "")) != p["expected_move_state"]
            or p["expected_move_state"] != "posted"
            or str(getattr(move, "move_type", "")) != "entry"
            or getattr(payment, "is_sent", None) is not p["expected_is_sent"]
            or p["expected_is_sent"] is not True
        ):
            raise OdooWriteHandlerError(
                "payment is not an approved sent in-process posted payment"
            )
        if (
            _record_id(getattr(payment, "company_id", None)) != company.id
            or _record_id(getattr(move, "company_id", None)) != company.id
            or _record_id(getattr(payment, "partner_id", None))
            != p["expected_partner_id"]
            or _record_id(getattr(move, "partner_id", None))
            != p["expected_partner_id"]
            or str(getattr(payment, "partner_type", ""))
            != p["expected_partner_type"]
            or str(getattr(payment, "payment_type", ""))
            != p["expected_direction"]
            or str(getattr(payment, "date", ""))
            != p["expected_payment_date"]
            or str(getattr(move, "date", ""))
            != p["expected_payment_date"]
            or _record_id(getattr(payment, "journal_id", None))
            != p["expected_journal_id"]
            or _record_id(getattr(move, "journal_id", None))
            != p["expected_journal_id"]
            or _record_id(getattr(payment, "currency_id", None))
            != p["expected_currency_id"]
            or _record_id(getattr(move, "currency_id", None))
            != p["expected_currency_id"]
            or _record_id(getattr(payment, "payment_method_line_id", None))
            != p["expected_payment_method_line_id"]
        ):
            raise OdooWriteHandlerError(
                "payment business identity differs from the approved input"
            )
        journal = self.record(
            "account.journal", p["expected_journal_id"], company
        )
        if (
            str(getattr(journal, "type", "")) not in {"bank", "cash", "credit"}
            or getattr(journal, "active", True) is False
        ):
            raise OdooWriteHandlerError(
                "payment journal is not an active payment journal"
            )
        company_currency_id = _record_id(getattr(company, "currency_id", None))
        if (
            company_currency_id != p["expected_currency_id"]
            or _record_id(getattr(journal, "currency_id", None))
            not in {None, company_currency_id}
        ):
            raise OdooWriteHandlerError(
                "payment cancellation v1 requires company currency"
            )
        currency = self.assert_currency(
            p["expected_currency_id"], company, journal
        )
        self.assert_amount(
            getattr(payment, "amount", None),
            p["expected_amount"],
            currency,
            "payment amount",
        )
        partner = self.check_partner(p["expected_partner_id"], company)
        method_line = self.record(
            "account.payment.method.line",
            p["expected_payment_method_line_id"],
            company,
        )
        method_id = _record_id(
            getattr(method_line, "payment_method_id", None)
        )
        if method_id is None:
            raise OdooWriteHandlerError(
                "payment method line has no auditable method"
            )
        method = self.record(
            "account.payment.method",
            method_id,
            company,
            shared=True,
        )
        if (
            _record_id(getattr(method_line, "company_id", None)) != company.id
            or _record_id(getattr(method_line, "journal_id", None))
            != journal.id
            or str(getattr(method_line, "payment_type", ""))
            != p["expected_direction"]
            or str(getattr(method, "code", "")) != "manual"
            or str(getattr(method, "payment_type", ""))
            != p["expected_direction"]
        ):
            raise OdooWriteHandlerError(
                "payment cancellation v1 requires the approved manual method"
            )
        destination_account_id = _record_id(
            getattr(payment, "destination_account_id", None)
        )
        outstanding_account_id = _record_id(
            getattr(payment, "outstanding_account_id", None)
        )
        if (
            destination_account_id is None
            or outstanding_account_id is None
            or destination_account_id == outstanding_account_id
        ):
            raise OdooWriteHandlerError(
                "payment destination or outstanding account is ambiguous"
            )
        if (
            _record_id(getattr(method_line, "payment_account_id", None))
            != outstanding_account_id
        ):
            raise OdooWriteHandlerError(
                "payment method outstanding account differs from the payment"
            )
        destination_account = self.check_account(
            destination_account_id, company
        )
        outstanding_account = self.check_account(
            outstanding_account_id, company
        )
        expected_destination_type = (
            "asset_receivable"
            if p["expected_partner_type"] == "customer"
            else "liability_payable"
        )
        if (
            str(getattr(destination_account, "account_type", ""))
            != expected_destination_type
            or str(getattr(outstanding_account, "account_type", ""))
            not in {"asset_cash", "asset_current", "liability_current"}
            or getattr(destination_account, "reconcile", None) is not True
            or getattr(outstanding_account, "reconcile", None) is not True
        ):
            raise OdooWriteHandlerError(
                "payment accounts are outside the standard cancellation slice"
            )
        if (
            _record_id(getattr(move, "origin_payment_id", None)) != payment.id
            or _ids(getattr(move, "payment_ids", [])) != [payment.id]
            or getattr(move, "posted_before", None) is not True
            or str(getattr(move, "auto_post", "")) != "no"
            or bool(getattr(move, "sending_data", False))
            or bool(getattr(move, "inalterable_hash", False))
            or bool(getattr(move, "need_cancel_request", False))
        ):
            raise OdooWriteHandlerError(
                "payment move has unsupported origin, posting, or lock evidence"
            )
        payment_external_plural = (
            "invoice_ids",
            "reconciled_invoice_ids",
            "reconciled_bill_ids",
            "reconciled_statement_line_ids",
        )
        payment_external_singular = (
            "paired_internal_transfer_payment_id",
            "destination_journal_id",
            "payment_transaction_id",
            "payment_token_id",
            "batch_payment_id",
        )
        if (
            bool(getattr(payment, "is_reconciled", False))
            or bool(getattr(payment, "is_matched", False))
            or bool(getattr(payment, "is_internal_transfer", False))
            or any(
                _ids(getattr(payment, field, []))
                for field in payment_external_plural
            )
            or any(
                _record_id(getattr(payment, field, None)) is not None
                for field in payment_external_singular
            )
            or _is_present(getattr(payment, "check_number", False))
            or _is_present(
                getattr(payment, "odoo_cli_v3_payment_binding", False)
            )
        ):
            raise OdooWriteHandlerError(
                "payment has target, bank, transfer, provider, batch, check, or V3 allocation effects"
            )
        move_external_singular = (
            "statement_line_id",
            "statement_id",
            "tax_cash_basis_rec_id",
            "tax_cash_basis_origin_move_id",
            "reversed_entry_id",
            "asset_id",
            "closing_return_id",
            "transfer_model_id",
            "purchase_id",
            "debit_origin_id",
            "invoice_pdf_report_id",
            "invoice_vendor_bill_id",
            "purchase_vendor_bill_id",
            "ubl_cii_xml_id",
            "l10n_es_edi_facturae_xml_id",
            "message_main_attachment_id",
        )
        move_external_plural = (
            "statement_line_ids",
            "tax_cash_basis_created_move_ids",
            "reversal_move_ids",
            "adjusting_entry_origin_move_ids",
            "adjusting_entries_move_ids",
            "exchange_diff_partial_ids",
            "transaction_ids",
            "authorized_transaction_ids",
            "asset_ids",
            "deferred_move_ids",
            "deferred_original_move_ids",
            "edi_document_ids",
            "expense_ids",
            "pos_order_ids",
            "stock_move_ids",
            "landed_costs_ids",
            "attachment_ids",
        )
        if (
            any(
                _record_id(getattr(move, field, None)) is not None
                for field in move_external_singular
            )
            or any(
                _ids(getattr(move, field, []))
                for field in move_external_plural
            )
            or any(
            _is_present(getattr(move, field, False))
            for field in (
                "invoice_pdf_report_file",
                "ubl_cii_xml_file",
                "l10n_es_edi_facturae_xml_file",
                "signature",
            )
            )
        ):
            raise OdooWriteHandlerError(
                "payment move has tax, FX, statement, reversal, asset, EDI, attachment, or external effects"
            )
        account_ids = {_record_id(getattr(line, "account_id", None)) for line in lines}
        if account_ids != {destination_account_id, outstanding_account_id}:
            raise OdooWriteHandlerError(
                "payment journal items do not use the exact approved account pair"
            )
        debit = Decimal("0")
        credit = Decimal("0")
        balances_by_account = {
            destination_account_id: Decimal("0"),
            outstanding_account_id: Decimal("0"),
        }
        for line in lines:
            line_debit = _decimal(getattr(line, "debit", None), "payment line debit")
            line_credit = _decimal(
                getattr(line, "credit", None), "payment line credit"
            )
            line_balance = _decimal(
                getattr(line, "balance", None), "payment line balance"
            )
            line_amount_currency = _decimal(
                getattr(line, "amount_currency", None),
                "payment line amount_currency",
            )
            if (
                _record_id(getattr(line, "move_id", None)) != move.id
                or _record_id(getattr(line, "company_id", None)) != company.id
                or _record_id(getattr(line, "partner_id", None))
                not in {None, p["expected_partner_id"]}
                or _record_id(getattr(line, "currency_id", None))
                != p["expected_currency_id"]
                or str(getattr(line, "parent_state", "")) != "posted"
                or bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None))
                is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
                or bool(getattr(line, "matching_number", False))
                or _record_id(getattr(line, "statement_line_id", None))
                is not None
                or _record_id(getattr(line, "statement_id", None))
                is not None
                or _record_id(getattr(line, "payment_id", None))
                not in {None, payment.id}
                or _ids(getattr(line, "tax_ids", []))
                or _record_id(getattr(line, "tax_line_id", None)) is not None
                or _ids(getattr(line, "tax_tag_ids", []))
                or _record_id(
                    getattr(line, "tax_repartition_line_id", None)
                )
                is not None
                or getattr(line, "analytic_distribution", False)
                not in (False, None, {})
                or _ids(getattr(line, "analytic_line_ids", []))
                or _ids(getattr(line, "asset_ids", []))
                or getattr(line, "deferred_start_date", None)
                not in {False, None}
                or getattr(line, "deferred_end_date", None)
                not in {False, None}
                or _ids(getattr(line, "reconciled_lines_ids", []))
                or _ids(
                    getattr(
                        line,
                        "reconciled_lines_excluding_exchange_diff_ids",
                        [],
                    )
                )
                or (line_debit > 0) == (line_credit > 0)
            ):
                raise OdooWriteHandlerError(
                    "payment journal item has reconciliation, tax, analytic, asset, deferred, statement, or malformed amount effects"
                )
            self.assert_amount(
                line_balance,
                line_debit - line_credit,
                currency,
                "payment line balance",
            )
            self.assert_amount(
                line_amount_currency,
                line_balance,
                currency,
                "payment line amount_currency",
            )
            debit += line_debit
            credit += line_credit
            balances_by_account[
                _record_id(getattr(line, "account_id", None))
            ] += line_balance
        self.assert_amount(debit, credit, currency, "payment move balance")
        self.assert_amount(
            debit, p["expected_amount"], currency, "payment move debit"
        )
        self.assert_amount(
            credit, p["expected_amount"], currency, "payment move credit"
        )
        direction_sign = (
            Decimal("1")
            if p["expected_direction"] == "inbound"
            else Decimal("-1")
        )
        self.assert_amount(
            balances_by_account[outstanding_account_id],
            direction_sign * _decimal(
                p["expected_amount"], "expected payment amount"
            ),
            currency,
            "payment outstanding-account balance",
        )
        self.assert_amount(
            balances_by_account[destination_account_id],
            -direction_sign * _decimal(
                p["expected_amount"], "expected payment amount"
            ),
            currency,
            "payment destination-account balance",
        )
        line_ids = [line.id for line in lines]
        if self.search_records(
            "account.partial.reconcile",
            [("debit_move_id", "in", line_ids)],
            company,
            limit=1,
        ) or self.search_records(
            "account.partial.reconcile",
            [("credit_move_id", "in", line_ids)],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "payment has a hidden partial reconciliation"
            )
        self.assert_effective_open_date(
            company,
            p["expected_payment_date"],
            "expected_payment_date",
            journal=journal,
            taxes=False,
            move=move,
        )
        return [
            ("res.company", company),
            ("res.currency", currency),
            ("res.partner", partner),
            ("account.journal", journal),
            ("account.payment.method.line", method_line),
            ("account.payment.method", method),
            ("account.account", destination_account),
            ("account.account", outstanding_account),
        ]

    def precheck_payment_cancel(
        self, p: dict[str, Any], company: Any
    ) -> dict[str, Any]:
        payment, move, lines, records = self._payment_cancel_records(
            p, company, write=True
        )
        dependencies = self._assert_unreconciled_payment_cancel_source(
            p, company, payment, move, lines
        )
        return {
            "checks": [
                "single_sent_in_process_payment",
                "posted_standard_two_line_payment_move",
                "company_currency_manual_payment_method",
                "approved_payment_business_identity_matches",
                "partial_and_full_reconcile_graph_empty",
                "target_bank_transfer_provider_batch_and_check_graph_empty",
                "tax_fx_analytic_asset_deferred_edi_and_attachment_graph_empty",
                "effective_odoo_lock_dates_open",
                "write_acl",
            ],
            "before": self.snapshots(
                records,
                company,
                required_fields_by_model={
                    "account.payment": {
                        "state",
                        "write_uid",
                        "write_date",
                    },
                    "account.move": {
                        "state",
                        "auto_post",
                        "sending_data",
                        "payment_state",
                        "write_uid",
                        "write_date",
                    },
                    "account.move.line": {
                        "parent_state",
                        "write_uid",
                        "write_date",
                    },
                },
            ),
            "dependencies": self.snapshots(dependencies, company),
        }

    @staticmethod
    def _assert_unchanged_or_controlled_log_delta(
        current: Mapping[str, Any],
        approved: Mapping[str, Any],
        *,
        user_id: int,
        label: str,
    ) -> None:
        log_fields = {"write_uid", "write_date"}
        if not log_fields.issubset(current) or not log_fields.issubset(approved):
            raise OdooWriteHandlerError(
                f"{label} log-access audit fields are incomplete"
            )
        if all(current[field] == approved[field] for field in log_fields):
            return
        if classic_read_many2one_id(current["write_uid"]) != user_id:
            raise OdooWriteHandlerError(
                f"{label} was not written by the bound execution user"
            )
        try:
            before = datetime.fromisoformat(str(approved["write_date"]))
            after = datetime.fromisoformat(str(current["write_date"]))
        except (TypeError, ValueError) as exc:
            raise OdooWriteHandlerError(
                f"{label} write_date is not an auditable Odoo datetime"
            ) from exc
        if (
            before.tzinfo is not None
            or after.tzinfo is not None
            or after < before
        ):
            raise OdooWriteHandlerError(
                f"{label} write_date is outside the approved monotonic delta"
            )

    def _assert_payment_cancel_exact_delta(
        self,
        p: Mapping[str, Any],
        company: Any,
        payment: Any,
        move: Any,
        lines: list[Any],
        before: Mapping[tuple[str, int], dict[str, Any]],
    ) -> None:
        expected_keys = {
            ("account.payment", payment.id),
            ("account.move", move.id),
            *(("account.move.line", line.id) for line in lines),
        }
        if set(before) != expected_keys:
            raise OdooWriteHandlerError(
                "payment cancellation approval graph differs"
            )
        if (
            str(getattr(payment, "state", "")) != "canceled"
            or str(getattr(move, "state", "")) != "cancel"
            or _record_id(getattr(payment, "move_id", None)) != move.id
            or _ids(getattr(move, "line_ids", []))
            != sorted(p["expected_line_ids"])
        ):
            raise OdooWriteHandlerError(
                "payment cancellation terminal state or graph differs"
            )
        approved_move = before[("account.move", move.id)]
        if (
            str(getattr(move, "auto_post", "")) != "no"
            or bool(getattr(move, "sending_data", False))
            or _snapshot_primitive(
                "payment_state", getattr(move, "payment_state", False)
            )
            != approved_move.get("payment_state")
        ):
            raise OdooWriteHandlerError(
                "payment move cancellation control fields differ"
            )
        allowed_by_model = {
            "account.payment": frozenset(
                {"state", "write_uid", "write_date"}
            ),
            "account.move": frozenset(
                {
                    "state",
                    "write_uid",
                    "write_date",
                }
            ),
            "account.move.line": frozenset(
                {"parent_state", "write_uid", "write_date"}
            ),
        }
        for model_name, record in [
            ("account.payment", payment),
            ("account.move", move),
            *(("account.move.line", line) for line in lines),
        ]:
            approved = before[(model_name, record.id)]
            current = self.snapshot(model_name, record, company)["values"]
            allowed = allowed_by_model[model_name]
            if set(current) != set(approved) or any(
                current[field] != approved[field]
                for field in set(current) - allowed
            ):
                raise OdooWriteHandlerError(
                    f"{model_name} changed outside the approved payment cancellation allowlist"
                )
            self._assert_unchanged_or_controlled_log_delta(
                current,
                approved,
                user_id=self.context.user_id,
                label=model_name,
            )
        for line in lines:
            if (
                str(getattr(line, "parent_state", "")) != "cancel"
                or bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None))
                is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
            ):
                raise OdooWriteHandlerError(
                    "cancelled payment journal item graph differs"
                )
        line_ids = [line.id for line in lines]
        if self.search_records(
            "account.partial.reconcile",
            [("debit_move_id", "in", line_ids)],
            company,
            limit=1,
        ) or self.search_records(
            "account.partial.reconcile",
            [("credit_move_id", "in", line_ids)],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "payment cancellation unexpectedly changed a reconciliation graph"
            )
        self.assert_move_balanced(move, company)

    def execute_payment_cancel(self, p, company, checked):
        payment, move, lines, records = self._payment_cancel_records(
            p, company, write=True
        )
        self._assert_unreconciled_payment_cancel_source(
            p, company, payment, move, lines
        )
        approved = self.trusted_before_values(
            {"before": checked.get("before")}, company
        )
        for model_name, record in records:
            if (
                self.snapshot(model_name, record, company)["values"]
                != approved.get((model_name, record.id))
            ):
                raise OdooWriteHandlerError(
                    "payment cancellation graph changed after approval"
                )
        action = getattr(
            payment.with_context(
                tracking_disable=True,
                mail_notrack=True,
            ),
            "action_cancel",
            None,
        )
        if not callable(action):
            raise OdooWriteHandlerError(
                "Odoo public payment cancellation API is unavailable"
            )
        action()
        self._assert_payment_cancel_exact_delta(
            p, company, payment, move, lines, approved
        )
        return records, _recovery(
            "manual_escalation",
            "manual_review_terminal_payment_cancel",
            [
                {"model": "account.payment", "record_id": payment.id},
                {"model": "account.move", "record_id": move.id},
            ],
        )

    def verify_payment_cancel(self, p, company, records, before):
        keyed = {
            (model_name, record.id): record
            for model_name, record in records
        }
        if len(keyed) != len(records):
            raise OdooWriteHandlerError(
                "payment cancellation result graph contains a duplicate"
            )
        expected_keys = {
            ("account.payment", p["payment_id"]),
            ("account.move", p["move_id"]),
            *(("account.move.line", line_id) for line_id in p["expected_line_ids"]),
        }
        if set(keyed) != expected_keys:
            raise OdooWriteHandlerError(
                "payment cancellation result graph differs"
            )
        payment = keyed[("account.payment", p["payment_id"])]
        move = keyed[("account.move", p["move_id"])]
        lines = [
            keyed[("account.move.line", line_id)]
            for line_id in sorted(p["expected_line_ids"])
        ]
        self._assert_payment_cancel_exact_delta(
            p, company, payment, move, lines, before
        )
        return [
            "payment_cancelled_fresh",
            "payment_move_cancelled_fresh",
            "approved_payment_and_two_line_graph_preserved",
            "payment_reconciliation_graph_remained_empty",
            "tax_fx_analytic_asset_deferred_and_external_graph_remained_empty",
            "move_name_sequence_and_posting_history_preserved",
            "payment_move_balanced",
            "record_graph_exact",
        ]

    def precheck_bank(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        journal = self.check_journal(p, company, {"bank"})
        statement_currency = self.assert_currency(p["currency_id"], company, journal)
        effective_currency_id = _record_id(journal.currency_id) or _record_id(
            company.currency_id
        )
        if effective_currency_id != p["currency_id"]:
            raise OdooWriteHandlerError(
                "bank statement currency differs from the journal currency"
            )
        if p["currency_id"] != _record_id(company.currency_id):
            raise OdooWriteHandlerError(
                "foreign-currency bank journals are disabled until an exact rate preview is approved"
            )
        liquidity_account_id = _record_id(
            getattr(journal, "default_account_id", None)
        )
        suspense_account_id = _record_id(
            getattr(journal, "suspense_account_id", None)
        )
        if liquidity_account_id is None or suspense_account_id is None:
            raise OdooWriteHandlerError(
                "bank journal liquidity or suspense account is not configured"
            )
        liquidity_account = self.check_account(liquidity_account_id, company)
        suspense_account = self.check_account(suspense_account_id, company)
        self.assert_open_date(company, p["statement_date"], "statement_date", journal=journal)
        partners: dict[int, Any] = {}
        foreign_currencies: dict[int, Any] = {}
        for line in p["lines"]:
            self.assert_open_date(
                company,
                line["transaction_date"],
                "transaction_date",
                journal=journal,
            )
            if line["partner_id"] is not None:
                if line["partner_id"] not in partners:
                    partners[line["partner_id"]] = self.check_partner(
                        line["partner_id"], company
                    )
            if line["foreign_currency_id"] is not None:
                foreign_amount = _decimal(
                    line["foreign_amount"], "foreign_amount"
                )
                if (
                    (line["direction"] == "credit" and foreign_amount <= 0)
                    or (line["direction"] == "debit" and foreign_amount >= 0)
                ):
                    raise OdooWriteHandlerError(
                        "bank foreign amount sign differs from its direction"
                    )
                if line["foreign_currency_id"] not in foreign_currencies:
                    foreign_currencies[line["foreign_currency_id"]] = (
                        self.assert_currency(line["foreign_currency_id"], company)
                    )
        duplicate_checks = [
            (
                "account.bank.statement",
                [
                    ("journal_id", "=", p["journal_id"]),
                    ("reference", "=", p["external_reference"]),
                ],
            ),
            (
                "account.bank.statement",
                [
                    ("journal_id", "=", p["journal_id"]),
                    (
                        "odoo_cli_v3_external_reference",
                        "=",
                        p["external_reference"],
                    ),
                ],
            ),
            (
                "account.bank.statement",
                [
                    ("journal_id", "=", p["journal_id"]),
                    ("odoo_cli_v3_source_digest", "=", p["source_digest"]),
                ],
            ),
            (
                "account.bank.statement.line",
                [
                    ("journal_id", "=", p["journal_id"]),
                    (
                        "ref",
                        "in",
                        [line["external_transaction_id"] for line in p["lines"]],
                    ),
                ],
            ),
            (
                "account.bank.statement.line",
                [
                    ("journal_id", "=", p["journal_id"]),
                    (
                        "odoo_cli_v3_external_transaction_id",
                        "in",
                        [line["external_transaction_id"] for line in p["lines"]],
                    ),
                ],
            ),
            (
                "account.bank.statement.line",
                [
                    ("journal_id", "=", p["journal_id"]),
                    (
                        "odoo_cli_v3_source_line_digest",
                        "in",
                        [line["source_line_digest"] for line in p["lines"]],
                    ),
                ],
            ),
        ]
        for model_name, domain in duplicate_checks:
            if self.search_records(model_name, domain, company, limit=1):
                raise OdooWriteHandlerError(
                    "bank source identity already exists in the journal"
                )
        self.create_model("account.bank.statement", company)
        self.create_model("account.bank.statement.line", company)
        dependencies = self.unique_records(
            [
                ("res.company", company),
                ("account.journal", journal),
                ("res.currency", statement_currency),
                ("account.account", liquidity_account),
                ("account.account", suspense_account),
                *(("res.partner", partner) for partner in partners.values()),
                *(
                    ("res.currency", currency)
                    for currency in foreign_currencies.values()
                ),
            ]
        )
        return {
            "checks": [
                "source_identity_unique", "source_digest", "balances",
                "journal", "journal_accounts", "currency", "partners",
                "transaction_dates",
            ],
            "before": [],
            "dependencies": self.snapshots(dependencies, company),
        }

    def execute_bank(self, p, company, checked):
        bank_lines = []
        model = self.create_model("account.bank.statement.line", company)
        for line in p["lines"]:
            sign = Decimal("1") if line["direction"] == "credit" else Decimal("-1")
            values = {
                "company_id": p["company_id"],
                "journal_id": p["journal_id"],
                "date": line["transaction_date"],
                "amount": float(sign * _decimal(line["amount"], "amount")),
                "payment_ref": line["summary"],
                "ref": line["external_transaction_id"],
                "odoo_cli_v3_external_transaction_id": line[
                    "external_transaction_id"
                ],
                "odoo_cli_v3_source_line_digest": line["source_line_digest"],
                "odoo_cli_v3_value_date": line["value_date"],
                "transaction_details": {
                    "version": 1,
                    "external_reference": p["external_reference"],
                    "statement_date": p["statement_date"],
                    "statement_currency_id": p["currency_id"],
                    "opening_balance": p["opening_balance"],
                    "closing_balance": p["closing_balance"],
                    "source_digest": p["source_digest"],
                    "source_filename": p["source_filename"],
                    "source_line_digest": line["source_line_digest"],
                    "value_date": line["value_date"],
                },
            }
            if line["partner_id"] is not None:
                values["partner_id"] = line["partner_id"]
            if line["foreign_currency_id"] is not None:
                values["foreign_currency_id"] = line["foreign_currency_id"]
                values["amount_currency"] = float(_decimal(line["foreign_amount"], "foreign_amount"))
            record = model.create(values)
            self.require_created(record, "account.bank.statement.line", company)
            bank_lines.append(record)
        statement = self.create_model("account.bank.statement", company).create(
            {
                "reference": p["external_reference"],
                "date": p["statement_date"],
                "balance_start": float(
                    _decimal(p["opening_balance"], "opening_balance")
                ),
                "balance_end_real": float(
                    _decimal(p["closing_balance"], "closing_balance")
                ),
                "line_ids": [(6, 0, [line.id for line in bank_lines])],
                "odoo_cli_v3_external_reference": p["external_reference"],
                "odoo_cli_v3_source_digest": p["source_digest"],
                "odoo_cli_v3_source_filename": p["source_filename"],
            }
        )
        self.require_created(statement, "account.bank.statement", company)
        if not statement.is_complete or not statement.is_valid:
            raise OdooWriteHandlerError(
                "bank statement checkpoint is incomplete or invalid"
            )
        records: list[tuple[str, Any]] = [("account.bank.statement", statement)]
        for bank_line in bank_lines:
            records.append(("account.bank.statement.line", bank_line))
            move_id = _record_id(bank_line.move_id)
            if move_id is None:
                raise OdooWriteHandlerError(
                    "bank statement line has no accounting move"
                )
            move = self.record("account.move", move_id, company)
            records.extend(self.move_records(move, company))
        records = self.unique_records(records)
        return records, self.available_recovery(
            "acct.bank.statement_import.v1",
            "post_compensating_bank_statement_v1",
            records,
            action_keys={("account.bank.statement", statement.id)},
        )

    def verify_bank(self, p, company, records):
        statements = [
            record
            for model_name, record in records
            if model_name == "account.bank.statement"
        ]
        bank_lines = [
            record
            for model_name, record in records
            if model_name == "account.bank.statement.line"
        ]
        if len(statements) != 1 or len(bank_lines) != len(p["lines"]):
            raise OdooWriteHandlerError("bank statement or line count differs")
        statement = statements[0]
        expected_odoo_date = max(
            line["transaction_date"] for line in p["lines"]
        )
        if (
            _record_id(statement.company_id) != company.id
            or _record_id(statement.journal_id) != p["journal_id"]
            or _record_id(statement.currency_id) != p["currency_id"]
            or str(statement.date) != expected_odoo_date
            or str(statement.reference or "") != p["external_reference"]
            or str(statement.odoo_cli_v3_external_reference or "")
            != p["external_reference"]
            or str(statement.odoo_cli_v3_source_digest or "")
            != p["source_digest"]
            or str(statement.odoo_cli_v3_source_filename or "")
            != p["source_filename"]
        ):
            raise OdooWriteHandlerError(
                "bank statement identity or links differ"
            )
        currency = self.assert_currency(p["currency_id"], company)
        self.assert_amount(
            statement.balance_start,
            p["opening_balance"],
            currency,
            "bank statement balances",
        )
        self.assert_amount(
            statement.balance_end,
            p["closing_balance"],
            currency,
            "bank statement balances",
        )
        self.assert_amount(
            statement.balance_end_real,
            p["closing_balance"],
            currency,
            "bank statement balances",
        )
        if statement.is_complete is not True or statement.is_valid is not True:
            raise OdooWriteHandlerError(
                "bank statement checkpoint is incomplete or invalid"
            )
        if _ids(statement.line_ids) != sorted(line.id for line in bank_lines):
            raise OdooWriteHandlerError("bank statement line links differ")

        keyed: dict[tuple[str, int], Any] = {}
        for model_name, record in records:
            key = (model_name, record.id)
            if key in keyed:
                raise OdooWriteHandlerError("bank read-back record is duplicated")
            keyed[key] = record
        actual_by_ref = {
            str(line.odoo_cli_v3_external_transaction_id): line
            for line in bank_lines
        }
        if set(actual_by_ref) != {
            line["external_transaction_id"] for line in p["lines"]
        }:
            raise OdooWriteHandlerError("bank external transaction IDs differ")
        expected_move_ids: set[int] = set()
        expected_move_line_ids: set[int] = set()
        journal = statement.journal_id
        liquidity_account_id = _record_id(journal.default_account_id)
        suspense_account_id = _record_id(journal.suspense_account_id)
        for approved in p["lines"]:
            record = actual_by_ref.get(approved["external_transaction_id"])
            if record is None:
                raise OdooWriteHandlerError("bank external transaction ID is missing")
            sign = Decimal("1") if approved["direction"] == "credit" else Decimal("-1")
            self.assert_amount(record.amount, sign * _decimal(approved["amount"], "amount"), currency, "bank amount")
            details = record.transaction_details
            expected_details = {
                "version": 1,
                "external_reference": p["external_reference"],
                "statement_date": p["statement_date"],
                "statement_currency_id": p["currency_id"],
                "opening_balance": p["opening_balance"],
                "closing_balance": p["closing_balance"],
                "source_digest": p["source_digest"],
                "source_filename": p["source_filename"],
                "source_line_digest": approved["source_line_digest"],
                "value_date": approved["value_date"],
            }
            if not isinstance(details, Mapping) or dict(details) != expected_details:
                raise OdooWriteHandlerError("bank source provenance differs")
            if (
                _record_id(record.statement_id) != statement.id
                or _record_id(record.company_id) != company.id
                or _record_id(record.journal_id) != p["journal_id"]
                or _record_id(record.currency_id) != p["currency_id"]
                or str(record.date) != approved["transaction_date"]
                or str(record.odoo_cli_v3_value_date)
                != approved["value_date"]
                or str(record.payment_ref or "") != approved["summary"]
                or str(record.ref or "") != approved["external_transaction_id"]
                or str(record.odoo_cli_v3_source_line_digest or "")
                != approved["source_line_digest"]
                or _record_id(record.partner_id) != approved["partner_id"]
            ):
                raise OdooWriteHandlerError(
                    "bank line date, value date, partner, summary, or links differ"
                )
            move_id = _record_id(record.move_id)
            move = keyed.get(("account.move", move_id))
            if move is None or move.state != "posted":
                raise OdooWriteHandlerError("bank statement line has no posted Odoo move receipt")
            if (
                _record_id(move.statement_line_id) != record.id
                or _record_id(move.company_id) != company.id
                or _record_id(move.journal_id) != p["journal_id"]
                or _record_id(move.currency_id)
                != (approved["foreign_currency_id"] or p["currency_id"])
                or str(move.date) != approved["transaction_date"]
                or _record_id(move.partner_id) != approved["partner_id"]
            ):
                raise OdooWriteHandlerError("bank accounting move links differ")
            move_lines = self.checked_move_lines(move, company)
            if len(move_lines) != 2:
                raise OdooWriteHandlerError(
                    "bank accounting move does not have the exact default lines"
                )
            by_account = {
                _record_id(line.account_id): line for line in move_lines
            }
            if set(by_account) != {liquidity_account_id, suspense_account_id}:
                raise OdooWriteHandlerError(
                    "bank accounting move uses unexpected accounts"
                )
            self.assert_amount(
                by_account[liquidity_account_id].amount_currency,
                sign * _decimal(approved["amount"], "amount"),
                currency,
                "bank liquidity amount",
            )
            if (
                _record_id(by_account[liquidity_account_id].currency_id)
                != p["currency_id"]
            ):
                raise OdooWriteHandlerError(
                    "bank liquidity line currency differs"
                )
            signed_amount = sign * _decimal(approved["amount"], "amount")
            liquidity_line = by_account[liquidity_account_id]
            suspense_line = by_account[suspense_account_id]
            for actual, expected, label in (
                (liquidity_line.balance, signed_amount, "bank liquidity balance"),
                (liquidity_line.debit, max(signed_amount, Decimal("0")), "bank liquidity debit"),
                (liquidity_line.credit, max(-signed_amount, Decimal("0")), "bank liquidity credit"),
                (suspense_line.balance, -signed_amount, "bank suspense balance"),
                (suspense_line.debit, max(-signed_amount, Decimal("0")), "bank suspense debit"),
                (suspense_line.credit, max(signed_amount, Decimal("0")), "bank suspense credit"),
            ):
                self.assert_amount(actual, expected, currency, label)
            self.assert_move_balanced(move, company)
            expected_move_ids.add(move.id)
            expected_move_line_ids.update(line.id for line in move_lines)
            if approved["foreign_currency_id"] is not None:
                if _record_id(record.foreign_currency_id) != approved["foreign_currency_id"]:
                    raise OdooWriteHandlerError("bank foreign currency differs")
                foreign_currency = self.assert_currency(approved["foreign_currency_id"], company)
                self.assert_amount(
                    record.amount_currency, approved["foreign_amount"],
                    foreign_currency, "bank foreign amount",
                )
                if (
                    _record_id(by_account[suspense_account_id].currency_id)
                    != approved["foreign_currency_id"]
                ):
                    raise OdooWriteHandlerError(
                        "bank suspense line foreign currency differs"
                    )
                self.assert_amount(
                    by_account[suspense_account_id].amount_currency,
                    -_decimal(approved["foreign_amount"], "foreign_amount"),
                    foreign_currency,
                    "bank suspense foreign amount",
                )
            elif (
                _record_id(record.foreign_currency_id) is not None
                or _decimal(record.amount_currency or 0, "foreign amount") != 0
            ):
                raise OdooWriteHandlerError(
                    "bank line has an unapproved foreign currency amount"
                )
            else:
                if (
                    _record_id(by_account[suspense_account_id].currency_id)
                    != p["currency_id"]
                ):
                    raise OdooWriteHandlerError(
                        "bank suspense line currency differs"
                    )
                self.assert_amount(
                    by_account[suspense_account_id].amount_currency,
                    -sign * _decimal(approved["amount"], "amount"),
                    currency,
                    "bank suspense amount",
                )
        actual_move_ids = {
            record.id for model_name, record in records if model_name == "account.move"
        }
        actual_move_line_ids = {
            record.id
            for model_name, record in records
            if model_name == "account.move.line"
        }
        allowed_models = {
            "account.bank.statement", "account.bank.statement.line",
            "account.move", "account.move.line",
        }
        if (
            any(model_name not in allowed_models for model_name, _record in records)
            or actual_move_ids != expected_move_ids
            or actual_move_line_ids != expected_move_line_ids
        ):
            raise OdooWriteHandlerError("bank accounting read-back graph differs")
        return [
            "statement_identity_matches", "statement_balances_match",
            "odoo_computed_statement_date_matches",
            "source_statement_date_matches",
            "statement_complete_and_valid", "line_count_matches",
            "external_ids_match", "dates_and_value_dates_match",
            "partners_and_summaries_match", "amounts_match",
            "foreign_amounts_match", "move_receipts_exist",
            "move_accounts_match", "moves_balanced", "record_graph_exact",
        ]

    def precheck_reconciliation(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        account = self.check_account(p["account_id"], company)
        if not getattr(account, "reconcile", False):
            raise OdooWriteHandlerError("account is not configured for reconciliation")
        partner = None
        if p["partner_id"] is not None:
            partner = self.check_partner(p["partner_id"], company)
        currency = self.assert_currency(p["currency_id"], company)
        company_currency_id = _record_id(company.currency_id)
        if p["currency_id"] != company_currency_id:
            raise OdooWriteHandlerError(
                "foreign-currency reconciliation is disabled until its exchange graph is approved exactly"
            )
        if bool(getattr(company, "tax_exigibility", False)):
            raise OdooWriteHandlerError(
                "cash-basis reconciliation is disabled until its tax graph is approved exactly"
            )
        lines = []
        source_moves: dict[int, Any] = {}
        source_move_lines: dict[int, list[Any]] = {}
        debit = Decimal("0")
        credit = Decimal("0")
        for line_id in p["line_ids"]:
            line = self.record("account.move.line", line_id, company, write=True)
            if (
                line.reconciled
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
                or _record_id(getattr(line, "full_reconcile_id", None)) is not None
                or getattr(line, "matching_number", None)
                or getattr(line.move_id, "state", None) != "posted"
            ):
                raise OdooWriteHandlerError("reconciliation line is not an open posted line")
            if (
                _record_id(line.account_id) != _record_id(account)
                or _record_id(line.partner_id) != p["partner_id"]
            ):
                raise OdooWriteHandlerError("reconciliation lines differ in account or partner")
            line_currency_id = _record_id(getattr(line, "currency_id", None))
            if line_currency_id != p["currency_id"]:
                raise OdooWriteHandlerError("reconciliation line currency differs")
            move_id = _record_id(line.move_id)
            if move_id is None:
                raise OdooWriteHandlerError(
                    "reconciliation line has no parent accounting move"
                )
            if move_id not in source_moves:
                source_move = self.record(
                    "account.move", move_id, company, write=True
                )
                source_moves[move_id] = source_move
                source_move_lines[move_id] = self.checked_move_lines(
                    source_move, company, write=True
                )
            residual_field = (
                "amount_residual" if p["currency_id"] == company_currency_id
                else "amount_residual_currency"
            )
            residual = _decimal(getattr(line, residual_field), residual_field)
            if residual > 0:
                debit += residual
            elif residual < 0:
                credit += abs(residual)
            lines.append(line)
        if any(
            _ids(getattr(move_line, "tax_ids", []))
            or _record_id(getattr(move_line, "tax_line_id", None)) is not None
            or _record_id(
                getattr(move_line, "tax_repartition_line_id", None)
            )
            is not None
            for move_lines in source_move_lines.values()
            for move_line in move_lines
        ):
            raise OdooWriteHandlerError(
                "tax-bearing reconciliation is disabled until its tax graph is approved exactly"
            )
        matched = min(debit, credit)
        self.assert_amount(matched, p["amount"], currency, "reconciliation amount")
        if debit == 0 or credit == 0:
            raise OdooWriteHandlerError("reconciliation requires debit and credit residuals")
        imbalance = abs(debit - credit)
        if p["mode"] == "partial":
            if imbalance == 0:
                raise OdooWriteHandlerError(
                    "partial reconciliation would fully reconcile the selected lines"
                )
        else:
            self.assert_amount(
                imbalance,
                p["tolerance_amount"],
                currency,
                "reconciliation tolerance",
            )
        writeoff_journal = None
        writeoff_account = None
        if p["mode"] == "full":
            writeoff_journal = self.record(
                "account.journal", p["writeoff_journal_id"], company
            ) if p["writeoff_journal_id"] else None
            if writeoff_journal and (
                writeoff_journal.type != "general"
                or getattr(writeoff_journal, "active", True) is False
            ):
                raise OdooWriteHandlerError("write-off journal must be general")
            if p["writeoff_account_id"]:
                if p["writeoff_account_id"] == p["account_id"]:
                    raise OdooWriteHandlerError(
                        "write-off account must differ from the reconciled account"
                    )
                writeoff_account = self.check_account(
                    p["writeoff_account_id"], company
                )
        self.assert_open_date(company, p["reconciliation_date"], "reconciliation_date")
        self.create_model("account.reconcile.wizard", company)
        before_records = self.unique_records(
            [("account.move", move) for move in source_moves.values()]
            + [
                ("account.move.line", line)
                for move_lines in source_move_lines.values()
                for line in move_lines
            ]
        )
        dependencies: list[tuple[str, Any]] = [
            ("res.company", company),
            ("account.account", account),
            ("res.currency", currency),
        ]
        if partner is not None:
            dependencies.append(("res.partner", partner))
        if writeoff_journal is not None:
            dependencies.append(("account.journal", writeoff_journal))
        if writeoff_account is not None:
            dependencies.append(("account.account", writeoff_account))
        dependencies = self.unique_records(dependencies)
        return {
            "checks": [
                "open_lines", "opposite_sides", "account", "partner",
                "currency", "amount", "source_moves", "tax_graph_absent",
            ],
            "before": self.snapshots(before_records, company),
            "dependencies": self.snapshots(dependencies, company),
        }

    def execute_reconciliation(self, p, company, checked):
        source_lines = [
            self.record("account.move.line", line_id, company, write=True)
            for line_id in p["line_ids"]
        ]
        source_moves = self.unique_records(
            [
                (
                    "account.move",
                    self.record(
                        "account.move",
                        _record_id(line.move_id),
                        company,
                        write=True,
                    ),
                )
                for line in source_lines
            ]
        )
        source_move_ids = {move.id for _model_name, move in source_moves}
        source_parent_lines = self.unique_records(
            [
                ("account.move.line", line)
                for _model_name, move in source_moves
                for line in self.checked_move_lines(move, company, write=True)
            ]
        )
        before = checked.get("before")
        expected_before_keys = {
            *(("account.move", move.id) for _model_name, move in source_moves),
            *(
                ("account.move.line", line.id)
                for _model_name, line in source_parent_lines
            ),
        }
        if not isinstance(before, list) or {
            (item.get("model"), item.get("record_id"))
            for item in before
            if isinstance(item, Mapping)
        } != expected_before_keys:
            raise OdooWriteHandlerError(
                "approved reconciliation before graph is invalid"
            )
        values: dict[str, Any] = {
            "date": p["reconciliation_date"],
            "allow_partials": p["mode"] == "partial",
        }
        if p["writeoff_account_id"] is not None:
            values.update({
                "account_id": p["writeoff_account_id"],
                "journal_id": p["writeoff_journal_id"],
                "label": p["writeoff_label"],
            })
        wizard = self.create_model(
            "account.reconcile.wizard", company,
            context={"active_model": "account.move.line", "active_ids": list(p["line_ids"])},
        ).create(values)
        result_lines = wizard.reconcile()
        line_records = [
            self.record("account.move.line", line_id, company)
            for line_id in p["line_ids"]
        ]
        for line_id in _ids(result_lines):
            if line_id not in p["line_ids"]:
                line_records.append(
                    self.record("account.move.line", line_id, company)
                )
        line_records = [
            record
            for _model_name, record in self.unique_records(
                [("account.move.line", line) for line in line_records]
            )
        ]
        partial_ids = sorted(
            {
                partial_id
                for line in line_records
                for partial_id in (
                    _ids(getattr(line, "matched_debit_ids", []))
                    + _ids(getattr(line, "matched_credit_ids", []))
                )
            }
        )
        if not partial_ids:
            raise OdooWriteHandlerError(
                "reconciliation created no readable partial reconcile records"
            )
        partials = [
            self.record("account.partial.reconcile", partial_id, company)
            for partial_id in partial_ids
        ]
        if any(
            _record_id(getattr(partial, "exchange_move_id", None)) is not None
            for partial in partials
        ):
            raise OdooWriteHandlerError(
                "reconciliation created an unsupported exchange-difference graph"
            )
        full_ids = sorted(
            {
                full_id
                for line in line_records
                for full_id in [_record_id(getattr(line, "full_reconcile_id", None))]
                if full_id is not None
            }
            | {
                full_id
                for partial in partials
                for full_id in [_record_id(partial.full_reconcile_id)]
                if full_id is not None
            }
        )
        fulls = [
            self.record("account.full.reconcile", full_id, company)
            for full_id in full_ids
        ]
        full_partial_ids = {
            partial_id
            for full in fulls
            for partial_id in _ids(full.partial_reconcile_ids)
        }
        if not set(partial_ids) <= full_partial_ids and fulls:
            raise OdooWriteHandlerError(
                "reconciliation full receipt omits a linked partial reconcile"
            )
        missing_partial_ids = full_partial_ids - set(partial_ids)
        if missing_partial_ids:
            partials.extend(
                self.record("account.partial.reconcile", partial_id, company)
                for partial_id in sorted(missing_partial_ids)
            )
            partial_ids = sorted(full_partial_ids)
            if any(
                _record_id(getattr(partial, "exchange_move_id", None))
                is not None
                or (
                    _record_id(getattr(partial, "full_reconcile_id", None))
                    not in set(full_ids)
                )
                for partial in partials
            ):
                raise OdooWriteHandlerError(
                    "reconciliation full receipt has an unsupported closure"
                )
        graph_line_ids = {
            line.id for line in line_records
        } | {
            endpoint_id
            for partial in partials
            for endpoint_id in (
                _record_id(partial.debit_move_id),
                _record_id(partial.credit_move_id),
            )
            if endpoint_id is not None
        } | {
            line_id
            for full in fulls
            for line_id in _ids(full.reconciled_line_ids)
        }
        line_records = [
            self.record("account.move.line", line_id, company)
            for line_id in sorted(graph_line_ids)
        ]
        related_move_ids = {
            move_id
            for line in line_records
            if line.id not in p["line_ids"]
            for move_id in [_record_id(line.move_id)]
            if move_id is not None and move_id not in source_move_ids
        }
        related_move_ids.update(
            move_id
            for partial in partials
            for move_id in [_record_id(partial.exchange_move_id)]
            if move_id is not None
        )
        caba_moves = self.search_records(
            "account.move",
            [("tax_cash_basis_rec_id", "in", partial_ids)],
            company,
            limit=1000,
        )
        if caba_moves:
            raise OdooWriteHandlerError(
                "reconciliation created an unsupported cash-basis tax graph"
            )
        related_move_ids.update(move.id for move in caba_moves)
        related_moves = [
            self.record("account.move", move_id, company)
            for move_id in sorted(related_move_ids)
        ]
        records: list[tuple[str, Any]] = [
            *source_moves,
            *source_parent_lines,
            *(("account.move.line", line) for line in line_records),
        ]
        records.extend(
            ("account.partial.reconcile", partial) for partial in partials
        )
        records.extend(("account.full.reconcile", full) for full in fulls)
        for move in related_moves:
            records.extend(self.move_records(move, company))
        records = self.unique_records(records)
        prior_partial_ids: set[int] = set()
        prior_full_ids: set[int] = set()
        for item in before:
            if (
                not isinstance(item, Mapping)
                or item.get("model") != "account.move.line"
                or not isinstance(item.get("values"), Mapping)
            ):
                continue
            values_before = item["values"]
            prior_partial_ids.update(
                _ids(values_before.get("matched_debit_ids", []))
            )
            prior_partial_ids.update(
                _ids(values_before.get("matched_credit_ids", []))
            )
            full_id = classic_read_many2one_id(
                values_before.get("full_reconcile_id")
            )
            if full_id is not None:
                prior_full_ids.add(full_id)
        action_keys = {
            (model_name, record.id)
            for model_name, record in records
            if (
                model_name == "account.partial.reconcile"
                and record.id not in prior_partial_ids
            )
            or (
                model_name == "account.full.reconcile"
                and record.id not in prior_full_ids
            )
            or (
                model_name == "account.move"
                and record.id in related_move_ids
            )
        }
        if prior_partial_ids or prior_full_ids:
            recovery = _recovery(
                "manual_escalation",
                _MANUAL_RECOVERY_METHODS[
                    "undo_reconciliation_and_reverse_writeoff_v1"
                ],
                [
                    {"model": model_name, "record_id": record_id}
                    for model_name, record_id in sorted(action_keys)
                ],
            )
        else:
            recovery = self.available_recovery(
                "acct.reconciliation.apply.v1",
                "undo_reconciliation_and_reverse_writeoff_v1",
                records,
                action_keys=action_keys,
            )
        return records, recovery

    def verify_reconciliation(self, p, company, records, before):
        keyed: dict[tuple[str, int], Any] = {}
        for model_name, record in records:
            key = (model_name, record.id)
            if key in keyed:
                raise OdooWriteHandlerError(
                    "reconciliation read-back record is duplicated"
                )
            keyed[key] = record
        if any(
            model_name not in {
                "account.move",
                "account.move.line",
                "account.partial.reconcile",
                "account.full.reconcile",
            }
            for model_name, _record_id_value in keyed
        ):
            raise OdooWriteHandlerError(
                "reconciliation read-back contains an unsupported model"
            )

        source_ids = set(p["line_ids"])
        originals = [
            keyed.get(("account.move.line", line_id))
            for line_id in p["line_ids"]
        ]
        if any(line is None for line in originals):
            raise OdooWriteHandlerError("reconciliation source line is missing")
        source_move_ids = {_record_id(line.move_id) for line in originals}
        if None in source_move_ids:
            raise OdooWriteHandlerError(
                "reconciliation source parent move is missing"
            )
        if not isinstance(before, Mapping):
            raise OdooWriteHandlerError(
                "trusted reconciliation before graph differs"
            )
        source_parent_line_ids = {
            line_id
            for move_id in source_move_ids
            for line_id in _ids(
                before.get(("account.move", move_id), {}).get("line_ids", [])
            )
        }
        expected_before_keys = {
            *(("account.move", move_id) for move_id in source_move_ids),
            *(
                ("account.move.line", line_id)
                for line_id in source_parent_line_ids
            ),
        }
        if (
            not source_ids <= source_parent_line_ids
            or set(before) != expected_before_keys
        ):
            raise OdooWriteHandlerError(
                "trusted reconciliation before graph differs"
            )

        for move_id in source_move_ids:
            move = keyed.get(("account.move", move_id))
            approved = before[("account.move", move_id)]
            if (
                move is None
                or move.state != "posted"
                or str(approved.get("state")) != "posted"
                or _ids(move.line_ids) != _ids(approved.get("line_ids", []))
            ):
                raise OdooWriteHandlerError(
                    "reconciliation source parent move differs"
                )
            self.assert_approved_record_delta(
                "account.move",
                move,
                company,
                approved,
                allowed_changed_fields=frozenset(
                    {"amount_residual", "payment_state"}
                ),
                label="reconciliation source parent move",
            )
        for line_id in source_parent_line_ids:
            line = keyed.get(("account.move.line", line_id))
            approved = before[("account.move.line", line_id)]
            if (
                line is None
                or _record_id(line.move_id) != _record_id(approved.get("move_id"))
                or _record_id(line.move_id) not in source_move_ids
            ):
                raise OdooWriteHandlerError(
                    "reconciliation source parent line graph differs"
                )
            allowed = (
                frozenset(
                    {
                        "amount_residual",
                        "amount_residual_currency",
                        "reconciled",
                        "full_reconcile_id",
                        "matched_debit_ids",
                        "matched_credit_ids",
                        "matching_number",
                    }
                )
                if line_id in source_ids
                else frozenset()
            )
            self.assert_approved_record_delta(
                "account.move.line",
                line,
                company,
                approved,
                allowed_changed_fields=allowed,
                label="reconciliation source parent line",
            )
        for line_id in source_ids:
            values = before[("account.move.line", line_id)]
            line = keyed[("account.move.line", line_id)]
            if (
                _ids(values.get("matched_debit_ids", []))
                or _ids(values.get("matched_credit_ids", []))
                or _record_id(values.get("full_reconcile_id")) is not None
                or values.get("matching_number")
                or values.get("reconciled") is not False
                or _record_id(line.account_id) != p["account_id"]
                or _record_id(line.partner_id) != p["partner_id"]
                or _record_id(line.currency_id) != p["currency_id"]
            ):
                raise OdooWriteHandlerError(
                    "trusted reconciliation source was not initially open"
                )

        move_records = {
            record.id: record
            for model_name, record in records
            if model_name == "account.move"
        }
        generated_move_ids = set(move_records) - source_move_ids
        generated_line_ids = {
            line_id
            for move_id in generated_move_ids
            for line_id in _ids(move_records[move_id].line_ids)
        }
        expected_line_ids = source_parent_line_ids | generated_line_ids
        actual_line_ids = {
            record.id
            for model_name, record in records
            if model_name == "account.move.line"
        }
        if actual_line_ids != expected_line_ids:
            raise OdooWriteHandlerError(
                "reconciliation parent and generated line graph differs"
            )

        partials = [
            record
            for model_name, record in records
            if model_name == "account.partial.reconcile"
        ]
        if not partials:
            raise OdooWriteHandlerError(
                "reconciliation partial graph is missing"
            )
        partial_ids = {partial.id for partial in partials}
        relevant_line_ids = source_ids | generated_line_ids
        linked_partial_ids = {
            partial_id
            for line_id in relevant_line_ids
            for partial_id in (
                _ids(keyed[("account.move.line", line_id)].matched_debit_ids)
                + _ids(keyed[("account.move.line", line_id)].matched_credit_ids)
            )
        }
        if linked_partial_ids != partial_ids:
            raise OdooWriteHandlerError(
                "reconciliation partial record set differs"
            )
        for partial in partials:
            if (
                _record_id(partial.company_id) != company.id
                or _record_id(partial.debit_move_id) not in relevant_line_ids
                or _record_id(partial.credit_move_id) not in relevant_line_ids
                or _record_id(partial.debit_currency_id) != p["currency_id"]
                or _record_id(partial.credit_currency_id) != p["currency_id"]
                or _record_id(getattr(partial, "exchange_move_id", None))
                is not None
            ):
                raise OdooWriteHandlerError(
                    "partial reconcile endpoint, company, currency, or exchange graph differs"
                )

        company_currency_id = _record_id(company.currency_id)
        currency = self.assert_currency(p["currency_id"], company)
        source_matched = Decimal("0")
        for partial in partials:
            debit_id = _record_id(partial.debit_move_id)
            credit_id = _record_id(partial.credit_move_id)
            if debit_id in source_ids and credit_id in source_ids:
                source_matched += abs(
                    _decimal(partial.amount, "partial reconcile amount")
                )
        self.assert_amount(
            source_matched,
            p["amount"],
            currency,
            "partial reconcile amount",
        )

        residual_field = "amount_residual"
        before_residuals = [
            _decimal(
                before[("account.move.line", line_id)][residual_field],
                residual_field,
            )
            for line_id in p["line_ids"]
        ]
        after_residuals = [
            _decimal(getattr(line, residual_field), residual_field)
            for line in originals
        ]
        before_debit = sum(
            (value for value in before_residuals if value > 0), Decimal("0")
        )
        before_credit = sum(
            (-value for value in before_residuals if value < 0), Decimal("0")
        )
        after_debit = sum(
            (value for value in after_residuals if value > 0), Decimal("0")
        )
        after_credit = sum(
            (-value for value in after_residuals if value < 0), Decimal("0")
        )

        expected_full_ids = {
            full_id
            for line_id in relevant_line_ids
            for full_id in [
                _record_id(
                    keyed[("account.move.line", line_id)].full_reconcile_id
                )
            ]
            if full_id is not None
        } | {
            full_id
            for partial in partials
            for full_id in [_record_id(partial.full_reconcile_id)]
            if full_id is not None
        }
        actual_full_ids = {
            record.id
            for model_name, record in records
            if model_name == "account.full.reconcile"
        }
        if actual_full_ids != expected_full_ids:
            raise OdooWriteHandlerError("full reconcile record set differs")

        if p["mode"] == "partial":
            self.assert_amount(
                before_debit - after_debit,
                p["amount"],
                currency,
                "debit residual reduction",
            )
            self.assert_amount(
                before_credit - after_credit,
                p["amount"],
                currency,
                "credit residual reduction",
            )
            if expected_full_ids:
                raise OdooWriteHandlerError(
                    "partial reconciliation unexpectedly created a full reconcile"
                )
            expected_matching = f"P{min(partial_ids)}"
            if any(str(line.matching_number) != expected_matching for line in originals):
                raise OdooWriteHandlerError(
                    "partial reconciliation matching number differs"
                )
        else:
            if any(value != 0 for value in after_residuals) or not all(
                line.reconciled for line in originals
            ):
                raise OdooWriteHandlerError(
                    "full reconciliation did not clear every source residual"
                )
            source_full_ids = {
                _record_id(line.full_reconcile_id) for line in originals
            }
            if (
                None in source_full_ids
                or len(source_full_ids) != 1
                or source_full_ids != expected_full_ids
            ):
                raise OdooWriteHandlerError(
                    "full reconciliation identity differs"
                )
            full_id = next(iter(source_full_ids))
            full = keyed[("account.full.reconcile", full_id)]
            if set(_ids(full.partial_reconcile_ids)) != partial_ids:
                raise OdooWriteHandlerError(
                    "full reconcile partial set differs"
                )
            endpoint_ids = {
                endpoint_id
                for partial in partials
                for endpoint_id in (
                    _record_id(partial.debit_move_id),
                    _record_id(partial.credit_move_id),
                )
            }
            if set(_ids(full.reconciled_line_ids)) != endpoint_ids:
                raise OdooWriteHandlerError(
                    "full reconcile line set differs"
                )
            if any(str(line.matching_number) != str(full_id) for line in originals):
                raise OdooWriteHandlerError(
                    "full reconciliation matching number differs"
                )

        tolerance = _decimal(p["tolerance_amount"], "tolerance_amount")
        if (
            (tolerance == 0 and generated_move_ids)
            or (tolerance > 0 and len(generated_move_ids) != 1)
        ):
            raise OdooWriteHandlerError(
                "reconciliation generated move set differs"
            )
        for move_id, move in move_records.items():
            if (
                move.state != "posted"
                or _record_id(getattr(move, "tax_cash_basis_rec_id", None))
                is not None
            ):
                raise OdooWriteHandlerError(
                    "reconciliation move state or cash-basis graph differs"
                )
            if move_id in generated_move_ids:
                self.assert_move_balanced(move, company)
        if any(
            _ids(getattr(keyed[("account.move.line", line_id)], "tax_ids", []))
            or _record_id(
                getattr(
                    keyed[("account.move.line", line_id)], "tax_line_id", None
                )
            )
            is not None
            or _record_id(
                getattr(
                    keyed[("account.move.line", line_id)],
                    "tax_repartition_line_id",
                    None,
                )
            )
            is not None
            for line_id in actual_line_ids
        ):
            raise OdooWriteHandlerError(
                "reconciliation tax-bearing line graph differs"
            )

        if tolerance > 0:
            writeoff_lines = [
                keyed[("account.move.line", line_id)]
                for line_id in generated_line_ids
                if _record_id(keyed[("account.move.line", line_id)].account_id)
                == p["writeoff_account_id"]
            ]
            if len(writeoff_lines) != 1:
                raise OdooWriteHandlerError(
                    "write-off journal item receipt differs"
                )
            writeoff_line = writeoff_lines[0]
            if str(writeoff_line.name or "") != p["writeoff_label"]:
                raise OdooWriteHandlerError("write-off label differs")
            writeoff_move = keyed.get(
                ("account.move", _record_id(writeoff_line.move_id))
            )
            if (
                writeoff_move is None
                or _record_id(writeoff_move.journal_id)
                != p["writeoff_journal_id"]
                or str(writeoff_move.date) != p["reconciliation_date"]
            ):
                raise OdooWriteHandlerError(
                    "write-off move journal or date differs"
                )
            self.assert_amount(
                abs(_decimal(writeoff_line.balance, "write-off amount")),
                tolerance,
                currency,
                "write-off amount",
            )

        expected_keys = {
            *(("account.move", move_id) for move_id in move_records),
            *(("account.move.line", line_id) for line_id in actual_line_ids),
            *(
                ("account.partial.reconcile", partial_id)
                for partial_id in partial_ids
            ),
            *(
                ("account.full.reconcile", full_id)
                for full_id in actual_full_ids
            ),
        }
        if set(keyed) != expected_keys:
            raise OdooWriteHandlerError(
                "reconciliation record graph differs"
            )
        return [
            "source_lines_exist", "source_parent_moves_match",
            "trusted_before_graph_matches", "partial_records_exact",
            "partial_endpoints_match", "partial_amount_matches",
            "residual_reductions_match", "matching_numbers_match",
            "mode_result_matches", "full_reconcile_graph_exact",
            "generated_moves_posted_and_balanced", "writeoff_matches",
            "record_graph_exact",
        ]

    def precheck_asset(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        source = self.record("account.move.line", p["source_move_line_id"], company, write=True)
        source_move = self.record("account.move", _record_id(source.move_id), company)
        source_lines = self.checked_move_lines(source_move, company)
        model = self.record("account.asset", p["asset_model_id"], company)
        currency = self.assert_currency(p["currency_id"], company)
        if source_move.state != "posted" or source.balance <= 0:
            raise OdooWriteHandlerError("asset source must be a posted positive journal item")
        if getattr(model, "state", None) != "model":
            raise OdooWriteHandlerError("asset_model_id is not an asset model")
        if p["currency_id"] != _record_id(company.currency_id):
            raise OdooWriteHandlerError("asset currency must be the company currency")
        if _record_id(source.account_id) != _record_id(model.account_asset_id):
            raise OdooWriteHandlerError("asset source account differs from the asset model")
        asset_account = self.check_account(_record_id(model.account_asset_id), company)
        depreciation_account = self.check_account(
            _record_id(model.account_depreciation_id), company
        )
        expense_account = self.check_account(
            _record_id(model.account_depreciation_expense_id), company
        )
        if str(asset_account.account_type) not in {"asset_fixed", "asset_non_current"}:
            raise OdooWriteHandlerError(
                "asset source account must be fixed or non-current"
            )
        if str(depreciation_account.account_type) not in {
            "asset_fixed", "asset_non_current"
        }:
            raise OdooWriteHandlerError(
                "accumulated depreciation account must be fixed or non-current"
            )
        if str(expense_account.account_type) not in {
            "expense", "expense_depreciation", "expense_direct_cost"
        }:
            raise OdooWriteHandlerError(
                "asset depreciation expense account type is incompatible"
            )
        account_ids = {
            asset_account.id, depreciation_account.id, expense_account.id
        }
        if len(account_ids) != 3:
            raise OdooWriteHandlerError("asset model accounting accounts must be distinct")
        asset_journal = self.record("account.journal", _record_id(model.journal_id), company)
        if asset_journal.type != "general" or getattr(asset_journal, "active", True) is False:
            raise OdooWriteHandlerError("asset model journal is not active and general")
        linked_assets = getattr(source, "asset_ids", [])
        if linked_assets:
            try:
                active_links = [
                    asset for asset in linked_assets
                    if str(getattr(asset, "state", "")) not in {"cancel", "cancelled"}
                ]
            except TypeError as exc:
                raise OdooWriteHandlerError(
                    "asset source links cannot be inspected safely"
                ) from exc
            if active_links:
                raise OdooWriteHandlerError(
                    "asset source line is already linked to a non-cancelled asset"
                )
        self.assert_amount(source.balance, p["acquisition_value"], currency, "acquisition value")
        self.assert_open_date(company, p["acquisition_date"], "acquisition_date")
        self.create_model("account.asset", company)
        before_records = self.unique_records([
            ("account.move", source_move),
            *(("account.move.line", line) for line in source_lines),
        ])
        dependencies = self.unique_records([
            ("res.company", company),
            ("res.currency", currency),
            ("account.asset", model),
            ("account.account", asset_account),
            ("account.account", depreciation_account),
            ("account.account", expense_account),
            ("account.journal", asset_journal),
        ])
        return {
            "checks": [
                "source_posted", "source_unused", "source_move_graph",
                "asset_model", "model_accounts", "model_journal", "amount", "date",
            ],
            "before": self.snapshots(before_records, company),
            "dependencies": self.snapshots(dependencies, company),
        }

    def execute_asset(self, p, company, checked):
        model = self.record("account.asset", p["asset_model_id"], company)
        copy_fields = (
            "method", "method_number", "method_period", "method_progress_factor",
            "prorata_computation_type", "prorata_date", "salvage_value",
            "account_asset_id", "account_depreciation_id",
            "account_depreciation_expense_id", "journal_id",
        )
        values: dict[str, Any] = {
            "name": p["asset_name"], "company_id": p["company_id"],
            "model_id": p["asset_model_id"], "acquisition_date": p["acquisition_date"],
            "original_value": float(_decimal(p["acquisition_value"], "acquisition_value")),
            "original_move_line_ids": [(6, 0, [p["source_move_line_id"]])],
        }
        for field in copy_fields:
            value = getattr(model, field, None)
            identifier = _record_id(value)
            values[field] = identifier if identifier is not None else value
        asset = self.create_model("account.asset", company).create(values)
        self.require_created(asset, "account.asset", company)
        if p["posting_mode"] == "confirm":
            asset.validate()
        source = self.record(
            "account.move.line", p["source_move_line_id"], company
        )
        source_move = self.record(
            "account.move", _record_id(source.move_id), company
        )
        records = self.unique_records([
            ("account.asset", asset),
            ("account.move", source_move),
            ("account.move.line", source),
            *self.move_records(source_move, company),
            *self.asset_schedule_records(asset, company),
        ])
        return records, self.available_recovery(
            "acct.asset.create.v1",
            "cancel_asset_and_reverse_schedule_v1",
            records,
            action_keys={("account.asset", asset.id)},
            guard_outcomes={
                (model_name, record.id): "survive_exact"
                for model_name, record in records
                if (
                    model_name == "account.move"
                    and record.id == source_move.id
                )
                or (
                    model_name == "account.move.line"
                    and _record_id(getattr(record, "move_id", None))
                    == source_move.id
                )
            },
        )

    def verify_asset(self, p, company, records, trusted_before=None):
        asset = self.only_record(records, "account.asset")
        if (
            _record_id(asset.model_id) != p["asset_model_id"]
            or _ids(asset.original_move_line_ids) != [p["source_move_line_id"]]
        ):
            raise OdooWriteHandlerError("asset model or source linkage differs")
        currency = self.assert_currency(p["currency_id"], company)
        self.assert_amount(asset.original_value, p["acquisition_value"], currency, "asset value")
        if (
            str(asset.name) != p["asset_name"]
            or str(asset.acquisition_date) != p["acquisition_date"]
            or _record_id(asset.currency_id) != p["currency_id"]
        ):
            raise OdooWriteHandlerError("asset identity, date, or currency differs")
        expected = "open" if p["posting_mode"] == "confirm" else "draft"
        if asset.state != expected:
            raise OdooWriteHandlerError("asset state differs")
        source = next(
            (
                record for model_name, record in records
                if model_name == "account.move.line"
                and record.id == p["source_move_line_id"]
            ),
            None,
        )
        if source is None or asset.id not in _ids(getattr(source, "asset_ids", [])):
            raise OdooWriteHandlerError("asset source reverse linkage differs")
        source_move = next(
            (
                record for model_name, record in records
                if model_name == "account.move"
                and record.id == _record_id(source.move_id)
            ),
            None,
        )
        if source_move is None:
            raise OdooWriteHandlerError("asset source move receipt is missing")
        expected_record_keys = {
            ("account.asset", asset.id),
            ("account.move", source_move.id),
            *(("account.move.line", line_id) for line_id in _ids(source_move.line_ids)),
        }
        schedule_ids = _ids(asset.depreciation_move_ids)
        schedule_moves = {
            record.id: record
            for model_name, record in records
            if model_name == "account.move" and record.id in schedule_ids
        }
        if set(schedule_moves) != set(schedule_ids):
            raise OdooWriteHandlerError("asset depreciation schedule receipt differs")
        for move in schedule_moves.values():
            expected_record_keys.add(("account.move", move.id))
            expected_record_keys.update(
                ("account.move.line", line_id) for line_id in _ids(move.line_ids)
            )
        actual_record_keys = [(model_name, record.id) for model_name, record in records]
        if len(actual_record_keys) != len(set(actual_record_keys)) or set(actual_record_keys) != expected_record_keys:
            raise OdooWriteHandlerError("asset affected record graph differs")

        model = self.record("account.asset", p["asset_model_id"], company)
        relation_fields = (
            "account_asset_id", "account_depreciation_id",
            "account_depreciation_expense_id", "journal_id",
        )
        scalar_fields = (
            "method", "method_number", "method_period",
            "method_progress_factor", "prorata_computation_type",
            "prorata_date", "salvage_value",
        )
        for field_name in relation_fields:
            if _record_id(getattr(asset, field_name)) != _record_id(
                getattr(model, field_name)
            ):
                raise OdooWriteHandlerError(
                    f"asset copied {field_name} differs from the live approved model"
                )
        for field_name in scalar_fields:
            if _primitive(getattr(asset, field_name, None)) != _primitive(
                getattr(model, field_name, None)
            ):
                raise OdooWriteHandlerError(
                    f"asset copied {field_name} differs from the live approved model"
                )
        if trusted_before:
            source_records = self.move_records(source_move, company)
            expected_before_keys = {
                (model_name, record.id) for model_name, record in source_records
            }
            if set(trusted_before) != expected_before_keys:
                raise OdooWriteHandlerError(
                    "asset approved source graph differs"
                )
            for model_name, record in source_records:
                approved = dict(trusted_before[(model_name, record.id)])
                current = dict(self.snapshot(model_name, record, company)["values"])
                if model_name == "account.move.line" and record.id == source.id:
                    approved_assets = set(_ids(approved.pop("asset_ids", [])))
                    current_assets = set(_ids(current.pop("asset_ids", [])))
                    if current_assets != approved_assets | {asset.id}:
                        raise OdooWriteHandlerError(
                            "asset source reverse link differs from approval"
                        )
                if current != approved:
                    raise OdooWriteHandlerError(
                        "asset source graph changed after approval"
                    )

        if p["posting_mode"] == "confirm":
            if not schedule_moves:
                raise OdooWriteHandlerError("confirmed asset has no depreciation schedule")
            scheduled_total = Decimal("0")
            for move in schedule_moves.values():
                if _record_id(move.asset_id) != asset.id:
                    raise OdooWriteHandlerError("asset schedule contains another asset")
                if str(move.asset_move_type) != "depreciation":
                    raise OdooWriteHandlerError("asset schedule contains a non-depreciation move")
                if (
                    _record_id(move.journal_id) != _record_id(asset.journal_id)
                    or _record_id(move.currency_id) != p["currency_id"]
                ):
                    raise OdooWriteHandlerError("asset schedule journal or currency differs")
                self.assert_depreciation_accounts(move, asset, company, currency)
                scheduled_total += _decimal(
                    move.depreciation_value, "scheduled depreciation value"
                )
            expected_depreciable = _decimal(
                asset.original_value, "asset original value"
            ) - _decimal(asset.salvage_value, "asset salvage value")
            self.assert_amount(
                scheduled_total,
                expected_depreciable,
                currency,
                "asset depreciation schedule total",
            )
        elif schedule_moves:
            raise OdooWriteHandlerError("draft asset unexpectedly has a depreciation schedule")
        return [
            "asset_exists", "identity_matches", "model_matches",
            "model_copy_matches", "source_link_matches", "source_reverse_link_matches",
            "value_matches", "state_matches", "record_graph_exact",
            "schedule_matches", "schedule_accounts_match", "schedule_total_matches",
        ]

    def precheck_depreciation(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        asset = self.record("account.asset", p["asset_id"], company)
        move = self.record("account.move", p["depreciation_move_id"], company, write=True)
        journal = self.check_journal(p, company, {"general"})
        currency = self.assert_currency(p["currency_id"], company, journal)
        depreciation_account = self.check_account(
            _record_id(asset.account_depreciation_id), company
        )
        expense_account = self.check_account(
            _record_id(asset.account_depreciation_expense_id), company
        )
        if str(depreciation_account.account_type) not in {
            "asset_fixed", "asset_non_current"
        } or str(expense_account.account_type) not in {
            "expense", "expense_depreciation", "expense_direct_cost"
        }:
            raise OdooWriteHandlerError(
                "asset depreciation account configuration is incompatible"
            )
        if (
            p["currency_id"] != _record_id(company.currency_id)
            or _record_id(asset.currency_id) != p["currency_id"]
        ):
            raise OdooWriteHandlerError(
                "asset depreciation must use the company currency"
            )
        if asset.state != "open" or move.state != "draft" or _record_id(move.asset_id) != asset.id:
            raise OdooWriteHandlerError("depreciation move is not a draft of the open asset")
        if str(getattr(move, "asset_move_type", "")) != "depreciation":
            raise OdooWriteHandlerError("asset move is not a depreciation schedule entry")
        if move.id not in _ids(asset.depreciation_move_ids):
            raise OdooWriteHandlerError("depreciation move is absent from the asset schedule")
        if _record_id(move.journal_id) != p["journal_id"] or _record_id(move.currency_id) != p["currency_id"]:
            raise OdooWriteHandlerError("depreciation journal or currency differs")
        start = _as_date(p["period_start"], "period_start")
        end = _as_date(p["period_end"], "period_end")
        if str(move.date) != p["posting_date"] or _as_date(move.date, "move.date") != end:
            raise OdooWriteHandlerError("depreciation posting date must equal the schedule period end")
        if _as_date(move.asset_depreciation_beginning_date, "asset_depreciation_beginning_date") != start:
            raise OdooWriteHandlerError("depreciation schedule beginning date differs")
        self.assert_open_date(company, p["posting_date"], "posting_date", journal=journal)
        move_lines = self.checked_move_lines(move, company)
        debit = sum(_decimal(line.debit, "debit") for line in move_lines)
        self.assert_amount(debit, p["amount"], currency, "depreciation amount")
        self.assert_amount(move.depreciation_value, p["amount"], currency, "depreciation value")
        self.assert_depreciation_accounts(move, asset, company, currency)
        schedule_records = self.asset_schedule_records(asset, company)
        return {
            "checks": [
                "asset_open", "scheduled_depreciation_move", "draft", "period",
                "date", "journal", "currency", "depreciation_value",
                "depreciation_accounts", "balanced_debit_amount", "full_schedule_graph",
            ],
            "before": self.snapshots(
                self.unique_records([("account.asset", asset), *schedule_records]),
                company,
            ),
            "dependencies": self.snapshots(
                self.unique_records(
                    [
                        ("res.company", company),
                        ("res.currency", currency),
                        ("account.journal", journal),
                        ("account.account", depreciation_account),
                        ("account.account", expense_account),
                    ]
                ),
                company,
            ),
        }

    def execute_depreciation(self, p, company, checked):
        asset = self.record("account.asset", p["asset_id"], company)
        move = self.record("account.move", p["depreciation_move_id"], company, write=True)
        move.action_post()
        records = self.unique_records([
            ("account.asset", asset),
            *self.asset_schedule_records(asset, company),
        ])
        return records, self.available_recovery(
            "acct.depreciation.post.v1",
            "reverse_depreciation_and_restore_schedule_v1",
            records,
            action_keys={("account.move", move.id)},
            guard_outcomes={
                (model_name, record.id): "survive_exact"
                for model_name, record in records
                if (
                    model_name == "account.move"
                    and record.id != move.id
                )
                or (
                    model_name == "account.move.line"
                    and _record_id(getattr(record, "move_id", None))
                    != move.id
                )
            },
        )

    def verify_depreciation(self, p, company, records, trusted_before=None):
        asset = self.only_record(records, "account.asset")
        moves = {
            record.id: record
            for model_name, record in records
            if model_name == "account.move"
        }
        schedule_ids = _ids(asset.depreciation_move_ids)
        if set(moves) != set(schedule_ids):
            raise OdooWriteHandlerError("depreciation schedule receipt differs")
        move = moves.get(p["depreciation_move_id"])
        if move is None:
            raise OdooWriteHandlerError("approved depreciation move receipt is missing")
        if (
            move.state != "posted"
            or _record_id(move.asset_id) != p["asset_id"]
            or move.asset_move_type != "depreciation"
            or str(move.asset_depreciation_beginning_date) != p["period_start"]
            or str(move.date) != p["period_end"]
        ):
            raise OdooWriteHandlerError("depreciation posting read-back differs")
        if (
            asset.state != "open"
            or _record_id(asset.currency_id) != p["currency_id"]
            or _record_id(move.journal_id) != p["journal_id"]
            or _record_id(move.currency_id) != p["currency_id"]
        ):
            raise OdooWriteHandlerError("depreciation asset, journal, or currency differs")
        expected_keys = {("account.asset", asset.id)}
        for schedule_move in moves.values():
            if _record_id(schedule_move.asset_id) != asset.id:
                raise OdooWriteHandlerError("depreciation schedule contains another asset")
            expected_keys.add(("account.move", schedule_move.id))
            expected_keys.update(
                ("account.move.line", line_id)
                for line_id in _ids(schedule_move.line_ids)
            )
        actual_keys = [(model_name, record.id) for model_name, record in records]
        if len(actual_keys) != len(set(actual_keys)) or set(actual_keys) != expected_keys:
            raise OdooWriteHandlerError("depreciation affected record graph differs")
        currency = self.assert_currency(p["currency_id"], company)
        self.assert_amount(move.depreciation_value, p["amount"], currency, "depreciation value")
        self.assert_depreciation_accounts(move, asset, company, currency)
        if not isinstance(trusted_before, Mapping):
            raise OdooWriteHandlerError("depreciation approval snapshots are missing")
        expected_before_keys = expected_keys
        if set(trusted_before) != expected_before_keys:
            raise OdooWriteHandlerError("depreciation approval schedule graph changed")
        asset_before = trusted_before[("account.asset", asset.id)]
        move_before = trusted_before[("account.move", move.id)]
        if str(move_before.get("state")) != "draft":
            raise OdooWriteHandlerError("approved depreciation move was not draft")
        if set(_ids(asset_before.get("depreciation_move_ids"))) != set(schedule_ids):
            raise OdooWriteHandlerError("asset schedule changed after approval")
        before_residual = _decimal(
            asset_before.get("value_residual"), "approved asset residual"
        )
        amount = _decimal(p["amount"], "depreciation amount")
        self.assert_amount(
            asset.value_residual,
            before_residual - amount,
            currency,
            "asset residual after depreciation",
        )
        before_book_value = _decimal(
            asset_before.get("book_value"), "approved asset book value"
        )
        self.assert_amount(
            asset.book_value,
            before_book_value - amount,
            currency,
            "asset book value after depreciation",
        )
        self.assert_approved_record_delta(
            "account.asset",
            asset,
            company,
            asset_before,
            allowed_changed_fields=frozenset({"value_residual", "book_value"}),
            label="depreciation asset schedule",
        )
        if str(getattr(move, "name", "") or "") in {"", "/"}:
            raise OdooWriteHandlerError("posted depreciation move has no receipt number")
        for schedule_move in moves.values():
            is_target = schedule_move.id == move.id
            self.assert_approved_record_delta(
                "account.move",
                schedule_move,
                company,
                trusted_before[("account.move", schedule_move.id)],
                allowed_changed_fields=(
                    frozenset({"state", "name"}) if is_target else frozenset()
                ),
                label="depreciation schedule",
            )
            for line_id in _ids(schedule_move.line_ids):
                line = next(
                    record
                    for model_name, record in records
                    if model_name == "account.move.line" and record.id == line_id
                )
                self.assert_approved_record_delta(
                    "account.move.line",
                    line,
                    company,
                    trusted_before[("account.move.line", line_id)],
                    allowed_changed_fields=frozenset(),
                    label="depreciation schedule",
                )
            if not is_target and (
                str(schedule_move.state)
                != str(trusted_before[("account.move", schedule_move.id)].get("state"))
                or str(schedule_move.date)
                != str(trusted_before[("account.move", schedule_move.id)].get("date"))
            ):
                raise OdooWriteHandlerError(
                    "another depreciation schedule move changed"
                )
        return [
            "move_exists", "move_posted", "asset_link_matches",
            "depreciation_type_matches", "period_matches", "value_matches",
            "journal_currency_match", "accounts_match", "move_balanced",
            "asset_residual_matches", "asset_book_value_matches",
            "approved_schedule_graph_allowlist_matches",
            "other_schedule_moves_unchanged",
            "schedule_retained", "record_graph_exact",
        ]

    def precheck_journal_entry(
        self,
        p: dict[str, Any],
        company: Any,
        *,
        adjustment: bool,
        raw_lock_dates: bool = True,
    ) -> dict[str, Any]:
        if any(line.get("tax_ids") for line in p["lines"]):
            raise OdooWriteHandlerError(
                "tax-bearing period entries are disabled until their generated tax graph can be verified exactly"
            )
        journal = self.check_journal(p, company, {"general"})
        currency = self.assert_currency(p["currency_id"], company, journal)
        if raw_lock_dates:
            self.assert_open_date(
                company,
                p["posting_date"],
                "posting_date",
                journal=journal,
                taxes=False,
            )
        dependencies: list[tuple[str, Any]] = [
            ("res.company", company),
            ("res.currency", currency),
            ("account.journal", journal),
        ]
        for line in p["lines"]:
            dependencies.append(
                ("account.account", self.check_account(line["account_id"], company))
            )
            if line["partner_id"] is not None:
                dependencies.append(
                    ("res.partner", self.check_partner(line["partner_id"], company))
                )
        self.create_model("account.move", company)
        return {
            "checks": [
                "balanced", "date", "journal", "currency", "accounts",
                "tax_graph_absent",
            ],
            "before": [],
            "dependencies": self.snapshots(
                self.unique_records(dependencies), company
            ),
        }

    def precheck_accrual(self, p, company):
        if p["posting_mode"] != "post":
            raise OdooWriteHandlerError(
                "draft accrual cannot bind an Odoo reversal schedule safely"
            )
        if _as_date(p["reversal_date"], "reversal_date") <= self.context.today:
            raise OdooWriteHandlerError(
                "accrual reversal_date must be future-dated for Odoo auto-post"
            )
        result = self.precheck_journal_entry(
            p, company, adjustment=False
        )
        document_binding = self.document_binding("accrual", p)
        business_binding = self.business_binding("accrual", p)
        if self.search_records(
            "account.move",
            [
                ("company_id", "=", company.id),
                ("move_type", "=", "entry"),
                ("odoo_cli_v3_document_binding", "=", document_binding),
            ],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "accrual already exists for the approved parameters"
            )
        if self.search_records(
            "account.move",
            [
                ("company_id", "=", company.id),
                ("move_type", "=", "entry"),
                ("odoo_cli_v3_business_binding", "=", business_binding),
            ],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "accrual business key already exists in this company"
            )
        self.create_model("account.move.reversal", company)
        result["checks"].extend(
            [
                "accrual_content_binding_unique",
                "accrual_business_binding_unique",
                "scheduled_reversal_public_wizard",
            ]
        )
        return result

    def precheck_adjustment(self, p, company):
        return self.precheck_journal_entry(p, company, adjustment=True)

    def precheck_journal_entry_create(
        self, p: dict[str, Any], company: Any
    ) -> dict[str, Any]:
        if p["posting_mode"] != "draft":
            raise OdooWriteHandlerError(
                "manual journal entry creation is restricted to draft mode"
            )
        result = self.precheck_journal_entry(
            p,
            company,
            adjustment=False,
            raw_lock_dates=False,
        )
        journal = self.check_journal(p, company, {"general"})
        self.assert_effective_open_date(
            company,
            p["posting_date"],
            "posting_date",
            journal=journal,
            taxes=False,
        )
        transaction_currency = self.assert_currency(
            p["currency_id"], company
        )
        company_currency_id = _record_id(
            getattr(company, "currency_id", None)
        )
        if company_currency_id is None:
            raise OdooWriteHandlerError(
                "company currency is not configured"
            )
        company_currency = self.assert_currency(
            company_currency_id, company
        )
        if not any(
            item.get("model") == "res.currency"
            and item.get("record_id") == company_currency_id
            for item in result["dependencies"]
        ):
            result["dependencies"].append(
                self.snapshot(
                    "res.currency", company_currency, company
                )
            )
            result["dependencies"].sort(
                key=lambda item: (item["model"], item["record_id"])
            )
        for line in p["lines"]:
            account = self.record(
                "account.account", line["account_id"], company
            )
            if str(getattr(account, "account_type", "")) in {
                "asset_receivable",
                "liability_payable",
                "off_balance",
            }:
                raise OdooWriteHandlerError(
                    "manual journal entry cannot use a receivable, payable, "
                    "or off-balance account"
                )
            self.assert_currency_precision(
                line["amount"],
                company_currency,
                "manual journal entry company amount",
            )
            self.assert_currency_precision(
                line["amount_currency"],
                transaction_currency,
                "manual journal entry transaction amount",
            )
        document_binding = self.document_binding("journal_entry", p)
        business_binding = self.business_binding("journal_entry", p)
        for field, binding, label in (
            (
                "odoo_cli_v3_document_binding",
                document_binding,
                "approved journal entry content",
            ),
            (
                "odoo_cli_v3_business_binding",
                business_binding,
                "journal and reference business key",
            ),
        ):
            if self.search_records(
                "account.move",
                [
                    ("company_id", "=", company.id),
                    ("move_type", "=", "entry"),
                    (field, "=", binding),
                ],
                company,
                limit=1,
            ):
                raise OdooWriteHandlerError(
                    f"manual journal entry {label} already exists"
                )
        result["checks"].extend(
            [
                "draft_only",
                "effective_odoo_lock_dates_open",
                "restricted_accounts_absent",
                "currency_precision_matches",
                "journal_entry_content_binding_unique",
                "journal_entry_business_binding_unique",
            ]
        )
        return result

    @staticmethod
    def journal_line_values(lines: list[dict[str, Any]]) -> list[tuple[int, int, dict[str, Any]]]:
        result = []
        for line in lines:
            amount = float(_decimal(line["amount"], "amount"))
            values = {
                "name": line["name"],
                "odoo_cli_v3_line_reference": line["line_reference"],
                "account_id": line["account_id"],
                "debit": amount if line["side"] == "debit" else 0.0,
                "credit": amount if line["side"] == "credit" else 0.0,
                "currency_id": line["currency_id"],
                "amount_currency": float(_decimal(line["amount_currency"], "amount_currency")),
                "tax_ids": [(6, 0, list(line["tax_ids"]))],
            }
            if line["partner_id"] is not None:
                values["partner_id"] = line["partner_id"]
            result.append((0, 0, values))
        return result

    @staticmethod
    def document_binding(kind: str, parameters: Mapping[str, Any]) -> str:
        if kind == "customer_invoice":
            return customer_invoice_document_binding(parameters)
        if kind == "vendor_bill":
            return vendor_bill_document_binding(parameters)
        if kind == "journal_entry":
            normalized = {
                "company_id": parameters["company_id"],
                "journal_id": parameters["journal_id"],
                "posting_date": parameters["posting_date"],
                "currency_id": parameters["currency_id"],
                "reference": parameters["reference"],
                "reason": parameters["reason"],
                "posting_mode": "draft",
                "lines": sorted(
                    (
                        {
                            "line_reference": line["line_reference"],
                            "account_id": line["account_id"],
                            "partner_id": line["partner_id"],
                            "currency_id": line["currency_id"],
                            "name": line["name"],
                            "side": line["side"],
                            "amount": _canonical_decimal(
                                line["amount"], "amount"
                            ),
                            "amount_currency": _canonical_decimal(
                                line["amount_currency"],
                                "amount_currency",
                            ),
                            "tax_ids": sorted(line["tax_ids"]),
                        }
                        for line in parameters["lines"]
                    ),
                    key=lambda item: item["line_reference"],
                ),
            }
            return _digest(
                {
                    "capability_kind": kind,
                    "parameters": normalized,
                }
            )
        return _digest(
            {
                "capability_kind": kind,
                "parameters": {
                    key: parameters[key]
                    for key in sorted(parameters)
                    if key != "idempotency_key"
                },
            }
        )

    @staticmethod
    def business_binding(kind: str, parameters: Mapping[str, Any]) -> str:
        if kind == "customer_invoice":
            return customer_invoice_business_binding(parameters)
        elif kind == "vendor_bill":
            return vendor_bill_business_binding(parameters)
        elif kind == "refund":
            identity = {
                "origin_move_id": parameters["origin_move_id"],
                "refund_mode": parameters["refund_mode"],
                "line_references": sorted(
                    line["line_reference"] for line in parameters["lines"]
                ),
            }
        elif kind in {"accrual", "accrual_scheduled_reversal"}:
            identity = {"reference": parameters["reference"]}
        elif kind == "journal_entry":
            identity = {
                "journal_id": parameters["journal_id"],
                "reference": parameters["reference"],
            }
        else:
            raise OdooWriteHandlerError("unsupported business binding kind")
        return _digest({"business_kind": kind, "identity": identity})

    def journal_entry_parameters_from_graph(
        self,
        move: Any,
        lines: list[Any],
        company: Any,
    ) -> dict[str, Any]:
        normalized_lines: list[dict[str, Any]] = []
        seen_references: set[str] = set()
        for line in lines:
            reference = str(
                getattr(line, "odoo_cli_v3_line_reference", "") or ""
            )
            if not reference or reference in seen_references:
                raise OdooWriteHandlerError(
                    "manual journal entry line reference is missing or duplicated"
                )
            seen_references.add(reference)
            debit = _decimal(getattr(line, "debit", None), "debit")
            credit = _decimal(getattr(line, "credit", None), "credit")
            if debit > 0 and credit == 0:
                side = "debit"
                amount = debit
            elif credit > 0 and debit == 0:
                side = "credit"
                amount = credit
            else:
                raise OdooWriteHandlerError(
                    "manual journal entry line side is ambiguous"
                )
            normalized_lines.append(
                {
                    "line_reference": reference,
                    "account_id": _record_id(line.account_id),
                    "partner_id": _record_id(
                        getattr(line, "partner_id", None)
                    ),
                    "currency_id": _record_id(line.currency_id),
                    "name": str(getattr(line, "name", "") or ""),
                    "side": side,
                    "amount": _canonical_decimal(amount, "amount"),
                    "amount_currency": _canonical_decimal(
                        getattr(line, "amount_currency", None),
                        "amount_currency",
                    ),
                    "tax_ids": _ids(getattr(line, "tax_ids", [])),
                }
            )
        parameters = {
            "company_id": company.id,
            "journal_id": _record_id(move.journal_id),
            "posting_date": str(move.date),
            "currency_id": _record_id(move.currency_id),
            "reference": str(move.ref or ""),
            "reason": str(
                getattr(move, "odoo_cli_v3_reason", "") or ""
            ),
            "posting_mode": "draft",
            "lines": normalized_lines,
        }
        if (
            parameters["journal_id"] is None
            or parameters["currency_id"] is None
            or not parameters["reference"]
            or not parameters["reason"]
            or any(
                line["account_id"] is None
                or line["currency_id"] is None
                or not line["name"]
                for line in normalized_lines
            )
        ):
            raise OdooWriteHandlerError(
                "manual journal entry graph cannot reproduce its immutable binding"
            )
        return parameters

    def execute_journal_entry_create(self, p, company, checked):
        journal = self.check_journal(p, company, {"general"})
        self.assert_effective_open_date(
            company,
            p["posting_date"],
            "posting_date",
            journal=journal,
            taxes=False,
        )
        values = {
            "move_type": "entry",
            "company_id": p["company_id"],
            "journal_id": p["journal_id"],
            "date": p["posting_date"],
            "ref": p["reference"],
            "odoo_cli_v3_reason": p["reason"],
            "odoo_cli_v3_document_binding": self.document_binding(
                "journal_entry", p
            ),
            "odoo_cli_v3_business_binding": self.business_binding(
                "journal_entry", p
            ),
            "line_ids": self.journal_line_values(p["lines"]),
        }
        move = self.create_model(
            "account.move",
            company,
            context={
                "tracking_disable": True,
                "mail_notrack": True,
            },
        ).create(values)
        self.require_created(move, "account.move", company)
        if str(getattr(move, "state", "")) != "draft":
            raise OdooWriteHandlerError(
                "manual journal entry was not created in draft state"
        )
        records = self.move_records(move, company)
        self.verify_journal_entry_create(p, company, records)
        self.assert_effective_open_date(
            company,
            p["posting_date"],
            "posting_date",
            journal=journal,
            taxes=False,
        )
        return records, _recovery(
            "manual_escalation",
            "manual_review_pristine_journal_entry",
            [{"model": "account.move", "record_id": move.id}],
        )

    def execute_journal_entry(self, p, company, *, accrual: bool):
        kind = "accrual" if accrual else "period_adjustment"
        values = {
            "move_type": "entry", "company_id": p["company_id"],
            "journal_id": p["journal_id"], "date": p["posting_date"],
            "ref": p["reference"], "line_ids": self.journal_line_values(p["lines"]),
            "odoo_cli_v3_document_binding": self.document_binding(kind, p),
        }
        if accrual:
            values["odoo_cli_v3_business_binding"] = self.business_binding(
                "accrual", p
            )
        if "period_end_date" in p:
            values["odoo_cli_v3_period_end_date"] = p["period_end_date"]
            values["odoo_cli_v3_reason"] = p["reason"]
        move = self.create_model("account.move", company).create(values)
        self.require_created(move, "account.move", company)
        if p["posting_mode"] == "post":
            move.action_post()
        records = self.move_records(move, company)
        if accrual and p["posting_mode"] == "post":
            wizard = self.create_model(
                "account.move.reversal", company,
                context={"active_model": "account.move", "active_ids": [move.id]},
            ).create({
                "date": p["reversal_date"], "journal_id": p["journal_id"],
                "reason": f"Scheduled reversal: {p['reference']}",
            })
            scheduled = self.record_from_action(
                "account.move", wizard.reverse_moves(is_modify=False), company
            )
            scheduled.write(
                {
                    "odoo_cli_v3_document_binding": self.document_binding(
                        "accrual_scheduled_reversal", p
                    ),
                    "odoo_cli_v3_business_binding": self.business_binding(
                        "accrual_scheduled_reversal", p
                    ),
                }
            )
            records.extend(self.move_records(scheduled, company))
        records = self.unique_records(records)
        recovery = self.available_recovery(
            (
                "acct.accrual.create.v1"
                if accrual
                else "acct.period.adjustment_create.v1"
            ),
            (
                "cancel_scheduled_and_reverse_accrual_origin_v1"
                if accrual
                else (
                    "cancel_draft_period_adjustment_v1"
                    if p["posting_mode"] == "draft"
                    else "reverse_posted_period_adjustment_v1"
                )
            ),
            records,
            action_keys={
                (model_name, record.id)
                for model_name, record in records
                if model_name == "account.move"
            },
        )
        return records, recovery

    def execute_accrual(self, p, company, checked):
        return self.execute_journal_entry(p, company, accrual=True)

    def execute_adjustment(self, p, company, checked):
        return self.execute_journal_entry(p, company, accrual=False)

    def verify_journal_entry(self, p, company, records):
        move = self.only_record(records, "account.move")
        if move.move_type != "entry" or _record_id(move.journal_id) != p["journal_id"]:
            raise OdooWriteHandlerError("journal entry type or journal differs")
        expected = "posted" if p["posting_mode"] == "post" else "draft"
        if move.state != expected:
            raise OdooWriteHandlerError("journal entry state differs")
        if (
            str(getattr(move.journal_id, "type", "")) != "general"
            or getattr(move.journal_id, "active", True) is False
            or _record_id(move.currency_id) != p["currency_id"]
        ):
            raise OdooWriteHandlerError("journal entry journal or currency differs")
        if str(move.date) != p["posting_date"] or str(move.ref or "") != p["reference"]:
            raise OdooWriteHandlerError("journal entry date or reference differs")
        if "period_end_date" in p and (
            str(getattr(move, "odoo_cli_v3_period_end_date", "") or "")
            != p["period_end_date"]
            or str(getattr(move, "odoo_cli_v3_reason", "") or "")
            != p["reason"]
        ):
            raise OdooWriteHandlerError(
                "period adjustment end date or reason differs"
            )
        move_lines = [
            self.record("account.move.line", line_id, company)
            for line_id in _ids(move.line_ids)
        ]
        debit = sum(_decimal(line.debit, "debit") for line in move_lines)
        credit = sum(_decimal(line.credit, "credit") for line in move_lines)
        if debit != credit:
            raise OdooWriteHandlerError("read-back journal entry is not balanced")
        unused = list(move_lines)
        for approved in p["lines"]:
            approved_amount = _decimal(approved["amount"], "amount")
            matches = [
                line for line in unused
                if str(line.name) == approved["name"]
                and str(getattr(line, "odoo_cli_v3_line_reference", "") or "")
                == approved["line_reference"]
                and _record_id(line.account_id) == approved["account_id"]
                and _record_id(getattr(line, "partner_id", None)) == approved["partner_id"]
                and _record_id(line.currency_id) == approved["currency_id"]
                and _decimal(line.debit, "debit") == (
                    approved_amount if approved["side"] == "debit" else Decimal("0")
                )
                and _decimal(line.credit, "credit") == (
                    approved_amount if approved["side"] == "credit" else Decimal("0")
                )
                and _decimal(line.amount_currency, "amount_currency")
                == _decimal(approved["amount_currency"], "amount_currency")
                and _ids(line.tax_ids) == sorted(approved["tax_ids"])
            ]
            if len(matches) != 1:
                raise OdooWriteHandlerError("read-back approved journal line differs or is ambiguous")
            unused.remove(matches[0])
        if any(_record_id(getattr(line, "tax_line_id", None)) is None for line in unused):
            raise OdooWriteHandlerError(
                "read-back journal entry has an unexpected non-tax line"
            )
        if unused:
            raise OdooWriteHandlerError("read-back journal entry has unexpected tax lines")
        self.assert_move_balanced(move, company)
        self.assert_exact_move_graph(records, [move], company)
        return [
            "entry_exists", "journal_matches", "state_matches", "date_matches",
            "reference_matches", "period_metadata_matches",
            "line_references_match", "approved_lines_match",
            "tax_graph_absent", "debit_credit_balanced", "record_graph_exact",
        ]

    def verify_accrual(self, p, company, records):
        if p["posting_mode"] == "draft":
            raise OdooWriteHandlerError("draft accrual is not an executable V3 mode")
        moves = [record for model, record in records if model == "account.move"]
        if len(moves) != 2:
            raise OdooWriteHandlerError("posted accrual has no unique scheduled reversal receipt")
        reversal_candidates = [
            move for move in moves
            if _record_id(getattr(move, "reversed_entry_id", None)) in {item.id for item in moves}
        ]
        if len(reversal_candidates) != 1:
            raise OdooWriteHandlerError("scheduled accrual reversal link is ambiguous")
        reversal = reversal_candidates[0]
        origin = next(move for move in moves if move.id != reversal.id)
        origin_records = [
            (model_name, record)
            for model_name, record in records
            if model_name == "account.move" and record.id == origin.id
            or model_name == "account.move.line"
            and _record_id(getattr(record, "move_id", None)) == origin.id
        ]
        checks = self.verify_journal_entry(p, company, origin_records)
        if _record_id(reversal.reversed_entry_id) != origin.id:
            raise OdooWriteHandlerError("scheduled accrual reversal origin differs")
        if reversal.id not in _ids(getattr(origin, "reversal_move_ids", [])):
            raise OdooWriteHandlerError("scheduled accrual reverse link differs")
        if str(reversal.date) != p["reversal_date"]:
            raise OdooWriteHandlerError("scheduled accrual reversal date differs")
        if (
            reversal.move_type != "entry"
            or _record_id(reversal.journal_id) != p["journal_id"]
            or _record_id(reversal.currency_id) != p["currency_id"]
            or str(getattr(reversal.journal_id, "type", "")) != "general"
            or getattr(reversal.journal_id, "active", True) is False
        ):
            raise OdooWriteHandlerError(
                "scheduled accrual reversal type, journal, or currency differs"
            )
        if _as_date(p["reversal_date"], "reversal_date") > self.context.today:
            if reversal.state != "draft" or reversal.auto_post != "at_date":
                raise OdooWriteHandlerError("future accrual reversal is not scheduled for auto-post")
        elif reversal.state != "posted":
            raise OdooWriteHandlerError("current accrual reversal is not posted")
        expected_origin_binding = self.document_binding("accrual", p)
        expected_reversal_binding = self.document_binding(
            "accrual_scheduled_reversal", p
        )
        expected_origin_business_binding = self.business_binding("accrual", p)
        expected_reversal_business_binding = self.business_binding(
            "accrual_scheduled_reversal", p
        )
        if (
            str(getattr(origin, "odoo_cli_v3_document_binding", "") or "")
            != expected_origin_binding
            or str(getattr(reversal, "odoo_cli_v3_document_binding", "") or "")
            != expected_reversal_binding
        ):
            raise OdooWriteHandlerError("accrual document binding differs")
        if (
            str(getattr(origin, "odoo_cli_v3_business_binding", "") or "")
            != expected_origin_business_binding
            or str(
                getattr(reversal, "odoo_cli_v3_business_binding", "") or ""
            )
            != expected_reversal_business_binding
        ):
            raise OdooWriteHandlerError("accrual business binding differs")
        self.assert_linewise_reversal(origin, reversal, company)
        self.assert_move_balanced(reversal, company)
        self.assert_exact_move_graph(records, [origin, reversal], company)
        return [
            *checks, "scheduled_reversal_exists",
            "scheduled_reversal_link_matches", "scheduled_reversal_date_matches",
            "scheduled_reversal_lines_exact", "scheduled_reversal_balanced",
            "document_bindings_match", "business_bindings_match",
            "record_graph_exact",
        ]

    def verify_adjustment(self, p, company, records):
        checks = self.verify_journal_entry(p, company, records)
        move = self.only_record(records, "account.move")
        if (
            str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
            != self.document_binding("period_adjustment", p)
        ):
            raise OdooWriteHandlerError("period adjustment document binding differs")
        return [*checks, "document_binding_matches"]

    def verify_journal_entry_create(self, p, company, records):
        checks = self.verify_journal_entry(p, company, records)
        move = self.only_record(records, "account.move")
        if (
            p["posting_mode"] != "draft"
            or str(getattr(move, "name", "") or "") not in {"", "/"}
            or getattr(move, "posted_before", None) is not False
            or str(getattr(move, "auto_post", "")) != "no"
            or str(getattr(move, "odoo_cli_v3_reason", "") or "")
            != p["reason"]
            or str(
                getattr(move, "odoo_cli_v3_document_binding", "") or ""
            )
            != self.document_binding("journal_entry", p)
            or str(
                getattr(move, "odoo_cli_v3_business_binding", "") or ""
            )
            != self.business_binding("journal_entry", p)
        ):
            raise OdooWriteHandlerError(
                "manual journal entry immutable metadata differs"
            )
        for _model_name, record in records:
            if (
                _model_name == "account.move.line"
                and (
                    _record_id(getattr(record, "tax_line_id", None))
                    is not None
                    or _ids(getattr(record, "tax_ids", []))
                    or _ids(getattr(record, "tax_tag_ids", []))
                    or getattr(record, "analytic_distribution", False)
                    not in (False, None, {})
                    or _ids(getattr(record, "analytic_line_ids", []))
                )
            ):
                raise OdooWriteHandlerError(
                    "manual journal entry generated an unapproved tax or analytic graph"
                )
        return [
            *checks,
            "draft_sequence_absent",
            "never_posted",
            "reason_matches",
            "document_binding_matches",
            "business_binding_matches",
            "tax_and_analytic_graph_absent",
        ]

    def precheck_deferred(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        source = self.record("account.move.line", p["source_move_line_id"], company, write=True)
        move = self.record("account.move", _record_id(source.move_id), company, write=True)
        expected_move_type = "in_invoice" if p["deferred_type"] == "expense" else "out_invoice"
        if move.state != "draft" or move.move_type != expected_move_type:
            raise OdooWriteHandlerError("deferred source must be a compatible draft invoice or bill")
        move_lines = self.checked_move_lines(move, company, write=True)
        if source.id not in _ids(getattr(move, "invoice_line_ids", [])):
            raise OdooWriteHandlerError("deferred source is not an invoice line")
        if source.deferred_start_date or source.deferred_end_date:
            raise OdooWriteHandlerError("deferred source already has schedule dates")
        if any(
            line.id != source.id
            and (
                getattr(line, "deferred_start_date", None)
                or getattr(line, "deferred_end_date", None)
            )
            for line in move_lines
        ):
            raise OdooWriteHandlerError(
                "another source line already has deferred dates"
            )
        if _ids(getattr(move, "deferred_move_ids", [])):
            raise OdooWriteHandlerError("deferred source already has generated entries")
        source_account = self.check_account(_record_id(source.account_id), company)
        expected_account_types = (
            {"expense", "expense_depreciation", "expense_direct_cost"}
            if p["deferred_type"] == "expense" else {"income", "income_other"}
        )
        if str(source_account.account_type) not in expected_account_types:
            raise OdooWriteHandlerError("source account is incompatible with deferred type")
        method_field = f"generate_deferred_{p['deferred_type']}_entries_method"
        amount_method_field = f"deferred_{p['deferred_type']}_amount_computation_method"
        account_field = f"deferred_{p['deferred_type']}_account_id"
        journal_field = f"deferred_{p['deferred_type']}_journal_id"
        if getattr(company, method_field) != p["expected_generation_method"]:
            raise OdooWriteHandlerError("company deferred generation method is not on_validation")
        if getattr(company, amount_method_field) != p["amount_computation_method"]:
            raise OdooWriteHandlerError("company deferred amount method differs")
        if _record_id(getattr(company, account_field)) != p["expected_deferred_account_id"]:
            raise OdooWriteHandlerError("company deferred account differs")
        if _record_id(getattr(company, journal_field)) != p["expected_deferred_journal_id"]:
            raise OdooWriteHandlerError("company deferred journal differs")
        deferred_account = self.check_account(
            p["expected_deferred_account_id"], company
        )
        required_deferred_type = (
            "asset_current" if p["deferred_type"] == "expense"
            else "liability_current"
        )
        if str(deferred_account.account_type) != required_deferred_type:
            raise OdooWriteHandlerError("deferred account type is incompatible")
        if deferred_account.id == source_account.id:
            raise OdooWriteHandlerError("source and deferred accounts must differ")
        deferred_journal = self.record("account.journal", p["expected_deferred_journal_id"], company)
        if deferred_journal.type != "general" or getattr(deferred_journal, "active", True) is False:
            raise OdooWriteHandlerError("deferred journal is not active and general")
        currency = self.assert_currency(p["currency_id"], company)
        if _record_id(move.currency_id) != p["currency_id"]:
            raise OdooWriteHandlerError("deferred source currency differs")
        source_amount = (
            abs(source.balance)
            if p["currency_id"] == _record_id(company.currency_id)
            else abs(source.amount_currency)
        )
        self.assert_amount(source_amount, p["total_amount"], currency, "deferred total")
        self.assert_open_date(company, move.date, "source posting date", journal=move.journal_id)
        start = _as_date(p["schedule_start_date"], "schedule_start_date")
        end = _as_date(p["schedule_end_date"], "schedule_end_date")
        move_date = _as_date(move.date, "source posting date")
        if (
            start.year == end.year
            and start.month == end.month
            and start.year == move_date.year
            and start.month == move_date.month
        ):
            raise OdooWriteHandlerError(
                "deferred schedule would generate no accounting entries"
            )
        return {
            "checks": [
                "source_draft", "source_invoice_line", "source_move_graph",
                "source_unused", "single_deferred_line", "company_method",
                "account", "account_type", "journal", "currency", "amount",
                "schedule_generates_entries",
            ],
            "before": self.snapshots(
                self.unique_records([
                    ("account.move", move),
                    *(("account.move.line", line) for line in move_lines),
                ]),
                company,
            ),
            "dependencies": self.snapshots(
                self.unique_records([
                    ("res.company", company),
                    ("res.currency", currency),
                    ("account.account", source_account),
                    ("account.account", deferred_account),
                    ("account.journal", deferred_journal),
                    (
                        "account.journal",
                        self.record(
                            "account.journal",
                            _record_id(move.journal_id),
                            company,
                        ),
                    ),
                ]),
                company,
                required_fields_by_model={
                    "res.company": _DEFERRED_COMPANY_REQUIRED_FIELDS[
                        p["deferred_type"]
                    ]
                },
            ),
        }

    def execute_deferred(self, p, company, checked):
        source = self.record("account.move.line", p["source_move_line_id"], company, write=True)
        move = source.move_id
        source.write({
            "deferred_start_date": p["schedule_start_date"],
            "deferred_end_date": p["schedule_end_date"],
        })
        move.action_post()
        records: list[tuple[str, Any]] = self.move_records(move, company)
        for deferred in move.deferred_move_ids:
            records.extend(self.move_records(deferred, company))
        records = self.unique_records(records)
        return records, self.available_recovery(
            "acct.deferred.create.v1",
            "reverse_deferred_source_and_schedule_v1",
            records,
            action_keys={("account.move", move.id)},
        )

    def verify_deferred(self, p, company, records, trusted_before=None):
        source = next(
            (
                record for model_name, record in records
                if model_name == "account.move.line"
                and record.id == p["source_move_line_id"]
            ),
            None,
        )
        if source is None:
            raise OdooWriteHandlerError("deferred source line receipt is missing")
        if (
            str(source.deferred_start_date) != p["schedule_start_date"]
            or str(source.deferred_end_date) != p["schedule_end_date"]
        ):
            raise OdooWriteHandlerError("deferred dates differ")
        source_move = next(
            (
                record for model_name, record in records
                if model_name == "account.move"
                and record.id == _record_id(source.move_id)
            ),
            None,
        )
        if source_move is None or source_move.state != "posted":
            raise OdooWriteHandlerError("deferred source move is not posted/readable")
        expected_move_type = (
            "in_invoice" if p["deferred_type"] == "expense" else "out_invoice"
        )
        if (
            source_move.move_type != expected_move_type
            or _record_id(source_move.currency_id) != p["currency_id"]
        ):
            raise OdooWriteHandlerError("deferred source type or currency differs")
        method_field = f"generate_deferred_{p['deferred_type']}_entries_method"
        amount_method_field = (
            f"deferred_{p['deferred_type']}_amount_computation_method"
        )
        account_field = f"deferred_{p['deferred_type']}_account_id"
        journal_field = f"deferred_{p['deferred_type']}_journal_id"
        if (
            getattr(company, method_field) != p["expected_generation_method"]
            or getattr(company, amount_method_field) != p["amount_computation_method"]
            or _record_id(getattr(company, account_field))
            != p["expected_deferred_account_id"]
            or _record_id(getattr(company, journal_field))
            != p["expected_deferred_journal_id"]
        ):
            raise OdooWriteHandlerError("deferred company configuration changed")
        deferred_account = self.check_account(
            p["expected_deferred_account_id"], company
        )
        required_deferred_type = (
            "asset_current" if p["deferred_type"] == "expense"
            else "liability_current"
        )
        if str(deferred_account.account_type) != required_deferred_type:
            raise OdooWriteHandlerError("deferred account type changed")
        deferred_journal = self.record(
            "account.journal", p["expected_deferred_journal_id"], company
        )
        if deferred_journal.type != "general" or getattr(deferred_journal, "active", True) is False:
            raise OdooWriteHandlerError("deferred journal changed")

        source_line_ids = set(_ids(source_move.line_ids))
        received_source_line_ids = {
            record.id
            for model_name, record in records
            if model_name == "account.move.line"
            and _record_id(record.move_id) == source_move.id
        }
        if received_source_line_ids != source_line_ids:
            raise OdooWriteHandlerError("deferred source journal item graph differs")
        for line_id in source_line_ids - {source.id}:
            line = next(
                record for model_name, record in records
                if model_name == "account.move.line" and record.id == line_id
            )
            if getattr(line, "deferred_start_date", None) or getattr(
                line, "deferred_end_date", None
            ):
                raise OdooWriteHandlerError("another source line gained deferred dates")

        generated_ids = set(_ids(source_move.deferred_move_ids))
        if not generated_ids:
            raise OdooWriteHandlerError("deferred source generated no accounting entries")
        generated_moves = {
            record.id: record
            for model_name, record in records
            if model_name == "account.move" and record.id in generated_ids
        }
        if set(generated_moves) != generated_ids:
            raise OdooWriteHandlerError("deferred generated move receipt differs")
        expected_keys = {
            ("account.move", source_move.id),
            *(("account.move.line", line_id) for line_id in source_line_ids),
        }
        source_account_id = _record_id(source.account_id)
        deferred_account_id = p["expected_deferred_account_id"]
        source_balance = _decimal(source.balance, "deferred source balance")
        initial_moves: list[Any] = []
        recognition_source_total = Decimal("0")
        recognition_deferred_total = Decimal("0")
        start = _as_date(p["schedule_start_date"], "schedule_start_date")
        end = _as_date(p["schedule_end_date"], "schedule_end_date")
        for generated in generated_moves.values():
            if (
                _record_id(generated.journal_id) != p["expected_deferred_journal_id"]
                or _ids(generated.deferred_original_move_ids) != [source_move.id]
            ):
                raise OdooWriteHandlerError("deferred generated move linkage differs")
            generated_date = _as_date(generated.date, "generated deferred date")
            if generated_date <= self.context.today:
                if generated.state != "posted":
                    raise OdooWriteHandlerError("current deferred move is not posted")
            elif generated.state != "draft" or str(generated.auto_post) != "at_date":
                raise OdooWriteHandlerError(
                    "future deferred move is not scheduled for posting"
                )
            line_ids = _ids(generated.line_ids)
            expected_keys.add(("account.move", generated.id))
            expected_keys.update(("account.move.line", line_id) for line_id in line_ids)
            generated_lines = [
                record for model_name, record in records
                if model_name == "account.move.line" and record.id in line_ids
            ]
            if len(generated_lines) != len(line_ids):
                raise OdooWriteHandlerError("deferred generated journal items are missing")
            if {
                _record_id(line.account_id) for line in generated_lines
            } != {source_account_id, deferred_account_id}:
                raise OdooWriteHandlerError("deferred generated move uses another account")
            self.assert_move_balanced(generated, company)
            source_net = sum(
                _decimal(line.balance, "deferred source account balance")
                for line in generated_lines
                if _record_id(line.account_id) == source_account_id
            )
            deferred_net = sum(
                _decimal(line.balance, "deferred account balance")
                for line in generated_lines
                if _record_id(line.account_id) == deferred_account_id
            )
            if generated_date == _as_date(source_move.date, "source move date"):
                if source_net == -source_balance and deferred_net == source_balance:
                    initial_moves.append(generated)
                    continue
            if not start <= generated_date <= end:
                raise OdooWriteHandlerError("deferred recognition date is outside schedule")
            recognition_source_total += source_net
            recognition_deferred_total += deferred_net
        if len(initial_moves) != 1:
            raise OdooWriteHandlerError("deferred initial transfer move differs")
        currency = self.assert_currency(p["currency_id"], company)
        source_amount = (
            abs(source.balance)
            if p["currency_id"] == _record_id(company.currency_id)
            else abs(source.amount_currency)
        )
        self.assert_amount(source_amount, p["total_amount"], currency, "deferred total")
        company_currency = self.assert_currency(
            _record_id(company.currency_id), company
        )
        self.assert_amount(
            recognition_source_total,
            source_balance,
            company_currency,
            "deferred recognition total",
        )
        self.assert_amount(
            recognition_deferred_total,
            -source_balance,
            company_currency,
            "deferred account release total",
        )
        actual_keys = [(model_name, record.id) for model_name, record in records]
        if len(actual_keys) != len(set(actual_keys)) or set(actual_keys) != expected_keys:
            raise OdooWriteHandlerError("deferred affected record graph differs")
        if not isinstance(trusted_before, Mapping):
            raise OdooWriteHandlerError("deferred approval snapshots are missing")
        move_before = trusted_before.get(("account.move", source_move.id))
        source_before = trusted_before.get(("account.move.line", source.id))
        expected_before_keys = {
            ("account.move", source_move.id),
            *(("account.move.line", line_id) for line_id in source_line_ids),
        }
        if (
            set(trusted_before) != expected_before_keys
            or not isinstance(move_before, Mapping)
            or not isinstance(source_before, Mapping)
        ):
            raise OdooWriteHandlerError("deferred approval snapshots are missing")
        if str(move_before.get("state")) != "draft":
            raise OdooWriteHandlerError("approved deferred source was not draft")
        if source_before.get("deferred_start_date") or source_before.get(
            "deferred_end_date"
        ):
            raise OdooWriteHandlerError("approved deferred source was already scheduled")
        if str(getattr(source_move, "name", "") or "") in {"", "/"}:
            raise OdooWriteHandlerError("posted deferred source has no receipt number")
        self.assert_approved_record_delta(
            "account.move",
            source_move,
            company,
            move_before,
            allowed_changed_fields=frozenset(
                {"name", "state", "deferred_move_ids"}
            ),
            label="deferred source",
        )
        self.assert_approved_record_delta(
            "account.move.line",
            source,
            company,
            source_before,
            allowed_changed_fields=frozenset(
                {"deferred_start_date", "deferred_end_date"}
            ),
            label="deferred source",
        )
        for line_id in source_line_ids - {source.id}:
            line = next(
                record
                for model_name, record in records
                if model_name == "account.move.line" and record.id == line_id
            )
            self.assert_approved_record_delta(
                "account.move.line",
                line,
                company,
                trusted_before[("account.move.line", line_id)],
                allowed_changed_fields=frozenset(
                    {
                        "amount_residual",
                        "amount_residual_currency",
                        "reconciled",
                        "matching_number",
                    }
                ),
                label="deferred source",
            )
            if (
                bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None)) is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
            ):
                raise OdooWriteHandlerError(
                    "deferred source posting unexpectedly reconciled another line"
                )
        return [
            "source_dates_match", "source_posted", "source_graph_exact",
            "source_posting_allowlist_matches",
            "other_source_lines_unchanged", "company_config_matches",
            "generated_moves_exist", "generated_links_match",
            "generated_states_match", "generated_moves_balanced",
            "generated_accounts_match", "initial_transfer_matches",
            "recognition_total_matches", "record_graph_exact",
        ]

    def _pristine_v3_draft_entry_graph(
        self,
        p: Mapping[str, Any],
        company: Any,
        *,
        require_expected_lines: bool,
    ) -> tuple[Any, list[Any], list[tuple[str, Any]]]:
        if self.context.trusted_recovery_plan is not None:
            raise OdooWriteHandlerError(
                "trusted recovery plan must be null for a normal move operation"
            )
        move = self.record("account.move", p["move_id"], company, write=True)
        line_ids = _ids(getattr(move, "line_ids", []))
        if not line_ids:
            raise OdooWriteHandlerError(
                "manual journal entry requires a complete non-empty line graph"
            )
        if require_expected_lines and line_ids != sorted(p["expected_line_ids"]):
            raise OdooWriteHandlerError(
                "manual journal entry line graph differs from the approved IDs"
            )
        lines = [
            self.record(
                "account.move.line", record_id, company, write=True
            )
            for record_id in line_ids
        ]
        if (
            str(getattr(move, "state", "")) != "draft"
            or str(getattr(move, "move_type", "")) != "entry"
            or getattr(move, "name", None) not in {False, "/"}
            or getattr(move, "posted_before", None) is not False
            or str(getattr(move, "auto_post", "")) != "no"
            or getattr(move, "auto_post_until", None) not in {False, None}
            or getattr(move, "sequence_prefix", None) not in {False, None, ""}
            or getattr(move, "sequence_number", None) not in {False, 0}
            or getattr(move, "secure_sequence_number", 0) not in {False, 0}
            or getattr(move, "made_sequence_gap", None) is not False
            or getattr(move, "checked", None) is not False
            or bool(getattr(move, "inalterable_hash", False))
            or bool(getattr(move, "need_cancel_request", False))
            or bool(getattr(move, "is_manually_modified", False))
            or _record_id(getattr(move, "company_id", None)) != company.id
        ):
            raise OdooWriteHandlerError(
                "move target is not a pristine V3 draft manual journal entry"
            )
        journal = getattr(move, "journal_id", None)
        currency = getattr(move, "currency_id", None)
        if (
            _record_id(journal) is None
            or _record_id(getattr(journal, "company_id", None)) != company.id
            or str(getattr(journal, "type", "")) != "general"
            or getattr(journal, "active", True) is False
            or _record_id(currency) is None
            or getattr(currency, "active", True) is False
        ):
            raise OdooWriteHandlerError(
                "manual journal entry journal or currency is not eligible"
            )
        if (
            str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
            != p["expected_document_binding"]
            or str(getattr(move, "odoo_cli_v3_business_binding", "") or "")
            != p["expected_business_binding"]
            or not self._valid_sha_binding(
                getattr(move, "odoo_cli_v3_document_binding", None)
            )
            or not self._valid_sha_binding(
                getattr(move, "odoo_cli_v3_business_binding", None)
            )
        ):
            raise OdooWriteHandlerError(
                "manual journal entry immutable binding differs"
            )
        graph_parameters = self.journal_entry_parameters_from_graph(
            move, lines, company
        )
        if (
            self.document_binding("journal_entry", graph_parameters)
            != p["expected_document_binding"]
            or self.business_binding("journal_entry", graph_parameters)
            != p["expected_business_binding"]
        ):
            raise OdooWriteHandlerError(
                "manual journal entry content no longer matches its immutable binding"
            )
        move_links = (
            "auto_post_origin_id",
            "origin_payment_id",
            "statement_line_id",
            "statement_id",
            "tax_cash_basis_rec_id",
            "tax_cash_basis_origin_move_id",
            "reversed_entry_id",
            "asset_id",
            "closing_return_id",
            "transfer_model_id",
            "purchase_id",
            "debit_origin_id",
            "invoice_pdf_report_id",
            "invoice_vendor_bill_id",
            "purchase_vendor_bill_id",
            "ubl_cii_xml_id",
            "l10n_es_edi_facturae_xml_id",
            "signing_user",
            "message_main_attachment_id",
        )
        move_link_sets = (
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
            "statement_line_ids",
            "transaction_ids",
            "authorized_transaction_ids",
            "asset_ids",
            "stock_move_ids",
            "landed_costs_ids",
            "debit_note_ids",
            "attachment_ids",
        )
        if any(
            _record_id(getattr(move, field, None)) is not None
            for field in move_links
        ) or any(_ids(getattr(move, field, [])) for field in move_link_sets):
            raise OdooWriteHandlerError(
                "manual journal entry has an external accounting or business link"
            )
        if (
            bool(getattr(move, "signature", False))
            or any(
                _is_present(getattr(move, field, False))
                for field in (
                    "access_token",
                    "invoice_pdf_report_file",
                    "l10n_es_edi_facturae_xml_file",
                    "ubl_cii_xml_file",
                )
            )
            or bool(getattr(move, "is_move_sent", False))
            or getattr(move, "sending_data", False) not in (False, None, {})
            or bool(getattr(move, "is_being_sent", False))
            or getattr(move, "invoice_source_email", False)
            not in (False, None, "")
        ):
            raise OdooWriteHandlerError(
                "manual journal entry has a sending, signature, or attachment effect"
            )
        total_debit = Decimal("0")
        total_credit = Decimal("0")
        for line in lines:
            account = getattr(line, "account_id", None)
            if (
                _record_id(getattr(line, "move_id", None)) != move.id
                or _record_id(getattr(line, "company_id", None)) != company.id
                or str(getattr(line, "parent_state", "")) != "draft"
                or _record_id(account) is None
                or getattr(account, "deprecated", False)
                or str(getattr(account, "account_type", ""))
                in {"asset_receivable", "liability_payable", "off_balance"}
                or bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None))
                is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
                or _record_id(getattr(line, "statement_line_id", None))
                is not None
                or _record_id(getattr(line, "payment_id", None)) is not None
                or _record_id(getattr(line, "statement_id", None)) is not None
                or _record_id(getattr(line, "purchase_order_id", None))
                is not None
                or _record_id(getattr(line, "reconcile_model_id", None))
                is not None
                or _ids(getattr(line, "asset_ids", []))
                or _ids(getattr(line, "sale_line_ids", []))
                or _ids(getattr(line, "distribution_analytic_account_ids", []))
                or _ids(getattr(line, "reconciled_lines_ids", []))
                or _record_id(getattr(line, "purchase_line_id", None))
                is not None
                or _record_id(getattr(line, "expense_id", None)) is not None
                or _record_id(getattr(line, "cogs_origin_id", None)) is not None
                or bool(getattr(line, "is_landed_costs_line", False))
                or _ids(getattr(line, "move_attachment_ids", []))
                or bool(getattr(line, "is_imported", False))
                or bool(getattr(line, "is_downpayment", False))
                or getattr(line, "analytic_distribution", False)
                not in (False, None, {})
                or _ids(getattr(line, "analytic_line_ids", []))
                or _record_id(getattr(line, "tax_line_id", None)) is not None
                or _ids(getattr(line, "tax_ids", []))
                or _ids(getattr(line, "tax_tag_ids", []))
                or getattr(line, "deferred_start_date", None)
                not in {None, False}
                or getattr(line, "deferred_end_date", None)
                not in {None, False}
                or getattr(line, "display_type", None)
                not in {None, False, "product"}
            ):
                raise OdooWriteHandlerError(
                    "manual journal entry line has a restricted account, tax, "
                    "analytic, reconciliation, or external effect"
                )
            debit = _decimal(getattr(line, "debit", None), "debit")
            credit = _decimal(getattr(line, "credit", None), "credit")
            if debit < 0 or credit < 0 or (debit > 0) == (credit > 0):
                raise OdooWriteHandlerError(
                    "manual journal entry line has invalid debit and credit"
                )
            total_debit += debit
            total_credit += credit
        self.assert_amount(
            total_debit, total_credit, currency, "manual entry balance"
        )
        records = [
            ("account.move", move),
            *(("account.move.line", line) for line in lines),
        ]
        return move, lines, records

    def precheck_move_post(
        self, p: dict[str, Any], company: Any
    ) -> dict[str, Any]:
        move, lines, records = self._pristine_v3_draft_entry_graph(
            p, company, require_expected_lines=False
        )
        if (
            p["expected_move_type"] != "entry"
            or _record_id(move.journal_id) != p["expected_journal_id"]
            or _record_id(move.currency_id) != p["expected_currency_id"]
            or str(move.date) != p["expected_posting_date"]
            or str(move.ref or "") != p["expected_reference"]
            or len(lines) != p["expected_line_count"]
        ):
            raise OdooWriteHandlerError(
                "manual journal entry posting identity differs"
            )
        self.assert_effective_open_date(
            company,
            p["expected_posting_date"],
            "expected_posting_date",
            journal=move.journal_id,
            taxes=False,
            move=move,
        )
        total_debit = sum(
            _decimal(line.debit, "debit") for line in lines
        )
        total_credit = sum(
            _decimal(line.credit, "credit") for line in lines
        )
        company_currency = getattr(company, "currency_id", None)
        if _record_id(company_currency) is None:
            raise OdooWriteHandlerError(
                "company currency is not configured"
            )
        self.assert_amount(
            total_debit,
            p["expected_total_debit"],
            company_currency,
            "expected_total_debit",
        )
        self.assert_amount(
            total_credit,
            p["expected_total_credit"],
            company_currency,
            "expected_total_credit",
        )
        return {
            "checks": [
                "pristine_v3_draft_manual_entry",
                "move_identity_matches",
                "document_and_business_bindings_match",
                "posting_date_open",
                "journal_currency_and_totals_match",
                "restricted_accounts_absent",
                "tax_analytic_reconciliation_graph_absent",
                "external_effect_graph_absent",
                "complete_line_graph",
                "write_acl",
            ],
            "before": self.snapshots(records, company),
            "dependencies": self.snapshots(
                self.unique_records(
                    [
                        ("account.journal", move.journal_id),
                        ("res.currency", move.currency_id),
                        ("res.currency", company.currency_id),
                        *(
                            ("account.account", line.account_id)
                            for line in lines
                        ),
                    ]
                ),
                company,
            ),
        }

    def execute_move_post(self, p, company, checked):
        move, _lines, _records = self._pristine_v3_draft_entry_graph(
            p, company, require_expected_lines=False
        )
        self.assert_effective_open_date(
            company,
            p["expected_posting_date"],
            "expected_posting_date",
            journal=move.journal_id,
            taxes=False,
            move=move,
        )
        move.with_context(
            tracking_disable=True,
            mail_notrack=True,
        ).action_post()
        if str(getattr(move, "state", "")) != "posted":
            raise OdooWriteHandlerError(
                "manual journal entry action_post did not post the move"
            )
        records = self.move_records(move, company)
        self.verify_move_post(
            p,
            company,
            records,
            self.trusted_before_values(checked, company),
        )
        return records, _recovery(
            "manual_escalation",
            "manual_review_move_reversal",
            [{"model": "account.move", "record_id": move.id}],
        )

    def verify_move_post(self, p, company, records, before):
        keyed = {
            (model_name, record.id): record
            for model_name, record in records
        }
        move_key = ("account.move", p["move_id"])
        move = keyed.get(move_key)
        if move is None:
            raise OdooWriteHandlerError(
                "posted manual journal entry read-back move is missing"
            )
        line_ids = _ids(getattr(move, "line_ids", []))
        expected_keys = {
            move_key,
            *(("account.move.line", record_id) for record_id in line_ids),
        }
        if (
            len(keyed) != len(records)
            or set(keyed) != expected_keys
            or set(before) != expected_keys
            or len(line_ids) != p["expected_line_count"]
            or str(getattr(move, "state", "")) != "posted"
            or str(getattr(move, "move_type", "")) != "entry"
            or str(getattr(move, "name", "") or "") in {"", "/"}
            or getattr(move, "posted_before", None) is not True
            or _record_id(move.journal_id) != p["expected_journal_id"]
            or _record_id(move.currency_id) != p["expected_currency_id"]
            or str(move.date) != p["expected_posting_date"]
            or str(move.ref or "") != p["expected_reference"]
            or str(
                getattr(move, "odoo_cli_v3_document_binding", "") or ""
            )
            != p["expected_document_binding"]
            or str(
                getattr(move, "odoo_cli_v3_business_binding", "") or ""
            )
            != p["expected_business_binding"]
        ):
            raise OdooWriteHandlerError(
                "posted manual journal entry graph or identity differs"
            )
        move_before = before.get(move_key)
        if (
            not isinstance(move_before, Mapping)
            or move_before.get("state") != "draft"
            or move_before.get("posted_before") is not False
        ):
            raise OdooWriteHandlerError(
                "manual journal entry posting approval snapshot is invalid"
            )
        move_current = self.assert_approved_record_delta(
            "account.move",
            move,
            company,
            move_before,
            allowed_changed_fields=frozenset(
                {
                    "state",
                    "name",
                    "posted_before",
                    "sequence_prefix",
                    "sequence_number",
                    "secure_sequence_number",
                    "inalterable_hash",
                    "checked",
                    "write_uid",
                    "write_date",
                }
            ),
            label="posted manual journal entry",
        )
        transaction_write_date = self.assert_controlled_log_access_delta(
            move_current,
            move_before,
            label="posted manual journal entry",
        )
        for line_id in line_ids:
            line = keyed[("account.move.line", line_id)]
            approved = before.get(("account.move.line", line_id))
            if not isinstance(approved, Mapping):
                raise OdooWriteHandlerError(
                    "manual journal entry line approval snapshot is missing"
                )
            current = self.snapshot(
                "account.move.line", line, company
            )["values"]
            if (
                set(current) != set(approved)
                or classic_read_many2one_id(approved.get("move_id"))
                != move.id
                or classic_read_many2one_id(current.get("move_id"))
                != move.id
                or approved.get("parent_state") != "draft"
                or current.get("parent_state") != "posted"
                or any(
                    current[field] != approved[field]
                    for field in set(current)
                    - {"move_id", "parent_state", "write_uid", "write_date"}
                )
            ):
                raise OdooWriteHandlerError(
                    "manual journal entry line changed outside the posting allowlist"
                )
            if self.assert_controlled_log_access_delta(
                current,
                approved,
                label="posted manual journal entry line",
            ) != transaction_write_date:
                raise OdooWriteHandlerError(
                    "manual journal entry posting audit timestamps differ"
                )
        total_debit = sum(
            _decimal(
                keyed[("account.move.line", line_id)].debit, "debit"
            )
            for line_id in line_ids
        )
        total_credit = sum(
            _decimal(
                keyed[("account.move.line", line_id)].credit, "credit"
            )
            for line_id in line_ids
        )
        company_currency = getattr(company, "currency_id", None)
        if _record_id(company_currency) is None:
            raise OdooWriteHandlerError(
                "company currency is not configured"
            )
        self.assert_amount(
            total_debit,
            p["expected_total_debit"],
            company_currency,
            "expected_total_debit",
        )
        self.assert_amount(
            total_credit,
            p["expected_total_credit"],
            company_currency,
            "expected_total_credit",
        )
        self.assert_move_balanced(move, company)
        return [
            "move_posted",
            "receipt_number_assigned",
            "posted_before_set",
            "identity_and_bindings_preserved",
            "business_lines_unchanged",
            "posting_delta_allowlist_matches",
            "tax_analytic_reconciliation_graph_absent",
            "debit_credit_balanced",
            "record_graph_exact",
        ]

    def precheck_reversal(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        if p.get("posting_mode") != "post":
            raise OdooWriteHandlerError("posting_mode must be post for move reversal")
        move = self.record("account.move", p["move_id"], company, write=True)
        if move.state != "posted" or move.move_type != "entry":
            raise OdooWriteHandlerError(
                "reversal target must be a posted general journal entry"
            )
        lines = self.checked_move_lines(move, company, write=True)
        if not lines:
            raise OdooWriteHandlerError("reversal target has no readable journal items")
        journal = self.check_journal(p, company, {"general"})
        if (
            str(getattr(move.journal_id, "type", "")) != "general"
            or getattr(move.journal_id, "active", True) is False
        ):
            raise OdooWriteHandlerError(
                "reversal target journal must be active and general"
            )
        currency = self.assert_currency(p["currency_id"], company, journal)
        if _record_id(move.currency_id) != p["currency_id"]:
            raise OdooWriteHandlerError("reversal currency differs from target")
        self.assert_amount(
            abs(move.amount_total), p["expected_total_amount"], currency,
            "reversal total",
        )
        unsafe_move_fields = (
            "statement_line_id", "statement_id", "asset_id",
            "deferred_move_ids", "deferred_original_move_ids",
            "tax_cash_basis_rec_id", "tax_cash_basis_origin_move_id",
            "reversed_entry_id", "reversal_move_ids",
        )
        if any(_ids(getattr(move, field, None)) for field in unsafe_move_fields):
            raise OdooWriteHandlerError(
                "reversal target has existing accounting dependencies"
            )
        for line in lines:
            if (
                bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None)) is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
                or _ids(getattr(line, "asset_ids", []))
                or getattr(line, "deferred_start_date", None)
                or getattr(line, "deferred_end_date", None)
            ):
                raise OdooWriteHandlerError(
                    "reversal target has existing accounting dependencies"
                )
        if self.search_records(
            "account.partial.reconcile",
            [("exchange_move_id", "=", move.id)],
            company,
            limit=1,
        ) or self.search_records(
            "account.move",
            [("tax_cash_basis_origin_move_id", "=", move.id)],
            company,
            limit=1,
        ):
            raise OdooWriteHandlerError(
                "reversal target has existing exchange or CABA dependencies"
            )
        has_taxes = any(
            _ids(getattr(line, "tax_ids", []))
            or _record_id(getattr(line, "tax_line_id", None)) is not None
            for line in lines
        )
        self.assert_open_date(
            company, p["reversal_date"], "reversal_date",
            journal=journal, taxes=has_taxes,
        )
        self.create_model("account.move.reversal", company)
        return {
            "checks": [
                "target_posted_entry", "target_total", "journal_active_general",
                "currency", "date", "dependency_graph_absent",
                "origin_graph_snapshotted",
            ],
            "before": self.snapshots(self.move_records(move, company), company),
        }

    def execute_reversal(self, p, company, checked):
        if p.get("posting_mode") != "post":
            raise OdooWriteHandlerError("posting_mode must be post for move reversal")
        origin = self.record("account.move", p["move_id"], company, write=True)
        wizard = self.create_model(
            "account.move.reversal", company,
            context={"active_model": "account.move", "active_ids": [p["move_id"]]},
        ).create({"date": p["reversal_date"], "journal_id": p["journal_id"], "reason": p["reason"]})
        action = wizard.reverse_moves(is_modify=False)
        reversal = self.record_from_action("account.move", action, company, write=True)
        reversal.write(
            {
                "odoo_cli_v3_reason": p["reason"],
                "odoo_cli_v3_document_binding": self.document_binding(
                    "move_reversal", p
                ),
            }
        )
        if reversal.state != "posted":
            reversal.action_post()
        if reversal.state != "posted":
            raise OdooWriteHandlerError("reversal did not reach posted state")
        records = [*self.move_records(origin, company), *self.move_records(reversal, company)]
        records = self.unique_records(records)
        return records, self.available_recovery(
            "acct.move.reverse.v1",
            "reverse_the_reversal_v1",
            records,
            action_keys={("account.move", reversal.id)},
        )

    def verify_reversal(self, p, company, records, trusted_before=None):
        if p.get("posting_mode") != "post":
            raise OdooWriteHandlerError("posting_mode must be post for move reversal")
        moves = [record for model, record in records if model == "account.move"]
        if len(moves) != 2:
            raise OdooWriteHandlerError("reversal record graph has no unique move pair")
        origin_candidates = [move for move in moves if move.id == p["move_id"]]
        if len(origin_candidates) != 1:
            raise OdooWriteHandlerError("approved reversal origin is missing")
        origin = origin_candidates[0]
        reversal = next(move for move in moves if move.id != origin.id)
        self.assert_approved_reversal_origin(
            origin, company, trusted_before
        )
        if (
            origin.state != "posted"
            or origin.move_type != "entry"
            or _record_id(origin.currency_id) != p["currency_id"]
            or str(getattr(origin.journal_id, "type", "")) != "general"
            or getattr(origin.journal_id, "active", True) is False
        ):
            raise OdooWriteHandlerError("reversal origin state or type differs")
        if _record_id(reversal.reversed_entry_id) != p["move_id"]:
            raise OdooWriteHandlerError("reversal origin link differs")
        if reversal.id not in _ids(getattr(origin, "reversal_move_ids", [])):
            raise OdooWriteHandlerError("reversal reverse link differs")
        self.require_links(reversal, p, ("currency_id", "journal_id"))
        if str(reversal.date) != p["reversal_date"]:
            raise OdooWriteHandlerError("reversal date differs")
        if str(getattr(reversal, "odoo_cli_v3_reason", "") or "") != p["reason"]:
            raise OdooWriteHandlerError("reversal reason differs")
        if (
            str(getattr(reversal, "odoo_cli_v3_document_binding", "") or "")
            != self.document_binding("move_reversal", p)
        ):
            raise OdooWriteHandlerError("reversal document binding differs")
        currency = self.assert_currency(p["currency_id"], company)
        self.assert_amount(
            abs(origin.amount_total), p["expected_total_amount"], currency,
            "reversal origin total",
        )
        self.assert_amount(abs(reversal.amount_total), p["expected_total_amount"], currency, "reversal total")
        if reversal.move_type != "entry" or reversal.state != "posted":
            raise OdooWriteHandlerError("reversal state differs")
        if (
            str(getattr(reversal.journal_id, "type", "")) != "general"
            or getattr(reversal.journal_id, "active", True) is False
        ):
            raise OdooWriteHandlerError("reversal journal is not active and general")
        self.assert_linewise_reversal(origin, reversal, company)
        self.assert_move_balanced(origin, company)
        self.assert_move_balanced(reversal, company)
        self.assert_exact_move_graph(records, [origin, reversal], company)
        return [
            "reversal_exists", "origin_link_matches", "date_matches",
            "journal_matches", "currency_matches", "reason_matches",
            "document_binding_matches", "total_matches", "state_matches",
            "origin_approval_matches", "linewise_reversal_exact",
            "move_balanced", "record_graph_exact",
        ]

    def recovery_reference(
        self,
        model_name: str,
        record: Any,
        company: Any,
        *,
        required_fields: frozenset[str],
    ) -> dict[str, Any]:
        raw = self.snapshot(
            model_name,
            record,
            company,
            required_fields=required_fields,
        )
        snapshot = create_record_snapshot(
            model=model_name,
            record_id=raw["record_id"],
            exists=True,
            record_state=raw["state"],
            values=raw["values"],
        )
        return {
            "model": model_name,
            "record_id": raw["record_id"],
            "company_id": company.id,
            "record_state": raw["state"],
            "record_fingerprint": _digest(snapshot),
        }

    @staticmethod
    def _valid_sha_binding(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        )

    def _assert_pristine_draft_document(
        self,
        move: Any,
        lines: list[Any],
        company: Any,
        *,
        expected_state: str,
        vendor: bool,
    ) -> None:
        document_label = "vendor bill" if vendor else "customer invoice"
        if (
            str(getattr(move, "state", "")) != expected_state
            or str(getattr(move, "move_type", ""))
            != ("in_invoice" if vendor else "out_invoice")
            or getattr(move, "name", None) not in {False, "/"}
            or getattr(move, "posted_before", None) is not False
            or str(getattr(move, "auto_post", "")) != "no"
            or getattr(move, "auto_post_until", None) not in {False, None}
            or getattr(move, "sequence_prefix", None) not in {False, None, ""}
            or getattr(move, "sequence_number", None) not in {False, 0}
            or getattr(move, "made_sequence_gap", None) is not False
            or getattr(move, "checked", None) is not False
            or _record_id(getattr(move, "company_id", None)) != company.id
        ):
            raise OdooWriteHandlerError(
                f"recovery target is not a pristine V3 draft {document_label}"
            )
        journal = getattr(move, "journal_id", None)
        if (
            _record_id(journal) is None
            or _record_id(getattr(journal, "company_id", None)) != company.id
            or str(getattr(journal, "type", ""))
            != ("purchase" if vendor else "sale")
            or getattr(journal, "active", True) is False
        ):
            raise OdooWriteHandlerError(
                "recovery target journal is not an active "
                + ("purchase" if vendor else "sales")
                + " journal"
            )
        if not self._valid_sha_binding(
            getattr(move, "odoo_cli_v3_document_binding", None)
        ) or not self._valid_sha_binding(
            getattr(move, "odoo_cli_v3_business_binding", None)
        ):
            raise OdooWriteHandlerError(
                "recovery target lacks immutable V3 document bindings"
            )
        currency = getattr(move, "currency_id", None)
        if _record_id(currency) is None:
            raise OdooWriteHandlerError(
                "recovery target has no auditable currency"
            )
        if str(getattr(move, "payment_state", "")) != "not_paid":
            raise OdooWriteHandlerError(
                "recovery target is not a fully unpaid draft"
            )
        self.assert_amount(
            abs(_decimal(getattr(move, "amount_residual", None), "amount_residual")),
            abs(_decimal(getattr(move, "amount_total", None), "amount_total")),
            currency,
            "recovery target unpaid residual",
        )
        if (
            getattr(move, "secure_sequence_number", 0) not in {False, 0}
            or bool(getattr(move, "inalterable_hash", False))
            or bool(getattr(move, "need_cancel_request", False))
            or bool(getattr(move, "is_manually_modified", False))
        ):
            raise OdooWriteHandlerError(
                "recovery target has prior posting, EDI, or manual mutation evidence"
            )
        singular_links = (
            "auto_post_origin_id",
            "origin_payment_id",
            "statement_line_id",
            "statement_id",
            "tax_cash_basis_rec_id",
            "tax_cash_basis_origin_move_id",
            "reversed_entry_id",
            "asset_id",
            "closing_return_id",
            "transfer_model_id",
            "purchase_id",
            "debit_origin_id",
            "invoice_pdf_report_id",
            "invoice_vendor_bill_id",
            "purchase_vendor_bill_id",
            "ubl_cii_xml_id",
            "l10n_es_edi_facturae_xml_id",
            "signing_user",
            "message_main_attachment_id",
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
            "statement_line_ids",
            "transaction_ids",
            "authorized_transaction_ids",
            "asset_ids",
            "stock_move_ids",
            "landed_costs_ids",
            "debit_note_ids",
            "attachment_ids",
        )
        if any(_record_id(getattr(move, field, None)) is not None for field in singular_links):
            raise OdooWriteHandlerError(
                "recovery target has a payment, statement, tax, reversal, or asset link"
            )
        if any(_ids(getattr(move, field, [])) for field in plural_links):
            raise OdooWriteHandlerError(
                "recovery target has linked payment, tax, EDI, asset, expense, "
                "sale, stock, or landed-cost effects"
            )
        if (
            bool(getattr(move, "signature", False))
            or any(
                _is_present(getattr(move, field, False))
                for field in (
                    "access_token",
                    "invoice_pdf_report_file",
                    "l10n_es_edi_facturae_xml_file",
                    "ubl_cii_xml_file",
                )
            )
            or bool(getattr(move, "is_move_sent", False))
            or getattr(move, "sending_data", False) not in (False, None, {})
            or bool(getattr(move, "is_being_sent", False))
            or getattr(move, "invoice_source_email", False)
            not in (False, None, "")
        ):
            raise OdooWriteHandlerError(
                "recovery target has invoice sending, signature, or attachment link effects"
            )
        if set(_ids(getattr(move, "line_ids", []))) != {line.id for line in lines}:
            raise OdooWriteHandlerError(
                "recovery guard records do not cover the complete line graph"
            )
        for line in lines:
            if (
                _record_id(getattr(line, "move_id", None)) != move.id
                or _record_id(getattr(line, "company_id", None)) != company.id
                or str(getattr(line, "parent_state", "")) != expected_state
                or bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None)) is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
                or _record_id(getattr(line, "statement_line_id", None)) is not None
                or _record_id(getattr(line, "payment_id", None)) is not None
                or _record_id(getattr(line, "statement_id", None)) is not None
                or _record_id(getattr(line, "purchase_order_id", None)) is not None
                or _record_id(getattr(line, "reconcile_model_id", None)) is not None
                or _ids(getattr(line, "asset_ids", []))
                or _ids(getattr(line, "sale_line_ids", []))
                or _ids(getattr(line, "distribution_analytic_account_ids", []))
                or _ids(getattr(line, "reconciled_lines_ids", []))
                or _ids(
                    getattr(
                        line,
                        "reconciled_lines_excluding_exchange_diff_ids",
                        [],
                    )
                )
                or _record_id(getattr(line, "purchase_line_id", None)) is not None
                or _record_id(getattr(line, "expense_id", None)) is not None
                or _record_id(getattr(line, "cogs_origin_id", None)) is not None
                or bool(getattr(line, "is_landed_costs_line", False))
                or _ids(getattr(line, "move_attachment_ids", []))
                or bool(getattr(line, "is_imported", False))
                or bool(getattr(line, "is_downpayment", False))
                or getattr(line, "analytic_distribution", False)
                not in (False, None, {})
                or _ids(getattr(line, "analytic_line_ids", []))
                or getattr(line, "deferred_start_date", None) not in {None, False}
                or getattr(line, "deferred_end_date", None) not in {None, False}
                or str(getattr(line, "display_type", "")) == "cogs"
            ):
                raise OdooWriteHandlerError(
                    "recovery line graph has reconciliation or external business effects"
                )

    def _draft_cancel_graph(
        self,
        parameters: Mapping[str, Any],
        company: Any,
    ) -> tuple[Any, list[Any], list[tuple[str, Any]], bool]:
        if self.context.trusted_recovery_plan is not None:
            raise OdooWriteHandlerError(
                "trusted recovery plan must be null for draft cancellation"
            )
        expected_move_type = parameters["expected_move_type"]
        vendor = expected_move_type == "in_invoice"
        if expected_move_type not in {"out_invoice", "in_invoice"}:
            raise OdooWriteHandlerError(
                "draft cancellation move type is not allowlisted"
            )
        move = self.record(
            "account.move", parameters["move_id"], company, write=True
        )
        line_ids = _ids(getattr(move, "line_ids", []))
        if not line_ids:
            raise OdooWriteHandlerError(
                "draft cancellation requires a complete non-empty line graph"
            )
        lines = [
            self.record("account.move.line", record_id, company)
            for record_id in line_ids
        ]
        self._assert_pristine_draft_document(
            move,
            lines,
            company,
            expected_state="draft",
            vendor=vendor,
        )
        if (
            str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
            != parameters["expected_document_binding"]
            or str(getattr(move, "odoo_cli_v3_business_binding", "") or "")
            != parameters["expected_business_binding"]
        ):
            raise OdooWriteHandlerError(
                "draft cancellation immutable document binding differs"
            )
        records = [
            ("account.move", move),
            *(("account.move.line", line) for line in lines),
        ]
        return move, lines, records, vendor

    def _execute_pristine_draft_cancel(
        self,
        move: Any,
        lines: list[Any],
        records: list[tuple[str, Any]],
        company: Any,
        checked: Mapping[str, Any],
        *,
        vendor: bool,
        completion_method: str,
    ) -> tuple[list[tuple[str, Any]], dict[str, Any]]:
        # Active button_cancel overrides can trigger EDI cron work, unlink
        # COGS, or mutate sale/asset/expense records, so this path avoids that
        # high-level action.  Public ORM write overrides and database
        # automations still require a separate module/automation safety gate
        # plus real-sandbox evidence before this disabled capability is staged.
        result = move.with_context(
            tracking_disable=True,
            skip_account_move_synchronization=True,
            skip_invoice_sync=True,
            skip_is_manually_modified=True,
        ).write({"state": "cancel"})
        if result is not True or str(getattr(move, "state", "")) != "cancel":
            raise OdooWriteHandlerError(
                "draft "
                + ("vendor bill" if vendor else "customer invoice")
                + " cancellation returned no exact result"
            )
        self._assert_recovery_exact_delta(
            move,
            lines,
            company,
            self.trusted_before_values(
                {"before": checked.get("before")}, company
            ),
            vendor=vendor,
        )
        return records, _recovery(
            "not_applicable", completion_method, []
        )

    def precheck_draft_cancel(
        self, p: dict[str, Any], company: Any
    ) -> dict[str, Any]:
        move, _lines, records, vendor = self._draft_cancel_graph(p, company)
        return {
            "checks": [
                "single_pristine_v3_draft_document",
                (
                    "draft_vendor_bill_target"
                    if vendor
                    else "draft_customer_invoice_target"
                ),
                "never_posted_or_hashed",
                "no_payment_reconciliation_or_external_effects",
                "fully_unpaid_residual_matches_total",
                "complete_line_guard_graph",
                "immutable_document_bindings_match",
                "write_acl",
            ],
            "before": self.snapshots(records, company),
            "dependencies": self.snapshots(
                [("account.journal", move.journal_id)], company
            ),
        }

    def execute_draft_cancel(self, p, company, checked):
        move, lines, records, vendor = self._draft_cancel_graph(p, company)
        return self._execute_pristine_draft_cancel(
            move,
            lines,
            records,
            company,
            checked,
            vendor=vendor,
            completion_method="draft_cancel_completed",
        )

    def verify_draft_cancel(self, p, company, records, before):
        if self.context.trusted_recovery_plan is not None:
            raise OdooWriteHandlerError(
                "trusted recovery plan must be null for draft cancellation"
            )
        keyed = {(model_name, record.id): record for model_name, record in records}
        move_key = ("account.move", p["move_id"])
        move = keyed.get(move_key)
        if move is None:
            raise OdooWriteHandlerError(
                "draft cancellation read-back move is missing"
            )
        line_ids = _ids(getattr(move, "line_ids", []))
        expected_keys = {
            move_key,
            *(("account.move.line", record_id) for record_id in line_ids),
        }
        if (
            not line_ids
            or len(keyed) != len(records)
            or set(keyed) != expected_keys
            or set(before) != expected_keys
        ):
            raise OdooWriteHandlerError(
                "draft cancellation read-back graph differs from the approved graph"
            )
        lines = [keyed[("account.move.line", record_id)] for record_id in line_ids]
        vendor = p["expected_move_type"] == "in_invoice"
        if (
            p["expected_move_type"] not in {"out_invoice", "in_invoice"}
            or str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
            != p["expected_document_binding"]
            or str(getattr(move, "odoo_cli_v3_business_binding", "") or "")
            != p["expected_business_binding"]
        ):
            raise OdooWriteHandlerError(
                "draft cancellation immutable document binding differs"
            )
        self._assert_recovery_exact_delta(
            move, lines, company, before, vendor=vendor
        )
        return [
            (
                "draft_vendor_bill_cancelled_exactly"
                if vendor
                else "draft_customer_invoice_cancelled_exactly"
            ),
            "never_posted_evidence_preserved",
            "document_and_business_bindings_preserved",
            "payment_reconciliation_and_external_links_absent",
            "unpaid_residual_and_payment_state_preserved",
            "line_guard_graph_matched_approved_allowed_delta",
            "no_delete_or_button_cancel_path_used",
        ]

    def precheck_draft_cancel_v2(
        self, p: dict[str, Any], company: Any
    ) -> dict[str, Any]:
        if p["expected_move_type"] == "entry":
            move, _lines, records = self._pristine_v3_draft_entry_graph(
                p, company, require_expected_lines=True
            )
            checks = [
                "single_pristine_v3_draft_manual_entry",
                "never_posted_or_hashed",
                "no_tax_analytic_reconciliation_or_external_effects",
                "complete_approved_line_guard_graph",
                "immutable_document_bindings_match",
                "write_acl",
            ]
        else:
            move, lines, records, vendor = self._draft_cancel_graph(
                p, company
            )
            if _ids(move.line_ids) != sorted(p["expected_line_ids"]):
                raise OdooWriteHandlerError(
                    "draft document line graph differs from the approved IDs"
                )
            checks = [
                "single_pristine_v3_draft_document",
                (
                    "draft_vendor_bill_target"
                    if vendor
                    else "draft_customer_invoice_target"
                ),
                "never_posted_or_hashed",
                "no_payment_reconciliation_or_external_effects",
                "fully_unpaid_residual_matches_total",
                "complete_approved_line_guard_graph",
                "immutable_document_bindings_match",
                "write_acl",
            ]
        return {
            "checks": checks,
            "before": self.snapshots(records, company),
            "dependencies": self.snapshots(
                [("account.journal", move.journal_id)], company
            ),
        }

    def _assert_entry_cancel_exact_delta(
        self,
        p: Mapping[str, Any],
        move: Any,
        lines: list[Any],
        company: Any,
        before: Mapping[tuple[str, int], dict[str, Any]],
    ) -> None:
        expected_line_ids = sorted(p["expected_line_ids"])
        if (
            str(getattr(move, "state", "")) != "cancel"
            or str(getattr(move, "move_type", "")) != "entry"
            or _ids(getattr(move, "line_ids", [])) != expected_line_ids
            or getattr(move, "name", None) not in {False, "/"}
            or getattr(move, "posted_before", None) is not False
            or str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
            != p["expected_document_binding"]
            or str(getattr(move, "odoo_cli_v3_business_binding", "") or "")
            != p["expected_business_binding"]
        ):
            raise OdooWriteHandlerError(
                "cancelled manual journal entry graph or binding differs"
            )
        expected_keys = {
            ("account.move", move.id),
            *(("account.move.line", line_id) for line_id in expected_line_ids),
        }
        if set(before) != expected_keys:
            raise OdooWriteHandlerError(
                "manual journal entry cancellation approval graph differs"
            )
        move_before = before.get(("account.move", move.id))
        if (
            not isinstance(move_before, Mapping)
            or move_before.get("state") != "draft"
            or move_before.get("posted_before") is not False
        ):
            raise OdooWriteHandlerError(
                "manual journal entry cancellation before evidence is invalid"
            )
        move_current = self.assert_approved_record_delta(
            "account.move",
            move,
            company,
            move_before,
            allowed_changed_fields=frozenset(
                {"state", "write_uid", "write_date"}
            ),
            label="cancelled manual journal entry",
        )
        transaction_write_date = self.assert_controlled_log_access_delta(
            move_current,
            move_before,
            label="cancelled manual journal entry",
        )
        keyed_lines = {line.id: line for line in lines}
        if set(keyed_lines) != set(expected_line_ids):
            raise OdooWriteHandlerError(
                "cancelled manual journal entry line graph differs"
            )
        for line_id in expected_line_ids:
            line_write_date = self._assert_recovery_line_exact_delta(
                keyed_lines[line_id],
                company,
                before.get(("account.move.line", line_id)),
                move_id=move.id,
            )
            if line_write_date != transaction_write_date:
                raise OdooWriteHandlerError(
                    "manual journal entry cancellation audit timestamps differ"
                )

    def execute_draft_cancel_v2(self, p, company, checked):
        if p["expected_move_type"] != "entry":
            move, lines, records, vendor = self._draft_cancel_graph(
                p, company
            )
            if _ids(move.line_ids) != sorted(p["expected_line_ids"]):
                raise OdooWriteHandlerError(
                    "draft document line graph differs from the approved IDs"
                )
            return self._execute_pristine_draft_cancel(
                move,
                lines,
                records,
                company,
                checked,
                vendor=vendor,
                completion_method="draft_cancel_v2_completed",
            )
        move, lines, records = self._pristine_v3_draft_entry_graph(
            p, company, require_expected_lines=True
        )
        result = move.with_context(
            tracking_disable=True,
            skip_account_move_synchronization=True,
            skip_invoice_sync=True,
            skip_is_manually_modified=True,
        ).write({"state": "cancel"})
        if result is not True or str(getattr(move, "state", "")) != "cancel":
            raise OdooWriteHandlerError(
                "manual journal entry cancellation returned no exact result"
            )
        self._assert_entry_cancel_exact_delta(
            p,
            move,
            lines,
            company,
            self.trusted_before_values(
                {"before": checked.get("before")}, company
            ),
        )
        return records, _recovery(
            "not_applicable", "draft_cancel_v2_completed", []
        )

    def verify_draft_cancel_v2(self, p, company, records, before):
        if p["expected_move_type"] != "entry":
            checks = self.verify_draft_cancel(
                p, company, records, before
            )
            move = self.only_record(records, "account.move")
            if _ids(move.line_ids) != sorted(p["expected_line_ids"]):
                raise OdooWriteHandlerError(
                    "cancelled draft document line graph differs"
                )
            return [*checks, "approved_line_ids_preserved"]
        keyed = {
            (model_name, record.id): record
            for model_name, record in records
        }
        move = keyed.get(("account.move", p["move_id"]))
        if move is None or len(keyed) != len(records):
            raise OdooWriteHandlerError(
                "cancelled manual journal entry result graph is invalid"
            )
        lines = [
            keyed.get(("account.move.line", line_id))
            for line_id in sorted(p["expected_line_ids"])
        ]
        if any(line is None for line in lines):
            raise OdooWriteHandlerError(
                "cancelled manual journal entry line graph is incomplete"
            )
        self._assert_entry_cancel_exact_delta(
            p, move, lines, company, before
        )
        return [
            "draft_manual_journal_entry_cancelled_exactly",
            "never_posted_evidence_preserved",
            "document_and_business_bindings_preserved",
            "approved_line_ids_preserved",
            "tax_analytic_reconciliation_and_external_links_absent",
            "line_guard_graph_matched_approved_allowed_delta",
            "no_delete_or_button_cancel_path_used",
        ]

    def _draft_document_recovery_graph(
        self,
        plan: Mapping[str, Any],
        company: Any,
    ) -> tuple[Any, list[Any], list[tuple[str, Any]], bool]:
        contract = (plan["method"], plan["oracle_id"])
        if contract == (
            DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
            DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE,
        ):
            vendor = False
        elif contract == (
            DRAFT_VENDOR_BILL_RECOVERY_METHOD,
            DRAFT_VENDOR_BILL_RECOVERY_ORACLE,
        ):
            vendor = True
        else:
            raise OdooWriteHandlerError(
                "recovery method is not allowlisted for this environment"
            )
        if (
            self.context.environment
            not in RECOVERY_ACTION_CONTRACTS[plan["method"]].allowed_environments
        ):
            raise OdooWriteHandlerError(
                "recovery method is not allowlisted for this environment"
            )
        actions = plan["action_targets"]
        guards = plan["guard_records"]
        if (
            len(actions) != 1
            or actions[0]["model"] != "account.move"
            or not guards
            or any(
                guard["model"] != "account.move.line"
                or guard["expected_outcome"] != "survive_allowed_delta"
                for guard in guards
            )
        ):
            raise OdooWriteHandlerError(
                "recovery plan does not contain the exact invoice action/guard graph"
            )
        self._assert_draft_recovery_module_graph_binding(plan, company)
        move = self.record(
            "account.move", actions[0]["record_id"], company, write=True
        )
        lines = [
            self.record("account.move.line", guard["record_id"], company)
            for guard in guards
        ]
        self._assert_pristine_draft_document(
            move,
            lines,
            company,
            expected_state="draft",
            vendor=vendor,
        )
        action_required = {
            "name", "state", "move_type", "company_id", "journal_id",
            "currency_id", "partner_id", "date", "invoice_date",
            "invoice_date_due", "invoice_line_ids",
            "invoice_payment_term_id", "ref", "line_ids",
            "auto_post", "auto_post_until", "posted_before",
            "sequence_prefix", "sequence_number", "secure_sequence_number",
            "made_sequence_gap", "inalterable_hash", "checked",
            "need_cancel_request", "auto_post_origin_id",
            "origin_payment_id", "payment_ids",
            "matched_payment_ids", "reconciled_payment_ids",
            "statement_line_id", "statement_line_ids", "statement_id",
            "tax_cash_basis_rec_id", "tax_cash_basis_origin_move_id",
            "tax_cash_basis_created_move_ids", "reversed_entry_id",
            "reversal_move_ids", "is_manually_modified",
            "adjusting_entry_origin_move_ids",
            "adjusting_entries_move_ids", "exchange_diff_partial_ids",
            "closing_return_id", "transfer_model_id", "transaction_ids",
            "authorized_transaction_ids", "purchase_id", "asset_ids",
            "asset_id", "deferred_move_ids", "deferred_original_move_ids",
            "edi_document_ids", "expense_ids", "pos_order_ids",
            "stock_move_ids", "landed_costs_ids",
            "debit_note_ids", "debit_origin_id",
            "invoice_pdf_report_id", "invoice_vendor_bill_id",
            "purchase_vendor_bill_id", "ubl_cii_xml_id",
            "l10n_es_edi_facturae_xml_id", "signature", "signing_user",
            "invoice_pdf_report_file", "ubl_cii_xml_file",
            "l10n_es_edi_facturae_xml_file",
            "is_move_sent", "sending_data", "is_being_sent",
            "invoice_source_email", "attachment_ids",
            "message_main_attachment_id", "audit_trail_message_ids",
            "activity_ids", "message_follower_ids", "message_ids",
            "rating_ids", "website_message_ids", "access_token",
            "fiscal_position_id", "invoice_cash_rounding_id",
            "invoice_incoterm_id", "incoterm_location", "partner_shipping_id",
            "partner_bank_id", "preferred_payment_method_line_id",
            "l10n_latam_document_type_id", "invoice_origin", "narration",
            "quick_edit_total_amount", "always_tax_exigible", "is_storno",
            "asset_value_change", "campaign_id", "medium_id", "source_id",
            "team_id", "delivery_date", "fapiao", "invoice_currency_rate",
            "invoice_user_id", "l10n_es_edi_facturae_reason_code",
            "l10n_es_invoicing_period_start_date",
            "l10n_es_invoicing_period_end_date", "l10n_es_is_simplified",
            "l10n_es_payment_means", "payment_reference",
            "payment_state_before_switch", "qr_code_method",
            "taxable_supply_date", "journal_line_ids",
            "asset_depreciation_beginning_date", "asset_number_days",
            "depreciation_value",
            "create_uid", "create_date", "write_uid", "write_date",
            "odoo_cli_v3_document_binding",
            "odoo_cli_v3_business_binding",
        }
        action_reference = self.recovery_reference(
            "account.move",
            move,
            company,
            required_fields=frozenset(action_required),
        )
        if action_reference != actions[0]:
            raise OdooWriteHandlerError(
                "recovery action target fingerprint changed after approval"
            )
        line_required_fields = {
            "move_id", "company_id", "account_id", "currency_id",
            "date_maturity", "matching_number", "name", "partner_id",
            "price_unit", "product_id", "quantity",
            "parent_state",
            "debit", "credit", "balance", "amount_currency",
            "reconciled", "full_reconcile_id", "matched_debit_ids",
            "matched_credit_ids", "tax_ids", "tax_line_id", "tax_tag_ids",
            "tax_repartition_line_id", "group_tax_id",
            "analytic_distribution", "analytic_line_ids",
            "distribution_analytic_account_ids",
            "payment_id", "statement_line_id", "statement_id",
            "purchase_line_id", "purchase_order_id", "sale_line_ids",
            "expense_id", "asset_ids", "reconcile_model_id",
            "reconciled_lines_ids",
            "reconciled_lines_excluding_exchange_diff_ids", "parent_id",
            "cogs_origin_id", "is_landed_costs_line",
            "deferred_start_date", "deferred_end_date",
            "move_attachment_ids", "tax_base_amount", "extra_tax_data",
            "deductible_amount", "is_imported", "is_downpayment", "is_storno",
            "sequence", "product_uom_id", "discount", "discount_date",
            "discount_amount_currency", "discount_balance",
            "l10n_latam_document_type_id",
            "no_followup", "collapse_composition", "collapse_prices",
            "create_uid", "create_date", "write_uid", "write_date",
            "display_type", "odoo_cli_v3_line_reference",
        }
        line_required = frozenset(line_required_fields)
        for line, guard in zip(lines, guards):
            reference = self.recovery_reference(
                "account.move.line",
                line,
                company,
                required_fields=line_required,
            )
            if {
                **reference,
                "expected_outcome": "survive_allowed_delta",
            } != guard:
                raise OdooWriteHandlerError(
                    "recovery guard fingerprint changed after approval"
                )
        records = [("account.move", move), *(
            ("account.move.line", line) for line in lines
        )]
        return move, lines, records, vendor

    def _assert_draft_recovery_module_graph_binding(
        self,
        plan: Mapping[str, Any],
        company: Any,
    ) -> None:
        expected_parameters = {
            "company_id": _record_id(company),
            "origin_operation_id": plan["origin_operation_id"],
            "module_graph_digest": self.context.module_graph.digest,
            "method": plan["method"],
            "action_targets": sorted(
                (
                    {"model": item["model"], "record_id": item["record_id"]}
                    for item in plan["action_targets"]
                ),
                key=lambda item: (item["model"], item["record_id"]),
            ),
            "guard_records": sorted(
                (
                    {"model": item["model"], "record_id": item["record_id"]}
                    for item in plan["guard_records"]
                ),
                key=lambda item: (item["model"], item["record_id"]),
            ),
            "oracle_id": plan["oracle_id"],
        }
        if _digest(expected_parameters) != plan["parameters_digest"]:
            raise OdooWriteHandlerError(
                "recovery origin installed-module graph differs from the current graph"
            )

    @staticmethod
    def _approved_recovery_record_references(
        plan: Mapping[str, Any],
    ) -> dict[tuple[str, int], dict[str, Any]]:
        result: dict[tuple[str, int], dict[str, Any]] = {}
        for role, field in (
            ("action", "action_targets"),
            ("guard", "guard_records"),
        ):
            records = plan.get(field)
            if not isinstance(records, list):
                raise OdooWriteHandlerError(
                    "trusted recovery plan record graph is invalid"
                )
            for raw in records:
                if not isinstance(raw, Mapping):
                    raise OdooWriteHandlerError(
                        "trusted recovery plan record graph is invalid"
                    )
                reference = dict(raw)
                key = (reference.get("model"), reference.get("record_id"))
                if key in result:
                    raise OdooWriteHandlerError(
                        "trusted recovery plan record graph contains a duplicate"
                    )
                result[key] = {**reference, "role": role}
        return result

    def _current_recovery_record_references(
        self,
        plan: Mapping[str, Any],
        company: Any,
        *,
        known_records: list[tuple[str, Any]] | None = None,
    ) -> dict[tuple[str, int], dict[str, Any]]:
        known_by_key = {
            (model_name, _record_id(record)): record
            for model_name, record in (known_records or [])
        }
        result: dict[tuple[str, int], dict[str, Any]] = {}
        for role, field in (
            ("action", "action_targets"),
            ("guard", "guard_records"),
        ):
            for approved in plan[field]:
                key = (approved["model"], approved["record_id"])
                if key in result:
                    raise OdooWriteHandlerError(
                        "current recovery record graph contains a duplicate"
                    )
                record = known_by_key.get(key)
                if record is None:
                    record = self.record(
                        approved["model"],
                        approved["record_id"],
                        company,
                        write=(
                            role == "action"
                            or approved.get("expected_outcome")
                            != "survive_exact"
                        ),
                    )
                reference = self.recovery_reference(
                    approved["model"],
                    record,
                    company,
                    required_fields=frozenset(),
                )
                result[key] = {
                    **reference,
                    "role": role,
                    **(
                        {"expected_outcome": approved["expected_outcome"]}
                        if role == "guard"
                        else {}
                    ),
                }
        if set(known_by_key) - set(result):
            raise OdooWriteHandlerError(
                "current recovery record graph contains an unexpected record"
            )
        return result

    def _recovery_records_by_role(
        self,
        plan: Mapping[str, Any],
        company: Any,
    ) -> tuple[
        list[tuple[str, Any]],
        list[tuple[str, Any]],
        list[tuple[str, Any]],
    ]:
        actions: list[tuple[str, Any]] = []
        guards: list[tuple[str, Any]] = []
        for role, field in (
            ("action", "action_targets"),
            ("guard", "guard_records"),
        ):
            for approved in plan[field]:
                record = self.record(
                    approved["model"],
                    approved["record_id"],
                    company,
                    write=(
                        role == "action"
                        or approved.get("expected_outcome")
                        != "survive_exact"
                    ),
                )
                target = actions if role == "action" else guards
                target.append((approved["model"], record))
        records = self.unique_records([*actions, *guards])
        if len(records) != len(actions) + len(guards):
            raise OdooWriteHandlerError(
                "recovery action and guard record graph overlaps"
            )
        tombstones = self._expected_recovery_tombstones(plan)
        for model_name, record in records:
            if (model_name, _record_id(record)) not in tombstones:
                continue
            record.check_access_rights("unlink")
            record.check_access_rule("unlink")
        return actions, guards, records

    @staticmethod
    def _recovery_guard_outcomes_from_plan(
        plan: Mapping[str, Any],
    ) -> dict[tuple[str, int], str]:
        return {
            (guard["model"], guard["record_id"]): guard["expected_outcome"]
            for guard in plan["guard_records"]
        }

    @classmethod
    def _expected_recovery_tombstones(
        cls,
        plan: Mapping[str, Any],
    ) -> frozenset[tuple[str, int]]:
        method = plan["method"]
        tombstones = {
            identity
            for identity, outcome in cls._recovery_guard_outcomes_from_plan(
                plan
            ).items()
            if outcome == "absent"
        }
        if method == "undo_reconciliation_and_reverse_writeoff_v1":
            tombstones.update(
                (target["model"], target["record_id"])
                for target in plan["action_targets"]
                if target["model"]
                in {"account.partial.reconcile", "account.full.reconcile"}
            )
        return frozenset(tombstones)

    def _precheck_recovery_create_acl(
        self,
        plan: Mapping[str, Any],
        company: Any,
    ) -> None:
        method = plan["method"]
        if method == "post_compensating_bank_statement_v1":
            self.create_model("account.bank.statement", company)
            self.create_model("account.bank.statement.line", company)
            return
        if (
            method
            in {
                "reverse_deferred_source_and_schedule_v1",
                "reverse_depreciation_and_restore_schedule_v1",
                "reverse_posted_customer_invoice_v1",
                "reverse_posted_period_adjustment_v1",
                "reverse_posted_refund_v1",
                "reverse_posted_vendor_bill_v1",
                "reverse_the_reversal_v1",
            }
            or (
                method
                in {
                    "cancel_scheduled_and_reverse_accrual_origin_v1",
                    "undo_reconciliation_and_reverse_writeoff_v1",
                }
                and any(
                    target["model"] == "account.move"
                    for target in plan["action_targets"]
                )
            )
        ):
            self.create_model("account.move.reversal", company)

    def _validate_recovery_execution_guard(
        self,
        p: Mapping[str, Any],
        plan: Mapping[str, Any],
        company: Any,
        current_record_references: Mapping[
            tuple[str, int], Mapping[str, Any]
        ],
    ) -> RecoveryPlanExecutionGuard:
        contract = RECOVERY_ACTION_CONTRACTS.get(plan.get("method"))
        if contract is None:
            raise OdooWriteHandlerError(
                "recovery method is not allowlisted for this environment"
            )
        try:
            return validate_recovery_plan_execution(
                plan,
                origin_capability_id=contract.origin_capability_id,
                origin_operation_id=p["origin_operation_id"],
                expected_plan_digest=p["expected_recovery_plan_digest"],
                environment=self.context.environment,
                company_id=_record_id(company),
                module_graph_digest=self.context.module_graph.digest,
                current_record_references=current_record_references,
            )
        except RecoveryPlanExecutionGuardError as exc:
            if self.context.environment == "production":
                raise OdooWriteHandlerError(
                    "recovery method is not allowlisted for this environment"
                ) from exc
            message = str(exc)
            if "parameters digest" in message:
                raise OdooWriteHandlerError(
                    "recovery origin installed-module graph differs from the current graph"
                ) from exc
            if plan.get("method") in {
                DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
                DRAFT_VENDOR_BILL_RECOVERY_METHOD,
            } and "guard outcome" in message:
                raise OdooWriteHandlerError(
                    "recovery plan does not contain the exact invoice action/guard graph"
                ) from exc
            if "does not match an executable origin contract" in message:
                raise OdooWriteHandlerError(
                    "recovery method is not allowlisted for this environment"
                ) from exc
            raise OdooWriteHandlerError(
                f"recovery plan execution guard rejected the plan: {exc}"
            ) from exc

    def precheck_recovery(self, p: dict[str, Any], company: Any) -> dict[str, Any]:
        plan = self.context.trusted_recovery_plan
        if not isinstance(plan, Mapping):
            raise OdooWriteHandlerError("trusted recovery plan is unavailable")
        try:
            validate_executable_recovery_plan(plan)
        except WriteReceiptError as exc:
            raise OdooWriteHandlerError(
                "trusted recovery plan is not executable"
            ) from exc
        if plan["origin_operation_id"] != p["origin_operation_id"]:
            raise OdooWriteHandlerError("recovery plan origin differs")
        if plan["plan_digest"] != p["expected_recovery_plan_digest"]:
            raise OdooWriteHandlerError("recovery plan digest differs")
        self._validate_recovery_execution_guard(
            p,
            plan,
            company,
            self._approved_recovery_record_references(plan),
        )
        if plan["method"] in {
            DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
            DRAFT_VENDOR_BILL_RECOVERY_METHOD,
        }:
            move, _lines, records, vendor = self._draft_document_recovery_graph(
                plan, company
            )
            current_references = self._current_recovery_record_references(
                plan, company, known_records=records
            )
            self._validate_recovery_execution_guard(
                p, plan, company, current_references
            )
            checks = [
                "receipt_derived_available_v2_plan",
                "nonproduction_test_or_sandbox_recovery",
                "strict_recovery_plan_execution_guard",
                (
                    "single_v3_draft_vendor_bill"
                    if vendor
                    else "single_v3_draft_customer_invoice"
                ),
                "never_posted_or_hashed",
                "no_payment_reconciliation_or_external_effects",
                "complete_line_guard_graph",
                "action_and_guard_fingerprints_match",
                "write_acl",
            ]
            dependencies = self.snapshots(
                [("account.journal", move.journal_id)], company
            )
        else:
            if plan["method"] not in RECOVERY_ACTION_METHODS:
                raise OdooWriteHandlerError(
                    "recovery method has no implemented ORM action"
                )
            _actions, _guards, records = self._recovery_records_by_role(
                plan, company
            )
            current_references = self._current_recovery_record_references(
                plan, company, known_records=records
            )
            self._validate_recovery_execution_guard(
                p, plan, company, current_references
            )
            self._precheck_recovery_create_acl(plan, company)
            checks = [
                "receipt_derived_available_v2_plan",
                "nonproduction_test_or_sandbox_recovery",
                "strict_recovery_plan_execution_guard",
                "complete_action_and_guard_graph",
                "action_and_guard_fingerprints_match",
                "write_and_unlink_acl_for_mutated_graph",
                "required_create_acl",
                "public_orm_recovery_action_registered",
            ]
            dependencies = []
        return {
            "checks": checks,
            "before": self.snapshots(records, company),
            "dependencies": dependencies,
        }

    def execute_recovery(self, p, company, checked):
        plan = self.context.trusted_recovery_plan
        if not isinstance(plan, Mapping):
            raise OdooWriteHandlerError("trusted recovery plan is unavailable")
        if plan["method"] in {
            DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
            DRAFT_VENDOR_BILL_RECOVERY_METHOD,
        }:
            move, lines, records, vendor = self._draft_document_recovery_graph(
                plan, company
            )
            return self._execute_pristine_draft_cancel(
                move,
                lines,
                records,
                company,
                checked,
                vendor=vendor,
                completion_method="recovery_completed",
            )
        if plan["method"] not in RECOVERY_ACTION_METHODS:
            raise OdooWriteHandlerError(
                "recovery method has no implemented ORM action"
            )
        actions, guards, planned_records = self._recovery_records_by_role(
            plan, company
        )
        current_references = self._current_recovery_record_references(
            plan, company, known_records=planned_records
        )
        self._validate_recovery_execution_guard(
            p, plan, company, current_references
        )
        planned_keys = {
            (model_name, _record_id(record))
            for model_name, record in planned_records
        }
        raw_before = checked.get("before")
        before_keys = [
            (item.get("model"), item.get("record_id"))
            for item in raw_before
            if isinstance(item, Mapping)
        ] if isinstance(raw_before, list) else []
        if (
            len(before_keys) != len(set(before_keys))
            or set(before_keys) != planned_keys
        ):
            raise OdooWriteHandlerError(
                "approved recovery before graph differs from the plan"
            )
        try:
            result = execute_recovery_action(
                self,
                plan["method"],
                company=company,
                action_records=actions,
                guard_records=guards,
                guard_outcomes=self._recovery_guard_outcomes_from_plan(plan),
                recovery_date=p["recovery_date"],
                reason=p["reason"],
            )
        except RecoveryActionError as exc:
            raise OdooWriteHandlerError(
                f"recovery ORM action failed closed: {exc}"
            ) from exc
        result_records = list(result.records)
        result_keys = [
            (model_name, _record_id(record))
            for model_name, record in result_records
        ]
        expected_tombstones = self._expected_recovery_tombstones(plan)
        contract = RECOVERY_ACTION_CONTRACTS[plan["method"]]
        if (
            not result.checks
            or len(result.checks) != len(set(result.checks))
            or len(result_keys) != len(set(result_keys))
            or any(record_id is None for _model_name, record_id in result_keys)
            or result.tombstones != expected_tombstones
            or planned_keys - expected_tombstones - set(result_keys)
            or set(result_keys) & expected_tombstones
            or any(
                model_name not in contract.result_models
                for model_name, _record_id_value in result_keys
            )
        ):
            raise OdooWriteHandlerError(
                "recovery ORM result graph differs from its exact contract"
            )
        return (
            result_records,
            _recovery("not_applicable", "recovery_completed", []),
            result.tombstones,
        )

    def _assert_recovery_exact_delta(
        self,
        move: Any,
        lines: list[Any],
        company: Any,
        before: Mapping[tuple[str, int], dict[str, Any]],
        *,
        vendor: bool,
    ) -> None:
        self._assert_pristine_draft_document(
            move,
            lines,
            company,
            expected_state="cancel",
            vendor=vendor,
        )
        move_before = before.get(("account.move", move.id))
        if (
            not isinstance(move_before, Mapping)
            or move_before.get("state") != "draft"
            or move_before.get("posted_before") is not False
        ):
            raise OdooWriteHandlerError(
                "recovery before evidence was not an unposted draft"
            )
        move_current = self.assert_approved_record_delta(
            "account.move",
            move,
            company,
            move_before,
            allowed_changed_fields=frozenset({"state", "write_uid", "write_date"}),
            label=(
                "recovered vendor bill"
                if vendor
                else "recovered customer invoice"
            ),
        )
        transaction_write_date = self.assert_controlled_log_access_delta(
            move_current,
            move_before,
            label=(
                "recovered vendor bill"
                if vendor
                else "recovered customer invoice"
            ),
        )
        for line in lines:
            line_before = before.get(("account.move.line", line.id))
            line_write_date = self._assert_recovery_line_exact_delta(
                line,
                company,
                line_before,
                move_id=move.id,
            )
            if line_write_date != transaction_write_date:
                raise OdooWriteHandlerError(
                    "recovery move and line write_date values differ within the transaction"
                )

    def _assert_recovery_line_exact_delta(
        self,
        line: Any,
        company: Any,
        approved: Mapping[str, Any] | None,
        *,
        move_id: int,
    ) -> datetime:
        if not isinstance(approved, Mapping):
            raise OdooWriteHandlerError(
                "recovery guard line approval snapshot is missing"
            )
        current = self.snapshot("account.move.line", line, company)["values"]
        # move_id's display label is derived from the parent state in Odoo.
        # Only that label may drift; the strict relation ID must stay exact.
        if (
            set(current) != set(approved)
            or classic_read_many2one_id(approved.get("move_id")) != move_id
            or classic_read_many2one_id(current.get("move_id")) != move_id
            or approved.get("parent_state") != "draft"
            or current.get("parent_state") != "cancel"
            or any(
                current[field] != approved[field]
                for field in set(current)
                - {"move_id", "parent_state", "write_uid", "write_date"}
            )
        ):
            raise OdooWriteHandlerError(
                "recovery guard line graph changed outside the approved allowlist"
            )
        return self.assert_controlled_log_access_delta(
            current,
            approved,
            label="recovery guard line",
        )

    def verify_recovery(self, p, company, records, before):
        plan = self.context.trusted_recovery_plan
        if not isinstance(plan, dict):
            raise OdooWriteHandlerError("trusted recovery plan is unavailable")
        self._assert_draft_recovery_module_graph_binding(plan, company)
        expected_tombstones = self._expected_recovery_tombstones(plan)
        try:
            fresh_checks = list(
                verify_recovery_action(
                    self,
                    plan["method"],
                    plan=plan,
                    company=company,
                    records=records,
                    before_values=before,
                    tombstone_keys=expected_tombstones,
                    recovery_date=p["recovery_date"],
                    reason=p["reason"],
                )
            )
        except RecoveryVerificationError as exc:
            raise OdooWriteHandlerError(
                f"fresh recovery verification failed closed: {exc}"
            ) from exc

        specialized_checks: list[str] = []
        if plan["method"] in {
            DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
            DRAFT_VENDOR_BILL_RECOVERY_METHOD,
        }:
            actions = plan["action_targets"]
            guards = plan["guard_records"]
            keyed = {
                (model_name, record.id): record
                for model_name, record in records
            }
            expected_keys = {
                (actions[0]["model"], actions[0]["record_id"]),
                *((guard["model"], guard["record_id"]) for guard in guards),
            }
            if set(keyed) != expected_keys or set(before) != expected_keys:
                raise OdooWriteHandlerError(
                    "recovery read-back graph differs from the approved guard graph"
                )
            move = keyed[("account.move", actions[0]["record_id"])]
            lines = [
                keyed[("account.move.line", guard["record_id"])]
                for guard in guards
            ]
            contract = (plan["method"], plan["oracle_id"])
            vendor = contract == (
                DRAFT_VENDOR_BILL_RECOVERY_METHOD,
                DRAFT_VENDOR_BILL_RECOVERY_ORACLE,
            )
            if not vendor and contract != (
                DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
                DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE,
            ):
                raise OdooWriteHandlerError(
                    "recovery method is not allowlisted for this environment"
                )
            self._assert_recovery_exact_delta(
                move, lines, company, before, vendor=vendor
            )
            specialized_checks = [
                (
                    "draft_vendor_bill_cancelled_exactly"
                    if vendor
                    else "draft_customer_invoice_cancelled_exactly"
                ),
                "never_posted_evidence_preserved",
                "document_and_business_bindings_preserved",
                "payment_reconciliation_and_external_links_absent",
                "line_guard_graph_matched_approved_allowed_delta",
                "no_delete_or_button_cancel_path_used",
            ]
        checks = sorted({*fresh_checks, *specialized_checks})
        if not expected_tombstones:
            return checks
        return checks, expected_tombstones

    def require_created(self, record: Any, model_name: str, company: Any) -> None:
        identifier = _record_id(record)
        if identifier is None:
            raise OdooWriteHandlerError(f"{model_name} create did not return a record")
        record.check_access_rights("read")
        record.check_access_rule("read")
        self.assert_company(record, company, model_name=model_name, shared=False)

    def record_from_action(self, model_name: str, action: Any, company: Any, *, write: bool = False) -> Any:
        if not isinstance(action, Mapping):
            raise OdooWriteHandlerError(f"{model_name} action returned no deterministic record receipt")
        record_id = action.get("res_id")
        if not isinstance(record_id, int) or isinstance(record_id, bool) or record_id <= 0:
            raise OdooWriteHandlerError(f"{model_name} action returned an ambiguous record receipt")
        return self.record(model_name, record_id, company, write=write)

    @staticmethod
    def only_record(records: list[tuple[str, Any]], model_name: str) -> Any:
        matches = [record for model, record in records if model == model_name]
        if len(matches) != 1:
            raise OdooWriteHandlerError(f"expected exactly one {model_name} result")
        return matches[0]

    @staticmethod
    def require_links(record: Any, parameters: Mapping[str, Any], fields: tuple[str, ...]) -> None:
        for field in fields:
            if field not in parameters:
                continue
            if _record_id(getattr(record, field)) != parameters[field]:
                raise OdooWriteHandlerError(f"derived {field} differs from approved input")

    @staticmethod
    def move_recovery(move: Any) -> dict[str, Any]:
        return _recovery(
            "manual_escalation",
            "manual_review_move_recovery",
            [{"model": "account.move", "record_id": move.id}],
        )


def precheck(capability_id: str, parameters: dict[str, Any], context: OdooWriteContext) -> dict[str, Any]:
    return OdooWriteHandlers(context).precheck(capability_id, parameters)


def execute(capability_id: str, parameters: dict[str, Any], context: OdooWriteContext) -> dict[str, Any]:
    return OdooWriteHandlers(context).execute(capability_id, parameters)


def verify(
    capability_id: str,
    parameters: dict[str, Any],
    execution: Mapping[str, Any],
    context: OdooWriteContext,
) -> dict[str, Any]:
    return OdooWriteHandlers(context).verify(capability_id, parameters, execution)

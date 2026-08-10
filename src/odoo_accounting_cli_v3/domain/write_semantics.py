"""Cross-field accounting checks shared by write previews and Odoo handlers."""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any, Callable


class WriteSemanticError(ValueError):
    pass


_UNSIGNED_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
_SIGNED_DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")


def _field(value: dict[str, Any], name: str) -> Any:
    try:
        return value[name]
    except KeyError as exc:
        raise WriteSemanticError(f"{name} is required") from exc


def _positive_id(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WriteSemanticError(f"{field} must be a positive integer")
    return value


def _non_empty_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WriteSemanticError(f"{field} must be non-empty text")
    return value


def _sha256_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise WriteSemanticError(f"{field} must be a SHA-256 digest")
    return value


def _date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        raise WriteSemanticError(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise WriteSemanticError(f"{field} must be an ISO date") from exc


def _decimal(
    value: Any,
    field: str,
    *,
    signed: bool = False,
    positive: bool = False,
) -> Decimal:
    pattern = _SIGNED_DECIMAL if signed else _UNSIGNED_DECIMAL
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise WriteSemanticError(f"{field} must be a canonical decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:  # Defensive; the pattern already excludes it.
        raise WriteSemanticError(f"{field} must be a decimal amount") from exc
    if not parsed.is_finite() or (parsed == 0 and value.startswith("-")):
        raise WriteSemanticError(f"{field} must be a canonical finite decimal")
    if positive and parsed <= 0:
        raise WriteSemanticError(f"{field} must be positive")
    return parsed


def _format(value: Decimal) -> str:
    return format(value, "f")


def _lines(value: Any, field: str = "lines") -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise WriteSemanticError(f"{field} must be an array of objects")
    return value


def _unique_field(lines: list[dict[str, Any]], field: str, label: str) -> None:
    values = [_field(line, field) for line in lines]
    if len(values) != len(set(values)):
        raise WriteSemanticError(f"{label} values must be unique")


def _validate_document(parameters: dict[str, Any], *, vendor: bool) -> dict[str, Any]:
    if _field(parameters, "posting_mode") != "draft":
        raise WriteSemanticError(
            "document creation is draft-only; use the dedicated approved "
            "document-post capability"
        )
    invoice_date = _date(_field(parameters, "invoice_date"), "invoice_date")
    _date(_field(parameters, "accounting_date"), "accounting_date")
    due_date = _date(_field(parameters, "due_date"), "due_date")
    if due_date < invoice_date:
        raise WriteSemanticError("due_date cannot precede invoice_date")
    lines = _lines(_field(parameters, "lines"))
    if not lines:
        raise WriteSemanticError("invoice lines cannot be empty")
    _unique_field(lines, "line_reference", "line_reference")
    subtotal = Decimal("0")
    for index, line in enumerate(lines):
        quantity = _decimal(
            _field(line, "quantity"), f"lines[{index}].quantity", positive=True
        )
        price = _decimal(_field(line, "price_unit"), f"lines[{index}].price_unit")
        subtotal += quantity * price
    if subtotal <= 0:
        raise WriteSemanticError("document must have a positive total effect")
    reference_field = "vendor_reference" if vendor else "reference"
    if not isinstance(_field(parameters, reference_field), str):
        raise WriteSemanticError(f"{reference_field} must be text")
    return {
        "checks": (
            "document_dates_valid",
            "document_lines_unique",
            "document_effect_positive",
        ),
        "computed": {"untaxed_line_subtotal": _format(subtotal)},
    }


def _validate_refund(parameters: dict[str, Any]) -> dict[str, Any]:
    _date(_field(parameters, "refund_date"), "refund_date")
    _decimal(
        _field(parameters, "expected_total_amount"),
        "expected_total_amount",
        positive=True,
    )
    lines = _lines(_field(parameters, "lines"))
    if _field(parameters, "posting_mode") != "draft":
        raise WriteSemanticError(
            "refund creation is draft-only until post-commit partner rank effects are auditable"
        )
    mode = _field(parameters, "refund_mode")
    if mode == "full" and lines:
        raise WriteSemanticError("full refund must not override origin lines")
    if mode == "partial" and not lines:
        raise WriteSemanticError("partial refund requires explicit lines")
    if mode not in {"full", "partial"}:
        raise WriteSemanticError("refund_mode is invalid")
    _unique_field(lines, "line_reference", "line_reference")
    for index, line in enumerate(lines):
        if _field(line, "tax_ids"):
            raise WriteSemanticError(
                "refund creation is taxless in the current verified scope"
            )
        _decimal(_field(line, "quantity"), f"lines[{index}].quantity", positive=True)
        _decimal(_field(line, "price_unit"), f"lines[{index}].price_unit")
    return {
        "checks": (
            "refund_mode_lines_consistent",
            "refund_total_explicit",
            "refund_creation_draft_only",
            "refund_parameters_taxless",
        ),
        "computed": {"refund_line_count": len(lines)},
    }


def _validate_payment(parameters: dict[str, Any]) -> dict[str, Any]:
    target_ids = _field(parameters, "target_move_ids")
    if not isinstance(target_ids, list) or not target_ids:
        raise WriteSemanticError("target_move_ids cannot be empty")
    for item in target_ids:
        _positive_id(item, "target_move_ids")
    if len(target_ids) != len(set(target_ids)):
        raise WriteSemanticError("target_move_ids must be unique")
    _date(_field(parameters, "payment_date"), "payment_date")
    amount = _decimal(_field(parameters, "amount"), "amount", positive=True)
    if _field(parameters, "partner_type") not in {"customer", "supplier"}:
        raise WriteSemanticError("partner_type is invalid")
    if _field(parameters, "direction") not in {"inbound", "outbound"}:
        raise WriteSemanticError("direction is invalid")
    return {
        "checks": ("payment_targets_unique", "payment_amount_positive"),
        "computed": {"payment_amount": _format(amount)},
    }


def _validate_payment_cancel(parameters: dict[str, Any]) -> dict[str, Any]:
    payment_id = _positive_id(_field(parameters, "payment_id"), "payment_id")
    move_id = _positive_id(_field(parameters, "move_id"), "move_id")
    if _field(parameters, "expected_payment_state") != "in_process":
        raise WriteSemanticError(
            "expected_payment_state must be in_process"
        )
    if _field(parameters, "expected_move_state") != "posted":
        raise WriteSemanticError("expected_move_state must be posted")
    payment_date = _date(
        _field(parameters, "expected_payment_date"),
        "expected_payment_date",
    )
    partner_id = _positive_id(
        _field(parameters, "expected_partner_id"), "expected_partner_id"
    )
    partner_type = _field(parameters, "expected_partner_type")
    if partner_type not in {"customer", "supplier"}:
        raise WriteSemanticError("expected_partner_type is invalid")
    direction = _field(parameters, "expected_direction")
    if direction not in {"inbound", "outbound"}:
        raise WriteSemanticError("expected_direction is invalid")
    amount = _decimal(
        _field(parameters, "expected_amount"),
        "expected_amount",
        positive=True,
    )
    currency_id = _positive_id(
        _field(parameters, "expected_currency_id"), "expected_currency_id"
    )
    journal_id = _positive_id(
        _field(parameters, "expected_journal_id"), "expected_journal_id"
    )
    payment_method_line_id = _positive_id(
        _field(parameters, "expected_payment_method_line_id"),
        "expected_payment_method_line_id",
    )
    if _field(parameters, "expected_is_sent") is not True:
        raise WriteSemanticError("expected_is_sent must be true")
    line_ids = _field(parameters, "expected_line_ids")
    if not isinstance(line_ids, list) or len(line_ids) != 2:
        raise WriteSemanticError("expected_line_ids must contain exactly two lines")
    for item in line_ids:
        _positive_id(item, "expected_line_ids")
    if len(line_ids) != len(set(line_ids)):
        raise WriteSemanticError("expected_line_ids must be unique")
    if line_ids != sorted(line_ids):
        raise WriteSemanticError("expected_line_ids must be sorted")
    _non_empty_text(_field(parameters, "reason"), "reason")
    _non_empty_text(_field(parameters, "idempotency_key"), "idempotency_key")
    return {
        "checks": (
            "payment_cancel_target_explicit",
            "payment_cancel_in_process_posted_only",
            "payment_cancel_identity_graph_explicit",
            "payment_cancel_sent_only",
            "payment_cancel_two_line_set_sorted_unique",
            "payment_cancel_amount_positive",
        ),
        "computed": {
            "payment_id": payment_id,
            "move_id": move_id,
            "expected_payment_state": "in_process",
            "expected_move_state": "posted",
            "expected_payment_date": payment_date.isoformat(),
            "expected_partner_id": partner_id,
            "expected_partner_type": partner_type,
            "expected_direction": direction,
            "expected_amount": _format(amount),
            "expected_currency_id": currency_id,
            "expected_journal_id": journal_id,
            "expected_payment_method_line_id": payment_method_line_id,
            "expected_is_sent": True,
            "expected_line_ids": list(line_ids),
            "expected_line_count": 2,
        },
    }


def _validate_bank(parameters: dict[str, Any]) -> dict[str, Any]:
    statement_date = _date(_field(parameters, "statement_date"), "statement_date")
    currency_id = _positive_id(_field(parameters, "currency_id"), "currency_id")
    opening = _decimal(_field(parameters, "opening_balance"), "opening_balance", signed=True)
    closing = _decimal(_field(parameters, "closing_balance"), "closing_balance", signed=True)
    lines = _lines(_field(parameters, "lines"))
    if not lines:
        raise WriteSemanticError("bank statement lines cannot be empty")
    _unique_field(lines, "external_transaction_id", "external transaction ID")
    _unique_field(lines, "source_line_digest", "source line digest")
    movement = Decimal("0")
    for index, line in enumerate(lines):
        transaction_date = _date(
            _field(line, "transaction_date"), f"lines[{index}].transaction_date"
        )
        _date(_field(line, "value_date"), f"lines[{index}].value_date")
        if transaction_date > statement_date:
            raise WriteSemanticError("transaction_date cannot follow statement_date")
        amount = _decimal(_field(line, "amount"), f"lines[{index}].amount", positive=True)
        direction = _field(line, "direction")
        if direction == "credit":
            movement += amount
        elif direction == "debit":
            movement -= amount
        else:
            raise WriteSemanticError("bank line direction is invalid")
        foreign_currency = _field(line, "foreign_currency_id")
        foreign_amount = _field(line, "foreign_amount")
        if (foreign_currency is None) != (foreign_amount is None):
            raise WriteSemanticError(
                "foreign currency and foreign amount must be provided together"
            )
        if foreign_currency is not None:
            _positive_id(foreign_currency, f"lines[{index}].foreign_currency_id")
            if foreign_currency == currency_id:
                raise WriteSemanticError("foreign currency must differ from statement currency")
            parsed_foreign_amount = _decimal(
                foreign_amount,
                f"lines[{index}].foreign_amount",
                signed=True,
                positive=False,
            )
            if parsed_foreign_amount == 0:
                raise WriteSemanticError("foreign amount must be non-zero")
            if (direction == "credit" and parsed_foreign_amount < 0) or (
                direction == "debit" and parsed_foreign_amount > 0
            ):
                raise WriteSemanticError(
                    "foreign amount sign must match the bank line direction"
                )
    expected_closing = opening + movement
    if expected_closing != closing:
        raise WriteSemanticError("closing balance does not match opening balance and lines")
    return {
        "checks": (
            "bank_source_lines_unique",
            "bank_currency_pairs_valid",
            "bank_closing_balance_reconciled",
        ),
        "computed": {
            "movement": _format(movement),
            "calculated_closing_balance": _format(expected_closing),
        },
    }


def _validate_reconciliation(parameters: dict[str, Any]) -> dict[str, Any]:
    line_ids = _field(parameters, "line_ids")
    if not isinstance(line_ids, list) or len(line_ids) < 2:
        raise WriteSemanticError("line_ids must contain at least two lines")
    for item in line_ids:
        _positive_id(item, "line_ids")
    if len(line_ids) != len(set(line_ids)):
        raise WriteSemanticError("line_ids must be unique")
    _date(_field(parameters, "reconciliation_date"), "reconciliation_date")
    amount = _decimal(_field(parameters, "amount"), "amount", positive=True)
    tolerance = _decimal(_field(parameters, "tolerance_amount"), "tolerance_amount")
    if tolerance > amount:
        raise WriteSemanticError("tolerance_amount cannot exceed amount")
    writeoff = (
        _field(parameters, "writeoff_account_id"),
        _field(parameters, "writeoff_journal_id"),
        _field(parameters, "writeoff_label"),
    )
    provided = tuple(value is not None for value in writeoff)
    if any(provided) and not all(provided):
        raise WriteSemanticError("all write-off fields must be provided together")
    if tolerance != 0 or any(provided):
        raise WriteSemanticError(
            "reconciliation write-off is disabled until its Odoo result and "
            "recovery graphs are verified exactly"
        )
    mode = _field(parameters, "mode")
    if mode == "partial" and (tolerance != 0 or any(provided)):
        raise WriteSemanticError("partial reconciliation cannot create a write-off")
    if mode == "full" and tolerance > 0 and not all(provided):
        raise WriteSemanticError("write-off fields are required for a non-zero tolerance")
    if mode == "full" and tolerance == 0 and any(provided):
        raise WriteSemanticError(
            "write-off fields are forbidden for a zero tolerance"
        )
    if mode not in {"full", "partial"}:
        raise WriteSemanticError("reconciliation mode is invalid")
    return {
        "checks": ("reconciliation_lines_unique", "writeoff_policy_valid"),
        "computed": {
            "reconciliation_amount": _format(amount),
            "tolerance_amount": _format(tolerance),
        },
    }


def _validate_asset(parameters: dict[str, Any]) -> dict[str, Any]:
    _date(_field(parameters, "acquisition_date"), "acquisition_date")
    value = _decimal(
        _field(parameters, "acquisition_value"), "acquisition_value", positive=True
    )
    return {
        "checks": ("asset_source_explicit", "asset_value_positive"),
        "computed": {"acquisition_value": _format(value)},
    }


def _validate_depreciation(parameters: dict[str, Any]) -> dict[str, Any]:
    asset_id = _positive_id(_field(parameters, "asset_id"), "asset_id")
    depreciation_move_id = _positive_id(
        _field(parameters, "depreciation_move_id"), "depreciation_move_id"
    )
    _positive_id(_field(parameters, "journal_id"), "journal_id")
    _positive_id(_field(parameters, "currency_id"), "currency_id")
    start = _date(_field(parameters, "period_start"), "period_start")
    end = _date(_field(parameters, "period_end"), "period_end")
    posting = _date(_field(parameters, "posting_date"), "posting_date")
    if end < start:
        raise WriteSemanticError("period_end cannot precede period_start")
    if posting != end:
        raise WriteSemanticError("posting_date must equal period_end")
    amount = _decimal(_field(parameters, "amount"), "amount", positive=True)
    return {
        "checks": (
            "depreciation_asset_explicit",
            "depreciation_move_explicit",
            "depreciation_period_valid",
            "depreciation_amount_positive",
        ),
        "computed": {
            "asset_id": asset_id,
            "depreciation_move_id": depreciation_move_id,
            "depreciation_amount": _format(amount),
        },
    }


def _validate_journal_lines(parameters: dict[str, Any]) -> dict[str, Any]:
    currency_id = _positive_id(_field(parameters, "currency_id"), "currency_id")
    lines = _lines(_field(parameters, "lines"))
    if len(lines) < 2:
        raise WriteSemanticError("journal entry requires at least two lines")
    _unique_field(lines, "line_reference", "line_reference")
    debit = Decimal("0")
    credit = Decimal("0")
    amount_currency = Decimal("0")
    sides: set[str] = set()
    for index, line in enumerate(lines):
        if _positive_id(_field(line, "currency_id"), f"lines[{index}].currency_id") != currency_id:
            raise WriteSemanticError("journal line currency must match transaction currency")
        amount = _decimal(_field(line, "amount"), f"lines[{index}].amount", positive=True)
        transaction_amount = _decimal(
            _field(line, "amount_currency"),
            f"lines[{index}].amount_currency",
            signed=True,
        )
        side = _field(line, "side")
        if side == "debit":
            if transaction_amount <= 0:
                raise WriteSemanticError("debit amount_currency must be positive")
            debit += amount
        elif side == "credit":
            if transaction_amount >= 0:
                raise WriteSemanticError("credit amount_currency must be negative")
            credit += amount
        else:
            raise WriteSemanticError("journal line side is invalid")
        sides.add(side)
        amount_currency += transaction_amount
    if sides != {"debit", "credit"} or debit != credit:
        raise WriteSemanticError("journal entry is not balanced in company currency")
    if amount_currency != 0:
        raise WriteSemanticError("journal entry is not balanced in transaction currency")
    return {
        "checks": (
            "journal_lines_unique",
            "company_currency_balanced",
            "transaction_currency_balanced",
        ),
        "computed": {
            "company_currency_debit": _format(debit),
            "company_currency_credit": _format(credit),
            "transaction_currency_balance": _format(amount_currency),
        },
    }


def _validate_accrual(parameters: dict[str, Any]) -> dict[str, Any]:
    posting = _date(_field(parameters, "posting_date"), "posting_date")
    reversal = _date(_field(parameters, "reversal_date"), "reversal_date")
    if reversal <= posting:
        raise WriteSemanticError("reversal_date must follow posting_date")
    if _field(parameters, "posting_mode") != "post":
        raise WriteSemanticError(
            "posting_mode must be post to create the approved reversal schedule"
        )
    return _validate_journal_lines(parameters)


def _validate_deferred(parameters: dict[str, Any]) -> dict[str, Any]:
    source_move_line_id = _positive_id(
        _field(parameters, "source_move_line_id"), "source_move_line_id"
    )
    deferred_type = _field(parameters, "deferred_type")
    if deferred_type not in {"expense", "revenue"}:
        raise WriteSemanticError("deferred_type is invalid")
    generation_method = _field(parameters, "expected_generation_method")
    if generation_method != "on_validation":
        raise WriteSemanticError(
            "expected_generation_method must be on_validation"
        )
    amount_computation_method = _field(parameters, "amount_computation_method")
    if amount_computation_method not in {"day", "month", "full_months"}:
        raise WriteSemanticError("amount_computation_method is invalid")
    deferred_account_id = _positive_id(
        _field(parameters, "expected_deferred_account_id"),
        "expected_deferred_account_id",
    )
    deferred_journal_id = _positive_id(
        _field(parameters, "expected_deferred_journal_id"),
        "expected_deferred_journal_id",
    )
    _positive_id(_field(parameters, "currency_id"), "currency_id")
    if _field(parameters, "posting_mode") != "post":
        raise WriteSemanticError("posting_mode must be post for deferred generation")
    start = _date(_field(parameters, "schedule_start_date"), "schedule_start_date")
    end = _date(_field(parameters, "schedule_end_date"), "schedule_end_date")
    if end < start:
        raise WriteSemanticError("deferred schedule end cannot precede its start")
    total = _decimal(_field(parameters, "total_amount"), "total_amount", positive=True)
    return {
        "checks": (
            "deferred_source_explicit",
            "deferred_odoo_config_explicit",
            "deferred_on_validation_only",
            "deferred_schedule_valid",
            "deferred_total_positive",
        ),
        "computed": {
            "source_move_line_id": source_move_line_id,
            "deferred_type": deferred_type,
            "expected_generation_method": generation_method,
            "amount_computation_method": amount_computation_method,
            "expected_deferred_account_id": deferred_account_id,
            "expected_deferred_journal_id": deferred_journal_id,
            "deferred_total_amount": _format(total),
        },
    }


def _validate_adjustment(parameters: dict[str, Any]) -> dict[str, Any]:
    posting = _date(_field(parameters, "posting_date"), "posting_date")
    period_end = _date(_field(parameters, "period_end_date"), "period_end_date")
    if posting != period_end:
        raise WriteSemanticError("posting_date must equal period_end_date")
    return _validate_journal_lines(parameters)


def _validate_journal_entry_create(parameters: dict[str, Any]) -> dict[str, Any]:
    journal_id = _positive_id(_field(parameters, "journal_id"), "journal_id")
    posting_date = _date(_field(parameters, "posting_date"), "posting_date")
    if _field(parameters, "posting_mode") != "draft":
        raise WriteSemanticError("posting_mode must be draft for journal entry creation")
    _non_empty_text(_field(parameters, "reference"), "reference")
    _non_empty_text(_field(parameters, "reason"), "reason")
    lines = _lines(_field(parameters, "lines"))
    for index, line in enumerate(lines):
        _positive_id(_field(line, "account_id"), f"lines[{index}].account_id")
        partner_id = _field(line, "partner_id")
        if partner_id is not None:
            _positive_id(partner_id, f"lines[{index}].partner_id")
        if _field(line, "tax_ids") != []:
            raise WriteSemanticError(
                f"lines[{index}].tax_ids must be empty for a manual journal entry"
            )
    journal_result = _validate_journal_lines(parameters)
    return {
        "checks": (
            "journal_entry_draft_only",
            "journal_entry_reference_and_reason_explicit",
            "journal_entry_accounts_and_partners_explicit",
            "journal_entry_tax_free",
            *journal_result["checks"],
        ),
        "computed": {
            "journal_id": journal_id,
            "posting_date": posting_date.isoformat(),
            "posting_mode": "draft",
            **journal_result["computed"],
        },
    }


def _validate_move_post(parameters: dict[str, Any]) -> dict[str, Any]:
    move_id = _positive_id(_field(parameters, "move_id"), "move_id")
    move_type = _field(parameters, "expected_move_type")
    if move_type != "entry":
        raise WriteSemanticError("expected_move_type must be entry")
    document_binding = _sha256_digest(
        _field(parameters, "expected_document_binding"),
        "expected_document_binding",
    )
    business_binding = _sha256_digest(
        _field(parameters, "expected_business_binding"),
        "expected_business_binding",
    )
    journal_id = _positive_id(
        _field(parameters, "expected_journal_id"), "expected_journal_id"
    )
    currency_id = _positive_id(
        _field(parameters, "expected_currency_id"), "expected_currency_id"
    )
    posting_date = _date(
        _field(parameters, "expected_posting_date"), "expected_posting_date"
    )
    reference = _non_empty_text(
        _field(parameters, "expected_reference"), "expected_reference"
    )
    _non_empty_text(_field(parameters, "reason"), "reason")
    debit = _decimal(
        _field(parameters, "expected_total_debit"),
        "expected_total_debit",
        positive=True,
    )
    credit = _decimal(
        _field(parameters, "expected_total_credit"),
        "expected_total_credit",
        positive=True,
    )
    if debit != credit:
        raise WriteSemanticError(
            "expected_total_debit must equal expected_total_credit"
        )
    line_count = _field(parameters, "expected_line_count")
    if (
        isinstance(line_count, bool)
        or not isinstance(line_count, int)
        or not 2 <= line_count <= 250
    ):
        raise WriteSemanticError(
            "expected_line_count must be an integer between 2 and 250"
        )
    return {
        "checks": (
            "move_post_target_is_manual_entry",
            "move_post_bindings_explicit",
            "move_post_graph_expectations_explicit",
            "move_post_totals_balanced",
        ),
        "computed": {
            "move_id": move_id,
            "expected_move_type": move_type,
            "expected_document_binding": document_binding,
            "expected_business_binding": business_binding,
            "expected_journal_id": journal_id,
            "expected_currency_id": currency_id,
            "expected_posting_date": posting_date.isoformat(),
            "expected_reference": reference,
            "expected_total_debit": _format(debit),
            "expected_total_credit": _format(credit),
            "expected_line_count": line_count,
        },
    }


def _validate_reversal(parameters: dict[str, Any]) -> dict[str, Any]:
    _date(_field(parameters, "reversal_date"), "reversal_date")
    if _field(parameters, "posting_mode") != "post":
        raise WriteSemanticError("posting_mode must be post for move reversal")
    total = _decimal(
        _field(parameters, "expected_total_amount"),
        "expected_total_amount",
        positive=True,
    )
    return {
        "checks": (
            "reversal_target_explicit",
            "reversal_total_explicit",
            "reversal_post_only",
        ),
        "computed": {"expected_total_amount": _format(total)},
    }


def _validate_draft_cancel(parameters: dict[str, Any]) -> dict[str, Any]:
    _positive_id(_field(parameters, "move_id"), "move_id")
    move_type = _field(parameters, "expected_move_type")
    if move_type not in {"out_invoice", "in_invoice"}:
        raise WriteSemanticError(
            "expected_move_type must be out_invoice or in_invoice"
        )
    computed: dict[str, str] = {"expected_move_type": move_type}
    for field in (
        "expected_document_binding",
        "expected_document_binding_v2",
        "expected_business_binding",
    ):
        computed[field] = _sha256_digest(_field(parameters, field), field)
    return {
        "checks": (
            "draft_cancel_target_explicit",
            "draft_cancel_move_type_explicit",
            "draft_cancel_document_binding_explicit",
            "draft_cancel_document_binding_v2_explicit",
            "draft_cancel_business_binding_explicit",
        ),
        "computed": computed,
    }


def _validate_draft_cancel_v2(parameters: dict[str, Any]) -> dict[str, Any]:
    move_id = _positive_id(_field(parameters, "move_id"), "move_id")
    move_type = _field(parameters, "expected_move_type")
    if move_type not in {"entry", "out_invoice", "in_invoice"}:
        raise WriteSemanticError(
            "expected_move_type must be entry, out_invoice, or in_invoice"
        )
    document_binding = _sha256_digest(
        _field(parameters, "expected_document_binding"),
        "expected_document_binding",
    )
    raw_document_binding_v2 = _field(
        parameters, "expected_document_binding_v2"
    )
    document_binding_v2 = (
        None
        if move_type == "entry"
        and raw_document_binding_v2 is None
        else _sha256_digest(
            raw_document_binding_v2,
            "expected_document_binding_v2",
        )
    )
    if move_type == "entry" and document_binding_v2 is not None:
        raise WriteSemanticError(
            "expected_document_binding_v2 must be null for entry"
        )
    if move_type != "entry" and document_binding_v2 is None:
        raise WriteSemanticError(
            "expected_document_binding_v2 must be a SHA-256 digest "
            "for invoice or bill"
        )
    business_binding = _sha256_digest(
        _field(parameters, "expected_business_binding"),
        "expected_business_binding",
    )
    line_ids = _field(parameters, "expected_line_ids")
    if not isinstance(line_ids, list) or not 2 <= len(line_ids) <= 1000:
        raise WriteSemanticError(
            "expected_line_ids must contain between 2 and 1000 lines"
        )
    for item in line_ids:
        _positive_id(item, "expected_line_ids")
    if len(line_ids) != len(set(line_ids)):
        raise WriteSemanticError("expected_line_ids must be unique")
    _non_empty_text(_field(parameters, "reason"), "reason")
    return {
        "checks": (
            "draft_cancel_v2_target_explicit",
            "draft_cancel_v2_move_type_supported",
            "draft_cancel_v2_bindings_explicit",
            "draft_cancel_v2_line_set_explicit",
        ),
        "computed": {
            "move_id": move_id,
            "expected_move_type": move_type,
            "expected_document_binding": document_binding,
            "expected_document_binding_v2": document_binding_v2,
            "expected_business_binding": business_binding,
            "expected_line_ids": list(line_ids),
            "expected_line_count": len(line_ids),
        },
    }


def _bounded_sorted_unique_ids(
    parameters: dict[str, Any], field: str
) -> list[int]:
    value = _field(parameters, field)
    if not isinstance(value, list) or not 2 <= len(value) <= 1000:
        raise WriteSemanticError(
            f"{field} must contain between 2 and 1000 lines"
        )
    for item in value:
        _positive_id(item, field)
    if len(value) != len(set(value)):
        raise WriteSemanticError(f"{field} must be unique")
    if value != sorted(value):
        raise WriteSemanticError(f"{field} must be sorted")
    return list(value)


def _validate_document_post(
    parameters: dict[str, Any], *, expected_move_type: str
) -> dict[str, Any]:
    move_id = _positive_id(_field(parameters, "move_id"), "move_id")
    move_type = _field(parameters, "expected_move_type")
    if move_type != expected_move_type:
        raise WriteSemanticError(
            f"expected_move_type must be {expected_move_type}"
        )
    document_binding = _sha256_digest(
        _field(parameters, "expected_document_binding"),
        "expected_document_binding",
    )
    document_binding_v2 = _sha256_digest(
        _field(parameters, "expected_document_binding_v2"),
        "expected_document_binding_v2",
    )
    business_binding = _sha256_digest(
        _field(parameters, "expected_business_binding"),
        "expected_business_binding",
    )
    partner_id = _positive_id(
        _field(parameters, "expected_partner_id"), "expected_partner_id"
    )
    journal_id = _positive_id(
        _field(parameters, "expected_journal_id"), "expected_journal_id"
    )
    currency_id = _positive_id(
        _field(parameters, "expected_currency_id"), "expected_currency_id"
    )
    payment_term_line_id = _positive_id(
        _field(parameters, "expected_payment_term_line_id"),
        "expected_payment_term_line_id",
    )
    payment_term_account_id = _positive_id(
        _field(parameters, "expected_payment_term_account_id"),
        "expected_payment_term_account_id",
    )
    invoice_date = _date(
        _field(parameters, "expected_invoice_date"), "expected_invoice_date"
    )
    accounting_date = _date(
        _field(parameters, "expected_accounting_date"),
        "expected_accounting_date",
    )
    due_date = _date(
        _field(parameters, "expected_due_date"), "expected_due_date"
    )
    if due_date < invoice_date:
        raise WriteSemanticError(
            "expected_due_date cannot precede expected_invoice_date"
        )
    reference = _field(parameters, "expected_reference")
    if not isinstance(reference, str):
        raise WriteSemanticError("expected_reference must be text")
    untaxed = _decimal(
        _field(parameters, "expected_amount_untaxed"),
        "expected_amount_untaxed",
    )
    tax = _decimal(
        _field(parameters, "expected_amount_tax"), "expected_amount_tax"
    )
    if tax != 0:
        raise WriteSemanticError(
            "expected_amount_tax must be zero for the current taxless "
            "document-post scope"
        )
    total = _decimal(
        _field(parameters, "expected_amount_total"),
        "expected_amount_total",
        positive=True,
    )
    residual = _decimal(
        _field(parameters, "expected_amount_residual"),
        "expected_amount_residual",
        positive=True,
    )
    if untaxed + tax != total:
        raise WriteSemanticError(
            "expected_amount_total must equal expected untaxed plus tax"
        )
    if residual != total:
        raise WriteSemanticError(
            "expected_amount_residual must equal expected_amount_total"
        )
    line_ids = _bounded_sorted_unique_ids(parameters, "expected_line_ids")
    if payment_term_line_id not in line_ids:
        raise WriteSemanticError(
            "expected_payment_term_line_id must belong to expected_line_ids"
        )
    _non_empty_text(_field(parameters, "reason"), "reason")
    _non_empty_text(
        _field(parameters, "idempotency_key"), "idempotency_key"
    )
    return {
        "checks": (
            "document_post_type_fixed",
            "document_post_bindings_explicit",
            "document_post_identity_explicit",
            "document_post_dates_valid",
            "document_post_amounts_consistent",
            "document_post_fully_unpaid",
            "document_post_complete_line_set_explicit",
            "document_post_payment_term_line_and_account_explicit",
        ),
        "computed": {
            "move_id": move_id,
            "expected_move_type": move_type,
            "expected_document_binding": document_binding,
            "expected_document_binding_v2": document_binding_v2,
            "expected_business_binding": business_binding,
            "expected_partner_id": partner_id,
            "expected_journal_id": journal_id,
            "expected_currency_id": currency_id,
            "expected_payment_term_line_id": payment_term_line_id,
            "expected_payment_term_account_id": payment_term_account_id,
            "expected_invoice_date": invoice_date.isoformat(),
            "expected_accounting_date": accounting_date.isoformat(),
            "expected_due_date": due_date.isoformat(),
            "expected_reference": reference,
            "expected_amount_untaxed": _format(untaxed),
            "expected_amount_tax": _format(tax),
            "expected_amount_total": _format(total),
            "expected_amount_residual": _format(residual),
            "expected_line_ids": line_ids,
            "expected_line_count": len(line_ids),
        },
    }


def _validate_refund_draft_cancel(
    parameters: dict[str, Any],
) -> dict[str, Any]:
    move_id = _positive_id(_field(parameters, "move_id"), "move_id")
    origin_move_id = _positive_id(
        _field(parameters, "expected_origin_move_id"),
        "expected_origin_move_id",
    )
    if move_id == origin_move_id:
        raise WriteSemanticError(
            "move_id and expected_origin_move_id must differ"
        )
    move_type = _field(parameters, "expected_move_type")
    if move_type not in {"out_refund", "in_refund"}:
        raise WriteSemanticError(
            "expected_move_type must be out_refund or in_refund"
        )
    bindings = {
        field: _sha256_digest(_field(parameters, field), field)
        for field in (
            "expected_document_binding",
            "expected_document_binding_v2",
            "expected_business_binding",
            "expected_origin_document_binding",
            "expected_origin_document_binding_v2",
            "expected_origin_business_binding",
        )
    }
    partner_id = _positive_id(
        _field(parameters, "expected_partner_id"), "expected_partner_id"
    )
    journal_id = _positive_id(
        _field(parameters, "expected_journal_id"), "expected_journal_id"
    )
    currency_id = _positive_id(
        _field(parameters, "expected_currency_id"), "expected_currency_id"
    )
    refund_date = _date(
        _field(parameters, "expected_refund_date"), "expected_refund_date"
    )
    total = _decimal(
        _field(parameters, "expected_total_amount"),
        "expected_total_amount",
        positive=True,
    )
    line_ids = _bounded_sorted_unique_ids(parameters, "expected_line_ids")
    origin_line_ids = _bounded_sorted_unique_ids(
        parameters, "expected_origin_line_ids"
    )
    if set(line_ids) & set(origin_line_ids):
        raise WriteSemanticError(
            "expected_line_ids and expected_origin_line_ids must not overlap"
        )
    _non_empty_text(_field(parameters, "reason"), "reason")
    _non_empty_text(
        _field(parameters, "idempotency_key"), "idempotency_key"
    )
    return {
        "checks": (
            "refund_draft_cancel_type_fixed",
            "refund_draft_cancel_bindings_explicit",
            "refund_draft_cancel_identity_explicit",
            "refund_draft_cancel_total_explicit",
            "refund_draft_cancel_complete_disjoint_graphs_explicit",
        ),
        "computed": {
            "move_id": move_id,
            "expected_origin_move_id": origin_move_id,
            "expected_move_type": move_type,
            **bindings,
            "expected_partner_id": partner_id,
            "expected_journal_id": journal_id,
            "expected_currency_id": currency_id,
            "expected_refund_date": refund_date.isoformat(),
            "expected_total_amount": _format(total),
            "expected_line_ids": line_ids,
            "expected_origin_line_ids": origin_line_ids,
            "expected_line_count": len(line_ids),
            "expected_origin_line_count": len(origin_line_ids),
        },
    }


def _validate_refund_post_reconcile(
    parameters: dict[str, Any],
) -> dict[str, Any]:
    base = _validate_refund_draft_cancel(parameters)
    computed = dict(base["computed"])
    mode = _field(parameters, "expected_source_refund_mode")
    if mode not in {"full", "partial"}:
        raise WriteSemanticError(
            "expected_source_refund_mode must be full or partial"
        )
    commercial_partner_id = _positive_id(
        _field(parameters, "expected_commercial_partner_id"),
        "expected_commercial_partner_id",
    )
    origin_total = _decimal(
        _field(parameters, "expected_origin_total_amount"),
        "expected_origin_total_amount",
        positive=True,
    )
    reconcile_amount = _decimal(
        _field(parameters, "expected_reconcile_amount"),
        "expected_reconcile_amount",
        positive=True,
    )
    total = _decimal(
        _field(parameters, "expected_total_amount"),
        "expected_total_amount",
        positive=True,
    )
    refund_term_line_id = _positive_id(
        _field(parameters, "expected_refund_payment_term_line_id"),
        "expected_refund_payment_term_line_id",
    )
    origin_term_line_id = _positive_id(
        _field(parameters, "expected_origin_payment_term_line_id"),
        "expected_origin_payment_term_line_id",
    )
    if refund_term_line_id not in computed["expected_line_ids"]:
        raise WriteSemanticError(
            "expected_refund_payment_term_line_id must belong to expected_line_ids"
        )
    if origin_term_line_id not in computed["expected_origin_line_ids"]:
        raise WriteSemanticError(
            "expected_origin_payment_term_line_id must belong to "
            "expected_origin_line_ids"
        )
    payment_term_account_id = _positive_id(
        _field(parameters, "expected_payment_term_account_id"),
        "expected_payment_term_account_id",
    )
    outcome = _field(parameters, "expected_reconciliation_outcome")
    refund_payment_state = _field(
        parameters, "expected_refund_payment_state_after"
    )
    origin_payment_state = _field(
        parameters, "expected_origin_payment_state_after"
    )
    refund_residual = _decimal(
        _field(parameters, "expected_refund_residual_after"),
        "expected_refund_residual_after",
    )
    origin_residual = _decimal(
        _field(parameters, "expected_origin_residual_after"),
        "expected_origin_residual_after",
    )
    if refund_payment_state != "paid":
        raise WriteSemanticError(
            "expected_refund_payment_state_after must be paid"
        )
    if refund_residual != 0:
        raise WriteSemanticError(
            "expected_refund_residual_after must be zero"
        )
    if mode == "full":
        if total != origin_total:
            raise WriteSemanticError(
                "full refund expected_total_amount must equal "
                "expected_origin_total_amount"
            )
        if outcome != "full_origin_reversal":
            raise WriteSemanticError(
                "expected_reconciliation_outcome is inconsistent with full refund"
            )
        if origin_payment_state != "reversed":
            raise WriteSemanticError(
                "expected_origin_payment_state_after is inconsistent with full refund"
            )
        expected_origin_residual = Decimal("0")
    else:
        if total >= origin_total:
            raise WriteSemanticError(
                "partial refund expected_total_amount must be less than "
                "expected_origin_total_amount"
            )
        if outcome != "partial_origin_reduction":
            raise WriteSemanticError(
                "expected_reconciliation_outcome is inconsistent with partial refund"
            )
        if origin_payment_state != "partial":
            raise WriteSemanticError(
                "expected_origin_payment_state_after is inconsistent with partial refund"
            )
        expected_origin_residual = origin_total - total
    if reconcile_amount != total:
        raise WriteSemanticError(
            "expected_reconcile_amount must equal expected_total_amount"
        )
    if origin_residual != expected_origin_residual:
        raise WriteSemanticError(
            "expected_origin_residual_after is inconsistent with refund mode"
        )
    computed = {
        **computed,
            "expected_source_refund_mode": mode,
            "expected_commercial_partner_id": commercial_partner_id,
            "expected_origin_total_amount": _format(origin_total),
            "expected_reconcile_amount": _format(reconcile_amount),
            "expected_refund_payment_term_line_id": refund_term_line_id,
            "expected_origin_payment_term_line_id": origin_term_line_id,
            "expected_payment_term_account_id": payment_term_account_id,
            "expected_reconciliation_outcome": outcome,
            "expected_refund_payment_state_after": refund_payment_state,
            "expected_origin_payment_state_after": origin_payment_state,
            "expected_refund_residual_after": _format(refund_residual),
            "expected_origin_residual_after": _format(origin_residual),
    }
    return {
        "checks": (
            *base["checks"],
            "refund_post_reconcile_mode_and_outcome_explicit",
            "refund_post_reconcile_term_lines_and_account_explicit",
            "refund_post_reconcile_residuals_consistent",
        ),
        "computed": computed,
    }


def _validate_recovery(parameters: dict[str, Any]) -> dict[str, Any]:
    _date(_field(parameters, "recovery_date"), "recovery_date")
    digest = _field(parameters, "expected_recovery_plan_digest")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise WriteSemanticError("expected_recovery_plan_digest must be a SHA-256 digest")
    return {
        "checks": ("recovery_plan_digest_explicit", "recovery_action_server_selected"),
        "computed": {"expected_recovery_plan_digest": digest},
    }


def _validate_reconciliation_undo(parameters: dict[str, Any]) -> dict[str, Any]:
    origin_operation_id = _non_empty_text(
        _field(parameters, "origin_operation_id"), "origin_operation_id"
    )
    if re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", origin_operation_id
    ) is None:
        raise WriteSemanticError("origin_operation_id is invalid")
    origin_revision = _field(parameters, "expected_origin_revision")
    if (
        isinstance(origin_revision, bool)
        or not isinstance(origin_revision, int)
        or not 1 <= origin_revision <= 2147483647
    ):
        raise WriteSemanticError(
            "expected_origin_revision must be a positive bounded integer"
        )
    receipt_digest = _sha256_digest(
        _field(parameters, "expected_origin_final_receipt_body_digest"),
        "expected_origin_final_receipt_body_digest",
    )
    plan_digest = _sha256_digest(
        _field(parameters, "expected_recovery_plan_digest"),
        "expected_recovery_plan_digest",
    )
    recovery_date = _date(_field(parameters, "recovery_date"), "recovery_date")
    _non_empty_text(_field(parameters, "reason"), "reason")
    return {
        "checks": (
            "reconciliation_undo_origin_operation_explicit",
            "reconciliation_undo_origin_revision_explicit",
            "reconciliation_undo_final_receipt_digest_explicit",
            "reconciliation_undo_recovery_plan_digest_explicit",
            "reconciliation_undo_requires_completed_verified_finalized_apply_origin",
            "reconciliation_undo_requires_retained_release_with_facade",
            "reconciliation_undo_requires_complete_origin_graph",
        ),
        "computed": {
            "origin_operation_id": origin_operation_id,
            "expected_origin_revision": origin_revision,
            "expected_origin_final_receipt_body_digest": receipt_digest,
            "expected_recovery_plan_digest": plan_digest,
            "recovery_date": recovery_date.isoformat(),
        },
    }


def _validate_bank_statement_compensate(
    parameters: dict[str, Any],
) -> dict[str, Any]:
    origin_operation_id = _non_empty_text(
        _field(parameters, "origin_operation_id"), "origin_operation_id"
    )
    if re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", origin_operation_id
    ) is None:
        raise WriteSemanticError("origin_operation_id is invalid")
    origin_revision = _field(parameters, "expected_origin_revision")
    if (
        isinstance(origin_revision, bool)
        or not isinstance(origin_revision, int)
        or not 1 <= origin_revision <= 2147483647
    ):
        raise WriteSemanticError(
            "expected_origin_revision must be a positive bounded integer"
        )
    receipt_digest = _sha256_digest(
        _field(parameters, "expected_origin_final_receipt_body_digest"),
        "expected_origin_final_receipt_body_digest",
    )
    plan_digest = _sha256_digest(
        _field(parameters, "expected_recovery_plan_digest"),
        "expected_recovery_plan_digest",
    )
    statement_id = _positive_id(
        _field(parameters, "expected_statement_id"), "expected_statement_id"
    )
    journal_id = _positive_id(
        _field(parameters, "expected_journal_id"), "expected_journal_id"
    )
    currency_id = _positive_id(
        _field(parameters, "expected_currency_id"), "expected_currency_id"
    )
    source_digest = _sha256_digest(
        _field(parameters, "expected_source_digest"),
        "expected_source_digest",
    )
    compensation_date = _date(
        _field(parameters, "compensation_date"), "compensation_date"
    )
    _non_empty_text(_field(parameters, "reason"), "reason")
    return {
        "checks": (
            "bank_statement_compensation_origin_operation_explicit",
            "bank_statement_compensation_origin_revision_explicit",
            "bank_statement_compensation_final_receipt_digest_explicit",
            "bank_statement_compensation_recovery_plan_digest_explicit",
            "bank_statement_compensation_business_bindings_explicit",
            "bank_statement_compensation_requires_completed_verified_finalized_import_origin",
            "bank_statement_compensation_requires_exact_retained_release_recovery_plan",
            "bank_statement_compensation_preserves_origin_and_compensates_complete_batch",
            "bank_statement_compensation_rejects_delete_partial_or_reconciled_origin_graph",
        ),
        "computed": {
            "origin_operation_id": origin_operation_id,
            "expected_origin_revision": origin_revision,
            "expected_origin_final_receipt_body_digest": receipt_digest,
            "expected_recovery_plan_digest": plan_digest,
            "expected_statement_id": statement_id,
            "expected_journal_id": journal_id,
            "expected_currency_id": currency_id,
            "expected_source_digest": source_digest,
            "compensation_date": compensation_date.isoformat(),
        },
    }


_VALIDATORS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "acct.invoice.customer_create.v1": lambda value: _validate_document(value, vendor=False),
    "acct.bill.vendor_create.v1": lambda value: _validate_document(value, vendor=True),
    "acct.refund.create.v1": _validate_refund,
    "acct.payment.register.v1": _validate_payment,
    "acct.payment.cancel.v1": _validate_payment_cancel,
    "acct.bank.statement_import.v1": _validate_bank,
    "acct.reconciliation.apply.v1": _validate_reconciliation,
    "acct.asset.create.v1": _validate_asset,
    "acct.depreciation.post.v1": _validate_depreciation,
    "acct.accrual.create.v1": _validate_accrual,
    "acct.deferred.create.v1": _validate_deferred,
    "acct.period.adjustment_create.v1": _validate_adjustment,
    "acct.journal.entry_create.v1": _validate_journal_entry_create,
    "acct.move.post.v1": _validate_move_post,
    "acct.move.reverse.v1": _validate_reversal,
    "acct.move.draft_cancel.v1": _validate_draft_cancel,
    "acct.move.draft_cancel.v2": _validate_draft_cancel_v2,
    "acct.invoice.customer_post.v1": lambda value: _validate_document_post(
        value, expected_move_type="out_invoice"
    ),
    "acct.bill.vendor_post.v1": lambda value: _validate_document_post(
        value, expected_move_type="in_invoice"
    ),
    "acct.refund.post_reconcile_origin.v1": _validate_refund_post_reconcile,
    "acct.refund.draft_cancel.v1": _validate_refund_draft_cancel,
    "acct.recovery.execute.v1": _validate_recovery,
    "acct.reconciliation.undo.v1": _validate_reconciliation_undo,
    "acct.bank.statement_compensate.v1": _validate_bank_statement_compensate,
}


def validate_write_semantics(
    capability_id: str, parameters: dict[str, Any]
) -> dict[str, Any]:
    """Reject cross-field accounting ambiguity after strict schema validation."""

    try:
        validator = _VALIDATORS[capability_id]
    except (KeyError, TypeError) as exc:
        raise WriteSemanticError("unsupported write capability") from exc
    if not isinstance(parameters, dict):
        raise WriteSemanticError("write parameters must be an object")
    company_id = _positive_id(_field(parameters, "company_id"), "company_id")
    result = validator(parameters)
    return {
        "capability_id": capability_id,
        "company_id": company_id,
        "checks": list(result["checks"]),
        "computed": result["computed"],
    }

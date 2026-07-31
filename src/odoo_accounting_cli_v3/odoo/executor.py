"""Trusted Odoo-side read executor and receipt verifier."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Callable, Iterable

from ..domain.ap_open_items import ApOpenItemsBackend, read_ap_open_items
from ..domain.ar_open_items import ArOpenItemsBackend, read_ar_open_items
from ..domain.multicompany_consolidated import (
    MulticompanyConsolidatedBackend,
    read_multicompany_consolidated,
)
from ..domain.multicurrency_balance import (
    MulticurrencyBalanceBackend,
    read_multicurrency_balance,
)
from ..domain.report_read import (
    ReportReadBackend,
    read_financial_report,
    read_tax_report,
)
from ..domain.trial_balance import TrialBalanceBackend, read_trial_balance
from ..document_bindings import (
    DocumentBindingError,
    canonical_document_binding_v2,
    full_refund_line_reference,
)
from ..gateway import RequestContext
from ..partial_refund_lineage import (
    partial_refund_line_from_odoo,
    partial_refund_origin_line_relation_is_exact,
)
from ..receipts import (
    create_read_receipt,
    valid_read_runtime_binding,
    verify_read_receipt,
)
from ..registry import Capability
from .ap_open_items import OdooApOpenItemsBackend
from .ar_open_items import OdooArOpenItemsBackend
from .multicompany_consolidated import OdooMulticompanyConsolidatedBackend
from .multicurrency_balance import OdooMulticurrencyBalanceBackend
from .report_read import OdooReportReadBackend
from .trial_balance import OdooTrialBalanceBackend


SHA256_HEX = frozenset("0123456789abcdef")
_LINE_REFERENCE_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789._:-"
)
_FINANCIAL_REPORT_ROOT_XMLIDS = frozenset(
    {
        "account_reports.balance_sheet",
        "account_reports.cash_flow_report",
        "account_reports.profit_and_loss",
    }
)
_TAX_REPORT_ROOT_XMLIDS = frozenset({"account.generic_tax_report"})
_CAPABILITIES = frozenset(
    {
        "acct.registry.list.v1",
        "acct.gl.trial_balance.v1",
        "acct.ar.open_items.v1",
        "acct.ap.open_items.v1",
        "acct.multicompany.consolidated_read.v1",
        "acct.multicurrency.balance_read.v1",
        "acct.move.document_post_eligibility.v1",
        "acct.move.draft_cancel_eligibility.v1",
        "acct.refund.draft_cancel_eligibility.v1",
        "acct.report.financial_read.v1",
        "acct.tax.report_read.v1",
    }
)


class OdooExecutionError(ValueError):
    pass


def _record_id(value: Any) -> int | None:
    if value in (False, None):
        return None
    raw = getattr(value, "id", value)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return None
    return raw


def _ids(value: Any) -> list[int]:
    if value in (False, None):
        return []
    raw = getattr(value, "ids", None)
    if raw is None:
        raw = value
    if isinstance(raw, (list, tuple, set, frozenset)):
        result = []
        for item in raw:
            record_id = _record_id(item)
            if record_id is not None:
                result.append(record_id)
        return sorted(set(result))
    record_id = _record_id(raw)
    return [] if record_id is None else [record_id]


def _valid_sha_binding(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in SHA256_HEX for character in value)
    )


def _decimal(value: Any) -> Decimal | None:
    if (
        value is False
        or value is None
        or (isinstance(value, str) and value == "")
    ):
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _nonnegative_decimal_text(value: Any) -> str | None:
    decimal = _decimal(value)
    if decimal is None or not decimal.is_finite() or decimal < 0:
        return None
    return format(decimal, "f")


def _canonical_graph_decimal(
    value: Any, *, positive: bool
) -> str | None:
    decimal = _decimal(value)
    if (
        decimal is None
        or not decimal.is_finite()
        or decimal < 0
        or (positive and decimal <= 0)
    ):
        return None
    result = format(decimal, "f")
    if "." in result:
        result = result.rstrip("0").rstrip(".")
    return "0" if result in {"", "-0"} else result


def _date_text(value: Any) -> str | None:
    if value in (False, None, ""):
        return None
    text = str(value)
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        return None
    return text if str(parsed) == text else None


def _graph_invoice_lines(
    records: Any,
    *,
    include_product: bool,
) -> list[dict[str, Any]] | None:
    lines = _iter_records(records)
    if not lines or len(lines) > 32:
        return None
    result: list[dict[str, Any]] = []
    references: set[str] = set()
    for line in lines:
        reference = getattr(
            line, "odoo_cli_v3_line_reference", None
        )
        name = getattr(line, "name", None)
        account_id = _record_id(getattr(line, "account_id", None))
        quantity = _canonical_graph_decimal(
            getattr(line, "quantity", None), positive=True
        )
        price_unit = _canonical_graph_decimal(
            getattr(line, "price_unit", None), positive=False
        )
        tax_ids = _ids(getattr(line, "tax_ids", []))
        if (
            not isinstance(reference, str)
            or not reference
            or not reference[0].isalnum()
            or not all(
                character in _LINE_REFERENCE_CHARACTERS
                for character in reference
            )
            or len(reference) > 128
            or reference in references
            or not isinstance(name, str)
            or not name.strip()
            or len(name) > 256
            or account_id is None
            or quantity is None
            or price_unit is None
            or len(tax_ids) > 8
        ):
            return None
        references.add(reference)
        projected: dict[str, Any] = {
            "line_reference": reference,
            "name": name,
            "account_id": account_id,
            "quantity": quantity,
            "price_unit": price_unit,
            "tax_ids": tax_ids,
            **(
                {
                    "product_id": _record_id(
                        getattr(line, "product_id", None)
                    )
                }
                if include_product
                else {}
            ),
        }
        result.append(projected)
    result.sort(key=lambda item: item["line_reference"])
    return result


def _document_graph_binding_candidate(
    move: Any,
    *,
    company_id: int,
    vendor: bool,
    posting_mode: str,
) -> tuple[str, str, str] | None:
    partner_id = _record_id(getattr(move, "partner_id", None))
    journal_id = _record_id(getattr(move, "journal_id", None))
    currency_id = _record_id(getattr(move, "currency_id", None))
    invoice_date = _date_text(getattr(move, "invoice_date", None))
    accounting_date = _date_text(getattr(move, "date", None))
    due_date = _date_text(getattr(move, "invoice_date_due", None))
    reference = getattr(move, "ref", None)
    lines = _graph_invoice_lines(
        getattr(move, "invoice_line_ids", []),
        include_product=True,
    )
    if (
        partner_id is None
        or journal_id is None
        or currency_id is None
        or invoice_date is None
        or accounting_date is None
        or due_date is None
        or posting_mode not in {"draft", "post"}
        or not isinstance(reference, str)
        or not reference.strip()
        or len(reference) > 256
        or lines is None
    ):
        return None
    parameters = {
        "company_id": company_id,
        "partner_id": partner_id,
        "invoice_date": invoice_date,
        "accounting_date": accounting_date,
        "due_date": due_date,
        "currency_id": currency_id,
        "journal_id": journal_id,
        "posting_mode": posting_mode,
        ("vendor_reference" if vendor else "reference"): reference,
        "lines": lines,
    }
    document_binding = hashlib.sha256(
        json.dumps(
            {
                "capability_kind": (
                    "vendor_bill" if vendor else "customer_invoice"
                ),
                "parameters": {
                    key: parameters[key] for key in sorted(parameters)
                },
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    try:
        document_binding_v2 = canonical_document_binding_v2(
            "vendor_bill" if vendor else "customer_invoice",
            parameters,
        )
    except DocumentBindingError:
        return None
    business_identity = (
        {
            "partner_id": partner_id,
            "vendor_reference": reference,
        }
        if vendor
        else {"reference": reference}
    )
    business_binding = hashlib.sha256(
        json.dumps(
            {
                "business_kind": (
                    "vendor_bill" if vendor else "customer_invoice"
                ),
                "identity": business_identity,
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return (
        document_binding,
        document_binding_v2,
        business_binding,
    )


def _refund_graph_binding_candidates(
    refund: Any,
    *,
    company_id: int,
    origin_move_id: int,
    vendor: bool,
) -> list[tuple[str, str, str, str]]:
    refund_date = _date_text(getattr(refund, "invoice_date", None))
    journal_id = _record_id(getattr(refund, "journal_id", None))
    currency_id = _record_id(getattr(refund, "currency_id", None))
    raw_total = _decimal(getattr(refund, "amount_total", None))
    total = (
        None
        if raw_total is None
        else _canonical_graph_decimal(abs(raw_total), positive=True)
    )
    reason = getattr(refund, "odoo_cli_v3_reason", None)
    partial_lines = _graph_invoice_lines(
        getattr(refund, "invoice_line_ids", []),
        include_product=False,
    )
    if (
        refund_date is None
        or journal_id is None
        or currency_id is None
        or total is None
        or not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > 512
        or not partial_lines
    ):
        return []
    common = {
        "company_id": company_id,
        "origin_move_id": origin_move_id,
        "refund_type": (
            "vendor_debit_note" if vendor else "customer_credit_note"
        ),
        "refund_date": refund_date,
        "journal_id": journal_id,
        "currency_id": currency_id,
        "expected_total_amount": total,
        "reason": reason,
        "posting_mode": "draft",
    }
    candidates = [("full", []), ("partial", partial_lines)]
    result: list[tuple[str, str, str, str]] = []
    for refund_mode, lines in candidates:
        parameters = {
            **common,
            "refund_mode": refund_mode,
            "lines": lines,
        }
        document_binding = hashlib.sha256(
            json.dumps(
                {
                    "capability_kind": "refund",
                    "parameters": {
                        key: parameters[key]
                        for key in sorted(parameters)
                    },
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        try:
            document_binding_v2 = canonical_document_binding_v2(
                "refund", parameters
            )
        except DocumentBindingError:
            continue
        business_binding = hashlib.sha256(
            json.dumps(
                {
                    "business_kind": "refund",
                    "identity": {
                        "origin_move_id": origin_move_id,
                        "refund_mode": refund_mode,
                        "line_references": sorted(
                            line["line_reference"] for line in lines
                        ),
                    },
                },
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        result.append(
            (
                refund_mode,
                document_binding,
                document_binding_v2,
                business_binding,
            )
        )
    return result


def _amounts_equal_abs(left: Any, right: Any) -> bool:
    left_decimal = _decimal(left)
    right_decimal = _decimal(right)
    if left_decimal is None or right_decimal is None:
        return False
    return abs(left_decimal) == abs(right_decimal)


def _iter_records(value: Any) -> list[Any]:
    if value in (False, None):
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    try:
        return list(value)
    except TypeError:
        return [value]


def _check_read_acl(record: Any) -> None:
    check_rights = getattr(record, "check_access_rights", None)
    check_rule = getattr(record, "check_access_rule", None)
    if not callable(check_rights) or not callable(check_rule):
        raise OdooExecutionError("explicit Odoo read ACL checks are unavailable")
    check_rights("read")
    check_rule("read")


def _acl_granted(record: Any, operation: str) -> bool:
    check_rights = getattr(record, "check_access_rights", None)
    check_rule = getattr(record, "check_access_rule", None)
    if not callable(check_rights) or not callable(check_rule):
        raise OdooExecutionError(
            f"explicit Odoo {operation} ACL checks are unavailable"
        )
    try:
        check_rights(operation)
        check_rule(operation)
    except Exception:
        return False
    return True


def _record_company_bound(
    record: Any, company_id: int, *, shared: bool
) -> bool:
    record_company_id = _record_id(getattr(record, "company_id", None))
    if record_company_id is not None:
        return record_company_id == company_id
    company_ids = _ids(getattr(record, "company_ids", []))
    if company_ids:
        return company_id in company_ids
    return shared


def _currency_journal_company_graph_valid(
    currency: Any,
    journal: Any,
    company: Any,
    *,
    currency_id: int | None,
    company_id: int,
    journal_type: str,
) -> bool:
    journal_currency_id = _record_id(
        getattr(journal, "currency_id", None)
    )
    company_currency_id = _record_id(
        getattr(company, "currency_id", None)
    )
    rounding = _decimal(getattr(currency, "rounding", None))
    return bool(
        currency_id is not None
        and getattr(currency, "active", True) is not False
        and rounding is not None
        and rounding.is_finite()
        and rounding > 0
        and _record_id(getattr(journal, "company_id", None))
        == company_id
        and str(getattr(journal, "type", "") or "") == journal_type
        and getattr(journal, "active", True) is not False
        and (
            journal_currency_id == currency_id
            if journal_currency_id is not None
            else company_currency_id is not None
        )
    )


def _account_dependency_valid(
    account: Any,
    company_id: int,
    *,
    expected_types: frozenset[str] | None = None,
) -> bool:
    if _record_id(account) is None:
        return False
    _check_read_acl(account)
    if (
        not _record_company_bound(account, company_id, shared=False)
        or bool(getattr(account, "deprecated", False))
    ):
        return False
    return expected_types is None or str(
        getattr(account, "account_type", "") or ""
    ) in expected_types


def _product_dependency_graph_valid(
    product: Any,
    company_id: int,
) -> bool:
    if _record_id(product) is None:
        return True
    if (
        not _acl_granted(product, "read")
        or getattr(product, "active", True) is False
        or not _record_company_bound(
            product, company_id, shared=True
        )
    ):
        return False
    for field in (
        "property_account_income_id",
        "property_account_expense_id",
    ):
        account = getattr(product, field, None)
        if _record_id(account) is not None and not _account_dependency_valid(
            account, company_id
        ):
            return False
    category = getattr(product, "categ_id", None)
    if _record_id(category) is None:
        return True
    if (
        not _acl_granted(category, "read")
        or not _record_company_bound(
            category, company_id, shared=True
        )
    ):
        return False
    for field in (
        "property_account_income_categ_id",
        "property_account_expense_categ_id",
        "property_stock_account_input_categ_id",
        "property_stock_account_output_categ_id",
        "property_stock_valuation_account_id",
    ):
        account = getattr(category, field, None)
        if _record_id(account) is not None and not _account_dependency_valid(
            account, company_id
        ):
            return False
    stock_journal = getattr(category, "property_stock_journal", None)
    return bool(
        _record_id(stock_journal) is None
        or (
            _acl_granted(stock_journal, "read")
            and _record_company_bound(
                stock_journal, company_id, shared=False
            )
        )
    )


def _amounts_equal_at_rounding(
    left: Any,
    right: Any,
    rounding: Any,
) -> bool:
    left_decimal = _decimal(left)
    right_decimal = _decimal(right)
    rounding_decimal = _decimal(rounding)
    if (
        left_decimal is None
        or right_decimal is None
        or rounding_decimal is None
        or not all(
            value.is_finite()
            for value in (
                left_decimal,
                right_decimal,
                rounding_decimal,
            )
        )
        or rounding_decimal <= 0
    ):
        return False
    return (
        left_decimal / rounding_decimal
    ).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    ) == (
        right_decimal / rounding_decimal
    ).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    )


def _taxless_document_graph_is_exact(
    move: Any,
    lines: list[Any],
    invoice_line_ids: list[int],
    *,
    company_id: int,
    commercial_partner_id: int,
    vendor: bool,
    expected_term_date: str | None = None,
    require_company_currency_amount_graph: bool = False,
) -> bool:
    keyed = {_record_id(line): line for line in lines}
    if (
        None in keyed
        or len(keyed) != len(lines)
        or not invoice_line_ids
        or any(line_id not in keyed for line_id in invoice_line_ids)
    ):
        return False
    invoice_lines = [keyed[line_id] for line_id in invoice_line_ids]
    invoice_account_types = (
        frozenset({"expense", "expense_depreciation", "expense_direct_cost"})
        if vendor
        else frozenset({"income", "income_other"})
    )
    expected_term_type = (
        "liability_payable" if vendor else "asset_receivable"
    )
    currency_rounding = getattr(
        getattr(move, "currency_id", None),
        "rounding",
        None,
    )
    if not _amounts_equal_at_rounding(
        0, 0, currency_rounding
    ):
        return False
    untaxed = Decimal("0")
    for line in lines:
        account = getattr(line, "account_id", None)
        expected_types = (
            invoice_account_types if line in invoice_lines else None
        )
        if not _account_dependency_valid(
            account, company_id, expected_types=expected_types
        ):
            return False
        if not _product_dependency_graph_valid(
            getattr(line, "product_id", None),
            company_id,
        ):
            return False
        if (
            _ids(getattr(line, "tax_ids", []))
            or _record_id(getattr(line, "tax_line_id", None)) is not None
            or _ids(getattr(line, "tax_tag_ids", []))
            or _record_id(
                getattr(line, "tax_repartition_line_id", None)
            )
            is not None
            or _record_id(getattr(line, "group_tax_id", None)) is not None
            or (
                _decimal(getattr(line, "tax_base_amount", 0))
                or Decimal("0")
            )
            != Decimal("0")
            or getattr(line, "extra_tax_data", False)
            not in (False, None, {})
            or getattr(line, "matching_number", False)
            not in (False, None, "")
            or _decimal(getattr(line, "deductible_amount", None))
            != Decimal("100")
            or (
                str(getattr(line, "display_type", "") or "")
                not in {"line_section", "line_subsection", "line_note"}
                and _record_id(getattr(line, "partner_id", None))
                != commercial_partner_id
            )
        ):
            return False
        debit = _decimal(getattr(line, "debit", None))
        credit = _decimal(getattr(line, "credit", None))
        balance = _decimal(getattr(line, "balance", None))
        amount_currency = _decimal(
            getattr(line, "amount_currency", None)
        )
        if (
            debit is None
            or credit is None
            or balance is None
            or amount_currency is None
            or not all(
                value.is_finite()
                for value in (debit, credit, balance, amount_currency)
            )
            or debit < 0
            or credit < 0
            or balance != debit - credit
        ):
            return False
    for line in invoice_lines:
        quantity = _decimal(getattr(line, "quantity", None))
        price_unit = _decimal(getattr(line, "price_unit", None))
        price_subtotal = _decimal(
            getattr(line, "price_subtotal", None)
        )
        price_total = _decimal(getattr(line, "price_total", None))
        if (
            quantity is None
            or price_unit is None
            or price_subtotal is None
            or price_total is None
            or not all(
                value.is_finite()
                for value in (
                    quantity,
                    price_unit,
                    price_subtotal,
                    price_total,
                )
            )
            or quantity <= 0
            or price_unit < 0
            or not _amounts_equal_at_rounding(
                price_subtotal,
                quantity * price_unit,
                currency_rounding,
            )
            or not _amounts_equal_at_rounding(
                price_total,
                price_subtotal,
                currency_rounding,
            )
        ):
            return False
        untaxed += price_subtotal
    term_lines = [
        line for line in lines if _record_id(line) not in invoice_line_ids
    ]
    if (
        len(term_lines) != 1
        or str(getattr(term_lines[0], "display_type", "") or "")
        != "payment_term"
        or str(
            getattr(
                getattr(term_lines[0], "account_id", None),
                "account_type",
                "",
            )
            or ""
        )
        != expected_term_type
        or _record_id(getattr(term_lines[0], "partner_id", None))
        != commercial_partner_id
        or (
            expected_term_date is not None
            and _date_text(
                getattr(term_lines[0], "date_maturity", None)
            )
            != expected_term_date
        )
    ):
        return False
    amount_untaxed = _decimal(getattr(move, "amount_untaxed", None))
    amount_tax = _decimal(getattr(move, "amount_tax", None))
    amount_total = _decimal(getattr(move, "amount_total", None))
    if require_company_currency_amount_graph:
        balance_direction = {
            "out_invoice": Decimal("-1"),
            "in_invoice": Decimal("1"),
            "out_refund": Decimal("1"),
            "in_refund": Decimal("-1"),
        }.get(str(getattr(move, "move_type", "") or ""))
        if (
            balance_direction is None
            or amount_total is None
            or not amount_total.is_finite()
            or amount_total <= 0
        ):
            return False
        for line in invoice_lines:
            price_total = _decimal(getattr(line, "price_total", None))
            if price_total is None or not price_total.is_finite():
                return False
            expected_balance = balance_direction * price_total
            expected_debit = max(expected_balance, Decimal("0"))
            expected_credit = max(-expected_balance, Decimal("0"))
            if not all(
                (
                    _amounts_equal_at_rounding(
                        getattr(line, field, None),
                        expected,
                        currency_rounding,
                    )
                    for field, expected in (
                        ("debit", expected_debit),
                        ("credit", expected_credit),
                        ("balance", expected_balance),
                        ("amount_currency", expected_balance),
                    )
                )
            ):
                return False
        term = term_lines[0]
        expected_term_balance = -balance_direction * amount_total
        expected_term_debit = max(
            expected_term_balance, Decimal("0")
        )
        expected_term_credit = max(
            -expected_term_balance, Decimal("0")
        )
        if not all(
            (
                _amounts_equal_at_rounding(
                    getattr(term, field, None),
                    expected,
                    currency_rounding,
                )
                for field, expected in (
                    ("debit", expected_term_debit),
                    ("credit", expected_term_credit),
                    ("balance", expected_term_balance),
                    ("amount_currency", expected_term_balance),
                    ("amount_residual", expected_term_balance),
                    (
                        "amount_residual_currency",
                        expected_term_balance,
                    ),
                )
            )
        ):
            return False
    debit_total = sum(
        (_decimal(getattr(line, "debit", None)) for line in lines),
        Decimal("0"),
    )
    credit_total = sum(
        (_decimal(getattr(line, "credit", None)) for line in lines),
        Decimal("0"),
    )
    return bool(
        amount_untaxed is not None
        and amount_tax is not None
        and amount_total is not None
        and amount_untaxed == untaxed
        and amount_tax == 0
        and amount_total == untaxed
        and debit_total == credit_total
    )


def _effective_posting_date_failure(
    move: Any,
    accounting_date: str | None,
    *,
    has_taxes: bool,
    today: Any,
) -> str | None:
    if accounting_date is None:
        return "effective_posting_date_invalid"
    parsed = datetime.strptime(accounting_date, "%Y-%m-%d").date()
    if parsed > today:
        return "effective_posting_date_in_future"
    tax_checker = getattr(move, "_affect_tax_report", None)
    lock_checker = getattr(move, "_get_violated_lock_dates", None)
    if not callable(tax_checker) or not callable(lock_checker):
        return "effective_lock_date_api_unavailable"
    try:
        affects_tax_report = tax_checker()
        violations = lock_checker(parsed, affects_tax_report)
    except Exception:
        return "effective_lock_date_check_failed"
    if (
        not isinstance(affects_tax_report, bool)
        or affects_tax_report is not has_taxes
    ):
        return "effective_tax_report_effect_mismatch"
    if not isinstance(violations, list):
        return "effective_lock_date_result_invalid"
    if violations:
        return "effective_lock_date_violated"
    return None


def _journal_line_signature(
    line: Any, *, reversed_amounts: bool
) -> tuple[Any, ...] | None:
    debit = _decimal(getattr(line, "debit", None))
    credit = _decimal(getattr(line, "credit", None))
    balance = _decimal(getattr(line, "balance", None))
    amount_currency = _decimal(getattr(line, "amount_currency", None))
    if (
        debit is None
        or credit is None
        or balance is None
        or amount_currency is None
        or not all(
            value.is_finite()
            for value in (debit, credit, balance, amount_currency)
        )
    ):
        return None
    if reversed_amounts:
        debit, credit = credit, debit
        balance = -balance
        amount_currency = -amount_currency
    display_type = str(
        getattr(line, "display_type", "") or ""
    )
    line_name = (
        ""
        if display_type == "payment_term"
        else str(getattr(line, "name", "") or "")
    )
    return (
        line_name,
        _record_id(getattr(line, "account_id", None)),
        _record_id(getattr(line, "partner_id", None)),
        _record_id(getattr(line, "currency_id", None)),
        debit,
        credit,
        balance,
        amount_currency,
        tuple(_ids(getattr(line, "tax_ids", []))),
        _record_id(getattr(line, "tax_line_id", None)),
        display_type,
    )


def _partial_refund_origin_line_relation_is_exact(
    origin_lines: list[Any],
    refund_lines: list[Any],
    *,
    origin_invoice_line_ids: list[int],
    refund_invoice_line_ids: list[int],
) -> bool:
    origin_by_id = {_record_id(line): line for line in origin_lines}
    refund_by_id = {_record_id(line): line for line in refund_lines}
    if (
        None in origin_by_id
        or None in refund_by_id
        or len(origin_by_id) != len(origin_lines)
        or len(refund_by_id) != len(refund_lines)
        or any(line_id not in origin_by_id for line_id in origin_invoice_line_ids)
        or any(line_id not in refund_by_id for line_id in refund_invoice_line_ids)
    ):
        return False
    return partial_refund_origin_line_relation_is_exact(
        (
            partial_refund_line_from_odoo(origin_by_id[line_id])
            for line_id in origin_invoice_line_ids
        ),
        (
            partial_refund_line_from_odoo(refund_by_id[line_id])
            for line_id in refund_invoice_line_ids
        ),
    )


def _linewise_reversal_is_exact(
    origin_lines: list[Any], refund_lines: list[Any]
) -> bool:
    expected = [
        _journal_line_signature(line, reversed_amounts=True)
        for line in origin_lines
    ]
    actual = [
        _journal_line_signature(line, reversed_amounts=False)
        for line in refund_lines
    ]
    return bool(
        all(signature is not None for signature in (*expected, *actual))
        and sorted(repr(signature) for signature in expected)
        == sorted(repr(signature) for signature in actual)
    )


def _full_refund_invoice_line_signature(
    line: Any,
    *,
    reversed_amounts: bool,
) -> tuple[Any, ...] | None:
    journal_signature = _journal_line_signature(
        line,
        reversed_amounts=reversed_amounts,
    )
    quantity = _decimal(getattr(line, "quantity", None))
    price_unit = _decimal(getattr(line, "price_unit", None))
    discount = _decimal(getattr(line, "discount", 0))
    price_subtotal = _decimal(getattr(line, "price_subtotal", None))
    price_total = _decimal(getattr(line, "price_total", None))
    decimal_values = (
        quantity,
        price_unit,
        discount,
        price_subtotal,
        price_total,
    )
    if (
        journal_signature is None
        or any(value is None for value in decimal_values)
        or not all(
            value.is_finite()
            for value in decimal_values
            if value is not None
        )
        or quantity <= 0
        or price_unit < 0
        or price_subtotal < 0
        or price_total < 0
    ):
        return None
    return (
        *journal_signature,
        _record_id(getattr(line, "product_id", None)),
        _record_id(getattr(line, "product_uom_id", None)),
        quantity,
        price_unit,
        discount,
        price_subtotal,
        price_total,
        _record_id(
            getattr(line, "tax_repartition_line_id", None)
        ),
        tuple(_ids(getattr(line, "tax_tag_ids", []))),
        _record_id(getattr(line, "group_tax_id", None)),
    )


def _full_refund_invoice_lineage_is_exact(
    origin_lines: list[Any],
    refund_lines: list[Any],
    *,
    origin_move_id: int,
    origin_invoice_line_ids: list[int],
    refund_invoice_line_ids: list[int],
) -> bool:
    origin_by_id = {_record_id(line): line for line in origin_lines}
    refund_by_id = {_record_id(line): line for line in refund_lines}
    if (
        None in origin_by_id
        or None in refund_by_id
        or len(origin_by_id) != len(origin_lines)
        or len(refund_by_id) != len(refund_lines)
        or len(origin_invoice_line_ids) != len(refund_invoice_line_ids)
        or not origin_invoice_line_ids
        or any(
            line_id not in origin_by_id
            for line_id in origin_invoice_line_ids
        )
        or any(
            line_id not in refund_by_id
            for line_id in refund_invoice_line_ids
        )
    ):
        return False

    origin_groups: dict[tuple[Any, ...], list[Any]] = {}
    refund_groups: dict[tuple[Any, ...], list[Any]] = {}
    for line_id in origin_invoice_line_ids:
        line = origin_by_id[line_id]
        signature = _full_refund_invoice_line_signature(
            line,
            reversed_amounts=True,
        )
        if signature is None:
            return False
        origin_groups.setdefault(signature, []).append(line)
    for line_id in refund_invoice_line_ids:
        line = refund_by_id[line_id]
        signature = _full_refund_invoice_line_signature(
            line,
            reversed_amounts=False,
        )
        if signature is None:
            return False
        refund_groups.setdefault(signature, []).append(line)
    if set(origin_groups) != set(refund_groups):
        return False

    observed_references: set[str] = set()
    for signature in origin_groups:
        origins = sorted(
            origin_groups[signature],
            key=lambda line: _record_id(line) or 0,
        )
        refunds = sorted(
            refund_groups[signature],
            key=lambda line: _record_id(line) or 0,
        )
        if len(origins) != len(refunds):
            return False
        for origin_line, refund_line in zip(origins, refunds, strict=True):
            origin_line_id = _record_id(origin_line)
            if origin_line_id is None:
                return False
            try:
                expected_reference = full_refund_line_reference(
                    origin_move_id,
                    origin_line_id,
                )
            except DocumentBindingError:
                return False
            observed_reference = str(
                getattr(
                    refund_line,
                    "odoo_cli_v3_line_reference",
                    "",
                )
                or ""
            )
            if (
                observed_reference != expected_reference
                or observed_reference in observed_references
            ):
                return False
            observed_references.add(observed_reference)
    return len(observed_references) == len(refund_invoice_line_ids)


def _line_external_effect_present(
    line: Any,
    *,
    move_id: int,
    company_id: int,
    parent_state: str,
) -> bool:
    return bool(
        _record_id(getattr(line, "move_id", None)) != move_id
        or _record_id(getattr(line, "company_id", None)) != company_id
        or str(getattr(line, "parent_state", "") or "") != parent_state
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
        or str(getattr(line, "display_type", "") or "") == "cogs"
    )


def _has_refund_move_external_effect(
    move: Any,
    *,
    allowed_reversed_entry_id: int | None,
    allowed_reversal_move_ids: frozenset[int],
) -> bool:
    reversed_entry_id = _record_id(getattr(move, "reversed_entry_id", None))
    reversal_move_ids = frozenset(
        _ids(getattr(move, "reversal_move_ids", []))
    )
    return bool(
        any(
            (
                _record_id(getattr(move, "auto_post_origin_id", None))
                is not None,
                _record_id(getattr(move, "origin_payment_id", None))
                is not None,
                _record_id(getattr(move, "statement_line_id", None))
                is not None,
                _record_id(getattr(move, "statement_id", None))
                is not None,
                _record_id(getattr(move, "tax_cash_basis_rec_id", None))
                is not None,
                _record_id(
                    getattr(move, "tax_cash_basis_origin_move_id", None)
                )
                is not None,
                _record_id(getattr(move, "asset_id", None)) is not None,
                _record_id(getattr(move, "closing_return_id", None))
                is not None,
                _record_id(getattr(move, "transfer_model_id", None))
                is not None,
                _record_id(getattr(move, "purchase_id", None))
                is not None,
                _record_id(getattr(move, "debit_origin_id", None))
                is not None,
                _record_id(getattr(move, "invoice_pdf_report_id", None))
                is not None,
                _record_id(getattr(move, "invoice_vendor_bill_id", None))
                is not None,
                _record_id(getattr(move, "purchase_vendor_bill_id", None))
                is not None,
                _record_id(getattr(move, "ubl_cii_xml_id", None))
                is not None,
                _record_id(
                    getattr(move, "l10n_es_edi_facturae_xml_id", None)
                )
                is not None,
                _record_id(getattr(move, "signing_user", None))
                is not None,
                _record_id(
                    getattr(move, "message_main_attachment_id", None)
                )
                is not None,
            )
        )
        or any(
            (
                _ids(getattr(move, "payment_ids", [])),
                _ids(getattr(move, "matched_payment_ids", [])),
                _ids(getattr(move, "reconciled_payment_ids", [])),
                _ids(
                    getattr(
                        move,
                        "tax_cash_basis_created_move_ids",
                        [],
                    )
                ),
                _ids(
                    getattr(move, "adjusting_entry_origin_move_ids", [])
                ),
                _ids(getattr(move, "adjusting_entries_move_ids", [])),
                _ids(getattr(move, "exchange_diff_partial_ids", [])),
                _ids(getattr(move, "deferred_move_ids", [])),
                _ids(getattr(move, "deferred_original_move_ids", [])),
                _ids(getattr(move, "edi_document_ids", [])),
                _ids(getattr(move, "expense_ids", [])),
                _ids(getattr(move, "pos_order_ids", [])),
                _ids(getattr(move, "statement_line_ids", [])),
                _ids(getattr(move, "transaction_ids", [])),
                _ids(getattr(move, "authorized_transaction_ids", [])),
                _ids(getattr(move, "asset_ids", [])),
                _ids(getattr(move, "stock_move_ids", [])),
                _ids(getattr(move, "landed_costs_ids", [])),
                _ids(getattr(move, "debit_note_ids", [])),
                _ids(getattr(move, "attachment_ids", [])),
            )
        )
        or reversed_entry_id != allowed_reversed_entry_id
        or reversal_move_ids != allowed_reversal_move_ids
        or _has_document_delivery_effect(move)
    )


def _has_document_delivery_effect(move: Any) -> bool:
    return bool(
        any(
            (
                getattr(move, "access_token", False)
                not in (False, None, "", b""),
                getattr(move, "invoice_pdf_report_file", False)
                not in (False, None, "", b""),
                getattr(move, "ubl_cii_xml_file", False)
                not in (False, None, "", b""),
                getattr(move, "l10n_es_edi_facturae_xml_file", False)
                not in (False, None, "", b""),
            )
        )
        or bool(getattr(move, "signature", False))
        or bool(getattr(move, "is_move_sent", False))
        or getattr(move, "sending_data", False) not in (False, None, {})
        or bool(getattr(move, "is_being_sent", False))
        or getattr(move, "invoice_source_email", False)
        not in (False, None, "")
    )


def _has_draft_cancel_singular_effect_link(move: Any) -> bool:
    return any(
        (
            _record_id(getattr(move, "auto_post_origin_id", None)) is not None,
            _record_id(getattr(move, "origin_payment_id", None)) is not None,
            _record_id(getattr(move, "statement_line_id", None)) is not None,
            _record_id(getattr(move, "statement_id", None)) is not None,
            _record_id(getattr(move, "tax_cash_basis_rec_id", None)) is not None,
            _record_id(getattr(move, "tax_cash_basis_origin_move_id", None)) is not None,
            _record_id(getattr(move, "reversed_entry_id", None)) is not None,
            _record_id(getattr(move, "asset_id", None)) is not None,
            _record_id(getattr(move, "closing_return_id", None)) is not None,
            _record_id(getattr(move, "transfer_model_id", None)) is not None,
            _record_id(getattr(move, "purchase_id", None)) is not None,
            _record_id(getattr(move, "debit_origin_id", None)) is not None,
            _record_id(getattr(move, "invoice_pdf_report_id", None)) is not None,
            _record_id(getattr(move, "invoice_vendor_bill_id", None)) is not None,
            _record_id(getattr(move, "purchase_vendor_bill_id", None)) is not None,
            _record_id(getattr(move, "ubl_cii_xml_id", None)) is not None,
            _record_id(getattr(move, "l10n_es_edi_facturae_xml_id", None)) is not None,
            _record_id(getattr(move, "signing_user", None)) is not None,
            _record_id(getattr(move, "message_main_attachment_id", None)) is not None,
        )
    )


def _has_draft_cancel_plural_effect_link(move: Any) -> bool:
    return any(
        (
            _ids(getattr(move, "payment_ids", [])),
            _ids(getattr(move, "matched_payment_ids", [])),
            _ids(getattr(move, "reconciled_payment_ids", [])),
            _ids(getattr(move, "tax_cash_basis_created_move_ids", [])),
            _ids(getattr(move, "reversal_move_ids", [])),
            _ids(getattr(move, "adjusting_entry_origin_move_ids", [])),
            _ids(getattr(move, "adjusting_entries_move_ids", [])),
            _ids(getattr(move, "exchange_diff_partial_ids", [])),
            _ids(getattr(move, "deferred_move_ids", [])),
            _ids(getattr(move, "deferred_original_move_ids", [])),
            _ids(getattr(move, "edi_document_ids", [])),
            _ids(getattr(move, "expense_ids", [])),
            _ids(getattr(move, "pos_order_ids", [])),
            _ids(getattr(move, "statement_line_ids", [])),
            _ids(getattr(move, "transaction_ids", [])),
            _ids(getattr(move, "authorized_transaction_ids", [])),
            _ids(getattr(move, "asset_ids", [])),
            _ids(getattr(move, "stock_move_ids", [])),
            _ids(getattr(move, "landed_costs_ids", [])),
            _ids(getattr(move, "debit_note_ids", [])),
            _ids(getattr(move, "attachment_ids", [])),
        )
    )


class OdooReadExecutor:
    """Dispatch only registered read handlers inside a bound non-su Odoo env."""

    def __init__(
        self,
        env: Any,
        *,
        capabilities: Iterable[Capability],
        odoo_instance_id: str,
        database_name: str,
        database_uuid: str,
        release_digest: str,
        environment: str,
        capability_channel: str,
        receipt_secret: bytes,
        receipt_key_id: str,
        consume_receipt: Callable[[str, str, datetime, datetime], bool],
        now: Callable[[], datetime] | None = None,
        receipt_id_factory: Callable[[], str] | None = None,
        trial_balance_backend_factory: Callable[[Any, int, frozenset[int]], TrialBalanceBackend]
        | None = None,
        ar_open_items_backend_factory: Callable[
            [Any, int, frozenset[int]], ArOpenItemsBackend
        ]
        | None = None,
        ap_open_items_backend_factory: Callable[
            [Any, int, frozenset[int]], ApOpenItemsBackend
        ]
        | None = None,
        multicompany_consolidated_backend_factory: Callable[
            [Any, int, frozenset[int]], MulticompanyConsolidatedBackend
        ]
        | None = None,
        multicurrency_balance_backend_factory: Callable[
            [Any, int, frozenset[int]], MulticurrencyBalanceBackend
        ]
        | None = None,
        report_read_backend_factory: Callable[
            [Any, int, frozenset[int]], ReportReadBackend
        ]
        | None = None,
    ) -> None:
        capability_list = tuple(capabilities)
        capability_map = {item.id: item for item in capability_list}
        if (
            not odoo_instance_id
            or not database_name
            or not _valid_sha_binding(release_digest)
            or not receipt_secret
            or not isinstance(receipt_key_id, str)
            or not receipt_key_id.strip()
            or not callable(consume_receipt)
            or not valid_read_runtime_binding(environment, capability_channel)
            or not capability_list
            or len(capability_map) != len(capability_list)
        ):
            raise OdooExecutionError(
                "trusted registry, instance, database, receipt key, and replay store are required"
            )
        self._env = env
        self._capabilities = capability_list
        self._capability_map = capability_map
        self._odoo_instance_id = odoo_instance_id
        self._database_name = database_name
        self._database_uuid = str(uuid.UUID(database_uuid))
        self._release_digest = release_digest
        self._environment = environment
        self._capability_channel = capability_channel
        self._receipt_secret = receipt_secret
        self._receipt_key_id = receipt_key_id
        self._consume_receipt = consume_receipt
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._receipt_id_factory = receipt_id_factory or (lambda: str(uuid.uuid4()))
        self._trial_balance_backend_factory = trial_balance_backend_factory or (
            lambda bound_env, user_id, allowed: OdooTrialBalanceBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )
        self._ar_open_items_backend_factory = ar_open_items_backend_factory or (
            lambda bound_env, user_id, allowed: OdooArOpenItemsBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )
        self._ap_open_items_backend_factory = ap_open_items_backend_factory or (
            lambda bound_env, user_id, allowed: OdooApOpenItemsBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )
        self._multicompany_consolidated_backend_factory = (
            multicompany_consolidated_backend_factory
            or (
                lambda bound_env, user_id, allowed: (
                    OdooMulticompanyConsolidatedBackend(
                        bound_env,
                        user_id=user_id,
                        allowed_company_ids=allowed,
                    )
                )
            )
        )
        self._multicurrency_balance_backend_factory = (
            multicurrency_balance_backend_factory
            or (
                lambda bound_env, user_id, allowed: OdooMulticurrencyBalanceBackend(
                    bound_env,
                    user_id=user_id,
                    allowed_company_ids=allowed,
                )
            )
        )
        self._report_read_backend_factory = report_read_backend_factory or (
            lambda bound_env, user_id, allowed: OdooReportReadBackend(
                bound_env,
                user_id=user_id,
                allowed_company_ids=allowed,
                database_uuid=self._database_uuid,
                release_digest=self._release_digest,
                allowed_root_xmlids_by_family={
                    "financial": _FINANCIAL_REPORT_ROOT_XMLIDS,
                    "tax": _TAX_REPORT_ROOT_XMLIDS,
                },
            )
        )

    def _assert_runtime_binding(self, context: RequestContext) -> None:
        actual_database = getattr(getattr(self._env, "cr", None), "dbname", None)
        if (
            context.odoo_instance_id != self._odoo_instance_id
            or context.database_name != self._database_name
            or context.database_uuid != self._database_uuid
            or context.environment != self._environment
            or actual_database != self._database_name
            or context.user_id != getattr(self._env, "uid", None)
            or getattr(self._env, "su", False)
        ):
            raise OdooExecutionError("Odoo executor runtime binding mismatch")

    @staticmethod
    def _canonical_json(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def _read_registry(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        company_id = parameters["company_id"]
        if company_id != context.company_id or company_id not in context.allowed_company_ids:
            raise OdooExecutionError("registry company is outside the signed company binding")
        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise OdooExecutionError("registry company does not exist or is not visible")
        company.check_access_rights("read")
        company.check_access_rule("read")

        environment_field = (
            "enabled_environments"
            if self._capability_channel == "enabled"
            else "staged_environments"
        )
        descriptors = []
        for candidate in self._capabilities:
            data = candidate.data
            if context.environment not in data.get(environment_field, []):
                continue
            if not all(
                self._env.user.has_group(xml_id)
                for xml_id in data["odoo_permissions"]
            ):
                continue
            contract_json = self._canonical_json(data)
            descriptors.append(
                {
                    "id": data["id"],
                    "domain": data["domain"],
                    "business_description": data["business_description"],
                    "access": data["access"],
                    "risk_level": data["risk_level"],
                    "company_scope": data["company_scope"],
                    "odoo_permissions": data["odoo_permissions"],
                    "approval_required": data["approval"]["required"],
                    "idempotency_required": data["idempotency"]["required"],
                    "input_schema_json": self._canonical_json(data["input_schema"]),
                    "output_schema_json": self._canonical_json(data["output_schema"]),
                    "contract_digest": hashlib.sha256(
                        contract_json.encode("utf-8")
                    ).hexdigest(),
                    "evidence_level": data["evidence"]["level"],
                    "verification_method": data["verification"]["method"],
                    "recovery_method": data["recovery"]["method"],
                    "capability_channel": self._capability_channel,
                }
            )
        descriptors.sort(key=lambda item: item["id"])
        count = len(descriptors)
        return {
            "capabilities": descriptors,
            "page": {"count": count, "total_count": count},
        }

    def _read_trial_balance(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._trial_balance_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_trial_balance(backend, parameters)

    def _read_ar_open_items(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._ar_open_items_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_ar_open_items(backend, parameters)

    def _read_ap_open_items(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._ap_open_items_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_ap_open_items(backend, parameters)

    def _read_multicompany_consolidated(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._multicompany_consolidated_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_multicompany_consolidated(backend, parameters)

    def _read_multicurrency_balance(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._multicurrency_balance_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_multicurrency_balance(backend, parameters)

    def _read_financial_report(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._report_read_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_financial_report(backend, parameters)

    def _read_tax_report(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._report_read_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_tax_report(backend, parameters)

    def _bound_read_company(
        self,
        context: RequestContext,
        company_id: int,
        *,
        label: str,
    ) -> Any:
        if (
            type(company_id) is not int
            or company_id <= 0
            or company_id != context.company_id
            or company_id not in context.allowed_company_ids
        ):
            raise OdooExecutionError(
                f"{label} company is outside the signed binding"
            )
        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise OdooExecutionError(
                f"{label} company does not exist or is not visible"
            )
        _check_read_acl(company)
        return company

    def _bound_read_move(
        self,
        move_id: int,
        company_id: int,
        *,
        label: str,
    ) -> Any:
        if type(move_id) is not int or move_id <= 0:
            raise OdooExecutionError(f"{label} identity is invalid")
        move = self._env["account.move"].browse(move_id).exists()
        if not move or len(move) != 1:
            raise OdooExecutionError(
                f"{label} does not exist or is not visible"
            )
        _check_read_acl(move)
        if _record_id(getattr(move, "company_id", None)) != company_id:
            raise OdooExecutionError(
                f"{label} is outside the bound company"
            )
        return move

    @staticmethod
    def _read_related_acl(*records: Any) -> None:
        checked: set[int] = set()
        for record in records:
            record_id = _record_id(record)
            if record_id is None:
                continue
            key = id(record)
            if key in checked:
                continue
            _check_read_acl(record)
            checked.add(key)

    def _has_exchange_or_caba_effect(self, move_ids: list[int]) -> bool:
        if not move_ids:
            raise OdooExecutionError(
                "external-effect search requires bound move identities"
            )
        searches = (
            (
                "account.partial.reconcile",
                [("exchange_move_id", "in", move_ids)],
            ),
            (
                "account.move",
                [("tax_cash_basis_origin_move_id", "in", move_ids)],
            ),
        )
        for model_name, domain in searches:
            model = self._env[model_name]
            check_rights = getattr(model, "check_access_rights", None)
            search = getattr(model, "search", None)
            if not callable(check_rights) or not callable(search):
                raise OdooExecutionError(
                    "external-effect read ACL search is unavailable"
                )
            check_rights("read")
            records = _iter_records(search(domain, limit=1))
            for record in records:
                _check_read_acl(record)
            if records:
                return True
        return False

    def _read_document_post_eligibility(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        company_id = parameters["company_id"]
        move_id = parameters["move_id"]
        expected_move_type = parameters["expected_move_type"]
        company = self._bound_read_company(
            context, company_id, label="document posting"
        )
        move = self._bound_read_move(
            move_id, company_id, label="document posting move"
        )
        failures: list[str] = []
        if not _acl_granted(move, "write"):
            failures.append("move_write_acl_denied")

        lines = _iter_records(getattr(move, "line_ids", []))
        for line in lines:
            _check_read_acl(line)
        if any(not _acl_granted(line, "write") for line in lines):
            failures.append("line_write_acl_denied")

        move_type = str(getattr(move, "move_type", "") or "")
        state = str(getattr(move, "state", "") or "")
        payment_state = str(getattr(move, "payment_state", "") or "")
        document_binding = str(
            getattr(move, "odoo_cli_v3_document_binding", "") or ""
        )
        raw_document_binding_v2 = getattr(
            move, "odoo_cli_v3_document_binding_v2", None
        )
        document_binding_v2 = str(raw_document_binding_v2 or "")
        business_binding = str(
            getattr(move, "odoo_cli_v3_business_binding", "") or ""
        )
        partner = getattr(move, "partner_id", None)
        journal = getattr(move, "journal_id", None)
        currency = getattr(move, "currency_id", None)
        commercial_partner = getattr(move, "commercial_partner_id", None)
        partner_id = _record_id(partner)
        journal_id = _record_id(journal)
        currency_id = _record_id(currency)
        company_currency_id = _record_id(
            getattr(company, "currency_id", None)
        )
        commercial_partner_id = _record_id(commercial_partner)
        self._read_related_acl(
            partner,
            commercial_partner,
            journal,
            currency,
            getattr(company, "currency_id", None),
        )

        invoice_date = _date_text(getattr(move, "invoice_date", None))
        accounting_date = _date_text(getattr(move, "date", None))
        due_date = _date_text(getattr(move, "invoice_date_due", None))
        raw_reference = getattr(move, "ref", None)
        reference = (
            raw_reference
            if isinstance(raw_reference, str)
            and raw_reference.strip()
            and len(raw_reference) <= 256
            else None
        )
        amount_untaxed = _nonnegative_decimal_text(
            getattr(move, "amount_untaxed", None)
        )
        amount_tax = _nonnegative_decimal_text(
            getattr(move, "amount_tax", None)
        )
        amount_total = _nonnegative_decimal_text(
            getattr(move, "amount_total", None)
        )
        amount_residual = _nonnegative_decimal_text(
            getattr(move, "amount_residual", None)
        )
        line_ids = _ids(getattr(move, "line_ids", []))
        invoice_line_ids = _ids(
            getattr(move, "invoice_line_ids", [])
        )
        candidate_write_capability_id = {
            "out_invoice": "acct.invoice.customer_post.v1",
            "in_invoice": "acct.bill.vendor_post.v1",
        }.get(expected_move_type)
        if candidate_write_capability_id is None:
            failures.append("expected_move_type_not_allowlisted")
        if move_type != expected_move_type:
            failures.append("move_type_mismatch")
        if state != "draft":
            failures.append("move_is_not_draft")
        if getattr(move, "name", None) not in {False, "/"}:
            failures.append("non_pristine_name_or_sequence")
        if getattr(move, "posted_before", None) is not False:
            failures.append("posted_before_not_false")
        if str(getattr(move, "auto_post", "") or "") != "no":
            failures.append("auto_post_not_disabled")
        if getattr(move, "auto_post_until", None) not in {False, None}:
            failures.append("auto_post_until_present")
        if getattr(move, "sequence_prefix", None) not in {False, None, ""}:
            failures.append("sequence_prefix_present")
        if getattr(move, "sequence_number", None) not in {False, 0}:
            failures.append("sequence_number_present")
        if getattr(move, "made_sequence_gap", None) is not False:
            failures.append("sequence_gap_flag_present")
        if getattr(move, "checked", None) is not False:
            failures.append("checked_flag_present")
        if (
            getattr(move, "secure_sequence_number", 0) not in {False, 0}
            or bool(getattr(move, "inalterable_hash", False))
            or bool(getattr(move, "need_cancel_request", False))
            or bool(getattr(move, "is_manually_modified", False))
        ):
            failures.append("posting_hash_edi_or_manual_mutation_evidence")
        if not _valid_sha_binding(document_binding):
            failures.append("document_binding_missing_or_invalid")
        if not _valid_sha_binding(document_binding_v2):
            failures.append(
                (
                    "legacy_binding_requires_provenance_migration"
                    if raw_document_binding_v2 in {None, False, ""}
                    else "document_binding_v2_invalid"
                )
            )
        if not _valid_sha_binding(business_binding):
            failures.append("business_binding_missing_or_invalid")
        graph_binding = _document_graph_binding_candidate(
            move,
            company_id=company_id,
            vendor=expected_move_type == "in_invoice",
            posting_mode="draft",
        )
        if (
            graph_binding is None
            or graph_binding[1:]
            != (document_binding_v2, business_binding)
        ):
            failures.append("document_graph_binding_mismatch")

        vendor = expected_move_type == "in_invoice"
        if not _currency_journal_company_graph_valid(
            currency,
            journal,
            company,
            currency_id=currency_id,
            company_id=company_id,
            journal_type="purchase" if vendor else "sale",
        ):
            failures.append(
                "currency_journal_or_company_configuration_invalid"
            )
        partner_company_id = _record_id(
            getattr(partner, "company_id", None)
        )
        if (
            partner_id is None
            or partner_company_id not in {None, company_id}
            or currency_id is None
        ):
            failures.append("partner_currency_or_company_binding_invalid")
        if (
            company_currency_id is None
            or currency_id != company_currency_id
        ):
            failures.append("document_currency_not_company_currency")
        rank_field = "supplier_rank" if vendor else "customer_rank"
        partner_rank = (
            getattr(partner, "supplier_rank", None)
            if vendor
            else getattr(partner, "customer_rank", None)
        )
        if (
            partner_id is None
            or commercial_partner_id != partner_id
            or _record_id(
                getattr(partner, "commercial_partner_id", None)
            )
            != partner_id
            or getattr(partner, "active", True) is False
            or not _record_company_bound(
                partner, company_id, shared=True
            )
            or isinstance(partner_rank, bool)
            or not isinstance(partner_rank, int)
            or partner_rank != 0
        ):
            failures.append(
                "posting_partner_commercial_rank_or_scope_invalid"
            )
        elif not _acl_granted(partner, "write"):
            failures.append("posting_partner_write_acl_denied")
        if _record_id(getattr(move, "partner_bank_id", None)) is not None:
            failures.append("partner_bank_side_effect_present")
        if (
            invoice_date is None
            or accounting_date is None
            or due_date is None
            or reference is None
        ):
            failures.append("document_date_or_reference_binding_invalid")
        if any(
            value is None
            for value in (
                amount_untaxed,
                amount_tax,
                amount_total,
                amount_residual,
            )
        ):
            failures.append("document_amount_binding_invalid")
        elif (
            Decimal(amount_untaxed) + Decimal(amount_tax)
            != Decimal(amount_total)
        ):
            failures.append("document_amounts_inconsistent")
        elif (
            Decimal(amount_total) <= 0
            or Decimal(amount_residual) <= 0
        ):
            failures.append("document_total_or_residual_not_positive")
        if payment_state != "not_paid":
            failures.append("payment_state_not_not_paid")
        if not _amounts_equal_abs(
            getattr(move, "amount_residual", None),
            getattr(move, "amount_total", None),
        ):
            failures.append("residual_total_mismatch")
        if (
            _has_draft_cancel_singular_effect_link(move)
            or _has_draft_cancel_plural_effect_link(move)
            or _has_document_delivery_effect(move)
            or self._has_exchange_or_caba_effect([move_id])
        ):
            failures.append("move_payment_or_external_effect_present")

        observed_line_ids = [_record_id(line) for line in lines]
        if (
            len(line_ids) < 2
            or len(line_ids) > 1000
            or len(lines) != len(line_ids)
            or any(line_id is None for line_id in observed_line_ids)
            or sorted(observed_line_ids) != line_ids
        ):
            failures.append("line_graph_not_complete")
        failed_line_ids = sorted(
            {
                _record_id(line) or 0
                for line in lines
                if _line_external_effect_present(
                    line,
                    move_id=move_id,
                    company_id=company_id,
                    parent_state="draft",
                )
            }
        )
        side_effect_line_ids = {
            _record_id(line) or 0
            for line in lines
            if (
                str(getattr(line, "display_type", "") or "")
                not in {"line_section", "line_subsection", "line_note"}
                and _record_id(getattr(line, "partner_id", None))
                != partner_id
            )
            or getattr(line, "matching_number", False)
            not in {False, None, ""}
            or _decimal(getattr(line, "deductible_amount", None))
            != Decimal("100")
        }
        if side_effect_line_ids:
            failures.append(
                "line_partner_matching_or_deductibility_side_effect"
            )
            failed_line_ids = sorted(
                {*failed_line_ids, *side_effect_line_ids}
            )
        if failed_line_ids:
            failures.append(
                "line_reconciliation_or_external_effect_present"
            )
        invoice_line_set = set(invoice_line_ids)
        payment_term_line_id = None
        payment_term_account_id = None
        if (
            not invoice_line_ids
            or not invoice_line_set.issubset(line_ids)
        ):
            failures.append("invoice_line_graph_not_complete")
        else:
            tax_lines = [
                line
                for line in lines
                if _record_id(line) not in invoice_line_set
                and _record_id(getattr(line, "tax_line_id", None))
                is not None
            ]
            term_lines = [
                line
                for line in lines
                if _record_id(line) not in invoice_line_set
                and line not in tax_lines
            ]
            if len(term_lines) == 1:
                payment_term_line_id = _record_id(term_lines[0])
                payment_term_account_id = _record_id(
                    getattr(term_lines[0], "account_id", None)
                )
            expected_term_type = (
                "liability_payable"
                if expected_move_type == "in_invoice"
                else "asset_receivable"
            )
            if (
                len(term_lines) != 1
                or str(
                    getattr(term_lines[0], "display_type", "") or ""
                )
                != "payment_term"
                or str(
                    getattr(
                        getattr(term_lines[0], "account_id", None),
                        "account_type",
                        "",
                    )
                    or ""
                )
                != expected_term_type
            ):
                failures.append("payment_term_graph_invalid")

        if not _taxless_document_graph_is_exact(
            move,
            lines,
            invoice_line_ids,
            company_id=company_id,
            commercial_partner_id=commercial_partner_id or 0,
            vendor=vendor,
            expected_term_date=due_date,
            require_company_currency_amount_graph=True,
        ):
            failures.append(
                "taxless_financial_and_dependency_graph_not_exact"
            )
        lock_failure = _effective_posting_date_failure(
            move,
            accounting_date,
            has_taxes=any(
                _ids(getattr(line, "tax_ids", []))
                or _record_id(getattr(line, "tax_line_id", None))
                is not None
                for line in lines
            ),
            today=self._now().date(),
        )
        if lock_failure is not None:
            failures.append(lock_failure)

        eligible = not failures
        write_parameters = (
            {
                "company_id": company_id,
                "move_id": move_id,
                "expected_move_type": expected_move_type,
                "expected_document_binding": document_binding,
                "expected_document_binding_v2": document_binding_v2,
                "expected_business_binding": business_binding,
                "expected_partner_id": partner_id,
                "expected_journal_id": journal_id,
                "expected_currency_id": currency_id,
                "expected_payment_term_line_id": payment_term_line_id,
                "expected_payment_term_account_id": (
                    payment_term_account_id
                ),
                "expected_invoice_date": invoice_date,
                "expected_accounting_date": accounting_date,
                "expected_due_date": due_date,
                "expected_reference": reference,
                "expected_amount_untaxed": amount_untaxed,
                "expected_amount_tax": amount_tax,
                "expected_amount_total": amount_total,
                "expected_amount_residual": amount_residual,
                "expected_line_ids": line_ids,
            }
            if eligible
            else None
        )
        return {
            "candidate_write_capability_id": (
                candidate_write_capability_id
            ),
            "basis": "odoo_pristine_v3_document_post_eligibility_read",
            "filters": {
                "company_id": company_id,
                "move_id": move_id,
                "expected_move_type": expected_move_type,
            },
            "target": {
                "company_id": company_id,
                "move_id": move_id,
                "move_type": move_type,
                "state": state,
                "posted_before": getattr(move, "posted_before", None),
                "payment_state": payment_state,
                "document_binding": document_binding,
                "document_binding_v2": document_binding_v2,
                "business_binding": business_binding,
                "partner_id": partner_id,
                "journal_id": journal_id,
                "currency_id": currency_id,
                "payment_term_line_id": payment_term_line_id,
                "payment_term_account_id": payment_term_account_id,
                "invoice_date": invoice_date,
                "accounting_date": accounting_date,
                "due_date": due_date,
                "reference": reference,
                "amount_untaxed": amount_untaxed,
                "amount_tax": amount_tax,
                "amount_total": amount_total,
                "amount_residual": amount_residual,
                "line_ids": line_ids,
                "invoice_line_ids": invoice_line_ids,
            },
            "eligible": eligible,
            "eligibility_failures": sorted(set(failures)),
            "failed_line_ids": failed_line_ids,
            "checks": [
                "bound_company_and_read_acl",
                "single_visible_invoice_or_bill",
                "pristine_v3_draft_and_bindings",
                "complete_document_identity_binding",
                "move_line_and_partner_write_acl",
                "self_commercial_partner_rank_zero",
                "active_currency_journal_and_company_currency",
                "company_currency_taxless_financial_dependency_graph_exact",
                "payment_term_line_and_account_bound",
                "effective_odoo_lock_date_open",
                "fully_unpaid_residual_matches_total",
                "no_payment_reconciliation_or_external_effects",
                "complete_line_guard_graph",
            ],
            "required_user_parameters": ["idempotency_key", "reason"],
            "write_parameters": write_parameters,
            "page": {"count": 1, "total_count": 1},
        }

    def _read_refund_draft_cancel_eligibility(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        company_id = parameters["company_id"]
        refund_id = parameters["move_id"]
        expected_move_type = parameters["expected_move_type"]
        company = self._bound_read_company(
            context, company_id, label="refund draft cancellation"
        )
        refund = self._bound_read_move(
            refund_id,
            company_id,
            label="refund draft cancellation move",
        )
        failures: list[str] = []
        if not _acl_granted(refund, "write"):
            failures.append("refund_write_acl_denied")
        origin_id = _record_id(getattr(refund, "reversed_entry_id", None))
        if origin_id is None:
            raise OdooExecutionError(
                "refund draft cancellation origin link is unavailable"
            )
        origin = self._bound_read_move(
            origin_id,
            company_id,
            label="refund draft cancellation origin",
        )

        refund_lines = _iter_records(getattr(refund, "line_ids", []))
        origin_lines = _iter_records(getattr(origin, "line_ids", []))
        for line in [*refund_lines, *origin_lines]:
            _check_read_acl(line)
        if any(
            not _acl_granted(line, "write") for line in refund_lines
        ):
            failures.append("refund_line_write_acl_denied")

        refund_type = str(getattr(refund, "move_type", "") or "")
        origin_type = str(getattr(origin, "move_type", "") or "")
        refund_state = str(getattr(refund, "state", "") or "")
        origin_state = str(getattr(origin, "state", "") or "")
        refund_payment_state = str(
            getattr(refund, "payment_state", "") or ""
        )
        origin_payment_state = str(
            getattr(origin, "payment_state", "") or ""
        )
        document_binding = str(
            getattr(refund, "odoo_cli_v3_document_binding", "") or ""
        )
        raw_document_binding_v2 = getattr(
            refund, "odoo_cli_v3_document_binding_v2", None
        )
        document_binding_v2 = str(raw_document_binding_v2 or "")
        business_binding = str(
            getattr(refund, "odoo_cli_v3_business_binding", "") or ""
        )
        origin_document_binding = str(
            getattr(origin, "odoo_cli_v3_document_binding", "") or ""
        )
        raw_origin_document_binding_v2 = getattr(
            origin, "odoo_cli_v3_document_binding_v2", None
        )
        origin_document_binding_v2 = str(
            raw_origin_document_binding_v2 or ""
        )
        origin_business_binding = str(
            getattr(origin, "odoo_cli_v3_business_binding", "") or ""
        )
        partner = getattr(refund, "partner_id", None)
        journal = getattr(refund, "journal_id", None)
        currency = getattr(refund, "currency_id", None)
        origin_partner = getattr(origin, "partner_id", None)
        origin_journal = getattr(origin, "journal_id", None)
        origin_currency = getattr(origin, "currency_id", None)
        commercial_partner = getattr(
            refund, "commercial_partner_id", None
        )
        origin_commercial_partner = getattr(
            origin, "commercial_partner_id", None
        )
        partner_id = _record_id(partner)
        journal_id = _record_id(journal)
        currency_id = _record_id(currency)
        commercial_partner_id = _record_id(commercial_partner)
        origin_commercial_partner_id = _record_id(
            origin_commercial_partner
        )
        self._read_related_acl(
            partner,
            commercial_partner,
            journal,
            currency,
            origin_partner,
            origin_commercial_partner,
            origin_journal,
            origin_currency,
        )

        refund_date = _date_text(getattr(refund, "invoice_date", None))
        accounting_date = _date_text(getattr(refund, "date", None))
        total_amount = _nonnegative_decimal_text(
            getattr(refund, "amount_total", None)
        )
        residual_amount = _nonnegative_decimal_text(
            getattr(refund, "amount_residual", None)
        )
        origin_total_amount = _nonnegative_decimal_text(
            getattr(origin, "amount_total", None)
        )
        origin_residual_amount = _nonnegative_decimal_text(
            getattr(origin, "amount_residual", None)
        )
        refund_line_ids = _ids(getattr(refund, "line_ids", []))
        origin_line_ids = _ids(getattr(origin, "line_ids", []))
        refund_invoice_line_ids = _ids(
            getattr(refund, "invoice_line_ids", [])
        )
        origin_invoice_line_ids = _ids(
            getattr(origin, "invoice_line_ids", [])
        )
        origin_reversal_ids = _ids(
            getattr(origin, "reversal_move_ids", [])
        )
        origin_invoice_date = _date_text(
            getattr(origin, "invoice_date", None)
            or getattr(origin, "date", None)
        )
        origin_accounting_date = _date_text(
            getattr(origin, "date", None)
        )
        origin_due_date = _date_text(
            getattr(origin, "invoice_date_due", None)
        )
        raw_origin_reference = getattr(origin, "ref", None)
        origin_reference = (
            raw_origin_reference
            if isinstance(raw_origin_reference, str)
            and raw_origin_reference.strip()
            and len(raw_origin_reference) <= 256
            else None
        )
        raw_refund_reason = getattr(
            refund, "odoo_cli_v3_reason", None
        )
        refund_reason = (
            raw_refund_reason
            if isinstance(raw_refund_reason, str)
            and raw_refund_reason.strip()
            and len(raw_refund_reason) <= 512
            else None
        )
        expected_origin_type = {
            "out_refund": "out_invoice",
            "in_refund": "in_invoice",
        }.get(expected_move_type)
        if expected_origin_type is None:
            failures.append("expected_move_type_not_allowlisted")
        if refund_type != expected_move_type:
            failures.append("move_type_mismatch")
        if refund_state != "draft":
            failures.append("refund_is_not_draft")
        if getattr(refund, "name", None) not in {False, "/"}:
            failures.append("refund_non_pristine_name_or_sequence")
        if getattr(refund, "posted_before", None) is not False:
            failures.append("refund_posted_before_not_false")
        if str(getattr(refund, "auto_post", "") or "") != "no":
            failures.append("refund_auto_post_not_disabled")
        if getattr(refund, "auto_post_until", None) not in {False, None}:
            failures.append("refund_auto_post_until_present")
        if getattr(refund, "sequence_prefix", None) not in {
            False,
            None,
            "",
        } or getattr(refund, "sequence_number", None) not in {False, 0}:
            failures.append("refund_sequence_evidence_present")
        if (
            getattr(refund, "made_sequence_gap", None) is not False
            or getattr(refund, "checked", None) is not False
            or getattr(refund, "secure_sequence_number", 0)
            not in {False, 0}
            or bool(getattr(refund, "inalterable_hash", False))
            or bool(getattr(refund, "need_cancel_request", False))
            or bool(getattr(refund, "is_manually_modified", False))
        ):
            failures.append(
                "refund_posting_hash_edi_or_manual_mutation_evidence"
            )
        if not _valid_sha_binding(document_binding):
            failures.append("refund_document_binding_missing_or_invalid")
        if not _valid_sha_binding(document_binding_v2):
            failures.append(
                (
                    "refund_legacy_binding_requires_provenance_migration"
                    if raw_document_binding_v2 in {None, False, ""}
                    else "refund_document_binding_v2_invalid"
                )
            )
        if not _valid_sha_binding(business_binding):
            failures.append("refund_business_binding_missing_or_invalid")
        if origin_type != expected_origin_type:
            failures.append("origin_move_type_mismatch")
        if origin_state != "posted":
            failures.append("origin_is_not_posted")
        if (
            getattr(origin, "posted_before", None) is not True
            or str(getattr(origin, "name", "") or "") in {"", "/"}
            or str(getattr(origin, "auto_post", "") or "") != "no"
            or getattr(origin, "auto_post_until", None)
            not in {False, None}
        ):
            failures.append("origin_posting_identity_invalid")
        if not _valid_sha_binding(origin_document_binding):
            failures.append("origin_document_binding_missing_or_invalid")
        if not _valid_sha_binding(origin_document_binding_v2):
            failures.append(
                (
                    "origin_legacy_binding_requires_provenance_migration"
                    if raw_origin_document_binding_v2
                    in {None, False, ""}
                    else "origin_document_binding_v2_invalid"
                )
            )
        if not _valid_sha_binding(origin_business_binding):
            failures.append("origin_business_binding_missing_or_invalid")
        refund_binding_matches = [
            refund_mode
            for (
                refund_mode,
                _candidate_document,
                candidate_document_v2,
                candidate_business,
            ) in (
                _refund_graph_binding_candidates(
                    refund,
                    company_id=company_id,
                    origin_move_id=origin_id,
                    vendor=expected_move_type == "in_refund",
                )
            )
            if (
                candidate_document_v2 == document_binding_v2
                and candidate_business == business_binding
            )
        ]
        if len(refund_binding_matches) != 1:
            failures.append("refund_graph_binding_mismatch")
        origin_binding_matches: list[str] = []
        for posting_mode in ("draft", "post"):
            origin_candidate = _document_graph_binding_candidate(
                origin,
                company_id=company_id,
                vendor=expected_move_type == "in_refund",
                posting_mode=posting_mode,
            )
            if origin_candidate is not None and origin_candidate[1:] == (
                origin_document_binding_v2,
                origin_business_binding,
            ):
                origin_binding_matches.append(posting_mode)
        if len(origin_binding_matches) != 1:
            failures.append("origin_graph_binding_mismatch")
        if origin_reversal_ids != [refund_id]:
            failures.append("origin_refund_graph_mismatch")

        expected_journal_type = (
            "purchase" if expected_move_type == "in_refund" else "sale"
        )
        partner_company_id = _record_id(
            getattr(partner, "company_id", None)
        )
        if (
            partner_id is None
            or commercial_partner_id is None
            or _record_id(
                getattr(partner, "commercial_partner_id", None)
            )
            != commercial_partner_id
            or journal_id is None
            or currency_id is None
            or partner_company_id not in {None, company_id}
            or _record_id(getattr(journal, "company_id", None))
            != company_id
            or str(getattr(journal, "type", "") or "")
            != expected_journal_type
            or getattr(journal, "active", True) is False
        ):
            failures.append("refund_identity_binding_invalid")
        if (
            _record_id(origin_partner) != partner_id
            or origin_commercial_partner_id
            != commercial_partner_id
            or _record_id(
                getattr(origin_partner, "commercial_partner_id", None)
            )
            != origin_commercial_partner_id
            or _record_id(origin_journal) != journal_id
            or _record_id(origin_currency) != currency_id
            or _record_id(
                getattr(origin_journal, "company_id", None)
            )
            != company_id
            or str(getattr(origin_journal, "type", "") or "")
            != expected_journal_type
            or getattr(origin_journal, "active", True) is False
            or _record_id(
                getattr(origin_partner, "company_id", None)
            )
            not in {None, company_id}
        ):
            failures.append("refund_origin_identity_mismatch")
        if (
            getattr(partner, "active", True) is False
            or not _record_company_bound(
                partner, company_id, shared=True
            )
        ):
            failures.append("refund_partner_inactive_or_scope_invalid")
        if not _currency_journal_company_graph_valid(
            currency,
            journal,
            company,
            currency_id=currency_id,
            company_id=company_id,
            journal_type=expected_journal_type,
        ):
            failures.append(
                "refund_currency_journal_or_company_configuration_invalid"
            )
        if (
            currency_id
            != _record_id(getattr(company, "currency_id", None))
            or getattr(company, "account_storno", None) is not False
        ):
            failures.append(
                "refund_company_currency_non_storno_scope_invalid"
            )
        if refund_date is None or accounting_date != refund_date:
            failures.append("refund_date_binding_invalid")
        if (
            origin_invoice_date is None
            or (
                refund_date is not None
                and refund_date < origin_invoice_date
            )
        ):
            failures.append("refund_date_precedes_or_lacks_origin_date")
        if total_amount is None or residual_amount is None:
            failures.append("refund_amount_binding_invalid")
        elif (
            Decimal(total_amount) <= 0
            or Decimal(residual_amount) <= 0
        ):
            failures.append("refund_total_or_residual_not_positive")
        if refund_payment_state != "not_paid":
            failures.append("refund_payment_state_not_not_paid")
        if not _amounts_equal_abs(
            getattr(refund, "amount_residual", None),
            getattr(refund, "amount_total", None),
        ):
            failures.append("refund_residual_total_mismatch")
        if (
            origin_total_amount is None
            or origin_residual_amount is None
        ):
            failures.append("origin_amount_binding_invalid")
        elif (
            Decimal(origin_total_amount) <= 0
            or Decimal(origin_residual_amount) <= 0
        ):
            failures.append("origin_total_or_residual_not_positive")
        if origin_payment_state != "not_paid":
            failures.append("origin_payment_state_not_not_paid")
        if not _amounts_equal_abs(
            getattr(origin, "amount_residual", None),
            getattr(origin, "amount_total", None),
        ):
            failures.append("origin_residual_total_mismatch")

        if _has_refund_move_external_effect(
            refund,
            allowed_reversed_entry_id=origin_id,
            allowed_reversal_move_ids=frozenset(),
        ):
            failures.append(
                "refund_payment_or_external_effect_present"
            )
        if _has_refund_move_external_effect(
            origin,
            allowed_reversed_entry_id=None,
            allowed_reversal_move_ids=frozenset({refund_id}),
        ):
            failures.append(
                "origin_payment_or_external_effect_present"
            )
        if self._has_exchange_or_caba_effect([refund_id, origin_id]):
            failures.append(
                "refund_or_origin_exchange_or_caba_effect_present"
            )

        observed_refund_line_ids = [
            _record_id(line) for line in refund_lines
        ]
        if (
            len(refund_line_ids) < 2
            or len(refund_line_ids) > 1000
            or len(refund_lines) != len(refund_line_ids)
            or any(
                line_id is None for line_id in observed_refund_line_ids
            )
            or sorted(observed_refund_line_ids) != refund_line_ids
        ):
            failures.append("refund_line_graph_not_complete")
        if (
            not refund_invoice_line_ids
            or not set(refund_invoice_line_ids).issubset(
                refund_line_ids
            )
        ):
            failures.append("refund_invoice_line_graph_not_complete")
        observed_origin_line_ids = [
            _record_id(line) for line in origin_lines
        ]
        if (
            len(origin_line_ids) < 2
            or len(origin_line_ids) > 1000
            or len(origin_lines) != len(origin_line_ids)
            or any(
                line_id is None for line_id in observed_origin_line_ids
            )
            or sorted(observed_origin_line_ids) != origin_line_ids
        ):
            failures.append("origin_line_graph_not_complete")
        if (
            not origin_invoice_line_ids
            or not set(origin_invoice_line_ids).issubset(
                origin_line_ids
            )
        ):
            failures.append("origin_invoice_line_graph_not_complete")
        failed_refund_line_ids = sorted(
            {
                _record_id(line) or 0
                for line in refund_lines
                if _line_external_effect_present(
                    line,
                    move_id=refund_id,
                    company_id=company_id,
                    parent_state="draft",
                )
            }
        )
        if failed_refund_line_ids:
            failures.append(
                "refund_line_reconciliation_or_external_effect_present"
            )
        failed_origin_line_ids = sorted(
            {
                _record_id(line) or 0
                for line in origin_lines
                if _line_external_effect_present(
                    line,
                    move_id=origin_id,
                    company_id=company_id,
                    parent_state="posted",
                )
            }
        )
        if failed_origin_line_ids:
            failures.append(
                "origin_line_reconciliation_or_external_effect_present"
            )

        source_refund_mode = (
            refund_binding_matches[0]
            if len(refund_binding_matches) == 1
            else None
        )
        vendor = expected_move_type == "in_refund"
        if (
            _record_id(
                getattr(refund, "invoice_payment_term_id", None)
            )
            is not None
            or _date_text(getattr(refund, "invoice_date_due", None))
            != refund_date
        ):
            failures.append("refund_payment_term_binding_invalid")
        if not _taxless_document_graph_is_exact(
            origin,
            origin_lines,
            origin_invoice_line_ids,
            company_id=company_id,
            commercial_partner_id=commercial_partner_id or 0,
            vendor=vendor,
            expected_term_date=origin_due_date,
            require_company_currency_amount_graph=True,
        ):
            failures.append(
                "origin_taxless_financial_dependency_graph_not_exact"
            )
        if not _taxless_document_graph_is_exact(
            refund,
            refund_lines,
            refund_invoice_line_ids,
            company_id=company_id,
            commercial_partner_id=commercial_partner_id or 0,
            vendor=vendor,
            expected_term_date=refund_date,
            require_company_currency_amount_graph=True,
        ):
            failures.append(
                "refund_taxless_financial_dependency_graph_not_exact"
            )
        if source_refund_mode == "full":
            if (
                len(refund_invoice_line_ids)
                != len(origin_invoice_line_ids)
                or not _linewise_reversal_is_exact(
                    origin_lines, refund_lines
                )
            ):
                failures.append("full_refund_linewise_reversal_not_exact")
            if not _full_refund_invoice_lineage_is_exact(
                origin_lines,
                refund_lines,
                origin_move_id=origin_id,
                origin_invoice_line_ids=origin_invoice_line_ids,
                refund_invoice_line_ids=refund_invoice_line_ids,
            ):
                failures.append("full_refund_invoice_lineage_not_exact")
        if source_refund_mode == "partial":
            refund_total = _decimal(getattr(refund, "amount_total", None))
            origin_total = _decimal(getattr(origin, "amount_total", None))
            if (
                refund_total is None
                or origin_total is None
                or not refund_total.is_finite()
                or not origin_total.is_finite()
                or abs(refund_total) > abs(origin_total)
            ):
                failures.append("partial_refund_total_exceeds_origin")
            if not _partial_refund_origin_line_relation_is_exact(
                origin_lines,
                refund_lines,
                origin_invoice_line_ids=origin_invoice_line_ids,
                refund_invoice_line_ids=refund_invoice_line_ids,
            ):
                failures.append(
                    "partial_refund_origin_line_relation_not_exact"
                )

        eligible = not failures
        write_parameters = (
            {
                "company_id": company_id,
                "move_id": refund_id,
                "expected_move_type": expected_move_type,
                "expected_origin_move_id": origin_id,
                "expected_document_binding": document_binding,
                "expected_document_binding_v2": document_binding_v2,
                "expected_business_binding": business_binding,
                "expected_origin_document_binding": (
                    origin_document_binding
                ),
                "expected_origin_document_binding_v2": (
                    origin_document_binding_v2
                ),
                "expected_origin_business_binding": (
                    origin_business_binding
                ),
                "expected_partner_id": partner_id,
                "expected_journal_id": journal_id,
                "expected_currency_id": currency_id,
                "expected_refund_date": refund_date,
                "expected_total_amount": total_amount,
                "expected_line_ids": refund_line_ids,
                "expected_origin_line_ids": origin_line_ids,
            }
            if eligible
            else None
        )
        return {
            "candidate_write_capability_id": (
                "acct.refund.draft_cancel.v1"
            ),
            "basis": (
                "odoo_pristine_v3_refund_and_origin_graph_"
                "draft_cancel_eligibility_read"
            ),
            "filters": {
                "company_id": company_id,
                "move_id": refund_id,
                "expected_move_type": expected_move_type,
            },
            "target": {
                "refund": {
                    "company_id": company_id,
                    "move_id": refund_id,
                    "move_type": refund_type,
                    "state": refund_state,
                    "posted_before": getattr(
                        refund, "posted_before", None
                    ),
                    "payment_state": refund_payment_state,
                    "document_binding": document_binding,
                    "document_binding_v2": document_binding_v2,
                    "business_binding": business_binding,
                    "origin_move_id": origin_id,
                    "partner_id": partner_id,
                    "journal_id": journal_id,
                    "currency_id": currency_id,
                    "refund_date": refund_date,
                    "accounting_date": accounting_date,
                    "reason": refund_reason,
                    "amount_total": total_amount,
                    "amount_residual": residual_amount,
                    "line_ids": refund_line_ids,
                    "invoice_line_ids": refund_invoice_line_ids,
                    "source_refund_mode": (
                        source_refund_mode
                    ),
                },
                "origin": {
                    "company_id": company_id,
                    "move_id": origin_id,
                    "move_type": origin_type,
                    "state": origin_state,
                    "posted_before": getattr(
                        origin, "posted_before", None
                    ),
                    "payment_state": origin_payment_state,
                    "document_binding": origin_document_binding,
                    "document_binding_v2": (
                        origin_document_binding_v2
                    ),
                    "business_binding": origin_business_binding,
                    "partner_id": _record_id(origin_partner),
                    "journal_id": _record_id(origin_journal),
                    "currency_id": _record_id(origin_currency),
                    "amount_total": origin_total_amount,
                    "amount_residual": origin_residual_amount,
                    "invoice_date": origin_invoice_date,
                    "accounting_date": origin_accounting_date,
                    "due_date": origin_due_date,
                    "reference": origin_reference,
                    "line_ids": origin_line_ids,
                    "invoice_line_ids": origin_invoice_line_ids,
                    "reversal_move_ids": origin_reversal_ids,
                    "source_posting_mode": (
                        origin_binding_matches[0]
                        if len(origin_binding_matches) == 1
                        else None
                    ),
                },
            },
            "eligible": eligible,
            "eligibility_failures": sorted(set(failures)),
            "failed_refund_line_ids": failed_refund_line_ids,
            "failed_origin_line_ids": failed_origin_line_ids,
            "checks": [
                "bound_company_and_read_acl",
                "single_visible_v3_draft_refund",
                "single_visible_bound_posted_origin",
                "exact_refund_origin_reversal_graph",
                "immutable_refund_and_origin_bindings",
                "refund_and_refund_line_write_acl",
                "active_partner_currency_journal_and_company_scope",
                "company_currency_and_non_storno_scope",
                "taxless_financial_dependency_graphs_exact",
                "full_refund_linewise_reversal_exact_when_applicable",
                "full_refund_invoice_lineage_exact_when_applicable",
                "partial_refund_total_within_origin_when_applicable",
                "partial_refund_origin_line_relation_exact_when_applicable",
                "fully_unpaid_residuals_match_totals",
                "no_payment_reconciliation_or_external_effects",
                "complete_refund_and_origin_line_guard_graphs",
            ],
            "required_user_parameters": ["idempotency_key", "reason"],
            "write_parameters": write_parameters,
            "page": {"count": 2, "total_count": 2},
        }

    def _read_draft_cancel_eligibility(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        company_id = parameters["company_id"]
        move_id = parameters["move_id"]
        expected_move_type = parameters["expected_move_type"]
        if company_id != context.company_id or company_id not in context.allowed_company_ids:
            raise OdooExecutionError("draft cancellation company is outside the signed binding")

        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise OdooExecutionError("draft cancellation company does not exist or is not visible")
        _check_read_acl(company)

        move = self._env["account.move"].browse(move_id).exists()
        if not move or len(move) != 1:
            raise OdooExecutionError("draft cancellation move does not exist or is not visible")
        _check_read_acl(move)
        if _record_id(getattr(move, "company_id", None)) != company_id:
            raise OdooExecutionError("draft cancellation move is outside the bound company")

        lines = _iter_records(getattr(move, "line_ids", []))
        for line in lines:
            _check_read_acl(line)

        move_type = str(getattr(move, "move_type", "") or "")
        state = str(getattr(move, "state", "") or "")
        document_binding = str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
        raw_document_binding_v2 = getattr(
            move, "odoo_cli_v3_document_binding_v2", None
        )
        document_binding_v2 = str(raw_document_binding_v2 or "")
        business_binding = str(getattr(move, "odoo_cli_v3_business_binding", "") or "")
        vendor = expected_move_type == "in_invoice"
        journal = getattr(move, "journal_id", None)
        currency = getattr(move, "currency_id", None)
        line_ids = _ids(getattr(move, "line_ids", []))
        failures: list[str] = []

        if not _acl_granted(move, "write"):
            failures.append("move_write_acl_denied")
        if any(not _acl_granted(line, "write") for line in lines):
            failures.append("line_write_acl_denied")
        if expected_move_type not in {"out_invoice", "in_invoice"}:
            failures.append("expected_move_type_not_allowlisted")
        if move_type != expected_move_type:
            failures.append("move_type_mismatch")
        if state != "draft":
            failures.append("move_is_not_draft")
        if getattr(move, "name", None) not in {False, "/"}:
            failures.append("non_pristine_name_or_sequence")
        if getattr(move, "posted_before", None) is not False:
            failures.append("posted_before_not_false")
        if str(getattr(move, "auto_post", "") or "") != "no":
            failures.append("auto_post_not_disabled")
        if getattr(move, "auto_post_until", None) not in {False, None}:
            failures.append("auto_post_until_present")
        if getattr(move, "sequence_prefix", None) not in {False, None, ""}:
            failures.append("sequence_prefix_present")
        if getattr(move, "sequence_number", None) not in {False, 0}:
            failures.append("sequence_number_present")
        if getattr(move, "made_sequence_gap", None) is not False:
            failures.append("sequence_gap_flag_present")
        if getattr(move, "checked", None) is not False:
            failures.append("checked_flag_present")
        if (
            _record_id(journal) is None
            or _record_id(getattr(journal, "company_id", None)) != company_id
            or str(getattr(journal, "type", "") or "") != ("purchase" if vendor else "sale")
            or getattr(journal, "active", True) is False
        ):
            failures.append("journal_not_active_expected_type")
        if not _valid_sha_binding(document_binding):
            failures.append("document_binding_missing_or_invalid")
        if not _valid_sha_binding(document_binding_v2):
            failures.append(
                (
                    "legacy_binding_requires_provenance_migration"
                    if raw_document_binding_v2 in {None, False, ""}
                    else "document_binding_v2_invalid"
                )
            )
        if not _valid_sha_binding(business_binding):
            failures.append("business_binding_missing_or_invalid")
        graph_binding = _document_graph_binding_candidate(
            move,
            company_id=company_id,
            vendor=expected_move_type == "in_invoice",
            posting_mode="draft",
        )
        if (
            graph_binding is None
            or graph_binding[1:]
            != (document_binding_v2, business_binding)
        ):
            failures.append("document_graph_binding_mismatch")
        if _record_id(currency) is None:
            failures.append("currency_missing")
        if str(getattr(move, "payment_state", "") or "") != "not_paid":
            failures.append("payment_state_not_not_paid")
        if not _amounts_equal_abs(
            getattr(move, "amount_residual", None), getattr(move, "amount_total", None)
        ):
            failures.append("residual_total_mismatch")
        if (
            getattr(move, "secure_sequence_number", 0) not in {False, 0}
            or bool(getattr(move, "inalterable_hash", False))
            or bool(getattr(move, "need_cancel_request", False))
            or bool(getattr(move, "is_manually_modified", False))
        ):
            failures.append("posting_hash_edi_or_manual_mutation_evidence")

        if _has_draft_cancel_singular_effect_link(move):
            failures.append("singular_external_effect_link_present")
        if _has_draft_cancel_plural_effect_link(move):
            failures.append("plural_external_effect_link_present")
        if (
            bool(getattr(move, "signature", False))
            or bool(getattr(move, "is_move_sent", False))
            or getattr(move, "sending_data", False) not in (False, None, {})
            or bool(getattr(move, "is_being_sent", False))
            or getattr(move, "invoice_source_email", False) not in (False, None, "")
        ):
            failures.append("invoice_sending_signature_or_attachment_effect_present")
        if not line_ids:
            failures.append("line_graph_empty")
        if set(line_ids) != {_record_id(line) for line in lines}:
            failures.append("line_graph_not_complete")

        line_failures = []
        for line in lines:
            line_id = _record_id(line)
            if (
                _record_id(getattr(line, "move_id", None)) != move_id
                or _record_id(getattr(line, "company_id", None)) != company_id
                or str(getattr(line, "parent_state", "") or "") != "draft"
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
                or _ids(getattr(line, "reconciled_lines_excluding_exchange_diff_ids", []))
                or _record_id(getattr(line, "purchase_line_id", None)) is not None
                or _record_id(getattr(line, "expense_id", None)) is not None
                or _record_id(getattr(line, "cogs_origin_id", None)) is not None
                or bool(getattr(line, "is_landed_costs_line", False))
                or _ids(getattr(line, "move_attachment_ids", []))
                or bool(getattr(line, "is_imported", False))
                or bool(getattr(line, "is_downpayment", False))
                or getattr(line, "analytic_distribution", False) not in (False, None, {})
                or _ids(getattr(line, "analytic_line_ids", []))
                or getattr(line, "deferred_start_date", None) not in {None, False}
                or getattr(line, "deferred_end_date", None) not in {None, False}
                or str(getattr(line, "display_type", "") or "") == "cogs"
            ):
                line_failures.append(line_id or 0)
        if line_failures:
            failures.append("line_reconciliation_or_external_effect_present")

        checks = [
            "bound_company_read_acl",
            "single_visible_move",
            "expected_move_type_allowlist",
            "pristine_draft_state_and_sequence",
            "immutable_v3_document_bindings_present",
            "move_and_complete_line_graph_write_acl",
            "active_sale_or_purchase_journal",
            "fully_unpaid_residual_matches_total",
            "no_payment_reconciliation_tax_asset_or_edi_links",
            "complete_line_guard_graph",
        ]
        eligible = not failures
        write_parameters = (
            {
                "company_id": company_id,
                "move_id": move_id,
                "expected_move_type": expected_move_type,
                "expected_document_binding": document_binding,
                "expected_document_binding_v2": document_binding_v2,
                "expected_business_binding": business_binding,
            }
            if eligible
            else None
        )
        return {
            "candidate_write_capability_id": "acct.move.draft_cancel.v1",
            "basis": "odoo_pristine_v3_draft_cancel_eligibility_read",
            "filters": {
                "company_id": company_id,
                "move_id": move_id,
                "expected_move_type": expected_move_type,
            },
            "target": {
                "company_id": company_id,
                "move_id": move_id,
                "move_type": move_type,
                "state": state,
                "payment_state": str(getattr(move, "payment_state", "") or ""),
                "journal_id": _record_id(journal),
                "currency_id": _record_id(currency),
                "line_ids": line_ids,
                "document_binding": document_binding,
                "document_binding_v2": document_binding_v2,
                "business_binding": business_binding,
            },
            "eligible": eligible,
            "eligibility_failures": sorted(set(failures)),
            "failed_line_ids": sorted(set(line_failures)),
            "checks": checks,
            "write_parameters": write_parameters,
            "page": {"count": 1, "total_count": 1},
        }

    def _read_handlers(
        self,
    ) -> dict[str, Callable[[RequestContext, dict[str, Any]], dict[str, Any]]]:
        return {
            "acct.registry.list.v1": self._read_registry,
            "acct.gl.trial_balance.v1": self._read_trial_balance,
            "acct.ar.open_items.v1": self._read_ar_open_items,
            "acct.ap.open_items.v1": self._read_ap_open_items,
            "acct.multicompany.consolidated_read.v1": self._read_multicompany_consolidated,
            "acct.multicurrency.balance_read.v1": self._read_multicurrency_balance,
            "acct.move.document_post_eligibility.v1": self._read_document_post_eligibility,
            "acct.move.draft_cancel_eligibility.v1": self._read_draft_cancel_eligibility,
            "acct.refund.draft_cancel_eligibility.v1": self._read_refund_draft_cancel_eligibility,
            "acct.report.financial_read.v1": self._read_financial_report,
            "acct.tax.report_read.v1": self._read_tax_report,
        }

    def __call__(
        self,
        context: RequestContext,
        capability: Capability,
        parameters: dict[str, Any],
        registry_digest: str,
        release_digest: str,
    ) -> dict[str, Any]:
        self._assert_runtime_binding(context)
        if not hmac.compare_digest(release_digest, self._release_digest):
            raise OdooExecutionError("Odoo executor release binding mismatch")
        registered = self._capability_map.get(capability.id)
        if registered is None or registered.data != capability.data:
            raise OdooExecutionError("read capability is not in the trusted registry")
        handler = self._read_handlers().get(capability.id)
        if handler is None:
            raise OdooExecutionError("read capability has no trusted Odoo handler")
        body = handler(context, parameters)
        receipt = create_read_receipt(
            receipt_id=self._receipt_id_factory(),
            capability_id=capability.id,
            parameters=parameters,
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=registry_digest,
            release_digest=release_digest,
            environment=self._environment,
            capability_channel=self._capability_channel,
            record_count=body["page"]["total_count"],
            observed_at=self._now(),
            key_id=self._receipt_key_id,
            secret=self._receipt_secret,
        )
        return {**body, "receipt": receipt}

    def verify(
        self,
        context: RequestContext,
        capability: Capability,
        parameters: dict[str, Any],
        result: dict[str, Any],
        registry_digest: str,
        release_digest: str,
    ) -> None:
        self._assert_runtime_binding(context)
        if not hmac.compare_digest(release_digest, self._release_digest):
            raise OdooExecutionError("Odoo executor release binding mismatch")
        body = {key: value for key, value in result.items() if key != "receipt"}
        verify_read_receipt(
            result.get("receipt"),
            capability_id=capability.id,
            parameters=parameters,
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=registry_digest,
            release_digest=release_digest,
            environment=self._environment,
            capability_channel=self._capability_channel,
            expected_record_count=body["page"]["total_count"],
            now=self._now(),
            consume_receipt=self._consume_receipt,
            expected_key_id=self._receipt_key_id,
            secret=self._receipt_secret,
        )

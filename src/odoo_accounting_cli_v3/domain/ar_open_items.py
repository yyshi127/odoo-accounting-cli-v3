"""Historical accounts-receivable open items with Decimal-safe residuals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Protocol


class OpenItemsError(ValueError):
    pass


MAX_SOURCE_LINES = 10_000


@dataclass(frozen=True)
class CurrencyInfo:
    id: int
    name: str
    symbol: str
    rounding: Decimal


@dataclass(frozen=True)
class OpenItemSource:
    move_line_id: int
    move_id: int
    move_name: str
    move_type: str
    payment_id: int | None
    line_date: date
    due_date: date | None
    partner_id: int | None
    partner_name: str
    account_id: int
    account_code: str
    account_name: str
    journal_id: int
    journal_code: str
    currency: CurrencyInfo
    balance: Decimal
    amount_currency: Decimal
    current_reconciled: bool


@dataclass(frozen=True)
class OpenItemPartial:
    debit_company: Decimal = Decimal("0")
    credit_company: Decimal = Decimal("0")
    debit_currency: Decimal = Decimal("0")
    credit_currency: Decimal = Decimal("0")
    matched_count: int = 0


class ArOpenItemsBackend(Protocol):
    def assert_read_access(self, *, company_id: int) -> None: ...

    def company_currency(self, *, company_id: int) -> CurrencyInfo: ...

    def assert_partner(self, *, company_id: int, partner_id: int) -> None: ...

    def currency(self, *, currency_id: int) -> CurrencyInfo: ...

    def source_lines(
        self,
        *,
        company_id: int,
        as_of_date: date,
        partner_id: int | None,
        currency_id: int | None,
        candidate_limit: int,
    ) -> list[OpenItemSource]: ...

    def partials_as_of(
        self, *, company_id: int, move_line_ids: set[int], as_of_date: date
    ) -> dict[int, OpenItemPartial]: ...


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise OpenItemsError(f"{field} must be a positive integer")
    return value


def _optional_positive_integer(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _positive_integer(value, field)


def _date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        raise OpenItemsError(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise OpenItemsError(f"{field} must be an ISO date") from exc


def _decimal(value: Any, field: str) -> Decimal:
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise OpenItemsError(f"{field} is not a decimal amount") from exc
    if not result.is_finite():
        raise OpenItemsError(f"{field} must be finite")
    return result


def _validate_currency(value: CurrencyInfo, field: str) -> CurrencyInfo:
    if not isinstance(value, CurrencyInfo):
        raise OpenItemsError(f"{field} is invalid")
    _positive_integer(value.id, f"{field}.id")
    if not isinstance(value.name, str) or not value.name:
        raise OpenItemsError(f"{field}.name is invalid")
    rounding = _decimal(value.rounding, f"{field}.rounding")
    if rounding <= 0:
        raise OpenItemsError(f"{field}.rounding must be positive")
    return value


def _round(value: Decimal, increment: Decimal) -> Decimal:
    increment = _decimal(increment, "currency rounding")
    if increment <= 0:
        raise OpenItemsError("currency rounding must be positive")
    return (value / increment).quantize(Decimal("1"), rounding=ROUND_HALF_UP) * increment


def _format(value: Decimal, increment: Decimal) -> str:
    rounded = _round(value, increment)
    places = max(0, -increment.normalize().as_tuple().exponent)
    return f"{rounded:.{places}f}"


def _is_zero(value: Decimal, increment: Decimal) -> bool:
    return _round(value, increment) == 0


def _aging(as_of_date: date, due_date: date | None) -> tuple[int | None, str]:
    if due_date is None:
        return None, "no_due_date"
    days = (as_of_date - due_date).days
    if days <= 0:
        return days, "current"
    if days <= 30:
        return days, "days_1_30"
    if days <= 60:
        return days, "days_31_60"
    if days <= 90:
        return days, "days_61_90"
    return days, "over_90"


def _company_summary(
    rows: list[tuple[dict[str, Any], Decimal, Decimal]], rounding: Decimal
) -> dict[str, Any]:
    residuals = [company_residual for _row, company_residual, _currency_residual in rows]
    debit = sum((value for value in residuals if value > 0), Decimal("0"))
    credit = -sum((value for value in residuals if value < 0), Decimal("0"))
    return {
        "item_count": len(rows),
        "debit_residual": _format(debit, rounding),
        "credit_residual": _format(credit, rounding),
        "net_residual": _format(debit - credit, rounding),
    }


def _validate_partial(value: OpenItemPartial, line_id: int) -> OpenItemPartial:
    if not isinstance(value, OpenItemPartial):
        raise OpenItemsError(f"partial totals for move line {line_id} are invalid")
    amounts = (
        value.debit_company,
        value.credit_company,
        value.debit_currency,
        value.credit_currency,
    )
    if any(_decimal(item, "partial amount") < 0 for item in amounts):
        raise OpenItemsError("partial reconcile amounts must not be negative")
    if (
        isinstance(value.matched_count, bool)
        or not isinstance(value.matched_count, int)
        or value.matched_count < 0
    ):
        raise OpenItemsError("partial reconcile count is invalid")
    return value


def read_ar_open_items(
    backend: ArOpenItemsBackend,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Return a strict historical result body; the trusted executor adds a receipt."""

    company_id = _positive_integer(parameters.get("company_id"), "company_id")
    as_of_date = _date(parameters.get("as_of_date"), "as_of_date")
    partner_id = _optional_positive_integer(parameters.get("partner_id"), "partner_id")
    currency_id = _optional_positive_integer(parameters.get("currency_id"), "currency_id")
    limit = _positive_integer(parameters.get("limit"), "limit")
    if limit > 500:
        raise OpenItemsError("limit must not exceed 500")
    offset = parameters.get("offset")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise OpenItemsError("offset must be a non-negative integer")

    backend.assert_read_access(company_id=company_id)
    company_currency = _validate_currency(
        backend.company_currency(company_id=company_id), "company currency"
    )
    if partner_id is not None:
        backend.assert_partner(company_id=company_id, partner_id=partner_id)
    if currency_id is not None:
        selected_currency = _validate_currency(
            backend.currency(currency_id=currency_id), "requested currency"
        )
        if selected_currency.id != currency_id:
            raise OpenItemsError("requested currency binding mismatch")

    sources = backend.source_lines(
        company_id=company_id,
        as_of_date=as_of_date,
        partner_id=partner_id,
        currency_id=currency_id,
        candidate_limit=MAX_SOURCE_LINES + 1,
    )
    if not isinstance(sources, list) or any(
        not isinstance(item, OpenItemSource) for item in sources
    ):
        raise OpenItemsError("open-item source lines are invalid")
    if len(sources) > MAX_SOURCE_LINES:
        raise OpenItemsError(
            f"open-item candidate set exceeds the staged safety limit of {MAX_SOURCE_LINES}"
        )
    source_ids = [item.move_line_id for item in sources]
    if len(source_ids) != len(set(source_ids)):
        raise OpenItemsError("open-item source lines contain duplicate IDs")
    if any(item.line_date > as_of_date for item in sources):
        raise OpenItemsError("open-item source line is after as_of_date")

    partials = backend.partials_as_of(
        company_id=company_id,
        move_line_ids=set(source_ids),
        as_of_date=as_of_date,
    )
    if not isinstance(partials, dict) or not set(partials).issubset(source_ids):
        raise OpenItemsError("partial reconcile totals are invalid")

    rows: list[tuple[dict[str, Any], Decimal, Decimal]] = []
    for source in sources:
        currency = _validate_currency(source.currency, "line currency")
        if currency_id is not None and currency.id != currency_id:
            raise OpenItemsError("backend returned a line outside the currency filter")
        if partner_id is not None and source.partner_id != partner_id:
            raise OpenItemsError("backend returned a line outside the partner filter")
        partial = _validate_partial(
            partials.get(source.move_line_id, OpenItemPartial()), source.move_line_id
        )
        balance = _decimal(source.balance, "line balance")
        amount_currency = _decimal(source.amount_currency, "line amount_currency")
        company_residual = _round(
            balance - partial.debit_company + partial.credit_company,
            company_currency.rounding,
        )
        currency_residual = _round(
            amount_currency - partial.debit_currency + partial.credit_currency,
            currency.rounding,
        )
        if _is_zero(company_residual, company_currency.rounding) and _is_zero(
            currency_residual, currency.rounding
        ):
            continue
        direction_amount = (
            company_residual
            if not _is_zero(company_residual, company_currency.rounding)
            else currency_residual
        )
        days_overdue, aging_bucket = _aging(as_of_date, source.due_date)
        rows.append(
            (
                {
                    "move_line_id": _positive_integer(
                        source.move_line_id, "move_line_id"
                    ),
                    "move_id": _positive_integer(source.move_id, "move_id"),
                    "move_name": str(source.move_name),
                    "move_type": str(source.move_type),
                    "payment_id": source.payment_id,
                    "line_date": source.line_date.isoformat(),
                    "due_date": (
                        source.due_date.isoformat() if source.due_date else None
                    ),
                    "partner_id": source.partner_id,
                    "partner_name": str(source.partner_name),
                    "account_id": _positive_integer(source.account_id, "account_id"),
                    "account_code": str(source.account_code),
                    "account_name": str(source.account_name),
                    "journal_id": _positive_integer(source.journal_id, "journal_id"),
                    "journal_code": str(source.journal_code),
                    "currency_id": currency.id,
                    "currency_name": currency.name,
                    "original_company_amount": _format(
                        balance, company_currency.rounding
                    ),
                    "residual_company_amount": _format(
                        company_residual, company_currency.rounding
                    ),
                    "original_currency_amount": _format(
                        amount_currency, currency.rounding
                    ),
                    "residual_currency_amount": _format(
                        currency_residual, currency.rounding
                    ),
                    "side": "debit" if direction_amount > 0 else "credit",
                    "reconciliation_status": (
                        "partially_reconciled_as_of"
                        if partial.matched_count
                        else "unreconciled_as_of"
                    ),
                    "partial_reconcile_count": partial.matched_count,
                    "current_reconciled": bool(source.current_reconciled),
                    "days_overdue": days_overdue,
                    "aging_bucket": aging_bucket,
                },
                company_residual,
                currency_residual,
            )
        )

    rows.sort(
        key=lambda item: (
            item[0]["due_date"] is None,
            item[0]["due_date"] or "9999-12-31",
            item[0]["line_date"],
            item[0]["move_line_id"],
        )
    )
    page_rows = rows[offset : offset + limit]

    currency_groups: dict[int, list[tuple[dict[str, Any], Decimal, Decimal]]] = {}
    for row in rows:
        currency_groups.setdefault(row[0]["currency_id"], []).append(row)
    currency_summaries = []
    for grouped_currency_id in sorted(currency_groups):
        grouped = currency_groups[grouped_currency_id]
        currency = next(
            source.currency
            for source in sources
            if source.currency.id == grouped_currency_id
        )
        residuals = [currency_residual for _row, _company, currency_residual in grouped]
        debit = sum((value for value in residuals if value > 0), Decimal("0"))
        credit = -sum((value for value in residuals if value < 0), Decimal("0"))
        currency_summaries.append(
            {
                "currency_id": currency.id,
                "currency_name": currency.name,
                "item_count": len(grouped),
                "debit_residual": _format(debit, currency.rounding),
                "credit_residual": _format(credit, currency.rounding),
                "net_residual": _format(debit - credit, currency.rounding),
            }
        )

    return {
        "basis": "odoo_accounting_date_current_reconciliation_graph",
        "filters": {
            "company_id": company_id,
            "as_of_date": as_of_date.isoformat(),
            "partner_id": partner_id,
            "currency_id": currency_id,
        },
        "items": [row for row, _company, _currency in page_rows],
        "page": {
            "limit": limit,
            "offset": offset,
            "count": len(page_rows),
            "total_count": len(rows),
        },
        "page_summary": _company_summary(page_rows, company_currency.rounding),
        "ledger_summary": _company_summary(rows, company_currency.rounding),
        "currency_summaries": currency_summaries,
        "company_currency": {
            "id": company_currency.id,
            "name": company_currency.name,
            "symbol": company_currency.symbol or company_currency.name,
            "rounding": format(company_currency.rounding, "f"),
        },
    }

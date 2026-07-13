"""Trial-balance domain service with Decimal-safe, pagination-stable totals."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Protocol


class TrialBalanceError(ValueError):
    pass


@dataclass(frozen=True)
class CurrencyInfo:
    id: int
    name: str
    symbol: str
    rounding: Decimal


@dataclass(frozen=True)
class AccountInfo:
    id: int
    code: str
    name: str
    account_type: str


@dataclass(frozen=True)
class Aggregate:
    debit: Decimal = Decimal("0")
    credit: Decimal = Decimal("0")
    balance: Decimal = Decimal("0")
    line_count: int = 0


class TrialBalanceBackend(Protocol):
    def assert_read_access(self, *, company_id: int) -> None: ...

    def company_currency(self, *, company_id: int) -> CurrencyInfo: ...

    def accounts(self, *, company_id: int, account_ids: set[int] | None) -> list[AccountInfo]: ...

    def opening_aggregates(
        self, *, company_id: int, before: date, account_id: int | None, include_off_balance: bool
    ) -> dict[int, Aggregate]: ...

    def period_aggregates(
        self, *, company_id: int, date_from: date, date_to: date, account_id: int | None,
        include_off_balance: bool
    ) -> dict[int, Aggregate]: ...


def _date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        raise TrialBalanceError(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise TrialBalanceError(f"{field} must be an ISO date") from exc


def _decimal(value: Any, field: str) -> Decimal:
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise TrialBalanceError(f"{field} is not a decimal amount") from exc
    if not result.is_finite():
        raise TrialBalanceError(f"{field} must be finite")
    return result


def _round(value: Decimal, increment: Decimal) -> Decimal:
    if increment <= 0 or not increment.is_finite():
        raise TrialBalanceError("currency rounding must be positive and finite")
    return (value / increment).quantize(Decimal("1"), rounding=ROUND_HALF_UP) * increment


def _format(value: Decimal, increment: Decimal) -> str:
    rounded = _round(value, increment)
    places = max(0, -increment.normalize().as_tuple().exponent)
    return f"{rounded:.{places}f}"


def _summary(rows: list[dict[str, Any]], rounding: Decimal) -> dict[str, Any]:
    opening = sum((_decimal(row["opening_balance"], "opening_balance") for row in rows), Decimal("0"))
    debit = sum((_decimal(row["period_debit"], "period_debit") for row in rows), Decimal("0"))
    credit = sum((_decimal(row["period_credit"], "period_credit") for row in rows), Decimal("0"))
    period = debit - credit
    closing = opening + period
    difference = debit - credit
    return {
        "opening_balance": _format(opening, rounding),
        "period_debit": _format(debit, rounding),
        "period_credit": _format(credit, rounding),
        "period_balance": _format(period, rounding),
        "closing_balance": _format(closing, rounding),
        "debit_credit_difference": _format(difference, rounding),
        "is_balanced": _round(difference, rounding) == 0,
    }


def read_trial_balance(
    backend: TrialBalanceBackend,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Return the strict result body; a trusted executor adds the signed receipt."""

    company_id = parameters["company_id"]
    date_from = _date(parameters["date_from"], "date_from")
    date_to = _date(parameters["date_to"], "date_to")
    if date_from > date_to:
        raise TrialBalanceError("date_from must not be after date_to")
    if parameters["opening_basis"] != "ledger_cumulative":
        raise TrialBalanceError("unsupported opening balance basis")
    account_id = parameters["account_id"]
    include_off_balance = parameters["include_off_balance"]
    include_zero = parameters["include_zero"]
    limit = parameters["limit"]
    offset = parameters["offset"]

    backend.assert_read_access(company_id=company_id)
    currency = backend.company_currency(company_id=company_id)
    requested_currency = parameters["currency_id"]
    if requested_currency is not None and requested_currency != currency.id:
        raise TrialBalanceError("presentation currency conversion is not implemented for this capability")

    opening = backend.opening_aggregates(
        company_id=company_id, before=date_from, account_id=account_id,
        include_off_balance=include_off_balance,
    )
    period = backend.period_aggregates(
        company_id=company_id, date_from=date_from, date_to=date_to, account_id=account_id,
        include_off_balance=include_off_balance,
    )
    active_ids = set(opening) | set(period)

    if account_id is not None:
        requested_accounts = backend.accounts(company_id=company_id, account_ids={account_id})
        if len(requested_accounts) != 1 or requested_accounts[0].id != account_id:
            raise TrialBalanceError("account does not exist in the bound company")
        accounts = requested_accounts if include_zero or account_id in active_ids else []
    elif include_zero:
        accounts = backend.accounts(company_id=company_id, account_ids=None)
    else:
        accounts = backend.accounts(company_id=company_id, account_ids=active_ids)

    rows: list[dict[str, Any]] = []
    for account in sorted(accounts, key=lambda item: (item.code, item.id)):
        opening_item = opening.get(account.id, Aggregate())
        period_item = period.get(account.id, Aggregate())
        opening_balance = _decimal(opening_item.balance, "opening balance")
        debit = _decimal(period_item.debit, "period debit")
        credit = _decimal(period_item.credit, "period credit")
        period_balance = debit - credit
        rows.append(
            {
                "account_id": account.id,
                "code": account.code,
                "name": account.name,
                "account_type": account.account_type,
                "opening_balance": _format(opening_balance, currency.rounding),
                "period_debit": _format(debit, currency.rounding),
                "period_credit": _format(credit, currency.rounding),
                "period_balance": _format(period_balance, currency.rounding),
                "closing_balance": _format(opening_balance + period_balance, currency.rounding),
                "move_line_count": opening_item.line_count + period_item.line_count,
            }
        )

    page_rows = rows[offset : offset + limit]
    return {
        "lines": page_rows,
        "page": {
            "limit": limit,
            "offset": offset,
            "count": len(page_rows),
            "total_count": len(rows),
        },
        "page_summary": _summary(page_rows, currency.rounding),
        "ledger_summary": _summary(rows, currency.rounding),
        "currency": {
            "id": currency.id,
            "name": currency.name,
            "symbol": currency.symbol or currency.name,
            "rounding": format(currency.rounding, "f"),
        },
    }

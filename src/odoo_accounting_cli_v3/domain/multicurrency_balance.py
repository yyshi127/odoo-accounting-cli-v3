"""Posted-ledger multicurrency balances without cutoff-rate revaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Protocol


class MulticurrencyBalanceError(ValueError):
    pass


MAX_REQUESTED_CURRENCIES = 50
MAX_BALANCE_GROUPS = 25_000
MAX_PAGE_SIZE = 500
MAX_PAGE_OFFSET = 1_000_000
RATE_RATIO_REL_TOLERANCE = Decimal("1e-12")


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
class BalanceAggregate:
    account_id: int
    currency_id: int
    company_balance: Decimal
    amount_currency: Decimal
    line_count: int


@dataclass(frozen=True)
class TechnicalRateSource:
    currency_id: int
    effective_date: date | None
    source_scope: str
    source_company_id: int | None
    source_record_id: int | None
    technical_rate: Decimal

    @classmethod
    def no_rate_identity(cls, *, currency_id: int) -> "TechnicalRateSource":
        return cls(
            currency_id=currency_id,
            effective_date=None,
            source_scope="no_rate_identity",
            source_company_id=None,
            source_record_id=None,
            technical_rate=Decimal("1"),
        )


@dataclass(frozen=True)
class EffectiveRate:
    currency_id: int
    transaction_technical_source: TechnicalRateSource
    company_technical_source: TechnicalRateSource
    transaction_to_company_rate: Decimal


class MulticurrencyBalanceBackend(Protocol):
    def assert_read_access(self, *, company_id: int) -> None: ...

    def company_currency(self, *, company_id: int) -> CurrencyInfo: ...

    def currencies(
        self, *, company_id: int, currency_ids: tuple[int, ...]
    ) -> list[CurrencyInfo]: ...

    def accounts(
        self, *, company_id: int, account_ids: set[int]
    ) -> list[AccountInfo]: ...

    def balance_aggregates(
        self,
        *,
        company_id: int,
        as_of_date: date,
        currency_ids: tuple[int, ...],
        exclude_off_balance: bool,
    ) -> list[BalanceAggregate]: ...

    def effective_rate(
        self,
        *,
        company_id: int,
        as_of_date: date,
        currency: CurrencyInfo,
        company_currency: CurrencyInfo,
    ) -> EffectiveRate: ...


def _date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        raise MulticurrencyBalanceError(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise MulticurrencyBalanceError(f"{field} must be an ISO date") from exc


def _decimal(value: Any, field: str) -> Decimal:
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise MulticurrencyBalanceError(f"{field} is not a decimal") from exc
    if not result.is_finite():
        raise MulticurrencyBalanceError(f"{field} must be finite")
    return result


def _positive_decimal(value: Any, field: str) -> Decimal:
    result = _decimal(value, field)
    if result <= 0:
        raise MulticurrencyBalanceError(f"{field} must be positive")
    return result


def _round(value: Decimal, increment: Decimal) -> Decimal:
    increment = _positive_decimal(increment, "currency rounding")
    return (value / increment).quantize(Decimal("1"), rounding=ROUND_HALF_UP) * increment


def _money(value: Decimal, increment: Decimal) -> str:
    rounded = _round(_decimal(value, "monetary amount"), increment)
    places = max(0, -increment.normalize().as_tuple().exponent)
    return f"{rounded:.{places}f}"


def _rate(value: Decimal, field: str) -> str:
    return format(_positive_decimal(value, field), "f")


def _currency_payload(currency: CurrencyInfo) -> dict[str, Any]:
    if currency.id <= 0 or not currency.name:
        raise MulticurrencyBalanceError("currency identity is invalid")
    rounding = _positive_decimal(currency.rounding, "currency rounding")
    return {
        "id": currency.id,
        "name": currency.name,
        "symbol": currency.symbol or currency.name,
        "rounding": format(rounding, "f"),
    }


def _summary(
    aggregates: list[BalanceAggregate], company_rounding: Decimal
) -> dict[str, Any]:
    company_balance = sum(
        (_decimal(item.company_balance, "ledger company balance") for item in aggregates),
        Decimal("0"),
    )
    return {
        "balance_group_count": len(aggregates),
        "account_count": len({item.account_id for item in aggregates}),
        "move_line_count": sum(item.line_count for item in aggregates),
        "ledger_company_balance": _money(company_balance, company_rounding),
    }


def _rates_match(actual: Decimal, expected: Decimal) -> bool:
    tolerance = max(abs(actual), abs(expected)) * RATE_RATIO_REL_TOLERANCE
    return abs(actual - expected) <= tolerance


def _technical_source_payload(
    item: TechnicalRateSource,
    *,
    currency: CurrencyInfo,
    as_of_date: date,
    allow_no_rate_identity: bool,
) -> dict[str, Any]:
    if item.currency_id != currency.id:
        raise MulticurrencyBalanceError("technical rate source currency binding mismatch")
    technical_rate = _positive_decimal(item.technical_rate, "Odoo technical rate")
    if item.source_scope == "no_rate_identity":
        if not allow_no_rate_identity:
            raise MulticurrencyBalanceError(
                "transaction currency requires an actual cutoff-date rate record"
            )
        if item != TechnicalRateSource.no_rate_identity(currency_id=currency.id):
            raise MulticurrencyBalanceError("no-rate identity source is invalid")
        source_model = "no_rate_identity"
    else:
        if item.source_scope not in {"company_specific", "global"}:
            raise MulticurrencyBalanceError("technical rate source scope is invalid")
        if item.effective_date is None or item.effective_date > as_of_date:
            raise MulticurrencyBalanceError(
                "technical rate source has no cutoff-date effective record"
            )
        if item.source_record_id is None or item.source_record_id <= 0:
            raise MulticurrencyBalanceError("currency rate source record is invalid")
        if item.source_scope == "company_specific":
            if item.source_company_id is None or item.source_company_id <= 0:
                raise MulticurrencyBalanceError("company-specific rate source is invalid")
        elif item.source_company_id is not None:
            raise MulticurrencyBalanceError("global rate must not claim a company source")
        source_model = "res.currency.rate"
    return {
        "currency_id": currency.id,
        "currency_name": currency.name,
        "effective_date": (
            item.effective_date.isoformat() if item.effective_date is not None else None
        ),
        "source_model": source_model,
        "source_scope": item.source_scope,
        "source_company_id": item.source_company_id,
        "source_record_id": item.source_record_id,
        "odoo_technical_rate": _rate(technical_rate, "Odoo technical rate"),
    }


def _validate_rate(
    item: EffectiveRate,
    *,
    currency: CurrencyInfo,
    company_currency: CurrencyInfo,
    as_of_date: date,
) -> dict[str, Any]:
    if item.currency_id != currency.id:
        raise MulticurrencyBalanceError("effective rate currency binding mismatch")
    transaction_source = _technical_source_payload(
        item.transaction_technical_source,
        currency=currency,
        as_of_date=as_of_date,
        allow_no_rate_identity=currency.id == company_currency.id,
    )
    company_source = _technical_source_payload(
        item.company_technical_source,
        currency=company_currency,
        as_of_date=as_of_date,
        allow_no_rate_identity=True,
    )
    if (
        currency.id == company_currency.id
        and item.transaction_technical_source != item.company_technical_source
    ):
        raise MulticurrencyBalanceError(
            "company-currency conversion must use the same technical source twice"
        )
    transaction_to_company = _positive_decimal(
        item.transaction_to_company_rate,
        "transaction-to-company rate",
    )
    expected = _positive_decimal(
        item.company_technical_source.technical_rate,
        "company Odoo technical rate",
    ) / _positive_decimal(
        item.transaction_technical_source.technical_rate,
        "transaction Odoo technical rate",
    )
    if not _rates_match(transaction_to_company, expected):
        raise MulticurrencyBalanceError(
            "Odoo conversion rate does not match the disclosed technical rate ratio"
        )
    return {
        "currency_id": currency.id,
        "currency_name": currency.name,
        "company_currency_id": company_currency.id,
        "company_currency_name": company_currency.name,
        "as_of_date": as_of_date.isoformat(),
        "direction": "transaction_currency_to_company_currency",
        "formula": "company_technical_rate / transaction_technical_rate",
        "transaction_technical_source": transaction_source,
        "company_technical_source": company_source,
        "transaction_to_company_rate": _rate(
            transaction_to_company, "transaction-to-company rate"
        ),
        "company_to_transaction_rate": _rate(
            Decimal("1") / transaction_to_company,
            "company-to-transaction rate",
        ),
    }


def read_multicurrency_balance(
    backend: MulticurrencyBalanceBackend,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Return booked AML balances plus separately evidenced cutoff-date rates."""

    company_id = parameters["company_id"]
    if isinstance(company_id, bool) or not isinstance(company_id, int) or company_id <= 0:
        raise MulticurrencyBalanceError("company_id must be a positive integer")
    as_of_date = _date(parameters["as_of_date"], "as_of_date")
    raw_currency_ids = parameters["currency_ids"]
    if (
        not isinstance(raw_currency_ids, list)
        or not raw_currency_ids
        or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in raw_currency_ids)
    ):
        raise MulticurrencyBalanceError("currency_ids must contain positive integers")
    if len(raw_currency_ids) != len(set(raw_currency_ids)):
        raise MulticurrencyBalanceError("currency_ids must be unique")
    if len(raw_currency_ids) > MAX_REQUESTED_CURRENCIES:
        raise MulticurrencyBalanceError("currency_ids exceeds the supported maximum")
    currency_ids = tuple(raw_currency_ids)
    if parameters["balance_basis"] != "posted_ledger_cumulative":
        raise MulticurrencyBalanceError("unsupported balance_basis")
    if parameters["off_balance_policy"] != "exclude":
        raise MulticurrencyBalanceError("unsupported off_balance_policy")
    limit = parameters["limit"]
    offset = parameters["offset"]
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or limit < 1
        or limit > MAX_PAGE_SIZE
    ):
        raise MulticurrencyBalanceError("limit is outside the supported range")
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or offset > MAX_PAGE_OFFSET
    ):
        raise MulticurrencyBalanceError("offset is outside the supported range")

    backend.assert_read_access(company_id=company_id)
    company_currency = backend.company_currency(company_id=company_id)
    _currency_payload(company_currency)
    currency_rows = backend.currencies(
        company_id=company_id,
        currency_ids=currency_ids,
    )
    currency_by_id = {item.id: item for item in currency_rows}
    if len(currency_by_id) != len(currency_rows):
        raise MulticurrencyBalanceError("currency catalog returned duplicate identities")
    if set(currency_by_id) != set(currency_ids):
        raise MulticurrencyBalanceError(
            "one or more requested currencies do not exist or are not visible"
        )
    for currency in currency_rows:
        _currency_payload(currency)

    aggregates = backend.balance_aggregates(
        company_id=company_id,
        as_of_date=as_of_date,
        currency_ids=currency_ids,
        exclude_off_balance=True,
    )
    if len(aggregates) > MAX_BALANCE_GROUPS:
        raise MulticurrencyBalanceError("balance group count exceeds the safety limit")
    seen_groups: set[tuple[int, int]] = set()
    account_ids: set[int] = set()
    for item in aggregates:
        group = (item.account_id, item.currency_id)
        if item.account_id <= 0 or item.currency_id not in currency_by_id:
            raise MulticurrencyBalanceError("balance aggregate escaped the requested scope")
        if group in seen_groups:
            raise MulticurrencyBalanceError("balance aggregate group is duplicated")
        if (
            isinstance(item.line_count, bool)
            or not isinstance(item.line_count, int)
            or item.line_count < 0
        ):
            raise MulticurrencyBalanceError("balance aggregate line count is invalid")
        _decimal(item.company_balance, "ledger company balance")
        _decimal(item.amount_currency, "ledger transaction amount")
        seen_groups.add(group)
        account_ids.add(item.account_id)

    account_rows = backend.accounts(company_id=company_id, account_ids=account_ids)
    account_by_id = {item.id: item for item in account_rows}
    if len(account_by_id) != len(account_rows) or set(account_by_id) != account_ids:
        raise MulticurrencyBalanceError(
            "one or more aggregate accounts do not exist in the bound company"
        )
    if any(
        item.id <= 0
        or not item.code
        or not item.name
        or not item.account_type
        for item in account_rows
    ):
        raise MulticurrencyBalanceError("account catalog identity is invalid")

    currency_order = {currency_id: index for index, currency_id in enumerate(currency_ids)}
    aggregates.sort(
        key=lambda item: (
            account_by_id[item.account_id].code,
            item.account_id,
            currency_order[item.currency_id],
        )
    )
    balances: list[dict[str, Any]] = []
    for item in aggregates:
        account = account_by_id[item.account_id]
        currency = currency_by_id[item.currency_id]
        company_amount = _money(item.company_balance, company_currency.rounding)
        transaction_amount = _money(item.amount_currency, currency.rounding)
        if currency.id == company_currency.id and company_amount != transaction_amount:
            raise MulticurrencyBalanceError(
                "company-currency AML balance and amount_currency disagree"
            )
        balances.append(
            {
                "account_id": account.id,
                "account_code": account.code,
                "account_name": account.name,
                "account_type": account.account_type,
                "currency_id": currency.id,
                "currency_name": currency.name,
                "company_currency_id": company_currency.id,
                "company_currency_name": company_currency.name,
                "ledger_company_balance": company_amount,
                "ledger_transaction_amount": transaction_amount,
                "move_line_count": item.line_count,
            }
        )

    ordered_currencies = [currency_by_id[currency_id] for currency_id in currency_ids]
    currency_summaries: list[dict[str, Any]] = []
    rates: list[dict[str, Any]] = []
    for currency in ordered_currencies:
        selected = [item for item in aggregates if item.currency_id == currency.id]
        company_total = sum(
            (_decimal(item.company_balance, "ledger company balance") for item in selected),
            Decimal("0"),
        )
        transaction_total = sum(
            (_decimal(item.amount_currency, "ledger transaction amount") for item in selected),
            Decimal("0"),
        )
        currency_summaries.append(
            {
                "currency_id": currency.id,
                "currency_name": currency.name,
                "currency_symbol": currency.symbol or currency.name,
                "currency_rounding": format(
                    _positive_decimal(currency.rounding, "currency rounding"), "f"
                ),
                "ledger_company_balance": _money(
                    company_total, company_currency.rounding
                ),
                "ledger_transaction_amount": _money(
                    transaction_total, currency.rounding
                ),
                "account_count": len({item.account_id for item in selected}),
                "move_line_count": sum(item.line_count for item in selected),
            }
        )
        effective_rate = backend.effective_rate(
            company_id=company_id,
            as_of_date=as_of_date,
            currency=currency,
            company_currency=company_currency,
        )
        rates.append(
            _validate_rate(
                effective_rate,
                currency=currency,
                company_currency=company_currency,
                as_of_date=as_of_date,
            )
        )

    page_aggregates = aggregates[offset : offset + limit]
    return {
        "basis": "odoo_posted_aml_booked_amounts_no_cutoff_revaluation",
        "filters": {
            "company_id": company_id,
            "as_of_date": as_of_date.isoformat(),
            "currency_ids": list(currency_ids),
            "balance_basis": "posted_ledger_cumulative",
            "off_balance_policy": "exclude",
        },
        "balances": balances[offset : offset + limit],
        "page": {
            "limit": limit,
            "offset": offset,
            "count": len(page_aggregates),
            "total_count": len(aggregates),
        },
        "page_summary": _summary(page_aggregates, company_currency.rounding),
        "ledger_summary": _summary(aggregates, company_currency.rounding),
        "currency_summaries": currency_summaries,
        "rates": rates,
        "company_currency": _currency_payload(company_currency),
    }

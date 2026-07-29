"""Strict multi-company gross ledger translation without invented eliminations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Protocol


class MulticompanyConsolidatedError(ValueError):
    pass


MAX_COMPANIES = 50
MAX_ACCOUNTS_PER_COMPANY = 10_000
MAX_TOTAL_ACCOUNTS = 20_000
MAX_PAGE_SIZE = 1_000
RATE_RATIO_REL_TOLERANCE = Decimal("1e-12")


@dataclass(frozen=True)
class CurrencyInfo:
    id: int
    name: str
    symbol: str
    rounding: Decimal


@dataclass(frozen=True)
class CompanyAccountLedgerAggregate:
    company_id: int
    account_id: int
    account_code: str
    account_name: str
    account_type: str
    opening_balance: Decimal
    opening_line_count: int
    period_debit: Decimal
    period_credit: Decimal
    period_line_count: int


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
class TranslationRate:
    company_id: int
    rate_company_id: int
    source_currency_id: int
    presentation_currency_id: int
    rate_date: date
    source_technical_source: TechnicalRateSource
    presentation_technical_source: TechnicalRateSource
    source_to_presentation_rate: Decimal


class MulticompanyConsolidatedBackend(Protocol):
    def assert_read_access(
        self, *, company_ids: tuple[int, ...], presentation_currency_id: int
    ) -> None: ...

    def presentation_currency(
        self, *, company_ids: tuple[int, ...], currency_id: int
    ) -> CurrencyInfo: ...

    def company_currency(self, *, company_id: int) -> CurrencyInfo: ...

    def ledger_account_aggregates(
        self,
        *,
        company_id: int,
        date_from: date,
        date_to: date,
        posted_only: bool,
        exclude_off_balance: bool,
    ) -> tuple[CompanyAccountLedgerAggregate, ...]: ...

    def translation_rate(
        self,
        *,
        company_id: int,
        rate_date: date,
        source_currency: CurrencyInfo,
        presentation_currency: CurrencyInfo,
    ) -> TranslationRate: ...


def _date(value: Any, field: str) -> date:
    if not isinstance(value, str):
        raise MulticompanyConsolidatedError(f"{field} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise MulticompanyConsolidatedError(
            f"{field} must be an ISO date"
        ) from exc


def _decimal(value: Any, field: str) -> Decimal:
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise MulticompanyConsolidatedError(f"{field} is not a decimal") from exc
    if not result.is_finite():
        raise MulticompanyConsolidatedError(f"{field} must be finite")
    return result


def _positive_decimal(value: Any, field: str) -> Decimal:
    result = _decimal(value, field)
    if result <= 0:
        raise MulticompanyConsolidatedError(f"{field} must be positive")
    return result


def _round(value: Decimal, increment: Decimal) -> Decimal:
    increment = _positive_decimal(increment, "currency rounding")
    return (
        (_decimal(value, "monetary amount") / increment).quantize(
            Decimal("1"), rounding=ROUND_HALF_UP
        )
        * increment
    )


def _money(value: Decimal, increment: Decimal) -> str:
    rounded = _round(value, increment)
    places = max(0, -increment.normalize().as_tuple().exponent)
    return f"{rounded:.{places}f}"


def _rate(value: Decimal, field: str) -> str:
    return format(_positive_decimal(value, field), "f")


def _currency_payload(currency: CurrencyInfo) -> dict[str, Any]:
    if (
        isinstance(currency.id, bool)
        or not isinstance(currency.id, int)
        or currency.id <= 0
        or not isinstance(currency.name, str)
        or not currency.name.strip()
    ):
        raise MulticompanyConsolidatedError("currency identity is invalid")
    rounding = _positive_decimal(currency.rounding, "currency rounding")
    return {
        "id": currency.id,
        "name": currency.name,
        "symbol": currency.symbol or currency.name,
        "rounding": format(rounding, "f"),
    }


def _technical_source_payload(
    item: TechnicalRateSource,
    *,
    currency: CurrencyInfo,
    rate_date: date,
    allow_no_rate_identity: bool,
) -> dict[str, Any]:
    if item.currency_id != currency.id:
        raise MulticompanyConsolidatedError(
            "technical rate source currency binding mismatch"
        )
    technical_rate = _positive_decimal(item.technical_rate, "Odoo technical rate")
    if item.source_scope == "no_rate_identity":
        if not allow_no_rate_identity:
            raise MulticompanyConsolidatedError(
                "presentation currency requires an actual cutoff-date rate record"
            )
        if item != TechnicalRateSource.no_rate_identity(currency_id=currency.id):
            raise MulticompanyConsolidatedError(
                "no-rate identity source is invalid"
            )
        source_model = "no_rate_identity"
    else:
        if item.source_scope not in {"company_specific", "global"}:
            raise MulticompanyConsolidatedError(
                "technical rate source scope is invalid"
            )
        if item.effective_date is None or item.effective_date > rate_date:
            raise MulticompanyConsolidatedError(
                "technical rate source has no cutoff-date effective record"
            )
        if (
            isinstance(item.source_record_id, bool)
            or not isinstance(item.source_record_id, int)
            or item.source_record_id <= 0
        ):
            raise MulticompanyConsolidatedError(
                "currency rate source record is invalid"
            )
        if item.source_scope == "company_specific":
            if (
                isinstance(item.source_company_id, bool)
                or not isinstance(item.source_company_id, int)
                or item.source_company_id <= 0
            ):
                raise MulticompanyConsolidatedError(
                    "company-specific rate source is invalid"
                )
        elif item.source_company_id is not None:
            raise MulticompanyConsolidatedError(
                "global rate must not claim a company source"
            )
        source_model = "res.currency.rate"
    return {
        "currency_id": currency.id,
        "currency_name": currency.name,
        "effective_date": (
            item.effective_date.isoformat()
            if item.effective_date is not None
            else None
        ),
        "source_model": source_model,
        "source_scope": item.source_scope,
        "source_company_id": item.source_company_id,
        "source_record_id": item.source_record_id,
        "odoo_technical_rate": _rate(
            technical_rate, "Odoo technical rate"
        ),
    }


def _rates_match(actual: Decimal, expected: Decimal) -> bool:
    tolerance = max(abs(actual), abs(expected)) * RATE_RATIO_REL_TOLERANCE
    return abs(actual - expected) <= tolerance


def _translation_rate_payload(
    item: TranslationRate,
    *,
    company_id: int,
    source_currency: CurrencyInfo,
    presentation_currency: CurrencyInfo,
    rate_date: date,
) -> dict[str, Any]:
    if item.company_id != company_id:
        raise MulticompanyConsolidatedError(
            "translation rate company binding mismatch"
        )
    rate_company_id = _positive_integer(
        item.rate_company_id,
        "translation rate company id",
    )
    if item.source_currency_id != source_currency.id:
        raise MulticompanyConsolidatedError(
            "translation rate source currency binding mismatch"
        )
    if item.presentation_currency_id != presentation_currency.id:
        raise MulticompanyConsolidatedError(
            "translation rate presentation currency binding mismatch"
        )
    if item.rate_date != rate_date:
        raise MulticompanyConsolidatedError(
            "translation rate date binding mismatch"
        )
    identity = source_currency.id == presentation_currency.id
    source_payload = _technical_source_payload(
        item.source_technical_source,
        currency=source_currency,
        rate_date=rate_date,
        allow_no_rate_identity=True,
    )
    presentation_payload = _technical_source_payload(
        item.presentation_technical_source,
        currency=presentation_currency,
        rate_date=rate_date,
        allow_no_rate_identity=identity,
    )
    for technical_source in (
        item.source_technical_source,
        item.presentation_technical_source,
    ):
        if (
            technical_source.source_scope == "company_specific"
            and technical_source.source_company_id != rate_company_id
        ):
            raise MulticompanyConsolidatedError(
                "company-specific technical rate source is outside "
                "the disclosed rate company"
            )
    conversion_rate = _positive_decimal(
        item.source_to_presentation_rate,
        "source-to-presentation rate",
    )
    expected_rate = _positive_decimal(
        item.presentation_technical_source.technical_rate,
        "presentation Odoo technical rate",
    ) / _positive_decimal(
        item.source_technical_source.technical_rate,
        "source Odoo technical rate",
    )
    if not _rates_match(conversion_rate, expected_rate):
        raise MulticompanyConsolidatedError(
            "Odoo conversion rate does not match the disclosed technical rate ratio"
        )
    if identity and (
        item.source_technical_source != item.presentation_technical_source
        or conversion_rate != Decimal("1")
    ):
        raise MulticompanyConsolidatedError(
            "identity translation must use one identical rate source and factor one"
        )
    return {
        "company_id": company_id,
        "rate_company_id": rate_company_id,
        "source_currency_id": source_currency.id,
        "source_currency_name": source_currency.name,
        "presentation_currency_id": presentation_currency.id,
        "presentation_currency_name": presentation_currency.name,
        "rate_date": rate_date.isoformat(),
        "direction": "company_currency_to_presentation_currency",
        "formula": "presentation_technical_rate / source_technical_rate",
        "source_technical_source": source_payload,
        "presentation_technical_source": presentation_payload,
        "source_to_presentation_rate": _rate(
            conversion_rate, "source-to-presentation rate"
        ),
        "presentation_to_source_rate": _rate(
            Decimal("1") / conversion_rate,
            "presentation-to-source rate",
        ),
    }


def _positive_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MulticompanyConsolidatedError(
            f"{field} must contain positive integers"
        )
    return value


def _line_count(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MulticompanyConsolidatedError(
            f"{field} must be a non-negative integer"
        )
    return value


def read_multicompany_consolidated(
    backend: MulticompanyConsolidatedBackend,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Return paged account balances and full gross summaries without fake consolidation."""

    raw_company_ids = parameters["company_ids"]
    if (
        not isinstance(raw_company_ids, list)
        or not raw_company_ids
        or len(raw_company_ids) > MAX_COMPANIES
    ):
        raise MulticompanyConsolidatedError(
            "company_ids must contain between 1 and 50 companies"
        )
    company_ids = tuple(
        _positive_integer(item, "company_ids") for item in raw_company_ids
    )
    if len(company_ids) != len(set(company_ids)):
        raise MulticompanyConsolidatedError("company_ids must be unique")
    company_ids = tuple(sorted(company_ids))
    date_from = _date(parameters["date_from"], "date_from")
    date_to = _date(parameters["date_to"], "date_to")
    if date_from > date_to:
        raise MulticompanyConsolidatedError(
            "date_from must not be after date_to"
        )
    presentation_currency_id = _positive_integer(
        parameters["presentation_currency_id"],
        "presentation_currency_id",
    )
    limit = _positive_integer(parameters["limit"], "limit")
    if limit > MAX_PAGE_SIZE:
        raise MulticompanyConsolidatedError(
            "limit must not exceed 1000"
        )
    offset = _line_count(parameters["offset"], "offset")

    backend.assert_read_access(
        company_ids=company_ids,
        presentation_currency_id=presentation_currency_id,
    )
    presentation_currency = backend.presentation_currency(
        company_ids=company_ids,
        currency_id=presentation_currency_id,
    )
    if presentation_currency.id != presentation_currency_id:
        raise MulticompanyConsolidatedError(
            "presentation currency binding mismatch"
        )
    presentation_payload = _currency_payload(presentation_currency)

    balance_fields = (
        "opening_balance",
        "period_debit",
        "period_credit",
        "period_balance",
        "closing_balance",
    )

    def sum_balances(
        items: list[dict[str, Any]],
        section: str,
        field: str,
    ) -> Decimal:
        return sum(
            (
                _decimal(
                    item[section][field],
                    f"{section} {field}",
                )
                for item in items
            ),
            Decimal("0"),
        )

    all_account_lines: list[dict[str, Any]] = []
    companies: list[dict[str, Any]] = []
    total_account_count = 0
    for company_id in company_ids:
        company_currency = backend.company_currency(company_id=company_id)
        company_currency_payload = _currency_payload(company_currency)
        raw_aggregates = tuple(
            backend.ledger_account_aggregates(
                company_id=company_id,
                date_from=date_from,
                date_to=date_to,
                posted_only=True,
                exclude_off_balance=True,
            )
        )
        if len(raw_aggregates) > MAX_ACCOUNTS_PER_COMPANY:
            raise MulticompanyConsolidatedError(
                "Odoo returned too many active accounts for one company"
            )
        total_account_count += len(raw_aggregates)
        if total_account_count > MAX_TOTAL_ACCOUNTS:
            raise MulticompanyConsolidatedError(
                "Odoo returned too many active accounts across companies"
            )

        validated: list[CompanyAccountLedgerAggregate] = []
        observed_account_ids: set[int] = set()
        for aggregate in raw_aggregates:
            if not isinstance(aggregate, CompanyAccountLedgerAggregate):
                raise MulticompanyConsolidatedError(
                    "ledger aggregate type is invalid"
                )
            if aggregate.company_id != company_id:
                raise MulticompanyConsolidatedError(
                    "ledger aggregate company binding mismatch"
                )
            account_id = _positive_integer(
                aggregate.account_id,
                "account id",
            )
            if account_id in observed_account_ids:
                raise MulticompanyConsolidatedError(
                    "ledger aggregate account ids must be unique"
                )
            observed_account_ids.add(account_id)
            for value, field, maximum in (
                (aggregate.account_code, "account code", 128),
                (aggregate.account_name, "account name", 256),
                (aggregate.account_type, "account type", 64),
            ):
                if (
                    not isinstance(value, str)
                    or not value.strip()
                    or len(value) > maximum
                ):
                    raise MulticompanyConsolidatedError(
                        f"ledger aggregate {field} is invalid"
                    )
            if aggregate.account_type == "off_balance":
                raise MulticompanyConsolidatedError(
                    "off-balance account escaped the requested scope"
                )
            _decimal(aggregate.opening_balance, "opening balance")
            _line_count(
                aggregate.opening_line_count,
                "opening line count",
            )
            if _decimal(aggregate.period_debit, "period debit") < 0:
                raise MulticompanyConsolidatedError(
                    "period debit must not be negative"
                )
            if _decimal(aggregate.period_credit, "period credit") < 0:
                raise MulticompanyConsolidatedError(
                    "period credit must not be negative"
                )
            _line_count(
                aggregate.period_line_count,
                "period line count",
            )
            validated.append(aggregate)
        validated.sort(
            key=lambda item: (
                item.account_code,
                item.account_id,
            )
        )

        translation_rate = backend.translation_rate(
            company_id=company_id,
            rate_date=date_to,
            source_currency=company_currency,
            presentation_currency=presentation_currency,
        )
        rate_payload = _translation_rate_payload(
            translation_rate,
            company_id=company_id,
            source_currency=company_currency,
            presentation_currency=presentation_currency,
            rate_date=date_to,
        )
        factor = _positive_decimal(
            translation_rate.source_to_presentation_rate,
            "source-to-presentation rate",
        )

        company_account_lines: list[dict[str, Any]] = []
        raw_company_totals = {
            field: Decimal("0") for field in balance_fields
        }
        opening_line_count = 0
        period_line_count = 0
        for aggregate in validated:
            opening = _decimal(
                aggregate.opening_balance,
                "opening balance",
            )
            debit = _decimal(aggregate.period_debit, "period debit")
            credit = _decimal(aggregate.period_credit, "period credit")
            period = debit - credit
            closing = opening + period
            raw_values = {
                "opening_balance": opening,
                "period_debit": debit,
                "period_credit": credit,
                "period_balance": period,
                "closing_balance": closing,
            }
            for field, value in raw_values.items():
                raw_company_totals[field] += value
            opening_line_count += aggregate.opening_line_count
            period_line_count += aggregate.period_line_count
            source_visible = {
                "opening_balance": _round(
                    opening,
                    company_currency.rounding,
                ),
                "period_debit": _round(
                    debit,
                    company_currency.rounding,
                ),
                "period_credit": _round(
                    credit,
                    company_currency.rounding,
                ),
            }
            source_visible["period_balance"] = (
                source_visible["period_debit"]
                - source_visible["period_credit"]
            )
            source_visible["closing_balance"] = (
                source_visible["opening_balance"]
                + source_visible["period_balance"]
            )
            translated_visible = {
                "opening_balance": _round(
                    opening * factor,
                    presentation_currency.rounding,
                ),
                "period_debit": _round(
                    debit * factor,
                    presentation_currency.rounding,
                ),
                "period_credit": _round(
                    credit * factor,
                    presentation_currency.rounding,
                ),
            }
            translated_visible["period_balance"] = (
                translated_visible["period_debit"]
                - translated_visible["period_credit"]
            )
            translated_visible["closing_balance"] = (
                translated_visible["opening_balance"]
                + translated_visible["period_balance"]
            )
            account_line = {
                "company_id": company_id,
                "account": {
                    "id": aggregate.account_id,
                    "code": aggregate.account_code,
                    "name": aggregate.account_name,
                    "account_type": aggregate.account_type,
                },
                "source_currency_id": company_currency.id,
                "presentation_currency_id": presentation_currency.id,
                "source_balances": {
                    field: _money(
                        value,
                        company_currency.rounding,
                    )
                    for field, value in source_visible.items()
                },
                "translated_balances": {
                    field: _money(
                        value,
                        presentation_currency.rounding,
                    )
                    for field, value in translated_visible.items()
                },
                "translation_rounding_residuals": {
                    field: _money(
                        _round(
                            raw_values[field] * factor,
                            presentation_currency.rounding,
                        )
                        - translated_visible[field],
                        presentation_currency.rounding,
                    )
                    for field in balance_fields
                },
                "balance_equation_control": {
                    "source_period_equals_debit_minus_credit": True,
                    "source_closing_equals_opening_plus_period": True,
                    "translated_period_equals_debit_minus_credit": True,
                    "translated_closing_equals_opening_plus_period": True,
                },
                "posted_move_line_count": (
                    aggregate.opening_line_count
                    + aggregate.period_line_count
                ),
            }
            company_account_lines.append(account_line)
            all_account_lines.append(account_line)

        source_balances = {
            field: _money(
                sum_balances(
                    company_account_lines,
                    "source_balances",
                    field,
                ),
                company_currency.rounding,
            )
            for field in balance_fields
        }
        translated_balances = {
            field: _money(
                sum_balances(
                    company_account_lines,
                    "translated_balances",
                    field,
                ),
                presentation_currency.rounding,
            )
            for field in balance_fields
        }
        translation_rounding_residuals = {
            field: _money(
                _round(
                    raw_company_totals[field] * factor,
                    presentation_currency.rounding,
                )
                - _decimal(
                    translated_balances[field],
                    f"translated {field}",
                ),
                presentation_currency.rounding,
            )
            for field in balance_fields
        }
        source_opening = _decimal(
            source_balances["opening_balance"],
            "source opening balance",
        )
        source_period = (
            _decimal(
                source_balances["period_debit"],
                "source period debit",
            )
            - _decimal(
                source_balances["period_credit"],
                "source period credit",
            )
        )
        source_closing = _decimal(
            source_balances["closing_balance"],
            "source closing balance",
        )
        balanced = all(
            _round(value, company_currency.rounding) == 0
            for value in (
                source_opening,
                source_period,
                source_closing,
            )
        )
        companies.append(
            {
                "company_id": company_id,
                "company_currency": company_currency_payload,
                "account_count": len(company_account_lines),
                "source_balances": source_balances,
                "translation_rate": rate_payload,
                "translated_balances": translated_balances,
                "translation_rounding_residuals": (
                    translation_rounding_residuals
                ),
                "ledger_control": {
                    "opening_difference": _money(
                        source_opening,
                        company_currency.rounding,
                    ),
                    "period_debit_credit_difference": _money(
                        source_period,
                        company_currency.rounding,
                    ),
                    "closing_difference": _money(
                        source_closing,
                        company_currency.rounding,
                    ),
                    "is_balanced": balanced,
                },
                "posted_move_line_count": (
                    opening_line_count + period_line_count
                ),
            }
        )

    all_account_lines.sort(
        key=lambda item: (
            item["company_id"],
            item["account"]["code"],
            item["account"]["id"],
        )
    )

    account_type_buckets: dict[str, dict[str, Any]] = {}
    for item in all_account_lines:
        account_type = item["account"]["account_type"]
        bucket = account_type_buckets.setdefault(
            account_type,
            {
                "company_ids": set(),
                "account_count": 0,
                "posted_move_line_count": 0,
                "translated_balances": {
                    field: Decimal("0") for field in balance_fields
                },
            },
        )
        bucket["company_ids"].add(item["company_id"])
        bucket["account_count"] += 1
        bucket["posted_move_line_count"] += item[
            "posted_move_line_count"
        ]
        for field in balance_fields:
            bucket["translated_balances"][field] += _decimal(
                item["translated_balances"][field],
                f"translated {field}",
            )

    account_type_summaries = [
        {
            "account_type": account_type,
            "company_ids": sorted(bucket["company_ids"]),
            "company_count": len(bucket["company_ids"]),
            "account_count": bucket["account_count"],
            "translated_balances": {
                field: _money(
                    bucket["translated_balances"][field],
                    presentation_currency.rounding,
                )
                for field in balance_fields
            },
            "posted_move_line_count": bucket[
                "posted_move_line_count"
            ],
        }
        for account_type, bucket in sorted(account_type_buckets.items())
    ]

    def translated_company_total(field: str) -> str:
        return _money(
            sum(
                (
                    _decimal(
                        company["translated_balances"][field],
                        f"translated {field}",
                    )
                    for company in companies
                ),
                Decimal("0"),
            ),
            presentation_currency.rounding,
        )

    gross_summary = {
        "company_count": len(companies),
        "account_count": len(all_account_lines),
        "account_type_count": len(account_type_summaries),
        "posted_move_line_count": sum(
            company["posted_move_line_count"]
            for company in companies
        ),
        **{
            field: translated_company_total(field)
            for field in balance_fields
        },
        "balanced_company_count": sum(
            1
            for company in companies
            if company["ledger_control"]["is_balanced"]
        ),
        "unbalanced_company_ids": [
            company["company_id"]
            for company in companies
            if not company["ledger_control"]["is_balanced"]
        ],
        "translation_rounding_residuals": {
            field: _money(
                sum(
                    (
                        _decimal(
                            company[
                                "translation_rounding_residuals"
                            ][field],
                            f"translation rounding residual {field}",
                        )
                        for company in companies
                    ),
                    Decimal("0"),
                ),
                presentation_currency.rounding,
            )
            for field in balance_fields
        },
    }
    page_lines = all_account_lines[offset : offset + limit]
    return {
        "basis": "posted_account_trial_balance_gross_translation",
        "filters": {
            "company_ids": list(company_ids),
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
            "presentation_currency_id": presentation_currency.id,
            "move_state": "posted",
            "off_balance_policy": "exclude",
            "limit": limit,
            "offset": offset,
        },
        "mapping_policy": {
            "status": "odoo_standard_account_type_only",
            "cross_company_account_mapping_computed": False,
        },
        "translation_policy": {
            "policy_id": "closing_spot_rate_gross_v1",
            "rate_date": date_to.isoformat(),
            "direction": "company_currency_to_presentation_currency",
            "formula": (
                "source_amount * "
                "(presentation_technical_rate / source_technical_rate)"
            ),
            "rounding": (
                "round_each_account_half_up_then_sum_visible_full_set"
            ),
            "opening_rate_basis": "date_to_closing_spot",
            "period_rate_basis": "date_to_closing_spot",
            "historical_or_average_rates_applied": False,
            "translation_reserve_computed": False,
        },
        "elimination_policy": {
            "status": "not_computed",
            "reason": "no_explicit_elimination_dataset_or_mapping",
            "adjustments": [],
        },
        "consolidation_status": {
            "status": "gross_translation_only",
            "complete_consolidation": False,
            "statement": (
                "This result is a gross posted account trial-balance "
                "translation only; it is not a completed consolidation "
                "or consolidated financial statement."
            ),
        },
        "presentation_currency": presentation_payload,
        "companies": companies,
        "account_type_summaries": account_type_summaries,
        "account_lines": page_lines,
        "gross_summary": gross_summary,
        "page": {
            "limit": limit,
            "offset": offset,
            "count": len(page_lines),
            "total_count": len(all_account_lines),
        },
    }

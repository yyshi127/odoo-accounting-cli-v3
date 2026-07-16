"""Non-superuser Odoo 19 backend for multicurrency ledger balances."""

from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from ..domain.multicurrency_balance import (
    MAX_BALANCE_GROUPS,
    RATE_RATIO_REL_TOLERANCE,
    AccountInfo,
    BalanceAggregate,
    CurrencyInfo,
    EffectiveRate,
    MulticurrencyBalanceError,
    TechnicalRateSource,
)


class OdooMulticurrencyBalanceBackend:
    def __init__(self, env: Any, *, user_id: int, allowed_company_ids: frozenset[int]) -> None:
        self._env = env
        self._user_id = user_id
        self._allowed_company_ids = allowed_company_ids

    def _bound(self, model_name: str, company: Any) -> Any:
        return self._env[model_name].with_context(
            allowed_company_ids=sorted(self._allowed_company_ids)
        ).with_company(company)

    def _company(self, company_id: int) -> Any:
        if company_id not in self._allowed_company_ids:
            raise MulticurrencyBalanceError(
                "company is outside the authenticated allowed companies"
            )
        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise MulticurrencyBalanceError("company does not exist or is not visible")
        company.check_access_rights("read")
        company.check_access_rule("read")
        return company

    def assert_read_access(self, *, company_id: int) -> None:
        if getattr(self._env, "su", False) or self._env.uid != self._user_id:
            raise MulticurrencyBalanceError(
                "Odoo environment is not bound to the authenticated non-superuser"
            )
        company = self._company(company_id)
        for model_name in (
            "account.account",
            "account.move.line",
            "res.currency",
            "res.currency.rate",
        ):
            self._bound(model_name, company).check_access_rights("read")

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        currency = self._company(company_id).currency_id
        return self._currency_info(currency)

    @staticmethod
    def _currency_info(record: Any) -> CurrencyInfo:
        return CurrencyInfo(
            id=int(record.id),
            name=str(record.name),
            symbol=str(record.symbol or record.name),
            rounding=Decimal(str(record.rounding)),
        )

    def currencies(
        self, *, company_id: int, currency_ids: tuple[int, ...]
    ) -> list[CurrencyInfo]:
        company = self._company(company_id)
        if not currency_ids:
            return []
        records = self._bound("res.currency", company).with_context(
            active_test=False
        ).search([("id", "in", list(currency_ids))], order="name, id")
        return [self._currency_info(record) for record in records]

    def accounts(
        self, *, company_id: int, account_ids: set[int]
    ) -> list[AccountInfo]:
        if not account_ids:
            return []
        company = self._company(company_id)
        records = self._bound("account.account", company).with_context(
            active_test=False
        ).search(
            [
                ("company_ids", "in", [company_id]),
                ("id", "in", sorted(account_ids)),
            ],
            order="code, id",
        )
        return [
            AccountInfo(
                id=int(record.id),
                code=str(record.with_company(company).code),
                name=str(record.name),
                account_type=str(record.account_type),
            )
            for record in records
        ]

    def balance_aggregates(
        self,
        *,
        company_id: int,
        as_of_date: date,
        currency_ids: tuple[int, ...],
        exclude_off_balance: bool,
    ) -> list[BalanceAggregate]:
        if not exclude_off_balance:
            raise MulticurrencyBalanceError("off-balance accounts must remain excluded")
        company = self._company(company_id)
        domain: list[Any] = [
            ("company_id", "=", company_id),
            ("parent_state", "=", "posted"),
            ("date", "<=", as_of_date),
            ("currency_id", "in", list(currency_ids)),
            ("account_id.account_type", "!=", "off_balance"),
        ]
        grouped = self._bound("account.move.line", company)._read_group(
            domain,
            groupby=["account_id", "currency_id"],
            aggregates=["balance:sum", "amount_currency:sum", "__count"],
            order="account_id, currency_id",
            limit=MAX_BALANCE_GROUPS + 1,
        )
        if len(grouped) > MAX_BALANCE_GROUPS:
            raise MulticurrencyBalanceError("balance group count exceeds the safety limit")
        result: list[BalanceAggregate] = []
        for account, currency, company_balance, amount_currency, line_count in grouped:
            if not account or not currency:
                raise MulticurrencyBalanceError("Odoo returned an unbound balance group")
            result.append(
                BalanceAggregate(
                    account_id=int(account.id),
                    currency_id=int(currency.id),
                    company_balance=Decimal(str(company_balance)),
                    amount_currency=Decimal(str(amount_currency)),
                    line_count=int(line_count),
                )
            )
        return result

    @staticmethod
    def _record_date(value: Any) -> date:
        if isinstance(value, date):
            return value
        try:
            return date.fromisoformat(str(value))
        except ValueError as exc:
            raise MulticurrencyBalanceError("currency rate effective date is invalid") from exc

    @staticmethod
    def _positive_decimal(value: Any, field: str) -> Decimal:
        try:
            result = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise MulticurrencyBalanceError(f"{field} is invalid") from exc
        if not result.is_finite() or result <= 0:
            raise MulticurrencyBalanceError(f"{field} must be positive and finite")
        return result

    @staticmethod
    def _rates_match(actual: Decimal, expected: Decimal) -> bool:
        tolerance = max(abs(actual), abs(expected)) * RATE_RATIO_REL_TOLERANCE
        return abs(actual - expected) <= tolerance

    def _technical_rate_source(
        self,
        *,
        rate_model: Any,
        root_company: Any,
        currency_id: int,
        as_of_date: date,
        allow_no_rate_identity: bool,
    ) -> TechnicalRateSource:
        common_domain: list[Any] = [
            ("currency_id", "=", currency_id),
            ("name", "<=", as_of_date),
        ]
        rate_record = rate_model.search(
            [*common_domain, ("company_id", "=", root_company.id)],
            order="name desc, id desc",
            limit=1,
        )
        source_scope = "company_specific"
        source_company_id: int | None = int(root_company.id)
        if not rate_record:
            rate_record = rate_model.search(
                [*common_domain, ("company_id", "=", False)],
                order="name desc, id desc",
                limit=1,
            )
            source_scope = "global"
            source_company_id = None
        if not rate_record:
            if not allow_no_rate_identity:
                raise MulticurrencyBalanceError(
                    "transaction currency has no actual cutoff-date rate record"
                )
            any_applicable_record = rate_model.search(
                [
                    ("currency_id", "=", currency_id),
                    ("company_id", "in", [False, root_company.id]),
                ],
                order="name asc, id asc",
                limit=1,
            )
            if any_applicable_record:
                raise MulticurrencyBalanceError(
                    "company currency has only future rate records; "
                    "Odoo earliest-future fallback is refused"
                )
            return TechnicalRateSource.no_rate_identity(currency_id=currency_id)

        effective_date = self._record_date(rate_record.name)
        if (
            effective_date > as_of_date
            or int(rate_record.currency_id.id) != currency_id
        ):
            raise MulticurrencyBalanceError(
                "currency rate escaped the requested cutoff scope"
            )
        if source_scope == "company_specific":
            actual_source_company = getattr(rate_record.company_id, "id", None)
            if actual_source_company != root_company.id:
                raise MulticurrencyBalanceError(
                    "company-specific rate source mismatch"
                )
        elif rate_record.company_id:
            raise MulticurrencyBalanceError(
                "global rate unexpectedly has a company"
            )
        return TechnicalRateSource(
            currency_id=currency_id,
            effective_date=effective_date,
            source_scope=source_scope,
            source_company_id=source_company_id,
            source_record_id=int(rate_record.id),
            technical_rate=self._positive_decimal(
                rate_record.rate, "Odoo technical currency rate"
            ),
        )

    def effective_rate(
        self,
        *,
        company_id: int,
        as_of_date: date,
        currency: CurrencyInfo,
        company_currency: CurrencyInfo,
    ) -> EffectiveRate:
        company = self._company(company_id)
        if int(company.currency_id.id) != company_currency.id:
            raise MulticurrencyBalanceError("company currency binding mismatch")
        root_company = company.root_id
        rate_model = self._bound("res.currency.rate", company)
        transaction_source: TechnicalRateSource | None = None
        if currency.id != company_currency.id:
            transaction_source = self._technical_rate_source(
                rate_model=rate_model,
                root_company=root_company,
                currency_id=currency.id,
                as_of_date=as_of_date,
                allow_no_rate_identity=False,
            )
        company_source = self._technical_rate_source(
            rate_model=rate_model,
            root_company=root_company,
            currency_id=company_currency.id,
            as_of_date=as_of_date,
            allow_no_rate_identity=True,
        )
        if transaction_source is None:
            transaction_source = company_source

        currency_model = self._bound("res.currency", company)
        currency_record = currency_model.browse(currency.id).exists()
        if not currency_record or len(currency_record) != 1:
            raise MulticurrencyBalanceError("rate currency does not exist or is not visible")
        conversion_rate = currency_model._get_conversion_rate(
            currency_record,
            company.currency_id,
            company,
            as_of_date,
        )
        conversion_rate = self._positive_decimal(
            conversion_rate, "Odoo transaction-to-company rate"
        )
        expected_rate = company_source.technical_rate / transaction_source.technical_rate
        if not self._rates_match(conversion_rate, expected_rate):
            raise MulticurrencyBalanceError(
                "Odoo conversion rate does not match the dual technical rate ratio"
            )
        return EffectiveRate(
            currency_id=currency.id,
            transaction_technical_source=transaction_source,
            company_technical_source=company_source,
            transaction_to_company_rate=conversion_rate,
        )

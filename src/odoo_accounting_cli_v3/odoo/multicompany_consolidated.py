"""Non-superuser Odoo 19 adapter for strict multi-company gross reads."""

from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from ..domain.multicompany_consolidated import (
    MAX_ACCOUNTS_PER_COMPANY,
    RATE_RATIO_REL_TOLERANCE,
    CompanyAccountLedgerAggregate,
    CurrencyInfo,
    MulticompanyConsolidatedError,
    TechnicalRateSource,
    TranslationRate,
)
from .trial_balance import OdooTrialBalanceBackend


def _is_odoo_access_error(exc: BaseException) -> bool:
    return exc.__class__.__name__ == "AccessError"


def _check_read_acl(record: Any) -> None:
    record.check_access_rights("read")
    record.check_access_rule("read")


class OdooMulticompanyConsolidatedBackend:
    def __init__(
        self,
        env: Any,
        *,
        user_id: int,
        allowed_company_ids: frozenset[int],
    ) -> None:
        self._env = env
        self._user_id = user_id
        self._allowed_company_ids = allowed_company_ids
        self._trial_balance_backend = OdooTrialBalanceBackend(
            env,
            user_id=user_id,
            allowed_company_ids=allowed_company_ids,
        )

    def _bound(self, model_name: str, company: Any) -> Any:
        return (
            self._env[model_name]
            .with_context(
                allowed_company_ids=sorted(self._allowed_company_ids)
            )
            .with_company(company)
        )

    def _company(self, company_id: int) -> Any:
        if company_id not in self._allowed_company_ids:
            raise MulticompanyConsolidatedError(
                "company is outside the authenticated allowed companies"
            )
        try:
            company = self._env["res.company"].browse(company_id).exists()
            if not company or len(company) != 1:
                raise MulticompanyConsolidatedError(
                    "company does not exist or is not visible"
                )
            _check_read_acl(company)
        except Exception as exc:
            if _is_odoo_access_error(exc):
                raise MulticompanyConsolidatedError(
                    "company does not exist or is not visible"
                ) from exc
            raise
        return company

    @staticmethod
    def _currency_info(record: Any) -> CurrencyInfo:
        return CurrencyInfo(
            id=int(record.id),
            name=str(record.name),
            symbol=str(record.symbol or record.name),
            rounding=Decimal(str(record.rounding)),
        )

    def _currency_record(
        self, *, company: Any, currency_id: int, presentation: bool
    ) -> Any:
        try:
            record = (
                self._bound("res.currency", company)
                .with_context(active_test=False)
                .browse(currency_id)
                .exists()
            )
            if not record or len(record) != 1:
                raise MulticompanyConsolidatedError(
                    (
                        "presentation currency"
                        if presentation
                        else "company currency"
                    )
                    + " does not exist or is not visible"
                )
            _check_read_acl(record)
        except Exception as exc:
            if _is_odoo_access_error(exc):
                raise MulticompanyConsolidatedError(
                    (
                        "presentation currency"
                        if presentation
                        else "company currency"
                    )
                    + " does not exist or is not visible"
                ) from exc
            raise
        return record

    def assert_read_access(
        self, *, company_ids: tuple[int, ...], presentation_currency_id: int
    ) -> None:
        if getattr(self._env, "su", False) or self._env.uid != self._user_id:
            raise MulticompanyConsolidatedError(
                "Odoo environment is not bound to the authenticated non-superuser"
            )
        if not company_ids or not set(company_ids).issubset(
            self._allowed_company_ids
        ):
            raise MulticompanyConsolidatedError(
                "company is outside the authenticated allowed companies"
            )
        for company_id in company_ids:
            company = self._company(company_id)
            self._trial_balance_backend.assert_read_access(
                company_id=company_id
            )
            for model_name in ("res.currency", "res.currency.rate"):
                self._bound(model_name, company).check_access_rights("read")
            self._currency_record(
                company=company,
                currency_id=presentation_currency_id,
                presentation=True,
            )

    def presentation_currency(
        self, *, company_ids: tuple[int, ...], currency_id: int
    ) -> CurrencyInfo:
        observed: CurrencyInfo | None = None
        for company_id in company_ids:
            company = self._company(company_id)
            candidate = self._currency_info(
                self._currency_record(
                    company=company,
                    currency_id=currency_id,
                    presentation=True,
                )
            )
            if observed is not None and candidate != observed:
                raise MulticompanyConsolidatedError(
                    "presentation currency metadata drifted across companies"
                )
            observed = candidate
        if observed is None:
            raise MulticompanyConsolidatedError(
                "presentation currency requires an explicit company scope"
            )
        return observed

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        company = self._company(company_id)
        currency_id = getattr(getattr(company, "currency_id", None), "id", None)
        if (
            isinstance(currency_id, bool)
            or not isinstance(currency_id, int)
            or currency_id <= 0
        ):
            raise MulticompanyConsolidatedError(
                "company currency does not exist or is not visible"
            )
        return self._currency_info(
            self._currency_record(
                company=company,
                currency_id=currency_id,
                presentation=False,
            )
        )

    def ledger_account_aggregates(
        self,
        *,
        company_id: int,
        date_from: date,
        date_to: date,
        posted_only: bool,
        exclude_off_balance: bool,
    ) -> tuple[CompanyAccountLedgerAggregate, ...]:
        if not posted_only:
            raise MulticompanyConsolidatedError(
                "multi-company ledger reads must remain posted-only"
            )
        if not exclude_off_balance:
            raise MulticompanyConsolidatedError(
                "multi-company ledger reads must exclude off-balance accounts"
            )
        self._company(company_id)
        account_rows = self._trial_balance_backend.accounts(
            company_id=company_id,
            account_ids=None,
        )
        accounts = {item.id: item for item in account_rows}
        if len(accounts) != len(account_rows):
            raise MulticompanyConsolidatedError(
                "Odoo returned duplicate account identities"
            )
        opening = self._trial_balance_backend.opening_aggregates(
            company_id=company_id,
            before=date_from,
            account_id=None,
            include_off_balance=False,
            group_limit=MAX_ACCOUNTS_PER_COMPANY + 1,
        )
        period = self._trial_balance_backend.period_aggregates(
            company_id=company_id,
            date_from=date_from,
            date_to=date_to,
            account_id=None,
            include_off_balance=False,
            group_limit=MAX_ACCOUNTS_PER_COMPANY + 1,
        )
        if (
            len(opening) > MAX_ACCOUNTS_PER_COMPANY
            or len(period) > MAX_ACCOUNTS_PER_COMPANY
        ):
            raise MulticompanyConsolidatedError(
                "Odoo returned too many active accounts for one company"
            )
        active_account_ids = set(opening) | set(period)
        if not active_account_ids.issubset(accounts):
            raise MulticompanyConsolidatedError(
                "ledger aggregates include an ACL-invisible account"
            )

        result: list[CompanyAccountLedgerAggregate] = []
        for account_id in sorted(
            active_account_ids,
            key=lambda item: (accounts[item].code, item),
        ):
            account = accounts[account_id]
            account_type = account.account_type
            if (
                not isinstance(account_type, str)
                or not account_type
                or account_type == "off_balance"
            ):
                raise MulticompanyConsolidatedError(
                    "ledger aggregate account type is invalid"
                )
            opening_item = opening.get(account_id)
            period_item = period.get(account_id)
            result.append(
                CompanyAccountLedgerAggregate(
                    company_id=company_id,
                    account_id=account_id,
                    account_code=account.code,
                    account_name=account.name,
                    account_type=account_type,
                    opening_balance=(
                        opening_item.balance
                        if opening_item is not None
                        else Decimal("0")
                    ),
                    opening_line_count=(
                        opening_item.line_count
                        if opening_item is not None
                        else 0
                    ),
                    period_debit=(
                        period_item.debit
                        if period_item is not None
                        else Decimal("0")
                    ),
                    period_credit=(
                        period_item.credit
                        if period_item is not None
                        else Decimal("0")
                    ),
                    period_line_count=(
                        period_item.line_count
                        if period_item is not None
                        else 0
                    ),
                )
            )
        return tuple(result)

    @staticmethod
    def _record_date(value: Any) -> date:
        if isinstance(value, date):
            return value
        try:
            return date.fromisoformat(str(value))
        except ValueError as exc:
            raise MulticompanyConsolidatedError(
                "currency rate effective date is invalid"
            ) from exc

    @staticmethod
    def _positive_decimal(value: Any, field: str) -> Decimal:
        try:
            result = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise MulticompanyConsolidatedError(
                f"{field} is invalid"
            ) from exc
        if not result.is_finite() or result <= 0:
            raise MulticompanyConsolidatedError(
                f"{field} must be positive and finite"
            )
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
        rate_date: date,
        allow_no_rate_identity: bool,
    ) -> TechnicalRateSource:
        common_domain: list[Any] = [
            ("currency_id", "=", currency_id),
            ("name", "<=", rate_date),
        ]
        record = rate_model.search(
            [*common_domain, ("company_id", "=", root_company.id)],
            order="name desc, id desc",
            limit=1,
        )
        source_scope = "company_specific"
        source_company_id: int | None = int(root_company.id)
        if not record:
            record = rate_model.search(
                [*common_domain, ("company_id", "=", False)],
                order="name desc, id desc",
                limit=1,
            )
            source_scope = "global"
            source_company_id = None
        if not record:
            if not allow_no_rate_identity:
                raise MulticompanyConsolidatedError(
                    "presentation currency has no actual cutoff-date rate record"
                )
            any_applicable = rate_model.search(
                [
                    ("currency_id", "=", currency_id),
                    ("company_id", "in", [False, root_company.id]),
                ],
                order="name asc, id asc",
                limit=1,
            )
            if any_applicable:
                raise MulticompanyConsolidatedError(
                    "company currency has only future rate records; "
                    "Odoo earliest-future fallback is refused"
                )
            return TechnicalRateSource.no_rate_identity(
                currency_id=currency_id
            )

        effective_date = self._record_date(record.name)
        if (
            effective_date > rate_date
            or int(record.currency_id.id) != currency_id
        ):
            raise MulticompanyConsolidatedError(
                "currency rate escaped the requested cutoff scope"
            )
        if source_scope == "company_specific":
            if getattr(record.company_id, "id", None) != root_company.id:
                raise MulticompanyConsolidatedError(
                    "company-specific rate source mismatch"
                )
        elif record.company_id:
            raise MulticompanyConsolidatedError(
                "global rate unexpectedly has a company"
            )
        return TechnicalRateSource(
            currency_id=currency_id,
            effective_date=effective_date,
            source_scope=source_scope,
            source_company_id=source_company_id,
            source_record_id=int(record.id),
            technical_rate=self._positive_decimal(
                record.rate, "Odoo technical currency rate"
            ),
        )

    def translation_rate(
        self,
        *,
        company_id: int,
        rate_date: date,
        source_currency: CurrencyInfo,
        presentation_currency: CurrencyInfo,
    ) -> TranslationRate:
        company = self._company(company_id)
        actual_source = self.company_currency(company_id=company_id)
        if actual_source != source_currency:
            raise MulticompanyConsolidatedError(
                "company currency binding mismatch"
            )
        source_record = self._currency_record(
            company=company,
            currency_id=source_currency.id,
            presentation=False,
        )
        presentation_record = self._currency_record(
            company=company,
            currency_id=presentation_currency.id,
            presentation=True,
        )
        currency_model = self._bound("res.currency", company)
        conversion_rate = self._positive_decimal(
            currency_model._get_conversion_rate(
                source_record,
                presentation_record,
                company,
                rate_date,
            ),
            "Odoo source-to-presentation rate",
        )
        if source_currency.id == presentation_currency.id:
            identity = TechnicalRateSource.no_rate_identity(
                currency_id=source_currency.id
            )
            if conversion_rate != Decimal("1"):
                raise MulticompanyConsolidatedError(
                    "Odoo identity conversion rate is not one"
                )
            return TranslationRate(
                company_id=company_id,
                rate_company_id=int(company.root_id.id),
                source_currency_id=source_currency.id,
                presentation_currency_id=presentation_currency.id,
                rate_date=rate_date,
                source_technical_source=identity,
                presentation_technical_source=identity,
                source_to_presentation_rate=conversion_rate,
            )

        root_company = company.root_id
        rate_model = self._bound("res.currency.rate", company)
        source_technical = self._technical_rate_source(
            rate_model=rate_model,
            root_company=root_company,
            currency_id=source_currency.id,
            rate_date=rate_date,
            allow_no_rate_identity=True,
        )
        presentation_technical = self._technical_rate_source(
            rate_model=rate_model,
            root_company=root_company,
            currency_id=presentation_currency.id,
            rate_date=rate_date,
            allow_no_rate_identity=False,
        )
        expected_rate = (
            presentation_technical.technical_rate
            / source_technical.technical_rate
        )
        if not self._rates_match(conversion_rate, expected_rate):
            raise MulticompanyConsolidatedError(
                "Odoo conversion rate does not match the dual technical rate ratio"
            )
        return TranslationRate(
            company_id=company_id,
            rate_company_id=int(root_company.id),
            source_currency_id=source_currency.id,
            presentation_currency_id=presentation_currency.id,
            rate_date=rate_date,
            source_technical_source=source_technical,
            presentation_technical_source=presentation_technical,
            source_to_presentation_rate=conversion_rate,
        )

"""Odoo 19 backend for the Decimal-safe trial-balance service."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

from ..domain.trial_balance import AccountInfo, Aggregate, CurrencyInfo, TrialBalanceError


def _is_odoo_access_error(exc: BaseException) -> bool:
    return exc.__class__.__name__ == "AccessError"


class OdooTrialBalanceBackend:
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
            raise TrialBalanceError("company is outside the authenticated allowed companies")
        try:
            company = self._env["res.company"].browse(company_id).exists()
            if not company or len(company) != 1:
                raise TrialBalanceError("company does not exist or is not visible")
            company.check_access_rights("read")
            company.check_access_rule("read")
        except Exception as exc:
            if _is_odoo_access_error(exc):
                raise TrialBalanceError("company does not exist or is not visible") from exc
            raise
        return company

    def assert_read_access(self, *, company_id: int) -> None:
        if getattr(self._env, "su", False) or self._env.uid != self._user_id:
            raise TrialBalanceError("Odoo environment is not bound to the authenticated non-superuser")
        company = self._company(company_id)
        for model_name in ("account.account", "account.move.line"):
            self._bound(model_name, company).check_access_rights("read")

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        currency = self._company(company_id).currency_id
        return CurrencyInfo(
            id=currency.id,
            name=str(currency.name),
            symbol=str(currency.symbol or currency.name),
            rounding=Decimal(str(currency.rounding)),
        )

    def accounts(self, *, company_id: int, account_ids: set[int] | None) -> list[AccountInfo]:
        company = self._company(company_id)
        domain: list[Any] = [("company_ids", "in", [company_id])]
        if account_ids is not None:
            if not account_ids:
                return []
            domain.append(("id", "in", sorted(account_ids)))
        records = self._bound("account.account", company).with_context(
            active_test=False
        ).search(domain, order="code, id")
        return [
            AccountInfo(
                id=record.id,
                code=str(record.with_company(company).code),
                name=str(record.name),
                account_type=str(record.account_type),
            )
            for record in records
        ]

    def _aggregate(
        self,
        *,
        company_id: int,
        domain: list[Any],
        group_limit: int | None = None,
    ) -> dict[int, Aggregate]:
        company = self._company(company_id)
        kwargs: dict[str, Any] = {
            "groupby": ["account_id"],
            "aggregates": [
                "debit:sum",
                "credit:sum",
                "balance:sum",
                "__count",
            ],
            "order": "account_id",
        }
        if group_limit is not None:
            kwargs["limit"] = group_limit
        rows = self._bound("account.move.line", company)._read_group(
            domain,
            **kwargs,
        )
        result: dict[int, Aggregate] = {}
        for grouped_account, debit, credit, balance, line_count in rows:
            if not grouped_account:
                continue
            result[int(grouped_account.id)] = Aggregate(
                debit=Decimal(str(debit)),
                credit=Decimal(str(credit)),
                balance=Decimal(str(balance)),
                line_count=int(line_count),
            )
        return result

    @staticmethod
    def _base_domain(
        company_id: int, account_id: int | None, include_off_balance: bool
    ) -> list[Any]:
        domain: list[Any] = [
            ("company_id", "=", company_id),
            ("parent_state", "=", "posted"),
        ]
        if account_id is not None:
            domain.append(("account_id", "=", account_id))
        if not include_off_balance:
            domain.append(("account_id.account_type", "!=", "off_balance"))
        return domain

    def opening_aggregates(
        self, *, company_id: int, before: date, account_id: int | None,
        include_off_balance: bool, group_limit: int | None = None
    ) -> dict[int, Aggregate]:
        domain = self._base_domain(company_id, account_id, include_off_balance)
        domain.append(("date", "<", before))
        return self._aggregate(
            company_id=company_id,
            domain=domain,
            group_limit=group_limit,
        )

    def period_aggregates(
        self, *, company_id: int, date_from: date, date_to: date, account_id: int | None,
        include_off_balance: bool, group_limit: int | None = None
    ) -> dict[int, Aggregate]:
        domain = self._base_domain(company_id, account_id, include_off_balance)
        domain.extend((("date", ">=", date_from), ("date", "<=", date_to)))
        return self._aggregate(
            company_id=company_id,
            domain=domain,
            group_limit=group_limit,
        )

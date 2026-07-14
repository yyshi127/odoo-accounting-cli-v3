"""Odoo 19 backend for historical accounts-receivable open items."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

from ..domain.ar_open_items import (
    CurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
    OpenItemsError,
)


class OdooArOpenItemsBackend:
    ACCOUNT_TYPE = "asset_receivable"

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
            raise OpenItemsError("company is outside the authenticated allowed companies")
        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise OpenItemsError("company does not exist or is not visible")
        company.check_access_rights("read")
        company.check_access_rule("read")
        return company

    def assert_read_access(self, *, company_id: int) -> None:
        if getattr(self._env, "su", False) or self._env.uid != self._user_id:
            raise OpenItemsError(
                "Odoo environment is not bound to the authenticated non-superuser"
            )
        company = self._company(company_id)
        for model_name in (
            "account.move.line",
            "account.partial.reconcile",
            "account.move",
            "account.account",
            "account.journal",
            "account.payment",
            "res.partner",
            "res.currency",
        ):
            self._bound(model_name, company).check_access_rights("read")

    @staticmethod
    def _currency_info(currency: Any) -> CurrencyInfo:
        return CurrencyInfo(
            id=int(currency.id),
            name=str(currency.name),
            symbol=str(currency.symbol or currency.name),
            rounding=Decimal(str(currency.rounding)),
        )

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        return self._currency_info(self._company(company_id).currency_id)

    def currency(self, *, currency_id: int) -> CurrencyInfo:
        currency = self._env["res.currency"].with_context(
            allowed_company_ids=sorted(self._allowed_company_ids)
        ).browse(currency_id).exists()
        if not currency or len(currency) != 1:
            raise OpenItemsError("currency does not exist or is not visible")
        currency.check_access_rights("read")
        currency.check_access_rule("read")
        return self._currency_info(currency)

    def assert_partner(self, *, company_id: int, partner_id: int) -> None:
        company = self._company(company_id)
        partner = self._bound("res.partner", company).browse(partner_id).exists()
        if not partner or len(partner) != 1:
            raise OpenItemsError("partner does not exist or is not visible")
        partner.check_access_rights("read")
        partner.check_access_rule("read")
        partner_company = partner.company_id
        if partner_company and partner_company.id != company_id:
            raise OpenItemsError("partner belongs to a different company")

    def source_lines(
        self,
        *,
        company_id: int,
        as_of_date: date,
        partner_id: int | None,
        currency_id: int | None,
        candidate_limit: int,
    ) -> list[OpenItemSource]:
        company = self._company(company_id)
        domain: list[Any] = [
            ("company_id", "=", company_id),
            ("parent_state", "=", "posted"),
            ("account_id.account_type", "=", self.ACCOUNT_TYPE),
            ("date", "<=", as_of_date),
        ]
        if partner_id is not None:
            domain.append(("partner_id", "=", partner_id))
        if currency_id is not None:
            domain.append(("currency_id", "=", currency_id))
        # A line is a candidate when it remains open now, or when a match dated
        # after the requested cutoff can make it historically open.
        domain.extend(
            (
                "|",
                "|",
                ("reconciled", "=", False),
                ("matched_debit_ids.max_date", ">", as_of_date),
                ("matched_credit_ids.max_date", ">", as_of_date),
            )
        )
        records = self._bound("account.move.line", company).search(
            domain, order="date_maturity, date, id", limit=candidate_limit
        )
        result = []
        for line in records:
            move = line.move_id
            partner = line.partner_id
            account = line.account_id.with_company(company)
            journal = line.journal_id
            currency = line.currency_id or company.currency_id
            payment = getattr(line, "payment_id", None) or getattr(
                move, "payment_id", None
            )
            result.append(
                OpenItemSource(
                    move_line_id=int(line.id),
                    move_id=int(move.id),
                    move_name=str(move.name or move.display_name or ""),
                    move_type=str(move.move_type),
                    payment_id=int(payment.id) if payment else None,
                    line_date=line.date,
                    due_date=line.date_maturity or None,
                    partner_id=int(partner.id) if partner else None,
                    partner_name=str(partner.display_name) if partner else "",
                    account_id=int(account.id),
                    account_code=str(account.code),
                    account_name=str(account.name),
                    journal_id=int(journal.id),
                    journal_code=str(journal.code),
                    currency=self._currency_info(currency),
                    balance=Decimal(str(line.balance)),
                    amount_currency=Decimal(str(line.amount_currency)),
                    current_reconciled=bool(line.reconciled),
                )
            )
        return result

    def partials_as_of(
        self, *, company_id: int, move_line_ids: set[int], as_of_date: date
    ) -> dict[int, OpenItemPartial]:
        if not move_line_ids:
            return {}
        company = self._company(company_id)
        partial_model = self._bound("account.partial.reconcile", company)
        line_ids = sorted(move_line_ids)
        result: dict[int, OpenItemPartial] = {}

        debit_rows = partial_model._read_group(
            [
                ("company_id", "=", company_id),
                ("max_date", "<=", as_of_date),
                ("debit_move_id", "in", line_ids),
            ],
            groupby=["debit_move_id"],
            aggregates=["amount:sum", "debit_amount_currency:sum", "__count"],
            order="debit_move_id",
        )
        for line, company_amount, currency_amount, count in debit_rows:
            if not line:
                continue
            line_id = int(line.id)
            if line_id not in move_line_ids:
                raise OpenItemsError("partial reconcile escaped the requested line scope")
            result[line_id] = OpenItemPartial(
                debit_company=Decimal(str(company_amount)),
                debit_currency=Decimal(str(currency_amount)),
                matched_count=int(count),
            )

        credit_rows = partial_model._read_group(
            [
                ("company_id", "=", company_id),
                ("max_date", "<=", as_of_date),
                ("credit_move_id", "in", line_ids),
            ],
            groupby=["credit_move_id"],
            aggregates=["amount:sum", "credit_amount_currency:sum", "__count"],
            order="credit_move_id",
        )
        for line, company_amount, currency_amount, count in credit_rows:
            if not line:
                continue
            line_id = int(line.id)
            if line_id not in move_line_ids:
                raise OpenItemsError("partial reconcile escaped the requested line scope")
            current = result.get(line_id, OpenItemPartial())
            result[line_id] = OpenItemPartial(
                debit_company=current.debit_company,
                credit_company=Decimal(str(company_amount)),
                debit_currency=current.debit_currency,
                credit_currency=Decimal(str(currency_amount)),
                matched_count=current.matched_count + int(count),
            )
        return result

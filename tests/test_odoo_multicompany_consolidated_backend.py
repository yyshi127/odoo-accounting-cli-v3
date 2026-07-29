"""Non-superuser Odoo adapter tests for the multi-company gross read."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from odoo_accounting_cli_v3.domain.multicompany_consolidated import (
    MulticompanyConsolidatedError,
)
from odoo_accounting_cli_v3.odoo.multicompany_consolidated import (
    OdooMulticompanyConsolidatedBackend,
)


class AccessError(Exception):
    pass


class MissingRecord:
    def exists(self):
        return self

    def __bool__(self):
        return False

    def __len__(self):
        return 0


class Record:
    def __init__(self, **values):
        self.__dict__.update(values)
        self.access_checks: list[tuple[str, str]] = []

    def exists(self):
        return self

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def check_access_rights(self, operation):
        self.access_checks.append(("rights", operation))

    def check_access_rule(self, operation):
        self.access_checks.append(("rule", operation))

    def with_company(self, _company):
        return self


class CompanyModel:
    def __init__(self, companies):
        self.companies = {item.id: item for item in companies}

    def browse(self, record_id):
        return self.companies.get(record_id, MissingRecord())


class BoundModel:
    def __init__(self):
        self.contexts: list[dict[str, object]] = []
        self.company_ids: list[int] = []
        self.rights: list[str] = []
        self._current_company = None

    def with_context(self, **context):
        self.contexts.append(context)
        return self

    def with_company(self, company):
        self.company_ids.append(company.id)
        self._current_company = company
        return self

    def check_access_rights(self, operation):
        self.rights.append(operation)


class CurrencyModel(BoundModel):
    def __init__(self, currencies):
        super().__init__()
        self.currencies = {item.id: item for item in currencies}
        self.conversion_calls: list[tuple[int, int, int, date]] = []

    def browse(self, record_id):
        return self.currencies.get(record_id, MissingRecord())

    def _get_conversion_rate(self, source, presentation, company, rate_date):
        self.conversion_calls.append(
            (source.id, presentation.id, company.id, rate_date)
        )
        if source.id == presentation.id:
            return 1
        return Decimal("0.14")


class AccountModel(BoundModel):
    def __init__(self, accounts):
        super().__init__()
        self.accounts = accounts

    def search(self, domain, order):
        company_id = next(
            value
            for field, operator, value in domain
            if field == "company_ids" and operator == "in"
        )[0]
        rows = [
            item
            for item in self.accounts
            if company_id in item.company_ids
        ]
        return sorted(rows, key=lambda item: (item.code, item.id))


class MoveLineModel(BoundModel):
    def __init__(self, accounts):
        super().__init__()
        self.accounts = {item.id: item for item in accounts}
        self.calls: list[dict[str, object]] = []

    def _read_group(self, domain, groupby, aggregates, order, limit=None):
        company_id = next(
            value
            for field, operator, value in domain
            if field == "company_id" and operator == "="
        )
        call = {
            "domain": domain,
            "groupby": groupby,
            "aggregates": aggregates,
            "order": order,
            "limit": limit,
        }
        self.calls.append(call)
        opening = any(
            field == "date" and operator == "<"
            for field, operator, _value in domain
        )
        account_ids = (101, 201) if company_id == 7 else (501, 601)
        opening_amount = Decimal("1000") if company_id == 7 else Decimal("500")
        activity = Decimal("200") if company_id == 7 else Decimal("120")
        if opening:
            return [
                (
                    self.accounts[account_ids[0]],
                    opening_amount,
                    Decimal("0"),
                    opening_amount,
                    1,
                ),
                (
                    self.accounts[account_ids[1]],
                    Decimal("0"),
                    opening_amount,
                    -opening_amount,
                    1,
                ),
            ]
        return [
            (
                self.accounts[account_ids[0]],
                activity,
                Decimal("0"),
                activity,
                1,
            ),
            (
                self.accounts[account_ids[1]],
                Decimal("0"),
                activity,
                -activity,
                1,
            ),
        ]


class RateModel(BoundModel):
    def __init__(self, rate_records):
        super().__init__()
        self.rate_records = rate_records
        self.search_calls: list[tuple[object, ...]] = []

    def search(self, domain, order, limit):
        self.search_calls.append((domain, order, limit))
        currency_id = next(
            value
            for field, operator, value in domain
            if field == "currency_id" and operator == "="
        )
        company_clause = next(
            (item for item in domain if item[0] == "company_id"), None
        )
        cutoff = next(
            (
                value
                for field, operator, value in domain
                if field == "name" and operator == "<="
            ),
            None,
        )
        rows = [
            item for item in self.rate_records if item.currency_id.id == currency_id
        ]
        if cutoff is not None:
            rows = [item for item in rows if item.name <= cutoff]
        if company_clause is not None:
            _field, operator, value = company_clause
            if operator == "=":
                expected = None if value is False else value
                rows = [
                    item
                    for item in rows
                    if getattr(item.company_id, "id", None) == expected
                ]
            elif operator == "in":
                expected = {None if item is False else item for item in value}
                rows = [
                    item
                    for item in rows
                    if getattr(item.company_id, "id", None) in expected
                ]
        rows.sort(key=lambda item: (item.name, item.id), reverse=True)
        return rows[0] if rows else MissingRecord()


class Environment:
    uid = 42
    su = False

    def __init__(self):
        self.cny = Record(id=6, name="CNY", symbol="CNY", rounding=Decimal("0.01"))
        self.usd = Record(id=1, name="USD", symbol="$", rounding=Decimal("0.01"))
        self.company_7 = Record(id=7, currency_id=self.cny)
        self.company_8 = Record(id=8, currency_id=self.usd)
        self.company_7.root_id = self.company_7
        self.company_8.root_id = self.company_8
        self.account_101 = Record(
            id=101,
            code="1000",
            name="Cash",
            account_type="asset_cash",
            company_ids=[7],
        )
        self.account_201 = Record(
            id=201,
            code="3000",
            name="Equity",
            account_type="equity",
            company_ids=[7],
        )
        self.account_501 = Record(
            id=501,
            code="1000",
            name="Cash",
            account_type="asset_cash",
            company_ids=[8],
        )
        self.account_601 = Record(
            id=601,
            code="3000",
            name="Equity",
            account_type="equity",
            company_ids=[8],
        )
        account_records = [
            self.account_101,
            self.account_201,
            self.account_501,
            self.account_601,
        ]
        self.companies = CompanyModel([self.company_7, self.company_8])
        self.currencies = CurrencyModel([self.cny, self.usd])
        self.accounts = AccountModel(account_records)
        self.move_lines = MoveLineModel(account_records)
        self.rates = RateModel(
            [
                Record(
                    id=701,
                    currency_id=self.usd,
                    name=date(2026, 6, 1),
                    rate=Decimal("0.14"),
                    company_id=self.company_7,
                )
            ]
        )

    def __getitem__(self, model_name):
        return {
            "res.company": self.companies,
            "res.currency": self.currencies,
            "res.currency.rate": self.rates,
            "account.account": self.accounts,
            "account.move.line": self.move_lines,
        }[model_name]


def backend(env=None, allowed=frozenset({7, 8})):
    env = env or Environment()
    return env, OdooMulticompanyConsolidatedBackend(
        env,
        user_id=42,
        allowed_company_ids=allowed,
    )


def test_acl_scope_and_posted_domains_are_applied_per_company() -> None:
    env, adapter = backend()

    adapter.assert_read_access(
        company_ids=(7, 8), presentation_currency_id=1
    )
    presentation = adapter.presentation_currency(
        company_ids=(7, 8), currency_id=1
    )
    aggregates = adapter.ledger_account_aggregates(
        company_id=7,
        date_from=date(2026, 1, 1),
        date_to=date(2026, 6, 30),
        posted_only=True,
        exclude_off_balance=True,
    )

    assert presentation.id == 1
    assert [
        (
            item.account_id,
            item.account_type,
            item.opening_balance,
            item.period_debit,
            item.period_credit,
        )
        for item in aggregates
    ] == [
        (
            101,
            "asset_cash",
            Decimal("1000"),
            Decimal("200"),
            Decimal("0"),
        ),
        (
            201,
            "equity",
            Decimal("-1000"),
            Decimal("0"),
            Decimal("200"),
        ),
    ]
    assert sum(item.opening_balance for item in aggregates) == 0
    assert sum(item.period_debit for item in aggregates) == sum(
        item.period_credit for item in aggregates
    )
    assert len(env.move_lines.calls) == 2
    for call in env.move_lines.calls:
        assert ("company_id", "=", 7) in call["domain"]
        assert ("parent_state", "=", "posted") in call["domain"]
        assert ("account_id.account_type", "!=", "off_balance") in call["domain"]
        assert call["groupby"] == ["account_id"]
        assert call["aggregates"] == [
            "debit:sum",
            "credit:sum",
            "balance:sum",
            "__count",
        ]
        assert call["order"] == "account_id"
        assert call["limit"] == 10001
    assert ("date", "<", date(2026, 1, 1)) in env.move_lines.calls[0]["domain"]
    assert ("date", ">=", date(2026, 1, 1)) in env.move_lines.calls[1]["domain"]
    assert ("date", "<=", date(2026, 6, 30)) in env.move_lines.calls[1]["domain"]
    assert set(env.move_lines.company_ids) == {7, 8}
    assert {"read"} == set(env.move_lines.rights)
    assert env.company_7.access_checks
    assert env.company_8.access_checks
    assert env.usd.access_checks


def test_translation_uses_cutoff_sources_and_rechecks_odoo_ratio() -> None:
    env, adapter = backend()
    source = adapter.company_currency(company_id=7)
    presentation = adapter.presentation_currency(company_ids=(7, 8), currency_id=1)

    rate = adapter.translation_rate(
        company_id=7,
        rate_date=date(2026, 6, 30),
        source_currency=source,
        presentation_currency=presentation,
    )

    assert rate.source_technical_source.source_scope == "no_rate_identity"
    assert rate.presentation_technical_source.source_scope == "company_specific"
    assert rate.presentation_technical_source.source_record_id == 701
    assert rate.rate_company_id == 7
    assert rate.source_to_presentation_rate == Decimal("0.14")
    assert env.currencies.conversion_calls == [
        (6, 1, 7, date(2026, 6, 30))
    ]

    env.currencies._get_conversion_rate = lambda *_args: Decimal("0.15")
    with pytest.raises(
        MulticompanyConsolidatedError, match="technical rate ratio"
    ):
        adapter.translation_rate(
            company_id=7,
            rate_date=date(2026, 6, 30),
            source_currency=source,
            presentation_currency=presentation,
        )


def test_identity_translation_does_not_invent_a_rate_record() -> None:
    _env, adapter = backend()
    usd = adapter.company_currency(company_id=8)

    rate = adapter.translation_rate(
        company_id=8,
        rate_date=date(2026, 6, 30),
        source_currency=usd,
        presentation_currency=usd,
    )

    assert rate.source_to_presentation_rate == Decimal("1")
    assert rate.source_technical_source.source_scope == "no_rate_identity"
    assert (
        rate.source_technical_source
        == rate.presentation_technical_source
    )


def test_su_cross_company_and_currency_acl_are_rejected() -> None:
    env = Environment()
    env.su = True
    _env, adapter = backend(env)
    with pytest.raises(MulticompanyConsolidatedError, match="non-superuser"):
        adapter.assert_read_access(
            company_ids=(7, 8), presentation_currency_id=1
        )

    _env, adapter = backend(allowed=frozenset({7}))
    with pytest.raises(MulticompanyConsolidatedError, match="allowed companies"):
        adapter.assert_read_access(
            company_ids=(7, 8), presentation_currency_id=1
        )

    env = Environment()
    env.usd.check_access_rule = lambda _operation: (_ for _ in ()).throw(
        AccessError("hidden")
    )
    _env, adapter = backend(env)
    with pytest.raises(
        MulticompanyConsolidatedError,
        match="presentation currency does not exist or is not visible",
    ):
        adapter.presentation_currency(company_ids=(7, 8), currency_id=1)

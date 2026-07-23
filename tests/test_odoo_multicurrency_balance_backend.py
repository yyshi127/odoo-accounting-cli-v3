"""Non-superuser Odoo backend tests for multicurrency balances and rates."""

import unittest
from datetime import date
from decimal import Decimal

from odoo_accounting_cli_v3.domain.multicurrency_balance import MulticurrencyBalanceError
from odoo_accounting_cli_v3.odoo.multicurrency_balance import (
    OdooMulticurrencyBalanceBackend,
)


class AccessError(Exception):
    pass


class Record:
    def exists(self):
        return self

    def __bool__(self):
        return True

    def __len__(self):
        return 1


class CurrencyRecord(Record):
    def __init__(self, currency_id, name, symbol, rounding):
        self.id = currency_id
        self.name = name
        self.symbol = symbol
        self.rounding = rounding


class Company(Record):
    id = 9

    def __init__(self, company_currency):
        self.currency_id = company_currency
        self.root_id = self
        self.access_checks = []

    def check_access_rights(self, operation):
        self.access_checks.append(("rights", operation))

    def check_access_rule(self, operation):
        self.access_checks.append(("rule", operation))


class MissingRecord:
    def exists(self):
        return self

    def __bool__(self):
        return False

    def __len__(self):
        return 0


class BoundModel:
    def __init__(self):
        self.contexts = []
        self.company_ids = []
        self.rights = []

    def with_context(self, **context):
        self.contexts.append(context)
        return self

    def with_company(self, company):
        self.company_ids.append(company.id)
        return self

    def check_access_rights(self, operation):
        self.rights.append(operation)


class CompanyModel:
    def __init__(self, company):
        self.company = company

    def browse(self, company_id):
        return self.company if company_id == self.company.id else MissingRecord()


class CurrencyModel(BoundModel):
    def __init__(self, records):
        super().__init__()
        self.records = {item.id: item for item in records}
        self.search_domain = None
        self.search_order = None
        self.conversion_calls = []
        self.conversion_factor = 6.5

    def search(self, domain, order):
        self.search_domain = domain
        self.search_order = order
        ids = next(value for field, operator, value in domain if field == "id" and operator == "in")
        return [self.records[item] for item in ids if item in self.records]

    def browse(self, currency_id):
        return self.records.get(currency_id, MissingRecord())

    def _get_conversion_rate(self, from_currency, to_currency, company, cutoff):
        self.conversion_calls.append(
            (from_currency.id, to_currency.id, company.id, cutoff)
        )
        return self.conversion_factor


class AccountRecord:
    def __init__(self, account_id, code, name, account_type):
        self.id = account_id
        self.code = code
        self.name = name
        self.account_type = account_type

    def with_company(self, company):
        if company.id != 9:
            raise AssertionError("unexpected company")
        return self


class AccountModel(BoundModel):
    def __init__(self, records):
        super().__init__()
        self.records = records
        self.search_domain = None

    def search(self, domain, order):
        self.search_domain = domain
        if order != "code, id":
            raise AssertionError("unexpected order")
        ids = set(next(value for field, operator, value in domain if field == "id" and operator == "in"))
        return [item for item in self.records if item.id in ids]


class MoveLineModel(BoundModel):
    def __init__(self, grouped_rows):
        super().__init__()
        self.grouped_rows = grouped_rows
        self.group_call = None

    def _read_group(self, domain, groupby, aggregates, order, limit):
        self.group_call = {
            "domain": domain,
            "groupby": groupby,
            "aggregates": aggregates,
            "order": order,
            "limit": limit,
        }
        return self.grouped_rows


class RateRecord(Record):
    def __init__(self, rate_id, currency, name, rate, company_id):
        self.id = rate_id
        self.currency_id = currency
        self.name = name
        self.rate = rate
        self.company_id = company_id


class RateModel(BoundModel):
    def __init__(self, records):
        super().__init__()
        self.records = records
        self.search_calls = []

    def search(self, domain, order, limit):
        self.search_calls.append((domain, order, limit))
        currency_id = next(
            value
            for field, operator, value in domain
            if field == "currency_id" and operator == "="
        )
        company_field = next(
            (item for item in domain if item[0] == "company_id"), None
        )
        cutoff = next(
            (value for field, operator, value in domain if field == "name" and operator == "<="),
            None,
        )

        def company_id(record):
            return getattr(record.company_id, "id", None)

        selected = [item for item in self.records if item.currency_id.id == currency_id]
        if cutoff is not None:
            selected = [item for item in selected if item.name <= cutoff]
        if company_field is not None:
            _field, operator, value = company_field
            if operator == "=":
                expected = None if value is False else value
                selected = [item for item in selected if company_id(item) == expected]
            elif operator == "in":
                expected = {None if item is False else item for item in value}
                selected = [item for item in selected if company_id(item) in expected]
            else:
                raise AssertionError("unexpected company operator")
        selected.sort(key=lambda item: (item.name, item.id), reverse=True)
        return selected[0] if selected else MissingRecord()


class Environment:
    uid = 42
    su = False

    def __init__(
        self,
        *,
        specific_rate=True,
        global_rate=False,
        company_rate_date=None,
        company_rate_value=1.0,
    ):
        self.cny = CurrencyRecord(6, "CNY", "CNY", 0.01)
        self.usd = CurrencyRecord(1, "USD", "$", 0.01)
        self.company = Company(self.cny)
        self.currencies = CurrencyModel([self.cny, self.usd])
        self.accounts = AccountModel(
            [AccountRecord(3855, "112200", "Accounts Receivable", "asset_receivable")]
        )
        self.move_lines = MoveLineModel(
            [(self.accounts.records[0], self.usd, 1950.0, 300.0, 8)]
        )
        rate_records = []
        if specific_rate:
            rate_records.append(
                RateRecord(
                    1,
                    self.usd,
                    date(2025, 12, 15),
                    0.15384615384615385,
                    self.company,
                )
            )
        if global_rate:
            rate_records.append(
                RateRecord(2, self.usd, date(2025, 12, 16), 0.15, None)
            )
        if company_rate_date is not None:
            rate_records.append(
                RateRecord(
                    3,
                    self.cny,
                    company_rate_date,
                    company_rate_value,
                    self.company,
                )
            )
        self.rates = RateModel(rate_records)

    def __getitem__(self, model_name):
        return {
            "res.company": CompanyModel(self.company),
            "res.currency": self.currencies,
            "res.currency.rate": self.rates,
            "account.account": self.accounts,
            "account.move.line": self.move_lines,
        }[model_name]


class OdooMulticurrencyBalanceBackendTest(unittest.TestCase):
    def backend(self, env=None):
        env = env or Environment()
        return env, OdooMulticurrencyBalanceBackend(
            env,
            user_id=42,
            allowed_company_ids=frozenset({9}),
        )

    def test_posted_inclusive_company_currency_domain_is_non_su_and_excludes_off_balance(self):
        env, backend = self.backend()

        backend.assert_read_access(company_id=9)
        rows = backend.balance_aggregates(
            company_id=9,
            as_of_date=date(2026, 7, 13),
            currency_ids=(6, 1),
            exclude_off_balance=True,
        )

        self.assertEqual(rows[0].company_balance, Decimal("1950.0"))
        self.assertEqual(rows[0].amount_currency, Decimal("300.0"))
        self.assertEqual(rows[0].line_count, 8)
        self.assertEqual(
            env.move_lines.group_call["domain"],
            [
                ("company_id", "=", 9),
                ("parent_state", "=", "posted"),
                ("date", "<=", date(2026, 7, 13)),
                ("currency_id", "in", [6, 1]),
                ("account_id.account_type", "!=", "off_balance"),
            ],
        )
        self.assertEqual(env.move_lines.group_call["groupby"], ["account_id", "currency_id"])
        self.assertEqual(
            env.move_lines.group_call["aggregates"],
            ["balance:sum", "amount_currency:sum", "__count"],
        )
        self.assertEqual(env.move_lines.group_call["limit"], 25_001)
        for model in (env.currencies, env.rates, env.accounts, env.move_lines):
            self.assertIn("read", model.rights)
            self.assertIn({"allowed_company_ids": [9]}, model.contexts)
            self.assertGreaterEqual(len(model.company_ids), 1)
            self.assertEqual(set(model.company_ids), {9})

    def test_company_access_error_is_reported_as_company_visibility(self):
        env, backend = self.backend()
        env.company.check_access_rule = lambda _operation: (_ for _ in ()).throw(
            AccessError("hidden company")
        )

        with self.assertRaisesRegex(MulticurrencyBalanceError, "company does not exist"):
            backend.assert_read_access(company_id=9)

    def test_company_specific_cutoff_rate_precedes_global_and_records_direction(self):
        env = Environment(specific_rate=True, global_rate=True)
        env, backend = self.backend(env)

        rate = backend.effective_rate(
            company_id=9,
            as_of_date=date(2026, 7, 13),
            currency=backend.currencies(company_id=9, currency_ids=(1,))[0],
            company_currency=backend.company_currency(company_id=9),
        )

        transaction = rate.transaction_technical_source
        company = rate.company_technical_source
        self.assertEqual(transaction.source_scope, "company_specific")
        self.assertEqual(transaction.source_company_id, 9)
        self.assertEqual(transaction.source_record_id, 1)
        self.assertEqual(transaction.effective_date, date(2025, 12, 15))
        self.assertEqual(transaction.technical_rate, Decimal("0.15384615384615385"))
        self.assertEqual(company.source_scope, "no_rate_identity")
        self.assertEqual(company.technical_rate, Decimal("1"))
        self.assertEqual(rate.transaction_to_company_rate, Decimal("6.5"))
        self.assertEqual(env.currencies.conversion_calls, [(1, 6, 9, date(2026, 7, 13))])
        self.assertEqual(len(env.rates.search_calls), 4)
        domain, order, limit = env.rates.search_calls[0]
        self.assertIn(("name", "<=", date(2026, 7, 13)), domain)
        self.assertIn(("company_id", "=", 9), domain)
        self.assertEqual((order, limit), ("name desc, id desc", 1))

    def test_global_cutoff_rate_is_used_only_when_company_specific_is_absent(self):
        env = Environment(specific_rate=False, global_rate=True)
        env.currencies.conversion_factor = 1 / 0.15
        env, backend = self.backend(env)

        rate = backend.effective_rate(
            company_id=9,
            as_of_date=date(2026, 7, 13),
            currency=backend.currencies(company_id=9, currency_ids=(1,))[0],
            company_currency=backend.company_currency(company_id=9),
        )

        transaction = rate.transaction_technical_source
        self.assertEqual(transaction.source_scope, "global")
        self.assertIsNone(transaction.source_company_id)
        self.assertEqual(transaction.source_record_id, 2)
        self.assertEqual(len(env.rates.search_calls), 5)
        self.assertIn(("company_id", "=", False), env.rates.search_calls[1][0])

    def test_missing_cutoff_rate_does_not_accept_odoo_future_or_one_fallback(self):
        env = Environment(specific_rate=False, global_rate=False)
        _, backend = self.backend(env)

        with self.assertRaisesRegex(MulticurrencyBalanceError, "cutoff-date rate"):
            backend.effective_rate(
                company_id=9,
                as_of_date=date(2026, 7, 13),
                currency=backend.currencies(company_id=9, currency_ids=(1,))[0],
                company_currency=backend.company_currency(company_id=9),
            )
        self.assertEqual(env.currencies.conversion_calls, [])

    def test_company_currency_without_any_rate_discloses_no_rate_identity(self):
        env, backend = self.backend()
        env.currencies.conversion_factor = 1
        company_currency = backend.company_currency(company_id=9)

        rate = backend.effective_rate(
            company_id=9,
            as_of_date=date(2026, 7, 13),
            currency=company_currency,
            company_currency=company_currency,
        )

        self.assertEqual(rate.transaction_to_company_rate, Decimal("1"))
        self.assertEqual(
            rate.transaction_technical_source,
            rate.company_technical_source,
        )
        self.assertEqual(
            rate.company_technical_source.source_scope, "no_rate_identity"
        )
        self.assertEqual(rate.company_technical_source.technical_rate, Decimal("1"))
        self.assertEqual(len(env.rates.search_calls), 3)
        self.assertEqual(env.currencies.conversion_calls, [(6, 6, 9, date(2026, 7, 13))])

    def test_company_currency_cutoff_record_is_disclosed_and_used_in_ratio(self):
        env = Environment(
            company_rate_date=date(2026, 1, 1), company_rate_value=2.0
        )
        env.currencies.conversion_factor = 13
        env, backend = self.backend(env)

        rate = backend.effective_rate(
            company_id=9,
            as_of_date=date(2026, 7, 13),
            currency=backend.currencies(company_id=9, currency_ids=(1,))[0],
            company_currency=backend.company_currency(company_id=9),
        )

        company = rate.company_technical_source
        self.assertEqual(company.source_scope, "company_specific")
        self.assertEqual(company.source_record_id, 3)
        self.assertEqual(company.effective_date, date(2026, 1, 1))
        self.assertEqual(company.technical_rate, Decimal("2.0"))
        self.assertEqual(rate.transaction_to_company_rate, Decimal("13"))

    def test_company_currency_only_future_record_fails_closed(self):
        env = Environment(
            company_rate_date=date(2026, 8, 1), company_rate_value=2.0
        )
        env, backend = self.backend(env)

        with self.assertRaisesRegex(MulticurrencyBalanceError, "future"):
            backend.effective_rate(
                company_id=9,
                as_of_date=date(2026, 7, 13),
                currency=backend.currencies(company_id=9, currency_ids=(1,))[0],
                company_currency=backend.company_currency(company_id=9),
            )
        self.assertEqual(env.currencies.conversion_calls, [])

    def test_odoo_conversion_factor_must_match_dual_technical_ratio(self):
        env = Environment()
        env.currencies.conversion_factor = 13
        env, backend = self.backend(env)

        with self.assertRaisesRegex(MulticurrencyBalanceError, "technical rate ratio"):
            backend.effective_rate(
                company_id=9,
                as_of_date=date(2026, 7, 13),
                currency=backend.currencies(company_id=9, currency_ids=(1,))[0],
                company_currency=backend.company_currency(company_id=9),
            )


if __name__ == "__main__":
    unittest.main()

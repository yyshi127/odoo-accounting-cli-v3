import unittest
from datetime import date
from decimal import Decimal

from odoo_accounting_cli_v3.odoo.ar_open_items import OdooArOpenItemsBackend
from odoo_accounting_cli_v3.odoo.ap_open_items import OdooApOpenItemsBackend


class Record:
    def __init__(self, record_id, **values):
        self.id = record_id
        for name, value in values.items():
            setattr(self, name, value)

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def exists(self):
        return self

    def check_access_rights(self, operation):
        if operation != "read":
            raise AssertionError("unexpected access operation")

    def check_access_rule(self, operation):
        if operation != "read":
            raise AssertionError("unexpected record-rule operation")

    def with_company(self, company):
        if company.id != 7:
            raise AssertionError("unexpected company binding")
        return self


class EmptyRecord:
    id = False

    def __bool__(self):
        return False

    def exists(self):
        return self


class BoundModel:
    def __init__(self):
        self.contexts = []
        self.companies = []
        self.access_checks = []

    def with_context(self, **context):
        self.contexts.append(context)
        return self

    def with_company(self, company):
        self.companies.append(company.id)
        return self

    def check_access_rights(self, operation):
        self.access_checks.append(operation)


class CompanyModel:
    def __init__(self, company):
        self.company = company

    def browse(self, company_id):
        if company_id != self.company.id:
            return EmptyRecord()
        return self.company


class BrowseModel(BoundModel):
    def __init__(self, records):
        super().__init__()
        self.records = records

    def browse(self, record_id):
        return self.records.get(record_id, EmptyRecord())


class MoveLineModel(BoundModel):
    def __init__(self, lines):
        super().__init__()
        self.lines = lines
        self.domain = None
        self.order = None

    def search(self, domain, order, limit):
        self.domain = domain
        self.order = order
        self.limit = limit
        return self.lines


class PartialModel(BoundModel):
    def __init__(self, debit_line, credit_line):
        super().__init__()
        self.calls = []
        self.debit_line = debit_line
        self.credit_line = credit_line

    def _read_group(self, domain, groupby, aggregates, order):
        self.calls.append((domain, groupby, aggregates, order))
        if groupby == ["debit_move_id"]:
            return [(self.debit_line, 30.0, 5.0, 2)]
        if groupby == ["credit_move_id"]:
            return [(self.credit_line, 7.0, 1.5, 1)]
        raise AssertionError("unexpected partial grouping")


def currency(record_id, name, symbol, rounding):
    return Record(record_id, name=name, symbol=symbol, rounding=rounding, company_id=False)


class Environment:
    uid = 42
    su = False

    def __init__(self):
        self.cny = currency(6, "CNY", "¥", 0.01)
        self.usd = currency(2, "USD", "$", 0.01)
        self.company = Record(7, currency_id=self.cny)
        self.partner = Record(301, display_name="Alpha", company_id=False)
        account = Record(401, code="1122", name="Accounts Receivable")
        journal = Record(501, code="INV")
        payment = Record(601)
        move_one = Record(
            201,
            name="INV/2026/001",
            move_type="out_invoice",
            payment_id=EmptyRecord(),
        )
        move_two = Record(
            202,
            name="BNK1/2026/001",
            move_type="entry",
            payment_id=payment,
        )
        self.line_one = Record(
            101,
            move_id=move_one,
            date=date(2026, 1, 10),
            date_maturity=date(2026, 1, 31),
            partner_id=self.partner,
            account_id=account,
            journal_id=journal,
            currency_id=self.usd,
            balance=70.0,
            amount_currency=10.0,
            reconciled=False,
        )
        self.line_two = Record(
            102,
            move_id=move_two,
            date=date(2026, 2, 1),
            date_maturity=False,
            partner_id=EmptyRecord(),
            account_id=account,
            journal_id=journal,
            currency_id=self.cny,
            balance=-10.0,
            amount_currency=-10.0,
            reconciled=True,
        )
        self.move_lines = MoveLineModel([self.line_one, self.line_two])
        self.partials = PartialModel(self.line_one, self.line_two)
        self.models = {
            "res.company": CompanyModel(self.company),
            "res.partner": BrowseModel({301: self.partner}),
            "res.currency": BrowseModel({2: self.usd, 6: self.cny}),
            "account.move.line": self.move_lines,
            "account.partial.reconcile": self.partials,
            "account.move": BoundModel(),
            "account.account": BoundModel(),
            "account.journal": BoundModel(),
            "account.payment": BoundModel(),
        }

    def __getitem__(self, model_name):
        return self.models[model_name]


class OdooArOpenItemsBackendTest(unittest.TestCase):
    def setUp(self):
        self.env = Environment()
        self.backend = OdooArOpenItemsBackend(
            self.env,
            user_id=42,
            allowed_company_ids=frozenset({7, 8}),
        )

    def test_source_domain_is_historical_posted_receivable_and_keeps_credits(self):
        self.backend.assert_read_access(company_id=7)
        lines = self.backend.source_lines(
            company_id=7,
            as_of_date=date(2026, 3, 31),
            partner_id=301,
            currency_id=2,
            candidate_limit=10_001,
        )

        self.assertEqual([item.move_line_id for item in lines], [101, 102])
        self.assertEqual(lines[0].balance, Decimal("70.0"))
        self.assertEqual(lines[0].amount_currency, Decimal("10.0"))
        self.assertEqual(lines[1].payment_id, 601)
        self.assertIsNone(lines[1].partner_id)
        self.assertIs(lines[1].current_reconciled, True)
        self.assertEqual(
            self.env.move_lines.domain,
            [
                ("company_id", "=", 7),
                ("parent_state", "=", "posted"),
                ("account_id.account_type", "=", "asset_receivable"),
                ("date", "<=", date(2026, 3, 31)),
                ("partner_id", "=", 301),
                ("currency_id", "=", 2),
                "|",
                "|",
                ("reconciled", "=", False),
                ("matched_debit_ids.max_date", ">", date(2026, 3, 31)),
                ("matched_credit_ids.max_date", ">", date(2026, 3, 31)),
            ],
        )
        self.assertEqual(self.env.move_lines.order, "date_maturity, date, id")
        self.assertEqual(self.env.move_lines.limit, 10_001)
        self.assertIn({"allowed_company_ids": [7, 8]}, self.env.move_lines.contexts)
        self.assertIn(7, self.env.move_lines.companies)

    def test_partial_totals_use_only_matches_at_or_before_as_of_date(self):
        partials = self.backend.partials_as_of(
            company_id=7,
            move_line_ids={101, 102},
            as_of_date=date(2026, 3, 31),
        )

        self.assertEqual(partials[101].debit_company, Decimal("30.0"))
        self.assertEqual(partials[101].debit_currency, Decimal("5.0"))
        self.assertEqual(partials[101].matched_count, 2)
        self.assertEqual(partials[102].credit_company, Decimal("7.0"))
        self.assertEqual(partials[102].credit_currency, Decimal("1.5"))
        self.assertEqual(partials[102].matched_count, 1)
        for domain, _groupby, _aggregates, _order in self.env.partials.calls:
            self.assertIn(("company_id", "=", 7), domain)
            self.assertIn(("max_date", "<=", date(2026, 3, 31)), domain)
            self.assertTrue(
                ("debit_move_id", "in", [101, 102]) in domain
                or ("credit_move_id", "in", [101, 102]) in domain
            )

    def test_ap_backend_uses_the_same_controls_but_only_payable_accounts(self):
        backend = OdooApOpenItemsBackend(
            self.env,
            user_id=42,
            allowed_company_ids=frozenset({7, 8}),
        )

        backend.source_lines(
            company_id=7,
            as_of_date=date(2026, 3, 31),
            partner_id=301,
            currency_id=2,
            candidate_limit=10_001,
        )

        self.assertIn(
            ("account_id.account_type", "=", "liability_payable"),
            self.env.move_lines.domain,
        )
        self.assertNotIn(
            ("account_id.account_type", "=", "asset_receivable"),
            self.env.move_lines.domain,
        )

    def test_company_partner_currency_and_non_superuser_bindings_are_enforced(self):
        self.backend.assert_read_access(company_id=7)
        self.backend.assert_partner(company_id=7, partner_id=301)
        self.assertEqual(self.backend.company_currency(company_id=7).id, 6)
        self.assertEqual(self.backend.currency(currency_id=2).name, "USD")

        with self.assertRaisesRegex(ValueError, "outside"):
            self.backend.assert_read_access(company_id=9)
        with self.assertRaisesRegex(ValueError, "partner"):
            self.backend.assert_partner(company_id=7, partner_id=999)

        self.env.su = True
        with self.assertRaisesRegex(ValueError, "non-superuser"):
            self.backend.assert_read_access(company_id=7)


if __name__ == "__main__":
    unittest.main()

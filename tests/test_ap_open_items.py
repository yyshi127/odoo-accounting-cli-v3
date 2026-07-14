import unittest
from datetime import date
from decimal import Decimal

from odoo_accounting_cli_v3.domain.ap_open_items import (
    ApOpenItemsBackend,
    CurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
    read_ap_open_items,
)


class PayablesBackend:
    currency_info = CurrencyInfo(6, "CNY", "¥", Decimal("0.01"))

    def __init__(self):
        self.calls = []

    def assert_read_access(self, *, company_id):
        self.calls.append(("access", company_id))

    def company_currency(self, *, company_id):
        self.calls.append(("company_currency", company_id))
        return self.currency_info

    def assert_partner(self, *, company_id, partner_id):
        self.calls.append(("partner", company_id, partner_id))

    def currency(self, *, currency_id):
        self.calls.append(("currency", currency_id))
        return self.currency_info

    def source_lines(
        self, *, company_id, as_of_date, partner_id, currency_id, candidate_limit
    ):
        self.calls.append(
            (
                "source",
                company_id,
                as_of_date,
                partner_id,
                currency_id,
                candidate_limit,
            )
        )
        return [
            OpenItemSource(
                move_line_id=101,
                move_id=201,
                move_name="BILL/2026/001",
                move_type="in_invoice",
                payment_id=None,
                line_date=date(2026, 1, 10),
                due_date=date(2026, 1, 31),
                partner_id=301,
                partner_name="Supplier A",
                account_id=401,
                account_code="2202",
                account_name="Accounts Payable",
                journal_id=501,
                journal_code="BILL",
                currency=self.currency_info,
                balance=Decimal("-120.00"),
                amount_currency=Decimal("-120.00"),
                current_reconciled=False,
            ),
            OpenItemSource(
                move_line_id=102,
                move_id=202,
                move_name="RBILL/2026/001",
                move_type="in_refund",
                payment_id=None,
                line_date=date(2026, 2, 1),
                due_date=date(2026, 2, 15),
                partner_id=301,
                partner_name="Supplier A",
                account_id=401,
                account_code="2202",
                account_name="Accounts Payable",
                journal_id=501,
                journal_code="BILL",
                currency=self.currency_info,
                balance=Decimal("30.00"),
                amount_currency=Decimal("30.00"),
                current_reconciled=False,
            ),
        ]

    def partials_as_of(self, *, company_id, move_line_ids, as_of_date):
        self.calls.append(("partials", company_id, move_line_ids, as_of_date))
        return {
            101: OpenItemPartial(
                credit_company=Decimal("20.00"),
                credit_currency=Decimal("20.00"),
                matched_count=1,
            )
        }


class PayableEntryBackend(PayablesBackend):
    def source_lines(
        self, *, company_id, as_of_date, partner_id, currency_id, candidate_limit
    ):
        return [
            OpenItemSource(
                move_line_id=103,
                move_id=203,
                move_name="BNK/2026/003",
                move_type="entry",
                payment_id=603,
                line_date=date(2026, 2, 20),
                due_date=None,
                partner_id=301,
                partner_name="Supplier A",
                account_id=401,
                account_code="2202",
                account_name="Accounts Payable",
                journal_id=502,
                journal_code="BNK",
                currency=self.currency_info,
                balance=Decimal("40.00"),
                amount_currency=Decimal("40.00"),
                current_reconciled=False,
            ),
            OpenItemSource(
                move_line_id=104,
                move_id=204,
                move_name="MISC/2026/004",
                move_type="entry",
                payment_id=None,
                line_date=date(2026, 2, 25),
                due_date=date(2026, 3, 1),
                partner_id=301,
                partner_name="Supplier A",
                account_id=401,
                account_code="2202",
                account_name="Accounts Payable",
                journal_id=503,
                journal_code="MISC",
                currency=self.currency_info,
                balance=Decimal("-10.00"),
                amount_currency=Decimal("-10.00"),
                current_reconciled=False,
            ),
        ]

    def partials_as_of(self, *, company_id, move_line_ids, as_of_date):
        return {
            103: OpenItemPartial(
                debit_company=Decimal("15.00"),
                debit_currency=Decimal("15.00"),
                matched_count=1,
            )
        }


def parameters(**changes):
    value = {
        "company_id": 7,
        "as_of_date": "2026-03-31",
        "partner_id": 301,
        "currency_id": 6,
        "limit": 100,
        "offset": 0,
    }
    value.update(changes)
    return value


class ApOpenItemsTest(unittest.TestCase):
    def test_vendor_bill_and_refund_keep_ledger_signs_and_historical_partial(self):
        backend: ApOpenItemsBackend = PayablesBackend()

        result = read_ap_open_items(backend, parameters())

        self.assertEqual(result["basis"], "odoo_accounting_date_current_reconciliation_graph")
        self.assertEqual(result["filters"], {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": 301,
            "currency_id": 6,
        })
        self.assertEqual(
            [(item["move_type"], item["side"], item["residual_company_amount"])
             for item in result["items"]],
            [("in_invoice", "credit", "-100.00"), ("in_refund", "debit", "30.00")],
        )
        self.assertEqual(
            result["items"][0]["reconciliation_status"],
            "partially_reconciled_as_of",
        )
        self.assertEqual(result["ledger_summary"], {
            "item_count": 2,
            "debit_residual": "30.00",
            "credit_residual": "100.00",
            "net_residual": "-70.00",
        })
        self.assertEqual(result["currency_summaries"], [{
            "currency_id": 6,
            "currency_name": "CNY",
            "item_count": 2,
            "debit_residual": "30.00",
            "credit_residual": "100.00",
            "net_residual": "-70.00",
        }])
        self.assertIn(
            ("source", 7, date(2026, 3, 31), 301, 6, 10_001),
            backend.calls,
        )
        self.assertIn(
            ("partials", 7, {101, 102}, date(2026, 3, 31)),
            backend.calls,
        )

    def test_pagination_changes_only_page_not_full_payables_summary(self):
        result = read_ap_open_items(
            PayablesBackend(), parameters(limit=1, offset=1)
        )

        self.assertEqual(result["page"], {
            "limit": 1,
            "offset": 1,
            "count": 1,
            "total_count": 2,
        })
        self.assertEqual(result["items"][0]["move_type"], "in_refund")
        self.assertEqual(result["page_summary"]["net_residual"], "30.00")
        self.assertEqual(result["ledger_summary"]["net_residual"], "-70.00")

    def test_payment_residual_and_manual_payable_entry_keep_distinct_evidence(self):
        result = read_ap_open_items(PayableEntryBackend(), parameters())
        by_id = {item["move_line_id"]: item for item in result["items"]}

        self.assertEqual(by_id[103]["payment_id"], 603)
        self.assertEqual(by_id[103]["residual_company_amount"], "25.00")
        self.assertEqual(by_id[103]["side"], "debit")
        self.assertEqual(by_id[103]["aging_bucket"], "no_due_date")
        self.assertEqual(by_id[104]["payment_id"], None)
        self.assertEqual(by_id[104]["residual_company_amount"], "-10.00")
        self.assertEqual(by_id[104]["side"], "credit")
        self.assertEqual(result["ledger_summary"]["net_residual"], "15.00")


if __name__ == "__main__":
    unittest.main()

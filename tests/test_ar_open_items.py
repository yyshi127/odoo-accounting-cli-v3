import json
import unittest
from dataclasses import replace
from datetime import date
from decimal import Decimal
from pathlib import Path

from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.domain.ar_open_items import (
    CurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
    OpenItemsError,
    read_ar_open_items,
)


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


class FakeBackend:
    company_currency_value = CurrencyInfo(6, "CNY", "¥", Decimal("0.01"))
    usd = CurrencyInfo(2, "USD", "$", Decimal("0.01"))

    def __init__(self) -> None:
        self.calls = []
        self.sources = [
            OpenItemSource(
                move_line_id=101,
                move_id=201,
                move_name="INV/2026/001",
                move_type="out_invoice",
                payment_id=None,
                line_date=date(2026, 1, 10),
                due_date=date(2026, 1, 31),
                partner_id=301,
                partner_name="Alpha Customer",
                account_id=401,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=501,
                journal_code="INV",
                currency=self.company_currency_value,
                balance=Decimal("100.00"),
                amount_currency=Decimal("100.00"),
                current_reconciled=False,
            ),
            OpenItemSource(
                move_line_id=102,
                move_id=202,
                move_name="RINV/2026/001",
                move_type="out_refund",
                payment_id=None,
                line_date=date(2026, 2, 10),
                due_date=date(2026, 2, 10),
                partner_id=301,
                partner_name="Alpha Customer",
                account_id=401,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=501,
                journal_code="INV",
                currency=self.company_currency_value,
                balance=Decimal("-25.00"),
                amount_currency=Decimal("-25.00"),
                current_reconciled=False,
            ),
            OpenItemSource(
                move_line_id=103,
                move_id=203,
                move_name="INV/2026/002",
                move_type="out_invoice",
                payment_id=None,
                line_date=date(2026, 3, 1),
                due_date=date(2026, 3, 31),
                partner_id=302,
                partner_name="Beta Customer",
                account_id=401,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=501,
                journal_code="INV",
                currency=self.company_currency_value,
                balance=Decimal("50.00"),
                amount_currency=Decimal("50.00"),
                current_reconciled=True,
            ),
            OpenItemSource(
                move_line_id=104,
                move_id=204,
                move_name="INV/2026/003",
                move_type="out_invoice",
                payment_id=None,
                line_date=date(2026, 4, 1),
                due_date=date(2026, 6, 30),
                partner_id=302,
                partner_name="Beta Customer",
                account_id=401,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=501,
                journal_code="INV",
                currency=self.usd,
                balance=Decimal("70.00"),
                amount_currency=Decimal("10.00"),
                current_reconciled=False,
            ),
            OpenItemSource(
                move_line_id=105,
                move_id=205,
                move_name="BNK1/2026/001",
                move_type="entry",
                payment_id=601,
                line_date=date(2026, 5, 1),
                due_date=None,
                partner_id=None,
                partner_name="",
                account_id=401,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=502,
                journal_code="BNK1",
                currency=self.company_currency_value,
                balance=Decimal("-10.00"),
                amount_currency=Decimal("-10.00"),
                current_reconciled=False,
            ),
            OpenItemSource(
                move_line_id=106,
                move_id=206,
                move_name="INV/2026/004",
                move_type="out_invoice",
                payment_id=None,
                line_date=date(2026, 5, 10),
                due_date=date(2026, 7, 31),
                partner_id=303,
                partner_name="Gamma Customer",
                account_id=401,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=501,
                journal_code="INV",
                currency=self.company_currency_value,
                balance=Decimal("80.00"),
                amount_currency=Decimal("80.00"),
                current_reconciled=True,
            ),
        ]
        self.partials = {
            101: OpenItemPartial(
                debit_company=Decimal("30.00"),
                debit_currency=Decimal("30.00"),
                matched_count=1,
            ),
            102: OpenItemPartial(
                credit_company=Decimal("5.00"),
                credit_currency=Decimal("5.00"),
                matched_count=1,
            ),
            103: OpenItemPartial(
                debit_company=Decimal("50.00"),
                debit_currency=Decimal("50.00"),
                matched_count=1,
            ),
            104: OpenItemPartial(
                debit_company=Decimal("14.00"),
                debit_currency=Decimal("2.00"),
                matched_count=1,
            ),
        }

    def assert_read_access(self, *, company_id: int) -> None:
        self.calls.append(("access", company_id))
        if company_id != 1:
            raise OpenItemsError("wrong company")

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        self.calls.append(("company_currency", company_id))
        return self.company_currency_value

    def assert_partner(self, *, company_id: int, partner_id: int) -> None:
        self.calls.append(("partner", partner_id))
        if partner_id not in {301, 302, 303}:
            raise OpenItemsError("partner does not exist")

    def currency(self, *, currency_id: int) -> CurrencyInfo:
        self.calls.append(("currency", currency_id))
        if currency_id == 6:
            return self.company_currency_value
        if currency_id == 2:
            return self.usd
        raise OpenItemsError("currency does not exist")

    def source_lines(
        self,
        *,
        company_id: int,
        as_of_date: date,
        partner_id: int | None,
        currency_id: int | None,
        candidate_limit: int,
    ) -> list[OpenItemSource]:
        self.calls.append(("source_lines", as_of_date))
        return [
            item
            for item in self.sources
            if (partner_id is None or item.partner_id == partner_id)
            and (currency_id is None or item.currency.id == currency_id)
        ][:candidate_limit]

    def partials_as_of(
        self, *, company_id: int, move_line_ids: set[int], as_of_date: date
    ) -> dict[int, OpenItemPartial]:
        if company_id != 1:
            raise AssertionError("unexpected company")
        self.calls.append(("partials", as_of_date))
        return {
            line_id: partial
            for line_id, partial in self.partials.items()
            if line_id in move_line_ids
        }


def parameters(**changes):
    result = {
        "company_id": 1,
        "as_of_date": "2026-06-30",
        "partner_id": None,
        "currency_id": None,
        "limit": 100,
        "offset": 0,
    }
    result.update(changes)
    return result


class ArOpenItemsTest(unittest.TestCase):
    def test_historical_residuals_include_credit_and_currently_closed_lines(self) -> None:
        result = read_ar_open_items(FakeBackend(), parameters())

        self.assertEqual(
            [item["move_line_id"] for item in result["items"]],
            [101, 102, 104, 106, 105],
        )
        by_id = {item["move_line_id"]: item for item in result["items"]}
        self.assertEqual(by_id[101]["residual_company_amount"], "70.00")
        self.assertEqual(by_id[101]["reconciliation_status"], "partially_reconciled_as_of")
        self.assertEqual(by_id[102]["side"], "credit")
        self.assertEqual(by_id[102]["residual_company_amount"], "-20.00")
        self.assertEqual(by_id[104]["residual_currency_amount"], "8.00")
        self.assertIs(by_id[106]["current_reconciled"], True)
        self.assertEqual(by_id[106]["residual_company_amount"], "80.00")
        self.assertNotIn(103, by_id)

    def test_full_summary_is_signed_decimal_safe_and_currency_separated(self) -> None:
        result = read_ar_open_items(FakeBackend(), parameters())

        self.assertEqual(
            result["ledger_summary"],
            {
                "item_count": 5,
                "debit_residual": "206.00",
                "credit_residual": "30.00",
                "net_residual": "176.00",
            },
        )
        self.assertEqual(
            result["currency_summaries"],
            [
                {
                    "currency_id": 2,
                    "currency_name": "USD",
                    "item_count": 1,
                    "debit_residual": "8.00",
                    "credit_residual": "0.00",
                    "net_residual": "8.00",
                },
                {
                    "currency_id": 6,
                    "currency_name": "CNY",
                    "item_count": 4,
                    "debit_residual": "150.00",
                    "credit_residual": "30.00",
                    "net_residual": "120.00",
                },
            ],
        )

    def test_pagination_changes_only_page_rows_and_page_summary(self) -> None:
        first = read_ar_open_items(FakeBackend(), parameters(limit=2, offset=0))
        second = read_ar_open_items(FakeBackend(), parameters(limit=2, offset=2))

        self.assertEqual(first["ledger_summary"], second["ledger_summary"])
        self.assertEqual(first["currency_summaries"], second["currency_summaries"])
        self.assertNotEqual(first["page_summary"], second["page_summary"])
        self.assertEqual(first["page"], {"limit": 2, "offset": 0, "count": 2, "total_count": 5})
        self.assertEqual(second["page"], {"limit": 2, "offset": 2, "count": 2, "total_count": 5})

        empty = read_ar_open_items(FakeBackend(), parameters(limit=2, offset=99))
        self.assertEqual(empty["items"], [])
        self.assertEqual(empty["page"], {"limit": 2, "offset": 99, "count": 0, "total_count": 5})
        self.assertEqual(empty["ledger_summary"], first["ledger_summary"])
        self.assertEqual(empty["page_summary"]["item_count"], 0)

    def test_each_line_is_rounded_before_ledger_summary(self) -> None:
        backend = FakeBackend()
        backend.company_currency_value = CurrencyInfo(
            6, "CNY", "¥", Decimal("0.05")
        )
        backend.sources = [
            replace(
                backend.sources[0],
                balance=Decimal("0.03"),
                amount_currency=Decimal("0.03"),
            ),
            replace(
                backend.sources[2],
                balance=Decimal("0.03"),
                amount_currency=Decimal("0.03"),
            ),
        ]
        backend.partials = {}

        result = read_ar_open_items(backend, parameters())

        self.assertEqual(
            [item["residual_company_amount"] for item in result["items"]],
            ["0.05", "0.05"],
        )
        self.assertEqual(result["ledger_summary"]["debit_residual"], "0.10")

    def test_transaction_residual_keeps_item_open_when_company_residual_is_zero(self) -> None:
        backend = FakeBackend()
        backend.sources = [
            replace(
                backend.sources[3],
                balance=Decimal("0"),
                amount_currency=Decimal("1.00"),
            )
        ]
        backend.partials = {}

        result = read_ar_open_items(backend, parameters())

        self.assertEqual(result["page"]["total_count"], 1)
        self.assertEqual(result["items"][0]["residual_company_amount"], "0.00")
        self.assertEqual(result["items"][0]["residual_currency_amount"], "1.00")
        self.assertEqual(result["items"][0]["side"], "debit")
        self.assertEqual(result["ledger_summary"]["net_residual"], "0.00")
        self.assertEqual(result["currency_summaries"][0]["net_residual"], "1.00")

    def test_basis_discloses_current_reconciliation_graph_limitation(self) -> None:
        result = read_ar_open_items(FakeBackend(), parameters())
        self.assertEqual(
            result["basis"],
            "odoo_accounting_date_current_reconciliation_graph",
        )

    def test_due_date_buckets_are_relative_to_signed_as_of_date(self) -> None:
        result = read_ar_open_items(FakeBackend(), parameters())
        by_id = {item["move_line_id"]: item for item in result["items"]}

        self.assertEqual(by_id[101]["days_overdue"], 150)
        self.assertEqual(by_id[101]["aging_bucket"], "over_90")
        self.assertEqual(by_id[104]["days_overdue"], 0)
        self.assertEqual(by_id[104]["aging_bucket"], "current")
        self.assertEqual(by_id[106]["days_overdue"], -31)
        self.assertEqual(by_id[106]["aging_bucket"], "current")
        self.assertIsNone(by_id[105]["days_overdue"])
        self.assertEqual(by_id[105]["aging_bucket"], "no_due_date")

    def test_filters_are_validated_and_forwarded_without_substitution(self) -> None:
        backend = FakeBackend()
        result = read_ar_open_items(
            backend,
            parameters(partner_id=302, currency_id=2, limit=5, offset=0),
        )

        self.assertEqual([item["move_line_id"] for item in result["items"]], [104])
        self.assertIn(("partner", 302), backend.calls)
        self.assertIn(("currency", 2), backend.calls)
        self.assertIn(("source_lines", date(2026, 6, 30)), backend.calls)

    def test_invalid_date_identifiers_and_page_are_rejected(self) -> None:
        invalid = (
            (parameters(as_of_date="2026-02-30"), "as_of_date"),
            (parameters(company_id=0), "company_id"),
            (parameters(partner_id=0), "partner_id"),
            (parameters(currency_id=0), "currency_id"),
            (parameters(limit=0), "limit"),
            (parameters(limit=501), "limit"),
            (parameters(offset=-1), "offset"),
        )
        for candidate, message in invalid:
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(OpenItemsError, message):
                    read_ar_open_items(FakeBackend(), candidate)

    def test_oversized_candidate_set_fails_instead_of_truncating_result(self) -> None:
        backend = FakeBackend()
        backend.sources = [backend.sources[0]] * 10_001

        with self.assertRaisesRegex(OpenItemsError, "staged safety limit of 10000"):
            read_ar_open_items(backend, parameters(limit=500))

        self.assertFalse(any(call[0] == "partials" for call in backend.calls))

    def test_result_body_plus_trusted_receipt_matches_registry_output(self) -> None:
        result = read_ar_open_items(FakeBackend(), parameters())
        result["receipt"] = {
            "id": "receipt-ar-1",
            "odoo_instance_id": "odoo19@tokyo2",
            "database_name": "odoo_test",
            "database_uuid": "11111111-1111-4111-8111-111111111111",
            "company_id": 1,
            "user_id": 42,
            "capability_id": "acct.ar.open_items.v1",
            "environment": "test",
            "capability_channel": "staged",
            "request_digest": "a" * 64,
            "result_digest": "b" * 64,
            "registry_digest": "c" * 64,
            "release_digest": "d" * 64,
            "record_count": 5,
            "observed_at": "2026-07-14T07:00:00Z",
            "signature_version": 2,
            "signature_purpose": "read_receipt_v2",
            "signature_key_id": "test-receipt-2026-07",
            "signature": "e" * 64,
        }
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        capability = next(
            item
            for item in registry["capabilities"]
            if item["id"] == "acct.ar.open_items.v1"
        )
        validate_value(result, capability["output_schema"])


if __name__ == "__main__":
    unittest.main()

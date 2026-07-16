"""Financial golden and contract tests for multicurrency ledger balances."""

import json
import unittest
from datetime import date
from decimal import Decimal
from pathlib import Path

from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.domain.multicurrency_balance import (
    AccountInfo,
    BalanceAggregate,
    CurrencyInfo,
    EffectiveRate,
    MulticurrencyBalanceError,
    TechnicalRateSource,
    read_multicurrency_balance,
)


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.company_currency_info = CurrencyInfo(6, "CNY", "CNY", Decimal("0.01"))
        self.currency_rows = [
            CurrencyInfo(1, "USD", "$", Decimal("0.01")),
            CurrencyInfo(2, "EUR", "EUR", Decimal("0.01")),
            self.company_currency_info,
        ]
        self.account_rows = [
            AccountInfo(3855, "112200", "Accounts Receivable", "asset_receivable"),
            AccountInfo(4001, "600100", "Expense", "expense"),
        ]
        self.aggregate_rows = [
            BalanceAggregate(3855, 1, Decimal("1950"), Decimal("300"), 8),
            BalanceAggregate(4001, 6, Decimal("-12.345"), Decimal("-12.345"), 2),
        ]
        company_source = TechnicalRateSource.no_rate_identity(currency_id=6)
        self.rate_rows = {
            1: EffectiveRate(
                currency_id=1,
                transaction_technical_source=TechnicalRateSource(
                    currency_id=1,
                    effective_date=date(2025, 12, 15),
                    source_scope="company_specific",
                    source_company_id=9,
                    source_record_id=1,
                    technical_rate=Decimal("0.15384615384615385"),
                ),
                company_technical_source=company_source,
                transaction_to_company_rate=Decimal("6.5"),
            ),
            2: EffectiveRate(
                currency_id=2,
                transaction_technical_source=TechnicalRateSource(
                    currency_id=2,
                    effective_date=date(2026, 6, 1),
                    source_scope="global",
                    source_company_id=None,
                    source_record_id=2,
                    technical_rate=Decimal("0.125"),
                ),
                company_technical_source=company_source,
                transaction_to_company_rate=Decimal("8"),
            ),
            6: EffectiveRate(
                currency_id=6,
                transaction_technical_source=company_source,
                company_technical_source=company_source,
                transaction_to_company_rate=Decimal("1"),
            ),
        }

    def assert_read_access(self, *, company_id: int) -> None:
        self.calls.append(("access", company_id))
        if company_id != 9:
            raise MulticurrencyBalanceError("wrong company")

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        self.calls.append(("company_currency", company_id))
        return self.company_currency_info

    def currencies(self, *, company_id: int, currency_ids: tuple[int, ...]) -> list[CurrencyInfo]:
        self.calls.append(("currencies", company_id, currency_ids))
        requested = set(currency_ids)
        return [item for item in self.currency_rows if item.id in requested]

    def accounts(self, *, company_id: int, account_ids: set[int]) -> list[AccountInfo]:
        self.calls.append(("accounts", company_id, frozenset(account_ids)))
        return [item for item in self.account_rows if item.id in account_ids]

    def balance_aggregates(
        self,
        *,
        company_id: int,
        as_of_date: date,
        currency_ids: tuple[int, ...],
        exclude_off_balance: bool,
    ) -> list[BalanceAggregate]:
        self.calls.append(
            ("balances", company_id, as_of_date, currency_ids, exclude_off_balance)
        )
        requested = set(currency_ids)
        return [item for item in self.aggregate_rows if item.currency_id in requested]

    def effective_rate(
        self,
        *,
        company_id: int,
        as_of_date: date,
        currency: CurrencyInfo,
        company_currency: CurrencyInfo,
    ) -> EffectiveRate:
        self.calls.append(("rate", company_id, as_of_date, currency.id, company_currency.id))
        return self.rate_rows[currency.id]


def parameters(**changes):
    result = {
        "company_id": 9,
        "as_of_date": "2026-07-13",
        "currency_ids": [6, 1, 2],
        "balance_basis": "posted_ledger_cumulative",
        "off_balance_policy": "exclude",
        "limit": 100,
        "offset": 0,
    }
    result.update(changes)
    return result


class MulticurrencyBalanceTest(unittest.TestCase):
    def test_golden_keeps_historical_ledger_amounts_separate_from_cutoff_rate(self) -> None:
        backend = FakeBackend()

        result = read_multicurrency_balance(backend, parameters())

        usd = next(item for item in result["balances"] if item["currency_id"] == 1)
        self.assertEqual(usd["ledger_company_balance"], "1950.00")
        self.assertEqual(usd["ledger_transaction_amount"], "300.00")
        usd_rate = next(item for item in result["rates"] if item["currency_id"] == 1)
        self.assertEqual(usd_rate["transaction_to_company_rate"], "6.5")
        self.assertEqual(
            usd_rate["transaction_technical_source"]["effective_date"],
            "2025-12-15",
        )
        self.assertEqual(
            usd_rate["transaction_technical_source"]["source_scope"],
            "company_specific",
        )
        self.assertEqual(
            usd_rate["transaction_technical_source"]["source_record_id"], 1
        )
        self.assertEqual(
            usd_rate["company_technical_source"]["source_scope"],
            "no_rate_identity",
        )
        self.assertEqual(
            usd_rate["formula"],
            "company_technical_rate / transaction_technical_rate",
        )
        self.assertEqual(
            usd_rate["direction"], "transaction_currency_to_company_currency"
        )
        self.assertEqual(
            Decimal(usd["ledger_company_balance"]),
            Decimal(usd["ledger_transaction_amount"])
            * Decimal(usd_rate["transaction_to_company_rate"]),
        )

    def test_changed_cutoff_rate_does_not_revalue_historically_booked_balance(self) -> None:
        backend = FakeBackend()
        backend.rate_rows[1] = EffectiveRate(
            currency_id=1,
            transaction_technical_source=TechnicalRateSource(
                currency_id=1,
                effective_date=date(2026, 7, 1),
                source_scope="company_specific",
                source_company_id=9,
                source_record_id=10,
                technical_rate=Decimal("0.142857142857142857"),
            ),
            company_technical_source=TechnicalRateSource.no_rate_identity(
                currency_id=6
            ),
            transaction_to_company_rate=Decimal("7"),
        )

        result = read_multicurrency_balance(backend, parameters())

        usd = next(item for item in result["balances"] if item["currency_id"] == 1)
        usd_rate = next(item for item in result["rates"] if item["currency_id"] == 1)
        self.assertEqual(usd["ledger_company_balance"], "1950.00")
        self.assertEqual(usd["ledger_transaction_amount"], "300.00")
        self.assertEqual(usd_rate["transaction_to_company_rate"], "7")
        self.assertNotEqual(
            Decimal(usd["ledger_company_balance"]),
            Decimal(usd["ledger_transaction_amount"])
            * Decimal(usd_rate["transaction_to_company_rate"]),
        )

    def test_company_currency_cutoff_record_is_disclosed_as_ratio_target(self) -> None:
        backend = FakeBackend()
        company_source = TechnicalRateSource(
            currency_id=6,
            effective_date=date(2026, 1, 1),
            source_scope="company_specific",
            source_company_id=9,
            source_record_id=11,
            technical_rate=Decimal("2"),
        )
        backend.rate_rows[1] = EffectiveRate(
            currency_id=1,
            transaction_technical_source=TechnicalRateSource(
                currency_id=1,
                effective_date=date(2025, 12, 15),
                source_scope="company_specific",
                source_company_id=9,
                source_record_id=1,
                technical_rate=Decimal("0.15384615384615385"),
            ),
            company_technical_source=company_source,
            transaction_to_company_rate=Decimal("13"),
        )

        result = read_multicurrency_balance(backend, parameters(currency_ids=[1]))

        rate = result["rates"][0]
        self.assertEqual(rate["transaction_to_company_rate"], "13")
        self.assertEqual(
            rate["company_technical_source"],
            {
                "currency_id": 6,
                "currency_name": "CNY",
                "effective_date": "2026-01-01",
                "source_model": "res.currency.rate",
                "source_scope": "company_specific",
                "source_company_id": 9,
                "source_record_id": 11,
                "odoo_technical_rate": "2",
            },
        )

    def test_every_requested_currency_has_summary_and_rate_even_without_activity(self) -> None:
        result = read_multicurrency_balance(FakeBackend(), parameters())

        self.assertEqual(result["filters"]["currency_ids"], [6, 1, 2])
        self.assertEqual(
            {item["currency_id"] for item in result["currency_summaries"]},
            {1, 2, 6},
        )
        eur = next(item for item in result["currency_summaries"] if item["currency_id"] == 2)
        self.assertEqual(eur["ledger_company_balance"], "0.00")
        self.assertEqual(eur["ledger_transaction_amount"], "0.00")
        self.assertEqual(eur["account_count"], 0)
        self.assertEqual(eur["move_line_count"], 0)
        self.assertEqual({item["currency_id"] for item in result["rates"]}, {1, 2, 6})

    def test_pagination_is_stable_and_does_not_change_full_summaries(self) -> None:
        first = read_multicurrency_balance(FakeBackend(), parameters(limit=1, offset=0))
        second = read_multicurrency_balance(FakeBackend(), parameters(limit=1, offset=1))

        self.assertEqual(first["page"]["total_count"], 2)
        self.assertEqual(first["ledger_summary"], second["ledger_summary"])
        self.assertEqual(first["currency_summaries"], second["currency_summaries"])
        self.assertNotEqual(first["page_summary"], second["page_summary"])
        self.assertEqual(
            [(item["account_code"], item["currency_name"]) for item in first["balances"]],
            [("112200", "USD")],
        )

    def test_company_currency_is_identity_and_uses_ledger_rounding(self) -> None:
        result = read_multicurrency_balance(FakeBackend(), parameters())
        cny = next(item for item in result["balances"] if item["currency_id"] == 6)
        self.assertEqual(cny["ledger_company_balance"], "-12.35")
        self.assertEqual(cny["ledger_transaction_amount"], "-12.35")
        identity = next(item for item in result["rates"] if item["currency_id"] == 6)
        self.assertEqual(identity["transaction_to_company_rate"], "1")
        self.assertEqual(identity["company_to_transaction_rate"], "1")
        self.assertEqual(
            identity["transaction_technical_source"],
            identity["company_technical_source"],
        )
        self.assertEqual(
            identity["company_technical_source"]["source_scope"],
            "no_rate_identity",
        )
        self.assertIsNone(
            identity["company_technical_source"]["effective_date"]
        )
        self.assertIsNone(
            identity["company_technical_source"]["source_record_id"]
        )

    def test_dual_technical_ratio_mismatch_fails_closed(self) -> None:
        backend = FakeBackend()
        backend.rate_rows[1] = EffectiveRate(
            currency_id=1,
            transaction_technical_source=TechnicalRateSource(
                currency_id=1,
                effective_date=date(2025, 12, 15),
                source_scope="company_specific",
                source_company_id=9,
                source_record_id=1,
                technical_rate=Decimal("0.15384615384615385"),
            ),
            company_technical_source=TechnicalRateSource.no_rate_identity(
                currency_id=6
            ),
            transaction_to_company_rate=Decimal("13"),
        )

        with self.assertRaisesRegex(MulticurrencyBalanceError, "technical rate ratio"):
            read_multicurrency_balance(backend, parameters(currency_ids=[1]))

    def test_extremely_small_rate_uses_relative_not_absolute_tolerance(self) -> None:
        backend = FakeBackend()
        backend.rate_rows[1] = EffectiveRate(
            currency_id=1,
            transaction_technical_source=TechnicalRateSource(
                currency_id=1,
                effective_date=date(2025, 12, 15),
                source_scope="company_specific",
                source_company_id=9,
                source_record_id=1,
                technical_rate=Decimal("1e15"),
            ),
            company_technical_source=TechnicalRateSource.no_rate_identity(
                currency_id=6
            ),
            transaction_to_company_rate=Decimal("1e-12"),
        )

        with self.assertRaisesRegex(MulticurrencyBalanceError, "technical rate ratio"):
            read_multicurrency_balance(backend, parameters(currency_ids=[1]))

    def test_invalid_date_duplicate_currency_policy_and_catalog_gaps_fail_closed(self) -> None:
        with self.assertRaisesRegex(MulticurrencyBalanceError, "as_of_date"):
            read_multicurrency_balance(FakeBackend(), parameters(as_of_date="2026-02-30"))
        with self.assertRaisesRegex(MulticurrencyBalanceError, "unique"):
            read_multicurrency_balance(FakeBackend(), parameters(currency_ids=[1, 1]))
        with self.assertRaisesRegex(MulticurrencyBalanceError, "balance_basis"):
            read_multicurrency_balance(FakeBackend(), parameters(balance_basis="period"))
        with self.assertRaisesRegex(MulticurrencyBalanceError, "off_balance_policy"):
            read_multicurrency_balance(FakeBackend(), parameters(off_balance_policy="include"))
        with self.assertRaisesRegex(MulticurrencyBalanceError, "not visible"):
            read_multicurrency_balance(FakeBackend(), parameters(currency_ids=[1, 999]))

    def test_result_body_plus_trusted_receipt_matches_registry_output(self) -> None:
        result = read_multicurrency_balance(FakeBackend(), parameters())
        result["receipt"] = {
            "id": "receipt-test-multicurrency-1",
            "odoo_instance_id": "odoo19@tokyo2",
            "database_name": "odoo_test",
            "database_uuid": "11111111-1111-4111-8111-111111111111",
            "company_id": 9,
            "user_id": 42,
            "capability_id": "acct.multicurrency.balance_read.v1",
            "environment": "test",
            "capability_channel": "staged",
            "request_digest": "a" * 64,
            "result_digest": "b" * 64,
            "registry_digest": "c" * 64,
            "release_digest": "d" * 64,
            "record_count": 2,
            "observed_at": "2026-07-13T07:00:00Z",
            "signature_version": 2,
            "signature_purpose": "read_receipt_v2",
            "signature_key_id": "test-receipt-2026-07",
            "signature": "e" * 64,
        }
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        capability = next(
            item
            for item in registry["capabilities"]
            if item["id"] == "acct.multicurrency.balance_read.v1"
        )
        validate_value(result, capability["output_schema"])


if __name__ == "__main__":
    unittest.main()

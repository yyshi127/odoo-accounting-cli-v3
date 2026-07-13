import json
import unittest
from datetime import date
from decimal import Decimal
from pathlib import Path

from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.domain.trial_balance import (
    AccountInfo,
    Aggregate,
    CurrencyInfo,
    TrialBalanceError,
    read_trial_balance,
)


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


class FakeBackend:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.currency = CurrencyInfo(1, "CNY", "¥", Decimal("0.01"))
        self.account_rows = [
            AccountInfo(1, "1002", "Bank", "asset_cash"),
            AccountInfo(2, "1122", "Receivable", "asset_receivable"),
            AccountInfo(3, "220201", "Payable", "liability_payable"),
            AccountInfo(4, "9999", "No activity", "expense"),
        ]
        self.opening = {
            1: Aggregate(balance=Decimal("0"), line_count=1),
            2: Aggregate(balance=Decimal("0"), line_count=2),
            3: Aggregate(balance=Decimal("0"), line_count=3),
        }
        self.period = {
            1: Aggregate(debit=Decimal("0"), credit=Decimal("113"), balance=Decimal("-113"), line_count=1),
            2: Aggregate(debit=Decimal("43726.99"), credit=Decimal("17470.60"), balance=Decimal("26256.39"), line_count=4),
            3: Aggregate(debit=Decimal("92466.64"), credit=Decimal("118610.03"), balance=Decimal("-26143.39"), line_count=5),
        }

    def assert_read_access(self, *, company_id: int) -> None:
        self.calls.append("access")
        if company_id != 1:
            raise TrialBalanceError("wrong company")

    def company_currency(self, *, company_id: int) -> CurrencyInfo:
        self.calls.append("currency")
        return self.currency

    def accounts(self, *, company_id: int, account_ids: set[int] | None) -> list[AccountInfo]:
        self.calls.append("accounts")
        if account_ids is None:
            return list(self.account_rows)
        return [item for item in self.account_rows if item.id in account_ids]

    def opening_aggregates(
        self, *, company_id: int, before: date, account_id: int | None,
        include_off_balance: bool
    ) -> dict[int, Aggregate]:
        self.calls.append("opening")
        return {key: value for key, value in self.opening.items() if account_id in (None, key)}

    def period_aggregates(
        self, *, company_id: int, date_from: date, date_to: date, account_id: int | None,
        include_off_balance: bool
    ) -> dict[int, Aggregate]:
        self.calls.append("period")
        return {key: value for key, value in self.period.items() if account_id in (None, key)}


def parameters(**changes):
    result = {
        "company_id": 1,
        "date_from": "2026-01-01",
        "date_to": "2026-12-31",
        "opening_basis": "ledger_cumulative",
        "currency_id": 1,
        "account_id": None,
        "include_off_balance": False,
        "include_zero": False,
        "limit": 100,
        "offset": 0,
    }
    result.update(changes)
    return result


class TrialBalanceTest(unittest.TestCase):
    def test_full_summary_is_decimal_safe_and_balanced(self) -> None:
        backend = FakeBackend()
        result = read_trial_balance(backend, parameters())
        self.assertEqual(result["ledger_summary"]["period_debit"], "136193.63")
        self.assertEqual(result["ledger_summary"]["period_credit"], "136193.63")
        self.assertEqual(result["ledger_summary"]["debit_credit_difference"], "0.00")
        self.assertIs(result["ledger_summary"]["is_balanced"], True)
        self.assertEqual(backend.calls.count("opening"), 1)
        self.assertEqual(backend.calls.count("period"), 1)
        self.assertEqual(backend.calls.count("accounts"), 1)

    def test_ledger_summary_does_not_change_with_pagination(self) -> None:
        first = read_trial_balance(FakeBackend(), parameters(limit=1, offset=0))
        second = read_trial_balance(FakeBackend(), parameters(limit=1, offset=1))
        self.assertEqual(first["ledger_summary"], second["ledger_summary"])
        self.assertNotEqual(first["page_summary"], second["page_summary"])
        self.assertEqual(first["page"]["total_count"], 3)

    def test_include_zero_controls_inactive_accounts(self) -> None:
        excluded = read_trial_balance(FakeBackend(), parameters(include_zero=False))
        included = read_trial_balance(FakeBackend(), parameters(include_zero=True))
        self.assertEqual(excluded["page"]["total_count"], 3)
        self.assertEqual(included["page"]["total_count"], 4)
        self.assertEqual(included["lines"][-1]["closing_balance"], "0.00")

    def test_invalid_period_currency_and_account_are_rejected(self) -> None:
        with self.assertRaisesRegex(TrialBalanceError, "date_from"):
            read_trial_balance(FakeBackend(), parameters(date_from="2026-12-31", date_to="2026-01-01"))
        with self.assertRaisesRegex(TrialBalanceError, "conversion"):
            read_trial_balance(FakeBackend(), parameters(currency_id=2))
        with self.assertRaisesRegex(TrialBalanceError, "does not exist"):
            read_trial_balance(FakeBackend(), parameters(account_id=999, include_zero=True))

    def test_result_body_plus_trusted_receipt_matches_registry_output(self) -> None:
        result = read_trial_balance(FakeBackend(), parameters())
        result["receipt"] = {
            "id": "receipt-test-1",
            "odoo_instance_id": "odoo19@tokyo2",
            "database_name": "odoo_test",
            "database_uuid": "11111111-1111-4111-8111-111111111111",
            "company_id": 1,
            "user_id": 42,
            "capability_id": "acct.gl.trial_balance.v1",
            "request_digest": "a" * 64,
            "result_digest": "b" * 64,
            "registry_digest": "c" * 64,
            "release_digest": "d" * 64,
            "record_count": 3,
            "observed_at": "2026-07-13T07:00:00Z",
            "signature_version": 1,
            "signature_purpose": "read_receipt_v1",
            "signature_key_id": "test-receipt-2026-07",
            "signature": "e" * 64,
        }
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        capability = next(
            item for item in registry["capabilities"] if item["id"] == "acct.gl.trial_balance.v1"
        )
        validate_value(result, capability["output_schema"])


if __name__ == "__main__":
    unittest.main()

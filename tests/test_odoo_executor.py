import json
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from odoo_accounting_cli_v3.domain.trial_balance import AccountInfo, Aggregate, CurrencyInfo
from odoo_accounting_cli_v3.gateway import RequestContext
from odoo_accounting_cli_v3.odoo.executor import OdooExecutionError, OdooReadExecutor
from odoo_accounting_cli_v3.registry import validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)
RECEIPT_KEY_ID = "test-receipt-2026-07"


class Cursor:
    dbname = "odoo_test"


class Environment:
    uid = 42
    su = False
    cr = Cursor()


class Backend:
    def assert_read_access(self, *, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")

    def company_currency(self, *, company_id):
        return CurrencyInfo(12, "CNY", "¥", Decimal("0.01"))

    def accounts(self, *, company_id, account_ids):
        return [AccountInfo(401, "1000", "Cash", "asset_cash")]

    def opening_aggregates(self, *, company_id, before, account_id, include_off_balance):
        return {}

    def period_aggregates(
        self, *, company_id, date_from, date_to, account_id, include_off_balance
    ):
        return {401: Aggregate(Decimal("100"), Decimal("100"), Decimal("0"), 2)}


def context(**changes):
    values = {
        "audience": "odoo-accounting-cli-v3",
        "auth_token_id": "token-1",
        "auth_issued_at": NOW - timedelta(seconds=5),
        "auth_expires_at": NOW + timedelta(minutes=4),
        "auth_signature_version": 1,
        "auth_signature_purpose": "auth_context_v1",
        "auth_key_id": "test-auth-2026-07",
        "auth_request_digest": "b" * 64,
        "auth_signature": "a" * 64,
        "principal": "pi:user-42",
        "odoo_instance_id": "odoo19@tokyo2",
        "database_name": "odoo_test",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "user_id": 42,
        "company_id": 7,
        "allowed_company_ids": frozenset({7}),
        "environment": "test",
    }
    values.update(changes)
    return RequestContext(**values)


def parameters():
    return {
        "company_id": 7, "date_from": "2026-01-01", "date_to": "2026-12-31",
        "opening_basis": "ledger_cumulative", "currency_id": 12,
        "account_id": None, "include_off_balance": False, "include_zero": False,
        "limit": 100, "offset": 0,
    }


def capability():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    item = next(item for item in document["capabilities"] if item["id"] == "acct.gl.trial_balance.v1")
    document["capabilities"] = [item]
    return validate_registry(document)[0]


class OdooReadExecutorTest(unittest.TestCase):
    def executor(self):
        consumed = set()

        def consume(receipt_id, request_digest, _observed_at, _verified_at):
            key = (receipt_id, request_digest)
            if key in consumed:
                return False
            consumed.add(key)
            return True

        return OdooReadExecutor(
            Environment(),
            odoo_instance_id="odoo19@tokyo2",
            database_name="odoo_test",
            database_uuid="11111111-1111-4111-8111-111111111111",
            environment="test",
            capability_channel="staged",
            receipt_secret=b"test-only-receipt-secret-32-byte",
            receipt_key_id=RECEIPT_KEY_ID,
            consume_receipt=consume,
            now=lambda: NOW,
            receipt_id_factory=lambda: "receipt-1",
            trial_balance_backend_factory=lambda _env, _user, _companies: Backend(),
        )

    def test_executes_handler_and_verifies_receipt(self) -> None:
        executor = self.executor()
        result = executor(context(), capability(), parameters(), "c" * 64, "d" * 64)
        self.assertEqual(result["ledger_summary"]["period_debit"], "100.00")
        executor.verify(context(), capability(), parameters(), result, "c" * 64, "d" * 64)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            executor.verify(context(), capability(), parameters(), result, "c" * 64, "d" * 64)

    def test_database_and_user_mismatch_are_rejected_before_handler(self) -> None:
        executor = self.executor()
        with self.assertRaisesRegex(OdooExecutionError, "binding mismatch"):
            executor(context(database_name="odoo_sg"), capability(), parameters(), "c" * 64, "d" * 64)
        with self.assertRaisesRegex(OdooExecutionError, "binding mismatch"):
            executor(context(user_id=43, principal="pi:user-43"), capability(), parameters(), "c" * 64, "d" * 64)


if __name__ == "__main__":
    unittest.main()

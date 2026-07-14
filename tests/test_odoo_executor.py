import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from odoo_accounting_cli_v3.domain.ar_open_items import (
    CurrencyInfo as ArCurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
)
from odoo_accounting_cli_v3.domain.trial_balance import AccountInfo, Aggregate, CurrencyInfo
from odoo_accounting_cli_v3.gateway import RequestContext
from odoo_accounting_cli_v3.odoo.executor import OdooExecutionError, OdooReadExecutor
from odoo_accounting_cli_v3.registry import validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)
RECEIPT_KEY_ID = "test-receipt-2026-07"


class Cursor:
    dbname = "odoo_test"


class User:
    def __init__(self, groups=None):
        self._groups = set(
            {"base.group_user", "account.group_account_readonly"}
            if groups is None
            else groups
        )

    def has_group(self, xml_id):
        return xml_id in self._groups


class Company:
    id = 7

    def __init__(self):
        self.access_checks = []

    def browse(self, company_id):
        if company_id != self.id:
            return MissingCompany()
        return self

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


class MissingCompany:
    def exists(self):
        return self

    def __bool__(self):
        return False

    def __len__(self):
        return 0


class Environment:
    uid = 42
    su = False
    cr = Cursor()

    def __init__(self, groups=None):
        self.user = User(groups)
        self.company = Company()

    def __getitem__(self, name):
        if name != "res.company":
            raise AssertionError(f"unexpected model: {name}")
        return self.company


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


class ArBackend:
    currency_info = ArCurrencyInfo(12, "CNY", "¥", Decimal("0.01"))

    def assert_read_access(self, *, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")

    def company_currency(self, *, company_id):
        return self.currency_info

    def assert_partner(self, *, company_id, partner_id):
        raise AssertionError("partner validation was not requested")

    def currency(self, *, currency_id):
        raise AssertionError("currency validation was not requested")

    def source_lines(
        self, *, company_id, as_of_date, partner_id, currency_id, candidate_limit
    ):
        return [
            OpenItemSource(
                move_line_id=701,
                move_id=801,
                move_name="INV/2026/007",
                move_type="out_invoice",
                payment_id=None,
                line_date=as_of_date,
                due_date=as_of_date,
                partner_id=901,
                partner_name="Customer",
                account_id=1001,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=1101,
                journal_code="INV",
                currency=self.currency_info,
                balance=Decimal("100"),
                amount_currency=Decimal("100"),
                current_reconciled=False,
            )
        ]

    def partials_as_of(self, *, company_id, move_line_ids, as_of_date):
        return {
            701: OpenItemPartial(
                debit_company=Decimal("30"),
                debit_currency=Decimal("30"),
                matched_count=1,
            )
        }


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


def capabilities():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return validate_registry(document)


def capability(capability_id="acct.gl.trial_balance.v1"):
    return next(item for item in capabilities() if item.id == capability_id)


class OdooReadExecutorTest(unittest.TestCase):
    def executor(self, *, env=None, registry=None):
        consumed = set()

        def consume(receipt_id, request_digest, _observed_at, _verified_at):
            key = (receipt_id, request_digest)
            if key in consumed:
                return False
            consumed.add(key)
            return True

        return OdooReadExecutor(
            env or Environment(),
            capabilities=capabilities() if registry is None else registry,
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
            ar_open_items_backend_factory=lambda _env, _user, _companies: ArBackend(),
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

    def test_registry_list_is_acl_filtered_sorted_and_receipted(self) -> None:
        env = Environment()
        executor = self.executor(env=env)
        requested = {"company_id": 7}
        registry_capability = capability("acct.registry.list.v1")
        result = executor(
            context(), registry_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(
            [item["id"] for item in result["capabilities"]],
            [
                "acct.ar.open_items.v1",
                "acct.gl.trial_balance.v1",
                "acct.registry.list.v1",
            ],
        )
        self.assertEqual(result["page"], {"count": 3, "total_count": 3})
        self.assertEqual(result["receipt"]["record_count"], 3)
        self.assertEqual(env.company.access_checks, [("rights", "read"), ("rule", "read")])
        for descriptor in result["capabilities"]:
            source = capability(descriptor["id"]).data
            canonical = json.dumps(
                source,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            self.assertEqual(descriptor["input_schema_json"], json.dumps(
                source["input_schema"], ensure_ascii=False, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ))
            self.assertEqual(descriptor["output_schema_json"], json.dumps(
                source["output_schema"], ensure_ascii=False, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ))
            self.assertEqual(
                descriptor["contract_digest"],
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(descriptor["capability_channel"], "staged")

        executor.verify(
            context(), registry_capability, requested, result, "c" * 64, "d" * 64
        )

    def test_registry_list_omits_capabilities_missing_any_required_group(self) -> None:
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        trial_balance = next(
            item
            for item in document["capabilities"]
            if item["id"] == "acct.gl.trial_balance.v1"
        )
        trial_balance["odoo_permissions"] = [
            "base.group_user",
            "account.group_account_readonly",
        ]
        registry = validate_registry(document)
        env = Environment(groups={"base.group_user"})
        result = self.executor(env=env, registry=registry)(
            context(),
            capability("acct.registry.list.v1"),
            {"company_id": 7},
            "c" * 64,
            "d" * 64,
        )
        self.assertEqual(
            [item["id"] for item in result["capabilities"]],
            ["acct.registry.list.v1"],
        )

    def test_ar_open_items_executes_trusted_handler_and_verifies_receipt(self) -> None:
        executor = self.executor()
        requested = {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": None,
            "currency_id": None,
            "limit": 100,
            "offset": 0,
        }
        ar_capability = capability("acct.ar.open_items.v1")

        result = executor(
            context(), ar_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(result["ledger_summary"]["net_residual"], "70.00")
        self.assertEqual(result["receipt"]["record_count"], 1)
        self.assertEqual(result["receipt"]["capability_id"], "acct.ar.open_items.v1")
        executor.verify(
            context(), ar_capability, requested, result, "c" * 64, "d" * 64
        )


if __name__ == "__main__":
    unittest.main()

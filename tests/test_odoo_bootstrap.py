import json
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from odoo_accounting_cli_v3.auth import context_payload, sign_request_context
from odoo_accounting_cli_v3.domain.trial_balance import AccountInfo, Aggregate, CurrencyInfo
from odoo_accounting_cli_v3.gateway import GatewayError
from odoo_accounting_cli_v3.odoo.bootstrap import (
    OdooBootstrapError,
    execute_read_from_odoo_shell,
    execute_read_json,
)
from odoo_accounting_cli_v3.odoo.executor import OdooReadExecutor
from odoo_accounting_cli_v3.registry import validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
NOW = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc)
AUTH_SECRET = b"test-only-auth-secret"
RECEIPT_SECRET = b"test-only-receipt-secret"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"


class Cursor:
    dbname = "odoo_test"


class ConfigParameters:
    def get_param(self, name):
        if name != "database.uuid":
            raise AssertionError("unexpected config parameter")
        return DATABASE_UUID


class RootEnvironment:
    cr = Cursor()

    def __getitem__(self, name):
        if name != "ir.config_parameter":
            raise AssertionError("unexpected root model")
        return ConfigParameters()


class Companies:
    def __init__(self, ids):
        self.ids = ids


class User:
    def __init__(self, *, company_ids=(7, 8), permitted=True):
        self.active = True
        self.company_ids = Companies(list(company_ids))
        self._permitted = permitted

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def has_group(self, xml_id):
        return self._permitted and xml_id == "account.group_account_readonly"

    def browse(self, user_id):
        if user_id != 42:
            raise AssertionError("unexpected user")
        return self

    def exists(self):
        return self


class BoundEnvironment:
    def __init__(self, user):
        self.uid = 42
        self.su = False
        self.cr = Cursor()
        self.user = user

    def __getitem__(self, name):
        if name != "res.users":
            raise AssertionError("unexpected bound model")
        return self.user


class Backend:
    def assert_read_access(self, *, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")

    def company_currency(self, *, company_id):
        return CurrencyInfo(12, "CNY", "CNY", Decimal("0.01"))

    def accounts(self, *, company_id, account_ids):
        return [AccountInfo(401, "1000", "Cash", "asset_cash")]

    def opening_aggregates(self, **_kwargs):
        return {}

    def period_aggregates(self, **_kwargs):
        return {401: Aggregate(Decimal("100"), Decimal("100"), Decimal("0"), 2)}


def enabled_capabilities():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    item = next(
        item for item in document["capabilities"] if item["id"] == "acct.gl.trial_balance.v1"
    )
    item["enabled_environments"] = ["test"]
    document["capabilities"] = [item]
    return validate_registry(document)


def parameters():
    return {
        "company_id": 7,
        "date_from": "2026-01-01",
        "date_to": "2026-12-31",
        "opening_basis": "ledger_cumulative",
        "currency_id": 12,
        "account_id": None,
        "include_off_balance": False,
        "include_zero": False,
        "limit": 100,
        "offset": 0,
    }


def signed_context(**changes):
    values = {
        "auth_token_id": "token-1",
        "principal": "pi:user-42",
        "odoo_instance_id": "odoo19@tokyo2",
        "database_name": "odoo_test",
        "database_uuid": DATABASE_UUID,
        "user_id": 42,
        "company_id": 7,
        "allowed_company_ids": frozenset({7, 8}),
        "environment": "test",
        "issued_at": NOW - timedelta(seconds=5),
        "expires_at": NOW + timedelta(minutes=4),
        "secret": AUTH_SECRET,
    }
    values.update(changes)
    return sign_request_context(**values)


def request_document(context=None):
    context = context or signed_context()
    wire_context = {**context_payload(context), "auth_signature": context.auth_signature}
    return {
        "capability_id": "acct.gl.trial_balance.v1",
        "context": wire_context,
        "parameters": parameters(),
    }


class OdooBootstrapTest(unittest.TestCase):
    def execute(self, request=None, *, user=None, consume_auth_token=None):
        factory_contexts = []
        bound = BoundEnvironment(user or User())

        def environment_factory(_cr, uid, context):
            self.assertEqual(uid, 42)
            factory_contexts.append(context)
            return bound

        def executor_factory(env, **kwargs):
            return OdooReadExecutor(
                env,
                **kwargs,
                receipt_id_factory=lambda: "receipt-bootstrap-1",
                trial_balance_backend_factory=lambda _env, _uid, _companies: Backend(),
            )

        result = execute_read_from_odoo_shell(
            RootEnvironment(),
            request or request_document(),
            capabilities=enabled_capabilities(),
            auth_secret=AUTH_SECRET,
            consume_auth_token=consume_auth_token or (lambda *_: True),
            receipt_secret=RECEIPT_SECRET,
            consume_receipt=lambda *_: True,
            release_digest="d" * 64,
            odoo_instance_id="odoo19@tokyo2",
            environment="test",
            now=NOW,
            environment_factory=environment_factory,
            executor_factory=executor_factory,
        )
        return result, factory_contexts

    def test_executes_with_bound_non_superuser_and_signed_receipt(self):
        result, factory_contexts = self.execute()
        self.assertEqual(factory_contexts, [{"allowed_company_ids": [7, 8]}])
        self.assertEqual(result["ledger_summary"]["period_debit"], "100.00")
        self.assertEqual(result["receipt"]["database_uuid"], DATABASE_UUID)
        self.assertEqual(result["receipt"]["user_id"], 42)

    def test_runtime_database_mismatch_is_rejected_before_environment_binding(self):
        context = signed_context(database_name="odoo_sg")
        with self.assertRaisesRegex(OdooBootstrapError, "does not match"):
            self.execute(request_document(context))

    def test_superuser_and_excess_company_scope_are_rejected(self):
        with self.assertRaisesRegex(OdooBootstrapError, "superuser"):
            self.execute(request_document(signed_context(user_id=1, principal="pi:user-1")))
        with self.assertRaisesRegex(OdooBootstrapError, "exceed"):
            self.execute(user=User(company_ids=(7,)))

    def test_missing_odoo_group_fails_closed(self):
        with self.assertRaisesRegex(GatewayError, "ACL"):
            self.execute(user=User(permitted=False))

    def test_replayed_authentication_token_is_rejected_before_read(self):
        with self.assertRaisesRegex(GatewayError, "authentication failed"):
            self.execute(consume_auth_token=lambda *_: False)

    def test_json_wrapper_rejects_duplicate_keys(self):
        with self.assertRaisesRegex(OdooBootstrapError, "duplicate JSON key"):
            execute_read_json(RootEnvironment(), '{"context":{},"context":{}}')

    def test_context_rejects_duplicate_allowed_companies(self):
        request = request_document()
        request["context"]["allowed_company_ids"] = [7, 7]
        with self.assertRaisesRegex(OdooBootstrapError, "unique positive"):
            self.execute(request)


if __name__ == "__main__":
    unittest.main()

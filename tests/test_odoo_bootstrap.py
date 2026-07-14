import json
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

from odoo_accounting_cli_v3.auth import context_payload, sign_request_context
from odoo_accounting_cli_v3.domain.ar_open_items import (
    CurrencyInfo as ArCurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
)
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
AUTH_SECRET = b"test-only-auth-secret-32-bytes!!"
RECEIPT_SECRET = b"test-only-receipt-secret-32-byte"
AUTH_KEY_ID = "test-auth-2026-07"
RECEIPT_KEY_ID = "test-receipt-2026-07"
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
    def __init__(self, *, company_ids=(7, 8), permitted=True, groups=None):
        self.active = True
        self.company_ids = Companies(list(company_ids))
        self._permitted = permitted
        self._groups = set(
            {"base.group_user", "account.group_account_readonly"}
            if groups is None
            else groups
        )

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def has_group(self, xml_id):
        return self._permitted and xml_id in self._groups

    def browse(self, user_id):
        if user_id != 42:
            raise AssertionError("unexpected user")
        return self

    def exists(self):
        return self


class Company:
    def __init__(self):
        self.access_checks = []

    def browse(self, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")
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


class BoundEnvironment:
    def __init__(self, user):
        self.uid = 42
        self.su = False
        self.cr = Cursor()
        self.user = user
        self.company = Company()

    def __getitem__(self, name):
        if name == "res.users":
            return self.user
        if name == "res.company":
            return self.company
        raise AssertionError("unexpected bound model")


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


class ArBackend:
    currency_info = ArCurrencyInfo(12, "CNY", "CNY", Decimal("0.01"))

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
                balance=Decimal("70"),
                amount_currency=Decimal("70"),
                current_reconciled=False,
            )
        ]

    def partials_as_of(self, *, company_id, move_line_ids, as_of_date):
        return {701: OpenItemPartial()}


class ApBackend(ArBackend):
    def assert_partner(self, *, company_id, partner_id):
        if (company_id, partner_id) != (7, 902):
            raise AssertionError("unexpected supplier binding")

    def currency(self, *, currency_id):
        if currency_id != 12:
            raise AssertionError("unexpected currency binding")
        return self.currency_info

    def source_lines(
        self, *, company_id, as_of_date, partner_id, currency_id, candidate_limit
    ):
        return [
            OpenItemSource(
                move_line_id=702,
                move_id=802,
                move_name="BILL/2026/007",
                move_type="in_invoice",
                payment_id=None,
                line_date=as_of_date,
                due_date=as_of_date,
                partner_id=902,
                partner_name="Supplier",
                account_id=1002,
                account_code="2202",
                account_name="Accounts Payable",
                journal_id=1102,
                journal_code="BILL",
                currency=self.currency_info,
                balance=Decimal("-70"),
                amount_currency=Decimal("-70"),
                current_reconciled=False,
            )
        ]

    def partials_as_of(self, *, company_id, move_line_ids, as_of_date):
        return {702: OpenItemPartial()}


def staged_capabilities():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
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
        "capability_id": "acct.gl.trial_balance.v1",
        "parameters": parameters(),
        "issued_at": NOW - timedelta(seconds=5),
        "expires_at": NOW + timedelta(minutes=4),
        "key_id": AUTH_KEY_ID,
        "secret": AUTH_SECRET,
    }
    values.update(changes)
    return sign_request_context(**values)


def request_document(
    context=None,
    *,
    capability_id="acct.gl.trial_balance.v1",
    request_parameters=None,
):
    request_parameters = request_parameters or parameters()
    if context is None:
        context = signed_context(
            capability_id=capability_id,
            parameters=request_parameters,
        )
    wire_context = {**context_payload(context), "auth_signature": context.auth_signature}
    return {
        "capability_id": capability_id,
        "context": wire_context,
        "parameters": request_parameters,
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
                ar_open_items_backend_factory=lambda _env, _uid, _companies: ArBackend(),
                ap_open_items_backend_factory=lambda _env, _uid, _companies: ApBackend(),
            )

        result = execute_read_from_odoo_shell(
            RootEnvironment(),
            request or request_document(),
            capabilities=staged_capabilities(),
            auth_secret=AUTH_SECRET,
            auth_key_id=AUTH_KEY_ID,
            consume_auth_token=consume_auth_token or (lambda *_: True),
            receipt_secret=RECEIPT_SECRET,
            receipt_key_id=RECEIPT_KEY_ID,
            consume_receipt=lambda *_: True,
            release_digest="d" * 64,
            odoo_instance_id="odoo19@tokyo2",
            environment="test",
            capability_channel="staged",
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

    def test_first_use_parameter_tampering_is_rejected_before_odoo_binding(self):
        request = request_document()
        request["parameters"]["date_to"] = "2026-11-30"
        with self.assertRaisesRegex(OdooBootstrapError, "content digest mismatch"):
            self.execute(request)

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

    def test_authentication_consumer_receives_signed_expiry_and_verification_time(self):
        calls = []

        def consume(token_id, request_digest, expires_at, verified_at):
            calls.append((token_id, request_digest, expires_at, verified_at))
            return True

        self.execute(consume_auth_token=consume)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "token-1")
        self.assertEqual(len(calls[0][1]), 64)
        self.assertEqual(calls[0][2], NOW + timedelta(minutes=4))
        self.assertEqual(calls[0][3], NOW)

    def test_json_wrapper_rejects_duplicate_keys(self):
        with self.assertRaisesRegex(OdooBootstrapError, "duplicate JSON key"):
            execute_read_json(RootEnvironment(), '{"context":{},"context":{}}')

    def test_context_rejects_duplicate_allowed_companies(self):
        request = request_document()
        request["context"]["allowed_company_ids"] = [7, 7]
        with self.assertRaisesRegex(OdooBootstrapError, "unique positive"):
            self.execute(request)

    def test_registry_list_uses_bound_odoo_acl_and_returns_standard_receipt(self):
        request = request_document(
            capability_id="acct.registry.list.v1",
            request_parameters={"company_id": 7},
        )
        result, _factory_contexts = self.execute(request)
        self.assertEqual(
            [item["id"] for item in result["capabilities"]],
            [
                "acct.ap.open_items.v1",
                "acct.ar.open_items.v1",
                "acct.gl.trial_balance.v1",
                "acct.registry.list.v1",
            ],
        )
        self.assertEqual(result["page"], {"count": 4, "total_count": 4})
        self.assertEqual(result["receipt"]["capability_id"], "acct.registry.list.v1")
        self.assertEqual(result["receipt"]["record_count"], 4)

    def test_ar_open_items_request_keeps_all_filters_and_returns_bound_receipt(self):
        requested = {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": None,
            "currency_id": None,
            "limit": 25,
            "offset": 0,
        }
        request = request_document(
            capability_id="acct.ar.open_items.v1",
            request_parameters=requested,
        )

        result, _factory_contexts = self.execute(request)

        self.assertEqual(result["filters"], {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": None,
            "currency_id": None,
        })
        self.assertEqual(result["page"]["limit"], 25)
        self.assertEqual(result["receipt"]["capability_id"], "acct.ar.open_items.v1")
        self.assertEqual(result["receipt"]["record_count"], 1)

    def test_ap_open_items_request_keeps_all_filters_and_returns_bound_receipt(self):
        requested = {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": 902,
            "currency_id": 12,
            "limit": 25,
            "offset": 0,
        }
        request = request_document(
            capability_id="acct.ap.open_items.v1",
            request_parameters=requested,
        )

        result, _factory_contexts = self.execute(request)

        self.assertEqual(result["filters"], {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": 902,
            "currency_id": 12,
        })
        self.assertEqual(result["page"]["limit"], 25)
        self.assertEqual(result["receipt"]["capability_id"], "acct.ap.open_items.v1")
        self.assertEqual(result["receipt"]["record_count"], 1)


if __name__ == "__main__":
    unittest.main()

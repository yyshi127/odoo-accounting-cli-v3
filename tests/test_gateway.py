import copy
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from odoo_accounting_cli_v3.contracts import ContractError
from odoo_accounting_cli_v3.gateway import CapabilityGateway, GatewayError, RequestContext
from odoo_accounting_cli_v3.receipts import ReceiptError, create_read_receipt, verify_read_receipt
from odoo_accounting_cli_v3.registry import validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
RELEASE_DIGEST = "d" * 64
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
RECEIPT_SECRET = b"test-only-gateway-receipt-secret"
AUTH_KEY_ID = "auth-key-2026-07"
RECEIPT_KEY_ID = "read-receipt-key-2026-07"


def enabled_capabilities():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    for item in document["capabilities"]:
        item["staged_environments"] = ["test"]
        item["enabled_environments"] = []
        item["evidence"]["level"] = "contract_tested"
    return validate_registry(document)


def context(user_id: int = 42, company_id: int = 7, database_uuid: str = DATABASE_UUID):
    return RequestContext(
        audience="odoo-accounting-cli-v3",
        auth_token_id=f"token-{user_id}-{company_id}",
        auth_issued_at=datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc),
        auth_expires_at=datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc) + timedelta(minutes=5),
        auth_signature_version=1,
        auth_signature_purpose="auth_context_v1",
        auth_key_id=AUTH_KEY_ID,
        auth_request_digest="b" * 64,
        auth_signature="a" * 64,
        principal=f"pi:test-user-{user_id}",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_test",
        database_uuid=database_uuid,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=frozenset({7, 8}),
        environment="test",
    )


def invoice_line():
    return {
        "name": "Consulting",
        "product_id": None,
        "account_id": 401,
        "quantity": "1",
        "price_unit": "100.00",
        "tax_ids": [],
    }


def trial_balance_parameters():
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


def trial_balance_body():
    summary = {
        "opening_balance": "0.00",
        "period_debit": "100.00",
        "period_credit": "100.00",
        "period_balance": "0.00",
        "closing_balance": "0.00",
        "debit_credit_difference": "0.00",
        "is_balanced": True,
    }
    return {
        "lines": [{
            "account_id": 401,
            "code": "1000",
            "name": "Cash",
            "account_type": "asset_cash",
            "opening_balance": "0.00",
            "period_debit": "100.00",
            "period_credit": "100.00",
            "period_balance": "0.00",
            "closing_balance": "0.00",
            "move_line_count": 2,
        }],
        "page": {"limit": 100, "offset": 0, "count": 1, "total_count": 1},
        "page_summary": copy.deepcopy(summary),
        "ledger_summary": copy.deepcopy(summary),
        "currency": {"id": 12, "name": "CNY", "symbol": "¥", "rounding": "0.01"},
    }


class GatewayTest(unittest.TestCase):
    def test_context_rejects_non_datetime_timestamps_as_gateway_error(self):
        values = context().__dict__.copy()
        values["auth_issued_at"] = "2026-07-13T07:00:00Z"
        with self.assertRaisesRegex(GatewayError, "timestamps"):
            RequestContext(**values)

    def test_context_rejects_invalid_signature_protocol_fields(self):
        for field, value, message in (
            ("auth_signature_version", 2, "version"),
            ("auth_signature_purpose", "read_receipt_v1", "purpose"),
            ("auth_key_id", "", "key ID"),
            ("auth_request_digest", "not-a-digest", "request digest"),
        ):
            with self.subTest(field=field):
                values = context().__dict__.copy()
                values[field] = value
                with self.assertRaisesRegex(GatewayError, message):
                    RequestContext(**values)

    def setUp(self) -> None:
        self.gateway = CapabilityGateway(
            enabled_capabilities(),
            release_digest=RELEASE_DIGEST,
            authenticate_context=lambda _context: True,
            acl_check=lambda _context, _capability, _parameters: True,
            availability_channel="staged",
        )

    def test_full_parameters_survive_prepare_and_preview(self) -> None:
        parameters = {
            "company_id": 7,
            "partner_id": 101,
            "invoice_date": "2026-07-13",
            "currency_id": 12,
            "lines": [invoice_line()],
            "idempotency_key": "invoice-20260713-101",
        }
        self.gateway.prepare(
            context(), operation_id="op-1", request_id="request-1",
            capability_id="acct.invoice.customer_create.v1", parameters=parameters,
        )
        preview = self.gateway.preview(context(), "op-1")
        self.assertEqual(preview["parameters"], parameters)

    def test_duplicate_idempotency_key_returns_same_operation(self) -> None:
        parameters = {"company_id": 7, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [invoice_line()], "idempotency_key": "same"}
        first = self.gateway.prepare(
            context(), operation_id="op-1", request_id="request-1",
            capability_id="acct.invoice.customer_create.v1", parameters=parameters,
        )
        second = self.gateway.prepare(
            context(), operation_id="op-2", request_id="request-2",
            capability_id="acct.invoice.customer_create.v1", parameters=copy.deepcopy(parameters),
        )
        self.assertEqual(first.operation_id, second.operation_id)

    def test_same_idempotency_key_with_changed_content_is_rejected(self) -> None:
        parameters = {"company_id": 7, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [invoice_line()], "idempotency_key": "conflict"}
        self.gateway.prepare(
            context(), operation_id="op-original", request_id="request-original",
            capability_id="acct.invoice.customer_create.v1", parameters=parameters,
        )
        changed = copy.deepcopy(parameters)
        changed["partner_id"] = 102
        with self.assertRaisesRegex(GatewayError, "idempotency conflict"):
            self.gateway.prepare(
                context(), operation_id="op-changed", request_id="request-changed",
                capability_id="acct.invoice.customer_create.v1", parameters=changed,
            )

    def test_cross_user_idempotency_collision_does_not_leak_operation(self) -> None:
        parameters = {"company_id": 7, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [invoice_line()], "idempotency_key": "private"}
        self.gateway.prepare(
            context(), operation_id="op-private", request_id="request-private",
            capability_id="acct.invoice.customer_create.v1", parameters=parameters,
        )
        with self.assertRaisesRegex(GatewayError, "another authenticated user"):
            self.gateway.prepare(
                context(user_id=43), operation_id="op-intruder", request_id="request-intruder",
                capability_id="acct.invoice.customer_create.v1", parameters=parameters,
            )

    def test_cross_company_request_is_rejected(self) -> None:
        parameters = {"company_id": 8, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [invoice_line()], "idempotency_key": "cross"}
        with self.assertRaisesRegex(GatewayError, "does not match"):
            self.gateway.prepare(
                context(), operation_id="op-cross", request_id="request-cross",
                capability_id="acct.invoice.customer_create.v1", parameters=parameters,
            )

    def test_missing_and_unknown_parameters_are_rejected(self) -> None:
        parameters = {"company_id": 7, "date_from": "2026-01-01", "date_to": "2026-12-31", "currency_id": None, "unexpected": True}
        with self.assertRaises(ContractError):
            self.gateway.validate_request(context(), "acct.gl.trial_balance.v1", parameters)

    def test_acl_rejection_is_enforced(self) -> None:
        gateway = CapabilityGateway(
            enabled_capabilities(), release_digest=RELEASE_DIGEST,
            authenticate_context=lambda _context: True,
            acl_check=lambda _context, _capability, _parameters: False,
            availability_channel="staged",
        )
        with self.assertRaisesRegex(GatewayError, "ACL"):
            gateway.get_capability(context(), "acct.gl.trial_balance.v1")

    def test_operation_status_is_bound_to_user_and_company(self) -> None:
        parameters = {"company_id": 7, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [invoice_line()], "idempotency_key": "bound"}
        self.gateway.prepare(
            context(), operation_id="op-bound", request_id="request-bound",
            capability_id="acct.invoice.customer_create.v1", parameters=parameters,
        )
        with self.assertRaisesRegex(GatewayError, "outside"):
            self.gateway.status(context(user_id=43), "op-bound")

    def test_only_test_enabled_capability_is_visible_or_callable(self) -> None:
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        gateway = CapabilityGateway(
            validate_registry(document), release_digest=RELEASE_DIGEST,
            authenticate_context=lambda _context: True,
            acl_check=lambda _context, _capability, _parameters: True,
            availability_channel="staged",
        )
        self.assertEqual(
            [item["id"] for item in gateway.list_capabilities(context())],
            [
                "acct.ar.open_items.v1",
                "acct.gl.trial_balance.v1",
                "acct.registry.list.v1",
            ],
        )
        with self.assertRaisesRegex(GatewayError, "not enabled"):
            gateway.get_capability(context(), "acct.invoice.customer_create.v1")

    def test_registry_list_requires_positive_bound_company(self) -> None:
        with self.assertRaises(ContractError):
            self.gateway.validate_request(
                context(), "acct.registry.list.v1", {"company_id": 0}
            )
        with self.assertRaisesRegex(GatewayError, "bound company"):
            self.gateway.validate_request(
                context(), "acct.registry.list.v1", {"company_id": 8}
            )

    def test_unauthenticated_context_is_rejected(self) -> None:
        gateway = CapabilityGateway(
            enabled_capabilities(), release_digest=RELEASE_DIGEST,
            authenticate_context=lambda _context: False,
            acl_check=lambda _context, _capability, _parameters: True,
            availability_channel="staged",
        )
        with self.assertRaisesRegex(GatewayError, "authentication failed"):
            gateway.list_capabilities(context())

    def test_database_binding_is_part_of_idempotency_identity(self) -> None:
        parameters = {"company_id": 7, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [invoice_line()], "idempotency_key": "same-db-local-key"}
        first = self.gateway.prepare(
            context(), operation_id="op-db-1", request_id="request-db-1",
            capability_id="acct.invoice.customer_create.v1", parameters=parameters,
        )
        second = self.gateway.prepare(
            context(database_uuid="22222222-2222-4222-8222-222222222222"),
            operation_id="op-db-2", request_id="request-db-2",
            capability_id="acct.invoice.customer_create.v1", parameters=parameters,
        )
        self.assertNotEqual(first.operation_id, second.operation_id)
        self.assertNotEqual(first.digest, second.digest)

    def test_read_executes_with_all_parameters_and_verifies_signed_receipt(self) -> None:
        observed = []

        def execute(bound_context, capability, bound_parameters, registry_sha, release_sha):
            observed.append(copy.deepcopy(bound_parameters))
            body = trial_balance_body()
            receipt = create_read_receipt(
                receipt_id="receipt-gateway-1",
                capability_id=capability.id,
                parameters=bound_parameters,
                result_body=body,
                auth_token_id=bound_context.auth_token_id,
                principal=bound_context.principal,
                odoo_instance_id=bound_context.odoo_instance_id,
                database_name=bound_context.database_name,
                database_uuid=bound_context.database_uuid,
                company_id=bound_context.company_id,
                user_id=bound_context.user_id,
                registry_digest=registry_sha,
                release_digest=release_sha,
                environment=bound_context.environment,
                capability_channel="staged",
                record_count=1,
                observed_at=datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc),
                key_id=RECEIPT_KEY_ID,
                secret=RECEIPT_SECRET,
            )
            return {**body, "receipt": receipt}

        def verify(bound_context, capability, bound_parameters, result, registry_sha, release_sha):
            body = {key: value for key, value in result.items() if key != "receipt"}
            verify_read_receipt(
                result["receipt"],
                capability_id=capability.id,
                parameters=bound_parameters,
                result_body=body,
                auth_token_id=bound_context.auth_token_id,
                principal=bound_context.principal,
                odoo_instance_id=bound_context.odoo_instance_id,
                database_name=bound_context.database_name,
                database_uuid=bound_context.database_uuid,
                company_id=bound_context.company_id,
                user_id=bound_context.user_id,
                registry_digest=registry_sha,
                release_digest=release_sha,
                environment=bound_context.environment,
                capability_channel="staged",
                expected_record_count=body["page"]["total_count"],
                now=datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc),
                consume_receipt=lambda *_: True,
                expected_key_id=RECEIPT_KEY_ID,
                secret=RECEIPT_SECRET,
            )

        gateway = CapabilityGateway(
            enabled_capabilities(), release_digest=RELEASE_DIGEST,
            authenticate_context=lambda _context: True,
            acl_check=lambda _context, _capability, _parameters: True,
            read_executor=execute,
            read_receipt_verifier=verify,
            availability_channel="staged",
        )
        requested = trial_balance_parameters()
        result = gateway.read(context(), "acct.gl.trial_balance.v1", requested)
        self.assertEqual(observed, [requested])
        self.assertEqual(result["ledger_summary"]["period_debit"], "100.00")

    def test_read_rejects_fabricated_receipt(self) -> None:
        def execute(*_args):
            body = trial_balance_body()
            receipt = {
                "id": "fabricated", "odoo_instance_id": "odoo19@tokyo2",
                "database_name": "odoo_test", "database_uuid": DATABASE_UUID,
                "company_id": 7, "user_id": 42,
                "capability_id": "acct.gl.trial_balance.v1",
                "capability_channel": "staged",
                "environment": "test",
                "request_digest": "a" * 64, "result_digest": "b" * 64,
                "registry_digest": "c" * 64, "release_digest": RELEASE_DIGEST,
                "record_count": 1, "observed_at": "2026-07-13T07:00:00Z",
                "signature_version": 2,
                "signature_purpose": "read_receipt_v2",
                "signature_key_id": RECEIPT_KEY_ID,
                "signature": "e" * 64,
            }
            return {**body, "receipt": receipt}

        def verify(bound_context, capability, bound_parameters, result, registry_sha, release_sha):
            body = {key: value for key, value in result.items() if key != "receipt"}
            verify_read_receipt(
                result["receipt"], capability_id=capability.id, parameters=bound_parameters,
                result_body=body, auth_token_id=bound_context.auth_token_id,
                principal=bound_context.principal,
                odoo_instance_id=bound_context.odoo_instance_id,
                database_name=bound_context.database_name,
                database_uuid=bound_context.database_uuid, company_id=bound_context.company_id,
                user_id=bound_context.user_id, registry_digest=registry_sha,
                release_digest=release_sha,
                environment=bound_context.environment,
                capability_channel="staged",
                expected_record_count=body["page"]["total_count"],
                now=datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc),
                consume_receipt=lambda *_: True,
                expected_key_id=RECEIPT_KEY_ID,
                secret=RECEIPT_SECRET,
            )

        gateway = CapabilityGateway(
            enabled_capabilities(), release_digest=RELEASE_DIGEST,
            authenticate_context=lambda _context: True,
            acl_check=lambda _context, _capability, _parameters: True,
            read_executor=execute, read_receipt_verifier=verify,
            availability_channel="staged",
        )
        with self.assertRaises(ReceiptError):
            gateway.read(context(), "acct.gl.trial_balance.v1", trial_balance_parameters())


if __name__ == "__main__":
    unittest.main()

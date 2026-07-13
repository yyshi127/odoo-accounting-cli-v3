import copy
import json
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.contracts import ContractError
from odoo_accounting_cli_v3.gateway import CapabilityGateway, GatewayError, RequestContext
from odoo_accounting_cli_v3.registry import validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


def enabled_capabilities():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    for item in document["capabilities"]:
        item["enabled_environments"] = ["test"]
        item["evidence"]["level"] = "contract_tested"
    return validate_registry(document)


def context(user_id: int = 42, company_id: int = 7):
    return RequestContext(user_id=user_id, company_id=company_id, allowed_company_ids=frozenset({7, 8}), environment="test")


class GatewayTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gateway = CapabilityGateway(enabled_capabilities(), acl_check=lambda _context, _capability: True)

    def test_full_parameters_survive_prepare_and_preview(self) -> None:
        parameters = {
            "company_id": 7,
            "partner_id": 101,
            "invoice_date": "2026-07-13",
            "currency_id": 12,
            "lines": [{"product": "Consulting", "quantity": "1", "price": "100.00"}],
            "idempotency_key": "invoice-20260713-101",
        }
        self.gateway.prepare(context(), operation_id="op-1", capability_id="acct.invoice.customer_create.v1", parameters=parameters)
        preview = self.gateway.preview(context(), "op-1")
        self.assertEqual(preview["parameters"], parameters)

    def test_duplicate_idempotency_key_returns_same_operation(self) -> None:
        parameters = {"company_id": 7, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [{}], "idempotency_key": "same"}
        first = self.gateway.prepare(context(), operation_id="op-1", capability_id="acct.invoice.customer_create.v1", parameters=parameters)
        second = self.gateway.prepare(context(), operation_id="op-2", capability_id="acct.invoice.customer_create.v1", parameters=copy.deepcopy(parameters))
        self.assertEqual(first.operation_id, second.operation_id)

    def test_cross_company_request_is_rejected(self) -> None:
        parameters = {"company_id": 8, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [{}], "idempotency_key": "cross"}
        with self.assertRaisesRegex(GatewayError, "does not match"):
            self.gateway.prepare(context(), operation_id="op-cross", capability_id="acct.invoice.customer_create.v1", parameters=parameters)

    def test_missing_and_unknown_parameters_are_rejected(self) -> None:
        parameters = {"company_id": 7, "date_from": "2026-01-01", "date_to": "2026-12-31", "currency_id": None, "unexpected": True}
        with self.assertRaises(ContractError):
            self.gateway.validate_request(context(), "acct.gl.trial_balance.v1", parameters)

    def test_acl_rejection_is_enforced(self) -> None:
        gateway = CapabilityGateway(enabled_capabilities(), acl_check=lambda _context, _capability: False)
        with self.assertRaisesRegex(GatewayError, "ACL"):
            gateway.get_capability(context(), "acct.gl.trial_balance.v1")

    def test_operation_status_is_bound_to_user_and_company(self) -> None:
        parameters = {"company_id": 7, "partner_id": 101, "invoice_date": "2026-07-13", "currency_id": 12, "lines": [{}], "idempotency_key": "bound"}
        self.gateway.prepare(context(), operation_id="op-bound", capability_id="acct.invoice.customer_create.v1", parameters=parameters)
        with self.assertRaisesRegex(GatewayError, "outside"):
            self.gateway.status(context(user_id=43), "op-bound")

    def test_disabled_capability_is_not_visible_or_callable(self) -> None:
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        gateway = CapabilityGateway(validate_registry(document), acl_check=lambda _context, _capability: True)
        self.assertEqual(gateway.list_capabilities(context()), [])
        with self.assertRaisesRegex(GatewayError, "not enabled"):
            gateway.get_capability(context(), "acct.gl.trial_balance.v1")


if __name__ == "__main__":
    unittest.main()

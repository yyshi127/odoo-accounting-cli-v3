import copy
import json
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.registry import RegistryError, load_registry, validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


class RegistryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    def test_repository_registry_is_valid_and_ids_are_unique(self) -> None:
        capabilities = load_registry(REGISTRY_PATH)
        self.assertEqual(len(capabilities), len({item.id for item in capabilities}))

    def test_all_goal_domains_are_registered(self) -> None:
        domains = {item["domain"] for item in self.document["capabilities"]}
        required = {
            "general_ledger", "accounts_receivable", "accounts_payable",
            "customer_invoice", "vendor_bill", "refund", "payment",
            "bank_statement", "reconciliation", "tax", "fixed_asset",
            "depreciation", "accrual", "deferred", "period_close",
            "financial_reporting", "multi_company", "multi_currency",
            "reversal", "diagnostics", "recovery",
        }
        self.assertEqual(required - domains, set())

    def test_every_write_requires_approval_and_idempotency(self) -> None:
        for item in self.document["capabilities"]:
            if item["access"] == "write":
                self.assertIs(item["approval"]["required"], True)
                self.assertIs(item["idempotency"]["required"], True)

    def test_no_capability_is_enabled_without_evidence(self) -> None:
        self.assertTrue(all(not item["enabled_environments"] for item in self.document["capabilities"]))

    def test_duplicate_id_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["capabilities"].append(copy.deepcopy(invalid["capabilities"][0]))
        with self.assertRaisesRegex(RegistryError, "duplicate capability id"):
            validate_registry(invalid)

    def test_unknown_parameters_are_forbidden_by_every_contract(self) -> None:
        for item in self.document["capabilities"]:
            self.assertIs(item["input_schema"]["additionalProperties"], False)
            self.assertIs(item["output_schema"]["additionalProperties"], False)

    def test_unverified_write_cannot_be_enabled_in_production(self) -> None:
        invalid = copy.deepcopy(self.document)
        write = next(item for item in invalid["capabilities"] if item["access"] == "write")
        write["enabled_environments"] = ["production"]
        with self.assertRaisesRegex(RegistryError, "cannot enable production"):
            validate_registry(invalid)


if __name__ == "__main__":
    unittest.main()

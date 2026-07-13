import copy
import json
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.registry import RegistryError, load_registry, registry_digest, validate_registry


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

    def test_claimed_production_level_without_receipts_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.document)
        read = next(item for item in invalid["capabilities"] if item["access"] == "read")
        read["enabled_environments"] = ["production"]
        read["evidence"]["level"] = "production_verified"
        with self.assertRaisesRegex(RegistryError, "production evidence is incomplete"):
            validate_registry(invalid)

    def test_sandbox_write_without_lifecycle_receipts_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.document)
        write = next(item for item in invalid["capabilities"] if item["access"] == "write")
        write["enabled_environments"] = ["sandbox"]
        write["evidence"]["level"] = "sandbox_verified"
        with self.assertRaisesRegex(RegistryError, "sandbox write evidence is incomplete"):
            validate_registry(invalid)

    def test_write_approval_ttl_is_bounded(self) -> None:
        invalid = copy.deepcopy(self.document)
        write = next(item for item in invalid["capabilities"] if item["access"] == "write")
        write["approval"]["ttl_seconds"] = 901
        with self.assertRaisesRegex(RegistryError, "ttl_seconds"):
            validate_registry(invalid)

    def test_policy_objects_reject_unknown_fields(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["capabilities"][0]["verification"]["trusted"] = True
        with self.assertRaisesRegex(RegistryError, "verification fields invalid"):
            validate_registry(invalid)

    def test_nested_schema_without_type_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["capabilities"][0]["input_schema"]["properties"]["company_id"].pop("type")
        with self.assertRaisesRegex(RegistryError, "type is required"):
            validate_registry(invalid)

    def test_unsupported_schema_keyword_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["capabilities"][0]["input_schema"]["properties"]["company_id"]["coerce"] = True
        with self.assertRaisesRegex(RegistryError, "unsupported schema keywords"):
            validate_registry(invalid)

    def test_validated_capability_is_immutable(self) -> None:
        capability = validate_registry(self.document)[0]
        first = capability.data
        first["enabled_environments"].append("production")
        self.assertEqual(capability.data["enabled_environments"], [])

    def test_registry_digest_is_deterministic_and_content_bound(self) -> None:
        first = validate_registry(self.document)
        second = validate_registry(copy.deepcopy(self.document))
        self.assertEqual(registry_digest(first), registry_digest(second))
        changed = copy.deepcopy(self.document)
        changed["capabilities"][0]["business_description"] += " Changed."
        self.assertNotEqual(registry_digest(first), registry_digest(validate_registry(changed)))


if __name__ == "__main__":
    unittest.main()

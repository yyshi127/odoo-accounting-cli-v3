import copy
import json
import unittest
from pathlib import Path

from odoo_accounting_cli_v3.registry import RegistryError, load_registry, registry_digest, validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"


def _evidence_receipt(
    kind: str,
    *,
    capability_id: str = "acct.invoice.customer_create.v1",
    environment: str = "sandbox",
) -> dict[str, object]:
    return {
        "artifact_sha256": "a" * 64,
        "capability_id": capability_id,
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": environment,
        "id": f"receipt-{environment}-{kind}",
        "kind": kind,
        "registry_sha256": "b" * 64,
        "release_sha256": "c" * 64,
        "signature": "signature",
        "verified_at": "2026-07-17T00:00:00Z",
    }


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

    def test_only_contract_tested_reads_are_staged_in_test(self) -> None:
        staged = [
            item
            for item in self.document["capabilities"]
            if item.get("staged_environments")
        ]
        self.assertEqual(
            [item["id"] for item in staged],
            [
                "acct.registry.list.v1",
                "acct.gl.trial_balance.v1",
                "acct.ar.open_items.v1",
                "acct.ap.open_items.v1",
                "acct.multicurrency.balance_read.v1",
                "acct.move.draft_cancel_eligibility.v1",
            ],
        )
        for item in staged:
            self.assertEqual(item["staged_environments"], ["test"])
            self.assertEqual(item["enabled_environments"], [])
            self.assertEqual(item["evidence"]["level"], "contract_tested")
        self.assertTrue(
            all(not item["enabled_environments"] for item in self.document["capabilities"])
        )
        self.assertTrue(
            all(
                not item["enabled_environments"]
                for item in self.document["capabilities"]
                if item["access"] == "write"
            )
        )

    def test_staging_and_enablement_are_separate_evidence_gates(self) -> None:
        declared = copy.deepcopy(self.document)
        declared_item = next(
            item for item in declared["capabilities"] if item["evidence"]["level"] == "declared"
        )
        declared_item["staged_environments"] = ["test"]
        with self.assertRaisesRegex(RegistryError, "contract-tested"):
            validate_registry(declared)

        incomplete = copy.deepcopy(self.document)
        trial_balance = next(
            item
            for item in incomplete["capabilities"]
            if item["id"] == "acct.gl.trial_balance.v1"
        )
        trial_balance["staged_environments"] = []
        trial_balance["enabled_environments"] = ["test"]
        with self.assertRaisesRegex(RegistryError, "test_verified"):
            validate_registry(incomplete)

    def test_registry_list_contract_is_strict_and_non_placeholder(self) -> None:
        item = next(
            item
            for item in self.document["capabilities"]
            if item["id"] == "acct.registry.list.v1"
        )
        self.assertEqual(
            item["input_schema"]["properties"]["company_id"],
            {"type": "integer", "minimum": 1},
        )
        self.assertEqual(
            item["output_schema"]["required"],
            ["capabilities", "page", "receipt"],
        )
        descriptor = item["output_schema"]["properties"]["capabilities"]["items"]
        self.assertEqual(
            set(descriptor["required"]),
            {
                "id", "domain", "business_description", "access", "risk_level",
                "company_scope", "odoo_permissions", "approval_required",
                "idempotency_required", "input_schema_json", "output_schema_json",
                "contract_digest", "evidence_level", "verification_method",
                "recovery_method", "capability_channel",
            },
        )
        self.assertTrue(descriptor["properties"])
        page = item["output_schema"]["properties"]["page"]
        self.assertEqual(page["required"], ["count", "total_count"])
        self.assertTrue(item["output_schema"]["properties"]["receipt"]["properties"])

    def test_ar_open_items_contract_is_strict_and_discloses_historical_basis(self) -> None:
        item = next(
            item
            for item in self.document["capabilities"]
            if item["id"] == "acct.ar.open_items.v1"
        )
        self.assertEqual(
            item["input_schema"]["required"],
            ["company_id", "as_of_date", "partner_id", "currency_id", "limit", "offset"],
        )
        self.assertEqual(
            item["output_schema"]["properties"]["basis"]["enum"],
            ["odoo_accounting_date_current_reconciliation_graph"],
        )
        self.assertTrue(
            item["output_schema"]["properties"]["items"]["items"]["properties"]
        )
        self.assertEqual(item["staged_environments"], ["test"])
        self.assertEqual(item["enabled_environments"], [])

    def test_draft_cancel_eligibility_contract_is_strict_and_not_enabled(self) -> None:
        item = next(
            item
            for item in self.document["capabilities"]
            if item["id"] == "acct.move.draft_cancel_eligibility.v1"
        )
        self.assertEqual(
            item["input_schema"]["required"],
            ["company_id", "move_id", "expected_move_type"],
        )
        self.assertIs(item["input_schema"]["additionalProperties"], False)
        self.assertEqual(item["access"], "read")
        self.assertEqual(item["risk_level"], "medium")
        self.assertEqual(item["odoo_permissions"], ["account.group_account_invoice"])
        self.assertEqual(item["company_scope"], "explicit_single_company")
        self.assertEqual(item["evidence"], {"level": "contract_tested", "receipts": []})
        self.assertEqual(item["staged_environments"], ["test"])
        self.assertEqual(item["enabled_environments"], [])
        output = item["output_schema"]
        self.assertEqual(
            output["required"],
            [
                "candidate_write_capability_id",
                "basis",
                "filters",
                "target",
                "eligible",
                "eligibility_failures",
                "failed_line_ids",
                "checks",
                "write_parameters",
                "page",
                "receipt",
            ],
        )
        self.assertIn("oneOf", output["properties"]["write_parameters"])

    def test_ap_open_items_contract_matches_strict_historical_open_item_shape(self) -> None:
        item = next(
            item
            for item in self.document["capabilities"]
            if item["id"] == "acct.ap.open_items.v1"
        )
        ar_item = next(
            item
            for item in self.document["capabilities"]
            if item["id"] == "acct.ar.open_items.v1"
        )
        self.assertEqual(item["input_schema"], ar_item["input_schema"])
        self.assertEqual(item["output_schema"], ar_item["output_schema"])
        self.assertIn("payable", item["business_description"])
        self.assertEqual(item["evidence"]["level"], "contract_tested")
        self.assertEqual(item["staged_environments"], ["test"])
        self.assertEqual(item["enabled_environments"], [])

    def test_multicurrency_contract_is_strict_but_not_claimed_as_verified(self) -> None:
        item = next(
            item
            for item in self.document["capabilities"]
            if item["id"] == "acct.multicurrency.balance_read.v1"
        )
        self.assertEqual(
            item["input_schema"]["required"],
            [
                "company_id",
                "as_of_date",
                "currency_ids",
                "balance_basis",
                "off_balance_policy",
                "limit",
                "offset",
            ],
        )
        currency_ids = item["input_schema"]["properties"]["currency_ids"]
        self.assertIs(currency_ids["uniqueItems"], True)
        self.assertEqual(currency_ids["maxItems"], 50)
        output = item["output_schema"]["properties"]
        self.assertTrue(output["balances"]["items"]["properties"])
        rate_properties = output["rates"]["items"]["properties"]
        self.assertEqual(
            rate_properties["formula"]["enum"],
            ["company_technical_rate / transaction_technical_rate"],
        )
        for source_name in (
            "transaction_technical_source",
            "company_technical_source",
        ):
            source = rate_properties[source_name]
            self.assertIs(source["additionalProperties"], False)
            self.assertEqual(
                source["properties"]["source_scope"]["enum"],
                ["no_rate_identity", "company_specific", "global"],
            )
            self.assertIn("odoo_technical_rate", source["required"])
        self.assertTrue(output["receipt"]["properties"])
        self.assertEqual(output["page"]["properties"]["total_count"]["maximum"], 25000)
        self.assertEqual(
            item["evidence"], {"level": "contract_tested", "receipts": []}
        )
        self.assertEqual(item["staged_environments"], ["test"])
        self.assertEqual(item["enabled_environments"], [])

    def test_duplicate_id_is_rejected(self) -> None:
        invalid = copy.deepcopy(self.document)
        invalid["capabilities"].append(copy.deepcopy(invalid["capabilities"][0]))
        with self.assertRaisesRegex(RegistryError, "duplicate capability id"):
            validate_registry(invalid)

    def test_unknown_parameters_are_forbidden_by_every_contract(self) -> None:
        for item in self.document["capabilities"]:
            self.assertIs(item["input_schema"]["additionalProperties"], False)
            self.assertIs(item["output_schema"]["additionalProperties"], False)

    def test_no_registered_contract_contains_empty_object_placeholders(self) -> None:
        def walk_schema(node: object, path: str) -> list[str]:
            failures: list[str] = []
            if isinstance(node, dict):
                if (
                    node.get("type") == "object"
                    and node.get("additionalProperties") is False
                    and node.get("properties") == {}
                    and node.get("required") == []
                ):
                    failures.append(path)
                for key in ("properties", "$defs", "definitions"):
                    for name, child in node.get(key, {}).items():
                        failures.extend(walk_schema(child, f"{path}.{key}.{name}"))
                if "items" in node:
                    failures.extend(walk_schema(node["items"], f"{path}.items"))
                for key in ("oneOf", "anyOf", "allOf"):
                    for index, child in enumerate(node.get(key, [])):
                        failures.extend(walk_schema(child, f"{path}.{key}[{index}]"))
            return failures

        failures: list[str] = []
        for item in self.document["capabilities"]:
            failures.extend(
                walk_schema(item["input_schema"], f"{item['id']}.input_schema")
            )
            failures.extend(
                walk_schema(item["output_schema"], f"{item['id']}.output_schema")
            )

        self.assertEqual(failures, [])

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

    def test_sandbox_write_requires_complete_same_environment_evidence(self) -> None:
        invalid = copy.deepcopy(self.document)
        write = next(item for item in invalid["capabilities"] if item["access"] == "write")
        write["enabled_environments"] = ["sandbox"]
        write["evidence"]["level"] = "sandbox_verified"
        write["evidence"]["receipts"] = [
            _evidence_receipt(kind)
            for kind in ("sandbox_write_lifecycle", "recovery", "security_negative")
        ]
        with self.assertRaisesRegex(RegistryError, "sandbox write evidence is incomplete"):
            validate_registry(invalid)

        wrong_environment = copy.deepcopy(invalid)
        wrong_environment_write = next(
            item
            for item in wrong_environment["capabilities"]
            if item["access"] == "write"
        )
        wrong_environment_write["evidence"]["receipts"] = [
            _evidence_receipt(kind, environment="production")
            for kind in (
                "accounting_oracle",
                "live_odoo",
                "pi_e2e",
                "release_identity",
                "recovery",
                "sandbox_write_lifecycle",
                "security_negative",
            )
        ]
        with self.assertRaisesRegex(RegistryError, "sandbox write evidence is incomplete"):
            validate_registry(wrong_environment)

        complete = copy.deepcopy(invalid)
        complete_write = next(
            item for item in complete["capabilities"] if item["access"] == "write"
        )
        complete_write["evidence"]["receipts"] = [
            _evidence_receipt(kind)
            for kind in (
                "accounting_oracle",
                "live_odoo",
                "pi_e2e",
                "release_identity",
                "recovery",
                "sandbox_write_lifecycle",
                "security_negative",
            )
        ]
        validate_registry(complete)

    def test_evidence_receipts_must_match_their_capability(self) -> None:
        invalid = copy.deepcopy(self.document)
        write = next(
            item
            for item in invalid["capabilities"]
            if item["id"] == "acct.bill.vendor_create.v1"
        )
        write["enabled_environments"] = ["sandbox"]
        write["evidence"]["level"] = "sandbox_verified"
        write["evidence"]["receipts"] = [
            _evidence_receipt(
                kind,
                capability_id="acct.invoice.customer_create.v1",
            )
            for kind in (
                "accounting_oracle",
                "live_odoo",
                "pi_e2e",
                "release_identity",
                "recovery",
                "sandbox_write_lifecycle",
                "security_negative",
            )
        ]

        with self.assertRaisesRegex(
            RegistryError, "capability_id does not match capability"
        ):
            validate_registry(invalid)

    def test_evidence_receipt_ids_are_unique_across_capabilities(self) -> None:
        invalid = copy.deepcopy(self.document)
        customer = next(
            item
            for item in invalid["capabilities"]
            if item["id"] == "acct.invoice.customer_create.v1"
        )
        vendor = next(
            item
            for item in invalid["capabilities"]
            if item["id"] == "acct.bill.vendor_create.v1"
        )
        for write in (customer, vendor):
            write["enabled_environments"] = ["sandbox"]
            write["evidence"]["level"] = "sandbox_verified"
            write["evidence"]["receipts"] = [
                _evidence_receipt(kind, capability_id=write["id"])
                for kind in (
                    "accounting_oracle",
                    "live_odoo",
                    "pi_e2e",
                    "release_identity",
                    "recovery",
                    "sandbox_write_lifecycle",
                    "security_negative",
                )
            ]

        with self.assertRaisesRegex(
            RegistryError, "duplicate evidence receipt id across capabilities"
        ):
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

    def test_one_of_schema_nodes_are_strictly_structured(self) -> None:
        write = next(
            item for item in self.document["capabilities"] if item["access"] == "write"
        )
        recovery = write["output_schema"]["properties"]["recovery_plan"]
        self.assertEqual(len(recovery["oneOf"]), 2)

        combined = copy.deepcopy(self.document)
        combined_write = next(
            item for item in combined["capabilities"] if item["access"] == "write"
        )
        combined_write["output_schema"]["properties"]["recovery_plan"]["type"] = "object"
        with self.assertRaisesRegex(RegistryError, "cannot be combined"):
            validate_registry(combined)

        single = copy.deepcopy(self.document)
        single_write = next(
            item for item in single["capabilities"] if item["access"] == "write"
        )
        single_write["output_schema"]["properties"]["recovery_plan"]["oneOf"] = [
            recovery["oneOf"][0]
        ]
        with self.assertRaisesRegex(RegistryError, "at least two"):
            validate_registry(single)

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

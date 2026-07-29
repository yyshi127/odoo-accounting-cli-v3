import copy
import hashlib
import hmac
import json
import secrets
import unittest
from pathlib import Path

from tools.pi_scenario_gate import (
    CorpusValidationError,
    TraceValidationError,
    canonical_sha256,
    load_attestation_keys,
    material_path_value,
    resolve_fixture_bindings,
    score_documents,
    trace_attestation_payload,
    validate_corpus,
    validate_trace_document,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = PROJECT_ROOT / "tests" / "fixtures" / "pi_scenarios.v1.json"
REGISTRY_PATH = PROJECT_ROOT / "registry" / "capabilities.json"
TEST_ATTESTATION_KEY_ID = "test-pi-capture-key"
TEST_ATTESTATION_KEY = secrets.token_bytes(32)
TEST_ATTESTATION_KEYS = {TEST_ATTESTATION_KEY_ID: TEST_ATTESTATION_KEY}
TEST_RELEASE_SHA256 = hashlib.sha256(b"test v3 release").hexdigest()
TEST_WRONG_RELEASE_SHA256 = hashlib.sha256(b"wrong test v3 release").hexdigest()
TEST_APPROVAL_DIGEST = hashlib.sha256(b"approval binding").hexdigest()
TEST_WRONG_PARAMETERS_DIGEST = hashlib.sha256(b"wrong parameters").hexdigest()
TEST_WRONG_RECEIPT_DIGEST = hashlib.sha256(b"wrong receipt parameters").hexdigest()
TEST_WRONG_CORPUS_DIGEST = hashlib.sha256(b"wrong corpus").hexdigest()
TEST_WRONG_REGISTRY_DIGEST = hashlib.sha256(b"wrong registry").hexdigest()


class PiScenarioGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        self.corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))

    def _bindings(self) -> dict[str, object]:
        return {
            name: definition["example"]
            for name, definition in self.corpus["fixture_bindings"].items()
        }

    def _perfect_trace_document(self) -> dict[str, object]:
        bindings = self._bindings()
        access_by_capability = {
            item["id"]: item["access"] for item in self.registry["capabilities"]
        }
        traces = []
        for index, scenario in enumerate(self.corpus["scenarios"], start=1):
            expected = scenario["expected"]
            parameters = resolve_fixture_bindings(
                expected["material_parameters"], bindings
            )
            clarification = copy.deepcopy(expected["clarification"])
            clarification["turns"] = [
                {
                    "field": field,
                    "question": f"请确认 {field}",
                    "answer": material_path_value(parameters, field),
                }
                for field in clarification["fields"]
            ]
            parameters_sha256 = canonical_sha256(parameters)
            is_write = access_by_capability[expected["capability_id"]] == "write"
            traces.append(
                {
                    "scenario_id": scenario["id"],
                    "trace_id": f"trace-{index:03d}",
                    "started_at": "2026-07-17T00:00:00Z",
                    "completed_at": "2026-07-17T00:00:01Z",
                    "events": [
                        {
                            "sequence": 1,
                            "type": "user_input",
                            "data": {"text": scenario["input"]},
                        },
                        {
                            "sequence": 2,
                            "type": "capability_selected",
                            "data": {
                                "capability_id": expected["capability_id"]
                            },
                        },
                        {
                            "sequence": 3,
                            "type": "clarification_completed",
                            "data": clarification,
                        },
                        {
                            "sequence": 4,
                            "type": "material_parameters_finalized",
                            "data": {"parameters": parameters},
                        },
                        {
                            "sequence": 5,
                            "type": "cli_input",
                            "data": {"parameters": copy.deepcopy(parameters)},
                        },
                        {
                            "sequence": 6,
                            "type": "prepare",
                            "data": {
                                "applicable": is_write,
                                "parameters": copy.deepcopy(parameters) if is_write else None,
                            },
                        },
                        {
                            "sequence": 7,
                            "type": "preview",
                            "data": {
                                "applicable": is_write,
                                "parameters": copy.deepcopy(parameters) if is_write else None,
                            },
                        },
                        {
                            "sequence": 8,
                            "type": "approval_binding",
                            "data": {
                                "applicable": is_write,
                                "parameters_sha256": parameters_sha256 if is_write else None,
                                "approval_digest": TEST_APPROVAL_DIGEST if is_write else None,
                            },
                        },
                        {
                            "sequence": 9,
                            "type": "odoo_execution",
                            "data": {
                                "parameters_sha256": parameters_sha256,
                                "execution_reference": f"odoo-execution-{index:03d}",
                            },
                        },
                        {
                            "sequence": 10,
                            "type": "odoo_result",
                            "data": {
                                "parameters_sha256": parameters_sha256,
                                "result_reference": f"odoo-result-{index:03d}",
                                "business_succeeded": True,
                                "bridge_guidance": None,
                            },
                        },
                        {
                            "sequence": 11,
                            "type": "audit_receipt",
                            "data": {
                                "parameters_sha256": parameters_sha256,
                                "receipt_id": f"receipt-{index:03d}",
                            },
                        },
                    ],
                }
            )
        document = {
            "schema_version": "odoo-accounting-cli-v3.pi-traces.v1",
            "corpus_id": self.corpus["corpus_id"],
            "corpus_sha256": canonical_sha256(self.corpus),
            "registry_sha256": canonical_sha256(self.registry),
            "capture": {
                "source": "pi_agent",
                "run_id": "pi-run-20260717-001",
                "captured_at": "2026-07-17T00:01:00Z",
                "pi_agent_version": "test-pi-build",
                "pi_bridge_version": "test-bridge-build",
                "v3_release_sha256": TEST_RELEASE_SHA256,
            },
            "bindings": bindings,
            "traces": traces,
        }
        self._resign(document)
        return document

    def _resign(self, document: dict[str, object]) -> None:
        document.pop("attestation", None)
        payload = trace_attestation_payload(document)
        document["attestation"] = {
            "algorithm": "hmac-sha256",
            "key_id": TEST_ATTESTATION_KEY_ID,
            "signed_payload_sha256": hashlib.sha256(payload).hexdigest(),
            "signature": hmac.new(
                TEST_ATTESTATION_KEY, payload, hashlib.sha256
            ).hexdigest(),
        }

    def test_repository_corpus_is_strict_and_covers_every_registered_capability(self) -> None:
        validate_corpus(self.corpus, self.registry)
        registered = {item["id"] for item in self.registry["capabilities"]}
        covered = {
            scenario["expected"]["capability_id"]
            for scenario in self.corpus["scenarios"]
        }
        self.assertEqual(covered, registered)
        self.assertEqual(len(self.corpus["scenarios"]), 28)
        self.assertEqual(
            {scenario["category"] for scenario in self.corpus["scenarios"]},
            {
                "ordinary",
                "ambiguous",
                "adversarial",
                "multi_company",
                "multi_currency",
                "recovery",
            },
        )
        clarification_fields = {
            field
            for scenario in self.corpus["scenarios"]
            for field in scenario["expected"]["clarification"]["fields"]
        }
        self.assertTrue(
            {
                "amount",
                "as_of_date",
                "company_id",
                "currency_id",
                "due_date",
                "journal_id",
                "lines[].tax_ids",
                "partner_id",
                "posting_date",
                "posting_mode",
            }.issubset(clarification_fields)
        )

        draft_cancel_scenarios = [
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"]
            == "acct.move.draft_cancel.v1"
        ]
        self.assertEqual(
            [scenario["id"] for scenario in draft_cancel_scenarios],
            ["pi-v1-customer-draft-cancel", "pi-v1-vendor-draft-cancel"],
        )
        for scenario in draft_cancel_scenarios:
            self.assertEqual(
                set(scenario["expected"]["material_parameters"]),
                {
                    "company_id",
                    "move_id",
                    "expected_move_type",
                    "expected_document_binding",
                    "expected_business_binding",
                    "reason",
                    "idempotency_key",
                },
            )

        tax_report_scenario = next(
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["id"] == "pi-v1-tax-report"
        )
        self.assertNotIn(
            "report_id",
            tax_report_scenario["expected"]["material_parameters"],
        )
        financial_report_scenarios = [
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"]
            == "acct.report.financial_read.v1"
        ]
        self.assertEqual(
            [scenario["id"] for scenario in financial_report_scenarios],
            [
                "pi-v1-financial-report-balance-sheet",
                "pi-v1-financial-report-profit-and-loss",
                "pi-v1-financial-report-cash-flow",
                "pi-v1-financial-report-ambiguous-kind",
            ],
        )
        self.assertEqual(
            [
                scenario["expected"]["material_parameters"]["report_request"][
                    "kind"
                ]
                for scenario in financial_report_scenarios[:3]
            ],
            ["balance_sheet", "profit_and_loss", "cash_flow"],
        )
        for scenario in financial_report_scenarios:
            self.assertNotIn(
                "report_id",
                scenario["expected"]["material_parameters"]["report_request"],
            )
        self.assertEqual(
            financial_report_scenarios[-1]["expected"]["clarification"],
            {"outcome": "clarified", "fields": ["report_request"]},
        )

        trace_document = self._perfect_trace_document()
        traces = {
            trace["scenario_id"]: trace for trace in trace_document["traces"]
        }
        for scenario in draft_cancel_scenarios:
            trace = traces[scenario["id"]]
            resolved = resolve_fixture_bindings(
                scenario["expected"]["material_parameters"], self._bindings()
            )
            self.assertEqual(
                trace["events"][5]["data"],
                {"applicable": True, "parameters": resolved},
            )
            self.assertEqual(
                trace["events"][6]["data"],
                {"applicable": True, "parameters": resolved},
            )
            self.assertEqual(
                trace["events"][7]["data"],
                {
                    "applicable": True,
                    "parameters_sha256": canonical_sha256(resolved),
                    "approval_digest": TEST_APPROVAL_DIGEST,
                },
            )

    def test_corpus_rejects_duplicate_ids_unknown_fields_and_incomplete_parameters(self) -> None:
        duplicate = copy.deepcopy(self.corpus)
        duplicate["scenarios"][1]["id"] = duplicate["scenarios"][0]["id"]
        with self.assertRaisesRegex(CorpusValidationError, "duplicate scenario id"):
            validate_corpus(duplicate, self.registry)

        extra = copy.deepcopy(self.corpus)
        extra["scenarios"][0]["unexpected"] = True
        with self.assertRaisesRegex(CorpusValidationError, "fields invalid"):
            validate_corpus(extra, self.registry)

        incomplete = copy.deepcopy(self.corpus)
        del incomplete["scenarios"][0]["expected"]["material_parameters"]["company_id"]
        with self.assertRaisesRegex(CorpusValidationError, "missing required parameters"):
            validate_corpus(incomplete, self.registry)

        optional_registry = copy.deepcopy(self.registry)
        optional_registry["capabilities"][0]["input_schema"]["required"] = []
        optional_omission = copy.deepcopy(self.corpus)
        del optional_omission["scenarios"][0]["expected"]["material_parameters"][
            "company_id"
        ]
        with self.assertRaisesRegex(CorpusValidationError, "missing required parameters"):
            validate_corpus(optional_omission, optional_registry)

        nested_registry = copy.deepcopy(self.registry)
        invoice_contract = next(
            item
            for item in nested_registry["capabilities"]
            if item["id"] == "acct.invoice.customer_create.v1"
        )
        line_schema = invoice_contract["input_schema"]["properties"]["lines"]["items"]
        line_schema["required"].remove("tax_ids")
        nested_omission = copy.deepcopy(self.corpus)
        invoice_scenario = next(
            scenario
            for scenario in nested_omission["scenarios"]
            if scenario["id"] == "pi-v1-customer-invoice"
        )
        del invoice_scenario["expected"]["material_parameters"]["lines"][0][
            "tax_ids"
        ]
        with self.assertRaisesRegex(
            CorpusValidationError, "missing material schema properties"
        ):
            validate_corpus(nested_omission, nested_registry)

    def test_corpus_rejects_placeholder_sha256_values(self) -> None:
        placeholder_fixture = copy.deepcopy(self.corpus)
        placeholder_fixture["fixture_bindings"]["recovery_plan_digest"][
            "example"
        ] = "a" * 64
        with self.assertRaisesRegex(CorpusValidationError, "placeholder SHA-256"):
            validate_corpus(placeholder_fixture, self.registry)

        placeholder_parameter = copy.deepcopy(self.corpus)
        bank_scenario = next(
            scenario
            for scenario in placeholder_parameter["scenarios"]
            if scenario["id"] == "pi-v1-bank-statement"
        )
        bank_scenario["expected"]["material_parameters"]["source_digest"] = "b" * 64
        with self.assertRaisesRegex(CorpusValidationError, "placeholder SHA-256"):
            validate_corpus(placeholder_parameter, self.registry)

    def test_empty_trace_set_cannot_claim_accuracy(self) -> None:
        trace_document = self._perfect_trace_document()
        trace_document["traces"] = []
        self._resign(trace_document)
        with self.assertRaisesRegex(
            TraceValidationError, "no captured Pi traces; accuracy is not scoreable"
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_perfect_captured_run_passes_with_exact_ratios(self) -> None:
        trace_document = self._perfect_trace_document()
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertTrue(report["acceptance_passed"])
        self.assertEqual(
            report["trace_coverage"],
            {
                "captured": 28,
                "expected": 28,
                "passed": True,
                "missing_scenario_ids": [],
            },
        )
        for gate_id in ("F01", "F02", "F03", "F05"):
            self.assertEqual(report["gates"][gate_id]["numerator"], 28)
            self.assertEqual(report["gates"][gate_id]["denominator"], 28)
            self.assertEqual(report["gates"][gate_id]["percent"], "100.00")
            self.assertTrue(report["gates"][gate_id]["passed"])

    def test_selection_gate_fails_below_95_percent(self) -> None:
        trace_document = self._perfect_trace_document()
        wrong_id = self.corpus["scenarios"][2]["expected"]["capability_id"]
        for trace in trace_document["traces"][:2]:
            trace["events"][1]["data"]["capability_id"] = wrong_id
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F01"]["numerator"], 26)
        self.assertEqual(report["gates"]["F01"]["denominator"], 28)
        self.assertEqual(report["gates"]["F01"]["percent"], "92.86")
        self.assertEqual(report["gates"]["F01"]["minimum_percent"], "95.00")
        self.assertFalse(report["gates"]["F01"]["passed"])
        self.assertFalse(report["acceptance_passed"])

    def test_selection_gate_accepts_one_miss_at_95_percent_or_higher(self) -> None:
        trace_document = self._perfect_trace_document()
        trace_document["traces"][0]["events"][1]["data"]["capability_id"] = (
            self.corpus["scenarios"][2]["expected"]["capability_id"]
        )
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F01"]["numerator"], 27)
        self.assertEqual(report["gates"]["F01"]["percent"], "96.43")
        self.assertTrue(report["gates"]["F01"]["passed"])

    def test_clarification_and_parameter_loss_are_scored_independently(self) -> None:
        trace_document = self._perfect_trace_document()
        trace_document["traces"][0]["events"][2]["data"] = {
            "outcome": "refused",
            "fields": [],
            "turns": [],
        }
        trace_document["traces"][1]["events"][3]["data"]["parameters"][
            "company_id"
        ] = 999999
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F01"]["numerator"], 28)
        self.assertEqual(report["gates"]["F02"]["numerator"], 27)
        self.assertEqual(report["gates"]["F03"]["numerator"], 27)
        self.assertEqual(len(report["gates"]["F02"]["failures"]), 1)
        self.assertEqual(len(report["gates"]["F03"]["failures"]), 1)

    def test_parameter_loss_after_finalization_fails_f03(self) -> None:
        trace_document = self._perfect_trace_document()
        invoice_trace = next(
            trace
            for trace in trace_document["traces"]
            if trace["scenario_id"] == "pi-v1-customer-invoice"
        )
        invoice_trace["events"][4]["data"]["parameters"]["company_id"] = 999999
        invoice_trace["events"][7]["data"]["parameters_sha256"] = (
            TEST_WRONG_PARAMETERS_DIGEST
        )
        invoice_trace["events"][10]["data"]["parameters_sha256"] = (
            TEST_WRONG_RECEIPT_DIGEST
        )
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F03"]["numerator"], 27)
        failure = report["gates"]["F03"]["failures"][
            "pi-v1-customer-invoice"
        ]
        self.assertEqual(
            set(failure["stages"]),
            {"approval_binding", "audit_receipt", "cli_input"},
        )

    def test_write_prepare_parameter_loss_fails_f03(self) -> None:
        trace_document = self._perfect_trace_document()
        invoice_trace = next(
            trace
            for trace in trace_document["traces"]
            if trace["scenario_id"] == "pi-v1-customer-invoice"
        )
        invoice_trace["events"][5]["data"]["parameters"]["currency_id"] = (
            self._bindings()["currency_eur_id"]
        )
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F03"]["numerator"], 27)
        failure = report["gates"]["F03"]["failures"][
            "pi-v1-customer-invoice"
        ]
        self.assertEqual(failure["stages"], ["prepare"])
        self.assertEqual(
            failure["details"]["prepare"]["paths"], ["$.currency_id"]
        )

    def test_unverified_terminal_business_result_fails_f05(self) -> None:
        trace_document = self._perfect_trace_document()
        invoice_trace = next(
            trace
            for trace in trace_document["traces"]
            if trace["scenario_id"] == "pi-v1-customer-invoice"
        )
        invoice_trace["events"][9]["data"]["business_succeeded"] = False
        invoice_trace["events"][9]["data"]["bridge_guidance"] = {
            "must_not_report_business_success": True,
            "next_action": "operation.status",
            "operation_id": "op-1",
            "reason": "terminal_write_result_is_not_business_verified",
        }
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F05"]["numerator"], 27)
        self.assertFalse(report["gates"]["F05"]["passed"])
        self.assertFalse(report["acceptance_passed"])
        failure = report["gates"]["F05"]["failures"][
            "pi-v1-customer-invoice"
        ]
        self.assertEqual(failure["reason"], "verified_answer_missing")
        self.assertEqual(
            failure["issues"]["business_succeeded"]["reason"],
            "terminal_result_not_business_verified",
        )

    def test_clarification_answer_must_be_captured_and_bound_to_final_value(self) -> None:
        trace_document = self._perfect_trace_document()
        trace_document["traces"][0]["events"][2]["data"]["turns"][0][
            "answer"
        ] = self._bindings()["company_secondary_id"]
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F02"]["numerator"], 27)
        self.assertEqual(report["gates"]["F03"]["numerator"], 28)
        self.assertIn(
            "company_id",
            report["gates"]["F02"]["failures"]["pi-v1-registry-list"][
                "issues"
            ],
        )

    def test_missing_scenario_is_counted_in_every_denominator_and_fails_coverage(self) -> None:
        trace_document = self._perfect_trace_document()
        missing_id = trace_document["traces"].pop()["scenario_id"]
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertFalse(report["trace_coverage"]["passed"])
        self.assertEqual(report["trace_coverage"]["missing_scenario_ids"], [missing_id])
        for gate_id in ("F01", "F02", "F03", "F05"):
            self.assertEqual(report["gates"][gate_id]["numerator"], 27)
            self.assertEqual(report["gates"][gate_id]["denominator"], 28)
            self.assertIn(missing_id, report["gates"][gate_id]["failures"])

    def test_trace_is_bound_to_corpus_input_and_rejects_unknown_event_fields(self) -> None:
        wrong_release = self._perfect_trace_document()
        with self.assertRaisesRegex(TraceValidationError, "release SHA-256 mismatch"):
            validate_trace_document(
                wrong_release,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_WRONG_RELEASE_SHA256,
            )

        wrong_digest = self._perfect_trace_document()
        wrong_digest["corpus_sha256"] = TEST_WRONG_CORPUS_DIGEST
        self._resign(wrong_digest)
        with self.assertRaisesRegex(TraceValidationError, "corpus_sha256 mismatch"):
            validate_trace_document(
                wrong_digest,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        wrong_registry = self._perfect_trace_document()
        wrong_registry["registry_sha256"] = TEST_WRONG_REGISTRY_DIGEST
        self._resign(wrong_registry)
        with self.assertRaisesRegex(TraceValidationError, "registry_sha256 mismatch"):
            validate_trace_document(
                wrong_registry,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        wrong_input = self._perfect_trace_document()
        wrong_input["traces"][0]["events"][0]["data"]["text"] += "（改写）"
        self._resign(wrong_input)
        with self.assertRaisesRegex(TraceValidationError, "does not match frozen input"):
            validate_trace_document(
                wrong_input,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        extra = self._perfect_trace_document()
        extra["traces"][0]["events"][0]["debug"] = True
        self._resign(extra)
        with self.assertRaisesRegex(TraceValidationError, "fields invalid"):
            validate_trace_document(
                extra,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        placeholder_approval = self._perfect_trace_document()
        placeholder_approval["traces"][4]["events"][7]["data"][
            "approval_digest"
        ] = "d" * 64
        self._resign(placeholder_approval)
        with self.assertRaisesRegex(TraceValidationError, "placeholder SHA-256"):
            validate_trace_document(
                placeholder_approval,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_unsigned_untrusted_and_tampered_trace_exports_are_rejected(self) -> None:
        unsigned = self._perfect_trace_document()
        unsigned.pop("attestation")
        with self.assertRaisesRegex(TraceValidationError, "attestation"):
            validate_trace_document(
                unsigned,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        untrusted = self._perfect_trace_document()
        untrusted["attestation"]["key_id"] = "unknown-capture-key"
        with self.assertRaisesRegex(TraceValidationError, "untrusted attestation key"):
            validate_trace_document(
                untrusted,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        tampered = self._perfect_trace_document()
        tampered["traces"][0]["events"][1]["data"]["capability_id"] = None
        with self.assertRaisesRegex(TraceValidationError, "signed payload digest mismatch"):
            validate_trace_document(
                tampered,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_host_attestation_key_document_is_strict(self) -> None:
        document = {
            "schema_version": "odoo-accounting-cli-v3.pi-attestation-keys.v1",
            "keys": {
                TEST_ATTESTATION_KEY_ID: {
                    "secret_hex": TEST_ATTESTATION_KEY.hex()
                }
            },
        }
        self.assertEqual(
            load_attestation_keys(document),
            TEST_ATTESTATION_KEYS,
        )
        document["keys"][TEST_ATTESTATION_KEY_ID]["unexpected"] = True
        with self.assertRaisesRegex(TraceValidationError, "fields invalid"):
            load_attestation_keys(document)

    def test_binding_types_and_trace_scenario_ids_are_strict(self) -> None:
        invalid_binding = self._perfect_trace_document()
        invalid_binding["bindings"]["company_primary_id"] = "not-an-id"
        self._resign(invalid_binding)
        with self.assertRaisesRegex(TraceValidationError, "binding type"):
            validate_trace_document(
                invalid_binding,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        duplicate = self._perfect_trace_document()
        duplicate["traces"][1]["scenario_id"] = duplicate["traces"][0]["scenario_id"]
        self._resign(duplicate)
        with self.assertRaisesRegex(TraceValidationError, "duplicate trace scenario id"):
            validate_trace_document(
                duplicate,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import hmac
import io
import json
import secrets
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from odoo_accounting_cli_v3.pi_evidence import PiEvidenceTrust
from odoo_accounting_cli_v3.registry import registry_digest, validate_registry
from pi_scenario_v3_fixture import (
    CAPTURED_AT,
    TRACE_COMPLETED_AT,
    TRACE_STARTED_AT,
    PiScenarioEvidenceFactory,
    build_evidence_trust,
    operation_digest_input_from_exchange,
)
from tools.pi_scenario_gate import (
    CorpusValidationError,
    TraceValidationError,
    approval_binding_sha256,
    canonical_json_text,
    canonical_sha256,
    load_attestation_keys,
    main as pi_scenario_gate_main,
    material_path_value,
    resolve_fixture_bindings,
    score_documents as _score_documents,
    trace_attestation_payload,
    validate_corpus,
    validate_trace_document as _validate_trace_document,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = PROJECT_ROOT / "tests" / "fixtures" / "pi_scenarios.v1.json"
REGISTRY_PATH = PROJECT_ROOT / "registry" / "capabilities.json"
TEST_ATTESTATION_KEY_ID = "test-pi-capture-key"
TEST_ATTESTATION_KEY = secrets.token_bytes(32)
TEST_ATTESTATION_KEYS = {TEST_ATTESTATION_KEY_ID: TEST_ATTESTATION_KEY}
TEST_PACKAGE_SHA256 = hashlib.sha256(b"test v3 package").hexdigest()
TEST_MANIFEST_SHA256 = hashlib.sha256(b"test v3 manifest").hexdigest()
TEST_RELEASE_SHA256 = TEST_PACKAGE_SHA256
TEST_WRONG_RELEASE_SHA256 = hashlib.sha256(b"wrong test v3 package").hexdigest()
TEST_WRONG_MANIFEST_SHA256 = hashlib.sha256(b"wrong test v3 manifest").hexdigest()
TEST_WRONG_PARAMETERS_DIGEST = hashlib.sha256(b"wrong parameters").hexdigest()
TEST_WRONG_RECEIPT_DIGEST = hashlib.sha256(b"wrong receipt parameters").hexdigest()
TEST_WRONG_CORPUS_DIGEST = hashlib.sha256(b"wrong corpus").hexdigest()
TEST_WRONG_REGISTRY_DIGEST = hashlib.sha256(b"wrong registry").hexdigest()
TEST_REGISTRY_DIGEST = registry_digest(
    validate_registry(json.loads(REGISTRY_PATH.read_text(encoding="utf-8")))
)


def build_test_evidence_trust(
    registry_document: object,
) -> PiEvidenceTrust:
    """Return release-pinned test trust without writing authority secrets."""

    capabilities = validate_registry(registry_document)
    return build_evidence_trust(
        capabilities,
        package_sha256=TEST_PACKAGE_SHA256,
        manifest_sha256=TEST_MANIFEST_SHA256,
        registry_digest=registry_digest(capabilities),
    )


def validate_trace_document(
    trace_document: object,
    corpus_document: object,
    registry_document: object,
    attestation_keys: dict[str, bytes],
    *,
    expected_release_sha256: str,
    expected_capture_binding: dict[str, object] | None = None,
    evidence_trust: PiEvidenceTrust | None = None,
) -> dict[str, object]:
    """Keep individual tests concise while exercising the strict production API."""

    return _validate_trace_document(
        trace_document,
        corpus_document,
        registry_document,
        attestation_keys,
        expected_package_sha256=expected_release_sha256,
        expected_manifest_sha256=TEST_MANIFEST_SHA256,
        expected_registry_digest=registry_digest(
            validate_registry(registry_document)
        ),
        evidence_trust=(
            evidence_trust
            if evidence_trust is not None
            else build_test_evidence_trust(registry_document)
        ),
        expected_capture_binding=expected_capture_binding,
    )


def score_documents(
    corpus_document: object,
    trace_document: object,
    registry_document: object,
    attestation_keys: dict[str, bytes],
    *,
    expected_release_sha256: str,
    expected_capture_binding: dict[str, object] | None = None,
    evidence_trust: PiEvidenceTrust | None = None,
) -> dict[str, object]:
    """Keep individual tests concise while exercising the strict production API."""

    return _score_documents(
        corpus_document,
        trace_document,
        registry_document,
        attestation_keys,
        expected_package_sha256=expected_release_sha256,
        expected_manifest_sha256=TEST_MANIFEST_SHA256,
        expected_registry_digest=registry_digest(
            validate_registry(registry_document)
        ),
        evidence_trust=(
            evidence_trust
            if evidence_trust is not None
            else build_test_evidence_trust(registry_document)
        ),
        expected_capture_binding=expected_capture_binding,
    )


class PiScenarioGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        self.corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        capabilities = validate_registry(self.registry)
        self.evidence_factory = PiScenarioEvidenceFactory(
            capabilities,
            package_sha256=TEST_PACKAGE_SHA256,
            manifest_sha256=TEST_MANIFEST_SHA256,
            registry_digest=registry_digest(capabilities),
        )
        self.evidence_trust = self.evidence_factory.trust

    def _bindings(self) -> dict[str, object]:
        return {
            name: definition["example"]
            for name, definition in self.corpus["fixture_bindings"].items()
        }

    @staticmethod
    def _expected_capture_binding() -> dict[str, object]:
        return {
            "pi_agent_version": "test-pi-build",
            "pi_bridge_version": "test-bridge-build",
            "provider": "test-provider",
            "model": "test-model-immutable-20260717",
            "system_prompt_sha256": hashlib.sha256(
                b"fixed test system prompt"
            ).hexdigest(),
            "tool_set_sha256": hashlib.sha256(
                b"fixed test Pi tool set"
            ).hexdigest(),
            "pi_runtime_sha256": hashlib.sha256(
                b"fixed test Pi runtime"
            ).hexdigest(),
        }

    @staticmethod
    def _event(trace: dict[str, object], event_type: str) -> dict[str, object]:
        return next(
            event["data"]
            for event in trace["events"]
            if event["type"] == event_type
        )

    def _trace(
        self, document: dict[str, object], scenario_id: str
    ) -> dict[str, object]:
        return next(
            trace
            for trace in document["traces"]
            if trace["scenario_id"] == scenario_id
        )

    def _assert_write_parameter_binding(
        self, trace: dict[str, object], parameters: dict[str, object]
    ) -> None:
        expected_digest = canonical_sha256(parameters)
        prepare = self._event(trace, "prepare")
        preview = self._event(trace, "preview")
        approval = self._event(trace, "approval_binding")
        execution = self._event(trace, "odoo_execution")
        self.assertEqual(prepare["parameters"], parameters)
        self.assertEqual(preview["parameters"], parameters)
        self.assertEqual(preview["parameters_sha256"], expected_digest)
        self.assertEqual(
            set(preview["preview"]),
            {
                "approval",
                "business_description",
                "capability_id",
                "operation_digest",
                "operation_id",
                "operation_state",
                "parameters",
                "precheck",
                "precheck_digest",
                "precheck_identity",
                "recovery",
                "risk_level",
            },
        )
        self.assertEqual(
            preview["preview"]["operation_state"], "awaiting_approval"
        )
        self.assertEqual(
            preview["preview"]["operation_digest"],
            canonical_sha256(prepare["operation_digest_input"]),
        )
        self.assertEqual(
            preview["preview"]["precheck_digest"],
            canonical_sha256(preview["preview"]["precheck"]),
        )
        self.assertEqual(approval["parameters_sha256"], expected_digest)
        self.assertEqual(approval["preview_sha256"], preview["preview_sha256"])
        self.assertEqual(
            {
                prepare["operation_id"],
                preview["operation_id"],
                approval["operation_id"],
                execution["operation_id"],
            },
            {prepare["operation_id"]},
        )
        self.assertNotEqual(
            approval["requester_user_id"], approval["approver_user_id"]
        )
        self.assertEqual(
            approval["approval_digest"], approval_binding_sha256(approval)
        )

    def _rehash_write_preview(self, trace: dict[str, object]) -> None:
        preview_event = self._event(trace, "preview")
        preview = preview_event["preview"]
        preview["precheck_digest"] = canonical_sha256(preview["precheck"])
        preview["precheck_identity"]["precheck_digest"] = preview[
            "precheck_digest"
        ]
        preview_event["parameters_sha256"] = canonical_sha256(
            preview_event["parameters"]
        )
        preview_event["preview_sha256"] = canonical_sha256(preview)
        approval = self._event(trace, "approval_binding")
        approval["parameters_sha256"] = preview_event["parameters_sha256"]
        approval["preview_sha256"] = preview_event["preview_sha256"]
        approval["approval_digest"] = approval_binding_sha256(approval)

    def _replace_assistant_result(
        self,
        trace: dict[str, object],
        **changes: object,
    ) -> None:
        assistant = self._event(trace, "assistant_final")
        result = json.loads(assistant["text"])
        result.update(changes)
        assistant["text"] = canonical_json_text(result)

    def _set_write_operation_id(
        self,
        trace: dict[str, object],
        operation_id: str,
    ) -> None:
        self._event(trace, "prepare")["operation_id"] = operation_id
        preview_event = self._event(trace, "preview")
        preview_event["operation_id"] = operation_id
        preview_event["preview"]["operation_id"] = operation_id
        preview_event["preview"]["precheck_identity"][
            "operation_id"
        ] = operation_id
        self._event(trace, "approval_binding")[
            "operation_id"
        ] = operation_id
        for event_type in (
            "odoo_execution",
            "odoo_result",
            "audit_receipt",
        ):
            self._event(trace, event_type)["operation_id"] = operation_id
        self._replace_assistant_result(trace, operation_id=operation_id)
        self._rehash_write_preview(trace)

    def _perfect_trace_document(
        self, *, registry_empty: bool = False
    ) -> dict[str, object]:
        bindings = self._bindings()
        capability_by_id = {
            item["id"]: item for item in self.registry["capabilities"]
        }
        actual_registry_digest = registry_digest(validate_registry(self.registry))
        traces = []
        for index, scenario in enumerate(self.corpus["scenarios"], start=1):
            expected = scenario["expected"]
            capability = capability_by_id[expected["capability_id"]]
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
            is_write = capability["access"] == "write"
            is_refused = expected["clarification"]["outcome"] == "refused"
            trusted_evidence = None
            events = [
                {
                    "type": "user_input",
                    "data": {"text": scenario["input"]},
                },
                {
                    "type": "capability_selected",
                    "data": {"capability_id": expected["capability_id"]},
                },
                {
                    "type": "clarification_completed",
                    "data": clarification,
                },
            ]
            if is_refused:
                events.extend(
                    [
                        {
                            "type": "execution_refused",
                            "data": {
                                "business_succeeded": False,
                                "write_tool_call_count": 0,
                                "odoo_effect": False,
                                "operation_id": None,
                                "receipt_id": None,
                                "reason": "The unsafe accounting request was refused.",
                            },
                        },
                        {
                            "type": "assistant_final",
                            "data": {
                                "text": canonical_json_text(
                                    {
                                        "status": "refused",
                                        "business_succeeded": False,
                                        "operation_id": None,
                                        "receipt_id": None,
                                        "result_digest": None,
                                    }
                                ),
                            },
                        },
                    ]
                )
            else:
                bundle = self.evidence_factory.build(
                    index=index,
                    scenario_id=scenario["id"],
                    capability_id=expected["capability_id"],
                    parameters=parameters,
                    registry_empty=(
                        registry_empty
                        and expected["capability_id"]
                        == "acct.registry.list.v1"
                    ),
                )
                trusted_evidence = bundle.evidence
                operation_reference = bundle.operation_id
                receipt_id = bundle.receipt_id
                tool_call_id = bundle.tool_call_id
                result_body = bundle.result_body
                result_digest = bundle.result_digest
                verification_evidence = copy.deepcopy(
                    bundle.verification_evidence
                )
                verification_digest = canonical_sha256(
                    verification_evidence
                )
                execution_event = {
                    "type": "odoo_execution",
                    "data": {
                        "parameters_sha256": parameters_sha256,
                        "operation_id": operation_reference,
                        "tool_call_id": tool_call_id,
                        "capability_id": expected["capability_id"],
                        "release_digest": TEST_MANIFEST_SHA256,
                        "registry_digest": actual_registry_digest,
                        "executed_at": bundle.executed_at,
                    },
                }
                result_event = {
                    "type": "odoo_result",
                    "data": {
                        "parameters_sha256": parameters_sha256,
                        "operation_id": operation_reference,
                        "tool_call_id": tool_call_id,
                        "capability_id": expected["capability_id"],
                        "release_digest": TEST_MANIFEST_SHA256,
                        "registry_digest": actual_registry_digest,
                        "result_body": result_body,
                        "result_digest": result_digest,
                        "business_succeeded": True,
                        "verification": {
                            "passed": True,
                            "evidence": verification_evidence,
                            "evidence_digest": verification_digest,
                            "verified_at": bundle.verified_at,
                        },
                        "database_finalized": is_write,
                        "odoo_effect": is_write,
                    },
                }
                receipt_event = {
                    "type": "audit_receipt",
                    "data": {
                        "parameters_sha256": parameters_sha256,
                        "receipt_id": receipt_id,
                        "operation_id": operation_reference,
                        "tool_call_id": tool_call_id,
                        "capability_id": expected["capability_id"],
                        "release_digest": TEST_MANIFEST_SHA256,
                        "registry_digest": actual_registry_digest,
                        "result_digest": result_digest,
                        "verification_evidence_digest": verification_digest,
                        "issued_at": bundle.receipt_issued_at,
                    },
                }
                assistant_event = {
                    "type": "assistant_final",
                    "data": {
                        "text": canonical_json_text(
                            {
                                "status": "verified_success",
                                "business_succeeded": True,
                                "operation_id": operation_reference,
                                "receipt_id": receipt_id,
                                "result_digest": result_digest,
                            }
                        ),
                        "tool_call_id": tool_call_id,
                    },
                }
                events.extend(
                    [
                        {
                            "type": "material_parameters_finalized",
                            "data": {"parameters": parameters},
                        },
                        {
                            "type": "cli_input",
                            "data": {"parameters": copy.deepcopy(parameters)},
                        },
                    ]
                )
                if is_write:
                    operation_id = bundle.operation_id
                    operation_digest_input = (
                        operation_digest_input_from_exchange(
                            trusted_evidence
                        )
                    )
                    preview_body = copy.deepcopy(
                        trusted_evidence["preview_exchange"][
                            "broker_response"
                        ]["data"]
                    )
                    preview_body.pop("approval_challenge")
                    preview_sha256 = canonical_sha256(preview_body)
                    raw_approval = trusted_evidence[
                        "approve_execute_exchange"
                    ]["broker_request"]["approval"]
                    approval = {
                        "operation_id": operation_id,
                        "parameters_sha256": parameters_sha256,
                        "preview_sha256": preview_sha256,
                        "requester_user_id": raw_approval["user_id"],
                        "approver_user_id": raw_approval[
                            "approver_user_id"
                        ],
                        "approved_at": raw_approval["issued_at"],
                        "expires_at": raw_approval["expires_at"],
                    }
                    approval["approval_digest"] = approval_binding_sha256(
                        approval
                    )
                    events.extend(
                        [
                            {
                                "type": "prepare",
                                "data": {
                                    "operation_id": operation_id,
                                    "parameters": copy.deepcopy(parameters),
                                    "operation_digest_input": (
                                        operation_digest_input
                                    ),
                                },
                            },
                            {
                                "type": "preview",
                                "data": {
                                    "operation_id": operation_id,
                                    "parameters": copy.deepcopy(parameters),
                                    "parameters_sha256": parameters_sha256,
                                    "preview": preview_body,
                                    "preview_sha256": preview_sha256,
                                },
                            },
                            {
                                "type": "approval_binding",
                                "data": approval,
                            },
                        ]
                    )
                events.extend(
                    [
                        execution_event,
                        result_event,
                        receipt_event,
                        assistant_event,
                    ]
                )
            for sequence, event in enumerate(events, start=1):
                event["sequence"] = sequence
            traces.append(
                {
                    "scenario_id": scenario["id"],
                    "trace_id": f"trace-{index:03d}",
                    "started_at": TRACE_STARTED_AT.isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "completed_at": TRACE_COMPLETED_AT.isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "events": events,
                    "trusted_evidence": trusted_evidence,
                }
            )
        document = {
            "schema_version": "odoo-accounting-cli-v3.pi-traces.v3",
            "corpus_id": self.corpus["corpus_id"],
            "corpus_sha256": canonical_sha256(self.corpus),
            "registry_digest": actual_registry_digest,
            "capture": {
                "source": "pi_agent",
                "run_id": "pi-run-20260717-001",
                "captured_at": CAPTURED_AT.isoformat().replace(
                    "+00:00", "Z"
                ),
                **self._expected_capture_binding(),
                "v3_manifest_sha256": TEST_MANIFEST_SHA256,
                "v3_package_sha256": TEST_PACKAGE_SHA256,
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

    def _run_cli(
        self,
        trace_document: dict[str, object],
        expected_capture_binding: dict[str, object],
    ) -> tuple[int, str, str]:
        documents = {
            "pi_scenarios.v1.json": self.corpus,
            "capabilities.json": self.registry,
            "pi-traces.json": trace_document,
            "attestation-keys.json": {
                "schema_version": (
                    "odoo-accounting-cli-v3.pi-attestation-keys.v1"
                ),
                "keys": {
                    TEST_ATTESTATION_KEY_ID: {
                        "secret_hex": TEST_ATTESTATION_KEY.hex()
                    }
                },
            },
            "capture-binding.json": expected_capture_binding,
        }

        def load(path: Path) -> object:
            return copy.deepcopy(documents[path.name])

        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch(
                "tools.pi_scenario_gate.load_json_document",
                side_effect=load,
            ),
            patch(
                "tools.pi_scenario_gate.load_pi_evidence_trust",
                return_value=self.evidence_trust,
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = pi_scenario_gate_main(
                [
                    "--traces",
                    "pi-traces.json",
                    "--attestation-keys",
                    "attestation-keys.json",
                    "--expected-package-sha256",
                    TEST_PACKAGE_SHA256,
                    "--expected-manifest-sha256",
                    TEST_MANIFEST_SHA256,
                    "--expected-registry-digest",
                    registry_digest(validate_registry(self.registry)),
                    "--expected-capture-binding",
                    "capture-binding.json",
                    "--trusted-authority-config",
                    "trusted-authority.json",
                ]
            )
        return result, stdout.getvalue(), stderr.getvalue()

    def test_repository_corpus_is_strict_and_covers_every_registered_capability(self) -> None:
        validate_corpus(self.corpus, self.registry)
        registered = {item["id"] for item in self.registry["capabilities"]}
        covered = {
            scenario["expected"]["capability_id"]
            for scenario in self.corpus["scenarios"]
        }
        self.assertEqual(covered, registered)
        self.assertEqual(self.corpus["frozen_revision"], 11)
        self.assertEqual(len(self.corpus["scenarios"]), 43)
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
                    "expected_document_binding_v2",
                    "expected_business_binding",
                    "reason",
                    "idempotency_key",
                },
            )

        phase_b_scenarios = {
            scenario["id"]: scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"]
            in {
                "acct.journal.entry_create.v1",
                "acct.move.post.v1",
                "acct.move.draft_cancel.v2",
            }
        }
        self.assertEqual(
            {
                scenario_id: scenario["expected"]["capability_id"]
                for scenario_id, scenario in phase_b_scenarios.items()
            },
            {
                "pi-v1-journal-entry-create": "acct.journal.entry_create.v1",
                "pi-v1-manual-entry-post": "acct.move.post.v1",
                "pi-v1-manual-entry-draft-cancel": "acct.move.draft_cancel.v2",
            },
        )
        self.assertEqual(
            set(
                phase_b_scenarios["pi-v1-journal-entry-create"]["expected"][
                    "material_parameters"
                ]
            ),
            {
                "company_id",
                "journal_id",
                "posting_date",
                "currency_id",
                "reference",
                "reason",
                "posting_mode",
                "lines",
                "idempotency_key",
            },
        )
        self.assertEqual(
            set(
                phase_b_scenarios["pi-v1-manual-entry-post"]["expected"][
                    "material_parameters"
                ]
            ),
            {
                "company_id",
                "move_id",
                "expected_move_type",
                "expected_document_binding",
                "expected_business_binding",
                "expected_journal_id",
                "expected_currency_id",
                "expected_posting_date",
                "expected_reference",
                "expected_total_debit",
                "expected_total_credit",
                "expected_line_count",
                "reason",
                "idempotency_key",
            },
        )
        self.assertEqual(
            set(
                phase_b_scenarios["pi-v1-manual-entry-draft-cancel"]["expected"][
                    "material_parameters"
                ]
            ),
            {
                "company_id",
                "move_id",
                "expected_move_type",
                "expected_document_binding",
                "expected_document_binding_v2",
                "expected_business_binding",
                "expected_line_ids",
                "reason",
                "idempotency_key",
            },
        )
        self.assertEqual(
            phase_b_scenarios["pi-v1-manual-entry-post"]["expected"][
                "material_parameters"
            ]["expected_move_type"],
            "entry",
        )
        move_post_scenarios = [
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"] == "acct.move.post.v1"
        ]
        self.assertEqual(
            [scenario["id"] for scenario in move_post_scenarios],
            ["pi-v1-manual-entry-post"],
        )
        self.assertTrue(
            all("手工分录" in scenario["input"] for scenario in move_post_scenarios)
        )

        document_lifecycle_scenarios = {
            scenario["id"]: scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"]
            in {
                "acct.move.document_post_eligibility.v1",
                "acct.refund.draft_cancel_eligibility.v1",
                "acct.invoice.customer_post.v1",
                "acct.bill.vendor_post.v1",
                "acct.refund.draft_cancel.v1",
            }
        }
        self.assertEqual(
            {
                scenario_id: scenario["expected"]["capability_id"]
                for scenario_id, scenario in document_lifecycle_scenarios.items()
            },
            {
                "pi-v1-document-post-eligibility-read": (
                    "acct.move.document_post_eligibility.v1"
                ),
                "pi-v1-refund-draft-cancel-eligibility-read": (
                    "acct.refund.draft_cancel_eligibility.v1"
                ),
                "pi-v1-customer-invoice-post": "acct.invoice.customer_post.v1",
                "pi-v1-vendor-bill-post": "acct.bill.vendor_post.v1",
                "pi-v1-refund-draft-cancel": "acct.refund.draft_cancel.v1",
            },
        )
        for scenario_id in (
            "pi-v1-document-post-eligibility-read",
            "pi-v1-refund-draft-cancel-eligibility-read",
        ):
            self.assertEqual(
                set(
                    document_lifecycle_scenarios[scenario_id]["expected"][
                        "material_parameters"
                    ]
                ),
                {"company_id", "move_id", "expected_move_type"},
            )
        post_fields = {
            "company_id",
            "move_id",
            "expected_move_type",
            "expected_document_binding",
            "expected_document_binding_v2",
            "expected_business_binding",
            "expected_partner_id",
            "expected_journal_id",
            "expected_currency_id",
            "expected_payment_term_line_id",
            "expected_payment_term_account_id",
            "expected_invoice_date",
            "expected_accounting_date",
            "expected_due_date",
            "expected_reference",
            "expected_amount_untaxed",
            "expected_amount_tax",
            "expected_amount_total",
            "expected_amount_residual",
            "expected_line_ids",
            "reason",
            "idempotency_key",
        }
        for scenario_id in (
            "pi-v1-customer-invoice-post",
            "pi-v1-vendor-bill-post",
        ):
            self.assertEqual(
                set(
                    document_lifecycle_scenarios[scenario_id]["expected"][
                        "material_parameters"
                    ]
                ),
                post_fields,
            )
        self.assertEqual(
            set(
                document_lifecycle_scenarios[
                    "pi-v1-refund-draft-cancel"
                ]["expected"]["material_parameters"]
            ),
            {
                "company_id",
                "move_id",
                "expected_move_type",
                "expected_origin_move_id",
                "expected_document_binding",
                "expected_document_binding_v2",
                "expected_business_binding",
                "expected_origin_document_binding",
                "expected_origin_document_binding_v2",
                "expected_origin_business_binding",
                "expected_partner_id",
                "expected_journal_id",
                "expected_currency_id",
                "expected_refund_date",
                "expected_total_amount",
                "expected_line_ids",
                "expected_origin_line_ids",
                "reason",
                "idempotency_key",
            },
        )
        resolved_document_lifecycle = {
            scenario_id: resolve_fixture_bindings(
                scenario["expected"]["material_parameters"], self._bindings()
            )
            for scenario_id, scenario in document_lifecycle_scenarios.items()
        }
        customer_post = resolved_document_lifecycle[
            "pi-v1-customer-invoice-post"
        ]
        vendor_post = resolved_document_lifecycle["pi-v1-vendor-bill-post"]
        refund_cancel = resolved_document_lifecycle[
            "pi-v1-refund-draft-cancel"
        ]
        self.assertEqual(
            {
                customer_post["move_id"],
                vendor_post["move_id"],
                refund_cancel["move_id"],
                refund_cancel["expected_origin_move_id"],
            },
            {1701, 1711, 1721, 1731},
        )
        binding_values = {
            customer_post["expected_document_binding"],
            customer_post["expected_document_binding_v2"],
            customer_post["expected_business_binding"],
            vendor_post["expected_document_binding"],
            vendor_post["expected_document_binding_v2"],
            vendor_post["expected_business_binding"],
            refund_cancel["expected_document_binding"],
            refund_cancel["expected_document_binding_v2"],
            refund_cancel["expected_business_binding"],
            refund_cancel["expected_origin_document_binding"],
            refund_cancel["expected_origin_document_binding_v2"],
            refund_cancel["expected_origin_business_binding"],
        }
        self.assertEqual(len(binding_values), 12)
        self.assertTrue(all(len(value) == 64 for value in binding_values))
        v2_binding_values = {
            customer_post["expected_document_binding_v2"],
            vendor_post["expected_document_binding_v2"],
            refund_cancel["expected_document_binding_v2"],
            refund_cancel["expected_origin_document_binding_v2"],
        }
        self.assertEqual(len(v2_binding_values), 4)
        self.assertTrue(
            all(
                len(value) == 64
                and value == value.lower()
                and set(value) <= set("0123456789abcdef")
                for value in v2_binding_values
            )
        )
        line_id_groups = (
            customer_post["expected_line_ids"],
            vendor_post["expected_line_ids"],
            refund_cancel["expected_line_ids"],
            refund_cancel["expected_origin_line_ids"],
        )
        self.assertTrue(
            all(group == sorted(set(group)) for group in line_id_groups)
        )
        self.assertEqual(
            len(set().union(*(set(group) for group in line_id_groups))),
            sum(len(group) for group in line_id_groups),
        )
        self.assertEqual(customer_post["expected_invoice_date"], "2026-06-20")
        self.assertEqual(vendor_post["expected_invoice_date"], "2026-06-21")
        self.assertEqual(refund_cancel["expected_refund_date"], "2026-06-24")
        self.assertEqual(
            {
                customer_post["expected_currency_id"],
                vendor_post["expected_currency_id"],
                refund_cancel["expected_currency_id"],
            },
            {self._bindings()["currency_cny_id"]},
        )
        self.assertEqual(
            customer_post["expected_payment_term_line_id"],
            customer_post["expected_line_ids"][-1],
        )
        self.assertEqual(
            vendor_post["expected_payment_term_line_id"],
            vendor_post["expected_line_ids"][-1],
        )
        self.assertEqual(customer_post["expected_amount_tax"], "0.00")
        self.assertEqual(vendor_post["expected_amount_tax"], "0.00")

        payment_cancel_scenarios = [
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"] == "acct.payment.cancel.v1"
        ]
        self.assertEqual(
            [scenario["id"] for scenario in payment_cancel_scenarios],
            ["pi-v1-payment-cancel"],
        )
        payment_cancel_scenario = payment_cancel_scenarios[0]
        self.assertEqual(
            set(payment_cancel_scenario["expected"]["material_parameters"]),
            {
                "company_id",
                "payment_id",
                "move_id",
                "expected_payment_state",
                "expected_move_state",
                "expected_payment_date",
                "expected_partner_id",
                "expected_partner_type",
                "expected_direction",
                "expected_amount",
                "expected_currency_id",
                "expected_journal_id",
                "expected_payment_method_line_id",
                "expected_is_sent",
                "expected_line_ids",
                "reason",
                "idempotency_key",
            },
        )
        self.assertEqual(
            payment_cancel_scenario["expected"]["material_parameters"][
                "expected_payment_state"
            ],
            "in_process",
        )
        self.assertEqual(
            payment_cancel_scenario["expected"]["material_parameters"][
                "expected_move_state"
            ],
            "posted",
        )
        self.assertIs(
            payment_cancel_scenario["expected"]["material_parameters"][
                "expected_is_sent"
            ],
            True,
        )
        payment_cancel_parameters = resolve_fixture_bindings(
            payment_cancel_scenario["expected"]["material_parameters"],
            self._bindings(),
        )
        payment_cancel_line_ids = payment_cancel_parameters["expected_line_ids"]
        self.assertEqual(len(payment_cancel_line_ids), 2)
        self.assertEqual(
            payment_cancel_line_ids,
            sorted(set(payment_cancel_line_ids)),
        )
        self.assertEqual(
            payment_cancel_scenario["expected"]["material_parameters"][
                "expected_currency_id"
            ],
            {"$fixture": "currency_cny_id"},
        )
        for required_phrase in (
            "尚未核销",
            "状态仍为 in_process",
            "不是退款、解除核销或银行流水补偿",
            "公司本位币人民币",
        ):
            self.assertIn(required_phrase, payment_cancel_scenario["input"])

        reconciliation_undo_scenarios = [
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"]
            == "acct.reconciliation.undo.v1"
        ]
        self.assertEqual(
            [scenario["id"] for scenario in reconciliation_undo_scenarios],
            ["pi-v1-reconciliation-undo"],
        )
        reconciliation_undo = reconciliation_undo_scenarios[0]
        self.assertEqual(
            set(reconciliation_undo["expected"]["material_parameters"]),
            {
                "company_id",
                "origin_operation_id",
                "expected_origin_revision",
                "expected_origin_final_receipt_body_digest",
                "expected_recovery_plan_digest",
                "recovery_date",
                "reason",
                "idempotency_key",
            },
        )
        resolved_undo = resolve_fixture_bindings(
            reconciliation_undo["expected"]["material_parameters"],
            self._bindings(),
        )
        self.assertEqual(resolved_undo["expected_origin_revision"], 6)
        self.assertEqual(
            len(resolved_undo["expected_origin_final_receipt_body_digest"]),
            64,
        )
        self.assertEqual(
            len(resolved_undo["expected_recovery_plan_digest"]),
            64,
        )
        for required_phrase in (
            "已经完成、验证且数据库最终确认",
            "不是取消未核销付款、退款或失败操作恢复",
            "已包含回执绑定核销撤销门面的保留 V3 版本",
            "完整保留八项参数",
            "先预览并等待审批",
        ):
            self.assertIn(required_phrase, reconciliation_undo["input"])

        bank_compensation_scenarios = [
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["expected"]["capability_id"]
            == "acct.bank.statement_compensate.v1"
        ]
        self.assertEqual(
            [scenario["id"] for scenario in bank_compensation_scenarios],
            [
                "pi-v1-bank-statement-compensate",
                "pi-v1-bank-statement-compensate-delete-refused",
                "pi-v1-bank-statement-compensate-partial-refused",
                "pi-v1-bank-statement-compensate-matched-refused",
            ],
        )
        expected_fields = {
            "company_id",
            "origin_operation_id",
            "expected_origin_revision",
            "expected_origin_final_receipt_body_digest",
            "expected_recovery_plan_digest",
            "expected_statement_id",
            "expected_journal_id",
            "expected_currency_id",
            "expected_source_digest",
            "compensation_date",
            "reason",
            "idempotency_key",
        }
        for scenario in bank_compensation_scenarios:
            self.assertEqual(
                set(scenario["expected"]["material_parameters"]),
                expected_fields,
            )
            resolved = resolve_fixture_bindings(
                scenario["expected"]["material_parameters"],
                self._bindings(),
            )
            self.assertEqual(resolved["expected_origin_revision"], 6)
            self.assertEqual(resolved["expected_statement_id"], 1601)
            self.assertEqual(resolved["expected_journal_id"], 403)
            self.assertEqual(resolved["expected_currency_id"], 1)
            for digest_field in (
                "expected_origin_final_receipt_body_digest",
                "expected_recovery_plan_digest",
                "expected_source_digest",
            ):
                self.assertEqual(len(resolved[digest_field]), 64)
        self.assertEqual(
            bank_compensation_scenarios[0]["expected"]["clarification"],
            {"outcome": "not_required", "fields": []},
        )
        for scenario in bank_compensation_scenarios[1:]:
            self.assertEqual(
                scenario["expected"]["clarification"],
                {"outcome": "refused", "fields": []},
            )
        for required_phrase in (
            "整批补偿",
            "完成、验证且数据库最终确认",
            "保留 V3 版本",
            "精确可用补偿计划",
            "保留原对账单、原流水行和原分录",
            "完整独立补偿对账单",
            "完整传递十二项参数",
            "先预览并等待审批",
        ):
            self.assertIn(required_phrase, bank_compensation_scenarios[0]["input"])
        self.assertIn("直接删除", bank_compensation_scenarios[1]["input"])
        self.assertIn("拒绝删除请求", bank_compensation_scenarios[1]["input"])
        self.assertIn("只反向补偿", bank_compensation_scenarios[2]["input"])
        self.assertIn("拒绝部分补偿", bank_compensation_scenarios[2]["input"])
        self.assertIn("完成匹配和核销", bank_compensation_scenarios[3]["input"])
        self.assertIn(
            "拒绝已匹配或已核销来源图",
            bank_compensation_scenarios[3]["input"],
        )

        invoice_draft_route = next(
            scenario
            for scenario in self.corpus["scenarios"]
            if scenario["id"] == "pi-v1-customer-invoice-draft-route"
        )
        self.assertIn("新建一张发票草稿", invoice_draft_route["input"])
        self.assertIn("不要过账", invoice_draft_route["input"])
        self.assertEqual(
            invoice_draft_route["expected"]["capability_id"],
            "acct.invoice.customer_create.v1",
        )
        self.assertNotEqual(
            invoice_draft_route["expected"]["capability_id"],
            "acct.move.post.v1",
        )
        self.assertEqual(
            invoice_draft_route["expected"]["material_parameters"]["posting_mode"],
            "draft",
        )
        self.assertNotIn("acct.invoice.post.v1", registered)

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
        for scenario in phase_b_scenarios.values():
            trace = traces[scenario["id"]]
            resolved = resolve_fixture_bindings(
                scenario["expected"]["material_parameters"], self._bindings()
            )
            self.assertEqual(trace["events"][4]["data"], {"parameters": resolved})
            self._assert_write_parameter_binding(trace, resolved)
        for scenario in draft_cancel_scenarios:
            trace = traces[scenario["id"]]
            resolved = resolve_fixture_bindings(
                scenario["expected"]["material_parameters"], self._bindings()
            )
            self._assert_write_parameter_binding(trace, resolved)
        for scenario_id in (
            "pi-v1-customer-invoice-post",
            "pi-v1-vendor-bill-post",
            "pi-v1-refund-draft-cancel",
        ):
            self._assert_write_parameter_binding(
                traces[scenario_id],
                resolved_document_lifecycle[scenario_id],
            )
        payment_cancel_trace = traces[payment_cancel_scenario["id"]]
        resolved_payment_cancel = resolve_fixture_bindings(
            payment_cancel_scenario["expected"]["material_parameters"],
            self._bindings(),
        )
        self.assertEqual(
            payment_cancel_trace["events"][4]["data"],
            {"parameters": resolved_payment_cancel},
        )
        self._assert_write_parameter_binding(
            payment_cancel_trace, resolved_payment_cancel
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
        for fixture_name in (
            "recovery_plan_digest",
            "reconciliation_origin_final_receipt_body_digest",
            "reconciliation_undo_recovery_plan_digest",
        ):
            with self.subTest(fixture_name=fixture_name):
                placeholder_fixture = copy.deepcopy(self.corpus)
                placeholder_fixture["fixture_bindings"][fixture_name][
                    "example"
                ] = "a" * 64
                with self.assertRaisesRegex(
                    CorpusValidationError, "placeholder SHA-256"
                ):
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
            expected_capture_binding=self._expected_capture_binding(),
        )
        self.assertTrue(report["acceptance_passed"])
        self.assertTrue(report["capture_binding_verified"])
        self.assertEqual(
            report["registry_digest"],
            registry_digest(validate_registry(self.registry)),
        )
        self.assertEqual(
            report["expected_capture_binding_sha256"],
            canonical_sha256(self._expected_capture_binding()),
        )
        self.assertEqual(
            report["trace_coverage"],
            {
                "captured": 43,
                "expected": 43,
                "passed": True,
                "missing_scenario_ids": [],
            },
        )
        self.assertEqual(
            report["schema_version"],
            "odoo-accounting-cli-v3.pi-gate-report.v3",
        )
        self.assertTrue(report["runtime_evidence_verified"])
        self.assertEqual(
            report["runtime_evidence"],
            {
                "verified": True,
                "verified_trace_count": 36,
                "expected_trace_count": 36,
                "read_exchange_count": 15,
                "write_exchange_count": 21,
                "write_authority_signature_verified_count": 21,
                "acl_independently_rechecked": False,
            },
        )
        for gate_id in ("F01", "F02", "F05"):
            self.assertEqual(report["gates"][gate_id]["numerator"], 43)
            self.assertEqual(report["gates"][gate_id]["denominator"], 43)
            self.assertEqual(report["gates"][gate_id]["percent"], "100.00")
            self.assertTrue(report["gates"][gate_id]["passed"])
        self.assertEqual(report["gates"]["F03"]["numerator"], 36)
        self.assertEqual(report["gates"]["F03"]["denominator"], 36)
        self.assertEqual(report["gates"]["F03"]["percent"], "100.00")
        self.assertTrue(report["gates"]["F03"]["passed"])
        self.assertEqual(report["gates"]["F04"]["numerator"], 21)
        self.assertEqual(report["gates"]["F04"]["denominator"], 21)
        self.assertEqual(report["gates"]["F04"]["percent"], "100.00")
        self.assertTrue(report["gates"]["F04"]["passed"])

    def test_dedicated_routes_are_captured_without_generic_masquerade(
        self,
    ) -> None:
        trace_document = self._perfect_trace_document()

        registry = self._trace(
            trace_document, "pi-v1-registry-list"
        )["trusted_evidence"]["read_exchange"]
        self.assertEqual(registry["action"], "read")
        self.assertEqual(
            registry["tool_name"], "odoo_v3_capability_list"
        )
        self.assertEqual(registry["pi_arguments"], {})
        self.assertEqual(registry["broker_request"]["parameters"], {})
        self.assertIsNone(registry["operation_before"])
        self.assertIsNone(registry["operation_after"])

        diagnostics = self._trace(
            trace_document, "pi-v1-operation-diagnostics"
        )["trusted_evidence"]["read_exchange"]
        self.assertEqual(
            diagnostics["action"], "operation.diagnostics"
        )
        self.assertEqual(
            diagnostics["tool_name"],
            "odoo_v3_operation_diagnostics",
        )
        self.assertEqual(
            diagnostics["pi_arguments"],
            {
                "company_id": self._bindings()["company_primary_id"],
                "operation_id": self._bindings()[
                    "failed_operation_id"
                ],
            },
        )
        self.assertIsNotNone(diagnostics["operation_before"])
        self.assertIsNone(diagnostics["operation_after"])

        recovery = self._trace(
            trace_document, "pi-v1-recovery-execute"
        )["trusted_evidence"]
        recover = recovery["prepare_exchange"]
        self.assertEqual(recover["action"], "operation.recover")
        self.assertEqual(
            recover["tool_name"], "odoo_v3_operation_recover"
        )
        self.assertEqual(
            set(recover["pi_arguments"]),
            {
                "origin_operation_id",
                "recovery_date",
                "reason",
                "idempotency_key",
            },
        )
        self.assertIn(
            recover["operation_before"]["state"],
            {"completed", "failed"},
        )
        self.assertEqual(
            recover["operation_after"]["capability_id"],
            "acct.recovery.execute.v1",
        )
        self.assertEqual(
            recover["operation_after"]["state"], "prepared"
        )
        self.assertEqual(
            recovery["preview_exchange"]["action"],
            "operation.preview",
        )
        self.assertEqual(
            recovery["approve_execute_exchange"]["action"],
            "operation.approve_execute",
        )

    def test_trace_requires_independent_package_manifest_and_registry_identities(
        self,
    ) -> None:
        trace_document = self._perfect_trace_document()
        expected_registry = registry_digest(validate_registry(self.registry))

        _validate_trace_document(
            trace_document,
            self.corpus,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_package_sha256=TEST_PACKAGE_SHA256,
            expected_manifest_sha256=TEST_MANIFEST_SHA256,
            expected_registry_digest=expected_registry,
            evidence_trust=self.evidence_trust,
        )

        cases = (
            (
                "package",
                {
                    "expected_package_sha256": TEST_WRONG_RELEASE_SHA256,
                    "expected_manifest_sha256": TEST_MANIFEST_SHA256,
                    "expected_registry_digest": expected_registry,
                },
                "package SHA-256 mismatch",
            ),
            (
                "manifest",
                {
                    "expected_package_sha256": TEST_PACKAGE_SHA256,
                    "expected_manifest_sha256": TEST_WRONG_MANIFEST_SHA256,
                    "expected_registry_digest": expected_registry,
                },
                "manifest SHA-256 mismatch",
            ),
            (
                "registry",
                {
                    "expected_package_sha256": TEST_PACKAGE_SHA256,
                    "expected_manifest_sha256": TEST_MANIFEST_SHA256,
                    "expected_registry_digest": TEST_WRONG_REGISTRY_DIGEST,
                },
                "registry_digest mismatch",
            ),
        )
        for label, identities, expected_error in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                TraceValidationError,
                expected_error,
            ):
                _validate_trace_document(
                    trace_document,
                    self.corpus,
                    self.registry,
                    TEST_ATTESTATION_KEYS,
                    evidence_trust=self.evidence_trust,
                    **identities,
                )

    def test_read_and_write_effect_semantics_are_rejected_fail_closed(
        self,
    ) -> None:
        cases = {
            "read_odoo_effect": (
                "pi-v1-trial-balance",
                "odoo_effect",
                True,
            ),
            "read_database_finalized": (
                "pi-v1-trial-balance",
                "database_finalized",
                True,
            ),
            "write_odoo_effect": (
                "pi-v1-customer-invoice",
                "odoo_effect",
                False,
            ),
            "write_database_finalized": (
                "pi-v1-customer-invoice",
                "database_finalized",
                False,
            ),
        }
        for name, (scenario_id, field, value) in cases.items():
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                trace = self._trace(trace_document, scenario_id)
                self._event(trace, "odoo_result")[field] = value
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError,
                    "odoo_result is not the exact trusted response",
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_execution_verification_and_receipt_timeline_fail_closed(
        self,
    ) -> None:
        cases = {
            "approval_before_trace": (
                "approval_binding",
                ("approved_at",),
                "2026-07-16T23:59:59.900000Z",
            ),
            "execution_after_trace": (
                "odoo_execution",
                ("executed_at",),
                "2026-07-17T00:01:00.100000Z",
            ),
            "verification_before_execution": (
                "odoo_result",
                ("verification", "verified_at"),
                "2026-07-17T00:00:00.200000Z",
            ),
            "verification_after_trace": (
                "odoo_result",
                ("verification", "verified_at"),
                "2026-07-17T00:01:00.100000Z",
            ),
            "receipt_before_verification": (
                "audit_receipt",
                ("issued_at",),
                "2026-07-17T00:00:00.312000Z",
            ),
            "receipt_after_trace": (
                "audit_receipt",
                ("issued_at",),
                "2026-07-17T00:01:00.100000Z",
            ),
        }
        for name, (event_type, path, value) in cases.items():
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                trace = self._trace(
                    trace_document, "pi-v1-customer-invoice"
                )
                target = self._event(trace, event_type)
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = value
                if event_type == "approval_binding":
                    target["approval_digest"] = approval_binding_sha256(
                        target
                    )
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError,
                    r"(not raw-bound|not broker-bound)",
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_legacy_v1_and_v2_trace_schemas_are_rejected_fail_closed(
        self,
    ) -> None:
        for version in ("v1", "v2"):
            with self.subTest(version=version):
                trace_document = self._perfect_trace_document()
                trace_document["schema_version"] = (
                    f"odoo-accounting-cli-v3.pi-traces.{version}"
                )
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError,
                    r"schema_version must be "
                    r"odoo-accounting-cli-v3\.pi-traces\.v3",
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_missing_legacy_and_forged_trusted_evidence_are_rejected(
        self,
    ) -> None:
        cases = {
            "missing": lambda trace: trace.update(
                {"trusted_evidence": None}
            ),
            "legacy_summary": lambda trace: trace.update(
                {
                    "trusted_evidence": {
                        "result_digest": TEST_WRONG_RECEIPT_DIGEST
                    }
                }
            ),
            "forged_pi_result": lambda trace: trace["trusted_evidence"][
                "read_exchange"
            ]["pi_result"].update({"details": {"ok": True}}),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                trace = self._trace(
                    trace_document, "pi-v1-trial-balance"
                )
                mutate(trace)
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError,
                    "trusted_evidence rejected",
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_forged_normalized_preview_is_rejected_even_when_rehashed(
        self,
    ) -> None:
        trace_document = self._perfect_trace_document()
        trace = self._trace(
            trace_document, "pi-v1-customer-invoice"
        )
        self._event(trace, "preview")["preview"][
            "business_description"
        ] = "Forged normalized preview"
        self._rehash_write_preview(trace)
        self._resign(trace_document)

        with self.assertRaisesRegex(
            TraceValidationError,
            "preview is not the exact raw preview projection",
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_forged_normalized_verification_is_rejected_when_rehashed(
        self,
    ) -> None:
        trace_document = self._perfect_trace_document()
        trace = self._trace(trace_document, "pi-v1-trial-balance")
        verification = self._event(trace, "odoo_result")["verification"]
        verification["evidence"]["output_schema_verified"] = False
        forged_digest = canonical_sha256(verification["evidence"])
        verification["evidence_digest"] = forged_digest
        self._event(trace, "audit_receipt")[
            "verification_evidence_digest"
        ] = forged_digest
        self._resign(trace_document)

        with self.assertRaisesRegex(
            TraceValidationError,
            "read verification is not receipt-bound",
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_whole_trace_wrapped_into_future_time_is_rejected(
        self,
    ) -> None:
        trace_document = self._perfect_trace_document()
        trace = self._trace(trace_document, "pi-v1-trial-balance")
        trace["started_at"] = "2026-07-18T00:00:00.000000Z"
        trace["completed_at"] = "2026-07-18T00:01:00.000000Z"
        exchange = trace["trusted_evidence"]["read_exchange"]
        exchange["occurred_at"] = "2026-07-18T00:00:00.300000Z"
        exchange["broker_dispatched_at"] = (
            "2026-07-18T00:00:00.310000Z"
        )
        exchange["broker_responded_at"] = (
            "2026-07-18T00:00:00.320000Z"
        )
        exchange["tool_completed_at"] = (
            "2026-07-18T00:00:00.330000Z"
        )
        self._event(trace, "odoo_execution")[
            "executed_at"
        ] = "2026-07-18T00:00:00.310000Z"
        self._event(trace, "odoo_result")["verification"][
            "verified_at"
        ] = "2026-07-18T00:00:00.315000Z"
        self._event(trace, "audit_receipt")[
            "issued_at"
        ] = "2026-07-18T00:00:00.315000Z"
        self._resign(trace_document)

        with self.assertRaisesRegex(
            TraceValidationError,
            "trusted_evidence rejected: exchange chronology is invalid",
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_trace_completed_after_capture_is_rejected(self) -> None:
        trace_document = self._perfect_trace_document()
        trace = self._trace(trace_document, "pi-v1-trial-balance")
        trace["completed_at"] = "2026-07-17T00:01:00.000001Z"
        self._resign(trace_document)

        with self.assertRaisesRegex(
            TraceValidationError,
            r"completed_at exceeds capture\.captured_at",
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_signed_empty_registry_response_is_rejected(self) -> None:
        trace_document = self._perfect_trace_document(
            registry_empty=True
        )
        with self.assertRaisesRegex(
            TraceValidationError,
            "trusted_evidence rejected: registry result is empty or "
            "internally inconsistent",
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_capture_binds_runtime_prompt_tools_provider_and_model(self) -> None:
        cases = {
            "missing_provider": (
                lambda capture: capture.pop("provider"),
                "traces.capture fields invalid",
            ),
            "placeholder_system_prompt": (
                lambda capture: capture.update({"system_prompt_sha256": "a" * 64}),
                "system_prompt_sha256 must not be a placeholder SHA-256",
            ),
        }
        for name, (mutate, expected_error) in cases.items():
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                mutate(trace_document["capture"])
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError, expected_error
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_capture_must_match_independently_supplied_binding(self) -> None:
        trace_document = self._perfect_trace_document()
        expected_binding = self._expected_capture_binding()
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
            expected_capture_binding=expected_binding,
        )
        self.assertTrue(report["acceptance_passed"])
        self.assertTrue(report["capture_binding_verified"])
        self.assertEqual(
            report["expected_capture_binding_sha256"],
            canonical_sha256(expected_binding),
        )

        trace_document["capture"]["provider"] = "attacker-provider"
        self._resign(trace_document)
        with self.assertRaisesRegex(
            TraceValidationError,
            "does not match expected_capture_binding",
        ):
            score_documents(
                self.corpus,
                trace_document,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
                expected_capture_binding=expected_binding,
            )

    def test_cli_requires_expected_capture_binding_path(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            pi_scenario_gate_main(
                [
                    "--traces",
                    "pi-traces.json",
                    "--attestation-keys",
                    "attestation-keys.json",
                    "--expected-package-sha256",
                    TEST_PACKAGE_SHA256,
                    "--expected-manifest-sha256",
                    TEST_MANIFEST_SHA256,
                    "--expected-registry-digest",
                    registry_digest(validate_registry(self.registry)),
                ]
            )
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--expected-capture-binding", stderr.getvalue())

    def test_unverified_capture_binding_cannot_pass_acceptance(self) -> None:
        report = score_documents(
            self.corpus,
            self._perfect_trace_document(),
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertFalse(report["capture_binding_verified"])
        self.assertIsNone(report["expected_capture_binding_sha256"])
        self.assertFalse(report["acceptance_passed"])

    def test_cli_report_proves_capture_binding_was_verified(self) -> None:
        binding = self._expected_capture_binding()
        result, stdout, stderr = self._run_cli(
            self._perfect_trace_document(), binding
        )
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        report = json.loads(stdout)
        self.assertTrue(report["capture_binding_verified"])
        self.assertEqual(
            report["expected_capture_binding_sha256"],
            canonical_sha256(binding),
        )
        self.assertTrue(report["acceptance_passed"])

    def test_cli_rejects_every_capture_binding_field_drift(self) -> None:
        binding = self._expected_capture_binding()
        for field in binding:
            with self.subTest(field=field):
                trace_document = self._perfect_trace_document()
                if field.endswith("_sha256"):
                    trace_document["capture"][field] = hashlib.sha256(
                        f"drifted {field}".encode("utf-8")
                    ).hexdigest()
                else:
                    trace_document["capture"][field] += "-drifted"
                self._resign(trace_document)
                result, stdout, stderr = self._run_cli(
                    trace_document, binding
                )
                self.assertEqual(result, 2)
                self.assertEqual(stdout, "")
                self.assertIn(
                    "does not match expected_capture_binding", stderr
                )

        unexpected = self._expected_capture_binding()
        unexpected["extra"] = "not-allowed"
        result, stdout, stderr = self._run_cli(
            self._perfect_trace_document(), unexpected
        )
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("expected_capture_binding fields invalid", stderr)

    def test_safe_refusal_has_no_execution_path_and_passes(self) -> None:
        trace_document = self._perfect_trace_document()
        refused_trace = self._trace(trace_document, "pi-v1-refund")
        self.assertEqual(
            [event["type"] for event in refused_trace["events"]],
            [
                "user_input",
                "capability_selected",
                "clarification_completed",
                "execution_refused",
                "assistant_final",
            ],
        )
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
            expected_capture_binding=self._expected_capture_binding(),
        )
        self.assertNotIn("pi-v1-refund", report["gates"]["F03"]["failures"])
        self.assertNotIn("pi-v1-refund", report["gates"]["F04"]["failures"])
        self.assertNotIn("pi-v1-refund", report["gates"]["F05"]["failures"])
        self.assertTrue(report["acceptance_passed"])

    def test_refused_scenario_cannot_reuse_fake_success_execution_events(self) -> None:
        trace_document = self._perfect_trace_document()
        refused_trace = self._trace(trace_document, "pi-v1-refund")
        write_trace = self._trace(trace_document, "pi-v1-customer-invoice")
        fake_events = copy.deepcopy(write_trace["events"])
        fake_events[0]["data"] = {"text": refused_trace["events"][0]["data"]["text"]}
        fake_events[1]["data"] = copy.deepcopy(refused_trace["events"][1]["data"])
        fake_events[2]["data"] = copy.deepcopy(refused_trace["events"][2]["data"])
        refused_trace["events"] = fake_events
        self._resign(trace_document)
        with self.assertRaisesRegex(
            TraceValidationError, "exactly the normalized refused Pi events"
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_write_trace_without_approval_is_rejected(self) -> None:
        trace_document = self._perfect_trace_document()
        invoice_trace = self._trace(trace_document, "pi-v1-customer-invoice")
        invoice_trace["events"] = [
            event
            for event in invoice_trace["events"]
            if event["type"] != "approval_binding"
        ]
        for sequence, event in enumerate(invoice_trace["events"], start=1):
            event["sequence"] = sequence
        self._resign(trace_document)
        with self.assertRaisesRegex(
            TraceValidationError, "exactly the normalized write Pi events"
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_opaque_preview_is_rejected_even_when_outer_digests_match(
        self,
    ) -> None:
        trace_document = self._perfect_trace_document()
        trace = self._trace(trace_document, "pi-v1-customer-invoice")
        preview_event = self._event(trace, "preview")
        preview_event["preview"] = {"opaque": "approved"}
        preview_event["preview_sha256"] = canonical_sha256(
            preview_event["preview"]
        )
        approval = self._event(trace, "approval_binding")
        approval["preview_sha256"] = preview_event["preview_sha256"]
        approval["approval_digest"] = approval_binding_sha256(approval)
        self._resign(trace_document)
        with self.assertRaisesRegex(
            TraceValidationError, "preview fields invalid"
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_full_preview_binding_rejects_rehashed_tampering(self) -> None:
        for name in (
            "business_description",
            "company",
            "parameters",
            "registry",
            "release",
            "operation_digest",
        ):
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                trace = self._trace(
                    trace_document, "pi-v1-customer-invoice"
                )
                prepare = self._event(trace, "prepare")
                preview_event = self._event(trace, "preview")
                preview = preview_event["preview"]
                identity = prepare["operation_digest_input"]
                if name == "business_description":
                    preview["business_description"] = "Opaque approval"
                elif name == "company":
                    identity["company_id"] = 999
                    preview["precheck"]["company_id"] = 999
                    preview["operation_digest"] = canonical_sha256(identity)
                elif name == "parameters":
                    changed = copy.deepcopy(preview_event["parameters"])
                    changed["company_id"] = 999
                    preview_event["parameters"] = changed
                    preview["parameters"] = copy.deepcopy(changed)
                    identity["parameters"] = copy.deepcopy(changed)
                    identity["company_id"] = 999
                    preview["precheck"]["company_id"] = 999
                    preview["precheck"]["parameters_digest"] = (
                        canonical_sha256(changed)
                    )
                    preview["operation_digest"] = canonical_sha256(identity)
                elif name == "registry":
                    identity["registry_digest"] = TEST_WRONG_REGISTRY_DIGEST
                    preview["precheck"]["registry_digest"] = (
                        TEST_WRONG_REGISTRY_DIGEST
                    )
                    preview["precheck_identity"]["registry_digest"] = (
                        TEST_WRONG_REGISTRY_DIGEST
                    )
                    preview["operation_digest"] = canonical_sha256(identity)
                elif name == "release":
                    identity["release_digest"] = TEST_WRONG_MANIFEST_SHA256
                    preview["precheck"]["release_digest"] = (
                        TEST_WRONG_MANIFEST_SHA256
                    )
                    preview["precheck_identity"]["release_digest"] = (
                        TEST_WRONG_MANIFEST_SHA256
                    )
                    preview["operation_digest"] = canonical_sha256(identity)
                else:
                    preview["operation_digest"] = TEST_WRONG_RECEIPT_DIGEST
                self._rehash_write_preview(trace)
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError,
                    "preview is not the exact raw preview projection",
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_same_user_expired_and_tampered_approvals_are_rejected(
        self,
    ) -> None:
        cases = {
            "same_user": lambda approval: approval.update(
                {"approver_user_id": approval["requester_user_id"]}
            ),
            "expired": lambda approval: approval.update(
                {"expires_at": "2026-07-17T00:00:00.250000Z"}
            ),
            "tampered_digest": lambda approval: approval.update(
                {"approval_digest": TEST_WRONG_RECEIPT_DIGEST}
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                invoice_trace = self._trace(
                    trace_document, "pi-v1-customer-invoice"
                )
                approval = self._event(invoice_trace, "approval_binding")
                mutate(approval)
                if name != "tampered_digest":
                    approval["approval_digest"] = approval_binding_sha256(
                        approval
                    )
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError,
                    "approval_binding is not raw-bound",
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_refused_assistant_cannot_report_business_success(self) -> None:
        trace_document = self._perfect_trace_document()
        refused_trace = self._trace(trace_document, "pi-v1-refund")
        assistant = self._event(refused_trace, "assistant_final")
        result = json.loads(assistant["text"])
        result["status"] = "verified_success"
        result["business_succeeded"] = True
        assistant["text"] = canonical_json_text(result)
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F05"]["numerator"], 42)
        self.assertFalse(report["gates"]["F05"]["passed"])
        failure = report["gates"]["F05"]["failures"]["pi-v1-refund"]
        self.assertIn("assistant_final.status", failure["issues"])
        self.assertIn("assistant_final.business_succeeded", failure["issues"])

    def test_assistant_final_rejects_prose_and_noncanonical_json(self) -> None:
        for name in ("prose", "noncanonical_json"):
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                trace = self._trace(
                    trace_document, "pi-v1-customer-invoice"
                )
                assistant = self._event(trace, "assistant_final")
                if name == "prose":
                    assistant["text"] = "发票已经成功，但没有结构化回执。"
                else:
                    assistant["text"] = json.dumps(
                        json.loads(assistant["text"]),
                        ensure_ascii=False,
                    )
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError,
                    "must be strict canonical JSON",
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_read_has_no_operation_and_tool_call_is_bound(self) -> None:
        operation_trace = self._perfect_trace_document()
        read_trace = self._trace(operation_trace, "pi-v1-trial-balance")
        self._event(read_trace, "odoo_execution")[
            "operation_id"
        ] = "illegal-read-operation"
        self._resign(operation_trace)
        with self.assertRaisesRegex(
            TraceValidationError,
            "operation_id must be null for a read capability",
        ):
            validate_trace_document(
                operation_trace,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

        assistant_trace = self._perfect_trace_document()
        read_trace = self._trace(assistant_trace, "pi-v1-trial-balance")
        self._replace_assistant_result(
            read_trace, operation_id="illegal-read-operation"
        )
        self._event(read_trace, "odoo_result")[
            "tool_call_id"
        ] = "different-tool-call"
        self._resign(assistant_trace)
        with self.assertRaisesRegex(
            TraceValidationError,
            "odoo_result.tool_call_id is not raw-bound",
        ):
            validate_trace_document(
                assistant_trace,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_refusal_cannot_claim_a_tool_call(self) -> None:
        trace_document = self._perfect_trace_document()
        trace = self._trace(trace_document, "pi-v1-refund")
        self._event(trace, "execution_refused")[
            "tool_call_id"
        ] = "illegal-refused-tool-call"
        self._resign(trace_document)
        with self.assertRaisesRegex(
            TraceValidationError, "fields invalid"
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_refused_tool_calls_effects_and_receipts_fail_f05(self) -> None:
        cases = {
            "write_tool_call_count": 1,
            "odoo_effect": True,
            "operation_id": "op-refused-illegal",
            "receipt_id": "receipt-refused-illegal",
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                trace_document = self._perfect_trace_document()
                refused_trace = self._trace(trace_document, "pi-v1-refund")
                refusal = self._event(refused_trace, "execution_refused")
                refusal[field] = value
                self._resign(trace_document)
                report = score_documents(
                    self.corpus,
                    trace_document,
                    self.registry,
                    TEST_ATTESTATION_KEYS,
                    expected_release_sha256=TEST_RELEASE_SHA256,
                )
                self.assertEqual(report["gates"]["F05"]["numerator"], 42)
                self.assertFalse(report["gates"]["F05"]["passed"])
                failure = report["gates"]["F05"]["failures"]["pi-v1-refund"]
                self.assertIn(f"execution_refused.{field}", failure["issues"])

    def test_positive_result_receipt_and_final_bindings_fail_closed(self) -> None:
        cases = {
            "verification": (
                "odoo_result",
                ("verification", "passed"),
                False,
                "verification",
            ),
            "database_finalized": (
                "odoo_result",
                ("database_finalized",),
                False,
                "database_finalized",
            ),
            "release_digest": (
                "audit_receipt",
                ("release_digest",),
                TEST_WRONG_MANIFEST_SHA256,
                "release_digest",
            ),
            "registry_digest": (
                "odoo_result",
                ("registry_digest",),
                TEST_WRONG_REGISTRY_DIGEST,
                "registry_digest",
            ),
            "capability_id": (
                "audit_receipt",
                ("capability_id",),
                "accounting.read.tampered.v1",
                "capability_id",
            ),
            "operation_id": (
                "odoo_result",
                ("operation_id",),
                "op-tampered",
                "operation_id",
            ),
            "result_digest": (
                "audit_receipt",
                ("result_digest",),
                TEST_WRONG_RECEIPT_DIGEST,
                "result_digest",
            ),
            "verification_evidence_digest": (
                "audit_receipt",
                ("verification_evidence_digest",),
                TEST_WRONG_RECEIPT_DIGEST,
                "verification_evidence_digest",
            ),
            "receipt_id": (
                "assistant_final",
                ("receipt_id",),
                "receipt-tampered",
                "receipt_id",
            ),
            "assistant_success": (
                "assistant_final",
                ("business_succeeded",),
                False,
                "assistant_final",
            ),
            "assistant_status": (
                "assistant_final",
                ("status",),
                "refused",
                "assistant_final",
            ),
        }
        for name, (event_type, path, value, expected_issue) in cases.items():
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                invoice_trace = self._trace(
                    trace_document, "pi-v1-customer-invoice"
                )
                event_data = self._event(invoice_trace, event_type)
                target = (
                    json.loads(event_data["text"])
                    if event_type == "assistant_final"
                    else event_data
                )
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = value
                if event_type == "assistant_final":
                    event_data["text"] = canonical_json_text(
                        json.loads(event_data["text"])
                        | {path[-1]: value}
                    )
                self._resign(trace_document)
                if event_type == "assistant_final":
                    report = score_documents(
                        self.corpus,
                        trace_document,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )
                    self.assertEqual(
                        report["gates"]["F05"]["numerator"], 42
                    )
                    self.assertFalse(report["gates"]["F05"]["passed"])
                    failure = report["gates"]["F05"]["failures"][
                        "pi-v1-customer-invoice"
                    ]
                    self.assertIn(expected_issue, failure["issues"])
                else:
                    with self.assertRaisesRegex(
                        TraceValidationError,
                        r"(not raw-bound|not the exact trusted response)",
                    ):
                        validate_trace_document(
                            trace_document,
                            self.corpus,
                            self.registry,
                            TEST_ATTESTATION_KEYS,
                            expected_release_sha256=TEST_RELEASE_SHA256,
                        )

    def test_cross_trace_operation_receipt_and_tool_ids_are_unique(
        self,
    ) -> None:
        for identifier in ("operation_id", "receipt_id", "tool_call_id"):
            with self.subTest(identifier=identifier):
                trace_document = self._perfect_trace_document()
                if identifier == "operation_id":
                    first = self._trace(
                        trace_document, "pi-v1-customer-invoice"
                    )
                    second = self._trace(
                        trace_document,
                        "pi-v1-customer-invoice-draft-route",
                    )
                    duplicate = self._event(first, "prepare")[
                        "operation_id"
                    ]
                    self._set_write_operation_id(second, duplicate)
                elif identifier == "receipt_id":
                    first = self._trace(
                        trace_document, "pi-v1-trial-balance"
                    )
                    second = self._trace(
                        trace_document, "pi-v1-customer-invoice"
                    )
                    duplicate = self._event(first, "audit_receipt")[
                        "receipt_id"
                    ]
                    self._event(second, "audit_receipt")[
                        "receipt_id"
                    ] = duplicate
                    self._replace_assistant_result(
                        second, receipt_id=duplicate
                    )
                else:
                    first = self._trace(
                        trace_document, "pi-v1-trial-balance"
                    )
                    second = self._trace(
                        trace_document, "pi-v1-customer-invoice"
                    )
                    duplicate = self._event(first, "odoo_execution")[
                        "tool_call_id"
                    ]
                    for event_type in (
                        "odoo_execution",
                        "odoo_result",
                        "audit_receipt",
                        "assistant_final",
                    ):
                        self._event(second, event_type)[
                            "tool_call_id"
                        ] = duplicate
                self._resign(trace_document)
                expected_error = {
                    "operation_id": (
                        "trusted_evidence does not match normalized events"
                    ),
                    "receipt_id": (
                        "trusted_evidence receipt does not match"
                    ),
                    "tool_call_id": (
                        "trusted_evidence tool call does not match"
                    ),
                }[identifier]
                with self.assertRaisesRegex(
                    TraceValidationError,
                    expected_error,
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_result_body_and_verification_evidence_are_recomputable(
        self,
    ) -> None:
        cases = {
            "result_body": (
                ("result_body", "operation_state"),
                "failed",
                "result_digest mismatch",
            ),
            "verification_evidence": (
                ("verification", "evidence", "passed"),
                False,
                "verification.evidence_digest mismatch",
            ),
        }
        for name, (path, value, expected_error) in cases.items():
            with self.subTest(name=name):
                trace_document = self._perfect_trace_document()
                trace = self._trace(
                    trace_document, "pi-v1-customer-invoice"
                )
                target = self._event(trace, "odoo_result")
                for field in path[:-1]:
                    target = target[field]
                target[path[-1]] = value
                self._resign(trace_document)
                with self.assertRaisesRegex(
                    TraceValidationError, expected_error
                ):
                    validate_trace_document(
                        trace_document,
                        self.corpus,
                        self.registry,
                        TEST_ATTESTATION_KEYS,
                        expected_release_sha256=TEST_RELEASE_SHA256,
                    )

    def test_selection_gate_fails_below_95_percent(self) -> None:
        trace_document = self._perfect_trace_document()
        wrong_id = "acct.refund.draft_cancel.v1"
        for trace in trace_document["traces"][:3]:
            trace["events"][1]["data"]["capability_id"] = wrong_id
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F01"]["numerator"], 40)
        self.assertEqual(report["gates"]["F01"]["denominator"], 43)
        self.assertEqual(report["gates"]["F01"]["percent"], "93.02")
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
        self.assertEqual(report["gates"]["F01"]["numerator"], 42)
        self.assertEqual(report["gates"]["F01"]["percent"], "97.67")
        self.assertTrue(report["gates"]["F01"]["passed"])

    def test_clarification_and_parameter_loss_are_scored_independently(self) -> None:
        clarification_document = self._perfect_trace_document()
        clarification_document["traces"][0]["events"][2]["data"] = {
            "outcome": "refused",
            "fields": [],
            "turns": [],
        }
        self._resign(clarification_document)
        report = score_documents(
            self.corpus,
            clarification_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F01"]["numerator"], 43)
        self.assertEqual(report["gates"]["F02"]["numerator"], 42)
        self.assertEqual(len(report["gates"]["F02"]["failures"]), 1)

        parameter_document = self._perfect_trace_document()
        parameter_document["traces"][1]["events"][3]["data"]["parameters"][
            "company_id"
        ] = 999999
        self._resign(parameter_document)
        with self.assertRaisesRegex(
            TraceValidationError,
            "parameters_sha256 is not raw-bound",
        ):
            validate_trace_document(
                parameter_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
            )

    def test_parameter_loss_after_finalization_fails_f03(self) -> None:
        trace_document = self._perfect_trace_document()
        invoice_trace = next(
            trace
            for trace in trace_document["traces"]
            if trace["scenario_id"] == "pi-v1-customer-invoice"
        )
        invoice_trace["events"][4]["data"]["parameters"]["company_id"] = 999999
        self._resign(trace_document)
        report = score_documents(
            self.corpus,
            trace_document,
            self.registry,
            TEST_ATTESTATION_KEYS,
            expected_release_sha256=TEST_RELEASE_SHA256,
        )
        self.assertEqual(report["gates"]["F03"]["numerator"], 35)
        failure = report["gates"]["F03"]["failures"][
            "pi-v1-customer-invoice"
        ]
        self.assertEqual(failure["stages"], ["cli_input"])

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
        self.assertEqual(report["gates"]["F03"]["numerator"], 35)
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
        self._event(invoice_trace, "odoo_result")["business_succeeded"] = False
        self._resign(trace_document)
        with self.assertRaisesRegex(
            TraceValidationError,
            "odoo_result is not the exact trusted response",
        ):
            validate_trace_document(
                trace_document,
                self.corpus,
                self.registry,
                TEST_ATTESTATION_KEYS,
                expected_release_sha256=TEST_RELEASE_SHA256,
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
        self.assertEqual(report["gates"]["F02"]["numerator"], 42)
        self.assertEqual(report["gates"]["F03"]["numerator"], 36)
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
        for gate_id in ("F01", "F02", "F05"):
            self.assertEqual(report["gates"][gate_id]["numerator"], 42)
            self.assertEqual(report["gates"][gate_id]["denominator"], 43)
            self.assertIn(missing_id, report["gates"][gate_id]["failures"])
        self.assertEqual(report["gates"]["F03"]["numerator"], 36)
        self.assertEqual(report["gates"]["F03"]["denominator"], 36)
        self.assertNotIn(missing_id, report["gates"]["F03"]["failures"])
        self.assertEqual(report["gates"]["F04"]["numerator"], 21)
        self.assertEqual(report["gates"]["F04"]["denominator"], 21)

    def test_trace_is_bound_to_corpus_input_and_rejects_unknown_event_fields(self) -> None:
        wrong_release = self._perfect_trace_document()
        with self.assertRaisesRegex(TraceValidationError, "package SHA-256 mismatch"):
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
        raw_registry_document_sha256 = canonical_sha256(self.registry)
        self.assertNotEqual(
            raw_registry_document_sha256,
            registry_digest(validate_registry(self.registry)),
        )
        wrong_registry["registry_digest"] = raw_registry_document_sha256
        self._resign(wrong_registry)
        with self.assertRaisesRegex(TraceValidationError, "registry_digest mismatch"):
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

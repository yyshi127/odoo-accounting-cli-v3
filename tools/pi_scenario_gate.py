"""Score frozen Pi natural-language traces for acceptance gates F01-F03.

This tool is deliberately offline: it consumes a frozen corpus and already
captured, normalized Pi traces.  It never invokes Pi, an LLM, Odoo, or a
network service.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import math
import re
import sys
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any

from odoo_accounting_cli_v3.contracts import ContractError, validate_value
from odoo_accounting_cli_v3.registry import RegistryError, validate_registry


CORPUS_SCHEMA = "odoo-accounting-cli-v3.pi-scenarios.v1"
TRACE_SCHEMA = "odoo-accounting-cli-v3.pi-traces.v1"
REPORT_SCHEMA = "odoo-accounting-cli-v3.pi-gate-report.v1"
SELECTION_MINIMUM_PERCENT = 95
COMPLETE_MINIMUM_PERCENT = 100
CATEGORIES = {
    "ordinary",
    "ambiguous",
    "adversarial",
    "multi_company",
    "multi_currency",
    "recovery",
}
CLARIFICATION_OUTCOMES = {"not_required", "clarified", "refused"}
SCENARIO_ID = re.compile(r"^pi-v1-[a-z0-9]+(?:-[a-z0-9]+)*$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
JSON_TYPES = {"array", "boolean", "integer", "number", "object", "string"}
EVENT_TYPES = (
    "user_input",
    "capability_selected",
    "clarification_completed",
    "material_parameters_finalized",
    "cli_input",
    "preview",
    "approval_binding",
    "odoo_execution",
    "odoo_result",
    "audit_receipt",
)
ATTESTATION_CONTEXT = b"odoo-accounting-cli-v3.pi-traces.v1\x00"


class CorpusValidationError(ValueError):
    """Raised when the frozen scenario corpus is invalid."""


class TraceValidationError(ValueError):
    """Raised when captured Pi evidence cannot be scored safely."""


def _exact_object(
    value: Any,
    fields: set[str],
    location: str,
    error_type: type[ValueError],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise error_type(f"{location} must be an object")
    missing = fields - set(value)
    extra = set(value) - fields
    if missing or extra:
        raise error_type(
            f"{location} fields invalid; missing={sorted(missing)}, extra={sorted(extra)}"
        )
    return value


def _nonempty_string(
    value: Any,
    location: str,
    error_type: type[ValueError],
    *,
    maximum: int = 2048,
) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise error_type(f"{location} must be a non-empty string of at most {maximum} characters")
    return value


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json_document(path: Path) -> Any:
    """Load strict JSON, including rejection of duplicate keys and NaN values."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON numeric constant: {value}")

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=reject_constant,
    )


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def trace_attestation_payload(trace_document: dict[str, Any]) -> bytes:
    """Canonical signed payload for a normalized Pi trace export."""

    unsigned = copy.deepcopy(trace_document)
    unsigned.pop("attestation", None)
    return ATTESTATION_CONTEXT + _canonical_json_bytes(unsigned)


def _matches_json_type(value: Any, kind: str) -> bool:
    if kind == "boolean":
        return isinstance(value, bool)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and not (isinstance(value, float) and not math.isfinite(value))
        )
    if kind == "string":
        return isinstance(value, str)
    if kind == "array":
        return isinstance(value, list)
    if kind == "object":
        return isinstance(value, dict)
    return False


def _validate_json_values(
    value: Any, location: str, error_type: type[ValueError]
) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise error_type(f"{location} must contain finite JSON numbers")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise error_type(f"{location} has a non-string object key")
            _validate_json_values(child, f"{location}.{key}", error_type)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json_values(child, f"{location}[{index}]", error_type)


def _registry_map(registry_document: Any) -> dict[str, dict[str, Any]]:
    try:
        capabilities = validate_registry(registry_document)
    except RegistryError as exc:
        raise CorpusValidationError(f"registry is invalid: {exc}") from exc
    return {capability.id: capability.data for capability in capabilities}


def _validate_fixture_references(
    value: Any,
    fixture_definitions: dict[str, Any],
    location: str,
) -> None:
    if isinstance(value, dict):
        if "$fixture" in value:
            if set(value) != {"$fixture"}:
                raise CorpusValidationError(
                    f"{location} fixture reference fields invalid"
                )
            name = value["$fixture"]
            if not isinstance(name, str) or name not in fixture_definitions:
                raise CorpusValidationError(
                    f"{location} references unknown fixture binding: {name!r}"
                )
            return
        for key, child in value.items():
            _validate_fixture_references(
                child, fixture_definitions, f"{location}.{key}"
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_fixture_references(
                child, fixture_definitions, f"{location}[{index}]"
            )
    _validate_json_values(value, location, CorpusValidationError)


def resolve_fixture_bindings(value: Any, bindings: dict[str, Any]) -> Any:
    """Return a detached value with every ``{"$fixture": name}`` replaced."""

    if isinstance(value, dict):
        if set(value) == {"$fixture"}:
            name = value["$fixture"]
            if not isinstance(name, str) or name not in bindings:
                raise TraceValidationError(f"missing fixture binding: {name!r}")
            return copy.deepcopy(bindings[name])
        return {
            key: resolve_fixture_bindings(child, bindings)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [resolve_fixture_bindings(child, bindings) for child in value]
    return copy.deepcopy(value)


def _material_path_parts(path: str) -> list[tuple[str, bool]]:
    if not isinstance(path, str) or not path:
        raise ValueError("material path must be a non-empty string")
    parts: list[tuple[str, bool]] = []
    for raw_part in path.split("."):
        is_array = raw_part.endswith("[]")
        name = raw_part[:-2] if is_array else raw_part
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            raise ValueError(f"invalid material path: {path}")
        parts.append((name, is_array))
    return parts


def _validate_material_path(schema: dict[str, Any], path: str) -> None:
    current = schema
    for name, is_array in _material_path_parts(path):
        declared = current.get("type")
        declared_types = declared if isinstance(declared, list) else [declared]
        if "object" not in declared_types or name not in current.get("properties", {}):
            raise ValueError(f"material path is not in the input schema: {path}")
        current = current["properties"][name]
        if is_array:
            declared = current.get("type")
            declared_types = declared if isinstance(declared, list) else [declared]
            if "array" not in declared_types or "items" not in current:
                raise ValueError(f"material path does not reference an array: {path}")
            current = current["items"]


def material_path_value(parameters: dict[str, Any], path: str) -> Any:
    """Return the exact value addressed by a dotted path with ``[]`` fan-out."""

    parts = _material_path_parts(path)

    def walk(value: Any, index: int) -> Any:
        name, is_array = parts[index]
        if not isinstance(value, dict) or name not in value:
            raise ValueError(f"material path is absent from parameters: {path}")
        child = value[name]
        if is_array:
            if not isinstance(child, list):
                raise ValueError(f"material path is not an array in parameters: {path}")
            if index == len(parts) - 1:
                return copy.deepcopy(child)
            return [walk(item, index + 1) for item in child]
        if index == len(parts) - 1:
            return copy.deepcopy(child)
        return walk(child, index + 1)

    return walk(parameters, 0)


def _require_full_schema_property_coverage(
    value: Any, schema: dict[str, Any], location: str
) -> None:
    declared = schema.get("type")
    declared_types = declared if isinstance(declared, list) else [declared]
    if isinstance(value, dict) and "object" in declared_types:
        properties = schema.get("properties", {})
        missing = set(properties) - set(value)
        if missing:
            raise CorpusValidationError(
                f"{location} missing material schema properties: {sorted(missing)}"
            )
        for name, child_schema in properties.items():
            _require_full_schema_property_coverage(
                value[name], child_schema, f"{location}.{name}"
            )
    elif isinstance(value, list) and "array" in declared_types:
        for index, item in enumerate(value):
            _require_full_schema_property_coverage(
                item, schema["items"], f"{location}[{index}]"
            )


def validate_corpus(
    corpus_document: Any, registry_document: Any
) -> dict[str, dict[str, Any]]:
    capabilities = _registry_map(registry_document)
    root = _exact_object(
        corpus_document,
        {
            "schema_version",
            "corpus_id",
            "frozen_revision",
            "description",
            "fixture_bindings",
            "scenarios",
        },
        "corpus",
        CorpusValidationError,
    )
    if root["schema_version"] != CORPUS_SCHEMA:
        raise CorpusValidationError(f"corpus.schema_version must be {CORPUS_SCHEMA}")
    corpus_id = _nonempty_string(
        root["corpus_id"], "corpus.corpus_id", CorpusValidationError, maximum=128
    )
    if not IDENTIFIER.fullmatch(corpus_id):
        raise CorpusValidationError("corpus.corpus_id has invalid format")
    revision = root["frozen_revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise CorpusValidationError("corpus.frozen_revision must be a positive integer")
    _nonempty_string(root["description"], "corpus.description", CorpusValidationError)

    fixture_definitions = root["fixture_bindings"]
    if not isinstance(fixture_definitions, dict) or not fixture_definitions:
        raise CorpusValidationError("corpus.fixture_bindings must be a non-empty object")
    for name, raw_definition in fixture_definitions.items():
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name):
            raise CorpusValidationError(f"invalid fixture binding name: {name!r}")
        definition = _exact_object(
            raw_definition,
            {"json_type", "description", "example"},
            f"corpus.fixture_bindings.{name}",
            CorpusValidationError,
        )
        if definition["json_type"] not in JSON_TYPES:
            raise CorpusValidationError(
                f"corpus.fixture_bindings.{name}.json_type is invalid"
            )
        _nonempty_string(
            definition["description"],
            f"corpus.fixture_bindings.{name}.description",
            CorpusValidationError,
            maximum=512,
        )
        if not _matches_json_type(definition["example"], definition["json_type"]):
            raise CorpusValidationError(
                f"corpus.fixture_bindings.{name}.example does not match json_type"
            )
        _validate_json_values(
            definition["example"],
            f"corpus.fixture_bindings.{name}.example",
            CorpusValidationError,
        )

    scenarios = root["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise CorpusValidationError("corpus.scenarios must be a non-empty array")
    seen_scenario_ids: set[str] = set()
    covered_capabilities: set[str] = set()
    covered_categories: set[str] = set()
    for index, raw_scenario in enumerate(scenarios):
        location = f"corpus.scenarios[{index}]"
        scenario = _exact_object(
            raw_scenario,
            {"id", "category", "input", "expected"},
            location,
            CorpusValidationError,
        )
        scenario_id = scenario["id"]
        if not isinstance(scenario_id, str) or not SCENARIO_ID.fullmatch(scenario_id):
            raise CorpusValidationError(f"{location}.id has invalid format")
        if scenario_id in seen_scenario_ids:
            raise CorpusValidationError(f"duplicate scenario id: {scenario_id}")
        seen_scenario_ids.add(scenario_id)
        if scenario["category"] not in CATEGORIES:
            raise CorpusValidationError(f"{location}.category is invalid")
        covered_categories.add(scenario["category"])
        prompt = _nonempty_string(
            scenario["input"], f"{location}.input", CorpusValidationError
        )
        if not re.search(r"[\u3400-\u9fff]", prompt):
            raise CorpusValidationError(f"{location}.input must contain Chinese text")

        expected = _exact_object(
            scenario["expected"],
            {"capability_id", "clarification", "material_parameters"},
            f"{location}.expected",
            CorpusValidationError,
        )
        capability_id = expected["capability_id"]
        if capability_id not in capabilities:
            raise CorpusValidationError(
                f"{location}.expected.capability_id is not registered: {capability_id!r}"
            )
        covered_capabilities.add(capability_id)
        clarification = _exact_object(
            expected["clarification"],
            {"outcome", "fields"},
            f"{location}.expected.clarification",
            CorpusValidationError,
        )
        outcome = clarification["outcome"]
        fields = clarification["fields"]
        if outcome not in CLARIFICATION_OUTCOMES:
            raise CorpusValidationError(
                f"{location}.expected.clarification.outcome is invalid"
            )
        if (
            not isinstance(fields, list)
            or any(not isinstance(field, str) or not field for field in fields)
            or len(fields) != len(set(fields))
            or fields != sorted(fields)
        ):
            raise CorpusValidationError(
                f"{location}.expected.clarification.fields must be a sorted unique string array"
            )
        schema = capabilities[capability_id]["input_schema"]
        for field in fields:
            try:
                _validate_material_path(schema, field)
            except ValueError as exc:
                raise CorpusValidationError(
                    f"{location}.expected.clarification.fields references an invalid parameter path: {field}"
                ) from exc
        if outcome == "clarified" and not fields:
            raise CorpusValidationError(
                f"{location}.expected.clarification.fields must identify clarified parameters"
            )
        if outcome != "clarified" and fields:
            raise CorpusValidationError(
                f"{location}.expected.clarification.fields must be empty for {outcome}"
            )

        parameters = expected["material_parameters"]
        if not isinstance(parameters, dict):
            raise CorpusValidationError(
                f"{location}.expected.material_parameters must be an object"
            )
        missing = set(schema["properties"]) - set(parameters)
        unknown = set(parameters) - set(schema["properties"])
        if missing:
            raise CorpusValidationError(
                f"{location}.expected.material_parameters missing required parameters: {sorted(missing)}"
            )
        if unknown:
            raise CorpusValidationError(
                f"{location}.expected.material_parameters has unknown parameters: {sorted(unknown)}"
            )
        _validate_fixture_references(
            parameters,
            fixture_definitions,
            f"{location}.expected.material_parameters",
        )
        examples = {
            name: definition["example"]
            for name, definition in fixture_definitions.items()
        }
        resolved = resolve_fixture_bindings(parameters, examples)
        _require_full_schema_property_coverage(
            resolved,
            schema,
            f"{location}.expected.material_parameters",
        )
        try:
            validate_value(resolved, schema)
        except ContractError as exc:
            raise CorpusValidationError(
                f"{location}.expected.material_parameters violates capability input schema: {exc}"
            ) from exc

    missing_categories = CATEGORIES - covered_categories
    if missing_categories:
        raise CorpusValidationError(
            f"corpus does not represent required categories: {sorted(missing_categories)}"
        )
    missing_capabilities = set(capabilities) - covered_capabilities
    if missing_capabilities:
        raise CorpusValidationError(
            f"corpus does not cover registered capabilities: {sorted(missing_capabilities)}"
        )
    return capabilities


def _parse_utc(value: Any, location: str) -> datetime:
    if not isinstance(value, str) or not RFC3339_UTC.fullmatch(value):
        raise TraceValidationError(f"{location} must be an RFC3339 UTC timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TraceValidationError(f"{location} is not a valid timestamp") from exc


def _validate_clarification_trace(value: Any, location: str) -> dict[str, Any]:
    clarification = _exact_object(
        value,
        {"outcome", "fields", "turns"},
        location,
        TraceValidationError,
    )
    if clarification["outcome"] not in CLARIFICATION_OUTCOMES:
        raise TraceValidationError(f"{location}.outcome is invalid")
    fields = clarification["fields"]
    if (
        not isinstance(fields, list)
        or any(not isinstance(field, str) or not field for field in fields)
        or len(fields) != len(set(fields))
        or fields != sorted(fields)
    ):
        raise TraceValidationError(
            f"{location}.fields must be a sorted unique string array"
        )
    turns = clarification["turns"]
    if not isinstance(turns, list):
        raise TraceValidationError(f"{location}.turns must be an array")
    turn_fields: list[str] = []
    for index, raw_turn in enumerate(turns):
        turn = _exact_object(
            raw_turn,
            {"field", "question", "answer"},
            f"{location}.turns[{index}]",
            TraceValidationError,
        )
        field = _nonempty_string(
            turn["field"],
            f"{location}.turns[{index}].field",
            TraceValidationError,
            maximum=256,
        )
        turn_fields.append(field)
        _nonempty_string(
            turn["question"],
            f"{location}.turns[{index}].question",
            TraceValidationError,
            maximum=2048,
        )
        _validate_json_values(
            turn["answer"],
            f"{location}.turns[{index}].answer",
            TraceValidationError,
        )
    if clarification["outcome"] == "clarified":
        if turn_fields != fields:
            raise TraceValidationError(
                f"{location}.turns must provide one ordered question and answer per clarified field"
            )
    elif turns:
        raise TraceValidationError(
            f"{location}.turns must be empty for {clarification['outcome']}"
        )
    return clarification


def validate_trace_document(
    trace_document: Any,
    corpus_document: Any,
    registry_document: Any,
    attestation_keys: dict[str, bytes],
    *,
    expected_release_sha256: str,
) -> None:
    capabilities = validate_corpus(corpus_document, registry_document)
    root = _exact_object(
        trace_document,
        {
            "schema_version",
            "corpus_id",
            "corpus_sha256",
            "registry_sha256",
            "capture",
            "bindings",
            "traces",
            "attestation",
        },
        "traces",
        TraceValidationError,
    )
    attestation = _exact_object(
        root["attestation"],
        {"algorithm", "key_id", "signed_payload_sha256", "signature"},
        "traces.attestation",
        TraceValidationError,
    )
    if attestation["algorithm"] != "hmac-sha256":
        raise TraceValidationError("traces.attestation.algorithm must be hmac-sha256")
    key_id = _nonempty_string(
        attestation["key_id"],
        "traces.attestation.key_id",
        TraceValidationError,
        maximum=128,
    )
    if not IDENTIFIER.fullmatch(key_id):
        raise TraceValidationError("traces.attestation.key_id has invalid format")
    if key_id not in attestation_keys:
        raise TraceValidationError(f"untrusted attestation key: {key_id}")
    key = attestation_keys[key_id]
    if not isinstance(key, bytes) or len(key) < 32:
        raise TraceValidationError(f"trusted attestation key is invalid: {key_id}")
    payload = trace_attestation_payload(root)
    payload_digest = hashlib.sha256(payload).hexdigest()
    claimed_payload_digest = attestation["signed_payload_sha256"]
    if (
        not isinstance(claimed_payload_digest, str)
        or not SHA256.fullmatch(claimed_payload_digest)
    ):
        raise TraceValidationError(
            "traces.attestation.signed_payload_sha256 must be lowercase SHA-256"
        )
    if claimed_payload_digest != payload_digest:
        raise TraceValidationError("traces.attestation signed payload digest mismatch")
    signature = attestation["signature"]
    if not isinstance(signature, str) or not SHA256.fullmatch(signature):
        raise TraceValidationError("traces.attestation.signature must be lowercase SHA-256")
    expected_signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise TraceValidationError("traces.attestation signature mismatch")
    if root["schema_version"] != TRACE_SCHEMA:
        raise TraceValidationError(f"traces.schema_version must be {TRACE_SCHEMA}")
    if root["corpus_id"] != corpus_document["corpus_id"]:
        raise TraceValidationError("traces.corpus_id mismatch")
    digest = root["corpus_sha256"]
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise TraceValidationError("traces.corpus_sha256 must be lowercase SHA-256")
    if digest != canonical_sha256(corpus_document):
        raise TraceValidationError("traces.corpus_sha256 mismatch")
    registry_digest = root["registry_sha256"]
    if not isinstance(registry_digest, str) or not SHA256.fullmatch(registry_digest):
        raise TraceValidationError("traces.registry_sha256 must be lowercase SHA-256")
    if registry_digest != canonical_sha256(registry_document):
        raise TraceValidationError("traces.registry_sha256 mismatch")

    capture = _exact_object(
        root["capture"],
        {
            "source",
            "run_id",
            "captured_at",
            "pi_agent_version",
            "pi_bridge_version",
            "v3_release_sha256",
        },
        "traces.capture",
        TraceValidationError,
    )
    if capture["source"] != "pi_agent":
        raise TraceValidationError("traces.capture.source must be pi_agent")
    for field in ("run_id", "pi_agent_version", "pi_bridge_version"):
        _nonempty_string(
            capture[field],
            f"traces.capture.{field}",
            TraceValidationError,
            maximum=128,
        )
    if not IDENTIFIER.fullmatch(capture["run_id"]):
        raise TraceValidationError("traces.capture.run_id has invalid format")
    if (
        not isinstance(capture["v3_release_sha256"], str)
        or not SHA256.fullmatch(capture["v3_release_sha256"])
    ):
        raise TraceValidationError(
            "traces.capture.v3_release_sha256 must be lowercase SHA-256"
        )
    if (
        not isinstance(expected_release_sha256, str)
        or not SHA256.fullmatch(expected_release_sha256)
    ):
        raise TraceValidationError(
            "expected release SHA-256 must be lowercase SHA-256"
        )
    if not hmac.compare_digest(
        capture["v3_release_sha256"], expected_release_sha256
    ):
        raise TraceValidationError("traces.capture release SHA-256 mismatch")
    _parse_utc(capture["captured_at"], "traces.capture.captured_at")

    fixture_definitions = corpus_document["fixture_bindings"]
    bindings = root["bindings"]
    if not isinstance(bindings, dict):
        raise TraceValidationError("traces.bindings must be an object")
    missing_bindings = set(fixture_definitions) - set(bindings)
    extra_bindings = set(bindings) - set(fixture_definitions)
    if missing_bindings or extra_bindings:
        raise TraceValidationError(
            "traces.bindings fields invalid; "
            f"missing={sorted(missing_bindings)}, extra={sorted(extra_bindings)}"
        )
    for name, value in bindings.items():
        if not _matches_json_type(value, fixture_definitions[name]["json_type"]):
            raise TraceValidationError(f"traces.bindings.{name} has invalid binding type")
        _validate_json_values(value, f"traces.bindings.{name}", TraceValidationError)

    traces = root["traces"]
    if not isinstance(traces, list):
        raise TraceValidationError("traces.traces must be an array")
    if not traces:
        raise TraceValidationError(
            "no captured Pi traces; accuracy is not scoreable"
        )
    scenarios = {scenario["id"]: scenario for scenario in corpus_document["scenarios"]}
    seen_scenarios: set[str] = set()
    seen_trace_ids: set[str] = set()
    for index, raw_trace in enumerate(traces):
        location = f"traces.traces[{index}]"
        trace = _exact_object(
            raw_trace,
            {"scenario_id", "trace_id", "started_at", "completed_at", "events"},
            location,
            TraceValidationError,
        )
        scenario_id = trace["scenario_id"]
        if scenario_id not in scenarios:
            raise TraceValidationError(f"{location}.scenario_id is not in the frozen corpus")
        if scenario_id in seen_scenarios:
            raise TraceValidationError(f"duplicate trace scenario id: {scenario_id}")
        seen_scenarios.add(scenario_id)
        scenario = scenarios[scenario_id]
        capability_id = scenario["expected"]["capability_id"]
        is_write = capabilities[capability_id]["access"] == "write"
        trace_id = _nonempty_string(
            trace["trace_id"], f"{location}.trace_id", TraceValidationError, maximum=128
        )
        if not IDENTIFIER.fullmatch(trace_id):
            raise TraceValidationError(f"{location}.trace_id has invalid format")
        if trace_id in seen_trace_ids:
            raise TraceValidationError(f"duplicate trace id: {trace_id}")
        seen_trace_ids.add(trace_id)
        started_at = _parse_utc(trace["started_at"], f"{location}.started_at")
        completed_at = _parse_utc(trace["completed_at"], f"{location}.completed_at")
        if completed_at < started_at:
            raise TraceValidationError(f"{location}.completed_at precedes started_at")

        events = trace["events"]
        if not isinstance(events, list) or len(events) != len(EVENT_TYPES):
            raise TraceValidationError(
                f"{location}.events must contain exactly the ten normalized Pi events"
            )
        for event_index, (raw_event, expected_type) in enumerate(
            zip(events, EVENT_TYPES), start=1
        ):
            event_location = f"{location}.events[{event_index - 1}]"
            event = _exact_object(
                raw_event,
                {"sequence", "type", "data"},
                event_location,
                TraceValidationError,
            )
            if event["sequence"] != event_index or isinstance(event["sequence"], bool):
                raise TraceValidationError(f"{event_location}.sequence is invalid")
            if event["type"] != expected_type:
                raise TraceValidationError(
                    f"{event_location}.type must be {expected_type}"
                )
            data_location = f"{event_location}.data"
            if expected_type == "user_input":
                data = _exact_object(
                    event["data"], {"text"}, data_location, TraceValidationError
                )
                if data["text"] != scenarios[scenario_id]["input"]:
                    raise TraceValidationError(
                        f"{data_location}.text does not match frozen input"
                    )
            elif expected_type == "capability_selected":
                data = _exact_object(
                    event["data"],
                    {"capability_id"},
                    data_location,
                    TraceValidationError,
                )
                selected = data["capability_id"]
                if selected is not None:
                    _nonempty_string(
                        selected,
                        f"{data_location}.capability_id",
                        TraceValidationError,
                        maximum=128,
                    )
            elif expected_type == "clarification_completed":
                _validate_clarification_trace(event["data"], data_location)
            elif expected_type in {"material_parameters_finalized", "cli_input"}:
                data = _exact_object(
                    event["data"],
                    {"parameters"},
                    data_location,
                    TraceValidationError,
                )
                if not isinstance(data["parameters"], dict):
                    raise TraceValidationError(
                        f"{data_location}.parameters must be an object"
                    )
                _validate_json_values(
                    data["parameters"],
                    f"{data_location}.parameters",
                    TraceValidationError,
                )
            elif expected_type == "preview":
                data = _exact_object(
                    event["data"],
                    {"applicable", "parameters"},
                    data_location,
                    TraceValidationError,
                )
                if not isinstance(data["applicable"], bool):
                    raise TraceValidationError(
                        f"{data_location}.applicable must be boolean"
                    )
                if data["applicable"] is not is_write:
                    raise TraceValidationError(
                        f"{data_location}.applicable does not match capability access"
                    )
                if is_write and not isinstance(data["parameters"], dict):
                    raise TraceValidationError(
                        f"{data_location}.parameters must be an object for writes"
                    )
                if not is_write and data["parameters"] is not None:
                    raise TraceValidationError(
                        f"{data_location}.parameters must be null for reads"
                    )
                _validate_json_values(
                    data["parameters"],
                    f"{data_location}.parameters",
                    TraceValidationError,
                )
            elif expected_type == "approval_binding":
                data = _exact_object(
                    event["data"],
                    {"applicable", "parameters_sha256", "approval_digest"},
                    data_location,
                    TraceValidationError,
                )
                if not isinstance(data["applicable"], bool):
                    raise TraceValidationError(
                        f"{data_location}.applicable must be boolean"
                    )
                if data["applicable"] is not is_write:
                    raise TraceValidationError(
                        f"{data_location}.applicable does not match capability access"
                    )
                for field in ("parameters_sha256", "approval_digest"):
                    value = data[field]
                    if is_write:
                        if not isinstance(value, str) or not SHA256.fullmatch(value):
                            raise TraceValidationError(
                                f"{data_location}.{field} must be lowercase SHA-256 for writes"
                            )
                    elif value is not None:
                        raise TraceValidationError(
                            f"{data_location}.{field} must be null for reads"
                        )
            elif expected_type in {"odoo_execution", "odoo_result"}:
                reference_field = (
                    "execution_reference"
                    if expected_type == "odoo_execution"
                    else "result_reference"
                )
                data = _exact_object(
                    event["data"],
                    {"parameters_sha256", reference_field},
                    data_location,
                    TraceValidationError,
                )
                if (
                    not isinstance(data["parameters_sha256"], str)
                    or not SHA256.fullmatch(data["parameters_sha256"])
                ):
                    raise TraceValidationError(
                        f"{data_location}.parameters_sha256 must be lowercase SHA-256"
                    )
                _nonempty_string(
                    data[reference_field],
                    f"{data_location}.{reference_field}",
                    TraceValidationError,
                    maximum=128,
                )
            else:
                data = _exact_object(
                    event["data"],
                    {"parameters_sha256", "receipt_id"},
                    data_location,
                    TraceValidationError,
                )
                if (
                    not isinstance(data["parameters_sha256"], str)
                    or not SHA256.fullmatch(data["parameters_sha256"])
                ):
                    raise TraceValidationError(
                        f"{data_location}.parameters_sha256 must be lowercase SHA-256"
                    )
                _nonempty_string(
                    data["receipt_id"],
                    f"{data_location}.receipt_id",
                    TraceValidationError,
                    maximum=128,
                )

        expected_parameters = resolve_fixture_bindings(
            scenario["expected"]["material_parameters"], bindings
        )
        try:
            validate_value(
                expected_parameters, capabilities[capability_id]["input_schema"]
            )
        except ContractError as exc:
            raise TraceValidationError(
                f"{location} fixture bindings produce invalid expected parameters: {exc}"
            ) from exc


def _events_by_type(trace: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {event["type"]: event["data"] for event in trace["events"]}


def _different_paths(expected: Any, actual: Any, path: str = "$") -> list[str]:
    if type(expected) is not type(actual):
        return [path]
    if isinstance(expected, dict):
        differences: list[str] = []
        for key in sorted(set(expected) | set(actual)):
            child_path = f"{path}.{key}"
            if key not in expected or key not in actual:
                differences.append(child_path)
            else:
                differences.extend(
                    _different_paths(expected[key], actual[key], child_path)
                )
        return differences
    if isinstance(expected, list):
        differences = []
        for index in range(max(len(expected), len(actual))):
            child_path = f"{path}[{index}]"
            if index >= len(expected) or index >= len(actual):
                differences.append(child_path)
            else:
                differences.extend(
                    _different_paths(expected[index], actual[index], child_path)
                )
        return differences
    return [] if expected == actual else [path]


def _percent(numerator: int, denominator: int) -> str:
    value = (Decimal(numerator) * Decimal(100) / Decimal(denominator)).quantize(
        Decimal("0.01"), rounding=ROUND_HALF_UP
    )
    return f"{value:.2f}"


def _gate_report(
    numerator: int,
    denominator: int,
    minimum_percent: int,
    failures: dict[str, Any],
) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "percent": _percent(numerator, denominator),
        "minimum_percent": f"{minimum_percent:.2f}",
        "passed": numerator * 100 >= minimum_percent * denominator,
        "failures": failures,
    }


def score_documents(
    corpus_document: Any,
    trace_document: Any,
    registry_document: Any,
    attestation_keys: dict[str, bytes],
    *,
    expected_release_sha256: str,
) -> dict[str, Any]:
    """Validate captured evidence and return a deterministic F01-F03 report."""

    validate_trace_document(
        trace_document,
        corpus_document,
        registry_document,
        attestation_keys,
        expected_release_sha256=expected_release_sha256,
    )
    scenarios = corpus_document["scenarios"]
    traces = {trace["scenario_id"]: trace for trace in trace_document["traces"]}
    bindings = trace_document["bindings"]
    access_by_capability = {
        item["id"]: item["access"] for item in registry_document["capabilities"]
    }
    f01_failures: dict[str, Any] = {}
    f02_failures: dict[str, Any] = {}
    f03_failures: dict[str, Any] = {}
    for scenario in scenarios:
        scenario_id = scenario["id"]
        trace = traces.get(scenario_id)
        if trace is None:
            failure = {"reason": "missing_trace"}
            f01_failures[scenario_id] = failure
            f02_failures[scenario_id] = failure
            f03_failures[scenario_id] = failure
            continue
        events = _events_by_type(trace)
        selected = events["capability_selected"]["capability_id"]
        clarification = events["clarification_completed"]
        parameters = events["material_parameters_finalized"]["parameters"]
        expected = scenario["expected"]
        if selected != expected["capability_id"]:
            f01_failures[scenario_id] = {
                "reason": "capability_mismatch",
                "expected": expected["capability_id"],
                "actual": selected,
            }
        actual_clarification = {
            "outcome": clarification["outcome"],
            "fields": clarification["fields"],
        }
        clarification_issues: dict[str, Any] = {}
        if actual_clarification != expected["clarification"]:
            clarification_issues["outcome_or_fields"] = {
                "expected": expected["clarification"],
                "actual": actual_clarification,
            }
        expected_parameters = resolve_fixture_bindings(
            expected["material_parameters"], bindings
        )
        if expected["clarification"]["outcome"] == "clarified":
            turns = {turn["field"]: turn for turn in clarification["turns"]}
            for field in expected["clarification"]["fields"]:
                turn = turns.get(field)
                if turn is None:
                    clarification_issues[field] = {"reason": "missing_question_answer"}
                    continue
                expected_answer = material_path_value(expected_parameters, field)
                try:
                    finalized_value = material_path_value(parameters, field)
                except ValueError:
                    finalized_value = {"missing": True}
                if turn["answer"] != expected_answer or finalized_value != turn["answer"]:
                    clarification_issues[field] = {
                        "reason": "answer_not_bound_to_expected_final_value",
                        "expected_answer": expected_answer,
                        "captured_answer": turn["answer"],
                        "finalized_value": finalized_value,
                    }
        if clarification_issues:
            f02_failures[scenario_id] = {
                "reason": "clarification_mismatch",
                "issues": clarification_issues,
            }

        stage_failures: dict[str, Any] = {}
        for stage in ("material_parameters_finalized", "cli_input"):
            differences = _different_paths(
                expected_parameters, events[stage]["parameters"]
            )
            if differences:
                stage_failures[stage] = {"paths": differences}
        is_write = access_by_capability[expected["capability_id"]] == "write"
        if is_write:
            differences = _different_paths(
                expected_parameters, events["preview"]["parameters"]
            )
            if differences:
                stage_failures["preview"] = {"paths": differences}
        expected_parameters_sha256 = canonical_sha256(expected_parameters)
        digest_stages = ["odoo_execution", "odoo_result", "audit_receipt"]
        if is_write:
            digest_stages.insert(0, "approval_binding")
        for stage in digest_stages:
            actual_digest = events[stage]["parameters_sha256"]
            if actual_digest != expected_parameters_sha256:
                stage_failures[stage] = {
                    "expected_parameters_sha256": expected_parameters_sha256,
                    "actual_parameters_sha256": actual_digest,
                }
        if stage_failures:
            f03_failures[scenario_id] = {
                "reason": "material_parameter_mismatch",
                "stages": sorted(stage_failures),
                "details": stage_failures,
            }

    denominator = len(scenarios)
    scenario_ids = [scenario["id"] for scenario in scenarios]
    missing = [scenario_id for scenario_id in scenario_ids if scenario_id not in traces]
    gates = {
        "F01": _gate_report(
            denominator - len(f01_failures),
            denominator,
            SELECTION_MINIMUM_PERCENT,
            f01_failures,
        ),
        "F02": _gate_report(
            denominator - len(f02_failures),
            denominator,
            COMPLETE_MINIMUM_PERCENT,
            f02_failures,
        ),
        "F03": _gate_report(
            denominator - len(f03_failures),
            denominator,
            COMPLETE_MINIMUM_PERCENT,
            f03_failures,
        ),
    }
    coverage = {
        "captured": len(traces),
        "expected": denominator,
        "passed": not missing,
        "missing_scenario_ids": missing,
    }
    return {
        "schema_version": REPORT_SCHEMA,
        "corpus_id": corpus_document["corpus_id"],
        "corpus_sha256": canonical_sha256(corpus_document),
        "registry_sha256": canonical_sha256(registry_document),
        "run_id": trace_document["capture"]["run_id"],
        "capture": copy.deepcopy(trace_document["capture"]),
        "attestation": copy.deepcopy(trace_document["attestation"]),
        "trace_coverage": coverage,
        "gates": gates,
        "acceptance_passed": coverage["passed"]
        and all(gate["passed"] for gate in gates.values()),
    }


def load_attestation_keys(document: Any) -> dict[str, bytes]:
    root = _exact_object(
        document,
        {"schema_version", "keys"},
        "attestation_keys",
        TraceValidationError,
    )
    if root["schema_version"] != "odoo-accounting-cli-v3.pi-attestation-keys.v1":
        raise TraceValidationError("attestation_keys.schema_version is invalid")
    definitions = root["keys"]
    if not isinstance(definitions, dict) or not definitions:
        raise TraceValidationError("attestation_keys.keys must be a non-empty object")
    keys: dict[str, bytes] = {}
    for key_id, raw_definition in definitions.items():
        if not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
            raise TraceValidationError(f"invalid attestation key id: {key_id!r}")
        definition = _exact_object(
            raw_definition,
            {"secret_hex"},
            f"attestation_keys.keys.{key_id}",
            TraceValidationError,
        )
        secret_hex = definition["secret_hex"]
        if (
            not isinstance(secret_hex, str)
            or len(secret_hex) < 64
            or len(secret_hex) > 512
            or len(secret_hex) % 2
            or re.fullmatch(r"[0-9a-f]+", secret_hex) is None
        ):
            raise TraceValidationError(
                f"attestation_keys.keys.{key_id}.secret_hex must encode 32-256 bytes"
            )
        keys[key_id] = bytes.fromhex(secret_hex)
    return keys


def _parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Score already captured Pi traces against frozen acceptance gates F01-F03; "
            "this command never invokes an LLM."
        )
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=project_root / "tests" / "fixtures" / "pi_scenarios.v1.json",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=project_root / "registry" / "capabilities.json",
    )
    parser.add_argument(
        "--traces",
        type=Path,
        required=True,
        help="normalized Pi trace capture; required so no synthetic accuracy is implied",
    )
    parser.add_argument(
        "--attestation-keys",
        type=Path,
        required=True,
        help="host-local trusted HMAC key file used to authenticate Pi trace exports",
    )
    parser.add_argument(
        "--expected-release-sha256",
        required=True,
        help="trusted canonical V3 package SHA-256 expected for this capture",
    )
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        corpus = load_json_document(args.corpus)
        registry = load_json_document(args.registry)
        traces = load_json_document(args.traces)
        attestation_keys = load_attestation_keys(
            load_json_document(args.attestation_keys)
        )
        report = score_documents(
            corpus,
            traces,
            registry,
            attestation_keys,
            expected_release_sha256=args.expected_release_sha256,
        )
        encoded = json.dumps(
            report, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2
        ) + "\n"
        if args.output is None:
            sys.stdout.write(encoded)
        else:
            args.output.write_text(encoded, encoding="utf-8")
    except (
        OSError,
        ValueError,
        CorpusValidationError,
        TraceValidationError,
    ) as exc:
        print(f"Pi scenario gate not scored: {exc}", file=sys.stderr)
        return 2
    return 0 if report["acceptance_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

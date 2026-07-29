"""Score frozen Pi natural-language traces for acceptance gates F01-F05.

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
from odoo_accounting_cli_v3.pi_evidence import (
    PiEvidenceError,
    PiEvidenceSummary,
    PiEvidenceTrust,
    PiEvidenceVerifier,
)
from odoo_accounting_cli_v3.registry import (
    RegistryError,
    registry_digest as capability_registry_digest,
    validate_registry,
)
from odoo_accounting_cli_v3.trusted_authority_bootstrap import (
    load_trusted_authority_runtime_config,
)
from odoo_accounting_cli_v3.verified_release import (
    load_verified_release_route,
)


CORPUS_SCHEMA = "odoo-accounting-cli-v3.pi-scenarios.v1"
TRACE_SCHEMA = "odoo-accounting-cli-v3.pi-traces.v3"
REPORT_SCHEMA = "odoo-accounting-cli-v3.pi-gate-report.v3"
SELECTION_MINIMUM_PERCENT = 95
COMPLETE_MINIMUM_PERCENT = 100
VERIFIED_ANSWER_MINIMUM_PERCENT = 100
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
PLACEHOLDER_SHA256_VALUES = frozenset(character * 64 for character in "0123456789abcdef")
RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
JSON_TYPES = {"array", "boolean", "integer", "number", "object", "string"}
EVENT_PREFIX = (
    "user_input",
    "capability_selected",
    "clarification_completed",
)
REFUSED_EVENT_TYPES = EVENT_PREFIX + (
    "execution_refused",
    "assistant_final",
)
READ_EVENT_TYPES = EVENT_PREFIX + (
    "material_parameters_finalized",
    "cli_input",
    "odoo_execution",
    "odoo_result",
    "audit_receipt",
    "assistant_final",
)
WRITE_EVENT_TYPES = EVENT_PREFIX + (
    "material_parameters_finalized",
    "cli_input",
    "prepare",
    "preview",
    "approval_binding",
    "odoo_execution",
    "odoo_result",
    "audit_receipt",
    "assistant_final",
)
ATTESTATION_CONTEXT = b"odoo-accounting-cli-v3.pi-traces.v3\x00"
CAPTURE_BINDING_FIELDS = {
    "pi_agent_version",
    "pi_bridge_version",
    "provider",
    "model",
    "system_prompt_sha256",
    "tool_set_sha256",
    "pi_runtime_sha256",
}
OPERATION_DIGEST_INPUT_FIELDS = {
    "capability_id",
    "company_id",
    "database_name",
    "database_uuid",
    "environment",
    "idempotency_key",
    "odoo_instance_id",
    "parameters",
    "principal",
    "registry_digest",
    "release_digest",
    "user_id",
}
PREVIEW_FIELDS = {
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
}
PRECHECK_FIELDS = {
    "capability_id",
    "company_id",
    "parameters_digest",
    "passed",
    "checks",
    "handler_details",
    "runtime_binding",
    "registry_digest",
    "release_digest",
}
PRECHECK_RUNTIME_FIELDS = {
    "user_id",
    "odoo_instance_id",
    "database_name",
    "database_uuid",
    "environment",
    "capability_channel",
}
PRECHECK_IDENTITY_FIELDS = {
    "operation_id",
    "precheck_digest",
    "registry_digest",
    "release_digest",
}
ASSISTANT_RESULT_FIELDS = {
    "status",
    "business_succeeded",
    "operation_id",
    "receipt_id",
    "result_digest",
}


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


def canonical_json_text(value: Any) -> str:
    return _canonical_json_bytes(value).decode("utf-8")


def _json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int coercion."""

    try:
        return _canonical_json_bytes(left) == _canonical_json_bytes(right)
    except (TypeError, ValueError, UnicodeError):
        return False


def approval_binding_sha256(value: dict[str, Any]) -> str:
    """Digest the exact independently approved operation and preview binding."""

    fields = {
        "operation_id",
        "parameters_sha256",
        "preview_sha256",
        "requester_user_id",
        "approver_user_id",
        "approved_at",
        "expires_at",
    }
    keys = set(value) if isinstance(value, dict) else set()
    if not isinstance(value, dict) or (
        keys != fields and keys != fields | {"approval_digest"}
    ):
        raise ValueError("approval binding fields are invalid")
    return canonical_sha256(
        {
            "purpose": "pi_scenario_approval_binding_v2",
            **{field: value[field] for field in sorted(fields)},
        }
    )


def _parse_assistant_result(text: Any, location: str) -> dict[str, Any]:
    text = _nonempty_string(
        text,
        location,
        TraceValidationError,
        maximum=8192,
    )

    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON numeric constant: {value}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TraceValidationError(
            f"{location} must be strict canonical JSON"
        ) from exc
    result = _exact_object(
        value,
        ASSISTANT_RESULT_FIELDS,
        location,
        TraceValidationError,
    )
    if canonical_json_text(result) != text:
        raise TraceValidationError(f"{location} must be strict canonical JSON")
    if result["status"] not in {"verified_success", "refused"}:
        raise TraceValidationError(f"{location}.status is invalid")
    if not isinstance(result["business_succeeded"], bool):
        raise TraceValidationError(
            f"{location}.business_succeeded must be boolean"
        )
    for field in ("operation_id", "receipt_id"):
        value = result[field]
        if value is not None:
            _require_identifier(value, f"{location}.{field}")
    if result["result_digest"] is not None:
        _require_sha256(
            result["result_digest"],
            f"{location}.result_digest",
            TraceValidationError,
        )
    return result


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
    elif isinstance(value, str) and value in PLACEHOLDER_SHA256_VALUES:
        raise error_type(f"{location} must not be a placeholder SHA-256")


def _require_sha256(
    value: Any,
    location: str,
    error_type: type[ValueError],
    *,
    reject_placeholder: bool = True,
) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise error_type(f"{location} must be lowercase SHA-256")
    if reject_placeholder and value in PLACEHOLDER_SHA256_VALUES:
        raise error_type(f"{location} must not be a placeholder SHA-256")
    return value


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


def _require_identifier(value: Any, location: str) -> str:
    result = _nonempty_string(
        value, location, TraceValidationError, maximum=128
    )
    if not IDENTIFIER.fullmatch(result):
        raise TraceValidationError(f"{location} has invalid format")
    return result


def _require_positive_integer(value: Any, location: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TraceValidationError(f"{location} must be a positive integer")
    return value


def _require_operation_reference(
    value: Any,
    *,
    is_write: bool,
    location: str,
) -> str | None:
    if is_write:
        return _require_identifier(value, location)
    if value is not None:
        raise TraceValidationError(
            f"{location} must be null for a read capability"
        )
    return None


def _validate_capture_binding(
    value: Any,
    location: str,
) -> dict[str, Any]:
    binding = _exact_object(
        value,
        CAPTURE_BINDING_FIELDS,
        location,
        TraceValidationError,
    )
    for field in (
        "pi_agent_version",
        "pi_bridge_version",
        "provider",
        "model",
    ):
        _nonempty_string(
            binding[field],
            f"{location}.{field}",
            TraceValidationError,
            maximum=256,
        )
    for field in (
        "system_prompt_sha256",
        "tool_set_sha256",
        "pi_runtime_sha256",
    ):
        _require_sha256(
            binding[field],
            f"{location}.{field}",
            TraceValidationError,
        )
    return binding


def _validate_operation_digest_input(
    value: Any,
    location: str,
) -> dict[str, Any]:
    identity = _exact_object(
        value,
        OPERATION_DIGEST_INPUT_FIELDS,
        location,
        TraceValidationError,
    )
    _require_identifier(
        identity["capability_id"], f"{location}.capability_id"
    )
    _require_positive_integer(identity["company_id"], f"{location}.company_id")
    _require_positive_integer(identity["user_id"], f"{location}.user_id")
    for field in (
        "database_name",
        "database_uuid",
        "idempotency_key",
        "odoo_instance_id",
        "principal",
    ):
        _nonempty_string(
            identity[field],
            f"{location}.{field}",
            TraceValidationError,
            maximum=512,
        )
    if identity["environment"] not in {"test", "sandbox", "production"}:
        raise TraceValidationError(f"{location}.environment is invalid")
    if not isinstance(identity["parameters"], dict):
        raise TraceValidationError(f"{location}.parameters must be an object")
    _validate_json_values(
        identity["parameters"],
        f"{location}.parameters",
        TraceValidationError,
    )
    for field in ("registry_digest", "release_digest"):
        _require_sha256(
            identity[field],
            f"{location}.{field}",
            TraceValidationError,
        )
    return identity


def _validate_preview_structure(
    value: Any,
    location: str,
) -> dict[str, Any]:
    preview = _exact_object(
        value,
        PREVIEW_FIELDS,
        location,
        TraceValidationError,
    )
    _require_identifier(preview["operation_id"], f"{location}.operation_id")
    _require_identifier(preview["capability_id"], f"{location}.capability_id")
    if preview["operation_state"] != "awaiting_approval":
        raise TraceValidationError(
            f"{location}.operation_state must be awaiting_approval"
        )
    _nonempty_string(
        preview["business_description"],
        f"{location}.business_description",
        TraceValidationError,
        maximum=4096,
    )
    _nonempty_string(
        preview["risk_level"],
        f"{location}.risk_level",
        TraceValidationError,
        maximum=128,
    )
    if not isinstance(preview["parameters"], dict):
        raise TraceValidationError(f"{location}.parameters must be an object")
    _validate_json_values(
        preview["parameters"],
        f"{location}.parameters",
        TraceValidationError,
    )
    _require_sha256(
        preview["operation_digest"],
        f"{location}.operation_digest",
        TraceValidationError,
    )
    for field in ("approval", "recovery"):
        if not isinstance(preview[field], dict):
            raise TraceValidationError(f"{location}.{field} must be an object")
        _validate_json_values(
            preview[field],
            f"{location}.{field}",
            TraceValidationError,
        )

    precheck = _exact_object(
        preview["precheck"],
        PRECHECK_FIELDS,
        f"{location}.precheck",
        TraceValidationError,
    )
    _require_identifier(
        precheck["capability_id"], f"{location}.precheck.capability_id"
    )
    _require_positive_integer(
        precheck["company_id"], f"{location}.precheck.company_id"
    )
    for field in (
        "parameters_digest",
        "registry_digest",
        "release_digest",
    ):
        _require_sha256(
            precheck[field],
            f"{location}.precheck.{field}",
            TraceValidationError,
        )
    if precheck["passed"] is not True:
        raise TraceValidationError(f"{location}.precheck.passed must be true")
    if not isinstance(precheck["checks"], list) or not precheck["checks"]:
        raise TraceValidationError(
            f"{location}.precheck.checks must be a non-empty array"
        )
    if not isinstance(precheck["handler_details"], dict):
        raise TraceValidationError(
            f"{location}.precheck.handler_details must be an object"
        )
    _validate_json_values(
        precheck["checks"],
        f"{location}.precheck.checks",
        TraceValidationError,
    )
    _validate_json_values(
        precheck["handler_details"],
        f"{location}.precheck.handler_details",
        TraceValidationError,
    )
    runtime = _exact_object(
        precheck["runtime_binding"],
        PRECHECK_RUNTIME_FIELDS,
        f"{location}.precheck.runtime_binding",
        TraceValidationError,
    )
    _require_positive_integer(
        runtime["user_id"],
        f"{location}.precheck.runtime_binding.user_id",
    )
    for field in (
        "odoo_instance_id",
        "database_name",
        "database_uuid",
    ):
        _nonempty_string(
            runtime[field],
            f"{location}.precheck.runtime_binding.{field}",
            TraceValidationError,
            maximum=512,
        )
    if runtime["environment"] not in {"test", "sandbox", "production"}:
        raise TraceValidationError(
            f"{location}.precheck.runtime_binding.environment is invalid"
        )
    if runtime["capability_channel"] not in {"staged", "enabled"}:
        raise TraceValidationError(
            f"{location}.precheck.runtime_binding.capability_channel is invalid"
        )
    precheck_digest = _require_sha256(
        preview["precheck_digest"],
        f"{location}.precheck_digest",
        TraceValidationError,
    )
    if precheck_digest != canonical_sha256(precheck):
        raise TraceValidationError(f"{location}.precheck_digest mismatch")
    identity = _exact_object(
        preview["precheck_identity"],
        PRECHECK_IDENTITY_FIELDS,
        f"{location}.precheck_identity",
        TraceValidationError,
    )
    _require_identifier(
        identity["operation_id"],
        f"{location}.precheck_identity.operation_id",
    )
    for field in (
        "precheck_digest",
        "registry_digest",
        "release_digest",
    ):
        _require_sha256(
            identity[field],
            f"{location}.precheck_identity.{field}",
            TraceValidationError,
        )
    return preview


def _validate_write_preview_binding(
    *,
    prepare: dict[str, Any],
    preview_event: dict[str, Any],
    finalized_parameters: dict[str, Any],
    capability: dict[str, Any],
    registry_digest: str,
    release_digest: str,
    location: str,
) -> None:
    identity = prepare["operation_digest_input"]
    preview = preview_event["preview"]
    precheck = preview["precheck"]
    runtime = precheck["runtime_binding"]
    precheck_identity = preview["precheck_identity"]
    company_id = finalized_parameters.get("company_id")
    expected_operation_digest = canonical_sha256(identity)
    expected_precheck_identity = {
        "operation_id": preview["operation_id"],
        "precheck_digest": preview["precheck_digest"],
        "registry_digest": registry_digest,
        "release_digest": release_digest,
    }
    expected_runtime = {
        "user_id": identity["user_id"],
        "odoo_instance_id": identity["odoo_instance_id"],
        "database_name": identity["database_name"],
        "database_uuid": identity["database_uuid"],
        "environment": identity["environment"],
    }
    actual_runtime = {
        field: runtime[field] for field in expected_runtime
    }
    if (
        prepare["operation_id"] != preview_event["operation_id"]
        or prepare["operation_id"] != preview["operation_id"]
        or preview_event["parameters"] != finalized_parameters
        or preview["parameters"] != finalized_parameters
        or identity["parameters"] != finalized_parameters
        or identity["capability_id"] != capability["id"]
        or preview["capability_id"] != capability["id"]
        or precheck["capability_id"] != capability["id"]
        or identity["company_id"] != company_id
        or precheck["company_id"] != company_id
        or identity["idempotency_key"]
        != finalized_parameters.get("idempotency_key")
        or identity["registry_digest"] != registry_digest
        or identity["release_digest"] != release_digest
        or precheck["registry_digest"] != registry_digest
        or precheck["release_digest"] != release_digest
        or preview["operation_digest"] != expected_operation_digest
        or precheck["parameters_digest"]
        != canonical_sha256(finalized_parameters)
        or precheck_identity != expected_precheck_identity
        or actual_runtime != expected_runtime
        or preview["business_description"]
        != capability["business_description"]
        or preview["risk_level"] != capability["risk_level"]
        or preview["approval"] != capability["approval"]
        or preview["recovery"] != capability["recovery"]
    ):
        raise TraceValidationError(
            f"{location} does not match the actual bound operation.preview"
        )


def _read_verification_evidence(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        "scope": "authenticated_odoo_response",
        "capability_id": receipt["capability_id"],
        "receipt_id": receipt["id"],
        "result_digest": receipt["result_digest"],
        "output_schema_verified": True,
        "response_signature_verified": True,
    }


def _validate_trusted_normalized_binding(
    *,
    trace: dict[str, Any],
    event_data: dict[str, dict[str, Any]],
    is_write: bool,
    trace_started_at: datetime,
    trace_completed_at: datetime,
    captured_at: datetime,
    finalized_parameters: dict[str, Any],
    location: str,
) -> None:
    evidence = trace["trusted_evidence"]
    exchanges = (
        [
            evidence["prepare_exchange"],
            evidence["preview_exchange"],
            evidence["approve_execute_exchange"],
        ]
        if is_write
        else [evidence["read_exchange"]]
    )
    if trace_completed_at > captured_at:
        raise TraceValidationError(
            f"{location}.completed_at exceeds capture.captured_at"
        )
    for exchange_index, exchange in enumerate(exchanges):
        occurred_at = _parse_utc(
            exchange["occurred_at"],
            f"{location}.trusted_evidence.exchange[{exchange_index}].occurred_at",
        )
        completed_at = _parse_utc(
            exchange["tool_completed_at"],
            f"{location}.trusted_evidence.exchange[{exchange_index}].tool_completed_at",
        )
        if (
            occurred_at < trace_started_at
            or completed_at > trace_completed_at
        ):
            raise TraceValidationError(
                f"{location}.trusted_evidence is outside the trace window"
            )

    terminal = exchanges[-1]
    execution = event_data["odoo_execution"]
    result_event = event_data["odoo_result"]
    receipt_event = event_data["audit_receipt"]
    if execution["executed_at"] != terminal["broker_dispatched_at"]:
        raise TraceValidationError(
            f"{location}.odoo_execution.executed_at is not broker-bound"
        )

    response = terminal["broker_response"]
    if is_write:
        raw_data = response["data"]
        raw_receipt = raw_data["audit_receipt"]
        raw_result_body = {
            key: value
            for key, value in raw_data.items()
            if key != "audit_receipt"
        }
        raw_verification = raw_data["verification"]
        expected_verification_evidence_digest = raw_verification[
            "evidence_digest"
        ]
        if (
            result_event["verification"]["passed"]
            is not raw_verification["passed"]
            or result_event["verification"]["verified_at"]
            != raw_verification["verified_at"]
            or result_event["verification"]["evidence_digest"]
            != expected_verification_evidence_digest
            or canonical_sha256(
                result_event["verification"]["evidence"]
            )
            != expected_verification_evidence_digest
        ):
            raise TraceValidationError(
                f"{location}.odoo_result.verification is not raw-bound"
            )
        expected_business_succeeded = response["business_succeeded"]
        expected_database_finalized = (
            raw_data.get("database_finalization") is not None
        )
        expected_odoo_effect = (
            expected_business_succeeded is True
            and raw_verification["passed"] is True
            and expected_database_finalized
        )
        expected_receipt = {
            "receipt_id": raw_receipt["receipt_id"],
            "operation_id": raw_receipt["operation_id"],
            "capability_id": raw_receipt["capability_id"],
            "release_digest": raw_receipt["release_digest"],
            "registry_digest": raw_receipt["registry_digest"],
            "result_digest": raw_receipt["result_digest"],
            "verification_evidence_digest": raw_receipt[
                "verification_evidence_digest"
            ],
            "issued_at": raw_receipt["issued_at"],
        }

        preview_event = event_data["preview"]
        raw_preview = evidence["preview_exchange"]["broker_response"]["data"]
        raw_preview_projection = {
            field: raw_preview[field] for field in PREVIEW_FIELDS
        }
        if (
            not _json_equal(
                preview_event["preview"],
                raw_preview_projection,
            )
            or not _json_equal(
                preview_event["parameters"],
                raw_preview_projection["parameters"],
            )
            or preview_event["preview_sha256"]
            != canonical_sha256(raw_preview_projection)
            or preview_event["parameters_sha256"]
            != canonical_sha256(raw_preview_projection["parameters"])
        ):
            raise TraceValidationError(
                f"{location}.preview is not the exact raw preview projection"
            )

        raw_approval = terminal["broker_request"]["approval"]
        expected_approval = {
            "operation_id": raw_approval["operation_id"],
            "parameters_sha256": canonical_sha256(
                raw_preview_projection["parameters"]
            ),
            "preview_sha256": canonical_sha256(raw_preview_projection),
            "requester_user_id": raw_approval["user_id"],
            "approver_user_id": raw_approval["approver_user_id"],
            "approved_at": raw_approval["issued_at"],
            "expires_at": raw_approval["expires_at"],
        }
        expected_approval["approval_digest"] = approval_binding_sha256(
            expected_approval
        )
        if not _json_equal(
            event_data["approval_binding"],
            expected_approval,
        ):
            raise TraceValidationError(
                f"{location}.approval_binding is not raw-bound"
            )
    else:
        raw_container = (
            response["data"]["result"]
            if terminal["action"] == "read"
            else response["data"]
        )
        raw_receipt = raw_container["receipt"]
        raw_result_body = {
            key: value
            for key, value in raw_container.items()
            if key != "receipt"
        }
        expected_verification_evidence = _read_verification_evidence(
            raw_receipt
        )
        expected_verification_evidence_digest = canonical_sha256(
            expected_verification_evidence
        )
        if (
            result_event["verification"]["passed"] is not True
            or not _json_equal(
                result_event["verification"]["evidence"],
                expected_verification_evidence,
            )
            or result_event["verification"]["evidence_digest"]
            != expected_verification_evidence_digest
            or result_event["verification"]["verified_at"]
            != raw_receipt["observed_at"]
        ):
            raise TraceValidationError(
                f"{location}.read verification is not receipt-bound"
            )
        expected_business_succeeded = response["ok"]
        expected_database_finalized = False
        expected_odoo_effect = False
        expected_receipt = {
            "receipt_id": raw_receipt["id"],
            "operation_id": None,
            "capability_id": raw_receipt["capability_id"],
            "release_digest": raw_receipt["release_digest"],
            "registry_digest": raw_receipt["registry_digest"],
            "result_digest": raw_receipt["result_digest"],
            "verification_evidence_digest": (
                expected_verification_evidence_digest
            ),
            "issued_at": raw_receipt["observed_at"],
        }
    expected_operation_id = (
        raw_receipt["operation_id"] if is_write else None
    )
    expected_parameters_sha256 = canonical_sha256(finalized_parameters)
    expected_common = {
        "parameters_sha256": expected_parameters_sha256,
        "operation_id": expected_operation_id,
        "tool_call_id": terminal["tool_call_id"],
        "capability_id": raw_receipt["capability_id"],
        "release_digest": raw_receipt["release_digest"],
        "registry_digest": raw_receipt["registry_digest"],
    }
    for event_name, event in (
        ("odoo_execution", execution),
        ("odoo_result", result_event),
        ("audit_receipt", receipt_event),
    ):
        for field, expected_value in expected_common.items():
            if not _json_equal(event[field], expected_value):
                raise TraceValidationError(
                    f"{location}.{event_name}.{field} is not raw-bound"
                )
    if (
        not _json_equal(result_event["result_body"], raw_result_body)
        or result_event["result_digest"] != raw_receipt["result_digest"]
        or result_event["business_succeeded"]
        is not expected_business_succeeded
        or result_event["database_finalized"]
        is not expected_database_finalized
        or result_event["odoo_effect"] is not expected_odoo_effect
    ):
        raise TraceValidationError(
            f"{location}.odoo_result is not the exact trusted response"
        )
    for field, expected_value in expected_receipt.items():
        if not _json_equal(receipt_event[field], expected_value):
            raise TraceValidationError(
                f"{location}.audit_receipt.{field} is not raw-bound"
            )


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
    expected_package_sha256: str,
    expected_manifest_sha256: str,
    expected_registry_digest: str,
    evidence_trust: PiEvidenceTrust,
    expected_capture_binding: dict[str, Any] | None = None,
) -> dict[str, PiEvidenceSummary]:
    capabilities = validate_corpus(corpus_document, registry_document)
    root = _exact_object(
        trace_document,
        {
            "schema_version",
            "corpus_id",
            "corpus_sha256",
            "registry_digest",
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
    _require_sha256(
        claimed_payload_digest,
        "traces.attestation.signed_payload_sha256",
        TraceValidationError,
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
    digest = _require_sha256(
        root["corpus_sha256"], "traces.corpus_sha256", TraceValidationError
    )
    if digest != canonical_sha256(corpus_document):
        raise TraceValidationError("traces.corpus_sha256 mismatch")
    registry_digest = _require_sha256(
        root["registry_digest"], "traces.registry_digest", TraceValidationError
    )
    observed_registry_digest = capability_registry_digest(
        validate_registry(registry_document)
    )
    _require_sha256(
        expected_registry_digest,
        "expected registry digest",
        TraceValidationError,
    )
    if (
        registry_digest != expected_registry_digest
        or registry_digest != observed_registry_digest
    ):
        raise TraceValidationError("traces.registry_digest mismatch")

    capture = _exact_object(
        root["capture"],
        {
            "source",
            "run_id",
            "captured_at",
            "pi_agent_version",
            "pi_bridge_version",
            "provider",
            "model",
            "system_prompt_sha256",
            "tool_set_sha256",
            "pi_runtime_sha256",
            "v3_manifest_sha256",
            "v3_package_sha256",
        },
        "traces.capture",
        TraceValidationError,
    )
    if capture["source"] != "pi_agent":
        raise TraceValidationError("traces.capture.source must be pi_agent")
    for field in (
        "run_id",
        "pi_agent_version",
        "pi_bridge_version",
        "provider",
        "model",
    ):
        _nonempty_string(
            capture[field],
            f"traces.capture.{field}",
            TraceValidationError,
            maximum=256,
        )
    if not IDENTIFIER.fullmatch(capture["run_id"]):
        raise TraceValidationError("traces.capture.run_id has invalid format")
    for field in (
        "system_prompt_sha256",
        "tool_set_sha256",
        "pi_runtime_sha256",
        "v3_manifest_sha256",
        "v3_package_sha256",
    ):
        _require_sha256(
            capture[field],
            f"traces.capture.{field}",
            TraceValidationError,
        )
    _require_sha256(
        expected_package_sha256,
        "expected package SHA-256",
        TraceValidationError,
    )
    _require_sha256(
        expected_manifest_sha256,
        "expected manifest SHA-256",
        TraceValidationError,
    )
    if not hmac.compare_digest(
        capture["v3_package_sha256"], expected_package_sha256
    ):
        raise TraceValidationError("traces.capture package SHA-256 mismatch")
    if not hmac.compare_digest(
        capture["v3_manifest_sha256"], expected_manifest_sha256
    ):
        raise TraceValidationError("traces.capture manifest SHA-256 mismatch")
    captured_at = _parse_utc(
        capture["captured_at"], "traces.capture.captured_at"
    )
    if (
        type(evidence_trust) is not PiEvidenceTrust
        or evidence_trust.receipt_config.release_digest
        != expected_manifest_sha256
        or evidence_trust.receipt_config.registry_digest
        != expected_registry_digest
        or evidence_trust.release_identity["package_sha256"]
        != expected_package_sha256
    ):
        raise TraceValidationError(
            "trusted Pi evidence route does not match the expected release"
        )
    evidence_verifier = PiEvidenceVerifier(
        evidence_trust,
        utc_clock=lambda: captured_at,
    )
    trusted_summaries: dict[str, PiEvidenceSummary] = {}
    if expected_capture_binding is not None:
        expected_binding = _validate_capture_binding(
            expected_capture_binding,
            "expected_capture_binding",
        )
        actual_binding = {
            field: capture[field] for field in CAPTURE_BINDING_FIELDS
        }
        if actual_binding != expected_binding:
            raise TraceValidationError(
                "traces.capture does not match expected_capture_binding"
            )

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
    seen_write_operation_ids: set[str] = set()
    seen_receipt_ids: set[str] = set()
    seen_tool_call_ids: set[str] = set()
    for index, raw_trace in enumerate(traces):
        location = f"traces.traces[{index}]"
        trace = _exact_object(
            raw_trace,
            {
                "scenario_id",
                "trace_id",
                "started_at",
                "completed_at",
                "events",
                "trusted_evidence",
            },
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
        is_refused = (
            scenario["expected"]["clarification"]["outcome"] == "refused"
        )
        trace_id = _require_identifier(trace["trace_id"], f"{location}.trace_id")
        if trace_id in seen_trace_ids:
            raise TraceValidationError(f"duplicate trace id: {trace_id}")
        seen_trace_ids.add(trace_id)
        started_at = _parse_utc(trace["started_at"], f"{location}.started_at")
        completed_at = _parse_utc(trace["completed_at"], f"{location}.completed_at")
        if completed_at < started_at:
            raise TraceValidationError(f"{location}.completed_at precedes started_at")

        events = trace["events"]
        expected_event_types = (
            REFUSED_EVENT_TYPES
            if is_refused
            else WRITE_EVENT_TYPES
            if is_write
            else READ_EVENT_TYPES
        )
        if not isinstance(events, list) or len(events) != len(expected_event_types):
            raise TraceValidationError(
                f"{location}.events must contain exactly the normalized "
                f"{'refused' if is_refused else 'write' if is_write else 'read'} "
                "Pi events"
            )
        for event_index, (raw_event, expected_type) in enumerate(
            zip(events, expected_event_types), start=1
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
            elif expected_type == "prepare":
                data = _exact_object(
                    event["data"],
                    {
                        "operation_id",
                        "parameters",
                        "operation_digest_input",
                    },
                    data_location,
                    TraceValidationError,
                )
                _require_identifier(
                    data["operation_id"], f"{data_location}.operation_id"
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
                _validate_operation_digest_input(
                    data["operation_digest_input"],
                    f"{data_location}.operation_digest_input",
                )
            elif expected_type == "preview":
                data = _exact_object(
                    event["data"],
                    {
                        "operation_id",
                        "parameters",
                        "parameters_sha256",
                        "preview",
                        "preview_sha256",
                    },
                    data_location,
                    TraceValidationError,
                )
                _require_identifier(
                    data["operation_id"], f"{data_location}.operation_id"
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
                parameters_sha256 = _require_sha256(
                    data["parameters_sha256"],
                    f"{data_location}.parameters_sha256",
                    TraceValidationError,
                )
                if parameters_sha256 != canonical_sha256(data["parameters"]):
                    raise TraceValidationError(
                        f"{data_location}.parameters_sha256 mismatch"
                    )
                _validate_preview_structure(
                    data["preview"],
                    f"{data_location}.preview",
                )
                preview_sha256 = _require_sha256(
                    data["preview_sha256"],
                    f"{data_location}.preview_sha256",
                    TraceValidationError,
                )
                if preview_sha256 != canonical_sha256(data["preview"]):
                    raise TraceValidationError(
                        f"{data_location}.preview_sha256 mismatch"
                    )
            elif expected_type == "approval_binding":
                data = _exact_object(
                    event["data"],
                    {
                        "operation_id",
                        "parameters_sha256",
                        "preview_sha256",
                        "approval_digest",
                        "requester_user_id",
                        "approver_user_id",
                        "approved_at",
                        "expires_at",
                    },
                    data_location,
                    TraceValidationError,
                )
                _require_identifier(
                    data["operation_id"], f"{data_location}.operation_id"
                )
                for field in (
                    "parameters_sha256",
                    "preview_sha256",
                    "approval_digest",
                ):
                    _require_sha256(
                        data[field],
                        f"{data_location}.{field}",
                        TraceValidationError,
                    )
                _require_positive_integer(
                    data["requester_user_id"],
                    f"{data_location}.requester_user_id",
                )
                _require_positive_integer(
                    data["approver_user_id"],
                    f"{data_location}.approver_user_id",
                )
                _parse_utc(data["approved_at"], f"{data_location}.approved_at")
                _parse_utc(data["expires_at"], f"{data_location}.expires_at")
            elif expected_type == "odoo_execution":
                data = _exact_object(
                    event["data"],
                    {
                        "parameters_sha256",
                        "operation_id",
                        "tool_call_id",
                        "capability_id",
                        "release_digest",
                        "registry_digest",
                        "executed_at",
                    },
                    data_location,
                    TraceValidationError,
                )
                _require_operation_reference(
                    data["operation_id"],
                    is_write=is_write,
                    location=f"{data_location}.operation_id",
                )
                _require_identifier(
                    data["tool_call_id"], f"{data_location}.tool_call_id"
                )
                _require_identifier(
                    data["capability_id"], f"{data_location}.capability_id"
                )
                for field in (
                    "parameters_sha256",
                    "release_digest",
                    "registry_digest",
                ):
                    _require_sha256(
                        data[field],
                        f"{data_location}.{field}",
                        TraceValidationError,
                    )
                _parse_utc(data["executed_at"], f"{data_location}.executed_at")
            elif expected_type == "odoo_result":
                data = _exact_object(
                    event["data"],
                    {
                        "parameters_sha256",
                        "operation_id",
                        "tool_call_id",
                        "capability_id",
                        "release_digest",
                        "registry_digest",
                        "result_body",
                        "result_digest",
                        "business_succeeded",
                        "verification",
                        "database_finalized",
                        "odoo_effect",
                    },
                    data_location,
                    TraceValidationError,
                )
                _require_operation_reference(
                    data["operation_id"],
                    is_write=is_write,
                    location=f"{data_location}.operation_id",
                )
                _require_identifier(
                    data["tool_call_id"], f"{data_location}.tool_call_id"
                )
                _require_identifier(
                    data["capability_id"], f"{data_location}.capability_id"
                )
                for field in (
                    "parameters_sha256",
                    "release_digest",
                    "registry_digest",
                    "result_digest",
                ):
                    _require_sha256(
                        data[field],
                        f"{data_location}.{field}",
                        TraceValidationError,
                    )
                if not isinstance(data["result_body"], dict) or not data[
                    "result_body"
                ]:
                    raise TraceValidationError(
                        f"{data_location}.result_body must be a non-empty object"
                    )
                _validate_json_values(
                    data["result_body"],
                    f"{data_location}.result_body",
                    TraceValidationError,
                )
                if data["result_digest"] != canonical_sha256(
                    data["result_body"]
                ):
                    raise TraceValidationError(
                        f"{data_location}.result_digest mismatch"
                    )
                if not isinstance(data["business_succeeded"], bool):
                    raise TraceValidationError(
                        f"{data_location}.business_succeeded must be boolean"
                    )
                if not isinstance(data["database_finalized"], bool):
                    raise TraceValidationError(
                        f"{data_location}.database_finalized must be boolean"
                    )
                if not isinstance(data["odoo_effect"], bool):
                    raise TraceValidationError(
                        f"{data_location}.odoo_effect must be boolean"
                    )
                verification = _exact_object(
                    data["verification"],
                    {
                        "passed",
                        "evidence",
                        "evidence_digest",
                        "verified_at",
                    },
                    f"{data_location}.verification",
                    TraceValidationError,
                )
                if not isinstance(verification["passed"], bool):
                    raise TraceValidationError(
                        f"{data_location}.verification.passed must be boolean"
                    )
                if not isinstance(verification["evidence"], dict) or not verification[
                    "evidence"
                ]:
                    raise TraceValidationError(
                        f"{data_location}.verification.evidence must be a "
                        "non-empty object"
                    )
                _validate_json_values(
                    verification["evidence"],
                    f"{data_location}.verification.evidence",
                    TraceValidationError,
                )
                evidence_digest = _require_sha256(
                    verification["evidence_digest"],
                    f"{data_location}.verification.evidence_digest",
                    TraceValidationError,
                )
                if evidence_digest != canonical_sha256(
                    verification["evidence"]
                ):
                    raise TraceValidationError(
                        f"{data_location}.verification.evidence_digest mismatch"
                    )
                _parse_utc(
                    verification["verified_at"],
                    f"{data_location}.verification.verified_at",
                )
            elif expected_type == "audit_receipt":
                data = _exact_object(
                    event["data"],
                    {
                        "parameters_sha256",
                        "receipt_id",
                        "operation_id",
                        "tool_call_id",
                        "capability_id",
                        "release_digest",
                        "registry_digest",
                        "result_digest",
                        "verification_evidence_digest",
                        "issued_at",
                    },
                    data_location,
                    TraceValidationError,
                )
                _require_identifier(
                    data["receipt_id"], f"{data_location}.receipt_id"
                )
                _require_operation_reference(
                    data["operation_id"],
                    is_write=is_write,
                    location=f"{data_location}.operation_id",
                )
                _require_identifier(
                    data["tool_call_id"], f"{data_location}.tool_call_id"
                )
                _require_identifier(
                    data["capability_id"], f"{data_location}.capability_id"
                )
                for field in (
                    "parameters_sha256",
                    "release_digest",
                    "registry_digest",
                    "result_digest",
                    "verification_evidence_digest",
                ):
                    _require_sha256(
                        data[field],
                        f"{data_location}.{field}",
                        TraceValidationError,
                    )
                _parse_utc(
                    data["issued_at"],
                    f"{data_location}.issued_at",
                )
            elif expected_type == "execution_refused":
                data = _exact_object(
                    event["data"],
                    {
                        "business_succeeded",
                        "write_tool_call_count",
                        "odoo_effect",
                        "operation_id",
                        "receipt_id",
                        "reason",
                    },
                    data_location,
                    TraceValidationError,
                )
                if data["business_succeeded"] is not False:
                    raise TraceValidationError(
                        f"{data_location}.business_succeeded must be false"
                    )
                if (
                    isinstance(data["write_tool_call_count"], bool)
                    or not isinstance(data["write_tool_call_count"], int)
                    or data["write_tool_call_count"] < 0
                ):
                    raise TraceValidationError(
                        f"{data_location}.write_tool_call_count must be a "
                        "non-negative integer"
                    )
                if not isinstance(data["odoo_effect"], bool):
                    raise TraceValidationError(
                        f"{data_location}.odoo_effect must be boolean"
                    )
                for field in ("operation_id", "receipt_id"):
                    value = data[field]
                    if value is not None:
                        _require_identifier(value, f"{data_location}.{field}")
                _nonempty_string(
                    data["reason"],
                    f"{data_location}.reason",
                    TraceValidationError,
                    maximum=512,
                )
            else:
                data = _exact_object(
                    event["data"],
                    {"text"} if is_refused else {"text", "tool_call_id"},
                    data_location,
                    TraceValidationError,
                )
                if not is_refused:
                    _require_identifier(
                        data["tool_call_id"],
                        f"{data_location}.tool_call_id",
                    )
                _parse_assistant_result(
                    data["text"],
                    f"{data_location}.text",
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
        event_data = _events_by_type(trace)
        if is_refused:
            if trace["trusted_evidence"] is not None:
                raise TraceValidationError(
                    f"{location}.trusted_evidence must be null for a refusal"
                )
        else:
            try:
                trusted_summary = evidence_verifier.verify_trusted_evidence(
                    trace["trusted_evidence"],
                    trace_id=trace_id,
                )
            except PiEvidenceError as exc:
                raise TraceValidationError(
                    f"{location}.trusted_evidence rejected: {exc}"
                ) from exc
            expected_kind = "write" if is_write else "read"
            if (
                trusted_summary.kind != expected_kind
                or trusted_summary.capability_id != capability_id
                or trusted_summary.operation_id
                != event_data["odoo_execution"]["operation_id"]
                or trusted_summary.result_digest
                != event_data["odoo_result"]["result_digest"]
            ):
                raise TraceValidationError(
                    f"{location}.trusted_evidence does not match normalized events"
                )
            expected_receipt_id = (
                trusted_summary.write_receipt_id
                if is_write
                else trusted_summary.read_receipt_id
            )
            if expected_receipt_id != event_data["audit_receipt"]["receipt_id"]:
                raise TraceValidationError(
                    f"{location}.trusted_evidence receipt does not match"
                )
            trusted_tool_call = (
                trace["trusted_evidence"]["approve_execute_exchange"]
                if is_write
                else trace["trusted_evidence"]["read_exchange"]
            )["tool_call_id"]
            if trusted_tool_call != event_data["odoo_execution"]["tool_call_id"]:
                raise TraceValidationError(
                    f"{location}.trusted_evidence tool call does not match"
                )
            _validate_trusted_normalized_binding(
                trace=trace,
                event_data=event_data,
                is_write=is_write,
                trace_started_at=started_at,
                trace_completed_at=completed_at,
                captured_at=captured_at,
                finalized_parameters=event_data[
                    "material_parameters_finalized"
                ]["parameters"],
                location=location,
            )
            trusted_summaries[scenario_id] = trusted_summary
        if not is_refused:
            execution = event_data["odoo_execution"]
            receipt = event_data["audit_receipt"]
            tool_call_id = execution["tool_call_id"]
            if tool_call_id in seen_tool_call_ids:
                raise TraceValidationError(
                    f"duplicate cross-trace tool_call_id: {tool_call_id}"
                )
            seen_tool_call_ids.add(tool_call_id)
            receipt_id = receipt["receipt_id"]
            if receipt_id in seen_receipt_ids:
                raise TraceValidationError(
                    f"duplicate cross-trace receipt_id: {receipt_id}"
                )
            seen_receipt_ids.add(receipt_id)
            if is_write:
                operation_id = execution["operation_id"]
                if operation_id in seen_write_operation_ids:
                    raise TraceValidationError(
                        f"duplicate cross-trace write operation_id: {operation_id}"
                    )
                seen_write_operation_ids.add(operation_id)
                _validate_write_preview_binding(
                    prepare=event_data["prepare"],
                    preview_event=event_data["preview"],
                    finalized_parameters=event_data[
                        "material_parameters_finalized"
                    ]["parameters"],
                    capability=capabilities[capability_id],
                    registry_digest=registry_digest,
                    release_digest=capture["v3_manifest_sha256"],
                    location=f"{location}.events.preview",
                )
    return trusted_summaries


def _events_by_type(trace: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {event["type"]: event["data"] for event in trace["events"]}


def _trusted_material_parameters(
    exchange: dict[str, Any],
) -> dict[str, Any]:
    """Return the complete material parameters from a verified real tool route."""

    action = exchange["action"]
    pi_arguments = exchange["pi_arguments"]
    if (
        action == "read"
        and exchange["tool_name"] == "odoo_v3_capability_list"
    ):
        return {
            "company_id": exchange["broker_request"]["context"]["company_id"]
        }
    if action == "operation.diagnostics":
        return {
            "company_id": pi_arguments["company_id"],
            "operation_id": pi_arguments["operation_id"],
        }
    if action == "operation.recover":
        operation_after = exchange["operation_after"]
        if not isinstance(operation_after, dict) or not isinstance(
            operation_after.get("parameters"), dict
        ):
            raise TraceValidationError(
                "trusted recovery exchange has no complete operation parameters"
            )
        return operation_after["parameters"]
    parameters = pi_arguments.get("parameters")
    if not isinstance(parameters, dict):
        raise TraceValidationError(
            "trusted exchange has no complete material parameters"
        )
    return parameters


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
    if denominator == 0:
        return "100.00"
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
    expected_package_sha256: str,
    expected_manifest_sha256: str,
    expected_registry_digest: str,
    evidence_trust: PiEvidenceTrust,
    expected_capture_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate captured evidence and return a deterministic F01-F05 report."""

    trusted_summaries = validate_trace_document(
        trace_document,
        corpus_document,
        registry_document,
        attestation_keys,
        expected_package_sha256=expected_package_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_registry_digest=expected_registry_digest,
        evidence_trust=evidence_trust,
        expected_capture_binding=expected_capture_binding,
    )
    validated_registry_digest = capability_registry_digest(
        validate_registry(registry_document)
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
    f04_failures: dict[str, Any] = {}
    f05_failures: dict[str, Any] = {}
    approval_scenario_ids = {
        scenario["id"]
        for scenario in scenarios
        if access_by_capability[scenario["expected"]["capability_id"]] == "write"
        and scenario["expected"]["clarification"]["outcome"] != "refused"
    }
    execution_scenario_ids = {
        scenario["id"]
        for scenario in scenarios
        if scenario["expected"]["clarification"]["outcome"] != "refused"
    }
    for scenario in scenarios:
        scenario_id = scenario["id"]
        expected = scenario["expected"]
        is_write = access_by_capability[expected["capability_id"]] == "write"
        is_refused = expected["clarification"]["outcome"] == "refused"
        trace = traces.get(scenario_id)
        if trace is None:
            failure = {"reason": "missing_trace"}
            f01_failures[scenario_id] = failure
            f02_failures[scenario_id] = failure
            if scenario_id in execution_scenario_ids:
                f03_failures[scenario_id] = failure
            if scenario_id in approval_scenario_ids:
                f04_failures[scenario_id] = failure
            f05_failures[scenario_id] = failure
            continue
        events = _events_by_type(trace)
        trace_started_at = _parse_utc(
            trace["started_at"], f"{scenario_id}.started_at"
        )
        trace_completed_at = _parse_utc(
            trace["completed_at"], f"{scenario_id}.completed_at"
        )
        selected = events["capability_selected"]["capability_id"]
        clarification = events["clarification_completed"]
        parameters = (
            None
            if is_refused
            else events["material_parameters_finalized"]["parameters"]
        )
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
                except (TypeError, ValueError):
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
        if not is_refused:
            for stage in ("material_parameters_finalized", "cli_input"):
                differences = _different_paths(
                    expected_parameters, events[stage]["parameters"]
                )
                if differences:
                    stage_failures[stage] = {"paths": differences}
            if is_write:
                for stage in ("prepare", "preview"):
                    differences = _different_paths(
                        expected_parameters, events[stage]["parameters"]
                    )
                    if differences:
                        stage_failures[stage] = {"paths": differences}
            trusted_exchange = (
                trace["trusted_evidence"]["prepare_exchange"]
                if is_write
                else trace["trusted_evidence"]["read_exchange"]
            )
            trusted_parameters = _trusted_material_parameters(
                trusted_exchange
            )
            trusted_differences = _different_paths(
                expected_parameters, trusted_parameters
            )
            if trusted_differences:
                stage_failures["trusted_broker_request"] = {
                    "paths": trusted_differences
                }
            expected_parameters_sha256 = canonical_sha256(expected_parameters)
            digest_stages = ["odoo_execution", "odoo_result", "audit_receipt"]
            if is_write:
                digest_stages.extend(("preview", "approval_binding"))
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

        if is_write and not is_refused:
            trusted_summary = trusted_summaries[scenario_id]
            approval = events["approval_binding"]
            preview = events["preview"]
            prepare = events["prepare"]
            execution = events["odoo_execution"]
            approval_issues: dict[str, Any] = {}
            if trusted_summary.authority_signature_verified is not True:
                approval_issues["trusted_approval"] = {
                    "reason": "approval_signature_or_execution_not_verified"
                }
            operation_ids = {
                "prepare": prepare["operation_id"],
                "preview": preview["operation_id"],
                "approval_binding": approval["operation_id"],
                "odoo_execution": execution["operation_id"],
            }
            if len(set(operation_ids.values())) != 1:
                approval_issues["operation_id"] = operation_ids
            expected_parameters_sha256 = canonical_sha256(expected_parameters)
            if approval["parameters_sha256"] != expected_parameters_sha256:
                approval_issues["parameters_sha256"] = {
                    "expected": expected_parameters_sha256,
                    "actual": approval["parameters_sha256"],
                }
            if approval["preview_sha256"] != preview["preview_sha256"]:
                approval_issues["preview_sha256"] = {
                    "expected": preview["preview_sha256"],
                    "actual": approval["preview_sha256"],
                }
            expected_approval_digest = approval_binding_sha256(approval)
            if approval["approval_digest"] != expected_approval_digest:
                approval_issues["approval_digest"] = {
                    "expected": expected_approval_digest,
                    "actual": approval["approval_digest"],
                }
            if approval["requester_user_id"] == approval["approver_user_id"]:
                approval_issues["independent_approver"] = {
                    "requester_user_id": approval["requester_user_id"],
                    "approver_user_id": approval["approver_user_id"],
                }
            approved_at = _parse_utc(
                approval["approved_at"], "approval_binding.approved_at"
            )
            expires_at = _parse_utc(
                approval["expires_at"], "approval_binding.expires_at"
            )
            executed_at = _parse_utc(
                execution["executed_at"], "odoo_execution.executed_at"
            )
            if not (
                trace_started_at
                <= approved_at
                <= executed_at
                <= trace_completed_at
                and executed_at < expires_at
            ):
                approval_issues["approval_window"] = {
                    "trace_started_at": trace["started_at"],
                    "approved_at": approval["approved_at"],
                    "executed_at": execution["executed_at"],
                    "expires_at": approval["expires_at"],
                    "trace_completed_at": trace["completed_at"],
                    "reason": "approval_or_execution_outside_valid_trace_window",
                }
            if approval_issues:
                f04_failures[scenario_id] = {
                    "reason": "approval_invalid",
                    "issues": approval_issues,
                }

        verified_answer_issues: dict[str, Any] = {}
        assistant = events["assistant_final"]
        assistant_result = _parse_assistant_result(
            assistant["text"], f"{scenario_id}.assistant_final.text"
        )
        if is_refused:
            refusal = events["execution_refused"]
            expected_values = {
                "business_succeeded": False,
                "write_tool_call_count": 0,
                "odoo_effect": False,
                "operation_id": None,
                "receipt_id": None,
            }
            for field, expected_value in expected_values.items():
                if refusal[field] != expected_value:
                    verified_answer_issues[f"execution_refused.{field}"] = {
                        "expected": expected_value,
                        "actual": refusal[field],
                    }
            assistant_expected = {
                "status": "refused",
                "business_succeeded": False,
                "operation_id": None,
                "receipt_id": None,
                "result_digest": None,
            }
            for field, expected_value in assistant_expected.items():
                if assistant_result[field] != expected_value:
                    verified_answer_issues[f"assistant_final.{field}"] = {
                        "expected": expected_value,
                        "actual": assistant_result[field],
                    }
        else:
            trusted_summary = trusted_summaries[scenario_id]
            trusted_response = (
                trace["trusted_evidence"]["approve_execute_exchange"]
                if is_write
                else trace["trusted_evidence"]["read_exchange"]
            )["broker_response"]
            execution = events["odoo_execution"]
            result_event = events["odoo_result"]
            receipt_event = events["audit_receipt"]
            expected_parameters_sha256 = canonical_sha256(expected_parameters)
            expected_release = trace_document["capture"]["v3_manifest_sha256"]
            expected_registry = validated_registry_digest
            expected_capability = expected["capability_id"]
            trusted_business_succeeded = (
                trusted_response.get("business_succeeded") is True
                if is_write
                else trusted_response.get("ok") is True
            )
            if not trusted_business_succeeded:
                verified_answer_issues["trusted_business_succeeded"] = {
                    "actual": trusted_business_succeeded,
                    "reason": "trusted_terminal_response_did_not_succeed",
                }
            if result_event["business_succeeded"] is not True:
                verified_answer_issues["business_succeeded"] = {
                    "actual": result_event["business_succeeded"],
                    "reason": "terminal_result_not_business_verified",
                }
            if result_event["verification"]["passed"] is not True:
                verified_answer_issues["verification"] = {
                    "actual": result_event["verification"]["passed"],
                    "reason": "result_verification_not_passed",
                }
            expected_effect = is_write
            if result_event["database_finalized"] is not expected_effect:
                verified_answer_issues["database_finalized"] = {
                    "expected": expected_effect,
                    "actual": result_event["database_finalized"],
                    "reason": "access_mode_database_finalization_mismatch",
                }
            if result_event["odoo_effect"] is not expected_effect:
                verified_answer_issues["odoo_effect"] = {
                    "expected": expected_effect,
                    "actual": result_event["odoo_effect"],
                    "reason": "access_mode_odoo_effect_mismatch",
                }
            for field, expected_value in (
                ("parameters_sha256", expected_parameters_sha256),
                ("capability_id", expected_capability),
                ("release_digest", expected_release),
                ("registry_digest", expected_registry),
            ):
                actual_values = {
                    "odoo_execution": execution[field],
                    "odoo_result": result_event[field],
                    "audit_receipt": receipt_event[field],
                }
                if any(value != expected_value for value in actual_values.values()):
                    verified_answer_issues[field] = {
                        "expected": expected_value,
                        "actual": actual_values,
                    }
            tool_call_ids = {
                "odoo_execution": execution["tool_call_id"],
                "odoo_result": result_event["tool_call_id"],
                "audit_receipt": receipt_event["tool_call_id"],
                "assistant_final": assistant["tool_call_id"],
            }
            if len(set(tool_call_ids.values())) != 1:
                verified_answer_issues["tool_call_id"] = tool_call_ids
            expected_operation_id = (
                execution["operation_id"] if is_write else None
            )
            operation_ids = {
                "odoo_execution": execution["operation_id"],
                "odoo_result": result_event["operation_id"],
                "audit_receipt": receipt_event["operation_id"],
                "assistant_final": assistant_result["operation_id"],
            }
            if any(
                operation_id != expected_operation_id
                for operation_id in operation_ids.values()
            ):
                verified_answer_issues["operation_id"] = {
                    "expected": expected_operation_id,
                    "actual": operation_ids,
                }
            result_digests = {
                "odoo_result": result_event["result_digest"],
                "audit_receipt": receipt_event["result_digest"],
                "assistant_final": assistant_result["result_digest"],
            }
            if len(set(result_digests.values())) != 1:
                verified_answer_issues["result_digest"] = result_digests
            if result_event["result_digest"] != canonical_sha256(
                result_event["result_body"]
            ):
                verified_answer_issues["result_body"] = {
                    "reason": "result_digest_not_recomputable",
                }
            if (
                receipt_event["verification_evidence_digest"]
                != result_event["verification"]["evidence_digest"]
            ):
                verified_answer_issues["verification_evidence_digest"] = {
                    "odoo_result": result_event["verification"]["evidence_digest"],
                    "audit_receipt": receipt_event[
                        "verification_evidence_digest"
                    ],
                }
            if result_event["verification"][
                "evidence_digest"
            ] != canonical_sha256(result_event["verification"]["evidence"]):
                verified_answer_issues["verification_evidence"] = {
                    "reason": "evidence_digest_not_recomputable",
                }
            if assistant_result["receipt_id"] != receipt_event["receipt_id"]:
                verified_answer_issues["receipt_id"] = {
                    "audit_receipt": receipt_event["receipt_id"],
                    "assistant_final": assistant_result["receipt_id"],
                }
            trusted_receipt_id = (
                trusted_summary.write_receipt_id
                if is_write
                else trusted_summary.read_receipt_id
            )
            if (
                assistant_result["receipt_id"] != trusted_receipt_id
                or assistant_result["result_digest"]
                != trusted_summary.result_digest
            ):
                verified_answer_issues["trusted_final_answer_binding"] = {
                    "expected_receipt_id": trusted_receipt_id,
                    "actual_receipt_id": assistant_result["receipt_id"],
                    "expected_result_digest": trusted_summary.result_digest,
                    "actual_result_digest": assistant_result["result_digest"],
                }
            if assistant_result["status"] != "verified_success" or (
                assistant_result["business_succeeded"] is not True
            ):
                verified_answer_issues["assistant_final"] = {
                    "status": assistant_result["status"],
                    "business_succeeded": assistant_result[
                        "business_succeeded"
                    ],
                    "reason": "verified_success_not_reported",
                }
            executed_at = _parse_utc(
                execution["executed_at"], f"{scenario_id}.executed_at"
            )
            verified_at = _parse_utc(
                result_event["verification"]["verified_at"],
                f"{scenario_id}.verified_at",
            )
            receipt_at = _parse_utc(
                receipt_event["issued_at"], f"{scenario_id}.receipt.issued_at"
            )
            timeline = [trace_started_at]
            labels = ["trace_started_at"]
            if is_write:
                timeline.append(
                    _parse_utc(
                        events["approval_binding"]["approved_at"],
                        f"{scenario_id}.approved_at",
                    )
                )
                labels.append("approved_at")
            timeline.extend(
                [executed_at, verified_at, receipt_at, trace_completed_at]
            )
            labels.extend(
                [
                    "executed_at",
                    "verified_at",
                    "receipt_issued_at",
                    "trace_completed_at",
                ]
            )
            if timeline != sorted(timeline):
                verified_answer_issues["event_timeline"] = {
                    "order": labels,
                    "actual": {
                        label: value.isoformat()
                        for label, value in zip(labels, timeline)
                    },
                    "reason": "events_outside_trace_or_out_of_order",
                }
        if verified_answer_issues:
            f05_failures[scenario_id] = {
                "reason": "verified_answer_missing",
                "issues": verified_answer_issues,
            }

    denominator = len(scenarios)
    execution_denominator = len(execution_scenario_ids)
    approval_denominator = len(approval_scenario_ids)
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
            execution_denominator - len(f03_failures),
            execution_denominator,
            COMPLETE_MINIMUM_PERCENT,
            f03_failures,
        ),
        "F04": _gate_report(
            approval_denominator - len(f04_failures),
            approval_denominator,
            COMPLETE_MINIMUM_PERCENT,
            f04_failures,
        ),
        "F05": _gate_report(
            denominator - len(f05_failures),
            denominator,
            VERIFIED_ANSWER_MINIMUM_PERCENT,
            f05_failures,
        ),
    }
    coverage = {
        "captured": len(traces),
        "expected": denominator,
        "passed": not missing,
        "missing_scenario_ids": missing,
    }
    capture_binding_verified = expected_capture_binding is not None
    runtime_evidence_verified = (
        len(trusted_summaries) == execution_denominator
        and all(
            summary.release_digest
            == trace_document["capture"]["v3_manifest_sha256"]
            and summary.registry_digest == validated_registry_digest
            for summary in trusted_summaries.values()
        )
    )
    read_evidence_count = sum(
        summary.kind == "read" for summary in trusted_summaries.values()
    )
    write_evidence_count = sum(
        summary.kind == "write" for summary in trusted_summaries.values()
    )
    return {
        "schema_version": REPORT_SCHEMA,
        "corpus_id": corpus_document["corpus_id"],
        "corpus_sha256": canonical_sha256(corpus_document),
        "registry_digest": validated_registry_digest,
        "run_id": trace_document["capture"]["run_id"],
        "capture": copy.deepcopy(trace_document["capture"]),
        "capture_binding_verified": capture_binding_verified,
        "expected_capture_binding_sha256": (
            canonical_sha256(expected_capture_binding)
            if capture_binding_verified
            else None
        ),
        "attestation": copy.deepcopy(trace_document["attestation"]),
        "attestation_signed_payload_sha256": trace_document["attestation"][
            "signed_payload_sha256"
        ],
        "trace_document_sha256": canonical_sha256(trace_document),
        "trace_coverage": coverage,
        "runtime_evidence": {
            "verified": runtime_evidence_verified,
            "verified_trace_count": len(trusted_summaries),
            "expected_trace_count": execution_denominator,
            "read_exchange_count": read_evidence_count,
            "write_exchange_count": write_evidence_count,
            "write_authority_signature_verified_count": sum(
                summary.kind == "write"
                and summary.authority_signature_verified
                for summary in trusted_summaries.values()
            ),
            "acl_independently_rechecked": False,
        },
        "runtime_evidence_verified": runtime_evidence_verified,
        "gates": gates,
        "acceptance_passed": capture_binding_verified
        and runtime_evidence_verified
        and coverage["passed"]
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


def load_pi_evidence_trust(
    authority_config_path: Path,
    *,
    expected_release_digest: str,
    expected_registry_digest: str,
) -> PiEvidenceTrust:
    """Load receipt and approval trust only through the verified release chain."""

    authority_config = load_trusted_authority_runtime_config(
        authority_config_path,
        require_root_owner=True,
    )
    route = load_verified_release_route(
        authority_config,
        expected_release_digest=expected_release_digest,
        expected_registry_digest=expected_registry_digest,
    )
    return PiEvidenceTrust.from_verified_release(route)


def _parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Score already captured Pi traces against frozen acceptance gates F01-F05; "
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
        "--expected-package-sha256",
        required=True,
        help="trusted canonical V3 package SHA-256 expected for this capture",
    )
    parser.add_argument(
        "--expected-manifest-sha256",
        required=True,
        help="trusted V3 release manifest SHA-256 expected for runtime receipts",
    )
    parser.add_argument(
        "--expected-registry-digest",
        required=True,
        help="trusted validated ordered capability registry digest",
    )
    parser.add_argument(
        "--expected-capture-binding",
        type=Path,
        required=True,
        help=(
            "trusted JSON binding for the exact Pi/Bridge versions, provider, "
            "model, system prompt, tool set, and Pi runtime"
        ),
    )
    parser.add_argument(
        "--trusted-authority-config",
        type=Path,
        required=True,
        help=(
            "root-managed trusted-authority runtime configuration for the "
            "exact retained release; receipt and approval secrets are loaded "
            "through the existing verified-release chain"
        ),
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
        expected_capture_binding = load_json_document(
            args.expected_capture_binding
        )
        evidence_trust = load_pi_evidence_trust(
            args.trusted_authority_config,
            expected_release_digest=args.expected_manifest_sha256,
            expected_registry_digest=args.expected_registry_digest,
        )
        report = score_documents(
            corpus,
            traces,
            registry,
            attestation_keys,
            expected_package_sha256=args.expected_package_sha256,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_registry_digest=args.expected_registry_digest,
            evidence_trust=evidence_trust,
            expected_capture_binding=expected_capture_binding,
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

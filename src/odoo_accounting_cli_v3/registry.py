"""Strict capability registry loading and validation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


CAPABILITY_ID = re.compile(r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$")
XML_ID = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ACCESS = {"read", "write"}
RISKS = {"low", "medium", "high", "critical"}
COMPANY_SCOPES = {"bound_company", "allowed_companies", "explicit_single_company"}
EVIDENCE_LEVELS = {
    "declared",
    "contract_tested",
    "test_verified",
    "sandbox_verified",
    "production_verified",
}
EVIDENCE_KINDS = {
    "accounting_oracle",
    "contract",
    "live_odoo",
    "pi_e2e",
    "recovery",
    "release_identity",
    "sandbox_write_lifecycle",
    "security_negative",
}
PRODUCTION_READ_EVIDENCE = {
    "accounting_oracle",
    "live_odoo",
    "pi_e2e",
    "release_identity",
    "security_negative",
}
PRODUCTION_WRITE_EVIDENCE = PRODUCTION_READ_EVIDENCE | {
    "recovery",
    "sandbox_write_lifecycle",
}
WRITE_IDEMPOTENCY_SCOPES = {
    "company_capability",
    "company_depreciation_move",
    "company_journal_source_digest",
    "company_line_set",
    "company_origin_move",
    "company_origin_operation",
    "company_source_line",
}
REQUIRED_FIELDS = {
    "id",
    "domain",
    "business_description",
    "input_schema",
    "output_schema",
    "access",
    "risk_level",
    "odoo_permissions",
    "company_scope",
    "approval",
    "idempotency",
    "verification",
    "recovery",
    "evidence",
    "enabled_environments",
}
OPTIONAL_FIELDS = {"staged_environments"}


class RegistryError(ValueError):
    """Raised when registry data violates its contract."""


@dataclass(frozen=True)
class Capability:
    _data_json: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Capability":
        return cls(json.dumps(data, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")))

    @property
    def data(self) -> dict[str, Any]:
        """Return a detached copy so validated policy cannot be mutated."""
        return json.loads(self._data_json)

    @property
    def id(self) -> str:
        return self.data["id"]


def _require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{location} must be an object")
    return value


def _require_exact_fields(value: Any, expected: set[str], location: str) -> dict[str, Any]:
    result = _require_object(value, location)
    missing = expected - set(result)
    extra = set(result) - expected
    if missing or extra:
        raise RegistryError(f"{location} fields invalid; missing={sorted(missing)}, extra={sorted(extra)}")
    return result


def _require_nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RegistryError(f"{location} must be a non-empty string")
    return value


def _validate_policy_metadata(item: dict[str, Any], location: str) -> None:
    access = item["access"]
    approval_fields = {"required"} if access == "read" else {"required", "policy", "ttl_seconds"}
    approval = _require_exact_fields(item["approval"], approval_fields, f"{location}.approval")
    expected_approval = access == "write"
    if not isinstance(approval["required"], bool) or approval["required"] is not expected_approval:
        expected = "false" if access == "read" else "true"
        raise RegistryError(f"{location}.approval.required must be {expected}")
    if access == "write":
        _require_nonempty_string(approval["policy"], f"{location}.approval.policy")
        ttl = approval["ttl_seconds"]
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 900:
            raise RegistryError(f"{location}.approval.ttl_seconds must be between 1 and 900")

    idempotency_fields = {"required"} if access == "read" else {"required", "scope"}
    idempotency = _require_exact_fields(item["idempotency"], idempotency_fields, f"{location}.idempotency")
    expected_idempotency = access == "write"
    if not isinstance(idempotency["required"], bool) or idempotency["required"] is not expected_idempotency:
        expected = "false" if access == "read" else "true"
        raise RegistryError(f"{location}.idempotency.required must be {expected}")
    if access == "write" and idempotency["scope"] not in WRITE_IDEMPOTENCY_SCOPES:
        raise RegistryError(f"{location}.idempotency.scope is invalid")

    for field in ("verification", "recovery"):
        value = _require_exact_fields(item[field], {"method"}, f"{location}.{field}")
        _require_nonempty_string(value["method"], f"{location}.{field}.method")


def _validate_evidence(item: dict[str, Any], location: str) -> None:
    evidence = _require_exact_fields(item["evidence"], {"level", "receipts"}, f"{location}.evidence")
    if evidence["level"] not in EVIDENCE_LEVELS:
        raise RegistryError(f"{location}.evidence.level is invalid")
    receipts = evidence["receipts"]
    if not isinstance(receipts, list):
        raise RegistryError(f"{location}.evidence.receipts must be an array")
    receipt_fields = {
        "artifact_sha256",
        "company_id",
        "database_uuid",
        "environment",
        "id",
        "kind",
        "registry_sha256",
        "release_sha256",
        "signature",
        "verified_at",
    }
    kinds: set[str] = set()
    receipt_ids: set[str] = set()
    for index, raw in enumerate(receipts):
        receipt_location = f"{location}.evidence.receipts[{index}]"
        receipt = _require_exact_fields(raw, receipt_fields, receipt_location)
        receipt_id = _require_nonempty_string(receipt["id"], f"{receipt_location}.id")
        if receipt_id in receipt_ids:
            raise RegistryError(f"{location}.evidence contains duplicate receipt id")
        receipt_ids.add(receipt_id)
        kind = receipt["kind"]
        if kind not in EVIDENCE_KINDS:
            raise RegistryError(f"{receipt_location}.kind is invalid")
        kinds.add(kind)
        if receipt["environment"] not in {"test", "sandbox", "production"}:
            raise RegistryError(f"{receipt_location}.environment is invalid")
        company_id = receipt["company_id"]
        if isinstance(company_id, bool) or not isinstance(company_id, int) or company_id <= 0:
            raise RegistryError(f"{receipt_location}.company_id must be positive")
        for field in ("database_uuid", "signature", "verified_at"):
            _require_nonempty_string(receipt[field], f"{receipt_location}.{field}")
        for field in ("artifact_sha256", "registry_sha256", "release_sha256"):
            digest = receipt[field]
            if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                raise RegistryError(f"{receipt_location}.{field} must be lowercase SHA-256")

    environments = set(item["enabled_environments"])
    staged_environments = set(item.get("staged_environments", []))
    if staged_environments:
        if item["evidence"]["level"] == "declared":
            raise RegistryError(
                f"{location} cannot stage execution without contract-tested evidence"
            )
        if staged_environments & environments:
            raise RegistryError(
                f"{location} cannot be staged and enabled in the same environment"
            )
    if "test" in environments:
        if evidence["level"] not in {
            "test_verified",
            "sandbox_verified",
            "production_verified",
        }:
            raise RegistryError(
                f"{location} cannot enable test without test_verified evidence"
            )
        required = (
            PRODUCTION_WRITE_EVIDENCE
            if item["access"] == "write"
            else PRODUCTION_READ_EVIDENCE
        )
        if not required.issubset(kinds):
            raise RegistryError(f"{location} test enablement evidence is incomplete")
    if "sandbox" in environments:
        if evidence["level"] not in {"sandbox_verified", "production_verified"}:
            raise RegistryError(f"{location} cannot enable sandbox without sandbox_verified evidence")
        if item["access"] == "write" and not {"sandbox_write_lifecycle", "recovery", "security_negative"}.issubset(kinds):
            raise RegistryError(f"{location} sandbox write evidence is incomplete")
    if "production" in environments:
        if evidence["level"] != "production_verified":
            raise RegistryError(f"{location} cannot enable production without production_verified evidence")
        required = PRODUCTION_WRITE_EVIDENCE if item["access"] == "write" else PRODUCTION_READ_EVIDENCE
        if not required.issubset(kinds):
            raise RegistryError(f"{location} production evidence is incomplete")


def _validate_json_schema(schema: Any, location: str) -> None:
    value = _require_object(schema, location)
    if value.get("type") != "object":
        raise RegistryError(f"{location}.type must be object")
    if value.get("additionalProperties") is not False:
        raise RegistryError(f"{location}.additionalProperties must be false")
    if not isinstance(value.get("properties"), dict):
        raise RegistryError(f"{location}.properties must be an object")
    required = value.get("required")
    if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
        raise RegistryError(f"{location}.required must be a string array")
    unknown = set(required) - set(value["properties"])
    if unknown:
        raise RegistryError(f"{location}.required references unknown properties: {sorted(unknown)}")
    for name, property_schema in value["properties"].items():
        _validate_schema_node(property_schema, f"{location}.properties.{name}")


def _validate_schema_node(schema: Any, location: str) -> None:
    value = _require_object(schema, location)
    if "oneOf" in value:
        if set(value) != {"oneOf"}:
            raise RegistryError(
                f"{location}.oneOf cannot be combined with other schema keywords"
            )
        alternatives = value["oneOf"]
        if (
            not isinstance(alternatives, list)
            or len(alternatives) < 2
            or any(not isinstance(alternative, dict) for alternative in alternatives)
        ):
            raise RegistryError(
                f"{location}.oneOf must contain at least two schema objects"
            )
        for index, alternative in enumerate(alternatives):
            _validate_schema_node(alternative, f"{location}.oneOf[{index}]")
        return

    declared = value.get("type")
    if declared is None:
        raise RegistryError(f"{location}.type is required")
    types = declared if isinstance(declared, list) else [declared]
    allowed = {"object", "array", "string", "integer", "number", "boolean", "null"}
    if (
        not types
        or any(not isinstance(item, str) or item not in allowed for item in types)
        or len(set(types)) != len(types)
    ):
        raise RegistryError(f"{location}.type is invalid")
    allowed_keywords = {"type", "enum"}
    if "object" in types:
        allowed_keywords |= {"properties", "required", "additionalProperties"}
    if "array" in types:
        allowed_keywords |= {"items", "minItems", "maxItems", "uniqueItems"}
    if {"string"} & set(types):
        allowed_keywords |= {"format", "pattern", "minLength", "maxLength"}
    if {"integer", "number"} & set(types):
        allowed_keywords |= {"minimum", "exclusiveMinimum", "maximum", "exclusiveMaximum"}
    unknown_keywords = set(value) - allowed_keywords
    if unknown_keywords:
        raise RegistryError(f"{location} has unsupported schema keywords: {sorted(unknown_keywords)}")
    if "enum" in value:
        enum = value["enum"]
        if not isinstance(enum, list) or not enum:
            raise RegistryError(f"{location}.enum must be a non-empty array")
    if "object" in types:
        properties = value.get("properties")
        required = value.get("required")
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or len(set(required)) != len(required)
            or any(not isinstance(name, str) or not name for name in required)
        ):
            raise RegistryError(f"{location} object requires properties and required")
        if value.get("additionalProperties") is not False:
            raise RegistryError(f"{location}.additionalProperties must be false")
        if set(required) - set(properties):
            raise RegistryError(f"{location}.required references unknown properties")
        for name, child in properties.items():
            _validate_schema_node(child, f"{location}.properties.{name}")
    if "array" in types:
        if "items" not in value:
            raise RegistryError(f"{location}.items is required for arrays")
        _validate_schema_node(value["items"], f"{location}.items")
        for keyword in ("minItems", "maxItems"):
            if keyword in value and (
                isinstance(value[keyword], bool)
                or not isinstance(value[keyword], int)
                or value[keyword] < 0
            ):
                raise RegistryError(f"{location}.{keyword} must be a non-negative integer")
        if "minItems" in value and "maxItems" in value and value["minItems"] > value["maxItems"]:
            raise RegistryError(f"{location} array bounds are invalid")
        if "uniqueItems" in value and not isinstance(value["uniqueItems"], bool):
            raise RegistryError(f"{location}.uniqueItems must be boolean")
    if "string" in types:
        if "format" in value and value["format"] not in {"date", "date-time"}:
            raise RegistryError(f"{location}.format is unsupported")
        for keyword in ("minLength", "maxLength"):
            if keyword in value and (
                isinstance(value[keyword], bool)
                or not isinstance(value[keyword], int)
                or value[keyword] < 0
            ):
                raise RegistryError(f"{location}.{keyword} must be a non-negative integer")
        if "minLength" in value and "maxLength" in value and value["minLength"] > value["maxLength"]:
            raise RegistryError(f"{location} string bounds are invalid")
        if "pattern" in value:
            if not isinstance(value["pattern"], str):
                raise RegistryError(f"{location}.pattern must be a string")
            try:
                re.compile(value["pattern"])
            except re.error as exc:
                raise RegistryError(f"{location}.pattern is invalid") from exc
    if {"integer", "number"} & set(types):
        for keyword in ("minimum", "exclusiveMinimum", "maximum", "exclusiveMaximum"):
            if keyword in value and (
                isinstance(value[keyword], bool) or not isinstance(value[keyword], (int, float))
            ):
                raise RegistryError(f"{location}.{keyword} must be numeric")


def validate_registry(document: Any) -> tuple[Capability, ...]:
    root = _require_object(document, "registry")
    if root.get("schema_version") != 1:
        raise RegistryError("registry.schema_version must be 1")
    entries = root.get("capabilities")
    if not isinstance(entries, list):
        raise RegistryError("registry.capabilities must be an array")

    seen: set[str] = set()
    capabilities: list[Capability] = []
    for index, raw in enumerate(entries):
        location = f"capabilities[{index}]"
        item = _require_object(raw, location)
        missing = REQUIRED_FIELDS - set(item)
        extra = set(item) - REQUIRED_FIELDS - OPTIONAL_FIELDS
        if missing or extra:
            raise RegistryError(f"{location} fields invalid; missing={sorted(missing)}, extra={sorted(extra)}")
        capability_id = item["id"]
        if not isinstance(capability_id, str) or not CAPABILITY_ID.fullmatch(capability_id):
            raise RegistryError(f"{location}.id has invalid format")
        if capability_id in seen:
            raise RegistryError(f"duplicate capability id: {capability_id}")
        seen.add(capability_id)
        _require_nonempty_string(item["domain"], f"{location}.domain")
        _require_nonempty_string(item["business_description"], f"{location}.business_description")
        _validate_json_schema(item["input_schema"], f"{location}.input_schema")
        _validate_json_schema(item["output_schema"], f"{location}.output_schema")
        if item["access"] not in ACCESS:
            raise RegistryError(f"{location}.access is invalid")
        if item["risk_level"] not in RISKS:
            raise RegistryError(f"{location}.risk_level is invalid")
        permissions = item["odoo_permissions"]
        if (
            not isinstance(permissions, list)
            or not permissions
            or len(set(permissions)) != len(permissions)
            or any(not isinstance(p, str) or not XML_ID.fullmatch(p) for p in permissions)
        ):
            raise RegistryError(f"{location}.odoo_permissions must be a non-empty string array")
        if item["company_scope"] not in COMPANY_SCOPES:
            raise RegistryError(f"{location}.company_scope is invalid")
        environments = item["enabled_environments"]
        if (
            not isinstance(environments, list)
            or len(set(environments)) != len(environments)
            or any(env not in {"test", "sandbox", "production"} for env in environments)
        ):
            raise RegistryError(f"{location}.enabled_environments is invalid")
        staged_environments = item.get("staged_environments", [])
        if (
            not isinstance(staged_environments, list)
            or len(set(staged_environments)) != len(staged_environments)
            or any(env not in {"test", "sandbox"} for env in staged_environments)
        ):
            raise RegistryError(f"{location}.staged_environments is invalid")
        _validate_policy_metadata(item, location)
        _validate_evidence(item, location)
        capabilities.append(Capability.from_dict(item))
    return tuple(capabilities)


def load_registry(path: Path) -> tuple[Capability, ...]:
    with path.open(encoding="utf-8") as stream:
        return validate_registry(json.load(stream))


def registry_digest(capabilities: Iterable[Capability]) -> str:
    """Digest the validated, ordered registry used by operations and releases."""
    document = [capability.data for capability in capabilities]
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

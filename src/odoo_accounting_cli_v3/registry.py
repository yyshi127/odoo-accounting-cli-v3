"""Strict capability registry loading and validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CAPABILITY_ID = re.compile(r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$")
ACCESS = {"read", "write"}
RISKS = {"low", "medium", "high", "critical"}
COMPANY_SCOPES = {"bound_company", "allowed_companies", "explicit_single_company"}
EVIDENCE_LEVELS = {"declared", "contract_tested", "sandbox_verified", "production_verified"}
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


class RegistryError(ValueError):
    """Raised when registry data violates its contract."""


@dataclass(frozen=True)
class Capability:
    data: dict[str, Any]

    @property
    def id(self) -> str:
        return self.data["id"]


def _require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{location} must be an object")
    return value


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
        extra = set(item) - REQUIRED_FIELDS
        if missing or extra:
            raise RegistryError(f"{location} fields invalid; missing={sorted(missing)}, extra={sorted(extra)}")
        capability_id = item["id"]
        if not isinstance(capability_id, str) or not CAPABILITY_ID.fullmatch(capability_id):
            raise RegistryError(f"{location}.id has invalid format")
        if capability_id in seen:
            raise RegistryError(f"duplicate capability id: {capability_id}")
        seen.add(capability_id)
        if not isinstance(item["business_description"], str) or not item["business_description"].strip():
            raise RegistryError(f"{location}.business_description must be non-empty")
        _validate_json_schema(item["input_schema"], f"{location}.input_schema")
        _validate_json_schema(item["output_schema"], f"{location}.output_schema")
        if item["access"] not in ACCESS:
            raise RegistryError(f"{location}.access is invalid")
        if item["risk_level"] not in RISKS:
            raise RegistryError(f"{location}.risk_level is invalid")
        permissions = item["odoo_permissions"]
        if not isinstance(permissions, list) or not permissions or any(not isinstance(p, str) for p in permissions):
            raise RegistryError(f"{location}.odoo_permissions must be a non-empty string array")
        if item["company_scope"] not in COMPANY_SCOPES:
            raise RegistryError(f"{location}.company_scope is invalid")
        for field in ("approval", "idempotency", "verification", "recovery", "evidence"):
            _require_object(item[field], f"{location}.{field}")
        if item["evidence"].get("level") not in EVIDENCE_LEVELS:
            raise RegistryError(f"{location}.evidence.level is invalid")
        environments = item["enabled_environments"]
        if not isinstance(environments, list) or any(env not in {"test", "sandbox", "production"} for env in environments):
            raise RegistryError(f"{location}.enabled_environments is invalid")
        if item["access"] == "write":
            if item["approval"].get("required") is not True:
                raise RegistryError(f"{location} write capability must require approval")
            if item["idempotency"].get("required") is not True:
                raise RegistryError(f"{location} write capability must require idempotency")
            if "production" in environments and item["evidence"].get("level") != "production_verified":
                raise RegistryError(f"{location} cannot enable production without production_verified evidence")
        capabilities.append(Capability(item))
    return tuple(capabilities)


def load_registry(path: Path) -> tuple[Capability, ...]:
    with path.open(encoding="utf-8") as stream:
        return validate_registry(json.load(stream))

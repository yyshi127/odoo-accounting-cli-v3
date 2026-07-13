"""Small strict validator for the registry's supported JSON Schema subset."""

from __future__ import annotations

from datetime import date
from typing import Any


class ContractError(ValueError):
    pass


TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _matches_type(value: Any, kind: str) -> bool:
    expected = TYPE_MAP.get(kind)
    if expected is None:
        raise ContractError(f"unsupported schema type: {kind}")
    if kind in {"integer", "number"} and isinstance(value, bool):
        return False
    return isinstance(value, expected)


def validate_value(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    declared = schema.get("type")
    types = declared if isinstance(declared, list) else [declared]
    if not types or not any(_matches_type(value, kind) for kind in types):
        raise ContractError(f"{path} has invalid type")
    if value is None:
        return
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError(f"{path} is not an allowed value")
    if isinstance(value, str) and schema.get("format") == "date":
        try:
            date.fromisoformat(value)
        except ValueError as exc:
            raise ContractError(f"{path} is not an ISO date") from exc
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ContractError(f"{path} has too few items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                validate_value(item, item_schema, f"{path}[{index}]")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = set(required) - set(value)
        if missing:
            raise ContractError(f"{path} missing required fields: {sorted(missing)}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise ContractError(f"{path} has unknown fields: {sorted(extra)}")
        for key, item in value.items():
            if key in properties:
                validate_value(item, properties[key], f"{path}.{key}")

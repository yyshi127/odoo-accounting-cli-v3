"""Small strict validator for the registry's supported JSON Schema subset."""

from __future__ import annotations

import json
import math
import re
from datetime import date, datetime
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
    if isinstance(value, str):
        if schema.get("format") == "date":
            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise ContractError(f"{path} is not an ISO date") from exc
        if schema.get("format") == "date-time":
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ContractError(f"{path} is not an ISO date-time") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ContractError(f"{path} date-time must include a timezone")
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            raise ContractError(f"{path} does not match the required pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ContractError(f"{path} must be finite")
        if "minimum" in schema and value < schema["minimum"]:
            raise ContractError(f"{path} is below the minimum")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise ContractError(f"{path} must exceed the exclusive minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise ContractError(f"{path} exceeds the maximum")
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            raise ContractError(f"{path} must be below the exclusive maximum")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ContractError(f"{path} is too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ContractError(f"{path} is too long")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ContractError(f"{path} has too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ContractError(f"{path} has too many items")
        if schema.get("uniqueItems"):
            encoded = [
                json.dumps(item, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
                for item in value
            ]
            if len(encoded) != len(set(encoded)):
                raise ContractError(f"{path} contains duplicate items")
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

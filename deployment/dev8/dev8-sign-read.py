#!/usr/bin/python3 -I
"""Create one short-lived dev8 request for an explicitly allowed read capability."""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


RELEASE_ROOT = Path(
    "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev8-bd21ca07c168"
)
RUNTIME_CONFIG = Path("/etc/odoo-accounting-cli-v3/runtime-test-dev8.json")
AUTH_SECRET = Path(
    "/etc/odoo-accounting-cli-v3/secrets/test/dev8-auth.hmac"
)
ALLOWED_CAPABILITIES = frozenset(
    {
        "acct.registry.list.v1",
        "acct.gl.trial_balance.v1",
        "acct.ar.open_items.v1",
        "acct.ap.open_items.v1",
    }
)

sys.path.insert(0, str(RELEASE_ROOT / "src"))

from odoo_accounting_cli_v3.auth import context_payload, sign_request_context  # noqa: E402
from odoo_accounting_cli_v3.contracts import validate_value  # noqa: E402
from odoo_accounting_cli_v3.registry import load_registry  # noqa: E402


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _load_json(text: str) -> object:
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )


def _positive(value: int, name: str) -> int:
    if isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _allowed_companies(value: str) -> frozenset[int]:
    parts = value.split(",")
    if not parts or any(not re.fullmatch(r"[1-9][0-9]*", part) for part in parts):
        raise ValueError("allowed company IDs must be comma-separated positive integers")
    company_ids = tuple(int(part) for part in parts)
    if len(company_ids) != len(set(company_ids)):
        raise ValueError("allowed company IDs must be unique")
    return frozenset(company_ids)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capability-id", choices=sorted(ALLOWED_CAPABILITIES), required=True)
    parser.add_argument("--parameters-json", required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--company-id", type=int, required=True)
    parser.add_argument("--allowed-company-ids", required=True)
    args = parser.parse_args()

    if not args.principal.strip() or any(ord(char) < 32 for char in args.principal):
        raise ValueError("principal must be non-empty and contain no control characters")
    user_id = _positive(args.user_id, "user_id")
    company_id = _positive(args.company_id, "company_id")
    allowed_company_ids = _allowed_companies(args.allowed_company_ids)
    if company_id not in allowed_company_ids:
        raise ValueError("bound company must be present in allowed company IDs")

    parameters = _load_json(args.parameters_json)
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be a JSON object")
    if parameters.get("company_id") != company_id:
        raise ValueError("parameter company_id must equal the authenticated company")

    if not RUNTIME_CONFIG.is_file() or RUNTIME_CONFIG.is_symlink():
        raise ValueError("the exact dev8 runtime configuration is unavailable")
    runtime = _load_json(RUNTIME_CONFIG.read_text(encoding="utf-8"))
    if not isinstance(runtime, dict):
        raise ValueError("the dev8 runtime configuration is invalid")
    expected_runtime = {
        "release_root": str(RELEASE_ROOT),
        "environment": "test",
        "capability_channel": "staged",
        "instance_id": "odoo19@43.165.173.80",
        "database_name": "odoo_test",
        "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        "auth_key_id": "test-auth-2026-07-dev8",
        "auth_secret_path": str(AUTH_SECRET),
        "canonical_package_path": (
            "/opt/odoo-accounting-cli-v3/packages/"
            "odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz"
        ),
        "canonical_package_sha256": (
            "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
        ),
    }
    if any(runtime.get(key) != value for key, value in expected_runtime.items()):
        raise ValueError("the runtime configuration is not the exact staged dev8 binding")
    if not AUTH_SECRET.is_file() or AUTH_SECRET.is_symlink():
        raise ValueError("the exact dev8 authentication secret is unavailable")

    capabilities = {item.id: item for item in load_registry(RELEASE_ROOT / "registry" / "capabilities.json")}
    capability = capabilities[args.capability_id]
    capability_data = capability.data
    if capability_data["access"] != "read" or "test" not in capability_data.get(
        "staged_environments", []
    ):
        raise ValueError("capability is not a staged dev8 read")
    validate_value(parameters, capability_data["input_schema"])

    now = datetime.now(timezone.utc)
    context = sign_request_context(
        auth_token_id=f"dev8-read-{uuid.uuid4()}",
        principal=args.principal,
        odoo_instance_id=runtime["instance_id"],
        database_name=runtime["database_name"],
        database_uuid=runtime["database_uuid"],
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=allowed_company_ids,
        environment=runtime["environment"],
        capability_id=args.capability_id,
        parameters=parameters,
        issued_at=now,
        expires_at=now + timedelta(minutes=4),
        key_id=runtime["auth_key_id"],
        secret=AUTH_SECRET.read_bytes(),
    )
    request = {
        "capability_id": args.capability_id,
        "context": {
            **context_payload(context),
            "auth_signature": context.auth_signature,
        },
        "parameters": parameters,
    }
    print(
        json.dumps(
            request,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()

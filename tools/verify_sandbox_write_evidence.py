"""Verify one sandbox write evidence bundle before registry promotion review.

This verifier is intentionally offline and non-authorizing.  It checks that a
future real-Odoo sandbox write drill has a single capability, company,
database, release, and registry binding before its retained receipts are even
eligible for human promotion review.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


CAPABILITY_ID = re.compile(r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_KINDS = frozenset(
    {
        "accounting_oracle",
        "live_odoo",
        "pi_e2e",
        "recovery",
        "release_identity",
        "sandbox_write_lifecycle",
        "security_negative",
    }
)
LIFECYCLE_FIELDS = frozenset(
    {
        "approval_digest",
        "execution_receipt_id",
        "failure_case_digest",
        "final_audit_receipt_id",
        "idempotency_replay_digest",
        "odoo_record_receipt_id",
        "parameter_roundtrip_sha256",
        "pi_e2e_digest",
        "prepare_receipt_id",
        "preview_digest",
        "recovery_case_digest",
        "security_negative_digest",
        "verification_receipt_id",
    }
)
RECEIPT_FIELDS = frozenset(
    {
        "artifact_sha256",
        "capability_id",
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
)


class SandboxWriteEvidenceError(ValueError):
    """Raised when a sandbox write evidence document is not promotable."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SandboxWriteEvidenceError(f"{label} must be an object")
    return value


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SandboxWriteEvidenceError(f"{label} must be a non-empty string")
    return value


def _require_hex64(value: Any, label: str) -> str:
    text = _require_text(value, label)
    if HEX64.fullmatch(text) is None:
        raise SandboxWriteEvidenceError(f"{label} must be lowercase SHA-256")
    return text


def _require_positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SandboxWriteEvidenceError(f"{label} must be a positive integer")
    return value


def verify_document(document: Any) -> dict[str, Any]:
    root = _require_object(document, "evidence")
    expected_root = {
        "capability_id",
        "company_id",
        "database_uuid",
        "environment",
        "lifecycle",
        "production_promotion_allowed",
        "registry_receipts",
        "release_identity",
        "schema_version",
        "scope",
    }
    if set(root) != expected_root:
        raise SandboxWriteEvidenceError("evidence fields are invalid")
    if root["schema_version"] != 1:
        raise SandboxWriteEvidenceError("evidence.schema_version must be 1")
    if root["scope"] != "odoo-accounting-cli-v3.sandbox-write-evidence.v1":
        raise SandboxWriteEvidenceError("evidence.scope is invalid")
    if root["environment"] != "sandbox":
        raise SandboxWriteEvidenceError("sandbox write evidence must target sandbox")
    if root["production_promotion_allowed"] is not False:
        raise SandboxWriteEvidenceError("sandbox evidence must not authorize production")

    capability_id = _require_text(root["capability_id"], "evidence.capability_id")
    if CAPABILITY_ID.fullmatch(capability_id) is None:
        raise SandboxWriteEvidenceError("evidence.capability_id is invalid")
    company_id = _require_positive_int(root["company_id"], "evidence.company_id")
    database_uuid = _require_text(root["database_uuid"], "evidence.database_uuid")

    release = _require_object(root["release_identity"], "evidence.release_identity")
    if set(release) != {"commit", "manifest_sha256", "package_sha256", "registry_digest", "release"}:
        raise SandboxWriteEvidenceError("release identity fields are invalid")
    _require_text(release["commit"], "release_identity.commit")
    _require_text(release["release"], "release_identity.release")
    manifest_sha256 = _require_hex64(
        release["manifest_sha256"], "release_identity.manifest_sha256"
    )
    registry_digest = _require_hex64(
        release["registry_digest"], "release_identity.registry_digest"
    )
    _require_hex64(release["package_sha256"], "release_identity.package_sha256")

    lifecycle = _require_object(root["lifecycle"], "evidence.lifecycle")
    if set(lifecycle) != LIFECYCLE_FIELDS:
        raise SandboxWriteEvidenceError("lifecycle fields are invalid")
    for field, value in lifecycle.items():
        if field.endswith("_id"):
            _require_text(value, f"lifecycle.{field}")
        else:
            _require_hex64(value, f"lifecycle.{field}")

    receipts = root["registry_receipts"]
    if not isinstance(receipts, list):
        raise SandboxWriteEvidenceError("registry_receipts must be an array")
    seen_ids: set[str] = set()
    seen_kinds: set[str] = set()
    for index, raw_receipt in enumerate(receipts):
        location = f"registry_receipts[{index}]"
        receipt = _require_object(raw_receipt, location)
        if set(receipt) != RECEIPT_FIELDS:
            raise SandboxWriteEvidenceError(f"{location} fields are invalid")
        receipt_id = _require_text(receipt["id"], f"{location}.id")
        if receipt_id in seen_ids:
            raise SandboxWriteEvidenceError("registry receipt ids must be unique")
        seen_ids.add(receipt_id)
        kind = receipt["kind"]
        if kind not in REQUIRED_KINDS:
            raise SandboxWriteEvidenceError(f"{location}.kind is invalid")
        if kind in seen_kinds:
            raise SandboxWriteEvidenceError("registry receipt kinds must be unique")
        seen_kinds.add(kind)
        if receipt["capability_id"] != capability_id:
            raise SandboxWriteEvidenceError(f"{location}.capability_id mismatch")
        if receipt["environment"] != "sandbox":
            raise SandboxWriteEvidenceError(f"{location}.environment mismatch")
        if receipt["company_id"] != company_id:
            raise SandboxWriteEvidenceError(f"{location}.company_id mismatch")
        if receipt["database_uuid"] != database_uuid:
            raise SandboxWriteEvidenceError(f"{location}.database_uuid mismatch")
        if receipt["registry_sha256"] != registry_digest:
            raise SandboxWriteEvidenceError(f"{location}.registry_sha256 mismatch")
        if receipt["release_sha256"] != manifest_sha256:
            raise SandboxWriteEvidenceError(f"{location}.release_sha256 mismatch")
        _require_hex64(receipt["artifact_sha256"], f"{location}.artifact_sha256")
        _require_hex64(receipt["signature"], f"{location}.signature")
        _require_text(receipt["verified_at"], f"{location}.verified_at")

    missing = REQUIRED_KINDS - seen_kinds
    if missing:
        raise SandboxWriteEvidenceError(
            f"registry evidence kinds are incomplete: {sorted(missing)}"
        )

    return {
        "capability_id": capability_id,
        "company_id": company_id,
        "database_uuid": database_uuid,
        "environment": "sandbox",
        "production_promotion_allowed": False,
        "registry_digest": registry_digest,
        "registry_receipt_count": len(receipts),
        "release_sha256": manifest_sha256,
        "verified": True,
    }


def verify_path(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxWriteEvidenceError("evidence JSON is invalid") from exc
    return verify_document(document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_json", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_path(args.evidence_json)
    except SandboxWriteEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

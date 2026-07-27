"""Verify one sandbox write evidence bundle before registry promotion review.

This verifier is intentionally offline and non-authorizing.  It checks that a
future real-Odoo sandbox write drill has a single capability, company,
database, release, and registry binding before its retained receipts are even
eligible for human promotion review.
"""

from __future__ import annotations

import argparse
import hashlib
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
INPUT_SCOPE = "odoo-accounting-cli-v3.sandbox-write-evidence-input.v1"
METADATA_SCOPE = "odoo-accounting-cli-v3.sandbox-write-evidence-metadata.v1"
OUTPUT_SCOPE = "odoo-accounting-cli-v3.sandbox-write-evidence.v1"
PREFLIGHT_SCOPE = "odoo-accounting-cli-v3.sandbox-write-preflight.v1"
PROMOTION_CANDIDATE_SCOPE = "odoo-accounting-cli-v3.write-promotion-candidate.v1"
PROMOTION_REVIEW_SCOPE = "odoo-accounting-cli-v3.write-promotion-review.v1"
DIGEST_LIFECYCLE_FIELDS = frozenset(
    field for field in LIFECYCLE_FIELDS if not field.endswith("_id")
)
ID_LIFECYCLE_FIELDS = LIFECYCLE_FIELDS - DIGEST_LIFECYCLE_FIELDS
DEFAULT_PREFLIGHT_MANIFEST = "preflight_manifest.json"
DEFAULT_LIFECYCLE_ARTIFACTS = {
    field: f"{field}.json" for field in sorted(DIGEST_LIFECYCLE_FIELDS)
}
PREFLIGHT_FIELDS = frozenset(
    {
        "capability_id",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "evidence_root",
        "production_promotion_allowed",
        "readiness_report",
        "readiness_report_sha256",
        "real_odoo_write_performed",
        "registry_digest",
        "release_identity",
        "runtime",
        "schema_version",
        "scope",
        "write_execution_mode",
    }
)
READINESS_FIELDS = frozenset(
    {
        "allowed_models",
        "capability",
        "checks",
        "production_promotion_allowed",
        "real_odoo_write_performed",
        "sandbox_drill_admissible",
    }
)
READINESS_CAPABILITY_FIELDS = frozenset(
    {
        "access",
        "approval",
        "company_scope",
        "enabled_environments",
        "evidence_level",
        "id",
        "idempotency",
        "recovery",
        "risk_level",
        "staged_environments",
    }
)
READINESS_CHECK_FIELDS = frozenset(
    {
        "approval_policy_present",
        "idempotency_policy_present",
        "odoo_handler_supported",
        "production_not_enabled",
        "recovery_method_present",
        "service_allowed_models_present",
        "strict_input_schema",
        "strict_output_schema",
        "write_not_enabled",
        "write_not_staged",
    }
)
PROMOTION_CANDIDATE_FIELDS = frozenset(
    {
        "capability_id",
        "company_id",
        "database_uuid",
        "production_promotion_allowed",
        "release_identity",
        "schema_version",
        "scope",
        "target_channel",
        "target_environment",
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
        "preflight_manifest_sha256",
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
    if root["scope"] != OUTPUT_SCOPE:
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
    preflight_manifest_sha256 = _require_hex64(
        root["preflight_manifest_sha256"], "evidence.preflight_manifest_sha256"
    )

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
    lifecycle_receipt_ids: set[str] = set()
    for field, value in lifecycle.items():
        if field.endswith("_id"):
            receipt_id = _require_text(value, f"lifecycle.{field}")
            if receipt_id in lifecycle_receipt_ids:
                raise SandboxWriteEvidenceError("lifecycle receipt ids must be unique")
            lifecycle_receipt_ids.add(receipt_id)
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
        if receipt_id in lifecycle_receipt_ids:
            raise SandboxWriteEvidenceError(
                "registry receipt ids must be distinct from lifecycle receipt ids"
            )
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
        "preflight_manifest_sha256": preflight_manifest_sha256,
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


def review_promotion_candidate(document: Any, candidate: Any) -> dict[str, Any]:
    evidence = verify_document(document)
    root = _require_object(candidate, "promotion_candidate")
    if set(root) != PROMOTION_CANDIDATE_FIELDS:
        raise SandboxWriteEvidenceError("promotion_candidate fields are invalid")
    if root["schema_version"] != 1:
        raise SandboxWriteEvidenceError("promotion_candidate.schema_version must be 1")
    if root["scope"] != PROMOTION_CANDIDATE_SCOPE:
        raise SandboxWriteEvidenceError("promotion_candidate.scope is invalid")
    if root["capability_id"] != evidence["capability_id"]:
        raise SandboxWriteEvidenceError("promotion_candidate.capability_id mismatch")
    if root["company_id"] != evidence["company_id"]:
        raise SandboxWriteEvidenceError("promotion_candidate.company_id mismatch")
    if root["database_uuid"] != evidence["database_uuid"]:
        raise SandboxWriteEvidenceError("promotion_candidate.database_uuid mismatch")
    if root["target_environment"] != "sandbox":
        raise SandboxWriteEvidenceError(
            "sandbox write evidence cannot authorize production promotion"
        )
    if root["target_channel"] != "staged":
        raise SandboxWriteEvidenceError(
            "sandbox write evidence may only support staged sandbox review"
        )
    if root["production_promotion_allowed"] is not False:
        raise SandboxWriteEvidenceError("promotion_candidate must not authorize production")
    release = _require_object(root["release_identity"], "promotion_candidate.release_identity")
    if set(release) != {"manifest_sha256", "registry_digest"}:
        raise SandboxWriteEvidenceError("promotion_candidate release identity fields are invalid")
    manifest_sha256 = _require_hex64(
        release["manifest_sha256"], "promotion_candidate.release_identity.manifest_sha256"
    )
    registry_digest = _require_hex64(
        release["registry_digest"], "promotion_candidate.release_identity.registry_digest"
    )
    if manifest_sha256 != evidence["release_sha256"]:
        raise SandboxWriteEvidenceError("promotion_candidate release manifest mismatch")
    if registry_digest != evidence["registry_digest"]:
        raise SandboxWriteEvidenceError("promotion_candidate registry digest mismatch")
    return {
        "capability_id": evidence["capability_id"],
        "company_id": evidence["company_id"],
        "database_uuid": evidence["database_uuid"],
        "environment": evidence["environment"],
        "evidence": evidence,
        "preflight_manifest_sha256": evidence["preflight_manifest_sha256"],
        "production_promotion_allowed": False,
        "promotion_allowed": True,
        "registry_digest": evidence["registry_digest"],
        "release_sha256": evidence["release_sha256"],
        "reviewed": True,
        "schema_version": 1,
        "scope": PROMOTION_REVIEW_SCOPE,
        "target_channel": "staged",
        "target_environment": "sandbox",
    }


def review_promotion_candidate_paths(
    evidence_path: Path,
    candidate_path: Path,
) -> dict[str, Any]:
    try:
        document = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxWriteEvidenceError("evidence JSON is invalid") from exc
    try:
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxWriteEvidenceError("promotion candidate JSON is invalid") from exc
    return review_promotion_candidate(document, candidate)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_path(base: Path, value: Any, label: str) -> Path:
    text = _require_text(value, label)
    path = Path(text)
    if not path.is_absolute():
        path = base / path
    resolved = path.resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError as exc:
        raise SandboxWriteEvidenceError(f"{label} escapes the evidence root") from exc
    if not resolved.is_file():
        raise SandboxWriteEvidenceError(f"{label} file is absent")
    return resolved


def _load_json_path(path: Path, label: str) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxWriteEvidenceError(f"{label} JSON is invalid") from exc


def _json_digest(value: Any) -> str:
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SandboxWriteEvidenceError("readiness_report is not canonical JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _validate_preflight_manifest(
    preflight: Any,
    *,
    metadata: dict[str, Any],
) -> None:
    document = _require_object(preflight, "preflight_manifest")
    if set(document) != PREFLIGHT_FIELDS:
        raise SandboxWriteEvidenceError("preflight_manifest fields are invalid")
    if document["schema_version"] != 1:
        raise SandboxWriteEvidenceError("preflight_manifest.schema_version must be 1")
    if document["scope"] != PREFLIGHT_SCOPE:
        raise SandboxWriteEvidenceError("preflight_manifest.scope is invalid")
    if document["environment"] != "sandbox":
        raise SandboxWriteEvidenceError("preflight_manifest must target sandbox")
    if document["production_promotion_allowed"] is not False:
        raise SandboxWriteEvidenceError("preflight_manifest must not authorize production")
    if document["real_odoo_write_performed"] is not False:
        raise SandboxWriteEvidenceError("preflight_manifest must not be a write receipt")
    if document["write_execution_mode"] != "sandbox_staged":
        raise SandboxWriteEvidenceError("preflight_manifest write mode is invalid")
    readiness = _require_object(
        document["readiness_report"], "preflight_manifest.readiness_report"
    )
    if document["readiness_report_sha256"] != _json_digest(readiness):
        raise SandboxWriteEvidenceError("preflight_manifest readiness_report_sha256 mismatch")
    if set(readiness) != READINESS_FIELDS:
        raise SandboxWriteEvidenceError("preflight_manifest readiness_report fields are invalid")
    if readiness.get("sandbox_drill_admissible") is not True:
        raise SandboxWriteEvidenceError("preflight_manifest readiness is not admissible")
    allowed_models = readiness["allowed_models"]
    if (
        not isinstance(allowed_models, list)
        or not allowed_models
        or any(not isinstance(model, str) or not model for model in allowed_models)
        or allowed_models != sorted(set(allowed_models))
    ):
        raise SandboxWriteEvidenceError(
            "preflight_manifest readiness allowed_models are invalid"
        )
    checks = _require_object(
        readiness["checks"], "preflight_manifest.readiness_report.checks"
    )
    if set(checks) != READINESS_CHECK_FIELDS:
        raise SandboxWriteEvidenceError("preflight_manifest readiness checks are invalid")
    if any(value is not True for value in checks.values()):
        raise SandboxWriteEvidenceError(
            "preflight_manifest readiness checks are not all true"
        )
    capability = _require_object(
        readiness.get("capability"), "preflight_manifest.readiness_report.capability"
    )
    if set(capability) != READINESS_CAPABILITY_FIELDS:
        raise SandboxWriteEvidenceError(
            "preflight_manifest readiness capability fields are invalid"
        )
    if capability.get("id") != document["capability_id"]:
        raise SandboxWriteEvidenceError("preflight_manifest readiness capability mismatch")
    if capability.get("access") != "write":
        raise SandboxWriteEvidenceError("preflight_manifest readiness capability is not write")
    if capability.get("enabled_environments") != []:
        raise SandboxWriteEvidenceError("preflight_manifest readiness capability is enabled")
    if capability.get("staged_environments") != []:
        raise SandboxWriteEvidenceError("preflight_manifest readiness capability is staged")
    approval = _require_object(
        capability.get("approval"), "preflight_manifest.readiness_report.capability.approval"
    )
    if approval.get("required") is not True:
        raise SandboxWriteEvidenceError("preflight_manifest readiness approval is not required")
    idempotency = _require_object(
        capability.get("idempotency"),
        "preflight_manifest.readiness_report.capability.idempotency",
    )
    if idempotency.get("required") is not True:
        raise SandboxWriteEvidenceError("preflight_manifest readiness idempotency is not required")
    recovery = _require_object(
        capability.get("recovery"), "preflight_manifest.readiness_report.capability.recovery"
    )
    _require_text(recovery.get("method"), "preflight_manifest readiness recovery.method")
    if readiness.get("production_promotion_allowed") is not False:
        raise SandboxWriteEvidenceError("preflight_manifest readiness must not authorize production")
    if readiness.get("real_odoo_write_performed") is not False:
        raise SandboxWriteEvidenceError("preflight_manifest readiness must be static")
    if document["capability_id"] != metadata["capability_id"]:
        raise SandboxWriteEvidenceError("preflight_manifest capability_id mismatch")
    if document["company_id"] != metadata["company_id"]:
        raise SandboxWriteEvidenceError("preflight_manifest company_id mismatch")
    if document["database_uuid"] != metadata["database_uuid"]:
        raise SandboxWriteEvidenceError("preflight_manifest database_uuid mismatch")
    if document["environment"] != metadata["environment"]:
        raise SandboxWriteEvidenceError("preflight_manifest environment mismatch")
    if document["registry_digest"] != metadata["release_identity"]["registry_digest"]:
        raise SandboxWriteEvidenceError("preflight_manifest registry_digest mismatch")
    release = _require_object(
        document["release_identity"], "preflight_manifest.release_identity"
    )
    if set(release) != {"commit", "manifest_sha256", "package_sha256", "release"}:
        raise SandboxWriteEvidenceError("preflight_manifest release identity fields are invalid")
    expected_release = metadata["release_identity"]
    for field in ("commit", "manifest_sha256", "package_sha256", "release"):
        if release[field] != expected_release[field]:
            raise SandboxWriteEvidenceError(
                f"preflight_manifest release_identity.{field} mismatch"
            )
    runtime = _require_object(document["runtime"], "preflight_manifest.runtime")
    for field in ("database_uuid", "environment", "write_execution_mode"):
        if runtime.get(field) != document[field]:
            raise SandboxWriteEvidenceError(f"preflight_manifest runtime.{field} mismatch")


def assemble_document(manifest: Any, *, base_dir: Path) -> dict[str, Any]:
    root = _require_object(manifest, "input")
    expected_root = {
        "capability_id",
        "company_id",
        "database_uuid",
        "environment",
        "lifecycle_artifacts",
        "lifecycle_receipt_ids",
        "preflight_manifest",
        "production_promotion_allowed",
        "registry_receipts",
        "release_identity",
        "schema_version",
        "scope",
    }
    if set(root) != expected_root:
        raise SandboxWriteEvidenceError("input fields are invalid")
    if root["schema_version"] != 1:
        raise SandboxWriteEvidenceError("input.schema_version must be 1")
    if root["scope"] != INPUT_SCOPE:
        raise SandboxWriteEvidenceError("input.scope is invalid")
    if root["environment"] != "sandbox":
        raise SandboxWriteEvidenceError("input must target sandbox")
    if root["production_promotion_allowed"] is not False:
        raise SandboxWriteEvidenceError("input must not authorize production")

    artifacts = _require_object(root["lifecycle_artifacts"], "input.lifecycle_artifacts")
    receipt_ids = _require_object(
        root["lifecycle_receipt_ids"], "input.lifecycle_receipt_ids"
    )
    if set(artifacts) != DIGEST_LIFECYCLE_FIELDS:
        raise SandboxWriteEvidenceError("lifecycle artifact fields are invalid")
    if set(receipt_ids) != ID_LIFECYCLE_FIELDS:
        raise SandboxWriteEvidenceError("lifecycle receipt id fields are invalid")
    preflight_path = _source_path(
        base_dir, root["preflight_manifest"], "input.preflight_manifest"
    )
    _validate_preflight_manifest(
        _load_json_path(preflight_path, "preflight_manifest"),
        metadata=root,
    )
    preflight_manifest_sha256 = _sha256_file(preflight_path)

    lifecycle: dict[str, str] = {}
    for field in sorted(DIGEST_LIFECYCLE_FIELDS):
        lifecycle[field] = _sha256_file(
            _source_path(base_dir, artifacts[field], f"lifecycle_artifacts.{field}")
        )
    for field in sorted(ID_LIFECYCLE_FIELDS):
        lifecycle[field] = _require_text(receipt_ids[field], f"lifecycle_receipt_ids.{field}")

    document = {
        "schema_version": 1,
        "scope": OUTPUT_SCOPE,
        "capability_id": root["capability_id"],
        "company_id": root["company_id"],
        "database_uuid": root["database_uuid"],
        "environment": root["environment"],
        "preflight_manifest_sha256": preflight_manifest_sha256,
        "production_promotion_allowed": False,
        "release_identity": root["release_identity"],
        "lifecycle": lifecycle,
        "registry_receipts": root["registry_receipts"],
    }
    verify_document(document)
    return document


def assemble_path(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxWriteEvidenceError("input JSON is invalid") from exc
    return assemble_document(manifest, base_dir=path.parent)


def build_input_manifest(metadata: Any, *, base_dir: Path) -> dict[str, Any]:
    root = _require_object(metadata, "metadata")
    expected_root = {
        "capability_id",
        "company_id",
        "database_uuid",
        "environment",
        "lifecycle_receipt_ids",
        "production_promotion_allowed",
        "registry_receipts",
        "release_identity",
        "schema_version",
        "scope",
    }
    if set(root) != expected_root:
        raise SandboxWriteEvidenceError("metadata fields are invalid")
    if root["schema_version"] != 1:
        raise SandboxWriteEvidenceError("metadata.schema_version must be 1")
    if root["scope"] != METADATA_SCOPE:
        raise SandboxWriteEvidenceError("metadata.scope is invalid")
    if root["environment"] != "sandbox":
        raise SandboxWriteEvidenceError("metadata must target sandbox")
    if root["production_promotion_allowed"] is not False:
        raise SandboxWriteEvidenceError("metadata must not authorize production")

    manifest = {
        "schema_version": 1,
        "scope": INPUT_SCOPE,
        "capability_id": root["capability_id"],
        "company_id": root["company_id"],
        "database_uuid": root["database_uuid"],
        "environment": root["environment"],
        "preflight_manifest": DEFAULT_PREFLIGHT_MANIFEST,
        "production_promotion_allowed": False,
        "release_identity": root["release_identity"],
        "lifecycle_artifacts": dict(DEFAULT_LIFECYCLE_ARTIFACTS),
        "lifecycle_receipt_ids": root["lifecycle_receipt_ids"],
        "registry_receipts": root["registry_receipts"],
    }
    assemble_document(manifest, base_dir=base_dir)
    return manifest


def build_input_manifest_path(path: Path) -> dict[str, Any]:
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxWriteEvidenceError("metadata JSON is invalid") from exc
    return build_input_manifest(metadata, base_dir=path.parent)


def inspect_retained_root(metadata: Any, *, base_dir: Path) -> dict[str, Any]:
    manifest = build_input_manifest(metadata, base_dir=base_dir)
    document = assemble_document(manifest, base_dir=base_dir)
    evidence = verify_document(document)
    return {
        "artifact_sha256": {
            field: _sha256_file(
                _source_path(
                    base_dir,
                    manifest["lifecycle_artifacts"][field],
                    f"lifecycle_artifacts.{field}",
                )
            )
            for field in sorted(DIGEST_LIFECYCLE_FIELDS)
        },
        "database_uuid": evidence["database_uuid"],
        "environment": evidence["environment"],
        "input_manifest": manifest,
        "preflight_manifest_sha256": document["preflight_manifest_sha256"],
        "production_promotion_allowed": False,
        "registry_digest": evidence["registry_digest"],
        "registry_receipt_count": evidence["registry_receipt_count"],
        "release_sha256": evidence["release_sha256"],
        "verified": True,
    }


def inspect_retained_root_path(path: Path) -> dict[str, Any]:
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SandboxWriteEvidenceError("metadata JSON is invalid") from exc
    result = inspect_retained_root(metadata, base_dir=path.parent)
    result["metadata_sha256"] = _sha256_file(path)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_json", nargs="?", type=Path)
    parser.add_argument(
        "--assemble-from",
        type=Path,
        help="Build and verify a sandbox write evidence JSON from an input manifest.",
    )
    parser.add_argument(
        "--build-input-from",
        type=Path,
        help="Build a sandbox-write evidence input manifest from standard retained artifacts and metadata.",
    )
    parser.add_argument(
        "--inspect-root",
        type=Path,
        help="Inspect standard retained sandbox-write artifacts and print their verified completeness report.",
    )
    parser.add_argument(
        "--review-promotion-from",
        type=Path,
        help="Verify a sandbox-write evidence JSON against a non-authorizing promotion candidate.",
    )
    parser.add_argument(
        "--promotion-candidate",
        type=Path,
        help="Promotion candidate JSON to review with --review-promotion-from.",
    )
    args = parser.parse_args(argv)
    try:
        selected = sum(
            item is not None
            for item in (
                args.evidence_json,
                args.assemble_from,
                args.build_input_from,
                args.inspect_root,
                args.review_promotion_from,
            )
        )
        if selected != 1:
            parser.error(
                "provide exactly one of evidence_json, --assemble-from, --build-input-from, --inspect-root, or --review-promotion-from"
            )
        if args.review_promotion_from is not None:
            if args.promotion_candidate is None:
                parser.error("--promotion-candidate is required with --review-promotion-from")
            result = review_promotion_candidate_paths(
                args.review_promotion_from,
                args.promotion_candidate,
            )
        elif args.promotion_candidate is not None:
            parser.error("--promotion-candidate requires --review-promotion-from")
        elif args.inspect_root is not None:
            result = inspect_retained_root_path(args.inspect_root)
        elif args.build_input_from is not None:
            result = build_input_manifest_path(args.build_input_from)
        elif args.assemble_from is not None:
            result = assemble_path(args.assemble_from)
        else:
            result = verify_path(args.evidence_json)
    except SandboxWriteEvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

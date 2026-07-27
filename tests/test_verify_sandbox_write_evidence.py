from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_sandbox_write_evidence",
    ROOT / "tools" / "verify_sandbox_write_evidence.py",
)
verifier = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(verifier)


KINDS = (
    "accounting_oracle",
    "live_odoo",
    "pi_e2e",
    "recovery",
    "release_identity",
    "sandbox_write_lifecycle",
    "security_negative",
)


def _receipt(kind: str, *, capability_id: str = "acct.invoice.customer_create.v1"):
    return {
        "artifact_sha256": "a" * 64,
        "capability_id": capability_id,
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "id": f"receipt-{kind}",
        "kind": kind,
        "registry_sha256": "b" * 64,
        "release_sha256": "c" * 64,
        "signature": "d" * 64,
        "verified_at": "2026-07-27T00:00:00Z",
    }


def _document():
    return {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.sandbox-write-evidence.v1",
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "preflight_manifest_sha256": "9" * 64,
        "production_promotion_allowed": False,
        "release_identity": {
            "commit": "abc123",
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev160-abc123",
        },
        "lifecycle": {
            "approval_digest": "1" * 64,
            "execution_receipt_id": "execution-receipt",
            "failure_case_digest": "2" * 64,
            "final_audit_receipt_id": "audit-receipt",
            "idempotency_replay_digest": "3" * 64,
            "odoo_record_receipt_id": "odoo-record-receipt",
            "parameter_roundtrip_sha256": "4" * 64,
            "pi_e2e_digest": "5" * 64,
            "prepare_receipt_id": "prepare-receipt",
            "preview_digest": "6" * 64,
            "recovery_case_digest": "7" * 64,
            "security_negative_digest": "8" * 64,
            "verification_receipt_id": "verification-receipt",
        },
        "registry_receipts": [_receipt(kind) for kind in KINDS],
    }


def test_complete_sandbox_write_evidence_is_accepted():
    result = verifier.verify_document(_document())

    assert result == {
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "production_promotion_allowed": False,
        "preflight_manifest_sha256": "9" * 64,
        "registry_digest": "b" * 64,
        "registry_receipt_count": 7,
        "release_sha256": "c" * 64,
        "verified": True,
    }


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (
            lambda document: document.__setitem__(
                "production_promotion_allowed", True
            ),
            "must not authorize production",
        ),
        (
            lambda document: document["registry_receipts"].pop(),
            "registry evidence kinds are incomplete",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "capability_id", "acct.bill.vendor_create.v1"
            ),
            "capability_id mismatch",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "registry_sha256", "f" * 64
            ),
            "registry_sha256 mismatch",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "release_sha256", "f" * 64
            ),
            "release_sha256 mismatch",
        ),
        (
            lambda document: document["lifecycle"].pop("recovery_case_digest"),
            "lifecycle fields are invalid",
        ),
        (
            lambda document: document.__setitem__("preflight_manifest_sha256", "X"),
            "preflight_manifest_sha256 must be lowercase SHA-256",
        ),
    ),
)
def test_sandbox_write_evidence_rejects_non_promotable_bundles(mutate, match):
    document = copy.deepcopy(_document())
    mutate(document)

    with pytest.raises(verifier.SandboxWriteEvidenceError, match=match):
        verifier.verify_document(document)


def test_cli_returns_nonzero_for_invalid_evidence(tmp_path, capsys):
    path = tmp_path / "evidence.json"
    path.write_text('{"schema_version":1}', encoding="utf-8")

    assert verifier.main([str(path)]) == 1
    assert "evidence fields are invalid" in capsys.readouterr().err


def _write_lifecycle_artifacts(tmp_path: Path) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for field in sorted(verifier.DIGEST_LIFECYCLE_FIELDS):
        path = tmp_path / f"{field}.json"
        path.write_text(
            json.dumps({"artifact": field}, sort_keys=True),
            encoding="utf-8",
        )
        artifacts[field] = path.name
    return artifacts


def _input_manifest(tmp_path: Path):
    return {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.sandbox-write-evidence-input.v1",
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "preflight_manifest_sha256": "9" * 64,
        "production_promotion_allowed": False,
        "release_identity": {
            "commit": "abc123",
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev162-abc123",
        },
        "lifecycle_artifacts": _write_lifecycle_artifacts(tmp_path),
        "lifecycle_receipt_ids": {
            "execution_receipt_id": "execution-receipt",
            "final_audit_receipt_id": "audit-receipt",
            "odoo_record_receipt_id": "odoo-record-receipt",
            "prepare_receipt_id": "prepare-receipt",
            "verification_receipt_id": "verification-receipt",
        },
        "registry_receipts": [_receipt(kind) for kind in KINDS],
    }


def test_assembler_builds_verified_evidence_from_retained_artifact_files(tmp_path):
    manifest = _input_manifest(tmp_path)
    document = verifier.assemble_document(manifest, base_dir=tmp_path)

    assert verifier.verify_document(document)["verified"] is True
    assert document["preflight_manifest_sha256"] == "9" * 64
    for field, relative_path in manifest["lifecycle_artifacts"].items():
        artifact = tmp_path / relative_path
        assert document["lifecycle"][field] == hashlib.sha256(
            artifact.read_bytes()
        ).hexdigest()


def test_assembler_cli_prints_verified_evidence_document(tmp_path, capsys):
    path = tmp_path / "input.json"
    path.write_text(json.dumps(_input_manifest(tmp_path)), encoding="utf-8")

    assert verifier.main(["--assemble-from", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["scope"] == "odoo-accounting-cli-v3.sandbox-write-evidence.v1"
    assert output["lifecycle"]["prepare_receipt_id"] == "prepare-receipt"
    assert verifier.verify_document(output)["registry_receipt_count"] == 7


def test_assembler_rejects_artifact_paths_that_escape_evidence_root(tmp_path):
    manifest = _input_manifest(tmp_path)
    manifest["lifecycle_artifacts"]["pi_e2e_digest"] = "../outside.json"

    with pytest.raises(verifier.SandboxWriteEvidenceError, match="escapes"):
        verifier.assemble_document(manifest, base_dir=tmp_path)

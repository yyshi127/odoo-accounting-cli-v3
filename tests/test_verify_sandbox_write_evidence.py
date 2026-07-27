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


def _promotion_candidate():
    return {
        "schema_version": 1,
        "scope": verifier.PROMOTION_CANDIDATE_SCOPE,
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "production_promotion_allowed": False,
        "release_identity": {
            "manifest_sha256": "c" * 64,
            "registry_digest": "b" * 64,
        },
        "target_channel": "staged",
        "target_environment": "sandbox",
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


def test_sandbox_write_evidence_supports_staged_sandbox_promotion_review():
    result = verifier.review_promotion_candidate(_document(), _promotion_candidate())

    assert result["scope"] == verifier.PROMOTION_REVIEW_SCOPE
    assert result["reviewed"] is True
    assert result["promotion_allowed"] is True
    assert result["production_promotion_allowed"] is False
    assert result["target_environment"] == "sandbox"
    assert result["target_channel"] == "staged"
    assert result["evidence"]["verified"] is True


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (
            lambda candidate: candidate.__setitem__("target_environment", "production"),
            "cannot authorize production promotion",
        ),
        (
            lambda candidate: candidate.__setitem__("target_channel", "enabled"),
            "only support staged sandbox review",
        ),
        (
            lambda candidate: candidate.__setitem__(
                "capability_id", "acct.bill.vendor_create.v1"
            ),
            "capability_id mismatch",
        ),
        (
            lambda candidate: candidate.__setitem__("company_id", 8),
            "company_id mismatch",
        ),
        (
            lambda candidate: candidate["release_identity"].__setitem__(
                "manifest_sha256", "f" * 64
            ),
            "release manifest mismatch",
        ),
        (
            lambda candidate: candidate["release_identity"].__setitem__(
                "registry_digest", "f" * 64
            ),
            "registry digest mismatch",
        ),
        (
            lambda candidate: candidate.__setitem__("production_promotion_allowed", True),
            "must not authorize production",
        ),
    ),
)
def test_promotion_review_rejects_unsafe_or_unbound_candidates(mutate, match):
    candidate = copy.deepcopy(_promotion_candidate())
    mutate(candidate)

    with pytest.raises(verifier.SandboxWriteEvidenceError, match=match):
        verifier.review_promotion_candidate(_document(), candidate)


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
            lambda document: document["lifecycle"].__setitem__(
                "verification_receipt_id",
                document["lifecycle"]["execution_receipt_id"],
            ),
            "lifecycle receipt ids must be unique",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "id", document["lifecycle"]["final_audit_receipt_id"]
            ),
            "distinct from lifecycle receipt ids",
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


def _write_preflight_manifest(tmp_path: Path) -> str:
    path = tmp_path / "preflight_manifest.json"
    readiness_report = {
        "allowed_models": ["account.move", "account.move.line"],
        "capability": {
            "access": "write",
            "approval": {"policy": "invoice_write", "required": True, "ttl_seconds": 900},
            "company_scope": "explicit_single_company",
            "enabled_environments": [],
            "evidence_level": "declared",
            "id": "acct.invoice.customer_create.v1",
            "idempotency": {"required": True, "scope": "company_capability"},
            "recovery": {
                "method": "manual_escalation_until_exact_invoice_compensation_is_sandbox_verified"
            },
            "risk_level": "high",
            "staged_environments": [],
        },
        "checks": {
            "approval_policy_present": True,
            "idempotency_policy_present": True,
            "odoo_handler_supported": True,
            "production_not_enabled": True,
            "recovery_method_present": True,
            "service_allowed_models_present": True,
            "strict_input_schema": True,
            "strict_output_schema": True,
            "write_not_enabled": True,
            "write_not_staged": True,
        },
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "sandbox_drill_admissible": True,
    }
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "scope": verifier.PREFLIGHT_SCOPE,
                "capability_id": "acct.invoice.customer_create.v1",
                "company_id": 7,
                "database_name": "odoo_v3_sandbox",
                "database_uuid": "11111111-1111-4111-8111-111111111111",
                "environment": "sandbox",
                "evidence_root": {
                    "available_bytes": 9_000_000_000,
                    "minimum_free_bytes": 8_589_934_592,
                    "path": str(tmp_path),
                },
                "production_promotion_allowed": False,
                "readiness_report": readiness_report,
                "readiness_report_sha256": hashlib.sha256(
                    json.dumps(
                        readiness_report,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
                "real_odoo_write_performed": False,
                "registry_digest": "b" * 64,
                "release_identity": {
                    "commit": "abc123",
                    "manifest_sha256": "c" * 64,
                    "package_sha256": "e" * 64,
                    "release": "0.1.0.dev162-abc123",
                },
                "runtime": {
                    "database_uuid": "11111111-1111-4111-8111-111111111111",
                    "environment": "sandbox",
                    "write_execution_mode": "sandbox_staged",
                },
                "write_execution_mode": "sandbox_staged",
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path.name


def _refresh_preflight_readiness_digest(preflight: dict) -> None:
    preflight["readiness_report_sha256"] = hashlib.sha256(
        json.dumps(
            preflight["readiness_report"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _input_manifest(tmp_path: Path):
    return {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.sandbox-write-evidence-input.v1",
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "preflight_manifest": _write_preflight_manifest(tmp_path),
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


def _metadata(tmp_path: Path):
    manifest = _input_manifest(tmp_path)
    return {
        "schema_version": 1,
        "scope": verifier.METADATA_SCOPE,
        "capability_id": manifest["capability_id"],
        "company_id": manifest["company_id"],
        "database_uuid": manifest["database_uuid"],
        "environment": manifest["environment"],
        "production_promotion_allowed": False,
        "release_identity": manifest["release_identity"],
        "lifecycle_receipt_ids": manifest["lifecycle_receipt_ids"],
        "registry_receipts": manifest["registry_receipts"],
    }


def test_assembler_builds_verified_evidence_from_retained_artifact_files(tmp_path):
    manifest = _input_manifest(tmp_path)
    document = verifier.assemble_document(manifest, base_dir=tmp_path)

    assert verifier.verify_document(document)["verified"] is True
    assert document["preflight_manifest_sha256"] == hashlib.sha256(
        (tmp_path / manifest["preflight_manifest"]).read_bytes()
    ).hexdigest()
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


def test_builder_creates_input_manifest_from_standard_retained_files(tmp_path):
    manifest = verifier.build_input_manifest(_metadata(tmp_path), base_dir=tmp_path)

    assert manifest["scope"] == verifier.INPUT_SCOPE
    assert manifest["preflight_manifest"] == "preflight_manifest.json"
    assert manifest["lifecycle_artifacts"] == verifier.DEFAULT_LIFECYCLE_ARTIFACTS
    evidence = verifier.assemble_document(manifest, base_dir=tmp_path)
    assert verifier.verify_document(evidence)["preflight_manifest_sha256"] == hashlib.sha256(
        (tmp_path / "preflight_manifest.json").read_bytes()
    ).hexdigest()


def test_builder_cli_prints_verified_input_manifest(tmp_path, capsys):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(_metadata(tmp_path)), encoding="utf-8")

    assert verifier.main(["--build-input-from", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["scope"] == verifier.INPUT_SCOPE
    assert output["lifecycle_artifacts"]["preview_digest"] == "preview_digest.json"
    assert verifier.verify_document(
        verifier.assemble_document(output, base_dir=tmp_path)
    )["verified"] is True


def test_inspector_reports_standard_root_hashes(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(_metadata(tmp_path)), encoding="utf-8")

    report = verifier.inspect_retained_root_path(path)

    assert report["verified"] is True
    assert report["metadata_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert report["preflight_manifest_sha256"] == hashlib.sha256(
        (tmp_path / "preflight_manifest.json").read_bytes()
    ).hexdigest()
    assert set(report["artifact_sha256"]) == verifier.DIGEST_LIFECYCLE_FIELDS
    assert report["artifact_sha256"]["preview_digest"] == hashlib.sha256(
        (tmp_path / "preview_digest.json").read_bytes()
    ).hexdigest()
    assert report["input_manifest"]["lifecycle_artifacts"] == (
        verifier.DEFAULT_LIFECYCLE_ARTIFACTS
    )


def test_inspector_cli_prints_completeness_report(tmp_path, capsys):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(_metadata(tmp_path)), encoding="utf-8")

    assert verifier.main(["--inspect-root", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["verified"] is True
    assert output["registry_receipt_count"] == 7
    assert output["artifact_sha256"]["approval_digest"] == hashlib.sha256(
        (tmp_path / "approval_digest.json").read_bytes()
    ).hexdigest()


def test_builder_rejects_missing_standard_artifacts(tmp_path):
    metadata = _metadata(tmp_path)
    (tmp_path / "preview_digest.json").unlink()

    with pytest.raises(verifier.SandboxWriteEvidenceError, match="file is absent"):
        verifier.build_input_manifest(metadata, base_dir=tmp_path)


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (
            lambda preflight: preflight.__setitem__(
                "capability_id", "acct.bill.vendor_create.v1"
            ),
            "readiness capability mismatch",
        ),
        (
            lambda preflight: preflight.__setitem__("company_id", 8),
            "company_id mismatch",
        ),
        (
            lambda preflight: preflight.__setitem__(
                "database_uuid", "22222222-2222-4222-8222-222222222222"
            ),
            "database_uuid mismatch",
        ),
        (
            lambda preflight: preflight.__setitem__("registry_digest", "f" * 64),
            "registry_digest mismatch",
        ),
        (
            lambda preflight: preflight["release_identity"].__setitem__(
                "manifest_sha256", "f" * 64
            ),
            "release_identity.manifest_sha256 mismatch",
        ),
        (
            lambda preflight: preflight.__setitem__(
                "real_odoo_write_performed", True
            ),
            "must not be a write receipt",
        ),
        (
            lambda preflight: preflight.__setitem__(
                "readiness_report_sha256", "f" * 64
            ),
            "readiness_report_sha256 mismatch",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"].__setitem__(
                    "sandbox_drill_admissible", False
                ),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness is not admissible",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"].pop("allowed_models"),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness_report fields are invalid",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"]["allowed_models"].append("account.move"),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness allowed_models are invalid",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"]["checks"].__setitem__(
                    "odoo_handler_supported", False
                ),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness checks are not all true",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"]["capability"].pop("approval"),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness capability fields are invalid",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"]["capability"].__setitem__(
                    "enabled_environments", ["sandbox"]
                ),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness capability is enabled",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"]["capability"].__setitem__(
                    "staged_environments", ["sandbox"]
                ),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness capability is staged",
        ),
        (
            lambda preflight: (
                preflight["readiness_report"]["checks"].__setitem__(
                    "write_not_staged", False
                ),
                _refresh_preflight_readiness_digest(preflight),
            ),
            "readiness checks are not all true",
        ),
    ),
)
def test_builder_rejects_preflight_manifest_scope_mismatches(
    tmp_path, mutate, match
):
    metadata = _metadata(tmp_path)
    path = tmp_path / "preflight_manifest.json"
    preflight = json.loads(path.read_text(encoding="utf-8"))
    mutate(preflight)
    path.write_text(json.dumps(preflight, sort_keys=True), encoding="utf-8")

    with pytest.raises(verifier.SandboxWriteEvidenceError, match=match):
        verifier.build_input_manifest(metadata, base_dir=tmp_path)


def test_assembler_rejects_artifact_paths_that_escape_evidence_root(tmp_path):
    manifest = _input_manifest(tmp_path)
    manifest["lifecycle_artifacts"]["pi_e2e_digest"] = "../outside.json"

    with pytest.raises(verifier.SandboxWriteEvidenceError, match="escapes"):
        verifier.assemble_document(manifest, base_dir=tmp_path)


def test_assembler_rejects_preflight_manifest_path_escape(tmp_path):
    manifest = _input_manifest(tmp_path)
    manifest["preflight_manifest"] = "../preflight_manifest.json"

    with pytest.raises(verifier.SandboxWriteEvidenceError, match="escapes"):
        verifier.assemble_document(manifest, base_dir=tmp_path)

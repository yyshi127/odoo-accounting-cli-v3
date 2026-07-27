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
ARTIFACT_SHA256 = hashlib.sha256(b"registry artifact").hexdigest()
PREFLIGHT_MANIFEST_SHA256 = hashlib.sha256(b"preflight manifest").hexdigest()
SIGNATURE_SHA256 = hashlib.sha256(b"registry signature").hexdigest()
LIFECYCLE_DIGESTS = {
    "approval_digest": hashlib.sha256(b"approval").hexdigest(),
    "failure_case_digest": hashlib.sha256(b"failure case").hexdigest(),
    "idempotency_replay_digest": hashlib.sha256(b"idempotency replay").hexdigest(),
    "parameter_roundtrip_sha256": hashlib.sha256(b"parameter roundtrip").hexdigest(),
    "pi_e2e_digest": hashlib.sha256(b"pi e2e").hexdigest(),
    "preview_digest": hashlib.sha256(b"preview").hexdigest(),
    "recovery_case_digest": hashlib.sha256(b"recovery case").hexdigest(),
    "security_negative_digest": hashlib.sha256(b"security negative").hexdigest(),
}


def _receipt(kind: str, *, capability_id: str = "acct.invoice.customer_create.v1"):
    return {
        "artifact_sha256": ARTIFACT_SHA256,
        "capability_id": capability_id,
        "company_id": 7,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "id": f"receipt-{kind}",
        "kind": kind,
        "registry_sha256": "b" * 64,
        "release_sha256": "c" * 64,
        "signature": SIGNATURE_SHA256,
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
        "preflight_manifest_sha256": PREFLIGHT_MANIFEST_SHA256,
        "production_promotion_allowed": False,
        "release_identity": {
            "commit": "abc123",
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev160-abc123",
        },
        "lifecycle": {
            "approval_digest": LIFECYCLE_DIGESTS["approval_digest"],
            "execution_receipt_id": "execution-receipt",
            "failure_case_digest": LIFECYCLE_DIGESTS["failure_case_digest"],
            "final_audit_receipt_id": "audit-receipt",
            "idempotency_replay_digest": LIFECYCLE_DIGESTS["idempotency_replay_digest"],
            "odoo_record_receipt_id": "odoo-record-receipt",
            "parameter_roundtrip_sha256": LIFECYCLE_DIGESTS["parameter_roundtrip_sha256"],
            "pi_e2e_digest": LIFECYCLE_DIGESTS["pi_e2e_digest"],
            "prepare_receipt_id": "prepare-receipt",
            "preview_digest": LIFECYCLE_DIGESTS["preview_digest"],
            "recovery_case_digest": LIFECYCLE_DIGESTS["recovery_case_digest"],
            "security_negative_digest": LIFECYCLE_DIGESTS["security_negative_digest"],
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
        "preflight_manifest_sha256": PREFLIGHT_MANIFEST_SHA256,
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


def test_sandbox_write_evidence_builds_staged_sandbox_promotion_candidate():
    candidate = verifier.build_promotion_candidate(
        _document(),
        target_environment="sandbox",
        target_channel="staged",
    )

    assert candidate == _promotion_candidate()


@pytest.mark.parametrize(
    ("target_environment", "target_channel", "match"),
    (
        (
            "production",
            "staged",
            "cannot build a production promotion candidate",
        ),
        (
            "sandbox",
            "enabled",
            "can only build a staged sandbox candidate",
        ),
    ),
)
def test_promotion_candidate_builder_rejects_unsafe_targets(
    target_environment,
    target_channel,
    match,
):
    with pytest.raises(verifier.SandboxWriteEvidenceError, match=match):
        verifier.build_promotion_candidate(
            _document(),
            target_environment=target_environment,
            target_channel=target_channel,
        )


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
        (
            lambda document: document.__setitem__("preflight_manifest_sha256", "9" * 64),
            "preflight_manifest_sha256 must not be a placeholder SHA-256",
        ),
        (
            lambda document: document["lifecycle"].__setitem__("approval_digest", "1" * 64),
            "lifecycle.approval_digest must not be a placeholder SHA-256",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "artifact_sha256", "a" * 64
            ),
            "registry_receipts\\[0\\].artifact_sha256 must not be a placeholder SHA-256",
        ),
        (
            lambda document: document["registry_receipts"][0].__setitem__(
                "signature", "d" * 64
            ),
            "registry_receipts\\[0\\].signature must not be a placeholder SHA-256",
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
            json.dumps(
                {
                    "schema_version": 1,
                    "scope": verifier.LIFECYCLE_ARTIFACT_SCOPE,
                    "artifact_kind": field,
                    "artifact": {"name": field},
                    "capability_id": "acct.invoice.customer_create.v1",
                    "company_id": 7,
                    "database_uuid": "11111111-1111-4111-8111-111111111111",
                    "environment": "sandbox",
                    "production_promotion_allowed": False,
                    "release_identity": {
                        "manifest_sha256": "c" * 64,
                        "registry_digest": "b" * 64,
                    },
                },
                sort_keys=True,
            ),
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


def test_metadata_builder_derives_release_binding_from_preflight(tmp_path):
    manifest = _input_manifest(tmp_path)
    preflight = json.loads(
        (tmp_path / manifest["preflight_manifest"]).read_text(encoding="utf-8")
    )

    metadata = verifier.build_metadata(
        preflight,
        registry_receipts=manifest["registry_receipts"],
        lifecycle_receipt_ids=manifest["lifecycle_receipt_ids"],
    )

    assert metadata == _metadata(tmp_path)


def test_metadata_builder_rejects_registry_receipt_mismatch(tmp_path):
    manifest = _input_manifest(tmp_path)
    preflight = json.loads(
        (tmp_path / manifest["preflight_manifest"]).read_text(encoding="utf-8")
    )
    receipts = copy.deepcopy(manifest["registry_receipts"])
    receipts[0]["capability_id"] = "acct.bill.vendor_create.v1"

    with pytest.raises(verifier.SandboxWriteEvidenceError, match="capability_id mismatch"):
        verifier.build_metadata(
            preflight,
            registry_receipts=receipts,
            lifecycle_receipt_ids=manifest["lifecycle_receipt_ids"],
        )


def test_metadata_builder_rejects_incomplete_lifecycle_receipt_ids(tmp_path):
    manifest = _input_manifest(tmp_path)
    preflight = json.loads(
        (tmp_path / manifest["preflight_manifest"]).read_text(encoding="utf-8")
    )
    receipt_ids = copy.deepcopy(manifest["lifecycle_receipt_ids"])
    receipt_ids.pop("verification_receipt_id")

    with pytest.raises(verifier.SandboxWriteEvidenceError, match="receipt id fields"):
        verifier.build_metadata(
            preflight,
            registry_receipts=manifest["registry_receipts"],
            lifecycle_receipt_ids=receipt_ids,
        )


def test_metadata_builder_cli_prints_metadata(tmp_path, capsys):
    manifest = _input_manifest(tmp_path)
    registry_receipts_path = tmp_path / "registry-receipts.json"
    lifecycle_receipt_ids_path = tmp_path / "lifecycle-receipt-ids.json"
    registry_receipts_path.write_text(
        json.dumps(manifest["registry_receipts"], sort_keys=True),
        encoding="utf-8",
    )
    lifecycle_receipt_ids_path.write_text(
        json.dumps(manifest["lifecycle_receipt_ids"], sort_keys=True),
        encoding="utf-8",
    )

    assert (
        verifier.main(
            [
                "--build-metadata-from-preflight",
                str(tmp_path / manifest["preflight_manifest"]),
                "--registry-receipts-json",
                str(registry_receipts_path),
                "--lifecycle-receipt-ids-json",
                str(lifecycle_receipt_ids_path),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["scope"] == verifier.METADATA_SCOPE
    assert output["capability_id"] == "acct.invoice.customer_create.v1"
    assert output["release_identity"]["registry_digest"] == "b" * 64


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


@pytest.mark.parametrize(
    ("mutate", "match"),
    (
        (
            lambda artifact: artifact.__setitem__(
                "capability_id", "acct.bill.vendor_create.v1"
            ),
            "capability_id mismatch",
        ),
        (
            lambda artifact: artifact.__setitem__("company_id", 8),
            "company_id mismatch",
        ),
        (
            lambda artifact: artifact["release_identity"].__setitem__(
                "manifest_sha256", "f" * 64
            ),
            "release manifest mismatch",
        ),
        (
            lambda artifact: artifact.__setitem__(
                "production_promotion_allowed", True
            ),
            "must not authorize production",
        ),
        (
            lambda artifact: artifact.__setitem__(
                "artifact_kind", "preview_digest"
            ),
            "artifact_kind mismatch",
        ),
    ),
)
def test_assembler_rejects_unbound_lifecycle_artifacts(tmp_path, mutate, match):
    manifest = _input_manifest(tmp_path)
    artifact_path = tmp_path / manifest["lifecycle_artifacts"]["approval_digest"]
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    mutate(artifact)
    artifact_path.write_text(json.dumps(artifact, sort_keys=True), encoding="utf-8")

    with pytest.raises(verifier.SandboxWriteEvidenceError, match=match):
        verifier.assemble_document(manifest, base_dir=tmp_path)


def test_lifecycle_artifact_builder_wraps_payload_with_metadata_binding(tmp_path):
    metadata = _metadata(tmp_path)

    artifact = verifier.build_lifecycle_artifact(
        metadata,
        artifact_kind="approval_digest",
        artifact={"approval_id": "approval-1", "approved": True},
    )

    assert artifact["scope"] == verifier.LIFECYCLE_ARTIFACT_SCOPE
    assert artifact["artifact_kind"] == "approval_digest"
    assert artifact["artifact"] == {"approval_id": "approval-1", "approved": True}
    assert artifact["capability_id"] == metadata["capability_id"]
    assert artifact["company_id"] == metadata["company_id"]
    assert artifact["database_uuid"] == metadata["database_uuid"]
    assert artifact["environment"] == "sandbox"
    assert artifact["production_promotion_allowed"] is False
    assert artifact["release_identity"] == {
        "manifest_sha256": "c" * 64,
        "registry_digest": "b" * 64,
    }


@pytest.mark.parametrize(
    ("artifact_kind", "artifact", "match"),
    (
        ("not_a_phase", {"ok": True}, "artifact_kind is invalid"),
        ("approval_digest", ["not", "object"], "artifact payload must be an object"),
    ),
)
def test_lifecycle_artifact_builder_rejects_invalid_inputs(
    tmp_path,
    artifact_kind,
    artifact,
    match,
):
    with pytest.raises(verifier.SandboxWriteEvidenceError, match=match):
        verifier.build_lifecycle_artifact(
            _metadata(tmp_path),
            artifact_kind=artifact_kind,
            artifact=artifact,
        )


def test_lifecycle_artifact_builder_cli_prints_bound_envelope(tmp_path, capsys):
    metadata_path = tmp_path / "metadata.json"
    payload_path = tmp_path / "approval-payload.json"
    metadata_path.write_text(json.dumps(_metadata(tmp_path)), encoding="utf-8")
    payload_path.write_text(
        json.dumps({"approval_id": "approval-1"}, sort_keys=True),
        encoding="utf-8",
    )

    assert (
        verifier.main(
            [
                "--build-artifact-from",
                str(metadata_path),
                "--artifact-kind",
                "approval_digest",
                "--artifact-json",
                str(payload_path),
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["scope"] == verifier.LIFECYCLE_ARTIFACT_SCOPE
    assert output["artifact_kind"] == "approval_digest"
    assert output["artifact"] == {"approval_id": "approval-1"}


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


def test_pipeline_inspector_reports_ordered_bound_steps(tmp_path):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(_metadata(tmp_path)), encoding="utf-8")

    report = verifier.inspect_pipeline_path(path)

    assert report["scope"] == verifier.PIPELINE_SCOPE
    assert report["verified"] is True
    assert report["production_promotion_allowed"] is False
    assert report["capability_id"] == "acct.invoice.customer_create.v1"
    assert report["promotion_candidate"]["target_environment"] == "sandbox"
    assert report["promotion_candidate"]["target_channel"] == "staged"
    assert [step["name"] for step in report["steps"]] == [
        "preflight_manifest_retained",
        "metadata_verified",
        "lifecycle_artifacts_verified",
        "input_manifest_built",
        "evidence_assembled",
        "promotion_candidate_built",
    ]
    assert all(step["sha256"] for step in report["steps"])


def test_pipeline_inspector_rejects_unbound_artifact(tmp_path):
    path = tmp_path / "metadata.json"
    metadata = _metadata(tmp_path)
    path.write_text(json.dumps(metadata), encoding="utf-8")
    artifact_path = tmp_path / "preview_digest.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["database_uuid"] = "22222222-2222-4222-8222-222222222222"
    artifact_path.write_text(json.dumps(artifact, sort_keys=True), encoding="utf-8")

    with pytest.raises(verifier.SandboxWriteEvidenceError, match="database_uuid mismatch"):
        verifier.inspect_pipeline_path(path)


def test_pipeline_inspector_cli_prints_pipeline_report(tmp_path, capsys):
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(_metadata(tmp_path)), encoding="utf-8")

    assert verifier.main(["--inspect-pipeline", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["scope"] == verifier.PIPELINE_SCOPE
    assert output["steps"][-1]["name"] == "promotion_candidate_built"
    assert output["promotion_candidate"]["production_promotion_allowed"] is False


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

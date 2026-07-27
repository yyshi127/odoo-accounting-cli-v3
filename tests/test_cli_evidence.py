from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from odoo_accounting_cli_v3.cli import main
from odoo_accounting_cli_v3.odoo.runner import OdooRunnerError

from test_odoo_read_boundary_evidence_runner import (
    RELEASE_DIGEST,
    runtime_config,
    valid_evidence,
)
from test_verify_sandbox_write_evidence import _document as sandbox_write_document
from test_verify_sandbox_write_evidence import _input_manifest as sandbox_write_input_manifest
from test_verify_sandbox_write_evidence import _metadata as sandbox_write_metadata
from test_verify_sandbox_write_evidence import _promotion_candidate as sandbox_write_promotion_candidate
from test_write_runtime import _make_runtime as make_write_runtime
from test_write_runtime import _write_json as write_runtime_json


def identity(config) -> dict:
    return {
        "commit": "1" * 40,
        "manifest_sha256": RELEASE_DIGEST,
        "package_sha256": config.canonical_package_sha256,
        "registry_digest": "5" * 64,
        "release": config.release_root.name,
        "verified": True,
        "version": "0.1.0.dev29",
    }


def test_evidence_read_boundary_returns_exact_release_runtime_and_evidence(
    tmp_path: Path,
):
    config = runtime_config(tmp_path)
    expected_identity = identity(config)
    runner = CliRunner()

    with patch(
        "odoo_accounting_cli_v3.cli.load_runtime_config", return_value=config
    ), patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ), patch(
        "odoo_accounting_cli_v3.cli._assert_runtime_release"
    ) as release_binding, patch(
        "odoo_accounting_cli_v3.cli.run_read_boundary_evidence",
        return_value=valid_evidence(),
    ) as collector:
        result = runner.invoke(
            main,
            [
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(tmp_path / "runtime.json"),
                "--timeout-seconds",
                "12",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload == {
        "command": "evidence.read-boundary",
        "data": {
            "evidence": valid_evidence(),
            "release_identity": expected_identity,
            "runtime": config.runtime_identity,
        },
        "ok": True,
    }
    release_binding.assert_called_once_with(
        config, expected_identity, command="evidence.read-boundary"
    )
    collector.assert_called_once_with(
        config,
        release_digest=RELEASE_DIGEST,
        timeout_seconds=12.0,
        launcher_diagnostics=False,
    )


def test_evidence_read_boundary_can_enable_hidden_launcher_diagnostics(tmp_path: Path):
    config = runtime_config(tmp_path)
    runner = CliRunner()

    with patch(
        "odoo_accounting_cli_v3.cli.load_runtime_config", return_value=config
    ), patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=identity(config),
    ), patch(
        "odoo_accounting_cli_v3.cli._assert_runtime_release"
    ), patch(
        "odoo_accounting_cli_v3.cli.run_read_boundary_evidence",
        return_value=valid_evidence(),
    ) as collector:
        result = runner.invoke(
            main,
            [
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(tmp_path / "runtime.json"),
                "--launcher-diagnostics",
            ],
        )

    assert result.exit_code == 0, result.output
    collector.assert_called_once_with(
        config,
        release_digest=RELEASE_DIGEST,
        timeout_seconds=30.0,
        launcher_diagnostics=True,
    )


def test_evidence_read_boundary_hides_runner_failure_detail(tmp_path: Path):
    config = runtime_config(tmp_path)
    runner = CliRunner()
    with patch(
        "odoo_accounting_cli_v3.cli.load_runtime_config", return_value=config
    ), patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=identity(config),
    ), patch(
        "odoo_accounting_cli_v3.cli._assert_runtime_release"
    ), patch(
        "odoo_accounting_cli_v3.cli.run_read_boundary_evidence",
        side_effect=OdooRunnerError("private database failure and canary"),
    ):
        result = runner.invoke(
            main,
            [
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(tmp_path / "runtime.json"),
            ],
        )

    assert result.exit_code == 6
    assert "rejection_code" not in __import__("json").loads(result.stderr)["error"]
    assert "private database failure" not in result.output
    assert "canary" not in result.output
    assert '"code":"odoo_read_boundary_evidence_failed"' in result.output


def test_evidence_read_boundary_diagnostics_emit_runner_failure_to_stderr(tmp_path: Path):
    config = runtime_config(tmp_path)
    runner = CliRunner()
    with patch(
        "odoo_accounting_cli_v3.cli.load_runtime_config", return_value=config
    ), patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=identity(config),
    ), patch(
        "odoo_accounting_cli_v3.cli._assert_runtime_release"
    ), patch(
        "odoo_accounting_cli_v3.cli.run_read_boundary_evidence",
        side_effect=OdooRunnerError("diagnostic child stderr"),
    ):
        result = runner.invoke(
            main,
            [
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(tmp_path / "runtime.json"),
                "--launcher-diagnostics",
            ],
        )

    assert result.exit_code == 6
    assert "diagnostic child stderr" in result.stderr
    assert '"code":"odoo_read_boundary_evidence_failed"' in result.output


@pytest.mark.parametrize(
    ("environment", "channel"),
    (("production", "enabled"), ("test", "enabled")),
)
def test_evidence_read_boundary_rejects_non_staged_test_runtime_before_release_or_child(
    tmp_path: Path, environment: str, channel: str
):
    config = replace(
        runtime_config(tmp_path),
        environment=environment,
        capability_channel=channel,
    )
    runner = CliRunner()
    with patch(
        "odoo_accounting_cli_v3.cli.load_runtime_config", return_value=config
    ), patch(
        "odoo_accounting_cli_v3.cli._load_release_identity"
    ) as identity_loader, patch(
        "odoo_accounting_cli_v3.cli.run_read_boundary_evidence"
    ) as collector:
        result = runner.invoke(
            main,
            [
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(tmp_path / "runtime.json"),
            ],
        )

    assert result.exit_code == 5
    assert '"code":"evidence_scope_rejected"' in result.output
    identity_loader.assert_not_called()
    collector.assert_not_called()


def test_evidence_verify_sandbox_write_returns_exact_release_admission(tmp_path: Path):
    document = sandbox_write_document()
    path = tmp_path / "sandbox-write-evidence.json"
    path.write_text(__import__("json").dumps(document), encoding="utf-8")
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev160-test",
        "verified": True,
        "version": "0.1.0.dev160",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "verify-sandbox-write",
                "--evidence-json",
                str(path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.verify-sandbox-write"
    assert payload["ok"] is True
    assert payload["business_succeeded"] is False
    assert payload["data"]["release_identity"] == expected_identity
    assert payload["data"]["evidence"]["verified"] is True
    assert payload["data"]["evidence"]["registry_receipt_count"] == 7


def test_evidence_verify_sandbox_write_rejects_release_mismatch(tmp_path: Path):
    document = sandbox_write_document()
    path = tmp_path / "sandbox-write-evidence.json"
    path.write_text(__import__("json").dumps(document), encoding="utf-8")

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev160-test",
            "verified": True,
            "version": "0.1.0.dev160",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "verify-sandbox-write",
                "--evidence-json",
                str(path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_evidence_release_mismatch"' in result.output


def test_evidence_verify_sandbox_write_rejects_invalid_bundle(tmp_path: Path):
    path = tmp_path / "sandbox-write-evidence.json"
    path.write_text('{"schema_version":1}', encoding="utf-8")

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev160-test",
            "verified": True,
            "version": "0.1.0.dev160",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "verify-sandbox-write",
                "--evidence-json",
                str(path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_evidence_rejected"' in result.output


def test_evidence_review_write_promotion_returns_non_authorizing_sandbox_review(
    tmp_path: Path,
):
    evidence_path = tmp_path / "sandbox-write-evidence.json"
    candidate_path = tmp_path / "promotion-candidate.json"
    evidence_path.write_text(
        __import__("json").dumps(sandbox_write_document()),
        encoding="utf-8",
    )
    candidate_path.write_text(
        __import__("json").dumps(sandbox_write_promotion_candidate()),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev179-test",
        "verified": True,
        "version": "0.1.0.dev179",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "review-write-promotion",
                "--evidence-json",
                str(evidence_path),
                "--candidate-json",
                str(candidate_path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.review-write-promotion"
    assert payload["ok"] is True
    assert payload["business_succeeded"] is False
    review = payload["data"]["promotion_review"]
    assert review["promotion_allowed"] is True
    assert review["production_promotion_allowed"] is False
    assert review["target_environment"] == "sandbox"
    assert review["target_channel"] == "staged"
    assert payload["data"]["release_identity"] == expected_identity


def test_evidence_build_write_promotion_candidate_from_exact_release_evidence(
    tmp_path: Path,
):
    evidence_path = tmp_path / "sandbox-write-evidence.json"
    evidence_path.write_text(
        __import__("json").dumps(sandbox_write_document()),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev180-test",
        "verified": True,
        "version": "0.1.0.dev180",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-write-promotion-candidate",
                "--evidence-json",
                str(evidence_path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.build-write-promotion-candidate"
    assert payload["business_succeeded"] is False
    candidate = payload["data"]["promotion_candidate"]
    assert candidate == sandbox_write_promotion_candidate()
    assert payload["data"]["release_identity"] == expected_identity


def test_evidence_build_write_promotion_candidate_rejects_production_target(
    tmp_path: Path,
):
    evidence_path = tmp_path / "sandbox-write-evidence.json"
    evidence_path.write_text(
        __import__("json").dumps(sandbox_write_document()),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev180-test",
            "verified": True,
            "version": "0.1.0.dev180",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-write-promotion-candidate",
                "--evidence-json",
                str(evidence_path),
                "--target-environment",
                "production",
            ],
        )

    assert result.exit_code == 6
    assert '"code":"write_promotion_candidate_build_rejected"' in result.output


def test_evidence_build_write_promotion_candidate_rejects_release_mismatch(
    tmp_path: Path,
):
    evidence_path = tmp_path / "sandbox-write-evidence.json"
    evidence_path.write_text(
        __import__("json").dumps(sandbox_write_document()),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev180-test",
            "verified": True,
            "version": "0.1.0.dev180",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-write-promotion-candidate",
                "--evidence-json",
                str(evidence_path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"write_promotion_candidate_release_mismatch"' in result.output


def test_evidence_review_write_promotion_rejects_production_candidate(tmp_path: Path):
    evidence_path = tmp_path / "sandbox-write-evidence.json"
    candidate_path = tmp_path / "promotion-candidate.json"
    candidate = sandbox_write_promotion_candidate()
    candidate["target_environment"] = "production"
    evidence_path.write_text(
        __import__("json").dumps(sandbox_write_document()),
        encoding="utf-8",
    )
    candidate_path.write_text(
        __import__("json").dumps(candidate),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev179-test",
            "verified": True,
            "version": "0.1.0.dev179",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "review-write-promotion",
                "--evidence-json",
                str(evidence_path),
                "--candidate-json",
                str(candidate_path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"write_promotion_candidate_rejected"' in result.output


def test_evidence_review_write_promotion_rejects_release_mismatch(tmp_path: Path):
    evidence_path = tmp_path / "sandbox-write-evidence.json"
    candidate_path = tmp_path / "promotion-candidate.json"
    evidence_path.write_text(
        __import__("json").dumps(sandbox_write_document()),
        encoding="utf-8",
    )
    candidate_path.write_text(
        __import__("json").dumps(sandbox_write_promotion_candidate()),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev179-test",
            "verified": True,
            "version": "0.1.0.dev179",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "review-write-promotion",
                "--evidence-json",
                str(evidence_path),
                "--candidate-json",
                str(candidate_path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"write_promotion_release_mismatch"' in result.output


def test_evidence_verify_sandbox_write_can_assemble_retained_artifacts(tmp_path: Path):
    path = tmp_path / "sandbox-write-input.json"
    path.write_text(
        __import__("json").dumps(sandbox_write_input_manifest(tmp_path)),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev162-test",
            "verified": True,
            "version": "0.1.0.dev162",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "verify-sandbox-write",
                "--assemble-from",
                str(path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["evidence"]["verified"] is True
    assert payload["data"]["evidence"]["registry_receipt_count"] == 7
    assert payload["business_succeeded"] is False


def test_evidence_build_sandbox_write_input_from_standard_retained_files(
    tmp_path: Path,
):
    path = tmp_path / "sandbox-write-metadata.json"
    path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev166-test",
        "verified": True,
        "version": "0.1.0.dev166",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-input",
                "--metadata-json",
                str(path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.build-sandbox-write-input"
    assert payload["business_succeeded"] is False
    assert payload["data"]["release_identity"] == expected_identity
    manifest = payload["data"]["input_manifest"]
    assert manifest["scope"] == "odoo-accounting-cli-v3.sandbox-write-evidence-input.v1"
    assert manifest["preflight_manifest"] == "preflight_manifest.json"
    assert manifest["lifecycle_artifacts"]["preview_digest"] == "preview_digest.json"


def test_evidence_build_sandbox_write_metadata_from_exact_release_preflight(
    tmp_path: Path,
):
    manifest = sandbox_write_input_manifest(tmp_path)
    registry_receipts_path = tmp_path / "registry-receipts.json"
    lifecycle_receipt_ids_path = tmp_path / "lifecycle-receipt-ids.json"
    registry_receipts_path.write_text(
        __import__("json").dumps(manifest["registry_receipts"]),
        encoding="utf-8",
    )
    lifecycle_receipt_ids_path.write_text(
        __import__("json").dumps(manifest["lifecycle_receipt_ids"]),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev183-test",
        "verified": True,
        "version": "0.1.0.dev183",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-metadata",
                "--preflight-json",
                str(tmp_path / manifest["preflight_manifest"]),
                "--registry-receipts-json",
                str(registry_receipts_path),
                "--lifecycle-receipt-ids-json",
                str(lifecycle_receipt_ids_path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.build-sandbox-write-metadata"
    assert payload["business_succeeded"] is False
    metadata = payload["data"]["metadata"]
    assert metadata["scope"] == "odoo-accounting-cli-v3.sandbox-write-evidence-metadata.v1"
    assert metadata["release_identity"]["registry_digest"] == "b" * 64
    assert metadata["registry_receipts"] == manifest["registry_receipts"]
    assert payload["data"]["release_identity"] == expected_identity


def test_evidence_build_sandbox_write_metadata_rejects_registry_receipt_mismatch(
    tmp_path: Path,
):
    manifest = sandbox_write_input_manifest(tmp_path)
    receipts = manifest["registry_receipts"]
    receipts[0]["company_id"] = 8
    registry_receipts_path = tmp_path / "registry-receipts.json"
    lifecycle_receipt_ids_path = tmp_path / "lifecycle-receipt-ids.json"
    registry_receipts_path.write_text(
        __import__("json").dumps(receipts),
        encoding="utf-8",
    )
    lifecycle_receipt_ids_path.write_text(
        __import__("json").dumps(manifest["lifecycle_receipt_ids"]),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev183-test",
            "verified": True,
            "version": "0.1.0.dev183",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-metadata",
                "--preflight-json",
                str(tmp_path / manifest["preflight_manifest"]),
                "--registry-receipts-json",
                str(registry_receipts_path),
                "--lifecycle-receipt-ids-json",
                str(lifecycle_receipt_ids_path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_metadata_build_rejected"' in result.output


def test_evidence_build_sandbox_write_metadata_rejects_release_mismatch(
    tmp_path: Path,
):
    manifest = sandbox_write_input_manifest(tmp_path)
    registry_receipts_path = tmp_path / "registry-receipts.json"
    lifecycle_receipt_ids_path = tmp_path / "lifecycle-receipt-ids.json"
    registry_receipts_path.write_text(
        __import__("json").dumps(manifest["registry_receipts"]),
        encoding="utf-8",
    )
    lifecycle_receipt_ids_path.write_text(
        __import__("json").dumps(manifest["lifecycle_receipt_ids"]),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev183-test",
            "verified": True,
            "version": "0.1.0.dev183",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-metadata",
                "--preflight-json",
                str(tmp_path / manifest["preflight_manifest"]),
                "--registry-receipts-json",
                str(registry_receipts_path),
                "--lifecycle-receipt-ids-json",
                str(lifecycle_receipt_ids_path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_metadata_release_mismatch"' in result.output


def test_evidence_build_sandbox_write_artifact_from_exact_release_metadata(
    tmp_path: Path,
):
    metadata_path = tmp_path / "sandbox-write-metadata.json"
    payload_path = tmp_path / "approval-payload.json"
    metadata_path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )
    payload_path.write_text(
        __import__("json").dumps({"approval_id": "approval-1"}),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev182-test",
        "verified": True,
        "version": "0.1.0.dev182",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-artifact",
                "--metadata-json",
                str(metadata_path),
                "--artifact-kind",
                "approval_digest",
                "--artifact-json",
                str(payload_path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.build-sandbox-write-artifact"
    assert payload["business_succeeded"] is False
    artifact = payload["data"]["lifecycle_artifact"]
    assert artifact["artifact_kind"] == "approval_digest"
    assert artifact["artifact"] == {"approval_id": "approval-1"}
    assert artifact["release_identity"] == {
        "manifest_sha256": "c" * 64,
        "registry_digest": "b" * 64,
    }
    assert payload["data"]["release_identity"] == expected_identity


def test_evidence_build_sandbox_write_artifact_rejects_invalid_kind(
    tmp_path: Path,
):
    metadata_path = tmp_path / "sandbox-write-metadata.json"
    payload_path = tmp_path / "approval-payload.json"
    metadata_path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )
    payload_path.write_text('{"approval_id":"approval-1"}', encoding="utf-8")

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "c" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev182-test",
            "verified": True,
            "version": "0.1.0.dev182",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-artifact",
                "--metadata-json",
                str(metadata_path),
                "--artifact-kind",
                "not_a_phase",
                "--artifact-json",
                str(payload_path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_artifact_build_rejected"' in result.output


def test_evidence_build_sandbox_write_artifact_rejects_release_mismatch(
    tmp_path: Path,
):
    metadata_path = tmp_path / "sandbox-write-metadata.json"
    payload_path = tmp_path / "approval-payload.json"
    metadata_path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )
    payload_path.write_text('{"approval_id":"approval-1"}', encoding="utf-8")

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev182-test",
            "verified": True,
            "version": "0.1.0.dev182",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-artifact",
                "--metadata-json",
                str(metadata_path),
                "--artifact-kind",
                "approval_digest",
                "--artifact-json",
                str(payload_path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_artifact_release_mismatch"' in result.output


def test_evidence_build_sandbox_write_input_rejects_release_mismatch(
    tmp_path: Path,
):
    path = tmp_path / "sandbox-write-metadata.json"
    path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev166-test",
            "verified": True,
            "version": "0.1.0.dev166",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "build-sandbox-write-input",
                "--metadata-json",
                str(path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_evidence_release_mismatch"' in result.output


def test_evidence_inspect_sandbox_write_root_reports_bound_hashes(
    tmp_path: Path,
):
    path = tmp_path / "sandbox-write-metadata.json"
    path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev167-test",
        "verified": True,
        "version": "0.1.0.dev167",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "inspect-sandbox-write-root",
                "--metadata-json",
                str(path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.inspect-sandbox-write-root"
    assert payload["business_succeeded"] is False
    report = payload["data"]["root_report"]
    assert report["verified"] is True
    assert report["metadata_sha256"] == __import__("hashlib").sha256(
        path.read_bytes()
    ).hexdigest()
    assert report["artifact_sha256"]["preview_digest"] == __import__(
        "hashlib"
    ).sha256((tmp_path / "preview_digest.json").read_bytes()).hexdigest()


def test_evidence_inspect_sandbox_write_pipeline_reports_ordered_steps(
    tmp_path: Path,
):
    path = tmp_path / "sandbox-write-metadata.json"
    path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev184-test",
        "verified": True,
        "version": "0.1.0.dev184",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "inspect-sandbox-write-pipeline",
                "--metadata-json",
                str(path),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.inspect-sandbox-write-pipeline"
    assert payload["business_succeeded"] is False
    report = payload["data"]["pipeline_report"]
    assert report["scope"] == "odoo-accounting-cli-v3.sandbox-write-evidence-pipeline.v1"
    assert [step["name"] for step in report["steps"]] == [
        "preflight_manifest_retained",
        "metadata_verified",
        "lifecycle_artifacts_verified",
        "input_manifest_built",
        "evidence_assembled",
        "promotion_candidate_built",
    ]
    assert report["promotion_candidate"]["target_environment"] == "sandbox"
    assert report["production_promotion_allowed"] is False
    assert payload["data"]["release_identity"] == expected_identity


def test_evidence_inspect_sandbox_write_pipeline_rejects_release_mismatch(
    tmp_path: Path,
):
    path = tmp_path / "sandbox-write-metadata.json"
    path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev184-test",
            "verified": True,
            "version": "0.1.0.dev184",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "inspect-sandbox-write-pipeline",
                "--metadata-json",
                str(path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_evidence_release_mismatch"' in result.output


def test_evidence_inspect_sandbox_write_root_rejects_release_mismatch(
    tmp_path: Path,
):
    path = tmp_path / "sandbox-write-metadata.json"
    path.write_text(
        __import__("json").dumps(sandbox_write_metadata(tmp_path)),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev167-test",
            "verified": True,
            "version": "0.1.0.dev167",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "inspect-sandbox-write-root",
                "--metadata-json",
                str(path),
            ],
        )

    assert result.exit_code == 6
    assert '"code":"sandbox_write_evidence_release_mismatch"' in result.output


def test_evidence_verify_sandbox_write_requires_exactly_one_input(tmp_path: Path):
    document = sandbox_write_document()
    evidence = tmp_path / "evidence.json"
    evidence.write_text(__import__("json").dumps(document), encoding="utf-8")
    manifest = tmp_path / "input.json"
    manifest.write_text(
        __import__("json").dumps(sandbox_write_input_manifest(tmp_path)),
        encoding="utf-8",
    )
    runner = CliRunner()

    missing = runner.invoke(main, ["evidence", "verify-sandbox-write"])
    both = runner.invoke(
        main,
        [
            "evidence",
            "verify-sandbox-write",
            "--evidence-json",
            str(evidence),
            "--assemble-from",
            str(manifest),
        ],
    )

    assert missing.exit_code == 2
    assert both.exit_code == 2
    assert '"code":"sandbox_write_evidence_input_required"' in missing.output
    assert '"code":"sandbox_write_evidence_input_required"' in both.output


def test_evidence_sandbox_write_preflight_accepts_staged_sandbox_runtime(
    tmp_path: Path,
):
    runtime_path, _document, _base = make_write_runtime(tmp_path / "runtime")
    evidence_root = tmp_path / "evidence-root"
    evidence_root.mkdir()
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev163",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ), patch("odoo_accounting_cli_v3.cli._assert_runtime_release"):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-write-preflight",
                "--capability-id",
                "acct.invoice.customer_create.v1",
                "--company-id",
                "7",
                "--write-runtime-config",
                str(runtime_path),
                "--evidence-root",
                str(evidence_root),
                "--min-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-write-preflight"
    assert payload["ok"] is True
    assert payload["business_succeeded"] is False
    assert payload["data"]["capability_id"] == "acct.invoice.customer_create.v1"
    assert payload["data"]["company_id"] == 7
    assert payload["data"]["database_name"] == "odoo_v3_sandbox"
    assert payload["data"]["preflight_manifest"]["capability_id"] == (
        "acct.invoice.customer_create.v1"
    )
    assert payload["data"]["preflight_manifest"]["company_id"] == 7
    assert payload["data"]["preflight_manifest"]["scope"] == (
        "odoo-accounting-cli-v3.sandbox-write-preflight.v1"
    )
    assert payload["data"]["preflight_manifest"]["readiness_report"][
        "sandbox_drill_admissible"
    ] is True
    assert payload["data"]["preflight_manifest"]["readiness_report_sha256"] == __import__(
        "hashlib"
    ).sha256(
        __import__("json")
        .dumps(
            payload["data"]["preflight_manifest"]["readiness_report"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .encode("utf-8")
    ).hexdigest()
    assert payload["data"]["preflight_manifest"]["real_odoo_write_performed"] is False
    assert payload["data"]["preflight_manifest_sha256"] == __import__(
        "hashlib"
    ).sha256(
        __import__("json")
        .dumps(
            payload["data"]["preflight_manifest"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .encode("utf-8")
    ).hexdigest()
    assert payload["data"]["sandbox_write_evidence_collection_admissible"] is True
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False


def test_evidence_write_capability_readiness_accepts_registered_write():
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev170",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "write-capability-readiness",
                "--capability-id",
                "acct.invoice.customer_create.v1",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.write-capability-readiness"
    assert payload["business_succeeded"] is False
    assert payload["data"]["sandbox_drill_admissible"] is True
    assert payload["data"]["sandbox_staging_promotion_ready"] is False
    assert payload["data"]["registry_evidence_level"] == "declared"
    assert payload["data"]["registry_receipt_count"] == 0
    assert payload["data"]["sandbox_staging_promotion_blockers"] == [
        "registry evidence level is not sandbox_verified",
        "registry has no retained sandbox write evidence receipts",
    ]
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False
    assert payload["data"]["capability"]["id"] == "acct.invoice.customer_create.v1"
    assert payload["data"]["capability"]["approval"]["required"] is True
    assert payload["data"]["capability"]["idempotency"]["required"] is True
    assert payload["data"]["checks"] == {
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
    }
    assert payload["data"]["capability"]["enabled_environments"] == []
    assert payload["data"]["capability"]["staged_environments"] == []
    assert "account.move" in payload["data"]["allowed_models"]


def test_evidence_write_capability_readiness_rejects_read_capability():
    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "d" * 64,
            "package_sha256": "4" * 64,
            "registry_digest": "b" * 64,
            "release": "release",
            "verified": True,
            "version": "0.1.0.dev170",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "write-capability-readiness",
                "--capability-id",
                "acct.registry.list.v1",
            ],
        )

    assert result.exit_code == 5
    assert '"code":"write_capability_rejected"' in result.output


def test_evidence_write_capabilities_readiness_reports_all_registered_writes():
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev171",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "write-capabilities-readiness",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.write-capabilities-readiness"
    assert payload["business_succeeded"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False
    assert payload["data"]["sandbox_drill_admissible"] is True
    assert all(
        item["sandbox_staging_promotion_ready"] is False
        for item in payload["data"]["capabilities"]
    )
    assert payload["data"]["total_write_capabilities"] == 14
    assert payload["data"]["admissible_count"] == 14
    reported = [item["capability"]["id"] for item in payload["data"]["capabilities"]]
    assert reported == sorted(reported)
    assert "acct.invoice.customer_create.v1" in reported
    assert all(item["sandbox_drill_admissible"] is True for item in payload["data"]["capabilities"])


def test_evidence_write_pipeline_readiness_reports_verified_and_missing(
    tmp_path: Path,
):
    evidence_root = tmp_path / "pipelines"
    capability_root = evidence_root / "acct.invoice.customer_create.v1"
    capability_root.mkdir(parents=True)
    (capability_root / "metadata.json").write_text(
        __import__("json").dumps(sandbox_write_metadata(capability_root)),
        encoding="utf-8",
    )
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "c" * 64,
        "package_sha256": "e" * 64,
        "registry_digest": "b" * 64,
        "release": "0.1.0.dev185-test",
        "verified": True,
        "version": "0.1.0.dev185",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "write-pipeline-readiness",
                "--evidence-root",
                str(evidence_root),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.write-pipeline-readiness"
    assert payload["business_succeeded"] is False
    data = payload["data"]
    assert data["total_write_capabilities"] == 14
    assert data["verified_count"] == 1
    assert data["missing_count"] == 13
    assert data["rejected_count"] == 0
    assert data["sandbox_pipeline_ready"] is False
    invoice = next(
        item
        for item in data["capabilities"]
        if item["capability_id"] == "acct.invoice.customer_create.v1"
    )
    assert invoice["status"] == "verified"
    assert invoice["pipeline_ready"] is True
    assert invoice["pipeline"]["scope"] == "odoo-accounting-cli-v3.sandbox-write-evidence-pipeline.v1"


def test_evidence_write_pipeline_readiness_reports_rejected_release_mismatch(
    tmp_path: Path,
):
    evidence_root = tmp_path / "pipelines"
    capability_root = evidence_root / "acct.invoice.customer_create.v1"
    capability_root.mkdir(parents=True)
    (capability_root / "metadata.json").write_text(
        __import__("json").dumps(sandbox_write_metadata(capability_root)),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "f" * 64,
            "package_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "release": "0.1.0.dev185-test",
            "verified": True,
            "version": "0.1.0.dev185",
        },
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "write-pipeline-readiness",
                "--evidence-root",
                str(evidence_root),
            ],
        )

    assert result.exit_code == 0, result.output
    data = __import__("json").loads(result.output)["data"]
    assert data["verified_count"] == 0
    assert data["missing_count"] == 13
    assert data["rejected_count"] == 1
    invoice = next(
        item
        for item in data["capabilities"]
        if item["capability_id"] == "acct.invoice.customer_create.v1"
    )
    assert invoice["status"] == "rejected"
    assert "exact release" in invoice["rejection"]


def test_evidence_sandbox_write_preflight_rejects_demo_database_name(
    tmp_path: Path,
):
    runtime_path, _document, base = make_write_runtime(tmp_path / "runtime")
    base["database_name"] = "codex_cn_m31_demo_01"
    write_runtime_json(Path(_document["base_runtime_config_path"]), base)
    evidence_root = tmp_path / "evidence-root"
    evidence_root.mkdir()

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "d" * 64,
            "package_sha256": "4" * 64,
            "registry_digest": "b" * 64,
            "release": "release",
            "verified": True,
            "version": "0.1.0.dev163",
        },
    ), patch("odoo_accounting_cli_v3.cli._assert_runtime_release"):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-write-preflight",
                "--capability-id",
                "acct.invoice.customer_create.v1",
                "--company-id",
                "7",
                "--write-runtime-config",
                str(runtime_path),
                "--evidence-root",
                str(evidence_root),
                "--min-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 5
    assert '"code":"sandbox_write_scope_rejected"' in result.output


def test_evidence_sandbox_write_preflight_rejects_non_write_capability(
    tmp_path: Path,
):
    runtime_path, _document, _base = make_write_runtime(tmp_path / "runtime")
    evidence_root = tmp_path / "evidence-root"
    evidence_root.mkdir()

    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-write-preflight",
            "--capability-id",
            "acct.registry.list.v1",
            "--company-id",
            "7",
            "--write-runtime-config",
            str(runtime_path),
            "--evidence-root",
            str(evidence_root),
            "--min-free-bytes",
            "1",
        ],
    )

    assert result.exit_code == 5
    assert '"code":"sandbox_write_capability_rejected"' in result.output


def test_evidence_sandbox_write_preflight_rejects_release_internal_evidence_root(
    tmp_path: Path,
):
    runtime_path, _document, _base = make_write_runtime(tmp_path / "runtime")
    release_root = Path(_base["release_root"])
    evidence_root = release_root / "write-evidence"
    evidence_root.mkdir(parents=True)

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value={
            "commit": "1" * 40,
            "manifest_sha256": "d" * 64,
            "package_sha256": "4" * 64,
            "registry_digest": "b" * 64,
            "release": "release",
            "verified": True,
            "version": "0.1.0.dev163",
        },
    ), patch("odoo_accounting_cli_v3.cli._assert_runtime_release"):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-write-preflight",
                "--capability-id",
                "acct.invoice.customer_create.v1",
                "--company-id",
                "7",
                "--write-runtime-config",
                str(runtime_path),
                "--evidence-root",
                str(evidence_root),
                "--min-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 5
    assert '"code":"sandbox_write_evidence_root_rejected"' in result.output

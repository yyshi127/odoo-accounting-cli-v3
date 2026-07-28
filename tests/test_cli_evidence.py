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


READY_CURRENT_ROUTE = {
    "blockers": [],
    "current_path": "/opt/odoo-accounting-cli-v3/current",
    "current_route_ready": True,
    "expected": {
        "commit": None,
        "manifest_sha256": None,
        "package_sha256": None,
        "registry_digest": None,
        "release": None,
    },
    "real_odoo_write_performed": False,
    "resolved_release_path": "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev207-a0af30bff17c",
    "route_identity": {
        "commit": "1" * 40,
        "manifest_sha256": "2" * 64,
        "package_sha256": "3" * 64,
        "registry_digest": "4" * 64,
        "release": "0.1.0.dev207-a0af30bff17c",
        "verified": True,
    },
}


def _ready_onboarding_receipt(
    tmp_path: Path,
    *,
    database_name: str = "odoo_v3_sandbox",
    release_identity: dict | None = None,
) -> Path:
    identity = release_identity or {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev191",
    }
    route = {
        **READY_CURRENT_ROUTE,
        "route_identity": {
            "commit": identity["commit"],
            "manifest_sha256": identity["manifest_sha256"],
            "package_sha256": identity["package_sha256"],
            "registry_digest": identity["registry_digest"],
            "release": identity["release"],
            "verified": True,
            "version": identity["version"],
        },
    }
    receipt = {
        "business_succeeded": False,
        "command": "evidence.sandbox-onboarding-readiness",
        "data": {
            "authorization": {"authorization_record_ready": True, "blockers": []},
            "blockers": [],
            "capacity": {
                "blockers": [],
                "real_odoo_write_performed": False,
                "sandbox_write_capacity_ready": True,
            },
            "database": {
                "sandbox_database_name": database_name,
                "sandbox_database_observed": True,
                "source_database_name": "odoo_sg",
            },
            "postgresql_write_performed": False,
            "real_odoo_write_performed": False,
            "route": route,
            "sandbox_onboarding_ready": True,
        },
        "ok": True,
    }
    path = tmp_path / "sandbox-onboarding-readiness.json"
    path.write_text(
        __import__("json").dumps(receipt, sort_keys=True),
        encoding="utf-8",
    )
    return path


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
    onboarding_receipt = _ready_onboarding_receipt(
        tmp_path,
        release_identity=expected_identity,
    )

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
                "--onboarding-receipt",
                str(onboarding_receipt),
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
    assert payload["data"]["onboarding"]["ready"] is True
    assert payload["data"]["preflight_manifest"]["onboarding_receipt"]["ready"] is True
    assert payload["data"]["preflight_manifest"]["onboarding_receipt_sha256"] == (
        payload["data"]["onboarding"]["receipt_sha256"]
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


def test_evidence_sandbox_write_preflight_rejects_unready_onboarding_receipt(
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
    onboarding_receipt = _ready_onboarding_receipt(
        tmp_path,
        database_name="wrong_sandbox",
        release_identity=expected_identity,
    )

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
                "--onboarding-receipt",
                str(onboarding_receipt),
                "--min-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 5, result.output
    assert '"code":"sandbox_onboarding_receipt_rejected"' in result.output


def test_evidence_sandbox_write_environment_audit_reports_ready_preconditions(
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
        "version": "0.1.0.dev191",
    }
    onboarding_receipt = _ready_onboarding_receipt(
        tmp_path,
        release_identity=expected_identity,
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-write-environment-audit",
                "--write-runtime-config",
                str(runtime_path),
                "--evidence-root",
                str(evidence_root),
                "--onboarding-receipt",
                str(onboarding_receipt),
                "--min-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-write-environment-audit"
    assert payload["business_succeeded"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False
    assert payload["data"]["runtime"]["ready"] is True
    assert payload["data"]["runtime"]["write_execution_mode"] == "sandbox_staged"
    assert payload["data"]["runtime"]["database_name"] == "odoo_v3_sandbox"
    assert payload["data"]["evidence_root"]["ready"] is True
    assert payload["data"]["onboarding"]["ready"] is True
    assert payload["data"]["environment_ready_for_sandbox_write_drills"] is True
    assert len(payload["data"]["capabilities"]) == 14
    assert payload["data"]["capability_summary"]["total_write_capabilities"] == 14
    assert payload["data"]["capability_summary"]["not_staging_ready_count"] == 14
    assert payload["data"]["capability_summary"]["sandbox_drill_admissible_count"] == 14
    assert payload["data"]["capability_summary"][
        "sandbox_staging_promotion_ready_count"
    ] == 0
    assert payload["data"]["capability_summary"]["staging_promotion_blockers"] == [
        "registry evidence level is not sandbox_verified",
        "registry has no retained sandbox write evidence receipts",
    ]
    assert payload["data"]["total_write_capabilities"] == 14
    assert payload["data"]["sandbox_drill_admissible_count"] == 14
    assert payload["data"]["sandbox_staging_promotion_ready_count"] == 0


def test_evidence_sandbox_write_environment_audit_summary_omits_capability_details(
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
        "version": "0.1.0.dev191",
    }
    onboarding_receipt = _ready_onboarding_receipt(
        tmp_path,
        release_identity=expected_identity,
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-write-environment-audit",
                "--write-runtime-config",
                str(runtime_path),
                "--evidence-root",
                str(evidence_root),
                "--onboarding-receipt",
                str(onboarding_receipt),
                "--min-free-bytes",
                "1",
                "--summary-only",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert "capabilities" not in payload["data"]
    assert payload["data"]["onboarding"]["ready"] is True
    assert payload["data"]["environment_ready_for_sandbox_write_drills"] is True
    assert payload["data"]["capability_summary"]["total_write_capabilities"] == 14
    assert payload["data"]["capability_summary"]["not_staging_ready_count"] == 14
    assert payload["data"]["capability_summary"]["sandbox_drill_admissible_count"] == 14
    assert payload["data"]["capability_summary"][
        "sandbox_staging_promotion_ready_count"
    ] == 0
    assert payload["data"]["capability_summary"][
        "not_staging_ready_capability_ids"
    ] == sorted(payload["data"]["capability_summary"]["not_staging_ready_capability_ids"])
    assert payload["data"]["capability_summary"]["staging_promotion_blockers"] == [
        "registry evidence level is not sandbox_verified",
        "registry has no retained sandbox write evidence receipts",
    ]


def test_evidence_sandbox_write_environment_audit_reports_missing_inputs(
    tmp_path: Path,
):
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev191",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-write-environment-audit",
                "--write-runtime-config",
                str(tmp_path / "missing-write-runtime.json"),
                "--min-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["environment_ready_for_sandbox_write_drills"] is False
    assert payload["data"]["runtime"]["ready"] is False
    assert payload["data"]["runtime"]["status"] == "missing"
    assert payload["data"]["evidence_root"]["ready"] is False
    assert payload["data"]["evidence_root"]["status"] == "missing"
    assert payload["data"]["evidence_root"]["blockers"] == [
        "sandbox write evidence root was not supplied"
    ]
    assert payload["data"]["onboarding"]["ready"] is False
    assert payload["data"]["onboarding"]["blockers"] == [
        "sandbox onboarding readiness receipt was not supplied"
    ]
    assert payload["data"]["capability_summary"]["total_write_capabilities"] == 14
    assert payload["data"]["capability_summary"]["not_staging_ready_count"] == 14
    assert payload["data"]["sandbox_staging_promotion_ready_count"] == 0


def _read_runtime_plan_args(
    *,
    tmp_path: Path,
    database_name: str = "odoo_v3_sandbox",
    odoo_python_sha256: str | None = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    odoo_bin_sha256: str | None = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    odoo_config_sha256: str | None = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
    canonical_package_sha256: str | None = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    measure_existing_files: bool = False,
) -> list[str]:
    args = [
        "evidence",
        "sandbox-read-runtime-config-plan",
        "--instance-id",
        "odoo19@sandbox",
        "--database-name",
        database_name,
        "--database-uuid",
        "11111111-1111-4111-8111-111111111111",
        "--odoo-python",
        str(tmp_path / "odoo-venv" / "bin" / "python"),
        "--odoo-bin",
        str(tmp_path / "odoo-server" / "odoo-bin"),
        "--odoo-config",
        str(tmp_path / "odoo.conf"),
        "--runtime-config-path",
        str(tmp_path / "runtime-sandbox.json"),
        "--release-root",
        str(tmp_path / "release"),
        "--canonical-package-path",
        str(tmp_path / "packages" / "release.tar.gz"),
        "--read-state-root",
        str(tmp_path / "read-state"),
        "--secret-root",
        str(tmp_path / "secrets"),
    ]
    for option, value in (
        ("--odoo-python-sha256", odoo_python_sha256),
        ("--odoo-bin-sha256", odoo_bin_sha256),
        ("--odoo-config-sha256", odoo_config_sha256),
        ("--canonical-package-sha256", canonical_package_sha256),
    ):
        if value is not None:
            args.extend((option, value))
    if measure_existing_files:
        args.append("--measure-existing-files")
    return args


def test_evidence_sandbox_read_runtime_config_plan_renders_current_schema(
    tmp_path: Path,
):
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev193",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            _read_runtime_plan_args(tmp_path=tmp_path),
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    planned = payload["data"]["document"]
    assert payload["command"] == "evidence.sandbox-read-runtime-config-plan"
    assert payload["business_succeeded"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False
    assert payload["data"]["secret_values_included"] is False
    assert payload["data"]["sandbox_read_runtime_configurable"] is True
    assert payload["data"]["blockers"] == []
    assert planned["environment"] == "sandbox"
    assert planned["capability_channel"] == "staged"
    assert planned["database_name"] == "odoo_v3_sandbox"
    assert planned["database_uuid"] == "11111111-1111-4111-8111-111111111111"
    assert Path(planned["auth_state_path"]) == tmp_path / "read-state" / "auth.sqlite3"
    assert Path(planned["receipt_state_path"]) == (
        tmp_path / "read-state" / "receipt.sqlite3"
    )
    assert Path(planned["auth_secret_path"]) == tmp_path / "secrets" / "read_auth.hmac"
    assert Path(planned["receipt_secret_path"]) == (
        tmp_path / "secrets" / "read_receipt.hmac"
    )
    assert payload["data"]["document_sha256"] == __import__("hashlib").sha256(
        __import__("json")
        .dumps(
            planned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .encode("utf-8")
    ).hexdigest()


def test_evidence_sandbox_read_runtime_config_plan_flags_unclear_database_name(
    tmp_path: Path,
):
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev193",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            _read_runtime_plan_args(
                tmp_path=tmp_path,
                database_name="odoo_prod",
            ),
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_read_runtime_configurable"] is False
    assert payload["data"]["blockers"] == [
        "sandbox read runtime database name is not clearly sandbox"
    ]


def test_evidence_sandbox_read_runtime_config_plan_flags_placeholder_digests(
    tmp_path: Path,
):
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev194",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            _read_runtime_plan_args(
                tmp_path=tmp_path,
                odoo_python_sha256="1" * 64,
                odoo_bin_sha256="2" * 64,
                odoo_config_sha256="3" * 64,
                canonical_package_sha256="4" * 64,
            ),
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_read_runtime_configurable"] is False
    assert payload["data"]["blockers"] == [
        "canonical_package_sha256 must be a real measured digest, not a placeholder",
        "odoo_bin_sha256 must be a real measured digest, not a placeholder",
        "odoo_config_sha256 must be a real measured digest, not a placeholder",
        "odoo_python_sha256 must be a real measured digest, not a placeholder",
    ]


def test_evidence_sandbox_read_runtime_config_plan_measures_existing_files(
    tmp_path: Path,
):
    for relative, payload in (
        ("odoo-venv/bin/python", b"python-bytes"),
        ("odoo-server/odoo-bin", b"odoo-bin-bytes"),
        ("odoo.conf", b"odoo-config-bytes"),
        ("packages/release.tar.gz", b"package-bytes"),
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev195",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            _read_runtime_plan_args(
                tmp_path=tmp_path,
                odoo_python_sha256=None,
                odoo_bin_sha256=None,
                odoo_config_sha256=None,
                canonical_package_sha256=None,
                measure_existing_files=True,
            ),
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    planned = payload["data"]["document"]
    assert payload["data"]["sandbox_read_runtime_configurable"] is True
    assert payload["data"]["blockers"] == []
    assert payload["data"]["source_measurements"]["odoo_python_sha256"][
        "measured_sha256"
    ] == planned["odoo_python_sha256"]
    assert payload["data"]["source_measurements"]["odoo_bin_sha256"][
        "measured_sha256"
    ] == planned["odoo_bin_sha256"]
    assert payload["data"]["source_measurements"]["odoo_config_sha256"][
        "measured_sha256"
    ] == planned["odoo_config_sha256"]
    assert payload["data"]["source_measurements"]["canonical_package_sha256"][
        "measured_sha256"
    ] == planned["canonical_package_sha256"]


def test_evidence_sandbox_read_runtime_config_plan_flags_digest_mismatch(
    tmp_path: Path,
):
    for relative, payload in (
        ("odoo-venv/bin/python", b"python-bytes"),
        ("odoo-server/odoo-bin", b"odoo-bin-bytes"),
        ("odoo.conf", b"odoo-config-bytes"),
        ("packages/release.tar.gz", b"package-bytes"),
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev195",
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=expected_identity,
    ):
        result = CliRunner().invoke(
            main,
            _read_runtime_plan_args(
                tmp_path=tmp_path,
                odoo_python_sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                measure_existing_files=True,
            ),
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_read_runtime_configurable"] is False
    assert "odoo_python_sha256 does not match measured file digest" in payload[
        "data"
    ]["blockers"]


def test_evidence_sandbox_database_candidates_selects_clear_sandbox():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-database-candidates",
            "--database-name",
            "odoo_sg",
            "--database-name",
            "codex_cn_m31_demo_01",
            "--database-name",
            "odoo_v3_sandbox",
            "--protected-database-name",
            "odoo_sg",
            "--selected-database-name",
            "odoo_v3_sandbox",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-database-candidates"
    assert payload["business_succeeded"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False
    assert payload["data"]["sandbox_database_selection_ready"] is True
    assert payload["data"]["eligible_database_names"] == ["odoo_v3_sandbox"]
    assert payload["data"]["candidate_summary"] == {
        "blocker_counts": {
            "database name is explicitly protected": 1,
            "database name is not clearly sandbox": 2,
            "database name looks production-like": 1,
            "database name looks transient or test-generated": 1,
        },
        "candidate_count": 3,
        "eligible_count": 1,
        "rejected_count": 2,
    }
    assert payload["data"]["selected_database_eligible"] is True
    by_name = {item["name"]: item for item in payload["data"]["candidates"]}
    assert by_name["odoo_sg"]["blockers"] == [
        "database name is explicitly protected",
        "database name is not clearly sandbox",
        "database name looks production-like",
    ]
    assert by_name["codex_cn_m31_demo_01"]["blockers"] == [
        "database name is not clearly sandbox",
        "database name looks transient or test-generated",
    ]


def test_evidence_sandbox_database_candidates_rejects_missing_or_bad_selection():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-database-candidates",
            "--database-name",
            "codex_cn_m31_demo_01",
            "--selected-database-name",
            "odoo_v3_sandbox",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_database_selection_ready"] is False
    assert payload["data"]["selected_database_eligible"] is False
    assert payload["data"]["blockers"] == [
        "no eligible clearly named dedicated sandbox database was observed",
        "selected database was not observed in the PostgreSQL catalog",
    ]


def test_evidence_sandbox_database_candidates_summary_omits_candidate_details():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-database-candidates",
            "--database-name",
            "codex_cn_m31_demo_01",
            "--database-name",
            "odoo_sg",
            "--protected-database-name",
            "odoo_sg",
            "--selected-database-name",
            "odoo_v3_sandbox",
            "--summary-only",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert "candidates" not in payload["data"]
    assert payload["data"]["sandbox_database_selection_ready"] is False
    assert payload["data"]["selected_database"] is None
    assert payload["data"]["selected_database_eligible"] is False
    assert payload["data"]["candidate_summary"] == {
        "blocker_counts": {
            "database name is explicitly protected": 1,
            "database name is not clearly sandbox": 2,
            "database name looks production-like": 1,
            "database name looks transient or test-generated": 1,
        },
        "candidate_count": 2,
        "eligible_count": 0,
        "rejected_count": 2,
    }
    assert payload["data"]["blockers"] == [
        "no eligible clearly named dedicated sandbox database was observed",
        "selected database was not observed in the PostgreSQL catalog",
    ]


def test_evidence_sandbox_database_provision_plan_requires_authorization():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-database-provision-plan",
            "--sandbox-database-name",
            "odoo_v3_sandbox",
            "--source-database-name",
            "odoo_sg",
            "--protected-database-name",
            "odoo_sg",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-database-provision-plan"
    assert payload["business_succeeded"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["postgresql_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False
    assert payload["data"]["sandbox_database_provision_ready"] is False
    assert payload["data"]["expected_database_filter"] == "^odoo_v3_sandbox$"
    assert payload["data"]["blockers"] == [
        "explicit authorization to create or clone the sandbox database has not been recorded"
    ]
    assert payload["data"]["warnings"] == [
        "source database is explicitly protected; clone only from an authorized read-only snapshot"
    ]


def test_evidence_sandbox_database_provision_plan_accepts_authorized_safe_plan():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-database-provision-plan",
            "--sandbox-database-name",
            "odoo_v3_sandbox",
            "--source-database-name",
            "odoo_template_clean",
            "--authorization-recorded",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_database_provision_ready"] is True
    assert payload["data"]["authorization_required_before_database_creation"] is True
    assert payload["data"]["plan"] == {
        "database_filter": "^odoo_v3_sandbox$",
        "sandbox_database_name": "odoo_v3_sandbox",
        "source_database_name": "odoo_template_clean",
    }
    assert payload["data"]["operator_actions"][0].startswith(
        "record explicit authorization"
    )


def test_evidence_sandbox_database_provision_plan_rejects_unsafe_name_and_filter():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-database-provision-plan",
            "--sandbox-database-name",
            "odoo_sg",
            "--source-database-name",
            "odoo_sg",
            "--protected-database-name",
            "odoo_sg",
            "--expected-database-filter",
            "^.*$",
            "--authorization-recorded",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_database_provision_ready"] is False
    assert payload["data"]["blockers"] == [
        "expected database filter must match the exact sandbox database name",
        "sandbox database name is not eligible for provisioning",
        "sandbox database name must differ from source database name",
    ]
    assert payload["data"]["sandbox_database_report"]["blockers"] == [
        "database name is explicitly protected",
        "database name is not clearly sandbox",
        "database name looks production-like",
    ]


def test_evidence_sandbox_provision_authorization_template_renders_checkable_document():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-provision-authorization-template",
            "--sandbox-database-name",
            "odoo_v3_sandbox",
            "--source-database-name",
            "odoo_sg",
            "--company",
            "SG Company",
            "--operator-id",
            "yyshi",
            "--retention-until",
            "2026-08-03T00:00:00Z",
            "--issued-at",
            "2026-07-27T12:00:00Z",
            "--ttl-seconds",
            "3600",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-provision-authorization-template"
    assert payload["business_succeeded"] is False
    assert payload["data"]["authorization_template_ready"] is True
    assert payload["data"]["business_write_authorized"] is False
    assert payload["data"]["template_only_not_authorized"] is True
    document = payload["data"]["authorization_record_template"]
    assert document["expires_at"] == "2026-07-27T13:00:00Z"
    assert document["immutable_summary"]["operator_id"] == "yyshi"
    assert document["immutable_summary"]["company_scope"] == ["SG Company"]
    assert payload["data"]["validation_command_args"][-2:] == [
        "--expected-company",
        "SG Company",
    ]
    digest = __import__("hashlib").sha256(
        __import__("json")
        .dumps(
            document["immutable_summary"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .encode("utf-8")
    ).hexdigest()
    assert document["immutable_summary_sha256"] == digest


def test_evidence_sandbox_provision_authorization_template_rejects_unsafe_name():
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-provision-authorization-template",
            "--sandbox-database-name",
            "odoo_sg",
            "--source-database-name",
            "odoo_sg",
            "--company",
            "SG Company",
            "--operator-id",
            "yyshi",
            "--retention-until",
            "2026-08-03T00:00:00Z",
            "--issued-at",
            "2026-07-27T12:00:00Z",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["authorization_template_ready"] is False
    assert payload["data"]["blockers"] == [
        "sandbox database name is not clearly sandbox",
        "sandbox database name looks production-like",
        "sandbox database name must differ from source database name",
    ]


def _sandbox_authorization_document(**overrides):
    summary = {
        "allowed_actions": [
            "create_or_clone_postgresql_database",
            "create_isolated_filestore",
            "start_sandbox_odoo_service",
            "measure_runtime_identity",
        ],
        "company_scope": ["SG Company"],
        "retention_until": "2026-08-03T00:00:00Z",
        "sandbox_database_name": "odoo_v3_sandbox",
        "source_database_name": "odoo_sg",
    }
    summary.update(overrides.pop("immutable_summary", {}))
    digest = __import__("hashlib").sha256(
        __import__("json")
        .dumps(
            summary,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .encode("utf-8")
    ).hexdigest()
    document = {
        "expires_at": "2026-07-27T13:00:00Z",
        "immutable_summary": summary,
        "immutable_summary_sha256": digest,
        "issued_at": "2026-07-27T12:00:00Z",
        "purpose": "sandbox_database_provision",
        "schema_version": 1,
    }
    document.update(overrides)
    return document


def test_evidence_sandbox_provision_authorization_check_accepts_bound_record(tmp_path):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        __import__("json").dumps(_sandbox_authorization_document(), sort_keys=True),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-provision-authorization-check",
            "--authorization-file",
            str(authorization),
            "--expected-sandbox-database-name",
            "odoo_v3_sandbox",
            "--expected-source-database-name",
            "odoo_sg",
            "--expected-company",
            "SG Company",
            "--now",
            "2026-07-27T12:30:00Z",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-provision-authorization-check"
    assert payload["business_succeeded"] is False
    assert payload["data"]["authorization_record_ready"] is True
    assert payload["data"]["business_write_authorized"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["postgresql_write_performed"] is False
    assert payload["data"]["blockers"] == []


def test_evidence_sandbox_provision_authorization_check_rejects_expired_tampered_record(
    tmp_path,
):
    authorization = tmp_path / "authorization.json"
    document = _sandbox_authorization_document()
    document["immutable_summary"]["source_database_name"] = "odoo"
    authorization.write_text(
        __import__("json").dumps(document, sort_keys=True),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-provision-authorization-check",
            "--authorization-file",
            str(authorization),
            "--expected-sandbox-database-name",
            "odoo_v3_sandbox",
            "--expected-source-database-name",
            "odoo_sg",
            "--expected-company",
            "SG Company",
            "--now",
            "2026-07-28T12:30:00Z",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["authorization_record_ready"] is False
    assert payload["data"]["blockers"] == [
        "authorization record is expired",
        "immutable_summary_sha256 does not match immutable_summary",
        "source database name is not bound to this authorization",
    ]


def test_evidence_sandbox_provision_authorization_check_rejects_cross_company(
    tmp_path,
):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        __import__("json").dumps(_sandbox_authorization_document(), sort_keys=True),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-provision-authorization-check",
            "--authorization-file",
            str(authorization),
            "--expected-sandbox-database-name",
            "odoo_v3_sandbox",
            "--expected-source-database-name",
            "odoo_sg",
            "--expected-company",
            "Other Company",
            "--now",
            "2026-07-27T12:30:00Z",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["authorization_record_ready"] is False
    assert payload["data"]["blockers"] == [
        "expected company scope is not fully authorized"
    ]


def test_evidence_sandbox_onboarding_readiness_reports_ready(tmp_path):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        __import__("json").dumps(_sandbox_authorization_document(), sort_keys=True),
        encoding="utf-8",
    )

    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=READY_CURRENT_ROUTE,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-onboarding-readiness",
                "--sandbox-database-name",
                "odoo_v3_sandbox",
                "--source-database-name",
                "odoo_sg",
                "--observed-database-name",
                "odoo_v3_sandbox",
                "--authorization-file",
                str(authorization),
                "--expected-company",
                "SG Company",
                "--capacity-path",
                str(tmp_path),
                "--required-free-bytes",
                "1",
                "--now",
                "2026-07-27T12:30:00Z",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-onboarding-readiness"
    assert payload["business_succeeded"] is False
    assert payload["data"]["sandbox_onboarding_ready"] is True
    assert payload["data"]["blockers"] == []
    assert payload["data"]["capacity"]["sandbox_write_capacity_ready"] is True
    assert payload["data"]["database"]["sandbox_database_observed"] is True
    assert payload["data"]["route"]["current_route_ready"] is True
    assert payload["data"]["authorization"]["authorization_record_ready"] is True
    assert payload["data"]["postgresql_write_performed"] is False
    assert payload["data"]["real_odoo_write_performed"] is False


def test_evidence_sandbox_onboarding_readiness_reports_missing_gates(tmp_path):
    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=READY_CURRENT_ROUTE,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-onboarding-readiness",
                "--sandbox-database-name",
                "odoo_v3_sandbox",
                "--source-database-name",
                "odoo_sg",
                "--capacity-path",
                str(tmp_path),
                "--required-free-bytes",
                str(1024**5),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_onboarding_ready"] is False
    assert payload["data"]["blockers"] == [
        "sandbox database was not observed in the PostgreSQL catalog",
        "sandbox provision authorization file was not supplied",
        "sandbox write capacity gate is not ready",
    ]
    assert payload["data"]["next_required_actions"] == [
        "free or add disk capacity and rerun evidence target-capacity-recheck",
        "create or select the dedicated sandbox database and rerun sandbox-database-candidates",
        "save a valid sandbox provision authorization JSON and rerun sandbox-provision-authorization-check",
    ]


def test_evidence_sandbox_onboarding_readiness_reports_bad_current_route(tmp_path):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(
        __import__("json").dumps(_sandbox_authorization_document(), sort_keys=True),
        encoding="utf-8",
    )
    bad_route = {
        **READY_CURRENT_ROUTE,
        "blockers": ["current route commit does not match expected value"],
        "current_route_ready": False,
    }

    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=bad_route,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "sandbox-onboarding-readiness",
                "--sandbox-database-name",
                "odoo_v3_sandbox",
                "--source-database-name",
                "odoo_sg",
                "--observed-database-name",
                "odoo_v3_sandbox",
                "--authorization-file",
                str(authorization),
                "--expected-company",
                "SG Company",
                "--capacity-path",
                str(tmp_path),
                "--required-free-bytes",
                "1",
                "--now",
                "2026-07-27T12:30:00Z",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_onboarding_ready"] is False
    assert payload["data"]["blockers"] == ["current release route is not ready"]
    assert payload["data"]["route"]["blockers"] == [
        "current route commit does not match expected value"
    ]
    assert payload["data"]["next_required_actions"] == [
        "fix current release route and rerun release current-route"
    ]


def test_evidence_sandbox_onboarding_receipt_check_accepts_ready_receipt(tmp_path):
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev210",
    }
    receipt = _ready_onboarding_receipt(
        tmp_path,
        release_identity=expected_identity,
    )

    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-onboarding-receipt-check",
            "--onboarding-receipt",
            str(receipt),
            "--expected-sandbox-database-name",
            "odoo_v3_sandbox",
            "--expected-release",
            "release",
            "--expected-commit",
            "1" * 40,
            "--expected-manifest-sha256",
            "d" * 64,
            "--expected-package-sha256",
            "4" * 64,
            "--expected-registry-digest",
            "b" * 64,
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.sandbox-onboarding-receipt-check"
    assert payload["business_succeeded"] is False
    assert payload["data"]["sandbox_write_preflight_receipt_acceptable"] is True
    assert payload["data"]["onboarding"]["ready"] is True
    assert payload["data"]["onboarding"]["blockers"] == []
    assert payload["data"]["postgresql_write_performed"] is False
    assert payload["data"]["real_odoo_write_performed"] is False


def test_evidence_sandbox_onboarding_receipt_check_reports_binding_mismatch(tmp_path):
    receipt = _ready_onboarding_receipt(tmp_path)

    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "sandbox-onboarding-receipt-check",
            "--onboarding-receipt",
            str(receipt),
            "--expected-sandbox-database-name",
            "other_sandbox",
            "--expected-registry-digest",
            "c" * 64,
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_write_preflight_receipt_acceptable"] is False
    assert payload["data"]["onboarding"]["ready"] is False
    assert payload["data"]["onboarding"]["blockers"] == [
        "sandbox onboarding database does not match write runtime",
        "sandbox onboarding route registry_digest does not match write runtime release",
    ]


def test_evidence_target_capacity_plan_reports_ready_v3_owned_candidates(tmp_path):
    retained = (
        tmp_path
        / "opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-0.1.0.dev198-keep.tar.gz"
    )
    retained.parent.mkdir(parents=True, exist_ok=True)
    retained.write_bytes(b"x" * 20)
    candidate = tmp_path / "opt/odoo-accounting-cli-v3/upload-sources/source.tar.gz"
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(b"x" * 10)

    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=READY_CURRENT_ROUTE,
    ) as route_report:
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "target-capacity-plan",
                "--root",
                str(tmp_path),
                "--required-free-bytes",
                "1",
                "--keep-release",
                "0.1.0.dev198-keep",
                "--expected-release",
                READY_CURRENT_ROUTE["route_identity"]["release"],
            ],
        )

    assert result.exit_code == 0, result.output
    route_report.assert_called_once()
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.target-capacity-plan"
    assert payload["business_succeeded"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["cleanup_executed"] is False
    assert payload["data"]["authorization_required_before_cleanup"] is True
    assert payload["data"]["sandbox_write_capacity_ready"] is True
    assert payload["data"]["blockers"] == []
    assert payload["data"]["route"]["current_route_ready"] is True
    assert payload["data"]["plan"]["cleanup_executed"] is False
    assert payload["data"]["plan"]["keep_releases"] == ["0.1.0.dev198-keep"]
    assert (
        payload["data"]["plan"]["candidates"][0]["category"]
        == "uploaded_release_source"
    )


def test_evidence_target_capacity_plan_reports_shortfall_without_cleanup(tmp_path):
    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=READY_CURRENT_ROUTE,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "target-capacity-plan",
                "--root",
                str(tmp_path),
                "--required-free-bytes",
                str(1024**5),
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_write_capacity_ready"] is False
    assert payload["data"]["cleanup_executed"] is False
    assert payload["data"]["blockers"] == [
        "reviewable V3-owned cleanup candidates cannot cover the capacity shortfall",
        "target filesystem free space is below the configured floor",
    ]
    assert payload["data"]["plan"]["shortfall_bytes"] > 0


def test_evidence_target_capacity_plan_summary_omits_candidates(tmp_path):
    candidate = tmp_path / "opt/odoo-accounting-cli-v3/upload-sources/source.tar.gz"
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(b"x" * 10)

    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=READY_CURRENT_ROUTE,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "target-capacity-plan",
                "--root",
                str(tmp_path),
                "--required-free-bytes",
                "1",
                "--summary-only",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert "candidates" not in payload["data"]["plan"]
    assert payload["data"]["plan"]["candidate_count"] == 1
    assert payload["data"]["plan"]["retained_candidate_count"] == 0
    assert payload["data"]["plan"]["candidates_truncated"] is True


def test_evidence_target_capacity_plan_limits_candidates(tmp_path):
    for index in range(3):
        candidate = (
            tmp_path
            / f"opt/odoo-accounting-cli-v3/upload-sources/source-{index}.tar.gz"
        )
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_bytes(b"x" * (10 + index))

    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=READY_CURRENT_ROUTE,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "target-capacity-plan",
                "--root",
                str(tmp_path),
                "--required-free-bytes",
                "1",
                "--max-candidates",
                "2",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert len(payload["data"]["plan"]["candidates"]) == 2
    assert payload["data"]["plan"]["candidate_count"] == 3
    assert payload["data"]["plan"]["retained_candidate_count"] == 2
    assert payload["data"]["plan"]["candidates_truncated"] is True


def test_evidence_target_capacity_plan_fails_closed_on_bad_current_route(tmp_path):
    bad_route = {
        **READY_CURRENT_ROUTE,
        "blockers": ["current route package_sha256 does not match expected value"],
        "current_route_ready": False,
    }

    with patch(
        "odoo_accounting_cli_v3.cli._current_route_report",
        return_value=bad_route,
    ):
        result = CliRunner().invoke(
            main,
            [
                "evidence",
                "target-capacity-plan",
                "--root",
                str(tmp_path),
                "--required-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["sandbox_write_capacity_ready"] is False
    assert payload["data"]["blockers"] == ["current release route is not ready"]
    assert payload["data"]["route"]["current_route_ready"] is False
    assert payload["data"]["cleanup_executed"] is False
    assert payload["data"]["real_odoo_write_performed"] is False


def test_evidence_target_capacity_recheck_reports_ready(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "target-capacity-recheck",
            "--path",
            str(tmp_path),
            "--required-free-bytes",
            "1",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["command"] == "evidence.target-capacity-recheck"
    assert payload["business_succeeded"] is False
    assert payload["data"]["cleanup_executed"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["sandbox_write_capacity_ready"] is True
    assert payload["data"]["shortfall_bytes"] == 0
    assert payload["data"]["filesystem"]["available_bytes"] >= 1


def test_evidence_target_capacity_recheck_reports_shortfall(tmp_path):
    result = CliRunner().invoke(
        main,
        [
            "evidence",
            "target-capacity-recheck",
            "--path",
            str(tmp_path),
            "--required-free-bytes",
            str(1024**5),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["cleanup_executed"] is False
    assert payload["data"]["sandbox_write_capacity_ready"] is False
    assert payload["data"]["blockers"] == [
        "target filesystem free space is below the configured floor"
    ]
    assert payload["data"]["shortfall_bytes"] > 0


def _write_runtime_plan_args(
    *,
    base_runtime_path: Path,
    tmp_path: Path,
) -> list[str]:
    return [
        "evidence",
        "write-runtime-config-plan",
        "--base-runtime-config",
        str(base_runtime_path),
        "--write-runtime-config",
        str(tmp_path / "write-runtime.json"),
        "--write-state-path",
        str(tmp_path / "write-state" / "write.sqlite3"),
        "--secret-root",
        str(tmp_path / "write-secrets"),
        "--socket-group-gid",
        "991",
        "--finalizer-service-uid",
        "992",
        "--finalizer-service-gid",
        "992",
        "--attestation-key-id",
        "effect-finalizer-v1",
        "--guard-installation-id",
        "22222222-2222-4222-8222-222222222222",
        "--database-oid",
        "16384",
        "--allow-non-root-owner",
    ]


def test_evidence_write_runtime_config_plan_renders_secret_free_schema_v2(
    tmp_path: Path,
):
    _runtime_path, document, _base = make_write_runtime(tmp_path / "runtime")
    base_runtime_path = Path(document["base_runtime_config_path"])

    result = CliRunner().invoke(
        main,
        _write_runtime_plan_args(
            base_runtime_path=base_runtime_path,
            tmp_path=tmp_path,
        ),
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    planned = payload["data"]["document"]
    assert payload["command"] == "evidence.write-runtime-config-plan"
    assert payload["business_succeeded"] is False
    assert payload["data"]["real_odoo_write_performed"] is False
    assert payload["data"]["production_promotion_allowed"] is False
    assert payload["data"]["secret_values_included"] is False
    assert payload["data"]["write_runtime_configurable"] is True
    assert payload["data"]["blockers"] == []
    assert planned["schema_version"] == 2
    assert planned["write_execution_mode"] == "sandbox_staged"
    assert planned["base_runtime_config_path"] == str(base_runtime_path)
    assert planned["effect_finalizer"]["guard_installation_id"] == (
        "22222222-2222-4222-8222-222222222222"
    )
    assert planned["execution"]["issuer"] == "odoo-v3-sandbox-execution"
    assert planned["verification"]["issuer"] == "odoo-v3-sandbox-verification"
    assert planned["recovery"]["issuer"] == "odoo-v3-sandbox-recovery"
    assert "issuer" not in planned["write_auth"]
    assert planned["write_auth"]["secret_path"].endswith("write_auth.hmac")
    assert payload["data"]["document_sha256"] == __import__("hashlib").sha256(
        __import__("json")
        .dumps(
            planned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        .encode("utf-8")
    ).hexdigest()


def test_evidence_write_runtime_config_plan_reports_base_runtime_scope_blocker(
    tmp_path: Path,
):
    _runtime_path, document, base = make_write_runtime(tmp_path / "runtime")
    base_runtime_path = Path(document["base_runtime_config_path"])
    base["environment"] = "production"
    base["capability_channel"] = "enabled"
    write_runtime_json(base_runtime_path, base)

    result = CliRunner().invoke(
        main,
        _write_runtime_plan_args(
            base_runtime_path=base_runtime_path,
            tmp_path=tmp_path,
        ),
    )

    assert result.exit_code == 0, result.output
    payload = __import__("json").loads(result.output)
    assert payload["data"]["write_runtime_configurable"] is False
    assert payload["data"]["blockers"] == [
        "sandbox_staged write runtime requires a staged sandbox base runtime"
    ]


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
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev163",
    }
    onboarding_receipt = _ready_onboarding_receipt(
        tmp_path,
        database_name="codex_cn_m31_demo_01",
        release_identity=expected_identity,
    )

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
                "--onboarding-receipt",
                str(onboarding_receipt),
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
    onboarding_receipt = _ready_onboarding_receipt(tmp_path)

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
            "--onboarding-receipt",
            str(onboarding_receipt),
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
    expected_identity = {
        "commit": "1" * 40,
        "manifest_sha256": "d" * 64,
        "package_sha256": "4" * 64,
        "registry_digest": "b" * 64,
        "release": "release",
        "verified": True,
        "version": "0.1.0.dev163",
    }
    onboarding_receipt = _ready_onboarding_receipt(
        tmp_path,
        release_identity=expected_identity,
    )

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
                "--onboarding-receipt",
                str(onboarding_receipt),
                "--min-free-bytes",
                "1",
            ],
        )

    assert result.exit_code == 5
    assert '"code":"sandbox_write_evidence_root_rejected"' in result.output

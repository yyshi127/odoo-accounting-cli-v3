from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import odoo_accounting_cli_v3.cli as cli_module


V2_SCHEMA = "odoo-accounting-cli-v3.read-evidence-index.v2"
V3_SCHEMA = "odoo-accounting-cli-v3.read-evidence-index.v3"
EXPECTED_IDENTITY = {
    "commit": "1" * 40,
    "manifest_sha256": "2" * 64,
    "package_sha256": "3" * 64,
    "registry_digest": "4" * 64,
    "release": "0.1.0.dev263-111111111111",
    "verified": True,
    "version": "0.1.0.dev263",
}


@pytest.fixture(autouse=True)
def _root_managed_schema_snapshot(monkeypatch: pytest.MonkeyPatch):
    def read_snapshot(
        path: Path,
        label: str,
        *,
        maximum: int,
        require_root_owner: bool,
    ) -> tuple[bytes, tuple[int, int]]:
        assert label == "read evidence index schema snapshot"
        assert maximum == cli_module.READ_EVIDENCE_V3_MAX_INDEX_BYTES
        assert require_root_owner is True
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise cli_module.HistoricalRouterError(
                "read evidence index schema snapshot cannot be verified"
            ) from exc
        if len(raw) > maximum:
            raise cli_module.HistoricalRouterError(
                "read evidence index schema snapshot exceeds its size limit"
            )
        return raw, (1, 1)

    monkeypatch.setattr(cli_module, "_read_trusted_file", read_snapshot)


def _write_canonical(path: Path, document: dict[str, object]) -> None:
    path.write_bytes(
        (
            json.dumps(
                document,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    )


def _capabilities():
    return cli_module._load_capabilities()


def test_external_read_evidence_dispatches_exact_v3_to_active_v3_verifier(
    tmp_path: Path,
):
    index = tmp_path / "index.json"
    _write_canonical(index, {"schema_version": V3_SCHEMA})
    verified = {
        "blockers": [],
        "external_read_evidence_verified": True,
        "goal_evidence_admissible": True,
        "index_kind": V3_SCHEMA,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
    }

    with patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3",
        return_value=verified,
    ) as v3_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index"
    ) as legacy_verifier:
        report = cli_module._external_read_evidence_report(
            index,
            expected_release_identity=EXPECTED_IDENTITY,
            capabilities=_capabilities(),
        )

    assert report == verified
    legacy_verifier.assert_not_called()
    assert v3_verifier.call_args.args == (index,)
    assert v3_verifier.call_args.kwargs["expected_release_identity"] == EXPECTED_IDENTITY
    assert "expected_capability_contracts" not in v3_verifier.call_args.kwargs
    assert "mode" not in v3_verifier.call_args.kwargs


def test_external_read_evidence_keeps_exact_v2_on_legacy_verifier(tmp_path: Path):
    index = tmp_path / "read-evidence-index.json"
    _write_canonical(index, {"schema_version": V2_SCHEMA})
    legacy_verifier_report = {
        "blockers": [],
        "external_read_evidence_verified": True,
        "goal_evidence_admissible": True,
        "index_kind": V2_SCHEMA,
        "production_promotion_allowed": True,
        "real_odoo_write_performed": False,
    }

    with patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index",
        return_value=legacy_verifier_report,
    ) as legacy_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3"
    ) as v3_verifier:
        report = cli_module._external_read_evidence_report(
            index,
            expected_release_identity=EXPECTED_IDENTITY,
            capabilities=_capabilities(),
        )

    assert report is not None
    assert report["evidence_protocol"] == "hmac-v2"
    assert report["external_read_evidence_verified"] is False
    assert report["goal_evidence_admissible"] is False
    assert report["production_promotion_allowed"] is False
    assert report["legacy_v2_structural_audit_verified"] is True
    assert cli_module.LEGACY_V2_BLOCKER in report["blockers"]
    readiness = cli_module._read_capabilities_readiness_report(
        _capabilities(),
        trusted_read_handlers=cli_module._load_read_capability_implementation(
            "evidence.read-capabilities-readiness"
        ),
        external_evidence_report=report,
    )
    assert readiness["external_read_evidence_verifier_ready"] is False
    assert readiness["goal_evidence_ready_count"] == 0
    assert readiness["read_goal_readiness_ready"] is False
    v3_verifier.assert_not_called()
    assert legacy_verifier.call_args.args == (index,)
    assert legacy_verifier.call_args.kwargs["expected_release_identity"] == EXPECTED_IDENTITY
    assert set(legacy_verifier.call_args.kwargs["expected_capability_contracts"]) == {
        capability.id
        for capability in _capabilities()
        if capability.data["access"] == "read"
    }
    assert "mode" not in legacy_verifier.call_args.kwargs


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v99"}\n',
        (
            b'{"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v3",'
            b'"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v2"}\n'
        ),
        b'{"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v3","x":NaN}\n',
    ],
)
def test_external_read_evidence_rejects_unknown_or_corrupt_schema_without_downgrade(
    tmp_path: Path,
    raw: bytes,
):
    index = tmp_path / "index.json"
    index.write_bytes(raw)

    with patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index"
    ) as legacy_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3"
    ) as v3_verifier:
        report = cli_module._external_read_evidence_report(
            index,
            expected_release_identity=EXPECTED_IDENTITY,
            capabilities=_capabilities(),
        )

    assert report is not None
    assert report["external_read_evidence_verified"] is False
    assert report["production_promotion_allowed"] is False
    assert report["blockers"]
    legacy_verifier.assert_not_called()
    v3_verifier.assert_not_called()


def test_read_evidence_index_check_uses_active_only_v3_api(tmp_path: Path):
    index = tmp_path / "index.json"
    _write_canonical(index, {"schema_version": V3_SCHEMA})
    verified = {
        "blockers": [],
        "external_read_evidence_verified": True,
        "goal_evidence_admissible": True,
        "index_kind": V3_SCHEMA,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
    }

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=EXPECTED_IDENTITY,
    ) as identity_loader, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3",
        return_value=verified,
    ) as v3_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index"
    ) as legacy_verifier:
        result = CliRunner().invoke(
            cli_module.main,
            [
                "evidence",
                "read-evidence-index-check",
                "--evidence-index",
                str(index),
            ],
        )

    assert result.exit_code == 0, result.output
    identity_loader.assert_called_once_with(
        command="evidence.read-evidence-index-check"
    )
    legacy_verifier.assert_not_called()
    assert v3_verifier.call_args.args == (index,)
    assert "expected_capability_contracts" not in v3_verifier.call_args.kwargs
    assert "mode" not in v3_verifier.call_args.kwargs


def test_read_evidence_index_check_loads_execution_identity_before_index_io(
    tmp_path: Path,
):
    index = tmp_path / "index.json"
    _write_canonical(index, {"schema_version": V3_SCHEMA})
    identity_failure = cli_module.CliFailure(
        command="evidence.read-evidence-index-check",
        code="release_identity_rejected",
        message="executing release identity rejected",
        exit_code=5,
    )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        side_effect=identity_failure,
    ), patch("odoo_accounting_cli_v3.cli._read_trusted_file") as index_reader, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index"
    ) as legacy_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3"
    ) as v3_verifier:
        result = CliRunner().invoke(
            cli_module.main,
            [
                "evidence",
                "read-evidence-index-check",
                "--evidence-index",
                str(index),
            ],
        )

    assert result.exit_code == 5
    assert json.loads(result.output)["error"]["code"] == "release_identity_rejected"
    index_reader.assert_not_called()
    legacy_verifier.assert_not_called()
    v3_verifier.assert_not_called()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v99"}\n',
        (
            b'{"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v3",'
            b'"schema_version":"odoo-accounting-cli-v3.read-evidence-index.v2"}\n'
        ),
    ],
)
def test_read_evidence_index_check_structurally_rejects_invalid_schema_without_verifier(
    tmp_path: Path,
    raw: bytes,
):
    index = tmp_path / "index.json"
    index.write_bytes(raw)

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=EXPECTED_IDENTITY,
    ), patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index"
    ) as legacy_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3"
    ) as v3_verifier:
        result = CliRunner().invoke(
            cli_module.main,
            [
                "evidence",
                "read-evidence-index-check",
                "--evidence-index",
                str(index),
            ],
        )

    assert result.exit_code == 5
    payload = json.loads(result.output)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "read_evidence_index_rejected"
    legacy_verifier.assert_not_called()
    v3_verifier.assert_not_called()


def test_read_evidence_index_check_does_not_default_missing_index_to_legacy(
    tmp_path: Path,
):
    index = tmp_path / "missing-index.json"

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=EXPECTED_IDENTITY,
    ), patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index"
    ) as legacy_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3"
    ) as v3_verifier:
        result = CliRunner().invoke(
            cli_module.main,
            [
                "evidence",
                "read-evidence-index-check",
                "--evidence-index",
                str(index),
            ],
        )

    assert result.exit_code == 5
    assert json.loads(result.output)["error"]["code"] == "read_evidence_index_rejected"
    legacy_verifier.assert_not_called()
    v3_verifier.assert_not_called()


def test_read_evidence_index_check_does_not_downgrade_v3_after_snapshot_swap(
    tmp_path: Path,
):
    index = tmp_path / "index.json"
    _write_canonical(index, {"schema_version": V3_SCHEMA})

    def swap_to_v2_and_reject(*_args, **_kwargs):
        _write_canonical(index, {"schema_version": V2_SCHEMA})
        raise cli_module.ReadEvidenceV3Error("v3 index schema changed after dispatch")

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=EXPECTED_IDENTITY,
    ), patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3",
        side_effect=swap_to_v2_and_reject,
    ) as v3_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index"
    ) as legacy_verifier:
        result = CliRunner().invoke(
            cli_module.main,
            [
                "evidence",
                "read-evidence-index-check",
                "--evidence-index",
                str(index),
            ],
        )

    assert result.exit_code == 5
    assert json.loads(result.output)["error"]["code"] == "read_evidence_index_rejected"
    v3_verifier.assert_called_once()
    legacy_verifier.assert_not_called()


def test_read_evidence_index_check_does_not_upgrade_v2_after_snapshot_swap(
    tmp_path: Path,
):
    index = tmp_path / "read-evidence-index.json"
    _write_canonical(index, {"schema_version": V2_SCHEMA})

    def swap_to_v3_and_reject(*_args, **_kwargs):
        _write_canonical(index, {"schema_version": V3_SCHEMA})
        raise cli_module.ReadEvidenceIndexError(
            "legacy index schema changed after dispatch"
        )

    with patch(
        "odoo_accounting_cli_v3.cli._load_release_identity",
        return_value=EXPECTED_IDENTITY,
    ), patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_index",
        side_effect=swap_to_v3_and_reject,
    ) as legacy_verifier, patch(
        "odoo_accounting_cli_v3.cli.verify_read_evidence_v3"
    ) as v3_verifier:
        result = CliRunner().invoke(
            cli_module.main,
            [
                "evidence",
                "read-evidence-index-check",
                "--evidence-index",
                str(index),
            ],
        )

    assert result.exit_code == 5
    assert json.loads(result.output)["error"]["code"] == "read_evidence_index_rejected"
    legacy_verifier.assert_called_once()
    v3_verifier.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--mode", "sealed"],
        ["--clock", "caller-controlled"],
        ["--now", "2026-08-03T00:00:00Z"],
        ["--trust-root", "/tmp/caller-trust"],
        ["--require-root-owner", "false"],
    ],
)
def test_read_evidence_index_check_rejects_caller_controlled_v3_trust_options(
    arguments: list[str],
):
    result = CliRunner().invoke(
        cli_module.main,
        [
            "evidence",
            "read-evidence-index-check",
            "--evidence-index",
            "/evidence/index.json",
            *arguments,
        ],
    )

    assert result.exit_code == 2
    assert "No such option" in result.output

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.odoo import runner as runner_module
from odoo_accounting_cli_v3.odoo.runner import (
    OdooRunnerError,
    RuntimeConfig,
    run_read_boundary_evidence,
)


DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
RELEASE_DIGEST = "a" * 64


def runtime_config(tmp_path: Path) -> RuntimeConfig:
    release_root = tmp_path / "releases" / "0.1.0.dev29-123456789abc"
    package = tmp_path / "packages" / f"odoo-accounting-cli-v3-{release_root.name}.tar.gz"
    (tmp_path / "state").mkdir()
    return RuntimeConfig(
        instance_id="odoo19@test",
        environment="test",
        capability_channel="staged",
        database_name="odoo_test",
        database_uuid=DATABASE_UUID,
        odoo_python=tmp_path / "bin" / "python3",
        odoo_python_sha256="1" * 64,
        odoo_bin=tmp_path / "bin" / "odoo",
        odoo_bin_sha256="2" * 64,
        odoo_config=tmp_path / "etc" / "odoo.conf",
        odoo_config_sha256="3" * 64,
        release_root=release_root,
        canonical_package_path=package,
        canonical_package_sha256="4" * 64,
        auth_state_path=tmp_path / "state" / "auth.sqlite3",
        receipt_state_path=tmp_path / "state" / "receipt.sqlite3",
        auth_key_id="auth-v1",
        receipt_key_id="receipt-v1",
        auth_secret_path=tmp_path / "secrets" / "auth.hmac",
        receipt_secret_path=tmp_path / "secrets" / "receipt.hmac",
    )


def valid_evidence() -> dict:
    marker_one = "1" * 64
    marker_two = "2" * 64
    relation = {"filenode": 8181, "oid": 4242, "row_count": 7}
    drift = {
        name: {
            "canary_sha256": digest * 64,
            "idle_after_cleanup": True,
            "rejected": True,
            "result_released": False,
        }
        for name, digest in (
            ("hidden_commit", "3"),
            ("hidden_rollback", "4"),
            ("rollback_hook_reopen", "5"),
        )
    }
    return {
        "checks": {
            "backend_pid_unchanged": True,
            "database_name_unchanged": True,
            "database_uuid_unchanged": True,
            "relation_filenode_unchanged": True,
            "relation_oid_unchanged": True,
            "relation_row_count_unchanged": True,
        },
        "database": {
            "after": {
                "backend_pid": 9911,
                "name": "odoo_test",
                "uuid": DATABASE_UUID,
            },
            "before": {
                "backend_pid": 9911,
                "name": "odoo_test",
                "uuid": DATABASE_UUID,
            },
        },
        "drift_probes": drift,
        "relation": {
            "after": dict(relation),
            "before": dict(relation),
            "name": "ir_config_parameter",
            "schema": "public",
        },
        "schema_version": "odoo-accounting-cli-v3.read-boundary-evidence.v1",
        "successful_transactions": {
            "after": {
                "idle_after_rollback": True,
                "isolation": "repeatable read",
                "marker_sha256": marker_two,
                "read_only": True,
            },
            "before": {
                "idle_after_rollback": True,
                "isolation": "repeatable read",
                "marker_sha256": marker_one,
                "read_only": True,
            },
        },
        "write_probe": {
            "idle_after_rollback": True,
            "rejected": True,
            "sqlstate": "25006",
            "statement_id": "ir-config-parameter-noop-update-v1",
        },
    }


def response(config: RuntimeConfig, evidence: dict | None = None) -> dict:
    return {
        "ok": True,
        "runtime": config.runtime_identity,
        "result": evidence or valid_evidence(),
    }


def test_runner_verifies_exact_release_and_uses_payload_without_auth_or_receipt_state(
    tmp_path: Path,
):
    config = runtime_config(tmp_path)
    observed_payload: dict = {}
    observed_environment: dict = {}
    observed_argv: list[str] = []

    def child_process(argv, *, source, payload_fd, env, **_kwargs):
        observed_argv[:] = list(argv)
        os.lseek(payload_fd, 0, os.SEEK_SET)
        observed_payload.update(json.loads(os.read(payload_fd, 65536)))
        observed_environment.update(env)
        marker = source.rsplit("_evidence_child_main(env, ", 1)[1].split(", ", 1)[1]
        marker = marker.split(")", 1)[0].strip().strip("'\"")
        stdout = marker + canonical_json(response(config)).decode("utf-8") + "\n"
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    with patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_canonical_package_binding"
    ) as package_binding, patch(
        "odoo_accounting_cli_v3.odoo.runner._verify_child_release"
    ) as release_verification, patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_runtime_execution_paths"
    ) as runtime_paths, patch(
        "odoo_accounting_cli_v3.odoo.runner._run_child_process",
        side_effect=child_process,
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner.load_runtime_secrets"
    ) as secrets_loader:
        result = run_read_boundary_evidence(
            config,
            release_digest=RELEASE_DIGEST,
            timeout_seconds=10,
        )

    assert result == valid_evidence()
    package_binding.assert_called_once_with(config)
    release_verification.assert_called_once_with(
        config.release_root,
        RELEASE_DIGEST,
        config.canonical_package_path,
        config.canonical_package_sha256,
    )
    runtime_paths.assert_called_once_with(config)
    secrets_loader.assert_not_called()
    assert set(observed_payload) == {
        "canonical_package_path",
        "canonical_package_sha256",
        "protocol",
        "release_digest",
        "release_root",
        "runtime",
    }
    assert not any(key.startswith("GCOV_") for key in observed_environment)
    assert observed_argv[:2] == [str(config.odoo_python), "-c"]
    assert "shell" not in observed_argv
    assert "traceback.print_exc(file=sys.stderr)" in observed_argv[2]
    assert "sys.modules['_rjsmin'] = None" in observed_argv[2]
    assert "__OACV3_LAUNCHER_CHECKPOINT__" not in observed_argv[2]
    assert "--logfile=/proc/self/fd/2" not in observed_argv[2]
    assert "Registry.new" in observed_argv[2]
    assert "update_module=False" in observed_argv[2]
    assert "odoo_loading.reset_modules_state = _odoo_accounting_cli_v3_noop_reset_modules_state" in observed_argv[2]
    assert not any("auth" in key or "receipt" in key or "state" in key for key in observed_payload)


def test_runner_can_emit_launcher_diagnostics_when_requested(tmp_path: Path):
    config = runtime_config(tmp_path)
    observed_argv: list[str] = []

    def child_process(argv, *, source, payload_fd, **_kwargs):
        observed_argv[:] = list(argv)
        marker = source.rsplit("_evidence_child_main(env, ", 1)[1].split(", ", 1)[1]
        marker = marker.split(")", 1)[0].strip().strip("'\"")
        stdout = marker + canonical_json(response(config)).decode("utf-8") + "\n"
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    with patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_canonical_package_binding"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._verify_child_release"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_runtime_execution_paths"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._run_child_process",
        side_effect=child_process,
    ):
        result = run_read_boundary_evidence(
            config,
            release_digest=RELEASE_DIGEST,
            launcher_diagnostics=True,
        )

    assert result == valid_evidence()
    assert "__OACV3_LAUNCHER_CHECKPOINT__" in observed_argv[2]
    diagnostic_log = config.auth_state_path.parent / "read-boundary-launcher-diagnostics.log"
    escaped_diagnostic_log = str(diagnostic_log).replace("\\", "\\\\")
    assert f"--logfile={escaped_diagnostic_log}" in observed_argv[2]
    assert f"_oacv3_diagnostic_log_path = {str(diagnostic_log)!r}" in observed_argv[2]
    assert "_oacv3_checkpoint('before_registry_new')" in observed_argv[2]


def test_runner_reports_child_stderr_only_for_launcher_diagnostics(tmp_path: Path):
    config = runtime_config(tmp_path)

    def child_process(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="",
            stderr="private odoo registry failure",
        )

    with patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_canonical_package_binding"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._verify_child_release"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_runtime_execution_paths"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._run_child_process",
        side_effect=child_process,
    ):
        with pytest.raises(OdooRunnerError, match="Odoo shell exited with status 1$"):
            run_read_boundary_evidence(config, release_digest=RELEASE_DIGEST)
        with pytest.raises(OdooRunnerError, match="private odoo registry failure"):
            run_read_boundary_evidence(
                config,
                release_digest=RELEASE_DIGEST,
                launcher_diagnostics=True,
            )


def test_runner_rejects_response_runtime_mismatch(tmp_path: Path):
    config = runtime_config(tmp_path)
    changed = response(config)
    changed["runtime"] = {**config.runtime_identity, "database_name": "other_db"}

    def child_process(argv, *, source, **_kwargs):
        marker = source.rsplit("_evidence_child_main(env, ", 1)[1].split(", ", 1)[1]
        marker = marker.split(")", 1)[0].strip().strip("'\"")
        stdout = marker + canonical_json(changed).decode("utf-8") + "\n"
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    with patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_canonical_package_binding"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._verify_child_release"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_runtime_execution_paths"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._run_child_process",
        side_effect=child_process,
    ):
        with pytest.raises(OdooRunnerError, match="runtime identity does not match"):
            run_read_boundary_evidence(config, release_digest=RELEASE_DIGEST)


def test_runner_rejects_evidence_database_binding_mismatch(tmp_path: Path):
    config = runtime_config(tmp_path)
    changed = valid_evidence()
    changed["database"]["after"] = {
        "backend_pid": 9911,
        "name": "other_db",
        "uuid": DATABASE_UUID,
    }

    def child_process(argv, *, source, **_kwargs):
        marker = source.rsplit("_evidence_child_main(env, ", 1)[1].split(", ", 1)[1]
        marker = marker.split(")", 1)[0].strip().strip("'\"")
        stdout = marker + canonical_json(response(config, changed)).decode("utf-8") + "\n"
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    with patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_canonical_package_binding"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._verify_child_release"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._validate_runtime_execution_paths"
    ), patch(
        "odoo_accounting_cli_v3.odoo.runner._run_child_process",
        side_effect=child_process,
    ):
        with pytest.raises(OdooRunnerError, match="evidence is invalid"):
            run_read_boundary_evidence(config, release_digest=RELEASE_DIGEST)


@pytest.mark.parametrize(
    ("environment", "channel"),
    (("production", "enabled"), ("test", "enabled")),
)
def test_runner_rejects_non_staged_test_scope_before_spawning_child(
    tmp_path: Path, environment: str, channel: str
):
    config = replace(
        runtime_config(tmp_path),
        environment=environment,
        capability_channel=channel,
    )
    with patch("odoo_accounting_cli_v3.odoo.runner._run_child_process") as child:
        with pytest.raises(OdooRunnerError, match="staged test runtime"):
            run_read_boundary_evidence(config, release_digest=RELEASE_DIGEST)
    child.assert_not_called()


@pytest.mark.parametrize(
    ("environment", "channel"),
    (("production", "enabled"), ("test", "enabled")),
)
@pytest.mark.skipif(os.name != "posix", reason="Odoo child paths are POSIX-only")
def test_evidence_child_rechecks_staged_test_scope_before_release_or_database_access(
    tmp_path: Path, environment: str, channel: str
):
    config = replace(
        runtime_config(tmp_path),
        environment=environment,
        capability_channel=channel,
    )
    payload = canonical_json(
        {
            "canonical_package_path": str(config.canonical_package_path),
            "canonical_package_sha256": config.canonical_package_sha256,
            "protocol": 1,
            "release_digest": RELEASE_DIGEST,
            "release_root": str(config.release_root),
            "runtime": config.runtime_identity,
        }
    )
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, payload)
    finally:
        os.close(write_fd)
    marker = "__ODOO_ACCOUNTING_CLI_V3_RESULT_" + "1" * 48 + "__:"
    with patch(
        "odoo_accounting_cli_v3.odoo.runner._verify_child_release"
    ) as release_verification, patch(
        "odoo_accounting_cli_v3.odoo.read_boundary_evidence.collect_read_boundary_evidence"
    ) as collector:
        with pytest.raises(OdooRunnerError, match="staged test runtime"):
            runner_module._evidence_child_main(object(), read_fd, marker)
    release_verification.assert_not_called()
    collector.assert_not_called()

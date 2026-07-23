from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from odoo_accounting_cli_v3.auth import authentication_request_digest
from odoo_accounting_cli_v3.effect_finalizer import EffectFinalizationIdentity
from odoo_accounting_cli_v3.effect_finalizer_runtime import (
    EffectFinalizerClientRuntime,
)
from odoo_accounting_cli_v3.effect_finalizer_uds import (
    EffectFinalizerConnectedClient,
)
from odoo_accounting_cli_v3.registry import Capability
from odoo_accounting_cli_v3.write_runtime import (
    WRITE_RUNTIME_SCHEMA_VERSION,
    WriteRoleConfig,
    WriteRuntimeConfig,
    WriteRuntimeSecrets,
)
from odoo_accounting_cli_v3.odoo import runner as base_runner
from odoo_accounting_cli_v3.odoo import write_runner as runner
from odoo_accounting_cli_v3.odoo.runner import OdooRunnerError, RuntimeConfig


RELEASE_DIGEST = "d" * 64
MARKER_TOKEN = "a" * 48
MARKER = f"__ODOO_ACCOUNTING_CLI_V3_RESULT_{MARKER_TOKEN}__:"
SECRET_VALUES = {
    "write_auth": b"write-auth-secret-material-0000000001",
    "approval": b"approval-secret-material-000000000002",
    "execution": b"execution-secret-material-00000000001",
    "verification": b"verification-secret-material-0000001",
    "recovery": b"recovery-secret-material-000000000002",
    "write_receipt": b"write-receipt-secret-material-000001",
}
LINUX_FD_EVIDENCE = (
    sys.platform == "linux"
    and hasattr(os, "memfd_create")
    and Path("/proc/self/fd").is_dir()
)


def _effect_finalizer() -> EffectFinalizerClientRuntime:
    return EffectFinalizerClientRuntime(
        socket_path="/run/odoo-accounting-cli-v3/effect-finalizer.sock",
        socket_owner_uid=0,
        socket_group_gid=991,
        socket_mode=0o660,
        finalizer_service_uid=992,
        finalizer_service_gid=992,
        finalizer_systemd_unit="odoo-accounting-cli-v3-effect-finalizer.service",
        finalization_identity=EffectFinalizationIdentity(
            attestation_key_id="effect-finalizer-v1",
            guard_installation_id="22222222-2222-4222-8222-222222222222",
            database_oid=16384,
        ),
        handoff_idle_timeout_seconds=100,
        request_io_timeout_seconds=5,
        max_request_bytes=16_384,
        max_response_bytes=16_384,
    )


def _runtime(tmp_path: Path) -> tuple[WriteRuntimeConfig, WriteRuntimeSecrets]:
    base = RuntimeConfig(
        instance_id="odoo19@sandbox",
        environment="sandbox",
        capability_channel="staged",
        database_name="odoo_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        odoo_python=tmp_path / "python",
        odoo_python_sha256="1" * 64,
        odoo_bin=tmp_path / "odoo-bin",
        odoo_bin_sha256="2" * 64,
        odoo_config=tmp_path / "odoo.conf",
        odoo_config_sha256="3" * 64,
        release_root=tmp_path / "release",
        canonical_package_path=tmp_path / "package.tar.gz",
        canonical_package_sha256="4" * 64,
        auth_state_path=tmp_path / "read-auth.sqlite3",
        receipt_state_path=tmp_path / "read-receipt.sqlite3",
        auth_key_id="read-auth-v1",
        receipt_key_id="read-receipt-v1",
        auth_secret_path=tmp_path / "read-auth.hmac",
        receipt_secret_path=tmp_path / "read-receipt.hmac",
    )
    base.gcov_state_path.mkdir(mode=0o700, exist_ok=True)
    base.gcov_state_path.chmod(0o700)
    roles = {
        name: WriteRoleConfig(
            key_id=f"{name}-v1",
            secret_path=tmp_path / f"{name}.hmac",
            issuer=(f"{name}-issuer" if name in {"execution", "verification", "recovery"} else None),
        )
        for name in SECRET_VALUES
    }
    config = WriteRuntimeConfig(
        schema_version=WRITE_RUNTIME_SCHEMA_VERSION,
        write_execution_mode="sandbox_staged",
        base_runtime_config_path=tmp_path / "read-runtime.json",
        write_state_path=tmp_path / "write.sqlite3",
        effect_finalizer=_effect_finalizer(),
        base_runtime=base,
        config_fingerprint="f" * 64,
        _require_root_owner=False,
        **roles,
    )
    return config, WriteRuntimeSecrets(**SECRET_VALUES)


def _precheck_result() -> dict[str, object]:
    return {
        "capability_id": "acct.invoice.customer.create.v1",
        "company_id": 7,
        "parameters_digest": "1" * 64,
        "passed": True,
        "checks": ["acl", "company"],
        "handler_details": {},
        "runtime_binding": {
            "user_id": 11,
            "odoo_instance_id": "odoo19@sandbox",
            "database_name": "odoo_v3_sandbox",
            "database_uuid": "11111111-1111-4111-8111-111111111111",
            "environment": "sandbox",
            "capability_channel": "staged",
        },
        "registry_digest": "2" * 64,
        "release_digest": RELEASE_DIGEST,
    }


def _approved_result() -> dict[str, object]:
    return {
        "reconciliation_only": False,
        "execution": {
            "result": {"kind": "execution", "succeeded": True},
            "evidence": {"odoo_records": [{"model": "account.move", "record_id": 91}]},
        },
        "verification": {
            "result": {"kind": "verification", "succeeded": True},
            "evidence": {"passed": True, "readback": {"record_id": 91}},
        },
    }


def _approver_result() -> dict[str, object]:
    return {
        "authorized": True,
        "approver_user_id": 22,
        "company_id": 7,
        "capability_id": "acct.invoice.customer.create.v1",
        "runtime_binding": {},
        "registry_digest": "2" * 64,
        "release_digest": RELEASE_DIGEST,
    }


def _executor_result() -> dict[str, object]:
    return {
        "authorized": True,
        "user_id": 11,
        "company_id": 7,
        "capability_id": "acct.invoice.customer.create.v1",
        "missing_groups": [],
        "runtime_binding": {},
        "registry_digest": "2" * 64,
        "release_digest": RELEASE_DIGEST,
    }


def _module_guard_evidence(config: WriteRuntimeConfig) -> dict[str, object]:
    return {
        "guard_protocol_version": 1,
        "database_name": config.base_runtime.database_name,
        "database_uuid": config.base_runtime.database_uuid,
        "backend_pid": 4101,
        "backend_start": "2026-07-18T01:02:03.000000Z",
        "advisory_lock": {
            "namespace": 1329677142,
            "key": 1297040433,
            "mode": "shared",
        },
        "table_lock": {
            "relation": "public.ir_module_module",
            "mode": "SHARE",
        },
        "module_graph": {
            "schema_version": 1,
            "modules": [
                {"name": "account", "latest_version": "19.0.1.0"}
            ],
            "digest": (
                "c329d2eca5c679e3cc3e72e9e9eebebfea8f798c4aa587c0e25fabe13b38988a"
            ),
        },
    }


def _mock_parent_boundary(monkeypatch, config, result, captured):
    monkeypatch.setattr(runner, "_validate_canonical_package_binding", Mock())
    monkeypatch.setattr(runner, "_verify_child_release", Mock(return_value=()))
    monkeypatch.setattr(runner, "_validate_runtime_paths", Mock())
    monkeypatch.setattr(runner.secret_tokens, "token_hex", Mock(return_value=MARKER_TOKEN))

    @contextmanager
    def private_payload(payload: bytes):
        captured["payload_bytes"] = payload
        yield 17

    def run_child(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        response = {
            "ok": True,
            "action": json.loads(captured["payload_bytes"])["action"],
            "runtime": config.runtime_identity,
            "result": result,
        }
        return subprocess.CompletedProcess(
            argv, 0, stdout=MARKER + json.dumps(response, separators=(",", ":")) + "\n", stderr=""
        )

    monkeypatch.setattr(runner, "_private_payload_fd", private_payload)
    monkeypatch.setattr(runner, "_run_child_process", run_child)

    class ParentGuard:
        evidence = _module_guard_evidence(config)

        def final_probe(self, *, timeout_seconds):
            captured.setdefault("guard_events", []).append(
                ("final_probe", timeout_seconds)
            )
            return self.evidence

        def release(self, *, timeout_seconds):
            captured.setdefault("guard_events", []).append(
                ("release", timeout_seconds)
            )

        def abort(self):
            captured.setdefault("guard_events", []).append(("abort", None))

    def acquire_guard(base, *, timeout_seconds, lock_timeout_ms):
        assert base is config.base_runtime
        captured.setdefault("guard_events", []).append(
            ("acquire", timeout_seconds, lock_timeout_ms)
        )
        return ParentGuard()

    monkeypatch.setattr(
        runner, "acquire_module_guard", acquire_guard, raising=False
    )


@pytest.mark.skipif(
    not LINUX_FD_EVIDENCE,
    reason="requires Linux /proc file-descriptor evidence and memfd_create",
)
@pytest.mark.parametrize("force_inheritable", [False, True])
def test_real_odoo_child_receives_guard_payload_but_not_finalizer_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    force_inheritable: bool,
) -> None:
    """Prove the exact runner allowlist across both Linux exec boundaries."""

    config, secrets = _runtime(tmp_path)
    finalizer_runtime = config.effect_finalizer
    handoff_socket, finalizer_peer = socket.socketpair()
    handoff_descriptor = handoff_socket.detach()
    finalizer_client = EffectFinalizerConnectedClient.from_inherited_fd(
        handoff_descriptor,
        expected_identity=finalizer_runtime.finalization_identity,
        response_sender_policy=lambda _peer: True,
        request_io_timeout_seconds=(
            finalizer_runtime.request_io_timeout_seconds
        ),
        max_request_bytes=finalizer_runtime.max_request_bytes,
        max_response_bytes=finalizer_runtime.max_response_bytes,
    )
    try:
        finalizer_descriptor = finalizer_client.fileno()
        assert finalizer_descriptor > 2
        assert finalizer_client.is_inheritable() is False
        os.set_inheritable(finalizer_descriptor, force_inheritable)
        finalizer_metadata = os.fstat(finalizer_descriptor)
        module_guard = _module_guard_evidence(config)
        payload = runner.canonical_json(
            {
                "protocol": runner.WRITE_CHILD_PROTOCOL_VERSION,
                "action": runner.ACTION_APPROVED_WRITE,
                "runtime": config.runtime_identity,
                "request_json": runner._normalize_request_json(
                    {
                        "context": {"signed": "fd-isolation-test"},
                        "capability_id": "acct.invoice.customer.create.v1",
                        "parameters": {"company_id": 7},
                    }
                ),
                "credentials": runner._credentials(
                    config, secrets, runner.ACTION_APPROVED_WRITE
                ),
                "release_digest": RELEASE_DIGEST,
                "canonical_package_path": str(
                    config.base_runtime.canonical_package_path
                ),
                "canonical_package_sha256": (
                    config.base_runtime.canonical_package_sha256
                ),
                "release_root": str(config.base_runtime.release_root),
                "module_guard": module_guard,
            }
        )
        child_code = (
            "import json,os,sys,time\n"
            "payload_fd=int(sys.argv[1])\n"
            "payload_identity=(int(sys.argv[2]),int(sys.argv[3]))\n"
            "finalizer_identity=(int(sys.argv[4]),int(sys.argv[5]))\n"
            "def identities():\n"
            "    root='/proc/self/fd'\n"
            "    result=[]\n"
            "    for name in os.listdir(root):\n"
            "        try:\n"
            "            metadata=os.stat(f'{root}/{name}')\n"
            "        except OSError:\n"
            "            continue\n"
            "        result.append((metadata.st_dev,metadata.st_ino))\n"
            "    return result\n"
            "self_fds=identities()\n"
            "payload_metadata=os.fstat(payload_fd)\n"
            "payload=json.loads(os.read(payload_fd,1048577))\n"
            "print(json.dumps({\n"
            "    'self_finalizer_count':self_fds.count(finalizer_identity),\n"
            "    'self_payload_count':self_fds.count(payload_identity),\n"
            "    'payload_fd_identity':[payload_metadata.st_dev,payload_metadata.st_ino],\n"
            "    'action':payload['action'],\n"
            "    'runtime_schema':payload['runtime']['write_runtime_schema_version'],\n"
            "    'guard_digest':payload['module_guard']['module_graph']['digest'],\n"
            "},sort_keys=True))\n"
            "time.sleep(0.5)\n"
        )
        environment = runner._safe_environment()
        environment_validator = Mock()
        monkeypatch.setattr(
            base_runner, "_validate_child_environment", environment_validator
        )
        with runner._private_payload_fd(payload) as payload_descriptor:
            payload_metadata = os.fstat(payload_descriptor)
            real_popen = base_runner.subprocess.Popen
            supervisor_evidence: dict[str, int] = {}

            def observed_supervisor_spawn(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                identities: list[tuple[int, int]] = []
                root = Path(f"/proc/{process.pid}/fd")
                for entry in root.iterdir():
                    try:
                        metadata = entry.stat()
                    except OSError:
                        continue
                    identities.append((metadata.st_dev, metadata.st_ino))
                supervisor_evidence.update(
                    {
                        "finalizer_count": identities.count(
                            (
                                finalizer_metadata.st_dev,
                                finalizer_metadata.st_ino,
                            )
                        ),
                        "payload_count": identities.count(
                            (
                                payload_metadata.st_dev,
                                payload_metadata.st_ino,
                            )
                        ),
                    }
                )
                return process

            monkeypatch.setattr(
                base_runner.subprocess, "Popen", observed_supervisor_spawn
            )
            completed = runner._run_child_process(
                [
                    sys.executable,
                    "-c",
                    child_code,
                    str(payload_descriptor),
                    str(payload_metadata.st_dev),
                    str(payload_metadata.st_ino),
                    str(finalizer_metadata.st_dev),
                    str(finalizer_metadata.st_ino),
                ],
                source="# fixed Odoo write bootstrap\n",
                payload_fd=payload_descriptor,
                timeout_seconds=10,
                cwd=str(tmp_path),
                env=environment,
            )
        environment_validator.assert_called_once_with(environment)
        assert supervisor_evidence == {
            "finalizer_count": 0,
            "payload_count": 1,
        }
        assert completed.returncode == 0, completed.stderr
        observed = json.loads(completed.stdout)
        assert observed == {
            "action": runner.ACTION_APPROVED_WRITE,
            "guard_digest": module_guard["module_graph"]["digest"],
            "payload_fd_identity": [
                payload_metadata.st_dev,
                payload_metadata.st_ino,
            ],
            "runtime_schema": WRITE_RUNTIME_SCHEMA_VERSION,
            "self_finalizer_count": 0,
            "self_payload_count": 1,
        }
        assert os.fstat(finalizer_descriptor) == finalizer_metadata
    finally:
        finalizer_client.close()
        finalizer_peer.close()


def test_precheck_preserves_all_parameters_and_only_transports_write_auth(
    tmp_path: Path, monkeypatch
) -> None:
    config, secrets = _runtime(tmp_path)
    captured: dict[str, object] = {}
    _mock_parent_boundary(monkeypatch, config, _precheck_result(), captured)
    request = {
        "context": {"signed": "internal-auth-context-v1"},
        "capability_id": "acct.invoice.customer.create.v1",
        "parameters": {
            "company_id": 7,
            "invoice_date": "2026-07-15",
            "partner_id": 33,
            "currency_id": 5,
            "lines": [{"account_id": 401, "quantity": 2, "price_unit": "19.95"}],
        },
        "trusted_recovery_plan": None,
    }

    assert runner.run_odoo_write_precheck(
        config, secrets, request, release_digest=RELEASE_DIGEST
    ) == _precheck_result()

    payload = json.loads(captured["payload_bytes"])
    assert json.loads(payload["request_json"]) == request
    assert set(payload["credentials"]) == {"write_auth"}
    assert payload["credentials"]["write_auth"]["key_id"] == config.write_auth.key_id
    exposed = json.dumps(captured["argv"]) + json.dumps(captured["env"]) + captured["source"]
    assert "invoice_date" not in exposed
    for secret in SECRET_VALUES.values():
        assert secret.decode("ascii") not in exposed


def test_approved_write_returns_phases_unchanged_and_excludes_recovery_receipt_keys(
    tmp_path: Path, monkeypatch
) -> None:
    config, secrets = _runtime(tmp_path)
    captured: dict[str, object] = {}
    expected = _approved_result()
    _mock_parent_boundary(monkeypatch, config, expected, captured)
    request = {
        "context": {"signed": "internal-auth-context-v1"},
        "operation": {"operation_id": "op-1", "parameters": {"company_id": 7}},
        "approval": {"approver_user_id": 22},
        "trusted_recovery_plan": None,
        "reconciliation_only": False,
    }

    assert runner.run_odoo_approved_write(
        config, secrets, request, release_digest=RELEASE_DIGEST
    ) == expected
    payload = json.loads(captured["payload_bytes"])
    assert set(payload["credentials"]) == {
        "write_auth", "approval", "execution", "verification"
    }
    serialized = json.dumps(payload["credentials"], sort_keys=True)
    assert "write_receipt" not in serialized
    assert "recovery" not in serialized
    assert SECRET_VALUES["write_receipt"].decode("ascii") not in serialized
    assert SECRET_VALUES["recovery"].decode("ascii") not in serialized


@pytest.mark.parametrize(
    ("call", "result"),
    [
        (runner.run_odoo_write_precheck, _precheck_result()),
        (runner.run_odoo_approved_write, _approved_result()),
    ],
)
def test_effect_capable_actions_hold_pre_registry_module_guard_until_final_probe(
    tmp_path: Path, monkeypatch, call, result
) -> None:
    config, secrets = _runtime(tmp_path)
    captured: dict[str, object] = {}
    _mock_parent_boundary(monkeypatch, config, result, captured)
    original_run = runner._run_child_process

    def ordered_run(*args, **kwargs):
        captured.setdefault("guard_events", []).append(("shell", None))
        return original_run(*args, **kwargs)

    monkeypatch.setattr(runner, "_run_child_process", ordered_run)

    assert call(
        config,
        secrets,
        {},
        release_digest=RELEASE_DIGEST,
        timeout_seconds=10,
    ) == result

    event_names = [event[0] for event in captured["guard_events"]]
    assert event_names == ["acquire", "shell", "final_probe", "release"]
    payload = json.loads(captured["payload_bytes"])
    assert payload["module_guard"]["backend_pid"] == 4101
    exposed = json.dumps(captured["argv"]) + json.dumps(captured["env"])
    assert "4101" not in exposed


def test_acl_audit_does_not_require_the_effect_guard(
    tmp_path: Path, monkeypatch
) -> None:
    config, secrets = _runtime(tmp_path)
    captured: dict[str, object] = {}
    _mock_parent_boundary(monkeypatch, config, _executor_result(), captured)

    def forbidden_guard(*_args, **_kwargs):
        raise AssertionError("ACL-only audit must remain available without the write guard")

    monkeypatch.setattr(runner, "acquire_module_guard", forbidden_guard)

    assert runner.run_odoo_authorize_executor(
        config, secrets, {}, release_digest=RELEASE_DIGEST
    )["authorized"] is True
    assert captured.get("guard_events") in (None, [])


def test_guard_probe_failure_aborts_without_normal_release(
    tmp_path: Path, monkeypatch
) -> None:
    config, secrets = _runtime(tmp_path)
    captured: dict[str, object] = {}
    _mock_parent_boundary(monkeypatch, config, _approved_result(), captured)

    class BrokenProbeGuard:
        evidence = {"schema_version": 1}

        def final_probe(self, *, timeout_seconds):
            captured.setdefault("guard_events", []).append(
                ("final_probe", timeout_seconds)
            )
            raise OdooRunnerError("module guard final probe failed")

        def release(self, *, timeout_seconds):
            captured.setdefault("guard_events", []).append(
                ("release", timeout_seconds)
            )

        def abort(self):
            captured.setdefault("guard_events", []).append(("abort", None))

    monkeypatch.setattr(
        runner,
        "acquire_module_guard",
        lambda *_args, **_kwargs: BrokenProbeGuard(),
    )

    with pytest.raises(OdooRunnerError, match="final probe failed"):
        runner.run_odoo_approved_write(
            config, secrets, {}, release_digest=RELEASE_DIGEST
        )

    assert [event[0] for event in captured["guard_events"]] == [
        "final_probe",
        "abort",
    ]


@pytest.mark.parametrize(
    ("call", "action", "result"),
    [
        (runner.run_odoo_authorize_executor, runner.ACTION_EXECUTOR, _executor_result()),
        (runner.run_odoo_authorize_approver, runner.ACTION_APPROVER, _approver_result()),
    ],
)
def test_acl_actions_are_fixed_and_only_receive_write_auth(
    tmp_path: Path, monkeypatch, call, action, result
) -> None:
    config, secrets = _runtime(tmp_path)
    captured: dict[str, object] = {}
    _mock_parent_boundary(monkeypatch, config, result, captured)

    assert call(
        config,
        secrets,
        {"context": {}, "capability_id": "cap", "parameters": {"company_id": 7}},
        release_digest=RELEASE_DIGEST,
    ) == result
    payload = json.loads(captured["payload_bytes"])
    assert payload["action"] == action
    assert set(payload["credentials"]) == {"write_auth"}


def test_error_timeout_disabled_and_nonzero_exit_fail_closed(
    tmp_path: Path, monkeypatch
) -> None:
    config, secrets = _runtime(tmp_path)
    captured: dict[str, object] = {}
    _mock_parent_boundary(monkeypatch, config, _precheck_result(), captured)
    monkeypatch.setattr(
        runner, "_run_child_process", Mock(side_effect=OdooRunnerError("Odoo shell timed out"))
    )
    with pytest.raises(OdooRunnerError, match="timed out"):
        runner.run_odoo_write_precheck(
            config, secrets, {}, release_digest=RELEASE_DIGEST, timeout_seconds=1
        )

    _mock_parent_boundary(monkeypatch, config, _precheck_result(), captured)
    monkeypatch.setattr(
        runner,
        "_run_child_process",
        Mock(return_value=subprocess.CompletedProcess([], 9, stdout="", stderr="secret")),
    )
    with pytest.raises(OdooRunnerError, match="status 9"):
        runner.run_odoo_write_precheck(config, secrets, {}, release_digest=RELEASE_DIGEST)

    disabled = WriteRuntimeConfig(
        **{**config.__dict__, "write_execution_mode": "disabled"}
    )
    with pytest.raises(OdooRunnerError, match="disabled"):
        runner.run_odoo_write_precheck(disabled, secrets, {}, release_digest=RELEASE_DIGEST)


def test_disabled_kill_switch_still_allows_read_only_acl_for_terminal_audit(
    tmp_path: Path, monkeypatch
) -> None:
    config, secrets = _runtime(tmp_path)
    disabled = WriteRuntimeConfig(
        **{**config.__dict__, "write_execution_mode": "disabled"}
    )
    captured: dict[str, object] = {}
    _mock_parent_boundary(monkeypatch, disabled, _executor_result(), captured)

    result = runner.run_odoo_authorize_executor(
        disabled,
        secrets,
        {"context": {}, "capability_id": "cap", "parameters": {"company_id": 7}},
        release_digest=RELEASE_DIGEST,
    )

    assert result["authorized"] is True
    assert json.loads(captured["payload_bytes"])["credentials"].keys() == {"write_auth"}


def test_hand_built_test_runtime_cannot_bypass_sandbox_staged_binding(
    tmp_path: Path,
) -> None:
    config, secrets = _runtime(tmp_path)
    test_base = RuntimeConfig(
        **{**config.base_runtime.__dict__, "environment": "test"}
    )
    forged = WriteRuntimeConfig(
        **{**config.__dict__, "base_runtime": test_base}
    )

    with pytest.raises(OdooRunnerError, match="sandbox-staged"):
        runner.run_odoo_write_precheck(
            forged, secrets, {}, release_digest=RELEASE_DIGEST
        )


def test_hand_built_secret_bundle_cannot_bypass_role_separation(
    tmp_path: Path,
) -> None:
    config, secrets = _runtime(tmp_path)
    forged = WriteRuntimeSecrets(
        **{**secrets.__dict__, "recovery": secrets.write_auth}
    )

    with pytest.raises(OdooRunnerError, match="secrets are not distinct"):
        runner.run_odoo_authorize_executor(
            config, forged, {}, release_digest=RELEASE_DIGEST
        )


def test_forged_duplicate_malformed_marker_action_and_runtime_are_rejected(
    tmp_path: Path,
) -> None:
    config, _secrets = _runtime(tmp_path)
    response = {
        "ok": True,
        "action": runner.ACTION_PRECHECK,
        "runtime": config.runtime_identity,
        "result": _precheck_result(),
    }
    line = MARKER + json.dumps(response, separators=(",", ":"))
    with pytest.raises(OdooRunnerError, match="exactly one"):
        runner._parse_write_response(line + "\n" + line, MARKER, config, runner.ACTION_PRECHECK)
    with pytest.raises(OdooRunnerError, match="dedicated line"):
        runner._parse_write_response("prefix" + line, MARKER, config, runner.ACTION_PRECHECK)

    wrong_action = {**response, "action": runner.ACTION_APPROVED_WRITE}
    with pytest.raises(OdooRunnerError, match="fields are invalid"):
        runner._parse_write_response(
            MARKER + json.dumps(wrong_action), MARKER, config, runner.ACTION_PRECHECK
        )
    wrong_runtime = {**response, "runtime": {**config.runtime_identity, "database_name": "other"}}
    with pytest.raises(OdooRunnerError, match="does not match"):
        runner._parse_write_response(
            MARKER + json.dumps(wrong_runtime), MARKER, config, runner.ACTION_PRECHECK
        )


def _write_capability() -> Capability:
    return Capability.from_dict(
        {
            "id": "acct.invoice.customer.create.v1",
            "access": "write",
            # ACL probes must remain usable for terminal audit after a write
            # capability is de-staged or the runtime kill switch is enabled.
            "staged_environments": [],
            "enabled_environments": [],
            "odoo_permissions": ["account.group_account_invoice"],
        }
    )


def _context(*, digest: str) -> SimpleNamespace:
    return SimpleNamespace(
        auth_request_digest=digest,
        company_id=7,
        allowed_company_ids=frozenset({7}),
        odoo_instance_id="odoo19@sandbox",
        database_name="odoo_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        environment="sandbox",
        user_id=11,
    )


def _identity() -> dict[str, object]:
    return {
        "instance_id": "odoo19@sandbox",
        "environment": "sandbox",
        "capability_channel": "staged",
        "database_name": "odoo_v3_sandbox",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "write_execution_mode": "sandbox_staged",
        "write_runtime_schema_version": WRITE_RUNTIME_SCHEMA_VERSION,
        "write_runtime_config_sha256": "f" * 64,
    }


class _User:
    def __init__(self, user_id: int, groups: set[str], *, active: bool = True):
        self.id = user_id
        self.active = active
        self.company_ids = SimpleNamespace(ids=[7])
        self._groups = groups

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def exists(self):
        return self

    def has_group(self, group: str) -> bool:
        return group in self._groups


class _UserModel:
    def __init__(self, user: _User):
        self.user = user

    def browse(self, user_id: int):
        assert user_id == self.user.id
        return self.user


class _BoundEnv:
    def __init__(self, user: _User):
        self.user = user
        self.uid = user.id
        self.model = _UserModel(user)

    def __getitem__(self, model: str):
        assert model == "res.users"
        return self.model


def test_executor_acl_is_a_non_superuser_read_and_binds_full_parameters(monkeypatch) -> None:
    parameters = {"company_id": 7, "invoice_date": "2026-07-15", "currency_id": 5}
    context = _context(
        digest=authentication_request_digest(
            "acct.invoice.customer.create.v1", parameters
        )
    )
    groups = {
        "odoo_accounting_cli_v3_control.group_executor",
        "account.group_account_invoice",
    }
    env = _BoundEnv(_User(11, groups))
    verified = Mock(return_value=True)
    monkeypatch.setattr(runner, "request_context_from_mapping", Mock(return_value=context))
    monkeypatch.setattr(runner, "verify_request_context", verified)
    monkeypatch.setattr(runner, "bind_non_superuser_environment", Mock(return_value=env))

    result = runner._execute_authorize_executor(
        object(),
        {"context": {}, "capability_id": "acct.invoice.customer.create.v1", "parameters": parameters},
        capabilities=(_write_capability(),),
        auth_secret=SECRET_VALUES["write_auth"],
        auth_key_id="write_auth-v1",
        release_digest=RELEASE_DIGEST,
        runtime=_identity(),
    )

    assert result["authorized"] is True
    assert result["missing_groups"] == []
    assert verified.call_args.kwargs["secret"] == SECRET_VALUES["write_auth"]
    assert not hasattr(env, "sudo") and not hasattr(env, "commit")


def test_approver_acl_reads_active_company_and_group_without_sudo_or_commit(monkeypatch) -> None:
    parameters = {"approver_user_id": 22, "company_id": 7}
    context = _context(
        digest=authentication_request_digest(
            "acct.invoice.customer.create.v1", parameters
        )
    )
    env = _BoundEnv(_User(22, {runner.APPROVER_GROUP}))
    monkeypatch.setattr(runner, "request_context_from_mapping", Mock(return_value=context))
    monkeypatch.setattr(runner, "verify_request_context", Mock(return_value=True))
    monkeypatch.setattr(runner, "bind_non_superuser_environment", Mock(return_value=env))

    result = runner._execute_authorize_approver(
        object(),
        {"context": {}, "capability_id": "acct.invoice.customer.create.v1", "parameters": parameters},
        capabilities=(_write_capability(),),
        auth_secret=SECRET_VALUES["write_auth"],
        auth_key_id="write_auth-v1",
        release_digest=RELEASE_DIGEST,
        runtime=_identity(),
    )

    assert result["authorized"] is True
    assert not hasattr(env, "sudo") and not hasattr(env, "commit")


def test_action_confusion_and_extra_credentials_are_rejected_before_dispatch(tmp_path: Path) -> None:
    config, secrets = _runtime(tmp_path)
    credentials = runner._credentials(config, secrets, runner.ACTION_APPROVED_WRITE)
    payload = {
        "action": runner.ACTION_APPROVED_WRITE,
        "runtime": config.runtime_identity,
        "release_root": str(config.base_runtime.release_root),
        "canonical_package_path": str(config.base_runtime.canonical_package_path),
        "canonical_package_sha256": config.base_runtime.canonical_package_sha256,
    }
    with pytest.raises(OdooRunnerError, match="action binding mismatch"):
        runner._child_runtime(payload, runner.ACTION_PRECHECK)

    precheck_payload = {"credentials": credentials}
    with pytest.raises(OdooRunnerError, match="credential roles"):
        runner._decode_credentials(precheck_payload, runner.ACTION_PRECHECK)


_DEFAULT_GUARD = object()


def _invoke_child(
    monkeypatch,
    capsys,
    config,
    secrets,
    action,
    request,
    result,
    *,
    module_guard=_DEFAULT_GUARD,
):
    release_root = Path(runner.__file__).resolve().parents[3]
    payload = runner.canonical_json(
        {
            "protocol": 1,
            "action": action,
            "runtime": config.runtime_identity,
            "request_json": runner._normalize_request_json(request),
            "credentials": runner._credentials(config, secrets, action),
            "release_digest": RELEASE_DIGEST,
            "canonical_package_path": str(release_root.parent.parent / "packages" / f"odoo-accounting-cli-v3-{release_root.name}.tar.gz"),
            "canonical_package_sha256": "4" * 64,
            "release_root": str(release_root),
            "module_guard": (
                _module_guard_evidence(config)
                if module_guard is _DEFAULT_GUARD
                and action in runner.MODULE_GUARDED_ACTIONS
                else (
                    None if module_guard is _DEFAULT_GUARD else module_guard
                )
            ),
        }
    )
    read_fd, write_fd = os.pipe()
    os.write(write_fd, payload)
    os.close(write_fd)
    monkeypatch.setattr(runner, "_validate_canonical_package_binding", Mock())
    monkeypatch.setattr(runner, "_verify_child_release", Mock(return_value=(_write_capability(),)))
    monkeypatch.setattr(runner, "_assert_actual_database", Mock())
    try:
        runner._write_child_main(object(), read_fd, MARKER, action)
    finally:
        try:
            os.close(read_fd)
        except OSError:
            pass
    response = json.loads(capsys.readouterr().out.strip()[len(MARKER) :])
    assert response["result"] == result
    return response


def test_child_rejects_missing_or_action_confused_module_guard(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    config, secrets = _runtime(tmp_path)
    monkeypatch.setattr(
        runner,
        "execute_write_precheck_from_odoo_shell",
        Mock(return_value=_precheck_result()),
    )
    request = {
        "context": {"signed": "v1"},
        "capability_id": "acct.invoice.customer.create.v1",
        "parameters": {"company_id": 7},
        "trusted_recovery_plan": None,
    }

    with pytest.raises(OdooRunnerError, match="module guard binding"):
        _invoke_child(
            monkeypatch,
            capsys,
            config,
            secrets,
            runner.ACTION_PRECHECK,
            request,
            _precheck_result(),
            module_guard=None,
        )

    with pytest.raises(OdooRunnerError, match="module guard binding"):
        _invoke_child(
            monkeypatch,
            capsys,
            config,
            secrets,
            runner.ACTION_EXECUTOR,
            request,
            _executor_result(),
            module_guard=_module_guard_evidence(config),
        )

    with pytest.raises(OdooRunnerError, match="module guard evidence"):
        _invoke_child(
            monkeypatch,
            capsys,
            config,
            secrets,
            runner.ACTION_PRECHECK,
            request,
            _precheck_result(),
            module_guard={"guard_protocol_version": 1},
        )


def test_child_dispatches_precheck_with_only_write_auth_and_verified_registry(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    config, secrets = _runtime(tmp_path)
    execute = Mock(return_value=_precheck_result())
    monkeypatch.setattr(runner, "execute_write_precheck_from_odoo_shell", execute)
    request = {
        "context": {"signed": "v1"},
        "capability_id": "acct.invoice.customer.create.v1",
        "parameters": {"company_id": 7, "invoice_date": "2026-07-15"},
        "trusted_recovery_plan": None,
    }

    _invoke_child(
        monkeypatch, capsys, config, secrets, runner.ACTION_PRECHECK, request, _precheck_result()
    )

    assert len(execute.call_args.args) == 2
    assert execute.call_args.args[1] == request
    kwargs = execute.call_args.kwargs
    assert kwargs["auth_secret"] == SECRET_VALUES["write_auth"]
    assert kwargs["auth_key_id"] == config.write_auth.key_id
    assert "approval_secret" not in kwargs
    assert "execution_secret" not in kwargs
    assert "verification_secret" not in kwargs


def test_child_dispatches_approved_write_without_receipt_or_recovery_secret(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    config, secrets = _runtime(tmp_path)
    expected = _approved_result()
    execute = Mock(return_value=expected)
    monkeypatch.setattr(runner, "execute_write_from_odoo_shell", execute)
    request = {
        "context": {"signed": "v1"},
        "operation": {"operation_id": "op-1", "parameters": {"company_id": 7}},
        "approval": {"approver_user_id": 22},
        "trusted_recovery_plan": None,
        "reconciliation_only": False,
    }

    _invoke_child(
        monkeypatch,
        capsys,
        config,
        secrets,
        runner.ACTION_APPROVED_WRITE,
        request,
        expected,
    )

    assert execute.call_args.args[1] == request
    kwargs = execute.call_args.kwargs
    assert kwargs["auth_secret"] == SECRET_VALUES["write_auth"]
    assert kwargs["approval_secret"] == SECRET_VALUES["approval"]
    assert kwargs["execution_secret"] == SECRET_VALUES["execution"]
    assert kwargs["verification_secret"] == SECRET_VALUES["verification"]
    assert "write_receipt_secret" not in kwargs
    assert "recovery_secret" not in kwargs

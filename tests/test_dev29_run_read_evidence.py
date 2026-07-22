from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


runner = _load(
    "dev29_run_read_evidence",
    ROOT / "deployment" / "dev29" / "run_read_evidence.py",
)
installer = _load(
    "dev29_install_release_contract",
    ROOT / "deployment" / "install-release.py",
)

VERSION = "0.1.0.dev29"
COMMIT = "a1234567890b1234567890b1234567890b123456"
RELEASE = f"{VERSION}-{COMMIT[:12]}"


def expected_values() -> dict[str, str]:
    return {
        "release": RELEASE,
        "version": VERSION,
        "commit": COMMIT,
        "manifest_sha256": "b" * 64,
        "package_sha256": "c" * 64,
    }


def test_supervisor_numeric_schema_version_guard_rejects_bool() -> None:
    assert runner._schema_version_is_one(1) is True
    for value in (True, 1.0, "1", None):
        assert runner._schema_version_is_one(value) is False


def common_cli() -> list[str]:
    values = {
        "evidence_name": "dev29-proof-001",
        "expected_release": RELEASE,
        "expected_version": VERSION,
        "expected_commit": COMMIT,
        "expected_manifest_sha256": "b" * 64,
        "expected_package_sha256": "c" * 64,
        "expected_closure_anchor_sha256": "d" * 64,
        "expected_closure_image_sha256": "e" * 64,
        "expected_system_python_sha256": "f" * 64,
        "expected_ld_so_preload_sha256": "1" * 64,
        "expected_ldconfig_sha256": "6" * 64,
        "expected_systemd_run_sha256": "2" * 64,
        "expected_systemctl_sha256": "3" * 64,
        "expected_strace_sha256": "4" * 64,
        "expected_runtime_open_index_sha256": "7" * 64,
        "expected_registry_digest": "5" * 64,
    }
    result: list[str] = []
    for name, option in runner.COMMON_OPTIONS:
        result.extend((option, values[name]))
    return result


def lease_cli() -> list[str]:
    values = {
        "expected_lease_nonce": "8" * 64,
        "expected_lease_device": "11",
        "expected_lease_inode": "12",
        "expected_lease_launcher_pid": "13",
        "expected_lease_launcher_starttime": "14",
        "expected_lease_guardian_pid": "15",
        "expected_lease_guardian_starttime": "16",
    }
    result: list[str] = []
    for name, option in runner.LEASE_OPTIONS:
        result.extend((option, values[name]))
    return result


def worker_pin_cli() -> list[str]:
    values = {
        "expected_worker_python_fd": "20",
        "expected_worker_python_device": "21",
        "expected_worker_python_inode": "22",
        "expected_worker_script_fd": "23",
        "expected_worker_script_device": "24",
        "expected_worker_script_inode": "25",
    }
    result: list[str] = []
    for name, option in runner.WORKER_PIN_OPTIONS:
        result.extend((option, values[name]))
    return result


def test_supervisor_release_anchor_matches_canonical_installer_four_field_contract():
    expected = expected_values()
    installed = installer.ExpectedIdentity(
        version=expected["version"],
        commit=expected["commit"],
        release=expected["release"],
        package_sha256=expected["package_sha256"],
        manifest_sha256=expected["manifest_sha256"],
    )
    assert runner._release_anchor_identity(expected) == installed.anchor
    assert set(installed.anchor) == {
        "release",
        "commit",
        "manifest_sha256",
        "package_sha256",
    }
    assert "version" not in installed.anchor


def test_launch_and_worker_require_external_registry_digest_and_lease_contract():
    launch = runner._parser().parse_args(["launch", *common_cli()])
    assert launch.expected_registry_digest == "5" * 64
    assert launch.expected_ldconfig_sha256 == "6" * 64
    with pytest.raises(SystemExit):
        runner._parser().parse_args(["supervise-worker", *common_cli()])
    supervise = runner._parser().parse_args(
        [
            "supervise-worker",
            *common_cli(),
            *lease_cli(),
            "--expected-unit",
            "odoo-accounting-cli-v3-dev29-dev29-proof-001.service",
            "--expected-wrapper-pid",
            "19",
            "--worker-gate-fd",
            "26",
            "--expected-worker-script-sha256",
            "9" * 64,
            *worker_pin_cli(),
        ]
    )
    assert supervise.expected_unit.endswith(".service")
    assert supervise.expected_lease_nonce == "8" * 64


def test_operator_examples_pass_every_required_common_option() -> None:
    document = (
        ROOT / "deployment" / "dev29" / "README-read-evidence.md"
    ).read_text(encoding="utf-8")
    for action in ("launch", "status", "recover"):
        marker = f'"$RUNNER" {action} \\\n'
        start = document.index(marker)
        end = document.index("```", start)
        example = document[start:end]
        for _name, option in runner.COMMON_OPTIONS:
            assert option in example, f"{action} example omits {option}"


def test_verifier_private_sidecar_is_a_sibling_of_the_suite_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "PRIVATE_EVIDENCE_PARENT", tmp_path)
    main = tmp_path / "dev29-proof-001"
    verifier = runner._verifier_private_sidecar_path(main.name)

    assert verifier == tmp_path / "dev29-proof-001.verifier"
    assert verifier.parent == main.parent
    assert verifier != main / "verifier"
    with pytest.raises(runner.SupervisorError, match="evidence name"):
        runner._verifier_private_sidecar_path("../escape")


def test_publisher_argv_forwards_external_ldconfig_digest_exactly() -> None:
    arguments = runner._parser().parse_args(["launch", *common_cli()])
    command = runner._publisher_argv(
        arguments,
        publisher_path=Path("/release/publish_read_evidence.py"),
        evidence=Path("/evidence/dev29-proof-001"),
        stage=Path("/staging/dev29-proof-001"),
        expected={**expected_values(), "registry_digest": "5" * 64},
        bundle_manifest_sha256="7" * 64,
    )
    assert command.count("--expected-ldconfig-sha256") == 1
    index = command.index("--expected-ldconfig-sha256")
    assert command[index + 1] == "6" * 64
    assert command[command.index("--expected-runtime-open-index-sha256") + 1] == "7" * 64
    assert command[command.index("--expected-strace-sha256") + 1] == "4" * 64


def test_launch_uses_named_exact_ownership_for_private_trace_and_state_paths() -> None:
    source = (ROOT / "deployment" / "dev29" / "run_read_evidence.py").read_text(
        encoding="utf-8"
    )
    assert "PRIVATE_EVIDENCE_PARENT: (0, 0, 0o700)" in source
    assert "RUNTIME_TRACE_STAGING_PARENT: (0, 0, 0o700)" in source
    assert "auth_state_parent: (odoo.pw_uid, odoo_group.gr_gid, 0o700)" in source
    assert "receipt_state_parent: (odoo.pw_uid, odoo_group.gr_gid, 0o700)" in source
    assert "writable[" not in source


def test_recovery_and_status_require_external_bundle_digest():
    for action in ("recover", "status"):
        with pytest.raises(SystemExit):
            runner._parser().parse_args([action, *common_cli()])
        parsed = runner._parser().parse_args(
            [
                action,
                *common_cli(),
                "--expected-bundle-manifest-sha256",
                "6" * 64,
            ]
        )
        assert parsed.expected_bundle_manifest_sha256 == "6" * 64
    internal = runner._parser().parse_args(
        [
            "recover-unit-wrapper",
            *common_cli(),
            *lease_cli(),
            "--expected-bundle-manifest-sha256",
            "6" * 64,
            "--expected-worker-script-sha256",
            "9" * 64,
            "--expected-unit",
            "odoo-accounting-cli-v3-dev29-dev29-proof-001.service",
        ]
    )
    assert internal.action == "recover-unit-wrapper"


@pytest.mark.parametrize("artifact", ["final", "pending"])
def test_status_forwards_external_ldconfig_digest_to_anchor_validation(
    artifact: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_parent = tmp_path / "evidence"
    anchor_parent = tmp_path / "anchors"
    staging_parent = tmp_path / "staging"
    release_root = tmp_path / "release"
    for directory in (evidence_parent, anchor_parent, staging_parent, release_root):
        directory.mkdir()
    evidence = evidence_parent / "dev29-proof-001"
    evidence.mkdir()
    stage = staging_parent / "dev29-proof-001"
    if artifact == "pending":
        anchor = anchor_parent / ".dev29-proof-001.json.pending"
    else:
        anchor = anchor_parent / "dev29-proof-001.json"
    anchor.write_text("{}\n", encoding="utf-8")
    anchor.chmod(0o400)

    calls: list[str] = []

    class Publisher:
        @staticmethod
        def stable_read(*_args, **_kwargs):
            return b"{}\n"

        @staticmethod
        def _validate_existing_anchor_for_stage_cleanup(
            _path,
            *,
            evidence,
            expected_release_identity,
                expected_bundle_manifest_sha256,
                expected_ldconfig_sha256,
                expected_runtime_open_index_sha256,
                expected_strace_sha256,
                validated_payload=None,
        ):
            del (
                evidence,
                expected_release_identity,
                    expected_bundle_manifest_sha256,
                    expected_runtime_open_index_sha256,
                    expected_strace_sha256,
                    validated_payload,
            )
            calls.append(expected_ldconfig_sha256)

    monkeypatch.setattr(runner, "EVIDENCE_PARENT", evidence_parent)
    monkeypatch.setattr(runner, "ANCHOR_PARENT", anchor_parent)
    monkeypatch.setattr(runner, "STAGING_PARENT", staging_parent)
    monkeypatch.setattr(runner, "_require_system_python", lambda: None)
    monkeypatch.setattr(runner, "_program", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(runner, "_verify_preload", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        runner, "_bootstrap_release", lambda _expected: (release_root, {})
    )
    monkeypatch.setattr(runner, "_verify_writable_directory", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "_load_module", lambda *_args, **_kwargs: Publisher)
    if artifact == "pending":
        monkeypatch.setattr(
            runner, "_recovery_artifact_state", lambda _name: "pending_anchor_commit"
        )

    arguments = runner._parser().parse_args(
        [
            "status",
            *common_cli(),
            "--expected-bundle-manifest-sha256",
            "7" * 64,
        ]
    )
    result = runner._status(arguments)

    assert calls == ["6" * 64]
    assert result["durable_anchor_verified"] is (artifact == "final")
    assert result["durable_pending_verified"] is (artifact == "pending")


def test_orchestration_recognizes_complete_stage_and_durable_pending_as_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_parent = tmp_path / "evidence"
    anchor_parent = tmp_path / "anchors"
    staging_parent = tmp_path / "staging"
    evidence_parent.mkdir()
    anchor_parent.mkdir()
    staging_parent.mkdir()
    evidence = evidence_parent / "proof"
    stage = staging_parent / "proof"
    evidence.mkdir()
    stage.mkdir()
    for name in runner.PUBLISHER_STAGE_FILES:
        (stage / name).write_text("{}\n", encoding="utf-8")
    pending = anchor_parent / ".proof.json.pending"
    pending.write_text('{"durable":true}\n', encoding="utf-8")
    pending.chmod(0o400)
    monkeypatch.setattr(runner, "EVIDENCE_PARENT", evidence_parent)
    monkeypatch.setattr(runner, "ANCHOR_PARENT", anchor_parent)
    monkeypatch.setattr(runner, "STAGING_PARENT", staging_parent)
    monkeypatch.setattr(runner, "_verify_writable_directory", lambda *_args, **_kwargs: None)
    assert runner._recovery_artifact_state("proof") == "pending_anchor_commit"

    removed = stage / next(iter(runner.PUBLISHER_STAGE_FILES))
    removed.unlink()
    with pytest.raises(runner.SupervisorError, match="recoverable final or pending"):
        runner._recovery_artifact_state("proof")
    removed.write_text("{}\n", encoding="utf-8")
    (anchor_parent / "proof.json").write_text('{"final":true}\n', encoding="utf-8")
    assert runner._recovery_artifact_state("proof") == "final_anchor_cleanup"


def test_systemctl_query_uses_fixed_binary_environment_and_no_stdin(monkeypatch):
    captured = {}

    def fake_run(path, digest, command, **kwargs):
        captured["path"] = path
        captured["digest"] = digest
        captured["command"] = command
        captured["kwargs"] = kwargs
        fields = [
            item.removeprefix("--property=")
            for item in command
            if item.startswith("--property=")
        ]
        stdout = "".join(f"{field}=value\n" for field in fields).encode()
        return subprocess.CompletedProcess(command, 0, stdout, b""), {"verified": True}

    monkeypatch.setattr(runner, "_run_pinned_program", fake_run)
    properties, execution = runner._systemctl_show(
        "odoo-accounting-cli-v3-dev29-proof.service",
        expected_systemctl_sha256="a" * 64,
    )
    assert properties["ProtectSystem"] == "value"
    assert execution == {"verified": True}
    assert captured["path"] == runner.SYSTEMCTL
    assert captured["digest"] == "a" * 64
    assert captured["command"][0] == str(runner.SYSTEMCTL)
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["kwargs"]["env"] == runner.OUTER_ENVIRONMENT


def test_supervisor_source_has_single_unit_hardening_and_final_exec_contract():
    source = (ROOT / "deployment" / "dev29" / "run_read_evidence.py").read_text(
        "utf-8"
    )
    for token in (
        "ProtectSystem=strict",
        "PrivateMounts=yes",
        "PrivateTmp=yes",
        "PrivateNetwork=yes",
        "NoNewPrivileges=yes",
        "ProtectHome=read-only",
        "KillMode=control-group",
        "RuntimeMaxSec=3600s",
        "TimeoutStopSec=30s",
        "CapabilityBoundingSet=",
        "stdin=subprocess.DEVNULL",
        "os.execve(",
        "_drop_publisher_capabilities()",
        'executable=f"/proc/self/fd/{descriptor}"',
        "pass_fds=(descriptor,)",
        "os.WUNTRACED",
        "PTRACE_O_EXITKILL",
        'Path(f"/proc/{process.pid}/exe").stat()',
        "SYSTEMD_RUN_COMMUNICATE_TIMEOUT_SECONDS",
        "_exec_pinned_publisher(",
    ):
        assert token in source
    assert "JoinsNamespaceOf" not in source
    assert "nested systemd" not in source.lower()


def test_systemd_run_communicate_timeout_exceeds_unit_shutdown_budget() -> None:
    assert runner.SYSTEMD_RUN_COMMUNICATE_TIMEOUT_SECONDS > 3600 + 30
    assert runner.SYSTEMD_RUN_COMMUNICATE_TIMEOUT_SECONDS < 2 * 3600
    source = (ROOT / "deployment" / "dev29" / "run_read_evidence.py").read_text(
        "utf-8"
    )
    assert "timeout=SYSTEMD_RUN_COMMUNICATE_TIMEOUT_SECONDS" in source


def _fake_stopped_status(signal_number: int) -> int:
    return (signal_number << 8) | 0x7F


def _enable_mock_posix_wait_constants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner.os, "WUNTRACED", 2, raising=False)
    monkeypatch.setattr(runner.os, "WNOHANG", 1, raising=False)
    monkeypatch.setattr(runner.os, "WIFEXITED", lambda status: status & 0x7F == 0, raising=False)
    monkeypatch.setattr(runner.os, "WEXITSTATUS", lambda status: status >> 8, raising=False)
    monkeypatch.setattr(
        runner.os,
        "WIFSIGNALED",
        lambda status: 0 < status & 0x7F < 0x7F,
        raising=False,
    )
    monkeypatch.setattr(runner.os, "WTERMSIG", lambda status: status & 0x7F, raising=False)
    monkeypatch.setattr(
        runner.os, "WIFSTOPPED", lambda status: status & 0xFF == 0x7F, raising=False
    )
    monkeypatch.setattr(runner.os, "WSTOPSIG", lambda status: status >> 8, raising=False)
    monkeypatch.setattr(runner.signal, "SIGKILL", 9, raising=False)
    monkeypatch.setattr(runner.signal, "SIGTRAP", 5, raising=False)


def _enable_mock_pidfd(monkeypatch: pytest.MonkeyPatch) -> list[tuple[int, int]]:
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(runner, "_reject_file_capabilities", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        runner,
        "_open_child_pidfd",
        lambda *_args, **_kwargs: os.open(os.devnull, os.O_RDONLY),
    )
    monkeypatch.setattr(
        runner,
        "_pidfd_send_signal",
        lambda descriptor, sig, **_kwargs: sent.append((descriptor, sig)),
    )
    return sent


def test_pinned_program_does_not_signal_pid_after_exec_wait_already_reaped_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_mock_posix_wait_constants(monkeypatch)
    _enable_mock_pidfd(monkeypatch)
    descriptor = os.open(tmp_path / "descriptor", os.O_CREAT | os.O_RDWR, 0o600)

    class Process:
        pid = 32101
        returncode = None

        def wait(self, timeout):
            raise AssertionError(f"already-reaped child was waited again: {timeout}")

    process = Process()
    monkeypatch.setattr(
        runner,
        "_open_pinned_program",
        lambda *_args, **_kwargs: (descriptor, (1,) * 9, {}),
    )
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(runner.os, "waitpid", lambda _pid, _flags: (process.pid, 0))
    monkeypatch.setattr(
        runner.os,
        "kill",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("already-reaped PID was signalled")
        ),
    )
    path = Path("/fixed/tool")
    with pytest.raises(runner.SupervisorError, match="exec trace stop is invalid"):
        runner._run_pinned_program(
            path,
            "a" * 64,
            [str(path)],
            label="already reaped",
            env=runner.OUTER_ENVIRONMENT,
        )
    assert process.returncode == 0


def test_pinned_program_detach_failure_still_kills_and_reaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_mock_posix_wait_constants(monkeypatch)
    sent = _enable_mock_pidfd(monkeypatch)
    descriptor = os.open(tmp_path / "descriptor", os.O_CREAT | os.O_RDWR, 0o600)
    killed: list[tuple[int, int]] = []

    class Process:
        pid = 32102
        returncode = None

        def wait(self, timeout):
            assert timeout == 5
            self.returncode = -signal.SIGKILL
            return self.returncode

    process = Process()
    monkeypatch.setattr(
        runner,
        "_open_pinned_program",
        lambda *_args, **_kwargs: (descriptor, (1,) * 9, {}),
    )
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        runner.os,
        "waitpid",
        lambda _pid, _flags: (process.pid, _fake_stopped_status(signal.SIGTRAP)),
    )
    monkeypatch.setattr(
        runner,
        "_ptrace_set_exitkill",
        lambda _pid: (_ for _ in ()).throw(OSError("setoptions failed")),
    )
    monkeypatch.setattr(
        runner,
        "_ptrace_detach",
        lambda *_args: (_ for _ in ()).throw(OSError("detach failed")),
    )
    path = Path("/fixed/tool")
    with pytest.raises(OSError, match="setoptions failed"):
        runner._run_pinned_program(
            path,
            "a" * 64,
            [str(path)],
            label="detach failure",
            env=runner.OUTER_ENVIRONMENT,
        )
    assert len(sent) == 1
    assert sent[0][1] == signal.SIGKILL
    assert process.returncode == -signal.SIGKILL


def test_pinned_program_refuses_when_failed_child_cannot_be_reaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_mock_posix_wait_constants(monkeypatch)
    sent = _enable_mock_pidfd(monkeypatch)
    descriptor = os.open(tmp_path / "descriptor", os.O_CREAT | os.O_RDWR, 0o600)
    killed: list[tuple[int, int]] = []

    class Process:
        pid = 32103
        returncode = None

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("fixed-tool", timeout)

    process = Process()
    monkeypatch.setattr(
        runner,
        "_open_pinned_program",
        lambda *_args, **_kwargs: (descriptor, (1,) * 9, {}),
    )
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        runner.os,
        "waitpid",
        lambda _pid, _flags: (process.pid, _fake_stopped_status(signal.SIGTRAP)),
    )
    monkeypatch.setattr(
        runner,
        "_ptrace_set_exitkill",
        lambda _pid: (_ for _ in ()).throw(OSError("setoptions failed")),
    )
    monkeypatch.setattr(runner, "_ptrace_detach", lambda *_args: None)
    path = Path("/fixed/tool")
    with pytest.raises(runner.SupervisorError, match="could not be reaped"):
        runner._run_pinned_program(
            path,
            "a" * 64,
            [str(path)],
            label="unreapable",
            env=runner.OUTER_ENVIRONMENT,
        )
    assert [item[1] for item in sent] == [signal.SIGKILL]


def test_pinned_program_rejects_security_capability_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = os.open(tmp_path / "descriptor", os.O_CREAT | os.O_RDWR, 0o600)
    monkeypatch.setattr(
        runner,
        "_open_pinned_program",
        lambda *_args, **_kwargs: (descriptor, (1,) * 9, {}),
    )
    monkeypatch.setattr(
        runner.os,
        "getxattr",
        lambda *_args, **_kwargs: b"capability",
        raising=False,
    )
    monkeypatch.setattr(
        runner.subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("capability-bearing executable was spawned")
        ),
    )
    path = Path("/fixed/tool")
    with pytest.raises(runner.SupervisorError, match="has file capabilities"):
        runner._run_pinned_program(
            path,
            "a" * 64,
            [str(path)],
            label="capability tool",
            env=runner.OUTER_ENVIRONMENT,
        )


def test_pidfd_open_failure_kills_and_reaps_unreused_direct_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_mock_posix_wait_constants(monkeypatch)
    descriptor = os.open(tmp_path / "descriptor", os.O_CREAT | os.O_RDWR, 0o600)

    class Process:
        pid = 32104
        returncode = None

        def wait(self, timeout):
            assert timeout == 5
            self.returncode = -signal.SIGKILL
            return self.returncode

    process = Process()
    monkeypatch.setattr(
        runner,
        "_open_pinned_program",
        lambda *_args, **_kwargs: (descriptor, (1,) * 9, {}),
    )
    monkeypatch.setattr(runner, "_reject_file_capabilities", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        runner,
        "_open_child_pidfd",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            runner.SupervisorError("pidfd unavailable")
        ),
    )
    monkeypatch.setattr(
        runner.os,
        "waitpid",
        lambda _pid, _flags: (process.pid, _fake_stopped_status(signal.SIGTRAP)),
    )
    detached: list[tuple[int, int]] = []
    monkeypatch.setattr(
        runner,
        "_ptrace_detach",
        lambda pid, sig=0: detached.append((pid, sig)),
    )
    path = Path("/fixed/tool")
    with pytest.raises(runner.SupervisorError, match="pidfd unavailable"):
        runner._run_pinned_program(
            path,
            "a" * 64,
            [str(path)],
            label="pre-pidfd",
            env=runner.OUTER_ENVIRONMENT,
        )
    assert detached == [(process.pid, signal.SIGKILL)]
    assert process.returncode == -signal.SIGKILL


def test_echild_with_exited_pidfd_does_not_fabricate_child_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(runner.signal, "SIGKILL", 9, raising=False)
    class Process:
        pid = 32105
        returncode = None

        def wait(self, timeout):
            raise ChildProcessError

    process = Process()
    monkeypatch.setattr(runner, "_pidfd_send_signal", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(runner, "_pidfd_has_exited", lambda *_args, **_kwargs: True)
    runner._kill_and_reap_pinned_child(
        process, pidfd=99, traced=False, label="externally reaped"
    )
    assert process.returncode is None


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root flock and exact lease metadata",
)
def test_launcher_lease_rejects_live_owner_and_replaces_only_unlocked_stale_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease_parent = tmp_path / "leases"
    lease_parent.mkdir(mode=0o700)
    os.chown(lease_parent, 0, 0)
    monkeypatch.setattr(runner, "LEASE_PARENT", lease_parent)
    unit = "odoo-accounting-cli-v3-dev29-lease-proof.service"
    descriptor, first = runner._create_launcher_lease("lease-proof", unit)
    assert os.get_inheritable(descriptor) is False
    assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o400
    with pytest.raises(runner.SupervisorError, match="already owned"):
        runner._create_launcher_lease("lease-proof", unit)
    os.close(descriptor)
    replacement, second = runner._create_launcher_lease("lease-proof", unit)
    try:
        assert (second["device"], second["inode"]) != (
            first["device"],
            first["inode"],
        )
        assert second["nonce"] != first["nonce"]
        runner._remove_launcher_lease(replacement, second)
    finally:
        os.close(replacement)
    assert not runner._lease_path("lease-proof").exists()


def test_pinned_stat_identity_ignores_atime_but_rejects_content_metadata_drift():
    values = {
        "st_dev": 1,
        "st_ino": 2,
        "st_nlink": 1,
        "st_size": 100,
        "st_mtime_ns": 3,
        "st_ctime_ns": 4,
        "st_mode": stat.S_IFREG | 0o755,
        "st_uid": 0,
        "st_gid": 0,
        "st_atime_ns": 5,
    }
    baseline = SimpleNamespace(**values)
    atime_changed = SimpleNamespace(**{**values, "st_atime_ns": 999})
    mtime_changed = SimpleNamespace(**{**values, "st_mtime_ns": 999})
    ctime_changed = SimpleNamespace(**{**values, "st_ctime_ns": 999})
    assert runner._pinned_stat_identity(baseline) == runner._pinned_stat_identity(
        atime_changed
    )
    assert runner._pinned_stat_identity(baseline) != runner._pinned_stat_identity(
        mtime_changed
    )
    assert runner._pinned_stat_identity(baseline) != runner._pinned_stat_identity(
        ctime_changed
    )


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux procfs and ptrace")
def test_pinned_program_executes_the_hashed_inode_via_proc_fd():
    path = next(
        candidate
        for candidate in (Path("/usr/bin/true"), Path("/bin/true"))
        if candidate.exists() and candidate.resolve(strict=True) == candidate
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    completed, execution = runner._run_pinned_program(
        path,
        digest,
        [str(path)],
        label="harmless pinned test",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=runner.OUTER_ENVIRONMENT,
        timeout=10,
    )
    assert completed.returncode == 0
    assert completed.stdout == b""
    assert completed.stderr == b""
    assert execution["pinned_device"] == execution["proc_exe_device"]
    assert execution["pinned_inode"] == execution["proc_exe_inode"]
    assert execution["ptrace_exitkill_set"] is True
    assert execution["ptrace_exec_stop_verified"] is True
    assert execution["ptrace_detached_before_communicate"] is True
    assert execution["parent_death_signal"] == "SIGKILL"
    assert execution["parent_identity_checked"] is True
    assert execution["security_capability_absent"] is True
    assert execution["child_reaped"] is True
    assert execution["all_checks_passed"] is True


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root-owned temporary executable, fork, and ptrace",
)
def test_exitkill_removes_tracee_when_pinned_program_supervisor_is_killed(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "pinned-sleep"
    shutil.copyfile("/usr/bin/sleep", tool)
    tool.chmod(0o755)
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    library = ctypes.CDLL(None, use_errno=True)
    original_subreaper = ctypes.c_int()
    assert library.prctl(37, ctypes.byref(original_subreaper), 0, 0, 0) == 0
    assert library.prctl(36, 1, 0, 0, 0) == 0
    read_fd, write_fd = os.pipe()
    tracer_pid = os.fork()
    if tracer_pid == 0:
        os.close(read_fd)
        real_set_exitkill = runner._ptrace_set_exitkill

        def announce_after_exitkill(pid: int) -> None:
            real_set_exitkill(pid)
            os.write(write_fd, f"{pid}\n".encode("ascii"))
            os.close(write_fd)
            while True:
                signal.pause()

        runner._ptrace_set_exitkill = announce_after_exitkill
        try:
            runner._run_pinned_program(
                tool,
                digest,
                [str(tool), "60"],
                label="exitkill integration test",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=runner.OUTER_ENVIRONMENT,
                timeout=60,
            )
        except BaseException:
            os._exit(125)
        os._exit(0)

    os.close(write_fd)
    try:
        ready, _writable, _exceptional = select.select([read_fd], [], [], 10)
        assert ready, "tracer did not establish the EXITKILL-protected exec-stop"
        tracee_text = os.read(read_fd, 64).decode("ascii").strip()
        assert tracee_text
        tracee_pid = int(tracee_text)
        assert Path(f"/proc/{tracee_pid}").exists()
        os.kill(tracer_pid, signal.SIGKILL)
        waited, status = os.waitpid(tracer_pid, 0)
        assert waited == tracer_pid
        assert os.WIFSIGNALED(status)
        deadline = time.monotonic() + 10
        tracee_status = None
        while time.monotonic() < deadline:
            waited_tracee, candidate_status = os.waitpid(tracee_pid, os.WNOHANG)
            if waited_tracee == tracee_pid:
                tracee_status = candidate_status
                break
            time.sleep(0.05)
        assert tracee_status is not None
        assert os.WIFSIGNALED(tracee_status)
        assert os.WTERMSIG(tracee_status) == signal.SIGKILL
        assert not Path(f"/proc/{tracee_pid}").exists()
    finally:
        os.close(read_fd)
        try:
            os.kill(tracer_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(tracer_pid, 0)
        except ChildProcessError:
            pass
        assert library.prctl(36, original_subreaper.value, 0, 0, 0) == 0


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root-owned temporary executable, fork, pidfd, and ptrace",
)
def test_pdeathsig_removes_detached_pinned_child_when_supervisor_is_killed(
    tmp_path: Path,
) -> None:
    tool = tmp_path / "pinned-sleep-pdeath"
    shutil.copyfile("/usr/bin/sleep", tool)
    tool.chmod(0o755)
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    library = ctypes.CDLL(None, use_errno=True)
    original_subreaper = ctypes.c_int()
    assert library.prctl(37, ctypes.byref(original_subreaper), 0, 0, 0) == 0
    assert library.prctl(36, 1, 0, 0, 0) == 0
    read_fd, write_fd = os.pipe()
    supervisor_pid = os.fork()
    if supervisor_pid == 0:
        os.close(read_fd)
        real_detach = runner._ptrace_detach

        def announce_after_detach(pid: int, signal_number: int = 0) -> None:
            real_detach(pid, signal_number)
            os.write(write_fd, f"{pid}\n".encode("ascii"))
            os.close(write_fd)

        runner._ptrace_detach = announce_after_detach
        try:
            runner._run_pinned_program(
                tool,
                digest,
                [str(tool), "60"],
                label="pdeath integration test",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=runner.OUTER_ENVIRONMENT,
                timeout=60,
            )
        except BaseException:
            os._exit(125)
        os._exit(0)

    os.close(write_fd)
    try:
        ready, _writable, _exceptional = select.select([read_fd], [], [], 10)
        assert ready, "supervisor did not detach its PDEATHSIG-protected child"
        tracee_pid = int(os.read(read_fd, 64).decode("ascii").strip())
        assert Path(f"/proc/{tracee_pid}").exists()
        os.kill(supervisor_pid, signal.SIGKILL)
        waited, status = os.waitpid(supervisor_pid, 0)
        assert waited == supervisor_pid and os.WIFSIGNALED(status)
        deadline = time.monotonic() + 10
        tracee_status = None
        while time.monotonic() < deadline:
            waited_tracee, candidate_status = os.waitpid(tracee_pid, os.WNOHANG)
            if waited_tracee == tracee_pid:
                tracee_status = candidate_status
                break
            time.sleep(0.05)
        assert tracee_status is not None
        assert os.WIFSIGNALED(tracee_status)
        assert os.WTERMSIG(tracee_status) == signal.SIGKILL
        assert not Path(f"/proc/{tracee_pid}").exists()
    finally:
        os.close(read_fd)
        try:
            os.kill(supervisor_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(supervisor_pid, 0)
        except ChildProcessError:
            pass
        assert library.prctl(36, original_subreaper.value, 0, 0, 0) == 0


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root-owned temporary executable and ptrace",
)
def test_path_replacement_cannot_change_executed_fd_and_is_rejected_afterward(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    tool = tmp_path / "pinned-sleep"
    replacement = tmp_path / "replacement"
    shutil.copyfile("/usr/bin/sleep", tool)
    shutil.copyfile("/usr/bin/false", replacement)
    tool.chmod(0o755)
    replacement.chmod(0o755)
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    real_popen = runner.subprocess.Popen
    observed = {}

    def swap_path_then_exec(*args, **kwargs):
        os.replace(replacement, tool)
        process = real_popen(*args, **kwargs)
        observed["process"] = process
        return process

    monkeypatch.setattr(runner.subprocess, "Popen", swap_path_then_exec)
    with pytest.raises(runner.SupervisorError, match="changed across pinned execution"):
        runner._run_pinned_program(
            tool,
            digest,
            [str(tool), "0"],
            label="replacement attack",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=runner.OUTER_ENVIRONMENT,
            timeout=10,
        )
    assert observed["process"].returncode == 0


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux descriptor exec support and root-owned files",
)
def test_publisher_exec_pins_python_and_script_fds_across_last_moment_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python_path = tmp_path / "python"
    publisher_path = tmp_path / "publisher.py"
    python_replacement = tmp_path / "python.replacement"
    publisher_replacement = tmp_path / "publisher.replacement"
    shutil.copyfile(sys.executable, python_path)
    shutil.copyfile("/usr/bin/false", python_replacement)
    python_path.chmod(0o755)
    python_replacement.chmod(0o755)
    publisher_bytes = b"raise SystemExit(0)\n"
    publisher_path.write_bytes(publisher_bytes)
    publisher_path.chmod(0o444)
    publisher_replacement.write_bytes(b"raise SystemExit(99)\n")
    publisher_replacement.chmod(0o444)
    python_digest = hashlib.sha256(python_path.read_bytes()).hexdigest()
    publisher_digest = hashlib.sha256(publisher_bytes).hexdigest()
    captured = {}

    class ExecCalled(RuntimeError):
        pass

    def fake_execve(executable_fd, argv, env):
        os.replace(python_replacement, python_path)
        os.replace(publisher_replacement, publisher_path)
        captured["python_inode"] = os.fstat(executable_fd).st_ino
        script_fd = int(argv[3].rsplit("/", 1)[1])
        os.lseek(script_fd, 0, os.SEEK_SET)
        captured["publisher_bytes"] = os.read(script_fd, 4096)
        captured["argv"] = argv
        captured["env"] = env
        raise ExecCalled

    original_python_inode = python_path.stat().st_ino
    monkeypatch.setattr(runner.os, "execve", fake_execve)
    with pytest.raises(ExecCalled):
        runner._exec_pinned_publisher(
            publisher_path=publisher_path,
            expected_publisher_sha256=publisher_digest,
            publisher_argv=[
                str(python_path),
                "-I",
                "-S",
                str(publisher_path),
                "--example",
            ],
            environment=runner.OUTER_ENVIRONMENT,
            system_python=python_path,
            expected_system_python_sha256=python_digest,
        )
    assert captured["python_inode"] == original_python_inode
    assert captured["publisher_bytes"] == publisher_bytes
    assert captured["argv"][3].startswith("/proc/self/fd/")
    assert captured["env"] == runner.OUTER_ENVIRONMENT


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux descriptor exec support and root-owned files",
)
def test_publisher_exec_rejects_path_replacement_before_final_revalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python_path = tmp_path / "python"
    publisher_path = tmp_path / "publisher.py"
    replacement = tmp_path / "publisher.replacement"
    shutil.copyfile(sys.executable, python_path)
    python_path.chmod(0o755)
    publisher_path.write_bytes(b"raise SystemExit(0)\n")
    publisher_path.chmod(0o444)
    replacement.write_bytes(b"raise SystemExit(99)\n")
    replacement.chmod(0o444)
    publisher_digest = hashlib.sha256(publisher_path.read_bytes()).hexdigest()
    real_revalidate = runner._revalidate_pinned_file
    calls = 0

    def replace_publisher_then_revalidate(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            os.replace(replacement, publisher_path)
        return real_revalidate(*args, **kwargs)

    monkeypatch.setattr(runner, "_revalidate_pinned_file", replace_publisher_then_revalidate)
    with pytest.raises(runner.SupervisorError, match="publisher script changed"):
        runner._exec_pinned_publisher(
            publisher_path=publisher_path,
            expected_publisher_sha256=publisher_digest,
            publisher_argv=[
                str(python_path),
                "-I",
                "-S",
                str(publisher_path),
            ],
            environment=runner.OUTER_ENVIRONMENT,
            system_python=python_path,
            expected_system_python_sha256=hashlib.sha256(
                python_path.read_bytes()
            ).hexdigest(),
        )


def test_main_rejects_before_argument_dispatch_when_python_gate_fails(monkeypatch):
    monkeypatch.setattr(
        runner,
        "_require_system_python",
        lambda: (_ for _ in ()).throw(runner.SupervisorError("wrong python")),
    )
    assert runner.main(["launch"]) == 2

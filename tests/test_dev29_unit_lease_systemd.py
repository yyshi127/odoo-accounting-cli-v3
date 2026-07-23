from __future__ import annotations

import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "deployment" / "dev29" / "run_read_evidence.py"
REAL_GATE = (
    sys.platform == "linux"
    and hasattr(os, "geteuid")
    and os.geteuid() == 0
    and os.environ.get("DEV29_REAL_UNIT_LEASE_TEST") == "1"
    and Path("/run/systemd/system").is_dir()
    and Path("/usr/bin/systemd-run").is_file()
)

pytestmark = pytest.mark.skipif(
    not REAL_GATE,
    reason="requires explicit Linux root systemd lease lifecycle gate",
)


def _load_runner():
    spec = importlib.util.spec_from_file_location("dev29_unit_lease_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


runner = _load_runner()


HELPER = r'''
from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace


def load_runner(path: str):
    spec = importlib.util.spec_from_file_location("dev29_lease_helper_runner", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_identity(directory: Path, name: str, pid: int, runner) -> None:
    path = directory / f"{name}.json"
    payload = {
        "pid": pid,
        "starttime": runner._proc_starttime(pid),
    }
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def arm_parent_death(expected_parent: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(126)
    if os.getppid() != expected_parent:
        os._exit(125)


def worker(arguments) -> int:
    directory = Path(arguments.directory)
    gate_fd = int(arguments.gate_fd)
    expected_parent = int(arguments.expected_parent)
    if os.getppid() != expected_parent:
        return 125
    lease_device = int(arguments.lease_device)
    lease_inode = int(arguments.lease_inode)
    inherited = []
    for name in os.listdir("/proc/self/fd"):
        if not name.isdigit() or int(name) == gate_fd:
            continue
        try:
            metadata = os.stat(f"/proc/self/fd/{name}")
        except FileNotFoundError:
            continue
        if (metadata.st_dev, metadata.st_ino) == (lease_device, lease_inode):
            inherited.append(int(name))
    (directory / "lease-inherited.txt").write_text(
        json.dumps(inherited) + "\n", encoding="utf-8"
    )
    payload = bytearray()
    while True:
        chunk = os.read(gate_fd, 16384)
        if not chunk:
            break
        payload.extend(chunk)
    os.close(gate_fd)
    if not payload.startswith(b"\xa5"):
        return 124
    write_identity(directory, "worker", os.getpid(), arguments.runner)
    (directory / "armed").write_text("armed\n", encoding="utf-8")
    if arguments.mode in {"exec", "timeout"}:
        os.execv("/usr/bin/sleep", ["lease-publisher-like-payload", "60"])
    if arguments.mode == "fail":
        return 7
    time.sleep(1)
    return 0


def wrapper(arguments) -> int:
    directory = Path(arguments.directory)
    payload = json.loads(arguments.payload)
    expected_top_argv = payload.pop("test_expected_top_argv")
    namespace = SimpleNamespace(**payload)
    runner = arguments.runner
    runner._top_level_argv = lambda _arguments, **_kwargs: list(expected_top_argv)

    def validate_test_systemd_run(value, *, arguments, unit, lease):
        del arguments, unit
        fields = {
            "schema_version",
            "method",
            "pid",
            "starttime",
            "parent_pid",
            "parent_starttime",
            "parent_death_signal_setup",
            "parent_death_signal_set_get_verified_before_exec",
            "parent_identity_checked_before_exec",
            "all_checks_passed",
        }
        pid = value.get("pid") if type(value) is dict else None
        if (
            type(value) is not dict
            or set(value) != fields
            or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or value.get("method") != "test-live-systemd-run-v1"
            or type(pid) is not int
            or pid <= 1
            or value.get("starttime") != runner._proc_starttime(pid)
            or value.get("parent_pid") != lease.get("guardian_pid")
            or value.get("parent_starttime") != lease.get("guardian_starttime")
            or runner._single_process_child(
                int(lease["guardian_pid"]), label="test launcher guardian"
            )
            != pid
            or runner._process_fd_matches(
                pid, device=int(lease["device"]), inode=int(lease["inode"])
            )
            or value.get("parent_death_signal_setup") != "SIGKILL"
            or value.get("parent_death_signal_set_get_verified_before_exec") is not True
            or value.get("parent_identity_checked_before_exec") is not True
            or value.get("all_checks_passed") is not True
        ):
            raise runner.SupervisorError("test systemd-run execution proof drifted")

    runner._validate_live_systemd_run_execution = validate_test_systemd_run
    write_identity(directory, "wrapper", os.getpid(), runner)
    if arguments.delay:
        time.sleep(arguments.delay)
    forbidden = runner.LEASE_PARENT / f"forbidden-{os.getpid()}"
    try:
        descriptor = os.open(
            forbidden,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError:
        (directory / "lease-read-only.txt").write_text("verified\n", encoding="utf-8")
    else:
        os.close(descriptor)
        os.unlink(forbidden)
        return 123

    def fake_spawn(_namespace, **_kwargs):
        read_fd, write_fd = os.pipe2(getattr(os, "O_CLOEXEC", 0))
        command = [
            sys.executable,
            __file__,
            "worker",
            "--runner",
            arguments.runner_path,
            "--directory",
            str(directory),
            "--gate-fd",
            str(read_fd),
            "--expected-parent",
            str(os.getpid()),
            "--lease-device",
            str(payload["expected_lease_device"]),
            "--lease-inode",
            str(payload["expected_lease_inode"]),
            "--mode",
            arguments.mode,
        ]
        parent_pid = os.getpid()
        process = subprocess.Popen(
            command,
            pass_fds=(read_fd,),
            close_fds=True,
            preexec_fn=lambda: arm_parent_death(parent_pid),
        )
        os.close(read_fd)
        pidfd = os.pidfd_open(process.pid, 0)
        write_identity(directory, "worker-spawned", process.pid, runner)
        execution = {
            "schema_version": 1,
            "method": "path-exec-ptrace-gated-worker-with-pinned-release-script-v1",
            "worker_pid": process.pid,
            "argv": command,
            "argv_sha256": "0" * 64,
            "python": {},
            "python_device": 1,
            "python_inode": 1,
            "script": {},
            "ptrace_exitkill_set": True,
            "ptrace_exec_stop_verified": True,
            "ptrace_detached_before_gate": True,
            "parent_death_signal": "SIGKILL",
            "parent_identity_checked": True,
            "security_capability_absent": True,
            "pidfd_monitoring": True,
            "all_checks_passed": True,
        }
        return process, pidfd, write_fd, execution

    runner._require_system_python = lambda: None
    runner._spawn_pinned_worker = fake_spawn
    return runner._unit_wrapper(namespace)


def guardian(arguments, launcher_pid: int, launcher_starttime: int) -> int:
    runner = arguments.runner
    directory = Path(arguments.directory)
    write_identity(directory, "guardian", os.getpid(), runner)
    expected_top_argv = runner._read_proc_argv(launcher_pid)
    if runner._read_proc_argv(os.getpid()) != expected_top_argv:
        return 123
    unit = arguments.unit
    lease_fd, lease = runner._create_launcher_lease(
        arguments.evidence_name,
        unit,
        launcher_pid=launcher_pid,
        launcher_starttime=launcher_starttime,
    )
    payload = {
        "action": "unit-wrapper",
        "evidence_name": arguments.evidence_name,
        "expected_release": "0.1.0.dev29-test00000000",
        "expected_unit": unit,
        "expected_worker_script_sha256": "a" * 64,
        "expected_lease_nonce": lease["nonce"],
        "expected_lease_device": str(lease["device"]),
        "expected_lease_inode": str(lease["inode"]),
        "expected_lease_launcher_pid": str(lease["launcher_pid"]),
        "expected_lease_launcher_starttime": str(lease["launcher_starttime"]),
        "expected_lease_guardian_pid": str(lease["guardian_pid"]),
        "expected_lease_guardian_starttime": str(lease["guardian_starttime"]),
        "test_expected_top_argv": expected_top_argv,
    }
    command = [
        "/usr/bin/systemd-run",
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        f"--unit={unit}",
        "--property=Type=exec",
        "--property=User=root",
        "--property=Group=root",
        "--property=ProtectSystem=strict",
        "--property=KillMode=control-group",
        f"--property=RuntimeMaxSec={arguments.runtime_max}s",
        "--property=TimeoutStopSec=5s",
        f"--property=ReadOnlyPaths={runner.LEASE_PARENT}",
        f"--property=ReadWritePaths={directory}",
        sys.executable,
        __file__,
        "wrapper",
        "--runner",
        arguments.runner_path,
        "--directory",
        str(directory),
        "--payload",
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        "--mode",
        arguments.mode,
        "--delay",
        str(arguments.delay),
    ]
    parent_pid = os.getpid()
    process = subprocess.Popen(
        command,
        close_fds=True,
        preexec_fn=lambda: arm_parent_death(parent_pid),
    )
    runner._finalize_launcher_lease_execution(
        lease_fd,
        lease,
        {
            "schema_version": 1,
            "method": "test-live-systemd-run-v1",
            "pid": process.pid,
            "starttime": runner._proc_starttime(process.pid),
            "parent_pid": parent_pid,
            "parent_starttime": runner._proc_starttime(parent_pid),
            "parent_death_signal_setup": "SIGKILL",
            "parent_death_signal_set_get_verified_before_exec": True,
            "parent_identity_checked_before_exec": True,
            "all_checks_passed": True,
        },
    )
    write_identity(directory, "systemd-run", process.pid, runner)
    try:
        return process.wait(timeout=90)
    finally:
        try:
            runner._remove_launcher_lease(lease_fd, lease)
        finally:
            os.close(lease_fd)


def top(arguments) -> int:
    runner = arguments.runner
    directory = Path(arguments.directory)
    launcher_pid = os.getpid()
    launcher_starttime = runner._proc_starttime(launcher_pid)
    write_identity(directory, "top", launcher_pid, runner)
    guardian_pid = os.fork()
    if guardian_pid == 0:
        runner._arm_guardian_parent_death(launcher_pid, launcher_starttime)
        try:
            result = guardian(arguments, launcher_pid, launcher_starttime)
        except BaseException:
            result = 2
        os._exit(runner._normalized_exit_code(result))
    waited, status = os.waitpid(guardian_pid, 0)
    if waited != guardian_pid:
        return 122
    terminal = runner._terminal_wait_status(status)
    return runner._normalized_exit_code(terminal if terminal is not None else 121)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("top", "wrapper", "worker"))
    parser.add_argument("--runner", dest="runner_path", required=True)
    parser.add_argument("--directory", required=True)
    parser.add_argument("--evidence-name")
    parser.add_argument("--unit")
    parser.add_argument("--mode", default="normal")
    parser.add_argument("--runtime-max", type=int, default=30)
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--payload")
    parser.add_argument("--gate-fd")
    parser.add_argument("--expected-parent")
    parser.add_argument("--lease-device")
    parser.add_argument("--lease-inode")
    arguments = parser.parse_args()
    arguments.runner = load_runner(arguments.runner_path)
    if arguments.action == "top":
        return top(arguments)
    if arguments.action == "wrapper":
        return wrapper(arguments)
    return worker(arguments)


raise SystemExit(main())
'''


def _identity(path: Path, timeout: float = 15) -> dict[str, int]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text("utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.05)
            continue
        assert set(value) == {"pid", "starttime"}
        return value
    raise AssertionError(f"identity marker did not appear: {path}")


def _wait_file(path: Path, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.05)
    raise AssertionError(f"marker did not appear: {path}")


def _same_process_is_gone(identity: dict[str, int]) -> bool:
    try:
        return runner._proc_starttime(identity["pid"]) != identity["starttime"]
    except runner.SupervisorError:
        return True


def _wait_collected(unit: str, identities: list[dict[str, int]], timeout: float = 20) -> None:
    deadline = time.monotonic() + timeout
    cgroup = Path("/sys/fs/cgroup/system.slice") / unit
    while time.monotonic() < deadline:
        shown = subprocess.run(
            ["/usr/bin/systemctl", "show", "--property=LoadState", "--value", unit],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout.strip()
        if shown == "not-found" and not cgroup.exists() and all(
            _same_process_is_gone(item) for item in identities
        ):
            return
        time.sleep(0.1)
    raise AssertionError(f"unit/process residue remained for {unit}")


def _prepare(tmp_path: Path, *, mode: str, runtime_max: int = 30, delay: float = 0):
    lease_parent = runner.LEASE_PARENT
    lease_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(lease_parent, 0, 0)
    lease_parent.chmod(0o700)
    metadata = lease_parent.lstat()
    assert stat.S_IMODE(metadata.st_mode) == 0o700
    helper = tmp_path / "unit-lease-helper.py"
    helper.write_text(HELPER, encoding="utf-8")
    helper.chmod(0o555)
    evidence_name = f"lease-{uuid.uuid4().hex[:16]}"
    unit = f"odoo-accounting-cli-v3-dev29-{evidence_name}.service"
    command = [
        sys.executable,
        str(helper),
        "top",
        "--runner",
        str(RUNNER_PATH),
        "--directory",
        str(tmp_path),
        "--evidence-name",
        evidence_name,
        "--unit",
        unit,
        "--mode",
        mode,
        "--runtime-max",
        str(runtime_max),
        "--delay",
        str(delay),
    ]
    process = subprocess.Popen(command, close_fds=True)
    return process, unit, evidence_name


def _finish(
    process: subprocess.Popen[bytes],
    unit: str,
    evidence_name: str,
    tmp_path: Path,
) -> None:
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
        raise
    identities = []
    for name in ("top", "guardian", "systemd-run", "wrapper", "worker-spawned", "worker"):
        path = tmp_path / f"{name}.json"
        if path.is_file():
            identities.append(json.loads(path.read_text("utf-8")))
    _wait_collected(unit, identities)
    lease = runner._lease_path(evidence_name)
    if os.path.lexists(lease):
        runner._remove_proven_stale_lease(lease)
    assert not os.path.lexists(lease)


def _kill_marked(tmp_path: Path, name: str) -> dict[str, int]:
    identity = _identity(tmp_path / f"{name}.json")
    os.kill(identity["pid"], signal.SIGKILL)
    return identity


def test_real_systemd_lease_normal_completion_is_read_only_and_not_inherited(
    tmp_path: Path,
) -> None:
    process, unit, evidence_name = _prepare(tmp_path, mode="normal")
    try:
        _wait_file(tmp_path / "armed")
        _wait_file(tmp_path / "lease-read-only.txt")
        assert json.loads((tmp_path / "lease-inherited.txt").read_text("utf-8")) == []
        read_only = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--property=ReadOnlyPaths",
                "--value",
                unit,
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        read_write = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--property=ReadWritePaths",
                "--value",
                unit,
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        assert str(runner.LEASE_PARENT) in read_only
        assert str(runner.LEASE_PARENT) not in read_write
    finally:
        _finish(process, unit, evidence_name, tmp_path)


def test_real_systemd_top_launcher_sigkill_after_worker_exec_kills_everything(
    tmp_path: Path,
) -> None:
    process, unit, evidence_name = _prepare(tmp_path, mode="exec")
    _wait_file(tmp_path / "armed")
    _kill_marked(tmp_path, "top")
    _finish(process, unit, evidence_name, tmp_path)


def test_real_systemd_guardian_sigkill_after_arm_kills_everything(tmp_path: Path) -> None:
    process, unit, evidence_name = _prepare(tmp_path, mode="exec")
    _wait_file(tmp_path / "armed")
    _kill_marked(tmp_path, "guardian")
    _finish(process, unit, evidence_name, tmp_path)


def test_real_systemd_systemd_run_sigkill_after_arm_kills_everything(
    tmp_path: Path,
) -> None:
    process, unit, evidence_name = _prepare(tmp_path, mode="exec")
    _wait_file(tmp_path / "armed")
    _kill_marked(tmp_path, "systemd-run")
    _finish(process, unit, evidence_name, tmp_path)


def test_real_systemd_wrapper_sigkill_kills_execed_worker_and_collects_unit(
    tmp_path: Path,
) -> None:
    process, unit, evidence_name = _prepare(tmp_path, mode="exec")
    _wait_file(tmp_path / "armed")
    _kill_marked(tmp_path, "wrapper")
    _finish(process, unit, evidence_name, tmp_path)


def test_real_systemd_worker_sigkill_is_reaped_and_collects_unit(tmp_path: Path) -> None:
    process, unit, evidence_name = _prepare(tmp_path, mode="exec")
    _wait_file(tmp_path / "armed")
    _kill_marked(tmp_path, "worker")
    _finish(process, unit, evidence_name, tmp_path)


def test_real_systemd_launcher_death_before_delayed_arm_starts_no_worker(
    tmp_path: Path,
) -> None:
    process, unit, evidence_name = _prepare(tmp_path, mode="exec", delay=3)
    _identity(tmp_path / "systemd-run.json")
    _kill_marked(tmp_path, "top")
    _finish(process, unit, evidence_name, tmp_path)
    assert not (tmp_path / "worker-spawned.json").exists()
    assert not (tmp_path / "armed").exists()


def test_real_systemd_failure_and_runtime_timeout_leave_no_process_or_unit(
    tmp_path: Path,
) -> None:
    failure = tmp_path / "failure"
    failure.mkdir()
    process, unit, evidence_name = _prepare(failure, mode="fail")
    _wait_file(failure / "armed")
    _finish(process, unit, evidence_name, failure)
    timeout = tmp_path / "timeout"
    timeout.mkdir()
    process, unit, evidence_name = _prepare(timeout, mode="timeout", runtime_max=2)
    _wait_file(timeout / "armed")
    _finish(process, unit, evidence_name, timeout)

#!/usr/bin/python3
"""Launch and supervise the single-unit Dev29 real-read evidence lifecycle."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import re
import secrets
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable, Iterable, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - imported for Linux deployment
    fcntl = None  # type: ignore[assignment]


sys.dont_write_bytecode = True
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SYSTEM_PYTHON = Path("/usr/bin/python3.12")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
LDCONFIG = Path("/usr/sbin/ldconfig.real")
LD_SO_PRELOAD = Path("/etc/ld.so.preload")
RELEASE_PARENT = Path("/opt/odoo-accounting-cli-v3/releases")
PACKAGE_PARENT = Path("/opt/odoo-accounting-cli-v3/packages")
TRUST_PARENT = Path("/opt/odoo-accounting-cli-v3/trusted-artifacts")
RUNTIME_PARENT = Path("/etc/odoo-accounting-cli-v3/candidates")
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
PRIVATE_EVIDENCE_PARENT = Path(
    "/var/lib/odoo-accounting-cli-v3/evidence-private"
)
RUNTIME_TRACE_STAGING_PARENT = Path(
    "/var/lib/odoo-accounting-cli-v3/runtime-open-trace"
)
ANCHOR_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence-anchors")
BROKER_HOME = Path("/var/lib/odoo-accounting-cli-v3-broker")
STAGING_PARENT = Path("/run/odoo-accounting-cli-v3-dev29")
LEASE_PARENT = Path("/run/odoo-accounting-cli-v3-dev29-leases")
VERIFIER_SIDECAR_SUFFIX = ".verifier"
RUNNER_RELATIVE = PurePosixPath("deployment/dev29/run_read_evidence.py")
SUITE_RELATIVE = PurePosixPath("deployment/dev29/run_read_suite.py")
CLOSURE_RELATIVE = PurePosixPath("deployment/dev29/odoo_closure.py")
VERIFIER_RELATIVE = PurePosixPath("deployment/dev29/verify_read_evidence.py")
PUBLISHER_RELATIVE = PurePosixPath("deployment/dev29/publish_read_evidence.py")
DIRECT_CHILD_RELATIVE = PurePosixPath("deployment/dev29/direct_child.py")
TRACE_RELATIVE = PurePosixPath("deployment/dev29/runtime_open_trace.py")
PLAN_RELATIVE = PurePosixPath("deployment/dev29/read_plan.json")
OUTER_CAPABILITIES = (
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
)
OUTER_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
}
SYSTEMD_RUN_COMMUNICATE_TIMEOUT_SECONDS = 3690
PR_SET_PDEATHSIG = 1
PR_GET_PDEATHSIG = 2
SIGKILL = getattr(signal, "SIGKILL", 9)
LEASE_POLL_SECONDS = 0.05
COMMON_OPTIONS = (
    ("evidence_name", "--evidence-name"),
    ("expected_release", "--expected-release"),
    ("expected_version", "--expected-version"),
    ("expected_commit", "--expected-commit"),
    ("expected_manifest_sha256", "--expected-manifest-sha256"),
    ("expected_package_sha256", "--expected-package-sha256"),
    ("expected_closure_anchor_sha256", "--expected-closure-anchor-sha256"),
    ("expected_closure_image_sha256", "--expected-closure-image-sha256"),
    ("expected_system_python_sha256", "--expected-system-python-sha256"),
    ("expected_ld_so_preload_sha256", "--expected-ld-so-preload-sha256"),
    ("expected_ldconfig_sha256", "--expected-ldconfig-sha256"),
    ("expected_systemd_run_sha256", "--expected-systemd-run-sha256"),
    ("expected_systemctl_sha256", "--expected-systemctl-sha256"),
    ("expected_strace_sha256", "--expected-strace-sha256"),
    ("expected_runtime_open_index_sha256", "--expected-runtime-open-index-sha256"),
    ("expected_registry_digest", "--expected-registry-digest"),
)
DISCOVERY_OPTIONS = (
    ("runtime_open_discovery_inventory", "--runtime-open-discovery-inventory"),
    (
        "runtime_open_discovery_static_closure_sha256",
        "--runtime-open-discovery-static-closure-sha256",
    ),
    ("runtime_open_discovery_watch_root", "--runtime-open-discovery-watch-root"),
    ("runtime_open_discovery_mutable_root", "--runtime-open-discovery-mutable-root"),
    (
        "runtime_open_discovery_sqlite_delta_contract_sha256",
        "--runtime-open-discovery-sqlite-delta-contract-sha256",
    ),
)
VERIFIER_DISCOVERY_OPTIONS = (
    ("verifier_evidence_dir", "--verifier-evidence-dir"),
    ("verifier_fragment_output", "--verifier-fragment-output"),
    ("expected_bundle_manifest_sha256", "--expected-bundle-manifest-sha256"),
)
LEASE_OPTIONS = (
    ("expected_lease_nonce", "--expected-lease-nonce"),
    ("expected_lease_device", "--expected-lease-device"),
    ("expected_lease_inode", "--expected-lease-inode"),
    ("expected_lease_launcher_pid", "--expected-lease-launcher-pid"),
    (
        "expected_lease_launcher_starttime",
        "--expected-lease-launcher-starttime",
    ),
    ("expected_lease_guardian_pid", "--expected-lease-guardian-pid"),
    (
        "expected_lease_guardian_starttime",
        "--expected-lease-guardian-starttime",
    ),
)
WORKER_PIN_OPTIONS = (
    ("expected_worker_python_fd", "--expected-worker-python-fd"),
    ("expected_worker_python_device", "--expected-worker-python-device"),
    ("expected_worker_python_inode", "--expected-worker-python-inode"),
    ("expected_worker_script_fd", "--expected-worker-script-fd"),
    ("expected_worker_script_device", "--expected-worker-script-device"),
    ("expected_worker_script_inode", "--expected-worker-script-inode"),
)
WORKER_BOOTSTRAP: dict[str, Any] | None = None
PUBLISHER_STAGE_FILES = frozenset(
    {
        "validation-report.json",
        "cleanup-receipt.json",
        "verifier-child.json",
        "verifier-process-control.json",
        "prepublication-guard.json",
        "supervisor-bootstrap.json",
        "verifier-runtime-trace.json",
    }
)


class SupervisorError(RuntimeError):
    pass


def _verifier_private_sidecar_path(evidence_name: str) -> Path:
    if SAFE_NAME.fullmatch(evidence_name) is None:
        raise SupervisorError("verifier sidecar evidence name is invalid")
    return PRIVATE_EVIDENCE_PARENT / f"{evidence_name}{VERIFIER_SIDECAR_SUFFIX}"


class SupervisorInterrupted(SupervisorError):
    pass


def _require_system_python() -> None:
    if (
        os.name != "posix"
        or os.geteuid() != 0
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or Path(sys.executable).resolve(strict=True) != SYSTEM_PYTHON
        or Path("/proc/self/exe").resolve(strict=True) != SYSTEM_PYTHON
    ):
        raise SupervisorError(
            "Dev29 lifecycle requires root /usr/bin/python3.12 -I -S"
        )


def _verify_preload(expected_sha256: str) -> dict[str, Any]:
    payload = _read(LD_SO_PRELOAD, label="ld.so.preload", maximum=64 * 1024)
    metadata = LD_SO_PRELOAD.lstat()
    if (
        HEX64.fullmatch(expected_sha256) is None
        or hashlib.sha256(payload).hexdigest() != expected_sha256
        or LD_SO_PRELOAD.is_symlink()
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_nlink != 1
    ):
        raise SupervisorError("ld.so.preload identity drifted")
    return {
        "path": str(LD_SO_PRELOAD),
        "sha256": expected_sha256,
        "size": len(payload),
        "uid": 0,
        "gid": 0,
        "mode": "0644",
    }


def _verify_writable_directory(
    path: Path, *, uid: int, gid: int, mode: int
) -> None:
    current = Path("/")
    for component in path.absolute().parts[1:]:
        current /= component
        metadata = current.lstat()
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, uid}
            or stat.S_IMODE(metadata.st_mode) & 0o002
        ):
            raise SupervisorError(f"writable path chain is unsafe: {current}")
    metadata = path.lstat()
    if (
        (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise SupervisorError(f"writable directory identity drifted: {path}")


def _verify_lease_parent() -> None:
    if os.name != "posix" or fcntl is None:
        raise SupervisorError("launcher lease requires Linux flock support")
    metadata = LEASE_PARENT.lstat()
    if (
        LEASE_PARENT.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SupervisorError("launcher lease directory identity drifted")


def _lease_path(evidence_name: str) -> Path:
    if SAFE_NAME.fullmatch(evidence_name) is None:
        raise SupervisorError("launcher lease evidence name is invalid")
    return LEASE_PARENT / f"{evidence_name}.lease"


def _proc_starttime(pid: int) -> int:
    if type(pid) is not int or pid <= 1:
        raise SupervisorError("process identity PID is invalid")
    try:
        payload = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError as exc:
        raise SupervisorError("process identity is no longer live") from exc
    if len(payload) > 64 * 1024 or not payload.endswith(b"\n"):
        raise SupervisorError("process identity stat record is invalid")
    first_space = payload.find(b" ")
    close = payload.rfind(b")")
    if close < 2 or payload[:first_space] != str(pid).encode("ascii"):
        raise SupervisorError("process identity stat record is invalid")
    fields = payload[close + 2 :].strip().split()
    if len(fields) < 20 or not fields[19].isdigit():
        raise SupervisorError("process identity stat record is invalid")
    return int(fields[19])


def _strict_positive_decimal(value: Any, *, label: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise SupervisorError(f"{label} is invalid")
    result = int(value)
    if str(result) != value:
        raise SupervisorError(f"{label} is invalid")
    return result


def _read_small_descriptor(descriptor: int, *, label: str) -> bytes:
    before = os.fstat(descriptor)
    if before.st_size <= 0 or before.st_size > 16 * 1024:
        raise SupervisorError(f"{label} size is invalid")
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) < before.st_size:
        chunk = os.read(descriptor, before.st_size - len(payload))
        if not chunk:
            raise SupervisorError(f"{label} changed during read")
        payload.extend(chunk)
    if os.read(descriptor, 1):
        raise SupervisorError(f"{label} changed during read")
    os.lseek(descriptor, 0, os.SEEK_SET)
    after = os.fstat(descriptor)
    if _pinned_stat_identity(before) != _pinned_stat_identity(after):
        raise SupervisorError(f"{label} changed during read")
    return bytes(payload)


def _parse_lease_payload(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise SupervisorError("launcher lease payload is invalid") from exc
    if type(value) is not dict or canonical_json(value) + b"\n" != payload:
        raise SupervisorError("launcher lease payload is not canonical")
    return value


def _lease_metadata(descriptor: int, *, allowed_modes: frozenset[int]) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
        or stat.S_IMODE(metadata.st_mode) not in allowed_modes
        or metadata.st_nlink != 1
    ):
        raise SupervisorError("launcher lease metadata is unsafe")
    return metadata


def _flock_is_owned_elsewhere(descriptor: int) -> bool:
    assert fcntl is not None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            return True
        raise SupervisorError("launcher lease lock cannot be verified") from exc
    return False


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _remove_proven_stale_lease(path: Path) -> None:
    """Remove only a safe inode for which this process acquired the sole flock."""
    assert fcntl is not None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = _lease_metadata(descriptor, allowed_modes=frozenset({0o400, 0o600}))
        if _flock_is_owned_elsewhere(descriptor):
            raise SupervisorError("launcher lease is already owned")
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_nlink) != (
            metadata.st_dev,
            metadata.st_ino,
            1,
        ):
            raise SupervisorError("stale launcher lease path changed")
        os.unlink(path)
        _fsync_directory(LEASE_PARENT)
    finally:
        os.close(descriptor)


def _create_launcher_lease(
    evidence_name: str,
    unit: str,
    *,
    launcher_pid: int | None = None,
    launcher_starttime: int | None = None,
    expected_process_argv: list[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    _verify_lease_parent()
    assert fcntl is not None
    path = _lease_path(evidence_name)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for attempt in range(2):
        try:
            descriptor = os.open(path, flags, 0o600)
            break
        except FileExistsError:
            if attempt:
                raise SupervisorError("launcher lease cannot be created")
            _remove_proven_stale_lease(path)
    else:  # pragma: no cover
        raise SupervisorError("launcher lease cannot be created")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        metadata = _lease_metadata(descriptor, allowed_modes=frozenset({0o600}))
        guardian_pid = os.getpid()
        guardian_starttime = _proc_starttime(guardian_pid)
        if launcher_pid is None:
            launcher_pid = guardian_pid
        if launcher_starttime is None:
            launcher_starttime = guardian_starttime
        if _proc_starttime(launcher_pid) != launcher_starttime:
            raise SupervisorError("request launcher identity changed before lease")
        launcher_argv = _read_proc_argv(launcher_pid)
        guardian_argv = _read_proc_argv(guardian_pid)
        guardian_parent_death_signal = _parent_death_signal()
        if (
            launcher_argv != guardian_argv
            or (
                expected_process_argv is not None
                and (
                    launcher_argv != expected_process_argv
                    or guardian_argv != expected_process_argv
                )
            )
        ):
            raise SupervisorError("launcher and guardian argv binding is invalid")
        document = {
            "schema_version": 1,
            "evidence_name": evidence_name,
            "unit": unit,
            "path": str(path),
            "nonce": secrets.token_hex(32),
            "launcher_pid": launcher_pid,
            "launcher_starttime": launcher_starttime,
            "guardian_pid": guardian_pid,
            "guardian_starttime": guardian_starttime,
            "launcher_argv": launcher_argv,
            "launcher_argv_sha256": hashlib.sha256(
                canonical_json(launcher_argv)
            ).hexdigest(),
            "guardian_argv": guardian_argv,
            "guardian_argv_sha256": hashlib.sha256(
                canonical_json(guardian_argv)
            ).hexdigest(),
            "guardian_parent_death_signal": guardian_parent_death_signal,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "nlink": 1,
            "mode": "0400",
        }
        payload = canonical_json(document) + b"\n"
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        final = _lease_metadata(descriptor, allowed_modes=frozenset({0o400}))
        if (final.st_dev, final.st_ino) != (document["device"], document["inode"]):
            raise SupervisorError("launcher lease inode changed during creation")
        _fsync_directory(LEASE_PARENT)
        return descriptor, document
    except BaseException:
        try:
            current = path.lstat()
            opened = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                os.unlink(path)
                _fsync_directory(LEASE_PARENT)
        except OSError:
            pass
        os.close(descriptor)
        raise


def _finalize_launcher_lease_execution(
    descriptor: int,
    document: dict[str, Any],
    execution: Mapping[str, Any],
) -> None:
    """Freeze the live pinned systemd-run exec-stop proof before it can run."""
    if "systemd_run_execution" in document:
        raise SupervisorError("launcher lease execution proof is already finalized")
    metadata = _lease_metadata(descriptor, allowed_modes=frozenset({0o400}))
    path = Path(str(document["path"]))
    current = path.lstat()
    if (
        _flock_is_owned_elsewhere(descriptor)
        or (metadata.st_dev, metadata.st_ino)
        != (document.get("device"), document.get("inode"))
        or (current.st_dev, current.st_ino, current.st_nlink)
        != (metadata.st_dev, metadata.st_ino, 1)
        or type(execution) is not dict
        or execution.get("parent_pid") != document.get("guardian_pid")
        or execution.get("parent_starttime") != document.get("guardian_starttime")
        or execution.get("parent_death_signal_setup") != "SIGKILL"
        or execution.get("parent_death_signal_set_get_verified_before_exec") is not True
        or execution.get("parent_identity_checked_before_exec") is not True
        or execution.get("all_checks_passed") is not True
    ):
        raise SupervisorError("launcher lease execution proof is invalid")
    finalized = {**document, "systemd_run_execution": dict(execution)}
    payload = canonical_json(finalized) + b"\n"
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    written = 0
    while written < len(payload):
        written += os.write(descriptor, payload[written:])
    os.fsync(descriptor)
    final = _lease_metadata(descriptor, allowed_modes=frozenset({0o400}))
    if (final.st_dev, final.st_ino, final.st_size) != (
        document["device"],
        document["inode"],
        len(payload),
    ):
        raise SupervisorError("launcher lease changed during execution finalization")
    _fsync_directory(LEASE_PARENT)
    document.clear()
    document.update(finalized)


def _remove_launcher_lease(descriptor: int, document: Mapping[str, Any]) -> None:
    path = Path(str(document["path"]))
    metadata = _lease_metadata(descriptor, allowed_modes=frozenset({0o400}))
    if _flock_is_owned_elsewhere(descriptor):
        raise SupervisorError("launcher lost its own lease lock")
    current = path.lstat()
    if (
        (metadata.st_dev, metadata.st_ino) != (document["device"], document["inode"])
        or (current.st_dev, current.st_ino, current.st_nlink)
        != (metadata.st_dev, metadata.st_ino, 1)
    ):
        raise SupervisorError("launcher lease changed before cleanup")
    os.unlink(path)
    _fsync_directory(LEASE_PARENT)


def _expected_lease(arguments: argparse.Namespace, *, unit: str) -> dict[str, Any]:
    nonce = arguments.expected_lease_nonce
    if not isinstance(nonce, str) or HEX64.fullmatch(nonce) is None:
        raise SupervisorError("launcher lease nonce is invalid")
    device = _strict_positive_decimal(
        arguments.expected_lease_device, label="launcher lease device"
    )
    inode = _strict_positive_decimal(
        arguments.expected_lease_inode, label="launcher lease inode"
    )
    launcher_pid = _strict_positive_decimal(
        arguments.expected_lease_launcher_pid, label="launcher lease PID"
    )
    starttime = _strict_positive_decimal(
        arguments.expected_lease_launcher_starttime,
        label="launcher lease process start time",
    )
    guardian_pid = _strict_positive_decimal(
        arguments.expected_lease_guardian_pid, label="launcher guardian PID"
    )
    guardian_starttime = _strict_positive_decimal(
        arguments.expected_lease_guardian_starttime,
        label="launcher guardian process start time",
    )
    launcher_argv = _read_proc_argv(launcher_pid)
    guardian_argv = _read_proc_argv(guardian_pid)
    if "recover" in arguments.action:
        top_action = "recover"
    elif "trace-verifier-fragment" in arguments.action:
        top_action = "trace-verifier-fragment"
    else:
        top_action = "launch"
    expected_argv = _top_level_argv(
        arguments,
        root=RELEASE_PARENT / arguments.expected_release,
        action=top_action,
    )
    if launcher_argv != expected_argv or guardian_argv != expected_argv:
        raise SupervisorError("launcher and guardian argv binding drifted")
    return {
        "schema_version": 1,
        "evidence_name": arguments.evidence_name,
        "unit": unit,
        "path": str(_lease_path(arguments.evidence_name)),
        "nonce": nonce,
        "launcher_pid": launcher_pid,
        "launcher_starttime": starttime,
        "guardian_pid": guardian_pid,
        "guardian_starttime": guardian_starttime,
        "launcher_argv": launcher_argv,
        "launcher_argv_sha256": hashlib.sha256(
            canonical_json(launcher_argv)
        ).hexdigest(),
        "guardian_argv": guardian_argv,
        "guardian_argv_sha256": hashlib.sha256(
            canonical_json(guardian_argv)
        ).hexdigest(),
        "guardian_parent_death_signal": SIGKILL,
        "device": device,
        "inode": inode,
        "nlink": 1,
        "mode": "0400",
    }


def _process_fd_matches(pid: int, *, device: int, inode: int) -> list[int]:
    matches: list[int] = []
    try:
        names = os.listdir(f"/proc/{pid}/fd")
    except OSError as exc:
        raise SupervisorError("process descriptor table cannot be inspected") from exc
    for name in names:
        if not name.isdigit():
            raise SupervisorError("process descriptor table is invalid")
        try:
            metadata = os.stat(f"/proc/{pid}/fd/{name}")
        except FileNotFoundError:
            continue
        if (metadata.st_dev, metadata.st_ino) == (device, inode):
            matches.append(int(name))
    return sorted(matches)


def _read_proc_argv(pid: int) -> list[str]:
    try:
        payload = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as exc:
        raise SupervisorError("process argv cannot be inspected") from exc
    if not payload or len(payload) > 1024 * 1024 or not payload.endswith(b"\0"):
        raise SupervisorError("process argv is invalid")
    try:
        result = [item.decode("utf-8", "strict") for item in payload[:-1].split(b"\0")]
    except UnicodeError as exc:
        raise SupervisorError("process argv is invalid") from exc
    if not result or any(not item for item in result):
        raise SupervisorError("process argv is invalid")
    return result


def _process_has_pidfd_for(owner_pid: int, target_pid: int) -> bool:
    try:
        names = os.listdir(f"/proc/{owner_pid}/fdinfo")
    except OSError as exc:
        raise SupervisorError("wrapper pidfd table cannot be inspected") from exc
    marker = f"Pid:\t{target_pid}\n".encode("ascii")
    matches = 0
    for name in names:
        if not name.isdigit():
            raise SupervisorError("wrapper pidfd table is invalid")
        try:
            payload = Path(f"/proc/{owner_pid}/fdinfo/{name}").read_bytes()
        except FileNotFoundError:
            continue
        if len(payload) > 64 * 1024:
            raise SupervisorError("wrapper pidfd record is invalid")
        if marker in payload:
            matches += 1
    return matches == 1


def _single_process_child(parent_pid: int, *, label: str) -> int:
    try:
        payload = Path(
            f"/proc/{parent_pid}/task/{parent_pid}/children"
        ).read_text("ascii")
    except OSError as exc:
        raise SupervisorError(f"{label} child identity cannot be inspected") from exc
    fields = payload.split()
    if len(fields) != 1 or not fields[0].isdigit() or int(fields[0]) <= 1:
        raise SupervisorError(f"{label} child identity is invalid")
    return int(fields[0])


def _validate_live_systemd_run_execution(
    value: Any,
    *,
    arguments: argparse.Namespace,
    unit: str,
    lease: Mapping[str, Any],
) -> None:
    fields = {
        "schema_version",
        "method",
        "pid",
        "starttime",
        "parent_pid",
        "parent_starttime",
        "argv",
        "argv_sha256",
        "file",
        "pinned_device",
        "pinned_inode",
        "proc_exe_device",
        "proc_exe_inode",
        "ptrace_exitkill_set",
        "ptrace_exec_stop_verified",
        "parent_death_signal_setup",
        "parent_death_signal_set_get_verified_before_exec",
        "parent_identity_checked_before_exec",
        "security_capability_absent",
        "pidfd_opened_before_exec_stop_release",
        "all_checks_passed",
    }
    file_fields = {
        "path",
        "sha256",
        "size",
        "uid",
        "gid",
        "mode",
        "device",
        "inode",
    }
    systemd_pid = value.get("pid") if type(value) is dict else None
    file_identity = value.get("file") if type(value) is dict else None
    if "recover" in arguments.action:
        wrapper_action = "recover-unit-wrapper"
    elif "trace-verifier-fragment" in arguments.action:
        wrapper_action = "trace-verifier-fragment-unit-wrapper"
    else:
        wrapper_action = "unit-wrapper"
    root = RELEASE_PARENT / arguments.expected_release
    wrapper_argv = _wrapper_argv(
        arguments,
        root=root,
        action=wrapper_action,
        unit=unit,
        worker_script_sha256=arguments.expected_worker_script_sha256,
    )
    expected_argv = _systemd_run_argv(
        unit=unit,
        root=root,
        writable=_outer_writable_paths(arguments.expected_release),
        wrapper_argv=wrapper_argv,
    )
    if (
        type(value) is not dict
        or set(value) != fields
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("method") != "open-fd-ptrace-live-exec-v1"
        or type(systemd_pid) is not int
        or systemd_pid <= 1
        or value.get("parent_pid") != lease.get("guardian_pid")
        or value.get("parent_starttime") != lease.get("guardian_starttime")
        or value.get("argv") != expected_argv
        or value.get("argv_sha256")
        != hashlib.sha256(canonical_json(expected_argv)).hexdigest()
        or type(file_identity) is not dict
        or set(file_identity) != file_fields
        or file_identity.get("path") != str(SYSTEMD_RUN)
        or file_identity.get("sha256") != arguments.expected_systemd_run_sha256
        or type(file_identity.get("size")) is not int
        or file_identity["size"] <= 0
        or file_identity.get("uid") != 0
        or file_identity.get("gid") != 0
        or file_identity.get("mode") != "0755"
        or type(file_identity.get("device")) is not int
        or file_identity["device"] <= 0
        or type(file_identity.get("inode")) is not int
        or file_identity["inode"] <= 0
        or value.get("pinned_device") != file_identity["device"]
        or value.get("pinned_inode") != file_identity["inode"]
        or value.get("proc_exe_device") != file_identity["device"]
        or value.get("proc_exe_inode") != file_identity["inode"]
        or value.get("ptrace_exitkill_set") is not True
        or value.get("ptrace_exec_stop_verified") is not True
        or value.get("parent_death_signal_setup") != "SIGKILL"
        or value.get("parent_death_signal_set_get_verified_before_exec") is not True
        or value.get("parent_identity_checked_before_exec") is not True
        or value.get("security_capability_absent") is not True
        or value.get("pidfd_opened_before_exec_stop_release") is not True
        or value.get("all_checks_passed") is not True
    ):
        raise SupervisorError("launcher systemd-run execution proof is invalid")
    try:
        executed = Path(f"/proc/{systemd_pid}/exe").stat()
    except OSError as exc:
        raise SupervisorError("launcher systemd-run executable is unavailable") from exc
    if (
        value.get("starttime") != _proc_starttime(systemd_pid)
        or _read_proc_argv(systemd_pid) != expected_argv
        or _single_process_child(
            int(lease["guardian_pid"]), label="launcher guardian"
        )
        != systemd_pid
        or not _process_has_pidfd_for(int(lease["guardian_pid"]), systemd_pid)
        or (executed.st_dev, executed.st_ino)
        != (file_identity["device"], file_identity["inode"])
        or _process_fd_matches(
            systemd_pid, device=int(lease["device"]), inode=int(lease["inode"])
        )
    ):
        raise SupervisorError("launcher live systemd-run execution drifted")


def _open_monitored_lease(
    arguments: argparse.Namespace, *, unit: str
) -> tuple[int, dict[str, Any]]:
    _verify_lease_parent()
    expected = _expected_lease(arguments, unit=unit)
    if _process_fd_matches(
        os.getpid(), device=expected["device"], inode=expected["inode"]
    ):
        raise SupervisorError("launcher lease descriptor was inherited by the unit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(expected["path"], flags)
    try:
        metadata = _lease_metadata(descriptor, allowed_modes=frozenset({0o400}))
        path_metadata = Path(expected["path"]).lstat()
        observed = _parse_lease_payload(
            _read_small_descriptor(descriptor, label="launcher lease")
        )
        if (
            (metadata.st_dev, metadata.st_ino) != (
                expected["device"],
                expected["inode"],
            )
            or (path_metadata.st_dev, path_metadata.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or set(observed) != {*expected, "systemd_run_execution"}
            or any(observed.get(key) != item for key, item in expected.items())
            or _proc_starttime(expected["launcher_pid"])
            != expected["launcher_starttime"]
            or _proc_starttime(expected["guardian_pid"])
            != expected["guardian_starttime"]
        ):
            raise SupervisorError("launcher lease identity drifted")
        if not _flock_is_owned_elsewhere(descriptor):
            raise SupervisorError("launcher lease has no live lock owner")
        if _single_process_child(
            expected["launcher_pid"], label="top launcher"
        ) != expected["guardian_pid"]:
            raise SupervisorError("launcher guardian relationship drifted")
        _validate_live_systemd_run_execution(
            observed["systemd_run_execution"],
            arguments=arguments,
            unit=unit,
            lease=observed,
        )
        return descriptor, observed
    except BaseException:
        os.close(descriptor)
        raise


def _parent_death_signal() -> int:
    library = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int()
    if library.prctl(PR_GET_PDEATHSIG, ctypes.byref(value), 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise SupervisorError("worker parent-death signal cannot be read") from OSError(
            error, os.strerror(error)
        )
    return value.value


def _hash_open_descriptor(descriptor: int, *, maximum: int, label: str) -> str:
    before = os.fstat(descriptor)
    if before.st_size <= 0 or before.st_size > maximum:
        raise SupervisorError(f"{label} size is invalid")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = before.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise SupervisorError(f"{label} changed during hashing")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise SupervisorError(f"{label} changed during hashing")
    os.lseek(descriptor, 0, os.SEEK_SET)
    if _pinned_stat_identity(before) != _pinned_stat_identity(os.fstat(descriptor)):
        raise SupervisorError(f"{label} changed during hashing")
    return digest.hexdigest()


def _await_worker_gate(arguments: argparse.Namespace, *, root: Path) -> None:
    """Validate inherited pins, close them, and cross the wrapper's one-byte gate."""
    global WORKER_BOOTSTRAP
    wrapper_pid = _strict_positive_decimal(
        arguments.expected_wrapper_pid, label="worker wrapper PID"
    )
    if os.getppid() != wrapper_pid or _parent_death_signal() != SIGKILL:
        raise SupervisorError("worker parent-death protection is invalid")
    python_fd = _strict_positive_decimal(
        arguments.expected_worker_python_fd, label="worker Python descriptor"
    )
    script_fd = _strict_positive_decimal(
        arguments.expected_worker_script_fd, label="worker script descriptor"
    )
    gate_fd = _strict_positive_decimal(arguments.worker_gate_fd, label="worker gate")
    if len({python_fd, script_fd, gate_fd}) != 3:
        raise SupervisorError("worker inherited descriptors are not unique")
    gate_metadata = os.fstat(gate_fd)
    expected_python = (
        _strict_positive_decimal(
            arguments.expected_worker_python_device,
            label="worker Python device",
        ),
        _strict_positive_decimal(
            arguments.expected_worker_python_inode,
            label="worker Python inode",
        ),
    )
    expected_script = (
        _strict_positive_decimal(
            arguments.expected_worker_script_device,
            label="worker script device",
        ),
        _strict_positive_decimal(
            arguments.expected_worker_script_inode,
            label="worker script inode",
        ),
    )
    script_path = root.joinpath(*RUNNER_RELATIVE.parts)
    if (
        not stat.S_ISFIFO(gate_metadata.st_mode)
        or Path("/proc/self/exe").stat().st_ino != expected_python[1]
    ):
        raise SupervisorError("worker pinned executable identity drifted")
    python_identity = {
        "path": str(SYSTEM_PYTHON),
        "sha256": arguments.expected_system_python_sha256,
        "device": expected_python[0],
        "inode": expected_python[1],
    }
    script_identity = {
        "path": str(script_path),
        "sha256": arguments.expected_worker_script_sha256,
        "device": expected_script[0],
        "inode": expected_script[1],
    }
    try:
        os.close(python_fd)
    except OSError:
        pass
    try:
        os.close(script_fd)
    except OSError:
        pass
    try:
        gate_payload = bytearray()
        while len(gate_payload) <= 128 * 1024:
            chunk = os.read(gate_fd, 16 * 1024)
            if not chunk:
                break
            gate_payload.extend(chunk)
        if len(gate_payload) > 128 * 1024 or gate_payload[:1] != b"\xa5":
            raise SupervisorError("worker arm gate is invalid")
        try:
            wrapper_execution = json.loads(
                bytes(gate_payload[1:]), object_pairs_hook=_pairs
            )
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise SupervisorError("worker arm proof is invalid") from exc
        if (
            type(wrapper_execution) is not dict
            or canonical_json(wrapper_execution) + b"\n" != bytes(gate_payload[1:])
            or wrapper_execution.get("method")
            != "path-exec-ptrace-gated-worker-with-pinned-release-script-v1"
            or wrapper_execution.get("worker_pid") != os.getpid()
            or wrapper_execution.get("parent_death_signal") != "SIGKILL"
            or wrapper_execution.get("pidfd_monitoring") is not True
            or wrapper_execution.get("all_checks_passed") is not True
            or not isinstance(wrapper_execution.get("python"), dict)
            or wrapper_execution["python"].get("path") != str(SYSTEM_PYTHON)
            or wrapper_execution["python"].get("sha256")
            != arguments.expected_system_python_sha256
            or wrapper_execution.get("python_device") != expected_python[0]
            or wrapper_execution.get("python_inode") != expected_python[1]
            or wrapper_execution.get("script") != script_identity
            or not isinstance(wrapper_execution.get("argv"), list)
            or len(wrapper_execution["argv"]) < 4
            or wrapper_execution["argv"][3] != str(script_path)
        ):
            raise SupervisorError("worker arm proof is invalid")
    finally:
        os.close(gate_fd)
    if os.getppid() != wrapper_pid or _parent_death_signal() != SIGKILL:
        raise SupervisorError("worker wrapper changed across arm gate")
    expected_lease = _expected_lease(arguments, unit=arguments.expected_unit)
    if _process_fd_matches(
        os.getpid(), device=expected_lease["device"], inode=expected_lease["inode"]
    ):
        raise SupervisorError("worker inherited the launcher lease descriptor")
    WORKER_BOOTSTRAP = {
        "schema_version": 1,
        "wrapper_pid": wrapper_pid,
        "worker_pid": os.getpid(),
        "parent_death_signal": "SIGKILL",
        "parent_identity_checked_before_and_after_gate": True,
        "launcher_lease_fd_inherited": False,
        "python": python_identity,
        "script": script_identity,
        "wrapper_execution": wrapper_execution,
        "gate_closed_before_work": True,
        "all_checks_passed": True,
    }


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SupervisorError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SupervisorError("supervisor value is not canonical JSON") from exc


def _schema_version_is_one(value: Any) -> bool:
    return type(value) is int and value == 1


def _read(path: Path, *, label: str, maximum: int = 512 * 1024 * 1024) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SupervisorError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise SupervisorError(f"{label} metadata is invalid")
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(payload)))
            if not chunk:
                raise SupervisorError(f"{label} changed during read")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if os.read(descriptor, 1) or identity != (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise SupervisorError(f"{label} changed during read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _json(payload: bytes, *, label: str, canonical: bool = False) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                SupervisorError(f"non-finite JSON number: {item}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SupervisorError(f"{label} is invalid JSON") from exc
    if type(value) is not dict or (canonical and payload != canonical_json(value) + b"\n"):
        raise SupervisorError(f"{label} is not canonical JSON")
    return value


def _identity(arguments: argparse.Namespace) -> dict[str, str]:
    discovery_mode = arguments.runtime_open_discovery_inventory is not None
    verifier_fragment_mode = arguments.action in {
        "trace-verifier-fragment",
        "trace-verifier-fragment-unit-wrapper",
        "trace-verifier-fragment-supervise-worker",
    }
    value = {
        "release": arguments.expected_release,
        "version": arguments.expected_version,
        "commit": arguments.expected_commit,
        "manifest_sha256": arguments.expected_manifest_sha256,
        "package_sha256": arguments.expected_package_sha256,
    }
    if (
        SAFE_NAME.fullmatch(value["release"]) is None
        or VERSION.fullmatch(value["version"]) is None
        or HEX40.fullmatch(value["commit"]) is None
        or HEX64.fullmatch(value["manifest_sha256"]) is None
        or HEX64.fullmatch(value["package_sha256"]) is None
        or value["release"] != f"{value['version']}-{value['commit'][:12]}"
        or HEX64.fullmatch(arguments.expected_registry_digest) is None
        or HEX64.fullmatch(arguments.expected_ldconfig_sha256) is None
    ):
        raise SupervisorError("expected release identity is invalid")
    if discovery_mode and verifier_fragment_mode:
        raise SupervisorError("runtime-open discovery mode is ambiguous")
    if discovery_mode:
        if (
            arguments.action not in {"launch", "unit-wrapper", "supervise-worker"}
            or arguments.expected_runtime_open_index_sha256 is not None
            or (
                arguments.runtime_open_discovery_static_closure_sha256 is not None
                and (
                    not isinstance(
                        arguments.runtime_open_discovery_static_closure_sha256, str
                    )
                    or HEX64.fullmatch(
                        arguments.runtime_open_discovery_static_closure_sha256
                    )
                    is None
                )
            )
            or (
                arguments.runtime_open_discovery_sqlite_delta_contract_sha256
                is not None
                and (
                    not isinstance(
                        arguments.runtime_open_discovery_sqlite_delta_contract_sha256,
                        str,
                    )
                    or HEX64.fullmatch(
                        arguments.runtime_open_discovery_sqlite_delta_contract_sha256
                    )
                    is None
                )
            )
            or not arguments.runtime_open_discovery_watch_root
        ):
            raise SupervisorError("runtime-open discovery identity is invalid")
    elif verifier_fragment_mode:
        if (
            HEX64.fullmatch(arguments.expected_runtime_open_index_sha256 or "")
            is None
            or HEX64.fullmatch(arguments.expected_bundle_manifest_sha256 or "")
            is None
            or not arguments.runtime_open_discovery_watch_root
        ):
            raise SupervisorError("runtime-open verifier discovery identity is invalid")
        _validate_verifier_fragment_paths(arguments)
    elif HEX64.fullmatch(arguments.expected_runtime_open_index_sha256 or "") is None:
        raise SupervisorError("expected release identity is invalid")
    return value


def _validate_verifier_fragment_paths(arguments: argparse.Namespace) -> None:
    evidence = Path(arguments.verifier_evidence_dir)
    output = Path(arguments.verifier_fragment_output)
    if (
        evidence.parent != EVIDENCE_PARENT
        or SAFE_NAME.fullmatch(evidence.name) is None
        or output.parent != PRIVATE_EVIDENCE_PARENT
        or not output.name.endswith(".json")
        or SAFE_NAME.fullmatch(output.name.removesuffix(".json")) is None
    ):
        raise SupervisorError("runtime-open verifier discovery paths are invalid")


def _create_verifier_fragment_evidence_dir(path: Path) -> None:
    path = Path(path).absolute()
    if (
        path.parent != EVIDENCE_PARENT
        or SAFE_NAME.fullmatch(path.name) is None
        or os.path.lexists(path)
    ):
        raise SupervisorError("runtime-open verifier evidence directory is invalid")
    os.mkdir(path, 0o700)
    if os.name == "posix":
        os.chmod(path, 0o500, follow_symlinks=False)
    else:
        os.chmod(path, 0o500)
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o500)
    ):
        raise SupervisorError("runtime-open verifier evidence directory is unsafe")


def _program(path: Path, expected_sha256: str, *, label: str) -> dict[str, Any]:
    if HEX64.fullmatch(expected_sha256) is None:
        raise SupervisorError(f"expected {label} digest is invalid")
    payload = _read(path, label=label)
    metadata = path.lstat()
    if (
        path.is_symlink()
        or path.resolve(strict=True) != path
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise SupervisorError(f"{label} identity drifted")
    return {
        "path": str(path),
        "sha256": expected_sha256,
        "size": len(payload),
        "uid": 0,
        "gid": 0,
        "mode": "0755",
    }


def _pinned_stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _open_pinned_program(
    path: Path, expected_sha256: str, *, label: str
) -> tuple[int, tuple[int, ...], dict[str, Any]]:
    if os.name != "posix" or HEX64.fullmatch(expected_sha256) is None:
        raise SupervisorError(f"expected {label} digest is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SupervisorError(f"{label} cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        identity = _pinned_stat_identity(metadata)
        if (
            path.is_symlink()
            or path.resolve(strict=True) != path
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or identity[:2] != (path_metadata.st_dev, path_metadata.st_ino)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 512 * 1024 * 1024
        ):
            raise SupervisorError(f"{label} identity drifted")
        payload = bytearray()
        while len(payload) < metadata.st_size:
            chunk = os.read(
                descriptor, min(1024 * 1024, metadata.st_size - len(payload))
            )
            if not chunk:
                raise SupervisorError(f"{label} changed during read")
            payload.extend(chunk)
        if (
            os.read(descriptor, 1)
            or identity != _pinned_stat_identity(os.fstat(descriptor))
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise SupervisorError(f"{label} identity drifted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, identity, {
            "path": str(path),
            "sha256": expected_sha256,
            "size": len(payload),
            "uid": 0,
            "gid": 0,
            "mode": "0755",
        }
    except BaseException:
        os.close(descriptor)
        raise


def _program_with_inode(
    path: Path, expected_sha256: str, *, label: str
) -> dict[str, Any]:
    descriptor, identity, file_identity = _open_pinned_program(
        path, expected_sha256, label=label
    )
    try:
        _reject_file_capabilities(descriptor, label=label)
        return {
            **file_identity,
            "device": identity[0],
            "inode": identity[1],
        }
    finally:
        os.close(descriptor)


def _open_pinned_publisher_script(
    path: Path, expected_sha256: str
) -> tuple[int, tuple[int, ...]]:
    if os.name != "posix" or HEX64.fullmatch(expected_sha256) is None:
        raise SupervisorError("expected publisher script digest is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SupervisorError("publisher script cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
        identity = _pinned_stat_identity(metadata)
        if (
            path.is_symlink()
            or path.resolve(strict=True) != path
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) not in {0o444, 0o555}
            or identity[:2] != (path_metadata.st_dev, path_metadata.st_ino)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 128 * 1024 * 1024
        ):
            raise SupervisorError("publisher script identity drifted")
        _revalidate_pinned_file(
            descriptor,
            path=path,
            identity=identity,
            expected_sha256=expected_sha256,
            label="publisher script",
        )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_pinned_file(
    descriptor: int,
    *,
    path: Path,
    identity: tuple[int, ...],
    expected_sha256: str,
    label: str,
) -> None:
    before = os.fstat(descriptor)
    if _pinned_stat_identity(before) != identity:
        raise SupervisorError(f"{label} changed before final exec")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = identity[3]
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise SupervisorError(f"{label} changed before final exec")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise SupervisorError(f"{label} changed before final exec")
    os.lseek(descriptor, 0, os.SEEK_SET)
    after = os.fstat(descriptor)
    path_metadata = path.lstat()
    if (
        _pinned_stat_identity(after) != identity
        or digest.hexdigest() != expected_sha256
        or path.is_symlink()
        or path.resolve(strict=True) != path
        or _pinned_stat_identity(path_metadata) != identity
    ):
        raise SupervisorError(f"{label} changed before final exec")


def _exec_pinned_publisher(
    *,
    publisher_path: Path,
    expected_publisher_sha256: str,
    publisher_argv: list[str],
    environment: Mapping[str, str],
    expected_system_python_sha256: str,
    recovery_outer_unit: Mapping[str, Any] | None = None,
    system_python: Path = SYSTEM_PYTHON,
) -> None:
    if (
        os.name != "posix"
        or not Path("/proc/self/fd").is_dir()
        or publisher_argv[:4]
        != [str(system_python), "-I", "-S", str(publisher_path)]
    ):
        raise SupervisorError("publisher final exec contract is invalid")
    recovery_fd: int | None = None
    if recovery_outer_unit is not None:
        if fcntl is None or not hasattr(os, "memfd_create"):
            raise SupervisorError("recovery outer unit requires sealed memfd support")
        recovery_payload = canonical_json(recovery_outer_unit) + b"\n"
        recovery_sha256 = hashlib.sha256(recovery_payload).hexdigest()
        recovery_fd = os.memfd_create(
            "dev29-recovery-outer-unit",
            getattr(os, "MFD_CLOEXEC", 0x0001)
            | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
        )
        try:
            written = 0
            while written < len(recovery_payload):
                written += os.write(recovery_fd, recovery_payload[written:])
            os.fchmod(recovery_fd, 0o400)
            os.lseek(recovery_fd, 0, os.SEEK_SET)
            seals = (
                getattr(fcntl, "F_SEAL_SEAL", 0x0001)
                | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
                | getattr(fcntl, "F_SEAL_GROW", 0x0004)
                | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
            )
            fcntl.fcntl(recovery_fd, getattr(fcntl, "F_ADD_SEALS", 1033), seals)
            os.set_inheritable(recovery_fd, True)
            publisher_argv = [
                *publisher_argv,
                "--recovery-outer-unit-fd",
                str(recovery_fd),
                "--expected-recovery-outer-unit-sha256",
                recovery_sha256,
            ]
        except BaseException:
            os.close(recovery_fd)
            raise
    python_fd, python_identity, _python_file = _open_pinned_program(
        system_python,
        expected_system_python_sha256,
        label="final publisher system Python",
    )
    publisher_fd: int | None = None
    try:
        publisher_fd, publisher_identity = _open_pinned_publisher_script(
            publisher_path, expected_publisher_sha256
        )
        os.set_inheritable(publisher_fd, True)
        _revalidate_pinned_file(
            python_fd,
            path=system_python,
            identity=python_identity,
            expected_sha256=expected_system_python_sha256,
            label="final publisher system Python",
        )
        _revalidate_pinned_file(
            publisher_fd,
            path=publisher_path,
            identity=publisher_identity,
            expected_sha256=expected_publisher_sha256,
            label="publisher script",
        )
        pinned_argv = list(publisher_argv)
        pinned_argv[3] = f"/proc/self/fd/{publisher_fd}"
        os.execve(python_fd, pinned_argv, dict(environment))
        raise SupervisorError("publisher descriptor exec unexpectedly returned")
    finally:
        if recovery_fd is not None:
            os.close(recovery_fd)
        if publisher_fd is not None:
            os.close(publisher_fd)
        os.close(python_fd)


def _ptrace_traceme() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(0, 0, None, None) != 0:
        os._exit(126)


def _ptrace_traceme_with_parent_death(expected_parent_pid: int) -> None:
    """Arm parent-death protection before the exec-stop without a race window."""
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0:
        os._exit(126)
    observed = ctypes.c_int()
    if (
        library.prctl(PR_GET_PDEATHSIG, ctypes.byref(observed), 0, 0, 0) != 0
        or observed.value != SIGKILL
    ):
        os._exit(126)
    if os.getppid() != expected_parent_pid:
        os._exit(125)
    if library.ptrace(0, 0, None, None) != 0:
        os._exit(126)


def _reject_file_capabilities(descriptor: int, *, label: str) -> None:
    missing = {getattr(errno, "ENODATA", 61)}
    if hasattr(errno, "ENOATTR"):
        missing.add(errno.ENOATTR)
    try:
        os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in missing:
            return
        raise SupervisorError(f"{label} capabilities cannot be verified") from exc
    raise SupervisorError(f"{label} has file capabilities")


def _ptrace_set_exitkill(pid: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(
        0x4200, pid, None, ctypes.c_void_p(0x00100000)
    ) != 0:  # PTRACE_SETOPTIONS, PTRACE_O_EXITKILL
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _ptrace_detach(pid: int, signal_number: int = 0) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(17, pid, None, ctypes.c_void_p(signal_number)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _terminal_wait_status(status: int) -> int | None:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return None


def _open_child_pidfd(pid: int, *, label: str) -> int:
    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        raise SupervisorError(f"{label} requires pidfd lifecycle control")
    try:
        return opener(pid, 0)
    except OSError as exc:
        raise SupervisorError(f"{label} pidfd could not be opened") from exc


def _pidfd_send_signal(descriptor: int, signal_number: int, *, label: str) -> None:
    sender = getattr(signal, "pidfd_send_signal", None)
    if sender is None:
        raise SupervisorError(f"{label} requires pidfd signal delivery")
    try:
        sender(descriptor, signal_number, None, 0)
    except ProcessLookupError:
        return
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return
        raise SupervisorError(f"{label} pidfd signal delivery failed") from exc


def _pidfd_has_exited(descriptor: int, *, timeout_seconds: float) -> bool:
    poller = select.poll()
    poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(max(0, int(timeout_seconds * 1000))))


def _kill_and_reap_pinned_child(
    process: subprocess.Popen[bytes], *, pidfd: int, traced: bool, label: str
) -> None:
    """Kill by stable pidfd and refuse unless death/reaping is proven."""
    pid = process.pid
    if process.returncode is not None:
        return
    detached_with_kill = False
    if traced:
        try:
            _ptrace_detach(pid, signal.SIGKILL)
            detached_with_kill = True
        except (OSError, ProcessLookupError):
            pass
    if not detached_with_kill:
        _pidfd_send_signal(pidfd, signal.SIGKILL, label=label)
    try:
        process.wait(timeout=5)
    except ChildProcessError:
        if not _pidfd_has_exited(pidfd, timeout_seconds=5):
            raise SupervisorError(f"failed {label} child could not be reaped")
        return
    except (OSError, subprocess.SubprocessError) as first_error:
        _pidfd_send_signal(pidfd, signal.SIGKILL, label=label)
        try:
            process.wait(timeout=5)
        except ChildProcessError:
            if _pidfd_has_exited(pidfd, timeout_seconds=5):
                return
            else:
                raise SupervisorError(
                    f"failed {label} child could not be reaped"
                ) from first_error
        except (OSError, subprocess.SubprocessError) as final_error:
            raise SupervisorError(f"failed {label} child could not be reaped") from final_error
    if process.returncode is None:
        raise SupervisorError(f"failed {label} child could not be reaped")


def _kill_and_reap_before_pidfd(
    process: subprocess.Popen[bytes], *, traced: bool, label: str
) -> None:
    """Close the tiny pre-pidfd window while the direct child cannot be reused."""
    pid = process.pid
    if process.returncode is not None:
        return
    try:
        waited, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
    except ChildProcessError:
        return
    if waited == pid:
        terminal = _terminal_wait_status(status)
        if terminal is not None:
            process.returncode = terminal
            return
        traced = os.WIFSTOPPED(status)
    if traced:
        try:
            _ptrace_detach(pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
    else:
        os.kill(pid, signal.SIGKILL)
    try:
        process.wait(timeout=5)
    except ChildProcessError:
        return
    except (OSError, subprocess.SubprocessError) as exc:
        raise SupervisorError(f"failed {label} pre-pidfd child could not be reaped") from exc
    if process.returncode is None:
        raise SupervisorError(f"failed {label} pre-pidfd child could not be reaped")


def _run_pinned_program(
    path: Path,
    expected_sha256: str,
    command: list[str],
    *,
    label: str,
    stdin: Any = subprocess.DEVNULL,
    stdout: Any = None,
    stderr: Any = None,
    cwd: Path | None = None,
    env: Mapping[str, str],
    timeout: int | None = None,
    exec_verified_callback: Callable[[Mapping[str, Any]], None] | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, Any]]:
    if not command or command[0] != str(path):
        raise SupervisorError(f"{label} argv does not name the pinned executable")
    descriptor, identity, file_identity = _open_pinned_program(
        path, expected_sha256, label=label
    )
    process: subprocess.Popen[bytes] | None = None
    pidfd: int | None = None
    traced = False
    handed_off = False
    reaped = False
    exitkill_set = False
    exec_stop_verified = False
    detached_before_communicate = False
    executed: os.stat_result | None = None
    try:
        _reject_file_capabilities(descriptor, label=label)
        expected_parent_pid = os.getpid()
        process = subprocess.Popen(
            command,
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
            preexec_fn=lambda: _ptrace_traceme_with_parent_death(
                expected_parent_pid
            ),
            close_fds=True,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            env=dict(env),
        )
        traced = True
        pidfd = _open_child_pidfd(process.pid, label=label)
        waited, status = os.waitpid(process.pid, os.WUNTRACED)
        terminal_returncode = _terminal_wait_status(status)
        if terminal_returncode is not None:
            process.returncode = terminal_returncode
            reaped = True
            traced = False
        if (
            waited != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            raise SupervisorError(f"{label} exec trace stop is invalid")
        _ptrace_set_exitkill(process.pid)
        exitkill_set = True
        executed = Path(f"/proc/{process.pid}/exe").stat()
        if (executed.st_dev, executed.st_ino) != identity[:2]:
            raise SupervisorError(f"{label} executed inode differs from pinned bytes")
        exec_stop_verified = True
        if exec_verified_callback is not None:
            exec_verified_callback(
                {
                    "schema_version": 1,
                    "method": "open-fd-ptrace-live-exec-v1",
                    "pid": process.pid,
                    "starttime": _proc_starttime(process.pid),
                    "parent_pid": expected_parent_pid,
                    "parent_starttime": _proc_starttime(expected_parent_pid),
                    "argv": list(command),
                    "argv_sha256": hashlib.sha256(
                        canonical_json(command)
                    ).hexdigest(),
                    "file": {
                        **file_identity,
                        "device": identity[0],
                        "inode": identity[1],
                    },
                    "pinned_device": identity[0],
                    "pinned_inode": identity[1],
                    "proc_exe_device": executed.st_dev,
                    "proc_exe_inode": executed.st_ino,
                    "ptrace_exitkill_set": exitkill_set,
                    "ptrace_exec_stop_verified": exec_stop_verified,
                    "parent_death_signal_setup": "SIGKILL",
                    "parent_death_signal_set_get_verified_before_exec": True,
                    "parent_identity_checked_before_exec": True,
                    "security_capability_absent": True,
                    "pidfd_opened_before_exec_stop_release": True,
                    "all_checks_passed": True,
                }
            )
        _ptrace_detach(process.pid)
        traced = False
        detached_before_communicate = True
        try:
            output, error_output = process.communicate(timeout=timeout)
            reaped = process.returncode is not None
        except subprocess.TimeoutExpired as exc:
            raise SupervisorError(f"{label} execution timed out") from exc
        current = os.fstat(descriptor)
        _reject_file_capabilities(descriptor, label=label)
        path_current = path.lstat()
        if identity != _pinned_stat_identity(current) or identity[:2] != (
            path_current.st_dev,
            path_current.st_ino,
        ):
            raise SupervisorError(f"{label} changed across pinned execution")
        execution = {
            "method": "open-fd-ptrace-exec-v1",
            "file": file_identity,
            "pinned_device": identity[0],
            "pinned_inode": identity[1],
            "proc_exe_device": executed.st_dev,
            "proc_exe_inode": executed.st_ino,
            "all_checks_passed": True,
        }
        execution.update(
            {
                "ptrace_exitkill_set": exitkill_set,
                "ptrace_exec_stop_verified": exec_stop_verified,
                "ptrace_detached_before_communicate": detached_before_communicate,
                "parent_death_signal": "SIGKILL",
                "parent_identity_checked": True,
                "security_capability_absent": True,
                "child_reaped": reaped,
            }
        )
        return subprocess.CompletedProcess(
            command, process.returncode, output, error_output
        ), execution
    except BaseException as exc:
        cleanup_error: SupervisorError | None = None
        if process is not None and not reaped:
            try:
                if pidfd is None:
                    _kill_and_reap_before_pidfd(
                        process, traced=traced, label=label
                    )
                else:
                    _kill_and_reap_pinned_child(
                        process, pidfd=pidfd, traced=traced, label=label
                    )
                reaped = True
            except SupervisorError as cleanup_exc:
                cleanup_error = cleanup_exc
        if cleanup_error is not None and not isinstance(exc, SupervisorError):
            raise cleanup_error from exc
        raise
    finally:
        if pidfd is not None:
            os.close(pidfd)
        os.close(descriptor)


def _forward_options(
    arguments: argparse.Namespace, options: tuple[tuple[str, str], ...]
) -> list[str]:
    forwarded: list[str] = []
    for name, option in options:
        value = getattr(arguments, name)
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            for item in value:
                forwarded.extend((option, str(item)))
            continue
        forwarded.extend((option, str(value)))
    return forwarded


def _top_level_argv(
    arguments: argparse.Namespace, *, root: Path, action: str | None = None
) -> list[str]:
    top_action = action or arguments.action
    if top_action not in {"launch", "recover", "trace-verifier-fragment"}:
        raise SupervisorError("top-level launcher action is invalid")
    result = [
        str(SYSTEM_PYTHON),
        "-I",
        "-S",
        str(root.joinpath(*RUNNER_RELATIVE.parts)),
        top_action,
        *_forward_options(arguments, COMMON_OPTIONS),
        *_forward_options(arguments, DISCOVERY_OPTIONS),
    ]
    if top_action == "trace-verifier-fragment":
        result.extend(_forward_options(arguments, VERIFIER_DISCOVERY_OPTIONS))
    if top_action == "recover":
        digest = arguments.expected_bundle_manifest_sha256
        if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
            raise SupervisorError("expected bundle manifest digest is invalid")
        result.extend(("--expected-bundle-manifest-sha256", digest))
    return result


def _wrapper_argv(
    arguments: argparse.Namespace,
    *,
    root: Path,
    action: str,
    unit: str,
    worker_script_sha256: str,
) -> list[str]:
    if action not in {
        "unit-wrapper",
        "recover-unit-wrapper",
        "trace-verifier-fragment-unit-wrapper",
    }:
        raise SupervisorError("unit wrapper action is invalid")
    result = [
        str(SYSTEM_PYTHON),
        "-I",
        "-S",
        str(root.joinpath(*RUNNER_RELATIVE.parts)),
        action,
        *_forward_options(arguments, COMMON_OPTIONS),
        *_forward_options(arguments, DISCOVERY_OPTIONS),
    ]
    if action == "trace-verifier-fragment-unit-wrapper":
        result.extend(_forward_options(arguments, VERIFIER_DISCOVERY_OPTIONS))
    if action == "recover-unit-wrapper":
        digest = arguments.expected_bundle_manifest_sha256
        if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
            raise SupervisorError("expected bundle manifest digest is invalid")
        result.extend(("--expected-bundle-manifest-sha256", digest))
    result.extend(_forward_options(arguments, LEASE_OPTIONS))
    result.extend(
        (
            "--expected-worker-script-sha256",
            worker_script_sha256,
            "--expected-unit",
            unit,
        )
    )
    return result


def _outer_writable_paths(release: str) -> list[str]:
    test_candidate = Path("/var/lib/odoo-accounting-cli-v3/test/candidates") / release
    return [
        str(EVIDENCE_PARENT),
        str(PRIVATE_EVIDENCE_PARENT),
        str(RUNTIME_TRACE_STAGING_PARENT),
        str(ANCHOR_PARENT),
        "/opt/odoo-accounting-cli-v3/dependencies",
        str(test_candidate / "auth"),
        str(test_candidate / "receipt"),
        str(test_candidate / "gcov"),
        str(BROKER_HOME),
        str(STAGING_PARENT),
    ]


def _systemd_run_argv(
    *, unit: str, root: Path, writable: list[str], wrapper_argv: list[str]
) -> list[str]:
    return [
        str(SYSTEMD_RUN),
        "--wait",
        "--collect",
        "--pipe",
        "--quiet",
        f"--unit={unit}",
        "--property=Type=exec",
        "--property=User=root",
        "--property=Group=root",
        "--property=ProtectSystem=strict",
        "--property=PrivateMounts=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateNetwork=yes",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectHome=read-only",
        "--property=KillMode=control-group",
        "--property=RuntimeMaxSec=3600s",
        "--property=TimeoutStopSec=30s",
        "--property=UMask=0077",
        f"--property=CapabilityBoundingSet={' '.join(OUTER_CAPABILITIES)}",
        f"--property=WorkingDirectory={root}",
        *(f"--property=ReadWritePaths={path}" for path in writable),
        f"--property=ReadOnlyPaths={LEASE_PARENT}",
        "--setenv=PATH=/usr/bin:/bin",
        "--setenv=HOME=/root",
        "--setenv=LANG=C.UTF-8",
        "--setenv=LC_ALL=C.UTF-8",
        "--setenv=TZ=UTC",
        "--setenv=PYTHONDONTWRITEBYTECODE=1",
        *wrapper_argv,
    ]


def _parse_systemd_exec_start(value: Any) -> tuple[str, list[str]]:
    """Extract the one executable path and argv from systemctl's bus rendering."""
    if not isinstance(value, str) or not value.startswith("{ ") or not value.endswith(
        " }"
    ):
        raise SupervisorError("outer transient unit ExecStart is invalid")
    fields: dict[str, str] = {}
    for item in value[2:-2].split(" ; "):
        key, separator, raw = item.partition("=")
        if separator != "=" or not key or key in fields:
            raise SupervisorError("outer transient unit ExecStart is invalid")
        fields[key] = raw
    if "path" not in fields or "argv[]" not in fields:
        raise SupervisorError("outer transient unit ExecStart is invalid")
    try:
        path = shlex.split(fields["path"], posix=True)
        argv = shlex.split(fields["argv[]"], posix=True)
    except ValueError as exc:
        raise SupervisorError("outer transient unit ExecStart is invalid") from exc
    if len(path) != 1 or not argv or any(not item for item in argv):
        raise SupervisorError("outer transient unit ExecStart is invalid")
    return path[0], argv


def _spawn_pinned_worker(
    arguments: argparse.Namespace,
    *,
    root: Path,
    script: Path,
    script_sha256: str,
    worker_action: str,
    forbidden_child_fds: Iterable[int] = (),
) -> tuple[subprocess.Popen[bytes], int, int, dict[str, Any]]:
    python_fd, python_identity, python_file = _open_pinned_program(
        SYSTEM_PYTHON,
        arguments.expected_system_python_sha256,
        label="unit worker system Python",
    )
    script_fd: int | None = None
    read_gate: int | None = None
    write_gate: int | None = None
    process: subprocess.Popen[bytes] | None = None
    pidfd: int | None = None
    traced = False
    handed_off = False
    try:
        script_fd, script_identity = _open_pinned_publisher_script(
            script, script_sha256
        )
        _reject_file_capabilities(python_fd, label="unit worker system Python")
        _reject_file_capabilities(script_fd, label="unit worker supervisor script")
        read_gate, write_gate = os.pipe2(getattr(os, "O_CLOEXEC", 0))
        worker_argv = [
            str(SYSTEM_PYTHON),
            "-I",
            "-S",
            str(script),
            worker_action,
            *_forward_options(arguments, COMMON_OPTIONS),
            *_forward_options(arguments, DISCOVERY_OPTIONS),
            *_forward_options(arguments, LEASE_OPTIONS),
        ]
        if worker_action == "trace-verifier-fragment-supervise-worker":
            worker_argv.extend(_forward_options(arguments, VERIFIER_DISCOVERY_OPTIONS))
        if worker_action == "recover-supervise-worker":
            worker_argv.extend(
                (
                    "--expected-bundle-manifest-sha256",
                    arguments.expected_bundle_manifest_sha256,
                )
            )
        worker_argv.extend(
            (
                "--expected-unit",
                arguments.expected_unit,
                "--expected-wrapper-pid",
                str(os.getpid()),
                "--worker-gate-fd",
                str(read_gate),
                "--expected-worker-script-sha256",
                script_sha256,
                "--expected-worker-python-fd",
                str(python_fd),
                "--expected-worker-python-device",
                str(python_identity[0]),
                "--expected-worker-python-inode",
                str(python_identity[1]),
                "--expected-worker-script-fd",
                str(script_fd),
                "--expected-worker-script-device",
                str(script_identity[0]),
                "--expected-worker-script-inode",
                str(script_identity[1]),
            )
        )
        expected_parent_pid = os.getpid()
        forbidden_fds = tuple(
            descriptor
            for descriptor in forbidden_child_fds
            if descriptor not in {read_gate, write_gate}
        )

        def worker_preexec() -> None:
            for descriptor in forbidden_fds:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            _ptrace_traceme_with_parent_death(expected_parent_pid)

        for descriptor in (read_gate,):
            os.set_inheritable(descriptor, True)
        try:
            process = subprocess.Popen(
                worker_argv,
                executable=str(SYSTEM_PYTHON),
                pass_fds=(read_gate,),
                preexec_fn=worker_preexec,
                close_fds=True,
                stdin=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=root,
                env=dict(OUTER_ENVIRONMENT),
            )
        finally:
            for descriptor in (read_gate,):
                os.set_inheritable(descriptor, False)
        traced = True
        os.close(read_gate)
        read_gate = None
        pidfd = _open_child_pidfd(process.pid, label="unit worker")
        waited, status = os.waitpid(process.pid, os.WUNTRACED)
        terminal = _terminal_wait_status(status)
        if terminal is not None:
            process.returncode = terminal
            traced = False
        if (
            waited != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            raise SupervisorError("unit worker exec trace stop is invalid")
        _ptrace_set_exitkill(process.pid)
        try:
            executed = Path(f"/proc/{process.pid}/exe").stat()
        except OSError as exc:
            try:
                child_fds = sorted(os.listdir(f"/proc/{process.pid}/fd"))
            except OSError:
                child_fds = []
            raise SupervisorError(
                "unit worker inherited descriptors are unavailable "
                f"(python_fd={python_fd}, script_fd={script_fd}, "
                f"gate_fd={read_gate}, child_fds={child_fds})"
            ) from exc
        if (
            (executed.st_dev, executed.st_ino) != python_identity[:2]
        ):
            raise SupervisorError("unit worker executed unpinned bytes")
        _ptrace_detach(process.pid)
        traced = False
        os.close(python_fd)
        python_fd = -1
        os.close(script_fd)
        script_fd = None
        result = {
            "schema_version": 1,
            "method": "path-exec-ptrace-gated-worker-with-pinned-release-script-v1",
            "worker_pid": process.pid,
            "argv": worker_argv,
            "argv_sha256": hashlib.sha256(canonical_json(worker_argv)).hexdigest(),
            "python": python_file,
            "python_device": python_identity[0],
            "python_inode": python_identity[1],
            "script": {
                "path": str(script),
                "sha256": script_sha256,
                "device": script_identity[0],
                "inode": script_identity[1],
            },
            "ptrace_exitkill_set": True,
            "ptrace_exec_stop_verified": True,
            "ptrace_detached_before_gate": True,
            "parent_death_signal": "SIGKILL",
            "parent_identity_checked": True,
            "security_capability_absent": True,
            "pidfd_monitoring": True,
            "all_checks_passed": True,
        }
        handed_off = True
        return process, pidfd, write_gate, result
    except BaseException as exc:
        cleanup_error: SupervisorError | None = None
        if process is not None and process.returncode is None:
            try:
                if pidfd is None:
                    _kill_and_reap_before_pidfd(
                        process, traced=traced, label="unit worker"
                    )
                else:
                    _kill_and_reap_pinned_child(
                        process, pidfd=pidfd, traced=traced, label="unit worker"
                    )
            except SupervisorError as candidate:
                cleanup_error = candidate
        if cleanup_error is not None:
            raise cleanup_error from exc
        raise
    finally:
        if pidfd is not None and not handed_off:
            os.close(pidfd)
        if read_gate is not None:
            os.close(read_gate)
        if write_gate is not None and not handed_off:
            os.close(write_gate)
        if script_fd is not None:
            os.close(script_fd)
        if python_fd >= 0:
            os.close(python_fd)


def _terminate_monitored_worker(
    process: subprocess.Popen[bytes], pidfd: int, *, label: str
) -> None:
    if process.returncode is None:
        _pidfd_send_signal(pidfd, signal.SIGKILL, label=label)
    try:
        process.wait(timeout=10)
    except ChildProcessError:
        if not _pidfd_has_exited(pidfd, timeout_seconds=10):
            raise SupervisorError(f"{label} did not exit")
    except (OSError, subprocess.SubprocessError) as exc:
        raise SupervisorError(f"{label} did not exit") from exc


def _worker_stderr_tail(process: subprocess.Popen[bytes], *, maximum: int = 4096) -> str:
    """Return a bounded UTF-8 stderr tail from a failed worker, when available."""
    stream = process.stderr
    if stream is None:
        return ""
    try:
        payload = stream.read(maximum + 1)
    except (OSError, ValueError):
        return ""
    if not payload:
        return ""
    if len(payload) > maximum:
        payload = payload[-maximum:]
    text = payload.decode("utf-8", "replace").strip()
    return text.replace("\n", "\\n")


def _unit_wrapper(arguments: argparse.Namespace) -> int:
    """Remain MainPID while a gated, pinned worker performs and publishes work."""
    _require_system_python()
    unit = f"odoo-accounting-cli-v3-dev29-{arguments.evidence_name}.service"
    if arguments.expected_unit != unit:
        raise SupervisorError("unit wrapper identity is invalid")
    lease_fd, lease = _open_monitored_lease(arguments, unit=unit)
    process: subprocess.Popen[bytes] | None = None
    pidfd: int | None = None
    gate: int | None = None
    try:
        root = RELEASE_PARENT / arguments.expected_release
        script = root.joinpath(*RUNNER_RELATIVE.parts)
        worker_action = (
            "recover-supervise-worker"
            if arguments.action == "recover-unit-wrapper"
            else "trace-verifier-fragment-supervise-worker"
            if arguments.action == "trace-verifier-fragment-unit-wrapper"
            else "supervise-worker"
        )
        process, pidfd, gate, execution = _spawn_pinned_worker(
            arguments,
            root=root,
            script=script,
            script_sha256=arguments.expected_worker_script_sha256,
            worker_action=worker_action,
            forbidden_child_fds=(lease_fd,),
        )
        if not _flock_is_owned_elsewhere(lease_fd):
            raise SupervisorError("launcher lease was lost before worker arm")
        execution["launcher_lease"] = {
            "identity": lease,
            "wrapper_monitor_descriptor": lease_fd,
            "descriptor_cloexec": not os.get_inheritable(lease_fd),
            "launcher_lock_verified_before_arm": True,
            "systemd_run_lease_fd_inherited": False,
            "all_checks_passed": True,
        }
        arm_payload = b"\xa5" + canonical_json(execution) + b"\n"
        written = 0
        while written < len(arm_payload):
            written += os.write(gate, arm_payload[written:])
        os.close(gate)
        gate = None
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while True:
            if not _flock_is_owned_elsewhere(lease_fd):
                _terminate_monitored_worker(
                    process, pidfd, label="lease-abandoned unit worker"
                )
                raise SupervisorError("launcher lease was abandoned")
            if poller.poll(max(1, int(LEASE_POLL_SECONDS * 1000))):
                try:
                    returncode = process.wait(timeout=10)
                except ChildProcessError as exc:
                    raise SupervisorError("unit worker was externally reaped") from exc
                except subprocess.SubprocessError as exc:
                    raise SupervisorError("unit worker exit could not be reaped") from exc
                if returncode != 0:
                    stderr_tail = _worker_stderr_tail(process)
                    detail = (
                        f": {stderr_tail}"
                        if stderr_tail
                        else " with no captured stderr"
                    )
                    raise SupervisorError(
                        f"unit worker failed with exit code {returncode}{detail}"
                    )
                return returncode
    except BaseException:
        if process is not None and pidfd is not None:
            _terminate_monitored_worker(process, pidfd, label="failed unit worker")
        raise
    finally:
        if gate is not None:
            os.close(gate)
        if pidfd is not None:
            os.close(pidfd)
        os.close(lease_fd)


def _bootstrap_file_identity(
    path: Path, *, allowed_modes: frozenset[int]
) -> dict[str, Any]:
    payload = _read(path, label=f"bootstrap file {path}")
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
        or mode not in allowed_modes
    ):
        raise SupervisorError(f"bootstrap file is unsafe: {path}")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "uid": 0,
        "gid": 0,
        "mode": f"{mode:04o}",
    }


def _bootstrap_release(expected: Mapping[str, str]) -> tuple[Path, dict[str, Any]]:
    root = RELEASE_PARENT / expected["release"]
    script = root.joinpath(*RUNNER_RELATIVE.parts)
    if Path(__file__).resolve(strict=True) != script.resolve(strict=True):
        raise SupervisorError("supervisor is outside the expected sealed release")
    current = Path("/")
    for component in root.parts[1:]:
        current /= component
        metadata = current.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or mode & 0o022
            or not mode & 0o111
        ):
            raise SupervisorError("release directory chain is unsafe")
    anchor = _json(
        _read(TRUST_PARENT / f"{expected['release']}.json", label="release anchor"),
        label="release anchor",
    )
    expected_anchor = _release_anchor_identity(expected)
    if anchor != expected_anchor:
        raise SupervisorError("release anchor identity mismatch")
    manifest_payload = _read(root / "RELEASE-MANIFEST.json", label="release manifest")
    manifest = _json(manifest_payload, label="release manifest")
    if (
        set(manifest) != {"schema_version", "version", "commit", "files", "manifest_sha256"}
        or not _schema_version_is_one(manifest.get("schema_version"))
        or manifest.get("version") != expected["version"]
        or manifest.get("commit") != expected["commit"]
        or manifest.get("manifest_sha256") != expected["manifest_sha256"]
        or hashlib.sha256(
            canonical_json({key: value for key, value in manifest.items() if key != "manifest_sha256"})
        ).hexdigest()
        != expected["manifest_sha256"]
        or type(manifest.get("files")) is not list
        or not manifest["files"]
        or len(manifest["files"]) > 20_000
    ):
        raise SupervisorError("release manifest identity is invalid")
    indexed: dict[str, dict[str, Any]] = {}
    for item in manifest["files"]:
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "size"}
            or not isinstance(item.get("path"), str)
            or not PurePosixPath(item["path"]).parts
            or PurePosixPath(item["path"]).is_absolute()
            or str(PurePosixPath(item["path"])) != item["path"]
            or any(part in {"", ".", ".."} for part in PurePosixPath(item["path"]).parts)
            or item["path"] in indexed
            or HEX64.fullmatch(item.get("sha256", "")) is None
            or type(item.get("size")) is not int
            or item["size"] < 0
        ):
            raise SupervisorError("release manifest member is invalid")
        indexed[item["path"]] = item
    required = {
        str(RUNNER_RELATIVE),
        str(SUITE_RELATIVE),
        str(CLOSURE_RELATIVE),
        str(VERIFIER_RELATIVE),
        str(PUBLISHER_RELATIVE),
        str(DIRECT_CHILD_RELATIVE),
        str(TRACE_RELATIVE),
        str(PLAN_RELATIVE),
    }
    if not required.issubset(indexed):
        raise SupervisorError("release manifest omits a Dev29 lifecycle member")
    actual: set[str] = set()
    for directory_text, names, files in os.walk(root, topdown=True, followlinks=False):
        directory = Path(directory_text)
        names.sort()
        files.sort()
        for name in names:
            child = directory / name
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
                raise SupervisorError("release directory is unsafe")
        for name in files:
            child = directory / name
            relative = child.relative_to(root).as_posix()
            if relative == "RELEASE-MANIFEST.json":
                continue
            actual.add(relative)
    if actual != set(indexed):
        raise SupervisorError("installed release file set differs from its manifest")
    for relative, item in indexed.items():
        path = root.joinpath(*PurePosixPath(relative).parts)
        metadata = path.lstat()
        payload = _read(path, label=f"release member {relative}", maximum=128 * 1024 * 1024)
        if (
            path.is_symlink()
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) not in {0o444, 0o555}
            or len(payload) != item["size"]
            or hashlib.sha256(payload).hexdigest() != item["sha256"]
        ):
            raise SupervisorError(f"release member drifted: {relative}")
    package = _read(
        PACKAGE_PARENT / f"odoo-accounting-cli-v3-{expected['release']}.tar.gz",
        label="canonical release package",
    )
    if hashlib.sha256(package).hexdigest() != expected["package_sha256"]:
        raise SupervisorError("canonical release package digest mismatch")
    return root, manifest


def _release_anchor_identity(expected: Mapping[str, str]) -> dict[str, str]:
    return {
        key: expected[key]
        for key in ("release", "commit", "manifest_sha256", "package_sha256")
    }


def _manifest_member_sha256(
    manifest: Mapping[str, Any], relative: PurePosixPath
) -> str:
    files = manifest.get("files")
    matches = (
        [item for item in files if item.get("path") == str(relative)]
        if type(files) is list and all(type(item) is dict for item in files)
        else []
    )
    if len(matches) != 1 or HEX64.fullmatch(matches[0].get("sha256", "")) is None:
        raise SupervisorError(f"release manifest identity is absent: {relative}")
    return matches[0]["sha256"]


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SupervisorError(f"cannot load sealed module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _write_stage(path: Path, value: Mapping[str, Any]) -> None:
    payload = canonical_json(value) + b"\n"
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SupervisorError("short staging write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publisher_argv(
    arguments: argparse.Namespace,
    *,
    publisher_path: Path,
    evidence: Path,
    stage: Path,
    expected: Mapping[str, str],
    bundle_manifest_sha256: str,
) -> list[str]:
    return [
        str(SYSTEM_PYTHON),
        "-I",
        "-S",
        str(publisher_path),
        "--evidence-dir",
        str(evidence),
        "--validation-report",
        str(stage / "validation-report.json"),
        "--cleanup-receipt",
        str(stage / "cleanup-receipt.json"),
        "--verifier-child",
        str(stage / "verifier-child.json"),
        "--verifier-process-control",
        str(stage / "verifier-process-control.json"),
        "--verifier-runtime-trace",
        str(stage / "verifier-runtime-trace.json"),
        "--prepublication-guard",
        str(stage / "prepublication-guard.json"),
        "--supervisor-bootstrap",
        str(stage / "supervisor-bootstrap.json"),
        "--staging-dir",
        str(stage),
        "--expected-bundle-manifest-sha256",
        bundle_manifest_sha256,
        "--expected-release",
        expected["release"],
        "--expected-version",
        expected["version"],
        "--expected-commit",
        expected["commit"],
        "--expected-manifest-sha256",
        expected["manifest_sha256"],
        "--expected-package-sha256",
        expected["package_sha256"],
        "--expected-registry-digest",
        arguments.expected_registry_digest,
        "--expected-ldconfig-sha256",
        arguments.expected_ldconfig_sha256,
        "--expected-runtime-open-index-sha256",
        arguments.expected_runtime_open_index_sha256,
        "--expected-strace-sha256",
        arguments.expected_strace_sha256,
    ]


def _recovery_artifact_state(evidence_name: str) -> str:
    if SAFE_NAME.fullmatch(evidence_name) is None:
        raise SupervisorError("recovery evidence name is invalid")
    evidence = EVIDENCE_PARENT / evidence_name
    anchor = ANCHOR_PARENT / f"{evidence_name}.json"
    pending = ANCHOR_PARENT / f".{evidence_name}.json.pending"
    stage = STAGING_PARENT / evidence_name
    if (
        not evidence.is_dir()
        or evidence.is_symlink()
        or not stage.is_dir()
        or stage.is_symlink()
    ):
        raise SupervisorError("recovery evidence or staging directory is unavailable")
    _verify_writable_directory(stage, uid=0, gid=0, mode=0o700)
    stage_members = {item.name for item in stage.iterdir()}
    if not stage_members <= PUBLISHER_STAGE_FILES:
        raise SupervisorError("recovery staging file set is invalid")
    if os.path.lexists(anchor):
        return "final_anchor_cleanup"
    if not os.path.lexists(pending) or stage_members != PUBLISHER_STAGE_FILES:
        raise SupervisorError("recoverable final or pending anchor is absent")
    metadata = pending.lstat()
    if (
        pending.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
        or stat.S_IMODE(metadata.st_mode)
        not in ({0o400} if os.name == "posix" else {0o400, 0o444})
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
        or metadata.st_size > 64 * 1024 * 1024
    ):
        raise SupervisorError("recoverable pending anchor is unsafe")
    return "pending_anchor_commit"


def _remove_stage(path: Path) -> None:
    path = path.absolute()
    if path.parent != STAGING_PARENT or SAFE_NAME.fullmatch(path.name) is None:
        raise SupervisorError("unsafe staging cleanup path")
    if not path.exists():
        return
    for child in path.iterdir():
        metadata = child.lstat()
        if child.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise SupervisorError("unsafe staging cleanup member")
        child.unlink()
    path.rmdir()


def _signal_handler(signum: int, _frame: Any) -> None:
    raise SupervisorInterrupted(f"supervisor interrupted by signal {signum}")


def _drop_publisher_capabilities() -> None:
    import ctypes

    class CapabilityHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class CapabilityData(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    library = ctypes.CDLL(None, use_errno=True)
    os.setgroups([])
    for capability in range(64):
        if library.prctl(24, capability, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            if error != 22:
                raise SupervisorError("publisher capability bounding drop failed")
    header = CapabilityHeader(0x20080522, 0)
    data = (CapabilityData * 2)()
    if library.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise SupervisorError("publisher capability set drop failed")
    if library.prctl(38, 1, 0, 0, 0) != 0:
        raise SupervisorError("publisher no-new-privileges setup failed")


def _systemctl_show(
    unit: str,
    *,
    expected_systemctl_sha256: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    fields = (
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "Type",
        "User",
        "Group",
        "MainPID",
        "ControlGroup",
        "InvocationID",
        "ExecStart",
        "WorkingDirectory",
        "ProtectSystem",
        "ProtectHome",
        "PrivateMounts",
        "PrivateTmp",
        "PrivateNetwork",
        "NoNewPrivileges",
        "RestrictSUIDSGID",
        "ProtectControlGroups",
        "KillMode",
        "RuntimeMaxUSec",
        "TimeoutStopUSec",
        "UMask",
        "ReadWritePaths",
        "ReadOnlyPaths",
        "Environment",
        "CapabilityBoundingSet",
    )
    completed, execution = _run_pinned_program(
        SYSTEMCTL,
        expected_systemctl_sha256,
        [
            str(SYSTEMCTL),
            "show",
            "--no-pager",
            *[f"--property={field}" for field in fields],
            unit,
        ],
        label="systemctl",
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=OUTER_ENVIRONMENT,
        timeout=30,
    )
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout.endswith(b"\n")
        or len(completed.stdout) > 1024 * 1024
    ):
        raise SupervisorError("systemctl unit property query failed")
    properties: dict[str, str] = {}
    try:
        for raw in completed.stdout.decode("utf-8", "strict").splitlines():
            key, separator, value = raw.partition("=")
            if separator != "=" or key not in fields or key in properties:
                raise SupervisorError("systemctl unit property output is invalid")
            properties[key] = value
    except UnicodeError as exc:
        raise SupervisorError("systemctl unit property output is invalid") from exc
    if set(properties) != set(fields):
        raise SupervisorError("systemctl unit property set is incomplete")
    return properties, execution


def _outer_unit_evidence(
    arguments: argparse.Namespace,
    *,
    root: Path,
    runtime: Mapping[str, Any],
    systemd_run_identity: Mapping[str, Any],
    systemctl_identity: Mapping[str, Any],
    internal_action: str = "supervise-worker",
) -> dict[str, Any]:
    if WORKER_BOOTSTRAP is None:
        raise SupervisorError("outer unit worker bootstrap proof is absent")
    expected_unit = f"odoo-accounting-cli-v3-dev29-{arguments.evidence_name}.service"
    if arguments.expected_unit != expected_unit:
        raise SupervisorError("outer transient unit identity is invalid")
    rows = Path("/proc/self/cgroup").read_text("ascii").splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::") or rows[0][3:] == "/":
        raise SupervisorError("outer transient unit cgroup is invalid")
    cgroup = rows[0][3:]
    properties, systemctl_execution = _systemctl_show(
        expected_unit,
        expected_systemctl_sha256=arguments.expected_systemctl_sha256,
    )
    worker_pid = os.getpid()
    wrapper_pid = WORKER_BOOTSTRAP.get("wrapper_pid")
    if type(wrapper_pid) is not int or wrapper_pid <= 1 or os.getppid() != wrapper_pid:
        raise SupervisorError("outer transient unit wrapper identity is invalid")
    worker_argv = _read_proc_argv(worker_pid)
    if worker_argv != WORKER_BOOTSTRAP["wrapper_execution"]["argv"]:
        raise SupervisorError("outer transient unit worker argv drifted")
    wrapper_argv = _read_proc_argv(wrapper_pid)
    if internal_action == "recover-supervise-worker":
        wrapper_action = "recover-unit-wrapper"
    elif internal_action == "trace-verifier-fragment-supervise-worker":
        wrapper_action = "trace-verifier-fragment-unit-wrapper"
    else:
        wrapper_action = "unit-wrapper"
    expected_wrapper_argv = _wrapper_argv(
        arguments,
        root=root,
        action=wrapper_action,
        unit=expected_unit,
        worker_script_sha256=arguments.expected_worker_script_sha256,
    )
    writable = _outer_writable_paths(arguments.expected_release)
    (
        _evidence_parent,
        _private_evidence_parent,
        _runtime_trace_staging_parent,
        _anchor_parent,
        dependency_mount_parent,
        auth_state_parent,
        receipt_state_parent,
        gcov_state_parent,
        _broker_home,
        _staging_parent,
    ) = writable
    if (
        str(Path(runtime["auth_state_path"]).parent) != auth_state_parent
        or str(Path(runtime["receipt_state_path"]).parent) != receipt_state_parent
        or str(Path(runtime["gcov_state_path"])) != gcov_state_parent
        or "/opt/odoo-accounting-cli-v3/dependencies" != dependency_mount_parent
    ):
        raise SupervisorError("outer runtime writable path contract drifted")
    static = {
        "Id": expected_unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "Type": "exec",
        "User": "root",
        "Group": "root",
        "MainPID": str(wrapper_pid),
        "ControlGroup": cgroup,
        "WorkingDirectory": str(root),
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "PrivateMounts": "yes",
        "PrivateTmp": "yes",
        "PrivateNetwork": "yes",
        "NoNewPrivileges": "yes",
        "ProtectControlGroups": "yes",
        "KillMode": "control-group",
        "RuntimeMaxUSec": "1h",
        "TimeoutStopUSec": "30s",
        "UMask": "0077",
    }
    try:
        configured_environment = {
            item.split("=", 1)[0]: item.split("=", 1)[1]
            for item in shlex.split(properties["Environment"])
        }
        configured_writable = shlex.split(properties["ReadWritePaths"])
        configured_read_only = shlex.split(properties["ReadOnlyPaths"])
        configured_capabilities = {
            item.upper() for item in shlex.split(properties["CapabilityBoundingSet"])
        }
    except (ValueError, IndexError) as exc:
        raise SupervisorError("outer transient unit list property is invalid") from exc
    exec_path, exec_argv = _parse_systemd_exec_start(properties["ExecStart"])
    if (
        wrapper_argv != expected_wrapper_argv
        or any(properties.get(key) != value for key, value in static.items())
        or re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"]) is None
        or configured_environment != OUTER_ENVIRONMENT
        or configured_writable != writable
        or configured_read_only != [str(LEASE_PARENT)]
        or configured_capabilities != set(OUTER_CAPABILITIES)
        or exec_path != expected_wrapper_argv[0]
        or exec_argv != expected_wrapper_argv
    ):
        raise SupervisorError("outer transient unit properties drifted")
    expected_lease = _expected_lease(arguments, unit=expected_unit)
    inherited_worker_lease_fds = _process_fd_matches(
        worker_pid, device=expected_lease["device"], inode=expected_lease["inode"]
    )
    lease_fd, lease = _open_monitored_lease(arguments, unit=expected_unit)
    try:
        wrapper_lease_fds = _process_fd_matches(
            wrapper_pid, device=lease["device"], inode=lease["inode"]
        )
        wrapper_has_worker_pidfd = _process_has_pidfd_for(wrapper_pid, worker_pid)
        parent_death_signal = _parent_death_signal()
        if (
            len(wrapper_lease_fds) != 1
            or inherited_worker_lease_fds
            or not wrapper_has_worker_pidfd
            or parent_death_signal != SIGKILL
        ):
            raise SupervisorError(
                "outer transient unit lease monitor is invalid "
                f"(wrapper_lease_fds={wrapper_lease_fds}, "
                f"inherited_worker_lease_fds={inherited_worker_lease_fds}, "
                f"wrapper_has_worker_pidfd={wrapper_has_worker_pidfd}, "
                f"parent_death_signal={parent_death_signal})"
            )
    finally:
        os.close(lease_fd)
    wrapper_cgroup_rows = Path(f"/proc/{wrapper_pid}/cgroup").read_text("ascii").splitlines()
    if wrapper_cgroup_rows != [f"0::{cgroup}"]:
        raise SupervisorError("outer transient unit wrapper cgroup drifted")
    wrapper_starttime = _proc_starttime(wrapper_pid)
    worker_starttime = _proc_starttime(worker_pid)
    launcher_pid = lease["launcher_pid"]
    guardian_pid = lease["guardian_pid"]
    if _single_process_child(launcher_pid, label="top launcher") != guardian_pid:
        raise SupervisorError("top launcher guardian relationship drifted")
    systemd_run_execution = lease["systemd_run_execution"]
    systemd_run_pid = systemd_run_execution["pid"]
    systemd_run_argv = _read_proc_argv(systemd_run_pid)
    systemd_run_exe = Path(f"/proc/{systemd_run_pid}/exe").stat()
    expected_systemd_run_argv = _systemd_run_argv(
        unit=expected_unit,
        root=root,
        writable=writable,
        wrapper_argv=expected_wrapper_argv,
    )
    if internal_action == "recover-supervise-worker":
        top_action = "recover"
    elif internal_action == "trace-verifier-fragment-supervise-worker":
        top_action = "trace-verifier-fragment"
    else:
        top_action = "launch"
    expected_top_argv = _top_level_argv(arguments, root=root, action=top_action)
    if (
        lease["launcher_argv"] != expected_top_argv
        or lease["guardian_argv"] != expected_top_argv
        or lease["guardian_parent_death_signal"] != SIGKILL
        or systemd_run_argv != expected_systemd_run_argv
        or systemd_run_execution["argv"] != expected_systemd_run_argv
        or systemd_run_execution["file"] != systemd_run_identity
        or not _process_has_pidfd_for(guardian_pid, systemd_run_pid)
        or (systemd_run_exe.st_dev, systemd_run_exe.st_ino)
        != (systemd_run_identity["device"], systemd_run_identity["inode"])
    ):
        raise SupervisorError("launcher guardian systemd-run identity drifted")
    lease_proof = WORKER_BOOTSTRAP["wrapper_execution"].get("launcher_lease")
    if (
        type(lease_proof) is not dict
        or lease_proof.get("identity") != lease
        or lease_proof.get("descriptor_cloexec") is not True
        or lease_proof.get("launcher_lock_verified_before_arm") is not True
        or lease_proof.get("systemd_run_lease_fd_inherited") is not False
        or lease_proof.get("all_checks_passed") is not True
    ):
        raise SupervisorError("outer transient unit launcher lease proof is invalid")
    return {
        "schema_version": 1,
        "unit": expected_unit,
        "supervisor_pid": worker_pid,
        "wrapper_pid": wrapper_pid,
        "worker_pid": worker_pid,
        "systemctl": dict(systemctl_identity),
        "systemctl_execution": systemctl_execution,
        "properties": properties,
        "proc": {
            "argv": worker_argv,
            "argv_sha256": hashlib.sha256(canonical_json(worker_argv)).hexdigest(),
            "cgroup": cgroup,
        },
        "wrapper": {
            "pid": wrapper_pid,
            "starttime": wrapper_starttime,
            "argv": wrapper_argv,
            "argv_sha256": hashlib.sha256(canonical_json(wrapper_argv)).hexdigest(),
            "cgroup": cgroup,
            "main_pid": True,
            "lease_monitor_fds": wrapper_lease_fds,
            "worker_pidfd_verified": True,
        },
        "worker": {
            "pid": worker_pid,
            "starttime": worker_starttime,
            "parent_pid": wrapper_pid,
            "argv": worker_argv,
            "argv_sha256": hashlib.sha256(canonical_json(worker_argv)).hexdigest(),
            "cgroup": cgroup,
            "parent_death_signal": "SIGKILL",
            "launcher_lease_fd_inherited": False,
            "bootstrap": WORKER_BOOTSTRAP,
        },
        "launcher_lease": {
            "identity": lease,
            "launcher": {
                "pid": launcher_pid,
                "starttime": lease["launcher_starttime"],
                "argv": _read_proc_argv(launcher_pid),
                "argv_sha256": lease["launcher_argv_sha256"],
            },
            "guardian": {
                "pid": guardian_pid,
                "starttime": lease["guardian_starttime"],
                "argv": _read_proc_argv(guardian_pid),
                "argv_sha256": lease["guardian_argv_sha256"],
                "parent_death_signal_observed_at_lease_creation": "SIGKILL",
            },
            "systemd_run": {
                "pid": systemd_run_pid,
                "starttime": _proc_starttime(systemd_run_pid),
                "argv": systemd_run_argv,
                "argv_sha256": hashlib.sha256(
                    canonical_json(systemd_run_argv)
                ).hexdigest(),
                "file": dict(systemd_run_identity),
                "execution": dict(systemd_run_execution),
                "parent_death_protection": {
                    "signal": systemd_run_execution["parent_death_signal_setup"],
                    "evidence_level": (
                        "trusted-preexec-set-get-plus-real-sigkill-test"
                    ),
                    "set_get_verified_before_exec": systemd_run_execution[
                        "parent_death_signal_set_get_verified_before_exec"
                    ],
                },
                "pidfd_owned_by_guardian": True,
            },
            "launcher_process_identity_verified": True,
            "launcher_lock_verified_live": True,
            "systemd_run_lease_fd_inherited": False,
            "worker_lease_fd_inherited": False,
            "wrapper_monitor_fd_count": 1,
            "read_only_bind": str(LEASE_PARENT),
            "all_checks_passed": True,
        },
        "expected_environment": OUTER_ENVIRONMENT,
        "read_write_paths": writable,
        "read_only_paths": [str(LEASE_PARENT)],
        "capability_bounding_set": list(OUTER_CAPABILITIES),
        "all_checks_passed": True,
    }


def _supervise(arguments: argparse.Namespace) -> dict[str, Any]:
    _require_system_python()
    expected = _identity(arguments)
    python_identity = _program(
        SYSTEM_PYTHON, arguments.expected_system_python_sha256, label="system Python"
    )
    _verify_preload(arguments.expected_ld_so_preload_sha256)
    systemd_run_identity = _program_with_inode(
        SYSTEMD_RUN, arguments.expected_systemd_run_sha256, label="systemd-run"
    )
    systemctl_identity = _program(
        SYSTEMCTL, arguments.expected_systemctl_sha256, label="systemctl"
    )
    ldconfig_identity = _program(
        LDCONFIG, arguments.expected_ldconfig_sha256, label="ldconfig.real"
    )
    _program(Path("/usr/bin/strace"), arguments.expected_strace_sha256, label="strace")
    root, manifest = _bootstrap_release(expected)
    expected_publisher_sha256 = _manifest_member_sha256(
        manifest, PUBLISHER_RELATIVE
    )
    suite = _load_module("_dev29_sealed_suite", root.joinpath(*SUITE_RELATIVE.parts))
    closure_module = _load_module(
        "_dev29_sealed_closure", root.joinpath(*CLOSURE_RELATIVE.parts)
    )
    suite_expected = suite.ExpectedIdentity(**expected)
    suite_closure = suite.ExpectedClosure(
        anchor_sha256=arguments.expected_closure_anchor_sha256,
        image_sha256=arguments.expected_closure_image_sha256,
        system_python_sha256=arguments.expected_system_python_sha256,
        loader_preload_sha256=arguments.expected_ld_so_preload_sha256,
        ldconfig_sha256=arguments.expected_ldconfig_sha256,
    )
    paths = suite._release_paths(suite_expected)
    import grp

    service_gid = grp.getgrnam("odoo").gr_gid
    plan, _plan_bytes = suite.load_plan(paths, enforce_root=True)
    runtime, _runtime_bytes = suite.load_runtime(
        paths["runtime"],
        plan,
        suite_expected,
        service_gid=service_gid,
        enforce_root=True,
    )
    outer_unit = _outer_unit_evidence(
        arguments,
        root=root,
        runtime=runtime,
        systemctl_identity=systemctl_identity,
        systemd_run_identity=systemd_run_identity,
    )
    evidence = EVIDENCE_PARENT / arguments.evidence_name
    anchor_path = ANCHOR_PARENT / f"{arguments.evidence_name}.json"
    stage = STAGING_PARENT / arguments.evidence_name
    if os.path.lexists(anchor_path) or os.path.lexists(stage):
        raise SupervisorError("Dev29 evidence or staging identity already exists")
    os.mkdir(stage, 0o700)
    active: dict[str, Any] | None = None
    for name in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(name, _signal_handler)
    closure_expected = closure_module.ExpectedIdentity(**expected)
    with suite.DependencyWatch([ANCHOR_PARENT]) as anchor_guard:
        with closure_module.activated_closure(
                closure_expected,
                expected_system_python_sha256=arguments.expected_system_python_sha256,
                expected_loader_preload_sha256=arguments.expected_ld_so_preload_sha256,
                expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
                expected_closure_anchor_sha256=arguments.expected_closure_anchor_sha256,
                expected_closure_image_sha256=arguments.expected_closure_image_sha256,
                expected_odoo_config_sha256=runtime["odoo_config_sha256"],
                expected_database_name=plan["database"]["name"],
                expected_database_uuid=plan["database"]["uuid"],
                root=Path("/"),
                script_path=paths["closure"],
        ) as active:
                evidence, bundle_sha256 = suite.run_suite(
                    evidence,
                    suite_expected,
                    suite_closure,
                    runtime_path=paths["runtime"],
                    outer_unit_evidence=outer_unit,
                    active_closure_document=active,
                    expected_runtime_trace_index_sha256=(
                        arguments.expected_runtime_open_index_sha256
                    ),
                    expected_strace_sha256=arguments.expected_strace_sha256,
                    runtime_open_discovery_inventory=(
                        arguments.runtime_open_discovery_inventory
                    ),
                    runtime_open_discovery_static_closure_sha256=(
                        arguments.runtime_open_discovery_static_closure_sha256
                    ),
                    runtime_open_discovery_watch_roots=tuple(
                        arguments.runtime_open_discovery_watch_root
                    ),
                    runtime_open_discovery_mutable_roots=tuple(
                        arguments.runtime_open_discovery_mutable_root
                    ),
                    runtime_open_discovery_sqlite_delta_contract_sha256=(
                        arguments.runtime_open_discovery_sqlite_delta_contract_sha256
                    ),
                )
                if arguments.runtime_open_discovery_inventory is not None:
                    anchor_guard.assert_clean()
                    stage.rmdir()
                    return {
                        "schema_version": 1,
                        "scope": (
                            "odoo-accounting-cli-v3.dev29."
                            "runtime-open-discovery-evidence.v1"
                        ),
                        "evidence_path": str(evidence),
                        "discovery_inventory": str(
                            arguments.runtime_open_discovery_inventory
                        ),
                        "discovery_inventory_sha256": bundle_sha256,
                        "candidate_is_approval": False,
                        "production_promotion_allowed": False,
                    }
                verifier_command = [
                    str(suite.CLOSURE_PYTHON),
                    "-I",
                    "-B",
                    "-S",
                    str(paths["verifier"]),
                    "--validate-only",
                    "--evidence-dir",
                    str(evidence),
                    "--expected-bundle-manifest-sha256",
                    bundle_sha256,
                    "--expected-release",
                    expected["release"],
                    "--expected-version",
                    expected["version"],
                    "--expected-commit",
                    expected["commit"],
                    "--expected-manifest-sha256",
                    expected["manifest_sha256"],
                    "--expected-package-sha256",
                    expected["package_sha256"],
                    "--expected-closure-anchor-sha256",
                    arguments.expected_closure_anchor_sha256,
                    "--expected-closure-image-sha256",
                    arguments.expected_closure_image_sha256,
                    "--expected-system-python-sha256",
                    arguments.expected_system_python_sha256,
                    "--expected-ld-so-preload-sha256",
                    arguments.expected_ld_so_preload_sha256,
                    "--expected-ldconfig-sha256",
                    arguments.expected_ldconfig_sha256,
                    "--expected-runtime-open-index-sha256",
                    arguments.expected_runtime_open_index_sha256,
                    "--expected-strace-sha256",
                    arguments.expected_strace_sha256,
                ]
                verifier_sidecar = _verifier_private_sidecar_path(
                    arguments.evidence_name
                )
                os.mkdir(verifier_sidecar, 0o700)
                verifier_trace_gate = suite.RuntimeTraceGate(
                    suite_expected,
                    expected_index_sha256=(
                        arguments.expected_runtime_open_index_sha256
                    ),
                    expected_strace_sha256=arguments.expected_strace_sha256,
                    private_sidecar=verifier_sidecar,
                )
                verifier_process = suite._run_direct_child(
                    "verifier",
                    verifier_command,
                    trace_target_id="independent-verifier",
                    trace_gate=verifier_trace_gate,
                    stdin=b"",
                    runtime=runtime,
                    expected=suite_expected,
                    closure=active,
                    timeout=600,
                )
                report = suite._strict_success(
                    verifier_process, label="independent evidence verifier"
                )
                verifier_child = verifier_process.dev29_attestation
                verifier_control = verifier_process.dev29_process_control
                verifier_trace_private = verifier_trace_gate.seal_private_manifest(
                    ("independent-verifier",)
                )
                verifier_trace = verifier_trace_gate.document(
                    ("independent-verifier",)
                )
                verifier_trace["private_sidecar"] = verifier_trace_private
                _write_stage(stage / "validation-report.json", report)
                _write_stage(stage / "verifier-child.json", verifier_child)
                _write_stage(stage / "verifier-process-control.json", verifier_control)
                _write_stage(stage / "verifier-runtime-trace.json", verifier_trace)
                anchor_guard.assert_clean()
        if active is None or "cleanup_receipt" not in active:
            raise SupervisorError("closure cleanup receipt is absent")
        cleanup = active["cleanup_receipt"]
        _write_stage(stage / "cleanup-receipt.json", cleanup)
        anchor_guard.assert_clean()
        prepublication_guard = anchor_guard.document()
        release_identity = report.get("release_identity")
        if (
            type(release_identity) is not dict
            or release_identity.get("registry_digest")
            != arguments.expected_registry_digest
        ):
            raise SupervisorError("validation report release identity is invalid")
        bootstrap = {
            "schema_version": 1,
            "supervisor_pid": os.getpid(),
            "release_identity": release_identity,
            "files": {
                "system_python": python_identity,
                "systemd_run": systemd_run_identity,
                "systemctl": systemctl_identity,
                "ldconfig": ldconfig_identity,
                "strace": _bootstrap_file_identity(
                    Path("/usr/bin/strace"), allowed_modes=frozenset({0o755})
                ),
                "ld_so_preload": _bootstrap_file_identity(
                    LD_SO_PRELOAD, allowed_modes=frozenset({0o644})
                ),
                "runner": _bootstrap_file_identity(
                    paths["root"].joinpath(*RUNNER_RELATIVE.parts),
                    allowed_modes=frozenset({0o444, 0o555}),
                ),
                "publisher": _bootstrap_file_identity(
                    paths["root"].joinpath(*PUBLISHER_RELATIVE.parts),
                    allowed_modes=frozenset({0o444, 0o555}),
                ),
            },
        }
        _write_stage(stage / "prepublication-guard.json", prepublication_guard)
        _write_stage(stage / "supervisor-bootstrap.json", bootstrap)
        publisher_path = paths["root"].joinpath(*PUBLISHER_RELATIVE.parts)
        publisher_argv = _publisher_argv(
            arguments,
            publisher_path=publisher_path,
            evidence=evidence,
            stage=stage,
            expected=expected,
            bundle_manifest_sha256=bundle_sha256,
        )
        _drop_publisher_capabilities()
    _exec_pinned_publisher(
        publisher_path=publisher_path,
        expected_publisher_sha256=expected_publisher_sha256,
        publisher_argv=publisher_argv,
        environment=OUTER_ENVIRONMENT,
        expected_system_python_sha256=arguments.expected_system_python_sha256,
    )
    raise SupervisorError("publisher exec unexpectedly returned")


def _trace_verifier_fragment_supervise(arguments: argparse.Namespace) -> dict[str, Any]:
    _require_system_python()
    expected = _identity(arguments)
    _validate_verifier_fragment_paths(arguments)
    _program(
        SYSTEM_PYTHON, arguments.expected_system_python_sha256, label="system Python"
    )
    _verify_preload(arguments.expected_ld_so_preload_sha256)
    systemd_run_identity = _program_with_inode(
        SYSTEMD_RUN, arguments.expected_systemd_run_sha256, label="systemd-run"
    )
    systemctl_identity = _program(
        SYSTEMCTL, arguments.expected_systemctl_sha256, label="systemctl"
    )
    _program(LDCONFIG, arguments.expected_ldconfig_sha256, label="ldconfig.real")
    _program(Path("/usr/bin/strace"), arguments.expected_strace_sha256, label="strace")
    root, _manifest = _bootstrap_release(expected)
    suite = _load_module("_dev29_verifier_fragment_suite", root.joinpath(*SUITE_RELATIVE.parts))
    closure_module = _load_module(
        "_dev29_verifier_fragment_closure", root.joinpath(*CLOSURE_RELATIVE.parts)
    )
    suite_expected = suite.ExpectedIdentity(**expected)
    suite_closure = suite.ExpectedClosure(
        anchor_sha256=arguments.expected_closure_anchor_sha256,
        image_sha256=arguments.expected_closure_image_sha256,
        system_python_sha256=arguments.expected_system_python_sha256,
        loader_preload_sha256=arguments.expected_ld_so_preload_sha256,
        ldconfig_sha256=arguments.expected_ldconfig_sha256,
    )
    suite_expected.validate()
    suite_closure.validate()
    paths = suite._release_paths(suite_expected)
    import grp

    service_gid = grp.getgrnam("odoo").gr_gid
    plan, _plan_bytes = suite.load_plan(paths, enforce_root=True)
    runtime, _runtime_bytes = suite.load_runtime(
        paths["runtime"],
        plan,
        suite_expected,
        service_gid=service_gid,
        enforce_root=True,
    )
    _outer_unit_evidence(
        arguments,
        root=root,
        runtime=runtime,
        systemctl_identity=systemctl_identity,
        systemd_run_identity=systemd_run_identity,
        internal_action="trace-verifier-fragment-supervise-worker",
    )
    output = Path(arguments.verifier_fragment_output)
    verifier_sidecar = _verifier_private_sidecar_path(
        f"{arguments.evidence_name}.verifier-fragment"
    )
    if os.path.lexists(output) or os.path.lexists(verifier_sidecar):
        raise SupervisorError("runtime-open verifier discovery output already exists")
    _create_verifier_fragment_evidence_dir(Path(arguments.verifier_evidence_dir))
    os.mkdir(verifier_sidecar, 0o700)
    os.mkdir(verifier_sidecar / ".trace-staging", 0o700)
    closure_expected = closure_module.ExpectedIdentity(**expected)
    with closure_module.activated_closure(
        closure_expected,
        expected_system_python_sha256=arguments.expected_system_python_sha256,
        expected_loader_preload_sha256=arguments.expected_ld_so_preload_sha256,
        expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
        expected_closure_anchor_sha256=arguments.expected_closure_anchor_sha256,
        expected_closure_image_sha256=arguments.expected_closure_image_sha256,
        expected_odoo_config_sha256=runtime["odoo_config_sha256"],
        expected_database_name=plan["database"]["name"],
        expected_database_uuid=plan["database"]["uuid"],
        root=Path("/"),
        script_path=paths["closure"],
    ) as active:
        verifier_command = [
            str(suite.CLOSURE_PYTHON),
            "-I",
            "-B",
            "-S",
            str(paths["verifier"]),
            "--validate-only",
            "--evidence-dir",
            str(arguments.verifier_evidence_dir),
            "--expected-bundle-manifest-sha256",
            arguments.expected_bundle_manifest_sha256,
            "--expected-release",
            expected["release"],
            "--expected-version",
            expected["version"],
            "--expected-commit",
            expected["commit"],
            "--expected-manifest-sha256",
            expected["manifest_sha256"],
            "--expected-package-sha256",
            expected["package_sha256"],
            "--expected-closure-anchor-sha256",
            arguments.expected_closure_anchor_sha256,
            "--expected-closure-image-sha256",
            arguments.expected_closure_image_sha256,
            "--expected-system-python-sha256",
            arguments.expected_system_python_sha256,
            "--expected-ld-so-preload-sha256",
            arguments.expected_ld_so_preload_sha256,
            "--expected-ldconfig-sha256",
            arguments.expected_ldconfig_sha256,
            "--expected-runtime-open-index-sha256",
            arguments.expected_runtime_open_index_sha256,
            "--expected-strace-sha256",
            arguments.expected_strace_sha256,
        ]
        trace_gate = suite.RuntimeTraceDiscoveryGate(
            suite_expected,
            expected_strace_sha256=arguments.expected_strace_sha256,
            private_sidecar=verifier_sidecar,
            watch_roots=tuple(arguments.runtime_open_discovery_watch_root),
        )
        process = suite._run_direct_child(
            "verifier",
            verifier_command,
            trace_target_id="independent-verifier",
            trace_gate=trace_gate,
            stdin=b"",
            runtime=runtime,
            expected=suite_expected,
            closure=active,
            timeout=600,
        )
        if process.returncode == 0:
            suite._strict_success(process, label="independent evidence verifier")
            verifier_bootstrap_only = False
        elif process.stdout or not process.stderr:
            raise SupervisorError(
                "independent evidence verifier did not fail closed for discovery"
            )
        elif b"bundle manifest" not in process.stderr:
            raise SupervisorError(
                "independent evidence verifier discovery failure is not bundle-bound"
            )
        else:
            verifier_bootstrap_only = True
        inventory = trace_gate.inventory(
            required_targets=("independent-verifier",),
            expected_static_closure_sha256=(
                arguments.runtime_open_discovery_static_closure_sha256
            ),
            watch_roots=tuple(arguments.runtime_open_discovery_watch_root),
            mutable_roots=tuple(arguments.runtime_open_discovery_mutable_root),
            sqlite_delta_contract_sha256=(
                arguments.runtime_open_discovery_sqlite_delta_contract_sha256
                or suite.discovery_sqlite_delta_contract_sha256()
            ),
            scope=suite.RUNTIME_OPEN_DISCOVERY_VERIFIER_FRAGMENT_SCOPE,
        )
        if verifier_bootstrap_only:
            inventory["targets"][0]["expected_returncodes"] = sorted(
                {0, int(process.returncode)}
            )
    payload = suite.canonical_json(inventory) + b"\n"
    suite.write_private(output, payload)
    return {
        "schema_version": 1,
        "scope": (
            "odoo-accounting-cli-v3.dev29."
            "runtime-open-discovery-verifier-evidence.v1"
        ),
        "verifier_evidence_dir": str(arguments.verifier_evidence_dir),
        "verifier_fragment": str(output),
        "verifier_fragment_sha256": hashlib.sha256(payload).hexdigest(),
        "target_count": len(inventory["targets"]),
        "bootstrap_only": verifier_bootstrap_only,
        "verifier_returncode": int(process.returncode),
        "candidate_is_approval": False,
        "production_promotion_allowed": False,
    }


def _recover_supervise(arguments: argparse.Namespace) -> dict[str, Any]:
    _require_system_python()
    expected = _identity(arguments)
    if (
        SAFE_NAME.fullmatch(arguments.evidence_name) is None
        or HEX64.fullmatch(arguments.expected_bundle_manifest_sha256) is None
    ):
        raise SupervisorError("recovery evidence identity is invalid")
    _program(
        SYSTEM_PYTHON,
        arguments.expected_system_python_sha256,
        label="system Python",
    )
    _verify_preload(arguments.expected_ld_so_preload_sha256)
    recovery_systemd_run_identity = _program_with_inode(
        SYSTEMD_RUN, arguments.expected_systemd_run_sha256, label="systemd-run"
    )
    systemctl_identity = _program(
        SYSTEMCTL, arguments.expected_systemctl_sha256, label="systemctl"
    )
    _program(LDCONFIG, arguments.expected_ldconfig_sha256, label="ldconfig.real")
    _program(Path("/usr/bin/strace"), arguments.expected_strace_sha256, label="strace")
    root, manifest = _bootstrap_release(expected)
    expected_publisher_sha256 = _manifest_member_sha256(
        manifest, PUBLISHER_RELATIVE
    )
    suite = _load_module("_dev29_recovery_suite", root.joinpath(*SUITE_RELATIVE.parts))
    suite_expected = suite.ExpectedIdentity(**expected)
    suite_closure = suite.ExpectedClosure(
        anchor_sha256=arguments.expected_closure_anchor_sha256,
        image_sha256=arguments.expected_closure_image_sha256,
        system_python_sha256=arguments.expected_system_python_sha256,
        loader_preload_sha256=arguments.expected_ld_so_preload_sha256,
        ldconfig_sha256=arguments.expected_ldconfig_sha256,
    )
    suite_expected.validate()
    suite_closure.validate()
    paths = suite._release_paths(suite_expected)
    import grp

    service_gid = grp.getgrnam("odoo").gr_gid
    plan, _plan_bytes = suite.load_plan(paths, enforce_root=True)
    runtime, _runtime_bytes = suite.load_runtime(
        paths["runtime"],
        plan,
        suite_expected,
        service_gid=service_gid,
        enforce_root=True,
    )
    recovery_outer_unit = _outer_unit_evidence(
        arguments,
        root=root,
        runtime=runtime,
        systemd_run_identity=recovery_systemd_run_identity,
        systemctl_identity=systemctl_identity,
        internal_action="recover-supervise-worker",
    )
    evidence = EVIDENCE_PARENT / arguments.evidence_name
    stage = STAGING_PARENT / arguments.evidence_name
    _recovery_artifact_state(arguments.evidence_name)
    publisher_path = root.joinpath(*PUBLISHER_RELATIVE.parts)
    publisher_argv = _publisher_argv(
        arguments,
        publisher_path=publisher_path,
        evidence=evidence,
        stage=stage,
        expected=expected,
        bundle_manifest_sha256=arguments.expected_bundle_manifest_sha256,
    )
    _drop_publisher_capabilities()
    _exec_pinned_publisher(
        publisher_path=publisher_path,
        expected_publisher_sha256=expected_publisher_sha256,
        publisher_argv=publisher_argv,
        environment=OUTER_ENVIRONMENT,
        expected_system_python_sha256=arguments.expected_system_python_sha256,
        recovery_outer_unit=recovery_outer_unit,
    )
    raise SupervisorError("recovery publisher exec unexpectedly returned")


def _status(arguments: argparse.Namespace) -> dict[str, Any]:
    _require_system_python()
    expected = _identity(arguments)
    if (
        SAFE_NAME.fullmatch(arguments.evidence_name) is None
        or HEX64.fullmatch(arguments.expected_bundle_manifest_sha256) is None
    ):
        raise SupervisorError("status evidence identity is invalid")
    _program(
        SYSTEM_PYTHON,
        arguments.expected_system_python_sha256,
        label="system Python",
    )
    _verify_preload(arguments.expected_ld_so_preload_sha256)
    _program(
        SYSTEMD_RUN, arguments.expected_systemd_run_sha256, label="systemd-run"
    )
    _program(SYSTEMCTL, arguments.expected_systemctl_sha256, label="systemctl")
    _program(LDCONFIG, arguments.expected_ldconfig_sha256, label="ldconfig.real")
    _program(Path("/usr/bin/strace"), arguments.expected_strace_sha256, label="strace")
    root, _manifest = _bootstrap_release(expected)
    evidence = EVIDENCE_PARENT / arguments.evidence_name
    anchor = ANCHOR_PARENT / f"{arguments.evidence_name}.json"
    pending = ANCHOR_PARENT / f".{arguments.evidence_name}.json.pending"
    stage = STAGING_PARENT / arguments.evidence_name
    stage_members: list[str] = []
    if os.path.lexists(stage):
        if not stage.is_dir() or stage.is_symlink():
            raise SupervisorError("status staging directory is unsafe")
        _verify_writable_directory(stage, uid=0, gid=0, mode=0o700)
        stage_members = sorted(item.name for item in stage.iterdir())
        if not set(stage_members) <= PUBLISHER_STAGE_FILES:
            raise SupervisorError("status staging file set is invalid")
        for name in stage_members:
            metadata = (stage / name).lstat()
            if (
                (stage / name).is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid) != (0, 0)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise SupervisorError("status staging member is unsafe")
    anchor_verified = False
    pending_verified = False
    if os.path.lexists(anchor) or os.path.lexists(pending):
        publisher = _load_module(
            "_dev29_status_publisher", root.joinpath(*PUBLISHER_RELATIVE.parts)
        )
    if os.path.lexists(anchor):
        publisher._validate_existing_anchor_for_stage_cleanup(
            anchor,
            evidence=evidence,
            expected_release_identity={
                **expected,
                "registry_digest": arguments.expected_registry_digest,
                "verified": True,
            },
            expected_bundle_manifest_sha256=(
                arguments.expected_bundle_manifest_sha256
            ),
            expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
            expected_runtime_open_index_sha256=(
                arguments.expected_runtime_open_index_sha256
            ),
            expected_strace_sha256=arguments.expected_strace_sha256,
        )
        anchor_verified = True
    elif os.path.lexists(pending):
        if _recovery_artifact_state(arguments.evidence_name) != "pending_anchor_commit":
            raise SupervisorError("pending publication is not recoverable")
        pending_payload = publisher.stable_read(
            pending,
            label="status recoverable pending anchor",
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o400}),
        )
        publisher._validate_existing_anchor_for_stage_cleanup(
            pending,
            evidence=evidence,
            expected_release_identity={
                **expected,
                "registry_digest": arguments.expected_registry_digest,
                "verified": True,
            },
            expected_bundle_manifest_sha256=(
                arguments.expected_bundle_manifest_sha256
            ),
            expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
            expected_runtime_open_index_sha256=(
                arguments.expected_runtime_open_index_sha256
            ),
            expected_strace_sha256=arguments.expected_strace_sha256,
            validated_payload=pending_payload,
        )
        pending_verified = True
    if anchor_verified and os.path.lexists(stage):
        lifecycle = "durable_anchor_cleanup_pending"
    elif anchor_verified:
        lifecycle = "complete"
    elif pending_verified:
        lifecycle = "durable_pending_commit_recoverable"
    elif os.path.lexists(stage):
        lifecycle = "prepublication_failed_or_running"
    elif os.path.lexists(evidence):
        lifecycle = "unanchored_evidence"
    else:
        lifecycle = "absent"
    return {
        "schema_version": 1,
        "evidence_name": arguments.evidence_name,
        "lifecycle": lifecycle,
        "evidence_exists": os.path.lexists(evidence),
        "durable_anchor_verified": anchor_verified,
        "durable_pending_verified": pending_verified,
        "staging_exists": os.path.lexists(stage),
        "staging_members": stage_members,
        "recovery_available": (
            (anchor_verified and os.path.lexists(stage)) or pending_verified
        ),
        "production_promotion_allowed": False,
    }


def _common(parser: argparse.ArgumentParser) -> None:
    for dest, option in COMMON_OPTIONS:
        parser.add_argument(
            option,
            required=dest != "expected_runtime_open_index_sha256",
        )
    parser.add_argument("--runtime-open-discovery-inventory", type=Path)
    parser.add_argument("--runtime-open-discovery-static-closure-sha256")
    parser.add_argument(
        "--runtime-open-discovery-watch-root",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--runtime-open-discovery-mutable-root",
        action="append",
        default=[],
    )
    parser.add_argument("--runtime-open-discovery-sqlite-delta-contract-sha256")


def _verifier_discovery(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verifier-evidence-dir", required=True, type=Path)
    parser.add_argument("--verifier-fragment-output", required=True, type=Path)
    parser.add_argument("--expected-bundle-manifest-sha256", required=True)


def _lease_options(parser: argparse.ArgumentParser) -> None:
    for _dest, option in LEASE_OPTIONS:
        parser.add_argument(option, required=True)


def _wrapper_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    action: str,
    *,
    recovery: bool,
) -> None:
    current = subparsers.add_parser(action)
    _common(current)
    _lease_options(current)
    if recovery:
        current.add_argument("--expected-bundle-manifest-sha256", required=True)
    current.add_argument("--expected-worker-script-sha256", required=True)
    current.add_argument("--expected-unit", required=True)


def _worker_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    action: str,
    *,
    recovery: bool,
) -> None:
    current = subparsers.add_parser(action)
    _common(current)
    _lease_options(current)
    if recovery:
        current.add_argument("--expected-bundle-manifest-sha256", required=True)
    current.add_argument("--expected-unit", required=True)
    current.add_argument("--expected-wrapper-pid", required=True)
    current.add_argument("--worker-gate-fd", required=True)
    current.add_argument("--expected-worker-script-sha256", required=True)
    for _dest, option in WORKER_PIN_OPTIONS:
        current.add_argument(option, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    _common(subparsers.add_parser("launch"))
    verifier = subparsers.add_parser("trace-verifier-fragment")
    _common(verifier)
    _verifier_discovery(verifier)
    recover = subparsers.add_parser("recover")
    _common(recover)
    recover.add_argument("--expected-bundle-manifest-sha256", required=True)
    status_parser = subparsers.add_parser("status")
    _common(status_parser)
    status_parser.add_argument("--expected-bundle-manifest-sha256", required=True)
    _wrapper_parser(subparsers, "unit-wrapper", recovery=False)
    verifier_wrapper = subparsers.add_parser("trace-verifier-fragment-unit-wrapper")
    _common(verifier_wrapper)
    _verifier_discovery(verifier_wrapper)
    _lease_options(verifier_wrapper)
    verifier_wrapper.add_argument("--expected-worker-script-sha256", required=True)
    verifier_wrapper.add_argument("--expected-unit", required=True)
    _wrapper_parser(subparsers, "recover-unit-wrapper", recovery=True)
    _worker_parser(subparsers, "supervise-worker", recovery=False)
    verifier_worker = subparsers.add_parser("trace-verifier-fragment-supervise-worker")
    _common(verifier_worker)
    _verifier_discovery(verifier_worker)
    _lease_options(verifier_worker)
    verifier_worker.add_argument("--expected-unit", required=True)
    verifier_worker.add_argument("--expected-wrapper-pid", required=True)
    verifier_worker.add_argument("--worker-gate-fd", required=True)
    verifier_worker.add_argument("--expected-worker-script-sha256", required=True)
    for _dest, option in WORKER_PIN_OPTIONS:
        verifier_worker.add_argument(option, required=True)
    _worker_parser(subparsers, "recover-supervise-worker", recovery=True)
    return parser


def _launch_guardian(
    arguments: argparse.Namespace,
    *,
    launcher_pid: int,
    launcher_starttime: int,
) -> int:
    _require_system_python()
    expected = _identity(arguments)
    if SAFE_NAME.fullmatch(arguments.evidence_name) is None:
        raise SupervisorError("evidence name is invalid")
    _program(
        SYSTEM_PYTHON,
        arguments.expected_system_python_sha256,
        label="system Python",
    )
    _program(SYSTEMCTL, arguments.expected_systemctl_sha256, label="systemctl")
    _program(LDCONFIG, arguments.expected_ldconfig_sha256, label="ldconfig.real")
    _program(
        Path("/usr/bin/strace"), arguments.expected_strace_sha256, label="strace"
    )
    _verify_preload(arguments.expected_ld_so_preload_sha256)
    root, release_manifest = _bootstrap_release(expected)
    script = root.joinpath(*RUNNER_RELATIVE.parts)
    if Path(__file__).resolve(strict=True) != script.resolve(strict=True):
        raise SupervisorError("launcher is outside the expected release")
    expected_top_argv = _top_level_argv(arguments, root=root)
    observed_parent_argv = _read_proc_argv(launcher_pid)
    observed_guardian_argv = _read_proc_argv(os.getpid())
    observed_parent_death = _parent_death_signal()
    observed_parent_pid = os.getppid()
    observed_parent_starttime = _proc_starttime(launcher_pid)
    if (
        observed_parent_death != SIGKILL
        or observed_parent_pid != launcher_pid
        or observed_parent_starttime != launcher_starttime
        or observed_guardian_argv != expected_top_argv
        or observed_parent_argv != expected_top_argv
    ):
        raise SupervisorError(
            "launcher guardian parent-death binding is invalid "
            f"(pdeath={observed_parent_death == SIGKILL}, "
            f"ppid={observed_parent_pid == launcher_pid}, "
            f"starttime={observed_parent_starttime == launcher_starttime}, "
            f"guardian_argv={observed_guardian_argv == expected_top_argv}, "
            f"launcher_argv={observed_parent_argv == expected_top_argv})"
        )
    unit = f"odoo-accounting-cli-v3-dev29-{arguments.evidence_name}.service"
    expected_worker_script_sha256 = _manifest_member_sha256(
        release_manifest, RUNNER_RELATIVE
    )
    _verify_lease_parent()
    auth_state_parent = Path(
        f"/var/lib/odoo-accounting-cli-v3/test/candidates/{expected['release']}/auth"
    )
    receipt_state_parent = Path(
        f"/var/lib/odoo-accounting-cli-v3/test/candidates/{expected['release']}/receipt"
    )
    gcov_state_parent = Path(
        f"/var/lib/odoo-accounting-cli-v3/test/candidates/{expected['release']}/gcov"
    )
    dependency_mount_point = Path(
        f"/opt/odoo-accounting-cli-v3/dependencies/{expected['release']}"
    )
    writable_text = _outer_writable_paths(expected["release"])
    writable = [Path(item) for item in writable_text]
    expected_writable = [
        EVIDENCE_PARENT,
        PRIVATE_EVIDENCE_PARENT,
        RUNTIME_TRACE_STAGING_PARENT,
        ANCHOR_PARENT,
        dependency_mount_point.parent,
        auth_state_parent,
        receipt_state_parent,
        gcov_state_parent,
        BROKER_HOME,
        STAGING_PARENT,
    ]
    if writable != expected_writable:
        raise SupervisorError("outer writable path contract is invalid")
    import grp
    import pwd

    odoo = pwd.getpwnam("odoo")
    odoo_group = grp.getgrnam("odoo")
    exact_writable = {
        EVIDENCE_PARENT: (0, 0, 0o755),
        PRIVATE_EVIDENCE_PARENT: (0, 0, 0o700),
        RUNTIME_TRACE_STAGING_PARENT: (0, 0, 0o700),
        ANCHOR_PARENT: (0, 0, 0o755),
        dependency_mount_point.parent: (0, odoo_group.gr_gid, 0o750),
        auth_state_parent: (odoo.pw_uid, odoo_group.gr_gid, 0o700),
        receipt_state_parent: (odoo.pw_uid, odoo_group.gr_gid, 0o700),
        gcov_state_parent: (odoo.pw_uid, odoo_group.gr_gid, 0o700),
        BROKER_HOME: (odoo.pw_uid, odoo_group.gr_gid, 0o700),
        STAGING_PARENT: (0, 0, 0o700),
    }
    for path, (uid, gid, mode) in exact_writable.items():
        _verify_writable_directory(path, uid=uid, gid=gid, mode=mode)
    if arguments.action == "recover":
        internal_action = "recover-unit-wrapper"
    elif arguments.action == "trace-verifier-fragment":
        internal_action = "trace-verifier-fragment-unit-wrapper"
    else:
        internal_action = "unit-wrapper"
    if arguments.action == "recover":
        if HEX64.fullmatch(arguments.expected_bundle_manifest_sha256) is None:
            raise SupervisorError("expected bundle manifest digest is invalid")
    lease_fd, lease = _create_launcher_lease(
        arguments.evidence_name,
        unit,
        launcher_pid=launcher_pid,
        launcher_starttime=launcher_starttime,
        expected_process_argv=expected_top_argv,
    )
    wrapper_arguments = argparse.Namespace(**{
        **vars(arguments),
        "expected_lease_nonce": lease["nonce"],
        "expected_lease_device": lease["device"],
        "expected_lease_inode": lease["inode"],
        "expected_lease_launcher_pid": lease["launcher_pid"],
        "expected_lease_launcher_starttime": lease["launcher_starttime"],
        "expected_lease_guardian_pid": lease["guardian_pid"],
        "expected_lease_guardian_starttime": lease["guardian_starttime"],
    })
    wrapper_argv = _wrapper_argv(
        wrapper_arguments,
        root=root,
        action=internal_action,
        unit=unit,
        worker_script_sha256=expected_worker_script_sha256,
    )
    command = _systemd_run_argv(
        unit=unit,
        root=root,
        writable=writable_text,
        wrapper_argv=wrapper_argv,
    )
    try:
        completed, _systemd_run_execution = _run_pinned_program(
            SYSTEMD_RUN,
            arguments.expected_systemd_run_sha256,
            command,
            label="systemd-run",
            stdin=subprocess.DEVNULL,
            cwd=root,
            env=OUTER_ENVIRONMENT,
            timeout=SYSTEMD_RUN_COMMUNICATE_TIMEOUT_SECONDS,
            exec_verified_callback=lambda execution: _finalize_launcher_lease_execution(
                lease_fd, lease, execution
            ),
        )
        return completed.returncode
    finally:
        try:
            _remove_launcher_lease(lease_fd, lease)
        finally:
            os.close(lease_fd)


def _arm_guardian_parent_death(
    expected_parent_pid: int, expected_parent_starttime: int
) -> None:
    if (
        os.getppid() != expected_parent_pid
        or _proc_starttime(expected_parent_pid) != expected_parent_starttime
    ):
        os._exit(125)
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0:
        os._exit(126)
    observed = ctypes.c_int()
    if (
        library.prctl(PR_GET_PDEATHSIG, ctypes.byref(observed), 0, 0, 0) != 0
        or observed.value != SIGKILL
    ):
        os._exit(126)
    if (
        os.getppid() != expected_parent_pid
        or _proc_starttime(expected_parent_pid) != expected_parent_starttime
    ):
        os._exit(125)


def _normalized_exit_code(returncode: int) -> int:
    if returncode < 0:
        return min(255, 128 + -returncode)
    return min(255, returncode)


def _launch(arguments: argparse.Namespace) -> int:
    """Keep a guardian between the top launcher, systemd-run, and the lease."""
    _require_system_python()
    if os.name != "posix" or not hasattr(os, "fork"):
        raise SupervisorError("launcher guardian requires Linux fork semantics")
    launcher_pid = os.getpid()
    launcher_starttime = _proc_starttime(launcher_pid)
    guardian_pid = os.fork()
    if guardian_pid == 0:
        try:
            _arm_guardian_parent_death(launcher_pid, launcher_starttime)
            result = _launch_guardian(
                arguments,
                launcher_pid=launcher_pid,
                launcher_starttime=launcher_starttime,
            )
        except (OSError, SupervisorError, subprocess.SubprocessError) as exc:
            print(f"Dev29 read evidence guardian refused: {exc}", file=sys.stderr)
            result = 2
        os._exit(_normalized_exit_code(result))
    try:
        guardian_pidfd = _open_child_pidfd(guardian_pid, label="launcher guardian")
    except BaseException as exc:
        try:
            waited, status = os.waitpid(guardian_pid, os.WNOHANG)
            if waited == 0:
                os.kill(guardian_pid, signal.SIGKILL)
                os.waitpid(guardian_pid, 0)
            elif _terminal_wait_status(status) is None:
                os.kill(guardian_pid, signal.SIGKILL)
                os.waitpid(guardian_pid, 0)
        except ChildProcessError:
            pass
        raise SupervisorError("launcher guardian pidfd setup failed") from exc
    try:
        waited, status = os.waitpid(guardian_pid, 0)
    except BaseException:
        try:
            _pidfd_send_signal(
                guardian_pidfd, signal.SIGKILL, label="launcher guardian"
            )
        except SupervisorError:
            pass
        try:
            os.waitpid(guardian_pid, 0)
        except ChildProcessError:
            pass
        raise
    finally:
        os.close(guardian_pidfd)
    if waited != guardian_pid:
        raise SupervisorError("launcher guardian wait identity is invalid")
    terminal = _terminal_wait_status(status)
    if terminal is None:
        raise SupervisorError("launcher guardian wait status is invalid")
    return _normalized_exit_code(terminal)


def main(argv: Iterable[str] | None = None) -> int:
    try:
        _require_system_python()
        arguments = _parser().parse_args(list(argv) if argv is not None else None)
        if arguments.action in {"launch", "recover", "trace-verifier-fragment"}:
            return _launch(arguments)
        if arguments.action in {
            "unit-wrapper",
            "recover-unit-wrapper",
            "trace-verifier-fragment-unit-wrapper",
        }:
            return _unit_wrapper(arguments)
        if arguments.action == "status":
            result = _status(arguments)
        else:
            root = RELEASE_PARENT / arguments.expected_release
            _await_worker_gate(arguments, root=root)
            if arguments.action == "recover-supervise-worker":
                result = _recover_supervise(arguments)
            elif arguments.action == "trace-verifier-fragment-supervise-worker":
                result = _trace_verifier_fragment_supervise(arguments)
            elif arguments.action == "supervise-worker":
                result = _supervise(arguments)
            else:  # pragma: no cover - argparse owns action validation
                raise SupervisorError("unknown internal worker action")
    except (OSError, SupervisorError, subprocess.SubprocessError) as exc:
        print(f"Dev29 read evidence refused: {exc}", file=sys.stderr)
        return 2
    print((canonical_json(result) + b"\n").decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

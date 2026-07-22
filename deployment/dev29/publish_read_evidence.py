#!/usr/bin/python3
"""Publish a Dev29 success anchor only after independent validation and cleanup."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import json
import os
import re
import signal
import stat
import struct
import subprocess
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux production dependency
    fcntl = None  # type: ignore[assignment]


sys.dont_write_bytecode = True
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
PRIVATE_EVIDENCE_PARENT = Path(
    "/var/lib/odoo-accounting-cli-v3/evidence-private"
)
ANCHOR_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence-anchors")
CLOSURE_PYTHON = "/usr/bin/python3.12"
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
LDCONFIG = Path("/usr/sbin/ldconfig.real")
STRACE = Path("/usr/bin/strace")
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_EXITKILL = 0x00100000
PR_SET_PDEATHSIG = 1
SIGKILL = getattr(signal, "SIGKILL", 9)
LD_SO_PRELOAD = Path("/etc/ld.so.preload")
RELEASE_PARENT = Path("/opt/odoo-accounting-cli-v3/releases")
TRACE_INDEX_PARENT = Path("/opt/odoo-accounting-cli-v3/runtime-open-manifests")
STAGING_PARENT = Path("/run/odoo-accounting-cli-v3-dev29")
LEASE_PARENT = Path("/run/odoo-accounting-cli-v3-dev29-leases")
RUNNER_RELATIVE = PurePosixPath("deployment/dev29/run_read_evidence.py")
PUBLISHER_RELATIVE = PurePosixPath("deployment/dev29/publish_read_evidence.py")
TRACE_RELATIVE = PurePosixPath("deployment/dev29/runtime_open_trace.py")
EXECUTABLE_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "bin/odoo-accounting-cli-v3-effect-finalizer",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)
TRACE_INDEX_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-index.v1"
TRACE_POLICY_SOURCE_SCOPE = (
    "odoo-accounting-cli-v3.dev29.runtime-open-policy-source.v1"
)
TRACE_MANIFEST_SCOPE = "direct-child-bootstrap-through-final-exec-v1"
TRACE_RECEIPTS_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-receipts.v1"
VERIFIER_SIDECAR_SUFFIX = ".verifier"
IN_REJECT_MASK = 28620
PUBLISHER_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
}
SYSTEMD_UNIT_FIELDS = (
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
MAX_BUNDLE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_RELEASE_FILES = 20_000
POSITIVE_NAMES = (
    "registry",
    "trial_balance",
    "ar_open_items",
    "ap_open_items",
    "multicurrency",
)
FINANCIAL_NAMES = (
    "trial_balance",
    "ar_open_items",
    "ap_open_items",
    "multicurrency",
)
NEGATIVE_NAMES = (
    "acl_deny",
    "cross_company",
    "mixed_company",
    "wrong_database_uuid",
    "expired",
    "tamper_parameters",
    "replay",
)


def expected_runtime_trace_targets() -> tuple[str, ...]:
    targets = ["release-identity", "witness-pre", "boundary-probe"]
    for name in POSITIVE_NAMES:
        targets.extend((f"positive-{name}-signer", f"positive-{name}-read"))
        if name in FINANCIAL_NAMES:
            targets.append(f"positive-{name}-oracle")
    for name in NEGATIVE_NAMES:
        if name != "replay":
            targets.append(f"negative-{name}-signer")
        targets.append(f"negative-{name}-read")
    targets.extend(("witness-post", "independent-verifier"))
    return tuple(targets)


def suite_runtime_trace_targets() -> tuple[str, ...]:
    return expected_runtime_trace_targets()[:-1]


class PublishError(RuntimeError):
    pass


def _verifier_private_sidecar_path(evidence: Path) -> Path:
    if SAFE_NAME.fullmatch(evidence.name) is None:
        raise PublishError("verifier sidecar evidence name is invalid")
    return PRIVATE_EVIDENCE_PARENT / f"{evidence.name}{VERIFIER_SIDECAR_SUFFIX}"


def _validate_publisher_process(expected_release: str) -> dict[str, Any]:
    expected_script = RELEASE_PARENT / expected_release
    expected_script = expected_script.joinpath(*PUBLISHER_RELATIVE.parts)
    argv_script = Path(sys.argv[0])
    match = re.fullmatch(r"/proc/self/fd/([0-9]+)", str(argv_script))
    if match is None or Path(__file__) != argv_script:
        raise PublishError("publisher was not loaded from its inherited fixed fd")
    publisher_fd = int(match.group(1))
    if publisher_fd <= 2:
        raise PublishError("publisher inherited fixed fd is invalid")
    status_fields: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text("ascii").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {
            "Uid",
            "Gid",
            "Groups",
            "CapInh",
            "CapPrm",
            "CapEff",
            "CapBnd",
            "CapAmb",
            "NoNewPrivs",
        }:
            status_fields[key] = value.strip()
    if (
        argv_script.resolve(strict=True) != expected_script.resolve(strict=True)
        or expected_script.is_symlink()
        or dict(os.environ) != PUBLISHER_ENVIRONMENT
        or os.getuid() != 0
        or os.getgid() != 0
        or os.getgroups() != []
        or status_fields
        != {
            "Uid": "0\t0\t0\t0",
            "Gid": "0\t0\t0\t0",
            "Groups": "",
            "CapInh": "0000000000000000",
            "CapPrm": "0000000000000000",
            "CapEff": "0000000000000000",
            "CapBnd": "0000000000000000",
            "CapAmb": "0000000000000000",
            "NoNewPrivs": "1",
        }
    ):
        raise PublishError("publisher process identity is invalid")
    descriptor_metadata = os.fstat(publisher_fd)
    path_metadata = expected_script.lstat()
    identity = (
        descriptor_metadata.st_dev,
        descriptor_metadata.st_ino,
        descriptor_metadata.st_nlink,
        descriptor_metadata.st_size,
        descriptor_metadata.st_mtime_ns,
        descriptor_metadata.st_ctime_ns,
        stat.S_IMODE(descriptor_metadata.st_mode),
        descriptor_metadata.st_uid,
        descriptor_metadata.st_gid,
    )
    if (
        not stat.S_ISREG(descriptor_metadata.st_mode)
        or descriptor_metadata.st_nlink != 1
        or (descriptor_metadata.st_uid, descriptor_metadata.st_gid) != (0, 0)
        or stat.S_IMODE(descriptor_metadata.st_mode) not in {0o400, 0o444}
        or identity
        != (
            path_metadata.st_dev,
            path_metadata.st_ino,
            path_metadata.st_nlink,
            path_metadata.st_size,
            path_metadata.st_mtime_ns,
            path_metadata.st_ctime_ns,
            stat.S_IMODE(path_metadata.st_mode),
            path_metadata.st_uid,
            path_metadata.st_gid,
        )
    ):
        raise PublishError("publisher inherited fixed fd identity drifted")
    digest = hashlib.sha256()
    offset = 0
    while offset < descriptor_metadata.st_size:
        chunk = os.pread(
            publisher_fd,
            min(1024 * 1024, descriptor_metadata.st_size - offset),
            offset,
        )
        if not chunk:
            raise PublishError("publisher inherited fixed fd changed during read")
        digest.update(chunk)
        offset += len(chunk)
    path_payload = stable_read(
        expected_script,
        label="sealed publisher release member",
        maximum=MAX_BUNDLE_MEMBER_BYTES,
        expected_uid=0,
        expected_gid=0,
        allowed_modes=frozenset({0o400, 0o444}),
    )
    if hashlib.sha256(path_payload).hexdigest() != digest.hexdigest():
        raise PublishError("publisher inherited fixed fd bytes drifted")
    os.close(publisher_fd)
    try:
        os.fstat(publisher_fd)
    except OSError as exc:
        if exc.errno != errno.EBADF:
            raise PublishError("publisher fixed fd close cannot be proved") from exc
    else:
        raise PublishError("publisher fixed fd remained open")
    return {
        "schema_version": 1,
        "method": "inherited-pinned-script-fd-v1",
        "path": str(expected_script),
        "sha256": digest.hexdigest(),
        "size": descriptor_metadata.st_size,
        "device": descriptor_metadata.st_dev,
        "inode": descriptor_metadata.st_ino,
        "argv_fixed_fd_verified": True,
        "fd_closed_before_children": True,
        "all_checks_passed": True,
    }


def _validate_publisher_script_execution(value: Any) -> None:
    if (
        type(value) is not dict
        or set(value)
        != {
            "schema_version",
            "method",
            "path",
            "sha256",
            "size",
            "device",
            "inode",
            "argv_fixed_fd_verified",
            "fd_closed_before_children",
            "all_checks_passed",
        }
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("method") != "inherited-pinned-script-fd-v1"
        or not isinstance(value.get("path"), str)
        or not isinstance(value.get("sha256"), str)
        or HEX64.fullmatch(value["sha256"]) is None
        or any(type(value.get(field)) is not int or value[field] <= 0 for field in ("size", "device", "inode"))
        or value.get("argv_fixed_fd_verified") is not True
        or value.get("fd_closed_before_children") is not True
        or value.get("all_checks_passed") is not True
    ):
        raise PublishError("publisher script execution proof is invalid")


def _ptrace_traceme() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(0, 0, None, None) != 0:
        os._exit(126)


def _ptrace_traceme_with_parent_death(expected_parent_pid: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0:
        os._exit(126)
    if os.getppid() != expected_parent_pid:
        os._exit(125)
    if library.ptrace(0, 0, None, None) != 0:
        os._exit(126)


def _ptrace_set_exitkill(pid: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(
        PTRACE_SETOPTIONS,
        pid,
        None,
        ctypes.c_void_p(PTRACE_O_EXITKILL),
    ) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _reject_systemctl_file_capabilities(descriptor: int) -> None:
    missing = {getattr(errno, "ENODATA", 61)}
    if hasattr(errno, "ENOATTR"):
        missing.add(errno.ENOATTR)
    try:
        os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in missing:
            return
        raise PublishError("publisher systemctl capabilities cannot be verified") from exc
    raise PublishError("publisher systemctl has file capabilities")


def _ptrace_detach(pid: int, signal_number: int = 0) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(17, pid, None, ctypes.c_void_p(signal_number)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _query_systemctl_properties(
    unit: str, *, expected_sha256: str
) -> tuple[dict[str, str], dict[str, Any]]:
    if os.name != "posix" or HEX64.fullmatch(expected_sha256) is None:
        raise PublishError("publisher systemctl digest is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(SYSTEMCTL, flags)
    process: subprocess.Popen[bytes] | None = None
    traced = False
    reaped = False
    exitkill_set = False
    exec_stop_verified = False
    detached_before_communicate = False
    try:
        metadata = os.fstat(descriptor)
        path_metadata = SYSTEMCTL.lstat()
        identity = (
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
        if (
            SYSTEMCTL.is_symlink()
            or SYSTEMCTL.resolve(strict=True) != SYSTEMCTL
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_BUNDLE_MEMBER_BYTES
            or identity[:2] != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise PublishError("publisher systemctl identity drifted")
        _reject_systemctl_file_capabilities(descriptor)
        payload = bytearray()
        while len(payload) < metadata.st_size:
            chunk = os.read(
                descriptor, min(1024 * 1024, metadata.st_size - len(payload))
            )
            if not chunk:
                raise PublishError("publisher systemctl changed during read")
            payload.extend(chunk)
        if (
            os.read(descriptor, 1)
            or identity
            != (
                (current := os.fstat(descriptor)).st_dev,
                current.st_ino,
                current.st_nlink,
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
                stat.S_IMODE(current.st_mode),
                current.st_uid,
                current.st_gid,
            )
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise PublishError("publisher systemctl identity drifted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        command = [
            str(SYSTEMCTL),
            "show",
            "--no-pager",
            *[f"--property={field}" for field in SYSTEMD_UNIT_FIELDS],
            unit,
        ]
        expected_parent_pid = os.getpid()
        process = subprocess.Popen(
            command,
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
            preexec_fn=lambda: _ptrace_traceme_with_parent_death(
                expected_parent_pid
            ),
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=PUBLISHER_ENVIRONMENT,
        )
        traced = True
        waited, status = os.waitpid(process.pid, os.WUNTRACED)
        if (
            waited != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            raise PublishError("publisher systemctl exec trace is invalid")
        _ptrace_set_exitkill(process.pid)
        exitkill_set = True
        executed = Path(f"/proc/{process.pid}/exe").stat()
        if (executed.st_dev, executed.st_ino) != identity[:2]:
            raise PublishError("publisher systemctl executed unpinned bytes")
        exec_stop_verified = True
        try:
            _ptrace_detach(process.pid)
        except BaseException:
            raise
        traced = False
        detached_before_communicate = True
        try:
            stdout, stderr = process.communicate(timeout=30)
            reaped = process.returncode is not None
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        current = os.fstat(descriptor)
        path_current = SYSTEMCTL.lstat()
        if identity != (
            current.st_dev,
            current.st_ino,
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
            stat.S_IMODE(current.st_mode),
            current.st_uid,
            current.st_gid,
        ) or identity[:2] != (path_current.st_dev, path_current.st_ino):
            raise PublishError("publisher systemctl changed across execution")
        if (
            process.returncode != 0
            or stderr
            or not stdout.endswith(b"\n")
            or len(stdout) > 1024 * 1024
        ):
            raise PublishError("publisher systemctl query failed")
        properties: dict[str, str] = {}
        try:
            for raw in stdout.decode("utf-8", "strict").splitlines():
                key, separator, item = raw.partition("=")
                if (
                    separator != "="
                    or key not in SYSTEMD_UNIT_FIELDS
                    or key in properties
                ):
                    raise PublishError("publisher systemctl output is invalid")
                properties[key] = item
        except UnicodeError as exc:
            raise PublishError("publisher systemctl output is invalid") from exc
        if set(properties) != set(SYSTEMD_UNIT_FIELDS):
            raise PublishError("publisher systemctl output is incomplete")
        return properties, {
            "method": "open-fd-ptrace-exec-v1",
            "file": {
                "path": str(SYSTEMCTL),
                "sha256": expected_sha256,
                "size": len(payload),
                "uid": 0,
                "gid": 0,
                "mode": "0755",
            },
            "pinned_device": identity[0],
            "pinned_inode": identity[1],
            "proc_exe_device": executed.st_dev,
            "proc_exe_inode": executed.st_ino,
            "ptrace_exitkill_set": exitkill_set,
            "ptrace_exec_stop_verified": exec_stop_verified,
            "ptrace_detached_before_communicate": detached_before_communicate,
            "parent_death_signal": "SIGKILL",
            "parent_identity_checked": True,
            "security_capability_absent": True,
            "child_reaped": reaped,
            "all_checks_passed": True,
        }
    except BaseException:
        if process is not None and process.returncode is None:
            try:
                if traced:
                    try:
                        _ptrace_detach(process.pid, signal.SIGKILL)
                    except OSError:
                        os.kill(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
        raise
    finally:
        os.close(descriptor)


def _validate_systemctl_execution(
    value: Any, *, systemctl: Mapping[str, Any]
) -> None:
    if (
        type(value) is not dict
        or set(value)
        != {
            "method",
            "file",
            "pinned_device",
            "pinned_inode",
            "proc_exe_device",
            "proc_exe_inode",
            "ptrace_exitkill_set",
            "ptrace_exec_stop_verified",
            "ptrace_detached_before_communicate",
            "parent_death_signal",
            "parent_identity_checked",
            "security_capability_absent",
            "child_reaped",
            "all_checks_passed",
        }
        or value.get("method") != "open-fd-ptrace-exec-v1"
        or value.get("file") != systemctl
        or type(value.get("pinned_device")) is not int
        or value["pinned_device"] <= 0
        or type(value.get("pinned_inode")) is not int
        or value["pinned_inode"] <= 0
        or value.get("proc_exe_device") != value["pinned_device"]
        or value.get("proc_exe_inode") != value["pinned_inode"]
        or value.get("ptrace_exitkill_set") is not True
        or value.get("ptrace_exec_stop_verified") is not True
        or value.get("ptrace_detached_before_communicate") is not True
        or value.get("parent_death_signal") != "SIGKILL"
        or value.get("parent_identity_checked") is not True
        or value.get("security_capability_absent") is not True
        or value.get("child_reaped") is not True
        or value.get("all_checks_passed") is not True
    ):
        raise PublishError("publisher systemctl execution proof is invalid")


def _proc_starttime(pid: int) -> int:
    if type(pid) is not int or pid <= 1:
        raise PublishError("publisher process PID is invalid")
    try:
        payload = Path(f"/proc/{pid}/stat").read_bytes()
    except OSError as exc:
        raise PublishError("publisher process identity is not live") from exc
    close = payload.rfind(b")")
    fields = payload[close + 2 :].strip().split() if close >= 2 else []
    if (
        len(payload) > 64 * 1024
        or not payload.endswith(b"\n")
        or payload[: payload.find(b" ")] != str(pid).encode("ascii")
        or len(fields) < 20
        or not fields[19].isdigit()
    ):
        raise PublishError("publisher process stat identity is invalid")
    return int(fields[19])


def _read_proc_argv(pid: int) -> list[str]:
    try:
        payload = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as exc:
        raise PublishError("publisher process argv is unavailable") from exc
    if not payload or len(payload) > 1024 * 1024 or not payload.endswith(b"\0"):
        raise PublishError("publisher process argv is invalid")
    try:
        result = [item.decode("utf-8", "strict") for item in payload[:-1].split(b"\0")]
    except UnicodeError as exc:
        raise PublishError("publisher process argv is invalid") from exc
    if not result or any(not item for item in result):
        raise PublishError("publisher process argv is invalid")
    return result


def _process_fd_matches(pid: int, *, device: int, inode: int) -> list[int]:
    try:
        names = os.listdir(f"/proc/{pid}/fd")
    except OSError as exc:
        raise PublishError("publisher process descriptor table is unavailable") from exc
    matches: list[int] = []
    for name in names:
        if not name.isdigit():
            raise PublishError("publisher process descriptor table is invalid")
        try:
            metadata = os.stat(f"/proc/{pid}/fd/{name}")
        except FileNotFoundError:
            continue
        if (metadata.st_dev, metadata.st_ino) == (device, inode):
            matches.append(int(name))
    return sorted(matches)


def _process_has_pidfd_for(owner_pid: int, target_pid: int) -> bool:
    try:
        names = os.listdir(f"/proc/{owner_pid}/fdinfo")
    except OSError as exc:
        raise PublishError("publisher pidfd table is unavailable") from exc
    marker = f"Pid:\t{target_pid}\n".encode("ascii")
    matches = 0
    for name in names:
        if not name.isdigit():
            raise PublishError("publisher pidfd table is invalid")
        try:
            payload = Path(f"/proc/{owner_pid}/fdinfo/{name}").read_bytes()
        except FileNotFoundError:
            continue
        if len(payload) > 64 * 1024:
            raise PublishError("publisher pidfd record is invalid")
        if marker in payload:
            matches += 1
    return matches == 1


def _single_process_child(parent_pid: int) -> int:
    try:
        value = Path(
            f"/proc/{parent_pid}/task/{parent_pid}/children"
        ).read_text("ascii")
    except OSError as exc:
        raise PublishError("publisher process child identity is unavailable") from exc
    fields = value.split()
    if len(fields) != 1 or not fields[0].isdigit() or int(fields[0]) <= 1:
        raise PublishError("publisher process child identity is invalid")
    return int(fields[0])


def _parent_death_signal() -> int:
    library = ctypes.CDLL(None, use_errno=True)
    value = ctypes.c_int()
    if library.prctl(2, ctypes.byref(value), 0, 0, 0) != 0:
        raise PublishError("publisher parent-death signal cannot be read")
    return value.value


def _validate_proc_document(value: Any, *, pid: int, cgroup: str) -> None:
    if (
        type(value) is not dict
        or set(value) != {"argv", "argv_sha256", "cgroup"}
        or not isinstance(value.get("argv"), list)
        or not value["argv"]
        or any(not isinstance(item, str) or not item for item in value["argv"])
        or value.get("argv_sha256")
        != hashlib.sha256(canonical_json(value["argv"])).hexdigest()
        or value.get("cgroup") != cgroup
        or pid <= 1
    ):
        raise PublishError("publisher outer unit process proof is invalid")


def _validate_live_launcher_lease(value: Any, *, unit: str, wrapper_pid: int) -> None:
    if fcntl is None or type(value) is not dict:
        raise PublishError("publisher launcher lease proof is invalid")
    required = {
        "identity",
        "launcher",
        "guardian",
        "systemd_run",
        "launcher_process_identity_verified",
        "launcher_lock_verified_live",
        "systemd_run_lease_fd_inherited",
        "worker_lease_fd_inherited",
        "wrapper_monitor_fd_count",
        "read_only_bind",
        "all_checks_passed",
    }
    identity = value.get("identity")
    if (
        set(value) != required
        or type(identity) is not dict
        or set(identity)
        != {
            "schema_version",
            "evidence_name",
            "unit",
            "path",
            "nonce",
            "launcher_pid",
            "launcher_starttime",
            "guardian_pid",
            "guardian_starttime",
            "launcher_argv_sha256",
            "guardian_argv_sha256",
            "device",
            "inode",
            "nlink",
            "mode",
        }
        or not _schema_version_is_one(identity.get("schema_version"))
        or identity.get("unit") != unit
        or not isinstance(identity.get("evidence_name"), str)
        or SAFE_NAME.fullmatch(identity["evidence_name"]) is None
        or identity.get("path")
        != str(LEASE_PARENT / f"{identity['evidence_name']}.lease")
        or not isinstance(identity.get("nonce"), str)
        or HEX64.fullmatch(identity["nonce"]) is None
        or identity.get("nlink") != 1
        or identity.get("mode") != "0400"
        or any(
            type(identity.get(field)) is not int or identity[field] <= 1
            for field in (
                "launcher_pid",
                "launcher_starttime",
                "guardian_pid",
                "guardian_starttime",
                "device",
                "inode",
            )
        )
        or any(
            not isinstance(identity.get(field), str)
            or HEX64.fullmatch(identity[field]) is None
            for field in ("launcher_argv_sha256", "guardian_argv_sha256")
        )
        or value.get("launcher_process_identity_verified") is not True
        or value.get("launcher_lock_verified_live") is not True
        or value.get("systemd_run_lease_fd_inherited") is not False
        or value.get("worker_lease_fd_inherited") is not False
        or value.get("wrapper_monitor_fd_count") != 1
        or value.get("read_only_bind") != str(LEASE_PARENT)
        or value.get("all_checks_passed") is not True
    ):
        raise PublishError("publisher launcher lease proof is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(identity["path"], flags)
    try:
        metadata = os.fstat(descriptor)
        payload = bytearray()
        while len(payload) <= 16 * 1024:
            chunk = os.read(descriptor, 16 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
        try:
            document = json.loads(bytes(payload), object_pairs_hook=_pairs)
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise PublishError("publisher launcher lease payload is invalid") from exc
        if (
            len(payload) > 16 * 1024
            or document != identity
            or canonical_json(document) + b"\n" != bytes(payload)
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or (metadata.st_dev, metadata.st_ino, metadata.st_nlink)
            != (identity["device"], identity["inode"], 1)
        ):
            raise PublishError("publisher launcher lease identity drifted")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, PermissionError):
            pass
        else:
            raise PublishError("publisher launcher lease has no live owner")
    finally:
        os.close(descriptor)
    launcher = value["launcher"]
    guardian = value["guardian"]
    systemd_run = value["systemd_run"]
    launcher_pid = identity["launcher_pid"]
    guardian_pid = identity["guardian_pid"]
    systemd_pid = systemd_run.get("pid") if type(systemd_run) is dict else None
    if (
        type(launcher) is not dict
        or set(launcher) != {"pid", "starttime", "argv", "argv_sha256"}
        or type(guardian) is not dict
        or set(guardian)
        != {"pid", "starttime", "argv", "argv_sha256", "parent_death_signal"}
        or type(systemd_run) is not dict
        or set(systemd_run)
        != {
            "pid",
            "starttime",
            "argv",
            "argv_sha256",
            "file",
            "parent_death_signal",
            "pidfd_owned_by_guardian",
        }
        or launcher.get("pid") != launcher_pid
        or launcher.get("starttime") != identity["launcher_starttime"]
        or guardian.get("pid") != guardian_pid
        or guardian.get("starttime") != identity["guardian_starttime"]
        or guardian.get("parent_death_signal") != "SIGKILL"
        or type(systemd_pid) is not int
        or systemd_pid <= 1
        or systemd_run.get("parent_death_signal") != "SIGKILL"
        or systemd_run.get("pidfd_owned_by_guardian") is not True
        or _proc_starttime(launcher_pid) != launcher["starttime"]
        or _proc_starttime(guardian_pid) != guardian["starttime"]
        or _proc_starttime(systemd_pid) != systemd_run.get("starttime")
        or _read_proc_argv(launcher_pid) != launcher.get("argv")
        or _read_proc_argv(guardian_pid) != guardian.get("argv")
        or _read_proc_argv(systemd_pid) != systemd_run.get("argv")
        or launcher.get("argv_sha256")
        != hashlib.sha256(canonical_json(launcher.get("argv"))).hexdigest()
        or guardian.get("argv_sha256")
        != hashlib.sha256(canonical_json(guardian.get("argv"))).hexdigest()
        or systemd_run.get("argv_sha256")
        != hashlib.sha256(canonical_json(systemd_run.get("argv"))).hexdigest()
        or launcher["argv_sha256"] != identity["launcher_argv_sha256"]
        or guardian["argv_sha256"] != identity["guardian_argv_sha256"]
        or _single_process_child(launcher_pid) != guardian_pid
        or _single_process_child(guardian_pid) != systemd_pid
        or not _process_has_pidfd_for(guardian_pid, systemd_pid)
        or len(
            _process_fd_matches(
                wrapper_pid, device=identity["device"], inode=identity["inode"]
            )
        )
        != 1
        or _process_fd_matches(os.getpid(), device=identity["device"], inode=identity["inode"])
    ):
        raise PublishError("publisher live launcher topology drifted")
    file_identity = systemd_run["file"]
    if (
        type(file_identity) is not dict
        or file_identity.get("path") != str(SYSTEMD_RUN)
        or file_identity.get("sha256") is None
        or HEX64.fullmatch(file_identity["sha256"]) is None
    ):
        raise PublishError("publisher systemd-run file proof is invalid")
    executed = Path(f"/proc/{systemd_pid}/exe").stat()
    live = SYSTEMD_RUN.stat()
    if (executed.st_dev, executed.st_ino) != (live.st_dev, live.st_ino):
        raise PublishError("publisher live systemd-run executable drifted")


def _reverify_outer_unit(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "unit",
        "supervisor_pid",
        "wrapper_pid",
        "worker_pid",
        "systemctl",
        "systemctl_execution",
        "properties",
        "proc",
        "wrapper",
        "worker",
        "launcher_lease",
        "expected_environment",
        "read_write_paths",
        "read_only_paths",
        "capability_bounding_set",
        "all_checks_passed",
    }:
        raise PublishError("publisher outer unit schema is invalid")
    unit = value.get("unit")
    systemctl = value.get("systemctl")
    properties = value.get("properties")
    wrapper_pid = value.get("wrapper_pid")
    worker_pid = value.get("worker_pid")
    wrapper = value.get("wrapper")
    worker = value.get("worker")
    if (
        not _schema_version_is_one(value.get("schema_version"))
        or value.get("supervisor_pid") != os.getpid()
        or worker_pid != os.getpid()
        or type(wrapper_pid) is not int
        or wrapper_pid <= 1
        or os.getppid() != wrapper_pid
        or not isinstance(unit, str)
        or re.fullmatch(r"odoo-accounting-cli-v3-dev29-[A-Za-z0-9._-]+\.service", unit)
        is None
        or type(systemctl) is not dict
        or set(systemctl) != {"path", "sha256", "size", "uid", "gid", "mode"}
        or systemctl.get("path") != str(SYSTEMCTL)
        or systemctl.get("uid") != 0
        or systemctl.get("gid") != 0
        or systemctl.get("mode") != "0755"
        or type(systemctl.get("size")) is not int
        or systemctl["size"] <= 0
        or not isinstance(systemctl.get("sha256"), str)
        or HEX64.fullmatch(systemctl["sha256"]) is None
        or type(properties) is not dict
        or set(properties) != set(SYSTEMD_UNIT_FIELDS)
        or properties.get("MainPID") != str(wrapper_pid)
        or properties.get("ReadOnlyPaths") != str(LEASE_PARENT)
        or value.get("read_only_paths") != [str(LEASE_PARENT)]
        or type(wrapper) is not dict
        or set(wrapper)
        != {
            "pid",
            "starttime",
            "argv",
            "argv_sha256",
            "cgroup",
            "main_pid",
            "lease_monitor_fds",
            "worker_pidfd_verified",
        }
        or wrapper.get("pid") != wrapper_pid
        or wrapper.get("main_pid") is not True
        or wrapper.get("worker_pidfd_verified") is not True
        or type(worker) is not dict
        or set(worker)
        != {
            "pid",
            "starttime",
            "parent_pid",
            "argv",
            "argv_sha256",
            "cgroup",
            "parent_death_signal",
            "launcher_lease_fd_inherited",
            "bootstrap",
        }
        or worker.get("pid") != worker_pid
        or worker.get("parent_pid") != wrapper_pid
        or worker.get("parent_death_signal") != "SIGKILL"
        or worker.get("launcher_lease_fd_inherited") is not False
        or value.get("all_checks_passed") is not True
    ):
        raise PublishError("publisher outer unit proof is invalid")
    _validate_systemctl_execution(value["systemctl_execution"], systemctl=systemctl)
    cgroup = properties["ControlGroup"]
    _validate_proc_document(value["proc"], pid=worker_pid, cgroup=cgroup)
    if (
        wrapper.get("argv_sha256")
        != hashlib.sha256(canonical_json(wrapper.get("argv"))).hexdigest()
        or wrapper.get("cgroup") != cgroup
        or wrapper.get("starttime") != _proc_starttime(wrapper_pid)
        or wrapper.get("argv") != _read_proc_argv(wrapper_pid)
        or worker.get("argv") != value["proc"]["argv"]
        or worker.get("argv_sha256") != value["proc"]["argv_sha256"]
        or worker.get("cgroup") != cgroup
        or worker.get("starttime") != _proc_starttime(worker_pid)
        or _parent_death_signal() != SIGKILL
        or not _process_has_pidfd_for(wrapper_pid, worker_pid)
    ):
        raise PublishError("publisher live outer worker topology drifted")
    _validate_live_launcher_lease(
        value["launcher_lease"], unit=unit, wrapper_pid=wrapper_pid
    )
    live_properties, execution = _query_systemctl_properties(
        unit, expected_sha256=systemctl["sha256"]
    )
    _validate_systemctl_execution(execution, systemctl=systemctl)
    if live_properties != properties:
        raise PublishError("publisher live outer unit properties drifted")
    return {
        "unit": unit,
        "systemctl": dict(systemctl),
        "properties": dict(properties),
        "properties_sha256": hashlib.sha256(canonical_json(properties)).hexdigest(),
        "proc": dict(value["proc"]),
        "wrapper": dict(wrapper),
        "worker": dict(worker),
        "launcher_lease": dict(value["launcher_lease"]),
        "outer_unit": dict(value),
        "outer_unit_sha256": hashlib.sha256(canonical_json(value)).hexdigest(),
        "systemctl_execution": execution,
        "all_checks_passed": True,
    }


def _reverify_recovery_outer_unit(
    original: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    live_cgroup: Mapping[str, Any],
) -> dict[str, Any]:
    unit = original.get("unit")
    systemctl = original.get("systemctl")
    original_properties = original.get("properties")
    if (
        type(original) is not dict
        or type(current) is not dict
        or not isinstance(unit, str)
        or type(systemctl) is not dict
        or set(systemctl) != {"path", "sha256", "size", "uid", "gid", "mode"}
        or systemctl.get("path") != str(SYSTEMCTL)
        or not isinstance(systemctl.get("sha256"), str)
        or HEX64.fullmatch(systemctl["sha256"]) is None
        or type(original_properties) is not dict
        or set(original_properties) != set(SYSTEMD_UNIT_FIELDS)
    ):
        raise PublishError("recovery outer unit source proof is invalid")
    verified = _reverify_outer_unit(current)
    live_properties = verified["properties"]
    dynamic = {"MainPID", "ControlGroup", "InvocationID", "ExecStart"}
    if (
        set(live_properties) != set(SYSTEMD_UNIT_FIELDS)
        or any(
            live_properties[field] != original_properties[field]
            for field in SYSTEMD_UNIT_FIELDS
            if field not in dynamic
        )
        or current.get("unit") != unit
        or current.get("systemctl") != systemctl
        or live_properties.get("MainPID") != str(os.getppid())
        or live_properties.get("ControlGroup") != live_cgroup.get("relative_path")
        or re.fullmatch(r"[0-9a-f]{32}", live_properties.get("InvocationID", ""))
        is None
        or "deployment/dev29/run_read_evidence.py"
        not in live_properties.get("ExecStart", "")
        or "recover-unit-wrapper" not in live_properties.get("ExecStart", "")
    ):
        raise PublishError("recovery live outer unit properties drifted")
    raw_argv = Path("/proc/self/cmdline").read_bytes()
    if not raw_argv or len(raw_argv) > 1024 * 1024 or raw_argv[-1:] != b"\0":
        raise PublishError("recovery publisher argv is invalid")
    try:
        argv = [item.decode("utf-8", "strict") for item in raw_argv[:-1].split(b"\0")]
    except UnicodeError as exc:
        raise PublishError("recovery publisher argv is invalid") from exc
    if not argv or any(not item for item in argv):
        raise PublishError("recovery publisher argv is invalid")
    proc = {
        "argv": argv,
        "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
        "cgroup": live_cgroup["relative_path"],
    }
    verified["proc"] = proc
    return verified


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PublishError(f"duplicate JSON key: {key}")
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
        raise PublishError("publisher value is not canonical JSON") from exc


def _schema_version_is_one(value: Any) -> bool:
    return type(value) is int and value == 1


def _expected_release_member_mode(name: str) -> int:
    return 0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444


def parse_json(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PublishError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublishError(f"{label} is invalid JSON") from exc
    if type(value) is not dict or payload != canonical_json(value) + b"\n":
        raise PublishError(f"{label} is not canonical JSON")
    return value


def _parse_release_manifest_json(payload: bytes) -> dict[str, Any]:
    """Parse the build artifact manifest without imposing JSON whitespace."""

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PublishError(f"non-finite JSON number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublishError("publisher exact release manifest is invalid JSON") from exc
    if type(value) is not dict:
        raise PublishError("publisher exact release manifest is not a JSON object")
    return value


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def stable_read(
    path: Path,
    *,
    label: str,
    maximum: int = 64 * 1024 * 1024,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    allowed_modes: frozenset[int] | None = None,
    allow_empty: bool = False,
) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PublishError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < (0 if allow_empty else 1)
            or before.st_size > maximum
            or (expected_uid is not None and before.st_uid != expected_uid)
            or (expected_gid is not None and before.st_gid != expected_gid)
            or (
                allowed_modes is not None
                and stat.S_IMODE(before.st_mode) not in allowed_modes
            )
        ):
            raise PublishError(f"{label} metadata is invalid")
        identity = _stat_fingerprint(before)
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(payload)))
            if not chunk:
                raise PublishError(f"{label} changed during read")
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if os.read(descriptor, 1) or identity != _stat_fingerprint(after):
            raise PublishError(f"{label} changed during read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _safe_root_chain(path: Path, *, final_mode: int) -> None:
    current = Path("/")
    for component in Path(path).absolute().parts[1:]:
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
            raise PublishError(f"unsafe root-owned path: {current}")
    if stat.S_IMODE(path.lstat().st_mode) != final_mode:
        raise PublishError(f"directory mode is invalid: {path}")


def _sealed_directory_identity(
    path: Path,
    *,
    label: str,
    expected_mode: int,
    enforce_root: bool,
    expected_names: set[str] | None = None,
) -> tuple[tuple[int, ...], tuple[str, ...]]:
    try:
        if enforce_root:
            _safe_root_chain(path, final_mode=expected_mode)
        before = path.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or (
                enforce_root
                and (
                    (before.st_uid, before.st_gid) != (0, 0)
                    or stat.S_IMODE(before.st_mode) != expected_mode
                )
            )
        ):
            raise PublishError(f"{label} metadata is invalid")
        with os.scandir(path) as entries:
            names = tuple(sorted(entry.name for entry in entries))
        after = path.lstat()
        if enforce_root:
            _safe_root_chain(path, final_mode=expected_mode)
    except PublishError:
        raise
    except OSError as exc:
        raise PublishError(f"{label} cannot be inventoried safely") from exc
    identity = _stat_fingerprint(before)
    if identity != _stat_fingerprint(after):
        raise PublishError(f"{label} changed during inventory")
    if expected_names is not None and (
        len(names) != len(expected_names) or set(names) != expected_names
    ):
        raise PublishError(f"{label} file set is not exact")
    return identity, names


def _sealed_release_tree_identity(
    root: Path, *, enforce_root: bool
) -> tuple[
    tuple[tuple[str, tuple[int, ...]], ...],
    tuple[tuple[str, tuple[int, ...]], ...],
]:
    directories: dict[str, tuple[int, ...]] = {}
    files: dict[str, tuple[int, ...]] = {}
    pending: list[tuple[Path, str]] = [(root, "")]
    entries_seen = 0
    while pending:
        directory, prefix = pending.pop()
        before = _sealed_directory_identity(
            directory,
            label="publisher sealed release directory",
            expected_mode=0o555,
            enforce_root=enforce_root,
        )
        directories[prefix] = before[0]
        for name in before[1]:
            entries_seen += 1
            if entries_seen > MAX_RELEASE_FILES:
                raise PublishError("publisher sealed release tree is too large")
            relative = f"{prefix}/{name}" if prefix else name
            path = directory / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise PublishError(
                    "publisher sealed release member cannot be inspected"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise PublishError("publisher sealed release symlink is forbidden")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((path, relative))
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or (
                    enforce_root
                    and (
                        (metadata.st_uid, metadata.st_gid) != (0, 0)
                        or stat.S_IMODE(metadata.st_mode)
                        != _expected_release_member_mode(relative)
                    )
                )
            ):
                raise PublishError("publisher sealed release member is unsafe")
            files[relative] = _stat_fingerprint(metadata)
        if (
            _sealed_directory_identity(
                directory,
                label="publisher sealed release directory",
                expected_mode=0o555,
                enforce_root=enforce_root,
            )
            != before
        ):
            raise PublishError("publisher sealed release directory changed")
    return tuple(sorted(directories.items())), tuple(sorted(files.items()))


def _namespace(process: str) -> dict[str, int]:
    metadata = Path(f"/proc/{process}/ns/mnt").stat()
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


def _mount_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _prove_cleanup_live(
    cleanup: Mapping[str, Any], *, closure: Mapping[str, Any]
) -> None:
    import fcntl

    if type(cleanup) is not dict or set(cleanup) != {
        "schema_version",
        "status",
        "unmount_order",
        "self_mount_namespace",
        "host_mount_namespace",
        "remaining_self_mounts",
        "remaining_host_mounts",
        "remaining_loop_devices",
        "loop_autoclear_required",
    }:
        raise PublishError("closure cleanup receipt schema is invalid")
    mount = closure.get("mount") if type(closure) is dict else None
    systemd = closure.get("systemd") if type(closure) is dict else None
    binds = systemd.get("bind_read_only_paths") if type(systemd) is dict else None
    mount_point = mount.get("mount_point") if type(mount) is dict else None
    if (
        type(binds) is not list
        or len(binds) != 4
        or not isinstance(mount_point, str)
        or not PurePosixPath(mount_point).is_absolute()
        or str(PurePosixPath(mount_point)) != mount_point
        or any(
            type(item) is not dict
            or set(item) != {"source", "destination"}
            or not isinstance(item.get("destination"), str)
            or not PurePosixPath(item["destination"]).is_absolute()
            or str(PurePosixPath(item["destination"])) != item["destination"]
            for item in binds
        )
    ):
        raise PublishError("closure cleanup binding identity is invalid")
    expected_unmount = [
        *[item["destination"] for item in reversed(binds)],
        mount_point,
    ]
    if (
        not _schema_version_is_one(cleanup.get("schema_version"))
        or cleanup.get("status") != "clean"
        or cleanup.get("unmount_order") != expected_unmount
        or cleanup.get("self_mount_namespace") != _namespace("self")
        or cleanup.get("host_mount_namespace") != _namespace("1")
        or cleanup["self_mount_namespace"] == cleanup["host_mount_namespace"]
        or cleanup.get("remaining_self_mounts") != []
        or cleanup.get("remaining_host_mounts") != []
        or cleanup.get("remaining_loop_devices") != []
        or cleanup.get("loop_autoclear_required") is not True
    ):
        raise PublishError("closure cleanup receipt is invalid")
    affected = [PurePosixPath(item) for item in expected_unmount]
    for process in ("self", "1"):
        payload = Path(f"/proc/{process}/mountinfo").read_bytes()
        if not payload.endswith(b"\n"):
            raise PublishError("post-cleanup mountinfo is truncated")
        for raw in payload.splitlines():
            fields = raw.decode("ascii", "strict").split(" ")
            if len(fields) < 6:
                raise PublishError("post-cleanup mountinfo is invalid")
            observed = PurePosixPath(_mount_unescape(fields[4]))
            if any(observed == target or target in observed.parents for target in affected):
                raise PublishError("closure mount remains after cleanup")
    expected_backing_device = mount.get("loop_backing_device")
    expected_backing_inode = mount.get("loop_backing_inode")
    recorded_loop = mount.get("loop_device")
    if (
        type(expected_backing_device) is not int
        or expected_backing_device < 0
        or type(expected_backing_inode) is not int
        or expected_backing_inode <= 0
        or not isinstance(recorded_loop, str)
        or re.fullmatch(r"/dev/loop[0-9]+", recorded_loop) is None
    ):
        raise PublishError("closure loop backing identity is invalid")
    candidates = {
        Path(recorded_loop),
        *{
            item
            for item in Path("/dev").glob("loop*")
            if re.fullmatch(r"loop[0-9]+", item.name)
        },
    }
    for candidate in sorted(candidates):
        try:
            descriptor = os.open(
                candidate,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
        except FileNotFoundError:
            if str(candidate) == recorded_loop:
                continue
            continue
        except OSError as exc:
            raise PublishError("loop device cannot be inspected after cleanup") from exc
        try:
            buffer = bytearray(232)
            try:
                fcntl.ioctl(descriptor, 0x4C05, buffer, True)
            except OSError as exc:
                if exc.errno == errno.ENXIO:
                    continue
                raise PublishError(
                    "loop device status cannot be inspected after cleanup"
                ) from exc
            backing_device, backing_inode = struct.unpack_from("@QQ", buffer, 0)
            if (
                backing_device == expected_backing_device
                and backing_inode == expected_backing_inode
            ):
                raise PublishError("closure loop backing remains after cleanup")
        finally:
            os.close(descriptor)


def _prove_supervisor_cgroup() -> dict[str, Any]:
    rows = Path("/proc/self/cgroup").read_text("ascii").splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::") or rows[0][3:] == "/":
        raise PublishError("publisher requires a dedicated cgroup v2 unit")
    relative = rows[0][3:]
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    directory = root.joinpath(*PurePosixPath(relative).parts[1:]).resolve(strict=True)
    if root not in directory.parents:
        raise PublishError("publisher cgroup escaped cgroupfs")
    child_directories: list[Path] = []
    for directory_text, names, _files in os.walk(directory, topdown=True, followlinks=False):
        current = Path(directory_text)
        child_directories.extend(current / name for name in names)
    processes = sorted(
        int(item)
        for item in (directory / "cgroup.procs").read_text("ascii").splitlines()
        if item
    )
    if child_directories or processes != [os.getpid()]:
        raise PublishError("publisher cgroup contains a surviving child")
    metadata = directory.stat()
    return {
        "version": 2,
        "relative_path": relative,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "sole_process": os.getpid(),
        "descendant_cgroups": 0,
        "descendant_processes": 0,
    }


def _expected_verifier_command(
    evidence: Path,
    report: Mapping[str, Any],
    expected_bundle_manifest_sha256: str,
    release_identity: Mapping[str, Any],
    expected_ldconfig_sha256: str,
    expected_runtime_open_index_sha256: str,
    expected_strace_sha256: str,
) -> list[str]:
    closure = report["closure_identity"]
    release_root = Path("/opt/odoo-accounting-cli-v3/releases") / release_identity["release"]
    return [
        CLOSURE_PYTHON,
        "-I",
        "-S",
        str(release_root / "deployment" / "dev29" / "verify_read_evidence.py"),
        "--validate-only",
        "--evidence-dir",
        str(evidence),
        "--expected-bundle-manifest-sha256",
        expected_bundle_manifest_sha256,
        "--expected-release",
        release_identity["release"],
        "--expected-version",
        release_identity["version"],
        "--expected-commit",
        release_identity["commit"],
        "--expected-manifest-sha256",
        release_identity["manifest_sha256"],
        "--expected-package-sha256",
        release_identity["package_sha256"],
        "--expected-closure-anchor-sha256",
        closure["anchor_sha256"],
        "--expected-closure-image-sha256",
        closure["image_sha256"],
        "--expected-system-python-sha256",
        closure["system_python_sha256"],
        "--expected-ld-so-preload-sha256",
        closure["loader_preload_sha256"],
        "--expected-ldconfig-sha256",
        expected_ldconfig_sha256,
        "--expected-runtime-open-index-sha256",
        expected_runtime_open_index_sha256,
        "--expected-strace-sha256",
        expected_strace_sha256,
    ]


def _validate_verifier_child(
    value: Mapping[str, Any],
    *,
    evidence: Path,
    report: Mapping[str, Any],
    expected_bundle_manifest_sha256: str,
    release_identity: Mapping[str, Any],
    expected_ldconfig_sha256: str,
    expected_runtime_open_index_sha256: str,
    expected_strace_sha256: str,
) -> None:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "role",
        "pid",
        "ppid",
        "command",
        "command_sha256",
        "python",
        "credentials",
        "self_mount_namespace",
        "host_mount_namespace",
        "same_supervisor_namespace",
        "mounts",
        "loop_device",
        "environment",
        "click",
    }:
        raise PublishError("verifier child schema is invalid")
    closure = report["closure_verification"]
    command = _expected_verifier_command(
        evidence,
        report,
        expected_bundle_manifest_sha256,
        release_identity,
        expected_ldconfig_sha256,
        expected_runtime_open_index_sha256,
        expected_strace_sha256,
    )
    expected_environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    expected_status = {
        "Uid": "0 0 0 0",
        "Gid": "0 0 0 0",
        "Groups": "",
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
    }
    if (
        not _schema_version_is_one(value.get("schema_version"))
        or value.get("role") != "verifier"
        or type(value.get("pid")) is not int
        or value["pid"] <= 1
        or value.get("ppid") != os.getpid()
        or value.get("command") != command
        or value.get("command_sha256")
        != hashlib.sha256(canonical_json(command)).hexdigest()
        or value.get("python")
        != {
            "path": CLOSURE_PYTHON,
            "resolved_path": CLOSURE_PYTHON,
            "isolated": True,
            "no_site": True,
            "sys_path": value.get("python", {}).get("sys_path"),
        }
        or type(value.get("python", {}).get("sys_path")) is not list
        or not value["python"]["sys_path"]
        or value.get("credentials")
        != {
            "uid": 0,
            "gid": 0,
            "groups": [],
            "status": expected_status,
            "capabilities_all_zero": True,
            "no_new_privileges": True,
        }
        or value.get("self_mount_namespace")
        != closure["mount"]["self_mount_namespace"]
        or value.get("host_mount_namespace")
        != closure["mount"]["host_mount_namespace"]
        or value.get("same_supervisor_namespace") is not True
        or value.get("loop_device") != closure["mount"]["loop_device"]
        or value.get("environment") != expected_environment
        or value.get("click") is not None
    ):
        raise PublishError("verifier child proof is invalid")
    for path_text in value["python"]["sys_path"]:
        portable = PurePosixPath(path_text) if isinstance(path_text, str) else None
        if (
            portable is None
            or not portable.is_absolute()
            or str(portable) != path_text
            or any(part in {".", ".."} for part in portable.parts)
            or not (
                path_text == "/usr/lib/python312.zip"
                or path_text == "/usr/lib/python3.12"
                or path_text.startswith("/usr/lib/python3.12/")
            )
        ):
            raise PublishError("verifier Python path is invalid")
    mounts = value.get("mounts")
    bindings = closure["activation"]["bindings"]
    if type(mounts) is not list or len(mounts) != 5:
        raise PublishError("verifier mount proof is invalid")
    expected_endpoints = [
        (
            closure["mount"]["mount_point"],
            closure["mount"]["mount_point"],
            None,
        ),
        *((item["source"], item["destination"], item) for item in bindings),
    ]
    mount_fields = {
        "source_path",
        "destination_path",
        "source_device",
        "source_inode",
        "destination_device",
        "destination_inode",
        "mount_id",
        "parent_mount_id",
        "major_minor",
        "root",
        "mount_point",
        "options",
        "filesystem_type",
        "mount_source",
        "super_options",
        "statvfs_read_only",
    }
    for index, (mount, endpoint) in enumerate(zip(mounts, expected_endpoints, strict=True)):
        source, destination, binding = endpoint
        if (
            type(mount) is not dict
            or set(mount) != mount_fields
            or mount.get("source_path") != source
            or mount.get("destination_path") != destination
            or mount.get("mount_point") != destination
            or type(mount.get("source_device")) is not int
            or type(mount.get("source_inode")) is not int
            or mount.get("destination_device") != mount.get("source_device")
            or mount.get("destination_inode") != mount.get("source_inode")
            or type(mount.get("mount_id")) is not int
            or mount["mount_id"] <= 0
            or type(mount.get("parent_mount_id")) is not int
            or mount["parent_mount_id"] <= 0
            or not isinstance(mount.get("root"), str)
            or not PurePosixPath(mount["root"]).is_absolute()
            or str(PurePosixPath(mount["root"])) != mount["root"]
            or type(mount.get("options")) is not list
            or mount["options"] != sorted(set(mount["options"]))
            or not {"ro", "nodev", "nosuid"}.issubset(mount["options"])
            or type(mount.get("super_options")) is not list
            or mount["super_options"] != sorted(set(mount["super_options"]))
            or mount.get("statvfs_read_only") is not True
        ):
            raise PublishError("verifier mount endpoint proof is invalid")
        if index == 0:
            if (
                mount.get("filesystem_type") != "squashfs"
                or mount.get("mount_source") != closure["mount"]["loop_device"]
                or mount.get("root") != "/"
            ):
                raise PublishError("verifier closure root mount proof is invalid")
        elif any(
            mount.get(field) != binding[field]
            for field in (
                "mount_id",
                "major_minor",
                "filesystem_type",
                "source_device",
                "source_inode",
            )
        ):
            raise PublishError("verifier bind mount proof is invalid")


def _validate_verifier_process_control(
    value: Mapping[str, Any], *, live_cgroup: Mapping[str, Any]
) -> None:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "execution_model",
        "nested_systemd_run_used",
        "new_process_group",
        "parent_death_signal",
        "timeout_kills_process_group",
        "timeout_observed",
        "leader_waited_and_reaped",
        "unit_cgroup",
    }:
        raise PublishError("verifier process-control schema is invalid")
    cgroup = value.get("unit_cgroup")
    fields = {
        "version",
        "relative_path",
        "device",
        "inode",
        "subtree_directory_count",
        "subtree_identity_sha256",
        "baseline_process_count",
        "baseline_processes_sha256",
        "final_process_count",
        "final_processes_sha256",
        "baseline_equals_final",
        "unexpected_descendant_count",
        "unexpected_descendants_sha256",
    }
    expected_process_sha = hashlib.sha256(canonical_json([os.getpid()])).hexdigest()
    if (
        not _schema_version_is_one(value.get("schema_version"))
        or value.get("execution_model") != "direct-fork-exec"
        or value.get("nested_systemd_run_used") is not False
        or value.get("new_process_group") is not True
        or value.get("parent_death_signal") != "SIGKILL"
        or value.get("timeout_kills_process_group") is not True
        or value.get("timeout_observed") is not False
        or value.get("leader_waited_and_reaped") is not True
        or type(cgroup) is not dict
        or set(cgroup) != fields
        or cgroup.get("version") != 2
        or cgroup.get("relative_path") != live_cgroup["relative_path"]
        or cgroup.get("device") != live_cgroup["device"]
        or cgroup.get("inode") != live_cgroup["inode"]
        or cgroup.get("subtree_directory_count") != 1
        or cgroup.get("subtree_identity_sha256")
        != hashlib.sha256(
            canonical_json(
                [
                    {
                        "path": "/",
                        "device": live_cgroup["device"],
                        "inode": live_cgroup["inode"],
                    }
                ]
            )
        ).hexdigest()
        or cgroup.get("baseline_process_count") != 1
        or cgroup.get("final_process_count") != 1
        or cgroup.get("baseline_processes_sha256") != expected_process_sha
        or cgroup.get("final_processes_sha256") != expected_process_sha
        or cgroup.get("baseline_equals_final") is not True
        or cgroup.get("unexpected_descendant_count") != 0
        or cgroup.get("unexpected_descendants_sha256")
        != hashlib.sha256(canonical_json([])).hexdigest()
    ):
        raise PublishError("verifier process-control proof is invalid")


def _bootstrap_file(path: Path, *, allowed_modes: frozenset[int]) -> dict[str, Any]:
    payload = stable_read(
        path,
        label=f"bootstrap file {path}",
        expected_uid=0,
        expected_gid=0,
        allowed_modes=allowed_modes,
    )
    metadata = path.lstat()
    if path.is_symlink() or metadata.st_nlink != 1:
        raise PublishError(f"bootstrap file is unsafe: {path}")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "uid": 0,
        "gid": 0,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def _validate_supervisor_bootstrap(
    value: Mapping[str, Any],
    *,
    release_identity: Mapping[str, Any],
    expected_ldconfig_sha256: str,
) -> None:
    release_root = RELEASE_PARENT / release_identity["release"]
    expected_files = {
        "system_python": _bootstrap_file(
            Path(CLOSURE_PYTHON), allowed_modes=frozenset({0o755})
        ),
        "systemd_run": _bootstrap_file(
            SYSTEMD_RUN, allowed_modes=frozenset({0o755})
        ),
        "systemctl": _bootstrap_file(
            SYSTEMCTL, allowed_modes=frozenset({0o755})
        ),
        "ldconfig": _bootstrap_file(
            LDCONFIG, allowed_modes=frozenset({0o755})
        ),
        "strace": _bootstrap_file(STRACE, allowed_modes=frozenset({0o755})),
        "ld_so_preload": _bootstrap_file(
            LD_SO_PRELOAD, allowed_modes=frozenset({0o644})
        ),
        "runner": _bootstrap_file(
            release_root.joinpath(*RUNNER_RELATIVE.parts),
            allowed_modes=frozenset({0o444, 0o555}),
        ),
        "publisher": _bootstrap_file(
            release_root.joinpath(*PUBLISHER_RELATIVE.parts),
            allowed_modes=frozenset({0o444, 0o555}),
        ),
    }
    if (
        HEX64.fullmatch(expected_ldconfig_sha256) is None
        or expected_files["ldconfig"]["sha256"] != expected_ldconfig_sha256
        or type(value) is not dict
        or set(value)
        != {"schema_version", "supervisor_pid", "release_identity", "files"}
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("supervisor_pid") != os.getpid()
        or value.get("release_identity") != release_identity
        or value.get("files") != expected_files
    ):
        raise PublishError("supervisor bootstrap identity is invalid")


def _validate_prepublication_guard(value: Mapping[str, Any]) -> None:
    metadata = ANCHOR_PARENT.lstat()
    identity = {
        "path": str(ANCHOR_PARENT),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }
    if (
        type(value) is not dict
        or set(value)
        != {
            "schema_version",
            "backend",
            "watch_count",
            "reject_mask",
            "roots",
            "root_identities",
            "events_observed",
            "all_checks_passed",
        }
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("backend") != "linux-inotify-recursive"
        or type(value.get("watch_count")) is not int
        or value["watch_count"] < 1
        or value.get("reject_mask") != IN_REJECT_MASK
        or value.get("roots") != [str(ANCHOR_PARENT)]
        or value.get("root_identities") != [identity]
        or value.get("events_observed") != 0
        or value.get("all_checks_passed") is not True
    ):
        raise PublishError("prepublication dependency guard is invalid")


def expected_bundle_files() -> set[str]:
    """Return the frozen, release-defined Dev29 evidence member set."""

    files = {
        "read-plan.json",
        "runtime.json",
        "expected-release.json",
        "verified-release-pre.json",
        "verified-release-post.json",
        "sandbox-profile.json",
        "outer-unit.json",
        "system-pre.json",
        "system-post.json",
        "dependency-pre.json",
        "dependency-post.json",
        "dependency-watch.json",
        "state-pre.json",
        "state-post.json",
        "state-delta.json",
        "runtime-open-trace.json",
        "suite.json",
        "witness-pre.stdout",
        "witness-pre.stderr",
        "witness-pre.exit",
        "witness-pre.child.json",
        "witness-pre.process-control.json",
        "witness-post.stdout",
        "witness-post.stderr",
        "witness-post.exit",
        "witness-post.child.json",
        "witness-post.process-control.json",
        "release/identity.stdout",
        "release/identity.stderr",
        "release/identity.exit",
        "release/identity.child.json",
        "release/identity.process-control.json",
        "boundary/probe.stdout",
        "boundary/probe.stderr",
        "boundary/probe.exit",
        "boundary/probe.child.json",
        "boundary/probe.process-control.json",
        "closure/verify-pre.stdout",
        "closure/verify-pre.stderr",
        "closure/verify-pre.exit",
        "closure/verify-post.stdout",
        "closure/verify-post.stderr",
        "closure/verify-post.exit",
        "closure/addons-paths.json",
        "closure/python-pre.json",
        "closure/python-post.json",
        "closure/external-runtime-pre.json",
        "closure/external-runtime-post.json",
        "closure/mount-pre.json",
        "closure/mount-post.json",
    }
    for name in POSITIVE_NAMES:
        prefix = f"positive/{name}"
        files.update(
            {
                f"{prefix}/signer.stdout",
                f"{prefix}/signer.stderr",
                f"{prefix}/signer.exit",
                f"{prefix}/signer.child.json",
                f"{prefix}/signer.process-control.json",
                f"{prefix}/request.json",
                f"{prefix}/read.stdout",
                f"{prefix}/read.stderr",
                f"{prefix}/read.exit",
                f"{prefix}/read.child.json",
                f"{prefix}/read.process-control.json",
                f"{prefix}/receipt.json",
            }
        )
        if name in FINANCIAL_NAMES:
            files.update(
                {
                    f"{prefix}/oracle.stdout",
                    f"{prefix}/oracle.stderr",
                    f"{prefix}/oracle.exit",
                    f"{prefix}/oracle.child.json",
                    f"{prefix}/oracle.process-control.json",
                }
            )
    for name in NEGATIVE_NAMES:
        prefix = f"negative/{name}"
        files.update(
            {
                f"{prefix}/request.json",
                f"{prefix}/expected.json",
                f"{prefix}/read.stdout",
                f"{prefix}/read.stderr",
                f"{prefix}/read.exit",
                f"{prefix}/read.child.json",
                f"{prefix}/read.process-control.json",
            }
        )
        if name == "replay":
            files.add(f"{prefix}/request-source.json")
        else:
            files.update(
                {
                    f"{prefix}/signer.stdout",
                    f"{prefix}/signer.stderr",
                    f"{prefix}/signer.exit",
                    f"{prefix}/signer.child.json",
                    f"{prefix}/signer.process-control.json",
                }
            )
    return files


def _metadata_identity(path: Path, *, relative: str, directory: bool) -> dict[str, Any]:
    metadata = path.lstat()
    if path.is_symlink() or (
        not stat.S_ISDIR(metadata.st_mode)
        if directory
        else not stat.S_ISREG(metadata.st_mode)
    ):
        raise PublishError(f"frozen bundle object is unsafe: {relative or '.'}")
    return {
        "path": relative,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "links": metadata.st_nlink,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _frozen_tree_snapshot(
    evidence: Path,
    *,
    expected_files: set[str],
    enforce_root: bool,
) -> dict[str, list[dict[str, Any]]]:
    expected_directories = {""}
    for relative in expected_files | {"BUNDLE-MANIFEST.json"}:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            expected_directories.add(str(parent))
            parent = parent.parent
    directories: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    actual_directories: set[str] = set()
    actual_files: set[str] = set()
    for directory_text, names, members in os.walk(
        evidence, topdown=True, followlinks=False
    ):
        directory = Path(directory_text)
        relative_directory = directory.relative_to(evidence).as_posix()
        if relative_directory == ".":
            relative_directory = ""
        names.sort()
        members.sort()
        actual_directories.add(relative_directory)
        identity = _metadata_identity(
            directory, relative=relative_directory, directory=True
        )
        if enforce_root and (
            (identity["uid"], identity["gid"], identity["mode"]) != (0, 0, "0500")
            or identity["links"] < 2
        ):
            raise PublishError("frozen bundle directory metadata is invalid")
        directories.append(identity)
        for name in names:
            child = directory / name
            child_relative = child.relative_to(evidence).as_posix()
            _metadata_identity(child, relative=child_relative, directory=True)
        for name in members:
            child = directory / name
            child_relative = child.relative_to(evidence).as_posix()
            actual_files.add(child_relative)
            identity = _metadata_identity(
                child, relative=child_relative, directory=False
            )
            if enforce_root and (
                (identity["uid"], identity["gid"], identity["mode"], identity["links"])
                != (0, 0, "0400", 1)
            ):
                raise PublishError("frozen bundle member metadata is invalid")
            files.append(identity)
    if (
        actual_directories != expected_directories
        or actual_files != expected_files | {"BUNDLE-MANIFEST.json"}
    ):
        raise PublishError("frozen bundle filesystem set is invalid")
    directories.sort(key=lambda item: item["path"])
    files.sort(key=lambda item: item["path"])
    return {"directories": directories, "files": files}


def _evidence_identity(
    evidence: Path,
    *,
    expected_bundle_manifest_sha256: str,
    expected_release_identity: Mapping[str, Any],
    closure_verification: Mapping[str, Any],
    enforce_root: bool,
) -> dict[str, Any]:
    metadata = evidence.lstat()
    if enforce_root:
        _safe_root_chain(evidence, final_mode=0o500)
    if evidence.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise PublishError("frozen evidence directory identity is invalid")
    expected_uid = 0 if enforce_root else metadata.st_uid
    expected_gid = 0 if enforce_root else metadata.st_gid
    expected_files = expected_bundle_files()
    before = _frozen_tree_snapshot(
        evidence, expected_files=expected_files, enforce_root=enforce_root
    )
    manifest_path = evidence / "BUNDLE-MANIFEST.json"
    payload = stable_read(
        manifest_path,
        label="frozen bundle manifest",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        allowed_modes=frozenset({0o400}) if enforce_root else None,
    )
    if hashlib.sha256(payload).hexdigest() != expected_bundle_manifest_sha256:
        raise PublishError("frozen bundle manifest digest drifted")
    manifest = parse_json(payload, label="frozen bundle manifest")
    manifest_fields = {
        "schema_version",
        "bundle_type",
        "evidence_name",
        "evidence_path",
        "release_identity",
        "closure_identity",
        "closure_verification_sha256",
        "plan_sha256",
        "runtime_sha256",
        "runtime_open_trace_sha256",
        "runtime_open_trace_private",
        "positive_cases",
        "financial_oracle_cases",
        "negative_cases",
        "auth_token_ids",
        "receipt_ids",
        "production_promotion_allowed",
        "files",
    }
    entries = manifest.get("files")
    auth_ids = manifest.get("auth_token_ids")
    receipt_ids = manifest.get("receipt_ids")
    if (
        set(manifest) != manifest_fields
        or not _schema_version_is_one(manifest.get("schema_version"))
        or manifest.get("bundle_type")
        != "odoo-accounting-cli-v3.dev29.read-suite-evidence"
        or manifest.get("evidence_path") != str(evidence)
        or manifest.get("evidence_name") != evidence.name
        or manifest.get("release_identity") != expected_release_identity
        or manifest.get("closure_identity")
        != closure_verification.get("closure_identity")
        or manifest.get("closure_verification_sha256")
        != hashlib.sha256(canonical_json(closure_verification) + b"\n").hexdigest()
        or not isinstance(manifest.get("plan_sha256"), str)
        or HEX64.fullmatch(manifest["plan_sha256"]) is None
        or not isinstance(manifest.get("runtime_sha256"), str)
        or HEX64.fullmatch(manifest["runtime_sha256"]) is None
        or not isinstance(manifest.get("runtime_open_trace_sha256"), str)
        or HEX64.fullmatch(manifest["runtime_open_trace_sha256"]) is None
        or manifest.get("positive_cases") != list(POSITIVE_NAMES)
        or manifest.get("financial_oracle_cases") != list(FINANCIAL_NAMES)
        or manifest.get("negative_cases") != list(NEGATIVE_NAMES)
        or manifest.get("production_promotion_allowed") is not False
        or type(auth_ids) is not dict
        or type(manifest.get("runtime_open_trace_private")) is not dict
        or set(auth_ids) != set((*POSITIVE_NAMES, *NEGATIVE_NAMES))
        or any(not isinstance(item, str) or not item for item in auth_ids.values())
        or len(set(auth_ids.values())) != len(POSITIVE_NAMES) + len(NEGATIVE_NAMES) - 1
        or auth_ids.get("replay") != auth_ids.get("trial_balance")
        or type(receipt_ids) is not dict
        or set(receipt_ids) != set(POSITIVE_NAMES)
        or any(not isinstance(item, str) or not item for item in receipt_ids.values())
        or len(set(receipt_ids.values())) != len(POSITIVE_NAMES)
        or type(entries) is not list
        or [item.get("path") for item in entries if type(item) is dict]
        != sorted(expected_files)
    ):
        raise PublishError("frozen bundle manifest identity is invalid")
    before_files = {item["path"]: item for item in before["files"]}
    member_identities: list[dict[str, Any]] = []
    outer_unit_document: dict[str, Any] | None = None
    runtime_open_trace_sha256: str | None = None
    for entry in entries:
        if (
            type(entry) is not dict
            or set(entry) != {"path", "sha256", "size"}
            or entry.get("path") not in expected_files
            or not isinstance(entry.get("sha256"), str)
            or HEX64.fullmatch(entry["sha256"]) is None
            or type(entry.get("size")) is not int
            or entry["size"] < 0
            or entry["size"] > MAX_BUNDLE_MEMBER_BYTES
        ):
            raise PublishError("frozen bundle manifest member is invalid")
        member = evidence.joinpath(*PurePosixPath(entry["path"]).parts)
        member_payload = stable_read(
            member,
            label=f"frozen bundle member {entry['path']}",
            maximum=MAX_BUNDLE_MEMBER_BYTES,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            allowed_modes=frozenset({0o400}) if enforce_root else None,
            allow_empty=True,
        )
        if (
            len(member_payload) != entry["size"]
            or hashlib.sha256(member_payload).hexdigest() != entry["sha256"]
            or _metadata_identity(member, relative=entry["path"], directory=False)
            != before_files[entry["path"]]
        ):
            raise PublishError(f"frozen bundle member drifted: {entry['path']}")
        member_identities.append(before_files[entry["path"]])
        if entry["path"] == "outer-unit.json":
            outer_unit_document = parse_json(
                member_payload, label="frozen outer transient unit"
            )
        if entry["path"] == "runtime-open-trace.json":
            runtime_open_trace_sha256 = hashlib.sha256(member_payload).hexdigest()
    after = _frozen_tree_snapshot(
        evidence, expected_files=expected_files, enforce_root=enforce_root
    )
    if after != before:
        raise PublishError("frozen bundle tree changed during publisher validation")
    if outer_unit_document is None:
        raise PublishError("frozen outer transient unit evidence is absent")
    if runtime_open_trace_sha256 != manifest["runtime_open_trace_sha256"]:
        raise PublishError("frozen runtime-open trace binding is invalid")
    return {
        "path": str(evidence),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "bundle_manifest_sha256": expected_bundle_manifest_sha256,
        "bundle_manifest_size": len(payload),
        "directory_count": len(before["directories"]),
        "file_count": len(before["files"]),
        "tree_identity_sha256": hashlib.sha256(canonical_json(before)).hexdigest(),
        "member_identity_sha256": hashlib.sha256(
            canonical_json(member_identities)
        ).hexdigest(),
        "outer_unit": outer_unit_document,
        "outer_unit_sha256": hashlib.sha256(
            canonical_json(outer_unit_document) + b"\n"
        ).hexdigest(),
        "runtime_open_trace_sha256": runtime_open_trace_sha256,
        "runtime_open_trace_private": manifest["runtime_open_trace_private"],
    }


def _reverify_private_runtime_trace_sidecar(
    evidence: Path,
    summary: Mapping[str, Any],
    *,
    expected_release: str,
    required_targets: Sequence[str],
    sidecar: Path | None = None,
    enforce_root: bool = True,
) -> dict[str, Any]:
    if (
        type(summary) is not dict
        or set(summary)
        != {
            "schema_version",
            "manifest_sha256",
            "trace_count",
            "tree_identity_sha256",
            "production_promotion_allowed",
        }
        or type(summary.get("schema_version")) is not int
        or summary["schema_version"] != 1
        or not isinstance(summary.get("manifest_sha256"), str)
        or HEX64.fullmatch(summary["manifest_sha256"]) is None
        or type(summary.get("trace_count")) is not int
        or summary["trace_count"] != len(required_targets)
        or not isinstance(summary.get("tree_identity_sha256"), str)
        or HEX64.fullmatch(summary["tree_identity_sha256"]) is None
        or summary.get("production_promotion_allowed") is not False
    ):
        raise PublishError("private runtime-open trace summary is invalid")
    sidecar = sidecar or (PRIVATE_EVIDENCE_PARENT / evidence.name)
    if enforce_root:
        _safe_root_chain(sidecar, final_mode=0o700)
    payload = stable_read(
        sidecar / "MANIFEST.json",
        label="private runtime-open trace manifest",
        expected_uid=0 if enforce_root else None,
        expected_gid=0 if enforce_root else None,
        allowed_modes=frozenset({0o400}) if enforce_root else None,
    )
    if hashlib.sha256(payload).hexdigest() != summary["manifest_sha256"]:
        raise PublishError("private runtime-open trace manifest drifted")
    document = parse_json(payload, label="private runtime-open trace manifest")
    entries = document.get("entries")
    if (
        set(document)
        != {
            "schema_version",
            "sidecar_type",
            "release",
            "evidence_name",
            "entries",
            "production_promotion_allowed",
        }
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or document.get("sidecar_type")
        != "odoo-accounting-cli-v3.dev29.private-runtime-open.v1"
        or type(entries) is not list
        or len(entries) != summary["trace_count"]
        or document.get("release") != expected_release
        or document.get("evidence_name") != sidecar.name
        or [item.get("target_id") for item in entries if type(item) is dict]
        != list(required_targets)
        or document.get("production_promotion_allowed") is not False
    ):
        raise PublishError("private runtime-open trace manifest is invalid")
    expected_members = {"MANIFEST.json"} | {
        f"{target_id}.strace" for target_id in required_targets
    }
    observed_members = {child.name for child in os.scandir(sidecar)}
    if observed_members != expected_members:
        raise PublishError("private runtime-open sidecar member set is invalid")
    identities: list[dict[str, Any]] = []
    for entry in entries:
        path = Path(entry.get("path", "")) if type(entry) is dict else Path()
        if (
            type(entry) is not dict
            or set(entry)
            != {
                "target_id",
                "manifest_sha256",
                "expected_leader_pid",
                "path",
                "device",
                "inode",
                "size",
                "mode",
                "sha256",
            }
            or path.parent != sidecar
            or path.name != f"{entry.get('target_id')}.strace"
            or entry.get("mode") != "0400"
            or not isinstance(entry.get("manifest_sha256"), str)
            or HEX64.fullmatch(entry["manifest_sha256"]) is None
            or type(entry.get("expected_leader_pid")) is not int
            or entry["expected_leader_pid"] <= 1
            or any(
                type(entry.get(field)) is not int or entry[field] < 0
                for field in ("device", "inode", "size")
            )
            or entry["inode"] <= 0
            or not isinstance(entry.get("sha256"), str)
            or HEX64.fullmatch(entry["sha256"]) is None
        ):
            raise PublishError("private runtime-open trace entry is invalid")
        trace = stable_read(
            path,
            label=f"private runtime-open trace {entry['target_id']}",
            maximum=128 * 1024 * 1024,
            expected_uid=0 if enforce_root else None,
            expected_gid=0 if enforce_root else None,
            allowed_modes=frozenset({0o400}) if enforce_root else None,
        )
        metadata = path.lstat()
        if (
            (metadata.st_dev, metadata.st_ino, metadata.st_size)
            != (entry.get("device"), entry.get("inode"), entry.get("size"))
            or hashlib.sha256(trace).hexdigest() != entry.get("sha256")
        ):
            raise PublishError("private runtime-open trace identity drifted")
        identities.append(
            {
                key: entry[key]
                for key in ("target_id", "device", "inode", "size", "sha256")
            }
        )
    if hashlib.sha256(canonical_json(identities)).hexdigest() != summary[
        "tree_identity_sha256"
    ]:
        raise PublishError("private runtime-open trace tree drifted")
    return {
        **dict(summary),
        "sidecar_reverified_before_publication": True,
    }


def _validate_runtime_release_manifest(
    payload: bytes,
    *,
    expected_release: str,
    expected_manifest_sha256: str,
    runtime_payload: bytes,
) -> dict[str, dict[str, Any]]:
    document = _parse_release_manifest_json(payload)
    files = document.get("files")
    if (
        set(document)
        != {"commit", "files", "manifest_sha256", "schema_version", "version"}
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or not isinstance(document.get("version"), str)
        or VERSION.fullmatch(document["version"]) is None
        or not isinstance(document.get("commit"), str)
        or HEX40.fullmatch(document["commit"]) is None
        or expected_release
        != f"{document['version']}-{document['commit'][:12]}"
        or not isinstance(document.get("manifest_sha256"), str)
        or HEX64.fullmatch(document["manifest_sha256"]) is None
        or not isinstance(expected_manifest_sha256, str)
        or HEX64.fullmatch(expected_manifest_sha256) is None
        or type(files) is not list
        or not files
        or len(files) > MAX_RELEASE_FILES
    ):
        raise PublishError("publisher release manifest identity is invalid")
    unsigned = {
        key: value for key, value in document.items() if key != "manifest_sha256"
    }
    try:
        semantic_payload = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PublishError(
            "publisher release manifest semantic value is invalid"
        ) from exc
    actual_semantic_sha256 = hashlib.sha256(semantic_payload).hexdigest()
    if actual_semantic_sha256 != document["manifest_sha256"]:
        raise PublishError("publisher release manifest semantic digest is invalid")
    if document["manifest_sha256"] != expected_manifest_sha256:
        raise PublishError(
            "publisher release manifest semantic digest differs from expected identity"
        )
    indexed: dict[str, dict[str, Any]] = {}
    for item in files:
        name = item.get("path") if type(item) is dict else None
        portable = PurePosixPath(name) if isinstance(name, str) else None
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "size"}
            or portable is None
            or portable.is_absolute()
            or not portable.parts
            or any(part in {"", ".", ".."} for part in portable.parts)
            or str(portable) != name
            or "\\" in name
            or name == "RELEASE-MANIFEST.json"
            or name in indexed
            or not isinstance(item.get("sha256"), str)
            or HEX64.fullmatch(item["sha256"]) is None
            or type(item.get("size")) is not int
            or item["size"] < 0
        ):
            raise PublishError("publisher release manifest member is invalid")
        indexed[name] = item
    runtime_member = indexed.get(str(TRACE_RELATIVE))
    if (
        runtime_member is None
        or runtime_member["sha256"]
        != hashlib.sha256(runtime_payload).hexdigest()
        or runtime_member["size"] != len(runtime_payload)
    ):
        raise PublishError("publisher release manifest runtime member is invalid")
    return indexed


def _validate_runtime_policy_source(
    index: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, str]],
    *,
    expected_release: str,
    enforce_root: bool,
) -> tuple[dict[str, bytes], dict[str, dict[str, Any]]]:
    """Rebuild the approved source from every exact installed manifest."""

    parent = TRACE_INDEX_PARENT / expected_release
    ordered = expected_runtime_trace_targets()
    expected_names = {
        "INDEX.json",
        *(f"{target_id}.json" for target_id in ordered),
    }
    directory_identity = _sealed_directory_identity(
        parent,
        label="runtime-open policy directory",
        expected_mode=0o555,
        enforce_root=enforce_root,
        expected_names=expected_names,
    )

    payloads: dict[str, bytes] = {}
    documents: dict[str, dict[str, Any]] = {}
    for target_id in ordered:
        entry = targets[target_id]
        payload = stable_read(
            parent / f"{target_id}.json",
            label=f"runtime-open policy manifest {target_id}",
            expected_uid=0 if enforce_root else None,
            expected_gid=0 if enforce_root else None,
            allowed_modes=frozenset({0o400}) if enforce_root else None,
        )
        if hashlib.sha256(payload).hexdigest() != entry["manifest_sha256"]:
            raise PublishError(
                f"runtime-open policy manifest digest differs: {target_id}"
            )
        document = parse_json(
            payload,
            label=f"runtime-open policy manifest {target_id}",
        )
        environment = document.get("environment")
        watch_roots = document.get("watch_roots")
        child_environment_sha256 = (
            hashlib.sha256(canonical_json(environment)).hexdigest()
            if type(environment) is dict
            else None
        )
        watch_roots_sha256 = (
            hashlib.sha256(canonical_json(tuple(watch_roots))).hexdigest()
            if type(watch_roots) is list
            else None
        )
        if (
            type(document.get("schema_version")) is not int
            or document.get("schema_version") != 1
            or document.get("scope") != TRACE_MANIFEST_SCOPE
            or document.get("release") != expected_release
            or document.get("target_id") != target_id
            or document.get("expected_static_closure_sha256")
            != index["expected_static_closure_sha256"]
            or child_environment_sha256
            != entry["child_environment_sha256"]
            or document.get("expected_child_environment_sha256")
            != child_environment_sha256
            or watch_roots_sha256 != entry["watch_roots_sha256"]
            or document.get("expected_watch_roots_sha256")
            != watch_roots_sha256
        ):
            raise PublishError(
                f"runtime-open policy manifest index binding differs: {target_id}"
            )
        payloads[target_id] = payload
        documents[target_id] = document

    if (
        _sealed_directory_identity(
            parent,
            label="runtime-open policy directory",
            expected_mode=0o555,
            enforce_root=enforce_root,
            expected_names=expected_names,
        )
        != directory_identity
    ):
        raise PublishError("runtime-open policy directory changed during read")

    source = {
        "schema_version": 1,
        "scope": TRACE_POLICY_SOURCE_SCOPE,
        "release": index["release"],
        "expected_strace_sha256": index["expected_strace_sha256"],
        "expected_static_closure_sha256": index[
            "expected_static_closure_sha256"
        ],
        "expected_runtime_module_sha256": index["runtime_module_sha256"],
        "expected_release_manifest_sha256": index[
            "release_manifest_sha256"
        ],
        "targets": [documents[target_id] for target_id in ordered],
        "production_promotion_allowed": False,
    }
    actual_sha256 = hashlib.sha256(canonical_json(source) + b"\n").hexdigest()
    if actual_sha256 != index["policy_source_sha256"]:
        raise PublishError("runtime-open policy source digest differs")
    return payloads, documents


def _validate_verifier_runtime_trace(
    evidence: Path,
    value: Mapping[str, Any],
    *,
    expected_release: str,
    expected_release_manifest_semantic_sha256: str,
    expected_index_sha256: str,
    expected_strace_sha256: str,
    enforce_root: bool = True,
) -> dict[str, Any]:
    receipts = value.get("receipts") if type(value) is dict else None
    summary = value.get("private_sidecar") if type(value) is dict else None
    if (
        type(value) is not dict
        or set(value)
        != {
            "schema_version",
            "scope",
            "release",
            "index_sha256",
            "expected_strace_sha256",
            "expected_static_closure_sha256",
            "policy_source_sha256",
            "runtime_module_sha256",
            "release_manifest_sha256",
            "receipts",
            "private_sidecar",
            "production_promotion_allowed",
        }
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or value.get("scope") != TRACE_RECEIPTS_SCOPE
        or value.get("release") != expected_release
        or value.get("index_sha256") != expected_index_sha256
        or value.get("expected_strace_sha256") != expected_strace_sha256
        or value.get("production_promotion_allowed") is not False
        or type(receipts) is not list
        or len(receipts) != 1
        or type(receipts[0]) is not dict
        or type(receipts[0].get("schema_version")) is not int
        or receipts[0].get("schema_version") != 1
        or receipts[0].get("target_id") != "independent-verifier"
        or receipts[0].get("role") != "verifier"
        or receipts[0].get("production_promotion_allowed") is not False
    ):
        raise PublishError("verifier runtime-open trace receipt is invalid")
    sidecar = _verifier_private_sidecar_path(evidence)
    sidecar_proof = _reverify_private_runtime_trace_sidecar(
        evidence,
        summary,
        expected_release=expected_release,
        required_targets=("independent-verifier",),
        sidecar=sidecar,
        enforce_root=enforce_root,
    )
    policy_parent = TRACE_INDEX_PARENT / expected_release
    expected_policy_names = {
        "INDEX.json",
        *(
            f"{target_id}.json"
            for target_id in expected_runtime_trace_targets()
        ),
    }
    policy_directory_identity = _sealed_directory_identity(
        policy_parent,
        label="runtime-open policy directory",
        expected_mode=0o555,
        enforce_root=enforce_root,
        expected_names=expected_policy_names,
    )
    index_payload = stable_read(
        policy_parent / "INDEX.json",
        label="runtime-open trace index",
        expected_uid=0 if enforce_root else None,
        expected_gid=0 if enforce_root else None,
        allowed_modes=frozenset({0o400}) if enforce_root else None,
    )
    if hashlib.sha256(index_payload).hexdigest() != expected_index_sha256:
        raise PublishError("runtime-open trace index drifted before publication")
    index = parse_json(index_payload, label="runtime-open trace index")
    targets = index.get("targets")
    if (
        set(index)
        != {
            "schema_version",
            "scope",
            "release",
            "expected_strace_sha256",
            "expected_static_closure_sha256",
            "policy_source_sha256",
            "runtime_module_sha256",
            "release_manifest_sha256",
            "targets",
            "production_promotion_allowed",
        }
        or type(index.get("schema_version")) is not int
        or index.get("schema_version") != 1
        or index.get("scope") != TRACE_INDEX_SCOPE
        or index.get("release") != expected_release
        or index.get("expected_strace_sha256") != expected_strace_sha256
        or any(
            not isinstance(index.get(field), str)
            or HEX64.fullmatch(index[field]) is None
            for field in (
                "expected_static_closure_sha256",
                "policy_source_sha256",
                "runtime_module_sha256",
                "release_manifest_sha256",
            )
        )
        or type(targets) is not list
        or index.get("production_promotion_allowed") is not False
        or index.get("expected_static_closure_sha256")
        != value.get("expected_static_closure_sha256")
        or index.get("policy_source_sha256")
        != value.get("policy_source_sha256")
        or index.get("runtime_module_sha256")
        != value.get("runtime_module_sha256")
        or index.get("release_manifest_sha256")
        != value.get("release_manifest_sha256")
    ):
        raise PublishError("runtime-open verifier index binding is invalid")
    indexed: dict[str, dict[str, str]] = {}
    ordered: list[str] = []
    for candidate in targets:
        if (
            type(candidate) is not dict
            or set(candidate)
            != {
                "target_id",
                "manifest_sha256",
                "watch_roots_sha256",
                "child_environment_sha256",
            }
            or not isinstance(candidate.get("target_id"), str)
            or candidate["target_id"] in indexed
            or any(
                not isinstance(candidate.get(field), str)
                or HEX64.fullmatch(candidate[field]) is None
                for field in (
                    "manifest_sha256",
                    "watch_roots_sha256",
                    "child_environment_sha256",
                )
            )
        ):
            raise PublishError("runtime-open verifier index target is invalid")
        ordered.append(candidate["target_id"])
        indexed[candidate["target_id"]] = dict(candidate)
    if tuple(ordered) != expected_runtime_trace_targets():
        raise PublishError("runtime-open verifier index target set is incomplete")
    manifest_payloads, manifest_documents = _validate_runtime_policy_source(
        index,
        indexed,
        expected_release=expected_release,
        enforce_root=enforce_root,
    )
    if (
        _sealed_directory_identity(
            policy_parent,
            label="runtime-open policy directory",
            expected_mode=0o555,
            enforce_root=enforce_root,
            expected_names=expected_policy_names,
        )
        != policy_directory_identity
    ):
        raise PublishError("runtime-open policy directory identity drifted")
    entry = indexed["independent-verifier"]
    release_root = RELEASE_PARENT / expected_release
    release_tree_identity = _sealed_release_tree_identity(
        release_root, enforce_root=enforce_root
    )
    runtime_path = release_root.joinpath(*TRACE_RELATIVE.parts)
    runtime_payload = stable_read(
        runtime_path,
        label="publisher runtime-open validator",
        expected_uid=0 if enforce_root else None,
        expected_gid=0 if enforce_root else None,
        allowed_modes=frozenset({0o444}) if enforce_root else None,
    )
    release_manifest_payload = stable_read(
        release_root / "RELEASE-MANIFEST.json",
        label="publisher exact release manifest",
        expected_uid=0 if enforce_root else None,
        expected_gid=0 if enforce_root else None,
        allowed_modes=frozenset({0o444}) if enforce_root else None,
    )
    if (
        hashlib.sha256(runtime_payload).hexdigest()
        != index["runtime_module_sha256"]
        or hashlib.sha256(release_manifest_payload).hexdigest()
        != index["release_manifest_sha256"]
    ):
        raise PublishError("runtime-open verifier release member binding differs")
    release_members = _validate_runtime_release_manifest(
        release_manifest_payload,
        expected_release=expected_release,
        expected_manifest_sha256=(
            expected_release_manifest_semantic_sha256
        ),
        runtime_payload=runtime_payload,
    )
    observed_directories = {name for name, _identity in release_tree_identity[0]}
    observed_files = {name for name, _identity in release_tree_identity[1]}
    expected_directories = {""}
    for name in release_members:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            expected_directories.add(str(parent))
            parent = parent.parent
    if (
        observed_files != set(release_members) | {"RELEASE-MANIFEST.json"}
        or observed_directories != expected_directories
    ):
        raise PublishError("publisher sealed release tree file set is not exact")
    for name, member in release_members.items():
        member_payload = (
            runtime_payload
            if name == str(TRACE_RELATIVE)
            else stable_read(
                release_root.joinpath(*PurePosixPath(name).parts),
                label=f"publisher sealed release member {name}",
                expected_uid=0 if enforce_root else None,
                expected_gid=0 if enforce_root else None,
                allowed_modes=(
                    frozenset({_expected_release_member_mode(name)})
                    if enforce_root
                    else None
                ),
                allow_empty=True,
            )
        )
        if (
            len(member_payload) != member["size"]
            or hashlib.sha256(member_payload).hexdigest() != member["sha256"]
        ):
            raise PublishError(f"publisher sealed release member differs: {name}")
    if (
        _sealed_release_tree_identity(release_root, enforce_root=enforce_root)
        != release_tree_identity
    ):
        raise PublishError("publisher sealed release tree changed during verification")
    manifest_payload = manifest_payloads["independent-verifier"]
    manifest_document = manifest_documents["independent-verifier"]
    module_name = "_dev29_publisher_runtime_open_trace"
    module = types.ModuleType(module_name)
    module.__file__ = str(runtime_path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(runtime_payload, str(runtime_path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    request = module.TraceRequest(
        release=expected_release,
        target_id="independent-verifier",
        expected_manifest_sha256=entry["manifest_sha256"],
        expected_strace_sha256=expected_strace_sha256,
        expected_static_closure_sha256=index["expected_static_closure_sha256"],
        expected_child_environment_sha256=entry["child_environment_sha256"],
        expected_watch_roots_sha256=entry["watch_roots_sha256"],
    )
    manifest = module.validate_manifest_document(manifest_document, request)
    private_manifest = parse_json(
        stable_read(
            sidecar / "MANIFEST.json",
            label="private verifier trace manifest",
            expected_uid=0 if enforce_root else None,
            expected_gid=0 if enforce_root else None,
            allowed_modes=frozenset({0o400}) if enforce_root else None,
        ),
        label="private verifier trace manifest",
    )
    private_entries = private_manifest.get("entries")
    if (
        type(private_entries) is not list
        or len(private_entries) != 1
        or private_entries[0].get("target_id") != "independent-verifier"
        or private_entries[0].get("manifest_sha256")
        != entry["manifest_sha256"]
    ):
        raise PublishError("private verifier raw trace entry is invalid")
    raw = private_entries[0]
    result = module.validate_trace_file(
        Path(raw["path"]),
        manifest,
        expected_leader_pid=raw["expected_leader_pid"],
    )
    receipt = receipts[0]
    receipt_fields = {
        "schema_version",
        "scope",
        "target_id",
        "role",
        "manifest_sha256",
        "policy_sha256",
        "watch_roots_sha256",
        "child_environment_sha256",
        "static_closure_sha256",
        "dynamic_namespace_receipt_sha256",
        "canonical_path_count",
        "canonical_path_set_sha256",
        "trace_sha256",
        "production_promotion_allowed",
    }
    policy_sha256 = hashlib.sha256(
        canonical_json(manifest_document["path_access_policy"])
    ).hexdigest()
    if (
        set(receipt) != receipt_fields
        or type(receipt.get("schema_version")) is not int
        or receipt.get("schema_version") != 1
        or receipt.get("scope") != TRACE_MANIFEST_SCOPE
        or receipt.get("target_id") != "independent-verifier"
        or receipt.get("role") != "verifier"
        or receipt.get("manifest_sha256") != entry["manifest_sha256"]
        or receipt.get("policy_sha256") != policy_sha256
        or receipt.get("watch_roots_sha256")
        != entry["watch_roots_sha256"]
        or receipt.get("child_environment_sha256")
        != entry["child_environment_sha256"]
        or receipt.get("static_closure_sha256")
        != index["expected_static_closure_sha256"]
        or not isinstance(receipt.get("dynamic_namespace_receipt_sha256"), str)
        or HEX64.fullmatch(receipt["dynamic_namespace_receipt_sha256"]) is None
        or type(receipt.get("canonical_path_count")) is not int
        or receipt["canonical_path_count"] <= 0
        or any(
            not isinstance(receipt.get(field), str)
            or HEX64.fullmatch(receipt[field]) is None
            for field in ("canonical_path_set_sha256", "trace_sha256")
        )
        or receipt.get("production_promotion_allowed") is not False
        or raw.get("sha256") != receipt.get("trace_sha256")
        or result.document()
        != {
            "canonical_path_count": receipt.get("canonical_path_count"),
            "canonical_path_set_sha256": receipt.get(
                "canonical_path_set_sha256"
            ),
            "trace_sha256": receipt.get("trace_sha256"),
        }
    ):
        raise PublishError("publisher verifier raw trace reparse differs")
    return {
        "receipt_sha256": hashlib.sha256(canonical_json(value) + b"\n").hexdigest(),
        "policy_source_sha256": index["policy_source_sha256"],
        "runtime_module_sha256": index["runtime_module_sha256"],
        "release_manifest_sha256": index["release_manifest_sha256"],
        "private_sidecar": sidecar_proof,
        "raw_trace_independently_reparsed_by_publisher": True,
        "production_promotion_allowed": False,
    }


def validate_inputs(
    evidence: Path,
    report: Mapping[str, Any],
    cleanup: Mapping[str, Any],
    verifier_child: Mapping[str, Any],
    verifier_process_control: Mapping[str, Any],
    verifier_runtime_trace: Mapping[str, Any],
    prepublication_guard: Mapping[str, Any],
    supervisor_bootstrap: Mapping[str, Any],
    *,
    expected_bundle_manifest_sha256: str,
    expected_release_identity: Mapping[str, str],
    expected_ldconfig_sha256: str,
    expected_runtime_open_index_sha256: str,
    expected_strace_sha256: str,
    enforce_root: bool = True,
) -> dict[str, Any]:
    evidence = Path(evidence).absolute()
    if (
        evidence.parent != EVIDENCE_PARENT
        or SAFE_NAME.fullmatch(evidence.name) is None
        or HEX64.fullmatch(expected_bundle_manifest_sha256) is None
        or set(report)
        != {
            "schema_version",
            "suite",
            "release_identity",
            "closure_identity",
            "closure_verification",
            "closure_verification_sha256",
            "bundle_manifest_sha256",
            "positive_case_count",
            "financial_oracle_count",
            "negative_case_count",
            "receipt_count",
            "d11_read_boundary_verified",
            "postgresql_witness_verified",
            "system_identity_unchanged",
            "dependency_identity_unchanged",
            "state_and_audit_chain_verified",
            "exact_release_core_receipts_verified",
            "odoo_closure_verified",
            "external_runtime_manifest_verified",
            "closure_mount_binding_verified",
            "direct_child_evidence_verified",
            "unit_cgroup_descendants_absent",
            "outer_systemd_unit_verified",
            "runtime_open_trace_verified",
            "runtime_open_trace",
            "all_checks_passed",
            "production_promotion_allowed",
        }
        or not _schema_version_is_one(report.get("schema_version"))
        or report.get("suite") != "odoo-accounting-cli-v3.dev29.real-read-gate"
        or report.get("bundle_manifest_sha256") != expected_bundle_manifest_sha256
        or report.get("release_identity") != expected_release_identity
        or report.get("all_checks_passed") is not True
        or report.get("direct_child_evidence_verified") is not True
        or report.get("unit_cgroup_descendants_absent") is not True
        or report.get("outer_systemd_unit_verified") is not True
        or report.get("runtime_open_trace_verified") is not True
        or type(report.get("runtime_open_trace")) is not dict
        or report["runtime_open_trace"].get("all_checks_passed") is not True
        or report["runtime_open_trace"].get("production_promotion_allowed") is not False
        or report["runtime_open_trace"].get("raw_traces_independently_reparsed")
        is not True
        or report.get("production_promotion_allowed") is not False
        or type(report.get("closure_identity")) is not dict
    ):
        raise PublishError("validation report is not publishable")
    closure = report["closure_identity"]
    closure_verification = report.get("closure_verification")
    if (
        type(closure_verification) is not dict
        or closure_verification.get("closure_identity") != closure
        or report.get("closure_verification_sha256")
        != hashlib.sha256(canonical_json(closure_verification)).hexdigest()
        or not isinstance(closure.get("image_path"), str)
        or not PurePosixPath(closure["image_path"]).is_absolute()
        or not isinstance(closure.get("image_sha256"), str)
        or HEX64.fullmatch(closure["image_sha256"]) is None
    ):
        raise PublishError("validation report closure identity is invalid")
    _validate_prepublication_guard(prepublication_guard)
    _validate_supervisor_bootstrap(
        supervisor_bootstrap,
        release_identity=expected_release_identity,
        expected_ldconfig_sha256=expected_ldconfig_sha256,
    )
    live_cgroup = _prove_supervisor_cgroup()
    _validate_verifier_child(
        verifier_child,
        evidence=evidence,
        report=report,
        expected_bundle_manifest_sha256=expected_bundle_manifest_sha256,
        release_identity=expected_release_identity,
        expected_ldconfig_sha256=supervisor_bootstrap["files"]["ldconfig"][
            "sha256"
        ],
        expected_runtime_open_index_sha256=expected_runtime_open_index_sha256,
        expected_strace_sha256=expected_strace_sha256,
    )
    _validate_verifier_process_control(
        verifier_process_control, live_cgroup=live_cgroup
    )
    _prove_cleanup_live(cleanup, closure=closure_verification)
    evidence_identity = _evidence_identity(
        evidence,
        expected_bundle_manifest_sha256=expected_bundle_manifest_sha256,
        expected_release_identity=expected_release_identity,
        closure_verification=closure_verification,
        enforce_root=enforce_root,
    )
    if (
        report["runtime_open_trace"].get("receipt_sha256")
        != evidence_identity["runtime_open_trace_sha256"]
    ):
        raise PublishError("validation report runtime-open trace binding differs")
    private_runtime_trace = _reverify_private_runtime_trace_sidecar(
        evidence,
        evidence_identity["runtime_open_trace_private"],
        expected_release=expected_release_identity["release"],
        required_targets=suite_runtime_trace_targets(),
    )
    if (
        report["runtime_open_trace"].get("private_sidecar")
        != evidence_identity["runtime_open_trace_private"]
    ):
        raise PublishError("validation report private trace binding differs")
    evidence_identity["private_runtime_trace_reverification"] = private_runtime_trace
    verifier_runtime_trace_proof = _validate_verifier_runtime_trace(
        evidence,
        verifier_runtime_trace,
        expected_release=expected_release_identity["release"],
        expected_release_manifest_semantic_sha256=(
            expected_release_identity["manifest_sha256"]
        ),
        expected_index_sha256=expected_runtime_open_index_sha256,
        expected_strace_sha256=expected_strace_sha256,
    )
    publication_outer_unit = _reverify_outer_unit(evidence_identity["outer_unit"])
    final_cgroup = _prove_supervisor_cgroup()
    if final_cgroup != live_cgroup:
        raise PublishError("publisher cgroup changed during final unit verification")
    evidence_identity["publication_outer_unit_reverification"] = (
        publication_outer_unit
    )
    return {
        "cgroup": final_cgroup,
        "evidence": evidence_identity,
        "verifier_runtime_trace": verifier_runtime_trace_proof,
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically move ``source`` to an absent ``destination`` on Linux."""

    if sys.platform != "linux":
        raise PublishError("renameat2(RENAME_NOREPLACE) requires Linux")
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise PublishError("libc renameat2 is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), destination)
    raise OSError(error, os.strerror(error), destination)


def _remove_pending_anchor(
    path: Path, *, enforce_root: bool, allow_absent: bool = True
) -> None:
    if not os.path.lexists(path):
        if allow_absent:
            return
        raise PublishError("private anchor staging file disappeared")
    metadata = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (enforce_root and (metadata.st_uid, metadata.st_gid) != (0, 0))
        or stat.S_IMODE(metadata.st_mode)
        not in ({0o600, 0o400} if os.name == "posix" else {0o666, 0o444})
    ):
        raise PublishError("private anchor staging file is unsafe")
    if os.name != "posix" and not enforce_root:
        os.chmod(path, 0o600)
    path.unlink()


def _anchor_readonly_modes(*, enforce_root: bool) -> frozenset[int]:
    if os.name == "posix" or enforce_root:
        return frozenset({0o400})
    return frozenset({0o400, 0o444})


def _make_pending_read_only(descriptor: int, path: Path) -> None:
    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, 0o400)
    else:
        os.chmod(path, 0o400)


def _read_and_fsync_pending(path: Path, *, enforce_root: bool) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 64 * 1024 * 1024
            or stat.S_IMODE(before.st_mode)
            not in _anchor_readonly_modes(enforce_root=enforce_root)
            or (enforce_root and (before.st_uid, before.st_gid) != (0, 0))
        ):
            raise PublishError("recoverable pending anchor metadata is invalid")
        payload = bytearray()
        while len(payload) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(payload))
            if not chunk:
                raise PublishError("recoverable pending anchor is truncated")
            payload.extend(chunk)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if os.read(descriptor, 1) or (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise PublishError("recoverable pending anchor changed during fsync")
        return bytes(payload)
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def _anchor_lock(path: Path, *, enforce_root: bool) -> Iterable[None]:
    if sys.platform != "linux":
        raise PublishError("publisher lock requires Linux flock")
    import fcntl

    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (enforce_root and (metadata.st_uid, metadata.st_gid) != (0, 0))
        ):
            raise PublishError("publisher lock identity is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        os.fsync(descriptor)
        _fsync_directory(path.parent)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _atomic_publish_locked(
    anchor_path: Path,
    payload: bytes,
    *,
    enforce_root: bool,
) -> Path:
    parent = anchor_path.parent
    if not payload or len(payload) > 64 * 1024 * 1024:
        raise PublishError("evidence anchor payload size is invalid")
    temporary = parent / f".{anchor_path.name}.pending"
    descriptor: int | None = None
    committed = False
    try:
        if os.path.lexists(anchor_path):
            existing = stable_read(
                anchor_path,
                label="existing evidence anchor",
                expected_uid=0 if enforce_root else None,
                expected_gid=0 if enforce_root else None,
                allowed_modes=_anchor_readonly_modes(enforce_root=enforce_root),
            )
            if existing != payload:
                raise PublishError("existing evidence anchor conflicts with publication")
            if os.path.lexists(temporary):
                metadata = temporary.lstat()
                if stat.S_IMODE(metadata.st_mode) in _anchor_readonly_modes(
                    enforce_root=enforce_root
                ):
                    staged = _read_and_fsync_pending(
                        temporary, enforce_root=enforce_root
                    )
                    if staged != payload:
                        raise PublishError(
                            "pending evidence anchor conflicts with final anchor"
                        )
                _remove_pending_anchor(
                    temporary, enforce_root=enforce_root, allow_absent=False
                )
            _fsync_directory(parent)
            return anchor_path
        if os.path.lexists(temporary):
            metadata = temporary.lstat()
            if (
                temporary.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or (enforce_root and (metadata.st_uid, metadata.st_gid) != (0, 0))
            ):
                raise PublishError("pending evidence anchor identity is unsafe")
            pending_mode = stat.S_IMODE(metadata.st_mode)
            writable_pending_modes = {0o600} if os.name == "posix" else {0o666}
            if pending_mode in writable_pending_modes:
                _remove_pending_anchor(
                    temporary, enforce_root=enforce_root, allow_absent=False
                )
                _fsync_directory(parent)
            elif pending_mode in _anchor_readonly_modes(enforce_root=enforce_root):
                staged = _read_and_fsync_pending(
                    temporary, enforce_root=enforce_root
                )
            else:
                raise PublishError("pending evidence anchor mode is invalid")
        if os.path.lexists(temporary):
            if staged != payload:
                raise PublishError("pending evidence anchor conflicts with publication")
            _rename_noreplace(temporary, anchor_path)
            committed = True
            _fsync_directory(parent)
            final = stable_read(
                anchor_path,
                label="recovered evidence anchor",
                expected_uid=0 if enforce_root else None,
                expected_gid=0 if enforce_root else None,
                allowed_modes=_anchor_readonly_modes(enforce_root=enforce_root),
            )
            if final != payload:
                raise PublishError("recovered evidence anchor verification failed")
            return anchor_path
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
            # O_BINARY is zero on Linux and prevents CRLF translation in
            # portable fault-injection tests.
            0o600,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PublishError("short private anchor staging write")
            view = view[written:]
        _make_pending_read_only(descriptor, temporary)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        staged = stable_read(
            temporary,
            label="private staged evidence anchor",
            expected_uid=0 if enforce_root else None,
            expected_gid=0 if enforce_root else None,
            allowed_modes=_anchor_readonly_modes(enforce_root=enforce_root),
        )
        if staged != payload or temporary.lstat().st_nlink != 1:
            raise PublishError("private staged evidence anchor verification failed")
        _fsync_directory(parent)
        try:
            _rename_noreplace(temporary, anchor_path)
            committed = True
        except FileExistsError:
            existing = stable_read(
                anchor_path,
                label="existing evidence anchor",
                expected_uid=0 if enforce_root else None,
                expected_gid=0 if enforce_root else None,
                allowed_modes=_anchor_readonly_modes(enforce_root=enforce_root),
            )
            if existing != payload or anchor_path.lstat().st_nlink != 1:
                raise PublishError("existing evidence anchor conflicts with publication")
            _remove_pending_anchor(
                temporary, enforce_root=enforce_root, allow_absent=False
            )
            _fsync_directory(parent)
            return anchor_path
        _fsync_directory(parent)
        final_metadata = anchor_path.lstat()
        if (
            final_metadata.st_nlink != 1
            or stat.S_IMODE(final_metadata.st_mode)
            not in _anchor_readonly_modes(enforce_root=enforce_root)
            or stable_read(
                anchor_path,
                label="published evidence anchor",
                expected_uid=0 if enforce_root else None,
                expected_gid=0 if enforce_root else None,
                allowed_modes=_anchor_readonly_modes(enforce_root=enforce_root),
            )
            != payload
        ):
            raise PublishError("published evidence anchor verification failed")
        return anchor_path
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if not committed and os.path.lexists(temporary):
            try:
                _remove_pending_anchor(temporary, enforce_root=enforce_root)
            except (OSError, PublishError):
                pass
        try:
            _fsync_directory(parent)
        except OSError:
            pass
        raise


def _atomic_publish_no_replace(
    anchor_path: Path,
    payload: bytes,
    *,
    enforce_root: bool,
) -> Path:
    lock = anchor_path.parent / f".{anchor_path.name}.lock"
    with _anchor_lock(lock, enforce_root=enforce_root):
        return _atomic_publish_locked(
            anchor_path, payload, enforce_root=enforce_root
        )


def _publish_recovery_payload_locked(anchor_path: Path, payload: bytes) -> Path:
    parent = anchor_path.parent
    temporary = parent / f".{anchor_path.name}.recovery.pending"
    descriptor: int | None = None
    committed = False
    try:
        if os.path.lexists(temporary):
            _remove_pending_anchor(temporary, enforce_root=True)
            _fsync_directory(parent)
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PublishError("short recovery anchor staging write")
            view = view[written:]
        _make_pending_read_only(descriptor, temporary)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        if stable_read(
            temporary,
            label="recovery publication payload",
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o400}),
        ) != payload:
            raise PublishError("recovery publication payload drifted")
        _fsync_directory(parent)
        try:
            _rename_noreplace(temporary, anchor_path)
            committed = True
        except FileExistsError:
            final = stable_read(
                anchor_path,
                label="raced recovery evidence anchor",
                expected_uid=0,
                expected_gid=0,
                allowed_modes=frozenset({0o400}),
            )
            if final != payload:
                raise PublishError("raced recovery evidence anchor conflicts")
            _remove_pending_anchor(
                temporary, enforce_root=True, allow_absent=False
            )
        _fsync_directory(parent)
        if stable_read(
            anchor_path,
            label="published recovery evidence anchor",
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o400}),
        ) != payload:
            raise PublishError("published recovery evidence anchor drifted")
        return anchor_path
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if not committed and os.path.lexists(temporary):
            try:
                _remove_pending_anchor(temporary, enforce_root=True)
                _fsync_directory(parent)
            except (OSError, PublishError):
                pass
        raise


def publish(
    evidence: Path,
    report: dict[str, Any],
    cleanup: dict[str, Any],
    verifier_child: dict[str, Any],
    verifier_process_control: dict[str, Any],
    verifier_runtime_trace: dict[str, Any],
    prepublication_guard: dict[str, Any],
    supervisor_bootstrap: dict[str, Any],
    *,
    expected_bundle_manifest_sha256: str,
    expected_release_identity: dict[str, str],
    expected_ldconfig_sha256: str,
    expected_runtime_open_index_sha256: str,
    expected_strace_sha256: str,
    publisher_script_execution: Mapping[str, Any],
    anchor_parent: Path = ANCHOR_PARENT,
    enforce_root: bool = True,
) -> Path:
    _validate_publisher_script_execution(publisher_script_execution)
    supervisor_cgroup = validate_inputs(
        evidence,
        report,
        cleanup,
        verifier_child,
        verifier_process_control,
        verifier_runtime_trace,
        prepublication_guard,
        supervisor_bootstrap,
        expected_bundle_manifest_sha256=expected_bundle_manifest_sha256,
        expected_release_identity=expected_release_identity,
        expected_ldconfig_sha256=expected_ldconfig_sha256,
        expected_runtime_open_index_sha256=expected_runtime_open_index_sha256,
        expected_strace_sha256=expected_strace_sha256,
        enforce_root=enforce_root,
    )
    if enforce_root:
        if os.name != "posix" or os.geteuid() != 0:
            raise PublishError("publisher requires POSIX root")
        _safe_root_chain(anchor_parent, final_mode=0o755)
    evidence = Path(evidence).absolute()
    anchor_path = anchor_parent / f"{evidence.name}.json"
    staging_documents = {
        "validation-report.json": report,
        "cleanup-receipt.json": cleanup,
        "verifier-child.json": verifier_child,
        "verifier-process-control.json": verifier_process_control,
        "verifier-runtime-trace.json": verifier_runtime_trace,
        "prepublication-guard.json": prepublication_guard,
        "supervisor-bootstrap.json": supervisor_bootstrap,
    }
    publication_unit = supervisor_cgroup["evidence"][
        "publication_outer_unit_reverification"
    ]
    document = {
        "schema_version": 1,
        "anchor_type": "odoo-accounting-cli-v3.dev29.read-suite-verification",
        "bundle_path": str(evidence),
        "bundle_manifest_sha256": expected_bundle_manifest_sha256,
        "release_identity": expected_release_identity,
        "closure_identity": report["closure_identity"],
        "validation_report": report,
        "validation_report_sha256": hashlib.sha256(canonical_json(report)).hexdigest(),
        "cleanup_receipt": cleanup,
        "cleanup_receipt_sha256": hashlib.sha256(canonical_json(cleanup)).hexdigest(),
        "verifier_child_sha256": hashlib.sha256(canonical_json(verifier_child)).hexdigest(),
        "verifier_child": verifier_child,
        "verifier_process_control_sha256": hashlib.sha256(
            canonical_json(verifier_process_control)
        ).hexdigest(),
        "verifier_process_control": verifier_process_control,
        "verifier_runtime_trace_sha256": hashlib.sha256(
            canonical_json(verifier_runtime_trace)
        ).hexdigest(),
        "verifier_runtime_trace": verifier_runtime_trace,
        "prepublication_guard": prepublication_guard,
        "prepublication_guard_sha256": hashlib.sha256(
            canonical_json(prepublication_guard)
        ).hexdigest(),
        "supervisor_bootstrap": supervisor_bootstrap,
        "supervisor_bootstrap_sha256": hashlib.sha256(
            canonical_json(supervisor_bootstrap)
        ).hexdigest(),
        "publisher_cgroup": supervisor_cgroup["cgroup"],
        "final_publication": {
            "mode": "initial",
            "publisher_pid": os.getpid(),
            "publisher_cgroup": supervisor_cgroup["cgroup"],
            "unit": publication_unit["unit"],
            "systemctl": publication_unit["systemctl"],
            "properties": publication_unit["properties"],
            "properties_sha256": publication_unit["properties_sha256"],
            "proc": publication_unit["proc"],
            "systemctl_execution": publication_unit["systemctl_execution"],
            "outer_unit": publication_unit["outer_unit"],
            "outer_unit_sha256": publication_unit["outer_unit_sha256"],
            "publisher_script_execution": dict(publisher_script_execution),
            "resumed_pending_sha256": None,
            "staging_documents_sha256": hashlib.sha256(
                canonical_json(staging_documents)
            ).hexdigest(),
            "all_checks_passed": True,
        },
        "frozen_evidence_identity": supervisor_cgroup["evidence"],
        "verifier_runtime_trace_reverification": supervisor_cgroup[
            "verifier_runtime_trace"
        ],
        "cleanup_completed_before_anchor": True,
        "production_promotion_allowed": False,
    }
    payload = canonical_json(document) + b"\n"
    return _atomic_publish_no_replace(
        anchor_path, payload, enforce_root=enforce_root
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--validation-report", required=True, type=Path)
    parser.add_argument("--cleanup-receipt", required=True, type=Path)
    parser.add_argument("--verifier-child", required=True, type=Path)
    parser.add_argument("--verifier-process-control", required=True, type=Path)
    parser.add_argument("--verifier-runtime-trace", required=True, type=Path)
    parser.add_argument("--prepublication-guard", required=True, type=Path)
    parser.add_argument("--supervisor-bootstrap", required=True, type=Path)
    parser.add_argument("--staging-dir", required=True, type=Path)
    parser.add_argument("--expected-bundle-manifest-sha256", required=True)
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument("--expected-registry-digest", required=True)
    parser.add_argument("--expected-ldconfig-sha256", required=True)
    parser.add_argument("--expected-runtime-open-index-sha256", required=True)
    parser.add_argument("--expected-strace-sha256", required=True)
    parser.add_argument("--recovery-outer-unit-fd")
    parser.add_argument("--expected-recovery-outer-unit-sha256")
    return parser


def _load_recovery_outer_unit(arguments: argparse.Namespace) -> dict[str, Any] | None:
    supplied = arguments.recovery_outer_unit_fd is not None
    if supplied != (arguments.expected_recovery_outer_unit_sha256 is not None):
        raise PublishError("recovery outer unit descriptor pair is incomplete")
    if not supplied:
        return None
    if (
        fcntl is None
        or not isinstance(arguments.recovery_outer_unit_fd, str)
        or re.fullmatch(r"[3-9]|[1-9][0-9]+", arguments.recovery_outer_unit_fd)
        is None
        or HEX64.fullmatch(arguments.expected_recovery_outer_unit_sha256) is None
    ):
        raise PublishError("recovery outer unit descriptor is invalid")
    descriptor = int(arguments.recovery_outer_unit_fd)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 0
            or metadata.st_size <= 0
            or metadata.st_size > 2 * 1024 * 1024
            or os.get_inheritable(descriptor) is not True
        ):
            raise PublishError("recovery outer unit memfd metadata is invalid")
        required_seals = (
            getattr(fcntl, "F_SEAL_SEAL", 0x0001)
            | getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
            | getattr(fcntl, "F_SEAL_GROW", 0x0004)
            | getattr(fcntl, "F_SEAL_WRITE", 0x0008)
        )
        if (
            fcntl.fcntl(
                descriptor, getattr(fcntl, "F_GET_SEALS", 1034)
            )
            != required_seals
        ):
            raise PublishError("recovery outer unit memfd is not fully sealed")
        payload = bytearray()
        while len(payload) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(payload))
            if not chunk:
                raise PublishError("recovery outer unit memfd changed during read")
            payload.extend(chunk)
        if (
            os.read(descriptor, 1)
            or os.fstat(descriptor).st_size != metadata.st_size
            or hashlib.sha256(payload).hexdigest()
            != arguments.expected_recovery_outer_unit_sha256
        ):
            raise PublishError("recovery outer unit memfd identity drifted")
        return parse_json(bytes(payload), label="recovery outer unit")
    finally:
        os.close(descriptor)


def _remove_staging_dir(
    path: Path, *, expected_files: set[str], allow_subset: bool = False
) -> None:
    path = path.absolute()
    if path.parent != STAGING_PARENT or SAFE_NAME.fullmatch(path.name) is None:
        raise PublishError("publisher staging path is unsafe")
    if not os.path.lexists(path):
        return
    actual = {item.name for item in path.iterdir()}
    if (not allow_subset and actual != expected_files) or not actual <= expected_files:
        raise PublishError("publisher staging file set is invalid")
    for name in sorted(actual):
        child = path / name
        metadata = child.lstat()
        if (
            child.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode)
            not in ({0o600} if os.name == "posix" else {0o600, 0o666})
            or metadata.st_nlink != 1
        ):
            raise PublishError("publisher staging member is unsafe")
        child.unlink()
    path.rmdir()
    _fsync_directory(path.parent)


def _validate_existing_anchor_for_stage_cleanup(
    anchor_path: Path,
    *,
    evidence: Path,
    expected_release_identity: Mapping[str, Any],
    expected_bundle_manifest_sha256: str,
    expected_ldconfig_sha256: str,
    expected_runtime_open_index_sha256: str,
    expected_strace_sha256: str,
    validated_payload: bytes | None = None,
) -> None:
    payload = validated_payload
    if payload is None:
        payload = stable_read(
            anchor_path,
            label="existing durable evidence anchor",
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o400}),
        )
    document = parse_json(payload, label="existing durable evidence anchor")
    fields = {
        "schema_version",
        "anchor_type",
        "bundle_path",
        "bundle_manifest_sha256",
        "release_identity",
        "closure_identity",
        "validation_report",
        "validation_report_sha256",
        "cleanup_receipt",
        "cleanup_receipt_sha256",
        "verifier_child",
        "verifier_child_sha256",
        "verifier_process_control",
        "verifier_process_control_sha256",
        "verifier_runtime_trace",
        "verifier_runtime_trace_sha256",
        "prepublication_guard",
        "prepublication_guard_sha256",
        "supervisor_bootstrap",
        "supervisor_bootstrap_sha256",
        "publisher_cgroup",
        "final_publication",
        "frozen_evidence_identity",
        "verifier_runtime_trace_reverification",
        "cleanup_completed_before_anchor",
        "production_promotion_allowed",
    }
    hashed = (
        ("validation_report", "validation_report_sha256"),
        ("cleanup_receipt", "cleanup_receipt_sha256"),
        ("verifier_child", "verifier_child_sha256"),
        ("verifier_process_control", "verifier_process_control_sha256"),
        ("verifier_runtime_trace", "verifier_runtime_trace_sha256"),
        ("prepublication_guard", "prepublication_guard_sha256"),
        ("supervisor_bootstrap", "supervisor_bootstrap_sha256"),
    )
    report = document.get("validation_report")
    frozen = document.get("frozen_evidence_identity")
    publication_unit = (
        frozen.get("publication_outer_unit_reverification")
        if type(frozen) is dict
        else None
    )
    frozen_outer_unit = frozen.get("outer_unit") if type(frozen) is dict else None
    final_publication = document.get("final_publication")
    verifier_trace_reverification = document.get(
        "verifier_runtime_trace_reverification"
    )
    supervisor_bootstrap = document.get("supervisor_bootstrap")
    bootstrap_files = (
        supervisor_bootstrap.get("files")
        if type(supervisor_bootstrap) is dict
        else None
    )
    bootstrap_ldconfig = (
        bootstrap_files.get("ldconfig") if type(bootstrap_files) is dict else None
    )
    if (
        set(document) != fields
        or not _schema_version_is_one(document.get("schema_version"))
        or document.get("anchor_type")
        != "odoo-accounting-cli-v3.dev29.read-suite-verification"
        or document.get("bundle_path") != str(evidence)
        or document.get("bundle_manifest_sha256")
        != expected_bundle_manifest_sha256
        or document.get("release_identity") != expected_release_identity
        or HEX64.fullmatch(expected_ldconfig_sha256) is None
        or type(bootstrap_ldconfig) is not dict
        or bootstrap_ldconfig.get("sha256") != expected_ldconfig_sha256
        or type(report) is not dict
        or report.get("release_identity") != expected_release_identity
        or report.get("bundle_manifest_sha256")
        != expected_bundle_manifest_sha256
        or report.get("all_checks_passed") is not True
        or report.get("production_promotion_allowed") is not False
        or type(frozen) is not dict
        or frozen.get("path") != str(evidence)
        or frozen.get("bundle_manifest_sha256")
        != expected_bundle_manifest_sha256
        or type(frozen_outer_unit) is not dict
        or type(publication_unit) is not dict
        or set(publication_unit)
        != {
            "unit",
            "systemctl",
            "properties",
            "properties_sha256",
            "proc",
            "wrapper",
            "worker",
            "launcher_lease",
            "outer_unit",
            "outer_unit_sha256",
            "systemctl_execution",
            "all_checks_passed",
        }
        or publication_unit.get("unit") != frozen_outer_unit.get("unit")
        or publication_unit.get("systemctl") != frozen_outer_unit.get("systemctl")
        or publication_unit.get("properties") != frozen_outer_unit.get("properties")
        or publication_unit.get("proc") != frozen_outer_unit.get("proc")
        or publication_unit.get("outer_unit") != frozen_outer_unit
        or publication_unit.get("outer_unit_sha256")
        != hashlib.sha256(canonical_json(frozen_outer_unit)).hexdigest()
        or publication_unit.get("properties_sha256")
        != hashlib.sha256(
            canonical_json(frozen_outer_unit.get("properties"))
        ).hexdigest()
        or publication_unit.get("all_checks_passed") is not True
        or type(final_publication) is not dict
        or type(verifier_trace_reverification) is not dict
        or verifier_trace_reverification.get(
            "raw_trace_independently_reparsed_by_publisher"
        )
        is not True
        or verifier_trace_reverification.get("production_promotion_allowed")
        is not False
        or set(final_publication)
        != {
            "mode",
            "publisher_pid",
            "publisher_cgroup",
            "unit",
            "systemctl",
            "properties",
            "properties_sha256",
            "proc",
            "outer_unit",
            "outer_unit_sha256",
            "systemctl_execution",
            "publisher_script_execution",
            "resumed_pending_sha256",
            "staging_documents_sha256",
            "all_checks_passed",
        }
        or final_publication.get("mode") not in {"initial", "recovered_pending"}
        or type(final_publication.get("publisher_pid")) is not int
        or final_publication["publisher_pid"] <= 1
        or type(final_publication.get("publisher_cgroup")) is not dict
        or final_publication.get("unit") != frozen_outer_unit.get("unit")
        or final_publication.get("systemctl") != frozen_outer_unit.get("systemctl")
        or type(final_publication.get("properties")) is not dict
        or set(final_publication["properties"]) != set(SYSTEMD_UNIT_FIELDS)
        or final_publication.get("properties_sha256")
        != hashlib.sha256(
            canonical_json(final_publication["properties"])
        ).hexdigest()
        or type(final_publication.get("proc")) is not dict
        or type(final_publication.get("outer_unit")) is not dict
        or final_publication.get("outer_unit_sha256")
        != hashlib.sha256(
            canonical_json(final_publication.get("outer_unit"))
        ).hexdigest()
        or set(final_publication["proc"]) != {"argv", "argv_sha256", "cgroup"}
        or type(final_publication["proc"].get("argv")) is not list
        or not final_publication["proc"]["argv"]
        or final_publication["proc"].get("argv_sha256")
        != hashlib.sha256(
            canonical_json(final_publication["proc"]["argv"])
        ).hexdigest()
        or not isinstance(final_publication["proc"].get("cgroup"), str)
        or not isinstance(final_publication.get("properties_sha256"), str)
        or HEX64.fullmatch(final_publication["properties_sha256"]) is None
        or type(final_publication.get("systemctl_execution")) is not dict
        or type(final_publication.get("publisher_script_execution")) is not dict
        or not isinstance(final_publication.get("staging_documents_sha256"), str)
        or HEX64.fullmatch(final_publication["staging_documents_sha256"]) is None
        or final_publication.get("all_checks_passed") is not True
        or (
            final_publication.get("mode") == "initial"
            and final_publication.get("resumed_pending_sha256") is not None
        )
        or (
            final_publication.get("mode") == "recovered_pending"
            and (
                not isinstance(
                    final_publication.get("resumed_pending_sha256"), str
                )
                or HEX64.fullmatch(final_publication["resumed_pending_sha256"])
                is None
            )
        )
        or document.get("cleanup_completed_before_anchor") is not True
        or document.get("production_promotion_allowed") is not False
        or any(
            type(document.get(value_field)) is not dict
            or document.get(digest_field)
            != hashlib.sha256(canonical_json(document[value_field])).hexdigest()
            for value_field, digest_field in hashed
        )
    ):
        raise PublishError("existing durable anchor cannot authorize stage cleanup")
    _validate_publisher_script_execution(
        final_publication["publisher_script_execution"]
    )
    _reverify_private_runtime_trace_sidecar(
        evidence,
        frozen["runtime_open_trace_private"],
        expected_release=expected_release_identity["release"],
        required_targets=suite_runtime_trace_targets(),
    )
    _validate_verifier_runtime_trace(
        evidence,
        document["verifier_runtime_trace"],
        expected_release=expected_release_identity["release"],
        expected_release_manifest_semantic_sha256=(
            expected_release_identity["manifest_sha256"]
        ),
        expected_index_sha256=expected_runtime_open_index_sha256,
        expected_strace_sha256=expected_strace_sha256,
    )
    if validated_payload is None:
        _fsync_directory(anchor_path.parent)
        if stable_read(
            anchor_path,
            label="stable durable evidence anchor",
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o400}),
        ) != payload:
            raise PublishError(
                "durable evidence anchor changed during stage cleanup recovery"
            )


def _recover_validated_pending_anchor(
    anchor_path: Path,
    *,
    evidence: Path,
    documents: Mapping[str, dict[str, Any]],
    expected_release_identity: Mapping[str, Any],
    expected_bundle_manifest_sha256: str,
    expected_ldconfig_sha256: str,
    expected_runtime_open_index_sha256: str,
    expected_strace_sha256: str,
    publisher_script_execution: Mapping[str, Any],
    recovery_outer_unit: Mapping[str, Any],
) -> Path:
    _validate_publisher_script_execution(publisher_script_execution)
    pending = anchor_path.parent / f".{anchor_path.name}.pending"
    mapping = {
        "validation-report.json": "validation_report",
        "cleanup-receipt.json": "cleanup_receipt",
        "verifier-child.json": "verifier_child",
        "verifier-process-control.json": "verifier_process_control",
        "verifier-runtime-trace.json": "verifier_runtime_trace",
        "prepublication-guard.json": "prepublication_guard",
        "supervisor-bootstrap.json": "supervisor_bootstrap",
    }
    if set(documents) != set(mapping):
        raise PublishError("pending publication staging document set is invalid")
    lock = anchor_path.parent / f".{anchor_path.name}.lock"
    with _anchor_lock(lock, enforce_root=True):
        payload = _read_and_fsync_pending(pending, enforce_root=True)
        _validate_existing_anchor_for_stage_cleanup(
            pending,
            evidence=evidence,
            expected_release_identity=expected_release_identity,
            expected_bundle_manifest_sha256=expected_bundle_manifest_sha256,
            expected_ldconfig_sha256=expected_ldconfig_sha256,
            expected_runtime_open_index_sha256=(
                expected_runtime_open_index_sha256
            ),
            expected_strace_sha256=expected_strace_sha256,
            validated_payload=payload,
        )
        document = parse_json(payload, label="recoverable pending evidence anchor")
        if any(document[field] != documents[name] for name, field in mapping.items()):
            raise PublishError("pending anchor differs from retained staging documents")
        report = document["validation_report"]
        cleanup = document["cleanup_receipt"]
        closure_verification = report.get("closure_verification")
        if type(closure_verification) is not dict:
            raise PublishError("pending anchor closure verification is invalid")
        _prove_cleanup_live(cleanup, closure=closure_verification)
        current_evidence = _evidence_identity(
            evidence,
            expected_bundle_manifest_sha256=expected_bundle_manifest_sha256,
            expected_release_identity=expected_release_identity,
            closure_verification=closure_verification,
            enforce_root=True,
        )
        _reverify_private_runtime_trace_sidecar(
            evidence,
            current_evidence["runtime_open_trace_private"],
            expected_release=expected_release_identity["release"],
            required_targets=suite_runtime_trace_targets(),
        )
        _validate_verifier_runtime_trace(
            evidence,
            documents["verifier-runtime-trace.json"],
            expected_release=expected_release_identity["release"],
            expected_release_manifest_semantic_sha256=(
                expected_release_identity["manifest_sha256"]
            ),
            expected_index_sha256=expected_runtime_open_index_sha256,
            expected_strace_sha256=expected_strace_sha256,
        )
        anchored_evidence = document["frozen_evidence_identity"]
        anchored_without_publication = {
            key: value
            for key, value in anchored_evidence.items()
            if key != "publication_outer_unit_reverification"
        }
        if current_evidence != anchored_without_publication:
            raise PublishError("pending anchor frozen evidence identity drifted")
        live_cgroup = _prove_supervisor_cgroup()
        recovery_unit = _reverify_recovery_outer_unit(
            anchored_evidence["outer_unit"],
            recovery_outer_unit,
            live_cgroup=live_cgroup,
        )
        document["final_publication"] = {
            "mode": "recovered_pending",
            "publisher_pid": os.getpid(),
            "publisher_cgroup": live_cgroup,
            "unit": recovery_unit["unit"],
            "systemctl": recovery_unit["systemctl"],
            "properties": recovery_unit["properties"],
            "properties_sha256": recovery_unit["properties_sha256"],
            "proc": recovery_unit["proc"],
            "systemctl_execution": recovery_unit["systemctl_execution"],
            "outer_unit": recovery_unit["outer_unit"],
            "outer_unit_sha256": recovery_unit["outer_unit_sha256"],
            "publisher_script_execution": dict(publisher_script_execution),
            "resumed_pending_sha256": hashlib.sha256(payload).hexdigest(),
            "staging_documents_sha256": hashlib.sha256(
                canonical_json(documents)
            ).hexdigest(),
            "all_checks_passed": True,
        }
        recovered_payload = canonical_json(document) + b"\n"
        result = _publish_recovery_payload_locked(anchor_path, recovered_payload)
        _remove_pending_anchor(pending, enforce_root=True, allow_absent=False)
        _fsync_directory(anchor_path.parent)
        return result


def main(argv: Iterable[str] | None = None) -> int:
    if (
        os.name != "posix"
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or Path(sys.executable).resolve(strict=True) != Path(CLOSURE_PYTHON)
        or Path("/proc/self/exe").resolve(strict=True) != Path(CLOSURE_PYTHON)
    ):
        print("Dev29 publisher refused: /usr/bin/python3.12 -I -S is required", file=sys.stderr)
        return 2
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    expected = {
        "release": arguments.expected_release,
        "version": arguments.expected_version,
        "commit": arguments.expected_commit,
        "manifest_sha256": arguments.expected_manifest_sha256,
        "package_sha256": arguments.expected_package_sha256,
        "registry_digest": arguments.expected_registry_digest,
        "verified": True,
    }
    stage_files = {
        "validation-report.json",
        "cleanup-receipt.json",
        "verifier-child.json",
        "verifier-process-control.json",
        "verifier-runtime-trace.json",
        "prepublication-guard.json",
        "supervisor-bootstrap.json",
    }
    stage_validated = False
    published = False
    try:
        if HEX40.fullmatch(expected["commit"]) is None or any(
            HEX64.fullmatch(expected[field]) is None
            for field in ("manifest_sha256", "package_sha256", "registry_digest")
        ) or any(
            HEX64.fullmatch(value) is None
            for value in (
                arguments.expected_ldconfig_sha256,
                arguments.expected_runtime_open_index_sha256,
                arguments.expected_strace_sha256,
            )
        ):
            raise PublishError("expected release identity is invalid")
        if (
            SAFE_NAME.fullmatch(expected["release"]) is None
            or VERSION.fullmatch(expected["version"]) is None
            or expected["release"]
            != f"{expected['version']}-{expected['commit'][:12]}"
        ):
            raise PublishError("expected release naming identity is invalid")
        publisher_script_execution = _validate_publisher_process(
            expected["release"]
        )
        recovery_outer_unit = _load_recovery_outer_unit(arguments)
        if (
            _bootstrap_file(LDCONFIG, allowed_modes=frozenset({0o755}))["sha256"]
            != arguments.expected_ldconfig_sha256
        ):
            raise PublishError("expected ldconfig identity is invalid")
        stage = arguments.staging_dir.absolute()
        if (
            stage.parent != STAGING_PARENT
            or stage.name != arguments.evidence_dir.name
            or not stage.is_dir()
            or stage.is_symlink()
        ):
            raise PublishError("publisher staging directory is invalid")
        _safe_root_chain(stage, final_mode=0o700)
        supplied = {
            arguments.validation_report.name: arguments.validation_report,
            arguments.cleanup_receipt.name: arguments.cleanup_receipt,
            arguments.verifier_child.name: arguments.verifier_child,
            arguments.verifier_process_control.name: arguments.verifier_process_control,
            arguments.verifier_runtime_trace.name: arguments.verifier_runtime_trace,
            arguments.prepublication_guard.name: arguments.prepublication_guard,
            arguments.supervisor_bootstrap.name: arguments.supervisor_bootstrap,
        }
        if set(supplied) != stage_files or any(
            path.absolute().parent != stage or path.name != name
            for name, path in supplied.items()
        ):
            raise PublishError("publisher staging arguments are invalid")
        actual_stage_files = {item.name for item in stage.iterdir()}
        anchor = ANCHOR_PARENT / f"{arguments.evidence_dir.name}.json"
        pending = ANCHOR_PARENT / f".{arguments.evidence_dir.name}.json.pending"
        if os.path.lexists(anchor):
            if not actual_stage_files <= stage_files:
                raise PublishError("publisher staging file set is invalid")
            _validate_existing_anchor_for_stage_cleanup(
                anchor,
                evidence=arguments.evidence_dir.absolute(),
                expected_release_identity=expected,
                expected_bundle_manifest_sha256=(
                    arguments.expected_bundle_manifest_sha256
                ),
                expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
                expected_runtime_open_index_sha256=(
                    arguments.expected_runtime_open_index_sha256
                ),
                expected_strace_sha256=arguments.expected_strace_sha256,
                publisher_script_execution=publisher_script_execution,
            )
            for leftover in (
                pending,
                ANCHOR_PARENT
                / f".{arguments.evidence_dir.name}.json.recovery.pending",
            ):
                if os.path.lexists(leftover):
                    _remove_pending_anchor(leftover, enforce_root=True)
            _fsync_directory(ANCHOR_PARENT)
            _remove_staging_dir(
                stage, expected_files=stage_files, allow_subset=True
            )
            print(
                canonical_json(
                    {
                        "anchor_path": str(anchor),
                        "published": True,
                        "staging_cleanup_recovered": True,
                    }
                ).decode("utf-8")
            )
            return 0
        if os.path.lexists(pending):
            if recovery_outer_unit is None:
                raise PublishError("pending recovery outer unit proof is absent")
            if actual_stage_files != stage_files:
                raise PublishError(
                    "pending anchor recovery requires the complete staging set"
                )
            documents = {
                name: parse_json(
                    stable_read(
                        path,
                        label=name,
                        expected_uid=0,
                        expected_gid=0,
                        allowed_modes=frozenset({0o600}),
                    ),
                    label=name,
                )
                for name, path in supplied.items()
            }
            anchor = _recover_validated_pending_anchor(
                anchor,
                evidence=arguments.evidence_dir.absolute(),
                documents=documents,
                expected_release_identity=expected,
                expected_bundle_manifest_sha256=(
                    arguments.expected_bundle_manifest_sha256
                ),
                expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
                expected_runtime_open_index_sha256=(
                    arguments.expected_runtime_open_index_sha256
                ),
                expected_strace_sha256=arguments.expected_strace_sha256,
                publisher_script_execution=publisher_script_execution,
                recovery_outer_unit=recovery_outer_unit,
            )
            _remove_staging_dir(stage, expected_files=stage_files)
            print(
                canonical_json(
                    {
                        "anchor_path": str(anchor),
                        "published": True,
                        "pending_anchor_recovered": True,
                        "staging_cleanup_recovered": True,
                    }
                ).decode("utf-8")
            )
            return 0
        if actual_stage_files != stage_files:
            raise PublishError("publisher staging file set is invalid")
        documents = {
            name: parse_json(
                stable_read(
                    path,
                    label=name,
                    expected_uid=0,
                    expected_gid=0,
                    allowed_modes=frozenset({0o600}),
                ),
                label=name,
            )
            for name, path in supplied.items()
        }
        stage_validated = True
        report = documents["validation-report.json"]
        cleanup = documents["cleanup-receipt.json"]
        child = documents["verifier-child.json"]
        control = documents["verifier-process-control.json"]
        verifier_trace = documents["verifier-runtime-trace.json"]
        guard = documents["prepublication-guard.json"]
        bootstrap = documents["supervisor-bootstrap.json"]
        anchor = publish(
            arguments.evidence_dir,
            report,
            cleanup,
            child,
            control,
            verifier_trace,
            guard,
            bootstrap,
            expected_bundle_manifest_sha256=arguments.expected_bundle_manifest_sha256,
            expected_release_identity=expected,
            expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
            expected_runtime_open_index_sha256=(
                arguments.expected_runtime_open_index_sha256
            ),
            expected_strace_sha256=arguments.expected_strace_sha256,
            publisher_script_execution=publisher_script_execution,
        )
        published = True
    except (OSError, PublishError) as exc:
        print(f"Dev29 publisher refused: {exc}", file=sys.stderr)
        return 2
    finally:
        if stage_validated and published:
            try:
                _remove_staging_dir(arguments.staging_dir, expected_files=stage_files)
            except (OSError, PublishError) as exc:
                print(f"Dev29 publisher staging cleanup failed: {exc}", file=sys.stderr)
                return 2
    print(canonical_json({"anchor_path": str(anchor), "published": True}).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/python3 -I
"""Run exactly one Dev15 read and freeze a manifest-bound evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, Iterable


RELEASE = "0.1.0.dev15-c4616386f921"
RELEASE_ROOT = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE
LAUNCHER = RELEASE_ROOT / "bin/odoo-accounting-cli-v3"
TOOLCHAIN_VERSION = "0.1.0.dev15-read-toolchain.1"
TOOLCHAIN_ROOT = Path("/opt/odoo-accounting-cli-v3/toolchains") / TOOLCHAIN_VERSION
TOOLCHAIN_MANIFEST = TOOLCHAIN_ROOT / "TOOLCHAIN-MANIFEST.json"
TOOLCHAIN_FILES = (
    "install_toolchain.py", "runtime_setup.py", "sign_read.py",
    "run_multicurrency_read.py", "multicurrency_sql_oracle.py",
    "verify_evidence.py", "read_plan.json",
)
TOOLCHAIN_CONTROL_FILES = ("README.md", "check_toolchain.py")
RUNTIME_CONFIG = (
    Path("/etc/odoo-accounting-cli-v3/candidates")
    / "runtime-test-dev15-c4616386f921.json"
)
COMMITTED_PLAN = TOOLCHAIN_ROOT / "read_plan.json"
SIGNER = TOOLCHAIN_ROOT / "sign_read.py"
ORACLE = TOOLCHAIN_ROOT / "multicurrency_sql_oracle.py"
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
CAPABILITY_ID = "acct.multicurrency.balance_read.v1"
READ_PLAN_SHA256 = "860de4fb5b4efe41f760295b0b8eee4ae8b63f15d70e25e418640c8eb5f04c80"
PACKAGE_SHA256 = "71d9bcea9c89b9ab2877406ca28b039791d380d0aeb09c60516a83b031b9c8bf"
MANIFEST_SHA256 = "f4ea1dbd6e6b57472875d27a64504ffb433812c568bcd7be546d2e5074d24be2"
REGISTRY_DIGEST = "ae50c3aa8d93472b7d58ca656ea9b2a42e18e5a38a9df0919320737b5632789b"
COMMIT = "c4616386f921946cf43cde2de449d2938a837422"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_BUNDLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
ORACLE_PYTHON = Path("/usr/bin/python3.12")
ORACLE_PYTHON_SHA256 = "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118"
ORACLE_PSQL = Path("/usr/lib/postgresql/16/bin/psql")
ORACLE_PSQL_SHA256 = "6d593ef8e95e5275691fcc28927cc540282db141ca1ec5e3806e7db5523613cb"
EXPECTED_V2_COMBINED_DIGEST = "eb4b194e034fba683794c5d5fd39707588e88fda569f3ac1c982e4b7c23aa891"
EXPECTED_V2_COMBINED_COUNT = 668
HISTORICAL_V2_DIGEST = "1d258235a87bb23d42bd49f5b2055fca4be78ed9e81063b0378d31e3f4696812"
V2_ROOTS = (
    (
        "tools_v2",
        Path("/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2"),
        576,
        "860c26d2bca049c46de6696598202de514b2d66c08657a2296d18fd9e210caf1",
    ),
    (
        "pi_bridge_v2_package",
        Path(
        "/mnt/odoo/odoo19/custom/services/pi-agent-bridge/"
            "odoo_accounting_agent_cli_v2/src/odoo_acc_cli"
        ),
        92,
        "fd2d28fb28c21e983a08d594f31f32f3867ca2ea5c2c4e004f7807ee7cdd5cf9",
    ),
)
PI_CONTROL_ROOTS = {
    "pi_bridge_systemd": Path("/etc/systemd/system"),
    "pi_bridge_control": Path("/mnt/odoo/odoo19/custom/services/pi-agent-bridge"),
}
PI_CONTROL_FILES = (
    ("pi_bridge_systemd", "sudo-pi-agent-bridge.service"),
    ("pi_bridge_control", "server.mjs"),
    ("pi_bridge_control", "extensions/odoo-tools.ts"),
    ("pi_bridge_control", "package.json"),
    ("pi_bridge_control", "package-lock.json"),
)
EXPECTED_PI_CONTROL_DIGEST = "52fb10453c439d7f3877d0208f335023bef0952a3911c049ab06e64e09974b62"
SERVICES = ("odoo19.service", "sudo-pi-agent-bridge.service")
V3_UNIT_FILES = (
    Path("/etc/systemd/system/odoo-accounting-cli-v3-broker.service"),
    Path("/etc/systemd/system/odoo-accounting-cli-v3-pi-broker.socket"),
    Path("/etc/systemd/system/odoo-accounting-cli-v3-session-mint.socket"),
    Path("/etc/systemd/system/odoo-accounting-cli-v3-trusted-approval.socket"),
    Path("/etc/systemd/system/odoo-accounting-cli-v3-pi-bridge.service"),
    Path("/etc/systemd/system/odoo-accounting-cli-v3-pi-bridge.socket"),
)
V3_CURRENT = Path("/opt/odoo-accounting-cli-v3/current")
V3_UNIT_FIELDS = (
    "Id", "Names", "LoadState", "ActiveState", "SubState", "FragmentPath",
    "SourcePath", "UnitFileState", "UnitFilePreset",
)
V3_UNIT_PREFIX = "odoo-accounting-cli-v3-"
SYSTEMD_ANALYZE = Path("/usr/bin/systemd-analyze")
SYSTEMCTL = Path("/usr/bin/systemctl")
SYSTEMD_SUPPLEMENTAL_PATHS = (
    "/etc/systemd/system", "/etc/systemd/system.attached",
    "/etc/systemd/system.control", "/run/systemd/system",
    "/run/systemd/system.attached", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/run/systemd/generator", "/run/systemd/generator.late",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system",
)
SKIP_DIRECTORIES = frozenset(
    {
        ".git", "__pycache__", "node_modules", "backups", "backup", "_backups",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv",
        ".venv_docx", "build", "dist", "outputs", "snapshots", "tmp", ".tox",
        ".eggs",
    }
)
SKIP_SUFFIXES = ("~", ".bak", ".backup", ".orig", ".rej", ".pyc", ".pyo")
MAX_JSON_BYTES = 16 * 1024 * 1024
BUNDLE_FILES = frozenset(
    {
        "exit", "oracle.exit", "oracle.json", "oracle.stderr", "read-plan.json",
        "receipt.json", "request.json", "response.json", "signer.exit",
        "signer.stderr", "state-post.json", "state-pre.json", "stderr",
        "system-post.json", "system-pre.json",
    }
)
BUNDLE_MANIFEST = "BUNDLE-MANIFEST.json"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(payload: bytes, *, label: str) -> dict[str, Any]:
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError(f"{label} is too large")
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_uid, metadata.st_gid, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def stable_read(
    path: Path, *, label: str, maximum: int = MAX_JSON_BYTES,
    expected_uid: int | None = None, expected_gid: int | None = None,
    expected_mode: int | None = None, allow_empty: bool = False,
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"{label} must be a one-link regular file")
        if before.st_size > maximum or (before.st_size == 0 and not allow_empty):
            raise ValueError(f"{label} size is invalid")
        if expected_uid is not None and before.st_uid != expected_uid:
            raise ValueError(f"{label} owner is invalid")
        if expected_gid is not None and before.st_gid != expected_gid:
            raise ValueError(f"{label} group is invalid")
        if expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode:
            raise ValueError(f"{label} mode is invalid")
        identity = _fingerprint(before)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"{label} changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or _fingerprint(os.fstat(descriptor)) != identity:
            raise ValueError(f"{label} identity changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | getattr(os, "O_BINARY", 0) | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def write_json(path: Path, value: Any) -> None:
    write_private(path, canonical_json(value) + b"\n")


def _safe_root_chain(path: Path, *, final_mode: int | None = None) -> None:
    current = Path("/")
    for component in path.absolute().parts[1:]:
        current /= component
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode) or current.is_symlink()
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not stat.S_IMODE(metadata.st_mode) & 0o111
        ):
            raise PermissionError(f"unsafe root-owned directory chain: {current}")
    if final_mode is not None and stat.S_IMODE(path.lstat().st_mode) != final_mode:
        raise PermissionError(f"directory mode is not {final_mode:04o}: {path}")


def fixed_executable_snapshot(path: Path, expected_sha256: str) -> dict[str, Any]:
    path = Path(path).absolute()
    if HEX64.fullmatch(expected_sha256) is None:
        raise ValueError("fixed executable SHA-256 is invalid")
    if os.name == "posix":
        _safe_root_chain(path.parent)
    payload = stable_read(
        path, label=f"fixed executable {path}", maximum=64 * 1024 * 1024,
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        expected_mode=0o755 if os.name == "posix" else None,
    )
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_sha256:
        raise ValueError(f"fixed executable SHA-256 mismatch: {path}")
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"fixed executable path is unsafe: {path}")
    return {
        "path": str(path), "sha256": digest,
        "uid": metadata.st_uid, "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def verify_oracle_executables(plan: dict[str, Any]) -> dict[str, Any]:
    database = plan.get("database")
    if not isinstance(database, dict) or any(
        database.get(key) != value
        for key, value in {
            "oracle_python": str(ORACLE_PYTHON),
            "oracle_python_sha256": ORACLE_PYTHON_SHA256,
            "oracle_psql": str(ORACLE_PSQL),
            "oracle_psql_sha256": ORACLE_PSQL_SHA256,
        }.items()
    ):
        raise ValueError("read plan Oracle executable binding is invalid")
    return {
        "python": fixed_executable_snapshot(ORACLE_PYTHON, ORACLE_PYTHON_SHA256),
        "psql": fixed_executable_snapshot(ORACLE_PSQL, ORACLE_PSQL_SHA256),
    }


def create_evidence_directory(
    path: Path, *, enforce_root: bool = True,
    expected_parent: Path = EVIDENCE_PARENT,
) -> Path:
    path = Path(path).absolute()
    expected_parent = Path(expected_parent).absolute()
    if (
        path == Path("/")
        or path.parent != expected_parent
        or SAFE_BUNDLE_NAME.fullmatch(path.name) is None
    ):
        raise ValueError("evidence directory must be a direct child of the fixed parent")
    if os.path.lexists(path):
        raise FileExistsError("evidence directory must not already exist")
    if enforce_root and os.name == "posix":
        _safe_root_chain(expected_parent)
    os.mkdir(path, 0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("evidence directory is not canonical")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("new evidence directory is not mode 0700")
    if enforce_root and os.name == "posix" and (metadata.st_uid, metadata.st_gid) != (0, 0):
        raise PermissionError("evidence directory must be root:root")
    _fsync_directory(path.parent)
    return path


def _source_member(path: Path) -> bool:
    name = path.name.lower()
    return not name.endswith(SKIP_SUFFIXES)


def source_tree_snapshot(
    component: str, root: Path, *, expected_count: int, expected_digest: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise ValueError(f"V2 source root is unsafe: {root}")
    members: list[dict[str, Any]] = []
    for directory_text, directories, names in os.walk(root, topdown=True, followlinks=False):
        for name in directories:
            path = Path(directory_text) / name
            child = path.lstat()
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                raise ValueError(f"unsafe directory object in V2 source tree: {path}")
        directories[:] = sorted(
            name for name in directories
            if name not in SKIP_DIRECTORIES
        )
        for name in sorted(names):
            path = Path(directory_text) / name
            child = path.lstat()
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISREG(child.st_mode):
                raise ValueError(f"unsafe object in V2 source tree: {path}")
            if not _source_member(path):
                continue
            relative = path.relative_to(root).as_posix()
            payload = stable_read(
                path, label=f"V2 source {relative}", maximum=64 * 1024 * 1024,
                allow_empty=True,
            )
            members.append(
                {
                    "component": component,
                    "path": relative,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
    members.sort(key=lambda item: (item["component"], item["path"]))
    digest = hashlib.sha256(canonical_json(members)).hexdigest()
    if len(members) != expected_count or digest != expected_digest:
        raise ValueError(f"{component} V2 source baseline drift")
    return {
        "component": component,
        "root": str(root),
        "algorithm": "canonical-json(component,path,sha256,size)-sha256-v1",
        "count": len(members),
        "paths": [item["path"] for item in members],
        "digest": digest,
    }, members


def fixed_file_snapshot(component: str, relative: str) -> dict[str, Any]:
    path = PI_CONTROL_ROOTS[component] / relative
    payload = stable_read(path, label=f"fixed source {path}", maximum=64 * 1024 * 1024)
    return {
        "component": component, "path": relative, "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def service_identity(unit: str) -> dict[str, Any]:
    fields = (
        "Id", "LoadState", "ActiveState", "SubState", "MainPID", "InvocationID",
        "ExecMainStartTimestamp", "ExecMainStartTimestampMonotonic", "FragmentPath",
        "ControlGroup", "User", "Group",
    )
    completed = subprocess.run(
        [
            "/usr/bin/systemctl", "show", unit,
            *[f"--property={field}" for field in fields],
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if completed.returncode != 0 or completed.stderr:
        raise ValueError(f"cannot capture service identity: {unit}")
    values: dict[str, str] = {}
    for line in completed.stdout.decode("utf-8", "strict").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    if set(values) != set(fields):
        raise ValueError(f"service identity fields are incomplete: {unit}")
    if values["LoadState"] != "loaded" or values["ActiveState"] != "active":
        raise ValueError(f"baseline service is not active: {unit}")
    return {"unit": unit, "properties": values}


def unit_absence(path: Path) -> dict[str, Any]:
    unit = path.name
    completed = subprocess.run(
        [
            "/usr/bin/systemctl", "show", unit,
            *[f"--property={field}" for field in V3_UNIT_FIELDS],
        ],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=15,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if completed.returncode != 0 or completed.stderr:
        raise ValueError(f"cannot prove V3 systemd unit absence: {unit}")
    values: dict[str, str] = {}
    for line in completed.stdout.decode("utf-8", "strict").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    expected = {
        "Id": unit, "Names": unit, "LoadState": "not-found",
        "ActiveState": "inactive", "SubState": "dead", "FragmentPath": "",
        "SourcePath": "", "UnitFileState": "", "UnitFilePreset": "",
    }
    if values != expected or os.path.lexists(path):
        raise ValueError(f"V3 systemd unit is present or loaded: {unit}")
    return {
        "path": str(path), "file_absent": True, "unit": unit,
        "properties": values,
    }


def _systemd_command_lines(
    command: list[str], *, command_runner: Callable[..., Any], label: str,
    allow_empty_no_match: bool = False,
) -> list[str]:
    completed = command_runner(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        timeout=15, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    empty_no_match = (
        allow_empty_no_match
        and completed.returncode == 1
        and completed.stdout == b""
        and completed.stderr == b""
    )
    if (completed.returncode != 0 and not empty_no_match) or completed.stderr:
        raise ValueError(f"cannot capture {label}")
    try:
        lines = completed.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not strict UTF-8") from exc
    if any(not line.strip() for line in lines):
        raise ValueError(f"{label} contains an empty record")
    return lines


def _residue_kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular_file"
    return "special"


def _systemd_target_guards_unchanged(
    guards: tuple[tuple[str, tuple[int, ...] | None, str | None], ...],
) -> bool:
    for raw_path, fingerprint, raw_target in guards:
        path = Path(raw_path)
        if fingerprint is None:
            if os.path.lexists(path):
                return False
            continue
        try:
            metadata = path.lstat()
            if _fingerprint(metadata) != fingerprint:
                return False
            if raw_target is not None and (
                not stat.S_ISLNK(metadata.st_mode)
                or os.readlink(path) != raw_target
            ):
                return False
            if raw_target is None and stat.S_ISLNK(metadata.st_mode):
                return False
        except OSError:
            return False
    return True


def _systemd_symlink_target(
    entry_path: Path,
) -> tuple[
    bool, bool, tuple[tuple[str, tuple[int, ...] | None, str | None], ...]
]:
    """Resolve every path-component symlink and freeze the complete chain."""

    absolute = Path(os.path.abspath(os.fspath(entry_path)))
    current = Path(absolute.anchor)
    pending = list(absolute.parts[1:])
    seen: set[tuple[int, int]] = set()
    guards: list[tuple[str, tuple[int, ...] | None, str | None]] = []
    target_alias = False
    hops = 0
    while pending:
        component = pending.pop(0)
        candidate = current / component
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            current = candidate.joinpath(*pending)
            pending.clear()
            break
        except OSError as exc:
            raise ValueError(
                f"cannot inspect systemd symlink target: {candidate}"
            ) from exc
        if not stat.S_ISLNK(metadata.st_mode):
            current = candidate
            continue
        hops += 1
        if hops > 64:
            raise ValueError(f"systemd symlink chain is too deep: {entry_path}")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen:
            raise ValueError(f"systemd symlink loop is forbidden: {entry_path}")
        seen.add(identity)
        try:
            raw_target = os.readlink(candidate)
        except OSError as exc:
            raise ValueError(f"cannot read systemd symlink: {candidate}") from exc
        target = Path(raw_target)
        if not target.is_absolute():
            target = candidate.parent / target
        target = Path(os.path.abspath(os.fspath(target)))
        target_alias = target_alias or any(
            part.startswith(V3_UNIT_PREFIX)
            for path in (candidate, Path(raw_target), target)
            for part in path.parts
        )
        guards.append((str(candidate), _fingerprint(metadata), raw_target))
        current = Path(target.anchor)
        pending = [*target.parts[1:], *pending]

    final_path = current
    target_alias = target_alias or any(
        part.startswith(V3_UNIT_PREFIX) for part in final_path.parts
    )
    try:
        final_metadata = final_path.lstat()
    except FileNotFoundError:
        final_metadata = None
        guards.append((str(final_path), None, None))
    except OSError as exc:
        raise ValueError(
            f"cannot inspect final systemd symlink target: {final_path}"
        ) from exc
    else:
        if stat.S_ISLNK(final_metadata.st_mode):
            raise ValueError(f"systemd symlink resolution changed: {entry_path}")
        guards.append((str(final_path), _fingerprint(final_metadata), None))
    frozen = tuple(guards)
    if not _systemd_target_guards_unchanged(frozen):
        raise ValueError(f"systemd symlink changed during scan: {entry_path}")
    return target_alias, (
        final_metadata is not None and stat.S_ISDIR(final_metadata.st_mode)
    ), frozen


def _systemd_directory_inventory(
    directory: Path,
) -> tuple[
    list[tuple[Path, os.stat_result, str | None]],
    tuple[tuple[str, tuple[int, ...], str | None], ...],
    tuple[int, ...],
]:
    metadata = directory.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ValueError(f"systemd directory changed during scan: {directory}")
    directory_fingerprint = _fingerprint(metadata)
    try:
        with os.scandir(directory) as scanned:
            names = sorted(entry.name for entry in scanned)
        entries: list[tuple[Path, os.stat_result, str | None]] = []
        inventory: list[tuple[str, tuple[int, ...], str | None]] = []
        for name in names:
            entry_path = directory / name
            entry_metadata = entry_path.lstat()
            target = (
                os.readlink(entry_path)
                if stat.S_ISLNK(entry_metadata.st_mode)
                else None
            )
            entries.append((entry_path, entry_metadata, target))
            inventory.append((name, _fingerprint(entry_metadata), target))
    except OSError as exc:
        raise ValueError(f"cannot inventory systemd directory: {directory}") from exc
    return entries, tuple(inventory), directory_fingerprint


def systemd_residue_snapshot(
    *, command_runner: Callable[..., Any] = subprocess.run,
    unit_paths: Iterable[str] | None = None,
    supplemental_paths: Iterable[str] = SYSTEMD_SUPPLEMENTAL_PATHS,
    enforce_root: bool = True,
) -> dict[str, Any]:
    loaded_units = _systemd_command_lines(
        [
            str(SYSTEMCTL), "list-units", "--all", "--plain", "--no-legend",
            "--no-pager", "--full", f"{V3_UNIT_PREFIX}*",
        ],
        command_runner=command_runner, label="V3-prefixed loaded systemd units",
    )
    unit_files = _systemd_command_lines(
        [
            str(SYSTEMCTL), "list-unit-files", "--plain", "--no-legend",
            "--no-pager", "--full", f"{V3_UNIT_PREFIX}*",
        ],
        command_runner=command_runner, label="V3-prefixed systemd unit files",
        allow_empty_no_match=True,
    )
    analyzed = list(unit_paths) if unit_paths is not None else _systemd_command_lines(
        [str(SYSTEMD_ANALYZE), "unit-paths"], command_runner=command_runner,
        label="systemd unit search paths",
    )
    if not analyzed:
        raise ValueError("systemd unit search path inventory is empty")
    if any(not isinstance(value, str) or not value for value in analyzed):
        raise ValueError("systemd unit search path inventory is invalid")
    supplemental_values = list(supplemental_paths)
    if any(not isinstance(value, str) or not value for value in supplemental_values):
        raise ValueError("systemd supplemental path inventory is invalid")
    analyzed_paths = sorted(set(analyzed))
    supplements = sorted(set(supplemental_values))
    requested_paths = sorted(set(analyzed_paths + supplements))
    for value in requested_paths:
        if not isinstance(value, str) or not value:
            raise ValueError(f"systemd unit search root is invalid: {value!r}")
        path = Path(value)
        if (
            not path.is_absolute() or str(path) != value
            or ".." in path.parts
        ):
            raise ValueError(f"systemd unit search root is not canonical: {value!r}")

    absent_roots: list[str] = []
    roots_by_identity: dict[tuple[int, int], dict[str, Any]] = {}
    filesystem_residue: list[dict[str, Any]] = []
    for requested in requested_paths:
        if not os.path.lexists(requested):
            absent_roots.append(requested)
            continue
        try:
            canonical = Path(requested).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"cannot canonicalize systemd unit search root: {requested}") from exc
        if not canonical.is_absolute() or canonical.is_symlink():
            raise ValueError(f"unsafe systemd unit search root: {requested}")
        metadata = canonical.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"systemd unit search root is not a directory: {requested}")
        if enforce_root and os.name == "posix":
            _safe_root_chain(canonical)
        identity = (metadata.st_dev, metadata.st_ino)
        root = roots_by_identity.get(identity)
        if root is None:
            root = {
                "canonical_path": str(canonical), "aliases": [],
                "device": metadata.st_dev, "inode": metadata.st_ino,
            }
            roots_by_identity[identity] = root
        root["aliases"].append(requested)

    directory_guards: list[
        tuple[
            Path, tuple[int, ...],
            tuple[tuple[str, tuple[int, ...], str | None], ...],
        ]
    ] = []
    symlink_guards: list[
        tuple[
            Path,
            tuple[
                bool, bool,
                tuple[tuple[str, tuple[int, ...] | None, str | None], ...],
            ],
        ]
    ] = []
    alias_guards: list[tuple[str, tuple[int, int]]] = []
    for root in roots_by_identity.values():
        root["aliases"] = sorted(set(root["aliases"]))
        canonical = Path(root["canonical_path"])
        before = canonical.lstat()
        if (before.st_dev, before.st_ino) != (root["device"], root["inode"]):
            raise ValueError(f"systemd unit search root changed before scan: {canonical}")
        pending = [canonical]
        scanned_directories: list[
            tuple[
                Path, tuple[int, ...],
                tuple[tuple[str, tuple[int, ...], str | None], ...],
            ]
        ] = []
        while pending:
            directory = pending.pop()
            entries, inventory, directory_fingerprint = (
                _systemd_directory_inventory(directory)
            )
            for entry_path, metadata, target in entries:
                relative = entry_path.relative_to(canonical)
                target_alias = False
                directory_symlink = False
                if target is not None:
                    resolution = _systemd_symlink_target(entry_path)
                    target_alias, directory_symlink, _target_guards = resolution
                    symlink_guards.append((entry_path, resolution))
                named_residue = any(
                    part.startswith(V3_UNIT_PREFIX) for part in relative.parts
                )
                if named_residue or target_alias or directory_symlink:
                    filesystem_residue.append(
                        {
                            "root": str(canonical), "path": relative.as_posix(),
                            "kind": _residue_kind(metadata.st_mode), "target": target,
                        }
                    )
                elif stat.S_ISDIR(metadata.st_mode):
                    pending.append(entry_path)
            _after_entries, after_inventory, after_fingerprint = (
                _systemd_directory_inventory(directory)
            )
            if (
                after_fingerprint != directory_fingerprint
                or after_inventory != inventory
            ):
                raise ValueError(f"systemd directory changed during scan: {directory}")
            scanned_directories.append(
                (directory, directory_fingerprint, inventory)
            )
        for directory, fingerprint, inventory in scanned_directories:
            _entries, current_inventory, current_fingerprint = (
                _systemd_directory_inventory(directory)
            )
            if current_fingerprint != fingerprint or current_inventory != inventory:
                raise ValueError(f"systemd directory changed during scan: {directory}")
        directory_guards.extend(scanned_directories)
        if _fingerprint(canonical.lstat()) != _fingerprint(before):
            raise ValueError(f"systemd unit search root changed during scan: {canonical}")
        for alias in root["aliases"]:
            try:
                alias_target = Path(alias).resolve(strict=True)
                alias_metadata = alias_target.lstat()
            except (OSError, RuntimeError) as exc:
                raise ValueError(f"systemd unit search root alias changed: {alias}") from exc
            if (alias_metadata.st_dev, alias_metadata.st_ino) != (
                before.st_dev, before.st_ino,
            ):
                raise ValueError(f"systemd unit search root alias changed: {alias}")
            alias_guards.append(
                (alias, (alias_metadata.st_dev, alias_metadata.st_ino))
            )

    loaded_units_after = _systemd_command_lines(
        [
            str(SYSTEMCTL), "list-units", "--all", "--plain", "--no-legend",
            "--no-pager", "--full", f"{V3_UNIT_PREFIX}*",
        ],
        command_runner=command_runner,
        label="post-scan V3-prefixed loaded systemd units",
    )
    unit_files_after = _systemd_command_lines(
        [
            str(SYSTEMCTL), "list-unit-files", "--plain", "--no-legend",
            "--no-pager", "--full", f"{V3_UNIT_PREFIX}*",
        ],
        command_runner=command_runner,
        label="post-scan V3-prefixed systemd unit files",
        allow_empty_no_match=True,
    )
    for directory, fingerprint, inventory in directory_guards:
        _entries, current_inventory, current_fingerprint = (
            _systemd_directory_inventory(directory)
        )
        if current_fingerprint != fingerprint or current_inventory != inventory:
            raise ValueError(f"systemd directory changed after scan: {directory}")
    for entry_path, resolution in symlink_guards:
        if _systemd_symlink_target(entry_path) != resolution:
            raise ValueError(f"systemd symlink target changed after scan: {entry_path}")
    for alias, identity in alias_guards:
        try:
            target_metadata = Path(alias).resolve(strict=True).lstat()
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"systemd unit search root alias changed: {alias}") from exc
        if (target_metadata.st_dev, target_metadata.st_ino) != identity:
            raise ValueError(f"systemd unit search root alias changed: {alias}")
    for absent in absent_roots:
        if os.path.lexists(absent):
            raise ValueError(f"absent systemd unit search root appeared: {absent}")

    roots = sorted(roots_by_identity.values(), key=lambda item: item["canonical_path"])
    filesystem_residue.sort(key=lambda item: (item["root"], item["path"]))
    document = {
        "prefix": V3_UNIT_PREFIX,
        "loaded_units": loaded_units,
        "unit_files": unit_files,
        "systemd_analyze_unit_paths": analyzed_paths,
        "supplemental_paths": supplements,
        "requested_paths": requested_paths,
        "absent_roots": sorted(absent_roots),
        "roots": roots,
        "filesystem_residue": filesystem_residue,
    }
    if (
        loaded_units or unit_files or loaded_units_after or unit_files_after
        or filesystem_residue
    ):
        raise ValueError("V3-prefixed systemd residue is present")
    return document


def system_snapshot() -> dict[str, Any]:
    captured = [
        source_tree_snapshot(
            component, path, expected_count=count, expected_digest=digest
        )
        for component, path, count, digest in V2_ROOTS
    ]
    v2_trees = [item[0] for item in captured]
    combined_entries = sorted(
        [entry for item in captured for entry in item[1]],
        key=lambda item: (item["component"], item["path"]),
    )
    combined_digest = hashlib.sha256(canonical_json(combined_entries)).hexdigest()
    if (
        len(combined_entries) != EXPECTED_V2_COMBINED_COUNT
        or combined_digest != EXPECTED_V2_COMBINED_DIGEST
    ):
        raise ValueError("combined V2 source baseline drift")
    pi_entries = [
        fixed_file_snapshot(component, relative)
        for component, relative in PI_CONTROL_FILES
    ]
    pi_digest = hashlib.sha256(canonical_json(pi_entries)).hexdigest()
    if pi_digest != EXPECTED_PI_CONTROL_DIGEST:
        raise ValueError("Pi Bridge control baseline drift")
    current_absent = not os.path.lexists(V3_CURRENT)
    units = [unit_absence(path) for path in V3_UNIT_FILES]
    if not current_absent or not all(item["file_absent"] for item in units):
        raise ValueError("V3 routing or systemd units appeared during staged read")
    return {
        "schema_version": 1,
        "v2": {
            "trees": v2_trees,
            "combined_algorithm": "canonical-json(component,path,sha256,size)-sha256-v1",
            "combined_count": len(combined_entries),
            "combined_digest": combined_digest,
            "expected_combined_digest": EXPECTED_V2_COMBINED_DIGEST,
            "historical_digest": HISTORICAL_V2_DIGEST,
        },
        "pi_bridge_control": {
            "algorithm": "canonical-json(component,path,sha256,size)-sha256-v1",
            "count": len(pi_entries), "digest": pi_digest, "entries": pi_entries,
            "roots": {key: str(value) for key, value in PI_CONTROL_ROOTS.items()},
        },
        "services": [service_identity(unit) for unit in SERVICES],
        "v3": {
            "current": {"path": str(V3_CURRENT), "absent": current_absent},
            "unit_files": units,
            "residue": systemd_residue_snapshot(),
        },
    }


def _sqlite_state_boundary(
    path: Path, *, expected_uid: int | None, expected_gid: int | None,
) -> tuple[dict[str, Any], tuple[int, ...], dict[str, Any] | None]:
    parent_metadata = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or path.parent.is_symlink()
        or (os.name == "posix" and stat.S_IMODE(parent_metadata.st_mode) != 0o700)
        or (expected_uid is not None and parent_metadata.st_uid != expected_uid)
        or (expected_gid is not None and parent_metadata.st_gid != expected_gid)
    ):
        raise ValueError(f"unsafe Dev15 SQLite state parent: {path.parent}")
    parent_fingerprint = _fingerprint(parent_metadata)
    parent = {
        "path": str(path.parent),
        "exists": True,
        "kind": "directory",
        "mode": f"{stat.S_IMODE(parent_metadata.st_mode):04o}",
        "uid": parent_metadata.st_uid,
        "gid": parent_metadata.st_gid,
        "device": parent_metadata.st_dev,
        "inode": parent_metadata.st_ino,
    }
    try:
        with os.scandir(path.parent) as scanned:
            entries = sorted(scanned, key=lambda entry: entry.name)
        entry_metadata = {
            entry.name: (path.parent / entry.name).lstat() for entry in entries
        }
    except (FileNotFoundError, OSError) as exc:
        raise ValueError(f"cannot inventory Dev15 SQLite state: {path}") from exc
    if set(entry_metadata) not in (set(), {path.name}):
        raise ValueError(f"unexpected Dev15 SQLite state sibling: {path.parent}")
    if _fingerprint(path.parent.lstat()) != parent_fingerprint:
        raise ValueError(f"Dev15 SQLite state parent changed during inventory: {path.parent}")
    metadata = entry_metadata.get(path.name)
    if metadata is None:
        return parent, parent_fingerprint, None
    if (
        not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600)
        or (expected_uid is not None and metadata.st_uid != expected_uid)
        or (expected_gid is not None and metadata.st_gid != expected_gid)
    ):
        raise ValueError(f"unsafe Dev15 SQLite state: {path}")
    database = {
        "path": str(path), "kind": "regular_file",
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid, "gid": metadata.st_gid,
        "device": metadata.st_dev, "inode": metadata.st_ino,
        "links": metadata.st_nlink, "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns, "ctime_ns": metadata.st_ctime_ns,
    }
    return parent, parent_fingerprint, database


def _read_rows(
    path: Path, statements: dict[str, tuple[str, tuple[Any, ...]]], *,
    expected_uid: int | None = None, expected_gid: int | None = None,
) -> dict[str, Any]:
    path = Path(path).absolute()
    before = _sqlite_state_boundary(
        path, expected_uid=expected_uid, expected_gid=expected_gid,
    )
    parent, _parent_fingerprint, database = before
    if database is None:
        after = _sqlite_state_boundary(
            path, expected_uid=expected_uid, expected_gid=expected_gid,
        )
        if after != before:
            raise ValueError(f"Dev15 SQLite state changed during absent snapshot: {path}")
        return {
            "exists": False, "parent": parent, "database": None, "queries": {},
        }

    stable_read(
        path, label=f"Dev15 SQLite state {path}", maximum=64 * 1024 * 1024,
        expected_uid=expected_uid, expected_gid=expected_gid,
        expected_mode=0o600 if os.name == "posix" else None,
    )
    connection = sqlite3.connect(
        f"{path.as_uri()}?mode=ro&immutable=1", uri=True, timeout=0,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
            raise ValueError(f"Dev15 SQLite query-only mode is not active: {path}")
        queries: dict[str, Any] = {}
        for name, (sql, parameters) in statements.items():
            rows = connection.execute(sql, parameters).fetchall()
            queries[name] = [dict(row) for row in rows]
    finally:
        connection.close()
        after = _sqlite_state_boundary(
            path, expected_uid=expected_uid, expected_gid=expected_gid,
        )
        if after != before:
            raise ValueError(f"Dev15 SQLite state changed during immutable snapshot: {path}")
    return {
        "exists": True, "parent": parent, "database": database,
        "queries": queries,
    }


def state_snapshot(
    runtime: dict[str, Any], *, token_id: str, receipt_id: str | None,
    state_uid: int | None = None, state_gid: int | None = None,
) -> dict[str, Any]:
    auth = _read_rows(
        Path(runtime["auth_state_path"]),
        {
            "count": ("SELECT COUNT(*) AS value FROM consumed_auth_tokens", ()),
            "token": (
                "SELECT token_id, request_digest, expires_at, consumed_at "
                "FROM consumed_auth_tokens WHERE token_id = ?", (token_id,),
            ),
        },
        expected_uid=state_uid, expected_gid=state_gid,
    )
    receipt_statements = {
        "receipt_count": ("SELECT COUNT(*) AS value FROM consumed_receipts", ()),
        "audit_count": ("SELECT COUNT(*) AS value FROM audit_events", ()),
        "audit_head": (
            "SELECT sequence, event_hash FROM audit_events "
            "ORDER BY sequence DESC LIMIT 1", (),
        ),
    }
    if receipt_id is not None:
        receipt_statements.update(
            {
                "receipt": (
                    "SELECT receipt_id, request_digest, observed_at, consumed_at "
                    "FROM consumed_receipts WHERE receipt_id = ?", (receipt_id,),
                ),
                "audit_event": (
                    "SELECT sequence, event_id, event_type, operation_id, occurred_at, "
                    "payload_json, previous_hash, event_hash FROM audit_events "
                    "WHERE event_id = ?", (f"read:{receipt_id}",),
                ),
            }
        )
    return {
        "auth_state_path": runtime["auth_state_path"],
        "receipt_state_path": runtime["receipt_state_path"],
        "auth": auth,
        "receipt": _read_rows(
            Path(runtime["receipt_state_path"]), receipt_statements,
            expected_uid=state_uid, expected_gid=state_gid,
        ),
    }


def _run_as(
    user: str, command: list[str], *, stdin: bytes = b"", timeout: int = 180,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "/usr/bin/sudo", "-n", "-u", user, "/usr/bin/env", "-i",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC",
            "PYTHONDONTWRITEBYTECODE=1", *command,
        ],
        input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=timeout,
    )


def _verify_manifest_entries(
    entries: Any, *, names: tuple[str, ...], label: str,
) -> None:
    if (
        not isinstance(entries, list)
        or len(entries) != len(names)
        or [item.get("name") for item in entries if isinstance(item, dict)]
        != list(names)
    ):
        raise ValueError(f"{label} manifest order/set is invalid")
    for item in entries:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "sha256", "size"}
            or HEX64.fullmatch(str(item["sha256"])) is None
            or type(item["size"]) is not int
            or item["size"] <= 0
        ):
            raise ValueError(f"{label} manifest metadata is invalid")
        payload = stable_read(
            TOOLCHAIN_ROOT / item["name"],
            label=f"installed Dev15 toolchain {item['name']}",
            maximum=16 * 1024 * 1024, expected_uid=0, expected_gid=0,
            expected_mode=0o444,
        )
        if (
            len(payload) != item["size"]
            or hashlib.sha256(payload).hexdigest() != item["sha256"]
        ):
            raise ValueError(f"installed Dev15 toolchain bytes mismatch: {item['name']}")


def _verify_toolchain(expected_manifest_sha256: str) -> dict[str, Any]:
    if HEX64.fullmatch(expected_manifest_sha256) is None:
        raise ValueError("expected toolchain manifest SHA-256 is invalid")
    _safe_root_chain(TOOLCHAIN_ROOT, final_mode=0o555)
    manifest_payload = stable_read(
        TOOLCHAIN_MANIFEST, label="installed Dev15 toolchain manifest",
        maximum=16 * 1024 * 1024, expected_uid=0, expected_gid=0,
        expected_mode=0o444,
    )
    if hashlib.sha256(manifest_payload).hexdigest() != expected_manifest_sha256:
        raise ValueError("installed Dev15 toolchain manifest raw SHA-256 mismatch")
    manifest = load_json_bytes(manifest_payload, label="installed Dev15 toolchain manifest")
    if (
        set(manifest)
        != {"application", "control_files", "files", "schema_version", "toolchain_version"}
        or manifest["schema_version"] != 2
        or manifest["toolchain_version"] != TOOLCHAIN_VERSION
        or manifest["application"] != {
            "commit": COMMIT, "manifest_sha256": MANIFEST_SHA256,
            "package_sha256": PACKAGE_SHA256, "registry_digest": REGISTRY_DIGEST,
            "release": RELEASE, "version": "0.1.0.dev15",
        }
    ):
        raise ValueError("installed Dev15 toolchain manifest identity is invalid")
    _verify_manifest_entries(
        manifest["files"], names=TOOLCHAIN_FILES, label="toolchain file"
    )
    _verify_manifest_entries(
        manifest["control_files"], names=TOOLCHAIN_CONTROL_FILES,
        label="toolchain control file",
    )
    expected_names = {
        "TOOLCHAIN-MANIFEST.json", *TOOLCHAIN_FILES, *TOOLCHAIN_CONTROL_FILES,
    }
    if {entry.name for entry in os.scandir(TOOLCHAIN_ROOT)} != expected_names:
        raise ValueError("installed Dev15 toolchain file set is not exact")
    if (
        Path(__file__).absolute() != TOOLCHAIN_ROOT / "run_multicurrency_read.py"
        or Path(__file__).is_symlink()
    ):
        raise ValueError("runner is not executing from the fixed Dev15 toolchain")
    return manifest


def _fixed_runtime_paths() -> dict[str, str]:
    state = (
        f"/var/lib/odoo-accounting-cli-v3-dev15-candidates/{RELEASE}/read-state"
    )
    secrets = f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{RELEASE}"
    return {
        "auth_state_path": f"{state}/auth/state.sqlite3",
        "receipt_state_path": f"{state}/receipt/state.sqlite3",
        "auth_secret_path": f"{secrets}/auth.hmac",
        "receipt_secret_path": f"{secrets}/receipt.hmac",
    }


def validate_runtime(runtime: dict[str, Any]) -> None:
    expected = {
        "instance_id": "odoo19@43.165.173.80",
        "environment": "test", "capability_channel": "staged",
        "database_name": "odoo_test", "database_uuid": DATABASE_UUID,
        "odoo_python": "/opt/odoo/odoo19/odoo19-venv/bin/python",
        "odoo_python_sha256": "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
        "odoo_bin": "/opt/odoo/odoo19/odoo-server/odoo-bin",
        "odoo_bin_sha256": "e0fb7977c59f73e652805d169bcd1bffe41df7bbf0c39ce47e8ad32126529003",
        "odoo_config": "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf",
        "odoo_config_sha256": "98a90d839e3ad16c32335057b27e33bc689cbccbb367350e31fbf41778ed70c3",
        "release_root": str(RELEASE_ROOT),
        "canonical_package_path": (
            f"/opt/odoo-accounting-cli-v3/packages/"
            f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
        ),
        "canonical_package_sha256": PACKAGE_SHA256,
        **_fixed_runtime_paths(),
    }
    if any(runtime.get(key) != value for key, value in expected.items()):
        raise ValueError("runtime escaped the fixed Dev15 read binding")
    if set(runtime) != set(expected) | {"auth_key_id", "receipt_key_id"}:
        raise ValueError("runtime fields are invalid")
    if (
        not str(runtime["auth_key_id"]).startswith("test-auth-dev15-")
        or not str(runtime["receipt_key_id"]).startswith("test-receipt-dev15-")
        or runtime["auth_key_id"] == runtime["receipt_key_id"]
    ):
        raise ValueError("runtime key roles are invalid")


def freeze_bundle(
    evidence: Path, *, request: dict[str, Any], receipt: dict[str, Any],
    toolchain_manifest_sha256: str,
) -> dict[str, Any]:
    evidence = Path(evidence).absolute()
    if SAFE_BUNDLE_NAME.fullmatch(evidence.name) is None:
        raise ValueError("evidence bundle name is unsafe")
    if HEX64.fullmatch(toolchain_manifest_sha256) is None:
        raise ValueError("bundle toolchain manifest SHA-256 is invalid")
    actual = {child.name for child in evidence.iterdir()}
    if actual != BUNDLE_FILES:
        raise ValueError("successful evidence file set drifted before freeze")
    entries = []
    for name in sorted(BUNDLE_FILES):
        path = evidence / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
            raise ValueError(f"unsafe evidence file before freeze: {name}")
        payload = stable_read(path, label=f"evidence {name}", allow_empty=True)
        entries.append(
            {"path": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
        )
    manifest = {
        "schema_version": 1,
        "bundle_type": "odoo-accounting-cli-v3.dev15.multicurrency-read-evidence",
        "release": RELEASE,
        "capability_id": CAPABILITY_ID,
        "evidence_name": evidence.name,
        "evidence_path": str(evidence),
        "plan_sha256": READ_PLAN_SHA256,
        "toolchain_manifest_sha256": toolchain_manifest_sha256,
        "auth_token_id": request["context"]["auth_token_id"],
        "receipt_id": receipt["id"],
        "files": entries,
    }
    write_private(evidence / BUNDLE_MANIFEST, canonical_json(manifest) + b"\n")
    for child in evidence.iterdir():
        if os.name == "posix":
            os.chmod(child, 0o400, follow_symlinks=False)
        else:
            os.chmod(child, 0o400)
        if os.name == "posix":
            descriptor = os.open(
                child, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    if os.name == "posix":
        os.chmod(evidence, 0o500, follow_symlinks=False)
    else:
        os.chmod(evidence, 0o500)
    _fsync_directory(evidence)
    _fsync_directory(evidence.parent)
    return manifest


def main() -> None:
    import grp
    import pwd

    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_dir", type=Path)
    parser.add_argument("expected_manifest_sha256")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("Dev15 evidence runner must execute as root on POSIX")
    _verify_toolchain(args.expected_manifest_sha256)
    evidence = create_evidence_directory(args.evidence_dir)
    plan_bytes = stable_read(
        COMMITTED_PLAN, label="byte-pinned Dev15 read plan",
        expected_uid=0, expected_gid=0, expected_mode=0o444,
    )
    if hashlib.sha256(plan_bytes).hexdigest() != READ_PLAN_SHA256:
        raise SystemExit("byte-pinned Dev15 read plan digest mismatch")
    plan = load_json_bytes(plan_bytes, label="byte-pinned Dev15 read plan")
    oracle_executables = verify_oracle_executables(plan)
    runtime_bytes = stable_read(
        RUNTIME_CONFIG, label="Dev15 runtime config",
        expected_uid=0, expected_gid=0, expected_mode=0o644,
    )
    runtime = load_json_bytes(runtime_bytes, label="Dev15 runtime config")
    validate_runtime(runtime)
    odoo = pwd.getpwnam("odoo")
    odoo_gid = grp.getgrnam("odoo").gr_gid

    write_private(evidence / "read-plan.json", plan_bytes)
    system_pre = system_snapshot()
    write_json(evidence / "system-pre.json", system_pre)

    signer = _run_as("odoo", ["/usr/bin/python3", "-I", str(SIGNER)], stdin=plan_bytes)
    write_private(evidence / "signer.stderr", signer.stderr)
    write_private(evidence / "signer.exit", f"{signer.returncode}\n".encode())
    if signer.returncode != 0 or signer.stderr:
        raise SystemExit("Dev15 signer failed closed")
    request = load_json_bytes(signer.stdout, label="signed request")
    token_id = request.get("context", {}).get("auth_token_id")
    if not isinstance(token_id, str) or not token_id:
        raise SystemExit("Dev15 signer did not return an auth token")
    write_private(evidence / "request.json", canonical_json(request) + b"\n")
    write_json(
        evidence / "state-pre.json",
        state_snapshot(
            runtime, token_id=token_id, receipt_id=None,
            state_uid=odoo.pw_uid, state_gid=odoo_gid,
        ),
    )

    executed = _run_as(
        "odoo",
        [
            str(LAUNCHER), "read", "--runtime-config", str(RUNTIME_CONFIG),
            "--timeout-seconds", "120",
        ],
        stdin=canonical_json(request) + b"\n", timeout=150,
    )
    write_private(evidence / "response.json", executed.stdout)
    write_private(evidence / "stderr", executed.stderr)
    write_private(evidence / "exit", f"{executed.returncode}\n".encode())
    if executed.returncode != 0 or executed.stderr:
        write_json(evidence / "system-post.json", system_snapshot())
        raise SystemExit("canonical Dev15 launcher did not return a clean read")
    response = load_json_bytes(executed.stdout, label="launcher response")
    result = response.get("data", {}).get("result")
    receipt = result.get("receipt") if isinstance(result, dict) else None
    if not isinstance(receipt, dict) or not isinstance(receipt.get("id"), str):
        write_json(evidence / "system-post.json", system_snapshot())
        raise SystemExit("launcher exit zero without a read receipt")
    write_json(evidence / "receipt.json", receipt)
    write_json(
        evidence / "state-post.json",
        state_snapshot(
            runtime, token_id=token_id, receipt_id=receipt["id"],
            state_uid=odoo.pw_uid, state_gid=odoo_gid,
        ),
    )

    if verify_oracle_executables(plan) != oracle_executables:
        raise SystemExit("fixed Oracle executable identity changed before execution")
    oracle = _run_as(
        "postgres", [str(ORACLE_PYTHON), "-I", "-S", str(ORACLE)],
        stdin=canonical_json(request) + b"\n", timeout=120,
    )
    write_private(evidence / "oracle.json", oracle.stdout)
    write_private(evidence / "oracle.stderr", oracle.stderr)
    write_private(evidence / "oracle.exit", f"{oracle.returncode}\n".encode())
    system_post = system_snapshot()
    write_json(evidence / "system-post.json", system_post)
    if oracle.returncode != 0 or oracle.stderr:
        raise SystemExit("independent PostgreSQL oracle failed")
    if system_post != system_pre:
        raise SystemExit("V2/Pi/Odoo/V3 system identity changed during staged read")
    load_json_bytes(oracle.stdout, label="oracle response")
    freeze_bundle(
        evidence, request=request, receipt=receipt,
        toolchain_manifest_sha256=args.expected_manifest_sha256,
    )
    print(str(evidence))


if __name__ == "__main__":
    main()

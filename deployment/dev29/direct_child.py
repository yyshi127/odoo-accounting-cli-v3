#!/usr/bin/python3 -I
"""Attest one already-demoted Dev29 child, then exec its fixed release command."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any


sys.dont_write_bytecode = True
MAX_ATTESTATION_BYTES = 4 * 1024 * 1024
PR_SET_PDEATHSIG = 1


class DirectChildError(RuntimeError):
    pass


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
        raise DirectChildError("child attestation is not canonical JSON") from exc


def _mount_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _status() -> dict[str, str]:
    try:
        lines = Path("/proc/self/status").read_text("ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise DirectChildError("child process status is unavailable") from exc
    selected = {
        "Uid",
        "Gid",
        "Groups",
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
    }
    result: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in selected:
            if key in result:
                raise DirectChildError("child process status is ambiguous")
            result[key] = value.strip()
    if set(result) != selected:
        raise DirectChildError("child process status is incomplete")
    return result


def _namespace(process: str) -> dict[str, int]:
    try:
        metadata = Path(f"/proc/{process}/ns/mnt").stat()
    except OSError as exc:
        raise DirectChildError("child mount namespace is unavailable") from exc
    return {"device": metadata.st_dev, "inode": metadata.st_ino}


MOUNT_FIELDS = {
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


def _safe_endpoint(path_text: str) -> tuple[Path, os.stat_result]:
    path = Path(path_text)
    if not path.is_absolute() or str(PurePosixPath(path_text)) != path_text:
        raise DirectChildError("child mount endpoint is not canonical")
    current = Path("/")
    try:
        for component in path.parts[1:]:
            current /= component
            if stat.S_ISLNK(current.lstat().st_mode):
                raise DirectChildError("child mount endpoint has a symlink ancestor")
        metadata = path.stat()
    except OSError as exc:
        raise DirectChildError(
            "child mount endpoint is unavailable: "
            f"path={path_text!r} errno={exc.errno}"
        ) from exc
    return path, metadata


def _canonical_path(path_text: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute() or str(PurePosixPath(path_text)) != path_text:
        raise DirectChildError("child mount endpoint is not canonical")
    return path


def _expected_mounts(values: list[str]) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    for value in values:
        try:
            item = json.loads(value)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise DirectChildError("expected child mount JSON is invalid") from exc
        if (
            type(item) is not dict
            or set(item) != MOUNT_FIELDS
            or canonical_json(item).decode("utf-8") != value
            or type(item.get("source_device")) is not int
            or type(item.get("source_inode")) is not int
            or type(item.get("destination_device")) is not int
            or type(item.get("destination_inode")) is not int
            or type(item.get("mount_id")) is not int
            or type(item.get("parent_mount_id")) is not int
            or any(item[field] <= 0 for field in (
                "source_device",
                "source_inode",
                "destination_device",
                "destination_inode",
                "mount_id",
                "parent_mount_id",
            ))
            or not isinstance(item.get("major_minor"), str)
            or re.fullmatch(r"[0-9]+:[0-9]+", item["major_minor"]) is None
            or not isinstance(item.get("root"), str)
            or not isinstance(item.get("mount_point"), str)
            or item.get("mount_point") != item.get("destination_path")
            or not isinstance(item.get("filesystem_type"), str)
            or not item["filesystem_type"]
            or not isinstance(item.get("mount_source"), str)
            or type(item.get("options")) is not list
            or item["options"] != sorted(set(item["options"]))
            or type(item.get("super_options")) is not list
            or item["super_options"] != sorted(set(item["super_options"]))
            or item.get("statvfs_read_only") is not True
        ):
            raise DirectChildError("expected child mount identity is invalid")
        _canonical_path(item["source_path"])
        _safe_endpoint(item["destination_path"])
        expected.append(item)
    if len(expected) != 5 or len({item["destination_path"] for item in expected}) != 5:
        raise DirectChildError("expected child mount set is invalid")
    return expected


def _mounts(expected: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        payload = Path("/proc/self/mountinfo").read_bytes()
    except OSError as exc:
        raise DirectChildError("child mountinfo is unavailable") from exc
    if not payload.endswith(b"\n"):
        raise DirectChildError("child mountinfo is truncated")
    wanted = {item["destination_path"] for item in expected}
    rows: dict[str, dict[str, Any]] = {}
    for raw in payload.splitlines():
        try:
            fields = raw.decode("ascii").split(" ")
            separator = fields.index("-")
        except (UnicodeError, ValueError) as exc:
            raise DirectChildError("child mountinfo is invalid") from exc
        if len(fields) < 10 or separator < 6 or len(fields) <= separator + 3:
            raise DirectChildError("child mountinfo row is incomplete")
        mount_point = _mount_unescape(fields[4])
        if mount_point not in wanted:
            continue
        if mount_point in rows:
            raise DirectChildError("child mount point is ambiguous")
        options = sorted(set(fields[5].split(",")))
        super_options = sorted(set(fields[separator + 3].split(",")))
        if not {"ro", "nodev", "nosuid"}.issubset(options):
            raise DirectChildError("child inherited a non-sealed mount")
        rows[mount_point] = {
            "mount_id": int(fields[0]),
            "parent_mount_id": int(fields[1]),
            "major_minor": fields[2],
            "root": _mount_unescape(fields[3]),
            "mount_point": mount_point,
            "options": options,
            "filesystem_type": fields[separator + 1],
            "mount_source": _mount_unescape(fields[separator + 2]),
            "super_options": super_options,
        }
    if set(rows) != wanted:
        raise DirectChildError("child did not inherit every closure mount")
    observed: list[dict[str, Any]] = []
    for item in expected:
        source = _canonical_path(item["source_path"])
        destination, destination_metadata = _safe_endpoint(item["destination_path"])
        try:
            read_only = bool(os.statvfs(destination).f_flag & getattr(os, "ST_RDONLY", 1))
        except OSError as exc:
            raise DirectChildError("child mount statvfs is unavailable") from exc
        row = rows[item["destination_path"]]
        value = {
            "source_path": str(source),
            "destination_path": str(destination),
            "source_device": item["source_device"],
            "source_inode": item["source_inode"],
            "destination_device": destination_metadata.st_dev,
            "destination_inode": destination_metadata.st_ino,
            **row,
            "statvfs_read_only": read_only,
        }
        if (
            value != item
            or (item["source_device"], item["source_inode"])
            != (destination_metadata.st_dev, destination_metadata.st_ino)
        ):
            raise DirectChildError("child mount identity differs from the supervisor")
        observed.append(value)
    return observed


def _expected_environment(role: str) -> dict[str, str]:
    homes = {
        "odoo": "/var/lib/odoo-accounting-cli-v3-broker",
        "signer": "/var/lib/odoo-accounting-cli-v3-broker",
        "postgres": "/var/lib/postgresql",
        "verifier": "/root",
    }
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": homes[role],
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _sha_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
    except OSError as exc:
        raise DirectChildError("Click package tree cannot be hashed") from exc
    return digest.hexdigest(), total


def _tree(root: Path, venv_root: Path) -> list[dict[str, Any]]:
    try:
        root = root.resolve(strict=True)
        venv_root = venv_root.resolve(strict=True)
    except OSError as exc:
        raise DirectChildError("Click package root is unavailable") from exc
    if root != venv_root and venv_root not in root.parents:
        raise DirectChildError("Click package root escaped the sealed venv")
    result: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        path = pending.pop()
        metadata = path.lstat()
        relative = path.relative_to(venv_root).as_posix()
        common = {
            "path": relative,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if stat.S_ISDIR(metadata.st_mode):
            result.append({**common, "kind": "directory"})
            pending.extend(
                Path(item.path)
                for item in sorted(os.scandir(path), key=lambda item: item.name, reverse=True)
            )
        elif stat.S_ISREG(metadata.st_mode):
            digest, size = _sha_file(path)
            result.append({**common, "kind": "regular", "sha256": digest, "size": size})
        else:
            raise DirectChildError("Click package tree contains a non-regular object")
        if len(result) > 10_000:
            raise DirectChildError("Click package tree is unexpectedly large")
    result.sort(key=lambda item: item["path"])
    return result


def _click_identity(venv_root: Path, release_root: Path) -> dict[str, Any]:
    try:
        import click
    except Exception as exc:
        raise DirectChildError("sealed Click cannot be imported") from exc
    origin_text = getattr(getattr(click, "__spec__", None), "origin", None)
    if not isinstance(origin_text, str):
        raise DirectChildError("Click import origin is unavailable")
    try:
        origin = Path(origin_text).resolve(strict=True)
        resolved_venv = venv_root.resolve(strict=True)
    except OSError as exc:
        raise DirectChildError("Click import origin cannot be resolved") from exc
    if resolved_venv not in origin.parents:
        raise DirectChildError("Click import escaped the sealed venv")
    distributions = [
        distribution
        for distribution in importlib.metadata.distributions()
        if (distribution.metadata.get("Name") or "").lower().replace("_", "-") == "click"
    ]
    if len(distributions) != 1:
        raise DirectChildError("sealed runtime must expose exactly one Click distribution")
    distribution = distributions[0]
    files = list(distribution.files or ())
    metadata_roots: set[Path] = set()
    for relative in files:
        parts = PurePosixPath(str(relative)).parts
        if parts and parts[0].lower().endswith(".dist-info"):
            metadata_roots.add(Path(distribution.locate_file(parts[0])))
    if len(metadata_roots) != 1:
        raise DirectChildError("Click dist-info root is unavailable or ambiguous")
    package_root = origin.parent
    roots = [package_root, next(iter(metadata_roots))]
    entries: list[dict[str, Any]] = []
    for root in roots:
        entries.extend(_tree(root, resolved_venv))
    entries.sort(key=lambda item: item["path"])
    if len({item["path"] for item in entries}) != len(entries):
        raise DirectChildError("Click package tree paths overlap")
    source_root = release_root / "src"
    shadows = (source_root / "click.py", source_root / "click")
    if any(os.path.lexists(path) for path in shadows):
        raise DirectChildError("release source shadows sealed Click")
    return {
        "distribution_name": distribution.metadata.get("Name"),
        "distribution_version": distribution.version,
        "origin": str(origin),
        "venv_root": str(resolved_venv),
        "tree_entries": entries,
        "tree_entry_count": len(entries),
        "tree_sha256": hashlib.sha256(canonical_json(entries)).hexdigest(),
        "release_source_shadow_absent": True,
    }


def _validate_command(
    role: str,
    command: list[str],
    *,
    expected_python: str,
    release_root: Path,
) -> None:
    expected_prefix = [expected_python, "-I"]
    if role in {"signer", "verifier"}:
        expected_prefix.append("-S")
    if len(command) <= len(expected_prefix) or command[: len(expected_prefix)] != expected_prefix:
        raise DirectChildError("direct child command does not use sealed isolated Python")
    script = Path(command[len(expected_prefix)])
    allowed = {
        "odoo": {release_root / "bin" / "odoo-accounting-cli-v3"},
        "signer": {release_root / "deployment" / "dev29" / "sign_read.py"},
        "postgres": {release_root / "deployment" / "dev29" / "read_oracles.py"},
        "verifier": {
            release_root / "deployment" / "dev29" / "verify_read_evidence.py"
        },
    }
    if role not in allowed or script not in allowed[role]:
        raise DirectChildError("direct child role cannot execute this release entrypoint")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--role", required=True, choices=("odoo", "signer", "postgres", "verifier")
    )
    parser.add_argument("--attestation-fd", required=True, type=int)
    parser.add_argument("--expected-uid", required=True, type=int)
    parser.add_argument("--expected-gid", required=True, type=int)
    parser.add_argument("--expected-python", required=True)
    parser.add_argument("--expected-venv-root", required=True, type=Path)
    parser.add_argument("--release-root", required=True, type=Path)
    parser.add_argument("--expected-self-namespace-device", required=True, type=int)
    parser.add_argument("--expected-self-namespace-inode", required=True, type=int)
    parser.add_argument("--expected-host-namespace-device", required=True, type=int)
    parser.add_argument("--expected-host-namespace-inode", required=True, type=int)
    parser.add_argument("--expected-loop-device", required=True)
    parser.add_argument("--expected-mount-json", action="append", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    command = list(arguments.command)
    if command and command[0] == "--":
        command.pop(0)
    _validate_command(
        arguments.role,
        command,
        expected_python=arguments.expected_python,
        release_root=arguments.release_root,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0) != 0 or os.getppid() == 1:
        raise DirectChildError("direct child parent-death control is invalid")
    status = _status()
    expected_uid = str(arguments.expected_uid)
    expected_gid = str(arguments.expected_gid)
    uid_values = status["Uid"].split()
    gid_values = status["Gid"].split()
    if (
        uid_values != [expected_uid] * 4
        or gid_values != [expected_gid] * 4
        or status["Groups"]
        or any(status[field] != "0000000000000000" for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        or status["NoNewPrivs"] != "1"
        or os.getgroups()
    ):
        raise DirectChildError("direct child credentials or capabilities are not sealed")
    self_namespace = _namespace("self")
    host_namespace = {
        "device": arguments.expected_host_namespace_device,
        "inode": arguments.expected_host_namespace_inode,
    }
    if (
        self_namespace
        != {
            "device": arguments.expected_self_namespace_device,
            "inode": arguments.expected_self_namespace_inode,
        }
        or self_namespace == host_namespace
    ):
        raise DirectChildError("direct child mount namespace is invalid")
    expected_mounts = _expected_mounts(arguments.expected_mount_json)
    mount_rows = _mounts(expected_mounts)
    if mount_rows[0]["mount_source"] != arguments.expected_loop_device:
        raise DirectChildError("direct child loop mount identity changed")
    environment = _expected_environment(arguments.role)
    if dict(os.environ) != environment:
        raise DirectChildError("direct child environment is not the exact allowlist")
    expected_no_site = arguments.role in {"signer", "verifier"}
    if (
        str(Path(sys.executable).absolute()) != arguments.expected_python
        or sys.flags.isolated != 1
        or bool(sys.flags.no_site) is not expected_no_site
    ):
        raise DirectChildError("direct child Python runtime is invalid")
    click_identity = (
        _click_identity(arguments.expected_venv_root, arguments.release_root)
        if arguments.role == "odoo"
        else None
    )
    report = {
        "schema_version": 1,
        "role": arguments.role,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "command": command,
        "command_sha256": hashlib.sha256(canonical_json(command)).hexdigest(),
        "python": {
            "path": str(Path(sys.executable).absolute()),
            "resolved_path": str(Path(sys.executable).resolve(strict=True)),
            "isolated": True,
            "no_site": expected_no_site,
            "sys_path": list(sys.path),
        },
        "credentials": {
            "uid": arguments.expected_uid,
            "gid": arguments.expected_gid,
            "groups": [],
            "status": status,
            "capabilities_all_zero": True,
            "no_new_privileges": True,
        },
        "self_mount_namespace": self_namespace,
        "host_mount_namespace": host_namespace,
        "same_supervisor_namespace": True,
        "mounts": mount_rows,
        "loop_device": arguments.expected_loop_device,
        "environment": environment,
        "click": click_identity,
    }
    payload = canonical_json(report) + b"\n"
    if len(payload) > MAX_ATTESTATION_BYTES:
        raise DirectChildError("direct child attestation is too large")
    try:
        written = os.write(arguments.attestation_fd, payload)
        os.close(arguments.attestation_fd)
    except OSError as exc:
        raise DirectChildError("direct child attestation cannot be emitted") from exc
    if written != len(payload):
        raise DirectChildError("direct child attestation write was short")
    os.execve(command[0], command, dict(os.environ))
    raise AssertionError("execve returned")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DirectChildError, OSError, ValueError) as exc:
        print(f"Dev29 direct child refused: {exc}", file=sys.stderr)
        raise SystemExit(126)

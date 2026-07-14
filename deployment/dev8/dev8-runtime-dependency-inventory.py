#!/usr/bin/python3 -I
"""Inventory external bytes used by the dev8 canonical release launcher."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import grp
import stat
import subprocess
from pathlib import Path
from typing import Any


RELEASE_ID = "0.1.0.dev8-bd21ca07c168"
RELEASE_ROOT = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE_ID
LAUNCHER = RELEASE_ROOT / "bin" / "odoo-accounting-cli-v3"
EXPECTED_LAUNCHER_SHA256 = (
    "3532fb5e83f9cc74d594f1020ea1572a5a2c6fa1a250c64fd3b210f110ef9944"
)
SYSTEM_PYTHON = Path("/usr/bin/python3")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def owner(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def path_info(path: Path, *, include_hash: bool = True) -> dict[str, Any]:
    metadata = path.lstat()
    kind = (
        "symlink"
        if stat.S_ISLNK(metadata.st_mode)
        else "file"
        if stat.S_ISREG(metadata.st_mode)
        else "directory"
        if stat.S_ISDIR(metadata.st_mode)
        else "other"
    )
    result: dict[str, Any] = {
        "path": str(path),
        "type": kind,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "owner": owner(metadata.st_uid),
        "group": group(metadata.st_gid),
        "size": metadata.st_size,
    }
    if kind == "symlink":
        result["target"] = os.readlink(path)
    elif kind == "file" and include_hash:
        result["sha256"] = sha256(path)
    return result


def ancestor_info(path: Path) -> list[dict[str, Any]]:
    current = path.parent
    values: list[dict[str, Any]] = []
    while True:
        values.append(path_info(current, include_hash=False))
        if current == current.parent:
            break
        current = current.parent
    values.reverse()
    return values


def aggregate(files: list[dict[str, Any]]) -> str:
    stable = [
        {
            "gid": item["gid"],
            "mode": item["mode"],
            "path": item["path"],
            "sha256": item["sha256"],
            "size": item["size"],
            "uid": item["uid"],
        }
        for item in sorted(files, key=lambda value: value["path"])
    ]
    encoded = json.dumps(
        stable,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_output_path(path: Path) -> None:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise RuntimeError("output must be an absolute file path")
    if os.path.lexists(path):
        raise RuntimeError("output must not already exist")
    parent = path.parent
    metadata = parent.lstat()
    resolved = parent.resolve(strict=True)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or parent.is_symlink()
        or resolved != parent
        or resolved == Path("/tmp")
        or Path("/tmp") not in resolved.parents
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RuntimeError("output directory must be a private caller-owned directory under /tmp")


def secure_write(path: Path, payload: bytes) -> None:
    validate_output_path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure output requires O_NOFOLLOW")
    flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid():
            raise RuntimeError("secure output descriptor is invalid")
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise RuntimeError("secure output write did not progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def click_probe() -> dict[str, Any]:
    source = r'''
import importlib.metadata
import json
from pathlib import Path

import click

distribution = importlib.metadata.distribution("click")
located = []
for relative in distribution.files or ():
    candidate = Path(distribution.locate_file(relative))
    try:
        if candidate.exists():
            located.append(str(candidate.absolute()))
    except OSError:
        continue
print(json.dumps({
    "click_file": str(Path(click.__file__).absolute()),
    "distribution_files": sorted(set(located)),
    "distribution_name": distribution.metadata["Name"],
    "distribution_version": distribution.version,
}, sort_keys=True, separators=(",", ":")))
'''
    completed = subprocess.run(
        [str(SYSTEM_PYTHON), "-I", "-B", "-X", "utf8", "-c", source],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    if completed.returncode != 0 or completed.stderr or not completed.stdout:
        raise RuntimeError("isolated system Python could not inventory Click")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("Click inventory response is invalid")
    return value


def python_version() -> dict[str, str]:
    source = (
        "import json,platform,sys;"
        "print(json.dumps({'executable':sys.executable,'implementation':"
        "platform.python_implementation(),'version':platform.python_version()},"
        "sort_keys=True,separators=(',',':')))"
    )
    completed = subprocess.run(
        [str(SYSTEM_PYTHON), "-I", "-B", "-X", "utf8", "-c", source],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError("isolated system Python version probe failed")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("system Python version response is invalid")
    return value


def launcher_version() -> dict[str, Any]:
    completed = subprocess.run(
        [str(LAUNCHER), "--version"],
        cwd="/tmp",
        env={
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    return {
        "exit_code": completed.returncode,
        "stderr": completed.stderr,
        "stdout": completed.stdout,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    validate_output_path(args.output)

    launcher = path_info(LAUNCHER)
    shebang = LAUNCHER.open("rb").readline(256).decode("ascii").rstrip("\r\n")
    resolved_python = SYSTEM_PYTHON.resolve(strict=True)
    python_link = path_info(SYSTEM_PYTHON)
    python_binary = path_info(resolved_python)
    click = click_probe()

    candidate_paths = {Path(value) for value in click["distribution_files"]}
    click_file = Path(click["click_file"])
    click_root = click_file.parent
    for path in click_root.rglob("*"):
        if path.is_file() or path.is_symlink():
            candidate_paths.add(path.absolute())

    click_files: list[dict[str, Any]] = []
    click_links: list[dict[str, Any]] = []
    for path in sorted(candidate_paths, key=str):
        try:
            info = path_info(path)
        except OSError:
            continue
        if info["type"] == "file":
            click_files.append(info)
        else:
            click_links.append(info)

    ancestor_paths = {
        Path(item["path"])
        for item in ancestor_info(resolved_python)
        + ancestor_info(click_file)
    }
    ancestors = [
        path_info(path, include_hash=False)
        for path in sorted(ancestor_paths, key=lambda value: (len(value.parts), str(value)))
    ]
    version_probe = launcher_version()
    checks = {
        "launcher_is_regular_non_symlink": launcher["type"] == "file",
        "launcher_is_executable": bool(LAUNCHER.stat().st_mode & 0o111),
        "launcher_sha256": launcher.get("sha256") == EXPECTED_LAUNCHER_SHA256,
        "launcher_shebang": shebang == "#!/usr/bin/python3 -I",
        "launcher_version": version_probe["exit_code"] == 0
        and version_probe["stderr"] == ""
        and "0.1.0.dev8" in version_probe["stdout"],
        "python_resolved_regular": python_binary["type"] == "file",
        "click_files_present": bool(click_files),
    }
    report = {
        "schema_version": 1,
        "release": RELEASE_ID,
        "launcher": {
            **launcher,
            "shebang": shebang,
            "version_probe": version_probe,
        },
        "launcher_python": {
            "configured_path": python_link,
            "resolved_path": str(resolved_python),
            "resolved_file": python_binary,
            "version": python_version(),
        },
        "click": {
            "distribution_name": click["distribution_name"],
            "version": click["distribution_version"],
            "module_file": str(click_file),
            "file_count": len(click_files),
            "file_aggregate_sha256": aggregate(click_files),
            "files": sorted(click_files, key=lambda value: value["path"]),
            "non_regular_entries": click_links,
        },
        "ancestors": ancestors,
        "checks": checks,
        "inventory_scope": [
            "manifest-covered launcher bytes",
            "resolved /usr/bin/python3 bytes and version",
            "installed Click distribution files, ownership, modes, and ancestors",
        ],
        "scoped_inventory_checks_passed": all(checks.values()),
        "production_dependency_closure_complete": False,
        "external_dependency_bound": False,
        "production_promotion_allowed": False,
        "promotion_blockers": [
            "the canonical launcher interpreter is the external /usr/bin/python3",
            "Click is loaded from the external system Python installation",
            "the release manifest and runtime contract do not bind those external bytes",
        ],
        "odoo_connected": False,
        "odoo_action_performed": False,
    }
    encoded = (
        json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    secure_write(
        args.output,
        encoded,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if not report["scoped_inventory_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

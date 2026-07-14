#!/usr/bin/python3 -I
"""Exercise dev8 package-path failures without starting an Odoo subprocess."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


RELEASE_ID = "0.1.0.dev8-bd21ca07c168"
VERSION = "0.1.0.dev8"
MANIFEST_SHA256 = "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06"
PACKAGE_SHA256 = "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
RELEASE_ROOT = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE_ID
ANCHOR = Path("/opt/odoo-accounting-cli-v3/trusted-artifacts") / f"{RELEASE_ID}.json"
PACKAGE_NAME = f"odoo-accounting-cli-v3-{RELEASE_ID}.tar.gz"
CANONICAL_PACKAGE = Path("/opt/odoo-accounting-cli-v3/packages") / PACKAGE_NAME
RUNTIME = Path("/etc/odoo-accounting-cli-v3/runtime-test-dev8.json")
SUDO = Path("/usr/bin/sudo")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise RuntimeError("descriptor write did not progress")
        remaining = remaining[written:]


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


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
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure output requires O_NOFOLLOW")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
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


def package_identity(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": sha256(path),
        "is_regular": stat.S_ISREG(metadata.st_mode),
        "is_symlink": path.is_symlink(),
    }


def descriptor_identity(path: Path) -> dict[str, object]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("descriptor identity requires O_NOFOLLOW")
    before = path.lstat()
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise RuntimeError("descriptor identity path changed while opened")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise RuntimeError("descriptor identity file changed while read")
        return {
            "device": after.st_dev,
            "inode": after.st_ino,
            "mode": f"{stat.S_IMODE(after.st_mode):04o}",
            "uid": after.st_uid,
            "gid": after.st_gid,
            "size": after.st_size,
            "mtime_ns": after.st_mtime_ns,
            "sha256": digest.hexdigest(),
        }
    finally:
        os.close(descriptor)


def secure_copy_exact(source: Path, destination: Path, expected_digest: str) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("secure fixture copy requires O_NOFOLLOW")
    source_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    source_fd = os.open(source, source_flags)
    destination_fd: int | None = None
    destination_created = False
    try:
        source_before = os.fstat(source_fd)
        if not stat.S_ISREG(source_before.st_mode):
            raise RuntimeError("canonical fixture source is not regular")
        destination_fd = os.open(destination, destination_flags, 0o400)
        destination_created = True
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            write_all(destination_fd, chunk)
        source_after = os.fstat(source_fd)
        if (
            (source_after.st_dev, source_after.st_ino, source_after.st_size, source_after.st_mtime_ns)
            != (source_before.st_dev, source_before.st_ino, source_before.st_size, source_before.st_mtime_ns)
            or digest.hexdigest() != expected_digest
        ):
            raise RuntimeError("canonical fixture source changed or has the wrong digest")
        os.fchown(destination_fd, 0, 0)
        os.fchmod(destination_fd, 0o444)
        os.fsync(destination_fd)
        copied = os.fstat(destination_fd)
        if copied.st_size != source_before.st_size:
            raise RuntimeError("same-byte fixture size mismatch")
    except BaseException:
        if destination_fd is not None:
            os.close(destination_fd)
            destination_fd = None
        if destination_created:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
    fsync_directory(destination.parent)


def create_fixed_marker(path: Path, odoo_gid: int, payload: bytes) -> dict[str, object]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("fixed marker creation requires O_NOFOLLOW")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        write_all(descriptor, payload)
        os.fchown(descriptor, 0, odoo_gid)
        os.fchmod(descriptor, 0o660)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)
    return descriptor_identity(path)


def safe_remove_tree(path: Path, allowed_parent: Path, prefix: str) -> None:
    if not os.path.lexists(path):
        return
    metadata = path.lstat()
    allowed = allowed_parent.resolve(strict=True)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != 0
        or path.resolve(strict=True).parent != allowed
        or not path.name.startswith(prefix)
    ):
        raise RuntimeError("refusing to remove an unexpected temporary directory")
    shutil.rmtree(path)


def encode_sqlite_value(value: object) -> object:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    return value


def sqlite_logical_fingerprint(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only = ON")
        schemas = [
            list(row)
            for row in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
            )
        ]
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        contents: list[dict[str, object]] = []
        counts: dict[str, int] = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({quoted})")]
            rows = [
                [encode_sqlite_value(value) for value in row]
                for row in connection.execute(f"SELECT * FROM {quoted}")
            ]
            rows.sort(key=lambda value: canonical(value))
            counts[table] = len(rows)
            contents.append({"columns": columns, "name": table, "rows": rows})
        logical_sha = hashlib.sha256(canonical({"schemas": schemas, "tables": contents})).hexdigest()
        return {
            "logical_sha256": logical_sha,
            "main_file_sha256": sha256(path),
            "table_counts": counts,
        }
    finally:
        connection.close()


def audit_fingerprint(path: Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only = ON")
        columns = [
            row[1] for row in connection.execute("PRAGMA table_info(audit_events)")
        ]
        rows = [
            [encode_sqlite_value(value) for value in row]
            for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence")
        ]
        return {
            "row_count": len(rows),
            "head": rows[-1][columns.index("event_hash")] if rows else None,
            "aggregate_sha256": hashlib.sha256(
                canonical({"columns": columns, "rows": rows})
            ).hexdigest(),
        }
    finally:
        connection.close()


def token_consumed(path: Path, token_id: str) -> bool:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        connection.execute("PRAGMA query_only = ON")
        found = connection.execute(
            "SELECT 1 FROM consumed_auth_tokens WHERE token_id = ?", (token_id,)
        ).fetchone()
        return found is not None
    finally:
        connection.close()


def state_fingerprint(runtime: dict[str, Any]) -> dict[str, object]:
    auth = Path(runtime["auth_state_path"])
    receipt = Path(runtime["receipt_state_path"])
    return {
        "auth": sqlite_logical_fingerprint(auth),
        "receipt": sqlite_logical_fingerprint(receipt),
        "audit": audit_fingerprint(receipt),
    }


def odoo_pid() -> int:
    completed = subprocess.run(
        ["systemctl", "show", "odoo19.service", "--property=MainPID", "--value"],
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=20,
    )
    if completed.returncode != 0 or completed.stderr.strip():
        raise RuntimeError("could not inventory the Odoo service PID")
    return int(completed.stdout.strip() or "0")


def harden_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if path.is_symlink():
            continue
        os.chown(path, 0, 0)
        path.chmod(0o555 if path.is_dir() else 0o444)
    os.chown(root, 0, 0)
    root.chmod(0o555)
    launcher = root / "releases" / RELEASE_ID / "bin" / "odoo-accounting-cli-v3"
    if launcher.exists():
        launcher.chmod(0o555)


def prepare_case(
    root: Path,
    name: str,
    runtime: dict[str, Any],
    canary_python: Path,
    canary_sha: str,
    same_byte_tmp: Path,
) -> tuple[Path, dict[str, Any]]:
    case_root = root / name
    release = case_root / "releases" / RELEASE_ID
    anchor = case_root / "trusted-artifacts" / f"{RELEASE_ID}.json"
    expected_package = case_root / "packages" / PACKAGE_NAME
    release.parent.mkdir(parents=True)
    anchor.parent.mkdir(parents=True)
    expected_package.parent.mkdir(parents=True)
    shutil.copytree(RELEASE_ROOT, release, symlinks=True)
    shutil.copy2(ANCHOR, anchor, follow_symlinks=False)

    config = dict(runtime)
    config["release_root"] = str(release)
    config["odoo_python"] = str(canary_python)
    config["odoo_python_sha256"] = canary_sha
    if name == "wrong-path":
        wrong = expected_package.with_name("wrong-name.tar.gz")
        shutil.copy2(CANONICAL_PACKAGE, wrong)
        config["canonical_package_path"] = str(wrong)
    elif name == "same-bytes-tmp-copy":
        config["canonical_package_path"] = str(same_byte_tmp)
    elif name == "symlink":
        expected_package.symlink_to(CANONICAL_PACKAGE)
        config["canonical_package_path"] = str(expected_package)
    elif name == "tampered-copy":
        shutil.copy2(CANONICAL_PACKAGE, expected_package)
        expected_package.chmod(0o600)
        with expected_package.open("ab") as stream:
            stream.write(b"\nDEV8-NEGATIVE-TAMPER\n")
        config["canonical_package_path"] = str(expected_package)
    else:
        raise ValueError(f"unknown case: {name}")
    config["canonical_package_sha256"] = PACKAGE_SHA256
    harden_tree(case_root)
    return release / "bin" / "odoo-accounting-cli-v3", config


def write_config(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        os.write(descriptor, canonical(value) + b"\n")
        os.fchmod(descriptor, 0o444)
        os.fchown(descriptor, 0, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sign_request(runtime: dict[str, Any], token_id: str) -> dict[str, object]:
    source = RELEASE_ROOT / "src"
    sys.path.insert(0, str(source))
    try:
        from odoo_accounting_cli_v3.auth import context_payload, sign_request_context
    finally:
        if sys.path[0] == str(source):
            sys.path.pop(0)

    parameters = {"company_id": 1}
    now = datetime.now(timezone.utc)
    context = sign_request_context(
        auth_token_id=token_id,
        principal="pi:test-user-2",
        odoo_instance_id=runtime["instance_id"],
        database_name=runtime["database_name"],
        database_uuid=runtime["database_uuid"],
        user_id=2,
        company_id=1,
        allowed_company_ids=frozenset({1}),
        environment=runtime["environment"],
        capability_id="acct.registry.list.v1",
        parameters=parameters,
        issued_at=now,
        expires_at=now + timedelta(minutes=4),
        key_id=runtime["auth_key_id"],
        secret=Path(runtime["auth_secret_path"]).read_bytes(),
    )
    return {
        "capability_id": "acct.registry.list.v1",
        "context": {
            **context_payload(context),
            "auth_signature": context.auth_signature,
        },
        "parameters": parameters,
    }


def execute(
    launcher: Path, config: Path, request: dict[str, object]
) -> dict[str, object]:
    completed = subprocess.run(
        [
            str(SUDO),
            "-n",
            "-u",
            "odoo",
            "--",
            "/usr/bin/env",
            "-i",
            "HOME=/tmp",
            "LANG=C.UTF-8",
            "PATH=/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE=1",
            str(launcher),
            "read",
            "--runtime-config",
            str(config),
        ],
        input=canonical(request).decode("utf-8") + "\n",
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    try:
        error = json.loads(completed.stderr) if completed.stderr else None
    except ValueError:
        error = None
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr_sha256": hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest(),
        "error": error,
    }


def verify_release_identity() -> None:
    launcher = RELEASE_ROOT / "bin" / "odoo-accounting-cli-v3"
    completed = subprocess.run(
        [str(launcher), "release", "identity"],
        cwd="/tmp",
        env={"HOME": "/tmp", "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError("the exact release failed identity verification")
    identity = json.loads(completed.stdout)["data"]
    if (
        identity["release"] != RELEASE_ID
        or identity["version"] != VERSION
        or identity["manifest_sha256"] != MANIFEST_SHA256
        or identity["package_sha256"] != PACKAGE_SHA256
        or identity["verified"] is not True
    ):
        raise RuntimeError("the exact release identity is not dev8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("this target gate must run as root")
    validate_output_path(args.output)
    runtime = json.loads(RUNTIME.read_text(encoding="utf-8"))
    if (
        runtime["release_root"] != str(RELEASE_ROOT)
        or runtime["canonical_package_path"] != str(CANONICAL_PACKAGE)
        or runtime["canonical_package_sha256"] != PACKAGE_SHA256
        or runtime["environment"] != "test"
        or runtime["capability_channel"] != "staged"
    ):
        raise SystemExit("the dev8 staged runtime binding is invalid")
    verify_release_identity()
    canonical_before = package_identity(CANONICAL_PACKAGE)
    if (
        not canonical_before["is_regular"]
        or canonical_before["is_symlink"]
        or canonical_before["sha256"] != PACKAGE_SHA256
        or canonical_before["uid"] != 0
        or canonical_before["gid"] != 0
        or canonical_before["mode"] != "0444"
    ):
        raise SystemExit("the real canonical package is not exact and regular")

    run_id = uuid.uuid4().hex
    temp_root = Path("/opt/odoo-accounting-cli-v3") / f".dev8-negative-{run_id}"
    config_root = Path("/etc/odoo-accounting-cli-v3") / f".dev8-negative-{run_id}"
    canary = temp_root / "odoo-python-canary"
    marker_directory = temp_root / "canary-state"
    marker = marker_directory / "marker"
    marker_payload = b"DEV8_CANARY_UNREACHED\n"
    cases = ["wrong-path", "same-bytes-tmp-copy", "symlink", "tampered-copy"]
    report: dict[str, object] | None = None
    tmp_fixture_root: Path | None = None
    temp_root_created = False
    config_root_created = False
    try:
        temp_root.mkdir(mode=0o755)
        temp_root_created = True
        config_root.mkdir(mode=0o755)
        config_root_created = True
        tmp_fixture_root = Path(
            tempfile.mkdtemp(prefix=".dev8-package-fixtures-", dir="/tmp")
        )
        tmp_metadata = tmp_fixture_root.lstat()
        if (
            tmp_fixture_root.is_symlink()
            or tmp_fixture_root.resolve(strict=True).parent != Path("/tmp")
            or tmp_metadata.st_uid != 0
            or stat.S_IMODE(tmp_metadata.st_mode) != 0o700
        ):
            raise RuntimeError("private /tmp fixture directory is not exact")
        same_byte_tmp = tmp_fixture_root / PACKAGE_NAME
        secure_copy_exact(CANONICAL_PACKAGE, same_byte_tmp, PACKAGE_SHA256)
        if descriptor_identity(same_byte_tmp)["sha256"] != PACKAGE_SHA256:
            raise RuntimeError("the /tmp same-byte fixture is not identical")
        odoo_gid = grp.getgrnam("odoo").gr_gid
        marker_directory.mkdir(mode=0o750)
        os.chown(marker_directory, 0, odoo_gid)
        marker_directory.chmod(0o550)
        marker_directory_metadata = marker_directory.lstat()
        if (
            marker_directory_metadata.st_uid != 0
            or marker_directory_metadata.st_gid != odoo_gid
            or stat.S_IMODE(marker_directory_metadata.st_mode) != 0o550
        ):
            raise RuntimeError("canary directory is not root:odoo non-writable")
        initial_marker = create_fixed_marker(marker, odoo_gid, marker_payload)
        if (
            initial_marker["uid"] != 0
            or initial_marker["gid"] != odoo_gid
            or initial_marker["mode"] != "0660"
            or initial_marker["sha256"] != hashlib.sha256(marker_payload).hexdigest()
        ):
            raise RuntimeError("fixed-inode canary marker is invalid")
        canary.write_text(
            "#!/bin/sh\n"
            f"printf reached > {str(marker)!r}\n"
            "exit 97\n",
            encoding="utf-8",
        )
        canary.chmod(0o555)
        canary_sha = sha256(canary)
        prepared: dict[str, tuple[Path, Path]] = {}
        for name in cases:
            launcher, case_config = prepare_case(
                temp_root, name, runtime, canary, canary_sha, same_byte_tmp
            )
            config_path = config_root / f"{name}.json"
            write_config(config_path, case_config)
            prepared[name] = (launcher, config_path)
        os.chown(config_root, 0, 0)
        config_root.chmod(0o555)
        os.chown(temp_root, 0, 0)
        temp_root.chmod(0o555)

        correct_relative = Path("packages") / PACKAGE_NAME
        wrong_path = temp_root / "wrong-path" / "packages" / "wrong-name.tar.gz"
        symlink_path = temp_root / "symlink" / correct_relative
        tampered_path = temp_root / "tampered-copy" / correct_relative
        artifact_evidence = {
            "wrong_path": {
                "path": str(wrong_path),
                "differs_from_expected_name": wrong_path.name != PACKAGE_NAME,
                "sha256": sha256(wrong_path),
                "same_bytes": sha256(wrong_path) == PACKAGE_SHA256,
            },
            "same_bytes_tmp_copy": {
                "path": str(same_byte_tmp),
                "private_directory": str(tmp_fixture_root),
                "private_directory_mode": f"{stat.S_IMODE(tmp_metadata.st_mode):04o}",
                "under_tmp": tmp_fixture_root.parent == Path("/tmp"),
                "identity": descriptor_identity(same_byte_tmp),
                "same_bytes": descriptor_identity(same_byte_tmp)["sha256"]
                == PACKAGE_SHA256,
            },
            "symlink": {
                "path": str(symlink_path),
                "is_symlink": symlink_path.is_symlink(),
                "target": os.readlink(symlink_path),
            },
            "tampered_copy": {
                "path": str(tampered_path),
                "sha256": sha256(tampered_path),
                "digest_differs": sha256(tampered_path) != PACKAGE_SHA256,
                "size": tampered_path.stat().st_size,
                "canonical_size": CANONICAL_PACKAGE.stat().st_size,
            },
            "fixed_inode_canary": {
                "directory": {
                    "path": str(marker_directory),
                    "uid": marker_directory_metadata.st_uid,
                    "gid": marker_directory_metadata.st_gid,
                    "mode": f"{stat.S_IMODE(marker_directory_metadata.st_mode):04o}",
                    "group_writable": bool(marker_directory_metadata.st_mode & 0o020),
                    "world_writable": bool(marker_directory_metadata.st_mode & 0o002),
                },
                "path": str(marker),
                "initial_identity": initial_marker,
            },
        }
        fixture_checks = {
            "wrong_path_is_same_bytes": artifact_evidence["wrong_path"]["same_bytes"]
            and artifact_evidence["wrong_path"]["differs_from_expected_name"],
            "tmp_copy_is_same_bytes": artifact_evidence["same_bytes_tmp_copy"][
                "same_bytes"
            ]
            and artifact_evidence["same_bytes_tmp_copy"]["under_tmp"],
            "symlink_fixture_is_link": artifact_evidence["symlink"]["is_symlink"],
            "tampered_fixture_differs": artifact_evidence["tampered_copy"][
                "digest_differs"
            ],
        }

        baseline_state = state_fingerprint(runtime)
        initial_pid = odoo_pid()
        if initial_pid <= 0 or not Path(f"/proc/{initial_pid}").is_dir():
            raise RuntimeError("the Odoo service has no live MainPID")
        results: dict[str, object] = {}
        for name in cases:
            token_id = f"dev8-negative-{name}-{uuid.uuid4()}"
            request = sign_request(runtime, token_id)
            before_consumed = token_consumed(Path(runtime["auth_state_path"]), token_id)
            launcher, config_path = prepared[name]
            outcome = execute(launcher, config_path, request)
            after_state = state_fingerprint(runtime)
            after_consumed = token_consumed(Path(runtime["auth_state_path"]), token_id)
            after_pid = odoo_pid()
            marker_after = descriptor_identity(marker)
            expected_exit = 5 if name in {"wrong-path", "same-bytes-tmp-copy"} else 6
            expected_error = (
                "runtime_release_mismatch"
                if name in {"wrong-path", "same-bytes-tmp-copy"}
                else "odoo_read_failed"
            )
            error = outcome.get("error")
            checks = {
                "fresh_token_before": before_consumed is False,
                "token_still_unconsumed": after_consumed is False,
                "expected_exit": outcome["exit_code"] == expected_exit,
                "stdout_empty": outcome["stdout"] == "",
                "structured_error": isinstance(error, dict)
                and error.get("error", {}).get("code") == expected_error
                and error.get("error", {}).get("odoo_action_performed") is False,
                "auth_hash_unchanged": after_state["auth"] == baseline_state["auth"],
                "receipt_hash_unchanged": after_state["receipt"]
                == baseline_state["receipt"],
                "audit_hash_unchanged": after_state["audit"] == baseline_state["audit"],
                "odoo_pid_unchanged": after_pid == initial_pid,
                "odoo_pid_active": after_pid > 0
                and Path(f"/proc/{after_pid}").is_dir(),
                "odoo_canary_fixed_inode_unchanged": marker_after == initial_marker,
            }
            results[name] = {
                "auth_token_id": token_id,
                "expected_exit": expected_exit,
                "expected_error": expected_error,
                "observed": outcome,
                "state_after": after_state,
                "odoo_pid_after": after_pid,
                "canary_marker_after": marker_after,
                "checks": checks,
                "all_checks_passed": all(checks.values()),
            }

        canonical_after = package_identity(CANONICAL_PACKAGE)
        final_marker = descriptor_identity(marker)
        report = {
            "schema_version": 1,
            "release": RELEASE_ID,
            "manifest_sha256": MANIFEST_SHA256,
            "canonical_package_path": str(CANONICAL_PACKAGE),
            "canonical_package_sha256": PACKAGE_SHA256,
            "canonical_package_before": canonical_before,
            "canonical_package_after": canonical_after,
            "canonical_package_unchanged": canonical_after == canonical_before,
            "artifact_evidence": artifact_evidence,
            "fixture_checks": fixture_checks,
            "baseline_state": baseline_state,
            "odoo_pid_before": initial_pid,
            "canary_marker_final": final_marker,
            "odoo_canary_reached": final_marker != initial_marker,
            "cases": results,
            "all_checks_passed": canonical_after == canonical_before
            and final_marker == initial_marker
            and all(fixture_checks.values())
            and all(value["all_checks_passed"] for value in results.values()),
            "production_promotion_allowed": False,
            "odoo_connected": False,
            "odoo_action_performed": False,
            "secret_material_emitted": False,
        }
    finally:
        if config_root_created:
            safe_remove_tree(
                config_root,
                Path("/etc/odoo-accounting-cli-v3"),
                ".dev8-negative-",
            )
        if temp_root_created:
            safe_remove_tree(
                temp_root,
                Path("/opt/odoo-accounting-cli-v3"),
                ".dev8-negative-",
            )
        if tmp_fixture_root is not None:
            safe_remove_tree(
                tmp_fixture_root,
                Path("/tmp"),
                ".dev8-package-fixtures-",
            )

    if report is None:
        raise RuntimeError("negative gates did not produce a report")
    report["temporary_artifacts_removed"] = (
        not temp_root.exists()
        and not config_root.exists()
        and tmp_fixture_root is not None
        and not tmp_fixture_root.exists()
    )
    report["all_checks_passed"] = bool(report["all_checks_passed"]) and bool(
        report["temporary_artifacts_removed"]
    )
    encoded = (
        json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    secure_write(
        args.output,
        encoded,
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if not report["all_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

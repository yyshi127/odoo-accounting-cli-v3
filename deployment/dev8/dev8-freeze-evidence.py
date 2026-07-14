#!/usr/bin/python3 -I
"""Freeze the exact dev8 canonical-launcher/read evidence and publish an anchor."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
import pwd
import grp
import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath


RELEASE = "0.1.0.dev8-bd21ca07c168"
VERSION = "0.1.0.dev8"
TOOLCHAIN_VERSION = "0.1.0.dev8-toolchain.3"
COMMIT = "bd21ca07c1689a42fbf903b91486269397b44733"
TREE = "fd389ef55fbc6723379a2928a10b665925829599"
PACKAGE_SHA256 = "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
PACKAGE_SIZE = 151492
MANIFEST_SHA256 = "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06"
REGISTRY_DIGEST = "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e"
RUNTIME_SHA256 = "a089d13a2418225e245d10cf76728ad6af31ce0b5fde9f5b14902c44eebe59b7"
PLAN_SHA256 = "c6dd18fc356bdbc26de43941656e9af62f639d06393ce87572e7a08e5759f2e5"
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
LAUNCHER_SHA256 = "3532fb5e83f9cc74d594f1020ea1572a5a2c6fa1a250c64fd3b210f110ef9944"
RELEASE_ROOT = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE
PACKAGE = Path("/opt/odoo-accounting-cli-v3/packages") / f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
RELEASE_ANCHOR = Path("/opt/odoo-accounting-cli-v3/trusted-artifacts") / f"{RELEASE}.json"
RUNTIME = Path("/etc/odoo-accounting-cli-v3/runtime-test-dev8.json")
UPLOAD_ROOT = Path("/root/odoo-accounting-cli-v3-dev8-upload")
PIPELINE_LOCK = Path("/opt/odoo-accounting-cli-v3/.dev8-pipeline.lock")
INSTALL_JOURNAL = Path("/opt/odoo-accounting-cli-v3/.dev8-install-transaction.json")
RUNTIME_JOURNAL = Path("/etc/odoo-accounting-cli-v3/.dev8-runtime-transaction.json")
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
TARGET = EVIDENCE_PARENT / RELEASE
STAGING = EVIDENCE_PARENT / f".{RELEASE}.staging"
ANCHOR_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence-anchors")
EVIDENCE_ANCHOR = ANCHOR_PARENT / f"{RELEASE}.json"
ANCHOR_STAGING = ANCHOR_PARENT / f".{RELEASE}.json.staging"
SERVER_BASELINE_NAME = "SERVER-BASELINE.json"
READ_NAMES = ("registry-list", "trial-balance", "ar-open-items", "ap-open-items")
READ_FILES = {
    "read-plan.input.json", "identity.json", "summary.json", "read-oracles.audit.json",
    *(f"{name}.{suffix}" for name in READ_NAMES for suffix in (
        "parameters.json", "request.json", "response.json", "receipt.json", "stderr", "exit"
    )),
    *(f"{name}.oracle.{suffix}" for name in ("trial-balance", "ar-open-items", "ap-open-items") for suffix in ("json", "stderr", "exit")),
}
STATE_FILES = {"auth-state.sqlite3", "receipt-state.sqlite3", "audit-events.json", "persistence-audit.json"}
EXECUTION_FILES = {
    "real-read.stdout", "real-read.stderr", "real-read.exit",
    "read-oracles.stdout", "read-oracles.stderr", "read-oracles.exit",
    "launcher-isolation.stdout", "launcher-isolation.stderr", "launcher-isolation.exit",
    "launcher-isolation.json", "execution-staging-audit.json",
}
DEPLOYMENT_FILES = {
    *(f"{name}.{suffix}" for name in ("install", "runtime-setup", "server-gate") for suffix in ("stdout", "stderr", "exit")),
}
SOURCE_HASHES = {
    "real-read-runner": "948ecb472bf4a99e7b8442235190875a4a8e0c5422881079e0422636f6810499",
    "signer": "e94e610d480f7ba0736e315a46ca98a6507e82e88e1b35ac2ca6a31ff0592896",
    "launcher-isolation": "9bb2a2596d639851df2567e5a8e9cef98f2c5849725946ecc72bb6b1cfbfa80e",
}
EXECUTION_SOURCE_HASHES = {
    "dev8-run-real-reads.sh": SOURCE_HASHES["real-read-runner"],
    "dev8-sign-read.py": SOURCE_HASHES["signer"],
    "dev8-launcher-isolation-gate.py": SOURCE_HASHES["launcher-isolation"],
    "dev8-run-read-oracles.sh": "a69faa4d38341c5c9135c43e0f6308c3335eb65fb90b72f757b8a1e26d1af618",
    "dev6-trial-balance-sql-oracle.py": "7aa959361ac994f17cd871d33211bbef02ab816993ff87f088c82a6541cfcb9b",
    "dev6-ar-sql-oracle.py": "cdb49967d60af0aa416cadaeb61503847ddfeb4d111aa0e01335fe06b78499c6",
    "dev7-ap-sql-oracle.py": "ad54540725e8110ea1449586d0dcddb1d6c70b1e387f0e843b989aca6b70f1e5",
}
TOOL_FILES = (
    "dev8-install.sh",
    "dev8-runtime-setup.sh",
    "dev8-server-gate.sh",
    "dev8-stage-execution-tools.py",
    "dev8-run-real-reads.sh",
    "dev8-sign-read.py",
    "dev8-launcher-isolation-gate.py",
    "dev8-run-read-oracles.sh",
    "dev6-trial-balance-sql-oracle.py",
    "dev6-ar-sql-oracle.py",
    "dev7-ap-sql-oracle.py",
    "dev8-persistence-audit.py",
    "dev8-runtime-dependency-inventory.py",
    "dev8-canonical-package-negative-gates.py",
    "dev8-freeze-evidence.py",
    "dev8-verify-frozen-evidence.py",
)
TOOLCHAIN_MANIFEST_NAME = "TOOLCHAIN-MANIFEST.json"
MANIFEST_FILES = (*TOOL_FILES, SERVER_BASELINE_NAME)
EXPECTED_EVIDENCE_FILES = {
    "release/release-package.tar.gz",
    "release/RELEASE-MANIFEST.json",
    "release/capabilities.json",
    "release/RELEASE-ANCHOR.json",
    "release/runtime-test-dev8.json",
    "release/build-identity.json",
    "release/github-ci.json",
    "gates/runtime-dependency-inventory.json",
    "gates/canonical-package-negative-gates.json",
    "isolation/pre-freeze.json",
    "transactions/install-completed.json",
    "transactions/runtime-completed.json",
    "security/secret-scan.json",
    f"tools/{TOOLCHAIN_MANIFEST_NAME}",
    f"tools/{SERVER_BASELINE_NAME}",
    "tools/TOOL-INVENTORY.json",
    "EVIDENCE-METADATA.json",
    "EVIDENCE-SHA256SUMS",
    *(f"reads/{name}" for name in READ_FILES),
    *(f"state/{name}" for name in STATE_FILES),
    *(f"execution/{name}" for name in EXECUTION_FILES),
    *(f"deployment/{name}" for name in DEPLOYMENT_FILES),
    *(f"tools/{name}" for name in TOOL_FILES),
}
EXPECTED_CI = {
    "run_id": 29319326192,
    "head_sha": COMMIT,
    "status": "completed",
    "conclusion": "success",
    "event": "push",
    "url": "https://github.com/yyshi127/odoo-accounting-cli-v3/actions/runs/29319326192",
    "jobs": [
        {"id": 87040612412, "name": "test (3.12)", "conclusion": "success"},
        {"id": 87040612414, "name": "wheel -> fresh venv -> outside-source CLI", "conclusion": "success"},
        {"id": 87040612507, "name": "test (3.11)", "conclusion": "success"},
    ],
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def exact_integer_fields(value: object, fields: tuple[str, ...]) -> bool:
    return isinstance(value, dict) and all(
        isinstance(value.get(field), int) and not isinstance(value.get(field), bool)
        for field in fields
    )


def validate_toolchain_manifest(document: object) -> dict[str, dict[str, object]]:
    expected_keys = {
        "schema_version", "toolchain_version", "application_release",
        "application_commit", "application_package_sha256", "source_directory",
        "files",
    }
    require(isinstance(document, dict) and set(document) == expected_keys, "toolchain manifest fields are not exact")
    require(
        isinstance(document.get("schema_version"), int)
        and not isinstance(document.get("schema_version"), bool)
        and document.get("schema_version") == 1
        and document.get("toolchain_version") == TOOLCHAIN_VERSION
        and document.get("application_release") == RELEASE
        and document.get("application_commit") == COMMIT
        and document.get("application_package_sha256") == PACKAGE_SHA256
        and document.get("source_directory") == "deployment/dev8",
        "toolchain manifest identity mismatch",
    )
    files = document.get("files")
    require(isinstance(files, list) and len(files) == len(MANIFEST_FILES), "toolchain manifest file count mismatch")
    entries: dict[str, dict[str, object]] = {}
    for entry in files:
        require(isinstance(entry, dict) and set(entry) == {"name", "sha256", "size"}, "toolchain manifest entry fields mismatch")
        name = entry.get("name")
        size = entry.get("size")
        digest_value = entry.get("sha256")
        require(
            isinstance(name, str) and name in MANIFEST_FILES and name not in entries
            and isinstance(size, int) and not isinstance(size, bool) and size >= 0
            and isinstance(digest_value, str) and HEX64.fullmatch(digest_value) is not None,
            "toolchain manifest entry is invalid",
        )
        entries[name] = entry
    require(list(entries) == list(MANIFEST_FILES), "toolchain manifest order or names mismatch")
    return entries


def validate_server_baseline(document: object) -> dict[str, object]:
    expected_keys = {
        "schema_version", "application_release", "captured_at", "hostname",
        "database_uuid", "services", "critical_files", "v3_paths_absent",
        "v3_unit_files", "v3_active_units", "production_dependency_metadata_safe",
        "production_promotion_allowed", "promotion_blockers",
    }
    require(isinstance(document, dict) and set(document) == expected_keys, "server baseline fields are not exact")
    require(
        isinstance(document.get("schema_version"), int)
        and not isinstance(document.get("schema_version"), bool)
        and document.get("schema_version") == 1
        and document.get("application_release") == RELEASE
        and isinstance(document.get("captured_at"), str)
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", document["captured_at"]) is not None
        and document.get("hostname") == "VM-0-6-ubuntu"
        and document.get("database_uuid") == DATABASE_UUID
        and document.get("v3_unit_files") == []
        and document.get("v3_active_units") == []
        and document.get("production_promotion_allowed") is False,
        "server baseline identity mismatch",
    )
    services = document.get("services")
    require(isinstance(services, list) and len(services) == 2, "server baseline service set mismatch")
    expected_units = ["odoo19.service", "sudo-pi-agent-bridge.service"]
    for expected_unit, service in zip(expected_units, services, strict=True):
        require(
            isinstance(service, dict)
            and set(service) == {"unit", "active_state", "sub_state", "main_pid", "cmdline_sha256"}
            and service.get("unit") == expected_unit
            and service.get("active_state") == "active"
            and service.get("sub_state") == "running"
            and isinstance(service.get("main_pid"), int)
            and not isinstance(service.get("main_pid"), bool)
            and int(service["main_pid"]) > 0
            and isinstance(service.get("cmdline_sha256"), str)
            and HEX64.fullmatch(service["cmdline_sha256"]) is not None,
            f"server baseline service record mismatch: {expected_unit}",
        )
    critical_files = document.get("critical_files")
    require(isinstance(critical_files, list) and len(critical_files) == 12, "server baseline critical file count mismatch")
    critical_fields = {
        "path", "sha256", "device", "inode", "uid", "gid", "mode", "nlink",
        "size", "mtime_ns", "ctime_ns",
    }
    seen_paths: set[str] = set()
    unsafe_paths: list[str] = []
    for entry in critical_files:
        require(isinstance(entry, dict) and set(entry) == critical_fields, "server baseline critical file fields mismatch")
        path = entry.get("path")
        mode = entry.get("mode")
        require(
            isinstance(path, str) and path.startswith("/mnt/odoo/odoo19/custom/") and path not in seen_paths
            and isinstance(entry.get("sha256"), str) and HEX64.fullmatch(entry["sha256"]) is not None
            and exact_integer_fields(entry, ("device", "inode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"))
            and all(int(entry[field]) >= 0 for field in ("device", "inode", "uid", "gid", "size", "mtime_ns", "ctime_ns"))
            and entry.get("nlink") == 1
            and isinstance(mode, str) and re.fullmatch(r"0[0-7]{3}", mode) is not None,
            "server baseline critical file record is invalid",
        )
        seen_paths.add(path)
        if int(mode, 8) & 0o022:
            unsafe_paths.append(path)
    expected_blockers = [
        f"{entry['path']} is group/world writable ({entry['mode']})"
        for entry in critical_files
        if int(str(entry["mode"]), 8) & 0o022
    ]
    require(
        document.get("production_dependency_metadata_safe") is (not unsafe_paths)
        and document.get("promotion_blockers") == expected_blockers,
        "server baseline production safety flags mismatch",
    )
    absent = document.get("v3_paths_absent")
    require(
        isinstance(absent, list) and len(absent) == 8 and len(set(absent)) == 8
        and all(isinstance(path, str) and path.startswith("/") for path in absent)
        and "/opt/odoo-accounting-cli-v3/current" in absent
        and "/root/odoo-accounting-cli-v3-dev8-upload" in absent,
        "server baseline V3 absence set mismatch",
    )
    return document


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON field: {key}")
        value[key] = item
    return value


SECRET_SCAN_FORMS = ["raw", "trimmed", "decoded-hex", "base64", "urlsafe-base64"]


def secret_needles(*secrets: bytes) -> set[bytes]:
    needles: set[bytes] = set()
    for secret in secrets:
        trimmed = secret.strip()
        bases = {secret, trimmed}
        try:
            bases.add(bytes.fromhex(trimmed.decode("ascii")))
        except (UnicodeDecodeError, ValueError):
            pass
        for value in tuple(bases):
            if value:
                needles.add(value)
                needles.add(base64.b64encode(value))
                needles.add(base64.urlsafe_b64encode(value))
    return {value for value in needles if len(value) >= 16}


def acquire_pipeline_lock() -> int:
    before = PIPELINE_LOCK.lstat()
    require(
        stat.S_ISREG(before.st_mode) and not PIPELINE_LOCK.is_symlink()
        and before.st_uid == 0 and before.st_gid == 0
        and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
        "freeze pipeline lock metadata is invalid",
    )
    descriptor = os.open(PIPELINE_LOCK, os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "freeze pipeline lock changed while opening")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.fstat(descriptor)
        after = PIPELINE_LOCK.lstat()
        require(
            (before.st_dev, before.st_ino) == (locked.st_dev, locked.st_ino) == (after.st_dev, after.st_ino)
            and stat.S_ISREG(after.st_mode) and not PIPELINE_LOCK.is_symlink()
            and after.st_uid == 0 and after.st_gid == 0
            and stat.S_IMODE(after.st_mode) == 0o600 and after.st_nlink == 1,
            "freeze pipeline lock changed while acquiring",
        )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        require(written > 0, "file write did not progress")
        remaining = remaining[written:]


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(value, dict), f"expected JSON object: {path}")
    return value


def load_json_bytes(payload: bytes, label: str) -> dict[str, object]:
    value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(value, dict), f"expected JSON object: {label}")
    return value


def path_info(path: Path) -> dict[str, object]:
    value = path.lstat()
    return {
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "nlink": value.st_nlink,
        "size": value.st_size,
        "device": value.st_dev,
        "inode": value.st_ino,
        "mtime_ns": value.st_mtime_ns,
        "ctime_ns": value.st_ctime_ns,
        "regular": stat.S_ISREG(value.st_mode),
        "directory": stat.S_ISDIR(value.st_mode),
        "symlink": stat.S_ISLNK(value.st_mode),
    }


def secure_source(path: Path, *, allowed_nlinks: set[int] | None = None) -> tuple[int, dict[str, object]]:
    before = path_info(path)
    expected_nlinks = {1} if allowed_nlinks is None else allowed_nlinks
    require(
        before["regular"] is True
        and before["symlink"] is False
        and before["nlink"] in expected_nlinks
        and not (int(str(before["mode"]), 8) & 0o022),
        f"unsafe evidence source: {path}",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    opened = os.fstat(descriptor)
    require(
        (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
            opened.st_ctime_ns, opened.st_uid, opened.st_gid,
            f"{stat.S_IMODE(opened.st_mode):04o}", opened.st_nlink,
        )
        == (
            before["device"], before["inode"], before["size"], before["mtime_ns"],
            before["ctime_ns"], before["uid"], before["gid"], before["mode"], before["nlink"],
        ),
        f"source changed while opening: {path}",
    )
    return descriptor, before


def secure_bytes(
    path: Path,
    *,
    max_bytes: int | None = None,
    allowed_nlinks: set[int] | None = None,
) -> bytes:
    descriptor, before = secure_source(path, allowed_nlinks=allowed_nlinks)
    chunks = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            require(max_bytes is None or total <= max_bytes, f"secure source is too large: {path}")
            chunks.append(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path_info(path)
    identity = (
        before["device"], before["inode"], before["size"], before["mtime_ns"],
        before["ctime_ns"], before["uid"], before["gid"], before["mode"], before["nlink"],
    )
    require(
        identity
        == (
            opened_after.st_dev, opened_after.st_ino, opened_after.st_size, opened_after.st_mtime_ns,
            opened_after.st_ctime_ns, opened_after.st_uid, opened_after.st_gid,
            f"{stat.S_IMODE(opened_after.st_mode):04o}", opened_after.st_nlink,
        )
        == (
            after["device"], after["inode"], after["size"], after["mtime_ns"],
            after["ctime_ns"], after["uid"], after["gid"], after["mode"], after["nlink"],
        ),
        f"secure source changed while reading: {path}",
    )
    return b"".join(chunks)


def baselined_file_bytes(entry: dict[str, object]) -> bytes:
    path = Path(str(entry["path"]))

    def fingerprint(value: os.stat_result) -> tuple[object, ...]:
        return (
            value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            f"{stat.S_IMODE(value.st_mode):04o}", value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns,
        )

    expected = (
        entry["device"], entry["inode"], entry["uid"], entry["gid"],
        entry["mode"], entry["nlink"], entry["size"], entry["mtime_ns"],
        entry["ctime_ns"],
    )
    before = path.lstat()
    require(
        path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink()
        and stat.S_ISREG(before.st_mode) and fingerprint(before) == expected,
        f"critical file differs from read-only baseline: {path}",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    chunks: list[bytes] = []
    try:
        opened = os.fstat(descriptor)
        require(fingerprint(opened) == expected, f"critical file changed while opening: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    require(
        fingerprint(opened_after) == expected and fingerprint(after) == expected,
        f"critical file changed while reading: {path}",
    )
    payload = b"".join(chunks)
    require(hashlib.sha256(payload).hexdigest() == entry["sha256"], f"critical file hash mismatch: {path}")
    return payload


def current_journal_identity(path: Path, kind: str) -> dict[str, object]:
    before = path_info(path)
    require(
        before["symlink"] is False and path.resolve(strict=True) == path
        and ((kind == "file" and before["regular"] is True and before["nlink"] == 1)
             or (kind == "directory" and before["directory"] is True)),
        f"pipeline journal object metadata mismatch: {path}",
    )
    result: dict[str, object] = {
        "dev": before["device"], "ino": before["inode"], "kind": kind,
        "uid": before["uid"], "gid": before["gid"],
        "mode": int(str(before["mode"]), 8),
    }
    if kind == "file":
        payload = secure_bytes(path)
        after = path_info(path)
        require(
            (before["device"], before["inode"], before["size"], before["mtime_ns"])
            == (after["device"], after["inode"], after["size"], after["mtime_ns"]),
            f"pipeline journal object changed while hashing: {path}",
        )
        result.update({"size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    return result


def journal_object_plan(
    path: Path,
    kind: str,
    uid: int,
    gid: int,
    modes: list[int],
    unique: bool,
    source: str | None,
    *,
    unrecorded_owners: list[list[int]] | None = None,
    unrecorded_modes: list[int] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "path": str(path), "kind": kind, "uid": uid, "gid": gid,
        "modes": modes, "unique": unique, "source": source, "identity": None,
    }
    if unrecorded_owners is not None or unrecorded_modes is not None:
        require(unrecorded_owners is not None and unrecorded_modes is not None, "incomplete runtime journal plan")
        result["unrecorded_owners"] = unrecorded_owners
        result["unrecorded_modes"] = unrecorded_modes
    return result


def validate_recorded_identity(recorded: object, planned: dict[str, object], label: str) -> dict[str, object]:
    kind = str(planned["kind"])
    fields = {"dev", "ino", "kind", "uid", "gid", "mode"}
    if kind == "file":
        fields |= {"size", "sha256"}
    require(
        isinstance(recorded, dict) and set(recorded) == fields
        and all(
            isinstance(recorded[field], int) and not isinstance(recorded[field], bool)
            for field in ("dev", "ino", "uid", "gid", "mode")
        )
        and int(recorded["dev"]) >= 0 and int(recorded["ino"]) >= 0
        and recorded["kind"] == kind
        and recorded["uid"] == planned["uid"] and recorded["gid"] == planned["gid"]
        and recorded["mode"] in planned["modes"]
        and (
            kind != "file"
            or (
                isinstance(recorded["size"], int) and not isinstance(recorded["size"], bool)
                and int(recorded["size"]) >= 0
                and isinstance(recorded["sha256"], str)
                and HEX64.fullmatch(recorded["sha256"]) is not None
            )
        ),
        f"pipeline journal object identity mismatch: {label}",
    )
    return recorded


def validate_completed_journals(
    install: dict[str, object],
    runtime: dict[str, object],
    odoo_uid: int,
    odoo_gid: int,
) -> dict[str, object]:
    install_keys = {"schema_version", "kind", "release", "transaction_id", "state", "parents", "objects"}
    runtime_keys = install_keys | {"upstream_install_transaction_id", "upstream_install_identity_sha256"}
    install_id = install.get("transaction_id")
    runtime_id = runtime.get("transaction_id")
    require(
        set(install) == install_keys
        and isinstance(install.get("schema_version"), int) and not isinstance(install.get("schema_version"), bool)
        and install.get("schema_version") == 1
        and install.get("kind") == "install" and install.get("release") == RELEASE
        and install.get("state") == "completed" and isinstance(install_id, str)
        and re.fullmatch(r"[0-9a-f]{32}", install_id) is not None,
        "completed install transaction journal mismatch",
    )
    require(
        set(runtime) == runtime_keys
        and isinstance(runtime.get("schema_version"), int) and not isinstance(runtime.get("schema_version"), bool)
        and runtime.get("schema_version") == 1
        and runtime.get("kind") == "runtime" and runtime.get("release") == RELEASE
        and runtime.get("state") == "completed" and isinstance(runtime_id, str)
        and re.fullmatch(r"[0-9a-f]{32}", runtime_id) is not None
        and runtime.get("upstream_install_transaction_id") == install_id
        and isinstance(runtime.get("upstream_install_identity_sha256"), str)
        and HEX64.fullmatch(str(runtime["upstream_install_identity_sha256"])) is not None,
        "completed runtime transaction journal mismatch",
    )

    root = Path("/opt/odoo-accounting-cli-v3")
    releases = root / "releases"
    packages = root / "packages"
    anchors = root / "trusted-artifacts"
    config_parent = Path("/etc/odoo-accounting-cli-v3")
    candidate_parent = Path("/var/lib/odoo-accounting-cli-v3/test/candidates")
    candidate_staging_parent = Path("/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging")
    secret_parent = config_parent / "secrets/test"
    parent_specs = {
        "install": {
            "root": (root, {(0, 0)}, None),
            "releases": (releases, {(0, 0)}, None),
            "packages": (packages, {(0, 0)}, None),
            "anchors": (anchors, {(0, 0)}, None),
        },
        "runtime": {
            "config_parent": (config_parent, {(0, 0)}, None),
            "candidate_parent": (candidate_parent, {(0, 0), (odoo_uid, odoo_gid)}, None),
            "candidate_staging_parent": (candidate_staging_parent, {(0, 0)}, {0o700}),
            "secret_parent": (secret_parent, {(0, 0), (0, odoo_gid)}, None),
        },
    }
    for kind, document in (("install", install), ("runtime", runtime)):
        parents = document.get("parents")
        specifications = parent_specs[kind]
        require(isinstance(parents, dict) and set(parents) == set(specifications), f"{kind} journal parent set mismatch")
        for label, (path, owners, modes) in specifications.items():
            record = parents[label]
            observed = current_journal_identity(path, "directory")
            require(
                isinstance(record, dict) and set(record) == {"path", "identity"}
                and record["path"] == str(path)
                and isinstance(record["identity"], dict)
                and set(record["identity"]) == {"dev", "ino", "kind", "uid", "gid", "mode"}
                and all(
                    isinstance(record["identity"][field], int)
                    and not isinstance(record["identity"][field], bool)
                    for field in ("dev", "ino", "uid", "gid", "mode")
                )
                and record["identity"] == observed
                and (int(observed["uid"]), int(observed["gid"])) in owners
                and not (int(observed["mode"]) & 0o022)
                and (modes is None or int(observed["mode"]) in modes),
                f"{kind} journal parent identity mismatch: {label}",
            )

    package_name = f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
    install_plans = {
        "package_staging": journal_object_plan(packages / f".{package_name}.{install_id}.staging", "file", 0, 0, [0o400, 0o444], True, None),
        "anchor_staging": journal_object_plan(anchors / f".{RELEASE}.{install_id}.anchor.staging", "file", 0, 0, [0o400, 0o444], True, None),
        "release_staging": journal_object_plan(releases / f".{RELEASE}.{install_id}.release.staging", "directory", 0, 0, [0o555], True, None),
        "package": journal_object_plan(packages / package_name, "file", 0, 0, [0o444], False, "package_staging"),
        "release": journal_object_plan(releases / RELEASE, "directory", 0, 0, [0o555], False, "release_staging"),
        "anchor": journal_object_plan(anchors / f"{RELEASE}.json", "file", 0, 0, [0o444], False, "anchor_staging"),
    }
    odoo_owner = [odoo_uid, odoo_gid]
    runtime_plans = {
        "config_staging": journal_object_plan(config_parent / f".runtime-test-dev8.json.{runtime_id}.staging", "file", 0, 0, [0o644], True, None, unrecorded_owners=[[0, 0]], unrecorded_modes=[0o600, 0o644]),
        "candidate_staging": journal_object_plan(candidate_staging_parent / f".{RELEASE}.{runtime_id}.candidate.staging", "directory", odoo_uid, odoo_gid, [0o700], True, None, unrecorded_owners=[[0, 0], odoo_owner], unrecorded_modes=[0o700]),
        "auth_staging": journal_object_plan(secret_parent / f".dev8-auth.{runtime_id}.hmac.staging", "file", 0, odoo_gid, [0o640], True, None, unrecorded_owners=[[0, 0], [0, odoo_gid]], unrecorded_modes=[0o600, 0o640]),
        "receipt_staging": journal_object_plan(secret_parent / f".dev8-receipt.{runtime_id}.hmac.staging", "file", 0, odoo_gid, [0o640], True, None, unrecorded_owners=[[0, 0], [0, odoo_gid]], unrecorded_modes=[0o600, 0o640]),
        "config": journal_object_plan(config_parent / "runtime-test-dev8.json", "file", 0, 0, [0o644], False, "config_staging", unrecorded_owners=[[0, 0]], unrecorded_modes=[0o644]),
        "candidate": journal_object_plan(candidate_parent / RELEASE, "directory", odoo_uid, odoo_gid, [0o700], False, "candidate_staging", unrecorded_owners=[odoo_owner], unrecorded_modes=[0o700]),
        "auth_secret": journal_object_plan(secret_parent / "dev8-auth.hmac", "file", 0, odoo_gid, [0o640], False, "auth_staging", unrecorded_owners=[[0, odoo_gid]], unrecorded_modes=[0o640]),
        "receipt_secret": journal_object_plan(secret_parent / "dev8-receipt.hmac", "file", 0, odoo_gid, [0o640], False, "receipt_staging", unrecorded_owners=[[0, odoo_gid]], unrecorded_modes=[0o640]),
    }
    final_identities: dict[str, dict[str, dict[str, object]]] = {"install": {}, "runtime": {}}
    for kind, document, plans in (("install", install, install_plans), ("runtime", runtime, runtime_plans)):
        objects = document.get("objects")
        require(isinstance(objects, dict) and set(objects) == set(plans), f"{kind} journal object set mismatch")
        for label, planned in plans.items():
            record = objects[label]
            require(
                isinstance(record, dict) and set(record) == set(planned)
                and canonical({**record, "identity": None}) == canonical(planned),
                f"{kind} journal object plan mismatch: {label}",
            )
            recorded = validate_recorded_identity(record["identity"], planned, f"{kind}:{label}")
            path = Path(str(planned["path"]))
            if planned["unique"] is True:
                require(not os.path.lexists(path), f"completed {kind} journal retains staging: {label}")
            else:
                observed = current_journal_identity(path, str(planned["kind"]))
                require(recorded == observed, f"{kind} journal final identity mismatch: {label}")
                final_identities[kind][label] = observed
        for label, planned in plans.items():
            source = planned["source"]
            if source is not None:
                require(objects[label]["identity"] == objects[source]["identity"], f"{kind} journal source identity mismatch: {label}")

    install_objects = install["objects"]
    require(
        install_objects["package"]["identity"]["size"] == PACKAGE_SIZE
        and install_objects["package"]["identity"]["sha256"] == PACKAGE_SHA256,
        "completed install package identity mismatch",
    )
    binding = {
        "anchor": install_objects["anchor"]["identity"],
        "install_transaction_id": install_id,
        "manifest_sha256": MANIFEST_SHA256,
        "package": install_objects["package"]["identity"],
        "registry_digest": REGISTRY_DIGEST,
        "release": install_objects["release"]["identity"],
    }
    binding_sha256 = hashlib.sha256(canonical(binding)).hexdigest()
    require(runtime["upstream_install_identity_sha256"] == binding_sha256, "runtime journal upstream install identity mismatch")
    return {
        "install_transaction_id": install_id,
        "runtime_transaction_id": runtime_id,
        "install_binding_sha256": binding_sha256,
        "install_final_identities": final_identities["install"],
        "runtime_final_identities": final_identities["runtime"],
    }


def validate_relative(relative: str) -> Path:
    portable = PurePosixPath(relative)
    require(
        not portable.is_absolute()
        and portable.parts
        and all(part not in {"", ".", ".."} for part in portable.parts)
        and not relative.lower().endswith(".hmac")
        and "/secrets/" not in f"/{relative.lower()}/",
        f"unsafe evidence destination: {relative}",
    )
    return Path(*portable.parts)


def copy_evidence(source: Path, relative: str) -> None:
    descriptor, before = secure_source(source)
    destination = STAGING / validate_relative(relative)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(output, remaining)
                require(written > 0, "evidence copy did not progress")
                remaining = remaining[written:]
        os.fsync(output)
        after_open = os.fstat(descriptor)
    finally:
        os.close(output)
        os.close(descriptor)
    after = path_info(source)
    identity = (
        before["device"], before["inode"], before["size"], before["mtime_ns"],
        before["ctime_ns"], before["uid"], before["gid"], before["mode"], before["nlink"],
    )
    require(
        identity
        == (
            after_open.st_dev, after_open.st_ino, after_open.st_size, after_open.st_mtime_ns,
            after_open.st_ctime_ns, after_open.st_uid, after_open.st_gid,
            f"{stat.S_IMODE(after_open.st_mode):04o}", after_open.st_nlink,
        )
        == (
            after["device"], after["inode"], after["size"], after["mtime_ns"],
            after["ctime_ns"], after["uid"], after["gid"], after["mode"], after["nlink"],
        )
        and digest.hexdigest() == sha256(destination),
        f"evidence source changed during copy: {source}",
    )


def write_json(relative: str, value: dict[str, object]) -> None:
    destination = STAGING / validate_relative(relative)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_bytes(relative: str, payload: bytes) -> None:
    destination = STAGING / validate_relative(relative)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_private_directory(path: Path, names: set[str], uid: int = 0) -> None:
    require(path.is_absolute() and path.parent == Path("/tmp"), f"evidence directory is not a direct /tmp child: {path}")
    info = path_info(path)
    require(
        info["directory"] is True
        and info["symlink"] is False
        and info["uid"] == uid
        and info["mode"] == "0700"
        and path.resolve(strict=True) == path,
        f"private evidence directory metadata is invalid: {path}",
    )
    require({item.name for item in path.iterdir()} == names, f"evidence file set is not exact: {path}")
    for name in names:
        source = path / name
        value = path_info(source)
        require(
            value["uid"] == uid
            and value["gid"] == (grp.getgrnam("odoo").gr_gid if uid == pwd.getpwnam("odoo").pw_uid else 0)
            and value["mode"] == "0600",
            f"private evidence file metadata is invalid: {source}",
        )
        descriptor, _ = secure_source(source)
        os.close(descriptor)


def validate_private_report(path: Path) -> None:
    require(path.is_absolute() and path.parent.parent == Path("/tmp"), "gate report must be in a private direct /tmp child")
    parent = path.parent
    parent_info = path_info(parent)
    value = path_info(path)
    require(
        parent_info["directory"] is True and parent_info["symlink"] is False
        and parent_info["uid"] == 0 and parent_info["gid"] == 0 and parent_info["mode"] == "0700"
        and value["regular"] is True and value["symlink"] is False
        and value["uid"] == 0 and value["gid"] == 0 and value["mode"] == "0600" and value["nlink"] == 1,
        f"private gate report metadata is invalid: {path}",
    )
    descriptor, _ = secure_source(path)
    os.close(descriptor)


def run_checked(*arguments: str) -> str:
    completed = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8", check=False, timeout=30)
    require(completed.returncode == 0, f"isolation command failed: {arguments!r}: {completed.stderr.strip()}")
    return completed.stdout


def run_unit_listing(*arguments: str) -> str:
    completed = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8", check=False, timeout=30)
    no_matches = completed.returncode == 1 and not completed.stdout.strip() and not completed.stderr.strip()
    require(
        completed.returncode == 0 or no_matches,
        f"isolation unit listing failed: {arguments!r}: returncode={completed.returncode}: {completed.stderr.strip()}",
    )
    return completed.stdout


def live_isolation(server_baseline: dict[str, object]) -> dict[str, object]:
    checks: dict[str, bool] = {}
    services: dict[str, object] = {}
    for expected_service in server_baseline["services"]:
        unit = str(expected_service["unit"])
        expected_pid = int(expected_service["main_pid"])
        output = run_checked(
            "/usr/bin/systemctl", "show", unit,
            "--property=ActiveState", "--property=SubState", "--property=MainPID",
        )
        properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        pid = int(properties.get("MainPID", "0") or "0")
        process = Path(f"/proc/{pid}")
        cmdline = (process / "cmdline").read_bytes().replace(b"\0", b" ") if process.is_dir() else b""
        cmdline_sha256 = hashlib.sha256(cmdline).hexdigest()
        passed = (
            properties.get("ActiveState") == "active"
            and properties.get("SubState") == "running"
            and pid == expected_pid
            and process.is_dir()
            and cmdline_sha256 == expected_service["cmdline_sha256"]
            and b"odoo-accounting-cli-v3" not in cmdline
        )
        checks[f"{unit}_stable"] = passed
        services[unit] = {
            "pid": pid, "expected_pid": expected_pid,
            "cmdline_sha256": cmdline_sha256,
            "expected_cmdline_sha256": expected_service["cmdline_sha256"],
            "active": properties.get("ActiveState"),
            "substate": properties.get("SubState"),
            "references_v3": b"odoo-accounting-cli-v3" in cmdline,
        }

    critical_reports = []
    for entry in server_baseline["critical_files"]:
        raw_path = str(entry["path"])
        path = Path(raw_path)
        payload = baselined_file_bytes(entry)
        value = path_info(path)
        observed = hashlib.sha256(payload).hexdigest()
        metadata_matches = (
            value["device"] == entry["device"] and value["inode"] == entry["inode"]
            and value["uid"] == entry["uid"] and value["gid"] == entry["gid"]
            and value["mode"] == entry["mode"] and value["nlink"] == entry["nlink"]
            and value["size"] == entry["size"] and value["mtime_ns"] == entry["mtime_ns"]
            and value["ctime_ns"] == entry["ctime_ns"]
        )
        matched = observed == entry["sha256"] and metadata_matches
        checks[f"v2:{path.name}:{len(critical_reports)}"] = matched
        critical_reports.append(
            {
                "path": raw_path,
                "expected_sha256": entry["sha256"],
                "sha256": observed,
                "expected_metadata": {
                    key: entry[key]
                    for key in ("device", "inode", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")
                },
                "observed_metadata": {
                    key: value[key]
                    for key in ("device", "inode", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns")
                },
                "metadata_matches": metadata_matches,
                "group_or_world_writable": bool(int(str(entry["mode"]), 8) & 0o022),
                "matches": matched,
            }
        )

    current = Path("/opt/odoo-accounting-cli-v3/current")
    checks["current_absent"] = not os.path.lexists(current)
    unit_files = run_unit_listing("/usr/bin/systemctl", "list-unit-files", "--no-legend", "odoo-accounting-cli-v3*")
    active_units = run_unit_listing("/usr/bin/systemctl", "list-units", "--all", "--no-legend", "odoo-accounting-cli-v3*")
    checks["v3_units_absent"] = not unit_files.strip() and not active_units.strip()
    database_uuid = run_checked(
        "/usr/bin/sudo", "-n", "-u", "postgres", "/usr/bin/env", "-i",
        "HOME=/var/lib/postgresql", "LANG=C.UTF-8", "PATH=/usr/bin:/bin",
        "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--tuples-only", "--no-align",
        "--dbname=odoo_test", "--command=SELECT value FROM ir_config_parameter WHERE key = 'database.uuid';",
    ).strip()
    checks["odoo_test_uuid"] = database_uuid == DATABASE_UUID

    package_info = path_info(PACKAGE)
    checks["canonical_package"] = (
        package_info["uid"] == 0 and package_info["gid"] == 0 and package_info["mode"] == "0444"
        and package_info["nlink"] == 1 and package_info["regular"] is True and package_info["symlink"] is False
        and package_info["size"] == PACKAGE_SIZE and sha256(PACKAGE) == PACKAGE_SHA256
    )
    tree_unsafe = []
    file_count = 0
    for path in [RELEASE_ROOT, *RELEASE_ROOT.rglob("*")]:
        value = path_info(path)
        expected_mode = "0555" if value["directory"] or path == RELEASE_ROOT / "bin/odoo-accounting-cli-v3" else "0444"
        if value["uid"] != 0 or value["gid"] != 0 or value["symlink"] or value["mode"] != expected_mode:
            tree_unsafe.append(str(path.relative_to(RELEASE_ROOT)) if path != RELEASE_ROOT else ".")
        if value["regular"]:
            file_count += 1
            if value["nlink"] != 1:
                tree_unsafe.append(f"linked:{path.relative_to(RELEASE_ROOT)}")
    checks["release_tree"] = not tree_unsafe and file_count == 64 and sha256(RELEASE_ROOT / "bin/odoo-accounting-cli-v3") == LAUNCHER_SHA256

    manifest = load_json(RELEASE_ROOT / "RELEASE-MANIFEST.json")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    checks["release_manifest"] = (
        manifest.get("version") == VERSION and manifest.get("commit") == COMMIT
        and manifest.get("manifest_sha256") == MANIFEST_SHA256
        and hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest() == MANIFEST_SHA256
        and len(manifest.get("files", [])) == 63
    )
    registry = load_json(RELEASE_ROOT / "registry/capabilities.json")
    capabilities = registry.get("capabilities")
    staged = sorted(item["id"] for item in capabilities or [] if "test" in item.get("staged_environments", []))
    enabled = sorted(item["id"] for item in capabilities or [] if "test" in item.get("enabled_environments", []))
    checks["registry"] = (
        isinstance(capabilities, list) and len(capabilities) == 22
        and hashlib.sha256(canonical(capabilities)).hexdigest() == REGISTRY_DIGEST
        and staged == ["acct.ap.open_items.v1", "acct.ar.open_items.v1", "acct.gl.trial_balance.v1", "acct.registry.list.v1"]
        and enabled == []
    )
    runtime = load_json(RUNTIME)
    checks["runtime_config"] = sha256(RUNTIME) == RUNTIME_SHA256 and runtime.get("release_root") == str(RELEASE_ROOT) and runtime.get("canonical_package_path") == str(PACKAGE) and runtime.get("canonical_package_sha256") == PACKAGE_SHA256 and runtime.get("database_uuid") == DATABASE_UUID
    for field in ("odoo_python", "odoo_bin", "odoo_config"):
        checks[f"runtime:{field}"] = sha256(Path(str(runtime[field]))) == runtime[f"{field}_sha256"]
    odoo_uid = pwd.getpwnam("odoo").pw_uid
    checks["state_modes"] = all(
        (lambda value: value["uid"] == odoo_uid and value["mode"] == "0600" and value["regular"] is True and value["symlink"] is False)(path_info(Path(str(runtime[field]))))
        for field in ("auth_state_path", "receipt_state_path")
    )
    expected_anchor = {"commit": COMMIT, "manifest_sha256": MANIFEST_SHA256, "package_sha256": PACKAGE_SHA256, "release": RELEASE}
    checks["release_anchor"] = load_json(RELEASE_ANCHOR) == expected_anchor
    report = {
        "schema_version": 1,
        "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "server_baseline_captured_at": server_baseline["captured_at"],
        "release": RELEASE,
        "services": services,
        "v2_critical": critical_reports,
        "database_uuid": database_uuid,
        "release_file_count": file_count,
        "release_tree_unsafe": tree_unsafe,
        "checks": checks,
        "all_checks_passed": all(checks.values()),
        "production_dependency_metadata_safe": server_baseline["production_dependency_metadata_safe"],
        "production_dependency_closure_complete": False,
        "production_promotion_allowed": False,
        "promotion_blockers": server_baseline["promotion_blockers"],
    }
    require(report["all_checks_passed"] is True, "pre-freeze live isolation did not pass")
    return report


def validate_inputs(
    args: argparse.Namespace,
) -> tuple[dict[str, object], dict[str, object], dict[str, bytes]]:
    validate_private_directory(args.read_evidence, READ_FILES)
    validate_private_directory(args.state_evidence, STATE_FILES)
    validate_private_directory(args.execution_evidence, EXECUTION_FILES)
    validate_private_directory(args.deployment_evidence, DEPLOYMENT_FILES)
    validate_private_report(args.dependency_inventory)
    validate_private_report(args.negative_gates)
    require(sha256(args.read_evidence / "read-plan.input.json") == PLAN_SHA256, "read plan hash mismatch")
    persistence = load_json(args.state_evidence / "persistence-audit.json")
    require(
        persistence.get("all_checks_passed") is True
        and persistence.get("release") == RELEASE
        and persistence.get("commit") == COMMIT
        and persistence.get("git_tree") == TREE
        and persistence.get("package_sha256") == PACKAGE_SHA256
        and persistence.get("manifest_sha256") == MANIFEST_SHA256
        and persistence.get("registry_digest") == REGISTRY_DIGEST
        and persistence.get("runtime_config_sha256") == RUNTIME_SHA256
        and persistence.get("read_plan_sha256") == PLAN_SHA256
        and persistence.get("audit_event_count") == 4
        and persistence.get("capability_counts") == {
            "acct.ap.open_items.v1": 1, "acct.ar.open_items.v1": 1,
            "acct.gl.trial_balance.v1": 1, "acct.registry.list.v1": 1,
        }
        and persistence.get("production_promotion_allowed") is False,
        "persistence evidence identity mismatch",
    )
    audit_head = persistence.get("audit_head")
    require(isinstance(audit_head, str) and HEX64.fullmatch(audit_head) is not None, "audit head is invalid")
    oracle = load_json(args.read_evidence / "read-oracles.audit.json")
    require(oracle.get("all_checks_passed") is True and oracle.get("release") == RELEASE and oracle.get("production_promotion_allowed") is False, "read oracle audit did not pass")

    staging = load_json(args.execution_evidence / "execution-staging-audit.json")
    odoo_uid = pwd.getpwnam("odoo").pw_uid
    odoo_gid = grp.getgrnam("odoo").gr_gid
    pipeline_lock = staging.get("pipeline_lock", {})
    live_pipeline_lock = path_info(PIPELINE_LOCK)
    require(
        isinstance(pipeline_lock, dict)
        and exact_integer_fields(pipeline_lock, ("device", "inode", "uid", "gid", "nlink"))
        and set(pipeline_lock) == {
            "path", "device", "inode", "uid", "gid", "mode", "nlink",
            "regular", "not_symlink", "o_nofollow", "same_inode",
            "exclusive", "acquired",
        }
        and pipeline_lock.get("path") == str(PIPELINE_LOCK)
        and pipeline_lock.get("device") == live_pipeline_lock.get("device")
        and pipeline_lock.get("inode") == live_pipeline_lock.get("inode")
        and pipeline_lock.get("uid") == live_pipeline_lock.get("uid") == 0
        and pipeline_lock.get("gid") == live_pipeline_lock.get("gid") == 0
        and pipeline_lock.get("mode") == live_pipeline_lock.get("mode") == "0600"
        and pipeline_lock.get("nlink") == live_pipeline_lock.get("nlink") == 1
        and pipeline_lock.get("regular") is live_pipeline_lock.get("regular") is True
        and pipeline_lock.get("not_symlink") is True
        and live_pipeline_lock.get("symlink") is False
        and pipeline_lock.get("o_nofollow") is True
        and pipeline_lock.get("same_inode") is True
        and pipeline_lock.get("exclusive") is True
        and pipeline_lock.get("acquired") is True,
        "execution pipeline lock evidence mismatch",
    )
    pipeline_transactions = staging.get("pipeline_transactions", {})
    transaction_keys = {
        "schema_version", "install_journal", "runtime_journal",
        "install_transaction_id", "install_state", "runtime_transaction_id",
        "runtime_state", "runtime_upstream_install_transaction_id",
        "computed_install_identity_sha256",
        "runtime_upstream_install_identity_sha256", "install_final_objects",
        "runtime_final_objects", "staging_objects_absent", "all_checks_passed",
    }
    require(
        isinstance(pipeline_transactions, dict)
        and set(pipeline_transactions) == transaction_keys
        and isinstance(pipeline_transactions.get("schema_version"), int)
        and not isinstance(pipeline_transactions.get("schema_version"), bool)
        and pipeline_transactions.get("schema_version") == 1
        and pipeline_transactions.get("install_state") == "completed"
        and pipeline_transactions.get("runtime_state") == "completed"
        and isinstance(pipeline_transactions.get("install_transaction_id"), str)
        and re.fullmatch(r"[0-9a-f]{32}", pipeline_transactions["install_transaction_id"]) is not None
        and isinstance(pipeline_transactions.get("runtime_transaction_id"), str)
        and re.fullmatch(r"[0-9a-f]{32}", pipeline_transactions["runtime_transaction_id"]) is not None
        and pipeline_transactions.get("runtime_upstream_install_transaction_id") == pipeline_transactions.get("install_transaction_id")
        and pipeline_transactions.get("computed_install_identity_sha256") == pipeline_transactions.get("runtime_upstream_install_identity_sha256")
        and isinstance(pipeline_transactions.get("computed_install_identity_sha256"), str)
        and HEX64.fullmatch(pipeline_transactions["computed_install_identity_sha256"]) is not None
        and pipeline_transactions.get("staging_objects_absent") is True
        and pipeline_transactions.get("all_checks_passed") is True,
        "pipeline transaction evidence envelope mismatch",
    )
    install_journal_payload = secure_bytes(INSTALL_JOURNAL, max_bytes=1_048_576)
    runtime_journal_payload = secure_bytes(RUNTIME_JOURNAL, max_bytes=1_048_576)
    install_document = json.loads(install_journal_payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    runtime_document = json.loads(runtime_journal_payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(install_document, dict) and isinstance(runtime_document, dict), "pipeline transaction journal is not an object")
    journal_contract = validate_completed_journals(install_document, runtime_document, odoo_uid, odoo_gid)
    require(
        journal_contract["install_transaction_id"] == pipeline_transactions["install_transaction_id"]
        and journal_contract["runtime_transaction_id"] == pipeline_transactions["runtime_transaction_id"]
        and journal_contract["install_binding_sha256"] == pipeline_transactions["computed_install_identity_sha256"]
        == pipeline_transactions["runtime_upstream_install_identity_sha256"],
        "live completed pipeline transaction journals mismatch execution evidence",
    )
    journal_report_keys = {
        "path", "device", "inode", "uid", "gid", "mode", "nlink",
        "regular", "not_symlink", "o_nofollow", "same_inode", "sha256",
    }
    for label, path, payload in (
        ("install_journal", INSTALL_JOURNAL, install_journal_payload),
        ("runtime_journal", RUNTIME_JOURNAL, runtime_journal_payload),
    ):
        report = pipeline_transactions[label]
        current = path_info(path)
        require(
            isinstance(report, dict) and set(report) == journal_report_keys
            and exact_integer_fields(report, ("device", "inode", "uid", "gid", "nlink"))
            and report.get("path") == str(path)
            and report.get("device") == current.get("device")
            and report.get("inode") == current.get("inode")
            and report.get("uid") == current.get("uid") == 0
            and report.get("gid") == current.get("gid") == 0
            and report.get("mode") == current.get("mode") == "0600"
            and report.get("nlink") == current.get("nlink") == 1
            and report.get("regular") is current.get("regular") is True
            and report.get("not_symlink") is True and current.get("symlink") is False
            and report.get("o_nofollow") is True and report.get("same_inode") is True
            and report.get("sha256") == hashlib.sha256(payload).hexdigest(),
            f"pipeline {label} metadata mismatch",
        )
    install_objects = {
        "package": (PACKAGE, "file", 0, 0, "0444"),
        "release": (RELEASE_ROOT, "directory", 0, 0, "0555"),
        "anchor": (RELEASE_ANCHOR, "file", 0, 0, "0444"),
    }
    runtime_objects = {
        "config": (RUNTIME, "file", 0, 0, "0644"),
        "candidate": (Path("/var/lib/odoo-accounting-cli-v3/test/candidates") / RELEASE, "directory", odoo_uid, odoo_gid, "0700"),
        "auth_secret": (Path("/etc/odoo-accounting-cli-v3/secrets/test/dev8-auth.hmac"), "file", 0, odoo_gid, "0640"),
        "receipt_secret": (Path("/etc/odoo-accounting-cli-v3/secrets/test/dev8-receipt.hmac"), "file", 0, odoo_gid, "0640"),
    }
    for report_key, expected_objects in (("install_final_objects", install_objects), ("runtime_final_objects", runtime_objects)):
        object_reports = pipeline_transactions[report_key]
        require(isinstance(object_reports, dict) and set(object_reports) == set(expected_objects), f"pipeline {report_key} set mismatch")
        for label, (path, kind, uid, gid, mode) in expected_objects.items():
            report = object_reports[label]
            current = path_info(path)
            require(
                isinstance(report, dict)
                and exact_integer_fields(report, ("device", "inode", "uid", "gid"))
                and set(report) == {"path", "device", "inode", "kind", "uid", "gid", "mode", "journal_identity_matched"}
                and report.get("path") == str(path) and report.get("kind") == kind
                and report.get("device") == current.get("device")
                and report.get("inode") == current.get("inode")
                and report.get("uid") == current.get("uid") == uid
                and report.get("gid") == current.get("gid") == gid
                and report.get("mode") == current.get("mode") == mode
                and report.get("journal_identity_matched") is True
                and current.get("symlink") is False
                and ((kind == "file" and current.get("regular") is True) or (kind == "directory" and current.get("directory") is True)),
                f"pipeline final object evidence mismatch: {label}",
            )
    stages = staging.get("stages", [])
    by_purpose = {item.get("purpose"): item for item in stages if isinstance(item, dict)}
    expected_guards = {
        "same_fd_source": True,
        "o_nofollow": True,
        "o_excl": True,
        "pre_post_source_identity_equal": True,
        "fsync": True,
    }
    stage_metadata_ok = len(stages) == 3 and set(by_purpose) == set(SOURCE_HASHES)
    for purpose, item in by_purpose.items():
        directory = item.get("staging_dir", {})
        staged = item.get("staged_file", {})
        execution = item.get("execution", {})
        expected_mode = "0400" if purpose == "real-read-runner" else "0440"
        expected_gid = 0 if purpose == "real-read-runner" else odoo_gid
        expected_exec_uid = 0 if purpose == "real-read-runner" else odoo_uid
        expected_exec_gid = 0 if purpose == "real-read-runner" else odoo_gid
        stage_metadata_ok = stage_metadata_ok and (
            directory.get("parent") == "/run" and directory.get("uid") == 0
            and directory.get("gid") == odoo_gid and directory.get("mode") == "0750"
            and directory.get("random") is True
            and staged.get("uid") == 0 and staged.get("gid") == expected_gid
            and staged.get("mode") == expected_mode and staged.get("nlink") == 1
            and staged.get("regular") is True and staged.get("not_symlink") is True
            and execution.get("uid") == expected_exec_uid and execution.get("gid") == expected_exec_gid
            and execution.get("exit_code") == 0
            and execution.get("timed_out") is False
            and execution.get("process_group_reaped") is True
            and item.get("copy_guards") == expected_guards
        )
    oracle_execution = staging.get("oracle", {})
    oracle_runner = oracle_execution.get("runner", {})
    oracle_sources = oracle_execution.get("sources", [])
    oracle_by_name = {
        item.get("source_name"): item
        for item in oracle_sources
        if isinstance(item, dict)
    }
    expected_oracle_names = {
        "dev6-trial-balance-sql-oracle.py",
        "dev6-ar-sql-oracle.py",
        "dev7-ap-sql-oracle.py",
    }
    oracle_metadata_ok = (
        len(oracle_sources) == 3
        and set(oracle_by_name) == expected_oracle_names
        and oracle_runner.get("source_name") == "dev8-run-read-oracles.sh"
        and oracle_runner.get("source_sha256") == EXECUTION_SOURCE_HASHES["dev8-run-read-oracles.sh"]
        and oracle_runner.get("execution", {}).get("uid") == 0
        and oracle_runner.get("execution", {}).get("gid") == 0
        and oracle_runner.get("execution", {}).get("exit_code") == 0
        and oracle_runner.get("execution", {}).get("timed_out") is False
        and oracle_runner.get("execution", {}).get("process_group_reaped") is True
        and oracle_runner.get("staging_dir", {}).get("parent") == "/run"
        and oracle_runner.get("staging_dir", {}).get("uid") == 0
        and oracle_runner.get("staging_dir", {}).get("gid") == odoo_gid
        and oracle_runner.get("staging_dir", {}).get("mode") == "0750"
        and oracle_runner.get("staging_dir", {}).get("random") is True
        and oracle_runner.get("staged_file", {}).get("uid") == 0
        and oracle_runner.get("staged_file", {}).get("gid") == 0
        and oracle_runner.get("staged_file", {}).get("mode") == "0400"
        and oracle_runner.get("staged_file", {}).get("nlink") == 1
        and oracle_runner.get("staged_file", {}).get("regular") is True
        and oracle_runner.get("staged_file", {}).get("not_symlink") is True
        and oracle_runner.get("copy_guards") == expected_guards
        and oracle_runner.get("cleanup") == {"file_absent": True, "dir_absent": True}
    )
    for name, item in oracle_by_name.items():
        staged = item.get("staged_file", {})
        execution = item.get("execution", {})
        cleanup = item.get("cleanup", {})
        oracle_metadata_ok = oracle_metadata_ok and (
            item.get("source_sha256") == EXECUTION_SOURCE_HASHES[name]
            and item.get("staging_path") == f"/tmp/{name}"
            and item.get("copy_guards") == expected_guards
            and staged.get("path") == f"/tmp/{name}"
            and staged.get("sha256") == EXECUTION_SOURCE_HASHES[name]
            and staged.get("uid") == 0 and staged.get("gid") == 0
            and staged.get("mode") == "0444" and staged.get("nlink") == 1
            and staged.get("regular") is True and staged.get("not_symlink") is True
            and execution.get("uid") == odoo_uid and execution.get("gid") == odoo_gid
            and execution.get("exit_code") == 0
            and execution.get("timed_out") is False
            and execution.get("process_group_reaped") is True
            and cleanup == {"file_absent": True, "dir_absent": True}
        )
    expected_cleanup_keys = {
        "real_read_stage_absent", "isolation_stage_absent", "odoo_output_absent",
        *(f"oracle_source_absent:{name}" for name in expected_oracle_names),
    }
    require(
        staging.get("all_checks_passed") is True
        and staging.get("release") == RELEASE
        and staging.get("read_plan_sha256") == PLAN_SHA256
        and staging.get("production_promotion_allowed") is False
        and staging.get("upload_root") == {"path": str(UPLOAD_ROOT), "uid": 0, "gid": 0, "mode": "0700", "not_odoo_traversable": True}
        and stage_metadata_ok
        and oracle_metadata_ok
        and staging.get("source_hashes") == EXECUTION_SOURCE_HASHES
        and staging.get("failure") is None
        and isinstance(staging.get("cleanup"), dict)
        and set(staging["cleanup"]) == expected_cleanup_keys
        and all(value is True for value in staging["cleanup"].values())
        and all(by_purpose[purpose].get("source_sha256") == expected for purpose, expected in SOURCE_HASHES.items())
        and all(item.get("cleanup", {}).get("file_absent") is True and item.get("cleanup", {}).get("dir_absent") is True for item in by_purpose.values()),
        "execution staging audit mismatch",
    )
    launcher_isolation = load_json(args.execution_evidence / "launcher-isolation.json")
    require(
        launcher_isolation.get("all_checks_passed") is True
        and launcher_isolation.get("release") == RELEASE
        and launcher_isolation.get("launcher_sha256") == LAUNCHER_SHA256
        and launcher_isolation.get("production_promotion_allowed") is False,
        "launcher isolation gate did not pass",
    )
    for name in ("real-read", "read-oracles", "launcher-isolation"):
        require((args.execution_evidence / f"{name}.exit").read_text("ascii").strip() == "0", f"{name} execution failed")
        require((args.execution_evidence / f"{name}.stderr").read_bytes() == b"", f"{name} execution stderr is not empty")

    dependency = load_json(args.dependency_inventory)
    require(
        dependency.get("release") == RELEASE
        and dependency.get("scoped_inventory_checks_passed") is True
        and dependency.get("production_dependency_closure_complete") is False
        and dependency.get("external_dependency_bound") is False
        and dependency.get("production_promotion_allowed") is False,
        "dependency inventory mismatch",
    )
    negative = load_json(args.negative_gates)
    negative_cases = negative.get("cases", {})
    expected_negative = {
        "wrong-path": (5, "runtime_release_mismatch"),
        "same-bytes-tmp-copy": (5, "runtime_release_mismatch"),
        "symlink": (6, "odoo_read_failed"),
        "tampered-copy": (6, "odoo_read_failed"),
    }
    negative_cases_ok = isinstance(negative_cases, dict) and set(negative_cases) == set(expected_negative)
    if negative_cases_ok:
        for name, (expected_exit, expected_error) in expected_negative.items():
            case = negative_cases[name]
            checks = case.get("checks", {}) if isinstance(case, dict) else {}
            negative_cases_ok = negative_cases_ok and (
                case.get("expected_exit") == expected_exit
                and case.get("expected_error") == expected_error
                and case.get("all_checks_passed") is True
                and isinstance(checks, dict)
                and set(checks) == {
                    "fresh_token_before", "token_still_unconsumed", "expected_exit",
                    "stdout_empty", "structured_error", "auth_hash_unchanged",
                    "receipt_hash_unchanged", "audit_hash_unchanged", "odoo_pid_unchanged",
                    "odoo_pid_active", "odoo_canary_fixed_inode_unchanged",
                }
                and all(value is True for value in checks.values())
                and case.get("odoo_pid_after") == EXPECTED_PIDS["odoo19.service"]
            )
    require(
        negative.get("release") == RELEASE
        and negative.get("manifest_sha256") == MANIFEST_SHA256
        and negative.get("canonical_package_sha256") == PACKAGE_SHA256
        and negative.get("canonical_package_unchanged") is True
        and negative.get("all_checks_passed") is True
        and negative.get("temporary_artifacts_removed") is True
        and negative.get("production_promotion_allowed") is False
        and negative.get("baseline_state", {}).get("auth", {}).get("table_counts", {}).get("consumed_auth_tokens") == 4
        and negative.get("baseline_state", {}).get("receipt", {}).get("table_counts", {}).get("consumed_receipts") == 4
        and negative.get("baseline_state", {}).get("audit", {}).get("row_count") == 4
        and negative.get("baseline_state", {}).get("audit", {}).get("head") == audit_head
        and negative_cases_ok
        and negative.get("fixture_checks") == {
            "wrong_path_is_same_bytes": True,
            "tmp_copy_is_same_bytes": True,
            "symlink_fixture_is_link": True,
            "tampered_fixture_differs": True,
        }
        and negative.get("odoo_pid_before") == EXPECTED_PIDS["odoo19.service"]
        and negative.get("odoo_canary_reached") is False
        and negative.get("secret_material_emitted") is False,
        "canonical-package negative gates mismatch",
    )

    build = load_json(UPLOAD_ROOT / "dev8-build-identity.json")
    require(
        build.get("release") == RELEASE and build.get("version") == VERSION
        and build.get("commit") == COMMIT and build.get("git_tree") == TREE
        and build.get("package_size") == PACKAGE_SIZE and build.get("package_sha256") == PACKAGE_SHA256
        and build.get("manifest_sha256") == MANIFEST_SHA256 and build.get("registry_digest") == REGISTRY_DIGEST
        and build.get("archive_members") == 64 and build.get("manifest_files") == 63
        and build.get("archive_links") == 0 and build.get("production_promotion_allowed") is False,
        "build identity mismatch",
    )
    ci = load_json(UPLOAD_ROOT / "dev8-github-ci.json")
    require(
        ci == EXPECTED_CI,
        "GitHub CI evidence mismatch",
    )
    for name in ("install", "runtime-setup", "server-gate"):
        require((args.deployment_evidence / f"{name}.exit").read_text("ascii").strip() == "0", f"{name} exit evidence is not zero")
        require((args.deployment_evidence / f"{name}.stderr").read_bytes() == b"", f"{name} stderr evidence is not empty")
    install = (args.deployment_evidence / "install.stdout").read_text("utf-8")
    runtime = (args.deployment_evidence / "runtime-setup.stdout").read_text("utf-8")
    server = (args.deployment_evidence / "server-gate.stdout").read_text("utf-8")
    require(
        f"installed_release={RELEASE}" in install and f"package_sha256={PACKAGE_SHA256}" in install
        and f"manifest_sha256={MANIFEST_SHA256}" in install and f"registry_digest={REGISTRY_DIGEST}" in install,
        "install stdout identity mismatch",
    )
    require(f"dev8_runtime_setup=passed" in runtime and f"release={RELEASE}" in runtime, "runtime setup stdout identity mismatch")
    require(
        "dev8_server_gate=passed" in server
        and "dev8_isolation_pre=passed" in server and "dev8_isolation_post=passed" in server
        and f"release={RELEASE}" in server and f"package_sha256={PACKAGE_SHA256}" in server
        and f"manifest_sha256={MANIFEST_SHA256}" in server and f"registry_digest={REGISTRY_DIGEST}" in server
        and "mutable_candidate_test_fixture_used=false" in server
        and "server_unit_test_source=github-ci-run-29319326192" in server
        and "production_critical_metadata_safe=false" in server,
        "server gate stdout identity or trust-source mismatch",
    )
    return (
        persistence,
        {"build": build, "ci": ci, "dependency": dependency, "negative": negative, "staging": staging, "launcher_isolation": launcher_isolation},
        {"install": install_journal_payload, "runtime": runtime_journal_payload},
    )


def assert_parent(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o755)
    value = path_info(path)
    require(value["directory"] and not value["symlink"] and value["uid"] == 0 and value["gid"] == 0 and not (int(str(value["mode"]), 8) & 0o022), f"unsafe evidence parent: {path}")


def validate_existing_target(anchor_path: Path) -> dict[str, object]:
    require(TARGET.is_dir() and not TARGET.is_symlink() and not os.path.lexists(STAGING), "partial target layout is unsafe")
    target_info = path_info(TARGET)
    require(target_info["uid"] == 0 and target_info["gid"] == 0 and target_info["mode"] == "0500", "partial target root metadata mismatch")
    anchor_info = path_info(anchor_path)
    require(
        anchor_info["regular"] is True and anchor_info["symlink"] is False
        and anchor_info["uid"] == 0 and anchor_info["gid"] == 0
        and anchor_info["mode"] == "0400" and anchor_info["nlink"] in {1, 2},
        "partial-freeze anchor metadata mismatch",
    )
    anchor_payload = secure_bytes(anchor_path, allowed_nlinks={1, 2})
    anchor = json.loads(anchor_payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(anchor, dict), "partial-freeze anchor is not an object")
    checksums = TARGET / "EVIDENCE-SHA256SUMS"
    metadata = TARGET / "EVIDENCE-METADATA.json"
    checksum_payload = secure_bytes(checksums)
    require(checksum_payload.endswith(b"\n"), "partial target checksum manifest must end with a newline")
    entries: dict[str, str] = {}
    for line in checksum_payload.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "partial target checksum line is invalid")
        expected, relative = match.groups()
        portable = PurePosixPath(relative)
        require(
            not portable.is_absolute() and portable.parts
            and all(part not in {"", ".", ".."} for part in portable.parts)
            and relative not in entries and relative != "EVIDENCE-SHA256SUMS",
            "partial target checksum path is unsafe",
        )
        entries[relative] = expected
    actual = set()
    for parent, directories, files in os.walk(TARGET, followlinks=False):
        for name in [*directories, *files]:
            path = Path(parent) / name
            relative = path.relative_to(TARGET).as_posix()
            info = path_info(path)
            require(info["uid"] == 0 and info["gid"] == 0 and info["symlink"] is False, "partial target tree metadata mismatch")
            if info["directory"]:
                require(info["mode"] == "0500", "partial target directory mode mismatch")
            else:
                require(info["regular"] and info["mode"] == "0400" and info["nlink"] == 1, "partial target file mode mismatch")
                actual.add(relative)
    require(actual == EXPECTED_EVIDENCE_FILES, "partial target file set is not exact")
    require(set(entries) == EXPECTED_EVIDENCE_FILES - {"EVIDENCE-SHA256SUMS"}, "partial target checksum entry set is not exact")
    require(
        all(
            hashlib.sha256(secure_bytes(TARGET / Path(*PurePosixPath(relative).parts))).hexdigest() == expected
            for relative, expected in entries.items()
        ),
        "partial target checksum mismatch",
    )
    metadata_payload = secure_bytes(metadata)
    metadata_document = json.loads(metadata_payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(
        isinstance(metadata_document, dict)
        and metadata_document.get("release") == RELEASE
        and metadata_document.get("commit") == COMMIT
        and metadata_document.get("git_tree") == TREE
        and metadata_document.get("evidence_file_count") == len(EXPECTED_EVIDENCE_FILES)
        and metadata_document.get("secret_material_included") is False
        and metadata_document.get("production_promotion_allowed") is False,
        "partial target evidence metadata mismatch",
    )
    secret_scan_payload = secure_bytes(TARGET / "security/secret-scan.json")
    secret_scan = json.loads(secret_scan_payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(
        secret_scan == {
            "schema_version": 1,
            "release": RELEASE,
            "scanned_file_count_before_report": len(EXPECTED_EVIDENCE_FILES) - 3,
            "secret_forms_scanned": SECRET_SCAN_FORMS,
            "auth_secret_absent": True,
            "receipt_secret_absent": True,
            "secret_material_included": False,
            "production_promotion_allowed": False,
        },
        "partial target secret scan report mismatch",
    )
    runtime_document = load_json(RUNTIME)
    auth_secret = secure_bytes(Path(str(runtime_document["auth_secret_path"])))
    receipt_secret = secure_bytes(Path(str(runtime_document["receipt_secret_path"])))
    needles = secret_needles(auth_secret, receipt_secret)
    require(needles, "partial target secret scan forms are empty")
    for relative in sorted(actual):
        payload = secure_bytes(TARGET / Path(*PurePosixPath(relative).parts))
        require(all(needle not in payload for needle in needles), f"secret material found during recovery: {relative}")
    require(all(needle not in anchor_payload for needle in needles), "secret material found in recovery anchor")
    anchor_keys = {
        "schema_version", "release", "commit", "git_tree", "evidence_path",
        "package_sha256", "release_manifest_sha256", "registry_digest",
        "runtime_config_sha256", "read_plan_sha256", "audit_head",
        "evidence_checksum_manifest_sha256", "evidence_metadata_sha256",
        "evidence_checksum_entries", "evidence_file_count", "production_promotion_allowed",
    }
    require(
        set(anchor) == anchor_keys
        and isinstance(anchor.get("schema_version"), int) and not isinstance(anchor.get("schema_version"), bool)
        and anchor.get("schema_version") == 1
        and anchor.get("release") == RELEASE and anchor.get("evidence_path") == str(TARGET)
        and anchor.get("commit") == COMMIT and anchor.get("git_tree") == TREE
        and anchor.get("package_sha256") == PACKAGE_SHA256
        and anchor.get("release_manifest_sha256") == MANIFEST_SHA256
        and anchor.get("registry_digest") == REGISTRY_DIGEST
        and anchor.get("runtime_config_sha256") == RUNTIME_SHA256
        and anchor.get("read_plan_sha256") == PLAN_SHA256
        and isinstance(anchor.get("audit_head"), str) and HEX64.fullmatch(str(anchor["audit_head"])) is not None
        and anchor.get("evidence_checksum_manifest_sha256") == hashlib.sha256(checksum_payload).hexdigest()
        and anchor.get("evidence_metadata_sha256") == hashlib.sha256(metadata_payload).hexdigest()
        and anchor.get("evidence_checksum_entries") == len(EXPECTED_EVIDENCE_FILES) - 1
        and anchor.get("evidence_file_count") == len(EXPECTED_EVIDENCE_FILES)
        and anchor.get("production_promotion_allowed") is False,
        "partial-freeze anchor recovery validation failed",
    )
    return anchor


def recover_anchor() -> bool:
    if not TARGET.is_dir() or os.path.lexists(STAGING):
        return False
    final_exists = EVIDENCE_ANCHOR.is_file() and not EVIDENCE_ANCHOR.is_symlink()
    staging_exists = ANCHOR_STAGING.is_file() and not ANCHOR_STAGING.is_symlink()
    if not final_exists and not staging_exists:
        return False
    source = EVIDENCE_ANCHOR if final_exists else ANCHOR_STAGING
    validate_existing_target(source)
    if final_exists and staging_exists:
        final_meta = EVIDENCE_ANCHOR.lstat()
        staging_meta = ANCHOR_STAGING.lstat()
        require((final_meta.st_dev, final_meta.st_ino) == (staging_meta.st_dev, staging_meta.st_ino), "anchor recovery paths are not the same inode")
        os.unlink(ANCHOR_STAGING)
    elif staging_exists:
        os.chmod(ANCHOR_STAGING, 0o400)
        os.link(ANCHOR_STAGING, EVIDENCE_ANCHOR, follow_symlinks=False)
        os.unlink(ANCHOR_STAGING)
    anchor_meta = EVIDENCE_ANCHOR.lstat()
    require(anchor_meta.st_uid == 0 and anchor_meta.st_gid == 0 and stat.S_IMODE(anchor_meta.st_mode) == 0o400 and anchor_meta.st_nlink == 1, "recovered anchor metadata mismatch")
    fsync_directory(EVIDENCE_PARENT)
    fsync_directory(ANCHOR_PARENT)
    print(json.dumps({"release": RELEASE, "recovered_or_verified_anchor": True, "production_promotion_allowed": False}, sort_keys=True))
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--read-evidence", type=Path, required=True)
    parser.add_argument("--state-evidence", type=Path, required=True)
    parser.add_argument("--execution-evidence", type=Path, required=True)
    parser.add_argument("--deployment-evidence", type=Path, required=True)
    parser.add_argument("--dependency-inventory", type=Path, required=True)
    parser.add_argument("--negative-gates", type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "evidence freeze must run as root")
    assert_parent(EVIDENCE_PARENT)
    assert_parent(ANCHOR_PARENT)
    pipeline_lock_fd = acquire_pipeline_lock()
    try:
        if recover_anchor():
            fcntl.flock(pipeline_lock_fd, fcntl.LOCK_UN)
            os.close(pipeline_lock_fd)
            return
    except Exception:
        os.close(pipeline_lock_fd)
        raise
    for path in (TARGET, STAGING, EVIDENCE_ANCHOR, ANCHOR_STAGING):
        require(not os.path.lexists(path), f"refusing to overwrite evidence path: {path}")
    require(UPLOAD_ROOT == Path("/root/odoo-accounting-cli-v3-dev8-upload"), "upload root binding changed")
    upload_info = path_info(UPLOAD_ROOT)
    require(upload_info["directory"] and upload_info["uid"] == 0 and upload_info["gid"] == 0 and upload_info["mode"] == "0700", "upload root metadata mismatch")
    upload_payloads: dict[str, bytes] = {}
    for name in (TOOLCHAIN_MANIFEST_NAME, SERVER_BASELINE_NAME):
        source = UPLOAD_ROOT / name
        source_info = path_info(source)
        require(
            source_info["uid"] == 0 and source_info["gid"] == 0
            and source_info["regular"] is True and source_info["symlink"] is False
            and source_info["nlink"] == 1 and not (int(str(source_info["mode"]), 8) & 0o022),
            f"deployment control source metadata is unsafe: {name}",
        )
        upload_payloads[name] = secure_bytes(source)
    toolchain_manifest = load_json_bytes(upload_payloads[TOOLCHAIN_MANIFEST_NAME], "toolchain manifest")
    manifest_entries = validate_toolchain_manifest(toolchain_manifest)
    baseline_expected = manifest_entries[SERVER_BASELINE_NAME]
    require(
        hashlib.sha256(upload_payloads[SERVER_BASELINE_NAME]).hexdigest() == baseline_expected["sha256"]
        and len(upload_payloads[SERVER_BASELINE_NAME]) == baseline_expected["size"],
        "server baseline differs from version-controlled manifest",
    )
    server_baseline = validate_server_baseline(
        load_json_bytes(upload_payloads[SERVER_BASELINE_NAME], "server baseline")
    )
    persistence, reports, journal_payloads = validate_inputs(args)
    isolation = live_isolation(server_baseline)
    STAGING.mkdir(mode=0o700)
    published = False
    try:
        core = {
            PACKAGE: "release/release-package.tar.gz",
            RELEASE_ROOT / "RELEASE-MANIFEST.json": "release/RELEASE-MANIFEST.json",
            RELEASE_ROOT / "registry/capabilities.json": "release/capabilities.json",
            RELEASE_ANCHOR: "release/RELEASE-ANCHOR.json",
            RUNTIME: "release/runtime-test-dev8.json",
            UPLOAD_ROOT / "dev8-build-identity.json": "release/build-identity.json",
            UPLOAD_ROOT / "dev8-github-ci.json": "release/github-ci.json",
            args.dependency_inventory: "gates/runtime-dependency-inventory.json",
            args.negative_gates: "gates/canonical-package-negative-gates.json",
        }
        for source, relative in core.items():
            copy_evidence(source, relative)
        write_bytes("transactions/install-completed.json", journal_payloads["install"])
        write_bytes("transactions/runtime-completed.json", journal_payloads["runtime"])
        for name in sorted(READ_FILES):
            copy_evidence(args.read_evidence / name, f"reads/{name}")
        for name in sorted(STATE_FILES):
            copy_evidence(args.state_evidence / name, f"state/{name}")
        for name in sorted(EXECUTION_FILES):
            copy_evidence(args.execution_evidence / name, f"execution/{name}")
        for name in sorted(DEPLOYMENT_FILES):
            copy_evidence(args.deployment_evidence / name, f"deployment/{name}")
        write_json("isolation/pre-freeze.json", isolation)

        copy_evidence(UPLOAD_ROOT / TOOLCHAIN_MANIFEST_NAME, f"tools/{TOOLCHAIN_MANIFEST_NAME}")
        frozen_manifest_payload = secure_bytes(STAGING / "tools" / TOOLCHAIN_MANIFEST_NAME)
        require(frozen_manifest_payload == upload_payloads[TOOLCHAIN_MANIFEST_NAME], "toolchain manifest changed before freeze")
        copy_evidence(UPLOAD_ROOT / SERVER_BASELINE_NAME, f"tools/{SERVER_BASELINE_NAME}")
        frozen_baseline_payload = secure_bytes(STAGING / "tools" / SERVER_BASELINE_NAME)
        require(frozen_baseline_payload == upload_payloads[SERVER_BASELINE_NAME], "server baseline changed before freeze")

        tool_entries = []
        for name in TOOL_FILES:
            source = UPLOAD_ROOT / name
            source_info = path_info(source)
            require(
                source_info["uid"] == 0 and source_info["gid"] == 0
                and source_info["regular"] is True and source_info["symlink"] is False
                and source_info["nlink"] == 1 and not (int(str(source_info["mode"]), 8) & 0o022),
                f"tool source metadata is unsafe: {name}",
            )
            copy_evidence(source, f"tools/{name}")
            frozen_tool = STAGING / "tools" / name
            expected_tool = manifest_entries[name]
            require(
                sha256(frozen_tool) == expected_tool["sha256"]
                and frozen_tool.stat().st_size == expected_tool["size"],
                f"tool differs from version-controlled manifest: {name}",
            )
            tool_entries.append(
                {
                    "name": name,
                    "sha256": sha256(frozen_tool),
                    "size": frozen_tool.stat().st_size,
                    "source_uid": 0,
                    "source_gid": 0,
                    "source_mode": source_info["mode"],
                    "source_nlink": 1,
                }
            )
        write_json(
            "tools/TOOL-INVENTORY.json",
            {
                "schema_version": 1,
                "release": RELEASE,
                "toolchain_version": TOOLCHAIN_VERSION,
                "source_directory": "deployment/dev8",
                "toolchain_manifest_sha256": hashlib.sha256(frozen_manifest_payload).hexdigest(),
                "server_baseline_sha256": hashlib.sha256(frozen_baseline_payload).hexdigest(),
                "server_baseline_size": len(frozen_baseline_payload),
                "upload_root": str(UPLOAD_ROOT),
                "tools": tool_entries,
                "tool_count": len(tool_entries),
                "secret_material_included": False,
                "production_promotion_allowed": False,
            },
        )

        runtime_document = load_json(RUNTIME)
        auth_secret = secure_bytes(Path(str(runtime_document["auth_secret_path"])))
        receipt_secret = secure_bytes(Path(str(runtime_document["receipt_secret_path"])))
        require(len(auth_secret) >= 32 and len(receipt_secret) >= 32, "runtime secrets are too short for evidence scanning")
        needles = secret_needles(auth_secret, receipt_secret)
        require(needles, "runtime secret scan forms are empty")
        scanned_files = 0
        for path in sorted(STAGING.rglob("*")):
            info = path_info(path)
            if info["directory"] is True:
                continue
            require(info["regular"] is True and info["symlink"] is False, f"unsafe evidence object during secret scan: {path}")
            payload = secure_bytes(path)
            require(all(needle not in payload for needle in needles), f"secret material found in evidence: {path.relative_to(STAGING)}")
            scanned_files += 1
        write_json(
            "security/secret-scan.json",
            {
                "schema_version": 1,
                "release": RELEASE,
                "scanned_file_count_before_report": scanned_files,
                "secret_forms_scanned": SECRET_SCAN_FORMS,
                "auth_secret_absent": True,
                "receipt_secret_absent": True,
                "secret_material_included": False,
                "production_promotion_allowed": False,
            },
        )

        audit_head = str(persistence["audit_head"])
        file_count_before_metadata = sum(path.is_file() for path in STAGING.rglob("*"))
        metadata = {
            "schema_version": 1,
            "release": RELEASE,
            "version": VERSION,
            "commit": COMMIT,
            "git_tree": TREE,
            "package_sha256": PACKAGE_SHA256,
            "package_size": PACKAGE_SIZE,
            "manifest_sha256": MANIFEST_SHA256,
            "registry_digest": REGISTRY_DIGEST,
            "runtime_config_sha256": RUNTIME_SHA256,
            "read_plan_sha256": PLAN_SHA256,
            "database_uuid": DATABASE_UUID,
            "audit_head": audit_head,
            "auth_tokens": 4,
            "consumed_receipts": 4,
            "receipt_audit_events": 4,
            "verified_capabilities": [
                "acct.ap.open_items.v1", "acct.ar.open_items.v1",
                "acct.gl.trial_balance.v1", "acct.registry.list.v1",
            ],
            "registered_capabilities": 22,
            "staged_capabilities": 4,
            "enabled_capabilities": 0,
            "frozen_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "evidence_scope": "dev8 canonical launcher, four staged real reads, three financial SQL oracles, persistence, security, and isolation",
            "evidence_visibility": "root-only directories 0500 and files 0400",
            "evidence_file_count": file_count_before_metadata + 2,
            "goal_complete": False,
            "secret_material_included": False,
            "production_writes_authorized": False,
            "odoo_accounting_write_performed": False,
            "pi_route_changed": False,
            "v2_changed": False,
            "production_dependency_closure_complete": False,
            "production_promotion_allowed": False,
            "promotion_blockers": [
                *reports["dependency"].get("promotion_blockers", []),
                *isolation["promotion_blockers"],
            ],
        }
        write_json("EVIDENCE-METADATA.json", metadata)
        checksum_lines = []
        for path in sorted((item for item in STAGING.rglob("*") if item.is_file()), key=lambda item: item.relative_to(STAGING).as_posix()):
            relative = path.relative_to(STAGING).as_posix()
            checksum_lines.append(f"{sha256(path)}  {relative}\n")
        checksum_path = STAGING / "EVIDENCE-SHA256SUMS"
        descriptor = os.open(checksum_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            write_all(descriptor, "".join(checksum_lines).encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        require(sum(path.is_file() for path in STAGING.rglob("*")) == metadata["evidence_file_count"], "evidence file count mismatch")

        for path in sorted(STAGING.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o500 if path.is_dir() else 0o400, follow_symlinks=False)
        os.chown(STAGING, 0, 0)
        os.chmod(STAGING, 0o500)
        for directory in sorted((path for path in STAGING.rglob("*") if path.is_dir()), key=lambda item: len(item.parts), reverse=True):
            fsync_directory(directory)
        fsync_directory(STAGING)
        anchor = {
            "schema_version": 1,
            "release": RELEASE,
            "commit": COMMIT,
            "git_tree": TREE,
            "evidence_path": str(TARGET),
            "package_sha256": PACKAGE_SHA256,
            "release_manifest_sha256": MANIFEST_SHA256,
            "registry_digest": REGISTRY_DIGEST,
            "runtime_config_sha256": RUNTIME_SHA256,
            "read_plan_sha256": PLAN_SHA256,
            "audit_head": audit_head,
            "evidence_checksum_manifest_sha256": sha256(checksum_path),
            "evidence_metadata_sha256": sha256(STAGING / "EVIDENCE-METADATA.json"),
            "evidence_checksum_entries": len(checksum_lines),
            "evidence_file_count": metadata["evidence_file_count"],
            "production_promotion_allowed": False,
        }
        anchor_descriptor = os.open(ANCHOR_STAGING, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            payload = json.dumps(anchor, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
            write_all(anchor_descriptor, payload)
            os.fsync(anchor_descriptor)
        finally:
            os.close(anchor_descriptor)
        os.chown(ANCHOR_STAGING, 0, 0)
        os.chmod(ANCHOR_STAGING, 0o400)
        os.replace(STAGING, TARGET)
        published = True
        fsync_directory(EVIDENCE_PARENT)
        os.link(ANCHOR_STAGING, EVIDENCE_ANCHOR, follow_symlinks=False)
        os.unlink(ANCHOR_STAGING)
        fsync_directory(ANCHOR_PARENT)
        print(json.dumps({**anchor, "all_checks_passed": True}, sort_keys=True))
        fcntl.flock(pipeline_lock_fd, fcntl.LOCK_UN)
        os.close(pipeline_lock_fd)
    except Exception:
        if not published:
            if STAGING.is_dir() and not STAGING.is_symlink():
                os.chmod(STAGING, 0o700)
                for path in STAGING.rglob("*"):
                    if path.is_dir():
                        os.chmod(path, 0o700)
                shutil.rmtree(STAGING)
            if ANCHOR_STAGING.is_file() and not ANCHOR_STAGING.is_symlink():
                os.unlink(ANCHOR_STAGING)
        raise


if __name__ == "__main__":
    main()

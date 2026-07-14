#!/usr/bin/python3 -I
"""Independently verify the frozen dev8 evidence, anchor, and live isolation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import fcntl
import grp
import io
import json
import os
import pwd
import re
import sqlite3
import stat
import subprocess
import tarfile
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath


RELEASE = "0.1.0.dev8-bd21ca07c168"
VERSION = "0.1.0.dev8"
TOOLCHAIN_VERSION = "0.1.0.dev8-toolchain.1"
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
ROOT = Path("/var/lib/odoo-accounting-cli-v3/evidence") / RELEASE
ANCHOR = Path("/var/lib/odoo-accounting-cli-v3/evidence-anchors") / f"{RELEASE}.json"
CHECKSUMS = ROOT / "EVIDENCE-SHA256SUMS"
METADATA = ROOT / "EVIDENCE-METADATA.json"
LIVE_RELEASE = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE
LIVE_PACKAGE = Path("/opt/odoo-accounting-cli-v3/packages") / f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
LIVE_ANCHOR = Path("/opt/odoo-accounting-cli-v3/trusted-artifacts") / f"{RELEASE}.json"
LIVE_RUNTIME = Path("/etc/odoo-accounting-cli-v3/runtime-test-dev8.json")
PIPELINE_LOCK = Path("/opt/odoo-accounting-cli-v3/.dev8-pipeline.lock")
INSTALL_JOURNAL = Path("/opt/odoo-accounting-cli-v3/.dev8-install-transaction.json")
RUNTIME_JOURNAL = Path("/etc/odoo-accounting-cli-v3/.dev8-runtime-transaction.json")
SERVER_BASELINE_NAME = "SERVER-BASELINE.json"
CASES = (
    ("registry-list", "acct.registry.list.v1"),
    ("trial-balance", "acct.gl.trial_balance.v1"),
    ("ar-open-items", "acct.ar.open_items.v1"),
    ("ap-open-items", "acct.ap.open_items.v1"),
)
READ_FILES = {
    "read-plan.input.json", "identity.json", "summary.json", "read-oracles.audit.json",
    *(f"{name}.{suffix}" for name, _ in CASES for suffix in (
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
TOOL_FILES = (
    "dev8-install.sh", "dev8-runtime-setup.sh", "dev8-server-gate.sh",
    "dev8-stage-execution-tools.py", "dev8-run-real-reads.sh", "dev8-sign-read.py",
    "dev8-launcher-isolation-gate.py", "dev8-run-read-oracles.sh",
    "dev6-trial-balance-sql-oracle.py", "dev6-ar-sql-oracle.py", "dev7-ap-sql-oracle.py",
    "dev8-persistence-audit.py", "dev8-runtime-dependency-inventory.py",
    "dev8-canonical-package-negative-gates.py", "dev8-freeze-evidence.py",
    "dev8-verify-frozen-evidence.py",
)
TOOLCHAIN_MANIFEST_NAME = "TOOLCHAIN-MANIFEST.json"
MANIFEST_FILES = (*TOOL_FILES, SERVER_BASELINE_NAME)
DEPLOYMENT_FILES = {
    *(f"{name}.{suffix}" for name in ("install", "runtime-setup", "server-gate") for suffix in ("stdout", "stderr", "exit")),
}
EXPECTED_FILES = {
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
GENESIS_HASH = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
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
EXPECTED_RUNTIME = {
    "auth_key_id": "test-auth-2026-07-dev8",
    "auth_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/dev8-auth.hmac",
    "auth_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/0.1.0.dev8-bd21ca07c168/auth.sqlite3",
    "canonical_package_path": "/opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz",
    "canonical_package_sha256": PACKAGE_SHA256,
    "capability_channel": "staged",
    "database_name": "odoo_test",
    "database_uuid": DATABASE_UUID,
    "environment": "test",
    "instance_id": "odoo19@43.165.173.80",
    "odoo_bin": "/opt/odoo/odoo19/odoo-server/odoo-bin",
    "odoo_bin_sha256": "e0fb7977c59f73e652805d169bcd1bffe41df7bbf0c39ce47e8ad32126529003",
    "odoo_config": "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf",
    "odoo_config_sha256": "98a90d839e3ad16c32335057b27e33bc689cbccbb367350e31fbf41778ed70c3",
    "odoo_python": "/opt/odoo/odoo19/odoo19-venv/bin/python",
    "odoo_python_sha256": "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
    "receipt_key_id": "test-receipt-2026-07-dev8",
    "receipt_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/dev8-receipt.hmac",
    "receipt_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/0.1.0.dev8-bd21ca07c168/receipt.sqlite3",
    "release_root": str(LIVE_RELEASE),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


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


def exact_integer_fields(value: object, fields: tuple[str, ...]) -> bool:
    return isinstance(value, dict) and all(
        isinstance(value.get(field), int) and not isinstance(value.get(field), bool)
        for field in fields
    )


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
        "verifier pipeline lock metadata is invalid",
    )
    descriptor = os.open(
        PIPELINE_LOCK,
        os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "verifier pipeline lock changed while opening")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = os.fstat(descriptor)
        after = PIPELINE_LOCK.lstat()
        require(
            (before.st_dev, before.st_ino) == (locked.st_dev, locked.st_ino) == (after.st_dev, after.st_ino)
            and stat.S_ISREG(after.st_mode) and not PIPELINE_LOCK.is_symlink()
            and after.st_uid == 0 and after.st_gid == 0
            and stat.S_IMODE(after.st_mode) == 0o600 and after.st_nlink == 1,
            "verifier pipeline lock changed while acquiring",
        )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        require(key not in value, f"duplicate JSON field: {key}")
        value[key] = item
    return value


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(value, dict), f"expected JSON object: {path}")
    return value


def load_json_bytes(payload: bytes, label: str) -> dict[str, object]:
    value = json.loads(payload.decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(value, dict), f"expected JSON object: {label}")
    return value


def strict_read(
    path: Path,
    *,
    mode: int,
    uid: int = 0,
    gid: int = 0,
    expected_sha256: str | None = None,
    max_bytes: int | None = None,
) -> bytes:
    before = path.lstat()
    require(
        stat.S_ISREG(before.st_mode) and not path.is_symlink()
        and before.st_uid == uid and before.st_gid == gid
        and stat.S_IMODE(before.st_mode) == mode and before.st_nlink == 1,
        f"strict evidence file metadata mismatch: {path}",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), f"evidence path changed while opening: {path}")
        chunks = []
        digest_value = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            require(max_bytes is None or total <= max_bytes, f"evidence file is too large: {path}")
            chunks.append(chunk)
            digest_value.update(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    identity = (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
        before.st_ctime_ns, before.st_uid, before.st_gid, before.st_mode, before.st_nlink,
    )
    require(
        identity
        == (
            opened_after.st_dev, opened_after.st_ino, opened_after.st_size,
            opened_after.st_mtime_ns, opened_after.st_ctime_ns, opened_after.st_uid,
            opened_after.st_gid, opened_after.st_mode, opened_after.st_nlink,
        )
        == (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns, after.st_uid, after.st_gid, after.st_mode, after.st_nlink,
        ),
        f"evidence file changed while reading: {path}",
    )
    if expected_sha256 is not None:
        require(digest_value.hexdigest() == expected_sha256, f"evidence checksum mismatch: {path}")
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


def parse_checksums(payload: bytes) -> dict[str, str]:
    require(payload.endswith(b"\n"), "evidence checksum manifest must end with a newline")
    result: dict[str, str] = {}
    for line in payload.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "invalid evidence checksum line")
        expected, relative = match.groups()
        portable = PurePosixPath(relative)
        require(
            not portable.is_absolute() and portable.parts
            and all(part not in {"", ".", ".."} for part in portable.parts)
            and relative not in result and relative != "EVIDENCE-SHA256SUMS",
            "unsafe or duplicate checksum path",
        )
        result[relative] = expected
    return result


def parse_time(value: object) -> datetime:
    require(isinstance(value, str), "timestamp is not text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("timestamp is invalid") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, "timestamp is naive")
    return parsed.astimezone(timezone.utc)


def inspect_tree() -> tuple[set[str], list[str]]:
    actual = set()
    unsafe = []
    root_meta = ROOT.lstat()
    if not (
        stat.S_ISDIR(root_meta.st_mode) and not ROOT.is_symlink()
        and root_meta.st_uid == 0 and root_meta.st_gid == 0
        and stat.S_IMODE(root_meta.st_mode) == 0o500
    ):
        unsafe.append(".")
    for parent, directories, files in os.walk(ROOT, followlinks=False):
        for name in [*directories, *files]:
            path = Path(parent) / name
            relative = path.relative_to(ROOT).as_posix()
            value = path.lstat()
            if stat.S_ISLNK(value.st_mode):
                unsafe.append(f"symlink:{relative}")
            elif stat.S_ISDIR(value.st_mode):
                if stat.S_IMODE(value.st_mode) != 0o500:
                    unsafe.append(f"mode:{relative}")
            elif stat.S_ISREG(value.st_mode):
                actual.add(relative)
                if stat.S_IMODE(value.st_mode) != 0o400 or value.st_nlink != 1:
                    unsafe.append(f"mode-or-link:{relative}")
            else:
                unsafe.append(f"type:{relative}")
            if value.st_uid != 0 or value.st_gid != 0:
                unsafe.append(f"owner:{relative}")
    return actual, unsafe


def verify_package(payload: bytes) -> dict[str, object]:
    require(len(payload) == PACKAGE_SIZE and hashlib.sha256(payload).hexdigest() == PACKAGE_SHA256, "frozen package identity mismatch")
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        members = archive.getmembers()
        by_name = {}
        for member in members:
            portable = PurePosixPath(member.name)
            require(
                not portable.is_absolute() and portable.parts
                and all(part not in {"", ".", ".."} for part in portable.parts)
                and member.name not in by_name and member.isreg(),
                "unsafe canonical package member",
            )
            by_name[member.name] = member
        require(len(members) == 64 and "RELEASE-MANIFEST.json" in by_name, "canonical package member set mismatch")
        stream = archive.extractfile(by_name["RELEASE-MANIFEST.json"])
        require(stream is not None, "package manifest is unreadable")
        manifest_bytes = stream.read()
        manifest = json.loads(manifest_bytes)
        entries = manifest.get("files")
        require(isinstance(entries, list) and len(entries) == 63, "package manifest file count mismatch")
        expected_names = set()
        for item in entries:
            require(isinstance(item, dict) and set(item) == {"path", "sha256", "size"}, "invalid package manifest entry")
            name = item["path"]
            require(isinstance(name, str) and name in by_name and name not in expected_names, "package manifest member mismatch")
            expected_names.add(name)
            member_stream = archive.extractfile(by_name[name])
            require(member_stream is not None, "package member is unreadable")
            payload = member_stream.read()
            require(len(payload) == item["size"] and hashlib.sha256(payload).hexdigest() == item["sha256"], f"package member digest mismatch: {name}")
        require(set(by_name) == expected_names | {"RELEASE-MANIFEST.json"}, "package has unmanifested members")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    canonical_manifest = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    require(
        manifest.get("version") == VERSION and manifest.get("commit") == COMMIT
        and manifest.get("manifest_sha256") == canonical_manifest == MANIFEST_SHA256,
        "package manifest identity mismatch",
    )
    return {"member_count": len(members), "manifest_file_count": len(entries), "manifest": manifest, "manifest_bytes": manifest_bytes}


def inspect_db(payload: bytes) -> tuple[dict[str, object], list[dict[str, object]]]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.deserialize(payload)
        connection.execute("PRAGMA query_only = ON")
        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("approval_records", "audit_events", "consumed_auth_tokens", "consumed_receipts", "idempotency_keys", "operations")
        }
        events = [dict(row) for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence")]
        report = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "quick_check": [row[0] for row in connection.execute("PRAGMA quick_check")],
            "foreign_key_violations": len(list(connection.execute("PRAGMA foreign_key_check"))),
            "counts": counts,
        }
        return report, events
    finally:
        connection.close()


def verify_chain(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    previous = GENESIS_HASH
    result = []
    for expected_sequence, row in enumerate(rows, start=1):
        payload = json.loads(str(row["payload_json"]))
        require(isinstance(payload, dict) and canonical(payload).decode("utf-8") == row["payload_json"], "audit payload is not canonical")
        expected = digest({
            "event_id": row["event_id"], "event_type": row["event_type"],
            "occurred_at": row["occurred_at"], "operation_id": row["operation_id"],
            "payload_json": row["payload_json"], "previous_hash": row["previous_hash"],
            "sequence": row["sequence"],
        })
        require(row["sequence"] == expected_sequence and row["previous_hash"] == previous and row["event_hash"] == expected, "audit chain mismatch")
        previous = str(row["event_hash"])
        item = {key: value for key, value in row.items() if key != "payload_json"}
        item["payload"] = payload
        result.append(item)
    return result


def run_checked(*arguments: str) -> str:
    completed = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8", check=False, timeout=30)
    require(completed.returncode == 0, f"live isolation command failed: {arguments!r}: {completed.stderr.strip()}")
    return completed.stdout


def live_object_identity(path: Path, kind: str, uid: int, gid: int, mode: int) -> dict[str, object]:
    before = path.lstat()
    require(
        not path.is_symlink() and path.resolve(strict=True) == path
        and before.st_uid == uid and before.st_gid == gid
        and stat.S_IMODE(before.st_mode) == mode
        and ((kind == "file" and stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
             or (kind == "directory" and stat.S_ISDIR(before.st_mode))),
        f"live pipeline object metadata mismatch: {path}",
    )
    result: dict[str, object] = {
        "dev": before.st_dev, "ino": before.st_ino, "kind": kind,
        "uid": uid, "gid": gid, "mode": mode,
    }
    if kind == "file":
        payload = strict_read(path, mode=mode, uid=uid, gid=gid)
        after = path.lstat()
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), f"live pipeline object changed: {path}")
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


def live_parent_identity(
    path: Path,
    owners: set[tuple[int, int]],
    modes: set[int] | None,
) -> dict[str, object]:
    value = path.lstat()
    mode = stat.S_IMODE(value.st_mode)
    require(
        path.resolve(strict=True) == path and not path.is_symlink()
        and stat.S_ISDIR(value.st_mode)
        and (value.st_uid, value.st_gid) in owners
        and not (mode & 0o022) and (modes is None or mode in modes),
        f"live pipeline parent metadata mismatch: {path}",
    )
    return {
        "dev": value.st_dev, "ino": value.st_ino, "kind": "directory",
        "uid": value.st_uid, "gid": value.st_gid, "mode": mode,
    }


def validate_completed_journals(
    install: dict[str, object],
    runtime: dict[str, object],
    odoo_uid: int,
    odoo_gid: int,
    *,
    compare_live: bool,
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
    for kind, document_value in (("install", install), ("runtime", runtime)):
        parents = document_value.get("parents")
        specifications = parent_specs[kind]
        require(isinstance(parents, dict) and set(parents) == set(specifications), f"{kind} journal parent set mismatch")
        for label, (path, owners, modes) in specifications.items():
            record = parents[label]
            require(isinstance(record, dict) and set(record) == {"path", "identity"} and record["path"] == str(path), f"{kind} journal parent record mismatch: {label}")
            identity = record["identity"]
            require(
                isinstance(identity, dict) and set(identity) == {"dev", "ino", "kind", "uid", "gid", "mode"}
                and all(
                    isinstance(identity[field], int) and not isinstance(identity[field], bool)
                    for field in ("dev", "ino", "uid", "gid", "mode")
                )
                and int(identity["dev"]) >= 0 and int(identity["ino"]) >= 0
                and identity["kind"] == "directory"
                and (int(identity["uid"]), int(identity["gid"])) in owners
                and not (int(identity["mode"]) & 0o022)
                and (modes is None or int(identity["mode"]) in modes),
                f"{kind} journal parent identity mismatch: {label}",
            )
            if compare_live:
                require(identity == live_parent_identity(path, owners, modes), f"live {kind} journal parent identity mismatch: {label}")

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
    for kind, document_value, plans in (("install", install, install_plans), ("runtime", runtime, runtime_plans)):
        objects = document_value.get("objects")
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
            if compare_live:
                if planned["unique"] is True:
                    require(not os.path.lexists(path), f"completed {kind} journal retains staging: {label}")
                else:
                    observed = live_object_identity(
                        path, str(planned["kind"]), int(planned["uid"]),
                        int(planned["gid"]), int(planned["modes"][0]),
                    )
                    require(recorded == observed, f"live {kind} journal final identity mismatch: {label}")
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
        "install_objects": install["objects"],
        "runtime_objects": runtime["objects"],
        "install_final_identities": final_identities["install"],
        "runtime_final_identities": final_identities["runtime"],
    }


def verify_live_isolation(server_baseline: dict[str, object]) -> dict[str, object]:
    checks: dict[str, bool] = {}
    services: dict[str, object] = {}
    for expected_service in server_baseline["services"]:
        unit = str(expected_service["unit"])
        expected_pid = int(expected_service["main_pid"])
        output = run_checked("/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--property=SubState", "--property=MainPID")
        properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        pid = int(properties.get("MainPID", "0") or "0")
        process = Path(f"/proc/{pid}")
        cmdline = (process / "cmdline").read_bytes().replace(b"\0", b" ") if process.is_dir() else b""
        cmdline_sha256 = hashlib.sha256(cmdline).hexdigest()
        checks[f"service:{unit}"] = (
            properties.get("ActiveState") == "active"
            and properties.get("SubState") == "running"
            and pid == expected_pid and process.is_dir()
            and cmdline_sha256 == expected_service["cmdline_sha256"]
            and b"odoo-accounting-cli-v3" not in cmdline
        )
        services[unit] = {
            "pid": pid, "expected_pid": expected_pid,
            "cmdline_sha256": cmdline_sha256,
            "expected_cmdline_sha256": expected_service["cmdline_sha256"],
            "references_v3": b"odoo-accounting-cli-v3" in cmdline,
        }
    critical_reports = []
    for index, entry in enumerate(server_baseline["critical_files"]):
        payload = baselined_file_bytes(entry)
        checks[f"v2:{index}"] = hashlib.sha256(payload).hexdigest() == entry["sha256"]
        critical_reports.append(
            {
                "path": entry["path"],
                "sha256": hashlib.sha256(payload).hexdigest(),
                "metadata_matches": True,
                "group_or_world_writable": bool(int(str(entry["mode"]), 8) & 0o022),
            }
        )
    checks["current_absent"] = not os.path.lexists("/opt/odoo-accounting-cli-v3/current")
    checks["v3_units_absent"] = not run_checked("/usr/bin/systemctl", "list-unit-files", "--no-legend", "odoo-accounting-cli-v3*").strip() and not run_checked("/usr/bin/systemctl", "list-units", "--all", "--no-legend", "odoo-accounting-cli-v3*").strip()
    database_uuid = run_checked(
        "/usr/bin/sudo", "-n", "-u", "postgres", "/usr/bin/env", "-i",
        "HOME=/var/lib/postgresql", "LANG=C.UTF-8", "PATH=/usr/bin:/bin",
        "psql", "--no-psqlrc", "--set=ON_ERROR_STOP=1", "--tuples-only", "--no-align",
        "--dbname=odoo_test", "--command=SELECT value FROM ir_config_parameter WHERE key = 'database.uuid';",
    ).strip()
    checks["odoo_test_uuid"] = database_uuid == DATABASE_UUID

    package_payload = strict_read(LIVE_PACKAGE, mode=0o444, expected_sha256=PACKAGE_SHA256)
    live_package = verify_package(package_payload)
    checks["live_package"] = len(package_payload) == PACKAGE_SIZE and live_package["member_count"] == 64

    release_root = LIVE_RELEASE.lstat()
    tree_unsafe: list[str] = []
    if not (
        stat.S_ISDIR(release_root.st_mode) and not LIVE_RELEASE.is_symlink()
        and release_root.st_uid == 0 and release_root.st_gid == 0
        and stat.S_IMODE(release_root.st_mode) == 0o555
    ):
        tree_unsafe.append(".")
    actual_files: set[str] = set()
    for parent, directories, files in os.walk(LIVE_RELEASE, followlinks=False):
        for name in directories:
            path = Path(parent) / name
            relative = path.relative_to(LIVE_RELEASE).as_posix()
            value = path.lstat()
            if not (
                stat.S_ISDIR(value.st_mode) and not path.is_symlink()
                and value.st_uid == 0 and value.st_gid == 0
                and stat.S_IMODE(value.st_mode) == 0o555
            ):
                tree_unsafe.append(relative)
        for name in files:
            path = Path(parent) / name
            relative = path.relative_to(LIVE_RELEASE).as_posix()
            value = path.lstat()
            if not stat.S_ISREG(value.st_mode) or path.is_symlink():
                tree_unsafe.append(relative)
            else:
                actual_files.add(relative)

    manifest_payload = strict_read(LIVE_RELEASE / "RELEASE-MANIFEST.json", mode=0o444)
    require(manifest_payload == live_package["manifest_bytes"], "live release manifest differs from canonical package")
    manifest = load_json_bytes(manifest_payload, "live release manifest")
    entries = manifest.get("files")
    require(isinstance(entries, list), "live release manifest entries are invalid")
    expected_files = {"RELEASE-MANIFEST.json"}
    for item in entries:
        require(isinstance(item, dict) and set(item) == {"path", "sha256", "size"}, "invalid live release manifest entry")
        name = item["path"]
        require(isinstance(name, str) and name not in expected_files, "duplicate live release manifest path")
        expected_files.add(name)
        payload = strict_read(
            LIVE_RELEASE / Path(*PurePosixPath(name).parts),
            mode=0o555 if name == "bin/odoo-accounting-cli-v3" else 0o444,
            expected_sha256=str(item["sha256"]),
        )
        require(len(payload) == item["size"], f"live release file size mismatch: {name}")
    checks["live_release_tree"] = not tree_unsafe and actual_files == expected_files and len(actual_files) == 64

    registry_payload = strict_read(LIVE_RELEASE / "registry/capabilities.json", mode=0o444)
    registry = load_json_bytes(registry_payload, "live capability registry")
    capabilities = registry.get("capabilities")
    staged = sorted(item["id"] for item in capabilities or [] if "test" in item.get("staged_environments", []))
    enabled = sorted(item["id"] for item in capabilities or [] if "test" in item.get("enabled_environments", []))
    checks["live_registry"] = (
        isinstance(capabilities, list) and len(capabilities) == 22
        and hashlib.sha256(canonical(capabilities)).hexdigest() == REGISTRY_DIGEST
        and staged == ["acct.ap.open_items.v1", "acct.ar.open_items.v1", "acct.gl.trial_balance.v1", "acct.registry.list.v1"]
        and enabled == []
    )

    runtime_payload = strict_read(LIVE_RUNTIME, mode=0o644, expected_sha256=RUNTIME_SHA256)
    runtime = load_json_bytes(runtime_payload, "live runtime config")
    checks["live_runtime"] = runtime == EXPECTED_RUNTIME
    for field in ("odoo_python", "odoo_bin", "odoo_config"):
        checks[f"runtime:{field}"] = sha256(Path(str(runtime[field]))) == runtime[f"{field}_sha256"]
    odoo_uid = pwd.getpwnam("odoo").pw_uid
    odoo_gid = pwd.getpwnam("odoo").pw_gid
    for field in ("auth_state_path", "receipt_state_path"):
        path = Path(str(runtime[field]))
        value = path.lstat()
        checks[f"state:{field}"] = (
            stat.S_ISREG(value.st_mode) and not path.is_symlink()
            and value.st_uid == odoo_uid and value.st_gid == odoo_gid
            and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1
        )
    for field in ("auth_secret_path", "receipt_secret_path"):
        path = Path(str(runtime[field]))
        value = path.lstat()
        checks[f"secret:{field}"] = (
            stat.S_ISREG(value.st_mode) and not path.is_symlink()
            and value.st_uid == 0 and value.st_gid == odoo_gid
            and stat.S_IMODE(value.st_mode) == 0o640 and value.st_nlink == 1
        )
    checks["live_launcher"] = hashlib.sha256(
        strict_read(LIVE_RELEASE / "bin/odoo-accounting-cli-v3", mode=0o555)
    ).hexdigest() == LAUNCHER_SHA256
    live_anchor = load_json_bytes(strict_read(LIVE_ANCHOR, mode=0o444), "live release anchor")
    checks["live_release_anchor"] = live_anchor == {
        "commit": COMMIT,
        "manifest_sha256": MANIFEST_SHA256,
        "package_sha256": PACKAGE_SHA256,
        "release": RELEASE,
    }
    report = {
        "server_baseline_captured_at": server_baseline["captured_at"],
        "services": services,
        "v2_critical": critical_reports,
        "database_uuid": database_uuid,
        "release_file_count": len(actual_files),
        "release_tree_unsafe": tree_unsafe,
        "checks": checks,
        "all_checks_passed": all(checks.values()),
        "production_dependency_metadata_safe": server_baseline["production_dependency_metadata_safe"],
        "production_dependency_closure_complete": False,
        "production_promotion_allowed": False,
        "promotion_blockers": server_baseline["promotion_blockers"],
    }
    return report


def main() -> None:
    # Integrity gate: trust only the external root-owned anchor, then its checksum
    # manifest, then the exact same-FD bytes of every frozen evidence file.
    pipeline_lock_fd = acquire_pipeline_lock()
    root_meta = ROOT.lstat()
    require(
        stat.S_ISDIR(root_meta.st_mode) and not ROOT.is_symlink()
        and root_meta.st_uid == 0 and root_meta.st_gid == 0
        and stat.S_IMODE(root_meta.st_mode) == 0o500,
        "frozen evidence root metadata is invalid",
    )
    anchor_payload = strict_read(ANCHOR, mode=0o400)
    anchor = load_json_bytes(anchor_payload, "external evidence anchor")
    anchor_keys = {
        "schema_version", "release", "commit", "git_tree", "evidence_path",
        "package_sha256", "release_manifest_sha256", "registry_digest",
        "runtime_config_sha256", "read_plan_sha256", "audit_head",
        "evidence_checksum_manifest_sha256", "evidence_metadata_sha256",
        "evidence_checksum_entries", "evidence_file_count",
        "production_promotion_allowed",
    }
    require(set(anchor) == anchor_keys, "external evidence anchor fields are not exact")
    require(
        anchor["schema_version"] == 1
        and anchor["release"] == RELEASE
        and anchor["commit"] == COMMIT
        and anchor["git_tree"] == TREE
        and anchor["evidence_path"] == str(ROOT)
        and anchor["package_sha256"] == PACKAGE_SHA256
        and anchor["release_manifest_sha256"] == MANIFEST_SHA256
        and anchor["registry_digest"] == REGISTRY_DIGEST
        and anchor["runtime_config_sha256"] == RUNTIME_SHA256
        and anchor["read_plan_sha256"] == PLAN_SHA256
        and isinstance(anchor["audit_head"], str)
        and HEX64.fullmatch(str(anchor["audit_head"])) is not None
        and anchor["evidence_checksum_entries"] == len(EXPECTED_FILES) - 1
        and anchor["evidence_file_count"] == len(EXPECTED_FILES)
        and anchor["production_promotion_allowed"] is False,
        "external evidence anchor identity mismatch",
    )
    checksum_payload = strict_read(
        CHECKSUMS,
        mode=0o400,
        expected_sha256=str(anchor["evidence_checksum_manifest_sha256"]),
    )
    checksums = parse_checksums(checksum_payload)
    actual, unsafe = inspect_tree()
    require(not unsafe, "frozen evidence tree metadata is unsafe")
    require(actual == EXPECTED_FILES, "frozen evidence file set is not exact")
    require(set(checksums) == EXPECTED_FILES - {"EVIDENCE-SHA256SUMS"}, "checksum entry set is not exact")
    require(len(checksums) == anchor["evidence_checksum_entries"], "checksum entry count differs from anchor")

    blobs: dict[str, bytes] = {}
    for relative, expected in sorted(checksums.items()):
        path = ROOT / Path(*PurePosixPath(relative).parts)
        journal_limit = 1_048_576 if relative in {
            "transactions/install-completed.json", "transactions/runtime-completed.json",
        } else None
        blobs[relative] = strict_read(
            path, mode=0o400, expected_sha256=expected, max_bytes=journal_limit,
        )
    require(
        checksums["EVIDENCE-METADATA.json"] == anchor["evidence_metadata_sha256"],
        "metadata digest differs from external anchor",
    )

    def document(relative: str) -> dict[str, object]:
        return load_json_bytes(blobs[relative], relative)

    package = verify_package(blobs["release/release-package.tar.gz"])
    require(
        blobs["release/RELEASE-MANIFEST.json"] == package["manifest_bytes"],
        "frozen manifest differs from canonical package",
    )
    registry = document("release/capabilities.json")
    capabilities = registry.get("capabilities")
    staged = sorted(item["id"] for item in capabilities or [] if "test" in item.get("staged_environments", []))
    enabled = sorted(item["id"] for item in capabilities or [] if "test" in item.get("enabled_environments", []))
    require(
        isinstance(capabilities, list) and len(capabilities) == 22
        and hashlib.sha256(canonical(capabilities)).hexdigest() == REGISTRY_DIGEST
        and staged == ["acct.ap.open_items.v1", "acct.ar.open_items.v1", "acct.gl.trial_balance.v1", "acct.registry.list.v1"]
        and enabled == [],
        "frozen capability registry mismatch",
    )

    build = document("release/build-identity.json")
    require(
        build.get("release") == RELEASE and build.get("version") == VERSION
        and build.get("commit") == COMMIT and build.get("git_tree") == TREE
        and build.get("package_size") == PACKAGE_SIZE and build.get("package_sha256") == PACKAGE_SHA256
        and build.get("manifest_sha256") == MANIFEST_SHA256 and build.get("registry_digest") == REGISTRY_DIGEST
        and build.get("archive_members") == 64 and build.get("manifest_files") == 63
        and build.get("archive_links") == 0 and build.get("production_promotion_allowed") is False,
        "frozen build identity mismatch",
    )
    require(document("release/github-ci.json") == EXPECTED_CI, "frozen GitHub CI evidence mismatch")
    require(
        document("release/RELEASE-ANCHOR.json") == {
            "commit": COMMIT,
            "manifest_sha256": MANIFEST_SHA256,
            "package_sha256": PACKAGE_SHA256,
            "release": RELEASE,
        },
        "frozen release anchor mismatch",
    )
    runtime = document("release/runtime-test-dev8.json")
    require(
        hashlib.sha256(blobs["release/runtime-test-dev8.json"]).hexdigest() == RUNTIME_SHA256
        and runtime == EXPECTED_RUNTIME,
        "frozen runtime config mismatch",
    )

    odoo = pwd.getpwnam("odoo")
    odoo_uid = odoo.pw_uid
    odoo_gid = grp.getgrnam("odoo").gr_gid
    install_document = document("transactions/install-completed.json")
    runtime_document = document("transactions/runtime-completed.json")
    frozen_journal_contract = validate_completed_journals(
        install_document, runtime_document, odoo_uid, odoo_gid, compare_live=False,
    )
    auth_secret = strict_read(Path(EXPECTED_RUNTIME["auth_secret_path"]), mode=0o640, uid=0, gid=odoo_gid)
    receipt_secret = strict_read(Path(EXPECTED_RUNTIME["receipt_secret_path"]), mode=0o640, uid=0, gid=odoo_gid)
    require(len(auth_secret) >= 32 and len(receipt_secret) >= 32 and auth_secret != receipt_secret, "live HMAC secrets are invalid")

    plan = document("reads/read-plan.input.json")
    require(
        hashlib.sha256(blobs["reads/read-plan.input.json"]).hexdigest() == PLAN_SHA256
        and plan.get("principal") == "pi:test-user-2" and plan.get("user_id") == 2
        and plan.get("company_id") == 1 and plan.get("allowed_company_ids") == [1]
        and isinstance(plan.get("reads"), dict) and set(plan["reads"]) == {name for name, _ in CASES},
        "frozen read plan mismatch",
    )
    require(
        document("reads/identity.json") == {
            "principal": plan["principal"], "user_id": plan["user_id"],
            "company_id": plan["company_id"], "allowed_company_ids": plan["allowed_company_ids"],
        },
        "frozen read identity mismatch",
    )
    release_identity = {
        "commit": COMMIT,
        "manifest_sha256": MANIFEST_SHA256,
        "package_sha256": PACKAGE_SHA256,
        "registry_digest": REGISTRY_DIGEST,
        "release": RELEASE,
        "verified": True,
        "version": VERSION,
    }
    token_ids: set[str] = set()
    receipt_ids: set[str] = set()
    summary_rows = []
    roundtrip = []
    for name, capability_id in CASES:
        parameters = document(f"reads/{name}.parameters.json")
        request = document(f"reads/{name}.request.json")
        response = document(f"reads/{name}.response.json")
        extracted_receipt = document(f"reads/{name}.receipt.json")
        require(parameters == plan["reads"][name], f"{name} planned parameters changed")
        require(
            set(request) == {"capability_id", "context", "parameters"}
            and request["capability_id"] == capability_id and request["parameters"] == parameters,
            f"{name} request binding mismatch",
        )
        context = request["context"]
        require(isinstance(context, dict), f"{name} context is invalid")
        expected_auth_digest = digest({"capability_id": capability_id, "parameters": parameters})
        expected_context = {
            "allowed_company_ids": [1],
            "audience": "odoo-accounting-cli-v3",
            "auth_key_id": "test-auth-2026-07-dev8",
            "auth_request_digest": expected_auth_digest,
            "auth_signature_purpose": "auth_context_v1",
            "auth_signature_version": 1,
            "company_id": 1,
            "database_name": "odoo_test",
            "database_uuid": DATABASE_UUID,
            "environment": "test",
            "odoo_instance_id": "odoo19@43.165.173.80",
            "principal": "pi:test-user-2",
            "user_id": 2,
        }
        require(
            set(context) == set(expected_context) | {"auth_issued_at", "auth_expires_at", "auth_token_id", "auth_signature"}
            and all(context.get(key) == value for key, value in expected_context.items()),
            f"{name} context fields are not exact",
        )
        issued = parse_time(context["auth_issued_at"])
        expires = parse_time(context["auth_expires_at"])
        require(expires - issued == timedelta(minutes=4), f"{name} auth TTL mismatch")
        token_id = context["auth_token_id"]
        require(isinstance(token_id, str) and token_id.startswith("dev8-read-"), f"{name} token namespace mismatch")
        uuid.UUID(token_id.removeprefix("dev8-read-"))
        require(token_id not in token_ids, "duplicate auth token")
        token_ids.add(token_id)
        signature = context["auth_signature"]
        unsigned_context = {key: value for key, value in context.items() if key != "auth_signature"}
        require(
            isinstance(signature, str) and HEX64.fullmatch(signature) is not None
            and hmac.compare_digest(signature, hmac.new(auth_secret, canonical(unsigned_context), hashlib.sha256).hexdigest()),
            f"{name} auth signature mismatch",
        )
        require(
            response.get("ok") is True and response.get("command") == "read"
            and isinstance(response.get("data"), dict),
            f"{name} response envelope mismatch",
        )
        data = response["data"]
        require(
            data.get("capability_id") == capability_id
            and data.get("release_identity") == release_identity
            and data.get("runtime") == {
                "capability_channel": "staged", "database_name": "odoo_test",
                "database_uuid": DATABASE_UUID, "environment": "test",
                "instance_id": "odoo19@43.165.173.80",
            },
            f"{name} response identity mismatch",
        )
        result = data.get("result")
        require(isinstance(result, dict) and isinstance(result.get("page"), dict), f"{name} result is invalid")
        receipt = result.get("receipt")
        require(isinstance(receipt, dict) and receipt == extracted_receipt, f"{name} extracted receipt mismatch")
        receipt_id = receipt.get("id")
        require(isinstance(receipt_id, str), f"{name} receipt ID missing")
        uuid.UUID(receipt_id)
        require(receipt_id not in receipt_ids, "duplicate receipt ID")
        receipt_ids.add(receipt_id)
        body = {key: value for key, value in result.items() if key != "receipt"}
        expected_request_digest = digest({
            "auth_token_id": token_id,
            "capability_channel": "staged",
            "capability_id": capability_id,
            "company_id": 1,
            "database_name": "odoo_test",
            "database_uuid": DATABASE_UUID,
            "environment": "test",
            "odoo_instance_id": "odoo19@43.165.173.80",
            "parameters": parameters,
            "principal": "pi:test-user-2",
            "registry_digest": REGISTRY_DIGEST,
            "release_digest": MANIFEST_SHA256,
            "user_id": 2,
        })
        expected_receipt = {
            "capability_id": capability_id,
            "capability_channel": "staged",
            "company_id": 1,
            "database_name": "odoo_test",
            "database_uuid": DATABASE_UUID,
            "environment": "test",
            "odoo_instance_id": "odoo19@43.165.173.80",
            "record_count": result["page"].get("total_count"),
            "registry_digest": REGISTRY_DIGEST,
            "release_digest": MANIFEST_SHA256,
            "request_digest": expected_request_digest,
            "result_digest": digest(body),
            "signature_key_id": "test-receipt-2026-07-dev8",
            "signature_purpose": "read_receipt_v2",
            "signature_version": 2,
            "user_id": 2,
        }
        require(
            set(receipt) == set(expected_receipt) | {"id", "observed_at", "signature"}
            and all(receipt.get(key) == value for key, value in expected_receipt.items()),
            f"{name} receipt binding mismatch",
        )
        parse_time(receipt["observed_at"])
        receipt_signature = receipt["signature"]
        unsigned_receipt = {key: value for key, value in receipt.items() if key != "signature"}
        require(
            isinstance(receipt_signature, str) and HEX64.fullmatch(receipt_signature) is not None
            and hmac.compare_digest(receipt_signature, hmac.new(receipt_secret, canonical(unsigned_receipt), hashlib.sha256).hexdigest()),
            f"{name} receipt signature mismatch",
        )
        require(blobs[f"reads/{name}.stderr"] == b"", f"{name} stderr is not empty")
        require(blobs[f"reads/{name}.exit"].strip() == b"0", f"{name} exit is not zero")
        summary_rows.append({
            "name": name, "capability_id": capability_id, "auth_token_id": token_id,
            "receipt_id": receipt_id, "record_count": receipt["record_count"],
        })
        roundtrip.append({"name": name, "capability_id": capability_id, "passed": True})
    require(len(token_ids) == len(receipt_ids) == 4, "read token or receipt cardinality mismatch")
    require(document("reads/summary.json") == {"all_verified": True, "reads": summary_rows}, "read summary mismatch")

    persistence = document("state/persistence-audit.json")
    auth_state, auth_events = inspect_db(blobs["state/auth-state.sqlite3"])
    receipt_state, receipt_events = inspect_db(blobs["state/receipt-state.sqlite3"])
    events = verify_chain(receipt_events)
    exported = json.loads(blobs["state/audit-events.json"].decode("utf-8"), object_pairs_hook=reject_duplicates)
    require(isinstance(exported, list) and exported == events, "exported audit events mismatch")
    audit_head = events[-1]["event_hash"] if events else None
    event_counts = Counter(event["payload"]["capability_id"] for event in events)
    require(
        auth_events == [] and auth_state["user_version"] == receipt_state["user_version"] == 2
        and auth_state["quick_check"] == receipt_state["quick_check"] == ["ok"]
        and auth_state["foreign_key_violations"] == receipt_state["foreign_key_violations"] == 0
        and auth_state["counts"] == {"approval_records": 0, "audit_events": 0, "consumed_auth_tokens": 4, "consumed_receipts": 0, "idempotency_keys": 0, "operations": 0}
        and receipt_state["counts"] == {"approval_records": 0, "audit_events": 4, "consumed_auth_tokens": 0, "consumed_receipts": 4, "idempotency_keys": 0, "operations": 0}
        and audit_head == anchor["audit_head"] == persistence.get("audit_head")
        and event_counts == {"acct.ap.open_items.v1": 1, "acct.ar.open_items.v1": 1, "acct.gl.trial_balance.v1": 1, "acct.registry.list.v1": 1}
        and auth_state["sha256"] == persistence.get("auth", {}).get("sha256")
        and receipt_state["sha256"] == persistence.get("receipt", {}).get("sha256")
        and persistence.get("release") == RELEASE and persistence.get("commit") == COMMIT
        and persistence.get("git_tree") == TREE and persistence.get("package_sha256") == PACKAGE_SHA256
        and persistence.get("manifest_sha256") == MANIFEST_SHA256 and persistence.get("registry_digest") == REGISTRY_DIGEST
        and persistence.get("runtime_config_sha256") == RUNTIME_SHA256 and persistence.get("read_plan_sha256") == PLAN_SHA256
        and persistence.get("audit_event_count") == 4 and persistence.get("all_checks_passed") is True
        and persistence.get("production_promotion_allowed") is False,
        "persistence or audit state mismatch",
    )

    oracle = document("reads/read-oracles.audit.json")
    oracle_names = {
        "trial-balance": ("acct.gl.trial_balance.v1", EXECUTION_SOURCE_HASHES["dev6-trial-balance-sql-oracle.py"]),
        "ar-open-items": ("acct.ar.open_items.v1", EXECUTION_SOURCE_HASHES["dev6-ar-sql-oracle.py"]),
        "ap-open-items": ("acct.ap.open_items.v1", EXECUTION_SOURCE_HASHES["dev7-ap-sql-oracle.py"]),
    }
    oracle_entries = oracle.get("oracles")
    oracle_by_name = {item.get("name"): item for item in oracle_entries or [] if isinstance(item, dict)}
    require(
        oracle.get("schema_version") == 1 and oracle.get("release") == RELEASE
        and oracle.get("database_name") == "odoo_test" and oracle.get("capability_channel") == "staged"
        and isinstance(oracle.get("checks"), dict) and oracle["checks"]
        and all(value is True for value in oracle["checks"].values())
        and isinstance(oracle_entries, list) and len(oracle_entries) == 3
        and set(oracle_by_name) == set(oracle_names)
        and len(oracle.get("request_roundtrip", [])) == 4
        and len(oracle.get("staged_inputs", [])) == 5
        and oracle.get("odoo_pid_before") == oracle.get("odoo_pid_after") == EXPECTED_PIDS["odoo19.service"]
        and oracle.get("all_checks_passed") is True
        and oracle.get("odoo_action_performed") is False
        and oracle.get("database_writes_permitted") is False
        and oracle.get("production_validated") is False
        and oracle.get("production_promotion_allowed") is False,
        "read oracle audit mismatch",
    )
    for name, (capability_id, script_hash) in oracle_names.items():
        item = oracle_by_name[name]
        report = document(f"reads/{name}.oracle.json")
        require(
            item.get("script_sha256") == script_hash
            and item.get("all_checks_passed") is True
            and item.get("transaction_isolation") == "repeatable read"
            and item.get("transaction_read_only") == "on"
            and item.get("rollback_completed") is True
            and report.get("capability_id") == capability_id
            and report.get("transaction_isolation") == "repeatable read"
            and report.get("transaction_read_only") == "on"
            and report.get("rollback_completed") is True
            and isinstance(report.get("checks"), dict) and report["checks"]
            and all(value is True for value in report["checks"].values())
            and report.get("all_checks_passed") is True
            and blobs[f"reads/{name}.oracle.stderr"] == b""
            and blobs[f"reads/{name}.oracle.exit"].strip() == b"0",
            f"{name} financial oracle mismatch",
        )

    staging_audit = document("execution/execution-staging-audit.json")
    lock_meta = PIPELINE_LOCK.lstat()
    strict_read(PIPELINE_LOCK, mode=0o600)
    lock_evidence = staging_audit.get("pipeline_lock", {})
    require(
        isinstance(lock_evidence, dict)
        and exact_integer_fields(lock_evidence, ("device", "inode", "uid", "gid", "nlink"))
        and set(lock_evidence) == {
            "path", "device", "inode", "uid", "gid", "mode", "nlink",
            "regular", "not_symlink", "o_nofollow", "same_inode", "exclusive", "acquired",
        }
        and lock_evidence.get("path") == str(PIPELINE_LOCK)
        and lock_evidence.get("device") == lock_meta.st_dev
        and lock_evidence.get("inode") == lock_meta.st_ino
        and lock_evidence.get("uid") == lock_evidence.get("gid") == 0
        and lock_evidence.get("mode") == "0600" and lock_evidence.get("nlink") == 1
        and all(lock_evidence.get(key) is True for key in ("regular", "not_symlink", "o_nofollow", "same_inode", "exclusive", "acquired")),
        "execution pipeline lock evidence mismatch",
    )
    pipeline_transactions = staging_audit.get("pipeline_transactions", {})
    transaction_keys = {
        "schema_version", "install_journal", "runtime_journal",
        "install_transaction_id", "install_state", "runtime_transaction_id",
        "runtime_state", "runtime_upstream_install_transaction_id",
        "computed_install_identity_sha256",
        "runtime_upstream_install_identity_sha256", "install_final_objects",
        "runtime_final_objects", "staging_objects_absent", "all_checks_passed",
    }
    require(
        isinstance(pipeline_transactions, dict) and set(pipeline_transactions) == transaction_keys
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
    install_journal_payload = strict_read(INSTALL_JOURNAL, mode=0o600, max_bytes=1_048_576)
    runtime_journal_payload = strict_read(RUNTIME_JOURNAL, mode=0o600, max_bytes=1_048_576)
    require(
        install_journal_payload == blobs["transactions/install-completed.json"]
        and runtime_journal_payload == blobs["transactions/runtime-completed.json"],
        "live completed transaction journals differ from frozen evidence",
    )
    live_journal_contract = validate_completed_journals(
        install_document, runtime_document, odoo_uid, odoo_gid, compare_live=True,
    )
    install_id = frozen_journal_contract["install_transaction_id"]
    runtime_id = frozen_journal_contract["runtime_transaction_id"]
    require(
        live_journal_contract == {
            **frozen_journal_contract,
            "install_final_identities": live_journal_contract["install_final_identities"],
            "runtime_final_identities": live_journal_contract["runtime_final_identities"],
        }
        and install_id == pipeline_transactions["install_transaction_id"]
        and runtime_id == pipeline_transactions["runtime_transaction_id"]
        and frozen_journal_contract["install_binding_sha256"]
        == pipeline_transactions["computed_install_identity_sha256"]
        == pipeline_transactions["runtime_upstream_install_identity_sha256"],
        "frozen/live transaction contract differs from execution evidence",
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
        current = path.lstat()
        require(
            isinstance(report, dict) and set(report) == journal_report_keys
            and exact_integer_fields(report, ("device", "inode", "uid", "gid", "nlink"))
            and report.get("path") == str(path)
            and report.get("device") == current.st_dev and report.get("inode") == current.st_ino
            and report.get("uid") == current.st_uid == 0 and report.get("gid") == current.st_gid == 0
            and report.get("mode") == "0600" and stat.S_IMODE(current.st_mode) == 0o600
            and report.get("nlink") == current.st_nlink == 1
            and all(report.get(key) is True for key in ("regular", "not_symlink", "o_nofollow", "same_inode"))
            and report.get("sha256") == hashlib.sha256(payload).hexdigest(),
            f"pipeline {label} metadata mismatch",
        )
    final_reports = {
        "install_final_objects": (live_journal_contract["install_final_identities"], install_document["objects"]),
        "runtime_final_objects": (live_journal_contract["runtime_final_identities"], runtime_document["objects"]),
    }
    for report_key, (identities, records) in final_reports.items():
        evidence = pipeline_transactions[report_key]
        require(isinstance(evidence, dict) and set(evidence) == set(identities), f"pipeline {report_key} evidence set mismatch")
        for label, identity in identities.items():
            report = evidence[label]
            require(
                isinstance(report, dict)
                and exact_integer_fields(report, ("device", "inode", "uid", "gid"))
                and set(report) == {"path", "device", "inode", "kind", "uid", "gid", "mode", "journal_identity_matched"}
                and report.get("path") == records[label]["path"]
                and report.get("kind") == identity["kind"]
                and report.get("device") == identity["dev"] and report.get("inode") == identity["ino"]
                and report.get("uid") == identity["uid"] and report.get("gid") == identity["gid"]
                and report.get("mode") == f"{int(identity['mode']):04o}" and report.get("journal_identity_matched") is True,
                f"pipeline final journal/object evidence mismatch: {label}",
            )
    expected_guards = {
        "same_fd_source": True, "o_nofollow": True, "o_excl": True,
        "pre_post_source_identity_equal": True, "fsync": True,
    }
    purpose_sources = {
        "real-read-runner": "dev8-run-real-reads.sh",
        "signer": "dev8-sign-read.py",
        "launcher-isolation": "dev8-launcher-isolation-gate.py",
    }
    stages = staging_audit.get("stages")
    by_purpose = {item.get("purpose"): item for item in stages or [] if isinstance(item, dict)}
    require(isinstance(stages, list) and len(stages) == 3 and set(by_purpose) == set(purpose_sources), "execution stage set mismatch")
    real_stage_path: str | None = None
    for purpose, source_name in purpose_sources.items():
        item = by_purpose[purpose]
        directory = item.get("staging_dir", {})
        staged_file = item.get("staged_file", {})
        execution = item.get("execution", {})
        path = directory.get("path")
        if purpose in {"real-read-runner", "signer"}:
            require(isinstance(path, str) and path.startswith("/run/dev8-real-read."), "real-read staging path mismatch")
            real_stage_path = path if real_stage_path is None else real_stage_path
            require(path == real_stage_path, "runner and signer did not share the same staging directory")
        else:
            require(isinstance(path, str) and path.startswith("/run/dev8-launcher-isolation."), "isolation staging path mismatch")
        expected_mode = "0400" if purpose == "real-read-runner" else "0440"
        expected_gid = 0 if purpose == "real-read-runner" else odoo_gid
        expected_exec_uid = 0 if purpose == "real-read-runner" else odoo_uid
        expected_exec_gid = 0 if purpose == "real-read-runner" else odoo_gid
        expected_output = {
            "real-read-runner": hashlib.sha256(blobs["execution/real-read.stdout"]).hexdigest(),
            "signer": hashlib.sha256(blobs["reads/summary.json"]).hexdigest(),
            "launcher-isolation": hashlib.sha256(blobs["execution/launcher-isolation.stdout"]).hexdigest(),
        }[purpose]
        require(
            item.get("source_name") == source_name
            and item.get("source_sha256") == EXECUTION_SOURCE_HASHES[source_name]
            and item.get("copy_guards") == expected_guards
            and item.get("cleanup") == {"file_absent": True, "dir_absent": True}
            and directory.get("parent") == "/run" and directory.get("uid") == 0
            and directory.get("gid") == odoo_gid and directory.get("mode") == "0750"
            and directory.get("random") is True
            and staged_file.get("path") == f"{path}/{source_name}"
            and staged_file.get("sha256") == EXECUTION_SOURCE_HASHES[source_name]
            and staged_file.get("uid") == 0 and staged_file.get("gid") == expected_gid
            and staged_file.get("mode") == expected_mode and staged_file.get("nlink") == 1
            and staged_file.get("regular") is True and staged_file.get("not_symlink") is True
            and execution.get("uid") == expected_exec_uid and execution.get("gid") == expected_exec_gid
            and execution.get("exit_code") == 0 and execution.get("output_sha256") == expected_output
            and execution.get("timed_out") is False and execution.get("process_group_reaped") is True,
            f"execution stage metadata mismatch: {purpose}",
        )
    oracle_execution = staging_audit.get("oracle", {})
    oracle_runner = oracle_execution.get("runner", {})
    oracle_sources = oracle_execution.get("sources", [])
    oracle_source_names = {
        "dev6-trial-balance-sql-oracle.py",
        "dev6-ar-sql-oracle.py",
        "dev7-ap-sql-oracle.py",
    }
    oracle_source_by_name = {item.get("source_name"): item for item in oracle_sources if isinstance(item, dict)}
    require(
        oracle_runner.get("source_name") == "dev8-run-read-oracles.sh"
        and oracle_runner.get("source_sha256") == EXECUTION_SOURCE_HASHES["dev8-run-read-oracles.sh"]
        and oracle_runner.get("staging_dir", {}).get("path") == real_stage_path
        and oracle_runner.get("staging_dir", {}).get("parent") == "/run"
        and oracle_runner.get("staging_dir", {}).get("uid") == 0
        and oracle_runner.get("staging_dir", {}).get("gid") == odoo_gid
        and oracle_runner.get("staging_dir", {}).get("mode") == "0750"
        and oracle_runner.get("staging_dir", {}).get("random") is True
        and oracle_runner.get("staged_file", {}).get("path") == f"{real_stage_path}/dev8-run-read-oracles.sh"
        and oracle_runner.get("staged_file", {}).get("sha256") == EXECUTION_SOURCE_HASHES["dev8-run-read-oracles.sh"]
        and oracle_runner.get("staged_file", {}).get("uid") == 0
        and oracle_runner.get("staged_file", {}).get("gid") == 0
        and oracle_runner.get("staged_file", {}).get("mode") == "0400"
        and oracle_runner.get("staged_file", {}).get("nlink") == 1
        and oracle_runner.get("staged_file", {}).get("regular") is True
        and oracle_runner.get("staged_file", {}).get("not_symlink") is True
        and oracle_runner.get("copy_guards") == expected_guards
        and oracle_runner.get("execution", {}).get("uid") == 0
        and oracle_runner.get("execution", {}).get("gid") == 0
        and oracle_runner.get("execution", {}).get("exit_code") == 0
        and oracle_runner.get("execution", {}).get("output_sha256") == hashlib.sha256(blobs["execution/read-oracles.stdout"]).hexdigest()
        and oracle_runner.get("execution", {}).get("timed_out") is False
        and oracle_runner.get("execution", {}).get("process_group_reaped") is True
        and oracle_runner.get("cleanup") == {"file_absent": True, "dir_absent": True}
        and isinstance(oracle_sources, list) and len(oracle_sources) == 3
        and set(oracle_source_by_name) == oracle_source_names,
        "oracle runner staging evidence mismatch",
    )
    for source_name, item in oracle_source_by_name.items():
        staged_file = item.get("staged_file", {})
        execution = item.get("execution", {})
        require(
            item.get("purpose") == f"oracle-source:{source_name}"
            and item.get("source_sha256") == EXECUTION_SOURCE_HASHES[source_name]
            and item.get("staging_path") == f"/tmp/{source_name}"
            and item.get("copy_guards") == expected_guards
            and item.get("cleanup") == {"file_absent": True, "dir_absent": True}
            and staged_file.get("path") == f"/tmp/{source_name}"
            and staged_file.get("sha256") == EXECUTION_SOURCE_HASHES[source_name]
            and staged_file.get("uid") == staged_file.get("gid") == 0
            and staged_file.get("mode") == "0444" and staged_file.get("nlink") == 1
            and staged_file.get("regular") is True and staged_file.get("not_symlink") is True
            and execution.get("uid") == odoo_uid and execution.get("gid") == odoo_gid
            and execution.get("exit_code") == 0
            and execution.get("output_sha256") == hashlib.sha256(blobs["reads/read-oracles.audit.json"]).hexdigest()
            and execution.get("timed_out") is False and execution.get("process_group_reaped") is True,
            f"oracle source staging evidence mismatch: {source_name}",
        )
    cleanup_keys = {
        "real_read_stage_absent", "isolation_stage_absent", "odoo_output_absent",
        *(f"oracle_source_absent:{name}" for name in oracle_source_names),
    }
    require(
        staging_audit.get("schema_version") == 1 and staging_audit.get("release") == RELEASE
        and staging_audit.get("upload_root") == {"path": "/root/odoo-accounting-cli-v3-dev8-upload", "uid": 0, "gid": 0, "mode": "0700", "not_odoo_traversable": True}
        and staging_audit.get("read_plan_sha256") == PLAN_SHA256
        and staging_audit.get("source_hashes") == EXECUTION_SOURCE_HASHES
        and isinstance(staging_audit.get("cleanup"), dict)
        and set(staging_audit["cleanup"]) == cleanup_keys
        and all(value is True for value in staging_audit["cleanup"].values())
        and staging_audit.get("failure") is None
        and staging_audit.get("all_checks_passed") is True
        and staging_audit.get("production_promotion_allowed") is False,
        "execution staging audit mismatch",
    )
    for name in ("real-read", "read-oracles", "launcher-isolation"):
        require(blobs[f"execution/{name}.exit"].strip() == b"0", f"{name} execution exit mismatch")
        require(blobs[f"execution/{name}.stderr"] == b"", f"{name} execution stderr is not empty")

    launcher_isolation = document("execution/launcher-isolation.json")
    require(
        launcher_isolation.get("release") == RELEASE
        and launcher_isolation.get("launcher_sha256") == LAUNCHER_SHA256
        and isinstance(launcher_isolation.get("checks"), dict)
        and launcher_isolation["checks"] and all(value is True for value in launcher_isolation["checks"].values())
        and launcher_isolation.get("all_checks_passed") is True
        and launcher_isolation.get("production_promotion_allowed") is False,
        "launcher isolation evidence mismatch",
    )

    dependency = document("gates/runtime-dependency-inventory.json")
    require(
        dependency.get("release") == RELEASE
        and dependency.get("scoped_inventory_checks_passed") is True
        and dependency.get("production_dependency_closure_complete") is False
        and dependency.get("external_dependency_bound") is False
        and isinstance(dependency.get("promotion_blockers"), list)
        and dependency.get("production_promotion_allowed") is False,
        "runtime dependency inventory mismatch",
    )
    negative = document("gates/canonical-package-negative-gates.json")
    expected_negative = {
        "wrong-path": (5, "runtime_release_mismatch"),
        "same-bytes-tmp-copy": (5, "runtime_release_mismatch"),
        "symlink": (6, "odoo_read_failed"),
        "tampered-copy": (6, "odoo_read_failed"),
    }
    negative_cases = negative.get("cases", {})
    negative_cases_ok = isinstance(negative_cases, dict) and set(negative_cases) == set(expected_negative)
    if negative_cases_ok:
        for name, (expected_exit, expected_error) in expected_negative.items():
            case = negative_cases[name]
            checks = case.get("checks", {}) if isinstance(case, dict) else {}
            negative_cases_ok = negative_cases_ok and (
                case.get("expected_exit") == expected_exit and case.get("expected_error") == expected_error
                and case.get("all_checks_passed") is True and isinstance(checks, dict)
                and set(checks) == {
                    "fresh_token_before", "token_still_unconsumed", "expected_exit", "stdout_empty",
                    "structured_error", "auth_hash_unchanged", "receipt_hash_unchanged",
                    "audit_hash_unchanged", "odoo_pid_unchanged", "odoo_pid_active",
                    "odoo_canary_fixed_inode_unchanged",
                }
                and all(value is True for value in checks.values())
                and case.get("odoo_pid_after") == EXPECTED_PIDS["odoo19.service"]
            )
    require(
        negative.get("release") == RELEASE and negative.get("manifest_sha256") == MANIFEST_SHA256
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
            "wrong_path_is_same_bytes": True, "tmp_copy_is_same_bytes": True,
            "symlink_fixture_is_link": True, "tampered_fixture_differs": True,
        }
        and negative.get("odoo_pid_before") == EXPECTED_PIDS["odoo19.service"]
        and negative.get("odoo_canary_reached") is False
        and negative.get("secret_material_emitted") is False,
        "canonical-package negative gates mismatch",
    )

    deployment_ok = True
    for name in ("install", "runtime-setup", "server-gate"):
        deployment_ok = deployment_ok and blobs[f"deployment/{name}.exit"].strip() == b"0"
        deployment_ok = deployment_ok and blobs[f"deployment/{name}.stderr"] == b""
    install_stdout = blobs["deployment/install.stdout"].decode("utf-8")
    runtime_stdout = blobs["deployment/runtime-setup.stdout"].decode("utf-8")
    server_stdout = blobs["deployment/server-gate.stdout"].decode("utf-8")
    deployment_ok = deployment_ok and all(marker in install_stdout for marker in (
        f"installed_release={RELEASE}", f"package_sha256={PACKAGE_SHA256}",
        f"manifest_sha256={MANIFEST_SHA256}", f"registry_digest={REGISTRY_DIGEST}",
    ))
    deployment_ok = deployment_ok and "dev8_runtime_setup=passed" in runtime_stdout and f"release={RELEASE}" in runtime_stdout
    deployment_ok = deployment_ok and all(marker in server_stdout for marker in (
        "dev8_server_gate=passed", "dev8_isolation_pre=passed", "dev8_isolation_post=passed",
        f"release={RELEASE}", f"package_sha256={PACKAGE_SHA256}",
        f"manifest_sha256={MANIFEST_SHA256}", f"registry_digest={REGISTRY_DIGEST}",
        "mutable_candidate_test_fixture_used=false",
        "server_unit_test_source=github-ci-run-29319326192",
        "production_critical_metadata_safe=false",
    ))
    require(deployment_ok, "deployment gate captures mismatch")

    pre_isolation = document("isolation/pre-freeze.json")
    require(
        pre_isolation.get("release") == RELEASE
        and isinstance(pre_isolation.get("checks"), dict) and pre_isolation["checks"]
        and all(value is True for value in pre_isolation["checks"].values())
        and pre_isolation.get("all_checks_passed") is True
        and pre_isolation.get("production_dependency_closure_complete") is False
        and pre_isolation.get("production_promotion_allowed") is False,
        "pre-freeze isolation evidence mismatch",
    )

    toolchain_manifest_payload = blobs[f"tools/{TOOLCHAIN_MANIFEST_NAME}"]
    toolchain_manifest = load_json_bytes(toolchain_manifest_payload, "toolchain manifest")
    manifest_entries = validate_toolchain_manifest(toolchain_manifest)
    server_baseline_payload = blobs[f"tools/{SERVER_BASELINE_NAME}"]
    baseline_expected = manifest_entries[SERVER_BASELINE_NAME]
    require(
        hashlib.sha256(server_baseline_payload).hexdigest() == baseline_expected["sha256"]
        and len(server_baseline_payload) == baseline_expected["size"],
        "frozen server baseline differs from toolchain manifest",
    )
    server_baseline = validate_server_baseline(
        load_json_bytes(server_baseline_payload, "server baseline")
    )
    require(
        pre_isolation.get("server_baseline_captured_at") == server_baseline["captured_at"]
        and pre_isolation.get("production_dependency_metadata_safe")
        is server_baseline["production_dependency_metadata_safe"]
        and pre_isolation.get("promotion_blockers") == server_baseline["promotion_blockers"],
        "pre-freeze isolation baseline binding mismatch",
    )
    inventory = document("tools/TOOL-INVENTORY.json")
    tool_entries = inventory.get("tools")
    require(
        set(inventory) == {
            "schema_version", "release", "toolchain_version", "source_directory",
            "toolchain_manifest_sha256", "server_baseline_sha256",
            "server_baseline_size", "upload_root", "tools", "tool_count",
            "secret_material_included", "production_promotion_allowed",
        }
        and isinstance(inventory.get("schema_version"), int)
        and not isinstance(inventory.get("schema_version"), bool)
        and inventory.get("schema_version") == 1 and inventory.get("release") == RELEASE
        and inventory.get("toolchain_version") == TOOLCHAIN_VERSION
        and inventory.get("source_directory") == "deployment/dev8"
        and inventory.get("toolchain_manifest_sha256") == hashlib.sha256(toolchain_manifest_payload).hexdigest()
        and inventory.get("server_baseline_sha256") == hashlib.sha256(server_baseline_payload).hexdigest()
        and inventory.get("server_baseline_size") == len(server_baseline_payload)
        and inventory.get("upload_root") == "/root/odoo-accounting-cli-v3-dev8-upload"
        and isinstance(tool_entries, list) and len(tool_entries) == len(TOOL_FILES)
        and inventory.get("tool_count") == len(TOOL_FILES)
        and inventory.get("secret_material_included") is False
        and inventory.get("production_promotion_allowed") is False,
        "tool inventory envelope mismatch",
    )
    require([item.get("name") for item in tool_entries] == list(TOOL_FILES), "tool inventory order or names mismatch")
    for item in tool_entries:
        require(isinstance(item, dict) and set(item) == {"name", "sha256", "size", "source_uid", "source_gid", "source_mode", "source_nlink"}, "tool inventory entry fields mismatch")
        name = item["name"]
        payload = blobs[f"tools/{name}"]
        source_mode = item["source_mode"]
        expected_tool = manifest_entries[name]
        require(
            item["sha256"] == hashlib.sha256(payload).hexdigest() and item["size"] == len(payload)
            and item["sha256"] == expected_tool["sha256"] and item["size"] == expected_tool["size"]
            and item["source_uid"] == item["source_gid"] == 0 and item["source_nlink"] == 1
            and isinstance(source_mode, str) and re.fullmatch(r"0[0-7]{3}", source_mode) is not None
            and not (int(source_mode, 8) & 0o022),
            f"tool inventory digest or source metadata mismatch: {name}",
        )
        if name in EXECUTION_SOURCE_HASHES:
            require(item["sha256"] == EXECUTION_SOURCE_HASHES[name], f"known execution tool hash mismatch: {name}")

    secret_scan = document("security/secret-scan.json")
    expected_pre_scan_count = len(EXPECTED_FILES - {"security/secret-scan.json", "EVIDENCE-METADATA.json", "EVIDENCE-SHA256SUMS"})
    require(
        secret_scan == {
            "schema_version": 1,
            "release": RELEASE,
            "scanned_file_count_before_report": expected_pre_scan_count,
            "secret_forms_scanned": SECRET_SCAN_FORMS,
            "auth_secret_absent": True,
            "receipt_secret_absent": True,
            "secret_material_included": False,
            "production_promotion_allowed": False,
        },
        "frozen secret scan report mismatch",
    )
    needles = secret_needles(auth_secret, receipt_secret)
    require(needles, "runtime secret scan forms are empty")
    for label, payload in [*blobs.items(), ("EVIDENCE-SHA256SUMS", checksum_payload), ("external-anchor", anchor_payload)]:
        require(all(needle not in payload for needle in needles), f"live secret material found in frozen evidence: {label}")

    metadata = document("EVIDENCE-METADATA.json")
    metadata_keys = {
        "schema_version", "release", "version", "commit", "git_tree", "package_sha256",
        "package_size", "manifest_sha256", "registry_digest", "runtime_config_sha256",
        "read_plan_sha256", "database_uuid", "audit_head", "auth_tokens",
        "consumed_receipts", "receipt_audit_events", "verified_capabilities",
        "registered_capabilities", "staged_capabilities", "enabled_capabilities",
        "frozen_at", "evidence_scope", "evidence_visibility", "evidence_file_count",
        "goal_complete", "secret_material_included", "production_writes_authorized",
        "odoo_accounting_write_performed", "pi_route_changed", "v2_changed",
        "production_dependency_closure_complete", "production_promotion_allowed",
        "promotion_blockers",
    }
    require(set(metadata) == metadata_keys, "evidence metadata fields are not exact")
    parse_time(metadata["frozen_at"])
    require(
        metadata["schema_version"] == 1 and metadata["release"] == RELEASE and metadata["version"] == VERSION
        and metadata["commit"] == COMMIT and metadata["git_tree"] == TREE
        and metadata["package_sha256"] == PACKAGE_SHA256 and metadata["package_size"] == PACKAGE_SIZE
        and metadata["manifest_sha256"] == MANIFEST_SHA256 and metadata["registry_digest"] == REGISTRY_DIGEST
        and metadata["runtime_config_sha256"] == RUNTIME_SHA256 and metadata["read_plan_sha256"] == PLAN_SHA256
        and metadata["database_uuid"] == DATABASE_UUID and metadata["audit_head"] == audit_head
        and metadata["auth_tokens"] == metadata["consumed_receipts"] == metadata["receipt_audit_events"] == 4
        and metadata["verified_capabilities"] == ["acct.ap.open_items.v1", "acct.ar.open_items.v1", "acct.gl.trial_balance.v1", "acct.registry.list.v1"]
        and metadata["registered_capabilities"] == 22 and metadata["staged_capabilities"] == 4
        and metadata["enabled_capabilities"] == 0 and metadata["evidence_file_count"] == len(EXPECTED_FILES)
        and metadata["evidence_visibility"] == "root-only directories 0500 and files 0400"
        and metadata["promotion_blockers"] == [
            *dependency["promotion_blockers"], *server_baseline["promotion_blockers"]
        ]
        and all(metadata[key] is False for key in (
            "goal_complete", "secret_material_included", "production_writes_authorized",
            "odoo_accounting_write_performed", "pi_route_changed", "v2_changed",
            "production_dependency_closure_complete", "production_promotion_allowed",
        )),
        "evidence metadata identity or safety flags mismatch",
    )

    live = verify_live_isolation(server_baseline)
    require(live["all_checks_passed"] is True and live["production_promotion_allowed"] is False, "post-freeze live isolation mismatch")
    report = {
        "schema_version": 1,
        "release": RELEASE,
        "checksum_entries": len(checksums),
        "actual_file_count": len(actual),
        "audit_head": audit_head,
        "identity_checks": {
            "external_anchor_first": True,
            "checksum_manifest_bound": True,
            "canonical_package": True,
            "registry": True,
            "build_and_ci": True,
            "runtime": True,
        },
        "evidence_checks": {
            "exact_root_only_file_set": True,
            "all_files_same_fd_checksum_verified_before_parse": True,
            "four_parameter_and_hmac_roundtrips": True,
            "persistence_and_audit_chain": True,
            "three_financial_oracles": True,
            "pipeline_lock_and_execution_staging": True,
            "deployment_and_negative_gates": True,
            "tool_snapshot": True,
            "live_secret_rescan": True,
            "pre_and_post_freeze_isolation": True,
        },
        "roundtrip": roundtrip,
        "unsafe_entries": [],
        "failed_checksum_paths": [],
        "live_isolation": live,
        "production_dependency_closure_complete": False,
        "production_promotion_allowed": False,
        "all_checks_passed": True,
    }
    print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True))
    fcntl.flock(pipeline_lock_fd, fcntl.LOCK_UN)
    os.close(pipeline_lock_fd)


if __name__ == "__main__":
    main()

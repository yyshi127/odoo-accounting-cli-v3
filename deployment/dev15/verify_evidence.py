#!/usr/bin/python3 -I
"""Independently verify and externally anchor one frozen Dev15 read bundle."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any


CAPABILITY_ID = "acct.multicurrency.balance_read.v1"
RELEASE = "0.1.0.dev15-c4616386f921"
VERSION = "0.1.0.dev15"
COMMIT = "c4616386f921946cf43cde2de449d2938a837422"
RELEASE_ROOT = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE
PACKAGE_PATH = (
    Path("/opt/odoo-accounting-cli-v3/packages")
    / f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
)
RELEASE_ANCHOR = (
    Path("/opt/odoo-accounting-cli-v3/trusted-artifacts") / f"{RELEASE}.json"
)
TOOLCHAIN_VERSION = "0.1.0.dev15-read-toolchain.1"
TOOLCHAIN_ROOT = Path("/opt/odoo-accounting-cli-v3/toolchains") / TOOLCHAIN_VERSION
TOOLCHAIN_MANIFEST = TOOLCHAIN_ROOT / "TOOLCHAIN-MANIFEST.json"
TOOLCHAIN_FILES = (
    "install_toolchain.py", "runtime_setup.py", "sign_read.py",
    "run_multicurrency_read.py", "multicurrency_sql_oracle.py",
    "verify_evidence.py", "read_plan.json",
)
TOOLCHAIN_CONTROL_FILES = ("README.md", "check_toolchain.py")
COMMITTED_PLAN = TOOLCHAIN_ROOT / "read_plan.json"
RUNTIME_CONFIG = (
    Path("/etc/odoo-accounting-cli-v3/candidates")
    / "runtime-test-dev15-c4616386f921.json"
)
ANCHOR_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence-anchors")
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
READ_PLAN_SHA256 = "860de4fb5b4efe41f760295b0b8eee4ae8b63f15d70e25e418640c8eb5f04c80"
MANIFEST_SHA256 = "f4ea1dbd6e6b57472875d27a64504ffb433812c568bcd7be546d2e5074d24be2"
PACKAGE_SHA256 = "71d9bcea9c89b9ab2877406ca28b039791d380d0aeb09c60516a83b031b9c8bf"
REGISTRY_DIGEST = "ae50c3aa8d93472b7d58ca656ea9b2a42e18e5a38a9df0919320737b5632789b"
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
SYSTEM_IDENTIFIER = "7616327373742442245"
SERVER_VERSION_NUM = 160014
SOCKET_DIRECTORY = "/var/run/postgresql"
SOCKET_PATH = "/var/run/postgresql/.s.PGSQL.5432"
ORACLE_PYTHON = "/usr/bin/python3.12"
ORACLE_PYTHON_SHA256 = "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118"
ORACLE_PSQL = "/usr/lib/postgresql/16/bin/psql"
ORACLE_PSQL_SHA256 = "6d593ef8e95e5275691fcc28927cc540282db141ca1ec5e3806e7db5523613cb"
V3_UNIT_PREFIX = "odoo-accounting-cli-v3-"
SYSTEMD_SUPPLEMENTAL_PATHS = (
    "/etc/systemd/system", "/etc/systemd/system.attached",
    "/etc/systemd/system.control", "/run/systemd/system",
    "/run/systemd/system.attached", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/run/systemd/generator", "/run/systemd/generator.late",
    "/usr/local/lib/systemd/system", "/usr/lib/systemd/system",
    "/lib/systemd/system",
)
GENESIS_HASH = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_BUNDLE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_RELEASE_ENTRIES = 20_000
RATE_TOLERANCE = Decimal("1e-12")
EXECUTABLE_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)
BUNDLE_FILES = frozenset(
    {
        "exit", "oracle.exit", "oracle.json", "oracle.stderr", "read-plan.json",
        "receipt.json", "request.json", "response.json", "signer.exit",
        "signer.stderr", "state-post.json", "state-pre.json", "stderr",
        "system-post.json", "system-pre.json",
    }
)
BUNDLE_MANIFEST = "BUNDLE-MANIFEST.json"
RECEIPT_FIELDS = frozenset(
    {
        "capability_id", "capability_channel", "company_id", "database_name",
        "database_uuid", "id", "environment", "observed_at", "odoo_instance_id",
        "record_count", "registry_digest", "release_digest", "request_digest",
        "result_digest", "signature", "signature_key_id", "signature_purpose",
        "signature_version", "user_id",
    }
)
AUTH_CONTEXT_FIELDS = frozenset(
    {
        "allowed_company_ids", "audience", "auth_expires_at", "auth_issued_at",
        "auth_key_id", "auth_request_digest", "auth_signature",
        "auth_signature_purpose", "auth_signature_version", "auth_token_id",
        "company_id", "database_name", "database_uuid", "environment",
        "principal", "odoo_instance_id", "user_id",
    }
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_evidence_path(
    evidence: Path, *, expected_parent: Path = EVIDENCE_PARENT,
) -> Path:
    evidence = Path(evidence).absolute()
    expected_parent = Path(expected_parent).absolute()
    require(
        evidence != Path("/")
        and evidence.parent == expected_parent
        and SAFE_BUNDLE_NAME.fullmatch(evidence.name) is not None,
        "evidence path is not a safe direct child of the fixed parent",
    )
    return evidence


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(payload: bytes, *, label: str) -> Any:
    require(len(payload) <= MAX_JSON_BYTES, f"{label} is too large")
    try:
        return json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc


def parse_object(payload: bytes, *, label: str, canonical: bool = False) -> dict[str, Any]:
    value = parse_json(payload, label=label)
    require(isinstance(value, dict), f"{label} must contain a JSON object")
    if canonical:
        require(payload == canonical_json(value) + b"\n", f"{label} is not canonical JSON")
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
        require(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            f"{label} must be a one-link regular file",
        )
        require(
            before.st_size <= maximum and (allow_empty or before.st_size > 0),
            f"{label} size is invalid",
        )
        if expected_uid is not None:
            require(before.st_uid == expected_uid, f"{label} owner is invalid")
        if expected_gid is not None:
            require(before.st_gid == expected_gid, f"{label} group is invalid")
        if expected_mode is not None:
            require(
                stat.S_IMODE(before.st_mode) == expected_mode,
                f"{label} mode is invalid",
            )
        identity = _fingerprint(before)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            require(bool(chunk), f"{label} changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(os.read(descriptor, 1) == b"", f"{label} grew during read")
        require(
            _fingerprint(os.fstat(descriptor)) == identity,
            f"{label} identity changed during read",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _safe_root_chain(path: Path, *, final_mode: int | None = None) -> None:
    current = Path("/")
    for component in path.absolute().parts[1:]:
        current /= component
        metadata = current.lstat()
        require(
            stat.S_ISDIR(metadata.st_mode) and not current.is_symlink(),
            f"unsafe directory in root chain: {current}",
        )
        require(
            (metadata.st_uid, metadata.st_gid) == (0, 0)
            and not stat.S_IMODE(metadata.st_mode) & 0o022
            and bool(stat.S_IMODE(metadata.st_mode) & 0o111),
            f"unsafe owner/mode in root chain: {current}",
        )
    if final_mode is not None:
        require(
            stat.S_IMODE(path.lstat().st_mode) == final_mode,
            f"unexpected fixed directory mode: {path}",
        )


def _fixed_runtime_paths(root: Path = Path("/")) -> dict[str, str]:
    state = (
        f"/var/lib/odoo-accounting-cli-v3-dev15-candidates/{RELEASE}/read-state"
    )
    secrets = f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{RELEASE}"
    values = {
        "auth_state_path": f"{state}/auth/state.sqlite3",
        "receipt_state_path": f"{state}/receipt/state.sqlite3",
        "auth_secret_path": f"{secrets}/auth.hmac",
        "receipt_secret_path": f"{secrets}/receipt.hmac",
    }
    if Path(root).absolute() == Path("/"):
        return values
    return {
        key: str(Path(root).absolute().joinpath(*Path(value).parts[1:]))
        for key, value in values.items()
    }


def validate_runtime(
    runtime: Any, *, expected_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
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
        **(expected_paths or _fixed_runtime_paths()),
    }
    require(isinstance(runtime, dict), "runtime is not an object")
    require(
        set(runtime) == set(expected) | {"auth_key_id", "receipt_key_id"},
        "runtime fields are invalid",
    )
    require(
        all(runtime.get(key) == value for key, value in expected.items()),
        "runtime is not the exact Dev15 binding",
    )
    auth_key = runtime["auth_key_id"]
    receipt_key = runtime["receipt_key_id"]
    require(
        isinstance(auth_key, str) and auth_key.startswith("test-auth-dev15-")
        and isinstance(receipt_key, str)
        and receipt_key.startswith("test-receipt-dev15-")
        and auth_key != receipt_key
        and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", auth_key) is not None
        and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", receipt_key) is not None,
        "runtime key role metadata is invalid",
    )
    return runtime


def load_pinned_plan(
    path: Path = COMMITTED_PLAN, *, enforce_metadata: bool = True,
) -> tuple[dict[str, Any], bytes]:
    payload = stable_read(
        path, label="byte-pinned Dev15 read plan",
        expected_uid=0 if enforce_metadata and os.name == "posix" else None,
        expected_gid=0 if enforce_metadata and os.name == "posix" else None,
        expected_mode=0o444 if enforce_metadata and os.name == "posix" else None,
    )
    require(
        hashlib.sha256(payload).hexdigest() == READ_PLAN_SHA256,
        "Dev15 read plan raw SHA-256 mismatch",
    )
    plan = parse_object(payload, label="byte-pinned Dev15 read plan")
    require(plan.get("schema_version") == 1, "Dev15 plan schema mismatch")
    require(plan.get("capability_id") == CAPABILITY_ID, "Dev15 plan capability mismatch")
    require(plan.get("parameters") == {
        "as_of_date": "2026-07-13", "balance_basis": "posted_ledger_cumulative",
        "company_id": 9, "currency_ids": [6, 1], "limit": 500,
        "off_balance_policy": "exclude", "offset": 0,
    }, "Dev15 plan parameter binding mismatch")
    require(plan.get("database") == {
        "current_user": "postgres", "instance_id": "odoo19@43.165.173.80",
        "name": "odoo_test", "oracle_psql": ORACLE_PSQL,
        "oracle_psql_sha256": ORACLE_PSQL_SHA256,
        "oracle_python": ORACLE_PYTHON,
        "oracle_python_sha256": ORACLE_PYTHON_SHA256,
        "server_version_num": SERVER_VERSION_NUM,
        "system_identifier": SYSTEM_IDENTIFIER,
        "unix_socket_directory": SOCKET_DIRECTORY,
        "unix_socket_path": SOCKET_PATH, "uuid": DATABASE_UUID,
    }, "Dev15 plan database/Oracle executable binding mismatch")
    return plan, payload


def private_secret(
    path: Path, *, expected_uid: int, expected_gid: int,
    expected_mode: int = 0o640,
) -> bytes:
    value = stable_read(
        path, label="Dev15 HMAC secret", maximum=4096,
        expected_uid=expected_uid, expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    require(len(value) == 32, "Dev15 HMAC secret must be exactly 32 bytes")
    return value


def _validate_release_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    require(
        set(manifest) == {"schema_version", "version", "commit", "files", "manifest_sha256"},
        "installed release manifest fields are invalid",
    )
    require(
        manifest["schema_version"] == 1 and manifest["version"] == VERSION
        and manifest["commit"] == COMMIT
        and manifest["manifest_sha256"] == MANIFEST_SHA256,
        "installed release manifest identity mismatch",
    )
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    require(
        hashlib.sha256(canonical_json(unsigned)).hexdigest() == MANIFEST_SHA256,
        "installed release manifest semantic digest mismatch",
    )
    entries = manifest["files"]
    require(isinstance(entries, list) and 0 < len(entries) <= MAX_RELEASE_ENTRIES, "release file manifest is invalid")
    indexed: dict[str, dict[str, Any]] = {}
    for item in entries:
        require(
            isinstance(item, dict) and set(item) == {"path", "sha256", "size"},
            "release member manifest item is invalid",
        )
        name = item["path"]
        portable = PurePosixPath(name) if isinstance(name, str) else PurePosixPath(".")
        require(
            isinstance(name, str) and name not in indexed and name != "RELEASE-MANIFEST.json"
            and not portable.is_absolute() and portable.as_posix() == name
            and name not in {"", "."} and ".." not in portable.parts,
            "release member path is invalid",
        )
        require(
            isinstance(item["sha256"], str) and HEX64.fullmatch(item["sha256"]) is not None
            and type(item["size"]) is int and 0 <= item["size"] <= MAX_RELEASE_FILE_BYTES,
            f"release member metadata is invalid: {name}",
        )
        indexed[name] = item
    return indexed


def _inventory_release() -> tuple[dict[str, Path], set[str]]:
    _safe_root_chain(RELEASE_ROOT, final_mode=0o555)
    files: dict[str, Path] = {}
    directories: set[str] = set()
    pending = [(RELEASE_ROOT, "")]
    entries = 0
    while pending:
        directory, prefix = pending.pop()
        metadata = directory.lstat()
        require(
            stat.S_ISDIR(metadata.st_mode) and not directory.is_symlink()
            and (metadata.st_uid, metadata.st_gid) == (0, 0)
            and stat.S_IMODE(metadata.st_mode) == 0o555,
            f"unsafe installed release directory: {directory}",
        )
        with os.scandir(directory) as iterator:
            children = list(iterator)
        for child in children:
            entries += 1
            require(entries <= MAX_RELEASE_ENTRIES, "installed release has too many entries")
            relative = f"{prefix}/{child.name}" if prefix else child.name
            path = directory / child.name
            child_metadata = child.stat(follow_symlinks=False)
            require(not stat.S_ISLNK(child_metadata.st_mode), f"release symlink is forbidden: {relative}")
            if stat.S_ISDIR(child_metadata.st_mode):
                directories.add(relative)
                pending.append((path, relative))
            elif stat.S_ISREG(child_metadata.st_mode):
                files[relative] = path
            else:
                raise ValueError(f"unsafe release object: {relative}")
    return files, directories


def verify_live_release(runtime: dict[str, Any]) -> None:
    """Verify package, external anchor and every release member without imports."""

    validate_runtime(runtime)
    package = stable_read(
        PACKAGE_PATH, label="canonical Dev15 package", maximum=MAX_RELEASE_BYTES,
        expected_uid=0, expected_gid=0, expected_mode=0o444,
    )
    require(hashlib.sha256(package).hexdigest() == PACKAGE_SHA256, "canonical package digest mismatch")
    anchor_payload = stable_read(
        RELEASE_ANCHOR, label="Dev15 release anchor",
        expected_uid=0, expected_gid=0, expected_mode=0o444,
    )
    anchor = parse_object(anchor_payload, label="Dev15 release anchor")
    require(anchor == {
        "commit": COMMIT, "manifest_sha256": MANIFEST_SHA256,
        "package_sha256": PACKAGE_SHA256, "release": RELEASE,
    }, "Dev15 external release anchor mismatch")
    manifest_payload = stable_read(
        RELEASE_ROOT / "RELEASE-MANIFEST.json", label="installed release manifest",
        expected_uid=0, expected_gid=0, expected_mode=0o444,
    )
    manifest = parse_object(manifest_payload, label="installed release manifest")
    indexed = _validate_release_manifest(manifest)
    files, directories = _inventory_release()
    expected_files = set(indexed) | {"RELEASE-MANIFEST.json"}
    expected_directories: set[str] = set()
    for name in indexed:
        parent = PurePosixPath(name).parent
        while parent.as_posix() != ".":
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    require(set(files) == expected_files, "installed release file set mismatch")
    require(directories == expected_directories, "installed release directory set mismatch")
    for name, item in indexed.items():
        payload = stable_read(
            files[name], label=f"installed release member {name}",
            maximum=MAX_RELEASE_FILE_BYTES, expected_uid=0, expected_gid=0,
            expected_mode=0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444,
            allow_empty=True,
        )
        require(
            len(payload) == item["size"]
            and hashlib.sha256(payload).hexdigest() == item["sha256"],
            f"installed release member mismatch: {name}",
        )


def _verify_toolchain_entries(
    entries: Any, *, names: tuple[str, ...], label: str,
) -> None:
    require(
        isinstance(entries, list)
        and len(entries) == len(names)
        and [item.get("name") for item in entries if isinstance(item, dict)]
        == list(names),
        f"Dev15 {label} order/set mismatch",
    )
    for item in entries:
        require(
            isinstance(item, dict)
            and set(item) == {"name", "sha256", "size"}
            and HEX64.fullmatch(str(item["sha256"])) is not None
            and type(item["size"]) is int and item["size"] > 0,
            f"Dev15 {label} metadata is invalid",
        )
        payload = stable_read(
            TOOLCHAIN_ROOT / item["name"],
            label=f"Dev15 installed toolchain {item['name']}",
            maximum=16 * 1024 * 1024, expected_uid=0, expected_gid=0,
            expected_mode=0o444,
        )
        require(
            len(payload) == item["size"]
            and hashlib.sha256(payload).hexdigest() == item["sha256"],
            f"Dev15 installed toolchain bytes mismatch: {item['name']}",
        )


def verify_toolchain(expected_manifest_sha256: str) -> dict[str, Any]:
    require(
        isinstance(expected_manifest_sha256, str)
        and HEX64.fullmatch(expected_manifest_sha256) is not None,
        "expected toolchain manifest SHA-256 is invalid",
    )
    _safe_root_chain(TOOLCHAIN_ROOT, final_mode=0o555)
    manifest_payload = stable_read(
        TOOLCHAIN_MANIFEST, label="Dev15 toolchain manifest",
        maximum=16 * 1024 * 1024,
        expected_uid=0, expected_gid=0, expected_mode=0o444,
    )
    require(
        hashlib.sha256(manifest_payload).hexdigest() == expected_manifest_sha256,
        "Dev15 toolchain manifest raw SHA-256 mismatch",
    )
    manifest = parse_object(manifest_payload, label="Dev15 toolchain manifest")
    require(
        set(manifest)
        == {"application", "control_files", "files", "schema_version", "toolchain_version"}
        and manifest["schema_version"] == 2
        and manifest["toolchain_version"] == TOOLCHAIN_VERSION,
        "Dev15 toolchain manifest identity is invalid",
    )
    require(manifest["application"] == {
        "commit": COMMIT, "manifest_sha256": MANIFEST_SHA256,
        "package_sha256": PACKAGE_SHA256, "registry_digest": REGISTRY_DIGEST,
        "release": RELEASE, "version": VERSION,
    }, "Dev15 toolchain application binding mismatch")
    _verify_toolchain_entries(
        manifest["files"], names=TOOLCHAIN_FILES, label="toolchain file"
    )
    _verify_toolchain_entries(
        manifest["control_files"], names=TOOLCHAIN_CONTROL_FILES,
        label="toolchain control file",
    )
    expected_names = {
        "TOOLCHAIN-MANIFEST.json", *TOOLCHAIN_FILES, *TOOLCHAIN_CONTROL_FILES,
    }
    require(
        {entry.name for entry in os.scandir(TOOLCHAIN_ROOT)} == expected_names,
        "Dev15 installed toolchain file set is not exact",
    )
    require(
        Path(__file__).absolute() == TOOLCHAIN_ROOT / "verify_evidence.py"
        and not Path(__file__).is_symlink(),
        "verifier is not executing from the fixed Dev15 toolchain",
    )
    return manifest


def read_request_digest(request: dict[str, Any], _receipt: dict[str, Any]) -> str:
    context = request["context"]
    return hashlib.sha256(canonical_json({
        "capability_id": CAPABILITY_ID,
        "auth_token_id": context["auth_token_id"],
        "company_id": 9,
        "environment": "test",
        "database_name": "odoo_test",
        "database_uuid": DATABASE_UUID,
        "parameters": request["parameters"],
        "principal": "pi:test-user-2",
        "capability_channel": "staged",
        "odoo_instance_id": "odoo19@43.165.173.80",
        "registry_digest": REGISTRY_DIGEST,
        "release_digest": MANIFEST_SHA256,
        "user_id": 2,
    })).hexdigest()


def signed_request_replay_digest(request: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(request)).hexdigest()


def audit_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json({
        "event_id": event["event_id"], "event_type": event["event_type"],
        "occurred_at": event["occurred_at"], "operation_id": event["operation_id"],
        "payload_json": event["payload_json"], "previous_hash": event["previous_hash"],
        "sequence": event["sequence"],
    })).hexdigest()


def _utc(value: Any, label: str, *, zulu: bool = False) -> datetime:
    require(isinstance(value, str) and value, f"{label} is invalid")
    if zulu:
        require(value.endswith("Z"), f"{label} is not canonical UTC Z form")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, f"{label} is not timezone-aware")
    require(parsed.utcoffset().total_seconds() == 0, f"{label} is not UTC")
    return parsed.astimezone(timezone.utc)


def verify_auth(
    request: dict[str, Any], runtime: dict[str, Any], auth_secret: bytes,
) -> tuple[datetime, datetime]:
    require(set(request) == {"capability_id", "context", "parameters"}, "signed request fields are invalid")
    require(request["capability_id"] == CAPABILITY_ID, "signed request capability mismatch")
    context = request["context"]
    require(isinstance(context, dict) and set(context) == AUTH_CONTEXT_FIELDS, "auth context fields are invalid")
    expected = {
        "allowed_company_ids": [9], "audience": "odoo-accounting-cli-v3",
        "auth_key_id": runtime["auth_key_id"], "auth_signature_purpose": "auth_context_v1",
        "auth_signature_version": 1, "company_id": 9, "database_name": "odoo_test",
        "database_uuid": DATABASE_UUID, "environment": "test",
        "principal": "pi:test-user-2", "odoo_instance_id": "odoo19@43.165.173.80",
        "user_id": 2,
    }
    require(all(context.get(key) == value for key, value in expected.items()), "authenticated request identity mismatch")
    token = context["auth_token_id"]
    require(
        isinstance(token, str) and re.fullmatch(
            r"dev15-multicurrency-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", token,
        ) is not None,
        "auth token ID is not a Dev15 UUIDv4",
    )
    expected_digest = hashlib.sha256(canonical_json({
        "capability_id": CAPABILITY_ID, "parameters": request["parameters"],
    })).hexdigest()
    require(context["auth_request_digest"] == expected_digest, "auth request digest mismatch")
    require(HEX64.fullmatch(str(context["auth_signature"])) is not None, "auth signature format is invalid")
    unsigned = {key: value for key, value in context.items() if key != "auth_signature"}
    signature = hmac.new(auth_secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
    require(hmac.compare_digest(signature, context["auth_signature"]), "auth HMAC mismatch")
    issued = _utc(context["auth_issued_at"], "auth issued_at")
    expires = _utc(context["auth_expires_at"], "auth expires_at")
    require((expires - issued).total_seconds() == 240, "auth TTL is not exactly four minutes")
    return issued, expires


def verify_receipt(
    request: dict[str, Any], result: dict[str, Any], runtime: dict[str, Any],
    receipt_secret: bytes,
) -> tuple[dict[str, Any], datetime]:
    receipt = result.get("receipt")
    require(isinstance(receipt, dict) and set(receipt) == RECEIPT_FIELDS, "receipt fields are invalid")
    expected = {
        "capability_id": CAPABILITY_ID, "capability_channel": "staged",
        "company_id": 9, "database_name": "odoo_test", "database_uuid": DATABASE_UUID,
        "environment": "test", "odoo_instance_id": "odoo19@43.165.173.80",
        "registry_digest": REGISTRY_DIGEST, "release_digest": MANIFEST_SHA256,
        "signature_key_id": runtime["receipt_key_id"],
        "signature_purpose": "read_receipt_v2", "signature_version": 2, "user_id": 2,
    }
    require(all(receipt.get(key) == value for key, value in expected.items()), "receipt binding mismatch")
    require(isinstance(receipt["id"], str) and 0 < len(receipt["id"]) <= 256, "receipt ID is invalid")
    require(receipt["request_digest"] == read_request_digest(request, receipt), "receipt request digest mismatch")
    body = {key: value for key, value in result.items() if key != "receipt"}
    require(
        receipt["result_digest"] == hashlib.sha256(canonical_json(body)).hexdigest(),
        "receipt result digest mismatch",
    )
    page = result.get("page")
    require(isinstance(page, dict) and receipt["record_count"] == page.get("total_count"), "receipt record count mismatch")
    require(all(HEX64.fullmatch(str(receipt[field])) is not None for field in ("request_digest", "result_digest", "registry_digest", "release_digest", "signature")), "receipt digest format is invalid")
    unsigned = {key: value for key, value in receipt.items() if key != "signature"}
    signature = hmac.new(receipt_secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
    require(hmac.compare_digest(signature, receipt["signature"]), "receipt HMAC mismatch")
    observed = _utc(receipt["observed_at"], "receipt observed_at", zulu=True)
    return receipt, observed


def _one(snapshot: dict[str, Any], store: str, query: str) -> dict[str, Any] | None:
    rows = snapshot[store]["queries"].get(query, [])
    require(isinstance(rows, list) and len(rows) <= 1, f"invalid {store}.{query} snapshot")
    return rows[0] if rows else None


def _count(snapshot: dict[str, Any], store: str, query: str) -> int:
    row = _one(snapshot, store, query)
    if row is None:
        return 0
    require(row is not None and set(row) == {"value"} and type(row["value"]) is int, f"invalid {store}.{query} count")
    return row["value"]


def verify_state(
    before: dict[str, Any], after: dict[str, Any], request: dict[str, Any],
    receipt: dict[str, Any], runtime: dict[str, Any],
    issued: datetime, expires: datetime, observed: datetime,
    *, expected_state_uid: int | None = None,
    expected_state_gid: int | None = None,
) -> None:
    for snapshot, post in ((before, False), (after, True)):
        require(set(snapshot) == {"auth_state_path", "receipt_state_path", "auth", "receipt"}, "state snapshot fields are invalid")
        require(snapshot["auth_state_path"] == runtime["auth_state_path"] and snapshot["receipt_state_path"] == runtime["receipt_state_path"], "state snapshot path binding mismatch")
        for store, state_key, expected_parent in (
            (snapshot["auth"], "auth", str(Path(runtime["auth_state_path"]).parent)),
            (snapshot["receipt"], "receipt", str(Path(runtime["receipt_state_path"]).parent)),
        ):
            require(
                isinstance(store, dict)
                and set(store) == {"exists", "parent", "database", "queries"}
                and type(store["exists"]) is bool
                and isinstance(store["queries"], dict),
                f"{state_key} state fields are invalid",
            )
            parent = store["parent"]
            require(
                isinstance(parent, dict)
                and set(parent)
                == {"path", "exists", "kind", "mode", "uid", "gid", "device", "inode"}
                and parent["path"] == expected_parent
                and parent["exists"] is True
                and parent["kind"] == "directory"
                and parent["mode"] == "0700"
                and type(parent["uid"]) is int and parent["uid"] >= 0
                and type(parent["gid"]) is int and parent["gid"] >= 0
                and type(parent["device"]) is int and parent["device"] > 0
                and type(parent["inode"]) is int and parent["inode"] > 0,
                f"{state_key} state parent is not odoo-owned mode 0700",
            )
            if expected_state_uid is not None:
                require(parent["uid"] == expected_state_uid, f"{state_key} state parent UID mismatch")
            if expected_state_gid is not None:
                require(parent["gid"] == expected_state_gid, f"{state_key} state parent GID mismatch")
            database = store["database"]
            if store["exists"]:
                expected_database_path = runtime[f"{state_key}_state_path"]
                require(
                    isinstance(database, dict)
                    and set(database)
                    == {
                        "path", "kind", "mode", "uid", "gid", "device", "inode",
                        "links", "size", "mtime_ns", "ctime_ns",
                    }
                    and database["path"] == expected_database_path
                    and database["kind"] == "regular_file"
                    and database["mode"] == "0600"
                    and database["uid"] == parent["uid"]
                    and database["gid"] == parent["gid"]
                    and type(database["device"]) is int and database["device"] > 0
                    and type(database["inode"]) is int and database["inode"] > 0
                    and type(database["links"]) is int and database["links"] == 1
                    and type(database["size"]) is int and database["size"] > 0
                    and type(database["mtime_ns"]) is int and database["mtime_ns"] >= 0
                    and type(database["ctime_ns"]) is int and database["ctime_ns"] >= 0,
                    f"{state_key} SQLite database identity is invalid",
                )
            else:
                require(database is None, f"absent {state_key} SQLite database has identity")
        require(
            snapshot["auth"]["parent"] == before["auth"]["parent"]
            and snapshot["receipt"]["parent"] == before["receipt"]["parent"],
            "state parent identity changed during read",
        )
        require(
            snapshot["auth"]["parent"]["uid"]
            == snapshot["receipt"]["parent"]["uid"]
            and snapshot["auth"]["parent"]["gid"]
            == snapshot["receipt"]["parent"]["gid"],
            "auth/receipt state parents are not the same odoo identity",
        )
        if post:
            require(
                snapshot["auth"]["exists"] is True
                and snapshot["receipt"]["exists"] is True,
                "post-read SQLite state was not durably created",
            )
        require(
            set(snapshot["auth"]["queries"])
            == ({"count", "token"} if snapshot["auth"]["exists"] else set()),
            "auth state query set mismatch",
        )
        expected_receipt_queries: set[str] = set()
        if snapshot["receipt"]["exists"]:
            expected_receipt_queries = {"receipt_count", "audit_count", "audit_head"}
            if post:
                expected_receipt_queries |= {"receipt", "audit_event"}
        require(
            set(snapshot["receipt"]["queries"]) == expected_receipt_queries,
            "receipt state query set mismatch",
        )
    for state_key in ("auth", "receipt"):
        if before[state_key]["exists"]:
            require(after[state_key]["exists"], f"{state_key} SQLite database disappeared")
            for field in ("path", "kind", "mode", "uid", "gid", "device", "inode", "links"):
                require(
                    after[state_key]["database"][field]
                    == before[state_key]["database"][field],
                    f"{state_key} SQLite database identity changed during read",
                )
    require(_one(before, "auth", "token") is None, "auth token already existed before request")
    require(_count(after, "auth", "count") == _count(before, "auth", "count") + 1, "auth state delta mismatch")
    require(_count(after, "receipt", "receipt_count") == _count(before, "receipt", "receipt_count") + 1, "receipt state delta mismatch")
    require(_count(after, "receipt", "audit_count") == _count(before, "receipt", "audit_count") + 1, "audit state delta mismatch")
    token = _one(after, "auth", "token")
    stored = _one(after, "receipt", "receipt")
    event = _one(after, "receipt", "audit_event")
    require(token is not None and set(token) == {"token_id", "request_digest", "expires_at", "consumed_at"}, "consumed auth token fields are invalid")
    require(token["token_id"] == request["context"]["auth_token_id"], "consumed auth token missing")
    require(token["request_digest"] == signed_request_replay_digest(request), "consumed full signed-request digest mismatch")
    require(_utc(token["expires_at"], "stored auth expiry") == expires, "stored auth expiry mismatch")
    token_consumed = _utc(token["consumed_at"], "auth consumed_at")
    require(issued <= token_consumed <= expires, "auth consumption escaped validity window")
    require(stored is not None and set(stored) == {"receipt_id", "request_digest", "observed_at", "consumed_at"}, "stored receipt fields are invalid")
    require(stored["receipt_id"] == receipt["id"] and stored["request_digest"] == receipt["request_digest"], "consumed receipt binding mismatch")
    require(_utc(stored["observed_at"], "stored receipt observed_at") == observed, "stored receipt observed time mismatch")
    receipt_consumed = _utc(stored["consumed_at"], "receipt consumed_at")
    require(observed <= receipt_consumed <= expires, "receipt consumption escaped auth validity window")
    require(event is not None and set(event) == {"sequence", "event_id", "event_type", "operation_id", "occurred_at", "payload_json", "previous_hash", "event_hash"}, "audit event fields are invalid")
    require(event["event_id"] == f"read:{receipt['id']}" and event["event_type"] == "read.verified" and event["operation_id"] is None, "verified read audit event missing")
    require(_utc(event["occurred_at"], "audit occurred_at") == observed, "audit time mismatch")
    head = _one(before, "receipt", "audit_head")
    expected_previous = GENESIS_HASH if head is None else head["event_hash"]
    expected_sequence = 1 if head is None else head["sequence"] + 1
    require(event["sequence"] == expected_sequence and event["previous_hash"] == expected_previous, "audit chain predecessor mismatch")
    require(event["event_hash"] == audit_hash(event), "audit event hash mismatch")
    payload = parse_object(event["payload_json"].encode("utf-8"), label="audit payload")
    require(canonical_json(payload).decode("utf-8") == event["payload_json"], "audit payload is not canonical")
    require(payload == {
        "auth_token_id": request["context"]["auth_token_id"],
        "capability_id": CAPABILITY_ID, "capability_channel": "staged",
        "company_id": 9, "environment": "test", "database_name": "odoo_test",
        "database_uuid": DATABASE_UUID, "odoo_instance_id": "odoo19@43.165.173.80",
        "principal": "pi:test-user-2", "receipt": receipt, "receipt_id": receipt["id"],
        "registry_digest": REGISTRY_DIGEST, "release_digest": MANIFEST_SHA256,
        "request_digest": receipt["request_digest"],
        "result_digest": receipt["result_digest"], "user_id": 2,
    }, "audit payload full binding mismatch")
    post_head = _one(after, "receipt", "audit_head")
    require(post_head == {"sequence": event["sequence"], "event_hash": event["event_hash"]}, "audit head mismatch")


def _decimal(value: Any, label: str, *, positive: bool = False) -> Decimal:
    require(isinstance(value, str), f"{label} is not a decimal string")
    try:
        result = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    require(result.is_finite() and (not positive or result > 0), f"{label} is invalid")
    return result


def _rate_equal(left: Decimal, right: Decimal) -> bool:
    tolerance = max(abs(left), abs(right)) * RATE_TOLERANCE
    return abs(left - right) <= tolerance


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "balance_group_count": len(rows),
        "account_count": len({row["account_id"] for row in rows}),
        "move_line_count": sum(row["move_line_count"] for row in rows),
        "ledger_company_balance": sum(
            (_decimal(row["ledger_company_balance"], "balance amount") for row in rows),
            Decimal("0"),
        ),
    }


def _verify_summary(actual: Any, rows: list[dict[str, Any]], label: str) -> None:
    require(isinstance(actual, dict) and set(actual) == {"balance_group_count", "account_count", "move_line_count", "ledger_company_balance"}, f"{label} fields are invalid")
    expected = _summary(rows)
    for key in ("balance_group_count", "account_count", "move_line_count"):
        require(actual[key] == expected[key], f"{label} {key} mismatch")
    require(_decimal(actual["ledger_company_balance"], f"{label} amount") == expected["ledger_company_balance"], f"{label} amount mismatch")


def _verify_rate_source(source: Any, *, currency: dict[str, Any], allow_identity: bool) -> Decimal:
    require(isinstance(source, dict) and set(source) == {"currency_id", "currency_name", "effective_date", "source_model", "source_scope", "source_company_id", "source_record_id", "odoo_technical_rate"}, "technical rate source fields are invalid")
    require(source["currency_id"] == currency["id"] and source["currency_name"] == currency["name"], "technical source currency mismatch")
    rate = _decimal(source["odoo_technical_rate"], "technical rate", positive=True)
    if source["source_scope"] == "no_rate_identity":
        require(
            allow_identity and source == {
                "currency_id": currency["id"], "currency_name": currency["name"],
                "effective_date": None, "source_model": "no_rate_identity",
                "source_scope": "no_rate_identity", "source_company_id": None,
                "source_record_id": None, "odoo_technical_rate": "1",
            },
            "no-rate identity source is invalid",
        )
    else:
        require(source["source_scope"] in {"company_specific", "global"} and source["source_model"] == "res.currency.rate", "technical rate source model/scope mismatch")
        require(isinstance(source["source_record_id"], int) and source["source_record_id"] > 0, "technical rate record ID is invalid")
        _utc(f"{source['effective_date']}T00:00:00+00:00", "rate effective date")
        require(source["effective_date"] <= "2026-07-13", "technical rate is after cutoff")
        if source["source_scope"] == "company_specific":
            require(source["source_company_id"] == 9, "company-specific rate source mismatch")
        else:
            require(source["source_company_id"] is None, "global rate claimed a company")
    return rate


def verify_golden_and_oracle(
    plan: dict[str, Any], request: dict[str, Any], result: dict[str, Any],
    oracle: dict[str, Any],
) -> None:
    expected = plan["expected"]
    require(
        isinstance(expected, dict)
        and set(expected)
        == {"balances", "company_currency", "currency_summaries", "ledger_summary", "rates"},
        "plan golden fields are invalid",
    )
    require(request["parameters"] == plan["parameters"], "plan/request parameter roundtrip mismatch")
    require(set(result) == {"basis", "filters", "balances", "page", "page_summary", "ledger_summary", "currency_summaries", "rates", "company_currency", "receipt"}, "multicurrency result fields are invalid")
    require(result["basis"] == "odoo_posted_aml_booked_amounts_no_cutoff_revaluation", "multicurrency basis mismatch")
    require(result["filters"] == {key: plan["parameters"][key] for key in ("company_id", "as_of_date", "currency_ids", "balance_basis", "off_balance_policy")}, "result filter roundtrip mismatch")

    expected_company_currency = expected["company_currency"]
    require(
        isinstance(expected_company_currency, dict)
        and set(expected_company_currency) == {"id", "name"},
        "plan company currency golden is invalid",
    )
    company_currency = result["company_currency"]
    require(isinstance(company_currency, dict) and set(company_currency) == {"id", "name", "symbol", "rounding"}, "company currency fields are invalid")
    require(
        company_currency["id"] == expected_company_currency["id"]
        and company_currency["name"] == expected_company_currency["name"]
        and _decimal(company_currency["rounding"], "company rounding", positive=True)
        == Decimal("0.01"),
        "company currency mismatch",
    )

    balances = result["balances"]
    expected_balances = expected["balances"]
    require(
        isinstance(balances, list)
        and isinstance(expected_balances, list)
        and len(balances) == len(expected_balances) == 3,
        "golden balance group count mismatch",
    )
    balance_fields = {"account_id", "account_code", "account_name", "account_type", "currency_id", "currency_name", "company_currency_id", "company_currency_name", "ledger_company_balance", "ledger_transaction_amount", "move_line_count"}
    expected_balance_fields = balance_fields - {"account_name"}
    groups: set[tuple[int, int]] = set()
    for balance, golden in zip(balances, expected_balances):
        require(isinstance(balance, dict) and set(balance) == balance_fields, "balance fields are invalid")
        require(
            isinstance(golden, dict) and set(golden) == expected_balance_fields,
            "plan balance golden fields are invalid",
        )
        group = (balance["account_id"], balance["currency_id"])
        require(group not in groups, "balance group is duplicated")
        groups.add(group)
        require(type(balance["account_id"]) is int and balance["account_id"] > 0 and isinstance(balance["account_code"], str) and balance["account_code"] and isinstance(balance["account_name"], str) and balance["account_name"], "account identity is invalid")
        for key in expected_balance_fields - {"ledger_company_balance", "ledger_transaction_amount"}:
            require(balance[key] == golden[key], f"golden balance {key} mismatch")
        require(
            balance["currency_id"] in plan["parameters"]["currency_ids"]
            and balance["company_currency_id"] == expected_company_currency["id"]
            and balance["company_currency_name"] == expected_company_currency["name"],
            "balance currency binding mismatch",
        )
        require(type(balance["move_line_count"]) is int and balance["move_line_count"] > 0, "balance move-line count is invalid")
        company_amount = _decimal(balance["ledger_company_balance"], "ledger company balance")
        transaction_amount = _decimal(balance["ledger_transaction_amount"], "ledger transaction amount")
        require(company_amount == _decimal(golden["ledger_company_balance"], "golden company balance"), "golden company balance mismatch")
        require(transaction_amount == _decimal(golden["ledger_transaction_amount"], "golden transaction amount"), "golden transaction amount mismatch")
        if balance["currency_id"] == expected_company_currency["id"]:
            require(company_amount == transaction_amount, "company-currency booked amounts disagree")
    expected_order = sorted(balances, key=lambda item: (item["account_code"], item["account_id"], [6, 1].index(item["currency_id"])))
    require(balances == expected_order, "balance ordering is not deterministic")
    require(
        [(item["account_id"], item["currency_id"]) for item in balances]
        == [(item["account_id"], item["currency_id"]) for item in expected_balances],
        "balance golden ordering mismatch",
    )
    page = result["page"]
    require(page == {"limit": plan["parameters"]["limit"], "offset": plan["parameters"]["offset"], "count": 3, "total_count": 3}, "pagination/count mismatch")
    _verify_summary(result["page_summary"], balances, "page summary")
    _verify_summary(result["ledger_summary"], balances, "ledger summary")
    expected_ledger = expected["ledger_summary"]
    require(
        isinstance(expected_ledger, dict)
        and set(expected_ledger)
        == {"balance_group_count", "account_count", "move_line_count", "ledger_company_balance"},
        "plan ledger summary golden fields are invalid",
    )
    for summary_name in ("page_summary", "ledger_summary"):
        actual_summary = result[summary_name]
        for key in ("balance_group_count", "account_count", "move_line_count"):
            require(actual_summary[key] == expected_ledger[key], f"golden {summary_name} {key} mismatch")
        require(
            _decimal(actual_summary["ledger_company_balance"], f"golden {summary_name} amount")
            == _decimal(expected_ledger["ledger_company_balance"], "plan ledger amount"),
            f"golden {summary_name} amount mismatch",
        )

    summaries = result["currency_summaries"]
    expected_summaries = expected["currency_summaries"]
    summary_fields = {"currency_id", "currency_name", "currency_symbol", "currency_rounding", "ledger_company_balance", "ledger_transaction_amount", "account_count", "move_line_count"}
    expected_summary_fields = summary_fields - {"currency_symbol", "currency_rounding"}
    require(
        isinstance(summaries, list)
        and isinstance(expected_summaries, list)
        and len(summaries) == len(expected_summaries) == 2
        and [item.get("currency_id") for item in summaries if isinstance(item, dict)]
        == plan["parameters"]["currency_ids"],
        "currency summaries do not cover request order",
    )
    for summary, golden in zip(summaries, expected_summaries):
        require(isinstance(summary, dict) and set(summary) == summary_fields, "currency summary fields are invalid")
        require(isinstance(golden, dict) and set(golden) == expected_summary_fields, "plan currency summary golden fields are invalid")
        selected = [item for item in balances if item["currency_id"] == summary["currency_id"]]
        require(summary["account_count"] == len({item["account_id"] for item in selected}) and summary["move_line_count"] == sum(item["move_line_count"] for item in selected), "currency summary counts mismatch")
        require(_decimal(summary["ledger_company_balance"], "currency company total") == sum((_decimal(item["ledger_company_balance"], "balance") for item in selected), Decimal("0")), "currency company total mismatch")
        require(_decimal(summary["ledger_transaction_amount"], "currency transaction total") == sum((_decimal(item["ledger_transaction_amount"], "amount") for item in selected), Decimal("0")), "currency transaction total mismatch")
        for key in expected_summary_fields - {"ledger_company_balance", "ledger_transaction_amount"}:
            require(summary[key] == golden[key], f"golden currency summary {key} mismatch")
        require(_decimal(summary["ledger_company_balance"], "golden currency company total") == _decimal(golden["ledger_company_balance"], "plan currency company total"), "golden currency company total mismatch")
        require(_decimal(summary["ledger_transaction_amount"], "golden currency transaction total") == _decimal(golden["ledger_transaction_amount"], "plan currency transaction total"), "golden currency transaction total mismatch")

    rates = result["rates"]
    expected_rates = expected["rates"]
    rate_fields = {"currency_id", "currency_name", "company_currency_id", "company_currency_name", "as_of_date", "direction", "formula", "transaction_technical_source", "company_technical_source", "transaction_to_company_rate", "company_to_transaction_rate"}
    require(
        isinstance(rates, list)
        and isinstance(expected_rates, list)
        and len(rates) == len(expected_rates) == 2
        and [item.get("currency_id") for item in rates if isinstance(item, dict)]
        == plan["parameters"]["currency_ids"],
        "rates do not cover request order",
    )
    catalog_by_id = {
        summary["currency_id"]: {"id": summary["currency_id"], "name": summary["currency_name"]}
        for summary in summaries
    }
    for rate, golden in zip(rates, expected_rates):
        require(isinstance(rate, dict) and set(rate) == rate_fields, "rate fields are invalid")
        expected_rate_fields = {
            "currency_id", "currency_name", "source_company_id", "source_record_id",
            "source_scope", "technical_rate", "transaction_to_company_rate",
            "company_to_transaction_rate",
        }
        if golden.get("source_scope") != "no_rate_identity":
            expected_rate_fields.add("effective_date")
        require(isinstance(golden, dict) and set(golden) == expected_rate_fields, "plan rate golden fields are invalid")
        require(rate["company_currency_id"] == expected_company_currency["id"] and rate["company_currency_name"] == expected_company_currency["name"] and rate["as_of_date"] == plan["parameters"]["as_of_date"] and rate["direction"] == "transaction_currency_to_company_currency" and rate["formula"] == "company_technical_rate / transaction_technical_rate", "rate metadata mismatch")
        currency = catalog_by_id[rate["currency_id"]]
        require(rate["currency_id"] == golden["currency_id"] and rate["currency_name"] == currency["name"] == golden["currency_name"], "rate currency name mismatch")
        transaction_source = rate["transaction_technical_source"]
        transaction_technical = _verify_rate_source(transaction_source, currency=currency, allow_identity=rate["currency_id"] == expected_company_currency["id"])
        company_technical = _verify_rate_source(rate["company_technical_source"], currency=company_currency, allow_identity=True)
        forward = _decimal(rate["transaction_to_company_rate"], "forward rate", positive=True)
        reverse = _decimal(rate["company_to_transaction_rate"], "reverse rate", positive=True)
        require(_rate_equal(forward, company_technical / transaction_technical), "forward rate/technical-source identity mismatch")
        require(_rate_equal(reverse, Decimal("1") / forward) and _rate_equal(forward * reverse, Decimal("1")), "bidirectional rate identity mismatch")
        require(_rate_equal(forward, _decimal(golden["transaction_to_company_rate"], "golden forward rate", positive=True)), "golden forward rate mismatch")
        require(_rate_equal(reverse, _decimal(golden["company_to_transaction_rate"], "golden reverse rate", positive=True)), "golden reverse rate mismatch")
        for source_key in ("source_company_id", "source_record_id", "source_scope"):
            require(transaction_source[source_key] == golden[source_key], f"golden rate {source_key} mismatch")
        require(_decimal(transaction_source["odoo_technical_rate"], "golden technical rate", positive=True) == _decimal(golden["technical_rate"], "plan technical rate", positive=True), "golden technical rate mismatch")
        require(transaction_source["effective_date"] == golden.get("effective_date"), "golden rate effective date mismatch")
        if rate["currency_id"] == expected_company_currency["id"]:
            require(rate["transaction_technical_source"] == rate["company_technical_source"] and forward == reverse == Decimal("1"), "company-currency identity rate mismatch")
        else:
            require(rate["company_technical_source"] == rates[0]["transaction_technical_source"], "company technical source is not the company-currency identity source")

    require(set(oracle) == {"schema_version", "capability_id", "database", "endpoint", "parameters", "transaction", "executables", "company_hierarchy", "company_currency", "currency_catalog", "balances", "rates"} and oracle["schema_version"] == 2 and oracle["capability_id"] == CAPABILITY_ID and oracle["parameters"] == request["parameters"], "oracle envelope/parameter binding mismatch")
    require(oracle["database"] == {"current_database": "odoo_test", "current_user": "postgres", "database_uuid": DATABASE_UUID, "server_version_num": SERVER_VERSION_NUM, "system_identifier": SYSTEM_IDENTIFIER}, "oracle database identity mismatch")
    endpoint = oracle["endpoint"]
    require(endpoint == {"inet_server_addr": None, "inet_server_port": None, "kind": "unix_socket", "requested_directory": SOCKET_DIRECTORY, "socket_path": SOCKET_PATH, "unix_socket_directories": SOCKET_DIRECTORY}, "oracle Unix-socket endpoint mismatch")
    require(oracle["transaction"] == {"isolation": "repeatable read", "read_only": "on", "rollback_completed": True}, "oracle was not rolled-back REPEATABLE READ/READ ONLY")
    require(oracle["executables"] == {
        "python": {
            "path": ORACLE_PYTHON, "sha256": ORACLE_PYTHON_SHA256,
            "uid": 0, "gid": 0, "mode": "0755",
        },
        "psql": {
            "path": ORACLE_PSQL, "sha256": ORACLE_PSQL_SHA256,
            "uid": 0, "gid": 0, "mode": "0755",
        },
    }, "oracle fixed executable evidence mismatch")
    hierarchy = oracle["company_hierarchy"]
    require(
        isinstance(hierarchy, dict)
        and set(hierarchy) == {"company_id", "parent_path", "root_company_id"}
        and hierarchy["company_id"] == plan["company_id"]
        and hierarchy["root_company_id"] == plan["company_id"]
        and isinstance(hierarchy["parent_path"], str)
        and re.fullmatch(r"(?:[1-9][0-9]*/)+", hierarchy["parent_path"]) is not None
        and int(hierarchy["parent_path"].split("/", 1)[0]) == hierarchy["root_company_id"],
        "oracle company hierarchy/root derivation mismatch",
    )
    oracle_company_currency = oracle["company_currency"]
    require(
        isinstance(oracle_company_currency, dict)
        and set(oracle_company_currency) == {"id", "name", "symbol", "rounding"}
        and all(
            oracle_company_currency[key] == company_currency[key]
            for key in ("id", "name", "symbol")
        )
        and _decimal(oracle_company_currency["rounding"], "oracle company rounding", positive=True)
        == _decimal(company_currency["rounding"], "result company rounding", positive=True),
        "oracle company currency mismatch",
    )
    catalog = oracle["currency_catalog"]
    require(isinstance(catalog, list) and [item.get("id") for item in catalog if isinstance(item, dict)] == [6, 1], "oracle currency catalog mismatch")
    for item, summary in zip(catalog, summaries):
        require(set(item) == {"id", "name", "symbol", "rounding"} and item["id"] == summary["currency_id"] and item["name"] == summary["currency_name"] and item["symbol"] == summary["currency_symbol"] and _decimal(item["rounding"], "oracle rounding") == _decimal(summary["currency_rounding"], "summary rounding"), "oracle/summary currency metadata mismatch")
    oracle_balances = oracle["balances"]
    require(isinstance(oracle_balances, list) and len(oracle_balances) == len(balances), "oracle balance group count mismatch")
    for actual, independent in zip(balances, oracle_balances):
        require(set(independent) == {"account_id", "account_code", "account_type", "currency_id", "currency_name", "ledger_company_balance", "ledger_transaction_amount", "move_line_count"}, "oracle balance fields are invalid")
        for field in ("account_id", "account_code", "account_type", "currency_id", "currency_name", "move_line_count"):
            require(independent[field] == actual[field], f"oracle balance {field} mismatch")
        require(_decimal(independent["ledger_company_balance"], "oracle company amount") == _decimal(actual["ledger_company_balance"], "result company amount") and _decimal(independent["ledger_transaction_amount"], "oracle transaction amount") == _decimal(actual["ledger_transaction_amount"], "result transaction amount"), "oracle booked amount mismatch")
    oracle_rates = oracle["rates"]
    require(isinstance(oracle_rates, list) and [item.get("currency_id") for item in oracle_rates if isinstance(item, dict)] == plan["parameters"]["currency_ids"], "oracle rate coverage mismatch")
    for actual, independent in zip(rates, oracle_rates):
        require(set(independent) == {"currency_id", "company_currency_id", "transaction_source", "company_source", "transaction_to_company_rate", "company_to_transaction_rate"} and independent["currency_id"] == actual["currency_id"] and independent["company_currency_id"] == 6, "oracle rate fields/binding mismatch")
        for oracle_source, result_source in ((independent["transaction_source"], actual["transaction_technical_source"]), (independent["company_source"], actual["company_technical_source"])):
            require(set(oracle_source) == {"effective_date", "source_company_id", "source_record_id", "source_scope", "technical_rate"}, "oracle source fields are invalid")
            for field in ("effective_date", "source_company_id", "source_record_id", "source_scope"):
                require(oracle_source[field] == result_source[field], f"oracle rate source {field} mismatch")
            require(_decimal(oracle_source["technical_rate"], "oracle technical rate") == _decimal(result_source["odoo_technical_rate"], "result technical rate"), "oracle technical rate mismatch")
        require(_rate_equal(_decimal(independent["transaction_to_company_rate"], "oracle forward"), _decimal(actual["transaction_to_company_rate"], "result forward")) and _rate_equal(_decimal(independent["company_to_transaction_rate"], "oracle reverse"), _decimal(actual["company_to_transaction_rate"], "result reverse")), "oracle bidirectional conversion mismatch")


def verify_system_snapshots(plan: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> None:
    require(before == after, "V2/Pi/Odoo/V3 system identity changed during read")
    require(set(before) == {"schema_version", "v2", "pi_bridge_control", "services", "v3"} and before["schema_version"] == 1, "system snapshot fields are invalid")
    baseline = plan["system_baseline"]
    v2 = before["v2"]
    require(set(v2) == {"trees", "combined_algorithm", "combined_count", "combined_digest", "expected_combined_digest", "historical_digest"}, "V2 snapshot fields are invalid")
    require(
        v2["combined_count"] == baseline["v2_combined_count"] == 668
        and v2["combined_digest"] == baseline["v2_combined_digest"]
        and v2["expected_combined_digest"] == baseline["v2_combined_digest"]
        and v2["historical_digest"] == baseline["historical_v2_digest"],
        "V2 exact baseline digest/count mismatch",
    )
    trees = v2["trees"]
    require(isinstance(trees, list) and len(trees) == len(baseline["v2_components"]), "V2 source component count mismatch")
    for tree, expected_tree in zip(trees, baseline["v2_components"]):
        require(
            set(tree) == {"component", "root", "algorithm", "count", "paths", "digest"}
            and tree["component"] == expected_tree["component"]
            and tree["root"] == expected_tree["root"]
            and tree["count"] == expected_tree["count"]
            and tree["digest"] == expected_tree["digest"]
            and isinstance(tree["paths"], list)
            and len(tree["paths"]) == tree["count"]
            and tree["paths"] == sorted(set(tree["paths"])),
            "V2 exact component evidence is invalid",
        )
    pi = before["pi_bridge_control"]
    require(
        isinstance(pi, dict)
        and set(pi) == {"algorithm", "count", "digest", "entries", "roots"}
        and pi["count"] == 5
        and pi["digest"] == baseline["pi_bridge_control_digest"]
        and pi["entries"] == baseline["pi_bridge_control_entries"],
        "Pi Bridge exact five-file control baseline mismatch",
    )
    require(pi["roots"] == baseline["pi_bridge_control_roots"], "Pi Bridge control roots mismatch")
    services = before["services"]
    require(isinstance(services, list) and [item.get("unit") for item in services if isinstance(item, dict)] == baseline["services"], "service identity scope mismatch")
    for service in services:
        props = service.get("properties")
        require(isinstance(props, dict) and props.get("LoadState") == "loaded" and props.get("ActiveState") == "active" and props.get("SubState") == "running" and str(props.get("MainPID", "")).isdigit() and int(props["MainPID"]) > 0 and props.get("FragmentPath"), "baseline service identity is invalid")
    v3 = before["v3"]
    require(
        isinstance(v3, dict) and set(v3) == {"current", "unit_files", "residue"}
        and v3["current"]
        == {"path": "/opt/odoo-accounting-cli-v3/current", "absent": True},
        "V3 current routing absence mismatch",
    )
    units = v3["unit_files"]
    require(
        isinstance(units, list) and len(units) == len(baseline["v3_unit_files"]),
        "V3 systemd unit evidence count mismatch",
    )
    for unit, path in zip(units, baseline["v3_unit_files"]):
        name = Path(path).name
        require(
            unit == {
                "path": path,
                "file_absent": True,
                "unit": name,
                "properties": {
                    "Id": name, "Names": name, "LoadState": "not-found",
                    "ActiveState": "inactive", "SubState": "dead",
                    "FragmentPath": "", "SourcePath": "",
                    "UnitFileState": "", "UnitFilePreset": "",
                },
            },
            "V3 systemd unit is present, loaded, or aliased",
        )
    residue = v3["residue"]
    require(
        isinstance(residue, dict)
        and set(residue) == {
            "prefix", "loaded_units", "unit_files", "systemd_analyze_unit_paths",
            "supplemental_paths", "requested_paths", "absent_roots", "roots",
            "filesystem_residue",
        }
        and residue["prefix"] == V3_UNIT_PREFIX
        and residue["loaded_units"] == []
        and residue["unit_files"] == []
        and residue["filesystem_residue"] == [],
        "V3-prefixed systemd residue is present or evidence is invalid",
    )
    analyzed_paths = residue["systemd_analyze_unit_paths"]
    supplemental_paths = residue["supplemental_paths"]
    requested_paths = residue["requested_paths"]
    absent_roots = residue["absent_roots"]
    roots = residue["roots"]
    require(
        isinstance(analyzed_paths, list) and analyzed_paths
        and all(isinstance(path, str) for path in analyzed_paths)
        and analyzed_paths == sorted(set(analyzed_paths))
        and supplemental_paths == sorted(set(SYSTEMD_SUPPLEMENTAL_PATHS))
        and isinstance(requested_paths, list)
        and all(isinstance(path, str) for path in requested_paths)
        and requested_paths == sorted(set(analyzed_paths + supplemental_paths))
        and isinstance(absent_roots, list)
        and all(isinstance(path, str) for path in absent_roots)
        and absent_roots == sorted(set(absent_roots))
        and set(absent_roots) <= set(requested_paths)
        and all(
            isinstance(path, str) and PurePosixPath(path).is_absolute()
            and str(PurePosixPath(path)) == path
            and ".." not in PurePosixPath(path).parts
            for path in requested_paths
        )
        and isinstance(roots, list),
        "systemd unit search root inventory is invalid",
    )
    present_aliases: list[str] = []
    root_identities: set[tuple[int, int]] = set()
    canonical_paths: list[str] = []
    for root in roots:
        require(
            isinstance(root, dict)
            and set(root) == {"canonical_path", "aliases", "device", "inode"}
            and isinstance(root["canonical_path"], str)
            and PurePosixPath(root["canonical_path"]).is_absolute()
            and str(PurePosixPath(root["canonical_path"])) == root["canonical_path"]
            and isinstance(root["aliases"], list) and root["aliases"]
            and all(isinstance(alias, str) for alias in root["aliases"])
            and root["aliases"] == sorted(set(root["aliases"]))
            and type(root["device"]) is int and root["device"] > 0
            and type(root["inode"]) is int and root["inode"] > 0,
            "systemd canonical search root evidence is invalid",
        )
        identity = (root["device"], root["inode"])
        require(identity not in root_identities, "systemd search roots were not deduplicated by device/inode")
        root_identities.add(identity)
        canonical_paths.append(root["canonical_path"])
        present_aliases.extend(root["aliases"])
    require(
        canonical_paths == sorted(set(canonical_paths))
        and sorted(present_aliases + absent_roots) == requested_paths
        and len(present_aliases) == len(set(present_aliases))
        and not set(present_aliases) & set(absent_roots),
        "systemd search root coverage is incomplete or ambiguous",
    )


def load_bundle(
    evidence: Path, *, enforce_root: bool,
    expected_toolchain_manifest_sha256: str,
) -> tuple[dict[str, bytes], dict[str, Any], str]:
    require(
        HEX64.fullmatch(expected_toolchain_manifest_sha256) is not None,
        "expected bundle toolchain manifest SHA-256 is invalid",
    )
    evidence = Path(evidence).absolute()
    require(SAFE_BUNDLE_NAME.fullmatch(evidence.name) is not None, "evidence bundle name is unsafe")
    metadata = evidence.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not evidence.is_symlink(), "evidence directory is invalid")
    if os.name == "posix":
        require(stat.S_IMODE(metadata.st_mode) == 0o500, "evidence directory must be frozen mode 0500")
        if enforce_root:
            require((metadata.st_uid, metadata.st_gid) == (0, 0), "evidence directory is not root:root")
    names = {entry.name for entry in os.scandir(evidence)}
    require(names == BUNDLE_FILES | {BUNDLE_MANIFEST}, "evidence bundle file set is not exact")
    manifest_payload = stable_read(
        evidence / BUNDLE_MANIFEST, label="bundle manifest",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        expected_mode=0o400 if os.name == "posix" else None,
    )
    manifest = parse_object(manifest_payload, label="bundle manifest", canonical=True)
    require(
        set(manifest)
        == {
            "schema_version", "bundle_type", "release", "capability_id",
            "evidence_name", "evidence_path", "plan_sha256",
            "toolchain_manifest_sha256", "auth_token_id",
            "receipt_id", "files",
        }
        and manifest["schema_version"] == 1
        and manifest["bundle_type"]
        == "odoo-accounting-cli-v3.dev15.multicurrency-read-evidence"
        and manifest["release"] == RELEASE
        and manifest["capability_id"] == CAPABILITY_ID
        and manifest["evidence_name"] == evidence.name
        and manifest["evidence_path"] == str(evidence)
        and manifest["plan_sha256"] == READ_PLAN_SHA256
        and manifest["toolchain_manifest_sha256"]
        == expected_toolchain_manifest_sha256,
        "bundle manifest identity mismatch",
    )
    entries = manifest["files"]
    require(isinstance(entries, list) and [item.get("path") for item in entries if isinstance(item, dict)] == sorted(BUNDLE_FILES), "bundle manifest file set/order mismatch")
    documents: dict[str, bytes] = {}
    for item in entries:
        require(set(item) == {"path", "sha256", "size"} and HEX64.fullmatch(str(item["sha256"])) is not None and type(item["size"]) is int and 0 <= item["size"] <= MAX_JSON_BYTES, "bundle member metadata is invalid")
        payload = stable_read(
            evidence / item["path"], label=f"bundle member {item['path']}",
            expected_uid=0 if enforce_root and os.name == "posix" else None,
            expected_gid=0 if enforce_root and os.name == "posix" else None,
            expected_mode=0o400 if os.name == "posix" else None,
            allow_empty=True,
        )
        require(len(payload) == item["size"] and hashlib.sha256(payload).hexdigest() == item["sha256"], f"bundle member hash/size mismatch: {item['path']}")
        documents[item["path"]] = payload
    return documents, manifest, hashlib.sha256(manifest_payload).hexdigest()


def verify_bundle(
    evidence: Path, runtime: dict[str, Any], *, auth_secret: bytes,
    receipt_secret: bytes, expected_toolchain_manifest_sha256: str,
    committed_plan_bytes: bytes | None = None,
    expected_paths: dict[str, str] | None = None, enforce_root: bool = False,
    expected_state_uid: int | None = None,
    expected_state_gid: int | None = None,
) -> dict[str, Any]:
    runtime = validate_runtime(runtime, expected_paths=expected_paths)
    documents, bundle_manifest, bundle_manifest_sha256 = load_bundle(
        evidence, enforce_root=enforce_root,
        expected_toolchain_manifest_sha256=expected_toolchain_manifest_sha256,
    )
    require(documents["exit"] == b"0\n" and documents["stderr"] == b"", "launcher exit/stderr evidence is not clean")
    require(documents["signer.exit"] == b"0\n" and documents["signer.stderr"] == b"", "signer exit/stderr evidence is not clean")
    require(documents["oracle.exit"] == b"0\n" and documents["oracle.stderr"] == b"", "oracle exit/stderr evidence is not clean")
    expected_plan_bytes = committed_plan_bytes if committed_plan_bytes is not None else load_pinned_plan()[1]
    require(hashlib.sha256(expected_plan_bytes).hexdigest() == READ_PLAN_SHA256, "test/production pinned plan hash mismatch")
    require(documents["read-plan.json"] == expected_plan_bytes, "bundle plan bytes are not the pinned Dev15 plan")
    plan = parse_object(documents["read-plan.json"], label="bundle read plan")
    request = parse_object(documents["request.json"], label="bundle request", canonical=True)
    response = parse_object(documents["response.json"], label="bundle response", canonical=True)
    receipt_file = parse_object(documents["receipt.json"], label="bundle receipt", canonical=True)
    oracle = parse_object(documents["oracle.json"], label="bundle oracle", canonical=True)
    state_pre = parse_object(documents["state-pre.json"], label="bundle state-pre", canonical=True)
    state_post = parse_object(documents["state-post.json"], label="bundle state-post", canonical=True)
    system_pre = parse_object(documents["system-pre.json"], label="bundle system-pre", canonical=True)
    system_post = parse_object(documents["system-post.json"], label="bundle system-post", canonical=True)
    require(response.get("ok") is True and response.get("command") == "read" and set(response) == {"ok", "command", "data"}, "launcher response is not an exact successful read envelope")
    data = response["data"]
    require(isinstance(data, dict) and set(data) == {"capability_id", "release_identity", "runtime", "result"} and data["capability_id"] == CAPABILITY_ID, "response data envelope mismatch")
    require(data["release_identity"] == {"commit": COMMIT, "manifest_sha256": MANIFEST_SHA256, "package_sha256": PACKAGE_SHA256, "registry_digest": REGISTRY_DIGEST, "release": RELEASE, "verified": True, "version": VERSION}, "response release identity mismatch")
    require(data["runtime"] == {"instance_id": "odoo19@43.165.173.80", "environment": "test", "capability_channel": "staged", "database_name": "odoo_test", "database_uuid": DATABASE_UUID}, "response runtime identity mismatch")
    result = data["result"]
    require(isinstance(result, dict), "verified result is missing")
    issued, expires = verify_auth(request, runtime, auth_secret)
    receipt, observed = verify_receipt(request, result, runtime, receipt_secret)
    require(issued <= observed <= expires, "receipt observation escaped auth validity window")
    require(receipt_file == receipt and bundle_manifest["auth_token_id"] == request["context"]["auth_token_id"] and bundle_manifest["receipt_id"] == receipt["id"], "bundle manifest/request/receipt binding mismatch")
    verify_state(
        state_pre, state_post, request, receipt, runtime, issued, expires, observed,
        expected_state_uid=expected_state_uid,
        expected_state_gid=expected_state_gid,
    )
    verify_system_snapshots(plan, system_pre, system_post)
    verify_golden_and_oracle(plan, request, result, oracle)
    return {
        "schema_version": 1, "release": RELEASE, "capability_id": CAPABILITY_ID,
        "auth_token_id": request["context"]["auth_token_id"], "receipt_id": receipt["id"],
        "record_count": receipt["record_count"],
        "move_line_count": result["ledger_summary"]["move_line_count"],
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "toolchain_version": TOOLCHAIN_VERSION,
        "toolchain_manifest_sha256": expected_toolchain_manifest_sha256,
        "real_odoo_receipt_verified": True, "receipt_v2_hmac_verified": True,
        "state_and_audit_chain_verified": True,
        "postgresql_identity_and_read_only_oracle_verified": True,
        "golden_answer_verified": True, "system_identity_unchanged": True,
        "all_checks_passed": True, "production_promotion_allowed": False,
    }


def verify_with_exact_release_core(
    evidence: Path, runtime: dict[str, Any], receipt_secret: bytes,
    *, expected_toolchain_manifest_sha256: str,
) -> None:
    documents, _manifest, _digest = load_bundle(
        evidence, enforce_root=True,
        expected_toolchain_manifest_sha256=expected_toolchain_manifest_sha256,
    )
    request = parse_object(documents["request.json"], label="core request", canonical=True)
    response = parse_object(documents["response.json"], label="core response", canonical=True)
    result = response["data"]["result"]
    receipt = result["receipt"]
    body = {key: value for key, value in result.items() if key != "receipt"}
    sys.path.insert(0, str(RELEASE_ROOT / "src"))
    from odoo_accounting_cli_v3.receipts import verify_read_receipt
    observed = _utc(receipt["observed_at"], "receipt observed_at", zulu=True)
    verify_read_receipt(
        receipt, capability_id=CAPABILITY_ID, parameters=request["parameters"],
        result_body=body, auth_token_id=request["context"]["auth_token_id"],
        principal="pi:test-user-2", odoo_instance_id="odoo19@43.165.173.80",
        database_name="odoo_test", database_uuid=DATABASE_UUID,
        company_id=9, user_id=2, registry_digest=REGISTRY_DIGEST,
        release_digest=MANIFEST_SHA256, environment="test",
        capability_channel="staged", expected_record_count=result["page"]["total_count"],
        now=observed, consume_receipt=lambda *_args: True,
        expected_key_id=runtime["receipt_key_id"], secret=receipt_secret,
    )


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_external_anchor(
    evidence: Path, report: dict[str, Any], *,
    anchor_parent: Path = ANCHOR_PARENT, enforce_root: bool = True,
) -> Path:
    evidence = Path(evidence).absolute()
    require(SAFE_BUNDLE_NAME.fullmatch(evidence.name) is not None, "bundle name is unsafe for external anchor")
    if enforce_root and os.name == "posix":
        _safe_root_chain(anchor_parent, final_mode=0o755)
    anchor_path = anchor_parent / f"{evidence.name}.json"
    document = {
        "schema_version": 1,
        "anchor_type": "odoo-accounting-cli-v3.dev15.read-evidence-verification",
        "bundle_path": str(evidence),
        "bundle_manifest_sha256": report["bundle_manifest_sha256"],
        "toolchain_version": report["toolchain_version"],
        "toolchain_manifest_sha256": report["toolchain_manifest_sha256"],
        "report": report,
        "report_sha256": hashlib.sha256(canonical_json(report)).hexdigest(),
    }
    payload = canonical_json(document) + b"\n"
    try:
        descriptor = os.open(
            anchor_path,
            os.O_WRONLY | getattr(os, "O_BINARY", 0) | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
    except FileExistsError:
        existing = stable_read(
            anchor_path, label="existing external evidence anchor",
            expected_uid=0 if enforce_root and os.name == "posix" else None,
            expected_gid=0 if enforce_root and os.name == "posix" else None,
            expected_mode=0o400 if os.name == "posix" else None,
        )
        parsed = parse_object(
            existing, label="existing external evidence anchor", canonical=True,
        )
        require(
            existing == payload and parsed == document,
            "existing external evidence anchor conflicts with this verification",
        )
        return anchor_path
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "short external anchor write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name == "posix":
        os.chmod(anchor_path, 0o400, follow_symlinks=False)
    _fsync_directory(anchor_parent)
    stable_read(
        anchor_path, label="external evidence anchor",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        expected_mode=0o400 if os.name == "posix" else None,
    )
    return anchor_path


def main() -> None:
    import grp
    import pwd

    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: verify_evidence.py EVIDENCE_DIR EXPECTED_MANIFEST_SHA256"
        )
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("Dev15 evidence verifier must execute as root on POSIX")
    evidence = validate_evidence_path(Path(sys.argv[1]))
    expected_toolchain_manifest_sha256 = sys.argv[2]
    verify_toolchain(expected_toolchain_manifest_sha256)
    runtime_payload = stable_read(
        RUNTIME_CONFIG, label="Dev15 runtime config",
        expected_uid=0, expected_gid=0, expected_mode=0o644,
    )
    runtime = validate_runtime(parse_object(runtime_payload, label="Dev15 runtime config"))
    verify_live_release(runtime)
    odoo_gid = grp.getgrnam("odoo").gr_gid
    odoo_uid = pwd.getpwnam("odoo").pw_uid
    auth_secret = private_secret(
        Path(runtime["auth_secret_path"]), expected_uid=0, expected_gid=odoo_gid,
    )
    receipt_secret = private_secret(
        Path(runtime["receipt_secret_path"]), expected_uid=0, expected_gid=odoo_gid,
    )
    require(not hmac.compare_digest(auth_secret, receipt_secret), "Dev15 HMAC role secrets alias")
    report = verify_bundle(
        evidence, runtime, auth_secret=auth_secret, receipt_secret=receipt_secret,
        expected_toolchain_manifest_sha256=expected_toolchain_manifest_sha256,
        enforce_root=True, expected_state_uid=odoo_uid,
        expected_state_gid=odoo_gid,
    )
    verify_with_exact_release_core(
        evidence, runtime, receipt_secret,
        expected_toolchain_manifest_sha256=expected_toolchain_manifest_sha256,
    )
    report["exact_release_core_receipt_verified"] = True
    report["external_anchor_path"] = str(ANCHOR_PARENT / f"{evidence.name}.json")
    anchor = write_external_anchor(evidence, report)
    require(str(anchor) == report["external_anchor_path"], "external anchor path mismatch")
    print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

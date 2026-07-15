#!/usr/bin/python3 -I
"""Freeze and verify a four-read batch against cumulative dev8 persistence."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import pwd
import re
import sqlite3
import stat
import tempfile
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import quote


RELEASE = "0.1.0.dev8-bd21ca07c168"
VERSION = "0.1.0.dev8"
COMMIT = "bd21ca07c1689a42fbf903b91486269397b44733"
TREE = "fd389ef55fbc6723379a2928a10b665925829599"
PACKAGE_SHA256 = "58cfd17e72858b10d4e233b9c21af6e0759dac0ec08a4293e004d7a3b3c22234"
PACKAGE_SIZE = 151492
MANIFEST_SHA256 = "fec52f03c8c5e970f5e89a01f71ef4f7de7de287ea129ea01700d4de23eb6f06"
REGISTRY_DIGEST = "d8f1e76b674137a330de11bffee43de8a7362f877360d4410edebb54e8856b3e"
RUNTIME_SHA256 = "a089d13a2418225e245d10cf76728ad6af31ce0b5fde9f5b14902c44eebe59b7"
PLAN_SHA256 = "c6dd18fc356bdbc26de43941656e9af62f639d06393ce87572e7a08e5759f2e5"
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
RELEASE_ROOT = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE
PACKAGE = (
    Path("/opt/odoo-accounting-cli-v3/packages")
    / f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
)
ANCHOR = Path("/opt/odoo-accounting-cli-v3/trusted-artifacts") / f"{RELEASE}.json"
RUNTIME = Path("/etc/odoo-accounting-cli-v3/runtime-test-dev8.json")
PRIOR_EVIDENCE_ROOT = (
    Path("/var/lib/odoo-accounting-cli-v3/evidence") / RELEASE
)
PRIOR_EVIDENCE_ANCHOR = (
    Path("/var/lib/odoo-accounting-cli-v3/evidence-anchors") / f"{RELEASE}.json"
)
PRIOR_TOOLCHAIN_VERSION = "0.1.0.dev8-toolchain.8"
PRIOR_ANCHOR_SHA256 = "429d02227cd2d4e35df84d9d0de25ad8f0be7081d8c4cae4d63366dab27b80d6"
PRIOR_ANCHOR_SIZE = 1120
PRIOR_CHECKSUM_MANIFEST_SHA256 = "0bb87449e070523cabf0967a26dbe04dc8f0c4da3bc1c490618429517320485e"
PRIOR_METADATA_SHA256 = "0320acebc25ca47590b6898d7630814beb0e1e7c453632c876a63f8c813f00be"
PRIOR_AUDIT_HEAD = "881bbbeb84a6abb19833f91e6f85ebf337b801c51d8867b344b661dfa9e54570"
PRIOR_STATE_FILES = {
    "auth-state.sqlite3": {
        "sha256": "a344df0dc16910cc517070c52fc0d34179b0ebe4502549e60b22fe96eb6c1109",
        "size": 98304,
    },
    "receipt-state.sqlite3": {
        "sha256": "a76ebbd71ff034da037fbeac4529f4d466ee8116bb172e1923c5f65d6ce8e82f",
        "size": 106496,
    },
    "audit-events.json": {
        "sha256": "d80bcb37184c54aabbe584a3d29c73293da77aed2ac4ca91eb9a789013e482d5",
        "size": 9329,
    },
    "persistence-audit.json": {
        "sha256": "91764d146c722e65123e674a3c2121f3285ac5209be7fb8f3bee271810d18bde",
        "size": 3359,
    },
}

CASES = (
    ("registry-list", "acct.registry.list.v1"),
    ("trial-balance", "acct.gl.trial_balance.v1"),
    ("ar-open-items", "acct.ar.open_items.v1"),
    ("ap-open-items", "acct.ap.open_items.v1"),
)
EXPECTED_PLAN = {
    "principal": "pi:test-user-2",
    "user_id": 2,
    "company_id": 1,
    "allowed_company_ids": [1],
    "reads": {
        "registry-list": {"company_id": 1},
        "trial-balance": {
            "account_id": None,
            "company_id": 1,
            "currency_id": None,
            "date_from": "2026-01-01",
            "date_to": "2026-12-31",
            "include_off_balance": False,
            "include_zero": False,
            "limit": 500,
            "offset": 0,
            "opening_basis": "ledger_cumulative",
        },
        "ar-open-items": {
            "as_of_date": "2026-07-14",
            "company_id": 1,
            "currency_id": None,
            "limit": 500,
            "offset": 0,
            "partner_id": None,
        },
        "ap-open-items": {
            "as_of_date": "2026-07-14",
            "company_id": 1,
            "currency_id": None,
            "limit": 500,
            "offset": 0,
            "partner_id": None,
        },
    },
}
EXPECTED_RUNTIME = {
    "auth_key_id": "test-auth-2026-07-dev8",
    "auth_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/dev8-auth.hmac",
    "auth_state_path": f"/var/lib/odoo-accounting-cli-v3/test/candidates/{RELEASE}/auth.sqlite3",
    "canonical_package_path": str(PACKAGE),
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
    "receipt_state_path": f"/var/lib/odoo-accounting-cli-v3/test/candidates/{RELEASE}/receipt.sqlite3",
    "release_root": str(RELEASE_ROOT),
}

STATE_SIDECAR_SUFFIXES = ("-wal", "-shm")
STATE_ROLLBACK_SUFFIX = "-journal"
EXPECTED_RELEASE_IDENTITY = {
    "commit": COMMIT,
    "manifest_sha256": MANIFEST_SHA256,
    "package_sha256": PACKAGE_SHA256,
    "registry_digest": REGISTRY_DIGEST,
    "release": RELEASE,
    "verified": True,
    "version": VERSION,
}
EXPECTED_READ_FILES = {
    "read-plan.input.json",
    "identity.json",
    "summary.json",
    "read-oracles.audit.json",
    *(f"{name}.{suffix}" for name, _ in CASES for suffix in (
        "parameters.json", "request.json", "response.json", "receipt.json", "stderr", "exit"
    )),
    *(f"{name}.oracle.{suffix}" for name in (
        "trial-balance", "ar-open-items", "ap-open-items"
    ) for suffix in ("json", "stderr", "exit")),
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GENESIS_HASH = "0" * 64
PRIOR_EVIDENCE_STATE = {
    "evidence_path": str(PRIOR_EVIDENCE_ROOT),
    "toolchain_version": PRIOR_TOOLCHAIN_VERSION,
    "auth_sha256": PRIOR_STATE_FILES["auth-state.sqlite3"]["sha256"],
    "receipt_sha256": PRIOR_STATE_FILES["receipt-state.sqlite3"]["sha256"],
    "audit_head": PRIOR_AUDIT_HEAD,
    "auth_tokens": 4,
    "consumed_receipts": 4,
    "audit_events": 4,
}
PERSISTENCE_CHECKS = {
    "exact_four_new_unique_auth_tokens",
    "exact_four_new_unique_receipts",
    "exact_four_new_audit_events",
    "new_auth_hmac_verified",
    "new_receipt_hmac_verified",
    "new_request_response_parameter_roundtrip",
    "cumulative_sqlite_snapshots_integral",
    "prior_state_bound",
    "prior_state_preserved",
    "prior_audit_prefix_preserved",
    "full_audit_chain_verified",
    "new_audit_suffix_bound_to_wire_receipts",
    "oracle_audit_verified",
}
REPORT_FIELDS = {
    "schema_version", "release", "version", "commit", "git_tree",
    "package_sha256", "manifest_sha256", "registry_digest",
    "runtime_config_sha256", "read_plan_sha256", "database_uuid", "auth",
    "receipt", "prior_evidence_state", "verified_batch_counts",
    "cumulative_counts", "prior_audit_head", "audit_head",
    "audit_event_count", "capability_counts", "wire_cases", "checks",
    "all_checks_passed", "secret_material_emitted", "odoo_action_performed",
    "database_writes_permitted", "production_validated",
    "production_promotion_allowed",
}


def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def load_json_bytes(payload: bytes, label: str) -> object:
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise RuntimeError(f"invalid JSON: {label}") from exc


def secure_read(
    path: Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    exact_mode: int | None = None,
) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or (expected_uid is not None and before.st_uid != expected_uid)
        or (expected_gid is not None and before.st_gid != expected_gid)
        or (exact_mode is not None and stat.S_IMODE(before.st_mode) != exact_mode)
    ):
        raise RuntimeError(f"unsafe evidence file metadata: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        before_identity = (
            before.st_dev, before.st_ino, before.st_uid, before.st_gid,
            stat.S_IMODE(before.st_mode), before.st_nlink, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        if (
            opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
            stat.S_IMODE(opened.st_mode), opened.st_nlink, opened.st_size,
            opened.st_mtime_ns, opened.st_ctime_ns,
        ) != before_identity:
            raise RuntimeError(f"evidence path changed while opening: {path}")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after_open = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after = path.lstat()
    after_open_identity = (
        after_open.st_dev, after_open.st_ino, after_open.st_uid,
        after_open.st_gid, stat.S_IMODE(after_open.st_mode), after_open.st_nlink,
        after_open.st_size, after_open.st_mtime_ns, after_open.st_ctime_ns,
    )
    after_identity = (
        after.st_dev, after.st_ino, after.st_uid, after.st_gid,
        stat.S_IMODE(after.st_mode), after.st_nlink, after.st_size,
        after.st_mtime_ns, after.st_ctime_ns,
    )
    if before_identity != after_open_identity or before_identity != after_identity:
        raise RuntimeError(f"evidence file changed while reading: {path}")
    return b"".join(chunks)


def load_json(path: Path, **metadata: int) -> object:
    return load_json_bytes(secure_read(path, **metadata), str(path))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def parse_time(value: object) -> datetime:
    require(isinstance(value, str), "timestamp is not text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("timestamp is invalid") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, "timestamp is naive")
    return parsed.astimezone(timezone.utc)


def utc_sql(value: object) -> str:
    return parse_time(value).isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_private_directory(path: Path, *, uid: int, must_exist: bool) -> None:
    require(path.is_absolute() and path.parent == Path("/tmp"), "directory must be a direct /tmp child")
    if not must_exist:
        require(not os.path.lexists(path), "output directory already exists")
        os.mkdir(path, 0o700)
    metadata = path.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and path.resolve(strict=True) == path
        and metadata.st_uid == uid
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        "private directory metadata is invalid",
    )


def secure_write(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            require(written > 0, "output write did not progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _full_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stat_at(parent_descriptor: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _open_state_component(
    parent_descriptor: int,
    source: Path,
    name: str,
    odoo_uid: int,
    expected_gid: int | None,
) -> tuple[int, tuple[int, ...]]:
    noatime = getattr(os, "O_NOATIME", None)
    require(noatime is not None, "Linux O_NOATIME is required for live state reads")
    before = _stat_at(parent_descriptor, name)
    require(before is not None, f"live state component disappeared: {source.parent / name}")
    require(
        stat.S_ISREG(before.st_mode)
        and before.st_uid == odoo_uid
        and before.st_nlink == 1
        and stat.S_IMODE(before.st_mode) == 0o600
        and (expected_gid is None or before.st_gid == expected_gid),
        f"unsafe live state metadata: {source.parent / name}",
    )
    absolute = (source.parent / name).lstat()
    require(
        _full_identity(absolute) == _full_identity(before),
        f"live state pathname changed before open: {source.parent / name}",
    )
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | noatime,
        dir_fd=parent_descriptor,
    )
    opened = os.fstat(descriptor)
    if _full_identity(opened) != _full_identity(before):
        os.close(descriptor)
        raise RuntimeError(f"live state identity changed while opening: {source.parent / name}")
    return descriptor, _full_identity(before)


def _verify_state_components(
    parent_descriptor: int,
    source: Path,
    guard_descriptors: dict[str, int],
    expected: dict[str, tuple[int, ...]],
    absent: set[str],
) -> None:
    for name, identity in expected.items():
        guarded = _full_identity(os.fstat(guard_descriptors[name]))
        anchored = _stat_at(parent_descriptor, name)
        require(anchored is not None, f"live state component disappeared: {source.parent / name}")
        absolute = (source.parent / name).lstat()
        require(
            guarded == identity
            and _full_identity(anchored) == identity
            and _full_identity(absolute) == identity,
            f"live state identity changed during snapshot: {source.parent / name}",
        )
    for name in absent:
        require(
            _stat_at(parent_descriptor, name) is None
            and not os.path.lexists(source.parent / name),
            f"live state sidecar appeared during snapshot: {source.parent / name}",
        )


def _read_guarded_component(
    descriptor: int,
    expected_identity: tuple[int, ...],
    output_descriptor: int | None = None,
) -> str:
    expected_size = expected_identity[6]
    offset = 0
    checksum = hashlib.sha256()
    while offset < expected_size:
        chunk = os.pread(descriptor, min(1024 * 1024, expected_size - offset), offset)
        require(chunk, "live state component became shorter while reading")
        checksum.update(chunk)
        if output_descriptor is not None:
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(output_descriptor, remaining)
                require(written > 0, "snapshot copy write did not progress")
                remaining = remaining[written:]
        offset += len(chunk)
    require(
        os.pread(descriptor, 1, expected_size) == b"",
        "live state component grew while reading",
    )
    return checksum.hexdigest()


def _copy_guarded_component(
    descriptor: int,
    expected_identity: tuple[int, ...],
    target: Path,
) -> str:
    output_descriptor = os.open(
        target,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        checksum = _read_guarded_component(
            descriptor, expected_identity, output_descriptor
        )
        os.fsync(output_descriptor)
    finally:
        os.close(output_descriptor)
    copied = target.lstat()
    require(
        stat.S_ISREG(copied.st_mode)
        and not target.is_symlink()
        and copied.st_uid == os.geteuid()
        and copied.st_nlink == 1
        and stat.S_IMODE(copied.st_mode) == 0o600
        and copied.st_size == expected_identity[6],
        f"unsafe private snapshot component: {target}",
    )
    require(sha256(target) == checksum, f"private snapshot copy mismatch: {target.name}")
    return checksum


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_snapshot_staging(
    staging: Path,
    staging_descriptor: int,
    staging_identity: tuple[int, int],
) -> None:
    opened = os.fstat(staging_descriptor)
    anchored = staging.lstat()
    require(
        stat.S_ISDIR(opened.st_mode)
        and not staging.is_symlink()
        and (opened.st_dev, opened.st_ino) == staging_identity
        and (anchored.st_dev, anchored.st_ino) == staging_identity,
        "private snapshot staging directory identity changed",
    )
    for name in os.listdir(staging_descriptor):
        metadata = os.stat(name, dir_fd=staging_descriptor, follow_symlinks=False)
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid(),
            f"unsafe private snapshot staging object: {name}",
        )
        os.unlink(name, dir_fd=staging_descriptor)
    os.fsync(staging_descriptor)
    anchored = staging.lstat()
    require(
        (anchored.st_dev, anchored.st_ino) == staging_identity,
        "private snapshot staging path changed before removal",
    )
    os.rmdir(staging)
    _fsync_directory(staging.parent)


def _remove_published_snapshot(
    target: Path,
    published_identity: tuple[int, int],
) -> None:
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) != published_identity:
        # A colliding or replacement path is not ours and must never be removed.
        return
    require(
        stat.S_ISREG(metadata.st_mode)
        and not target.is_symlink()
        and metadata.st_uid == os.geteuid(),
        "published snapshot metadata changed during failure cleanup",
    )
    os.unlink(target)
    _fsync_directory(target.parent)


def _connect_snapshot_source(uri: str) -> sqlite3.Connection:
    return sqlite3.connect(uri, uri=True)


def snapshot(source: Path, target: Path, odoo_uid: int) -> None:
    require(source.is_absolute(), "live state path must be absolute")
    require(target.is_absolute(), "snapshot target path must be absolute")
    require(not os.path.lexists(target), f"snapshot target already exists: {target}")
    target_parent = target.parent.lstat()
    require(
        stat.S_ISDIR(target_parent.st_mode)
        and not target.parent.is_symlink()
        and target_parent.st_uid == os.geteuid()
        and not target_parent.st_mode & 0o022,
        f"unsafe snapshot target parent: {target.parent}",
    )
    parent_before = source.parent.lstat()
    require(
        stat.S_ISDIR(parent_before.st_mode) and not source.parent.is_symlink(),
        f"unsafe live state parent: {source.parent}",
    )
    parent_descriptor = os.open(
        source.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    guard_descriptors: dict[str, int] = {}
    staging_descriptor: int | None = None
    staging: Path | None = None
    staging_identity: tuple[int, int] | None = None
    published_identity: tuple[int, int] | None = None
    try:
        parent_opened = os.fstat(parent_descriptor)
        require(
            (parent_opened.st_dev, parent_opened.st_ino)
            == (parent_before.st_dev, parent_before.st_ino),
            f"live state parent changed while opening: {source.parent}",
        )
        main_descriptor, main_identity = _open_state_component(
            parent_descriptor,
            source,
            source.name,
            odoo_uid,
            None,
        )
        guard_descriptors[source.name] = main_descriptor
        expected = {source.name: main_identity}

        sidecar_names = {f"{source.name}{suffix}" for suffix in STATE_SIDECAR_SUFFIXES}
        present_sidecars = {
            name for name in sidecar_names if _stat_at(parent_descriptor, name) is not None
        }
        require(
            not present_sidecars or present_sidecars == sidecar_names,
            f"incomplete SQLite WAL sidecar set: {source}",
        )
        absent_sidecars = sidecar_names - present_sidecars
        journal_name = f"{source.name}{STATE_ROLLBACK_SUFFIX}"
        require(
            _stat_at(parent_descriptor, journal_name) is None
            and not os.path.lexists(source.parent / journal_name),
            f"rollback journal is forbidden for WAL state: {source}",
        )
        required_absent = absent_sidecars | {journal_name}
        for name in sorted(present_sidecars):
            descriptor, identity = _open_state_component(
                parent_descriptor,
                source,
                name,
                odoo_uid,
                main_identity[3],
            )
            guard_descriptors[name] = descriptor
            expected[name] = identity

        _verify_state_components(
            parent_descriptor,
            source,
            guard_descriptors,
            expected,
            required_absent,
        )

        staging = Path(tempfile.mkdtemp(prefix=".sqlite-snapshot-", dir=target.parent))
        staging_metadata = staging.lstat()
        staging_identity = (staging_metadata.st_dev, staging_metadata.st_ino)
        staging_descriptor = os.open(
            staging,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        staging_opened = os.fstat(staging_descriptor)
        require(
            stat.S_ISDIR(staging_metadata.st_mode)
            and stat.S_ISDIR(staging_opened.st_mode)
            and not staging.is_symlink()
            and staging_metadata.st_uid == staging_opened.st_uid == os.geteuid()
            and stat.S_IMODE(staging_metadata.st_mode)
            == stat.S_IMODE(staging_opened.st_mode) == 0o700
            and (staging_opened.st_dev, staging_opened.st_ino)
            == staging_identity,
            "private snapshot staging metadata or identity is invalid",
        )

        staged_source = staging / source.name
        copied_hashes = {
            source.name: _copy_guarded_component(
                guard_descriptors[source.name], expected[source.name], staged_source
            )
        }
        wal_name = f"{source.name}-wal"
        if wal_name in present_sidecars:
            copied_hashes[wal_name] = _copy_guarded_component(
                guard_descriptors[wal_name],
                expected[wal_name],
                Path(f"{staged_source}-wal"),
            )
        _verify_state_components(
            parent_descriptor,
            source,
            guard_descriptors,
            expected,
            required_absent,
        )
        for name, checksum in copied_hashes.items():
            require(
                _read_guarded_component(guard_descriptors[name], expected[name])
                == checksum,
                f"live state bytes changed during snapshot: {source.parent / name}",
            )
        _verify_state_components(
            parent_descriptor,
            source,
            guard_descriptors,
            expected,
            required_absent,
        )

        encoded_path = quote(staged_source.as_posix(), safe="/")
        source_uri = f"file:{encoded_path}?mode=ro&cache=private"
        staged_target = staging / ".snapshot-result.sqlite3"
        source_connection: sqlite3.Connection | None = None
        target_connection: sqlite3.Connection | None = None
        try:
            source_connection = _connect_snapshot_source(source_uri)
            target_connection = sqlite3.connect(staged_target)
            source_connection.execute("PRAGMA query_only = ON")
            source_connection.execute("BEGIN")
            source_connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            require(
                source_connection.execute("PRAGMA journal_mode").fetchone()[0]
                == "wal",
                "private source copy did not retain WAL mode",
            )
            source_connection.backup(target_connection)
        finally:
            if target_connection is not None:
                target_connection.close()
            if source_connection is not None:
                source_connection.close()

        check_connection = sqlite3.connect(
            f"file:{quote(staged_target.as_posix(), safe='/')}?mode=ro&immutable=1",
            uri=True,
        )
        try:
            require(
                check_connection.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                "private SQLite snapshot integrity check failed",
            )
        finally:
            check_connection.close()
        os.chmod(staged_target, 0o600)
        staged_target_descriptor = os.open(
            staged_target,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(staged_target_descriptor)
        finally:
            os.close(staged_target_descriptor)
        staged_target_metadata = staged_target.lstat()
        require(
            stat.S_ISREG(staged_target_metadata.st_mode)
            and not staged_target.is_symlink()
            and staged_target_metadata.st_uid == os.geteuid()
            and stat.S_IMODE(staged_target_metadata.st_mode) == 0o600
            and staged_target_metadata.st_nlink == 1,
            "private SQLite snapshot target metadata is invalid",
        )
        for name, checksum in copied_hashes.items():
            require(
                sha256(staging / name) == checksum,
                f"SQLite changed private source bytes: {name}",
            )
        require(
            not any(
                name.endswith("-journal")
                for name in os.listdir(staging_descriptor)
            ),
            "private SQLite journal remained after snapshot",
        )
        _verify_state_components(
            parent_descriptor,
            source,
            guard_descriptors,
            expected,
            required_absent,
        )
        _fsync_directory(staging)
        published_identity = (
            staged_target_metadata.st_dev,
            staged_target_metadata.st_ino,
        )
        os.link(staged_target, target, follow_symlinks=False)
        published = target.lstat()
        require(
            stat.S_ISREG(published.st_mode)
            and not target.is_symlink()
            and published.st_uid == os.geteuid()
            and (published.st_dev, published.st_ino) == published_identity
            and stat.S_IMODE(published.st_mode) == 0o600
            and published.st_nlink == 2,
            "published snapshot metadata is invalid",
        )
        _fsync_directory(target.parent)
        _verify_state_components(
            parent_descriptor,
            source,
            guard_descriptors,
            expected,
            required_absent,
        )
    except BaseException:
        if published_identity is not None:
            _remove_published_snapshot(target, published_identity)
            published_identity = None
        raise
    finally:
        cleanup_error: BaseException | None = None
        if staging_descriptor is not None and staging is not None and staging_identity is not None:
            try:
                _cleanup_snapshot_staging(
                    staging, staging_descriptor, staging_identity
                )
            except BaseException as exc:
                cleanup_error = exc
            finally:
                os.close(staging_descriptor)
        for descriptor in guard_descriptors.values():
            os.close(descriptor)
        os.close(parent_descriptor)
        if cleanup_error is not None:
            if published_identity is not None:
                _remove_published_snapshot(target, published_identity)
            raise cleanup_error
    try:
        published = target.lstat()
        require(
            published_identity is not None
            and (published.st_dev, published.st_ino) == published_identity
            and stat.S_ISREG(published.st_mode)
            and published.st_uid == os.geteuid()
            and stat.S_IMODE(published.st_mode) == 0o600
            and published.st_nlink == 1,
            "published snapshot final identity is invalid",
        )
        _fsync_directory(target.parent)
    except BaseException:
        if published_identity is not None:
            _remove_published_snapshot(target, published_identity)
        raise


def inspect_state(path: Path) -> tuple[dict[str, object], dict[str, list[dict[str, object]]]]:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        required = {
            "approval_records",
            "audit_events",
            "consumed_auth_tokens",
            "consumed_receipts",
            "idempotency_keys",
            "operations",
            "schema_meta",
        }
        require(required <= tables, f"state schema is incomplete: {path.name}")
        counts = {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in sorted(required - {"schema_meta"})
        }
        rows = {
            "schema_meta": [dict(row) for row in connection.execute("SELECT * FROM schema_meta ORDER BY key")],
            "auth": [dict(row) for row in connection.execute("SELECT * FROM consumed_auth_tokens ORDER BY token_id")],
            "receipts": [dict(row) for row in connection.execute("SELECT * FROM consumed_receipts ORDER BY receipt_id")],
            "events": [dict(row) for row in connection.execute("SELECT * FROM audit_events ORDER BY sequence")],
        }
        report = {
            "sha256": sha256(path),
            "size": path.stat().st_size,
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "quick_check": [row[0] for row in connection.execute("PRAGMA quick_check")],
            "foreign_key_violations": len(list(connection.execute("PRAGMA foreign_key_check"))),
            "counts": counts,
        }
        return report, rows
    finally:
        connection.close()


def verify_audit_chain(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    previous = GENESIS_HASH
    exported = []
    for expected_sequence, row in enumerate(rows, start=1):
        payload = load_json_bytes(str(row["payload_json"]).encode("utf-8"), "audit payload")
        require(isinstance(payload, dict), "audit payload is not an object")
        require(canonical(payload).decode("utf-8") == row["payload_json"], "audit payload is not canonical")
        expected_hash = digest(
            {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "occurred_at": row["occurred_at"],
                "operation_id": row["operation_id"],
                "payload_json": row["payload_json"],
                "previous_hash": row["previous_hash"],
                "sequence": row["sequence"],
            }
        )
        require(
            row["sequence"] == expected_sequence
            and row["previous_hash"] == previous
            and hmac.compare_digest(str(row["event_hash"]), expected_hash),
            "audit hash chain verification failed",
        )
        previous = str(row["event_hash"])
        exported.append({**row, "payload": payload})
        del exported[-1]["payload_json"]
    return exported


def verify_exact_row_subset(
    prior_rows: list[dict[str, object]],
    current_rows: list[dict[str, object]],
    key: str,
    label: str,
) -> tuple[set[object], set[object]]:
    """Require every prior row to remain byte-for-value identical in current state."""
    prior: dict[object, dict[str, object]] = {}
    current: dict[object, dict[str, object]] = {}
    for row in prior_rows:
        require(isinstance(row, dict) and key in row, f"{label} prior row is invalid")
        require(row[key] not in prior, f"{label} prior key is duplicated")
        prior[row[key]] = row
    for row in current_rows:
        require(isinstance(row, dict) and key in row, f"{label} current row is invalid")
        require(row[key] not in current, f"{label} current key is duplicated")
        current[row[key]] = row
    require(set(prior) <= set(current), f"{label} prior keys are not a subset")
    require(
        all(current[row_key] == row for row_key, row in prior.items()),
        f"{label} prior rows changed",
    )
    return set(prior), set(current)


def verify_exact_prefix(
    prior_rows: list[dict[str, object]],
    current_rows: list[dict[str, object]],
    label: str,
) -> None:
    require(len(current_rows) >= len(prior_rows), f"{label} current sequence is shorter")
    require(
        current_rows[: len(prior_rows)] == prior_rows,
        f"{label} prior sequence is not an exact prefix",
    )


def frozen_files(root: Path) -> dict[str, bytes]:
    """Read a root-owned 0500/0400 evidence tree without following links."""
    require(root.is_absolute(), "prior evidence root is not absolute")
    pending = [root]
    files: dict[str, bytes] = {}
    while pending:
        directory = pending.pop()
        metadata = directory.lstat()
        require(
            stat.S_ISDIR(metadata.st_mode)
            and not directory.is_symlink()
            and directory.resolve(strict=True) == directory
            and metadata.st_uid == metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o500,
            f"unsafe prior evidence directory: {directory}",
        )
        for path in directory.iterdir():
            value = path.lstat()
            require(not path.is_symlink(), f"prior evidence link is forbidden: {path}")
            if stat.S_ISDIR(value.st_mode):
                pending.append(path)
                continue
            require(stat.S_ISREG(value.st_mode), f"prior evidence object is invalid: {path}")
            relative = path.relative_to(root).as_posix()
            require(relative not in files, "duplicate prior evidence path")
            files[relative] = secure_read(
                path, expected_uid=0, expected_gid=0, exact_mode=0o400
            )
    return files


def checksum_entries(payload: bytes) -> dict[str, str]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeError("prior checksum manifest is not UTF-8") from exc
    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "prior checksum line is invalid")
        checksum, relative = match.groups()
        portable = PurePosixPath(relative)
        require(
            not portable.is_absolute()
            and portable.parts
            and all(part not in {"", ".", ".."} for part in portable.parts)
            and "\\" not in relative
            and relative not in entries,
            "prior checksum path is unsafe or duplicated",
        )
        entries[relative] = checksum
    return entries


def validate_prior_evidence() -> tuple[
    dict[str, list[dict[str, object]]],
    dict[str, list[dict[str, object]]],
    list[dict[str, object]],
]:
    """Bind the immutable non-final evidence and return its read-only state rows."""
    anchor_payload = secure_read(
        PRIOR_EVIDENCE_ANCHOR,
        expected_uid=0,
        expected_gid=0,
        exact_mode=0o400,
    )
    require(
        len(anchor_payload) == PRIOR_ANCHOR_SIZE
        and hashlib.sha256(anchor_payload).hexdigest() == PRIOR_ANCHOR_SHA256,
        "prior evidence anchor bytes mismatch",
    )
    anchor = load_json_bytes(anchor_payload, str(PRIOR_EVIDENCE_ANCHOR))
    require(
        anchor
        == {
            "schema_version": 1,
            "release": RELEASE,
            "commit": COMMIT,
            "git_tree": TREE,
            "evidence_path": str(PRIOR_EVIDENCE_ROOT),
            "package_sha256": PACKAGE_SHA256,
            "release_manifest_sha256": MANIFEST_SHA256,
            "registry_digest": REGISTRY_DIGEST,
            "runtime_config_sha256": RUNTIME_SHA256,
            "read_plan_sha256": PLAN_SHA256,
            "audit_head": PRIOR_AUDIT_HEAD,
            "evidence_checksum_manifest_sha256": PRIOR_CHECKSUM_MANIFEST_SHA256,
            "evidence_metadata_sha256": PRIOR_METADATA_SHA256,
            "evidence_checksum_entries": 94,
            "evidence_file_count": 95,
            "production_promotion_allowed": False,
        },
        "prior evidence anchor content mismatch",
    )

    files = frozen_files(PRIOR_EVIDENCE_ROOT)
    require(set(PRIOR_STATE_FILES) == {
        path.name for path in (PRIOR_EVIDENCE_ROOT / "state").iterdir()
    }, "prior state file set is not exact")
    checksum_payload = files.get("EVIDENCE-SHA256SUMS")
    require(
        isinstance(checksum_payload, bytes)
        and hashlib.sha256(checksum_payload).hexdigest()
        == PRIOR_CHECKSUM_MANIFEST_SHA256,
        "prior checksum manifest digest mismatch",
    )
    entries = checksum_entries(checksum_payload)
    require(
        len(entries) == 94
        and len(files) == 95
        and set(files) == set(entries) | {"EVIDENCE-SHA256SUMS"},
        "prior evidence file/checksum set mismatch",
    )
    for relative, expected in entries.items():
        require(
            hashlib.sha256(files[relative]).hexdigest() == expected,
            f"prior evidence checksum mismatch: {relative}",
        )

    metadata_payload = files["EVIDENCE-METADATA.json"]
    require(
        hashlib.sha256(metadata_payload).hexdigest() == PRIOR_METADATA_SHA256,
        "prior evidence metadata digest mismatch",
    )
    metadata = load_json_bytes(metadata_payload, "prior evidence metadata")
    require(
        isinstance(metadata, dict)
        and metadata.get("release") == RELEASE
        and metadata.get("audit_head") == PRIOR_AUDIT_HEAD
        and metadata.get("auth_tokens") == 4
        and metadata.get("consumed_receipts") == 4
        and metadata.get("receipt_audit_events") == 4
        and metadata.get("goal_complete") is False
        and metadata.get("production_promotion_allowed") is False,
        "prior evidence metadata content mismatch",
    )
    toolchain_payload = files["tools/TOOLCHAIN-MANIFEST.json"]
    toolchain = load_json_bytes(toolchain_payload, "prior toolchain manifest")
    require(
        isinstance(toolchain, dict)
        and set(toolchain) == {
            "schema_version", "toolchain_version", "application_release",
            "application_commit", "application_package_sha256",
            "source_directory", "files",
        }
        and toolchain.get("schema_version") == 1
        and toolchain.get("toolchain_version") == PRIOR_TOOLCHAIN_VERSION
        and toolchain.get("application_release") == RELEASE
        and toolchain.get("application_commit") == COMMIT
        and toolchain.get("application_package_sha256") == PACKAGE_SHA256
        and toolchain.get("source_directory") == "deployment/dev8"
        and isinstance(toolchain.get("files"), list),
        "prior toolchain identity mismatch",
    )

    for name, expected in PRIOR_STATE_FILES.items():
        relative = f"state/{name}"
        require(
            len(files[relative]) == expected["size"]
            and hashlib.sha256(files[relative]).hexdigest() == expected["sha256"]
            and entries[relative] == expected["sha256"],
            f"prior state identity mismatch: {name}",
        )
    prior_auth_report, prior_auth_rows = inspect_state(
        PRIOR_EVIDENCE_ROOT / "state/auth-state.sqlite3"
    )
    prior_receipt_report, prior_receipt_rows = inspect_state(
        PRIOR_EVIDENCE_ROOT / "state/receipt-state.sqlite3"
    )
    require(
        prior_auth_report["sha256"] == PRIOR_STATE_FILES["auth-state.sqlite3"]["sha256"]
        and prior_auth_report["size"] == PRIOR_STATE_FILES["auth-state.sqlite3"]["size"]
        and prior_receipt_report["sha256"] == PRIOR_STATE_FILES["receipt-state.sqlite3"]["sha256"]
        and prior_receipt_report["size"] == PRIOR_STATE_FILES["receipt-state.sqlite3"]["size"]
        and prior_auth_report["user_version"] == prior_receipt_report["user_version"] == 2
        and prior_auth_report["quick_check"] == prior_receipt_report["quick_check"] == ["ok"]
        and prior_auth_report["foreign_key_violations"]
        == prior_receipt_report["foreign_key_violations"] == 0
        and prior_auth_report["counts"] == {
            "approval_records": 0, "audit_events": 0,
            "consumed_auth_tokens": 4, "consumed_receipts": 0,
            "idempotency_keys": 0, "operations": 0,
        }
        and prior_receipt_report["counts"] == {
            "approval_records": 0, "audit_events": 4,
            "consumed_auth_tokens": 0, "consumed_receipts": 4,
            "idempotency_keys": 0, "operations": 0,
        },
        "prior SQLite state mismatch",
    )
    prior_events = verify_audit_chain(prior_receipt_rows["events"])
    prior_export = load_json_bytes(files["state/audit-events.json"], "prior audit export")
    require(
        isinstance(prior_export, list)
        and prior_export == prior_events
        and len(prior_events) == 4
        and prior_events[-1]["event_hash"] == PRIOR_AUDIT_HEAD,
        "prior audit prefix evidence mismatch",
    )
    prior_report = load_json_bytes(
        files["state/persistence-audit.json"], "prior persistence report"
    )
    require(
        isinstance(prior_report, dict)
        and prior_report.get("release") == RELEASE
        and prior_report.get("commit") == COMMIT
        and prior_report.get("git_tree") == TREE
        and prior_report.get("auth") == prior_auth_report
        and prior_report.get("receipt") == prior_receipt_report
        and prior_report.get("audit_head") == PRIOR_AUDIT_HEAD
        and prior_report.get("audit_event_count") == 4
        and prior_report.get("capability_counts")
        == {capability_id: 1 for _, capability_id in sorted(CASES, key=lambda item: item[1])}
        and prior_report.get("all_checks_passed") is True
        and prior_report.get("database_writes_permitted") is False
        and prior_report.get("production_promotion_allowed") is False,
        "prior persistence report mismatch",
    )
    # Re-read the fixed state objects after SQLite inspection. This is both a
    # preservation assertion and a guard against an accidental mutable open.
    for name, expected in PRIOR_STATE_FILES.items():
        payload = secure_read(
            PRIOR_EVIDENCE_ROOT / "state" / name,
            expected_uid=0,
            expected_gid=0,
            exact_mode=0o400,
        )
        require(
            len(payload) == expected["size"]
            and hashlib.sha256(payload).hexdigest() == expected["sha256"],
            f"prior state changed during validation: {name}",
        )
    return prior_auth_rows, prior_receipt_rows, prior_events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--read-evidence", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "persistence audit must run as root")
    validate_private_directory(args.read_evidence, uid=0, must_exist=True)
    actual_names = {path.name for path in args.read_evidence.iterdir()}
    require(actual_names == EXPECTED_READ_FILES, "real-read evidence file set is not exact")
    for name in actual_names:
        secure_read(args.read_evidence / name, expected_uid=0, exact_mode=0o600)

    runtime_bytes = secure_read(RUNTIME, expected_uid=0, exact_mode=0o644)
    require(hashlib.sha256(runtime_bytes).hexdigest() == RUNTIME_SHA256, "runtime config digest mismatch")
    runtime = load_json_bytes(runtime_bytes, str(RUNTIME))
    require(runtime == EXPECTED_RUNTIME, "runtime config is not the exact dev8 binding")
    require(
        PACKAGE.stat().st_size == PACKAGE_SIZE
        and sha256(PACKAGE) == PACKAGE_SHA256
        and not PACKAGE.is_symlink(),
        "canonical package identity mismatch",
    )
    require(
        load_json(ANCHOR, expected_uid=0, exact_mode=0o444)
        == {
            "commit": COMMIT,
            "manifest_sha256": MANIFEST_SHA256,
            "package_sha256": PACKAGE_SHA256,
            "release": RELEASE,
        },
        "release anchor mismatch",
    )
    prior_auth_rows, prior_receipt_rows, prior_events = validate_prior_evidence()

    plan_path = args.read_evidence / "read-plan.input.json"
    require(sha256(plan_path) == PLAN_SHA256, "read plan digest mismatch")
    plan = load_json(plan_path, expected_uid=0, exact_mode=0o600)
    require(plan == EXPECTED_PLAN, "read plan content mismatch")
    require(
        load_json(args.read_evidence / "identity.json", expected_uid=0, exact_mode=0o600)
        == {key: EXPECTED_PLAN[key] for key in ("principal", "user_id", "company_id", "allowed_company_ids")},
        "read identity did not round-trip",
    )

    auth_secret = secure_read(Path(EXPECTED_RUNTIME["auth_secret_path"]), expected_uid=0)
    receipt_secret = secure_read(Path(EXPECTED_RUNTIME["receipt_secret_path"]), expected_uid=0)
    require(len(auth_secret) >= 32 and len(receipt_secret) >= 32, "runtime HMAC secret is too short")

    wire: dict[str, dict[str, object]] = {}
    tokens: dict[str, dict[str, object]] = {}
    receipts: dict[str, dict[str, object]] = {}
    summary_rows = []
    for name, capability_id in CASES:
        parameters = load_json(args.read_evidence / f"{name}.parameters.json", expected_uid=0, exact_mode=0o600)
        request = load_json(args.read_evidence / f"{name}.request.json", expected_uid=0, exact_mode=0o600)
        response = load_json(args.read_evidence / f"{name}.response.json", expected_uid=0, exact_mode=0o600)
        extracted = load_json(args.read_evidence / f"{name}.receipt.json", expected_uid=0, exact_mode=0o600)
        require(parameters == EXPECTED_PLAN["reads"][name], f"{name} planned parameters changed")
        require(
            isinstance(request, dict)
            and set(request) == {"capability_id", "context", "parameters"}
            and request["capability_id"] == capability_id
            and request["parameters"] == parameters,
            f"{name} request binding mismatch",
        )
        context = request["context"]
        require(isinstance(context, dict), f"{name} context is invalid")
        signature = context.get("auth_signature")
        unsigned_context = {key: value for key, value in context.items() if key != "auth_signature"}
        auth_digest = digest({"capability_id": capability_id, "parameters": parameters})
        expected_context = {
            "allowed_company_ids": [1],
            "audience": "odoo-accounting-cli-v3",
            "auth_key_id": "test-auth-2026-07-dev8",
            "auth_request_digest": auth_digest,
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
        require(all(context.get(key) == value for key, value in expected_context.items()), f"{name} context binding mismatch")
        issued = parse_time(context.get("auth_issued_at"))
        expires = parse_time(context.get("auth_expires_at"))
        require(expires - issued == timedelta(minutes=4), f"{name} auth TTL mismatch")
        token_id = context.get("auth_token_id")
        require(isinstance(token_id, str) and token_id.startswith("dev8-read-"), f"{name} token namespace mismatch")
        uuid.UUID(token_id.removeprefix("dev8-read-"))
        require(token_id not in tokens, "duplicate auth token")
        require(
            isinstance(signature, str)
            and HEX64.fullmatch(signature) is not None
            and hmac.compare_digest(signature, hmac.new(auth_secret, canonical(unsigned_context), hashlib.sha256).hexdigest()),
            f"{name} auth signature mismatch",
        )
        tokens[token_id] = {
            "digest": digest(request),
            "expires": utc_sql(context["auth_expires_at"]),
        }

        require(
            isinstance(response, dict)
            and response.get("ok") is True
            and response.get("command") == "read"
            and isinstance(response.get("data"), dict),
            f"{name} response envelope mismatch",
        )
        data = response["data"]
        require(
            data.get("capability_id") == capability_id
            and data.get("release_identity") == EXPECTED_RELEASE_IDENTITY
            and data.get("runtime") == {
                "capability_channel": "staged",
                "database_name": "odoo_test",
                "database_uuid": DATABASE_UUID,
                "environment": "test",
                "instance_id": "odoo19@43.165.173.80",
            },
            f"{name} response identity mismatch",
        )
        result = data.get("result")
        require(isinstance(result, dict) and isinstance(result.get("page"), dict), f"{name} result is invalid")
        receipt = result.get("receipt")
        require(isinstance(receipt, dict) and receipt == extracted, f"{name} extracted receipt mismatch")
        receipt_id = receipt.get("id")
        require(isinstance(receipt_id, str), f"{name} receipt ID missing")
        uuid.UUID(receipt_id)
        require(receipt_id not in receipts, "duplicate receipt ID")
        unsigned_receipt = {key: value for key, value in receipt.items() if key != "signature"}
        body = {key: value for key, value in result.items() if key != "receipt"}
        expected_request_digest = digest(
            {
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
            }
        )
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
        require(all(receipt.get(key) == value for key, value in expected_receipt.items()), f"{name} receipt binding mismatch")
        require(
            isinstance(receipt.get("signature"), str)
            and HEX64.fullmatch(receipt["signature"]) is not None
            and hmac.compare_digest(
                receipt["signature"],
                hmac.new(receipt_secret, canonical(unsigned_receipt), hashlib.sha256).hexdigest(),
            ),
            f"{name} receipt signature mismatch",
        )
        observed = utc_sql(receipt.get("observed_at"))
        receipts[receipt_id] = {
            "request_digest": expected_request_digest,
            "observed": observed,
            "name": name,
            "capability_id": capability_id,
            "token_id": token_id,
            "receipt": receipt,
        }
        require(secure_read(args.read_evidence / f"{name}.stderr", expected_uid=0, exact_mode=0o600) == b"", f"{name} stderr is not empty")
        require(secure_read(args.read_evidence / f"{name}.exit", expected_uid=0, exact_mode=0o600).strip() == b"0", f"{name} exit is not zero")
        summary_rows.append(
            {
                "name": name,
                "capability_id": capability_id,
                "auth_token_id": token_id,
                "receipt_id": receipt_id,
                "record_count": receipt["record_count"],
            }
        )
        wire[name] = {"request": request, "response": response, "receipt": receipt}

    require(
        load_json(args.read_evidence / "summary.json", expected_uid=0, exact_mode=0o600)
        == {"all_verified": True, "reads": summary_rows},
        "real-read summary mismatch",
    )
    oracle_audit = load_json(args.read_evidence / "read-oracles.audit.json", expected_uid=0, exact_mode=0o600)
    require(
        isinstance(oracle_audit, dict)
        and oracle_audit.get("release") == RELEASE
        and oracle_audit.get("all_checks_passed") is True
        and oracle_audit.get("production_promotion_allowed") is False
        and len(oracle_audit.get("request_roundtrip", [])) == 4
        and len(oracle_audit.get("oracles", [])) == 3,
        "read-oracle audit mismatch",
    )
    for name in ("trial-balance", "ar-open-items", "ap-open-items"):
        report = load_json(args.read_evidence / f"{name}.oracle.json", expected_uid=0, exact_mode=0o600)
        require(
            isinstance(report, dict)
            and report.get("all_checks_passed") is True
            and report.get("transaction_isolation") == "repeatable read"
            and report.get("transaction_read_only") == "on"
            and report.get("rollback_completed") is True,
            f"{name} oracle did not pass",
        )
        require(secure_read(args.read_evidence / f"{name}.oracle.stderr", expected_uid=0, exact_mode=0o600) == b"", f"{name} oracle stderr is not empty")
        require(secure_read(args.read_evidence / f"{name}.oracle.exit", expected_uid=0, exact_mode=0o600).strip() == b"0", f"{name} oracle exit is not zero")

    validate_private_directory(args.output_directory, uid=0, must_exist=False)
    odoo_uid = pwd.getpwnam("odoo").pw_uid
    auth_snapshot = args.output_directory / "auth-state.sqlite3"
    receipt_snapshot = args.output_directory / "receipt-state.sqlite3"
    snapshot(Path(EXPECTED_RUNTIME["auth_state_path"]), auth_snapshot, odoo_uid)
    snapshot(Path(EXPECTED_RUNTIME["receipt_state_path"]), receipt_snapshot, odoo_uid)
    auth_report, auth_rows = inspect_state(auth_snapshot)
    receipt_report, receipt_rows = inspect_state(receipt_snapshot)
    require(
        auth_report["user_version"] == receipt_report["user_version"] == 2
        and auth_report["quick_check"] == receipt_report["quick_check"] == ["ok"]
        and auth_report["foreign_key_violations"] == receipt_report["foreign_key_violations"] == 0,
        "SQLite integrity or schema version mismatch",
    )
    require(
        auth_report["counts"] == {
            "approval_records": 0,
            "audit_events": 0,
            "consumed_auth_tokens": 8,
            "consumed_receipts": 0,
            "idempotency_keys": 0,
            "operations": 0,
        },
        "auth state is not the exact cumulative eight-read state",
    )
    require(
        receipt_report["counts"] == {
            "approval_records": 0,
            "audit_events": 8,
            "consumed_auth_tokens": 0,
            "consumed_receipts": 8,
            "idempotency_keys": 0,
            "operations": 0,
        },
        "receipt state is not the exact cumulative eight-read state",
    )
    prior_auth_keys, current_auth_keys = verify_exact_row_subset(
        prior_auth_rows["auth"], auth_rows["auth"], "token_id", "auth state"
    )
    prior_receipt_keys, current_receipt_keys = verify_exact_row_subset(
        prior_receipt_rows["receipts"],
        receipt_rows["receipts"],
        "receipt_id",
        "receipt state",
    )
    auth_by_token = {row["token_id"]: row for row in auth_rows["auth"]}
    require(
        current_auth_keys - prior_auth_keys == set(tokens)
        and prior_auth_keys.isdisjoint(tokens),
        "new consumed auth token set mismatch",
    )
    for token_id, expected in tokens.items():
        row = auth_by_token[token_id]
        require(
            row["request_digest"] == expected["digest"]
            and row["expires_at"] == expected["expires"],
            "consumed auth token content mismatch",
        )
    consumed_by_receipt = {row["receipt_id"]: row for row in receipt_rows["receipts"]}
    require(
        current_receipt_keys - prior_receipt_keys == set(receipts)
        and prior_receipt_keys.isdisjoint(receipts),
        "new consumed receipt set mismatch",
    )
    for receipt_id, expected in receipts.items():
        row = consumed_by_receipt[receipt_id]
        require(
            row["request_digest"] == expected["request_digest"]
            and row["observed_at"] == expected["observed"],
            "consumed receipt content mismatch",
        )

    schema_meta = {row["key"]: row["value"] for row in receipt_rows["schema_meta"]}
    require(
        schema_meta.get("receipt_verifier_key_id") == "test-receipt-2026-07-dev8"
        and schema_meta.get("receipt_verifier_secret_sha256") == hashlib.sha256(receipt_secret).hexdigest(),
        "receipt verifier persistence binding mismatch",
    )
    events = verify_audit_chain(receipt_rows["events"])
    require(len(events) == 8, "cumulative audit event count mismatch")
    verify_exact_prefix(
        prior_receipt_rows["events"], receipt_rows["events"], "audit chain"
    )
    verify_exact_prefix(prior_events, events, "exported audit chain")
    require(
        events[3]["event_hash"] == PRIOR_AUDIT_HEAD,
        "prior audit head is not preserved at sequence four",
    )
    receipts_by_name = {str(value["name"]): value for value in receipts.values()}
    require(set(receipts_by_name) == {name for name, _ in CASES}, "wire receipt names mismatch")
    for event, (name, capability_id) in zip(events[4:], CASES, strict=True):
        expected = receipts_by_name[name]
        payload = event["payload"]
        require(
            event["event_id"] == f"read:{expected['receipt']['id']}"
            and event["event_type"] == "read.verified"
            and event["operation_id"] is None
            and event["occurred_at"] == expected["observed"]
            and payload.get("auth_token_id") == expected["token_id"]
            and payload.get("capability_id") == capability_id
            and payload.get("principal") == "pi:test-user-2"
            and payload.get("receipt") == expected["receipt"]
            and payload.get("receipt_id") == expected["receipt"]["id"]
            and payload.get("request_digest") == expected["request_digest"]
            and payload.get("result_digest") == expected["receipt"]["result_digest"]
            and payload.get("release_digest") == MANIFEST_SHA256
            and payload.get("registry_digest") == REGISTRY_DIGEST,
            f"{name} audit event does not match wire evidence",
        )

    audit_head = events[-1]["event_hash"]
    capability_counts = dict(sorted(Counter(event["payload"]["capability_id"] for event in events).items()))
    require(
        capability_counts == {capability_id: 2 for _, capability_id in sorted(CASES, key=lambda item: item[1])},
        "cumulative capability counts mismatch",
    )
    exported_events = [{key: value for key, value in event.items()} for event in events]
    secure_write(
        args.output_directory / "audit-events.json",
        json.dumps(exported_events, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    for name, expected in PRIOR_STATE_FILES.items():
        prior_payload = secure_read(
            PRIOR_EVIDENCE_ROOT / "state" / name,
            expected_uid=0,
            expected_gid=0,
            exact_mode=0o400,
        )
        require(
            len(prior_payload) == expected["size"]
            and hashlib.sha256(prior_payload).hexdigest() == expected["sha256"],
            f"prior state was not preserved: {name}",
        )
    report = {
        "schema_version": 1,
        "release": RELEASE,
        "version": VERSION,
        "commit": COMMIT,
        "git_tree": TREE,
        "package_sha256": PACKAGE_SHA256,
        "manifest_sha256": MANIFEST_SHA256,
        "registry_digest": REGISTRY_DIGEST,
        "runtime_config_sha256": RUNTIME_SHA256,
        "read_plan_sha256": PLAN_SHA256,
        "database_uuid": DATABASE_UUID,
        "auth": auth_report,
        "receipt": receipt_report,
        "prior_evidence_state": PRIOR_EVIDENCE_STATE,
        "verified_batch_counts": {
            "auth_tokens": 4,
            "consumed_receipts": 4,
            "audit_events": 4,
        },
        "cumulative_counts": {
            "auth_tokens": 8,
            "consumed_receipts": 8,
            "audit_events": 8,
        },
        "prior_audit_head": PRIOR_AUDIT_HEAD,
        "audit_head": audit_head,
        "audit_event_count": len(events),
        "capability_counts": capability_counts,
        "wire_cases": summary_rows,
        "checks": {
            "exact_four_new_unique_auth_tokens": len(tokens) == 4,
            "exact_four_new_unique_receipts": len(receipts) == 4,
            "exact_four_new_audit_events": len(events[4:]) == 4,
            "new_auth_hmac_verified": True,
            "new_receipt_hmac_verified": True,
            "new_request_response_parameter_roundtrip": True,
            "cumulative_sqlite_snapshots_integral": True,
            "prior_state_bound": True,
            "prior_state_preserved": True,
            "prior_audit_prefix_preserved": True,
            "full_audit_chain_verified": True,
            "new_audit_suffix_bound_to_wire_receipts": True,
            "oracle_audit_verified": True,
        },
        "all_checks_passed": True,
        "secret_material_emitted": False,
        "odoo_action_performed": False,
        "database_writes_permitted": False,
        "production_validated": False,
        "production_promotion_allowed": False,
    }
    require(set(report) == REPORT_FIELDS, "persistence report fields are not exact")
    require(
        set(report["checks"]) == PERSISTENCE_CHECKS
        and all(report["checks"].values()),
        "persistence report checks are not exact or did not pass",
    )
    secure_write(
        args.output_directory / "persistence-audit.json",
        json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    directory_fd = os.open(args.output_directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()

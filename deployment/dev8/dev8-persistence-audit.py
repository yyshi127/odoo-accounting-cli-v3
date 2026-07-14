#!/usr/bin/python3 -I
"""Freeze and verify the exact four-read dev8 persistence batch."""

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
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


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
    exact_mode: int | None = None,
) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or (expected_uid is not None and before.st_uid != expected_uid)
        or (exact_mode is not None and stat.S_IMODE(before.st_mode) != exact_mode)
    ):
        raise RuntimeError(f"unsafe evidence file metadata: {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
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
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if identity != (
        after_open.st_dev,
        after_open.st_ino,
        after_open.st_size,
        after_open.st_mtime_ns,
    ) or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
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


def snapshot(source: Path, target: Path, odoo_uid: int) -> None:
    before = source.lstat()
    require(
        stat.S_ISREG(before.st_mode)
        and not source.is_symlink()
        and before.st_uid == odoo_uid
        and before.st_nlink == 1
        and stat.S_IMODE(before.st_mode) == 0o600,
        f"unsafe live state metadata: {source}",
    )
    source_connection = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    target_connection = sqlite3.connect(target)
    try:
        source_connection.backup(target_connection)
    finally:
        target_connection.close()
        source_connection.close()
    os.chmod(target, 0o600)
    after = source.lstat()
    require(
        (before.st_dev, before.st_ino, before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
        == (after.st_dev, after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)),
        f"live state identity changed during snapshot: {source}",
    )


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
            "consumed_auth_tokens": 4,
            "consumed_receipts": 0,
            "idempotency_keys": 0,
            "operations": 0,
        },
        "auth state counts are not the exact four-read batch",
    )
    require(
        receipt_report["counts"] == {
            "approval_records": 0,
            "audit_events": 4,
            "consumed_auth_tokens": 0,
            "consumed_receipts": 4,
            "idempotency_keys": 0,
            "operations": 0,
        },
        "receipt state counts are not the exact four-read batch",
    )
    auth_by_token = {row["token_id"]: row for row in auth_rows["auth"]}
    require(set(auth_by_token) == set(tokens), "consumed auth token set mismatch")
    for token_id, expected in tokens.items():
        row = auth_by_token[token_id]
        require(
            row["request_digest"] == expected["digest"]
            and row["expires_at"] == expected["expires"],
            "consumed auth token content mismatch",
        )
    consumed_by_receipt = {row["receipt_id"]: row for row in receipt_rows["receipts"]}
    require(set(consumed_by_receipt) == set(receipts), "consumed receipt set mismatch")
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
    require(len(events) == 4, "audit event count mismatch")
    for event, (name, capability_id) in zip(events, CASES, strict=True):
        expected = receipts[summary_rows[[item["name"] for item in summary_rows].index(name)]["receipt_id"]]
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
    exported_events = [{key: value for key, value in event.items()} for event in events]
    secure_write(
        args.output_directory / "audit-events.json",
        json.dumps(exported_events, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
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
        "audit_head": audit_head,
        "audit_event_count": len(events),
        "capability_counts": capability_counts,
        "wire_cases": summary_rows,
        "checks": {
            "exact_four_unique_auth_tokens": len(tokens) == 4,
            "exact_four_unique_receipts": len(receipts) == 4,
            "auth_hmac_verified": True,
            "receipt_hmac_verified": True,
            "request_response_parameter_roundtrip": True,
            "sqlite_snapshots_integral": True,
            "audit_chain_verified": True,
            "oracle_audit_verified": True,
        },
        "all_checks_passed": True,
        "secret_material_emitted": False,
        "odoo_action_performed": False,
        "database_writes_permitted": False,
        "production_validated": False,
        "production_promotion_allowed": False,
    }
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

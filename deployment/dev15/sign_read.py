#!/usr/bin/python3 -I
"""Sign the one byte-pinned Dev15 multicurrency evidence request."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable


CAPABILITY_ID = "acct.multicurrency.balance_read.v1"
RELEASE = "0.1.0.dev15-c4616386f921"
COMMIT = "c4616386f921946cf43cde2de449d2938a837422"
VERSION = "0.1.0.dev15"
RELEASE_ROOT = Path("/opt/odoo-accounting-cli-v3/releases") / RELEASE
TOOLCHAIN_VERSION = "0.1.0.dev15-read-toolchain.2"
TOOLCHAIN_ROOT = Path("/opt/odoo-accounting-cli-v3/toolchains") / TOOLCHAIN_VERSION
RUNTIME_CONFIG = (
    Path("/etc/odoo-accounting-cli-v3/candidates")
    / "runtime-test-dev15-c4616386f921.json"
)
COMMITTED_PLAN = TOOLCHAIN_ROOT / "read_plan.json"
READ_PLAN_SHA256 = "f15442df9d707ed77dc9c79ce0aa67fb022b4e5c1c94889ca4ab5ff0d1b2f161"
MANIFEST_SHA256 = "f4ea1dbd6e6b57472875d27a64504ffb433812c568bcd7be546d2e5074d24be2"
PACKAGE_SHA256 = "71d9bcea9c89b9ab2877406ca28b039791d380d0aeb09c60516a83b031b9c8bf"
REGISTRY_DIGEST = "ae50c3aa8d93472b7d58ca656ea9b2a42e18e5a38a9df0919320737b5632789b"
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
AUTH_KEY_PREFIX = "test-auth-dev15-"
RECEIPT_KEY_PREFIX = "test-receipt-dev15-"
MAX_JSON_BYTES = 1024 * 1024

EXPECTED_RUNTIME_FIELDS = {
    "capability_channel": "staged",
    "environment": "test",
    "odoo_bin": "/opt/odoo/odoo19/odoo-server/odoo-bin",
    "odoo_bin_sha256": "e0fb7977c59f73e652805d169bcd1bffe41df7bbf0c39ce47e8ad32126529003",
    "odoo_config": "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf",
    "odoo_config_sha256": "98a90d839e3ad16c32335057b27e33bc689cbccbb367350e31fbf41778ed70c3",
    "odoo_python": "/opt/odoo/odoo19/odoo19-venv/bin/python",
    "odoo_python_sha256": "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
}
RUNTIME_FIELDS = frozenset(
    {
        "instance_id", "environment", "capability_channel", "database_name",
        "database_uuid", "odoo_python", "odoo_python_sha256", "odoo_bin",
        "odoo_bin_sha256", "odoo_config", "odoo_config_sha256", "release_root",
        "canonical_package_path", "canonical_package_sha256", "auth_state_path",
        "receipt_state_path", "auth_key_id", "receipt_key_id", "auth_secret_path",
        "receipt_secret_path",
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


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(payload: bytes, *, label: str) -> Any:
    if len(payload) > MAX_JSON_BYTES:
        raise ValueError(f"{label} is too large")
    try:
        text = payload.decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON") from exc


def load_json(text: str) -> Any:
    return load_json_bytes(text.encode("utf-8"), label="JSON input")


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
    expected_mode: int | None = None,
) -> bytes:
    flags = (
        os.O_RDONLY | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"{label} must be a one-link regular file")
        if before.st_size < 1 or before.st_size > maximum:
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
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError(f"{label} changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} grew during read")
        if _fingerprint(os.fstat(descriptor)) != identity:
            raise ValueError(f"{label} identity changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def fixed_runtime_paths(root: Path = Path("/")) -> dict[str, str]:
    root = Path(root).absolute()

    def fixed(absolute: str) -> str:
        if root == Path("/"):
            return absolute
        return str(root.joinpath(*Path(absolute).parts[1:]))

    state = (
        f"/var/lib/odoo-accounting-cli-v3-dev15-candidates/{RELEASE}/read-state"
    )
    secrets = f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{RELEASE}"
    return {
        "auth_state_path": fixed(f"{state}/auth/state.sqlite3"),
        "receipt_state_path": fixed(f"{state}/receipt/state.sqlite3"),
        "auth_secret_path": fixed(f"{secrets}/auth.hmac"),
        "receipt_secret_path": fixed(f"{secrets}/receipt.hmac"),
    }


def validate_plan(plan: Any) -> dict[str, Any]:
    expected_keys = {
        "allowed_company_ids", "application", "capability_id", "company_id",
        "database", "expected", "parameters", "principal", "runtime",
        "schema_version", "system_baseline", "user_id",
    }
    if not isinstance(plan, dict) or set(plan) != expected_keys:
        raise ValueError("Dev15 read plan fields are invalid")
    if (
        plan["schema_version"] != 1
        or plan["capability_id"] != CAPABILITY_ID
        or plan["user_id"] != 2
        or plan["company_id"] != 9
        or plan["allowed_company_ids"] != [9]
        or plan["principal"] != "pi:test-user-2"
    ):
        raise ValueError("Dev15 read plan identity is invalid")
    if plan["application"] != {
        "commit": COMMIT, "manifest_sha256": MANIFEST_SHA256,
        "package_sha256": PACKAGE_SHA256, "registry_digest": REGISTRY_DIGEST,
        "release": RELEASE, "version": VERSION,
    }:
        raise ValueError("Dev15 application binding is invalid")
    if plan["database"] != {
        "current_user": "postgres", "instance_id": "odoo19@43.165.173.80",
        "name": "odoo_test", "server_version_num": 160014,
        "system_identifier": "7616327373742442245",
        "oracle_python": "/usr/bin/python3.12",
        "oracle_python_sha256": "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118",
        "oracle_psql": "/usr/lib/postgresql/16/bin/psql",
        "oracle_psql_sha256": "6d593ef8e95e5275691fcc28927cc540282db141ca1ec5e3806e7db5523613cb",
        "unix_socket_directory": "/var/run/postgresql",
        "unix_socket_path": "/var/run/postgresql/.s.PGSQL.5432",
        "uuid": DATABASE_UUID,
    }:
        raise ValueError("Dev15 database/oracle binding is invalid")
    if plan["runtime"] != EXPECTED_RUNTIME_FIELDS:
        raise ValueError("Dev15 runtime executable binding is invalid")
    parameters = plan["parameters"]
    if parameters != {
        "as_of_date": "2026-07-13",
        "balance_basis": "posted_ledger_cumulative",
        "company_id": 9,
        "currency_ids": [6, 1],
        "limit": 500,
        "off_balance_policy": "exclude",
        "offset": 0,
    }:
        raise ValueError("multicurrency parameters escaped the approved evidence scope")
    if not isinstance(plan["expected"], dict) or not isinstance(plan["system_baseline"], dict):
        raise ValueError("Dev15 golden answer or system baseline is missing")
    return plan


def load_pinned_plan(
    path: Path = COMMITTED_PLAN, *, enforce_metadata: bool = True,
) -> tuple[dict[str, Any], bytes]:
    payload = stable_read(
        path, label="pinned Dev15 read plan",
        expected_uid=0 if enforce_metadata and os.name == "posix" else None,
        expected_gid=0 if enforce_metadata and os.name == "posix" else None,
        expected_mode=0o444 if enforce_metadata and os.name == "posix" else None,
    )
    if hashlib.sha256(payload).hexdigest() != READ_PLAN_SHA256:
        raise ValueError("Dev15 read plan raw SHA-256 mismatch")
    return validate_plan(load_json_bytes(payload, label="pinned Dev15 read plan")), payload


def validate_committed_plan(
    plan: Any, *, committed_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validated = validate_plan(plan)
    expected = committed_plan if committed_plan is not None else load_pinned_plan()[0]
    if validated != expected:
        raise ValueError("request plan is not identical to the byte-pinned Dev15 plan")
    return validated


def validate_runtime(
    runtime: Any, *, expected_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_FIELDS:
        raise ValueError("runtime configuration fields are invalid")
    expected = {
        "instance_id": "odoo19@43.165.173.80",
        "environment": "test",
        "capability_channel": "staged",
        "database_name": "odoo_test",
        "database_uuid": DATABASE_UUID,
        **EXPECTED_RUNTIME_FIELDS,
        "release_root": str(RELEASE_ROOT),
        "canonical_package_path": (
            f"/opt/odoo-accounting-cli-v3/packages/"
            f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
        ),
        "canonical_package_sha256": PACKAGE_SHA256,
        **(expected_paths or fixed_runtime_paths()),
    }
    if any(runtime.get(key) != value for key, value in expected.items()):
        raise ValueError("runtime is not the exact Dev15 binding")
    auth_key = runtime["auth_key_id"]
    receipt_key = runtime["receipt_key_id"]
    if (
        not isinstance(auth_key, str) or not auth_key.startswith(AUTH_KEY_PREFIX)
        or not isinstance(receipt_key, str)
        or not receipt_key.startswith(RECEIPT_KEY_PREFIX)
        or auth_key == receipt_key
        or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", auth_key) is None
        or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", receipt_key) is None
    ):
        raise ValueError("runtime key IDs are not the fixed Dev15 roles")
    return runtime


def build_signed_request(
    plan: dict[str, Any], runtime: dict[str, Any], secret: bytes, *,
    now: datetime | None = None, token_factory: Callable[[], str] | None = None,
    committed_plan: dict[str, Any] | None = None,
    expected_paths: dict[str, str] | None = None,
) -> dict[str, Any]:
    plan = validate_committed_plan(plan, committed_plan=committed_plan)
    runtime = validate_runtime(runtime, expected_paths=expected_paths)
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("authentication secret must contain at least 32 bytes")
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise ValueError("issued_at must be timezone-aware")
    issued_at = issued_at.astimezone(timezone.utc)
    expires_at = issued_at + timedelta(minutes=4)
    token = (token_factory or (lambda: str(uuid.uuid4())))()
    try:
        if str(uuid.UUID(token)) != token:
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("token factory must return a canonical UUID") from exc
    parameters = plan["parameters"]
    request_digest = hashlib.sha256(canonical_json({
        "capability_id": CAPABILITY_ID, "parameters": parameters,
    })).hexdigest()
    unsigned_context = {
        "allowed_company_ids": [9],
        "audience": "odoo-accounting-cli-v3",
        "auth_expires_at": expires_at.isoformat(),
        "auth_issued_at": issued_at.isoformat(),
        "auth_key_id": runtime["auth_key_id"],
        "auth_request_digest": request_digest,
        "auth_signature_purpose": "auth_context_v1",
        "auth_signature_version": 1,
        "auth_token_id": f"dev15-multicurrency-{token}",
        "company_id": 9,
        "database_name": "odoo_test",
        "database_uuid": DATABASE_UUID,
        "environment": "test",
        "principal": "pi:test-user-2",
        "odoo_instance_id": "odoo19@43.165.173.80",
        "user_id": 2,
    }
    context = {
        **unsigned_context,
        "auth_signature": hmac.new(
            secret, canonical_json(unsigned_context), hashlib.sha256
        ).hexdigest(),
    }
    if set(context) != AUTH_CONTEXT_FIELDS:
        raise AssertionError("internal auth context field drift")
    return {
        "capability_id": CAPABILITY_ID,
        "context": context,
        "parameters": parameters,
    }


def read_private_secret(
    path: Path, *, expected_uid: int, expected_gid: int,
    expected_mode: int = 0o640,
) -> bytes:
    payload = stable_read(
        path, label="Dev15 authentication secret", maximum=4096,
        expected_uid=expected_uid, expected_gid=expected_gid,
        expected_mode=expected_mode,
    )
    if len(payload) != 32:
        raise ValueError("Dev15 authentication secret must contain exactly 32 bytes")
    return payload


def verify_toolchain_location(script_name: str) -> None:
    expected = TOOLCHAIN_ROOT / script_name
    actual = Path(__file__).absolute()
    if actual != expected or actual.is_symlink():
        raise ValueError("signer is not executing from the fixed Dev15 toolchain")
    current = Path("/")
    for component in expected.parent.parts[1:]:
        current /= component
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode) or current.is_symlink()
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        ):
            raise ValueError(f"unsafe toolchain parent: {current}")
    root_metadata = TOOLCHAIN_ROOT.lstat()
    if stat.S_IMODE(root_metadata.st_mode) != 0o555:
        raise ValueError("Dev15 toolchain root must be root:root mode 0555")
    stable_read(
        expected, label="Dev15 signer", maximum=2 * 1024 * 1024,
        expected_uid=0, expected_gid=0, expected_mode=0o444,
    )


def main() -> None:
    import grp

    if len(sys.argv) != 1:
        raise SystemExit("usage: sign_read.py < read_plan.json")
    verify_toolchain_location("sign_read.py")
    committed_plan, committed_bytes = load_pinned_plan()
    supplied = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
    if supplied != committed_bytes:
        raise SystemExit("stdin is not the exact byte-pinned Dev15 read plan")
    plan = validate_committed_plan(
        load_json_bytes(supplied, label="stdin read plan"),
        committed_plan=committed_plan,
    )
    runtime_payload = stable_read(
        RUNTIME_CONFIG, label="Dev15 runtime config",
        expected_uid=0, expected_gid=0, expected_mode=0o644,
    )
    runtime = validate_runtime(
        load_json_bytes(runtime_payload, label="Dev15 runtime config")
    )
    odoo_gid = grp.getgrnam("odoo").gr_gid
    request = build_signed_request(
        plan, runtime,
        read_private_secret(
            Path(runtime["auth_secret_path"]), expected_uid=0,
            expected_gid=odoo_gid,
        ),
        committed_plan=committed_plan,
    )
    os.write(1, canonical_json(request) + b"\n")


if __name__ == "__main__":
    main()

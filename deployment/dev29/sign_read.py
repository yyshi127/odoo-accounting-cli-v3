#!/usr/bin/env python3
"""Sign one byte-pinned Dev29 target read request without caller parameters."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable


PLAN_PATH = Path(__file__).resolve().with_name("read_plan.json")
MAX_JSON_BYTES = 2 * 1024 * 1024
AUTH_KEY_PREFIX = "test-auth-dev29-"
RECEIPT_KEY_PREFIX = "test-receipt-dev29-"
IDENTITY_FIELDS = frozenset(
    {
        "principal",
        "user_id",
        "company_id",
        "allowed_company_ids",
    }
)
RUNTIME_FIELDS = frozenset(
    {
        "instance_id",
        "environment",
        "capability_channel",
        "database_name",
        "database_uuid",
        "odoo_python",
        "odoo_python_sha256",
        "odoo_bin",
        "odoo_bin_sha256",
        "odoo_config",
        "odoo_config_sha256",
        "release_root",
        "canonical_package_path",
        "canonical_package_sha256",
        "auth_state_path",
        "receipt_state_path",
        "gcov_state_path",
        "auth_key_id",
        "receipt_key_id",
        "auth_secret_path",
        "receipt_secret_path",
    }
)
PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "target",
        "database",
        "runtime",
        "cases",
        "negative_cases",
        "witness",
    }
)
CASE_FIELDS = frozenset(
    {
        "name",
        "capability_id",
        "principal",
        "user_id",
        "company_id",
        "allowed_company_ids",
        "parameters",
        "expected",
    }
)
NEGATIVE_FIELDS = frozenset(
    {
        "name",
        "base_case",
        "principal",
        "user_id",
        "company_id",
        "allowed_company_ids",
        "mutation",
        "expected_error",
    }
)
MUTATION_FIELDS = frozenset({"kind", "fields"})
MUTATION_KINDS = frozenset(
    {
        "identity_override",
        "context_override",
        "expire_after_sign",
        "parameters_after_sign",
        "replay_exact_request",
    }
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Dev29SignerError(ValueError):
    """The fixed plan, runtime, secret, or request selector was rejected."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise Dev29SignerError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _constant(value: str) -> Any:
    raise Dev29SignerError(f"non-finite JSON number: {value}")


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise Dev29SignerError("request data is not canonical JSON") from exc


def _schema_version_is_one(value: Any) -> bool:
    return type(value) is int and value == 1


def load_json_bytes(payload: bytes, *, label: str) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_JSON_BYTES:
        raise Dev29SignerError(f"{label} is empty or too large")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except Dev29SignerError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise Dev29SignerError(f"{label} is not valid UTF-8 JSON") from exc
    if type(value) is not dict:
        raise Dev29SignerError(f"{label} must be a JSON object")
    return value


def stable_read(
    path: Path,
    *,
    label: str,
    maximum: int = MAX_JSON_BYTES,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    allowed_modes: frozenset[int] | None = None,
) -> bytes:
    path = Path(path)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_nlink != 1:
            raise Dev29SignerError(f"{label} is not a single-link regular file")
        mode = stat.S_IMODE(before.st_mode)
        if expected_uid is not None and before.st_uid != expected_uid:
            raise Dev29SignerError(f"{label} owner is invalid")
        if expected_gid is not None and before.st_gid != expected_gid:
            raise Dev29SignerError(f"{label} group is invalid")
        if allowed_modes is not None and mode not in allowed_modes:
            raise Dev29SignerError(f"{label} mode is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                raise Dev29SignerError(f"{label} changed while opened")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise Dev29SignerError(f"{label} is too large")
            after = os.fstat(descriptor)
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            ):
                raise Dev29SignerError(f"{label} changed while read")
        finally:
            os.close(descriptor)
    except Dev29SignerError:
        raise
    except OSError as exc:
        raise Dev29SignerError(f"{label} cannot be read") from exc
    return b"".join(chunks)


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise Dev29SignerError(f"{label} must be a positive integer")
    return value


def _identity(value: dict[str, Any], *, label: str) -> dict[str, Any]:
    identity = {field: value.get(field) for field in IDENTITY_FIELDS}
    if (
        not isinstance(identity["principal"], str)
        or not identity["principal"].strip()
        or identity["principal"] != identity["principal"].strip()
        or any(ord(character) < 32 for character in identity["principal"])
    ):
        raise Dev29SignerError(f"{label} principal is invalid")
    _positive_integer(identity["user_id"], f"{label} user_id")
    _positive_integer(identity["company_id"], f"{label} company_id")
    allowed = identity["allowed_company_ids"]
    if (
        type(allowed) is not list
        or not allowed
        or any(type(item) is not int or item <= 0 for item in allowed)
        or len(allowed) != len(set(allowed))
    ):
        raise Dev29SignerError(f"{label} allowed companies are invalid")
    return identity


def validate_plan(plan: Any) -> dict[str, Any]:
    if (
        type(plan) is not dict
        or set(plan) != PLAN_FIELDS
        or not _schema_version_is_one(plan.get("schema_version"))
    ):
        raise Dev29SignerError("Dev29 read plan fields are invalid")
    cases = plan.get("cases")
    negatives = plan.get("negative_cases")
    if type(cases) is not list or len(cases) != 5 or type(negatives) is not list:
        raise Dev29SignerError("Dev29 read plan cases are invalid")
    names: set[str] = set()
    for item in cases:
        if type(item) is not dict or set(item) != CASE_FIELDS:
            raise Dev29SignerError("Dev29 positive case fields are invalid")
        name = item.get("name")
        capability = item.get("capability_id")
        if (
            not isinstance(name, str)
            or not name
            or name in names
            or not isinstance(capability, str)
            or not capability.startswith("acct.")
            or type(item.get("parameters")) is not dict
            or type(item.get("expected")) is not dict
        ):
            raise Dev29SignerError("Dev29 positive case is invalid")
        _identity(item, label=f"case {name}")
        names.add(name)
    negative_names: set[str] = set()
    for item in negatives:
        if type(item) is not dict or set(item) != NEGATIVE_FIELDS:
            raise Dev29SignerError("Dev29 negative case fields are invalid")
        name = item.get("name")
        mutation = item.get("mutation")
        if (
            not isinstance(name, str)
            or not name
            or name in negative_names
            or item.get("base_case") not in names
            or type(mutation) is not dict
            or set(mutation) != MUTATION_FIELDS
            or mutation.get("kind") not in MUTATION_KINDS
            or type(mutation.get("fields")) is not dict
            or not isinstance(item.get("expected_error"), str)
            or not item["expected_error"]
        ):
            raise Dev29SignerError("Dev29 negative case is invalid")
        _identity(item, label=f"negative case {name}")
        negative_names.add(name)
    return plan


def validate_runtime(plan: dict[str, Any], runtime: Any) -> dict[str, Any]:
    if type(runtime) is not dict or set(runtime) != RUNTIME_FIELDS:
        raise Dev29SignerError("runtime configuration fields are invalid")
    database = plan.get("database")
    target = plan.get("target")
    expected_runtime = plan.get("runtime")
    if type(database) is not dict or type(target) is not dict or type(expected_runtime) is not dict:
        raise Dev29SignerError("Dev29 plan runtime binding is invalid")
    expected = {
        "instance_id": target.get("instance_id", f"odoo19@{target.get('host', '')}"),
        "environment": "test",
        "capability_channel": "staged",
        "database_name": database.get("name"),
        "database_uuid": database.get("uuid"),
        **expected_runtime,
    }
    for field, value in expected.items():
        if field in runtime and runtime[field] != value:
            raise Dev29SignerError(f"runtime {field} does not match the fixed plan")
    if (
        not isinstance(runtime["auth_key_id"], str)
        or not runtime["auth_key_id"].startswith(AUTH_KEY_PREFIX)
        or not isinstance(runtime["receipt_key_id"], str)
        or not runtime["receipt_key_id"].startswith(RECEIPT_KEY_PREFIX)
        or runtime["auth_key_id"] == runtime["receipt_key_id"]
    ):
        raise Dev29SignerError("runtime key roles are invalid")
    for field in ("canonical_package_sha256", "odoo_python_sha256", "odoo_bin_sha256", "odoo_config_sha256"):
        if not isinstance(runtime[field], str) or SHA256.fullmatch(runtime[field]) is None:
            raise Dev29SignerError(f"runtime {field} is invalid")
    for field in RUNTIME_FIELDS - {
        "instance_id", "environment", "capability_channel", "database_name",
        "database_uuid", "auth_key_id", "receipt_key_id",
        "canonical_package_sha256", "odoo_python_sha256", "odoo_bin_sha256",
        "odoo_config_sha256",
    }:
        if (
            not isinstance(runtime[field], str)
            or "\x00" in runtime[field]
            or not PurePosixPath(runtime[field]).is_absolute()
        ):
            raise Dev29SignerError(f"runtime {field} is not an absolute path")
    return runtime


def _select_case(
    plan: dict[str, Any], *, case_name: str | None, negative_name: str | None
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if (case_name is None) == (negative_name is None):
        raise Dev29SignerError("select exactly one positive or negative case")
    cases = {item["name"]: item for item in plan["cases"]}
    if case_name is not None:
        try:
            return cases[case_name], None
        except KeyError:
            raise Dev29SignerError("unknown Dev29 positive case") from None
    negatives = {item["name"]: item for item in plan["negative_cases"]}
    try:
        negative = negatives[str(negative_name)]
    except KeyError:
        raise Dev29SignerError("unknown Dev29 negative case") from None
    if negative["mutation"]["kind"] == "replay_exact_request":
        raise Dev29SignerError("replay uses the retained exact positive request")
    return cases[negative["base_case"]], negative


def _load_release_auth(release_root: Path):
    source_root = release_root / "src"
    expected = source_root / "odoo_accounting_cli_v3" / "auth.py"
    if not expected.is_file() or expected.is_symlink():
        raise Dev29SignerError("exact-release authentication source is unavailable")
    sys.path.insert(0, str(source_root))
    try:
        from odoo_accounting_cli_v3 import auth  # type: ignore
    finally:
        try:
            sys.path.remove(str(source_root))
        except ValueError:  # pragma: no cover - defensive only.
            pass
    if Path(auth.__file__).resolve(strict=True) != expected.resolve(strict=True):
        raise Dev29SignerError("authentication code was not loaded from the exact release")
    return auth


def build_signed_request(
    plan: dict[str, Any],
    runtime: dict[str, Any],
    secret: bytes,
    *,
    case_name: str | None = None,
    negative_name: str | None = None,
    now: datetime | None = None,
    token_factory: Callable[[], str] | None = None,
    auth_module: Any | None = None,
) -> dict[str, Any]:
    plan = validate_plan(plan)
    runtime = validate_runtime(plan, runtime)
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise Dev29SignerError("authentication secret must contain exactly 32 bytes")
    base, negative = _select_case(
        plan, case_name=case_name, negative_name=negative_name
    )
    identity = _identity(negative or base, label="selected case")
    parameters = json.loads(canonical_json(base["parameters"]).decode("utf-8"))
    mutation = negative["mutation"] if negative is not None else None
    if mutation is not None and mutation["kind"] == "identity_override":
        for field, value in mutation["fields"].items():
            if not isinstance(field, str) or not field.startswith("parameters."):
                raise Dev29SignerError("identity override escaped the fixed request")
            parameter = field.removeprefix("parameters.")
            if parameter not in parameters:
                raise Dev29SignerError("identity override escaped the fixed request")
            parameters[parameter] = value

    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None or issued_at.utcoffset() is None:
        raise Dev29SignerError("signing time must be timezone-aware")
    issued_at = issued_at.astimezone(timezone.utc)
    if mutation is not None and mutation["kind"] == "expire_after_sign":
        age_seconds = mutation["fields"].get("age_seconds", 600)
        if type(age_seconds) is not int or age_seconds < 301 or age_seconds > 86_400:
            raise Dev29SignerError("expired case age is invalid")
        issued_at -= timedelta(seconds=age_seconds)
    expires_at = issued_at + timedelta(minutes=4)

    token_value = (token_factory or (lambda: str(uuid.uuid4())))()
    try:
        if str(uuid.UUID(token_value)) != token_value:
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise Dev29SignerError("token factory must return a canonical UUID") from exc
    selector = negative["name"] if negative is not None else base["name"]
    token_id = f"dev29-read-{selector}-{token_value}"

    database_uuid = runtime["database_uuid"]
    if mutation is not None and mutation["kind"] == "context_override":
        fields = mutation["fields"]
        if set(fields) == {"context.database_uuid"}:
            database_uuid = fields["context.database_uuid"]
        elif set(fields) == {"database_uuid"}:  # Kept for isolated unit fixtures.
            database_uuid = fields["database_uuid"]
        else:
            raise Dev29SignerError("context override is outside the fixed database binding")
        if not isinstance(database_uuid, str):
            raise Dev29SignerError("context override is outside the fixed database binding")

    auth = auth_module or _load_release_auth(Path(runtime["release_root"]))
    try:
        context = auth.sign_request_context(
            auth_token_id=token_id,
            principal=identity["principal"],
            odoo_instance_id=runtime["instance_id"],
            database_name=runtime["database_name"],
            database_uuid=database_uuid,
            user_id=identity["user_id"],
            company_id=identity["company_id"],
            allowed_company_ids=frozenset(identity["allowed_company_ids"]),
            environment=runtime["environment"],
            capability_id=base["capability_id"],
            parameters=parameters,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=runtime["auth_key_id"],
            secret=secret,
        )
        context_value = {
            **auth.context_payload(context),
            "auth_signature": context.auth_signature,
        }
    except Exception as exc:
        raise Dev29SignerError("exact-release request signing failed") from exc
    request = {
        "capability_id": base["capability_id"],
        "context": context_value,
        "parameters": parameters,
    }
    if mutation is not None and mutation["kind"] == "parameters_after_sign":
        fields = mutation["fields"]
        normalized: dict[str, Any] = {}
        for field, value in fields.items():
            if not isinstance(field, str):
                raise Dev29SignerError("parameter tamper fields are outside the fixed request")
            parameter = field.removeprefix("parameters.")
            if parameter not in parameters:
                raise Dev29SignerError("parameter tamper fields are outside the fixed request")
            normalized[parameter] = value
        if not normalized:
            raise Dev29SignerError("parameter tamper fields are outside the fixed request")
        request["parameters"] = {**parameters, **normalized}
    return request


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--case")
    selection.add_argument("--negative")
    parser.add_argument("--runtime-config", required=True, type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    release_root = Path(__file__).resolve().parents[2]
    if os.name == "posix":
        metadata = Path(__file__).lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or Path(__file__).is_symlink()
        ):
            raise SystemExit("Dev29 signer is not running from a sealed release")
    plan = validate_plan(
        load_json_bytes(
            stable_read(
                PLAN_PATH,
                label="Dev29 read plan",
                expected_uid=0 if os.name == "posix" else None,
                expected_gid=0 if os.name == "posix" else None,
                allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
            ),
            label="Dev29 read plan",
        )
    )
    runtime = validate_runtime(
        plan,
        load_json_bytes(
            stable_read(
                arguments.runtime_config,
                label="Dev29 runtime configuration",
                expected_uid=0 if os.name == "posix" else None,
                expected_gid=os.getegid() if os.name == "posix" else None,
                allowed_modes=frozenset({0o640})
                if os.name == "posix"
                else None,
            ),
            label="Dev29 runtime configuration",
        ),
    )
    if Path(runtime["release_root"]).resolve(strict=True) != release_root:
        raise SystemExit("Dev29 signer release root does not match the runtime")
    effective_gid = os.getegid() if os.name == "posix" else None
    secret = stable_read(
        Path(runtime["auth_secret_path"]),
        label="Dev29 authentication secret",
        maximum=4096,
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=effective_gid,
        allowed_modes=frozenset({0o640}) if os.name == "posix" else None,
    )
    request = build_signed_request(
        plan,
        runtime,
        secret,
        case_name=arguments.case,
        negative_name=arguments.negative,
    )
    sys.stdout.buffer.write(canonical_json(request) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

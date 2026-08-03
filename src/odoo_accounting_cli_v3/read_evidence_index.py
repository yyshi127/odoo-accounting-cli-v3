"""Independent, fail-closed verification for retained read evidence indexes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .historical_router import HistoricalRouterError, _read_trusted_file
from .odoo.runner import CONFIG_FIELDS
from .receipts import ReceiptError, verify_read_receipt
from .registry import PRODUCTION_READ_EVIDENCE


EVIDENCE_INDEX_SCHEMA = "odoo-accounting-cli-v3.read-evidence-index.v2"
ATTESTATION_SCHEMA = "odoo-accounting-cli-v3.read-evidence-attestation.v2"
ATTESTATION_KEYS_SCHEMA = (
    "odoo-accounting-cli-v3.read-evidence-attestation-keys.v2"
)
TRUST_ANCHOR_SCHEMA = "odoo-accounting-cli-v3.read-evidence-trust-anchor.v1"
ARTIFACT_SCHEMA = "odoo-accounting-cli-v3.read-evidence-artifact.v2"
SOURCE_BUNDLE_SCHEMA = "odoo-accounting-cli-v3.read-evidence-source-bundle.v1"
ATTESTATION_CONTEXT = (
    b"odoo-accounting-cli-v3.read-evidence-attestation.v2\x00"
)
REQUIRED_EVIDENCE_KINDS = tuple(sorted(PRODUCTION_READ_EVIDENCE))
LEGACY_V2_BLOCKER = (
    "legacy HMAC read evidence v2 is not admissible for Goal evidence; "
    "SSHSIG v3 with active admission and raw verifier evidence is required"
)
DEFAULT_EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
DEFAULT_EVIDENCE_SOURCE_PARENT = Path(
    "/var/lib/odoo-accounting-cli-v3/evidence-sources"
)
DEFAULT_ATTESTATION_KEYS_PARENT = Path(
    "/etc/odoo-accounting-cli-v3/trust/read-evidence"
)
DEFAULT_TRUSTED_ARTIFACT_PARENT = Path(
    "/opt/odoo-accounting-cli-v3/trusted-artifacts"
)

_MAX_INDEX_BYTES = 2 * 1024 * 1024
_MAX_KEYS_BYTES = 1024 * 1024
_MAX_ATTESTATION_BYTES = 256 * 1024
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_FILE_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_SOURCE_FILES = 2048
_MAX_SOURCE_DIRECTORIES = 512
_MAX_SOURCE_DEPTH = 16
_MAX_SOURCE_ENTRIES = _MAX_SOURCE_FILES + _MAX_SOURCE_DIRECTORIES + 1
_MAX_SOURCE_BUNDLES = 16
_MAX_SOURCE_CACHE_BYTES = _MAX_SOURCE_TOTAL_BYTES + _MAX_SOURCE_MANIFEST_BYTES
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 100_000
_MAX_JSON_STRING_BYTES = 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CAPABILITY_ID = re.compile(
    r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$"
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DATABASE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_ENVIRONMENTS = frozenset({"test", "sandbox", "production"})
_CAPABILITY_CHANNELS = frozenset({"staged", "enabled"})
_SECURITY_NEGATIVE_CASES = (
    ("acl_deny", "odoo_acl_denied"),
    ("cross_company", "company_binding_rejected"),
    ("expired", "authentication_expired"),
    ("replay", "authentication_replayed"),
    ("tamper_parameters", "authentication_tampered"),
)
_PI_EVENT_ORDER = (
    "user_input",
    "capability_selected",
    "clarification_completed",
    "material_parameters_finalized",
    "cli_input",
    "odoo_execution",
    "odoo_result",
    "audit_receipt",
    "assistant_final",
)

_RELEASE_IDENTITY_FIELDS = frozenset(
    {
        "commit",
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
        "release",
        "verified",
        "version",
    }
)
_INDEX_FIELDS = frozenset(
    {"capabilities", "evidence_root", "release_identity", "schema_version"}
)
_CAPABILITY_FIELDS = frozenset({"capability_id", "evidence", "scope"})
_EVIDENCE_FIELDS = frozenset(
    {
        "artifact_path",
        "artifact_sha256",
        "attestation_path",
        "attestation_sha256",
        "evidence_kind",
    }
)
_KEY_DOCUMENT_FIELDS = frozenset({"keys", "schema_version"})
_KEY_FIELDS = frozenset(
    {"authority_id", "evidence_kind", "key_id", "secret_base64"}
)
_TRUST_ANCHOR_FIELDS = frozenset(
    {
        "attestation_keys_path",
        "attestation_keys_sha256",
        "authorities",
        "read_runtime_config_path",
        "read_runtime_config_sha256",
        "release_identity",
        "schema_version",
        "scope",
        "source_parent",
    }
)
_AUTHORITY_BINDING_FIELDS = frozenset(
    {
        "authority_id",
        "evidence_kind",
        "key_id",
        "verifier_id",
        "verifier_sha256",
    }
)
_SCOPE_FIELDS = frozenset(
    {
        "allowed_company_ids",
        "capability_channel",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "odoo_instance_id",
        "principal",
        "receipt_key_id",
        "registry_digest",
        "release_digest",
        "user_id",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {
        "capability_contract_sha256",
        "capability_id",
        "evidence_kind",
        "payload",
        "release_identity",
        "schema_version",
        "scope",
        "source",
    }
)
_SOURCE_FIELDS = frozenset(
    {
        "bundle_id",
        "bundle_manifest_path",
        "bundle_manifest_sha256",
        "evidence_member_path",
        "evidence_member_sha256",
    }
)
_SOURCE_MANIFEST_FIELDS = frozenset(
    {
        "bundle_id",
        "collected_at",
        "collector_id",
        "collector_sha256",
        "files",
        "release_identity",
        "schema_version",
        "scope",
    }
)
_SOURCE_FILE_FIELDS = frozenset({"path", "sha256", "size"})
_CASES_PAYLOAD_FIELDS = frozenset({"cases"})
_READ_CASE_FIELDS = frozenset(
    {"auth_token_id", "case_id", "parameters", "receipt", "result_body"}
)
_ORACLE_CASE_FIELDS = frozenset(
    {
        "auth_token_id",
        "case_id",
        "oracle_result",
        "parameters",
        "postgresql_witness",
        "receipt",
        "result_body",
    }
)
_ORACLE_WITNESS_FIELDS = frozenset(
    {
        "company_id",
        "database_name",
        "database_uuid",
        "isolation_level",
        "oracle_result_sha256",
        "post_state_sha256",
        "pre_state_sha256",
        "query_sha256",
        "rolled_back",
        "row_stream_sha256",
        "transaction_read_only",
        "write_statement_count",
    }
)
_PI_CASE_FIELDS = frozenset(
    {
        "assistant_result_sha256",
        "audit_receipt_sha256",
        "auth_token_id",
        "case_id",
        "cli_parameters",
        "collected_parameters",
        "event_order",
        "natural_language_request",
        "receipt",
        "result_body",
        "selected_capability_id",
    }
)
_SECURITY_CASE_FIELDS = frozenset(
    {
        "case_id",
        "exit_code",
        "expected_error_code",
        "observed_error_code",
        "odoo_effect",
        "odoo_write_count",
        "postgresql_write_count",
        "receipt_count",
        "request_sha256",
        "response_sha256",
    }
)
_RELEASE_PAYLOAD_FIELDS = frozenset(
    {
        "canonical_package_sha256",
        "capability_contract_sha256",
        "commit",
        "registry_digest",
        "release",
        "release_manifest_identity_sha256",
        "release_root",
        "version",
    }
)
_ATTESTATION_FIELDS = frozenset(
    {"algorithm", "claims", "key_id", "schema_version", "signature"}
)
_CLAIM_FIELDS = frozenset(
    {
        "artifact_sha256",
        "authority_id",
        "capability_contract_sha256",
        "capability_id",
        "commit",
        "evidence_kind",
        "manifest_sha256",
        "observed_at",
        "package_sha256",
        "registry_digest",
        "release",
        "scope_sha256",
        "source_bundle_manifest_sha256",
        "verification_summary_sha256",
        "verifier_id",
        "verifier_sha256",
        "version",
    }
)


class ReadEvidenceIndexError(ValueError):
    """Raised when an external read evidence index cannot be trusted."""


@dataclass(frozen=True)
class _SourceSnapshot:
    root: Path
    manifest: dict[str, Any]
    manifest_raw: bytes
    manifest_sha256: str
    file_entries: dict[str, dict[str, Any]]
    member_payloads: dict[str, bytes]
    expected_files: frozenset[str]
    expected_directories: frozenset[str]


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReadEvidenceIndexError("read evidence value is not canonical JSON") from exc


def canonical_json_bytes(value: Any) -> bytes:
    """Return the one accepted on-disk JSON representation."""

    return (_canonical_json(value) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadEvidenceIndexError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReadEvidenceIndexError(f"non-finite JSON number is forbidden: {value}")


def _check_json_complexity(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ReadEvidenceIndexError("read evidence JSON exceeds its node limit")
        if depth > _MAX_JSON_DEPTH:
            raise ReadEvidenceIndexError("read evidence JSON exceeds its depth limit")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > _MAX_JSON_STRING_BYTES:
                raise ReadEvidenceIndexError(
                    "read evidence JSON string exceeds its size limit"
                )
        elif type(current) is list:
            stack.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            for key, item in current.items():
                if type(key) is not str:
                    raise ReadEvidenceIndexError(
                        "read evidence JSON object key is invalid"
                    )
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
        elif current is not None and type(current) not in {
            bool,
            int,
            float,
        }:
            raise ReadEvidenceIndexError("read evidence JSON value is invalid")


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ReadEvidenceIndexError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ReadEvidenceIndexError(f"{label} is not valid JSON") from exc
    if type(value) is not dict:
        raise ReadEvidenceIndexError(f"{label} must be a JSON object")
    _check_json_complexity(value)
    return value


def _strict_json_object(raw: bytes, label: str) -> dict[str, Any]:
    value = _json_object(raw, label)
    if canonical_json_bytes(value) != raw:
        raise ReadEvidenceIndexError(f"{label} must use canonical JSON")
    return value


def _read_json_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    require_root_owner: bool,
) -> tuple[dict[str, Any], bytes]:
    raw = _read_file_bytes(
        path,
        label,
        maximum=maximum,
        require_root_owner=require_root_owner,
    )
    return _strict_json_object(raw, label), raw


def _read_file_bytes(
    path: Path,
    label: str,
    *,
    maximum: int,
    require_root_owner: bool,
) -> bytes:
    try:
        raw, identity = _read_trusted_file(
            path,
            label,
            maximum=maximum,
            require_root_owner=require_root_owner,
        )
        metadata = path.lstat()
        if (
            (metadata.st_dev, metadata.st_ino) != identity
            or metadata.st_nlink != 1
        ):
            raise ReadEvidenceIndexError(
                f"{label} must be a stable single-link file"
            )
    except HistoricalRouterError as exc:
        raise ReadEvidenceIndexError(str(exc)) from exc
    except ReadEvidenceIndexError:
        raise
    except OSError as exc:
        raise ReadEvidenceIndexError(f"{label} cannot be verified") from exc
    return raw


def _private_mode_is_safe(mode: int) -> bool:
    permissions = stat.S_IMODE(mode)
    return permissions in {0o400, 0o600}


def _read_private_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    require_root_owner: bool,
) -> bytes:
    raw = _read_file_bytes(
        path,
        label,
        maximum=maximum,
        require_root_owner=require_root_owner,
    )
    if os.name == "posix" and require_root_owner:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ReadEvidenceIndexError(f"{label} cannot be verified") from exc
        if not _private_mode_is_safe(metadata.st_mode):
            raise ReadEvidenceIndexError(
                f"{label} must be root-private mode 0400 or 0600"
            )
    return raw


def _json_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_json_equal(left: Any, right: Any) -> bool:
    return hmac.compare_digest(
        _canonical_json(left).encode("utf-8"),
        _canonical_json(right).encode("utf-8"),
    )


def _exact_fields(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReadEvidenceIndexError(f"{label} must be an object")
    if set(value) != set(fields):
        raise ReadEvidenceIndexError(f"{label} fields are invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ReadEvidenceIndexError(f"{label} must be a lowercase SHA-256")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ReadEvidenceIndexError(f"{label} is invalid")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReadEvidenceIndexError(f"{label} must be a positive integer")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ReadEvidenceIndexError(f"{label} must be a non-negative integer")
    return value


def _database_uuid(value: Any, label: str) -> str:
    if type(value) is not str:
        raise ReadEvidenceIndexError(f"{label} is invalid")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ReadEvidenceIndexError(f"{label} is invalid") from exc
    if str(parsed) != value:
        raise ReadEvidenceIndexError(f"{label} must be canonical")
    return value


def _timestamp(value: Any, label: str) -> str:
    if type(value) is not str or _RFC3339_UTC.fullmatch(value) is None:
        raise ReadEvidenceIndexError(f"{label} must be UTC RFC3339")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ReadEvidenceIndexError(f"{label} must be UTC RFC3339") from exc
    return value


def _canonical_absolute_path(value: Any, label: str) -> Path:
    if type(value) is not str or not value or "\x00" in value or len(value) > 4096:
        raise ReadEvidenceIndexError(f"{label} must be a canonical absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise ReadEvidenceIndexError(f"{label} must be a canonical absolute path")
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        raise ReadEvidenceIndexError(f"{label} cannot be resolved") from exc
    if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
        raise ReadEvidenceIndexError(f"{label} must be a canonical absolute path")
    return path


def _validate_directory(path: Path, label: str, *, require_root_owner: bool) -> None:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or path.is_symlink()
            or os.path.normcase(str(path.resolve(strict=True)))
            != os.path.normcase(str(path))
        ):
            raise ReadEvidenceIndexError(
                f"{label} must be a canonical non-symlink directory"
            )
        if os.name == "posix":
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ReadEvidenceIndexError(
                    f"{label} must not be group/world writable"
                )
            if require_root_owner and metadata.st_uid != 0:
                raise ReadEvidenceIndexError(f"{label} must be root-owned")
    except ReadEvidenceIndexError:
        raise
    except OSError as exc:
        raise ReadEvidenceIndexError(f"{label} cannot be verified") from exc


def _release_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _exact_fields(value, _RELEASE_IDENTITY_FIELDS, label)
    if identity["verified"] is not True:
        raise ReadEvidenceIndexError(f"{label} must be independently verified")
    if type(identity["commit"]) is not str or _COMMIT.fullmatch(identity["commit"]) is None:
        raise ReadEvidenceIndexError(f"{label} commit is invalid")
    for field in (
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
    ):
        _digest(identity[field], f"{label} {field}")
    for field in ("release", "version"):
        if type(identity[field]) is not str or not identity[field] or len(identity[field]) > 128:
            raise ReadEvidenceIndexError(f"{label} {field} is invalid")
        _identifier(identity[field], f"{label} {field}")
    if not identity["release"].startswith(identity["version"] + "-"):
        raise ReadEvidenceIndexError(f"{label} release/version binding is invalid")
    if not identity["release"].endswith(identity["commit"][:12]):
        raise ReadEvidenceIndexError(f"{label} release/commit binding is invalid")
    return identity


def _scope(
    value: Any,
    label: str,
    *,
    release_identity: dict[str, Any],
) -> dict[str, Any]:
    scope = _exact_fields(value, _SCOPE_FIELDS, label)
    _positive_integer(scope["company_id"], f"{label} company_id")
    _positive_integer(scope["user_id"], f"{label} user_id")
    database_name = scope["database_name"]
    if type(database_name) is not str or _DATABASE_NAME.fullmatch(database_name) is None:
        raise ReadEvidenceIndexError(f"{label} database_name is invalid")
    _database_uuid(scope["database_uuid"], f"{label} database_uuid")
    if (
        type(scope["environment"]) is not str
        or scope["environment"] not in _ENVIRONMENTS
    ):
        raise ReadEvidenceIndexError(f"{label} environment is invalid")
    if (
        type(scope["capability_channel"]) is not str
        or scope["capability_channel"] not in _CAPABILITY_CHANNELS
    ):
        raise ReadEvidenceIndexError(f"{label} capability_channel is invalid")
    if (
        scope["environment"] == "production"
        and scope["capability_channel"] != "enabled"
    ):
        raise ReadEvidenceIndexError(
            f"{label} production scope cannot use a staged capability channel"
        )
    instance_id = scope["odoo_instance_id"]
    if (
        type(instance_id) is not str
        or not instance_id.strip()
        or instance_id != instance_id.strip()
        or len(instance_id) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in instance_id)
    ):
        raise ReadEvidenceIndexError(f"{label} odoo_instance_id is invalid")
    _identifier(scope["receipt_key_id"], f"{label} receipt_key_id")
    principal = scope["principal"]
    if (
        type(principal) is not str
        or not principal.strip()
        or principal != principal.strip()
        or len(principal) > 256
    ):
        raise ReadEvidenceIndexError(f"{label} principal is invalid")
    allowed_company_ids = scope["allowed_company_ids"]
    if (
        type(allowed_company_ids) is not list
        or not allowed_company_ids
        or len(allowed_company_ids) > 256
        or any(type(item) is not int or item <= 0 for item in allowed_company_ids)
        or allowed_company_ids != sorted(set(allowed_company_ids))
        or scope["company_id"] not in allowed_company_ids
    ):
        raise ReadEvidenceIndexError(
            f"{label} allowed_company_ids must be sorted, unique, and include company_id"
        )
    _digest(scope["registry_digest"], f"{label} registry_digest")
    _digest(scope["release_digest"], f"{label} release_digest")
    if scope["registry_digest"] != release_identity["registry_digest"]:
        raise ReadEvidenceIndexError(f"{label} registry binding mismatch")
    if scope["release_digest"] != release_identity["manifest_sha256"]:
        raise ReadEvidenceIndexError(f"{label} release binding mismatch")
    return scope


def _read_runtime_receipt_secret(
    path: Path, *, require_root_owner: bool
) -> bytes:
    secret = _read_file_bytes(
        path,
        "read evidence runtime receipt secret",
        maximum=4096,
        require_root_owner=require_root_owner,
    )
    if os.name == "posix" and require_root_owner:
        try:
            mode = path.lstat().st_mode
        except OSError as exc:
            raise ReadEvidenceIndexError(
                "read evidence runtime receipt secret cannot be verified"
            ) from exc
        if stat.S_IMODE(mode) not in {0o400, 0o440, 0o600, 0o640}:
            raise ReadEvidenceIndexError(
                "read evidence runtime receipt secret permissions are unsafe"
            )
    if len(secret) < 32:
        raise ReadEvidenceIndexError(
            "read evidence runtime receipt secret is too short"
        )
    return secret


def _load_runtime_binding(
    path: Path,
    expected_sha256: str,
    *,
    scope: dict[str, Any],
    release_identity: dict[str, Any],
    require_root_owner: bool,
) -> tuple[dict[str, Any], bytes, bytes]:
    raw = _read_file_bytes(
        path,
        "read evidence runtime configuration",
        maximum=65_536,
        require_root_owner=require_root_owner,
    )
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ReadEvidenceIndexError(
            "read evidence runtime configuration digest mismatch"
        )
    runtime = _json_object(raw, "read evidence runtime configuration")
    if set(runtime) != set(CONFIG_FIELDS):
        raise ReadEvidenceIndexError(
            "read evidence runtime configuration fields are invalid"
        )
    bindings = {
        "instance_id": "odoo_instance_id",
        "environment": "environment",
        "capability_channel": "capability_channel",
        "database_name": "database_name",
        "database_uuid": "database_uuid",
        "receipt_key_id": "receipt_key_id",
    }
    for runtime_field, scope_field in bindings.items():
        if runtime.get(runtime_field) != scope[scope_field]:
            raise ReadEvidenceIndexError(
                f"read evidence runtime {runtime_field} does not match the trusted scope"
            )
    if runtime.get("canonical_package_sha256") != release_identity["package_sha256"]:
        raise ReadEvidenceIndexError(
            "read evidence runtime package identity mismatch"
        )
    expected_release_root = str(
        (
            Path("/opt/odoo-accounting-cli-v3/releases")
            / release_identity["release"]
        ).resolve()
    )
    if runtime.get("release_root") != expected_release_root:
        raise ReadEvidenceIndexError("read evidence runtime release root mismatch")
    receipt_secret_path = _canonical_absolute_path(
        runtime.get("receipt_secret_path"),
        "read evidence runtime receipt_secret_path",
    )
    receipt_secret = _read_runtime_receipt_secret(
        receipt_secret_path, require_root_owner=require_root_owner
    )
    return runtime, raw, receipt_secret


def _load_trust_anchor(
    *,
    release_identity: dict[str, Any],
    trusted_artifact_parent: Path,
    attestation_keys_parent: Path,
    evidence_source_parent: Path,
    require_root_owner: bool,
) -> tuple[
    dict[str, Any],
    bytes,
    dict[str, dict[str, Any]],
    dict[str, Any],
    bytes,
]:
    anchor_path = trusted_artifact_parent / (
        release_identity["release"] + ".read-evidence.json"
    )
    anchor, anchor_raw = _read_json_file(
        anchor_path,
        "read evidence trust anchor",
        maximum=_MAX_KEYS_BYTES,
        require_root_owner=require_root_owner,
    )
    _exact_fields(anchor, _TRUST_ANCHOR_FIELDS, "read evidence trust anchor")
    if anchor["schema_version"] != TRUST_ANCHOR_SCHEMA:
        raise ReadEvidenceIndexError("read evidence trust anchor schema is invalid")
    anchored_identity = _release_identity(
        anchor["release_identity"], "read evidence trust anchor release identity"
    )
    if anchored_identity != release_identity:
        raise ReadEvidenceIndexError("read evidence trust anchor release identity mismatch")
    trusted_scope = _scope(
        anchor["scope"],
        "read evidence trust anchor scope",
        release_identity=release_identity,
    )
    keys_sha256 = _digest(
        anchor["attestation_keys_sha256"],
        "read evidence trust anchor attestation_keys_sha256",
    )
    runtime_sha256 = _digest(
        anchor["read_runtime_config_sha256"],
        "read evidence trust anchor read_runtime_config_sha256",
    )
    keys_path = _canonical_absolute_path(
        anchor["attestation_keys_path"],
        "read evidence trust anchor attestation_keys_path",
    )
    expected_keys_path = (
        attestation_keys_parent
        / release_identity["release"]
        / "attestation-keys.json"
    )
    if os.path.normcase(str(keys_path)) != os.path.normcase(str(expected_keys_path)):
        raise ReadEvidenceIndexError(
            "read evidence trust anchor attestation key path is not release-canonical"
        )
    source_parent = _canonical_absolute_path(
        anchor["source_parent"], "read evidence trust anchor source_parent"
    )
    expected_source_parent = evidence_source_parent / release_identity["release"]
    if os.path.normcase(str(source_parent)) != os.path.normcase(
        str(expected_source_parent)
    ):
        raise ReadEvidenceIndexError(
            "read evidence trust anchor source parent is not release-canonical"
        )
    runtime_path = _canonical_absolute_path(
        anchor["read_runtime_config_path"],
        "read evidence trust anchor read_runtime_config_path",
    )
    authority_entries = anchor["authorities"]
    if type(authority_entries) is not list or len(authority_entries) != len(
        REQUIRED_EVIDENCE_KINDS
    ):
        raise ReadEvidenceIndexError(
            "read evidence trust anchor must bind one verifier per evidence kind"
        )
    observed_kinds: list[str] = []
    observed_authorities: set[str] = set()
    observed_key_ids: set[str] = set()
    observed_verifiers: set[str] = set()
    observed_verifier_hashes: set[str] = set()
    authority_bindings: dict[str, dict[str, Any]] = {}
    for index, raw_binding in enumerate(authority_entries):
        binding = _exact_fields(
            raw_binding,
            _AUTHORITY_BINDING_FIELDS,
            f"read evidence trust anchor authority {index}",
        )
        kind = binding["evidence_kind"]
        if kind not in REQUIRED_EVIDENCE_KINDS:
            raise ReadEvidenceIndexError(
                "read evidence trust anchor authority purpose is invalid"
            )
        observed_kinds.append(kind)
        authority_id = _identifier(
            binding["authority_id"], "read evidence trust anchor authority_id"
        )
        key_id = _identifier(
            binding["key_id"], "read evidence trust anchor key_id"
        )
        verifier_id = _identifier(
            binding["verifier_id"], "read evidence trust anchor verifier_id"
        )
        verifier_sha256 = _digest(
            binding["verifier_sha256"],
            "read evidence trust anchor verifier_sha256",
        )
        if (
            authority_id in observed_authorities
            or key_id in observed_key_ids
            or verifier_id in observed_verifiers
            or verifier_sha256 in observed_verifier_hashes
        ):
            raise ReadEvidenceIndexError(
                "read evidence trust anchor authorities must be purpose-isolated"
            )
        observed_authorities.add(authority_id)
        observed_key_ids.add(key_id)
        observed_verifiers.add(verifier_id)
        observed_verifier_hashes.add(verifier_sha256)
        authority_bindings[key_id] = dict(binding)
    if observed_kinds != list(REQUIRED_EVIDENCE_KINDS):
        raise ReadEvidenceIndexError(
            "read evidence trust anchor authority kinds/order do not match"
        )
    runtime, runtime_raw, receipt_secret = _load_runtime_binding(
        runtime_path,
        runtime_sha256,
        scope=trusted_scope,
        release_identity=release_identity,
        require_root_owner=require_root_owner,
    )
    return (
        {
            **anchor,
            "anchor_path": str(anchor_path),
            "anchor_sha256": hashlib.sha256(anchor_raw).hexdigest(),
            "attestation_keys_path": str(keys_path),
            "attestation_keys_sha256": keys_sha256,
            "read_runtime_config_path": str(runtime_path),
            "read_runtime_config_sha256": runtime_sha256,
            "scope": trusted_scope,
            "source_parent": str(source_parent),
        },
        anchor_raw,
        authority_bindings,
        runtime,
        receipt_secret,
    )


def _load_authorities(
    path: Path,
    *,
    expected_sha256: str,
    authority_bindings: dict[str, dict[str, Any]],
    require_root_owner: bool,
) -> tuple[dict[str, dict[str, Any]], bytes]:
    raw = _read_private_file(
        path,
        "read evidence attestation keys",
        maximum=_MAX_KEYS_BYTES,
        require_root_owner=require_root_owner,
    )
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ReadEvidenceIndexError("read evidence attestation key digest mismatch")
    document = _strict_json_object(raw, "read evidence attestation keys")
    _exact_fields(document, _KEY_DOCUMENT_FIELDS, "read evidence key document")
    if document["schema_version"] != ATTESTATION_KEYS_SCHEMA:
        raise ReadEvidenceIndexError("read evidence key document schema is invalid")
    keys = document["keys"]
    if type(keys) is not list or len(keys) != len(REQUIRED_EVIDENCE_KINDS):
        raise ReadEvidenceIndexError(
            "read evidence key document must contain one authority per evidence kind"
        )
    observed_kinds: list[str] = []
    observed_ids: set[str] = set()
    observed_authorities: set[str] = set()
    observed_secrets: set[bytes] = set()
    authorities: dict[str, dict[str, Any]] = {}
    for index, raw_key in enumerate(keys):
        key = _exact_fields(raw_key, _KEY_FIELDS, f"read evidence key {index}")
        kind = key["evidence_kind"]
        if kind not in REQUIRED_EVIDENCE_KINDS:
            raise ReadEvidenceIndexError("read evidence authority purpose is invalid")
        observed_kinds.append(kind)
        key_id = _identifier(key["key_id"], "read evidence key_id")
        authority_id = _identifier(
            key["authority_id"], "read evidence authority_id"
        )
        if key_id in observed_ids or authority_id in observed_authorities:
            raise ReadEvidenceIndexError("read evidence authority identifiers must be unique")
        secret_text = key["secret_base64"]
        if type(secret_text) is not str or len(secret_text) > 256:
            raise ReadEvidenceIndexError("read evidence authority secret is invalid")
        try:
            secret = base64.b64decode(secret_text, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ReadEvidenceIndexError(
                "read evidence authority secret is invalid"
            ) from exc
        if (
            not 32 <= len(secret) <= 64
            or base64.b64encode(secret).decode("ascii") != secret_text
        ):
            raise ReadEvidenceIndexError("read evidence authority secret is invalid")
        if secret in observed_secrets:
            raise ReadEvidenceIndexError("read evidence authority secrets must be unique")
        observed_ids.add(key_id)
        observed_authorities.add(authority_id)
        observed_secrets.add(secret)
        authorities[key_id] = {
            "authority_id": authority_id,
            "evidence_kind": kind,
            "secret": secret,
        }
    if observed_kinds != list(REQUIRED_EVIDENCE_KINDS):
        raise ReadEvidenceIndexError(
            "read evidence authority kinds/order do not match the required evidence set"
        )
    if set(authorities) != set(authority_bindings):
        raise ReadEvidenceIndexError(
            "read evidence attestation keys do not match the trust anchor"
        )
    for key_id, authority in authorities.items():
        binding = authority_bindings[key_id]
        if (
            authority["authority_id"] != binding["authority_id"]
            or authority["evidence_kind"] != binding["evidence_kind"]
        ):
            raise ReadEvidenceIndexError(
                "read evidence attestation authority binding mismatch"
            )
        authority["verifier_id"] = binding["verifier_id"]
        authority["verifier_sha256"] = binding["verifier_sha256"]
    return authorities, raw


def create_read_evidence_attestation(
    claims: dict[str, Any], *, key_id: str, secret: bytes
) -> dict[str, Any]:
    """Create a purpose-bound attestation for a specialized trusted verifier."""

    _identifier(key_id, "read evidence key_id")
    if type(secret) is not bytes or not 32 <= len(secret) <= 64:
        raise ReadEvidenceIndexError("read evidence attestation secret is invalid")
    if type(claims) is not dict:
        raise ReadEvidenceIndexError("read evidence attestation claims are invalid")
    payload = ATTESTATION_CONTEXT + _canonical_json(claims).encode("utf-8")
    return {
        "algorithm": "hmac-sha256",
        "claims": json.loads(_canonical_json(claims)),
        "key_id": key_id,
        "schema_version": ATTESTATION_SCHEMA,
        "signature": hmac.new(secret, payload, hashlib.sha256).hexdigest(),
    }


def _relative_source_path(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value) > 4096 or "\\" in value:
        raise ReadEvidenceIndexError(f"{label} is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ReadEvidenceIndexError(f"{label} is invalid")
    return value


def _source_mode_is_immutable(mode: int, *, directory: bool) -> bool:
    return stat.S_IMODE(mode) == (0o500 if directory else 0o400)


def _validate_source_directory(
    path: Path, label: str, *, require_root_owner: bool
) -> tuple[int, int]:
    _validate_directory(path, label, require_root_owner=require_root_owner)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReadEvidenceIndexError(f"{label} cannot be verified") from exc
    if (
        os.name == "posix"
        and require_root_owner
        and not _source_mode_is_immutable(metadata.st_mode, directory=True)
    ):
        raise ReadEvidenceIndexError(f"{label} must be immutable mode 0500")
    return metadata.st_dev, metadata.st_ino


def _validate_source_file_mode(
    path: Path, label: str, *, require_root_owner: bool
) -> None:
    if os.name != "posix" or not require_root_owner:
        return
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReadEvidenceIndexError(f"{label} cannot be verified") from exc
    if not _source_mode_is_immutable(metadata.st_mode, directory=False):
        raise ReadEvidenceIndexError(f"{label} must be immutable mode 0400")


def _expected_source_directories(paths: set[str]) -> set[str]:
    expected: set[str] = set()
    for relative in paths:
        parts = PurePosixPath(relative).parts[:-1]
        for end in range(1, len(parts) + 1):
            expected.add(PurePosixPath(*parts[:end]).as_posix())
    return expected


def _source_tree_files(
    root: Path, *, require_root_owner: bool
) -> tuple[set[str], set[str]]:
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    root_identity = _validate_source_directory(
        root,
        "read evidence source bundle root",
        require_root_owner=require_root_owner,
    )
    directory_identities = {root_identity}
    pending: list[tuple[Path, int, tuple[int, int]]] = [(root, 0, root_identity)]
    entry_count = 0
    while pending:
        directory, depth, expected_identity = pending.pop()
        identity = _validate_source_directory(
            directory,
            "read evidence source bundle directory",
            require_root_owner=require_root_owner,
        )
        if identity != expected_identity:
            raise ReadEvidenceIndexError(
                "read evidence source bundle directory changed during enumeration"
            )
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise ReadEvidenceIndexError(
                "read evidence source bundle cannot be enumerated"
            ) from exc
        try:
            with entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > _MAX_SOURCE_ENTRIES:
                        raise ReadEvidenceIndexError(
                            "read evidence source bundle exceeds its entry count limit"
                        )
                    path = Path(entry.path)
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise ReadEvidenceIndexError(
                            "read evidence source bundle member cannot be inspected"
                        ) from exc
                    if stat.S_ISLNK(metadata.st_mode):
                        raise ReadEvidenceIndexError(
                            "read evidence source bundle must not contain links"
                        )
                    relative = path.relative_to(root).as_posix()
                    if stat.S_ISDIR(metadata.st_mode):
                        if depth + 1 > _MAX_SOURCE_DEPTH:
                            raise ReadEvidenceIndexError(
                                "read evidence source bundle exceeds its depth limit"
                            )
                        identity = _validate_source_directory(
                            path,
                            "read evidence source bundle directory",
                            require_root_owner=require_root_owner,
                        )
                        if identity in directory_identities:
                            raise ReadEvidenceIndexError(
                                "read evidence source bundle contains a duplicate directory identity"
                            )
                        directory_identities.add(identity)
                        observed_directories.add(relative)
                        if len(observed_directories) > _MAX_SOURCE_DIRECTORIES:
                            raise ReadEvidenceIndexError(
                                "read evidence source bundle exceeds its directory count limit"
                            )
                        pending.append((path, depth + 1, identity))
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ReadEvidenceIndexError(
                            "read evidence source bundle contains a non-regular member"
                        )
                    observed_files.add(relative)
                    if len(observed_files) > _MAX_SOURCE_FILES + 1:
                        raise ReadEvidenceIndexError(
                            "read evidence source bundle exceeds its file count limit"
                        )
        except ReadEvidenceIndexError:
            raise
        except OSError as exc:
            raise ReadEvidenceIndexError(
                "read evidence source bundle cannot be enumerated"
            ) from exc
    return observed_files, observed_directories


def _load_source_bundle(
    source: Any,
    *,
    payload: dict[str, Any],
    capability_id: str,
    evidence_kind: str,
    release_identity: dict[str, Any],
    trusted_scope: dict[str, Any],
    source_parent: Path,
    require_root_owner: bool,
    cache: dict[str, _SourceSnapshot],
) -> tuple[dict[str, Any], str]:
    source = _exact_fields(source, _SOURCE_FIELDS, "read evidence artifact source")
    bundle_id = _identifier(source["bundle_id"], "read evidence source bundle_id")
    bundle_root = source_parent / bundle_id
    manifest_path = bundle_root / "BUNDLE-MANIFEST.json"
    if source["bundle_manifest_path"] != str(manifest_path):
        raise ReadEvidenceIndexError(
            "read evidence source manifest path is not release-canonical"
        )
    expected_manifest_sha256 = _digest(
        source["bundle_manifest_sha256"],
        "read evidence source bundle_manifest_sha256",
    )
    cache_key = str(manifest_path)
    cached = cache.get(cache_key)
    if cached is None:
        if len(cache) >= _MAX_SOURCE_BUNDLES:
            raise ReadEvidenceIndexError(
                "read evidence source bundle count exceeds its limit"
            )
        _validate_source_directory(
            bundle_root,
            "read evidence source bundle root",
            require_root_owner=require_root_owner,
        )
        manifest, manifest_raw = _read_json_file(
            manifest_path,
            "read evidence source bundle manifest",
            maximum=_MAX_SOURCE_MANIFEST_BYTES,
            require_root_owner=require_root_owner,
        )
        manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
        if not hmac.compare_digest(manifest_sha256, expected_manifest_sha256):
            raise ReadEvidenceIndexError(
                "read evidence source bundle manifest digest mismatch"
            )
        _validate_source_file_mode(
            manifest_path,
            "read evidence source bundle manifest",
            require_root_owner=require_root_owner,
        )
        _exact_fields(
            manifest,
            _SOURCE_MANIFEST_FIELDS,
            "read evidence source bundle manifest",
        )
        if manifest["schema_version"] != SOURCE_BUNDLE_SCHEMA:
            raise ReadEvidenceIndexError(
                "read evidence source bundle schema is invalid"
            )
        if manifest["bundle_id"] != bundle_id:
            raise ReadEvidenceIndexError(
                "read evidence source bundle identity mismatch"
            )
        if _release_identity(
            manifest["release_identity"],
            "read evidence source bundle release identity",
        ) != release_identity:
            raise ReadEvidenceIndexError(
                "read evidence source bundle release identity mismatch"
            )
        if _scope(
            manifest["scope"],
            "read evidence source bundle scope",
            release_identity=release_identity,
        ) != trusted_scope:
            raise ReadEvidenceIndexError(
                "read evidence source bundle scope mismatch"
            )
        _timestamp(manifest["collected_at"], "read evidence source collected_at")
        _identifier(manifest["collector_id"], "read evidence source collector_id")
        _digest(
            manifest["collector_sha256"],
            "read evidence source collector_sha256",
        )
        files = manifest["files"]
        if (
            type(files) is not list
            or not files
            or len(files) > _MAX_SOURCE_FILES
        ):
            raise ReadEvidenceIndexError(
                "read evidence source bundle files are invalid"
            )
        file_entries: dict[str, dict[str, Any]] = {}
        paths: list[str] = []
        declared_total = 0
        for index, raw_entry in enumerate(files):
            entry = _exact_fields(
                raw_entry,
                _SOURCE_FILE_FIELDS,
                f"read evidence source bundle file {index}",
            )
            relative = _relative_source_path(
                entry["path"], f"read evidence source bundle file {index} path"
            )
            size = _nonnegative_integer(
                entry["size"], f"read evidence source bundle file {index} size"
            )
            if size > _MAX_SOURCE_FILE_BYTES:
                raise ReadEvidenceIndexError(
                    "read evidence source bundle member exceeds its size limit"
                )
            _digest(
                entry["sha256"],
                f"read evidence source bundle file {index} sha256",
            )
            if relative in file_entries:
                raise ReadEvidenceIndexError(
                    "read evidence source bundle contains a duplicate path"
                )
            paths.append(relative)
            file_entries[relative] = entry
            declared_total += size
        if paths != sorted(paths):
            raise ReadEvidenceIndexError(
                "read evidence source bundle files must be sorted"
            )
        if declared_total > _MAX_SOURCE_TOTAL_BYTES:
            raise ReadEvidenceIndexError(
                "read evidence source bundle exceeds its total size limit"
            )
        cached_bytes = sum(
            len(snapshot.manifest_raw)
            + sum(len(raw) for raw in snapshot.member_payloads.values())
            for snapshot in cache.values()
        )
        if (
            cached_bytes + len(manifest_raw) + declared_total
            > _MAX_SOURCE_CACHE_BYTES
        ):
            raise ReadEvidenceIndexError(
                "read evidence source bundle aggregate cache size exceeds its limit"
            )
        expected_files = {"BUNDLE-MANIFEST.json", *file_entries}
        expected_directories = _expected_source_directories(set(file_entries))
        actual_files, actual_directories = _source_tree_files(
            bundle_root, require_root_owner=require_root_owner
        )
        if (
            actual_files != expected_files
            or actual_directories != expected_directories
        ):
            raise ReadEvidenceIndexError(
                "read evidence source bundle tree is not exact"
            )
        actual_total = 0
        member_payloads: dict[str, bytes] = {}
        for relative, entry in file_entries.items():
            member_path = bundle_root / PurePosixPath(relative)
            raw = _read_file_bytes(
                member_path,
                f"read evidence source bundle member {relative}",
                maximum=_MAX_SOURCE_FILE_BYTES,
                require_root_owner=require_root_owner,
            )
            _validate_source_file_mode(
                member_path,
                f"read evidence source bundle member {relative}",
                require_root_owner=require_root_owner,
            )
            actual_total += len(raw)
            if (
                len(raw) != entry["size"]
                or not hmac.compare_digest(
                    hashlib.sha256(raw).hexdigest(), entry["sha256"]
                )
            ):
                raise ReadEvidenceIndexError(
                    f"read evidence source bundle member {relative} mismatch"
                )
            member_payloads[relative] = raw
        if actual_total != declared_total:
            raise ReadEvidenceIndexError(
                "read evidence source bundle total size mismatch"
            )
        cached = _SourceSnapshot(
            root=bundle_root,
            manifest=manifest,
            manifest_raw=manifest_raw,
            manifest_sha256=manifest_sha256,
            file_entries=file_entries,
            member_payloads=member_payloads,
            expected_files=frozenset(expected_files),
            expected_directories=frozenset(expected_directories),
        )
        cache[cache_key] = cached
    if not hmac.compare_digest(cached.manifest_sha256, expected_manifest_sha256):
        raise ReadEvidenceIndexError(
            "read evidence source bundle manifest digest mismatch"
        )
    member_relative = _relative_source_path(
        source["evidence_member_path"],
        "read evidence source evidence_member_path",
    )
    expected_member_relative = f"artifacts/{capability_id}/{evidence_kind}.json"
    if member_relative != expected_member_relative:
        raise ReadEvidenceIndexError(
            "read evidence source member path is not capability-canonical"
        )
    member_entry = cached.file_entries.get(member_relative)
    if member_entry is None:
        raise ReadEvidenceIndexError(
            "read evidence source member is absent from the bundle manifest"
        )
    member_sha256 = _digest(
        source["evidence_member_sha256"],
        "read evidence source evidence_member_sha256",
    )
    if not hmac.compare_digest(member_entry["sha256"], member_sha256):
        raise ReadEvidenceIndexError("read evidence source member digest mismatch")
    member_raw = cached.member_payloads[member_relative]
    if not hmac.compare_digest(hashlib.sha256(member_raw).hexdigest(), member_sha256):
        raise ReadEvidenceIndexError("read evidence source member changed")
    member_payload = _strict_json_object(member_raw, "read evidence source member")
    if not _canonical_json_equal(member_payload, payload):
        raise ReadEvidenceIndexError(
            "read evidence artifact payload does not match its retained source member"
        )
    return cached.manifest, cached.manifest_sha256


def _reverify_source_snapshots(
    cache: dict[str, _SourceSnapshot], *, require_root_owner: bool
) -> None:
    for snapshot in cache.values():
        try:
            actual_files, actual_directories = _source_tree_files(
                snapshot.root, require_root_owner=require_root_owner
            )
            if (
                actual_files != set(snapshot.expected_files)
                or actual_directories != set(snapshot.expected_directories)
            ):
                raise ReadEvidenceIndexError("source bundle tree changed")
            manifest_path = snapshot.root / "BUNDLE-MANIFEST.json"
            manifest_raw = _read_file_bytes(
                manifest_path,
                "read evidence source bundle manifest",
                maximum=_MAX_SOURCE_MANIFEST_BYTES,
                require_root_owner=require_root_owner,
            )
            _validate_source_file_mode(
                manifest_path,
                "read evidence source bundle manifest",
                require_root_owner=require_root_owner,
            )
            if not hmac.compare_digest(manifest_raw, snapshot.manifest_raw):
                raise ReadEvidenceIndexError("source bundle manifest changed")
            for relative, expected_raw in snapshot.member_payloads.items():
                member_path = snapshot.root / PurePosixPath(relative)
                actual_raw = _read_file_bytes(
                    member_path,
                    f"read evidence source bundle member {relative}",
                    maximum=_MAX_SOURCE_FILE_BYTES,
                    require_root_owner=require_root_owner,
                )
                _validate_source_file_mode(
                    member_path,
                    f"read evidence source bundle member {relative}",
                    require_root_owner=require_root_owner,
                )
                if not hmac.compare_digest(actual_raw, expected_raw):
                    raise ReadEvidenceIndexError(
                        f"source bundle member {relative} changed"
                    )
        except ReadEvidenceIndexError as exc:
            raise ReadEvidenceIndexError(
                f"read evidence source bundle changed: {exc}"
            ) from exc


def _case_list(value: Any, label: str) -> list[dict[str, Any]]:
    payload = _exact_fields(value, _CASES_PAYLOAD_FIELDS, label)
    cases = payload["cases"]
    if type(cases) is not list or not cases or len(cases) > 64:
        raise ReadEvidenceIndexError(f"{label} cases are invalid")
    case_ids = [
        case.get("case_id") if type(case) is dict else None for case in cases
    ]
    if (
        any(
            type(case_id) is not str
            or _IDENTIFIER.fullmatch(case_id) is None
            for case_id in case_ids
        )
        or case_ids != sorted(set(case_ids))
    ):
        raise ReadEvidenceIndexError(
            f"{label} case IDs must be valid, sorted, and unique"
        )
    return cases


def _verify_read_case(
    value: Any,
    *,
    fields: frozenset[str],
    capability_id: str,
    parameters_field: str,
    scope: dict[str, Any],
    receipt_secret: bytes,
    consume_receipt: Any,
    collected_at: str,
) -> dict[str, Any]:
    case = _exact_fields(value, fields, "read evidence Odoo read case")
    case_id = _identifier(case["case_id"], "read evidence case_id")
    auth_token_id = _identifier(
        case["auth_token_id"], "read evidence auth_token_id"
    )
    parameters = case[parameters_field]
    result_body = case["result_body"]
    receipt = case["receipt"]
    if type(parameters) is not dict or type(result_body) is not dict:
        raise ReadEvidenceIndexError(
            "read evidence request parameters and result body must be objects"
        )
    if (
        "company_id" in parameters
        and parameters["company_id"] != scope["company_id"]
    ):
        raise ReadEvidenceIndexError(
            "read evidence request company does not match the trusted scope"
        )
    if type(receipt) is not dict:
        raise ReadEvidenceIndexError("read evidence receipt must be an object")
    page = result_body.get("page")
    record_count = page.get("total_count") if type(page) is dict else None
    if type(record_count) is not int or record_count < 0:
        raise ReadEvidenceIndexError(
            "read evidence result does not provide a valid page record count"
        )
    try:
        observed_at = datetime.fromisoformat(
            str(receipt.get("observed_at", "")).replace("Z", "+00:00")
        )
        collection_time = datetime.fromisoformat(
            collected_at.replace("Z", "+00:00")
        )
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("naive timestamp")
        verify_read_receipt(
            receipt,
            capability_id=capability_id,
            parameters=parameters,
            result_body=result_body,
            auth_token_id=auth_token_id,
            principal=scope["principal"],
            odoo_instance_id=scope["odoo_instance_id"],
            database_name=scope["database_name"],
            database_uuid=scope["database_uuid"],
            company_id=scope["company_id"],
            user_id=scope["user_id"],
            registry_digest=scope["registry_digest"],
            release_digest=scope["release_digest"],
            environment=scope["environment"],
            capability_channel=scope["capability_channel"],
            expected_record_count=record_count,
            now=collection_time.astimezone(timezone.utc),
            consume_receipt=consume_receipt,
            expected_key_id=scope["receipt_key_id"],
            secret=receipt_secret,
        )
    except (ReceiptError, TypeError, ValueError) as exc:
        raise ReadEvidenceIndexError(
            f"read evidence receipt verification failed: {exc}"
        ) from exc
    return {
        "case_id": case_id,
        "receipt_id": receipt["id"],
        "request_digest": receipt["request_digest"],
        "result_digest": receipt["result_digest"],
    }


def _verification_summary(
    kind: str, *, case_count: int, receipt_count: int
) -> dict[str, Any]:
    return {
        "independent_verifier_proven": False,
        "legacy_structural_case_count": case_count,
        "legacy_structural_checks_passed": True,
        "legacy_structural_receipt_count": receipt_count,
        "postgresql_read_proven": False,
        "postgresql_write_absence_proven": False,
        "real_odoo_read_proven": False,
        "real_odoo_write_absence_proven": False,
    }


def _validate_payload(
    payload: Any,
    *,
    kind: str,
    capability_id: str,
    capability_contract_sha256: str,
    release_identity: dict[str, Any],
    scope: dict[str, Any],
    receipt_secret: bytes,
    consume_receipt: Any,
    collected_at: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    verified_cases: list[dict[str, Any]] = []
    if kind == "live_odoo":
        cases = _case_list(payload, "live Odoo evidence payload")
        for raw_case in cases:
            verified_cases.append(
                _verify_read_case(
                    raw_case,
                    fields=_READ_CASE_FIELDS,
                    capability_id=capability_id,
                    parameters_field="parameters",
                    scope=scope,
                    receipt_secret=receipt_secret,
                    consume_receipt=consume_receipt,
                    collected_at=collected_at,
                )
            )
    elif kind == "accounting_oracle":
        cases = _case_list(payload, "accounting oracle evidence payload")
        for raw_case in cases:
            verified = _verify_read_case(
                raw_case,
                fields=_ORACLE_CASE_FIELDS,
                capability_id=capability_id,
                parameters_field="parameters",
                scope=scope,
                receipt_secret=receipt_secret,
                consume_receipt=consume_receipt,
                collected_at=collected_at,
            )
            oracle_result = raw_case["oracle_result"]
            if type(oracle_result) is not dict or _canonical_json(
                oracle_result
            ) != _canonical_json(raw_case["result_body"]):
                raise ReadEvidenceIndexError(
                    "accounting oracle result does not exactly match the signed Odoo result"
                )
            witness = _exact_fields(
                raw_case["postgresql_witness"],
                _ORACLE_WITNESS_FIELDS,
                "accounting oracle PostgreSQL witness",
            )
            _nonnegative_integer(
                witness["write_statement_count"],
                "accounting oracle write_statement_count",
            )
            if (
                witness["database_name"] != scope["database_name"]
                or witness["database_uuid"] != scope["database_uuid"]
                or witness["company_id"] != scope["company_id"]
                or witness["isolation_level"] != "repeatable_read"
                or witness["transaction_read_only"] is not True
                or witness["rolled_back"] is not True
                or witness["write_statement_count"] != 0
                or witness["pre_state_sha256"] != witness["post_state_sha256"]
                or witness["oracle_result_sha256"] != _json_digest(oracle_result)
            ):
                raise ReadEvidenceIndexError(
                    "accounting oracle PostgreSQL witness is not read-only and exact"
                )
            for field in (
                "oracle_result_sha256",
                "post_state_sha256",
                "pre_state_sha256",
                "query_sha256",
                "row_stream_sha256",
            ):
                _digest(witness[field], f"accounting oracle witness {field}")
            verified_cases.append(verified)
    elif kind == "pi_e2e":
        cases = _case_list(payload, "Pi E2E evidence payload")
        for raw_case in cases:
            case = _exact_fields(raw_case, _PI_CASE_FIELDS, "Pi E2E case")
            if (
                type(case["natural_language_request"]) is not str
                or not case["natural_language_request"].strip()
                or case["natural_language_request"]
                != case["natural_language_request"].strip()
                or len(case["natural_language_request"]) > 16_384
                or case["selected_capability_id"] != capability_id
                or type(case["collected_parameters"]) is not dict
                or not _canonical_json_equal(
                    case["collected_parameters"], case["cli_parameters"]
                )
                or case["event_order"] != list(_PI_EVENT_ORDER)
            ):
                raise ReadEvidenceIndexError(
                    "Pi E2E intent, selection, parameters, or event order is invalid"
                )
            verified = _verify_read_case(
                case,
                fields=_PI_CASE_FIELDS,
                capability_id=capability_id,
                parameters_field="cli_parameters",
                scope=scope,
                receipt_secret=receipt_secret,
                consume_receipt=consume_receipt,
                collected_at=collected_at,
            )
            if (
                _digest(
                    case["assistant_result_sha256"],
                    "Pi E2E assistant_result_sha256",
                )
                != _json_digest(case["result_body"])
                or _digest(
                    case["audit_receipt_sha256"],
                    "Pi E2E audit_receipt_sha256",
                )
                != _json_digest(case["receipt"])
            ):
                raise ReadEvidenceIndexError(
                    "Pi E2E final result or audit receipt binding is invalid"
                )
            verified_cases.append(verified)
    elif kind == "security_negative":
        cases = _case_list(payload, "security negative evidence payload")
        expected = list(_SECURITY_NEGATIVE_CASES)
        observed: list[tuple[str, str]] = []
        request_digests: set[str] = set()
        response_digests: set[str] = set()
        for raw_case in cases:
            case = _exact_fields(
                raw_case, _SECURITY_CASE_FIELDS, "security negative case"
            )
            case_id = _identifier(case["case_id"], "security negative case_id")
            expected_error = _identifier(
                case["expected_error_code"],
                "security negative expected_error_code",
            )
            observed_error = _identifier(
                case["observed_error_code"],
                "security negative observed_error_code",
            )
            request_sha256 = _digest(
                case["request_sha256"], "security negative request_sha256"
            )
            response_sha256 = _digest(
                case["response_sha256"], "security negative response_sha256"
            )
            _positive_integer(case["exit_code"], "security negative exit_code")
            for field in (
                "odoo_write_count",
                "postgresql_write_count",
                "receipt_count",
            ):
                _nonnegative_integer(
                    case[field], f"security negative {field}"
                )
            if (
                expected_error != observed_error
                or case["exit_code"] != 6
                or case["odoo_effect"] != "none"
                or case["odoo_write_count"] != 0
                or case["postgresql_write_count"] != 0
                or case["receipt_count"] != 0
                or request_sha256 == response_sha256
                or request_sha256 in request_digests
                or response_sha256 in response_digests
            ):
                raise ReadEvidenceIndexError(
                    "security negative case did not prove a side-effect-free rejection"
                )
            request_digests.add(request_sha256)
            response_digests.add(response_sha256)
            observed.append((case_id, expected_error))
        if observed != expected:
            raise ReadEvidenceIndexError(
                "security negative cases do not cover ACL, company, expiry, replay, and tampering"
            )
    elif kind == "release_identity":
        release_payload = _exact_fields(
            payload, _RELEASE_PAYLOAD_FIELDS, "release identity evidence payload"
        )
        expected_release_root = str(
            (
                Path("/opt/odoo-accounting-cli-v3/releases")
                / release_identity["release"]
            ).resolve()
        )
        expected = {
            "canonical_package_sha256": release_identity["package_sha256"],
            "capability_contract_sha256": capability_contract_sha256,
            "commit": release_identity["commit"],
            "registry_digest": release_identity["registry_digest"],
            "release": release_identity["release"],
            "release_manifest_identity_sha256": release_identity[
                "manifest_sha256"
            ],
            "release_root": expected_release_root,
            "version": release_identity["version"],
        }
        if release_payload != expected:
            raise ReadEvidenceIndexError(
                "release identity evidence does not match the executing release"
            )
        cases = [release_payload]
    else:
        raise ReadEvidenceIndexError("read evidence kind is unsupported")
    case_count = len(cases)
    receipt_count = len(verified_cases)
    return (
        _verification_summary(
            kind, case_count=case_count, receipt_count=receipt_count
        ),
        verified_cases,
    )


def _validate_artifact(
    value: Any,
    *,
    capability_id: str,
    capability_contract_sha256: str,
    evidence_kind: str,
    release_identity: dict[str, Any],
    trusted_scope: dict[str, Any],
    source_parent: Path,
    receipt_secret: bytes,
    consume_receipt: Any,
    require_root_owner: bool,
    source_cache: dict[str, _SourceSnapshot],
) -> tuple[dict[str, Any], dict[str, Any], str]:
    artifact = _exact_fields(value, _ARTIFACT_FIELDS, "read evidence artifact")
    if artifact["schema_version"] != ARTIFACT_SCHEMA:
        raise ReadEvidenceIndexError("read evidence artifact schema is invalid")
    if artifact["capability_id"] != capability_id:
        raise ReadEvidenceIndexError("read evidence artifact capability mismatch")
    if artifact["evidence_kind"] != evidence_kind:
        raise ReadEvidenceIndexError("read evidence artifact purpose mismatch")
    if artifact["capability_contract_sha256"] != capability_contract_sha256:
        raise ReadEvidenceIndexError(
            "read evidence artifact capability contract mismatch"
        )
    if _release_identity(
        artifact["release_identity"], "read evidence artifact release identity"
    ) != release_identity:
        raise ReadEvidenceIndexError("read evidence artifact release identity mismatch")
    if _scope(
        artifact["scope"],
        "read evidence artifact scope",
        release_identity=release_identity,
    ) != trusted_scope:
        raise ReadEvidenceIndexError("read evidence artifact trusted scope mismatch")
    payload = artifact["payload"]
    if type(payload) is not dict:
        raise ReadEvidenceIndexError("read evidence artifact payload must be an object")
    source_manifest, source_manifest_sha256 = _load_source_bundle(
        artifact["source"],
        payload=payload,
        capability_id=capability_id,
        evidence_kind=evidence_kind,
        release_identity=release_identity,
        trusted_scope=trusted_scope,
        source_parent=source_parent,
        require_root_owner=require_root_owner,
        cache=source_cache,
    )
    summary, verified_cases = _validate_payload(
        payload,
        kind=evidence_kind,
        capability_id=capability_id,
        capability_contract_sha256=capability_contract_sha256,
        release_identity=release_identity,
        scope=trusted_scope,
        receipt_secret=receipt_secret,
        consume_receipt=consume_receipt,
        collected_at=source_manifest["collected_at"],
    )
    return (
        summary,
        {
            "collected_at": source_manifest["collected_at"],
            "collector_id": source_manifest["collector_id"],
            "collector_sha256": source_manifest["collector_sha256"],
            "structurally_checked_cases": verified_cases,
        },
        source_manifest_sha256,
    )


def _validate_claims(
    value: Any,
    *,
    authority: dict[str, Any],
    artifact_sha256: str,
    capability_id: str,
    capability_contract_sha256: str,
    evidence_kind: str,
    release_identity: dict[str, Any],
    scope: dict[str, Any],
    source_bundle_manifest_sha256: str,
    summary: dict[str, Any],
    collected_at: str,
) -> dict[str, Any]:
    claims = _exact_fields(value, _CLAIM_FIELDS, "read evidence attestation claims")
    if claims["authority_id"] != authority["authority_id"]:
        raise ReadEvidenceIndexError("read evidence authority identity mismatch")
    if claims["evidence_kind"] != evidence_kind:
        raise ReadEvidenceIndexError("read evidence attestation purpose mismatch")
    if claims["artifact_sha256"] != artifact_sha256:
        raise ReadEvidenceIndexError("read evidence attestation artifact mismatch")
    if claims["capability_id"] != capability_id:
        raise ReadEvidenceIndexError("read evidence attestation capability mismatch")
    if claims["capability_contract_sha256"] != capability_contract_sha256:
        raise ReadEvidenceIndexError(
            "read evidence attestation capability contract mismatch"
        )
    for field in (
        "commit",
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
        "release",
        "version",
    ):
        if claims[field] != release_identity[field]:
            raise ReadEvidenceIndexError(
                f"read evidence attestation release {field} mismatch"
            )
    observed_at = _timestamp(claims["observed_at"], "read evidence observed_at")
    if observed_at != collected_at:
        raise ReadEvidenceIndexError(
            "read evidence attestation observation time mismatch"
        )
    verifier_id = _identifier(claims["verifier_id"], "read evidence verifier_id")
    verifier_sha256 = _digest(
        claims["verifier_sha256"], "read evidence verifier_sha256"
    )
    if (
        verifier_id != authority["verifier_id"]
        or verifier_sha256 != authority["verifier_sha256"]
    ):
        raise ReadEvidenceIndexError(
            "read evidence attestation verifier binding mismatch"
        )
    if claims["scope_sha256"] != _json_digest(scope):
        raise ReadEvidenceIndexError("read evidence attestation scope mismatch")
    if claims["source_bundle_manifest_sha256"] != source_bundle_manifest_sha256:
        raise ReadEvidenceIndexError(
            "read evidence attestation source bundle mismatch"
        )
    if claims["verification_summary_sha256"] != _json_digest(summary):
        raise ReadEvidenceIndexError(
            "read evidence attestation derived summary mismatch"
        )
    for field in (
        "scope_sha256",
        "source_bundle_manifest_sha256",
        "verification_summary_sha256",
    ):
        _digest(claims[field], f"read evidence attestation {field}")
    return claims


def _verify_attestation(
    document: dict[str, Any],
    *,
    authorities: dict[str, dict[str, Any]],
    artifact_sha256: str,
    capability_id: str,
    capability_contract_sha256: str,
    evidence_kind: str,
    release_identity: dict[str, Any],
    scope: dict[str, Any],
    source_bundle_manifest_sha256: str,
    summary: dict[str, Any],
    collected_at: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    attestation = _exact_fields(
        document, _ATTESTATION_FIELDS, "read evidence attestation"
    )
    if (
        attestation["schema_version"] != ATTESTATION_SCHEMA
        or attestation["algorithm"] != "hmac-sha256"
    ):
        raise ReadEvidenceIndexError("read evidence attestation envelope is invalid")
    key_id = _identifier(attestation["key_id"], "read evidence attestation key_id")
    authority = authorities.get(key_id)
    if authority is None:
        raise ReadEvidenceIndexError("read evidence attestation key is untrusted")
    if authority["evidence_kind"] != evidence_kind:
        raise ReadEvidenceIndexError("read evidence authority purpose mismatch")
    claims = _validate_claims(
        attestation["claims"],
        authority=authority,
        artifact_sha256=artifact_sha256,
        capability_id=capability_id,
        capability_contract_sha256=capability_contract_sha256,
        evidence_kind=evidence_kind,
        release_identity=release_identity,
        scope=scope,
        source_bundle_manifest_sha256=source_bundle_manifest_sha256,
        summary=summary,
        collected_at=collected_at,
    )
    signature = attestation["signature"]
    expected = hmac.new(
        authority["secret"],
        ATTESTATION_CONTEXT + _canonical_json(claims).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if (
        type(signature) is not str
        or _SHA256.fullmatch(signature) is None
        or not hmac.compare_digest(signature, expected)
    ):
        raise ReadEvidenceIndexError("read evidence attestation signature mismatch")
    return claims, authority


def _validate_capability_entry(
    value: Any,
    *,
    label: str,
    release_identity: dict[str, Any],
    trusted_scope: dict[str, Any],
) -> dict[str, Any]:
    capability = _exact_fields(value, _CAPABILITY_FIELDS, label)
    capability_id = capability["capability_id"]
    if type(capability_id) is not str or _CAPABILITY_ID.fullmatch(capability_id) is None:
        raise ReadEvidenceIndexError(f"{label} capability_id is invalid")
    if _scope(
        capability["scope"],
        f"{label} scope",
        release_identity=release_identity,
    ) != trusted_scope:
        raise ReadEvidenceIndexError(f"{label} does not match the trusted scope")
    return capability


def _exact_directory_entries(path: Path, expected: set[str], label: str) -> None:
    entries: Any = None
    actual: set[str] = set()
    try:
        entries = os.scandir(path)
        for entry in entries:
            actual.add(entry.name)
            if len(actual) > len(expected):
                raise ReadEvidenceIndexError(f"{label} file set is not exact")
    except ReadEvidenceIndexError:
        raise
    except OSError as exc:
        raise ReadEvidenceIndexError(f"{label} cannot be enumerated") from exc
    finally:
        close = getattr(entries, "close", None)
        if close is not None:
            close()
    if actual != expected:
        raise ReadEvidenceIndexError(f"{label} file set is not exact")


def verify_read_evidence_index(
    index_path: Path,
    *,
    expected_release_identity: dict[str, Any],
    expected_capability_contracts: dict[str, str],
    require_root_owner: bool = True,
    evidence_parent: Path = DEFAULT_EVIDENCE_PARENT,
    attestation_keys_parent: Path = DEFAULT_ATTESTATION_KEYS_PARENT,
    evidence_source_parent: Path = DEFAULT_EVIDENCE_SOURCE_PARENT,
    trusted_artifact_parent: Path = DEFAULT_TRUSTED_ARTIFACT_PARENT,
) -> dict[str, Any]:
    """Verify exact-release source evidence under a release-derived trust anchor."""

    index_path = Path(index_path)
    evidence_parent = _canonical_absolute_path(
        str(Path(evidence_parent)), "read evidence parent"
    )
    attestation_keys_parent = _canonical_absolute_path(
        str(Path(attestation_keys_parent)), "read evidence attestation keys parent"
    )
    evidence_source_parent = _canonical_absolute_path(
        str(Path(evidence_source_parent)), "read evidence source parent"
    )
    trusted_artifact_parent = _canonical_absolute_path(
        str(Path(trusted_artifact_parent)), "read evidence trusted artifact parent"
    )
    expected_identity = _release_identity(
        expected_release_identity, "expected release identity"
    )
    if type(expected_capability_contracts) is not dict or not expected_capability_contracts:
        raise ReadEvidenceIndexError(
            "expected read capability contracts must not be empty"
        )
    expected_ids = sorted(expected_capability_contracts)
    for capability_id in expected_ids:
        if type(capability_id) is not str or _CAPABILITY_ID.fullmatch(capability_id) is None:
            raise ReadEvidenceIndexError("expected read capability ID is invalid")
        _digest(
            expected_capability_contracts[capability_id],
            f"expected {capability_id} contract",
        )
    (
        trust_anchor,
        _anchor_raw,
        authority_bindings,
        _runtime,
        receipt_secret,
    ) = _load_trust_anchor(
        release_identity=expected_identity,
        trusted_artifact_parent=trusted_artifact_parent,
        attestation_keys_parent=attestation_keys_parent,
        evidence_source_parent=evidence_source_parent,
        require_root_owner=require_root_owner,
    )
    trusted_scope = trust_anchor["scope"]
    attestation_keys_path = Path(trust_anchor["attestation_keys_path"])
    source_parent = Path(trust_anchor["source_parent"])
    authorities, keys_raw = _load_authorities(
        attestation_keys_path,
        expected_sha256=trust_anchor["attestation_keys_sha256"],
        authority_bindings=authority_bindings,
        require_root_owner=require_root_owner,
    )
    index, index_raw = _read_json_file(
        index_path,
        "read evidence index",
        maximum=_MAX_INDEX_BYTES,
        require_root_owner=require_root_owner,
    )
    _exact_fields(index, _INDEX_FIELDS, "read evidence index")
    if index["schema_version"] != EVIDENCE_INDEX_SCHEMA:
        raise ReadEvidenceIndexError("read evidence index schema is invalid")
    release_identity = _release_identity(
        index["release_identity"], "read evidence index release identity"
    )
    if release_identity != expected_identity:
        raise ReadEvidenceIndexError("read evidence index release identity mismatch")
    evidence_root = _canonical_absolute_path(
        index["evidence_root"], "read evidence root"
    )
    if evidence_root.parent != evidence_parent:
        raise ReadEvidenceIndexError(
            "read evidence root must be a direct child of the canonical evidence parent"
        )
    if _IDENTIFIER.fullmatch(evidence_root.name) is None:
        raise ReadEvidenceIndexError("read evidence root run identity is invalid")
    _validate_directory(
        evidence_root,
        "read evidence root",
        require_root_owner=require_root_owner,
    )
    expected_index_path = evidence_root / "read-evidence-index.json"
    if os.path.normcase(str(index_path)) != os.path.normcase(str(expected_index_path)):
        raise ReadEvidenceIndexError(
            "read evidence index must be the canonical file inside its evidence root"
        )
    capabilities = index["capabilities"]
    if type(capabilities) is not list:
        raise ReadEvidenceIndexError("read evidence capabilities must be a list")
    capability_ids = [
        item.get("capability_id") if type(item) is dict else None
        for item in capabilities
    ]
    if capability_ids != expected_ids:
        raise ReadEvidenceIndexError(
            "read evidence capability IDs/order do not match the current registry"
        )
    expected_root_entries = {"read-evidence-index.json", *expected_ids}
    _exact_directory_entries(
        evidence_root, expected_root_entries, "read evidence root"
    )
    reports: list[dict[str, Any]] = []
    source_cache: dict[str, _SourceSnapshot] = {}
    consumed_receipts: dict[str, str] = {}

    def consume_receipt(
        receipt_id: str,
        request_digest: str,
        _observed_at: datetime,
        _now: datetime,
    ) -> bool:
        if receipt_id in consumed_receipts:
            return False
        consumed_receipts[receipt_id] = request_digest
        return True

    for capability_index, raw_capability in enumerate(capabilities):
        capability = _validate_capability_entry(
            raw_capability,
            label=f"read evidence capability {capability_index}",
            release_identity=release_identity,
            trusted_scope=trusted_scope,
        )
        capability_id = capability["capability_id"]
        capability_root = evidence_root / capability_id
        _validate_directory(
            capability_root,
            f"read evidence capability directory {capability_id}",
            require_root_owner=require_root_owner,
        )
        evidence_entries = capability["evidence"]
        if type(evidence_entries) is not list:
            raise ReadEvidenceIndexError(
                f"read evidence {capability_id} evidence must be a list"
            )
        kinds = [
            item.get("evidence_kind") if type(item) is dict else None
            for item in evidence_entries
        ]
        if kinds != list(REQUIRED_EVIDENCE_KINDS):
            raise ReadEvidenceIndexError(
                f"read evidence {capability_id} evidence kinds/order do not match the required evidence set"
            )
        expected_files: set[str] = set()
        artifact_digests: dict[str, str] = {}
        attestation_digests: dict[str, str] = {}
        authority_ids: dict[str, str] = {}
        verifier_ids: dict[str, str] = {}
        structural_audit_summaries: dict[str, dict[str, Any]] = {}
        source_bundle_digests: dict[str, str] = {}
        source_metadata: dict[str, dict[str, Any]] = {}
        for entry_index, raw_entry in enumerate(evidence_entries):
            entry = _exact_fields(
                raw_entry,
                _EVIDENCE_FIELDS,
                f"read evidence {capability_id} entry {entry_index}",
            )
            kind = entry["evidence_kind"]
            artifact_name = f"{kind}.artifact.json"
            attestation_name = f"{kind}.attestation.json"
            expected_files.update({artifact_name, attestation_name})
            artifact_path = capability_root / artifact_name
            attestation_path = capability_root / attestation_name
            if entry["artifact_path"] != str(artifact_path):
                raise ReadEvidenceIndexError(
                    f"read evidence {capability_id} {kind} artifact_path is not the canonical evidence path"
                )
            if entry["attestation_path"] != str(attestation_path):
                raise ReadEvidenceIndexError(
                    f"read evidence {capability_id} {kind} attestation_path is not the canonical evidence path"
                )
            expected_artifact_sha256 = _digest(
                entry["artifact_sha256"],
                f"read evidence {capability_id} {kind} artifact_sha256",
            )
            expected_attestation_sha256 = _digest(
                entry["attestation_sha256"],
                f"read evidence {capability_id} {kind} attestation_sha256",
            )
            artifact, artifact_raw = _read_json_file(
                artifact_path,
                f"read evidence {capability_id} {kind} artifact",
                maximum=_MAX_ARTIFACT_BYTES,
                require_root_owner=require_root_owner,
            )
            artifact_sha256 = hashlib.sha256(artifact_raw).hexdigest()
            if not hmac.compare_digest(
                artifact_sha256, expected_artifact_sha256
            ):
                raise ReadEvidenceIndexError(
                    f"read evidence {capability_id} {kind} artifact digest mismatch"
                )
            summary, retained_source, source_bundle_manifest_sha256 = (
                _validate_artifact(
                    artifact,
                    capability_id=capability_id,
                    capability_contract_sha256=expected_capability_contracts[
                        capability_id
                    ],
                    evidence_kind=kind,
                    release_identity=release_identity,
                    trusted_scope=trusted_scope,
                    source_parent=source_parent,
                    receipt_secret=receipt_secret,
                    consume_receipt=consume_receipt,
                    require_root_owner=require_root_owner,
                    source_cache=source_cache,
                )
            )
            attestation, attestation_raw = _read_json_file(
                attestation_path,
                f"read evidence {capability_id} {kind} attestation",
                maximum=_MAX_ATTESTATION_BYTES,
                require_root_owner=require_root_owner,
            )
            attestation_sha256 = hashlib.sha256(attestation_raw).hexdigest()
            if not hmac.compare_digest(
                attestation_sha256, expected_attestation_sha256
            ):
                raise ReadEvidenceIndexError(
                    f"read evidence {capability_id} {kind} attestation digest mismatch"
                )
            claims, authority = _verify_attestation(
                attestation,
                authorities=authorities,
                artifact_sha256=artifact_sha256,
                capability_id=capability_id,
                capability_contract_sha256=expected_capability_contracts[
                    capability_id
                ],
                evidence_kind=kind,
                release_identity=release_identity,
                scope=trusted_scope,
                source_bundle_manifest_sha256=source_bundle_manifest_sha256,
                summary=summary,
                collected_at=retained_source["collected_at"],
            )
            if (
                retained_source["collector_id"] == claims["verifier_id"]
                or retained_source["collector_sha256"]
                == claims["verifier_sha256"]
            ):
                raise ReadEvidenceIndexError(
                    "read evidence collector and verifier must be independent"
                )
            artifact_digests[kind] = artifact_sha256
            attestation_digests[kind] = attestation_sha256
            authority_ids[kind] = authority["authority_id"]
            verifier_ids[kind] = claims["verifier_id"]
            structural_audit_summaries[kind] = summary
            source_bundle_digests[kind] = source_bundle_manifest_sha256
            source_metadata[kind] = retained_source
        _exact_directory_entries(
            capability_root,
            expected_files,
            f"read evidence capability directory {capability_id}",
        )
        reports.append(
            {
                "artifact_digests": artifact_digests,
                "attestation_digests": attestation_digests,
                "authority_ids": authority_ids,
                "capability_contract_sha256": expected_capability_contracts[
                    capability_id
                ],
                "capability_id": capability_id,
                "scope": trusted_scope,
                "source_bundle_digests": source_bundle_digests,
                "source_metadata": source_metadata,
                "legacy_structural_audit_verified": True,
                "structurally_audited_evidence_kinds": list(
                    REQUIRED_EVIDENCE_KINDS
                ),
                "verified": False,
                "verified_evidence_kinds": [],
                "verifier_ids": verifier_ids,
                "structural_audit_summaries": structural_audit_summaries,
            }
        )
    _reverify_source_snapshots(
        source_cache, require_root_owner=require_root_owner
    )
    return {
        "attestation_keys_path": str(attestation_keys_path),
        "attestation_keys_sha256": hashlib.sha256(keys_raw).hexdigest(),
        "blockers": [LEGACY_V2_BLOCKER],
        "capabilities": reports,
        "evidence_root": str(evidence_root),
        "evidence_protocol": "hmac-v2",
        "external_read_evidence_verified": False,
        "goal_evidence_admissible": False,
        "index_kind": EVIDENCE_INDEX_SCHEMA,
        "index_path": str(index_path),
        "index_sha256": hashlib.sha256(index_raw).hexdigest(),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "release_identity": release_identity,
        "required_evidence_kinds": list(REQUIRED_EVIDENCE_KINDS),
        "scope": trusted_scope,
        "scope_sha256": _json_digest(trusted_scope),
        "trust_anchor_path": trust_anchor["anchor_path"],
        "trust_anchor_sha256": trust_anchor["anchor_sha256"],
        "read_runtime_config_path": trust_anchor["read_runtime_config_path"],
        "read_runtime_config_sha256": trust_anchor[
            "read_runtime_config_sha256"
        ],
        "legacy_v2_structural_audit_verified": True,
        "structurally_audited_capability_count": len(reports),
        "verified_capability_count": 0,
    }


__all__ = [
    "ATTESTATION_KEYS_SCHEMA",
    "ATTESTATION_SCHEMA",
    "ARTIFACT_SCHEMA",
    "DEFAULT_ATTESTATION_KEYS_PARENT",
    "DEFAULT_EVIDENCE_PARENT",
    "DEFAULT_EVIDENCE_SOURCE_PARENT",
    "DEFAULT_TRUSTED_ARTIFACT_PARENT",
    "EVIDENCE_INDEX_SCHEMA",
    "REQUIRED_EVIDENCE_KINDS",
    "ReadEvidenceIndexError",
    "SOURCE_BUNDLE_SCHEMA",
    "TRUST_ANCHOR_SCHEMA",
    "canonical_json_bytes",
    "create_read_evidence_attestation",
    "_private_mode_is_safe",
    "verify_read_evidence_index",
]

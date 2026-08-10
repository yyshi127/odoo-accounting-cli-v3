"""Fail-closed SSHSIG v3 read-evidence closure verification.

This module verifies the release, trust, authorization, detached-signature,
publication, and retained-file closure.  The current normalized raw adapters
do not prove the underlying Odoo/oracle/Pi facts, so a successful closure is
reported as cryptographically verified but not Goal-admissible.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Mapping

from .registry import PRODUCTION_READ_EVIDENCE, load_registry, registry_digest
from .release import ReleaseError, verify_manifest
from .sshsig import (
    SSHSigError,
    VERIFICATION_REPORT_FIELDS,
    verify_sshsig,
)


EVIDENCE_INDEX_SCHEMA = "odoo-accounting-cli-v3.read-evidence-index.v3"
TRUST_ANCHOR_SCHEMA = "odoo-accounting-cli-v3.read-evidence-trust-anchor.v3"
SCOPE_SCHEMA = "odoo-accounting-cli-v3.read-evidence-scope.v3"
AUTHORIZATION_SCHEMA = "odoo-accounting-cli-v3.read-evidence-authorization.v3"
COLLECTION_PLAN_SCHEMA = "odoo-accounting-cli-v3.read-evidence-collection-plan.v3"
RAW_MANIFEST_SCHEMA = "odoo-accounting-cli-v3.read-evidence-raw-manifest.v3"
RAW_EVIDENCE_SCHEMA = "odoo-accounting-cli-v3.read-evidence-raw.v3"
VERIFIER_REPORT_SCHEMA = "odoo-accounting-cli-v3.read-evidence-verifier-report.v3"
ACTIVE_ADMISSION_SCHEMA = "odoo-accounting-cli-v3.read-evidence-active-admission.v3"
ACTIVE_RECORD_SCHEMA = "odoo-accounting-cli-v3.read-evidence-active-record.v1"
LEGACY_V2_SCHEMA = "odoo-accounting-cli-v3.read-evidence-index.v2"

INDEX_FILENAME = "index.json"
SCOPE_FILENAME = "scope.json"
AUTHORIZATION_FILENAME = "authorization.json"
COLLECTION_PLAN_FILENAME = "collection-plan.json"
RAW_MANIFEST_FILENAME = "raw/raw-manifest.json"
ADMISSION_FILENAME = "active-admission.json"
REVOCATIONS_FILENAME = "revocations"

EVIDENCE_KINDS = tuple(sorted(PRODUCTION_READ_EVIDENCE))
ADMISSION_RELEASE_IDENTITY_FIELDS = (
    "commit",
    "manifest_sha256",
    "package_sha256",
    "registry_digest",
    "release",
)
RAW_SOURCE_ADAPTER_BLOCKER = (
    "raw source semantic adapters are incomplete; normalized signed claims "
    "are not Goal-admissible evidence"
)

MAX_INDEX_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_ANCHOR_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_JSON_STRING_BYTES = 1024 * 1024
MAX_RELATIVE_PATH_BYTES = 512
MAX_TREE_DEPTH = 8
MAX_TREE_FILES = 128
MAX_TREE_DIRECTORIES = 16
MAX_TREE_TOTAL_BYTES = 128 * 1024 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_CAPABILITY_ID = re.compile(r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_RFC3339 = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

_RELEASE_FIELDS = frozenset(
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
_FILE_REF_FIELDS = frozenset({"path", "sha256", "size"})
_SIGNED_REF_FIELDS = frozenset(
    {
        "path",
        "role",
        "sha256",
        "signature_path",
        "signature_sha256",
        "signature_size",
        "size",
    }
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
_SECURITY_CASES = (
    ("acl_deny", "odoo_acl_denied"),
    ("cross_company", "company_binding_rejected"),
    ("expired", "authentication_expired"),
    ("replay", "authentication_replayed"),
    ("tamper_parameters", "authentication_tampered"),
)


class ReadEvidenceV3Error(ValueError):
    """Raised when a v3 evidence closure is not independently trustworthy."""


@dataclass(frozen=True)
class RoleBinding:
    principal: str
    namespace: str


def _binding(role: str) -> RoleBinding:
    token = role.replace(".", "-").replace("_", "-")
    namespace = role.replace(".", "/")
    return RoleBinding(
        principal=f"odoo-read-evidence-v3-{token}",
        namespace=f"odoo-accounting-cli-v3/read-evidence-v3/{namespace}/v1",
    )


ROLE_BINDINGS: dict[str, RoleBinding] = {
    "admission": _binding("admission"),
    "authorization": _binding("authorization"),
    "collector": _binding("collector"),
    "scope": _binding("scope"),
    **{f"verifier.{kind}": _binding(f"verifier.{kind}") for kind in EVIDENCE_KINDS},
}


@dataclass(frozen=True)
class _ExecutionContext:
    active_record_path: Path
    admission_store_path: Path
    evidence_runs_root: Path
    identity: dict[str, Any]
    read_capability_contracts: dict[str, str]
    release_root: Path
    trust_anchor_path: Path
    trust_root: Path
    ssh_keygen_path: Path


@dataclass(frozen=True)
class _Snapshot:
    descriptor: int
    identity: tuple[int, ...]
    path: Path
    raw: bytes
    relative: str | None
    sha256: str


def _is_supported_linux() -> bool:
    return (
        os.name == "posix"
        and sys.platform.startswith("linux")
        and Path("/proc/self/fd").is_dir()
    )


def _require_linux_boundary() -> None:
    if not _is_supported_linux():
        raise ReadEvidenceV3Error(
            "read evidence v3 verification requires Linux POSIX /proc/self/fd"
        )
    if int(getattr(os, "O_NOFOLLOW", 0)) == 0:
        raise ReadEvidenceV3Error("read evidence v3 requires O_NOFOLLOW")


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReadEvidenceV3Error("value is not canonical JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadEvidenceV3Error(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ReadEvidenceV3Error(f"non-finite JSON number is forbidden: {value}")


def _check_json_complexity(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ReadEvidenceV3Error("read evidence JSON exceeds its node limit")
        if depth > MAX_JSON_DEPTH:
            raise ReadEvidenceV3Error("read evidence JSON exceeds its depth limit")
        if type(current) is str:
            if len(current.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise ReadEvidenceV3Error(
                    "read evidence JSON string exceeds its size limit"
                )
        elif type(current) is list:
            stack.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            for key, item in current.items():
                if type(key) is not str:
                    raise ReadEvidenceV3Error("JSON object key is invalid")
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
        elif type(current) is float:
            if not math.isfinite(current):
                raise ReadEvidenceV3Error("non-finite JSON number is forbidden")
        elif current is not None and type(current) not in {bool, int}:
            raise ReadEvidenceV3Error("JSON value type is invalid")


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ReadEvidenceV3Error:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ReadEvidenceV3Error(f"{label} is not valid JSON") from exc
    if type(value) is not dict:
        raise ReadEvidenceV3Error(f"{label} must be a JSON object")
    _check_json_complexity(value)
    return value


def _strict_json_object(raw: bytes, label: str) -> dict[str, Any]:
    value = _json_object(raw, label)
    if _canonical_json_bytes(value) != raw:
        raise ReadEvidenceV3Error(f"{label} must use canonical JSON")
    return value


def detect_read_evidence_schema(raw: bytes) -> Literal["v2", "v3", "invalid"]:
    """Classify bounded canonical index bytes without selecting a trust root."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_INDEX_BYTES:
        return "invalid"
    try:
        value = _strict_json_object(raw, "read evidence index")
    except ReadEvidenceV3Error:
        return "invalid"
    schema = value.get("schema_version")
    if schema == EVIDENCE_INDEX_SCHEMA:
        return "v3"
    if schema == LEGACY_V2_SCHEMA:
        return "v2"
    return "invalid"


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    stable_mode = (
        int(metadata.st_mode)
        if os.name == "posix"
        else int(stat.S_IFMT(metadata.st_mode))
    )
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stable_mode,
        int(metadata.st_nlink),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _validate_posix_path(path: Path, *, directory: bool) -> None:
    current = path
    first = True
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ReadEvidenceV3Error("root-managed path cannot be inspected") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ReadEvidenceV3Error("root-managed path must not contain a symbolic link")
        expected = stat.S_ISDIR(metadata.st_mode) if (directory or not first) else stat.S_ISREG(metadata.st_mode)
        if not expected:
            kind = "directory" if (directory or not first) else "file"
            raise ReadEvidenceV3Error(f"root-managed path component must be a {kind}")
        if metadata.st_uid != 0:
            raise ReadEvidenceV3Error("root-managed path must be owned by root")
        if stat.S_IMODE(metadata.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            raise ReadEvidenceV3Error(
                "root-managed path must not be group- or world-writable"
            )
        parent = current.parent
        if parent == current:
            break
        current = parent
        first = False


def _read_bounded_fd(descriptor: int, *, maximum: int, label: str) -> bytes:
    if type(maximum) is not int or maximum <= 0:
        raise ReadEvidenceV3Error(f"{label} exceeds its size limit")
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
        except OSError as exc:
            raise ReadEvidenceV3Error(f"{label} cannot be read safely") from exc
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ReadEvidenceV3Error(f"{label} exceeds its size limit")
    return b"".join(chunks)


def _open_snapshot(
    path: Path,
    *,
    maximum: int,
    label: str,
    relative: str | None = None,
) -> _Snapshot:
    _validate_posix_path(path, directory=False)
    try:
        before_path = path.lstat()
    except OSError as exc:
        raise ReadEvidenceV3Error(f"{label} cannot be inspected") from exc
    if stat.S_ISLNK(before_path.st_mode) or not stat.S_ISREG(before_path.st_mode):
        raise ReadEvidenceV3Error(f"{label} must be a regular non-link file")
    if before_path.st_nlink != 1:
        raise ReadEvidenceV3Error(f"{label} must be a stable single-link file")
    if before_path.st_size < 0 or before_path.st_size > maximum:
        raise ReadEvidenceV3Error(f"{label} exceeds its size limit")
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(
        getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReadEvidenceV3Error(f"{label} cannot be opened safely") from exc
    try:
        before_fd = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before_fd.st_mode)
            or before_fd.st_nlink != 1
            or _stat_identity(before_fd) != _stat_identity(before_path)
        ):
            raise ReadEvidenceV3Error(f"{label} changed before it was opened")
        raw = _read_bounded_fd(descriptor, maximum=maximum, label=label)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        identity = _stat_identity(before_fd)
        if (
            identity != _stat_identity(after_fd)
            or identity != _stat_identity(after_path)
            or len(raw) != before_fd.st_size
        ):
            raise ReadEvidenceV3Error(f"{label} changed while it was read")
        return _Snapshot(
            descriptor=descriptor,
            identity=identity,
            path=path,
            raw=raw,
            relative=relative,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    except BaseException:
        os.close(descriptor)
        raise


def _reverify_snapshot(snapshot: _Snapshot, label: str) -> None:
    try:
        descriptor_metadata = os.fstat(snapshot.descriptor)
        path_metadata = snapshot.path.lstat()
    except OSError as exc:
        raise ReadEvidenceV3Error(f"{label} cannot be reverified") from exc
    if (
        _stat_identity(descriptor_metadata) != snapshot.identity
        or _stat_identity(path_metadata) != snapshot.identity
    ):
        raise ReadEvidenceV3Error(f"{label} changed after verification")


def _close_snapshot(snapshot: _Snapshot) -> None:
    try:
        os.close(snapshot.descriptor)
    except OSError:
        pass


class _Closure:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.snapshots: dict[str, _Snapshot] = {}

    def read(self, relative: str, *, maximum: int, label: str) -> _Snapshot:
        relative = _relative_path(relative, label)
        existing = self.snapshots.get(relative)
        if existing is not None:
            if len(existing.raw) > maximum:
                raise ReadEvidenceV3Error(f"{label} exceeds its size limit")
            return existing
        portable = PurePosixPath(relative)
        snapshot = _open_snapshot(
            self.root.joinpath(*portable.parts),
            maximum=maximum,
            label=label,
            relative=relative,
        )
        self.snapshots[relative] = snapshot
        return snapshot

    def entries(self) -> list[dict[str, Any]]:
        return [
            {
                "path": relative,
                "sha256": snapshot.sha256,
                "size": len(snapshot.raw),
            }
            for relative, snapshot in sorted(self.snapshots.items())
        ]

    def reverify(self) -> None:
        for relative, snapshot in sorted(self.snapshots.items()):
            _reverify_snapshot(snapshot, f"closure file {relative}")

    def close(self) -> None:
        for snapshot in self.snapshots.values():
            _close_snapshot(snapshot)


def _exact_fields(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReadEvidenceV3Error(f"{label} must be an object")
    if set(value) != set(expected):
        raise ReadEvidenceV3Error(f"{label} fields are invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ReadEvidenceV3Error(f"{label} must be a lowercase SHA-256 digest")
    return value


def _positive(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ReadEvidenceV3Error(f"{label} must be a positive integer")
    return value


def _nonnegative(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ReadEvidenceV3Error(f"{label} must be a non-negative integer")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ReadEvidenceV3Error(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if type(value) is not str or _RFC3339.fullmatch(value) is None:
        raise ReadEvidenceV3Error(f"{label} must be canonical UTC RFC3339")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReadEvidenceV3Error(f"{label} must be canonical UTC RFC3339") from exc


def _relative_path(value: Any, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        raise ReadEvidenceV3Error(f"{label} must be a canonical relative path")
    if len(value.encode("utf-8")) > MAX_RELATIVE_PATH_BYTES:
        raise ReadEvidenceV3Error(f"{label} exceeds the relative path limit")
    portable = PurePosixPath(value)
    if (
        portable.is_absolute()
        or not portable.parts
        or len(portable.parts) > MAX_TREE_DEPTH
        or any(part in {"", ".", ".."} for part in portable.parts)
        or str(portable) != value
    ):
        raise ReadEvidenceV3Error(f"{label} must be a canonical relative path")
    return value


def _release_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _exact_fields(value, _RELEASE_FIELDS, label)
    if type(identity["commit"]) is not str or _COMMIT.fullmatch(identity["commit"]) is None:
        raise ReadEvidenceV3Error(f"{label} commit is invalid")
    for field in ("manifest_sha256", "package_sha256", "registry_digest"):
        _digest(identity[field], f"{label} {field}")
    if type(identity["release"]) is not str or _RELEASE.fullmatch(identity["release"]) is None:
        raise ReadEvidenceV3Error(f"{label} release is invalid")
    if type(identity["version"]) is not str or not identity["version"]:
        raise ReadEvidenceV3Error(f"{label} version is invalid")
    if identity["verified"] is not True:
        raise ReadEvidenceV3Error(f"{label} is not verified")
    return dict(identity)


def _admission_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _exact_fields(
        value, frozenset(ADMISSION_RELEASE_IDENTITY_FIELDS), label
    )
    if type(identity["commit"]) is not str or _COMMIT.fullmatch(identity["commit"]) is None:
        raise ReadEvidenceV3Error(f"{label} commit is invalid")
    for field in ("manifest_sha256", "package_sha256", "registry_digest"):
        _digest(identity[field], f"{label} {field}")
    if type(identity["release"]) is not str or _RELEASE.fullmatch(identity["release"]) is None:
        raise ReadEvidenceV3Error(f"{label} release is invalid")
    return dict(identity)


def _project_admission_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    return {field: identity[field] for field in ADMISSION_RELEASE_IDENTITY_FIELDS}


def _validate_contracts(value: Mapping[str, str]) -> dict[str, str]:
    if type(value) is not dict or not value:
        raise ReadEvidenceV3Error(
            "executing release read capability contracts must not be empty"
        )
    result: dict[str, str] = {}
    for capability_id in sorted(value):
        if type(capability_id) is not str or _CAPABILITY_ID.fullmatch(capability_id) is None:
            raise ReadEvidenceV3Error("executing release capability ID is invalid")
        result[capability_id] = _digest(
            value[capability_id], f"executing release {capability_id} contract"
        )
    return result


def _role_filename(role: str) -> str:
    if role not in ROLE_BINDINGS:
        raise ReadEvidenceV3Error("read evidence role is not fixed")
    return role.replace(".", "__") + ".allowed-signers"


def _one_off_json(path: Path, *, maximum: int, label: str, strict: bool) -> tuple[dict[str, Any], _Snapshot]:
    snapshot = _open_snapshot(path, maximum=maximum, label=label)
    try:
        value = (
            _strict_json_object(snapshot.raw, label)
            if strict
            else _json_object(snapshot.raw, label)
        )
        return value, snapshot
    except BaseException:
        _close_snapshot(snapshot)
        raise


def _load_execution_context() -> _ExecutionContext:
    from .read_evidence_admission import DEFAULT_READ_EVIDENCE_ADMISSION_PATH

    release_root = Path(__file__).resolve().parents[2]
    release = release_root.name
    if _RELEASE.fullmatch(release) is None:
        raise ReadEvidenceV3Error("executing release name is invalid")
    deployment_anchor_path = (
        release_root.parent.parent / "trusted-artifacts" / f"{release}.json"
    )
    manifest_path = release_root / "RELEASE-MANIFEST.json"
    anchor, anchor_snapshot = _one_off_json(
        deployment_anchor_path,
        maximum=MAX_ANCHOR_BYTES,
        label="executing release deployment anchor",
        strict=False,
    )
    manifest, manifest_snapshot = _one_off_json(
        manifest_path,
        maximum=MAX_INDEX_BYTES,
        label="executing release manifest",
        strict=False,
    )
    try:
        _exact_fields(
            anchor,
            frozenset({"commit", "manifest_sha256", "package_sha256", "release"}),
            "executing release deployment anchor",
        )
        if anchor["release"] != release or anchor["commit"] != manifest.get("commit"):
            raise ReadEvidenceV3Error("executing release deployment anchor mismatch")
        _digest(anchor["manifest_sha256"], "deployment manifest digest")
        _digest(anchor["package_sha256"], "deployment package digest")
        try:
            verify_manifest(
                release_root,
                manifest,
                expected_manifest_sha256=anchor["manifest_sha256"],
            )
            capabilities = load_registry(release_root / "registry" / "capabilities.json")
        except (OSError, ValueError, ReleaseError) as exc:
            raise ReadEvidenceV3Error("executing release integrity verification failed") from exc
        identity = {
            "commit": manifest["commit"],
            "manifest_sha256": manifest["manifest_sha256"],
            "package_sha256": anchor["package_sha256"],
            "registry_digest": registry_digest(capabilities),
            "release": release,
            "verified": True,
            "version": manifest["version"],
        }
        read_capability_contracts = {
            capability.id: hashlib.sha256(
                json.dumps(
                    capability.data,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            for capability in sorted(capabilities, key=lambda item: item.id)
            if capability.data["access"] == "read"
        }
    finally:
        _close_snapshot(anchor_snapshot)
        _close_snapshot(manifest_snapshot)
    evidence_root = Path("/var/lib/odoo-accounting-cli-v3/read-evidence-v3") / release
    return _ExecutionContext(
        active_record_path=evidence_root / "active.json",
        admission_store_path=DEFAULT_READ_EVIDENCE_ADMISSION_PATH,
        evidence_runs_root=evidence_root / "runs",
        identity=identity,
        read_capability_contracts=read_capability_contracts,
        release_root=release_root,
        trust_anchor_path=(
            Path("/opt/odoo-accounting-cli-v3/trusted-artifacts")
            / f"{release}.read-evidence-v3.json"
        ),
        trust_root=(
            Path("/etc/odoo-accounting-cli-v3/trust/read-evidence-v3") / release
        ),
        ssh_keygen_path=Path("/usr/bin/ssh-keygen"),
    )


def _tree_digest(entries: list[dict[str, Any]]) -> str:
    normalized = sorted(entries, key=lambda item: item["path"])
    return hashlib.sha256(_canonical_json_bytes(normalized)).hexdigest()


def _scan_tree(root: Path) -> tuple[set[str], set[str], int]:
    _validate_posix_path(root, directory=True)
    files: set[str] = set()
    directories: set[str] = set()
    total = 0
    stack: list[tuple[Path, PurePosixPath | None, int]] = [(root, None, 0)]
    while stack:
        directory, relative_root, depth = stack.pop()
        if depth > MAX_TREE_DEPTH:
            raise ReadEvidenceV3Error("read evidence tree exceeds its depth limit")
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise ReadEvidenceV3Error("read evidence tree cannot be enumerated") from exc
        for entry in entries:
            relative = (
                PurePosixPath(entry.name)
                if relative_root is None
                else relative_root / entry.name
            )
            relative_text = _relative_path(str(relative), "read evidence tree path")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ReadEvidenceV3Error("read evidence tree entry cannot be inspected") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ReadEvidenceV3Error("read evidence tree entry must be non-link")
            path = Path(entry.path)
            if stat.S_ISDIR(metadata.st_mode):
                _validate_posix_path(path, directory=True)
                directories.add(relative_text)
                if len(directories) > MAX_TREE_DIRECTORIES:
                    raise ReadEvidenceV3Error("read evidence tree has too many directories")
                stack.append((path, relative, depth + 1))
            elif stat.S_ISREG(metadata.st_mode):
                _validate_posix_path(path, directory=False)
                if os.name == "posix" and metadata.st_nlink != 1:
                    raise ReadEvidenceV3Error(
                        "read evidence tree files must be stable single-link files"
                    )
                files.add(relative_text)
                total += int(metadata.st_size)
                if len(files) > MAX_TREE_FILES:
                    raise ReadEvidenceV3Error("read evidence tree has too many files")
                if total > MAX_TREE_TOTAL_BYTES:
                    raise ReadEvidenceV3Error("read evidence tree exceeds its byte limit")
            else:
                raise ReadEvidenceV3Error("read evidence tree contains a special file")
    return files, directories, total


def _validate_location(
    index_path: Path, context: _ExecutionContext
) -> tuple[Path, str]:
    try:
        path = Path(index_path)
    except (TypeError, ValueError) as exc:
        raise ReadEvidenceV3Error("index path must be absolute and canonical") from exc
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ReadEvidenceV3Error("index path must be absolute and canonical")
    if path.name != INDEX_FILENAME:
        raise ReadEvidenceV3Error(f"v3 index filename must be {INDEX_FILENAME}")
    run_root = path.parent
    run_id = _identifier(run_root.name, "read evidence run_id")
    expected = context.evidence_runs_root / run_id / INDEX_FILENAME
    if os.path.normcase(str(path)) != os.path.normcase(str(expected)):
        raise ReadEvidenceV3Error(
            "active v3 index is not at the canonical active evidence path"
        )
    return run_root, run_id


def _load_trust_anchor(
    context: _ExecutionContext,
) -> tuple[dict[str, Any], _Snapshot]:
    anchor, snapshot = _one_off_json(
        context.trust_anchor_path,
        maximum=MAX_ANCHOR_BYTES,
        label="read evidence v3 trust anchor",
        strict=True,
    )
    try:
        _exact_fields(
            anchor,
            frozenset(
                {
                    "release_identity",
                    "revocations_sha256",
                    "roles",
                    "schema_version",
                    "ssh_keygen_sha256",
                }
            ),
            "read evidence v3 trust anchor",
        )
        if anchor["schema_version"] != TRUST_ANCHOR_SCHEMA:
            raise ReadEvidenceV3Error("read evidence v3 trust anchor schema is invalid")
        if _release_identity(anchor["release_identity"], "trust anchor release identity") != context.identity:
            raise ReadEvidenceV3Error("trust anchor executing release identity mismatch")
        _digest(anchor["ssh_keygen_sha256"], "trust anchor ssh-keygen digest")
        _digest(anchor["revocations_sha256"], "trust anchor revocations digest")
        roles = anchor["roles"]
        if type(roles) is not dict or set(roles) != set(ROLE_BINDINGS):
            raise ReadEvidenceV3Error("trust anchor roles are not the fixed role set")
        fingerprints: list[str] = []
        for role in ROLE_BINDINGS:
            record = _exact_fields(
                roles[role],
                frozenset({"allowed_signers_sha256", "public_key_sha256"}),
                f"trust anchor role {role}",
            )
            _digest(record["allowed_signers_sha256"], f"{role} allowed signers digest")
            fingerprints.append(
                _digest(record["public_key_sha256"], f"{role} public key fingerprint")
            )
        if len(set(fingerprints)) != len(ROLE_BINDINGS):
            raise ReadEvidenceV3Error("trust anchor role key fingerprints must be unique")
        return anchor, snapshot
    except BaseException:
        _close_snapshot(snapshot)
        raise


def _file_reference(
    closure: _Closure,
    value: Any,
    *,
    expected_path: str,
    maximum: int,
    label: str,
) -> _Snapshot:
    reference = _exact_fields(value, _FILE_REF_FIELDS, label)
    path = _relative_path(reference["path"], f"{label} path")
    if path != expected_path:
        raise ReadEvidenceV3Error(f"{label} relative path mismatch")
    expected_digest = _digest(reference["sha256"], f"{label} sha256")
    expected_size = _nonnegative(reference["size"], f"{label} size")
    snapshot = closure.read(path, maximum=maximum, label=label)
    if snapshot.sha256 != expected_digest:
        raise ReadEvidenceV3Error(f"{label} digest mismatch")
    if len(snapshot.raw) != expected_size:
        raise ReadEvidenceV3Error(f"{label} size mismatch")
    return snapshot


def _verify_signature(
    message: _Snapshot,
    signature: _Snapshot,
    *,
    role: str,
    anchor: dict[str, Any],
    context: _ExecutionContext,
) -> dict[str, Any]:
    binding = ROLE_BINDINGS[role]
    role_anchor = anchor["roles"][role]
    try:
        report = verify_sshsig(
            message.raw,
            ssh_keygen_path=context.ssh_keygen_path,
            ssh_keygen_sha256=anchor["ssh_keygen_sha256"],
            allowed_signers_path=context.trust_root / "roles" / _role_filename(role),
            allowed_signers_sha256=role_anchor["allowed_signers_sha256"],
            revocations_path=context.trust_root / REVOCATIONS_FILENAME,
            revocations_sha256=anchor["revocations_sha256"],
            signature_path=signature.path,
            signature_sha256=signature.sha256,
            principal=binding.principal,
            namespace=binding.namespace,
        )
    except SSHSigError as exc:
        raise ReadEvidenceV3Error(f"{role} detached SSHSIG verification failed") from exc
    if type(report) is not dict or frozenset(report) != VERIFICATION_REPORT_FIELDS:
        raise ReadEvidenceV3Error(f"{role} SSHSIG report fields are invalid")
    expected = {
        "allowed_signers_sha256": role_anchor["allowed_signers_sha256"],
        "message_sha256": message.sha256,
        "namespace": binding.namespace,
        "principal": binding.principal,
        "public_key_sha256": role_anchor["public_key_sha256"],
        "revocations_sha256": anchor["revocations_sha256"],
        "signature_sha256": signature.sha256,
        "ssh_keygen_sha256": anchor["ssh_keygen_sha256"],
    }
    if report.get("verified") is not True or any(
        report.get(field) != expected_value for field, expected_value in expected.items()
    ):
        raise ReadEvidenceV3Error(f"{role} SSHSIG trust binding mismatch")
    return report


def _signed_reference(
    closure: _Closure,
    value: Any,
    *,
    expected_path: str,
    expected_role: str,
    maximum: int,
    label: str,
    anchor: dict[str, Any],
    context: _ExecutionContext,
) -> tuple[_Snapshot, dict[str, Any]]:
    reference = _exact_fields(value, _SIGNED_REF_FIELDS, label)
    if reference["role"] != expected_role:
        raise ReadEvidenceV3Error(f"{label} role mismatch")
    message = _file_reference(
        closure,
        {field: reference[field] for field in _FILE_REF_FIELDS},
        expected_path=expected_path,
        maximum=maximum,
        label=label,
    )
    signature_path = _relative_path(
        reference["signature_path"], f"{label} signature path"
    )
    if signature_path != expected_path + ".sshsig":
        raise ReadEvidenceV3Error(f"{label} signature relative path mismatch")
    signature = closure.read(
        signature_path,
        maximum=MAX_SIGNATURE_BYTES,
        label=f"{label} signature",
    )
    if signature.sha256 != _digest(
        reference["signature_sha256"], f"{label} signature sha256"
    ):
        raise ReadEvidenceV3Error(f"{label} signature digest mismatch")
    if len(signature.raw) != _nonnegative(
        reference["signature_size"], f"{label} signature size"
    ):
        raise ReadEvidenceV3Error(f"{label} signature size mismatch")
    return message, _verify_signature(
        message,
        signature,
        role=expected_role,
        anchor=anchor,
        context=context,
    )


def _document(
    snapshot: _Snapshot,
    *,
    schema: str,
    fields: frozenset[str],
    label: str,
    identity: dict[str, Any],
    run_id: str,
) -> dict[str, Any]:
    value = _strict_json_object(snapshot.raw, label)
    _exact_fields(value, fields, label)
    if value["schema_version"] != schema:
        raise ReadEvidenceV3Error(f"{label} schema is invalid")
    if _release_identity(value["release_identity"], f"{label} release identity") != identity:
        raise ReadEvidenceV3Error(f"{label} release identity mismatch")
    if value["run_id"] != run_id:
        raise ReadEvidenceV3Error(f"{label} run_id mismatch")
    return value


def _validate_scope(
    value: dict[str, Any], *, identity: dict[str, Any], contracts: dict[str, str], run_id: str
) -> None:
    _exact_fields(
        value,
        frozenset(
            {
                "capability_contracts",
                "company_ids",
                "database_name",
                "database_uuid",
                "environment",
                "release_identity",
                "run_id",
                "schema_version",
            }
        ),
        "read evidence scope",
    )
    if value["schema_version"] != SCOPE_SCHEMA:
        raise ReadEvidenceV3Error("read evidence scope schema is invalid")
    if _release_identity(value["release_identity"], "scope release identity") != identity:
        raise ReadEvidenceV3Error("read evidence scope release identity mismatch")
    if value["run_id"] != run_id:
        raise ReadEvidenceV3Error("read evidence scope run_id mismatch")
    if value["capability_contracts"] != contracts:
        raise ReadEvidenceV3Error("read evidence scope capability contracts mismatch")
    companies = value["company_ids"]
    if type(companies) is not list or not companies:
        raise ReadEvidenceV3Error("read evidence scope company_ids are invalid")
    if any(type(item) is not int or item <= 0 for item in companies):
        raise ReadEvidenceV3Error("read evidence scope company_ids are invalid")
    if companies != sorted(companies) or len(set(companies)) != len(companies):
        raise ReadEvidenceV3Error("read evidence scope company_ids are invalid")
    if type(value["database_name"]) is not str or not value["database_name"]:
        raise ReadEvidenceV3Error("read evidence scope database_name is invalid")
    database_uuid = value["database_uuid"]
    if type(database_uuid) is not str or not database_uuid:
        raise ReadEvidenceV3Error("read evidence scope database_uuid is invalid")
    try:
        parsed_uuid = uuid.UUID(database_uuid)
    except (AttributeError, ValueError) as exc:
        raise ReadEvidenceV3Error("read evidence scope database_uuid is invalid") from exc
    if str(parsed_uuid) != database_uuid:
        raise ReadEvidenceV3Error("read evidence scope database_uuid is not canonical")
    environment = value["environment"]
    if type(environment) is not str or environment not in {
        "test",
        "sandbox",
        "production",
    }:
        raise ReadEvidenceV3Error("read evidence scope environment is invalid")


def _semantic_summary(
    raw: dict[str, Any],
    *,
    evidence_kind: str,
    identity: dict[str, Any],
    contracts: dict[str, str],
    run_id: str,
    scope: dict[str, Any],
    scope_sha256: str,
) -> dict[str, Any]:
    _exact_fields(
        raw,
        frozenset(
            {
                "capabilities",
                "evidence_kind",
                "release_identity",
                "run_id",
                "schema_version",
                "scope_sha256",
            }
        ),
        f"raw {evidence_kind}",
    )
    if raw["schema_version"] != RAW_EVIDENCE_SCHEMA or raw["evidence_kind"] != evidence_kind:
        raise ReadEvidenceV3Error(f"raw {evidence_kind} envelope is invalid")
    if _release_identity(raw["release_identity"], f"raw {evidence_kind} release identity") != identity:
        raise ReadEvidenceV3Error(f"raw {evidence_kind} release identity mismatch")
    if raw["run_id"] != run_id or raw["scope_sha256"] != scope_sha256:
        raise ReadEvidenceV3Error(f"raw {evidence_kind} scope/run binding mismatch")
    entries = raw["capabilities"]
    if type(entries) is not list:
        raise ReadEvidenceV3Error(f"raw {evidence_kind} capability contracts are invalid")
    ids = [item.get("capability_id") if type(item) is dict else None for item in entries]
    if ids != sorted(contracts):
        raise ReadEvidenceV3Error(f"raw {evidence_kind} capability contracts mismatch")
    summaries: list[dict[str, Any]] = []
    for entry in entries:
        _exact_fields(
            entry,
            frozenset({"capability_contract_sha256", "capability_id", "case"}),
            f"raw {evidence_kind} capability",
        )
        capability_id = entry["capability_id"]
        if entry["capability_contract_sha256"] != contracts[capability_id]:
            raise ReadEvidenceV3Error(f"raw {evidence_kind} capability contracts mismatch")
        case = entry["case"]
        if evidence_kind == "accounting_oracle":
            case = _exact_fields(
                case,
                frozenset(
                    {"actual_sha256", "difference_count", "expected_sha256", "input_sha256", "row_count"}
                ),
                "accounting oracle case",
            )
            for field in ("actual_sha256", "expected_sha256", "input_sha256"):
                _digest(case[field], f"accounting oracle {field}")
            if case["actual_sha256"] != case["expected_sha256"] or _nonnegative(case["difference_count"], "oracle difference_count") != 0:
                raise ReadEvidenceV3Error("accounting oracle expected/actual results differ")
            _nonnegative(case["row_count"], "oracle row_count")
        elif evidence_kind == "live_odoo":
            case = _exact_fields(
                case,
                frozenset(
                    {
                        "company_id", "database_uuid", "odoo_model", "odoo_write_count",
                        "read_only", "receipt_sha256", "record_count", "request_sha256", "response_sha256"
                    }
                ),
                "live Odoo case",
            )
            for field in ("receipt_sha256", "request_sha256", "response_sha256"):
                _digest(case[field], f"live Odoo {field}")
            company_id = _positive(case["company_id"], "live Odoo company_id")
            if (
                case["read_only"] is not True
                or _nonnegative(case["odoo_write_count"], "live Odoo write count") != 0
            ):
                raise ReadEvidenceV3Error("live Odoo case is not read-only")
            if company_id not in scope["company_ids"] or case["database_uuid"] != scope["database_uuid"]:
                raise ReadEvidenceV3Error("live Odoo case scope mismatch")
            if type(case["odoo_model"]) is not str or not case["odoo_model"]:
                raise ReadEvidenceV3Error("live Odoo model is invalid")
            _nonnegative(case["record_count"], "live Odoo record count")
        elif evidence_kind == "pi_e2e":
            case = _exact_fields(
                case,
                frozenset(
                    {
                        "audit_receipt_sha256", "cli_parameters_sha256", "event_order",
                        "natural_language_sha256", "odoo_result_sha256", "selected_capability_id"
                    }
                ),
                "Pi E2E case",
            )
            for field in (
                "audit_receipt_sha256", "cli_parameters_sha256", "natural_language_sha256", "odoo_result_sha256"
            ):
                _digest(case[field], f"Pi E2E {field}")
            if case["selected_capability_id"] != capability_id or case["event_order"] != list(_PI_EVENT_ORDER):
                raise ReadEvidenceV3Error("Pi E2E event/capability semantics mismatch")
        elif evidence_kind == "release_identity":
            case = _exact_fields(
                case,
                frozenset({"capability_contract_sha256", "observed_release_identity"}),
                "release identity case",
            )
            if case["capability_contract_sha256"] != contracts[capability_id] or _release_identity(case["observed_release_identity"], "observed release identity") != identity:
                raise ReadEvidenceV3Error("release identity case mismatch")
        elif evidence_kind == "security_negative":
            case = _exact_fields(case, frozenset({"cases"}), "security negative capability")
            cases = case["cases"]
            if type(cases) is not list or len(cases) != len(_SECURITY_CASES):
                raise ReadEvidenceV3Error("security negative cases are incomplete")
            for observed, (case_id, expected_code) in zip(cases, _SECURITY_CASES, strict=True):
                observed = _exact_fields(
                    observed,
                    frozenset(
                        {
                            "case_id", "expected_error_code", "observed_error_code",
                            "odoo_write_count", "postgresql_write_count", "receipt_count"
                        }
                    ),
                    "security negative case",
                )
                if observed["case_id"] != case_id or observed["expected_error_code"] != expected_code or observed["observed_error_code"] != expected_code:
                    raise ReadEvidenceV3Error("security negative case result mismatch")
                if any(
                    _nonnegative(observed[field], f"security negative {field}") != 0
                    for field in ("odoo_write_count", "postgresql_write_count", "receipt_count")
                ):
                    raise ReadEvidenceV3Error("security negative case has a side effect")
        else:
            raise ReadEvidenceV3Error("unsupported evidence kind")
        summaries.append(
            {
                "capability_contract_sha256": contracts[capability_id],
                "capability_id": capability_id,
                "case_sha256": hashlib.sha256(_canonical_json_bytes(case)).hexdigest(),
            }
        )
    return {"capabilities": summaries, "evidence_kind": evidence_kind}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _lookup_published_admission(
    context: _ExecutionContext,
    *,
    authorization_id: str,
    payload_sha256: str,
    sequence: int,
    admission_signature_sha256: str,
) -> Mapping[str, Any]:
    try:
        from .read_evidence_admission import SQLiteReadEvidenceAdmissionStore
    except (ImportError, AttributeError) as exc:
        raise ReadEvidenceV3Error("admission publication ledger is unavailable") from exc
    try:
        store = SQLiteReadEvidenceAdmissionStore.open_existing(
            context.admission_store_path
        )
        decision = store.require_published(
            authorization_id=authorization_id,
            payload_sha256=payload_sha256,
            sequence=sequence,
            admission_signature_sha256=admission_signature_sha256,
        )
        payload = decision.payload
        published_at = decision.published_at
        return {
            "admission_signature_path": decision.admission_signature_path,
            "admission_signature_sha256": decision.admission_signature_sha256,
            "admission_signature_size": decision.admission_signature_size,
            "authorization_id": payload.get("authorization_id"),
            "payload_sha256": decision.payload_sha256,
            "publication_state": decision.state.name,
            "published_at": (
                published_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                if published_at is not None
                else None
            ),
            "sequence": decision.sequence,
        }
    except Exception as exc:
        raise ReadEvidenceV3Error("admission publication ledger lookup failed") from exc


def _verify_active_publication(
    context: _ExecutionContext,
    *,
    admission: dict[str, Any],
    admission_snapshot: _Snapshot,
    admission_signature: _Snapshot,
    index_snapshot: _Snapshot,
    now: datetime,
) -> _Snapshot:
    active, active_snapshot = _one_off_json(
        context.active_record_path,
        maximum=MAX_JSON_BYTES,
        label="read evidence active record",
        strict=True,
    )
    try:
        _exact_fields(
            active,
            frozenset(
                {
                    "admission_sha256", "index_sha256", "payload_sha256",
                    "release_identity", "run_id", "schema_version", "sequence"
                }
            ),
            "read evidence active record",
        )
        if active["schema_version"] != ACTIVE_RECORD_SCHEMA:
            raise ReadEvidenceV3Error("read evidence active record schema mismatch")
        _positive(active["sequence"], "active record sequence")
        expected_active = {
            "admission_sha256": admission_snapshot.sha256,
            "index_sha256": index_snapshot.sha256,
            "payload_sha256": admission_snapshot.sha256,
            "release_identity": admission["release_identity"],
            "run_id": admission["run_id"],
            "sequence": admission["sequence"],
        }
        if any(active.get(field) != expected for field, expected in expected_active.items()):
            raise ReadEvidenceV3Error("read evidence active record binding mismatch")
        publication = _lookup_published_admission(
            context,
            authorization_id=admission["authorization_id"],
            payload_sha256=admission_snapshot.sha256,
            sequence=admission["sequence"],
            admission_signature_sha256=admission_signature.sha256,
        )
        required = {
            "admission_signature_path", "admission_signature_sha256",
            "admission_signature_size", "authorization_id", "payload_sha256",
            "publication_state", "published_at", "sequence"
        }
        if type(publication) is not dict:
            raise ReadEvidenceV3Error("admission publication binding fields are invalid")
        if publication.get("publication_state") != "PUBLISHED":
            raise ReadEvidenceV3Error("admission ledger row is not PUBLISHED")
        if set(publication) != required:
            raise ReadEvidenceV3Error("admission publication binding fields are invalid")
        _positive(
            publication["admission_signature_size"],
            "admission publication signature size",
        )
        _positive(publication["sequence"], "admission publication sequence")
        expected_publication = {
            "admission_signature_path": f"{ADMISSION_FILENAME}.sshsig",
            "admission_signature_sha256": admission_signature.sha256,
            "admission_signature_size": len(admission_signature.raw),
            "authorization_id": admission["authorization_id"],
            "payload_sha256": admission_snapshot.sha256,
            "sequence": admission["sequence"],
        }
        if any(publication.get(field) != expected for field, expected in expected_publication.items()):
            raise ReadEvidenceV3Error("admission publication binding mismatch")
        published_at = _timestamp(publication["published_at"], "admission published_at")
        if not (
            _timestamp(admission["admitted_at"], "admitted_at")
            <= published_at
            <= now
        ):
            raise ReadEvidenceV3Error("admission publication timestamp is invalid")
        return active_snapshot
    except BaseException:
        _close_snapshot(active_snapshot)
        raise


def verify_read_evidence_v3(
    index_path: Path,
    *,
    expected_release_identity: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify the exact active SSHSIG closure under executing-release trust."""

    _require_linux_boundary()
    context = _load_execution_context()
    executing_identity = _release_identity(context.identity, "executing release identity")
    asserted_identity = _release_identity(
        expected_release_identity, "expected release identity"
    )
    if asserted_identity != executing_identity:
        raise ReadEvidenceV3Error(
            "expected identity does not match the executing release"
        )
    contracts = _validate_contracts(context.read_capability_contracts)
    run_root, run_id = _validate_location(Path(index_path), context)
    closure = _Closure(run_root)
    anchor_snapshot: _Snapshot | None = None
    active_snapshot: _Snapshot | None = None
    try:
        anchor, anchor_snapshot = _load_trust_anchor(context)
        index_snapshot = closure.read(
            INDEX_FILENAME, maximum=MAX_INDEX_BYTES, label="read evidence v3 index"
        )
        index = _strict_json_object(index_snapshot.raw, "read evidence v3 index")
        _exact_fields(
            index,
            frozenset(
                {
                    "admission_path", "authorization", "closure_paths",
                    "collection_plan", "raw_manifest", "release_identity", "run_id",
                    "schema_version", "scope", "verifier_reports"
                }
            ),
            "read evidence v3 index",
        )
        if index["schema_version"] != EVIDENCE_INDEX_SCHEMA:
            raise ReadEvidenceV3Error("read evidence v3 index schema is invalid")
        if _release_identity(index["release_identity"], "index release identity") != executing_identity:
            raise ReadEvidenceV3Error("read evidence v3 index release identity mismatch")
        if index["run_id"] != run_id:
            raise ReadEvidenceV3Error("read evidence v3 index run_id mismatch")
        if index["admission_path"] != ADMISSION_FILENAME:
            raise ReadEvidenceV3Error("read evidence admission relative path mismatch")

        scope_snapshot, _ = _signed_reference(
            closure, index["scope"], expected_path=SCOPE_FILENAME,
            expected_role="scope", maximum=MAX_JSON_BYTES, label="read evidence scope",
            anchor=anchor, context=context,
        )
        scope = _strict_json_object(scope_snapshot.raw, "read evidence scope")
        _validate_scope(scope, identity=executing_identity, contracts=contracts, run_id=run_id)
        scope_sha256 = scope_snapshot.sha256

        authorization_snapshot, _ = _signed_reference(
            closure, index["authorization"], expected_path=AUTHORIZATION_FILENAME,
            expected_role="authorization", maximum=MAX_JSON_BYTES,
            label="read evidence authorization", anchor=anchor, context=context,
        )
        authorization = _document(
            authorization_snapshot,
            schema=AUTHORIZATION_SCHEMA,
            fields=frozenset(
                {
                    "authorization_id", "collector_role", "expires_at", "nonce_sha256",
                    "not_before", "release_identity", "run_id", "schema_version",
                    "scope_sha256", "verifier_roles"
                }
            ),
            label="read evidence authorization", identity=executing_identity, run_id=run_id,
        )
        authorization_id = _identifier(authorization["authorization_id"], "authorization_id")
        _digest(authorization["nonce_sha256"], "authorization nonce_sha256")
        if authorization["scope_sha256"] != scope_sha256:
            raise ReadEvidenceV3Error("authorization scope digest mismatch")
        if authorization["collector_role"] != "collector" or authorization["verifier_roles"] != {
            kind: f"verifier.{kind}" for kind in EVIDENCE_KINDS
        }:
            raise ReadEvidenceV3Error("authorization role bindings are invalid")
        not_before = _timestamp(authorization["not_before"], "authorization not_before")
        expires_at = _timestamp(authorization["expires_at"], "authorization expires_at")
        if not_before >= expires_at:
            raise ReadEvidenceV3Error("authorization time window is invalid")

        plan_snapshot, _ = _signed_reference(
            closure, index["collection_plan"], expected_path=COLLECTION_PLAN_FILENAME,
            expected_role="collector", maximum=MAX_JSON_BYTES,
            label="read evidence collection plan", anchor=anchor, context=context,
        )
        plan = _document(
            plan_snapshot,
            schema=COLLECTION_PLAN_SCHEMA,
            fields=frozenset(
                {
                    "authorization_sha256", "expected_raw_paths", "release_identity",
                    "run_id", "schema_version", "scope_sha256"
                }
            ),
            label="read evidence collection plan", identity=executing_identity, run_id=run_id,
        )
        raw_paths = [f"raw/{kind}.json" for kind in EVIDENCE_KINDS]
        if (
            plan["authorization_sha256"] != authorization_snapshot.sha256
            or plan["scope_sha256"] != scope_sha256
            or plan["expected_raw_paths"] != raw_paths
        ):
            raise ReadEvidenceV3Error("collection plan binding mismatch")

        raw_manifest_snapshot, _ = _signed_reference(
            closure, index["raw_manifest"], expected_path=RAW_MANIFEST_FILENAME,
            expected_role="collector", maximum=MAX_JSON_BYTES,
            label="read evidence raw manifest", anchor=anchor, context=context,
        )
        raw_manifest = _document(
            raw_manifest_snapshot,
            schema=RAW_MANIFEST_SCHEMA,
            fields=frozenset(
                {
                    "authorization_sha256", "collection_plan_sha256", "files",
                    "release_identity", "run_id", "schema_version", "scope_sha256"
                }
            ),
            label="read evidence raw manifest", identity=executing_identity, run_id=run_id,
        )
        if (
            raw_manifest["authorization_sha256"] != authorization_snapshot.sha256
            or raw_manifest["collection_plan_sha256"] != plan_snapshot.sha256
            or raw_manifest["scope_sha256"] != scope_sha256
        ):
            raise ReadEvidenceV3Error("raw manifest binding mismatch")
        raw_refs = raw_manifest["files"]
        if type(raw_refs) is not list or len(raw_refs) != len(EVIDENCE_KINDS):
            raise ReadEvidenceV3Error("raw manifest file set is invalid")
        raw_snapshots: dict[str, _Snapshot] = {}
        raw_summaries: dict[str, dict[str, Any]] = {}
        for kind, raw_path, raw_ref in zip(EVIDENCE_KINDS, raw_paths, raw_refs, strict=True):
            raw_snapshot = _file_reference(
                closure, raw_ref, expected_path=raw_path, maximum=MAX_RAW_BYTES,
                label=f"raw evidence {kind}",
            )
            raw_snapshots[kind] = raw_snapshot
            raw_summaries[kind] = _semantic_summary(
                _strict_json_object(raw_snapshot.raw, f"raw evidence {kind}"),
                evidence_kind=kind, identity=executing_identity, contracts=contracts,
                run_id=run_id, scope=scope, scope_sha256=scope_sha256,
            )

        verifier_refs = index["verifier_reports"]
        if type(verifier_refs) is not list:
            raise ReadEvidenceV3Error("verifier evidence kinds/order are invalid")
        kinds = [item.get("evidence_kind") if type(item) is dict else None for item in verifier_refs]
        if kinds != list(EVIDENCE_KINDS):
            raise ReadEvidenceV3Error("verifier evidence kinds/order are invalid")
        for kind, raw_path, reference in zip(EVIDENCE_KINDS, raw_paths, verifier_refs, strict=True):
            reference_fields = frozenset({"evidence_kind", *_SIGNED_REF_FIELDS})
            _exact_fields(reference, reference_fields, f"verifier report reference {kind}")
            signed_reference = {field: reference[field] for field in _SIGNED_REF_FIELDS}
            report_path = f"verifiers/{kind}.json"
            report_snapshot, _ = _signed_reference(
                closure, signed_reference, expected_path=report_path,
                expected_role=f"verifier.{kind}", maximum=MAX_JSON_BYTES,
                label=f"verifier report {kind}", anchor=anchor, context=context,
            )
            report = _document(
                report_snapshot,
                schema=VERIFIER_REPORT_SCHEMA,
                fields=frozenset(
                    {
                        "authorization_sha256", "collection_plan_sha256", "evidence_kind",
                        "raw_manifest_sha256", "raw_path", "raw_sha256", "raw_size",
                        "release_identity", "run_id", "schema_version", "scope_sha256",
                        "verification_summary"
                    }
                ),
                label=f"verifier report {kind}", identity=executing_identity, run_id=run_id,
            )
            if (
                report["evidence_kind"] != kind
                or report["authorization_sha256"] != authorization_snapshot.sha256
                or report["collection_plan_sha256"] != plan_snapshot.sha256
                or report["raw_manifest_sha256"] != raw_manifest_snapshot.sha256
                or report["scope_sha256"] != scope_sha256
                or report["raw_path"] != raw_path
                or report["raw_sha256"] != raw_snapshots[kind].sha256
                or _positive(
                    report["raw_size"], f"verifier report {kind} raw_size"
                )
                != len(raw_snapshots[kind].raw)
            ):
                raise ReadEvidenceV3Error(f"verifier report {kind} binding mismatch")
            if report["verification_summary"] != raw_summaries[kind]:
                raise ReadEvidenceV3Error(
                    f"verifier report {kind} does not match the recomputed summary"
                )

        index_signature = closure.read(
            f"{INDEX_FILENAME}.sshsig", maximum=MAX_SIGNATURE_BYTES,
            label="read evidence index signature",
        )
        _verify_signature(
            index_snapshot, index_signature, role="collector", anchor=anchor, context=context
        )
        pre_entries = closure.entries()
        pre_paths = [item["path"] for item in pre_entries]
        declared_paths = index["closure_paths"]
        if (
            type(declared_paths) is not list
            or declared_paths != sorted(set(declared_paths))
            or declared_paths != pre_paths
        ):
            raise ReadEvidenceV3Error("index pre-admission closure paths mismatch")
        pre_tree = _tree_digest(pre_entries)
        pre_total = sum(item["size"] for item in pre_entries)

        admission_snapshot = closure.read(
            ADMISSION_FILENAME, maximum=MAX_JSON_BYTES,
            label="read evidence active admission",
        )
        admission = _strict_json_object(
            admission_snapshot.raw, "read evidence active admission"
        )
        _exact_fields(
            admission,
            frozenset(
                {
                    "admitted_at", "authorization_id", "authorization_sha256",
                    "closure_file_count", "closure_total_bytes", "closure_tree_sha256",
                    "index_path", "index_sha256", "index_signature_path",
                    "index_signature_sha256", "index_signature_size", "index_size",
                    "nonce_sha256", "release_identity", "run_id", "schema_version",
                    "scope_sha256", "sequence"
                }
            ),
            "read evidence active admission",
        )
        if admission["schema_version"] != ACTIVE_ADMISSION_SCHEMA:
            raise ReadEvidenceV3Error("active admission schema is invalid")
        if _admission_identity(admission["release_identity"], "admission release identity") != _project_admission_identity(executing_identity):
            raise ReadEvidenceV3Error("active admission release identity mismatch")
        admitted_at = _timestamp(admission["admitted_at"], "admitted_at")
        if not (not_before <= admitted_at < expires_at):
            raise ReadEvidenceV3Error("admitted_at is outside the authorization window")
        for field in (
            "closure_file_count",
            "closure_total_bytes",
            "index_signature_size",
            "index_size",
        ):
            _positive(admission[field], f"active admission {field}")
        expected_admission = {
            "authorization_id": authorization_id,
            "authorization_sha256": authorization_snapshot.sha256,
            "closure_file_count": len(pre_entries),
            "closure_total_bytes": pre_total,
            "closure_tree_sha256": pre_tree,
            "index_path": INDEX_FILENAME,
            "index_sha256": index_snapshot.sha256,
            "index_signature_path": f"{INDEX_FILENAME}.sshsig",
            "index_signature_sha256": index_signature.sha256,
            "index_signature_size": len(index_signature.raw),
            "index_size": len(index_snapshot.raw),
            "nonce_sha256": authorization["nonce_sha256"],
            "run_id": run_id,
            "scope_sha256": scope_sha256,
        }
        if any(admission.get(field) != expected for field, expected in expected_admission.items()):
            raise ReadEvidenceV3Error("active admission closure binding mismatch")
        _positive(admission["sequence"], "admission sequence")
        admission_signature = closure.read(
            f"{ADMISSION_FILENAME}.sshsig", maximum=MAX_SIGNATURE_BYTES,
            label="read evidence admission signature",
        )
        _verify_signature(
            admission_snapshot, admission_signature, role="admission",
            anchor=anchor, context=context,
        )
        now = _utc_now()
        if now < not_before or now >= expires_at:
            raise ReadEvidenceV3Error("active read evidence authorization has expired")
        active_snapshot = _verify_active_publication(
            context,
            admission=admission,
            admission_snapshot=admission_snapshot,
            admission_signature=admission_signature,
            index_snapshot=index_snapshot,
            now=now,
        )

        final_entries = closure.entries()
        expected_files = {item["path"] for item in final_entries}
        observed_files, observed_directories, _ = _scan_tree(run_root)
        if observed_files != expected_files:
            raise ReadEvidenceV3Error("read evidence closure file set is not exact")
        expected_directories = {
            str(parent)
            for path in expected_files
            for parent in PurePosixPath(path).parents
            if str(parent) != "."
        }
        if observed_directories != expected_directories:
            raise ReadEvidenceV3Error("read evidence closure directory set is not exact")
        closure.reverify()
        final_files, final_directories, _ = _scan_tree(run_root)
        if final_files != expected_files or final_directories != expected_directories:
            raise ReadEvidenceV3Error(
                "read evidence closure changed during final verification"
            )
        _reverify_snapshot(anchor_snapshot, "read evidence v3 trust anchor")
        if active_snapshot is not None:
            _reverify_snapshot(active_snapshot, "read evidence active record")
        final_tree = _tree_digest(final_entries)
        capabilities = [
            {
                "capability_contract_sha256": contract,
                "capability_id": capability_id,
                "signed_evidence_kinds": list(EVIDENCE_KINDS),
                "verified": False,
                "verified_evidence_kinds": [],
            }
            for capability_id, contract in contracts.items()
        ]
        return {
            "admission_path": str(run_root / ADMISSION_FILENAME),
            "admission_sha256": admission_snapshot.sha256,
            "admitted_closure_file_count": len(pre_entries),
            "admitted_closure_total_bytes": pre_total,
            "admitted_closure_tree_sha256": pre_tree,
            "blockers": [RAW_SOURCE_ADAPTER_BLOCKER],
            "capabilities": capabilities,
            "closure_files": final_entries,
            "closure_tree_sha256": final_tree,
            "cryptographic_closure_verified": True,
            "cryptographically_verified_evidence_kinds": list(EVIDENCE_KINDS),
            "evidence_protocol": "sshsig-v3",
            "external_read_evidence_verified": False,
            "file_count": len(final_entries),
            "goal_evidence_admissible": False,
            "index_kind": EVIDENCE_INDEX_SCHEMA,
            "index_path": str(index_path),
            "index_sha256": index_snapshot.sha256,
            "mode": "active",
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "release_identity": executing_identity,
            "required_evidence_kinds": list(EVIDENCE_KINDS),
            "semantic_evidence_level": "normalized_contract_only",
            "total_bytes": sum(item["size"] for item in final_entries),
            "verified_evidence_kinds": [],
        }
    finally:
        if active_snapshot is not None:
            _close_snapshot(active_snapshot)
        if anchor_snapshot is not None:
            _close_snapshot(anchor_snapshot)
        closure.close()


__all__ = [
    "ACTIVE_ADMISSION_SCHEMA",
    "ACTIVE_RECORD_SCHEMA",
    "ADMISSION_FILENAME",
    "AUTHORIZATION_SCHEMA",
    "COLLECTION_PLAN_SCHEMA",
    "EVIDENCE_INDEX_SCHEMA",
    "EVIDENCE_KINDS",
    "INDEX_FILENAME",
    "RAW_EVIDENCE_SCHEMA",
    "RAW_MANIFEST_SCHEMA",
    "RAW_SOURCE_ADAPTER_BLOCKER",
    "ReadEvidenceV3Error",
    "ROLE_BINDINGS",
    "SCOPE_SCHEMA",
    "TRUST_ANCHOR_SCHEMA",
    "VERIFIER_REPORT_SCHEMA",
    "detect_read_evidence_schema",
    "verify_read_evidence_v3",
]

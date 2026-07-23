#!/usr/bin/env python3
"""Independently verify and externally anchor one frozen Dev29 read bundle."""

from __future__ import annotations

import argparse
import base64
import configparser
import ctypes
import errno
import hashlib
import hmac
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import stat
import struct
import subprocess
import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


sys.dont_write_bytecode = True

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_RELEASE_FILES = 20_000
MAX_TREE_FILES = 100_000
MAX_EXTERNAL_ENTRIES = 150_000
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
RELEASE_PARENT = Path("/opt/odoo-accounting-cli-v3/releases")
PACKAGE_PARENT = Path("/opt/odoo-accounting-cli-v3/packages")
TRUST_PARENT = Path("/opt/odoo-accounting-cli-v3/trusted-artifacts")
RUNNER_RELATIVE = PurePosixPath("deployment/dev29/run_read_suite.py")
VERIFIER_RELATIVE = PurePosixPath("deployment/dev29/verify_read_evidence.py")
PLAN_RELATIVE = PurePosixPath("deployment/dev29/read_plan.json")
RUNTIME_PARENT = Path("/etc/odoo-accounting-cli-v3/candidates")
TRACE_INDEX_PARENT = Path("/opt/odoo-accounting-cli-v3/runtime-open-manifests")
TRACE_INDEX_NAME = "INDEX.json"
TRACE_INDEX_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-index.v1"
TRACE_POLICY_SOURCE_SCOPE = (
    "odoo-accounting-cli-v3.dev29.runtime-open-policy-source.v1"
)
TRACE_MANIFEST_SCOPE = "direct-child-bootstrap-through-final-exec-v1"
PRIVATE_EVIDENCE_PARENT = Path(
    "/var/lib/odoo-accounting-cli-v3/evidence-private"
)
TRACE_RELATIVE = PurePosixPath("deployment/dev29/runtime_open_trace.py")
EXECUTABLE_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "bin/odoo-accounting-cli-v3-effect-finalizer",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)
CLOSURE_PYTHON = "/usr/bin/python3.12"
CLOSURE_LDCONFIG = "/usr/sbin/ldconfig.real"
SYSTEMCTL = Path("/usr/bin/systemctl")
LDCONFIG_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/root",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
}
PTRACE_SETOPTIONS = 0x4200
PTRACE_O_EXITKILL = 0x00100000
PR_SET_PDEATHSIG = 1
SIGKILL = getattr(signal, "SIGKILL", 9)
SYSTEMCTL_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
}
SYSTEMD_UNIT_FIELDS = (
    "Id",
    "LoadState",
    "ActiveState",
    "SubState",
    "Type",
    "User",
    "Group",
    "MainPID",
    "ControlGroup",
    "InvocationID",
    "ExecStart",
    "WorkingDirectory",
    "ProtectSystem",
    "ProtectHome",
    "PrivateMounts",
    "PrivateTmp",
    "PrivateNetwork",
    "NoNewPrivileges",
    "RestrictSUIDSGID",
    "ProtectControlGroups",
    "KillMode",
    "RuntimeMaxUSec",
    "TimeoutStopUSec",
    "UMask",
    "ReadWritePaths",
    "Environment",
    "CapabilityBoundingSet",
)
POSITIVE_NAMES = (
    "registry",
    "trial_balance",
    "ar_open_items",
    "ap_open_items",
    "multicurrency",
)
FINANCIAL_NAMES = (
    "trial_balance",
    "ar_open_items",
    "ap_open_items",
    "multicurrency",
)
NEGATIVE_NAMES = (
    "acl_deny",
    "cross_company",
    "mixed_company",
    "wrong_database_uuid",
    "expired",
    "tamper_parameters",
    "replay",
)


def expected_runtime_trace_targets() -> tuple[str, ...]:
    targets = ["release-identity", "witness-pre", "boundary-probe"]
    for name in POSITIVE_NAMES:
        targets.extend((f"positive-{name}-signer", f"positive-{name}-read"))
        if name in FINANCIAL_NAMES:
            targets.append(f"positive-{name}-oracle")
    for name in NEGATIVE_NAMES:
        if name != "replay":
            targets.append(f"negative-{name}-signer")
        targets.append(f"negative-{name}-read")
    targets.extend(("witness-post", "independent-verifier"))
    return tuple(targets)


def suite_runtime_trace_targets() -> tuple[str, ...]:
    return expected_runtime_trace_targets()[:-1]


def _expected_trace_role(target_id: str) -> str:
    if target_id in {"witness-pre", "witness-post"} or target_id.endswith("-oracle"):
        return "postgres"
    if target_id.endswith("-signer"):
        return "signer"
    if target_id == "independent-verifier":
        return "verifier"
    return "odoo"
CLOSURE_SECURITY_EXPECTED = {
    "root_only": True,
    "image_all_root": True,
    "mount_read_only": True,
    "config_sealed_outside_image": True,
    "config_placeholder_fail_closed": True,
    "source_manifest_stable": True,
    "no_external_symlinks": True,
    "python_path_escape_absent": True,
    "system_python_exact_and_sealed": True,
    "system_python_isolated_no_site_required": True,
    "loop_autoclear": True,
    "loader_preload_is_root_os_trust_anchor": True,
    "runtime_open_trace_required_for_completion": True,
    "static_runtime_closure_complete": False,
    "promotion_eligible_from_static_verification": False,
}
CLOSURE_SECURITY_FIELDS = frozenset(CLOSURE_SECURITY_EXPECTED)
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
        "auth_key_id",
        "receipt_key_id",
        "auth_secret_path",
        "receipt_secret_path",
    }
)
REQUEST_CONTEXT_FIELDS = frozenset(
    {
        "allowed_company_ids",
        "audience",
        "auth_expires_at",
        "auth_issued_at",
        "auth_key_id",
        "auth_request_digest",
        "auth_signature",
        "auth_signature_purpose",
        "auth_signature_version",
        "auth_token_id",
        "company_id",
        "database_name",
        "database_uuid",
        "environment",
        "odoo_instance_id",
        "principal",
        "user_id",
    }
)


class EvidenceVerificationError(RuntimeError):
    """The release, evidence bundle, or live independent check failed."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceVerificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _constant(value: str) -> Any:
    raise EvidenceVerificationError(f"non-finite JSON number: {value}")


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
        raise EvidenceVerificationError("value is not canonical JSON") from exc


def _schema_version_is_one(value: Any) -> bool:
    return type(value) is int and value == 1


def _expected_release_member_mode(name: str) -> int:
    return 0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444


def parse_json(payload: bytes, *, label: str, canonical: bool = False) -> dict[str, Any]:
    if not payload or len(payload) > MAX_JSON_BYTES:
        raise EvidenceVerificationError(f"{label} is empty or too large")
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except EvidenceVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError(f"{label} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise EvidenceVerificationError(f"{label} must be a JSON object")
    if canonical and payload != canonical_json(value) + b"\n":
        raise EvidenceVerificationError(f"{label} is not canonical JSON plus LF")
    return value


def _fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def stable_read(
    path: Path,
    *,
    label: str,
    maximum: int = MAX_JSON_BYTES,
    allow_empty: bool = False,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    allowed_modes: frozenset[int] | None = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceVerificationError(f"{label} cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
            or (before.st_size == 0 and not allow_empty)
            or (expected_uid is not None and before.st_uid != expected_uid)
            or (expected_gid is not None and before.st_gid != expected_gid)
            or (allowed_modes is not None and mode not in allowed_modes)
        ):
            raise EvidenceVerificationError(f"{label} metadata is invalid")
        identity = _fingerprint(before)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise EvidenceVerificationError(f"{label} changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or _fingerprint(os.fstat(descriptor)) != identity:
            raise EvidenceVerificationError(f"{label} changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _safe_root_chain(path: Path, *, final_mode: int | None = None) -> None:
    current = Path("/")
    for component in Path(path).absolute().parts[1:]:
        current /= component
        metadata = current.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or mode & 0o022
            or not mode & 0o111
        ):
            raise EvidenceVerificationError(f"unsafe root-owned path: {current}")
    if final_mode is not None and stat.S_IMODE(Path(path).lstat().st_mode) != final_mode:
        raise EvidenceVerificationError(f"directory mode is invalid: {path}")


def _expected_identity(
    release: str,
    version: str,
    commit: str,
    manifest_sha256: str,
    package_sha256: str,
) -> dict[str, str]:
    if (
        SAFE_NAME.fullmatch(release) is None
        or VERSION.fullmatch(version) is None
        or HEX40.fullmatch(commit) is None
        or HEX64.fullmatch(manifest_sha256) is None
        or HEX64.fullmatch(package_sha256) is None
        or release != f"{version}-{commit[:12]}"
    ):
        raise EvidenceVerificationError("expected release identity is invalid")
    return {
        "release": release,
        "version": version,
        "commit": commit,
        "manifest_sha256": manifest_sha256,
        "package_sha256": package_sha256,
    }


def bootstrap_verify_release(expected: dict[str, str]) -> tuple[Path, dict[str, Any]]:
    """Verify the complete release before importing any sibling implementation."""

    root = RELEASE_PARENT / expected["release"]
    verifier = root.joinpath(*VERIFIER_RELATIVE.parts)
    if Path(__file__).resolve(strict=True) != verifier.resolve(strict=True):
        raise EvidenceVerificationError("verifier is outside the expected sealed release")
    if os.name == "posix":
        _safe_root_chain(root, final_mode=0o555)
    anchor_bytes = stable_read(
        TRUST_PARENT / f"{expected['release']}.json",
        label="external release anchor",
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
    )
    anchor = parse_json(anchor_bytes, label="external release anchor")
    if anchor != {
        "commit": expected["commit"],
        "manifest_sha256": expected["manifest_sha256"],
        "package_sha256": expected["package_sha256"],
        "release": expected["release"],
    }:
        raise EvidenceVerificationError("external release anchor mismatch")
    manifest_bytes = stable_read(
        root / "RELEASE-MANIFEST.json",
        label="installed release manifest",
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
    )
    manifest = parse_json(manifest_bytes, label="installed release manifest")
    if (
        set(manifest) != {"commit", "files", "manifest_sha256", "schema_version", "version"}
        or not _schema_version_is_one(manifest.get("schema_version"))
        or manifest.get("commit") != expected["commit"]
        or manifest.get("version") != expected["version"]
        or manifest.get("manifest_sha256") != expected["manifest_sha256"]
    ):
        raise EvidenceVerificationError("installed release manifest identity mismatch")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if hashlib.sha256(canonical_json(unsigned)).hexdigest() != expected["manifest_sha256"]:
        raise EvidenceVerificationError("installed release manifest semantic digest mismatch")
    files = manifest.get("files")
    if type(files) is not list or not files or len(files) > MAX_RELEASE_FILES:
        raise EvidenceVerificationError("installed release manifest files are invalid")
    indexed: dict[str, dict[str, Any]] = {}
    for item in files:
        name = item.get("path") if type(item) is dict else None
        portable = PurePosixPath(name) if isinstance(name, str) else None
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "size"}
            or portable is None
            or portable.is_absolute()
            or not portable.parts
            or any(part in {"", ".", ".."} for part in portable.parts)
            or str(portable) != name
            or name in indexed
            or not isinstance(item.get("sha256"), str)
            or HEX64.fullmatch(item["sha256"]) is None
            or type(item.get("size")) is not int
            or item["size"] < 0
        ):
            raise EvidenceVerificationError("installed release manifest entry is invalid")
        indexed[name] = item
    if str(RUNNER_RELATIVE) not in indexed or str(VERIFIER_RELATIVE) not in indexed:
        raise EvidenceVerificationError("installed release omits Dev29 verifier components")
    actual: dict[str, Path] = {}
    for directory_text, directories, names in os.walk(root, topdown=True, followlinks=False):
        directory = Path(directory_text)
        directories.sort()
        names.sort()
        for name in directories:
            child = directory / name
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceVerificationError("installed release directory is unsafe")
            if os.name == "posix" and (
                metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o555
            ):
                raise EvidenceVerificationError("installed release directory metadata drifted")
        for name in names:
            child = directory / name
            relative = child.relative_to(root).as_posix()
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise EvidenceVerificationError(f"installed release file is unsafe: {relative}")
            if relative != "RELEASE-MANIFEST.json":
                actual[relative] = child
    if set(actual) != set(indexed):
        raise EvidenceVerificationError("installed release file set mismatch")
    for name, item in indexed.items():
        payload = stable_read(
            actual[name],
            label=f"installed release member {name}",
            maximum=max(MAX_JSON_BYTES, item["size"]),
            allow_empty=item["size"] == 0,
            expected_uid=0 if os.name == "posix" else None,
            expected_gid=0 if os.name == "posix" else None,
            allowed_modes=frozenset({_expected_release_member_mode(name)})
            if os.name == "posix"
            else None,
        )
        if len(payload) != item["size"] or hashlib.sha256(payload).hexdigest() != item["sha256"]:
            raise EvidenceVerificationError(f"installed release member mismatch: {name}")
    package = PACKAGE_PARENT / f"odoo-accounting-cli-v3-{expected['release']}.tar.gz"
    package_payload = stable_read(
        package,
        label="canonical release package",
        maximum=512 * 1024 * 1024,
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
    )
    if hashlib.sha256(package_payload).hexdigest() != expected["package_sha256"]:
        raise EvidenceVerificationError("canonical release package digest mismatch")
    return root, manifest


def validate_evidence_path(path: Path, *, enforce_root: bool = True) -> Path:
    path = Path(path).absolute()
    if (
        path.parent != EVIDENCE_PARENT
        or SAFE_NAME.fullmatch(path.name) is None
        or path.is_symlink()
    ):
        raise EvidenceVerificationError("evidence is not a direct child of the fixed parent")
    if enforce_root and os.name == "posix":
        _safe_root_chain(path, final_mode=0o500)
    return path


def expected_bundle_files() -> set[str]:
    files = {
        "read-plan.json",
        "runtime.json",
        "expected-release.json",
        "verified-release-pre.json",
        "verified-release-post.json",
        "sandbox-profile.json",
        "outer-unit.json",
        "system-pre.json",
        "system-post.json",
        "dependency-pre.json",
        "dependency-post.json",
        "dependency-watch.json",
        "state-pre.json",
        "state-post.json",
        "state-delta.json",
        "runtime-open-trace.json",
        "suite.json",
        "witness-pre.stdout",
        "witness-pre.stderr",
        "witness-pre.exit",
        "witness-pre.child.json",
        "witness-pre.process-control.json",
        "witness-post.stdout",
        "witness-post.stderr",
        "witness-post.exit",
        "witness-post.child.json",
        "witness-post.process-control.json",
        "release/identity.stdout",
        "release/identity.stderr",
        "release/identity.exit",
        "release/identity.child.json",
        "release/identity.process-control.json",
        "boundary/probe.stdout",
        "boundary/probe.stderr",
        "boundary/probe.exit",
        "boundary/probe.child.json",
        "boundary/probe.process-control.json",
        "closure/verify-pre.stdout",
        "closure/verify-pre.stderr",
        "closure/verify-pre.exit",
        "closure/verify-post.stdout",
        "closure/verify-post.stderr",
        "closure/verify-post.exit",
        "closure/addons-paths.json",
        "closure/python-pre.json",
        "closure/python-post.json",
        "closure/external-runtime-pre.json",
        "closure/external-runtime-post.json",
        "closure/mount-pre.json",
        "closure/mount-post.json",
    }
    for name in POSITIVE_NAMES:
        prefix = f"positive/{name}"
        files.update(
            {
                f"{prefix}/signer.stdout",
                f"{prefix}/signer.stderr",
                f"{prefix}/signer.exit",
                f"{prefix}/signer.child.json",
                f"{prefix}/signer.process-control.json",
                f"{prefix}/request.json",
                f"{prefix}/read.stdout",
                f"{prefix}/read.stderr",
                f"{prefix}/read.exit",
                f"{prefix}/read.child.json",
                f"{prefix}/read.process-control.json",
                f"{prefix}/receipt.json",
            }
        )
        if name in FINANCIAL_NAMES:
            files.update(
                {
                    f"{prefix}/oracle.stdout",
                    f"{prefix}/oracle.stderr",
                    f"{prefix}/oracle.exit",
                    f"{prefix}/oracle.child.json",
                    f"{prefix}/oracle.process-control.json",
                }
            )
    for name in NEGATIVE_NAMES:
        prefix = f"negative/{name}"
        files.update(
            {
                f"{prefix}/request.json",
                f"{prefix}/expected.json",
                f"{prefix}/read.stdout",
                f"{prefix}/read.stderr",
                f"{prefix}/read.exit",
                f"{prefix}/read.child.json",
                f"{prefix}/read.process-control.json",
            }
        )
        if name == "replay":
            files.add(f"{prefix}/request-source.json")
        else:
            files.update(
                {
                    f"{prefix}/signer.stdout",
                    f"{prefix}/signer.stderr",
                    f"{prefix}/signer.exit",
                    f"{prefix}/signer.child.json",
                    f"{prefix}/signer.process-control.json",
                }
            )
    return files


def load_bundle(
    evidence: Path,
    *,
    expected: dict[str, str],
    expected_bundle_manifest_sha256: str,
    enforce_root: bool = True,
) -> tuple[dict[str, bytes], dict[str, Any], str]:
    if HEX64.fullmatch(expected_bundle_manifest_sha256) is None:
        raise EvidenceVerificationError("expected bundle manifest digest is invalid")
    evidence = validate_evidence_path(evidence, enforce_root=enforce_root)
    manifest_path = evidence / "BUNDLE-MANIFEST.json"
    manifest_bytes = stable_read(
        manifest_path,
        label="bundle manifest",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=frozenset({0o400}) if enforce_root and os.name == "posix" else None,
    )
    observed_manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if observed_manifest_sha256 != expected_bundle_manifest_sha256:
        raise EvidenceVerificationError("bundle manifest digest mismatch")
    manifest = parse_json(manifest_bytes, label="bundle manifest", canonical=True)
    expected_fields = {
        "schema_version",
        "bundle_type",
        "evidence_name",
        "evidence_path",
        "release_identity",
        "closure_identity",
        "closure_verification_sha256",
        "plan_sha256",
        "runtime_sha256",
        "runtime_open_trace_sha256",
        "runtime_open_trace_private",
        "positive_cases",
        "financial_oracle_cases",
        "negative_cases",
        "auth_token_ids",
        "receipt_ids",
        "production_promotion_allowed",
        "files",
    }
    release_identity = manifest.get("release_identity")
    if (
        set(manifest) != expected_fields
        or not _schema_version_is_one(manifest.get("schema_version"))
        or manifest.get("bundle_type")
        != "odoo-accounting-cli-v3.dev29.read-suite-evidence"
        or manifest.get("evidence_name") != evidence.name
        or manifest.get("evidence_path") != str(evidence)
        or type(release_identity) is not dict
        or any(release_identity.get(key) != value for key, value in expected.items())
        or release_identity.get("verified") is not True
        or not isinstance(release_identity.get("registry_digest"), str)
        or HEX64.fullmatch(release_identity["registry_digest"]) is None
        or type(manifest.get("closure_identity")) is not dict
        or not isinstance(manifest.get("closure_verification_sha256"), str)
        or HEX64.fullmatch(manifest["closure_verification_sha256"]) is None
        or manifest.get("positive_cases") != list(POSITIVE_NAMES)
        or manifest.get("financial_oracle_cases") != list(FINANCIAL_NAMES)
        or manifest.get("negative_cases") != list(NEGATIVE_NAMES)
        or manifest.get("production_promotion_allowed") is not False
        or not isinstance(manifest.get("runtime_open_trace_sha256"), str)
        or HEX64.fullmatch(manifest["runtime_open_trace_sha256"]) is None
        or type(manifest.get("runtime_open_trace_private")) is not dict
        or type(manifest.get("auth_token_ids")) is not dict
        or set(manifest["auth_token_ids"]) != set((*POSITIVE_NAMES, *NEGATIVE_NAMES))
        or type(manifest.get("receipt_ids")) is not dict
        or set(manifest["receipt_ids"]) != set(POSITIVE_NAMES)
    ):
        raise EvidenceVerificationError("bundle manifest identity is invalid")
    expected_files = expected_bundle_files()
    entries = manifest.get("files")
    if (
        type(entries) is not list
        or [item.get("path") for item in entries if type(item) is dict]
        != sorted(expected_files)
    ):
        raise EvidenceVerificationError("bundle manifest file set or order is invalid")
    documents: dict[str, bytes] = {}
    actual_files: set[str] = set()
    for directory_text, directories, names in os.walk(evidence, topdown=True, followlinks=False):
        directory = Path(directory_text)
        directories.sort()
        names.sort()
        if enforce_root and os.name == "posix" and stat.S_IMODE(directory.lstat().st_mode) != 0o500:
            raise EvidenceVerificationError("frozen bundle directory mode is invalid")
        for name in directories:
            child = directory / name
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise EvidenceVerificationError("frozen bundle directory is unsafe")
        for name in names:
            child = directory / name
            relative = child.relative_to(evidence).as_posix()
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise EvidenceVerificationError(f"frozen bundle member is unsafe: {relative}")
            if enforce_root and os.name == "posix" and (
                metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                raise EvidenceVerificationError(f"frozen bundle metadata is invalid: {relative}")
            actual_files.add(relative)
    if actual_files != expected_files | {"BUNDLE-MANIFEST.json"}:
        raise EvidenceVerificationError("frozen bundle filesystem set is invalid")
    for entry in entries:
        if (
            type(entry) is not dict
            or set(entry) != {"path", "sha256", "size"}
            or entry["path"] not in expected_files
            or not isinstance(entry.get("sha256"), str)
            or HEX64.fullmatch(entry["sha256"]) is None
            or type(entry.get("size")) is not int
            or entry["size"] < 0
            or entry["size"] > MAX_JSON_BYTES
        ):
            raise EvidenceVerificationError("bundle file manifest entry is invalid")
        payload = stable_read(
            evidence.joinpath(*PurePosixPath(entry["path"]).parts),
            label=f"bundle member {entry['path']}",
            maximum=MAX_JSON_BYTES,
            allow_empty=True,
            expected_uid=0 if enforce_root and os.name == "posix" else None,
            expected_gid=0 if enforce_root and os.name == "posix" else None,
            allowed_modes=frozenset({0o400}) if enforce_root and os.name == "posix" else None,
        )
        if len(payload) != entry["size"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise EvidenceVerificationError(f"bundle member digest mismatch: {entry['path']}")
        documents[entry["path"]] = payload
    return documents, manifest, observed_manifest_sha256


def _json(documents: Mapping[str, bytes], name: str) -> dict[str, Any]:
    return parse_json(documents[name], label=f"bundle {name}", canonical=True)


def _exit(documents: Mapping[str, bytes], name: str, expected: int) -> None:
    if documents[name] != f"{expected}\n".encode("ascii"):
        raise EvidenceVerificationError(f"bundle exit evidence is invalid: {name}")


def _datetime(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceVerificationError(f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceVerificationError(f"{label} is not a timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceVerificationError(f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def verify_auth_request(
    request: dict[str, Any],
    *,
    auth_secret: bytes,
    runtime: dict[str, Any],
    expect_content_match: bool,
) -> None:
    context = request.get("context") if type(request) is dict else None
    if (
        not isinstance(auth_secret, bytes)
        or len(auth_secret) != 32
        or type(context) is not dict
        or set(context) != REQUEST_CONTEXT_FIELDS
        or context.get("audience") != "odoo-accounting-cli-v3"
        or context.get("auth_signature_version") != 1
        or context.get("auth_signature_purpose") != "auth_context_v1"
        or context.get("auth_key_id") != runtime["auth_key_id"]
        or context.get("environment") != runtime["environment"]
        or not isinstance(context.get("auth_token_id"), str)
        or not context["auth_token_id"]
        or not isinstance(context.get("principal"), str)
        or not context["principal"].strip()
        or not isinstance(context.get("odoo_instance_id"), str)
        or not context["odoo_instance_id"].strip()
        or not isinstance(context.get("database_name"), str)
        or not context["database_name"].strip()
        or type(context.get("user_id")) is not int
        or context["user_id"] <= 0
        or type(context.get("company_id")) is not int
        or context["company_id"] <= 0
        or type(context.get("allowed_company_ids")) is not list
        or context["allowed_company_ids"]
        != sorted(set(context["allowed_company_ids"]))
        or context["company_id"] not in context["allowed_company_ids"]
        or any(type(item) is not int or item <= 0 for item in context["allowed_company_ids"])
        or not isinstance(context.get("auth_request_digest"), str)
        or HEX64.fullmatch(context["auth_request_digest"]) is None
        or not isinstance(context.get("auth_signature"), str)
        or HEX64.fullmatch(context["auth_signature"]) is None
    ):
        raise EvidenceVerificationError("signed request authentication is invalid")
    try:
        normalized_uuid = str(uuid.UUID(context["database_uuid"]))
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvidenceVerificationError("signed request authentication is invalid") from exc
    if normalized_uuid != context["database_uuid"]:
        raise EvidenceVerificationError("signed request authentication is invalid")
    issued = _datetime(context["auth_issued_at"], label="auth issued_at")
    expires = _datetime(context["auth_expires_at"], label="auth expires_at")
    if expires <= issued or expires - issued > timedelta(minutes=5):
        raise EvidenceVerificationError("signed request authentication is invalid")
    signature_payload = {
        "allowed_company_ids": sorted(context["allowed_company_ids"]),
        "audience": context["audience"],
        "auth_expires_at": expires.isoformat(),
        "auth_issued_at": issued.isoformat(),
        "auth_key_id": context["auth_key_id"],
        "auth_request_digest": context["auth_request_digest"],
        "auth_signature_purpose": context["auth_signature_purpose"],
        "auth_signature_version": context["auth_signature_version"],
        "auth_token_id": context["auth_token_id"],
        "company_id": context["company_id"],
        "database_name": context["database_name"],
        "database_uuid": context["database_uuid"],
        "environment": context["environment"],
        "principal": context["principal"],
        "odoo_instance_id": context["odoo_instance_id"],
        "user_id": context["user_id"],
    }
    expected_signature = hmac.new(
        auth_secret, canonical_json(signature_payload), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, context["auth_signature"]):
        raise EvidenceVerificationError("signed request authentication is invalid")
    expected_digest = hashlib.sha256(
        canonical_json(
            {
                "capability_id": request["capability_id"],
                "parameters": request["parameters"],
            }
        )
    ).hexdigest()
    matches = hmac.compare_digest(context["auth_request_digest"], expected_digest)
    if matches is not expect_content_match:
        raise EvidenceVerificationError("signed request content-digest expectation is invalid")


def verify_receipt(
    request: dict[str, Any],
    response: dict[str, Any],
    *,
    receipt_secret: bytes,
    runtime: dict[str, Any],
    release_identity: dict[str, Any],
) -> dict[str, Any]:
    context = request["context"]
    result = response["data"]["result"]
    receipt = result["receipt"]
    body = {key: value for key, value in result.items() if key != "receipt"}
    page = body.get("page")
    if type(page) is not dict or type(page.get("total_count")) is not int:
        raise EvidenceVerificationError("positive result page evidence is invalid")
    fields = {
        "capability_id",
        "capability_channel",
        "company_id",
        "database_name",
        "database_uuid",
        "id",
        "environment",
        "observed_at",
        "odoo_instance_id",
        "record_count",
        "registry_digest",
        "release_digest",
        "request_digest",
        "result_digest",
        "signature",
        "signature_key_id",
        "signature_purpose",
        "signature_version",
        "user_id",
    }
    if (
        not isinstance(receipt_secret, bytes)
        or len(receipt_secret) != 32
        or type(receipt) is not dict
        or set(receipt) != fields
        or receipt.get("capability_id") != request["capability_id"]
        or receipt.get("capability_channel") != runtime["capability_channel"]
        or receipt.get("company_id") != context["company_id"]
        or receipt.get("database_name") != runtime["database_name"]
        or receipt.get("database_uuid") != runtime["database_uuid"]
        or receipt.get("environment") != runtime["environment"]
        or receipt.get("odoo_instance_id") != runtime["instance_id"]
        or receipt.get("record_count") != page["total_count"]
        or receipt.get("registry_digest") != release_identity["registry_digest"]
        or receipt.get("release_digest") != release_identity["manifest_sha256"]
        or receipt.get("signature_key_id") != runtime["receipt_key_id"]
        or receipt.get("signature_purpose") != "read_receipt_v2"
        or receipt.get("signature_version") != 2
        or receipt.get("user_id") != context["user_id"]
        or not isinstance(receipt.get("id"), str)
        or not receipt["id"]
        or any(
            not isinstance(receipt.get(field), str)
            or HEX64.fullmatch(receipt[field]) is None
            for field in (
                "registry_digest",
                "release_digest",
                "request_digest",
                "result_digest",
                "signature",
            )
        )
    ):
        raise EvidenceVerificationError("positive receipt HMAC/binding is invalid")
    observed = _datetime(receipt["observed_at"], label="receipt observed_at")
    if receipt["observed_at"] != observed.isoformat().replace("+00:00", "Z"):
        raise EvidenceVerificationError("positive receipt HMAC/binding is invalid")
    request_digest = hashlib.sha256(
        canonical_json(
            {
                "capability_id": request["capability_id"],
                "auth_token_id": context["auth_token_id"],
                "company_id": context["company_id"],
                "environment": runtime["environment"],
                "database_name": runtime["database_name"],
                "database_uuid": runtime["database_uuid"],
                "parameters": request["parameters"],
                "principal": context["principal"],
                "capability_channel": runtime["capability_channel"],
                "odoo_instance_id": runtime["instance_id"],
                "registry_digest": release_identity["registry_digest"],
                "release_digest": release_identity["manifest_sha256"],
                "user_id": context["user_id"],
            }
        )
    ).hexdigest()
    if (
        not hmac.compare_digest(receipt["request_digest"], request_digest)
        or not hmac.compare_digest(
            receipt["result_digest"], hashlib.sha256(canonical_json(body)).hexdigest()
        )
    ):
        raise EvidenceVerificationError("positive receipt HMAC/binding is invalid")
    unsigned = {key: value for key, value in receipt.items() if key != "signature"}
    expected_signature = hmac.new(
        receipt_secret, canonical_json(unsigned), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, receipt["signature"]):
        raise EvidenceVerificationError("positive receipt HMAC/binding is invalid")
    issued = _datetime(context["auth_issued_at"], label="auth issued_at")
    expires = _datetime(context["auth_expires_at"], label="auth expires_at")
    if not issued <= observed < expires:
        raise EvidenceVerificationError("receipt observation escaped authentication lifetime")
    return receipt


def assert_no_secret_leak(documents: Mapping[str, bytes], secrets: Sequence[bytes]) -> None:
    patterns: list[bytes] = []
    for secret in secrets:
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise EvidenceVerificationError("runtime secret length is invalid")
        patterns.extend(
            (
                secret,
                secret.hex().encode("ascii"),
                base64.b64encode(secret),
                base64.urlsafe_b64encode(secret),
            )
        )
    for name, payload in documents.items():
        if any(pattern and pattern in payload for pattern in patterns):
            raise EvidenceVerificationError(f"raw runtime secret leaked into bundle: {name}")


def _validate_identity(value: Mapping[str, Any], *, label: str) -> None:
    allowed = value.get("allowed_company_ids")
    if (
        not isinstance(value.get("principal"), str)
        or not value["principal"]
        or value["principal"] != value["principal"].strip()
        or type(value.get("user_id")) is not int
        or value["user_id"] <= 0
        or type(value.get("company_id")) is not int
        or value["company_id"] <= 0
        or type(allowed) is not list
        or not allowed
        or any(type(item) is not int or item <= 0 for item in allowed)
        or allowed != sorted(set(allowed))
    ):
        raise EvidenceVerificationError(f"{label} identity is invalid")


def validate_plan(plan: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        set(plan)
        != {
            "schema_version",
            "target",
            "database",
            "runtime",
            "cases",
            "negative_cases",
            "witness",
        }
        or not _schema_version_is_one(plan.get("schema_version"))
    ):
        raise EvidenceVerificationError("Dev29 read plan envelope is invalid")
    target = plan.get("target")
    database = plan.get("database")
    fixed_runtime = plan.get("runtime")
    witness = plan.get("witness")
    if not all(type(item) is dict for item in (target, database, fixed_runtime, witness)):
        raise EvidenceVerificationError("Dev29 read plan scope is invalid")
    if (
        target.get("environment") != "test"
        or target.get("capability_channel") != "staged"
        or target.get("host") != "43.165.173.80"
        or target.get("instance_id") != "odoo19@43.165.173.80"
        or database.get("name") != "odoo_test"
        or database.get("current_user") != "postgres"
        or database.get("unix_socket_directory") != "/var/run/postgresql"
        or database.get("unix_socket_path") != "/var/run/postgresql/.s.PGSQL.5432"
        or database.get("port") != 5432
        or type(database.get("server_version_num")) is not int
        or not isinstance(database.get("system_identifier"), str)
        or not database["system_identifier"].isdigit()
        or any(
            type(target.get(field)) is not list or not target[field]
            for field in ("services", "v3_unit_names", "v2_roots", "pi_control_files")
        )
    ):
        raise EvidenceVerificationError("Dev29 fixed target scope is invalid")
    try:
        if str(uuid.UUID(database["uuid"])) != database["uuid"]:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceVerificationError("Dev29 database UUID is invalid") from exc
    if set(fixed_runtime) != {
        "odoo_python",
        "odoo_python_sha256",
        "odoo_bin",
        "odoo_bin_sha256",
        "odoo_config",
        "odoo_config_sha256",
    }:
        raise EvidenceVerificationError("Dev29 fixed runtime plan is invalid")
    for digest_field in ("odoo_python_sha256", "odoo_bin_sha256", "odoo_config_sha256"):
        if not isinstance(fixed_runtime.get(digest_field), str) or HEX64.fullmatch(
            fixed_runtime[digest_field]
        ) is None:
            raise EvidenceVerificationError("Dev29 fixed runtime digest is invalid")

    positive_fields = {
        "name",
        "capability_id",
        "principal",
        "user_id",
        "company_id",
        "allowed_company_ids",
        "parameters",
        "expected",
    }
    cases = plan.get("cases")
    if type(cases) is not list or [item.get("name") for item in cases if type(item) is dict] != list(
        POSITIVE_NAMES
    ):
        raise EvidenceVerificationError("Dev29 positive case set is invalid")
    case_map: dict[str, Any] = {}
    for case in cases:
        if (
            type(case) is not dict
            or set(case) != positive_fields
            or not isinstance(case.get("capability_id"), str)
            or not case["capability_id"].startswith("acct.")
            or type(case.get("parameters")) is not dict
            or type(case.get("expected")) is not dict
        ):
            raise EvidenceVerificationError("Dev29 positive case is invalid")
        _validate_identity(case, label=f"positive case {case.get('name')}")
        case_map[case["name"]] = case

    negative_fields = {
        "name",
        "base_case",
        "principal",
        "user_id",
        "company_id",
        "allowed_company_ids",
        "mutation",
        "expected_error",
    }
    expected_errors = {
        "acl_deny": "odoo_acl_denied",
        "cross_company": "company_binding_rejected",
        "mixed_company": "company_binding_rejected",
        "wrong_database_uuid": "database_binding_rejected",
        "expired": "authentication_expired",
        "tamper_parameters": "authentication_tampered",
        "replay": "authentication_replayed",
    }
    negatives = plan.get("negative_cases")
    if type(negatives) is not list or [item.get("name") for item in negatives if type(item) is dict] != list(
        NEGATIVE_NAMES
    ):
        raise EvidenceVerificationError("Dev29 negative case set is invalid")
    negative_map: dict[str, Any] = {}
    mutation_kinds = {
        "identity_override",
        "context_override",
        "expire_after_sign",
        "parameters_after_sign",
        "replay_exact_request",
    }
    for negative in negatives:
        mutation = negative.get("mutation") if type(negative) is dict else None
        if (
            type(negative) is not dict
            or set(negative) != negative_fields
            or negative.get("base_case") not in case_map
            or negative.get("expected_error") != expected_errors.get(negative.get("name"))
            or type(mutation) is not dict
            or set(mutation) != {"kind", "fields"}
            or mutation.get("kind") not in mutation_kinds
            or type(mutation.get("fields")) is not dict
        ):
            raise EvidenceVerificationError("Dev29 negative case is invalid")
        _validate_identity(negative, label=f"negative case {negative.get('name')}")
        negative_map[negative["name"]] = negative
    if (
        type(witness.get("relations")) is not list
        or not witness["relations"]
        or len({item.get("name") for item in witness["relations"] if type(item) is dict})
        != len(witness["relations"])
    ):
        raise EvidenceVerificationError("Dev29 witness relation plan is invalid")
    return case_map, negative_map


def validate_runtime(
    runtime: dict[str, Any],
    *,
    plan: dict[str, Any],
    expected: Mapping[str, str],
    verify_live_files: bool,
) -> None:
    if set(runtime) != RUNTIME_FIELDS:
        raise EvidenceVerificationError("Dev29 runtime fields are invalid")
    release = expected["release"]
    target = plan["target"]
    database = plan["database"]
    fixed = plan["runtime"]
    expected_values = {
        "instance_id": target["instance_id"],
        "environment": "test",
        "capability_channel": "staged",
        "database_name": database["name"],
        "database_uuid": database["uuid"],
        **fixed,
        "release_root": str(RELEASE_PARENT / release),
        "canonical_package_path": str(
            PACKAGE_PARENT / f"odoo-accounting-cli-v3-{release}.tar.gz"
        ),
        "canonical_package_sha256": expected["package_sha256"],
        "auth_state_path": (
            f"/var/lib/odoo-accounting-cli-v3/test/candidates/{release}/auth/state.sqlite3"
        ),
        "receipt_state_path": (
            f"/var/lib/odoo-accounting-cli-v3/test/candidates/{release}/receipt/state.sqlite3"
        ),
        "auth_secret_path": (
            f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{release}/auth.hmac"
        ),
        "receipt_secret_path": (
            f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{release}/receipt.hmac"
        ),
    }
    if any(runtime.get(key) != value for key, value in expected_values.items()):
        raise EvidenceVerificationError("Dev29 runtime binding is invalid")
    if (
        not isinstance(runtime.get("auth_key_id"), str)
        or not runtime["auth_key_id"].startswith("test-auth-dev29-")
        or not isinstance(runtime.get("receipt_key_id"), str)
        or not runtime["receipt_key_id"].startswith("test-receipt-dev29-")
        or runtime["auth_key_id"] == runtime["receipt_key_id"]
    ):
        raise EvidenceVerificationError("Dev29 runtime key roles are invalid")
    if verify_live_files:
        for path_field, digest_field in (
            ("odoo_python", "odoo_python_sha256"),
            ("odoo_bin", "odoo_bin_sha256"),
            ("odoo_config", "odoo_config_sha256"),
        ):
            payload = stable_read(
                Path(runtime[path_field]),
                label=f"live runtime dependency {path_field}",
                maximum=128 * 1024 * 1024,
            )
            if hashlib.sha256(payload).hexdigest() != runtime[digest_field]:
                raise EvidenceVerificationError(f"live runtime dependency drifted: {path_field}")


def _registry_object(value: Any, *, label: str, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise EvidenceVerificationError(f"registry contract object is invalid: {label}")
    return value


def _registry_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceVerificationError(f"registry text is invalid: {label}")
    return value


def _validate_registry_schema_node(value: Any, *, label: str) -> None:
    if type(value) is not dict:
        raise EvidenceVerificationError(f"registry JSON Schema node is invalid: {label}")
    if "oneOf" in value:
        alternatives = value.get("oneOf")
        if (
            set(value) != {"oneOf"}
            or type(alternatives) is not list
            or len(alternatives) < 2
        ):
            raise EvidenceVerificationError(
                f"registry JSON Schema oneOf is invalid: {label}"
            )
        for index, alternative in enumerate(alternatives):
            _validate_registry_schema_node(
                alternative, label=f"{label}.oneOf[{index}]"
            )
        return
    declared = value.get("type")
    types = declared if type(declared) is list else [declared]
    allowed_types = {"object", "array", "string", "integer", "number", "boolean", "null"}
    if (
        not types
        or any(type(item) is not str or item not in allowed_types for item in types)
        or len(types) != len(set(types))
    ):
        raise EvidenceVerificationError(f"registry JSON Schema type is invalid: {label}")
    keywords = {"type", "enum"}
    if "object" in types:
        keywords |= {"properties", "required", "additionalProperties"}
    if "array" in types:
        keywords |= {"items", "minItems", "maxItems", "uniqueItems"}
    if "string" in types:
        keywords |= {"format", "pattern", "minLength", "maxLength"}
    if {"integer", "number"} & set(types):
        keywords |= {"minimum", "exclusiveMinimum", "maximum", "exclusiveMaximum"}
    if set(value) - keywords:
        raise EvidenceVerificationError(
            f"registry JSON Schema keyword is unsupported: {label}"
        )
    if "enum" in value and (type(value["enum"]) is not list or not value["enum"]):
        raise EvidenceVerificationError(f"registry JSON Schema enum is invalid: {label}")
    if "object" in types:
        properties = value.get("properties")
        required = value.get("required")
        if (
            type(properties) is not dict
            or type(required) is not list
            or len(required) != len(set(required))
            or any(type(item) is not str or not item for item in required)
            or set(required) - set(properties)
            or value.get("additionalProperties") is not False
        ):
            raise EvidenceVerificationError(
                f"registry object JSON Schema is invalid: {label}"
            )
        for name, child in properties.items():
            if type(name) is not str or not name:
                raise EvidenceVerificationError(
                    f"registry JSON Schema property is invalid: {label}"
                )
            _validate_registry_schema_node(child, label=f"{label}.properties.{name}")
    if "array" in types:
        if "items" not in value:
            raise EvidenceVerificationError(
                f"registry array JSON Schema is invalid: {label}"
            )
        _validate_registry_schema_node(value["items"], label=f"{label}.items")
        for field in ("minItems", "maxItems"):
            if field in value and (type(value[field]) is not int or value[field] < 0):
                raise EvidenceVerificationError(
                    f"registry array JSON Schema bound is invalid: {label}"
                )
        if (
            "minItems" in value
            and "maxItems" in value
            and value["minItems"] > value["maxItems"]
        ):
            raise EvidenceVerificationError(
                f"registry array JSON Schema bounds are invalid: {label}"
            )
        if "uniqueItems" in value and type(value["uniqueItems"]) is not bool:
            raise EvidenceVerificationError(
                f"registry array JSON Schema uniqueness is invalid: {label}"
            )
    if "string" in types:
        if "format" in value and value["format"] not in {"date", "date-time"}:
            raise EvidenceVerificationError(
                f"registry string JSON Schema format is invalid: {label}"
            )
        for field in ("minLength", "maxLength"):
            if field in value and (type(value[field]) is not int or value[field] < 0):
                raise EvidenceVerificationError(
                    f"registry string JSON Schema bound is invalid: {label}"
                )
        if (
            "minLength" in value
            and "maxLength" in value
            and value["minLength"] > value["maxLength"]
        ):
            raise EvidenceVerificationError(
                f"registry string JSON Schema bounds are invalid: {label}"
            )
        if "pattern" in value:
            try:
                re.compile(value["pattern"])
            except (TypeError, re.error) as exc:
                raise EvidenceVerificationError(
                    f"registry string JSON Schema pattern is invalid: {label}"
                ) from exc
    if {"integer", "number"} & set(types):
        for field in ("minimum", "exclusiveMinimum", "maximum", "exclusiveMaximum"):
            if field in value and (
                type(value[field]) not in {int, float}
            ):
                raise EvidenceVerificationError(
                    f"registry numeric JSON Schema bound is invalid: {label}"
                )


def _validate_registry_evidence(item: Mapping[str, Any], *, label: str) -> None:
    evidence = _registry_object(
        item.get("evidence"), label=f"{label}.evidence", fields={"level", "receipts"}
    )
    levels = {
        "declared",
        "contract_tested",
        "test_verified",
        "sandbox_verified",
        "production_verified",
    }
    receipts = evidence.get("receipts")
    if evidence.get("level") not in levels or type(receipts) is not list:
        raise EvidenceVerificationError(f"registry evidence is invalid: {label}")
    receipt_fields = {
        "artifact_sha256",
        "company_id",
        "database_uuid",
        "environment",
        "id",
        "kind",
        "registry_sha256",
        "release_sha256",
        "signature",
        "verified_at",
    }
    kinds_allowed = {
        "accounting_oracle",
        "contract",
        "live_odoo",
        "pi_e2e",
        "recovery",
        "release_identity",
        "sandbox_write_lifecycle",
        "security_negative",
    }
    seen_ids: set[str] = set()
    kinds: set[str] = set()
    for index, raw in enumerate(receipts):
        receipt = _registry_object(
            raw, label=f"{label}.evidence.receipts[{index}]", fields=receipt_fields
        )
        receipt_id = _registry_text(receipt["id"], label="evidence receipt id")
        if receipt_id in seen_ids:
            raise EvidenceVerificationError("registry evidence receipt ID is duplicated")
        seen_ids.add(receipt_id)
        if receipt.get("kind") not in kinds_allowed:
            raise EvidenceVerificationError("registry evidence kind is invalid")
        kinds.add(receipt["kind"])
        if receipt.get("environment") not in {"test", "sandbox", "production"}:
            raise EvidenceVerificationError("registry evidence environment is invalid")
        if type(receipt.get("company_id")) is not int or receipt["company_id"] <= 0:
            raise EvidenceVerificationError("registry evidence company is invalid")
        for field in ("database_uuid", "signature", "verified_at"):
            _registry_text(receipt.get(field), label=f"evidence receipt {field}")
        for field in ("artifact_sha256", "registry_sha256", "release_sha256"):
            if not isinstance(receipt.get(field), str) or HEX64.fullmatch(receipt[field]) is None:
                raise EvidenceVerificationError("registry evidence digest is invalid")
    enabled = set(item["enabled_environments"])
    staged = set(item.get("staged_environments", []))
    if staged and (evidence["level"] == "declared" or staged & enabled):
        raise EvidenceVerificationError("registry staged evidence policy is invalid")
    read_required = {
        "accounting_oracle",
        "live_odoo",
        "pi_e2e",
        "release_identity",
        "security_negative",
    }
    required = (
        read_required | {"recovery", "sandbox_write_lifecycle"}
        if item["access"] == "write"
        else read_required
    )
    if "test" in enabled and (
        evidence["level"] not in {"test_verified", "sandbox_verified", "production_verified"}
        or not required.issubset(kinds)
    ):
        raise EvidenceVerificationError("registry test enablement evidence is incomplete")
    if "sandbox" in enabled and (
        evidence["level"] not in {"sandbox_verified", "production_verified"}
        or (
            item["access"] == "write"
            and not {"sandbox_write_lifecycle", "recovery", "security_negative"}.issubset(kinds)
        )
    ):
        raise EvidenceVerificationError("registry sandbox evidence is incomplete")
    if "production" in enabled and (
        evidence["level"] != "production_verified" or not required.issubset(kinds)
    ):
        raise EvidenceVerificationError("registry production evidence is incomplete")


def independent_registry_digest(path: Path) -> str:
    payload = stable_read(
        path,
        label="exact release capability registry",
        maximum=MAX_JSON_BYTES,
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
    )
    document = parse_json(payload, label="exact release capability registry")
    if (
        type(document) is not dict
        or set(document) != {"schema_version", "capabilities"}
        or not _schema_version_is_one(document.get("schema_version"))
        or type(document.get("capabilities")) is not list
    ):
        raise EvidenceVerificationError("capability registry envelope is invalid")
    required = {
        "id",
        "domain",
        "business_description",
        "input_schema",
        "output_schema",
        "access",
        "risk_level",
        "odoo_permissions",
        "company_scope",
        "approval",
        "idempotency",
        "verification",
        "recovery",
        "evidence",
        "enabled_environments",
    }
    optional = {"staged_environments"}
    capability_id_pattern = re.compile(r"^acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*$")
    xml_id_pattern = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
    scopes = {"bound_company", "allowed_companies", "explicit_single_company"}
    idempotency_scopes = {
        "company_capability",
        "company_depreciation_move",
        "company_journal_source_digest",
        "company_line_set",
        "company_origin_move",
        "company_origin_operation",
        "company_source_line",
    }
    seen: set[str] = set()
    for index, item in enumerate(document["capabilities"]):
        label = f"capabilities[{index}]"
        if type(item) is not dict or required - set(item) or set(item) - required - optional:
            raise EvidenceVerificationError(f"registry capability fields are invalid: {label}")
        capability_id = item.get("id")
        if (
            not isinstance(capability_id, str)
            or capability_id_pattern.fullmatch(capability_id) is None
            or capability_id in seen
        ):
            raise EvidenceVerificationError(f"registry capability ID is invalid: {label}")
        seen.add(capability_id)
        _registry_text(item.get("domain"), label=f"{label}.domain")
        _registry_text(
            item.get("business_description"), label=f"{label}.business_description"
        )
        _validate_registry_schema_node(item.get("input_schema"), label=f"{label}.input")
        _validate_registry_schema_node(item.get("output_schema"), label=f"{label}.output")
        access = item.get("access")
        if (
            access not in {"read", "write"}
            or item.get("risk_level") not in {"low", "medium", "high", "critical"}
            or item.get("company_scope") not in scopes
        ):
            raise EvidenceVerificationError(f"registry policy is invalid: {label}")
        permissions = item.get("odoo_permissions")
        if (
            type(permissions) is not list
            or not permissions
            or len(permissions) != len(set(permissions))
            or any(
                not isinstance(value, str) or xml_id_pattern.fullmatch(value) is None
                for value in permissions
            )
        ):
            raise EvidenceVerificationError(f"registry ACL policy is invalid: {label}")
        enabled = item.get("enabled_environments")
        staged = item.get("staged_environments", [])
        if any(
            type(values) is not list
            or len(values) != len(set(values))
            or any(value not in allowed for value in values)
            for values, allowed in (
                (enabled, {"test", "sandbox", "production"}),
                (staged, {"test", "sandbox"}),
            )
        ):
            raise EvidenceVerificationError(f"registry environment policy is invalid: {label}")
        approval_fields = {"required"} if access == "read" else {"required", "policy", "ttl_seconds"}
        approval = _registry_object(
            item.get("approval"), label=f"{label}.approval", fields=approval_fields
        )
        if approval.get("required") is not (access == "write"):
            raise EvidenceVerificationError(f"registry approval policy is invalid: {label}")
        if access == "write" and (
            not _registry_text(approval.get("policy"), label=f"{label}.approval.policy")
            or type(approval.get("ttl_seconds")) is not int
            or not 1 <= approval["ttl_seconds"] <= 900
        ):
            raise EvidenceVerificationError(f"registry approval policy is invalid: {label}")
        idempotency_fields = {"required"} if access == "read" else {"required", "scope"}
        idempotency = _registry_object(
            item.get("idempotency"),
            label=f"{label}.idempotency",
            fields=idempotency_fields,
        )
        if (
            idempotency.get("required") is not (access == "write")
            or (access == "write" and idempotency.get("scope") not in idempotency_scopes)
        ):
            raise EvidenceVerificationError(f"registry idempotency policy is invalid: {label}")
        for field in ("verification", "recovery"):
            policy = _registry_object(
                item.get(field), label=f"{label}.{field}", fields={"method"}
            )
            _registry_text(policy.get("method"), label=f"{label}.{field}.method")
        _validate_registry_evidence(item, label=label)
    return hashlib.sha256(canonical_json(document["capabilities"])).hexdigest()


def _stream_sha256(path: Path, *, label: str) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceVerificationError(f"{label} cannot be opened safely") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise EvidenceVerificationError(f"{label} is not a one-link regular file")
        identity = _fingerprint(before)
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > 8 * 1024 * 1024 * 1024:
                raise EvidenceVerificationError(f"{label} is too large")
        if _fingerprint(os.fstat(descriptor)) != identity:
            raise EvidenceVerificationError(f"{label} changed during hashing")
        return digest.hexdigest(), before
    finally:
        os.close(descriptor)


def validate_closure_document(
    document: dict[str, Any],
    *,
    runtime: Mapping[str, Any],
    plan: Mapping[str, Any],
    expected: Mapping[str, str],
    expected_closure_anchor_sha256: str,
    expected_closure_image_sha256: str,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    verify_live_files: bool,
) -> dict[str, Any]:
    if (
        HEX64.fullmatch(expected_closure_anchor_sha256) is None
        or HEX64.fullmatch(expected_closure_image_sha256) is None
        or HEX64.fullmatch(expected_system_python_sha256) is None
        or HEX64.fullmatch(expected_loader_preload_sha256) is None
    ):
        raise EvidenceVerificationError("expected closure identity is invalid")
    if set(document) != {
        "schema_version",
        "status",
        "release_identity",
        "closure_identity",
        "database_scope",
        "mount",
        "systemd",
        "security",
        "activation",
    } or not _schema_version_is_one(
        document.get("schema_version")
    ) or document.get("status") != "active_verified":
        raise EvidenceVerificationError("closure verification envelope is invalid")
    if document.get("release_identity") != expected:
        raise EvidenceVerificationError("closure release identity is invalid")
    closure = document.get("closure_identity")
    fields = {
        "anchor_path",
        "anchor_sha256",
        "image_path",
        "image_sha256",
        "closure_manifest_sha256",
        "source_manifest_sha256",
        "sealed_config_path",
        "sealed_config_sha256",
        "system_python_sha256",
        "loader_preload_sha256",
        "loader_preload",
        "installed_modules_count",
        "installed_modules_sha256",
        "database_graph_sha256",
        "module_mapping_sha256",
        "module_payload_mapping_sha256",
        "external_runtime_manifest_sha256",
        "external_runtime_manifest_path",
        "external_runtime_paths",
        "external_runtime_derivation_method",
        "external_runtime_entry_count",
        "external_runtime_native_path_count",
        "closure_elf_count",
    }
    expected_anchor_path = str(
        PurePosixPath("/opt/odoo-accounting-cli-v3/dependency-anchors")
        / f"{expected['release']}.json"
    )
    expected_image_path = str(
        PurePosixPath("/opt/odoo-accounting-cli-v3/dependency-images")
        / f"{expected['release']}.squashfs"
    )
    expected_sealed_config = str(
        PurePosixPath("/etc/odoo-accounting-cli-v3/dependencies")
        / expected["release"]
        / "odoo-server19.conf"
    )
    if (
        type(closure) is not dict
        or set(closure) != fields
        or closure.get("anchor_path") != expected_anchor_path
        or closure.get("anchor_sha256") != expected_closure_anchor_sha256
        or closure.get("image_path") != expected_image_path
        or closure.get("image_sha256") != expected_closure_image_sha256
        or closure.get("sealed_config_path") != expected_sealed_config
        or closure.get("sealed_config_sha256") != runtime["odoo_config_sha256"]
        or closure.get("system_python_sha256") != expected_system_python_sha256
        or closure.get("loader_preload_sha256") != expected_loader_preload_sha256
        or type(closure.get("installed_modules_count")) is not int
        or closure["installed_modules_count"] <= 0
        or closure.get("external_runtime_derivation_method")
        != "static-python-elf-dt-needed-loader-preload-plus-root-owned-ld-cache-v2"
        or type(closure.get("external_runtime_entry_count")) is not int
        or closure["external_runtime_entry_count"] <= 0
        or type(closure.get("external_runtime_native_path_count")) is not int
        or closure["external_runtime_native_path_count"] <= 0
        or type(closure.get("closure_elf_count")) is not int
        or closure["closure_elf_count"] <= 0
    ):
        raise EvidenceVerificationError("closure identity is invalid")
    loader_preload = closure.get("loader_preload")
    libraries = loader_preload.get("libraries") if type(loader_preload) is dict else None
    symlinks = loader_preload.get("symlink_chain") if type(loader_preload) is dict else None
    if (
        type(loader_preload) is not dict
        or set(loader_preload)
        != {
            "path",
            "sha256",
            "size",
            "mode",
            "uid",
            "gid",
            "libraries",
            "symlink_chain",
            "loader_token_profile",
        }
        or loader_preload.get("path") != "/etc/ld.so.preload"
        or loader_preload.get("sha256") != expected_loader_preload_sha256
        or type(loader_preload.get("size")) is not int
        or not 0 < loader_preload["size"] <= 64 * 1024
        or loader_preload.get("mode") != "0644"
        or loader_preload.get("uid") != 0
        or loader_preload.get("gid") != 0
        or loader_preload.get("loader_token_profile")
        != "glibc-x86_64-debian-lib-v1"
        or type(libraries) is not list
        or not libraries
        or len(libraries) > 32
        or type(symlinks) is not list
    ):
        raise EvidenceVerificationError("closure loader preload identity is invalid")
    symlink_paths: list[str] = []
    for library in libraries:
        if type(library) is not dict or set(library) != {
            "configured_path",
            "expanded_path",
            "rooted_path",
            "resolved_path",
        }:
            raise EvidenceVerificationError("closure loader preload library is invalid")
        configured = library.get("configured_path")
        expanded = library.get("expanded_path")
        if (
            not isinstance(configured, str)
            or not configured
            or expanded
            != configured.replace("${LIB}", "lib/x86_64-linux-gnu").replace(
                "$LIB", "lib/x86_64-linux-gnu"
            )
            or not isinstance(expanded, str)
            or "$" in expanded
            or not PurePosixPath(expanded).is_absolute()
            or str(PurePosixPath(expanded)) != expanded
            or library.get("rooted_path") != expanded
            or not isinstance(library.get("resolved_path"), str)
            or not PurePosixPath(library["resolved_path"]).is_absolute()
            or str(PurePosixPath(library["resolved_path"])) != library["resolved_path"]
        ):
            raise EvidenceVerificationError("closure loader preload library path is invalid")
    for link in symlinks:
        if (
            type(link) is not dict
            or set(link) != {"path", "target", "uid", "gid"}
            or not isinstance(link.get("path"), str)
            or not PurePosixPath(link["path"]).is_absolute()
            or str(PurePosixPath(link["path"])) != link["path"]
            or not isinstance(link.get("target"), str)
            or not link["target"]
            or link.get("uid") != 0
            or link.get("gid") != 0
        ):
            raise EvidenceVerificationError("closure loader preload symlink is invalid")
        symlink_paths.append(link["path"])
    if symlink_paths != sorted(set(symlink_paths)):
        raise EvidenceVerificationError("closure loader preload symlink order is invalid")
    for field in (
        "closure_manifest_sha256",
        "source_manifest_sha256",
        "installed_modules_sha256",
        "database_graph_sha256",
        "module_mapping_sha256",
        "module_payload_mapping_sha256",
        "external_runtime_manifest_sha256",
    ):
        if not isinstance(closure.get(field), str) or HEX64.fullmatch(closure[field]) is None:
            raise EvidenceVerificationError("closure semantic digest is invalid")
    expected_external_manifest = str(
        PurePosixPath(
            f"/opt/odoo-accounting-cli-v3/dependencies/{expected['release']}"
        )
        / "EXTERNAL-RUNTIME-MANIFEST.json"
    )
    external_paths = closure.get("external_runtime_paths")
    if (
        closure.get("external_runtime_manifest_path") != expected_external_manifest
        or type(external_paths) is not list
        or external_paths != sorted(set(external_paths))
        or "/usr/bin/python3.12" not in external_paths
        or "/usr/lib/python3.12" not in external_paths
        or "/etc/ld.so.cache" not in external_paths
        or "/etc/ld.so.preload" not in external_paths
        or any(item["resolved_path"] not in external_paths for item in libraries)
        or any(
            not isinstance(item, str)
            or not PurePosixPath(item).is_absolute()
            or str(PurePosixPath(item)) != item
            for item in external_paths
        )
    ):
        raise EvidenceVerificationError("closure external runtime identity is invalid")
    database = plan["database"]
    if document.get("database_scope") != {
        "database_name": database["name"],
        "database_uuid": database["uuid"],
    }:
        raise EvidenceVerificationError("closure database scope is invalid")
    mount_point = PurePosixPath(
        f"/opt/odoo-accounting-cli-v3/dependencies/{expected['release']}"
    )
    mount = document.get("mount")
    mount_fields = {
        "mount_point",
        "filesystem_type",
        "read_only",
        "nodev",
        "nosuid",
        "backing_image_sha256",
        "namespace_scope",
        "self_mount_namespace",
        "host_mount_namespace",
        "loop_device",
        "loop_backing_device",
        "loop_backing_inode",
        "loop_offset",
        "loop_sizelimit",
        "loop_read_only",
        "loop_autoclear",
    }
    self_namespace = mount.get("self_mount_namespace") if type(mount) is dict else None
    host_namespace = mount.get("host_mount_namespace") if type(mount) is dict else None
    if (
        type(mount) is not dict
        or set(mount) != mount_fields
        or mount.get("mount_point") != str(mount_point)
        or mount.get("filesystem_type") != "squashfs"
        or mount.get("read_only") is not True
        or mount.get("nodev") is not True
        or mount.get("nosuid") is not True
        or mount.get("backing_image_sha256") != expected_closure_image_sha256
        or mount.get("namespace_scope") != "systemd-private"
        or type(self_namespace) is not dict
        or set(self_namespace) != {"device", "inode"}
        or type(host_namespace) is not dict
        or set(host_namespace) != {"device", "inode"}
        or any(
            type(namespace.get(field)) is not int or namespace[field] <= 0
            for namespace in (self_namespace, host_namespace)
            for field in ("device", "inode")
        )
        or self_namespace == host_namespace
        or not isinstance(mount.get("loop_device"), str)
        or re.fullmatch(r"/dev/loop[0-9]+", mount["loop_device"]) is None
        or type(mount.get("loop_backing_device")) is not int
        or mount["loop_backing_device"] <= 0
        or type(mount.get("loop_backing_inode")) is not int
        or mount["loop_backing_inode"] <= 0
        or mount.get("loop_offset") != 0
        or mount.get("loop_sizelimit") != 0
        or mount.get("loop_read_only") is not True
        or mount.get("loop_autoclear") is not True
    ):
        raise EvidenceVerificationError("closure mount identity is invalid")
    expected_binds = [
        {
            "source": str(mount_point / "odoo-server"),
            "destination": str(PurePosixPath(runtime["odoo_bin"]).parent),
        },
        {
            "source": str(mount_point / "odoo19-venv"),
            "destination": str(PurePosixPath(runtime["odoo_python"]).parent.parent),
        },
        {
            "source": str(mount_point / "custom-addons"),
            "destination": str(PurePosixPath(runtime["odoo_config"]).parent),
        },
        {
            "source": closure["sealed_config_path"],
            "destination": runtime["odoo_config"],
        },
    ]
    systemd = document.get("systemd")
    if (
        type(systemd) is not dict
        or set(systemd)
        != {
            "execution_model",
            "private_mounts",
            "bind_read_only_paths",
            "binding_phase",
            "supervisor_unit_properties",
            "child_execution",
        }
        or systemd.get("execution_model")
        != "single-supervisor-private-mount-namespace-v1"
        or systemd.get("private_mounts") is not True
        or systemd.get("bind_read_only_paths") != expected_binds
        or systemd.get("binding_phase")
        != "root-supervisor-after-squashfs-mount"
        or systemd.get("supervisor_unit_properties") != ["PrivateMounts=yes"]
        or systemd.get("child_execution")
        != {
            "method": "direct-fork-exec",
            "systemd_run_forbidden": True,
            "credential_drop_required": True,
            "capabilities_zero_required": True,
            "no_new_privileges_required": True,
        }
    ):
        raise EvidenceVerificationError("closure systemd bind plan is invalid")
    activation = document.get("activation")
    bindings = activation.get("bindings") if type(activation) is dict else None
    if (
        type(activation) is not dict
        or set(activation)
        != {
            "execution_model",
            "bindings",
            "binding_count",
            "config_binding_last",
            "host_mounts_absent",
            "direct_child_fork_exec_required",
            "systemd_run_forbidden",
        }
        or activation.get("execution_model")
        != "single-supervisor-private-mount-namespace-v1"
        or type(bindings) is not list
        or len(bindings) != 4
        or activation.get("binding_count") != 4
        or activation.get("config_binding_last") is not True
        or activation.get("host_mounts_absent") is not True
        or activation.get("direct_child_fork_exec_required") is not True
        or activation.get("systemd_run_forbidden") is not True
    ):
        raise EvidenceVerificationError("closure activation evidence is invalid")
    binding_fields = {
        "source",
        "destination",
        "mount_id",
        "major_minor",
        "filesystem_type",
        "source_device",
        "source_inode",
        "read_only",
        "nodev",
        "nosuid",
    }
    for binding, expected_bind in zip(bindings, expected_binds, strict=True):
        if (
            type(binding) is not dict
            or set(binding) != binding_fields
            or binding.get("source") != expected_bind["source"]
            or binding.get("destination") != expected_bind["destination"]
            or type(binding.get("mount_id")) is not int
            or binding["mount_id"] <= 0
            or not isinstance(binding.get("major_minor"), str)
            or re.fullmatch(r"[0-9]+:[0-9]+", binding["major_minor"]) is None
            or not isinstance(binding.get("filesystem_type"), str)
            or not binding["filesystem_type"]
            or type(binding.get("source_device")) is not int
            or binding["source_device"] <= 0
            or type(binding.get("source_inode")) is not int
            or binding["source_inode"] <= 0
            or binding.get("read_only") is not True
            or binding.get("nodev") is not True
            or binding.get("nosuid") is not True
        ):
            raise EvidenceVerificationError("closure activation binding is invalid")
    security = document.get("security")
    if (
        type(security) is not dict
        or set(security) != CLOSURE_SECURITY_FIELDS
        or security != CLOSURE_SECURITY_EXPECTED
    ):
        raise EvidenceVerificationError("closure security proof is invalid")
    if verify_live_files:
        anchor_digest, anchor_metadata = _stream_sha256(
            Path(closure["anchor_path"]), label="closure anchor"
        )
        image_digest, image_metadata = _stream_sha256(
            Path(closure["image_path"]), label="closure image"
        )
        config_digest, config_metadata = _stream_sha256(
            Path(closure["sealed_config_path"]), label="sealed Odoo config"
        )
        preload_digest, preload_metadata = _stream_sha256(
            Path("/etc/ld.so.preload"), label="loader preload"
        )
        if (
            anchor_digest != expected_closure_anchor_sha256
            or image_digest != expected_closure_image_sha256
            or config_digest != runtime["odoo_config_sha256"]
            or preload_digest != expected_loader_preload_sha256
            or preload_metadata.st_uid != 0
            or preload_metadata.st_gid != 0
            or stat.S_IMODE(preload_metadata.st_mode) != 0o644
            or preload_metadata.st_nlink != 1
            or any(metadata.st_uid != 0 for metadata in (anchor_metadata, image_metadata, config_metadata))
            or (mount["loop_backing_device"], mount["loop_backing_inode"])
            != (image_metadata.st_dev, image_metadata.st_ino)
        ):
            raise EvidenceVerificationError("live closure file identity drifted")
        observed_self = Path("/proc/self/ns/mnt").stat()
        observed_host = Path("/proc/1/ns/mnt").stat()
        if (
            self_namespace
            != {"device": observed_self.st_dev, "inode": observed_self.st_ino}
            or host_namespace
            != {"device": observed_host.st_dev, "inode": observed_host.st_ino}
        ):
            raise EvidenceVerificationError("live closure mount namespace drifted")
        for item in expected_binds[:3]:
            source = Path(item["source"])
            metadata = source.lstat()
            if (
                source.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or not os.statvfs(source).f_flag & os.ST_RDONLY
            ):
                raise EvidenceVerificationError("live closure bind source is unsafe")
        placeholder = Path(
            str(
                mount_point
                / "custom-addons"
                / PurePosixPath(runtime["odoo_config"]).name
            )
        )
        metadata = placeholder.lstat()
        if (
            placeholder.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != 0
            or not os.statvfs(placeholder).f_flag & os.ST_RDONLY
        ):
            raise EvidenceVerificationError("closure config placeholder is unsafe")
    return document


def _independent_selected_regular_files(mount_point: Path) -> list[Path]:
    roots = tuple(
        mount_point / name
        for name in ("odoo-server", "odoo19-venv", "custom-addons")
    )
    result: list[Path] = []
    seen: set[tuple[int, int]] = set()
    pending = list(roots)
    while pending:
        path = pending.pop()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise EvidenceVerificationError(
                f"closure dependency cannot be inspected: {path}"
            ) from exc
        if stat.S_ISDIR(metadata.st_mode):
            try:
                pending.extend(
                    Path(child.path) for child in sorted(os.scandir(path), key=lambda item: item.name)
                )
            except OSError as exc:
                raise EvidenceVerificationError(
                    f"closure directory cannot be enumerated: {path}"
                ) from exc
        elif stat.S_ISREG(metadata.st_mode):
            identity = (metadata.st_dev, metadata.st_ino)
            if identity not in seen:
                seen.add(identity)
                result.append(path)
        elif stat.S_ISLNK(metadata.st_mode):
            try:
                resolved = path.resolve(strict=True)
                resolved_metadata = resolved.lstat()
            except OSError as exc:
                raise EvidenceVerificationError(
                    f"closure symlink cannot be resolved: {path}"
                ) from exc
            if stat.S_ISREG(resolved_metadata.st_mode):
                identity = (resolved_metadata.st_dev, resolved_metadata.st_ino)
                if identity not in seen:
                    seen.add(identity)
                    result.append(resolved)
        else:
            raise EvidenceVerificationError(
                f"closure dependency contains a special object: {path}"
            )
        if len(seen) > MAX_TREE_FILES:
            raise EvidenceVerificationError("closure dependency inventory is too large")
    return result


def _independent_elf_dynamic(path: Path) -> tuple[str | None, list[str], list[str]]:
    try:
        resolved = path.resolve(strict=True)
        payload = stable_read(
            resolved,
            label=f"closure ELF {path}",
            maximum=256 * 1024 * 1024,
        )
    except OSError as exc:
        raise EvidenceVerificationError(f"closure ELF cannot be read: {path}") from exc
    if len(payload) < 64 or payload[:4] != b"\x7fELF":
        raise EvidenceVerificationError(f"closure ELF header is invalid: {path}")
    elf_class, data_encoding = payload[4], payload[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2}:
        raise EvidenceVerificationError(
            f"closure ELF class or endianness is unsupported: {path}"
        )
    endian = "<" if data_encoding == 1 else ">"
    try:
        if elf_class == 2:
            phoff = struct.unpack_from(endian + "Q", payload, 32)[0]
            phentsize = struct.unpack_from(endian + "H", payload, 54)[0]
            phnum = struct.unpack_from(endian + "H", payload, 56)[0]
            minimum_phentsize = 56
        else:
            phoff = struct.unpack_from(endian + "I", payload, 28)[0]
            phentsize = struct.unpack_from(endian + "H", payload, 42)[0]
            phnum = struct.unpack_from(endian + "H", payload, 44)[0]
            minimum_phentsize = 32
    except struct.error as exc:
        raise EvidenceVerificationError(f"closure ELF header is truncated: {path}") from exc
    if (
        phentsize < minimum_phentsize
        or phnum <= 0
        or phnum > 4096
        or phoff + phentsize * phnum > len(payload)
    ):
        raise EvidenceVerificationError(
            f"closure ELF program header table is invalid: {path}"
        )
    loads: list[tuple[int, int, int]] = []
    dynamic: tuple[int, int] | None = None
    interpreter: str | None = None
    for index in range(phnum):
        offset = phoff + index * phentsize
        try:
            if elf_class == 2:
                segment_type = struct.unpack_from(endian + "I", payload, offset)[0]
                file_offset, virtual = struct.unpack_from(
                    endian + "QQ", payload, offset + 8
                )
                file_size = struct.unpack_from(endian + "Q", payload, offset + 32)[0]
            else:
                segment_type, file_offset, virtual = struct.unpack_from(
                    endian + "III", payload, offset
                )
                file_size = struct.unpack_from(endian + "I", payload, offset + 16)[0]
        except struct.error as exc:
            raise EvidenceVerificationError(
                f"closure ELF program header is truncated: {path}"
            ) from exc
        if file_offset + file_size > len(payload):
            raise EvidenceVerificationError(f"closure ELF segment is invalid: {path}")
        if segment_type == 1:
            loads.append((virtual, file_offset, file_size))
        elif segment_type == 2:
            if dynamic is not None:
                raise EvidenceVerificationError(
                    f"closure ELF has multiple dynamic segments: {path}"
                )
            dynamic = (file_offset, file_size)
        elif segment_type == 3:
            raw = payload[file_offset : file_offset + file_size]
            if not raw.endswith(b"\0") or raw.count(b"\0") != 1:
                raise EvidenceVerificationError(
                    f"closure ELF interpreter is invalid: {path}"
                )
            interpreter = os.fsdecode(raw[:-1])
            if not interpreter.startswith("/"):
                raise EvidenceVerificationError(
                    f"closure ELF interpreter is not absolute: {path}"
                )
    if dynamic is None:
        return interpreter, [], []
    entry_size = 16 if elf_class == 2 else 8
    dynamic_offset, dynamic_size = dynamic
    if dynamic_size % entry_size:
        raise EvidenceVerificationError(
            f"closure ELF dynamic table is unaligned: {path}"
        )
    needed_offsets: list[int] = []
    search_offsets: list[int] = []
    string_address: int | None = None
    string_size: int | None = None
    terminated = False
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, entry_size):
        try:
            tag, value = struct.unpack_from(
                endian + ("qQ" if elf_class == 2 else "iI"), payload, offset
            )
        except struct.error as exc:
            raise EvidenceVerificationError(
                f"closure ELF dynamic entry is truncated: {path}"
            ) from exc
        if tag == 0:
            terminated = True
            break
        if tag == 1:
            needed_offsets.append(value)
        elif tag == 5:
            string_address = value
        elif tag == 10:
            string_size = value
        elif tag in {15, 29}:
            search_offsets.append(value)
    if not terminated or string_address is None or string_size is None:
        raise EvidenceVerificationError(
            f"closure ELF dynamic string table is incomplete: {path}"
        )
    string_offset: int | None = None
    for virtual, file_offset, file_size in loads:
        if virtual <= string_address < virtual + file_size:
            string_offset = file_offset + string_address - virtual
            break
    if string_offset is None or string_offset + string_size > len(payload):
        raise EvidenceVerificationError(
            f"closure ELF dynamic string table is out of bounds: {path}"
        )

    def dynamic_string(index: int) -> str:
        if index < 0 or index >= string_size:
            raise EvidenceVerificationError(
                f"closure ELF dynamic string index is invalid: {path}"
            )
        start = string_offset + index
        end = payload.find(b"\0", start, string_offset + string_size)
        if end < 0:
            raise EvidenceVerificationError(
                f"closure ELF dynamic string is unterminated: {path}"
            )
        value = os.fsdecode(payload[start:end])
        if not value or "\x00" in value:
            raise EvidenceVerificationError(
                f"closure ELF dynamic string is empty: {path}"
            )
        return value

    needed = [dynamic_string(index) for index in needed_offsets]
    if any("/" in item or item in {".", ".."} for item in needed):
        raise EvidenceVerificationError(f"closure ELF dependency is unsafe: {path}")
    search: list[str] = []
    for index in search_offsets:
        search.extend(dynamic_string(index).split(":"))
    return interpreter, needed, search


def _loader_stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _hash_loader_descriptor(
    descriptor: int,
    *,
    identity: tuple[int, ...],
    expected_sha256: str,
) -> int:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        metadata = os.fstat(descriptor)
        if _loader_stat_identity(metadata) != identity:
            raise EvidenceVerificationError("fixed loader-cache reader identity drifted")
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise EvidenceVerificationError("fixed loader-cache reader changed during read")
            digest.update(chunk)
            remaining -= len(chunk)
        if (
            os.read(descriptor, 1)
            or _loader_stat_identity(os.fstat(descriptor)) != identity
            or digest.hexdigest() != expected_sha256
        ):
            raise EvidenceVerificationError("fixed loader-cache reader identity drifted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return metadata.st_size
    except OSError as exc:
        raise EvidenceVerificationError("fixed loader-cache reader cannot be hashed") from exc


def _verify_executed_loader_bytes(pid: int, expected_sha256: str) -> None:
    # /proc/<pid>/exe is a kernel magic link, so O_NOFOLLOW cannot be used here.
    # The child is ptrace-stopped before its first instruction; hashing this fd
    # proves the actual executable bytes even when overlayfs reports a different
    # device/inode than the path fd opened by the parent.
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(f"/proc/{pid}/exe", flags)
    except OSError as exc:
        raise EvidenceVerificationError(
            "fixed loader-cache executed bytes cannot be opened"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_JSON_BYTES
        ):
            raise EvidenceVerificationError(
                "fixed loader-cache reader executed unpinned bytes"
            )
        try:
            _hash_loader_descriptor(
                descriptor,
                identity=_loader_stat_identity(metadata),
                expected_sha256=expected_sha256,
            )
        except EvidenceVerificationError as exc:
            raise EvidenceVerificationError(
                "fixed loader-cache reader executed unpinned bytes"
            ) from exc
    finally:
        os.close(descriptor)


def _independent_loader_cache(
    expected_ldconfig_sha256: str,
) -> dict[str, list[Path]]:
    ldconfig = Path(CLOSURE_LDCONFIG)
    if os.name != "posix" or HEX64.fullmatch(expected_ldconfig_sha256) is None:
        raise EvidenceVerificationError("fixed loader-cache reader digest is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(ldconfig, flags)
    except OSError as exc:
        raise EvidenceVerificationError("fixed loader-cache reader cannot be opened safely") from exc
    process: subprocess.Popen[bytes] | None = None
    traced = False
    try:
        metadata = os.fstat(descriptor)
        path_metadata = ldconfig.lstat()
        identity = _loader_stat_identity(metadata)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_JSON_BYTES
            or identity != _loader_stat_identity(path_metadata)
        ):
            raise EvidenceVerificationError("fixed loader-cache reader is unsafe")
        _hash_loader_descriptor(
            descriptor,
            identity=identity,
            expected_sha256=expected_ldconfig_sha256,
        )
        command = [str(ldconfig), "-p"]
        process = subprocess.Popen(
            command,
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
            preexec_fn=_ptrace_traceme,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=LDCONFIG_ENVIRONMENT,
        )
        traced = True
        waited, status = os.waitpid(process.pid, os.WUNTRACED)
        if (
            waited != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                process.returncode = os.waitstatus_to_exitcode(status)
                traced = False
            raise EvidenceVerificationError("fixed loader-cache reader exec trace is invalid")
        _ptrace_set_exitkill(process.pid)
        _verify_executed_loader_bytes(process.pid, expected_ldconfig_sha256)
        traced = False
        try:
            _ptrace_detach(process.pid)
        except BaseException:
            traced = True
            raise
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        _hash_loader_descriptor(
            descriptor,
            identity=identity,
            expected_sha256=expected_ldconfig_sha256,
        )
        path_current = ldconfig.lstat()
        if _loader_stat_identity(path_current) != identity:
            raise EvidenceVerificationError(
                "fixed loader-cache reader changed across pinned execution"
            )
        if process.returncode != 0 or stderr or len(stdout) > 16 * 1024 * 1024:
            raise EvidenceVerificationError("fixed loader cache cannot be listed")
        try:
            output = stdout.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise EvidenceVerificationError("fixed loader cache cannot be listed") from exc
    except BaseException:
        if process is not None and process.returncode is None:
            _kill_and_reap_loader_process(process, traced=traced)
        raise
    finally:
        os.close(descriptor)
    mapping: dict[str, list[Path]] = {}
    for raw in output.splitlines():
        match = re.fullmatch(r"([^\s]+) \([^)]*\) => (/[^\s]+)", raw.strip())
        if match is None:
            continue
        name, path_text = match.groups()
        candidate = Path(path_text)
        if candidate.exists():
            mapping.setdefault(name, []).append(candidate)
    for name, paths in mapping.items():
        mapping[name] = sorted(dict.fromkeys(paths), key=str)
    if not mapping:
        raise EvidenceVerificationError("fixed loader cache listing is empty")
    return mapping


def independently_derive_external_runtime(
    closure: Mapping[str, Any], *, expected_ldconfig_sha256: str
) -> tuple[list[str], int, int]:
    if (
        os.name != "posix"
        or not hasattr(os, "uname")
        or os.uname().machine != "x86_64"
        or sys.version_info[:2] != (3, 12)
        or Path("/proc/self/exe").resolve(strict=True)
        != Path("/usr/bin/python3.12").resolve(strict=True)
    ):
        raise EvidenceVerificationError(
            "independent external-runtime derivation host facts are invalid"
        )
    mount_point = Path(closure["mount"]["mount_point"])
    files = _independent_selected_regular_files(mount_point)
    selected_roots = [
        (mount_point / name).resolve(strict=True)
        for name in ("odoo-server", "odoo19-venv", "custom-addons")
    ]
    by_basename: dict[str, list[Path]] = {}
    elf_files: list[Path] = []
    for path in files:
        by_basename.setdefault(path.name, []).append(path)
        try:
            with path.open("rb") as stream:
                if stream.read(4) == b"\x7fELF":
                    elf_files.append(path)
        except OSError as exc:
            raise EvidenceVerificationError(
                f"closure ELF candidate cannot be read: {path}"
            ) from exc
    if not elf_files:
        raise EvidenceVerificationError("closure ELF inventory is empty")
    cache = _independent_loader_cache(expected_ldconfig_sha256)
    defaults = tuple(
        Path(path)
        for path in (
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
        )
    )
    queue = list(elf_files)
    processed: set[tuple[int, int]] = set()
    external: set[Path] = set()

    def inside_selected(candidate: Path) -> bool:
        resolved = candidate.resolve(strict=True)
        return any(
            resolved == root or root in resolved.parents for root in selected_roots
        )

    while queue:
        elf = queue.pop()
        resolved_elf = elf.resolve(strict=True)
        metadata = resolved_elf.lstat()
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in processed:
            continue
        processed.add(identity)
        interpreter, needed, raw_search = _independent_elf_dynamic(elf)
        if interpreter is not None:
            candidate = Path(interpreter)
            if not candidate.is_file():
                raise EvidenceVerificationError(
                    f"closure ELF interpreter is unavailable: {interpreter}"
                )
            external.update({candidate, candidate.resolve(strict=True)})
            queue.append(candidate.resolve(strict=True))
        origin = resolved_elf.parent
        search: list[Path] = []
        for raw in raw_search:
            expanded = raw.replace("${ORIGIN}", str(origin)).replace(
                "$ORIGIN", str(origin)
            )
            if "$" in expanded or not expanded or not Path(expanded).is_absolute():
                raise EvidenceVerificationError(
                    f"closure ELF search path is unsafe: {elf}"
                )
            search.append(Path(expanded))
        for dependency in needed:
            candidates: list[Path] = []
            for directory in search:
                candidate = directory / dependency
                if candidate.exists():
                    if not inside_selected(candidate):
                        raise EvidenceVerificationError(
                            f"closure ELF RPATH escapes the closure: {elf}"
                        )
                    candidates.append(candidate)
            if not candidates:
                internal = by_basename.get(dependency, [])
                if len(internal) == 1:
                    candidates = internal
                elif len(internal) > 1:
                    raise EvidenceVerificationError(
                        f"closure ELF internal dependency is ambiguous: {dependency}"
                    )
            if not candidates:
                candidates = cache.get(dependency, [])
            if not candidates:
                candidates = [
                    directory / dependency
                    for directory in defaults
                    if (directory / dependency).exists()
                ]
            if not candidates:
                raise EvidenceVerificationError(
                    f"closure ELF dependency is unresolved: {dependency}"
                )
            resolved_candidates = list(
                dict.fromkeys(candidate.resolve(strict=True) for candidate in candidates)
            )
            if len(resolved_candidates) != 1:
                same_abi = [
                    candidate
                    for candidate in resolved_candidates
                    if "x86_64-linux-gnu" in str(candidate)
                ]
                if len(same_abi) != 1:
                    raise EvidenceVerificationError(
                        f"closure ELF dependency resolution is ambiguous: {dependency}"
                    )
                resolved = same_abi[0]
            else:
                resolved = resolved_candidates[0]
            selected = candidates[0]
            if inside_selected(resolved):
                queue.append(resolved)
            else:
                external.update({selected, resolved})
                queue.append(resolved)
    fixed = {
        Path("/usr/bin/python3.12"),
        Path("/usr/lib/python3.12"),
        Path("/etc/ld.so.cache"),
    }
    roots = sorted({str(path.absolute()) for path in fixed | external})
    return roots, len(elf_files), len(roots) - len(fixed)


def independently_snapshot_external_manifest(roots: Sequence[str]) -> dict[str, Any]:
    canonical_roots = sorted(set(roots))
    if canonical_roots != list(roots):
        raise EvidenceVerificationError("derived external runtime roots are not canonical")
    entries: dict[str, dict[str, Any]] = {}
    for root_text in canonical_roots:
        root = Path(root_text)
        if not root.is_absolute() or str(root) != root_text:
            raise EvidenceVerificationError("derived external runtime root is invalid")
        pending = [root]
        while pending:
            path = pending.pop()
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise EvidenceVerificationError(
                    f"derived external runtime path is absent: {path}"
                ) from exc
            common = {
                "path": str(path),
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
            if stat.S_ISDIR(metadata.st_mode):
                entry = {**common, "kind": "directory"}
                try:
                    pending.extend(
                        Path(child.path)
                        for child in sorted(os.scandir(path), key=lambda item: item.name)
                    )
                except OSError as exc:
                    raise EvidenceVerificationError(
                        f"derived external runtime directory is unreadable: {path}"
                    ) from exc
            elif stat.S_ISREG(metadata.st_mode):
                digest, observed = _stream_sha256(
                    path, label=f"derived external runtime {path}"
                )
                entry = {
                    **common,
                    "kind": "regular",
                    "size": observed.st_size,
                    "sha256": digest,
                }
            elif stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(path)
                entry = {**common, "kind": "symlink", "target": target}
                pending.append(path.resolve(strict=True))
            else:
                raise EvidenceVerificationError(
                    f"derived external runtime contains a special object: {path}"
                )
            previous = entries.get(str(path))
            if previous is not None and previous != entry:
                raise EvidenceVerificationError(
                    "derived external runtime identity is ambiguous"
                )
            entries[str(path)] = entry
            if len(entries) > MAX_EXTERNAL_ENTRIES:
                raise EvidenceVerificationError(
                    "derived external runtime inventory is too large"
                )
    return {
        "schema_version": 1,
        "python_abi": "3.12",
        "roots": canonical_roots,
        "entries": [entries[path] for path in sorted(entries)],
    }


def validate_external_runtime_manifest(
    closure: Mapping[str, Any], *, verify_live_files: bool, expected_ldconfig_sha256: str
) -> dict[str, Any]:
    if not verify_live_files:
        raise EvidenceVerificationError(
            "external-runtime completeness requires live independent derivation"
        )
    identity = closure["closure_identity"]
    manifest_path = Path(identity["external_runtime_manifest_path"])
    payload = stable_read(
        manifest_path,
        label="closure external runtime manifest",
        maximum=MAX_JSON_BYTES,
        expected_uid=0 if verify_live_files and os.name == "posix" else None,
        expected_gid=0 if verify_live_files and os.name == "posix" else None,
        allowed_modes=frozenset({0o444})
        if verify_live_files and os.name == "posix"
        else None,
    )
    document = parse_json(payload, label="closure external runtime manifest")
    roots = document.get("roots") if type(document) is dict else None
    entries = document.get("entries") if type(document) is dict else None
    if (
        set(document) != {"schema_version", "python_abi", "roots", "entries"}
        or not _schema_version_is_one(document.get("schema_version"))
        or document.get("python_abi") != "3.12"
        or roots != identity["external_runtime_paths"]
        or type(entries) is not list
        or not entries
        or payload != canonical_json(document) + b"\n"
        or hashlib.sha256(canonical_json(document)).hexdigest()
        != identity["external_runtime_manifest_sha256"]
        or identity.get("external_runtime_entry_count") != len(entries)
        or identity.get("external_runtime_native_path_count") != len(roots) - 3
    ):
        raise EvidenceVerificationError("closure external runtime manifest is invalid")
    entry_paths = [item.get("path") for item in entries if type(item) is dict]
    if entry_paths != sorted(set(entry_paths)) or any(root not in entry_paths for root in roots):
        raise EvidenceVerificationError("closure external runtime coverage is invalid")
    derived_roots, derived_elf_count, derived_native_count = (
        independently_derive_external_runtime(
            closure, expected_ldconfig_sha256=expected_ldconfig_sha256
        )
    )
    if (
        roots != derived_roots
        or identity.get("closure_elf_count") != derived_elf_count
        or identity.get("external_runtime_native_path_count")
        != derived_native_count
    ):
        raise EvidenceVerificationError(
            "closure external runtime omits an independently derived dependency"
        )
    if independently_snapshot_external_manifest(derived_roots) != document:
        raise EvidenceVerificationError(
            "closure external runtime manifest omits or changes a live dependency entry"
        )
    root_paths = [PurePosixPath(item) for item in roots]
    for item in entries:
        path_text = item.get("path") if type(item) is dict else None
        kind = item.get("kind") if type(item) is dict else None
        portable = PurePosixPath(path_text) if isinstance(path_text, str) else None
        common = {"path", "kind", "mode", "uid", "gid"}
        fields = {
            "directory": common,
            "regular": common | {"size", "sha256"},
            "symlink": common | {"target"},
        }
        if (
            portable is None
            or not portable.is_absolute()
            or str(portable) != path_text
            or kind not in fields
            or set(item) != fields[kind]
            or not any(portable == root or root in portable.parents for root in root_paths)
            or not isinstance(item.get("mode"), str)
            or re.fullmatch(r"[0-7]{4}", item["mode"]) is None
            or item.get("uid") != 0
            or item.get("gid") != 0
        ):
            raise EvidenceVerificationError("closure external runtime entry is invalid")
        if kind == "regular" and (
            type(item.get("size")) is not int
            or item["size"] < 0
            or not isinstance(item.get("sha256"), str)
            or HEX64.fullmatch(item["sha256"]) is None
        ):
            raise EvidenceVerificationError("closure external runtime file entry is invalid")
        if kind == "symlink" and (
            not isinstance(item.get("target"), str) or not item["target"]
        ):
            raise EvidenceVerificationError("closure external runtime symlink entry is invalid")
    return {
        "schema_version": 1,
        "manifest_path": str(manifest_path),
        "manifest_file_sha256": hashlib.sha256(payload).hexdigest(),
        "manifest_semantic_sha256": identity["external_runtime_manifest_sha256"],
        "root_count": len(roots),
        "entry_count": len(entries),
        "derived_roots": derived_roots,
        "native_path_count": identity["external_runtime_native_path_count"],
        "closure_elf_count": identity["closure_elf_count"],
        "derivation_method": identity["external_runtime_derivation_method"],
        "roots_sha256": hashlib.sha256(canonical_json(roots)).hexdigest(),
        "all_entries_recomputed": True,
    }


def _read_virtual_text(path: Path, *, label: str, maximum: int = 16 * 1024 * 1024) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceVerificationError(f"{label} cannot be opened") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise EvidenceVerificationError(f"{label} is too large")
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("utf-8", "strict")
    except UnicodeError as exc:
        raise EvidenceVerificationError(f"{label} is not UTF-8") from exc


def _mount_unescape(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value
    )


def current_mount_binding(closure: Mapping[str, Any]) -> dict[str, Any]:
    mount_point = closure["mount"]["mount_point"]
    matches = []
    for line in _read_virtual_text(
        Path("/proc/self/mountinfo"), label="Linux mountinfo"
    ).splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise EvidenceVerificationError("Linux mountinfo line is invalid") from exc
        if len(fields) < 10 or separator < 6 or len(fields) <= separator + 3:
            raise EvidenceVerificationError("Linux mountinfo line is incomplete")
        if _mount_unescape(fields[4]) == mount_point:
            matches.append((fields, separator))
    if len(matches) != 1:
        raise EvidenceVerificationError("closure mount point is absent or ambiguous")
    fields, separator = matches[0]
    filesystem_type = fields[separator + 1]
    source = _mount_unescape(fields[separator + 2])
    options = sorted(set(fields[5].split(",")))
    super_options = sorted(set(fields[separator + 3].split(",")))
    if (
        filesystem_type != "squashfs"
        or "ro" not in options
        or "nodev" not in options
        or "nosuid" not in options
        or re.fullmatch(r"/dev/loop[0-9]+", source) is None
        or not os.statvfs(mount_point).f_flag & os.ST_RDONLY
    ):
        raise EvidenceVerificationError("closure mount flags or source are invalid")
    device = fields[2]
    if re.fullmatch(r"[0-9]+:[0-9]+", device) is None:
        raise EvidenceVerificationError("closure mount device identity is invalid")
    backing = _read_virtual_text(
        Path(f"/sys/dev/block/{device}/loop/backing_file"),
        label="loop backing file",
        maximum=64 * 1024,
    ).strip()
    if not backing or backing.endswith(" (deleted)"):
        raise EvidenceVerificationError("closure loop backing file is invalid")
    if not backing.startswith("/"):
        backing = "/" + backing
    expected_image = Path(closure["closure_identity"]["image_path"])
    if Path(backing).resolve(strict=True) != expected_image.resolve(strict=True):
        raise EvidenceVerificationError("closure mount backing image is invalid")
    try:
        loop_metadata = Path(source).lstat()
        image_metadata = expected_image.lstat()
        if (
            not stat.S_ISBLK(loop_metadata.st_mode)
            or f"{os.major(loop_metadata.st_rdev)}:{os.minor(loop_metadata.st_rdev)}"
            != device
        ):
            raise EvidenceVerificationError("closure loop device identity is invalid")
        import fcntl

        descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            status = bytearray(232)
            fcntl.ioctl(descriptor, 0x4C05, status, True)
        finally:
            os.close(descriptor)
        backing_device, backing_inode, _rdevice, offset, sizelimit = struct.unpack_from(
            "=QQQQQ", status, 0
        )
        _number, _encryption, _key_size, flags = struct.unpack_from(
            "=IIII", status, 40
        )
        self_metadata = Path("/proc/self/ns/mnt").stat()
        host_metadata = Path("/proc/1/ns/mnt").stat()
    except EvidenceVerificationError:
        raise
    except OSError as exc:
        raise EvidenceVerificationError(
            "closure loop or namespace identity cannot be inspected"
        ) from exc
    self_namespace = {"device": self_metadata.st_dev, "inode": self_metadata.st_ino}
    host_namespace = {"device": host_metadata.st_dev, "inode": host_metadata.st_ino}
    if (
        (backing_device, backing_inode) != (image_metadata.st_dev, image_metadata.st_ino)
        or offset != 0
        or sizelimit != 0
        or flags & 0x1 != 0x1
        or flags & 0x4 != 0x4
        or self_namespace == host_namespace
        or closure["mount"]["namespace_scope"] != "systemd-private"
        or closure["mount"]["self_mount_namespace"] != self_namespace
        or closure["mount"]["host_mount_namespace"] != host_namespace
        or closure["mount"]["loop_device"] != source
        or closure["mount"]["loop_backing_device"] != backing_device
        or closure["mount"]["loop_backing_inode"] != backing_inode
        or closure["mount"]["loop_offset"] != offset
        or closure["mount"]["loop_sizelimit"] != sizelimit
        or closure["mount"]["loop_read_only"] is not True
        or closure["mount"]["loop_autoclear"] is not True
    ):
        raise EvidenceVerificationError(
            "closure loop or private namespace attestation drifted"
        )
    return {
        "schema_version": 1,
        "mount_id": int(fields[0]),
        "parent_mount_id": int(fields[1]),
        "device_major_minor": device,
        "root": _mount_unescape(fields[3]),
        "mount_point": mount_point,
        "filesystem_type": filesystem_type,
        "source": source,
        "options": options,
        "super_options": super_options,
        "loop_backing_file": str(expected_image),
        "loop_backing_image_sha256": closure["closure_identity"]["image_sha256"],
        "namespace_scope": "systemd-private",
        "self_mount_namespace": self_namespace,
        "host_mount_namespace": host_namespace,
        "loop_device": source,
        "loop_backing_device": backing_device,
        "loop_backing_inode": backing_inode,
        "loop_offset": offset,
        "loop_sizelimit": sizelimit,
        "loop_read_only": True,
        "loop_autoclear": True,
        "statvfs_read_only": True,
    }


def validate_mount_binding_document(
    document: dict[str, Any], *, closure: Mapping[str, Any]
) -> None:
    fields = {
        "schema_version",
        "mount_id",
        "parent_mount_id",
        "device_major_minor",
        "root",
        "mount_point",
        "filesystem_type",
        "source",
        "options",
        "super_options",
        "loop_backing_file",
        "loop_backing_image_sha256",
        "namespace_scope",
        "self_mount_namespace",
        "host_mount_namespace",
        "loop_device",
        "loop_backing_device",
        "loop_backing_inode",
        "loop_offset",
        "loop_sizelimit",
        "loop_read_only",
        "loop_autoclear",
        "statvfs_read_only",
    }
    options = document.get("options") if type(document) is dict else None
    super_options = document.get("super_options") if type(document) is dict else None
    if (
        type(document) is not dict
        or set(document) != fields
        or not _schema_version_is_one(document.get("schema_version"))
        or type(document.get("mount_id")) is not int
        or document["mount_id"] <= 0
        or type(document.get("parent_mount_id")) is not int
        or document["parent_mount_id"] < 0
        or not isinstance(document.get("device_major_minor"), str)
        or re.fullmatch(r"[0-9]+:[0-9]+", document["device_major_minor"]) is None
        or not isinstance(document.get("root"), str)
        or document.get("mount_point") != closure["mount"]["mount_point"]
        or document.get("filesystem_type") != "squashfs"
        or not isinstance(document.get("source"), str)
        or not document["source"].startswith("/dev/loop")
        or type(options) is not list
        or options != sorted(set(options))
        or not {"ro", "nodev", "nosuid"}.issubset(set(options))
        or type(super_options) is not list
        or super_options != sorted(set(super_options))
        or document.get("loop_backing_file")
        != closure["closure_identity"]["image_path"]
        or document.get("loop_backing_image_sha256")
        != closure["closure_identity"]["image_sha256"]
        or document.get("namespace_scope") != "systemd-private"
        or document.get("self_mount_namespace")
        != closure["mount"]["self_mount_namespace"]
        or document.get("host_mount_namespace")
        != closure["mount"]["host_mount_namespace"]
        or document.get("self_mount_namespace")
        == document.get("host_mount_namespace")
        or document.get("loop_device") != closure["mount"]["loop_device"]
        or document.get("loop_backing_device")
        != closure["mount"]["loop_backing_device"]
        or document.get("loop_backing_inode")
        != closure["mount"]["loop_backing_inode"]
        or document.get("loop_offset") != 0
        or document.get("loop_sizelimit") != 0
        or document.get("loop_read_only") is not True
        or document.get("loop_autoclear") is not True
        or document.get("statvfs_read_only") is not True
    ):
        raise EvidenceVerificationError("recorded closure mount binding is invalid")


def validate_addons_document(
    document: dict[str, Any],
    *,
    closure: Mapping[str, Any],
    runtime: Mapping[str, Any],
    verify_live_file: bool,
) -> None:
    paths = document.get("paths") if type(document) is dict else None
    if (
        set(document)
        != {
            "schema_version",
            "paths",
            "path_count",
            "all_paths_covered_by_read_only_binds",
            "config_sha256",
        }
        or not _schema_version_is_one(document.get("schema_version"))
        or type(paths) is not list
        or not paths
        or document.get("path_count") != len(paths)
        or document.get("all_paths_covered_by_read_only_binds") is not True
        or document.get("config_sha256") != runtime["odoo_config_sha256"]
    ):
        raise EvidenceVerificationError("addons_path evidence is invalid")
    roots = [
        Path(item["destination"])
        for item in closure["systemd"]["bind_read_only_paths"][:3]
        if item["destination"]
        != str(PurePosixPath(runtime["odoo_python"]).parent.parent)
    ]
    if any(
        not isinstance(item, str)
        or not Path(item).is_absolute()
        or not any(Path(item) == root or root in Path(item).parents for root in roots)
        for item in paths
    ):
        raise EvidenceVerificationError("addons_path escaped closure binds")
    if verify_live_file:
        config_path = Path(closure["closure_identity"]["sealed_config_path"])
        payload = stable_read(
            config_path,
            label="sealed Odoo config for addons_path verification",
            maximum=16 * 1024 * 1024,
        )
        try:
            parser = configparser.RawConfigParser(interpolation=None, strict=True)
            parser.read_string(payload.decode("utf-8", "strict"))
            actual = [item.strip() for item in parser.get("options", "addons_path").split(",") if item.strip()]
        except (configparser.Error, UnicodeError) as exc:
            raise EvidenceVerificationError("sealed addons_path cannot be parsed") from exc
        if actual != paths:
            raise EvidenceVerificationError("addons_path evidence differs from sealed config")


def validate_signed_selection(
    request: dict[str, Any],
    *,
    base_case: Mapping[str, Any],
    selected_identity: Mapping[str, Any],
    runtime: Mapping[str, Any],
    mutation: Mapping[str, Any] | None,
) -> None:
    context = request.get("context") if type(request) is dict else None
    parameters = request.get("parameters") if type(request) is dict else None
    if (
        set(request) != {"capability_id", "context", "parameters"}
        or request.get("capability_id") != base_case["capability_id"]
        or type(context) is not dict
        or type(parameters) is not dict
    ):
        raise EvidenceVerificationError("signed request escaped the fixed plan")
    expected_parameters = json.loads(canonical_json(base_case["parameters"]).decode("utf-8"))
    if mutation is not None and mutation["kind"] in {
        "identity_override",
        "parameters_after_sign",
    }:
        for dotted, value in mutation["fields"].items():
            if not isinstance(dotted, str) or not dotted.startswith("parameters."):
                raise EvidenceVerificationError("fixed mutation escaped request parameters")
            key = dotted.removeprefix("parameters.")
            if key not in expected_parameters:
                raise EvidenceVerificationError("fixed mutation escaped request parameters")
            expected_parameters[key] = value
    database_uuid = runtime["database_uuid"]
    if mutation is not None and mutation["kind"] == "context_override":
        fields = mutation["fields"]
        if set(fields) != {"context.database_uuid"}:
            raise EvidenceVerificationError("context mutation escaped database UUID")
        database_uuid = fields["context.database_uuid"]
    expected_context = {
        "principal": selected_identity["principal"],
        "user_id": selected_identity["user_id"],
        "company_id": selected_identity["company_id"],
        "allowed_company_ids": sorted(selected_identity["allowed_company_ids"]),
        "odoo_instance_id": runtime["instance_id"],
        "database_name": runtime["database_name"],
        "database_uuid": database_uuid,
        "environment": runtime["environment"],
        "auth_key_id": runtime["auth_key_id"],
    }
    if parameters != expected_parameters or any(
        context.get(key) != value for key, value in expected_context.items()
    ):
        raise EvidenceVerificationError("signed request identity or parameters drifted")
    if set(context) != REQUEST_CONTEXT_FIELDS:
        raise EvidenceVerificationError("signed request context fields are invalid")
    token = context.get("auth_token_id")
    if not isinstance(token, str) or not token.startswith("dev29-read-"):
        raise EvidenceVerificationError("signed request token is not Dev29-scoped")
    for field in ("auth_request_digest", "auth_signature"):
        if not isinstance(context.get(field), str) or HEX64.fullmatch(context[field]) is None:
            raise EvidenceVerificationError("signed request digest is invalid")


def _validate_positive_response(
    response: dict[str, Any],
    request: Mapping[str, Any],
    runtime: Mapping[str, Any],
    release_identity: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    data = response.get("data") if type(response) is dict else None
    expected_runtime = {
        "capability_channel": runtime["capability_channel"],
        "database_name": runtime["database_name"],
        "database_uuid": runtime["database_uuid"],
        "environment": runtime["environment"],
        "instance_id": runtime["instance_id"],
    }
    if (
        set(response) != {"command", "data", "ok"}
        or response.get("command") != "read"
        or response.get("ok") is not True
        or type(data) is not dict
        or set(data) != {"capability_id", "release_identity", "result", "runtime"}
        or data.get("capability_id") != request.get("capability_id")
        or data.get("release_identity") != release_identity
        or data.get("runtime") != expected_runtime
        or type(data.get("result")) is not dict
    ):
        raise EvidenceVerificationError("positive CLI response binding is invalid")
    receipt = data["result"].get("receipt")
    if type(receipt) is not dict or not isinstance(receipt.get("id"), str) or not receipt["id"]:
        raise EvidenceVerificationError("positive CLI response has no receipt")
    return data["result"], receipt


def _validate_registry_result(case: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    capabilities = result.get("capabilities")
    page = result.get("page")
    expected = case["expected"].get("capabilities")
    if (
        type(capabilities) is not list
        or type(page) is not dict
        or page != {"count": 5, "total_count": 5}
        or type(expected) is not list
        or len(capabilities) != len(expected)
        or not expected
    ):
        raise EvidenceVerificationError("registry result shape is invalid")
    fields = (
        "id",
        "contract_digest",
        "domain",
        "access",
        "risk_level",
        "company_scope",
        "odoo_permissions",
    )
    if [{key: item.get(key) for key in fields} for item in capabilities] != expected:
        raise EvidenceVerificationError("registry result does not match the fixed plan")


def _validate_negative_failure(
    payload: bytes,
    *,
    exit_code: int,
    name: str,
    expected_rejection_code: str,
) -> dict[str, Any]:
    if exit_code != 6:
        raise EvidenceVerificationError(
            f"negative read did not use the fixed rejection exit: {name}"
        )
    failure = parse_json(payload, label=f"negative read stderr {name}", canonical=True)
    error = failure.get("error") if type(failure) is dict else None
    if (
        set(failure) != {"command", "error", "ok"}
        or failure.get("command") != "read"
        or failure.get("ok") is not False
        or type(error) is not dict
        or set(error)
        != {
            "code",
            "message",
            "odoo_action_performed",
            "rejection_code",
            "retryable",
        }
        or error.get("code") != "odoo_read_failed"
        or error.get("rejection_code") != expected_rejection_code
        or error.get("odoo_action_performed") is not False
        or error.get("retryable") is not False
        or not isinstance(error.get("message"), str)
        or not error["message"]
    ):
        raise EvidenceVerificationError(f"negative failure envelope is invalid: {name}")
    if _contains_key(failure, "receipt") or _contains_key(failure, "result"):
        raise EvidenceVerificationError(f"negative failure leaked business evidence: {name}")
    return failure


def _contains_key(value: Any, key: str) -> bool:
    if type(value) is dict:
        return key in value or any(_contains_key(item, key) for item in value.values())
    if type(value) is list:
        return any(_contains_key(item, key) for item in value)
    return False


def validate_boundary_response(
    response: dict[str, Any],
    *,
    runtime: Mapping[str, Any],
    release_identity: Mapping[str, Any],
) -> None:
    data = response.get("data") if type(response) is dict else None
    if (
        set(response) != {"command", "data", "ok"}
        or response.get("command") != "evidence.read-boundary"
        or response.get("ok") is not True
        or type(data) is not dict
        or set(data) != {"evidence", "release_identity", "runtime"}
        or data.get("release_identity") != release_identity
        or data.get("runtime")
        != {
            "capability_channel": runtime["capability_channel"],
            "database_name": runtime["database_name"],
            "database_uuid": runtime["database_uuid"],
            "environment": runtime["environment"],
            "instance_id": runtime["instance_id"],
        }
        or type(data.get("evidence")) is not dict
    ):
        raise EvidenceVerificationError("D11 response envelope is invalid")
    value = data["evidence"]
    if set(value) != {
        "checks",
        "database",
        "drift_probes",
        "relation",
        "schema_version",
        "successful_transactions",
        "write_probe",
    } or value.get("schema_version") != "odoo-accounting-cli-v3.read-boundary-evidence.v1":
        raise EvidenceVerificationError("D11 evidence schema is invalid")
    database = value.get("database")
    if type(database) is not dict or set(database) != {"before", "after"}:
        raise EvidenceVerificationError("D11 database evidence is invalid")
    for snapshot in database.values():
        try:
            valid_uuid = str(uuid.UUID(snapshot.get("uuid"))) == snapshot.get("uuid")
        except (AttributeError, TypeError, ValueError):
            valid_uuid = False
        if (
            type(snapshot) is not dict
            or set(snapshot) != {"backend_pid", "name", "uuid"}
            or type(snapshot.get("backend_pid")) is not int
            or snapshot["backend_pid"] <= 0
            or snapshot.get("name") != runtime["database_name"]
            or snapshot.get("uuid") != runtime["database_uuid"]
            or not valid_uuid
        ):
            raise EvidenceVerificationError("D11 database snapshot is invalid")
    if database["before"] != database["after"]:
        raise EvidenceVerificationError("D11 database snapshot changed")
    check_fields = {
        "backend_pid_unchanged",
        "database_name_unchanged",
        "database_uuid_unchanged",
        "relation_filenode_unchanged",
        "relation_oid_unchanged",
        "relation_row_count_unchanged",
    }
    checks = value.get("checks")
    if type(checks) is not dict or set(checks) != check_fields or any(
        checks[field] is not True for field in check_fields
    ):
        raise EvidenceVerificationError("D11 invariant checks are invalid")
    relation = value.get("relation")
    if (
        type(relation) is not dict
        or set(relation) != {"after", "before", "name", "schema"}
        or relation.get("schema") != "public"
        or relation.get("name") != "ir_config_parameter"
    ):
        raise EvidenceVerificationError("D11 relation evidence is invalid")
    for snapshot in (relation["before"], relation["after"]):
        if (
            type(snapshot) is not dict
            or set(snapshot) != {"filenode", "oid", "row_count"}
            or type(snapshot.get("filenode")) is not int
            or snapshot["filenode"] <= 0
            or type(snapshot.get("oid")) is not int
            or snapshot["oid"] <= 0
            or type(snapshot.get("row_count")) is not int
            or snapshot["row_count"] < 0
        ):
            raise EvidenceVerificationError("D11 relation snapshot is invalid")
    if relation["before"] != relation["after"]:
        raise EvidenceVerificationError("D11 relation snapshot changed")
    transactions = value.get("successful_transactions")
    if type(transactions) is not dict or set(transactions) != {"before", "after"}:
        raise EvidenceVerificationError("D11 successful transaction evidence is invalid")
    marker_hashes: set[str] = set()
    for transaction in transactions.values():
        if (
            type(transaction) is not dict
            or set(transaction)
            != {"idle_after_rollback", "isolation", "marker_sha256", "read_only"}
            or transaction.get("idle_after_rollback") is not True
            or transaction.get("isolation") != "repeatable read"
            or transaction.get("read_only") is not True
            or not isinstance(transaction.get("marker_sha256"), str)
            or HEX64.fullmatch(transaction["marker_sha256"]) is None
        ):
            raise EvidenceVerificationError("D11 successful transaction is invalid")
        marker_hashes.add(transaction["marker_sha256"])
    if len(marker_hashes) != 2:
        raise EvidenceVerificationError("D11 transaction markers are not distinct")
    if value.get("write_probe") != {
        "idle_after_rollback": True,
        "rejected": True,
        "sqlstate": "25006",
        "statement_id": "ir-config-parameter-noop-update-v1",
    }:
        raise EvidenceVerificationError("D11 write rejection probe is invalid")
    probes = value.get("drift_probes")
    names = {"hidden_commit", "hidden_rollback", "rollback_hook_reopen"}
    if type(probes) is not dict or set(probes) != names:
        raise EvidenceVerificationError("D11 drift probe set is invalid")
    canaries: set[str] = set()
    for probe in probes.values():
        if (
            type(probe) is not dict
            or set(probe)
            != {"canary_sha256", "idle_after_cleanup", "rejected", "result_released"}
            or not isinstance(probe.get("canary_sha256"), str)
            or HEX64.fullmatch(probe["canary_sha256"]) is None
            or probe.get("idle_after_cleanup") is not True
            or probe.get("rejected") is not True
            or probe.get("result_released") is not False
        ):
            raise EvidenceVerificationError("D11 drift probe is invalid")
        canaries.add(probe["canary_sha256"])
    if len(canaries) != 3:
        raise EvidenceVerificationError("D11 drift canaries are not distinct")


def validate_witness(
    value: dict[str, Any],
    *,
    plan: Mapping[str, Any],
    runtime: Mapping[str, Any],
) -> None:
    transaction = value.get("transaction")
    database = value.get("database")
    endpoint = value.get("endpoint")
    oracle_python = value.get("oracle_python")
    if (
        set(value)
        != {
            "schema_version",
            "command",
            "all_checks_passed",
            "database",
            "endpoint",
            "relations",
            "fixture_gaps",
            "contains_raw_rows",
            "contains_credentials",
            "odoo_action_performed",
            "database_writes_permitted",
            "production_validated",
            "transaction",
            "oracle_python",
        }
        or
        not _schema_version_is_one(value.get("schema_version"))
        or value.get("command") != "witness"
        or value.get("all_checks_passed") is not True
        or value.get("fixture_gaps") != []
        or value.get("contains_raw_rows") is not False
        or value.get("contains_credentials") is not False
        or value.get("odoo_action_performed") is not False
        or value.get("database_writes_permitted") is not False
        or value.get("production_validated") is not False
        or transaction
        != {
            "final_status": "IDLE",
            "isolation": "repeatable read",
            "read_only": "on",
            "rollback_completed": True,
        }
        or oracle_python
        != {
            "path": runtime["odoo_python"],
            "sha256": runtime["odoo_python_sha256"],
            "isolated": True,
        }
    ):
        raise EvidenceVerificationError("PostgreSQL witness boundary is invalid")
    expected_database = plan["database"]
    postmaster_started_at = (
        database.get("postmaster_started_at") if type(database) is dict else None
    )
    if (
        type(database) is not dict
        or set(database)
        != {
            "current_database",
            "current_user",
            "database_uuid",
            "server_version_num",
            "system_identifier",
            "postmaster_started_at",
        }
        or database.get("current_database") != expected_database["name"]
        or database.get("current_user") != expected_database["current_user"]
        or database.get("database_uuid") != expected_database["uuid"]
        or database.get("server_version_num") != expected_database["server_version_num"]
        or str(database.get("system_identifier")) != expected_database["system_identifier"]
        or endpoint
        != {
            "kind": "unix_socket",
            "requested_directory": expected_database["unix_socket_directory"],
            "socket_path": expected_database["unix_socket_path"],
        }
    ):
        raise EvidenceVerificationError("PostgreSQL witness identity is invalid")
    _datetime(postmaster_started_at, label="PostgreSQL postmaster_started_at")
    relations = value.get("relations")
    planned = {item["name"]: item for item in plan["witness"]["relations"]}
    if type(relations) is not list or [item.get("name") for item in relations] != list(planned):
        raise EvidenceVerificationError("PostgreSQL witness relation set is invalid")
    for relation in relations:
        fixed = planned[relation["name"]]
        if (
            set(relation)
            != {
                "name",
                "oid",
                "owner",
                "relkind",
                "primary_key",
                "schema_sha256",
                "column_count",
                "witness_scope",
                "required_columns",
                "baseline_count",
                "projection_sha256",
                "row_count",
                "row_stream_sha256",
            }
            or relation.get("oid") != fixed["oid"]
            or relation.get("owner") != fixed["owner"]
            or relation.get("relkind") != fixed["relkind"]
            or relation.get("primary_key") != fixed["primary_key"]
            or relation.get("witness_scope") != fixed["witness_scope"]
            or relation.get("required_columns") != fixed["required_columns"]
            or relation.get("baseline_count") != fixed["baseline_count"]
            or relation.get("projection_sha256")
            != hashlib.sha256(canonical_json(fixed["witness_projection"])).hexdigest()
            or type(relation.get("column_count")) is not int
            or relation["column_count"] < len(fixed["required_columns"])
            or type(relation.get("row_count")) is not int
            or relation["row_count"] <= 0
            or (
                fixed["baseline_count"] is not None
                and relation["row_count"] != fixed["baseline_count"]
            )
            or not isinstance(relation.get("row_stream_sha256"), str)
            or HEX64.fullmatch(relation["row_stream_sha256"]) is None
            or not isinstance(relation.get("schema_sha256"), str)
            or HEX64.fullmatch(relation["schema_sha256"]) is None
        ):
            raise EvidenceVerificationError("PostgreSQL witness relation is invalid")


def validate_oracle_report(
    value: dict[str, Any],
    *,
    case: Mapping[str, Any],
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    plan: Mapping[str, Any],
    runtime: Mapping[str, Any],
    witness: Mapping[str, Any],
) -> None:
    result = response["data"]["result"]
    body = {key: item for key, item in result.items() if key != "receipt"}
    page = body.get("page")
    checks = value.get("checks")
    expected_metrics = {
        key: item
        for key, item in case["expected"].items()
        if key != "historical_source"
    }
    expected_check_names = {
        "business_result",
        *(f"golden_{key}" for key in expected_metrics),
        "signed_receipt_binding",
        "nonempty_business_result",
    }
    expected_database = witness["database"]
    expected_endpoint = witness["endpoint"]
    expected_relation_schema = {
        item["name"]: item["schema_sha256"] for item in witness["relations"]
    }
    if (
        set(value)
        != {
            "schema_version",
            "command",
            "case",
            "capability_id",
            "all_checks_passed",
            "checks",
            "database",
            "endpoint",
            "relation_schema_sha256",
            "access",
            "parameters_sha256",
            "business_result_sha256",
            "oracle_metrics_sha256",
            "record_count",
            "release_identity_sha256",
            "fixture_gaps",
            "odoo_action_performed",
            "database_writes_permitted",
            "production_validated",
            "transaction",
            "oracle_python",
        }
        or case.get("name") not in FINANCIAL_NAMES
        or expected_database.get("current_database") != plan["database"]["name"]
        or expected_database.get("database_uuid") != plan["database"]["uuid"]
        or expected_endpoint.get("socket_path")
        != plan["database"]["unix_socket_path"]
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("command") != "verify"
        or value.get("case") != case["name"]
        or value.get("capability_id") != case["capability_id"]
        or value.get("all_checks_passed") is not True
        or value.get("fixture_gaps") != []
        or value.get("odoo_action_performed") is not False
        or value.get("database_writes_permitted") is not False
        or value.get("production_validated") is not False
        or checks != {name: True for name in expected_check_names}
        or value.get("database") != expected_database
        or value.get("endpoint") != expected_endpoint
        or value.get("relation_schema_sha256") != expected_relation_schema
        or value.get("transaction")
        != {
            "final_status": "IDLE",
            "isolation": "repeatable read",
            "read_only": "on",
            "rollback_completed": True,
        }
        or value.get("oracle_python")
        != {
            "path": runtime["odoo_python"],
            "sha256": runtime["odoo_python_sha256"],
            "isolated": True,
        }
        or type(page) is not dict
        or type(page.get("total_count")) is not int
        or value.get("record_count") != page["total_count"]
        or value.get("parameters_sha256")
        != hashlib.sha256(canonical_json(request["parameters"])).hexdigest()
        or value.get("business_result_sha256")
        != hashlib.sha256(canonical_json(body)).hexdigest()
        or value.get("oracle_metrics_sha256")
        != hashlib.sha256(canonical_json(expected_metrics)).hexdigest()
        or value.get("release_identity_sha256")
        != hashlib.sha256(canonical_json(response["data"]["release_identity"])).hexdigest()
    ):
        raise EvidenceVerificationError(f"financial Oracle evidence is invalid: {case['name']}")
    access = value.get("access")
    required_group = (
        "base.group_user" if case["name"] == "registry" else "account.group_account_readonly"
    )
    if access != {
        "user_id": case["user_id"],
        "company_id": case["company_id"],
        "company_member": True,
        "required_group": required_group,
        "required_group_member": True,
    }:
        raise EvidenceVerificationError("financial Oracle access evidence is invalid")


def _state_count(snapshot: Mapping[str, Any], store: str, query: str) -> int:
    try:
        rows = snapshot[store]["queries"].get(query, [])
    except (KeyError, TypeError) as exc:
        raise EvidenceVerificationError("SQLite state query envelope is invalid") from exc
    if not rows:
        return 0
    if len(rows) != 1 or set(rows[0]) != {"value"} or type(rows[0]["value"]) is not int:
        raise EvidenceVerificationError(f"SQLite count query is invalid: {store}.{query}")
    return rows[0]["value"]


def _audit_hash(row: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        canonical_json(
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
    ).hexdigest()


def validate_state_delta(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    requests: Mapping[str, dict[str, Any]],
    receipts: Mapping[str, dict[str, Any]],
    runtime: Mapping[str, Any],
    suite_started_at: str,
    observed_not_after: str,
) -> dict[str, Any]:
    suite_started = _datetime(suite_started_at, label="suite started_at")
    observed_upper = _datetime(
        observed_not_after, label="state observation upper bound"
    )
    if observed_upper < suite_started:
        raise EvidenceVerificationError("state observation window is invalid")
    for snapshot in (before, after):
        if (
            set(snapshot) != {"schema_version", "auth", "receipt"}
            or not _schema_version_is_one(snapshot.get("schema_version"))
            or snapshot.get("auth", {}).get("path") != runtime["auth_state_path"]
            or snapshot.get("receipt", {}).get("path") != runtime["receipt_state_path"]
        ):
            raise EvidenceVerificationError("SQLite state snapshot binding is invalid")
    positive_tokens = {
        name: requests[name]["context"]["auth_token_id"] for name in POSITIVE_NAMES
    }
    acl_token = requests["acl_deny"]["context"]["auth_token_id"]
    expected_tokens = set(positive_tokens.values()) | {acl_token}
    if (
        _state_count(after, "auth", "count") - _state_count(before, "auth", "count") != 6
        or _state_count(after, "receipt", "receipt_count")
        - _state_count(before, "receipt", "receipt_count")
        != 5
        or _state_count(after, "receipt", "audit_count")
        - _state_count(before, "receipt", "audit_count")
        != 5
    ):
        raise EvidenceVerificationError("SQLite auth/receipt/audit count delta is invalid")
    token_rows = after["auth"]["queries"].get("selected_tokens", [])
    if (
        before["auth"]["queries"].get("selected_tokens", []) != []
        or before["receipt"]["queries"].get("selected_receipts", []) != []
        or before["receipt"]["queries"].get("audit_delta", []) != []
        or len(token_rows) != 6
        or any(
            type(row) is not dict
            or set(row) != {"token_id", "request_digest", "expires_at", "consumed_at"}
            for row in token_rows
        )
        or [row["token_id"] for row in token_rows]
        != sorted(row["token_id"] for row in token_rows)
        or len({row["token_id"] for row in token_rows}) != 6
        or {row["token_id"] for row in token_rows} != expected_tokens
    ):
        raise EvidenceVerificationError("SQLite consumed authentication token set is invalid")
    request_by_token = {
        request["context"]["auth_token_id"]: request
        for name, request in requests.items()
        if name != "replay"
    }
    for row in token_rows:
        request = request_by_token[row["token_id"]]
        context = request["context"]
        issued = _datetime(context["auth_issued_at"], label="auth issued_at")
        expires = _datetime(context["auth_expires_at"], label="auth expires_at")
        consumed = _datetime(row["consumed_at"], label="auth consumed_at")
        if (
            row["request_digest"]
            != hashlib.sha256(canonical_json(request)).hexdigest()
            or row["expires_at"] != context["auth_expires_at"]
            or not issued <= consumed < expires
            or not suite_started <= consumed <= observed_upper
        ):
            raise EvidenceVerificationError("SQLite authentication request digest is invalid")
    receipt_rows = after["receipt"]["queries"].get("selected_receipts", [])
    receipt_by_id = {receipt["id"]: receipt for receipt in receipts.values()}
    request_by_receipt = {receipts[name]["id"]: requests[name] for name in POSITIVE_NAMES}
    if (
        len(receipt_rows) != 5
        or any(
            type(row) is not dict
            or set(row)
            != {"receipt_id", "request_digest", "observed_at", "consumed_at"}
            for row in receipt_rows
        )
        or [row["receipt_id"] for row in receipt_rows]
        != sorted(row["receipt_id"] for row in receipt_rows)
        or len({row["receipt_id"] for row in receipt_rows}) != 5
        or {row["receipt_id"] for row in receipt_rows} != set(receipt_by_id)
    ):
        raise EvidenceVerificationError("SQLite consumed receipt set is invalid")
    for row in receipt_rows:
        receipt = receipt_by_id[row["receipt_id"]]
        request = request_by_receipt[row["receipt_id"]]
        observed = _datetime(receipt["observed_at"], label="receipt observed_at")
        consumed = _datetime(row["consumed_at"], label="receipt consumed_at")
        expires = _datetime(
            request["context"]["auth_expires_at"], label="receipt auth expires_at"
        )
        if (
            row["request_digest"] != receipt["request_digest"]
            or row["observed_at"] != receipt["observed_at"]
            or not observed <= consumed < expires
            or not suite_started <= observed <= consumed <= observed_upper
        ):
            raise EvidenceVerificationError("SQLite receipt binding is invalid")
    delta = after["receipt"]["queries"].get("audit_delta", [])
    if len(delta) != 5:
        raise EvidenceVerificationError("SQLite audit event delta is invalid")
    pre_head = before["receipt"]["queries"].get("audit_head", [])
    if pre_head and (
        len(pre_head) != 1
        or type(pre_head[0]) is not dict
        or set(pre_head[0]) != {"sequence", "event_hash"}
        or type(pre_head[0]["sequence"]) is not int
        or pre_head[0]["sequence"] < 1
        or not isinstance(pre_head[0]["event_hash"], str)
        or HEX64.fullmatch(pre_head[0]["event_hash"]) is None
    ):
        raise EvidenceVerificationError("SQLite pre-run audit head is invalid")
    previous = "0" * 64 if not pre_head else pre_head[0]["event_hash"]
    expected_sequence = 1 if not pre_head else pre_head[0]["sequence"] + 1
    event_ids: set[str] = set()
    for index, row in enumerate(delta):
        if (
            type(row) is not dict
            or set(row)
            != {
                "sequence",
                "event_id",
                "event_type",
                "operation_id",
                "occurred_at",
                "payload_json",
                "previous_hash",
                "event_hash",
            }
            or row["event_type"] != "read.verified"
            or row["operation_id"] is not None
            or row["sequence"] != expected_sequence + index
            or row["previous_hash"] != previous
            or row["event_hash"] != _audit_hash(row)
            or row["event_id"] in event_ids
        ):
            raise EvidenceVerificationError("SQLite audit hash chain is invalid")
        try:
            payload = parse_json(
                row["payload_json"].encode("utf-8"), label="SQLite audit payload"
            )
        except (AttributeError, UnicodeError) as exc:
            raise EvidenceVerificationError("SQLite audit payload is invalid") from exc
        receipt_id = payload.get("receipt_id")
        receipt = receipt_by_id.get(receipt_id)
        request = request_by_receipt.get(receipt_id)
        expected_payload = None
        if receipt is not None and request is not None:
            expected_payload = {
                "auth_token_id": request["context"]["auth_token_id"],
                "capability_id": receipt["capability_id"],
                "capability_channel": receipt["capability_channel"],
                "company_id": receipt["company_id"],
                "environment": receipt["environment"],
                "database_name": receipt["database_name"],
                "database_uuid": receipt["database_uuid"],
                "odoo_instance_id": receipt["odoo_instance_id"],
                "principal": request["context"]["principal"],
                "receipt": receipt,
                "receipt_id": receipt["id"],
                "registry_digest": receipt["registry_digest"],
                "release_digest": receipt["release_digest"],
                "request_digest": receipt["request_digest"],
                "result_digest": receipt["result_digest"],
                "user_id": receipt["user_id"],
            }
        if (
            expected_payload is None
            or row["event_id"] != f"read:{receipt_id}"
            or payload != expected_payload
            or row["occurred_at"] != receipt["observed_at"]
            or not suite_started
            <= _datetime(row["occurred_at"], label="audit occurred_at")
            <= observed_upper
        ):
            raise EvidenceVerificationError("SQLite audit receipt binding is invalid")
        event_ids.add(row["event_id"])
        previous = row["event_hash"]
    post_head = after["receipt"]["queries"].get("audit_head", [])
    if (
        len(post_head) != 1
        or type(post_head[0]) is not dict
        or set(post_head[0]) != {"sequence", "event_hash"}
        or post_head[0]
        != {"sequence": delta[-1]["sequence"], "event_hash": delta[-1]["event_hash"]}
    ):
        raise EvidenceVerificationError("SQLite post-run audit head is invalid")
    return {
        "auth_token_delta": 6,
        "receipt_delta": 5,
        "audit_event_delta": 5,
        "positive_tokens": positive_tokens,
        "acl_denial_token": acl_token,
        "receipt_ids": {name: receipt["id"] for name, receipt in receipts.items()},
        "all_checks_passed": True,
    }


def _verify_positive_artifacts(
    documents: Mapping[str, bytes],
    *,
    cases: Mapping[str, dict[str, Any]],
    runtime: dict[str, Any],
    release_identity: dict[str, Any],
    auth_secret: bytes,
    receipt_secret: bytes,
    plan: Mapping[str, Any],
    witness: Mapping[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    requests: dict[str, dict[str, Any]] = {}
    receipts: dict[str, dict[str, Any]] = {}
    oracle_reports: dict[str, dict[str, Any]] = {}
    for name in POSITIVE_NAMES:
        prefix = f"positive/{name}"
        _exit(documents, f"{prefix}/signer.exit", 0)
        if documents[f"{prefix}/signer.stderr"]:
            raise EvidenceVerificationError(f"positive signer stderr is not empty: {name}")
        if documents[f"{prefix}/signer.stdout"] != documents[f"{prefix}/request.json"]:
            raise EvidenceVerificationError(f"positive signer output drifted: {name}")
        request = _json(documents, f"{prefix}/request.json")
        case = cases[name]
        validate_signed_selection(
            request,
            base_case=case,
            selected_identity=case,
            runtime=runtime,
            mutation=None,
        )
        verify_auth_request(
            request,
            auth_secret=auth_secret,
            runtime=runtime,
            expect_content_match=True,
        )
        requests[name] = request
        _exit(documents, f"{prefix}/read.exit", 0)
        if documents[f"{prefix}/read.stderr"]:
            raise EvidenceVerificationError(f"positive read stderr is not empty: {name}")
        response = parse_json(
            documents[f"{prefix}/read.stdout"],
            label=f"positive read stdout {name}",
            canonical=True,
        )
        result, receipt = _validate_positive_response(
            response, request, runtime, release_identity
        )
        receipt_file = _json(documents, f"{prefix}/receipt.json")
        if receipt_file != receipt:
            raise EvidenceVerificationError(f"positive receipt file drifted: {name}")
        verified_receipt = verify_receipt(
            request,
            response,
            receipt_secret=receipt_secret,
            runtime=runtime,
            release_identity=release_identity,
        )
        if verified_receipt != receipt:
            raise EvidenceVerificationError(f"positive receipt verification drifted: {name}")
        receipts[name] = receipt
        if name == "registry":
            _validate_registry_result(case, result)
        if name in FINANCIAL_NAMES:
            _exit(documents, f"{prefix}/oracle.exit", 0)
            if documents[f"{prefix}/oracle.stderr"]:
                raise EvidenceVerificationError(f"financial Oracle stderr is not empty: {name}")
            oracle = parse_json(
                documents[f"{prefix}/oracle.stdout"],
                label=f"financial Oracle stdout {name}",
                canonical=True,
            )
            validate_oracle_report(
                oracle,
                case=case,
                request=request,
                response=response,
                plan=plan,
                runtime=runtime,
                witness=witness,
            )
            oracle_reports[name] = oracle
    tokens = [request["context"]["auth_token_id"] for request in requests.values()]
    receipt_ids = [receipt["id"] for receipt in receipts.values()]
    if len(tokens) != len(set(tokens)) or len(receipt_ids) != len(set(receipt_ids)):
        raise EvidenceVerificationError("positive authentication or receipt identities collide")
    return requests, receipts, oracle_reports


def _verify_negative_artifacts(
    documents: Mapping[str, bytes],
    plan: dict[str, Any],
    runtime: dict[str, Any],
    requests: dict[str, dict[str, Any]],
    auth_secret: bytes,
) -> dict[str, dict[str, Any]]:
    cases = {item["name"]: item for item in plan["cases"]}
    negatives = {item["name"]: item for item in plan["negative_cases"]}
    reports: dict[str, dict[str, Any]] = {}
    for name in NEGATIVE_NAMES:
        prefix = f"negative/{name}"
        negative = negatives[name]
        request = _json(documents, f"{prefix}/request.json")
        base = cases[negative["base_case"]]
        if name == "replay":
            source = _json(documents, f"{prefix}/request-source.json")
            if source != {
                "byte_identical": True,
                "kind": "replay_exact_request",
                "positive_case": negative["base_case"],
            } or documents[f"{prefix}/request.json"] != documents[
                f"positive/{negative['base_case']}/request.json"
            ]:
                raise EvidenceVerificationError("replay did not reuse exact successful bytes")
        else:
            _exit(documents, f"{prefix}/signer.exit", 0)
            if documents[f"{prefix}/signer.stderr"]:
                raise EvidenceVerificationError(f"negative signer stderr is not empty: {name}")
            if documents[f"{prefix}/signer.stdout"] != documents[f"{prefix}/request.json"]:
                raise EvidenceVerificationError(f"negative signer output drifted: {name}")
            validate_signed_selection(
                request,
                base_case=base,
                selected_identity=negative,
                runtime=runtime,
                mutation=negative["mutation"],
            )
        requests[name] = request
        verify_auth_request(
            request,
            auth_secret=auth_secret,
            runtime=runtime,
            expect_content_match=name != "tamper_parameters",
        )
        expected_doc = _json(documents, f"{prefix}/expected.json")
        if expected_doc != {
            "business_result_forbidden": True,
            "logical_error": negative["expected_error"],
            "mutation": negative["mutation"],
            "receipt_forbidden": True,
        }:
            raise EvidenceVerificationError(f"negative expectation drifted: {name}")
        if documents[f"{prefix}/read.stdout"]:
            raise EvidenceVerificationError(f"negative read leaked stdout: {name}")
        try:
            exit_code = int(documents[f"{prefix}/read.exit"].decode("ascii").strip())
        except (UnicodeError, ValueError) as exc:
            raise EvidenceVerificationError(f"negative exit is invalid: {name}") from exc
        if exit_code != 6:
            raise EvidenceVerificationError(
                f"negative read did not use the fixed rejection exit: {name}"
            )
        failure = parse_json(
            documents[f"{prefix}/read.stderr"],
            label=f"negative read stderr {name}",
            canonical=True,
        )
        _validate_negative_failure(
            documents[f"{prefix}/read.stderr"],
            exit_code=exit_code,
            name=name,
            expected_rejection_code=negative["expected_error"],
        )
        reports[name] = {
            "logical_error": negative["expected_error"],
            "cli_error": failure["error"]["code"],
            "rejection_code": failure["error"]["rejection_code"],
            "exit_code": exit_code,
            "verified": True,
        }
    if requests["replay"] != requests[negatives["replay"]["base_case"]]:
        raise EvidenceVerificationError("replay semantic request is not identical")
    return reports


def validate_expired_negative_time(
    request: Mapping[str, Any], *, suite_started_at: str
) -> None:
    try:
        expires_text = request["context"]["auth_expires_at"]
    except (KeyError, TypeError) as exc:
        raise EvidenceVerificationError(
            "expired negative request timestamp is absent"
        ) from exc
    expires = _datetime(expires_text, label="expired negative auth_expires_at")
    started = _datetime(suite_started_at, label="suite started_at")
    if not expires < started:
        raise EvidenceVerificationError(
            "expired negative request was not expired before suite execution"
        )


def validate_sandbox_profile(
    value: dict[str, Any],
    *,
    runtime: Mapping[str, Any],
    release: str,
    closure: Mapping[str, Any],
    outer_unit: Mapping[str, Any],
) -> None:
    expected = {
        "schema_version": 1,
        "execution_model": "single-supervisor-direct-role-children-v1",
        "outer_runner": "/usr/bin/systemd-run",
        "nested_systemd_run_forbidden": True,
        "direct_child_bootstrap": str(
            RELEASE_PARENT / release / "deployment/dev29/direct_child.py"
        ),
        "roles": {
            "odoo": {"user": "odoo", "group": "odoo"},
            "signer": {"user": "odoo", "group": "odoo"},
            "postgres": {"user": "postgres", "group": "postgres"},
            "verifier": {"user": "root", "group": "root"},
        },
        "protect_system": "strict",
        "private_tmp": True,
        "private_network": True,
        "no_new_privileges": True,
        "restrict_suid_sgid": True,
        "umask": "0077",
        "working_directory": str(RELEASE_PARENT / release),
        "home": "/var/lib/odoo-accounting-cli-v3-broker",
        "read_write_paths": outer_unit["read_write_paths"],
        "outer_unit_evidence_sha256": hashlib.sha256(
            canonical_json(outer_unit)
        ).hexdigest(),
        "actual_systemd_properties_verified": True,
        "private_mounts": True,
        "bind_read_only_paths": closure["systemd"]["bind_read_only_paths"],
        "child_process_control": {
            "new_process_group": True,
            "parent_death_signal": "SIGKILL",
            "timeout_kills_process_group": True,
            "supplementary_groups_cleared": True,
            "capabilities_all_zero": True,
        },
        "production_routing_changed": False,
    }
    if value != expected:
        raise EvidenceVerificationError("systemd sandbox profile is invalid")


def _ptrace_traceme() -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(0, 0, None, None) != 0:
        os._exit(126)


def _ptrace_traceme_with_parent_death(expected_parent_pid: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0:
        os._exit(126)
    if os.getppid() != expected_parent_pid:
        os._exit(125)
    if library.ptrace(0, 0, None, None) != 0:
        os._exit(126)


def _reject_systemctl_file_capabilities(descriptor: int) -> None:
    missing = {getattr(errno, "ENODATA", 61)}
    if hasattr(errno, "ENOATTR"):
        missing.add(errno.ENOATTR)
    try:
        os.getxattr(descriptor, "security.capability")
    except OSError as exc:
        if exc.errno in missing:
            return
        raise EvidenceVerificationError(
            "outer unit systemctl capabilities cannot be verified"
        ) from exc
    raise EvidenceVerificationError("outer unit systemctl has file capabilities")


def _ptrace_detach(pid: int, signal_number: int = 0) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if library.ptrace(17, pid, None, ctypes.c_void_p(signal_number)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _ptrace_set_exitkill(pid: int) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    if (
        library.ptrace(
            PTRACE_SETOPTIONS,
            pid,
            None,
            ctypes.c_void_p(PTRACE_O_EXITKILL),
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _kill_and_reap_loader_process(
    process: subprocess.Popen[bytes], *, traced: bool
) -> None:
    if process.returncode is not None:
        return
    if traced:
        try:
            _ptrace_detach(process.pid, SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    try:
        os.kill(process.pid, SIGKILL)
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait()
    except (ChildProcessError, OSError):
        pass


def _query_systemctl_properties(
    unit: str, *, expected_sha256: str
) -> tuple[dict[str, str], dict[str, Any]]:
    if os.name != "posix" or HEX64.fullmatch(expected_sha256) is None:
        raise EvidenceVerificationError("outer unit systemctl digest is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(SYSTEMCTL, flags)
    process: subprocess.Popen[bytes] | None = None
    traced = False
    reaped = False
    exitkill_set = False
    exec_stop_verified = False
    detached_before_communicate = False
    try:
        metadata = os.fstat(descriptor)
        path_metadata = SYSTEMCTL.lstat()
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_uid,
            metadata.st_gid,
        )
        if (
            SYSTEMCTL.is_symlink()
            or SYSTEMCTL.resolve(strict=True) != SYSTEMCTL
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > MAX_JSON_BYTES
            or identity[:2] != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise EvidenceVerificationError("outer unit systemctl identity drifted")
        _reject_systemctl_file_capabilities(descriptor)
        payload = bytearray()
        while len(payload) < metadata.st_size:
            chunk = os.read(
                descriptor, min(1024 * 1024, metadata.st_size - len(payload))
            )
            if not chunk:
                raise EvidenceVerificationError("outer unit systemctl changed during read")
            payload.extend(chunk)
        if (
            os.read(descriptor, 1)
            or identity
            != (
                (current := os.fstat(descriptor)).st_dev,
                current.st_ino,
                current.st_nlink,
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
                stat.S_IMODE(current.st_mode),
                current.st_uid,
                current.st_gid,
            )
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise EvidenceVerificationError("outer unit systemctl identity drifted")
        os.lseek(descriptor, 0, os.SEEK_SET)
        command = [
            str(SYSTEMCTL),
            "show",
            "--no-pager",
            *[f"--property={field}" for field in SYSTEMD_UNIT_FIELDS],
            unit,
        ]
        expected_parent_pid = os.getpid()
        process = subprocess.Popen(
            command,
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
            preexec_fn=lambda: _ptrace_traceme_with_parent_death(
                expected_parent_pid
            ),
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=SYSTEMCTL_ENVIRONMENT,
        )
        traced = True
        waited, status = os.waitpid(process.pid, os.WUNTRACED)
        if (
            waited != process.pid
            or not os.WIFSTOPPED(status)
            or os.WSTOPSIG(status) != signal.SIGTRAP
        ):
            raise EvidenceVerificationError("outer unit systemctl exec trace is invalid")
        _ptrace_set_exitkill(process.pid)
        exitkill_set = True
        executed = Path(f"/proc/{process.pid}/exe").stat()
        if (executed.st_dev, executed.st_ino) != identity[:2]:
            raise EvidenceVerificationError("outer unit systemctl executed unpinned bytes")
        exec_stop_verified = True
        _ptrace_detach(process.pid)
        traced = False
        detached_before_communicate = True
        try:
            stdout, stderr = process.communicate(timeout=30)
            reaped = process.returncode is not None
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
        current = os.fstat(descriptor)
        path_current = SYSTEMCTL.lstat()
        if identity != (
            current.st_dev,
            current.st_ino,
            current.st_nlink,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
            stat.S_IMODE(current.st_mode),
            current.st_uid,
            current.st_gid,
        ) or identity[:2] != (path_current.st_dev, path_current.st_ino):
            raise EvidenceVerificationError("outer unit systemctl changed across execution")
        if (
            process.returncode != 0
            or stderr
            or not stdout.endswith(b"\n")
            or len(stdout) > 1024 * 1024
        ):
            raise EvidenceVerificationError("outer unit systemctl query failed")
        properties: dict[str, str] = {}
        try:
            for raw in stdout.decode("utf-8", "strict").splitlines():
                key, separator, item = raw.partition("=")
                if (
                    separator != "="
                    or key not in SYSTEMD_UNIT_FIELDS
                    or key in properties
                ):
                    raise EvidenceVerificationError(
                        "outer unit systemctl output is invalid"
                    )
                properties[key] = item
        except UnicodeError as exc:
            raise EvidenceVerificationError(
                "outer unit systemctl output is invalid"
            ) from exc
        if set(properties) != set(SYSTEMD_UNIT_FIELDS):
            raise EvidenceVerificationError("outer unit systemctl output is incomplete")
        return properties, {
            "method": "open-fd-ptrace-exec-v1",
            "file": {
                "path": str(SYSTEMCTL),
                "sha256": expected_sha256,
                "size": len(payload),
                "uid": 0,
                "gid": 0,
                "mode": "0755",
            },
            "pinned_device": identity[0],
            "pinned_inode": identity[1],
            "proc_exe_device": executed.st_dev,
            "proc_exe_inode": executed.st_ino,
            "ptrace_exitkill_set": exitkill_set,
            "ptrace_exec_stop_verified": exec_stop_verified,
            "ptrace_detached_before_communicate": detached_before_communicate,
            "parent_death_signal": "SIGKILL",
            "parent_identity_checked": True,
            "security_capability_absent": True,
            "child_reaped": reaped,
            "all_checks_passed": True,
        }
    except BaseException:
        if process is not None and process.returncode is None:
            try:
                if traced:
                    try:
                        _ptrace_detach(process.pid, signal.SIGKILL)
                    except OSError:
                        os.kill(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                pass
        raise
    finally:
        os.close(descriptor)


def _validate_systemctl_execution(
    value: Any, *, systemctl: Mapping[str, Any]
) -> None:
    if (
        type(value) is not dict
        or set(value)
        != {
            "method",
            "file",
            "pinned_device",
            "pinned_inode",
            "proc_exe_device",
            "proc_exe_inode",
            "ptrace_exitkill_set",
            "ptrace_exec_stop_verified",
            "ptrace_detached_before_communicate",
            "parent_death_signal",
            "parent_identity_checked",
            "security_capability_absent",
            "child_reaped",
            "all_checks_passed",
        }
        or value.get("method") != "open-fd-ptrace-exec-v1"
        or value.get("file") != systemctl
        or type(value.get("pinned_device")) is not int
        or value["pinned_device"] <= 0
        or type(value.get("pinned_inode")) is not int
        or value["pinned_inode"] <= 0
        or value.get("proc_exe_device") != value["pinned_device"]
        or value.get("proc_exe_inode") != value["pinned_inode"]
        or value.get("ptrace_exitkill_set") is not True
        or value.get("ptrace_exec_stop_verified") is not True
        or value.get("ptrace_detached_before_communicate") is not True
        or value.get("parent_death_signal") != "SIGKILL"
        or value.get("parent_identity_checked") is not True
        or value.get("security_capability_absent") is not True
        or value.get("child_reaped") is not True
        or value.get("all_checks_passed") is not True
    ):
        raise EvidenceVerificationError("outer unit systemctl execution proof is invalid")


def validate_outer_unit(
    value: Mapping[str, Any], *, runtime: Mapping[str, Any], release: str
) -> None:
    capabilities = [
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
    ]
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    writable = [
        "/var/lib/odoo-accounting-cli-v3/evidence",
        "/var/lib/odoo-accounting-cli-v3/evidence-private",
        "/var/lib/odoo-accounting-cli-v3/runtime-open-trace",
        "/var/lib/odoo-accounting-cli-v3/evidence-anchors",
        "/opt/odoo-accounting-cli-v3/dependencies",
        str(Path(runtime["auth_state_path"]).parent),
        str(Path(runtime["receipt_state_path"]).parent),
        "/var/lib/odoo-accounting-cli-v3-broker",
        "/run/odoo-accounting-cli-v3-dev29",
    ]
    if type(value) is not dict or set(value) != {
        "schema_version",
        "unit",
        "supervisor_pid",
        "systemctl",
        "systemctl_execution",
        "properties",
        "proc",
        "expected_environment",
        "read_write_paths",
        "read_only_paths",
        "capability_bounding_set",
        "all_checks_passed",
    }:
        raise EvidenceVerificationError("outer transient unit schema is invalid")
    parent = os.getppid()
    unit = value.get("unit")
    properties = value.get("properties")
    process = value.get("proc")
    systemctl = value.get("systemctl")
    systemctl_execution = value.get("systemctl_execution")
    if (
        not _schema_version_is_one(value.get("schema_version"))
        or not isinstance(unit, str)
        or re.fullmatch(r"odoo-accounting-cli-v3-dev29-[A-Za-z0-9._-]+\.service", unit)
        is None
        or value.get("supervisor_pid") != parent
        or type(properties) is not dict
        or type(process) is not dict
        or set(process) != {"argv", "argv_sha256", "cgroup"}
        or value.get("expected_environment") != environment
        or value.get("read_write_paths") != writable
        or value.get("read_only_paths")
        != ["/run/odoo-accounting-cli-v3-dev29-leases"]
        or value.get("capability_bounding_set") != capabilities
        or value.get("all_checks_passed") is not True
    ):
        raise EvidenceVerificationError("outer transient unit proof is invalid")
    try:
        live_argv = [
            item.decode("utf-8", "strict")
            for item in Path(f"/proc/{parent}/cmdline").read_bytes().split(b"\0")
            if item
        ]
        cgroup_rows = Path(f"/proc/{parent}/cgroup").read_text("ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise EvidenceVerificationError("outer supervisor live identity is unavailable") from exc
    if (
        process.get("argv") != live_argv
        or process.get("argv_sha256")
        != hashlib.sha256(canonical_json(live_argv)).hexdigest()
        or len(cgroup_rows) != 1
        or not cgroup_rows[0].startswith("0::")
        or process.get("cgroup") != cgroup_rows[0][3:]
        or not live_argv
        or live_argv[:4]
        != [
            CLOSURE_PYTHON,
            "-I",
            "-S",
            str(RELEASE_PARENT / release / "deployment/dev29/run_read_evidence.py"),
        ]
    ):
        raise EvidenceVerificationError("outer supervisor process binding is invalid")
    expected_static = {
        "Id": unit,
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "Type": "exec",
        "User": "root",
        "Group": "root",
        "MainPID": str(parent),
        "ControlGroup": process["cgroup"],
        "WorkingDirectory": str(RELEASE_PARENT / release),
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "PrivateMounts": "yes",
        "PrivateTmp": "yes",
        "PrivateNetwork": "yes",
        "NoNewPrivileges": "yes",
        "ProtectControlGroups": "yes",
        "KillMode": "control-group",
        "RuntimeMaxUSec": "1h",
        "TimeoutStopUSec": "30s",
        "UMask": "0077",
    }
    property_fields = {
        *expected_static,
        "InvocationID",
        "ExecStart",
        "ReadWritePaths",
        "Environment",
        "CapabilityBoundingSet",
    }
    try:
        observed_environment = {
            item.split("=", 1)[0]: item.split("=", 1)[1]
            for item in shlex.split(properties.get("Environment", ""))
        }
        observed_writable = shlex.split(properties.get("ReadWritePaths", ""))
        observed_capabilities = {
            item.upper()
            for item in shlex.split(properties.get("CapabilityBoundingSet", ""))
        }
    except (ValueError, IndexError) as exc:
        raise EvidenceVerificationError("outer systemd list property is invalid") from exc
    if (
        set(properties) != property_fields
        or any(properties.get(key) != item for key, item in expected_static.items())
        or re.fullmatch(r"[0-9a-f]{32}", properties.get("InvocationID", "")) is None
        or not properties.get("ExecStart")
        or observed_environment != environment
        or observed_writable != writable
        or observed_capabilities != set(capabilities)
        or type(systemctl) is not dict
        or set(systemctl) != {"path", "sha256", "size", "uid", "gid", "mode"}
        or systemctl.get("path") != "/usr/bin/systemctl"
        or systemctl.get("uid") != 0
        or systemctl.get("gid") != 0
        or systemctl.get("mode") != "0755"
        or not isinstance(systemctl.get("sha256"), str)
        or HEX64.fullmatch(systemctl["sha256"]) is None
    ):
        raise EvidenceVerificationError("outer systemd property proof is invalid")
    _validate_systemctl_execution(systemctl_execution, systemctl=systemctl)
    live_properties, live_execution = _query_systemctl_properties(
        unit, expected_sha256=systemctl["sha256"]
    )
    _validate_systemctl_execution(live_execution, systemctl=systemctl)
    if live_properties != properties:
        raise EvidenceVerificationError("outer unit live systemd properties drifted")


def _validate_file_snapshot(value: Any, *, expected_path: str) -> None:
    if (
        type(value) is not dict
        or set(value) != {"path", "sha256", "size", "uid", "gid", "mode"}
        or value.get("path") != expected_path
        or not isinstance(value.get("sha256"), str)
        or HEX64.fullmatch(value["sha256"]) is None
        or type(value.get("size")) is not int
        or value["size"] < 0
        or type(value.get("uid")) is not int
        or type(value.get("gid")) is not int
        or not isinstance(value.get("mode"), str)
        or re.fullmatch(r"[0-7]{4}", value["mode"]) is None
    ):
        raise EvidenceVerificationError(f"file identity evidence is invalid: {expected_path}")


def _validate_service(value: Any, *, unit: str, expect_absent: bool) -> None:
    if type(value) is not dict or set(value) != {
        "unit",
        "properties",
        "fragment",
        "dropins",
    }:
        raise EvidenceVerificationError(f"systemd service evidence is invalid: {unit}")
    properties = value.get("properties")
    fields = {
        "Id",
        "Names",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ExecMainStartTimestampMonotonic",
        "InvocationID",
        "NRestarts",
        "StateChangeTimestampMonotonic",
        "FragmentPath",
        "SourcePath",
        "UnitFileState",
        "DropInPaths",
    }
    if value.get("unit") != unit or type(properties) is not dict or set(properties) != fields:
        raise EvidenceVerificationError(f"systemd service fields are invalid: {unit}")
    if (
        properties.get("Id") != unit
        or unit not in properties.get("Names", "").split()
        or not properties.get("NRestarts", "").isdigit()
        or not properties.get("StateChangeTimestampMonotonic", "").isdigit()
        or type(value.get("dropins")) is not list
        or [item.get("path") for item in value["dropins"]]
        != (properties["DropInPaths"].split() if properties["DropInPaths"] else [])
    ):
        raise EvidenceVerificationError(f"systemd service continuity is invalid: {unit}")
    for dropin in value["dropins"]:
        _validate_file_snapshot(dropin, expected_path=dropin["path"])
    if expect_absent:
        if (
            properties["LoadState"] != "not-found"
            or properties["ActiveState"] != "inactive"
            or properties["FragmentPath"]
            or properties["SourcePath"]
            or value["fragment"] is not None
            or value["dropins"]
            or properties["InvocationID"]
        ):
            raise EvidenceVerificationError(f"staged V3 service was not absent: {unit}")
        return
    if (
        properties["LoadState"] != "loaded"
        or properties["ActiveState"] != "active"
        or properties["SubState"] != "running"
        or not properties["MainPID"].isdigit()
        or int(properties["MainPID"]) <= 0
        or not properties["ExecMainStartTimestampMonotonic"].isdigit()
        or int(properties["ExecMainStartTimestampMonotonic"]) <= 0
        or re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"]) is None
        or int(properties["StateChangeTimestampMonotonic"]) <= 0
        or not properties["FragmentPath"]
        or value["fragment"] is None
    ):
        raise EvidenceVerificationError(f"required service was not running: {unit}")
    _validate_file_snapshot(value["fragment"], expected_path=properties["FragmentPath"])


def validate_system_document(
    value: dict[str, Any], *, plan: Mapping[str, Any], runtime: Mapping[str, Any]
) -> None:
    if set(value) != {
        "schema_version",
        "host",
        "runtime_files",
        "v2_roots",
        "pi_control_files",
        "services",
        "v3",
    } or not _schema_version_is_one(value.get("schema_version")):
        raise EvidenceVerificationError("system identity evidence is invalid")
    target = plan["target"]
    host = value["host"]
    if (
        type(host) is not dict
        or set(host) != {"expected", "node", "machine_id_sha256", "kernel"}
        or host.get("expected") != target["host"]
        or not isinstance(host.get("node"), str)
        or not host["node"]
        or not isinstance(host.get("kernel"), str)
        or not host["kernel"]
        or not isinstance(host.get("machine_id_sha256"), str)
        or HEX64.fullmatch(host["machine_id_sha256"]) is None
    ):
        raise EvidenceVerificationError("host identity evidence is invalid")
    runtime_files = value["runtime_files"]
    runtime_bindings = (
        ("odoo_python", "odoo_python_sha256"),
        ("odoo_bin", "odoo_bin_sha256"),
        ("odoo_config", "odoo_config_sha256"),
    )
    if type(runtime_files) is not list or [item.get("field") for item in runtime_files] != [
        item[0] for item in runtime_bindings
    ]:
        raise EvidenceVerificationError("runtime file evidence set is invalid")
    for item, (field, digest_field) in zip(runtime_files, runtime_bindings, strict=True):
        snapshot = {key: child for key, child in item.items() if key != "field"}
        _validate_file_snapshot(snapshot, expected_path=runtime[field])
        if snapshot["sha256"] != runtime[digest_field]:
            raise EvidenceVerificationError("runtime file digest evidence is invalid")
    trees = value["v2_roots"]
    if type(trees) is not list or [item.get("path") for item in trees] != target["v2_roots"]:
        raise EvidenceVerificationError("V2 source identity set is invalid")
    for tree in trees:
        if (
            set(tree) != {"path", "count", "digest", "algorithm", "root"}
            or tree.get("algorithm") != "canonical-json(path,sha256,size)-sha256-v1"
            or type(tree.get("count")) is not int
            or tree["count"] <= 0
            or not isinstance(tree.get("digest"), str)
            or HEX64.fullmatch(tree["digest"]) is None
            or type(tree.get("root")) is not dict
        ):
            raise EvidenceVerificationError("V2 source tree evidence is invalid")
    pi_files = value["pi_control_files"]
    if type(pi_files) is not list or [item.get("path") for item in pi_files] != target[
        "pi_control_files"
    ]:
        raise EvidenceVerificationError("Pi control file evidence set is invalid")
    for snapshot in pi_files:
        _validate_file_snapshot(snapshot, expected_path=snapshot["path"])
    services = value["services"]
    if type(services) is not list or [item.get("unit") for item in services] != target[
        "services"
    ]:
        raise EvidenceVerificationError("required service evidence set is invalid")
    for service, unit in zip(services, target["services"], strict=True):
        _validate_service(service, unit=unit, expect_absent=False)
    v3 = value["v3"]
    expected_current = str(RELEASE_PARENT.parent / "current")
    if (
        type(v3) is not dict
        or set(v3) != {"current", "units"}
        or v3.get("current") != {"path": expected_current, "absent": True}
        or type(v3.get("units")) is not list
        or [item.get("unit") for item in v3["units"]] != target["v3_unit_names"]
    ):
        raise EvidenceVerificationError("staged V3 absence evidence is invalid")
    for item, unit in zip(v3["units"], target["v3_unit_names"], strict=True):
        if type(item) is not dict or set(item) != {"unit", "systemd", "locations"}:
            raise EvidenceVerificationError("staged V3 unit evidence is invalid")
        _validate_service(item["systemd"], unit=unit, expect_absent=True)
        if type(item["locations"]) is not list or not item["locations"] or any(
            location.get("absent") is not True for location in item["locations"]
        ):
            raise EvidenceVerificationError("staged V3 unit-file absence is invalid")


def validate_system_continuity(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    plan: Mapping[str, Any],
    runtime: Mapping[str, Any],
) -> None:
    validate_system_document(before, plan=plan, runtime=runtime)
    validate_system_document(after, plan=plan, runtime=runtime)
    if after != before:
        raise EvidenceVerificationError("Odoo/Pi/V2/V3 system identity changed")


def expected_dependency_roots(
    *,
    runtime: Mapping[str, Any],
    expected: Mapping[str, str],
    closure: Mapping[str, Any],
    external_runtime_paths: Sequence[str],
) -> tuple[Path, ...]:
    release = expected["release"]
    identity = closure["closure_identity"]
    candidates = (
        Path(closure["mount"]["mount_point"]),
        Path(identity["sealed_config_path"]),
        Path(identity["anchor_path"]),
        Path(identity["image_path"]),
        Path(CLOSURE_PYTHON),
        Path(CLOSURE_LDCONFIG),
        RELEASE_PARENT / release,
        PACKAGE_PARENT / f"odoo-accounting-cli-v3-{release}.tar.gz",
        TRUST_PARENT / f"{release}.json",
        RUNTIME_PARENT / f"runtime-test-{release}.json",
        Path(runtime["auth_secret_path"]),
        Path(runtime["receipt_secret_path"]),
        *(Path(item) for item in external_runtime_paths),
    )
    result: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        absolute = candidate.absolute()
        text = str(absolute)
        if text not in seen:
            result.append(absolute)
            seen.add(text)
    return tuple(result)


def _validate_dependency_entry(value: Any, *, root: Path) -> str:
    common = {"path", "kind", "uid", "gid", "mode"}
    fields = {
        "directory": common,
        "file": common | {"sha256", "size"},
        "symlink": common | {"target", "target_sha256"},
    }
    kind = value.get("kind") if type(value) is dict else None
    relative = value.get("path") if type(value) is dict else None
    portable = PurePosixPath(relative) if isinstance(relative, str) else None
    if (
        type(value) is not dict
        or kind not in fields
        or set(value) != fields[kind]
        or portable is None
        or portable.is_absolute()
        or relative not in {".", str(portable)}
        or (relative != "." and (not portable.parts or ".." in portable.parts))
        or type(value.get("uid")) is not int
        or value["uid"] < 0
        or type(value.get("gid")) is not int
        or value["gid"] < 0
        or not isinstance(value.get("mode"), str)
        or re.fullmatch(r"[0-7]{4}", value["mode"]) is None
    ):
        raise EvidenceVerificationError(
            f"dependency entry schema is invalid: {root}"
        )
    if kind == "file" and (
        type(value.get("size")) is not int
        or value["size"] < 0
        or not isinstance(value.get("sha256"), str)
        or HEX64.fullmatch(value["sha256"]) is None
    ):
        raise EvidenceVerificationError(f"dependency file entry is invalid: {root}")
    if kind == "symlink" and (
        not isinstance(value.get("target"), str)
        or not value["target"]
        or not isinstance(value.get("target_sha256"), str)
        or HEX64.fullmatch(value["target_sha256"]) is None
        or value["target_sha256"]
        != hashlib.sha256(value["target"].encode("utf-8")).hexdigest()
    ):
        raise EvidenceVerificationError(
            f"dependency symlink entry is invalid: {root}"
        )
    return relative


def _live_dependency_entry(path: Path, root: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        relative = "." if path == root else path.relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise EvidenceVerificationError(
            f"live dependency path is unavailable: {path}"
        ) from exc
    common = {
        "path": relative,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }
    if stat.S_ISREG(metadata.st_mode):
        digest, observed = _stream_sha256(path, label=f"live dependency {path}")
        return {
            **common,
            "kind": "file",
            "sha256": digest,
            "size": observed.st_size,
        }
    if stat.S_ISDIR(metadata.st_mode):
        return {**common, "kind": "directory"}
    if stat.S_ISLNK(metadata.st_mode):
        target = os.readlink(path)
        return {
            **common,
            "kind": "symlink",
            "target": target,
            "target_sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
        }
    raise EvidenceVerificationError(
        f"live dependency contains an unsafe special object: {path}"
    )


def _live_dependency_root(root: Path) -> dict[str, Any]:
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise EvidenceVerificationError(f"live dependency root is absent: {root}") from exc
    entries = [_live_dependency_entry(root, root)]
    if stat.S_ISDIR(root_metadata.st_mode) and not root.is_symlink():
        for directory_text, directories, names in os.walk(
            root, topdown=True, followlinks=False
        ):
            directory = Path(directory_text)
            directories.sort()
            names.sort()
            retained: list[str] = []
            for name in directories:
                child = directory / name
                entries.append(_live_dependency_entry(child, root))
                if not child.is_symlink():
                    retained.append(name)
            directories[:] = retained
            for name in names:
                entries.append(_live_dependency_entry(directory / name, root))
            if len(entries) > MAX_TREE_FILES:
                raise EvidenceVerificationError(
                    "live dependency snapshot contains too many entries"
                )
    entries.sort(key=lambda item: item["path"])
    return {
        "root": str(root),
        "entry_count": len(entries),
        "manifest_sha256": hashlib.sha256(canonical_json(entries)).hexdigest(),
        "entries": entries,
    }


def validate_dependency_document(
    value: dict[str, Any],
    *,
    runtime: Mapping[str, Any],
    expected: Mapping[str, str],
    closure: Mapping[str, Any],
    external_runtime_paths: Sequence[str],
    verify_live_files: bool,
) -> None:
    roots = value.get("roots") if type(value) is dict else None
    expected_roots = expected_dependency_roots(
        runtime=runtime,
        expected=expected,
        closure=closure,
        external_runtime_paths=external_runtime_paths,
    )
    expected_root_text = [str(item) for item in expected_roots]
    if (
        set(value)
        != {"schema_version", "algorithm", "root_count", "entry_count", "roots", "combined_sha256"}
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("algorithm") != "canonical-json-complete-lstat-tree-sha256-v1"
        or type(roots) is not list
        or not roots
        or [item.get("root") if type(item) is dict else None for item in roots]
        != expected_root_text
        or value.get("root_count") != len(roots)
        or value.get("combined_sha256") != hashlib.sha256(canonical_json(roots)).hexdigest()
    ):
        raise EvidenceVerificationError("dependency identity evidence is invalid")
    total = 0
    for root_document, expected_root in zip(roots, expected_roots, strict=True):
        entries = root_document.get("entries") if type(root_document) is dict else None
        if (
            type(root_document) is not dict
            or set(root_document) != {"root", "entry_count", "manifest_sha256", "entries"}
            or root_document.get("root") != str(expected_root)
            or type(entries) is not list
            or not entries
            or root_document.get("entry_count") != len(entries)
            or root_document.get("manifest_sha256")
            != hashlib.sha256(canonical_json(entries)).hexdigest()
        ):
            raise EvidenceVerificationError("dependency root evidence is invalid")
        paths = [
            _validate_dependency_entry(item, root=expected_root) for item in entries
        ]
        if paths != sorted(set(paths)) or paths[0] != ".":
            raise EvidenceVerificationError("dependency entry path set is invalid")
        if verify_live_files and _live_dependency_root(expected_root) != root_document:
            raise EvidenceVerificationError("live dependency identity drifted")
        total += len(entries)
    if value.get("entry_count") != total:
        raise EvidenceVerificationError("dependency entry count is invalid")


def _verified_release_summary(
    root: Path, manifest: Mapping[str, Any], expected: Mapping[str, str]
) -> dict[str, Any]:
    payload = stable_read(
        root / "RELEASE-MANIFEST.json",
        label="installed release manifest summary",
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
    )
    return {
        **expected,
        "manifest_file_sha256": hashlib.sha256(payload).hexdigest(),
        "release_file_count": len(manifest["files"]),
        "verified": True,
    }


def _validate_closure_python(value: dict[str, Any], *, expected_sha256: str) -> None:
    if (
        not isinstance(expected_sha256, str)
        or HEX64.fullmatch(expected_sha256) is None
        or set(value)
        != {
            "schema_version",
            "path",
            "sha256",
            "size",
            "uid",
            "gid",
            "mode",
            "root_owned",
            "one_link_regular",
            "resolved_executable",
            "isolated",
            "no_site",
        }
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("path") != CLOSURE_PYTHON
        or value.get("sha256") != expected_sha256
        or value.get("uid") != 0
        or value.get("gid") != 0
        or value.get("mode") != "0755"
        or value.get("root_owned") is not True
        or value.get("one_link_regular") is not True
        or value.get("resolved_executable") != CLOSURE_PYTHON
        or value.get("isolated") is not True
        or value.get("no_site") is not True
        or not isinstance(value.get("sha256"), str)
        or HEX64.fullmatch(value["sha256"]) is None
        or type(value.get("size")) is not int
        or value["size"] <= 0
    ):
        raise EvidenceVerificationError("closure verification Python evidence is invalid")


def _current_child_mounts(closure: Mapping[str, Any]) -> list[dict[str, Any]]:
    root = closure["mount"]["mount_point"]
    bindings = closure["activation"]["bindings"]
    endpoints = [(root, root), *((item["source"], item["destination"]) for item in bindings)]
    wanted = {destination for _source, destination in endpoints}
    rows: dict[str, dict[str, Any]] = {}
    for line in _read_virtual_text(
        Path("/proc/self/mountinfo"), label="verifier child mountinfo"
    ).splitlines():
        fields = line.split(" ")
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise EvidenceVerificationError("verifier child mountinfo is invalid") from exc
        if len(fields) < 10 or separator < 6 or len(fields) <= separator + 3:
            raise EvidenceVerificationError("verifier child mountinfo row is incomplete")
        mount_point = _mount_unescape(fields[4])
        if mount_point not in wanted:
            continue
        if mount_point in rows:
            raise EvidenceVerificationError("verifier child mount is ambiguous")
        rows[mount_point] = {
            "mount_id": int(fields[0]),
            "parent_mount_id": int(fields[1]),
            "major_minor": fields[2],
            "root": _mount_unescape(fields[3]),
            "mount_point": mount_point,
            "options": sorted(set(fields[5].split(","))),
            "filesystem_type": fields[separator + 1],
            "mount_source": _mount_unescape(fields[separator + 2]),
            "super_options": sorted(set(fields[separator + 3].split(","))),
        }
    if set(rows) != wanted:
        raise EvidenceVerificationError("verifier child mount set is incomplete")
    result: list[dict[str, Any]] = []
    for index, (source_text, destination_text) in enumerate(endpoints):
        try:
            source = Path(source_text)
            destination = Path(destination_text)
            source_metadata = source.stat()
            destination_metadata = destination.stat()
            read_only = bool(
                os.statvfs(destination).f_flag & getattr(os, "ST_RDONLY", 1)
            )
        except OSError as exc:
            raise EvidenceVerificationError("verifier child mount endpoint is unavailable") from exc
        value = {
            "source_path": source_text,
            "destination_path": destination_text,
            "source_device": source_metadata.st_dev,
            "source_inode": source_metadata.st_ino,
            "destination_device": destination_metadata.st_dev,
            "destination_inode": destination_metadata.st_ino,
            **rows[destination_text],
            "statvfs_read_only": read_only,
        }
        if (
            (source_metadata.st_dev, source_metadata.st_ino)
            != (destination_metadata.st_dev, destination_metadata.st_ino)
            or not read_only
            or not {"ro", "nodev", "nosuid"}.issubset(value["options"])
        ):
            raise EvidenceVerificationError("verifier child mount is not sealed")
        if index == 0:
            if (
                value["mount_source"] != closure["mount"]["loop_device"]
                or value["filesystem_type"] != "squashfs"
            ):
                raise EvidenceVerificationError("verifier closure root mount drifted")
        else:
            binding = bindings[index - 1]
            if any(
                value[field] != binding[field]
                for field in (
                    "mount_id",
                    "major_minor",
                    "filesystem_type",
                    "source_device",
                    "source_inode",
                )
            ):
                raise EvidenceVerificationError("verifier child bind identity drifted")
        result.append(value)
    return result


def _current_unit_cgroup_identity() -> dict[str, Any]:
    rows = _read_virtual_text(Path("/proc/self/cgroup"), label="verifier cgroup").splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::"):
        raise EvidenceVerificationError("verifier requires cgroup v2")
    relative = rows[0][3:]
    portable = PurePosixPath(relative)
    if not portable.is_absolute() or str(portable) != relative or relative == "/":
        raise EvidenceVerificationError("verifier unit cgroup path is invalid")
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    directory = root.joinpath(*portable.parts[1:]).resolve(strict=True)
    if root not in directory.parents:
        raise EvidenceVerificationError("verifier unit cgroup escaped cgroupfs")
    subdirectories: list[Path] = []
    for directory_text, names, _files in os.walk(directory, topdown=True, followlinks=False):
        current = Path(directory_text)
        for name in sorted(names):
            child = current / name
            if child.is_symlink() or not child.is_dir():
                raise EvidenceVerificationError("verifier unit cgroup subtree is unsafe")
            subdirectories.append(child)
    if subdirectories:
        raise EvidenceVerificationError("verifier unit cgroup has delegated descendants")
    metadata = directory.stat()
    try:
        processes = sorted(
            {
                int(item)
                for item in (directory / "cgroup.procs").read_text("ascii").splitlines()
                if item
            }
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise EvidenceVerificationError("verifier unit cgroup process set is unavailable") from exc
    if processes != sorted([os.getppid(), os.getpid()]):
        raise EvidenceVerificationError("verifier unit cgroup contains an unexpected process")
    return {
        "relative_path": relative,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "processes": processes,
    }


def _validate_process_control(value: Any, *, live_cgroup: Mapping[str, Any]) -> None:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "execution_model",
        "nested_systemd_run_used",
        "new_process_group",
        "parent_death_signal",
        "timeout_kills_process_group",
        "timeout_observed",
        "leader_waited_and_reaped",
        "unit_cgroup",
    }:
        raise EvidenceVerificationError("direct child process-control schema is invalid")
    cgroup = value.get("unit_cgroup")
    fields = {
        "version",
        "relative_path",
        "device",
        "inode",
        "subtree_directory_count",
        "subtree_identity_sha256",
        "baseline_process_count",
        "baseline_processes_sha256",
        "final_process_count",
        "final_processes_sha256",
        "baseline_equals_final",
        "unexpected_descendant_count",
        "unexpected_descendants_sha256",
    }
    if (
        not _schema_version_is_one(value.get("schema_version"))
        or value.get("execution_model") != "direct-fork-exec"
        or value.get("nested_systemd_run_used") is not False
        or value.get("new_process_group") is not True
        or value.get("parent_death_signal") != "SIGKILL"
        or value.get("timeout_kills_process_group") is not True
        or value.get("timeout_observed") is not False
        or value.get("leader_waited_and_reaped") is not True
        or type(cgroup) is not dict
        or set(cgroup) != fields
        or cgroup.get("version") != 2
        or cgroup.get("relative_path") != live_cgroup["relative_path"]
        or cgroup.get("device") != live_cgroup["device"]
        or cgroup.get("inode") != live_cgroup["inode"]
        or cgroup.get("subtree_directory_count") != 1
        or cgroup.get("subtree_identity_sha256")
        != hashlib.sha256(
            canonical_json(
                [
                    {
                        "path": "/",
                        "device": cgroup.get("device"),
                        "inode": cgroup.get("inode"),
                    }
                ]
            )
        ).hexdigest()
        or type(cgroup.get("baseline_process_count")) is not int
        or cgroup["baseline_process_count"] != 1
        or cgroup.get("final_process_count") != cgroup["baseline_process_count"]
        or cgroup.get("baseline_processes_sha256")
        != hashlib.sha256(canonical_json([os.getppid()])).hexdigest()
        or cgroup.get("baseline_processes_sha256") != cgroup.get("final_processes_sha256")
        or not isinstance(cgroup.get("baseline_processes_sha256"), str)
        or HEX64.fullmatch(cgroup["baseline_processes_sha256"]) is None
        or cgroup.get("baseline_equals_final") is not True
        or cgroup.get("unexpected_descendant_count") != 0
        or cgroup.get("unexpected_descendants_sha256")
        != hashlib.sha256(canonical_json([])).hexdigest()
    ):
        raise EvidenceVerificationError("direct child process-control proof is invalid")


def _rebuild_click_tree(root: Path, venv_root: Path) -> list[dict[str, Any]]:
    try:
        root = root.resolve(strict=True)
        venv_root = venv_root.resolve(strict=True)
    except OSError as exc:
        raise EvidenceVerificationError("attested Click tree is unavailable") from exc
    if root == venv_root or venv_root not in root.parents:
        raise EvidenceVerificationError("attested Click tree escaped the venv")
    result: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        path = pending.pop()
        metadata = path.lstat()
        common = {
            "path": path.relative_to(venv_root).as_posix(),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        if stat.S_ISDIR(metadata.st_mode):
            result.append({**common, "kind": "directory"})
            pending.extend(
                Path(item.path)
                for item in sorted(os.scandir(path), key=lambda item: item.name, reverse=True)
            )
        elif stat.S_ISREG(metadata.st_mode):
            payload = stable_read(
                path,
                label="attested Click tree member",
                maximum=128 * 1024 * 1024,
                allow_empty=True,
            )
            result.append(
                {
                    **common,
                    "kind": "regular",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
        else:
            raise EvidenceVerificationError("attested Click tree has a special file")
        if len(result) > 10_000:
            raise EvidenceVerificationError("attested Click tree is too large")
    result.sort(key=lambda item: item["path"])
    return result


def _expected_child_environment(role: str) -> dict[str, str]:
    homes = {
        "odoo": "/var/lib/odoo-accounting-cli-v3-broker",
        "signer": "/var/lib/odoo-accounting-cli-v3-broker",
        "postgres": "/var/lib/postgresql",
        "verifier": "/root",
    }
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": homes[role],
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _validate_attested_command(
    command: Any,
    *,
    role: str,
    artifact: str,
    root: Path,
    runtime: Mapping[str, Any],
    expected: Mapping[str, str],
) -> list[str]:
    if type(command) is not list or any(not isinstance(item, str) for item in command):
        raise EvidenceVerificationError("direct child command is invalid")
    runtime_path = RUNTIME_PARENT / f"runtime-test-{expected['release']}.json"
    launcher = root / "bin" / "odoo-accounting-cli-v3"
    signer = root / "deployment" / "dev29" / "sign_read.py"
    oracle = root / "deployment" / "dev29" / "read_oracles.py"
    plan_path = root.joinpath(*PLAN_RELATIVE.parts)
    odoo_prefix = [runtime["odoo_python"], "-I"]
    system_prefix = [CLOSURE_PYTHON, "-I", "-S"]
    expected_command: list[str] | None = None
    if artifact == "release/identity" and role == "odoo":
        expected_command = [*odoo_prefix, str(launcher), "release", "identity"]
    elif artifact == "boundary/probe" and role == "odoo":
        expected_command = [
            *odoo_prefix,
            str(launcher),
            "evidence",
            "read-boundary",
            "--runtime-config",
            str(runtime_path),
            "--timeout-seconds",
            "120",
        ]
    elif artifact in {"witness-pre", "witness-post"} and role == "postgres":
        expected_command = [
            *odoo_prefix,
            str(oracle),
            "witness",
            "--plan",
            str(plan_path),
        ]
    else:
        parts = artifact.split("/")
        if len(parts) == 3 and parts[0] in {"positive", "negative"}:
            section, case_name, action = parts
            if action == "signer" and role == "signer":
                selector = "--case" if section == "positive" else "--negative"
                expected_command = [
                    *system_prefix,
                    str(signer),
                    selector,
                    case_name,
                    "--runtime-config",
                    str(runtime_path),
                ]
            elif action == "read" and role == "odoo":
                expected_command = [
                    *odoo_prefix,
                    str(launcher),
                    "read",
                    "--runtime-config",
                    str(runtime_path),
                    "--timeout-seconds",
                    "120",
                ]
            elif (
                section == "positive"
                and case_name in FINANCIAL_NAMES
                and action == "oracle"
                and role == "postgres"
                and len(command) == 12
                and command[:8]
                == [
                    *odoo_prefix,
                    str(oracle),
                    "verify",
                    "--plan",
                    str(plan_path),
                    "--case",
                    case_name,
                ]
                and command[8] == "--request"
                and command[10] == "--response"
            ):
                request_path = Path(command[9])
                response_path = Path(command[11])
                if (
                    request_path.name == "request.json"
                    and response_path.name == "response.json"
                    and request_path.parent == response_path.parent
                    and request_path.parent.parent == Path("/run")
                    and request_path.parent.name.startswith(
                        "odoo-accounting-cli-v3-dev29-oracle-"
                    )
                ):
                    expected_command = list(command)
    if expected_command is None or command != expected_command:
        raise EvidenceVerificationError("direct child command escaped the fixed suite")
    return command


def _validate_child_attestation(
    value: Any,
    *,
    role: str,
    artifact: str,
    root: Path,
    runtime: Mapping[str, Any],
    expected: Mapping[str, str],
    closure: Mapping[str, Any],
    expected_mounts: list[dict[str, Any]],
) -> None:
    if type(value) is not dict or set(value) != {
        "schema_version",
        "role",
        "pid",
        "ppid",
        "command",
        "command_sha256",
        "python",
        "credentials",
        "self_mount_namespace",
        "host_mount_namespace",
        "same_supervisor_namespace",
        "mounts",
        "loop_device",
        "environment",
        "click",
    }:
        raise EvidenceVerificationError("direct child attestation schema is invalid")
    command = _validate_attested_command(
        value.get("command"),
        role=role,
        artifact=artifact,
        root=root,
        runtime=runtime,
        expected=expected,
    )
    if (
        not _schema_version_is_one(value.get("schema_version"))
        or value.get("role") != role
        or type(value.get("pid")) is not int
        or value["pid"] <= 1
        or value.get("ppid") != os.getppid()
        or value.get("command_sha256")
        != hashlib.sha256(canonical_json(command)).hexdigest()
        or value.get("self_mount_namespace")
        != closure["mount"]["self_mount_namespace"]
        or value.get("host_mount_namespace")
        != closure["mount"]["host_mount_namespace"]
        or value.get("same_supervisor_namespace") is not True
        or value.get("mounts") != expected_mounts
        or value.get("loop_device") != closure["mount"]["loop_device"]
        or value.get("environment") != _expected_child_environment(role)
    ):
        raise EvidenceVerificationError("direct child attestation envelope is invalid")
    try:
        import grp
        import pwd

        account = {"odoo": "odoo", "signer": "odoo", "postgres": "postgres"}[role]
        identity = pwd.getpwnam(account)
        group = grp.getgrnam(account)
    except (KeyError, OSError) as exc:
        raise EvidenceVerificationError("direct child account identity is unavailable") from exc
    if identity.pw_gid != group.gr_gid:
        raise EvidenceVerificationError("direct child account primary group drifted")
    expected_status = {
        "Uid": " ".join([str(identity.pw_uid)] * 4),
        "Gid": " ".join([str(group.gr_gid)] * 4),
        "Groups": "",
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
    }
    if value.get("credentials") != {
        "uid": identity.pw_uid,
        "gid": group.gr_gid,
        "groups": [],
        "status": expected_status,
        "capabilities_all_zero": True,
        "no_new_privileges": True,
    }:
        raise EvidenceVerificationError("direct child credential proof is invalid")
    python = value.get("python")
    expected_python = CLOSURE_PYTHON if role == "signer" else runtime["odoo_python"]
    expected_no_site = role == "signer"
    if (
        type(python) is not dict
        or set(python) != {"path", "resolved_path", "isolated", "no_site", "sys_path"}
        or python.get("path") != expected_python
        or not isinstance(python.get("resolved_path"), str)
        or not PurePosixPath(python["resolved_path"]).is_absolute()
        or str(PurePosixPath(python["resolved_path"])) != python["resolved_path"]
        or python.get("isolated") is not True
        or python.get("no_site") is not expected_no_site
        or type(python.get("sys_path")) is not list
        or not python["sys_path"]
    ):
        raise EvidenceVerificationError("direct child Python proof is invalid")
    venv_root = Path(runtime["odoo_python"]).parent.parent.resolve(strict=True)
    external_roots = [Path(item).resolve(strict=True) for item in closure["closure_identity"]["external_runtime_paths"]]
    for path_text in python["sys_path"]:
        if (
            not isinstance(path_text, str)
            or not path_text
            or not PurePosixPath(path_text).is_absolute()
            or str(PurePosixPath(path_text)) != path_text
            or any(part in {".", ".."} for part in PurePosixPath(path_text).parts)
        ):
            raise EvidenceVerificationError("direct child Python path is not canonical")
        candidate = Path(path_text)
        if path_text == "/usr/lib/python312.zip" and not candidate.exists():
            continue
        try:
            candidate = candidate.resolve(strict=True)
        except OSError as exc:
            raise EvidenceVerificationError("direct child Python path is unavailable") from exc
        covered = candidate == venv_root or venv_root in candidate.parents
        covered = covered or any(
            candidate == external or external in candidate.parents
            for external in external_roots
        )
        if not covered or candidate == root or root in candidate.parents:
            raise EvidenceVerificationError("direct child Python path escaped trusted roots")
    click = value.get("click")
    if role != "odoo":
        if click is not None:
            raise EvidenceVerificationError("non-Odoo child imported Click")
        return
    if (
        type(click) is not dict
        or set(click)
        != {
            "distribution_name",
            "distribution_version",
            "origin",
            "venv_root",
            "tree_entries",
            "tree_entry_count",
            "tree_sha256",
            "release_source_shadow_absent",
        }
        or not isinstance(click.get("distribution_name"), str)
        or click["distribution_name"].lower().replace("_", "-") != "click"
        or not isinstance(click.get("distribution_version"), str)
        or not click["distribution_version"]
        or click.get("venv_root") != str(venv_root)
        or click.get("release_source_shadow_absent") is not True
        or type(click.get("tree_entries")) is not list
        or click.get("tree_entry_count") != len(click["tree_entries"])
        or click.get("tree_sha256")
        != hashlib.sha256(canonical_json(click["tree_entries"])).hexdigest()
    ):
        raise EvidenceVerificationError("Odoo Click proof is invalid")
    try:
        origin = Path(click["origin"]).resolve(strict=True)
    except (KeyError, OSError, TypeError) as exc:
        raise EvidenceVerificationError("Odoo Click origin is invalid") from exc
    if venv_root not in origin.parents or origin.name != "__init__.py":
        raise EvidenceVerificationError("Odoo Click origin escaped the venv")
    dist_roots: set[Path] = set()
    for entry in click["tree_entries"]:
        if type(entry) is not dict or not isinstance(entry.get("path"), str):
            raise EvidenceVerificationError("Odoo Click tree entry is invalid")
        parts = PurePosixPath(entry["path"]).parts
        for index, component in enumerate(parts):
            if component.lower().endswith(".dist-info"):
                dist_roots.add(venv_root.joinpath(*parts[: index + 1]))
    if len(dist_roots) != 1:
        raise EvidenceVerificationError("Odoo Click dist-info proof is ambiguous")
    rebuilt = _rebuild_click_tree(origin.parent, venv_root)
    rebuilt.extend(_rebuild_click_tree(next(iter(dist_roots)), venv_root))
    rebuilt.sort(key=lambda item: item["path"])
    if rebuilt != click["tree_entries"]:
        raise EvidenceVerificationError("Odoo Click tree changed after execution")
    if any(os.path.lexists(path) for path in (root / "src" / "click.py", root / "src" / "click")):
        raise EvidenceVerificationError("release source shadows sealed Click")


def _child_artifact_roles() -> dict[str, str]:
    result = {
        "release/identity": "odoo",
        "boundary/probe": "odoo",
        "witness-pre": "postgres",
        "witness-post": "postgres",
    }
    for name in POSITIVE_NAMES:
        result[f"positive/{name}/signer"] = "signer"
        result[f"positive/{name}/read"] = "odoo"
        if name in FINANCIAL_NAMES:
            result[f"positive/{name}/oracle"] = "postgres"
    for name in NEGATIVE_NAMES:
        result[f"negative/{name}/read"] = "odoo"
        if name != "replay":
            result[f"negative/{name}/signer"] = "signer"
    return result


def _read_runtime_trace_index(
    expected: Mapping[str, str],
    *,
    root: Path,
    release_manifest: Mapping[str, Any],
    expected_sha256: str,
    expected_strace_sha256: str,
    enforce_root: bool = True,
) -> tuple[dict[str, Any], dict[str, dict[str, str]], bytes]:
    if (
        HEX64.fullmatch(expected_sha256) is None
        or HEX64.fullmatch(expected_strace_sha256) is None
    ):
        raise EvidenceVerificationError("runtime-open trace expectation is invalid")
    path = TRACE_INDEX_PARENT / expected["release"] / TRACE_INDEX_NAME
    if enforce_root and os.name == "posix":
        _safe_root_chain(path.parent, final_mode=0o555)
    payload = stable_read(
        path,
        label="runtime-open trace index",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o400})
            if enforce_root and os.name == "posix"
            else None
        ),
    )
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise EvidenceVerificationError("runtime-open trace index digest mismatch")
    index = parse_json(payload, label="runtime-open trace index", canonical=True)
    if (
        set(index)
        != {
            "schema_version",
            "scope",
            "release",
            "expected_strace_sha256",
            "expected_static_closure_sha256",
            "policy_source_sha256",
            "runtime_module_sha256",
            "release_manifest_sha256",
            "targets",
            "production_promotion_allowed",
        }
        or type(index.get("schema_version")) is not int
        or index["schema_version"] != 1
        or index.get("scope") != TRACE_INDEX_SCOPE
        or index.get("release") != expected["release"]
        or index.get("expected_strace_sha256") != expected_strace_sha256
        or not isinstance(index.get("expected_static_closure_sha256"), str)
        or HEX64.fullmatch(index["expected_static_closure_sha256"]) is None
        or not isinstance(index.get("policy_source_sha256"), str)
        or HEX64.fullmatch(index["policy_source_sha256"]) is None
        or not isinstance(index.get("runtime_module_sha256"), str)
        or HEX64.fullmatch(index["runtime_module_sha256"]) is None
        or not isinstance(index.get("release_manifest_sha256"), str)
        or HEX64.fullmatch(index["release_manifest_sha256"]) is None
        or type(index.get("targets")) is not list
        or index.get("production_promotion_allowed") is not False
    ):
        raise EvidenceVerificationError("runtime-open trace index identity is invalid")
    targets: dict[str, dict[str, str]] = {}
    ordered: list[str] = []
    for entry in index["targets"]:
        if (
            type(entry) is not dict
            or set(entry)
            != {
                "target_id",
                "manifest_sha256",
                "watch_roots_sha256",
                "child_environment_sha256",
            }
            or not isinstance(entry.get("target_id"), str)
            or SAFE_NAME.fullmatch(entry["target_id"]) is None
            or entry["target_id"] in targets
            or not isinstance(entry.get("manifest_sha256"), str)
            or HEX64.fullmatch(entry["manifest_sha256"]) is None
            or not isinstance(entry.get("watch_roots_sha256"), str)
            or HEX64.fullmatch(entry["watch_roots_sha256"]) is None
            or not isinstance(entry.get("child_environment_sha256"), str)
            or HEX64.fullmatch(entry["child_environment_sha256"]) is None
        ):
            raise EvidenceVerificationError("runtime-open trace index target is invalid")
        ordered.append(entry["target_id"])
        targets[entry["target_id"]] = dict(entry)
    if tuple(ordered) != expected_runtime_trace_targets():
        raise EvidenceVerificationError("runtime-open trace target set is incomplete")
    expected_policy_files = {
        TRACE_INDEX_NAME,
        *(f"{target_id}.json" for target_id in ordered),
    }
    directory_identity = _runtime_trace_policy_directory_identity(
        path.parent, expected_names=expected_policy_files
    )
    runtime_payload = stable_read(
        root.joinpath(*TRACE_RELATIVE.parts),
        label="exact release runtime-open validator",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o444})
            if enforce_root and os.name == "posix"
            else None
        ),
    )
    release_manifest_payload = stable_read(
        root / "RELEASE-MANIFEST.json",
        label="exact release manifest for runtime-open policy",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o444})
            if enforce_root and os.name == "posix"
            else None
        ),
    )
    manifest_entries = [
        item
        for item in release_manifest.get("files", [])
        if type(item) is dict and item.get("path") == str(TRACE_RELATIVE)
    ]
    if (
        len(manifest_entries) != 1
        or hashlib.sha256(runtime_payload).hexdigest()
        != index["runtime_module_sha256"]
        or manifest_entries[0].get("sha256")
        != index["runtime_module_sha256"]
        or type(manifest_entries[0].get("size")) is not int
        or manifest_entries[0]["size"] != len(runtime_payload)
        or hashlib.sha256(release_manifest_payload).hexdigest()
        != index["release_manifest_sha256"]
    ):
        raise EvidenceVerificationError(
            "runtime-open policy release member binding differs"
        )
    manifest_documents = []
    for target_id in ordered:
        manifest, _policy_sha256 = _validate_runtime_trace_manifest(
            target_id,
            targets[target_id],
            index,
            expected,
            enforce_root=enforce_root,
        )
        manifest_documents.append(manifest)
    policy_source = {
        "schema_version": 1,
        "scope": TRACE_POLICY_SOURCE_SCOPE,
        "release": index["release"],
        "expected_strace_sha256": index["expected_strace_sha256"],
        "expected_static_closure_sha256": index[
            "expected_static_closure_sha256"
        ],
        "expected_runtime_module_sha256": index["runtime_module_sha256"],
        "expected_release_manifest_sha256": index[
            "release_manifest_sha256"
        ],
        "targets": manifest_documents,
        "production_promotion_allowed": False,
    }
    if (
        hashlib.sha256(canonical_json(policy_source) + b"\n").hexdigest()
        != index["policy_source_sha256"]
    ):
        raise EvidenceVerificationError("runtime-open policy source digest mismatch")
    if (
        _runtime_trace_policy_directory_identity(
            path.parent, expected_names=expected_policy_files
        )
        != directory_identity
    ):
        raise EvidenceVerificationError(
            "runtime-open policy directory changed during verification"
        )
    return index, targets, runtime_payload


def _runtime_trace_policy_directory_identity(
    path: Path, *, expected_names: set[str]
) -> tuple[int, ...]:
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(before.st_mode):
            raise EvidenceVerificationError(
                "runtime-open policy directory identity is invalid"
            )
        with os.scandir(path) as entries:
            observed_names = [entry.name for entry in entries]
        after = path.lstat()
    except EvidenceVerificationError:
        raise
    except OSError as exc:
        raise EvidenceVerificationError(
            "runtime-open policy directory cannot be inspected"
        ) from exc
    if (
        _fingerprint(before) != _fingerprint(after)
        or len(observed_names) != len(expected_names)
        or set(observed_names) != expected_names
    ):
        raise EvidenceVerificationError(
            "runtime-open policy installed file set is invalid"
        )
    return _fingerprint(after)


def _validate_runtime_trace_manifest(
    target_id: str,
    entry: Mapping[str, str],
    index: Mapping[str, Any],
    expected: Mapping[str, str],
    *,
    enforce_root: bool = True,
) -> tuple[dict[str, Any], str]:
    path = TRACE_INDEX_PARENT / expected["release"] / f"{target_id}.json"
    payload = stable_read(
        path,
        label=f"runtime-open manifest {target_id}",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o400}) if enforce_root and os.name == "posix" else None
        ),
    )
    if hashlib.sha256(payload).hexdigest() != entry["manifest_sha256"]:
        raise EvidenceVerificationError("runtime-open manifest digest mismatch")
    manifest = parse_json(
        payload, label=f"runtime-open manifest {target_id}", canonical=True
    )
    fields = {
        "schema_version",
        "scope",
        "release",
        "target_id",
        "role",
        "working_directory",
        "environment",
        "bootstrap_argv",
        "final_argv",
        "allowed_paths",
        "path_access_policy",
        "watch_roots",
        "expected_static_closure_sha256",
        "expected_child_environment_sha256",
        "expected_watch_roots_sha256",
        "expected_returncodes",
    }
    allowed = manifest.get("allowed_paths")
    policies = manifest.get("path_access_policy")
    watches = manifest.get("watch_roots")
    if (
        set(manifest) != fields
        or type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
        or manifest.get("scope") != TRACE_MANIFEST_SCOPE
        or manifest.get("release") != expected["release"]
        or manifest.get("target_id") != target_id
        or manifest.get("role") != _expected_trace_role(target_id)
        or manifest.get("expected_static_closure_sha256")
        != index["expected_static_closure_sha256"]
        or manifest.get("environment")
        != _expected_child_environment(manifest.get("role"))
        or manifest.get("expected_child_environment_sha256")
        != entry["child_environment_sha256"]
        or hashlib.sha256(canonical_json(manifest.get("environment"))).hexdigest()
        != entry["child_environment_sha256"]
        or manifest.get("expected_watch_roots_sha256")
        != entry["watch_roots_sha256"]
        or type(allowed) is not list
        or not allowed
        or allowed != sorted(set(allowed))
        or any(not isinstance(item, str) or not item.startswith("/") for item in allowed)
        or type(watches) is not list
        or not watches
        or watches != sorted(set(watches))
        or hashlib.sha256(canonical_json(tuple(watches))).hexdigest()
        != entry["watch_roots_sha256"]
        or type(policies) is not list
        or not policies
        or type(manifest.get("bootstrap_argv")) is not list
        or not manifest["bootstrap_argv"]
        or type(manifest.get("final_argv")) is not list
        or not manifest["final_argv"]
        or type(manifest.get("expected_returncodes")) is not list
        or not manifest["expected_returncodes"]
    ):
        raise EvidenceVerificationError("runtime-open manifest identity is invalid")
    policy_fields = {
        "path",
        "role",
        "classification",
        "allowed_access",
        "create_suffixes",
        "delta_verifier",
        "delta_contract_sha256",
        "allow_success",
        "allowed_errnos",
        "failure_guard",
    }
    policy_paths: list[str] = []
    for policy in policies:
        if (
            type(policy) is not dict
            or set(policy) != policy_fields
            or policy.get("role") != manifest["role"]
            or policy.get("classification")
            not in {"immutable", "mutable-state", "unix-socket", "process-view"}
            or not isinstance(policy.get("path"), str)
            or not policy["path"].startswith("/")
            or type(policy.get("allowed_access")) is not list
            or not policy["allowed_access"]
            or policy["allowed_access"] != sorted(set(policy["allowed_access"]))
            or type(policy.get("create_suffixes")) is not list
            or type(policy.get("allow_success")) is not bool
            or type(policy.get("allowed_errnos")) is not list
        ):
            raise EvidenceVerificationError("runtime-open access policy is invalid")
        if not _runtime_access_policy_is_safe(policy):
            raise EvidenceVerificationError("runtime-open access policy is unsafe")
        policy_paths.append(policy["path"])
    if policy_paths != sorted(set(policy_paths)):
        raise EvidenceVerificationError("runtime-open access policy is ambiguous")
    for observed in allowed:
        matches = [
            policy
            for policy in policies
            if _runtime_policy_matches(policy, observed)
        ]
        if len(matches) != 1:
            raise EvidenceVerificationError("runtime-open allow path policy is ambiguous")
        watched = any(observed == root or observed.startswith(root + "/") for root in watches)
        if matches[0]["classification"] == "immutable":
            if not watched:
                raise EvidenceVerificationError("runtime-open immutable path is unwatched")
        elif watched:
            raise EvidenceVerificationError("runtime-open non-immutable path is watched")
    return manifest, hashlib.sha256(canonical_json(policies)).hexdigest()


def _runtime_process_view_path(path: str) -> bool:
    roots = ("/proc/self", "/proc/@self", "/proc/1")
    return any(path == root or path.startswith(root + "/") for root in roots)


def _runtime_policy_matches(policy: Mapping[str, Any], observed: str) -> bool:
    return observed == policy["path"] or (
        policy["classification"] == "mutable-state"
        and any(observed == policy["path"] + suffix for suffix in policy["create_suffixes"])
    )


def _runtime_access_policy_is_safe(policy: Mapping[str, Any]) -> bool:
    immutable_access = {"read", "metadata", "execute"}
    mutable_access = {"read", "write", "create", "truncate", "append", "delete", "metadata"}
    socket_access = {"unix-connect", "unix-send"}
    process_view_access = {"read", "metadata"}
    access = set(policy["allowed_access"])
    suffixes = policy["create_suffixes"]
    errnos = policy["allowed_errnos"]
    classification = policy["classification"]
    delta = policy["delta_verifier"]
    delta_contract = policy["delta_contract_sha256"]
    guard = policy["failure_guard"]
    if (
        suffixes != sorted(set(suffixes))
        or any(
            not isinstance(suffix, str)
            or re.fullmatch(r"-[0-9A-Za-z._-]{1,31}", suffix) is None
            for suffix in suffixes
        )
        or errnos != sorted(set(errnos))
        or any(
            not isinstance(errno, str)
            or re.fullmatch(r"E[A-Z0-9_]{1,63}", errno) is None
            for errno in errnos
        )
        or (not policy["allow_success"] and not errnos)
    ):
        return False
    if classification == "immutable":
        return (
            access <= immutable_access
            and not suffixes
            and delta is None
            and delta_contract is None
            and guard == ("dev29-watch-tree-identity-v1" if errnos else None)
        )
    if classification == "mutable-state":
        return (
            access <= mutable_access
            and delta == "dev29-sqlite-state-delta-v1"
            and isinstance(delta_contract, str)
            and re.fullmatch(r"[0-9a-f]{64}", delta_contract) is not None
            and (not suffixes or {"create", "write"} <= access)
            and guard == (delta if errnos else None)
        )
    if classification == "unix-socket":
        return (
            access <= socket_access
            and not suffixes
            and delta is None
            and delta_contract is None
            and policy["allow_success"]
            and not errnos
            and guard is None
        )
    return (
        classification == "process-view"
        and _runtime_process_view_path(policy["path"])
        and access <= process_view_access
        and not suffixes
        and delta is None
        and delta_contract is None
        and policy["allow_success"]
        and not errnos
        and guard is None
    )


def _load_runtime_trace_module(
    root: Path,
    *,
    expected_sha256: str,
    verified_payload: bytes | None = None,
    enforce_root: bool = True,
) -> Any:
    path = root.joinpath(*TRACE_RELATIVE.parts)
    if verified_payload is None:
        payload = stable_read(
            path,
            label="exact release runtime-open parser",
            expected_uid=0 if enforce_root and os.name == "posix" else None,
            expected_gid=0 if enforce_root and os.name == "posix" else None,
            allowed_modes=(
                frozenset({0o444})
                if enforce_root and os.name == "posix"
                else None
            ),
        )
    elif type(verified_payload) is bytes:
        payload = verified_payload
    else:
        raise EvidenceVerificationError("runtime-open parser payload is invalid")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise EvidenceVerificationError("runtime-open parser digest differs")
    name = "_dev29_independent_runtime_open_trace"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(payload, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    if Path(module.__file__).resolve(strict=True) != path.resolve(strict=True):
        raise EvidenceVerificationError("runtime-open parser escaped the release")
    return module


def _load_private_runtime_trace_sidecar(
    evidence_name: str,
    expected_release: str,
    summary: Mapping[str, Any],
    required_targets: Sequence[str],
    *,
    enforce_root: bool = True,
) -> dict[str, dict[str, Any]]:
    if (
        type(summary) is not dict
        or set(summary)
        != {
            "schema_version",
            "manifest_sha256",
            "trace_count",
            "tree_identity_sha256",
            "production_promotion_allowed",
        }
        or type(summary.get("schema_version")) is not int
        or summary["schema_version"] != 1
        or not isinstance(summary.get("manifest_sha256"), str)
        or HEX64.fullmatch(summary["manifest_sha256"]) is None
        or type(summary.get("trace_count")) is not int
        or summary["trace_count"] != len(required_targets)
        or not isinstance(summary.get("tree_identity_sha256"), str)
        or HEX64.fullmatch(summary["tree_identity_sha256"]) is None
        or summary.get("production_promotion_allowed") is not False
    ):
        raise EvidenceVerificationError("private runtime-open summary is invalid")
    sidecar = PRIVATE_EVIDENCE_PARENT / evidence_name
    if enforce_root and os.name == "posix":
        _safe_root_chain(sidecar, final_mode=0o700)
    payload = stable_read(
        sidecar / "MANIFEST.json",
        label="private runtime-open manifest",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o400})
            if enforce_root and os.name == "posix"
            else None
        ),
    )
    if hashlib.sha256(payload).hexdigest() != summary["manifest_sha256"]:
        raise EvidenceVerificationError("private runtime-open manifest digest mismatch")
    document = parse_json(
        payload, label="private runtime-open manifest", canonical=True
    )
    entries = document.get("entries")
    if (
        set(document)
        != {
            "schema_version",
            "sidecar_type",
            "release",
            "evidence_name",
            "entries",
            "production_promotion_allowed",
        }
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or document.get("sidecar_type")
        != "odoo-accounting-cli-v3.dev29.private-runtime-open.v1"
        or document.get("evidence_name") != evidence_name
        or document.get("release") != expected_release
        or document.get("production_promotion_allowed") is not False
        or type(entries) is not list
        or [item.get("target_id") for item in entries if type(item) is dict]
        != list(required_targets)
    ):
        raise EvidenceVerificationError("private runtime-open manifest is invalid")
    expected_members = {"MANIFEST.json"} | {
        f"{target_id}.strace" for target_id in required_targets
    }
    observed_members = {child.name for child in os.scandir(sidecar)}
    if observed_members != expected_members:
        raise EvidenceVerificationError(
            "private runtime-open sidecar member set is invalid"
        )
    indexed: dict[str, dict[str, Any]] = {}
    identity_rows: list[dict[str, Any]] = []
    for entry in entries:
        target_id = entry.get("target_id") if type(entry) is dict else None
        expected_path = sidecar / f"{target_id}.strace"
        if (
            type(entry) is not dict
            or set(entry)
            != {
                "target_id",
                "manifest_sha256",
                "expected_leader_pid",
                "path",
                "device",
                "inode",
                "size",
                "mode",
                "sha256",
            }
            or entry.get("path") != str(expected_path)
            or entry.get("mode") != "0400"
            or type(entry.get("expected_leader_pid")) is not int
            or entry["expected_leader_pid"] <= 1
            or any(type(entry.get(field)) is not int or entry[field] < 0 for field in ("device", "inode", "size"))
            or entry["inode"] <= 0
            or not isinstance(entry.get("sha256"), str)
            or HEX64.fullmatch(entry["sha256"]) is None
        ):
            raise EvidenceVerificationError("private runtime-open trace entry is invalid")
        metadata = expected_path.lstat()
        payload = stable_read(
            expected_path,
            label=f"private runtime-open trace {target_id}",
            maximum=128 * 1024 * 1024,
            expected_uid=0 if enforce_root and os.name == "posix" else None,
            expected_gid=0 if enforce_root and os.name == "posix" else None,
            allowed_modes=(
                frozenset({0o400})
                if enforce_root and os.name == "posix"
                else None
            ),
        )
        if (
            (metadata.st_dev, metadata.st_ino, metadata.st_size)
            != (entry["device"], entry["inode"], entry["size"])
            or hashlib.sha256(payload).hexdigest() != entry["sha256"]
        ):
            raise EvidenceVerificationError("private runtime-open raw identity drifted")
        indexed[target_id] = entry
        identity_rows.append(
            {
                key: entry[key]
                for key in ("target_id", "device", "inode", "size", "sha256")
            }
        )
    if hashlib.sha256(canonical_json(identity_rows)).hexdigest() != summary[
        "tree_identity_sha256"
    ]:
        raise EvidenceVerificationError("private runtime-open tree identity differs")
    return indexed


def validate_runtime_open_trace(
    documents: Mapping[str, bytes],
    bundle_manifest: Mapping[str, Any],
    expected: Mapping[str, str],
    *,
    root: Path,
    release_manifest: Mapping[str, Any],
    expected_index_sha256: str,
    expected_strace_sha256: str,
) -> dict[str, Any]:
    receipt_set = parse_json(
        documents["runtime-open-trace.json"],
        label="bundle runtime-open trace receipts",
        canonical=True,
    )
    if (
        bundle_manifest.get("runtime_open_trace_sha256")
        != hashlib.sha256(documents["runtime-open-trace.json"]).hexdigest()
    ):
        raise EvidenceVerificationError("bundle runtime-open trace digest is invalid")
    index, targets, runtime_payload = _read_runtime_trace_index(
        expected,
        root=root,
        release_manifest=release_manifest,
        expected_sha256=expected_index_sha256,
        expected_strace_sha256=expected_strace_sha256,
    )
    receipts = receipt_set.get("receipts")
    private_summary = receipt_set.get("private_sidecar")
    if (
        set(receipt_set)
        != {
            "schema_version",
            "scope",
            "release",
            "index_sha256",
            "expected_strace_sha256",
            "expected_static_closure_sha256",
            "policy_source_sha256",
            "runtime_module_sha256",
            "release_manifest_sha256",
            "receipts",
            "private_sidecar",
            "production_promotion_allowed",
        }
        or type(receipt_set.get("schema_version")) is not int
        or receipt_set["schema_version"] != 1
        or receipt_set.get("scope")
        != "odoo-accounting-cli-v3.dev29.runtime-open-receipts.v1"
        or receipt_set.get("release") != expected["release"]
        or receipt_set.get("index_sha256") != expected_index_sha256
        or receipt_set.get("expected_strace_sha256") != expected_strace_sha256
        or receipt_set.get("expected_static_closure_sha256")
        != index["expected_static_closure_sha256"]
        or receipt_set.get("policy_source_sha256")
        != index["policy_source_sha256"]
        or receipt_set.get("runtime_module_sha256")
        != index["runtime_module_sha256"]
        or receipt_set.get("release_manifest_sha256")
        != index["release_manifest_sha256"]
        or receipt_set.get("production_promotion_allowed") is not False
        or type(receipts) is not list
        or [item.get("target_id") for item in receipts if type(item) is dict]
        != list(suite_runtime_trace_targets())
    ):
        raise EvidenceVerificationError("runtime-open trace receipt set is invalid")
    if bundle_manifest.get("runtime_open_trace_private") != private_summary:
        raise EvidenceVerificationError("bundle private runtime-open binding differs")
    private_entries = _load_private_runtime_trace_sidecar(
        Path(bundle_manifest["evidence_path"]).name,
        expected["release"],
        private_summary,
        suite_runtime_trace_targets(),
    )
    runtime_trace = _load_runtime_trace_module(
        root,
        expected_sha256=index["runtime_module_sha256"],
        verified_payload=runtime_payload,
    )
    receipt_fields = {
        "schema_version",
        "scope",
        "target_id",
        "role",
        "manifest_sha256",
        "policy_sha256",
        "watch_roots_sha256",
        "child_environment_sha256",
        "static_closure_sha256",
        "dynamic_namespace_receipt_sha256",
        "canonical_path_count",
        "canonical_path_set_sha256",
        "trace_sha256",
        "production_promotion_allowed",
    }
    dynamic: set[str] = set()
    for receipt in receipts:
        target_id = receipt.get("target_id") if type(receipt) is dict else None
        if target_id not in targets:
            raise EvidenceVerificationError("runtime-open trace target is unknown")
        manifest, policy_sha256 = _validate_runtime_trace_manifest(
            target_id, targets[target_id], index, expected
        )
        request = runtime_trace.TraceRequest(
            release=expected["release"],
            target_id=target_id,
            expected_manifest_sha256=targets[target_id]["manifest_sha256"],
            expected_strace_sha256=expected_strace_sha256,
            expected_static_closure_sha256=index[
                "expected_static_closure_sha256"
            ],
            expected_child_environment_sha256=targets[target_id][
                "child_environment_sha256"
            ],
            expected_watch_roots_sha256=targets[target_id][
                "watch_roots_sha256"
            ],
        )
        parsed_manifest, _identity = runtime_trace.load_trace_manifest(request)
        raw_entry = private_entries[target_id]
        reparsed = runtime_trace.validate_trace_file(
            Path(raw_entry["path"]),
            parsed_manifest,
            expected_leader_pid=raw_entry["expected_leader_pid"],
        )
        if (
            set(receipt) != receipt_fields
            or type(receipt.get("schema_version")) is not int
            or receipt["schema_version"] != 1
            or receipt.get("scope") != TRACE_MANIFEST_SCOPE
            or receipt.get("role") != manifest["role"]
            or receipt.get("manifest_sha256") != targets[target_id]["manifest_sha256"]
            or receipt.get("policy_sha256") != policy_sha256
            or receipt.get("watch_roots_sha256")
            != targets[target_id]["watch_roots_sha256"]
            or receipt.get("child_environment_sha256")
            != targets[target_id]["child_environment_sha256"]
            or receipt.get("static_closure_sha256")
            != index["expected_static_closure_sha256"]
            or not isinstance(receipt.get("dynamic_namespace_receipt_sha256"), str)
            or HEX64.fullmatch(receipt["dynamic_namespace_receipt_sha256"]) is None
            or type(receipt.get("canonical_path_count")) is not int
            or receipt["canonical_path_count"] <= 0
            or any(
                not isinstance(receipt.get(field), str)
                or HEX64.fullmatch(receipt[field]) is None
                for field in (
                    "canonical_path_set_sha256",
                    "trace_sha256",
                )
            )
            or receipt.get("production_promotion_allowed") is not False
            or reparsed.document()
            != {
                "canonical_path_count": receipt["canonical_path_count"],
                "canonical_path_set_sha256": receipt[
                    "canonical_path_set_sha256"
                ],
                "trace_sha256": receipt["trace_sha256"],
            }
            or raw_entry["sha256"] != receipt["trace_sha256"]
        ):
            raise EvidenceVerificationError("runtime-open trace receipt is invalid")
        dynamic.add(receipt["dynamic_namespace_receipt_sha256"])
    if len(dynamic) != 1:
        raise EvidenceVerificationError("runtime-open dynamic namespace changed during suite")
    return {
        "index_sha256": expected_index_sha256,
        "receipt_sha256": hashlib.sha256(
            documents["runtime-open-trace.json"]
        ).hexdigest(),
        "trace_count": len(receipts),
        "policy_source_sha256": index["policy_source_sha256"],
        "runtime_module_sha256": index["runtime_module_sha256"],
        "release_manifest_sha256": index["release_manifest_sha256"],
        "dynamic_namespace_receipt_sha256": next(iter(dynamic)),
        "private_sidecar": private_summary,
        "raw_traces_independently_reparsed": True,
        "all_checks_passed": True,
        "production_promotion_allowed": False,
    }


def verify_bundle(
    evidence: Path,
    *,
    expected: dict[str, str],
    expected_bundle_manifest_sha256: str,
    root: Path,
    release_manifest: dict[str, Any],
    runtime: dict[str, Any],
    runtime_bytes: bytes,
    auth_secret: bytes,
    receipt_secret: bytes,
    expected_closure_anchor_sha256: str,
    expected_closure_image_sha256: str,
    expected_system_python_sha256: str,
    expected_loader_preload_sha256: str,
    expected_ldconfig_sha256: str,
    expected_runtime_trace_index_sha256: str,
    expected_strace_sha256: str,
    verify_live_closure: bool,
) -> dict[str, Any]:
    documents, bundle_manifest, bundle_manifest_sha256 = load_bundle(
        evidence,
        expected=expected,
        expected_bundle_manifest_sha256=expected_bundle_manifest_sha256,
    )
    runtime_open_trace = validate_runtime_open_trace(
        documents,
        bundle_manifest,
        expected,
        root=root,
        release_manifest=release_manifest,
        expected_index_sha256=expected_runtime_trace_index_sha256,
        expected_strace_sha256=expected_strace_sha256,
    )
    release_plan_bytes = stable_read(
        root.joinpath(*PLAN_RELATIVE.parts),
        label="exact release Dev29 plan",
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
    )
    if documents["read-plan.json"] != release_plan_bytes:
        raise EvidenceVerificationError("bundle plan differs from the exact release plan")
    plan = parse_json(documents["read-plan.json"], label="bundle read plan")
    cases, _negatives = validate_plan(plan)
    if documents["runtime.json"] != runtime_bytes:
        raise EvidenceVerificationError("bundle runtime differs from the live sealed runtime")
    bundled_runtime = parse_json(documents["runtime.json"], label="bundle runtime")
    if bundled_runtime != runtime:
        raise EvidenceVerificationError("bundle runtime semantics drifted")
    validate_runtime(runtime, plan=plan, expected=expected, verify_live_files=verify_live_closure)
    if (
        bundle_manifest.get("plan_sha256")
        != hashlib.sha256(release_plan_bytes).hexdigest()
        or bundle_manifest.get("runtime_sha256") != hashlib.sha256(runtime_bytes).hexdigest()
        or _json(documents, "expected-release.json") != expected
    ):
        raise EvidenceVerificationError("bundle plan/runtime/release binding is invalid")

    release_summary = _verified_release_summary(root, release_manifest, expected)
    if (
        _json(documents, "verified-release-pre.json") != release_summary
        or _json(documents, "verified-release-post.json") != release_summary
    ):
        raise EvidenceVerificationError("bundle release verification drifted")
    _exit(documents, "release/identity.exit", 0)
    if documents["release/identity.stderr"]:
        raise EvidenceVerificationError("release identity command emitted stderr")
    release_response = parse_json(
        documents["release/identity.stdout"],
        label="release identity stdout",
        canonical=True,
    )
    release_identity = release_response.get("data") if type(release_response) is dict else None
    registry_path = root / "registry" / "capabilities.json"
    registry_digest = independent_registry_digest(registry_path)
    expected_release_identity = {
        **expected,
        "registry_digest": registry_digest,
        "verified": True,
    }
    if (
        set(release_response) != {"command", "data", "ok"}
        or release_response.get("command") != "release.identity"
        or release_response.get("ok") is not True
        or release_identity != expected_release_identity
        or bundle_manifest.get("release_identity") != expected_release_identity
    ):
        raise EvidenceVerificationError("exact release CLI identity is invalid")

    for phase in ("pre", "post"):
        _exit(documents, f"closure/verify-{phase}.exit", 0)
        if documents[f"closure/verify-{phase}.stderr"]:
            raise EvidenceVerificationError(f"closure {phase} verification emitted stderr")
    if documents["closure/verify-pre.stdout"] != documents["closure/verify-post.stdout"]:
        raise EvidenceVerificationError("closure verification changed during the suite")
    closure = parse_json(
        documents["closure/verify-pre.stdout"],
        label="closure verification stdout",
        canonical=True,
    )
    validate_closure_document(
        closure,
        runtime=runtime,
        plan=plan,
        expected=expected,
        expected_closure_anchor_sha256=expected_closure_anchor_sha256,
        expected_closure_image_sha256=expected_closure_image_sha256,
        expected_system_python_sha256=expected_system_python_sha256,
        expected_loader_preload_sha256=expected_loader_preload_sha256,
        verify_live_files=verify_live_closure,
    )
    mount_pre = _json(documents, "closure/mount-pre.json")
    mount_post = _json(documents, "closure/mount-post.json")
    validate_mount_binding_document(mount_pre, closure=closure)
    if mount_post != mount_pre:
        raise EvidenceVerificationError("closure mount binding changed during the suite")
    if verify_live_closure and current_mount_binding(closure) != mount_post:
        raise EvidenceVerificationError("live closure mount binding drifted")
    if (
        bundle_manifest.get("closure_identity") != closure["closure_identity"]
        or bundle_manifest.get("closure_verification_sha256")
        != hashlib.sha256(documents["closure/verify-pre.stdout"]).hexdigest()
    ):
        raise EvidenceVerificationError("bundle closure identity is invalid")
    addons_document = _json(documents, "closure/addons-paths.json")
    validate_addons_document(
        addons_document,
        closure=closure,
        runtime=runtime,
        verify_live_file=verify_live_closure,
    )
    external_runtime = validate_external_runtime_manifest(
        closure,
        verify_live_files=verify_live_closure,
        expected_ldconfig_sha256=expected_ldconfig_sha256,
    )
    if (
        _json(documents, "closure/external-runtime-pre.json") != external_runtime
        or _json(documents, "closure/external-runtime-post.json") != external_runtime
    ):
        raise EvidenceVerificationError("external runtime identity changed during the suite")
    closure_python_pre = _json(documents, "closure/python-pre.json")
    closure_python_post = _json(documents, "closure/python-post.json")
    _validate_closure_python(
        closure_python_pre,
        expected_sha256=expected_system_python_sha256,
    )
    if closure_python_post != closure_python_pre:
        raise EvidenceVerificationError("closure verification Python changed during the suite")
    if verify_live_closure:
        digest, metadata = _stream_sha256(
            Path(CLOSURE_PYTHON), label="closure verification Python"
        )
        if (
            digest != closure_python_post["sha256"]
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or Path(CLOSURE_PYTHON).is_symlink()
            or Path(CLOSURE_PYTHON).resolve(strict=True) != Path(CLOSURE_PYTHON)
            or Path(sys.executable).resolve(strict=True) != Path(CLOSURE_PYTHON)
            or Path("/proc/self/exe").resolve(strict=True) != Path(CLOSURE_PYTHON)
            or sys.flags.isolated != 1
            or sys.flags.no_site != 1
        ):
            raise EvidenceVerificationError("live closure verification Python drifted")

    if not verify_live_closure:
        raise EvidenceVerificationError(
            "direct child evidence requires independent live closure verification"
        )
    expected_child_mounts = _current_child_mounts(closure)
    live_cgroup = _current_unit_cgroup_identity()
    for artifact, role in _child_artifact_roles().items():
        _validate_child_attestation(
            _json(documents, f"{artifact}.child.json"),
            role=role,
            artifact=artifact,
            root=root,
            runtime=runtime,
            expected=expected,
            closure=closure,
            expected_mounts=expected_child_mounts,
        )
        _validate_process_control(
            _json(documents, f"{artifact}.process-control.json"),
            live_cgroup=live_cgroup,
        )

    outer_unit = _json(documents, "outer-unit.json")
    validate_outer_unit(
        outer_unit,
        runtime=runtime,
        release=expected["release"],
    )
    validate_sandbox_profile(
        _json(documents, "sandbox-profile.json"),
        runtime=runtime,
        release=expected["release"],
        closure=closure,
        outer_unit=outer_unit,
    )
    system_pre = _json(documents, "system-pre.json")
    system_post = _json(documents, "system-post.json")
    validate_system_continuity(
        system_pre,
        system_post,
        plan=plan,
        runtime=runtime,
    )
    dependency_pre = _json(documents, "dependency-pre.json")
    dependency_post = _json(documents, "dependency-post.json")
    validate_dependency_document(
        dependency_pre,
        runtime=runtime,
        expected=expected,
        closure=closure,
        external_runtime_paths=external_runtime["derived_roots"],
        verify_live_files=verify_live_closure,
    )
    if dependency_post != dependency_pre:
        raise EvidenceVerificationError("dependency identity changed during the suite")
    dependency_root_paths = {item["root"] for item in dependency_pre["roots"]}
    if not set(closure["closure_identity"]["external_runtime_paths"]).issubset(
        dependency_root_paths
    ):
        raise EvidenceVerificationError("external runtime was not fully dependency-watched")
    dependency_watch = _json(documents, "dependency-watch.json")
    expected_watch_roots = [item["root"] for item in dependency_pre["roots"]]
    if (
        set(dependency_watch)
        != {
            "schema_version",
            "backend",
            "watch_count",
            "reject_mask",
            "roots",
            "root_identities",
            "events_observed",
            "all_checks_passed",
        }
        or not _schema_version_is_one(
            dependency_watch.get("schema_version")
        )
        or dependency_watch.get("backend") != "linux-inotify-recursive"
        or type(dependency_watch.get("watch_count")) is not int
        or dependency_watch["watch_count"] < len(expected_watch_roots)
        or type(dependency_watch.get("reject_mask")) is not int
        or dependency_watch["reject_mask"] <= 0
        or dependency_watch.get("roots") != expected_watch_roots
        or type(dependency_watch.get("root_identities")) is not list
        or [
            item.get("path") if type(item) is dict else None
            for item in dependency_watch["root_identities"]
        ]
        != expected_watch_roots
        or any(
            type(item) is not dict
            or set(item) != {"path", "device", "inode"}
            or type(item.get("device")) is not int
            or item["device"] < 0
            or type(item.get("inode")) is not int
            or item["inode"] <= 0
            for item in dependency_watch["root_identities"]
        )
        or dependency_watch.get("events_observed") != 0
        or dependency_watch.get("all_checks_passed") is not True
    ):
        raise EvidenceVerificationError("dependency inotify evidence is invalid")
    if verify_live_closure:
        live_root_identities = []
        for root_text in expected_watch_roots:
            metadata = Path(root_text).lstat()
            live_root_identities.append(
                {
                    "path": root_text,
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                }
            )
        if live_root_identities != dependency_watch["root_identities"]:
            raise EvidenceVerificationError("dependency watch root identity drifted")

    for phase in ("pre", "post"):
        _exit(documents, f"witness-{phase}.exit", 0)
        if documents[f"witness-{phase}.stderr"]:
            raise EvidenceVerificationError(f"PostgreSQL witness {phase} emitted stderr")
    if documents["witness-pre.stdout"] != documents["witness-post.stdout"]:
        raise EvidenceVerificationError("PostgreSQL witness changed during the suite")
    witness = parse_json(
        documents["witness-pre.stdout"], label="PostgreSQL witness", canonical=True
    )
    validate_witness(witness, plan=plan, runtime=runtime)
    _exit(documents, "boundary/probe.exit", 0)
    if documents["boundary/probe.stderr"]:
        raise EvidenceVerificationError("D11 probe emitted stderr")
    boundary = parse_json(
        documents["boundary/probe.stdout"], label="D11 probe stdout", canonical=True
    )
    validate_boundary_response(
        boundary, runtime=runtime, release_identity=expected_release_identity
    )

    suite = _json(documents, "suite.json")
    started = _datetime(suite.get("started_at"), label="suite started_at")
    finished = _datetime(suite.get("finished_at"), label="suite finished_at")
    if finished < started:
        raise EvidenceVerificationError("suite observation window is invalid")

    requests, receipts, oracle_reports = _verify_positive_artifacts(
        documents,
        cases=cases,
        runtime=runtime,
        release_identity=expected_release_identity,
        auth_secret=auth_secret,
        receipt_secret=receipt_secret,
        plan=plan,
        witness=witness,
    )
    negative_reports = _verify_negative_artifacts(
        documents,
        plan,
        runtime,
        requests,
        auth_secret,
    )
    validate_expired_negative_time(
        requests["expired"], suite_started_at=suite["started_at"]
    )
    token_ids = {
        name: request["context"]["auth_token_id"] for name, request in requests.items()
    }
    receipt_ids = {name: receipt["id"] for name, receipt in receipts.items()}
    if (
        bundle_manifest.get("auth_token_ids") != dict(sorted(token_ids.items()))
        or bundle_manifest.get("receipt_ids") != dict(sorted(receipt_ids.items()))
    ):
        raise EvidenceVerificationError("bundle request/receipt identity map is invalid")
    state_pre = _json(documents, "state-pre.json")
    state_post = _json(documents, "state-post.json")
    state_delta = validate_state_delta(
        state_pre,
        state_post,
        requests=requests,
        receipts=receipts,
        runtime=runtime,
        suite_started_at=suite["started_at"],
        observed_not_after=suite["finished_at"],
    )
    if _json(documents, "state-delta.json") != state_delta:
        raise EvidenceVerificationError("bundle SQLite state delta evidence drifted")

    expected_negative_suite = {
        name: {
            "logical_error": report["logical_error"],
            "cli_error": report["cli_error"],
            "rejection_code": report["rejection_code"],
            "exit_code": report["exit_code"],
            "stdout_empty": True,
            "receipt_absent": True,
            "business_result_absent": True,
        }
        for name, report in negative_reports.items()
    }
    expected_suite_fields = {
        "schema_version",
        "suite",
        "started_at",
        "finished_at",
        "release_identity",
        "positive_cases",
        "financial_oracles",
        "negative_cases",
        "d11_read_boundary_passed",
        "postgresql_witness_unchanged",
        "system_identity_unchanged",
        "dependency_identity_unchanged",
        "odoo_closure_verified",
        "odoo_closure_unchanged",
        "addons_paths_covered_by_read_only_binds",
        "external_runtime_identity_unchanged",
        "closure_mount_binding_unchanged",
        "state_delta_verified",
        "sandbox_profile_enforced",
        "runtime_open_trace_verified",
        "runtime_open_trace_sha256",
        "odoo_business_writes_permitted",
        "production_promotion_allowed",
    }
    if (
        set(suite) != expected_suite_fields
        or not _schema_version_is_one(suite.get("schema_version"))
        or suite.get("suite") != "odoo-accounting-cli-v3.dev29.real-read-gate"
        or finished < started
        or suite.get("release_identity") != expected_release_identity
        or suite.get("positive_cases")
        != {name: {"passed": True} for name in POSITIVE_NAMES}
        or suite.get("financial_oracles")
        != {
            name: {
                "passed": oracle_reports[name]["all_checks_passed"],
                "fixture_gaps": oracle_reports[name]["fixture_gaps"],
            }
            for name in FINANCIAL_NAMES
        }
        or suite.get("negative_cases") != expected_negative_suite
        or any(
            suite.get(field) is not True
            for field in (
                "d11_read_boundary_passed",
                "postgresql_witness_unchanged",
                "system_identity_unchanged",
                "dependency_identity_unchanged",
                "odoo_closure_verified",
                "odoo_closure_unchanged",
                "addons_paths_covered_by_read_only_binds",
                "external_runtime_identity_unchanged",
                "closure_mount_binding_unchanged",
                "state_delta_verified",
                "sandbox_profile_enforced",
                "runtime_open_trace_verified",
            )
        )
        or suite.get("runtime_open_trace_sha256")
        != runtime_open_trace["receipt_sha256"]
        or suite.get("odoo_business_writes_permitted") is not False
        or suite.get("production_promotion_allowed") is not False
    ):
        raise EvidenceVerificationError("suite conclusion evidence is invalid")
    assert_no_secret_leak(documents, (auth_secret, receipt_secret))
    return {
        "schema_version": 1,
        "suite": suite["suite"],
        "release_identity": expected_release_identity,
        "closure_identity": closure["closure_identity"],
        "closure_verification": closure,
        "closure_verification_sha256": hashlib.sha256(
            canonical_json(closure)
        ).hexdigest(),
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "positive_case_count": len(POSITIVE_NAMES),
        "financial_oracle_count": len(FINANCIAL_NAMES),
        "negative_case_count": len(NEGATIVE_NAMES),
        "receipt_count": len(receipts),
        "d11_read_boundary_verified": True,
        "postgresql_witness_verified": True,
        "system_identity_unchanged": True,
        "dependency_identity_unchanged": True,
        "state_and_audit_chain_verified": True,
        "exact_release_core_receipts_verified": True,
        "odoo_closure_verified": True,
        "external_runtime_manifest_verified": True,
        "closure_mount_binding_verified": True,
        "direct_child_evidence_verified": True,
        "unit_cgroup_descendants_absent": True,
        "outer_systemd_unit_verified": True,
        "runtime_open_trace_verified": True,
        "runtime_open_trace": runtime_open_trace,
        "all_checks_passed": True,
        "production_promotion_allowed": False,
    }


def _private_secret(path: Path, *, service_gid: int) -> bytes:
    value = stable_read(
        path,
        label=f"Dev29 runtime secret {path.name}",
        maximum=4096,
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=service_gid if os.name == "posix" else None,
        allowed_modes=frozenset({0o640}) if os.name == "posix" else None,
    )
    if len(value) != 32:
        raise EvidenceVerificationError("Dev29 runtime secret length is invalid")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--expected-bundle-manifest-sha256", required=True)
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument("--expected-closure-anchor-sha256", required=True)
    parser.add_argument("--expected-closure-image-sha256", required=True)
    parser.add_argument("--expected-system-python-sha256", required=True)
    parser.add_argument("--expected-ld-so-preload-sha256", required=True)
    parser.add_argument("--expected-ldconfig-sha256", required=True)
    parser.add_argument("--expected-runtime-open-index-sha256", required=True)
    parser.add_argument("--expected-strace-sha256", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    if os.name != "posix" or sys.flags.isolated != 1 or sys.flags.no_site != 1:
        print(
            "Dev29 evidence verification refused: fixed /usr/bin/python3.12 -I -S is required",
            file=sys.stderr,
        )
        return 2
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        if arguments.validate_only is not True:
            raise EvidenceVerificationError("Dev29 verifier requires --validate-only")
        if os.name != "posix" or os.geteuid() != 0:
            raise EvidenceVerificationError("Dev29 evidence verifier must run as root on POSIX")
        import grp

        expected = _expected_identity(
            arguments.expected_release,
            arguments.expected_version,
            arguments.expected_commit,
            arguments.expected_manifest_sha256,
            arguments.expected_package_sha256,
        )
        root, release_manifest = bootstrap_verify_release(expected)
        runtime_path = RUNTIME_PARENT / f"runtime-test-{expected['release']}.json"
        service_gid = grp.getgrnam("odoo").gr_gid
        runtime_bytes = stable_read(
            runtime_path,
            label="live sealed Dev29 runtime",
            expected_uid=0,
            expected_gid=service_gid,
            allowed_modes=frozenset({0o640}),
        )
        runtime = parse_json(runtime_bytes, label="live sealed Dev29 runtime", canonical=True)
        plan_bytes = stable_read(
            root.joinpath(*PLAN_RELATIVE.parts),
            label="exact release Dev29 plan",
            expected_uid=0,
            expected_gid=0,
            allowed_modes=frozenset({0o444}),
        )
        plan = parse_json(plan_bytes, label="exact release Dev29 plan")
        validate_plan(plan)
        validate_runtime(runtime, plan=plan, expected=expected, verify_live_files=True)
        auth_secret = _private_secret(
            Path(runtime["auth_secret_path"]), service_gid=service_gid
        )
        receipt_secret = _private_secret(
            Path(runtime["receipt_secret_path"]), service_gid=service_gid
        )
        if hmac.compare_digest(auth_secret, receipt_secret):
            raise EvidenceVerificationError("Dev29 HMAC role secrets alias")
        evidence = validate_evidence_path(arguments.evidence_dir)
        report = verify_bundle(
            evidence,
            expected=expected,
            expected_bundle_manifest_sha256=arguments.expected_bundle_manifest_sha256,
            root=root,
            release_manifest=release_manifest,
            runtime=runtime,
            runtime_bytes=runtime_bytes,
            auth_secret=auth_secret,
            receipt_secret=receipt_secret,
            expected_closure_anchor_sha256=arguments.expected_closure_anchor_sha256,
            expected_closure_image_sha256=arguments.expected_closure_image_sha256,
            expected_system_python_sha256=arguments.expected_system_python_sha256,
            expected_loader_preload_sha256=arguments.expected_ld_so_preload_sha256,
            expected_ldconfig_sha256=arguments.expected_ldconfig_sha256,
            expected_runtime_trace_index_sha256=(
                arguments.expected_runtime_open_index_sha256
            ),
            expected_strace_sha256=arguments.expected_strace_sha256,
            verify_live_closure=True,
        )
    except (EvidenceVerificationError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(f"Dev29 evidence verification refused: {exc}", file=sys.stderr)
        return 2
    print((canonical_json(report) + b"\n").decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

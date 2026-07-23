#!/usr/bin/env python3
"""Run the exact Dev29 staged read suite and freeze its evidence bundle.

This program is intentionally release-contained.  It accepts the release
identity from the operator, verifies that identity against the installed
manifest, canonical package, and external release anchor, and then executes
only the fixed ``read_plan.json`` cases.  It never routes V3 or writes Odoo
business data.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import hashlib
import json
import os
import platform
import re
import signal
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable, Iterable, Mapping, Sequence


sys.dont_write_bytecode = True

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_RELEASE_FILE_BYTES = 128 * 1024 * 1024
MAX_RELEASE_FILES = 20_000
MAX_TREE_FILES = 100_000
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
RELEASE_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
EVIDENCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
PRIVATE_EVIDENCE_PARENT = Path(
    "/var/lib/odoo-accounting-cli-v3/evidence-private"
)
ANCHOR_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence-anchors")
ORACLE_STAGING_PARENT = Path("/run/odoo-accounting-cli-v3-dev29")
RELEASE_PARENT = Path("/opt/odoo-accounting-cli-v3/releases")
PACKAGE_PARENT = Path("/opt/odoo-accounting-cli-v3/packages")
TRUSTED_ARTIFACT_PARENT = Path("/opt/odoo-accounting-cli-v3/trusted-artifacts")
CONFIG_PARENT = Path("/etc/odoo-accounting-cli-v3/candidates")
PLAN_RELATIVE = PurePosixPath("deployment/dev29/read_plan.json")
SIGNER_RELATIVE = PurePosixPath("deployment/dev29/sign_read.py")
ORACLE_RELATIVE = PurePosixPath("deployment/dev29/read_oracles.py")
RUNNER_RELATIVE = PurePosixPath("deployment/dev29/run_read_suite.py")
VERIFIER_RELATIVE = PurePosixPath("deployment/dev29/verify_read_evidence.py")
CLOSURE_RELATIVE = PurePosixPath("deployment/dev29/odoo_closure.py")
DIRECT_CHILD_RELATIVE = PurePosixPath("deployment/dev29/direct_child.py")
TRACE_RELATIVE = PurePosixPath("deployment/dev29/runtime_open_trace.py")
EXECUTABLE_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "bin/odoo-accounting-cli-v3-effect-finalizer",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)
LAUNCHER_RELATIVE = PurePosixPath("bin/odoo-accounting-cli-v3")
TRACE_INDEX_PARENT = Path("/opt/odoo-accounting-cli-v3/runtime-open-manifests")
TRACE_INDEX_NAME = "INDEX.json"
TRACE_INDEX_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-index.v1"
TRACE_POLICY_SOURCE_SCOPE = (
    "odoo-accounting-cli-v3.dev29.runtime-open-policy-source.v1"
)
TRACE_ATTESTATION_FD = 198
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
SKIP_DIRECTORIES = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".venv",
        "venv",
        "build",
        "dist",
        "tmp",
        ".tox",
        "backups",
    }
)
SKIP_SUFFIXES = ("~", ".bak", ".backup", ".orig", ".rej", ".pyc", ".pyo")
SYSTEMCTL = Path("/usr/bin/systemctl")
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
CLOSURE_PYTHON = "/usr/bin/python3.12"
CLOSURE_LDCONFIG = "/usr/sbin/ldconfig.real"
SYSTEMD_ROOTS = (
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/run/systemd/transient"),
    Path("/run/systemd/generator.early"),
    Path("/run/systemd/generator"),
    Path("/run/systemd/generator.late"),
    Path("/usr/local/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
)
SQLITE_SUFFIXES = ("", "-wal", "-shm")
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_ISDIR = 0x40000000
IN_REJECT_MASK = (
    IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_UNMOUNT
    | IN_Q_OVERFLOW
)


class ReadSuiteError(RuntimeError):
    """The fixed suite or a required evidence invariant failed closed."""


@dataclass(frozen=True)
class ExpectedIdentity:
    release: str
    version: str
    commit: str
    manifest_sha256: str
    package_sha256: str

    def validate(self) -> "ExpectedIdentity":
        if (
            not isinstance(self.release, str)
            or RELEASE_NAME.fullmatch(self.release) is None
            or not isinstance(self.version, str)
            or VERSION.fullmatch(self.version) is None
            or not isinstance(self.commit, str)
            or HEX40.fullmatch(self.commit) is None
            or not isinstance(self.manifest_sha256, str)
            or HEX64.fullmatch(self.manifest_sha256) is None
            or not isinstance(self.package_sha256, str)
            or HEX64.fullmatch(self.package_sha256) is None
            or self.release != f"{self.version}-{self.commit[:12]}"
        ):
            raise ReadSuiteError("expected release identity is invalid")
        return self

    def document(self) -> dict[str, str]:
        self.validate()
        return {
            "commit": self.commit,
            "manifest_sha256": self.manifest_sha256,
            "package_sha256": self.package_sha256,
            "release": self.release,
            "version": self.version,
        }


@dataclass(frozen=True)
class ExpectedClosure:
    anchor_sha256: str
    image_sha256: str
    system_python_sha256: str
    loader_preload_sha256: str
    ldconfig_sha256: str

    def validate(self) -> "ExpectedClosure":
        if (
            not isinstance(self.anchor_sha256, str)
            or HEX64.fullmatch(self.anchor_sha256) is None
            or not isinstance(self.image_sha256, str)
            or HEX64.fullmatch(self.image_sha256) is None
            or not isinstance(self.system_python_sha256, str)
            or HEX64.fullmatch(self.system_python_sha256) is None
            or not isinstance(self.loader_preload_sha256, str)
            or HEX64.fullmatch(self.loader_preload_sha256) is None
            or not isinstance(self.ldconfig_sha256, str)
            or HEX64.fullmatch(self.ldconfig_sha256) is None
        ):
            raise ReadSuiteError("expected Odoo closure identity is invalid")
        return self


def expected_runtime_trace_targets() -> tuple[str, ...]:
    """Return every fixed direct child that must cross the runtime-open gate."""

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
    return tuple(
        target
        for target in expected_runtime_trace_targets()
        if target != "independent-verifier"
    )


def discovery_sqlite_delta_contract_sha256() -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "schema_version": 1,
                "scope": (
                    "odoo-accounting-cli-v3.dev29."
                    "runtime-open-discovery-sqlite-delta-contract.v1"
                ),
                "delta_verifier": "dev29-sqlite-state-delta-v1",
                "mutable_state_roots": [
                    "auth_state_parent",
                    "receipt_state_parent",
                    "runtime_open_trace_private_sidecar",
                ],
                "allowed_mutations": [
                    "sqlite_auth_nonce_store",
                    "sqlite_receipt_nonce_store",
                    "private_raw_trace_seal",
                ],
                "candidate_is_approval": False,
                "production_promotion_allowed": False,
            }
        )
    ).hexdigest()


def _expected_trace_role(target_id: str) -> str:
    if target_id in {"witness-pre", "witness-post"} or target_id.endswith("-oracle"):
        return "postgres"
    if target_id.endswith("-signer"):
        return "signer"
    if target_id == "independent-verifier":
        return "verifier"
    return "odoo"


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReadSuiteError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _constant(value: str) -> Any:
    raise ReadSuiteError(f"non-finite JSON number: {value}")


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
        raise ReadSuiteError("value is not canonical JSON") from exc


def _schema_version_is_one(value: Any) -> bool:
    return type(value) is int and value == 1


def _expected_release_member_mode(name: str) -> int:
    return 0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444


def load_json_bytes(
    payload: bytes,
    *,
    label: str,
    canonical: bool = False,
    allow_empty: bool = False,
) -> dict[str, Any]:
    if (
        not isinstance(payload, bytes)
        or (not payload and not allow_empty)
        or len(payload) > MAX_JSON_BYTES
    ):
        raise ReadSuiteError(f"{label} is empty or too large")
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except ReadSuiteError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReadSuiteError(f"{label} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise ReadSuiteError(f"{label} must be a JSON object")
    if canonical and payload != canonical_json(value) + b"\n":
        raise ReadSuiteError(f"{label} is not canonical JSON plus LF")
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
    allow_path_symlink: bool = False,
) -> bytes:
    path = Path(path)
    original_path = path
    link_before: os.stat_result | None = None
    if allow_path_symlink:
        try:
            link_before = path.lstat()
            path = path.resolve(strict=True)
        except OSError as exc:
            raise ReadSuiteError(f"{label} symlink cannot be resolved safely") from exc
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReadSuiteError(f"{label} cannot be opened safely") from exc
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
            raise ReadSuiteError(f"{label} metadata is invalid")
        if link_before is not None:
            try:
                link_after = original_path.lstat()
            except OSError as exc:
                raise ReadSuiteError(f"{label} symlink cannot be rechecked") from exc
            if _fingerprint(link_before) != _fingerprint(link_after):
                raise ReadSuiteError(f"{label} symlink drifted during read")
        identity = _fingerprint(before)
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ReadSuiteError(f"{label} changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or _fingerprint(os.fstat(descriptor)) != identity:
            raise ReadSuiteError(f"{label} changed during read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_runtime_trace_module(
    payload: bytes,
    path: Path,
    *,
    expected_sha256: str,
) -> ModuleType:
    """Execute only runtime-open validator bytes already bound to the index."""

    if (
        not isinstance(expected_sha256, str)
        or HEX64.fullmatch(expected_sha256) is None
        or hashlib.sha256(payload).hexdigest() != expected_sha256
    ):
        raise ReadSuiteError("runtime-open trace module digest mismatch")
    name = "_dev29_runtime_open_trace"
    module = ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        code = compile(payload, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _trace_policy_document(manifest: Any) -> list[dict[str, Any]]:
    return [
        {
            "path": item.path,
            "role": item.role,
            "classification": item.classification,
            "allowed_access": list(item.allowed_access),
            "create_suffixes": list(item.create_suffixes),
            "delta_verifier": item.delta_verifier,
            "delta_contract_sha256": item.delta_contract_sha256,
            "allow_success": item.allow_success,
            "allowed_errnos": list(item.allowed_errnos),
            "failure_guard": item.failure_guard,
        }
        for item in manifest.path_access_policy
    ]


def _crash_injection_gate(_point: str) -> None:
    """Test-only crash boundary; production deliberately performs no action."""


def _attested_child_environment_sha256(value: Any, expected_sha256: str) -> str:
    attestation = getattr(value, "dev29_attestation", None)
    child_environment = (
        attestation.get("environment") if type(attestation) is dict else None
    )
    digest = (
        hashlib.sha256(canonical_json(child_environment)).hexdigest()
        if type(child_environment) is dict
        else None
    )
    if (
        type(child_environment) is not dict
        or not isinstance(expected_sha256, str)
        or HEX64.fullmatch(expected_sha256) is None
        or digest != expected_sha256
    ):
        raise ReadSuiteError("runtime-open child environment attestation differs")
    return digest


def load_runtime_trace_index(
    expected: ExpectedIdentity,
    *,
    expected_sha256: str,
    expected_strace_sha256: str,
    enforce_root: bool = True,
) -> tuple[dict[str, Any], dict[str, dict[str, str]]]:
    if (
        not isinstance(expected_sha256, str)
        or HEX64.fullmatch(expected_sha256) is None
        or not isinstance(expected_strace_sha256, str)
        or HEX64.fullmatch(expected_strace_sha256) is None
    ):
        raise ReadSuiteError("runtime-open trace index expectation is invalid")
    path = TRACE_INDEX_PARENT / expected.release / TRACE_INDEX_NAME
    if enforce_root and os.name == "posix":
        _safe_root_chain(path.parent)
    payload = stable_read(
        path,
        label="runtime-open trace index",
        maximum=MAX_JSON_BYTES,
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o400}) if enforce_root and os.name == "posix" else None
        ),
    )
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ReadSuiteError("runtime-open trace index digest mismatch")
    document = load_json_bytes(
        payload, label="runtime-open trace index", canonical=True
    )
    if (
        set(document)
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
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
        or document.get("scope") != TRACE_INDEX_SCOPE
        or document.get("release") != expected.release
        or document.get("expected_strace_sha256") != expected_strace_sha256
        or not isinstance(document.get("expected_static_closure_sha256"), str)
        or HEX64.fullmatch(document["expected_static_closure_sha256"]) is None
        or not isinstance(document.get("policy_source_sha256"), str)
        or HEX64.fullmatch(document["policy_source_sha256"]) is None
        or not isinstance(document.get("runtime_module_sha256"), str)
        or HEX64.fullmatch(document["runtime_module_sha256"]) is None
        or not isinstance(document.get("release_manifest_sha256"), str)
        or HEX64.fullmatch(document["release_manifest_sha256"]) is None
        or document.get("production_promotion_allowed") is not False
        or type(document.get("targets")) is not list
    ):
        raise ReadSuiteError("runtime-open trace index identity is invalid")
    targets: dict[str, dict[str, str]] = {}
    ordered: list[str] = []
    for item in document["targets"]:
        if (
            type(item) is not dict
            or set(item)
            != {
                "target_id",
                "manifest_sha256",
                "watch_roots_sha256",
                "child_environment_sha256",
            }
            or not isinstance(item.get("target_id"), str)
            or EVIDENCE_NAME.fullmatch(item["target_id"]) is None
            or item["target_id"] in targets
            or not isinstance(item.get("manifest_sha256"), str)
            or HEX64.fullmatch(item["manifest_sha256"]) is None
            or not isinstance(item.get("watch_roots_sha256"), str)
            or HEX64.fullmatch(item["watch_roots_sha256"]) is None
            or not isinstance(item.get("child_environment_sha256"), str)
            or HEX64.fullmatch(item["child_environment_sha256"]) is None
        ):
            raise ReadSuiteError("runtime-open trace index target is invalid")
        ordered.append(item["target_id"])
        targets[item["target_id"]] = dict(item)
    if tuple(ordered) != expected_runtime_trace_targets():
        raise ReadSuiteError("runtime-open trace target set or order is incomplete")
    _verify_runtime_trace_policy_source(
        expected,
        document,
        targets,
        enforce_root=enforce_root,
    )
    return document, targets


def _verify_runtime_trace_policy_source(
    expected: ExpectedIdentity,
    index: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, str]],
    *,
    enforce_root: bool,
) -> str:
    """Reconstruct the approved source from the exact installed policy files."""

    parent = TRACE_INDEX_PARENT / expected.release
    if enforce_root and os.name == "posix":
        _safe_root_chain(parent, final_modes=frozenset({0o555}))
    elif parent.is_symlink() or not parent.is_dir():
        raise ReadSuiteError("runtime-open trace policy directory is unsafe")
    ordered = expected_runtime_trace_targets()
    expected_names = {TRACE_INDEX_NAME, *(f"{target_id}.json" for target_id in ordered)}
    try:
        observed_before = {entry.name for entry in os.scandir(parent)}
    except OSError as exc:
        raise ReadSuiteError("runtime-open trace policy directory cannot be read") from exc
    if observed_before != expected_names:
        raise ReadSuiteError("runtime-open trace policy file set is incomplete")
    documents: list[dict[str, Any]] = []
    for target_id in ordered:
        entry = targets[target_id]
        payload = stable_read(
            parent / f"{target_id}.json",
            label=f"runtime-open trace manifest {target_id}",
            maximum=MAX_JSON_BYTES,
            expected_uid=0 if enforce_root and os.name == "posix" else None,
            expected_gid=0 if enforce_root and os.name == "posix" else None,
            allowed_modes=(
                frozenset({0o400})
                if enforce_root and os.name == "posix"
                else None
            ),
        )
        if hashlib.sha256(payload).hexdigest() != entry["manifest_sha256"]:
            raise ReadSuiteError(
                f"runtime-open trace manifest digest mismatch: {target_id}"
            )
        document = load_json_bytes(
            payload,
            label=f"runtime-open trace manifest {target_id}",
            canonical=True,
        )
        environment = document.get("environment")
        watch_roots = document.get("watch_roots")
        child_environment_sha256 = (
            hashlib.sha256(canonical_json(environment)).hexdigest()
            if type(environment) is dict
            else None
        )
        watch_roots_sha256 = (
            hashlib.sha256(canonical_json(tuple(watch_roots))).hexdigest()
            if type(watch_roots) is list
            else None
        )
        if (
            document.get("target_id") != target_id
            or child_environment_sha256 != entry["child_environment_sha256"]
            or document.get("expected_child_environment_sha256")
            != child_environment_sha256
            or watch_roots_sha256 != entry["watch_roots_sha256"]
            or document.get("expected_watch_roots_sha256")
            != watch_roots_sha256
        ):
            raise ReadSuiteError(
                f"runtime-open trace manifest index binding differs: {target_id}"
            )
        documents.append(document)
    try:
        observed_after = {entry.name for entry in os.scandir(parent)}
    except OSError as exc:
        raise ReadSuiteError("runtime-open trace policy directory cannot be reread") from exc
    if observed_after != observed_before:
        raise ReadSuiteError("runtime-open trace policy file set changed during read")
    if enforce_root and os.name == "posix":
        _safe_root_chain(parent, final_modes=frozenset({0o555}))
    source = {
        "schema_version": 1,
        "scope": TRACE_POLICY_SOURCE_SCOPE,
        "release": index["release"],
        "expected_strace_sha256": index["expected_strace_sha256"],
        "expected_static_closure_sha256": index[
            "expected_static_closure_sha256"
        ],
        "expected_runtime_module_sha256": index["runtime_module_sha256"],
        "expected_release_manifest_sha256": index["release_manifest_sha256"],
        "targets": documents,
        "production_promotion_allowed": False,
    }
    actual_sha256 = hashlib.sha256(canonical_json(source) + b"\n").hexdigest()
    if actual_sha256 != index["policy_source_sha256"]:
        raise ReadSuiteError("runtime-open policy source digest mismatch")
    return actual_sha256


def _read_runtime_trace_release_binding(
    expected: ExpectedIdentity,
    index: Mapping[str, Any],
    *,
    enforce_root: bool = True,
) -> tuple[bytes, bytes]:
    """Bind the validator bytes to both the policy index and release manifest."""

    runtime_sha256 = index.get("runtime_module_sha256")
    release_manifest_sha256 = index.get("release_manifest_sha256")
    if (
        not isinstance(runtime_sha256, str)
        or HEX64.fullmatch(runtime_sha256) is None
        or not isinstance(release_manifest_sha256, str)
        or HEX64.fullmatch(release_manifest_sha256) is None
    ):
        raise ReadSuiteError("runtime-open release binding is invalid")
    paths = _release_paths(expected)
    if enforce_root and os.name == "posix":
        _safe_root_chain(paths["root"], final_modes=frozenset({0o555}))
    runtime_path = paths["root"].joinpath(*TRACE_RELATIVE.parts)
    runtime_payload = stable_read(
        runtime_path,
        label="runtime-open trace module",
        maximum=MAX_RELEASE_FILE_BYTES,
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o444})
            if enforce_root and os.name == "posix"
            else None
        ),
    )
    if hashlib.sha256(runtime_payload).hexdigest() != runtime_sha256:
        raise ReadSuiteError("runtime-open trace module digest mismatch")
    release_manifest_payload = stable_read(
        paths["manifest"],
        label="runtime-open release manifest",
        maximum=MAX_JSON_BYTES,
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=(
            frozenset({0o444}) if enforce_root and os.name == "posix" else None
        ),
    )
    if (
        hashlib.sha256(release_manifest_payload).hexdigest()
        != release_manifest_sha256
    ):
        raise ReadSuiteError("runtime-open release manifest digest mismatch")
    release_manifest = load_json_bytes(
        release_manifest_payload, label="runtime-open release manifest"
    )
    release_members = _manifest_index(release_manifest, expected)
    runtime_member = release_members.get(str(TRACE_RELATIVE))
    if (
        type(runtime_member) is not dict
        or runtime_member.get("sha256") != runtime_sha256
        or runtime_member.get("size") != len(runtime_payload)
    ):
        raise ReadSuiteError(
            "runtime-open trace module is not exactly bound by release manifest"
        )
    return runtime_payload, release_manifest_payload


class RuntimeTraceGate:
    """Execute and bind each fixed direct child to its external trace policy."""

    def __init__(
        self,
        expected: ExpectedIdentity,
        *,
        expected_index_sha256: str,
        expected_strace_sha256: str,
        private_sidecar: Path,
    ) -> None:
        self.expected = expected
        self.index_sha256 = expected_index_sha256
        self.index, self.targets = load_runtime_trace_index(
            expected,
            expected_sha256=expected_index_sha256,
            expected_strace_sha256=expected_strace_sha256,
            enforce_root=True,
        )
        runtime_payload, _release_manifest_payload = (
            _read_runtime_trace_release_binding(
                expected,
                self.index,
                enforce_root=True,
            )
        )
        runtime_path = _release_paths(expected)["root"].joinpath(
            *TRACE_RELATIVE.parts
        )
        self.module = _load_runtime_trace_module(
            runtime_payload,
            runtime_path,
            expected_sha256=self.index["runtime_module_sha256"],
        )
        self.receipts: list[dict[str, Any]] = []
        self.consumed: set[str] = set()
        self.private_sidecar = Path(private_sidecar)
        self.private_entries: list[dict[str, Any]] = []

    def __enter__(self) -> "RuntimeTraceGate":
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        return None

    def manifest(self, target_id: str, bootstrap: Sequence[str], final: Sequence[str]) -> Any:
        if (
            target_id not in self.targets
            or target_id in self.consumed
        ):
            raise ReadSuiteError("runtime-open trace target state is invalid")
        entry = self.targets[target_id]
        request = self.module.TraceRequest(
            release=self.expected.release,
            target_id=target_id,
            expected_manifest_sha256=entry["manifest_sha256"],
            expected_strace_sha256=self.index["expected_strace_sha256"],
            expected_static_closure_sha256=self.index[
                "expected_static_closure_sha256"
            ],
            expected_child_environment_sha256=entry[
                "child_environment_sha256"
            ],
            expected_watch_roots_sha256=entry["watch_roots_sha256"],
        )
        template, _identity = self.module.load_trace_manifest(request)
        if template.target_id != target_id:
            raise ReadSuiteError("runtime-open trace manifest argv binding differs")
        try:
            return self.module.materialize_bootstrap_template(
                template, tuple(bootstrap), tuple(final)
            )
        except self.module.RuntimeOpenTraceError as exc:
            raise ReadSuiteError(
                "runtime-open trace manifest argv binding differs"
            ) from exc

    def record(
        self,
        target_id: str,
        manifest: Any,
        guard: Any,
        result: Any,
        private_identity: Mapping[str, Any],
        *,
        expected_leader_pid: int,
        child_environment_sha256: str,
    ) -> None:
        if target_id in self.consumed or result.production_promotion_allowed is not False:
            raise ReadSuiteError("runtime-open trace receipt state is invalid")
        environment = guard.receipt()
        receipt = {
            "schema_version": 1,
            "scope": self.module.SCOPE,
            "target_id": target_id,
            "role": manifest.role,
            "manifest_sha256": manifest.manifest_sha256,
            "policy_sha256": hashlib.sha256(
                canonical_json(_trace_policy_document(manifest))
            ).hexdigest(),
            "watch_roots_sha256": hashlib.sha256(
                canonical_json(manifest.watch_roots)
            ).hexdigest(),
            "child_environment_sha256": child_environment_sha256,
            **environment,
            **result.document(),
            "production_promotion_allowed": False,
        }
        self.receipts.append(receipt)
        self.private_entries.append(
            {
                "target_id": target_id,
                "manifest_sha256": manifest.manifest_sha256,
                "expected_leader_pid": expected_leader_pid,
                **dict(private_identity),
            }
        )
        self.consumed.add(target_id)

    def execute(
        self,
        target_id: str,
        bootstrap: Sequence[str],
        final: Sequence[str],
        *,
        inherited_fds: Sequence[int],
        callback: Callable[[subprocess.Popen[bytes]], Any],
    ) -> Any:
        manifest = self.manifest(target_id, bootstrap, final)
        process: subprocess.Popen[bytes] | None = None
        with self.module.validate_strace_tool(
            self.index["expected_strace_sha256"]
        ) as trusted_strace:
            with self.module.PrivateTraceStaging(
                target_id,
                parent=self.private_sidecar / ".trace-staging",
            ) as staging:
                with self.module.RuntimeEnvironmentGuard(manifest) as guard:
                    try:
                        process = self.module.launch_traced_process(
                            staging.path,
                            manifest,
                            trusted_strace,
                            inherited_fds=inherited_fds,
                            stdin=subprocess.PIPE,
                        )
                        self.module.verify_and_release_traced_process(
                            process.pid,
                            trusted_strace,
                            manifest,
                            supervisor_pid=os.getpid(),
                            timeout_seconds=5.0,
                        )
                        value = callback(process)
                        child_environment_sha256 = (
                            _attested_child_environment_sha256(
                                value,
                                manifest.expected_child_environment_sha256,
                            )
                        )
                        guard.finish()
                        staging.assert_private_identity()
                        result = self.module.validate_trace_file(
                            staging.path,
                            manifest,
                            expected_leader_pid=process.pid,
                            expected_mode=0o600,
                        )
                        self.module.reverify_trace_result(result, manifest)
                        private_identity = staging.seal_to(
                            self.private_sidecar / f"{target_id}.strace",
                            target_id=target_id,
                            manifest_sha256=manifest.manifest_sha256,
                            expected_leader_pid=process.pid,
                        )
                        self.record(
                            target_id,
                            manifest,
                            guard,
                            result,
                            private_identity,
                            expected_leader_pid=process.pid,
                            child_environment_sha256=child_environment_sha256,
                        )
                        return value
                    except BaseException:
                        if process is not None and process.poll() is None:
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                process.kill()
                            try:
                                process.communicate(timeout=5)
                            except (OSError, subprocess.TimeoutExpired):
                                pass
                        raise

    def document(self, required_targets: Sequence[str]) -> dict[str, Any]:
        if tuple(item["target_id"] for item in self.receipts) != tuple(required_targets):
            raise ReadSuiteError("runtime-open trace receipt set or order is incomplete")
        return {
            "schema_version": 1,
            "scope": "odoo-accounting-cli-v3.dev29.runtime-open-receipts.v1",
            "release": self.expected.release,
            "index_sha256": self.index_sha256,
            "expected_strace_sha256": self.index["expected_strace_sha256"],
            "expected_static_closure_sha256": self.index[
                "expected_static_closure_sha256"
            ],
            "policy_source_sha256": self.index["policy_source_sha256"],
            "runtime_module_sha256": self.index["runtime_module_sha256"],
            "release_manifest_sha256": self.index[
                "release_manifest_sha256"
            ],
            "receipts": list(self.receipts),
            "production_promotion_allowed": False,
        }

    def seal_private_manifest(
        self, required_targets: Sequence[str]
    ) -> dict[str, Any]:
        if tuple(item["target_id"] for item in self.private_entries) != tuple(
            required_targets
        ):
            raise ReadSuiteError("private runtime-open trace set is incomplete")
        manifest = {
            "schema_version": 1,
            "sidecar_type": "odoo-accounting-cli-v3.dev29.private-runtime-open.v1",
            "release": self.expected.release,
            "evidence_name": self.private_sidecar.name,
            "entries": list(self.private_entries),
            "production_promotion_allowed": False,
        }
        payload = canonical_json(manifest) + b"\n"
        path = self.private_sidecar / "MANIFEST.json"
        pending = self.private_sidecar / ".MANIFEST.json.pending"
        directory_fd = os.open(
            self.private_sidecar,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            final_exists = os.path.lexists(path)
            pending_exists = os.path.lexists(pending)
            if final_exists and pending_exists:
                raise ReadSuiteError(
                    "private runtime-open manifest recovery is ambiguous"
                )
            for entry in self.private_entries:
                expected_path = self.private_sidecar / f"{entry['target_id']}.strace"
                if entry.get("path") != str(expected_path):
                    raise ReadSuiteError(
                        "private runtime-open trace escaped its sidecar"
                    )
                try:
                    self.module.verify_private_seal_sidecar(
                        expected_path,
                        entry,
                        journal_required=not final_exists,
                    )
                except (OSError, self.module.RuntimeOpenTraceError) as exc:
                    raise ReadSuiteError(
                        "private runtime-open seal transaction is invalid"
                    ) from exc
            if final_exists:
                observed = stable_read(
                    path,
                    label="private runtime-open manifest",
                    expected_uid=0 if os.name == "posix" else None,
                    expected_gid=0 if os.name == "posix" else None,
                    allowed_modes=(
                        frozenset({0o400}) if os.name == "posix" else None
                    ),
                )
                if observed != payload:
                    raise ReadSuiteError(
                        "existing private runtime-open manifest differs"
                    )
            else:
                if not pending_exists:
                    write_private(pending, payload)
                    _crash_injection_gate(
                        "private-manifest-after-pending-write"
                    )
                else:
                    metadata = pending.lstat()
                    allowed = {0o600, 0o400} if os.name == "posix" else {
                        stat.S_IMODE(metadata.st_mode)
                    }
                    if (
                        pending.is_symlink()
                        or not stat.S_ISREG(metadata.st_mode)
                        or stat.S_IMODE(metadata.st_mode) not in allowed
                        or pending.read_bytes() != payload
                    ):
                        raise ReadSuiteError(
                            "recoverable private runtime-open manifest differs"
                        )
                if os.name == "posix":
                    os.chmod(pending, 0o400, follow_symlinks=False)
                pending_fd = os.open(
                    pending,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    os.fsync(pending_fd)
                    if os.fstat(pending_fd).st_size != len(payload):
                        raise ReadSuiteError(
                            "private runtime-open manifest size drifted"
                        )
                finally:
                    os.close(pending_fd)
                os.fsync(directory_fd)
                _crash_injection_gate(
                    "private-manifest-after-chmod-fsync"
                )
                self.module._renameat2_noreplace(
                    directory_fd,
                    pending.name,
                    directory_fd,
                    path.name,
                )
                _crash_injection_gate(
                    "private-manifest-after-rename-before-directory-fsync"
                )
                os.fsync(directory_fd)
                _crash_injection_gate(
                    "private-manifest-after-directory-fsync"
                )
                observed = stable_read(
                    path,
                    label="sealed private runtime-open manifest",
                    expected_uid=0 if os.name == "posix" else None,
                    expected_gid=0 if os.name == "posix" else None,
                    allowed_modes=(
                        frozenset({0o400}) if os.name == "posix" else None
                    ),
                )
                if observed != payload:
                    raise ReadSuiteError(
                        "sealed private runtime-open manifest differs"
                    )
            for entry in self.private_entries:
                journal_name = self.module._seal_sidecar_name(entry["target_id"])
                try:
                    self.module.verify_private_seal_sidecar(
                        self.private_sidecar / f"{entry['target_id']}.strace",
                        entry,
                        journal_required=True,
                    )
                except self.module.RuntimeOpenTraceError:
                    if os.path.lexists(self.private_sidecar / journal_name):
                        raise
                    continue
                os.unlink(journal_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
            _crash_injection_gate(
                "private-manifest-after-seal-journal-cleanup"
            )
        finally:
            os.close(directory_fd)
        tree_identity = hashlib.sha256(
            canonical_json(
                [
                    {
                        key: entry[key]
                        for key in (
                            "target_id",
                            "device",
                            "inode",
                            "size",
                            "sha256",
                        )
                    }
                    for entry in self.private_entries
                ]
            )
        ).hexdigest()
        return {
            "schema_version": 1,
            "manifest_sha256": hashlib.sha256(payload).hexdigest(),
            "trace_count": len(self.private_entries),
            "tree_identity_sha256": tree_identity,
            "production_promotion_allowed": False,
        }


@dataclass(frozen=True)
class _DiscoveryTraceManifest:
    release: str
    target_id: str
    role: str
    working_directory: str
    environment: Mapping[str, str]
    bootstrap_argv: tuple[str, ...]
    final_argv: tuple[str, ...]
    watch_roots: tuple[str, ...]
    expected_strace_sha256: str
    expected_static_closure_sha256: str
    expected_child_environment_sha256: str
    expected_uid: int
    expected_gid: int
    dynamic_argv_template: bool = False


class RuntimeTraceDiscoveryGate:
    """Collect raw traces and exact argv inventory without approving policy."""

    def __init__(
        self,
        expected: ExpectedIdentity,
        *,
        expected_strace_sha256: str,
        private_sidecar: Path,
        watch_roots: Sequence[str],
    ) -> None:
        if not isinstance(expected_strace_sha256, str) or HEX64.fullmatch(
            expected_strace_sha256
        ) is None:
            raise ReadSuiteError("runtime-open discovery strace identity is invalid")
        paths = _release_paths(expected)
        manifest = load_json_bytes(
            stable_read(
                paths["manifest"],
                label="runtime-open discovery release manifest",
                expected_uid=0 if os.name == "posix" else None,
                expected_gid=0 if os.name == "posix" else None,
                allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
            ),
            label="runtime-open discovery release manifest",
        )
        indexed = _manifest_index(manifest, expected)
        trace_member = indexed.get(str(TRACE_RELATIVE))
        if trace_member is None:
            raise ReadSuiteError("runtime-open discovery validator is absent")
        runtime_path = paths["root"].joinpath(*TRACE_RELATIVE.parts)
        runtime_payload = stable_read(
            runtime_path,
            label="runtime-open discovery validator",
            maximum=MAX_RELEASE_FILE_BYTES,
            expected_uid=0 if os.name == "posix" else None,
            expected_gid=0 if os.name == "posix" else None,
            allowed_modes=frozenset({_expected_release_member_mode(str(TRACE_RELATIVE))})
            if os.name == "posix"
            else None,
        )
        self.module = _load_runtime_trace_module(
            runtime_payload,
            runtime_path,
            expected_sha256=trace_member["sha256"],
        )
        self.expected = expected
        self.expected_strace_sha256 = expected_strace_sha256
        self.private_sidecar = Path(private_sidecar)
        self.watch_roots = tuple(watch_roots)
        self.static_closure_sha256: str | None = None
        self.entries: list[dict[str, Any]] = []
        self.consumed: set[str] = set()

    def _manifest(
        self, target_id: str, bootstrap: Sequence[str], final: Sequence[str]
    ) -> _DiscoveryTraceManifest:
        if target_id not in suite_runtime_trace_targets() or target_id in self.consumed:
            raise ReadSuiteError("runtime-open discovery target state is invalid")
        role = _expected_trace_role(target_id)
        release_root = str(_release_paths(self.expected)["root"])
        try:
            self.module.dynamic_bootstrap_template(
                tuple(bootstrap),
                tuple(final),
                role=role,
                release_root=release_root,
            )
            uid, gid, is_template = self.module._validate_bootstrap_argv(
                tuple(bootstrap),
                tuple(final),
                role=role,
                release_root=release_root,
            )
        except self.module.RuntimeOpenTraceError as exc:
            raise ReadSuiteError(
                "runtime-open discovery argv cannot be templated"
            ) from exc
        if is_template:
            raise ReadSuiteError("runtime-open discovery received a template argv")
        environment = dict(self.module.ROLE_ENVIRONMENTS[role])
        candidate = _DiscoveryTraceManifest(
            release=self.expected.release,
            target_id=target_id,
            role=role,
            working_directory=release_root,
            environment=environment,
            bootstrap_argv=tuple(bootstrap),
            final_argv=tuple(final),
            watch_roots=self.watch_roots,
            expected_strace_sha256=self.expected_strace_sha256,
            expected_static_closure_sha256="0" * 64,
            expected_child_environment_sha256=hashlib.sha256(
                canonical_json(environment)
            ).hexdigest(),
            expected_uid=uid,
            expected_gid=gid,
        )
        try:
            captured = self.module.capture_runtime_environment(candidate)
            static_closure_sha256 = hashlib.sha256(
                canonical_json(captured["static_closure"])
            ).hexdigest()
        except self.module.RuntimeOpenTraceError as exc:
            raise ReadSuiteError(
                "runtime-open discovery static closure cannot be captured"
            ) from exc
        if self.static_closure_sha256 is None:
            self.static_closure_sha256 = static_closure_sha256
        elif self.static_closure_sha256 != static_closure_sha256:
            raise ReadSuiteError("runtime-open discovery static closure drifted")
        return _DiscoveryTraceManifest(
            release=candidate.release,
            target_id=candidate.target_id,
            role=candidate.role,
            working_directory=candidate.working_directory,
            environment=candidate.environment,
            bootstrap_argv=candidate.bootstrap_argv,
            final_argv=candidate.final_argv,
            watch_roots=candidate.watch_roots,
            expected_strace_sha256=candidate.expected_strace_sha256,
            expected_static_closure_sha256=static_closure_sha256,
            expected_child_environment_sha256=(
                candidate.expected_child_environment_sha256
            ),
            expected_uid=candidate.expected_uid,
            expected_gid=candidate.expected_gid,
        )

    def execute(
        self,
        target_id: str,
        bootstrap: Sequence[str],
        final: Sequence[str],
        *,
        inherited_fds: Sequence[int],
        callback: Callable[[subprocess.Popen[bytes]], Any],
    ) -> Any:
        manifest = self._manifest(target_id, bootstrap, final)
        process: subprocess.Popen[bytes] | None = None
        with self.module.validate_strace_tool(self.expected_strace_sha256) as trusted:
            with self.module.PrivateTraceStaging(
                target_id,
                parent=self.private_sidecar / ".trace-staging",
            ) as staging:
                try:
                    launch = self.module.build_strace_launch(
                        staging.path,
                        manifest,
                        trusted,
                        inherited_fds=inherited_fds,
                    )
                    process = subprocess.Popen(
                        launch.argv,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        cwd=manifest.working_directory,
                        env=dict(manifest.environment),
                        close_fds=True,
                        pass_fds=launch.pass_fds,
                    )
                    self.module.verify_and_release_traced_process(
                        process.pid,
                        trusted,
                        manifest,
                        supervisor_pid=os.getpid(),
                        timeout_seconds=5.0,
                    )
                    value = callback(process)
                    _attested_child_environment_sha256(
                        value, manifest.expected_child_environment_sha256
                    )
                    staging.assert_private_identity()
                    raw_identity = staging.seal_to(
                        self.private_sidecar / f"{target_id}.strace",
                        target_id=target_id,
                        manifest_sha256="0" * 64,
                        expected_leader_pid=process.pid,
                    )
                    self.entries.append(
                        {
                            "target_id": target_id,
                            "trace_path": raw_identity["path"],
                            "expected_leader_pid": process.pid,
                            "role": manifest.role,
                            "working_directory": manifest.working_directory,
                            "bootstrap_argv": list(manifest.bootstrap_argv),
                            "final_argv": list(manifest.final_argv),
                            "expected_returncodes": [int(value.returncode)],
                        }
                    )
                    self.consumed.add(target_id)
                    return value
                except BaseException:
                    if process is not None and process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            process.kill()
                        try:
                            process.communicate(timeout=5)
                        except (OSError, subprocess.TimeoutExpired):
                            pass
                    raise

    def inventory(
        self,
        *,
        required_targets: Sequence[str],
        expected_static_closure_sha256: str | None,
        watch_roots: Sequence[str],
        mutable_roots: Sequence[str],
        sqlite_delta_contract_sha256: str,
    ) -> dict[str, Any]:
        if tuple(item["target_id"] for item in self.entries) != tuple(required_targets):
            raise ReadSuiteError("runtime-open discovery target set is incomplete")
        if self.static_closure_sha256 is None:
            raise ReadSuiteError("runtime-open discovery static closure is absent")
        if (
            expected_static_closure_sha256 is not None
            and expected_static_closure_sha256 != self.static_closure_sha256
        ):
            raise ReadSuiteError("runtime-open discovery static closure mismatched")
        return {
            "schema_version": 1,
            "scope": (
                "odoo-accounting-cli-v3.dev29."
                "runtime-open-discovery-suite-fragment.v1"
            ),
            "release": self.expected.release,
            "expected_static_closure_sha256": self.static_closure_sha256,
            "watch_roots": list(watch_roots),
            "mutable_roots": list(mutable_roots),
            "sqlite_delta_contract_sha256": sqlite_delta_contract_sha256,
            "targets": list(self.entries),
        }


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | getattr(os, "O_BINARY", 0)
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def write_json(path: Path, value: Any) -> None:
    write_private(path, canonical_json(value) + b"\n")


def _safe_root_chain(path: Path, *, final_modes: frozenset[int] | None = None) -> None:
    path = Path(path).absolute()
    current = Path("/")
    for component in path.parts[1:]:
        current /= component
        metadata = current.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or current.is_symlink()
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or mode & 0o022
            or not mode & 0o111
        ):
            raise ReadSuiteError(f"unsafe root-owned directory chain: {current}")
    if final_modes is not None and stat.S_IMODE(path.lstat().st_mode) not in final_modes:
        raise ReadSuiteError(f"directory mode is invalid: {path}")


def create_evidence_directory(
    path: Path,
    *,
    expected_parent: Path = EVIDENCE_PARENT,
    enforce_root: bool = True,
) -> Path:
    path = Path(path).absolute()
    parent = Path(expected_parent).absolute()
    if (
        path == Path("/")
        or path.parent != parent
        or EVIDENCE_NAME.fullmatch(path.name) is None
    ):
        raise ReadSuiteError(
            "evidence directory must be a named direct child of the fixed parent"
        )
    if os.path.lexists(path):
        raise ReadSuiteError("evidence directory already exists")
    if enforce_root and os.name == "posix":
        _safe_root_chain(parent)
    os.mkdir(path, 0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ReadSuiteError("evidence directory is not canonical")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ReadSuiteError("evidence directory is not mode 0700")
    if enforce_root and os.name == "posix" and (metadata.st_uid, metadata.st_gid) != (0, 0):
        raise ReadSuiteError("evidence directory is not root:root")
    _fsync_directory(parent)
    return path


def _release_paths(expected: ExpectedIdentity) -> dict[str, Path]:
    expected.validate()
    root = RELEASE_PARENT / expected.release
    return {
        "root": root,
        "manifest": root / "RELEASE-MANIFEST.json",
        "package": PACKAGE_PARENT / f"odoo-accounting-cli-v3-{expected.release}.tar.gz",
        "anchor": TRUSTED_ARTIFACT_PARENT / f"{expected.release}.json",
        "plan": root.joinpath(*PLAN_RELATIVE.parts),
        "signer": root.joinpath(*SIGNER_RELATIVE.parts),
        "oracle": root.joinpath(*ORACLE_RELATIVE.parts),
        "closure": root.joinpath(*CLOSURE_RELATIVE.parts),
        "direct_child": root.joinpath(*DIRECT_CHILD_RELATIVE.parts),
        "runner": root.joinpath(*RUNNER_RELATIVE.parts),
        "verifier": root.joinpath(*VERIFIER_RELATIVE.parts),
        "launcher": root.joinpath(*LAUNCHER_RELATIVE.parts),
        "runtime": CONFIG_PARENT / f"runtime-test-{expected.release}.json",
    }


def _manifest_index(manifest: dict[str, Any], expected: ExpectedIdentity) -> dict[str, dict[str, Any]]:
    if (
        set(manifest) != {"commit", "files", "manifest_sha256", "schema_version", "version"}
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 1
        or manifest.get("version") != expected.version
        or manifest.get("commit") != expected.commit
        or manifest.get("manifest_sha256") != expected.manifest_sha256
    ):
        raise ReadSuiteError("installed release manifest identity is invalid")
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if hashlib.sha256(canonical_json(unsigned)).hexdigest() != expected.manifest_sha256:
        raise ReadSuiteError("installed release manifest semantic digest is invalid")
    files = manifest.get("files")
    if type(files) is not list or not files or len(files) > MAX_RELEASE_FILES:
        raise ReadSuiteError("installed release manifest file list is invalid")
    indexed: dict[str, dict[str, Any]] = {}
    for item in files:
        if type(item) is not dict or set(item) != {"path", "sha256", "size"}:
            raise ReadSuiteError("installed release manifest entry is invalid")
        name = item.get("path")
        portable = PurePosixPath(name) if isinstance(name, str) else None
        if (
            portable is None
            or portable.is_absolute()
            or not portable.parts
            or any(part in {"", ".", ".."} for part in portable.parts)
            or str(portable) != name
            or name in indexed
            or not isinstance(item.get("sha256"), str)
            or HEX64.fullmatch(item["sha256"]) is None
            or type(item.get("size")) is not int
            or item["size"] < 0
            or item["size"] > MAX_RELEASE_FILE_BYTES
        ):
            raise ReadSuiteError("installed release manifest entry is invalid")
        indexed[name] = item
    for required in (
        str(PLAN_RELATIVE),
        str(SIGNER_RELATIVE),
        str(ORACLE_RELATIVE),
        str(CLOSURE_RELATIVE),
        str(DIRECT_CHILD_RELATIVE),
        str(RUNNER_RELATIVE),
        str(TRACE_RELATIVE),
        str(VERIFIER_RELATIVE),
        str(LAUNCHER_RELATIVE),
    ):
        if required not in indexed:
            raise ReadSuiteError(f"installed release omits required Dev29 member: {required}")
    return indexed


def verify_release(
    expected: ExpectedIdentity,
    *,
    executing_script: Path | None = None,
    enforce_root: bool = True,
) -> dict[str, Any]:
    """Verify every installed release member before executing any of its code."""

    expected.validate()
    paths = _release_paths(expected)
    root = paths["root"]
    if executing_script is not None and Path(executing_script).resolve(strict=True) != paths[
        "runner"
    ].resolve(strict=True):
        raise ReadSuiteError("suite runner is outside the expected sealed release")
    if root.resolve(strict=True).name != expected.release:
        raise ReadSuiteError("installed release root identity is invalid")
    if enforce_root and os.name == "posix":
        _safe_root_chain(root, final_modes=frozenset({0o555}))
    anchor_bytes = stable_read(
        paths["anchor"],
        label="external release anchor",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if enforce_root and os.name == "posix" else None,
    )
    anchor = load_json_bytes(anchor_bytes, label="external release anchor")
    if anchor != {
        "commit": expected.commit,
        "manifest_sha256": expected.manifest_sha256,
        "package_sha256": expected.package_sha256,
        "release": expected.release,
    }:
        raise ReadSuiteError("external release anchor does not match expectation")
    manifest_bytes = stable_read(
        paths["manifest"],
        label="installed release manifest",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if enforce_root and os.name == "posix" else None,
    )
    manifest = load_json_bytes(manifest_bytes, label="installed release manifest")
    indexed = _manifest_index(manifest, expected)
    actual: dict[str, Path] = {}
    directories: set[str] = set()
    for directory_text, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        directory = Path(directory_text)
        relative_directory = directory.relative_to(root).as_posix()
        if relative_directory != ".":
            directories.add(relative_directory)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            child = directory / name
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise ReadSuiteError("installed release contains an unsafe directory")
            if enforce_root and os.name == "posix" and (
                metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o555
            ):
                raise ReadSuiteError("installed release directory metadata drifted")
        for name in file_names:
            child = directory / name
            relative = child.relative_to(root).as_posix()
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ReadSuiteError(f"installed release contains unsafe file: {relative}")
            if relative != "RELEASE-MANIFEST.json":
                actual[relative] = child
            if len(actual) > MAX_RELEASE_FILES:
                raise ReadSuiteError("installed release contains too many files")
    if set(actual) != set(indexed):
        raise ReadSuiteError("installed release file set does not match its manifest")
    for name, item in indexed.items():
        payload = stable_read(
            actual[name],
            label=f"installed release member {name}",
            maximum=MAX_RELEASE_FILE_BYTES,
            allow_empty=item["size"] == 0,
            expected_uid=0 if enforce_root and os.name == "posix" else None,
            expected_gid=0 if enforce_root and os.name == "posix" else None,
            allowed_modes=frozenset({_expected_release_member_mode(name)})
            if enforce_root and os.name == "posix"
            else None,
        )
        if len(payload) != item["size"] or hashlib.sha256(payload).hexdigest() != item["sha256"]:
            raise ReadSuiteError(f"installed release member mismatch: {name}")
    package_bytes = stable_read(
        paths["package"],
        label="canonical release package",
        maximum=512 * 1024 * 1024,
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if enforce_root and os.name == "posix" else None,
    )
    if hashlib.sha256(package_bytes).hexdigest() != expected.package_sha256:
        raise ReadSuiteError("canonical release package digest mismatch")
    return {
        **expected.document(),
        "manifest_file_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "release_file_count": len(indexed),
        "verified": True,
    }


def load_plan(paths: Mapping[str, Path], *, enforce_root: bool = True) -> tuple[dict[str, Any], bytes]:
    plan_bytes = stable_read(
        paths["plan"],
        label="sealed Dev29 read plan",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=0 if enforce_root and os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if enforce_root and os.name == "posix" else None,
    )
    plan = load_json_bytes(plan_bytes, label="sealed Dev29 read plan")
    if set(plan) != {
        "schema_version",
        "target",
        "database",
        "runtime",
        "cases",
        "negative_cases",
        "witness",
    } or not _schema_version_is_one(plan.get("schema_version")):
        raise ReadSuiteError("Dev29 read plan envelope is invalid")
    cases = plan.get("cases")
    negatives = plan.get("negative_cases")
    if (
        type(cases) is not list
        or tuple(item.get("name") for item in cases if type(item) is dict) != POSITIVE_NAMES
        or type(negatives) is not list
        or tuple(item.get("name") for item in negatives if type(item) is dict) != NEGATIVE_NAMES
    ):
        raise ReadSuiteError("Dev29 read plan case set or order is invalid")
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
    for item in cases:
        if (
            type(item) is not dict
            or set(item) != positive_fields
            or not isinstance(item.get("capability_id"), str)
            or not item["capability_id"].startswith("acct.")
            or type(item.get("parameters")) is not dict
            or type(item.get("expected")) is not dict
        ):
            raise ReadSuiteError("Dev29 positive case is invalid")
        _validate_plan_identity(item, label=f"positive case {item.get('name')}")
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
    case_names = set(POSITIVE_NAMES)
    for item in negatives:
        mutation = item.get("mutation") if type(item) is dict else None
        if (
            type(item) is not dict
            or set(item) != negative_fields
            or item.get("base_case") not in case_names
            or not isinstance(item.get("expected_error"), str)
            or not item["expected_error"]
            or type(mutation) is not dict
            or set(mutation) != {"kind", "fields"}
            or mutation.get("kind")
            not in {
                "identity_override",
                "context_override",
                "expire_after_sign",
                "parameters_after_sign",
                "replay_exact_request",
            }
            or type(mutation.get("fields")) is not dict
        ):
            raise ReadSuiteError("Dev29 negative case is invalid")
        _validate_plan_identity(item, label=f"negative case {item.get('name')}")
    target = plan.get("target")
    database = plan.get("database")
    runtime = plan.get("runtime")
    witness = plan.get("witness")
    if not all(type(item) is dict for item in (target, database, runtime, witness)):
        raise ReadSuiteError("Dev29 target, database, runtime, or witness plan is invalid")
    if (
        target.get("environment") != "test"
        or target.get("capability_channel") != "staged"
        or database.get("name") != "odoo_test"
        or not isinstance(database.get("uuid"), str)
        or not isinstance(target.get("services"), list)
        or not isinstance(target.get("v3_unit_names"), list)
        or not isinstance(target.get("v2_roots"), list)
        or not isinstance(target.get("pi_control_files"), list)
        or len(target["services"]) < 2
        or not target["v3_unit_names"]
        or not target["v2_roots"]
        or not target["pi_control_files"]
    ):
        raise ReadSuiteError("Dev29 target safety scope is invalid")
    try:
        if str(uuid.UUID(database["uuid"])) != database["uuid"]:
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise ReadSuiteError("Dev29 database UUID is invalid") from exc
    return plan, plan_bytes


def _validate_plan_identity(value: Mapping[str, Any], *, label: str) -> None:
    principal = value.get("principal")
    user_id = value.get("user_id")
    company_id = value.get("company_id")
    allowed = value.get("allowed_company_ids")
    if (
        not isinstance(principal, str)
        or not principal
        or principal != principal.strip()
        or type(user_id) is not int
        or user_id <= 0
        or type(company_id) is not int
        or company_id <= 0
        or type(allowed) is not list
        or not allowed
        or any(type(item) is not int or item <= 0 for item in allowed)
        or len(allowed) != len(set(allowed))
    ):
        raise ReadSuiteError(f"{label} identity is invalid")


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


def load_runtime(
    path: Path,
    plan: dict[str, Any],
    expected: ExpectedIdentity,
    *,
    service_gid: int | None = None,
    enforce_root: bool = True,
) -> tuple[dict[str, Any], bytes]:
    paths = _release_paths(expected)
    if Path(path).absolute() != paths["runtime"]:
        raise ReadSuiteError("runtime configuration escaped the fixed Dev29 candidate path")
    runtime_bytes = stable_read(
        path,
        label="Dev29 runtime configuration",
        expected_uid=0 if enforce_root and os.name == "posix" else None,
        expected_gid=service_gid if enforce_root and os.name == "posix" else None,
        allowed_modes=frozenset({0o640}) if enforce_root and os.name == "posix" else None,
    )
    runtime = load_json_bytes(runtime_bytes, label="Dev29 runtime configuration")
    if set(runtime) != RUNTIME_FIELDS:
        raise ReadSuiteError("Dev29 runtime configuration fields are invalid")
    target = plan["target"]
    database = plan["database"]
    fixed_runtime = plan["runtime"]
    state_root = f"/var/lib/odoo-accounting-cli-v3/test/candidates/{expected.release}"
    secret_root = f"/etc/odoo-accounting-cli-v3/secrets/test/candidates/{expected.release}"
    expected_values = {
        "instance_id": target["instance_id"],
        "environment": "test",
        "capability_channel": "staged",
        "database_name": database["name"],
        "database_uuid": database["uuid"],
        **fixed_runtime,
        "release_root": str(paths["root"]),
        "canonical_package_path": str(paths["package"]),
        "canonical_package_sha256": expected.package_sha256,
        "auth_state_path": f"{state_root}/auth/state.sqlite3",
        "receipt_state_path": f"{state_root}/receipt/state.sqlite3",
        "gcov_state_path": f"{state_root}/gcov",
        "auth_secret_path": f"{secret_root}/auth.hmac",
        "receipt_secret_path": f"{secret_root}/receipt.hmac",
    }
    for key, value in expected_values.items():
        if runtime.get(key) != value:
            raise ReadSuiteError(f"Dev29 runtime binding mismatch: {key}")
    if (
        not isinstance(runtime["auth_key_id"], str)
        or not runtime["auth_key_id"].startswith("test-auth-dev29-")
        or not isinstance(runtime["receipt_key_id"], str)
        or not runtime["receipt_key_id"].startswith("test-receipt-dev29-")
        or runtime["auth_key_id"] == runtime["receipt_key_id"]
    ):
        raise ReadSuiteError("Dev29 runtime key roles are invalid")
    for field in (
        "odoo_python_sha256",
        "odoo_bin_sha256",
        "odoo_config_sha256",
        "canonical_package_sha256",
    ):
        if not isinstance(runtime[field], str) or HEX64.fullmatch(runtime[field]) is None:
            raise ReadSuiteError(f"Dev29 runtime digest is invalid: {field}")
    for path_field, digest_field in (
        ("odoo_python", "odoo_python_sha256"),
        ("odoo_bin", "odoo_bin_sha256"),
        ("odoo_config", "odoo_config_sha256"),
    ):
        payload = stable_read(
            Path(runtime[path_field]),
            label=f"fixed runtime dependency {path_field}",
            maximum=MAX_RELEASE_FILE_BYTES,
            allow_empty=False,
            allow_path_symlink=path_field == "odoo_python",
        )
        if hashlib.sha256(payload).hexdigest() != runtime[digest_field]:
            raise ReadSuiteError(f"fixed runtime dependency drifted: {path_field}")
    return runtime, runtime_bytes


def run_closure_verify(
    paths: Mapping[str, Path],
    runtime: Mapping[str, Any],
    plan: Mapping[str, Any],
    expected: ExpectedIdentity,
    expected_closure: ExpectedClosure,
    *,
    timeout: int = 300,
) -> subprocess.CompletedProcess[bytes]:
    expected_closure.validate()
    database = plan["database"]
    return subprocess.run(
        [
            CLOSURE_PYTHON,
            "-I",
            "-S",
            str(paths["closure"]),
            "verify-active",
            "--expected-release",
            expected.release,
            "--expected-version",
            expected.version,
            "--expected-commit",
            expected.commit,
            "--expected-manifest-sha256",
            expected.manifest_sha256,
            "--expected-package-sha256",
            expected.package_sha256,
            "--expected-closure-anchor-sha256",
            expected_closure.anchor_sha256,
            "--expected-closure-image-sha256",
            expected_closure.image_sha256,
            "--expected-system-python-sha256",
            expected_closure.system_python_sha256,
            "--expected-ld-so-preload-sha256",
            expected_closure.loader_preload_sha256,
            "--expected-ldconfig-sha256",
            expected_closure.ldconfig_sha256,
            "--expected-odoo-config-sha256",
            runtime["odoo_config_sha256"],
            "--expected-database-name",
            database["name"],
            "--expected-database-uuid",
            database["uuid"],
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )


def validate_closure_document(
    document: dict[str, Any],
    *,
    runtime: Mapping[str, Any],
    plan: Mapping[str, Any],
    expected: ExpectedIdentity,
    expected_closure: ExpectedClosure,
) -> dict[str, Any]:
    expected_closure.validate()
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
        "lifecycle",
    } or not _schema_version_is_one(
        document.get("schema_version")
    ) or document.get("status") != "active_verified":
        raise ReadSuiteError("Odoo closure verification envelope is invalid")
    if document.get("release_identity") != expected.document():
        raise ReadSuiteError("Odoo closure release identity is invalid")
    closure = document.get("closure_identity")
    required_closure = {
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
        / f"{expected.release}.json"
    )
    expected_image_path = str(
        PurePosixPath("/opt/odoo-accounting-cli-v3/dependency-images")
        / f"{expected.release}.squashfs"
    )
    expected_sealed_config = str(
        PurePosixPath("/etc/odoo-accounting-cli-v3/dependencies")
        / expected.release
        / "odoo-server19.conf"
    )
    if (
        type(closure) is not dict
        or set(closure) != required_closure
        or closure.get("anchor_path") != expected_anchor_path
        or closure.get("anchor_sha256") != expected_closure.anchor_sha256
        or closure.get("image_path") != expected_image_path
        or closure.get("image_sha256") != expected_closure.image_sha256
        or closure.get("sealed_config_path") != expected_sealed_config
        or closure.get("sealed_config_sha256") != runtime["odoo_config_sha256"]
        or closure.get("system_python_sha256")
        != expected_closure.system_python_sha256
        or closure.get("loader_preload_sha256")
        != expected_closure.loader_preload_sha256
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
        raise ReadSuiteError("Odoo closure identity is invalid")
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
        or loader_preload.get("sha256") != expected_closure.loader_preload_sha256
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
        or [item.get("path") for item in symlinks if type(item) is dict]
        != sorted(item.get("path") for item in symlinks if type(item) is dict)
    ):
        raise ReadSuiteError("Odoo loader preload identity is invalid")
    for library in libraries:
        if type(library) is not dict or set(library) != {
            "configured_path",
            "expanded_path",
            "rooted_path",
            "resolved_path",
        }:
            raise ReadSuiteError("Odoo loader preload library is invalid")
        configured = library["configured_path"]
        expanded = library["expanded_path"]
        if (
            not isinstance(configured, str)
            or not configured
            or expanded
            != configured.replace("${LIB}", "lib/x86_64-linux-gnu").replace(
                "$LIB", "lib/x86_64-linux-gnu"
            )
            or "$" in expanded
            or not PurePosixPath(expanded).is_absolute()
            or str(PurePosixPath(expanded)) != expanded
            or library["rooted_path"] != expanded
            or not isinstance(library["resolved_path"], str)
            or not PurePosixPath(library["resolved_path"]).is_absolute()
            or str(PurePosixPath(library["resolved_path"])) != library["resolved_path"]
        ):
            raise ReadSuiteError("Odoo loader preload library path is invalid")
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
            raise ReadSuiteError("Odoo loader preload symlink identity is invalid")
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
            raise ReadSuiteError("Odoo closure semantic digest is invalid")
    expected_external_manifest = str(
        PurePosixPath(f"/opt/odoo-accounting-cli-v3/dependencies/{expected.release}")
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
        raise ReadSuiteError("Odoo closure external runtime identity is invalid")
    database = plan["database"]
    if document.get("database_scope") != {
        "database_name": database["name"],
        "database_uuid": database["uuid"],
    }:
        raise ReadSuiteError("Odoo closure database scope is invalid")
    mount_point = PurePosixPath(
        f"/opt/odoo-accounting-cli-v3/dependencies/{expected.release}"
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
        or mount.get("backing_image_sha256") != expected_closure.image_sha256
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
        raise ReadSuiteError("Odoo closure mount identity is invalid")
    if os.name == "posix":
        image_metadata = Path(closure["image_path"]).lstat()
        observed_self = Path("/proc/self/ns/mnt").stat()
        observed_host = Path("/proc/1/ns/mnt").stat()
        if (
            (mount["loop_backing_device"], mount["loop_backing_inode"])
            != (image_metadata.st_dev, image_metadata.st_ino)
            or self_namespace
            != {"device": observed_self.st_dev, "inode": observed_self.st_ino}
            or host_namespace
            != {"device": observed_host.st_dev, "inode": observed_host.st_ino}
        ):
            raise ReadSuiteError("Odoo closure namespace or image inode drifted")
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
        raise ReadSuiteError("Odoo closure systemd bind plan is invalid")
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
        raise ReadSuiteError("Odoo closure activation evidence is invalid")
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
            raise ReadSuiteError("Odoo closure activation binding is invalid")
    if os.name == "posix":
        for item in expected_binds[:3]:
            source = Path(item["source"])
            metadata = source.lstat()
            if (
                source.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or not os.statvfs(source).f_flag & os.ST_RDONLY
            ):
                raise ReadSuiteError("Odoo closure bind source is not root-owned read-only")
        sealed_config = Path(expected_binds[3]["source"])
        sealed_metadata = sealed_config.lstat()
        if (
            sealed_config.is_symlink()
            or not stat.S_ISREG(sealed_metadata.st_mode)
            or sealed_metadata.st_nlink != 1
            or sealed_metadata.st_uid != 0
            or mount_point == sealed_config
            or mount_point in sealed_config.parents
        ):
            raise ReadSuiteError("sealed Odoo config bind source is unsafe")
        placeholder = Path(
            str(
                mount_point
                / "custom-addons"
                / PurePosixPath(runtime["odoo_config"]).name
            )
        )
        placeholder_metadata = placeholder.lstat()
        if (
            placeholder.is_symlink()
            or not stat.S_ISREG(placeholder_metadata.st_mode)
            or placeholder_metadata.st_nlink != 1
            or placeholder_metadata.st_uid != 0
            or not os.statvfs(placeholder).f_flag & os.ST_RDONLY
        ):
            raise ReadSuiteError("sealed config bind destination placeholder is unsafe")
    security = document.get("security")
    if (
        type(security) is not dict
        or set(security) != CLOSURE_SECURITY_FIELDS
        or security != CLOSURE_SECURITY_EXPECTED
    ):
        raise ReadSuiteError("Odoo closure security proof is invalid")
    return document


def _under_any_root(path: PurePosixPath, roots: Sequence[PurePosixPath]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _external_runtime_allowed_roots(
    roots: Sequence[PurePosixPath], entries: Sequence[Any]
) -> tuple[PurePosixPath, ...]:
    allowed: list[PurePosixPath] = list(roots)
    entry_paths = {
        item.get("path")
        for item in entries
        if type(item) is dict and isinstance(item.get("path"), str)
    }
    changed = True
    while changed:
        changed = False
        for item in entries:
            if type(item) is not dict or item.get("kind") != "symlink":
                continue
            path_text = item.get("path")
            target = item.get("target")
            if not isinstance(path_text, str) or not isinstance(target, str):
                continue
            link_path = PurePosixPath(path_text)
            if not _under_any_root(link_path, allowed):
                continue
            try:
                resolved = Path(path_text).resolve(strict=True)
            except OSError as exc:
                raise ReadSuiteError(
                    "closure external runtime symlink target is absent"
                ) from exc
            resolved_text = str(resolved)
            if resolved_text not in entry_paths:
                raise ReadSuiteError(
                    "closure external runtime symlink target is uncovered"
                )
            portable = PurePosixPath(resolved_text)
            if portable not in allowed:
                allowed.append(portable)
                changed = True
    return tuple(allowed)


def external_runtime_snapshot(closure: Mapping[str, Any]) -> dict[str, Any]:
    identity = closure["closure_identity"]
    manifest_path = Path(identity["external_runtime_manifest_path"])
    payload = stable_read(
        manifest_path,
        label="closure external runtime manifest",
        maximum=MAX_JSON_BYTES,
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=0 if os.name == "posix" else None,
        allowed_modes=frozenset({0o444}) if os.name == "posix" else None,
    )
    document = load_json_bytes(payload, label="closure external runtime manifest")
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
        or identity.get("external_runtime_native_path_count") != len(roots) - 4
    ):
        raise ReadSuiteError("closure external runtime manifest is invalid")
    entry_paths = [item.get("path") for item in entries if type(item) is dict]
    if entry_paths != sorted(set(entry_paths)) or any(root not in entry_paths for root in roots):
        raise ReadSuiteError("closure external runtime manifest coverage is invalid")
    root_paths = [PurePosixPath(item) for item in roots]
    allowed_paths = _external_runtime_allowed_roots(root_paths, entries)
    for item in entries:
        path_text = item.get("path") if type(item) is dict else None
        kind = item.get("kind") if type(item) is dict else None
        portable = PurePosixPath(path_text) if isinstance(path_text, str) else None
        common_fields = {"path", "kind", "mode", "uid", "gid"}
        expected_fields = {
            "directory": common_fields,
            "regular": common_fields | {"size", "sha256"},
            "symlink": common_fields | {"target"},
        }
        if (
            portable is None
            or not portable.is_absolute()
            or str(portable) != path_text
            or kind not in expected_fields
            or set(item) != expected_fields[kind]
            or not _under_any_root(portable, allowed_paths)
            or not isinstance(item.get("mode"), str)
            or re.fullmatch(r"[0-7]{4}", item["mode"]) is None
            or item.get("uid") != 0
            or item.get("gid") != 0
        ):
            raise ReadSuiteError("closure external runtime manifest entry is invalid")
        live = Path(path_text)
        metadata = live.lstat()
        if (
            metadata.st_uid != item["uid"]
            or metadata.st_gid != item["gid"]
            or f"{stat.S_IMODE(metadata.st_mode):04o}" != item["mode"]
        ):
            raise ReadSuiteError("closure external runtime metadata drifted")
        if kind == "directory":
            if live.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise ReadSuiteError("closure external runtime directory drifted")
        elif kind == "regular":
            if (
                live.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or type(item.get("size")) is not int
                or item["size"] < 0
                or not isinstance(item.get("sha256"), str)
                or HEX64.fullmatch(item["sha256"]) is None
            ):
                raise ReadSuiteError("closure external runtime file identity is invalid")
            digest, size = _stream_digest(live, label=f"external runtime {path_text}")
            if (digest, size) != (item["sha256"], item["size"]):
                raise ReadSuiteError("closure external runtime file drifted")
        else:
            if not stat.S_ISLNK(metadata.st_mode) or os.readlink(live) != item.get("target"):
                raise ReadSuiteError("closure external runtime symlink drifted")
            resolved = str(live.resolve(strict=True))
            if resolved not in entry_paths:
                raise ReadSuiteError("closure external runtime symlink target is uncovered")
    return {
        "schema_version": 1,
        "manifest_path": str(manifest_path),
        "manifest_file_sha256": hashlib.sha256(payload).hexdigest(),
        "manifest_semantic_sha256": identity["external_runtime_manifest_sha256"],
        "root_count": len(roots),
        "entry_count": len(entries),
        "derived_roots": roots,
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
        raise ReadSuiteError(f"{label} cannot be opened") from exc
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
                raise ReadSuiteError(f"{label} is too large")
    finally:
        os.close(descriptor)
    try:
        return b"".join(chunks).decode("utf-8", "strict")
    except UnicodeError as exc:
        raise ReadSuiteError(f"{label} is not UTF-8") from exc


def _mount_unescape(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def mount_binding_snapshot(closure: Mapping[str, Any]) -> dict[str, Any]:
    mount_point = closure["mount"]["mount_point"]
    matches = []
    for line in _read_virtual_text(
        Path("/proc/self/mountinfo"), label="Linux mountinfo"
    ).splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise ReadSuiteError("Linux mountinfo line is invalid") from exc
        if len(fields) < 10 or separator < 6 or len(fields) <= separator + 3:
            raise ReadSuiteError("Linux mountinfo line is incomplete")
        if _mount_unescape(fields[4]) == mount_point:
            matches.append((fields, separator))
    if len(matches) != 1:
        raise ReadSuiteError("closure mount point is absent or ambiguous")
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
        raise ReadSuiteError("closure mount flags or source are invalid")
    device = fields[2]
    if re.fullmatch(r"[0-9]+:[0-9]+", device) is None:
        raise ReadSuiteError("closure mount device identity is invalid")
    backing_path = Path(f"/sys/dev/block/{device}/loop/backing_file")
    backing = _read_virtual_text(
        backing_path, label="loop backing file", maximum=64 * 1024
    ).strip()
    if not backing or backing.endswith(" (deleted)"):
        raise ReadSuiteError("closure loop backing file is invalid")
    if not backing.startswith("/"):
        backing = "/" + backing
    expected_image = Path(closure["closure_identity"]["image_path"])
    if Path(backing).resolve(strict=True) != expected_image.resolve(strict=True):
        raise ReadSuiteError("closure mount is not backed by the expected image")
    try:
        loop_metadata = Path(source).lstat()
        image_metadata = expected_image.lstat()
        if (
            not stat.S_ISBLK(loop_metadata.st_mode)
            or f"{os.major(loop_metadata.st_rdev)}:{os.minor(loop_metadata.st_rdev)}"
            != device
        ):
            raise ReadSuiteError("closure loop device identity is invalid")
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
    except ReadSuiteError:
        raise
    except OSError as exc:
        raise ReadSuiteError("closure loop or namespace identity cannot be inspected") from exc
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
        raise ReadSuiteError("closure loop or private namespace attestation drifted")
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


def validate_addons_paths(
    closure: Mapping[str, Any], runtime: Mapping[str, Any]
) -> dict[str, Any]:
    config_path = Path(closure["closure_identity"]["sealed_config_path"])
    payload = stable_read(
        config_path,
        label="sealed Odoo closure configuration",
        maximum=16 * 1024 * 1024,
    )
    if hashlib.sha256(payload).hexdigest() != runtime["odoo_config_sha256"]:
        raise ReadSuiteError("sealed Odoo configuration digest drifted")
    try:
        parser = configparser.RawConfigParser(interpolation=None, strict=True)
        parser.read_string(payload.decode("utf-8", "strict"))
        raw = parser.get("options", "addons_path")
    except (configparser.Error, UnicodeError) as exc:
        raise ReadSuiteError("sealed Odoo addons_path cannot be parsed") from exc
    addons = [item.strip() for item in raw.split(",") if item.strip()]
    destinations = [
        Path(item["destination"])
        for item in closure["systemd"]["bind_read_only_paths"][:3]
        if item["destination"]
        != str(PurePosixPath(runtime["odoo_python"]).parent.parent)
    ]
    if not addons:
        raise ReadSuiteError("sealed Odoo addons_path is empty")
    for item in addons:
        candidate = Path(item)
        if not candidate.is_absolute() or not any(
            candidate == root or root in candidate.parents for root in destinations
        ):
            raise ReadSuiteError("sealed Odoo addons_path escaped read-only closure binds")
    return {
        "schema_version": 1,
        "paths": addons,
        "path_count": len(addons),
        "all_paths_covered_by_read_only_binds": True,
        "config_sha256": runtime["odoo_config_sha256"],
    }


def _hash_file_snapshot(path: Path, *, label: str) -> dict[str, Any]:
    payload = stable_read(path, label=label, maximum=MAX_RELEASE_FILE_BYTES, allow_empty=True)
    metadata = path.lstat()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def closure_python_snapshot(expected_sha256: str) -> dict[str, Any]:
    snapshot = _hash_file_snapshot(
        Path(CLOSURE_PYTHON), label="root-owned closure verification Python"
    )
    metadata = Path(CLOSURE_PYTHON).lstat()
    if (
        Path(CLOSURE_PYTHON).is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
        or stat.S_IMODE(metadata.st_mode) != 0o755
        or snapshot["sha256"] != expected_sha256
        or Path(sys.executable).resolve(strict=True)
        != Path(CLOSURE_PYTHON).resolve(strict=True)
        or Path("/proc/self/exe").resolve(strict=True)
        != Path(CLOSURE_PYTHON).resolve(strict=True)
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
    ):
        raise ReadSuiteError("closure verification Python trust boundary is invalid")
    return {
        "schema_version": 1,
        **snapshot,
        "root_owned": True,
        "one_link_regular": True,
        "resolved_executable": str(Path(CLOSURE_PYTHON).resolve(strict=True)),
        "isolated": True,
        "no_site": True,
    }


def _tree_snapshot(root: Path) -> dict[str, Any]:
    root = Path(root)
    root_metadata = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
        raise ReadSuiteError(f"source tree root is unsafe: {root}")
    members: list[dict[str, Any]] = []
    for directory_text, directories, names in os.walk(root, topdown=True, followlinks=False):
        directory = Path(directory_text)
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRECTORIES)
        for name in directories:
            child = directory / name
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise ReadSuiteError(f"unsafe source tree directory: {child}")
        for name in sorted(names):
            child = directory / name
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise ReadSuiteError(f"unsafe source tree object: {child}")
            if name.lower().endswith(SKIP_SUFFIXES):
                continue
            payload = stable_read(
                child,
                label=f"source tree member {child}",
                maximum=MAX_RELEASE_FILE_BYTES,
                allow_empty=True,
            )
            members.append(
                {
                    "path": child.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
            if len(members) > MAX_TREE_FILES:
                raise ReadSuiteError(f"source tree contains too many files: {root}")
    members.sort(key=lambda item: item["path"])
    return {
        "path": str(root),
        "count": len(members),
        "digest": hashlib.sha256(canonical_json(members)).hexdigest(),
        "algorithm": "canonical-json(path,sha256,size)-sha256-v1",
        "root": {
            "uid": root_metadata.st_uid,
            "gid": root_metadata.st_gid,
            "mode": f"{stat.S_IMODE(root_metadata.st_mode):04o}",
            "device": root_metadata.st_dev,
            "inode": root_metadata.st_ino,
        },
    }


def _systemctl_show(unit: str) -> dict[str, Any]:
    fields = (
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
    )
    completed = subprocess.run(
        [str(SYSTEMCTL), "show", unit, "--no-pager", f"--property={','.join(fields)}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if completed.returncode != 0 or completed.stderr:
        raise ReadSuiteError(f"systemd identity lookup failed: {unit}")
    values: dict[str, str] = {}
    try:
        lines = completed.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise ReadSuiteError(f"systemd identity is not UTF-8: {unit}") from exc
    for line in lines:
        if "=" not in line:
            raise ReadSuiteError(f"systemd identity output is invalid: {unit}")
        key, value = line.split("=", 1)
        if key in values or key not in fields:
            raise ReadSuiteError(f"systemd identity fields are invalid: {unit}")
        values[key] = value
    if set(values) != set(fields) and values.get("LoadState") == "not-found":
        for missing in set(fields) - set(values):
            values[missing] = "0" if missing in {"MainPID", "NRestarts"} else ""
    if set(values) != set(fields):
        raise ReadSuiteError(f"systemd identity fields are incomplete: {unit}")
    fragment: dict[str, Any] | None = None
    if values["FragmentPath"]:
        fragment = _hash_file_snapshot(
            Path(values["FragmentPath"]), label=f"service fragment {unit}"
        )
    dropin_paths = values["DropInPaths"].split() if values["DropInPaths"] else []
    if (
        dropin_paths != sorted(set(dropin_paths))
        or any(not PurePosixPath(item).is_absolute() for item in dropin_paths)
    ):
        raise ReadSuiteError(f"systemd drop-in path set is invalid: {unit}")
    dropins = [
        _hash_file_snapshot(Path(item), label=f"service drop-in {unit}")
        for item in dropin_paths
    ]
    return {
        "unit": unit,
        "properties": values,
        "fragment": fragment,
        "dropins": dropins,
    }


def _v3_unit_absence(unit: str) -> dict[str, Any]:
    identity = _systemctl_show(unit)
    properties = identity["properties"]
    if (
        properties["Id"] != unit
        or unit not in properties["Names"].split()
        or properties["LoadState"] != "not-found"
        or properties["ActiveState"] != "inactive"
        or properties["FragmentPath"]
        or properties["SourcePath"]
        or properties["InvocationID"]
        or properties["DropInPaths"]
        or identity["dropins"]
        or identity["fragment"] is not None
    ):
        raise ReadSuiteError(f"staged V3 unit is present or loaded: {unit}")
    locations = []
    for root in SYSTEMD_ROOTS:
        candidate = root / unit
        present = os.path.lexists(candidate)
        if present:
            raise ReadSuiteError(f"staged V3 unit file exists: {candidate}")
        locations.append({"path": str(candidate), "absent": True})
    return {"unit": unit, "systemd": identity, "locations": locations}


def _required_service_identity(unit: str) -> dict[str, Any]:
    identity = _systemctl_show(unit)
    properties = identity["properties"]
    if (
        properties["Id"] != unit
        or unit not in properties["Names"].split()
        or properties["LoadState"] != "loaded"
        or properties["ActiveState"] != "active"
        or properties["SubState"] != "running"
        or not properties["MainPID"].isdigit()
        or int(properties["MainPID"]) <= 0
        or not properties["ExecMainStartTimestampMonotonic"].isdigit()
        or int(properties["ExecMainStartTimestampMonotonic"]) <= 0
        or re.fullmatch(r"[0-9a-f]{32}", properties["InvocationID"]) is None
        or not properties["NRestarts"].isdigit()
        or not properties["StateChangeTimestampMonotonic"].isdigit()
        or int(properties["StateChangeTimestampMonotonic"]) <= 0
        or not properties["FragmentPath"]
        or identity["fragment"] is None
    ):
        raise ReadSuiteError(f"required systemd service is not continuously running: {unit}")
    return identity


def system_snapshot(plan: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    target = plan["target"]
    runtime_files = []
    for field, digest_field in (
        ("odoo_python", "odoo_python_sha256"),
        ("odoo_bin", "odoo_bin_sha256"),
        ("odoo_config", "odoo_config_sha256"),
    ):
        snapshot = _hash_file_snapshot(
            Path(runtime[field]), label=f"system runtime dependency {field}"
        )
        if snapshot["sha256"] != runtime[digest_field]:
            raise ReadSuiteError(f"system runtime dependency drifted: {field}")
        runtime_files.append({"field": field, **snapshot})
    v2 = [_tree_snapshot(Path(item)) for item in target["v2_roots"]]
    pi_files = [
        _hash_file_snapshot(Path(item), label=f"Pi Bridge control file {item}")
        for item in target["pi_control_files"]
    ]
    current = RELEASE_PARENT.parent / "current"
    if os.path.lexists(current):
        raise ReadSuiteError("V3 current route exists during staged evidence")
    machine_id_path = Path("/etc/machine-id")
    machine_id = stable_read(
        machine_id_path,
        label="machine identity",
        maximum=4096,
        allow_empty=False,
    )
    return {
        "schema_version": 1,
        "host": {
            "expected": target["host"],
            "node": platform.node(),
            "machine_id_sha256": hashlib.sha256(machine_id.strip()).hexdigest(),
            "kernel": platform.release(),
        },
        "runtime_files": runtime_files,
        "v2_roots": v2,
        "pi_control_files": pi_files,
        "services": [_required_service_identity(item) for item in target["services"]],
        "v3": {
            "current": {"path": str(current), "absent": True},
            "units": [_v3_unit_absence(item) for item in target["v3_unit_names"]],
        },
    }


def require_system_continuity(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> None:
    if after != before:
        raise ReadSuiteError("Odoo/Pi/V2/V3 system identity changed")


def _dependency_roots(
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
) -> tuple[Path, ...]:
    paths = _release_paths(expected)
    closure_identity = closure["closure_identity"]
    roots = (
        Path(closure["mount"]["mount_point"]),
        Path(closure_identity["sealed_config_path"]),
        Path(closure_identity["anchor_path"]),
        Path(closure_identity["image_path"]),
        Path(CLOSURE_PYTHON),
        Path(CLOSURE_LDCONFIG),
        paths["root"],
        paths["package"],
        paths["anchor"],
        paths["runtime"],
        Path(runtime["auth_secret_path"]),
        Path(runtime["receipt_secret_path"]),
        *(
            Path(item)
            for item in closure_identity["external_runtime_paths"]
        ),
    )
    normalized: list[Path] = []
    seen: set[str] = set()
    for item in roots:
        text = str(item.absolute())
        if text not in seen:
            normalized.append(item.absolute())
            seen.add(text)
    return tuple(normalized)


def _stream_digest(path: Path, *, label: str) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReadSuiteError(f"{label} cannot be opened safely") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ReadSuiteError(f"{label} is not a one-link regular file")
        identity = _fingerprint(before)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if total > 2 * 1024 * 1024 * 1024:
                raise ReadSuiteError(f"{label} is too large")
        if _fingerprint(os.fstat(descriptor)) != identity:
            raise ReadSuiteError(f"{label} changed during hashing")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), total


def _dependency_entry(path: Path, root: Path) -> dict[str, Any]:
    metadata = path.lstat()
    relative = "." if path == root else path.relative_to(root).as_posix()
    common = {
        "path": relative,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }
    if stat.S_ISREG(metadata.st_mode):
        digest, size = _stream_digest(path, label=f"dependency {path}")
        return {**common, "kind": "file", "sha256": digest, "size": size}
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
    raise ReadSuiteError(f"dependency tree contains an unsafe special object: {path}")


def dependency_snapshot(
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
) -> dict[str, Any]:
    documents = []
    total = 0
    for root in _dependency_roots(runtime, expected, closure):
        metadata = root.lstat()
        entries = [_dependency_entry(root, root)]
        if stat.S_ISDIR(metadata.st_mode) and not root.is_symlink():
            for directory_text, directories, names in os.walk(
                root, topdown=True, followlinks=False
            ):
                directory = Path(directory_text)
                directories.sort()
                names.sort()
                retained: list[str] = []
                for name in directories:
                    child = directory / name
                    entries.append(_dependency_entry(child, root))
                    if not child.is_symlink():
                        retained.append(name)
                directories[:] = retained
                for name in names:
                    entries.append(_dependency_entry(directory / name, root))
                if total + len(entries) > MAX_TREE_FILES:
                    raise ReadSuiteError("dependency snapshot contains too many entries")
        entries.sort(key=lambda item: item["path"])
        total += len(entries)
        documents.append(
            {
                "root": str(root),
                "entry_count": len(entries),
                "manifest_sha256": hashlib.sha256(canonical_json(entries)).hexdigest(),
                "entries": entries,
            }
        )
    return {
        "schema_version": 1,
        "algorithm": "canonical-json-complete-lstat-tree-sha256-v1",
        "root_count": len(documents),
        "entry_count": total,
        "roots": documents,
        "combined_sha256": hashlib.sha256(canonical_json(documents)).hexdigest(),
    }


class DependencyWatch:
    """Recursive Linux inotify guard for every byte used by the read suite."""

    def __init__(self, roots: Sequence[Path]) -> None:
        self.roots = tuple(Path(item).absolute() for item in roots)
        self.fd: int | None = None
        self.watch_count = 0
        self.root_identities: list[dict[str, Any]] = []

    def __enter__(self) -> "DependencyWatch":
        if os.name != "posix" or not sys.platform.startswith("linux"):
            raise ReadSuiteError("dependency inotify guard requires Linux")
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add = libc.inotify_add_watch
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int
        fd = init(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if fd < 0:
            raise ReadSuiteError("inotify dependency guard cannot be initialized")
        self.fd = fd
        try:
            self.root_identities = []
            for root in self.roots:
                metadata = root.lstat()
                self.root_identities.append(
                    {
                        "path": str(root),
                        "device": metadata.st_dev,
                        "inode": metadata.st_ino,
                    }
                )
            watched: set[tuple[int, int]] = set()
            candidates: list[Path] = []
            for root in self.roots:
                candidates.append(root)
                if root.is_dir() and not root.is_symlink():
                    for directory_text, directories, _names in os.walk(
                        root, topdown=True, followlinks=False
                    ):
                        directory = Path(directory_text)
                        directories[:] = sorted(
                            name
                            for name in directories
                            if not (directory / name).is_symlink()
                        )
                        candidates.append(directory)
            for candidate in candidates:
                metadata = candidate.lstat()
                identity = (metadata.st_dev, metadata.st_ino)
                if identity in watched:
                    continue
                watch = add(fd, os.fsencode(candidate), IN_REJECT_MASK)
                if watch < 0:
                    error = ctypes.get_errno()
                    raise ReadSuiteError(
                        f"inotify dependency watch failed: {candidate}: errno {error}"
                    )
                watched.add(identity)
            self.watch_count = len(watched)
            if self.watch_count == 0:
                raise ReadSuiteError("inotify dependency guard installed no watches")
            self.assert_clean()
            return self
        except BaseException:
            os.close(fd)
            self.fd = None
            raise

    def _events(self) -> list[dict[str, Any]]:
        if self.fd is None:
            raise ReadSuiteError("inotify dependency guard is not active")
        import struct

        result: list[dict[str, Any]] = []
        while True:
            try:
                payload = os.read(self.fd, 1024 * 1024)
            except BlockingIOError:
                break
            if not payload:
                break
            offset = 0
            while offset < len(payload):
                if len(payload) - offset < 16:
                    raise ReadSuiteError("inotify dependency event is truncated")
                watch, mask, cookie, name_length = struct.unpack_from("iIII", payload, offset)
                offset += 16
                if name_length > len(payload) - offset:
                    raise ReadSuiteError("inotify dependency name is truncated")
                raw_name = payload[offset : offset + name_length].rstrip(b"\x00")
                offset += name_length
                result.append(
                    {
                        "watch": watch,
                        "mask": mask,
                        "cookie": cookie,
                        "name_sha256": hashlib.sha256(raw_name).hexdigest()
                        if raw_name
                        else None,
                    }
                )
        return result

    def assert_clean(self) -> None:
        events = self._events()
        if any(event["mask"] & IN_REJECT_MASK for event in events):
            raise ReadSuiteError("dependency tree changed while the read suite was active")

    def document(self) -> dict[str, Any]:
        observed = []
        for root in self.roots:
            metadata = root.lstat()
            observed.append(
                {
                    "path": str(root),
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                }
            )
        if observed != self.root_identities:
            raise ReadSuiteError("dependency watch root identity changed")
        return {
            "schema_version": 1,
            "backend": "linux-inotify-recursive",
            "watch_count": self.watch_count,
            "reject_mask": IN_REJECT_MASK,
            "roots": [str(item) for item in self.roots],
            "root_identities": self.root_identities,
            "events_observed": 0,
            "all_checks_passed": True,
        }

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        try:
            if exc_type is None:
                self.assert_clean()
        finally:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
        return False


def _sqlite_inventory(
    path: Path,
    *,
    expected_uid: int | None,
    expected_gid: int | None,
) -> dict[str, Any]:
    path = Path(path).absolute()
    parent = path.parent
    metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
        or (expected_uid is not None and metadata.st_uid != expected_uid)
        or (expected_gid is not None and metadata.st_gid != expected_gid)
    ):
        raise ReadSuiteError(f"SQLite state parent is unsafe: {parent}")
    parent_fingerprint = _fingerprint(metadata)
    allowed_names = {
        path.name,
        f"{path.name}-wal",
        f"{path.name}-shm",
        f"{path.name}.writer.lock",
    }
    entries: dict[str, dict[str, Any]] = {}
    try:
        names = sorted(entry.name for entry in os.scandir(parent))
    except OSError as exc:
        raise ReadSuiteError(f"SQLite state cannot be inventoried: {path}") from exc
    if not set(names).issubset(allowed_names):
        raise ReadSuiteError(f"SQLite state parent contains an unexpected object: {parent}")
    for name in names:
        item = parent / name
        child = item.lstat()
        if (
            item.is_symlink()
            or not stat.S_ISREG(child.st_mode)
            or child.st_nlink != 1
            or (expected_uid is not None and child.st_uid != expected_uid)
            or (expected_gid is not None and child.st_gid != expected_gid)
            or (os.name == "posix" and stat.S_IMODE(child.st_mode) & 0o077)
        ):
            raise ReadSuiteError(f"SQLite state object is unsafe: {item}")
        entries[name] = {
            "path": str(item),
            "size": child.st_size,
            "sha256": hashlib.sha256(
                stable_read(
                    item,
                    label=f"SQLite state object {item}",
                    maximum=128 * 1024 * 1024,
                    allow_empty=True,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
            ).hexdigest(),
            "uid": child.st_uid,
            "gid": child.st_gid,
            "mode": f"{stat.S_IMODE(child.st_mode):04o}",
            "device": child.st_dev,
            "inode": child.st_ino,
            "mtime_ns": child.st_mtime_ns,
            "ctime_ns": child.st_ctime_ns,
        }
    if _fingerprint(parent.lstat()) != parent_fingerprint:
        raise ReadSuiteError(f"SQLite state parent changed during inventory: {parent}")
    return {
        "parent": {
            "path": str(parent),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        },
        "entries": entries,
    }


def _copy_sqlite_snapshot(
    path: Path,
    staging: Path,
    *,
    expected_uid: int | None,
    expected_gid: int | None,
) -> tuple[dict[str, Any], Path | None]:
    """Copy a stable main/WAL/SHM set before opening only the private copy."""

    before = _sqlite_inventory(
        path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    main_name = path.name
    if main_name not in before["entries"]:
        after = _sqlite_inventory(
            path, expected_uid=expected_uid, expected_gid=expected_gid
        )
        if after != before:
            raise ReadSuiteError(f"absent SQLite state changed during snapshot: {path}")
        return before, None
    staging.mkdir(mode=0o700)
    for suffix in SQLITE_SUFFIXES:
        name = f"{main_name}{suffix}"
        if name not in before["entries"]:
            continue
        source = path.parent / name
        payload = stable_read(
            source,
            label=f"live SQLite snapshot member {source}",
            maximum=128 * 1024 * 1024,
            allow_empty=True,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        write_private(staging / name, payload)
        if hashlib.sha256(payload).hexdigest() != before["entries"][name]["sha256"]:
            raise ReadSuiteError(f"SQLite snapshot member digest drifted: {source}")
    after = _sqlite_inventory(
        path, expected_uid=expected_uid, expected_gid=expected_gid
    )
    if after != before:
        raise ReadSuiteError(f"live SQLite state changed during snapshot copy: {path}")
    return before, staging / main_name


def _sqlite_rows(
    copied: Path,
    statements: Mapping[str, tuple[str, tuple[Any, ...]]],
) -> dict[str, list[dict[str, Any]]]:
    connection = sqlite3.connect(
        f"{copied.as_uri()}?mode=ro", uri=True, timeout=0, isolation_level=None
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only = ON")
        if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
            raise ReadSuiteError("private SQLite snapshot is not query-only")
        if str(connection.execute("PRAGMA integrity_check").fetchone()[0]).lower() != "ok":
            raise ReadSuiteError("private SQLite snapshot failed integrity_check")
        return {
            name: [dict(row) for row in connection.execute(sql, parameters).fetchall()]
            for name, (sql, parameters) in statements.items()
        }
    except sqlite3.Error as exc:
        raise ReadSuiteError("private SQLite snapshot query failed") from exc
    finally:
        connection.close()


def _remove_private_tree(path: Path) -> None:
    if not os.path.lexists(path):
        return
    resolved_parent = path.parent.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved.parent != resolved_parent or path.is_symlink():
        raise ReadSuiteError("private staging path escaped its parent")
    for child in path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise ReadSuiteError("private staging contains an unsafe object")
        child.unlink()
    path.rmdir()


def _placeholders(values: Sequence[str]) -> str:
    if not values:
        return "NULL"
    return ",".join("?" for _ in values)


def state_snapshot(
    runtime: dict[str, Any],
    *,
    staging_parent: Path,
    token_ids: Sequence[str] = (),
    receipt_ids: Sequence[str] = (),
    audit_after_sequence: int = 0,
    include_audit_delta: bool = True,
    state_uid: int | None = None,
    state_gid: int | None = None,
) -> dict[str, Any]:
    if (
        any(not isinstance(item, str) or not item for item in (*token_ids, *receipt_ids))
        or len(token_ids) != len(set(token_ids))
        or len(receipt_ids) != len(set(receipt_ids))
        or type(audit_after_sequence) is not int
        or audit_after_sequence < 0
        or type(include_audit_delta) is not bool
    ):
        raise ReadSuiteError("state snapshot selectors are invalid")
    staging_parent.mkdir(mode=0o700)
    auth_stage = staging_parent / "auth"
    receipt_stage = staging_parent / "receipt"
    auth_meta, auth_copy = _copy_sqlite_snapshot(
        Path(runtime["auth_state_path"]),
        auth_stage,
        expected_uid=state_uid,
        expected_gid=state_gid,
    )
    receipt_meta, receipt_copy = _copy_sqlite_snapshot(
        Path(runtime["receipt_state_path"]),
        receipt_stage,
        expected_uid=state_uid,
        expected_gid=state_gid,
    )
    try:
        auth_queries: dict[str, list[dict[str, Any]]] = {}
        if auth_copy is not None:
            auth_queries = _sqlite_rows(
                auth_copy,
                {
                    "count": ("SELECT COUNT(*) AS value FROM consumed_auth_tokens", ()),
                    "selected_tokens": (
                        "SELECT token_id, request_digest, expires_at, consumed_at "
                        f"FROM consumed_auth_tokens WHERE token_id IN ({_placeholders(token_ids)}) "
                        "ORDER BY token_id",
                        tuple(token_ids),
                    ),
                },
            )
        receipt_queries: dict[str, list[dict[str, Any]]] = {}
        if receipt_copy is not None:
            receipt_queries = _sqlite_rows(
                receipt_copy,
                {
                    "receipt_count": ("SELECT COUNT(*) AS value FROM consumed_receipts", ()),
                    "selected_receipts": (
                        "SELECT receipt_id, request_digest, observed_at, consumed_at "
                        f"FROM consumed_receipts WHERE receipt_id IN ({_placeholders(receipt_ids)}) "
                        "ORDER BY receipt_id",
                        tuple(receipt_ids),
                    ),
                    "audit_count": ("SELECT COUNT(*) AS value FROM audit_events", ()),
                    "audit_head": (
                        "SELECT sequence, event_hash FROM audit_events "
                        "ORDER BY sequence DESC LIMIT 1",
                        (),
                    ),
                    "audit_delta": (
                        "SELECT sequence, event_id, event_type, operation_id, occurred_at, "
                        "payload_json, previous_hash, event_hash FROM audit_events "
                        + ("WHERE sequence > ? " if include_audit_delta else "WHERE 0 ")
                        + "ORDER BY sequence",
                        (audit_after_sequence,) if include_audit_delta else (),
                    ),
                },
            )
    finally:
        _remove_private_tree(auth_stage)
        _remove_private_tree(receipt_stage)
        staging_parent.rmdir()
    return {
        "schema_version": 1,
        "auth": {
            "path": runtime["auth_state_path"],
            "live_files": auth_meta,
            "exists": auth_copy is not None,
            "queries": auth_queries,
        },
        "receipt": {
            "path": runtime["receipt_state_path"],
            "live_files": receipt_meta,
            "exists": receipt_copy is not None,
            "queries": receipt_queries,
        },
    }


def sandbox_profile(
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    outer_unit: Mapping[str, Any],
) -> dict[str, Any]:
    writable = outer_unit.get("read_write_paths")
    if type(writable) is not list:
        raise ReadSuiteError("outer unit writable path proof is invalid")
    return {
        "schema_version": 1,
        "execution_model": "single-supervisor-direct-role-children-v1",
        "outer_runner": str(SYSTEMD_RUN),
        "nested_systemd_run_forbidden": True,
        "direct_child_bootstrap": str(_release_paths(expected)["direct_child"]),
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
        "working_directory": str(_release_paths(expected)["root"]),
        "home": "/var/lib/odoo-accounting-cli-v3-broker",
        "read_write_paths": writable,
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


def _validate_direct_child_command(
    role: str,
    command: Sequence[str],
    *,
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
) -> list[str]:
    paths = _release_paths(expected)
    values = list(command)
    prefix = (
        [CLOSURE_PYTHON, "-I", "-S"]
        if role in {"signer", "verifier"}
        else [runtime["odoo_python"], "-I"]
    )
    if len(values) <= len(prefix) or values[: len(prefix)] != prefix:
        raise ReadSuiteError("direct child command must use sealed isolated Odoo Python")
    script = values[len(prefix)]
    arguments = values[len(prefix) + 1 :]
    if role == "odoo" and script == str(paths["launcher"]):
        allowed = (
            arguments == ["release", "identity"]
            or arguments
            == [
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(paths["runtime"]),
                "--timeout-seconds",
                "120",
            ]
            or arguments
            == [
                "read",
                "--runtime-config",
                str(paths["runtime"]),
                "--timeout-seconds",
                "120",
            ]
        )
    elif role == "signer" and script == str(paths["signer"]):
        allowed = (
            len(arguments) == 4
            and arguments[0] in {"--case", "--negative"}
            and arguments[2:] == ["--runtime-config", str(paths["runtime"])]
            and (
                (arguments[0] == "--case" and arguments[1] in POSITIVE_NAMES)
                or (
                    arguments[0] == "--negative"
                    and arguments[1] in set(NEGATIVE_NAMES) - {"replay"}
                )
            )
        )
    elif role == "postgres" and script == str(paths["oracle"]):
        allowed = arguments == ["witness", "--plan", str(paths["plan"])]
        if len(arguments) == 7 and arguments[:4] == [
            "verify",
            "--plan",
            str(paths["plan"]),
            "--case",
        ]:
            allowed = (
                arguments[4] in FINANCIAL_NAMES
                and arguments[5:] == ["--request-stdin", "--response-stdin"]
            )
        elif len(arguments) == 9 and arguments[:4] == [
            "verify",
            "--plan",
            str(paths["plan"]),
            "--case",
        ]:
            request_path = Path(arguments[6]) if arguments[5] == "--request" else None
            response_path = Path(arguments[8]) if arguments[7] == "--response" else None
            allowed = (
                arguments[4] in FINANCIAL_NAMES
                and request_path is not None
                and response_path is not None
                and request_path.name == "request.json"
                and response_path.name == "response.json"
                and request_path.parent == response_path.parent
                and request_path.parent.parent == ORACLE_STAGING_PARENT
                and request_path.parent.name.startswith(
                    "odoo-accounting-cli-v3-dev29-oracle-"
                )
            )
    elif role == "verifier" and script == str(paths["verifier"]):
        allowed = len(arguments) == 29 and arguments[0] == "--validate-only"
        if allowed:
            pairs = arguments[1:]
            values = {
                pairs[index]: pairs[index + 1] for index in range(0, len(pairs), 2)
            }
            allowed = (
                list(values)
                == [
                    "--evidence-dir",
                    "--expected-bundle-manifest-sha256",
                    "--expected-release",
                    "--expected-version",
                    "--expected-commit",
                    "--expected-manifest-sha256",
                    "--expected-package-sha256",
                    "--expected-closure-anchor-sha256",
                    "--expected-closure-image-sha256",
                    "--expected-system-python-sha256",
                    "--expected-ld-so-preload-sha256",
                    "--expected-ldconfig-sha256",
                    "--expected-runtime-open-index-sha256",
                    "--expected-strace-sha256",
                ]
                and Path(values["--evidence-dir"]).parent == EVIDENCE_PARENT
                and EVIDENCE_NAME.fullmatch(Path(values["--evidence-dir"]).name)
                is not None
                and HEX64.fullmatch(values["--expected-bundle-manifest-sha256"])
                is not None
                and values["--expected-release"] == expected.release
                and values["--expected-version"] == expected.version
                and values["--expected-commit"] == expected.commit
                and values["--expected-manifest-sha256"] == expected.manifest_sha256
                and values["--expected-package-sha256"] == expected.package_sha256
                and all(
                    HEX64.fullmatch(values[name]) is not None
                    for name in (
                        "--expected-closure-anchor-sha256",
                        "--expected-closure-image-sha256",
                        "--expected-system-python-sha256",
                        "--expected-ld-so-preload-sha256",
                        "--expected-ldconfig-sha256",
                        "--expected-runtime-open-index-sha256",
                        "--expected-strace-sha256",
                    )
                )
            )
    else:
        allowed = False
    if not allowed:
        raise ReadSuiteError("direct child role/argv is not allowlisted")
    return values


def _direct_child_environment(role: str) -> dict[str, str]:
    homes = {
        "odoo": "/var/lib/odoo-accounting-cli-v3-broker",
        "signer": "/var/lib/odoo-accounting-cli-v3-broker",
        "postgres": "/var/lib/postgresql",
        "verifier": "/root",
    }
    if role not in homes:
        raise ReadSuiteError("direct child role is invalid")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": homes[role],
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if role in {"odoo", "postgres"}:
        environment["ODOO_ACCOUNTING_CLI_V3_EXPECTED_PYTHON"] = (
            "/opt/odoo/odoo19/odoo19-venv/bin/python"
        )
    return environment


def _mountinfo_rows_for(points: Sequence[str]) -> dict[str, dict[str, Any]]:
    wanted = set(points)
    if len(wanted) != len(points):
        raise ReadSuiteError("direct child mount points are not unique")
    result: dict[str, dict[str, Any]] = {}
    for line in _read_virtual_text(
        Path("/proc/self/mountinfo"), label="direct child supervisor mountinfo"
    ).splitlines():
        fields = line.split(" ")
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise ReadSuiteError("direct child supervisor mountinfo is invalid") from exc
        if len(fields) < 10 or separator < 6 or len(fields) <= separator + 3:
            raise ReadSuiteError("direct child supervisor mountinfo row is incomplete")
        mount_point = _mount_unescape(fields[4])
        if mount_point not in wanted:
            continue
        if mount_point in result:
            raise ReadSuiteError("direct child supervisor mount is ambiguous")
        result[mount_point] = {
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
    if set(result) != wanted:
        raise ReadSuiteError("direct child supervisor mount set is incomplete")
    return result


def _expected_direct_child_mounts(closure: Mapping[str, Any]) -> list[dict[str, Any]]:
    root = closure["mount"]["mount_point"]
    bindings = closure["activation"]["bindings"]
    endpoints = [(root, root), *((item["source"], item["destination"]) for item in bindings)]
    rows = _mountinfo_rows_for([destination for _source, destination in endpoints])
    expected: list[dict[str, Any]] = []
    for index, (source_text, destination_text) in enumerate(endpoints):
        source = Path(source_text)
        destination = Path(destination_text)
        try:
            source_metadata = source.stat()
            destination_metadata = destination.stat()
            read_only = bool(
                os.statvfs(destination).f_flag & getattr(os, "ST_RDONLY", 1)
            )
        except OSError as exc:
            raise ReadSuiteError("direct child mount endpoint is unavailable") from exc
        if (
            (source_metadata.st_dev, source_metadata.st_ino)
            != (destination_metadata.st_dev, destination_metadata.st_ino)
            or not read_only
        ):
            raise ReadSuiteError("direct child mount endpoint is not the sealed source")
        row = rows[destination_text]
        value = {
            "source_path": source_text,
            "destination_path": destination_text,
            "source_device": source_metadata.st_dev,
            "source_inode": source_metadata.st_ino,
            "destination_device": destination_metadata.st_dev,
            "destination_inode": destination_metadata.st_ino,
            **row,
            "statvfs_read_only": True,
        }
        if not {"ro", "nodev", "nosuid"}.issubset(value["options"]):
            raise ReadSuiteError("direct child mount is not strict read-only")
        if index == 0:
            if (
                value["mount_source"] != closure["mount"]["loop_device"]
                or value["filesystem_type"] != "squashfs"
            ):
                raise ReadSuiteError("direct child closure root mount identity drifted")
        else:
            binding = bindings[index - 1]
            if (
                value["mount_id"] != binding["mount_id"]
                or value["major_minor"] != binding["major_minor"]
                or value["filesystem_type"] != binding["filesystem_type"]
                or value["source_device"] != binding["source_device"]
                or value["source_inode"] != binding["source_inode"]
            ):
                raise ReadSuiteError("direct child bind identity drifted")
        expected.append(value)
    return expected


def _attested_tree(root: Path, venv_root: Path) -> list[dict[str, Any]]:
    try:
        root = root.resolve(strict=True)
        venv_root = venv_root.resolve(strict=True)
    except OSError as exc:
        raise ReadSuiteError("attested Click tree is unavailable") from exc
    if root == venv_root or venv_root not in root.parents:
        raise ReadSuiteError("attested Click tree escaped the sealed venv")
    entries: list[dict[str, Any]] = []
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
            entries.append({**common, "kind": "directory"})
            pending.extend(
                Path(item.path)
                for item in sorted(
                    os.scandir(path), key=lambda item: item.name, reverse=True
                )
            )
        elif stat.S_ISREG(metadata.st_mode):
            payload = stable_read(
                path,
                label="attested Click tree member",
                maximum=MAX_RELEASE_FILE_BYTES,
                allow_empty=True,
            )
            entries.append(
                {
                    **common,
                    "kind": "regular",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                }
            )
        else:
            raise ReadSuiteError("attested Click tree contains a non-regular object")
        if len(entries) > 10_000:
            raise ReadSuiteError("attested Click tree is unexpectedly large")
    entries.sort(key=lambda item: item["path"])
    return entries


def _validate_child_attestation(
    value: Any,
    *,
    role: str,
    command: Sequence[str],
    runtime: Mapping[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    expected_uid: int,
    expected_gid: int,
    expected_mounts: list[dict[str, Any]],
    environment: Mapping[str, str],
) -> None:
    paths = _release_paths(expected)
    expected_python = (
        CLOSURE_PYTHON if role in {"signer", "verifier"} else runtime["odoo_python"]
    )
    expected_no_site = role in {"signer", "verifier"}
    if (
        type(value) is not dict
        or set(value)
        != {
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
        }
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("role") != role
        or type(value.get("pid")) is not int
        or value["pid"] <= 1
        or value.get("ppid") != os.getpid()
        or value.get("command") != list(command)
        or value.get("command_sha256")
        != hashlib.sha256(canonical_json(list(command))).hexdigest()
        or value.get("self_mount_namespace")
        != closure["mount"]["self_mount_namespace"]
        or value.get("host_mount_namespace")
        != closure["mount"]["host_mount_namespace"]
        or value.get("same_supervisor_namespace") is not True
        or value.get("mounts") != expected_mounts
        or value.get("loop_device") != closure["mount"]["loop_device"]
        or value.get("environment") != dict(environment)
    ):
        raise ReadSuiteError("direct child attestation envelope is invalid")
    python = value["python"]
    if (
        type(python) is not dict
        or set(python) != {"path", "resolved_path", "isolated", "no_site", "sys_path"}
        or python.get("path") != expected_python
        or not isinstance(python.get("resolved_path"), str)
        or python.get("isolated") is not True
        or python.get("no_site") is not expected_no_site
        or type(python.get("sys_path")) is not list
        or not python["sys_path"]
    ):
        raise ReadSuiteError("direct child Python attestation is invalid")
    venv_root = Path(runtime["odoo_python"]).parent.parent.resolve(strict=True)
    external_paths = [
        Path(item) for item in closure["closure_identity"]["external_runtime_paths"]
    ]
    for item in python["sys_path"]:
        if not isinstance(item, str) or not item or not Path(item).is_absolute():
            raise ReadSuiteError("direct child Python path is not canonical")
        candidate = Path(item)
        covered = candidate == venv_root or venv_root in candidate.parents
        covered = covered or item == "/usr/lib/python312.zip"
        covered = covered or any(
            candidate == root or root in candidate.parents for root in external_paths
        )
        if not covered or candidate == paths["root"] or paths["root"] in candidate.parents:
            raise ReadSuiteError("direct child Python path escaped the sealed roots")
    credentials = value["credentials"]
    expected_status = {
        "Uid": " ".join([str(expected_uid)] * 4),
        "Gid": " ".join([str(expected_gid)] * 4),
        "Groups": "",
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
    }
    expected_credentials = {
        "uid": expected_uid,
        "gid": expected_gid,
        "groups": [],
        "status": expected_status,
        "capabilities_all_zero": True,
        "no_new_privileges": True,
    }
    comparable_credentials = credentials
    if type(credentials) is dict and type(credentials.get("status")) is dict:
        comparable_status = dict(credentials["status"])
        for key in ("Uid", "Gid"):
            if isinstance(comparable_status.get(key), str):
                comparable_status[key] = " ".join(comparable_status[key].split())
        comparable_credentials = {
            **credentials,
            "status": comparable_status,
        }
    if comparable_credentials != expected_credentials:
        mismatches: list[dict[str, Any]] = []
        observed_mapping = (
            comparable_credentials if type(comparable_credentials) is dict else {}
        )
        for key in sorted(set(observed_mapping) | set(expected_credentials)):
            observed_item = observed_mapping.get(key)
            expected_item = expected_credentials.get(key)
            if observed_item != expected_item:
                mismatches.append(
                    {
                        "field": key,
                        "observed": observed_item,
                        "expected": expected_item,
                    }
                )
        payload = canonical_json(
            {
                "observed": credentials,
                "expected": expected_credentials,
                "mismatches": mismatches,
            }
        )
        preview = payload[:2048].decode("utf-8", errors="replace")
        raise ReadSuiteError(
            "direct child credential attestation is invalid: "
            f"credential_sha256={hashlib.sha256(payload).hexdigest()} "
            f"credential_preview={preview!r}"
        )
    click = value["click"]
    if role != "odoo":
        if click is not None:
            raise ReadSuiteError("non-Odoo child unexpectedly imported Click")
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
        raise ReadSuiteError("Odoo Click attestation is invalid")
    try:
        origin = Path(click["origin"]).resolve(strict=True)
    except (KeyError, OSError, TypeError) as exc:
        raise ReadSuiteError("Odoo Click origin is invalid") from exc
    if venv_root not in origin.parents or origin.name != "__init__.py":
        raise ReadSuiteError("Odoo Click origin escaped the sealed venv")
    dist_roots = {
        venv_root.joinpath(*PurePosixPath(item["path"]).parts[:4])
        for item in click["tree_entries"]
        if type(item) is dict
        and isinstance(item.get("path"), str)
        and any(part.lower().endswith(".dist-info") for part in PurePosixPath(item["path"]).parts)
    }
    dist_roots = {root for root in dist_roots if root.name.lower().endswith(".dist-info")}
    if len(dist_roots) != 1:
        raise ReadSuiteError("Odoo Click dist-info attestation is ambiguous")
    rebuilt = _attested_tree(origin.parent, venv_root)
    rebuilt.extend(_attested_tree(next(iter(dist_roots)), venv_root))
    rebuilt.sort(key=lambda item: item["path"])
    if rebuilt != click["tree_entries"]:
        raise ReadSuiteError("Odoo Click tree changed after child execution")
    if any(os.path.lexists(path) for path in (paths["root"] / "src" / "click.py", paths["root"] / "src" / "click")):
        raise ReadSuiteError("release source shadows the sealed Click package")


def _child_preexec(uid: int, gid: int) -> Callable[[], None]:
    try:
        maximum_capability = int(
            Path("/proc/sys/kernel/cap_last_cap").read_text("ascii").strip()
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReadSuiteError("kernel capability boundary is unavailable") from exc
    if not 0 <= maximum_capability <= 255:
        raise ReadSuiteError("kernel capability boundary is invalid")

    def apply() -> None:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)

        def prctl(option: int, argument: int = 0) -> None:
            if libc.prctl(option, argument, 0, 0, 0) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))

        os.setsid()
        prctl(1, 9)  # PR_SET_PDEATHSIG, SIGKILL
        if os.getppid() == 1:
            raise OSError("parent died before child credential drop")
        prctl(28, 0x1 | 0x2)  # SECBIT_NOROOT | SECBIT_NOROOT_LOCKED
        prctl(47, 4)  # PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL
        for capability in range(maximum_capability + 1):
            prctl(24, capability)  # PR_CAPBSET_DROP
        os.setgroups([])
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)

        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

        class Data(ctypes.Structure):
            _fields_ = [
                ("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32),
            ]

        header = Header(0x20080522, 0)
        data = (Data * 2)()
        if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        prctl(47, 4)
        prctl(38, 1)  # PR_SET_NO_NEW_PRIVS

    return apply


def _unit_cgroup_snapshot() -> dict[str, Any]:
    try:
        rows = Path("/proc/self/cgroup").read_text("ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ReadSuiteError("unit cgroup identity is unavailable") from exc
    if len(rows) != 1 or not rows[0].startswith("0::"):
        raise ReadSuiteError("Dev29 requires a unified cgroup v2 unit")
    relative = rows[0][3:]
    portable = PurePosixPath(relative)
    if (
        not portable.is_absolute()
        or str(portable) != relative
        or relative == "/"
        or any(part in {"", ".", ".."} for part in portable.parts[1:])
    ):
        raise ReadSuiteError("Dev29 unit cgroup path is invalid")
    root = Path("/sys/fs/cgroup").resolve(strict=True)
    directory = root.joinpath(*portable.parts[1:]).resolve(strict=True)
    if root not in directory.parents:
        raise ReadSuiteError("Dev29 unit cgroup escaped cgroupfs")
    processes: set[int] = set()
    subtree: list[dict[str, Any]] = []
    try:
        for directory_text, names, files in os.walk(directory, topdown=True, followlinks=False):
            current = Path(directory_text)
            names.sort()
            if "cgroup.procs" not in files:
                raise ReadSuiteError("Dev29 unit cgroup subtree is invalid")
            for name in names:
                child = current / name
                if child.is_symlink() or not child.is_dir():
                    raise ReadSuiteError("Dev29 unit cgroup subtree is unsafe")
            current_metadata = current.stat()
            current_processes = sorted(
                {
                    int(item)
                    for item in (current / "cgroup.procs").read_text("ascii").splitlines()
                    if item
                }
            )
            processes.update(current_processes)
            subtree.append(
                {
                    "path": "/" if current == directory else current.relative_to(directory).as_posix(),
                    "device": current_metadata.st_dev,
                    "inode": current_metadata.st_ino,
                    "processes": current_processes,
                }
            )
        metadata = directory.stat()
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReadSuiteError("Dev29 unit cgroup process set is unavailable") from exc
    if len(subtree) != 1:
        raise ReadSuiteError("Dev29 unit cgroup must not contain delegated child cgroups")
    processes = sorted(processes)
    if os.getpid() not in processes or any(process <= 1 for process in processes):
        raise ReadSuiteError("Dev29 unit cgroup process set is invalid")
    return {
        "version": 2,
        "relative_path": relative,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "processes": processes,
        "subtree": subtree,
    }


def _same_cgroup_identity(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return all(
        left.get(field) == right.get(field)
        for field in ("version", "relative_path", "device", "inode")
    ) and [
        {key: item[key] for key in ("path", "device", "inode")}
        for item in left.get("subtree", [])
    ] == [
        {key: item[key] for key in ("path", "device", "inode")}
        for item in right.get("subtree", [])
    ]


def _cleanup_cgroup_descendants(
    baseline: Mapping[str, Any],
    *,
    deadline_seconds: float = 5.0,
    natural_exit_grace_seconds: float = 0.25,
) -> tuple[dict[str, Any], list[int]]:
    baseline_processes = set(baseline["processes"])
    deadline = time.monotonic() + deadline_seconds
    natural_exit_deadline = time.monotonic() + natural_exit_grace_seconds
    observed: set[int] = set()
    while True:
        current = _unit_cgroup_snapshot()
        if not _same_cgroup_identity(baseline, current):
            raise ReadSuiteError("Dev29 unit cgroup identity changed during child execution")
        unexpected = set(current["processes"]) - baseline_processes
        if not unexpected:
            return current, sorted(observed)
        if time.monotonic() < natural_exit_deadline:
            time.sleep(0.02)
            continue
        observed.update(unexpected)
        for process in unexpected:
            try:
                descriptor = os.pidfd_open(process, 0)
            except ProcessLookupError:
                continue
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            finally:
                os.close(descriptor)
        if time.monotonic() >= deadline:
            raise ReadSuiteError("direct child left descendants in the unit cgroup")
        time.sleep(0.02)


def _process_set_sha256(processes: Sequence[int]) -> str:
    return hashlib.sha256(canonical_json(list(processes))).hexdigest()


def _direct_child_failure_context(returncode: int | None, stderr: bytes) -> str:
    try:
        preview = stderr[:512].decode("utf-8", "replace")
    except AttributeError:
        preview = ""
    preview = preview.replace("\n", "\\n")
    return (
        f"returncode={returncode} stderr_sha256={hashlib.sha256(stderr).hexdigest()} "
        f"stderr_preview={preview!r}"
    )


def _dedicated_supervisor_processes(processes: Sequence[int]) -> bool:
    current = os.getpid()
    parent = os.getppid()
    allowed = ({current}, {current, parent} if parent > 1 else {current})
    return set(processes) in allowed


def _communicate_direct_child(
    process: subprocess.Popen[bytes],
    *,
    read_fd: int,
    write_fd: int,
    stdin: bytes,
    timeout: int,
    baseline_cgroup: Mapping[str, Any],
    role: str,
    command_values: Sequence[str],
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    expected_uid: int,
    expected_gid: int,
    expected_mounts: Sequence[Mapping[str, Any]],
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[bytes]:
    chunks: list[bytes] = []
    read_error: list[BaseException] = []

    def drain_attestation() -> None:
        total = 0
        try:
            while True:
                chunk = os.read(read_fd, 64 * 1024)
                if not chunk:
                    return
                total += len(chunk)
                if total > 4 * 1024 * 1024:
                    raise ReadSuiteError("direct child attestation is too large")
                chunks.append(chunk)
        except BaseException as exc:
            read_error.append(exc)
        finally:
            os.close(read_fd)

    os.close(write_fd)
    reader = threading.Thread(target=drain_attestation, daemon=True)
    reader.start()
    try:
        stdout, stderr = process.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        final_cgroup, _killed = _cleanup_cgroup_descendants(baseline_cgroup)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired as cleanup_exc:
            raise ReadSuiteError(
                "timed-out direct child retained inherited pipes"
            ) from cleanup_exc
        reader.join(5)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise ReadSuiteError(
                "timed-out direct child left a process-group survivor"
            ) from exc
        if set(final_cgroup["processes"]) != set(baseline_cgroup["processes"]):
            raise ReadSuiteError(
                "timed-out direct child left a unit-cgroup survivor"
            ) from exc
        raise ReadSuiteError(
            "direct child timed out and its process group was killed"
        ) from exc
    reader.join(5)
    if reader.is_alive() or read_error:
        raise ReadSuiteError("direct child attestation pipe did not close cleanly")
    attestation_payload = b"".join(chunks)
    if not attestation_payload:
        raise ReadSuiteError(
            "direct child attestation is absent: "
            + _direct_child_failure_context(process.returncode, stderr)
        )
    try:
        attestation = load_json_bytes(
            attestation_payload, label="direct child attestation", canonical=True
        )
    except ReadSuiteError as exc:
        raise ReadSuiteError(
            "direct child attestation is invalid: "
            + _direct_child_failure_context(process.returncode, stderr)
        ) from exc
    final_cgroup, observed_descendants = _cleanup_cgroup_descendants(baseline_cgroup)
    if observed_descendants:
        raise ReadSuiteError("completed direct child left descendants in the unit cgroup")
    _validate_child_attestation(
        attestation,
        role=role,
        command=command_values,
        runtime=runtime,
        expected=expected,
        closure=closure,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mounts=expected_mounts,
        environment=environment,
    )
    completed = subprocess.CompletedProcess(
        list(command_values), process.returncode, stdout, stderr
    )
    completed.dev29_attestation = attestation  # type: ignore[attr-defined]
    completed.dev29_process_control = {  # type: ignore[attr-defined]
        "schema_version": 1,
        "execution_model": "direct-fork-exec",
        "nested_systemd_run_used": False,
        "new_process_group": True,
        "parent_death_signal": "SIGKILL",
        "timeout_kills_process_group": True,
        "timeout_observed": False,
        "leader_waited_and_reaped": True,
        "unit_cgroup": {
            "version": baseline_cgroup["version"],
            "relative_path": baseline_cgroup["relative_path"],
            "device": baseline_cgroup["device"],
            "inode": baseline_cgroup["inode"],
            "subtree_directory_count": len(baseline_cgroup["subtree"]),
            "subtree_identity_sha256": hashlib.sha256(
                canonical_json(
                    [
                        {key: item[key] for key in ("path", "device", "inode")}
                        for item in baseline_cgroup["subtree"]
                    ]
                )
            ).hexdigest(),
            "baseline_process_count": len(baseline_cgroup["processes"]),
            "baseline_processes_sha256": _process_set_sha256(
                baseline_cgroup["processes"]
            ),
            "final_process_count": len(final_cgroup["processes"]),
            "final_processes_sha256": _process_set_sha256(final_cgroup["processes"]),
            "baseline_equals_final": (
                baseline_cgroup["processes"] == final_cgroup["processes"]
            ),
            "unexpected_descendant_count": len(observed_descendants),
            "unexpected_descendants_sha256": _process_set_sha256(
                observed_descendants
            ),
        },
    }
    return completed


def _run_direct_child(
    role: str,
    command: Sequence[str],
    *,
    trace_target_id: str,
    trace_gate: RuntimeTraceGate,
    stdin: bytes,
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    if os.name != "posix" or os.geteuid() != 0:
        raise ReadSuiteError("direct role runner requires the root POSIX supervisor")
    if closure["activation"].get("systemd_run_forbidden") is not True:
        raise ReadSuiteError("closure does not forbid nested systemd-run")
    command_values = _validate_direct_child_command(
        role, command, runtime=runtime, expected=expected
    )
    import grp
    import pwd

    account = {"odoo": "odoo", "signer": "odoo", "postgres": "postgres", "verifier": "root"}.get(role)
    if account is None:
        raise ReadSuiteError("direct child role is invalid")
    identity = pwd.getpwnam(account)
    group = grp.getgrnam(account)
    if identity.pw_gid != group.gr_gid:
        raise ReadSuiteError("direct child service account primary group drifted")
    paths = _release_paths(expected)
    self_namespace = closure["mount"]["self_mount_namespace"]
    host_namespace = closure["mount"]["host_mount_namespace"]
    expected_mounts = _expected_direct_child_mounts(closure)
    baseline_cgroup = _unit_cgroup_snapshot()
    if not _dedicated_supervisor_processes(baseline_cgroup["processes"]):
        raise ReadSuiteError("Dev29 unit cgroup is not dedicated to the sole supervisor")
    read_fd, pipe_write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        os.fstat(TRACE_ATTESTATION_FD)
    except OSError:
        pass
    else:
        os.close(read_fd)
        os.close(pipe_write_fd)
        raise ReadSuiteError("fixed runtime-trace attestation descriptor is occupied")
    os.dup2(pipe_write_fd, TRACE_ATTESTATION_FD, inheritable=True)
    os.close(pipe_write_fd)
    write_fd = TRACE_ATTESTATION_FD
    child_python = CLOSURE_PYTHON if role in {"signer", "verifier"} else runtime["odoo_python"]
    bootstrap = [
        child_python,
        "-I",
        *(["-S"] if role in {"signer", "verifier"} else []),
        str(paths["direct_child"]),
        "--role",
        role,
        "--attestation-fd",
        str(write_fd),
        "--expected-uid",
        str(identity.pw_uid),
        "--expected-gid",
        str(group.gr_gid),
        "--expected-python",
        child_python,
        "--expected-venv-root",
        str(Path(runtime["odoo_python"]).parent.parent),
        "--release-root",
        str(paths["root"]),
        "--expected-self-namespace-device",
        str(self_namespace["device"]),
        "--expected-self-namespace-inode",
        str(self_namespace["inode"]),
        "--expected-host-namespace-device",
        str(host_namespace["device"]),
        "--expected-host-namespace-inode",
        str(host_namespace["inode"]),
        "--expected-loop-device",
        closure["mount"]["loop_device"],
    ]
    for item in expected_mounts:
        bootstrap.extend(
            ("--expected-mount-json", canonical_json(item).decode("utf-8"))
        )
    bootstrap.extend(("--", *command_values))
    environment = _direct_child_environment(role)
    try:
        return trace_gate.execute(
            trace_target_id,
            bootstrap,
            command_values,
            inherited_fds=(write_fd,),
            callback=lambda process: _communicate_direct_child(
                process,
                read_fd=read_fd,
                write_fd=write_fd,
                stdin=stdin,
                timeout=timeout,
                baseline_cgroup=baseline_cgroup,
                role=role,
                command_values=command_values,
                runtime=runtime,
                expected=expected,
                closure=closure,
                expected_uid=identity.pw_uid,
                expected_gid=group.gr_gid,
                expected_mounts=expected_mounts,
                environment=environment,
            ),
        )
    except BaseException:
        for descriptor in (read_fd, write_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _run_odoo_isolated(
    command: Sequence[str],
    *,
    trace_target_id: str,
    trace_gate: RuntimeTraceGate,
    stdin: bytes,
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    timeout: int = 180,
) -> subprocess.CompletedProcess[bytes]:
    return _run_direct_child(
        "odoo",
        command,
        trace_target_id=trace_target_id,
        trace_gate=trace_gate,
        stdin=stdin,
        runtime=runtime,
        expected=expected,
        closure=closure,
        timeout=timeout,
    )


def _run_postgres(
    command: Sequence[str],
    *,
    trace_target_id: str,
    trace_gate: RuntimeTraceGate,
    stdin: bytes = b"",
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    timeout: int = 180,
) -> subprocess.CompletedProcess[bytes]:
    return _run_direct_child(
        "postgres",
        command,
        trace_target_id=trace_target_id,
        trace_gate=trace_gate,
        stdin=stdin,
        runtime=runtime,
        expected=expected,
        closure=closure,
        timeout=timeout,
    )


def _run_signer(
    command: Sequence[str],
    *,
    trace_target_id: str,
    trace_gate: RuntimeTraceGate,
    stdin: bytes,
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    timeout: int = 60,
) -> subprocess.CompletedProcess[bytes]:
    return _run_direct_child(
        "signer",
        command,
        trace_target_id=trace_target_id,
        trace_gate=trace_gate,
        stdin=stdin,
        runtime=runtime,
        expected=expected,
        closure=closure,
        timeout=timeout,
    )


def _write_completed(directory: Path, prefix: str, result: subprocess.CompletedProcess[bytes]) -> None:
    write_private(directory / f"{prefix}.stdout", result.stdout)
    write_private(directory / f"{prefix}.stderr", result.stderr)
    write_private(directory / f"{prefix}.exit", f"{result.returncode}\n".encode("ascii"))
    attestation = getattr(result, "dev29_attestation", None)
    process_control = getattr(result, "dev29_process_control", None)
    if (attestation is None) is not (process_control is None):
        raise ReadSuiteError("direct child evidence is incomplete")
    if attestation is not None:
        write_json(directory / f"{prefix}.child.json", attestation)
        write_json(directory / f"{prefix}.process-control.json", process_control)


def _mkdir_private(path: Path) -> None:
    os.mkdir(path, 0o700)
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ReadSuiteError(f"private evidence directory is unsafe: {path}")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ReadSuiteError(f"private evidence directory mode is invalid: {path}")


def _strict_success(result: subprocess.CompletedProcess[bytes], *, label: str) -> dict[str, Any]:
    if result.returncode != 0 or result.stderr:
        raise ReadSuiteError(f"{label} did not return clean success")
    return load_json_bytes(result.stdout, label=label, canonical=True)


def _strict_negative(
    result: subprocess.CompletedProcess[bytes],
    *,
    label: str,
    expected_rejection_code: str,
) -> dict[str, Any]:
    if result.returncode != 6 or result.stdout or not result.stderr:
        raise ReadSuiteError(f"{label} did not fail closed")
    failure = load_json_bytes(result.stderr, label=label, canonical=True)
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
        raise ReadSuiteError(f"{label} failure envelope is invalid")
    if _contains_key(failure, "receipt") or _contains_key(failure, "result"):
        raise ReadSuiteError(f"{label} leaked a business result or receipt")
    return failure


def _contains_key(value: Any, key: str) -> bool:
    if type(value) is dict:
        return key in value or any(_contains_key(item, key) for item in value.values())
    if type(value) is list:
        return any(_contains_key(item, key) for item in value)
    return False


def _validate_positive_response(
    response: dict[str, Any],
    request: dict[str, Any],
    runtime: dict[str, Any],
    release_identity: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    data = response.get("data") if type(response) is dict else None
    if (
        set(response) != {"command", "data", "ok"}
        or response.get("command") != "read"
        or response.get("ok") is not True
        or type(data) is not dict
        or set(data) != {"capability_id", "release_identity", "result", "runtime"}
        or data.get("capability_id") != request.get("capability_id")
        or data.get("release_identity") != release_identity
        or data.get("runtime")
        != {
            "capability_channel": runtime["capability_channel"],
            "database_name": runtime["database_name"],
            "database_uuid": runtime["database_uuid"],
            "environment": runtime["environment"],
            "instance_id": runtime["instance_id"],
        }
        or type(data.get("result")) is not dict
    ):
        raise ReadSuiteError("positive CLI response binding is invalid")
    receipt = data["result"].get("receipt")
    if type(receipt) is not dict or not isinstance(receipt.get("id"), str) or not receipt["id"]:
        raise ReadSuiteError("positive CLI response has no receipt")
    return data["result"], receipt


def _validate_registry_result(case: dict[str, Any], result: dict[str, Any]) -> None:
    capabilities = result.get("capabilities")
    page = result.get("page")
    expected = case["expected"].get("capabilities")
    if (
        type(capabilities) is not list
        or type(page) is not dict
        or page != {"count": 5, "total_count": 5}
        or type(expected) is not list
        or len(capabilities) != len(expected) != 0
    ):
        raise ReadSuiteError("registry positive result shape is invalid")
    projected = [
        {
            key: item.get(key)
            for key in (
                "id",
                "contract_digest",
                "domain",
                "access",
                "risk_level",
                "company_scope",
                "odoo_permissions",
            )
        }
        for item in capabilities
    ]
    if projected != expected:
        raise ReadSuiteError("registry positive result does not match the fixed plan")


def _request_token(request: dict[str, Any]) -> str:
    context = request.get("context") if type(request) is dict else None
    token = context.get("auth_token_id") if type(context) is dict else None
    if not isinstance(token, str) or not token.startswith("dev29-read-"):
        raise ReadSuiteError("signed request has no Dev29 authentication token")
    return token


def _oracle_staging(
    request_bytes: bytes,
    response_bytes: bytes,
    *,
    release: str,
    case_name: str,
    uid: int,
    gid: int,
) -> tuple[Path, Path, Path]:
    parent = ORACLE_STAGING_PARENT
    if EVIDENCE_NAME.fullmatch(release) is None or case_name not in FINANCIAL_NAMES:
        raise ReadSuiteError("Oracle staging identity is invalid")
    path = parent / f"odoo-accounting-cli-v3-dev29-oracle-{release}-{case_name}"
    os.mkdir(path, 0o700)
    if os.name == "posix":
        os.chown(path, uid, gid)
        os.chmod(path, 0o700)
    request = path / "request.json"
    response = path / "response.json"
    write_private(request, request_bytes)
    write_private(response, response_bytes)
    if os.name == "posix":
        for item in (request, response):
            os.chown(item, uid, gid)
            os.chmod(item, 0o400)
    return path, request, response


def _cleanup_oracle_staging(path: Path) -> None:
    if path.parent != ORACLE_STAGING_PARENT or not path.name.startswith(
        "odoo-accounting-cli-v3-dev29-oracle-"
    ):
        raise ReadSuiteError("Oracle staging path is unsafe")
    for child in path.iterdir():
        if child.is_symlink() or not child.is_file():
            raise ReadSuiteError("Oracle staging contains an unsafe object")
        child.unlink()
    path.rmdir()


def run_oracle_verify(
    paths: Mapping[str, Path],
    runtime: dict[str, Any],
    expected: ExpectedIdentity,
    closure: Mapping[str, Any],
    *,
    trace_gate: RuntimeTraceGate,
    case_name: str,
    request_bytes: bytes,
    response_bytes: bytes,
    postgres_uid: int,
    postgres_gid: int,
) -> subprocess.CompletedProcess[bytes]:
    try:
        stdin = canonical_json(
            {
                "schema_version": 1,
                "request": json.loads(request_bytes),
                "response": json.loads(response_bytes),
            }
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ReadSuiteError("Oracle stdin payload is invalid") from exc
    if len(stdin) > 32 * 1024 * 1024:
        raise ReadSuiteError("Oracle stdin payload exceeds the fixed boundary")
    return _run_postgres(
        [
            runtime["odoo_python"],
            "-I",
            str(paths["oracle"]),
            "verify",
            "--plan",
            str(paths["plan"]),
            "--case",
            case_name,
            "--request-stdin",
            "--response-stdin",
        ],
        trace_target_id=f"positive-{case_name}-oracle",
        trace_gate=trace_gate,
        stdin=stdin,
        runtime=runtime,
        expected=expected,
        closure=closure,
        timeout=180,
    )


def _validate_oracle_result(
    value: dict[str, Any],
    *,
    case: Mapping[str, Any],
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    plan: Mapping[str, Any],
    runtime: Mapping[str, Any],
    witness: Mapping[str, Any],
) -> None:
    case_name = case["name"]
    result = response["data"]["result"]
    body = {key: item for key, item in result.items() if key != "receipt"}
    page = body.get("page")
    expected_metrics = {
        key: item
        for key, item in case["expected"].items()
        if key != "historical_source"
    }
    expected_checks = {
        "business_result",
        *(f"golden_{key}" for key in expected_metrics),
        "signed_receipt_binding",
        "nonempty_business_result",
    }
    expected_access = {
        "user_id": case["user_id"],
        "company_id": case["company_id"],
        "company_member": True,
        "required_group": "account.group_account_readonly",
        "required_group_member": True,
    }
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
        or case_name not in FINANCIAL_NAMES
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("command") != "verify"
        or value.get("case") != case_name
        or value.get("capability_id") != case["capability_id"]
        or value.get("all_checks_passed") is not True
        or value.get("checks") != {name: True for name in expected_checks}
        or value.get("database") != witness["database"]
        or value.get("endpoint") != witness["endpoint"]
        or value.get("relation_schema_sha256") != expected_relation_schema
        or value.get("access") != expected_access
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
        != hashlib.sha256(
            canonical_json(response["data"]["release_identity"])
        ).hexdigest()
        or value.get("fixture_gaps") != []
        or value.get("odoo_action_performed") is not False
        or value.get("database_writes_permitted") is not False
        or value.get("production_validated") is not False
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
        or witness["database"].get("current_database") != plan["database"]["name"]
        or witness["database"].get("database_uuid") != plan["database"]["uuid"]
    ):
        raise ReadSuiteError(f"financial Oracle did not prove the fixed case: {case_name}")


def _validate_witness(
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
        or not _schema_version_is_one(value.get("schema_version"))
        or value.get("command") != "witness"
        or value.get("all_checks_passed") is not True
        or value.get("fixture_gaps") != []
        or value.get("contains_raw_rows") is not False
        or value.get("contains_credentials") is not False
        or value.get("odoo_action_performed") is not False
        or value.get("database_writes_permitted") is not False
        or value.get("production_validated") is not False
        or type(transaction) is not dict
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
        raise ReadSuiteError("PostgreSQL witness is not rollback-only or complete")
    expected_database = plan["database"]
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
        raise ReadSuiteError("PostgreSQL witness identity is invalid")
    try:
        started = datetime.fromisoformat(
            database["postmaster_started_at"].replace("Z", "+00:00")
        )
    except (AttributeError, ValueError) as exc:
        raise ReadSuiteError("PostgreSQL postmaster start identity is invalid") from exc
    if started.tzinfo is None or started.utcoffset() is None:
        raise ReadSuiteError("PostgreSQL postmaster start identity is invalid")
    relations = value.get("relations")
    planned = {item["name"]: item for item in plan["witness"]["relations"]}
    if type(relations) is not list or [item.get("name") for item in relations] != list(
        planned
    ):
        raise ReadSuiteError("PostgreSQL witness relation set is invalid")
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
            or not isinstance(relation.get("schema_sha256"), str)
            or HEX64.fullmatch(relation["schema_sha256"]) is None
            or not isinstance(relation.get("row_stream_sha256"), str)
            or HEX64.fullmatch(relation["row_stream_sha256"]) is None
        ):
            raise ReadSuiteError("PostgreSQL witness relation is invalid")


def _validate_boundary(
    response: dict[str, Any], runtime: dict[str, Any], release_identity: dict[str, Any]
) -> None:
    data = response.get("data")
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
        raise ReadSuiteError("D11 CLI envelope is invalid")
    evidence = data["evidence"]
    if (
        evidence.get("schema_version")
        != "odoo-accounting-cli-v3.read-boundary-evidence.v1"
        or evidence.get("database", {}).get("before", {}).get("name")
        != runtime["database_name"]
        or evidence.get("database", {}).get("before", {}).get("uuid")
        != runtime["database_uuid"]
        or evidence.get("database", {}).get("before")
        != evidence.get("database", {}).get("after")
        or evidence.get("write_probe")
        != {
            "idle_after_rollback": True,
            "rejected": True,
            "sqlstate": "25006",
            "statement_id": "ir-config-parameter-noop-update-v1",
        }
    ):
        raise ReadSuiteError("D11 read boundary evidence is invalid")
    probes = evidence.get("drift_probes")
    if type(probes) is not dict or set(probes) != {
        "hidden_commit",
        "hidden_rollback",
        "rollback_hook_reopen",
    }:
        raise ReadSuiteError("D11 drift probe set is invalid")
    hashes = set()
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
            raise ReadSuiteError("D11 drift probe is invalid")
        hashes.add(probe["canary_sha256"])
    if len(hashes) != 3:
        raise ReadSuiteError("D11 canary hashes are not distinct")


def _count(snapshot: dict[str, Any], store: str, query: str) -> int:
    rows = snapshot[store]["queries"].get(query, [])
    if not rows:
        return 0
    if len(rows) != 1 or set(rows[0]) != {"value"} or type(rows[0]["value"]) is not int:
        raise ReadSuiteError(f"state count query is invalid: {store}.{query}")
    return rows[0]["value"]


def _audit_hash(row: dict[str, Any]) -> str:
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


def _state_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ReadSuiteError(f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReadSuiteError(f"{label} is not a timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReadSuiteError(f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def verify_state_delta(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    requests: Mapping[str, dict[str, Any]],
    receipts: Mapping[str, dict[str, Any]],
    suite_started_at: str,
    observed_not_after: str,
) -> dict[str, Any]:
    suite_started = _state_timestamp(suite_started_at, label="suite started_at")
    observed_upper = _state_timestamp(
        observed_not_after, label="state observation upper bound"
    )
    if observed_upper < suite_started:
        raise ReadSuiteError("state observation window is invalid")
    positive_tokens = {name: _request_token(requests[name]) for name in POSITIVE_NAMES}
    acl_token = _request_token(requests["acl_deny"])
    expected_tokens = set(positive_tokens.values()) | {acl_token}
    auth_before = _count(before, "auth", "count")
    auth_after = _count(after, "auth", "count")
    receipt_before = _count(before, "receipt", "receipt_count")
    receipt_after = _count(after, "receipt", "receipt_count")
    audit_before = _count(before, "receipt", "audit_count")
    audit_after = _count(after, "receipt", "audit_count")
    if (
        auth_after - auth_before != 6
        or receipt_after - receipt_before != 5
        or audit_after - audit_before != 5
    ):
        raise ReadSuiteError("SQLite auth/receipt/audit count delta is invalid")
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
        raise ReadSuiteError("SQLite consumed authentication token set is invalid")
    request_by_token = {
        _request_token(request): request
        for name, request in requests.items()
        if name != "replay"
    }
    for row in token_rows:
        request = request_by_token[row["token_id"]]
        context = request["context"]
        issued = _state_timestamp(context["auth_issued_at"], label="auth issued_at")
        expires = _state_timestamp(context["auth_expires_at"], label="auth expires_at")
        consumed = _state_timestamp(row["consumed_at"], label="auth consumed_at")
        if (
            row["request_digest"]
            != hashlib.sha256(canonical_json(request)).hexdigest()
            or row["expires_at"] != context["auth_expires_at"]
            or not issued <= consumed < expires
            or not suite_started <= consumed <= observed_upper
        ):
            raise ReadSuiteError("SQLite authentication token request digest is invalid")
    receipt_rows = after["receipt"]["queries"].get("selected_receipts", [])
    receipt_by_id = {item["id"]: item for item in receipts.values()}
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
        raise ReadSuiteError("SQLite consumed receipt set is invalid")
    for row in receipt_rows:
        receipt = receipt_by_id[row["receipt_id"]]
        request = request_by_receipt[row["receipt_id"]]
        observed = _state_timestamp(receipt["observed_at"], label="receipt observed_at")
        consumed = _state_timestamp(row["consumed_at"], label="receipt consumed_at")
        expires = _state_timestamp(
            request["context"]["auth_expires_at"], label="receipt auth expires_at"
        )
        if (
            row["request_digest"] != receipt["request_digest"]
            or row["observed_at"] != receipt["observed_at"]
            or not observed <= consumed < expires
            or not suite_started <= observed <= consumed <= observed_upper
        ):
            raise ReadSuiteError("SQLite consumed receipt binding is invalid")
    delta = after["receipt"]["queries"].get("audit_delta", [])
    if len(delta) != 5:
        raise ReadSuiteError("SQLite read audit delta is invalid")
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
        raise ReadSuiteError("SQLite pre-run audit head is invalid")
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
            raise ReadSuiteError("SQLite audit hash chain is invalid")
        payload = load_json_bytes(
            row["payload_json"].encode("utf-8"), label="SQLite audit payload"
        )
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
            <= _state_timestamp(row["occurred_at"], label="audit occurred_at")
            <= observed_upper
        ):
            raise ReadSuiteError("SQLite audit receipt binding is invalid")
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
        raise ReadSuiteError("SQLite post-run audit head is invalid")
    return {
        "auth_token_delta": 6,
        "receipt_delta": 5,
        "audit_event_delta": 5,
        "positive_tokens": positive_tokens,
        "acl_denial_token": acl_token,
        "receipt_ids": {name: receipt["id"] for name, receipt in receipts.items()},
        "all_checks_passed": True,
    }


def _iter_bundle_files(evidence: Path) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for directory_text, directories, names in os.walk(
        evidence, topdown=True, followlinks=False
    ):
        directory = Path(directory_text)
        directories.sort()
        names.sort()
        for name in directories:
            child = directory / name
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise ReadSuiteError(f"unsafe bundle directory: {child}")
        for name in names:
            child = directory / name
            relative = child.relative_to(evidence).as_posix()
            metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ReadSuiteError(f"unsafe bundle file: {relative}")
            files.append((relative, child))
    files.sort(key=lambda item: item[0])
    return files


def assert_no_secret_leak(evidence: Path, secrets: Sequence[bytes]) -> None:
    patterns: list[bytes] = []
    for secret in secrets:
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise ReadSuiteError("runtime secret length is invalid")
        patterns.extend(
            (
                secret,
                secret.hex().encode("ascii"),
                base64.b64encode(secret),
                base64.urlsafe_b64encode(secret),
            )
        )
    for relative, path in _iter_bundle_files(evidence):
        payload = stable_read(
            path,
            label=f"bundle leak scan {relative}",
            maximum=MAX_JSON_BYTES,
            allow_empty=True,
        )
        if any(pattern and pattern in payload for pattern in patterns):
            raise ReadSuiteError(f"raw runtime secret leaked into evidence: {relative}")


def freeze_bundle(
    evidence: Path,
    *,
    expected: ExpectedIdentity,
    plan_sha256: str,
    runtime_sha256: str,
    release_identity: dict[str, Any],
    closure_verification: Mapping[str, Any],
    token_ids: Mapping[str, str],
    receipt_ids: Mapping[str, str],
    runtime_open_trace_sha256: str,
    runtime_open_trace_private: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    evidence = Path(evidence).absolute()
    if evidence.parent != EVIDENCE_PARENT or EVIDENCE_NAME.fullmatch(evidence.name) is None:
        raise ReadSuiteError("bundle path escaped the fixed evidence parent")
    manifest_path = evidence / "BUNDLE-MANIFEST.json"
    if os.path.lexists(manifest_path):
        raise ReadSuiteError("bundle manifest already exists")
    entries = []
    for relative, path in _iter_bundle_files(evidence):
        payload = stable_read(
            path,
            label=f"bundle member {relative}",
            maximum=MAX_JSON_BYTES,
            allow_empty=True,
        )
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    manifest = {
        "schema_version": 1,
        "bundle_type": "odoo-accounting-cli-v3.dev29.read-suite-evidence",
        "evidence_name": evidence.name,
        "evidence_path": str(evidence),
        "release_identity": release_identity,
        "closure_identity": closure_verification["closure_identity"],
        "closure_verification_sha256": hashlib.sha256(
            canonical_json(closure_verification) + b"\n"
        ).hexdigest(),
        "plan_sha256": plan_sha256,
        "runtime_sha256": runtime_sha256,
        "runtime_open_trace_sha256": runtime_open_trace_sha256,
        "runtime_open_trace_private": dict(runtime_open_trace_private),
        "positive_cases": list(POSITIVE_NAMES),
        "financial_oracle_cases": list(FINANCIAL_NAMES),
        "negative_cases": list(NEGATIVE_NAMES),
        "auth_token_ids": dict(sorted(token_ids.items())),
        "receipt_ids": dict(sorted(receipt_ids.items())),
        "production_promotion_allowed": False,
        "files": entries,
    }
    manifest_bytes = canonical_json(manifest) + b"\n"
    write_private(manifest_path, manifest_bytes)
    for relative, path in _iter_bundle_files(evidence):
        if os.name == "posix":
            os.chmod(path, 0o400, follow_symlinks=False)
        else:
            os.chmod(path, 0o400)
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    directories = []
    for directory_text, names, _files in os.walk(evidence, topdown=False, followlinks=False):
        directory = Path(directory_text)
        directories.append(directory)
        for name in names:
            child = directory / name
            if child.is_symlink() or not child.is_dir():
                raise ReadSuiteError("bundle directory changed during freeze")
    for directory in directories:
        if os.name == "posix":
            os.chmod(directory, 0o500, follow_symlinks=False)
        else:
            os.chmod(directory, 0o500)
        _fsync_directory(directory)
    _fsync_directory(evidence.parent)
    return manifest, hashlib.sha256(manifest_bytes).hexdigest()


def _read_secret(path: Path, *, service_gid: int) -> bytes:
    secret = stable_read(
        path,
        label=f"Dev29 runtime secret {path.name}",
        maximum=4096,
        expected_uid=0 if os.name == "posix" else None,
        expected_gid=service_gid if os.name == "posix" else None,
        allowed_modes=frozenset({0o640}) if os.name == "posix" else None,
    )
    if len(secret) != 32:
        raise ReadSuiteError("Dev29 runtime secret must contain exactly 32 bytes")
    return secret


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_signed_selection(
    request: dict[str, Any],
    *,
    base_case: dict[str, Any],
    selected_identity: Mapping[str, Any],
    runtime: dict[str, Any],
    mutation: dict[str, Any] | None,
) -> None:
    context = request.get("context")
    parameters = request.get("parameters")
    if (
        set(request) != {"capability_id", "context", "parameters"}
        or request.get("capability_id") != base_case["capability_id"]
        or type(context) is not dict
        or type(parameters) is not dict
    ):
        raise ReadSuiteError("signed request envelope escaped the fixed plan")
    expected_parameters = json.loads(canonical_json(base_case["parameters"]).decode("utf-8"))
    if mutation is not None and mutation["kind"] in {
        "identity_override",
        "parameters_after_sign",
    }:
        for dotted, value in mutation["fields"].items():
            if not isinstance(dotted, str) or not dotted.startswith("parameters."):
                raise ReadSuiteError("fixed mutation escaped request parameters")
            key = dotted.removeprefix("parameters.")
            if key not in expected_parameters:
                raise ReadSuiteError("fixed mutation escaped request parameters")
            expected_parameters[key] = value
    database_uuid = runtime["database_uuid"]
    if mutation is not None and mutation["kind"] == "context_override":
        fields = mutation["fields"]
        database_uuid = fields.get("context.database_uuid", fields.get("database_uuid"))
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
        raise ReadSuiteError("signed request identity or parameters escaped the fixed plan")
    required_context_fields = {
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
    if set(context) != required_context_fields:
        raise ReadSuiteError("signed request context fields are invalid")
    for digest_field in ("auth_request_digest", "auth_signature"):
        if not isinstance(context[digest_field], str) or HEX64.fullmatch(context[digest_field]) is None:
            raise ReadSuiteError("signed request digest is invalid")


def run_suite(
    evidence_path: Path,
    expected: ExpectedIdentity,
    expected_closure: ExpectedClosure,
    *,
    runtime_path: Path | None = None,
    outer_unit_evidence: Mapping[str, Any],
    active_closure_document: Mapping[str, Any] | None = None,
    expected_runtime_trace_index_sha256: str | None,
    expected_strace_sha256: str,
    runtime_open_discovery_inventory: Path | None = None,
    runtime_open_discovery_static_closure_sha256: str | None = None,
    runtime_open_discovery_watch_roots: Sequence[str] = (),
    runtime_open_discovery_mutable_roots: Sequence[str] = (),
    runtime_open_discovery_sqlite_delta_contract_sha256: str | None = None,
) -> tuple[Path, str]:
    if os.name != "posix" or os.geteuid() != 0:
        raise ReadSuiteError("Dev29 read suite must run as root on POSIX")
    import grp
    import pwd

    expected.validate()
    expected_closure.validate()
    paths = _release_paths(expected)
    if Path(__file__).resolve(strict=True) != paths["runner"].resolve(strict=True):
        raise ReadSuiteError("Dev29 read suite is not executing from the sealed release")
    verified_release = verify_release(
        expected, executing_script=Path(__file__), enforce_root=True
    )
    odoo = pwd.getpwnam("odoo")
    odoo_group = grp.getgrnam("odoo")
    postgres = pwd.getpwnam("postgres")
    postgres_group = grp.getgrnam("postgres")
    if odoo.pw_gid != odoo_group.gr_gid or postgres.pw_gid != postgres_group.gr_gid:
        raise ReadSuiteError("service account primary group identity is invalid")
    plan, plan_bytes = load_plan(paths, enforce_root=True)
    configured_runtime = (runtime_path or paths["runtime"]).absolute()
    if configured_runtime != paths["runtime"]:
        raise ReadSuiteError("Dev29 suite requires the release-bound runtime configuration")
    runtime, runtime_bytes = load_runtime(
        configured_runtime,
        plan,
        expected,
        service_gid=odoo_group.gr_gid,
        enforce_root=True,
    )
    if (
        type(outer_unit_evidence) is not dict
        or set(outer_unit_evidence)
        != {
            "schema_version",
            "unit",
            "supervisor_pid",
            "wrapper_pid",
            "worker_pid",
            "systemctl",
            "systemctl_execution",
            "properties",
            "proc",
            "wrapper",
            "worker",
            "launcher_lease",
            "expected_environment",
            "read_write_paths",
            "read_only_paths",
            "capability_bounding_set",
            "all_checks_passed",
        }
        or not _schema_version_is_one(
            outer_unit_evidence.get("schema_version")
        )
        or outer_unit_evidence.get("supervisor_pid") != os.getpid()
        or outer_unit_evidence.get("read_only_paths")
        != ["/run/odoo-accounting-cli-v3-dev29-leases"]
        or outer_unit_evidence.get("all_checks_passed") is not True
    ):
        raise ReadSuiteError("outer transient unit evidence is invalid")
    auth_secret = _read_secret(
        Path(runtime["auth_secret_path"]), service_gid=odoo_group.gr_gid
    )
    receipt_secret = _read_secret(
        Path(runtime["receipt_secret_path"]), service_gid=odoo_group.gr_gid
    )
    if auth_secret == receipt_secret:
        raise ReadSuiteError("Dev29 runtime secrets are not purpose-isolated")

    evidence = create_evidence_directory(evidence_path)
    private_sidecar = PRIVATE_EVIDENCE_PARENT / evidence.name
    _safe_root_chain(PRIVATE_EVIDENCE_PARENT)
    if os.path.lexists(private_sidecar):
        raise ReadSuiteError("private runtime-open evidence sidecar already exists")
    os.mkdir(private_sidecar, 0o700)
    os.mkdir(private_sidecar / ".trace-staging", 0o700)
    sidecar_metadata = private_sidecar.lstat()
    trace_staging_metadata = (private_sidecar / ".trace-staging").lstat()
    if (
        not stat.S_ISDIR(sidecar_metadata.st_mode)
        or stat.S_IMODE(sidecar_metadata.st_mode) != 0o700
        or (sidecar_metadata.st_uid, sidecar_metadata.st_gid) != (0, 0)
        or not stat.S_ISDIR(trace_staging_metadata.st_mode)
        or stat.S_IMODE(trace_staging_metadata.st_mode) != 0o700
        or (trace_staging_metadata.st_uid, trace_staging_metadata.st_gid) != (0, 0)
    ):
        raise ReadSuiteError("private runtime-open evidence sidecar is unsafe")
    discovery_mode = runtime_open_discovery_inventory is not None
    if discovery_mode:
        if (
            expected_runtime_trace_index_sha256 is not None
            or (
                runtime_open_discovery_static_closure_sha256 is not None
                and (
                    not isinstance(runtime_open_discovery_static_closure_sha256, str)
                    or HEX64.fullmatch(runtime_open_discovery_static_closure_sha256)
                    is None
                )
            )
            or (
                runtime_open_discovery_sqlite_delta_contract_sha256 is not None
                and (
                    not isinstance(
                        runtime_open_discovery_sqlite_delta_contract_sha256, str
                    )
                    or HEX64.fullmatch(
                        runtime_open_discovery_sqlite_delta_contract_sha256
                    )
                    is None
                )
            )
            or not runtime_open_discovery_watch_roots
        ):
            raise ReadSuiteError("runtime-open discovery inputs are invalid")
        trace_gate = RuntimeTraceDiscoveryGate(
            expected,
            expected_strace_sha256=expected_strace_sha256,
            private_sidecar=private_sidecar,
            watch_roots=runtime_open_discovery_watch_roots,
        )
    else:
        if not isinstance(expected_runtime_trace_index_sha256, str):
            raise ReadSuiteError("runtime-open index SHA-256 is required")
        trace_gate = RuntimeTraceGate(
            expected,
            expected_index_sha256=expected_runtime_trace_index_sha256,
            expected_strace_sha256=expected_strace_sha256,
            private_sidecar=private_sidecar,
        )
    for name in ("release", "closure", "boundary", "positive", "negative"):
        _mkdir_private(evidence / name)
    for name in POSITIVE_NAMES:
        _mkdir_private(evidence / "positive" / name)
    for name in NEGATIVE_NAMES:
        _mkdir_private(evidence / "negative" / name)
    write_private(evidence / "read-plan.json", plan_bytes)
    write_private(evidence / "runtime.json", runtime_bytes)
    write_json(evidence / "expected-release.json", expected.document())
    write_json(evidence / "verified-release-pre.json", verified_release)
    write_json(evidence / "outer-unit.json", outer_unit_evidence)
    closure_python_pre = closure_python_snapshot(expected_closure.system_python_sha256)
    write_json(evidence / "closure" / "python-pre.json", closure_python_pre)
    if active_closure_document is None:
        closure_pre_process = run_closure_verify(
            paths, runtime, plan, expected, expected_closure
        )
    else:
        closure_pre_process = subprocess.CompletedProcess(
            ["supervisor-preverified-active-closure"],
            0,
            canonical_json(dict(active_closure_document)) + b"\n",
            b"",
        )
    _write_completed(evidence / "closure", "verify-pre", closure_pre_process)
    closure = _strict_success(closure_pre_process, label="Odoo closure verification pre")
    validate_closure_document(
        closure,
        runtime=runtime,
        plan=plan,
        expected=expected,
        expected_closure=expected_closure,
    )
    addons_paths = validate_addons_paths(closure, runtime)
    write_json(evidence / "closure" / "addons-paths.json", addons_paths)
    external_runtime_pre = external_runtime_snapshot(closure)
    write_json(
        evidence / "closure" / "external-runtime-pre.json", external_runtime_pre
    )
    mount_binding_pre = mount_binding_snapshot(closure)
    write_json(evidence / "closure" / "mount-pre.json", mount_binding_pre)
    profile = sandbox_profile(runtime, expected, closure, outer_unit_evidence)
    write_json(evidence / "sandbox-profile.json", profile)
    started_at = _utc_now()

    system_pre = system_snapshot(plan, runtime)
    write_json(evidence / "system-pre.json", system_pre)
    dependency_initial = dependency_snapshot(runtime, expected, closure)
    requests: dict[str, dict[str, Any]] = {}
    receipts: dict[str, dict[str, Any]] = {}
    oracle_reports: dict[str, dict[str, Any]] = {}
    negative_reports: dict[str, dict[str, Any]] = {}

    with DependencyWatch(_dependency_roots(runtime, expected, closure)) as guard:
        dependency_pre = dependency_snapshot(runtime, expected, closure)
        if dependency_pre != dependency_initial:
            raise ReadSuiteError("dependency tree changed while recursive watches were installed")
        guard.assert_clean()
        write_json(evidence / "dependency-pre.json", dependency_pre)

        release_process = _run_odoo_isolated(
            [
                runtime["odoo_python"],
                "-I",
                str(paths["launcher"]),
                "release",
                "identity",
            ],
            trace_target_id="release-identity",
            trace_gate=trace_gate,
            stdin=b"",
            runtime=runtime,
            expected=expected,
            closure=closure,
            timeout=60,
        )
        _write_completed(evidence / "release", "identity", release_process)
        release_response = _strict_success(release_process, label="exact release identity")
        if (
            set(release_response) != {"command", "data", "ok"}
            or release_response.get("command") != "release.identity"
            or release_response.get("ok") is not True
            or type(release_response.get("data")) is not dict
        ):
            raise ReadSuiteError("exact release CLI identity envelope is invalid")
        release_identity = release_response["data"]
        if (
            release_identity.get("commit") != expected.commit
            or release_identity.get("manifest_sha256") != expected.manifest_sha256
            or release_identity.get("package_sha256") != expected.package_sha256
            or release_identity.get("release") != expected.release
            or release_identity.get("version") != expected.version
            or release_identity.get("verified") is not True
            or not isinstance(release_identity.get("registry_digest"), str)
            or HEX64.fullmatch(release_identity["registry_digest"]) is None
        ):
            raise ReadSuiteError("exact release CLI identity does not match expectation")

        witness_pre_process = _run_postgres(
            [
                runtime["odoo_python"],
                "-I",
                str(paths["oracle"]),
                "witness",
                "--plan",
                str(paths["plan"]),
            ],
            trace_target_id="witness-pre",
            trace_gate=trace_gate,
            runtime=runtime,
            expected=expected,
            closure=closure,
            timeout=180,
        )
        _write_completed(evidence, "witness-pre", witness_pre_process)
        witness_pre = _strict_success(witness_pre_process, label="PostgreSQL witness pre")
        _validate_witness(witness_pre, plan=plan, runtime=runtime)

        boundary_process = _run_odoo_isolated(
            [
                runtime["odoo_python"],
                "-I",
                str(paths["launcher"]),
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(configured_runtime),
                "--timeout-seconds",
                "120",
            ],
            trace_target_id="boundary-probe",
            trace_gate=trace_gate,
            stdin=b"",
            runtime=runtime,
            expected=expected,
            closure=closure,
            timeout=150,
        )
        _write_completed(evidence / "boundary", "probe", boundary_process)
        boundary_response = _strict_success(
            boundary_process, label="D11 read boundary"
        )
        _validate_boundary(boundary_response, runtime, release_identity)

        state_pre = state_snapshot(
            runtime,
            staging_parent=evidence / ".state-pre-staging",
            include_audit_delta=False,
            state_uid=odoo.pw_uid,
            state_gid=odoo_group.gr_gid,
        )
        write_json(evidence / "state-pre.json", state_pre)
        pre_head = state_pre["receipt"]["queries"].get("audit_head", [])
        audit_after_sequence = 0 if not pre_head else pre_head[0].get("sequence")
        if type(audit_after_sequence) is not int or audit_after_sequence < 0:
            raise ReadSuiteError("pre-run audit head is invalid")

        cases = {item["name"]: item for item in plan["cases"]}
        for name in POSITIVE_NAMES:
            case = cases[name]
            directory = evidence / "positive" / name
            signer_process = _run_signer(
                [
                    CLOSURE_PYTHON,
                    "-I",
                    "-S",
                    str(paths["signer"]),
                    "--case",
                    name,
                    "--runtime-config",
                    str(configured_runtime),
                ],
                trace_target_id=f"positive-{name}-signer",
                trace_gate=trace_gate,
                stdin=b"",
                runtime=runtime,
                expected=expected,
                closure=closure,
                timeout=60,
            )
            _write_completed(directory, "signer", signer_process)
            request = _strict_success(signer_process, label=f"positive signer {name}")
            _validate_signed_selection(
                request,
                base_case=case,
                selected_identity=case,
                runtime=runtime,
                mutation=None,
            )
            requests[name] = request
            request_bytes = canonical_json(request) + b"\n"
            write_private(directory / "request.json", request_bytes)
            read_process = _run_odoo_isolated(
                [
                    runtime["odoo_python"],
                    "-I",
                    str(paths["launcher"]),
                    "read",
                    "--runtime-config",
                    str(configured_runtime),
                    "--timeout-seconds",
                    "120",
                ],
                trace_target_id=f"positive-{name}-read",
                trace_gate=trace_gate,
                stdin=request_bytes,
                runtime=runtime,
                expected=expected,
                closure=closure,
                timeout=150,
            )
            _write_completed(directory, "read", read_process)
            response = _strict_success(read_process, label=f"positive read {name}")
            result, receipt = _validate_positive_response(
                response, request, runtime, release_identity
            )
            if name == "registry":
                _validate_registry_result(case, result)
            receipts[name] = receipt
            write_json(directory / "receipt.json", receipt)
            if name in FINANCIAL_NAMES:
                oracle_process = run_oracle_verify(
                    paths,
                    runtime,
                    expected,
                    closure,
                    trace_gate=trace_gate,
                    case_name=name,
                    request_bytes=request_bytes,
                    response_bytes=canonical_json(response) + b"\n",
                    postgres_uid=postgres.pw_uid,
                    postgres_gid=postgres_group.gr_gid,
                )
                _write_completed(directory, "oracle", oracle_process)
                oracle = _strict_success(
                    oracle_process, label=f"financial Oracle {name}"
                )
                _validate_oracle_result(
                    oracle,
                    case=case,
                    request=request,
                    response=response,
                    plan=plan,
                    runtime=runtime,
                    witness=witness_pre,
                )
                oracle_reports[name] = oracle
            guard.assert_clean()

        negatives = {item["name"]: item for item in plan["negative_cases"]}
        for name in NEGATIVE_NAMES:
            negative = negatives[name]
            base = cases[negative["base_case"]]
            directory = evidence / "negative" / name
            if negative["mutation"]["kind"] == "replay_exact_request":
                request = requests[negative["base_case"]]
                write_json(
                    directory / "request-source.json",
                    {
                        "kind": "replay_exact_request",
                        "positive_case": negative["base_case"],
                        "byte_identical": True,
                    },
                )
            else:
                signer_process = _run_signer(
                    [
                        CLOSURE_PYTHON,
                        "-I",
                        "-S",
                        str(paths["signer"]),
                        "--negative",
                        name,
                        "--runtime-config",
                        str(configured_runtime),
                    ],
                    trace_target_id=f"negative-{name}-signer",
                    trace_gate=trace_gate,
                    stdin=b"",
                    runtime=runtime,
                    expected=expected,
                    closure=closure,
                    timeout=60,
                )
                _write_completed(directory, "signer", signer_process)
                request = _strict_success(
                    signer_process, label=f"negative signer {name}"
                )
                _validate_signed_selection(
                    request,
                    base_case=base,
                    selected_identity=negative,
                    runtime=runtime,
                    mutation=negative["mutation"],
                )
            requests[name] = request
            request_bytes = canonical_json(request) + b"\n"
            write_private(directory / "request.json", request_bytes)
            write_json(
                directory / "expected.json",
                {
                    "logical_error": negative["expected_error"],
                    "mutation": negative["mutation"],
                    "business_result_forbidden": True,
                    "receipt_forbidden": True,
                },
            )
            read_process = _run_odoo_isolated(
                [
                    runtime["odoo_python"],
                    "-I",
                    str(paths["launcher"]),
                    "read",
                    "--runtime-config",
                    str(configured_runtime),
                    "--timeout-seconds",
                    "120",
                ],
                trace_target_id=f"negative-{name}-read",
                trace_gate=trace_gate,
                stdin=request_bytes,
                runtime=runtime,
                expected=expected,
                closure=closure,
                timeout=150,
            )
            _write_completed(directory, "read", read_process)
            failure = _strict_negative(
                read_process,
                label=f"negative read {name}",
                expected_rejection_code=negative["expected_error"],
            )
            negative_reports[name] = {
                "logical_error": negative["expected_error"],
                "cli_error": failure["error"]["code"],
                "rejection_code": failure["error"]["rejection_code"],
                "exit_code": read_process.returncode,
                "stdout_empty": True,
                "receipt_absent": True,
                "business_result_absent": True,
            }
            guard.assert_clean()

        all_tokens = sorted({_request_token(item) for item in requests.values()})
        all_receipt_ids = sorted(item["id"] for item in receipts.values())
        state_post = state_snapshot(
            runtime,
            staging_parent=evidence / ".state-post-staging",
            token_ids=all_tokens,
            receipt_ids=all_receipt_ids,
            audit_after_sequence=audit_after_sequence,
            state_uid=odoo.pw_uid,
            state_gid=odoo_group.gr_gid,
        )
        write_json(evidence / "state-post.json", state_post)
        state_delta = verify_state_delta(
            state_pre,
            state_post,
            requests=requests,
            receipts=receipts,
            suite_started_at=started_at,
            observed_not_after=_utc_now(),
        )
        write_json(evidence / "state-delta.json", state_delta)

        witness_post_process = _run_postgres(
            [
                runtime["odoo_python"],
                "-I",
                str(paths["oracle"]),
                "witness",
                "--plan",
                str(paths["plan"]),
            ],
            trace_target_id="witness-post",
            trace_gate=trace_gate,
            runtime=runtime,
            expected=expected,
            closure=closure,
            timeout=180,
        )
        _write_completed(evidence, "witness-post", witness_post_process)
        witness_post = _strict_success(
            witness_post_process, label="PostgreSQL witness post"
        )
        _validate_witness(witness_post, plan=plan, runtime=runtime)
        if witness_post != witness_pre:
            raise ReadSuiteError("PostgreSQL relation/data witness changed during the suite")

        system_post = system_snapshot(plan, runtime)
        write_json(evidence / "system-post.json", system_post)
        require_system_continuity(system_pre, system_post)
        verified_release_post = verify_release(expected, enforce_root=True)
        write_json(evidence / "verified-release-post.json", verified_release_post)
        if verified_release_post != verified_release:
            raise ReadSuiteError("exact release identity changed during the suite")
        if active_closure_document is None:
            closure_post_process = run_closure_verify(
                paths, runtime, plan, expected, expected_closure
            )
        else:
            closure_post_process = subprocess.CompletedProcess(
                ["supervisor-preverified-active-closure"],
                0,
                canonical_json(dict(active_closure_document)) + b"\n",
                b"",
            )
        _write_completed(evidence / "closure", "verify-post", closure_post_process)
        closure_post = _strict_success(
            closure_post_process, label="Odoo closure verification post"
        )
        validate_closure_document(
            closure_post,
            runtime=runtime,
            plan=plan,
            expected=expected,
            expected_closure=expected_closure,
        )
        if closure_post != closure:
            raise ReadSuiteError("Odoo closure identity changed during the suite")
        closure_python_post = closure_python_snapshot(
            expected_closure.system_python_sha256
        )
        write_json(evidence / "closure" / "python-post.json", closure_python_post)
        if closure_python_post != closure_python_pre:
            raise ReadSuiteError("closure verification Python changed during the suite")
        external_runtime_post = external_runtime_snapshot(closure_post)
        write_json(
            evidence / "closure" / "external-runtime-post.json",
            external_runtime_post,
        )
        if external_runtime_post != external_runtime_pre:
            raise ReadSuiteError("external Odoo runtime dependencies changed during the suite")
        mount_binding_post = mount_binding_snapshot(closure_post)
        write_json(evidence / "closure" / "mount-post.json", mount_binding_post)
        if mount_binding_post != mount_binding_pre:
            raise ReadSuiteError("Odoo closure mount binding changed during the suite")
        dependency_post = dependency_snapshot(runtime, expected, closure)
        write_json(evidence / "dependency-post.json", dependency_post)
        if dependency_post != dependency_pre:
            raise ReadSuiteError("complete dependency tree changed during the suite")
        guard.assert_clean()
        watch_document = guard.document()

    write_json(evidence / "dependency-watch.json", watch_document)
    if isinstance(trace_gate, RuntimeTraceDiscoveryGate):
        assert runtime_open_discovery_inventory is not None
        sqlite_delta_contract_sha256 = (
            runtime_open_discovery_sqlite_delta_contract_sha256
            or discovery_sqlite_delta_contract_sha256()
        )
        inventory = trace_gate.inventory(
            required_targets=suite_runtime_trace_targets(),
            expected_static_closure_sha256=(
                runtime_open_discovery_static_closure_sha256
            ),
            watch_roots=runtime_open_discovery_watch_roots,
            mutable_roots=runtime_open_discovery_mutable_roots,
            sqlite_delta_contract_sha256=sqlite_delta_contract_sha256,
        )
        payload = canonical_json(inventory) + b"\n"
        write_private(runtime_open_discovery_inventory, payload)
        write_json(
            evidence / "runtime-open-discovery.json",
            {
                "schema_version": 1,
                "scope": "odoo-accounting-cli-v3.dev29.runtime-open-discovery-suite.v1",
                "inventory_path": str(runtime_open_discovery_inventory),
                "inventory_sha256": hashlib.sha256(payload).hexdigest(),
                "target_count": len(inventory["targets"]),
                "candidate_is_approval": False,
                "production_promotion_allowed": False,
            },
        )
        return evidence, hashlib.sha256(payload).hexdigest()
    runtime_trace_private = trace_gate.seal_private_manifest(
        suite_runtime_trace_targets()
    )
    runtime_trace_receipt = trace_gate.document(suite_runtime_trace_targets())
    runtime_trace_receipt["private_sidecar"] = runtime_trace_private
    write_json(evidence / "runtime-open-trace.json", runtime_trace_receipt)
    runtime_open_trace_sha256 = hashlib.sha256(
        canonical_json(runtime_trace_receipt) + b"\n"
    ).hexdigest()
    finished_at = _utc_now()
    suite = {
        "schema_version": 1,
        "suite": "odoo-accounting-cli-v3.dev29.real-read-gate",
        "started_at": started_at,
        "finished_at": finished_at,
        "release_identity": release_identity,
        "positive_cases": {name: {"passed": True} for name in POSITIVE_NAMES},
        "financial_oracles": {
            name: {
                "passed": oracle_reports[name]["all_checks_passed"],
                "fixture_gaps": oracle_reports[name]["fixture_gaps"],
            }
            for name in FINANCIAL_NAMES
        },
        "negative_cases": negative_reports,
        "d11_read_boundary_passed": True,
        "postgresql_witness_unchanged": True,
        "system_identity_unchanged": True,
        "dependency_identity_unchanged": True,
        "odoo_closure_verified": True,
        "odoo_closure_unchanged": True,
        "addons_paths_covered_by_read_only_binds": True,
        "external_runtime_identity_unchanged": True,
        "closure_mount_binding_unchanged": True,
        "state_delta_verified": True,
        "sandbox_profile_enforced": True,
        "runtime_open_trace_verified": True,
        "runtime_open_trace_sha256": runtime_open_trace_sha256,
        "odoo_business_writes_permitted": False,
        "production_promotion_allowed": False,
    }
    write_json(evidence / "suite.json", suite)
    assert_no_secret_leak(evidence, (auth_secret, receipt_secret))
    token_ids = {name: _request_token(request) for name, request in requests.items()}
    receipt_ids = {name: receipt["id"] for name, receipt in receipts.items()}
    _manifest, manifest_sha256 = freeze_bundle(
        evidence,
        expected=expected,
        plan_sha256=hashlib.sha256(plan_bytes).hexdigest(),
        runtime_sha256=hashlib.sha256(runtime_bytes).hexdigest(),
        release_identity=release_identity,
        closure_verification=closure,
        token_ids=token_ids,
        receipt_ids=receipt_ids,
        runtime_open_trace_sha256=runtime_open_trace_sha256,
        runtime_open_trace_private=runtime_trace_private,
    )
    return evidence, manifest_sha256


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--runtime-config", type=Path)
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
    parser.add_argument("--expected-runtime-open-index-sha256")
    parser.add_argument("--expected-strace-sha256", required=True)
    parser.add_argument("--runtime-open-discovery-inventory", type=Path)
    parser.add_argument("--runtime-open-discovery-static-closure-sha256")
    parser.add_argument(
        "--runtime-open-discovery-watch-root",
        action="append",
        default=[],
    )
    parser.add_argument(
        "--runtime-open-discovery-mutable-root",
        action="append",
        default=[],
    )
    parser.add_argument("--runtime-open-discovery-sqlite-delta-contract-sha256")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    if os.name != "posix" or sys.flags.isolated != 1 or sys.flags.no_site != 1:
        print(
            "Dev29 read suite refused: fixed /usr/bin/python3.12 -I -S is required",
            file=sys.stderr,
        )
        return 2
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    expected = ExpectedIdentity(
        release=arguments.expected_release,
        version=arguments.expected_version,
        commit=arguments.expected_commit,
        manifest_sha256=arguments.expected_manifest_sha256,
        package_sha256=arguments.expected_package_sha256,
    )
    expected_closure = ExpectedClosure(
        anchor_sha256=arguments.expected_closure_anchor_sha256,
        image_sha256=arguments.expected_closure_image_sha256,
        system_python_sha256=arguments.expected_system_python_sha256,
        loader_preload_sha256=arguments.expected_ld_so_preload_sha256,
        ldconfig_sha256=arguments.expected_ldconfig_sha256,
    )
    try:
        evidence, manifest_sha256 = run_suite(
            arguments.evidence_dir,
            expected,
            expected_closure,
            runtime_path=arguments.runtime_config,
            expected_runtime_trace_index_sha256=(
                arguments.expected_runtime_open_index_sha256
            ),
            expected_strace_sha256=arguments.expected_strace_sha256,
            runtime_open_discovery_inventory=(
                arguments.runtime_open_discovery_inventory
            ),
            runtime_open_discovery_static_closure_sha256=(
                arguments.runtime_open_discovery_static_closure_sha256
            ),
            runtime_open_discovery_watch_roots=tuple(
                arguments.runtime_open_discovery_watch_root
            ),
            runtime_open_discovery_mutable_roots=tuple(
                arguments.runtime_open_discovery_mutable_root
            ),
            runtime_open_discovery_sqlite_delta_contract_sha256=(
                arguments.runtime_open_discovery_sqlite_delta_contract_sha256
            ),
        )
    except (OSError, ReadSuiteError, subprocess.SubprocessError) as exc:
        print(f"Dev29 read suite refused: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "bundle_manifest_sha256": manifest_sha256,
                "discovery_inventory": (
                    str(arguments.runtime_open_discovery_inventory)
                    if arguments.runtime_open_discovery_inventory is not None
                    else None
                ),
                "evidence_path": str(evidence),
                "production_promotion_allowed": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

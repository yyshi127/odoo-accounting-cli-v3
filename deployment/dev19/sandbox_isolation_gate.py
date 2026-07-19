#!/usr/bin/python3 -I
"""Strict E00b sandbox-isolation contract.

This module currently implements the reviewed policy/observation contract and
the fail-closed evaluator.  Its operational CLI intentionally returns exit 2
until the root-only live Linux collector is implemented; caller-supplied
observations and clock overrides are never accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import sys
import time
import types
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID


POLICY_KIND = "odoo-accounting-cli-v3.sandbox-isolation-policy.v1"
OBSERVATION_KIND = "odoo-accounting-cli-v3.sandbox-isolation-observation.v1"
RECOVERY_RECEIPT_KIND = "odoo-accounting-cli-v3.sandbox-recovery-drill-receipt.v1"
RECOVERY_PAIR_MANIFEST_KIND = (
    "odoo-accounting-cli-v3.sandbox-recovery-pair-manifest.v1"
)
RELEASE_APPROVAL_ALLOWLIST_KIND = (
    "odoo-accounting-cli-v3.release-approval-allowlist.v1"
)
POLICY_APPROVAL_ALLOWLIST_KIND = (
    "odoo-accounting-cli-v3.e00b-policy-approval-allowlist.v1"
)
RECOVERY_APPROVAL_ALLOWLIST_KIND = (
    "odoo-accounting-cli-v3.recovery-drill-approval-allowlist.v1"
)
HOST_CONTEXT_APPROVAL_KIND = "odoo-accounting-cli-v3.host-context-approval.v1"
TRUSTED_RELEASE_ALLOWLIST_PATH = (
    "/etc/odoo-accounting-cli-v3/approved-releases.json"
)
TRUSTED_HOST_CONTEXT_PATH = (
    "/etc/odoo-accounting-cli-v3/approved-host-context.json"
)
TRUSTED_POLICY_ALLOWLIST_PATH = (
    "/etc/odoo-accounting-cli-v3/approved-e00b-policies.json"
)
TRUSTED_RECOVERY_ALLOWLIST_PATH = (
    "/etc/odoo-accounting-cli-v3/approved-recovery-drills.json"
)
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_RECOVERY_ARTIFACT_BYTES = 1 << 40
MAX_RELEASE_FILE_BYTES = 64 * 1024 * 1024
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_RELEASE_FILES = 10_000
MAX_RELEASE_TREE_ENTRIES = 20_000
MAX_PROC_CMDLINE_BYTES = 64 * 1024
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION_PATTERN = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
HOST_NAMESPACE_NAMES = {
    "user": "user",
    "mnt": "mnt",
    "pid": "pid",
    "pid_for_children": "pid",
    "net": "net",
    "uts": "uts",
    "ipc": "ipc",
    "cgroup": "cgroup",
    "time": "time",
    "time_for_children": "time",
}
REQUIRED_RELEASE_DEPENDENCIES = {
    "deployment/dev19/sandbox_isolation_gate.py": "collector_sha256",
    "deployment/dev18/sandbox_capacity_gate.py": "dev18_collector_sha256",
    "deployment/dev19/sandbox_namespace_probe.py": "namespace_probe_sha256",
}
DEV18_VERIFIER_PATH = "deployment/dev18/sandbox_capacity_gate.py"
EXECUTABLE_RELEASE_MEMBERS = frozenset(
    {
        "bin/odoo-accounting-cli-v3",
        "bin/odoo-accounting-cli-v3-broker",
        "bin/odoo-accounting-cli-v3-effect-finalizer",
        "deployment/dev9/run-private-mount-gate.sh",
    }
)


class IsolationGateError(RuntimeError):
    """A malformed or unverifiable E00b contract."""


class InvalidInvocationError(IsolationGateError):
    """A command line that is outside the operational interface."""


class HelpRequestedError(InvalidInvocationError):
    """A non-authorizing request for operator documentation."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IsolationGateError(message)


def _reject_duplicate_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise IsolationGateError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise IsolationGateError(f"non-finite JSON number: {value}")


def load_strict_json(payload: bytes) -> object:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IsolationGateError("JSON is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_nonfinite,
        )
    except IsolationGateError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IsolationGateError("JSON is invalid") from exc
    return value


def _exact_object(
    value: object, fields: set[str], label: str
) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    document = value
    _require(set(document) == fields, f"{label} fields are invalid")
    return document


def _exact_list(
    value: object, label: str, *, maximum: int = 256
) -> list[Any]:
    _require(type(value) is list, f"{label} must be an array")
    items = value
    _require(len(items) <= maximum, f"{label} is too large")
    return items


def _text(
    value: object,
    label: str,
    *,
    pattern: re.Pattern[str] = SAFE_ID,
    maximum: int = 256,
) -> str:
    _require(type(value) is str, f"{label} must be a string")
    _require(1 <= len(value) <= maximum, f"{label} length is invalid")
    _require(pattern.fullmatch(value) is not None, f"{label} format is invalid")
    return value


def _hex64(value: object, label: str) -> str:
    return _text(value, label, pattern=HEX64, maximum=64)


def _uuid(value: object, label: str) -> str:
    _require(type(value) is str, f"{label} must be a UUID string")
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as exc:
        raise IsolationGateError(f"{label} is invalid") from exc
    _require(str(parsed) == value, f"{label} must be canonical lowercase UUID")
    _require(parsed.version in {1, 2, 3, 4, 5}, f"{label} version is invalid")
    return value


def _integer(
    value: object, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1
) -> int:
    _require(type(value) is int, f"{label} must be an integer")
    _require(minimum <= value <= maximum, f"{label} is out of range")
    return value


def _boolean(value: object, label: str) -> bool:
    _require(type(value) is bool, f"{label} must be a boolean")
    return value


def _absolute_path(value: object, label: str) -> str:
    _require(type(value) is str, f"{label} must be a path string")
    _require(1 < len(value) <= 4096, f"{label} length is invalid")
    path = PurePosixPath(value)
    _require(path.is_absolute(), f"{label} must be absolute")
    _require(str(path) == value, f"{label} must be canonical")
    _require(".." not in path.parts and "." not in path.parts, f"{label} is unsafe")
    return value


def _timestamp(value: object, label: str) -> datetime:
    _require(type(value) is str, f"{label} must be a timestamp string")
    _require(value.endswith("Z"), f"{label} must be UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise IsolationGateError(f"{label} is invalid") from exc
    _require(parsed.tzinfo is not None, f"{label} must have a timezone")
    return parsed.astimezone(UTC)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _release_manifest_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _regular_file_fingerprint(item: object) -> tuple[int, ...]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
    )


def _linux_open_flags(*, directory: bool) -> int:
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_CLOEXEC"):
        value = getattr(os, name, None)
        _require(
            type(value) is int and value > 0,
            "required secure Linux open flags are unavailable",
        )
        flags |= value
    if directory:
        value = getattr(os, "O_DIRECTORY", None)
        _require(
            type(value) is int and value > 0,
            "required secure Linux open flags are unavailable",
        )
        flags |= value
    return flags


def _validate_trusted_directory_metadata(metadata: object, label: str) -> None:
    _require(stat.S_ISDIR(metadata.st_mode), f"{label} ancestor is not a directory")
    _require(
        metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_mode & 0o022 == 0,
        f"{label} ancestor must be root-owned and non-writable",
    )


def _open_trusted_directory_fd(path: Path, label: str) -> int:
    _require(sys.platform == "linux", "trusted directory walk requires Linux")
    _require(path.is_absolute(), f"{label} ancestor path must be absolute")
    parts = path.parts
    _require(bool(parts) and parts[0] == "/", f"{label} ancestor path is invalid")
    flags = _linux_open_flags(directory=True)
    current: int | None = None
    try:
        current = os.open("/", flags)
        _validate_trusted_directory_metadata(os.fstat(current), label)
        for component in parts[1:]:
            _require(
                component not in {"", ".", "..", "/"}
                and "/" not in component,
                f"{label} ancestor path is invalid",
            )
            child = os.open(component, flags, dir_fd=current)
            try:
                _validate_trusted_directory_metadata(os.fstat(child), label)
            except Exception:
                os.close(child)
                raise
            previous = current
            current = child
            os.close(previous)
        return current
    except IsolationGateError:
        if current is not None:
            os.close(current)
        raise
    except OSError as exc:
        if current is not None:
            os.close(current)
        raise IsolationGateError(f"{label} ancestor cannot be opened safely") from exc


def _verify_root_directory_chain(path: Path, label: str) -> None:
    if sys.platform != "linux":
        return
    descriptor = _open_trusted_directory_fd(path, label)
    os.close(descriptor)


def _validate_trusted_regular_metadata(
    metadata: object, label: str, *, maximum_size: int
) -> None:
    _require(stat.S_ISREG(metadata.st_mode), f"{label} must be a regular file")
    _require(metadata.st_nlink == 1, f"{label} must have exactly one link")
    _require(
        metadata.st_uid == 0 and metadata.st_gid == 0,
        f"{label} must be root-owned",
    )
    _require(
        metadata.st_mode & 0o022 == 0,
        f"{label} must not be group/world writable",
    )
    _require(0 <= metadata.st_size <= maximum_size, f"{label} size is invalid")


def _open_trusted_regular_fd(
    path: Path, label: str, *, maximum_size: int
) -> tuple[int, int, str, object]:
    _require(path.is_absolute(), f"{label} path must be absolute")
    _require(path.name not in {"", ".", ".."}, f"{label} path is invalid")
    parent = _open_trusted_directory_fd(path.parent, label)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path.name,
            _linux_open_flags(directory=False),
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        _validate_trusted_regular_metadata(
            opened, label, maximum_size=maximum_size
        )
        entry = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        _require(
            _regular_file_fingerprint(entry)
            == _regular_file_fingerprint(opened),
            f"{label} changed while being opened",
        )
        return descriptor, parent, path.name, opened
    except IsolationGateError:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)
        raise IsolationGateError(f"{label} cannot be opened safely") from exc


def _read_linux_regular_file(path: Path, label: str) -> bytes:
    descriptor, parent, name, opened = _open_trusted_regular_fd(
        path, label, maximum_size=MAX_INPUT_BYTES
    )
    try:
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            payload.extend(chunk)
            _require(len(payload) <= MAX_INPUT_BYTES, f"{label} is too large")
        opened_after = os.fstat(descriptor)
        entry_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except IsolationGateError:
        raise
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be read safely") from exc
    finally:
        os.close(descriptor)
        os.close(parent)
    _require(
        _regular_file_fingerprint(opened)
        == _regular_file_fingerprint(opened_after)
        == _regular_file_fingerprint(entry_after),
        f"{label} changed while being read",
    )
    return bytes(payload)


def _read_bounded_regular_file(path: Path, label: str) -> bytes:
    _require(path.is_absolute(), f"{label} path must be absolute")
    if sys.platform == "linux":
        return _read_linux_regular_file(path, label)
    try:
        before = path.lstat()
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be opened") from exc
    _require(not path.is_symlink(), f"{label} must not be a symlink")
    _require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file")
    _require(before.st_nlink == 1, f"{label} must have exactly one link")
    _require(before.st_size <= MAX_INPUT_BYTES, f"{label} is too large")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                payload.extend(chunk)
                _require(len(payload) <= MAX_INPUT_BYTES, f"{label} is too large")
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be read safely") from exc
    _require(
        _regular_file_fingerprint(before)
        == _regular_file_fingerprint(opened)
        == _regular_file_fingerprint(opened_after)
        == _regular_file_fingerprint(after),
        f"{label} changed while being read",
    )
    return bytes(payload)


def _hash_linux_regular_file(
    path: Path, label: str, *, maximum_size: int
) -> tuple[str, int]:
    descriptor, parent, name, opened = _open_trusted_regular_fd(
        path, label, maximum_size=maximum_size
    )
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            total += len(chunk)
            _require(total <= maximum_size, f"{label} is too large")
            digest.update(chunk)
        opened_after = os.fstat(descriptor)
        entry_after = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except IsolationGateError:
        raise
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be read safely") from exc
    finally:
        os.close(descriptor)
        os.close(parent)
    _require(
        _regular_file_fingerprint(opened)
        == _regular_file_fingerprint(opened_after)
        == _regular_file_fingerprint(entry_after),
        f"{label} changed while being hashed",
    )
    _require(total == opened.st_size, f"{label} size changed while being hashed")
    return digest.hexdigest(), total


def _hash_bounded_regular_file(
    path: Path, label: str, *, maximum_size: int
) -> tuple[str, int]:
    _require(path.is_absolute(), f"{label} path must be absolute")
    _require(
        type(maximum_size) is int and 0 < maximum_size <= MAX_RECOVERY_ARTIFACT_BYTES,
        f"{label} maximum size is invalid",
    )
    if sys.platform == "linux":
        return _hash_linux_regular_file(path, label, maximum_size=maximum_size)
    try:
        before = path.lstat()
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be opened") from exc
    _require(not path.is_symlink(), f"{label} must not be a symlink")
    _require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file")
    _require(before.st_nlink == 1, f"{label} must have exactly one link")
    _require(0 <= before.st_size <= maximum_size, f"{label} size is invalid")
    digest = hashlib.sha256()
    total = 0
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            while True:
                chunk = os.read(descriptor, 1_048_576)
                if not chunk:
                    break
                total += len(chunk)
                _require(total <= maximum_size, f"{label} is too large")
                digest.update(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except IsolationGateError:
        raise
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be read safely") from exc
    _require(
        _regular_file_fingerprint(before)
        == _regular_file_fingerprint(opened)
        == _regular_file_fingerprint(opened_after)
        == _regular_file_fingerprint(after),
        f"{label} changed while being hashed",
    )
    _require(total == before.st_size, f"{label} size changed while being hashed")
    return digest.hexdigest(), total


def _read_pinned_json(path_value: str, expected_sha256: str, label: str) -> object:
    _absolute_path(path_value, f"{label} path")
    _hex64(expected_sha256, f"{label} SHA-256")
    payload = _read_bounded_regular_file(Path(path_value), label)
    _require(
        hashlib.sha256(payload).hexdigest() == expected_sha256,
        f"{label} SHA-256 mismatch",
    )
    return load_strict_json(payload)


def _read_bound_approval_payload(
    path: Path, expected_sha256: str, label: str
) -> bytes:
    _hex64(expected_sha256, f"{label} approved SHA-256")
    payload = _read_bounded_regular_file(path, label)
    _require(
        hashlib.sha256(payload).hexdigest() == expected_sha256,
        f"{label} changed since policy approval",
    )
    return payload


def _load_e00a_bundle(policy: dict[str, Any]) -> dict[str, object]:
    e00a = policy["e00a"]
    return {
        "policy": _read_pinned_json(
            e00a["policy_path"], e00a["policy_sha256"], "E00a policy"
        ),
        "observation": _read_pinned_json(
            e00a["observation_path"],
            e00a["observation_sha256"],
            "E00a observation",
        ),
        "report": _read_pinned_json(
            e00a["report_path"], e00a["report_sha256"], "E00a report"
        ),
    }


def _verify_e00a_bundle(
    policy: dict[str, Any],
    bundle: dict[str, object],
    dev18_module: Any,
    *,
    expected_host_context_approval_sha256: str,
) -> dict[str, object]:
    _require(
        callable(getattr(dev18_module, "_validate_policy", None))
        and callable(getattr(dev18_module, "_validate_observation", None))
        and callable(getattr(dev18_module, "evaluate", None)),
        "Dev18 verifier interface is unavailable",
    )
    e00a_policy = dev18_module._validate_policy(bundle["policy"])
    e00a_observation = dev18_module._validate_observation(bundle["observation"])
    report = bundle["report"]
    _require(type(report) is dict, "E00a report must be an object")
    evaluated_at = _timestamp(report.get("evaluated_at"), "E00a evaluated_at")
    regenerated = dev18_module.evaluate(
        e00a_policy,
        e00a_observation,
        now=evaluated_at,
        policy_raw_sha256=policy["e00a"]["policy_sha256"],
        observation_raw_sha256=policy["e00a"]["observation_sha256"],
    )
    _require(regenerated == report, "E00a report does not reproduce exactly")
    _require(
        report.get("capacity_gate_passed") is True
        and report.get("eligible_for_sandbox_provisioning_review") is True
        and report.get("sandbox_provisioning_authorized") is False
        and report.get("sandbox_accounting_write_authorized") is False
        and report.get("production_accounting_write_authorized") is False,
        "E00a report is not a passing non-authorizing receipt",
    )
    _require(
        report.get("observation") == e00a_observation,
        "E00a report does not embed the pinned observation",
    )
    host_approval = _verify_e00a_host_approval(
        policy,
        e00a_observation,
        expected_host_context_approval_sha256=(
            expected_host_context_approval_sha256
        ),
    )
    _require(
        e00a_observation["target"]["database_name"]
        == policy["sandbox"]["database_name"]
        and e00a_observation["target"]["database_exists"] is False,
        "E00a did not prove the sandbox database absent",
    )
    _require(
        e00a_observation["postgresql"]["system_identifier"]
        == policy["e00a"]["production_cluster_system_identifier"],
        "E00a production cluster identity mismatch",
    )
    observed_uuids = {item["uuid"] for item in e00a_observation["databases"]}
    _require(
        observed_uuids == set(policy["e00a"]["protected_database_uuids"]),
        "E00a protected database UUID closure mismatch",
    )
    protected_identity = _canonical_sha256(
        {
            "postgresql": e00a_observation["postgresql"],
            "catalog": e00a_observation["catalog"],
            "databases": e00a_observation["databases"],
            "protected_resources": e00a_observation["protected_resources"],
        }
    )
    _require(
        protected_identity == policy["e00a"]["protected_identity_sha256"],
        "E00a protected identity digest mismatch",
    )
    _require(
        report["capture_finished_at"] == policy["e00a"]["captured_at"],
        "E00a capture timestamp mismatch",
    )
    return {
        "policy_sha256": policy["e00a"]["policy_sha256"],
        "observation_sha256": policy["e00a"]["observation_sha256"],
        "report_sha256": policy["e00a"]["report_sha256"],
        "protected_identity_sha256": protected_identity,
        "host_context_approval_sha256": host_approval["approval_sha256"],
    }


def _unique_texts(
    value: object,
    label: str,
    *,
    pattern: re.Pattern[str] = SAFE_ID,
    maximum: int = 256,
) -> list[str]:
    items = [
        _text(item, f"{label}[{index}]", pattern=pattern, maximum=maximum)
        for index, item in enumerate(_exact_list(value, label))
    ]
    _require(len(items) == len(set(items)), f"{label} contains duplicates")
    return items


def _unique_paths(value: object, label: str) -> list[str]:
    items = [
        _absolute_path(item, f"{label}[{index}]")
        for index, item in enumerate(_exact_list(value, label))
    ]
    _require(len(items) == len(set(items)), f"{label} contains duplicates")
    return items


def _unique_uuids(value: object, label: str) -> list[str]:
    items = [
        _uuid(item, f"{label}[{index}]")
        for index, item in enumerate(_exact_list(value, label))
    ]
    _require(len(items) == len(set(items)), f"{label} contains duplicates")
    return items


def _unique_integers(value: object, label: str) -> list[int]:
    items = [
        _integer(item, f"{label}[{index}]", minimum=1)
        for index, item in enumerate(_exact_list(value, label))
    ]
    _require(len(items) == len(set(items)), f"{label} contains duplicates")
    return items


def _validate_release(value: object, label: str) -> dict[str, Any]:
    release = _exact_object(
        value,
        {
            "release_id",
            "manifest_sha256",
            "package_sha256",
            "release_root",
            "trusted_anchor_path",
            "trusted_anchor_sha256",
        },
        label,
    )
    _text(release["release_id"], f"{label}.release_id")
    _hex64(release["manifest_sha256"], f"{label}.manifest_sha256")
    _hex64(release["package_sha256"], f"{label}.package_sha256")
    _absolute_path(release["release_root"], f"{label}.release_root")
    _absolute_path(release["trusted_anchor_path"], f"{label}.trusted_anchor_path")
    _hex64(
        release["trusted_anchor_sha256"], f"{label}.trusted_anchor_sha256"
    )
    return release


def _validate_dependencies(value: object) -> dict[str, Any]:
    dependencies = _exact_object(
        value,
        {"dev18_collector_sha256", "namespace_probe_sha256"},
        "policy.dependencies",
    )
    for name in dependencies:
        _hex64(dependencies[name], f"policy.dependencies.{name}")
    return dependencies


def _release_member_path(value: object, label: str) -> str:
    _require(type(value) is str, f"{label} path is invalid")
    _require(
        bool(value)
        and "\\" not in value
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
        and len(value.encode("utf-8")) <= 4095,
        f"{label} path is invalid",
    )
    portable = PurePosixPath(value)
    _require(
        not portable.is_absolute()
        and bool(portable.parts)
        and portable.as_posix() == value
        and all(
            part not in {"", ".", ".."} and len(part.encode("utf-8")) <= 255
            for part in portable.parts
        )
        and value != "RELEASE-MANIFEST.json",
        f"{label} path is invalid",
    )
    return value


def _validate_release_manifest(
    value: object, policy: dict[str, Any]
) -> dict[str, dict[str, object]]:
    manifest = _exact_object(
        value,
        {"schema_version", "version", "commit", "files", "manifest_sha256"},
        "release manifest",
    )
    _require(
        type(manifest["schema_version"]) is int
        and manifest["schema_version"] == 1,
        "release manifest schema mismatch",
    )
    version = _text(
        manifest["version"],
        "release manifest version",
        pattern=VERSION_PATTERN,
        maximum=128,
    )
    commit = _text(
        manifest["commit"],
        "release manifest commit",
        pattern=COMMIT_PATTERN,
        maximum=40,
    )
    supplied_digest = _hex64(
        manifest["manifest_sha256"], "release manifest SHA-256"
    )
    unsigned = {name: item for name, item in manifest.items() if name != "manifest_sha256"}
    _require(
        _release_manifest_sha256(unsigned) == supplied_digest,
        "release manifest digest mismatch",
    )
    _require(
        supplied_digest == policy["release"]["manifest_sha256"],
        "release manifest does not match the policy anchor",
    )
    _require(
        policy["release"]["release_id"] == f"{version}-{commit[:12]}",
        "release ID does not bind manifest version and commit",
    )
    rows: dict[str, dict[str, object]] = {}
    total_size = 0
    for index, item in enumerate(
        _exact_list(
            manifest["files"],
            "release manifest files",
            maximum=MAX_RELEASE_FILES,
        )
    ):
        row = _exact_object(
            item, {"path", "sha256", "size"}, f"release manifest file {index}"
        )
        path = _release_member_path(row["path"], f"release manifest file {index}")
        _require(path not in rows, "release manifest paths contain duplicates")
        _hex64(row["sha256"], f"release manifest file {index} SHA-256")
        size = _integer(
            row["size"],
            f"release manifest file {index} size",
            maximum=MAX_RELEASE_FILE_BYTES,
        )
        total_size += size
        _require(
            total_size <= MAX_RELEASE_BYTES,
            "release manifest exceeds the total size limit",
        )
        rows[path] = row
    _require(rows, "release manifest files must not be empty")
    for path, digest_field in REQUIRED_RELEASE_DEPENDENCIES.items():
        _require(path in rows, f"release manifest dependency is absent: {path}")
        expected_digest = (
            policy["collector_sha256"]
            if digest_field == "collector_sha256"
            else policy["dependencies"][digest_field]
        )
        _require(
            rows[path]["sha256"] == expected_digest,
            f"release manifest dependency digest mismatch: {path}",
        )
    _require(
        EXECUTABLE_RELEASE_MEMBERS.issubset(rows),
        "release manifest is missing an installer executable",
    )
    return rows


def _verify_release_anchor(
    policy: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, str]:
    release = policy["release"]
    anchor = _read_pinned_json(
        release["trusted_anchor_path"],
        release["trusted_anchor_sha256"],
        "trusted release anchor",
    )
    anchor = _exact_object(
        anchor,
        {"release", "commit", "manifest_sha256", "package_sha256"},
        "trusted release anchor",
    )
    _text(anchor["release"], "trusted release anchor.release")
    _text(
        anchor["commit"],
        "trusted release anchor.commit",
        pattern=COMMIT_PATTERN,
        maximum=40,
    )
    _hex64(
        anchor["manifest_sha256"], "trusted release anchor.manifest_sha256"
    )
    _hex64(anchor["package_sha256"], "trusted release anchor.package_sha256")
    _require(
        anchor
        == {
            "release": release["release_id"],
            "commit": manifest["commit"],
            "manifest_sha256": release["manifest_sha256"],
            "package_sha256": release["package_sha256"],
        },
        "trusted release anchor identity mismatch",
    )
    return anchor


def _verify_release_approval(
    policy: dict[str, Any],
    manifest: dict[str, Any],
    *,
    expected_release_approval_allowlist_sha256: str,
) -> dict[str, str]:
    payload = _read_bound_approval_payload(
        Path(TRUSTED_RELEASE_ALLOWLIST_PATH),
        expected_release_approval_allowlist_sha256,
        "trusted release approval allowlist",
    )
    allowlist = _exact_object(
        load_strict_json(payload),
        {"kind", "approvals"},
        "trusted release approval allowlist",
    )
    _require(
        allowlist["kind"] == RELEASE_APPROVAL_ALLOWLIST_KIND,
        "trusted release approval allowlist kind mismatch",
    )
    approvals = _exact_list(
        allowlist["approvals"], "trusted release approval allowlist.approvals"
    )
    _require(
        1 <= len(approvals) <= 4096,
        "trusted release approval allowlist size is invalid",
    )
    rows: list[dict[str, Any]] = []
    approval_ids: set[str] = set()
    release_ids: set[str] = set()
    for index, value in enumerate(approvals):
        label = f"trusted release approval allowlist.approvals[{index}]"
        row = _exact_object(
            value,
            {
                "approval_id",
                "approved_at",
                "release_id",
                "commit",
                "manifest_sha256",
                "package_sha256",
                "trusted_anchor_sha256",
            },
            label,
        )
        approval_id = _text(row["approval_id"], f"{label}.approval_id")
        release_id = _text(row["release_id"], f"{label}.release_id")
        approved_at = _timestamp(row["approved_at"], f"{label}.approved_at")
        _text(
            row["commit"],
            f"{label}.commit",
            pattern=COMMIT_PATTERN,
            maximum=40,
        )
        for field in (
            "manifest_sha256",
            "package_sha256",
            "trusted_anchor_sha256",
        ):
            _hex64(row[field], f"{label}.{field}")
        _require(
            approval_id not in approval_ids,
            "trusted release approval IDs must be unique",
        )
        _require(
            release_id not in release_ids,
            "trusted release approvals must identify unique releases",
        )
        approval_ids.add(approval_id)
        release_ids.add(release_id)
        rows.append(row)

    release = policy["release"]
    expected = {
        "release_id": release["release_id"],
        "commit": manifest["commit"],
        "manifest_sha256": release["manifest_sha256"],
        "package_sha256": release["package_sha256"],
        "trusted_anchor_sha256": release["trusted_anchor_sha256"],
    }
    matches = [
        row
        for row in rows
        if all(row[field] == value for field, value in expected.items())
    ]
    _require(
        len(matches) == 1,
        "release identity is not independently approved",
    )
    selected = matches[0]
    _require(
        _timestamp(selected["approved_at"], "trusted release approval approved_at")
        <= _timestamp(policy["valid_from"], "policy valid_from"),
        "trusted release approval postdates the policy",
    )
    return {
        "approval_id": selected["approval_id"],
        "approved_at": selected["approved_at"],
        "allowlist_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _verify_policy_approval(
    policy: dict[str, Any], policy_raw_sha256: str
) -> dict[str, str]:
    _hex64(policy_raw_sha256, "raw E00b policy SHA-256")
    payload = _read_bounded_regular_file(
        Path(TRUSTED_POLICY_ALLOWLIST_PATH),
        "trusted E00b policy approval allowlist",
    )
    allowlist = _exact_object(
        load_strict_json(payload),
        {"kind", "approvals"},
        "trusted E00b policy approval allowlist",
    )
    _require(
        allowlist["kind"] == POLICY_APPROVAL_ALLOWLIST_KIND,
        "trusted E00b policy approval allowlist kind mismatch",
    )
    approvals = _exact_list(
        allowlist["approvals"],
        "trusted E00b policy approval allowlist.approvals",
    )
    _require(
        1 <= len(approvals) <= 4096,
        "trusted E00b policy approval allowlist size is invalid",
    )
    rows: list[dict[str, Any]] = []
    approval_ids: set[str] = set()
    policy_ids: set[str] = set()
    policy_digests: set[str] = set()
    nonces: set[str] = set()
    for index, value in enumerate(approvals):
        label = f"trusted E00b policy approval allowlist.approvals[{index}]"
        row = _exact_object(
            value,
            {
                "approval_id",
                "approved_at",
                "expires_at",
                "policy_id",
                "policy_sha256",
                "challenge_nonce",
                "release_id",
                "e00a_report_sha256",
                "sandbox_generation_id",
                "release_approval_allowlist_sha256",
                "host_context_approval_sha256",
                "recovery_approval_allowlist_sha256",
            },
            label,
        )
        approval_id = _text(row["approval_id"], f"{label}.approval_id")
        policy_id = _text(row["policy_id"], f"{label}.policy_id")
        policy_digest = _hex64(row["policy_sha256"], f"{label}.policy_sha256")
        nonce = _hex64(row["challenge_nonce"], f"{label}.challenge_nonce")
        approved_at = _timestamp(row["approved_at"], f"{label}.approved_at")
        expires_at = _timestamp(row["expires_at"], f"{label}.expires_at")
        _text(row["release_id"], f"{label}.release_id")
        _hex64(
            row["e00a_report_sha256"], f"{label}.e00a_report_sha256"
        )
        for field in (
            "release_approval_allowlist_sha256",
            "host_context_approval_sha256",
            "recovery_approval_allowlist_sha256",
        ):
            _hex64(row[field], f"{label}.{field}")
        _uuid(row["sandbox_generation_id"], f"{label}.sandbox_generation_id")
        _require(
            approval_id not in approval_ids,
            "trusted E00b policy approval IDs must be unique",
        )
        _require(
            policy_id not in policy_ids
            and policy_digest not in policy_digests
            and nonce not in nonces,
            "trusted E00b policy approvals must have unique policy identities",
        )
        _require(
            approved_at < expires_at,
            "trusted E00b policy approval window is invalid",
        )
        approval_ids.add(approval_id)
        policy_ids.add(policy_id)
        policy_digests.add(policy_digest)
        nonces.add(nonce)
        rows.append(row)

    supporting_digests: dict[str, str] = {}
    for field, path, label in (
        (
            "release_approval_allowlist_sha256",
            TRUSTED_RELEASE_ALLOWLIST_PATH,
            "trusted release approval allowlist",
        ),
        (
            "host_context_approval_sha256",
            TRUSTED_HOST_CONTEXT_PATH,
            "trusted host context approval",
        ),
        (
            "recovery_approval_allowlist_sha256",
            TRUSTED_RECOVERY_ALLOWLIST_PATH,
            "trusted recovery drill approval allowlist",
        ),
    ):
        supporting_digests[field] = hashlib.sha256(
            _read_bounded_regular_file(Path(path), label)
        ).hexdigest()

    expected = {
        "policy_id": policy["policy_id"],
        "policy_sha256": policy_raw_sha256,
        "challenge_nonce": policy["challenge_nonce"],
        "release_id": policy["release"]["release_id"],
        "e00a_report_sha256": policy["e00a"]["report_sha256"],
        "sandbox_generation_id": policy["sandbox"]["sandbox_generation_id"],
        "expires_at": policy["expires_at"],
        **supporting_digests,
    }
    matches = [
        row
        for row in rows
        if all(row[field] == value for field, value in expected.items())
    ]
    _require(
        len(matches) == 1,
        "E00b policy is not independently approved",
    )
    selected = matches[0]
    _require(
        _timestamp(selected["approved_at"], "trusted E00b policy approval approved_at")
        <= _timestamp(policy["valid_from"], "policy valid_from"),
        "trusted E00b policy approval time is invalid",
    )
    return {
        "approval_id": selected["approval_id"],
        "approved_at": selected["approved_at"],
        "allowlist_sha256": hashlib.sha256(payload).hexdigest(),
        **supporting_digests,
    }


def _verify_supporting_approval_roots(
    policy_approval: dict[str, str],
) -> None:
    bindings = _exact_object(
        policy_approval,
        {
            "approval_id",
            "approved_at",
            "allowlist_sha256",
            "release_approval_allowlist_sha256",
            "host_context_approval_sha256",
            "recovery_approval_allowlist_sha256",
        },
        "opening trusted approval bindings",
    )
    _text(bindings["approval_id"], "opening trusted approval ID")
    _timestamp(bindings["approved_at"], "opening trusted approval time")
    for field in (
        "allowlist_sha256",
        "release_approval_allowlist_sha256",
        "host_context_approval_sha256",
        "recovery_approval_allowlist_sha256",
    ):
        _hex64(bindings[field], f"opening trusted approval {field}")
    for path, field, label in (
        (
            TRUSTED_POLICY_ALLOWLIST_PATH,
            "allowlist_sha256",
            "trusted E00b policy approval allowlist",
        ),
        (
            TRUSTED_RELEASE_ALLOWLIST_PATH,
            "release_approval_allowlist_sha256",
            "trusted release approval allowlist",
        ),
        (
            TRUSTED_HOST_CONTEXT_PATH,
            "host_context_approval_sha256",
            "trusted host context approval",
        ),
        (
            TRUSTED_RECOVERY_ALLOWLIST_PATH,
            "recovery_approval_allowlist_sha256",
            "trusted recovery drill approval allowlist",
        ),
    ):
        _read_bound_approval_payload(Path(path), bindings[field], label)


def _verify_canonical_package(policy: dict[str, Any]) -> dict[str, object]:
    release = policy["release"]
    package_path = Path(
        "/opt/odoo-accounting-cli-v3/packages/"
        f"odoo-accounting-cli-v3-{release['release_id']}.tar.gz"
    )
    try:
        metadata = package_path.lstat()
    except OSError as exc:
        raise IsolationGateError("canonical release package is unavailable") from exc
    _require(
        not package_path.is_symlink()
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o444,
        "canonical release package metadata mismatch",
    )
    if sys.platform == "linux":
        _require(
            package_path.resolve(strict=True) == package_path
            and metadata.st_uid == 0
            and metadata.st_gid == 0,
            "canonical release package trust mismatch",
        )
        _verify_root_directory_chain(package_path.parent, "canonical release package")
    digest, size = _hash_bounded_regular_file(
        package_path,
        "canonical release package",
        maximum_size=MAX_RELEASE_BYTES,
    )
    _require(
        digest == release["package_sha256"],
        "canonical release package digest mismatch",
    )
    return {"path": str(package_path), "sha256": digest, "size": size}


def _validate_release_inventory(
    rows: dict[str, dict[str, object]],
    inventory: dict[str, dict[str, object]],
) -> None:
    expected_files = set(rows) | {"RELEASE-MANIFEST.json"}
    expected_directories = {"."}
    for name in expected_files:
        for parent in PurePosixPath(name).parents:
            if parent.as_posix() != ".":
                expected_directories.add(parent.as_posix())
    actual_files = {
        name for name, item in inventory.items() if item.get("kind") == "file"
    }
    actual_directories = {
        name for name, item in inventory.items() if item.get("kind") == "directory"
    }
    _require(
        actual_files == expected_files
        and actual_directories == expected_directories
        and set(inventory) == actual_files | actual_directories,
        "installed release tree does not match the manifest closure",
    )
    root_device = inventory["."].get("device")
    for name in sorted(actual_directories):
        item = inventory[name]
        _require(
            set(item) == {"kind", "uid", "gid", "mode", "device"}
            and item["kind"] == "directory"
            and item["uid"] == 0
            and item["gid"] == 0
            and item["mode"] == 0o555
            and item["device"] == root_device,
            f"installed release directory metadata mismatch: {name}",
        )
    for name in sorted(actual_files):
        item = inventory[name]
        expected_mode = 0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444
        _require(
            set(item)
            == {"kind", "uid", "gid", "mode", "device", "nlink", "size", "sha256"}
            and item["kind"] == "file"
            and item["uid"] == 0
            and item["gid"] == 0
            and item["mode"] == expected_mode
            and item["device"] == root_device
            and item["nlink"] == 1,
            f"installed release file metadata mismatch: {name}",
        )
        _hex64(item["sha256"], f"installed release file digest: {name}")
        _integer(
            item["size"],
            f"installed release file size: {name}",
            maximum=(
                MAX_INPUT_BYTES
                if name == "RELEASE-MANIFEST.json"
                else MAX_RELEASE_FILE_BYTES
            ),
        )
        if name != "RELEASE-MANIFEST.json":
            _require(
                item["size"] == rows[name]["size"]
                and item["sha256"] == rows[name]["sha256"],
                f"installed release file content mismatch: {name}",
            )


def _verify_release_tree(
    release_root: Path, rows: dict[str, dict[str, object]]
) -> dict[str, dict[str, object]]:
    try:
        paths = [release_root, *release_root.rglob("*")]
    except OSError as exc:
        raise IsolationGateError("installed release tree cannot be enumerated") from exc
    _require(
        len(paths) <= MAX_RELEASE_TREE_ENTRIES,
        "installed release tree has too many entries",
    )
    inventory: dict[str, dict[str, object]] = {}
    for path in paths:
        relative = "." if path == release_root else path.relative_to(release_root).as_posix()
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise IsolationGateError(
                f"installed release entry cannot be inspected: {relative}"
            ) from exc
        _require(
            not stat.S_ISLNK(metadata.st_mode),
            f"installed release symlink is forbidden: {relative}",
        )
        if stat.S_ISDIR(metadata.st_mode):
            if sys.platform == "linux":
                _require(
                    path.resolve(strict=True) == path,
                    f"installed release directory is not physical: {relative}",
                )
            inventory[relative] = {
                "kind": "directory",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "device": metadata.st_dev,
            }
        elif stat.S_ISREG(metadata.st_mode):
            maximum_size = (
                MAX_INPUT_BYTES
                if relative == "RELEASE-MANIFEST.json"
                else MAX_RELEASE_FILE_BYTES
            )
            digest, size = _hash_bounded_regular_file(
                path, f"installed release file {relative}", maximum_size=maximum_size
            )
            inventory[relative] = {
                "kind": "file",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "mode": stat.S_IMODE(metadata.st_mode),
                "device": metadata.st_dev,
                "nlink": metadata.st_nlink,
                "size": size,
                "sha256": digest,
            }
        else:
            raise IsolationGateError(
                f"installed release object type is unsafe: {relative}"
            )
    _validate_release_inventory(rows, inventory)
    return inventory


def _verify_hermetic_python_flags() -> None:
    flags = getattr(sys, "flags", None)
    _require(
        flags is not None
        and getattr(flags, "isolated", None) == 1
        and getattr(flags, "dont_write_bytecode", None) == 1
        and sys.dont_write_bytecode is True
        and getattr(flags, "no_site", None) == 1
        and getattr(flags, "safe_path", None) is True
        and getattr(flags, "no_user_site", None) == 1
        and getattr(flags, "ignore_environment", None) == 1
        and getattr(flags, "optimize", None) == 0,
        "live isolation gate requires Python -I -B -S with safe unoptimized flags",
    )


def _read_runtime_proc_text(path: PurePosixPath, label: str) -> str:
    _require(path.is_absolute(), f"{label} proc path must be absolute")
    try:
        descriptor = os.open(
            str(path),
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.fstat(descriptor)
            _require(stat.S_ISREG(metadata.st_mode), f"{label} is not a proc file")
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 4097 - len(payload))
                if not chunk:
                    break
                payload.extend(chunk)
                _require(len(payload) <= 4096, f"{label} is too large")
        finally:
            os.close(descriptor)
    except IsolationGateError:
        raise
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be read safely") from exc
    try:
        value = bytes(payload).decode("ascii")
    except UnicodeDecodeError as exc:
        raise IsolationGateError(f"{label} is not ASCII") from exc
    _require("\x00" not in value, f"{label} contains NUL")
    return value


def _read_namespace_identity_facts(
    path: PurePosixPath, namespace: str, label: str
) -> dict[str, object]:
    kernel_name = HOST_NAMESPACE_NAMES[namespace]
    try:
        before = os.stat(str(path))
        link_before = os.readlink(str(path))
        opened = os.stat(str(path))
        link_after = os.readlink(str(path))
    except OSError as exc:
        raise IsolationGateError(f"{label} cannot be inspected") from exc
    before_identity = (before.st_dev, before.st_ino)
    opened_identity = (opened.st_dev, opened.st_ino)
    _require(
        before_identity == opened_identity and link_before == link_after,
        f"{label} changed during inspection",
    )
    link_match = re.fullmatch(
        rf"{re.escape(kernel_name)}:\[([1-9][0-9]*)\]", link_before
    )
    _require(
        before.st_dev > 0
        and before.st_ino > 0
        and link_match is not None
        and int(link_match.group(1), 10) == before.st_ino,
        f"{label} identity is invalid",
    )
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "link": link_before,
    }


def _validate_host_context(value: object, label: str) -> dict[str, Any]:
    context = _exact_object(
        value,
        {"hostname", "machine_id_sha256", "boot_id_sha256", "namespaces"},
        label,
    )
    _text(
        context["hostname"],
        f"{label}.hostname",
        pattern=HOSTNAME_PATTERN,
        maximum=253,
    )
    _hex64(context["machine_id_sha256"], f"{label}.machine_id_sha256")
    _hex64(context["boot_id_sha256"], f"{label}.boot_id_sha256")
    namespaces = _exact_object(
        context["namespaces"], set(HOST_NAMESPACE_NAMES), f"{label}.namespaces"
    )
    for name, kernel_name in HOST_NAMESPACE_NAMES.items():
        namespace = _exact_object(
            namespaces[name],
            {"device", "inode", "link"},
            f"{label}.namespaces.{name}",
        )
        _integer(
            namespace["device"],
            f"{label}.namespaces.{name}.device",
            minimum=1,
            maximum=2**63 - 1,
        )
        _integer(
            namespace["inode"],
            f"{label}.namespaces.{name}.inode",
            minimum=1,
            maximum=2**63 - 1,
        )
        link_match = (
            re.fullmatch(
                rf"{re.escape(kernel_name)}:\[([1-9][0-9]*)\]",
                namespace["link"],
            )
            if type(namespace["link"]) is str
            else None
        )
        _require(
            link_match is not None
            and int(link_match.group(1), 10) == namespace["inode"],
            f"{label}.namespaces.{name}.link/inode identity is invalid",
        )
    return context


def _parse_root_status_ids(value: str) -> None:
    rows: dict[str, list[str]] = {}
    for line in value.splitlines():
        name, separator, remainder = line.partition(":")
        if separator and name in {"Uid", "Gid"}:
            _require(name not in rows, f"runtime status contains duplicate {name}")
            rows[name] = remainder.split()
    _require(set(rows) == {"Uid", "Gid"}, "runtime status UID/GID fields are missing")
    _require(
        all(values == ["0", "0", "0", "0"] for values in rows.values()),
        "live isolation gate requires real, effective, saved, and filesystem root IDs",
    )


def _capture_live_host_context() -> dict[str, object]:
    _require(
        hasattr(os, "getresuid") and os.getresuid() == (0, 0, 0),
        "live isolation gate requires real, effective, and saved root UID",
    )
    _require(
        hasattr(os, "getresgid") and os.getresgid() == (0, 0, 0),
        "live isolation gate requires real, effective, and saved root GID",
    )
    uid_map = _read_runtime_proc_text(
        PurePosixPath("/proc/self/uid_map"), "runtime UID map"
    )
    gid_map = _read_runtime_proc_text(
        PurePosixPath("/proc/self/gid_map"), "runtime GID map"
    )

    def parse_map(value: str) -> tuple[int, int, int] | None:
        lines = [line.split() for line in value.splitlines() if line.strip()]
        if len(lines) != 1 or len(lines[0]) != 3:
            return None
        if any(re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", item) is None for item in lines[0]):
            return None
        return tuple(int(item) for item in lines[0])  # type: ignore[return-value]

    _require(
        parse_map(uid_map) == (0, 0, 4_294_967_295)
        and parse_map(gid_map) == (0, 0, 4_294_967_295),
        "live isolation gate requires initial user namespace ID maps",
    )
    _parse_root_status_ids(
        _read_runtime_proc_text(
            PurePosixPath("/proc/self/status"), "runtime process status"
        )
    )
    namespaces: dict[str, dict[str, object]] = {}
    for namespace in HOST_NAMESPACE_NAMES:
        current = _read_namespace_identity_facts(
            PurePosixPath(f"/proc/self/ns/{namespace}"),
            namespace,
            f"runtime {namespace} namespace",
        )
        init = _read_namespace_identity_facts(
            PurePosixPath(f"/proc/1/ns/{namespace}"),
            namespace,
            f"PID 1 {namespace} namespace",
        )
        _require(
            current == init,
            "live isolation gate requires the initial host namespaces",
        )
        namespaces[namespace] = current
    machine_id = _read_bounded_regular_file(Path("/etc/machine-id"), "machine ID")
    boot_id = _read_bounded_regular_file(
        Path("/proc/sys/kernel/random/boot_id"), "boot ID"
    )
    _require(
        re.fullmatch(rb"[0-9a-f]{32}\n?", machine_id) is not None,
        "live isolation gate machine identity is invalid",
    )
    try:
        UUID(boot_id.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise IsolationGateError("live isolation gate boot identity is invalid") from exc
    return _validate_host_context(
        {
            "hostname": socket.gethostname(),
            "machine_id_sha256": hashlib.sha256(machine_id).hexdigest(),
            "boot_id_sha256": hashlib.sha256(boot_id).hexdigest(),
            "namespaces": namespaces,
        },
        "live host context",
    )


def _load_host_context_approval(
    policy: dict[str, Any],
    *,
    expected_host_context_approval_sha256: str,
) -> tuple[dict[str, Any], str]:
    payload = _read_bound_approval_payload(
        Path(TRUSTED_HOST_CONTEXT_PATH),
        expected_host_context_approval_sha256,
        "trusted host context approval",
    )
    approval = _exact_object(
        load_strict_json(payload),
        {
            "kind",
            "approval_id",
            "approved_at",
            "e00a_report_sha256",
            "e00a_observation_sha256",
            "host",
        },
        "trusted host context approval",
    )
    _require(
        approval["kind"] == HOST_CONTEXT_APPROVAL_KIND,
        "trusted host context approval kind mismatch",
    )
    _text(approval["approval_id"], "trusted host context approval.approval_id")
    approved_at = _timestamp(
        approval["approved_at"], "trusted host context approval.approved_at"
    )
    _hex64(
        approval["e00a_report_sha256"],
        "trusted host context approval.e00a_report_sha256",
    )
    _hex64(
        approval["e00a_observation_sha256"],
        "trusted host context approval.e00a_observation_sha256",
    )
    host = _validate_host_context(
        approval["host"], "trusted host context approval.host"
    )
    _require(
        approval["e00a_report_sha256"] == policy["e00a"]["report_sha256"]
        and approval["e00a_observation_sha256"]
        == policy["e00a"]["observation_sha256"],
        "trusted host context approval does not bind E00a",
    )
    _require(
        _timestamp(policy["e00a"]["captured_at"], "E00a captured_at")
        <= approved_at
        <= _timestamp(policy["valid_from"], "policy valid_from"),
        "trusted host context approval time is invalid",
    )
    _require(
        host["machine_id_sha256"] == policy["host"]["machine_id_sha256"],
        "trusted host context approval machine identity mismatch",
    )
    return approval, hashlib.sha256(payload).hexdigest()


def _verify_initial_root_context(
    policy: dict[str, Any],
    *,
    expected_host_context_approval_sha256: str,
) -> dict[str, object]:
    approval, _approval_sha256 = _load_host_context_approval(
        policy,
        expected_host_context_approval_sha256=(
            expected_host_context_approval_sha256
        ),
    )
    before = _capture_live_host_context()
    after = _capture_live_host_context()
    _require(before == after, "live host context changed during verification")
    _require(
        after == approval["host"],
        "live host context does not match the independent approval",
    )
    return after


def _verify_e00a_host_approval(
    policy: dict[str, Any],
    observation: dict[str, Any],
    *,
    expected_host_context_approval_sha256: str,
) -> dict[str, str]:
    approval, approval_sha256 = _load_host_context_approval(
        policy,
        expected_host_context_approval_sha256=(
            expected_host_context_approval_sha256
        ),
    )
    host = approval["host"]
    _require(
        observation.get("host")
        == {
            "hostname": host["hostname"],
            "machine_id_sha256": host["machine_id_sha256"],
            "boot_id_sha256": host["boot_id_sha256"],
        }
        and type(observation.get("provenance")) is dict
        and observation["provenance"].get("mount_namespace_identity_sha256")
        == _canonical_sha256(host["namespaces"]["mnt"]),
        "E00a host context does not match the independent approval",
    )
    return {
        "approval_id": approval["approval_id"],
        "approved_at": approval["approved_at"],
        "approval_sha256": approval_sha256,
    }


def _read_process_executable() -> str:
    try:
        before = os.readlink("/proc/self/exe")
        after = os.readlink("/proc/self/exe")
    except OSError as exc:
        raise IsolationGateError("process executable cannot be inspected") from exc
    _require(before == after, "process executable changed during inspection")
    return before


def _read_process_cmdline() -> list[str]:
    def read_once() -> tuple[bytes, list[str]]:
        try:
            descriptor = os.open(
                "/proc/self/cmdline",
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                _require(
                    stat.S_ISREG(metadata.st_mode),
                    "process command line is not a proc file",
                )
                payload = bytearray()
                while True:
                    chunk = os.read(
                        descriptor,
                        min(4096, MAX_PROC_CMDLINE_BYTES + 1 - len(payload)),
                    )
                    if not chunk:
                        break
                    payload.extend(chunk)
                    _require(
                        len(payload) <= MAX_PROC_CMDLINE_BYTES,
                        "process command line is too large",
                    )
            finally:
                os.close(descriptor)
        except IsolationGateError:
            raise
        except OSError as exc:
            raise IsolationGateError(
                "process command line cannot be inspected"
            ) from exc
        raw = bytes(payload)
        _require(
            bool(raw) and raw.endswith(b"\x00"),
            "process command line framing is invalid",
        )
        encoded_arguments = raw[:-1].split(b"\x00")
        _require(
            bool(encoded_arguments) and all(encoded_arguments),
            "process command line framing is invalid",
        )
        arguments = [os.fsdecode(argument) for argument in encoded_arguments]
        _require(
            all(
                os.fsencode(argument) == encoded
                for argument, encoded in zip(arguments, encoded_arguments, strict=True)
            ),
            "process command line encoding is invalid",
        )
        return raw, arguments

    before_raw, before_arguments = read_once()
    after_raw, after_arguments = read_once()
    _require(
        before_raw == after_raw and before_arguments == after_arguments,
        "process command line changed during inspection",
    )
    return before_arguments


def _verify_trusted_runtime_path(path: Path, require_regular: bool) -> None:
    _require(path.is_absolute(), "trusted runtime path must be absolute")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        current = path.parent
        while not current.exists() and current.parent != current:
            current = current.parent
        _require(current.exists(), "trusted runtime path ancestor is absent")
        _verify_root_directory_chain(current, "trusted runtime path")
        return
    except OSError as exc:
        raise IsolationGateError("trusted runtime path cannot be inspected") from exc
    _require(not path.is_symlink(), "trusted runtime path must not be a symlink")
    _require(
        stat.S_ISREG(metadata.st_mode)
        if require_regular
        else stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode),
        "trusted runtime path type is invalid",
    )
    if stat.S_ISREG(metadata.st_mode):
        _require(metadata.st_nlink == 1, "trusted runtime file must have one link")
    if sys.platform == "linux":
        _require(path.resolve(strict=True) == path, "trusted runtime path is not physical")
        _require(
            metadata.st_uid == 0
            and metadata.st_gid == 0
            and metadata.st_mode & 0o022 == 0,
            "trusted runtime path is not root-owned and non-writable",
        )
        _verify_root_directory_chain(path.parent, "trusted runtime path")


def _verify_direct_interpreter_invocation(
    collector_path: Path, cli_arguments: list[str]
) -> None:
    _require(
        type(cli_arguments) is list
        and len(cli_arguments) == 4
        and all(type(item) is str and bool(item) for item in cli_arguments)
        and cli_arguments[0] == "--policy"
        and cli_arguments[2] == "--expected-policy-sha256",
        "live isolation gate requires direct trusted interpreter invocation",
    )
    expected_script_arguments = [str(collector_path), *cli_arguments]
    _require(
        type(getattr(sys, "argv", None)) is list
        and sys.argv == expected_script_arguments
        and Path(sys.argv[0]).is_absolute(),
        "live isolation gate requires direct trusted interpreter invocation",
    )
    executable_value = getattr(sys, "executable", None)
    _require(
        type(executable_value) is str and Path(executable_value).is_absolute(),
        "live isolation gate requires direct trusted interpreter invocation",
    )
    expected_process_arguments = [
        executable_value,
        "-I",
        "-B",
        "-S",
        *expected_script_arguments,
    ]
    _require(
        _read_process_cmdline() == expected_process_arguments,
        "live isolation gate requires direct trusted interpreter invocation",
    )
    try:
        executable = Path(executable_value).resolve(strict=True)
    except OSError as exc:
        raise IsolationGateError(
            "live isolation gate requires direct trusted interpreter invocation"
        ) from exc
    process_executable = Path(_read_process_executable())
    _require(
        process_executable.is_absolute() and process_executable == executable,
        "live isolation gate requires direct trusted interpreter invocation",
    )
    _verify_trusted_runtime_path(executable, True)
    search_paths = getattr(sys, "path", None)
    _require(
        type(search_paths) is list and bool(search_paths),
        "live isolation gate requires direct trusted interpreter invocation",
    )
    for item in search_paths:
        _require(
            type(item) is str and bool(item) and Path(item).is_absolute(),
            "live isolation gate requires direct trusted interpreter invocation",
        )
        _verify_trusted_runtime_path(Path(item), False)


def _verify_release_runtime(
    policy: dict[str, Any],
    cli_arguments: list[str],
    *,
    expected_release_approval_allowlist_sha256: str,
    expected_host_context_approval_sha256: str,
) -> dict[str, dict[str, object]]:
    _require(sys.platform == "linux", "live isolation gate requires Linux")
    _require(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "live isolation gate requires root",
    )
    _verify_initial_root_context(
        policy,
        expected_host_context_approval_sha256=(
            expected_host_context_approval_sha256
        ),
    )
    _verify_hermetic_python_flags()
    release_root = Path(policy["release"]["release_root"])
    expected_collector = (
        release_root / "deployment" / "dev19" / "sandbox_isolation_gate.py"
    )
    collector_path = Path(__file__)
    _require(collector_path.is_absolute(), "collector program path must be absolute")
    _require(
        collector_path == expected_collector,
        "collector program is outside the pinned release layout",
    )
    _verify_direct_interpreter_invocation(collector_path, cli_arguments)
    _verify_root_directory_chain(release_root, "release root")
    collector_payload = _read_bounded_regular_file(collector_path, "collector program")
    _require(
        hashlib.sha256(collector_payload).hexdigest() == policy["collector_sha256"],
        "collector program SHA-256 mismatch",
    )
    manifest_payload = _read_bounded_regular_file(
        release_root / "RELEASE-MANIFEST.json", "release manifest"
    )
    manifest = load_strict_json(manifest_payload)
    rows = _validate_release_manifest(manifest, policy)
    _verify_release_anchor(policy, manifest)
    _verify_release_approval(
        policy,
        manifest,
        expected_release_approval_allowlist_sha256=(
            expected_release_approval_allowlist_sha256
        ),
    )
    _verify_canonical_package(policy)
    for relative_path in REQUIRED_RELEASE_DEPENDENCIES:
        row = rows[relative_path]
        payload = _read_bounded_regular_file(
            release_root.joinpath(*PurePosixPath(relative_path).parts),
            f"release dependency {relative_path}",
        )
        _require(
            len(payload) == row["size"]
            and hashlib.sha256(payload).hexdigest() == row["sha256"],
            f"release dependency changed: {relative_path}",
        )
    _verify_release_tree(release_root, rows)
    return rows


def _load_dev18_verifier(
    policy: dict[str, Any], rows: dict[str, dict[str, object]]
) -> types.ModuleType:
    _require(DEV18_VERIFIER_PATH in rows, "Dev18 verifier is absent from the release")
    row = rows[DEV18_VERIFIER_PATH]
    source_path = Path(policy["release"]["release_root"]).joinpath(
        *PurePosixPath(DEV18_VERIFIER_PATH).parts
    )
    payload = _read_bounded_regular_file(source_path, "Dev18 verifier")
    _require(
        len(payload) == row["size"]
        and hashlib.sha256(payload).hexdigest() == row["sha256"]
        and row["sha256"] == policy["dependencies"]["dev18_collector_sha256"],
        "Dev18 verifier dependency changed",
    )
    module = types.ModuleType("_odoo_accounting_cli_v3_dev18_capacity_gate")
    module.__file__ = str(source_path)
    module.__package__ = ""
    try:
        code = compile(payload, str(source_path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except (Exception, SystemExit) as exc:
        raise IsolationGateError("Dev18 verifier cannot be loaded safely") from exc
    _require(
        callable(getattr(module, "_validate_policy", None))
        and callable(getattr(module, "_validate_observation", None))
        and callable(getattr(module, "evaluate", None)),
        "Dev18 verifier interface is unavailable",
    )
    return module


def _verify_e00a_prerequisite(
    policy: dict[str, Any],
    dev18_module: types.ModuleType,
    *,
    expected_host_context_approval_sha256: str,
) -> dict[str, object]:
    bundle = _load_e00a_bundle(policy)
    try:
        return _verify_e00a_bundle(
            policy,
            bundle,
            dev18_module,
            expected_host_context_approval_sha256=(
                expected_host_context_approval_sha256
            ),
        )
    except IsolationGateError:
        raise
    except (Exception, SystemExit) as exc:
        raise IsolationGateError(
            "E00a bundle was rejected by the pinned Dev18 verifier"
        ) from exc


def _validate_e00a(value: object, label: str) -> dict[str, Any]:
    e00a = _exact_object(
        value,
        {
            "policy_path",
            "policy_sha256",
            "report_path",
            "report_sha256",
            "observation_path",
            "observation_sha256",
            "captured_at",
            "production_cluster_system_identifier",
            "protected_database_uuids",
            "protected_identity_sha256",
        },
        label,
    )
    _absolute_path(e00a["policy_path"], f"{label}.policy_path")
    _hex64(e00a["policy_sha256"], f"{label}.policy_sha256")
    _absolute_path(e00a["report_path"], f"{label}.report_path")
    _hex64(e00a["report_sha256"], f"{label}.report_sha256")
    _absolute_path(e00a["observation_path"], f"{label}.observation_path")
    _hex64(e00a["observation_sha256"], f"{label}.observation_sha256")
    _timestamp(e00a["captured_at"], f"{label}.captured_at")
    _text(
        e00a["production_cluster_system_identifier"],
        f"{label}.production_cluster_system_identifier",
        pattern=re.compile(r"^[0-9]{10,32}$"),
        maximum=32,
    )
    protected = _unique_uuids(
        e00a["protected_database_uuids"], f"{label}.protected_database_uuids"
    )
    _require(protected, f"{label}.protected_database_uuids must not be empty")
    _hex64(
        e00a["protected_identity_sha256"],
        f"{label}.protected_identity_sha256",
    )
    return e00a


def _validate_host_policy(value: object) -> dict[str, Any]:
    host = _exact_object(value, {"machine_id_sha256"}, "policy.host")
    _hex64(host["machine_id_sha256"], "policy.host.machine_id_sha256")
    return host


_SANDBOX_POLICY_FIELDS = {
    "environment",
    "odoo_instance_id",
    "database_name",
    "database_uuid",
    "database_filter",
    "database_catalog_names",
    "postgresql_identity_sha256",
    "postgresql_service_unit",
    "postgresql_os_user",
    "postgresql_uid",
    "postgresql_gid",
    "postgresql_role",
    "postgresql_data_dir",
    "postgresql_socket_dir",
    "postgresql_port",
    "odoo_identity_sha256",
    "odoo_service_unit",
    "odoo_os_user",
    "odoo_uid",
    "odoo_gid",
    "odoo_config_path",
    "odoo_executable_path",
    "data_dir",
    "filestore_dir",
    "immutable_addon_roots",
    "sandbox_paths_identity_sha256",
    "state_identity_sha256",
    "secrets_identity_sha256",
    "write_state_path",
    "secret_paths",
    "sandbox_generation_id",
    "executor_user_id",
    "approver_user_id",
    "allowed_company_ids",
}


def _validate_sandbox_policy(value: object) -> dict[str, Any]:
    sandbox = _exact_object(value, _SANDBOX_POLICY_FIELDS, "policy.sandbox")
    _text(sandbox["environment"], "policy.sandbox.environment")
    _text(sandbox["odoo_instance_id"], "policy.sandbox.odoo_instance_id")
    _text(
        sandbox["database_name"],
        "policy.sandbox.database_name",
        pattern=SAFE_NAME,
        maximum=128,
    )
    _uuid(sandbox["database_uuid"], "policy.sandbox.database_uuid")
    _text(
        sandbox["database_filter"],
        "policy.sandbox.database_filter",
        pattern=re.compile(r"^\^[A-Za-z0-9_.\\-]+\$$"),
        maximum=256,
    )
    catalog = _unique_texts(
        sandbox["database_catalog_names"],
        "policy.sandbox.database_catalog_names",
        pattern=SAFE_NAME,
        maximum=128,
    )
    _require(catalog, "policy.sandbox.database_catalog_names must not be empty")
    for name in (
        "postgresql_identity_sha256",
        "odoo_identity_sha256",
        "sandbox_paths_identity_sha256",
        "state_identity_sha256",
        "secrets_identity_sha256",
    ):
        _hex64(sandbox[name], f"policy.sandbox.{name}")
    for name in (
        "postgresql_service_unit",
        "postgresql_os_user",
        "postgresql_role",
        "odoo_service_unit",
        "odoo_os_user",
    ):
        _text(sandbox[name], f"policy.sandbox.{name}")
    for name in ("postgresql_uid", "postgresql_gid", "odoo_uid", "odoo_gid"):
        _integer(sandbox[name], f"policy.sandbox.{name}", minimum=1)
    _integer(
        sandbox["postgresql_port"],
        "policy.sandbox.postgresql_port",
        minimum=1,
        maximum=65535,
    )
    for name in (
        "postgresql_data_dir",
        "postgresql_socket_dir",
        "odoo_config_path",
        "odoo_executable_path",
        "data_dir",
        "filestore_dir",
        "write_state_path",
    ):
        _absolute_path(sandbox[name], f"policy.sandbox.{name}")
    addons = _unique_paths(
        sandbox["immutable_addon_roots"],
        "policy.sandbox.immutable_addon_roots",
    )
    secrets = _unique_paths(sandbox["secret_paths"], "policy.sandbox.secret_paths")
    _require(addons, "policy.sandbox.immutable_addon_roots must not be empty")
    _require(secrets, "policy.sandbox.secret_paths must not be empty")
    _uuid(
        sandbox["sandbox_generation_id"],
        "policy.sandbox.sandbox_generation_id",
    )
    _integer(
        sandbox["executor_user_id"],
        "policy.sandbox.executor_user_id",
        minimum=1,
    )
    _integer(
        sandbox["approver_user_id"],
        "policy.sandbox.approver_user_id",
        minimum=1,
    )
    companies = _unique_integers(
        sandbox["allowed_company_ids"], "policy.sandbox.allowed_company_ids"
    )
    _require(companies, "policy.sandbox.allowed_company_ids must not be empty")
    return sandbox


_DATABASE_ENDPOINT_FIELDS = {
    "endpoint_id",
    "socket_path",
    "port",
    "database_name",
    "role_name",
    "cluster_system_identifier",
}


def _validate_database_endpoints(value: object, label: str) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for index, item in enumerate(_exact_list(value, label)):
        endpoint = _exact_object(
            item, _DATABASE_ENDPOINT_FIELDS, f"{label}[{index}]"
        )
        _text(endpoint["endpoint_id"], f"{label}[{index}].endpoint_id")
        _absolute_path(endpoint["socket_path"], f"{label}[{index}].socket_path")
        _integer(
            endpoint["port"], f"{label}[{index}].port", minimum=1, maximum=65535
        )
        for name in ("database_name", "role_name"):
            _text(
                endpoint[name],
                f"{label}[{index}].{name}",
                pattern=SAFE_NAME,
                maximum=128,
            )
        _text(
            endpoint["cluster_system_identifier"],
            f"{label}[{index}].cluster_system_identifier",
            pattern=re.compile(r"^[0-9]{10,32}$"),
            maximum=32,
        )
        endpoints.append(endpoint)
    _require(endpoints, f"{label} must not be empty")
    _require(
        len(endpoints) == len({item["endpoint_id"] for item in endpoints}),
        f"{label} endpoint IDs contain duplicates",
    )
    return endpoints


def _validate_production_policy(value: object) -> dict[str, Any]:
    production = _exact_object(
        value,
        {
            "protected_service_units",
            "protected_paths",
            "protected_postgresql_sockets",
            "protected_database_names",
            "protected_database_endpoints",
            "protected_identity_sha256",
        },
        "policy.production",
    )
    for name in ("protected_service_units", "protected_database_names"):
        values = _unique_texts(
            production[name], f"policy.production.{name}", pattern=SAFE_NAME, maximum=128
        )
        _require(values, f"policy.production.{name} must not be empty")
    for name in ("protected_paths", "protected_postgresql_sockets"):
        values = _unique_paths(production[name], f"policy.production.{name}")
        _require(values, f"policy.production.{name} must not be empty")
    endpoints = _validate_database_endpoints(
        production["protected_database_endpoints"],
        "policy.production.protected_database_endpoints",
    )
    _require(
        {item["database_name"] for item in endpoints}
        == set(production["protected_database_names"]),
        "policy production database endpoint name coverage is incomplete",
    )
    _require(
        {item["socket_path"] for item in endpoints}
        == set(production["protected_postgresql_sockets"]),
        "policy production database endpoint socket coverage is incomplete",
    )
    _hex64(
        production["protected_identity_sha256"],
        "policy.production.protected_identity_sha256",
    )
    return production


def _validate_recovery_policy(value: object) -> dict[str, Any]:
    recovery = _exact_object(
        value,
        {
            "drill_receipt_path",
            "drill_receipt_sha256",
            "approval_id",
            "approved_by_user_id",
            "database_backup_path",
            "database_backup_sha256",
            "filestore_backup_path",
            "filestore_backup_sha256",
            "paired_manifest_path",
            "paired_manifest_sha256",
            "previous_database_uuid",
            "previous_generation_id",
            "previous_state_path",
            "previous_state_identity_sha256",
            "old_evidence_path",
            "old_evidence_identity_sha256",
            "previous_key_ids",
            "new_key_ids",
        },
        "policy.recovery",
    )
    _absolute_path(recovery["drill_receipt_path"], "policy.recovery.drill_receipt_path")
    _text(recovery["approval_id"], "policy.recovery.approval_id")
    _integer(
        recovery["approved_by_user_id"],
        "policy.recovery.approved_by_user_id",
        minimum=1,
    )
    for name in (
        "database_backup_path",
        "filestore_backup_path",
        "paired_manifest_path",
        "old_evidence_path",
    ):
        _absolute_path(recovery[name], f"policy.recovery.{name}")
    for name in (
        "drill_receipt_sha256",
        "database_backup_sha256",
        "filestore_backup_sha256",
        "paired_manifest_sha256",
        "previous_state_identity_sha256",
        "old_evidence_identity_sha256",
    ):
        _hex64(recovery[name], f"policy.recovery.{name}")
    _uuid(recovery["previous_database_uuid"], "policy.recovery.previous_database_uuid")
    _uuid(recovery["previous_generation_id"], "policy.recovery.previous_generation_id")
    _absolute_path(recovery["previous_state_path"], "policy.recovery.previous_state_path")
    for name in ("previous_key_ids", "new_key_ids"):
        keys = _unique_texts(recovery[name], f"policy.recovery.{name}")
        _require(keys, f"policy.recovery.{name} must not be empty")
    _require(
        set(recovery["previous_key_ids"]).isdisjoint(recovery["new_key_ids"]),
        "policy recovery key identities were not rotated",
    )
    return recovery


def _validate_policy(value: object) -> dict[str, Any]:
    policy = _exact_object(
        value,
        {
            "kind",
            "policy_id",
            "challenge_nonce",
            "valid_from",
            "expires_at",
            "max_capture_duration_seconds",
            "max_observation_age_seconds",
            "collector_sha256",
            "dependencies",
            "release",
            "e00a",
            "host",
            "sandbox",
            "production",
            "recovery",
        },
        "policy",
    )
    _require(policy["kind"] == POLICY_KIND, "policy kind mismatch")
    _text(policy["policy_id"], "policy.policy_id")
    _hex64(policy["challenge_nonce"], "policy.challenge_nonce")
    valid_from = _timestamp(policy["valid_from"], "policy.valid_from")
    expires_at = _timestamp(policy["expires_at"], "policy.expires_at")
    _require(valid_from < expires_at, "policy time window is invalid")
    _require(
        (expires_at - valid_from).total_seconds() <= 3600,
        "policy time window is too long",
    )
    _integer(
        policy["max_capture_duration_seconds"],
        "policy.max_capture_duration_seconds",
        minimum=1,
        maximum=600,
    )
    _integer(
        policy["max_observation_age_seconds"],
        "policy.max_observation_age_seconds",
        minimum=1,
        maximum=300,
    )
    _hex64(policy["collector_sha256"], "policy.collector_sha256")
    _validate_dependencies(policy["dependencies"])
    release = _validate_release(policy["release"], "policy.release")
    release_root = PurePosixPath(release["release_root"])
    _require(
        release_root.parent == PurePosixPath("/opt/odoo-accounting-cli-v3/releases")
        and release_root.name == release["release_id"],
        "policy release is outside the immutable release layout",
    )
    _require(
        release["trusted_anchor_path"]
        == (
            "/opt/odoo-accounting-cli-v3/trusted-artifacts/"
            f"{release['release_id']}.json"
        ),
        "policy trusted release anchor path is invalid",
    )
    e00a = _validate_e00a(policy["e00a"], "policy.e00a")
    _validate_host_policy(policy["host"])
    sandbox = _validate_sandbox_policy(policy["sandbox"])
    production = _validate_production_policy(policy["production"])
    recovery = _validate_recovery_policy(policy["recovery"])

    _require(sandbox["environment"] == "sandbox", "policy environment must be sandbox")
    _require(
        sandbox["database_filter"] == f"^{re.escape(sandbox['database_name'])}$",
        "policy database filter is not exact",
    )
    _require(
        sandbox["database_name"] in sandbox["database_catalog_names"],
        "policy sandbox database is absent from catalog",
    )
    _require(
        sandbox["database_uuid"] not in e00a["protected_database_uuids"],
        "policy sandbox UUID collides with production",
    )
    _require(
        sandbox["database_uuid"] != recovery["previous_database_uuid"],
        "policy sandbox UUID was not rotated",
    )
    _require(
        sandbox["sandbox_generation_id"] != recovery["previous_generation_id"],
        "policy sandbox generation was not rotated",
    )
    _require(
        sandbox["write_state_path"] != recovery["previous_state_path"],
        "policy sandbox state path was reused",
    )
    _require(
        sandbox["executor_user_id"] != sandbox["approver_user_id"],
        "policy executor and approver must differ",
    )
    _require(
        recovery["approved_by_user_id"] == sandbox["approver_user_id"],
        "policy recovery drill was not approved by the sandbox approver",
    )
    _require(
        production["protected_identity_sha256"]
        == e00a["protected_identity_sha256"],
        "policy production identity does not bind E00a",
    )
    _require(
        all(
            endpoint["cluster_system_identifier"]
            == e00a["production_cluster_system_identifier"]
            for endpoint in production["protected_database_endpoints"]
        ),
        "policy production database endpoint cluster does not bind E00a",
    )
    release_root = PurePosixPath(release["release_root"])
    _require(
        any(
            release_root == PurePosixPath(addon_root)
            or release_root in PurePosixPath(addon_root).parents
            for addon_root in sandbox["immutable_addon_roots"]
        ),
        "policy release add-on root is not bound",
    )
    return policy


def _validate_role(value: object) -> dict[str, Any]:
    role = _exact_object(
        value,
        {
            "name",
            "superuser",
            "create_db",
            "create_role",
            "inherit",
            "replication",
            "bypass_rls",
            "memberships",
            "owned_database_names",
            "connect_database_names",
        },
        "observation.postgresql.role",
    )
    _text(role["name"], "observation.postgresql.role.name")
    for name in (
        "superuser",
        "create_db",
        "create_role",
        "inherit",
        "replication",
        "bypass_rls",
    ):
        _boolean(role[name], f"observation.postgresql.role.{name}")
    for name in ("memberships", "owned_database_names", "connect_database_names"):
        _unique_texts(
            role[name],
            f"observation.postgresql.role.{name}",
            pattern=SAFE_NAME,
            maximum=128,
        )
    return role


def _validate_postgresql_observation(value: object) -> dict[str, Any]:
    postgresql = _exact_object(
        value,
        {
            "identity_sha256",
            "service_unit",
            "service_active",
            "system_identifier",
            "os_user",
            "uid",
            "gid",
            "data_dir",
            "socket_dir",
            "port",
            "database_name",
            "database_uuid",
            "database_catalog_names",
            "role",
        },
        "observation.postgresql",
    )
    _hex64(postgresql["identity_sha256"], "observation.postgresql.identity_sha256")
    for name in ("service_unit", "os_user"):
        _text(postgresql[name], f"observation.postgresql.{name}")
    _boolean(postgresql["service_active"], "observation.postgresql.service_active")
    _text(
        postgresql["system_identifier"],
        "observation.postgresql.system_identifier",
        pattern=re.compile(r"^[0-9]{10,32}$"),
        maximum=32,
    )
    for name in ("uid", "gid"):
        _integer(postgresql[name], f"observation.postgresql.{name}", minimum=1)
    for name in ("data_dir", "socket_dir"):
        _absolute_path(postgresql[name], f"observation.postgresql.{name}")
    _integer(postgresql["port"], "observation.postgresql.port", minimum=1, maximum=65535)
    _text(
        postgresql["database_name"],
        "observation.postgresql.database_name",
        pattern=SAFE_NAME,
        maximum=128,
    )
    _uuid(postgresql["database_uuid"], "observation.postgresql.database_uuid")
    _unique_texts(
        postgresql["database_catalog_names"],
        "observation.postgresql.database_catalog_names",
        pattern=SAFE_NAME,
        maximum=128,
    )
    _validate_role(postgresql["role"])
    return postgresql


def _validate_odoo_observation(value: object) -> dict[str, Any]:
    odoo = _exact_object(
        value,
        {
            "identity_sha256",
            "service_unit",
            "service_active",
            "os_user",
            "uid",
            "gid",
            "environment",
            "instance_id",
            "config_path",
            "executable_path",
            "data_dir",
            "filestore_dir",
            "immutable_addon_roots",
            "paths_identity_sha256",
            "db_name",
            "dbfilter",
            "list_db",
            "max_cron_threads",
            "cron_active_count",
            "mail_server_active_count",
            "external_integration_active_count",
        },
        "observation.odoo",
    )
    for name in ("identity_sha256", "paths_identity_sha256"):
        _hex64(odoo[name], f"observation.odoo.{name}")
    for name in ("service_unit", "os_user", "environment", "instance_id"):
        _text(odoo[name], f"observation.odoo.{name}")
    _boolean(odoo["service_active"], "observation.odoo.service_active")
    for name in ("uid", "gid"):
        _integer(odoo[name], f"observation.odoo.{name}", minimum=1)
    for name in ("config_path", "executable_path", "data_dir", "filestore_dir"):
        _absolute_path(odoo[name], f"observation.odoo.{name}")
    _unique_paths(odoo["immutable_addon_roots"], "observation.odoo.immutable_addon_roots")
    _text(odoo["db_name"], "observation.odoo.db_name", pattern=SAFE_NAME, maximum=128)
    _text(
        odoo["dbfilter"],
        "observation.odoo.dbfilter",
        pattern=re.compile(r"^.*\S.*$"),
        maximum=256,
    )
    _boolean(odoo["list_db"], "observation.odoo.list_db")
    for name in (
        "max_cron_threads",
        "cron_active_count",
        "mail_server_active_count",
        "external_integration_active_count",
    ):
        _integer(odoo[name], f"observation.odoo.{name}", minimum=0, maximum=1_000_000)
    return odoo


_SERVICE_ISOLATION_FIELDS = {
    "mount_namespace_isolated",
    "network_namespace_isolated",
    "private_network",
    "outbound_network_denied",
    "no_new_privileges",
    "capability_bounding_set_empty",
    "no_inherited_production_fds",
    "immutable_addons_read_only",
}


def _validate_service_isolation(value: object) -> dict[str, Any]:
    isolation = _exact_object(
        value, _SERVICE_ISOLATION_FIELDS, "observation.service_isolation"
    )
    for name in _SERVICE_ISOLATION_FIELDS:
        _boolean(isolation[name], f"observation.service_isolation.{name}")
    return isolation


def _validate_denial_rows(value: object, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(_exact_list(value, label)):
        row = _exact_object(item, {"target", "denied", "result"}, f"{label}[{index}]")
        if label.endswith("database_names"):
            _text(row["target"], f"{label}[{index}].target", pattern=SAFE_NAME, maximum=128)
        else:
            _absolute_path(row["target"], f"{label}[{index}].target")
        _boolean(row["denied"], f"{label}[{index}].denied")
        _text(
            row["result"],
            f"{label}[{index}].result",
            pattern=re.compile(r"^[A-Z][A-Z0-9_]{0,31}$"),
            maximum=32,
        )
        rows.append(row)
    _require(
        len(rows) == len({str(row["target"]) for row in rows}),
        f"{label} contains duplicate targets",
    )
    return rows


def _validate_database_endpoint_denials(
    value: object, label: str
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    fields = _DATABASE_ENDPOINT_FIELDS | {"denied", "result"}
    for index, item in enumerate(_exact_list(value, label)):
        row = _exact_object(item, fields, f"{label}[{index}]")
        _validate_database_endpoints(
            [{name: row[name] for name in _DATABASE_ENDPOINT_FIELDS}],
            f"{label}[{index}].endpoint",
        )
        _boolean(row["denied"], f"{label}[{index}].denied")
        _text(
            row["result"],
            f"{label}[{index}].result",
            pattern=re.compile(r"^[A-Z][A-Z0-9_]{0,31}$"),
            maximum=32,
        )
        rows.append(row)
    _require(
        len(rows) == len({str(row["endpoint_id"]) for row in rows}),
        f"{label} contains duplicate endpoint IDs",
    )
    return rows


def _validate_access_denials(value: object) -> dict[str, Any]:
    denials = _exact_object(
        value,
        {"paths", "postgresql_sockets", "database_names", "database_endpoints"},
        "observation.access_denials",
    )
    for name in ("paths", "postgresql_sockets", "database_names"):
        _validate_denial_rows(
            denials[name], f"observation.access_denials.{name}"
        )
    _validate_database_endpoint_denials(
        denials["database_endpoints"],
        "observation.access_denials.database_endpoints",
    )
    return denials


def _validate_principals(value: object) -> dict[str, Any]:
    principals = _exact_object(
        value,
        {
            "executor_user_id",
            "approver_user_id",
            "executor_active",
            "approver_active",
            "executor_admin",
            "approver_admin",
            "executor_company_ids",
            "approver_company_ids",
            "executor_only_group",
            "approver_only_group",
        },
        "observation.principals",
    )
    for name in ("executor_user_id", "approver_user_id"):
        _integer(principals[name], f"observation.principals.{name}", minimum=1)
    for name in (
        "executor_active",
        "approver_active",
        "executor_admin",
        "approver_admin",
        "executor_only_group",
        "approver_only_group",
    ):
        _boolean(principals[name], f"observation.principals.{name}")
    for name in ("executor_company_ids", "approver_company_ids"):
        _unique_integers(principals[name], f"observation.principals.{name}")
    return principals


def _validate_state(value: object) -> dict[str, Any]:
    state = _exact_object(
        value,
        {
            "generation_id",
            "write_state_path",
            "secret_paths",
            "state_identity_sha256",
            "secrets_identity_sha256",
            "state_isolated",
            "secrets_isolated",
            "write_execution_mode",
            "staged_write_capability_ids",
            "enabled_capability_ids",
        },
        "observation.state_isolation",
    )
    _uuid(state["generation_id"], "observation.state_isolation.generation_id")
    _absolute_path(state["write_state_path"], "observation.state_isolation.write_state_path")
    _unique_paths(state["secret_paths"], "observation.state_isolation.secret_paths")
    _hex64(state["state_identity_sha256"], "observation.state_isolation.state_identity_sha256")
    _hex64(
        state["secrets_identity_sha256"],
        "observation.state_isolation.secrets_identity_sha256",
    )
    for name in ("state_isolated", "secrets_isolated"):
        _boolean(state[name], f"observation.state_isolation.{name}")
    _text(state["write_execution_mode"], "observation.state_isolation.write_execution_mode")
    for name in ("staged_write_capability_ids", "enabled_capability_ids"):
        _unique_texts(state[name], f"observation.state_isolation.{name}")
    return state


def _validate_protected_identity(value: object) -> dict[str, Any]:
    protected = _exact_object(
        value,
        {"service_units", "before_sha256", "after_sha256"},
        "observation.protected_identity",
    )
    _unique_texts(
        protected["service_units"],
        "observation.protected_identity.service_units",
        pattern=SAFE_NAME,
        maximum=128,
    )
    _hex64(protected["before_sha256"], "observation.protected_identity.before_sha256")
    _hex64(protected["after_sha256"], "observation.protected_identity.after_sha256")
    return protected


def _validate_recovery_drill(value: object) -> dict[str, Any]:
    recovery = _exact_object(
        value,
        {
            "kind",
            "receipt_id",
            "receipt_path",
            "receipt_sha256",
            "approval_id",
            "approved_by_user_id",
            "host_machine_id_sha256",
            "release",
            "e00a_report_sha256",
            "completed_at",
            "status",
            "writes_quiesced",
            "previous_database_uuid",
            "new_database_uuid",
            "previous_generation_id",
            "new_generation_id",
            "previous_state_path",
            "new_state_path",
            "database_backup_path",
            "database_backup_sha256",
            "filestore_backup_path",
            "filestore_backup_sha256",
            "paired_manifest_path",
            "paired_manifest_sha256",
            "seed_oracle_passed",
            "failure_atomic",
            "reset_canary_absent",
            "old_state_read_only",
            "old_evidence_retained",
            "previous_state_identity_sha256",
            "old_evidence_path",
            "old_evidence_identity_sha256",
            "previous_key_ids",
            "new_key_ids",
            "keys_rotated",
        },
        "observation.recovery_drill",
    )
    _require(recovery["kind"] == RECOVERY_RECEIPT_KIND, "recovery receipt kind mismatch")
    for name in ("receipt_id", "approval_id"):
        _text(recovery[name], f"observation.recovery_drill.{name}")
    _integer(
        recovery["approved_by_user_id"],
        "observation.recovery_drill.approved_by_user_id",
        minimum=1,
    )
    _hex64(
        recovery["host_machine_id_sha256"],
        "observation.recovery_drill.host_machine_id_sha256",
    )
    _validate_release(recovery["release"], "observation.recovery_drill.release")
    _hex64(
        recovery["e00a_report_sha256"],
        "observation.recovery_drill.e00a_report_sha256",
    )
    _timestamp(recovery["completed_at"], "observation.recovery_drill.completed_at")
    for name in (
        "receipt_sha256",
        "database_backup_sha256",
        "filestore_backup_sha256",
        "paired_manifest_sha256",
        "previous_state_identity_sha256",
        "old_evidence_identity_sha256",
    ):
        _hex64(recovery[name], f"observation.recovery_drill.{name}")
    _absolute_path(
        recovery["receipt_path"], "observation.recovery_drill.receipt_path"
    )
    _text(recovery["status"], "observation.recovery_drill.status")
    for name in (
        "writes_quiesced",
        "seed_oracle_passed",
        "failure_atomic",
        "reset_canary_absent",
        "old_state_read_only",
        "old_evidence_retained",
        "keys_rotated",
    ):
        _boolean(recovery[name], f"observation.recovery_drill.{name}")
    for name in (
        "previous_database_uuid",
        "new_database_uuid",
        "previous_generation_id",
        "new_generation_id",
    ):
        _uuid(recovery[name], f"observation.recovery_drill.{name}")
    for name in (
        "previous_state_path",
        "new_state_path",
        "database_backup_path",
        "filestore_backup_path",
        "paired_manifest_path",
        "old_evidence_path",
    ):
        _absolute_path(recovery[name], f"observation.recovery_drill.{name}")
    for name in ("previous_key_ids", "new_key_ids"):
        _unique_texts(recovery[name], f"observation.recovery_drill.{name}")
    return recovery


def _load_recovery_receipt(policy: dict[str, Any]) -> dict[str, Any]:
    recovery_policy = policy["recovery"]
    document = _read_pinned_json(
        recovery_policy["drill_receipt_path"],
        recovery_policy["drill_receipt_sha256"],
        "recovery drill receipt",
    )
    _require(type(document) is dict, "recovery drill receipt must be an object")
    augmented = {
        **document,
        "receipt_path": recovery_policy["drill_receipt_path"],
        "receipt_sha256": recovery_policy["drill_receipt_sha256"],
    }
    return _validate_recovery_drill(augmented)


def _verify_recovery_receipt_binding(
    policy: dict[str, Any], receipt: dict[str, Any]
) -> None:
    recovery = policy["recovery"]
    sandbox = policy["sandbox"]
    completed_at = _timestamp(receipt["completed_at"], "recovery completed_at")
    _require(
        receipt["receipt_path"] == recovery["drill_receipt_path"]
        and receipt["receipt_sha256"] == recovery["drill_receipt_sha256"]
        and receipt["approval_id"] == recovery["approval_id"]
        and receipt["approved_by_user_id"] == recovery["approved_by_user_id"]
        and receipt["host_machine_id_sha256"]
        == policy["host"]["machine_id_sha256"]
        and receipt["release"] == policy["release"]
        and receipt["e00a_report_sha256"] == policy["e00a"]["report_sha256"]
        and _timestamp(policy["e00a"]["captured_at"], "E00a captured_at")
        <= completed_at
        <= _timestamp(policy["valid_from"], "policy valid_from")
        and receipt["status"] == "PASSED"
        and receipt["writes_quiesced"] is True
        and receipt["seed_oracle_passed"] is True
        and receipt["failure_atomic"] is True
        and receipt["reset_canary_absent"] is True,
        "recovery receipt provenance or outcome does not match policy",
    )
    _require(
        receipt["database_backup_path"] == recovery["database_backup_path"]
        and receipt["database_backup_sha256"] == recovery["database_backup_sha256"]
        and receipt["filestore_backup_path"] == recovery["filestore_backup_path"]
        and receipt["filestore_backup_sha256"]
        == recovery["filestore_backup_sha256"]
        and receipt["paired_manifest_path"] == recovery["paired_manifest_path"]
        and receipt["paired_manifest_sha256"]
        == recovery["paired_manifest_sha256"],
        "recovery receipt artifacts do not match policy",
    )
    _require(
        receipt["previous_database_uuid"] == recovery["previous_database_uuid"]
        and receipt["new_database_uuid"] == sandbox["database_uuid"]
        and receipt["new_database_uuid"] != receipt["previous_database_uuid"]
        and receipt["previous_generation_id"] == recovery["previous_generation_id"]
        and receipt["new_generation_id"] == sandbox["sandbox_generation_id"]
        and receipt["new_generation_id"] != receipt["previous_generation_id"]
        and receipt["previous_state_path"] == recovery["previous_state_path"]
        and receipt["new_state_path"] == sandbox["write_state_path"]
        and receipt["new_state_path"] != receipt["previous_state_path"],
        "recovery receipt generation does not match policy",
    )
    _require(
        receipt["old_state_read_only"] is True
        and receipt["old_evidence_retained"] is True
        and receipt["previous_state_identity_sha256"]
        == recovery["previous_state_identity_sha256"]
        and receipt["old_evidence_path"] == recovery["old_evidence_path"]
        and receipt["old_evidence_identity_sha256"]
        == recovery["old_evidence_identity_sha256"],
        "recovery receipt old-state evidence does not match policy",
    )
    _require(
        receipt["previous_key_ids"] == recovery["previous_key_ids"]
        and receipt["new_key_ids"] == recovery["new_key_ids"]
        and set(receipt["previous_key_ids"]).isdisjoint(receipt["new_key_ids"])
        and receipt["keys_rotated"] is True,
        "recovery receipt key rotation does not match policy",
    )


def _validate_recovery_pair_manifest(
    value: object, policy: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    manifest = _exact_object(
        value,
        {
            "kind",
            "manifest_id",
            "receipt_id",
            "approval_id",
            "host_machine_id_sha256",
            "release",
            "e00a_report_sha256",
            "created_at",
            "previous_database_uuid",
            "previous_generation_id",
            "previous_state_path",
            "artifacts",
        },
        "recovery pair manifest",
    )
    _require(
        manifest["kind"] == RECOVERY_PAIR_MANIFEST_KIND,
        "recovery pair manifest kind mismatch",
    )
    for name in ("manifest_id", "receipt_id", "approval_id"):
        _text(manifest[name], f"recovery pair manifest.{name}")
    _hex64(
        manifest["host_machine_id_sha256"],
        "recovery pair manifest.host_machine_id_sha256",
    )
    _validate_release(manifest["release"], "recovery pair manifest.release")
    _hex64(
        manifest["e00a_report_sha256"],
        "recovery pair manifest.e00a_report_sha256",
    )
    created_at = _timestamp(
        manifest["created_at"], "recovery pair manifest.created_at"
    )
    _uuid(
        manifest["previous_database_uuid"],
        "recovery pair manifest.previous_database_uuid",
    )
    _uuid(
        manifest["previous_generation_id"],
        "recovery pair manifest.previous_generation_id",
    )
    _absolute_path(
        manifest["previous_state_path"],
        "recovery pair manifest.previous_state_path",
    )
    _require(
        manifest["receipt_id"] == receipt["receipt_id"]
        and manifest["approval_id"] == receipt["approval_id"]
        and manifest["host_machine_id_sha256"]
        == receipt["host_machine_id_sha256"]
        and manifest["release"] == receipt["release"] == policy["release"]
        and manifest["e00a_report_sha256"] == receipt["e00a_report_sha256"]
        and manifest["previous_database_uuid"]
        == receipt["previous_database_uuid"]
        and manifest["previous_generation_id"]
        == receipt["previous_generation_id"]
        and manifest["previous_state_path"] == receipt["previous_state_path"]
        and created_at <= _timestamp(receipt["completed_at"], "recovery completed_at"),
        "recovery pair manifest provenance does not match receipt",
    )
    artifacts: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(
        _exact_list(manifest["artifacts"], "recovery pair manifest.artifacts", maximum=2)
    ):
        artifact = _exact_object(
            item,
            {"kind", "path", "sha256", "size"},
            f"recovery pair manifest artifact {index}",
        )
        kind = _text(
            artifact["kind"],
            f"recovery pair manifest artifact {index}.kind",
            pattern=SAFE_NAME,
            maximum=64,
        )
        _require(
            kind in {"database_backup", "filestore_backup"}
            and kind not in artifacts,
            "recovery pair manifest artifact kinds are invalid",
        )
        _absolute_path(
            artifact["path"], f"recovery pair manifest artifact {index}.path"
        )
        _hex64(
            artifact["sha256"],
            f"recovery pair manifest artifact {index}.sha256",
        )
        _integer(
            artifact["size"],
            f"recovery pair manifest artifact {index}.size",
            minimum=1,
            maximum=MAX_RECOVERY_ARTIFACT_BYTES,
        )
        artifacts[kind] = artifact
    _require(
        set(artifacts) == {"database_backup", "filestore_backup"},
        "recovery pair manifest must contain both backup artifacts",
    )
    recovery = policy["recovery"]
    _require(
        artifacts["database_backup"]["path"] == recovery["database_backup_path"]
        and artifacts["database_backup"]["sha256"]
        == recovery["database_backup_sha256"]
        and artifacts["filestore_backup"]["path"]
        == recovery["filestore_backup_path"]
        and artifacts["filestore_backup"]["sha256"]
        == recovery["filestore_backup_sha256"],
        "recovery pair manifest does not match recovery policy",
    )
    return artifacts


def _verify_recovery_approval(
    policy: dict[str, Any],
    receipt: dict[str, Any],
    *,
    expected_recovery_approval_allowlist_sha256: str,
) -> dict[str, str]:
    payload = _read_bound_approval_payload(
        Path(TRUSTED_RECOVERY_ALLOWLIST_PATH),
        expected_recovery_approval_allowlist_sha256,
        "trusted recovery drill approval allowlist",
    )
    allowlist = _exact_object(
        load_strict_json(payload),
        {"kind", "approvals"},
        "trusted recovery drill approval allowlist",
    )
    _require(
        allowlist["kind"] == RECOVERY_APPROVAL_ALLOWLIST_KIND,
        "trusted recovery drill approval allowlist kind mismatch",
    )
    approvals = _exact_list(
        allowlist["approvals"],
        "trusted recovery drill approval allowlist.approvals",
    )
    _require(
        1 <= len(approvals) <= 4096,
        "trusted recovery drill approval allowlist size is invalid",
    )
    rows: list[dict[str, Any]] = []
    approval_ids: set[str] = set()
    receipt_digests: set[str] = set()
    for index, value in enumerate(approvals):
        label = f"trusted recovery drill approval allowlist.approvals[{index}]"
        row = _exact_object(
            value,
            {
                "approval_id",
                "approved_by_user_id",
                "approved_at",
                "expires_at",
                "receipt_sha256",
                "paired_manifest_sha256",
                "database_backup_sha256",
                "filestore_backup_sha256",
                "e00a_report_sha256",
                "release_id",
                "previous_database_uuid",
                "new_database_uuid",
                "previous_generation_id",
                "new_generation_id",
            },
            label,
        )
        approval_id = _text(row["approval_id"], f"{label}.approval_id")
        _integer(
            row["approved_by_user_id"],
            f"{label}.approved_by_user_id",
            minimum=1,
        )
        approved_at = _timestamp(row["approved_at"], f"{label}.approved_at")
        expires_at = _timestamp(row["expires_at"], f"{label}.expires_at")
        for field in (
            "receipt_sha256",
            "paired_manifest_sha256",
            "database_backup_sha256",
            "filestore_backup_sha256",
            "e00a_report_sha256",
        ):
            _hex64(row[field], f"{label}.{field}")
        _text(row["release_id"], f"{label}.release_id")
        for field in (
            "previous_database_uuid",
            "new_database_uuid",
            "previous_generation_id",
            "new_generation_id",
        ):
            _uuid(row[field], f"{label}.{field}")
        _require(
            approval_id not in approval_ids,
            "trusted recovery drill approval IDs must be unique",
        )
        _require(
            row["receipt_sha256"] not in receipt_digests,
            "trusted recovery drill receipt approvals must be unique",
        )
        _require(
            approved_at < expires_at,
            "trusted recovery drill approval window is invalid",
        )
        approval_ids.add(approval_id)
        receipt_digests.add(row["receipt_sha256"])
        rows.append(row)

    expected = {
        "approval_id": receipt["approval_id"],
        "approved_by_user_id": receipt["approved_by_user_id"],
        "expires_at": policy["expires_at"],
        "receipt_sha256": receipt["receipt_sha256"],
        "paired_manifest_sha256": receipt["paired_manifest_sha256"],
        "database_backup_sha256": receipt["database_backup_sha256"],
        "filestore_backup_sha256": receipt["filestore_backup_sha256"],
        "e00a_report_sha256": receipt["e00a_report_sha256"],
        "release_id": receipt["release"]["release_id"],
        "previous_database_uuid": receipt["previous_database_uuid"],
        "new_database_uuid": receipt["new_database_uuid"],
        "previous_generation_id": receipt["previous_generation_id"],
        "new_generation_id": receipt["new_generation_id"],
    }
    matches = [
        row
        for row in rows
        if all(row[field] == value for field, value in expected.items())
    ]
    _require(
        len(matches) == 1,
        "recovery drill receipt is not independently approved",
    )
    selected = matches[0]
    selected_approved_at = _timestamp(
        selected["approved_at"], "trusted recovery drill approval approved_at"
    )
    _require(
        _timestamp(receipt["completed_at"], "recovery completed_at")
        <= selected_approved_at
        <= _timestamp(policy["valid_from"], "policy valid_from"),
        "trusted recovery drill approval time is invalid",
    )
    return {
        "approval_id": selected["approval_id"],
        "approved_at": selected["approved_at"],
        "approval_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _verify_recovery_prerequisite(
    policy: dict[str, Any],
    *,
    expected_recovery_approval_allowlist_sha256: str,
) -> dict[str, object]:
    receipt = _load_recovery_receipt(policy)
    _verify_recovery_receipt_binding(policy, receipt)
    approval = _verify_recovery_approval(
        policy,
        receipt,
        expected_recovery_approval_allowlist_sha256=(
            expected_recovery_approval_allowlist_sha256
        ),
    )
    recovery = policy["recovery"]
    manifest = _read_pinned_json(
        recovery["paired_manifest_path"],
        recovery["paired_manifest_sha256"],
        "recovery pair manifest",
    )
    artifacts = _validate_recovery_pair_manifest(manifest, policy, receipt)
    for kind, artifact in artifacts.items():
        actual_sha256, actual_size = _hash_bounded_regular_file(
            Path(artifact["path"]),
            f"recovery {kind}",
            maximum_size=MAX_RECOVERY_ARTIFACT_BYTES,
        )
        _require(
            actual_sha256 == artifact["sha256"]
            and actual_size == artifact["size"],
            f"recovery {kind} artifact changed",
        )
    return {
        "receipt_id": receipt["receipt_id"],
        "receipt_sha256": receipt["receipt_sha256"],
        "paired_manifest_sha256": recovery["paired_manifest_sha256"],
        "artifacts_verified": True,
        "approval_sha256": approval["approval_sha256"],
    }


def _validate_observation(value: object) -> dict[str, Any]:
    observation = _exact_object(
        value,
        {
            "kind",
            "policy_id",
            "policy_sha256",
            "challenge_nonce",
            "run_id",
            "capture_started_at",
            "capture_finished_at",
            "capture_duration_ns",
            "collector_sha256",
            "release",
            "e00a",
            "host",
            "postgresql",
            "odoo",
            "service_isolation",
            "access_denials",
            "principals",
            "state_isolation",
            "protected_identity",
            "recovery_drill",
        },
        "observation",
    )
    _require(observation["kind"] == OBSERVATION_KIND, "observation kind mismatch")
    _text(observation["policy_id"], "observation.policy_id")
    _hex64(observation["policy_sha256"], "observation.policy_sha256")
    _hex64(observation["challenge_nonce"], "observation.challenge_nonce")
    _uuid(observation["run_id"], "observation.run_id")
    _timestamp(observation["capture_started_at"], "observation.capture_started_at")
    _timestamp(observation["capture_finished_at"], "observation.capture_finished_at")
    _integer(
        observation["capture_duration_ns"],
        "observation.capture_duration_ns",
        maximum=600 * 1_000_000_000,
    )
    _hex64(observation["collector_sha256"], "observation.collector_sha256")
    _validate_release(observation["release"], "observation.release")
    _validate_e00a(observation["e00a"], "observation.e00a")
    host = _exact_object(
        observation["host"],
        {"machine_id_sha256", "host_mount_namespace"},
        "observation.host",
    )
    _hex64(host["machine_id_sha256"], "observation.host.machine_id_sha256")
    _boolean(host["host_mount_namespace"], "observation.host.host_mount_namespace")
    _validate_postgresql_observation(observation["postgresql"])
    _validate_odoo_observation(observation["odoo"])
    _validate_service_isolation(observation["service_isolation"])
    _validate_access_denials(observation["access_denials"])
    _validate_principals(observation["principals"])
    _validate_state(observation["state_isolation"])
    _validate_protected_identity(observation["protected_identity"])
    _validate_recovery_drill(observation["recovery_drill"])
    return observation


def evaluate(
    policy_value: object,
    observation_value: object,
    *,
    now: datetime,
) -> dict[str, object]:
    policy = _validate_policy(policy_value)
    observation = _validate_observation(observation_value)
    _require(type(now) is datetime, "evaluation time must be a datetime")
    _require(now.tzinfo is not None, "evaluation time must have a timezone")
    now = now.astimezone(UTC)
    blockers: list[str] = []

    def block(name: str, condition: bool) -> None:
        if not condition and name not in blockers:
            blockers.append(name)

    valid_from = _timestamp(policy["valid_from"], "policy.valid_from")
    expires_at = _timestamp(policy["expires_at"], "policy.expires_at")
    capture_started_at = _timestamp(
        observation["capture_started_at"], "observation.capture_started_at"
    )
    capture_finished_at = _timestamp(
        observation["capture_finished_at"], "observation.capture_finished_at"
    )
    wall_duration_ns = int(
        (capture_finished_at - capture_started_at).total_seconds() * 1_000_000_000
    )
    block("policy_time", valid_from <= now <= expires_at)
    block(
        "observation_time",
        valid_from <= capture_started_at <= capture_finished_at <= now <= expires_at,
    )
    block(
        "observation_age",
        0
        <= (now - capture_finished_at).total_seconds()
        <= policy["max_observation_age_seconds"],
    )
    block(
        "capture_duration",
        0 <= wall_duration_ns <= policy["max_capture_duration_seconds"] * 1_000_000_000
        and observation["capture_duration_ns"]
        <= policy["max_capture_duration_seconds"] * 1_000_000_000
        and abs(wall_duration_ns - observation["capture_duration_ns"])
        <= 100_000_000,
    )
    block(
        "policy_binding",
        observation["policy_id"] == policy["policy_id"]
        and observation["policy_sha256"] == _canonical_sha256(policy)
        and observation["challenge_nonce"] == policy["challenge_nonce"],
    )
    block("collector_identity", observation["collector_sha256"] == policy["collector_sha256"])
    block("release_binding", observation["release"] == policy["release"])
    block("e00a_binding", observation["e00a"] == policy["e00a"])
    block(
        "host_identity",
        observation["host"]["machine_id_sha256"]
        == policy["host"]["machine_id_sha256"]
        and observation["host"]["host_mount_namespace"] is True,
    )

    sandbox = policy["sandbox"]
    postgresql = observation["postgresql"]
    role = postgresql["role"]
    block(
        "postgresql_identity",
        postgresql["identity_sha256"] == sandbox["postgresql_identity_sha256"]
        and postgresql["service_unit"] == sandbox["postgresql_service_unit"]
        and postgresql["service_active"] is True
        and postgresql["os_user"] == sandbox["postgresql_os_user"]
        and postgresql["uid"] == sandbox["postgresql_uid"]
        and postgresql["gid"] == sandbox["postgresql_gid"]
        and postgresql["data_dir"] == sandbox["postgresql_data_dir"]
        and postgresql["socket_dir"] == sandbox["postgresql_socket_dir"]
        and postgresql["port"] == sandbox["postgresql_port"],
    )
    block(
        "postgresql_cluster_independence",
        postgresql["system_identifier"]
        != policy["e00a"]["production_cluster_system_identifier"],
    )
    block("database_name", postgresql["database_name"] == sandbox["database_name"])
    block(
        "database_uuid",
        postgresql["database_uuid"] == sandbox["database_uuid"]
        and postgresql["database_uuid"]
        not in policy["e00a"]["protected_database_uuids"],
    )
    block(
        "database_catalog",
        postgresql["database_catalog_names"] == sandbox["database_catalog_names"],
    )
    block(
        "postgresql_role",
        role["name"] == sandbox["postgresql_role"]
        and all(
            role[name] is False
            for name in (
                "superuser",
                "create_db",
                "create_role",
                "inherit",
                "replication",
                "bypass_rls",
            )
        )
        and role["memberships"] == []
        and role["owned_database_names"] == [sandbox["database_name"]]
        and role["connect_database_names"] == [sandbox["database_name"]],
    )

    odoo = observation["odoo"]
    block(
        "odoo_identity",
        odoo["identity_sha256"] == sandbox["odoo_identity_sha256"]
        and odoo["service_unit"] == sandbox["odoo_service_unit"]
        and odoo["service_active"] is True
        and odoo["os_user"] == sandbox["odoo_os_user"]
        and odoo["uid"] == sandbox["odoo_uid"]
        and odoo["gid"] == sandbox["odoo_gid"]
        and odoo["environment"] == "sandbox"
        and odoo["instance_id"] == sandbox["odoo_instance_id"]
        and odoo["config_path"] == sandbox["odoo_config_path"]
        and odoo["executable_path"] == sandbox["odoo_executable_path"]
        and odoo["data_dir"] == sandbox["data_dir"]
        and odoo["filestore_dir"] == sandbox["filestore_dir"]
        and odoo["immutable_addon_roots"] == sandbox["immutable_addon_roots"]
        and odoo["paths_identity_sha256"] == sandbox["sandbox_paths_identity_sha256"],
    )
    block("odoo_database_name", odoo["db_name"] == sandbox["database_name"])
    block("odoo_database_filter", odoo["dbfilter"] == sandbox["database_filter"])
    block("odoo_list_db", odoo["list_db"] is False)
    block(
        "odoo_cron",
        odoo["max_cron_threads"] == 0 and odoo["cron_active_count"] == 0,
    )
    block("odoo_mail", odoo["mail_server_active_count"] == 0)
    block(
        "odoo_external_integrations",
        odoo["external_integration_active_count"] == 0,
    )
    block(
        "service_isolation",
        all(observation["service_isolation"][name] is True for name in _SERVICE_ISOLATION_FIELDS),
    )

    denial_policy_fields = {
        "paths": "protected_paths",
        "postgresql_sockets": "protected_postgresql_sockets",
        "database_names": "protected_database_names",
    }
    denial_results = {
        "paths": {"EACCES", "ENOENT"},
        "postgresql_sockets": {"EACCES", "ENOENT", "UNREACHABLE"},
        "database_names": {"UNREACHABLE", "EACCES", "ENOENT"},
    }
    for name, policy_field in denial_policy_fields.items():
        rows = observation["access_denials"][name]
        targets = [row["target"] for row in rows]
        block(
            f"production_access_denial:{name}",
            set(targets) == set(policy["production"][policy_field])
            and len(targets) == len(policy["production"][policy_field])
            and all(
                row["denied"] is True and row["result"] in denial_results[name]
                for row in rows
            ),
        )
    endpoint_rows = observation["access_denials"]["database_endpoints"]
    endpoint_facts = [
        {name: row[name] for name in _DATABASE_ENDPOINT_FIELDS}
        for row in endpoint_rows
    ]
    block(
        "production_access_denial:database_endpoints",
        endpoint_facts == policy["production"]["protected_database_endpoints"]
        and all(
            row["denied"] is True
            and row["result"]
            in {"EACCES", "ENOENT", "ENOTDIR", "EPERM", "UNREACHABLE"}
            for row in endpoint_rows
        ),
    )

    principals = observation["principals"]
    allowed_companies = sandbox["allowed_company_ids"]
    block(
        "principal_separation",
        principals["executor_user_id"] == sandbox["executor_user_id"]
        and principals["approver_user_id"] == sandbox["approver_user_id"]
        and principals["executor_user_id"] != principals["approver_user_id"]
        and principals["executor_active"] is True
        and principals["approver_active"] is True
        and principals["executor_admin"] is False
        and principals["approver_admin"] is False
        and principals["executor_company_ids"] == allowed_companies
        and principals["approver_company_ids"] == allowed_companies
        and principals["executor_only_group"] is True
        and principals["approver_only_group"] is True,
    )

    state = observation["state_isolation"]
    block(
        "state_isolation",
        state["generation_id"] == sandbox["sandbox_generation_id"]
        and state["write_state_path"] == sandbox["write_state_path"]
        and state["secret_paths"] == sandbox["secret_paths"]
        and state["state_identity_sha256"] == sandbox["state_identity_sha256"]
        and state["secrets_identity_sha256"] == sandbox["secrets_identity_sha256"]
        and state["state_isolated"] is True
        and state["secrets_isolated"] is True,
    )
    block("write_execution_mode", state["write_execution_mode"] == "disabled")
    block("write_capabilities_closed", state["staged_write_capability_ids"] == [])
    block("enabled_capabilities_closed", state["enabled_capability_ids"] == [])

    protected = observation["protected_identity"]
    block(
        "protected_identity",
        protected["service_units"] == policy["production"]["protected_service_units"]
        and protected["before_sha256"]
        == policy["production"]["protected_identity_sha256"]
        and protected["after_sha256"]
        == policy["production"]["protected_identity_sha256"],
    )

    recovery_policy = policy["recovery"]
    recovery = observation["recovery_drill"]
    block(
        "recovery_drill",
        recovery["receipt_path"] == recovery_policy["drill_receipt_path"]
        and recovery["receipt_sha256"] == recovery_policy["drill_receipt_sha256"]
        and recovery["approval_id"] == recovery_policy["approval_id"]
        and recovery["approved_by_user_id"]
        == recovery_policy["approved_by_user_id"]
        and recovery["host_machine_id_sha256"]
        == policy["host"]["machine_id_sha256"]
        and recovery["release"] == policy["release"]
        and recovery["e00a_report_sha256"] == policy["e00a"]["report_sha256"]
        and _timestamp(recovery["completed_at"], "recovery completed_at")
        >= _timestamp(policy["e00a"]["captured_at"], "E00a captured_at")
        and _timestamp(recovery["completed_at"], "recovery completed_at")
        <= valid_from
        and recovery["status"] == "PASSED"
        and recovery["writes_quiesced"] is True
        and recovery["seed_oracle_passed"] is True
        and recovery["failure_atomic"] is True
        and recovery["reset_canary_absent"] is True,
    )
    block(
        "recovery_artifacts",
        recovery["database_backup_path"] == recovery_policy["database_backup_path"]
        and recovery["database_backup_sha256"]
        == recovery_policy["database_backup_sha256"]
        and recovery["filestore_backup_path"]
        == recovery_policy["filestore_backup_path"]
        and recovery["filestore_backup_sha256"]
        == recovery_policy["filestore_backup_sha256"]
        and recovery["paired_manifest_path"]
        == recovery_policy["paired_manifest_path"]
        and recovery["paired_manifest_sha256"]
        == recovery_policy["paired_manifest_sha256"],
    )
    block(
        "recovery_database_generation",
        recovery["previous_database_uuid"] == recovery_policy["previous_database_uuid"]
        and recovery["new_database_uuid"] == sandbox["database_uuid"]
        and recovery["new_database_uuid"] != recovery["previous_database_uuid"],
    )
    block(
        "recovery_generation",
        recovery["previous_generation_id"] == recovery_policy["previous_generation_id"]
        and recovery["new_generation_id"] == sandbox["sandbox_generation_id"]
        and recovery["new_generation_id"] != recovery["previous_generation_id"],
    )
    block(
        "recovery_state_path",
        recovery["previous_state_path"] == recovery_policy["previous_state_path"]
        and recovery["new_state_path"] == sandbox["write_state_path"]
        and recovery["new_state_path"] != recovery["previous_state_path"],
    )
    block(
        "recovery_old_evidence",
        recovery["old_state_read_only"] is True
        and recovery["old_evidence_retained"] is True
        and recovery["previous_state_identity_sha256"]
        == recovery_policy["previous_state_identity_sha256"]
        and recovery["old_evidence_path"] == recovery_policy["old_evidence_path"]
        and recovery["old_evidence_identity_sha256"]
        == recovery_policy["old_evidence_identity_sha256"],
    )
    block(
        "recovery_key_rotation",
        recovery["keys_rotated"] is True
        and recovery["previous_key_ids"] == recovery_policy["previous_key_ids"]
        and recovery["new_key_ids"] == recovery_policy["new_key_ids"]
        and set(recovery["previous_key_ids"]).isdisjoint(recovery["new_key_ids"]),
    )

    blockers.sort()
    contract_conditions_passed = not blockers
    return {
        "kind": "odoo-accounting-cli-v3.sandbox-isolation-contract-report.v1",
        "policy_id": policy["policy_id"],
        "challenge_nonce": policy["challenge_nonce"],
        "run_id": observation["run_id"],
        "policy_sha256": _canonical_sha256(policy),
        "observation_sha256": _canonical_sha256(observation),
        "evaluated_at": now.isoformat().replace("+00:00", "Z"),
        "evidence_origin": "caller_supplied_contract_test",
        "contract_conditions_passed": contract_conditions_passed,
        "isolation_gate_passed": False,
        "eligible_for_sandbox_write_staging_review": False,
        "blockers": blockers,
        "trust_blockers": ["live_evidence_unverified"],
        "sandbox_provisioning_authorized": False,
        "sandbox_accounting_write_authorized": False,
        "production_accounting_write_authorized": False,
        "registry_change_authorized": False,
    }


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InvalidInvocationError("command invocation is invalid")


class _DenyHelp(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        raise HelpRequestedError(
            "help is non-authorizing; use the deployed operator documentation"
        )


class _StoreOnce(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error("command option was repeated")
        setattr(namespace, self.dest, values)


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(add_help=False)
    parser.add_argument("-h", "--help", action=_DenyHelp, nargs=0)
    parser.add_argument("--policy", required=True, action=_StoreOnce)
    parser.add_argument(
        "--expected-policy-sha256", required=True, action=_StoreOnce
    )
    return parser


def _emit_json(stream: object, value: object) -> None:
    stream.write(_canonical_bytes(value).decode("utf-8") + "\n")


def _error_document(code: str, message: str) -> dict[str, object]:
    return {
        "ok": False,
        "error": {"code": code, "message": message},
        "eligible_for_sandbox_write_staging_review": False,
        "sandbox_provisioning_authorized": False,
        "sandbox_accounting_write_authorized": False,
        "production_accounting_write_authorized": False,
        "registry_change_authorized": False,
    }


def _read_policy(path_value: str, expected_sha256: str) -> dict[str, Any]:
    path = Path(path_value)
    _hex64(expected_sha256, "expected policy SHA-256")
    payload = _read_bounded_regular_file(path, "policy")
    _require(
        hashlib.sha256(payload).hexdigest() == expected_sha256,
        "policy SHA-256 mismatch",
    )
    value = load_strict_json(payload)
    return _validate_policy(value)


def _live_utc_now() -> datetime:
    return datetime.now(UTC)


def _live_monotonic_ns() -> int:
    return time.monotonic_ns()


def _verify_live_policy_time(
    policy: dict[str, Any],
    previous: tuple[datetime, int] | None = None,
) -> tuple[datetime, int]:
    now = _live_utc_now()
    _require(type(now) is datetime, "live UTC clock returned an invalid value")
    _require(
        now.tzinfo is not None and now.utcoffset() is not None,
        "live UTC clock is not timezone-aware",
    )
    now = now.astimezone(UTC)
    monotonic_ns = _integer(
        _live_monotonic_ns(), "live monotonic clock", minimum=0
    )
    valid_from = _timestamp(policy["valid_from"], "policy valid_from")
    expires_at = _timestamp(policy["expires_at"], "policy expires_at")
    _require(
        valid_from <= now <= expires_at,
        "policy is not active at live UTC time",
    )
    if previous is not None:
        previous_now, previous_monotonic_ns = previous
        _require(now >= previous_now, "live UTC clock moved backwards")
        _require(
            monotonic_ns >= previous_monotonic_ns,
            "live monotonic clock moved backwards",
        )
        remaining_ns = int(
            (expires_at - previous_now).total_seconds() * 1_000_000_000
        )
        _require(
            monotonic_ns - previous_monotonic_ns <= remaining_ns,
            "policy expired according to live monotonic clock",
        )
    return now, monotonic_ns


def _main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except HelpRequestedError as exc:
        _emit_json(sys.stderr, _error_document("help_requested", str(exc)))
        return 2
    except InvalidInvocationError as exc:
        _emit_json(sys.stderr, _error_document("invalid_invocation", str(exc)))
        return 2
    try:
        policy = _read_policy(args.policy, args.expected_policy_sha256)
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("invalid_policy", str(exc)))
        return 2
    try:
        policy_approval = _verify_policy_approval(
            policy, args.expected_policy_sha256
        )
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("untrusted_policy", str(exc)))
        return 2
    try:
        live_time_checkpoint = _verify_live_policy_time(policy)
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("inactive_policy", str(exc)))
        return 2
    try:
        cli_arguments = [
            "--policy",
            args.policy,
            "--expected-policy-sha256",
            args.expected_policy_sha256,
        ]
        release_rows = _verify_release_runtime(
            policy,
            cli_arguments,
            expected_release_approval_allowlist_sha256=policy_approval[
                "release_approval_allowlist_sha256"
            ],
            expected_host_context_approval_sha256=policy_approval[
                "host_context_approval_sha256"
            ],
        )
        dev18_module = _load_dev18_verifier(policy, release_rows)
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("untrusted_runtime", str(exc)))
        return 2
    try:
        _verify_e00a_prerequisite(
            policy,
            dev18_module,
            expected_host_context_approval_sha256=policy_approval[
                "host_context_approval_sha256"
            ],
        )
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("untrusted_e00a", str(exc)))
        return 2
    try:
        _verify_recovery_prerequisite(
            policy,
            expected_recovery_approval_allowlist_sha256=policy_approval[
                "recovery_approval_allowlist_sha256"
            ],
        )
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("untrusted_recovery", str(exc)))
        return 2
    try:
        _verify_initial_root_context(
            policy,
            expected_host_context_approval_sha256=policy_approval[
                "host_context_approval_sha256"
            ],
        )
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("untrusted_runtime", str(exc)))
        return 2
    try:
        final_policy = _read_policy(args.policy, args.expected_policy_sha256)
        _require(
            final_policy == policy,
            "policy changed during verification",
        )
        _verify_supporting_approval_roots(policy_approval)
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("untrusted_policy", str(exc)))
        return 2
    try:
        _verify_live_policy_time(policy, live_time_checkpoint)
    except IsolationGateError as exc:
        _emit_json(sys.stderr, _error_document("inactive_policy", str(exc)))
        return 2
    _emit_json(
        sys.stderr,
        _error_document(
            "live_collector_unavailable",
            "Dev19 live Linux collector is not implemented; no E00b result was issued",
        ),
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        raise
    except SystemExit:
        _emit_json(
            sys.stderr,
            _error_document("internal_error", "unexpected internal failure"),
        )
        return 2
    except Exception:
        _emit_json(
            sys.stderr,
            _error_document("internal_error", "unexpected internal failure"),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

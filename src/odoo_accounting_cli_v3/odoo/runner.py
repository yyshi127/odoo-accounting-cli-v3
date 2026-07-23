"""Controlled subprocess boundary for executing one Odoo shell read request."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ..operations import canonical_json
from ..release import ReleaseError, ReleaseIdentity, verify_manifest


READ_REJECTION_CODES = frozenset(
    {
        "authentication_expired",
        "authentication_replayed",
        "authentication_tampered",
        "company_binding_rejected",
        "database_binding_rejected",
        "odoo_acl_denied",
    }
)


class OdooRunnerError(ValueError):
    """Raised when runtime configuration or child execution is not trustworthy."""

    def __init__(self, message: str, *, rejection_code: str | None = None) -> None:
        if rejection_code is not None and rejection_code not in READ_REJECTION_CODES:
            raise ValueError("read rejection code is not allowlisted")
        super().__init__(message)
        self.rejection_code = rejection_code


ENVIRONMENTS = frozenset({"test", "sandbox", "production"})
CAPABILITY_CHANNELS = frozenset({"enabled", "staged"})
CONFIG_FIELDS = frozenset(
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
RUNTIME_FIELDS = frozenset(
    {
        "instance_id",
        "environment",
        "capability_channel",
        "database_name",
        "database_uuid",
    }
)
CHILD_FIELDS = frozenset(
    {
        "protocol",
        "runtime",
        "request_json",
        "auth_secret",
        "auth_key_id",
        "receipt_secret",
        "receipt_key_id",
        "release_digest",
        "canonical_package_path",
        "canonical_package_sha256",
        "release_root",
        "auth_state_path",
        "receipt_state_path",
    }
)
EVIDENCE_CHILD_FIELDS = frozenset(
    {
        "protocol",
        "runtime",
        "release_digest",
        "canonical_package_path",
        "canonical_package_sha256",
        "release_root",
    }
)
RESPONSE_FIELDS = frozenset({"ok", "runtime", "result"})
REJECTION_RESPONSE_FIELDS = frozenset({"ok", "runtime", "rejection_code"})
FIXED_CHILD_ENVIRONMENT = {
    "HOME": "/var/lib/odoo-accounting-cli-v3-broker",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TZ": "UTC",
}
GCOV_CHILD_ENVIRONMENT_KEYS = frozenset(
    {"GCOV_ERROR_FILE", "GCOV_EXIT_AT_ERROR", "GCOV_PREFIX", "GCOV_PREFIX_STRIP"}
)
DATABASE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
SHA256 = re.compile(r"[0-9a-f]{64}")
MARKER = re.compile(r"__ODOO_ACCOUNTING_CLI_V3_RESULT_[0-9a-f]{48}__:")
MAX_PRIVATE_PAYLOAD_BYTES = 1024 * 1024
MAX_CHILD_STDOUT_BYTES = 4 * 1024 * 1024
MAX_CHILD_STDERR_BYTES = 1024 * 1024
MAX_TIMEOUT_SECONDS = 120.0


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OdooRunnerError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise OdooRunnerError(f"non-finite JSON number is forbidden: {value}")


def _load_json_object(value: str, label: str) -> dict[str, Any]:
    try:
        result = json.loads(
            value,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise OdooRunnerError(f"{label} is not valid JSON") from exc
    if not isinstance(result, dict):
        raise OdooRunnerError(f"{label} must be a JSON object")
    return result


def _strict_text(value: Any, field: str, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OdooRunnerError(f"{field} is invalid")
    return value


def _absolute_path(value: Any, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise OdooRunnerError(f"{field} must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise OdooRunnerError(f"{field} must be an absolute path")
    return path


@dataclass(frozen=True)
class RuntimeConfig:
    """Root-managed identity and fixed paths for an Odoo runtime."""

    instance_id: str
    environment: str
    capability_channel: str
    database_name: str
    database_uuid: str
    odoo_python: Path
    odoo_python_sha256: str
    odoo_bin: Path
    odoo_bin_sha256: str
    odoo_config: Path
    odoo_config_sha256: str
    release_root: Path
    canonical_package_path: Path
    canonical_package_sha256: str
    auth_state_path: Path
    receipt_state_path: Path
    auth_key_id: str
    receipt_key_id: str
    auth_secret_path: Path
    receipt_secret_path: Path

    def __post_init__(self) -> None:
        _strict_text(self.instance_id, "instance_id")
        if not isinstance(self.environment, str) or self.environment not in ENVIRONMENTS:
            raise OdooRunnerError("environment is invalid")
        if self.capability_channel not in CAPABILITY_CHANNELS:
            raise OdooRunnerError("capability_channel is invalid")
        if self.environment == "production" and self.capability_channel != "enabled":
            raise OdooRunnerError("production cannot execute staged capabilities")
        if (
            not isinstance(self.database_name, str)
            or DATABASE_NAME.fullmatch(self.database_name) is None
        ):
            raise OdooRunnerError("database_name is invalid")
        try:
            normalized_uuid = str(uuid.UUID(self.database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise OdooRunnerError("database_uuid must be a UUID") from exc
        object.__setattr__(self, "database_uuid", normalized_uuid)
        for field in (
            "odoo_python",
            "odoo_bin",
            "odoo_config",
            "release_root",
            "canonical_package_path",
            "auth_state_path",
            "receipt_state_path",
            "auth_secret_path",
            "receipt_secret_path",
        ):
            path = getattr(self, field)
            if not isinstance(path, Path) or not path.is_absolute():
                raise OdooRunnerError(f"{field} must be an absolute path")
        if self.auth_state_path == self.receipt_state_path:
            raise OdooRunnerError("authentication and receipt state paths must be distinct")
        if self.auth_secret_path == self.receipt_secret_path:
            raise OdooRunnerError("authentication and receipt secret paths must be distinct")
        _strict_text(self.auth_key_id, "auth_key_id")
        _strict_text(self.receipt_key_id, "receipt_key_id")
        if self.auth_key_id == self.receipt_key_id:
            raise OdooRunnerError("authentication and receipt key IDs must be distinct")
        for field in (
            "odoo_python_sha256",
            "odoo_bin_sha256",
            "odoo_config_sha256",
            "canonical_package_sha256",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or SHA256.fullmatch(value) is None:
                raise OdooRunnerError(f"{field} must be a lowercase SHA-256 digest")

    @property
    def runtime_identity(self) -> dict[str, str]:
        return {
            "instance_id": self.instance_id,
            "environment": self.environment,
            "capability_channel": self.capability_channel,
            "database_name": self.database_name,
            "database_uuid": self.database_uuid,
        }


def _config_from_mapping(value: Any) -> RuntimeConfig:
    if not isinstance(value, Mapping) or set(value) != CONFIG_FIELDS:
        raise OdooRunnerError("runtime configuration fields are invalid")
    return RuntimeConfig(
        instance_id=_strict_text(value["instance_id"], "instance_id"),
        environment=value["environment"],
        capability_channel=value["capability_channel"],
        database_name=value["database_name"],
        database_uuid=value["database_uuid"],
        odoo_python=_absolute_path(value["odoo_python"], "odoo_python"),
        odoo_python_sha256=value["odoo_python_sha256"],
        odoo_bin=_absolute_path(value["odoo_bin"], "odoo_bin"),
        odoo_bin_sha256=value["odoo_bin_sha256"],
        odoo_config=_absolute_path(value["odoo_config"], "odoo_config"),
        odoo_config_sha256=value["odoo_config_sha256"],
        release_root=_absolute_path(value["release_root"], "release_root"),
        canonical_package_path=_absolute_path(
            value["canonical_package_path"], "canonical_package_path"
        ),
        canonical_package_sha256=value["canonical_package_sha256"],
        auth_state_path=_absolute_path(value["auth_state_path"], "auth_state_path"),
        receipt_state_path=_absolute_path(value["receipt_state_path"], "receipt_state_path"),
        auth_key_id=_strict_text(value["auth_key_id"], "auth_key_id"),
        receipt_key_id=_strict_text(value["receipt_key_id"], "receipt_key_id"),
        auth_secret_path=_absolute_path(value["auth_secret_path"], "auth_secret_path"),
        receipt_secret_path=_absolute_path(value["receipt_secret_path"], "receipt_secret_path"),
    )


def load_runtime_config(
    path: str | os.PathLike[str], *, require_root_owner: bool = True
) -> RuntimeConfig:
    """Load an exact-field JSON config, rejecting mutable non-root POSIX files."""

    config_path = Path(path)
    if not config_path.is_absolute():
        raise OdooRunnerError("runtime configuration path must be absolute")
    try:
        metadata = config_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or config_path.is_symlink():
            raise OdooRunnerError("runtime configuration must be a regular non-symlink file")
        if os.name == "posix" and require_root_owner:
            parent = config_path.parent
            parent_metadata = parent.lstat()
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent.is_symlink()
                or parent.resolve(strict=True) != parent
                or parent_metadata.st_uid != 0
                or parent_metadata.st_mode & 0o022
            ):
                raise OdooRunnerError(
                    "runtime configuration directory must be canonical and root-managed"
                )
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise OdooRunnerError(
                    "runtime configuration must be root-owned and not group/world writable"
                )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(config_path, flags)
        try:
            opened = os.fstat(descriptor)
            if os.name == "posix" and (
                (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or (require_root_owner and opened.st_uid != 0)
            ):
                raise OdooRunnerError("runtime configuration changed while it was opened")
            chunks = []
            total = 0
            while True:
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > 65_536:
                    raise OdooRunnerError("runtime configuration is too large")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        try:
            raw = b"".join(chunks).decode("utf-8")
        except UnicodeError as exc:
            raise OdooRunnerError("runtime configuration cannot be read") from exc
        document = _load_json_object(raw, "runtime configuration")
    except OdooRunnerError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OdooRunnerError("runtime configuration cannot be read") from exc
    return _config_from_mapping(document)


def require_staged_test_evidence_runtime(config: RuntimeConfig) -> None:
    """Keep the DML rejection probe out of every production-capable runtime."""

    if not isinstance(config, RuntimeConfig):
        raise OdooRunnerError("a validated runtime configuration is required")
    if config.environment != "test" or config.capability_channel != "staged":
        raise OdooRunnerError(
            "read-boundary DML evidence is restricted to a staged test runtime"
        )


def _require_immutable_dependency_mounts(config: RuntimeConfig) -> None:
    """Require a read-only execution namespace with only state and HOME writable."""

    if os.name != "posix":
        return
    readonly_flag = getattr(os, "ST_RDONLY", None)
    if not isinstance(readonly_flag, int) or readonly_flag <= 0:
        raise OdooRunnerError("immutable dependency mount attestation is unavailable")
    readonly_paths = (
        (config.release_root, "release_root"),
        (config.canonical_package_path, "canonical_package_path"),
        (config.odoo_python.parent.parent, "odoo_python_environment"),
        (config.odoo_bin.parent, "odoo_server_root"),
        (config.odoo_config.parent, "odoo_addons_root"),
        (config.odoo_config, "odoo_config"),
        (config.auth_secret_path, "auth_secret_path"),
        (config.receipt_secret_path, "receipt_secret_path"),
    )
    writable_paths = (
        (config.auth_state_path.parent, "auth_state_parent"),
        (config.receipt_state_path.parent, "receipt_state_parent"),
        (Path(FIXED_CHILD_ENVIRONMENT["HOME"]), "child_home"),
    )
    try:
        for path, label in readonly_paths:
            if not os.statvfs(path).f_flag & readonly_flag:
                raise OdooRunnerError(
                    f"{label} is not on an immutable read-only mount"
                )
        for path, label in writable_paths:
            if os.statvfs(path).f_flag & readonly_flag:
                raise OdooRunnerError(
                    f"{label} is not on the explicit writable mount"
                )
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError("dependency mount attestation failed") from exc


def _validate_runtime_execution_paths(config: RuntimeConfig) -> None:
    for path, expected_digest, label in (
        (config.odoo_python, config.odoo_python_sha256, "odoo_python"),
        (config.odoo_bin, config.odoo_bin_sha256, "odoo_bin"),
        (config.odoo_config, config.odoo_config_sha256, "odoo_config"),
    ):
        if not path.is_file():
            raise OdooRunnerError(f"{label} is not a regular file")
        _verify_runtime_file_digest(path, expected_digest, label)
    if not config.release_root.is_dir() or config.release_root.is_symlink():
        raise OdooRunnerError("release_root is not a directory")
    runner_source = (
        config.release_root
        / "src"
        / "odoo_accounting_cli_v3"
        / "odoo"
        / "runner.py"
    )
    if not runner_source.is_file():
        raise OdooRunnerError("release_root does not contain the Odoo runner")
    _require_immutable_dependency_mounts(config)


def _validate_runtime_paths(config: RuntimeConfig) -> None:
    _validate_runtime_execution_paths(config)
    for path, label in (
        (config.auth_state_path, "auth_state_path"),
        (config.receipt_state_path, "receipt_state_path"),
    ):
        _validate_private_state_path(path, label)


def _verify_runtime_file_digest(path: Path, expected_digest: str, label: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise OdooRunnerError(f"{label} is not a regular file")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(descriptor)
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError(f"{label} cannot be verified") from exc
    if not hmac.compare_digest(digest.hexdigest(), expected_digest):
        raise OdooRunnerError(f"{label} does not match its root-managed digest")


def _verify_canonical_package(path: Path, expected_digest: str) -> None:
    """Hash one canonical root-managed package through the descriptor we opened."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise OdooRunnerError("canonical_package_path must be an absolute path")
    if not isinstance(expected_digest, str) or SHA256.fullmatch(expected_digest) is None:
        raise OdooRunnerError("canonical_package_sha256 must be a lowercase SHA-256 digest")
    if os.name == "posix" and not hasattr(os, "O_NOFOLLOW"):
        raise OdooRunnerError("canonical release package requires O_NOFOLLOW")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or path.resolve(strict=True) != path
        ):
            raise OdooRunnerError("canonical release package is not a regular canonical file")
        if os.name == "posix":
            current = path.parent
            while True:
                metadata = current.lstat()
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or current.is_symlink()
                    or metadata.st_uid != 0
                    or metadata.st_mode & 0o022
                ):
                    raise OdooRunnerError(
                        "canonical release package ancestors are not root-managed"
                    )
                if current.parent == current:
                    break
                current = current.parent
            if before.st_uid != 0 or before.st_mode & 0o022:
                raise OdooRunnerError("canonical release package is not root-managed")
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or (
                    os.name == "posix"
                    and (opened.st_uid != 0 or opened.st_mode & 0o022)
                )
            ):
                raise OdooRunnerError("canonical release package changed while it was opened")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (
            (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or not stat.S_ISREG(after.st_mode)
            or path.is_symlink()
        ):
            raise OdooRunnerError("canonical release package changed while it was verified")
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError("canonical release package cannot be verified") from exc
    if not hmac.compare_digest(digest.hexdigest(), expected_digest):
        raise OdooRunnerError("canonical release package digest does not match")


def _expected_canonical_package_path(release_root: Path) -> Path:
    return (
        release_root.parent.parent
        / "packages"
        / f"odoo-accounting-cli-v3-{release_root.name}.tar.gz"
    )


def _validate_canonical_package_binding(config: RuntimeConfig) -> None:
    if config.canonical_package_path != _expected_canonical_package_path(
        config.release_root
    ):
        raise OdooRunnerError("canonical release package path does not match release_root")
    _verify_canonical_package(
        config.canonical_package_path,
        config.canonical_package_sha256,
    )


def _validate_private_state_path(path: Path, label: str) -> None:
    try:
        parent = path.parent
        parent_metadata = parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent.is_symlink()
            or (
                os.path.lexists(path)
                and (not path.is_file() or path.is_symlink())
            )
        ):
            raise OdooRunnerError(f"{label} is invalid")
        if os.name == "posix":
            if parent.resolve(strict=True) != parent:
                raise OdooRunnerError(f"{label} parent path must not contain symlinks")
            if parent_metadata.st_uid not in {0, os.geteuid()} or parent_metadata.st_mode & 0o022:
                raise OdooRunnerError(f"{label} parent directory is not private")
            if path.exists():
                metadata = path.lstat()
                if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                    raise OdooRunnerError(f"{label} file is not private")
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError(f"{label} is invalid") from exc


def _assert_root_managed_path(path: Path, label: str, *, directory: bool) -> None:
    try:
        metadata = path.lstat()
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected_type(metadata.st_mode) or path.is_symlink():
            raise OdooRunnerError(f"{label} is not a canonical trusted path")
        if path.resolve(strict=True) != path:
            raise OdooRunnerError(f"{label} contains a symlink or non-canonical component")
        if os.name == "posix" and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
            raise OdooRunnerError(f"{label} is not root-managed")
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError(f"{label} cannot be verified") from exc


def _read_small_json_file(path: Path, label: str) -> dict[str, Any]:
    _assert_root_managed_path(path, label, directory=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            expected = path.lstat()
            if os.name == "posix" and (
                (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
                or opened.st_uid != 0
                or opened.st_mode & 0o022
            ):
                raise OdooRunnerError(f"{label} changed while it was opened")
            raw = os.read(descriptor, 65_537)
            if len(raw) > 65_536 or os.read(descriptor, 1):
                raise OdooRunnerError(f"{label} is too large")
        finally:
            os.close(descriptor)
        return _load_json_object(raw.decode("utf-8"), label)
    except OdooRunnerError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OdooRunnerError(f"{label} cannot be read") from exc


def _assert_release_tree_root_managed(release_root: Path) -> None:
    for path in release_root.rglob("*"):
        _assert_root_managed_path(
            path,
            f"release tree path {path.relative_to(release_root).as_posix()}",
            directory=path.is_dir(),
        )


def _verify_child_release(
    release_root: Path,
    expected_manifest_digest: str,
    expected_package_path: Path,
    expected_package_digest: str,
):
    if not isinstance(expected_manifest_digest, str) or SHA256.fullmatch(
        expected_manifest_digest
    ) is None:
        raise OdooRunnerError("child release digest is invalid")
    if not isinstance(expected_package_digest, str) or SHA256.fullmatch(
        expected_package_digest
    ) is None:
        raise OdooRunnerError("child package digest is invalid")
    trusted_root = release_root.parent.parent
    manifest_path = release_root / "RELEASE-MANIFEST.json"
    anchor_directory = trusted_root / "trusted-artifacts"
    anchor_path = anchor_directory / f"{release_root.name}.json"
    for path, label in (
        (trusted_root, "V3 deployment root"),
        (release_root.parent, "release directory"),
        (release_root, "release root"),
        (anchor_directory, "trusted artifact directory"),
    ):
        _assert_root_managed_path(path, label, directory=True)
    manifest = _read_small_json_file(manifest_path, "release manifest")
    anchor = _read_small_json_file(anchor_path, "release anchor")
    try:
        release_identity = ReleaseIdentity(
            version=manifest.get("version", ""),
            commit=manifest.get("commit", ""),
        )
    except ReleaseError as exc:
        raise OdooRunnerError("child release manifest identity is invalid") from exc
    expected_release = f"{release_identity.version}-{release_identity.commit[:12]}"
    if (
        set(anchor) != {"commit", "manifest_sha256", "package_sha256", "release"}
        or anchor.get("release") != release_root.name
        or release_root.name != expected_release
        or anchor.get("commit") != manifest.get("commit")
        or anchor.get("manifest_sha256") != expected_manifest_digest
        or anchor.get("package_sha256") != expected_package_digest
        or expected_package_path
        != release_root.parent.parent / "packages" / release_identity.package_name
    ):
        raise OdooRunnerError("child release anchor does not match the requested release")
    try:
        verify_manifest(
            release_root,
            manifest,
            expected_manifest_sha256=expected_manifest_digest,
        )
        _assert_release_tree_root_managed(release_root)
        from ..registry import load_registry

        return load_registry(release_root / "registry" / "capabilities.json")
    except (OSError, ValueError, ReleaseError) as exc:
        raise OdooRunnerError("child release integrity verification failed") from exc


def _normalize_request_json(value: Any) -> str:
    if isinstance(value, str):
        document = _load_json_object(value, "request")
    elif isinstance(value, dict):
        document = value
    else:
        raise OdooRunnerError("request must be a JSON object or JSON object string")
    try:
        normalized = canonical_json(document).decode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OdooRunnerError("request is not canonical JSON") from exc
    if len(normalized.encode("utf-8")) > MAX_PRIVATE_PAYLOAD_BYTES // 2:
        raise OdooRunnerError("request exceeds the private payload limit")
    return normalized


def _read_private_secret(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or path.is_symlink():
            raise OdooRunnerError(f"{label} must be a regular non-symlink file")
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if os.name == "posix":
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise OdooRunnerError(f"{label} changed while it was opened")
                if opened.st_uid != 0 or stat.S_IMODE(opened.st_mode) & ~0o640:
                    raise OdooRunnerError(
                        f"{label} must be root-owned, group-readable at most, and private"
                    )
            chunks = []
            total = 0
            while True:
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > 4096:
                    raise OdooRunnerError(f"{label} is too large")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError(f"{label} cannot be read") from exc
    secret = b"".join(chunks)
    if len(secret) < 32:
        raise OdooRunnerError(f"{label} must contain at least 32 bytes")
    return secret


def load_runtime_secrets(config: RuntimeConfig) -> tuple[bytes, bytes]:
    """Read distinct root-managed purpose-specific keys without following links."""

    auth_secret = _read_private_secret(config.auth_secret_path, "auth_secret_path")
    receipt_secret = _read_private_secret(config.receipt_secret_path, "receipt_secret_path")
    if hmac.compare_digest(auth_secret, receipt_secret):
        raise OdooRunnerError("authentication and receipt secrets must be distinct")
    return auth_secret, receipt_secret


def _runtime_gcov_directory(config: RuntimeConfig) -> Path:
    prefix = config.auth_state_path.parent / "gcov"
    try:
        prefix.mkdir(mode=0o700, parents=False, exist_ok=True)
        metadata = prefix.lstat()
        parent = prefix.parent.resolve(strict=True)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or prefix.is_symlink()
            or prefix.resolve(strict=True) != prefix
            or prefix.parent.resolve(strict=True) != parent
        ):
            raise OdooRunnerError("the fixed Odoo gcov directory is not trustworthy")
        if os.name == "posix" and (
            metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
        ):
            raise OdooRunnerError("the fixed Odoo gcov directory is not private")
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError("the fixed Odoo gcov directory cannot be prepared") from exc
    return prefix


def _safe_environment(config: RuntimeConfig | None = None) -> dict[str, str]:
    environment = dict(FIXED_CHILD_ENVIRONMENT)
    if config is not None:
        prefix = _runtime_gcov_directory(config)
        environment.update(
            {
                "GCOV_ERROR_FILE": str(prefix / "gcov-error.log"),
                "GCOV_EXIT_AT_ERROR": "0",
                "GCOV_PREFIX": str(prefix),
                "GCOV_PREFIX_STRIP": "0",
            }
        )
    return environment


def _validate_child_home(value: str) -> None:
    """Require the fixed child HOME to be one canonical private directory."""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise OdooRunnerError("the fixed Odoo HOME directory is not trustworthy")
    home = Path(value)
    if not home.is_absolute():
        raise OdooRunnerError("the fixed Odoo HOME directory is not trustworthy")
    try:
        metadata = home.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or home.is_symlink()
            or home.resolve(strict=True) != home
        ):
            raise OdooRunnerError(
                "the fixed Odoo HOME directory is not trustworthy"
            )
        if os.name == "posix":
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise OdooRunnerError(
                    "the fixed Odoo HOME directory must have mode 0700"
                )
            if metadata.st_uid != os.geteuid():
                raise OdooRunnerError(
                    "the fixed Odoo HOME directory must be owned by the effective uid"
                )
            no_follow = getattr(os, "O_NOFOLLOW", None)
            directory = getattr(os, "O_DIRECTORY", None)
            if no_follow is None or directory is None:
                raise OdooRunnerError(
                    "the fixed Odoo HOME directory cannot be opened safely"
                )
            flags = os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(home, flags)
            try:
                opened = os.fstat(descriptor)
                if (
                    (opened.st_dev, opened.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                    or not stat.S_ISDIR(opened.st_mode)
                    or stat.S_IMODE(opened.st_mode) != 0o700
                    or opened.st_uid != os.geteuid()
                ):
                    raise OdooRunnerError(
                        "the fixed Odoo HOME directory changed while it was opened"
                    )
            finally:
                os.close(descriptor)
    except OdooRunnerError:
        raise
    except (OSError, RuntimeError) as exc:
        raise OdooRunnerError(
            "the fixed Odoo HOME directory is not trustworthy"
        ) from exc


def _validate_child_environment(env: Mapping[str, str]) -> None:
    """Reject any environment drift and validate HOME before child creation."""

    if not isinstance(env, dict):
        raise OdooRunnerError("the fixed Odoo child environment is invalid")
    if env == FIXED_CHILD_ENVIRONMENT:
        _validate_child_home(env["HOME"])
        return
    fixed = {key: value for key, value in env.items() if key not in GCOV_CHILD_ENVIRONMENT_KEYS}
    gcov = {key: value for key, value in env.items() if key in GCOV_CHILD_ENVIRONMENT_KEYS}
    if fixed != FIXED_CHILD_ENVIRONMENT or set(gcov) != GCOV_CHILD_ENVIRONMENT_KEYS:
        raise OdooRunnerError("the fixed Odoo child environment is invalid")
    prefix = gcov.get("GCOV_PREFIX")
    error_file = gcov.get("GCOV_ERROR_FILE")
    if (
        not isinstance(prefix, str)
        or not isinstance(error_file, str)
        or gcov.get("GCOV_PREFIX_STRIP") != "0"
        or gcov.get("GCOV_EXIT_AT_ERROR") != "0"
        or "\x00" in prefix
        or "\x00" in error_file
    ):
        raise OdooRunnerError("the fixed Odoo gcov environment is invalid")
    prefix_path = Path(prefix)
    error_path = Path(error_file)
    if (
        not prefix_path.is_absolute()
        or not error_path.is_absolute()
        or error_path.parent != prefix_path
        or error_path.name != "gcov-error.log"
    ):
        raise OdooRunnerError("the fixed Odoo gcov environment is invalid")
    try:
        metadata = prefix_path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or prefix_path.is_symlink()
            or prefix_path.resolve(strict=True) != prefix_path
        ):
            raise OdooRunnerError("the fixed Odoo gcov directory is not trustworthy")
        if os.name == "posix" and (
            metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
        ):
            raise OdooRunnerError("the fixed Odoo gcov directory is not private")
    except OdooRunnerError:
        raise
    except OSError as exc:
        raise OdooRunnerError("the fixed Odoo gcov directory cannot be verified") from exc
    _validate_child_home(env["HOME"])


@contextmanager
def _private_payload_fd(payload: bytes):
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_PRIVATE_PAYLOAD_BYTES:
        raise OdooRunnerError("private child payload is invalid or too large")
    if os.name == "posix":
        if not hasattr(os, "memfd_create"):
            raise OdooRunnerError("the POSIX runtime does not support sealed memory files")
        flags = getattr(os, "MFD_CLOEXEC", 0) | getattr(os, "MFD_ALLOW_SEALING", 0)
        descriptor = os.memfd_create("odoo-accounting-cli-v3-payload", flags=flags)
        try:
            view = memoryview(payload)
            written = 0
            while written < len(view):
                written += os.write(descriptor, view[written:])
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                import fcntl

                seals = (
                    fcntl.F_SEAL_SEAL
                    | fcntl.F_SEAL_SHRINK
                    | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_WRITE
                )
                fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
            except (AttributeError, OSError) as exc:
                raise OdooRunnerError("private child payload could not be sealed") from exc
            yield descriptor
        finally:
            os.close(descriptor)
        return
    # Local non-POSIX unit tests mock the trusted POSIX child boundary.
    with tempfile.TemporaryFile(mode="w+b") as stream:
        stream.write(payload)
        stream.flush()
        stream.seek(0)
        yield stream.fileno()


def _child_source(config: RuntimeConfig, payload_fd: int, marker: str) -> str:
    source_root = str(config.release_root / "src")
    return (
        "import sys\n"
        f"sys.path.insert(0, {source_root!r})\n"
        "from odoo_accounting_cli_v3.odoo.runner import _child_main\n"
        f"_child_main(env, {payload_fd!r}, {marker!r})\n"
    )


def _evidence_child_source(
    config: RuntimeConfig, payload_fd: int, marker: str
) -> str:
    source_root = str(config.release_root / "src")
    return (
        "import sys\n"
        f"sys.path.insert(0, {source_root!r})\n"
        "from odoo_accounting_cli_v3.odoo.runner import _evidence_child_main\n"
        f"_evidence_child_main(env, {payload_fd!r}, {marker!r})\n"
    )


def _kill_child_process_group(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            process.send_signal(signal.SIGTERM)
        elif process.poll() is None:  # pragma: no cover - trusted runtime is POSIX.
            process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL should be final.
        if os.name == "posix":
            _force_kill_linux_supervisor_tree(process)
        else:
            process.kill()
            process.wait(timeout=5)


def _decode_child_output(value: bytes, label: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeError as exc:
        raise OdooRunnerError(f"Odoo shell {label} is not valid UTF-8") from exc


class _SupervisorTerminationRequested(BaseException):
    """Interrupt the persistent supervisor so it can reap the full child tree."""


def _request_supervised_tree_termination(_signum: int, _frame: Any) -> None:
    raise _SupervisorTerminationRequested


def _install_linux_parent_death_guard(expected_parent_pid: int) -> None:
    """Arm PDEATHSIG and close the parent-exit-before-prctl race."""

    if sys.platform != "linux":
        raise OSError("the Odoo process supervisor requires Linux")
    if (
        isinstance(expected_parent_pid, bool)
        or not isinstance(expected_parent_pid, int)
        or expected_parent_pid <= 1
    ):
        raise OSError("the Odoo process supervisor parent is invalid")

    # This handler remains installed in the persistent supervisor. It is not
    # installed in a pre-exec child, where execve would reset it.
    signal.signal(signal.SIGTERM, _request_supervised_tree_termination)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM})
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        result = prctl(1, signal.SIGTERM, 0, 0, 0)  # PR_SET_PDEATHSIG
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
    except (AttributeError, OSError) as exc:
        raise OSError("the Odoo process supervisor parent guard failed") from exc

    # Linux does not deliver a retroactive PDEATHSIG if the parent died before
    # prctl completed. Checking after arming it closes that documented race.
    if os.getppid() != expected_parent_pid:
        _request_supervised_tree_termination(signal.SIGTERM, None)

    # Reparent Odoo descendants here if their immediate parent exits. This lets
    # the persistent supervisor clean daemon-like leftovers without signalling
    # a possibly reused process-group identifier after the leader was reaped.
    result = prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _kill_adopted_linux_descendants() -> None:
    """Kill and reap every descendant adopted by the Linux subreaper."""

    children_path = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
    while True:
        try:
            raw_children = children_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            continue
        if not raw_children:
            return
        try:
            children = tuple(int(value) for value in raw_children.split())
        except ValueError:
            continue
        if any(pid <= 1 for pid in children) or len(set(children)) != len(children):
            continue

        for pid in children:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for pid in children:
            while True:
                try:
                    os.waitpid(pid, 0)
                    break
                except InterruptedError:
                    continue
                except ChildProcessError:
                    break


def _validate_linux_descendant_reaper() -> None:
    """Fail before Odoo starts unless the Linux adopted-child view is usable."""

    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise OSError("the Odoo process supervisor requires Linux pidfds")
    children_path = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
    try:
        raw_children = children_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise OSError("the Odoo process supervisor cannot inspect descendants") from exc
    if raw_children:
        raise OSError("the Odoo process supervisor has unexpected children")


def _linux_process_state(pid: int) -> str | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    closing_parenthesis = value.rfind(")")
    if closing_parenthesis < 0:
        return None
    remainder = value[closing_parenthesis + 1 :].split()
    return remainder[0] if remainder else None


def _force_kill_linux_supervisor_tree(process: subprocess.Popen[bytes]) -> None:
    """Last-resort exact-PID cleanup before killing a stuck supervisor."""

    try:
        process.send_signal(signal.SIGSTOP)
    except ProcessLookupError:
        process.wait(timeout=5)
        return
    children_path = Path(
        f"/proc/{process.pid}/task/{process.pid}/children"
    )
    while process.poll() is None:
        try:
            raw_children = children_path.read_text(encoding="ascii").strip()
            children = tuple(int(value) for value in raw_children.split())
        except (OSError, UnicodeError, ValueError):
            continue
        if any(pid <= 1 for pid in children) or len(set(children)) != len(children):
            continue
        states = {pid: _linux_process_state(pid) for pid in children}
        if any(state is None for state in states.values()):
            continue
        live_children = tuple(pid for pid, state in states.items() if state != "Z")
        if not live_children:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            return
        for pid in live_children:
            try:
                descriptor = os.pidfd_open(pid)
            except OSError:
                continue
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except OSError:
                pass
            finally:
                os.close(descriptor)


def _terminate_supervised_linux_tree(child: subprocess.Popen[bytes]) -> None:
    """Kill the direct Odoo child, then every cross-session adopted descendant."""

    if child.poll() is None:
        try:
            os.kill(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        while True:
            try:
                child.wait()
                break
            except InterruptedError:
                continue
    _kill_adopted_linux_descendants()


def _finish_supervised_linux_tree(child: subprocess.Popen[bytes]) -> None:
    """Never leave the supervisor while any adopted descendant may remain."""

    while True:
        try:
            _terminate_supervised_linux_tree(child)
            return
        except BaseException:
            continue


def _restore_child_signal_mask(mask: set[signal.Signals]) -> None:
    """Restore the pre-supervisor mask in the single-threaded pre-exec child."""

    signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def _linux_process_supervisor_main() -> None:
    """Keep a Linux process-group owner alive until the Odoo child exits."""

    failure = b"Odoo process supervisor failed\n"
    child: subprocess.Popen[bytes] | None = None
    try:
        if (
            sys.platform != "linux"
            or len(sys.argv) < 6
            or sys.argv[4] != "--"
            or os.getpid() != os.getpgrp()
            or os.getsid(0) != os.getpid()
        ):
            raise OSError("invalid Odoo process supervisor boundary")
        expected_parent_pid = int(sys.argv[1])
        payload_fd = int(sys.argv[2])
        source_fd = int(sys.argv[3])
        if (
            expected_parent_pid <= 1
            or payload_fd <= 2
            or source_fd <= 2
            or source_fd == payload_fd
        ):
            raise OSError("invalid Odoo process supervisor identity")
        child_argv = sys.argv[5:]
        if not child_argv or any(
            not isinstance(value, str) or not value for value in child_argv
        ):
            raise OSError("invalid Odoo child command")
        _install_linux_parent_death_guard(expected_parent_pid)
        _validate_linux_descendant_reaper()
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        if signal.SIGTERM in previous_mask:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            raise OSError("the Odoo process supervisor signal mask is invalid")
        try:
            # This fixed helper is single-threaded. The pre-exec hook only
            # restores the inherited mask; it never executes request data.
            spawned = subprocess.Popen(
                child_argv,
                stdin=source_fd,
                stdout=None,
                stderr=None,
                text=False,
                shell=False,
                close_fds=True,
                pass_fds=(payload_fd,),
                start_new_session=False,
                cwd=None,
                env=None,
                preexec_fn=lambda: _restore_child_signal_mask(previous_mask),
            )
            child = spawned
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        returncode = child.wait()
        _kill_adopted_linux_descendants()
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
    except _SupervisorTerminationRequested:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if child is not None:
            _finish_supervised_linux_tree(child)
        os._exit(128 + signal.SIGTERM)
    except BaseException:
        if child is not None:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            _finish_supervised_linux_tree(child)
        try:
            os.write(2, failure)
        finally:
            os._exit(125)

    if returncode < 0:
        terminating_signal = -returncode
        if terminating_signal not in {signal.SIGKILL, signal.SIGSTOP}:
            signal.signal(terminating_signal, signal.SIG_DFL)
        os.kill(os.getpid(), terminating_signal)
        os._exit(128 + min(terminating_signal, 127))
    os._exit(returncode if 0 <= returncode <= 255 else 125)


def _linux_supervisor_argv(
    argv: list[str], payload_fd: int, source_fd: int
) -> list[str]:
    """Build a fixed supervisor invocation without request data in argv or env."""

    source_root = Path(__file__).resolve().parents[2]
    bootstrap = (
        "import sys\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        "from odoo_accounting_cli_v3.odoo.runner import "
        "_linux_process_supervisor_main\n"
        "_linux_process_supervisor_main()\n"
    )
    return [
        sys.executable,
        "-I",
        "-c",
        bootstrap,
        str(os.getpid()),
        str(payload_fd),
        str(source_fd),
        "--",
        *argv,
    ]


def _run_child_process(
    argv: list[str],
    *,
    source: str,
    payload_fd: int,
    timeout_seconds: float,
    cwd: str,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    if sys.platform != "linux":  # pragma: no cover - local tests mock this boundary.
        raise OdooRunnerError("the trusted Odoo shell runner requires a Linux runtime")
    _validate_child_environment(env)
    try:
        source_bytes = source.encode("utf-8")
    except UnicodeError as exc:
        raise OdooRunnerError("Odoo shell bootstrap is not valid UTF-8") from exc
    if not source_bytes or len(source_bytes) > 65_536:
        raise OdooRunnerError("Odoo shell bootstrap is invalid or too large")
    source_context = _private_payload_fd(source_bytes)
    try:
        source_fd = source_context.__enter__()
        try:
            process = subprocess.Popen(
                _linux_supervisor_argv(argv, payload_fd, source_fd),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=False,
                close_fds=True,
                pass_fds=(payload_fd, source_fd),
                start_new_session=True,
                cwd=cwd,
                env=env,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OdooRunnerError("Odoo shell could not be started") from exc
    finally:
        source_context.__exit__(None, None, None)

    streams = {
        "stdout": (process.stdout, MAX_CHILD_STDOUT_BYTES, bytearray()),
        "stderr": (process.stderr, MAX_CHILD_STDERR_BYTES, bytearray()),
    }
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        if process.stdout is None or process.stderr is None:
            raise OdooRunnerError("Odoo shell pipes could not be created")

        for label, (stream, maximum, buffer) in streams.items():
            os.set_blocking(stream.fileno(), False)
            selector.register(
                stream,
                selectors.EVENT_READ,
                (label, maximum, buffer),
            )

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_child_process_group(process)
                raise OdooRunnerError("Odoo shell timed out")
            for key, _event in selector.select(timeout=min(remaining, 0.1)):
                label, maximum, buffer = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), min(65_536, maximum + 1 - len(buffer)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    _kill_child_process_group(process)
                    raise OdooRunnerError(
                        f"Odoo shell {label} exceeded its size limit"
                    )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_child_process_group(process)
            raise OdooRunnerError("Odoo shell timed out")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _kill_child_process_group(process)
            raise OdooRunnerError("Odoo shell timed out") from exc
        return subprocess.CompletedProcess(
            argv,
            returncode,
            stdout=_decode_child_output(bytes(streams["stdout"][2]), "stdout"),
            stderr=_decode_child_output(bytes(streams["stderr"][2]), "stderr"),
        )
    except BaseException:
        _kill_child_process_group(process)
        raise
    finally:
        selector.close()
        for stream, _maximum, _buffer in streams.values():
            if stream is not None and not stream.closed:
                stream.close()


def _parse_response(stdout: Any, marker: str, config: RuntimeConfig) -> dict[str, Any]:
    if not isinstance(stdout, str) or stdout.count(marker) != 1:
        raise OdooRunnerError("Odoo shell did not emit exactly one result marker")
    marked_lines = [line for line in stdout.splitlines() if line.startswith(marker)]
    if len(marked_lines) != 1:
        raise OdooRunnerError("Odoo shell result marker is not on a dedicated line")
    response = _load_json_object(marked_lines[0][len(marker) :], "Odoo shell response")
    is_success = set(response) == RESPONSE_FIELDS and response.get("ok") is True
    is_rejection = (
        set(response) == REJECTION_RESPONSE_FIELDS
        and response.get("ok") is False
        and response.get("rejection_code") in READ_REJECTION_CODES
    )
    if not is_success and not is_rejection:
        raise OdooRunnerError("Odoo shell response fields are invalid")
    runtime = response.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_FIELDS:
        raise OdooRunnerError("Odoo shell runtime identity is invalid")
    try:
        observed_uuid = str(uuid.UUID(runtime["database_uuid"]))
    except (AttributeError, TypeError, ValueError) as exc:
        raise OdooRunnerError("Odoo shell runtime identity is invalid") from exc
    observed = {**runtime, "database_uuid": observed_uuid}
    if observed != config.runtime_identity:
        raise OdooRunnerError("Odoo shell runtime identity does not match configuration")
    if is_rejection:
        raise OdooRunnerError(
            "Odoo read request was rejected",
            rejection_code=response["rejection_code"],
        )
    result = response.get("result")
    if not isinstance(result, dict):
        raise OdooRunnerError("Odoo shell result must be an object")
    return result


def run_odoo_shell(
    config: RuntimeConfig,
    request: dict[str, Any] | str,
    *,
    release_digest: str,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Execute one request without exposing request data or secrets in argv/env."""

    if not isinstance(config, RuntimeConfig):
        raise OdooRunnerError("a validated runtime configuration is required")
    if not isinstance(release_digest, str) or SHA256.fullmatch(release_digest) is None:
        raise OdooRunnerError("release_digest must be a lowercase SHA-256 digest")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise OdooRunnerError(
            f"timeout_seconds must be positive and no greater than {MAX_TIMEOUT_SECONDS:g}"
        )
    request_json = _normalize_request_json(request)
    _validate_canonical_package_binding(config)
    # Verify the configured release with trusted parent code before secrets can be
    # copied into a child that imports Python from that release. The child repeats
    # this check; neither check eliminates the filesystem TOCTOU window.
    _verify_child_release(
        config.release_root,
        release_digest,
        config.canonical_package_path,
        config.canonical_package_sha256,
    )
    _validate_runtime_paths(config)
    auth_secret, receipt_secret = load_runtime_secrets(config)
    payload = canonical_json(
        {
            "protocol": 1,
            "runtime": config.runtime_identity,
            "request_json": request_json,
            "auth_secret": base64.b64encode(auth_secret).decode("ascii"),
            "auth_key_id": config.auth_key_id,
            "receipt_secret": base64.b64encode(receipt_secret).decode("ascii"),
            "receipt_key_id": config.receipt_key_id,
            "release_digest": release_digest,
            "canonical_package_path": str(config.canonical_package_path),
            "canonical_package_sha256": config.canonical_package_sha256,
            "release_root": str(config.release_root),
            "auth_state_path": str(config.auth_state_path),
            "receipt_state_path": str(config.receipt_state_path),
        }
    )
    marker = f"__ODOO_ACCOUNTING_CLI_V3_RESULT_{secrets.token_hex(24)}__:"
    if MARKER.fullmatch(marker) is None:  # Defensive if marker generation is replaced.
        raise OdooRunnerError("result marker generation failed")
    argv = [
        str(config.odoo_python),
        str(config.odoo_bin),
        "shell",
        "-c",
        str(config.odoo_config),
        "-d",
        config.database_name,
        "--no-http",
        "--logfile=/dev/null",
    ]
    with _private_payload_fd(payload) as payload_fd:
        completed = _run_child_process(
            argv,
            source=_child_source(config, payload_fd, marker),
            payload_fd=payload_fd,
            timeout_seconds=float(timeout_seconds),
            cwd=str(config.release_root),
            env=_safe_environment(config),
        )
    if completed.returncode != 0:
        raise OdooRunnerError(f"Odoo shell exited with status {completed.returncode}")
    return _parse_response(completed.stdout, marker, config)


def run_read_boundary_evidence(
    config: RuntimeConfig,
    *,
    release_digest: str,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Collect rollback-only evidence without loading auth or receipt state."""

    if not isinstance(config, RuntimeConfig):
        raise OdooRunnerError("a validated runtime configuration is required")
    require_staged_test_evidence_runtime(config)
    if not isinstance(release_digest, str) or SHA256.fullmatch(release_digest) is None:
        raise OdooRunnerError("release_digest must be a lowercase SHA-256 digest")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise OdooRunnerError(
            f"timeout_seconds must be positive and no greater than {MAX_TIMEOUT_SECONDS:g}"
        )
    _validate_canonical_package_binding(config)
    _verify_child_release(
        config.release_root,
        release_digest,
        config.canonical_package_path,
        config.canonical_package_sha256,
    )
    _validate_runtime_execution_paths(config)
    payload = canonical_json(
        {
            "protocol": 1,
            "runtime": config.runtime_identity,
            "release_digest": release_digest,
            "canonical_package_path": str(config.canonical_package_path),
            "canonical_package_sha256": config.canonical_package_sha256,
            "release_root": str(config.release_root),
        }
    )
    marker = f"__ODOO_ACCOUNTING_CLI_V3_RESULT_{secrets.token_hex(24)}__:"
    if MARKER.fullmatch(marker) is None:
        raise OdooRunnerError("result marker generation failed")
    argv = [
        str(config.odoo_python),
        str(config.odoo_bin),
        "shell",
        "-c",
        str(config.odoo_config),
        "-d",
        config.database_name,
        "--no-http",
        "--logfile=/dev/null",
    ]
    with _private_payload_fd(payload) as payload_fd:
        completed = _run_child_process(
            argv,
            source=_evidence_child_source(config, payload_fd, marker),
            payload_fd=payload_fd,
            timeout_seconds=float(timeout_seconds),
            cwd=str(config.release_root),
            env=_safe_environment(config),
        )
    if completed.returncode != 0:
        raise OdooRunnerError(f"Odoo shell exited with status {completed.returncode}")
    result = _parse_response(completed.stdout, marker, config)
    from .read_boundary_evidence import (
        ReadBoundaryEvidenceError,
        validate_read_boundary_evidence,
    )

    try:
        return validate_read_boundary_evidence(
            result,
            expected_database_name=config.database_name,
            expected_database_uuid=config.database_uuid,
        )
    except ReadBoundaryEvidenceError as exc:
        raise OdooRunnerError("Odoo read-boundary evidence is invalid") from exc


def _decode_secret(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise OdooRunnerError(f"{field} is invalid")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise OdooRunnerError(f"{field} is invalid") from exc
    if not result:
        raise OdooRunnerError(f"{field} is invalid")
    return result


def _record_verified_read_audit(
    store: Any,
    request_json: str,
    result: dict[str, Any],
    *,
    registry_digest: str,
    release_digest: str,
    environment: str,
    capability_channel: str,
    now: datetime,
) -> None:
    request = _load_json_object(request_json, "audited request")
    context = request.get("context")
    parameters = request.get("parameters")
    receipt = result.get("receipt") if isinstance(result, dict) else None
    result_body = (
        {key: value for key, value in result.items() if key != "receipt"}
        if isinstance(result, dict)
        else None
    )
    if not all(
        isinstance(value, dict)
        for value in (context, parameters, receipt, result_body)
    ):
        raise OdooRunnerError("verified read audit identity is missing")
    page = result_body.get("page")
    record_count = page.get("total_count") if isinstance(page, dict) else None
    capability_id = request.get("capability_id")
    required_context = {
        field: context.get(field)
        for field in (
            "auth_token_id",
            "principal",
            "odoo_instance_id",
            "database_name",
            "database_uuid",
            "company_id",
            "user_id",
        )
    }
    if (
        not isinstance(capability_id, str)
        or not capability_id
        or any(value is None for value in required_context.values())
        or type(record_count) is not int
        or record_count < 0
        or not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise OdooRunnerError("verified read audit identity is invalid")
    store.record_verified_read(
        receipt=receipt,
        capability_id=capability_id,
        parameters=parameters,
        result_body=result_body,
        auth_token_id=required_context["auth_token_id"],
        principal=required_context["principal"],
        odoo_instance_id=required_context["odoo_instance_id"],
        database_name=required_context["database_name"],
        database_uuid=required_context["database_uuid"],
        company_id=required_context["company_id"],
        user_id=required_context["user_id"],
        registry_digest=registry_digest,
        release_digest=release_digest,
        environment=environment,
        capability_channel=capability_channel,
        expected_record_count=record_count,
        now=now,
    )


def _child_main(root_env: Any, payload_fd: int, marker: str) -> None:
    """Odoo-shell entrypoint referenced by the fixed stdin program."""

    if not isinstance(marker, str) or MARKER.fullmatch(marker) is None:
        raise OdooRunnerError("child result marker is invalid")
    if isinstance(payload_fd, bool) or not isinstance(payload_fd, int) or payload_fd <= 2:
        raise OdooRunnerError("child payload is invalid")
    try:
        with os.fdopen(payload_fd, "rb", closefd=True) as stream:
            payload_bytes = stream.read(MAX_PRIVATE_PAYLOAD_BYTES + 1)
        if not payload_bytes or len(payload_bytes) > MAX_PRIVATE_PAYLOAD_BYTES:
            raise OdooRunnerError("child payload is invalid")
        payload_text = payload_bytes.decode("utf-8")
    except OdooRunnerError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OdooRunnerError("child payload is invalid") from exc
    payload = _load_json_object(payload_text, "child payload")
    if set(payload) != CHILD_FIELDS or payload.get("protocol") != 1:
        raise OdooRunnerError("child payload fields are invalid")
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_FIELDS:
        raise OdooRunnerError("child runtime identity is invalid")
    child_release_root = _absolute_path(payload["release_root"], "release_root")
    runtime_config = RuntimeConfig(
        instance_id=runtime["instance_id"],
        environment=runtime["environment"],
        capability_channel=runtime["capability_channel"],
        database_name=runtime["database_name"],
        database_uuid=runtime["database_uuid"],
        odoo_python=Path("/unused/odoo-python"),
        odoo_python_sha256="0" * 64,
        odoo_bin=Path("/unused/odoo-bin"),
        odoo_bin_sha256="0" * 64,
        odoo_config=Path("/unused/odoo.conf"),
        odoo_config_sha256="0" * 64,
        release_root=child_release_root,
        canonical_package_path=_absolute_path(
            payload["canonical_package_path"], "canonical_package_path"
        ),
        canonical_package_sha256=payload["canonical_package_sha256"],
        auth_state_path=_absolute_path(payload["auth_state_path"], "auth_state_path"),
        receipt_state_path=_absolute_path(payload["receipt_state_path"], "receipt_state_path"),
        auth_key_id=_strict_text(payload["auth_key_id"], "auth_key_id"),
        receipt_key_id=_strict_text(payload["receipt_key_id"], "receipt_key_id"),
        auth_secret_path=child_release_root / ".unused-auth-secret",
        receipt_secret_path=child_release_root / ".unused-receipt-secret",
    )
    release_root = runtime_config.release_root.resolve()
    if Path(__file__).resolve().parents[3] != release_root:
        raise OdooRunnerError("child code is not loaded from the configured release")
    release_digest = payload.get("release_digest")
    if not isinstance(release_digest, str) or SHA256.fullmatch(release_digest) is None:
        raise OdooRunnerError("child release digest is invalid")
    request_json = payload.get("request_json")
    if not isinstance(request_json, str):
        raise OdooRunnerError("child request is invalid")

    _validate_canonical_package_binding(runtime_config)
    capabilities = _verify_child_release(
        release_root,
        release_digest,
        runtime_config.canonical_package_path,
        runtime_config.canonical_package_sha256,
    )

    from ..persistence import ReplayRejected, SQLitePersistence
    from ..registry import registry_digest as calculate_registry_digest
    from .bootstrap import execute_read_json

    _validate_private_state_path(runtime_config.auth_state_path, "auth_state_path")
    _validate_private_state_path(runtime_config.receipt_state_path, "receipt_state_path")
    receipt_secret = _decode_secret(
        payload.get("receipt_secret"), "receipt_secret"
    )
    previous_umask = os.umask(0o077)
    try:
        auth_store = SQLitePersistence(runtime_config.auth_state_path)
        receipt_store = SQLitePersistence(
            runtime_config.receipt_state_path,
            receipt_key_id=runtime_config.receipt_key_id,
            receipt_secret=receipt_secret,
        )
    finally:
        os.umask(previous_umask)

    replay_rejected = False

    def consume_auth_token(
        token_id: str,
        request_digest: str,
        expires_at: datetime,
        verified_at: datetime,
    ) -> bool:
        try:
            auth_store.consume_auth_token(
                token_id=token_id,
                request_digest=request_digest,
                expires_at=expires_at,
                now=verified_at,
            )
        except ReplayRejected:
            nonlocal replay_rejected
            replay_rejected = True
            return False
        return True

    try:
        result_json = execute_read_json(
            root_env,
            request_json,
            capabilities=capabilities,
            auth_secret=_decode_secret(payload.get("auth_secret"), "auth_secret"),
            auth_key_id=runtime_config.auth_key_id,
            consume_auth_token=consume_auth_token,
            receipt_secret=receipt_secret,
            receipt_key_id=runtime_config.receipt_key_id,
            # The executor verifies the signed receipt in memory. Durable replay
            # consumption is combined with the audit append immediately below.
            consume_receipt=lambda *_: True,
            release_digest=release_digest,
            odoo_instance_id=runtime_config.instance_id,
            environment=runtime_config.environment,
            capability_channel=runtime_config.capability_channel,
        )
    except Exception as exc:
        rejection_code = _classify_trusted_read_rejection(
            exc, replay_rejected=replay_rejected
        )
        if rejection_code is None:
            raise
        response = {
            "ok": False,
            "runtime": runtime_config.runtime_identity,
            "rejection_code": rejection_code,
        }
        print(marker + canonical_json(response).decode("utf-8"), flush=True)
        return
    result = _load_json_object(result_json, "Odoo result")
    _record_verified_read_audit(
        receipt_store,
        request_json,
        result,
        registry_digest=calculate_registry_digest(capabilities),
        release_digest=release_digest,
        environment=runtime_config.environment,
        capability_channel=runtime_config.capability_channel,
        now=datetime.now(timezone.utc),
    )
    response = {"ok": True, "runtime": runtime_config.runtime_identity, "result": result}
    print(marker + canonical_json(response).decode("utf-8"), flush=True)


def _classify_trusted_read_rejection(
    exc: BaseException, *, replay_rejected: bool
) -> str | None:
    """Classify only explicit policy failures from the same Odoo execution."""

    from ..auth import AuthenticationError
    from ..gateway import GatewayError
    from .bootstrap import OdooBootstrapError

    message = str(exc)
    if type(exc) is AuthenticationError:
        if message == "authentication context is not currently valid":
            return "authentication_expired"
        if message == "authentication signature mismatch":
            return "authentication_tampered"
        return None
    if type(exc) is OdooBootstrapError:
        if message == "signed request does not match the Odoo runtime":
            return "database_binding_rejected"
        if message == "signed request content digest mismatch":
            return "authentication_tampered"
        if message in {
            "signed allowed companies exceed the Odoo user companies",
            "signed company is not assigned to the Odoo user",
        }:
            return "company_binding_rejected"
        return None
    if type(exc) is GatewayError:
        if message == "request context authentication failed" and replay_rejected:
            return "authentication_replayed"
        if message == "Odoo ACL rejected capability":
            return "odoo_acl_denied"
        if message in {
            "request company does not match bound company",
            "request includes an unauthorized company",
        }:
            return "company_binding_rejected"
        return None
    return None


def _evidence_child_main(root_env: Any, payload_fd: int, marker: str) -> None:
    """Exact-release Odoo-shell entrypoint for read-boundary evidence."""

    if not isinstance(marker, str) or MARKER.fullmatch(marker) is None:
        raise OdooRunnerError("child result marker is invalid")
    if isinstance(payload_fd, bool) or not isinstance(payload_fd, int) or payload_fd <= 2:
        raise OdooRunnerError("child payload is invalid")
    try:
        with os.fdopen(payload_fd, "rb", closefd=True) as stream:
            payload_bytes = stream.read(MAX_PRIVATE_PAYLOAD_BYTES + 1)
        if not payload_bytes or len(payload_bytes) > MAX_PRIVATE_PAYLOAD_BYTES:
            raise OdooRunnerError("child payload is invalid")
        payload_text = payload_bytes.decode("utf-8")
    except OdooRunnerError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OdooRunnerError("child payload is invalid") from exc
    payload = _load_json_object(payload_text, "child payload")
    if set(payload) != EVIDENCE_CHILD_FIELDS or payload.get("protocol") != 1:
        raise OdooRunnerError("child payload fields are invalid")
    runtime = payload.get("runtime")
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_FIELDS:
        raise OdooRunnerError("child runtime identity is invalid")
    child_release_root = _absolute_path(payload["release_root"], "release_root")
    runtime_config = RuntimeConfig(
        instance_id=runtime["instance_id"],
        environment=runtime["environment"],
        capability_channel=runtime["capability_channel"],
        database_name=runtime["database_name"],
        database_uuid=runtime["database_uuid"],
        odoo_python=Path("/unused/odoo-python"),
        odoo_python_sha256="0" * 64,
        odoo_bin=Path("/unused/odoo-bin"),
        odoo_bin_sha256="0" * 64,
        odoo_config=Path("/unused/odoo.conf"),
        odoo_config_sha256="0" * 64,
        release_root=child_release_root,
        canonical_package_path=_absolute_path(
            payload["canonical_package_path"], "canonical_package_path"
        ),
        canonical_package_sha256=payload["canonical_package_sha256"],
        auth_state_path=child_release_root / ".unused-evidence-auth-state",
        receipt_state_path=child_release_root / ".unused-evidence-receipt-state",
        auth_key_id="unused-evidence-auth-key",
        receipt_key_id="unused-evidence-receipt-key",
        auth_secret_path=child_release_root / ".unused-evidence-auth-secret",
        receipt_secret_path=child_release_root / ".unused-evidence-receipt-secret",
    )
    require_staged_test_evidence_runtime(runtime_config)
    release_root = runtime_config.release_root.resolve()
    if Path(__file__).resolve().parents[3] != release_root:
        raise OdooRunnerError("child code is not loaded from the configured release")
    release_digest = payload.get("release_digest")
    if not isinstance(release_digest, str) or SHA256.fullmatch(release_digest) is None:
        raise OdooRunnerError("child release digest is invalid")
    _validate_canonical_package_binding(runtime_config)
    _verify_child_release(
        release_root,
        release_digest,
        runtime_config.canonical_package_path,
        runtime_config.canonical_package_sha256,
    )

    from .read_boundary_evidence import (
        collect_read_boundary_evidence,
        validate_read_boundary_evidence,
    )

    try:
        result = collect_read_boundary_evidence(root_env)
        validate_read_boundary_evidence(
            result,
            expected_database_name=runtime_config.database_name,
            expected_database_uuid=runtime_config.database_uuid,
        )
    except Exception:
        raise OdooRunnerError(
            "Odoo read-boundary evidence collection failed"
        ) from None
    response = {
        "ok": True,
        "runtime": runtime_config.runtime_identity,
        "result": result,
    }
    print(marker + canonical_json(response).decode("utf-8"), flush=True)

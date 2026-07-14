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


class OdooRunnerError(ValueError):
    """Raised when runtime configuration or child execution is not trustworthy."""


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
RESPONSE_FIELDS = frozenset({"ok", "runtime", "result"})
FIXED_CHILD_ENVIRONMENT = {
    "HOME": "/home/odoo",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TZ": "UTC",
}
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
        or any(ord(character) < 32 for character in value)
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


def _validate_runtime_paths(config: RuntimeConfig) -> None:
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


def _safe_environment() -> dict[str, str]:
    return dict(FIXED_CHILD_ENVIRONMENT)


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


def _kill_child_process_group(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:  # pragma: no cover - trusted runtime is POSIX.
            process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL should be final.
        process.kill()
        process.wait(timeout=5)


def _decode_child_output(value: bytes, label: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeError as exc:
        raise OdooRunnerError(f"Odoo shell {label} is not valid UTF-8") from exc


def _run_child_process(
    argv: list[str],
    *,
    source: str,
    payload_fd: int,
    timeout_seconds: float,
    cwd: str,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    if os.name != "posix":  # pragma: no cover - local tests mock this Linux boundary.
        raise OdooRunnerError("the trusted Odoo shell runner requires a POSIX runtime")
    try:
        source_bytes = source.encode("utf-8")
    except UnicodeError as exc:
        raise OdooRunnerError("Odoo shell bootstrap is not valid UTF-8") from exc
    if not source_bytes or len(source_bytes) > 65_536:
        raise OdooRunnerError("Odoo shell bootstrap is invalid or too large")
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            pass_fds=(payload_fd,),
            start_new_session=True,
            cwd=cwd,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OdooRunnerError("Odoo shell could not be started") from exc

    streams = {
        "stdout": (process.stdout, MAX_CHILD_STDOUT_BYTES, bytearray()),
        "stderr": (process.stderr, MAX_CHILD_STDERR_BYTES, bytearray()),
    }
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise OdooRunnerError("Odoo shell pipes could not be created")
        try:
            process.stdin.write(source_bytes)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            process.stdin.close()

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
    if set(response) != RESPONSE_FIELDS or response.get("ok") is not True:
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
    ]
    with _private_payload_fd(payload) as payload_fd:
        completed = _run_child_process(
            argv,
            source=_child_source(config, payload_fd, marker),
            payload_fd=payload_fd,
            timeout_seconds=float(timeout_seconds),
            cwd=str(config.release_root),
            env=_safe_environment(),
        )
    if completed.returncode != 0:
        raise OdooRunnerError(f"Odoo shell exited with status {completed.returncode}")
    return _parse_response(completed.stdout, marker, config)


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
            return False
        return True

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

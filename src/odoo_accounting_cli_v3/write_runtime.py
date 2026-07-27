"""Root-managed, role-separated runtime boundary for accounting writes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .effect_finalizer import (
    EffectFinalizationError,
    EffectFinalizationIdentity,
)
from .effect_finalizer_runtime import (
    EffectFinalizerClientRuntime,
    EffectFinalizerRuntimeError,
)
from .odoo.runner import OdooRunnerError, RuntimeConfig, load_runtime_config
from .operations import canonical_json


class WriteRuntimeError(ValueError):
    """Raised when write runtime configuration or key material is unsafe."""


WRITE_RUNTIME_SCHEMA_VERSION = 2
WRITE_EXECUTION_MODES = frozenset({"disabled", "sandbox_staged", "enabled"})
WRITE_ROLE_NAMES = (
    "write_auth",
    "approval",
    "execution",
    "verification",
    "recovery",
    "write_receipt",
)
ISSUER_ROLE_NAMES = frozenset({"execution", "verification", "recovery"})
WRITE_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "write_execution_mode",
        "base_runtime_config_path",
        "write_state_path",
        "effect_finalizer",
        *WRITE_ROLE_NAMES,
    }
)
EFFECT_FINALIZER_FIELDS = frozenset(
    {
        "socket_path",
        "socket_owner_uid",
        "socket_group_gid",
        "socket_mode",
        "finalizer_service_uid",
        "finalizer_service_gid",
        "finalizer_systemd_unit",
        "attestation_key_id",
        "guard_installation_id",
        "database_oid",
        "handoff_idle_timeout_seconds",
        "request_io_timeout_seconds",
        "max_request_bytes",
        "max_response_bytes",
    }
)
ROLE_FIELDS = frozenset({"key_id", "secret_path"})
ISSUER_ROLE_FIELDS = frozenset({"issuer", "key_id", "secret_path"})
MIN_SECRET_BYTES = 32
MAX_CONFIG_BYTES = 65_536
MAX_SECRET_BYTES = 4_096
SHA256_LENGTH = 64


@dataclass(frozen=True)
class WriteRoleConfig:
    """One fixed purpose-specific key reference, without secret material."""

    key_id: str
    secret_path: Path
    issuer: str | None = None


@dataclass(frozen=True)
class WriteRuntimeSecrets:
    """Validated write secrets whose representation never contains key bytes."""

    write_auth: bytes = field(repr=False)
    approval: bytes = field(repr=False)
    execution: bytes = field(repr=False)
    verification: bytes = field(repr=False)
    recovery: bytes = field(repr=False)
    write_receipt: bytes = field(repr=False)


@dataclass(frozen=True)
class WriteRuntimeConfig:
    """Exact root-managed write configuration bound to one read runtime."""

    schema_version: int
    write_execution_mode: str
    base_runtime_config_path: Path
    write_state_path: Path
    effect_finalizer: EffectFinalizerClientRuntime
    write_auth: WriteRoleConfig
    approval: WriteRoleConfig
    execution: WriteRoleConfig
    verification: WriteRoleConfig
    recovery: WriteRoleConfig
    write_receipt: WriteRoleConfig
    base_runtime: RuntimeConfig = field(repr=False)
    config_fingerprint: str
    _require_root_owner: bool = field(repr=False, compare=False)

    @property
    def runtime_identity(self) -> dict[str, object]:
        return {
            **self.base_runtime.runtime_identity,
            "write_execution_mode": self.write_execution_mode,
            "write_runtime_schema_version": self.schema_version,
            "write_runtime_config_sha256": self.config_fingerprint,
        }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WriteRuntimeError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise WriteRuntimeError(f"non-finite JSON number is forbidden: {value}")


def _effect_finalizer_from_mapping(value: Any) -> EffectFinalizerClientRuntime:
    if not isinstance(value, Mapping) or set(value) != EFFECT_FINALIZER_FIELDS:
        raise WriteRuntimeError("effect finalizer configuration fields are invalid")
    item = dict(value)
    try:
        identity = EffectFinalizationIdentity(
            attestation_key_id=item.pop("attestation_key_id"),
            guard_installation_id=item.pop("guard_installation_id"),
            database_oid=item.pop("database_oid"),
        )
        return EffectFinalizerClientRuntime(
            **item,
            finalization_identity=identity,
        )
    except (
        EffectFinalizationError,
        EffectFinalizerRuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        raise WriteRuntimeError("effect finalizer configuration is invalid") from exc


def _load_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except WriteRuntimeError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise WriteRuntimeError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise WriteRuntimeError(f"{label} must be a JSON object")
    return value


def _strict_text(value: Any, label: str, *, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise WriteRuntimeError(f"{label} is invalid")
    return value


def _absolute_path(value: Any, label: str) -> Path:
    if type(value) is not str or not value or "\x00" in value:
        raise WriteRuntimeError(f"{label} must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise WriteRuntimeError(f"{label} must be an absolute path")
    return path


def _normalized_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _is_canonical(path: Path, *, strict: bool) -> bool:
    try:
        resolved = path.resolve(strict=strict)
    except OSError:
        return False
    return _normalized_path(path) == _normalized_path(resolved)


def _validate_posix_file(
    metadata: os.stat_result,
    label: str,
    *,
    require_root_owner: bool,
) -> None:
    if os.name != "posix":
        return
    mode = stat.S_IMODE(metadata.st_mode)
    if require_root_owner and metadata.st_uid != 0:
        raise WriteRuntimeError(f"{label} must be root-owned")
    if mode not in {0o400, 0o440, 0o600, 0o640}:
        raise WriteRuntimeError(f"{label} has an unsafe POSIX mode")


def _validate_config_parent(path: Path, *, require_root_owner: bool) -> None:
    try:
        parent = path.parent
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or parent.is_symlink()
            or not _is_canonical(parent, strict=True)
        ):
            raise WriteRuntimeError(
                "runtime configuration directory must be canonical and non-symlink"
            )
        if os.name == "posix":
            if require_root_owner and metadata.st_uid != 0:
                raise WriteRuntimeError(
                    "runtime configuration directory must be root-owned"
                )
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise WriteRuntimeError(
                    "runtime configuration directory must not be group/world writable"
                )
    except WriteRuntimeError:
        raise
    except OSError as exc:
        raise WriteRuntimeError("runtime configuration directory is invalid") from exc


def _validate_secret_parent(
    path: Path, label: str, *, require_root_owner: bool
) -> None:
    try:
        parent = path.parent
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or parent.is_symlink()
            or not _is_canonical(parent, strict=True)
        ):
            raise WriteRuntimeError(
                f"{label} parent directory must be canonical and non-symlink"
            )
        if os.name == "posix":
            if require_root_owner and metadata.st_uid != 0:
                raise WriteRuntimeError(f"{label} parent directory must be root-owned")
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                raise WriteRuntimeError(
                    f"{label} parent directory must not be group/world writable"
                )
    except WriteRuntimeError:
        raise
    except OSError as exc:
        raise WriteRuntimeError(f"{label} parent directory is invalid") from exc


def _read_trusted_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    require_root_owner: bool,
    validate_parent: bool,
) -> tuple[bytes, tuple[int, int]]:
    if validate_parent:
        _validate_config_parent(path, require_root_owner=require_root_owner)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or not _is_canonical(path, strict=True)
        ):
            raise WriteRuntimeError(f"{label} must be a regular non-symlink file")
        _validate_posix_file(
            before,
            label,
            require_root_owner=require_root_owner,
        )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise WriteRuntimeError(f"{label} changed while it was opened")
            _validate_posix_file(
                opened,
                label,
                require_root_owner=require_root_owner,
            )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise WriteRuntimeError(f"{label} is too large")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (
            not stat.S_ISREG(after.st_mode)
            or path.is_symlink()
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise WriteRuntimeError(f"{label} changed while it was read")
        _validate_posix_file(
            after,
            label,
            require_root_owner=require_root_owner,
        )
        return b"".join(chunks), (opened.st_dev, opened.st_ino)
    except WriteRuntimeError:
        raise
    except OSError as exc:
        raise WriteRuntimeError(f"{label} cannot be read") from exc


def _read_config(
    path: Path, label: str, *, require_root_owner: bool
) -> tuple[dict[str, Any], bytes]:
    raw, _ = _read_trusted_file(
        path,
        label,
        maximum=MAX_CONFIG_BYTES,
        require_root_owner=require_root_owner,
        validate_parent=True,
    )
    return _load_json_object(raw, label), raw


def _role_from_mapping(name: str, value: Any) -> WriteRoleConfig:
    fields = ISSUER_ROLE_FIELDS if name in ISSUER_ROLE_NAMES else ROLE_FIELDS
    if not isinstance(value, Mapping) or set(value) != fields:
        raise WriteRuntimeError(f"{name} fields are invalid")
    issuer = (
        _strict_text(value["issuer"], f"{name}.issuer")
        if name in ISSUER_ROLE_NAMES
        else None
    )
    return WriteRoleConfig(
        key_id=_strict_text(value["key_id"], f"{name}.key_id"),
        secret_path=_absolute_path(value["secret_path"], f"{name}.secret_path"),
        issuer=issuer,
    )


def _base_runtime_mapping(config: RuntimeConfig) -> dict[str, object]:
    return {
        "instance_id": config.instance_id,
        "environment": config.environment,
        "capability_channel": config.capability_channel,
        "database_name": config.database_name,
        "database_uuid": config.database_uuid,
        "odoo_python": str(config.odoo_python),
        "odoo_python_sha256": config.odoo_python_sha256,
        "odoo_bin": str(config.odoo_bin),
        "odoo_bin_sha256": config.odoo_bin_sha256,
        "odoo_config": str(config.odoo_config),
        "odoo_config_sha256": config.odoo_config_sha256,
        "release_root": str(config.release_root),
        "canonical_package_path": str(config.canonical_package_path),
        "canonical_package_sha256": config.canonical_package_sha256,
        "auth_state_path": str(config.auth_state_path),
        "receipt_state_path": str(config.receipt_state_path),
        "gcov_state_path": str(config.gcov_state_path),
        "auth_key_id": config.auth_key_id,
        "receipt_key_id": config.receipt_key_id,
        "auth_secret_path": str(config.auth_secret_path),
        "receipt_secret_path": str(config.receipt_secret_path),
    }


def _validate_state_path(path: Path, base_runtime: RuntimeConfig) -> None:
    if _normalized_path(path) in {
        _normalized_path(base_runtime.auth_state_path),
        _normalized_path(base_runtime.receipt_state_path),
    }:
        raise WriteRuntimeError("write state path must be distinct from read state paths")
    try:
        parent = path.parent
        parent_metadata = parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent.is_symlink()
            or not _is_canonical(parent, strict=True)
        ):
            raise WriteRuntimeError(
                "write state parent directory must be canonical and non-symlink"
            )
        if os.name == "posix":
            parent_mode = stat.S_IMODE(parent_metadata.st_mode)
            if parent_mode & 0o077:
                raise WriteRuntimeError("write state parent directory must be private")
            if parent_metadata.st_uid not in {0, os.geteuid()}:
                raise WriteRuntimeError("write state parent directory owner is invalid")
        if os.path.lexists(path):
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or path.is_symlink()
                or not _is_canonical(path, strict=True)
            ):
                raise WriteRuntimeError(
                    "write state must be a regular non-symlink file"
                )
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise WriteRuntimeError(
                    "write state must be service-owned with POSIX mode 0600"
                )
    except WriteRuntimeError:
        raise
    except OSError as exc:
        raise WriteRuntimeError("write state path is invalid") from exc


def _state_inode(path: Path) -> tuple[int, int] | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WriteRuntimeError("state path cannot be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise WriteRuntimeError("state path must be a regular non-symlink file")
    return metadata.st_dev, metadata.st_ino


def _validate_state_inode_independence(
    path: Path, base_runtime: RuntimeConfig
) -> None:
    write_inode = _state_inode(path)
    if write_inode is None:
        return
    for read_path in (base_runtime.auth_state_path, base_runtime.receipt_state_path):
        read_inode = _state_inode(read_path)
        if read_inode is not None and write_inode == read_inode:
            raise WriteRuntimeError("write state inode must be distinct from read state")


def _role_configs(config: WriteRuntimeConfig) -> tuple[WriteRoleConfig, ...]:
    return tuple(getattr(config, name) for name in WRITE_ROLE_NAMES)


def _read_all_secrets(
    config: WriteRuntimeConfig,
) -> tuple[WriteRuntimeSecrets, tuple[bytes, bytes]]:
    named_paths = (
        ("base_read_auth", config.base_runtime.auth_secret_path),
        ("base_read_receipt", config.base_runtime.receipt_secret_path),
        *(
            (name, getattr(config, name).secret_path)
            for name in WRITE_ROLE_NAMES
        ),
    )
    materials: dict[str, bytes] = {}
    inodes: dict[str, tuple[int, int]] = {}
    for name, path in named_paths:
        _validate_secret_parent(
            path,
            f"{name}.secret_path",
            require_root_owner=config._require_root_owner,
        )
        secret, inode = _read_trusted_file(
            path,
            f"{name}.secret_path",
            maximum=MAX_SECRET_BYTES,
            require_root_owner=config._require_root_owner,
            validate_parent=False,
        )
        if len(secret) < MIN_SECRET_BYTES:
            raise WriteRuntimeError(
                f"{name}.secret_path must contain at least 32 bytes"
            )
        materials[name] = secret
        inodes[name] = inode
    if len(set(inodes.values())) != len(inodes):
        raise WriteRuntimeError(
            "write and base read secret inodes must be distinct"
        )
    names = tuple(materials)
    for index, left_name in enumerate(names):
        for right_name in names[index + 1 :]:
            if hmac.compare_digest(materials[left_name], materials[right_name]):
                raise WriteRuntimeError(
                    "write and base read secret bytes must be distinct"
                )
    return (
        WriteRuntimeSecrets(
            **{name: materials[name] for name in WRITE_ROLE_NAMES}
        ),
        (materials["base_read_auth"], materials["base_read_receipt"]),
    )


def load_write_runtime_config(
    path: str | os.PathLike[str], *, require_root_owner: bool = True
) -> WriteRuntimeConfig:
    """Load one exact write config and fail closed on any role overlap."""

    if type(require_root_owner) is not bool:
        raise WriteRuntimeError("require_root_owner must be a boolean")
    config_path = Path(path)
    if not config_path.is_absolute():
        raise WriteRuntimeError("write runtime configuration path must be absolute")
    document, _ = _read_config(
        config_path,
        "write runtime configuration",
        require_root_owner=require_root_owner,
    )
    if set(document) != WRITE_CONFIG_FIELDS:
        raise WriteRuntimeError("write runtime configuration fields are invalid")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != WRITE_RUNTIME_SCHEMA_VERSION
    ):
        raise WriteRuntimeError("write runtime schema_version is invalid")
    mode = document["write_execution_mode"]
    if type(mode) is not str or mode not in WRITE_EXECUTION_MODES:
        raise WriteRuntimeError("write_execution_mode is invalid")
    base_path = _absolute_path(
        document["base_runtime_config_path"], "base_runtime_config_path"
    )
    state_path = _absolute_path(document["write_state_path"], "write_state_path")
    effect_finalizer = _effect_finalizer_from_mapping(
        document["effect_finalizer"]
    )
    if _normalized_path(base_path) == _normalized_path(config_path):
        raise WriteRuntimeError("base and write runtime configuration paths must differ")

    base_document, _ = _read_config(
        base_path,
        "base runtime configuration",
        require_root_owner=require_root_owner,
    )
    try:
        base_runtime = load_runtime_config(
            base_path,
            require_root_owner=require_root_owner,
        )
    except OdooRunnerError as exc:
        raise WriteRuntimeError("base runtime configuration is invalid") from exc
    if base_document != _base_runtime_mapping(base_runtime):
        raise WriteRuntimeError("base runtime configuration changed while it was loaded")
    if mode == "sandbox_staged" and (
        base_runtime.environment != "sandbox"
        or base_runtime.capability_channel != "staged"
    ):
        raise WriteRuntimeError(
            "sandbox_staged writes require a staged sandbox base runtime"
        )
    if mode == "enabled" and base_runtime.capability_channel != "enabled":
        raise WriteRuntimeError(
            "enabled writes require an enabled base runtime channel"
        )

    roles = {name: _role_from_mapping(name, document[name]) for name in WRITE_ROLE_NAMES}
    key_ids = (
        base_runtime.auth_key_id,
        base_runtime.receipt_key_id,
        *(roles[name].key_id for name in WRITE_ROLE_NAMES),
    )
    if len(set(key_ids)) != len(key_ids):
        raise WriteRuntimeError("write and base read key IDs must be distinct")
    paths = (
        base_runtime.auth_secret_path,
        base_runtime.receipt_secret_path,
        *(roles[name].secret_path for name in WRITE_ROLE_NAMES),
    )
    if len({_normalized_path(value) for value in paths}) != len(paths):
        raise WriteRuntimeError("write and base read secret paths must be distinct")
    issuers = tuple(roles[name].issuer for name in sorted(ISSUER_ROLE_NAMES))
    if len(set(issuers)) != len(issuers):
        raise WriteRuntimeError("execution, verification, and recovery issuers must be distinct")

    _validate_state_path(state_path, base_runtime)
    _validate_state_inode_independence(state_path, base_runtime)
    fingerprint = hashlib.sha256(
        canonical_json(
            {
                "fingerprint_version": 1,
                "base_runtime_configuration": base_document,
                "write_runtime_configuration": document,
            }
        )
    ).hexdigest()
    if len(fingerprint) != SHA256_LENGTH:  # pragma: no cover - hashlib invariant
        raise WriteRuntimeError("write runtime configuration fingerprint is invalid")
    config = WriteRuntimeConfig(
        schema_version=WRITE_RUNTIME_SCHEMA_VERSION,
        write_execution_mode=mode,
        base_runtime_config_path=base_path,
        write_state_path=state_path,
        effect_finalizer=effect_finalizer,
        base_runtime=base_runtime,
        config_fingerprint=fingerprint,
        _require_root_owner=require_root_owner,
        **roles,
    )
    _read_all_secrets(config)
    return config


def load_write_runtime_secrets(config: WriteRuntimeConfig) -> WriteRuntimeSecrets:
    """Re-read and return six validated role secrets without exposing read keys."""

    if not isinstance(config, WriteRuntimeConfig):
        raise WriteRuntimeError("write runtime configuration is required")
    secrets, _base_secrets = _read_all_secrets(config)
    return secrets


__all__ = [
    "WRITE_CONFIG_FIELDS",
    "WRITE_EXECUTION_MODES",
    "WRITE_RUNTIME_SCHEMA_VERSION",
    "WriteRoleConfig",
    "WriteRuntimeConfig",
    "WriteRuntimeError",
    "WriteRuntimeSecrets",
    "load_write_runtime_config",
    "load_write_runtime_secrets",
]

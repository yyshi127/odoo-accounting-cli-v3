"""Fail-closed runtime configuration and factory for ``TrustedAuthority``.

This module binds the authority to the existing root-managed write key roles
and to a dedicated durable SQLite store.  Identity resolution, operation
resolution, approval policy, and the trusted clock remain explicit process
dependencies; none can be supplied by a Pi request or inferred here.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from .auth import MAX_CONTEXT_TTL
from .operations import Operation, canonical_json
from .trusted_authority import (
    AuthorityError,
    AuthorityKeys,
    TrustedAuthority,
    TrustedSession,
)
from .trusted_authority_sqlite import SQLiteApprovalChallengeStore
from .write_runtime import (
    WRITE_ROLE_NAMES,
    WriteRuntimeConfig,
    WriteRuntimeError,
    _absolute_path,
    _is_canonical,
    _normalized_path,
    _read_config,
    load_write_runtime_config,
    load_write_runtime_secrets,
)


AUTHORITY_RUNTIME_SCHEMA_VERSION = 1
AUTHORITY_RUNTIME_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "write_runtime_config_path",
        "authority_state_path",
        "sqlite_busy_timeout_ms",
        "context_ttl_seconds",
    }
)
MAX_SQLITE_BUSY_TIMEOUT_MS = 60_000


class TrustedAuthorityBootstrapError(ValueError):
    """Authority configuration or construction failed before serving requests."""


@dataclass(frozen=True)
class TrustedAuthorityRuntimeConfig:
    schema_version: int
    config_path: Path
    write_runtime_config_path: Path
    authority_state_path: Path
    sqlite_busy_timeout_ms: int
    context_ttl_seconds: int
    write_runtime: WriteRuntimeConfig = field(repr=False)
    config_fingerprint: str
    _require_root_owner: bool = field(repr=False, compare=False)

    @property
    def runtime_identity(self) -> dict[str, object]:
        return {
            **self.write_runtime.runtime_identity,
            "trusted_authority_runtime_schema_version": self.schema_version,
            "trusted_authority_runtime_config_sha256": self.config_fingerprint,
        }


@dataclass(frozen=True)
class TrustedAuthorityRuntime:
    """Constructed in-process authority and its durable store, without keys."""

    config: TrustedAuthorityRuntimeConfig
    authority: TrustedAuthority = field(repr=False)
    store: SQLiteApprovalChallengeStore = field(repr=False)

    @property
    def runtime_identity(self) -> dict[str, object]:
        return self.config.runtime_identity


def _positive_bounded_integer(
    value: object, label: str, *, maximum: int
) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TrustedAuthorityBootstrapError(f"{label} is invalid")
    return value


def _path_inode(path: Path, label: str) -> tuple[int, int] | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TrustedAuthorityBootstrapError(f"{label} cannot be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise TrustedAuthorityBootstrapError(
            f"{label} must be a regular non-symlink file"
        )
    return metadata.st_dev, metadata.st_ino


def _protected_runtime_paths(
    authority_config_path: Path,
    write_runtime_config_path: Path,
    write_runtime: WriteRuntimeConfig,
) -> tuple[Path, ...]:
    base = write_runtime.base_runtime
    return (
        authority_config_path,
        write_runtime_config_path,
        write_runtime.base_runtime_config_path,
        write_runtime.write_state_path,
        base.auth_state_path,
        base.receipt_state_path,
        base.odoo_python,
        base.odoo_bin,
        base.odoo_config,
        base.canonical_package_path,
        base.auth_secret_path,
        base.receipt_secret_path,
        *(getattr(write_runtime, name).secret_path for name in WRITE_ROLE_NAMES),
    )


def _validate_authority_state_path(
    path: Path,
    *,
    authority_config_path: Path,
    write_runtime_config_path: Path,
    write_runtime: WriteRuntimeConfig,
) -> None:
    protected_paths = _protected_runtime_paths(
        authority_config_path, write_runtime_config_path, write_runtime
    )
    normalized = _normalized_path(path)
    if normalized in {_normalized_path(value) for value in protected_paths}:
        raise TrustedAuthorityBootstrapError(
            "authority state path must be distinct from configuration, secret, and other state paths"
        )
    try:
        parent = path.parent
        parent_metadata = parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent.is_symlink()
            or not _is_canonical(parent, strict=True)
        ):
            raise TrustedAuthorityBootstrapError(
                "authority state parent directory must be canonical and non-symlink"
            )
        if os.name == "posix":
            if stat.S_IMODE(parent_metadata.st_mode) & 0o077:
                raise TrustedAuthorityBootstrapError(
                    "authority state parent directory must be private"
                )
            if parent_metadata.st_uid not in {0, os.geteuid()}:
                raise TrustedAuthorityBootstrapError(
                    "authority state parent directory owner is invalid"
                )
        state_inode = _path_inode(path, "authority state")
        if state_inode is not None:
            metadata = path.lstat()
            if not _is_canonical(path, strict=True):
                raise TrustedAuthorityBootstrapError(
                    "authority state path must be canonical"
                )
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise TrustedAuthorityBootstrapError(
                    "authority state must be service-owned with POSIX mode 0600"
                )
            for protected in protected_paths:
                protected_inode = _path_inode(protected, "protected runtime file")
                if protected_inode is not None and protected_inode == state_inode:
                    raise TrustedAuthorityBootstrapError(
                        "authority state inode must be distinct from configuration, secret, and other state inodes"
                    )
        elif not _is_canonical(path, strict=False):
            raise TrustedAuthorityBootstrapError(
                "authority state path must be canonical"
            )
    except TrustedAuthorityBootstrapError:
        raise
    except OSError as exc:
        raise TrustedAuthorityBootstrapError(
            "authority state path is invalid"
        ) from exc


def load_trusted_authority_runtime_config(
    path: str | os.PathLike[str], *, require_root_owner: bool = True
) -> TrustedAuthorityRuntimeConfig:
    """Load the exact root-managed authority configuration without key bytes."""

    if type(require_root_owner) is not bool:
        raise TrustedAuthorityBootstrapError(
            "require_root_owner must be a boolean"
        )
    config_path = Path(path)
    if not config_path.is_absolute():
        raise TrustedAuthorityBootstrapError(
            "trusted authority runtime configuration path must be absolute"
        )
    try:
        document, _raw = _read_config(
            config_path,
            "trusted authority runtime configuration",
            require_root_owner=require_root_owner,
        )
    except WriteRuntimeError as exc:
        raise TrustedAuthorityBootstrapError(str(exc)) from exc
    if set(document) != AUTHORITY_RUNTIME_CONFIG_FIELDS:
        raise TrustedAuthorityBootstrapError(
            "trusted authority runtime configuration fields are invalid"
        )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != AUTHORITY_RUNTIME_SCHEMA_VERSION
    ):
        raise TrustedAuthorityBootstrapError(
            "trusted authority runtime schema_version is invalid"
        )
    try:
        write_runtime_path = _absolute_path(
            document["write_runtime_config_path"],
            "write_runtime_config_path",
        )
        authority_state_path = _absolute_path(
            document["authority_state_path"], "authority_state_path"
        )
    except WriteRuntimeError as exc:
        raise TrustedAuthorityBootstrapError(str(exc)) from exc
    if _normalized_path(config_path) == _normalized_path(write_runtime_path):
        raise TrustedAuthorityBootstrapError(
            "authority and write runtime configuration paths must be distinct"
        )
    busy_timeout_ms = _positive_bounded_integer(
        document["sqlite_busy_timeout_ms"],
        "SQLite busy timeout",
        maximum=MAX_SQLITE_BUSY_TIMEOUT_MS,
    )
    context_ttl_seconds = _positive_bounded_integer(
        document["context_ttl_seconds"],
        "write context TTL",
        maximum=int(MAX_CONTEXT_TTL.total_seconds()),
    )
    try:
        write_runtime = load_write_runtime_config(
            write_runtime_path, require_root_owner=require_root_owner
        )
    except WriteRuntimeError as exc:
        raise TrustedAuthorityBootstrapError(
            "trusted authority write runtime configuration was rejected"
        ) from exc
    _validate_authority_state_path(
        authority_state_path,
        authority_config_path=config_path,
        write_runtime_config_path=write_runtime_path,
        write_runtime=write_runtime,
    )
    fingerprint = hashlib.sha256(
        canonical_json(
            {
                "fingerprint_version": 1,
                "trusted_authority_runtime_configuration": document,
                "write_runtime_configuration_sha256": write_runtime.config_fingerprint,
            }
        )
    ).hexdigest()
    return TrustedAuthorityRuntimeConfig(
        schema_version=AUTHORITY_RUNTIME_SCHEMA_VERSION,
        config_path=config_path,
        write_runtime_config_path=write_runtime_path,
        authority_state_path=authority_state_path,
        sqlite_busy_timeout_ms=busy_timeout_ms,
        context_ttl_seconds=context_ttl_seconds,
        write_runtime=write_runtime,
        config_fingerprint=fingerprint,
        _require_root_owner=require_root_owner,
    )


def build_trusted_authority(
    path: str | os.PathLike[str],
    *,
    session_resolver: Callable[[str], TrustedSession | None],
    operation_resolver: Callable[[str], Operation | None],
    approver_authorizer: Callable[[TrustedSession, Operation], bool],
    approval_ttl_resolver: Callable[[Operation], int],
    clock: Callable[[], datetime],
    require_root_owner: bool = True,
) -> TrustedAuthorityRuntime:
    """Build one durable authority; storage and key failures have no fallback."""

    dependencies = (
        session_resolver,
        operation_resolver,
        approver_authorizer,
        approval_ttl_resolver,
        clock,
    )
    if any(not callable(dependency) for dependency in dependencies):
        raise TrustedAuthorityBootstrapError(
            "trusted authority external dependencies must be callable"
        )
    config = load_trusted_authority_runtime_config(
        path, require_root_owner=require_root_owner
    )
    try:
        secrets = load_write_runtime_secrets(config.write_runtime)
    except WriteRuntimeError as exc:
        raise TrustedAuthorityBootstrapError(
            "trusted authority secrets rejected"
        ) from exc
    try:
        keys = AuthorityKeys(
            context_key_id=config.write_runtime.write_auth.key_id,
            context_secret=secrets.write_auth,
            approval_key_id=config.write_runtime.approval.key_id,
            approval_secret=secrets.approval,
        )
    except AuthorityError as exc:
        raise TrustedAuthorityBootstrapError(
            "trusted authority key bindings were rejected"
        ) from exc
    try:
        store = SQLiteApprovalChallengeStore(
            config.authority_state_path,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        )
    except AuthorityError as exc:
        raise TrustedAuthorityBootstrapError(
            "trusted authority state store rejected"
        ) from exc
    try:
        authority = TrustedAuthority(
            session_resolver=session_resolver,
            operation_resolver=operation_resolver,
            approver_authorizer=approver_authorizer,
            approval_ttl_resolver=approval_ttl_resolver,
            keys=keys,
            store=store,
            clock=clock,
            context_ttl_seconds=config.context_ttl_seconds,
        )
    except AuthorityError as exc:
        raise TrustedAuthorityBootstrapError(
            "trusted authority construction was rejected"
        ) from exc
    return TrustedAuthorityRuntime(config=config, authority=authority, store=store)


__all__ = [
    "AUTHORITY_RUNTIME_CONFIG_FIELDS",
    "AUTHORITY_RUNTIME_SCHEMA_VERSION",
    "MAX_SQLITE_BUSY_TIMEOUT_MS",
    "TrustedAuthorityBootstrapError",
    "TrustedAuthorityRuntime",
    "TrustedAuthorityRuntimeConfig",
    "build_trusted_authority",
    "load_trusted_authority_runtime_config",
]

"""Root-managed runtime configuration for the isolated finalizer service."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .effect_finalizer import (
    EffectFinalizationError,
    EffectFinalizationIdentity,
)
from .odoo.effect_finalizer_db import (
    EffectFinalizerDatabaseConfig,
    EffectFinalizerDatabaseError,
    preflight_effect_finalizer_database_config,
)
from .operations import canonical_json


class EffectFinalizerRuntimeError(ValueError):
    """The finalizer service configuration or HMAC credential is unsafe."""


EFFECT_FINALIZER_RUNTIME_SCHEMA_VERSION = 2
EFFECT_FINALIZER_DEPENDENCY_MANIFEST_PATH = Path(
    "/etc/odoo-accounting-cli-v3/effect-finalizer-runtime-manifest.json"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UNIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service\Z")
_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "service_uid",
        "service_gid",
        "database_name",
        "database_uuid",
        "database_user",
        "database_host",
        "database_port",
        "database_connect_timeout_seconds",
        "dependency_manifest_path",
        "dependency_manifest_sha256",
        "pgpass_path",
        "attestation_key_id",
        "expected_guard_installation_id",
        "expected_database_oid",
        "attestation_secret_path",
        "journal_path",
        "proof_ttl_seconds",
        "statement_timeout_ms",
        "uds",
    }
)
_UDS_FIELDS = frozenset(
    {
        "socket_path",
        "socket_owner_uid",
        "socket_group_gid",
        "socket_mode",
        "broker_service_uid",
        "broker_systemd_unit",
        "finalizer_systemd_unit",
        "handoff_idle_timeout_seconds",
        "request_io_timeout_seconds",
        "max_request_bytes",
        "max_response_bytes",
        "max_inflight_requests",
    }
)
_MAX_CONFIG_BYTES = 65_536
_MAX_SECRET_BYTES = 4096
_MAX_DEPENDENCY_MANIFEST_BYTES = 4 * 1024 * 1024
_DATABASE_RESPONSE_COMMIT_MARGIN_MS = 1000


def _strict_text(value: Any, label: str, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise EffectFinalizerRuntimeError(f"{label} is invalid")
    return value


def _absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise EffectFinalizerRuntimeError(f"{label} is invalid")
    path = Path(value)
    if not path.is_absolute():
        raise EffectFinalizerRuntimeError(f"{label} must be absolute")
    return path


def _identity(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > 2**31 - 1
    ):
        raise EffectFinalizerRuntimeError(f"{label} is invalid")
    return value


@dataclass(frozen=True)
class EffectFinalizerUdsConfig:
    socket_path: str
    socket_owner_uid: int
    socket_group_gid: int
    socket_mode: int
    broker_service_uid: int
    broker_systemd_unit: str
    finalizer_systemd_unit: str
    handoff_idle_timeout_seconds: float
    request_io_timeout_seconds: float
    max_request_bytes: int
    max_response_bytes: int
    max_inflight_requests: int

    def __post_init__(self) -> None:
        parsed = PurePosixPath(self.socket_path) if isinstance(self.socket_path, str) else None
        if (
            parsed is None
            or not parsed.is_absolute()
            or str(parsed) != self.socket_path
            or self.socket_path.startswith("//")
            or any(part in {".", ".."} for part in parsed.parts)
            or _identity(self.socket_owner_uid, "socket owner UID", allow_zero=True)
            != self.socket_owner_uid
            or _identity(self.socket_group_gid, "socket group GID")
            != self.socket_group_gid
            or _identity(self.broker_service_uid, "broker service UID")
            != self.broker_service_uid
            or isinstance(self.socket_mode, bool)
            or not isinstance(self.socket_mode, int)
            or self.socket_mode & ~0o777
            or self.socket_mode & 0o007
            or self.socket_mode & 0o600 != 0o600
            or not isinstance(self.broker_systemd_unit, str)
            or _UNIT_NAME.fullmatch(self.broker_systemd_unit) is None
            or not isinstance(self.finalizer_systemd_unit, str)
            or _UNIT_NAME.fullmatch(self.finalizer_systemd_unit) is None
            or self.broker_systemd_unit == self.finalizer_systemd_unit
            or isinstance(self.handoff_idle_timeout_seconds, bool)
            or not isinstance(self.handoff_idle_timeout_seconds, (int, float))
            or not 90.0 <= float(self.handoff_idle_timeout_seconds) <= 120.0
            or isinstance(self.request_io_timeout_seconds, bool)
            or not isinstance(self.request_io_timeout_seconds, (int, float))
            or not 0.05 <= float(self.request_io_timeout_seconds) <= 30.0
            or isinstance(self.max_request_bytes, bool)
            or not isinstance(self.max_request_bytes, int)
            or not 1024 <= self.max_request_bytes <= 65_536
            or isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1024 <= self.max_response_bytes <= 65_536
            or isinstance(self.max_inflight_requests, bool)
            or not isinstance(self.max_inflight_requests, int)
            or not 1 <= self.max_inflight_requests <= 16
        ):
            raise EffectFinalizerRuntimeError(
                "effect finalizer UDS configuration is invalid"
            )


@dataclass(frozen=True)
class EffectFinalizerClientRuntime:
    """Secret-free values the broker main adapter may consume."""

    socket_path: str
    socket_owner_uid: int
    socket_group_gid: int
    socket_mode: int
    finalizer_service_uid: int
    finalizer_service_gid: int
    finalizer_systemd_unit: str
    finalization_identity: EffectFinalizationIdentity
    handoff_idle_timeout_seconds: float
    request_io_timeout_seconds: float
    max_request_bytes: int
    max_response_bytes: int

    def __post_init__(self) -> None:
        parsed = (
            PurePosixPath(self.socket_path)
            if isinstance(self.socket_path, str)
            else None
        )
        if (
            parsed is None
            or not parsed.is_absolute()
            or str(parsed) != self.socket_path
            or self.socket_path.startswith("//")
            or any(part in {".", ".."} for part in parsed.parts)
            or _identity(
                self.socket_owner_uid, "socket owner UID", allow_zero=True
            )
            != self.socket_owner_uid
            or _identity(self.socket_group_gid, "socket group GID")
            != self.socket_group_gid
            or isinstance(self.socket_mode, bool)
            or not isinstance(self.socket_mode, int)
            or self.socket_mode & ~0o777
            or self.socket_mode & 0o007
            or self.socket_mode & 0o600 != 0o600
            or _identity(self.finalizer_service_uid, "finalizer service UID")
            != self.finalizer_service_uid
            or _identity(self.finalizer_service_gid, "finalizer service GID")
            != self.finalizer_service_gid
            or not isinstance(self.finalizer_systemd_unit, str)
            or _UNIT_NAME.fullmatch(self.finalizer_systemd_unit) is None
            or not isinstance(
                self.finalization_identity, EffectFinalizationIdentity
            )
            or isinstance(self.handoff_idle_timeout_seconds, bool)
            or not isinstance(self.handoff_idle_timeout_seconds, (int, float))
            or not 90.0 <= float(self.handoff_idle_timeout_seconds) <= 120.0
            or isinstance(self.request_io_timeout_seconds, bool)
            or not isinstance(self.request_io_timeout_seconds, (int, float))
            or not 0.05 <= float(self.request_io_timeout_seconds) <= 30.0
            or isinstance(self.max_request_bytes, bool)
            or not isinstance(self.max_request_bytes, int)
            or not 1024 <= self.max_request_bytes <= 65_536
            or isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1024 <= self.max_response_bytes <= 65_536
        ):
            raise EffectFinalizerRuntimeError(
                "effect finalizer client runtime is invalid"
            )
        object.__setattr__(
            self,
            "handoff_idle_timeout_seconds",
            float(self.handoff_idle_timeout_seconds),
        )
        object.__setattr__(
            self,
            "request_io_timeout_seconds",
            float(self.request_io_timeout_seconds),
        )

    @property
    def attestation_key_id(self) -> str:
        return self.finalization_identity.attestation_key_id


@dataclass(frozen=True)
class EffectFinalizerRuntimeConfig:
    schema_version: int
    service_uid: int
    service_gid: int
    dependency_manifest_path: Path
    dependency_manifest_sha256: str
    finalization_identity: EffectFinalizationIdentity
    attestation_secret_path: Path
    journal_path: Path
    proof_ttl_seconds: int
    database: EffectFinalizerDatabaseConfig
    uds: EffectFinalizerUdsConfig
    config_fingerprint: str
    require_posix_owner: bool = field(repr=False, compare=False)

    @property
    def attestation_key_id(self) -> str:
        return self.finalization_identity.attestation_key_id

    @property
    def client_runtime(self) -> EffectFinalizerClientRuntime:
        return EffectFinalizerClientRuntime(
            socket_path=self.uds.socket_path,
            socket_owner_uid=self.uds.socket_owner_uid,
            socket_group_gid=self.uds.socket_group_gid,
            socket_mode=self.uds.socket_mode,
            finalizer_service_uid=self.service_uid,
            finalizer_service_gid=self.service_gid,
            finalizer_systemd_unit=self.uds.finalizer_systemd_unit,
            finalization_identity=self.finalization_identity,
            handoff_idle_timeout_seconds=float(
                self.uds.handoff_idle_timeout_seconds
            ),
            request_io_timeout_seconds=float(
                self.uds.request_io_timeout_seconds
            ),
            max_request_bytes=self.uds.max_request_bytes,
            max_response_bytes=self.uds.max_response_bytes,
        )


@dataclass(frozen=True)
class EffectFinalizerRuntimeSecrets:
    attestation_secret: bytes = field(repr=False)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EffectFinalizerRuntimeError("runtime JSON contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise EffectFinalizerRuntimeError("runtime JSON contains a non-finite number")


def _secure_regular_file(
    path: Path,
    *,
    label: str,
    maximum: int,
    require_root_owner: bool,
    allowed_owners: frozenset[int],
    allowed_posix_modes: frozenset[int] | None = None,
) -> bytes:
    try:
        parent = path.parent
        current = parent
        parent_metadata = None
        while True:
            ancestor_metadata = current.lstat()
            if (
                not stat.S_ISDIR(ancestor_metadata.st_mode)
                or current.is_symlink()
                or current.resolve(strict=True) != current
                or (
                    os.name == "posix"
                    and require_root_owner
                    and (
                        ancestor_metadata.st_uid != 0
                        or stat.S_IMODE(ancestor_metadata.st_mode) & 0o022
                    )
                )
            ):
                raise EffectFinalizerRuntimeError(f"{label} is unsafe")
            if current == parent:
                parent_metadata = ancestor_metadata
            if current.parent == current:
                break
            current = current.parent
        if parent_metadata is None:
            raise EffectFinalizerRuntimeError(f"{label} is unsafe")
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent.is_symlink()
            or parent.resolve(strict=True) != parent
            or not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or path.resolve(strict=True) != path
        ):
            raise EffectFinalizerRuntimeError(f"{label} is unsafe")
        if os.name == "posix" and require_root_owner:
            if (
                parent_metadata.st_uid != 0
                or stat.S_IMODE(parent_metadata.st_mode) & 0o022
                or metadata.st_uid not in allowed_owners
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise EffectFinalizerRuntimeError(f"{label} is unsafe")
        if (
            os.name == "posix"
            and allowed_posix_modes is not None
            and stat.S_IMODE(metadata.st_mode) not in allowed_posix_modes
        ):
            raise EffectFinalizerRuntimeError(f"{label} is unsafe")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise EffectFinalizerRuntimeError(f"{label} changed while opened")
            chunks = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(4096, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise EffectFinalizerRuntimeError(f"{label} is too large")
        finally:
            os.close(descriptor)
        return b"".join(chunks)
    except EffectFinalizerRuntimeError:
        raise
    except OSError as exc:
        raise EffectFinalizerRuntimeError(f"{label} is unavailable") from exc


def _load_document(path: Path, *, require_root_owner: bool) -> tuple[dict[str, Any], bytes]:
    raw = _secure_regular_file(
        path,
        label="effect finalizer runtime configuration",
        maximum=_MAX_CONFIG_BYTES,
        require_root_owner=require_root_owner,
        allowed_owners=frozenset({0}),
    )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except EffectFinalizerRuntimeError:
        raise
    except (ValueError, UnicodeError) as exc:
        raise EffectFinalizerRuntimeError(
            "effect finalizer runtime configuration is invalid"
        ) from exc
    if not isinstance(value, dict):
        raise EffectFinalizerRuntimeError(
            "effect finalizer runtime configuration must be an object"
        )
    return value, raw


def _uds_from_mapping(value: Any) -> EffectFinalizerUdsConfig:
    if not isinstance(value, Mapping) or set(value) != _UDS_FIELDS:
        raise EffectFinalizerRuntimeError("effect finalizer UDS fields are invalid")
    try:
        return EffectFinalizerUdsConfig(**dict(value))
    except TypeError as exc:
        raise EffectFinalizerRuntimeError(
            "effect finalizer UDS configuration is invalid"
        ) from exc


def load_effect_finalizer_runtime_config(
    path: str | os.PathLike[str], *, require_root_owner: bool = True
) -> EffectFinalizerRuntimeConfig:
    if type(require_root_owner) is not bool:
        raise EffectFinalizerRuntimeError("runtime owner policy is invalid")
    config_path = Path(path)
    if not config_path.is_absolute():
        raise EffectFinalizerRuntimeError("runtime configuration path must be absolute")
    document, raw = _load_document(
        config_path, require_root_owner=require_root_owner
    )
    if (
        type(document.get("schema_version")) is not int
        or document.get("schema_version")
        != EFFECT_FINALIZER_RUNTIME_SCHEMA_VERSION
    ):
        raise EffectFinalizerRuntimeError(
            "effect finalizer runtime schema version is invalid"
        )
    if set(document) != _CONFIG_FIELDS:
        raise EffectFinalizerRuntimeError(
            "effect finalizer runtime configuration fields are invalid"
        )
    service_uid = _identity(document["service_uid"], "finalizer service UID")
    service_gid = _identity(document["service_gid"], "finalizer service GID")
    uds = _uds_from_mapping(document["uds"])
    if service_uid == uds.broker_service_uid:
        raise EffectFinalizerRuntimeError(
            "broker and finalizer service UIDs must be distinct"
        )
    if service_gid == uds.socket_group_gid:
        raise EffectFinalizerRuntimeError(
            "finalizer service and broker socket GIDs must be distinct"
        )
    secret_path = _absolute_path(
        document["attestation_secret_path"], "attestation secret path"
    )
    dependency_manifest_path = _absolute_path(
        document["dependency_manifest_path"], "dependency manifest path"
    )
    if (
        require_root_owner
        and dependency_manifest_path
        != EFFECT_FINALIZER_DEPENDENCY_MANIFEST_PATH
    ):
        raise EffectFinalizerRuntimeError(
            "dependency manifest path differs from the production path"
        )
    dependency_manifest_sha256 = document["dependency_manifest_sha256"]
    if (
        not isinstance(dependency_manifest_sha256, str)
        or _SHA256.fullmatch(dependency_manifest_sha256) is None
    ):
        raise EffectFinalizerRuntimeError("dependency manifest digest is invalid")
    dependency_manifest = _secure_regular_file(
        dependency_manifest_path,
        label="effect finalizer dependency manifest",
        maximum=_MAX_DEPENDENCY_MANIFEST_BYTES,
        require_root_owner=require_root_owner,
        allowed_owners=frozenset({0}),
        allowed_posix_modes=frozenset({0o444}),
    )
    if hashlib.sha256(dependency_manifest).hexdigest() != dependency_manifest_sha256:
        raise EffectFinalizerRuntimeError("dependency manifest digest differs")
    pgpass_path = _absolute_path(document["pgpass_path"], "pgpass path")
    journal_path = _absolute_path(document["journal_path"], "journal path")
    paths = {
        os.path.normcase(os.path.abspath(value))
        for value in (
            config_path,
            dependency_manifest_path,
            secret_path,
            pgpass_path,
            journal_path,
        )
    }
    if len(paths) != 5:
        raise EffectFinalizerRuntimeError("finalizer runtime paths must be distinct")
    proof_ttl = document["proof_ttl_seconds"]
    if (
        isinstance(proof_ttl, bool)
        or not isinstance(proof_ttl, int)
        or not 1 <= proof_ttl <= 300
    ):
        raise EffectFinalizerRuntimeError("finalizer proof TTL is invalid")
    key_id = _strict_text(document["attestation_key_id"], "attestation key ID")
    try:
        finalization_identity = EffectFinalizationIdentity(
            attestation_key_id=key_id,
            guard_installation_id=document["expected_guard_installation_id"],
            database_oid=document["expected_database_oid"],
        )
    except EffectFinalizationError as exc:
        raise EffectFinalizerRuntimeError(
            "effect finalizer identity is invalid"
        ) from exc
    try:
        database = EffectFinalizerDatabaseConfig(
            database_name=document["database_name"],
            database_uuid=document["database_uuid"],
            database_user=document["database_user"],
            expected_guard_installation_id=(
                finalization_identity.guard_installation_id
            ),
            expected_database_oid=finalization_identity.database_oid,
            host=document["database_host"],
            port=document["database_port"],
            passfile_path=pgpass_path,
            connect_timeout_seconds=document[
                "database_connect_timeout_seconds"
            ],
            statement_timeout_ms=document["statement_timeout_ms"],
            require_posix_owner=require_root_owner,
        )
    except EffectFinalizerDatabaseError as exc:
        raise EffectFinalizerRuntimeError(
            "effect finalizer database configuration is invalid"
        ) from exc
    database_attempt_budget_ms = (
        database.connect_timeout_seconds * 1000
        + database.statement_timeout_ms
        + _DATABASE_RESPONSE_COMMIT_MARGIN_MS
    )
    if (
        database_attempt_budget_ms
        >= uds.request_io_timeout_seconds * 1000
        or proof_ttl * 1000 <= database_attempt_budget_ms
    ):
        raise EffectFinalizerRuntimeError(
            "finalizer timeouts cannot cover one database attempt"
        )
    fingerprint = hashlib.sha256(canonical_json(document)).hexdigest()
    config = EffectFinalizerRuntimeConfig(
        schema_version=EFFECT_FINALIZER_RUNTIME_SCHEMA_VERSION,
        service_uid=service_uid,
        service_gid=service_gid,
        dependency_manifest_path=dependency_manifest_path,
        dependency_manifest_sha256=dependency_manifest_sha256,
        finalization_identity=finalization_identity,
        attestation_secret_path=secret_path,
        journal_path=journal_path,
        proof_ttl_seconds=proof_ttl,
        database=database,
        uds=uds,
        config_fingerprint=fingerprint,
        require_posix_owner=require_root_owner,
    )
    return config


def load_effect_finalizer_runtime_secrets(
    config: EffectFinalizerRuntimeConfig,
) -> EffectFinalizerRuntimeSecrets:
    if not isinstance(config, EffectFinalizerRuntimeConfig):
        raise EffectFinalizerRuntimeError("effect finalizer runtime is invalid")
    secret = _secure_regular_file(
        config.attestation_secret_path,
        label="effect finalizer HMAC credential",
        maximum=_MAX_SECRET_BYTES,
        require_root_owner=config.require_posix_owner,
        allowed_owners=frozenset({0, config.service_uid}),
        allowed_posix_modes=frozenset({0o400, 0o600}),
    )
    if len(secret) < 32:
        raise EffectFinalizerRuntimeError(
            "effect finalizer HMAC credential is too short"
        )
    # The DB adapter performs the exact one-entry pgpass content check.  This
    # preflight only proves the two credential files cannot be the same inode.
    try:
        hmac_metadata = config.attestation_secret_path.stat()
        pgpass_metadata = config.database.passfile_path.stat()
    except OSError as exc:
        raise EffectFinalizerRuntimeError(
            "effect finalizer credentials are unavailable"
        ) from exc
    if (hmac_metadata.st_dev, hmac_metadata.st_ino) == (
        pgpass_metadata.st_dev,
        pgpass_metadata.st_ino,
    ):
        raise EffectFinalizerRuntimeError(
            "effect finalizer credential inodes must be distinct"
        )
    return EffectFinalizerRuntimeSecrets(attestation_secret=secret)


def preflight_effect_finalizer_runtime_credentials(
    config: EffectFinalizerRuntimeConfig,
) -> EffectFinalizerRuntimeSecrets:
    """Read credentials only after the external Python runtime was verified."""

    if not isinstance(config, EffectFinalizerRuntimeConfig):
        raise EffectFinalizerRuntimeError("effect finalizer runtime is invalid")
    try:
        preflight_effect_finalizer_database_config(config.database)
    except EffectFinalizerDatabaseError as exc:
        raise EffectFinalizerRuntimeError(
            "effect finalizer pgpass preflight failed"
        ) from exc
    return load_effect_finalizer_runtime_secrets(config)


__all__ = [
    "EFFECT_FINALIZER_RUNTIME_SCHEMA_VERSION",
    "EFFECT_FINALIZER_DEPENDENCY_MANIFEST_PATH",
    "EffectFinalizerClientRuntime",
    "EffectFinalizerRuntimeConfig",
    "EffectFinalizerRuntimeError",
    "EffectFinalizerRuntimeSecrets",
    "EffectFinalizerUdsConfig",
    "load_effect_finalizer_runtime_config",
    "load_effect_finalizer_runtime_secrets",
    "preflight_effect_finalizer_runtime_credentials",
]

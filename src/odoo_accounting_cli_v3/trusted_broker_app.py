"""Fail-closed production composition for the trusted accounting broker."""

from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from . import __version__
from .broker_audit import SQLiteBrokerAuditSink
from .effect_finalizer_runtime import EffectFinalizerClientRuntime
from .effect_finalizer_uds import preconnect_effect_finalizer_socket
from .historical_router import (
    HistoricalReleaseRouter,
    HistoricalRoutingManifest,
    _read_trusted_file as _read_historical_file,
    load_historical_routing_manifest,
)
from .odoo.runner import RuntimeConfig
from .odoo_approver_authorizer import (
    OdooApproverAuthorizer,
    OdooApproverReleaseRuntime,
)
from .persistence import OperationNotFound, SQLitePersistence
from .operations import canonical_json
from .trusted_authority import TrustedSession
from .trusted_authority_bootstrap import (
    TrustedAuthorityRuntime,
    TrustedAuthorityRuntimeConfig,
    build_trusted_authority,
    load_trusted_authority_runtime_config,
)
from .trusted_approval_uds import TrustedApprovalUdsConfig
from .trusted_broker import ReleaseAuthority, TrustedBroker
from .trusted_broker_uds import (
    BrokerDispatchRequest,
    BrokerDispatchResult,
    TrustedBrokerUdsConfig,
)
from .trusted_idempotency import (
    SQLitePrepareIdempotencyResolver,
    SQLiteRecoveryIdempotencyResolver,
)
from .trusted_read import TrustedReadAdapter
from .trusted_result_delivery import (
    ResultDeliveryRoute,
    TrustedResultDeliveryResolver,
)
from .trusted_response_verifier import (
    ReleaseReceiptVerificationConfig,
    build_release_response_verifier_resolver,
)
from .trusted_session_mint_uds import TrustedSessionMintUdsConfig
from .trusted_session_sqlite import SQLiteTrustedSessionStore
from .verified_release import VerifiedReleaseRoute, load_verified_release_route
from .write_app import (
    MIN_ODOO_CALL_TIMEOUT_SECONDS,
    ODOO_WRITE_TIMEOUT_SECONDS,
    POST_ODOO_LOCAL_MARGIN_SECONDS,
)
from .write_runtime import WriteRuntimeError, _absolute_path, _read_config


BROKER_RUNTIME_SCHEMA_VERSION = 1
MAX_SQLITE_BUSY_TIMEOUT_MS = 1_000
_PI_SQLITE_PHASES = 3
_APPROVAL_FIXED_SQLITE_PHASES = 6
_PI_DEADLINE_MARGIN_SECONDS = 5.0
_MINT_DEADLINE_MARGIN_SECONDS = 1.0
_APPROVAL_DEADLINE_MARGIN_SECONDS = 2.0
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "broker_service_uid",
        "broker_service_gid",
        "current_release_digest",
        "current_registry_digest",
        "historical_routing_manifest_path",
        "historical_routing_manifest_sha256",
        "read_runtime_config_path",
        "read_runtime_config_sha256",
        "shared_write_state_path",
        "trusted_session_state_path",
        "broker_audit_state_path",
        "sqlite_busy_timeout_ms",
        "read_context_ttl_seconds",
        "read_timeout_seconds",
        "historical_timeout_seconds",
        "historical_max_stdin_bytes",
        "historical_max_stdout_bytes",
        "historical_max_stderr_bytes",
        "approver_context_ttl_seconds",
        "approver_timeout_seconds",
        "release_routes",
        "pi_broker_uds",
        "session_mint_uds",
        "trusted_approval_uds",
    }
)
_ROUTE_FIELDS = frozenset(
    {
        "release_digest",
        "registry_digest",
        "authority_runtime_config_path",
        "authority_runtime_config_sha256",
    }
)
_BROKER_UDS_FIELDS = frozenset(
    {
        "socket_path",
        "allowed_client_uid",
        "socket_group_gid",
        "socket_mode",
        "max_body_bytes",
        "max_response_bytes",
        "max_header_bytes",
        "max_header_count",
        "max_inflight_requests",
        "request_timeout_seconds",
    }
)
_MINT_UDS_FIELDS = frozenset(
    {
        "socket_path",
        "odoo_issuer_uid",
        "pi_bridge_uid",
        "socket_group_gid",
        "session_ttl_seconds",
        "session_max_uses",
        "socket_mode",
        "max_body_bytes",
        "max_response_bytes",
        "max_header_bytes",
        "max_header_count",
        "max_inflight_requests",
        "request_timeout_seconds",
    }
)
_APPROVAL_UDS_FIELDS = frozenset(
    {
        "socket_path",
        "odoo_client_uid",
        "pi_bridge_uid",
        "socket_group_gid",
        "socket_mode",
        "max_body_bytes",
        "max_response_bytes",
        "max_header_bytes",
        "max_header_count",
        "max_inflight_broker_calls",
        "request_timeout_seconds",
    }
)


class TrustedBrokerRuntimeError(ValueError):
    """The production composition snapshot or topology was rejected."""


@dataclass(frozen=True, slots=True)
class ReleaseRouteRuntimeConfig:
    release_digest: str
    registry_digest: str
    authority_runtime_config_path: Path
    authority_runtime_config_sha256: str


@dataclass(frozen=True, slots=True)
class TrustedBrokerRuntimeConfig:
    schema_version: int
    config_path: Path
    broker_service_uid: int
    broker_service_gid: int
    current_release_digest: str
    current_registry_digest: str
    historical_routing_manifest_path: Path
    historical_routing_manifest_sha256: str
    read_runtime_config_path: Path
    read_runtime_config_sha256: str
    shared_write_state_path: Path
    trusted_session_state_path: Path
    broker_audit_state_path: Path
    sqlite_busy_timeout_ms: int
    read_context_ttl_seconds: int
    read_timeout_seconds: float
    historical_timeout_seconds: float
    historical_max_stdin_bytes: int
    historical_max_stdout_bytes: int
    historical_max_stderr_bytes: int
    approver_context_ttl_seconds: int
    approver_timeout_seconds: float
    release_routes: tuple[ReleaseRouteRuntimeConfig, ...]
    pi_broker_uds: TrustedBrokerUdsConfig
    session_mint_uds: TrustedSessionMintUdsConfig
    trusted_approval_uds: TrustedApprovalUdsConfig
    config_fingerprint: str
    _require_root_owner: bool = field(repr=False, compare=False)

    @property
    def route_identities(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (route.release_digest, route.registry_digest)
            for route in self.release_routes
        )


@dataclass(frozen=True, slots=True)
class LoadedReleaseTopology:
    manifest: HistoricalRoutingManifest
    authority_configs: tuple[TrustedAuthorityRuntimeConfig, ...]
    releases: tuple[VerifiedReleaseRoute, ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class TrustedBrokerRuntime:
    """Fully preflighted in-process dependencies for all three transports."""

    config: TrustedBrokerRuntimeConfig
    topology: LoadedReleaseTopology
    operation_store: SQLitePersistence = field(repr=False)
    read_result_store: SQLitePersistence = field(repr=False)
    session_store: SQLiteTrustedSessionStore = field(repr=False)
    audit_sink: SQLiteBrokerAuditSink = field(repr=False)
    authorities: tuple[TrustedAuthorityRuntime, ...] = field(repr=False)
    historical_router: HistoricalReleaseRouter = field(repr=False)
    read_adapter: TrustedReadAdapter = field(repr=False)
    result_delivery_resolver: TrustedResultDeliveryResolver = field(
        repr=False
    )
    broker: TrustedBroker = field(repr=False)

    def dispatch_pi(self, request: BrokerDispatchRequest) -> BrokerDispatchResult:
        if not isinstance(request, BrokerDispatchRequest):
            raise TrustedBrokerRuntimeError("Pi dispatch request is invalid")
        result = self.broker.dispatch(
            action=request.action,
            payload=request.payload,
            session_handle=request.session_handle,
            expected_release_digest=request.release_digest,
            expected_registry_digest=request.registry_digest,
            deadline_monotonic=request.deadline_monotonic,
            peer_uid=request.peer_uid,
            peer_gid=request.observed_peer_gid,
            peer_pid=request.observed_peer_pid,
        )
        return BrokerDispatchResult(
            status_code=result.status_code,
            body=result.body,
            authority_verified=result.authority_verified,
            executed_release_digest=result.executed_release_digest,
            executed_registry_digest=result.executed_registry_digest,
        )

    def verify_integrity(self) -> bool:
        self.operation_store.verify_chain()
        self.read_result_store.verify_chain()
        if not self.session_store.verify_integrity() or not self.audit_sink.verify():
            raise TrustedBrokerRuntimeError("trusted runtime integrity failed")
        if any(not runtime.store.verify_audit_chain() for runtime in self.authorities):
            raise TrustedBrokerRuntimeError("authority runtime integrity failed")
        return True


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise TrustedBrokerRuntimeError(f"{label} is invalid")
    return value


def _path(value: object, label: str) -> Path:
    try:
        return _absolute_path(value, label)
    except WriteRuntimeError as exc:
        raise TrustedBrokerRuntimeError(f"{label} is invalid") from exc


def _positive_integer(value: object, label: str, *, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise TrustedBrokerRuntimeError(f"{label} is invalid")
    return value


def _bounded_float(
    value: object, label: str, *, minimum: float, maximum: float
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not minimum <= float(value) <= maximum
    ):
        raise TrustedBrokerRuntimeError(f"{label} is invalid")
    return float(value)


def _mapping(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise TrustedBrokerRuntimeError(f"{label} fields are invalid")
    return dict(value)


def _normalized(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def _existing_file_identity(path: Path, label: str) -> tuple[int, int] | None:
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TrustedBrokerRuntimeError(f"{label} cannot be inspected") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise TrustedBrokerRuntimeError(f"{label} is not a regular file")
    return metadata.st_dev, metadata.st_ino


def _assert_distinct_file_paths(paths: Mapping[str, Path]) -> None:
    normalized: dict[str, str] = {}
    inodes: dict[tuple[int, int], str] = {}
    for label, path in paths.items():
        name = _normalized(path)
        if name in normalized:
            raise TrustedBrokerRuntimeError(
                f"{label} aliases {normalized[name]} by path"
            )
        normalized[name] = label
        identity = _existing_file_identity(path, label)
        if identity is not None:
            if identity in inodes:
                raise TrustedBrokerRuntimeError(
                    f"{label} aliases {inodes[identity]} by inode"
                )
            inodes[identity] = label


def _route(value: object) -> ReleaseRouteRuntimeConfig:
    item = _mapping(value, _ROUTE_FIELDS, "release route")
    return ReleaseRouteRuntimeConfig(
        release_digest=_digest(item["release_digest"], "route release digest"),
        registry_digest=_digest(item["registry_digest"], "route registry digest"),
        authority_runtime_config_path=_path(
            item["authority_runtime_config_path"],
            "authority runtime configuration path",
        ),
        authority_runtime_config_sha256=_digest(
            item["authority_runtime_config_sha256"],
            "authority runtime configuration digest",
        ),
    )


def _broker_uds(value: object) -> TrustedBrokerUdsConfig:
    item = _mapping(value, _BROKER_UDS_FIELDS, "Pi broker UDS")
    try:
        return TrustedBrokerUdsConfig(**item)
    except Exception as exc:
        raise TrustedBrokerRuntimeError("Pi broker UDS is invalid") from exc


def _mint_uds(
    value: object,
    *,
    current_release_digest: str,
    current_registry_digest: str,
) -> TrustedSessionMintUdsConfig:
    item = _mapping(value, _MINT_UDS_FIELDS, "session mint UDS")
    try:
        return TrustedSessionMintUdsConfig(
            **item,
            current_release_digest=current_release_digest,
            current_registry_digest=current_registry_digest,
        )
    except Exception as exc:
        raise TrustedBrokerRuntimeError("session mint UDS is invalid") from exc


def _approval_uds(value: object) -> TrustedApprovalUdsConfig:
    item = _mapping(value, _APPROVAL_UDS_FIELDS, "trusted approval UDS")
    try:
        return TrustedApprovalUdsConfig(**item)
    except Exception as exc:
        raise TrustedBrokerRuntimeError("trusted approval UDS is invalid") from exc


def _assert_transport_topology(
    *,
    broker_service_uid: int,
    pi: TrustedBrokerUdsConfig,
    mint: TrustedSessionMintUdsConfig,
    approval: TrustedApprovalUdsConfig,
) -> None:
    if (
        pi.allowed_client_uid != mint.pi_bridge_uid
        or pi.allowed_client_uid != approval.pi_bridge_uid
        or mint.odoo_issuer_uid != approval.odoo_client_uid
        or broker_service_uid
        in {pi.allowed_client_uid, mint.odoo_issuer_uid}
    ):
        raise TrustedBrokerRuntimeError("trusted service UID topology is invalid")
    if (
        pi.socket_group_gid == mint.socket_group_gid
        or mint.socket_group_gid != approval.socket_group_gid
    ):
        raise TrustedBrokerRuntimeError("trusted socket group topology is invalid")
    if any(
        config.socket_mode != 0o660
        for config in (pi, mint, approval)
    ):
        raise TrustedBrokerRuntimeError("production socket mode must be 0660")
    socket_paths = {
        pi.socket_path,
        mint.socket_path,
        approval.socket_path,
    }
    if len(socket_paths) != 3:
        raise TrustedBrokerRuntimeError("trusted socket paths must be distinct")


def load_trusted_broker_runtime_config(
    path: str | os.PathLike[str], *, require_root_owner: bool = True
) -> TrustedBrokerRuntimeConfig:
    """Load one exact, secret-free root composition snapshot."""

    if type(require_root_owner) is not bool:
        raise TrustedBrokerRuntimeError("require_root_owner is invalid")
    config_path = Path(path)
    if not config_path.is_absolute():
        raise TrustedBrokerRuntimeError(
            "trusted broker runtime configuration path must be absolute"
        )
    try:
        document, _raw = _read_config(
            config_path,
            "trusted broker runtime configuration",
            require_root_owner=require_root_owner,
        )
    except WriteRuntimeError as exc:
        raise TrustedBrokerRuntimeError(
            "trusted broker runtime configuration was rejected"
        ) from exc
    if set(document) != _ROOT_FIELDS:
        raise TrustedBrokerRuntimeError(
            "trusted broker runtime configuration fields are invalid"
        )
    if document["schema_version"] != BROKER_RUNTIME_SCHEMA_VERSION:
        raise TrustedBrokerRuntimeError("trusted broker runtime schema is invalid")

    service_uid = _positive_integer(
        document["broker_service_uid"], "broker service UID", maximum=2**32 - 2
    )
    service_gid = _positive_integer(
        document["broker_service_gid"], "broker service GID", maximum=2**32 - 2
    )
    current_release = _digest(
        document["current_release_digest"], "current release digest"
    )
    current_registry = _digest(
        document["current_registry_digest"], "current registry digest"
    )
    manifest_path = _path(
        document["historical_routing_manifest_path"],
        "historical routing manifest path",
    )
    read_runtime_path = _path(
        document["read_runtime_config_path"], "read runtime configuration path"
    )
    shared_write_state_path = _path(
        document["shared_write_state_path"], "shared write state path"
    )
    session_state_path = _path(
        document["trusted_session_state_path"], "trusted session state path"
    )
    audit_state_path = _path(
        document["broker_audit_state_path"], "broker audit state path"
    )
    raw_routes = document["release_routes"]
    if (
        not isinstance(raw_routes, list)
        or not raw_routes
        or len(raw_routes) > 64
    ):
        raise TrustedBrokerRuntimeError("release routes are invalid")
    routes = tuple(_route(item) for item in raw_routes)
    if (
        len({route.release_digest for route in routes}) != len(routes)
        or len(
            {
                (route.release_digest, route.registry_digest)
                for route in routes
            }
        )
        != len(routes)
        or len({route.authority_runtime_config_path for route in routes})
        != len(routes)
    ):
        raise TrustedBrokerRuntimeError("release routes are duplicated")
    current_matches = tuple(
        route
        for route in routes
        if route.release_digest == current_release
    )
    if (
        len(current_matches) != 1
        or current_matches[0].registry_digest != current_registry
    ):
        raise TrustedBrokerRuntimeError("current release route is missing or invalid")

    sqlite_busy_timeout_ms = _positive_integer(
        document["sqlite_busy_timeout_ms"],
        "SQLite busy timeout",
        maximum=MAX_SQLITE_BUSY_TIMEOUT_MS,
    )
    sqlite_busy_timeout_seconds = sqlite_busy_timeout_ms / 1000.0

    pi_uds = _broker_uds(document["pi_broker_uds"])
    mint_uds = _mint_uds(
        document["session_mint_uds"],
        current_release_digest=current_release,
        current_registry_digest=current_registry,
    )
    approval_uds = _approval_uds(document["trusted_approval_uds"])
    _assert_transport_topology(
        broker_service_uid=service_uid,
        pi=pi_uds,
        mint=mint_uds,
        approval=approval_uds,
    )
    if not (
        pi_uds.request_timeout_seconds <= 115
        and mint_uds.session_ttl_seconds
        >= int(pi_uds.request_timeout_seconds) + 5
    ):
        raise TrustedBrokerRuntimeError("broker/session outer deadline is invalid")

    read_timeout = _bounded_float(
        document["read_timeout_seconds"],
        "read timeout",
        minimum=0.1,
        maximum=105,
    )
    historical_timeout = _bounded_float(
        document["historical_timeout_seconds"],
        "historical timeout",
        minimum=ODOO_WRITE_TIMEOUT_SECONDS + 5,
        maximum=110,
    )
    approver_timeout = _bounded_float(
        document["approver_timeout_seconds"],
        "approver timeout",
        minimum=0.1,
        maximum=24,
    )
    if (
        read_timeout + 5 > pi_uds.request_timeout_seconds
        or historical_timeout + 5 > pi_uds.request_timeout_seconds
        or approver_timeout + 1 > approval_uds.request_timeout_seconds
    ):
        raise TrustedBrokerRuntimeError("nested runtime deadlines are invalid")
    if (
        sqlite_busy_timeout_seconds + _MINT_DEADLINE_MARGIN_SECONDS
        > mint_uds.request_timeout_seconds
    ):
        raise TrustedBrokerRuntimeError(
            "session mint SQLite deadline budget is invalid"
        )
    if (
        read_timeout
        + (_PI_SQLITE_PHASES * sqlite_busy_timeout_seconds)
        + _PI_DEADLINE_MARGIN_SECONDS
        > pi_uds.request_timeout_seconds
        or historical_timeout
        + (_PI_SQLITE_PHASES * sqlite_busy_timeout_seconds)
        + _PI_DEADLINE_MARGIN_SECONDS
        > pi_uds.request_timeout_seconds
    ):
        raise TrustedBrokerRuntimeError(
            "Pi broker aggregate deadline budget is invalid"
        )
    if (
        approver_timeout
        + (
            (len(routes) + _APPROVAL_FIXED_SQLITE_PHASES)
            * sqlite_busy_timeout_seconds
        )
        + _APPROVAL_DEADLINE_MARGIN_SECONDS
        > approval_uds.request_timeout_seconds
    ):
        raise TrustedBrokerRuntimeError(
            "trusted approval aggregate deadline budget is invalid"
        )

    known_files = {
        "broker runtime config": config_path,
        "historical routing manifest": manifest_path,
        "read runtime config": read_runtime_path,
        "shared write state": shared_write_state_path,
        "trusted session state": session_state_path,
        "broker audit state": audit_state_path,
        **{
            f"authority runtime config {index}": route.authority_runtime_config_path
            for index, route in enumerate(routes)
        },
    }
    _assert_distinct_file_paths(known_files)

    fingerprint = hashlib.sha256(canonical_json(document)).hexdigest()
    return TrustedBrokerRuntimeConfig(
        schema_version=BROKER_RUNTIME_SCHEMA_VERSION,
        config_path=config_path,
        broker_service_uid=service_uid,
        broker_service_gid=service_gid,
        current_release_digest=current_release,
        current_registry_digest=current_registry,
        historical_routing_manifest_path=manifest_path,
        historical_routing_manifest_sha256=_digest(
            document["historical_routing_manifest_sha256"],
            "historical routing manifest digest",
        ),
        read_runtime_config_path=read_runtime_path,
        read_runtime_config_sha256=_digest(
            document["read_runtime_config_sha256"],
            "read runtime configuration digest",
        ),
        shared_write_state_path=shared_write_state_path,
        trusted_session_state_path=session_state_path,
        broker_audit_state_path=audit_state_path,
        sqlite_busy_timeout_ms=sqlite_busy_timeout_ms,
        read_context_ttl_seconds=_positive_integer(
            document["read_context_ttl_seconds"],
            "read context TTL",
            maximum=300,
        ),
        read_timeout_seconds=read_timeout,
        historical_timeout_seconds=historical_timeout,
        historical_max_stdin_bytes=_positive_integer(
            document["historical_max_stdin_bytes"],
            "historical stdin limit",
            maximum=4 * 1024 * 1024,
        ),
        historical_max_stdout_bytes=_positive_integer(
            document["historical_max_stdout_bytes"],
            "historical stdout limit",
            maximum=16 * 1024 * 1024,
        ),
        historical_max_stderr_bytes=_positive_integer(
            document["historical_max_stderr_bytes"],
            "historical stderr limit",
            maximum=1024 * 1024,
        ),
        approver_context_ttl_seconds=_positive_integer(
            document["approver_context_ttl_seconds"],
            "approver context TTL",
            maximum=300,
        ),
        approver_timeout_seconds=approver_timeout,
        release_routes=routes,
        pi_broker_uds=pi_uds,
        session_mint_uds=mint_uds,
        trusted_approval_uds=approval_uds,
        config_fingerprint=fingerprint,
        _require_root_owner=require_root_owner,
    )


def _trusted_file_digest(
    path: Path,
    *,
    label: str,
    maximum: int,
    require_root_owner: bool,
) -> str:
    try:
        raw, _identity = _read_historical_file(
            path,
            label,
            maximum=maximum,
            require_root_owner=require_root_owner,
        )
    except Exception as exc:
        raise TrustedBrokerRuntimeError(f"{label} was rejected") from exc
    return hashlib.sha256(raw).hexdigest()


def _same_path(left: Path, right: Path) -> bool:
    return _normalized(left) == _normalized(right)


def _tenant_identity(runtime: RuntimeConfig) -> tuple[str, str, str, str]:
    return (
        runtime.instance_id,
        runtime.database_name,
        runtime.database_uuid,
        runtime.environment,
    )


def _assert_loaded_topology(
    config: TrustedBrokerRuntimeConfig,
    manifest: HistoricalRoutingManifest,
    authority_configs: tuple[TrustedAuthorityRuntimeConfig, ...],
) -> None:
    if (
        type(config) is not TrustedBrokerRuntimeConfig
        or type(manifest) is not HistoricalRoutingManifest
        or len(authority_configs) != len(config.release_routes)
        or any(type(item) is not TrustedAuthorityRuntimeConfig for item in authority_configs)
    ):
        raise TrustedBrokerRuntimeError("loaded release topology is invalid")
    configured_routes = {
        route.release_digest: route for route in config.release_routes
    }
    if (
        manifest.current_release_digest != config.current_release_digest
        or set(manifest.routes) != set(configured_routes)
        or any(
            manifest.routes[release].registry_digest
            != configured_routes[release].registry_digest
            for release in configured_routes
        )
    ):
        raise TrustedBrokerRuntimeError(
            "historical and authority route sets are not identical"
        )

    tenants: set[tuple[str, str, str, str]] = set()
    state_paths: dict[str, Path] = {
        "shared write state": config.shared_write_state_path,
        "trusted session state": config.trusted_session_state_path,
        "broker audit state": config.broker_audit_state_path,
    }
    release_roots: set[str] = set()
    finalizer_runtimes: list[EffectFinalizerClientRuntime] = []
    for route_config, authority in zip(config.release_routes, authority_configs):
        write = authority.write_runtime
        base = write.base_runtime
        finalizer = write.effect_finalizer
        manifest_route = manifest.routes[route_config.release_digest]
        if (
            not _same_path(authority.config_path, route_config.authority_runtime_config_path)
            or not _same_path(
                authority.write_runtime_config_path,
                manifest_route.runtime_config_path,
            )
            or not _same_path(write.write_state_path, config.shared_write_state_path)
            or authority.sqlite_busy_timeout_ms != config.sqlite_busy_timeout_ms
        ):
            raise TrustedBrokerRuntimeError("release runtime path topology is invalid")
        if type(finalizer) is not EffectFinalizerClientRuntime:
            raise TrustedBrokerRuntimeError(
                "release finalizer client runtime is invalid"
            )
        finalizer_runtimes.append(finalizer)
        tenants.add(_tenant_identity(base))
        release_root = _normalized(base.release_root)
        if release_root in release_roots:
            raise TrustedBrokerRuntimeError("release roots are duplicated")
        release_roots.add(release_root)
        state_paths[
            f"authority state {route_config.release_digest}"
        ] = authority.authority_state_path
        state_paths[
            f"read auth state {route_config.release_digest}"
        ] = base.auth_state_path
        state_paths[
            f"read receipt state {route_config.release_digest}"
        ] = base.receipt_state_path
    if len(tenants) != 1:
        raise TrustedBrokerRuntimeError("release tenant identities differ")
    finalizer = finalizer_runtimes[0]
    if any(item != finalizer for item in finalizer_runtimes[1:]):
        raise TrustedBrokerRuntimeError(
            "retained releases use different finalizer client runtimes"
        )
    transport_paths = {
        _normalized(Path(config.pi_broker_uds.socket_path)),
        _normalized(Path(config.session_mint_uds.socket_path)),
        _normalized(Path(config.trusted_approval_uds.socket_path)),
    }
    if (
        _normalized(Path(finalizer.socket_path)) in transport_paths
        or finalizer.socket_owner_uid != 0
        or finalizer.socket_mode != 0o660
        or finalizer.socket_group_gid
        in {
            config.pi_broker_uds.socket_group_gid,
            config.session_mint_uds.socket_group_gid,
            config.trusted_approval_uds.socket_group_gid,
        }
        or finalizer.finalizer_service_uid
        in {
            0,
            config.broker_service_uid,
            config.pi_broker_uds.allowed_client_uid,
            config.session_mint_uds.odoo_issuer_uid,
        }
        or finalizer.finalizer_service_gid
        in {
            0,
            config.broker_service_gid,
            finalizer.socket_group_gid,
            config.pi_broker_uds.socket_group_gid,
            config.session_mint_uds.socket_group_gid,
        }
        or finalizer.handoff_idle_timeout_seconds
        < config.historical_timeout_seconds + POST_ODOO_LOCAL_MARGIN_SECONDS
        or finalizer.request_io_timeout_seconds
        + POST_ODOO_LOCAL_MARGIN_SECONDS
        + MIN_ODOO_CALL_TIMEOUT_SECONDS
        >= config.historical_timeout_seconds
    ):
        raise TrustedBrokerRuntimeError(
            "independent finalizer service topology is invalid"
        )
    current_index = next(
        index
        for index, route in enumerate(config.release_routes)
        if route.release_digest == config.current_release_digest
    )
    if not _same_path(
        authority_configs[current_index].write_runtime.base_runtime_config_path,
        config.read_runtime_config_path,
    ):
        raise TrustedBrokerRuntimeError("current read runtime path is invalid")
    _assert_distinct_file_paths(state_paths)


def load_release_topology(
    config: TrustedBrokerRuntimeConfig,
    *,
    release_loader: Callable[..., VerifiedReleaseRoute] = load_verified_release_route,
) -> LoadedReleaseTopology:
    """Verify every configured file, route, release, registry, and state binding."""

    if type(config) is not TrustedBrokerRuntimeConfig or not callable(release_loader):
        raise TrustedBrokerRuntimeError("release topology dependencies are invalid")
    require_root_owner = config._require_root_owner
    if not secrets.compare_digest(
        _trusted_file_digest(
            config.historical_routing_manifest_path,
            label="historical routing manifest",
            maximum=1024 * 1024,
            require_root_owner=require_root_owner,
        ),
        config.historical_routing_manifest_sha256,
    ):
        raise TrustedBrokerRuntimeError("historical routing manifest digest differs")
    try:
        manifest = load_historical_routing_manifest(
            config.historical_routing_manifest_path,
            require_root_owner=require_root_owner,
        )
    except Exception as exc:
        raise TrustedBrokerRuntimeError("historical routing manifest was rejected") from exc

    authority_configs: list[TrustedAuthorityRuntimeConfig] = []
    releases: list[VerifiedReleaseRoute] = []
    for route in config.release_routes:
        if not secrets.compare_digest(
            _trusted_file_digest(
                route.authority_runtime_config_path,
                label="trusted authority runtime configuration",
                maximum=65_536,
                require_root_owner=require_root_owner,
            ),
            route.authority_runtime_config_sha256,
        ):
            raise TrustedBrokerRuntimeError(
                "trusted authority runtime configuration digest differs"
            )
        try:
            authority = load_trusted_authority_runtime_config(
                route.authority_runtime_config_path,
                require_root_owner=require_root_owner,
            )
        except Exception as exc:
            raise TrustedBrokerRuntimeError(
                "trusted authority runtime configuration was rejected"
            ) from exc
        manifest_route = manifest.routes.get(route.release_digest)
        if manifest_route is None or not secrets.compare_digest(
            _trusted_file_digest(
                authority.write_runtime_config_path,
                label="write runtime configuration",
                maximum=65_536,
                require_root_owner=require_root_owner,
            ),
            manifest_route.runtime_config_sha256,
        ):
            raise TrustedBrokerRuntimeError("write runtime route digest differs")
        try:
            release = release_loader(
                authority,
                expected_release_digest=route.release_digest,
                expected_registry_digest=route.registry_digest,
            )
        except Exception as exc:
            raise TrustedBrokerRuntimeError("verified release route was rejected") from exc
        if (
            type(release) is not VerifiedReleaseRoute
            or release.release_digest != route.release_digest
            or release.registry_digest != route.registry_digest
            or release.authority_config != authority
        ):
            raise TrustedBrokerRuntimeError("verified release route is invalid")
        authority_configs.append(authority)
        releases.append(release)

    loaded_authorities = tuple(authority_configs)
    _assert_loaded_topology(config, manifest, loaded_authorities)
    if not secrets.compare_digest(
        _trusted_file_digest(
            config.read_runtime_config_path,
            label="current read runtime configuration",
            maximum=65_536,
            require_root_owner=require_root_owner,
        ),
        config.read_runtime_config_sha256,
    ):
        raise TrustedBrokerRuntimeError("current read runtime digest differs")
    return LoadedReleaseTopology(
        manifest=manifest,
        authority_configs=loaded_authorities,
        releases=tuple(releases),
    )


def _operation_resolver(store: SQLitePersistence) -> Callable[[str], Any]:
    def resolve(operation_id: str) -> Any:
        try:
            return store.get_operation(operation_id)
        except OperationNotFound:
            return None

    return resolve


def _runtime_identifier(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(24)}"


def _assert_service_identity(config: TrustedBrokerRuntimeConfig) -> None:
    if os.name != "posix":
        raise TrustedBrokerRuntimeError("production broker requires POSIX")
    if (
        not hasattr(os, "geteuid")
        or not hasattr(os, "getegid")
        or os.geteuid() != config.broker_service_uid
        or os.getegid() != config.broker_service_gid
        or os.geteuid() == 0
    ):
        raise TrustedBrokerRuntimeError(
            "broker must run as its dedicated non-root service identity"
        )


def _assert_finalizer_socket_membership(
    config: TrustedBrokerRuntimeConfig,
    topology: LoadedReleaseTopology,
) -> None:
    try:
        socket_group_gid = (
            topology.releases[0].write_runtime.effect_finalizer.socket_group_gid
        )
        groups = set(os.getgroups())
        groups.add(os.getegid())
    except Exception as exc:
        raise TrustedBrokerRuntimeError(
            "broker finalizer socket group could not be verified"
        ) from exc
    if socket_group_gid not in groups:
        raise TrustedBrokerRuntimeError(
            "broker is not a member of the finalizer client socket group"
        )


def build_trusted_broker_runtime(
    path: str | os.PathLike[str],
    *,
    require_root_owner: bool = True,
    enforce_service_identity: bool | None = None,
    enforce_source_release: bool | None = None,
    utc_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> TrustedBrokerRuntime:
    """Construct every dependency and verify all stores before accepting traffic."""

    if (
        type(require_root_owner) is not bool
        or (
            enforce_service_identity is not None
            and type(enforce_service_identity) is not bool
        )
        or (
            enforce_source_release is not None
            and type(enforce_source_release) is not bool
        )
        or not callable(utc_clock)
    ):
        raise TrustedBrokerRuntimeError("broker construction options are invalid")
    config = load_trusted_broker_runtime_config(
        path, require_root_owner=require_root_owner
    )
    enforce_identity = (
        require_root_owner
        if enforce_service_identity is None
        else enforce_service_identity
    )
    if enforce_identity:
        _assert_service_identity(config)
    topology = load_release_topology(config)
    if enforce_identity:
        _assert_finalizer_socket_membership(config, topology)
    enforce_source = (
        require_root_owner
        if enforce_source_release is None
        else enforce_source_release
    )
    if enforce_source:
        current_release = next(
            release
            for release in topology.releases
            if release.release_digest == config.current_release_digest
        )
        try:
            current_release.assert_executing_broker_source(
                __file__,
                package_version=__version__,
            )
        except Exception as exc:
            raise TrustedBrokerRuntimeError(
                "executing broker package differs from the current release"
            ) from exc
    try:
        operation_store = SQLitePersistence(
            config.shared_write_state_path,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
        )
        session_store = SQLiteTrustedSessionStore(
            config.trusted_session_state_path,
            clock=utc_clock,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
            max_ttl_seconds=config.session_mint_uds.session_ttl_seconds,
            max_session_uses=config.session_mint_uds.session_max_uses,
        )
        audit_sink = SQLiteBrokerAuditSink(
            config.broker_audit_state_path,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
            clock=utc_clock,
        )
        resolve_operation = _operation_resolver(operation_store)
        release_map = {
            (release.release_digest, release.registry_digest): release
            for release in topology.releases
        }

        def resolve_approver_runtime(
            release_digest: str, registry_digest: str
        ) -> OdooApproverReleaseRuntime:
            release = release_map.get((release_digest, registry_digest))
            if release is None:
                raise TrustedBrokerRuntimeError("approver release route is unknown")
            return OdooApproverReleaseRuntime(
                release_digest=release.release_digest,
                registry_digest=release.registry_digest,
                config=release.write_runtime,
                secrets=release.write_secrets,
            )

        approver_authorizer = OdooApproverAuthorizer(
            runtime_resolver=resolve_approver_runtime,
            clock=utc_clock,
            context_ttl_seconds=config.approver_context_ttl_seconds,
            timeout_seconds=config.approver_timeout_seconds,
        )
        authority_runtimes: list[TrustedAuthorityRuntime] = []
        authority_map: dict[tuple[str, str], ReleaseAuthority] = {}
        for release in topology.releases:
            runtime = build_trusted_authority(
                release.authority_config.config_path,
                session_resolver=session_store.resolve,
                operation_resolver=resolve_operation,
                approver_authorizer=approver_authorizer,
                approval_ttl_resolver=release.approval_ttl_seconds,
                clock=utc_clock,
                require_root_owner=require_root_owner,
            )
            if (
                runtime.config.config_fingerprint
                != release.authority_config.config_fingerprint
                or runtime.config.write_runtime.config_fingerprint
                != release.write_runtime.config_fingerprint
            ):
                raise TrustedBrokerRuntimeError(
                    "authority runtime changed during broker construction"
                )
            authority_runtimes.append(runtime)
            route = (release.release_digest, release.registry_digest)
            authority_map[route] = ReleaseAuthority(
                release_digest=release.release_digest,
                registry_digest=release.registry_digest,
                authority=runtime.authority,
            )

        def resolve_authority(
            release_digest: str, registry_digest: str
        ) -> ReleaseAuthority | None:
            return authority_map.get((release_digest, registry_digest))

        def resolve_challenge(challenge_id: str) -> ReleaseAuthority | None:
            matched: list[ReleaseAuthority] = []
            for runtime, release in zip(authority_runtimes, topology.releases):
                challenge = runtime.store.find_challenge(challenge_id)
                if challenge is None:
                    continue
                route = (
                    challenge.operation.release_digest,
                    challenge.operation.registry_digest,
                )
                expected = (release.release_digest, release.registry_digest)
                if route != expected:
                    raise TrustedBrokerRuntimeError(
                        "approval challenge route differs from its authority store"
                    )
                matched.append(authority_map[expected])
            if len(matched) > 1:
                raise TrustedBrokerRuntimeError(
                    "approval challenge is duplicated across release stores"
                )
            return None if not matched else matched[0]

        response_verifier = build_release_response_verifier_resolver(
            (
                ReleaseReceiptVerificationConfig(
                    release_digest=release.release_digest,
                    registry_digest=release.registry_digest,
                    capability_channel=release.base_runtime.capability_channel,
                    read_receipt_key_id=release.base_runtime.receipt_key_id,
                    read_receipt_secret=release.read_receipt_secret,
                    write_receipt_key_id=release.write_runtime.write_receipt.key_id,
                    write_receipt_secret=release.write_secrets.write_receipt,
                )
                for release in topology.releases
            ),
            operation_resolver=resolve_operation,
            utc_clock=utc_clock,
        )
        current = release_map[
            (config.current_release_digest, config.current_registry_digest)
        ]
        read_result_store = SQLitePersistence(
            current.base_runtime.receipt_state_path,
            busy_timeout_ms=config.sqlite_busy_timeout_ms,
            receipt_key_id=current.base_runtime.receipt_key_id,
            receipt_secret=current.read_receipt_secret,
            enable_verified_read_results=True,
        )
        result_delivery_routes = {
            (release.release_digest, release.registry_digest): (
                ResultDeliveryRoute(
                    release_digest=release.release_digest,
                    registry_digest=release.registry_digest,
                    capability_channel=(
                        release.base_runtime.capability_channel
                    ),
                    write_receipt_key_id=(
                        release.write_runtime.write_receipt.key_id
                    ),
                    write_receipt_secret=(
                        release.write_secrets.write_receipt
                    ),
                )
            )
            for release in topology.releases
        }

        def resolve_result_delivery_route(
            release_digest: str, registry_digest: str
        ) -> ResultDeliveryRoute | None:
            return result_delivery_routes.get(
                (release_digest, registry_digest)
            )

        result_delivery_resolver = TrustedResultDeliveryResolver(
            current_release_digest=current.release_digest,
            current_registry_digest=current.registry_digest,
            read_store=read_result_store,
            write_store=operation_store,
            route_resolver=resolve_result_delivery_route,
            clock=utc_clock,
        )
        finalizer_runtime = current.write_runtime.effect_finalizer

        def preconnect_finalizer(route: Any):
            release = release_map.get(
                (route.release_digest, route.registry_digest)
            )
            expected_route = topology.manifest.routes.get(route.release_digest)
            if (
                release is None
                or route != expected_route
                or release.write_runtime.effect_finalizer != finalizer_runtime
            ):
                raise TrustedBrokerRuntimeError(
                    "historical finalizer release binding is invalid"
                )
            return preconnect_effect_finalizer_socket(
                finalizer_runtime.socket_path,
                expected_owner_uid=finalizer_runtime.socket_owner_uid,
                expected_group_gid=finalizer_runtime.socket_group_gid,
                expected_mode=finalizer_runtime.socket_mode,
                timeout_seconds=finalizer_runtime.request_io_timeout_seconds,
            )

        read_adapter = TrustedReadAdapter(
            runtime_config_path=config.read_runtime_config_path,
            expected_release_digest=config.current_release_digest,
            expected_registry_digest=config.current_registry_digest,
            session_resolver=session_store.resolve,
            context_ttl_seconds=config.read_context_ttl_seconds,
            timeout_seconds=config.read_timeout_seconds,
            clock=utc_clock,
        )
        historical_router = HistoricalReleaseRouter(
            config.historical_routing_manifest_path,
            operation_store,
            effect_finalizer_preconnector=preconnect_finalizer,
            require_root_owner=require_root_owner,
            timeout_seconds=config.historical_timeout_seconds,
            max_stdin_bytes=config.historical_max_stdin_bytes,
            max_stdout_bytes=config.historical_max_stdout_bytes,
            max_stderr_bytes=config.historical_max_stderr_bytes,
            pinned_manifest=topology.manifest,
        )
        broker = TrustedBroker(
            current_release_digest=current.release_digest,
            current_registry_digest=current.registry_digest,
            session_resolver=session_store.resolve,
            authority_resolver=resolve_authority,
            challenge_authority_resolver=resolve_challenge,
            response_verifier_resolver=response_verifier,
            audit_sink=audit_sink,
            prepare_idempotency_resolver=SQLitePrepareIdempotencyResolver(
                operation_store
            ),
            recovery_idempotency_resolver=SQLiteRecoveryIdempotencyResolver(
                operation_store
            ),
            operation_resolver=resolve_operation,
            precheck_resolver=operation_store.get_precheck_record,
            historical_executor=historical_router,
            read_authorizer=read_adapter.authorize,
            read_executor=read_adapter.execute,
            operation_id_factory=lambda: _runtime_identifier("operation"),
            request_id_factory=lambda: _runtime_identifier("request"),
            recovery_operation_id_factory=lambda: _runtime_identifier("recovery"),
            utc_clock=utc_clock,
            result_delivery_resolver=result_delivery_resolver,
        )
        runtime = TrustedBrokerRuntime(
            config=config,
            topology=topology,
            operation_store=operation_store,
            read_result_store=read_result_store,
            session_store=session_store,
            audit_sink=audit_sink,
            authorities=tuple(authority_runtimes),
            historical_router=historical_router,
            read_adapter=read_adapter,
            result_delivery_resolver=result_delivery_resolver,
            broker=broker,
        )
        runtime.verify_integrity()
        return runtime
    except TrustedBrokerRuntimeError:
        raise
    except Exception as exc:
        raise TrustedBrokerRuntimeError(
            "trusted broker runtime construction failed"
        ) from exc


__all__ = [
    "BROKER_RUNTIME_SCHEMA_VERSION",
    "LoadedReleaseTopology",
    "ReleaseRouteRuntimeConfig",
    "TrustedBrokerRuntime",
    "TrustedBrokerRuntimeConfig",
    "TrustedBrokerRuntimeError",
    "build_trusted_broker_runtime",
    "load_release_topology",
    "load_trusted_broker_runtime_config",
]

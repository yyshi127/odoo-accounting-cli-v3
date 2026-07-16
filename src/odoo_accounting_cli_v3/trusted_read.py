"""Production read authorizer and executor for the trusted Pi broker.

The Pi-facing request contains only a capability ID and business parameters.
This adapter resolves identity from an opaque trusted session handle, signs a
short-lived read context, and executes it through the root-managed Odoo runner.
It never accepts runtime, release, database, company, user, or token controls
from the business request.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .auth import (
    authentication_request_digest,
    context_payload,
    sign_request_context,
    verify_request_context,
)
from .contracts import validate_value
from .gateway import RequestContext
from .operations import canonical_json
from .registry import Capability, load_registry, registry_digest
from .trusted_authority import TrustedSession
from .trusted_broker import AuthorizedReadAction
from .odoo.bootstrap import request_context_from_mapping
from .odoo.runner import (
    MAX_TIMEOUT_SECONDS,
    RuntimeConfig,
    load_runtime_config,
    load_runtime_secrets,
    run_odoo_shell,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SESSION_HANDLE = re.compile(r"[A-Za-z0-9._~-]{32,512}\Z")
_CAPABILITY_ID = re.compile(r"acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*\Z")
_BUSINESS_FIELDS = frozenset({"capability_id", "parameters"})
_FULL_REQUEST_FIELDS = frozenset({"capability_id", "context", "parameters"})
_RELEASE_IDENTITY_FIELDS = frozenset(
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
_MAX_RUNTIME_CONFIG_BYTES = 65_536
_MAX_CONTEXT_TTL_SECONDS = 300


class TrustedReadError(ValueError):
    """Stable, detail-free failure at the production read boundary."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class _RuntimeFileIdentity:
    digest: str
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _RuntimeSnapshot:
    config: RuntimeConfig
    config_file: _RuntimeFileIdentity
    release_identity_json: str
    capabilities: tuple[Capability, ...]
    auth_secret: bytes = field(repr=False, compare=False)
    secret_fingerprints: tuple[str, str]

    @property
    def release_identity(self) -> dict[str, Any]:
        return json.loads(self.release_identity_json)


def _trusted_text(value: object, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TrustedReadError("trusted_read_configuration_rejected")
    return value


def _aware_now(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception as exc:
        raise TrustedReadError("trusted_read_configuration_rejected") from exc
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise TrustedReadError("trusted_read_configuration_rejected")
    return value


def _read_runtime_config_identity(path: Path) -> _RuntimeFileIdentity:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not path.is_absolute()
            or not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or os.path.normcase(os.path.abspath(path.resolve(strict=True)))
            != os.path.normcase(os.path.abspath(path))
        ):
            raise TrustedReadError("trusted_read_configuration_rejected")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise TrustedReadError("trusted_read_configuration_rejected")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_RUNTIME_CONFIG_BYTES:
                raise TrustedReadError("trusted_read_configuration_rejected")
            digest.update(chunk)
        after = path.lstat()
        before_values = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_values = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            before_values != after_values
            or not stat.S_ISREG(after.st_mode)
            or path.is_symlink()
        ):
            raise TrustedReadError("trusted_read_configuration_rejected")
        return _RuntimeFileIdentity(
            digest=digest.hexdigest(),
            device=before.st_dev,
            inode=before.st_ino,
            size=before.st_size,
            modified_ns=before.st_mtime_ns,
            changed_ns=before.st_ctime_ns,
        )
    except TrustedReadError:
        raise
    except OSError as exc:
        raise TrustedReadError("trusted_read_configuration_rejected") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _default_release_identity_loader(config: RuntimeConfig) -> Mapping[str, Any]:
    # Keep one release-verification implementation across the direct CLI,
    # write runtime, and trusted broker adapter.
    from .cli import _assert_runtime_release, _load_release_identity
    from .odoo.runner import _validate_canonical_package_binding

    _validate_canonical_package_binding(config)
    identity = _load_release_identity(config.release_root, command="read")
    _assert_runtime_release(config, identity)
    return identity


def _default_registry_loader(config: RuntimeConfig) -> Iterable[Capability]:
    return load_registry(config.release_root / "registry" / "capabilities.json")


def _context_mapping(context: RequestContext) -> dict[str, Any]:
    return {**context_payload(context), "auth_signature": context.auth_signature}


def _canonical_object(
    value: object,
    fields: frozenset[str],
    *,
    code: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TrustedReadError(code)
    try:
        detached = json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise TrustedReadError(code) from exc
    if not isinstance(detached, dict) or set(detached) != fields:
        raise TrustedReadError(code)
    return detached


class TrustedReadAdapter:
    """Release-pinned authorizer/executor pair for ``TrustedBroker`` reads."""

    __slots__ = (
        "_auth_token_resolver",
        "_clock",
        "_config_loader",
        "_context_ttl_seconds",
        "_expected_registry_digest",
        "_expected_release_digest",
        "_pinned",
        "_registry_loader",
        "_release_identity_loader",
        "_runner",
        "_runtime_config_path",
        "_secret_loader",
        "_session_resolver",
        "_timeout_seconds",
    )

    def __init__(
        self,
        *,
        runtime_config_path: str | os.PathLike[str],
        expected_release_digest: str,
        expected_registry_digest: str,
        session_resolver: Callable[[str], TrustedSession | None],
        context_ttl_seconds: int = 300,
        timeout_seconds: float = 30.0,
        clock: Callable[[], datetime] | None = None,
        auth_token_resolver: Callable[[TrustedSession], str] | None = None,
        config_loader: Callable[[Path], RuntimeConfig] = load_runtime_config,
        secret_loader: Callable[[RuntimeConfig], tuple[bytes, bytes]] = (
            load_runtime_secrets
        ),
        release_identity_loader: Callable[
            [RuntimeConfig], Mapping[str, Any]
        ] = _default_release_identity_loader,
        registry_loader: Callable[[RuntimeConfig], Iterable[Capability]] = (
            _default_registry_loader
        ),
        runner: Callable[..., dict[str, Any]] = run_odoo_shell,
    ) -> None:
        try:
            path = Path(runtime_config_path)
        except (TypeError, ValueError) as exc:
            raise TrustedReadError("trusted_read_configuration_rejected") from exc
        if (
            not path.is_absolute()
            or not isinstance(expected_release_digest, str)
            or _SHA256.fullmatch(expected_release_digest) is None
            or not isinstance(expected_registry_digest, str)
            or _SHA256.fullmatch(expected_registry_digest) is None
            or not callable(session_resolver)
            or type(context_ttl_seconds) is not int
            or not 1 <= context_ttl_seconds <= _MAX_CONTEXT_TTL_SECONDS
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < float(timeout_seconds) <= MAX_TIMEOUT_SECONDS
            or not all(
                callable(item)
                for item in (
                    config_loader,
                    secret_loader,
                    release_identity_loader,
                    registry_loader,
                    runner,
                )
            )
        ):
            raise TrustedReadError("trusted_read_configuration_rejected")
        selected_clock = clock or (lambda: datetime.now(timezone.utc))
        selected_token_resolver = auth_token_resolver or (
            lambda _session: f"read-{uuid.uuid4()}"
        )
        if not callable(selected_clock) or not callable(selected_token_resolver):
            raise TrustedReadError("trusted_read_configuration_rejected")

        self._runtime_config_path = path
        self._expected_release_digest = expected_release_digest
        self._expected_registry_digest = expected_registry_digest
        self._session_resolver = session_resolver
        self._context_ttl_seconds = context_ttl_seconds
        self._timeout_seconds = float(timeout_seconds)
        self._clock = selected_clock
        self._auth_token_resolver = selected_token_resolver
        self._config_loader = config_loader
        self._secret_loader = secret_loader
        self._release_identity_loader = release_identity_loader
        self._registry_loader = registry_loader
        self._runner = runner
        try:
            self._pinned = self._capture_snapshot()
        except TrustedReadError:
            raise
        except Exception as exc:  # Defensive dependency boundary.
            raise TrustedReadError("trusted_read_configuration_rejected") from exc

    @property
    def release_digest(self) -> str:
        return self._expected_release_digest

    @property
    def registry_digest(self) -> str:
        return self._expected_registry_digest

    def _capture_snapshot(self) -> _RuntimeSnapshot:
        before = _read_runtime_config_identity(self._runtime_config_path)
        try:
            config = self._config_loader(self._runtime_config_path)
            if type(config) is not RuntimeConfig:
                raise TrustedReadError("trusted_read_configuration_rejected")
            raw_identity = self._release_identity_loader(config)
            identity = _canonical_object(
                raw_identity,
                _RELEASE_IDENTITY_FIELDS,
                code="trusted_read_configuration_rejected",
            )
            if (
                identity["verified"] is not True
                or any(
                    _SHA256.fullmatch(identity[field]) is None
                    for field in (
                        "manifest_sha256",
                        "package_sha256",
                        "registry_digest",
                    )
                )
                or identity["manifest_sha256"] != self._expected_release_digest
                or identity["registry_digest"] != self._expected_registry_digest
                or identity["package_sha256"] != config.canonical_package_sha256
                or identity["release"] != config.release_root.name
            ):
                raise TrustedReadError("trusted_read_configuration_rejected")
            for field_name in ("commit", "release", "version"):
                _trusted_text(identity[field_name], maximum=256)

            capabilities = tuple(self._registry_loader(config))
            if (
                not capabilities
                or any(type(item) is not Capability for item in capabilities)
                or len({item.id for item in capabilities}) != len(capabilities)
                or registry_digest(capabilities) != self._expected_registry_digest
            ):
                raise TrustedReadError("trusted_read_configuration_rejected")
            secrets = self._secret_loader(config)
            if (
                not isinstance(secrets, tuple)
                or len(secrets) != 2
                or any(not isinstance(item, bytes) or len(item) < 32 for item in secrets)
                or hmac.compare_digest(secrets[0], secrets[1])
            ):
                raise TrustedReadError("trusted_read_configuration_rejected")
            after = _read_runtime_config_identity(self._runtime_config_path)
            if before != after:
                raise TrustedReadError("trusted_read_configuration_rejected")
            return _RuntimeSnapshot(
                config=config,
                config_file=before,
                release_identity_json=canonical_json(identity).decode("utf-8"),
                capabilities=capabilities,
                auth_secret=secrets[0],
                secret_fingerprints=(
                    hashlib.sha256(secrets[0]).hexdigest(),
                    hashlib.sha256(secrets[1]).hexdigest(),
                ),
            )
        except TrustedReadError:
            raise
        except Exception as exc:
            raise TrustedReadError("trusted_read_configuration_rejected") from exc

    def _snapshot(self) -> _RuntimeSnapshot:
        observed = self._capture_snapshot()
        pinned = self._pinned
        if (
            observed.config != pinned.config
            or observed.config_file != pinned.config_file
            or observed.release_identity_json != pinned.release_identity_json
            or observed.capabilities != pinned.capabilities
            or observed.secret_fingerprints != pinned.secret_fingerprints
        ):
            raise TrustedReadError("trusted_read_configuration_rejected")
        return observed

    def _session(self, session_handle: str, now: datetime) -> TrustedSession:
        if (
            not isinstance(session_handle, str)
            or _SESSION_HANDLE.fullmatch(session_handle) is None
        ):
            raise TrustedReadError("trusted_read_authorization_rejected")
        try:
            session = self._session_resolver(session_handle)
        except Exception as exc:
            raise TrustedReadError("trusted_read_authorization_rejected") from exc
        if (
            not isinstance(session, TrustedSession)
            or now < session.issued_at
            or now >= session.expires_at
        ):
            raise TrustedReadError("trusted_read_authorization_rejected")
        return session

    @staticmethod
    def _runtime_binding(identity: object, config: RuntimeConfig, *, code: str) -> None:
        if (
            getattr(identity, "odoo_instance_id", None) != config.instance_id
            or getattr(identity, "database_name", None) != config.database_name
            or getattr(identity, "database_uuid", None) != config.database_uuid
            or getattr(identity, "environment", None) != config.environment
            or getattr(identity, "user_id", None) == 1
            or getattr(identity, "company_id", None)
            not in getattr(identity, "allowed_company_ids", frozenset())
        ):
            raise TrustedReadError(code)

    @staticmethod
    def _business_request(value: object, *, code: str) -> dict[str, Any]:
        request = _canonical_object(value, _BUSINESS_FIELDS, code=code)
        if (
            not isinstance(request["capability_id"], str)
            or _CAPABILITY_ID.fullmatch(request["capability_id"]) is None
            or not isinstance(request["parameters"], dict)
        ):
            raise TrustedReadError(code)
        return request

    @staticmethod
    def _capability(
        snapshot: _RuntimeSnapshot,
        identity: TrustedSession | RequestContext,
        request: Mapping[str, Any],
        *,
        code: str,
    ) -> Capability:
        capability = next(
            (
                item
                for item in snapshot.capabilities
                if item.id == request["capability_id"]
            ),
            None,
        )
        if capability is None or capability.data["access"] != "read":
            raise TrustedReadError(code)
        environment_field = (
            "enabled_environments"
            if snapshot.config.capability_channel == "enabled"
            else "staged_environments"
        )
        if identity.environment not in capability.data.get(environment_field, []):
            raise TrustedReadError(code)
        try:
            validate_value(request["parameters"], capability.data["input_schema"])
        except Exception as exc:
            raise TrustedReadError(code) from exc
        scope = capability.data["company_scope"]
        parameters = request["parameters"]
        if scope in {"bound_company", "explicit_single_company"}:
            if parameters.get("company_id") != identity.company_id:
                raise TrustedReadError(code)
        elif scope == "allowed_companies":
            company_ids = parameters.get("company_ids")
            if (
                not isinstance(company_ids, list)
                or not company_ids
                or not set(company_ids).issubset(identity.allowed_company_ids)
            ):
                raise TrustedReadError(code)
        else:  # pragma: no cover - registry validation owns this invariant.
            raise TrustedReadError(code)
        return capability

    def authorize(
        self, session_handle: str, request: dict[str, Any]
    ) -> AuthorizedReadAction:
        """Resolve a trusted session and sign one exact business read request."""

        try:
            now = _aware_now(self._clock)
            session = self._session(session_handle, now)
            snapshot = self._snapshot()
            self._runtime_binding(
                session,
                snapshot.config,
                code="trusted_read_authorization_rejected",
            )
            business = self._business_request(
                request, code="trusted_read_authorization_rejected"
            )
            self._capability(
                snapshot,
                session,
                business,
                code="trusted_read_authorization_rejected",
            )
            expires_at = min(
                session.expires_at,
                now + timedelta(seconds=self._context_ttl_seconds),
            )
            if expires_at <= now:
                raise TrustedReadError("trusted_read_authorization_rejected")
            try:
                token_id = _trusted_text(self._auth_token_resolver(session))
                context = sign_request_context(
                    auth_token_id=token_id,
                    principal=session.principal,
                    odoo_instance_id=session.odoo_instance_id,
                    database_name=session.database_name,
                    database_uuid=session.database_uuid,
                    user_id=session.user_id,
                    company_id=session.company_id,
                    allowed_company_ids=session.allowed_company_ids,
                    environment=session.environment,
                    capability_id=business["capability_id"],
                    parameters=business["parameters"],
                    issued_at=now,
                    expires_at=expires_at,
                    key_id=snapshot.config.auth_key_id,
                    secret=snapshot.auth_secret,
                )
            except Exception as exc:
                raise TrustedReadError("trusted_read_authorization_rejected") from exc
            return AuthorizedReadAction(context=context, request=business)
        except TrustedReadError:
            raise
        except Exception as exc:
            raise TrustedReadError("trusted_read_authorization_rejected") from exc

    def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        """Revalidate and execute one signed read through ``run_odoo_shell``."""

        try:
            full_request = _canonical_object(
                request,
                _FULL_REQUEST_FIELDS,
                code="trusted_read_execution_rejected",
            )
            business = self._business_request(
                {
                    "capability_id": full_request["capability_id"],
                    "parameters": full_request["parameters"],
                },
                code="trusted_read_execution_rejected",
            )
            context = request_context_from_mapping(full_request["context"])
            snapshot = self._snapshot()
            now = _aware_now(self._clock)
            self._runtime_binding(
                context,
                snapshot.config,
                code="trusted_read_execution_rejected",
            )
            verify_request_context(
                context,
                now=now,
                secret=snapshot.auth_secret,
                expected_key_id=snapshot.config.auth_key_id,
            )
            if not hmac.compare_digest(
                context.auth_request_digest,
                authentication_request_digest(
                    business["capability_id"], business["parameters"]
                ),
            ):
                raise TrustedReadError("trusted_read_execution_rejected")
            capability = self._capability(
                snapshot,
                context,
                business,
                code="trusted_read_execution_rejected",
            )
            try:
                raw_result = self._runner(
                    snapshot.config,
                    full_request,
                    release_digest=self._expected_release_digest,
                    timeout_seconds=self._timeout_seconds,
                )
            except Exception as exc:
                raise TrustedReadError("trusted_read_runner_failed") from exc
            if not isinstance(raw_result, dict):
                raise TrustedReadError("trusted_read_runner_failed")
            try:
                result = json.loads(canonical_json(raw_result))
                validate_value(result, capability.data["output_schema"])
            except Exception as exc:
                raise TrustedReadError("trusted_read_runner_failed") from exc
            receipt = result.get("receipt")
            if (
                not isinstance(receipt, dict)
                or receipt.get("release_digest") != self._expected_release_digest
                or receipt.get("registry_digest") != self._expected_registry_digest
            ):
                raise TrustedReadError("trusted_read_runner_failed")

            post_snapshot = self._snapshot()
            post_now = _aware_now(self._clock)
            verify_request_context(
                context,
                now=post_now,
                secret=post_snapshot.auth_secret,
                expected_key_id=post_snapshot.config.auth_key_id,
            )
            return {
                "command": "read",
                "data": {
                    "capability_id": business["capability_id"],
                    "release_identity": post_snapshot.release_identity,
                    "result": result,
                    "runtime": dict(post_snapshot.config.runtime_identity),
                },
                "ok": True,
            }
        except TrustedReadError:
            raise
        except Exception as exc:
            raise TrustedReadError("trusted_read_execution_rejected") from exc


__all__ = ["TrustedReadAdapter", "TrustedReadError"]

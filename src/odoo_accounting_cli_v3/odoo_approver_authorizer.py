"""Release-bound Odoo ACL adapter for trusted approval decisions.

The adapter accepts only authority-owned :class:`TrustedSession` and durable
:class:`Operation` objects.  It creates a fresh, short-lived write-auth context
for the exact approver/company/capability check and treats every unavailable or
untrusted Odoo response as an authorization failure.
"""

from __future__ import annotations

import json
import math
import re
import secrets as secret_tokens
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from .auth import context_payload, sign_request_context
from .odoo.runner import RuntimeConfig
from .odoo.write_runner import run_odoo_authorize_approver
from .operations import Operation, canonical_json
from .trusted_authority import TrustedSession
from .write_runtime import (
    WRITE_EXECUTION_MODES,
    WRITE_RUNTIME_SCHEMA_VERSION,
    WriteRoleConfig,
    WriteRuntimeConfig,
    WriteRuntimeSecrets,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESULT_FIELDS = frozenset(
    {
        "authorized",
        "approver_user_id",
        "company_id",
        "capability_id",
        "runtime_binding",
        "registry_digest",
        "release_digest",
    }
)
_MAX_CONTEXT_TTL_SECONDS = 300
_MAX_RUNNER_TIMEOUT_SECONDS = 120.0
_MIN_WRITE_AUTH_SECRET_BYTES = 32


class OdooApproverAuthorizationError(RuntimeError):
    """The trusted Odoo approver authorization could not be established."""


class OdooApproverRuntimeResolver(Protocol):
    def __call__(
        self, release_digest: str, registry_digest: str
    ) -> "OdooApproverReleaseRuntime": ...


class OdooApproverRunner(Protocol):
    def __call__(
        self,
        config: WriteRuntimeConfig,
        secrets: WriteRuntimeSecrets,
        request: dict[str, Any],
        *,
        release_digest: str,
        timeout_seconds: float,
    ) -> dict[str, Any]: ...


def _authorization_failed() -> OdooApproverAuthorizationError:
    return OdooApproverAuthorizationError("Odoo approver authorization failed")


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _token() -> str:
    return secret_tokens.token_hex(32)


@dataclass(frozen=True, slots=True)
class OdooApproverReleaseRuntime:
    """One trusted release/registry route and its validated write-auth runtime."""

    release_digest: str
    registry_digest: str
    config: WriteRuntimeConfig
    secrets: WriteRuntimeSecrets = field(repr=False)

    def __post_init__(self) -> None:
        config = self.config
        secrets = self.secrets
        if not (
            _valid_digest(self.release_digest)
            and _valid_digest(self.registry_digest)
            and type(config) is WriteRuntimeConfig
            and type(secrets) is WriteRuntimeSecrets
            and config.schema_version == WRITE_RUNTIME_SCHEMA_VERSION
            and config.write_execution_mode in WRITE_EXECUTION_MODES
            and type(config.base_runtime) is RuntimeConfig
            and _valid_digest(config.config_fingerprint)
            and type(config.write_auth) is WriteRoleConfig
            and isinstance(config.write_auth.key_id, str)
            and bool(config.write_auth.key_id.strip())
            and isinstance(secrets.write_auth, bytes)
            and len(secrets.write_auth) >= _MIN_WRITE_AUTH_SECRET_BYTES
        ):
            raise OdooApproverAuthorizationError(
                "Odoo approver release runtime is invalid"
            )


@dataclass(frozen=True, slots=True)
class OdooApproverAuthorizer:
    """Callable ``TrustedSession + Operation -> bool`` Odoo ACL adapter."""

    runtime_resolver: OdooApproverRuntimeResolver = field(repr=False)
    runner: OdooApproverRunner = field(
        default=run_odoo_authorize_approver, repr=False
    )
    clock: Callable[[], datetime] = field(default=_utcnow, repr=False)
    token_factory: Callable[[], str] = field(default=_token, repr=False)
    context_ttl_seconds: int = 60
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if (
            not callable(self.runtime_resolver)
            or not callable(self.runner)
            or not callable(self.clock)
            or not callable(self.token_factory)
            or type(self.context_ttl_seconds) is not int
            or self.context_ttl_seconds <= 0
            or self.context_ttl_seconds > _MAX_CONTEXT_TTL_SECONDS
            or isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
            or self.timeout_seconds > _MAX_RUNNER_TIMEOUT_SECONDS
        ):
            raise OdooApproverAuthorizationError(
                "Odoo approver authorizer configuration is invalid"
            )

    @staticmethod
    def _same_tenant(session: TrustedSession, operation: Operation) -> bool:
        return (
            session.user_id != operation.user_id
            and session.company_id == operation.company_id
            and operation.company_id in session.allowed_company_ids
            and session.odoo_instance_id == operation.odoo_instance_id
            and session.database_name == operation.database_name
            and session.database_uuid == operation.database_uuid
            and session.environment == operation.environment
        )

    @staticmethod
    def _runtime_matches(
        binding: OdooApproverReleaseRuntime,
        session: TrustedSession,
        operation: Operation,
    ) -> bool:
        base = binding.config.base_runtime
        return (
            binding.release_digest == operation.release_digest
            and binding.registry_digest == operation.registry_digest
            and base.instance_id == session.odoo_instance_id
            and base.instance_id == operation.odoo_instance_id
            and base.database_name == session.database_name
            and base.database_name == operation.database_name
            and base.database_uuid == session.database_uuid
            and base.database_uuid == operation.database_uuid
            and base.environment == session.environment
            and base.environment == operation.environment
        )

    @staticmethod
    def _runtime_binding(config: WriteRuntimeConfig) -> dict[str, Any]:
        base = config.base_runtime
        return {
            "odoo_instance_id": base.instance_id,
            "database_name": base.database_name,
            "database_uuid": base.database_uuid,
            "environment": base.environment,
            "capability_channel": base.capability_channel,
        }

    def _authorize(self, session: TrustedSession, operation: Operation) -> bool:
        if not isinstance(session, TrustedSession) or not isinstance(
            operation, Operation
        ):
            raise _authorization_failed()
        operation.assert_integrity()
        if not self._same_tenant(session, operation):
            return False

        binding = self.runtime_resolver(
            operation.release_digest, operation.registry_digest
        )
        if type(binding) is not OdooApproverReleaseRuntime or not self._runtime_matches(
            binding, session, operation
        ):
            raise _authorization_failed()

        now = self.clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise _authorization_failed()
        now = now.astimezone(timezone.utc)
        if now < session.issued_at or now >= session.expires_at:
            raise _authorization_failed()
        expires_at = min(
            session.expires_at,
            now + timedelta(seconds=self.context_ttl_seconds),
        )
        if expires_at <= now:
            raise _authorization_failed()

        token = self.token_factory()
        if not isinstance(token, str) or _SHA256.fullmatch(token) is None:
            raise _authorization_failed()
        parameters = {
            "approver_user_id": session.user_id,
            "company_id": operation.company_id,
        }
        context = sign_request_context(
            auth_token_id=f"odoo-approver-{token}",
            principal=session.principal,
            odoo_instance_id=session.odoo_instance_id,
            database_name=session.database_name,
            database_uuid=session.database_uuid,
            user_id=session.user_id,
            company_id=session.company_id,
            allowed_company_ids=session.allowed_company_ids,
            environment=session.environment,
            capability_id=operation.capability_id,
            parameters=parameters,
            issued_at=now,
            expires_at=expires_at,
            key_id=binding.config.write_auth.key_id,
            secret=binding.secrets.write_auth,
        )
        request = {
            "context": {
                **context_payload(context),
                "auth_signature": context.auth_signature,
            },
            "capability_id": operation.capability_id,
            "parameters": parameters,
        }
        raw_result = self.runner(
            binding.config,
            binding.secrets,
            request,
            release_digest=operation.release_digest,
            timeout_seconds=float(self.timeout_seconds),
        )
        if not isinstance(raw_result, dict):
            raise _authorization_failed()
        try:
            result = json.loads(canonical_json(raw_result))
        except (TypeError, ValueError, UnicodeError):
            raise _authorization_failed() from None
        expected_runtime = self._runtime_binding(binding.config)
        if not (
            isinstance(result, dict)
            and set(result) == _RESULT_FIELDS
            and type(result.get("authorized")) is bool
            and type(result.get("approver_user_id")) is int
            and result["approver_user_id"] == session.user_id
            and type(result.get("company_id")) is int
            and result["company_id"] == operation.company_id
            and result.get("capability_id") == operation.capability_id
            and isinstance(result.get("runtime_binding"), dict)
            and result["runtime_binding"] == expected_runtime
            and result.get("registry_digest") == operation.registry_digest
            and result.get("release_digest") == operation.release_digest
        ):
            raise _authorization_failed()
        return result["authorized"]

    def __call__(self, session: TrustedSession, operation: Operation) -> bool:
        try:
            return self._authorize(session, operation)
        except Exception:
            # Do not attach backend exceptions: they may contain command output,
            # paths, or secret material.  The authority only receives this
            # stable, non-sensitive failure.
            pass
        raise _authorization_failed()


__all__ = [
    "OdooApproverAuthorizationError",
    "OdooApproverAuthorizer",
    "OdooApproverReleaseRuntime",
    "OdooApproverRunner",
    "OdooApproverRuntimeResolver",
]

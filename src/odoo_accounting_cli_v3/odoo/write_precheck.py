"""Fail-closed Odoo boundary for authenticated accounting write prechecks.

This module is deliberately read-only: it binds an authenticated non-superuser,
checks runtime and registry policy, and calls only ``OdooWriteHandlers.precheck``.
It never executes, verifies, commits, rolls back, or elevates an Odoo operation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Protocol, TypeVar

from ..auth import authentication_request_digest, verify_request_context
from ..contracts import validate_value
from ..domain.write_semantics import validate_write_semantics
from ..gateway import RequestContext
from ..operations import canonical_json
from ..registry import Capability, registry_digest
from ..write_receipts import (
    index_recovery_guard_graph,
    validate_executable_recovery_plan,
)
from .bootstrap import (
    bind_non_superuser_environment,
    database_uuid,
    request_context_from_mapping,
)


class OdooWritePrecheckError(ValueError):
    """An authenticated Odoo write precheck was rejected."""


_T = TypeVar("_T")


class _RollbackOnlyPrecheck(Exception):
    def __init__(self, value: Any) -> None:
        super().__init__("rollback-only precheck completed")
        self.value = value


def run_rollback_only_precheck(root_env: Any, callback: Callable[[], _T]) -> _T:
    """Return a precheck value only after its entire savepoint was rolled back."""

    savepoint = getattr(getattr(root_env, "cr", None), "savepoint", None)
    if not callable(savepoint):
        raise OdooWritePrecheckError(
            "Odoo cursor cannot enforce a rollback-only precheck"
        )
    try:
        with savepoint():
            value = callback()
            raise _RollbackOnlyPrecheck(value)
    except _RollbackOnlyPrecheck as completed:
        return completed.value


class WritePrecheckHandler(Protocol):
    def precheck(
        self, capability_id: str, parameters: dict[str, Any]
    ) -> Mapping[str, Any]: ...


REQUEST_FIELDS = frozenset(
    {"context", "capability_id", "parameters", "trusted_recovery_plan"}
)
CHANNELS = frozenset({"staged", "enabled"})
ENVIRONMENTS = frozenset({"test", "sandbox", "production"})
EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"
SHA256 = re.compile(r"[0-9a-f]{64}")
HANDLER_CORE_FIELDS = frozenset(
    {"capability_id", "company_id", "parameters_digest", "checks"}
)
HANDLER_FORBIDDEN_FIELDS = frozenset(
    {"passed", "handler_details", "runtime_binding", "registry_digest", "release_digest"}
)


def _digest(value: Any) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OdooWritePrecheckError(
            "write precheck content is not canonical JSON"
        ) from exc


def _validate_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise OdooWritePrecheckError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _validate_request(
    request: Any,
) -> tuple[Mapping[str, Any], str, dict[str, Any], Any]:
    if not isinstance(request, Mapping) or set(request) != REQUEST_FIELDS:
        raise OdooWritePrecheckError("write precheck request fields are invalid")
    capability_id = request["capability_id"]
    if not isinstance(capability_id, str) or not capability_id.strip():
        raise OdooWritePrecheckError("capability_id is required")
    parameters = request["parameters"]
    if not isinstance(parameters, dict):
        raise OdooWritePrecheckError("parameters must be an object")
    try:
        detached_parameters = json.loads(canonical_json(parameters))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OdooWritePrecheckError("parameters are not canonical JSON") from exc
    return (
        request["context"],
        capability_id,
        detached_parameters,
        request["trusted_recovery_plan"],
    )


def _trusted_recovery_plan(
    value: Any,
    *,
    capability_id: str,
    parameters: dict[str, Any],
    company_id: int,
) -> dict[str, Any] | None:
    if capability_id != "acct.recovery.execute.v1":
        if value is not None:
            raise OdooWritePrecheckError(
                "trusted recovery plan must be null for non-recovery prechecks"
            )
        return None
    if not isinstance(value, Mapping) or not value:
        raise OdooWritePrecheckError(
            "trusted recovery plan is required for recovery precheck"
        )
    try:
        plan = json.loads(canonical_json(value))
        validate_executable_recovery_plan(plan)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OdooWritePrecheckError("trusted recovery plan is invalid") from exc
    if (
        plan["origin_operation_id"] != parameters["origin_operation_id"]
        or plan["plan_digest"] != parameters["expected_recovery_plan_digest"]
    ):
        raise OdooWritePrecheckError(
            "trusted recovery plan is unavailable or outside the bound operation"
        )
    try:
        index_recovery_guard_graph(plan, expected_company_id=company_id)
    except ValueError as exc:
        raise OdooWritePrecheckError(
            "trusted recovery plan is unavailable or outside the bound operation"
        ) from exc
    return plan


def _select_capability(
    capabilities: tuple[Capability, ...],
    capability_id: str,
    context: RequestContext,
    capability_channel: str,
    parameters: dict[str, Any],
) -> Capability:
    if capability_channel not in CHANNELS:
        raise OdooWritePrecheckError("capability channel is invalid")
    if context.environment == "production" and capability_channel == "staged":
        raise OdooWritePrecheckError(
            "staged write prechecks cannot run in production"
        )
    matches = [item for item in capabilities if item.id == capability_id]
    if len(matches) != 1:
        raise OdooWritePrecheckError("write capability is unknown or duplicated")
    capability = matches[0]
    data = capability.data
    environment_field = (
        "enabled_environments"
        if capability_channel == "enabled"
        else "staged_environments"
    )
    if data["access"] != "write" or context.environment not in data.get(
        environment_field, []
    ):
        raise OdooWritePrecheckError(
            "write capability is not available in the bound environment and channel"
        )
    validate_value(parameters, data["input_schema"])
    validate_write_semantics(capability_id, parameters)
    if parameters.get("company_id") != context.company_id:
        raise OdooWritePrecheckError("write precheck company binding mismatch")
    return capability


def _assert_runtime_binding(
    context: RequestContext,
    *,
    actual_database_name: Any,
    actual_database_uuid: str,
    odoo_instance_id: str,
    environment: str,
) -> None:
    if (
        context.odoo_instance_id != odoo_instance_id
        or context.database_name != actual_database_name
        or context.database_uuid != actual_database_uuid
        or context.environment != environment
        or context.company_id not in context.allowed_company_ids
    ):
        raise OdooWritePrecheckError(
            "signed request does not match the Odoo instance, database, environment, or company"
        )


def _assert_executor_acl(bound_env: Any, capability: Capability) -> None:
    try:
        user = bound_env.user
        if getattr(user, "id", None) != getattr(bound_env, "uid", None):
            raise OdooWritePrecheckError("bound Odoo executor identity mismatch")
        if not user.has_group(EXECUTOR_GROUP):
            raise OdooWritePrecheckError("Odoo executor group is required")
        missing = [
            xml_id
            for xml_id in capability.data["odoo_permissions"]
            if not user.has_group(xml_id)
        ]
    except OdooWritePrecheckError:
        raise
    except (AttributeError, KeyError, TypeError) as exc:
        raise OdooWritePrecheckError("Odoo executor ACL could not be verified") from exc
    if missing:
        raise OdooWritePrecheckError(
            "Odoo capability ACL is missing: " + ", ".join(sorted(missing))
        )


def _default_handler_factory(
    bound_env: Any,
    context: RequestContext,
    observed_at: datetime,
    trusted_recovery_plan: Mapping[str, Any] | None,
) -> WritePrecheckHandler:
    from .write_handlers import OdooWriteContext, OdooWriteHandlers

    return OdooWriteHandlers(
        OdooWriteContext(
            env=bound_env,
            user_id=context.user_id,
            allowed_company_ids=context.allowed_company_ids,
            today=observed_at.date(),
            trusted_recovery_plan=trusted_recovery_plan,
        )
    )


def canonical_precheck_evidence(
    raw: Any,
    *,
    capability_id: str,
    company_id: int,
    parameters: dict[str, Any],
    context: RequestContext,
    actual_database_name: str,
    actual_database_uuid: str,
    capability_channel: str,
    registry_sha256: str,
    release_digest: str,
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise OdooWritePrecheckError("Odoo handler precheck evidence must be an object")
    result = dict(raw)
    if set(result) & HANDLER_FORBIDDEN_FIELDS:
        raise OdooWritePrecheckError(
            "Odoo handler precheck evidence contains reserved fields"
        )
    parameters_digest = _digest(parameters)
    if (
        result.get("capability_id") != capability_id
        or result.get("company_id") != company_id
        or result.get("parameters_digest") != parameters_digest
    ):
        raise OdooWritePrecheckError(
            "Odoo handler precheck evidence binding mismatch"
        )
    checks = result.get("checks")
    if (
        not isinstance(checks, list)
        or not checks
        or any(not isinstance(item, str) or not item.strip() for item in checks)
        or checks != sorted(set(checks))
    ):
        raise OdooWritePrecheckError(
            "Odoo handler precheck checks must be non-empty, unique, and sorted"
        )
    handler_details = {
        key: value for key, value in result.items() if key not in HANDLER_CORE_FIELDS
    }
    evidence = {
        "capability_id": capability_id,
        "company_id": company_id,
        "parameters_digest": parameters_digest,
        "passed": True,
        "checks": checks,
        "handler_details": handler_details,
        "runtime_binding": {
            "user_id": context.user_id,
            "odoo_instance_id": context.odoo_instance_id,
            "database_name": actual_database_name,
            "database_uuid": actual_database_uuid,
            "environment": context.environment,
            "capability_channel": capability_channel,
        },
        "registry_digest": registry_sha256,
        "release_digest": release_digest,
    }
    try:
        canonical = canonical_json(evidence)
        detached = json.loads(canonical)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise OdooWritePrecheckError(
            "Odoo handler precheck evidence is not canonical JSON"
        ) from exc
    if not isinstance(detached, dict):
        raise OdooWritePrecheckError("Odoo handler precheck evidence is invalid")
    return detached


def execute_write_precheck_from_odoo_shell(
    root_env: Any,
    request: Any,
    *,
    capabilities: Iterable[Capability],
    auth_secret: bytes,
    auth_key_id: str,
    expected_registry_digest: str,
    release_digest: str,
    odoo_instance_id: str,
    environment: str,
    capability_channel: str,
    now: datetime | None = None,
    environment_factory: Callable[[Any, int, dict[str, Any]], Any] | None = None,
    handler_factory: Callable[..., WritePrecheckHandler] | None = None,
) -> dict[str, Any]:
    """Run one authenticated, policy-bound, read-only Odoo write precheck."""

    try:
        (
            raw_context,
            capability_id,
            parameters,
            raw_recovery_plan,
        ) = _validate_request(request)
        observed_at = now or datetime.now(timezone.utc)
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise OdooWritePrecheckError(
                "write precheck current time must include a timezone"
            )
        if not isinstance(odoo_instance_id, str) or not odoo_instance_id.strip():
            raise OdooWritePrecheckError("Odoo instance ID is required")
        if environment not in ENVIRONMENTS:
            raise OdooWritePrecheckError("runtime environment is invalid")

        release_sha256 = _validate_digest(release_digest, "release digest")
        expected_registry_sha256 = _validate_digest(
            expected_registry_digest, "expected registry digest"
        )
        capability_list = tuple(capabilities)
        if (
            not capability_list
            or any(not isinstance(item, Capability) for item in capability_list)
            or len({item.id for item in capability_list}) != len(capability_list)
        ):
            raise OdooWritePrecheckError(
                "validated capabilities must be non-empty and unique"
            )
        actual_registry_sha256 = registry_digest(capability_list)
        if not hmac.compare_digest(
            expected_registry_sha256, actual_registry_sha256
        ):
            raise OdooWritePrecheckError("runtime registry digest mismatch")

        context = request_context_from_mapping(raw_context)
        actual_database_name = getattr(getattr(root_env, "cr", None), "dbname", None)
        if not isinstance(actual_database_name, str) or not actual_database_name:
            raise OdooWritePrecheckError("Odoo database name is missing")
        actual_database_uuid = database_uuid(root_env)
        _assert_runtime_binding(
            context,
            actual_database_name=actual_database_name,
            actual_database_uuid=actual_database_uuid,
            odoo_instance_id=odoo_instance_id,
            environment=environment,
        )
        verify_request_context(
            context,
            now=observed_at,
            secret=auth_secret,
            expected_key_id=auth_key_id,
        )
        expected_request_digest = authentication_request_digest(
            capability_id, parameters
        )
        if not hmac.compare_digest(
            context.auth_request_digest, expected_request_digest
        ):
            raise OdooWritePrecheckError(
                "signed write precheck request digest mismatch"
            )

        capability = _select_capability(
            capability_list,
            capability_id,
            context,
            capability_channel,
            parameters,
        )
        trusted_recovery_plan = _trusted_recovery_plan(
            raw_recovery_plan,
            capability_id=capability_id,
            parameters=parameters,
            company_id=context.company_id,
        )
        bound_env = bind_non_superuser_environment(
            root_env,
            context,
            environment_factory=environment_factory,
        )
        _assert_executor_acl(bound_env, capability)
        if handler_factory is None:
            handler = _default_handler_factory(
                bound_env, context, observed_at, trusted_recovery_plan
            )
        elif trusted_recovery_plan is None:
            handler = handler_factory(bound_env, context, observed_at)
        else:
            handler = handler_factory(
                bound_env, context, observed_at, trusted_recovery_plan
            )
        return run_rollback_only_precheck(
            root_env,
            lambda: canonical_precheck_evidence(
                handler.precheck(capability_id, parameters),
                capability_id=capability_id,
                company_id=context.company_id,
                parameters=parameters,
                context=context,
                actual_database_name=actual_database_name,
                actual_database_uuid=actual_database_uuid,
                capability_channel=capability_channel,
                registry_sha256=actual_registry_sha256,
                release_digest=release_sha256,
            ),
        )
    except OdooWritePrecheckError:
        raise
    except Exception as exc:
        raise OdooWritePrecheckError(
            "Odoo write precheck failed closed"
        ) from exc


__all__ = [
    "OdooWritePrecheckError",
    "canonical_precheck_evidence",
    "execute_write_precheck_from_odoo_shell",
    "run_rollback_only_precheck",
]

"""Fail-closed Odoo shell bootstrap for signed read requests."""

from __future__ import annotations

import json
import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from ..auth import authentication_request_digest, verify_request_context
from ..gateway import CapabilityGateway, RequestContext
from ..operations import canonical_json
from ..registry import Capability
from .executor import OdooReadExecutor
from .read_transaction import run_readonly_odoo_transaction


class OdooBootstrapError(ValueError):
    pass


CONTEXT_FIELDS = {
    "allowed_company_ids",
    "audience",
    "auth_expires_at",
    "auth_issued_at",
    "auth_key_id",
    "auth_request_digest",
    "auth_signature",
    "auth_signature_purpose",
    "auth_signature_version",
    "auth_token_id",
    "company_id",
    "database_name",
    "database_uuid",
    "environment",
    "odoo_instance_id",
    "principal",
    "user_id",
}
REQUEST_FIELDS = {"capability_id", "context", "parameters"}


def _parse_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise OdooBootstrapError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OdooBootstrapError(f"{field} must be an RFC 3339 string") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OdooBootstrapError(f"{field} must include a timezone")
    return parsed


def request_context_from_mapping(value: Any) -> RequestContext:
    if not isinstance(value, Mapping) or set(value) != CONTEXT_FIELDS:
        raise OdooBootstrapError("request context fields are invalid")
    allowed = value["allowed_company_ids"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or any(isinstance(item, bool) or not isinstance(item, int) or item <= 0 for item in allowed)
        or len(allowed) != len(set(allowed))
    ):
        raise OdooBootstrapError("allowed_company_ids must contain unique positive integers")
    return RequestContext(
        audience=value["audience"],
        auth_token_id=value["auth_token_id"],
        auth_issued_at=_parse_datetime(value["auth_issued_at"], "auth_issued_at"),
        auth_expires_at=_parse_datetime(value["auth_expires_at"], "auth_expires_at"),
        auth_signature_version=value["auth_signature_version"],
        auth_signature_purpose=value["auth_signature_purpose"],
        auth_key_id=value["auth_key_id"],
        auth_request_digest=value["auth_request_digest"],
        auth_signature=value["auth_signature"],
        principal=value["principal"],
        odoo_instance_id=value["odoo_instance_id"],
        database_name=value["database_name"],
        database_uuid=value["database_uuid"],
        user_id=value["user_id"],
        company_id=value["company_id"],
        allowed_company_ids=frozenset(allowed),
        environment=value["environment"],
    )


def database_uuid(root_env: Any) -> str:
    """Read immutable database identity before dropping shell privileges."""
    try:
        value = root_env["ir.config_parameter"].get_param("database.uuid")
        return str(uuid.UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise OdooBootstrapError("Odoo database UUID is missing or invalid") from exc


def _default_environment_factory(cr: Any, uid: int, context: dict[str, Any]) -> Any:
    from odoo.api import Environment  # Imported only inside an Odoo runtime.

    return Environment(cr, uid, context, su=False)


def bind_non_superuser_environment(
    root_env: Any,
    context: RequestContext,
    *,
    environment_factory: Callable[[Any, int, dict[str, Any]], Any] | None = None,
) -> Any:
    if context.user_id == 1:
        raise OdooBootstrapError("Odoo superuser cannot execute accounting capabilities")
    allowed_company_ids = [
        context.company_id,
        *sorted(context.allowed_company_ids - {context.company_id}),
    ]
    factory = environment_factory or _default_environment_factory
    bound_env = factory(
        root_env.cr,
        context.user_id,
        {"allowed_company_ids": allowed_company_ids},
    )
    if getattr(bound_env, "su", False) or getattr(bound_env, "uid", None) != context.user_id:
        raise OdooBootstrapError("failed to construct a bound non-superuser environment")
    user = bound_env["res.users"].browse(context.user_id).exists()
    if not user or len(user) != 1 or not user.active:
        raise OdooBootstrapError("bound Odoo user is missing or inactive")
    actual_company_ids = frozenset(int(item) for item in user.company_ids.ids)
    if not context.allowed_company_ids.issubset(actual_company_ids):
        raise OdooBootstrapError("signed allowed companies exceed the Odoo user companies")
    if context.company_id not in actual_company_ids:
        raise OdooBootstrapError("signed company is not assigned to the Odoo user")
    return bound_env


def _validate_request_document(value: Any) -> tuple[str, Mapping[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != REQUEST_FIELDS:
        raise OdooBootstrapError("read request fields are invalid")
    capability_id = value["capability_id"]
    parameters = value["parameters"]
    if not isinstance(capability_id, str) or not capability_id:
        raise OdooBootstrapError("capability_id is required")
    if not isinstance(parameters, dict):
        raise OdooBootstrapError("parameters must be an object")
    return capability_id, value["context"], parameters


def _execute_read_from_hardened_odoo_shell(
    root_env: Any,
    request: Any,
    *,
    capabilities: Iterable[Capability],
    auth_secret: bytes,
    auth_key_id: str,
    consume_auth_token: Callable[[str, str, datetime, datetime], bool],
    receipt_secret: bytes,
    receipt_key_id: str,
    consume_receipt: Callable[[str, str, datetime, datetime], bool],
    release_digest: str,
    odoo_instance_id: str,
    environment: str,
    capability_channel: str = "enabled",
    now: datetime | None = None,
    environment_factory: Callable[[Any, int, dict[str, Any]], Any] | None = None,
    executor_factory: Callable[..., OdooReadExecutor] = OdooReadExecutor,
) -> dict[str, Any]:
    """Execute one read after the caller has hardened the Odoo cursor."""
    if not callable(consume_auth_token) or not callable(consume_receipt):
        raise OdooBootstrapError("durable request and receipt replay stores are required")
    capability_list = tuple(capabilities)
    capability_id, raw_context, parameters = _validate_request_document(request)
    context = request_context_from_mapping(raw_context)
    observed_at = now or datetime.now(timezone.utc)
    actual_database_name = getattr(getattr(root_env, "cr", None), "dbname", None)
    actual_database_uuid = database_uuid(root_env)
    if (
        context.odoo_instance_id != odoo_instance_id
        or context.database_name != actual_database_name
        or context.database_uuid != actual_database_uuid
        or context.environment != environment
    ):
        raise OdooBootstrapError("signed request does not match the Odoo runtime")
    verify_request_context(
        context,
        now=observed_at,
        secret=auth_secret,
        expected_key_id=auth_key_id,
    )
    expected_content_digest = authentication_request_digest(
        capability_id, parameters
    )
    if not hmac.compare_digest(
        context.auth_request_digest, expected_content_digest
    ):
        raise OdooBootstrapError("signed request content digest mismatch")
    bound_env = bind_non_superuser_environment(
        root_env,
        context,
        environment_factory=environment_factory,
    )

    request_digest = hashlib.sha256(canonical_json(request)).hexdigest()
    request_consumed = False

    def authenticate(candidate: RequestContext) -> bool:
        nonlocal request_consumed
        if candidate != context:
            return False
        verify_request_context(
            candidate,
            now=observed_at,
            secret=auth_secret,
            expected_key_id=auth_key_id,
        )
        if not request_consumed:
            if not consume_auth_token(
                candidate.auth_token_id,
                request_digest,
                candidate.auth_expires_at,
                observed_at,
            ):
                return False
            request_consumed = True
        return True

    def acl_check(
        candidate: RequestContext,
        capability: Capability,
        _parameters: dict[str, Any] | None,
    ) -> bool:
        if candidate != context:
            return False
        user = bound_env.user
        return all(user.has_group(xml_id) for xml_id in capability.data["odoo_permissions"])

    executor = executor_factory(
        bound_env,
        capabilities=capability_list,
        odoo_instance_id=odoo_instance_id,
        database_name=actual_database_name,
        database_uuid=actual_database_uuid,
        release_digest=release_digest,
        environment=environment,
        capability_channel=capability_channel,
        receipt_secret=receipt_secret,
        receipt_key_id=receipt_key_id,
        consume_receipt=consume_receipt,
        now=lambda: observed_at,
    )
    gateway = CapabilityGateway(
        capability_list,
        release_digest=release_digest,
        authenticate_context=authenticate,
        acl_check=acl_check,
        read_executor=executor,
        read_receipt_verifier=executor.verify,
        availability_channel=capability_channel,
    )
    return gateway.read(context, capability_id, parameters)


def execute_read_from_odoo_shell(
    root_env: Any,
    request: Any,
    *,
    capabilities: Iterable[Capability],
    auth_secret: bytes,
    auth_key_id: str,
    consume_auth_token: Callable[[str, str, datetime, datetime], bool],
    receipt_secret: bytes,
    receipt_key_id: str,
    consume_receipt: Callable[[str, str, datetime, datetime], bool],
    release_digest: str,
    odoo_instance_id: str,
    environment: str,
    capability_channel: str = "enabled",
    now: datetime | None = None,
    environment_factory: Callable[[Any, int, dict[str, Any]], Any] | None = None,
    executor_factory: Callable[..., OdooReadExecutor] = OdooReadExecutor,
) -> dict[str, Any]:
    """Execute one signed read inside a proven rollback-only Odoo transaction."""

    return run_readonly_odoo_transaction(
        root_env,
        lambda: _execute_read_from_hardened_odoo_shell(
            root_env,
            request,
            capabilities=capabilities,
            auth_secret=auth_secret,
            auth_key_id=auth_key_id,
            consume_auth_token=consume_auth_token,
            receipt_secret=receipt_secret,
            receipt_key_id=receipt_key_id,
            consume_receipt=consume_receipt,
            release_digest=release_digest,
            odoo_instance_id=odoo_instance_id,
            environment=environment,
            capability_channel=capability_channel,
            now=now,
            environment_factory=environment_factory,
            executor_factory=executor_factory,
        ),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OdooBootstrapError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def execute_read_json(root_env: Any, request_json: str, **kwargs: Any) -> str:
    """JSON-only wrapper suitable for a controlled Odoo shell bootstrap."""
    try:
        request = json.loads(request_json, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise OdooBootstrapError("request is not valid JSON") from exc
    result = execute_read_from_odoo_shell(root_env, request, **kwargs)
    return canonical_json(result).decode("utf-8")

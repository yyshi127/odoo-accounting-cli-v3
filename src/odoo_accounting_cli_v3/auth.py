"""Short-lived signed identity/company bindings for Pi-to-V3 requests."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .gateway import (
    AUTH_SIGNATURE_PURPOSE,
    AUTH_SIGNATURE_VERSION,
    WRITE_AUTH_SIGNATURE_PURPOSE,
    WRITE_AUTH_SIGNATURE_VERSION,
    RequestContext,
)
from .operations import canonical_json


class AuthenticationError(ValueError):
    pass


MAX_CONTEXT_TTL = timedelta(minutes=5)
DEFAULT_AUDIENCE = "odoo-accounting-cli-v3"
AUTH_CONTEXT_PURPOSE = AUTH_SIGNATURE_PURPOSE
SIGNATURE_VERSION = AUTH_SIGNATURE_VERSION
WRITE_ACTION_CONTEXT_PURPOSE = WRITE_AUTH_SIGNATURE_PURPOSE
WRITE_ACTION_SIGNATURE_VERSION = WRITE_AUTH_SIGNATURE_VERSION
WRITE_ACTIONS = frozenset(
    {
        "operation.prepare",
        "operation.preview",
        "operation.approve_execute",
        "operation.status",
        "operation.result",
        "operation.recover",
    }
)
MIN_HMAC_SECRET_BYTES = 32


def _require_hmac_secret(secret: object) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < MIN_HMAC_SECRET_BYTES:
        raise AuthenticationError("authentication HMAC secret must be bytes of at least 32 bytes")
    return secret


def context_payload(context: RequestContext) -> dict[str, object]:
    return {
        "allowed_company_ids": sorted(context.allowed_company_ids),
        "audience": context.audience,
        "auth_expires_at": context.auth_expires_at.astimezone(timezone.utc).isoformat(),
        "auth_issued_at": context.auth_issued_at.astimezone(timezone.utc).isoformat(),
        "auth_key_id": context.auth_key_id,
        "auth_request_digest": context.auth_request_digest,
        "auth_signature_purpose": context.auth_signature_purpose,
        "auth_signature_version": context.auth_signature_version,
        "auth_token_id": context.auth_token_id,
        "company_id": context.company_id,
        "database_name": context.database_name,
        "database_uuid": context.database_uuid,
        "environment": context.environment,
        "principal": context.principal,
        "odoo_instance_id": context.odoo_instance_id,
        "user_id": context.user_id,
    }


def _signature_payload(context: RequestContext) -> dict[str, object]:
    return context_payload(context)


def authentication_request_digest(
    capability_id: str, parameters: dict[str, object]
) -> str:
    if not isinstance(capability_id, str) or not capability_id.strip():
        raise AuthenticationError("authentication capability ID is required")
    if not isinstance(parameters, dict):
        raise AuthenticationError("authentication request parameters must be an object")
    try:
        payload = canonical_json(
            {"capability_id": capability_id, "parameters": parameters}
        )
    except (TypeError, ValueError) as exc:
        raise AuthenticationError("authentication request content is invalid") from exc
    return hashlib.sha256(payload).hexdigest()


def write_action_request_digest(action: str, request: dict[str, object]) -> str:
    if not isinstance(action, str) or action not in WRITE_ACTIONS:
        raise AuthenticationError("unsupported write action")
    if not isinstance(request, dict):
        raise AuthenticationError("write action request must be an object")
    if "context" in request:
        raise AuthenticationError("write action request must exclude context")
    try:
        payload = canonical_json({"action": action, "request": request})
    except (TypeError, ValueError) as exc:
        raise AuthenticationError("write action request content is invalid") from exc
    return hashlib.sha256(payload).hexdigest()


def _sign_context(
    *,
    auth_token_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    user_id: int,
    company_id: int,
    allowed_company_ids: frozenset[int],
    environment: str,
    request_digest: str,
    signature_version: int,
    signature_purpose: str,
    issued_at: datetime,
    expires_at: datetime,
    key_id: str,
    secret: bytes,
    audience: str,
) -> RequestContext:
    secret = _require_hmac_secret(secret)
    if not isinstance(key_id, str) or not key_id.strip():
        raise AuthenticationError("authentication key ID is required")
    if expires_at - issued_at > MAX_CONTEXT_TTL:
        raise AuthenticationError("authentication context exceeds maximum TTL")
    unsigned = RequestContext(
        audience=audience,
        auth_token_id=auth_token_id,
        auth_issued_at=issued_at,
        auth_expires_at=expires_at,
        auth_signature_version=signature_version,
        auth_signature_purpose=signature_purpose,
        auth_key_id=key_id,
        auth_request_digest=request_digest,
        auth_signature="0" * 64,
        principal=principal,
        odoo_instance_id=odoo_instance_id,
        database_name=database_name,
        database_uuid=database_uuid,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=allowed_company_ids,
        environment=environment,
    )
    signature = hmac.new(
        secret, canonical_json(_signature_payload(unsigned)), hashlib.sha256
    ).hexdigest()
    return replace(unsigned, auth_signature=signature)


def sign_request_context(
    *,
    auth_token_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    user_id: int,
    company_id: int,
    allowed_company_ids: frozenset[int],
    environment: str,
    capability_id: str,
    parameters: dict[str, object],
    issued_at: datetime,
    expires_at: datetime,
    key_id: str,
    secret: bytes,
    audience: str = DEFAULT_AUDIENCE,
) -> RequestContext:
    return _sign_context(
        audience=audience,
        auth_token_id=auth_token_id,
        principal=principal,
        odoo_instance_id=odoo_instance_id,
        database_name=database_name,
        database_uuid=database_uuid,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=allowed_company_ids,
        environment=environment,
        request_digest=authentication_request_digest(capability_id, parameters),
        signature_version=SIGNATURE_VERSION,
        signature_purpose=AUTH_CONTEXT_PURPOSE,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=key_id,
        secret=secret,
    )


def sign_write_action_context(
    *,
    auth_token_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    user_id: int,
    company_id: int,
    allowed_company_ids: frozenset[int],
    environment: str,
    action: str,
    request: dict[str, object],
    issued_at: datetime,
    expires_at: datetime,
    key_id: str,
    secret: bytes,
    audience: str = DEFAULT_AUDIENCE,
) -> RequestContext:
    return _sign_context(
        audience=audience,
        auth_token_id=auth_token_id,
        principal=principal,
        odoo_instance_id=odoo_instance_id,
        database_name=database_name,
        database_uuid=database_uuid,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=allowed_company_ids,
        environment=environment,
        request_digest=write_action_request_digest(action, request),
        signature_version=WRITE_ACTION_SIGNATURE_VERSION,
        signature_purpose=WRITE_ACTION_CONTEXT_PURPOSE,
        issued_at=issued_at,
        expires_at=expires_at,
        key_id=key_id,
        secret=secret,
    )


def _verify_context_signature(
    context: RequestContext,
    *,
    now: datetime,
    secret: bytes,
    expected_key_id: str,
    expected_signature_version: int,
    expected_signature_purpose: str,
    protocol_name: str,
    audience: str,
) -> None:
    secret = _require_hmac_secret(secret)
    if not isinstance(expected_key_id, str) or not expected_key_id.strip():
        raise AuthenticationError("authentication expected key ID is required")
    if now.tzinfo is None or now.utcoffset() is None:
        raise AuthenticationError("timezone-aware current time is required")
    if context.audience != audience:
        raise AuthenticationError("authentication audience mismatch")
    if context.auth_signature_version != expected_signature_version:
        raise AuthenticationError(f"{protocol_name} signature version mismatch")
    if context.auth_signature_purpose != expected_signature_purpose:
        raise AuthenticationError(f"{protocol_name} signature purpose mismatch")
    if context.auth_key_id != expected_key_id:
        raise AuthenticationError("authentication key ID mismatch")
    if context.auth_expires_at - context.auth_issued_at > MAX_CONTEXT_TTL:
        raise AuthenticationError("authentication context exceeds maximum TTL")
    if now < context.auth_issued_at or now >= context.auth_expires_at:
        raise AuthenticationError("authentication context is not currently valid")
    expected = hmac.new(
        secret, canonical_json(_signature_payload(context)), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, context.auth_signature):
        raise AuthenticationError("authentication signature mismatch")


def verify_request_context(
    context: RequestContext,
    *,
    now: datetime,
    secret: bytes,
    expected_key_id: str,
    audience: str = DEFAULT_AUDIENCE,
) -> bool:
    _verify_context_signature(
        context,
        now=now,
        secret=secret,
        expected_key_id=expected_key_id,
        expected_signature_version=SIGNATURE_VERSION,
        expected_signature_purpose=AUTH_CONTEXT_PURPOSE,
        protocol_name="authentication",
        audience=audience,
    )
    return True


def verify_write_action_context(
    context: RequestContext,
    *,
    action: str,
    request: dict[str, object],
    now: datetime,
    secret: bytes,
    expected_key_id: str,
    audience: str = DEFAULT_AUDIENCE,
) -> bool:
    _verify_context_signature(
        context,
        now=now,
        secret=secret,
        expected_key_id=expected_key_id,
        expected_signature_version=WRITE_ACTION_SIGNATURE_VERSION,
        expected_signature_purpose=WRITE_ACTION_CONTEXT_PURPOSE,
        protocol_name="write action context",
        audience=audience,
    )
    expected_digest = write_action_request_digest(action, request)
    if not hmac.compare_digest(expected_digest, context.auth_request_digest):
        raise AuthenticationError("write action request digest mismatch")
    return True

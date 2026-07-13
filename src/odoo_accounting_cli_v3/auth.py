"""Short-lived signed identity/company bindings for Pi-to-V3 requests."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from .gateway import RequestContext
from .operations import canonical_json


class AuthenticationError(ValueError):
    pass


MAX_CONTEXT_TTL = timedelta(minutes=5)
DEFAULT_AUDIENCE = "odoo-accounting-cli-v3"


def context_payload(context: RequestContext) -> dict[str, object]:
    return {
        "allowed_company_ids": sorted(context.allowed_company_ids),
        "audience": context.audience,
        "auth_expires_at": context.auth_expires_at.astimezone(timezone.utc).isoformat(),
        "auth_issued_at": context.auth_issued_at.astimezone(timezone.utc).isoformat(),
        "auth_token_id": context.auth_token_id,
        "company_id": context.company_id,
        "database_name": context.database_name,
        "database_uuid": context.database_uuid,
        "environment": context.environment,
        "principal": context.principal,
        "odoo_instance_id": context.odoo_instance_id,
        "user_id": context.user_id,
    }


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
    issued_at: datetime,
    expires_at: datetime,
    secret: bytes,
    audience: str = DEFAULT_AUDIENCE,
) -> RequestContext:
    if not secret:
        raise AuthenticationError("authentication signing secret is required")
    if expires_at - issued_at > MAX_CONTEXT_TTL:
        raise AuthenticationError("authentication context exceeds maximum TTL")
    unsigned = RequestContext(
        audience=audience,
        auth_token_id=auth_token_id,
        auth_issued_at=issued_at,
        auth_expires_at=expires_at,
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
    signature = hmac.new(secret, canonical_json(context_payload(unsigned)), hashlib.sha256).hexdigest()
    return replace(unsigned, auth_signature=signature)


def verify_request_context(
    context: RequestContext,
    *,
    now: datetime,
    secret: bytes,
    audience: str = DEFAULT_AUDIENCE,
) -> bool:
    if not secret or now.tzinfo is None or now.utcoffset() is None:
        raise AuthenticationError("authentication secret and timezone-aware current time are required")
    if context.audience != audience:
        raise AuthenticationError("authentication audience mismatch")
    if context.auth_expires_at - context.auth_issued_at > MAX_CONTEXT_TTL:
        raise AuthenticationError("authentication context exceeds maximum TTL")
    if now < context.auth_issued_at or now >= context.auth_expires_at:
        raise AuthenticationError("authentication context is not currently valid")
    expected = hmac.new(secret, canonical_json(context_payload(context)), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, context.auth_signature):
        raise AuthenticationError("authentication signature mismatch")
    return True

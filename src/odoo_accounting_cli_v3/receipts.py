"""Signed, content-bound receipts emitted only by trusted execution adapters."""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .operations import canonical_json


class ReceiptError(ValueError):
    pass


SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_READ_RECEIPT_AGE = timedelta(minutes=5)
READ_RECEIPT_PURPOSE = "read_receipt_v1"
SIGNATURE_VERSION = 1
MIN_HMAC_SECRET_BYTES = 32


def _require_hmac_secret(secret: object) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < MIN_HMAC_SECRET_BYTES:
        raise ReceiptError("read receipt HMAC secret must be bytes of at least 32 bytes")
    return secret


def _signature_payload(unsigned: dict[str, Any]) -> dict[str, Any]:
    return unsigned


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _aware(value: Any) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def read_request_digest(
    *,
    capability_id: str,
    parameters: dict[str, Any],
    auth_token_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    company_id: int,
    user_id: int,
    registry_digest: str,
    release_digest: str,
) -> str:
    return _digest(
        {
            "capability_id": capability_id,
            "auth_token_id": auth_token_id,
            "company_id": company_id,
            "database_name": database_name,
            "database_uuid": str(uuid.UUID(database_uuid)),
            "parameters": parameters,
            "principal": principal,
            "odoo_instance_id": odoo_instance_id,
            "registry_digest": registry_digest,
            "release_digest": release_digest,
            "user_id": user_id,
        }
    )


def create_read_receipt(
    *,
    receipt_id: str,
    capability_id: str,
    parameters: dict[str, Any],
    result_body: dict[str, Any],
    auth_token_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    company_id: int,
    user_id: int,
    registry_digest: str,
    release_digest: str,
    record_count: int,
    observed_at: datetime,
    key_id: str,
    secret: bytes,
) -> dict[str, Any]:
    secret = _require_hmac_secret(secret)
    if (
        not isinstance(receipt_id, str)
        or not receipt_id
        or not isinstance(auth_token_id, str)
        or not auth_token_id
        or not capability_id
        or not principal
    ):
        raise ReceiptError("receipt identity, capability, and principal are required")
    if not isinstance(key_id, str) or not key_id.strip():
        raise ReceiptError("read receipt key ID is required")
    if (
        isinstance(company_id, bool)
        or not isinstance(company_id, int)
        or company_id <= 0
        or isinstance(user_id, bool)
        or not isinstance(user_id, int)
        or user_id <= 0
        or isinstance(record_count, bool)
        or not isinstance(record_count, int)
        or record_count < 0
    ):
        raise ReceiptError("receipt numeric bindings are invalid")
    if not _aware(observed_at):
        raise ReceiptError("receipt timestamp must be timezone-aware")
    if not SHA256.fullmatch(registry_digest) or not SHA256.fullmatch(release_digest):
        raise ReceiptError("receipt runtime digests are invalid")
    normalized_database_uuid = str(uuid.UUID(database_uuid))
    unsigned = {
        "id": receipt_id,
        "odoo_instance_id": odoo_instance_id,
        "database_name": database_name,
        "database_uuid": normalized_database_uuid,
        "company_id": company_id,
        "user_id": user_id,
        "capability_id": capability_id,
        "request_digest": read_request_digest(
            capability_id=capability_id,
            parameters=parameters,
            auth_token_id=auth_token_id,
            principal=principal,
            odoo_instance_id=odoo_instance_id,
            database_name=database_name,
            database_uuid=normalized_database_uuid,
            company_id=company_id,
            user_id=user_id,
            registry_digest=registry_digest,
            release_digest=release_digest,
        ),
        "result_digest": _digest(result_body),
        "registry_digest": registry_digest,
        "release_digest": release_digest,
        "record_count": record_count,
        "observed_at": observed_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "signature_version": SIGNATURE_VERSION,
        "signature_purpose": READ_RECEIPT_PURPOSE,
        "signature_key_id": key_id,
    }
    return {
        **unsigned,
        "signature": hmac.new(
            secret, canonical_json(_signature_payload(unsigned)), hashlib.sha256
        ).hexdigest(),
    }


def verify_read_receipt(
    receipt: dict[str, Any],
    *,
    capability_id: str,
    parameters: dict[str, Any],
    result_body: dict[str, Any],
    auth_token_id: str,
    principal: str,
    odoo_instance_id: str,
    database_name: str,
    database_uuid: str,
    company_id: int,
    user_id: int,
    registry_digest: str,
    release_digest: str,
    expected_record_count: int,
    now: datetime,
    consume_receipt: Callable[[str, str, datetime, datetime], bool],
    expected_key_id: str,
    secret: bytes,
) -> None:
    secret = _require_hmac_secret(secret)
    if not isinstance(expected_key_id, str) or not expected_key_id.strip():
        raise ReceiptError("read receipt expected key ID is required")
    expected_fields = {
        "capability_id",
        "company_id",
        "database_name",
        "database_uuid",
        "id",
        "observed_at",
        "odoo_instance_id",
        "record_count",
        "registry_digest",
        "release_digest",
        "request_digest",
        "result_digest",
        "signature",
        "signature_key_id",
        "signature_purpose",
        "signature_version",
        "user_id",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_fields:
        raise ReceiptError("read receipt fields are invalid")
    if (
        not _aware(now)
        or not callable(consume_receipt)
        or isinstance(expected_record_count, bool)
        or not isinstance(expected_record_count, int)
        or expected_record_count < 0
    ):
        raise ReceiptError("read receipt verification context is invalid")
    if type(receipt["signature_version"]) is not int or receipt["signature_version"] != SIGNATURE_VERSION:
        raise ReceiptError("read receipt signature version mismatch")
    if receipt["signature_purpose"] != READ_RECEIPT_PURPOSE:
        raise ReceiptError("read receipt signature purpose mismatch")
    if receipt["signature_key_id"] != expected_key_id:
        raise ReceiptError("read receipt signature key ID mismatch")
    if (
        not isinstance(receipt["id"], str)
        or not receipt["id"]
        or isinstance(receipt["record_count"], bool)
        or not isinstance(receipt["record_count"], int)
        or receipt["record_count"] != expected_record_count
    ):
        raise ReceiptError("read receipt identity or record count is invalid")
    try:
        observed_at = datetime.fromisoformat(
            receipt["observed_at"].replace("Z", "+00:00")
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ReceiptError("read receipt timestamp is invalid") from exc
    if (
        not _aware(observed_at)
        or observed_at > now
        or now - observed_at > MAX_READ_RECEIPT_AGE
    ):
        raise ReceiptError("read receipt is stale or from the future")
    bindings = (
        receipt["capability_id"] == capability_id
        and receipt["odoo_instance_id"] == odoo_instance_id
        and receipt["database_name"] == database_name
        and receipt["database_uuid"] == str(uuid.UUID(database_uuid))
        and receipt["company_id"] == company_id
        and receipt["user_id"] == user_id
        and receipt["registry_digest"] == registry_digest
        and receipt["release_digest"] == release_digest
    )
    if not bindings:
        raise ReceiptError("read receipt binding mismatch")
    expected_request = read_request_digest(
        capability_id=capability_id,
        parameters=parameters,
        auth_token_id=auth_token_id,
        principal=principal,
        odoo_instance_id=odoo_instance_id,
        database_name=database_name,
        database_uuid=database_uuid,
        company_id=company_id,
        user_id=user_id,
        registry_digest=registry_digest,
        release_digest=release_digest,
    )
    if receipt["request_digest"] != expected_request or receipt["result_digest"] != _digest(result_body):
        raise ReceiptError("read receipt content digest mismatch")
    signature = receipt["signature"]
    if not isinstance(signature, str) or not SHA256.fullmatch(signature):
        raise ReceiptError("read receipt signature is invalid")
    unsigned = {key: value for key, value in receipt.items() if key != "signature"}
    expected_signature = hmac.new(
        secret, canonical_json(_signature_payload(unsigned)), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise ReceiptError("read receipt signature mismatch")
    if not consume_receipt(
        receipt["id"], receipt["request_digest"], observed_at, now
    ):
        raise ReceiptError("read receipt was already consumed")

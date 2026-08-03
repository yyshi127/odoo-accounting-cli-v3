"""Read-only reconstruction of already verified Pi business results."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .auth import authentication_request_digest
from .operations import State, canonical_json
from .persistence import SQLitePersistence
from .trusted_authority import TrustedSession
from .trusted_broker import TrustedDeliveredResult
from .write_receipts import (
    RESULT_BODY_FIELDS,
    create_write_audit_receipt,
    validate_write_result_body,
    verify_write_audit_receipt,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CAPABILITY_ID = re.compile(
    r"acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*\Z"
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIAGNOSTICS_CAPABILITY_ID = "acct.diagnostics.operation_read.v1"
_LOCATOR_FIELDS = {
    "action",
    "business_succeeded",
    "capability_id",
    "operation_id",
    "receipt_id",
    "result_digest",
    "status",
}


class TrustedResultDeliveryError(ValueError):
    """Persisted evidence could not prove one exact verified result."""


@dataclass(frozen=True, slots=True)
class ResultDeliveryRoute:
    release_digest: str
    registry_digest: str
    capability_channel: str
    write_receipt_key_id: str
    write_receipt_secret: bytes = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.release_digest) is not str
            or _SHA256.fullmatch(self.release_digest) is None
            or type(self.registry_digest) is not str
            or _SHA256.fullmatch(self.registry_digest) is None
            or self.capability_channel not in {"staged", "enabled"}
            or type(self.write_receipt_key_id) is not str
            or not self.write_receipt_key_id
            or type(self.write_receipt_secret) is not bytes
            or len(self.write_receipt_secret) < 32
        ):
            raise TrustedResultDeliveryError(
                "result delivery route is invalid"
            )


class TrustedResultDeliveryResolver:
    """Resolve only retained verified evidence; never dispatch Odoo or a child."""

    __slots__ = (
        "_clock",
        "_current_registry_digest",
        "_current_release_digest",
        "_read_store",
        "_route_resolver",
        "_write_store",
    )

    def __init__(
        self,
        *,
        current_release_digest: str,
        current_registry_digest: str,
        read_store: SQLitePersistence,
        write_store: SQLitePersistence,
        route_resolver: Callable[
            [str, str], ResultDeliveryRoute | None
        ],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if (
            type(current_release_digest) is not str
            or _SHA256.fullmatch(current_release_digest) is None
            or type(current_registry_digest) is not str
            or _SHA256.fullmatch(current_registry_digest) is None
            or type(read_store) is not SQLitePersistence
            or type(write_store) is not SQLitePersistence
            or not callable(route_resolver)
            or not callable(clock)
        ):
            raise TrustedResultDeliveryError(
                "result delivery resolver configuration is invalid"
            )
        self._current_release_digest = current_release_digest
        self._current_registry_digest = current_registry_digest
        self._read_store = read_store
        self._write_store = write_store
        self._route_resolver = route_resolver
        self._clock = clock

    @staticmethod
    def _locator(locator: object) -> dict[str, Any]:
        if type(locator) is not dict or set(locator) != _LOCATOR_FIELDS:
            raise TrustedResultDeliveryError(
                "result delivery locator is invalid"
            )
        action = locator.get("action")
        operation_id = locator.get("operation_id")
        if (
            action not in {"read", "operation.result"}
            or locator.get("business_succeeded") is not True
            or locator.get("status") != "verified_success"
            or type(locator.get("capability_id")) is not str
            or _CAPABILITY_ID.fullmatch(locator["capability_id"]) is None
            or type(locator.get("receipt_id")) is not str
            or _IDENTIFIER.fullmatch(locator["receipt_id"]) is None
            or type(locator.get("result_digest")) is not str
            or _SHA256.fullmatch(locator["result_digest"]) is None
            or (
                action == "read"
                and locator["capability_id"] == _DIAGNOSTICS_CAPABILITY_ID
            )
            or (action == "read" and operation_id is not None)
            or (
                action == "operation.result"
                and (
                    type(operation_id) is not str
                    or _IDENTIFIER.fullmatch(operation_id) is None
                )
            )
        ):
            raise TrustedResultDeliveryError(
                "result delivery locator is invalid"
            )
        return locator

    @staticmethod
    def _session_matches(
        session: TrustedSession,
        *,
        principal: str,
        user_id: int,
        company_id: int,
        odoo_instance_id: str,
        database_name: str,
        database_uuid: str,
        environment: str,
    ) -> bool:
        return (
            principal == session.principal
            and user_id == session.user_id
            and company_id == session.company_id
            and company_id in session.allowed_company_ids
            and odoo_instance_id == session.odoo_instance_id
            and database_name == session.database_name
            and database_uuid == session.database_uuid
            and environment == session.environment
        )

    def _route(
        self, release_digest: str, registry_digest: str
    ) -> ResultDeliveryRoute:
        try:
            route = self._route_resolver(
                release_digest, registry_digest
            )
        except Exception as exc:
            raise TrustedResultDeliveryError(
                "result delivery route is unavailable"
            ) from exc
        if (
            type(route) is not ResultDeliveryRoute
            or not hmac.compare_digest(
                route.release_digest, release_digest
            )
            or not hmac.compare_digest(
                route.registry_digest, registry_digest
            )
        ):
            raise TrustedResultDeliveryError(
                "result delivery route is unavailable"
            )
        return route

    def _read(
        self,
        locator: dict[str, Any],
        session: TrustedSession,
    ) -> TrustedDeliveredResult:
        record = self._read_store.get_verified_read_result(
            locator["receipt_id"]
        )
        if (
            record.capability_id != locator["capability_id"]
            or not hmac.compare_digest(
                record.result_digest, locator["result_digest"]
            )
            or record.current_release_digest
            != self._current_release_digest
            or record.current_registry_digest
            != self._current_registry_digest
            or record.executed_release_digest
            != self._current_release_digest
            or record.executed_registry_digest
            != self._current_registry_digest
            or not self._session_matches(
                session,
                principal=record.principal,
                user_id=record.user_id,
                company_id=record.company_id,
                odoo_instance_id=record.odoo_instance_id,
                database_name=record.database_name,
                database_uuid=record.database_uuid,
                environment=record.environment,
            )
        ):
            raise TrustedResultDeliveryError(
                "verified read result binding differs"
            )
        return TrustedDeliveredResult(
            action="read",
            capability_id=record.capability_id,
            operation_id=None,
            receipt_id=record.receipt_id,
            result_digest=record.result_digest,
            principal=record.principal,
            user_id=record.user_id,
            company_id=record.company_id,
            odoo_instance_id=record.odoo_instance_id,
            database_name=record.database_name,
            database_uuid=record.database_uuid,
            environment=record.environment,
            executed_release_digest=record.executed_release_digest,
            executed_registry_digest=record.executed_registry_digest,
            business_result=record.result_body,
            audit_receipt=record.receipt,
        )

    def _write(
        self,
        locator: dict[str, Any],
        session: TrustedSession,
    ) -> TrustedDeliveredResult:
        material = self._write_store.get_terminal_write_delivery(
            locator["operation_id"]
        )
        operation = material.operation
        approval = material.approval_record
        durable = material.final_receipt
        audit_event = material.audit_event
        if operation.state is not State.COMPLETED:
            raise TrustedResultDeliveryError(
                "terminal write result is not a verified success"
            )
        route = self._route(
            operation.release_digest, operation.registry_digest
        )
        details = durable.body.get("receipt_details")
        if type(details) is not dict:
            raise TrustedResultDeliveryError(
                "terminal write result is invalid"
            )
        result_body = {
            field: details.get(field) for field in RESULT_BODY_FIELDS
        }
        try:
            validate_write_result_body(
                result_body, operation_id=operation.operation_id
            )
        except Exception as exc:
            raise TrustedResultDeliveryError(
                "terminal write result is invalid"
            ) from exc
        if (
            operation.capability_id != locator["capability_id"]
            or operation.operation_id != locator["operation_id"]
            or not self._session_matches(
                session,
                principal=operation.principal,
                user_id=operation.user_id,
                company_id=operation.company_id,
                odoo_instance_id=operation.odoo_instance_id,
                database_name=operation.database_name,
                database_uuid=operation.database_uuid,
                environment=operation.environment,
            )
            or details != {
                **result_body,
                "capability_channel": route.capability_channel,
            }
            or result_body["operation_state"] != State.COMPLETED.value
            or type(result_body.get("verification")) is not dict
            or result_body["verification"].get("passed") is not True
            or durable.operation_id != operation.operation_id
            or durable.operation_revision != operation.revision
            or durable.terminal_state != State.COMPLETED.value
            or durable.result_succeeded is not True
            or durable.audit_event_id != audit_event.event_id
            or audit_event.operation_id != operation.operation_id
            or audit_event.event_type != "operation.completed"
            or approval.operation_id != operation.operation_id
            or approval.approver_user_id != operation.approver_user_id
            or approval.approval_signature
            != operation.approval_signature
        ):
            raise TrustedResultDeliveryError(
                "terminal write result binding differs"
            )
        request_digest = authentication_request_digest(
            operation.capability_id, operation.parameters
        )
        receipt_id = "write-" + hashlib.sha256(
            canonical_json(
                {
                    "audit_event_id": audit_event.event_id,
                    "audit_head": audit_event.event_hash,
                    "operation_id": operation.operation_id,
                    "result": result_body,
                }
            )
        ).hexdigest()
        receipt = create_write_audit_receipt(
            receipt_id=receipt_id,
            request_id=operation.request_id,
            operation_id=operation.operation_id,
            capability_id=operation.capability_id,
            principal=operation.principal,
            odoo_instance_id=operation.odoo_instance_id,
            database_name=operation.database_name,
            database_uuid=operation.database_uuid,
            user_id=operation.user_id,
            approver_user_id=approval.approver_user_id,
            company_id=operation.company_id,
            environment=operation.environment,
            capability_channel=route.capability_channel,
            request_digest=request_digest,
            operation_digest=operation.digest,
            approval_digest=approval.approval_signature,
            registry_digest=operation.registry_digest,
            release_digest=operation.release_digest,
            audit_head=audit_event.event_hash,
            result_body=result_body,
            issued_at=audit_event.occurred_at,
            signing_key_id=route.write_receipt_key_id,
            secret=route.write_receipt_secret,
        )
        try:
            now = self._clock()
            verify_write_audit_receipt(
                receipt,
                request_id=operation.request_id,
                operation_id=operation.operation_id,
                capability_id=operation.capability_id,
                principal=operation.principal,
                odoo_instance_id=operation.odoo_instance_id,
                database_name=operation.database_name,
                database_uuid=operation.database_uuid,
                user_id=operation.user_id,
                approver_user_id=approval.approver_user_id,
                company_id=operation.company_id,
                environment=operation.environment,
                capability_channel=route.capability_channel,
                request_digest=request_digest,
                operation_digest=operation.digest,
                approval_digest=approval.approval_signature,
                registry_digest=operation.registry_digest,
                release_digest=operation.release_digest,
                audit_head=audit_event.event_hash,
                result_body=result_body,
                now=now,
                expected_signing_key_id=route.write_receipt_key_id,
                secret=route.write_receipt_secret,
            )
        except Exception as exc:
            raise TrustedResultDeliveryError(
                "terminal write receipt verification failed"
            ) from exc
        if (
            receipt["receipt_id"] != locator["receipt_id"]
            or not hmac.compare_digest(
                receipt["result_digest"], locator["result_digest"]
            )
        ):
            raise TrustedResultDeliveryError(
                "terminal write locator differs"
            )
        return TrustedDeliveredResult(
            action="operation.result",
            capability_id=operation.capability_id,
            operation_id=operation.operation_id,
            receipt_id=receipt["receipt_id"],
            result_digest=receipt["result_digest"],
            principal=operation.principal,
            user_id=operation.user_id,
            company_id=operation.company_id,
            odoo_instance_id=operation.odoo_instance_id,
            database_name=operation.database_name,
            database_uuid=operation.database_uuid,
            environment=operation.environment,
            executed_release_digest=operation.release_digest,
            executed_registry_digest=operation.registry_digest,
            business_result=result_body,
            audit_receipt=receipt,
        )

    def __call__(
        self,
        locator: dict[str, Any],
        session: TrustedSession,
    ) -> TrustedDeliveredResult:
        locator = self._locator(locator)
        if type(session) is not TrustedSession:
            raise TrustedResultDeliveryError(
                "result delivery session is invalid"
            )
        if locator["action"] == "read":
            return self._read(locator, session)
        return self._write(locator, session)


__all__ = [
    "ResultDeliveryRoute",
    "TrustedResultDeliveryError",
    "TrustedResultDeliveryResolver",
]

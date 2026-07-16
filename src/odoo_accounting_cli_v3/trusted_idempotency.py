"""Trusted cross-release prepare idempotency lookup.

Every retained release must use the same durable operation store.  This
adapter resolves a retry by identities that do not change when the current
release changes; the broker then reloads the operation and independently
compares its complete canonical business request before selecting that
operation's retained release.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .operations import Operation, canonical_json
from .persistence import SQLitePersistence
from .trusted_authority import TrustedSession


class TrustedIdempotencyError(ValueError):
    """The trusted prepare lookup could not establish an exact identity."""


@dataclass(frozen=True, slots=True)
class SQLitePrepareIdempotencyResolver:
    """Resolve prepare retries from the one shared durable SQLite store."""

    store: SQLitePersistence

    def __post_init__(self) -> None:
        if not isinstance(self.store, SQLitePersistence):
            raise TrustedIdempotencyError("durable operation store is invalid")

    def __call__(
        self,
        session: TrustedSession,
        capability_id: str,
        parameters: Mapping[str, Any],
    ) -> str | None:
        if not isinstance(session, TrustedSession):
            raise TrustedIdempotencyError("trusted session is invalid")
        if (
            type(capability_id) is not str
            or not capability_id.strip()
            or len(capability_id) > 512
        ):
            raise TrustedIdempotencyError("capability_id is invalid")
        try:
            detached = json.loads(canonical_json(parameters))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise TrustedIdempotencyError("parameters are not canonical JSON") from exc
        if type(detached) is not dict:
            raise TrustedIdempotencyError("parameters must be an object")
        idempotency_key = detached.get("idempotency_key")
        if (
            type(idempotency_key) is not str
            or not idempotency_key.strip()
            or len(idempotency_key) > 512
        ):
            raise TrustedIdempotencyError("idempotency_key is invalid")
        if detached.get("company_id") != session.company_id:
            raise TrustedIdempotencyError("business company does not match the session")

        operation = self.store.find_operation_by_idempotency(
            odoo_instance_id=session.odoo_instance_id,
            database_uuid=session.database_uuid,
            environment=session.environment,
            company_id=session.company_id,
            capability_id=capability_id,
            idempotency_key=idempotency_key,
        )
        return None if operation is None else operation.operation_id


@dataclass(frozen=True, slots=True)
class SQLiteRecoveryIdempotencyResolver:
    """Resolve an already-created recovery after an ambiguous child response."""

    store: SQLitePersistence

    def __post_init__(self) -> None:
        if not isinstance(self.store, SQLitePersistence):
            raise TrustedIdempotencyError("durable operation store is invalid")

    def __call__(
        self,
        session: TrustedSession,
        origin: Operation,
        request: Mapping[str, Any],
    ) -> str | None:
        if not isinstance(session, TrustedSession) or not isinstance(origin, Operation):
            raise TrustedIdempotencyError("trusted recovery identity is invalid")
        try:
            detached = json.loads(canonical_json(request))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise TrustedIdempotencyError(
                "recovery request is not canonical JSON"
            ) from exc
        if type(detached) is not dict:
            raise TrustedIdempotencyError("recovery request must be an object")
        required = {
            "origin_operation_id",
            "recovery_date",
            "reason",
            "idempotency_key",
        }
        if set(detached) != required:
            raise TrustedIdempotencyError("recovery request fields are invalid")
        idempotency_key = detached["idempotency_key"]
        if (
            type(idempotency_key) is not str
            or not idempotency_key.strip()
            or len(idempotency_key) > 512
            or detached["origin_operation_id"] != origin.operation_id
            or origin.principal != session.principal
            or origin.user_id != session.user_id
            or origin.company_id != session.company_id
            or origin.odoo_instance_id != session.odoo_instance_id
            or origin.database_name != session.database_name
            or origin.database_uuid != session.database_uuid
            or origin.environment != session.environment
        ):
            raise TrustedIdempotencyError("recovery request binding is invalid")

        operation = self.store.find_operation_by_idempotency(
            odoo_instance_id=session.odoo_instance_id,
            database_uuid=session.database_uuid,
            environment=session.environment,
            company_id=session.company_id,
            capability_id="acct.recovery.execute.v1",
            idempotency_key=idempotency_key,
        )
        if operation is None:
            return None
        parameters = operation.parameters
        if not (
            operation.principal == session.principal
            and operation.user_id == session.user_id
            and operation.company_id == session.company_id
            and operation.odoo_instance_id == session.odoo_instance_id
            and operation.database_name == session.database_name
            and operation.database_uuid == session.database_uuid
            and operation.environment == session.environment
            and operation.capability_id == "acct.recovery.execute.v1"
            and operation.idempotency_key == idempotency_key
            and set(parameters)
            == {
                "company_id",
                "expected_recovery_plan_digest",
                "idempotency_key",
                "origin_operation_id",
                "reason",
                "recovery_date",
            }
            and parameters.get("company_id") == session.company_id
            and parameters.get("origin_operation_id") == origin.operation_id
            and parameters.get("recovery_date") == detached["recovery_date"]
            and parameters.get("reason") == detached["reason"]
            and parameters.get("idempotency_key") == idempotency_key
        ):
            raise TrustedIdempotencyError("stored recovery content conflicts")
        return operation.operation_id


__all__ = [
    "SQLitePrepareIdempotencyResolver",
    "SQLiteRecoveryIdempotencyResolver",
    "TrustedIdempotencyError",
]

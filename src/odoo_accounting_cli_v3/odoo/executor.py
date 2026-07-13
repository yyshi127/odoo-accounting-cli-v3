"""Trusted Odoo-side read executor and receipt verifier."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from ..domain.trial_balance import TrialBalanceBackend, read_trial_balance
from ..gateway import RequestContext
from ..receipts import create_read_receipt, verify_read_receipt
from ..registry import Capability
from .trial_balance import OdooTrialBalanceBackend


class OdooExecutionError(ValueError):
    pass


class OdooReadExecutor:
    """Dispatch only registered read handlers inside a bound non-su Odoo env."""

    def __init__(
        self,
        env: Any,
        *,
        odoo_instance_id: str,
        database_name: str,
        database_uuid: str,
        receipt_secret: bytes,
        consume_receipt: Callable[[str, str], bool],
        now: Callable[[], datetime] | None = None,
        receipt_id_factory: Callable[[], str] | None = None,
        trial_balance_backend_factory: Callable[[Any, int, frozenset[int]], TrialBalanceBackend]
        | None = None,
    ) -> None:
        if (
            not odoo_instance_id
            or not database_name
            or not receipt_secret
            or not callable(consume_receipt)
        ):
            raise OdooExecutionError(
                "trusted instance, database, receipt key, and replay store are required"
            )
        self._env = env
        self._odoo_instance_id = odoo_instance_id
        self._database_name = database_name
        self._database_uuid = str(uuid.UUID(database_uuid))
        self._receipt_secret = receipt_secret
        self._consume_receipt = consume_receipt
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._receipt_id_factory = receipt_id_factory or (lambda: str(uuid.uuid4()))
        self._trial_balance_backend_factory = trial_balance_backend_factory or (
            lambda bound_env, user_id, allowed: OdooTrialBalanceBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )

    def _assert_runtime_binding(self, context: RequestContext) -> None:
        actual_database = getattr(getattr(self._env, "cr", None), "dbname", None)
        if (
            context.odoo_instance_id != self._odoo_instance_id
            or context.database_name != self._database_name
            or context.database_uuid != self._database_uuid
            or actual_database != self._database_name
            or context.user_id != getattr(self._env, "uid", None)
            or getattr(self._env, "su", False)
        ):
            raise OdooExecutionError("Odoo executor runtime binding mismatch")

    def __call__(
        self,
        context: RequestContext,
        capability: Capability,
        parameters: dict[str, Any],
        registry_digest: str,
        release_digest: str,
    ) -> dict[str, Any]:
        self._assert_runtime_binding(context)
        if capability.id != "acct.gl.trial_balance.v1":
            raise OdooExecutionError("read capability has no trusted Odoo handler")
        backend = self._trial_balance_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        body = read_trial_balance(backend, parameters)
        receipt = create_read_receipt(
            receipt_id=self._receipt_id_factory(),
            capability_id=capability.id,
            parameters=parameters,
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=registry_digest,
            release_digest=release_digest,
            record_count=body["page"]["total_count"],
            observed_at=self._now(),
            secret=self._receipt_secret,
        )
        return {**body, "receipt": receipt}

    def verify(
        self,
        context: RequestContext,
        capability: Capability,
        parameters: dict[str, Any],
        result: dict[str, Any],
        registry_digest: str,
        release_digest: str,
    ) -> None:
        self._assert_runtime_binding(context)
        body = {key: value for key, value in result.items() if key != "receipt"}
        verify_read_receipt(
            result.get("receipt"),
            capability_id=capability.id,
            parameters=parameters,
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=registry_digest,
            release_digest=release_digest,
            expected_record_count=body["page"]["total_count"],
            now=self._now(),
            consume_receipt=self._consume_receipt,
            secret=self._receipt_secret,
        )

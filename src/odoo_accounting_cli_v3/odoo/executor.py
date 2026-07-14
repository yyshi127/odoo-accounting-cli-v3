"""Trusted Odoo-side read executor and receipt verifier."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from ..domain.ar_open_items import ArOpenItemsBackend, read_ar_open_items
from ..domain.trial_balance import TrialBalanceBackend, read_trial_balance
from ..gateway import RequestContext
from ..receipts import (
    create_read_receipt,
    valid_read_runtime_binding,
    verify_read_receipt,
)
from ..registry import Capability
from .ar_open_items import OdooArOpenItemsBackend
from .trial_balance import OdooTrialBalanceBackend


class OdooExecutionError(ValueError):
    pass


class OdooReadExecutor:
    """Dispatch only registered read handlers inside a bound non-su Odoo env."""

    def __init__(
        self,
        env: Any,
        *,
        capabilities: Iterable[Capability],
        odoo_instance_id: str,
        database_name: str,
        database_uuid: str,
        environment: str,
        capability_channel: str,
        receipt_secret: bytes,
        receipt_key_id: str,
        consume_receipt: Callable[[str, str, datetime, datetime], bool],
        now: Callable[[], datetime] | None = None,
        receipt_id_factory: Callable[[], str] | None = None,
        trial_balance_backend_factory: Callable[[Any, int, frozenset[int]], TrialBalanceBackend]
        | None = None,
        ar_open_items_backend_factory: Callable[
            [Any, int, frozenset[int]], ArOpenItemsBackend
        ]
        | None = None,
    ) -> None:
        capability_list = tuple(capabilities)
        capability_map = {item.id: item for item in capability_list}
        if (
            not odoo_instance_id
            or not database_name
            or not receipt_secret
            or not isinstance(receipt_key_id, str)
            or not receipt_key_id.strip()
            or not callable(consume_receipt)
            or not valid_read_runtime_binding(environment, capability_channel)
            or not capability_list
            or len(capability_map) != len(capability_list)
        ):
            raise OdooExecutionError(
                "trusted registry, instance, database, receipt key, and replay store are required"
            )
        self._env = env
        self._capabilities = capability_list
        self._capability_map = capability_map
        self._odoo_instance_id = odoo_instance_id
        self._database_name = database_name
        self._database_uuid = str(uuid.UUID(database_uuid))
        self._environment = environment
        self._capability_channel = capability_channel
        self._receipt_secret = receipt_secret
        self._receipt_key_id = receipt_key_id
        self._consume_receipt = consume_receipt
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._receipt_id_factory = receipt_id_factory or (lambda: str(uuid.uuid4()))
        self._trial_balance_backend_factory = trial_balance_backend_factory or (
            lambda bound_env, user_id, allowed: OdooTrialBalanceBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )
        self._ar_open_items_backend_factory = ar_open_items_backend_factory or (
            lambda bound_env, user_id, allowed: OdooArOpenItemsBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )

    def _assert_runtime_binding(self, context: RequestContext) -> None:
        actual_database = getattr(getattr(self._env, "cr", None), "dbname", None)
        if (
            context.odoo_instance_id != self._odoo_instance_id
            or context.database_name != self._database_name
            or context.database_uuid != self._database_uuid
            or context.environment != self._environment
            or actual_database != self._database_name
            or context.user_id != getattr(self._env, "uid", None)
            or getattr(self._env, "su", False)
        ):
            raise OdooExecutionError("Odoo executor runtime binding mismatch")

    @staticmethod
    def _canonical_json(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def _read_registry(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        company_id = parameters["company_id"]
        if company_id != context.company_id or company_id not in context.allowed_company_ids:
            raise OdooExecutionError("registry company is outside the signed company binding")
        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise OdooExecutionError("registry company does not exist or is not visible")
        company.check_access_rights("read")
        company.check_access_rule("read")

        environment_field = (
            "enabled_environments"
            if self._capability_channel == "enabled"
            else "staged_environments"
        )
        descriptors = []
        for candidate in self._capabilities:
            data = candidate.data
            if context.environment not in data.get(environment_field, []):
                continue
            if not all(
                self._env.user.has_group(xml_id)
                for xml_id in data["odoo_permissions"]
            ):
                continue
            contract_json = self._canonical_json(data)
            descriptors.append(
                {
                    "id": data["id"],
                    "domain": data["domain"],
                    "business_description": data["business_description"],
                    "access": data["access"],
                    "risk_level": data["risk_level"],
                    "company_scope": data["company_scope"],
                    "odoo_permissions": data["odoo_permissions"],
                    "approval_required": data["approval"]["required"],
                    "idempotency_required": data["idempotency"]["required"],
                    "input_schema_json": self._canonical_json(data["input_schema"]),
                    "output_schema_json": self._canonical_json(data["output_schema"]),
                    "contract_digest": hashlib.sha256(
                        contract_json.encode("utf-8")
                    ).hexdigest(),
                    "evidence_level": data["evidence"]["level"],
                    "verification_method": data["verification"]["method"],
                    "recovery_method": data["recovery"]["method"],
                    "capability_channel": self._capability_channel,
                }
            )
        descriptors.sort(key=lambda item: item["id"])
        count = len(descriptors)
        return {
            "capabilities": descriptors,
            "page": {"count": count, "total_count": count},
        }

    def __call__(
        self,
        context: RequestContext,
        capability: Capability,
        parameters: dict[str, Any],
        registry_digest: str,
        release_digest: str,
    ) -> dict[str, Any]:
        self._assert_runtime_binding(context)
        registered = self._capability_map.get(capability.id)
        if registered is None or registered.data != capability.data:
            raise OdooExecutionError("read capability is not in the trusted registry")
        if capability.id == "acct.registry.list.v1":
            body = self._read_registry(context, parameters)
        elif capability.id == "acct.gl.trial_balance.v1":
            backend = self._trial_balance_backend_factory(
                self._env, context.user_id, context.allowed_company_ids
            )
            body = read_trial_balance(backend, parameters)
        elif capability.id == "acct.ar.open_items.v1":
            backend = self._ar_open_items_backend_factory(
                self._env, context.user_id, context.allowed_company_ids
            )
            body = read_ar_open_items(backend, parameters)
        else:
            raise OdooExecutionError("read capability has no trusted Odoo handler")
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
            environment=self._environment,
            capability_channel=self._capability_channel,
            record_count=body["page"]["total_count"],
            observed_at=self._now(),
            key_id=self._receipt_key_id,
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
            environment=self._environment,
            capability_channel=self._capability_channel,
            expected_record_count=body["page"]["total_count"],
            now=self._now(),
            consume_receipt=self._consume_receipt,
            expected_key_id=self._receipt_key_id,
            secret=self._receipt_secret,
        )

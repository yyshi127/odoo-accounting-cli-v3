"""Stable Pi-facing capability gateway contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .contracts import validate_value
from .operations import Operation
from .registry import Capability


class GatewayError(ValueError):
    pass


@dataclass(frozen=True)
class RequestContext:
    user_id: int
    company_id: int
    allowed_company_ids: frozenset[int]
    environment: str

    def __post_init__(self) -> None:
        if self.user_id <= 0 or self.company_id <= 0:
            raise GatewayError("positive user and company bindings are required")
        if self.company_id not in self.allowed_company_ids:
            raise GatewayError("bound company must be in allowed companies")
        if self.environment not in {"test", "sandbox", "production"}:
            raise GatewayError("invalid environment")


class CapabilityGateway:
    """Policy boundary used by Pi tools; it does not execute Odoo directly."""

    def __init__(
        self,
        capabilities: Iterable[Capability],
        *,
        acl_check: Callable[[RequestContext, Capability], bool],
    ) -> None:
        self._capabilities = {item.id: item for item in capabilities}
        self._acl_check = acl_check
        self._operations: dict[str, Operation] = {}
        self._idempotency: dict[tuple[int, str, str], str] = {}

    def _authorized(self, context: RequestContext, capability_id: str) -> Capability:
        try:
            capability = self._capabilities[capability_id]
        except KeyError as exc:
            raise GatewayError("unknown capability") from exc
        if context.environment not in capability.data["enabled_environments"]:
            raise GatewayError("capability is not enabled in this environment")
        if not self._acl_check(context, capability):
            raise GatewayError("Odoo ACL rejected capability")
        return capability

    @staticmethod
    def _validate_company_scope(context: RequestContext, capability: Capability, parameters: dict[str, Any]) -> None:
        scope = capability.data["company_scope"]
        if scope in {"bound_company", "explicit_single_company"}:
            parameter_company = parameters.get("company_id")
            if parameter_company != context.company_id:
                raise GatewayError("request company does not match bound company")
        elif scope == "allowed_companies":
            requested = parameters.get("company_ids")
            if not isinstance(requested, list) or not requested:
                raise GatewayError("company_ids are required")
            if not set(requested).issubset(context.allowed_company_ids):
                raise GatewayError("request includes an unauthorized company")

    def list_capabilities(self, context: RequestContext) -> list[dict[str, Any]]:
        visible = []
        for capability in self._capabilities.values():
            if context.environment in capability.data["enabled_environments"] and self._acl_check(context, capability):
                visible.append(capability.data.copy())
        return sorted(visible, key=lambda item: item["id"])

    def get_capability(self, context: RequestContext, capability_id: str) -> dict[str, Any]:
        return self._authorized(context, capability_id).data.copy()

    def validate_request(
        self,
        context: RequestContext,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> Capability:
        capability = self._authorized(context, capability_id)
        validate_value(parameters, capability.data["input_schema"])
        self._validate_company_scope(context, capability, parameters)
        return capability

    def prepare(
        self,
        context: RequestContext,
        *,
        operation_id: str,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> Operation:
        capability = self.validate_request(context, capability_id, parameters)
        if capability.data["access"] != "write":
            raise GatewayError("read capability cannot be prepared as a write")
        idempotency_key = parameters.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise GatewayError("non-empty idempotency_key is required")
        identity = (context.company_id, capability_id, idempotency_key)
        existing_id = self._idempotency.get(identity)
        if existing_id:
            return self._operations[existing_id]
        if operation_id in self._operations:
            raise GatewayError("operation_id already exists")
        operation = Operation.prepare(
            operation_id=operation_id,
            capability_id=capability_id,
            parameters=parameters,
            user_id=context.user_id,
            company_id=context.company_id,
            idempotency_key=idempotency_key,
        )
        self._operations[operation_id] = operation
        self._idempotency[identity] = operation_id
        return operation

    def preview(self, context: RequestContext, operation_id: str) -> dict[str, Any]:
        operation = self.status(context, operation_id)
        capability = self._authorized(context, operation.capability_id)
        return {
            "operation_id": operation.operation_id,
            "capability_id": operation.capability_id,
            "business_description": capability.data["business_description"],
            "parameters": operation.parameters,
            "operation_digest": operation.digest,
            "risk_level": capability.data["risk_level"],
            "approval": capability.data["approval"].copy(),
            "recovery": capability.data["recovery"].copy(),
        }

    def status(self, context: RequestContext, operation_id: str) -> Operation:
        try:
            operation = self._operations[operation_id]
        except KeyError as exc:
            raise GatewayError("unknown operation") from exc
        if operation.user_id != context.user_id or operation.company_id != context.company_id:
            raise GatewayError("operation is outside the bound user or company")
        return operation

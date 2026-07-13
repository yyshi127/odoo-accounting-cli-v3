"""Stable Pi-facing capability gateway contract."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable

from .contracts import validate_value
from .operations import Operation, canonical_json
from .registry import Capability, registry_digest


class GatewayError(ValueError):
    pass


@dataclass(frozen=True)
class RequestContext:
    audience: str
    auth_token_id: str
    auth_issued_at: datetime
    auth_expires_at: datetime
    auth_signature: str
    principal: str
    odoo_instance_id: str
    database_name: str
    database_uuid: str
    user_id: int
    company_id: int
    allowed_company_ids: frozenset[int]
    environment: str

    def __post_init__(self) -> None:
        if not isinstance(self.audience, str) or not self.audience.strip():
            raise GatewayError("authentication audience is required")
        if not isinstance(self.auth_token_id, str) or not self.auth_token_id.strip():
            raise GatewayError("authentication token ID is required")
        if (
            not isinstance(self.auth_issued_at, datetime)
            or not isinstance(self.auth_expires_at, datetime)
            or self.auth_issued_at.tzinfo is None
            or self.auth_issued_at.utcoffset() is None
            or self.auth_expires_at.tzinfo is None
            or self.auth_expires_at.utcoffset() is None
            or self.auth_expires_at <= self.auth_issued_at
        ):
            raise GatewayError("authentication timestamps must be timezone-aware and increasing")
        if not isinstance(self.auth_signature, str) or re.fullmatch(r"[0-9a-f]{64}", self.auth_signature) is None:
            raise GatewayError("authentication signature must be a lowercase SHA-256 HMAC")
        if not isinstance(self.principal, str) or not self.principal.strip():
            raise GatewayError("authenticated principal is required")
        if not isinstance(self.odoo_instance_id, str) or not self.odoo_instance_id.strip():
            raise GatewayError("Odoo instance binding is required")
        if (
            not isinstance(self.database_name, str)
            or not self.database_name.strip()
            or len(self.database_name) > 128
            or any(ord(character) < 32 for character in self.database_name)
        ):
            raise GatewayError("database_name is invalid")
        try:
            normalized_database_uuid = str(uuid.UUID(self.database_uuid))
        except (AttributeError, TypeError, ValueError) as exc:
            raise GatewayError("database_uuid must be a UUID") from exc
        object.__setattr__(self, "database_uuid", normalized_database_uuid)
        if (
            isinstance(self.user_id, bool)
            or not isinstance(self.user_id, int)
            or self.user_id <= 0
            or isinstance(self.company_id, bool)
            or not isinstance(self.company_id, int)
            or self.company_id <= 0
        ):
            raise GatewayError("positive user and company bindings are required")
        if not isinstance(self.allowed_company_ids, frozenset) or not self.allowed_company_ids or any(
            isinstance(company_id, bool) or not isinstance(company_id, int) or company_id <= 0
            for company_id in self.allowed_company_ids
        ):
            raise GatewayError("allowed companies must contain positive IDs")
        if self.company_id not in self.allowed_company_ids:
            raise GatewayError("bound company must be in allowed companies")
        if self.environment not in {"test", "sandbox", "production"}:
            raise GatewayError("invalid environment")


class CapabilityGateway:
    """In-process policy prototype used by Pi tools; it does not execute Odoo.

    Durable operation/idempotency storage is required before any write
    capability can be enabled outside tests.
    """

    def __init__(
        self,
        capabilities: Iterable[Capability],
        *,
        release_digest: str,
        authenticate_context: Callable[[RequestContext], bool],
        acl_check: Callable[[RequestContext, Capability, dict[str, Any] | None], bool],
        read_executor: Callable[
            [RequestContext, Capability, dict[str, Any], str, str], dict[str, Any]
        ]
        | None = None,
        read_receipt_verifier: Callable[
            [RequestContext, Capability, dict[str, Any], dict[str, Any], str, str], None
        ]
        | None = None,
    ) -> None:
        capability_list = tuple(capabilities)
        if re.fullmatch(r"[0-9a-f]{64}", release_digest) is None:
            raise GatewayError("release_digest must be a lowercase SHA-256 digest")
        self._capabilities = {item.id: item for item in capability_list}
        self._registry_digest = registry_digest(capability_list)
        self._release_digest = release_digest
        self._authenticate_context = authenticate_context
        self._acl_check = acl_check
        if (read_executor is None) != (read_receipt_verifier is None):
            raise GatewayError("read executor and receipt verifier must be configured together")
        self._read_executor = read_executor
        self._read_receipt_verifier = read_receipt_verifier
        self._operations: dict[str, Operation] = {}
        self._idempotency: dict[tuple[str, str, str, str, int, str, str], str] = {}

    def _authenticate(self, context: RequestContext) -> None:
        if not self._authenticate_context(context):
            raise GatewayError("request context authentication failed")

    def _available(self, context: RequestContext, capability_id: str) -> Capability:
        self._authenticate(context)
        try:
            capability = self._capabilities[capability_id]
        except KeyError as exc:
            raise GatewayError("unknown capability") from exc
        if context.environment not in capability.data["enabled_environments"]:
            raise GatewayError("capability is not enabled in this environment")
        return capability

    def _authorized(
        self,
        context: RequestContext,
        capability_id: str,
        parameters: dict[str, Any] | None = None,
    ) -> Capability:
        capability = self._available(context, capability_id)
        if not self._acl_check(context, capability, parameters):
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
        self._authenticate(context)
        visible = []
        for capability in self._capabilities.values():
            if (
                context.environment in capability.data["enabled_environments"]
                and self._acl_check(context, capability, None)
            ):
                visible.append(capability.data.copy())
        return sorted(visible, key=lambda item: item["id"])

    def get_capability(self, context: RequestContext, capability_id: str) -> dict[str, Any]:
        return self._authorized(context, capability_id).data.copy()

    def read(
        self,
        context: RequestContext,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> dict[str, Any]:
        normalized_parameters = json.loads(canonical_json(parameters))
        capability = self.validate_request(context, capability_id, normalized_parameters)
        if capability.data["access"] != "read":
            raise GatewayError("write capability cannot be executed through the read tool")
        if self._read_executor is None or self._read_receipt_verifier is None:
            raise GatewayError("trusted read executor is not configured")
        result = self._read_executor(
            context,
            capability,
            normalized_parameters,
            self._registry_digest,
            self._release_digest,
        )
        if not isinstance(result, dict):
            raise GatewayError("read executor returned a non-object result")
        validate_value(result, capability.data["output_schema"])
        self._read_receipt_verifier(
            context,
            capability,
            normalized_parameters,
            result,
            self._registry_digest,
            self._release_digest,
        )
        return json.loads(canonical_json(result))

    def validate_request(
        self,
        context: RequestContext,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> Capability:
        capability = self._available(context, capability_id)
        validate_value(parameters, capability.data["input_schema"])
        self._validate_company_scope(context, capability, parameters)
        if not self._acl_check(context, capability, parameters):
            raise GatewayError("Odoo ACL rejected capability")
        return capability

    @staticmethod
    def _idempotency_scope(capability: Capability, parameters: dict[str, Any]) -> str:
        scope = capability.data["idempotency"]["scope"]
        if scope == "company_capability":
            value: Any = {"idempotency_key": parameters["idempotency_key"]}
        elif scope == "company_journal_source_digest":
            value = {"journal_id": parameters["journal_id"], "source_digest": parameters["source_digest"]}
        elif scope == "company_line_set":
            value = {"line_ids": sorted(parameters["line_ids"])}
        elif scope == "company_source_line":
            value = {"source_move_line_id": parameters["source_move_line_id"]}
        elif scope == "company_depreciation_line":
            value = {"depreciation_line_id": parameters["depreciation_line_id"]}
        elif scope == "company_origin_move":
            value = {"move_id": parameters.get("origin_move_id", parameters.get("move_id"))}
        elif scope == "company_origin_operation":
            value = {"operation_id": parameters["operation_id"]}
        else:  # Registry validation makes this unreachable.
            raise GatewayError("unsupported idempotency scope")
        return hashlib.sha256(canonical_json(value)).hexdigest()

    def prepare(
        self,
        context: RequestContext,
        *,
        operation_id: str,
        request_id: str,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> Operation:
        capability = self.validate_request(context, capability_id, parameters)
        if capability.data["access"] != "write":
            raise GatewayError("read capability cannot be prepared as a write")
        idempotency_key = parameters.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise GatewayError("non-empty idempotency_key is required")
        identity = (
            context.odoo_instance_id,
            context.database_name,
            context.database_uuid,
            context.environment,
            context.company_id,
            capability_id,
            self._idempotency_scope(capability, parameters),
        )
        existing_id = self._idempotency.get(identity)
        if existing_id:
            existing = self._operations[existing_id]
            if existing.user_id != context.user_id or existing.principal != context.principal:
                raise GatewayError("idempotency key belongs to another authenticated user")
            candidate = Operation.prepare(
                operation_id=existing.operation_id,
                request_id=existing.request_id,
                capability_id=capability_id,
                parameters=parameters,
                principal=context.principal,
                user_id=context.user_id,
                company_id=context.company_id,
                idempotency_key=idempotency_key,
                odoo_instance_id=context.odoo_instance_id,
                database_name=context.database_name,
                database_uuid=context.database_uuid,
                environment=context.environment,
                registry_digest=self._registry_digest,
                release_digest=self._release_digest,
            )
            if candidate.digest != existing.digest:
                raise GatewayError("idempotency conflict: request content or runtime binding changed")
            return existing
        if operation_id in self._operations:
            raise GatewayError("operation_id already exists")
        operation = Operation.prepare(
            operation_id=operation_id,
            request_id=request_id,
            capability_id=capability_id,
            parameters=parameters,
            principal=context.principal,
            user_id=context.user_id,
            company_id=context.company_id,
            idempotency_key=idempotency_key,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            environment=context.environment,
            registry_digest=self._registry_digest,
            release_digest=self._release_digest,
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
        self._authenticate(context)
        try:
            operation = self._operations[operation_id]
        except KeyError as exc:
            raise GatewayError("unknown operation") from exc
        if (
            operation.principal != context.principal
            or operation.odoo_instance_id != context.odoo_instance_id
            or operation.database_name != context.database_name
            or operation.user_id != context.user_id
            or operation.company_id != context.company_id
            or operation.database_uuid != context.database_uuid
            or operation.environment != context.environment
        ):
            raise GatewayError("operation is outside the bound principal, database, environment, user, or company")
        return operation

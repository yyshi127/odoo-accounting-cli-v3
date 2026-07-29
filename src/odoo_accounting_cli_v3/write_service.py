"""Durable orchestration for approved Odoo accounting writes.

The service owns policy, state transitions, durable evidence acceptance, and
the final signed receipt.  The injected backend is the only component allowed
to touch Odoo; it must return Odoo-bound ``TrustedResult`` signatures.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from .auth import authentication_request_digest
from .contracts import validate_value
from .gateway import (
    WRITE_AUTH_SIGNATURE_PURPOSE,
    WRITE_AUTH_SIGNATURE_VERSION,
    CapabilityGateway,
    RequestContext,
)
from .effect_finalizer import (
    EffectFinalizationError,
    EffectFinalizationIdentity,
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    trusted_result_envelope_digest,
    validate_effect_finalization_evidence,
)
from .operations import (
    Approval,
    Operation,
    ResultKind,
    State,
    TrustedResult,
    approve_operation,
    begin_execution as validate_begin_execution,
    canonical_json,
    complete_operation as validate_complete_operation,
    complete_recovery as validate_complete_recovery,
    record_execution_result as validate_execution_result,
    sign_recovery_result,
)
from .odoo.module_graph import (
    OdooModuleGraphError,
    validate_module_graph_evidence,
)
from .persistence import (
    ConcurrentUpdate as PersistenceConcurrentUpdate,
    OperationNotFound,
    SQLitePersistence,
)
from .registry import Capability, registry_digest
from .recovery_contracts import (
    RecoveryContractError,
    select_recovery_action_contract,
)
from .recovery_evidence import (
    OriginRecoveryCompletionError,
    OriginRecoveryCompletionEvidence,
    create_origin_recovery_completion_evidence,
    origin_recovery_completion_evidence_digest,
    validate_origin_recovery_completion_evidence,
)
from .write_receipts import (
    WriteReceiptError,
    create_write_audit_receipt,
    index_recovery_guard_graph,
    validate_record_snapshot,
    validate_executable_recovery_plan,
    validate_recovery_plan,
    validate_write_difference,
    validate_write_result_body,
    verify_write_audit_receipt,
)


class WriteServiceError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_FIELDS = {
    "model",
    "record_id",
    "company_id",
    "record_state",
    "record_fingerprint",
}
_ALLOWED_MODELS = {
    "acct.invoice.customer_create.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.bill.vendor_create.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.refund.create.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.payment.register.v1": frozenset(
        {
            "account.payment",
            "account.move",
            "account.move.line",
            "account.partial.reconcile",
            "account.full.reconcile",
        }
    ),
    "acct.payment.cancel.v1": frozenset(
        {"account.payment", "account.move", "account.move.line"}
    ),
    "acct.bank.statement_import.v1": frozenset(
        {
            "account.bank.statement",
            "account.bank.statement.line",
            "account.move",
            "account.move.line",
        }
    ),
    "acct.reconciliation.apply.v1": frozenset(
        {
            "account.move",
            "account.move.line",
            "account.partial.reconcile",
            "account.full.reconcile",
        }
    ),
    "acct.asset.create.v1": frozenset(
        {"account.asset", "account.move", "account.move.line"}
    ),
    "acct.depreciation.post.v1": frozenset(
        {"account.asset", "account.move", "account.move.line"}
    ),
    "acct.accrual.create.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.deferred.create.v1": frozenset({"account.move", "account.move.line"}),
    "acct.period.adjustment_create.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.journal.entry_create.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.move.post.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.move.reverse.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.move.draft_cancel.v1": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.move.draft_cancel.v2": frozenset(
        {"account.move", "account.move.line"}
    ),
    "acct.recovery.execute.v1": frozenset(
        {
            "account.asset",
            "account.bank.statement",
            "account.bank.statement.line",
            "account.full.reconcile",
            "account.move",
            "account.move.line",
            "account.partial.reconcile",
            "account.payment",
        }
    ),
}


@dataclass(frozen=True)
class BackendEvidence:
    """A signed backend result and its exact canonical evidence body."""

    result: TrustedResult
    evidence: dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.result, TrustedResult) or not isinstance(
            self.evidence, dict
        ):
            raise WriteServiceError("backend evidence is invalid")


@dataclass(frozen=True)
class BackendWriteOutcome:
    """The execution and read-back evidence returned by one Odoo invocation."""

    execution: BackendEvidence
    verification: BackendEvidence | None

    def __post_init__(self) -> None:
        if not isinstance(self.execution, BackendEvidence) or (
            self.verification is not None
            and not isinstance(self.verification, BackendEvidence)
        ):
            raise WriteServiceError("combined backend write outcome is invalid")


@dataclass(frozen=True)
class WriteServiceSecurity:
    approval_key_id: str
    approval_secret: bytes
    approval_ttl_seconds: int
    execution_key_id: str
    execution_secret: bytes
    execution_issuers: frozenset[str]
    verification_key_id: str
    verification_secret: bytes
    verification_issuers: frozenset[str]
    receipt_key_id: str
    receipt_secret: bytes

    def __post_init__(self) -> None:
        identifiers = (
            self.approval_key_id,
            self.execution_key_id,
            self.verification_key_id,
            self.receipt_key_id,
        )
        secrets = (
            self.approval_secret,
            self.execution_secret,
            self.verification_secret,
            self.receipt_secret,
        )
        issuer_sets = (self.execution_issuers, self.verification_issuers)
        if any(not isinstance(value, str) or not value.strip() for value in identifiers):
            raise WriteServiceError("write security key IDs are required")
        if any(type(value) is not bytes or len(value) < 32 for value in secrets):
            raise WriteServiceError("write security secrets must contain at least 32 bytes")
        if (
            isinstance(self.approval_ttl_seconds, bool)
            or not isinstance(self.approval_ttl_seconds, int)
            or not 0 < self.approval_ttl_seconds <= 900
        ):
            raise WriteServiceError("approval TTL must be between 1 and 900 seconds")
        if any(
            not isinstance(values, frozenset)
            or not values
            or any(not isinstance(value, str) or not value.strip() for value in values)
            for values in issuer_sets
        ):
            raise WriteServiceError("trusted backend issuer allowlists are invalid")
        if len(set(identifiers)) != len(identifiers):
            raise WriteServiceError("write security key IDs must be distinct")
        if len(set(secrets)) != len(secrets):
            raise WriteServiceError("write security secrets must be distinct")


PrecheckExecutor = Callable[
    [RequestContext, Capability, Operation, str, str], dict[str, Any]
]
WriteExecutor = Callable[
    [RequestContext, Capability, Operation, Approval, str, str], BackendEvidence
]
VerificationExecutor = Callable[
    [RequestContext, Capability, Operation, dict[str, Any], str, str],
    BackendEvidence,
]
CombinedWriteExecutor = Callable[
    [RequestContext, Capability, Operation, Approval, str, str],
    BackendWriteOutcome,
]
EffectFinalizer = Callable[
    [EffectFinalizationIntent], EffectFinalizationReceipt
]


def _digest(value: Any) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WriteServiceError("backend evidence is not canonical JSON") from exc


def _index_company_bound_fresh_snapshots(
    snapshots: list[dict[str, Any]], company_id: int
) -> dict[tuple[str, int], dict[str, Any]]:
    """Validate and index fresh records, including company-less full reconciles."""

    fresh_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    values_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for snapshot in snapshots:
        validate_record_snapshot(snapshot)
        key = (snapshot["model"], snapshot["record_id"])
        values = json.loads(snapshot["values_json"])
        if key in fresh_by_key or not isinstance(values, dict):
            raise WriteServiceError(
                "fresh verification snapshot identity or company is invalid"
            )
        if key[0] != "account.full.reconcile" and (
            values.get("company_id") != company_id
        ):
            raise WriteServiceError(
                "fresh verification snapshot identity or company is invalid"
            )
        fresh_by_key[key] = snapshot
        values_by_key[key] = values
    for key, values in values_by_key.items():
        if key[0] != "account.full.reconcile":
            continue
        for field_name, model_name in (
            ("reconciled_line_ids", "account.move.line"),
            ("partial_reconcile_ids", "account.partial.reconcile"),
        ):
            record_ids = values.get(field_name)
            if (
                not isinstance(record_ids, list)
                or not record_ids
                or any(
                    isinstance(record_id, bool)
                    or not isinstance(record_id, int)
                    or record_id <= 0
                    for record_id in record_ids
                )
                or len(record_ids) != len(set(record_ids))
                or any(
                    values_by_key.get((model_name, record_id), {}).get(
                        "company_id"
                    )
                    != company_id
                    for record_id in record_ids
                )
            ):
                raise WriteServiceError(
                    "fresh full reconcile snapshot is not bound to company graph"
                )
    return fresh_by_key


def _utc_timestamp(value: datetime | str) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise WriteServiceError("verification timestamp is invalid") from exc
    else:
        parsed = value
    if (
        not isinstance(parsed, datetime)
        or parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        raise WriteServiceError("verification timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def write_idempotency_scope(
    capability: Capability, parameters: dict[str, Any]
) -> str:
    """Return the content-bound scope sent to both SQLite and Odoo anchors."""

    scope = capability.data["idempotency"]["scope"]
    if scope == "company_capability":
        value: Any = {"idempotency_key": parameters["idempotency_key"]}
    elif scope == "company_journal_source_digest":
        value = {
            "journal_id": parameters["journal_id"],
            "source_digest": parameters["source_digest"],
        }
    elif scope == "company_line_set":
        value = {"line_ids": sorted(parameters["line_ids"])}
    elif scope == "company_source_line":
        value = {"source_move_line_id": parameters["source_move_line_id"]}
    elif scope == "company_depreciation_move":
        value = {"depreciation_move_id": parameters["depreciation_move_id"]}
    elif scope == "company_origin_move":
        value = {
            "move_id": parameters.get("origin_move_id", parameters.get("move_id"))
        }
    elif scope == "company_origin_operation":
        value = {"operation_id": parameters["origin_operation_id"]}
    else:
        raise WriteServiceError("unsupported write idempotency scope")
    return _digest(value)


class DurableWriteService:
    """Pi-facing durable write lifecycle without an in-memory success path."""

    def __init__(
        self,
        capabilities: Iterable[Capability],
        *,
        release_digest: str,
        store: SQLitePersistence,
        security: WriteServiceSecurity,
        authenticate_context: Callable[[RequestContext], bool],
        acl_check: Callable[[RequestContext, Capability, dict[str, Any] | None], bool],
        approver_authorized: Callable[[int, int, str], bool],
        precheck_executor: PrecheckExecutor,
        write_executor: WriteExecutor,
        verification_executor: VerificationExecutor,
        availability_channel: str,
        now: Callable[[], datetime],
        effect_finalizer: EffectFinalizer,
        effect_finalizer_identity: EffectFinalizationIdentity,
        receipt_id_factory: Callable[[], str] | None = None,
        execute_and_verify: CombinedWriteExecutor | None = None,
    ) -> None:
        capability_list = tuple(capabilities)
        if not capability_list or len({item.id for item in capability_list}) != len(
            capability_list
        ):
            raise WriteServiceError("validated capabilities are required")
        if re.fullmatch(r"[0-9a-f]{64}", release_digest) is None:
            raise WriteServiceError("release digest must be a lowercase SHA-256 digest")
        if not isinstance(store, SQLitePersistence):
            raise WriteServiceError("durable SQLite persistence is required")
        for function in (
            authenticate_context,
            acl_check,
            approver_authorized,
            precheck_executor,
            write_executor,
            verification_executor,
            effect_finalizer,
            now,
        ):
            if not callable(function):
                raise WriteServiceError("write service callbacks must be callable")
        if availability_channel not in {"staged", "enabled"}:
            raise WriteServiceError("write availability channel is invalid")
        if not isinstance(effect_finalizer_identity, EffectFinalizationIdentity):
            raise WriteServiceError("effect finalizer identity is required")
        self._capabilities = {item.id: item for item in capability_list}
        self._registry_digest = registry_digest(capability_list)
        self._release_digest = release_digest
        self._store = store
        self._security = security
        self._authenticate_context = authenticate_context
        self._approver_authorized = approver_authorized
        self._precheck_executor = precheck_executor
        self._write_executor = write_executor
        self._verification_executor = verification_executor
        self._effect_finalizer = effect_finalizer
        self._effect_finalizer_identity = effect_finalizer_identity
        self._availability_channel = availability_channel
        self._now = now
        if receipt_id_factory is not None and not callable(receipt_id_factory):
            raise WriteServiceError("receipt_id_factory must be callable")
        if execute_and_verify is not None and not callable(execute_and_verify):
            raise WriteServiceError("combined write executor must be callable")
        self._execute_and_verify = execute_and_verify
        self._policy = CapabilityGateway(
            capability_list,
            release_digest=release_digest,
            authenticate_context=authenticate_context,
            acl_check=acl_check,
            availability_channel=availability_channel,
        )

    def _capability(
        self,
        context: RequestContext,
        operation: Operation,
        *,
        enforce_acl: bool = True,
        enforce_availability: bool = True,
    ) -> Capability:
        if (
            operation.registry_digest != self._registry_digest
            or operation.release_digest != self._release_digest
        ):
            raise WriteServiceError("historical_release_required")
        capability = self._policy.validate_request(
            context,
            operation.capability_id,
            operation.parameters,
            enforce_acl=enforce_acl,
            enforce_availability=enforce_availability,
        )
        if capability.data["access"] != "write":
            raise WriteServiceError("operation capability is not a write")
        return capability

    @staticmethod
    def _assert_context_binding(context: RequestContext, operation: Operation) -> None:
        if (
            operation.principal != context.principal
            or operation.user_id != context.user_id
            or operation.company_id != context.company_id
            or operation.odoo_instance_id != context.odoo_instance_id
            or operation.database_name != context.database_name
            or operation.database_uuid != context.database_uuid
            or operation.environment != context.environment
        ):
            raise WriteServiceError(
                "operation is outside the bound principal, database, environment, user, or company"
            )

    @staticmethod
    def _assert_authenticated_content(
        context: RequestContext,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> str:
        if (
            context.auth_signature_version == WRITE_AUTH_SIGNATURE_VERSION
            and context.auth_signature_purpose == WRITE_AUTH_SIGNATURE_PURPOSE
        ):
            # The injected authenticator verifies the exact action and request
            # envelope.  Persistence consumes that action-bound digest here.
            return context.auth_request_digest
        expected = authentication_request_digest(capability_id, parameters)
        if not hmac.compare_digest(context.auth_request_digest, expected):
            raise WriteServiceError(
                "authenticated request digest does not match the write content"
            )
        return expected

    def _consume_authenticated_write(
        self,
        context: RequestContext,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> None:
        request_digest = self._assert_authenticated_content(
            context, capability_id, parameters
        )
        self._store.consume_auth_token(
            token_id=context.auth_token_id,
            request_digest=request_digest,
            expires_at=context.auth_expires_at,
            now=self._now(),
        )

    def status(self, context: RequestContext, operation_id: str) -> Operation:
        if self._authenticate_context(context) is not True:
            raise WriteServiceError("request context authentication failed")
        operation = self._store.get_operation(operation_id)
        self._assert_context_binding(context, operation)
        self._assert_authenticated_content(
            context, operation.capability_id, operation.parameters
        )
        operation.assert_integrity()
        return operation

    def operation_diagnostics(
        self,
        context: RequestContext,
        *,
        company_id: int,
        operation_id: str,
    ) -> dict[str, Any]:
        """Read a non-secret diagnostic projection from the trusted write store."""

        from .operation_diagnostics import OperationDiagnosticsReader

        return OperationDiagnosticsReader(
            store=self._store,
            status_reader=self.status,
            terminal_result_reader=self.result,
            recovered_completion_reader=(
                self._verified_recovered_origin_completion
            ),
        ).read(
            context,
            company_id=company_id,
            operation_id=operation_id,
        )

    def _verified_recovered_origin_completion(
        self,
        context: RequestContext,
        origin: Operation,
        recovery_operation_id: str,
    ) -> dict[str, Any]:
        """Reverify the signed completion graph for one recovered origin."""

        current = self.status(context, origin.operation_id)
        if current != origin or origin.state != State.RECOVERED:
            raise WriteServiceError(
                "diagnostic origin is not the current recovered operation"
            )
        recovery_operation = self._store.get_operation(
            recovery_operation_id
        )
        self._assert_context_binding(context, recovery_operation)
        expected = self._rebuild_origin_recovery_completion_evidence(
            recovery_operation=recovery_operation,
        )
        binding = self._store.get_recovery_operation_binding(
            recovery_operation.operation_id
        )
        if binding.origin_operation_id != origin.operation_id:
            raise WriteServiceError(
                "recovered origin binding differs from its recovery operation"
            )
        plan = self._bound_origin_recovery_plan(origin, binding)
        resolution_receipt = self._store.get_final_write_receipt(
            expected.recovery_final_receipt.receipt_id
        )
        self._validate_recovered_origin(
            origin=origin,
            binding=binding,
            plan=plan,
            expected=expected,
            resolution_receipt=resolution_receipt,
        )
        receipts = [
            receipt
            for receipt in self._store.get_final_write_receipts(
                origin.operation_id
            )
            if receipt.operation_revision == origin.revision
            and receipt.terminal_state == State.RECOVERED.value
        ]
        if len(receipts) != 1:
            raise WriteServiceError(
                "recovered origin has no unique final receipt"
            )
        completion_receipt = receipts[0]
        return {
            "completion_evidence_digest": (
                origin_recovery_completion_evidence_digest(expected)
            ),
            "completion_receipt_body_digest": (
                completion_receipt.body_digest
            ),
            "completion_receipt_id": completion_receipt.receipt_id,
            "origin_operation_id": origin.operation_id,
            "recovery_operation_id": recovery_operation.operation_id,
            "recovery_plan_digest": plan["plan_digest"],
        }

    def prepare(
        self,
        context: RequestContext,
        *,
        operation_id: str,
        request_id: str,
        capability_id: str,
        parameters: dict[str, Any],
    ) -> Operation:
        return self._prepare_operation(
            context,
            operation_id=operation_id,
            request_id=request_id,
            capability_id=capability_id,
            parameters=parameters,
            allow_receipt_derived_recovery=False,
        )

    def _prepare_operation(
        self,
        context: RequestContext,
        *,
        operation_id: str,
        request_id: str,
        capability_id: str,
        parameters: dict[str, Any],
        allow_receipt_derived_recovery: bool,
    ) -> Operation:
        try:
            normalized_parameters = json.loads(canonical_json(parameters))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise WriteServiceError("write parameters are not canonical JSON") from exc
        capability = self._policy.validate_request(
            context, capability_id, normalized_parameters
        )
        if capability.data["access"] != "write":
            raise WriteServiceError("read capability cannot be prepared as a write")
        if (
            capability_id == "acct.recovery.execute.v1"
            and not allow_receipt_derived_recovery
        ):
            raise WriteServiceError(
                "recovery can only be prepared from a verified origin receipt"
            )
        self._consume_authenticated_write(
            context, capability_id, normalized_parameters
        )
        idempotency_key = normalized_parameters.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise WriteServiceError("non-empty idempotency_key is required")
        candidate = Operation.prepare(
            operation_id=operation_id,
            request_id=request_id,
            capability_id=capability_id,
            parameters=normalized_parameters,
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
        operation, _created = self._store.get_or_create_operation(
            candidate, scope=write_idempotency_scope(capability, normalized_parameters)
        )
        self._assert_context_binding(context, operation)
        return operation

    def preview(self, context: RequestContext, operation_id: str) -> dict[str, Any]:
        operation = self.status(context, operation_id)
        capability = self._capability(context, operation)
        if operation.state not in {
            State.PREPARED,
            State.PRECHECKED,
            State.AWAITING_APPROVAL,
        }:
            raise WriteServiceError("operation can no longer be previewed")
        self._consume_authenticated_write(
            context, capability.id, operation.parameters
        )
        evidence = self._precheck_executor(
            context,
            capability,
            operation,
            self._registry_digest,
            self._release_digest,
        )
        if (
            not isinstance(evidence, dict)
            or evidence.get("passed") is not True
            or evidence.get("capability_id") != capability.id
            or evidence.get("company_id") != operation.company_id
        ):
            raise WriteServiceError("Odoo precheck did not produce passing bound evidence")
        self._validate_precheck_evidence_binding(
            operation,
            evidence,
            expected_channel=self._availability_channel,
        )
        precheck_digest = _digest(evidence)
        if operation.state == State.PREPARED:
            operation = self._store.record_precheck(
                operation_id=operation.operation_id,
                evidence=evidence,
                occurred_at=self._now(),
                expected_revision=operation.revision,
            ).operation
        elif operation.precheck_digest != precheck_digest:
            raise WriteServiceError(
                "live Odoo precheck differs from the immutable approved preview"
            )
        if operation.state == State.PRECHECKED:
            updated = operation.transition(
                State.AWAITING_APPROVAL, expected_revision=operation.revision
            )
            operation = self._store.cas_update_operation(
                updated,
                expected_revision=operation.revision,
                occurred_at=self._now(),
            )
        return {
            "operation_id": operation.operation_id,
            "operation_state": operation.state.value,
            "capability_id": capability.id,
            "business_description": capability.data["business_description"],
            "parameters": operation.parameters,
            "operation_digest": operation.digest,
            "precheck": evidence,
            "precheck_identity": {
                "operation_id": operation.operation_id,
                "precheck_digest": precheck_digest,
                "registry_digest": operation.registry_digest,
                "release_digest": operation.release_digest,
            },
            "precheck_digest": precheck_digest,
            "risk_level": capability.data["risk_level"],
            "approval": capability.data["approval"].copy(),
            "recovery": capability.data["recovery"].copy(),
        }

    @staticmethod
    def _validate_backend_digest(payload: BackendEvidence) -> None:
        if _digest(payload.evidence) != payload.result.evidence_digest:
            raise WriteServiceError("trusted backend evidence digest mismatch")

    @staticmethod
    def _validate_record(
        value: Any,
        *,
        operation: Operation,
        allowed_models: frozenset[str],
        label: str,
    ) -> tuple[str, int]:
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise WriteServiceError(f"{label} fields are invalid")
        if value["company_id"] != operation.company_id:
            raise WriteServiceError(f"{label} company does not match the operation")
        if value["model"] not in allowed_models:
            raise WriteServiceError(f"{label} model is not allowed for the capability")
        if (
            isinstance(value["record_id"], bool)
            or not isinstance(value["record_id"], int)
            or value["record_id"] <= 0
            or not isinstance(value["record_state"], str)
            or not value["record_state"].strip()
            or _SHA256.fullmatch(value["record_fingerprint"]) is None
        ):
            raise WriteServiceError(f"{label} identity is invalid")
        return value["model"], value["record_id"]

    @staticmethod
    def _validate_difference_binding(
        difference: Any,
        *,
        operation: Operation,
        allowed_models: frozenset[str],
        records_by_key: dict[tuple[str, int], dict[str, Any]],
    ) -> None:
        validate_write_difference(difference)
        record_keys = set(records_by_key)
        snapshots: dict[str, dict[tuple[str, int], dict[str, Any]]] = {}
        for phase in ("before", "after"):
            keyed: dict[tuple[str, int], dict[str, Any]] = {}
            for snapshot in difference[phase]:
                key = (snapshot["model"], snapshot["record_id"])
                if key in keyed:
                    raise WriteServiceError(
                        f"difference {phase} snapshots contain a duplicate record"
                    )
                keyed[key] = snapshot
            snapshots[phase] = keyed
        if set(snapshots["before"]) - set(snapshots["after"]):
            raise WriteServiceError(
                "difference after snapshots omit a prechecked record"
            )

        values_by_phase = {
            phase: {
                key: json.loads(snapshot["values_json"])
                for key, snapshot in snapshots[phase].items()
            }
            for phase in ("before", "after")
        }

        def company_bound(
            key: tuple[str, int],
            values: dict[str, Any],
            phase_values: dict[tuple[str, int], dict[str, Any]],
        ) -> bool:
            if key[0] != "account.full.reconcile":
                return values.get("company_id") == operation.company_id
            line_ids = values.get("reconciled_line_ids")
            if (
                not isinstance(line_ids, list)
                or not line_ids
                or any(
                    isinstance(line_id, bool)
                    or not isinstance(line_id, int)
                    or line_id <= 0
                    for line_id in line_ids
                )
                or len(line_ids) != len(set(line_ids))
            ):
                return False
            return all(
                phase_values.get(("account.move.line", line_id), {}).get(
                    "company_id"
                )
                == operation.company_id
                for line_id in line_ids
            )

        for phase in ("before", "after"):
            phase_values = values_by_phase[phase]
            for snapshot in difference[phase]:
                key = (snapshot["model"], snapshot["record_id"])
                if snapshot["model"] not in allowed_models:
                    raise WriteServiceError(
                        "difference snapshot model is not allowed for the capability"
                    )
                values = json.loads(snapshot["values_json"])
                if (
                    "company_id" in values
                    and values["company_id"] != operation.company_id
                ):
                    raise WriteServiceError(
                        "difference snapshot company does not match the operation"
                    )
                if snapshot["exists"] is False and (
                    snapshot["record_state"] != "absent" or values
                ):
                    raise WriteServiceError(
                        "an absent difference snapshot must have absent state and empty values"
                    )
                if snapshot["exists"] is False:
                    if phase == "before":
                        created = snapshots["after"].get(key)
                        created_values = (
                            json.loads(created["values_json"])
                            if created is not None
                            else {}
                        )
                        if (
                            created is None
                            or created["exists"] is not True
                            or not company_bound(
                                key,
                                created_values,
                                values_by_phase["after"],
                            )
                        ):
                            raise WriteServiceError(
                                "difference before snapshots may describe an "
                                "absent record only when the company-bound "
                                "record is created"
                            )
                    else:
                        prior = snapshots["before"].get(key)
                        prior_values = values_by_phase["before"].get(key, {})
                        if (
                            prior is None
                            or prior["exists"] is not True
                            or not company_bound(
                                key,
                                prior_values,
                                values_by_phase["before"],
                            )
                        ):
                            raise WriteServiceError(
                                "difference tombstone has no company-bound "
                                "before snapshot"
                            )
                elif not company_bound(key, values, phase_values):
                    raise WriteServiceError(
                        "difference snapshot has no verifiable operation company binding"
                    )
                if (
                    snapshot["exists"] is True
                    and snapshot["record_state"] == "absent"
                ):
                    raise WriteServiceError(
                        "an existing difference snapshot cannot have absent state"
                    )
        for key, record in records_by_key.items():
            if key not in snapshots["before"]:
                raise WriteServiceError(
                    "every Odoo result record requires a before snapshot"
                )
            current = snapshots["after"].get(key)
            if current is None or current["exists"] is not True:
                raise WriteServiceError(
                    "every Odoo result record requires an existing after snapshot"
                )
            if (
                current["record_state"] != record["record_state"]
                or _digest(current) != record["record_fingerprint"]
            ):
                raise WriteServiceError(
                    "Odoo result record differs from its after snapshot"
                )

    @staticmethod
    def _validate_execution_evidence(
        payload: BackendEvidence, operation: Operation, capability: Capability
    ) -> None:
        DurableWriteService._validate_backend_digest(payload)
        evidence = payload.evidence
        if set(evidence) != {
            "operation_id",
            "capability_id",
            "succeeded",
            "odoo_records",
            "difference",
            "recovery_plan",
            "recovery_parameters",
            "module_graph",
            "failure_checks",
        }:
            raise WriteServiceError("execution evidence fields are invalid")
        if (
            evidence["operation_id"] != operation.operation_id
            or evidence["capability_id"] != capability.id
            or type(evidence["succeeded"]) is not bool
            or evidence["succeeded"] != payload.result.succeeded
            or not isinstance(evidence["odoo_records"], list)
            or not isinstance(evidence["difference"], dict)
            or not isinstance(evidence["recovery_plan"], dict)
            or not isinstance(evidence["recovery_parameters"], dict)
            or not isinstance(evidence["failure_checks"], list)
        ):
            raise WriteServiceError("execution evidence binding is invalid")
        module_graph = evidence["module_graph"]
        trusted_module_graph = None
        if module_graph is not None:
            try:
                trusted_module_graph = validate_module_graph_evidence(module_graph)
            except OdooModuleGraphError as exc:
                raise WriteServiceError(
                    "execution installed-module graph is invalid"
                ) from exc
        if payload.result.succeeded and module_graph is None:
            raise WriteServiceError(
                "successful execution requires installed-module graph evidence"
            )
        allowed_models = _ALLOWED_MODELS.get(capability.id)
        if allowed_models is None:
            raise WriteServiceError("write capability has no Odoo model allowlist")
        records = evidence["odoo_records"]
        record_keys: set[tuple[str, int]] = set()
        records_by_key: dict[tuple[str, int], dict[str, Any]] = {}
        for record in records:
            key = DurableWriteService._validate_record(
                record,
                operation=operation,
                allowed_models=allowed_models,
                label="Odoo result record",
            )
            if key in record_keys:
                raise WriteServiceError("Odoo result records contain a duplicate")
            record_keys.add(key)
            records_by_key[key] = record
        if payload.result.succeeded and not records:
            raise WriteServiceError("successful execution requires an Odoo result record")
        DurableWriteService._validate_difference_binding(
            evidence["difference"],
            operation=operation,
            allowed_models=allowed_models,
            records_by_key=records_by_key,
        )
        if payload.result.succeeded and (
            not evidence["difference"]["before"]
            or not evidence["difference"]["after"]
        ):
            raise WriteServiceError(
                "successful execution requires before and after snapshots"
            )
        plan = evidence["recovery_plan"]
        validate_recovery_plan(plan)
        if (
            plan["origin_operation_id"] != operation.operation_id
            or plan["recovery_capability_id"] != "acct.recovery.execute.v1"
            or plan["parameters_digest"] != _digest(evidence["recovery_parameters"])
        ):
            raise WriteServiceError("recovery plan is not bound to the execution evidence")
        if plan.get("status") == "available":
            try:
                validate_executable_recovery_plan(plan)
                contract = select_recovery_action_contract(
                    capability.id, plan["method"], plan["oracle_id"]
                )
            except (WriteReceiptError, RecoveryContractError) as exc:
                raise WriteServiceError(
                    "available recovery action contract is invalid"
                ) from exc
            recovery_parameters = evidence["recovery_parameters"]
            action_identities = sorted(
                (
                    {
                        "model": target["model"],
                        "record_id": target["record_id"],
                    }
                    for target in plan["action_targets"]
                ),
                key=lambda item: (item["model"], item["record_id"]),
            )
            guard_identities = sorted(
                (
                    {
                        "model": target["model"],
                        "record_id": target["record_id"],
                    }
                    for target in plan["guard_records"]
                ),
                key=lambda item: (item["model"], item["record_id"]),
            )
            if (
                trusted_module_graph is None
                or operation.environment not in contract.allowed_environments
                or contract.production_promotion_allowed
                or set(recovery_parameters)
                != {
                    "company_id",
                    "origin_operation_id",
                    "module_graph_digest",
                    "method",
                    "action_targets",
                    "guard_records",
                    "oracle_id",
                }
                or recovery_parameters["company_id"] != operation.company_id
                or recovery_parameters["origin_operation_id"]
                != operation.operation_id
                or recovery_parameters["module_graph_digest"]
                != trusted_module_graph.digest
                or recovery_parameters["method"] != contract.method
                or recovery_parameters["oracle_id"] != contract.oracle_id
                or recovery_parameters["action_targets"]
                != action_identities
                or recovery_parameters["guard_records"] != guard_identities
                or any(
                    target["model"] not in contract.action_models
                    for target in plan["action_targets"]
                )
                or any(
                    target["model"] not in contract.guard_models
                    or target["expected_outcome"]
                    not in contract.allowed_guard_outcomes
                    for target in plan["guard_records"]
                )
                or any(
                    model_name not in contract.result_models
                    for model_name, _record_id_value in record_keys
                )
                or record_keys
                != {
                    *(
                        (target["model"], target["record_id"])
                        for target in plan["action_targets"]
                    ),
                    *(
                        (target["model"], target["record_id"])
                        for target in plan["guard_records"]
                    ),
                }
            ):
                raise WriteServiceError(
                    "available recovery is not bound to its exact "
                    "company, environment, module graph, or record contract"
                )
        plan_targets = (
            [*plan["action_targets"], *plan["guard_records"]]
            if plan.get("plan_version") == 2
            else plan["target_records"]
        )
        for target in plan_targets:
            key = DurableWriteService._validate_record(
                {field: target[field] for field in _RECORD_FIELDS},
                operation=operation,
                allowed_models=allowed_models,
                label="recovery target",
            )
            if key not in record_keys:
                raise WriteServiceError(
                    "recovery target is not an Odoo result record"
                )
            result_record = records_by_key[key]
            if (
                target["record_state"] != result_record["record_state"]
                or target["record_fingerprint"]
                != result_record["record_fingerprint"]
            ):
                raise WriteServiceError(
                    "recovery target fingerprint differs from the Odoo result record"
                )
        if payload.result.succeeded and evidence["failure_checks"]:
            raise WriteServiceError("successful execution cannot contain failure checks")
        if not payload.result.succeeded and not evidence["failure_checks"]:
            raise WriteServiceError("failed execution requires failure checks")

    @staticmethod
    def _validate_verification_evidence(
        payload: BackendEvidence,
        operation: Operation,
        capability: Capability,
        execution: BackendEvidence,
    ) -> None:
        DurableWriteService._validate_backend_digest(payload)
        evidence = payload.evidence
        if set(evidence) != {
            "operation_id",
            "capability_id",
            "passed",
            "method",
            "checks",
            "verified_at",
            "readback",
        }:
            raise WriteServiceError("verification evidence fields are invalid")
        if evidence.get("method") != capability.data["verification"]["method"]:
            raise WriteServiceError(
                "verification method does not match the capability contract"
            )
        if (
            evidence["operation_id"] != operation.operation_id
            or evidence["capability_id"] != capability.id
            or type(evidence["passed"]) is not bool
            or evidence["passed"] != payload.result.succeeded
            or not isinstance(evidence["method"], str)
            or not isinstance(evidence["checks"], list)
            or not evidence["checks"]
            or any(not isinstance(item, str) or not item.strip() for item in evidence["checks"])
            or len(evidence["checks"]) != len(set(evidence["checks"]))
            or not isinstance(evidence["verified_at"], str)
            or not isinstance(evidence["readback"], dict)
        ):
            raise WriteServiceError("verification evidence binding is invalid")
        verified_at = datetime.fromisoformat(
            _utc_timestamp(evidence["verified_at"]).replace("Z", "+00:00")
        )
        if (
            payload.result.issued_at < execution.result.issued_at
            or verified_at < execution.result.issued_at
        ):
            raise WriteServiceError("verification predates execution evidence")
        readback = evidence["readback"]
        if set(readback) != {
            "company_id",
            "records",
            "fresh_snapshots",
            "fresh_snapshots_digest",
            "request_parameters_digest",
            "control_anchor",
        }:
            raise WriteServiceError("verification readback fields are invalid")
        if (
            readback["company_id"] != operation.company_id
            or readback["request_parameters_digest"] != _digest(operation.parameters)
            or not isinstance(readback["records"], list)
            or not isinstance(readback["fresh_snapshots"], list)
            or not isinstance(readback["fresh_snapshots_digest"], str)
            or _SHA256.fullmatch(readback["fresh_snapshots_digest"]) is None
            or readback["fresh_snapshots_digest"]
            != _digest(readback["fresh_snapshots"])
        ):
            raise WriteServiceError("verification readback is not bound to the operation")
        if payload.result.succeeded:
            if canonical_json(readback["records"]) != canonical_json(
                execution.evidence["odoo_records"]
            ):
                raise WriteServiceError(
                    "successful verification records differ from execution"
                )
        elif readback["records"] or readback["fresh_snapshots"]:
            raise WriteServiceError(
                "failed verification cannot claim a successful fresh readback"
            )
        fresh_by_key = _index_company_bound_fresh_snapshots(
            readback["fresh_snapshots"], operation.company_id
        )
        if payload.result.succeeded:
            if set(fresh_by_key) != {
                (record["model"], record["record_id"])
                for record in readback["records"]
            }:
                raise WriteServiceError(
                    "fresh verification snapshots do not cover every result record"
                )
            for record in readback["records"]:
                snapshot = fresh_by_key[(record["model"], record["record_id"])]
                if (
                    snapshot["record_state"] != record["record_state"]
                    or _digest(snapshot) != record["record_fingerprint"]
                ):
                    raise WriteServiceError(
                        "fresh verification fingerprint differs from execution"
                    )
        anchor = readback["control_anchor"]
        expected_anchor_state = "verified" if payload.result.succeeded else "failed"
        if (
            not isinstance(anchor, dict)
            or set(anchor)
            != {
                "operation_id",
                "capability_id",
                "company_id",
                "state",
                "execution_evidence_digest",
            }
            or anchor["operation_id"] != operation.operation_id
            or anchor["capability_id"] != capability.id
            or anchor["company_id"] != operation.company_id
            or anchor["state"] != expected_anchor_state
            or anchor["execution_evidence_digest"]
            != operation.execution_result_digest
        ):
            raise WriteServiceError("verification control anchor binding is invalid")

    @staticmethod
    def _compose_result_body(
        *,
        operation: Operation,
        execution: BackendEvidence,
        verification: BackendEvidence | None,
        database_finalization: dict[str, Any] | None,
        operation_state: State | None = None,
    ) -> dict[str, Any]:
        state = operation.state if operation_state is None else operation_state
        if state not in {State.COMPLETED, State.FAILED}:
            raise WriteServiceError("operation has no final write result")
        if verification is None:
            verification_body = {
                "method": "execution_failure_readback",
                "passed": False,
                "checks": execution.evidence["failure_checks"],
                "evidence_digest": execution.result.evidence_digest,
                "verified_at": _utc_timestamp(execution.result.issued_at),
            }
        else:
            evidence = verification.evidence
            verification_body = {
                "method": evidence["method"],
                "passed": evidence["passed"],
                "checks": evidence["checks"],
                "evidence_digest": verification.result.evidence_digest,
                "verified_at": _utc_timestamp(evidence["verified_at"]),
            }
        return {
            "operation_id": operation.operation_id,
            "operation_state": state.value,
            "odoo_records": execution.evidence["odoo_records"],
            "difference": execution.evidence["difference"],
            "verification": verification_body,
            "database_finalization": database_finalization,
            "recovery_plan": execution.evidence["recovery_plan"],
        }

    def _result_output(
        self,
        *,
        operation: Operation,
        capability: Capability,
        capability_channel: str,
        approver_user_id: int,
        approval_digest: str,
        execution: BackendEvidence,
        verification: BackendEvidence | None,
        database_finalization: dict[str, Any] | None,
        terminal_audit_event: Any,
    ) -> dict[str, Any]:
        if capability_channel not in {"staged", "enabled"}:
            raise WriteServiceError("durable capability channel is invalid")
        result_body = self._receipt_details(
            operation=operation,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
        )
        if (
            terminal_audit_event.operation_id != operation.operation_id
            or not isinstance(terminal_audit_event.event_hash, str)
            or _SHA256.fullmatch(terminal_audit_event.event_hash) is None
        ):
            raise WriteServiceError("terminal operation audit event is invalid")
        now = self._now()
        request_digest = authentication_request_digest(
            capability.id, operation.parameters
        )
        receipt_id = "write-" + _digest(
            {
                "audit_event_id": terminal_audit_event.event_id,
                "audit_head": terminal_audit_event.event_hash,
                "operation_id": operation.operation_id,
                "result": result_body,
            }
        )
        receipt = create_write_audit_receipt(
            receipt_id=receipt_id,
            request_id=operation.request_id,
            operation_id=operation.operation_id,
            capability_id=capability.id,
            principal=operation.principal,
            odoo_instance_id=operation.odoo_instance_id,
            database_name=operation.database_name,
            database_uuid=operation.database_uuid,
            user_id=operation.user_id,
            approver_user_id=approver_user_id,
            company_id=operation.company_id,
            environment=operation.environment,
            capability_channel=capability_channel,
            request_digest=request_digest,
            operation_digest=operation.digest,
            approval_digest=approval_digest,
            registry_digest=operation.registry_digest,
            release_digest=operation.release_digest,
            audit_head=terminal_audit_event.event_hash,
            result_body=result_body,
            issued_at=terminal_audit_event.occurred_at,
            signing_key_id=self._security.receipt_key_id,
            secret=self._security.receipt_secret,
        )
        verify_write_audit_receipt(
            receipt,
            request_id=operation.request_id,
            operation_id=operation.operation_id,
            capability_id=capability.id,
            principal=operation.principal,
            odoo_instance_id=operation.odoo_instance_id,
            database_name=operation.database_name,
            database_uuid=operation.database_uuid,
            user_id=operation.user_id,
            approver_user_id=approver_user_id,
            company_id=operation.company_id,
            environment=operation.environment,
            capability_channel=capability_channel,
            request_digest=request_digest,
            operation_digest=operation.digest,
            approval_digest=approval_digest,
            registry_digest=operation.registry_digest,
            release_digest=operation.release_digest,
            audit_head=terminal_audit_event.event_hash,
            result_body=result_body,
            now=now,
            expected_signing_key_id=self._security.receipt_key_id,
            secret=self._security.receipt_secret,
        )
        output = {**result_body, "audit_receipt": receipt}
        validate_value(output, capability.data["output_schema"])
        return json.loads(canonical_json(output))

    @classmethod
    def _receipt_details(
        cls,
        *,
        operation: Operation,
        execution: BackendEvidence,
        verification: BackendEvidence | None,
        database_finalization: dict[str, Any] | None,
    ) -> dict[str, Any]:
        result_body = cls._compose_result_body(
            operation=operation,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
        )
        validate_write_result_body(result_body, operation_id=operation.operation_id)
        return json.loads(canonical_json(result_body))

    @classmethod
    def _durable_receipt_details(
        cls,
        *,
        operation: Operation,
        execution: BackendEvidence,
        verification: BackendEvidence | None,
        capability_channel: str,
        database_finalization: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if capability_channel not in {"staged", "enabled"}:
            raise WriteServiceError("durable capability channel is invalid")
        return {
            **cls._receipt_details(
                operation=operation,
                execution=execution,
                verification=verification,
                database_finalization=database_finalization,
            ),
            "capability_channel": capability_channel,
        }

    @staticmethod
    def _validate_precheck_evidence_binding(
        operation: Operation,
        evidence: Any,
        *,
        expected_channel: str | None,
    ) -> str:
        fields = {
            "capability_id",
            "company_id",
            "parameters_digest",
            "passed",
            "checks",
            "handler_details",
            "runtime_binding",
            "registry_digest",
            "release_digest",
        }
        runtime_fields = {
            "user_id",
            "odoo_instance_id",
            "database_name",
            "database_uuid",
            "environment",
            "capability_channel",
        }
        runtime = evidence.get("runtime_binding") if isinstance(evidence, dict) else None
        if (
            not isinstance(evidence, dict)
            or set(evidence) != fields
            or evidence.get("capability_id") != operation.capability_id
            or evidence.get("company_id") != operation.company_id
            or evidence.get("parameters_digest") != _digest(operation.parameters)
            or evidence.get("passed") is not True
            or not isinstance(evidence.get("checks"), list)
            or not evidence["checks"]
            or not isinstance(evidence.get("handler_details"), dict)
            or evidence.get("registry_digest") != operation.registry_digest
            or evidence.get("release_digest") != operation.release_digest
            or not isinstance(runtime, dict)
            or set(runtime) != runtime_fields
            or runtime.get("user_id") != operation.user_id
            or runtime.get("odoo_instance_id") != operation.odoo_instance_id
            or runtime.get("database_name") != operation.database_name
            or runtime.get("database_uuid") != operation.database_uuid
            or runtime.get("environment") != operation.environment
            or runtime.get("capability_channel") not in {"staged", "enabled"}
            or (
                expected_channel is not None
                and runtime.get("capability_channel") != expected_channel
            )
        ):
            raise WriteServiceError("Odoo precheck runtime binding is invalid")
        return runtime["capability_channel"]

    def _pinned_capability_channel(self, operation: Operation) -> str:
        record = self._store.get_precheck_record(operation.operation_id)
        evidence = record.evidence
        return self._validate_precheck_evidence_binding(
            operation,
            evidence,
            expected_channel=None,
        )

    @staticmethod
    def _receipt_channel(
        receipt: Any,
        *,
        result_body: dict[str, Any],
        pinned_channel: str,
    ) -> str:
        details = receipt.body.get("receipt_details")
        expected = {**result_body, "capability_channel": pinned_channel}
        if not isinstance(details, dict) or canonical_json(details) != canonical_json(expected):
            raise WriteServiceError("durable final receipt differs from verified result")
        return pinned_channel

    def _validated_incident_origin_results(
        self,
        origin: Operation,
        *,
        binding: Any | None = None,
    ) -> tuple[BackendEvidence, BackendEvidence]:
        if binding is None:
            if origin.state != State.FAILED:
                raise WriteServiceError(
                    "incident recovery requires a failed origin operation"
                )
            incident = origin
            expected_recovery_results = 0
        else:
            expected_revision = {
                State.FAILED: binding.origin_operation_revision,
                State.RECOVERING: binding.origin_operation_revision + 1,
                State.RECOVERED: binding.origin_operation_revision + 2,
            }.get(origin.state)
            if expected_revision is None or origin.revision != expected_revision:
                raise WriteServiceError(
                    "incident recovery origin lifecycle differs from its binding"
                )
            incident = replace(
                origin,
                state=State.FAILED,
                revision=binding.origin_operation_revision,
            )
            incident.assert_integrity()
            expected_recovery_results = (
                1 if origin.state == State.RECOVERED else 0
            )
        records = self._store.get_trusted_result_records(origin.operation_id)
        executions = [record for record in records if record.kind == "execution"]
        verifications = [
            record for record in records if record.kind == "verification"
        ]
        recoveries = [record for record in records if record.kind == "recovery"]
        if (
            len(records) != 2 + expected_recovery_results
            or len(executions) != 1
            or len(verifications) != 1
            or len(recoveries) != expected_recovery_results
            or executions[0].succeeded is not True
            or verifications[0].succeeded is not False
            or incident.execution_result_digest
            != executions[0].evidence_digest
            or incident.verification_result_digest
            != verifications[0].evidence_digest
            or verifications[0].prior_evidence_digest
            != executions[0].evidence_digest
        ):
            raise WriteServiceError(
                "incident recovery requires durable successful execution and "
                "failed verification evidence"
            )
        if binding is not None and (
            binding.origin_execution_result_id != executions[0].result_id
            or binding.origin_execution_evidence_digest
            != executions[0].evidence_digest
            or binding.origin_result_id != verifications[0].result_id
            or binding.origin_result_evidence_digest
            != verifications[0].evidence_digest
            or binding.origin_terminal_state != State.FAILED.value
            or binding.audit_event.payload.get("binding_version") != 2
        ):
            raise WriteServiceError(
                "incident recovery binding differs from durable origin results"
            )
        execution = self._stored_backend_evidence(executions[0])
        verification = self._stored_backend_evidence(verifications[0])
        self._verify_terminal_trusted_results(
            operation=incident,
            execution=execution,
            verification=verification,
        )
        try:
            capability = self._capabilities[incident.capability_id]
        except KeyError as exc:
            raise WriteServiceError(
                "incident recovery origin capability is unavailable"
            ) from exc
        self._validate_execution_evidence(execution, incident, capability)
        self._validate_verification_evidence(
            verification, incident, capability, execution
        )
        return execution, verification

    def _verified_effect_finalization_intent(
        self,
        operation: Operation,
        execution: BackendEvidence,
        verification: BackendEvidence,
    ) -> EffectFinalizationIntent:
        if operation.state != State.COMPLETED:
            raise WriteServiceError(
                "effect finalization requires a completed operation"
            )
        resolution_execution_digest = trusted_result_envelope_digest(
            execution.result, operation
        )
        if operation.capability_id == "acct.recovery.execute.v1":
            try:
                binding = self._store.get_recovery_operation_binding(
                    operation.operation_id
                )
                origin = self._store.get_operation(binding.origin_operation_id)
            except Exception as exc:
                raise WriteServiceError(
                    "incident recovery has no durable origin binding"
                ) from exc
            self._assert_recovery_operation_binding(
                operation,
                origin,
                operation.parameters.get("expected_recovery_plan_digest"),
                binding,
            )
            origin_execution, _origin_verification = (
                self._validated_incident_origin_results(
                    origin, binding=binding
                )
            )
            return EffectFinalizationIntent(
                database_name=origin.database_name,
                database_uuid=origin.database_uuid,
                operation_id=origin.operation_id,
                operation_digest=origin.digest,
                execution_result_digest=trusted_result_envelope_digest(
                    origin_execution.result, origin
                ),
                resolution_operation_id=operation.operation_id,
                resolution_operation_digest=operation.digest,
                resolution_execution_result_digest=(
                    resolution_execution_digest
                ),
                resolution_result_digest=trusted_result_envelope_digest(
                    verification.result, operation
                ),
                resolution_kind="recovered",
            )
        return EffectFinalizationIntent(
            database_name=operation.database_name,
            database_uuid=operation.database_uuid,
            operation_id=operation.operation_id,
            operation_digest=operation.digest,
            execution_result_digest=resolution_execution_digest,
            resolution_operation_id=operation.operation_id,
            resolution_operation_digest=operation.digest,
            resolution_execution_result_digest=resolution_execution_digest,
            resolution_result_digest=trusted_result_envelope_digest(
                verification.result, operation
            ),
            resolution_kind="verified",
        )

    def _validated_database_finalization(
        self,
        operation: Operation,
        value: Any,
        *,
        execution: BackendEvidence,
        verification: BackendEvidence | None,
    ) -> dict[str, Any] | None:
        if operation.state == State.FAILED:
            if value is not None:
                raise WriteServiceError(
                    "failed operation cannot contain database effect finalization"
                )
            return None
        if operation.state != State.COMPLETED:
            raise WriteServiceError("operation has no database effect finalization")
        if verification is None:
            raise WriteServiceError(
                "completed operation has no verification result"
            )
        try:
            intent = self._verified_effect_finalization_intent(
                operation, execution, verification
            )
            return validate_effect_finalization_evidence(
                value,
                intent=intent,
                expected_attestation_key_id=(
                    self._effect_finalizer_identity.attestation_key_id
                ),
                expected_guard_installation_id=(
                    self._effect_finalizer_identity.guard_installation_id
                ),
                expected_database_oid=self._effect_finalizer_identity.database_oid,
            )
        except EffectFinalizationError as exc:
            raise WriteServiceError(
                "completed operation has no valid database effect finalization"
            ) from exc

    @staticmethod
    def _stored_backend_evidence(record: Any) -> BackendEvidence:
        try:
            kind = ResultKind(record.kind)
        except (AttributeError, TypeError, ValueError) as exc:
            raise WriteServiceError("stored trusted result kind is invalid") from exc
        return BackendEvidence(
            result=TrustedResult(
                kind=kind,
                operation_id=record.operation_id,
                request_id=record.request_id,
                operation_digest=record.operation_digest,
                operation_state_digest=record.operation_state_digest,
                operation_revision=record.operation_revision,
                company_id=record.company_id,
                issuer=record.issuer,
                key_id=record.key_id,
                succeeded=record.succeeded,
                evidence_digest=record.evidence_digest,
                prior_evidence_digest=record.prior_evidence_digest,
                issued_at=record.issued_at,
                signature_version=record.signature_version,
                signature_purpose=record.signature_purpose,
                signature=record.signature,
            ),
            evidence=record.evidence,
        )

    def _verify_terminal_trusted_results(
        self,
        *,
        operation: Operation,
        execution: BackendEvidence,
        verification: BackendEvidence | None,
    ) -> None:
        if operation.state not in {State.COMPLETED, State.FAILED}:
            raise WriteServiceError("operation has no terminal trusted results")
        if verification is None:
            if operation.state != State.FAILED or operation.revision <= 0:
                raise WriteServiceError("terminal execution result state is invalid")
            executing = replace(
                operation,
                state=State.EXECUTING,
                revision=operation.revision - 1,
                execution_result_digest=None,
            )
            executing.assert_integrity()
            try:
                reconstructed = validate_execution_result(
                    executing,
                    execution.result,
                    now=self._now(),
                    secret=self._security.execution_secret,
                    expected_key_id=self._security.execution_key_id,
                    allowed_issuers=self._security.execution_issuers,
                    expected_revision=executing.revision,
                )
            except Exception as exc:
                raise WriteServiceError(
                    "durable execution result signature is invalid"
                ) from exc
            if reconstructed != operation:
                raise WriteServiceError("durable execution result changed terminal state")
            return

        if operation.revision < 2:
            raise WriteServiceError("terminal verification result state is invalid")
        verifying = replace(
            operation,
            state=State.VERIFYING,
            revision=operation.revision - 1,
            verification_result_digest=None,
        )
        verifying.assert_integrity()
        executing = self._executing_snapshot(verifying)
        try:
            reconstructed_verifying = validate_execution_result(
                executing,
                execution.result,
                now=self._now(),
                secret=self._security.execution_secret,
                expected_key_id=self._security.execution_key_id,
                allowed_issuers=self._security.execution_issuers,
                expected_revision=executing.revision,
            )
            reconstructed_terminal = validate_complete_operation(
                verifying,
                verification.result,
                now=self._now(),
                secret=self._security.verification_secret,
                expected_key_id=self._security.verification_key_id,
                allowed_issuers=self._security.verification_issuers,
                expected_revision=verifying.revision,
            )
        except Exception as exc:
            raise WriteServiceError(
                "durable trusted result signature is invalid"
            ) from exc
        if reconstructed_verifying != verifying or reconstructed_terminal != operation:
            raise WriteServiceError("durable trusted results changed terminal state")

    def result(self, context: RequestContext, operation_id: str) -> dict[str, Any]:
        """Rebuild the same verified terminal output after response loss."""

        operation = self.status(context, operation_id)
        capability = self._capability(
            context,
            operation,
            enforce_acl=False,
            enforce_availability=False,
        )
        if operation.state not in {State.COMPLETED, State.FAILED}:
            raise WriteServiceError("operation has no terminal result")
        records = self._store.get_trusted_result_records(operation.operation_id)
        execution_records = [record for record in records if record.kind == "execution"]
        verification_records = [record for record in records if record.kind == "verification"]
        if len(execution_records) != 1 or len(verification_records) > 1:
            raise WriteServiceError("terminal trusted result evidence is incomplete")
        execution = self._stored_backend_evidence(execution_records[0])
        verification = (
            None
            if not verification_records
            else self._stored_backend_evidence(verification_records[0])
        )
        self._verify_terminal_trusted_results(
            operation=operation,
            execution=execution,
            verification=verification,
        )
        self._validate_execution_evidence(execution, operation, capability)
        if verification is not None:
            self._validate_verification_evidence(
                verification, operation, capability, execution
            )
        final_record = verification_records[0] if verification_records else execution_records[0]
        events = {
            event.event_id: event for event in self._store.audit_events()
        }
        try:
            terminal_event = events[final_record.audit_event_id]
        except KeyError as exc:
            raise WriteServiceError("terminal trusted result audit event is missing") from exc
        approval_record = self._store.get_approval_record(operation.operation_id)
        pinned_channel = self._pinned_capability_channel(operation)
        final_receipts = [
            receipt
            for receipt in self._store.get_final_write_receipts(
                operation.operation_id
            )
            if receipt.operation_revision == operation.revision
            and receipt.terminal_state == operation.state.value
        ]
        if len(final_receipts) != 1:
            raise WriteServiceError("terminal operation has no unique durable final receipt")
        stored = final_receipts[0]
        if (
            stored.result_id != final_record.result_id
            or stored.audit_event_id != terminal_event.event_id
        ):
            raise WriteServiceError("durable final receipt differs from verified result")
        details = stored.body.get("receipt_details")
        database_finalization = self._validated_database_finalization(
            operation,
            details.get("database_finalization")
            if isinstance(details, dict)
            else None,
            execution=execution,
            verification=verification,
        )
        result_details = self._receipt_details(
            operation=operation,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
        )
        self._receipt_channel(
            stored,
            result_body=result_details,
            pinned_channel=pinned_channel,
        )
        output = self._result_output(
            operation=operation,
            capability=capability,
            capability_channel=pinned_channel,
            approver_user_id=approval_record.approver_user_id,
            approval_digest=approval_record.approval_signature,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
            terminal_audit_event=terminal_event,
        )
        if (
            operation.state == State.COMPLETED
            and operation.capability_id == "acct.recovery.execute.v1"
        ):
            self._complete_incident_origin_recovery(
                recovery_operation=operation,
            )
        return output

    def _validated_origin_recovery_plan(
        self,
        context: RequestContext,
        origin_operation: Operation,
        *,
        expected_plan_digest: str | None = None,
    ) -> dict[str, Any]:
        self._validated_incident_origin_results(origin_operation)
        output = self.result(context, origin_operation.operation_id)
        plan = output.get("recovery_plan")
        try:
            validate_executable_recovery_plan(plan)
        except Exception as exc:
            raise WriteServiceError("origin recovery plan is invalid") from exc
        try:
            index_recovery_guard_graph(
                plan, expected_company_id=origin_operation.company_id
            )
        except Exception as exc:
            raise WriteServiceError(
                "origin recovery plan is unavailable or outside the bound company"
            ) from exc
        if (
            plan["origin_operation_id"] != origin_operation.operation_id
            or plan["recovery_capability_id"] != "acct.recovery.execute.v1"
            or (
                expected_plan_digest is not None
                and not hmac.compare_digest(
                    plan["plan_digest"], expected_plan_digest
                )
            )
        ):
            raise WriteServiceError(
                "origin recovery plan is unavailable or outside the bound company"
            )
        if (
            output.get("operation_state") != State.FAILED.value
            or output.get("verification", {}).get("passed") is not False
            or output.get("database_finalization") is not None
        ):
            raise WriteServiceError(
                "incident recovery origin result is not a failed verification"
            )
        return json.loads(canonical_json(plan))

    def prepare_recovery(
        self,
        context: RequestContext,
        *,
        origin_operation_id: str,
        expected_origin_revision: int,
        recovery_operation_id: str,
        request_id: str,
        recovery_date: str,
        reason: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Prepare a new, independently approved recovery operation."""

        origin = self.status(context, origin_operation_id)
        if (
            isinstance(expected_origin_revision, bool)
            or not isinstance(expected_origin_revision, int)
            or origin.revision != expected_origin_revision
        ):
            raise WriteServiceError("origin operation revision changed")
        if recovery_operation_id == origin.operation_id:
            raise WriteServiceError(
                "recovery operation must be distinct from its origin"
            )
        plan = self._validated_origin_recovery_plan(context, origin)
        parameters = {
            "company_id": origin.company_id,
            "origin_operation_id": origin.operation_id,
            "expected_recovery_plan_digest": plan["plan_digest"],
            "recovery_date": recovery_date,
            "reason": reason,
            "idempotency_key": idempotency_key,
        }
        recovery = self._prepare_operation(
            context,
            operation_id=recovery_operation_id,
            request_id=request_id,
            capability_id="acct.recovery.execute.v1",
            parameters=parameters,
            allow_receipt_derived_recovery=True,
        )
        try:
            binding = self._store.get_recovery_operation_binding(
                recovery.operation_id
            )
        except OperationNotFound:
            binding = self._store.bind_recovery_operation(
                origin_operation_id=origin.operation_id,
                recovery_operation_id=recovery.operation_id,
                expected_origin_revision=origin.revision,
                plan_digest=plan["plan_digest"],
                occurred_at=self._now(),
            )
        self._assert_recovery_operation_binding(
            recovery, origin, plan["plan_digest"], binding
        )
        return {
            "operation": recovery,
            "origin_operation_id": origin.operation_id,
            "origin_operation_revision": origin.revision,
            "recovery_plan_digest": plan["plan_digest"],
            "next_action": "operation.preview",
        }

    @staticmethod
    def _assert_recovery_operation_binding(
        operation: Operation,
        origin: Operation,
        plan_digest: Any,
        binding: Any,
    ) -> None:
        expected_origin_revision = {
            State.FAILED: binding.origin_operation_revision,
            State.RECOVERING: binding.origin_operation_revision + 1,
            State.RECOVERED: binding.origin_operation_revision + 2,
        }.get(origin.state)
        if (
            operation.operation_id == origin.operation_id
            or binding.recovery_operation_id != operation.operation_id
            or binding.recovery_request_id != operation.request_id
            or binding.recovery_operation_digest != operation.digest
            or binding.origin_operation_id != origin.operation_id
            or binding.origin_request_id != origin.request_id
            or binding.origin_operation_digest != origin.digest
            or expected_origin_revision is None
            or origin.revision != expected_origin_revision
            or binding.audit_event.payload.get("binding_version") != 2
            or not isinstance(plan_digest, str)
            or not hmac.compare_digest(binding.plan_digest, plan_digest)
            or binding.origin_terminal_state != State.FAILED.value
            or binding.principal != operation.principal
            or binding.user_id != operation.user_id
            or binding.company_id != operation.company_id
            or binding.odoo_instance_id != operation.odoo_instance_id
            or binding.database_name != operation.database_name
            or binding.database_uuid != operation.database_uuid
            or binding.environment != operation.environment
            or binding.registry_digest != operation.registry_digest
            or binding.release_digest != operation.release_digest
        ):
            raise WriteServiceError(
                "recovery operation binding differs from durable origin evidence"
            )

    def _bound_origin_recovery_plan(
        self,
        origin: Operation,
        binding: Any,
    ) -> dict[str, Any]:
        try:
            receipt = self._store.get_final_write_receipt(
                binding.origin_final_receipt_id
            )
        except Exception as exc:
            raise WriteServiceError(
                "incident origin final receipt is unavailable"
            ) from exc
        details = receipt.body.get("receipt_details")
        plan = (
            details.get("recovery_plan")
            if isinstance(details, dict)
            else None
        )
        try:
            validate_executable_recovery_plan(plan)
        except WriteReceiptError as exc:
            raise WriteServiceError(
                "incident origin recovery plan is invalid"
            ) from exc
        if (
            receipt.operation_id != origin.operation_id
            or receipt.operation_digest != origin.digest
            or receipt.operation_revision
            != binding.origin_operation_revision
            or receipt.terminal_state != State.FAILED.value
            or receipt.body_digest
            != binding.origin_final_receipt_body_digest
            or plan["origin_operation_id"] != origin.operation_id
            or plan["recovery_capability_id"]
            != "acct.recovery.execute.v1"
            or not hmac.compare_digest(
                plan["plan_digest"],
                binding.plan_digest,
            )
        ):
            raise WriteServiceError(
                "incident origin receipt differs from its recovery binding"
            )
        return json.loads(canonical_json(plan))

    def _recovery_resolution_sources(
        self,
        recovery_operation: Operation,
    ) -> tuple[
        Operation,
        Any,
        dict[str, Any],
        BackendEvidence,
        BackendEvidence,
        Any,
        Any,
        dict[str, Any],
    ]:
        if (
            recovery_operation.state != State.COMPLETED
            or recovery_operation.capability_id
            != "acct.recovery.execute.v1"
        ):
            raise WriteServiceError(
                "origin completion requires a completed recovery operation"
            )
        recovery_operation.assert_integrity()
        try:
            binding = self._store.get_recovery_operation_binding(
                recovery_operation.operation_id
            )
            origin = self._store.get_operation(
                binding.origin_operation_id
            )
        except Exception as exc:
            raise WriteServiceError(
                "completed recovery has no durable origin binding"
            ) from exc
        plan = self._bound_origin_recovery_plan(origin, binding)
        self._assert_recovery_operation_binding(
            recovery_operation,
            origin,
            plan["plan_digest"],
            binding,
        )

        records = self._store.get_trusted_result_records(
            recovery_operation.operation_id
        )
        executions = [
            record for record in records if record.kind == "execution"
        ]
        verifications = [
            record for record in records if record.kind == "verification"
        ]
        if (
            len(records) != 2
            or len(executions) != 1
            or len(verifications) != 1
        ):
            raise WriteServiceError(
                "recovery operation trusted results are incomplete"
            )
        execution = self._stored_backend_evidence(executions[0])
        verification = self._stored_backend_evidence(verifications[0])
        self._verify_terminal_trusted_results(
            operation=recovery_operation,
            execution=execution,
            verification=verification,
        )
        try:
            capability = self._capabilities[recovery_operation.capability_id]
        except KeyError as exc:
            raise WriteServiceError(
                "recovery operation capability is unavailable"
            ) from exc
        self._validate_execution_evidence(
            execution,
            recovery_operation,
            capability,
        )
        self._validate_verification_evidence(
            verification,
            recovery_operation,
            capability,
            execution,
        )

        final_receipts = [
            receipt
            for receipt in self._store.get_final_write_receipts(
                recovery_operation.operation_id
            )
            if receipt.operation_revision == recovery_operation.revision
            and receipt.terminal_state == State.COMPLETED.value
        ]
        if len(final_receipts) != 1:
            raise WriteServiceError(
                "recovery operation has no unique final receipt"
            )
        final_receipt = final_receipts[0]
        if (
            final_receipt.result_id != verifications[0].result_id
            or final_receipt.evidence_digest
            != verification.result.evidence_digest
        ):
            raise WriteServiceError(
                "recovery operation final receipt differs from verification"
            )
        events = {
            event.event_id: event for event in self._store.audit_events()
        }
        try:
            terminal_event = events[verifications[0].audit_event_id]
        except KeyError as exc:
            raise WriteServiceError(
                "recovery operation terminal audit event is missing"
            ) from exc
        if (
            terminal_event.operation_id != recovery_operation.operation_id
            or final_receipt.audit_event_id != terminal_event.event_id
            or final_receipt.body.get("audit_event_hash")
            != terminal_event.event_hash
        ):
            raise WriteServiceError(
                "recovery operation terminal audit binding is invalid"
            )
        details = final_receipt.body.get("receipt_details")
        database_finalization = self._validated_database_finalization(
            recovery_operation,
            (
                details.get("database_finalization")
                if isinstance(details, dict)
                else None
            ),
            execution=execution,
            verification=verification,
        )
        result_body = self._receipt_details(
            operation=recovery_operation,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
        )
        self._receipt_channel(
            final_receipt,
            result_body=result_body,
            pinned_channel=self._pinned_capability_channel(
                recovery_operation
            ),
        )
        return (
            origin,
            binding,
            plan,
            execution,
            verification,
            final_receipt,
            terminal_event,
            database_finalization,
        )

    def _rebuild_origin_recovery_completion_evidence(
        self,
        *,
        recovery_operation: Operation,
    ) -> OriginRecoveryCompletionEvidence:
        (
            origin,
            binding,
            plan,
            execution,
            verification,
            final_receipt,
            terminal_event,
            database_finalization,
        ) = self._recovery_resolution_sources(recovery_operation)
        failed_origin = replace(
            origin,
            state=State.FAILED,
            revision=binding.origin_operation_revision,
        )
        failed_origin.assert_integrity()
        if not hmac.compare_digest(
            plan["plan_digest"],
            recovery_operation.parameters[
                "expected_recovery_plan_digest"
            ],
        ):
            raise WriteServiceError(
                "recovery operation plan differs from its origin"
            )
        try:
            return create_origin_recovery_completion_evidence(
                origin_operation=failed_origin,
                recovery_operation=recovery_operation,
                recovery_plan_digest=plan["plan_digest"],
                recovery_execution_result=execution.result,
                recovery_execution_evidence=execution.evidence,
                recovery_verification_result=verification.result,
                recovery_verification_evidence=verification.evidence,
                recovery_final_receipt_id=final_receipt.receipt_id,
                recovery_final_receipt_body=final_receipt.body,
                recovery_final_receipt_body_digest=final_receipt.body_digest,
                terminal_audit_event_id=terminal_event.event_id,
                terminal_audit_event_hash=terminal_event.event_hash,
                database_finalization=database_finalization,
            )
        except OriginRecoveryCompletionError as exc:
            raise WriteServiceError(
                "recovery completion evidence is invalid"
            ) from exc

    @staticmethod
    def _origin_recovery_receipt_details(
        operation: Operation,
        evidence: OriginRecoveryCompletionEvidence,
    ) -> dict[str, Any]:
        if (
            operation.state != State.RECOVERED
            or operation.operation_id
            != evidence.origin_operation.operation_id
            or operation.revision
            != evidence.origin_operation.operation_revision + 2
        ):
            raise WriteServiceError(
                "origin recovery receipt operation binding is invalid"
            )
        evidence_digest = (
            origin_recovery_completion_evidence_digest(evidence)
        )
        return {
            "operation_id": operation.operation_id,
            "operation_state": State.RECOVERED.value,
            "recovery_completion": evidence.to_dict(),
            "recovery_completion_digest": evidence_digest,
        }

    def _validate_recovered_origin(
        self,
        *,
        origin: Operation,
        binding: Any,
        plan: dict[str, Any],
        expected: OriginRecoveryCompletionEvidence,
        resolution_receipt: Any,
    ) -> None:
        if (
            origin.state != State.RECOVERED
            or origin.revision != binding.origin_operation_revision + 2
        ):
            raise WriteServiceError(
                "origin operation is not durably recovered"
            )
        recovery_records = self._store.get_recovery_records(
            origin.operation_id
        )
        if (
            len(recovery_records) != 1
            or recovery_records[0].operation_revision
            != binding.origin_operation_revision
            or recovery_records[0].from_state != State.FAILED.value
            or not hmac.compare_digest(
                recovery_records[0].plan_digest,
                plan["plan_digest"],
            )
            or canonical_json(recovery_records[0].plan)
            != canonical_json(plan)
            or recovery_records[0].initiated_at
            < resolution_receipt.recorded_at
        ):
            raise WriteServiceError(
                "origin recovery transition record is invalid"
            )
        results = self._store.get_trusted_result_records(
            origin.operation_id
        )
        recovery_results = [
            record for record in results if record.kind == "recovery"
        ]
        if len(results) != 3 or len(recovery_results) != 1:
            raise WriteServiceError(
                "origin recovery trusted result is not unique"
            )
        record = recovery_results[0]
        try:
            evidence = validate_origin_recovery_completion_evidence(
                record.evidence,
                expected=expected,
            )
        except OriginRecoveryCompletionError as exc:
            raise WriteServiceError(
                "origin recovery completion evidence is invalid"
            ) from exc
        evidence_digest = (
            origin_recovery_completion_evidence_digest(evidence)
        )
        if (
            not hmac.compare_digest(record.evidence_digest, evidence_digest)
            or not hmac.compare_digest(
                record.prior_evidence_digest or "",
                plan["plan_digest"],
            )
            or record.succeeded is not True
        ):
            raise WriteServiceError(
                "origin recovery trusted result binding is invalid"
            )
        trusted = self._stored_backend_evidence(record).result
        recovering = replace(
            origin,
            state=State.RECOVERING,
            revision=origin.revision - 1,
        )
        recovering.assert_integrity()
        try:
            reconstructed = validate_complete_recovery(
                recovering,
                trusted,
                recovery_plan_digest=plan["plan_digest"],
                now=self._now(),
                secret=self._security.verification_secret,
                expected_key_id=self._security.verification_key_id,
                allowed_issuers=self._security.verification_issuers,
                expected_revision=recovering.revision,
            )
        except Exception as exc:
            raise WriteServiceError(
                "origin recovery trusted result signature is invalid"
            ) from exc
        if reconstructed != origin:
            raise WriteServiceError(
                "origin recovery trusted result changed terminal state"
            )

        receipts = [
            receipt
            for receipt in self._store.get_final_write_receipts(
                origin.operation_id
            )
            if receipt.operation_revision == origin.revision
            and receipt.terminal_state == State.RECOVERED.value
        ]
        if len(receipts) != 1:
            raise WriteServiceError(
                "recovered origin has no unique final receipt"
            )
        receipt = receipts[0]
        expected_details = self._origin_recovery_receipt_details(
            origin,
            evidence,
        )
        if (
            receipt.result_id != record.result_id
            or receipt.evidence_digest != evidence_digest
            or receipt.audit_event_id != record.audit_event_id
            or receipt.recorded_at < recovery_records[0].initiated_at
            or canonical_json(receipt.body.get("evidence"))
            != canonical_json(evidence.to_dict())
            or canonical_json(receipt.body.get("receipt_details"))
            != canonical_json(expected_details)
        ):
            raise WriteServiceError(
                "recovered origin final receipt is invalid"
            )

    def _complete_incident_origin_recovery(
        self,
        *,
        recovery_operation: Operation,
    ) -> Operation:
        expected = self._rebuild_origin_recovery_completion_evidence(
            recovery_operation=recovery_operation,
        )
        binding = self._store.get_recovery_operation_binding(
            recovery_operation.operation_id
        )
        origin = self._store.get_operation(binding.origin_operation_id)
        plan = self._bound_origin_recovery_plan(origin, binding)
        resolution_receipt = self._store.get_final_write_receipt(
            expected.recovery_final_receipt.receipt_id
        )
        evidence_digest = (
            origin_recovery_completion_evidence_digest(expected)
        )

        for _attempt in range(3):
            origin = self._store.get_operation(binding.origin_operation_id)
            self._assert_recovery_operation_binding(
                recovery_operation,
                origin,
                plan["plan_digest"],
                binding,
            )
            if origin.state == State.RECOVERED:
                self._validate_recovered_origin(
                    origin=origin,
                    binding=binding,
                    plan=plan,
                    expected=expected,
                    resolution_receipt=resolution_receipt,
                )
                return origin
            if origin.state == State.FAILED:
                occurred_at = self._now()
                if occurred_at < resolution_receipt.recorded_at:
                    raise WriteServiceError(
                        "origin recovery transition predates its resolution receipt"
                    )
                try:
                    origin = self._store.begin_recovery(
                        operation_id=origin.operation_id,
                        recovery_plan=plan,
                        recovery_plan_digest=plan["plan_digest"],
                        actor_principal=origin.principal,
                        actor_user_id=origin.user_id,
                        actor_company_id=origin.company_id,
                        occurred_at=occurred_at,
                        expected_revision=origin.revision,
                    ).operation
                except PersistenceConcurrentUpdate:
                    continue
            if origin.state != State.RECOVERING:
                raise WriteServiceError(
                    "origin recovery lifecycle is invalid"
                )
            records = self._store.get_recovery_records(
                origin.operation_id
            )
            if (
                len(records) != 1
                or records[0].initiated_at
                < resolution_receipt.recorded_at
                or not hmac.compare_digest(
                    records[0].plan_digest,
                    plan["plan_digest"],
                )
                or canonical_json(records[0].plan)
                != canonical_json(plan)
            ):
                raise WriteServiceError(
                    "origin recovering state has no exact durable plan"
                )
            verification_records = [
                record
                for record in self._store.get_trusted_result_records(
                    recovery_operation.operation_id
                )
                if record.kind == "verification"
            ]
            if len(verification_records) != 1:
                raise WriteServiceError(
                    "recovery resolution verifier is not unique"
                )
            completed_at = self._now()
            result = sign_recovery_result(
                operation=origin,
                recovery_plan_digest=plan["plan_digest"],
                issuer=verification_records[0].issuer,
                key_id=self._security.verification_key_id,
                succeeded=True,
                evidence_digest=evidence_digest,
                issued_at=completed_at,
                secret=self._security.verification_secret,
            )
            try:
                acceptance = self._store.complete_recovery(
                    result,
                    evidence=expected.to_dict(),
                    now=completed_at,
                    secret=self._security.verification_secret,
                    expected_key_id=self._security.verification_key_id,
                    allowed_issuers=self._security.verification_issuers,
                    expected_revision=origin.revision,
                    receipt_factory=lambda terminal: (
                        self._origin_recovery_receipt_details(
                            terminal,
                            expected,
                        )
                    ),
                )
            except PersistenceConcurrentUpdate:
                continue
            self._validate_recovered_origin(
                origin=acceptance.operation,
                binding=binding,
                plan=plan,
                expected=expected,
                resolution_receipt=resolution_receipt,
            )
            return acceptance.operation
        raise WriteServiceError(
            "origin recovery completion lost a concurrent update race"
        )

    def trusted_recovery_plan(
        self,
        context: RequestContext,
        operation: Operation,
    ) -> dict[str, Any] | None:
        """Load the server-held plan supplied to the Odoo recovery handler."""

        if operation.capability_id != "acct.recovery.execute.v1":
            return None
        self._assert_context_binding(context, operation)
        try:
            binding = self._store.get_recovery_operation_binding(
                operation.operation_id
            )
        except OperationNotFound as exc:
            raise WriteServiceError(
                "recovery operation has no durable origin binding"
            ) from exc
        origin = self.status(
            context, operation.parameters["origin_operation_id"]
        )
        plan = self._validated_origin_recovery_plan(
            context,
            origin,
            expected_plan_digest=operation.parameters[
                "expected_recovery_plan_digest"
            ],
        )
        self._assert_recovery_operation_binding(
            operation, origin, plan["plan_digest"], binding
        )
        return plan

    def _assert_live_precheck(
        self,
        context: RequestContext,
        capability: Capability,
        operation: Operation,
    ) -> None:
        live_precheck = self._precheck_executor(
            context,
            capability,
            operation,
            self._registry_digest,
            self._release_digest,
        )
        self._validate_precheck_evidence_binding(
            operation,
            live_precheck,
            expected_channel=self._pinned_capability_channel(operation),
        )
        if (
            not isinstance(live_precheck, dict)
            or live_precheck.get("passed") is not True
            or live_precheck.get("capability_id") != capability.id
            or live_precheck.get("company_id") != operation.company_id
            or _digest(live_precheck) != operation.precheck_digest
        ):
            raise WriteServiceError(
                "live Odoo precheck no longer matches the approved preview"
            )

    @staticmethod
    def _executing_snapshot(operation: Operation) -> Operation:
        if operation.state == State.EXECUTING:
            operation.assert_integrity()
            return operation
        if operation.state != State.VERIFYING or operation.revision <= 0:
            raise WriteServiceError("operation has no reconstructable executing state")
        snapshot = replace(
            operation,
            state=State.EXECUTING,
            revision=operation.revision - 1,
            execution_result_digest=None,
        )
        snapshot.assert_integrity()
        return snapshot

    def _validate_replayed_approval(
        self,
        operation: Operation,
        approval: Approval,
        capability: Capability,
    ) -> Operation:
        executing = self._executing_snapshot(operation)
        if executing.revision <= 0:
            raise WriteServiceError("executing operation revision is invalid")
        approved = replace(
            executing,
            state=State.APPROVED,
            revision=executing.revision - 1,
        )
        approved.assert_integrity()
        record = self._store.get_approval_record(operation.operation_id)
        if record.record_origin != "native_v3" or record.accepted_at is None:
            raise WriteServiceError("operation has no replayable native approval")
        try:
            replayed = validate_begin_execution(
                approved,
                approval,
                now=record.accepted_at,
                secret=self._security.approval_secret,
                expected_key_id=self._security.approval_key_id,
                # The native approval was authorized and durably accepted
                # before execution began.  Reconciliation of an already
                # executing Odoo anchor must remain possible after later ACL
                # revocation; a missing/claimed anchor is still blocked by the
                # Odoo-side live ACL gate.
                is_approver_authorized=lambda *_args: True,
                approval_ttl_seconds=self._approval_ttl_seconds(capability),
                expected_revision=approved.revision,
            )
        except Exception as exc:
            raise WriteServiceError("resubmitted approval does not match the durable approval") from exc
        if replayed != executing:
            raise WriteServiceError("replayed approval changed the executing operation")
        return executing

    def _approval_ttl_seconds(self, capability: Capability) -> int:
        capability_ttl = capability.data["approval"]["ttl_seconds"]
        if (
            isinstance(capability_ttl, bool)
            or not isinstance(capability_ttl, int)
            or capability_ttl <= 0
        ):
            raise WriteServiceError("capability approval TTL is invalid")
        return min(self._security.approval_ttl_seconds, capability_ttl)

    def _stored_execution_for_verifying(
        self,
        operation: Operation,
        capability: Capability,
    ) -> tuple[Operation, BackendEvidence]:
        executing = self._executing_snapshot(operation)
        records = self._store.get_trusted_result_records(operation.operation_id)
        execution_records = [record for record in records if record.kind == "execution"]
        verification_records = [record for record in records if record.kind == "verification"]
        if len(execution_records) != 1 or verification_records:
            raise WriteServiceError("verifying operation has invalid durable result evidence")
        execution = self._stored_backend_evidence(execution_records[0])
        self._validate_execution_evidence(execution, executing, capability)
        try:
            reconstructed = validate_execution_result(
                executing,
                execution.result,
                now=self._now(),
                secret=self._security.execution_secret,
                expected_key_id=self._security.execution_key_id,
                allowed_issuers=self._security.execution_issuers,
                expected_revision=executing.revision,
            )
        except Exception as exc:
            raise WriteServiceError("durable execution result cannot resume verification") from exc
        if reconstructed != operation:
            raise WriteServiceError("durable execution result changed the verifying operation")
        return executing, execution

    @staticmethod
    def _same_backend_evidence(left: BackendEvidence, right: BackendEvidence) -> bool:
        return left.result == right.result and hmac.compare_digest(
            canonical_json(left.evidence), canonical_json(right.evidence)
        )

    def _call_write_backend(
        self,
        context: RequestContext,
        capability: Capability,
        executing: Operation,
        approval: Approval,
    ) -> BackendWriteOutcome:
        if self._execute_and_verify is not None:
            outcome = self._execute_and_verify(
                context,
                capability,
                executing,
                approval,
                self._registry_digest,
                self._release_digest,
            )
            if not isinstance(outcome, BackendWriteOutcome):
                raise WriteServiceError("combined Odoo backend returned an invalid outcome")
            return outcome
        return BackendWriteOutcome(
            execution=self._write_executor(
                context,
                capability,
                executing,
                approval,
                self._registry_digest,
                self._release_digest,
            ),
            verification=None,
        )

    def _verification_backend(
        self,
        context: RequestContext,
        capability: Capability,
        verifying: Operation,
        execution: BackendEvidence,
        combined: BackendEvidence | None,
    ) -> BackendEvidence:
        if combined is not None:
            return combined
        return self._verification_executor(
            context,
            capability,
            verifying,
            execution.evidence,
            self._registry_digest,
            self._release_digest,
        )

    def _terminal_output(
        self,
        *,
        operation: Operation,
        capability: Capability,
        capability_channel: str,
        approval: Approval,
        execution: BackendEvidence,
        verification: BackendEvidence | None,
        database_finalization: dict[str, Any] | None,
        final_receipt: Any,
        terminal_audit_event: Any,
    ) -> dict[str, Any]:
        if final_receipt is None:
            raise WriteServiceError("terminal write has no durable final receipt")
        database_finalization = self._validated_database_finalization(
            operation,
            database_finalization,
            execution=execution,
            verification=verification,
        )
        result_body = self._receipt_details(
            operation=operation,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
        )
        if (
            final_receipt.audit_event_id != terminal_audit_event.event_id
        ):
            raise WriteServiceError("durable final receipt content is invalid")
        self._receipt_channel(
            final_receipt,
            result_body=result_body,
            pinned_channel=capability_channel,
        )
        return self._result_output(
            operation=operation,
            capability=capability,
            capability_channel=capability_channel,
            approver_user_id=approval.approver_user_id,
            approval_digest=approval.signature,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
            terminal_audit_event=terminal_audit_event,
        )

    def approve_execute(
        self,
        context: RequestContext,
        approval: Approval,
        *,
        reconciliation_only: bool,
    ) -> dict[str, Any]:
        if type(reconciliation_only) is not bool:
            raise WriteServiceError("reconciliation_only must be a boolean")
        operation = self.status(context, approval.operation_id)
        if operation.state in {State.COMPLETED, State.FAILED}:
            if not reconciliation_only:
                raise WriteServiceError(
                    "terminal operation retrieval requires reconciliation-only authority"
                )
            self._consume_authenticated_write(
                context, operation.capability_id, operation.parameters
            )
            return self.result(context, operation.operation_id)
        approval_expired = self._now() >= approval.expires_at
        if reconciliation_only:
            if not (
                operation.state is State.VERIFYING
                or (
                    operation.state is State.EXECUTING
                    and approval_expired
                )
            ):
                raise WriteServiceError(
                    "reconciliation-only authority requires verifying state or an expired executing operation"
                )
        elif operation.state is State.VERIFYING:
            raise WriteServiceError(
                "verifying operation requires reconciliation-only authority"
            )
        elif approval_expired:
            raise WriteServiceError(
                "expired approval requires reconciliation-only authority"
            )
        capability = self._capability(
            context,
            operation,
            enforce_acl=operation.state not in {State.EXECUTING, State.VERIFYING},
            enforce_availability=operation.state
            not in {State.EXECUTING, State.VERIFYING},
        )
        if operation.state not in {
            State.AWAITING_APPROVAL,
            State.APPROVED,
            State.EXECUTING,
            State.VERIFYING,
        }:
            raise WriteServiceError("operation cannot execute from its current state")
        capability_channel = self._pinned_capability_channel(operation)
        self._consume_authenticated_write(
            context, capability.id, operation.parameters
        )
        live_precheck_confirmed = False
        approval_ttl_seconds = self._approval_ttl_seconds(capability)

        if operation.state == State.AWAITING_APPROVAL:
            approve_operation(
                operation,
                approval,
                now=self._now(),
                secret=self._security.approval_secret,
                expected_key_id=self._security.approval_key_id,
                is_approver_authorized=self._approver_authorized,
                consume_nonce=lambda *_args: True,
                approval_ttl_seconds=approval_ttl_seconds,
                expected_revision=operation.revision,
            )
            self._assert_live_precheck(context, capability, operation)
            live_precheck_confirmed = True
            accepted = self._store.accept_approval(
                approval,
                now=self._now(),
                secret=self._security.approval_secret,
                expected_key_id=self._security.approval_key_id,
                is_approver_authorized=self._approver_authorized,
                approval_ttl_seconds=approval_ttl_seconds,
                expected_revision=operation.revision,
            )
            operation = accepted.operation

        if operation.state == State.APPROVED:
            validate_begin_execution(
                operation,
                approval,
                now=self._now(),
                secret=self._security.approval_secret,
                expected_key_id=self._security.approval_key_id,
                is_approver_authorized=self._approver_authorized,
                approval_ttl_seconds=approval_ttl_seconds,
                expected_revision=operation.revision,
            )
            if not live_precheck_confirmed:
                self._assert_live_precheck(context, capability, operation)
            executing = self._store.begin_execution(
                approval,
                now=self._now(),
                secret=self._security.approval_secret,
                expected_key_id=self._security.approval_key_id,
                is_approver_authorized=self._approver_authorized,
                approval_ttl_seconds=approval_ttl_seconds,
                expected_revision=operation.revision,
            ).operation
        elif operation.state in {State.EXECUTING, State.VERIFYING}:
            executing = self._validate_replayed_approval(
                operation, approval, capability
            )
        else:  # The accepted approval above must produce State.APPROVED.
            raise WriteServiceError("operation approval transition is invalid")

        if operation.state == State.VERIFYING:
            stored_executing, execution = self._stored_execution_for_verifying(
                operation, capability
            )
            if stored_executing != executing:
                raise WriteServiceError("verifying execution snapshot changed")
            combined_verification = None
            if self._execute_and_verify is not None:
                replay = self._call_write_backend(
                    context, capability, executing, approval
                )
                self._validate_execution_evidence(
                    replay.execution, executing, capability
                )
                if not self._same_backend_evidence(replay.execution, execution):
                    raise WriteServiceError(
                        "Odoo anchor replay differs from durable execution evidence"
                    )
                combined_verification = replay.verification
            verifying = operation
        else:
            outcome = self._call_write_backend(
                context, capability, executing, approval
            )
            execution = outcome.execution
            combined_verification = outcome.verification
            if not execution.result.succeeded and combined_verification is not None:
                raise WriteServiceError(
                    "failed execution cannot include verification evidence"
                )
        self._validate_execution_evidence(execution, executing, capability)
        if execution.result.succeeded and execution.result.issued_at >= approval.expires_at:
            raise WriteServiceError("execution evidence was issued after approval expiry")

        if operation.state != State.VERIFYING:
            execution_acceptance = self._store.record_execution_result(
                execution.result,
                evidence=execution.evidence,
                now=self._now(),
                secret=self._security.execution_secret,
                expected_key_id=self._security.execution_key_id,
                allowed_issuers=self._security.execution_issuers,
                expected_revision=executing.revision,
                receipt_factory=(
                    None
                    if execution.result.succeeded
                    else lambda terminal: self._durable_receipt_details(
                        operation=terminal,
                        execution=execution,
                        verification=None,
                        capability_channel=capability_channel,
                        database_finalization=None,
                    )
                ),
            )
            if execution_acceptance.operation.state == State.FAILED:
                return self._terminal_output(
                    operation=execution_acceptance.operation,
                    capability=capability,
                    capability_channel=capability_channel,
                    approval=approval,
                    execution=execution,
                    verification=None,
                    database_finalization=None,
                    final_receipt=execution_acceptance.final_receipt,
                    terminal_audit_event=execution_acceptance.audit_event,
                )
            verifying = execution_acceptance.operation

        verification = self._verification_backend(
            context,
            capability,
            verifying,
            execution,
            combined_verification,
        )
        self._validate_verification_evidence(
            verification, verifying, capability, execution
        )
        try:
            terminal_candidate = validate_complete_operation(
                verifying,
                verification.result,
                now=self._now(),
                secret=self._security.verification_secret,
                expected_key_id=self._security.verification_key_id,
                allowed_issuers=self._security.verification_issuers,
                expected_revision=verifying.revision,
            )
        except Exception as exc:
            raise WriteServiceError(
                "trusted verification result cannot enter a terminal state"
            ) from exc
        self._verify_terminal_trusted_results(
            operation=terminal_candidate,
            execution=execution,
            verification=verification,
        )
        database_finalization = None
        if terminal_candidate.state == State.COMPLETED:
            try:
                intent = self._verified_effect_finalization_intent(
                    terminal_candidate,
                    execution,
                    verification,
                )
                finalization_receipt = self._effect_finalizer(intent)
                if not isinstance(
                    finalization_receipt, EffectFinalizationReceipt
                ):
                    raise EffectFinalizationError(
                        "effect finalizer returned no typed database receipt"
                    )
                finalization_receipt.validate_for_intent(intent)
                database_finalization = finalization_receipt.evidence
                validate_effect_finalization_evidence(
                    database_finalization,
                    intent=intent,
                    expected_attestation_key_id=(
                        self._effect_finalizer_identity.attestation_key_id
                    ),
                    expected_guard_installation_id=(
                        self._effect_finalizer_identity.guard_installation_id
                    ),
                    expected_database_oid=(
                        self._effect_finalizer_identity.database_oid
                    ),
                )
            except Exception as exc:
                raise WriteServiceError(
                    "database effect finalization failed; operation remains verifying"
                ) from exc
        final_acceptance = self._store.complete_operation(
            verification.result,
            evidence=verification.evidence,
            now=self._now(),
            secret=self._security.verification_secret,
            expected_key_id=self._security.verification_key_id,
            allowed_issuers=self._security.verification_issuers,
            expected_revision=verifying.revision,
            receipt_factory=lambda terminal: self._durable_receipt_details(
                operation=terminal,
                execution=execution,
                verification=verification,
                capability_channel=capability_channel,
                database_finalization=database_finalization,
            ),
        )
        output = self._terminal_output(
            operation=final_acceptance.operation,
            capability=capability,
            capability_channel=capability_channel,
            approval=approval,
            execution=execution,
            verification=verification,
            database_finalization=database_finalization,
            final_receipt=final_acceptance.final_receipt,
            terminal_audit_event=final_acceptance.audit_event,
        )
        if (
            final_acceptance.operation.state == State.COMPLETED
            and final_acceptance.operation.capability_id
            == "acct.recovery.execute.v1"
        ):
            self._complete_incident_origin_recovery(
                recovery_operation=final_acceptance.operation,
            )
        return output

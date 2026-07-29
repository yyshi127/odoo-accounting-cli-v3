"""Pure, fail-closed validation for executing a recovery plan.

The guard in this module performs no Odoo access and no mutation.  It binds a
receipt-derived, available V2 recovery plan to one registered action contract,
one non-production runtime, one company, one installed-module graph, and the
caller's freshly reconstructed action/guard reference graph.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import Any

from .operations import canonical_json
from .recovery_contracts import (
    RecoveryContractError,
    select_recovery_action_contract,
)
from .write_receipts import (
    WriteReceiptError,
    index_recovery_guard_graph,
    validate_executable_recovery_plan,
)


class RecoveryPlanExecutionGuardError(ValueError):
    """Recovery execution inputs do not match one immutable plan contract."""


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MODEL = re.compile(r"^[a-z][a-z0-9_.]{0,127}$")
_NON_PRODUCTION_ENVIRONMENTS = frozenset({"test", "sandbox"})
_TERMINAL_CAPABILITY_IDS = frozenset(
    {"acct.move.draft_cancel.v1", "acct.recovery.execute.v1"}
)
_TARGET_FIELDS = frozenset(
    {
        "company_id",
        "model",
        "record_fingerprint",
        "record_id",
        "record_state",
    }
)
_ACTION_REFERENCE_FIELDS = _TARGET_FIELDS | {"role"}
_GUARD_REFERENCE_FIELDS = _TARGET_FIELDS | {"role", "expected_outcome"}


@dataclass(frozen=True, slots=True, order=True)
class NormalizedRecoveryRecord:
    """One immutable, canonically ordered action or guard record binding."""

    role: str
    model: str
    record_id: int
    company_id: int
    record_state: str
    record_fingerprint: str
    expected_outcome: str | None

    @property
    def identity(self) -> tuple[str, int]:
        return self.model, self.record_id


@dataclass(frozen=True, slots=True)
class RecoveryPlanExecutionGuard:
    """Frozen output proving all inputs matched before a recovery write."""

    origin_capability_id: str
    origin_operation_id: str
    recovery_capability_id: str
    environment: str
    company_id: int
    module_graph_digest: str
    method: str
    oracle_id: str
    plan_digest: str
    parameters_digest: str
    guard_graph_digest: str
    actions: tuple[NormalizedRecoveryRecord, ...]
    guards: tuple[NormalizedRecoveryRecord, ...]

    @property
    def action_identities(self) -> tuple[tuple[str, int], ...]:
        return tuple(record.identity for record in self.actions)

    @property
    def guard_identities(self) -> tuple[tuple[str, int], ...]:
        return tuple(record.identity for record in self.guards)

    @property
    def guard_outcomes(self) -> tuple[tuple[str, int, str], ...]:
        return tuple(
            (record.model, record.record_id, record.expected_outcome)
            for record in self.guards
            if record.expected_outcome is not None
        )


def _error(message: str) -> RecoveryPlanExecutionGuardError:
    return RecoveryPlanExecutionGuardError(message)


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise _error(f"{field} is invalid")
    return value


def _sha256(value: Any, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise _error(f"{field} must be a lowercase SHA-256 digest")
    return value


def _positive_integer(value: Any, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise _error(f"{field} must be a positive integer")
    return value


def _digest(value: Any, field: str) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error(f"{field} is not canonical JSON") from exc


def _canonical_parameter_binding(
    *,
    plan: dict[str, Any],
    company_id: int,
    module_graph_digest: str,
) -> dict[str, Any]:
    def identities(field: str) -> list[dict[str, Any]]:
        return [
            {"model": record["model"], "record_id": record["record_id"]}
            for record in sorted(
                plan[field],
                key=lambda item: (item["model"], item["record_id"]),
            )
        ]

    return {
        "company_id": company_id,
        "origin_operation_id": plan["origin_operation_id"],
        "module_graph_digest": module_graph_digest,
        "method": plan["method"],
        "action_targets": identities("action_targets"),
        "guard_records": identities("guard_records"),
        "oracle_id": plan["oracle_id"],
    }


def _validate_current_reference(
    key: Any,
    value: Any,
    *,
    expected_company_id: int,
) -> tuple[tuple[str, int], dict[str, Any]]:
    if (
        type(key) is not tuple
        or len(key) != 2
        or type(key[0]) is not str
        or _MODEL.fullmatch(key[0]) is None
        or type(key[1]) is not int
        or key[1] <= 0
    ):
        raise _error("current recovery record identity is invalid")
    if not isinstance(value, Mapping):
        raise _error("current recovery record reference must be an object")
    reference = dict(value)
    role = reference.get("role")
    expected_fields = (
        _ACTION_REFERENCE_FIELDS if role == "action" else _GUARD_REFERENCE_FIELDS
        if role == "guard"
        else None
    )
    if expected_fields is None:
        raise _error("current recovery record role is invalid")
    if frozenset(reference) != expected_fields:
        raise _error("current recovery record reference fields are invalid")
    model = _text(reference["model"], "current recovery record model", maximum=128)
    if _MODEL.fullmatch(model) is None:
        raise _error("current recovery record model is invalid")
    record_id = _positive_integer(
        reference["record_id"], "current recovery record_id"
    )
    company_id = _positive_integer(
        reference["company_id"], "current recovery company_id"
    )
    if company_id != expected_company_id:
        raise _error("current recovery record company mismatch")
    _text(
        reference["record_state"],
        "current recovery record_state",
        maximum=128,
    )
    _sha256(
        reference["record_fingerprint"],
        "current recovery record_fingerprint",
    )
    if key != (model, record_id):
        raise _error("current recovery record key differs from its payload")
    if role == "guard":
        _text(
            reference["expected_outcome"],
            "current recovery expected_outcome",
            maximum=64,
        )
    return key, reference


def _current_graph(
    value: Any,
    *,
    expected_company_id: int,
) -> dict[tuple[str, int], dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise _error("current_record_references must be a mapping")
    graph: dict[tuple[str, int], dict[str, Any]] = {}
    payload_identities: set[tuple[str, int]] = set()
    try:
        items = list(value.items())
    except (AttributeError, TypeError, ValueError) as exc:
        raise _error("current_record_references is invalid") from exc
    for raw_key, raw_reference in items:
        key, reference = _validate_current_reference(
            raw_key,
            raw_reference,
            expected_company_id=expected_company_id,
        )
        payload_identity = (reference["model"], reference["record_id"])
        if key in graph or payload_identity in payload_identities:
            raise _error("current recovery record graph contains a duplicate")
        graph[key] = reference
        payload_identities.add(payload_identity)
    if len(graph) != len(value):
        raise _error("current recovery record graph contains a duplicate")
    return graph


def _normalized_record(reference: dict[str, Any]) -> NormalizedRecoveryRecord:
    return NormalizedRecoveryRecord(
        role=reference["role"],
        model=reference["model"],
        record_id=reference["record_id"],
        company_id=reference["company_id"],
        record_state=reference["record_state"],
        record_fingerprint=reference["record_fingerprint"],
        expected_outcome=reference.get("expected_outcome"),
    )


def validate_recovery_plan_execution(
    plan: Any,
    *,
    origin_capability_id: str,
    origin_operation_id: str,
    expected_plan_digest: str,
    environment: str,
    company_id: int,
    module_graph_digest: str,
    current_record_references: Mapping[
        tuple[str, int], Mapping[str, Any]
    ],
) -> RecoveryPlanExecutionGuard:
    """Validate and freeze one exact recovery execution graph.

    ``current_record_references`` must have the exact shape returned by
    :func:`write_receipts.index_recovery_guard_graph`, rebuilt from fresh
    pre-write record references.  Every field is compared to the receipt plan;
    missing, extra, duplicate, overlapping, re-roled, or changed references
    are rejected.
    """

    if type(plan) is not dict:
        raise _error("recovery execution plan must be a plain object")
    try:
        validate_executable_recovery_plan(plan)
    except (TypeError, ValueError, WriteReceiptError) as exc:
        raise _error("recovery execution requires a valid available V2 plan") from exc

    origin_capability_id = _text(
        origin_capability_id, "origin_capability_id", maximum=128
    )
    if origin_capability_id in _TERMINAL_CAPABILITY_IDS:
        raise _error("terminal capability has no executable recovery")
    origin_operation_id = _text(
        origin_operation_id, "origin_operation_id", maximum=512
    )
    expected_plan_digest = _sha256(
        expected_plan_digest, "expected_plan_digest"
    )
    environment = _text(environment, "environment", maximum=32)
    if environment not in _NON_PRODUCTION_ENVIRONMENTS:
        raise _error("recovery execution is restricted to test and sandbox")
    company_id = _positive_integer(company_id, "company_id")
    module_graph_digest = _sha256(
        module_graph_digest, "module_graph_digest"
    )

    if plan["origin_operation_id"] != origin_operation_id:
        raise _error("recovery plan origin operation mismatch")
    if not hmac.compare_digest(plan["plan_digest"], expected_plan_digest):
        raise _error("recovery plan digest mismatch")

    try:
        contract = select_recovery_action_contract(
            origin_capability_id,
            plan["method"],
            plan["oracle_id"],
        )
    except RecoveryContractError as exc:
        raise _error(
            "recovery plan does not match an executable origin contract"
        ) from exc
    if (
        environment not in contract.allowed_environments
        or contract.production_promotion_allowed
    ):
        raise _error("recovery contract is not executable in this environment")

    try:
        planned_graph = index_recovery_guard_graph(
            plan, expected_company_id=company_id
        )
    except (TypeError, ValueError, WriteReceiptError) as exc:
        raise _error("recovery plan graph is not uniquely company-bound") from exc

    action_keys = {
        key for key, reference in planned_graph.items()
        if reference["role"] == "action"
    }
    guard_keys = {
        key for key, reference in planned_graph.items()
        if reference["role"] == "guard"
    }
    if (
        not action_keys
        or not guard_keys
        or action_keys & guard_keys
        or action_keys | guard_keys != set(planned_graph)
    ):
        raise _error("recovery plan action and guard roles are incomplete")
    for key in action_keys:
        model = key[0]
        if model not in contract.action_models or model not in contract.result_models:
            raise _error("recovery action model is outside its contract")
    for key in guard_keys:
        reference = planned_graph[key]
        model = key[0]
        if model not in contract.guard_models or model not in contract.result_models:
            raise _error("recovery guard model is outside its contract")
        if reference["expected_outcome"] not in contract.allowed_guard_outcomes:
            raise _error("recovery guard outcome is outside its contract")

    expected_parameters = _canonical_parameter_binding(
        plan=plan,
        company_id=company_id,
        module_graph_digest=module_graph_digest,
    )
    expected_parameters_digest = _digest(
        expected_parameters, "canonical recovery parameters"
    )
    if not hmac.compare_digest(
        plan["parameters_digest"], expected_parameters_digest
    ):
        raise _error(
            "recovery parameters digest does not bind the canonical graph"
        )

    current_graph = _current_graph(
        current_record_references,
        expected_company_id=company_id,
    )
    if set(current_graph) != set(planned_graph):
        raise _error(
            "current recovery graph has missing or unexpected identities"
        )
    for key in sorted(planned_graph):
        if current_graph[key] != planned_graph[key]:
            raise _error(
                "current recovery record differs from its approved reference"
            )

    actions = tuple(
        _normalized_record(current_graph[key])
        for key in sorted(action_keys)
    )
    guards = tuple(
        _normalized_record(current_graph[key])
        for key in sorted(guard_keys)
    )
    return RecoveryPlanExecutionGuard(
        origin_capability_id=origin_capability_id,
        origin_operation_id=origin_operation_id,
        recovery_capability_id=plan["recovery_capability_id"],
        environment=environment,
        company_id=company_id,
        module_graph_digest=module_graph_digest,
        method=contract.method,
        oracle_id=contract.oracle_id,
        plan_digest=plan["plan_digest"],
        parameters_digest=plan["parameters_digest"],
        guard_graph_digest=plan["guard_graph_digest"],
        actions=actions,
        guards=guards,
    )

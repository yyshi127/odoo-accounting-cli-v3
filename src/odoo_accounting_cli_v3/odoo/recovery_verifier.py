"""Independent, read-only recovery business-oracle verification.

The verifier accepts no execution-time check labels and performs no mutation.
It is intended to run after cache invalidation in a fresh, non-superuser Odoo
environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
from typing import Any, Mapping, Protocol, Sequence

from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)
from odoo_accounting_cli_v3.write_receipts import (
    WriteReceiptError,
    create_record_snapshot,
    validate_executable_recovery_plan,
)


class RecoveryVerificationError(ValueError):
    """Fresh recovery readback does not prove the approved business result."""


class RecoveryReadAdapter(Protocol):
    """Read-only surface required from the fresh bound Odoo handler."""

    def snapshot(
        self, model_name: str, record: Any, company: Any
    ) -> dict[str, Any]: ...

    def record_is_absent(
        self, model_name: str, record_id: int, company: Any
    ) -> bool: ...

    def move_records(
        self, move: Any, company: Any
    ) -> list[tuple[str, Any]]: ...

    def assert_linewise_reversal(
        self, origin: Any, reversal: Any, company: Any
    ) -> None: ...

    def assert_move_balanced(self, move: Any, company: Any) -> None: ...


RecordTuple = tuple[str, Any]
RecordIdentity = tuple[str, int]

_DRAFT_METHOD_TYPES: Mapping[str, frozenset[str]] = {
    "cancel_pristine_v3_draft_customer_invoice_v1": frozenset(
        {"out_invoice"}
    ),
    "cancel_pristine_v3_draft_vendor_bill_v1": frozenset({"in_invoice"}),
    "cancel_draft_refund_v1": frozenset({"out_refund", "in_refund"}),
    "cancel_draft_period_adjustment_v1": frozenset({"entry"}),
}
_GENERIC_METHOD_TYPES: Mapping[str, frozenset[str]] = {
    "reverse_posted_customer_invoice_v1": frozenset({"out_invoice"}),
    "reverse_posted_vendor_bill_v1": frozenset({"in_invoice"}),
    "reverse_posted_refund_v1": frozenset({"out_refund", "in_refund"}),
    "reverse_posted_period_adjustment_v1": frozenset({"entry"}),
    "reverse_the_reversal_v1": frozenset({"entry"}),
}
RECOVERY_VERIFICATION_METHODS = frozenset(RECOVERY_ACTION_CONTRACTS)
_IMPLEMENTED_VERIFICATION_METHODS = frozenset(
    {
        *_DRAFT_METHOD_TYPES,
        *_GENERIC_METHOD_TYPES,
        "cancel_and_unreconcile_payment_v1",
        "post_compensating_bank_statement_v1",
        "undo_reconciliation_and_reverse_writeoff_v1",
        "cancel_asset_and_reverse_schedule_v1",
        "reverse_depreciation_and_restore_schedule_v1",
        "cancel_scheduled_and_reverse_accrual_origin_v1",
        "reverse_deferred_source_and_schedule_v1",
    }
)
if _IMPLEMENTED_VERIFICATION_METHODS != RECOVERY_VERIFICATION_METHODS:
    raise RuntimeError(
        "recovery verification registry differs from recovery contracts"
    )
_REVERSED_MOVE_TYPE = {
    "out_invoice": "out_refund",
    "in_invoice": "in_refund",
    "out_refund": "out_invoice",
    "in_refund": "in_invoice",
    "entry": "entry",
}
_LOG_FIELDS = frozenset({"write_uid", "write_date"})
_RECONCILIATION_LINE_FIELDS = frozenset(
    {
        "amount_residual",
        "amount_residual_currency",
        "reconciled",
        "full_reconcile_id",
        "matched_debit_ids",
        "matched_credit_ids",
        "matching_number",
    }
)


def _error(message: str) -> RecoveryVerificationError:
    return RecoveryVerificationError(message)


def _record_id(value: Any) -> int | None:
    if value is False or value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    identifier = getattr(value, "id", None)
    if isinstance(identifier, bool) or not isinstance(identifier, int):
        return None
    return identifier if identifier > 0 else None


def _relation_id(value: Any) -> int | None:
    if isinstance(value, (list, tuple)):
        if (
            len(value) == 2
            and isinstance(value[0], int)
            and not isinstance(value[0], bool)
            and isinstance(value[1], str)
        ):
            return value[0] if value[0] > 0 else None
        identifiers = _relation_ids(value)
        if len(identifiers) > 1:
            raise _error("singular relation contains multiple identities")
        return identifiers[0] if identifiers else None
    return _record_id(value)


def _relation_ids(value: Any) -> tuple[int, ...]:
    if value is False or value is None:
        return ()
    if isinstance(value, bool):
        raise _error("record relation is ambiguous")
    identifiers = getattr(value, "ids", None)
    if identifiers is not None:
        raw = list(identifiers)
    elif isinstance(value, int):
        raw = [value]
    elif isinstance(value, (str, bytes, Mapping)):
        raise _error("record relation is ambiguous")
    else:
        try:
            raw = list(value)
        except TypeError:
            raw = [value]
    result: list[int] = []
    for item in raw:
        identifier = _record_id(item)
        if identifier is None:
            raise _error("record relation contains an invalid identity")
        result.append(identifier)
    if len(result) != len(set(result)):
        raise _error("record relation contains duplicate identities")
    return tuple(sorted(result))


def _state(record: Any) -> str:
    value = getattr(record, "state", None)
    if not isinstance(value, str) or not value:
        raise _error("fresh record has no auditable state")
    return value


def _decimal(value: Any, field: str) -> Decimal:
    if isinstance(value, bool):
        raise _error(f"{field} is not a finite amount")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise _error(f"{field} is not a finite amount") from exc
    if not result.is_finite():
        raise _error(f"{field} is not a finite amount")
    return result


def _iso_date(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise _error(f"{field} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise _error(f"{field} must be an ISO date") from exc
    if parsed.isoformat() != value:
        raise _error(f"{field} must be an ISO date")
    return value


def _reason(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 500
        or any(ord(character) < 32 for character in value)
    ):
        raise _error("reason is invalid")
    return value


def _digest(value: Any) -> str:
    try:
        return hashlib.sha256(canonical_json(value)).hexdigest()
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error("evidence value is not canonical JSON") from exc


def _company_id(company: Any) -> int:
    identifier = _record_id(company)
    if identifier is None:
        raise _error("company has no valid identity")
    return identifier


def _normalize_tombstones(value: Any) -> frozenset[RecordIdentity]:
    if isinstance(value, (str, bytes, Mapping)):
        raise _error("tombstone_keys must contain record identities")
    try:
        raw = list(value)
    except TypeError as exc:
        raise _error("tombstone_keys must contain record identities") from exc
    result: set[RecordIdentity] = set()
    for identity in raw:
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or not isinstance(identity[0], str)
            or not identity[0].startswith("account.")
            or isinstance(identity[1], bool)
            or not isinstance(identity[1], int)
            or identity[1] <= 0
        ):
            raise _error("tombstone identity is invalid")
        if identity in result:
            raise _error("tombstone graph contains a duplicate identity")
        result.add(identity)
    return frozenset(result)


def _normalize_before(
    value: Any, expected: set[RecordIdentity]
) -> dict[RecordIdentity, dict[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise _error("before_values do not cover the exact recovery plan graph")
    result: dict[RecordIdentity, dict[str, Any]] = {}
    for identity, values in value.items():
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or identity not in expected
            or not isinstance(values, dict)
        ):
            raise _error("before_values contain an invalid record")
        try:
            canonical_json(values)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise _error("before_values are not canonical JSON") from exc
        result[identity] = dict(values)
    return result


def _normalize_records(
    records: Any,
) -> tuple[tuple[RecordTuple, ...], dict[RecordIdentity, Any]]:
    if isinstance(records, (str, bytes, Mapping)):
        raise _error("records must be record tuples")
    try:
        raw = list(records)
    except TypeError as exc:
        raise _error("records must be record tuples") from exc
    normalized: list[RecordTuple] = []
    indexed: dict[RecordIdentity, Any] = {}
    for item in raw:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0].startswith("account.")
        ):
            raise _error("records contain an invalid record tuple")
        model_name, record = item
        record_id = _record_id(record)
        if record_id is None:
            raise _error("records contain an unidentified record")
        identity = (model_name, record_id)
        if identity in indexed:
            raise _error("records contain a duplicate identity")
        indexed[identity] = record
        normalized.append((model_name, record))
    return tuple(normalized), indexed


def _snapshot(
    adapter: RecoveryReadAdapter,
    model_name: str,
    record: Any,
    company: Any,
) -> tuple[str, dict[str, Any]]:
    try:
        raw = adapter.snapshot(model_name, record, company)
    except Exception as exc:
        raise _error("fresh record snapshot failed") from exc
    expected_fields = {
        "model",
        "record_id",
        "company_id",
        "state",
        "values",
        "values_digest",
    }
    if not isinstance(raw, dict) or set(raw) != expected_fields:
        raise _error("fresh record snapshot shape is invalid")
    record_id = _record_id(record)
    values = raw.get("values")
    if (
        raw["model"] != model_name
        or raw["record_id"] != record_id
        or raw["company_id"] != _company_id(company)
        or not isinstance(raw["state"], str)
        or not raw["state"]
        or not isinstance(values, dict)
        or not isinstance(raw["values_digest"], str)
        or not hmac.compare_digest(raw["values_digest"], _digest(values))
    ):
        raise _error("fresh record snapshot binding is invalid")
    return raw["state"], dict(values)


def _assert_allowed_delta(
    before: Mapping[str, Any],
    current: Mapping[str, Any],
    allowed_fields: frozenset[str],
    *,
    label: str,
) -> None:
    if set(before) != set(current) or any(
        before[field] != current[field]
        for field in before
        if field not in allowed_fields
    ):
        raise _error(f"{label} changed outside its recovery allowlist")


def _assert_adapter_call(label: str, callback: Any, *args: Any) -> None:
    try:
        result = callback(*args)
    except Exception as exc:
        raise _error(f"{label} failed") from exc
    if result is not None:
        raise _error(f"{label} returned an ambiguous result")


@dataclass(slots=True)
class _Graph:
    adapter: RecoveryReadAdapter
    company: Any
    method: str
    plan: dict[str, Any]
    action_keys: frozenset[RecordIdentity]
    guard_outcomes: dict[RecordIdentity, str]
    before: dict[RecordIdentity, dict[str, Any]]
    records: tuple[RecordTuple, ...]
    by_key: dict[RecordIdentity, Any]
    snapshots: dict[RecordIdentity, dict[str, Any]]
    states: dict[RecordIdentity, str]
    tombstones: frozenset[RecordIdentity]
    planned_survivors: frozenset[RecordIdentity]
    new_keys: frozenset[RecordIdentity]
    consumed_delta_guards: set[RecordIdentity]

    def record(self, model_name: str, record_id: int) -> Any:
        record = self.by_key.get((model_name, record_id))
        if record is None:
            raise _error(f"fresh graph is missing {model_name} {record_id}")
        return record

    def values(self, identity: RecordIdentity) -> dict[str, Any]:
        try:
            return self.snapshots[identity]
        except KeyError as exc:
            raise _error("fresh graph snapshot is missing") from exc

    def before_values(self, identity: RecordIdentity) -> dict[str, Any]:
        try:
            return self.before[identity]
        except KeyError as exc:
            raise _error("approved before values are missing") from exc

    def assert_guard_delta(
        self,
        identity: RecordIdentity,
        allowed_fields: frozenset[str],
        *,
        label: str,
    ) -> None:
        if (
            self.guard_outcomes.get(identity)
            != "survive_allowed_delta"
            or identity in self.consumed_delta_guards
        ):
            raise _error(f"{label} delta guard coverage is ambiguous")
        _assert_allowed_delta(
            self.before_values(identity),
            self.values(identity),
            allowed_fields,
            label=label,
        )
        self.consumed_delta_guards.add(identity)

    def move_graph_keys(self, move: Any) -> frozenset[RecordIdentity]:
        try:
            records = self.adapter.move_records(move, self.company)
        except Exception as exc:
            raise _error("fresh move graph read failed") from exc
        if not isinstance(records, list):
            raise _error("fresh move graph is not a record list")
        keys: list[RecordIdentity] = []
        move_id = _record_id(move)
        for item in records:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or item[0] not in {"account.move", "account.move.line"}
                or _record_id(item[1]) is None
            ):
                raise _error("fresh move graph contains an invalid record")
            keys.append((item[0], _record_id(item[1])))
        if (
            len(keys) != len(set(keys))
            or ("account.move", move_id) not in keys
            or not set(keys).issubset(self.by_key)
        ):
            raise _error("fresh move graph is incomplete or duplicated")
        expected_line_ids = set(
            _relation_ids(getattr(move, "line_ids", None))
        )
        actual_line_ids = {
            record_id
            for model_name, record_id in keys
            if model_name == "account.move.line"
        }
        if expected_line_ids != actual_line_ids:
            raise _error("fresh move journal-item graph differs")
        for line_id in actual_line_ids:
            line = self.record("account.move.line", line_id)
            if _record_id(getattr(line, "move_id", None)) != move_id:
                raise _error("fresh journal item parent link differs")
        return frozenset(keys)

    def assert_balanced(self, move: Any) -> None:
        _assert_adapter_call(
            "fresh move balance oracle",
            self.adapter.assert_move_balanced,
            move,
            self.company,
        )

    def assert_linewise_reversal(
        self, origin: Any, reversal: Any
    ) -> None:
        _assert_adapter_call(
            "fresh linewise reversal oracle",
            self.adapter.assert_linewise_reversal,
            origin,
            reversal,
            self.company,
        )

    def assert_only_new_move_graphs(self, roots: Sequence[Any]) -> None:
        expected: set[RecordIdentity] = set()
        for root in roots:
            expected.update(self.move_graph_keys(root))
        expected.difference_update(self.planned_survivors)
        if expected != set(self.new_keys):
            raise _error("fresh recovery result contains an incomplete or extra graph")


def _expected_tombstones(
    method: str,
    action_keys: set[RecordIdentity],
    guard_outcomes: Mapping[RecordIdentity, str],
) -> frozenset[RecordIdentity]:
    result = {
        identity
        for identity, outcome in guard_outcomes.items()
        if outcome == "absent"
    }
    if method == "undo_reconciliation_and_reverse_writeoff_v1":
        result.update(
            identity
            for identity in action_keys
            if identity[0]
            in {"account.partial.reconcile", "account.full.reconcile"}
        )
    return frozenset(result)


def _build_graph(
    adapter: RecoveryReadAdapter,
    method: str,
    *,
    plan: Any,
    company: Any,
    records: Any,
    before_values: Any,
    tombstone_keys: Any,
) -> _Graph:
    if not all(
        callable(getattr(adapter, name, None))
        for name in (
            "snapshot",
            "record_is_absent",
            "move_records",
            "assert_linewise_reversal",
            "assert_move_balanced",
        )
    ):
        raise _error("fresh recovery adapter surface is incomplete")
    if not isinstance(plan, dict):
        raise _error("recovery plan must be a plain object")
    try:
        validate_executable_recovery_plan(plan)
    except (TypeError, ValueError, WriteReceiptError) as exc:
        raise _error("fresh verification requires an executable V2 plan") from exc
    if plan["method"] != method:
        raise _error("recovery plan method differs")
    contract = RECOVERY_ACTION_CONTRACTS.get(method)
    if contract is None or plan["oracle_id"] != contract.oracle_id:
        raise _error("recovery plan oracle differs from its contract")
    company_id = _company_id(company)
    action_keys: set[RecordIdentity] = set()
    guard_outcomes: dict[RecordIdentity, str] = {}
    references: dict[RecordIdentity, dict[str, Any]] = {}
    for role, field in (("action", "action_targets"), ("guard", "guard_records")):
        for reference in plan[field]:
            identity = (reference["model"], reference["record_id"])
            if identity in references or reference["company_id"] != company_id:
                raise _error("recovery plan graph overlaps or crosses company")
            if (
                role == "action"
                and reference["model"] not in contract.action_models
            ) or (
                role == "guard"
                and reference["model"] not in contract.guard_models
            ):
                raise _error("recovery plan model is outside its contract")
            references[identity] = reference
            if role == "action":
                action_keys.add(identity)
            else:
                outcome = reference["expected_outcome"]
                if outcome not in contract.allowed_guard_outcomes:
                    raise _error("recovery plan guard outcome is invalid")
                guard_outcomes[identity] = outcome
    if not action_keys or not guard_outcomes:
        raise _error("recovery plan action/guard graph is incomplete")
    before = _normalize_before(before_values, set(references))
    for identity, reference in references.items():
        try:
            snapshot = create_record_snapshot(
                model=identity[0],
                record_id=identity[1],
                exists=True,
                record_state=reference["record_state"],
                values=before[identity],
            )
        except WriteReceiptError as exc:
            raise _error("approved before snapshot cannot be reconstructed") from exc
        if not hmac.compare_digest(
            reference["record_fingerprint"], _digest(snapshot)
        ):
            raise _error("approved before values differ from the recovery plan")
    tombstones = _normalize_tombstones(tombstone_keys)
    expected_tombstones = _expected_tombstones(
        method, action_keys, guard_outcomes
    )
    if tombstones != expected_tombstones:
        raise _error("fresh tombstone graph differs from the recovery plan")
    normalized_records, by_key = _normalize_records(records)
    planned_survivors = frozenset(references) - tombstones
    if (
        not planned_survivors.issubset(by_key)
        or set(by_key) & tombstones
        or any(model not in contract.result_models for model, _id in by_key)
    ):
        raise _error("fresh result omits a survivor or includes a tombstone")
    for model_name, record_id in sorted(tombstones):
        try:
            absent = adapter.record_is_absent(
                model_name, record_id, company
            )
        except Exception as exc:
            raise _error("fresh tombstone absence read failed") from exc
        if absent is not True:
            raise _error("expected tombstone record still exists")
    snapshots: dict[RecordIdentity, dict[str, Any]] = {}
    states: dict[RecordIdentity, str] = {}
    for identity, record in by_key.items():
        state, values = _snapshot(
            adapter, identity[0], record, company
        )
        states[identity] = state
        snapshots[identity] = values
    for identity, outcome in guard_outcomes.items():
        if outcome != "survive_exact":
            continue
        if identity not in snapshots:
            raise _error("survive_exact guard is absent")
        reference = references[identity]
        if (
            states[identity] != reference["record_state"]
            or snapshots[identity] != before[identity]
        ):
            raise _error("survive_exact guard changed after recovery")
    graph = _Graph(
        adapter=adapter,
        company=company,
        method=method,
        plan=plan,
        action_keys=frozenset(action_keys),
        guard_outcomes=guard_outcomes,
        before=before,
        records=normalized_records,
        by_key=by_key,
        snapshots=snapshots,
        states=states,
        tombstones=tombstones,
        planned_survivors=planned_survivors,
        new_keys=frozenset(set(by_key) - planned_survivors),
        consumed_delta_guards=set(),
    )
    _assert_global_graph_closure(graph)
    return graph


def _assert_global_graph_closure(graph: _Graph) -> None:
    for (model_name, _record_id_value), record in graph.by_key.items():
        if model_name == "account.move":
            graph.move_graph_keys(record)
        elif model_name == "account.move.line":
            parent_id = _record_id(getattr(record, "move_id", None))
            if ("account.move", parent_id) not in graph.by_key:
                raise _error("fresh journal item parent move is absent")
        elif model_name == "account.bank.statement":
            statement_id = _record_id(record)
            line_ids = set(_relation_ids(getattr(record, "line_ids", None)))
            received = {
                record_id
                for (other_model, record_id), line in graph.by_key.items()
                if other_model == "account.bank.statement.line"
                and _record_id(getattr(line, "statement_id", None))
                == statement_id
            }
            if line_ids != received:
                raise _error("fresh bank statement line graph differs")
        elif model_name == "account.bank.statement.line":
            if (
                ("account.bank.statement", _record_id(
                    getattr(record, "statement_id", None)
                ))
                not in graph.by_key
                or (
                    "account.move",
                    _record_id(getattr(record, "move_id", None)),
                )
                not in graph.by_key
            ):
                raise _error("fresh bank line parent graph is incomplete")
        elif model_name == "account.payment":
            if (
                "account.move",
                _record_id(getattr(record, "move_id", None)),
            ) not in graph.by_key:
                raise _error("fresh payment accounting move is absent")
        elif model_name == "account.partial.reconcile":
            for field in ("debit_move_id", "credit_move_id"):
                if (
                    "account.move.line",
                    _record_id(getattr(record, field, None)),
                ) not in graph.by_key:
                    raise _error("fresh partial reconcile endpoint is absent")
    for (model_name, _record_id_value), record in graph.by_key.items():
        if model_name != "account.move":
            continue
        for field in (
            "reversal_move_ids",
            "deferred_move_ids",
            "deferred_original_move_ids",
        ):
            for related_id in _relation_ids(getattr(record, field, None)):
                if ("account.move", related_id) not in graph.by_key:
                    raise _error(
                        f"fresh move {field} relation is outside the result graph"
                    )
    for (model_name, _record_id_value), record in graph.by_key.items():
        if model_name != "account.asset":
            continue
        for move_id in _relation_ids(
            getattr(record, "depreciation_move_ids", None)
        ):
            if ("account.move", move_id) not in graph.by_key:
                raise _error("fresh asset schedule is outside the result graph")


def _planned_records(
    graph: _Graph, model_name: str, *, actions_only: bool = False
) -> list[Any]:
    keys = (
        graph.action_keys
        if actions_only
        else frozenset(graph.planned_survivors)
    )
    return [
        graph.by_key[(model, record_id)]
        for model, record_id in sorted(keys)
        if model == model_name and (model, record_id) in graph.by_key
    ]


def _one_action(graph: _Graph, model_name: str) -> Any:
    records = _planned_records(graph, model_name, actions_only=True)
    if len(records) != 1 or len(graph.action_keys) != 1:
        raise _error(f"recovery oracle requires one {model_name} action")
    return records[0]


def _new_moves(graph: _Graph) -> list[Any]:
    return [
        graph.by_key[identity]
        for identity in sorted(graph.new_keys)
        if identity[0] == "account.move"
    ]


def _assert_new_reversal(
    graph: _Graph,
    origin: Any,
    recovery_date: str,
    reason: str,
    *,
    require_date: bool = True,
) -> Any:
    origin_id = _record_id(origin)
    candidates = [
        move
        for move in _new_moves(graph)
        if _record_id(getattr(move, "reversed_entry_id", None))
        == origin_id
    ]
    if len(candidates) != 1:
        raise _error("fresh recovery has no unique reversal move")
    reversal = candidates[0]
    expected_type = _REVERSED_MOVE_TYPE.get(
        str(getattr(origin, "move_type", ""))
    )
    if (
        _state(reversal) != "posted"
        or expected_type is None
        or str(getattr(reversal, "move_type", "")) != expected_type
        or (
            require_date
            and str(getattr(reversal, "date", "")) != recovery_date
        )
        or str(getattr(reversal, "odoo_cli_v3_reason", "")) != reason
        or _record_id(reversal)
        not in _relation_ids(getattr(origin, "reversal_move_ids", None))
    ):
        raise _error(
            "fresh reversal state, type, link, date, or reason differs"
        )
    graph.assert_linewise_reversal(origin, reversal)
    graph.assert_balanced(origin)
    graph.assert_balanced(reversal)
    return reversal


def _line_ids_for_move(graph: _Graph, move: Any) -> frozenset[int]:
    move_id = _record_id(move)
    line_ids = frozenset(_relation_ids(getattr(move, "line_ids", None)))
    received = {
        record_id
        for (model_name, record_id), line in graph.by_key.items()
        if model_name == "account.move.line"
        and _record_id(getattr(line, "move_id", None)) == move_id
    }
    if not line_ids or line_ids != received:
        raise _error("fresh move line graph differs")
    return line_ids


def _verify_draft_cancel(graph: _Graph) -> tuple[str, ...]:
    move = _one_action(graph, "account.move")
    move_key = ("account.move", _record_id(move))
    before = graph.before_values(move_key)
    current = graph.values(move_key)
    if (
        str(before.get("state")) != "draft"
        or _state(move) != "cancel"
        or str(getattr(move, "move_type", ""))
        not in _DRAFT_METHOD_TYPES[graph.method]
    ):
        raise _error("fresh draft cancellation state or type differs")
    _assert_allowed_delta(
        before,
        current,
        frozenset({"state", *_LOG_FIELDS}),
        label="draft cancellation action",
    )
    line_ids = _line_ids_for_move(graph, move)
    for line_id in sorted(line_ids):
        identity = ("account.move.line", line_id)
        if identity not in graph.before:
            raise _error("draft cancellation line was not approved")
        line = graph.record(*identity)
        before_line = graph.before_values(identity)
        if (
            _record_id(getattr(line, "move_id", None)) != _record_id(move)
            or str(before_line.get("parent_state")) != "draft"
            or str(getattr(line, "parent_state", "")) != "cancel"
        ):
            raise _error("fresh draft cancellation line state differs")
        graph.assert_guard_delta(
            identity,
            frozenset({"parent_state", "move_id", *_LOG_FIELDS}),
            label="draft cancellation journal item",
        )
    for identity, outcome in graph.guard_outcomes.items():
        if outcome != "survive_allowed_delta" or identity[0] == (
            "account.move.line"
        ):
            continue
        graph.assert_guard_delta(
            identity,
            _LOG_FIELDS,
            label="draft cancellation external guard",
        )
    if graph.tombstones or graph.new_keys:
        raise _error("draft cancellation created or deleted an extra record")
    return (
        f"{graph.method}_fresh_state_matches",
        "draft_cancel_line_graph_exact",
        "draft_cancel_delta_allowlist_matches",
    )


def _verify_generic_reversal(
    graph: _Graph, recovery_date: str, reason: str
) -> tuple[str, ...]:
    origin = _one_action(graph, "account.move")
    origin_key = ("account.move", _record_id(origin))
    before = graph.before_values(origin_key)
    current = graph.values(origin_key)
    move_type = str(getattr(origin, "move_type", ""))
    if (
        str(before.get("state")) != "posted"
        or _state(origin) != "posted"
        or move_type not in _GENERIC_METHOD_TYPES[graph.method]
    ):
        raise _error("fresh generic reversal origin differs")
    if (
        graph.method == "reverse_the_reversal_v1"
        and _relation_id(before.get("reversed_entry_id")) is None
    ):
        raise _error("fresh reverse-the-reversal origin was not a reversal")
    reversal = _assert_new_reversal(
        graph, origin, recovery_date, reason
    )
    allowed = {"reversal_move_ids", *_LOG_FIELDS}
    if move_type == "entry":
        allowed.update({"amount_residual", "payment_state"})
    _assert_allowed_delta(
        before,
        current,
        frozenset(allowed),
        label="generic reversal origin",
    )
    before_reversal_ids = set(
        _relation_ids(before.get("reversal_move_ids"))
    )
    current_reversal_ids = set(
        _relation_ids(getattr(origin, "reversal_move_ids", None))
    )
    if current_reversal_ids != before_reversal_ids | {_record_id(reversal)}:
        raise _error("fresh reversal backlink set differs")
    for identity, outcome in graph.guard_outcomes.items():
        if outcome == "survive_exact":
            continue
        if identity[0] == "account.move.line":
            line = graph.record(*identity)
            parent_id = _record_id(getattr(line, "move_id", None))
            parent_key = ("account.move", parent_id)
            if parent_id != _record_id(origin) and not (
                graph.method == "reverse_the_reversal_v1"
                and graph.guard_outcomes.get(parent_key)
                == "survive_exact"
            ):
                raise _error(
                    "generic reversal delta line has another parent"
                )
            allowed_delta = frozenset(
                {*_RECONCILIATION_LINE_FIELDS, *_LOG_FIELDS}
            )
        else:
            raise _error(
                "generic reversal has an unsupported allowed-delta guard"
            )
        graph.assert_guard_delta(
            identity,
            allowed_delta,
            label="generic reversal guard",
        )
    graph.assert_only_new_move_graphs((reversal,))
    return (
        f"{graph.method}_fresh_reversal_matches",
        "reversal_date_and_reason_match",
        "reversal_linewise_inverse_matches",
        "reversal_graph_complete",
    )


def _binding(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _error(f"{field} binding is unavailable")
    try:
        canonical_json(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise _error(f"{field} binding is invalid") from exc
    return dict(value)


def _verify_payment(graph: _Graph) -> tuple[str, ...]:
    payment = _one_action(graph, "account.payment")
    payment_key = ("account.payment", _record_id(payment))
    before = graph.before_values(payment_key)
    current = graph.values(payment_key)
    if (
        str(before.get("state")) not in {"in_process", "paid"}
        or _state(payment) != "canceled"
    ):
        raise _error("fresh payment cancellation state differs")
    _assert_allowed_delta(
        before,
        current,
        frozenset({"state", *_LOG_FIELDS}),
        label="payment action",
    )
    binding = _binding(
        getattr(payment, "odoo_cli_v3_payment_binding", None),
        "payment",
    )
    payment_move_id = _record_id(getattr(payment, "move_id", None))
    payment_move = graph.record("account.move", payment_move_id)
    if (
        binding.get("payment_id") != _record_id(payment)
        or binding.get("payment_move_id") != payment_move_id
        or _state(payment_move) != "cancel"
    ):
        raise _error("fresh payment accounting identity or state differs")
    payment_line_ids = frozenset(
        _relation_ids(getattr(payment_move, "line_ids", None))
    )
    bound_payment_line_ids = frozenset(
        _relation_ids(binding.get("payment_line_ids"))
    )
    if payment_line_ids != bound_payment_line_ids:
        raise _error("fresh payment journal-item binding differs")
    for line_id in sorted(payment_line_ids):
        line = graph.record("account.move.line", line_id)
        if (
            bool(getattr(line, "reconciled", False))
            or _relation_id(getattr(line, "full_reconcile_id", None))
            is not None
            or _relation_ids(getattr(line, "matched_debit_ids", None))
            or _relation_ids(getattr(line, "matched_credit_ids", None))
        ):
            raise _error("fresh payment journal item remains reconciled")
    raw_target_before = binding.get("target_before")
    if not isinstance(raw_target_before, list) or any(
        not isinstance(item, Mapping)
        or set(item) != {"move_id", "amount_residual"}
        or _record_id(item.get("move_id")) != item.get("move_id")
        for item in raw_target_before
    ):
        raise _error("payment target move binding is invalid")
    target_move_before = {
        item["move_id"]: dict(item) for item in raw_target_before
    }
    bound_target_move_ids = set(
        _relation_ids(binding.get("target_move_ids"))
    )
    if (
        len(target_move_before) != len(raw_target_before)
        or set(target_move_before) != bound_target_move_ids
    ):
        raise _error("payment target move binding is invalid")
    for move_id, approved in target_move_before.items():
        move = graph.record("account.move", move_id)
        if (
            _state(move) != "posted"
            or abs(
                _decimal(
                    getattr(move, "amount_residual", None),
                    "payment target residual",
                )
            )
            != _decimal(
                approved.get("amount_residual"),
                "bound payment target residual",
            )
        ):
            raise _error("fresh payment target residual was not restored")
    raw_target_lines = binding.get("target_line_before")
    target_line_fields = {
        "line_id",
        "move_id",
        "amount_residual",
        "amount_residual_currency",
        "reconciled",
        "full_reconcile_id",
        "matched_debit_ids",
        "matched_credit_ids",
    }
    if not isinstance(raw_target_lines, list) or any(
        not isinstance(item, Mapping)
        or set(item) != target_line_fields
        or _record_id(item.get("line_id")) != item.get("line_id")
        or _record_id(item.get("move_id")) != item.get("move_id")
        for item in raw_target_lines
    ):
        raise _error("payment target line binding is unavailable")
    target_lines = {
        item["line_id"]: dict(item) for item in raw_target_lines
    }
    if not target_lines or len(target_lines) != len(raw_target_lines):
        raise _error("payment target line binding is unavailable")
    for line_id, approved in target_lines.items():
        line = graph.record("account.move.line", line_id)
        if (
            approved.get("move_id") not in bound_target_move_ids
            or _record_id(getattr(line, "move_id", None))
            != approved.get("move_id")
            or _decimal(
                getattr(line, "amount_residual", None),
                "payment target line residual",
            )
            != _decimal(
                approved.get("amount_residual"),
                "bound target line residual",
            )
            or _decimal(
                getattr(line, "amount_residual_currency", None),
                "payment target line currency residual",
            )
            != _decimal(
                approved.get("amount_residual_currency"),
                "bound target line currency residual",
            )
            or bool(getattr(line, "reconciled", False))
            != bool(approved.get("reconciled"))
            or _relation_id(getattr(line, "full_reconcile_id", None))
            != _relation_id(approved.get("full_reconcile_id"))
            or set(_relation_ids(getattr(line, "matched_debit_ids", None)))
            != set(_relation_ids(approved.get("matched_debit_ids")))
            or set(_relation_ids(getattr(line, "matched_credit_ids", None)))
            != set(_relation_ids(approved.get("matched_credit_ids")))
        ):
            raise _error("fresh payment target line state was not restored")
    target_move_ids = set(target_move_before)
    target_line_ids = set(target_lines)
    for identity, outcome in graph.guard_outcomes.items():
        if outcome != "survive_allowed_delta":
            continue
        model_name, record_id = identity
        if identity == ("account.move", payment_move_id):
            allowed = frozenset(
                {
                    "state",
                    "payment_state",
                    "amount_residual",
                    "reversal_move_ids",
                    *_LOG_FIELDS,
                }
            )
        elif (
            model_name == "account.move.line"
            and record_id in payment_line_ids
        ):
            allowed = frozenset(
                {
                    "parent_state",
                    *_RECONCILIATION_LINE_FIELDS,
                    *_LOG_FIELDS,
                }
            )
        elif model_name == "account.move" and record_id in target_move_ids:
            allowed = frozenset(
                {"amount_residual", "payment_state", *_LOG_FIELDS}
            )
        elif (
            model_name == "account.move.line"
            and record_id in target_line_ids
        ):
            allowed = frozenset(
                {*_RECONCILIATION_LINE_FIELDS, *_LOG_FIELDS}
            )
        elif model_name == "account.move.line" and _record_id(
            getattr(graph.record(*identity), "move_id", None)
        ) in target_move_ids:
            allowed = _LOG_FIELDS
        else:
            raise _error("payment has an unsupported allowed-delta guard")
        graph.assert_guard_delta(
            identity, allowed, label="payment recovery guard"
        )
    if graph.new_keys:
        raise _error("payment cancellation created an unexpected record")
    if not graph.tombstones or any(
        model_name
        not in {"account.partial.reconcile", "account.full.reconcile"}
        for model_name, _record_id_value in graph.tombstones
    ):
        raise _error("payment reconciliation tombstone graph differs")
    graph.assert_balanced(payment_move)
    return (
        "payment_cancelled_fresh",
        "payment_move_cancelled_fresh",
        "payment_reconciliation_tombstones_absent",
        "payment_target_residuals_restored",
        "payment_binding_matches_fresh_readback",
    )


def _verify_bank(
    graph: _Graph, recovery_date: str, reason: str
) -> tuple[str, ...]:
    original = _one_action(graph, "account.bank.statement")
    original_key = ("account.bank.statement", _record_id(original))
    if graph.values(original_key) != graph.before_values(original_key):
        raise _error("original bank statement changed after compensation")
    new_statements = [
        graph.by_key[identity]
        for identity in sorted(graph.new_keys)
        if identity[0] == "account.bank.statement"
    ]
    if len(new_statements) != 1:
        raise _error("fresh bank compensation has no unique statement")
    compensating = new_statements[0]
    original_line_ids = frozenset(
        _relation_ids(getattr(original, "line_ids", None))
    )
    compensating_line_ids = frozenset(
        _relation_ids(getattr(compensating, "line_ids", None))
    )
    if (
        not original_line_ids
        or len(compensating_line_ids) != len(original_line_ids)
        or str(getattr(compensating, "date", "")) != recovery_date
        or str(getattr(compensating, "reference", "")) != reason
        or getattr(compensating, "is_complete", None) is not True
        or getattr(compensating, "is_valid", None) is not True
        or _decimal(
            getattr(compensating, "balance_start", None),
            "compensating opening balance",
        )
        != _decimal(
            getattr(original, "balance_end_real", None),
            "original closing balance",
        )
        or _decimal(
            getattr(compensating, "balance_end_real", None),
            "compensating closing balance",
        )
        != _decimal(
            getattr(original, "balance_start", None),
            "original opening balance",
        )
    ):
        raise _error("fresh compensating bank statement differs")
    original_lines = {
        line_id: graph.record("account.bank.statement.line", line_id)
        for line_id in original_line_ids
    }
    compensating_lines = {
        line_id: graph.record("account.bank.statement.line", line_id)
        for line_id in compensating_line_ids
    }
    paired: dict[int, Any] = {}
    for line in compensating_lines.values():
        prefix = "Recovery of bank line "
        reference = str(getattr(line, "ref", ""))
        if not reference.startswith(prefix):
            raise _error("compensating bank line has no source identity")
        try:
            source_id = int(reference[len(prefix):])
        except ValueError as exc:
            raise _error("compensating bank source identity is invalid") from exc
        if source_id not in original_lines or source_id in paired:
            raise _error("compensating bank line pairing is ambiguous")
        source = original_lines[source_id]
        if (
            _decimal(getattr(line, "amount", None), "compensating amount")
            != -_decimal(getattr(source, "amount", None), "source amount")
            or str(getattr(line, "date", "")) != recovery_date
            or str(getattr(line, "payment_ref", "")) != reason
            or _record_id(getattr(line, "journal_id", None))
            != _record_id(getattr(source, "journal_id", None))
            or _record_id(getattr(line, "partner_id", None))
            != _record_id(getattr(source, "partner_id", None))
            or _record_id(getattr(line, "foreign_currency_id", None))
            != _record_id(getattr(source, "foreign_currency_id", None))
        ):
            raise _error("fresh compensating bank line differs")
        foreign_currency_id = _record_id(
            getattr(source, "foreign_currency_id", None)
        )
        if (
            foreign_currency_id is not None
            and _decimal(
                getattr(line, "amount_currency", None),
                "compensating foreign amount",
            )
            != -_decimal(
                getattr(source, "amount_currency", None),
                "source foreign amount",
            )
        ):
            raise _error("fresh compensating bank foreign amount differs")
        move_id = _record_id(getattr(line, "move_id", None))
        move = graph.record("account.move", move_id)
        if _state(move) != "posted":
            raise _error("compensating bank line move is not posted")
        graph.assert_balanced(move)
        paired[source_id] = line
    if set(paired) != set(original_lines):
        raise _error("fresh compensating bank line set differs")
    expected_new: set[RecordIdentity] = {
        ("account.bank.statement", _record_id(compensating)),
        *(("account.bank.statement.line", line_id)
          for line_id in compensating_line_ids),
    }
    for line in compensating_lines.values():
        expected_new.update(
            graph.move_graph_keys(
                graph.record(
                    "account.move",
                    _record_id(getattr(line, "move_id", None)),
                )
            )
        )
    expected_new.difference_update(graph.planned_survivors)
    if expected_new != set(graph.new_keys):
        raise _error("fresh compensating bank graph is incomplete or extra")
    if graph.tombstones:
        raise _error("bank compensation unexpectedly deleted a record")
    return (
        "bank_original_graph_fresh_exact",
        "bank_compensating_statement_fresh",
        "bank_line_amounts_fresh_inverse",
        "bank_balances_fresh_inverse",
        "bank_compensation_graph_complete",
    )


def _partial_endpoints(
    graph: _Graph, identity: RecordIdentity
) -> tuple[int, int]:
    values = graph.before_values(identity)
    debit_id = _relation_id(values.get("debit_move_id"))
    credit_id = _relation_id(values.get("credit_move_id"))
    if debit_id is None or credit_id is None or debit_id == credit_id:
        raise _error("approved partial reconcile endpoints are invalid")
    return debit_id, credit_id


def _verify_reconciliation(
    graph: _Graph, recovery_date: str, reason: str
) -> tuple[str, ...]:
    partial_keys = {
        identity
        for identity in graph.tombstones
        if identity[0] == "account.partial.reconcile"
    }
    if not partial_keys:
        raise _error("reconciliation recovery has no partial tombstone")
    writeoff_moves = [
        graph.by_key[identity]
        for identity in sorted(graph.action_keys)
        if identity[0] == "account.move" and identity in graph.by_key
    ]
    if len(writeoff_moves) > 1:
        raise _error("fresh reconciliation write-off graph is ambiguous")
    writeoff_ids = {_record_id(move) for move in writeoff_moves}
    debit_amounts: dict[int, Decimal] = {}
    credit_amounts: dict[int, Decimal] = {}
    debit_currency_amounts: dict[int, Decimal] = {}
    credit_currency_amounts: dict[int, Decimal] = {}
    endpoints: set[int] = set()
    for identity in sorted(partial_keys):
        debit_id, credit_id = _partial_endpoints(graph, identity)
        values = graph.before_values(identity)
        amount = _decimal(values.get("amount"), "partial reconcile amount")
        debit_amounts[debit_id] = debit_amounts.get(
            debit_id, Decimal("0")
        ) + amount
        credit_amounts[credit_id] = credit_amounts.get(
            credit_id, Decimal("0")
        ) + amount
        debit_currency_amounts[debit_id] = debit_currency_amounts.get(
            debit_id, Decimal("0")
        ) + _decimal(
            values.get("debit_amount_currency", amount),
            "partial debit currency amount",
        )
        credit_currency_amounts[credit_id] = credit_currency_amounts.get(
            credit_id, Decimal("0")
        ) + _decimal(
            values.get("credit_amount_currency", amount),
            "partial credit currency amount",
        )
        endpoints.update((debit_id, credit_id))
    source_ids = {
        line_id
        for line_id in endpoints
        if _record_id(
            getattr(
                graph.record("account.move.line", line_id),
                "move_id",
                None,
            )
        )
        not in writeoff_ids
    }
    if not source_ids:
        raise _error("fresh reconciliation has no source endpoint")
    tombstone_partial_ids = {
        record_id
        for model_name, record_id in partial_keys
        if model_name == "account.partial.reconcile"
    }
    tombstone_full_ids = {
        record_id
        for model_name, record_id in graph.tombstones
        if model_name == "account.full.reconcile"
    }
    for line_id in sorted(endpoints):
        identity = ("account.move.line", line_id)
        line = graph.record(*identity)
        before = graph.before_values(identity)
        expected_residual = _decimal(
            before.get("amount_residual"),
            "approved source residual",
        )
        expected_residual += debit_amounts.get(
            line_id, Decimal("0")
        )
        expected_residual -= credit_amounts.get(
            line_id, Decimal("0")
        )
        expected_currency_residual = _decimal(
            before.get("amount_residual_currency"),
            "approved source currency residual",
        )
        expected_currency_residual += debit_currency_amounts.get(
            line_id, Decimal("0")
        )
        expected_currency_residual -= credit_currency_amounts.get(
            line_id, Decimal("0")
        )
        if (
            _decimal(
                getattr(line, "amount_residual", None),
                "fresh source residual",
            )
            != expected_residual
            or _decimal(
                getattr(line, "amount_residual_currency", None),
                "fresh source currency residual",
            )
            != expected_currency_residual
        ):
            raise _error(
                "fresh reconciliation source residual was not restored"
            )
        current_debit = set(
            _relation_ids(getattr(line, "matched_debit_ids", None))
        )
        current_credit = set(
            _relation_ids(getattr(line, "matched_credit_ids", None))
        )
        if (
            current_debit
            != set(_relation_ids(before.get("matched_debit_ids")))
            - tombstone_partial_ids
            or current_credit
            != set(_relation_ids(before.get("matched_credit_ids")))
            - tombstone_partial_ids
        ):
            raise _error(
                "fresh reconciliation source match links were not removed"
            )
        before_full = _relation_id(before.get("full_reconcile_id"))
        expected_full = (
            None if before_full in tombstone_full_ids else before_full
        )
        if (
            _relation_id(getattr(line, "full_reconcile_id", None))
            != expected_full
        ):
            raise _error(
                "fresh reconciliation source full link was not removed"
            )
        if (
            graph.guard_outcomes.get(identity)
            == "survive_allowed_delta"
        ):
            graph.assert_guard_delta(
                identity,
                frozenset(
                    {*_RECONCILIATION_LINE_FIELDS, *_LOG_FIELDS}
                ),
                label="reconciliation endpoint line",
            )
    reversal_roots: list[Any] = []
    if writeoff_moves:
        reversal = _assert_new_reversal(
            graph, writeoff_moves[0], recovery_date, reason
        )
        reversal_roots.append(reversal)
        writeoff_key = ("account.move", _record_id(writeoff_moves[0]))
        _assert_allowed_delta(
            graph.before_values(writeoff_key),
            graph.values(writeoff_key),
            frozenset(
                {
                    "reversal_move_ids",
                    "amount_residual",
                    "payment_state",
                    *_LOG_FIELDS,
                }
            ),
            label="reconciliation write-off move",
        )
    if reversal_roots:
        graph.assert_only_new_move_graphs(reversal_roots)
    elif graph.new_keys:
        raise _error("reconciliation recovery created an unexpected record")
    for identity, outcome in graph.guard_outcomes.items():
        if (
            outcome != "survive_allowed_delta"
            or identity in graph.consumed_delta_guards
        ):
            continue
        if identity[0] == "account.move":
            allowed = frozenset(
                {"amount_residual", "payment_state", *_LOG_FIELDS}
            )
        elif identity[0] == "account.move.line":
            allowed = _LOG_FIELDS
        else:
            raise _error(
                "reconciliation has an unsupported allowed-delta guard"
            )
        graph.assert_guard_delta(
            identity, allowed, label="reconciliation recovery guard"
        )
    return (
        "reconciliation_tombstones_fresh_absent",
        "reconciliation_source_links_fresh_removed",
        "reconciliation_source_residuals_fresh_restored",
        (
            "reconciliation_writeoff_fresh_reversed"
            if writeoff_moves
            else "reconciliation_writeoff_not_applicable"
        ),
        "reconciliation_result_graph_complete",
    )


def _verify_asset(
    graph: _Graph, reason: str
) -> tuple[str, ...]:
    asset = _one_action(graph, "account.asset")
    asset_key = ("account.asset", _record_id(asset))
    before = graph.before_values(asset_key)
    current = graph.values(asset_key)
    if (
        str(before.get("state")) not in {"draft", "open"}
        or _state(asset) not in {"cancel", "cancelled"}
    ):
        raise _error("fresh asset cancellation state differs")
    schedule_ids = set(_relation_ids(before.get("depreciation_move_ids")))
    tombstone_move_ids = {
        record_id
        for model_name, record_id in graph.tombstones
        if model_name == "account.move"
    }
    if not tombstone_move_ids.issubset(schedule_ids):
        raise _error("asset tombstone move is outside the approved schedule")
    posted_schedule_ids: set[int] = set()
    draft_schedule_ids: set[int] = set()
    for move_id in schedule_ids:
        identity = ("account.move", move_id)
        values = graph.before_values(identity)
        before_state = str(values.get("state"))
        if before_state == "draft":
            draft_schedule_ids.add(move_id)
        elif before_state == "posted":
            posted_schedule_ids.add(move_id)
        else:
            raise _error("approved asset schedule state is unsupported")
    if draft_schedule_ids != tombstone_move_ids:
        raise _error("fresh asset draft schedule tombstones differ")
    for move_id in draft_schedule_ids:
        line_ids = set(
            _relation_ids(
                graph.before_values(("account.move", move_id)).get(
                    "line_ids"
                )
            )
        )
        if {
            ("account.move.line", line_id) for line_id in line_ids
        } - graph.tombstones:
            raise _error("fresh asset draft schedule line still exists")
    current_schedule_ids = set(
        _relation_ids(getattr(asset, "depreciation_move_ids", None))
    )
    if current_schedule_ids != posted_schedule_ids:
        raise _error("fresh cancelled asset retained an unexpected schedule")
    _assert_allowed_delta(
        before,
        current,
        frozenset(
            {
                "state",
                "depreciation_move_ids",
                "value_residual",
                "book_value",
                *_LOG_FIELDS,
            }
        ),
        label="asset cancellation",
    )
    reversal_roots: list[Any] = []
    for move_id in sorted(posted_schedule_ids):
        move = graph.record("account.move", move_id)
        reversal = _assert_new_reversal(
            graph,
            move,
            recovery_date="1970-01-01",
            reason=reason,
            require_date=False,
        )
        reversal_roots.append(reversal)
        _assert_allowed_delta(
            graph.before_values(("account.move", move_id)),
            graph.values(("account.move", move_id)),
            frozenset(
                {
                    "reversal_move_ids",
                    "amount_residual",
                    "payment_state",
                    *_LOG_FIELDS,
                }
            ),
            label="asset posted schedule move",
        )
    schedule_line_ids = {
        line_id
        for move_id in schedule_ids
        for line_id in _relation_ids(
            graph.before_values(("account.move", move_id)).get("line_ids")
        )
    }
    for identity, outcome in graph.guard_outcomes.items():
        if outcome != "survive_allowed_delta":
            continue
        if (
            identity[0] == "account.move"
            and identity[1] in posted_schedule_ids
        ):
            allowed = frozenset(
                {
                    "reversal_move_ids",
                    "amount_residual",
                    "payment_state",
                    *_LOG_FIELDS,
                }
            )
        elif (
            identity[0] == "account.move.line"
            and identity[1] in schedule_line_ids
            and _record_id(
                getattr(graph.record(*identity), "move_id", None)
            )
            in posted_schedule_ids
        ):
            allowed = frozenset(
                {*_RECONCILIATION_LINE_FIELDS, *_LOG_FIELDS}
            )
        else:
            raise _error("asset has an unsupported allowed-delta guard")
        graph.assert_guard_delta(
            identity, allowed, label="asset recovery guard"
        )
    if reversal_roots:
        graph.assert_only_new_move_graphs(reversal_roots)
    elif graph.new_keys:
        raise _error("asset cancellation created an unexpected record")
    return (
        "asset_cancelled_fresh",
        "asset_draft_schedule_fresh_absent",
        (
            "asset_posted_schedule_fresh_reversed"
            if posted_schedule_ids
            else "asset_posted_schedule_not_applicable"
        ),
        "asset_source_graph_fresh_unchanged",
        "asset_result_graph_complete",
    )


def _verify_depreciation(
    graph: _Graph, recovery_date: str, reason: str
) -> tuple[str, ...]:
    move = _one_action(graph, "account.move")
    move_key = ("account.move", _record_id(move))
    assets = _planned_records(graph, "account.asset")
    if (
        len(assets) != 1
        or _state(move) != "posted"
        or str(getattr(move, "move_type", "")) != "entry"
        or str(getattr(move, "asset_move_type", ""))
        != "depreciation"
        or _record_id(getattr(move, "asset_id", None))
        != _record_id(assets[0])
    ):
        raise _error("fresh depreciation recovery graph differs")
    asset = assets[0]
    asset_key = ("account.asset", _record_id(asset))
    if (
        _state(asset) != "open"
        or _record_id(move)
        not in _relation_ids(
            getattr(asset, "depreciation_move_ids", None)
        )
    ):
        raise _error("fresh depreciation asset schedule was not restored")
    reversal = _assert_new_reversal(
        graph, move, recovery_date, reason
    )
    amount = _decimal(
        getattr(move, "depreciation_value", None),
        "depreciation value",
    )
    before_asset = graph.before_values(asset_key)
    if (
        _decimal(
            getattr(asset, "value_residual", None),
            "fresh asset residual",
        )
        != _decimal(
            before_asset.get("value_residual"),
            "approved asset residual",
        )
        + amount
        or _decimal(
            getattr(asset, "book_value", None),
            "fresh asset book value",
        )
        != _decimal(
            before_asset.get("book_value"),
            "approved asset book value",
        )
        + amount
    ):
        raise _error("fresh depreciation asset values were not restored")
    _assert_allowed_delta(
        before_asset,
        graph.values(asset_key),
        frozenset(
            {
                "value_residual",
                "book_value",
                "depreciation_move_ids",
                *_LOG_FIELDS,
            }
        ),
        label="depreciation asset",
    )
    _assert_allowed_delta(
        graph.before_values(move_key),
        graph.values(move_key),
        frozenset(
            {
                "reversal_move_ids",
                "amount_residual",
                "payment_state",
                *_LOG_FIELDS,
            }
        ),
        label="depreciation origin move",
    )
    target_line_ids = set(_relation_ids(getattr(move, "line_ids", None)))
    for identity, outcome in graph.guard_outcomes.items():
        if outcome != "survive_allowed_delta":
            continue
        if identity == asset_key:
            allowed = frozenset(
                {
                    "value_residual",
                    "book_value",
                    "depreciation_move_ids",
                    *_LOG_FIELDS,
                }
            )
        elif (
            identity[0] == "account.move.line"
            and identity[1] in target_line_ids
        ):
            allowed = frozenset(
                {*_RECONCILIATION_LINE_FIELDS, *_LOG_FIELDS}
            )
        else:
            raise _error(
                "depreciation has an unsupported allowed-delta guard"
            )
        graph.assert_guard_delta(
            identity, allowed, label="depreciation recovery guard"
        )
    graph.assert_only_new_move_graphs((reversal,))
    return (
        "depreciation_fresh_reversed",
        "depreciation_asset_schedule_fresh_restored",
        "depreciation_asset_values_fresh_restored",
        "depreciation_reversal_linewise_inverse",
        "depreciation_result_graph_complete",
    )


def _verify_accrual(
    graph: _Graph, recovery_date: str, reason: str
) -> tuple[str, ...]:
    actions = _planned_records(graph, "account.move", actions_only=True)
    if len(actions) != 2 or len(graph.action_keys) != 2:
        raise _error("fresh accrual action pair is incomplete")
    pairs = [
        (origin, scheduled)
        for origin in actions
        for scheduled in actions
        if origin is not scheduled
        and _relation_id(
            graph.before_values(
                ("account.move", _record_id(scheduled))
            ).get("reversed_entry_id")
        )
        == _record_id(origin)
    ]
    if len(pairs) != 1:
        raise _error("approved accrual origin/schedule pair is ambiguous")
    origin, scheduled = pairs[0]
    origin_key = ("account.move", _record_id(origin))
    scheduled_key = ("account.move", _record_id(scheduled))
    if (
        _state(origin) != "posted"
        or str(getattr(origin, "move_type", "")) != "entry"
        or str(graph.before_values(scheduled_key).get("state")) != "draft"
        or _state(scheduled) != "cancel"
        or str(getattr(scheduled, "auto_post", "")) != "at_date"
        or date.fromisoformat(str(getattr(scheduled, "date", "")))
        <= date.fromisoformat(recovery_date)
    ):
        raise _error("fresh accrual state or future schedule differs")
    reversal = _assert_new_reversal(
        graph, origin, recovery_date, reason
    )
    _assert_allowed_delta(
        graph.before_values(origin_key),
        graph.values(origin_key),
        frozenset(
            {
                "reversal_move_ids",
                "amount_residual",
                "payment_state",
                *_LOG_FIELDS,
            }
        ),
        label="accrual origin",
    )
    _assert_allowed_delta(
        graph.before_values(scheduled_key),
        graph.values(scheduled_key),
        frozenset({"state", *_LOG_FIELDS}),
        label="accrual scheduled reversal",
    )
    for identity, outcome in graph.guard_outcomes.items():
        if outcome == "survive_exact":
            continue
        if identity[0] != "account.move.line":
            graph.assert_guard_delta(
                identity,
                _LOG_FIELDS,
                label="accrual non-line guard",
            )
            continue
        line = graph.record(*identity)
        parent_id = _record_id(getattr(line, "move_id", None))
        allowed = set(_LOG_FIELDS)
        if parent_id == _record_id(scheduled):
            allowed.add("parent_state")
            if str(getattr(line, "parent_state", "")) != "cancel":
                raise _error("fresh accrual scheduled line is not canceled")
        elif parent_id == _record_id(origin):
            allowed.update(_RECONCILIATION_LINE_FIELDS)
        else:
            raise _error("accrual guard line has another parent")
        graph.assert_guard_delta(
            identity,
            frozenset(allowed),
            label="accrual guard line",
        )
    graph.assert_only_new_move_graphs((reversal,))
    return (
        "accrual_future_schedule_fresh_cancelled",
        "accrual_origin_fresh_reversed",
        "accrual_reversal_linewise_inverse",
        "accrual_result_graph_complete",
    )


def _verify_deferred(
    graph: _Graph, recovery_date: str, reason: str
) -> tuple[str, ...]:
    source = _one_action(graph, "account.move")
    source_key = ("account.move", _record_id(source))
    before_source = graph.before_values(source_key)
    if (
        _state(source) != "posted"
        or str(getattr(source, "move_type", ""))
        not in {"out_invoice", "in_invoice"}
    ):
        raise _error("fresh deferred source state or type differs")
    original_schedule_ids = set(
        _relation_ids(before_source.get("deferred_move_ids"))
    )
    if not original_schedule_ids or any(
        ("account.move", move_id) not in graph.planned_survivors
        for move_id in original_schedule_ids
    ):
        raise _error("approved deferred schedule graph is incomplete")
    reversal = _assert_new_reversal(
        graph, source, recovery_date, reason
    )
    inverse_ids = set(
        _relation_ids(getattr(reversal, "deferred_move_ids", None))
    )
    if not inverse_ids or any(
        ("account.move", move_id) not in graph.new_keys
        for move_id in inverse_ids
    ):
        raise _error("fresh compensating deferred schedule is incomplete")
    if len(inverse_ids) != len(original_schedule_ids):
        raise _error("fresh deferred schedule count differs")
    originals_by_date: dict[str, Any] = {}
    inverses_by_date: dict[str, Any] = {}
    for move_id in original_schedule_ids:
        move = graph.record("account.move", move_id)
        key = str(getattr(move, "date", ""))
        if key in originals_by_date:
            raise _error("approved deferred schedule dates are ambiguous")
        originals_by_date[key] = move
    for move_id in inverse_ids:
        move = graph.record("account.move", move_id)
        key = str(getattr(move, "date", ""))
        if key in inverses_by_date:
            raise _error("fresh inverse deferred dates are ambiguous")
        inverses_by_date[key] = move
    if set(originals_by_date) != set(inverses_by_date):
        raise _error("fresh inverse deferred schedule dates differ")
    for schedule_date in sorted(originals_by_date):
        original = originals_by_date[schedule_date]
        inverse = inverses_by_date[schedule_date]
        if (
            _state(inverse) != _state(original)
            or _record_id(reversal)
            not in _relation_ids(
                getattr(inverse, "deferred_original_move_ids", None)
            )
        ):
            raise _error("fresh inverse deferred schedule linkage differs")
        graph.assert_linewise_reversal(original, inverse)
        graph.assert_balanced(original)
        graph.assert_balanced(inverse)
    _assert_allowed_delta(
        before_source,
        graph.values(source_key),
        frozenset({"reversal_move_ids", *_LOG_FIELDS}),
        label="deferred source",
    )
    graph.assert_only_new_move_graphs(
        (reversal, *(graph.record("account.move", item) for item in inverse_ids))
    )
    return (
        "deferred_source_fresh_reversed",
        "deferred_original_schedule_fresh_exact",
        "deferred_inverse_schedule_fresh_linewise",
        "deferred_inverse_schedule_links_match",
        "deferred_result_graph_complete",
    )


def verify_recovery_action(
    adapter: RecoveryReadAdapter,
    method: str,
    *,
    plan: Any,
    company: Any,
    records: Any,
    before_values: Any,
    tombstone_keys: Any,
    recovery_date: str,
    reason: str,
) -> tuple[str, ...]:
    """Verify one recovery using only fresh reads and business oracles."""

    if method not in RECOVERY_VERIFICATION_METHODS:
        raise _error("recovery method has no fresh business oracle")
    recovery_date = _iso_date(recovery_date, "recovery_date")
    reason = _reason(reason)
    try:
        graph = _build_graph(
            adapter,
            method,
            plan=plan,
            company=company,
            records=records,
            before_values=before_values,
            tombstone_keys=tombstone_keys,
        )
        if method in _DRAFT_METHOD_TYPES:
            oracle_checks = _verify_draft_cancel(graph)
        elif method in _GENERIC_METHOD_TYPES:
            oracle_checks = _verify_generic_reversal(
                graph, recovery_date, reason
            )
        elif method == "cancel_and_unreconcile_payment_v1":
            oracle_checks = _verify_payment(graph)
        elif method == "post_compensating_bank_statement_v1":
            oracle_checks = _verify_bank(
                graph, recovery_date, reason
            )
        elif method == "undo_reconciliation_and_reverse_writeoff_v1":
            oracle_checks = _verify_reconciliation(
                graph, recovery_date, reason
            )
        elif method == "cancel_asset_and_reverse_schedule_v1":
            oracle_checks = _verify_asset(graph, reason)
        elif method == "reverse_depreciation_and_restore_schedule_v1":
            oracle_checks = _verify_depreciation(
                graph, recovery_date, reason
            )
        elif method == "cancel_scheduled_and_reverse_accrual_origin_v1":
            oracle_checks = _verify_accrual(
                graph, recovery_date, reason
            )
        elif method == "reverse_deferred_source_and_schedule_v1":
            oracle_checks = _verify_deferred(
                graph, recovery_date, reason
            )
        else:
            raise _error("recovery method has no fresh business oracle")
    except RecoveryVerificationError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise _error("fresh recovery evidence is malformed") from exc
    expected_delta_guards = {
        identity
        for identity, outcome in graph.guard_outcomes.items()
        if outcome == "survive_allowed_delta"
    }
    if graph.consumed_delta_guards != expected_delta_guards:
        raise _error(
            "fresh business oracle did not cover every allowed-delta guard"
        )
    checks = {
        "fresh_plan_before_fingerprints_match",
        "fresh_survive_exact_snapshots_match",
        "fresh_expected_tombstones_absent",
        "fresh_result_graph_unique_and_complete",
        *oracle_checks,
    }
    return tuple(sorted(checks))

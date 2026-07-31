"""Public-ORM recovery action adapter for non-draft recovery contracts.

This module executes only the accounting compensation step.  Approval,
fingerprint validation, transaction ownership, snapshotting, and durable
receipts remain the responsibility of the surrounding write handler.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Protocol, Sequence

from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)


class RecoveryActionError(ValueError):
    """The approved recovery graph cannot be executed unambiguously."""


class RecoveryORMAdapter(Protocol):
    """Narrow public ORM surface supplied by the bound write handler."""

    def create_model(
        self,
        model_name: str,
        company: Any,
        *,
        context: dict[str, Any] | None = None,
    ) -> Any: ...

    def record(
        self,
        model_name: str,
        record_id: int,
        company: Any,
        *,
        write: bool = False,
        shared: bool = False,
    ) -> Any: ...

    def require_created(
        self, record: Any, model_name: str, company: Any
    ) -> None: ...

    def move_records(
        self, move: Any, company: Any
    ) -> list[tuple[str, Any]]: ...


RecordTuple = tuple[str, Any]
RecordIdentity = tuple[str, int]


@dataclass(frozen=True, slots=True)
class RecoveryActionResult:
    """Existing records, deleted identities, and performed checks."""

    records: tuple[RecordTuple, ...]
    tombstones: frozenset[RecordIdentity]
    checks: tuple[str, ...]


_GENERIC_REVERSALS: Mapping[str, tuple[str, ...]] = {
    "reverse_posted_customer_invoice_v1": ("out_invoice",),
    "reverse_posted_vendor_bill_v1": ("in_invoice",),
    "reverse_posted_refund_v1": ("out_refund", "in_refund"),
    "reverse_posted_period_adjustment_v1": ("entry",),
    "reverse_the_reversal_v1": ("entry",),
}
FAIL_CLOSED_RECOVERY_METHODS = frozenset(
    {
        *_GENERIC_REVERSALS,
        "cancel_asset_and_reverse_schedule_v1",
        "reverse_depreciation_and_restore_schedule_v1",
        "cancel_scheduled_and_reverse_accrual_origin_v1",
        "reverse_deferred_source_and_schedule_v1",
    }
)
_DRAFT_CANCELLATIONS: Mapping[str, tuple[str, ...]] = {
    "cancel_draft_refund_v1": ("out_refund", "in_refund"),
    "cancel_draft_period_adjustment_v1": ("entry",),
}

RECOVERY_ACTION_METHODS = frozenset(
    {
        *_GENERIC_REVERSALS,
        *_DRAFT_CANCELLATIONS,
        "cancel_and_unreconcile_payment_v1",
        "post_compensating_bank_statement_v1",
        "undo_reconciliation_without_writeoff_v1",
        "cancel_asset_and_reverse_schedule_v1",
        "reverse_depreciation_and_restore_schedule_v1",
        "cancel_scheduled_and_reverse_accrual_origin_v1",
        "reverse_deferred_source_and_schedule_v1",
    }
)
# Compatibility name retained for the first integration draft.
NON_DRAFT_RECOVERY_METHODS = RECOVERY_ACTION_METHODS

_REVERSAL_MOVE_TYPES = {
    "out_invoice": "out_refund",
    "in_invoice": "in_refund",
    "out_refund": "out_invoice",
    "in_refund": "in_invoice",
    "entry": "entry",
}
_RELATION_MOVE_FIELDS = (
    "reversal_move_ids",
    "deferred_move_ids",
    "deferred_original_move_ids",
)


def _record_id(value: Any) -> int | None:
    if value is False or value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    identifier = getattr(value, "id", None)
    if isinstance(identifier, bool) or not isinstance(identifier, int):
        return None
    return identifier if identifier > 0 else None


def _relation_ids(value: Any) -> tuple[int, ...]:
    if value is False or value is None:
        return ()
    if isinstance(value, bool):
        raise RecoveryActionError("record relation is ambiguous")
    if isinstance(value, int):
        identifier = _record_id(value)
        if identifier is None:
            raise RecoveryActionError("record relation has an invalid identity")
        return (identifier,)
    ids_value = getattr(value, "ids", None)
    if ids_value is not None:
        raw = list(ids_value)
    elif isinstance(value, (str, bytes, Mapping)):
        raise RecoveryActionError("record relation is ambiguous")
    else:
        try:
            raw = list(value)
        except TypeError:
            identifier = _record_id(value)
            if identifier is None:
                raise RecoveryActionError("record relation is ambiguous")
            return (identifier,)
    result: list[int] = []
    for item in raw:
        identifier = _record_id(item)
        if identifier is None:
            raise RecoveryActionError("record relation has an invalid identity")
        result.append(identifier)
    if len(result) != len(set(result)):
        raise RecoveryActionError("record relation contains duplicate identities")
    return tuple(result)


def _record_exists(record: Any) -> bool:
    exists_method = getattr(record, "exists", None)
    if not callable(exists_method):
        return bool(record)
    existing = exists_method()
    try:
        return bool(existing) and len(existing) == 1
    except TypeError:
        return bool(existing)


def _validated_date(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 10:
        raise RecoveryActionError("recovery_date must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise RecoveryActionError("recovery_date must be an ISO date") from exc
    if parsed.isoformat() != value:
        raise RecoveryActionError("recovery_date must be an ISO date")
    return value


def _validated_reason(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 500
        or any(ord(character) < 32 for character in value)
    ):
        raise RecoveryActionError(
            "reason must be a non-empty canonical string of at most 500 characters"
        )
    return value


def _decimal(value: Any, field: str) -> Decimal:
    if isinstance(value, bool):
        raise RecoveryActionError(f"{field} is not a finite amount")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise RecoveryActionError(f"{field} is not a finite amount") from exc
    if not result.is_finite():
        raise RecoveryActionError(f"{field} is not a finite amount")
    return result


def _normalize_records(
    records: Sequence[RecordTuple], *, label: str
) -> tuple[RecordTuple, ...]:
    if isinstance(records, (str, bytes, Mapping)):
        raise RecoveryActionError(f"{label} must be record tuples")
    normalized: list[RecordTuple] = []
    identities: set[RecordIdentity] = set()
    for item in records:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0]
        ):
            raise RecoveryActionError(f"{label} contains an invalid record tuple")
        model_name, record = item
        record_id = _record_id(record)
        if record_id is None or not _record_exists(record):
            raise RecoveryActionError(
                f"{label} contains an absent or unidentified record"
            )
        identity = (model_name, record_id)
        if identity in identities:
            raise RecoveryActionError(
                f"{label} contains a duplicate record identity"
            )
        identities.add(identity)
        normalized.append((model_name, record))
    return tuple(normalized)


def _validated_guard_outcomes(
    guards: Sequence[RecordTuple],
    values: Mapping[RecordIdentity, str],
    *,
    allowed: frozenset[str],
) -> dict[RecordIdentity, str]:
    if not isinstance(values, Mapping):
        raise RecoveryActionError(
            "guard_outcomes must be an identity-to-outcome mapping"
        )
    expected = {
        (model_name, _record_id(record))
        for model_name, record in guards
    }
    if set(values) != expected:
        raise RecoveryActionError(
            "guard_outcomes do not cover the exact guard record graph"
        )
    result: dict[RecordIdentity, str] = {}
    for identity, outcome in values.items():
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or not isinstance(identity[0], str)
            or isinstance(identity[1], bool)
            or not isinstance(identity[1], int)
            or identity[1] <= 0
            or not isinstance(outcome, str)
            or outcome not in allowed
        ):
            raise RecoveryActionError(
                "guard_outcomes contain an invalid contract outcome"
            )
        result[identity] = outcome
    return result


def _only_record(records: Sequence[RecordTuple], model_name: str) -> Any:
    matches = [record for model, record in records if model == model_name]
    if len(matches) != 1:
        raise RecoveryActionError(
            f"expected exactly one {model_name} recovery action record"
        )
    return matches[0]


def _public_method(record: Any, method_name: str) -> Any:
    if method_name.startswith("_"):
        raise RecoveryActionError("private ORM methods are forbidden")
    method = getattr(record, method_name, None)
    if not callable(method):
        raise RecoveryActionError(
            f"record has no public {method_name} recovery method"
        )
    return method


def _fingerprint_values(record: Any, fields: Sequence[str]) -> tuple[Any, ...]:
    result: list[Any] = []
    for field in fields:
        value = getattr(record, field, None)
        if field.endswith("_ids") or isinstance(value, (list, tuple, set)):
            result.append((field, "ids", _relation_ids(value)))
            continue
        identifier = _record_id(value)
        if identifier is not None:
            result.append((field, "id", identifier))
            continue
        result.append((field, "value", str(value)))
    return tuple(result)


class RecoveryActionExecutor:
    """Execute one exact recovery action through a bound public ORM adapter."""

    def __init__(self, adapter: RecoveryORMAdapter) -> None:
        required = ("create_model", "record", "require_created", "move_records")
        if any(not callable(getattr(adapter, name, None)) for name in required):
            raise RecoveryActionError(
                "recovery ORM adapter does not expose the required public surface"
            )
        self.adapter = adapter

    def execute(
        self,
        method: str,
        *,
        company: Any,
        action_records: Sequence[RecordTuple],
        guard_records: Sequence[RecordTuple],
        guard_outcomes: Mapping[RecordIdentity, str],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        if method not in RECOVERY_ACTION_METHODS:
            raise RecoveryActionError(
                "recovery method is not executable by this action adapter"
            )
        if method in FAIL_CLOSED_RECOVERY_METHODS:
            raise RecoveryActionError(
                "recovery method is fail-closed pending an exact Odoo "
                "mutation and recovery evidence graph"
            )
        contract = RECOVERY_ACTION_CONTRACTS.get(method)
        if contract is None:
            raise RecoveryActionError("recovery action contract is unavailable")
        recovery_date = _validated_date(recovery_date)
        reason = _validated_reason(reason)
        actions = _normalize_records(action_records, label="action_records")
        guards = _normalize_records(guard_records, label="guard_records")
        action_keys = {
            (model, _record_id(record)) for model, record in actions
        }
        guard_keys = {(model, _record_id(record)) for model, record in guards}
        if not actions or action_keys & guard_keys:
            raise RecoveryActionError(
                "recovery action and guard records are empty or overlap"
            )
        if any(model not in contract.action_models for model, _record in actions):
            raise RecoveryActionError(
                "recovery action model is outside its contract"
            )
        if any(model not in contract.guard_models for model, _record in guards):
            raise RecoveryActionError(
                "recovery guard model is outside its contract"
            )
        outcomes = _validated_guard_outcomes(
            guards,
            guard_outcomes,
            allowed=contract.allowed_guard_outcomes,
        )
        if method in _DRAFT_CANCELLATIONS:
            result = self._execute_draft_cancel(
                method,
                company,
                actions,
                guards,
                recovery_date,
                reason,
            )
        elif method in _GENERIC_REVERSALS:
            result = self._execute_generic_reversal(
                method,
                company,
                actions,
                guards,
                recovery_date,
                reason,
            )
        elif method == "cancel_and_unreconcile_payment_v1":
            result = self._execute_payment(
                company,
                actions,
                guards,
                outcomes,
                recovery_date,
                reason,
            )
        elif method == "post_compensating_bank_statement_v1":
            result = self._execute_bank(
                company, actions, guards, recovery_date, reason
            )
        elif method == "undo_reconciliation_without_writeoff_v1":
            result = self._execute_reconciliation(
                company,
                actions,
                guards,
                outcomes,
                recovery_date,
                reason,
            )
        elif method == "cancel_asset_and_reverse_schedule_v1":
            result = self._execute_asset(
                company,
                actions,
                guards,
                outcomes,
                recovery_date,
                reason,
            )
        elif method == "reverse_depreciation_and_restore_schedule_v1":
            result = self._execute_depreciation(
                company, actions, guards, recovery_date, reason
            )
        elif method == "cancel_scheduled_and_reverse_accrual_origin_v1":
            result = self._execute_accrual(
                company, actions, guards, recovery_date, reason
            )
        else:
            result = self._execute_deferred(
                company, actions, guards, recovery_date, reason
            )

        if any(
            model not in contract.result_models
            for model, _record in result.records
        ):
            raise RecoveryActionError(
                "recovery result model is outside its contract"
            )
        if any(
            model not in contract.result_models
            for model, _record_id_value in result.tombstones
        ):
            raise RecoveryActionError(
                "recovery tombstone model is outside its contract"
            )
        return result

    @staticmethod
    def _assert_draft_line_has_no_external_effects(
        line: Any, *, move_id: int
    ) -> None:
        if (
            _record_id(getattr(line, "move_id", None)) != move_id
            or str(getattr(line, "parent_state", "")) != "draft"
            or bool(getattr(line, "reconciled", False))
            or _record_id(getattr(line, "full_reconcile_id", None)) is not None
            or _relation_ids(getattr(line, "matched_debit_ids", None))
            or _relation_ids(getattr(line, "matched_credit_ids", None))
            or _record_id(getattr(line, "payment_id", None)) is not None
            or _record_id(getattr(line, "statement_line_id", None)) is not None
            or _record_id(getattr(line, "statement_id", None)) is not None
            or _relation_ids(getattr(line, "asset_ids", None))
            or getattr(line, "deferred_start_date", None) not in {None, False}
            or getattr(line, "deferred_end_date", None) not in {None, False}
        ):
            raise RecoveryActionError(
                "draft recovery line graph has external accounting effects"
            )

    def _execute_draft_cancel(
        self,
        method: str,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        move = _only_record(actions, "account.move")
        move_id = _record_id(move)
        if (
            len(actions) != 1
            or str(getattr(move, "state", "")) != "draft"
            or str(getattr(move, "move_type", ""))
            not in _DRAFT_CANCELLATIONS[method]
            or move_id is None
        ):
            raise RecoveryActionError(
                "draft recovery action state or type differs"
            )
        singular_effects = (
            "origin_payment_id",
            "statement_line_id",
            "statement_id",
            "tax_cash_basis_rec_id",
            "tax_cash_basis_origin_move_id",
            "asset_id",
        )
        plural_effects = (
            "payment_ids",
            "matched_payment_ids",
            "reconciled_payment_ids",
            "statement_line_ids",
            "tax_cash_basis_created_move_ids",
            "exchange_diff_partial_ids",
            "asset_ids",
            "deferred_move_ids",
            "deferred_original_move_ids",
        )
        if any(
            _record_id(getattr(move, field, None)) is not None
            for field in singular_effects
        ) or any(
            _relation_ids(getattr(move, field, None))
            for field in plural_effects
        ):
            raise RecoveryActionError(
                "draft recovery action has external accounting effects"
            )
        line_ids = frozenset(_relation_ids(getattr(move, "line_ids", None)))
        guard_lines = {
            _record_id(record): record
            for model, record in guards
            if model == "account.move.line"
            and _record_id(getattr(record, "move_id", None)) == move_id
        }
        if not line_ids or set(guard_lines) != set(line_ids):
            raise RecoveryActionError(
                "draft recovery line guard graph is incomplete"
            )
        for line in guard_lines.values():
            self._assert_draft_line_has_no_external_effects(
                line, move_id=move_id
            )
        guarded_others = [
            (model, record)
            for model, record in guards
            if not (
                model == "account.move.line"
                and _record_id(getattr(record, "move_id", None)) == move_id
            )
        ]
        other_fingerprint = tuple(
            (
                model,
                _record_id(record),
                _fingerprint_values(
                    record,
                    (
                        "state",
                        "date",
                        "move_type",
                        "line_ids",
                        "amount_residual",
                        "payment_state",
                    ),
                ),
            )
            for model, record in guarded_others
        )
        controlled = _public_method(move, "with_context")(
            tracking_disable=True,
            skip_account_move_synchronization=True,
            skip_invoice_sync=True,
            skip_is_manually_modified=True,
        )
        result = _public_method(controlled, "write")({"state": "cancel"})
        if result is not True or str(getattr(move, "state", "")) != "cancel":
            raise RecoveryActionError(
                "draft recovery cancellation returned no exact state result"
            )
        if any(
            not _record_exists(line)
            or str(getattr(line, "parent_state", "")) != "cancel"
            for line in guard_lines.values()
        ):
            raise RecoveryActionError(
                "draft recovery line state did not follow cancellation"
            )
        if other_fingerprint != tuple(
            (
                model,
                _record_id(record),
                _fingerprint_values(
                    record,
                    (
                        "state",
                        "date",
                        "move_type",
                        "line_ids",
                        "amount_residual",
                        "payment_state",
                    ),
                ),
            )
            for model, record in guarded_others
        ):
            raise RecoveryActionError(
                "draft recovery changed an external guard record"
            )
        survivors = self._surviving_records((*actions, *guards))
        records = self._result_records(
            (*survivors, *self._move_graph((move,), company))
        )
        return RecoveryActionResult(
            records=records,
            tombstones=frozenset(),
            checks=(
                f"{method}_completed",
                "draft_state_cancelled_exactly",
                "complete_line_guard_graph",
                "external_accounting_effects_absent",
                "external_guard_graph_unchanged",
                "recovery_parameters_validated",
                "recovery_receipt_binding_required",
            ),
        )

    def _record_from_action(
        self, action: Any, company: Any, *, origin_id: int
    ) -> Any:
        if not isinstance(action, Mapping):
            raise RecoveryActionError(
                "reversal wizard returned no deterministic record receipt"
            )
        record_id = action.get("res_id")
        if (
            isinstance(record_id, bool)
            or not isinstance(record_id, int)
            or record_id <= 0
            or record_id == origin_id
        ):
            raise RecoveryActionError(
                "reversal wizard returned an ambiguous record receipt"
            )
        if action.get("res_model", "account.move") != "account.move":
            raise RecoveryActionError(
                "reversal wizard returned an ambiguous record receipt"
            )
        res_ids = action.get("res_ids")
        if res_ids is not None:
            if (
                not isinstance(res_ids, (list, tuple))
                or len(res_ids) != 1
                or res_ids[0] != record_id
            ):
                raise RecoveryActionError(
                    "reversal wizard returned an ambiguous record receipt"
                )
        reversal = self.adapter.record(
            "account.move", record_id, company, write=True
        )
        if _record_id(reversal) != record_id or not _record_exists(reversal):
            raise RecoveryActionError(
                "reversal wizard record receipt is not readable"
            )
        return reversal

    def _reverse_move(
        self,
        origin: Any,
        company: Any,
        recovery_date: str,
        reason: str,
    ) -> Any:
        origin_id = _record_id(origin)
        if origin_id is None or str(getattr(origin, "state", "")) != "posted":
            raise RecoveryActionError("reversal origin must be posted")
        move_type = str(getattr(origin, "move_type", ""))
        if move_type not in _REVERSAL_MOVE_TYPES:
            raise RecoveryActionError("reversal origin move type is unsupported")
        journal_id = _record_id(getattr(origin, "journal_id", None))
        if journal_id is None:
            raise RecoveryActionError("reversal origin has no journal")
        wizard_model = self.adapter.create_model(
            "account.move.reversal",
            company,
            context={
                "active_model": "account.move",
                "active_ids": [origin_id],
            },
        )
        wizard = wizard_model.create(
            {
                "date": recovery_date,
                "journal_id": journal_id,
                "reason": reason,
            }
        )
        if _record_id(wizard) is None:
            raise RecoveryActionError(
                "reversal wizard create returned no deterministic record"
            )
        action = _public_method(wizard, "reverse_moves")(is_modify=False)
        reversal = self._record_from_action(
            action, company, origin_id=origin_id
        )
        write_result = _public_method(reversal, "write")(
            {"odoo_cli_v3_reason": reason}
        )
        if (
            write_result is not True
            or str(getattr(reversal, "odoo_cli_v3_reason", "")) != reason
        ):
            raise RecoveryActionError(
                "reversal reason was not persisted exactly"
            )
        if str(getattr(reversal, "state", "")) == "draft":
            _public_method(reversal, "action_post")()
        if str(getattr(reversal, "state", "")) != "posted":
            raise RecoveryActionError("reversal did not reach posted state")
        if (
            _record_id(getattr(reversal, "reversed_entry_id", None))
            != origin_id
            or str(getattr(reversal, "move_type", ""))
            != _REVERSAL_MOVE_TYPES[move_type]
            or str(getattr(reversal, "date", "")) != recovery_date
        ):
            raise RecoveryActionError(
                "reversal read-back identity, type, or date differs"
            )
        return reversal

    def _move_graph(
        self, roots: Sequence[Any], company: Any
    ) -> tuple[RecordTuple, ...]:
        pending = list(roots)
        seen_moves: set[int] = set()
        records: list[RecordTuple] = []
        while pending:
            move = pending.pop(0)
            move_id = _record_id(move)
            if move_id is None or move_id in seen_moves:
                continue
            if len(seen_moves) >= 200:
                raise RecoveryActionError(
                    "recovery move closure exceeds the auditable limit"
                )
            seen_moves.add(move_id)
            graph = self.adapter.move_records(move, company)
            if not isinstance(graph, list) or not any(
                model == "account.move" and _record_id(record) == move_id
                for model, record in graph
            ):
                raise RecoveryActionError(
                    "adapter returned an incomplete move record graph"
                )
            records.extend(graph)
            for field in _RELATION_MOVE_FIELDS:
                for related_id in _relation_ids(getattr(move, field, None)):
                    if related_id not in seen_moves:
                        pending.append(
                            self.adapter.record(
                                "account.move",
                                related_id,
                                company,
                            )
                        )
        return self._result_records(records)

    @staticmethod
    def _result_records(
        records: Sequence[RecordTuple],
    ) -> tuple[RecordTuple, ...]:
        by_identity: dict[RecordIdentity, Any] = {}
        for model_name, record in records:
            record_id = _record_id(record)
            if record_id is None or not _record_exists(record):
                continue
            by_identity[(model_name, record_id)] = record
        return tuple(
            (model_name, by_identity[(model_name, record_id)])
            for model_name, record_id in sorted(by_identity)
        )

    def _surviving_records(
        self,
        records: Sequence[RecordTuple],
        *,
        must_be_absent: frozenset[RecordIdentity] = frozenset(),
    ) -> tuple[RecordTuple, ...]:
        result: list[RecordTuple] = []
        seen_absent: set[RecordIdentity] = set()
        for model_name, record in records:
            identity = (model_name, _record_id(record))
            if _record_exists(record):
                if identity in must_be_absent:
                    raise RecoveryActionError(
                        "recovery action did not delete an approved tombstone record"
                    )
                result.append((model_name, record))
            elif identity in must_be_absent:
                seen_absent.add(identity)
            else:
                raise RecoveryActionError(
                    "recovery action deleted a record outside its tombstone set"
                )
        if seen_absent != set(must_be_absent):
            raise RecoveryActionError(
                "recovery tombstone set differs from deleted records"
            )
        return self._result_records(result)

    def _execute_generic_reversal(
        self,
        method: str,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        origin = _only_record(actions, "account.move")
        if len(actions) != 1:
            raise RecoveryActionError(
                "generic reversal requires one account.move action"
            )
        if (
            str(getattr(origin, "state", "")) != "posted"
            or str(getattr(origin, "move_type", ""))
            not in _GENERIC_REVERSALS[method]
        ):
            raise RecoveryActionError(
                "generic reversal origin state or type differs"
            )
        if (
            method == "reverse_the_reversal_v1"
            and _record_id(getattr(origin, "reversed_entry_id", None)) is None
        ):
            raise RecoveryActionError(
                "reverse-the-reversal target is not a reversal"
            )
        raise RecoveryActionError(
            "recovery method is fail-closed until Odoo reversal chatter "
            "and automatic reconciliation effects are captured exactly"
        )
        reversal = self._reverse_move(
            origin, company, recovery_date, reason
        )
        survivors = self._surviving_records((*actions, *guards))
        records = self._result_records(
            (
                *survivors,
                *self._move_graph((origin, reversal), company),
            )
        )
        return RecoveryActionResult(
            records=records,
            tombstones=frozenset(),
            checks=(
                f"{method}_completed",
                "public_reversal_wizard",
                "reversal_origin_link_matches",
                "reversal_posted",
                "recovery_date_applied",
                "recovery_reason_persisted",
            ),
        )

    def _execute_payment(
        self,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        guard_outcomes: Mapping[RecordIdentity, str],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        payment = _only_record(actions, "account.payment")
        if len(actions) != 1 or str(getattr(payment, "state", "")) not in {
            "in_process",
            "paid",
        }:
            raise RecoveryActionError(
                "payment recovery requires one posted payment"
            )
        payment_move_id = _record_id(getattr(payment, "move_id", None))
        guard_by_key = {
            (model, _record_id(record)): record for model, record in guards
        }
        payment_move = guard_by_key.get(("account.move", payment_move_id))
        if (
            payment_move is None
            or str(getattr(payment_move, "state", "")) != "posted"
        ):
            raise RecoveryActionError(
                "payment accounting move is absent or not posted"
            )
        payment_line_ids = frozenset(
            _relation_ids(getattr(payment_move, "line_ids", None))
        )
        if not payment_line_ids:
            raise RecoveryActionError(
                "payment accounting move has no journal items"
            )
        payment_lines = []
        for line_id in sorted(payment_line_ids):
            line = guard_by_key.get(("account.move.line", line_id))
            if (
                line is None
                or _record_id(getattr(line, "move_id", None))
                != payment_move_id
            ):
                raise RecoveryActionError(
                    "payment journal item guard graph is incomplete"
                )
            payment_lines.append(line)
        tombstones = frozenset(
            identity
            for identity, outcome in guard_outcomes.items()
            if outcome == "absent"
        )
        if any(
            model
            not in {"account.partial.reconcile", "account.full.reconcile"}
            for model, _record_id_value in tombstones
        ) or not any(
            model == "account.partial.reconcile"
            for model, _record_id_value in tombstones
        ):
            raise RecoveryActionError(
                "payment recovery has no exact reconciliation records"
            )
        for line in payment_lines:
            _public_method(line, "remove_move_reconcile")()
        _public_method(payment, "action_cancel")()
        if str(getattr(payment, "state", "")) != "canceled":
            raise RecoveryActionError("payment did not reach canceled state")
        survivors = self._surviving_records(
            (*actions, *guards), must_be_absent=tombstones
        )
        records = self._result_records(
            (*survivors, *self._move_graph((payment_move,), company))
        )
        return RecoveryActionResult(
            records=records,
            tombstones=tombstones,
            checks=(
                "payment_move_lines_unreconciled_exactly",
                "payment_canceled",
                "approved_absent_reconciliation_records_tombstoned",
                "approved_surviving_reconciliation_records_retained",
                "recovery_parameters_validated",
            ),
        )

    @staticmethod
    def _bank_original_fingerprint(
        statement: Any, lines: Sequence[Any]
    ) -> tuple[Any, ...]:
        statement_fields = (
            "date",
            "reference",
            "balance_start",
            "balance_end",
            "balance_end_real",
            "is_complete",
            "is_valid",
            "line_ids",
        )
        line_fields = (
            "date",
            "amount",
            "amount_currency",
            "payment_ref",
            "ref",
            "partner_id",
            "foreign_currency_id",
            "journal_id",
            "statement_id",
            "move_id",
        )
        return (
            _fingerprint_values(statement, statement_fields),
            tuple(
                (
                    _record_id(line),
                    _fingerprint_values(line, line_fields),
                )
                for line in sorted(lines, key=lambda item: _record_id(item) or 0)
            ),
        )

    def _execute_bank(
        self,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        statement = _only_record(actions, "account.bank.statement")
        if (
            len(actions) != 1
            or getattr(statement, "is_complete", None) is not True
            or getattr(statement, "is_valid", None) is not True
        ):
            raise RecoveryActionError(
                "bank recovery requires one complete valid statement"
            )
        statement_id = _record_id(statement)
        line_ids = frozenset(_relation_ids(getattr(statement, "line_ids", None)))
        guard_lines = {
            _record_id(record): record
            for model, record in guards
            if model == "account.bank.statement.line"
        }
        if not line_ids or set(guard_lines) != set(line_ids):
            raise RecoveryActionError(
                "bank statement line guard graph is incomplete"
            )
        lines = [guard_lines[line_id] for line_id in sorted(line_ids)]
        journal_ids = {
            _record_id(getattr(line, "journal_id", None)) for line in lines
        }
        if (
            None in journal_ids
            or len(journal_ids) != 1
            or any(
                _record_id(getattr(line, "statement_id", None))
                != statement_id
                for line in lines
            )
        ):
            raise RecoveryActionError(
                "bank statement line ownership is ambiguous"
            )
        original_fingerprint = self._bank_original_fingerprint(
            statement, lines
        )
        line_model = self.adapter.create_model(
            "account.bank.statement.line", company
        )
        inverse_lines: list[Any] = []
        for line in lines:
            values: dict[str, Any] = {
                "company_id": _record_id(company),
                "journal_id": next(iter(journal_ids)),
                "date": recovery_date,
                "amount": float(-_decimal(line.amount, "bank line amount")),
                "payment_ref": reason,
                "ref": f"Recovery of bank line {_record_id(line)}",
            }
            partner_id = _record_id(getattr(line, "partner_id", None))
            if partner_id is not None:
                values["partner_id"] = partner_id
            foreign_currency_id = _record_id(
                getattr(line, "foreign_currency_id", None)
            )
            if foreign_currency_id is not None:
                values["foreign_currency_id"] = foreign_currency_id
                values["amount_currency"] = float(
                    -_decimal(
                        getattr(line, "amount_currency", None),
                        "bank line foreign amount",
                    )
                )
            inverse = line_model.create(values)
            self.adapter.require_created(
                inverse, "account.bank.statement.line", company
            )
            inverse_lines.append(inverse)
        new_statement = self.adapter.create_model(
            "account.bank.statement", company
        ).create(
            {
                "reference": reason,
                "date": recovery_date,
                "balance_start": float(
                    _decimal(
                        statement.balance_end_real,
                        "bank statement closing balance",
                    )
                ),
                "balance_end_real": float(
                    _decimal(
                        statement.balance_start,
                        "bank statement opening balance",
                    )
                ),
                "line_ids": [
                    (6, 0, [_record_id(line) for line in inverse_lines])
                ],
            }
        )
        self.adapter.require_created(
            new_statement, "account.bank.statement", company
        )
        new_statement_id = _record_id(new_statement)
        if (
            new_statement_id == statement_id
            or getattr(new_statement, "is_complete", None) is not True
            or getattr(new_statement, "is_valid", None) is not True
            or frozenset(
                _relation_ids(getattr(new_statement, "line_ids", None))
            )
            != frozenset(_record_id(line) for line in inverse_lines)
            or any(
                _record_id(getattr(line, "statement_id", None))
                != new_statement_id
                for line in inverse_lines
            )
        ):
            raise RecoveryActionError(
                "compensating bank statement read-back differs"
            )
        if (
            self._bank_original_fingerprint(statement, lines)
            != original_fingerprint
        ):
            raise RecoveryActionError(
                "original bank statement graph changed during compensation"
            )
        new_move_roots = [
            self.adapter.record(
                "account.move",
                _record_id(line.move_id),
                company,
            )
            for line in inverse_lines
            if _record_id(getattr(line, "move_id", None)) is not None
        ]
        survivors = self._surviving_records((*actions, *guards))
        records = self._result_records(
            (
                *survivors,
                ("account.bank.statement", new_statement),
                *(
                    ("account.bank.statement.line", line)
                    for line in inverse_lines
                ),
                *self._move_graph(new_move_roots, company),
            )
        )
        return RecoveryActionResult(
            records=records,
            tombstones=frozenset(),
            checks=(
                "independent_compensating_statement_created",
                "bank_line_amounts_reversed",
                "opening_and_closing_balances_reversed",
                "original_statement_and_bank_lines_unchanged_during_action",
                "recovery_date_applied",
                "recovery_reason_persisted",
            ),
        )

    def _execute_reconciliation(
        self,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        guard_outcomes: Mapping[RecordIdentity, str],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        if any(
            model
            not in {
                "account.partial.reconcile",
                "account.full.reconcile",
            }
            for model, _record in actions
        ) or not any(
            model == "account.partial.reconcile"
            for model, _record in actions
        ):
            raise RecoveryActionError(
                "reconciliation recovery action graph is invalid"
            )
        guard_by_key = {
            (model, _record_id(record)): record for model, record in guards
        }
        endpoint_ids: set[int] = set()
        for model, partial in actions:
            if model != "account.partial.reconcile":
                continue
            debit_id = _record_id(getattr(partial, "debit_move_id", None))
            credit_id = _record_id(getattr(partial, "credit_move_id", None))
            if debit_id is None or credit_id is None or debit_id == credit_id:
                raise RecoveryActionError(
                    "partial reconcile endpoints are ambiguous"
                )
            endpoint_ids.update((debit_id, credit_id))
        endpoint_lines: dict[int, Any] = {}
        for line_id in sorted(endpoint_ids):
            line = guard_by_key.get(("account.move.line", line_id))
            if line is None:
                raise RecoveryActionError(
                    "reconciliation endpoint guard graph is incomplete"
                )
            endpoint_lines[line_id] = line
        endpoint_move_ids = {
            _record_id(getattr(line, "move_id", None))
            for line in endpoint_lines.values()
        }
        if None in endpoint_move_ids:
            raise RecoveryActionError(
                "reconciliation source parent move graph is ambiguous"
            )
        source_lines = list(endpoint_lines.values())
        if not source_lines:
            raise RecoveryActionError(
                "reconciliation action identifies no source lines"
            )
        source_move_ids = {
            _record_id(getattr(line, "move_id", None))
            for line in source_lines
        }
        tombstones = frozenset(
            (model, _record_id(record))
            for model, record in actions
            if model
            in {"account.partial.reconcile", "account.full.reconcile"}
        ) | frozenset(
            identity
            for identity, outcome in guard_outcomes.items()
            if outcome == "absent"
        )
        if any(
            model
            not in {"account.partial.reconcile", "account.full.reconcile"}
            for model, _record_id_value in tombstones
        ):
            raise RecoveryActionError(
                "reconciliation tombstone outcome targets an invalid model"
            )
        for line in sorted(source_lines, key=lambda item: _record_id(item) or 0):
            _public_method(line, "remove_move_reconcile")()
        survivors = self._surviving_records(
            (*actions, *guards), must_be_absent=tombstones
        )
        source_moves = [
            guard_by_key[("account.move", move_id)]
            for move_id in sorted(source_move_ids)
            if ("account.move", move_id) in guard_by_key
        ]
        if len(source_moves) != len(source_move_ids):
            raise RecoveryActionError(
                "reconciliation source parent move graph is incomplete"
            )
        records = self._result_records(
            (
                *survivors,
                *self._move_graph(
                    source_moves,
                    company,
                ),
            )
        )
        return RecoveryActionResult(
            records=records,
            tombstones=tombstones,
            checks=(
                "source_lines_unreconciled_exactly",
                "approved_reconcile_tombstones_absent",
                "approved_surviving_reconcile_guards_retained",
                "writeoff_absent_by_contract",
                "recovery_parameters_validated",
                "recovery_receipt_binding_required",
            ),
        )

    def _execute_asset(
        self,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        guard_outcomes: Mapping[RecordIdentity, str],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        asset = _only_record(actions, "account.asset")
        if len(actions) != 1 or str(getattr(asset, "state", "")) not in {
            "draft",
            "open",
        }:
            raise RecoveryActionError(
                "asset recovery requires one draft or open asset"
            )
        guard_by_key = {
            (model, _record_id(record)): record for model, record in guards
        }
        schedule_ids = frozenset(
            _relation_ids(getattr(asset, "depreciation_move_ids", None))
        )
        schedule_moves = []
        absent: set[RecordIdentity] = set()
        posted_reversals_before: dict[int, frozenset[int]] = {}
        for move_id in sorted(schedule_ids):
            move = guard_by_key.get(("account.move", move_id))
            if move is None:
                raise RecoveryActionError(
                    "asset schedule guard graph is incomplete"
                )
            schedule_moves.append(move)
            if str(getattr(move, "state", "")) == "draft":
                absent.add(("account.move", move_id))
                for line_id in _relation_ids(getattr(move, "line_ids", None)):
                    if ("account.move.line", line_id) not in guard_by_key:
                        raise RecoveryActionError(
                            "asset draft schedule line graph is incomplete"
                        )
                    absent.add(("account.move.line", line_id))
            elif str(getattr(move, "state", "")) == "posted":
                posted_reversals_before[move_id] = frozenset(
                    _relation_ids(getattr(move, "reversal_move_ids", None))
                )
            else:
                raise RecoveryActionError(
                    "asset schedule contains an unsupported move state"
                )
        approved_absent = {
            identity
            for identity, outcome in guard_outcomes.items()
            if outcome == "absent"
        }
        if approved_absent != absent:
            raise RecoveryActionError(
                "asset tombstone outcomes do not match the draft schedule graph"
            )
        _public_method(asset, "set_to_cancelled")()
        if str(getattr(asset, "state", "")) not in {
            "cancel",
            "cancelled",
        }:
            raise RecoveryActionError("asset did not reach cancelled state")
        tombstones = frozenset(absent)
        survivors = self._surviving_records(
            (*actions, *guards), must_be_absent=tombstones
        )
        created_schedule_reversals: list[Any] = []
        for schedule_move in schedule_moves:
            schedule_id = _record_id(schedule_move)
            if schedule_id not in posted_reversals_before:
                continue
            after_ids = frozenset(
                _relation_ids(
                    getattr(schedule_move, "reversal_move_ids", None)
                )
            )
            created_ids = after_ids - posted_reversals_before[schedule_id]
            if not created_ids:
                raise RecoveryActionError(
                    "posted asset schedule move gained no reversal"
                )
            for reversal_id in sorted(created_ids):
                reversal = self.adapter.record(
                    "account.move", reversal_id, company
                )
                if (
                    str(getattr(reversal, "state", "")) != "posted"
                    or _record_id(
                        getattr(reversal, "reversed_entry_id", None)
                    )
                    != schedule_id
                ):
                    raise RecoveryActionError(
                        "asset schedule reversal read-back differs"
                    )
                write_result = _public_method(reversal, "write")(
                    {"odoo_cli_v3_reason": reason}
                )
                if (
                    write_result is not True
                    or str(
                        getattr(reversal, "odoo_cli_v3_reason", "")
                    )
                    != reason
                ):
                    raise RecoveryActionError(
                        "asset schedule reversal reason was not persisted"
                    )
                created_schedule_reversals.append(reversal)
        related_moves = [
            record
            for model, record in survivors
            if model == "account.move"
        ]
        for move_id in _relation_ids(
            getattr(asset, "depreciation_move_ids", None)
        ):
            if move_id not in {
                _record_id(move) for move in related_moves
            }:
                related_moves.append(
                    self.adapter.record("account.move", move_id, company)
                )
        records = self._result_records(
            (
                *survivors,
                *self._move_graph(
                    (*related_moves, *created_schedule_reversals),
                    company,
                ),
            )
        )
        return RecoveryActionResult(
            records=records,
            tombstones=tombstones,
            checks=(
                "asset_cancelled_publicly",
                (
                    "posted_schedule_reversed"
                    if posted_reversals_before
                    else "posted_schedule_not_applicable"
                ),
                "draft_schedule_removed_exactly",
                (
                    "asset_schedule_reversal_reason_persisted"
                    if posted_reversals_before
                    else "asset_schedule_reversal_reason_not_applicable"
                ),
                "recovery_parameters_validated",
            ),
        )

    def _execute_depreciation(
        self,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        move = _only_record(actions, "account.move")
        asset = _only_record(guards, "account.asset")
        if (
            len(actions) != 1
            or str(getattr(move, "state", "")) != "posted"
            or str(getattr(move, "move_type", "")) != "entry"
            or str(getattr(move, "asset_move_type", ""))
            != "depreciation"
            or _record_id(getattr(move, "asset_id", None))
            != _record_id(asset)
            or str(getattr(asset, "state", "")) != "open"
        ):
            raise RecoveryActionError(
                "depreciation recovery graph or state differs"
            )
        reversal = self._reverse_move(
            move, company, recovery_date, reason
        )
        survivors = self._surviving_records((*actions, *guards))
        schedule_moves = [
            self.adapter.record("account.move", move_id, company)
            for move_id in _relation_ids(
                getattr(asset, "depreciation_move_ids", None)
            )
        ]
        if _record_id(move) not in {
            _record_id(schedule) for schedule in schedule_moves
        }:
            raise RecoveryActionError(
                "depreciation move was not restored to the asset schedule"
            )
        records = self._result_records(
            (
                *survivors,
                *self._move_graph(
                    (*schedule_moves, reversal), company
                ),
            )
        )
        return RecoveryActionResult(
            records=records,
            tombstones=frozenset(),
            checks=(
                "depreciation_reversed_publicly",
                "asset_schedule_restored",
                "reversal_posted",
                "recovery_date_applied",
                "recovery_reason_persisted",
            ),
        )

    def _execute_accrual(
        self,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        moves = [record for model, record in actions if model == "account.move"]
        if len(actions) != 2 or len(moves) != 2:
            raise RecoveryActionError(
                "accrual recovery requires an exact origin/schedule pair"
            )
        candidates = [
            (origin, scheduled)
            for origin in moves
            for scheduled in moves
            if origin is not scheduled
            and _record_id(getattr(scheduled, "reversed_entry_id", None))
            == _record_id(origin)
        ]
        if len(candidates) != 1:
            raise RecoveryActionError(
                "accrual origin/schedule linkage is ambiguous"
            )
        origin, scheduled = candidates[0]
        try:
            scheduled_date = date.fromisoformat(
                str(getattr(scheduled, "date", ""))
            )
        except ValueError as exc:
            raise RecoveryActionError(
                "accrual schedule date is invalid"
            ) from exc
        if (
            str(getattr(origin, "state", "")) != "posted"
            or str(getattr(origin, "move_type", "")) != "entry"
            or str(getattr(scheduled, "state", "")) != "draft"
            or str(getattr(scheduled, "move_type", "")) != "entry"
            or str(getattr(scheduled, "auto_post", "")) != "at_date"
            or scheduled_date <= date.fromisoformat(recovery_date)
        ):
            raise RecoveryActionError(
                "accrual origin or future schedule state differs"
            )
        _public_method(scheduled, "button_cancel")()
        if str(getattr(scheduled, "state", "")) != "cancel":
            raise RecoveryActionError(
                "scheduled accrual reversal did not reach cancel state"
            )
        reversal = self._reverse_move(
            origin, company, recovery_date, reason
        )
        survivors = self._surviving_records((*actions, *guards))
        records = self._result_records(
            (
                *survivors,
                *self._move_graph(
                    (origin, scheduled, reversal), company
                ),
            )
        )
        return RecoveryActionResult(
            records=records,
            tombstones=frozenset(),
            checks=(
                "future_scheduled_accrual_cancelled",
                "accrual_origin_reversed_publicly",
                "reversal_posted",
                "recovery_date_applied",
                "recovery_reason_persisted",
            ),
        )

    def _execute_deferred(
        self,
        company: Any,
        actions: tuple[RecordTuple, ...],
        guards: tuple[RecordTuple, ...],
        recovery_date: str,
        reason: str,
    ) -> RecoveryActionResult:
        source = _only_record(actions, "account.move")
        if (
            len(actions) != 1
            or str(getattr(source, "state", "")) != "posted"
            or str(getattr(source, "move_type", ""))
            not in {"out_invoice", "in_invoice"}
        ):
            raise RecoveryActionError(
                "deferred recovery source state or type differs"
            )
        generated_ids = frozenset(
            _relation_ids(getattr(source, "deferred_move_ids", None))
        )
        guard_move_ids = {
            _record_id(record)
            for model, record in guards
            if model == "account.move"
        }
        if not generated_ids or not generated_ids.issubset(guard_move_ids):
            raise RecoveryActionError(
                "deferred schedule guard graph is incomplete"
            )
        raise RecoveryActionError(
            "recovery method is fail-closed until Odoo reversal chatter "
            "and automatic reconciliation effects are captured exactly"
        )
        reversal = self._reverse_move(
            source, company, recovery_date, reason
        )
        survivors = self._surviving_records((*actions, *guards))
        generated_moves = [
            self.adapter.record("account.move", move_id, company)
            for move_id in sorted(generated_ids)
        ]
        records = self._result_records(
            (
                *survivors,
                *self._move_graph(
                    (source, *generated_moves, reversal), company
                ),
            )
        )
        if not _relation_ids(
            getattr(reversal, "deferred_move_ids", None)
        ):
            raise RecoveryActionError(
                "deferred source reversal generated no compensating schedule"
            )
        return RecoveryActionResult(
            records=records,
            tombstones=frozenset(),
            checks=(
                "deferred_source_reversed_publicly",
                "compensating_deferred_schedule_created",
                "original_deferred_graph_preserved",
                "recovery_date_applied",
                "recovery_reason_persisted",
            ),
        )


def execute_recovery_action(
    adapter: RecoveryORMAdapter,
    method: str,
    *,
    company: Any,
    action_records: Sequence[RecordTuple],
    guard_records: Sequence[RecordTuple],
    guard_outcomes: Mapping[RecordIdentity, str],
    recovery_date: str,
    reason: str,
) -> RecoveryActionResult:
    """Convenience entry point for ``OdooWriteHandlers`` integration."""

    return RecoveryActionExecutor(adapter).execute(
        method,
        company=company,
        action_records=action_records,
        guard_records=guard_records,
        guard_outcomes=guard_outcomes,
        recovery_date=recovery_date,
        reason=reason,
    )

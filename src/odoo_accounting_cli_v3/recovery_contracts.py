"""Pure, non-production recovery action contracts.

These contracts describe action, guard, and result model closures only.  They
do not execute Odoo writes and do not constitute real Odoo recovery evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Iterable, Mapping


class RecoveryContractError(ValueError):
    """A recovery contract or exact contract lookup is invalid."""


_CAPABILITY_ID = re.compile(
    r"acct\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\.v[1-9][0-9]*"
)
_ACTION_NAME = re.compile(r"[a-z][a-z0-9_]*_v[1-9][0-9]*")
_RECOVERY_MODEL = re.compile(
    r"(?:account\.[a-z][a-z0-9_.]*|mail\.message)"
)
_EXECUTABLE_GUARD_OUTCOMES = frozenset(
    {"survive_exact", "survive_allowed_delta", "absent"}
)
_NON_PRODUCTION_ENVIRONMENTS = frozenset({"test", "sandbox"})
_TERMINAL_CAPABILITY_IDS = frozenset(
    {
        "acct.move.draft_cancel.v1",
        "acct.move.draft_cancel.v2",
        "acct.refund.draft_cancel.v1",
        "acct.recovery.execute.v1",
    }
)
_LOOKUP_ERROR = (
    "recovery action contract does not match the requested origin, method, "
    "and oracle"
)


def _matches(pattern: re.Pattern[str], value: object, *, maximum: int = 128) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and pattern.fullmatch(value) is not None
    )


def _validate_model_set(value: object, field: str) -> None:
    if (
        type(value) is not frozenset
        or not value
        or any(
            not _matches(_RECOVERY_MODEL, model)
            for model in value
        )
    ):
        raise RecoveryContractError(
            f"{field} must be a non-empty frozen set of supported recovery models"
        )


@dataclass(frozen=True, slots=True)
class RecoveryActionContract:
    """One exact, test/sandbox-only executable recovery action contract."""

    origin_capability_id: str
    method: str
    oracle_id: str
    action_models: frozenset[str]
    guard_models: frozenset[str]
    result_models: frozenset[str]
    allowed_guard_outcomes: frozenset[str]
    production_promotion_allowed: bool = False
    allowed_environments: frozenset[str] = _NON_PRODUCTION_ENVIRONMENTS

    def __post_init__(self) -> None:
        if not _matches(_CAPABILITY_ID, self.origin_capability_id):
            raise RecoveryContractError("origin_capability_id is invalid")
        if self.origin_capability_id in _TERMINAL_CAPABILITY_IDS:
            raise RecoveryContractError(
                "terminal capabilities cannot register another recovery action"
            )
        if not _matches(_ACTION_NAME, self.method):
            raise RecoveryContractError("recovery method is invalid")
        if not _matches(_ACTION_NAME, self.oracle_id):
            raise RecoveryContractError("recovery oracle_id is invalid")
        _validate_model_set(self.action_models, "action_models")
        _validate_model_set(self.guard_models, "guard_models")
        _validate_model_set(self.result_models, "result_models")
        if (
            type(self.allowed_guard_outcomes) is not frozenset
            or not self.allowed_guard_outcomes
            or not self.allowed_guard_outcomes.issubset(
                _EXECUTABLE_GUARD_OUTCOMES
            )
        ):
            raise RecoveryContractError(
                "allowed_guard_outcomes are invalid for executable recovery"
            )
        if type(self.production_promotion_allowed) is not bool:
            raise RecoveryContractError(
                "production_promotion_allowed must be boolean"
            )
        if self.production_promotion_allowed:
            raise RecoveryContractError(
                "production promotion is not allowed for recovery contracts"
            )
        if (
            type(self.allowed_environments) is not frozenset
            or self.allowed_environments != _NON_PRODUCTION_ENVIRONMENTS
        ):
            raise RecoveryContractError(
                "recovery contracts are restricted to test and sandbox"
            )


def _contract(
    origin_capability_id: str,
    method: str,
    oracle_id: str,
    *,
    action_models: tuple[str, ...],
    guard_models: tuple[str, ...],
    result_models: tuple[str, ...],
    allowed_guard_outcomes: tuple[str, ...],
) -> RecoveryActionContract:
    return RecoveryActionContract(
        origin_capability_id=origin_capability_id,
        method=method,
        oracle_id=oracle_id,
        action_models=frozenset(action_models),
        guard_models=frozenset(guard_models),
        result_models=frozenset(result_models),
        allowed_guard_outcomes=frozenset(allowed_guard_outcomes),
    )


_CONTRACTS = (
    _contract(
        "acct.invoice.customer_create.v1",
        "cancel_pristine_v3_draft_customer_invoice_v1",
        "cancel_pristine_v3_draft_customer_invoice_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move.line",),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_allowed_delta",),
    ),
    _contract(
        "acct.invoice.customer_create.v1",
        "reverse_posted_customer_invoice_v1",
        "reverse_posted_customer_invoice_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line"),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_exact",),
    ),
    _contract(
        "acct.bill.vendor_create.v1",
        "cancel_pristine_v3_draft_vendor_bill_v1",
        "cancel_pristine_v3_draft_vendor_bill_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move.line",),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_allowed_delta",),
    ),
    _contract(
        "acct.bill.vendor_create.v1",
        "reverse_posted_vendor_bill_v1",
        "reverse_posted_vendor_bill_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line"),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_exact",),
    ),
    _contract(
        "acct.refund.create.v1",
        "cancel_draft_refund_v1",
        "cancel_draft_refund_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line", "mail.message"),
        result_models=("account.move", "account.move.line", "mail.message"),
        allowed_guard_outcomes=("survive_exact", "survive_allowed_delta"),
    ),
    _contract(
        "acct.refund.create.v1",
        "reverse_posted_refund_v1",
        "reverse_posted_refund_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line", "mail.message"),
        result_models=("account.move", "account.move.line", "mail.message"),
        allowed_guard_outcomes=("survive_exact",),
    ),
    _contract(
        "acct.payment.register.v1",
        "cancel_and_unreconcile_payment_v1",
        "cancel_and_unreconcile_payment_exact_v1",
        action_models=("account.payment",),
        guard_models=(
            "account.move",
            "account.move.line",
            "account.partial.reconcile",
            "account.full.reconcile",
        ),
        result_models=(
            "account.payment",
            "account.move",
            "account.move.line",
            "account.partial.reconcile",
            "account.full.reconcile",
        ),
        allowed_guard_outcomes=(
            "survive_exact",
            "survive_allowed_delta",
            "absent",
        ),
    ),
    _contract(
        "acct.bank.statement_import.v1",
        "post_compensating_bank_statement_v1",
        "post_compensating_bank_statement_exact_v1",
        action_models=(
            "account.bank.statement",
            "account.bank.statement.line",
        ),
        guard_models=(
            "account.bank.statement",
            "account.bank.statement.line",
            "account.move",
            "account.move.line",
        ),
        result_models=(
            "account.bank.statement",
            "account.bank.statement.line",
            "account.move",
            "account.move.line",
        ),
        allowed_guard_outcomes=("survive_exact",),
    ),
    _contract(
        "acct.reconciliation.apply.v1",
        "undo_reconciliation_without_writeoff_v1",
        "undo_reconciliation_without_writeoff_exact_v1",
        action_models=(
            "account.partial.reconcile",
            "account.full.reconcile",
        ),
        guard_models=(
            "account.move",
            "account.move.line",
            "account.partial.reconcile",
            "account.full.reconcile",
        ),
        result_models=(
            "account.move",
            "account.move.line",
            "account.partial.reconcile",
            "account.full.reconcile",
        ),
        allowed_guard_outcomes=(
            "survive_exact",
            "survive_allowed_delta",
            "absent",
        ),
    ),
    _contract(
        "acct.asset.create.v1",
        "cancel_asset_and_reverse_schedule_v1",
        "cancel_asset_and_reverse_schedule_exact_v1",
        action_models=("account.asset",),
        guard_models=("account.asset", "account.move", "account.move.line"),
        result_models=("account.asset", "account.move", "account.move.line"),
        allowed_guard_outcomes=(
            "survive_exact",
            "survive_allowed_delta",
            "absent",
        ),
    ),
    _contract(
        "acct.depreciation.post.v1",
        "reverse_depreciation_and_restore_schedule_v1",
        "reverse_depreciation_and_restore_schedule_exact_v1",
        action_models=("account.asset", "account.move"),
        guard_models=("account.asset", "account.move", "account.move.line"),
        result_models=("account.asset", "account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_exact", "survive_allowed_delta"),
    ),
    _contract(
        "acct.accrual.create.v1",
        "cancel_scheduled_and_reverse_accrual_origin_v1",
        "cancel_scheduled_and_reverse_accrual_origin_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line"),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_allowed_delta",),
    ),
    _contract(
        "acct.deferred.create.v1",
        "reverse_deferred_source_and_schedule_v1",
        "reverse_deferred_source_and_schedule_exact_v1",
        action_models=("account.move", "account.move.line"),
        guard_models=("account.move", "account.move.line"),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_exact",),
    ),
    _contract(
        "acct.period.adjustment_create.v1",
        "cancel_draft_period_adjustment_v1",
        "cancel_draft_period_adjustment_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line"),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_allowed_delta",),
    ),
    _contract(
        "acct.period.adjustment_create.v1",
        "reverse_posted_period_adjustment_v1",
        "reverse_posted_period_adjustment_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line"),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_allowed_delta",),
    ),
    _contract(
        "acct.move.reverse.v1",
        "reverse_the_reversal_v1",
        "reverse_the_reversal_exact_v1",
        action_models=("account.move",),
        guard_models=("account.move", "account.move.line"),
        result_models=("account.move", "account.move.line"),
        allowed_guard_outcomes=("survive_exact", "survive_allowed_delta"),
    ),
)


def _build_contract_catalog(
    contracts: Iterable[RecoveryActionContract],
) -> Mapping[str, RecoveryActionContract]:
    by_method: dict[str, RecoveryActionContract] = {}
    oracle_ids: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    for contract in contracts:
        if not isinstance(contract, RecoveryActionContract):
            raise RecoveryContractError(
                "recovery catalog entries must be RecoveryActionContract values"
            )
        identity = (
            contract.origin_capability_id,
            contract.method,
            contract.oracle_id,
        )
        if contract.method in by_method:
            raise RecoveryContractError(
                "recovery contract methods must be unique"
            )
        if contract.oracle_id in oracle_ids:
            raise RecoveryContractError(
                "recovery contract oracle_ids must be unique"
            )
        if identity in identities:
            raise RecoveryContractError(
                "recovery contract identities must be unique"
            )
        by_method[contract.method] = contract
        oracle_ids.add(contract.oracle_id)
        identities.add(identity)
    if not by_method:
        raise RecoveryContractError("recovery contract catalog cannot be empty")
    if any(
        contract.origin_capability_id in _TERMINAL_CAPABILITY_IDS
        for contract in by_method.values()
    ):
        raise RecoveryContractError(
            "terminal capabilities cannot have executable recovery contracts"
        )
    return MappingProxyType(dict(sorted(by_method.items())))


RECOVERY_ACTION_CONTRACTS = _build_contract_catalog(_CONTRACTS)
EXECUTABLE_RECOVERY_METHODS = frozenset(RECOVERY_ACTION_CONTRACTS)


def select_recovery_action_contract(
    origin_capability_id: str,
    method: str,
    oracle_id: str,
) -> RecoveryActionContract:
    """Select one exact contract without fallback or capability inference."""

    if (
        not _matches(_CAPABILITY_ID, origin_capability_id)
        or not _matches(_ACTION_NAME, method)
        or not _matches(_ACTION_NAME, oracle_id)
    ):
        raise RecoveryContractError(_LOOKUP_ERROR)
    contract = RECOVERY_ACTION_CONTRACTS.get(method)
    if (
        contract is None
        or contract.origin_capability_id != origin_capability_id
        or contract.oracle_id != oracle_id
    ):
        raise RecoveryContractError(_LOOKUP_ERROR)
    return contract


def contracts_for_capability(
    capability_id: str,
) -> tuple[RecoveryActionContract, ...]:
    """Return the capability's contracts in stable method/oracle order."""

    if not _matches(_CAPABILITY_ID, capability_id):
        raise RecoveryContractError("capability_id is invalid")
    return tuple(
        sorted(
            (
                contract
                for contract in RECOVERY_ACTION_CONTRACTS.values()
                if contract.origin_capability_id == capability_id
            ),
            key=lambda contract: (contract.method, contract.oracle_id),
        )
    )

"""Handler integration tests for the fresh recovery verifier.

These tests exercise argument binding and fail-closed composition.  The
business oracles themselves are covered by ``test_odoo_recovery_verifier``;
no live Odoo database is used here.
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

import odoo_accounting_cli_v3.odoo.write_handlers as write_handlers_module
from odoo_accounting_cli_v3.odoo.recovery_verifier import (
    RecoveryVerificationError,
)
from odoo_accounting_cli_v3.odoo.write_handlers import (
    OdooWriteHandlerError,
    OdooWriteHandlers,
)
from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)
from odoo_accounting_cli_v3.recovery_guard import (
    RecoveryPlanExecutionGuardError,
)


METHODS = tuple(sorted(RECOVERY_ACTION_CONTRACTS))
RECOVERY_CAPABILITY_ID = "acct.recovery.execute.v1"


class Record:
    def __init__(self, record_id: int) -> None:
        self.id = record_id


class DirectVerifyHarness(OdooWriteHandlers):
    """Only bypass setup that precedes the verifier integration boundary."""

    def __init__(self, plan: dict[str, Any]) -> None:
        self.context = SimpleNamespace(trusted_recovery_plan=plan)
        self.module_graph_bindings: list[tuple[dict[str, Any], Any]] = []
        self.specialized_delta_calls: list[tuple[Any, ...]] = []

    def _assert_draft_recovery_module_graph_binding(
        self,
        plan: dict[str, Any],
        company: Any,
    ) -> None:
        self.module_graph_bindings.append((plan, company))

    def _assert_recovery_exact_delta(self, *args: Any, **kwargs: Any) -> None:
        self.specialized_delta_calls.append((*args, kwargs))


def _plan_and_graph(
    method: str,
) -> tuple[
    dict[str, Any],
    list[tuple[str, Record]],
    dict[tuple[str, int], dict[str, Any]],
]:
    contract = RECOVERY_ACTION_CONTRACTS[method]
    action_model = sorted(contract.action_models)[0]
    guard_model = sorted(contract.guard_models)[0]
    guard_outcome = (
        "absent"
        if "absent" in contract.allowed_guard_outcomes
        else sorted(contract.allowed_guard_outcomes)[0]
    )
    action = Record(101)
    guard = Record(202)
    plan = {
        "method": method,
        "oracle_id": contract.oracle_id,
        "action_targets": [
            {"model": action_model, "record_id": action.id}
        ],
        "guard_records": [
            {
                "model": guard_model,
                "record_id": guard.id,
                "expected_outcome": guard_outcome,
            }
        ],
    }
    records = [(action_model, action), (guard_model, guard)]
    before = {
        (action_model, action.id): {"company_id": 7},
        (guard_model, guard.id): {"company_id": 7},
    }
    return plan, records, before


@pytest.mark.parametrize("method", METHODS)
def test_all_sixteen_methods_forward_the_complete_fresh_verifier_binding(
    method: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, records, before = _plan_and_graph(method)
    company = Record(7)
    parameters = {
        "recovery_date": "2026-08-02",
        "reason": f"Approved recovery for {method}",
    }
    handler = DirectVerifyHarness(plan)
    expected_tombstones = handler._expected_recovery_tombstones(plan)
    captured: dict[str, Any] = {}

    def verifier(
        adapter: Any,
        selected_method: str,
        **kwargs: Any,
    ) -> tuple[str, ...]:
        captured.update(
            {
                "adapter": adapter,
                "method": selected_method,
                **kwargs,
            }
        )
        return ("fresh_business_oracle_passed",)

    monkeypatch.setattr(
        write_handlers_module,
        "verify_recovery_action",
        verifier,
    )

    result = handler.verify_recovery(
        parameters,
        company,
        records,
        before,
    )
    if expected_tombstones:
        checks, tombstones = result
    else:
        checks = result
        tombstones = frozenset()

    assert captured == {
        "adapter": handler,
        "method": method,
        "plan": plan,
        "company": company,
        "records": records,
        "before_values": before,
        "tombstone_keys": expected_tombstones,
        "recovery_date": parameters["recovery_date"],
        "reason": parameters["reason"],
    }
    assert "fresh_business_oracle_passed" in checks
    assert tombstones == expected_tombstones
    assert handler.module_graph_bindings == [(plan, company)]


@pytest.mark.parametrize("method", METHODS)
def test_all_sixteen_verifier_errors_fail_closed_at_the_handler_boundary(
    method: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, records, before = _plan_and_graph(method)
    handler = DirectVerifyHarness(plan)

    def reject(*_args: Any, **_kwargs: Any) -> tuple[str, ...]:
        raise RecoveryVerificationError("fresh oracle mismatch")

    monkeypatch.setattr(
        write_handlers_module,
        "verify_recovery_action",
        reject,
    )

    with pytest.raises(
        OdooWriteHandlerError,
        match="fresh recovery verification failed closed",
    ) as rejected:
        handler.verify_recovery(
            {
                "recovery_date": "2026-08-02",
                "reason": "Approved recovery",
            },
            Record(7),
            records,
            before,
        )

    assert isinstance(rejected.value.__cause__, RecoveryVerificationError)


class OuterVerifyHarness(OdooWriteHandlers):
    def __init__(
        self,
        verification_tombstones: set[tuple[str, int]],
    ) -> None:
        self._verification_tombstones = verification_tombstones
        self._company = Record(7)
        self.context = SimpleNamespace(
            module_graph=SimpleNamespace(evidence={"digest": "module-graph"})
        )

    def company(self, company_id: int) -> Record:
        assert company_id == self._company.id
        return self._company

    def trusted_before_values(
        self,
        execution: dict[str, Any],
        company: Any,
    ) -> dict[tuple[str, int], dict[str, Any]]:
        assert company is self._company
        assert execution["before"] == []
        return {}

    def verify_recovery(
        self,
        parameters: dict[str, Any],
        company: Any,
        records: list[tuple[str, Any]],
        before: dict[tuple[str, int], dict[str, Any]],
    ) -> tuple[list[str], set[tuple[str, int]]]:
        assert parameters["company_id"] == 7
        assert company is self._company
        assert records == []
        assert before == {}
        return ["fresh_business_oracle_passed"], self._verification_tombstones

    def snapshots(
        self,
        records: list[tuple[str, Any]],
        company: Any,
    ) -> list[dict[str, Any]]:
        assert records == []
        assert company is self._company
        return []

    def tombstone_snapshot(
        self,
        model_name: str,
        record_id: int,
        company: Any,
    ) -> dict[str, Any]:
        assert company is self._company
        return {
            "model": model_name,
            "record_id": record_id,
            "exists": False,
        }


def _outer_execution(
    parameters: dict[str, Any],
    committed_tombstones: set[tuple[str, int]],
) -> dict[str, Any]:
    return {
        "capability_id": RECOVERY_CAPABILITY_ID,
        "parameters_digest": hashlib.sha256(
            canonical_json(parameters)
        ).hexdigest(),
        "module_graph": {"digest": "module-graph"},
        "records": [],
        "before": [],
        "after": [
            {
                "model": model_name,
                "record_id": record_id,
                "exists": False,
            }
            for model_name, record_id in sorted(committed_tombstones)
        ],
    }


@pytest.mark.parametrize(
    ("committed_tombstones", "verification_tombstones"),
    (
        ({("account.partial.reconcile", 301)}, set()),
        (set(), {("account.partial.reconcile", 301)}),
        (
            {("account.partial.reconcile", 301)},
            {("account.full.reconcile", 401)},
        ),
    ),
)
def test_verification_tombstones_must_exactly_equal_execution_tombstones(
    committed_tombstones: set[tuple[str, int]],
    verification_tombstones: set[tuple[str, int]],
) -> None:
    parameters = {
        "company_id": 7,
        "origin_operation_id": "origin-op-1",
        "expected_recovery_plan_digest": "a" * 64,
        "recovery_date": "2026-08-02",
        "reason": "Approved recovery",
        "idempotency_key": "recovery-1",
    }
    handler = OuterVerifyHarness(verification_tombstones)

    with pytest.raises(
        OdooWriteHandlerError,
        match="verification tombstones differ from execution",
    ):
        handler.verify(
            RECOVERY_CAPABILITY_ID,
            parameters,
            _outer_execution(parameters, committed_tombstones),
        )


def test_matching_execution_and_verification_tombstones_are_preserved() -> None:
    parameters = {
        "company_id": 7,
        "origin_operation_id": "origin-op-1",
        "expected_recovery_plan_digest": "a" * 64,
        "recovery_date": "2026-08-02",
        "reason": "Approved recovery",
        "idempotency_key": "recovery-1",
    }
    tombstones = {("account.partial.reconcile", 301)}
    result = OuterVerifyHarness(tombstones).verify(
        RECOVERY_CAPABILITY_ID,
        parameters,
        _outer_execution(parameters, tombstones),
    )

    assert result["passed"] is True
    assert result["checks"] == ["fresh_business_oracle_passed"]
    assert result["after"] == [
        {
            "model": "account.partial.reconcile",
            "record_id": 301,
            "exists": False,
        }
    ]


class ProductionGuardHarness(OdooWriteHandlers):
    def __init__(self) -> None:
        self.context = SimpleNamespace(
            environment="production",
            module_graph=SimpleNamespace(digest="b" * 64),
        )


@pytest.mark.parametrize("method", METHODS)
def test_all_sixteen_recovery_contracts_remain_nonproduction_only(
    method: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = RECOVERY_ACTION_CONTRACTS[method]
    assert contract.allowed_environments == frozenset({"test", "sandbox"})
    assert contract.production_promotion_allowed is False
    handler = ProductionGuardHarness()
    observed: dict[str, Any] = {}

    def reject_production(
        _plan: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        observed.update(kwargs)
        raise RecoveryPlanExecutionGuardError(
            "recovery contracts are restricted to test and sandbox"
        )

    monkeypatch.setattr(
        write_handlers_module,
        "validate_recovery_plan_execution",
        reject_production,
    )

    with pytest.raises(
        OdooWriteHandlerError,
        match="not allowlisted for this environment",
    ):
        handler._validate_recovery_execution_guard(
            {
                "origin_operation_id": "origin-op-1",
                "expected_recovery_plan_digest": "c" * 64,
            },
            {"method": method},
            Record(7),
            {},
        )

    assert observed["environment"] == "production"
    assert observed["origin_capability_id"] == contract.origin_capability_id

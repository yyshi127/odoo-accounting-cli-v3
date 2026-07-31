from __future__ import annotations

import copy
import hashlib

import pytest

from odoo_accounting_cli_v3.auth import sign_write_action_context
from odoo_accounting_cli_v3.operations import (
    State,
    canonical_json,
    sign_execution_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.persistence import (
    IdempotencyConflict,
    OperationNotFound,
    SQLitePersistence,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_record_snapshot,
    create_recovery_plan_v2,
)
from odoo_accounting_cli_v3.write_service import (
    BackendEvidence,
    WriteServiceError,
)

from test_write_service import (
    APPROVAL_SECRET,
    EXECUTION_SECRET,
    NOW,
    TEST_MODULE_GRAPH,
    VERIFICATION_SECRET,
    Backend,
    _approval,
    _clone_service,
    _context,
    _invoice_parameters,
    _prepare_and_preview,
    _verification_evidence,
    service,
)


APPLY_CAPABILITY_ID = "acct.reconciliation.apply.v1"
UNDO_CAPABILITY_ID = "acct.reconciliation.undo.v1"
UNDO_METHOD = "undo_reconciliation_without_writeoff_v1"
UNDO_ORACLE = "undo_reconciliation_without_writeoff_exact_v1"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _record(snapshot: dict[str, object], company_id: int) -> dict[str, object]:
    return {
        "model": snapshot["model"],
        "record_id": snapshot["record_id"],
        "company_id": company_id,
        "record_state": snapshot["record_state"],
        "record_fingerprint": _digest(snapshot),
    }


def _apply_parameters(suffix: str) -> dict[str, object]:
    return {
        "company_id": 7,
        "line_ids": [301, 302],
        "account_id": 1200,
        "partner_id": 101,
        "reconciliation_date": "2026-07-15",
        "currency_id": 12,
        "mode": "partial",
        "amount": "50.00",
        "tolerance_amount": "0",
        "writeoff_account_id": None,
        "writeoff_journal_id": None,
        "writeoff_label": None,
        "idempotency_key": f"reconcile-{suffix}",
    }


def _reconciliation_execution_evidence(operation) -> dict[str, object]:
    debit_before = create_record_snapshot(
        model="account.move.line",
        record_id=301,
        exists=True,
        record_state="open",
        values={
            "amount_residual": "100.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    credit_before = create_record_snapshot(
        model="account.move.line",
        record_id=302,
        exists=True,
        record_state="open",
        values={
            "amount_residual": "-100.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    partial_before = create_record_snapshot(
        model="account.partial.reconcile",
        record_id=901,
        exists=False,
        record_state="absent",
        values={},
    )
    debit_after = create_record_snapshot(
        model="account.move.line",
        record_id=301,
        exists=True,
        record_state="partially_reconciled",
        values={
            "amount_residual": "50.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    credit_after = create_record_snapshot(
        model="account.move.line",
        record_id=302,
        exists=True,
        record_state="partially_reconciled",
        values={
            "amount_residual": "-50.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    partial_after = create_record_snapshot(
        model="account.partial.reconcile",
        record_id=901,
        exists=True,
        record_state="active",
        values={
            "amount": "50.00",
            "company_id": operation.company_id,
            "credit_move_id": 302,
            "debit_move_id": 301,
        },
    )
    action = _record(partial_after, operation.company_id)
    guards = [
        {
            **_record(snapshot, operation.company_id),
            "expected_outcome": "survive_allowed_delta",
        }
        for snapshot in (debit_after, credit_after)
    ]
    recovery_parameters = {
        "company_id": operation.company_id,
        "origin_operation_id": operation.operation_id,
        "module_graph_digest": TEST_MODULE_GRAPH.digest,
        "method": UNDO_METHOD,
        "action_targets": [
            {"model": "account.partial.reconcile", "record_id": 901}
        ],
        "guard_records": [
            {"model": "account.move.line", "record_id": 301},
            {"model": "account.move.line", "record_id": 302},
        ],
        "oracle_id": UNDO_ORACLE,
    }
    plan = create_recovery_plan_v2(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=UNDO_METHOD,
        requires_approval=True,
        action_targets=[action],
        guard_records=guards,
        oracle_id=UNDO_ORACLE,
        parameters=recovery_parameters,
    )
    after = [partial_after, debit_after, credit_after]
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": [
            action,
            *[
                {key: guard[key] for key in action}
                for guard in guards
            ],
        ],
        "difference": create_difference(
            before=[partial_before, debit_before, credit_before],
            after=after,
            changed_fields=[
                "amount",
                "amount_residual",
                "company_id",
                "credit_move_id",
                "debit_move_id",
                "reconciled",
            ],
        ),
        "recovery_plan": plan,
        "recovery_parameters": recovery_parameters,
        "module_graph": TEST_MODULE_GRAPH.evidence,
        "failure_checks": [],
    }


class ReconciliationBackend(Backend):
    def execute(
        self,
        _context,
        _capability,
        operation,
        _approval,
        _registry_digest,
        _release_digest,
    ):
        self.calls.append("execute")
        evidence = _reconciliation_execution_evidence(operation)
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-write-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)


def _undo_execution_evidence(operation) -> dict[str, object]:
    partial_before = create_record_snapshot(
        model="account.partial.reconcile",
        record_id=901,
        exists=True,
        record_state="active",
        values={
            "amount": "50.00",
            "company_id": operation.company_id,
            "credit_move_id": 302,
            "debit_move_id": 301,
        },
    )
    debit_before = create_record_snapshot(
        model="account.move.line",
        record_id=301,
        exists=True,
        record_state="partially_reconciled",
        values={
            "amount_residual": "50.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    credit_before = create_record_snapshot(
        model="account.move.line",
        record_id=302,
        exists=True,
        record_state="partially_reconciled",
        values={
            "amount_residual": "-50.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    partial_after = create_record_snapshot(
        model="account.partial.reconcile",
        record_id=901,
        exists=False,
        record_state="absent",
        values={},
    )
    debit_after = create_record_snapshot(
        model="account.move.line",
        record_id=301,
        exists=True,
        record_state="open",
        values={
            "amount_residual": "100.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    credit_after = create_record_snapshot(
        model="account.move.line",
        record_id=302,
        exists=True,
        record_state="open",
        values={
            "amount_residual": "-100.00",
            "company_id": operation.company_id,
            "reconciled": False,
        },
    )
    recovery_parameters = {"operation_id": operation.operation_id}
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": [
            _record(debit_after, operation.company_id),
            _record(credit_after, operation.company_id),
        ],
        "difference": create_difference(
            before=[partial_before, debit_before, credit_before],
            after=[partial_after, debit_after, credit_after],
            changed_fields=[
                "amount_residual",
                "company_id",
                "credit_move_id",
                "debit_move_id",
                "reconciled",
            ],
        ),
        "recovery_plan": create_recovery_plan_v2(
            origin_operation_id=operation.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="manual_escalation",
            method="inspect_failed_receipt_bound_reconciliation_undo",
            requires_approval=True,
            action_targets=[],
            guard_records=[],
            oracle_id="manual_escalation",
            parameters=recovery_parameters,
        ),
        "recovery_parameters": recovery_parameters,
        "module_graph": TEST_MODULE_GRAPH.evidence,
        "failure_checks": [],
    }


class UndoCompletingBackend(ReconciliationBackend):
    def execute(
        self,
        context,
        capability,
        operation,
        approval,
        registry_digest,
        release_digest,
    ):
        if operation.capability_id != UNDO_CAPABILITY_ID:
            return super().execute(
                context,
                capability,
                operation,
                approval,
                registry_digest,
                release_digest,
            )
        self.calls.append("execute")
        evidence = _undo_execution_evidence(operation)
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-write-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=_digest(evidence),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)

    def verify(
        self,
        context,
        capability,
        operation,
        execution_evidence,
        registry_digest,
        release_digest,
    ):
        if operation.capability_id != UNDO_CAPABILITY_ID:
            return super().verify(
                context,
                capability,
                operation,
                execution_evidence,
                registry_digest,
                release_digest,
            )
        self.calls.append("verify")
        evidence = _verification_evidence(operation, execution_evidence)
        fresh_snapshots = [
            snapshot
            for snapshot in evidence["readback"]["fresh_snapshots"]
            if snapshot["exists"] is True
        ]
        evidence["readback"]["fresh_snapshots"] = fresh_snapshots
        evidence["readback"]["fresh_snapshots_digest"] = _digest(
            fresh_snapshots
        )
        evidence["method"] = capability.data["verification"]["method"]
        evidence["checks"] = [
            "receipt_bound_partial_reconcile_is_absent",
            "source_lines_are_open",
            "origin_operation_remains_completed",
        ]
        result = sign_verification_result(
            operation=operation,
            issuer="odoo-write-verifier",
            key_id="verification-v1",
            succeeded=True,
            evidence_digest=_digest(evidence),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)


def _prepare_context(
    *,
    operation_id: str,
    request_id: str,
    parameters: dict[str, object],
    token_id: str,
    company_id: int = 7,
):
    request = {
        "operation_id": operation_id,
        "request_id": request_id,
        "capability_id": UNDO_CAPABILITY_ID,
        "parameters": parameters,
    }
    return sign_write_action_context(
        auth_token_id=token_id,
        principal=f"pi:sandbox-user-42",
        odoo_instance_id="odoo19@sandbox",
        database_name="codex_odoo_accounting_cli_v3_sandbox",
        database_uuid="11111111-1111-4111-8111-111111111111",
        user_id=42,
        company_id=company_id,
        allowed_company_ids=frozenset({company_id}),
        environment="sandbox",
        action="operation.prepare",
        request=request,
        issued_at=NOW,
        expires_at=NOW.replace(minute=NOW.minute + 4),
        key_id="write-auth-v2",
        secret=APPROVAL_SECRET,
    )


def _complete_reconciliation_origin(
    gateway,
    *,
    suffix: str,
) -> tuple[object, dict[str, object], object]:
    parameters = _apply_parameters(suffix)
    prepared = gateway.prepare(
        _context(
            parameters=parameters,
            token_id=f"token-apply-{suffix}-prepare",
            capability_id=APPLY_CAPABILITY_ID,
        ),
        operation_id=f"op-apply-{suffix}",
        request_id=f"request-apply-{suffix}",
        capability_id=APPLY_CAPABILITY_ID,
        parameters=parameters,
    )
    gateway.preview(
        _context(
            parameters=parameters,
            token_id=f"token-apply-{suffix}-preview",
            capability_id=APPLY_CAPABILITY_ID,
        ),
        prepared.operation_id,
    )
    awaiting = gateway.status(
        _context(
            parameters=parameters,
            capability_id=APPLY_CAPABILITY_ID,
        ),
        prepared.operation_id,
    )
    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id=f"token-apply-{suffix}-execute",
            capability_id=APPLY_CAPABILITY_ID,
        ),
        _approval(awaiting, f"approval-apply-{suffix}"),
        reconciliation_only=False,
    )
    return gateway.status(
        _context(
            parameters=parameters,
            capability_id=APPLY_CAPABILITY_ID,
        ),
        prepared.operation_id,
    ), output, parameters


def _undo_parameters(
    origin,
    output: dict[str, object],
    receipt,
) -> dict[str, object]:
    return {
        "company_id": origin.company_id,
        "origin_operation_id": origin.operation_id,
        "expected_origin_revision": origin.revision,
        "expected_origin_final_receipt_body_digest": receipt.body_digest,
        "expected_recovery_plan_digest": output["recovery_plan"][
            "plan_digest"
        ],
        "recovery_date": "2026-07-16",
        "reason": "Undo the exact completed reconciliation receipt",
        "idempotency_key": f"undo-{origin.operation_id}",
    }


@pytest.fixture
def undo_case(service):
    original, _original_backend, store = service
    backend = ReconciliationBackend()
    gateway = _clone_service(original, backend, store)
    origin, output, _parameters = _complete_reconciliation_origin(
        gateway,
        suffix="undo-origin",
    )
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _undo_parameters(origin, output, receipt)
    return gateway, backend, store, origin, output, receipt, parameters


def _prepare_undo(
    gateway,
    parameters: dict[str, object],
    *,
    operation_id: str,
    request_id: str,
    token_id: str,
    company_id: int = 7,
):
    return gateway.prepare(
        _prepare_context(
            operation_id=operation_id,
            request_id=request_id,
            parameters=parameters,
            token_id=token_id,
            company_id=company_id,
        ),
        operation_id=operation_id,
        request_id=request_id,
        capability_id=UNDO_CAPABILITY_ID,
        parameters=parameters,
    )


def test_completed_verified_finalized_origin_creates_restart_safe_binding(
    undo_case,
):
    gateway, backend, store, origin, output, receipt, parameters = undo_case

    undo = _prepare_undo(
        gateway,
        parameters,
        operation_id="op-undo-primary",
        request_id="request-undo-primary",
        token_id="token-undo-primary",
    )
    binding = store.get_reconciliation_undo_operation_binding(
        undo.operation_id
    )

    assert origin.state is State.COMPLETED
    assert output["verification"]["passed"] is True
    assert output["database_finalization"]
    assert undo.state is State.PREPARED
    assert binding.origin_operation_id == origin.operation_id
    assert binding.origin_operation_revision == origin.revision
    assert binding.origin_final_receipt_id == receipt.receipt_id
    assert (
        binding.origin_final_receipt_body_digest
        == receipt.body_digest
    )
    assert binding.origin_execution_result_id
    assert binding.origin_execution_evidence_digest
    assert binding.origin_verification_result_id
    assert binding.origin_verification_evidence_digest
    assert binding.origin_database_finalization_digest
    assert binding.undo_operation_id == undo.operation_id
    assert binding.undo_operation_revision == 0
    assert binding.plan_digest == output["recovery_plan"]["plan_digest"]
    assert (
        binding.audit_event.event_type
        == "reconciliation.undo.binding.created"
    )
    assert gateway.trusted_recovery_plan(
        _prepare_context(
            operation_id="op-undo-primary",
            request_id="request-undo-primary",
            parameters=parameters,
            token_id="token-undo-plan",
        ),
        undo,
    ) == output["recovery_plan"]

    exact_retry = _prepare_undo(
        gateway,
        copy.deepcopy(parameters),
        operation_id="op-undo-primary",
        request_id="request-undo-primary",
        token_id="token-undo-exact-retry",
    )
    duplicate_identity = _prepare_undo(
        gateway,
        copy.deepcopy(parameters),
        operation_id="op-undo-duplicate",
        request_id="request-undo-duplicate",
        token_id="token-undo-duplicate",
    )
    assert exact_retry == undo
    assert duplicate_identity == undo
    assert sum(
        event.event_type == "reconciliation.undo.binding.created"
        for event in store.audit_events()
    ) == 1

    restarted_store = SQLitePersistence(store.path)
    restarted_gateway = _clone_service(
        gateway,
        backend,
        restarted_store,
    )
    restarted_binding = (
        restarted_store.get_reconciliation_undo_operation_binding(
            undo.operation_id
        )
    )
    assert restarted_binding == binding
    assert restarted_gateway.trusted_recovery_plan(
        _prepare_context(
            operation_id="op-undo-primary",
            request_id="request-undo-primary",
            parameters=parameters,
            token_id="token-undo-restart-plan",
        ),
        restarted_store.get_operation(undo.operation_id),
    ) == output["recovery_plan"]
    assert restarted_store.get_operation(origin.operation_id).state is (
        State.COMPLETED
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reason", "A different approved business reason"),
        ("recovery_date", "2026-07-17"),
        ("idempotency_key", "changed-undo-key"),
    ),
)
def test_same_origin_rejects_changed_undo_content(
    undo_case,
    field: str,
    value: object,
):
    gateway, _backend, _store, _origin, _output, _receipt, parameters = (
        undo_case
    )
    _prepare_undo(
        gateway,
        parameters,
        operation_id="op-undo-bound",
        request_id="request-undo-bound",
        token_id="token-undo-bound",
    )
    changed = copy.deepcopy(parameters)
    changed[field] = value

    with pytest.raises(
        IdempotencyConflict,
        match="different request content",
    ):
        _prepare_undo(
            gateway,
            changed,
            operation_id=f"op-undo-changed-{field}",
            request_id=f"request-undo-changed-{field}",
            token_id=f"token-undo-changed-{field}",
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        (
            "expected_origin_revision",
            5,
            "exact completed reconciliation origin revision",
        ),
        (
            "expected_origin_final_receipt_body_digest",
            "a" * 64,
            "final receipt digest changed",
        ),
        (
            "expected_recovery_plan_digest",
            "b" * 64,
            "recovery plan binding changed",
        ),
    ),
)
def test_origin_revision_receipt_and_plan_tampering_are_rejected(
    undo_case,
    field: str,
    value: object,
    message: str,
):
    gateway, _backend, _store, _origin, _output, _receipt, parameters = (
        undo_case
    )
    changed = copy.deepcopy(parameters)
    changed[field] = value

    with pytest.raises(WriteServiceError, match=message):
        _prepare_undo(
            gateway,
            changed,
            operation_id=f"op-undo-forged-{field}",
            request_id=f"request-undo-forged-{field}",
            token_id=f"token-undo-forged-{field}",
        )


def test_cross_company_origin_is_rejected(undo_case):
    gateway, _backend, _store, _origin, _output, _receipt, parameters = (
        undo_case
    )
    changed = copy.deepcopy(parameters)
    changed["company_id"] = 8

    with pytest.raises(WriteServiceError, match="outside the bound"):
        _prepare_undo(
            gateway,
            changed,
            operation_id="op-undo-cross-company",
            request_id="request-undo-cross-company",
            token_id="token-undo-cross-company",
            company_id=8,
        )


def test_non_reconciliation_origin_is_rejected(service):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(
        gateway,
        parameters=_invoice_parameters("undo-wrong-origin"),
    )
    output = gateway.approve_execute(
        _context(
            parameters=_invoice_parameters("undo-wrong-origin"),
            token_id="token-wrong-origin-execute",
        ),
        _approval(awaiting, "approval-wrong-origin"),
        reconciliation_only=False,
    )
    origin = store.get_operation(awaiting.operation_id)
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _undo_parameters(origin, output, receipt)

    with pytest.raises(
        WriteServiceError,
        match="exact completed reconciliation origin revision",
    ):
        _prepare_undo(
            gateway,
            parameters,
            operation_id="op-undo-wrong-origin",
            request_id="request-undo-wrong-origin",
            token_id="token-undo-wrong-origin",
        )


def test_failed_reconciliation_origin_is_rejected(service):
    original, _backend, store = service
    backend = ReconciliationBackend(verification_passes=False)
    gateway = _clone_service(original, backend, store)
    origin, output, _parameters = _complete_reconciliation_origin(
        gateway,
        suffix="failed",
    )
    assert origin.state is State.FAILED
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _undo_parameters(origin, output, receipt)

    with pytest.raises(
        WriteServiceError,
        match="exact completed reconciliation origin revision",
    ):
        _prepare_undo(
            gateway,
            parameters,
            operation_id="op-undo-failed-origin",
            request_id="request-undo-failed-origin",
            token_id="token-undo-failed-origin",
        )


def test_unfinalized_reconciliation_origin_is_rejected(service):
    original, _backend, store = service
    backend = ReconciliationBackend()
    gateway = _clone_service(original, backend, store)
    parameters = _apply_parameters("unfinalized")
    prepared = gateway.prepare(
        _context(
            parameters=parameters,
            token_id="token-unfinalized-prepare",
            capability_id=APPLY_CAPABILITY_ID,
        ),
        operation_id="op-apply-unfinalized",
        request_id="request-apply-unfinalized",
        capability_id=APPLY_CAPABILITY_ID,
        parameters=parameters,
    )
    gateway.preview(
        _context(
            parameters=parameters,
            token_id="token-unfinalized-preview",
            capability_id=APPLY_CAPABILITY_ID,
        ),
        prepared.operation_id,
    )
    awaiting = gateway.status(
        _context(
            parameters=parameters,
            capability_id=APPLY_CAPABILITY_ID,
        ),
        prepared.operation_id,
    )
    finalizer = original._test_effect_finalizer
    finalizer.error = RuntimeError("database finalization unavailable")
    with pytest.raises(WriteServiceError, match="database effect finalization"):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id="token-unfinalized-execute",
                capability_id=APPLY_CAPABILITY_ID,
            ),
            _approval(awaiting, "approval-unfinalized"),
            reconciliation_only=False,
        )
    finalizer.error = None
    origin = store.get_operation(prepared.operation_id)
    assert origin.state is State.VERIFYING
    undo_parameters = {
        "company_id": 7,
        "origin_operation_id": origin.operation_id,
        "expected_origin_revision": origin.revision,
        "expected_origin_final_receipt_body_digest": "a" * 64,
        "expected_recovery_plan_digest": "b" * 64,
        "recovery_date": "2026-07-16",
        "reason": "Must not undo an unfinalized reconciliation",
        "idempotency_key": "undo-unfinalized",
    }

    with pytest.raises(
        WriteServiceError,
        match="exact completed reconciliation origin revision",
    ):
        _prepare_undo(
            gateway,
            undo_parameters,
            operation_id="op-undo-unfinalized",
            request_id="request-undo-unfinalized",
            token_id="token-undo-unfinalized",
        )


def test_completed_undo_does_not_transition_origin_into_incident_recovery(
    service,
):
    original, _backend, store = service
    backend = UndoCompletingBackend()
    gateway = _clone_service(original, backend, store)
    origin, origin_output, origin_parameters = (
        _complete_reconciliation_origin(
            gateway,
            suffix="completed-undo",
        )
    )
    origin_revision = origin.revision
    receipt = store.get_final_write_receipts(origin.operation_id)[0]
    parameters = _undo_parameters(origin, origin_output, receipt)
    undo = _prepare_undo(
        gateway,
        parameters,
        operation_id="op-undo-completed",
        request_id="request-undo-completed",
        token_id="token-undo-completed-prepare",
    )
    gateway.preview(
        _context(
            parameters=parameters,
            token_id="token-undo-completed-preview",
            capability_id=UNDO_CAPABILITY_ID,
        ),
        undo.operation_id,
    )
    awaiting = gateway.status(
        _context(
            parameters=parameters,
            capability_id=UNDO_CAPABILITY_ID,
        ),
        undo.operation_id,
    )
    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-undo-completed-execute",
            capability_id=UNDO_CAPABILITY_ID,
        ),
        _approval(awaiting, "approval-undo-completed"),
        reconciliation_only=False,
    )

    assert output["operation_state"] == State.COMPLETED.value
    assert store.get_operation(undo.operation_id).state is State.COMPLETED
    durable_origin = store.get_operation(origin.operation_id)
    assert durable_origin.state is State.COMPLETED
    assert durable_origin.revision == origin_revision
    assert gateway.result(
        _context(
            parameters=parameters,
            capability_id=UNDO_CAPABILITY_ID,
        ),
        undo.operation_id,
    ) == output
    assert store.get_operation(origin.operation_id).state is State.COMPLETED
    assert gateway.result(
        _context(
            parameters=origin_parameters,
            capability_id=APPLY_CAPABILITY_ID,
        ),
        origin.operation_id,
    ) == origin_output
    assert not any(
        event.operation_id == origin.operation_id
        and event.event_type
        in {"operation.recovery_started", "operation.recovered"}
        for event in store.audit_events()
    )


def test_preview_rejects_missing_binding_before_odoo_precheck(
    undo_case,
    monkeypatch: pytest.MonkeyPatch,
):
    gateway, backend, store, _origin, _output, _receipt, parameters = (
        undo_case
    )
    undo = _prepare_undo(
        gateway,
        parameters,
        operation_id="op-undo-missing-binding-preview",
        request_id="request-undo-missing-binding-preview",
        token_id="token-undo-missing-binding-preview-prepare",
    )
    calls_before = list(backend.calls)

    def missing_binding(_operation_id: str):
        raise OperationNotFound(
            "reconciliation undo binding does not exist"
        )

    monkeypatch.setattr(
        store,
        "get_reconciliation_undo_operation_binding",
        missing_binding,
    )

    with pytest.raises(
        WriteServiceError,
        match="no durable origin binding",
    ):
        gateway.preview(
            _context(
                parameters=parameters,
                token_id="token-undo-missing-binding-preview",
                capability_id=UNDO_CAPABILITY_ID,
            ),
            undo.operation_id,
        )

    assert store.get_operation(undo.operation_id).state is State.PREPARED
    assert backend.calls == calls_before


def test_binding_is_rechecked_after_approval_before_execution(
    undo_case,
    monkeypatch: pytest.MonkeyPatch,
):
    gateway, backend, store, _origin, _output, _receipt, parameters = (
        undo_case
    )
    undo = _prepare_undo(
        gateway,
        parameters,
        operation_id="op-undo-binding-toctou",
        request_id="request-undo-binding-toctou",
        token_id="token-undo-binding-toctou-prepare",
    )
    gateway.preview(
        _context(
            parameters=parameters,
            token_id="token-undo-binding-toctou-preview",
            capability_id=UNDO_CAPABILITY_ID,
        ),
        undo.operation_id,
    )
    awaiting = store.get_operation(undo.operation_id)
    original_get = store.get_reconciliation_undo_operation_binding
    binding_checks = 0

    def binding_disappears_before_execution(operation_id: str):
        nonlocal binding_checks
        binding_checks += 1
        if binding_checks >= 3:
            raise OperationNotFound(
                "reconciliation undo binding does not exist"
            )
        return original_get(operation_id)

    monkeypatch.setattr(
        store,
        "get_reconciliation_undo_operation_binding",
        binding_disappears_before_execution,
    )
    calls_before = list(backend.calls)

    with pytest.raises(
        WriteServiceError,
        match="no durable origin binding",
    ):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id="token-undo-binding-toctou-execute",
                capability_id=UNDO_CAPABILITY_ID,
            ),
            _approval(awaiting, "approval-undo-binding-toctou"),
            reconciliation_only=False,
        )

    assert binding_checks == 3
    assert store.get_operation(undo.operation_id).state is State.APPROVED
    assert backend.calls == [*calls_before, "precheck"]
    assert "execute" not in backend.calls[len(calls_before):]

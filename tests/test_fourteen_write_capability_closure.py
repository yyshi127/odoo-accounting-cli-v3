"""Local development closure matrix for the fourteen write capabilities.

This suite proves registry/schema coverage, concrete handler dispatch,
durable idempotency, signed failure handling, and recovery registration.  It
does not execute a live Odoo database and is not sandbox or production
evidence.
"""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.domain.write_semantics import (
    validate_write_semantics,
)
from odoo_accounting_cli_v3.draft_invoice_recovery import (
    DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
    DRAFT_VENDOR_BILL_RECOVERY_METHOD,
)
from odoo_accounting_cli_v3.odoo.recovery_actions import (
    FAIL_CLOSED_RECOVERY_METHODS,
    RECOVERY_ACTION_METHODS,
    execute_recovery_action,
)
from odoo_accounting_cli_v3.odoo.recovery_verifier import (
    RECOVERY_VERIFICATION_METHODS,
    verify_recovery_action,
)
from odoo_accounting_cli_v3.odoo.write_handlers import (
    OdooWriteHandlers,
    _RECOVERY_ACTIONS,
)
from odoo_accounting_cli_v3.operations import (
    Operation,
    State,
    approve_operation,
    begin_execution,
    canonical_json,
    record_execution_result,
    record_precheck,
    sign_approval,
    sign_execution_result,
)
from odoo_accounting_cli_v3.persistence import (
    IdempotencyConflict,
    SQLitePersistence,
)
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
    contracts_for_capability,
)
from odoo_accounting_cli_v3.registry import (
    load_registry,
    registry_digest,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_recovery_plan_v2,
)
from odoo_accounting_cli_v3.write_service import (
    BackendEvidence,
    DurableWriteService,
    WriteServiceError,
    write_idempotency_scope,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 29, 8, 0, tzinfo=timezone.utc)
APPROVAL_SECRET = b"closure-approval-secret-material-32"
EXECUTION_SECRET = b"closure-execution-secret-material-32"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
RELEASE_DIGEST = "f" * 64

# The tuple is the explicit 14 x 5 inventory.  The five executable columns are
# exercised below: create dispatch, duplicate control, failure control,
# verification dispatch, and recovery/terminal disposition.
CAPABILITY_MATRIX = (
    (
        "acct.invoice.customer_create.v1",
        "customer_invoice",
        (
            "cancel_pristine_v3_draft_customer_invoice_v1",
            "reverse_posted_customer_invoice_v1",
        ),
    ),
    (
        "acct.bill.vendor_create.v1",
        "vendor_bill",
        (
            "cancel_pristine_v3_draft_vendor_bill_v1",
            "reverse_posted_vendor_bill_v1",
        ),
    ),
    (
        "acct.refund.create.v1",
        "refund",
        ("cancel_draft_refund_v1", "reverse_posted_refund_v1"),
    ),
    (
        "acct.payment.register.v1",
        "payment",
        ("cancel_and_unreconcile_payment_v1",),
    ),
    (
        "acct.bank.statement_import.v1",
        "bank",
        ("post_compensating_bank_statement_v1",),
    ),
    (
        "acct.reconciliation.apply.v1",
        "reconciliation",
        ("undo_reconciliation_without_writeoff_v1",),
    ),
    (
        "acct.asset.create.v1",
        "asset",
        ("cancel_asset_and_reverse_schedule_v1",),
    ),
    (
        "acct.depreciation.post.v1",
        "depreciation",
        ("reverse_depreciation_and_restore_schedule_v1",),
    ),
    (
        "acct.accrual.create.v1",
        "accrual",
        ("cancel_scheduled_and_reverse_accrual_origin_v1",),
    ),
    (
        "acct.deferred.create.v1",
        "deferred",
        ("reverse_deferred_source_and_schedule_v1",),
    ),
    (
        "acct.period.adjustment_create.v1",
        "adjustment",
        (
            "cancel_draft_period_adjustment_v1",
            "reverse_posted_period_adjustment_v1",
        ),
    ),
    (
        "acct.move.reverse.v1",
        "reversal",
        ("reverse_the_reversal_v1",),
    ),
    ("acct.move.draft_cancel.v1", "draft_cancel", ()),
    ("acct.recovery.execute.v1", "recovery", ()),
)

CAPABILITY_IDS = tuple(row[0] for row in CAPABILITY_MATRIX)
TERMINAL_CAPABILITY_IDS = frozenset(
    {"acct.move.draft_cancel.v1", "acct.recovery.execute.v1"}
)

INVOICE_LINE = {
    "line_reference": "line-1",
    "name": "Service",
    "product_id": None,
    "account_id": 401,
    "quantity": "1",
    "price_unit": "100.00",
    "tax_ids": [],
}
JOURNAL_LINES = [
    {
        "line_reference": "debit-1",
        "account_id": 401,
        "partner_id": None,
        "currency_id": 12,
        "name": "Debit",
        "side": "debit",
        "amount": "100.00",
        "amount_currency": "100.00",
        "tax_ids": [],
    },
    {
        "line_reference": "credit-1",
        "account_id": 402,
        "partner_id": None,
        "currency_id": 12,
        "name": "Credit",
        "side": "credit",
        "amount": "100.00",
        "amount_currency": "-100.00",
        "tax_ids": [],
    },
]

VALID_PARAMETERS = {
    "acct.invoice.customer_create.v1": {
        "company_id": 7,
        "partner_id": 101,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15",
        "due_date": "2026-08-15",
        "currency_id": 12,
        "journal_id": 5,
        "posting_mode": "draft",
        "reference": "INV-1",
        "lines": [INVOICE_LINE],
        "idempotency_key": "idem-invoice",
    },
    "acct.bill.vendor_create.v1": {
        "company_id": 7,
        "partner_id": 102,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15",
        "due_date": "2026-08-15",
        "currency_id": 12,
        "journal_id": 6,
        "posting_mode": "draft",
        "vendor_reference": "BILL-1",
        "lines": [INVOICE_LINE],
        "idempotency_key": "idem-bill",
    },
    "acct.refund.create.v1": {
        "company_id": 7,
        "origin_move_id": 501,
        "refund_type": "customer_credit_note",
        "refund_mode": "full",
        "refund_date": "2026-07-16",
        "journal_id": 5,
        "currency_id": 12,
        "expected_total_amount": "100.00",
        "reason": "Approved refund",
        "posting_mode": "draft",
        "lines": [],
        "idempotency_key": "idem-refund",
    },
    "acct.payment.register.v1": {
        "company_id": 7,
        "target_move_ids": [501],
        "partner_id": 101,
        "partner_type": "customer",
        "direction": "inbound",
        "payment_date": "2026-07-16",
        "currency_id": 12,
        "amount": "100.00",
        "journal_id": 7,
        "payment_method_line_id": 8,
        "memo": "Payment INV-1",
        "idempotency_key": "idem-payment",
    },
    "acct.bank.statement_import.v1": {
        "company_id": 7,
        "journal_id": 7,
        "statement_date": "2026-07-16",
        "currency_id": 12,
        "external_reference": "STMT-1",
        "source_digest": "a" * 64,
        "source_filename": "stmt.csv",
        "opening_balance": "0",
        "closing_balance": "100.00",
        "lines": [
            {
                "external_transaction_id": "tx-1",
                "transaction_date": "2026-07-16",
                "value_date": "2026-07-16",
                "direction": "credit",
                "amount": "100.00",
                "foreign_currency_id": None,
                "foreign_amount": None,
                "summary": "Receipt",
                "partner_id": 101,
                "source_line_digest": "b" * 64,
            }
        ],
        "idempotency_key": "idem-bank",
    },
    "acct.reconciliation.apply.v1": {
        "company_id": 7,
        "line_ids": [601, 602],
        "account_id": 1100,
        "partner_id": 101,
        "reconciliation_date": "2026-07-16",
        "currency_id": 12,
        "mode": "full",
        "amount": "100.00",
        "tolerance_amount": "0",
        "writeoff_account_id": None,
        "writeoff_journal_id": None,
        "writeoff_label": None,
        "idempotency_key": "idem-reconcile",
    },
    "acct.asset.create.v1": {
        "company_id": 7,
        "source_move_line_id": 701,
        "asset_model_id": 9,
        "asset_name": "Computer",
        "acquisition_date": "2026-07-15",
        "currency_id": 12,
        "acquisition_value": "1200.00",
        "posting_mode": "confirm",
        "idempotency_key": "idem-asset",
    },
    "acct.depreciation.post.v1": {
        "company_id": 7,
        "asset_id": 801,
        "depreciation_move_id": 802,
        "period_start": "2026-07-01",
        "period_end": "2026-07-31",
        "posting_date": "2026-07-31",
        "journal_id": 8,
        "currency_id": 12,
        "amount": "100.00",
        "idempotency_key": "idem-depreciation",
    },
    "acct.accrual.create.v1": {
        "company_id": 7,
        "journal_id": 8,
        "posting_date": "2026-07-31",
        "reversal_date": "2026-08-01",
        "currency_id": 12,
        "reference": "ACCRUAL-1",
        "posting_mode": "post",
        "lines": JOURNAL_LINES,
        "idempotency_key": "idem-accrual",
    },
    "acct.deferred.create.v1": {
        "company_id": 7,
        "source_move_line_id": 901,
        "deferred_type": "expense",
        "schedule_start_date": "2026-07-01",
        "schedule_end_date": "2027-06-30",
        "expected_generation_method": "on_validation",
        "amount_computation_method": "month",
        "expected_deferred_account_id": 1500,
        "expected_deferred_journal_id": 8,
        "currency_id": 12,
        "total_amount": "1200.00",
        "posting_mode": "post",
        "idempotency_key": "idem-deferred",
    },
    "acct.period.adjustment_create.v1": {
        "company_id": 7,
        "journal_id": 8,
        "posting_date": "2026-07-31",
        "period_end_date": "2026-07-31",
        "currency_id": 12,
        "reference": "ADJ-1",
        "reason": "Month end",
        "posting_mode": "post",
        "lines": JOURNAL_LINES,
        "idempotency_key": "idem-adjustment",
    },
    "acct.move.reverse.v1": {
        "company_id": 7,
        "move_id": 1001,
        "reversal_date": "2026-08-01",
        "journal_id": 8,
        "currency_id": 12,
        "expected_total_amount": "100.00",
        "reason": "Approved reversal",
        "posting_mode": "post",
        "idempotency_key": "idem-reversal",
    },
    "acct.move.draft_cancel.v1": {
        "company_id": 7,
        "move_id": 1002,
        "expected_move_type": "out_invoice",
        "expected_document_binding": "c" * 64,
        "expected_document_binding_v2": "e" * 64,
        "expected_business_binding": "d" * 64,
        "reason": "Cancel pristine draft",
        "idempotency_key": "idem-draft-cancel",
    },
    "acct.recovery.execute.v1": {
        "company_id": 7,
        "origin_operation_id": "origin-op-1",
        "expected_recovery_plan_digest": "e" * 64,
        "recovery_date": "2026-08-02",
        "reason": "Execute approved recovery",
        "idempotency_key": "idem-recovery",
    },
}

MUTATIONS = {
    "acct.invoice.customer_create.v1": ("reference", "INV-CHANGED"),
    "acct.bill.vendor_create.v1": ("vendor_reference", "BILL-CHANGED"),
    "acct.refund.create.v1": ("reason", "Changed refund reason"),
    "acct.payment.register.v1": ("memo", "Changed payment memo"),
    "acct.bank.statement_import.v1": (
        "external_reference",
        "STMT-CHANGED",
    ),
    "acct.reconciliation.apply.v1": (
        "reconciliation_date",
        "2026-07-17",
    ),
    "acct.asset.create.v1": ("asset_name", "Changed computer"),
    "acct.depreciation.post.v1": ("amount", "101.00"),
    "acct.accrual.create.v1": ("reference", "ACCRUAL-CHANGED"),
    "acct.deferred.create.v1": ("total_amount", "1201.00"),
    "acct.period.adjustment_create.v1": ("reference", "ADJ-CHANGED"),
    "acct.move.reverse.v1": ("reason", "Changed reversal reason"),
    "acct.move.draft_cancel.v1": ("reason", "Changed cancel reason"),
    "acct.recovery.execute.v1": ("reason", "Changed recovery reason"),
}

REGISTRY = load_registry(ROOT / "registry" / "capabilities.json")
WRITE_CAPABILITIES = {
    capability.id: capability
    for capability in REGISTRY
    if (
        capability.data["access"] == "write"
        and capability.id in CAPABILITY_IDS
    )
}
REGISTRY_DIGEST = registry_digest(REGISTRY)


def _parameters(capability_id: str) -> dict[str, object]:
    return copy.deepcopy(VALID_PARAMETERS[capability_id])


def _operation(
    capability_id: str,
    parameters: dict[str, object],
    marker: str,
) -> Operation:
    suffix = capability_id.removeprefix("acct.").removesuffix(".v1")
    return Operation.prepare(
        operation_id=f"op-{suffix}-{marker}",
        request_id=f"request-{suffix}-{marker}",
        capability_id=capability_id,
        parameters=parameters,
        principal="pi:test-user-42",
        user_id=42,
        company_id=7,
        idempotency_key=str(parameters["idempotency_key"]),
        odoo_instance_id="odoo19@test",
        database_name="odoo_accounting_cli_v3_test",
        database_uuid=DATABASE_UUID,
        environment="test",
        registry_digest=REGISTRY_DIGEST,
        release_digest=RELEASE_DIGEST,
    )


def _executing_operation(
    capability_id: str,
    parameters: dict[str, object],
) -> Operation:
    prepared = _operation(capability_id, parameters, "failure")
    prechecked = record_precheck(
        prepared,
        precheck_digest="1" * 64,
        expected_revision=prepared.revision,
    )
    awaiting = prechecked.transition(
        State.AWAITING_APPROVAL,
        expected_revision=prechecked.revision,
    )
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce=f"nonce-{capability_id}",
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )
    approved = approve_operation(
        awaiting,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda *_args: True,
        consume_nonce=lambda *_args: True,
        approval_ttl_seconds=600,
        expected_revision=awaiting.revision,
    )
    return begin_execution(
        approved,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda *_args: True,
        approval_ttl_seconds=600,
        expected_revision=approved.revision,
    )


def _failed_execution(
    operation: Operation,
) -> BackendEvidence:
    recovery_parameters = {"operation_id": operation.operation_id}
    evidence = {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": False,
        "odoo_records": [],
        "difference": create_difference(
            before=[],
            after=[],
            changed_fields=[],
        ),
        "recovery_plan": create_recovery_plan_v2(
            origin_operation_id=operation.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="manual_escalation",
            method="inspect_rejected_execution",
            requires_approval=True,
            action_targets=[],
            guard_records=[],
            oracle_id="manual_escalation",
            parameters=recovery_parameters,
        ),
        "recovery_parameters": recovery_parameters,
        "module_graph": None,
        "failure_checks": ["execution_rejected_without_verified_effect"],
    }
    digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
    result = sign_execution_result(
        operation=operation,
        issuer="odoo-write-executor",
        key_id="execution-v1",
        succeeded=False,
        evidence_digest=digest,
        issued_at=NOW,
        secret=EXECUTION_SECRET,
    )
    return BackendEvidence(result=result, evidence=evidence)


@pytest.mark.parametrize(
    ("capability_id", "dispatch_key", "_recovery_methods"),
    CAPABILITY_MATRIX,
)
def test_all_fourteen_have_concrete_precheck_execute_and_verify_dispatch(
    capability_id: str,
    dispatch_key: str,
    _recovery_methods: tuple[str, ...],
) -> None:
    for phase in ("precheck", "execute", "verify"):
        expected_name = f"{phase}_{dispatch_key}"
        assert OdooWriteHandlers.dispatch_name(capability_id, phase) == expected_name
        assert expected_name in OdooWriteHandlers.__dict__
        assert callable(OdooWriteHandlers.__dict__[expected_name])


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_all_fourteen_samples_pass_strict_schema_semantics_and_write_policy(
    capability_id: str,
) -> None:
    capability = WRITE_CAPABILITIES[capability_id]
    parameters = _parameters(capability_id)

    validate_value(parameters, capability.data["input_schema"])
    semantics = validate_write_semantics(capability_id, parameters)

    assert semantics["capability_id"] == capability_id
    assert semantics["company_id"] == 7
    assert semantics["checks"]
    assert capability.data["approval"]["required"] is True
    assert capability.data["idempotency"]["required"] is True
    assert "idempotency_key" in capability.data["input_schema"]["required"]


def test_registry_and_matrix_identify_exactly_the_same_fourteen_writes() -> None:
    assert len(CAPABILITY_MATRIX) == 14
    assert len(set(CAPABILITY_IDS)) == 14
    assert set(WRITE_CAPABILITIES) == set(CAPABILITY_IDS)
    assert set(VALID_PARAMETERS) == set(CAPABILITY_IDS)
    assert set(MUTATIONS) == set(CAPABILITY_IDS)


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_all_fourteen_idempotency_scopes_replay_exact_duplicate_and_reject_drift(
    capability_id: str,
    tmp_path: Path,
) -> None:
    capability = WRITE_CAPABILITIES[capability_id]
    parameters = _parameters(capability_id)
    scope = write_idempotency_scope(capability, parameters)
    store = SQLitePersistence(
        (tmp_path / f"{capability_id.replace('.', '_')}.sqlite3").resolve()
    )

    first, created = store.get_or_create_operation(
        _operation(capability_id, parameters, "first"),
        scope=scope,
    )
    duplicate, duplicate_created = store.get_or_create_operation(
        _operation(capability_id, copy.deepcopy(parameters), "duplicate"),
        scope=scope,
    )
    assert created is True
    assert duplicate_created is False
    assert duplicate.operation_id == first.operation_id

    changed = copy.deepcopy(parameters)
    field, value = MUTATIONS[capability_id]
    changed[field] = value
    validate_value(changed, capability.data["input_schema"])
    validate_write_semantics(capability_id, changed)
    assert write_idempotency_scope(capability, changed) == scope
    with pytest.raises(
        IdempotencyConflict,
        match="different request content",
    ):
        store.get_or_create_operation(
            _operation(capability_id, changed, "changed"),
            scope=scope,
        )


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_all_fourteen_share_signed_failure_and_tamper_fail_closed_controls(
    capability_id: str,
) -> None:
    capability = WRITE_CAPABILITIES[capability_id]
    executing = _executing_operation(capability_id, _parameters(capability_id))
    payload = _failed_execution(executing)

    DurableWriteService._validate_execution_evidence(
        payload,
        executing,
        capability,
    )
    tampered_evidence = copy.deepcopy(payload.evidence)
    tampered_evidence["failure_checks"] = ["forged_failure_check"]
    with pytest.raises(
        WriteServiceError,
        match="evidence digest mismatch",
    ):
        DurableWriteService._validate_backend_digest(
            BackendEvidence(
                result=payload.result,
                evidence=tampered_evidence,
            )
        )

    failed = record_execution_result(
        executing,
        payload.result,
        now=NOW,
        secret=EXECUTION_SECRET,
        expected_key_id="execution-v1",
        allowed_issuers=frozenset({"odoo-write-executor"}),
        expected_revision=executing.revision,
    )
    result_body = DurableWriteService._receipt_details(
        operation=failed,
        execution=payload,
        verification=None,
        database_finalization=None,
    )

    assert failed.state is State.FAILED
    assert failed.verification_result_digest is None
    assert result_body["operation_state"] == State.FAILED.value
    assert result_body["verification"]["passed"] is False
    assert result_body["odoo_records"] == []
    assert result_body["database_finalization"] is None


@pytest.mark.parametrize(
    ("capability_id", "_dispatch_key", "expected_methods"),
    CAPABILITY_MATRIX,
)
def test_twelve_origins_have_sixteen_paths_and_two_terminals_have_none(
    capability_id: str,
    _dispatch_key: str,
    expected_methods: tuple[str, ...],
) -> None:
    actual = contracts_for_capability(capability_id)
    assert tuple(contract.method for contract in actual) == expected_methods
    if capability_id in TERMINAL_CAPABILITY_IDS:
        assert actual == ()
    else:
        assert actual


def test_every_recovery_contract_remains_registered_but_blocked_actions_are_not_allowlisted() -> None:
    contract_methods = frozenset(RECOVERY_ACTION_CONTRACTS)
    specialized_draft_methods = frozenset(
        {
            DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD,
            DRAFT_VENDOR_BILL_RECOVERY_METHOD,
        }
    )

    assert len(contract_methods) == 16
    assert sum(
        len(contracts_for_capability(capability_id))
        for capability_id in CAPABILITY_IDS
    ) == 16
    assert _RECOVERY_ACTIONS == (
        contract_methods - FAIL_CLOSED_RECOVERY_METHODS
    )
    assert (
        RECOVERY_ACTION_METHODS | specialized_draft_methods
        == contract_methods
    )
    assert RECOVERY_VERIFICATION_METHODS == contract_methods
    assert callable(execute_recovery_action)
    assert callable(verify_recovery_action)

"""Offline development closure for the three Phase B move capabilities.

This suite proves local registry/schema and accounting-semantic coverage,
durable idempotency, signed failure handling, tamper rejection, concrete
three-phase handler dispatch, and closed evidence gates.  It does not execute
an Odoo database and must not be represented as sandbox or production Odoo
evidence.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.contracts import ContractError, validate_value
from odoo_accounting_cli_v3.domain.write_semantics import (
    WriteSemanticError,
    validate_write_semantics,
)
from odoo_accounting_cli_v3.odoo.write_handlers import OdooWriteHandlers
from odoo_accounting_cli_v3.operations import (
    Operation,
    State,
    TrustedResultRejected,
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
from odoo_accounting_cli_v3.registry import load_registry, registry_digest
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
APPROVAL_SECRET = b"phase-b-closure-approval-secret-material"
EXECUTION_SECRET = b"phase-b-closure-execution-secret-material"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
RELEASE_DIGEST = "f" * 64

CAPABILITY_MATRIX = (
    ("acct.journal.entry_create.v1", "journal_entry_create"),
    ("acct.move.post.v1", "move_post"),
    ("acct.move.draft_cancel.v2", "draft_cancel_v2"),
)
CAPABILITY_IDS = tuple(row[0] for row in CAPABILITY_MATRIX)

EXPECTED_INPUT_FIELDS = {
    "acct.journal.entry_create.v1": {
        "company_id",
        "journal_id",
        "posting_date",
        "currency_id",
        "reference",
        "reason",
        "posting_mode",
        "lines",
        "idempotency_key",
    },
    "acct.move.post.v1": {
        "company_id",
        "move_id",
        "expected_move_type",
        "expected_document_binding",
        "expected_business_binding",
        "expected_journal_id",
        "expected_currency_id",
        "expected_posting_date",
        "expected_reference",
        "expected_total_debit",
        "expected_total_credit",
        "expected_line_count",
        "reason",
        "idempotency_key",
    },
    "acct.move.draft_cancel.v2": {
        "company_id",
        "move_id",
        "expected_move_type",
        "expected_document_binding",
        "expected_business_binding",
        "expected_line_ids",
        "reason",
        "idempotency_key",
    },
}

EXPECTED_SEMANTIC_CHECKS = {
    "acct.journal.entry_create.v1": {
        "journal_entry_draft_only",
        "journal_entry_reference_and_reason_explicit",
        "journal_entry_accounts_and_partners_explicit",
        "journal_entry_tax_free",
        "journal_lines_unique",
        "company_currency_balanced",
        "transaction_currency_balanced",
    },
    "acct.move.post.v1": {
        "move_post_target_is_manual_entry",
        "move_post_bindings_explicit",
        "move_post_graph_expectations_explicit",
        "move_post_totals_balanced",
    },
    "acct.move.draft_cancel.v2": {
        "draft_cancel_v2_target_explicit",
        "draft_cancel_v2_move_type_supported",
        "draft_cancel_v2_bindings_explicit",
        "draft_cancel_v2_line_set_explicit",
    },
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
    "acct.journal.entry_create.v1": {
        "company_id": 7,
        "journal_id": 8,
        "posting_date": "2026-07-31",
        "currency_id": 12,
        "reference": "Manual reclassification 2026-07",
        "reason": "Approved reclassification",
        "posting_mode": "draft",
        "lines": JOURNAL_LINES,
        "idempotency_key": "phase-b-journal-entry",
    },
    "acct.move.post.v1": {
        "company_id": 7,
        "move_id": 882,
        "expected_move_type": "entry",
        "expected_document_binding": "d" * 64,
        "expected_business_binding": "e" * 64,
        "expected_journal_id": 8,
        "expected_currency_id": 12,
        "expected_posting_date": "2026-07-31",
        "expected_reference": "Manual reclassification 2026-07",
        "expected_total_debit": "100.00",
        "expected_total_credit": "100.00",
        "expected_line_count": 2,
        "reason": "Approved posting",
        "idempotency_key": "phase-b-post-882",
    },
    "acct.move.draft_cancel.v2": {
        "company_id": 7,
        "move_id": 883,
        "expected_move_type": "entry",
        "expected_document_binding": "a" * 64,
        "expected_business_binding": "b" * 64,
        "expected_line_ids": [2001, 2002],
        "reason": "Cancel duplicate pristine draft entry",
        "idempotency_key": "phase-b-cancel-883",
    },
}

IDEMPOTENCY_MUTATIONS = {
    "acct.journal.entry_create.v1": (
        "reference",
        "Manual reclassification 2026-07 changed",
    ),
    "acct.move.post.v1": ("reason", "Changed approved posting reason"),
    "acct.move.draft_cancel.v2": (
        "reason",
        "Changed approved cancellation reason",
    ),
}

REGISTRY = load_registry(ROOT / "registry" / "capabilities.json")
CAPABILITIES = {
    capability.id: capability
    for capability in REGISTRY
    if capability.id in CAPABILITY_IDS
}
REGISTRY_DIGEST = registry_digest(REGISTRY)


def _parameters(capability_id: str) -> dict[str, object]:
    return copy.deepcopy(VALID_PARAMETERS[capability_id])


def _operation(
    capability_id: str,
    parameters: dict[str, object],
    marker: str,
) -> Operation:
    identifier = capability_id.replace(".", "-")
    return Operation.prepare(
        operation_id=f"op-{identifier}-{marker}",
        request_id=f"request-{identifier}-{marker}",
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


def _signed_failed_execution(operation: Operation) -> BackendEvidence:
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


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_phase_b_strict_schema_and_accounting_semantics(
    capability_id: str,
) -> None:
    assert set(CAPABILITIES) == set(CAPABILITY_IDS)
    capability = CAPABILITIES[capability_id]
    schema = capability.data["input_schema"]
    parameters = _parameters(capability_id)

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == EXPECTED_INPUT_FIELDS[capability_id]
    assert set(schema["required"]) == EXPECTED_INPUT_FIELDS[capability_id]
    validate_value(parameters, schema)

    semantics = validate_write_semantics(capability_id, parameters)
    assert semantics["capability_id"] == capability_id
    assert semantics["company_id"] == 7
    assert set(semantics["checks"]) == EXPECTED_SEMANTIC_CHECKS[capability_id]

    unknown = copy.deepcopy(parameters)
    unknown["unapproved_extra"] = True
    with pytest.raises(ContractError):
        validate_value(unknown, schema)


def test_phase_b_journal_and_post_cross_field_imbalances_fail_semantics() -> None:
    journal = _parameters("acct.journal.entry_create.v1")
    journal["lines"][1]["amount"] = "99.00"
    journal["lines"][1]["amount_currency"] = "-99.00"
    validate_value(
        journal,
        CAPABILITIES["acct.journal.entry_create.v1"].data["input_schema"],
    )
    with pytest.raises(WriteSemanticError, match="not balanced"):
        validate_write_semantics("acct.journal.entry_create.v1", journal)

    posting = _parameters("acct.move.post.v1")
    posting["expected_total_credit"] = "99.00"
    validate_value(
        posting,
        CAPABILITIES["acct.move.post.v1"].data["input_schema"],
    )
    with pytest.raises(WriteSemanticError, match="must equal"):
        validate_write_semantics("acct.move.post.v1", posting)


def test_phase_b_draft_cancel_rejects_non_unique_or_unbound_line_sets() -> None:
    capability_id = "acct.move.draft_cancel.v2"
    schema = CAPABILITIES[capability_id].data["input_schema"]

    duplicate = _parameters(capability_id)
    duplicate["expected_line_ids"] = [2001, 2001]
    with pytest.raises(ContractError):
        validate_value(duplicate, schema)
    with pytest.raises(WriteSemanticError, match="must be unique"):
        validate_write_semantics(capability_id, duplicate)

    too_small = _parameters(capability_id)
    too_small["expected_line_ids"] = [2001]
    with pytest.raises(ContractError):
        validate_value(too_small, schema)
    with pytest.raises(WriteSemanticError, match="between 2 and 1000"):
        validate_write_semantics(capability_id, too_small)


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_phase_b_idempotency_reuses_exact_request_and_rejects_content_drift(
    capability_id: str,
    tmp_path: Path,
) -> None:
    capability = CAPABILITIES[capability_id]
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
    field, value = IDEMPOTENCY_MUTATIONS[capability_id]
    changed[field] = value
    validate_value(changed, capability.data["input_schema"])
    validate_write_semantics(capability_id, changed)
    assert write_idempotency_scope(capability, changed) == scope
    with pytest.raises(IdempotencyConflict, match="different request content"):
        store.get_or_create_operation(
            _operation(capability_id, changed, "changed"),
            scope=scope,
        )


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_phase_b_signed_failure_and_tampering_fail_closed(
    capability_id: str,
) -> None:
    capability = CAPABILITIES[capability_id]
    executing = _executing_operation(capability_id, _parameters(capability_id))
    payload = _signed_failed_execution(executing)

    DurableWriteService._validate_execution_evidence(
        payload,
        executing,
        capability,
    )

    tampered_evidence = copy.deepcopy(payload.evidence)
    tampered_evidence["failure_checks"] = ["forged_failure_check"]
    with pytest.raises(WriteServiceError, match="evidence digest mismatch"):
        DurableWriteService._validate_backend_digest(
            BackendEvidence(
                result=payload.result,
                evidence=tampered_evidence,
            )
        )

    tampered_signature = replace(payload.result, signature="0" * 64)
    with pytest.raises(TrustedResultRejected, match="signature mismatch"):
        record_execution_result(
            executing,
            tampered_signature,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-write-executor"}),
            expected_revision=executing.revision,
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
    receipt = DurableWriteService._receipt_details(
        operation=failed,
        execution=payload,
        verification=None,
        database_finalization=None,
    )
    assert failed.state is State.FAILED
    assert failed.verification_result_digest is None
    assert receipt["operation_state"] == State.FAILED.value
    assert receipt["verification"]["passed"] is False
    assert receipt["odoo_records"] == []
    assert receipt["database_finalization"] is None


@pytest.mark.parametrize(("capability_id", "dispatch_key"), CAPABILITY_MATRIX)
def test_phase_b_has_concrete_precheck_execute_and_verify_dispatch(
    capability_id: str,
    dispatch_key: str,
) -> None:
    for phase in ("precheck", "execute", "verify"):
        expected_name = f"{phase}_{dispatch_key}"
        assert OdooWriteHandlers.dispatch_name(capability_id, phase) == expected_name
        assert expected_name in OdooWriteHandlers.__dict__
        assert callable(OdooWriteHandlers.__dict__[expected_name])


@pytest.mark.parametrize("capability_id", CAPABILITY_IDS)
def test_phase_b_remains_declared_disabled_and_without_odoo_evidence(
    capability_id: str,
) -> None:
    capability = CAPABILITIES[capability_id].data

    assert capability["access"] == "write"
    assert capability["approval"]["required"] is True
    assert capability["idempotency"]["required"] is True
    assert capability["evidence"] == {"level": "declared", "receipts": []}
    assert capability.get("staged_environments", []) == []
    assert capability["enabled_environments"] == []

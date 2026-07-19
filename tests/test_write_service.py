from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.auth import (
    authentication_request_digest,
    sign_write_action_context,
    verify_write_action_context,
)
from odoo_accounting_cli_v3.effect_finalizer import (
    EffectFinalizationError,
    EffectFinalizationIdentity,
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
    trusted_result_envelope_digest,
)
from odoo_accounting_cli_v3.gateway import RequestContext
from odoo_accounting_cli_v3.operations import (
    State,
    canonical_json,
    record_execution_result,
    sign_approval,
    sign_execution_result,
    sign_verification_result,
)
from odoo_accounting_cli_v3.odoo.module_graph import build_trusted_module_graph
from odoo_accounting_cli_v3.persistence import (
    IdempotencyConflict,
    ReplayRejected,
    SQLitePersistence,
)
from odoo_accounting_cli_v3.registry import validate_registry
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_record_snapshot,
    create_recovery_plan,
    create_recovery_plan_v2,
)
from odoo_accounting_cli_v3.write_service import (
    _ALLOWED_MODELS,
    _index_company_bound_fresh_snapshots,
    BackendEvidence,
    BackendWriteOutcome,
    DurableWriteService,
    WriteServiceError,
    WriteServiceSecurity,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 7, 15, 3, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
RELEASE_DIGEST = "d" * 64
APPROVAL_SECRET = b"approval-secret-material-at-least-32"
EXECUTION_SECRET = b"execution-secret-material-at-least-32"
VERIFICATION_SECRET = b"verification-secret-material-32-bytes"
RECEIPT_SECRET = b"write-receipt-secret-material-32-bytes"
EFFECT_FINALIZER_SECRET = b"effect-finalizer-secret-material-32-bytes"
GUARD_INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"
FINALIZER_IDENTITY = EffectFinalizationIdentity(
    attestation_key_id="effect-finalizer-v1",
    guard_installation_id=GUARD_INSTALLATION_ID,
    database_oid=16384,
)
TEST_MODULE_GRAPH = build_trusted_module_graph(
    [{"name": "account", "latest_version": "19.0.test"}]
)


def test_write_service_accepts_every_model_emitted_by_hardened_write_handlers():
    assert _ALLOWED_MODELS["acct.invoice.customer_create.v1"] == {
        "account.move", "account.move.line",
    }
    assert _ALLOWED_MODELS["acct.bill.vendor_create.v1"] == {
        "account.move", "account.move.line",
    }
    assert _ALLOWED_MODELS["acct.refund.create.v1"] == {
        "account.move", "account.move.line",
    }
    assert _ALLOWED_MODELS["acct.payment.register.v1"] == {
        "account.payment", "account.move", "account.move.line",
        "account.partial.reconcile", "account.full.reconcile",
    }
    assert _ALLOWED_MODELS["acct.bank.statement_import.v1"] == {
        "account.bank.statement", "account.bank.statement.line",
        "account.move", "account.move.line",
    }
    assert _ALLOWED_MODELS["acct.reconciliation.apply.v1"] == {
        "account.move", "account.move.line", "account.partial.reconcile",
        "account.full.reconcile",
    }
    for capability_id in (
        "acct.depreciation.post.v1",
        "acct.accrual.create.v1",
        "acct.period.adjustment_create.v1",
        "acct.move.reverse.v1",
        "acct.move.draft_cancel.v1",
    ):
        assert {"account.move", "account.move.line"} <= _ALLOWED_MODELS[
            capability_id
        ]


def test_companyless_full_reconcile_is_bound_through_every_fresh_journal_item():
    line_snapshots = [
        create_record_snapshot(
            model="account.move.line",
            record_id=line_id,
            exists=True,
            record_state="reconciled",
            values={"company_id": 7, "reconciled": True},
        )
        for line_id in (101, 102)
    ]
    full_snapshot = create_record_snapshot(
        model="account.full.reconcile",
        record_id=201,
        exists=True,
        record_state="full",
        values={
            "partial_reconcile_ids": [301],
            "reconciled_line_ids": [101, 102],
        },
    )
    partial_snapshot = create_record_snapshot(
        model="account.partial.reconcile",
        record_id=301,
        exists=True,
        record_state="linked",
        values={"company_id": 7},
    )

    indexed = _index_company_bound_fresh_snapshots(
        [*line_snapshots, partial_snapshot, full_snapshot], 7
    )

    assert set(indexed) == {
        ("account.move.line", 101),
        ("account.move.line", 102),
        ("account.partial.reconcile", 301),
        ("account.full.reconcile", 201),
    }


def test_companyless_full_reconcile_rejects_missing_or_unbound_journal_items():
    full_snapshot = create_record_snapshot(
        model="account.full.reconcile",
        record_id=201,
        exists=True,
        record_state="full",
        values={
            "partial_reconcile_ids": [301],
            "reconciled_line_ids": [101],
        },
    )
    with pytest.raises(
        WriteServiceError,
        match="full reconcile snapshot is not bound to company graph",
    ):
        _index_company_bound_fresh_snapshots([full_snapshot], 7)

    ordinary_without_company = create_record_snapshot(
        model="account.move.line",
        record_id=101,
        exists=True,
        record_state="reconciled",
        values={"reconciled": True},
    )
    with pytest.raises(
        WriteServiceError,
        match="snapshot identity or company is invalid",
    ):
        _index_company_bound_fresh_snapshots(
            [ordinary_without_company, full_snapshot], 7
        )


def _capabilities():
    document = json.loads((ROOT / "registry" / "capabilities.json").read_text(encoding="utf-8"))
    for item in document["capabilities"]:
        if item["access"] == "write":
            item["staged_environments"] = ["sandbox"]
            item["evidence"]["level"] = "contract_tested"
    return validate_registry(document)


def _context(
    *,
    user_id: int = 42,
    company_id: int = 7,
    parameters: dict[str, object] | None = None,
    token_id: str | None = None,
    capability_id: str = "acct.invoice.customer_create.v1",
) -> RequestContext:
    bound_parameters = _invoice_parameters() if parameters is None else parameters
    return RequestContext(
        audience="odoo-accounting-cli-v3",
        auth_token_id=token_id or f"token-{user_id}-{company_id}",
        auth_issued_at=NOW - timedelta(minutes=1),
        auth_expires_at=NOW + timedelta(minutes=4),
        auth_signature_version=1,
        auth_signature_purpose="auth_context_v1",
        auth_key_id="auth-v1",
        auth_request_digest=authentication_request_digest(
            capability_id, bound_parameters
        ),
        auth_signature="b" * 64,
        principal=f"pi:sandbox-user-{user_id}",
        odoo_instance_id="odoo19@sandbox",
        database_name="codex_odoo_accounting_cli_v3_sandbox",
        database_uuid=DATABASE_UUID,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=frozenset({company_id}),
        environment="sandbox",
    )


def _invoice_parameters(idempotency_key: str = "invoice-1") -> dict[str, object]:
    return {
        "company_id": 7,
        "partner_id": 101,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15",
        "due_date": "2026-08-15",
        "currency_id": 12,
        "journal_id": 5,
        "posting_mode": "post",
        "reference": "INV-SANDBOX-1",
        "lines": [
            {
                "line_reference": "line-1",
                "name": "Consulting",
                "product_id": None,
                "account_id": 401,
                "quantity": "1",
                "price_unit": "100.00",
                "tax_ids": [],
            }
        ],
        "idempotency_key": idempotency_key,
    }


def _vendor_bill_parameters(
    idempotency_key: str = "vendor-bill-1",
) -> dict[str, object]:
    parameters = _invoice_parameters(idempotency_key)
    parameters.pop("reference")
    parameters["vendor_reference"] = "BILL-SANDBOX-1"
    return parameters


def _draft_cancel_parameters(
    idempotency_key: str = "draft-cancel-1",
    *,
    move_id: int = 501,
) -> dict[str, object]:
    return {
        "company_id": 7,
        "move_id": move_id,
        "expected_move_type": "out_invoice",
        "expected_document_binding": "a" * 64,
        "expected_business_binding": "b" * 64,
        "reason": "Cancel an explicitly bound pristine draft invoice",
        "idempotency_key": idempotency_key,
    }


def _execution_evidence(
    operation_id: str,
    *,
    capability_id: str = "acct.invoice.customer_create.v1",
    succeeded: bool = True,
    draft_customer_invoice: bool = False,
    draft_vendor_bill: bool = False,
) -> dict[str, object]:
    draft_document = draft_customer_invoice or draft_vendor_bill
    document_capability_id = (
        "acct.bill.vendor_create.v1"
        if draft_vendor_bill
        else capability_id
    )
    recovery_method = (
        "cancel_pristine_v3_draft_vendor_bill_v1"
        if draft_vendor_bill
        else "cancel_pristine_v3_draft_customer_invoice_v1"
    )
    recovery_oracle = (
        "cancel_pristine_v3_draft_vendor_bill_exact_v1"
        if draft_vendor_bill
        else "cancel_pristine_v3_draft_customer_invoice_exact_v1"
    )
    before = create_record_snapshot(
        model="account.move",
        record_id=501,
        exists=False,
        record_state="absent",
        values={},
    )
    after = create_record_snapshot(
        model="account.move",
        record_id=501,
        exists=True,
        record_state="draft" if draft_document else "posted",
        values={
            "amount_total": "100.00",
            "company_id": 7,
            "state": "draft" if draft_document else "posted",
        },
    )
    target = {
        "model": "account.move",
        "record_id": 501,
        "company_id": 7,
        "record_state": "draft" if draft_document else "posted",
        "record_fingerprint": hashlib.sha256(canonical_json(after)).hexdigest(),
    }
    guard_before = create_record_snapshot(
        model="account.move.line",
        record_id=502,
        exists=False,
        record_state="absent",
        values={},
    )
    guard_after = create_record_snapshot(
        model="account.move.line",
        record_id=502,
        exists=True,
        record_state="unknown",
        values={"company_id": 7, "move_id": 501},
    )
    guard = {
        "model": "account.move.line",
        "record_id": 502,
        "company_id": 7,
        "record_state": "unknown",
        "record_fingerprint": hashlib.sha256(
            canonical_json(guard_after)
        ).hexdigest(),
        "expected_outcome": (
            "survive_allowed_delta"
            if succeeded and draft_document
            else "survive_exact"
            if succeeded
            else "manual_review"
        ),
    }
    recovery_parameters = (
        {
            "move_id": 501,
            "module_graph_digest": TEST_MODULE_GRAPH.digest,
            "action_targets": [{"model": "account.move", "record_id": 501}],
            "guard_records": [
                {"model": "account.move.line", "record_id": 502}
            ],
            "oracle_id": (
                recovery_oracle
                if draft_document
                else "cancel_draft_move_exact_v1"
            ),
        }
        if succeeded
        else {"operation_id": operation_id}
    )
    recovery = create_recovery_plan_v2(
        origin_operation_id=operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available" if succeeded else "manual_escalation",
        method=(
            recovery_method
            if succeeded and draft_document
            else "cancel_draft_move"
            if succeeded
            else "inspect_ambiguous_execution"
        ),
        requires_approval=True,
        action_targets=[target] if succeeded else [],
        guard_records=[guard] if succeeded else [],
        oracle_id=(
            recovery_oracle
            if succeeded and draft_document
            else "cancel_draft_move_exact_v1"
            if succeeded
            else "manual_escalation"
        ),
        parameters=recovery_parameters,
    )
    return {
        "operation_id": operation_id,
        "capability_id": document_capability_id,
        "succeeded": succeeded,
        "odoo_records": [target, {key: guard[key] for key in target}] if succeeded else [],
        "difference": create_difference(
            before=[before, guard_before] if succeeded else [],
            after=[after, guard_after] if succeeded else [],
            changed_fields=["amount_total", "company_id", "move_id", "state"] if succeeded else [],
        ),
        "recovery_plan": recovery,
        "recovery_parameters": recovery_parameters,
        "module_graph": TEST_MODULE_GRAPH.evidence if succeeded else None,
        "failure_checks": [] if succeeded else ["execution_rejected_before_verified_effect"],
    }


def _verification_evidence(
    operation,
    execution_evidence: dict[str, object],
    *,
    passed: bool = True,
) -> dict[str, object]:
    fresh_snapshots = (
        copy.deepcopy(execution_evidence["difference"]["after"])
        if passed
        else []
    )
    fresh_records = (
        copy.deepcopy(execution_evidence["odoo_records"])
        if passed
        else []
    )
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "passed": passed,
        "method": "read_back_exact_move_lines_tax_preview_single_due_residual_and_content_business_bindings_v1",
        "checks": ["company_matches", "record_exists", "state_is_posted"],
        "verified_at": NOW.isoformat(),
        "readback": {
            "company_id": 7,
            "records": fresh_records,
            "fresh_snapshots": fresh_snapshots,
            "fresh_snapshots_digest": hashlib.sha256(
                canonical_json(fresh_snapshots)
            ).hexdigest(),
            "request_parameters_digest": hashlib.sha256(
                canonical_json(operation.parameters)
            ).hexdigest(),
            "control_anchor": {
                "operation_id": operation.operation_id,
                "capability_id": operation.capability_id,
                "company_id": operation.company_id,
                "state": "verified" if passed else "failed",
                "execution_evidence_digest": operation.execution_result_digest,
            },
        },
    }


def _draft_cancel_execution_evidence(operation) -> dict[str, object]:
    move_id = operation.parameters["move_id"]
    line_id = move_id + 1
    before = [
        create_record_snapshot(
            model="account.move",
            record_id=move_id,
            exists=True,
            record_state="draft",
            values={
                "company_id": operation.company_id,
                "move_type": operation.parameters["expected_move_type"],
                "state": "draft",
            },
        ),
        create_record_snapshot(
            model="account.move.line",
            record_id=line_id,
            exists=True,
            record_state="draft",
            values={
                "company_id": operation.company_id,
                "move_id": move_id,
                "parent_state": "draft",
            },
        ),
    ]
    after = [
        create_record_snapshot(
            model="account.move",
            record_id=move_id,
            exists=True,
            record_state="cancel",
            values={
                "company_id": operation.company_id,
                "move_type": operation.parameters["expected_move_type"],
                "state": "cancel",
            },
        ),
        create_record_snapshot(
            model="account.move.line",
            record_id=line_id,
            exists=True,
            record_state="cancel",
            values={
                "company_id": operation.company_id,
                "move_id": move_id,
                "parent_state": "cancel",
            },
        ),
    ]
    records = [
        {
            "model": snapshot["model"],
            "record_id": snapshot["record_id"],
            "company_id": operation.company_id,
            "record_state": snapshot["record_state"],
            "record_fingerprint": hashlib.sha256(
                canonical_json(snapshot)
            ).hexdigest(),
        }
        for snapshot in after
    ]
    recovery_parameters = {"move_id": move_id}
    recovery_plan = create_recovery_plan_v2(
        origin_operation_id=operation.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="not_applicable",
        method="not_applicable_pristine_draft_cancel_is_terminal",
        requires_approval=False,
        action_targets=[],
        guard_records=[],
        oracle_id="not_applicable",
        parameters=recovery_parameters,
    )
    return {
        "operation_id": operation.operation_id,
        "capability_id": operation.capability_id,
        "succeeded": True,
        "odoo_records": records,
        "difference": create_difference(
            before=before,
            after=after,
            changed_fields=["parent_state", "state"],
        ),
        "recovery_plan": recovery_plan,
        "recovery_parameters": recovery_parameters,
        "module_graph": TEST_MODULE_GRAPH.evidence,
        "failure_checks": [],
    }


class Backend:
    def __init__(self, *, execution_succeeds: bool = True, verification_passes: bool = True):
        self.execution_succeeds = execution_succeeds
        self.verification_passes = verification_passes
        self.calls: list[str] = []

    def precheck(self, _context, capability, operation, registry_digest, release_digest):
        self.calls.append("precheck")
        return {
            "capability_id": capability.id,
            "company_id": operation.parameters["company_id"],
            "parameters_digest": hashlib.sha256(
                canonical_json(operation.parameters)
            ).hexdigest(),
            "checks": ["acl", "company", "journal", "open_period"],
            "handler_details": {},
            "passed": True,
            "runtime_binding": {
                "user_id": operation.user_id,
                "odoo_instance_id": operation.odoo_instance_id,
                "database_name": operation.database_name,
                "database_uuid": operation.database_uuid,
                "environment": operation.environment,
                "capability_channel": "staged",
            },
            "registry_digest": registry_digest,
            "release_digest": release_digest,
        }

    def execute(self, _context, capability, operation, _approval, _registry_digest, _release_digest):
        self.calls.append("execute")
        evidence = _execution_evidence(
            operation.operation_id,
            capability_id=operation.capability_id,
            succeeded=self.execution_succeeds,
            draft_customer_invoice=(
                operation.capability_id == "acct.invoice.customer_create.v1"
                and operation.parameters.get("posting_mode") == "draft"
            ),
            draft_vendor_bill=(
                operation.capability_id == "acct.bill.vendor_create.v1"
                and operation.parameters.get("posting_mode") == "draft"
            ),
        )
        digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-write-executor",
            key_id="execution-v1",
            succeeded=self.execution_succeeds,
            evidence_digest=digest,
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)

    def verify(self, _context, capability, operation, execution_evidence, _registry_digest, _release_digest):
        self.calls.append("verify")
        assert execution_evidence["capability_id"] == capability.id
        evidence = _verification_evidence(
            operation,
            execution_evidence,
            passed=self.verification_passes,
        )
        evidence["method"] = capability.data["verification"]["method"]
        digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
        result = sign_verification_result(
            operation=operation,
            issuer="odoo-write-verifier",
            key_id="verification-v1",
            succeeded=self.verification_passes,
            evidence_digest=digest,
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)

    def execute_and_verify(
        self,
        context,
        capability,
        operation,
        approval,
        registry_digest,
        release_digest,
    ):
        execution = self.execute(
            context,
            capability,
            operation,
            approval,
            registry_digest,
            release_digest,
        )
        if not execution.result.succeeded:
            return BackendWriteOutcome(execution=execution, verification=None)
        verifying = record_execution_result(
            operation,
            execution.result,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id="execution-v1",
            allowed_issuers=frozenset({"odoo-write-executor"}),
            expected_revision=operation.revision,
        )
        verification = self.verify(
            context,
            capability,
            verifying,
            execution.evidence,
            registry_digest,
            release_digest,
        )
        return BackendWriteOutcome(
            execution=execution,
            verification=verification,
        )


class DraftCancelBackend(Backend):
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
        evidence = _draft_cancel_execution_evidence(operation)
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-write-executor",
            key_id="execution-v1",
            succeeded=True,
            evidence_digest=hashlib.sha256(canonical_json(evidence)).hexdigest(),
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)

    def verify(
        self,
        _context,
        capability,
        operation,
        execution_evidence,
        _registry_digest,
        _release_digest,
    ):
        self.calls.append("verify")
        evidence = _verification_evidence(operation, execution_evidence)
        evidence["method"] = capability.data["verification"]["method"]
        evidence["checks"] = [
            "move_state_is_cancel",
            "line_parent_state_is_cancel",
            "document_and_business_bindings_match",
        ]
        result = sign_verification_result(
            operation=operation,
            issuer="odoo-write-verifier",
            key_id="verification-v1",
            succeeded=True,
            evidence_digest=hashlib.sha256(canonical_json(evidence)).hexdigest(),
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        return BackendEvidence(result=result, evidence=evidence)


class Finalizer:
    def __init__(self) -> None:
        self.calls: list[EffectFinalizationIntent] = []
        self.requests: dict[str, EffectFinalizationRequest] = {}
        self.receipts: dict[str, EffectFinalizationReceipt] = {}
        self.error: Exception | None = None
        self.lose_first_response = False

    def __call__(
        self, intent: EffectFinalizationIntent
    ) -> EffectFinalizationReceipt:
        self.calls.append(intent)
        if self.error is not None:
            raise self.error
        request = self.requests.setdefault(
            intent.intent_digest,
            EffectFinalizationRequest.from_intent(
                intent,
                verified_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
            ),
        )
        attestation = create_effect_attestation(
            request,
            key_id="effect-finalizer-v1",
            secret=EFFECT_FINALIZER_SECRET,
        )
        replayed = request.request_digest in self.receipts
        receipt = EffectFinalizationReceipt.from_database_mapping(
            {
                "receipt_attestation_id": attestation.attestation_id,
                "receipt_guard_installation_id": GUARD_INSTALLATION_ID,
                "receipt_database_oid": 16384,
                "receipt_database_uuid": request.database_uuid,
                "resolved_operation_id": request.operation_id,
                "receipt_resolution_operation_id": request.resolution_operation_id,
                "applied_resolution_kind": request.resolution_kind,
                "resolved_anchor_count": (
                    1 if request.resolution_kind == "verified" else 2
                ),
                "remaining_unresolved_count": 0,
                "guard_epoch": 0,
                "receipt_attestation_digest": attestation.attestation_digest,
                "finalized_at": "2026-07-18T15:00:01Z",
                "finalized_txid": "9123",
                "replayed": replayed,
            },
            request=request,
            attestation=attestation,
        )
        if replayed:
            assert receipt.evidence == self.receipts[request.request_digest].evidence
        else:
            self.receipts[request.request_digest] = receipt
            if self.lose_first_response:
                raise EffectFinalizationError(
                    "simulated response loss after database finalization"
                )
        return receipt


@pytest.fixture
def service(tmp_path: Path):
    backend = Backend()
    finalizer = Finalizer()
    store = SQLitePersistence((tmp_path / "operations.sqlite3").resolve())
    security = WriteServiceSecurity(
        approval_key_id="approval-v2",
        approval_secret=APPROVAL_SECRET,
        approval_ttl_seconds=600,
        execution_key_id="execution-v1",
        execution_secret=EXECUTION_SECRET,
        execution_issuers=frozenset({"odoo-write-executor"}),
        verification_key_id="verification-v1",
        verification_secret=VERIFICATION_SECRET,
        verification_issuers=frozenset({"odoo-write-verifier"}),
        receipt_key_id="write-receipt-v1",
        receipt_secret=RECEIPT_SECRET,
    )
    value = DurableWriteService(
        _capabilities(),
        release_digest=RELEASE_DIGEST,
        store=store,
        security=security,
        authenticate_context=lambda _context: True,
        acl_check=lambda _context, _capability, _parameters: True,
        approver_authorized=lambda approver_id, company_id, _capability_id: (
            approver_id == 99 and company_id == 7
        ),
        precheck_executor=backend.precheck,
        write_executor=backend.execute,
        verification_executor=backend.verify,
        availability_channel="staged",
        now=lambda: NOW,
        effect_finalizer=finalizer,
        effect_finalizer_identity=FINALIZER_IDENTITY,
        receipt_id_factory=lambda: "write-receipt-1",
    )
    value._test_effect_finalizer = finalizer
    return value, backend, store


def _prepare_and_preview(
    service: DurableWriteService,
    *,
    parameters: dict[str, object] | None = None,
):
    parameters = _invoice_parameters() if parameters is None else parameters
    operation = service.prepare(
        _context(parameters=parameters, token_id="token-prepare-invoice-1"),
        operation_id="op-invoice-1",
        request_id="request-invoice-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters=parameters,
    )
    assert operation.state == State.PREPARED
    preview = service.preview(
        _context(parameters=parameters, token_id="token-preview-invoice-1"),
        operation.operation_id,
    )
    assert preview["operation_state"] == State.AWAITING_APPROVAL
    return service.status(
        _context(parameters=parameters), operation.operation_id
    )


def _approval(awaiting, nonce: str):
    return sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce=nonce,
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )


def _accept(store: SQLitePersistence, approval):
    return store.accept_approval(
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda approver_id, company_id, _capability_id: (
            approver_id == 99 and company_id == 7
        ),
        approval_ttl_seconds=600,
        expected_revision=approval.operation_revision,
    ).operation


def _begin(store: SQLitePersistence, approval, approved):
    return store.begin_execution(
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="approval-v2",
        is_approver_authorized=lambda approver_id, company_id, _capability_id: (
            approver_id == 99 and company_id == 7
        ),
        approval_ttl_seconds=600,
        expected_revision=approved.revision,
    ).operation


def _clone_service(
    original: DurableWriteService,
    backend: Backend,
    store: SQLitePersistence,
    *,
    release_digest: str = RELEASE_DIGEST,
    availability_channel: str = "staged",
    acl_allowed: bool = True,
    approver_allowed: bool = True,
) -> DurableWriteService:
    return DurableWriteService(
        tuple(original._capabilities.values()),
        release_digest=release_digest,
        store=store,
        security=original._security,
        authenticate_context=lambda _context: True,
        acl_check=lambda _context, _capability, _parameters: acl_allowed,
        approver_authorized=lambda approver_id, company_id, _capability_id: (
            approver_allowed and approver_id == 99 and company_id == 7
        ),
        precheck_executor=backend.precheck,
        write_executor=backend.execute,
        verification_executor=backend.verify,
        availability_channel=availability_channel,
        now=lambda: NOW,
        effect_finalizer=original._effect_finalizer,
        effect_finalizer_identity=original._effect_finalizer_identity,
    )


def _draft_cancel_service(service):
    original, _original_backend, store = service
    backend = DraftCancelBackend()
    return (
        _clone_service(original, backend, store),
        backend,
        store,
        original._test_effect_finalizer,
    )


def _prepare_draft_cancel(
    gateway: DurableWriteService,
    parameters: dict[str, object],
    *,
    suffix: str,
):
    capability_id = "acct.move.draft_cancel.v1"
    prepared = gateway.prepare(
        _context(
            parameters=parameters,
            token_id=f"token-draft-cancel-{suffix}-prepare",
            capability_id=capability_id,
        ),
        operation_id=f"op-draft-cancel-{suffix}",
        request_id=f"request-draft-cancel-{suffix}",
        capability_id=capability_id,
        parameters=parameters,
    )
    preview = gateway.preview(
        _context(
            parameters=parameters,
            token_id=f"token-draft-cancel-{suffix}-preview",
            capability_id=capability_id,
        ),
        prepared.operation_id,
    )
    awaiting = gateway.status(
        _context(parameters=parameters, capability_id=capability_id),
        prepared.operation_id,
    )
    return prepared, preview, awaiting


def test_prepare_preview_persists_every_preapproval_state_and_full_parameters(service):
    gateway, backend, store = service

    awaiting = _prepare_and_preview(gateway)

    assert awaiting.parameters == _invoice_parameters()
    assert awaiting.revision == 2
    assert backend.calls == ["precheck"]
    assert [event.event_type for event in store.audit_events()] == [
        "operation.prechecked",
        "operation.awaiting_approval",
    ]


def test_duplicate_request_returns_original_operation_and_changed_content_is_rejected(service):
    gateway, _backend, _store = service
    first = gateway.prepare(
        _context(parameters=_invoice_parameters("same"), token_id="token-one"),
        operation_id="op-one", request_id="request-one",
        capability_id="acct.invoice.customer_create.v1", parameters=_invoice_parameters("same"),
    )
    duplicate = gateway.prepare(
        _context(parameters=_invoice_parameters("same"), token_id="token-two"),
        operation_id="op-two", request_id="request-two",
        capability_id="acct.invoice.customer_create.v1", parameters=copy.deepcopy(_invoice_parameters("same")),
    )
    assert duplicate.operation_id == first.operation_id

    changed = _invoice_parameters("same")
    changed["partner_id"] = 102
    with pytest.raises(Exception, match="different request content"):
        gateway.prepare(
            _context(parameters=changed, token_id="token-three"),
            operation_id="op-three", request_id="request-three",
            capability_id="acct.invoice.customer_create.v1", parameters=changed,
        )


def test_recovery_capability_cannot_be_prepared_from_user_supplied_parameters(service):
    gateway, _backend, store = service
    parameters = {
        "company_id": 7,
        "origin_operation_id": "origin-user-supplied",
        "expected_recovery_plan_digest": "f" * 64,
        "recovery_date": "2026-07-16",
        "reason": "Attempt to bypass the verified origin receipt",
        "idempotency_key": "forged-recovery",
    }

    with pytest.raises(WriteServiceError, match="verified origin receipt"):
        gateway.prepare(
            _context(parameters=parameters, token_id="token-forged-recovery"),
            operation_id="op-forged-recovery",
            request_id="request-forged-recovery",
            capability_id="acct.recovery.execute.v1",
            parameters=parameters,
        )

    with pytest.raises(Exception, match="does not exist"):
        store.get_operation("op-forged-recovery")


def test_authenticated_content_mismatch_and_replayed_mutation_token_are_rejected(service):
    gateway, backend, _store = service
    parameters = _invoice_parameters("auth-binding")
    different = copy.deepcopy(parameters)
    different["partner_id"] = 999

    with pytest.raises(WriteServiceError, match="authenticated request digest"):
        gateway.prepare(
            _context(parameters=different, token_id="token-wrong-content"),
            operation_id="op-auth-wrong",
            request_id="request-auth-wrong",
            capability_id="acct.invoice.customer_create.v1",
            parameters=parameters,
        )

    operation = gateway.prepare(
        _context(parameters=parameters, token_id="token-auth-prepare"),
        operation_id="op-auth-bound",
        request_id="request-auth-bound",
        capability_id="acct.invoice.customer_create.v1",
        parameters=parameters,
    )
    preview_context = _context(
        parameters=parameters, token_id="token-auth-preview-once"
    )
    gateway.preview(preview_context, operation.operation_id)
    with pytest.raises(ReplayRejected, match="already consumed"):
        gateway.preview(preview_context, operation.operation_id)
    assert backend.calls == ["precheck"]


def test_v2_write_authenticator_binds_status_to_the_exact_action_and_request(service):
    gateway, _backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    status_request = {"operation_id": awaiting.operation_id}
    status_context = sign_write_action_context(
        auth_token_id="token-v2-status",
        principal=awaiting.principal,
        odoo_instance_id=awaiting.odoo_instance_id,
        database_name=awaiting.database_name,
        database_uuid=awaiting.database_uuid,
        user_id=awaiting.user_id,
        company_id=awaiting.company_id,
        allowed_company_ids=frozenset({awaiting.company_id}),
        environment=awaiting.environment,
        action="operation.status",
        request=status_request,
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=4),
        key_id="write-auth-v2",
        secret=APPROVAL_SECRET,
    )
    gateway._authenticate_context = lambda context: verify_write_action_context(
        context,
        action="operation.status",
        request=status_request,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="write-auth-v2",
    )
    gateway._policy._authenticate_context = gateway._authenticate_context

    assert gateway.status(status_context, awaiting.operation_id) == awaiting

    preview_context = sign_write_action_context(
        auth_token_id="token-v2-preview",
        principal=awaiting.principal,
        odoo_instance_id=awaiting.odoo_instance_id,
        database_name=awaiting.database_name,
        database_uuid=awaiting.database_uuid,
        user_id=awaiting.user_id,
        company_id=awaiting.company_id,
        allowed_company_ids=frozenset({awaiting.company_id}),
        environment=awaiting.environment,
        action="operation.preview",
        request=status_request,
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=4),
        key_id="write-auth-v2",
        secret=APPROVAL_SECRET,
    )
    with pytest.raises(Exception, match="digest"):
        gateway.status(preview_context, awaiting.operation_id)


def test_approve_execute_verifies_and_returns_schema_valid_signed_receipt(service):
    gateway, backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="approval-nonce-1",
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )

    output = gateway.approve_execute(
        _context(), approval, reconciliation_only=False
    )

    assert output["operation_state"] == "completed"
    assert output["verification"]["passed"] is True
    assert output["odoo_records"][0]["model"] == "account.move"
    assert output["audit_receipt"]["operation_id"] == awaiting.operation_id
    assert gateway.status(_context(), awaiting.operation_id).state == State.COMPLETED
    assert backend.calls == ["precheck", "precheck", "execute", "verify"]
    assert [record.kind for record in store.get_trusted_result_records(awaiting.operation_id)] == [
        "execution",
        "verification",
    ]
    finalizer = gateway._test_effect_finalizer
    assert len(finalizer.calls) == 1
    intent = finalizer.calls[0]
    assert intent.operation_id == awaiting.operation_id
    assert intent.database_uuid == DATABASE_UUID
    assert intent.resolution_kind == "verified"
    request = finalizer.requests[intent.intent_digest]
    durable = store.get_final_write_receipts(awaiting.operation_id)[0]
    assert durable.body["receipt_details"]["database_finalization"] == (
        finalizer.receipts[request.request_digest].evidence
    )
    assert output["database_finalization"] == (
        durable.body["receipt_details"]["database_finalization"]
    )
    assert gateway.result(_context(), awaiting.operation_id) == output


def test_success_order_is_hmac_validation_then_database_finalizer_then_sqlite_completion(
    service, monkeypatch: pytest.MonkeyPatch
):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(gateway)
    order: list[str] = []
    trusted = gateway._verify_terminal_trusted_results
    complete = store.complete_operation
    finalizer = gateway._test_effect_finalizer
    finalize = gateway._effect_finalizer

    def record_trusted(*args, **kwargs):
        order.append("trusted_hmac")
        return trusted(*args, **kwargs)

    def record_finalize(request):
        order.append("database_finalizer")
        return finalize(request)

    def record_complete(*args, **kwargs):
        order.append("sqlite_complete")
        return complete(*args, **kwargs)

    monkeypatch.setattr(gateway, "_verify_terminal_trusted_results", record_trusted)
    monkeypatch.setattr(gateway, "_effect_finalizer", record_finalize)
    monkeypatch.setattr(store, "complete_operation", record_complete)

    output = gateway.approve_execute(
        _context(token_id="token-effect-order"),
        _approval(awaiting, "approval-effect-order"),
        reconciliation_only=False,
    )

    assert output["operation_state"] == "completed"
    assert order == ["trusted_hmac", "database_finalizer", "sqlite_complete"]
    assert len(finalizer.calls) == 1


def test_finalizer_failure_leaves_verifying_without_success_or_final_receipt(service):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(gateway)
    finalizer = gateway._test_effect_finalizer
    finalizer.error = EffectFinalizationError("simulated finalizer failure")

    with pytest.raises(WriteServiceError, match="database effect finalization"):
        gateway.approve_execute(
            _context(token_id="token-effect-failure"),
            _approval(awaiting, "approval-effect-failure"),
            reconciliation_only=False,
        )

    assert gateway.status(_context(), awaiting.operation_id).state == State.VERIFYING
    assert store.get_final_write_receipts(awaiting.operation_id) == ()
    assert len(finalizer.calls) == 1


def test_response_loss_replays_same_database_proof_before_one_local_completion(service):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-effect-replay")
    finalizer = gateway._test_effect_finalizer
    finalizer.lose_first_response = True

    with pytest.raises(WriteServiceError, match="database effect finalization"):
        gateway.approve_execute(
            _context(token_id="token-effect-first"),
            approval,
            reconciliation_only=False,
        )
    assert gateway.status(_context(), awaiting.operation_id).state == State.VERIFYING
    assert store.get_final_write_receipts(awaiting.operation_id) == ()

    output = gateway.approve_execute(
        _context(token_id="token-effect-reconcile"),
        approval,
        reconciliation_only=True,
    )

    assert output["operation_state"] == "completed"
    assert len(finalizer.calls) == 2
    assert finalizer.calls[0] == finalizer.calls[1]
    assert len(store.get_final_write_receipts(awaiting.operation_id)) == 1


def test_draft_cancel_runs_the_full_write_lifecycle_and_replays_without_duplicates(
    service,
):
    gateway, backend, store, finalizer = _draft_cancel_service(service)
    parameters = _draft_cancel_parameters()
    capability_id = "acct.move.draft_cancel.v1"

    prepared, preview, awaiting = _prepare_draft_cancel(
        gateway, parameters, suffix="lifecycle"
    )

    assert prepared.state == State.PREPARED
    assert preview["operation_state"] == State.AWAITING_APPROVAL
    assert awaiting.state == State.AWAITING_APPROVAL
    approval = _approval(awaiting, "approval-draft-cancel-lifecycle")
    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-draft-cancel-lifecycle-execute",
            capability_id=capability_id,
        ),
        approval,
        reconciliation_only=False,
    )

    assert output["operation_state"] == "completed"
    assert output["verification"]["passed"] is True
    assert output["verification"]["method"] == (
        gateway._capabilities[capability_id].data["verification"]["method"]
    )
    assert output["recovery_plan"]["status"] == "not_applicable"
    assert gateway.status(
        _context(parameters=parameters, capability_id=capability_id),
        awaiting.operation_id,
    ).state == State.COMPLETED
    assert backend.calls == ["precheck", "precheck", "execute", "verify"]
    assert [
        event.event_type
        for event in store.audit_events()
        if event.operation_id == awaiting.operation_id
    ] == [
        "operation.prechecked",
        "operation.awaiting_approval",
        "operation.approved",
        "operation.executing",
        "operation.verifying",
        "operation.completed",
    ]
    assert [
        record.kind
        for record in store.get_trusted_result_records(awaiting.operation_id)
    ] == ["execution", "verification"]

    assert len(finalizer.calls) == 1
    intent = finalizer.calls[0]
    assert intent.operation_id == awaiting.operation_id
    assert intent.resolution_operation_id == awaiting.operation_id
    assert intent.operation_digest == awaiting.digest
    assert intent.resolution_operation_digest == awaiting.digest
    assert intent.resolution_kind == "verified"
    assert output["database_finalization"]["resolved_anchor_count"] == 1
    assert output["database_finalization"]["operation_id"] == awaiting.operation_id
    assert (
        output["database_finalization"]["resolution_operation_id"]
        == awaiting.operation_id
    )
    assert len(store.get_final_write_receipts(awaiting.operation_id)) == 1
    assert gateway.result(
        _context(parameters=parameters, capability_id=capability_id),
        awaiting.operation_id,
    ) == output

    duplicate = gateway.prepare(
        _context(
            parameters=parameters,
            token_id="token-draft-cancel-lifecycle-prepare-replay",
            capability_id=capability_id,
        ),
        operation_id="op-draft-cancel-lifecycle-replay",
        request_id="request-draft-cancel-lifecycle-replay",
        capability_id=capability_id,
        parameters=copy.deepcopy(parameters),
    )
    assert duplicate.operation_id == awaiting.operation_id
    replay = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-draft-cancel-lifecycle-result-replay",
            capability_id=capability_id,
        ),
        approval,
        reconciliation_only=True,
    )
    assert replay == output
    assert backend.calls == ["precheck", "precheck", "execute", "verify"]
    assert len(finalizer.calls) == 1
    assert len(finalizer.receipts) == 1
    assert len(store.get_final_write_receipts(awaiting.operation_id)) == 1


def test_draft_cancel_same_move_rejects_changed_content_and_idempotency_key(service):
    gateway, _backend, _store, _finalizer = _draft_cancel_service(service)
    capability_id = "acct.move.draft_cancel.v1"
    parameters = _draft_cancel_parameters("draft-cancel-scope")
    first = gateway.prepare(
        _context(
            parameters=parameters,
            token_id="token-draft-cancel-scope-first",
            capability_id=capability_id,
        ),
        operation_id="op-draft-cancel-scope-first",
        request_id="request-draft-cancel-scope-first",
        capability_id=capability_id,
        parameters=parameters,
    )
    assert first.state == State.PREPARED

    changed_content = {**parameters, "reason": "A different cancellation reason"}
    with pytest.raises(
        IdempotencyConflict, match="different request content"
    ):
        gateway.prepare(
            _context(
                parameters=changed_content,
                token_id="token-draft-cancel-scope-changed-content",
                capability_id=capability_id,
            ),
            operation_id="op-draft-cancel-scope-changed-content",
            request_id="request-draft-cancel-scope-changed-content",
            capability_id=capability_id,
            parameters=changed_content,
        )

    changed_key = {**parameters, "idempotency_key": "draft-cancel-other-key"}
    with pytest.raises(
        IdempotencyConflict, match="different request content"
    ):
        gateway.prepare(
            _context(
                parameters=changed_key,
                token_id="token-draft-cancel-scope-changed-key",
                capability_id=capability_id,
            ),
            operation_id="op-draft-cancel-scope-changed-key",
            request_id="request-draft-cancel-scope-changed-key",
            capability_id=capability_id,
            parameters=changed_key,
        )


def test_draft_cancel_finalizer_response_loss_replays_one_verified_anchor(service):
    gateway, backend, store, finalizer = _draft_cancel_service(service)
    parameters = _draft_cancel_parameters("draft-cancel-response-loss")
    capability_id = "acct.move.draft_cancel.v1"
    _prepared, _preview, awaiting = _prepare_draft_cancel(
        gateway, parameters, suffix="response-loss"
    )
    approval = _approval(awaiting, "approval-draft-cancel-response-loss")
    finalizer.lose_first_response = True

    with pytest.raises(WriteServiceError, match="database effect finalization"):
        gateway.approve_execute(
            _context(
                parameters=parameters,
                token_id="token-draft-cancel-response-loss-first",
                capability_id=capability_id,
            ),
            approval,
            reconciliation_only=False,
        )

    assert gateway.status(
        _context(parameters=parameters, capability_id=capability_id),
        awaiting.operation_id,
    ).state == State.VERIFYING
    assert store.get_final_write_receipts(awaiting.operation_id) == ()
    assert len(finalizer.calls) == 1
    assert len(finalizer.requests) == 1
    assert len(finalizer.receipts) == 1

    output = gateway.approve_execute(
        _context(
            parameters=parameters,
            token_id="token-draft-cancel-response-loss-replay",
            capability_id=capability_id,
        ),
        approval,
        reconciliation_only=True,
    )

    assert output["operation_state"] == "completed"
    assert output["database_finalization"]["resolution_kind"] == "verified"
    assert output["database_finalization"]["resolved_anchor_count"] == 1
    assert len(finalizer.calls) == 2
    assert finalizer.calls[0] == finalizer.calls[1]
    assert len(finalizer.requests) == 1
    assert len(finalizer.receipts) == 1
    assert backend.calls.count("execute") == 1
    assert len(store.get_final_write_receipts(awaiting.operation_id)) == 1
    assert gateway.result(
        _context(parameters=parameters, capability_id=capability_id),
        awaiting.operation_id,
    ) == output


def test_terminal_result_reverifies_stored_trusted_result_hmac(service, monkeypatch):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(gateway)
    output = gateway.approve_execute(
        _context(token_id="token-hmac-complete"),
        _approval(awaiting, "approval-hmac-complete"),
        reconciliation_only=False,
    )
    records = store.get_trusted_result_records(awaiting.operation_id)
    forged = tuple(
        replace(record, signature="f" * 64)
        if record.kind == "execution"
        else record
        for record in records
    )
    monkeypatch.setattr(store, "get_trusted_result_records", lambda _operation_id: forged)

    with pytest.raises(WriteServiceError, match="signature"):
        gateway.result(_context(), awaiting.operation_id)
    assert output["operation_state"] == "completed"


def test_terminal_receipt_uses_pinned_precheck_channel_after_runtime_promotion(service):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(gateway)
    output = gateway.approve_execute(
        _context(token_id="token-channel-complete"),
        _approval(awaiting, "approval-channel-complete"),
        reconciliation_only=False,
    )
    promoted_backend = Backend()
    promoted = _clone_service(
        gateway,
        promoted_backend,
        store,
        availability_channel="enabled",
    )

    replay = promoted.result(_context(), awaiting.operation_id)

    assert replay == output
    assert replay["audit_receipt"]["capability_channel"] == "staged"


def test_different_release_cannot_execute_or_resign_existing_operation(service):
    gateway, backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-cross-release")
    other_backend = Backend()
    other_release = _clone_service(
        gateway,
        other_backend,
        store,
        release_digest="e" * 64,
    )

    with pytest.raises(WriteServiceError, match="historical_release_required"):
        other_release.approve_execute(
            _context(token_id="token-cross-release-execute"),
            approval,
            reconciliation_only=False,
        )
    assert other_backend.calls == []

    output = gateway.approve_execute(
        _context(token_id="token-original-release-execute"),
        approval,
        reconciliation_only=False,
    )
    with pytest.raises(WriteServiceError, match="historical_release_required"):
        other_release.result(_context(), awaiting.operation_id)
    assert output["operation_state"] == "completed"
    assert backend.calls == ["precheck", "precheck", "execute", "verify"]


def test_executing_replay_uses_historical_acl_but_new_execution_does_not(service):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-revoked-after-start")
    approved = _accept(store, approval)
    _begin(store, approval, approved)
    replay_backend = Backend()
    revoked = _clone_service(
        gateway,
        replay_backend,
        store,
        acl_allowed=False,
        approver_allowed=False,
    )

    output = revoked.approve_execute(
        _context(token_id="token-revoked-replay"),
        approval,
        reconciliation_only=False,
    )

    assert output["operation_state"] == "completed"
    assert replay_backend.calls == ["execute", "verify"]


def test_executing_replay_uses_pinned_channel_after_runtime_promotion(service):
    gateway, _backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-promoted-after-start")
    approved = _accept(store, approval)
    _begin(store, approval, approved)
    replay_backend = Backend()
    promoted = _clone_service(
        gateway,
        replay_backend,
        store,
        availability_channel="enabled",
    )

    output = promoted.approve_execute(
        _context(token_id="token-promoted-replay"),
        approval,
        reconciliation_only=False,
    )

    assert output["operation_state"] == "completed"
    assert output["audit_receipt"]["capability_channel"] == "staged"
    assert replay_backend.calls == ["execute", "verify"]


def test_crash_after_approval_resumes_from_durable_approved_state(service):
    gateway, backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-resume-approved")
    approved = _accept(store, approval)
    assert approved.state == State.APPROVED

    output = gateway.approve_execute(
        _context(token_id="token-resume-approved"),
        approval,
        reconciliation_only=False,
    )

    assert output["operation_state"] == "completed"
    assert backend.calls == ["precheck", "precheck", "execute", "verify"]
    assert gateway.status(_context(), awaiting.operation_id).state == State.COMPLETED


def test_crash_after_begin_execution_replays_executing_state_without_new_precheck(service):
    gateway, backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-resume-executing")
    approved = _accept(store, approval)
    executing = _begin(store, approval, approved)
    assert executing.state == State.EXECUTING

    output = gateway.approve_execute(
        _context(token_id="token-resume-executing"),
        approval,
        reconciliation_only=False,
    )

    assert output["operation_state"] == "completed"
    assert backend.calls == ["precheck", "execute", "verify"]


def test_expired_executing_operation_requires_reconciliation_only_authority(service):
    gateway, backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-expired-executing")
    approved = _accept(store, approval)
    _begin(store, approval, approved)
    backend.calls.clear()
    gateway._now = lambda: approval.expires_at

    with pytest.raises(WriteServiceError, match="requires reconciliation-only"):
        gateway.approve_execute(
            _context(token_id="token-expired-executing-wrong-mode"),
            approval,
            reconciliation_only=False,
        )
    assert backend.calls == []

    reconciliation_context = replace(
        _context(token_id="token-expired-executing-reconcile"),
        auth_issued_at=approval.expires_at - timedelta(seconds=10),
        auth_expires_at=approval.expires_at + timedelta(minutes=4),
    )

    def anchor_unknown(*_args):
        backend.calls.append("reconcile")
        raise RuntimeError("durable anchor is not observable")

    gateway._write_executor = anchor_unknown
    with pytest.raises(RuntimeError, match="not observable"):
        gateway.approve_execute(
            reconciliation_context,
            approval,
            reconciliation_only=True,
        )
    assert backend.calls == ["reconcile"]
    assert gateway.status(_context(), awaiting.operation_id).state == State.EXECUTING


def test_crash_after_execution_result_resumes_verification_without_reexecuting_business_write(
    service,
):
    gateway, backend, store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-resume-verifying")
    approved = _accept(store, approval)
    executing = _begin(store, approval, approved)
    capability = gateway._capabilities[executing.capability_id]
    execution = backend.execute(
        _context(),
        capability,
        executing,
        approval,
        gateway._registry_digest,
        gateway._release_digest,
    )
    verifying = store.record_execution_result(
        execution.result,
        evidence=execution.evidence,
        now=NOW,
        secret=EXECUTION_SECRET,
        expected_key_id="execution-v1",
        allowed_issuers=frozenset({"odoo-write-executor"}),
        expected_revision=executing.revision,
    ).operation
    assert verifying.state == State.VERIFYING
    backend.calls.clear()

    with pytest.raises(WriteServiceError, match="requires reconciliation-only"):
        gateway.approve_execute(
            _context(token_id="token-resume-verifying-wrong-mode"),
            approval,
            reconciliation_only=False,
        )
    assert backend.calls == []

    output = gateway.approve_execute(
        _context(token_id="token-resume-verifying"),
        approval,
        reconciliation_only=True,
    )

    assert output["operation_state"] == "completed"
    assert backend.calls == ["verify"]


def test_combined_odoo_invocation_replays_anchor_after_execution_persistence(service):
    gateway, backend, store = service
    gateway._execute_and_verify = backend.execute_and_verify
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-combined-replay")
    approved = _accept(store, approval)
    executing = _begin(store, approval, approved)
    capability = gateway._capabilities[executing.capability_id]
    first = backend.execute(
        _context(),
        capability,
        executing,
        approval,
        gateway._registry_digest,
        gateway._release_digest,
    )
    store.record_execution_result(
        first.result,
        evidence=first.evidence,
        now=NOW,
        secret=EXECUTION_SECRET,
        expected_key_id="execution-v1",
        allowed_issuers=frozenset({"odoo-write-executor"}),
        expected_revision=executing.revision,
    )
    backend.calls.clear()

    output = gateway.approve_execute(
        _context(token_id="token-combined-replay"),
        approval,
        reconciliation_only=True,
    )

    assert output["operation_state"] == "completed"
    assert backend.calls == ["execute", "verify"]
    terminal_context = _context(token_id="token-terminal-replay")
    replay = gateway.approve_execute(
        terminal_context,
        approval,
        reconciliation_only=True,
    )
    assert replay == output
    assert backend.calls == ["execute", "verify"]
    with pytest.raises(Exception, match="already consumed"):
        gateway.approve_execute(
            terminal_context,
            approval,
            reconciliation_only=True,
        )
    fresh_replay = gateway.approve_execute(
        _context(token_id="token-terminal-replay-fresh"),
        approval,
        reconciliation_only=True,
    )
    assert fresh_replay == output
    assert backend.calls == ["execute", "verify"]


def test_recovery_is_a_new_operation_derived_from_a_failed_verification_receipt(service):
    gateway, backend, store = service
    backend.verification_passes = False
    draft_parameters = {**_invoice_parameters(), "posting_mode": "draft"}
    awaiting = _prepare_and_preview(gateway, parameters=draft_parameters)
    approval = _approval(awaiting, "approval-origin-for-recovery")
    gateway.approve_execute(
        _context(parameters=draft_parameters),
        approval,
        reconciliation_only=False,
    )
    backend.verification_passes = True
    origin = gateway.status(
        _context(parameters=draft_parameters), awaiting.operation_id
    )
    assert origin.state == State.FAILED
    recovery_request = {
        "origin_operation_id": origin.operation_id,
        "expected_origin_revision": origin.revision,
        "recovery_operation_id": "op-invoice-1-recovery",
        "request_id": "request-invoice-1-recovery",
        "recovery_date": "2026-07-16",
        "reason": "Reverse the duplicate sandbox invoice",
        "idempotency_key": "recover-op-invoice-1",
    }

    def recovery_context(token_id):
        return sign_write_action_context(
            auth_token_id=token_id,
            principal=origin.principal,
            odoo_instance_id=origin.odoo_instance_id,
            database_name=origin.database_name,
            database_uuid=origin.database_uuid,
            user_id=origin.user_id,
            company_id=origin.company_id,
            allowed_company_ids=frozenset({origin.company_id}),
            environment=origin.environment,
            action="operation.recover",
            request=recovery_request,
            issued_at=NOW - timedelta(seconds=10),
            expires_at=NOW + timedelta(minutes=4),
            key_id="write-auth-v2",
            secret=APPROVAL_SECRET,
        )

    def authenticate(context):
        return verify_write_action_context(
            context,
            action="operation.recover",
            request=recovery_request,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id="write-auth-v2",
        )

    gateway._authenticate_context = authenticate
    gateway._policy._authenticate_context = authenticate
    prepared = gateway.prepare_recovery(
        recovery_context("token-recovery-prepare"), **recovery_request
    )
    recovery = prepared["operation"]
    binding = store.get_recovery_operation_binding(recovery.operation_id)

    assert recovery.state == State.PREPARED
    assert recovery.capability_id == "acct.recovery.execute.v1"
    assert recovery.parameters == {
        "company_id": 7,
        "origin_operation_id": origin.operation_id,
        "expected_recovery_plan_digest": prepared["recovery_plan_digest"],
        "recovery_date": "2026-07-16",
        "reason": "Reverse the duplicate sandbox invoice",
        "idempotency_key": "recover-op-invoice-1",
    }
    assert prepared["next_action"] == "operation.preview"
    assert binding.origin_operation_id == origin.operation_id
    assert binding.origin_operation_revision == origin.revision
    assert binding.recovery_operation_digest == recovery.digest
    assert binding.plan_digest == prepared["recovery_plan_digest"]
    trusted = gateway.trusted_recovery_plan(
        recovery_context("token-recovery-read-plan"), recovery
    )
    assert trusted["plan_digest"] == recovery.parameters[
        "expected_recovery_plan_digest"
    ]
    assert trusted["origin_operation_id"] == origin.operation_id

    replayed = gateway.prepare_recovery(
        recovery_context("token-recovery-idempotent-replay"), **recovery_request
    )
    assert replayed["operation"] == recovery
    assert store.get_recovery_operation_binding(recovery.operation_id) == binding

    changed_revision = {**recovery_request, "expected_origin_revision": origin.revision - 1}
    changed_context = sign_write_action_context(
        auth_token_id="token-recovery-stale",
        principal=origin.principal,
        odoo_instance_id=origin.odoo_instance_id,
        database_name=origin.database_name,
        database_uuid=origin.database_uuid,
        user_id=origin.user_id,
        company_id=origin.company_id,
        allowed_company_ids=frozenset({origin.company_id}),
        environment=origin.environment,
        action="operation.recover",
        request=changed_revision,
        issued_at=NOW - timedelta(seconds=10),
        expires_at=NOW + timedelta(minutes=4),
        key_id="write-auth-v2",
        secret=APPROVAL_SECRET,
    )
    gateway._authenticate_context = lambda context: verify_write_action_context(
        context,
        action="operation.recover",
        request=changed_revision,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id="write-auth-v2",
    )
    gateway._policy._authenticate_context = gateway._authenticate_context
    with pytest.raises(WriteServiceError, match="revision changed"):
        gateway.prepare_recovery(changed_context, **changed_revision)


def test_origin_recovery_rejects_a_plan_not_bound_to_the_requested_digest(service, monkeypatch):
    gateway, backend, _store = service
    backend.verification_passes = False
    draft_parameters = {**_invoice_parameters(), "posting_mode": "draft"}
    awaiting = _prepare_and_preview(gateway, parameters=draft_parameters)
    approval = _approval(awaiting, "approval-forged-line-outcome")
    gateway.approve_execute(
        _context(parameters=draft_parameters),
        approval,
        reconciliation_only=False,
    )
    backend.verification_passes = True
    origin = gateway.status(
        _context(parameters=draft_parameters), awaiting.operation_id
    )
    origin_result = gateway.result(
        _context(parameters=draft_parameters), origin.operation_id
    )
    original_plan = origin_result["recovery_plan"]
    forged_plan = create_recovery_plan_v2(
        origin_operation_id=origin.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="cancel_pristine_v3_draft_customer_invoice_v1",
        requires_approval=True,
        action_targets=original_plan["action_targets"],
        guard_records=[
            {**guard, "expected_outcome": "survive_exact"}
            for guard in original_plan["guard_records"]
        ],
        oracle_id="cancel_pristine_v3_draft_customer_invoice_exact_v1",
        parameters={"origin_operation_id": origin.operation_id},
    )
    monkeypatch.setattr(
        gateway,
        "result",
        lambda *_args: {**origin_result, "recovery_plan": forged_plan},
    )

    with pytest.raises(
        WriteServiceError,
        match="unavailable or outside the bound company",
    ):
        gateway._validated_origin_recovery_plan(
            _context(parameters=draft_parameters),
            origin,
            expected_plan_digest=original_plan["plan_digest"],
        )


def test_vendor_bill_recovery_has_its_own_approval_and_idempotency_operation(
    service,
):
    gateway, backend, store = service
    backend.verification_passes = False
    bill_parameters = {
        **_vendor_bill_parameters(),
        "posting_mode": "draft",
    }
    origin = gateway.prepare(
        _context(
            parameters=bill_parameters,
            token_id="token-prepare-bill",
            capability_id="acct.bill.vendor_create.v1",
        ),
        operation_id="op-vendor-bill-1",
        request_id="request-vendor-bill-1",
        capability_id="acct.bill.vendor_create.v1",
        parameters=bill_parameters,
    )
    gateway.preview(
        _context(
            parameters=bill_parameters,
            token_id="token-preview-bill",
            capability_id="acct.bill.vendor_create.v1",
        ),
        origin.operation_id,
    )
    awaiting = gateway.status(
        _context(
            parameters=bill_parameters,
            capability_id="acct.bill.vendor_create.v1",
        ),
        origin.operation_id,
    )
    origin_approval = _approval(awaiting, "approval-origin-vendor-bill")
    gateway.approve_execute(
        _context(
            parameters=bill_parameters,
            token_id="token-execute-bill",
            capability_id="acct.bill.vendor_create.v1",
        ),
        origin_approval,
        reconciliation_only=False,
    )
    backend.verification_passes = True
    origin = gateway.status(
        _context(
            parameters=bill_parameters,
            capability_id="acct.bill.vendor_create.v1",
        ),
        origin.operation_id,
    )
    origin_result = gateway.result(
        _context(
            parameters=bill_parameters,
            capability_id="acct.bill.vendor_create.v1",
        ),
        origin.operation_id,
    )
    assert origin_result["recovery_plan"]["method"] == (
        "cancel_pristine_v3_draft_vendor_bill_v1"
    )

    request = {
        "origin_operation_id": origin.operation_id,
        "expected_origin_revision": origin.revision,
        "recovery_operation_id": "op-vendor-bill-1-recovery",
        "request_id": "request-vendor-bill-1-recovery",
        "recovery_date": "2026-07-16",
        "reason": "Cancel the duplicate sandbox vendor bill",
        "idempotency_key": "recover-op-vendor-bill-1",
    }

    def recovery_context(token_id):
        return sign_write_action_context(
            auth_token_id=token_id,
            principal=origin.principal,
            odoo_instance_id=origin.odoo_instance_id,
            database_name=origin.database_name,
            database_uuid=origin.database_uuid,
            user_id=origin.user_id,
            company_id=origin.company_id,
            allowed_company_ids=frozenset({origin.company_id}),
            environment=origin.environment,
            action="operation.recover",
            request=request,
            issued_at=NOW - timedelta(seconds=10),
            expires_at=NOW + timedelta(minutes=4),
            key_id="write-auth-v2",
            secret=APPROVAL_SECRET,
        )

    prepared = gateway.prepare_recovery(
        recovery_context("token-prepare-vendor-bill-recovery"), **request
    )
    recovery = prepared["operation"]
    binding = store.get_recovery_operation_binding(recovery.operation_id)

    assert recovery.capability_id == "acct.recovery.execute.v1"
    assert recovery.operation_id != origin.operation_id
    assert recovery.idempotency_key == "recover-op-vendor-bill-1"
    assert binding.origin_operation_id == origin.operation_id
    assert binding.recovery_operation_digest == recovery.digest
    assert gateway.prepare_recovery(
        recovery_context("token-replay-vendor-bill-recovery"), **request
    )["operation"] == recovery

    gateway.preview(
        recovery_context("token-preview-vendor-bill-recovery"),
        recovery.operation_id,
    )
    awaiting_recovery = gateway.status(
        recovery_context("token-status-vendor-bill-recovery"),
        recovery.operation_id,
    )
    recovery_approval = _approval(
        awaiting_recovery, "approval-independent-vendor-bill-recovery"
    )
    assert recovery_approval.operation_id == recovery.operation_id
    assert recovery_approval.operation_digest == awaiting_recovery.digest
    assert recovery_approval.signature != origin_approval.signature

def test_completed_customer_invoice_cannot_be_reinterpreted_as_incident_recovery(service):
    gateway, _backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    approval = _approval(awaiting, "approval-posted-origin-recovery-rejected")
    gateway.approve_execute(_context(), approval, reconciliation_only=False)
    origin = gateway.status(_context(), awaiting.operation_id)

    with pytest.raises(WriteServiceError, match="failed origin"):
        gateway.prepare_recovery(
            _context(token_id="token-posted-origin-recovery-rejected"),
            origin_operation_id=origin.operation_id,
            expected_origin_revision=origin.revision,
            recovery_operation_id="op-posted-origin-recovery-rejected",
            request_id="req-posted-origin-recovery-rejected",
            recovery_date="2026-07-16",
            reason="must not reinterpret a posted invoice",
            idempotency_key="recover-posted-origin-rejected",
        )


def test_completed_origin_is_rejected_before_environment_reinterpretation(service):
    gateway, _backend, _store = service
    draft_parameters = {**_invoice_parameters(), "posting_mode": "draft"}
    awaiting = _prepare_and_preview(gateway, parameters=draft_parameters)
    approval = _approval(awaiting, "approval-production-origin-rejected")
    gateway.approve_execute(
        _context(parameters=draft_parameters),
        approval,
        reconciliation_only=False,
    )
    origin = gateway.status(
        _context(parameters=draft_parameters), awaiting.operation_id
    )

    with pytest.raises(WriteServiceError, match="failed origin"):
        gateway._validated_origin_recovery_plan(
            _context(parameters=draft_parameters),
            replace(origin, environment="production"),
        )


def _failed_verification_origin(
    gateway: DurableWriteService,
    backend: Backend,
):
    backend.verification_passes = False
    awaiting = _prepare_and_preview(gateway)
    output = gateway.approve_execute(
        _context(token_id="token-incident-origin-execute"),
        _approval(awaiting, "approval-incident-origin"),
        reconciliation_only=False,
    )
    origin = gateway.status(
        _context(token_id="token-incident-origin-status"),
        awaiting.operation_id,
    )
    assert output["operation_state"] == "failed"
    assert output["verification"]["passed"] is False
    assert origin.state == State.FAILED
    backend.verification_passes = True
    return origin


def _incident_recovery_request(origin, *, suffix: str) -> dict[str, object]:
    return {
        "origin_operation_id": origin.operation_id,
        "expected_origin_revision": origin.revision,
        "recovery_operation_id": f"op-incident-recovery-{suffix}",
        "request_id": f"request-incident-recovery-{suffix}",
        "recovery_date": "2026-07-16",
        "reason": "Resolve a durably failed verification incident",
        "idempotency_key": f"incident-recovery-{suffix}",
    }


def _install_incident_recovery_auth(
    gateway: DurableWriteService,
    origin,
    request: dict[str, object],
):
    def context(token_id: str):
        return sign_write_action_context(
            auth_token_id=token_id,
            principal=origin.principal,
            odoo_instance_id=origin.odoo_instance_id,
            database_name=origin.database_name,
            database_uuid=origin.database_uuid,
            user_id=origin.user_id,
            company_id=origin.company_id,
            allowed_company_ids=frozenset({origin.company_id}),
            environment=origin.environment,
            action="operation.recover",
            request=request,
            issued_at=NOW - timedelta(seconds=10),
            expires_at=NOW + timedelta(minutes=4),
            key_id="write-auth-v2",
            secret=APPROVAL_SECRET,
        )

    def authenticate(value):
        return verify_write_action_context(
            value,
            action="operation.recover",
            request=request,
            now=NOW,
            secret=APPROVAL_SECRET,
            expected_key_id="write-auth-v2",
        )

    gateway._authenticate_context = authenticate
    gateway._policy._authenticate_context = authenticate
    return context


def _prepare_incident_recovery_awaiting(
    gateway: DurableWriteService,
    backend: Backend,
    *,
    suffix: str,
):
    origin = _failed_verification_origin(gateway, backend)
    request = _incident_recovery_request(origin, suffix=suffix)
    context = _install_incident_recovery_auth(gateway, origin, request)
    prepared = gateway.prepare_recovery(
        context(f"token-{suffix}-prepare"), **request
    )
    recovery = prepared["operation"]
    gateway.preview(context(f"token-{suffix}-preview"), recovery.operation_id)
    awaiting = gateway.status(
        context(f"token-{suffix}-status"), recovery.operation_id
    )
    return origin, recovery, awaiting, context


def test_incident_recovery_requires_failed_verification_and_finalizes_two_anchors(
    service,
):
    gateway, backend, store = service
    origin = _failed_verification_origin(gateway, backend)
    request = _incident_recovery_request(origin, suffix="success")
    context = _install_incident_recovery_auth(gateway, origin, request)

    prepared = gateway.prepare_recovery(
        context("token-incident-recovery-prepare"), **request
    )
    recovery = prepared["operation"]
    assert recovery.operation_id != origin.operation_id
    gateway.preview(
        context("token-incident-recovery-preview"), recovery.operation_id
    )
    awaiting = gateway.status(
        context("token-incident-recovery-status"), recovery.operation_id
    )
    output = gateway.approve_execute(
        context("token-incident-recovery-execute"),
        _approval(awaiting, "approval-incident-recovery"),
        reconciliation_only=False,
    )

    assert output["operation_state"] == "completed"
    assert store.get_operation(origin.operation_id).state == State.FAILED
    assert store.get_operation(recovery.operation_id).state == State.COMPLETED
    intent = gateway._test_effect_finalizer.calls[-1]
    origin_execution = gateway._stored_backend_evidence(
        next(
            record
            for record in store.get_trusted_result_records(origin.operation_id)
            if record.kind == "execution"
        )
    )
    recovery_records = store.get_trusted_result_records(recovery.operation_id)
    recovery_execution = gateway._stored_backend_evidence(
        next(record for record in recovery_records if record.kind == "execution")
    )
    recovery_verification = gateway._stored_backend_evidence(
        next(record for record in recovery_records if record.kind == "verification")
    )
    assert intent.operation_id == origin.operation_id
    assert intent.operation_digest == origin.digest
    assert intent.execution_result_digest == trusted_result_envelope_digest(
        origin_execution.result, origin
    )
    assert intent.resolution_operation_id == recovery.operation_id
    assert intent.resolution_operation_digest == recovery.digest
    assert (
        intent.resolution_execution_result_digest
        == trusted_result_envelope_digest(recovery_execution.result, recovery)
    )
    assert intent.resolution_result_digest == trusted_result_envelope_digest(
        recovery_verification.result, recovery
    )
    assert intent.resolution_kind == "recovered"
    assert output["database_finalization"]["resolved_anchor_count"] == 2
    assert output["database_finalization"]["operation_id"] == origin.operation_id
    assert (
        output["database_finalization"]["resolution_operation_id"]
        == recovery.operation_id
    )
    assert len(store.get_final_write_receipts(recovery.operation_id)) == 1
    assert gateway.result(
        context("token-incident-recovery-result"), recovery.operation_id
    ) == output


def test_incident_recovery_finalizer_failure_leaves_verifying_without_local_receipt(
    service,
):
    gateway, backend, store = service
    origin, recovery, awaiting, context = _prepare_incident_recovery_awaiting(
        gateway, backend, suffix="finalizer-failure"
    )
    finalizer = gateway._test_effect_finalizer
    finalizer.error = EffectFinalizationError("simulated recovered finalization failure")

    with pytest.raises(WriteServiceError, match="database effect finalization"):
        gateway.approve_execute(
            context("token-incident-finalizer-failure-execute"),
            _approval(awaiting, "approval-incident-finalizer-failure"),
            reconciliation_only=False,
        )

    assert gateway.status(
        context("token-incident-finalizer-failure-status"),
        recovery.operation_id,
    ).state == State.VERIFYING
    assert store.get_final_write_receipts(recovery.operation_id) == ()
    assert finalizer.calls[-1].operation_id == origin.operation_id
    assert finalizer.calls[-1].resolution_operation_id == recovery.operation_id
    assert finalizer.calls[-1].resolution_kind == "recovered"


def test_incident_recovery_response_loss_replays_the_same_two_anchor_intent(service):
    gateway, backend, store = service
    _origin, recovery, awaiting, context = _prepare_incident_recovery_awaiting(
        gateway, backend, suffix="response-loss"
    )
    approval = _approval(awaiting, "approval-incident-response-loss")
    finalizer = gateway._test_effect_finalizer
    finalizer.lose_first_response = True

    with pytest.raises(WriteServiceError, match="database effect finalization"):
        gateway.approve_execute(
            context("token-incident-response-loss-first"),
            approval,
            reconciliation_only=False,
        )
    assert gateway.status(
        context("token-incident-response-loss-verifying"),
        recovery.operation_id,
    ).state == State.VERIFYING
    assert store.get_final_write_receipts(recovery.operation_id) == ()

    output = gateway.approve_execute(
        context("token-incident-response-loss-replay"),
        approval,
        reconciliation_only=True,
    )

    assert output["operation_state"] == "completed"
    assert output["database_finalization"]["resolved_anchor_count"] == 2
    assert len(finalizer.calls) == 2
    assert finalizer.calls[0] == finalizer.calls[1]
    assert len(store.get_final_write_receipts(recovery.operation_id)) == 1


def test_incident_recovery_rejects_execution_failure_without_verification(service):
    gateway, backend, _store = service
    backend.execution_succeeds = False
    awaiting = _prepare_and_preview(gateway)
    gateway.approve_execute(
        _context(token_id="token-failed-execution-origin"),
        _approval(awaiting, "approval-failed-execution-origin"),
        reconciliation_only=False,
    )
    origin = gateway.status(
        _context(token_id="token-failed-execution-origin-status"),
        awaiting.operation_id,
    )
    request = _incident_recovery_request(origin, suffix="execution-failed")
    context = _install_incident_recovery_auth(gateway, origin, request)

    with pytest.raises(
        WriteServiceError,
        match="durable successful execution and failed verification",
    ):
        gateway.prepare_recovery(
            context("token-failed-execution-recovery"), **request
        )


def test_incident_recovery_rejects_missing_durable_verification(
    service, monkeypatch: pytest.MonkeyPatch
):
    gateway, backend, store = service
    origin = _failed_verification_origin(gateway, backend)
    records = store.get_trusted_result_records(origin.operation_id)
    original = store.get_trusted_result_records
    monkeypatch.setattr(
        store,
        "get_trusted_result_records",
        lambda operation_id: (
            tuple(record for record in records if record.kind == "execution")
            if operation_id == origin.operation_id
            else original(operation_id)
        ),
    )
    request = _incident_recovery_request(origin, suffix="missing-verification")
    context = _install_incident_recovery_auth(gateway, origin, request)

    with pytest.raises(
        WriteServiceError,
        match="durable successful execution and failed verification",
    ):
        gateway.prepare_recovery(
            context("token-missing-verification-recovery"), **request
        )


def test_incident_recovery_operation_must_be_distinct_from_origin(service):
    gateway, backend, _store = service
    origin = _failed_verification_origin(gateway, backend)
    request = _incident_recovery_request(origin, suffix="same-operation")
    request["recovery_operation_id"] = origin.operation_id
    context = _install_incident_recovery_auth(gateway, origin, request)

    with pytest.raises(WriteServiceError, match="distinct from its origin"):
        gateway.prepare_recovery(
            context("token-same-operation-recovery"), **request
        )


def test_current_release_rejects_a_legacy_recovery_binding_before_execution(
    service, monkeypatch: pytest.MonkeyPatch
):
    gateway, backend, store = service
    _origin, recovery, _awaiting, context = _prepare_incident_recovery_awaiting(
        gateway, backend, suffix="legacy-binding"
    )
    binding = store.get_recovery_operation_binding(recovery.operation_id)
    legacy = replace(
        binding,
        audit_event=replace(
            binding.audit_event,
            payload={**binding.audit_event.payload, "binding_version": 1},
        ),
    )
    monkeypatch.setattr(
        store, "get_recovery_operation_binding", lambda _operation_id: legacy
    )

    with pytest.raises(
        WriteServiceError,
        match="binding differs from durable origin evidence",
    ):
        gateway.trusted_recovery_plan(
            context("token-legacy-binding-plan"), recovery
        )


def test_expired_or_self_approval_never_calls_business_executor(service):
    gateway, backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    expired = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="expired-nonce",
        issued_at=NOW - timedelta(minutes=8),
        expires_at=NOW - timedelta(minutes=1),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )
    with pytest.raises(Exception, match="requires reconciliation-only authority"):
        gateway.approve_execute(_context(), expired, reconciliation_only=False)
    assert backend.calls == ["precheck"]

    with pytest.raises(Exception, match="requester cannot approve"):
        sign_approval(
            operation=awaiting,
            approver_user_id=42,
            nonce="self-nonce",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=1),
            approval_ttl_seconds=600,
            key_id="approval-v2",
            secret=APPROVAL_SECRET,
        )


def test_registry_capability_ttl_is_enforced_before_odoo_execution(service):
    gateway, backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    limited_data = gateway._capabilities[awaiting.capability_id].data
    limited_data["approval"]["ttl_seconds"] = 60
    limited = type(gateway._capabilities[awaiting.capability_id]).from_dict(
        limited_data
    )
    gateway._capabilities[awaiting.capability_id] = limited
    gateway._policy._capabilities[awaiting.capability_id] = limited
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="approval-over-capability-ttl",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )

    with pytest.raises(Exception, match="policy TTL"):
        gateway.approve_execute(_context(), approval, reconciliation_only=False)
    assert backend.calls == ["precheck"]


def test_approval_execution_rechecks_the_exact_immutable_precheck(service):
    gateway, backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="approval-nonce-precheck-drift",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )
    original_precheck = backend.precheck

    def changed_precheck(*args):
        evidence = original_precheck(*args)
        evidence["checks"] = [*evidence["checks"], "configuration_changed"]
        return evidence

    gateway._precheck_executor = changed_precheck
    with pytest.raises(WriteServiceError, match="no longer matches"):
        gateway.approve_execute(_context(), approval, reconciliation_only=False)

    assert gateway.status(_context(), awaiting.operation_id).state == State.AWAITING_APPROVAL
    assert backend.calls == ["precheck", "precheck"]


def test_tampered_backend_evidence_is_rejected_without_business_success(service):
    gateway, backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="approval-nonce-tamper",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )
    original_execute = backend.execute

    def tampered(*args):
        signed = original_execute(*args)
        value = copy.deepcopy(signed.evidence)
        value["odoo_records"][0]["record_id"] = 999
        return BackendEvidence(result=signed.result, evidence=value)

    gateway._write_executor = tampered
    with pytest.raises(WriteServiceError, match="digest"):
        gateway.approve_execute(_context(), approval, reconciliation_only=False)
    assert gateway.status(_context(), awaiting.operation_id).state == State.EXECUTING


def test_signed_execution_requires_absent_or_existing_before_for_each_result_record(service):
    gateway, backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="approval-nonce-missing-result-before",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )

    def signed_missing_result_before(
        _context, _capability, operation, _approval, _registry, _release
    ):
        evidence = _execution_evidence(operation.operation_id)
        unrelated = create_record_snapshot(
            model="account.move",
            record_id=500,
            exists=True,
            record_state="posted",
            values={"company_id": 7, "state": "posted"},
        )
        evidence["difference"] = create_difference(
            before=[unrelated],
            after=copy.deepcopy(evidence["difference"]["after"]),
            changed_fields=["amount_total", "company_id", "state"],
        )
        digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
        return BackendEvidence(
            result=sign_execution_result(
                operation=operation,
                issuer="odoo-write-executor",
                key_id="execution-v1",
                succeeded=True,
                evidence_digest=digest,
                issued_at=NOW,
                secret=EXECUTION_SECRET,
            ),
            evidence=evidence,
        )

    gateway._write_executor = signed_missing_result_before
    with pytest.raises(WriteServiceError, match="before snapshot"):
        gateway.approve_execute(_context(), approval, reconciliation_only=False)
    assert gateway.status(_context(), awaiting.operation_id).state == State.EXECUTING


def test_signed_cross_company_odoo_evidence_is_rejected_before_completed_state(service):
    gateway, backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="approval-nonce-cross-company",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )

    def signed_cross_company(_context, _capability, operation, _approval, _registry, _release):
        evidence = _execution_evidence(operation.operation_id)
        evidence["odoo_records"][0]["company_id"] = 8
        evidence["recovery_plan"] = create_recovery_plan(
            origin_operation_id=operation.operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="available",
            method="reverse_move",
            requires_approval=True,
            target_records=copy.deepcopy(evidence["odoo_records"]),
            parameters=evidence["recovery_parameters"],
        )
        digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
        return BackendEvidence(
            result=sign_execution_result(
                operation=operation,
                issuer="odoo-write-executor",
                key_id="execution-v1",
                succeeded=True,
                evidence_digest=digest,
                issued_at=NOW,
                secret=EXECUTION_SECRET,
            ),
            evidence=evidence,
        )

    gateway._write_executor = signed_cross_company
    with pytest.raises(WriteServiceError, match="company"):
        gateway.approve_execute(_context(), approval, reconciliation_only=False)
    assert gateway.status(_context(), awaiting.operation_id).state == State.EXECUTING


def test_wrong_verification_method_cannot_be_persisted_as_completed(service):
    gateway, backend, _store = service
    awaiting = _prepare_and_preview(gateway)
    approval = sign_approval(
        operation=awaiting,
        approver_user_id=99,
        nonce="approval-nonce-wrong-method",
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600,
        key_id="approval-v2",
        secret=APPROVAL_SECRET,
    )
    original_verify = backend.verify

    def wrong_method(*args):
        signed = original_verify(*args)
        evidence = copy.deepcopy(signed.evidence)
        evidence["method"] = "unrelated_check"
        operation = args[2]
        digest = hashlib.sha256(canonical_json(evidence)).hexdigest()
        return BackendEvidence(
            result=sign_verification_result(
                operation=operation,
                issuer="odoo-write-verifier",
                key_id="verification-v1",
                succeeded=True,
                evidence_digest=digest,
                issued_at=NOW,
                secret=VERIFICATION_SECRET,
            ),
            evidence=evidence,
        )

    gateway._verification_executor = wrong_method
    with pytest.raises(WriteServiceError, match="method"):
        gateway.approve_execute(_context(), approval, reconciliation_only=False)
    assert gateway.status(_context(), awaiting.operation_id).state == State.VERIFYING


def test_execution_failure_is_audited_and_never_reported_as_success(tmp_path: Path):
    backend = Backend(execution_succeeds=False)
    finalizer = Finalizer()
    store = SQLitePersistence((tmp_path / "failure.sqlite3").resolve())
    security = WriteServiceSecurity(
        approval_key_id="approval-v2", approval_secret=APPROVAL_SECRET,
        approval_ttl_seconds=600, execution_key_id="execution-v1",
        execution_secret=EXECUTION_SECRET,
        execution_issuers=frozenset({"odoo-write-executor"}),
        verification_key_id="verification-v1", verification_secret=VERIFICATION_SECRET,
        verification_issuers=frozenset({"odoo-write-verifier"}),
        receipt_key_id="write-receipt-v1", receipt_secret=RECEIPT_SECRET,
    )
    gateway = DurableWriteService(
        _capabilities(), release_digest=RELEASE_DIGEST, store=store, security=security,
        authenticate_context=lambda _context: True,
        acl_check=lambda *_: True, approver_authorized=lambda *_: True,
        precheck_executor=backend.precheck, write_executor=backend.execute,
        verification_executor=backend.verify, availability_channel="staged",
        now=lambda: NOW, effect_finalizer=finalizer,
        effect_finalizer_identity=FINALIZER_IDENTITY,
        receipt_id_factory=lambda: "failure-receipt",
    )
    awaiting = _prepare_and_preview(gateway)
    approval = sign_approval(
        operation=awaiting, approver_user_id=99, nonce="failure-nonce",
        issued_at=NOW, expires_at=NOW + timedelta(minutes=5),
        approval_ttl_seconds=600, key_id="approval-v2", secret=APPROVAL_SECRET,
    )

    output = gateway.approve_execute(
        _context(), approval, reconciliation_only=False
    )

    assert output["operation_state"] == "failed"
    assert output["verification"]["passed"] is False
    assert output["odoo_records"] == []
    assert output["database_finalization"] is None
    assert backend.calls == ["precheck", "precheck", "execute"]
    assert finalizer.calls == []
    assert gateway.status(_context(), awaiting.operation_id).state == State.FAILED

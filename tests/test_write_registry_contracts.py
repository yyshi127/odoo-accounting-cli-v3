import copy
import json
from pathlib import Path

import pytest

from odoo_accounting_cli_v3.contracts import ContractError, validate_value
from odoo_accounting_cli_v3.odoo.write_handlers import _CAPABILITIES as ODOO_WRITE_CAPABILITIES
from odoo_accounting_cli_v3.registry import load_registry
from odoo_accounting_cli_v3.write_service import _ALLOWED_MODELS


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
SHA256 = "a" * 64
BASELINE_WRITE_IDS = (
    "acct.invoice.customer_create.v1",
    "acct.bill.vendor_create.v1",
    "acct.refund.create.v1",
    "acct.payment.register.v1",
    "acct.bank.statement_import.v1",
    "acct.reconciliation.apply.v1",
    "acct.asset.create.v1",
    "acct.depreciation.post.v1",
    "acct.accrual.create.v1",
    "acct.deferred.create.v1",
    "acct.period.adjustment_create.v1",
    "acct.move.reverse.v1",
    "acct.move.draft_cancel.v1",
    "acct.recovery.execute.v1",
)
PHASE_B_WRITE_IDS = (
    "acct.journal.entry_create.v1",
    "acct.move.post.v1",
    "acct.move.draft_cancel.v2",
)
PAYMENT_CANCEL_WRITE_IDS = (
    "acct.payment.cancel.v1",
)
RECONCILIATION_UNDO_WRITE_IDS = (
    "acct.reconciliation.undo.v1",
)
BANK_STATEMENT_COMPENSATE_WRITE_IDS = (
    "acct.bank.statement_compensate.v1",
)
WRITE_IDS = (
    *BASELINE_WRITE_IDS[:13],
    *PHASE_B_WRITE_IDS,
    *PAYMENT_CANCEL_WRITE_IDS,
    BASELINE_WRITE_IDS[13],
    *RECONCILIATION_UNDO_WRITE_IDS,
    *BANK_STATEMENT_COMPENSATE_WRITE_IDS,
)

EXPECTED_INPUT_FIELDS = {
    "acct.invoice.customer_create.v1": {
        "company_id", "partner_id", "invoice_date", "accounting_date",
        "due_date", "currency_id", "journal_id", "posting_mode", "reference",
        "lines", "idempotency_key",
    },
    "acct.bill.vendor_create.v1": {
        "company_id", "partner_id", "invoice_date", "accounting_date",
        "due_date", "currency_id", "journal_id", "posting_mode",
        "vendor_reference", "lines", "idempotency_key",
    },
    "acct.refund.create.v1": {
        "company_id", "origin_move_id", "refund_type", "refund_mode",
        "refund_date", "journal_id", "currency_id", "expected_total_amount",
        "reason", "posting_mode", "lines", "idempotency_key",
    },
    "acct.payment.register.v1": {
        "company_id", "target_move_ids", "partner_id", "partner_type",
        "direction", "payment_date", "currency_id", "amount", "journal_id",
        "payment_method_line_id", "memo", "idempotency_key",
    },
    "acct.payment.cancel.v1": {
        "company_id", "payment_id", "move_id", "expected_payment_state",
        "expected_move_state", "expected_payment_date", "expected_partner_id",
        "expected_partner_type", "expected_direction", "expected_amount",
        "expected_currency_id", "expected_journal_id",
        "expected_payment_method_line_id", "expected_is_sent",
        "expected_line_ids", "reason", "idempotency_key",
    },
    "acct.bank.statement_import.v1": {
        "company_id", "journal_id", "statement_date", "currency_id",
        "external_reference", "source_digest", "source_filename",
        "opening_balance", "closing_balance", "lines", "idempotency_key",
    },
    "acct.reconciliation.apply.v1": {
        "company_id", "line_ids", "account_id", "partner_id",
        "reconciliation_date", "currency_id", "mode", "amount",
        "tolerance_amount", "writeoff_account_id", "writeoff_journal_id",
        "writeoff_label", "idempotency_key",
    },
    "acct.reconciliation.undo.v1": {
        "company_id", "origin_operation_id", "expected_origin_revision",
        "expected_origin_final_receipt_body_digest",
        "expected_recovery_plan_digest", "recovery_date", "reason",
        "idempotency_key",
    },
    "acct.bank.statement_compensate.v1": {
        "company_id", "origin_operation_id", "expected_origin_revision",
        "expected_origin_final_receipt_body_digest",
        "expected_recovery_plan_digest", "expected_statement_id",
        "expected_journal_id", "expected_currency_id",
        "expected_source_digest", "compensation_date", "reason",
        "idempotency_key",
    },
    "acct.asset.create.v1": {
        "company_id", "source_move_line_id", "asset_model_id", "asset_name",
        "acquisition_date", "currency_id", "acquisition_value", "posting_mode",
        "idempotency_key",
    },
    "acct.depreciation.post.v1": {
        "company_id", "asset_id", "depreciation_move_id", "period_start",
        "period_end", "posting_date", "journal_id", "currency_id", "amount",
        "idempotency_key",
    },
    "acct.accrual.create.v1": {
        "company_id", "journal_id", "posting_date", "reversal_date",
        "currency_id", "reference", "posting_mode", "lines", "idempotency_key",
    },
    "acct.deferred.create.v1": {
        "company_id", "source_move_line_id", "deferred_type",
        "schedule_start_date", "schedule_end_date", "expected_generation_method",
        "amount_computation_method", "expected_deferred_account_id",
        "expected_deferred_journal_id", "currency_id", "total_amount",
        "posting_mode", "idempotency_key",
    },
    "acct.period.adjustment_create.v1": {
        "company_id", "journal_id", "posting_date", "period_end_date",
        "currency_id", "reference", "reason", "posting_mode", "lines",
        "idempotency_key",
    },
    "acct.journal.entry_create.v1": {
        "company_id", "journal_id", "posting_date", "currency_id", "reference",
        "reason", "posting_mode", "lines", "idempotency_key",
    },
    "acct.move.post.v1": {
        "company_id", "move_id", "expected_move_type",
        "expected_document_binding", "expected_business_binding",
        "expected_journal_id", "expected_currency_id", "expected_posting_date",
        "expected_reference", "expected_total_debit", "expected_total_credit",
        "expected_line_count", "reason", "idempotency_key",
    },
    "acct.move.reverse.v1": {
        "company_id", "move_id", "reversal_date", "journal_id", "currency_id",
        "expected_total_amount", "reason", "posting_mode", "idempotency_key",
    },
    "acct.move.draft_cancel.v1": {
        "company_id", "move_id", "expected_move_type",
        "expected_document_binding", "expected_business_binding", "reason",
        "idempotency_key",
    },
    "acct.move.draft_cancel.v2": {
        "company_id", "move_id", "expected_move_type",
        "expected_document_binding", "expected_business_binding",
        "expected_line_ids", "reason", "idempotency_key",
    },
    "acct.recovery.execute.v1": {
        "company_id", "origin_operation_id", "expected_recovery_plan_digest",
        "recovery_date", "reason", "idempotency_key",
    },
}

EXPECTED_OUTPUT_FIELDS = {
    "operation_id", "operation_state", "odoo_records", "difference",
    "verification", "database_finalization", "audit_receipt", "recovery_plan",
}
EXPECTED_SNAPSHOT_FIELDS = {
    "model", "record_id", "exists", "record_state", "values_json",
    "values_digest",
}
EXPECTED_AUDIT_FIELDS = {
    "receipt_id", "request_id", "operation_id", "capability_id", "principal",
    "odoo_instance_id", "database_name", "database_uuid", "user_id",
    "approver_user_id", "company_id", "environment", "capability_channel",
    "request_digest", "operation_digest", "approval_digest", "result_digest",
    "verification_evidence_digest", "registry_digest", "release_digest",
    "audit_head", "issued_at", "signature_version", "signature_purpose",
    "signing_key_id", "signature",
}
EXPECTED_RECORD_REF_FIELDS = {
    "model", "record_id", "company_id", "record_state", "record_fingerprint",
}
EXPECTED_DIFFERENCE_FIELDS = {
    "before", "after", "changed_fields", "before_digest", "after_digest",
}
EXPECTED_VERIFICATION_FIELDS = {
    "method", "passed", "checks", "evidence_digest", "verified_at",
}
EXPECTED_RECOVERY_PLAN_V1_FIELDS = {
    "origin_operation_id", "recovery_capability_id", "status", "method",
    "requires_approval", "target_records", "parameters_digest", "plan_digest",
}
EXPECTED_RECOVERY_PLAN_V2_FIELDS = {
    "plan_version", "origin_operation_id", "recovery_capability_id", "status",
    "method", "requires_approval", "action_targets", "guard_records",
    "oracle_id", "guard_graph_digest", "parameters_digest", "plan_digest",
}
EXPECTED_RECOVERY_GUARD_FIELDS = EXPECTED_RECORD_REF_FIELDS | {
    "expected_outcome",
}


def _document():
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def _writes():
    return {
        item["id"]: item
        for item in _document()["capabilities"]
        if item["access"] == "write"
    }


def _walk_schema(node, path="$"):
    yield path, node
    if "oneOf" in node:
        for index, child in enumerate(node["oneOf"]):
            yield from _walk_schema(child, f"{path}.oneOf[{index}]")
        return
    types = node["type"] if isinstance(node["type"], list) else [node["type"]]
    if "object" in types:
        for name, child in node["properties"].items():
            yield from _walk_schema(child, f"{path}.{name}")
    if "array" in types:
        yield from _walk_schema(node["items"], f"{path}[]")


def _assert_schema_is_bounded_and_non_placeholder(schema):
    for path, node in _walk_schema(schema):
        if "oneOf" in node:
            assert set(node) == {"oneOf"}, path
            assert len(node["oneOf"]) == 2, path
            continue
        types = node["type"] if isinstance(node["type"], list) else [node["type"]]
        if "object" in types:
            assert node["properties"], f"{path} is a placeholder object"
            assert set(node["required"]) == set(node["properties"]), path
            assert node["additionalProperties"] is False
        if "array" in types:
            assert node.get("uniqueItems") is True, path
            assert isinstance(node.get("minItems"), int), path
            assert isinstance(node.get("maxItems"), int), path
            assert 0 <= node["minItems"] <= node["maxItems"], path
        if "string" in types:
            assert node.get("minLength", 0) >= 1, path
            assert node.get("maxLength", 0) >= node["minLength"], path
            assert isinstance(node.get("pattern"), str) and node["pattern"], path
        if "integer" in types and (
            path.endswith("_id")
            or path.endswith("_ids[]")
            or path.endswith(".record_id")
            or path.endswith(".user_id")
            or path.endswith(".company_id")
        ):
            assert node.get("minimum") == 1, path


def _invoice_line():
    return {
        "line_reference": "line-1", "name": "Consulting", "product_id": None,
        "account_id": 401, "quantity": "1", "price_unit": "100.00",
        "tax_ids": [31],
    }


def _refund_line():
    return {
        "line_reference": "refund-line-1", "name": "Refund consulting",
        "account_id": 401, "quantity": "1", "price_unit": "100.00",
        "tax_ids": [31],
    }


def _journal_line(reference, side):
    return {
        "line_reference": reference, "account_id": 401,
        "partner_id": None, "currency_id": 12,
        "name": f"{side} line", "side": side,
        "amount": "100.00", "amount_currency": "100.00" if side == "debit" else "-100.00",
        "tax_ids": [],
    }


VALID_INPUTS = {
    "acct.invoice.customer_create.v1": {
        "company_id": 7, "partner_id": 101, "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15", "due_date": "2026-08-15",
        "currency_id": 12, "journal_id": 5, "posting_mode": "draft",
        "reference": "INV-EXT-1", "lines": [_invoice_line()],
        "idempotency_key": "invoice-1",
    },
    "acct.bill.vendor_create.v1": {
        "company_id": 7, "partner_id": 102, "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15", "due_date": "2026-08-15",
        "currency_id": 12, "journal_id": 6, "posting_mode": "draft",
        "vendor_reference": "BILL-EXT-1", "lines": [_invoice_line()],
        "idempotency_key": "bill-1",
    },
    "acct.refund.create.v1": {
        "company_id": 7, "origin_move_id": 201,
        "refund_type": "customer_credit_note", "refund_mode": "partial",
        "refund_date": "2026-07-15", "journal_id": 5, "currency_id": 12,
        "expected_total_amount": "100.00", "reason": "Service adjustment",
        "posting_mode": "draft", "lines": [_refund_line()],
        "idempotency_key": "refund-1",
    },
    "acct.payment.register.v1": {
        "company_id": 7, "target_move_ids": [201], "partner_id": 101,
        "partner_type": "customer", "direction": "inbound",
        "payment_date": "2026-07-15", "currency_id": 12, "amount": "100.00",
        "journal_id": 7, "payment_method_line_id": 9, "memo": "INV-201",
        "idempotency_key": "payment-1",
    },
    "acct.payment.cancel.v1": {
        "company_id": 7, "payment_id": 991, "move_id": 1991,
        "expected_payment_state": "in_process",
        "expected_move_state": "posted",
        "expected_payment_date": "2026-07-16",
        "expected_partner_id": 101, "expected_partner_type": "customer",
        "expected_direction": "inbound", "expected_amount": "251.00",
        "expected_currency_id": 12, "expected_journal_id": 9,
        "expected_payment_method_line_id": 3, "expected_is_sent": True,
        "expected_line_ids": [3001, 3002],
        "reason": "Cancel an unreconciled duplicate payment",
        "idempotency_key": "payment-cancel-991",
    },
    "acct.bank.statement_import.v1": {
        "company_id": 7, "journal_id": 7, "statement_date": "2026-07-15",
        "currency_id": 12, "external_reference": "BANK-2026-07-15",
        "source_digest": SHA256, "source_filename": "bank.csv",
        "opening_balance": "0", "closing_balance": "100.00",
        "lines": [{
            "external_transaction_id": "bank-txn-1", "transaction_date": "2026-07-15",
            "value_date": "2026-07-15", "direction": "credit", "amount": "100.00",
            "foreign_currency_id": None, "foreign_amount": None,
            "summary": "Customer receipt", "partner_id": 101,
            "source_line_digest": "b" * 64,
        }],
        "idempotency_key": "bank-import-1",
    },
    "acct.reconciliation.apply.v1": {
        "company_id": 7, "line_ids": [301, 302], "account_id": 1200,
        "partner_id": 101, "reconciliation_date": "2026-07-15",
        "currency_id": 12, "mode": "full", "amount": "100.00",
        "tolerance_amount": "0", "writeoff_account_id": None,
        "writeoff_journal_id": None, "writeoff_label": None,
        "idempotency_key": "reconcile-1",
    },
    "acct.asset.create.v1": {
        "company_id": 7, "source_move_line_id": 401, "asset_model_id": 11,
        "asset_name": "Laptop", "acquisition_date": "2026-07-15",
        "currency_id": 12, "acquisition_value": "1200.00",
        "posting_mode": "draft", "idempotency_key": "asset-1",
    },
    "acct.depreciation.post.v1": {
        "company_id": 7, "asset_id": 501, "depreciation_move_id": 502,
        "period_start": "2026-07-01", "period_end": "2026-07-31",
        "posting_date": "2026-07-31", "journal_id": 8, "currency_id": 12,
        "amount": "100.00", "idempotency_key": "depreciation-1",
    },
    "acct.accrual.create.v1": {
        "company_id": 7, "journal_id": 8, "posting_date": "2026-07-31",
        "reversal_date": "2026-08-01", "currency_id": 12,
        "reference": "July accrual", "posting_mode": "post",
        "lines": [_journal_line("accrual-1", "debit"), _journal_line("accrual-2", "credit")],
        "idempotency_key": "accrual-1",
    },
    "acct.deferred.create.v1": {
        "company_id": 7, "source_move_line_id": 601,
        "deferred_type": "expense", "schedule_start_date": "2026-07-01",
        "schedule_end_date": "2027-06-30",
        "expected_generation_method": "on_validation",
        "amount_computation_method": "month", "expected_deferred_account_id": 480,
        "expected_deferred_journal_id": 8, "currency_id": 12,
        "total_amount": "1200.00", "posting_mode": "post",
        "idempotency_key": "deferred-1",
    },
    "acct.period.adjustment_create.v1": {
        "company_id": 7, "journal_id": 8, "posting_date": "2026-07-31",
        "period_end_date": "2026-07-31", "currency_id": 12,
        "reference": "July close", "reason": "Accrued expense",
        "posting_mode": "post",
        "lines": [_journal_line("adjust-1", "debit"), _journal_line("adjust-2", "credit")],
        "idempotency_key": "adjustment-1",
    },
    "acct.move.reverse.v1": {
        "company_id": 7, "move_id": 701, "reversal_date": "2026-08-01",
        "journal_id": 8, "currency_id": 12, "expected_total_amount": "100.00",
        "reason": "Approved correction", "posting_mode": "post",
        "idempotency_key": "reversal-1",
    },
    "acct.move.draft_cancel.v1": {
        "company_id": 7, "move_id": 702,
        "expected_move_type": "out_invoice",
        "expected_document_binding": "a" * 64,
        "expected_business_binding": "b" * 64,
        "reason": "Cancel duplicate pristine draft",
        "idempotency_key": "draft-cancel-1",
    },
    "acct.recovery.execute.v1": {
        "company_id": 7, "origin_operation_id": "op-original-1",
        "expected_recovery_plan_digest": SHA256, "recovery_date": "2026-07-15",
        "reason": "Execute approved compensation", "idempotency_key": "recovery-1",
    },
    "acct.reconciliation.undo.v1": {
        "company_id": 7,
        "origin_operation_id": "op-reconciliation-apply-1",
        "expected_origin_revision": 6,
        "expected_origin_final_receipt_body_digest": "b" * 64,
        "expected_recovery_plan_digest": "c" * 64,
        "recovery_date": "2026-07-16",
        "reason": "Undo the complete verified reconciliation graph",
        "idempotency_key": "undo-reconciliation-op-1",
    },
    "acct.bank.statement_compensate.v1": {
        "company_id": 7,
        "origin_operation_id": "op-bank-statement-import-1",
        "expected_origin_revision": 6,
        "expected_origin_final_receipt_body_digest": "d" * 64,
        "expected_recovery_plan_digest": "e" * 64,
        "expected_statement_id": 711,
        "expected_journal_id": 7,
        "expected_currency_id": 12,
        "expected_source_digest": "f" * 64,
        "compensation_date": "2026-07-16",
        "reason": "Compensate the complete verified bank import batch",
        "idempotency_key": "compensate-bank-statement-import-op-1",
    },
    "acct.journal.entry_create.v1": {
        "company_id": 7, "journal_id": 8, "posting_date": "2026-07-31",
        "currency_id": 12, "reference": "Manual reclassification 2026-07",
        "reason": "Approved reclassification", "posting_mode": "draft",
        "lines": [
            _journal_line("journal-entry-1", "debit"),
            _journal_line("journal-entry-2", "credit"),
        ],
        "idempotency_key": "journal-entry-july-reclassification",
    },
    "acct.move.post.v1": {
        "company_id": 7, "move_id": 882, "expected_move_type": "entry",
        "expected_document_binding": "d" * 64,
        "expected_business_binding": "e" * 64, "expected_journal_id": 8,
        "expected_currency_id": 12, "expected_posting_date": "2026-07-31",
        "expected_reference": "Manual reclassification 2026-07",
        "expected_total_debit": "100.00",
        "expected_total_credit": "100.00", "expected_line_count": 2,
        "reason": "Approved posting", "idempotency_key": "post-move-882",
    },
    "acct.move.draft_cancel.v2": {
        "company_id": 7, "move_id": 883, "expected_move_type": "entry",
        "expected_document_binding": "f" * 64,
        "expected_business_binding": "0" * 64,
        "expected_line_ids": [2001, 2002],
        "reason": "Cancel duplicate pristine draft entry",
        "idempotency_key": "cancel-draft-entry-883",
    },
}


def _record_ref(*, model="account.move", record_id=201):
    return {
        "model": model, "record_id": record_id, "company_id": 7,
        "record_state": "posted", "record_fingerprint": "b" * 64,
    }


def _snapshot(exists):
    return {
        "model": "account.move", "record_id": 201, "exists": exists,
        "record_state": "posted" if exists else "absent", "values_json": "{}",
        "values_digest": "c" * 64,
    }


def _database_finalization():
    return {
        "attestation_digest": "0" * 64,
        "attestation_id": "22222222-2222-4222-8222-222222222222",
        "attestation_key_id": "effect-finalizer-v1",
        "database_oid": 16384,
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "finalized_at": "2026-07-15T08:00:01Z",
        "finalized_txid": "9123",
        "guard_epoch": 0,
        "guard_installation_id": "33333333-3333-4333-8333-333333333333",
        "intent_digest": "1" * 64,
        "operation_id": "op-1",
        "proof_expires_at": "2026-07-15T08:05:00Z",
        "proof_verified_at": "2026-07-15T08:00:00Z",
        "protocol_version": 1,
        "receipt_digest": "2" * 64,
        "remaining_unresolved_count": 0,
        "request_digest": "3" * 64,
        "resolution_kind": "verified",
        "resolution_operation_id": "op-1",
        "resolved_anchor_count": 1,
    }


def _valid_output(capability_id):
    return {
        "operation_id": "op-1", "operation_state": "completed",
        "odoo_records": [_record_ref()],
        "difference": {
            "before": [_snapshot(False)], "after": [_snapshot(True)],
            "changed_fields": ["account.move.state"],
            "before_digest": "d" * 64, "after_digest": "e" * 64,
        },
        "verification": {
            "method": "read_back", "passed": True,
            "checks": ["record_exists", "company_matches"],
            "evidence_digest": "f" * 64, "verified_at": "2026-07-15T08:00:00Z",
        },
        "database_finalization": _database_finalization(),
        "audit_receipt": {
            "receipt_id": "receipt-1", "request_id": "request-1",
            "operation_id": "op-1", "capability_id": capability_id,
            "principal": "pi:sandbox-user-42",
            "odoo_instance_id": "odoo19-tokyo2", "database_name": "odoo_sandbox",
            "database_uuid": "11111111-1111-4111-8111-111111111111",
            "user_id": 42, "approver_user_id": 84, "company_id": 7,
            "environment": "sandbox", "capability_channel": "staged",
            "request_digest": "1" * 64,
            "operation_digest": "2" * 64, "approval_digest": "3" * 64,
            "result_digest": "4" * 64, "verification_evidence_digest": "0" * 64,
            "registry_digest": "5" * 64,
            "release_digest": "6" * 64, "audit_head": "7" * 64,
            "issued_at": "2026-07-15T08:00:00Z", "signature_version": 1,
            "signature_purpose": "write_audit_receipt_v1",
            "signing_key_id": "write-receipt-key-1", "signature": "8" * 64,
        },
        "recovery_plan": {
            "origin_operation_id": "op-1",
            "recovery_capability_id": "acct.recovery.execute.v1",
            "status": "available", "method": "reverse_move",
            "requires_approval": True, "target_records": [_record_ref()],
            "parameters_digest": "9" * 64, "plan_digest": "a" * 64,
        },
    }


def _valid_v2_output(capability_id):
    result = _valid_output(capability_id)
    result["recovery_plan"] = {
        "plan_version": 2,
        "origin_operation_id": "op-1",
        "recovery_capability_id": "acct.recovery.execute.v1",
        "status": "available",
        "method": "reverse_move",
        "requires_approval": True,
        "action_targets": [_record_ref()],
        "guard_records": [{
            **_record_ref(model="account.move.line", record_id=301),
            "expected_outcome": "survive_exact",
        }],
        "oracle_id": "acct.recovery.reverse_move.v1",
        "guard_graph_digest": "8" * 64,
        "parameters_digest": "9" * 64,
        "plan_digest": "a" * 64,
    }
    return result


def test_exact_write_capability_set_and_safety_gates_remain_closed():
    writes = _writes()
    assert tuple(writes) == WRITE_IDS
    assert len(BASELINE_WRITE_IDS) == 14
    assert tuple(
        capability_id
        for capability_id in WRITE_IDS
        if capability_id in BASELINE_WRITE_IDS
    ) == BASELINE_WRITE_IDS
    assert tuple(
        capability_id
        for capability_id in WRITE_IDS
        if capability_id in PHASE_B_WRITE_IDS
    ) == PHASE_B_WRITE_IDS
    assert tuple(
        capability_id
        for capability_id in WRITE_IDS
        if capability_id in PAYMENT_CANCEL_WRITE_IDS
    ) == PAYMENT_CANCEL_WRITE_IDS
    assert tuple(
        capability_id
        for capability_id in WRITE_IDS
        if capability_id in RECONCILIATION_UNDO_WRITE_IDS
    ) == RECONCILIATION_UNDO_WRITE_IDS
    assert tuple(
        capability_id
        for capability_id in WRITE_IDS
        if capability_id in BANK_STATEMENT_COMPENSATE_WRITE_IDS
    ) == BANK_STATEMENT_COMPENSATE_WRITE_IDS
    for item in writes.values():
        assert item["evidence"] == {"level": "declared", "receipts": []}
        assert item.get("staged_environments", []) == []
        assert item["enabled_environments"] == []


def test_phase_b_journal_entry_create_contract_is_exact_draft_only_and_tax_free():
    writes = _writes()
    capability = writes["acct.journal.entry_create.v1"]
    schema = capability["input_schema"]
    properties = schema["properties"]

    assert capability["risk_level"] == "high"
    assert capability["odoo_permissions"] == ["account.group_account_user"]
    assert capability["idempotency"] == {
        "required": True, "scope": "company_capability",
    }
    assert set(properties) == EXPECTED_INPUT_FIELDS[
        "acct.journal.entry_create.v1"
    ]
    for name in ("company_id", "journal_id", "currency_id"):
        assert properties[name] == {"type": "integer", "minimum": 1}
    assert properties["posting_mode"] == {
        "type": "string", "enum": ["draft"], "minLength": 5,
        "maxLength": 5, "pattern": "^draft$",
    }
    assert properties["posting_date"] == {
        "type": "string", "format": "date", "minLength": 10,
        "maxLength": 10, "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    }
    assert properties["reference"] == {
        "type": "string", "minLength": 1, "maxLength": 256,
        "pattern": r"^.*\S.*$",
    }
    assert properties["reason"] == {
        "type": "string", "minLength": 1, "maxLength": 512,
        "pattern": r"^.*\S.*$",
    }
    assert properties["idempotency_key"] == {
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    }
    lines = properties["lines"]
    assert {
        "minItems": lines["minItems"],
        "maxItems": lines["maxItems"],
        "uniqueItems": lines["uniqueItems"],
    } == {"minItems": 2, "maxItems": 250, "uniqueItems": True}
    line = lines["items"]
    assert set(line["properties"]) == {
        "line_reference", "account_id", "partner_id", "currency_id", "name",
        "side", "amount", "amount_currency", "tax_ids",
    }
    assert set(line["required"]) == set(line["properties"])
    assert line["additionalProperties"] is False
    assert line["properties"]["tax_ids"] == {
        "type": "array", "minItems": 0, "maxItems": 0,
        "uniqueItems": True, "items": {"type": "integer", "minimum": 1},
    }
    assert capability["output_schema"] == writes[
        BASELINE_WRITE_IDS[0]
    ]["output_schema"]

    invalid = copy.deepcopy(VALID_INPUTS["acct.journal.entry_create.v1"])
    invalid["posting_mode"] = "post"
    with pytest.raises(ContractError):
        validate_value(invalid, schema)
    invalid = copy.deepcopy(VALID_INPUTS["acct.journal.entry_create.v1"])
    invalid["lines"][0]["tax_ids"] = [31]
    with pytest.raises(ContractError):
        validate_value(invalid, schema)


def test_phase_b_move_post_contract_binds_one_exact_manual_entry_graph():
    writes = _writes()
    capability = writes["acct.move.post.v1"]
    schema = capability["input_schema"]
    properties = schema["properties"]

    assert capability["risk_level"] == "critical"
    assert capability["odoo_permissions"] == [
        "account.group_account_user", "account.group_account_invoice",
    ]
    assert capability["idempotency"] == {
        "required": True, "scope": "company_origin_move",
    }
    assert set(properties) == EXPECTED_INPUT_FIELDS["acct.move.post.v1"]
    for name in (
        "company_id", "move_id", "expected_journal_id",
        "expected_currency_id",
    ):
        assert properties[name] == {"type": "integer", "minimum": 1}
    assert properties["expected_move_type"] == {
        "type": "string", "enum": ["entry"], "minLength": 5,
        "maxLength": 5, "pattern": "^entry$",
    }
    digest_schema = {
        "type": "string", "minLength": 64, "maxLength": 64,
        "pattern": "^[0-9a-f]{64}$",
    }
    assert properties["expected_document_binding"] == digest_schema
    assert properties["expected_business_binding"] == digest_schema
    assert properties["expected_posting_date"] == {
        "type": "string", "format": "date", "minLength": 10,
        "maxLength": 10, "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
    }
    positive_amount_schema = {
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": (
            r"^(?:0\.(?:0*[1-9][0-9]*)|"
            r"[1-9][0-9]*(?:\.[0-9]+)?)$"
        ),
    }
    assert properties["expected_total_debit"] == positive_amount_schema
    assert properties["expected_total_credit"] == positive_amount_schema
    assert properties["expected_line_count"] == {
        "type": "integer", "minimum": 2, "maximum": 250,
    }
    assert properties["expected_reference"] == {
        "type": "string", "minLength": 1, "maxLength": 256,
        "pattern": r"^.*\S.*$",
    }
    assert properties["reason"] == {
        "type": "string", "minLength": 1, "maxLength": 512,
        "pattern": r"^.*\S.*$",
    }
    assert properties["idempotency_key"] == {
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    }
    assert capability["output_schema"] == writes[
        BASELINE_WRITE_IDS[0]
    ]["output_schema"]

    for field, value in (
        ("expected_move_type", "out_invoice"),
        ("expected_document_binding", "A" * 64),
        ("expected_total_debit", "0"),
        ("expected_line_count", 1),
        ("expected_line_count", 251),
    ):
        invalid = copy.deepcopy(VALID_INPUTS["acct.move.post.v1"])
        invalid[field] = value
        with pytest.raises(ContractError):
            validate_value(invalid, schema)


def test_phase_b_draft_cancel_v2_contract_binds_supported_type_and_exact_line_set():
    writes = _writes()
    capability = writes["acct.move.draft_cancel.v2"]
    schema = capability["input_schema"]
    properties = schema["properties"]

    assert capability["risk_level"] == "high"
    assert capability["odoo_permissions"] == [
        "account.group_account_user", "account.group_account_invoice",
    ]
    assert capability["idempotency"] == {
        "required": True, "scope": "company_origin_move",
    }
    assert capability["recovery"] == {
        "method": "not_applicable_pristine_draft_cancel_is_terminal",
    }
    assert set(properties) == EXPECTED_INPUT_FIELDS[
        "acct.move.draft_cancel.v2"
    ]
    for name in ("company_id", "move_id"):
        assert properties[name] == {"type": "integer", "minimum": 1}
    assert properties["expected_move_type"] == {
        "type": "string",
        "enum": ["entry", "out_invoice", "in_invoice"],
        "minLength": 5,
        "maxLength": 11,
        "pattern": "^(?:entry|out_invoice|in_invoice)$",
    }
    assert properties["expected_line_ids"] == {
        "type": "array", "minItems": 2, "maxItems": 1000,
        "uniqueItems": True, "items": {"type": "integer", "minimum": 1},
    }
    assert properties["expected_document_binding"] == {
        "type": "string", "minLength": 64, "maxLength": 64,
        "pattern": "^[0-9a-f]{64}$",
    }
    assert properties["expected_business_binding"] == properties[
        "expected_document_binding"
    ]
    assert properties["reason"] == {
        "type": "string", "minLength": 1, "maxLength": 512,
        "pattern": r"^.*\S.*$",
    }
    assert properties["idempotency_key"] == {
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    }
    assert capability["output_schema"] == writes[
        BASELINE_WRITE_IDS[0]
    ]["output_schema"]
    assert writes["acct.move.draft_cancel.v1"]["input_schema"]["properties"][
        "expected_move_type"
    ]["enum"] == ["out_invoice", "in_invoice"]

    for field, value in (
        ("expected_move_type", "out_refund"),
        ("expected_line_ids", [2001]),
        ("expected_line_ids", [2001, 2001]),
        ("expected_line_ids", list(range(1, 1002))),
    ):
        invalid = copy.deepcopy(VALID_INPUTS["acct.move.draft_cancel.v2"])
        invalid[field] = value
        with pytest.raises(ContractError):
            validate_value(invalid, schema)


def test_payment_cancel_contract_is_exact_terminal_and_disabled():
    writes = _writes()
    capability = writes["acct.payment.cancel.v1"]
    schema = capability["input_schema"]
    properties = schema["properties"]

    assert capability["risk_level"] == "critical"
    assert "company-currency-only" in capability["business_description"]
    assert "foreign-currency" in capability["business_description"]
    assert capability["odoo_permissions"] == ["account.group_account_manager"]
    assert capability["company_scope"] == "explicit_single_company"
    assert capability["approval"] == {
        "required": True, "policy": "payment_cancel", "ttl_seconds": 600,
    }
    assert capability["idempotency"] == {
        "required": True, "scope": "company_origin_move",
    }
    assert capability["verification"] == {
        "method": (
            "read_back_exact_unreconciled_in_process_payment_cancel_graph_"
            "and_allowed_delta_v1"
        ),
    }
    assert capability["recovery"] == {
        "method": "manual_escalation_after_terminal_payment_cancel",
    }
    assert capability["evidence"] == {"level": "declared", "receipts": []}
    assert capability.get("staged_environments", []) == []
    assert capability["enabled_environments"] == []
    assert set(properties) == EXPECTED_INPUT_FIELDS["acct.payment.cancel.v1"]
    assert set(schema["required"]) == set(properties)
    assert schema["additionalProperties"] is False

    for name in (
        "company_id", "payment_id", "move_id", "expected_partner_id",
        "expected_currency_id", "expected_journal_id",
        "expected_payment_method_line_id",
    ):
        assert properties[name] == {"type": "integer", "minimum": 1}
    assert properties["expected_payment_state"]["enum"] == ["in_process"]
    assert properties["expected_move_state"]["enum"] == ["posted"]
    assert properties["expected_partner_type"]["enum"] == [
        "customer", "supplier",
    ]
    assert properties["expected_direction"]["enum"] == [
        "inbound", "outbound",
    ]
    assert properties["expected_is_sent"] == {
        "type": "boolean", "enum": [True],
    }
    assert properties["expected_line_ids"] == {
        "type": "array", "minItems": 2, "maxItems": 2,
        "uniqueItems": True, "items": {"type": "integer", "minimum": 1},
    }
    assert capability["output_schema"] == writes[
        BASELINE_WRITE_IDS[0]
    ]["output_schema"]

    for field, value in (
        ("expected_payment_state", "paid"),
        ("expected_move_state", "draft"),
        ("expected_partner_type", "employee"),
        ("expected_direction", "transfer"),
        ("expected_amount", "0"),
        ("expected_is_sent", False),
        ("expected_line_ids", [3001]),
        ("expected_line_ids", [3001, 3001]),
    ):
        invalid = copy.deepcopy(VALID_INPUTS["acct.payment.cancel.v1"])
        invalid[field] = value
        with pytest.raises(ContractError):
            validate_value(invalid, schema)


def test_reconciliation_undo_contract_is_receipt_bound_and_disabled():
    writes = _writes()
    capability = writes["acct.reconciliation.undo.v1"]
    schema = capability["input_schema"]
    properties = schema["properties"]

    assert capability["risk_level"] == "critical"
    assert capability["odoo_permissions"] == ["account.group_account_manager"]
    assert capability["company_scope"] == "explicit_single_company"
    assert capability["approval"] == {
        "required": True, "policy": "reconciliation_undo", "ttl_seconds": 600,
    }
    assert capability["idempotency"] == {
        "required": True, "scope": "company_origin_operation",
    }
    description = capability["business_description"]
    for phrase in (
        "completed, verified, and database-finalized",
        "acct.reconciliation.apply.v1",
        "retained V3 release",
        "already contained this receipt-bound facade",
        "reject legacy",
    ):
        assert phrase in description
    assert capability["verification"] == {
        "method": (
            "read_back_receipt_bound_complete_reconciliation_graph_undo_"
            "and_writeoff_reversal_v1"
        ),
    }
    assert capability["recovery"] == {
        "method": (
            "manual_escalation_if_receipt_bound_reconciliation_undo_fails"
        ),
    }
    assert capability["evidence"] == {"level": "declared", "receipts": []}
    assert capability.get("staged_environments", []) == []
    assert capability["enabled_environments"] == []
    assert set(properties) == EXPECTED_INPUT_FIELDS[
        "acct.reconciliation.undo.v1"
    ]
    assert set(schema["required"]) == set(properties)
    assert schema["additionalProperties"] is False
    assert properties["company_id"] == {"type": "integer", "minimum": 1}
    assert properties["expected_origin_revision"] == {
        "type": "integer", "minimum": 1, "maximum": 2147483647,
    }
    for name in (
        "expected_origin_final_receipt_body_digest",
        "expected_recovery_plan_digest",
    ):
        assert properties[name] == {
            "type": "string", "minLength": 64, "maxLength": 64,
            "pattern": "^[0-9a-f]{64}$",
        }
    assert capability["output_schema"] == writes[
        BASELINE_WRITE_IDS[0]
    ]["output_schema"]

    for field, value in (
        ("origin_operation_id", ""),
        ("expected_origin_revision", 0),
        ("expected_origin_revision", -1),
        ("expected_origin_revision", True),
        ("expected_origin_final_receipt_body_digest", "A" * 64),
        ("expected_recovery_plan_digest", "c" * 63),
        ("recovery_date", "20260716"),
        ("reason", " "),
    ):
        invalid = copy.deepcopy(VALID_INPUTS["acct.reconciliation.undo.v1"])
        invalid[field] = value
        with pytest.raises(ContractError):
            validate_value(invalid, schema)

    injected = copy.deepcopy(VALID_INPUTS["acct.reconciliation.undo.v1"])
    injected["line_ids"] = [301, 302]
    with pytest.raises(ContractError):
        validate_value(injected, schema)


def test_bank_statement_compensate_contract_is_exact_declared_and_disabled():
    writes = _writes()
    capability = writes["acct.bank.statement_compensate.v1"]
    schema = capability["input_schema"]
    properties = schema["properties"]

    assert capability["risk_level"] == "critical"
    assert capability["odoo_permissions"] == ["account.group_account_manager"]
    assert capability["company_scope"] == "explicit_single_company"
    assert capability["approval"] == {
        "required": True,
        "policy": "bank_statement_compensate",
        "ttl_seconds": 600,
    }
    assert capability["idempotency"] == {
        "required": True,
        "scope": "company_origin_operation",
    }
    description = capability["business_description"]
    for phrase in (
        "independent whole-batch compensating bank statement",
        "completed, verified, and database-finalized",
        "acct.bank.statement_import.v1",
        "exact retained V3 release",
        "exact available recovery plan",
        "preserve the origin statement, lines, and moves",
        "reject deletion, subset or partial compensation",
        "reconciled or bank-matched lines",
        "Current production-routed imports do not produce a qualifying available plan",
    ):
        assert phrase in description
    assert capability["verification"] == {
        "method": (
            "read_back_receipt_bound_complete_bank_statement_graph_and_"
            "independent_whole_batch_compensation_v1"
        ),
    }
    assert capability["recovery"] == {
        "method": (
            "manual_escalation_if_receipt_bound_bank_statement_"
            "compensation_fails"
        ),
    }
    assert capability["evidence"] == {"level": "declared", "receipts": []}
    assert capability.get("staged_environments", []) == []
    assert capability["enabled_environments"] == []
    assert set(properties) == EXPECTED_INPUT_FIELDS[
        "acct.bank.statement_compensate.v1"
    ]
    assert set(schema["required"]) == set(properties)
    assert schema["additionalProperties"] is False
    for name in (
        "company_id",
        "expected_statement_id",
        "expected_journal_id",
        "expected_currency_id",
    ):
        assert properties[name] == {"type": "integer", "minimum": 1}
    assert properties["expected_origin_revision"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 2147483647,
    }
    for name in (
        "expected_origin_final_receipt_body_digest",
        "expected_recovery_plan_digest",
        "expected_source_digest",
    ):
        assert properties[name] == {
            "type": "string",
            "minLength": 64,
            "maxLength": 64,
            "pattern": "^[0-9a-f]{64}$",
        }
    assert capability["output_schema"] == writes[
        BASELINE_WRITE_IDS[0]
    ]["output_schema"]

    for field, value in (
        ("origin_operation_id", ""),
        ("expected_origin_revision", 0),
        ("expected_origin_revision", True),
        ("expected_origin_final_receipt_body_digest", "A" * 64),
        ("expected_recovery_plan_digest", "e" * 63),
        ("expected_statement_id", 0),
        ("expected_journal_id", False),
        ("expected_currency_id", -1),
        ("expected_source_digest", "f" * 65),
        ("compensation_date", "20260716"),
        ("reason", " "),
    ):
        invalid = copy.deepcopy(
            VALID_INPUTS["acct.bank.statement_compensate.v1"]
        )
        invalid[field] = value
        with pytest.raises(ContractError):
            validate_value(invalid, schema)

    injected = copy.deepcopy(
        VALID_INPUTS["acct.bank.statement_compensate.v1"]
    )
    injected["line_ids"] = [301, 302]
    with pytest.raises(ContractError):
        validate_value(injected, schema)


def test_write_inputs_have_exact_complete_fields_and_no_placeholders():
    writes = _writes()
    for capability_id, expected in EXPECTED_INPUT_FIELDS.items():
        schema = writes[capability_id]["input_schema"]
        assert set(schema["properties"]) == expected
        assert set(schema["required"]) == expected
        _assert_schema_is_bounded_and_non_placeholder(schema)


def test_write_outputs_share_one_strict_auditable_shape():
    writes = _writes()
    first = writes[WRITE_IDS[0]]["output_schema"]
    assert set(first["properties"]) == EXPECTED_OUTPUT_FIELDS
    assert set(first["required"]) == EXPECTED_OUTPUT_FIELDS
    assert first["properties"]["operation_state"]["enum"] == [
        "completed", "failed",
    ]
    for capability_id in WRITE_IDS:
        schema = writes[capability_id]["output_schema"]
        assert schema == first
        _assert_schema_is_bounded_and_non_placeholder(schema)
        snapshots = schema["properties"]["difference"]["properties"]
        for name in ("before", "after"):
            item = snapshots[name]["items"]
            assert set(item["properties"]) == EXPECTED_SNAPSHOT_FIELDS
            assert set(item["required"]) == EXPECTED_SNAPSHOT_FIELDS
        audit = schema["properties"]["audit_receipt"]
        assert set(audit["properties"]) == EXPECTED_AUDIT_FIELDS
        assert set(audit["required"]) == EXPECTED_AUDIT_FIELDS
        record_ref = schema["properties"]["odoo_records"]["items"]
        assert set(record_ref["properties"]) == EXPECTED_RECORD_REF_FIELDS
        difference = schema["properties"]["difference"]
        assert set(difference["properties"]) == EXPECTED_DIFFERENCE_FIELDS
        verification = schema["properties"]["verification"]
        assert set(verification["properties"]) == EXPECTED_VERIFICATION_FIELDS
        recovery = schema["properties"]["recovery_plan"]
        assert set(recovery) == {"oneOf"}
        assert len(recovery["oneOf"]) == 2
        historical, guarded = recovery["oneOf"]
        assert set(historical["properties"]) == EXPECTED_RECOVERY_PLAN_V1_FIELDS
        assert set(historical["required"]) == EXPECTED_RECOVERY_PLAN_V1_FIELDS
        assert set(guarded["properties"]) == EXPECTED_RECOVERY_PLAN_V2_FIELDS
        assert set(guarded["required"]) == EXPECTED_RECOVERY_PLAN_V2_FIELDS
        assert guarded["properties"]["plan_version"] == {
            "type": "integer", "enum": [2], "minimum": 2, "maximum": 2,
        }
        assert set(
            guarded["properties"]["guard_records"]["items"]["properties"]
        ) == EXPECTED_RECOVERY_GUARD_FIELDS
        assert guarded["properties"]["guard_records"]["items"]["properties"][
            "expected_outcome"
        ]["enum"] == [
            "survive_exact", "survive_allowed_delta", "absent", "manual_review",
        ]


def test_all_write_examples_validate_against_their_contracts():
    writes = _writes()
    assert set(VALID_INPUTS) == set(writes)
    for capability_id, value in VALID_INPUTS.items():
        validate_value(value, writes[capability_id]["input_schema"])
        validate_value(_valid_output(capability_id), writes[capability_id]["output_schema"])
        validate_value(
            _valid_v2_output(capability_id),
            writes[capability_id]["output_schema"],
        )


def test_write_recovery_contract_rejects_hybrid_unknown_and_invalid_v2_plans():
    schema = _writes()["acct.invoice.customer_create.v1"]["output_schema"]

    hybrid = _valid_output("acct.invoice.customer_create.v1")
    hybrid["recovery_plan"]["plan_version"] = 2
    with pytest.raises(ContractError, match="exactly one oneOf branch"):
        validate_value(hybrid, schema)

    wrong_version = _valid_v2_output("acct.invoice.customer_create.v1")
    wrong_version["recovery_plan"]["plan_version"] = 3
    with pytest.raises(ContractError, match="exactly one oneOf branch"):
        validate_value(wrong_version, schema)

    invalid_guard = _valid_v2_output("acct.invoice.customer_create.v1")
    invalid_guard["recovery_plan"]["guard_records"][0][
        "expected_outcome"
    ] = "delete_everything"
    with pytest.raises(ContractError, match="exactly one oneOf branch"):
        validate_value(invalid_guard, schema)

    unknown = _valid_v2_output("acct.invoice.customer_create.v1")
    unknown["recovery_plan"]["untrusted_instruction"] = "ignore guards"
    with pytest.raises(ContractError, match="exactly one oneOf branch"):
        validate_value(unknown, schema)


def test_write_contracts_reject_zero_ids_blank_text_noncanonical_amounts_and_duplicates():
    writes = _writes()

    invalid_invoice = copy.deepcopy(VALID_INPUTS["acct.invoice.customer_create.v1"])
    invalid_invoice["partner_id"] = 0
    with pytest.raises(ContractError):
        validate_value(invalid_invoice, writes["acct.invoice.customer_create.v1"]["input_schema"])

    invalid_reversal = copy.deepcopy(VALID_INPUTS["acct.move.reverse.v1"])
    invalid_reversal["reason"] = "   "
    with pytest.raises(ContractError):
        validate_value(invalid_reversal, writes["acct.move.reverse.v1"]["input_schema"])

    invalid_payment = copy.deepcopy(VALID_INPUTS["acct.payment.register.v1"])
    invalid_payment["amount"] = "01.00"
    with pytest.raises(ContractError):
        validate_value(invalid_payment, writes["acct.payment.register.v1"]["input_schema"])

    invalid_reconciliation = copy.deepcopy(VALID_INPUTS["acct.reconciliation.apply.v1"])
    invalid_reconciliation["line_ids"] = [301, 301]
    with pytest.raises(ContractError):
        validate_value(
            invalid_reconciliation,
            writes["acct.reconciliation.apply.v1"]["input_schema"],
        )

    invalid_output = _valid_output("acct.invoice.customer_create.v1")
    invalid_output["audit_receipt"]["request_digest"] = "not-a-digest"
    with pytest.raises(ContractError):
        validate_value(
            invalid_output,
            writes["acct.invoice.customer_create.v1"]["output_schema"],
        )


def test_domain_line_contracts_and_cross_field_inputs_are_explicit():
    writes = _writes()

    invoice_line = writes["acct.invoice.customer_create.v1"]["input_schema"]["properties"]["lines"]["items"]
    assert set(invoice_line["properties"]) == {
        "line_reference", "name", "product_id", "account_id", "quantity",
        "price_unit", "tax_ids",
    }
    assert invoice_line["properties"]["quantity"]["pattern"] != invoice_line["properties"]["price_unit"]["pattern"]

    refund_lines = writes["acct.refund.create.v1"]["input_schema"]["properties"]["lines"]
    assert refund_lines["minItems"] == 0
    assert set(refund_lines["items"]["properties"]) == {
        "line_reference", "name", "account_id", "quantity", "price_unit", "tax_ids",
    }

    bank_line = writes["acct.bank.statement_import.v1"]["input_schema"]["properties"]["lines"]["items"]
    assert writes["acct.bank.statement_import.v1"]["input_schema"]["properties"][
        "lines"
    ]["maxItems"] == 200
    assert writes["acct.bank.statement_import.v1"]["input_schema"]["properties"][
        "external_reference"
    ]["maxLength"] == 255
    assert set(bank_line["properties"]) == {
        "external_transaction_id", "transaction_date", "value_date", "direction",
        "amount", "foreign_currency_id", "foreign_amount", "summary", "partner_id",
        "source_line_digest",
    }
    assert "currency_id" not in bank_line["properties"]
    assert "null" in bank_line["properties"]["foreign_currency_id"]["type"]
    assert "null" in bank_line["properties"]["foreign_amount"]["type"]

    for capability_id in (
        "acct.accrual.create.v1",
        "acct.period.adjustment_create.v1",
        "acct.journal.entry_create.v1",
    ):
        line = writes[capability_id]["input_schema"]["properties"]["lines"]["items"]
        assert set(line["properties"]) == {
            "line_reference", "account_id", "partner_id", "currency_id", "name",
            "side", "amount", "amount_currency", "tax_ids",
        }
        assert line["properties"]["amount"]["pattern"] != line["properties"]["amount_currency"]["pattern"]

    recovery = writes["acct.recovery.execute.v1"]["input_schema"]
    assert set(recovery["properties"]) == EXPECTED_INPUT_FIELDS["acct.recovery.execute.v1"]
    assert not {"recovery_action", "target_records", "journal_id"} & set(recovery["properties"])

    depreciation = writes["acct.depreciation.post.v1"]["input_schema"]
    assert "depreciation_move_id" in depreciation["properties"]
    assert "depreciation_line_id" not in depreciation["properties"]
    assert writes["acct.depreciation.post.v1"]["idempotency"] == {
        "required": True,
        "scope": "company_depreciation_move",
    }

    deferred = writes["acct.deferred.create.v1"]["input_schema"]
    assert not {
        "deferred_model_id", "recognition_frequency", "recognition_day",
    } & set(deferred["properties"])
    assert deferred["properties"]["expected_generation_method"]["enum"] == [
        "on_validation"
    ]
    assert deferred["properties"]["amount_computation_method"]["enum"] == [
        "day", "month", "full_months"
    ]
    assert deferred["properties"]["posting_mode"]["enum"] == ["post"]

    accrual = writes["acct.accrual.create.v1"]["input_schema"]
    assert accrual["properties"]["posting_mode"]["enum"] == ["post"]

    reversal = writes["acct.move.reverse.v1"]["input_schema"]
    assert reversal["properties"]["posting_mode"]["enum"] == ["post"]

    draft_cancel = writes["acct.move.draft_cancel.v1"]
    assert draft_cancel["input_schema"]["properties"]["expected_move_type"][
        "enum"
    ] == ["out_invoice", "in_invoice"]
    assert draft_cancel["idempotency"] == {
        "required": True,
        "scope": "company_origin_move",
    }
    assert draft_cancel["enabled_environments"] == []
    assert draft_cancel.get("staged_environments", []) == []

    assert writes["acct.bank.statement_import.v1"]["recovery"][
        "method"
    ].startswith("manual_escalation_")
    assert writes["acct.payment.register.v1"]["recovery"] == {
        "method": (
            "manual_escalation_until_exact_payment_compensation_is_"
            "sandbox_verified"
        )
    }
    assert writes["acct.reconciliation.apply.v1"]["recovery"][
        "method"
    ].startswith("manual_escalation_")
    assert writes["acct.payment.register.v1"]["verification"]["method"].startswith(
        "read_back_exact_payment_move_full_reconcile_graph_"
    )
    assert writes["acct.bank.statement_import.v1"]["verification"][
        "method"
    ].startswith("read_back_exact_statement_line_move_graph_company_balances_")
    assert writes["acct.reconciliation.apply.v1"]["verification"][
        "method"
    ].startswith("read_back_exact_source_parent_moves_lines_partial_full_")


def test_period_reversal_and_recovery_metadata_do_not_overclaim_automation():
    writes = _writes()
    assert writes["acct.accrual.create.v1"]["verification"] == {
        "method": (
            "read_back_exact_accrual_and_scheduled_reversal_graph_lines_"
            "links_balances_content_and_business_bindings_v1"
        )
    }
    assert writes["acct.accrual.create.v1"]["recovery"] == {
        "method": "manual_escalation_review_accrual_schedule"
    }
    assert writes["acct.period.adjustment_create.v1"]["verification"] == {
        "method": (
            "read_back_exact_period_adjustment_graph_lines_metadata_balance_"
            "and_binding_v1"
        )
    }
    assert writes["acct.period.adjustment_create.v1"]["recovery"] == {
        "method": "manual_escalation_review_period_adjustment"
    }
    assert writes["acct.move.reverse.v1"]["verification"] == {
        "method": (
            "read_back_approved_origin_unchanged_and_exact_reversal_graph_"
            "links_lines_balances_binding_v1"
        )
    }
    assert writes["acct.move.reverse.v1"]["recovery"] == {
        "method": "manual_escalation_review_move_reversal"
    }

    draft_cancel = writes["acct.move.draft_cancel.v1"]
    assert "normal approved write state machine" in draft_cancel[
        "business_description"
    ]
    assert draft_cancel["verification"] == {
        "method": (
            "read_back_exact_pristine_draft_cancel_graph_bindings_and_"
            "allowlisted_state_audit_delta_v1"
        )
    }
    assert draft_cancel["recovery"] == {
        "method": "not_applicable_pristine_draft_cancel_is_terminal"
    }

    recovery = writes["acct.recovery.execute.v1"]
    assert "failed-verification accounting incident" in recovery[
        "business_description"
    ]
    assert "distinct approved operation" in recovery["business_description"]
    assert "completed origins" in recovery["business_description"]
    assert recovery["verification"] == {
        "method": (
            "read_back_trusted_plan_target_fingerprints_and_action_specific_"
            "compensation_state_v1"
        )
    }
    assert recovery["recovery"] == {
        "method": (
            "manual_escalation_if_separate_compensating_operation_fails"
        )
    }


def test_asset_and_deferred_require_enterprise_canonical_schedule_evidence_before_staging():
    writes = _writes()
    for capability_id in (
        "acct.asset.create.v1",
        "acct.deferred.create.v1",
    ):
        capability = writes[capability_id]
        assert "staging stays blocked" in capability["business_description"]
        assert "enterprise_canonical_receipt_required_before_staging" in (
            capability["verification"]["method"]
        )
        assert capability["evidence"] == {"level": "declared", "receipts": []}
        assert capability.get("staged_environments", []) == []
        assert capability["enabled_environments"] == []

    assert writes["acct.depreciation.post.v1"]["verification"] == {
        "method": (
            "read_back_approved_full_schedule_graph_allowlisted_posting_delta_"
            "accounts_balances_residual_and_book_value_v1"
        )
    }


def test_document_and_refund_metadata_match_strict_graph_verifiers_and_manual_recovery():
    writes = _writes()
    for capability_id in (
        "acct.invoice.customer_create.v1",
        "acct.bill.vendor_create.v1",
    ):
        assert writes[capability_id]["verification"]["method"].startswith(
            "read_back_exact_move_lines_tax_preview_single_due_residual_"
        )
        assert writes[capability_id]["recovery"]["method"].startswith(
            "manual_escalation_until_exact_"
        )
    refund = writes["acct.refund.create.v1"]
    assert refund["verification"] == {
        "method": (
            "read_back_approved_origin_exact_refund_graph_lines_tax_due_"
            "residual_and_bindings_v1"
        )
    }
    assert refund["recovery"]["method"].startswith(
        "manual_escalation_until_exact_refund_"
    )


def test_write_batch_limits_fit_the_precommit_audit_graph_budget():
    writes = _writes()
    for capability_id in (
        "acct.invoice.customer_create.v1",
        "acct.bill.vendor_create.v1",
        "acct.refund.create.v1",
    ):
        lines = writes[capability_id]["input_schema"]["properties"]["lines"]
        assert lines["maxItems"] == 32
        assert lines["items"]["properties"]["tax_ids"]["maxItems"] == 8
    assert writes["acct.payment.register.v1"]["input_schema"]["properties"][
        "target_move_ids"
    ]["maxItems"] == 100
    assert writes["acct.reconciliation.apply.v1"]["input_schema"]["properties"][
        "line_ids"
    ]["maxItems"] == 200
    for capability_id in (
        "acct.accrual.create.v1",
        "acct.period.adjustment_create.v1",
        "acct.journal.entry_create.v1",
    ):
        assert writes[capability_id]["input_schema"]["properties"]["lines"][
            "maxItems"
        ] == 250


def test_schema_boundaries_allow_zero_unit_price_and_failed_verification_but_not_zero_amount():
    writes = _writes()

    zero_price = copy.deepcopy(VALID_INPUTS["acct.invoice.customer_create.v1"])
    zero_price["lines"][0]["price_unit"] = "0"
    validate_value(zero_price, writes["acct.invoice.customer_create.v1"]["input_schema"])

    zero_quantity = copy.deepcopy(zero_price)
    zero_quantity["lines"][0]["quantity"] = "0"
    with pytest.raises(ContractError):
        validate_value(zero_quantity, writes["acct.invoice.customer_create.v1"]["input_schema"])

    zero_payment = copy.deepcopy(VALID_INPUTS["acct.payment.register.v1"])
    zero_payment["amount"] = "0"
    with pytest.raises(ContractError):
        validate_value(zero_payment, writes["acct.payment.register.v1"]["input_schema"])

    negative_zero_balance = copy.deepcopy(VALID_INPUTS["acct.bank.statement_import.v1"])
    negative_zero_balance["opening_balance"] = "-0.00"
    with pytest.raises(ContractError):
        validate_value(
            negative_zero_balance,
            writes["acct.bank.statement_import.v1"]["input_schema"],
        )

    debit_foreign = copy.deepcopy(
        VALID_INPUTS["acct.bank.statement_import.v1"]
    )
    debit_foreign["closing_balance"] = "-100.00"
    debit_foreign["lines"][0].update(
        {
            "direction": "debit",
            "foreign_currency_id": 13,
            "foreign_amount": "-75.00",
        }
    )
    validate_value(
        debit_foreign,
        writes["acct.bank.statement_import.v1"]["input_schema"],
    )

    failed_output = _valid_output("acct.payment.register.v1")
    failed_output["operation_state"] = "failed"
    failed_output["odoo_records"] = []
    failed_output["difference"]["before"] = []
    failed_output["difference"]["after"] = []
    failed_output["difference"]["changed_fields"] = []
    failed_output["verification"]["passed"] = False
    failed_output["database_finalization"] = None
    validate_value(failed_output, writes["acct.payment.register.v1"]["output_schema"])


def test_registry_loader_accepts_the_hardened_write_contracts():
    capabilities = load_registry(REGISTRY_PATH)
    assert {item.id for item in capabilities if item.data["access"] == "write"} == set(WRITE_IDS)


def test_registered_write_capabilities_are_bound_to_control_and_odoo_layers():
    registered_write_ids = {
        item.id
        for item in load_registry(REGISTRY_PATH)
        if item.data["access"] == "write"
    }

    assert registered_write_ids == set(WRITE_IDS)
    assert set(_ALLOWED_MODELS) == registered_write_ids
    assert ODOO_WRITE_CAPABILITIES == registered_write_ids
    for capability_id, models in _ALLOWED_MODELS.items():
        assert models, f"{capability_id} has no auditable Odoo model allowlist"
        assert all(model.startswith("account.") for model in models)

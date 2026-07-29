from __future__ import annotations

from datetime import date
from decimal import Decimal
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo.write_handlers import (
    _RECOVERY_ACTIONS,
    _SNAPSHOT_FIELDS,
    _snapshot_primitive,
    OdooWriteContext,
    OdooWriteHandlerError,
    OdooWriteHandlers,
)
from odoo_accounting_cli_v3.odoo.module_graph import (
    OPTIONAL_FIELD_PROVIDERS,
    build_trusted_module_graph,
)
from odoo_accounting_cli_v3.odoo.write_bootstrap import _execution_evidence
from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.registry import load_registry
from odoo_accounting_cli_v3.write_service import (
    _ALLOWED_MODELS,
    DurableWriteService,
)
from odoo_accounting_cli_v3.write_receipts import (
    create_record_snapshot,
    create_recovery_plan_v2,
    validate_executable_recovery_plan,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "odoo_accounting_cli_v3" / "odoo" / "write_handlers.py"
_TEST_MODULE_NAMES = {
    "account",
    *(
        module
        for fields in OPTIONAL_FIELD_PROVIDERS.values()
        for providers in fields.values()
        for module in providers
    ),
}
TEST_MODULE_GRAPH = build_trusted_module_graph(
    [
        {"name": name, "latest_version": "19.0.test"}
        for name in sorted(_TEST_MODULE_NAMES)
    ]
)


@pytest.mark.parametrize(
    "field",
    [
        "access_token",
        "invoice_pdf_report_file",
        "l10n_es_edi_facturae_xml_file",
        "signature",
        "ubl_cii_xml_file",
    ],
)
def test_sensitive_snapshot_fields_never_emit_raw_content(field):
    raw = "super-secret-pdf-or-token-content"

    assert _snapshot_primitive(field, raw) == {"present": True}
    assert raw.encode("utf-8") not in canonical_json(
        _snapshot_primitive(field, raw)
    )
    assert _snapshot_primitive(field, False) == {"present": False}


class Record:
    def __init__(self, identifier: int, **values):
        self.id = identifier
        self.ids = [identifier]
        self.access = []
        self.writes = []
        self.contexts = []
        self.action_post_calls = 0
        self.lock_date_checks = []
        self.tax_effect_checks = 0
        for key, value in values.items():
            setattr(self, key, value)

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def __iter__(self):
        return iter([self])

    def exists(self):
        return self

    def check_access_rights(self, operation):
        self.access.append(("rights", operation))

    def check_access_rule(self, operation):
        self.access.append(("rule", operation))

    def write(self, values):
        self.writes.append(values)
        for key, value in values.items():
            setattr(self, key, value)
        return True

    def with_context(self, **values):
        self.contexts.append(values)
        return self

    def action_post(self):
        self.action_post_calls += 1
        self.state = "posted"
        return False

    def _get_violated_lock_dates(self, accounting_date, *args):
        self.lock_date_checks.append((accounting_date, *args))
        return list(getattr(self, "violated_lock_dates", []))

    def _affect_tax_report(self):
        self.tax_effect_checks += 1
        return getattr(self, "affects_tax_report", False)


class Model:
    def __init__(self, records=None, factory=None):
        self.records = records or {}
        self.factory = factory
        self.access = []
        self.contexts = []
        self.companies = []
        self.creates = []

    def with_context(self, *args, **kwargs):
        self.contexts.append((args, kwargs))
        return self

    def with_company(self, company):
        self.companies.append(company.id)
        return self

    def check_access_rights(self, operation):
        self.access.append(operation)

    def browse(self, identifier):
        return self.records.get(identifier, EmptyRecord())

    def create(self, values):
        self.creates.append(values)
        if self.factory:
            return self.factory(values)
        raise AssertionError("unexpected create")


class EmptyRecord:
    ids = []

    def __bool__(self):
        return False

    def __len__(self):
        return 0

    def exists(self):
        return self


class Env:
    def __init__(self, models, *, uid=42, su=False):
        self.models = models
        self.uid = uid
        self.su = su

    def __getitem__(self, model):
        return self.models[model]


def context(
    env=None,
    *,
    recovery_plan=None,
    environment="sandbox",
    module_graph=TEST_MODULE_GRAPH,
):
    return OdooWriteContext(
        env=env or Env({}),
        user_id=42,
        allowed_company_ids=frozenset({7}),
        today=date(2026, 7, 15),
        environment=environment,
        module_graph=module_graph,
        trusted_recovery_plan=recovery_plan,
    )


def company(**values):
    defaults = {
        "currency_id": Record(1),
        "hard_lock_date": None,
        "fiscalyear_lock_date": None,
        "tax_lock_date": None,
        "sale_lock_date": None,
        "purchase_lock_date": None,
        "violated_lock_dates": [],
    }
    defaults.update(values)
    return Record(7, **defaults)


class Harness(OdooWriteHandlers):
    def __init__(
        self,
        *,
        models=None,
        records=None,
        recovery_plan=None,
        environment="sandbox",
        module_graph=TEST_MODULE_GRAPH,
    ):
        self.context = context(
            recovery_plan=recovery_plan,
            environment=environment,
            module_graph=module_graph,
        )
        self.models = models or {}
        self.records = records or {}
        self.test_company = company()

    def company(self, company_id):
        assert company_id == 7
        return self.test_company

    def create_model(self, model_name, company, *, context=None):
        model = self.models[model_name]
        if context:
            model.with_context(**context)
        model.check_access_rights("create")
        return model

    def record(self, model_name, record_id, company, *, write=False, shared=False):
        return self.records[(model_name, record_id)]

    def search_records(self, model_name, domain, company, *, limit=1):
        return []

    def require_created(self, record, model_name, company):
        assert record.id > 0

    def snapshots(self, records, company, *, required_fields_by_model=None):
        required_fields_by_model = required_fields_by_model or {}
        return [
            self.snapshot(
                model,
                record,
                company,
                required_fields=required_fields_by_model.get(model, ()),
            )
            for model, record in records
        ]

    def snapshot(self, model, record, company, *, required_fields=()):
        values = dict(getattr(record, "snapshot_values", {}))
        return {
            "model": model,
            "record_id": record.id,
            "company_id": company.id,
            "state": str(getattr(record, "state", "unknown") or "unknown"),
            "values": values,
            "values_digest": hashlib.sha256(canonical_json(values)).hexdigest(),
        }


def recovery_target(model_name, record):
    handler = Harness()
    raw = handler.snapshot(model_name, record, handler.test_company)
    snapshot = create_record_snapshot(
        model=model_name,
        record_id=record.id,
        exists=True,
        record_state=raw["state"],
        values=raw["values"],
    )
    return {
        "model": model_name,
        "record_id": record.id,
        "company_id": handler.test_company.id,
        "record_state": raw["state"],
        "record_fingerprint": hashlib.sha256(canonical_json(snapshot)).hexdigest(),
    }


def executable_recovery_plan(
    *,
    origin_operation_id="op-1",
    action_targets,
    guard_records,
    method="cancel_pristine_v3_draft_customer_invoice_v1",
    oracle_id="cancel_pristine_v3_draft_customer_invoice_exact_v1",
    expected_outcome="survive_allowed_delta",
):
    ordered_action_identities = sorted(
        (
            {"model": record["model"], "record_id": record["record_id"]}
            for record in action_targets
        ),
        key=lambda item: (item["model"], item["record_id"]),
    )
    ordered_guard_identities = sorted(
        (
            {"model": record["model"], "record_id": record["record_id"]}
            for record in guard_records
        ),
        key=lambda item: (item["model"], item["record_id"]),
    )
    return create_recovery_plan_v2(
        origin_operation_id=origin_operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=method,
        requires_approval=True,
        action_targets=action_targets,
        guard_records=[
            {**record, "expected_outcome": expected_outcome}
            for record in guard_records
        ],
        oracle_id=oracle_id,
        parameters={
            "company_id": 7,
            "origin_operation_id": origin_operation_id,
            "module_graph_digest": TEST_MODULE_GRAPH.digest,
            "method": method,
            "action_targets": ordered_action_identities,
            "guard_records": ordered_guard_identities,
            "oracle_id": oracle_id,
        },
    )


def payment_binding(
    *, payment_id=None, payment_move_id=None, payment_line_ids=None,
    amount="50",
):
    return {
        "version": 1,
        "payment_id": payment_id,
        "payment_move_id": payment_move_id,
        "payment_line_ids": list(payment_line_ids or []),
        "target_move_ids": [11],
        "target_before": [{"move_id": 11, "amount_residual": "100"}],
        "target_line_before": [
            {
                "line_id": 111,
                "move_id": 11,
                "amount_residual": "100",
                "amount_residual_currency": "100",
                "reconciled": False,
                "full_reconcile_id": None,
                "matched_debit_ids": [],
                "matched_credit_ids": [],
            }
        ],
        "total_residual": "100",
        "amount": str(amount),
        "partner_id": 10,
        "partner_type": "customer",
        "direction": "inbound",
        "payment_date": "2026-07-10",
        "currency_id": 1,
        "journal_id": 2,
        "payment_method_line_id": 3,
        "memo": "PAY-1",
    }


def bank_parameters_for_handler():
    return {
        "company_id": 7,
        "journal_id": 2,
        "currency_id": 1,
        "statement_date": "2026-07-10",
        "external_reference": "BANK-2026-07-10",
        "opening_balance": "5",
        "closing_balance": "12",
        "source_digest": "a" * 64,
        "source_filename": "bank.csv",
        "lines": [
            {
                "direction": "credit",
                "amount": "10",
                "transaction_date": "2026-07-10",
                "summary": "in",
                "external_transaction_id": "T1",
                "source_line_digest": "b" * 64,
                "value_date": "2026-07-10",
                "partner_id": None,
                "foreign_currency_id": None,
                "foreign_amount": None,
            },
            {
                "direction": "debit",
                "amount": "3",
                "transaction_date": "2026-07-10",
                "summary": "out",
                "external_transaction_id": "T2",
                "source_line_digest": "c" * 64,
                "value_date": "2026-07-10",
                "partner_id": None,
                "foreign_currency_id": None,
                "foreign_amount": None,
            },
        ],
    }


def bank_graph_harness():
    comp = company()
    currency = Record(1, company_id=None, active=True, rounding="0.01")
    liquidity_account = Record(901, company_id=comp)
    suspense_account = Record(902, company_id=comp)
    journal = Record(
        2,
        company_id=comp,
        currency_id=currency,
        default_account_id=liquidity_account,
        suspense_account_id=suspense_account,
    )
    records = {
        ("res.currency", 1): currency,
        ("account.account", 901): liquidity_account,
        ("account.account", 902): suspense_account,
    }
    created_lines = []

    def create_line(values):
        index = len(created_lines)
        line_id = 401 + index
        move_id = 491 + index
        amount = Decimal(str(values["amount"]))
        liquidity = Record(
            601 + index * 2,
            company_id=comp,
            move_id=Record(move_id),
            account_id=liquidity_account,
            debit=max(amount, Decimal("0")),
            credit=max(-amount, Decimal("0")),
            balance=amount,
            amount_currency=amount,
            currency_id=currency,
        )
        foreign_currency = (
            Record(
                values["foreign_currency_id"],
                company_id=None,
                active=True,
                rounding="0.01",
            )
            if values.get("foreign_currency_id")
            else None
        )
        if foreign_currency is not None:
            records[("res.currency", foreign_currency.id)] = foreign_currency
        suspense = Record(
            602 + index * 2,
            company_id=comp,
            move_id=Record(move_id),
            account_id=suspense_account,
            debit=max(-amount, Decimal("0")),
            credit=max(amount, Decimal("0")),
            balance=-amount,
            amount_currency=(
                -Decimal(str(values["amount_currency"]))
                if foreign_currency is not None
                else -amount
            ),
            currency_id=foreign_currency or currency,
        )
        partner = Record(values["partner_id"]) if values.get("partner_id") else None
        move = Record(
            move_id,
            state="posted",
            company_id=comp,
            journal_id=journal,
            currency_id=foreign_currency or currency,
            partner_id=partner,
            date=values["date"],
            line_ids=[liquidity, suspense],
        )
        line = Record(
            line_id,
            state="posted",
            company_id=comp,
            journal_id=journal,
            currency_id=currency,
            statement_id=None,
            move_id=move,
            date=values["date"],
            amount=amount,
            amount_currency=values.get("amount_currency", False),
            foreign_currency_id=foreign_currency,
            partner_id=partner,
            payment_ref=values["payment_ref"],
            ref=values["ref"],
            transaction_details=values["transaction_details"],
            odoo_cli_v3_external_transaction_id=values[
                "odoo_cli_v3_external_transaction_id"
            ],
            odoo_cli_v3_source_line_digest=values[
                "odoo_cli_v3_source_line_digest"
            ],
            odoo_cli_v3_value_date=values["odoo_cli_v3_value_date"],
            is_reconciled=False,
            amount_residual=-amount,
            payment_ids=[],
            internal_index=f"20260710-{line_id}",
        )
        move.statement_line_id = line
        created_lines.append(line)
        records[("account.bank.statement.line", line_id)] = line
        records[("account.move", move_id)] = move
        records[("account.move.line", liquidity.id)] = liquidity
        records[("account.move.line", suspense.id)] = suspense
        return line

    def create_statement(values):
        statement = Record(
            390,
            company_id=comp,
            journal_id=journal,
            currency_id=currency,
            line_ids=list(created_lines),
            reference=values["reference"],
            date=max(line.date for line in created_lines),
            balance_start=values["balance_start"],
            balance_end=values["balance_end_real"],
            balance_end_real=values["balance_end_real"],
            is_complete=True,
            is_valid=True,
            odoo_cli_v3_external_reference=values[
                "odoo_cli_v3_external_reference"
            ],
            odoo_cli_v3_source_digest=values["odoo_cli_v3_source_digest"],
            odoo_cli_v3_source_filename=values["odoo_cli_v3_source_filename"],
        )
        for line in created_lines:
            line.statement_id = statement
        records[("account.bank.statement", statement.id)] = statement
        return statement

    line_model = Model(factory=create_line)
    statement_model = Model(factory=create_statement)
    handler = Harness(
        models={
            "account.bank.statement.line": line_model,
            "account.bank.statement": statement_model,
        },
        records=records,
    )
    handler.test_company = comp
    return handler, line_model, statement_model, created_lines


def test_source_has_no_privilege_or_transaction_escape_and_no_private_orm_calls():
    source = SOURCE.read_text(encoding="utf-8")
    for forbidden in (".sudo(", ".commit(", ".rollback("):
        assert forbidden not in source
    # Calls made on Odoo objects are all public. Private names may exist on our own helpers.
    assert "._create_payments(" not in source
    assert "._reverse_moves(" not in source
    assert "._generate_deferred_entries(" not in source
    assert "._post(" not in source
    assert ".remove_move_reconcile(" not in source


def test_all_twenty_three_registered_write_capabilities_have_three_real_dispatch_phases():
    baseline_identifiers = {
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
    }
    phase_b_identifiers = {
        "acct.journal.entry_create.v1",
        "acct.move.post.v1",
        "acct.move.draft_cancel.v2",
    }
    payment_close_identifiers = {
        "acct.payment.cancel.v1",
    }
    reconciliation_undo_identifiers = {
        "acct.reconciliation.undo.v1",
    }
    bank_compensation_identifiers = {
        "acct.bank.statement_compensate.v1",
    }
    document_lifecycle_identifiers = {
        "acct.invoice.customer_post.v1",
        "acct.bill.vendor_post.v1",
        "acct.refund.draft_cancel.v1",
    }
    identifiers = {
        capability.id
        for capability in load_registry(ROOT / "registry" / "capabilities.json")
        if capability.data["access"] == "write"
    }
    assert len(baseline_identifiers) == 14
    assert len(phase_b_identifiers) == 3
    assert len(payment_close_identifiers) == 1
    assert len(reconciliation_undo_identifiers) == 1
    assert len(bank_compensation_identifiers) == 1
    assert len(document_lifecycle_identifiers) == 3
    assert identifiers == (
        baseline_identifiers
        | phase_b_identifiers
        | payment_close_identifiers
        | reconciliation_undo_identifiers
        | bank_compensation_identifiers
        | document_lifecycle_identifiers
    )
    for identifier in sorted(identifiers):
        for phase in ("precheck", "execute", "verify"):
            assert callable(getattr(OdooWriteHandlers, OdooWriteHandlers.dispatch_name(identifier, phase)))


def test_environment_rejects_superuser_and_wrong_principal():
    with pytest.raises(OdooWriteHandlerError, match="non-superuser"):
        OdooWriteHandlers(context(Env({}, uid=42, su=True)))
    with pytest.raises(OdooWriteHandlerError, match="non-superuser"):
        OdooWriteHandlers(context(Env({}, uid=99, su=False)))


def test_record_lookup_enforces_model_and_record_acl_rules_and_company():
    comp = company()
    journal = Record(8, company_id=comp)
    model = Model({8: journal})
    handler = OdooWriteHandlers(context(Env({"account.journal": model})))
    result = handler.record("account.journal", 8, comp, write=True)
    assert result is journal
    assert model.access == ["read"]
    assert journal.access == [
        ("rights", "read"), ("rule", "read"),
        ("rights", "write"), ("rule", "write"),
    ]
    assert model.contexts[-1][1]["allowed_company_ids"] == [7]
    assert model.companies == [7]


def test_record_lookup_rejects_cross_company_and_non_unique_records():
    comp = company()
    foreign = Record(8, company_id=Record(9))
    handler = OdooWriteHandlers(context(Env({"account.journal": Model({8: foreign})})))
    with pytest.raises(OdooWriteHandlerError, match="another company"):
        handler.record("account.journal", 8, comp)


def test_snapshot_fails_closed_when_required_audit_fields_are_unavailable():
    comp = company()

    class PartialMove(Record):
        def fields_get(self, fields):
            return {"state": {"type": "selection"}}

        def read(self, fields):
            return [{"id": self.id, "state": self.state}]

    move = PartialMove(8, state="draft", company_id=comp)
    handler = OdooWriteHandlers(
        context(Env({"account.move": Model({8: move})}))
    )

    with pytest.raises(OdooWriteHandlerError, match="required auditable fields"):
        handler.snapshot("account.move", move, comp)

    class CompanyWithoutTaxExigibility(Record):
        def fields_get(self, fields):
            return {
                field: {"type": "char"}
                for field in fields
                if field != "tax_exigibility"
            }

        def read(self, fields):
            raise AssertionError("missing tax_exigibility must fail before read")

    incomplete_company = CompanyWithoutTaxExigibility(
        7, currency_id=Record(1)
    )
    handler = OdooWriteHandlers(
        context(Env({"res.company": Model({7: incomplete_company})}))
    )
    with pytest.raises(OdooWriteHandlerError, match="tax_exigibility"):
        handler.snapshot("res.company", incomplete_company, incomplete_company)

    handler = OdooWriteHandlers(context(Env({"account.journal": Model()})))
    with pytest.raises(OdooWriteHandlerError, match="does not exist uniquely"):
        handler.record("account.journal", 8, comp)


def test_snapshot_reads_binary_fields_as_sizes_without_materializing_payloads():
    class Currency(Record):
        def fields_get(self, fields):
            return {field: {"type": "char"} for field in fields}

        def read(self, fields):
            assert self.contexts[-1] == {"bin_size": True}
            values = {
                "name": "USD",
                "symbol": "$",
                "active": True,
                "rounding": "0.01",
                "decimal_places": 2,
            }
            return [{"id": self.id, **{field: values[field] for field in fields}}]

    currency = Currency(1)
    handler = OdooWriteHandlers(
        context(Env({"res.currency": Model({currency.id: currency})}))
    )

    snapshot = handler.snapshot(
        "res.currency", currency, company(currency_id=currency)
    )

    assert snapshot["values"]["name"] == "USD"


def test_asset_and_deferred_snapshot_manifests_fail_closed_when_fields_are_missing():
    comp = company()

    class PartialRecord(Record):
        def __init__(self, identifier, *, missing, **values):
            super().__init__(identifier, **values)
            self.missing = missing

        def fields_get(self, fields):
            return {
                field: {"type": "char"}
                for field in fields
                if field != self.missing
            }

        def read(self, fields):
            raise AssertionError("missing required fields must fail before read")

    asset = PartialRecord(81, missing="method", company_id=comp, state="model")
    handler = OdooWriteHandlers(
        context(Env({"account.asset": Model({81: asset})}))
    )
    with pytest.raises(OdooWriteHandlerError, match=r"account\.asset.*method"):
        handler.snapshot("account.asset", asset, comp)

    partial_company = PartialRecord(
        7,
        missing="deferred_expense_journal_id",
        currency_id=Record(1),
    )
    handler = OdooWriteHandlers(
        context(Env({"res.company": Model({7: partial_company})}))
    )
    with pytest.raises(
        OdooWriteHandlerError,
        match=r"res\.company.*deferred_expense_journal_id",
    ):
        handler.snapshot(
            "res.company",
            partial_company,
            partial_company,
            required_fields={
                "generate_deferred_expense_entries_method",
                "deferred_expense_amount_computation_method",
                "deferred_expense_account_id",
                "deferred_expense_journal_id",
            },
        )


@pytest.mark.parametrize(
    "missing",
    [
        "parent_state",
        "analytic_distribution",
        "analytic_line_ids",
        "tax_tag_ids",
    ],
)
def test_move_line_snapshot_manifest_requires_financial_reporting_fields(missing):
    comp = company()

    class PartialMoveLine(Record):
        def fields_get(self, fields):
            return {
                field: {"type": "char"}
                for field in fields
                if field != missing
            }

        def read(self, fields):
            raise AssertionError("missing required fields must fail before read")

    line = PartialMoveLine(91, company_id=comp)
    handler = OdooWriteHandlers(
        context(Env({"account.move.line": Model({91: line})}))
    )

    with pytest.raises(
        OdooWriteHandlerError,
        match=rf"account\.move\.line.*{missing}",
    ):
        handler.snapshot("account.move.line", line, comp)


@pytest.mark.parametrize(
    ("model_name", "required_fields"),
    [
        (
            "account.move",
            {
                "auto_post_until",
                "sequence_prefix",
                "sequence_number",
                "made_sequence_gap",
                "checked",
                "statement_line_ids",
                "closing_return_id",
                "transfer_model_id",
                "transaction_ids",
                "authorized_transaction_ids",
                "purchase_id",
                "asset_ids",
                "debit_note_ids",
                "debit_origin_id",
                "invoice_pdf_report_id",
                "invoice_vendor_bill_id",
                "purchase_vendor_bill_id",
                "ubl_cii_xml_id",
                "l10n_es_edi_facturae_xml_id",
                "signature",
                "signing_user",
                "is_move_sent",
                "sending_data",
                "is_being_sent",
                "invoice_source_email",
                "attachment_ids",
                "message_main_attachment_id",
                "audit_trail_message_ids",
                "fiscal_position_id",
                "invoice_cash_rounding_id",
                "invoice_incoterm_id",
                "incoterm_location",
                "partner_shipping_id",
                "partner_bank_id",
                "preferred_payment_method_line_id",
                "l10n_latam_document_type_id",
                "invoice_origin",
                "narration",
                "quick_edit_total_amount",
                "always_tax_exigible",
                "is_storno",
                "create_uid",
                "create_date",
                "write_uid",
                "write_date",
            },
        ),
        (
            "account.move.line",
            {
                "payment_id",
                "statement_id",
                "purchase_order_id",
                "group_tax_id",
                "distribution_analytic_account_ids",
                "reconcile_model_id",
                "reconciled_lines_ids",
                "reconciled_lines_excluding_exchange_diff_ids",
                "parent_id",
                "move_attachment_ids",
                "tax_base_amount",
                "extra_tax_data",
                "deductible_amount",
                "is_imported",
                "is_downpayment",
                "is_storno",
                "sequence",
                "product_uom_id",
                "discount",
                "discount_date",
                "discount_amount_currency",
                "discount_balance",
                "l10n_latam_document_type_id",
                "create_uid",
                "create_date",
                "write_uid",
                "write_date",
            },
        ),
    ],
)
def test_recovery_external_effect_fields_are_in_real_snapshot_manifest(
    model_name, required_fields
):
    comp = company()

    class CompleteRecord(Record):
        def fields_get(self, fields):
            return {field: {"type": "char"} for field in fields}

        def read(self, fields):
            return [{field: False for field in fields}]

    record = CompleteRecord(92, company_id=comp, state="draft")
    handler = OdooWriteHandlers(
        context(Env({model_name: Model({92: record})}))
    )

    snapshot = handler.snapshot(model_name, record, comp)

    assert required_fields <= set(snapshot["values"])


def test_recovery_snapshot_accepts_optional_fields_proven_absent_by_module_graph():
    comp = company()
    graph = build_trusted_module_graph(
        [
            {"name": name, "latest_version": "19.0.test"}
            for name in sorted(_TEST_MODULE_NAMES - {"point_of_sale"})
        ]
    )

    class MoveWithoutPos(Record):
        def fields_get(self, fields):
            return {
                field: {"type": "char"}
                for field in fields
                if field != "pos_order_ids"
            }

        def read(self, fields):
            return [{field: False for field in fields}]

    move = MoveWithoutPos(93, company_id=comp, state="draft")
    handler = OdooWriteHandlers(
        OdooWriteContext(
            env=Env({"account.move": Model({93: move})}),
            user_id=42,
            allowed_company_ids=frozenset({7}),
            today=date(2026, 7, 15),
            environment="sandbox",
            module_graph=graph,
        )
    )

    snapshot = handler.snapshot(
        "account.move",
        move,
        comp,
        required_fields={"state", "pos_order_ids"},
    )

    assert "pos_order_ids" not in snapshot["values"]


def test_odoo19_move_snapshot_drops_stale_move_payment_id_only():
    assert "payment_id" not in _SNAPSHOT_FIELDS["account.move"]
    assert "payment_id" in _SNAPSHOT_FIELDS["account.move.line"]


def test_open_date_rejects_future_and_locked_periods():
    handler = Harness()
    with pytest.raises(OdooWriteHandlerError, match="future"):
        handler.assert_open_date(company(), "2026-07-16", "posting_date")
    locked = company(fiscalyear_lock_date=date(2026, 6, 30))
    with pytest.raises(OdooWriteHandlerError, match="fiscalyear_lock_date"):
        handler.assert_open_date(locked, "2026-06-30", "posting_date")


def test_customer_invoice_uses_account_move_create_and_public_action_post():
    move = Record(100, state="draft", company_id=Record(7))
    model = Model(factory=lambda values: move)
    handler = Harness(models={"account.move": model})
    parameters = {
        "company_id": 7, "partner_id": 10, "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10", "due_date": "2026-08-10",
        "currency_id": 1, "journal_id": 2, "posting_mode": "post",
            "reference": "INV-EXT-1", "lines": [{
                "line_reference": "invoice-line-1", "name": "service",
                "product_id": None, "account_id": 3,
            "quantity": "2", "price_unit": "50.00", "tax_ids": [4],
        }],
    }
    records, recovery = handler.execute_customer_invoice(parameters, handler.test_company, {})
    assert records == [("account.move", move)]
    assert move.action_post_calls == 1
    values = model.creates[0]
    assert values["move_type"] == "out_invoice"
    assert values["date"] == "2026-07-10"
    assert values["invoice_date_due"] == "2026-08-10"
    assert values["invoice_payment_term_id"] is False
    assert values["odoo_cli_v3_document_binding"] == handler.document_binding(
        "customer_invoice", parameters
    )
    assert values["odoo_cli_v3_business_binding"] == handler.business_binding(
        "customer_invoice", parameters
    )
    assert values["invoice_line_ids"][0][2]["tax_ids"] == [(6, 0, [4])]
    assert values["invoice_line_ids"][0][2]["odoo_cli_v3_line_reference"] == (
        "invoice-line-1"
    )
    assert recovery == {
        "status": "manual_escalation",
        "method": "manual_review_customer_invoice_recovery",
        "targets": [{"model": "account.move", "record_id": 100}],
    }


def draft_invoice_creation_graph(
    *,
    payment_ids=None,
    reconciled=False,
    adjusting_entry_origin_move_ids=None,
):
    currency = Record(1, active=True, rounding=0.01)
    journal = Record(2, company_id=Record(7), type="sale", active=True)
    move = Record(
        101,
        name="/",
        state="draft",
        move_type="out_invoice",
        company_id=Record(7),
        journal_id=journal,
        currency_id=currency,
        amount_total=50,
        amount_residual=50,
        payment_state="not_paid",
        line_ids=[],
        auto_post="no",
        auto_post_until=False,
        posted_before=False,
        sequence_prefix=False,
        sequence_number=0,
        made_sequence_gap=False,
        checked=False,
        odoo_cli_v3_document_binding="a" * 64,
        odoo_cli_v3_business_binding="b" * 64,
        payment_ids=list(payment_ids or []),
        adjusting_entry_origin_move_ids=list(
            adjusting_entry_origin_move_ids or []
        ),
        debit_note_ids=[],
        debit_origin_id=None,
        invoice_pdf_report_id=None,
        invoice_vendor_bill_id=None,
        purchase_vendor_bill_id=None,
        ubl_cii_xml_id=None,
        l10n_es_edi_facturae_xml_id=None,
        invoice_pdf_report_file=False,
        l10n_es_edi_facturae_xml_file=False,
        ubl_cii_xml_file=False,
        signature=False,
        signing_user=None,
        is_move_sent=False,
        sending_data=False,
        is_being_sent=False,
        invoice_source_email=False,
        attachment_ids=[],
        message_main_attachment_id=None,
        audit_trail_message_ids=[],
        activity_ids=[],
        message_follower_ids=[],
        message_ids=[],
        rating_ids=[],
        website_message_ids=[],
        access_token=False,
        fiscal_position_id=None,
        invoice_cash_rounding_id=None,
        invoice_incoterm_id=None,
        incoterm_location=False,
        partner_shipping_id=None,
        partner_bank_id=None,
        preferred_payment_method_line_id=None,
        l10n_latam_document_type_id=None,
        invoice_origin=False,
        narration=False,
        quick_edit_total_amount=0,
        always_tax_exigible=False,
        is_storno=False,
        asset_value_change=False,
        campaign_id=None,
        medium_id=None,
        source_id=None,
        team_id=None,
        delivery_date=None,
        fapiao=False,
        invoice_currency_rate=1,
        invoice_user_id=Record(42),
        l10n_es_edi_facturae_reason_code=False,
        l10n_es_invoicing_period_start_date=None,
        l10n_es_invoicing_period_end_date=None,
        l10n_es_is_simplified=False,
        l10n_es_payment_means=False,
        payment_reference=False,
        payment_state_before_switch=False,
        qr_code_method=False,
        taxable_supply_date=None,
    )
    line1 = Record(
        102,
        company_id=Record(7),
        move_id=move,
        parent_state="draft",
        reconciled=reconciled,
        analytic_distribution=False,
        analytic_line_ids=[],
        tax_tag_ids=[],
        move_attachment_ids=[],
        tax_base_amount=0,
        extra_tax_data=False,
        deductible_amount=0,
        is_imported=False,
        is_downpayment=False,
        is_storno=False,
        sequence=10,
        product_uom_id=None,
        discount=0,
        discount_date=None,
        discount_amount_currency=0,
        discount_balance=0,
        l10n_latam_document_type_id=None,
        no_followup=False,
        collapse_composition=False,
        collapse_prices=False,
    )
    line2 = Record(
        103,
        company_id=Record(7),
        move_id=move,
        parent_state="draft",
        reconciled=False,
        analytic_distribution=False,
        analytic_line_ids=[],
        tax_tag_ids=[],
        move_attachment_ids=[],
        tax_base_amount=0,
        extra_tax_data=False,
        deductible_amount=0,
        is_imported=False,
        is_downpayment=False,
        is_storno=False,
        sequence=20,
        product_uom_id=None,
        discount=0,
        discount_date=None,
        discount_amount_currency=0,
        discount_balance=0,
        l10n_latam_document_type_id=None,
        no_followup=False,
        collapse_composition=False,
        collapse_prices=False,
    )
    move.line_ids = [line1, line2]
    move.journal_line_ids = [line1, line2]
    return move, line1, line2


def test_sandbox_draft_customer_invoice_emits_only_the_exact_line_guard_descriptor():
    move, line1, line2 = draft_invoice_creation_graph()
    model = Model(factory=lambda values: move)
    handler = Harness(
        models={"account.move": model},
        records={
            ("account.move.line", 102): line1,
            ("account.move.line", 103): line2,
        },
    )
    parameters = {
        "company_id": 7,
        "partner_id": 10,
        "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10",
        "due_date": "2026-08-10",
        "currency_id": 1,
        "journal_id": 2,
        "posting_mode": "draft",
        "reference": "INV-DRAFT-RECOVERY-1",
        "lines": [{
            "line_reference": "invoice-line-1",
            "name": "service",
            "product_id": None,
            "account_id": 3,
            "quantity": "1",
            "price_unit": "50.00",
            "tax_ids": [],
        }],
    }

    records, recovery = handler.execute_customer_invoice(
        parameters, handler.test_company, {}
    )

    assert {(model_name, record.id) for model_name, record in records} == {
        ("account.move", 101),
        ("account.move.line", 102),
        ("account.move.line", 103),
    }
    assert recovery == {
        "status": "available",
        "method": "cancel_pristine_v3_draft_customer_invoice_v1",
        "targets": [{"model": "account.move", "record_id": 101}],
            "guards": [
                {
                    "model": "account.move.line",
                    "record_id": 102,
                    "expected_outcome": "survive_allowed_delta",
                },
                {
                    "model": "account.move.line",
                    "record_id": 103,
                    "expected_outcome": "survive_allowed_delta",
                },
        ],
        "oracle_id": "cancel_pristine_v3_draft_customer_invoice_exact_v1",
    }


def test_sandbox_draft_vendor_bill_emits_only_the_exact_line_guard_descriptor():
    move, line1, line2 = draft_invoice_creation_graph()
    move.move_type = "in_invoice"
    move.journal_id.type = "purchase"
    model = Model(factory=lambda values: move)
    handler = Harness(
        models={"account.move": model},
        records={
            ("account.move.line", 102): line1,
            ("account.move.line", 103): line2,
        },
    )
    parameters = {
        "company_id": 7,
        "partner_id": 10,
        "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10",
        "due_date": "2026-08-10",
        "currency_id": 1,
        "journal_id": 2,
        "posting_mode": "draft",
        "vendor_reference": "BILL-DRAFT-RECOVERY-1",
        "lines": [{
            "line_reference": "bill-line-1",
            "name": "service",
            "product_id": None,
            "account_id": 3,
            "quantity": "1",
            "price_unit": "50.00",
            "tax_ids": [],
        }],
    }

    records, recovery = handler.execute_vendor_bill(
        parameters, handler.test_company, {}
    )

    assert {(model_name, record.id) for model_name, record in records} == {
        ("account.move", 101),
        ("account.move.line", 102),
        ("account.move.line", 103),
    }
    assert model.creates[0]["move_type"] == "in_invoice"
    assert model.creates[0]["ref"] == "BILL-DRAFT-RECOVERY-1"
    assert recovery == {
        "status": "available",
        "method": "cancel_pristine_v3_draft_vendor_bill_v1",
        "targets": [{"model": "account.move", "record_id": 101}],
            "guards": [
                {
                    "model": "account.move.line",
                    "record_id": 102,
                    "expected_outcome": "survive_allowed_delta",
                },
                {
                    "model": "account.move.line",
                    "record_id": 103,
                    "expected_outcome": "survive_allowed_delta",
                },
        ],
        "oracle_id": "cancel_pristine_v3_draft_vendor_bill_exact_v1",
    }


def test_handler_descriptor_and_real_snapshot_shapes_form_an_executable_v2_plan():
    move, line1, line2 = draft_invoice_creation_graph()
    handler = Harness(
        models={"account.move": Model(factory=lambda values: move)},
        records={
            ("account.move.line", line1.id): line1,
            ("account.move.line", line2.id): line2,
        },
    )
    parameters = {
        "company_id": 7,
        "partner_id": 10,
        "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10",
        "due_date": "2026-08-10",
        "currency_id": 1,
        "journal_id": 2,
        "posting_mode": "draft",
        "reference": "INV-DRAFT-INTEGRATION-1",
        "lines": [{
            "line_reference": "invoice-line-1",
            "name": "service",
            "product_id": None,
            "account_id": 3,
            "quantity": "1",
            "price_unit": "50.00",
            "tax_ids": [],
        }],
        "idempotency_key": "invoice-draft-integration-1",
    }
    document_binding = handler.document_binding("customer_invoice", parameters)
    business_binding = handler.business_binding("customer_invoice", parameters)
    move.odoo_cli_v3_document_binding = document_binding
    move.odoo_cli_v3_business_binding = business_binding
    move.snapshot_values = {
        "name": "/",
        "state": "draft",
        "move_type": "out_invoice",
        "company_id": [7, "Sandbox Company"],
        "journal_id": [2, "Sales"],
        "currency_id": [1, "USD"],
        "partner_id": [10, "Customer"],
        "date": "2026-07-10",
        "invoice_date": "2026-07-10",
        "invoice_date_due": "2026-08-10",
        "invoice_line_ids": [line1.id],
        "invoice_payment_term_id": False,
        "ref": "INV-DRAFT-INTEGRATION-1",
        "line_ids": [line1.id, line2.id],
        "journal_line_ids": [line1.id, line2.id],
        "auto_post": "no",
        "auto_post_until": False,
        "posted_before": False,
        "sequence_prefix": False,
        "sequence_number": 0,
        "secure_sequence_number": 0,
        "made_sequence_gap": False,
        "inalterable_hash": False,
        "checked": False,
        "is_manually_modified": False,
        "need_cancel_request": False,
        "auto_post_origin_id": False,
        "origin_payment_id": False,
        "payment_ids": [],
        "matched_payment_ids": [],
        "reconciled_payment_ids": [],
        "statement_line_id": False,
        "statement_id": False,
        "tax_cash_basis_rec_id": False,
        "tax_cash_basis_origin_move_id": False,
        "tax_cash_basis_created_move_ids": [],
        "reversed_entry_id": False,
        "reversal_move_ids": [],
        "adjusting_entry_origin_move_ids": [],
        "adjusting_entries_move_ids": [],
        "exchange_diff_partial_ids": [],
        "statement_line_ids": [],
        "closing_return_id": False,
        "transfer_model_id": False,
        "transaction_ids": [],
        "authorized_transaction_ids": [],
        "purchase_id": False,
        "asset_id": False,
        "asset_ids": [],
        "deferred_move_ids": [],
        "deferred_original_move_ids": [],
        "edi_document_ids": [],
        "expense_ids": [],
        "pos_order_ids": [],
        "stock_move_ids": [],
        "landed_costs_ids": [],
        "debit_note_ids": [],
        "debit_origin_id": False,
        "invoice_pdf_report_id": False,
        "invoice_vendor_bill_id": False,
        "purchase_vendor_bill_id": False,
        "ubl_cii_xml_id": False,
        "l10n_es_edi_facturae_xml_id": False,
        "invoice_pdf_report_file": {"present": False},
        "l10n_es_edi_facturae_xml_file": {"present": False},
        "ubl_cii_xml_file": {"present": False},
        "signature": {"present": False},
        "signing_user": False,
        "is_move_sent": False,
        "sending_data": False,
        "is_being_sent": False,
        "invoice_source_email": False,
        "attachment_ids": [],
        "message_main_attachment_id": False,
        "audit_trail_message_ids": [],
        "activity_ids": [],
        "message_follower_ids": [],
        "message_ids": [],
        "rating_ids": [],
        "website_message_ids": [],
        "access_token": {"present": False},
        "fiscal_position_id": False,
        "invoice_cash_rounding_id": False,
        "invoice_incoterm_id": False,
        "incoterm_location": False,
        "partner_shipping_id": False,
        "partner_bank_id": False,
        "preferred_payment_method_line_id": False,
        "l10n_latam_document_type_id": False,
        "invoice_origin": False,
        "narration": False,
        "quick_edit_total_amount": "0",
        "always_tax_exigible": False,
        "is_storno": False,
        "asset_value_change": False,
        "campaign_id": False,
        "medium_id": False,
        "source_id": False,
        "team_id": False,
        "delivery_date": False,
        "fapiao": False,
        "invoice_currency_rate": "1",
        "invoice_user_id": [42, "V3 Executor"],
        "l10n_es_edi_facturae_reason_code": False,
        "l10n_es_invoicing_period_start_date": False,
        "l10n_es_invoicing_period_end_date": False,
        "l10n_es_is_simplified": False,
        "l10n_es_payment_means": False,
        "payment_reference": False,
        "payment_state_before_switch": False,
        "qr_code_method": False,
        "taxable_supply_date": False,
        "asset_depreciation_beginning_date": False,
        "asset_number_days": 0,
        "depreciation_value": "0",
        "create_uid": [42, "V3 Executor"],
        "create_date": "2026-07-10 09:00:00",
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-10 09:00:00",
        "odoo_cli_v3_document_binding": document_binding,
        "odoo_cli_v3_business_binding": business_binding,
    }
    for line in (line1, line2):
        line.snapshot_values = {
            "move_id": [move.id, "/"],
            "company_id": [7, "Sandbox Company"],
            "account_id": [10 if line is line1 else 20, "Account"],
            "currency_id": [1, "USD"],
            "parent_state": "draft",
            "reconciled": False,
            "full_reconcile_id": False,
            "matched_debit_ids": [],
            "matched_credit_ids": [],
            "asset_ids": [],
            "sale_line_ids": [],
            "analytic_distribution": False,
            "analytic_line_ids": [],
            "tax_tag_ids": [],
            "tax_ids": [],
            "tax_line_id": False,
            "tax_repartition_line_id": False,
            "payment_id": False,
            "statement_line_id": False,
            "statement_id": False,
            "purchase_line_id": False,
            "purchase_order_id": False,
            "expense_id": False,
            "group_tax_id": False,
            "distribution_analytic_account_ids": [],
            "reconcile_model_id": False,
            "reconciled_lines_ids": [],
            "reconciled_lines_excluding_exchange_diff_ids": [],
            "parent_id": False,
            "cogs_origin_id": False,
            "is_landed_costs_line": False,
            "deferred_start_date": False,
            "deferred_end_date": False,
            "move_attachment_ids": [],
            "tax_base_amount": "0",
            "extra_tax_data": False,
            "deductible_amount": "0",
            "is_imported": False,
            "is_downpayment": False,
            "is_storno": False,
            "sequence": 10,
            "product_uom_id": False,
            "discount": "0",
            "discount_date": False,
            "discount_amount_currency": "0",
            "discount_balance": "0",
            "l10n_latam_document_type_id": False,
            "no_followup": False,
            "collapse_composition": False,
            "collapse_prices": False,
            "date_maturity": False,
            "matching_number": False,
            "name": "Invoice line" if line is line1 else "Payment term",
            "partner_id": [10, "Customer"],
            "price_unit": "100" if line is line1 else "0",
            "product_id": False,
            "quantity": "1" if line is line1 else "0",
            "create_uid": [42, "V3 Executor"],
            "create_date": "2026-07-10 09:00:00",
            "write_uid": [42, "V3 Executor"],
            "write_date": "2026-07-10 09:00:00",
            "display_type": "product",
            "debit": "100" if line is line1 else "0",
            "credit": "0" if line is line1 else "100",
            "balance": "100" if line is line1 else "-100",
            "amount_currency": "100" if line is line1 else "-100",
            "odoo_cli_v3_line_reference": (
                "line-1" if line is line1 else "line-2"
            ),
        }
    checked = {
        "capability_id": "acct.invoice.customer_create.v1",
        "company_id": 7,
        "parameters_digest": hashlib.sha256(canonical_json(parameters)).hexdigest(),
        "module_graph": handler.context.module_graph.evidence,
        "checks": ["approved_live_precheck"],
        "before": [],
    }

    raw = handler.execute_prechecked(
        "acct.invoice.customer_create.v1", parameters, checked
    )
    operation = SimpleNamespace(
        operation_id="op-draft-integration-1",
        capability_id="acct.invoice.customer_create.v1",
        company_id=7,
        environment="sandbox",
        parameters=parameters,
    )
    evidence = _execution_evidence(operation, raw)

    validate_executable_recovery_plan(evidence["recovery_plan"])
    assert evidence["recovery_plan"]["status"] == "available"
    assert {
        (item["model"], item["record_id"])
        for item in evidence["recovery_plan"]["guard_records"]
    } == {
        ("account.move.line", line1.id),
        ("account.move.line", line2.id),
    }


@pytest.mark.parametrize(
    ("payment_ids", "reconciled", "adjusting_origins", "match"),
    [
        ([Record(991)], False, [], "linked payment"),
        ([], True, [], "external business effects"),
        ([], False, [Record(992)], "linked payment"),
    ],
)
def test_sandbox_draft_invoice_never_advertises_recovery_for_an_unsafe_graph(
    payment_ids, reconciled, adjusting_origins, match
):
    move, line1, line2 = draft_invoice_creation_graph(
        payment_ids=payment_ids,
        reconciled=reconciled,
        adjusting_entry_origin_move_ids=adjusting_origins,
    )
    handler = Harness(
        models={"account.move": Model(factory=lambda values: move)},
        records={
            ("account.move.line", line1.id): line1,
            ("account.move.line", line2.id): line2,
        },
    )
    parameters = {
        "company_id": 7,
        "partner_id": 10,
        "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10",
        "due_date": "2026-08-10",
        "currency_id": 1,
        "journal_id": 2,
        "posting_mode": "draft",
        "reference": "INV-DRAFT-UNSAFE-1",
        "lines": [{
            "line_reference": "invoice-line-1",
            "name": "service",
            "product_id": None,
            "account_id": 3,
            "quantity": "1",
            "price_unit": "50.00",
            "tax_ids": [],
        }],
    }

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.execute_customer_invoice(parameters, handler.test_company, {})


def test_production_draft_invoice_never_advertises_unverified_automatic_recovery():
    move = Record(104, state="draft", company_id=Record(7), line_ids=[])
    handler = Harness(
        models={"account.move": Model(factory=lambda values: move)},
        environment="production",
    )
    parameters = {
        "company_id": 7,
        "partner_id": 10,
        "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10",
        "due_date": "2026-08-10",
        "currency_id": 1,
        "journal_id": 2,
        "posting_mode": "draft",
        "reference": "INV-PRODUCTION-CLOSED-1",
        "lines": [{
            "line_reference": "invoice-line-1",
            "name": "service",
            "product_id": None,
            "account_id": 3,
            "quantity": "1",
            "price_unit": "50.00",
            "tax_ids": [],
        }],
    }

    _records, recovery = handler.execute_customer_invoice(
        parameters, handler.test_company, {}
    )

    assert recovery["status"] == "manual_escalation"
    assert recovery["method"] == "manual_review_customer_invoice_recovery"


def test_vendor_bill_uses_vendor_reference_and_purchase_move_type():
    move = Record(101, state="draft", company_id=Record(7))
    model = Model(factory=lambda values: move)
    handler = Harness(models={"account.move": model}, environment="unit")
    parameters = {
        "company_id": 7, "partner_id": 10, "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10", "due_date": "2026-08-10",
        "currency_id": 1, "journal_id": 2, "posting_mode": "draft",
            "vendor_reference": "SUP-1", "lines": [{
                "line_reference": "bill-line-1", "name": "service",
                "product_id": None, "account_id": 3,
            "quantity": "1", "price_unit": "50.00", "tax_ids": [],
        }],
    }
    handler.execute_vendor_bill(parameters, handler.test_company, {})
    assert model.creates[0]["move_type"] == "in_invoice"
    assert model.creates[0]["ref"] == "SUP-1"
    assert model.creates[0]["invoice_payment_term_id"] is False
    assert model.creates[0]["odoo_cli_v3_document_binding"] == (
        handler.document_binding("vendor_bill", parameters)
    )
    assert model.creates[0]["odoo_cli_v3_business_binding"] == (
        handler.business_binding("vendor_bill", parameters)
    )
    assert model.creates[0]["invoice_line_ids"][0][2][
        "odoo_cli_v3_line_reference"
    ] == "bill-line-1"
    assert move.action_post_calls == 0


class TaxPreviewHarness(Harness):
    def __init__(self, *, tax_result, **kwargs):
        super().__init__(**kwargs)
        self.tax_result = tax_result
        self.tax_compute_calls = []

    def tax_recordset(self, tax_ids, company):
        owner = self

        class TaxSet:
            ids = list(tax_ids)

            def compute_all(self, *args, **kwargs):
                owner.tax_compute_calls.append((args, kwargs))
                return owner.tax_result

        return TaxSet()


def document_handler_and_parameters():
    comp = company()
    currency = Record(1, active=True, rounding="0.01", company_id=None)
    partner = Record(10, active=True, company_id=None)
    journal = Record(
        2,
        type="sale",
        active=True,
        company_id=comp,
        currency_id=currency,
    )
    account = Record(
        3,
        account_type="income",
        deprecated=False,
        company_id=comp,
    )
    tax = Record(
        4,
        active=True,
        type_tax_use="sale",
        company_id=comp,
    )
    handler = TaxPreviewHarness(
        tax_result={
            "total_excluded": 100.0,
            "total_included": 110.0,
            "taxes": [{"id": 4, "amount": 10.0}],
        },
        models={"account.move": Model()},
        records={
            ("res.currency", 1): currency,
            ("res.partner", 10): partner,
            ("account.journal", 2): journal,
            ("account.account", 3): account,
            ("account.tax", 4): tax,
        },
    )
    handler.test_company = comp
    parameters = {
        "company_id": 7,
        "partner_id": 10,
        "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10",
        "due_date": "2026-08-10",
        "currency_id": 1,
        "journal_id": 2,
        "posting_mode": "post",
        "reference": "INV-EXT-STRICT-1",
        "lines": [
            {
                "line_reference": "invoice-line-1",
                "name": "service",
                "product_id": None,
                "account_id": 3,
                "quantity": "2",
                "price_unit": "50.00",
                "tax_ids": [4],
            }
        ],
        "idempotency_key": "invoice-idem-1",
    }
    return handler, parameters


def test_document_precheck_binds_dependencies_tax_preview_and_business_identity():
    handler, parameters = document_handler_and_parameters()

    checked = handler.precheck_customer_invoice(parameters, handler.test_company)

    assert checked["before"] == []
    assert checked["financial_preview"] == {
        "amount_untaxed": "100.0",
        "amount_tax": "10.0",
        "amount_total": "110.0",
        "lines": [
            {
                "line_reference": "invoice-line-1",
                "amount_untaxed": "100.0",
                "amount_tax": "10.0",
                "amount_total": "110.0",
                "taxes": [{"tax_id": 4, "amount": "10.0"}],
            }
        ],
    }
    assert {item["model"] for item in checked["dependencies"]} == {
        "res.company",
        "res.currency",
        "res.partner",
        "account.journal",
        "account.account",
        "account.tax",
    }
    assert handler.tax_compute_calls[0][1]["currency"].id == 1
    assert handler.tax_compute_calls[0][1]["partner"].id == 10
    assert handler.tax_compute_calls[0][1]["is_refund"] is False
    assert checked["document_binding"] == handler.document_binding(
        "customer_invoice", parameters
    )

    handler.search_records = lambda *args, **kwargs: [Record(999)]
    with pytest.raises(OdooWriteHandlerError, match="business document already exists"):
        handler.precheck_customer_invoice(parameters, handler.test_company)


def test_document_verification_requires_exact_graph_direction_and_tax_preview():
    handler, parameters = document_handler_and_parameters()
    comp = handler.test_company
    currency = handler.records[("res.currency", 1)]
    partner = handler.records[("res.partner", 10)]
    journal = handler.records[("account.journal", 2)]
    income = handler.records[("account.account", 3)]
    tax = handler.records[("account.tax", 4)]
    tax_account = Record(5, account_type="liability_current", company_id=comp)
    receivable = Record(6, account_type="asset_receivable", company_id=comp)
    move = Record(
        100,
        state="posted",
        move_type="out_invoice",
        company_id=comp,
        partner_id=partner,
        currency_id=currency,
        journal_id=journal,
        date="2026-07-10",
        invoice_date="2026-07-10",
        invoice_date_due="2026-08-10",
        invoice_payment_term_id=None,
        ref="INV-EXT-STRICT-1",
        amount_untaxed=100,
        amount_tax=10,
        amount_total=110,
        amount_residual=110,
        payment_state="not_paid",
        odoo_cli_v3_document_binding=handler.document_binding(
            "customer_invoice", parameters
        ),
        odoo_cli_v3_business_binding=handler.business_binding(
            "customer_invoice", parameters
        ),
    )
    product_line = Record(
        1001,
        company_id=comp,
        move_id=move,
        name="service",
        odoo_cli_v3_line_reference="invoice-line-1",
        account_id=income,
        product_id=None,
        tax_ids=[tax],
        tax_line_id=None,
        quantity=2,
        price_unit=50,
        price_subtotal=100,
        price_total=110,
        debit=0,
        credit=100,
        balance=-100,
        amount_currency=-100,
    )
    tax_line = Record(
        1002,
        company_id=comp,
        move_id=move,
        account_id=tax_account,
        partner_id=partner,
        tax_ids=[],
        tax_line_id=tax,
        debit=0,
        credit=10,
        balance=-10,
        amount_currency=-10,
    )
    term_line = Record(
        1003,
        company_id=comp,
        move_id=move,
        account_id=receivable,
        partner_id=partner,
        tax_ids=[],
        tax_line_id=None,
        date_maturity="2026-08-10",
        debit=110,
        credit=0,
        balance=110,
        amount_currency=110,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
    )
    move.invoice_line_ids = [product_line]
    move.line_ids = [product_line, tax_line, term_line]
    handler.records.update(
        {
            ("account.move.line", product_line.id): product_line,
            ("account.move.line", tax_line.id): tax_line,
            ("account.move.line", term_line.id): term_line,
        }
    )
    records = [
        ("account.move", move),
        ("account.move.line", product_line),
        ("account.move.line", tax_line),
        ("account.move.line", term_line),
    ]

    checks = handler.verify_customer_invoice(
        parameters, handler.test_company, records
    )
    assert "record_graph_exact" in checks
    assert "tax_lines_match_preview" in checks
    assert "unpaid_residual_matches" in checks

    term_line.account_id = Record(7, account_type="liability_payable")
    with pytest.raises(OdooWriteHandlerError, match="payment term account type"):
        handler.verify_customer_invoice(parameters, handler.test_company, records)


def test_refund_uses_public_reversal_wizard_and_replaces_partial_lines():
    refund = Record(201, state="draft", company_id=Record(7))
    origin = Record(200, state="posted", company_id=Record(7), line_ids=[])

    class Wizard(Record):
        def refund_moves(self):
            self.called = True
            return {"res_id": 201}

    wizard = Wizard(1)
    model = Model(factory=lambda values: wizard)
    handler = Harness(
        models={"account.move.reversal": model},
        records={("account.move", 200): origin, ("account.move", 201): refund},
    )
    parameters = {
        "origin_move_id": 200, "refund_date": "2026-07-10", "journal_id": 2,
        "reason": "partial", "refund_mode": "partial", "posting_mode": "post",
            "lines": [{"line_reference": "refund-line-1", "name": "part", "account_id": 3, "quantity": "1", "price_unit": "20", "tax_ids": []}],
    }
    records, _ = handler.execute_refund(parameters, handler.test_company, {})
    assert records == [("account.move", origin), ("account.move", refund)]
    assert wizard.called is True
    assert refund.writes[0]["invoice_line_ids"][0] == (5, 0, 0)
    assert refund.writes[0]["odoo_cli_v3_reason"] == "partial"
    assert refund.writes[0]["invoice_payment_term_id"] is False
    assert refund.writes[0]["odoo_cli_v3_document_binding"] == (
        handler.document_binding("refund", parameters)
    )
    assert refund.writes[0]["odoo_cli_v3_business_binding"] == (
        handler.business_binding("refund", parameters)
    )
    assert refund.writes[0]["invoice_line_ids"][1][2][
        "odoo_cli_v3_line_reference"
    ] == "refund-line-1"
    assert refund.action_post_calls == 1
    assert _["status"] == "available"
    assert _["method"] == "reverse_posted_refund_v1"


def test_refund_draft_fails_closed_if_public_wizard_already_posted_it():
    refund = Record(211, state="posted", company_id=Record(7))

    class Wizard(Record):
        def refund_moves(self):
            return {"res_id": 211}

    handler = Harness(
        models={"account.move.reversal": Model(factory=lambda values: Wizard(1))},
        records={
            ("account.move", 210): Record(
                210, state="posted", company_id=Record(7), line_ids=[]
            ),
            ("account.move", 211): refund,
        },
    )
    p = {
        "origin_move_id": 210, "refund_date": "2026-07-10", "journal_id": 2,
        "reason": "draft", "refund_mode": "full", "posting_mode": "draft",
        "lines": [],
    }
    with pytest.raises(OdooWriteHandlerError, match="preserve the approved draft mode"):
        handler.execute_refund(p, handler.test_company, {})


def refund_precheck_handler_and_parameters():
    comp = company()
    currency = Record(1, active=True, rounding="0.01", company_id=None)
    partner = Record(10, active=True, company_id=None)
    journal = Record(
        2,
        type="sale",
        active=True,
        company_id=comp,
        currency_id=currency,
    )
    income = Record(
        3, account_type="income", deprecated=False, company_id=comp
    )
    receivable = Record(
        6, account_type="asset_receivable", deprecated=False, company_id=comp
    )
    origin = Record(
        200,
        state="posted",
        move_type="out_invoice",
        company_id=comp,
        partner_id=partner,
        journal_id=journal,
        currency_id=currency,
        date="2026-07-01",
        invoice_date="2026-07-01",
        amount_untaxed=100,
        amount_tax=0,
        amount_total=100,
        amount_residual=100,
        payment_state="not_paid",
        reversal_move_ids=[],
    )
    product_line = Record(
        2001,
        company_id=comp,
        move_id=origin,
        account_id=income,
        product_id=None,
        tax_ids=[],
        tax_line_id=None,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        asset_ids=[],
        deferred_start_date=None,
        deferred_end_date=None,
    )
    term_line = Record(
        2002,
        company_id=comp,
        move_id=origin,
        account_id=receivable,
        product_id=None,
        tax_ids=[],
        tax_line_id=None,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        asset_ids=[],
        deferred_start_date=None,
        deferred_end_date=None,
    )
    origin.line_ids = [product_line, term_line]
    origin.invoice_line_ids = [product_line]
    handler = TaxPreviewHarness(
        tax_result={},
        models={"account.move.reversal": Model()},
        records={
            ("res.currency", 1): currency,
            ("res.partner", 10): partner,
            ("account.journal", 2): journal,
            ("account.account", 3): income,
            ("account.account", 6): receivable,
            ("account.move", 200): origin,
            ("account.move.line", 2001): product_line,
            ("account.move.line", 2002): term_line,
        },
    )
    handler.test_company = comp
    parameters = {
        "company_id": 7,
        "origin_move_id": 200,
        "refund_type": "customer_credit_note",
        "refund_mode": "partial",
        "refund_date": "2026-07-10",
        "journal_id": 2,
        "currency_id": 1,
        "expected_total_amount": "20",
        "reason": "partial service refund",
        "posting_mode": "post",
        "lines": [
            {
                "line_reference": "refund-line-1",
                "name": "part",
                "account_id": 3,
                "quantity": "1",
                "price_unit": "20",
                "tax_ids": [],
            }
        ],
        "idempotency_key": "refund-idem-1",
    }
    return handler, parameters


def test_refund_precheck_binds_origin_graph_and_exact_partial_total():
    handler, parameters = refund_precheck_handler_and_parameters()

    checked = handler.precheck_refund(parameters, handler.test_company)

    assert {(item["model"], item["record_id"]) for item in checked["before"]} == {
        ("account.move", 200),
        ("account.move.line", 2001),
        ("account.move.line", 2002),
    }
    assert checked["financial_preview"]["amount_total"] == "20"
    assert checked["document_binding"] == handler.document_binding(
        "refund", parameters
    )
    assert "origin_graph_snapshotted" in checked["checks"]

    parameters["expected_total_amount"] = "21"
    with pytest.raises(OdooWriteHandlerError, match="partial refund total"):
        handler.precheck_refund(parameters, handler.test_company)


def test_refund_precheck_rejects_reconciled_or_previously_reversed_origin():
    handler, parameters = refund_precheck_handler_and_parameters()
    origin = handler.records[("account.move", 200)]
    origin.reversal_move_ids = [Record(300)]
    with pytest.raises(OdooWriteHandlerError, match="accounting dependencies"):
        handler.precheck_refund(parameters, handler.test_company)


def test_full_refund_verification_binds_origin_and_exact_reversal_graph():
    handler, parameters = refund_precheck_handler_and_parameters()
    parameters["refund_mode"] = "full"
    parameters["lines"] = []
    parameters["expected_total_amount"] = "100"
    origin = handler.records[("account.move", 200)]
    partner = origin.partner_id
    currency = origin.currency_id
    journal = origin.journal_id
    origin_product = handler.records[("account.move.line", 2001)]
    origin_term = handler.records[("account.move.line", 2002)]
    for line, values in (
        (
            origin_product,
            {
                "name": "service",
                "partner_id": partner,
                "currency_id": currency,
                "debit": 0,
                "credit": 100,
                "balance": -100,
                "amount_currency": -100,
                "display_type": "product",
                "odoo_cli_v3_line_reference": "origin-line-1",
            },
        ),
        (
            origin_term,
            {
                "name": "INV/ORIGIN",
                "partner_id": partner,
                "currency_id": currency,
                "debit": 100,
                "credit": 0,
                "balance": 100,
                "amount_currency": 100,
                "display_type": "payment_term",
                "date_maturity": "2026-08-01",
                "odoo_cli_v3_line_reference": "",
            },
        ),
    ):
        for key, value in values.items():
            setattr(line, key, value)
    refund = Record(
        300,
        state="posted",
        move_type="out_refund",
        company_id=handler.test_company,
        reversed_entry_id=origin,
        reversal_move_ids=[],
        partner_id=partner,
        journal_id=journal,
        currency_id=currency,
        date="2026-07-10",
        invoice_date="2026-07-10",
        invoice_date_due="2026-07-10",
        invoice_payment_term_id=None,
        amount_untaxed=100,
        amount_tax=0,
        amount_total=100,
        amount_residual=100,
        payment_state="not_paid",
        odoo_cli_v3_reason="partial service refund",
        odoo_cli_v3_document_binding=handler.document_binding(
            "refund", parameters
        ),
        odoo_cli_v3_business_binding=handler.business_binding(
            "refund", parameters
        ),
    )
    refund_product = Record(
        3001,
        company_id=handler.test_company,
        move_id=refund,
        name="service",
        partner_id=partner,
        currency_id=currency,
        account_id=origin_product.account_id,
        product_id=None,
        quantity=1,
        price_unit=100,
        price_subtotal=100,
        price_total=100,
        tax_ids=[],
        tax_line_id=None,
        debit=100,
        credit=0,
        balance=100,
        amount_currency=100,
        display_type="product",
        odoo_cli_v3_line_reference="origin-line-1",
    )
    refund_term = Record(
        3002,
        company_id=handler.test_company,
        move_id=refund,
        name="INV/ORIGIN",
        partner_id=partner,
        currency_id=currency,
        account_id=origin_term.account_id,
        product_id=None,
        tax_ids=[],
        tax_line_id=None,
        date_maturity="2026-07-10",
        debit=0,
        credit=100,
        balance=-100,
        amount_currency=-100,
        display_type="payment_term",
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        odoo_cli_v3_line_reference="",
    )
    refund.invoice_line_ids = [refund_product]
    refund.line_ids = [refund_product, refund_term]
    origin.reversal_move_ids = [refund]
    handler.records.update(
        {
            ("account.move", 300): refund,
            ("account.move.line", 3001): refund_product,
            ("account.move.line", 3002): refund_term,
        }
    )
    origin_before = {
        "state": "posted",
        "move_type": "out_invoice",
        "line_ids": [2001, 2002],
        "invoice_line_ids": [2001],
        "reversal_move_ids": [],
        "amount_total": "100",
        "amount_residual": "100",
    }
    origin.snapshot_values = {
        **origin_before,
        "reversal_move_ids": [300],
    }
    origin_product.snapshot_values = {"balance": "-100"}
    origin_term.snapshot_values = {"balance": "100"}
    trusted_before = {
        ("account.move", 200): origin_before,
        ("account.move.line", 2001): {"balance": "-100"},
        ("account.move.line", 2002): {"balance": "100"},
    }
    records = [
        ("account.move", origin),
        ("account.move.line", origin_product),
        ("account.move.line", origin_term),
        ("account.move", refund),
        ("account.move.line", refund_product),
        ("account.move.line", refund_term),
    ]

    checks = handler.verify_refund(
        parameters, handler.test_company, records, trusted_before
    )
    assert "origin_approval_matches" in checks
    assert "linewise_full_refund_exact" in checks
    assert "record_graph_exact" in checks

    with pytest.raises(
        OdooWriteHandlerError,
        match="approved refund origin snapshots are missing",
    ):
        handler.verify_refund(
            parameters, handler.test_company, records
        )

    refund_product.debit = 99
    with pytest.raises(OdooWriteHandlerError, match="linewise reversal"):
        handler.verify_refund(
            parameters, handler.test_company, records, trusted_before
        )

    origin.reversal_move_ids = []
    handler.records[("account.move.line", 2002)].reconciled = True
    with pytest.raises(OdooWriteHandlerError, match="accounting dependencies"):
        handler.precheck_refund(parameters, handler.test_company)


def test_payment_uses_public_register_action_and_deterministic_res_id():
    target_line = Record(
        111,
        company_id=Record(7),
        matched_debit_ids=[],
        matched_credit_ids=[],
    )
    target = Record(11, company_id=Record(7), line_ids=[target_line])
    payment_line = Record(
        311,
        company_id=Record(7),
        matched_debit_ids=[],
        matched_credit_ids=[],
    )
    payment_move = Record(
        310, company_id=Record(7), line_ids=[payment_line]
    )
    payment = Record(301, company_id=Record(7), move_id=payment_move)

    class Wizard(Record):
        partner_id = Record(10)
        currency_id = Record(1)
        journal_id = Record(2)
        payment_method_line_id = Record(3)
        partner_type = "customer"
        payment_type = "inbound"

        def action_create_payments(self):
            self.called = True
            return {"res_id": 301}

    wizard = Wizard(1)
    model = Model(factory=lambda values: wizard)
    handler = Harness(
        models={"account.payment.register": model},
        records={
            ("account.payment", 301): payment,
            ("account.move", 11): target,
            ("account.move", 310): payment_move,
            ("account.move.line", 111): target_line,
            ("account.move.line", 311): payment_line,
        },
    )
    p = {
        "target_move_ids": [11], "payment_date": "2026-07-10", "amount": "50",
        "currency_id": 1, "journal_id": 2, "payment_method_line_id": 3,
        "memo": "PAY-1", "partner_id": 10, "partner_type": "customer",
        "direction": "inbound",
    }
    records, _ = handler.execute_payment(
        p, handler.test_company, {"payment_binding": payment_binding()}
    )
    assert ("account.payment", payment) in records
    assert wizard.called is True
    assert model.creates[0]["communication"] == "PAY-1"
    assert model.contexts[0][1] == {"active_model": "account.move", "active_ids": [11]}


def test_payment_with_prior_reconcile_binding_escalates_recovery():
    full = Record(550)
    target_line = Record(
        111,
        company_id=Record(7),
        matched_debit_ids=[],
        matched_credit_ids=[Record(501)],
        full_reconcile_id=full,
    )
    target = Record(11, company_id=Record(7), line_ids=[target_line])
    payment_line = Record(
        311,
        company_id=Record(7),
        matched_debit_ids=[Record(501)],
        matched_credit_ids=[],
        full_reconcile_id=full,
    )
    payment_move = Record(
        310, company_id=Record(7), line_ids=[payment_line]
    )
    partial = Record(
        501,
        company_id=Record(7),
        exchange_move_id=None,
        full_reconcile_id=full,
    )
    payment = Record(
        301, company_id=Record(7), move_id=payment_move
    )

    class Wizard(Record):
        partner_id = Record(10)
        currency_id = Record(1)
        journal_id = Record(2)
        payment_method_line_id = Record(3)
        partner_type = "customer"
        payment_type = "inbound"

        def action_create_payments(self):
            return {"res_id": 301}

    handler = Harness(
        models={
            "account.payment.register": Model(
                factory=lambda values: Wizard(1)
            )
        },
        records={
            ("account.payment", 301): payment,
            ("account.move", 11): target,
            ("account.move", 310): payment_move,
            ("account.move.line", 111): target_line,
            ("account.move.line", 311): payment_line,
            ("account.partial.reconcile", 501): partial,
            ("account.full.reconcile", 550): full,
        },
    )
    parameters = {
        "target_move_ids": [11],
        "payment_date": "2026-07-10",
        "amount": "50",
        "currency_id": 1,
        "journal_id": 2,
        "payment_method_line_id": 3,
        "memo": "PAY-1",
        "partner_id": 10,
        "partner_type": "customer",
        "direction": "inbound",
    }
    binding = payment_binding()
    binding["target_line_before"][0].update(
        {
            "full_reconcile_id": 901,
            "matched_credit_ids": [900],
        }
    )

    _records, recovery = handler.execute_payment(
        parameters,
        handler.test_company,
        {"payment_binding": binding},
    )

    assert recovery == {
        "status": "manual_escalation",
        "method": "manual_review_payment_recovery",
        "targets": [{"model": "account.payment", "record_id": 301}],
    }


def test_payment_persists_exact_binding_and_returns_full_reconciliation_graph():
    full = Record(550, partial_reconcile_ids=[], reconciled_line_ids=[])
    target_line = Record(
        111,
        company_id=Record(7),
        move_id=Record(11),
        debit=100,
        credit=0,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=full,
        matched_debit_ids=[],
        matched_credit_ids=[Record(501)],
    )
    target = Record(
        11,
        state="posted",
        company_id=Record(7),
        partner_id=Record(10),
        currency_id=Record(1),
        amount_residual=0,
        line_ids=[target_line],
    )
    payment_receivable = Record(
        311,
        company_id=Record(7),
        move_id=Record(310),
        debit=0,
        credit=100,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=full,
        matched_debit_ids=[Record(501)],
        matched_credit_ids=[],
    )
    payment_liquidity = Record(
        312,
        company_id=Record(7),
        move_id=Record(310),
        debit=100,
        credit=0,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
    )
    payment_move = Record(
        310,
        state="posted",
        company_id=Record(7),
        line_ids=[payment_receivable, payment_liquidity],
    )
    partial = Record(
        501,
        company_id=Record(7),
        debit_move_id=target_line,
        credit_move_id=payment_receivable,
        amount=100,
        debit_amount_currency=100,
        credit_amount_currency=100,
        full_reconcile_id=full,
        exchange_move_id=None,
        company_currency_id=Record(1),
        debit_currency_id=Record(1),
        credit_currency_id=Record(1),
    )
    payment = Record(
        301,
        state="paid",
        company_id=Record(7),
        partner_id=Record(10),
        currency_id=Record(1),
        journal_id=Record(2),
        payment_method_line_id=Record(3),
        partner_type="customer",
        payment_type="inbound",
        date="2026-07-10",
        amount=100,
        memo="PAY-1",
        move_id=payment_move,
        reconciled_invoice_ids=[target],
        reconciled_bill_ids=[],
    )
    full.partial_reconcile_ids = [partial]
    full.reconciled_line_ids = [target_line, payment_receivable]

    class Wizard(Record):
        partner_id = Record(10)
        currency_id = Record(1)
        journal_id = Record(2)
        payment_method_line_id = Record(3)
        partner_type = "customer"
        payment_type = "inbound"

        def action_create_payments(self):
            return {"res_id": 301}

    handler = Harness(
        models={"account.payment.register": Model(factory=lambda values: Wizard(1))},
        records={
            ("account.payment", 301): payment,
            ("account.move", 11): target,
            ("account.move", 310): payment_move,
            ("account.move.line", 111): target_line,
            ("account.move.line", 311): payment_receivable,
            ("account.move.line", 312): payment_liquidity,
            ("account.partial.reconcile", 501): partial,
            ("account.full.reconcile", 550): full,
            ("res.currency", 1): Record(1, rounding="0.01"),
        },
    )
    p = {
        "target_move_ids": [11], "payment_date": "2026-07-10", "amount": "100",
        "currency_id": 1, "journal_id": 2, "payment_method_line_id": 3,
        "memo": "PAY-1", "partner_id": 10, "partner_type": "customer",
        "direction": "inbound",
    }

    records, recovery = handler.execute_payment(
        p,
        handler.test_company,
        {"payment_binding": payment_binding(amount="100")},
    )

    stored_binding = payment.writes[-1]["odoo_cli_v3_payment_binding"]
    assert stored_binding == payment_binding(
        payment_id=301,
        payment_move_id=310,
        payment_line_ids=[311, 312],
        amount="100",
    )
    assert {(model, record.id) for model, record in records} == {
        ("account.payment", 301),
        ("account.move", 11),
        ("account.move", 310),
        ("account.move.line", 111),
        ("account.move.line", 311),
        ("account.move.line", 312),
        ("account.partial.reconcile", 501),
        ("account.full.reconcile", 550),
    }
    assert recovery["status"] == "available"
    assert recovery["method"] == "cancel_and_unreconcile_payment_v1"
    assert {(target["model"], target["record_id"]) for target in recovery["targets"]} == {
        ("account.payment", 301),
    }
    assert {
        (guard["model"], guard["record_id"], guard["expected_outcome"])
        for guard in recovery["guards"]
    } == {
        ("account.move", 11, "survive_allowed_delta"),
        ("account.move", 310, "survive_allowed_delta"),
        ("account.move.line", 111, "survive_allowed_delta"),
        ("account.move.line", 311, "survive_allowed_delta"),
        ("account.move.line", 312, "survive_allowed_delta"),
        ("account.partial.reconcile", 501, "absent"),
        ("account.full.reconcile", 550, "absent"),
    }
    target.snapshot_values = {
        "state": "posted",
        "line_ids": [111],
        "journal_id": 2,
        "currency_id": 1,
        "partner_id": 10,
        "amount_total": "100",
        "amount_residual": "0",
        "payment_state": "paid",
    }
    target_line.snapshot_values = {
        "move_id": 11,
        "account_id": 22,
        "currency_id": 1,
        "debit": "100",
        "credit": "0",
        "balance": "100",
        "amount_currency": "100",
        "amount_residual": "0",
        "amount_residual_currency": "0",
        "reconciled": True,
        "full_reconcile_id": 550,
        "matched_debit_ids": [],
        "matched_credit_ids": [501],
        "matching_number": "550",
    }
    before = {
        ("account.move", 11): {
            **target.snapshot_values,
            "amount_residual": "100",
            "payment_state": "not_paid",
        },
        ("account.move.line", 111): {
            **target_line.snapshot_values,
            "amount_residual": "100",
            "amount_residual_currency": "100",
            "reconciled": False,
            "full_reconcile_id": False,
            "matched_credit_ids": [],
            "matching_number": False,
        },
    }
    assert "record_graph_exact" in handler.verify_payment(
        p, handler.test_company, records, before
    )
    target_line.snapshot_values["debit"] = "99"
    with pytest.raises(OdooWriteHandlerError, match="allowlist"):
        handler.verify_payment(p, handler.test_company, records, before)


def test_payment_rejects_ambiguous_public_action_receipt():
    class Wizard(Record):
        partner_id = Record(10)
        currency_id = Record(1)
        journal_id = Record(2)
        payment_method_line_id = Record(3)
        partner_type = "customer"
        payment_type = "inbound"

        def action_create_payments(self):
            return True

    handler = Harness(models={"account.payment.register": Model(factory=lambda values: Wizard(1))})
    p = {
        "target_move_ids": [11], "payment_date": "2026-07-10", "amount": "50",
        "currency_id": 1, "journal_id": 2, "payment_method_line_id": 3,
        "memo": "PAY-1", "partner_id": 10, "partner_type": "customer",
        "direction": "inbound",
    }
    with pytest.raises(OdooWriteHandlerError, match="deterministic record receipt"):
        handler.execute_payment(
            p, handler.test_company, {"payment_binding": payment_binding()}
        )


def test_payment_precheck_rejects_ambiguous_multi_target_partial_allocation():
    comp = company(tax_exigibility=False)
    currency = Record(1, company_id=None, active=True, rounding="0.01")
    partner = Record(10, company_id=None, company_ids=[], active=True)
    journal = Record(
        2, company_id=comp, type="bank", active=True, currency_id=currency
    )
    method = Record(
        3,
        company_id=comp,
        journal_id=journal,
        payment_method_id=Record(4),
        payment_type="inbound",
    )
    payment_method = Record(4, payment_type="inbound")
    records = {
        ("res.currency", 1): currency,
        ("res.partner", 10): partner,
        ("account.journal", 2): journal,
        ("account.payment.method.line", 3): method,
        ("account.payment.method", 4): payment_method,
    }
    for move_id, line_id, residual in ((11, 111, 100), (12, 112, 50)):
        move = Record(
            move_id,
            state="posted",
            move_type="out_invoice",
            company_id=comp,
            partner_id=partner,
            currency_id=currency,
            amount_residual=residual,
            line_ids=[],
        )
        line = Record(
            line_id,
            company_id=comp,
            move_id=move,
            amount_residual=residual,
            amount_residual_currency=residual,
            reconciled=False,
            full_reconcile_id=None,
            matched_debit_ids=[],
            matched_credit_ids=[],
            tax_ids=[],
            tax_line_id=None,
            tax_repartition_line_id=None,
        )
        move.line_ids = [line]
        records[("account.move", move_id)] = move
        records[("account.move.line", line_id)] = line

    handler = Harness(
        models={"account.payment.register": Model()}, records=records
    )
    handler.test_company = comp
    parameters = {
        "company_id": 7,
        "target_move_ids": [11, 12],
        "payment_date": "2026-07-10",
        "amount": "100",
        "currency_id": 1,
        "journal_id": 2,
        "payment_method_line_id": 3,
        "memo": "PAY-MULTI",
        "partner_id": 10,
        "partner_type": "customer",
        "direction": "inbound",
    }
    single_target = {
        **parameters,
        "target_move_ids": [11],
        "amount": "100",
        "memo": "PAY-SINGLE",
    }
    checked = handler.precheck_payment(single_target, comp)
    assert {
        (item["model"], item["record_id"])
        for item in checked["dependencies"]
    } == {
        ("res.company", 7),
        ("res.partner", 10),
        ("account.journal", 2),
        ("res.currency", 1),
        ("account.payment.method.line", 3),
        ("account.payment.method", 4),
    }
    assert {
        (item["model"], item["record_id"])
        for item in checked["before"]
    } == {("account.move", 11), ("account.move.line", 111)}
    comp.tax_exigibility = True
    with pytest.raises(OdooWriteHandlerError, match="cash-basis"):
        handler.precheck_payment(single_target, comp)
    comp.tax_exigibility = False
    with pytest.raises(OdooWriteHandlerError, match="allocation"):
        handler.precheck_payment(parameters, comp)


def test_bank_import_creates_complete_statement_and_full_posted_move_graph():
    handler, line_model, statement_model, created = bank_graph_harness()
    p = bank_parameters_for_handler()
    records, recovery = handler.execute_bank(p, handler.test_company, {})
    assert len(created) == 2
    assert line_model.creates[0]["amount"] == 10.0
    assert line_model.creates[1]["amount"] == -3.0
    assert line_model.creates[0]["odoo_cli_v3_external_transaction_id"] == "T1"
    assert line_model.creates[0]["odoo_cli_v3_source_line_digest"] == "b" * 64
    assert line_model.creates[0]["odoo_cli_v3_value_date"] == "2026-07-10"
    assert line_model.creates[0]["transaction_details"] == {
        "version": 1,
        "external_reference": "BANK-2026-07-10",
        "statement_date": "2026-07-10",
        "statement_currency_id": 1,
        "opening_balance": "5",
        "closing_balance": "12",
        "source_digest": "a" * 64,
        "source_filename": "bank.csv",
        "source_line_digest": "b" * 64,
        "value_date": "2026-07-10",
    }
    assert statement_model.creates[0] == {
        "reference": "BANK-2026-07-10",
        "date": "2026-07-10",
        "balance_start": 5.0,
        "balance_end_real": 12.0,
        "line_ids": [(6, 0, [401, 402])],
        "odoo_cli_v3_external_reference": "BANK-2026-07-10",
        "odoo_cli_v3_source_digest": "a" * 64,
        "odoo_cli_v3_source_filename": "bank.csv",
    }
    assert {(model_name, record.id) for model_name, record in records} == {
        ("account.bank.statement", 390),
        ("account.bank.statement.line", 401),
        ("account.bank.statement.line", 402),
        ("account.move", 491),
        ("account.move", 492),
        ("account.move.line", 601),
        ("account.move.line", 602),
        ("account.move.line", 603),
        ("account.move.line", 604),
    }
    assert "statement_balances_match" in handler.verify_bank(
        p, handler.test_company, records
    )
    assert recovery["status"] == "available"
    assert recovery["method"] == "post_compensating_bank_statement_v1"
    assert all(
        guard["expected_outcome"] == "survive_exact"
        for guard in recovery["guards"]
    )


def test_bank_readback_rejects_changed_statement_provenance():
    handler, _line_model, _statement_model, _created = bank_graph_harness()
    p = bank_parameters_for_handler()
    records, _recovery = handler.execute_bank(p, handler.test_company, {})
    statement = next(
        record for model_name, record in records
        if model_name == "account.bank.statement"
    )
    statement.balance_start = 6
    with pytest.raises(OdooWriteHandlerError, match="statement balances"):
        handler.verify_bank(p, handler.test_company, records)

    statement.balance_start = 5
    line = next(
        record for model_name, record in records
        if model_name == "account.bank.statement.line"
        and record.odoo_cli_v3_external_transaction_id == "T1"
    )
    line.odoo_cli_v3_value_date = "2026-07-11"
    with pytest.raises(OdooWriteHandlerError, match="value date"):
        handler.verify_bank(p, handler.test_company, records)


def test_bank_foreign_suspense_and_computed_statement_date_match_odoo_19():
    handler, _line_model, _statement_model, _created = bank_graph_harness()
    p = bank_parameters_for_handler()
    p["statement_date"] = "2026-07-12"
    p["lines"][0].update(
        {
            "transaction_date": "2026-07-09",
            "value_date": "2026-07-10",
            "foreign_currency_id": 2,
            "foreign_amount": "12",
        }
    )
    p["lines"][1].update(
        {
            "transaction_date": "2026-07-11",
            "foreign_currency_id": 2,
            "foreign_amount": "-4",
        }
    )
    records, _recovery = handler.execute_bank(p, handler.test_company, {})

    statement = next(
        record
        for model_name, record in records
        if model_name == "account.bank.statement"
    )
    assert statement.date == "2026-07-11"
    assert "source_statement_date_matches" in handler.verify_bank(
        p, handler.test_company, records
    )
    foreign_line = next(
        record
        for model_name, record in records
        if model_name == "account.bank.statement.line"
        and record.odoo_cli_v3_external_transaction_id == "T1"
    )
    suspense = next(
        line
        for line in foreign_line.move_id.line_ids
        if line.account_id.id == 902
    )
    assert suspense.currency_id.id == 2
    assert suspense.amount_currency == Decimal("-12")
    debit_foreign_line = next(
        record
        for model_name, record in records
        if model_name == "account.bank.statement.line"
        and record.odoo_cli_v3_external_transaction_id == "T2"
    )
    debit_suspense = next(
        line
        for line in debit_foreign_line.move_id.line_ids
        if line.account_id.id == 902
    )
    assert debit_suspense.amount_currency == Decimal("4")


def test_bank_precheck_rejects_existing_source_identity_before_create():
    class DuplicateBankHarness(Harness):
        def __init__(self):
            super().__init__()
            self.journal = Record(
                2,
                type="bank",
                active=True,
                currency_id=Record(1),
                default_account_id=Record(901),
                suspense_account_id=Record(902),
            )
            self.searches = []
            self.duplicate = True

        def check_journal(self, parameters, company, allowed_types):
            return self.journal

        def assert_currency(self, currency_id, company, journal=None):
            return Record(currency_id, rounding="0.01")

        def check_account(self, account_id, company):
            return Record(account_id)

        def assert_open_date(self, *args, **kwargs):
            return date(2026, 7, 10)

        def create_model(self, *args, **kwargs):
            return object()

        def search_records(self, model_name, domain, company, *, limit=1):
            self.searches.append((model_name, domain, limit))
            if self.duplicate and any(
                field == "odoo_cli_v3_source_digest"
                for field, _operator, _value in domain
            ):
                return [Record(999)]
            return []

    handler = DuplicateBankHarness()
    wrong_sign = bank_parameters_for_handler()
    wrong_sign["lines"][1].update(
        {"foreign_currency_id": 2, "foreign_amount": "4"}
    )
    with pytest.raises(OdooWriteHandlerError, match="sign"):
        handler.precheck_bank(wrong_sign, handler.test_company)
    foreign_journal = bank_parameters_for_handler()
    foreign_journal["currency_id"] = 2
    handler.journal.currency_id = Record(2)
    with pytest.raises(OdooWriteHandlerError, match="rate preview"):
        handler.precheck_bank(foreign_journal, handler.test_company)
    handler.journal.currency_id = Record(1)
    handler.duplicate = False
    checked = handler.precheck_bank(
        bank_parameters_for_handler(), handler.test_company
    )
    assert {
        (item["model"], item["record_id"])
        for item in checked["dependencies"]
    } == {
        ("res.company", 7),
        ("account.journal", 2),
        ("res.currency", 1),
        ("account.account", 901),
        ("account.account", 902),
    }
    handler.duplicate = True
    with pytest.raises(OdooWriteHandlerError, match="already exists"):
        handler.precheck_bank(
            bank_parameters_for_handler(), handler.test_company
        )
    assert any(
        model_name == "account.bank.statement"
        and any(field == "reference" for field, _operator, _value in domain)
        for model_name, domain, _limit in handler.searches
    )
    assert any(
        any(
            field == "odoo_cli_v3_source_digest"
            for field, _operator, _value in domain
        )
        for _model_name, domain, _limit in handler.searches
    )


def test_reconciliation_uses_public_wizard_reconcile():
    comp = company()
    currency = Record(1, rounding="0.01")
    account = Record(22)
    move1 = Record(801, state="posted", company_id=comp, line_ids=[])
    move2 = Record(802, state="posted", company_id=comp, line_ids=[])
    line1 = Record(
        501,
        company_id=comp,
        move_id=move1,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=40,
        amount_residual_currency=40,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[Record(701)],
        matching_number="P701",
    )
    line2 = Record(
        502,
        company_id=comp,
        move_id=move2,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=None,
        matched_debit_ids=[Record(701)],
        matched_credit_ids=[],
        matching_number="P701",
    )
    other_account = Record(23)
    untouched_line = Record(
        503,
        company_id=comp,
        move_id=move1,
        account_id=other_account,
        partner_id=None,
        currency_id=currency,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        matching_number=False,
        tax_ids=[],
        tax_line_id=None,
        tax_repartition_line_id=None,
    )
    partial = Record(
        701,
        company_id=comp,
        debit_move_id=line1,
        credit_move_id=line2,
        amount=60,
        debit_amount_currency=60,
        credit_amount_currency=60,
        company_currency_id=currency,
        debit_currency_id=currency,
        credit_currency_id=currency,
        full_reconcile_id=None,
        exchange_move_id=None,
        max_date="2026-07-10",
        draft_caba_move_vals=None,
    )
    move1.line_ids = [line1, untouched_line]
    move2.line_ids = [line2]

    class Result:
        ids = [501, 502]

    class Wizard(Record):
        def reconcile(self):
            self.called = True
            return Result()

    wizard = Wizard(1)
    model = Model(factory=lambda values: wizard)
    handler = Harness(
        models={"account.reconcile.wizard": model},
        records={
            ("account.move", 801): move1,
            ("account.move", 802): move2,
            ("account.move.line", 501): line1,
            ("account.move.line", 502): line2,
            ("account.move.line", 503): untouched_line,
            ("account.partial.reconcile", 701): partial,
            ("res.currency", 1): currency,
        },
    )
    handler.test_company = comp
    p = {
        "company_id": 7,
        "line_ids": [501, 502], "reconciliation_date": "2026-07-10",
        "account_id": 22, "partner_id": None, "currency_id": 1,
        "amount": "60", "tolerance_amount": "0", "mode": "partial",
        "writeoff_account_id": None,
        "writeoff_journal_id": None, "writeoff_label": None,
    }
    records, recovery = handler.execute_reconciliation(
        p,
        handler.test_company,
        {"before": [
            {"model": "account.move", "record_id": 801},
            {"model": "account.move", "record_id": 802},
            {"model": "account.move.line", "record_id": 501},
            {"model": "account.move.line", "record_id": 502},
            {"model": "account.move.line", "record_id": 503},
        ]},
    )
    assert wizard.called is True
    assert model.creates[0]["allow_partials"] is True
    assert {(model_name, record.id) for model_name, record in records} == {
        ("account.move", 801),
        ("account.move", 802),
        ("account.move.line", 501),
        ("account.move.line", 502),
        ("account.move.line", 503),
        ("account.partial.reconcile", 701),
    }
    before = {
        ("account.move", 801): {"state": "posted", "line_ids": [501, 503]},
        ("account.move", 802): {"state": "posted", "line_ids": [502]},
        ("account.move.line", 501): {
            "move_id": 801,
            "amount_residual": "100",
            "amount_residual_currency": "100",
            "matched_debit_ids": [],
            "matched_credit_ids": [],
            "full_reconcile_id": False,
            "matching_number": False,
            "reconciled": False,
        },
        ("account.move.line", 502): {
            "move_id": 802,
            "amount_residual": "-60",
            "amount_residual_currency": "-60",
            "matched_debit_ids": [],
            "matched_credit_ids": [],
            "full_reconcile_id": False,
            "matching_number": False,
            "reconciled": False,
        },
        ("account.move.line", 503): {
            "move_id": 801,
            "account_id": 23,
            "balance": "-100",
            "amount_residual": "0",
            "amount_residual_currency": "0",
            "matched_debit_ids": [],
            "matched_credit_ids": [],
            "full_reconcile_id": False,
            "matching_number": False,
            "reconciled": False,
        },
    }
    move1.snapshot_values = dict(before[("account.move", 801)])
    move2.snapshot_values = dict(before[("account.move", 802)])
    line1.snapshot_values = {
        **before[("account.move.line", 501)],
        "amount_residual": "40",
        "amount_residual_currency": "40",
        "matched_credit_ids": [701],
        "matching_number": "P701",
    }
    line2.snapshot_values = {
        **before[("account.move.line", 502)],
        "amount_residual": "0",
        "amount_residual_currency": "0",
        "matched_debit_ids": [701],
        "reconciled": True,
        "matching_number": "P701",
    }
    untouched_line.snapshot_values = dict(before[("account.move.line", 503)])
    assert "partial_amount_matches" in handler.verify_reconciliation(
        p, handler.test_company, records, before
    )
    partial.amount = 59
    with pytest.raises(OdooWriteHandlerError, match="partial reconcile amount"):
        handler.verify_reconciliation(p, handler.test_company, records, before)
    partial.amount = 60
    untouched_line.snapshot_values["balance"] = "-99"
    with pytest.raises(OdooWriteHandlerError, match="allowlist"):
        handler.verify_reconciliation(p, handler.test_company, records, before)
    assert recovery["status"] == "available"
    assert recovery["method"] == (
        "undo_reconciliation_and_reverse_writeoff_v1"
    )


def test_reconciliation_with_prior_reconcile_graph_escalates_recovery():
    comp = company()
    currency = Record(1, rounding="0.01")
    account = Record(22)
    move1 = Record(801, state="posted", company_id=comp, line_ids=[])
    move2 = Record(802, state="posted", company_id=comp, line_ids=[])
    line1 = Record(
        501,
        company_id=comp,
        move_id=move1,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=40,
        amount_residual_currency=40,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[Record(701)],
    )
    line2 = Record(
        502,
        company_id=comp,
        move_id=move2,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=None,
        matched_debit_ids=[Record(701)],
        matched_credit_ids=[],
    )
    partial = Record(
        701,
        company_id=comp,
        debit_move_id=line1,
        credit_move_id=line2,
        amount=60,
        debit_amount_currency=60,
        credit_amount_currency=60,
        company_currency_id=currency,
        debit_currency_id=currency,
        credit_currency_id=currency,
        full_reconcile_id=None,
        exchange_move_id=None,
    )
    move1.line_ids = [line1]
    move2.line_ids = [line2]

    class Result:
        ids = [501, 502]

    class Wizard(Record):
        def reconcile(self):
            return Result()

    handler = Harness(
        models={
            "account.reconcile.wizard": Model(
                factory=lambda values: Wizard(1)
            )
        },
        records={
            ("account.move", 801): move1,
            ("account.move", 802): move2,
            ("account.move.line", 501): line1,
            ("account.move.line", 502): line2,
            ("account.partial.reconcile", 701): partial,
        },
    )
    handler.test_company = comp
    parameters = {
        "company_id": 7,
        "line_ids": [501, 502],
        "reconciliation_date": "2026-07-10",
        "account_id": 22,
        "partner_id": None,
        "currency_id": 1,
        "amount": "60",
        "tolerance_amount": "0",
        "mode": "partial",
        "writeoff_account_id": None,
        "writeoff_journal_id": None,
        "writeoff_label": None,
    }
    before = [
        {"model": "account.move", "record_id": 801},
        {"model": "account.move", "record_id": 802},
        {
            "model": "account.move.line",
            "record_id": 501,
            "values": {
                "matched_debit_ids": [],
                "matched_credit_ids": [900],
                "full_reconcile_id": 901,
            },
        },
        {"model": "account.move.line", "record_id": 502},
    ]

    _records, recovery = handler.execute_reconciliation(
        parameters, handler.test_company, {"before": before}
    )

    assert recovery == {
        "status": "manual_escalation",
        "method": "manual_review_reconciliation_recovery",
        "targets": [
            {"model": "account.partial.reconcile", "record_id": 701}
        ],
    }


def test_full_reconciliation_returns_and_verifies_full_reconcile_identity():
    comp = company()
    currency = Record(1, rounding="0.01")
    account = Record(22)
    full = Record(800, partial_reconcile_ids=[], reconciled_line_ids=[])
    move1 = Record(811, state="posted", company_id=comp, line_ids=[])
    move2 = Record(812, state="posted", company_id=comp, line_ids=[])
    line1 = Record(
        511,
        company_id=comp,
        move_id=move1,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=full,
        matched_debit_ids=[],
        matched_credit_ids=[Record(710)],
        matching_number="800",
    )
    line2 = Record(
        512,
        company_id=comp,
        move_id=move2,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=full,
        matched_debit_ids=[Record(710)],
        matched_credit_ids=[],
        matching_number="800",
    )
    partial = Record(
        710,
        company_id=comp,
        debit_move_id=line1,
        credit_move_id=line2,
        amount=100,
        debit_amount_currency=100,
        credit_amount_currency=100,
        company_currency_id=currency,
        debit_currency_id=currency,
        credit_currency_id=currency,
        full_reconcile_id=full,
        exchange_move_id=None,
        max_date="2026-07-10",
        draft_caba_move_vals=None,
    )
    full.partial_reconcile_ids = [partial]
    full.reconciled_line_ids = [line1, line2]
    move1.line_ids = [line1]
    move2.line_ids = [line2]

    class Result:
        ids = [511, 512]

    class Wizard(Record):
        def reconcile(self):
            return Result()

    handler = Harness(
        models={
            "account.reconcile.wizard": Model(
                factory=lambda values: Wizard(1)
            )
        },
        records={
            ("account.move", 811): move1,
            ("account.move", 812): move2,
            ("account.move.line", 511): line1,
            ("account.move.line", 512): line2,
            ("account.partial.reconcile", 710): partial,
            ("account.full.reconcile", 800): full,
            ("res.currency", 1): currency,
        },
    )
    handler.test_company = comp
    p = {
        "company_id": 7,
        "line_ids": [511, 512],
        "reconciliation_date": "2026-07-10",
        "account_id": 22,
        "partner_id": None,
        "currency_id": 1,
        "amount": "100",
        "tolerance_amount": "0",
        "mode": "full",
        "writeoff_account_id": None,
        "writeoff_journal_id": None,
        "writeoff_label": None,
    }
    before_refs = [
        {"model": "account.move", "record_id": 811},
        {"model": "account.move", "record_id": 812},
        {"model": "account.move.line", "record_id": 511},
        {"model": "account.move.line", "record_id": 512},
    ]
    records, _recovery = handler.execute_reconciliation(
        p, comp, {"before": before_refs}
    )
    assert ("account.full.reconcile", full) in records
    before = {
        ("account.move", 811): {"state": "posted", "line_ids": [511]},
        ("account.move", 812): {"state": "posted", "line_ids": [512]},
        ("account.move.line", 511): {
            "move_id": 811,
            "amount_residual": "100", "amount_residual_currency": "100",
            "matched_debit_ids": [], "matched_credit_ids": [],
            "full_reconcile_id": False, "matching_number": False,
            "reconciled": False,
        },
        ("account.move.line", 512): {
            "move_id": 812,
            "amount_residual": "-100", "amount_residual_currency": "-100",
            "matched_debit_ids": [], "matched_credit_ids": [],
            "full_reconcile_id": False, "matching_number": False,
            "reconciled": False,
        },
    }
    move1.snapshot_values = dict(before[("account.move", 811)])
    move2.snapshot_values = dict(before[("account.move", 812)])
    line1.snapshot_values = {
        **before[("account.move.line", 511)],
        "amount_residual": "0",
        "amount_residual_currency": "0",
        "matched_credit_ids": [710],
        "full_reconcile_id": 800,
        "matching_number": "800",
        "reconciled": True,
    }
    line2.snapshot_values = {
        **before[("account.move.line", 512)],
        "amount_residual": "0",
        "amount_residual_currency": "0",
        "matched_debit_ids": [710],
        "full_reconcile_id": 800,
        "matching_number": "800",
        "reconciled": True,
    }
    assert "matching_numbers_match" in handler.verify_reconciliation(
        p, comp, records, before
    )
    full.partial_reconcile_ids = []
    with pytest.raises(OdooWriteHandlerError, match="partial set"):
        handler.verify_reconciliation(p, comp, records, before)


def test_full_reconciliation_captures_exact_writeoff_move_closure():
    comp = company()
    currency = Record(1, rounding="0.01")
    account = Record(22)
    writeoff_account = Record(99)
    full = Record(800, partial_reconcile_ids=[], reconciled_line_ids=[])
    move1 = Record(811, state="posted", company_id=comp, line_ids=[])
    move2 = Record(812, state="posted", company_id=comp, line_ids=[])
    line1 = Record(
        511,
        company_id=comp,
        move_id=move1,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=full,
        matched_debit_ids=[],
        matched_credit_ids=[Record(710), Record(711)],
        matching_number="800",
    )
    line2 = Record(
        512,
        company_id=comp,
        move_id=move2,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=full,
        matched_debit_ids=[Record(710)],
        matched_credit_ids=[],
        matching_number="800",
    )
    writeoff_move = Record(
        900,
        state="posted",
        company_id=comp,
        journal_id=Record(77),
        date="2026-07-10",
        tax_cash_basis_rec_id=None,
        line_ids=[],
    )
    reconcile_line = Record(
        513,
        company_id=comp,
        move_id=writeoff_move,
        account_id=account,
        partner_id=None,
        currency_id=currency,
        debit=0,
        credit=40,
        balance=-40,
        amount_currency=-40,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=True,
        full_reconcile_id=full,
        matched_debit_ids=[Record(711)],
        matched_credit_ids=[],
        matching_number="800",
        tax_ids=[],
        tax_line_id=None,
        tax_repartition_line_id=None,
    )
    writeoff_line = Record(
        514,
        company_id=comp,
        move_id=writeoff_move,
        account_id=writeoff_account,
        partner_id=None,
        currency_id=currency,
        name="Approved difference",
        debit=40,
        credit=0,
        balance=40,
        amount_currency=40,
        amount_residual=0,
        amount_residual_currency=0,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        matching_number=False,
        tax_ids=[],
        tax_line_id=None,
        tax_repartition_line_id=None,
    )
    partial1 = Record(
        710,
        company_id=comp,
        debit_move_id=line1,
        credit_move_id=line2,
        amount=60,
        debit_amount_currency=60,
        credit_amount_currency=60,
        company_currency_id=currency,
        debit_currency_id=currency,
        credit_currency_id=currency,
        full_reconcile_id=full,
        exchange_move_id=None,
    )
    partial2 = Record(
        711,
        company_id=comp,
        debit_move_id=line1,
        credit_move_id=reconcile_line,
        amount=40,
        debit_amount_currency=40,
        credit_amount_currency=40,
        company_currency_id=currency,
        debit_currency_id=currency,
        credit_currency_id=currency,
        full_reconcile_id=full,
        exchange_move_id=None,
    )
    move1.line_ids = [line1]
    move2.line_ids = [line2]
    writeoff_move.line_ids = [reconcile_line, writeoff_line]
    full.partial_reconcile_ids = [partial1, partial2]
    full.reconciled_line_ids = [line1, line2, reconcile_line]

    class Result:
        ids = [511, 512]

    class Wizard(Record):
        def reconcile(self):
            return Result()

    handler = Harness(
        models={
            "account.reconcile.wizard": Model(
                factory=lambda values: Wizard(1)
            )
        },
        records={
            ("account.move", 811): move1,
            ("account.move", 812): move2,
            ("account.move", 900): writeoff_move,
            ("account.move.line", 511): line1,
            ("account.move.line", 512): line2,
            ("account.move.line", 513): reconcile_line,
            ("account.move.line", 514): writeoff_line,
            ("account.partial.reconcile", 710): partial1,
            ("account.partial.reconcile", 711): partial2,
            ("account.full.reconcile", 800): full,
            ("res.currency", 1): currency,
        },
    )
    handler.test_company = comp
    p = {
        "company_id": 7,
        "line_ids": [511, 512],
        "reconciliation_date": "2026-07-10",
        "account_id": 22,
        "partner_id": None,
        "currency_id": 1,
        "amount": "60",
        "tolerance_amount": "40",
        "mode": "full",
        "writeoff_account_id": 99,
        "writeoff_journal_id": 77,
        "writeoff_label": "Approved difference",
    }
    before_refs = [
        {"model": "account.move", "record_id": 811},
        {"model": "account.move", "record_id": 812},
        {"model": "account.move.line", "record_id": 511},
        {"model": "account.move.line", "record_id": 512},
    ]
    records, _recovery = handler.execute_reconciliation(
        p, comp, {"before": before_refs}
    )
    assert {(model, record.id) for model, record in records} == {
        ("account.move", 811),
        ("account.move", 812),
        ("account.move", 900),
        ("account.move.line", 511),
        ("account.move.line", 512),
        ("account.move.line", 513),
        ("account.move.line", 514),
        ("account.partial.reconcile", 710),
        ("account.partial.reconcile", 711),
        ("account.full.reconcile", 800),
    }
    before = {
        ("account.move", 811): {"state": "posted", "line_ids": [511]},
        ("account.move", 812): {"state": "posted", "line_ids": [512]},
        ("account.move.line", 511): {
            "move_id": 811,
            "amount_residual": "100",
            "amount_residual_currency": "100",
            "matched_debit_ids": [],
            "matched_credit_ids": [],
            "full_reconcile_id": False,
            "matching_number": False,
            "reconciled": False,
        },
        ("account.move.line", 512): {
            "move_id": 812,
            "amount_residual": "-60",
            "amount_residual_currency": "-60",
            "matched_debit_ids": [],
            "matched_credit_ids": [],
            "full_reconcile_id": False,
            "matching_number": False,
            "reconciled": False,
        },
    }
    move1.snapshot_values = dict(before[("account.move", 811)])
    move2.snapshot_values = dict(before[("account.move", 812)])
    line1.snapshot_values = {
        **before[("account.move.line", 511)],
        "amount_residual": "0",
        "amount_residual_currency": "0",
        "matched_credit_ids": [710, 711],
        "full_reconcile_id": 800,
        "matching_number": "800",
        "reconciled": True,
    }
    line2.snapshot_values = {
        **before[("account.move.line", 512)],
        "amount_residual": "0",
        "amount_residual_currency": "0",
        "matched_debit_ids": [710],
        "full_reconcile_id": 800,
        "matching_number": "800",
        "reconciled": True,
    }
    assert "writeoff_matches" in handler.verify_reconciliation(
        p, comp, records, before
    )


def test_reconciliation_precheck_accepts_explicit_null_partner_without_lookup():
    comp = company()
    account = Record(22, reconcile=True, company_id=comp)
    move1 = Record(801, state="posted", company_id=comp, line_ids=[])
    move2 = Record(802, state="posted", company_id=comp, line_ids=[])
    lines = {
        ("account.move.line", 501): Record(
            501,
            company_id=comp,
            account_id=account,
            partner_id=None,
            reconciled=False,
            move_id=move1,
            amount_residual=100,
            amount_residual_currency=100,
            currency_id=Record(1),
            full_reconcile_id=None,
            matched_debit_ids=[],
            matched_credit_ids=[],
            matching_number=False,
            tax_ids=[],
            tax_line_id=None,
            tax_repartition_line_id=None,
        ),
        ("account.move.line", 502): Record(
            502,
            company_id=comp,
            account_id=account,
            partner_id=None,
            reconciled=False,
            move_id=move2,
            amount_residual=-60,
            amount_residual_currency=-60,
            currency_id=Record(1),
            full_reconcile_id=None,
            matched_debit_ids=[],
            matched_credit_ids=[],
            matching_number=False,
            tax_ids=[],
            tax_line_id=None,
            tax_repartition_line_id=None,
        ),
    }
    untouched_line = Record(
        503,
        company_id=comp,
        account_id=Record(23),
        partner_id=None,
        reconciled=False,
        move_id=move1,
        amount_residual=0,
        amount_residual_currency=0,
        currency_id=Record(1),
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        matching_number=False,
        tax_ids=[],
        tax_line_id=None,
        tax_repartition_line_id=None,
    )
    lines[("account.move.line", 503)] = untouched_line
    move1.line_ids = [lines[("account.move.line", 501)], untouched_line]
    move2.line_ids = [lines[("account.move.line", 502)]]
    lines[("account.move", 801)] = move1
    lines[("account.move", 802)] = move2

    class NullablePartnerHarness(Harness):
        def check_account(self, account_id, company):
            assert account_id == 22
            return account

        def check_partner(self, partner_id, company):
            raise AssertionError("null partner must not trigger a partner lookup")

        def assert_currency(self, currency_id, company, journal=None):
            return Record(currency_id, rounding=0.01)

        def assert_open_date(self, *args, **kwargs):
            return date(2026, 7, 10)

        def create_model(self, *args, **kwargs):
            return object()

    handler = NullablePartnerHarness(records=lines)
    handler.test_company = comp
    result = handler.precheck_reconciliation(
        {
            "company_id": 7,
            "line_ids": [501, 502],
            "account_id": 22,
            "partner_id": None,
            "reconciliation_date": "2026-07-10",
            "currency_id": 1,
            "mode": "partial",
            "amount": "60",
            "tolerance_amount": "0",
            "writeoff_account_id": None,
            "writeoff_journal_id": None,
            "writeoff_label": None,
        },
        comp,
    )

    assert "partner" in result["checks"]
    assert {
        (item["model"], item["record_id"])
        for item in result["before"]
    } == {
        ("account.move", 801),
        ("account.move", 802),
        ("account.move.line", 501),
        ("account.move.line", 502),
        ("account.move.line", 503),
    }
    assert {
        (item["model"], item["record_id"])
        for item in result["dependencies"]
    } == {
        ("res.company", 7),
        ("account.account", 22),
        ("res.currency", 1),
    }
    comp.tax_exigibility = True
    with pytest.raises(OdooWriteHandlerError, match="cash-basis"):
        handler.precheck_reconciliation(
            {
                "company_id": 7,
                "line_ids": [501, 502],
                "account_id": 22,
                "partner_id": None,
                "reconciliation_date": "2026-07-10",
                "currency_id": 1,
                "mode": "partial",
                "amount": "60",
                "tolerance_amount": "0",
                "writeoff_account_id": None,
                "writeoff_journal_id": None,
                "writeoff_label": None,
            },
            comp,
        )
    comp.tax_exigibility = False
    lines[("account.move.line", 501)].tax_ids = [Record(31)]
    with pytest.raises(OdooWriteHandlerError, match="tax-bearing"):
        handler.precheck_reconciliation(
            {
                "company_id": 7,
                "line_ids": [501, 502],
                "account_id": 22,
                "partner_id": None,
                "reconciliation_date": "2026-07-10",
                "currency_id": 1,
                "mode": "partial",
                "amount": "60",
                "tolerance_amount": "0",
                "writeoff_account_id": None,
                "writeoff_journal_id": None,
                "writeoff_label": None,
            },
            comp,
        )
    lines[("account.move.line", 501)].tax_ids = []
    lines[("account.move.line", 501)].matched_credit_ids = [Record(799)]
    with pytest.raises(OdooWriteHandlerError, match="open posted"):
        handler.precheck_reconciliation(
            {
                "company_id": 7,
                "line_ids": [501, 502],
                "account_id": 22,
                "partner_id": None,
                "reconciliation_date": "2026-07-10",
                "currency_id": 1,
                "mode": "partial",
                "amount": "60",
                "tolerance_amount": "0",
                "writeoff_account_id": None,
                "writeoff_journal_id": None,
                "writeoff_label": None,
            },
            comp,
        )


def test_asset_uses_public_create_and_validate_and_does_not_write_state_or_currency():
    source_move = Record(54, state="posted", company_id=Record(7), line_ids=[])
    source = Record(55, company_id=Record(7), move_id=source_move, asset_ids=[])
    dep_debit = Record(603, company_id=Record(7), debit=1200.0, credit=0.0)
    dep_credit = Record(604, company_id=Record(7), debit=0.0, credit=1200.0)
    depreciation = Record(
        602, state="posted", company_id=Record(7),
        line_ids=SimpleNamespace(ids=[603, 604]),
    )
    asset = Record(
        601, state="draft", company_id=Record(7), depreciation_move_ids=[]
    )

    def validate():
        asset.validated = True
        asset.state = "open"
        asset.depreciation_move_ids = [depreciation]

    asset.validate = validate
    asset_model = Record(
        600, method="linear", method_number=12, method_period="1",
        method_progress_factor=1.0, prorata_computation_type="none", prorata_date=None,
        salvage_value=0.0, account_asset_id=Record(20), account_depreciation_id=Record(21),
        account_depreciation_expense_id=Record(22), journal_id=Record(23),
    )
    model = Model(factory=lambda values: asset)
    handler = Harness(
        models={"account.asset": model},
        records={
            ("account.asset", 600): asset_model,
            ("account.move", 54): source_move,
            ("account.move.line", 55): source,
            ("account.move", 602): depreciation,
            ("account.move.line", 603): dep_debit,
            ("account.move.line", 604): dep_credit,
        },
    )
    p = {
        "company_id": 7, "asset_name": "Laptop", "asset_model_id": 600,
        "acquisition_date": "2026-07-10", "acquisition_value": "1200",
        "source_move_line_id": 55, "posting_mode": "confirm",
    }
    records, recovery = handler.execute_asset(p, handler.test_company, {})
    values = model.creates[0]
    assert values["model_id"] == 600
    assert values["original_move_line_ids"] == [(6, 0, [55])]
    assert "state" not in values
    assert "currency_id" not in values
    assert asset.validated is True
    assert [(model_name, record.id) for model_name, record in records] == [
        ("account.asset", 601),
        ("account.move", 54),
        ("account.move.line", 55),
        ("account.move", 602),
        ("account.move.line", 603),
        ("account.move.line", 604),
    ]
    assert recovery["status"] == "available"
    assert recovery["method"] == "cancel_asset_and_reverse_schedule_v1"


def test_asset_precheck_binds_full_source_model_accounts_and_allows_cancelled_prior_asset():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding=0.01)
    source_move = Record(
        54, company_id=comp, state="posted", line_ids=SimpleNamespace(ids=[55, 56])
    )
    cancelled = Record(99, company_id=comp, state="cancelled")
    source = Record(
        55, company_id=comp, move_id=source_move, balance=1200.0,
        account_id=Record(20), asset_ids=[cancelled],
    )
    counterpart = Record(56, company_id=comp, move_id=source_move)
    asset_account = Record(20, company_id=comp, account_type="asset_fixed", deprecated=False)
    accumulated = Record(21, company_id=comp, account_type="asset_fixed", deprecated=False)
    expense = Record(22, company_id=comp, account_type="expense_depreciation", deprecated=False)
    journal = Record(23, company_id=comp, type="general", active=True)
    asset_model = Record(
        600, company_id=comp, state="model", account_asset_id=asset_account,
        account_depreciation_id=accumulated,
        account_depreciation_expense_id=expense, journal_id=journal,
    )
    handler = Harness(
        models={"account.asset": Model()},
        records={
            ("account.move", 54): source_move,
            ("account.move.line", 55): source,
            ("account.move.line", 56): counterpart,
            ("account.asset", 600): asset_model,
            ("account.account", 20): asset_account,
            ("account.account", 21): accumulated,
            ("account.account", 22): expense,
            ("account.journal", 23): journal,
            ("res.currency", 1): currency,
        },
    )
    handler.test_company = comp
    checked = handler.precheck_asset(
        {
            "company_id": 7, "source_move_line_id": 55,
            "asset_model_id": 600, "currency_id": 1,
            "acquisition_value": "1200", "acquisition_date": "2026-07-10",
        },
        comp,
    )
    assert {(item["model"], item["record_id"]) for item in checked["before"]} == {
        ("account.move", 54), ("account.move.line", 55),
        ("account.move.line", 56),
    }
    assert {(item["model"], item["record_id"]) for item in checked["dependencies"]} == {
        ("res.company", 7), ("res.currency", 1), ("account.asset", 600),
        ("account.account", 20), ("account.account", 21),
        ("account.account", 22), ("account.journal", 23),
    }
    asset_account.account_type = "asset_current"
    with pytest.raises(OdooWriteHandlerError, match="fixed or non-current"):
        handler.precheck_asset(
            {
                "company_id": 7, "source_move_line_id": 55,
                "asset_model_id": 600, "currency_id": 1,
                "acquisition_value": "1200", "acquisition_date": "2026-07-10",
            },
            comp,
        )


def test_asset_verifier_requires_exact_schedule_accounts_total_and_source_graph():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding=0.01)
    asset_account = Record(20, company_id=comp)
    accumulated = Record(21, company_id=comp)
    expense = Record(22, company_id=comp)
    journal = Record(23, company_id=comp, type="general", active=True)
    source_move = Record(
        54, company_id=comp, state="posted", line_ids=SimpleNamespace(ids=[55])
    )
    asset = Record(
        601, company_id=comp, state="open", model_id=Record(600), name="Laptop",
        acquisition_date=date(2026, 7, 10), original_value=1200.0,
        currency_id=currency, original_move_line_ids=SimpleNamespace(ids=[55]),
        journal_id=journal, account_asset_id=asset_account,
        account_depreciation_id=accumulated,
        account_depreciation_expense_id=expense, method="linear",
        method_number=12, method_period="1", method_progress_factor=1.0,
        prorata_computation_type="none", prorata_date=None, salvage_value=0.0,
        depreciation_move_ids=SimpleNamespace(ids=[602]), value_residual=0.0,
    )
    source = Record(
        55, company_id=comp, move_id=source_move,
        asset_ids=SimpleNamespace(ids=[601]),
    )
    dep_debit = Record(
        603, company_id=comp, move_id=Record(602), account_id=expense,
        debit=1200.0, credit=0.0, balance=1200.0,
    )
    dep_credit = Record(
        604, company_id=comp, move_id=Record(602), account_id=accumulated,
        debit=0.0, credit=1200.0, balance=-1200.0,
    )
    depreciation = Record(
        602, company_id=comp, state="posted", asset_id=asset,
        asset_move_type="depreciation", journal_id=journal, currency_id=currency,
        depreciation_value=1200.0, line_ids=SimpleNamespace(ids=[603, 604]),
    )
    handler = Harness(records={
        ("res.currency", 1): currency,
        ("account.asset", 600): Record(
            600, company_id=comp, account_asset_id=asset_account,
            account_depreciation_id=accumulated,
            account_depreciation_expense_id=expense, journal_id=journal,
            method="linear", method_number=12, method_period="1",
            method_progress_factor=1.0, prorata_computation_type="none",
            prorata_date=None, salvage_value=0.0,
        ),
        ("account.move", 54): source_move,
        ("account.move.line", 55): source,
        ("account.move", 602): depreciation,
        ("account.move.line", 603): dep_debit,
        ("account.move.line", 604): dep_credit,
    })
    handler.test_company = comp
    parameters = {
        "company_id": 7, "asset_name": "Laptop", "asset_model_id": 600,
        "acquisition_date": "2026-07-10", "acquisition_value": "1200",
        "source_move_line_id": 55, "posting_mode": "confirm", "currency_id": 1,
    }
    records = [
        ("account.asset", asset), ("account.move", source_move),
        ("account.move.line", source), ("account.move", depreciation),
        ("account.move.line", dep_debit), ("account.move.line", dep_credit),
    ]
    assert "schedule_total_matches" in handler.verify_asset(
        parameters, comp, records
    )
    dep_debit.account_id = asset_account
    with pytest.raises(OdooWriteHandlerError, match="unexpected account"):
        handler.verify_asset(parameters, comp, records)


def test_depreciation_posts_only_the_explicit_depreciation_move():
    line1 = Record(703, company_id=Record(7))
    line2 = Record(704, company_id=Record(7))
    move = Record(
        702, state="draft", company_id=Record(7),
        line_ids=SimpleNamespace(ids=[703, 704]),
    )
    asset = Record(
        701, state="open", company_id=Record(7), depreciation_move_ids=[move]
    )
    move.asset_id = asset
    handler = Harness(records={
        ("account.asset", 701): asset,
        ("account.move", 702): move,
        ("account.move.line", 703): line1,
        ("account.move.line", 704): line2,
    })
    records, recovery = handler.execute_depreciation(
        {"asset_id": 701, "depreciation_move_id": 702}, handler.test_company, {}
    )
    assert [(model_name, record.id) for model_name, record in records] == [
        ("account.asset", 701), ("account.move", 702),
        ("account.move.line", 703), ("account.move.line", 704),
    ]
    assert move.action_post_calls == 1
    assert recovery["status"] == "available"
    assert recovery["method"] == (
        "reverse_depreciation_and_restore_schedule_v1"
    )


def depreciation_precheck_fixture():
    comp = company()
    currency = Record(1, active=True, rounding=0.01)
    journal = Record(2, company_id=comp, type="general", active=True, currency_id=currency)
    accumulated = Record(21, company_id=comp, account_type="asset_fixed")
    expense = Record(22, company_id=comp, account_type="expense_depreciation")
    asset = Record(
        701, company_id=comp, state="open", depreciation_move_ids=SimpleNamespace(ids=[702]),
        prorata_computation_type="daily_computation",
        currency_id=currency,
        account_depreciation_id=accumulated,
        account_depreciation_expense_id=expense,
    )
    line1 = Record(
        703, company_id=comp, debit=100.0, credit=0.0, balance=100.0,
        account_id=expense,
    )
    line2 = Record(
        704, company_id=comp, debit=0.0, credit=100.0, balance=-100.0,
        account_id=accumulated,
    )
    move = Record(
        702, company_id=comp, state="draft", asset_id=asset,
        asset_move_type="depreciation", journal_id=journal, currency_id=currency,
        date=date(2026, 7, 10), asset_depreciation_beginning_date=date(2026, 7, 1),
        asset_number_days=10, depreciation_value=100.0,
        line_ids=SimpleNamespace(ids=[703, 704]),
    )
    handler = Harness(records={
        ("account.asset", 701): asset, ("account.move", 702): move,
        ("account.journal", 2): journal, ("res.currency", 1): currency,
        ("account.account", 21): accumulated,
        ("account.account", 22): expense,
        ("account.move.line", 703): line1, ("account.move.line", 704): line2,
    })
    handler.test_company = comp
    parameters = {
        "company_id": 7, "asset_id": 701, "depreciation_move_id": 702,
        "period_start": "2026-07-01", "period_end": "2026-07-10",
        "posting_date": "2026-07-10", "journal_id": 2,
        "currency_id": 1, "amount": "100",
    }
    return handler, move, parameters


def test_depreciation_precheck_binds_odoo_schedule_type_period_days_and_value():
    handler, move, parameters = depreciation_precheck_fixture()
    checked = handler.precheck_depreciation(parameters, handler.test_company)
    assert "scheduled_depreciation_move" in checked["checks"]
    assert "depreciation_value" in checked["checks"]
    assert "day_count" not in checked["checks"]
    assert {(item["model"], item["record_id"]) for item in checked["before"]} == {
        ("account.asset", 701), ("account.move", 702),
        ("account.move.line", 703), ("account.move.line", 704),
    }

    mutations = (
        ("asset_move_type", "sale", "not a depreciation"),
        ("asset_depreciation_beginning_date", date(2026, 7, 2), "beginning date"),
        ("depreciation_value", 99.0, "depreciation value"),
    )
    for field, bad_value, message in mutations:
        original = getattr(move, field)
        setattr(move, field, bad_value)
        with pytest.raises(OdooWriteHandlerError, match=message):
            handler.precheck_depreciation(parameters, handler.test_company)
        setattr(move, field, original)


def test_depreciation_verifier_binds_full_schedule_residual_and_other_moves():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding=0.01)
    journal = Record(2, company_id=comp, type="general", active=True)
    accumulated = Record(21, company_id=comp)
    expense = Record(22, company_id=comp)
    asset = Record(
        701, company_id=comp, state="open", value_residual=100.0,
        book_value=100.0,
        currency_id=currency,
        account_depreciation_id=accumulated,
        account_depreciation_expense_id=expense,
        depreciation_move_ids=SimpleNamespace(ids=[702, 705]),
    )
    target_debit = Record(
        703, company_id=comp, account_id=expense,
        debit=100.0, credit=0.0, balance=100.0,
    )
    target_credit = Record(
        704, company_id=comp, account_id=accumulated,
        debit=0.0, credit=100.0, balance=-100.0,
    )
    target = Record(
        702, company_id=comp, state="posted", name="DEP/2026/0001",
        asset_id=asset,
        asset_move_type="depreciation", journal_id=journal, currency_id=currency,
        date=date(2026, 7, 10), asset_depreciation_beginning_date=date(2026, 7, 1),
        depreciation_value=100.0, line_ids=SimpleNamespace(ids=[703, 704]),
    )
    other_debit = Record(706, company_id=comp)
    other_credit = Record(707, company_id=comp)
    other = Record(
        705, company_id=comp, state="draft", asset_id=asset,
        asset_move_type="depreciation", journal_id=journal, currency_id=currency,
        date=date(2026, 8, 10), depreciation_value=100.0,
        line_ids=SimpleNamespace(ids=[706, 707]),
    )
    asset.snapshot_values = {
        "state": "open", "depreciation_move_ids": [702, 705],
        "value_residual": "100", "book_value": "100",
    }
    target.snapshot_values = {
        "state": "posted", "name": "DEP/2026/0001",
        "date": "2026-07-10", "journal_id": 2,
        "depreciation_value": "100", "line_ids": [703, 704],
    }
    target_debit.snapshot_values = {
        "account_id": 22, "debit": "100", "credit": "0",
        "balance": "100",
    }
    target_credit.snapshot_values = {
        "account_id": 21, "debit": "0", "credit": "100",
        "balance": "-100",
    }
    other.snapshot_values = {
        "state": "draft", "name": "/", "date": "2026-08-10",
        "journal_id": 2, "depreciation_value": "100",
        "line_ids": [706, 707],
    }
    other_debit.snapshot_values = {
        "account_id": 22, "debit": "100", "credit": "0",
        "balance": "100",
    }
    other_credit.snapshot_values = {
        "account_id": 21, "debit": "0", "credit": "100",
        "balance": "-100",
    }
    handler = Harness(records={
        ("res.currency", 1): currency,
        ("account.move.line", 703): target_debit,
        ("account.move.line", 704): target_credit,
        ("account.move.line", 706): other_debit,
        ("account.move.line", 707): other_credit,
    })
    handler.test_company = comp
    parameters = {
        "asset_id": 701, "depreciation_move_id": 702,
        "period_start": "2026-07-01", "period_end": "2026-07-10",
        "posting_date": "2026-07-10", "journal_id": 2,
        "currency_id": 1, "amount": "100",
    }
    records = [
        ("account.asset", asset), ("account.move", target),
        ("account.move.line", target_debit),
        ("account.move.line", target_credit), ("account.move", other),
        ("account.move.line", other_debit),
        ("account.move.line", other_credit),
    ]
    before = {
        ("account.asset", 701): {
            "state": "open", "depreciation_move_ids": [702, 705],
            "value_residual": "200", "book_value": "200",
        },
        ("account.move", 702): {
            "state": "draft", "name": "/", "date": "2026-07-10",
            "journal_id": 2, "depreciation_value": "100",
            "line_ids": [703, 704],
        },
        ("account.move.line", 703): dict(target_debit.snapshot_values),
        ("account.move.line", 704): dict(target_credit.snapshot_values),
        ("account.move", 705): {
            **other.snapshot_values,
        },
        ("account.move.line", 706): dict(other_debit.snapshot_values),
        ("account.move.line", 707): dict(other_credit.snapshot_values),
    }
    assert "asset_residual_matches" in handler.verify_depreciation(
        parameters, comp, records, before
    )
    other.state = "posted"
    with pytest.raises(OdooWriteHandlerError, match="another depreciation"):
        handler.verify_depreciation(parameters, comp, records, before)
    other.state = "draft"
    other_debit.snapshot_values["account_id"] = 999
    with pytest.raises(OdooWriteHandlerError, match="schedule graph changed"):
        handler.verify_depreciation(parameters, comp, records, before)


def test_adjustment_creates_balanced_public_account_move():
    move = Record(801, state="draft", company_id=Record(7))
    model = Model(factory=lambda values: move)
    handler = Harness(models={"account.move": model})
    p = {
        "company_id": 7, "journal_id": 2, "posting_date": "2026-07-10",
        "reference": "ADJ-1", "reason": "Month-end cutoff",
        "period_end_date": "2026-07-31", "posting_mode": "post",
        "lines": [
            {"line_reference": "adj-d", "name": "d", "account_id": 10, "partner_id": None, "side": "debit", "amount": "100", "currency_id": 1, "amount_currency": "100", "tax_ids": []},
            {"line_reference": "adj-c", "name": "c", "account_id": 11, "partner_id": None, "side": "credit", "amount": "100", "currency_id": 1, "amount_currency": "-100", "tax_ids": []},
        ],
        "reversal_date": "2026-08-01",
    }
    _, recovery = handler.execute_adjustment(p, handler.test_company, {})
    values = model.creates[0]
    assert values["move_type"] == "entry"
    assert values["line_ids"][0][2]["debit"] == 100.0
    assert values["line_ids"][1][2]["credit"] == 100.0
    assert values["line_ids"][0][2]["odoo_cli_v3_line_reference"] == "adj-d"
    assert values["odoo_cli_v3_reason"] == "Month-end cutoff"
    assert values["odoo_cli_v3_period_end_date"] == "2026-07-31"
    assert values["odoo_cli_v3_document_binding"] == handler.document_binding(
        "period_adjustment", p
    )
    assert move.action_post_calls == 1
    assert recovery["status"] == "manual_escalation"
    assert recovery["method"] == "manual_review_period_adjustment"


def test_journal_entry_precheck_binds_every_approved_dependency_separately():
    comp = company()
    currency = Record(1, company_id=None, active=True, rounding="0.01")
    journal = Record(
        2, company_id=comp, type="general", active=True, currency_id=currency
    )
    debit_account = Record(3, company_id=comp, deprecated=False)
    credit_account = Record(4, company_id=comp, deprecated=False)
    partner = Record(5, company_id=None, active=True)
    handler = Harness(
        models={"account.move": Model()},
        records={
            ("res.currency", 1): currency,
            ("account.journal", 2): journal,
            ("account.account", 3): debit_account,
            ("account.account", 4): credit_account,
            ("res.partner", 5): partner,
        },
    )
    handler.test_company = comp
    checked = handler.precheck_adjustment(
        {
            "company_id": 7,
            "journal_id": 2,
            "currency_id": 1,
            "posting_date": "2026-07-10",
            "lines": [
                {"account_id": 3, "partner_id": 5, "tax_ids": []},
                {"account_id": 4, "partner_id": None, "tax_ids": []},
            ],
        },
        comp,
    )
    assert checked["before"] == []
    assert {
        (item["model"], item["record_id"])
        for item in checked["dependencies"]
    } == {
        ("res.company", 7),
        ("res.currency", 1),
        ("account.journal", 2),
        ("account.account", 3),
        ("account.account", 4),
        ("res.partner", 5),
    }


@pytest.mark.parametrize("precheck_name", ("precheck_accrual", "precheck_adjustment"))
def test_period_entry_precheck_rejects_tax_graphs_until_exact_tax_verification_exists(
    precheck_name,
):
    handler = Harness()
    parameters = {
        "posting_mode": "post",
        "reversal_date": "2026-08-01",
        "lines": [{"tax_ids": [6]}],
    }

    with pytest.raises(OdooWriteHandlerError, match="tax"):
        getattr(handler, precheck_name)(parameters, handler.test_company)


def test_adjustment_verification_requires_exact_graph_and_document_binding():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding="0.01")
    journal = Record(2, company_id=comp, type="general", active=True)
    debit_account = Record(10, company_id=comp)
    credit_account = Record(11, company_id=comp)
    move = Record(
        809, state="posted", company_id=comp, move_type="entry",
        journal_id=journal, currency_id=currency, date=date(2026, 7, 31),
        ref="ADJ-1", odoo_cli_v3_period_end_date=date(2026, 7, 31),
        odoo_cli_v3_reason="cutoff", line_ids=SimpleNamespace(ids=[807, 808]),
    )
    debit = Record(
        807, company_id=comp, move_id=move, name="debit",
        odoo_cli_v3_line_reference="adj-d", account_id=debit_account,
        partner_id=None, currency_id=currency, debit=100, credit=0, balance=100,
        amount_currency=100, tax_ids=[], tax_line_id=None, display_type="product",
    )
    credit = Record(
        808, company_id=comp, move_id=move, name="credit",
        odoo_cli_v3_line_reference="adj-c", account_id=credit_account,
        partner_id=None, currency_id=currency, debit=0, credit=100, balance=-100,
        amount_currency=-100, tax_ids=[], tax_line_id=None, display_type="product",
    )
    handler = Harness(records={
        ("res.currency", 1): currency,
        ("account.move.line", 807): debit,
        ("account.move.line", 808): credit,
    })
    handler.test_company = comp
    parameters = {
        "journal_id": 2, "currency_id": 1, "posting_date": "2026-07-31",
        "period_end_date": "2026-07-31", "reference": "ADJ-1",
        "reason": "cutoff", "posting_mode": "post",
        "lines": [
            {"line_reference": "adj-d", "name": "debit", "account_id": 10,
             "partner_id": None, "side": "debit", "amount": "100",
             "currency_id": 1, "amount_currency": "100", "tax_ids": []},
            {"line_reference": "adj-c", "name": "credit", "account_id": 11,
             "partner_id": None, "side": "credit", "amount": "100",
             "currency_id": 1, "amount_currency": "-100", "tax_ids": []},
        ],
    }
    move.odoo_cli_v3_document_binding = handler.document_binding(
        "period_adjustment", parameters
    )
    graph = [
        ("account.move", move),
        ("account.move.line", debit),
        ("account.move.line", credit),
    ]

    assert "document_binding_matches" in handler.verify_adjustment(
        parameters, comp, graph
    )
    with pytest.raises(OdooWriteHandlerError, match="record graph"):
        handler.verify_adjustment(
            parameters, comp, [*graph, ("account.move.line", Record(999))]
        )
    move.odoo_cli_v3_document_binding = "f" * 64
    with pytest.raises(OdooWriteHandlerError, match="document binding"):
        handler.verify_adjustment(parameters, comp, graph)


def test_posted_accrual_creates_public_scheduled_reversal_receipt():
    move = Record(811, state="draft", company_id=Record(7))
    scheduled = Record(812, state="draft", company_id=Record(7))

    class Wizard(Record):
        def reverse_moves(self, is_modify=False):
            self.argument = is_modify
            return {"res_id": 812}

    move_model = Model(factory=lambda values: move)
    reversal_model = Model(factory=lambda values: Wizard(1))
    handler = Harness(
        models={"account.move": move_model, "account.move.reversal": reversal_model},
        records={("account.move", 812): scheduled},
    )
    p = {
        "company_id": 7, "journal_id": 2, "posting_date": "2026-07-10",
        "reference": "ACCR-1", "posting_mode": "post",
        "lines": [
            {"line_reference": "accr-d", "name": "d", "account_id": 10, "partner_id": None, "side": "debit", "amount": "100", "currency_id": 1, "amount_currency": "100", "tax_ids": []},
            {"line_reference": "accr-c", "name": "c", "account_id": 11, "partner_id": None, "side": "credit", "amount": "100", "currency_id": 1, "amount_currency": "-100", "tax_ids": []},
        ],
        "reversal_date": "2026-08-01",
    }
    records, recovery = handler.execute_accrual(p, handler.test_company, {})
    assert [(model, record.id) for model, record in records] == [
        ("account.move", 811), ("account.move", 812)
    ]
    assert reversal_model.contexts[0][1]["active_ids"] == [811]
    assert reversal_model.creates[0]["date"] == "2026-08-01"
    assert move_model.creates[0]["line_ids"][0][2][
        "odoo_cli_v3_line_reference"
    ] == "accr-d"
    assert move_model.creates[0][
        "odoo_cli_v3_document_binding"
    ] == handler.document_binding("accrual", p)
    assert move_model.creates[0][
        "odoo_cli_v3_business_binding"
    ] == handler.business_binding("accrual", p)
    assert scheduled.writes == [
        {
            "odoo_cli_v3_document_binding": handler.document_binding(
                "accrual_scheduled_reversal", p
            ),
            "odoo_cli_v3_business_binding": handler.business_binding(
                "accrual_scheduled_reversal", p
            ),
        }
    ]
    assert recovery["status"] == "manual_escalation"
    assert recovery["method"] == "manual_review_accrual_schedule"


def test_accrual_precheck_rejects_draft_or_nonfuture_reversal_before_orm_writes():
    handler = Harness()
    base = {
        "posting_mode": "draft", "reversal_date": "2026-08-01",
    }
    with pytest.raises(OdooWriteHandlerError, match="draft accrual"):
        handler.precheck_accrual(base, handler.test_company)
    with pytest.raises(OdooWriteHandlerError, match="future-dated"):
        handler.precheck_accrual(
            {"posting_mode": "post", "reversal_date": "2026-07-15"},
            handler.test_company,
        )


def test_accrual_precheck_rejects_existing_company_reference_business_binding():
    class DuplicateAccrualHarness(Harness):
        def precheck_journal_entry(self, p, company, *, adjustment):
            return {"checks": ["journal_entry"], "before": [], "dependencies": []}

        def create_model(self, *args, **kwargs):
            return object()

        def search_records(self, model_name, domain, company, *, limit=1):
            self.last_search = (model_name, domain, limit)
            if any(
                field == "odoo_cli_v3_business_binding"
                and value == self.business_binding("accrual", parameters)
                for field, operator, value in domain
                if operator == "="
            ):
                return [Record(900, company_id=company)]
            return []

    parameters = {
        "company_id": 7,
        "posting_mode": "post",
        "reversal_date": "2026-08-01",
        "reference": "ACCR-UNIQUE-1",
    }
    handler = DuplicateAccrualHarness()

    with pytest.raises(OdooWriteHandlerError, match="accrual business key"):
        handler.precheck_accrual(parameters, handler.test_company)


def test_accrual_verification_rejects_changed_reversal_date_and_auto_post_mode():
    class VerifyHarness(Harness):
        def verify_journal_entry(self, p, company, records):
            return ["origin_verified"]

        def assert_linewise_reversal(self, origin, reversal, company):
            pass

        def assert_move_balanced(self, move, company):
            pass

        def assert_exact_move_graph(self, records, moves, company):
            pass

    journal = Record(2, type="general", active=True)
    currency = Record(1)
    origin = Record(
        821, state="posted", company_id=Record(7),
        reversal_move_ids=SimpleNamespace(ids=[822]),
    )
    scheduled = Record(
        822, state="draft", company_id=Record(7), reversed_entry_id=origin,
        date=date(2026, 8, 2), auto_post="at_date", move_type="entry",
        journal_id=journal, currency_id=currency,
    )
    handler = VerifyHarness()
    p = {
        "posting_mode": "post", "reversal_date": "2026-08-01",
        "journal_id": 2, "currency_id": 1, "reference": "ACCR-1",
    }
    origin.odoo_cli_v3_document_binding = handler.document_binding("accrual", p)
    origin.odoo_cli_v3_business_binding = handler.business_binding("accrual", p)
    scheduled.odoo_cli_v3_document_binding = handler.document_binding(
        "accrual_scheduled_reversal", p
    )
    scheduled.odoo_cli_v3_business_binding = handler.business_binding(
        "accrual_scheduled_reversal", p
    )
    records = [("account.move", origin), ("account.move", scheduled)]
    with pytest.raises(OdooWriteHandlerError, match="reversal date differs"):
        handler.verify_accrual(p, handler.test_company, records)
    scheduled.date = date(2026, 8, 1)
    scheduled.auto_post = "no"
    with pytest.raises(OdooWriteHandlerError, match="not scheduled for auto-post"):
        handler.verify_accrual(p, handler.test_company, records)
    scheduled.auto_post = "at_date"
    assert "scheduled_reversal_date_matches" in handler.verify_accrual(
        p, handler.test_company, records
    )
    origin.odoo_cli_v3_business_binding = "f" * 64
    with pytest.raises(OdooWriteHandlerError, match="business binding"):
        handler.verify_accrual(p, handler.test_company, records)


def test_accrual_verification_requires_exact_linewise_reversal_and_record_graph():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding="0.01")
    journal = Record(2, company_id=comp, type="general", active=True)
    account_debit = Record(10, company_id=comp)
    account_credit = Record(11, company_id=comp)
    origin = Record(
        831, state="posted", company_id=comp, move_type="entry",
        journal_id=journal, currency_id=currency, date=date(2026, 7, 10),
        ref="ACCR-1", line_ids=SimpleNamespace(ids=[833, 834]),
        reversal_move_ids=SimpleNamespace(ids=[832]),
    )
    scheduled = Record(
        832, state="draft", company_id=comp, move_type="entry",
        journal_id=journal, currency_id=currency, date=date(2026, 8, 1),
        ref="Reversal of: ACCR-1", reversed_entry_id=origin,
        auto_post="at_date", line_ids=SimpleNamespace(ids=[835, 836]),
    )
    origin_debit = Record(
        833, company_id=comp, move_id=origin, name="expense",
        odoo_cli_v3_line_reference="accr-d", account_id=account_debit,
        partner_id=None, currency_id=currency, debit=100, credit=0,
        balance=100, amount_currency=100, tax_ids=[], tax_line_id=None,
        display_type="product",
    )
    origin_credit = Record(
        834, company_id=comp, move_id=origin, name="liability",
        odoo_cli_v3_line_reference="accr-c", account_id=account_credit,
        partner_id=None, currency_id=currency, debit=0, credit=100,
        balance=-100, amount_currency=-100, tax_ids=[], tax_line_id=None,
        display_type="product",
    )
    reverse_credit = Record(
        835, company_id=comp, move_id=scheduled, name="expense",
        odoo_cli_v3_line_reference="", account_id=account_debit,
        partner_id=None, currency_id=currency, debit=0, credit=100,
        balance=-100, amount_currency=-100, tax_ids=[], tax_line_id=None,
        display_type="product",
    )
    reverse_debit = Record(
        836, company_id=comp, move_id=scheduled, name="liability",
        odoo_cli_v3_line_reference="", account_id=account_credit,
        partner_id=None, currency_id=currency, debit=100, credit=0,
        balance=100, amount_currency=100, tax_ids=[], tax_line_id=None,
        display_type="product",
    )
    records_by_key = {
        ("res.currency", 1): currency,
        ("account.move.line", 833): origin_debit,
        ("account.move.line", 834): origin_credit,
        ("account.move.line", 835): reverse_credit,
        ("account.move.line", 836): reverse_debit,
    }
    handler = Harness(records=records_by_key)
    handler.test_company = comp
    parameters = {
        "journal_id": 2, "currency_id": 1, "posting_date": "2026-07-10",
        "reference": "ACCR-1", "posting_mode": "post",
        "reversal_date": "2026-08-01",
        "lines": [
            {"line_reference": "accr-d", "name": "expense", "account_id": 10,
             "partner_id": None, "side": "debit", "amount": "100",
             "currency_id": 1, "amount_currency": "100", "tax_ids": []},
            {"line_reference": "accr-c", "name": "liability", "account_id": 11,
             "partner_id": None, "side": "credit", "amount": "100",
             "currency_id": 1, "amount_currency": "-100", "tax_ids": []},
        ],
    }
    origin.odoo_cli_v3_document_binding = handler.document_binding(
        "accrual", parameters
    )
    origin.odoo_cli_v3_business_binding = handler.business_binding(
        "accrual", parameters
    )
    scheduled.odoo_cli_v3_document_binding = handler.document_binding(
        "accrual_scheduled_reversal", parameters
    )
    scheduled.odoo_cli_v3_business_binding = handler.business_binding(
        "accrual_scheduled_reversal", parameters
    )
    graph = [
        ("account.move", origin),
        ("account.move.line", origin_debit),
        ("account.move.line", origin_credit),
        ("account.move", scheduled),
        ("account.move.line", reverse_credit),
        ("account.move.line", reverse_debit),
    ]

    assert "scheduled_reversal_lines_exact" in handler.verify_accrual(
        parameters, comp, graph
    )
    reverse_credit.amount_currency = -99
    with pytest.raises(OdooWriteHandlerError, match="linewise reversal"):
        handler.verify_accrual(parameters, comp, graph)
    reverse_credit.amount_currency = -100
    with pytest.raises(OdooWriteHandlerError, match="record graph"):
        handler.verify_accrual(
            parameters, comp, [*graph, ("account.move.line", Record(999))]
        )


def test_deferred_writes_only_dates_then_posts_source_and_returns_generated_moves():
    source_other = Record(904, company_id=Record(7))
    generated_line_1 = Record(905, company_id=Record(7))
    generated_line_2 = Record(906, company_id=Record(7))
    generated = Record(
        903, state="draft", company_id=Record(7),
        line_ids=SimpleNamespace(ids=[905, 906]),
    )
    parent = Record(
        902, state="draft", company_id=Record(7), deferred_move_ids=[generated],
        line_ids=SimpleNamespace(ids=[901, 904]),
    )
    source = Record(901, company_id=Record(7), move_id=parent)
    handler = Harness(records={
        ("account.move.line", 901): source,
        ("account.move.line", 904): source_other,
        ("account.move.line", 905): generated_line_1,
        ("account.move.line", 906): generated_line_2,
    })
    p = {"source_move_line_id": 901, "schedule_start_date": "2026-07-01", "schedule_end_date": "2027-06-30"}
    records, recovery = handler.execute_deferred(p, handler.test_company, {})
    assert source.writes == [{"deferred_start_date": "2026-07-01", "deferred_end_date": "2027-06-30"}]
    assert parent.action_post_calls == 1
    assert [(model, record.id) for model, record in records] == [
        ("account.move", 902), ("account.move.line", 901),
        ("account.move.line", 904), ("account.move", 903),
        ("account.move.line", 905), ("account.move.line", 906),
    ]
    assert recovery["status"] == "available"
    assert recovery["method"] == "reverse_deferred_source_and_schedule_v1"


def test_deferred_precheck_binds_full_invoice_config_and_account_types():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding=0.01)
    source_journal = Record(10, company_id=comp, type="purchase", active=True)
    deferred_journal = Record(40, company_id=comp, type="general", active=True)
    expense = Record(20, company_id=comp, account_type="expense", deprecated=False)
    deferred = Record(
        30, company_id=comp, account_type="asset_current", deprecated=False
    )
    comp.generate_deferred_expense_entries_method = "on_validation"
    comp.deferred_expense_amount_computation_method = "month"
    comp.deferred_expense_account_id = deferred
    comp.deferred_expense_journal_id = deferred_journal
    move = Record(
        902, company_id=comp, state="draft", move_type="in_invoice",
        currency_id=currency, date=date(2026, 7, 1), journal_id=source_journal,
        line_ids=SimpleNamespace(ids=[901, 904]),
        invoice_line_ids=SimpleNamespace(ids=[901]), deferred_move_ids=[],
    )
    source = Record(
        901, company_id=comp, move_id=move, account_id=expense,
        balance=1200.0, amount_currency=1200.0,
        deferred_start_date=None, deferred_end_date=None,
    )
    payable = Record(
        904, company_id=comp, move_id=move,
        deferred_start_date=None, deferred_end_date=None,
    )
    handler = Harness(records={
        ("account.move.line", 901): source,
        ("account.move.line", 904): payable,
        ("account.move", 902): move,
        ("account.account", 20): expense,
        ("account.account", 30): deferred,
            ("account.journal", 40): deferred_journal,
            ("account.journal", 10): source_journal,
        ("res.currency", 1): currency,
    })
    handler.test_company = comp
    parameters = {
        "source_move_line_id": 901, "deferred_type": "expense",
        "schedule_start_date": "2026-07-01",
        "schedule_end_date": "2026-08-31",
        "expected_generation_method": "on_validation",
        "amount_computation_method": "month",
        "expected_deferred_account_id": 30,
        "expected_deferred_journal_id": 40,
        "currency_id": 1, "total_amount": "1200",
    }
    checked = handler.precheck_deferred(parameters, comp)
    assert {(item["model"], item["record_id"]) for item in checked["before"]} == {
        ("account.move", 902), ("account.move.line", 901),
        ("account.move.line", 904),
    }
    assert {(item["model"], item["record_id"]) for item in checked["dependencies"]} == {
        ("res.company", 7), ("res.currency", 1),
        ("account.account", 20), ("account.account", 30),
        ("account.journal", 10), ("account.journal", 40),
    }
    deferred.account_type = "asset_fixed"
    with pytest.raises(OdooWriteHandlerError, match="account type"):
        handler.precheck_deferred(parameters, comp)
    deferred.account_type = "asset_current"
    payable.deferred_start_date = date(2026, 7, 1)
    with pytest.raises(OdooWriteHandlerError, match="another source line"):
        handler.precheck_deferred(parameters, comp)


def test_deferred_verifier_proves_transfer_release_schedule_and_exact_graph():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding=0.01)
    expense = Record(20, company_id=comp, account_type="expense")
    deferred = Record(
        30, company_id=comp, account_type="asset_current", deprecated=False
    )
    journal = Record(40, company_id=comp, type="general", active=True)
    comp.generate_deferred_expense_entries_method = "on_validation"
    comp.deferred_expense_amount_computation_method = "month"
    comp.deferred_expense_account_id = deferred
    comp.deferred_expense_journal_id = journal
    source_move = Record(
        902, company_id=comp, state="posted", name="BILL/2026/0001",
        move_type="in_invoice",
        currency_id=currency, date=date(2026, 7, 1),
        line_ids=SimpleNamespace(ids=[901, 904]),
        deferred_move_ids=SimpleNamespace(ids=[903, 907]),
    )
    source = Record(
        901, company_id=comp, move_id=source_move, account_id=expense,
        balance=1200.0, amount_currency=1200.0,
        deferred_start_date=date(2026, 7, 1),
        deferred_end_date=date(2026, 7, 31),
    )
    payable = Record(
        904, company_id=comp, move_id=source_move,
        deferred_start_date=None, deferred_end_date=None,
    )
    initial = Record(
        903, company_id=comp, state="posted", journal_id=journal,
        date=date(2026, 7, 1), auto_post="at_date",
        deferred_original_move_ids=SimpleNamespace(ids=[902]),
        line_ids=SimpleNamespace(ids=[905, 906]),
    )
    initial_source = Record(
        905, company_id=comp, move_id=initial, account_id=expense,
        debit=0.0, credit=1200.0, balance=-1200.0,
    )
    initial_deferred = Record(
        906, company_id=comp, move_id=initial, account_id=deferred,
        debit=1200.0, credit=0.0, balance=1200.0,
    )
    recognition = Record(
        907, company_id=comp, state="draft", journal_id=journal,
        date=date(2026, 7, 31), auto_post="at_date",
        deferred_original_move_ids=SimpleNamespace(ids=[902]),
        line_ids=SimpleNamespace(ids=[908, 909]),
    )
    recognition_source = Record(
        908, company_id=comp, move_id=recognition, account_id=expense,
        debit=1200.0, credit=0.0, balance=1200.0,
    )
    recognition_deferred = Record(
        909, company_id=comp, move_id=recognition, account_id=deferred,
        debit=0.0, credit=1200.0, balance=-1200.0,
    )
    source_move.snapshot_values = {
        "name": "BILL/2026/0001", "state": "posted",
        "move_type": "in_invoice", "currency_id": 1,
        "line_ids": [901, 904], "invoice_line_ids": [901],
        "payment_state": "not_paid", "amount_residual": "1200",
        "deferred_move_ids": [903, 907],
    }
    source.snapshot_values = {
        "move_id": 902, "account_id": 20, "partner_id": None,
        "product_id": 80, "quantity": "1", "price_unit": "1200",
        "debit": "1200", "credit": "0", "balance": "1200",
        "amount_currency": "1200", "currency_id": 1, "tax_ids": [],
        "deferred_start_date": "2026-07-01",
        "deferred_end_date": "2026-07-31",
    }
    payable.snapshot_values = {
        "move_id": 902, "account_id": 200, "partner_id": 70,
        "product_id": None, "debit": "0", "credit": "1200",
        "balance": "-1200", "amount_currency": "-1200",
        "currency_id": 1, "tax_ids": [], "amount_residual": "-1200",
        "amount_residual_currency": "-1200", "reconciled": False,
        "deferred_start_date": None, "deferred_end_date": None,
    }
    records = [
        ("account.move", source_move), ("account.move.line", source),
        ("account.move.line", payable), ("account.move", initial),
        ("account.move.line", initial_source),
        ("account.move.line", initial_deferred), ("account.move", recognition),
        ("account.move.line", recognition_source),
        ("account.move.line", recognition_deferred),
    ]
    handler = Harness(records={
        ("res.currency", 1): currency,
        ("account.account", 30): deferred,
        ("account.journal", 40): journal,
        ("account.move.line", 905): initial_source,
        ("account.move.line", 906): initial_deferred,
        ("account.move.line", 908): recognition_source,
        ("account.move.line", 909): recognition_deferred,
    })
    handler.test_company = comp
    parameters = {
        "source_move_line_id": 901, "deferred_type": "expense",
        "schedule_start_date": "2026-07-01",
        "schedule_end_date": "2026-07-31",
        "expected_generation_method": "on_validation",
        "amount_computation_method": "month",
        "expected_deferred_account_id": 30,
        "expected_deferred_journal_id": 40,
        "currency_id": 1, "total_amount": "1200",
    }
    before = {
        ("account.move", 902): {
            **source_move.snapshot_values,
            "name": "/", "state": "draft", "payment_state": "not_paid",
            "deferred_move_ids": [],
        },
        ("account.move.line", 901): {
            **source.snapshot_values,
            "deferred_start_date": None, "deferred_end_date": None,
        },
        ("account.move.line", 904): dict(payable.snapshot_values),
    }
    assert "recognition_total_matches" in handler.verify_deferred(
        parameters, comp, records, before
    )
    payable.snapshot_values["account_id"] = 999
    with pytest.raises(OdooWriteHandlerError, match="source graph changed"):
        handler.verify_deferred(parameters, comp, records, before)
    payable.snapshot_values["account_id"] = 200
    recognition_source.balance = 1199.0
    recognition_source.debit = 1199.0
    recognition_deferred.balance = -1199.0
    recognition_deferred.credit = 1199.0
    with pytest.raises(OdooWriteHandlerError, match="recognition total"):
        handler.verify_deferred(parameters, comp, records, before)


def test_reversal_uses_public_reverse_moves_and_readable_action_receipt():
    origin_line = Record(1003, company_id=Record(7))
    reversal_line = Record(1004, company_id=Record(7))
    origin = Record(
        1001, state="posted", company_id=Record(7),
        line_ids=SimpleNamespace(ids=[1003]),
    )
    reversal = Record(
        1002, state="draft", company_id=Record(7),
        line_ids=SimpleNamespace(ids=[1004]),
    )

    class Wizard(Record):
        def reverse_moves(self, is_modify=False):
            self.argument = is_modify
            return {"res_id": 1002}

    wizard = Wizard(1)
    handler = Harness(
        models={"account.move.reversal": Model(factory=lambda values: wizard)},
        records={
            ("account.move", 1001): origin,
            ("account.move", 1002): reversal,
            ("account.move.line", 1003): origin_line,
            ("account.move.line", 1004): reversal_line,
        },
    )
    p = {"move_id": 1001, "reversal_date": "2026-07-10", "journal_id": 2, "reason": "correct", "posting_mode": "post"}
    records, recovery = handler.execute_reversal(p, handler.test_company, {})
    assert records == [
        ("account.move", origin), ("account.move.line", origin_line),
        ("account.move", reversal), ("account.move.line", reversal_line),
    ]
    assert wizard.argument is False
    assert reversal.action_post_calls == 1
    assert reversal.writes == [
        {
            "odoo_cli_v3_reason": "correct",
            "odoo_cli_v3_document_binding": handler.document_binding(
                "move_reversal", p
            ),
        }
    ]
    assert recovery["status"] == "available"
    assert recovery["method"] == "reverse_the_reversal_v1"


def test_reversal_precheck_requires_safe_general_entry_and_binds_full_origin_graph():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding="0.01")
    journal = Record(
        2, company_id=comp, type="general", active=True, currency_id=currency
    )
    line_debit = Record(
        1003, company_id=comp, reconciled=False, full_reconcile_id=None,
        matched_debit_ids=[], matched_credit_ids=[], asset_ids=[],
    )
    line_credit = Record(
        1004, company_id=comp, reconciled=False, full_reconcile_id=None,
        matched_debit_ids=[], matched_credit_ids=[], asset_ids=[],
    )
    move = Record(
        1001, company_id=comp, state="posted", move_type="entry",
        journal_id=journal, currency_id=currency, amount_total=100,
        line_ids=SimpleNamespace(ids=[1003, 1004]),
        statement_line_id=None, statement_id=None, asset_id=None,
        deferred_move_ids=[], deferred_original_move_ids=[],
        tax_cash_basis_rec_id=None, tax_cash_basis_origin_move_id=None,
    )
    handler = Harness(
        models={"account.move.reversal": Model()},
        records={
            ("account.move", 1001): move,
            ("account.move.line", 1003): line_debit,
            ("account.move.line", 1004): line_credit,
            ("account.journal", 2): journal,
            ("res.currency", 1): currency,
        },
    )
    handler.test_company = comp
    parameters = {
        "move_id": 1001, "reversal_date": "2026-07-10", "journal_id": 2,
        "currency_id": 1, "expected_total_amount": "100", "reason": "fix",
        "posting_mode": "post",
    }

    checked = handler.precheck_reversal(parameters, comp)
    assert {(item["model"], item["record_id"]) for item in checked["before"]} == {
        ("account.move", 1001),
        ("account.move.line", 1003),
        ("account.move.line", 1004),
    }

    move.move_type = "out_invoice"
    with pytest.raises(OdooWriteHandlerError, match="general journal entry"):
        handler.precheck_reversal(parameters, comp)
    move.move_type = "entry"
    journal.active = False
    with pytest.raises(OdooWriteHandlerError, match="inactive"):
        handler.precheck_reversal(parameters, comp)
    journal.active = True
    journal.type = "sale"
    with pytest.raises(OdooWriteHandlerError, match="journal type"):
        handler.precheck_reversal(parameters, comp)


@pytest.mark.parametrize(
    ("target", "field", "value"),
    (
        ("move", "statement_line_id", Record(91)),
        ("move", "statement_id", Record(98)),
        ("move", "asset_id", Record(92)),
        ("move", "deferred_move_ids", [Record(93)]),
        ("move", "deferred_original_move_ids", [Record(99)]),
        ("move", "tax_cash_basis_rec_id", Record(94)),
        ("move", "tax_cash_basis_origin_move_id", Record(100)),
        ("move", "reversed_entry_id", Record(102)),
        ("move", "reversal_move_ids", [Record(103)]),
        ("line", "matched_debit_ids", [Record(95)]),
        ("line", "matched_credit_ids", [Record(101)]),
        ("line", "full_reconcile_id", Record(96)),
        ("line", "reconciled", True),
        ("line", "asset_ids", [Record(97)]),
    ),
)
def test_reversal_precheck_rejects_existing_accounting_dependencies(
    target, field, value
):
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding="0.01")
    journal = Record(
        2, company_id=comp, type="general", active=True, currency_id=currency
    )
    line = Record(
        1003, company_id=comp, reconciled=False, full_reconcile_id=None,
        matched_debit_ids=[], matched_credit_ids=[], asset_ids=[],
    )
    move = Record(
        1001, company_id=comp, state="posted", move_type="entry",
        journal_id=journal, currency_id=currency, amount_total=100,
        line_ids=SimpleNamespace(ids=[1003]),
        statement_line_id=None, statement_id=None, asset_id=None,
        deferred_move_ids=[], deferred_original_move_ids=[],
        tax_cash_basis_rec_id=None, tax_cash_basis_origin_move_id=None,
    )
    setattr(move if target == "move" else line, field, value)
    handler = Harness(
        models={"account.move.reversal": Model()},
        records={
            ("account.move", 1001): move,
            ("account.move.line", 1003): line,
            ("account.journal", 2): journal,
            ("res.currency", 1): currency,
        },
    )
    handler.test_company = comp
    parameters = {
        "move_id": 1001, "reversal_date": "2026-07-10", "journal_id": 2,
        "currency_id": 1, "expected_total_amount": "100", "reason": "fix",
        "posting_mode": "post",
    }

    with pytest.raises(OdooWriteHandlerError, match="dependencies"):
        handler.precheck_reversal(parameters, comp)


@pytest.mark.parametrize(
    "dependent_model", ("account.partial.reconcile", "account.move")
)
def test_reversal_precheck_rejects_exchange_and_caba_reverse_dependencies(
    dependent_model,
):
    class DependencyHarness(Harness):
        def search_records(self, model_name, domain, company, *, limit=1):
            return [Record(2000)] if model_name == dependent_model else []

    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding="0.01")
    journal = Record(
        2, company_id=comp, type="general", active=True, currency_id=currency
    )
    line = Record(
        1003, company_id=comp, reconciled=False, full_reconcile_id=None,
        matched_debit_ids=[], matched_credit_ids=[], asset_ids=[],
    )
    move = Record(
        1001, company_id=comp, state="posted", move_type="entry",
        journal_id=journal, currency_id=currency, amount_total=100,
        line_ids=SimpleNamespace(ids=[1003]),
        statement_line_id=None, statement_id=None, asset_id=None,
        deferred_move_ids=[], deferred_original_move_ids=[],
        tax_cash_basis_rec_id=None, tax_cash_basis_origin_move_id=None,
    )
    handler = DependencyHarness(
        models={"account.move.reversal": Model()},
        records={
            ("account.move", 1001): move,
            ("account.move.line", 1003): line,
            ("account.journal", 2): journal,
            ("res.currency", 1): currency,
        },
    )
    handler.test_company = comp
    parameters = {
        "move_id": 1001, "reversal_date": "2026-07-10", "journal_id": 2,
        "currency_id": 1, "expected_total_amount": "100", "reason": "fix",
        "posting_mode": "post",
    }

    with pytest.raises(OdooWriteHandlerError, match="exchange or CABA"):
        handler.precheck_reversal(parameters, comp)


def test_reversal_verification_requires_exact_linewise_graph_and_approved_origin():
    comp = company()
    currency = Record(1, company_id=comp, active=True, rounding="0.01")
    journal = Record(2, company_id=comp, type="general", active=True)
    account_debit = Record(10, company_id=comp)
    account_credit = Record(11, company_id=comp)
    origin = Record(
        1001, state="posted", company_id=comp, move_type="entry",
        journal_id=journal, currency_id=currency, date=date(2026, 7, 9),
        amount_total=100, line_ids=SimpleNamespace(ids=[1003, 1004]),
        reversal_move_ids=SimpleNamespace(ids=[1002]),
    )
    reversal = Record(
        1002, state="posted", company_id=comp, move_type="entry",
        journal_id=journal, currency_id=currency, date=date(2026, 7, 10),
        amount_total=-100, reversed_entry_id=origin,
        odoo_cli_v3_reason="fix", line_ids=SimpleNamespace(ids=[1005, 1006]),
    )
    origin_debit = Record(
        1003, company_id=comp, move_id=origin, name="debit", account_id=account_debit,
        partner_id=None, currency_id=currency, debit=100, credit=0, balance=100,
        amount_currency=100, tax_ids=[], tax_line_id=None, display_type="product",
    )
    origin_credit = Record(
        1004, company_id=comp, move_id=origin, name="credit", account_id=account_credit,
        partner_id=None, currency_id=currency, debit=0, credit=100, balance=-100,
        amount_currency=-100, tax_ids=[], tax_line_id=None, display_type="product",
    )
    reverse_credit = Record(
        1005, company_id=comp, move_id=reversal, name="debit", account_id=account_debit,
        partner_id=None, currency_id=currency, debit=0, credit=100, balance=-100,
        amount_currency=-100, tax_ids=[], tax_line_id=None, display_type="product",
    )
    reverse_debit = Record(
        1006, company_id=comp, move_id=reversal, name="credit", account_id=account_credit,
        partner_id=None, currency_id=currency, debit=100, credit=0, balance=100,
        amount_currency=100, tax_ids=[], tax_line_id=None, display_type="product",
    )
    handler = Harness(records={
        ("res.currency", 1): currency,
        ("account.move.line", 1003): origin_debit,
        ("account.move.line", 1004): origin_credit,
        ("account.move.line", 1005): reverse_credit,
        ("account.move.line", 1006): reverse_debit,
    })
    handler.test_company = comp
    parameters = {
        "move_id": 1001, "reversal_date": "2026-07-10", "journal_id": 2,
        "currency_id": 1, "expected_total_amount": "100", "reason": "fix",
        "posting_mode": "post",
    }
    reversal.odoo_cli_v3_document_binding = handler.document_binding(
        "move_reversal", parameters
    )
    graph = [
        ("account.move", origin),
        ("account.move.line", origin_debit),
        ("account.move.line", origin_credit),
        ("account.move", reversal),
        ("account.move.line", reverse_credit),
        ("account.move.line", reverse_debit),
    ]
    before = {
        ("account.move", 1001): {
            "state": "posted", "move_type": "entry", "journal_id": 2,
            "currency_id": 1, "line_ids": [1003, 1004], "amount_total": "100",
            "date": "2026-07-09", "ref": False, "partner_id": False,
            "odoo_cli_v3_document_binding": False,
        },
        ("account.move.line", 1003): {
            "move_id": 1001, "name": "debit", "account_id": 10,
            "partner_id": False, "currency_id": 1, "debit": "100",
            "credit": "0", "balance": "100", "amount_currency": "100",
            "tax_ids": [], "tax_line_id": False, "display_type": "product",
        },
        ("account.move.line", 1004): {
            "move_id": 1001, "name": "credit", "account_id": 11,
            "partner_id": False, "currency_id": 1, "debit": "0",
            "credit": "100", "balance": "-100", "amount_currency": "-100",
            "tax_ids": [], "tax_line_id": False, "display_type": "product",
        },
    }

    assert "linewise_reversal_exact" in handler.verify_reversal(
        parameters, comp, graph, before
    )
    reverse_credit.balance = -99
    with pytest.raises(OdooWriteHandlerError, match="linewise reversal"):
        handler.verify_reversal(parameters, comp, graph, before)
    reverse_credit.balance = -100
    with pytest.raises(OdooWriteHandlerError, match="record graph"):
        handler.verify_reversal(
            parameters, comp, [*graph, ("account.move.line", Record(999))], before
        )


def draft_move_recovery_fixture(*, vendor=False):
    currency = Record(1, active=True, rounding=0.01)
    journal = Record(
        2,
        company_id=Record(7),
        type="purchase" if vendor else "sale",
        active=True,
    )
    move = Record(
        1101,
        state="draft",
        name="/",
        move_type="in_invoice" if vendor else "out_invoice",
        company_id=Record(7),
        journal_id=journal,
        currency_id=currency,
        amount_total=100,
        amount_residual=100,
        payment_state="not_paid",
        invoice_date="2026-07-10",
        invoice_date_due="2026-08-10",
        invoice_line_ids=[],
        invoice_payment_term_id=None,
        ref=("BILL-DRAFT-RECOVERY-1" if vendor else "DRAFT-RECOVERY-1"),
        line_ids=[],
        auto_post="no",
        auto_post_until=None,
        posted_before=False,
        sequence_prefix=None,
        sequence_number=0,
        made_sequence_gap=False,
        secure_sequence_number=0,
        inalterable_hash=False,
        checked=False,
        origin_payment_id=None,
        payment_ids=[],
        matched_payment_ids=[],
        reconciled_payment_ids=[],
        statement_line_id=None,
        statement_line_ids=[],
        statement_id=None,
        tax_cash_basis_rec_id=None,
        tax_cash_basis_origin_move_id=None,
        tax_cash_basis_created_move_ids=[],
        reversed_entry_id=None,
        reversal_move_ids=[],
        adjusting_entry_origin_move_ids=[],
        adjusting_entries_move_ids=[],
        exchange_diff_partial_ids=[],
        closing_return_id=None,
        transfer_model_id=None,
        transaction_ids=[],
        authorized_transaction_ids=[],
        purchase_id=None,
        asset_id=None,
        asset_ids=[],
        deferred_move_ids=[],
        deferred_original_move_ids=[],
        edi_document_ids=[],
        expense_ids=[],
        pos_order_ids=[],
        stock_move_ids=[],
        landed_costs_ids=[],
        debit_note_ids=[],
        debit_origin_id=None,
        invoice_pdf_report_id=None,
        invoice_vendor_bill_id=None,
        purchase_vendor_bill_id=None,
        ubl_cii_xml_id=None,
        l10n_es_edi_facturae_xml_id=None,
        invoice_pdf_report_file=False,
        l10n_es_edi_facturae_xml_file=False,
        ubl_cii_xml_file=False,
        signature=False,
        signing_user=None,
        is_move_sent=False,
        sending_data=False,
        is_being_sent=False,
        invoice_source_email=False,
        attachment_ids=[],
        message_main_attachment_id=None,
        audit_trail_message_ids=[],
        activity_ids=[],
        message_follower_ids=[],
        message_ids=[],
        rating_ids=[],
        website_message_ids=[],
        access_token=False,
        fiscal_position_id=None,
        invoice_cash_rounding_id=None,
        invoice_incoterm_id=None,
        incoterm_location=False,
        partner_shipping_id=None,
        partner_bank_id=None,
        preferred_payment_method_line_id=None,
        l10n_latam_document_type_id=None,
        invoice_origin=False,
        narration=False,
        quick_edit_total_amount=0,
        always_tax_exigible=False,
        is_storno=False,
        asset_value_change=False,
        campaign_id=None,
        medium_id=None,
        source_id=None,
        team_id=None,
        delivery_date=None,
        fapiao=False,
        invoice_currency_rate=1,
        invoice_user_id=Record(42),
        l10n_es_edi_facturae_reason_code=False,
        l10n_es_invoicing_period_start_date=None,
        l10n_es_invoicing_period_end_date=None,
        l10n_es_is_simplified=False,
        l10n_es_payment_means=False,
        payment_reference=False,
        payment_state_before_switch=False,
        qr_code_method=False,
        taxable_supply_date=None,
        asset_depreciation_beginning_date=None,
        asset_number_days=0,
        depreciation_value=0,
        create_uid=Record(42),
        create_date="2026-07-10 09:00:00",
        write_uid=Record(42),
        write_date="2026-07-10 09:00:00",
        need_cancel_request=False,
        is_manually_modified=False,
        odoo_cli_v3_document_binding="a" * 64,
        odoo_cli_v3_business_binding="b" * 64,
    )
    line1 = Record(
        1102,
        state="unknown",
        company_id=Record(7),
        move_id=move,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        asset_ids=[],
        tax_ids=[],
        tax_line_id=None,
        tax_repartition_line_id=None,
        deferred_start_date=None,
        deferred_end_date=None,
        statement_line_id=None,
        statement_id=None,
        sale_line_ids=[],
        purchase_line_id=None,
        purchase_order_id=None,
        expense_id=None,
        payment_id=None,
        group_tax_id=None,
        distribution_analytic_account_ids=[],
        reconcile_model_id=None,
        reconciled_lines_ids=[],
        reconciled_lines_excluding_exchange_diff_ids=[],
        parent_id=None,
        analytic_distribution=False,
        analytic_line_ids=[],
        tax_tag_ids=[],
        cogs_origin_id=None,
        is_landed_costs_line=False,
        move_attachment_ids=[],
        tax_base_amount=0,
        extra_tax_data=False,
        deductible_amount=0,
        is_imported=False,
        is_storno=False,
        is_downpayment=False,
        sequence=10,
        product_uom_id=None,
        discount=0,
        discount_date=None,
        discount_amount_currency=0,
        discount_balance=0,
        l10n_latam_document_type_id=None,
        no_followup=False,
        collapse_composition=False,
        collapse_prices=False,
        create_uid=Record(42),
        create_date="2026-07-10 09:00:00",
        write_uid=Record(42),
        write_date="2026-07-10 09:00:00",
        display_type="product",
        date_maturity=None,
        matching_number=False,
        name="Invoice line",
        partner_id=Record(10),
        price_unit=100,
        product_id=None,
        quantity=1,
        reconciled=False,
        parent_state="draft",
    )
    line2 = Record(
        1103,
        state="unknown",
        company_id=Record(7),
        move_id=move,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        asset_ids=[],
        tax_ids=[],
        tax_line_id=None,
        tax_repartition_line_id=None,
        deferred_start_date=None,
        deferred_end_date=None,
        statement_line_id=None,
        statement_id=None,
        sale_line_ids=[],
        purchase_line_id=None,
        purchase_order_id=None,
        expense_id=None,
        payment_id=None,
        group_tax_id=None,
        distribution_analytic_account_ids=[],
        reconcile_model_id=None,
        reconciled_lines_ids=[],
        reconciled_lines_excluding_exchange_diff_ids=[],
        parent_id=None,
        analytic_distribution=False,
        analytic_line_ids=[],
        tax_tag_ids=[],
        cogs_origin_id=None,
        is_landed_costs_line=False,
        move_attachment_ids=[],
        tax_base_amount=0,
        extra_tax_data=False,
        deductible_amount=0,
        is_imported=False,
        is_storno=False,
        is_downpayment=False,
        sequence=20,
        product_uom_id=None,
        discount=0,
        discount_date=None,
        discount_amount_currency=0,
        discount_balance=0,
        l10n_latam_document_type_id=None,
        no_followup=False,
        collapse_composition=False,
        collapse_prices=False,
        create_uid=Record(42),
        create_date="2026-07-10 09:00:00",
        write_uid=Record(42),
        write_date="2026-07-10 09:00:00",
        display_type="payment_term",
        date_maturity="2026-08-10",
        matching_number=False,
        name="Payment term",
        partner_id=Record(10),
        price_unit=0,
        product_id=None,
        quantity=0,
        reconciled=False,
        parent_state="draft",
    )
    move.line_ids = [line1, line2]
    move.invoice_line_ids = [line1]
    move.journal_line_ids = [line1, line2]
    move.snapshot_values = {
        "state": "draft",
        "name": "/",
        "move_type": "in_invoice" if vendor else "out_invoice",
        "company_id": 7,
        "journal_id": 2,
        "currency_id": 1,
        "amount_total": "100",
        "amount_residual": "100",
        "payment_state": "not_paid",
        "partner_id": 10,
        "date": "2026-07-10",
        "invoice_date": "2026-07-10",
        "invoice_date_due": "2026-08-10",
        "invoice_line_ids": [1102],
        "invoice_payment_term_id": False,
        "line_ids": [1102, 1103],
        "journal_line_ids": [1102, 1103],
        "ref": "BILL-DRAFT-RECOVERY-1" if vendor else "DRAFT-RECOVERY-1",
        "auto_post": "no",
        "auto_post_until": False,
        "posted_before": False,
        "sequence_prefix": False,
        "sequence_number": 0,
        "made_sequence_gap": False,
        "secure_sequence_number": 0,
        "inalterable_hash": False,
        "checked": False,
        "auto_post_origin_id": False,
        "origin_payment_id": False,
        "payment_ids": [],
        "matched_payment_ids": [],
        "reconciled_payment_ids": [],
        "statement_line_id": False,
        "statement_line_ids": [],
        "statement_id": False,
        "tax_cash_basis_rec_id": False,
        "tax_cash_basis_origin_move_id": False,
        "tax_cash_basis_created_move_ids": [],
        "reversed_entry_id": False,
        "reversal_move_ids": [],
        "adjusting_entry_origin_move_ids": [],
        "adjusting_entries_move_ids": [],
        "exchange_diff_partial_ids": [],
        "closing_return_id": False,
        "transfer_model_id": False,
        "transaction_ids": [],
        "authorized_transaction_ids": [],
        "purchase_id": False,
        "asset_id": False,
        "asset_ids": [],
        "deferred_move_ids": [],
        "deferred_original_move_ids": [],
        "edi_document_ids": [],
        "expense_ids": [],
        "pos_order_ids": [],
        "stock_move_ids": [],
        "landed_costs_ids": [],
        "debit_note_ids": [],
        "debit_origin_id": False,
        "invoice_pdf_report_id": False,
        "invoice_vendor_bill_id": False,
        "purchase_vendor_bill_id": False,
        "ubl_cii_xml_id": False,
        "l10n_es_edi_facturae_xml_id": False,
        "invoice_pdf_report_file": {"present": False},
        "l10n_es_edi_facturae_xml_file": {"present": False},
        "ubl_cii_xml_file": {"present": False},
        "signature": {"present": False},
        "signing_user": False,
        "is_move_sent": False,
        "sending_data": False,
        "is_being_sent": False,
        "invoice_source_email": False,
        "attachment_ids": [],
        "message_main_attachment_id": False,
        "audit_trail_message_ids": [],
        "activity_ids": [],
        "message_follower_ids": [],
        "message_ids": [],
        "rating_ids": [],
        "website_message_ids": [],
        "access_token": {"present": False},
        "fiscal_position_id": False,
        "invoice_cash_rounding_id": False,
        "invoice_incoterm_id": False,
        "incoterm_location": False,
        "partner_shipping_id": False,
        "partner_bank_id": False,
        "preferred_payment_method_line_id": False,
        "l10n_latam_document_type_id": False,
        "no_followup": False,
        "collapse_composition": False,
        "collapse_prices": False,
        "invoice_origin": False,
        "narration": False,
        "quick_edit_total_amount": "0",
        "always_tax_exigible": False,
        "is_storno": False,
        "asset_value_change": False,
        "campaign_id": False,
        "medium_id": False,
        "source_id": False,
        "team_id": False,
        "delivery_date": False,
        "fapiao": False,
        "invoice_currency_rate": "1",
        "invoice_user_id": [42, "V3 Executor"],
        "l10n_es_edi_facturae_reason_code": False,
        "l10n_es_invoicing_period_start_date": False,
        "l10n_es_invoicing_period_end_date": False,
        "l10n_es_is_simplified": False,
        "l10n_es_payment_means": False,
        "payment_reference": False,
        "payment_state_before_switch": False,
        "qr_code_method": False,
        "taxable_supply_date": False,
        "asset_depreciation_beginning_date": False,
        "asset_number_days": 0,
        "depreciation_value": "0",
        "create_uid": [42, "V3 Executor"],
        "create_date": "2026-07-10 09:00:00",
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-10 09:00:00",
        "need_cancel_request": False,
        "is_manually_modified": False,
        "odoo_cli_v3_document_binding": "a" * 64,
        "odoo_cli_v3_business_binding": "b" * 64,
    }
    line1.snapshot_values = {
        "move_id": [
            1101,
            (
                "Draft Bill BILL-DRAFT-RECOVERY-1"
                if vendor
                else "Draft Invoice DRAFT-RECOVERY-1"
            ),
        ],
        "parent_state": "draft",
        "company_id": 7,
        "account_id": 10,
        "currency_id": 1,
        "debit": "100",
        "credit": "0",
        "balance": "100",
        "amount_currency": "100",
        "reconciled": False,
        "full_reconcile_id": False,
        "matched_debit_ids": [],
        "matched_credit_ids": [],
        "tax_ids": [],
        "tax_line_id": False,
        "tax_repartition_line_id": False,
        "analytic_distribution": False,
        "analytic_line_ids": [],
        "tax_tag_ids": [],
        "payment_id": False,
        "statement_line_id": False,
        "statement_id": False,
        "purchase_line_id": False,
        "purchase_order_id": False,
        "sale_line_ids": [],
        "expense_id": False,
        "asset_ids": [],
        "group_tax_id": False,
        "distribution_analytic_account_ids": [],
        "reconcile_model_id": False,
        "reconciled_lines_ids": [],
        "reconciled_lines_excluding_exchange_diff_ids": [],
        "parent_id": False,
        "cogs_origin_id": False,
        "is_landed_costs_line": False,
        "deferred_start_date": False,
        "deferred_end_date": False,
        "move_attachment_ids": [],
        "tax_base_amount": "0",
        "extra_tax_data": False,
        "deductible_amount": "0",
        "is_imported": False,
        "is_storno": False,
        "is_downpayment": False,
        "sequence": 10,
        "product_uom_id": False,
        "discount": "0",
        "discount_date": False,
        "discount_amount_currency": "0",
        "discount_balance": "0",
        "l10n_latam_document_type_id": False,
        "no_followup": False,
        "collapse_composition": False,
        "collapse_prices": False,
        "create_uid": [42, "V3 Executor"],
        "create_date": "2026-07-10 09:00:00",
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-10 09:00:00",
        "display_type": "product",
        "date_maturity": False,
        "matching_number": False,
        "name": "Invoice line",
        "partner_id": 10,
        "price_unit": "100",
        "product_id": False,
        "quantity": "1",
        "odoo_cli_v3_line_reference": "line-1",
    }
    line2.snapshot_values = {
        "move_id": [
            1101,
            (
                "Draft Bill BILL-DRAFT-RECOVERY-1"
                if vendor
                else "Draft Invoice DRAFT-RECOVERY-1"
            ),
        ],
        "parent_state": "draft",
        "company_id": 7,
        "account_id": 20,
        "currency_id": 1,
        "debit": "0",
        "credit": "100",
        "balance": "-100",
        "amount_currency": "-100",
        "reconciled": False,
        "full_reconcile_id": False,
        "matched_debit_ids": [],
        "matched_credit_ids": [],
        "tax_ids": [],
        "tax_line_id": False,
        "tax_repartition_line_id": False,
        "analytic_distribution": False,
        "analytic_line_ids": [],
        "tax_tag_ids": [],
        "payment_id": False,
        "statement_line_id": False,
        "statement_id": False,
        "purchase_line_id": False,
        "purchase_order_id": False,
        "sale_line_ids": [],
        "expense_id": False,
        "asset_ids": [],
        "group_tax_id": False,
        "distribution_analytic_account_ids": [],
        "reconcile_model_id": False,
        "reconciled_lines_ids": [],
        "reconciled_lines_excluding_exchange_diff_ids": [],
        "parent_id": False,
        "cogs_origin_id": False,
        "is_landed_costs_line": False,
        "deferred_start_date": False,
        "deferred_end_date": False,
        "move_attachment_ids": [],
        "tax_base_amount": "0",
        "extra_tax_data": False,
        "deductible_amount": "0",
        "is_imported": False,
        "is_storno": False,
        "is_downpayment": False,
        "sequence": 20,
        "product_uom_id": False,
        "discount": "0",
        "discount_date": False,
        "discount_amount_currency": "0",
        "discount_balance": "0",
        "l10n_latam_document_type_id": False,
        "create_uid": [42, "V3 Executor"],
        "create_date": "2026-07-10 09:00:00",
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-10 09:00:00",
        "display_type": "payment_term",
        "date_maturity": "2026-08-10",
        "matching_number": False,
        "name": "Payment term",
        "partner_id": 10,
        "price_unit": "0",
        "product_id": False,
        "quantity": "0",
        "odoo_cli_v3_line_reference": "line-2",
    }

    def exact_write(values):
        move.writes.append(values)
        for key, value in values.items():
            setattr(move, key, value)
            move.snapshot_values[key] = value
        if values.get("state") == "cancel":
            move.write_uid = Record(42)
            move.write_date = "2026-07-10 09:01:00"
            move.snapshot_values["write_uid"] = [42, "V3 Executor"]
            move.snapshot_values["write_date"] = "2026-07-10 09:01:00"
            for line in (line1, line2):
                line.parent_state = "cancel"
                line.snapshot_values["parent_state"] = "cancel"
                line.write_uid = Record(42)
                line.write_date = "2026-07-10 09:01:00"
                line.snapshot_values["write_uid"] = [42, "V3 Executor"]
                line.snapshot_values["write_date"] = "2026-07-10 09:01:00"
                line.snapshot_values["move_id"] = [
                    move.id,
                    (
                        "Cancelled Bill BILL-DRAFT-RECOVERY-1"
                        if vendor
                        else "Cancelled Invoice DRAFT-RECOVERY-1"
                    ),
                ]
        return True

    move.write = exact_write
    move.button_cancel = lambda: pytest.fail("button_cancel must not be called")
    move.unlink = lambda: pytest.fail("unlink must not be called")
    records = {
        ("account.move", move.id): move,
        ("account.move.line", line1.id): line1,
        ("account.move.line", line2.id): line2,
    }
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[
            recovery_target("account.move.line", line1),
            recovery_target("account.move.line", line2),
        ],
        method=(
            "cancel_pristine_v3_draft_vendor_bill_v1"
            if vendor
            else "cancel_pristine_v3_draft_customer_invoice_v1"
        ),
        oracle_id=(
            "cancel_pristine_v3_draft_vendor_bill_exact_v1"
            if vendor
            else "cancel_pristine_v3_draft_customer_invoice_exact_v1"
        ),
    )
    return move, line1, line2, records, plan


def draft_cancel_parameters(*, vendor=False):
    return {
        "company_id": 7,
        "move_id": 1101,
        "expected_move_type": "in_invoice" if vendor else "out_invoice",
        "expected_document_binding": "a" * 64,
        "expected_business_binding": "b" * 64,
        "reason": "cancel duplicate pristine draft",
        "idempotency_key": (
            "cancel-pristine-vendor-bill-1101"
            if vendor
            else "cancel-pristine-customer-invoice-1101"
        ),
    }


def journal_entry_create_parameters():
    return {
        "company_id": 7,
        "journal_id": 2,
        "posting_date": "2026-07-10",
        "currency_id": 1,
        "reference": "MANUAL-ENTRY-1",
        "reason": "Approved reclassification",
        "posting_mode": "draft",
        "lines": [
            {
                "line_reference": "manual-debit",
                "account_id": 10,
                "partner_id": None,
                "currency_id": 1,
                "name": "Manual debit",
                "side": "debit",
                "amount": "100",
                "amount_currency": "100",
                "tax_ids": [],
            },
            {
                "line_reference": "manual-credit",
                "account_id": 11,
                "partner_id": None,
                "currency_id": 1,
                "name": "Manual credit",
                "side": "credit",
                "amount": "100",
                "amount_currency": "-100",
                "tax_ids": [],
            },
        ],
        "idempotency_key": "manual-entry-1",
    }


def move_post_parameters():
    source = journal_entry_create_parameters()
    return {
        "company_id": 7,
        "move_id": 1201,
        "expected_move_type": "entry",
        "expected_document_binding": OdooWriteHandlers.document_binding(
            "journal_entry", source
        ),
        "expected_business_binding": OdooWriteHandlers.business_binding(
            "journal_entry", source
        ),
        "expected_journal_id": 2,
        "expected_currency_id": 1,
        "expected_posting_date": "2026-07-10",
        "expected_reference": "MANUAL-ENTRY-1",
        "expected_total_debit": "100",
        "expected_total_credit": "100",
        "expected_line_count": 2,
        "reason": "Approved posting",
        "idempotency_key": "post-manual-entry-1201",
    }


def draft_cancel_v2_entry_parameters():
    source = journal_entry_create_parameters()
    return {
        "company_id": 7,
        "move_id": 1201,
        "expected_move_type": "entry",
        "expected_document_binding": OdooWriteHandlers.document_binding(
            "journal_entry", source
        ),
        "expected_business_binding": OdooWriteHandlers.business_binding(
            "journal_entry", source
        ),
        "expected_line_ids": [1202, 1203],
        "reason": "Cancel duplicate pristine manual entry",
        "idempotency_key": "cancel-manual-entry-1201",
    }


def payment_cancel_parameters():
    return {
        "company_id": 7,
        "payment_id": 920,
        "move_id": 921,
        "expected_payment_state": "in_process",
        "expected_move_state": "posted",
        "expected_payment_date": "2026-07-15",
        "expected_partner_id": 101,
        "expected_partner_type": "customer",
        "expected_direction": "inbound",
        "expected_amount": "100.00",
        "expected_currency_id": 1,
        "expected_journal_id": 2,
        "expected_payment_method_line_id": 3,
        "expected_is_sent": True,
        "expected_line_ids": [922, 923],
        "reason": "Cancel an unallocated duplicate payment",
        "idempotency_key": "cancel-payment-920",
    }


def unallocated_payment_fixture():
    currency = Record(1, active=True, rounding=0.01)
    comp = company(currency_id=currency)
    journal = Record(
        2,
        company_id=comp,
        type="bank",
        active=True,
        currency_id=None,
    )
    partner = Record(101, active=True, company_id=None, company_ids=[])
    payment_method = Record(
        4,
        code="manual",
        payment_type="inbound",
    )
    payment_method_line = Record(
        3,
        active=True,
        company_id=comp,
        journal_id=journal,
        payment_method_id=payment_method,
        payment_type="inbound",
    )
    receivable = Record(
        10,
        company_id=comp,
        company_ids=[comp],
        deprecated=False,
        account_type="asset_receivable",
        reconcile=True,
    )
    outstanding = Record(
        11,
        company_id=comp,
        company_ids=[comp],
        deprecated=False,
        account_type="asset_current",
        reconcile=True,
    )
    payment_method_line.payment_account_id = outstanding
    move = Record(
        921,
        state="posted",
        name="BNK1/2026/00001",
        move_type="entry",
        company_id=comp,
        journal_id=journal,
        currency_id=currency,
        partner_id=partner,
        date="2026-07-15",
        ref="Unallocated receipt",
        line_ids=[],
        posted_before=True,
        auto_post="no",
        inalterable_hash=False,
        need_cancel_request=False,
        sending_data=False,
        payment_state="not_paid",
        affects_tax_report=False,
    )
    payment = Record(
        920,
        state="in_process",
        name="BNK1/2026/00001",
        company_id=comp,
        partner_id=partner,
        journal_id=journal,
        currency_id=currency,
        date="2026-07-15",
        amount=Decimal("100.00"),
        payment_type="inbound",
        partner_type="customer",
        memo="Unallocated receipt",
        payment_method_line_id=payment_method_line,
        destination_account_id=receivable,
        outstanding_account_id=outstanding,
        move_id=move,
        is_sent=True,
        is_reconciled=False,
        is_matched=False,
        invoice_ids=[],
        is_internal_transfer=False,
        reconciled_invoice_ids=[],
        reconciled_bill_ids=[],
        reconciled_statement_line_ids=[],
        paired_internal_transfer_payment_id=None,
        destination_journal_id=None,
        payment_transaction_id=None,
        payment_token_id=None,
        batch_payment_id=None,
        check_number=False,
        odoo_cli_v3_payment_binding=False,
    )
    debit = Record(
        922,
        move_id=move,
        company_id=comp,
        account_id=outstanding,
        partner_id=partner,
        currency_id=currency,
        parent_state="posted",
        date="2026-07-15",
        name="Unallocated receipt",
        debit=Decimal("100.00"),
        credit=Decimal("0"),
        balance=Decimal("100.00"),
        amount_currency=Decimal("100.00"),
        amount_residual=Decimal("100.00"),
        amount_residual_currency=Decimal("100.00"),
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        matching_number=False,
        statement_line_id=None,
        statement_id=None,
        payment_id=payment,
        tax_ids=[],
        tax_line_id=None,
        tax_tag_ids=[],
        tax_repartition_line_id=None,
        analytic_distribution=False,
        analytic_line_ids=[],
        asset_ids=[],
        deferred_start_date=None,
        deferred_end_date=None,
        reconciled_lines_ids=[],
        reconciled_lines_excluding_exchange_diff_ids=[],
    )
    credit = Record(
        923,
        move_id=move,
        company_id=comp,
        account_id=receivable,
        partner_id=partner,
        currency_id=currency,
        parent_state="posted",
        date="2026-07-15",
        name="Unallocated receipt",
        debit=Decimal("0"),
        credit=Decimal("100.00"),
        balance=Decimal("-100.00"),
        amount_currency=Decimal("-100.00"),
        amount_residual=Decimal("-100.00"),
        amount_residual_currency=Decimal("-100.00"),
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        matching_number=False,
        statement_line_id=None,
        statement_id=None,
        payment_id=payment,
        tax_ids=[],
        tax_line_id=None,
        tax_tag_ids=[],
        tax_repartition_line_id=None,
        analytic_distribution=False,
        analytic_line_ids=[],
        asset_ids=[],
        deferred_start_date=None,
        deferred_end_date=None,
        reconciled_lines_ids=[],
        reconciled_lines_excluding_exchange_diff_ids=[],
    )
    move.line_ids = [debit, credit]
    move.origin_payment_id = payment
    move.payment_ids = [payment]
    payment.snapshot_values = {
        "name": payment.name,
        "state": "in_process",
        "company_id": [7, "Test company"],
        "partner_id": [101, "Test customer"],
        "journal_id": [2, "Bank"],
        "currency_id": [1, "USD"],
        "date": "2026-07-15",
        "amount": 100.0,
        "payment_type": "inbound",
        "partner_type": "customer",
        "payment_method_line_id": [3, "Manual"],
        "destination_account_id": [10, "Receivable"],
        "outstanding_account_id": [11, "Outstanding receipts"],
        "move_id": [921, move.name],
        "is_sent": True,
        "is_reconciled": False,
        "is_matched": False,
        "invoice_ids": [],
        "is_internal_transfer": False,
        "reconciled_invoice_ids": [],
        "reconciled_bill_ids": [],
        "reconciled_statement_line_ids": [],
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-15 09:00:00",
    }
    move.snapshot_values = {
        "name": move.name,
        "state": "posted",
        "move_type": "entry",
        "company_id": [7, "Test company"],
        "journal_id": [2, "Bank"],
        "currency_id": [1, "USD"],
        "partner_id": [101, "Test customer"],
        "date": "2026-07-15",
        "ref": "Unallocated receipt",
        "line_ids": [922, 923],
        "origin_payment_id": [920, payment.name],
        "payment_ids": [920],
        "posted_before": True,
        "auto_post": "no",
        "sending_data": False,
        "payment_state": "not_paid",
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-15 09:00:00",
    }
    for line in (debit, credit):
        line.snapshot_values = {
            "move_id": [921, move.name],
            "company_id": [7, "Test company"],
            "parent_state": "posted",
            "account_id": [line.account_id.id, "Payment account"],
            "partner_id": [101, "Test customer"],
            "currency_id": [1, "USD"],
            "date": "2026-07-15",
            "debit": float(line.debit),
            "credit": float(line.credit),
            "balance": float(line.balance),
            "amount_currency": float(line.amount_currency),
            "reconciled": False,
            "full_reconcile_id": False,
            "matched_debit_ids": [],
            "matched_credit_ids": [],
            "tax_ids": [],
            "tax_line_id": False,
            "tax_tag_ids": [],
            "analytic_distribution": False,
            "analytic_line_ids": [],
            "write_uid": [42, "V3 Executor"],
            "write_date": "2026-07-15 09:00:00",
        }
    records = {
        ("res.currency", 1): currency,
        ("res.partner", 101): partner,
        ("account.journal", 2): journal,
        ("account.payment.method.line", 3): payment_method_line,
        ("account.payment.method", 4): payment_method,
        ("account.account", 10): receivable,
        ("account.account", 11): outstanding,
        ("account.payment", 920): payment,
        ("account.move", 921): move,
        ("account.move.line", 922): debit,
        ("account.move.line", 923): credit,
    }
    return comp, payment, move, debit, credit, records


def install_exact_payment_cancel(
    payment,
    move,
    lines,
    *,
    payment_drift=False,
    move_control_drift=None,
):
    payment.action_cancel_calls = 0

    def action_cancel():
        payment.action_cancel_calls += 1
        payment.state = "canceled"
        payment.snapshot_values.update(
            {
                "state": "canceled",
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-15 09:01:00",
            }
        )
        move.state = "cancel"
        move.snapshot_values.update(
            {
                "state": "cancel",
                "auto_post": "no",
                "sending_data": False,
                "payment_state": "not_paid",
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-15 09:01:00",
            }
        )
        for line in lines:
            line.parent_state = "cancel"
            line.snapshot_values["parent_state"] = "cancel"
        if payment_drift:
            payment.amount = Decimal("101.00")
            payment.snapshot_values["amount"] = 101.0
        if move_control_drift == "auto_post":
            move.auto_post = "at_date"
            move.snapshot_values["auto_post"] = "at_date"
        elif move_control_drift == "sending_data":
            move.sending_data = {"author": "unexpected"}
            move.snapshot_values["sending_data"] = {
                "author": "unexpected"
            }
        elif move_control_drift == "payment_state":
            move.payment_state = "paid"
            move.snapshot_values["payment_state"] = "paid"

    payment.action_cancel = action_cancel


def pristine_manual_entry_fixture(
    *,
    document_binding=None,
    business_binding=None,
    reason="Approved reclassification",
):
    source = journal_entry_create_parameters()
    document_binding = document_binding or OdooWriteHandlers.document_binding(
        "journal_entry", source
    )
    business_binding = business_binding or OdooWriteHandlers.business_binding(
        "journal_entry", source
    )
    currency = Record(1, active=True, rounding=0.01)
    comp = company(currency_id=currency)
    journal = Record(
        2,
        company_id=comp,
        type="general",
        active=True,
        currency_id=currency,
    )
    debit_account = Record(
        10,
        company_id=comp,
        company_ids=[comp],
        deprecated=False,
        account_type="expense",
    )
    credit_account = Record(
        11,
        company_id=comp,
        company_ids=[comp],
        deprecated=False,
        account_type="income",
    )
    move = Record(
        1201,
        state="draft",
        name="/",
        move_type="entry",
        company_id=comp,
        journal_id=journal,
        currency_id=currency,
        date="2026-07-10",
        ref="MANUAL-ENTRY-1",
        line_ids=[],
        auto_post="no",
        auto_post_until=None,
        posted_before=False,
        sequence_prefix=None,
        sequence_number=0,
        secure_sequence_number=0,
        made_sequence_gap=False,
        checked=False,
        inalterable_hash=False,
        need_cancel_request=False,
        is_manually_modified=False,
        odoo_cli_v3_reason=reason,
        odoo_cli_v3_document_binding=document_binding,
        odoo_cli_v3_business_binding=business_binding,
        create_uid=Record(42),
        create_date="2026-07-10 09:00:00",
        write_uid=Record(42),
        write_date="2026-07-10 09:00:00",
        narration=False,
        message_ids=[],
    )
    debit = Record(
        1202,
        state="unknown",
        parent_state="draft",
        move_id=move,
        company_id=comp,
        account_id=debit_account,
        partner_id=None,
        currency_id=currency,
        name="Manual debit",
        odoo_cli_v3_line_reference="manual-debit",
        debit=100,
        credit=0,
        balance=100,
        amount_currency=100,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        tax_ids=[],
        tax_line_id=None,
        tax_tag_ids=[],
        analytic_distribution=False,
        analytic_line_ids=[],
        display_type="product",
        create_uid=Record(42),
        create_date="2026-07-10 09:00:00",
        write_uid=Record(42),
        write_date="2026-07-10 09:00:00",
    )
    credit = Record(
        1203,
        state="unknown",
        parent_state="draft",
        move_id=move,
        company_id=comp,
        account_id=credit_account,
        partner_id=None,
        currency_id=currency,
        name="Manual credit",
        odoo_cli_v3_line_reference="manual-credit",
        debit=0,
        credit=100,
        balance=-100,
        amount_currency=-100,
        reconciled=False,
        full_reconcile_id=None,
        matched_debit_ids=[],
        matched_credit_ids=[],
        tax_ids=[],
        tax_line_id=None,
        tax_tag_ids=[],
        analytic_distribution=False,
        analytic_line_ids=[],
        display_type="product",
        create_uid=Record(42),
        create_date="2026-07-10 09:00:00",
        write_uid=Record(42),
        write_date="2026-07-10 09:00:00",
    )
    move.line_ids = [debit, credit]
    move.snapshot_values = {
        "state": "draft",
        "name": "/",
        "move_type": "entry",
        "company_id": 7,
        "journal_id": 2,
        "currency_id": 1,
        "date": "2026-07-10",
        "ref": "MANUAL-ENTRY-1",
        "line_ids": [1202, 1203],
        "auto_post": "no",
        "posted_before": False,
        "sequence_prefix": False,
        "sequence_number": 0,
        "secure_sequence_number": 0,
        "inalterable_hash": False,
        "checked": False,
        "odoo_cli_v3_reason": reason,
        "odoo_cli_v3_document_binding": document_binding,
        "odoo_cli_v3_business_binding": business_binding,
        "narration": False,
        "message_ids": [],
        "create_uid": [42, "V3 Executor"],
        "create_date": "2026-07-10 09:00:00",
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-10 09:00:00",
    }
    for line in (debit, credit):
        line.snapshot_values = {
            "move_id": [1201, "Draft Entry MANUAL-ENTRY-1"],
            "parent_state": "draft",
            "company_id": 7,
            "account_id": line.account_id.id,
            "currency_id": 1,
            "name": line.name,
            "debit": str(line.debit),
            "credit": str(line.credit),
            "balance": str(line.balance),
            "amount_currency": str(line.amount_currency),
            "tax_ids": [],
            "tax_line_id": False,
            "tax_tag_ids": [],
            "analytic_distribution": False,
            "analytic_line_ids": [],
            "odoo_cli_v3_line_reference": line.odoo_cli_v3_line_reference,
            "create_uid": [42, "V3 Executor"],
            "create_date": "2026-07-10 09:00:00",
            "write_uid": [42, "V3 Executor"],
            "write_date": "2026-07-10 09:00:00",
        }
    records = {
        ("res.currency", 1): currency,
        ("account.journal", 2): journal,
        ("account.account", 10): debit_account,
        ("account.account", 11): credit_account,
        ("account.move", 1201): move,
        ("account.move.line", 1202): debit,
        ("account.move.line", 1203): credit,
    }
    return comp, move, debit, credit, records


def install_exact_manual_entry_post(
    move,
    lines,
    *,
    material_drift=False,
    date_drift=False,
    chatter_drift=False,
):
    def action_post():
        move.action_post_calls += 1
        move.state = "posted"
        move.name = "MISC/2026/0001"
        move.posted_before = True
        move.sequence_prefix = "MISC/2026/"
        move.sequence_number = 1
        move.checked = True
        move.write_uid = Record(42)
        move.write_date = "2026-07-10 09:01:00"
        move.snapshot_values.update(
            {
                "state": "posted",
                "name": "MISC/2026/0001",
                "posted_before": True,
                "sequence_prefix": "MISC/2026/",
                "sequence_number": 1,
                "checked": True,
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-10 09:01:00",
            }
        )
        if material_drift:
            move.narration = "unapproved posting side effect"
            move.snapshot_values["narration"] = move.narration
        if date_drift:
            move.date = "2026-07-16"
            move.snapshot_values["date"] = move.date
        if chatter_drift:
            move.message_ids = [Record(9001)]
            move.snapshot_values["message_ids"] = [9001]
        for line in lines:
            line.parent_state = "posted"
            line.write_uid = Record(42)
            line.write_date = "2026-07-10 09:01:00"
            line.snapshot_values.update(
                {
                    "move_id": [1201, "MISC/2026/0001"],
                    "parent_state": "posted",
                    "write_uid": [42, "V3 Executor"],
                    "write_date": "2026-07-10 09:01:00",
                }
            )
        return False

    move.action_post = action_post


def install_exact_manual_entry_cancel(move, lines):
    def write(values):
        move.writes.append(values)
        assert values == {"state": "cancel"}
        move.state = "cancel"
        move.write_uid = Record(42)
        move.write_date = "2026-07-10 09:01:00"
        move.snapshot_values.update(
            {
                "state": "cancel",
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-10 09:01:00",
            }
        )
        for line in lines:
            line.parent_state = "cancel"
            line.write_uid = Record(42)
            line.write_date = "2026-07-10 09:01:00"
            line.snapshot_values.update(
                {
                    "move_id": [1201, "Cancelled Entry MANUAL-ENTRY-1"],
                    "parent_state": "cancel",
                    "write_uid": [42, "V3 Executor"],
                    "write_date": "2026-07-10 09:01:00",
                }
            )
        return True

    move.write = write
    move.button_cancel = lambda: pytest.fail("button_cancel must not be called")
    move.button_draft = lambda: pytest.fail("button_draft must not be called")
    move.unlink = lambda: pytest.fail("unlink must not be called")


@pytest.mark.parametrize(
    "account_type",
    ["asset_receivable", "liability_payable", "off_balance"],
)
def test_journal_entry_create_rejects_restricted_account_types(
    account_type,
):
    parameters = journal_entry_create_parameters()
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture()
    records[("account.account", 10)].account_type = account_type
    handler = Harness(
        models={"account.move": Model(factory=lambda values: move)},
        records=records,
    )
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError,
        match="cannot use a receivable, payable, or off-balance account",
    ):
        handler.precheck("acct.journal.entry_create.v1", parameters)


@pytest.mark.parametrize(
    "capability_id",
    ["acct.journal.entry_create.v1", "acct.move.post.v1"],
)
def test_phaseb_manual_entry_writes_reject_effective_odoo_lock_date(
    capability_id,
):
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture()
    lock_subject = (
        comp
        if capability_id == "acct.journal.entry_create.v1"
        else move
    )
    lock_subject.violated_lock_dates = [
        (date(2026, 7, 10), "fiscalyear_lock_date")
    ]
    handler = Harness(
        models={"account.move": Model(factory=lambda values: move)},
        records=records,
    )
    handler.test_company = comp
    parameters = (
        journal_entry_create_parameters()
        if capability_id == "acct.journal.entry_create.v1"
        else move_post_parameters()
    )

    with pytest.raises(
        OdooWriteHandlerError,
        match=(
            "violates effective Odoo lock dates: "
            "fiscalyear_lock_date=2026-07-10"
        ),
    ):
        handler.precheck(capability_id, parameters)

    expected_call = (
        (date(2026, 7, 10), False, records[("account.journal", 2)])
        if capability_id == "acct.journal.entry_create.v1"
        else (date(2026, 7, 10), False)
    )
    assert lock_subject.lock_date_checks == [expected_call]
    assert move.tax_effect_checks == (
        0 if capability_id == "acct.journal.entry_create.v1" else 1
    )


def test_move_post_rejects_an_unexpected_live_odoo_tax_effect():
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture()
    move.affects_tax_report = True
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError,
        match="manual journal entry has an unexpected Odoo tax effect",
    ):
        handler.precheck("acct.move.post.v1", move_post_parameters())

    assert move.tax_effect_checks == 1
    assert move.lock_date_checks == []


@pytest.mark.parametrize(
    "capability_id",
    ["acct.journal.entry_create.v1", "acct.move.post.v1"],
)
def test_phaseb_manual_entry_writes_use_effective_lock_result_not_raw_soft_lock(
    capability_id,
):
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture()
    comp.fiscalyear_lock_date = date(2026, 7, 10)
    handler = Harness(
        models={"account.move": Model(factory=lambda values: move)},
        records=records,
    )
    handler.test_company = comp
    parameters = (
        journal_entry_create_parameters()
        if capability_id == "acct.journal.entry_create.v1"
        else move_post_parameters()
    )

    checked = handler.precheck(capability_id, parameters)

    assert "effective_odoo_lock_dates_open" in checked["checks"] or (
        capability_id == "acct.move.post.v1"
        and "posting_date_open" in checked["checks"]
    )


def test_journal_entry_create_rechecks_effective_lock_before_create():
    parameters = journal_entry_create_parameters()
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture()
    move_model = Model(factory=lambda values: move)
    handler = Harness(models={"account.move": move_model}, records=records)
    handler.test_company = comp
    checked = handler.precheck(
        "acct.journal.entry_create.v1", parameters
    )
    comp.violated_lock_dates = [
        (date(2026, 7, 10), "fiscalyear_lock_date")
    ]

    with pytest.raises(
        OdooWriteHandlerError,
        match="violates effective Odoo lock dates",
    ):
        handler.execute_prechecked(
            "acct.journal.entry_create.v1", parameters, checked
        )

    assert move_model.creates == []
    assert len(comp.lock_date_checks) == 2


@pytest.mark.parametrize(
    ("drift", "error"),
    (
        ("tax", "unexpected Odoo tax effect"),
        ("lock", "violates effective Odoo lock dates"),
    ),
)
def test_move_post_rechecks_live_tax_and_lock_state_before_action(
    drift,
    error,
):
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture()
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = move_post_parameters()
    checked = handler.precheck("acct.move.post.v1", parameters)
    if drift == "tax":
        move.affects_tax_report = True
    else:
        move.violated_lock_dates = [
            (date(2026, 7, 10), "fiscalyear_lock_date")
        ]

    with pytest.raises(OdooWriteHandlerError, match=error):
        handler.execute_prechecked(
            "acct.move.post.v1", parameters, checked
        )

    assert move.action_post_calls == 0
    assert move.tax_effect_checks == 2
    assert len(move.lock_date_checks) == (1 if drift == "tax" else 2)


def test_journal_entry_create_stays_draft_and_persists_both_bindings():
    parameters = journal_entry_create_parameters()
    document_binding = OdooWriteHandlers.document_binding(
        "journal_entry", parameters
    )
    business_binding = OdooWriteHandlers.business_binding(
        "journal_entry", parameters
    )
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture(
        document_binding=document_binding,
        business_binding=business_binding,
    )
    move_model = Model(factory=lambda values: move)
    handler = Harness(models={"account.move": move_model}, records=records)
    handler.test_company = comp

    checked = handler.precheck(
        "acct.journal.entry_create.v1", parameters
    )
    execution = handler.execute_prechecked(
        "acct.journal.entry_create.v1", parameters, checked
    )
    verification = handler.verify(
        "acct.journal.entry_create.v1", parameters, execution
    )

    created = move_model.creates[0]
    assert created["move_type"] == "entry"
    assert created["odoo_cli_v3_document_binding"] == document_binding
    assert created["odoo_cli_v3_business_binding"] == business_binding
    assert created["odoo_cli_v3_reason"] == parameters["reason"]
    assert move_model.contexts == [
        (
            (),
            {
                "tracking_disable": True,
                "mail_notrack": True,
            },
        )
    ]
    assert move.state == "draft"
    assert move.action_post_calls == 0
    assert len(comp.lock_date_checks) == 3
    assert verification["passed"] is True
    assert "draft_sequence_absent" in verification["checks"]
    assert execution["recovery"]["status"] == "manual_escalation"


def test_move_post_calls_action_post_once_and_accepts_only_exact_posting_delta():
    comp, move, debit, credit, records = pristine_manual_entry_fixture()
    install_exact_manual_entry_post(move, [debit, credit])
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = move_post_parameters()

    checked = handler.precheck("acct.move.post.v1", parameters)
    execution = handler.execute_prechecked(
        "acct.move.post.v1", parameters, checked
    )
    verification = handler.verify(
        "acct.move.post.v1", parameters, execution
    )

    assert move.action_post_calls == 1
    assert move.tax_effect_checks == 2
    assert move.lock_date_checks == [
        (date(2026, 7, 10), False),
        (date(2026, 7, 10), False),
    ]
    assert move.contexts[-1] == {
        "tracking_disable": True,
        "mail_notrack": True,
    }
    assert move.writes == []
    assert move.state == "posted"
    assert verification["passed"] is True
    assert "posting_delta_allowlist_matches" in verification["checks"]
    assert "business_lines_unchanged" in verification["checks"]


def test_move_post_rejects_material_drift_outside_the_posting_allowlist():
    comp, move, debit, credit, records = pristine_manual_entry_fixture()
    install_exact_manual_entry_post(
        move, [debit, credit], material_drift=True
    )
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = move_post_parameters()

    checked = handler.precheck("acct.move.post.v1", parameters)
    with pytest.raises(
        OdooWriteHandlerError,
        match="outside the approved posting allowlist",
    ):
        handler.execute_prechecked(
            "acct.move.post.v1", parameters, checked
        )
    assert move.action_post_calls == 1


@pytest.mark.parametrize(
    ("side_effect", "error"),
    (
        ("date", "graph or identity differs"),
        ("chatter", "outside the approved posting allowlist"),
    ),
)
def test_move_post_rejects_date_or_chatter_drift_before_execution_returns(
    side_effect,
    error,
):
    comp, move, debit, credit, records = pristine_manual_entry_fixture()
    install_exact_manual_entry_post(
        move,
        [debit, credit],
        date_drift=side_effect == "date",
        chatter_drift=side_effect == "chatter",
    )
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = move_post_parameters()

    checked = handler.precheck("acct.move.post.v1", parameters)
    with pytest.raises(OdooWriteHandlerError, match=error):
        handler.execute_prechecked(
            "acct.move.post.v1", parameters, checked
        )

    assert move.action_post_calls == 1


def test_payment_cancel_calls_only_public_action_once_and_verifies_exact_delta():
    comp, payment, move, debit, credit, records = (
        unallocated_payment_fixture()
    )
    install_exact_payment_cancel(payment, move, [debit, credit])
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = payment_cancel_parameters()

    checked = handler.precheck("acct.payment.cancel.v1", parameters)
    execution = handler.execute_prechecked(
        "acct.payment.cancel.v1", parameters, checked
    )
    verification = handler.verify(
        "acct.payment.cancel.v1", parameters, execution
    )

    assert payment.action_cancel_calls == 1
    assert payment.contexts[-1] == {
        "tracking_disable": True,
        "mail_notrack": True,
    }
    assert payment.writes == []
    assert move.writes == []
    assert payment.state == "canceled"
    assert move.state == "cancel"
    assert [debit.parent_state, credit.parent_state] == [
        "cancel",
        "cancel",
    ]
    assert move.tax_effect_checks == 2
    assert move.lock_date_checks == [
        (date(2026, 7, 15), False),
        (date(2026, 7, 15), False),
    ]
    assert execution["recovery"] == {
        "status": "manual_escalation",
        "method": "manual_review_terminal_payment_cancel",
        "targets": [
            {"model": "account.payment", "record_id": 920},
            {"model": "account.move", "record_id": 921},
        ],
    }
    assert verification["passed"] is True
    assert "payment_cancelled_fresh" in verification["checks"]
    assert "payment_reconciliation_graph_remained_empty" in (
        verification["checks"]
    )


@pytest.mark.parametrize(
    ("unsafe_case", "error"),
    (
        ("paid", "not an approved sent in-process posted payment"),
        (
            "partial",
            "reconciliation, tax, analytic, asset, deferred",
        ),
        (
            "tax",
            "reconciliation, tax, analytic, asset, deferred",
        ),
        (
            "provider",
            "target, bank, transfer, provider, batch, check",
        ),
        (
            "matched",
            "target, bank, transfer, provider, batch, check",
        ),
        (
            "targeted",
            "target, bank, transfer, provider, batch, check",
        ),
        (
            "sending",
            "unsupported origin, posting, or lock evidence",
        ),
    ),
)
def test_payment_cancel_rejects_paid_reconciled_tax_or_provider_sources(
    unsafe_case,
    error,
):
    comp, payment, _move, debit, _credit, records = (
        unallocated_payment_fixture()
    )
    if unsafe_case == "paid":
        payment.state = "paid"
    elif unsafe_case == "partial":
        debit.matched_credit_ids = [Record(3001)]
    elif unsafe_case == "tax":
        debit.tax_ids = [Record(301)]
    elif unsafe_case == "provider":
        payment.payment_transaction_id = Record(401)
    elif unsafe_case == "matched":
        payment.is_matched = True
    elif unsafe_case == "targeted":
        payment.invoice_ids = [Record(501)]
    else:
        records[("account.move", 921)].sending_data = {
            "author": "in-flight"
        }
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match=error):
        handler.precheck(
            "acct.payment.cancel.v1", payment_cancel_parameters()
        )


def test_payment_cancel_rejects_reversed_accounting_direction():
    comp, _payment, _move, debit, credit, records = (
        unallocated_payment_fixture()
    )
    debit.account_id, credit.account_id = credit.account_id, debit.account_id
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError,
        match="outstanding-account balance differs",
    ):
        handler.precheck(
            "acct.payment.cancel.v1", payment_cancel_parameters()
        )


def test_payment_cancel_rejects_payment_method_account_drift():
    comp, _payment, _move, _debit, _credit, records = (
        unallocated_payment_fixture()
    )
    records[("account.payment.method.line", 3)].payment_account_id = (
        records[("account.account", 10)]
    )
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError,
        match="method outstanding account differs",
    ):
        handler.precheck(
            "acct.payment.cancel.v1", payment_cancel_parameters()
        )


def test_payment_cancel_rejects_hidden_partial_reconcile_search_result():
    comp, _payment, _move, _debit, _credit, records = (
        unallocated_payment_fixture()
    )
    handler = Harness(records=records)
    handler.test_company = comp

    def search_records(model_name, domain, company, *, limit=1):
        assert company is comp
        assert limit == 1
        if model_name == "account.partial.reconcile":
            return [Record(3001)]
        return []

    handler.search_records = search_records

    with pytest.raises(
        OdooWriteHandlerError,
        match="hidden partial reconciliation",
    ):
        handler.precheck(
            "acct.payment.cancel.v1", payment_cancel_parameters()
        )


def test_payment_cancel_rejects_graph_drift_after_approval_before_action():
    comp, payment, move, debit, credit, records = (
        unallocated_payment_fixture()
    )
    install_exact_payment_cancel(payment, move, [debit, credit])
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = payment_cancel_parameters()
    checked = handler.precheck("acct.payment.cancel.v1", parameters)
    move.line_ids = [debit]

    with pytest.raises(
        OdooWriteHandlerError,
        match="journal-item graph differs",
    ):
        handler.execute_prechecked(
            "acct.payment.cancel.v1", parameters, checked
        )

    assert payment.action_cancel_calls == 0


def test_payment_cancel_rechecks_effective_lock_before_public_action():
    comp, payment, move, debit, credit, records = (
        unallocated_payment_fixture()
    )
    install_exact_payment_cancel(payment, move, [debit, credit])
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = payment_cancel_parameters()
    checked = handler.precheck("acct.payment.cancel.v1", parameters)
    move.violated_lock_dates = [
        (date(2026, 7, 15), "fiscalyear_lock_date")
    ]

    with pytest.raises(
        OdooWriteHandlerError,
        match="violates effective Odoo lock dates",
    ):
        handler.execute_prechecked(
            "acct.payment.cancel.v1", parameters, checked
        )

    assert payment.action_cancel_calls == 0
    assert move.tax_effect_checks == 2
    assert move.lock_date_checks == [
        (date(2026, 7, 15), False),
        (date(2026, 7, 15), False),
    ]


def test_payment_cancel_rejects_material_action_side_effect_in_transaction():
    comp, payment, move, debit, credit, records = (
        unallocated_payment_fixture()
    )
    install_exact_payment_cancel(
        payment,
        move,
        [debit, credit],
        payment_drift=True,
    )
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = payment_cancel_parameters()
    checked = handler.precheck("acct.payment.cancel.v1", parameters)

    with pytest.raises(
        OdooWriteHandlerError,
        match="outside the approved payment cancellation allowlist",
    ):
        handler.execute_prechecked(
            "acct.payment.cancel.v1", parameters, checked
        )

    assert payment.action_cancel_calls == 1


@pytest.mark.parametrize(
    "control_field",
    ("auto_post", "sending_data", "payment_state"),
)
def test_payment_cancel_rejects_wrong_move_control_terminal_value(
    control_field,
):
    comp, payment, move, debit, credit, records = (
        unallocated_payment_fixture()
    )
    install_exact_payment_cancel(
        payment,
        move,
        [debit, credit],
        move_control_drift=control_field,
    )
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = payment_cancel_parameters()
    checked = handler.precheck("acct.payment.cancel.v1", parameters)

    with pytest.raises(
        OdooWriteHandlerError,
        match="cancellation control fields differ",
    ):
        handler.execute_prechecked(
            "acct.payment.cancel.v1", parameters, checked
        )

    assert payment.action_cancel_calls == 1


def test_draft_cancel_v2_cancels_pristine_manual_entry_exactly():
    comp, move, debit, credit, records = pristine_manual_entry_fixture()
    install_exact_manual_entry_cancel(move, [debit, credit])
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = draft_cancel_v2_entry_parameters()

    checked = handler.precheck("acct.move.draft_cancel.v2", parameters)
    execution = handler.execute_prechecked(
        "acct.move.draft_cancel.v2", parameters, checked
    )
    verification = handler.verify(
        "acct.move.draft_cancel.v2", parameters, execution
    )

    assert move.writes == [{"state": "cancel"}]
    assert move.contexts[-1] == {
        "tracking_disable": True,
        "skip_account_move_synchronization": True,
        "skip_invoice_sync": True,
        "skip_is_manually_modified": True,
    }
    assert move.state == "cancel"
    assert verification["passed"] is True
    assert (
        "draft_manual_journal_entry_cancelled_exactly"
        in verification["checks"]
    )
    assert execution["recovery"] == {
        "status": "not_applicable",
        "method": "draft_cancel_v2_completed",
        "targets": [],
    }


@pytest.mark.parametrize(
    ("drift", "error"),
    (
        ("line_ids", "line graph differs"),
        ("document_binding", "immutable binding differs"),
        ("business_binding", "immutable binding differs"),
    ),
)
def test_draft_cancel_v2_rejects_line_or_binding_drift_after_precheck(
    drift,
    error,
):
    comp, move, _debit, _credit, records = pristine_manual_entry_fixture()
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = draft_cancel_v2_entry_parameters()
    checked = handler.precheck("acct.move.draft_cancel.v2", parameters)

    if drift == "line_ids":
        move.line_ids = move.line_ids[:1]
    elif drift == "document_binding":
        move.odoo_cli_v3_document_binding = "c" * 64
    else:
        move.odoo_cli_v3_business_binding = "c" * 64

    with pytest.raises(OdooWriteHandlerError, match=error):
        handler.execute_prechecked(
            "acct.move.draft_cancel.v2", parameters, checked
        )


@pytest.mark.parametrize("vendor", [False, True])
def test_draft_cancel_is_normal_exact_verified_write_without_recovery_plan(
    vendor,
):
    move, line1, _line2, records_by_key, _plan = (
        draft_move_recovery_fixture(vendor=vendor)
    )
    handler = Harness(records=records_by_key, recovery_plan=None)
    parameters = draft_cancel_parameters(vendor=vendor)
    assert "expected_line_ids" not in parameters

    checked = handler.precheck("acct.move.draft_cancel.v1", parameters)
    assert checked["semantic_precheck"]["computed"] == {
        "expected_move_type": parameters["expected_move_type"],
        "expected_document_binding": "a" * 64,
        "expected_business_binding": "b" * 64,
    }
    assert {
        (item["model"], item["record_id"])
        for item in checked["before"]
    } == {
        ("account.move", 1101),
        ("account.move.line", 1102),
        ("account.move.line", 1103),
    }

    execution = handler.execute_prechecked(
        "acct.move.draft_cancel.v1", parameters, checked
    )
    assert move.writes == [{"state": "cancel"}]
    assert line1.parent_state == "cancel"
    assert execution["recovery"] == {
        "status": "not_applicable",
        "method": "draft_cancel_completed",
        "targets": [],
    }

    verification = handler.verify(
        "acct.move.draft_cancel.v1", parameters, execution
    )
    assert verification["passed"] is True
    assert (
        "draft_vendor_bill_cancelled_exactly"
        if vendor
        else "draft_customer_invoice_cancelled_exactly"
    ) in verification["checks"]


def test_draft_cancel_rejects_injected_trusted_recovery_plan_and_binding_drift():
    _move, _line1, _line2, records_by_key, plan = (
        draft_move_recovery_fixture()
    )
    parameters = draft_cancel_parameters()

    with pytest.raises(OdooWriteHandlerError, match="must be null"):
        Harness(
            records=records_by_key, recovery_plan=plan
        ).precheck("acct.move.draft_cancel.v1", parameters)

    handler = Harness(records=records_by_key)
    for field in (
        "expected_document_binding",
        "expected_business_binding",
    ):
        tampered = {**parameters, field: "c" * 64}
        with pytest.raises(OdooWriteHandlerError, match="binding differs"):
            handler.precheck("acct.move.draft_cancel.v1", tampered)


@pytest.mark.parametrize(
    ("target", "field", "value"),
    [
        ("move", "state", "posted"),
        ("move", "posted_before", True),
        ("move", "inalterable_hash", "hash"),
        ("move", "edi_document_ids", [Record(1901)]),
        ("move", "payment_ids", [Record(1902)]),
        ("move", "asset_ids", [Record(1903)]),
        ("move", "stock_move_ids", [Record(1904)]),
        ("line", "reconciled", True),
        ("line", "purchase_line_id", Record(1905)),
        ("line", "sale_line_ids", [Record(1906)]),
        ("line", "analytic_distribution", {"7": 100}),
    ],
)
def test_draft_cancel_rejects_posting_and_external_effect_graphs(
    target, field, value
):
    move, line1, _line2, records_by_key, _plan = (
        draft_move_recovery_fixture()
    )
    setattr(move if target == "move" else line1, field, value)
    handler = Harness(records=records_by_key)

    with pytest.raises(OdooWriteHandlerError):
        handler.precheck(
            "acct.move.draft_cancel.v1", draft_cancel_parameters()
        )


@pytest.mark.parametrize(
    ("payment_state", "amount_residual"),
    [
        ("paid", 0),
        ("partial", 50),
        ("in_payment", 0),
        ("blocked", 100),
        ("reversed", 0),
        ("invoicing_legacy", 100),
    ],
)
def test_draft_cancel_rejects_non_pristine_payment_state(
    payment_state, amount_residual
):
    move, _line1, _line2, records_by_key, _plan = (
        draft_move_recovery_fixture()
    )
    move.payment_state = payment_state
    move.amount_residual = amount_residual
    move.snapshot_values["payment_state"] = payment_state
    move.snapshot_values["amount_residual"] = str(amount_residual)

    with pytest.raises(OdooWriteHandlerError, match="fully unpaid draft"):
        Harness(records=records_by_key).precheck(
            "acct.move.draft_cancel.v1", draft_cancel_parameters()
        )


def test_draft_cancel_rejects_not_paid_residual_mismatch():
    move, _line1, _line2, records_by_key, _plan = (
        draft_move_recovery_fixture()
    )
    move.amount_residual = 0
    move.snapshot_values["amount_residual"] = "0"

    with pytest.raises(OdooWriteHandlerError, match="unpaid residual"):
        Harness(records=records_by_key).precheck(
            "acct.move.draft_cancel.v1", draft_cancel_parameters()
        )


def test_draft_cancel_rejects_cross_company_graph_and_fingerprint_drift():
    move, line1, _line2, records_by_key, _plan = (
        draft_move_recovery_fixture()
    )
    handler = Harness(records=records_by_key)
    parameters = draft_cancel_parameters()

    move.company_id = Record(8)
    with pytest.raises(OdooWriteHandlerError, match="pristine V3 draft"):
        handler.precheck("acct.move.draft_cancel.v1", parameters)

    move.company_id = Record(7)
    line1.company_id = Record(8)
    with pytest.raises(OdooWriteHandlerError, match="external business effects"):
        handler.precheck("acct.move.draft_cancel.v1", parameters)

    line1.company_id = Record(7)
    move.journal_id.company_id = Record(8)
    with pytest.raises(OdooWriteHandlerError, match="active sales journal"):
        handler.precheck("acct.move.draft_cancel.v1", parameters)

    move.journal_id.company_id = Record(7)
    checked = handler.precheck("acct.move.draft_cancel.v1", parameters)
    move.ref = "DRIFTED-AFTER-APPROVAL"
    move.snapshot_values["ref"] = move.ref
    with pytest.raises(OdooWriteHandlerError, match="changed outside the approved"):
        handler.execute_prechecked(
            "acct.move.draft_cancel.v1", parameters, checked
        )


@pytest.mark.parametrize("phase", ["precheck", "execute", "verify"])
def test_draft_recovery_rejects_module_graph_changed_since_origin_execution(
    phase,
):
    _move, _line1, _line2, records_by_key, plan = (
        draft_move_recovery_fixture()
    )
    changed_graph = build_trusted_module_graph(
        [
            {
                "name": name,
                "latest_version": (
                    "19.0.changed" if name == "account" else version
                ),
            }
            for name, version in TEST_MODULE_GRAPH.modules
        ]
    )
    handler = Harness(
        recovery_plan=plan,
        records=records_by_key,
        module_graph=changed_graph,
    )

    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
    }
    with pytest.raises(OdooWriteHandlerError, match="module graph"):
        if phase == "precheck":
            handler.precheck_recovery(parameters, handler.test_company)
        elif phase == "execute":
            handler.execute_recovery(parameters, handler.test_company, {})
        else:
            handler.verify_recovery(
                parameters,
                handler.test_company,
                list(records_by_key.values()),
                {},
            )


@pytest.mark.parametrize("vendor", [False, True])
def test_draft_document_recovery_requires_complete_external_effect_fingerprint(
    vendor,
):
    _move, _line1, _line2, records_by_key, plan = (
        draft_move_recovery_fixture(vendor=vendor)
    )

    class CaptureRequiredFieldsHarness(Harness):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.required = {}

        def snapshot(self, model, record, company, *, required_fields=()):
            self.required.setdefault(model, set()).update(required_fields)
            return super().snapshot(
                model,
                record,
                company,
                required_fields=required_fields,
            )

    handler = CaptureRequiredFieldsHarness(
        recovery_plan=plan,
        records=records_by_key,
    )
    handler.precheck_recovery(
        {
            "origin_operation_id": "op-1",
            "expected_recovery_plan_digest": plan["plan_digest"],
            "company_id": 7,
        },
        handler.test_company,
    )

    assert {
        "name",
        "invoice_date",
        "invoice_date_due",
        "invoice_line_ids",
        "invoice_payment_term_id",
        "ref",
        "auto_post_until",
        "sequence_prefix",
        "sequence_number",
        "made_sequence_gap",
        "checked",
        "statement_line_ids",
        "closing_return_id",
        "transfer_model_id",
        "transaction_ids",
        "authorized_transaction_ids",
        "purchase_id",
        "asset_ids",
        "stock_move_ids",
        "landed_costs_ids",
        "debit_note_ids",
        "debit_origin_id",
        "invoice_pdf_report_id",
        "invoice_vendor_bill_id",
        "purchase_vendor_bill_id",
        "ubl_cii_xml_id",
        "l10n_es_edi_facturae_xml_id",
        "signature",
        "signing_user",
        "is_move_sent",
        "sending_data",
        "is_being_sent",
        "invoice_source_email",
        "attachment_ids",
        "message_main_attachment_id",
        "audit_trail_message_ids",
        "activity_ids",
        "message_follower_ids",
        "message_ids",
        "rating_ids",
        "website_message_ids",
        "access_token",
        "asset_value_change",
        "campaign_id",
        "medium_id",
        "source_id",
        "team_id",
        "delivery_date",
        "fapiao",
        "invoice_currency_rate",
        "invoice_user_id",
        "l10n_es_edi_facturae_reason_code",
        "l10n_es_invoicing_period_start_date",
        "l10n_es_invoicing_period_end_date",
        "l10n_es_is_simplified",
        "l10n_es_payment_means",
        "payment_reference",
        "payment_state_before_switch",
        "qr_code_method",
        "taxable_supply_date",
        "journal_line_ids",
        "asset_depreciation_beginning_date",
        "asset_number_days",
        "depreciation_value",
        "invoice_pdf_report_file",
        "l10n_es_edi_facturae_xml_file",
        "ubl_cii_xml_file",
        "fiscal_position_id",
        "invoice_cash_rounding_id",
        "invoice_incoterm_id",
        "incoterm_location",
        "partner_shipping_id",
        "partner_bank_id",
        "preferred_payment_method_line_id",
        "l10n_latam_document_type_id",
        "invoice_origin",
        "narration",
        "quick_edit_total_amount",
        "always_tax_exigible",
        "is_storno",
        "create_uid",
        "create_date",
        "write_uid",
        "write_date",
    } <= handler.required["account.move"]
    assert {
        "payment_id",
        "date_maturity",
        "matching_number",
        "name",
        "partner_id",
        "price_unit",
        "product_id",
        "quantity",
        "statement_id",
        "purchase_order_id",
        "group_tax_id",
        "distribution_analytic_account_ids",
        "reconcile_model_id",
        "reconciled_lines_ids",
        "reconciled_lines_excluding_exchange_diff_ids",
        "parent_id",
        "cogs_origin_id",
        "is_landed_costs_line",
        "move_attachment_ids",
        "tax_base_amount",
        "extra_tax_data",
        "deductible_amount",
        "is_imported",
        "is_downpayment",
        "is_storno",
        "sequence",
        "product_uom_id",
        "discount",
        "discount_date",
        "discount_amount_currency",
        "discount_balance",
        "l10n_latam_document_type_id",
        "no_followup",
        "collapse_composition",
        "collapse_prices",
        "create_uid",
        "create_date",
        "write_uid",
        "write_date",
    } <= handler.required["account.move.line"]


@pytest.mark.parametrize("vendor", [False, True])
@pytest.mark.parametrize(
    ("target", "field", "value", "match"),
    [
        ("move", "name", "INV/2026/0001", "pristine"),
        ("move", "auto_post_until", "2026-12-31", "pristine"),
        ("move", "sequence_prefix", "INV/2026/", "pristine"),
        ("move", "sequence_number", 1, "pristine"),
        ("move", "made_sequence_gap", True, "pristine"),
        ("move", "checked", True, "pristine"),
        ("move", "statement_line_ids", [Record(1201)], "link"),
        ("move", "closing_return_id", Record(1202), "link"),
        ("move", "transfer_model_id", Record(1203), "link"),
        ("move", "transaction_ids", [Record(1204)], "link"),
        (
            "move",
            "authorized_transaction_ids",
            [Record(1205)],
            "link",
        ),
        ("move", "purchase_id", Record(1206), "link"),
        ("move", "asset_ids", [Record(1207)], "link"),
        ("move", "stock_move_ids", [Record(1208)], "link"),
        ("move", "landed_costs_ids", [Record(1209)], "link"),
        ("move", "debit_note_ids", [Record(1218)], "link"),
        ("move", "debit_origin_id", Record(1219), "link"),
        ("move", "invoice_pdf_report_id", Record(1220), "link"),
        ("move", "invoice_vendor_bill_id", Record(1221), "link"),
        ("move", "purchase_vendor_bill_id", Record(1222), "link"),
        ("move", "ubl_cii_xml_id", Record(1223), "link"),
        (
            "move",
            "l10n_es_edi_facturae_xml_id",
            Record(1224),
            "link",
        ),
        ("move", "signature", "signed-payload", "link"),
        ("move", "signing_user", Record(1225), "link"),
        ("move", "is_move_sent", True, "sending"),
        ("move", "sending_data", {"mail": "queued"}, "sending"),
        ("move", "is_being_sent", True, "sending"),
        (
            "move",
            "invoice_source_email",
            "invoice@example.com",
            "sending",
        ),
        ("move", "attachment_ids", [Record(1227)], "link"),
        ("move", "message_main_attachment_id", Record(1228), "link"),
        ("line", "payment_id", Record(1210), "external business effects"),
        ("line", "statement_id", Record(1211), "external business effects"),
        (
            "line",
            "purchase_order_id",
            Record(1212),
            "external business effects",
        ),
        (
            "line",
            "distribution_analytic_account_ids",
            [Record(1213)],
            "external business effects",
        ),
        (
            "line",
            "reconcile_model_id",
            Record(1214),
            "external business effects",
        ),
        (
            "line",
            "reconciled_lines_ids",
            [Record(1215)],
            "external business effects",
        ),
        (
            "line",
            "reconciled_lines_excluding_exchange_diff_ids",
            [Record(1216)],
            "external business effects",
        ),
        ("line", "cogs_origin_id", Record(1217), "external business effects"),
        ("line", "is_landed_costs_line", True, "external business effects"),
        (
            "line",
            "move_attachment_ids",
            [Record(1226)],
            "external business effects",
        ),
        ("line", "is_imported", True, "external business effects"),
        ("line", "is_downpayment", True, "external business effects"),
    ],
)
def test_draft_document_recovery_rejects_extended_live_effects(
    vendor, target, field, value, match
):
    move, line1, _line2, records_by_key, plan = (
        draft_move_recovery_fixture(vendor=vendor)
    )
    setattr(move if target == "move" else line1, field, value)
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


@pytest.mark.parametrize("vendor", [False, True])
def test_draft_document_recovery_allows_fingerprinted_audit_messages(vendor):
    move, line1, line2, records_by_key, _plan = draft_move_recovery_fixture(
        vendor=vendor
    )
    move.audit_trail_message_ids = [Record(1229)]
    move.snapshot_values["audit_trail_message_ids"] = [1229]
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[
            recovery_target("account.move.line", line1),
            recovery_target("account.move.line", line2),
        ],
        method=(
            "cancel_pristine_v3_draft_vendor_bill_v1"
            if vendor
            else "cancel_pristine_v3_draft_customer_invoice_v1"
        ),
        oracle_id=(
            "cancel_pristine_v3_draft_vendor_bill_exact_v1"
            if vendor
            else "cancel_pristine_v3_draft_customer_invoice_exact_v1"
        ),
    )
    handler = Harness(recovery_plan=plan, records=records_by_key)

    checked = handler.precheck_recovery(
        {
            "origin_operation_id": "op-1",
            "expected_recovery_plan_digest": plan["plan_digest"],
            "company_id": 7,
        },
        handler.test_company,
    )

    assert checked["before"]


def test_draft_document_recovery_rejects_forged_exact_line_outcome():
    move, line1, line2, records_by_key, _plan = draft_move_recovery_fixture()
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[
            recovery_target("account.move.line", line1),
            recovery_target("account.move.line", line2),
        ],
        expected_outcome="survive_exact",
    )
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match="exact invoice action/guard graph"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_cancel_pristine_v3_draft_customer_invoice_is_exact_and_auditable():
    move, line1, line2, records_by_key, plan = draft_move_recovery_fixture()
    write_checks = []

    class AccessHarness(Harness):
        def record(self, model_name, record_id, company, *, write=False, shared=False):
            write_checks.append((model_name, record_id, write))
            return super().record(
                model_name, record_id, company, write=write, shared=shared
            )

    handler = AccessHarness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
        "recovery_date": "2026-07-10",
        "reason": "undo duplicate draft",
    }
    checked = handler.precheck_recovery(parameters, handler.test_company)
    assert set((item["model"], item["record_id"]) for item in checked["before"]) == {
        ("account.move", 1101),
        ("account.move.line", 1102),
        ("account.move.line", 1103),
    }
    assert [
        (item["model"], item["record_id"])
        for item in checked["dependencies"]
    ] == [("account.journal", 2)]
    records, recovery = handler.execute_recovery(
        parameters, handler.test_company, checked
    )
    assert move.state == "cancel"
    assert move.writes == [{"state": "cancel"}]
    assert move.contexts == [{
        "tracking_disable": True,
        "skip_account_move_synchronization": True,
        "skip_invoice_sync": True,
        "skip_is_manually_modified": True,
    }]
    assert line1.snapshot_values["move_id"] == [
        1101,
        "Cancelled Invoice DRAFT-RECOVERY-1",
    ]
    assert line1.snapshot_values["parent_state"] == "cancel"
    assert {(model_name, record.id) for model_name, record in records} == {
        ("account.move", 1101),
        ("account.move.line", 1102),
        ("account.move.line", 1103),
    }
    assert recovery == {
        "status": "not_applicable",
        "method": "recovery_completed",
        "targets": [],
    }
    before = {
        (item["model"], item["record_id"]): item["values"]
        for item in checked["before"]
    }
    verification_checks = handler.verify_recovery(
        parameters, handler.test_company, records, before
    )
    assert "draft_customer_invoice_cancelled_exactly" in verification_checks
    assert (
        "line_guard_graph_matched_approved_allowed_delta"
        in verification_checks
    )
    assert ("account.move", 1101, True) in write_checks


def test_cancel_pristine_v3_draft_vendor_bill_is_exact_and_auditable():
    move, line1, line2, records_by_key, plan = draft_move_recovery_fixture(
        vendor=True
    )
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
        "recovery_date": "2026-07-10",
        "reason": "undo duplicate sandbox vendor bill",
    }

    checked = handler.precheck_recovery(parameters, handler.test_company)
    assert "single_v3_draft_vendor_bill" in checked["checks"]
    assert {
        (item["model"], item["record_id"])
        for item in checked["before"]
    } == {
        ("account.move", 1101),
        ("account.move.line", 1102),
        ("account.move.line", 1103),
    }
    assert [
        (item["model"], item["record_id"])
        for item in checked["dependencies"]
    ] == [("account.journal", 2)]

    records, recovery = handler.execute_recovery(
        parameters, handler.test_company, checked
    )

    assert move.state == "cancel"
    assert move.writes == [{"state": "cancel"}]
    assert line1.snapshot_values["move_id"] == [
        1101,
        "Cancelled Bill BILL-DRAFT-RECOVERY-1",
    ]
    assert line1.snapshot_values["parent_state"] == "cancel"
    assert {(model_name, record.id) for model_name, record in records} == {
        ("account.move", 1101),
        ("account.move.line", 1102),
        ("account.move.line", 1103),
    }
    assert recovery == {
        "status": "not_applicable",
        "method": "recovery_completed",
        "targets": [],
    }
    before = {
        (item["model"], item["record_id"]): item["values"]
        for item in checked["before"]
    }
    verification_checks = handler.verify_recovery(
        parameters, handler.test_company, records, before
    )
    assert "draft_vendor_bill_cancelled_exactly" in verification_checks
    assert (
        "line_guard_graph_matched_approved_allowed_delta"
        in verification_checks
    )


@pytest.mark.parametrize(
    ("target", "field", "value", "match"),
    [
        ("move", "write_uid", [99, "Other User"], "bound execution user"),
        ("line", "write_uid", [99, "Other User"], "bound execution user"),
        (
            "move",
            "write_date",
            "2026-07-10 08:59:59",
            "monotonic delta",
        ),
        ("line", "write_date", "not-a-date", "auditable Odoo datetime"),
        (
            "line",
            "write_date",
            "2026-07-10 09:02:00",
            "differ within the transaction",
        ),
        (
            "move",
            "create_date",
            "2026-07-10 09:00:01",
            "changed outside the approved",
        ),
    ],
)
def test_recovery_rejects_uncontrolled_log_access_delta(
    target, field, value, match
):
    move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    exact_write = move.write

    def write_with_log_access_drift(values):
        result = exact_write(values)
        record = move if target == "move" else line1
        record.snapshot_values[field] = value
        return result

    move.write = write_with_log_access_drift
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
    }
    checked = handler.precheck_recovery(parameters, handler.test_company)

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.execute_recovery(parameters, handler.test_company, checked)


def test_draft_vendor_bill_recovery_requires_purchase_journal_and_bill_type():
    move, _line1, _line2, records_by_key, plan = draft_move_recovery_fixture(
        vendor=True
    )
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
    }

    move.journal_id.type = "sale"
    with pytest.raises(OdooWriteHandlerError, match="active purchase journal"):
        handler.precheck_recovery(parameters, handler.test_company)

    move.journal_id.type = "purchase"
    move.move_type = "out_invoice"
    with pytest.raises(OdooWriteHandlerError, match="draft vendor bill"):
        handler.precheck_recovery(parameters, handler.test_company)


def test_draft_vendor_bill_recovery_rejects_purchase_link_and_incomplete_lines():
    move, line1, _line2, records_by_key, _plan = draft_move_recovery_fixture(
        vendor=True
    )
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[recovery_target("account.move.line", line1)],
        method="cancel_pristine_v3_draft_vendor_bill_v1",
        oracle_id="cancel_pristine_v3_draft_vendor_bill_exact_v1",
    )
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
    }
    with pytest.raises(OdooWriteHandlerError, match="complete line graph"):
        handler.precheck_recovery(parameters, handler.test_company)

    _move, line1, _line2, records_by_key, plan = (
        draft_move_recovery_fixture(vendor=True)
    )
    line1.purchase_line_id = Record(990)
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters["expected_recovery_plan_digest"] = plan["plan_digest"]
    with pytest.raises(OdooWriteHandlerError, match="external business effects"):
        handler.precheck_recovery(parameters, handler.test_company)


@pytest.mark.parametrize(
    ("target", "field", "value", "match"),
    [
        ("move", "stock_move_ids", [Record(990)], "linked payment"),
        ("move", "landed_costs_ids", [Record(991)], "linked payment"),
        ("line", "cogs_origin_id", Record(992), "external business effects"),
        ("line", "is_landed_costs_line", True, "external business effects"),
    ],
)
def test_draft_vendor_bill_recovery_rejects_stock_and_landed_cost_links(
    target, field, value, match
):
    move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture(
        vendor=True
    )
    setattr(move if target == "move" else line1, field, value)
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("move", "stock_move_ids"),
        ("move", "landed_costs_ids"),
        ("line", "cogs_origin_id"),
        ("line", "is_landed_costs_line"),
        ("line", "analytic_distribution"),
        ("line", "analytic_line_ids"),
        ("line", "tax_tag_ids"),
        ("line", "parent_state"),
    ],
)
def test_draft_vendor_bill_recovery_requires_auditable_stock_effect_fields(
    target, field
):
    move, line1, line2, records_by_key, _plan = draft_move_recovery_fixture(
        vendor=True
    )
    record = move if target == "move" else line1
    record.snapshot_values.pop(field)
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[
            recovery_target("account.move.line", line1),
            recovery_target("account.move.line", line2),
        ],
        method="cancel_pristine_v3_draft_vendor_bill_v1",
        oracle_id="cancel_pristine_v3_draft_vendor_bill_exact_v1",
    )

    class RequiredFieldHarness(Harness):
        def snapshot(self, model, current, company, *, required_fields=()):
            missing = set(required_fields) - set(current.snapshot_values)
            if missing:
                raise OdooWriteHandlerError(
                    f"{model} is missing required auditable fields: "
                    + ", ".join(sorted(missing))
                )
            return super().snapshot(
                model,
                current,
                company,
                required_fields=required_fields,
            )

    handler = RequiredFieldHarness(
        recovery_plan=plan, records=records_by_key
    )
    with pytest.raises(
        OdooWriteHandlerError, match="missing required auditable fields"
    ):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


@pytest.mark.parametrize(
    ("target", "field", "value", "match"),
    [
        ("move", "stock_move_ids", [990], "action target fingerprint"),
        ("move", "landed_costs_ids", [991], "action target fingerprint"),
        ("line", "cogs_origin_id", 992, "guard fingerprint"),
        ("line", "is_landed_costs_line", True, "guard fingerprint"),
        ("line", "analytic_distribution", {"17": 100}, "guard fingerprint"),
        ("line", "analytic_line_ids", [993], "guard fingerprint"),
        ("line", "tax_tag_ids", [994], "guard fingerprint"),
        ("line", "group_tax_id", 995, "guard fingerprint"),
        ("line", "parent_id", 996, "guard fingerprint"),
        ("move", "closing_return_id", 997, "action target fingerprint"),
        ("move", "transaction_ids", [998], "action target fingerprint"),
        ("move", "audit_trail_message_ids", [999], "action target fingerprint"),
        ("move", "fiscal_position_id", 1000, "action target fingerprint"),
        (
            "move",
            "invoice_cash_rounding_id",
            1001,
            "action target fingerprint",
        ),
        ("move", "invoice_incoterm_id", 1002, "action target fingerprint"),
        ("move", "incoterm_location", "Port", "action target fingerprint"),
        ("move", "partner_shipping_id", 1003, "action target fingerprint"),
        ("move", "partner_bank_id", 1004, "action target fingerprint"),
        (
            "move",
            "preferred_payment_method_line_id",
            1005,
            "action target fingerprint",
        ),
        (
            "move",
            "l10n_latam_document_type_id",
            1006,
            "action target fingerprint",
        ),
        ("move", "invoice_origin", "SO001", "action target fingerprint"),
        ("move", "narration", "note", "action target fingerprint"),
        (
            "move",
            "quick_edit_total_amount",
            "1",
            "action target fingerprint",
        ),
        ("move", "always_tax_exigible", True, "action target fingerprint"),
        ("move", "is_storno", True, "action target fingerprint"),
        ("line", "sequence", 99, "guard fingerprint"),
        ("line", "product_uom_id", 1007, "guard fingerprint"),
        ("line", "discount", "5", "guard fingerprint"),
        ("line", "discount_date", "2026-07-11", "guard fingerprint"),
        (
            "line",
            "discount_amount_currency",
            "5",
            "guard fingerprint",
        ),
        ("line", "discount_balance", "5", "guard fingerprint"),
        ("line", "tax_base_amount", "1", "guard fingerprint"),
        ("line", "extra_tax_data", {"tax": 1}, "guard fingerprint"),
        ("line", "deductible_amount", "1", "guard fingerprint"),
        ("line", "is_storno", True, "guard fingerprint"),
        (
            "line",
            "l10n_latam_document_type_id",
            1008,
            "guard fingerprint",
        ),
    ],
)
def test_draft_vendor_bill_recovery_binds_stock_effect_fields_to_approval(
    target, field, value, match
):
    move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture(
        vendor=True
    )
    record = move if target == "move" else line1
    record.snapshot_values[field] = value
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


@pytest.mark.parametrize("vendor", [False, True])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("analytic_distribution", {"17": 100}),
        ("analytic_line_ids", [Record(995)]),
    ],
)
def test_draft_document_recovery_rejects_unapproved_analytic_effects(
    vendor, field, value
):
    _move, line1, _line2, records_by_key, plan = (
        draft_move_recovery_fixture(vendor=vendor)
    )
    setattr(line1, field, value)
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match="external business effects"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_draft_vendor_bill_recovery_rejects_non_state_post_write_drift():
    move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture(
        vendor=True
    )
    exact_write = move.write

    def write_with_line_drift(values):
        result = exact_write(values)
        line1.snapshot_values["debit"] = "99"
        return result

    move.write = write_with_line_drift
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
    }
    checked = handler.precheck_recovery(parameters, handler.test_company)

    with pytest.raises(OdooWriteHandlerError, match="guard line graph changed"):
        handler.execute_recovery(parameters, handler.test_company, checked)


@pytest.mark.parametrize(
    ("target", "field", "value", "match"),
    [
        (
            "move",
            "invoice_user_id",
            [999, "Unauthorized Salesperson"],
            "graph changed",
        ),
        ("move", "message_ids", [999], "graph changed"),
        ("line", "no_followup", True, "guard line graph changed"),
    ],
)
def test_recovery_rejects_unapproved_material_write_override_drift(
    target, field, value, match
):
    move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    exact_write = move.write

    def write_with_material_drift(values):
        result = exact_write(values)
        record = move if target == "move" else line1
        record.snapshot_values[field] = value
        return result

    move.write = write_with_material_drift
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
    }
    checked = handler.precheck_recovery(parameters, handler.test_company)

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.execute_recovery(parameters, handler.test_company, checked)


def test_recovery_rejects_write_override_side_effects_before_business_commit():
    move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    exact_write = move.write

    def write_with_side_effect(values):
        result = exact_write(values)
        line1.reconciled = True
        return result

    move.write = write_with_side_effect
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
        "recovery_date": "2026-07-10",
        "reason": "undo duplicate draft",
    }
    checked = handler.precheck_recovery(parameters, handler.test_company)

    with pytest.raises(OdooWriteHandlerError, match="external business effects"):
        handler.execute_recovery(parameters, handler.test_company, checked)


def test_recovery_rejects_a_line_reparent_hidden_in_the_post_write_snapshot():
    move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    exact_write = move.write

    def write_with_reparented_snapshot(values):
        result = exact_write(values)
        line1.snapshot_values["move_id"] = [9999, "Other Move"]
        return result

    move.write = write_with_reparented_snapshot
    handler = Harness(recovery_plan=plan, records=records_by_key)
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
        "recovery_date": "2026-07-10",
        "reason": "undo duplicate draft",
    }
    checked = handler.precheck_recovery(parameters, handler.test_company)

    with pytest.raises(OdooWriteHandlerError, match="guard line graph changed"):
        handler.execute_recovery(parameters, handler.test_company, checked)


def test_cancel_draft_recovery_rejects_incomplete_line_guard_closure():
    move, line1, _line2, records_by_key, _plan = draft_move_recovery_fixture()
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[recovery_target("account.move.line", line1)],
    )
    handler = Harness(recovery_plan=plan, records=records_by_key)
    with pytest.raises(OdooWriteHandlerError, match="guard.*complete line graph"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("posted_before", True, "pristine"),
        ("move_type", "in_invoice", "pristine"),
        ("odoo_cli_v3_document_binding", "", "immutable V3"),
        ("payment_ids", [Record(991)], "linked payment"),
        ("adjusting_entry_origin_move_ids", [Record(992)], "linked payment"),
        ("adjusting_entries_move_ids", [Record(993)], "linked payment"),
        ("exchange_diff_partial_ids", [Record(994)], "linked payment"),
    ],
)
def test_draft_customer_invoice_recovery_rejects_prior_or_external_effects(
    field, value, match
):
    move, _line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    setattr(move, field, value)
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_draft_customer_invoice_recovery_rejects_live_line_fingerprint_drift():
    _move, line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    line1.snapshot_values["debit"] = "99"
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match="guard fingerprint changed"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_draft_customer_invoice_recovery_rejects_live_action_fingerprint_drift():
    move, _line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    move.snapshot_values["ref"] = "CHANGED-AFTER-APPROVAL"
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match="action target fingerprint changed"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_draft_customer_invoice_recovery_is_never_executable_in_production():
    _move, _line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    handler = Harness(
        recovery_plan=plan,
        records=records_by_key,
        environment="production",
    )

    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_draft_vendor_bill_recovery_is_never_executable_in_production():
    _move, _line1, _line2, records_by_key, plan = (
        draft_move_recovery_fixture(vendor=True)
    )
    handler = Harness(
        recovery_plan=plan,
        records=records_by_key,
        environment="production",
    )

    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


@pytest.mark.parametrize(
    ("method", "oracle_id"),
    [
        (
            "cancel_pristine_v3_draft_vendor_bill_v1",
            "cancel_pristine_v3_draft_customer_invoice_exact_v1",
        ),
        (
            "cancel_pristine_v3_draft_customer_invoice_v1",
            "cancel_pristine_v3_draft_vendor_bill_exact_v1",
        ),
    ],
)
def test_customer_and_vendor_recovery_method_oracle_pairs_cannot_be_crossed(
    method, oracle_id
):
    move, line1, line2, records_by_key, _plan = (
        draft_move_recovery_fixture(vendor=True)
    )
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[
            recovery_target("account.move.line", line1),
            recovery_target("account.move.line", line2),
        ],
        method=method,
        oracle_id=oracle_id,
    )
    handler = Harness(recovery_plan=plan, records=records_by_key)

    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_every_advertised_available_recovery_method_has_an_execute_allowlist_branch():
    assert _RECOVERY_ACTIONS == {
        "cancel_and_unreconcile_payment_v1",
        "cancel_asset_and_reverse_schedule_v1",
        "cancel_draft_period_adjustment_v1",
        "cancel_draft_refund_v1",
        "cancel_pristine_v3_draft_customer_invoice_v1",
        "cancel_pristine_v3_draft_vendor_bill_v1",
        "cancel_scheduled_and_reverse_accrual_origin_v1",
        "post_compensating_bank_statement_v1",
        "reverse_deferred_source_and_schedule_v1",
        "reverse_depreciation_and_restore_schedule_v1",
        "reverse_posted_customer_invoice_v1",
        "reverse_posted_period_adjustment_v1",
        "reverse_posted_refund_v1",
        "reverse_posted_vendor_bill_v1",
        "reverse_the_reversal_v1",
        "undo_reconciliation_and_reverse_writeoff_v1",
    }


def test_payment_and_posted_reversal_recovery_remain_fail_closed():
    payment = Record(1201, state="paid", company_id=Record(7))
    guard = Record(1202, state="posted", company_id=Record(7))
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.payment", payment)],
        guard_records=[recovery_target("account.move", guard)],
        method="cancel_payment",
        oracle_id="cancel_payment_unverified",
    )
    handler = Harness(
        recovery_plan=plan,
        records={
            ("account.payment", payment.id): payment,
            ("account.move", guard.id): guard,
        },
    )
    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-1",
                "expected_recovery_plan_digest": plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_bank_recovery_is_not_executable_until_precise_compensation_exists():
    bank_line = Record(1301, company_id=Record(7), is_reconciled=True)
    guard = Record(1300, company_id=Record(7), state="posted")
    bank_plan = executable_recovery_plan(
        origin_operation_id="op-bank",
        action_targets=[
            recovery_target("account.bank.statement.line", bank_line)
        ],
        guard_records=[recovery_target("account.move", guard)],
        method="undo_bank_reconciliation",
        oracle_id="bank_recovery_unverified",
    )
    handler = Harness(
        recovery_plan=bank_plan, records={
            ("account.bank.statement.line", 1301): bank_line,
            ("account.move", 1300): guard,
        },
    )

    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-bank",
                "expected_recovery_plan_digest": bank_plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_asset_recovery_is_closed_until_full_schedule_compensation_is_verified():
    asset = Record(1302, company_id=Record(7), state="open")
    guard = Record(1303, company_id=Record(7), state="posted")
    asset_plan = executable_recovery_plan(
        origin_operation_id="op-asset",
        action_targets=[recovery_target("account.asset", asset)],
        guard_records=[recovery_target("account.move", guard)],
        method="cancel_asset",
        oracle_id="asset_recovery_unverified",
    )
    handler = Harness(
        recovery_plan=asset_plan,
        records={
            ("account.asset", 1302): asset,
            ("account.move", 1303): guard,
        },
    )
    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            {
                "origin_operation_id": "op-asset",
                "expected_recovery_plan_digest": asset_plan["plan_digest"],
                "company_id": 7,
            },
            handler.test_company,
        )


def test_recovery_precheck_rejects_user_when_trusted_plan_is_missing_or_action_not_allowlisted():
    handler = Harness(recovery_plan=None)
    with pytest.raises(OdooWriteHandlerError, match="unavailable"):
        handler.precheck_recovery(
            {"origin_operation_id": "op-1", "expected_recovery_plan_digest": "a" * 64, "company_id": 7},
            handler.test_company,
        )
    move = Record(1, company_id=Record(7), state="draft")
    guard = Record(2, company_id=Record(7), state="unknown")
    plan = executable_recovery_plan(
        action_targets=[recovery_target("account.move", move)],
        guard_records=[recovery_target("account.move.line", guard)],
        method="unlink_anything",
        oracle_id="untrusted_oracle",
    )
    handler = Harness(
        recovery_plan=plan,
        records={
            ("account.move", 1): move,
            ("account.move.line", 2): guard,
        },
    )
    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            {"origin_operation_id": "op-1", "expected_recovery_plan_digest": plan["plan_digest"], "company_id": 7},
            handler.test_company,
        )


def test_recovery_precheck_rejects_tampering_before_closed_oracle_gate():
    _move, _line1, _line2, records_by_key, plan = draft_move_recovery_fixture()
    parameters = {
        "origin_operation_id": "op-1",
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": 7,
    }
    tampered = {
        **plan,
        "action_targets": [
            {**plan["action_targets"][0], "record_fingerprint": "f" * 64}
        ],
    }
    handler = Harness(recovery_plan=tampered, records=records_by_key)
    with pytest.raises(OdooWriteHandlerError, match="not executable"):
        handler.precheck_recovery(parameters, handler.test_company)


def existing_document_create_parameters(*, vendor=False):
    result = {
        "company_id": 7,
        "partner_id": 10,
        "invoice_date": "2026-07-10",
        "accounting_date": "2026-07-10",
        "due_date": "2026-08-10",
        "currency_id": 1,
        "journal_id": 2,
        "posting_mode": "draft",
        "lines": [
            {
                "line_reference": "line-1",
                "name": "Invoice line",
                "product_id": None,
                "account_id": 10,
                "quantity": "1",
                "price_unit": "100",
                "tax_ids": [],
            }
        ],
        "idempotency_key": (
            "create-existing-vendor-bill-1101"
            if vendor
            else "create-existing-customer-invoice-1101"
        ),
    }
    result["vendor_reference" if vendor else "reference"] = (
        "BILL-DRAFT-RECOVERY-1" if vendor else "DRAFT-RECOVERY-1"
    )
    return result


def existing_document_post_parameters(*, vendor=False):
    source = existing_document_create_parameters(vendor=vendor)
    kind = "vendor_bill" if vendor else "customer_invoice"
    return {
        "company_id": 7,
        "move_id": 1101,
        "expected_move_type": "in_invoice" if vendor else "out_invoice",
        "expected_document_binding": OdooWriteHandlers.document_binding(
            kind, source
        ),
        "expected_business_binding": OdooWriteHandlers.business_binding(
            kind, source
        ),
        "expected_partner_id": 10,
        "expected_journal_id": 2,
        "expected_currency_id": 1,
        "expected_invoice_date": "2026-07-10",
        "expected_accounting_date": "2026-07-10",
        "expected_due_date": "2026-08-10",
        "expected_reference": (
            "BILL-DRAFT-RECOVERY-1" if vendor else "DRAFT-RECOVERY-1"
        ),
        "expected_amount_untaxed": "100",
        "expected_amount_tax": "0",
        "expected_amount_total": "100",
        "expected_amount_residual": "100",
        "expected_line_ids": [1102, 1103],
        "reason": "Approved existing V3 document posting",
        "idempotency_key": (
            "post-existing-vendor-bill-1101"
            if vendor
            else "post-existing-customer-invoice-1101"
        ),
    }


def test_document_graph_reconstruction_uses_the_same_canonical_order_as_eligibility():
    lines = [
        Record(
            1104,
            odoo_cli_v3_line_reference="line-b",
            name="Second source line",
            account_id=Record(10),
            product_id=False,
            quantity=1,
            price_unit=20,
            tax_ids=[Record(4), Record(3)],
        ),
        Record(
            1102,
            odoo_cli_v3_line_reference="line-a",
            name="First source line",
            account_id=Record(11),
            product_id=False,
            quantity=2,
            price_unit=10,
            tax_ids=[],
        ),
    ]

    binding_lines, dependency_lines = Harness()._create_document_lines_from_graph(
        lines,
        include_product_in_binding=True,
    )

    assert [line["line_reference"] for line in binding_lines] == [
        "line-a",
        "line-b",
    ]
    assert [line["line_reference"] for line in dependency_lines] == [
        "line-a",
        "line-b",
    ]
    assert binding_lines[1]["tax_ids"] == [3, 4]


def existing_document_post_fixture(*, vendor=False):
    move, line1, line2, records, _plan = draft_move_recovery_fixture(
        vendor=vendor
    )
    currency = move.currency_id
    partner = Record(
        10,
        active=True,
        company_id=None,
        company_ids=[],
        customer_rank=0,
        supplier_rank=0,
        create_uid=Record(42),
        create_date="2026-07-10 09:00:00",
        write_uid=Record(42),
        write_date="2026-07-10 09:00:00",
    )
    partner.commercial_partner_id = partner
    partner.snapshot_values = {
        "active": True,
        "company_id": False,
        "company_ids": [],
        "commercial_partner_id": [10, "Test Partner"],
        "customer_rank": 0,
        "supplier_rank": 0,
        "create_uid": [42, "V3 Executor"],
        "create_date": "2026-07-10 09:00:00",
        "write_uid": [42, "V3 Executor"],
        "write_date": "2026-07-10 09:00:00",
    }
    move.partner_id = partner
    move.commercial_partner_id = partner
    move.date = "2026-07-10"
    move.amount_untaxed = 100
    move.amount_tax = 0
    move.snapshot_values.update(
        {
            "partner_id": 10,
            "commercial_partner_id": [10, "Test Partner"],
            "date": "2026-07-10",
            "amount_untaxed": "100",
            "amount_tax": "0",
        }
    )
    parameters = existing_document_post_parameters(vendor=vendor)
    move.odoo_cli_v3_document_binding = parameters[
        "expected_document_binding"
    ]
    move.odoo_cli_v3_business_binding = parameters[
        "expected_business_binding"
    ]
    move.snapshot_values.update(
        {
            "odoo_cli_v3_document_binding": move.odoo_cli_v3_document_binding,
            "odoo_cli_v3_business_binding": move.odoo_cli_v3_business_binding,
        }
    )
    for line, account_id, debit, credit in (
        (line1, 10, 100, 0),
        (line2, 20, 0, 100),
    ):
        line.account_id = Record(
            account_id,
            company_ids=[Record(7)],
            deprecated=False,
            account_type=(
                "expense"
                if vendor and line is line1
                else (
                    "liability_payable"
                    if vendor and line is line2
                    else (
                    "asset_receivable"
                    if not vendor and line is line2
                    else "income"
                    )
                )
            ),
        )
        line.currency_id = currency
        line.debit = debit
        line.credit = credit
        line.balance = debit - credit
        line.amount_currency = debit - credit
        line.deductible_amount = 100
        line.snapshot_values["deductible_amount"] = "100"
        if line is line1:
            line.price_subtotal = 100
            line.price_total = 100
        line.odoo_cli_v3_line_reference = line.snapshot_values[
            "odoo_cli_v3_line_reference"
        ]
    records[("res.partner", 10)] = partner
    records[("account.journal", 2)] = move.journal_id
    records[("account.account", 10)] = line1.account_id
    records[("account.account", 20)] = line2.account_id
    records[("res.currency", 1)] = currency
    return company(currency_id=currency), move, line1, line2, records


def install_exact_existing_document_post(
    move, lines, *, unexpected_reference_drift=False
):
    def action_post():
        move.action_post_calls += 1
        move.state = "posted"
        move.name = "BILL/2026/0001" if move.move_type == "in_invoice" else "INV/2026/0001"
        move.posted_before = True
        move.sequence_prefix = (
            "BILL/2026/" if move.move_type == "in_invoice" else "INV/2026/"
        )
        move.sequence_number = 1
        move.checked = True
        move.write_uid = Record(42)
        move.write_date = "2026-07-10 09:01:00"
        move.snapshot_values.update(
            {
                "state": "posted",
                "name": move.name,
                "posted_before": True,
                "sequence_prefix": move.sequence_prefix,
                "sequence_number": 1,
                "checked": True,
                "write_uid": [42, "V3 Executor"],
                "write_date": "2026-07-10 09:01:00",
            }
        )
        if unexpected_reference_drift:
            move.ref = "UNAPPROVED-POSTING-DRIFT"
            move.snapshot_values["ref"] = move.ref
        for line in lines:
            line.parent_state = "posted"
            line.write_uid = Record(42)
            line.write_date = "2026-07-10 09:01:00"
            line.snapshot_values.update(
                {
                    "move_id": [move.id, move.name],
                    "parent_state": "posted",
                    "write_uid": [42, "V3 Executor"],
                    "write_date": "2026-07-10 09:01:00",
                }
            )
        rank_field = (
            "supplier_rank"
            if move.move_type == "in_invoice"
            else "customer_rank"
        )
        posting_partners = {
            move.partner_id.id: move.partner_id,
            move.partner_id.commercial_partner_id.id: (
                move.partner_id.commercial_partner_id
            ),
        }
        for partner in posting_partners.values():
            setattr(partner, rank_field, getattr(partner, rank_field) + 1)
            partner.write_uid = Record(42)
            partner.write_date = "2026-07-10 09:01:00"
            partner.snapshot_values.update(
                {
                    rank_field: getattr(partner, rank_field),
                    "write_uid": [42, "V3 Executor"],
                    "write_date": "2026-07-10 09:01:00",
                }
            )
        return False

    move.action_post = action_post


def _rekey_document_graph(move, lines, *, move_id, line_ids):
    move.id = move_id
    move.ids = [move_id]
    for line, line_id in zip(lines, line_ids, strict=True):
        line.id = line_id
        line.ids = [line_id]
        line.move_id = move
        line.snapshot_values["move_id"] = [move_id, str(move.name)]
    move.line_ids = list(lines)
    move.invoice_line_ids = [lines[0]]
    move.snapshot_values["line_ids"] = list(line_ids)
    move.snapshot_values["journal_line_ids"] = list(line_ids)
    move.snapshot_values["invoice_line_ids"] = [line_ids[0]]


def refund_create_source_parameters(*, vendor=False):
    return {
        "company_id": 7,
        "origin_move_id": 1401,
        "refund_type": (
            "vendor_debit_note" if vendor else "customer_credit_note"
        ),
        "refund_mode": "full",
        "refund_date": "2026-07-10",
        "journal_id": 2,
        "currency_id": 1,
        "expected_total_amount": "100",
        "reason": "Duplicate refund",
        "posting_mode": "draft",
        "lines": [],
        "idempotency_key": (
            "create-vendor-refund-1301"
            if vendor
            else "create-customer-refund-1301"
        ),
    }


def refund_draft_cancel_parameters(*, vendor=False):
    refund_source = refund_create_source_parameters(vendor=vendor)
    origin_source = existing_document_create_parameters(vendor=vendor)
    origin_kind = "vendor_bill" if vendor else "customer_invoice"
    return {
        "company_id": 7,
        "move_id": 1301,
        "expected_move_type": "in_refund" if vendor else "out_refund",
        "expected_origin_move_id": 1401,
        "expected_document_binding": OdooWriteHandlers.document_binding(
            "refund", refund_source
        ),
        "expected_business_binding": OdooWriteHandlers.business_binding(
            "refund", refund_source
        ),
        "expected_origin_document_binding": OdooWriteHandlers.document_binding(
            origin_kind, origin_source
        ),
        "expected_origin_business_binding": OdooWriteHandlers.business_binding(
            origin_kind, origin_source
        ),
        "expected_partner_id": 10,
        "expected_journal_id": 2,
        "expected_currency_id": 1,
        "expected_refund_date": "2026-07-10",
        "expected_total_amount": "100",
        "expected_line_ids": [1302, 1303],
        "expected_origin_line_ids": [1402, 1403],
        "reason": "Cancel duplicate pristine draft refund",
        "idempotency_key": (
            "cancel-vendor-refund-1301"
            if vendor
            else "cancel-customer-refund-1301"
        ),
    }


def refund_draft_cancel_fixture(*, vendor=False):
    refund, refund_line1, refund_line2, _records, _plan = (
        draft_move_recovery_fixture(vendor=vendor)
    )
    origin, origin_line1, origin_line2, _origin_records, _origin_plan = (
        draft_move_recovery_fixture(vendor=vendor)
    )
    refund_lines = [refund_line1, refund_line2]
    origin_lines = [origin_line1, origin_line2]
    _rekey_document_graph(
        refund, refund_lines, move_id=1301, line_ids=[1302, 1303]
    )
    _rekey_document_graph(
        origin, origin_lines, move_id=1401, line_ids=[1402, 1403]
    )
    currency = refund.currency_id
    partner = Record(10, active=True)
    for move in (refund, origin):
        move.partner_id = partner
        move.date = "2026-07-10"
        move.amount_untaxed = 100
        move.amount_tax = 0
        move.snapshot_values.update(
            {
                "partner_id": 10,
                "date": "2026-07-10",
                "amount_untaxed": "100",
                "amount_tax": "0",
            }
        )
    refund.invoice_date_due = "2026-07-10"
    refund.snapshot_values["invoice_date_due"] = "2026-07-10"
    refund.move_type = "in_refund" if vendor else "out_refund"
    parameters = refund_draft_cancel_parameters(vendor=vendor)
    refund.odoo_cli_v3_reason = "Duplicate refund"
    refund.odoo_cli_v3_document_binding = parameters[
        "expected_document_binding"
    ]
    refund.odoo_cli_v3_business_binding = parameters[
        "expected_business_binding"
    ]
    refund.snapshot_values.update(
        {
            "move_type": refund.move_type,
            "odoo_cli_v3_reason": "Duplicate refund",
            "odoo_cli_v3_document_binding": (
                refund.odoo_cli_v3_document_binding
            ),
            "odoo_cli_v3_business_binding": (
                refund.odoo_cli_v3_business_binding
            ),
        }
    )
    origin.state = "posted"
    origin.name = "BILL/2026/0001" if vendor else "INV/2026/0001"
    origin.posted_before = True
    origin.sequence_prefix = "BILL/2026/" if vendor else "INV/2026/"
    origin.sequence_number = 1
    origin.checked = True
    origin.odoo_cli_v3_document_binding = parameters[
        "expected_origin_document_binding"
    ]
    origin.odoo_cli_v3_business_binding = parameters[
        "expected_origin_business_binding"
    ]
    origin.snapshot_values.update(
        {
            "state": "posted",
            "name": origin.name,
            "posted_before": True,
            "sequence_prefix": origin.sequence_prefix,
            "sequence_number": 1,
            "checked": True,
            "odoo_cli_v3_document_binding": (
                origin.odoo_cli_v3_document_binding
            ),
            "odoo_cli_v3_business_binding": (
                origin.odoo_cli_v3_business_binding
            ),
        }
    )
    refund.reversed_entry_id = origin
    refund.snapshot_values["reversed_entry_id"] = origin.id
    origin.reversal_move_ids = [refund]
    origin.snapshot_values["reversal_move_ids"] = [refund.id]
    for line in origin_lines:
        line.parent_state = "posted"
        line.snapshot_values["parent_state"] = "posted"
        line.snapshot_values["move_id"] = [origin.id, origin.name]
    origin_amounts = (
        ((100, 0), (0, 100))
        if vendor
        else ((0, 100), (100, 0))
    )
    refund_amounts = tuple(
        (credit, debit) for debit, credit in origin_amounts
    )
    for lines, amounts in (
        (origin_lines, origin_amounts),
        (refund_lines, refund_amounts),
    ):
        for line, account_id, (debit, credit) in zip(
            lines, (10, 20), amounts, strict=True
        ):
            line.account_id = Record(account_id, deprecated=False)
            line.account_id.account_type = (
                "expense"
                if vendor and line is lines[0]
                else (
                    "liability_payable"
                    if vendor and line is lines[1]
                    else (
                        "asset_receivable"
                        if not vendor and line is lines[1]
                        else "income"
                    )
                )
            )
            line.currency_id = currency
            line.debit = debit
            line.credit = credit
            line.balance = debit - credit
            line.amount_currency = debit - credit
            line.snapshot_values.update(
                {
                    "debit": str(debit),
                    "credit": str(credit),
                    "balance": str(debit - credit),
                    "amount_currency": str(debit - credit),
                }
            )
            if line is lines[0]:
                line.price_subtotal = 100
                line.price_total = 100
                line.snapshot_values.update(
                    {
                        "price_subtotal": "100",
                        "price_total": "100",
                    }
                )
            line.odoo_cli_v3_line_reference = line.snapshot_values[
                "odoo_cli_v3_line_reference"
            ]
    refund_line2.date_maturity = "2026-07-10"
    refund_line2.snapshot_values["date_maturity"] = "2026-07-10"
    refund.button_cancel = lambda: pytest.fail("button_cancel must not be called")
    refund.button_draft = lambda: pytest.fail("button_draft must not be called")
    refund.unlink = lambda: pytest.fail("unlink must not be called")
    records = {
        ("res.currency", 1): currency,
        ("res.partner", 10): partner,
        ("account.journal", 2): refund.journal_id,
        ("account.account", 10): refund_line1.account_id,
        ("account.account", 20): refund_line2.account_id,
        ("account.move", refund.id): refund,
        ("account.move.line", refund_line1.id): refund_line1,
        ("account.move.line", refund_line2.id): refund_line2,
        ("account.move", origin.id): origin,
        ("account.move.line", origin_line1.id): origin_line1,
        ("account.move.line", origin_line2.id): origin_line2,
    }
    return (
        company(currency_id=currency),
        refund,
        refund_lines,
        origin,
        origin_lines,
        records,
    )


@pytest.mark.parametrize(
    ("vendor", "capability_id"),
    (
        (False, "acct.invoice.customer_post.v1"),
        (True, "acct.bill.vendor_post.v1"),
    ),
)
def test_existing_v3_document_post_is_exact_and_verified(vendor, capability_id):
    comp, move, line1, line2, records = existing_document_post_fixture(
        vendor=vendor
    )
    install_exact_existing_document_post(move, [line1, line2])
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = existing_document_post_parameters(vendor=vendor)

    checked = handler.precheck(capability_id, parameters)
    execution = handler.execute_prechecked(
        capability_id, parameters, checked
    )
    verification = handler.verify(capability_id, parameters, execution)

    assert move.action_post_calls == 1
    assert move.state == "posted"
    assert verification["passed"] is True
    assert "existing_v3_document_posted_exactly" in verification["checks"]
    assert execution["recovery"] == {
        "status": "manual_escalation",
        "method": (
            "manual_review_vendor_bill_recovery"
            if vendor
            else "manual_review_customer_invoice_recovery"
        ),
        "targets": [{"model": "account.move", "record_id": 1101}],
    }


@pytest.mark.parametrize(
    ("vendor", "capability_id"),
    (
        (False, "acct.invoice.customer_post.v1"),
        (True, "acct.bill.vendor_post.v1"),
    ),
)
def test_document_post_handler_bootstrap_evidence_is_accepted_by_write_service(
    vendor, capability_id
):
    comp, move, line1, line2, records = existing_document_post_fixture(
        vendor=vendor
    )
    install_exact_existing_document_post(move, [line1, line2])
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = existing_document_post_parameters(vendor=vendor)
    checked = handler.precheck(capability_id, parameters)
    raw = handler.execute_prechecked(capability_id, parameters, checked)
    operation = SimpleNamespace(
        operation_id=f"op-{capability_id}",
        capability_id=capability_id,
        company_id=7,
        environment="sandbox",
        parameters=parameters,
    )

    evidence = _execution_evidence(operation, raw)
    records_by_key = {
        (record["model"], record["record_id"]): record
        for record in evidence["odoo_records"]
    }
    DurableWriteService._validate_difference_binding(
        evidence["difference"],
        operation=operation,
        allowed_models=_ALLOWED_MODELS[capability_id],
        records_by_key=records_by_key,
    )

    assert ("res.partner", 10) in records_by_key


@pytest.mark.parametrize(
    ("target", "field", "value"),
    (
        ("move", "edi_document_ids", [Record(1601)]),
        ("move", "auto_post", "at_date"),
        ("move", "purchase_id", Record(1602)),
        ("line", "reconciled", True),
        ("line", "sale_line_ids", [Record(1603)]),
    ),
)
def test_existing_v3_document_post_rejects_external_or_automated_graph(
    target, field, value
):
    comp, move, line1, _line2, records = existing_document_post_fixture()
    setattr(move if target == "move" else line1, field, value)
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError):
        handler.precheck(
            "acct.invoice.customer_post.v1",
            existing_document_post_parameters(),
        )


def test_existing_v3_document_post_rejects_pre_execution_and_action_drift():
    comp, move, line1, line2, records = existing_document_post_fixture()
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = existing_document_post_parameters()
    checked = handler.precheck("acct.invoice.customer_post.v1", parameters)
    move.ref = "CHANGED-AFTER-APPROVAL"
    move.snapshot_values["ref"] = move.ref

    with pytest.raises(
        OdooWriteHandlerError, match="approved|immutable binding"
    ):
        handler.execute_prechecked(
            "acct.invoice.customer_post.v1", parameters, checked
        )
    assert move.action_post_calls == 0

    comp, move, line1, line2, records = existing_document_post_fixture()
    install_exact_existing_document_post(
        move, [line1, line2], unexpected_reference_drift=True
    )
    handler = Harness(records=records)
    handler.test_company = comp
    checked = handler.precheck("acct.invoice.customer_post.v1", parameters)
    with pytest.raises(
        OdooWriteHandlerError, match="identity|posting allowlist"
    ):
        handler.execute_prechecked(
            "acct.invoice.customer_post.v1", parameters, checked
        )
    assert move.action_post_calls == 1


@pytest.mark.parametrize("vendor", (False, True))
def test_refund_draft_cancel_changes_only_the_refund_graph(vendor):
    comp, refund, refund_lines, origin, _origin_lines, records = (
        refund_draft_cancel_fixture(vendor=vendor)
    )
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = refund_draft_cancel_parameters(vendor=vendor)
    origin_snapshot = dict(origin.snapshot_values)

    checked = handler.precheck("acct.refund.draft_cancel.v1", parameters)
    assert len(checked["before"]) == 6
    execution = handler.execute_prechecked(
        "acct.refund.draft_cancel.v1", parameters, checked
    )
    verification = handler.verify(
        "acct.refund.draft_cancel.v1", parameters, execution
    )

    assert refund.writes == [{"state": "cancel"}]
    assert all(line.parent_state == "cancel" for line in refund_lines)
    assert origin.snapshot_values == origin_snapshot
    assert verification["passed"] is True
    assert "draft_refund_cancelled_exactly" in verification["checks"]
    assert "origin_document_graph_unchanged" in verification["checks"]
    assert execution["recovery"] == {
        "status": "not_applicable",
        "method": "refund_draft_cancel_completed",
        "targets": [],
    }


def test_refund_draft_cancel_accepts_origin_created_and_posted_directly():
    comp, _refund, _refund_lines, origin, _origin_lines, records = (
        refund_draft_cancel_fixture()
    )
    source = existing_document_create_parameters()
    source["posting_mode"] = "post"
    direct_post_binding = OdooWriteHandlers.document_binding(
        "customer_invoice", source
    )
    origin.odoo_cli_v3_document_binding = direct_post_binding
    origin.snapshot_values[
        "odoo_cli_v3_document_binding"
    ] = direct_post_binding
    parameters = refund_draft_cancel_parameters()
    parameters["expected_origin_document_binding"] = direct_post_binding
    handler = Harness(records=records)
    handler.test_company = comp

    checked = handler.precheck(
        "acct.refund.draft_cancel.v1", parameters
    )

    assert checked["before"]
    assert checked["dependencies"]


def test_refund_draft_cancel_rejects_full_refund_linewise_drift():
    comp, _refund, refund_lines, _origin, _origin_lines, records = (
        refund_draft_cancel_fixture()
    )
    refund_lines[0].balance += 1
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match="linewise reversal"):
        handler.precheck(
            "acct.refund.draft_cancel.v1",
            refund_draft_cancel_parameters(),
        )


def test_refund_draft_cancel_rejects_partial_refund_financial_graph_drift():
    comp, refund, refund_lines, _origin, _origin_lines, records = (
        refund_draft_cancel_fixture()
    )
    source = refund_create_source_parameters()
    source.update(
        {
            "refund_mode": "partial",
            "lines": [
                {
                    "line_reference": "line-1",
                    "name": "Invoice line",
                    "account_id": 10,
                    "quantity": "1",
                    "price_unit": "100",
                    "tax_ids": [],
                }
            ],
        }
    )
    parameters = refund_draft_cancel_parameters()
    parameters["expected_document_binding"] = (
        OdooWriteHandlers.document_binding("refund", source)
    )
    parameters["expected_business_binding"] = (
        OdooWriteHandlers.business_binding("refund", source)
    )
    refund.odoo_cli_v3_document_binding = parameters[
        "expected_document_binding"
    ]
    refund.odoo_cli_v3_business_binding = parameters[
        "expected_business_binding"
    ]
    refund.snapshot_values.update(
        {
            "odoo_cli_v3_document_binding": refund.odoo_cli_v3_document_binding,
            "odoo_cli_v3_business_binding": refund.odoo_cli_v3_business_binding,
        }
    )
    refund_lines[0].price_total = 99
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError,
        match="partial refund line total amount differs",
    ):
        handler.precheck("acct.refund.draft_cancel.v1", parameters)


@pytest.mark.parametrize(
    ("target", "field", "value", "error"),
    (
        ("refund", "edi_document_ids", [Record(1701)], "linked|external"),
        ("refund_line", "reconciled", True, "external"),
        ("origin", "reversal_move_ids", [], "origin"),
        ("origin", "payment_ids", [Record(1702)], "external"),
        ("origin_line", "matched_debit_ids", [Record(1703)], "external"),
    ),
)
def test_refund_draft_cancel_rejects_unsafe_or_unbound_graph(
    target, field, value, error
):
    comp, refund, refund_lines, origin, origin_lines, records = (
        refund_draft_cancel_fixture()
    )
    record = {
        "refund": refund,
        "refund_line": refund_lines[0],
        "origin": origin,
        "origin_line": origin_lines[0],
    }[target]
    setattr(record, field, value)
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match=error):
        handler.precheck(
            "acct.refund.draft_cancel.v1",
            refund_draft_cancel_parameters(),
        )


def test_refund_draft_cancel_rejects_origin_drift_before_write():
    comp, refund, _refund_lines, origin, _origin_lines, records = (
        refund_draft_cancel_fixture()
    )
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = refund_draft_cancel_parameters()
    checked = handler.precheck("acct.refund.draft_cancel.v1", parameters)
    origin.ref = "ORIGIN-CHANGED-AFTER-APPROVAL"
    origin.snapshot_values["ref"] = origin.ref

    with pytest.raises(
        OdooWriteHandlerError, match="approved|immutable binding"
    ):
        handler.execute_prechecked(
            "acct.refund.draft_cancel.v1", parameters, checked
        )
    assert refund.writes == []


class DenyTargetLineWriteHarness(Harness):
    def __init__(self, *, denied_line_id, **kwargs):
        super().__init__(**kwargs)
        self.denied_line_id = denied_line_id

    def record(
        self,
        model_name,
        record_id,
        company,
        *,
        write=False,
        shared=False,
    ):
        if (
            model_name == "account.move.line"
            and record_id == self.denied_line_id
            and write
        ):
            raise OdooWriteHandlerError(
                "account.move.line write ACL denied"
            )
        return super().record(
            model_name,
            record_id,
            company,
            write=write,
            shared=shared,
        )


def test_existing_document_post_requires_write_acl_on_every_target_line():
    comp, _move, _line1, _line2, records = (
        existing_document_post_fixture()
    )
    handler = DenyTargetLineWriteHarness(
        denied_line_id=1102, records=records
    )
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match="line write ACL denied"):
        handler.precheck(
            "acct.invoice.customer_post.v1",
            existing_document_post_parameters(),
        )


def test_refund_draft_cancel_requires_write_acl_on_every_refund_line():
    comp, _refund, _refund_lines, _origin, _origin_lines, records = (
        refund_draft_cancel_fixture()
    )
    handler = DenyTargetLineWriteHarness(
        denied_line_id=1302, records=records
    )
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match="line write ACL denied"):
        handler.precheck(
            "acct.refund.draft_cancel.v1",
            refund_draft_cancel_parameters(),
        )


class DenyDocumentDependencyHarness(Harness):
    def record(
        self,
        model_name,
        record_id,
        company,
        *,
        write=False,
        shared=False,
    ):
        if model_name == "account.account":
            raise OdooWriteHandlerError(
                "document dependency read ACL denied"
            )
        return super().record(
            model_name,
            record_id,
            company,
            write=write,
            shared=shared,
        )


@pytest.mark.parametrize("refund", (False, True))
def test_document_actions_require_read_acl_on_account_dependencies(refund):
    if refund:
        comp, _move, _lines, _origin, _origin_lines, records = (
            refund_draft_cancel_fixture()
        )
        capability_id = "acct.refund.draft_cancel.v1"
        parameters = refund_draft_cancel_parameters()
    else:
        comp, _move, _line1, _line2, records = (
            existing_document_post_fixture()
        )
        capability_id = "acct.invoice.customer_post.v1"
        parameters = existing_document_post_parameters()
    handler = DenyDocumentDependencyHarness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError, match="dependency read ACL denied"
    ):
        handler.precheck(capability_id, parameters)


def test_existing_document_post_rejects_graph_and_hash_rewrite():
    comp, move, line1, _line2, records = existing_document_post_fixture()
    forged_source = existing_document_create_parameters()
    forged_source["lines"][0]["price_unit"] = "90"
    line1.price_unit = 90
    move.odoo_cli_v3_document_binding = OdooWriteHandlers.document_binding(
        "customer_invoice", forged_source
    )
    move.snapshot_values[
        "odoo_cli_v3_document_binding"
    ] = move.odoo_cli_v3_document_binding
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError, match="cannot reproduce"
    ):
        handler.precheck(
            "acct.invoice.customer_post.v1",
            existing_document_post_parameters(),
        )


def test_existing_document_post_rejects_irreversible_decimal_lexeme():
    comp, move, _line1, _line2, records = existing_document_post_fixture()
    lexical_source = existing_document_create_parameters()
    lexical_source["lines"][0]["price_unit"] = "100.00"
    lexical_binding = OdooWriteHandlers.document_binding(
        "customer_invoice", lexical_source
    )
    move.odoo_cli_v3_document_binding = lexical_binding
    move.snapshot_values["odoo_cli_v3_document_binding"] = lexical_binding
    parameters = existing_document_post_parameters()
    parameters["expected_document_binding"] = lexical_binding
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError, match="cannot reproduce"
    ):
        handler.precheck("acct.invoice.customer_post.v1", parameters)


def test_refund_draft_cancel_rejects_irreversible_total_lexeme():
    comp, refund, _lines, _origin, _origin_lines, records = (
        refund_draft_cancel_fixture()
    )
    lexical_source = refund_create_source_parameters()
    lexical_source["expected_total_amount"] = "100.00"
    lexical_binding = OdooWriteHandlers.document_binding(
        "refund", lexical_source
    )
    refund.odoo_cli_v3_document_binding = lexical_binding
    refund.snapshot_values["odoo_cli_v3_document_binding"] = lexical_binding
    parameters = refund_draft_cancel_parameters()
    parameters["expected_document_binding"] = lexical_binding
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(
        OdooWriteHandlerError, match="unique immutable binding"
    ):
        handler.precheck("acct.refund.draft_cancel.v1", parameters)


@pytest.mark.parametrize("refund", (False, True))
def test_document_actions_reject_dependency_drift_after_precheck(refund):
    if refund:
        comp, move, _lines, _origin, _origin_lines, records = (
            refund_draft_cancel_fixture()
        )
        capability_id = "acct.refund.draft_cancel.v1"
        parameters = refund_draft_cancel_parameters()
    else:
        comp, move, _line1, _line2, records = (
            existing_document_post_fixture()
        )
        capability_id = "acct.invoice.customer_post.v1"
        parameters = existing_document_post_parameters()
    handler = Harness(records=records)
    handler.test_company = comp
    checked = handler.precheck(capability_id, parameters)
    records[("account.account", 10)].deprecated = True

    with pytest.raises(OdooWriteHandlerError, match="deprecated"):
        handler.execute_prechecked(capability_id, parameters, checked)
    if refund:
        assert move.writes == []
    else:
        assert move.action_post_calls == 0


def test_existing_document_post_handler_rejects_zero_value_graph():
    comp, move, line1, line2, records = existing_document_post_fixture()
    source = existing_document_create_parameters()
    source["lines"][0]["price_unit"] = "0"
    binding = OdooWriteHandlers.document_binding(
        "customer_invoice", source
    )
    move.odoo_cli_v3_document_binding = binding
    move.snapshot_values["odoo_cli_v3_document_binding"] = binding
    move.amount_untaxed = 0
    move.amount_total = 0
    move.amount_residual = 0
    move.snapshot_values.update(
        {
            "amount_untaxed": "0",
            "amount_total": "0",
            "amount_residual": "0",
        }
    )
    line1.price_unit = 0
    line1.debit = 0
    line1.balance = 0
    line1.amount_currency = 0
    line2.credit = 0
    line2.balance = 0
    line2.amount_currency = 0
    parameters = existing_document_post_parameters()
    parameters.update(
        {
            "expected_document_binding": binding,
            "expected_amount_untaxed": "0",
            "expected_amount_total": "0",
            "expected_amount_residual": "0",
        }
    )
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match="must be positive"):
        handler._existing_document_post_graph(
            parameters, comp, vendor=False
        )


@pytest.mark.parametrize(
    ("target", "field", "value", "match"),
    (
        ("move", "partner_bank_id", Record(1901), "partner bank"),
        ("line", "matching_number", "I-import-batch", "reconciliation marker"),
        ("line", "partner_id", Record(1902), "line partner"),
        ("partner", "customer_rank", 1, "zero customer_rank"),
        (
            "partner",
            "commercial_partner_id",
            Record(1903),
            "selected partner to be its commercial partner",
        ),
    ),
)
def test_customer_invoice_post_rejects_unmodelled_odoo_side_effects(
    target, field, value, match
):
    comp, move, line1, _line2, records = existing_document_post_fixture()
    subject = {
        "move": move,
        "line": line1,
        "partner": move.partner_id,
    }[target]
    setattr(subject, field, value)
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match=match):
        handler.precheck(
            "acct.invoice.customer_post.v1",
            existing_document_post_parameters(),
        )


def test_vendor_bill_post_rejects_partial_deductibility_side_effect():
    comp, _move, line1, _line2, records = existing_document_post_fixture(
        vendor=True
    )
    line1.deductible_amount = 50
    handler = Harness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match="fully deductible"):
        handler.precheck(
            "acct.bill.vendor_post.v1",
            existing_document_post_parameters(vendor=True),
        )


def test_existing_document_post_requires_partner_write_acl():
    class DenyPartnerWriteHarness(Harness):
        def record(
            self,
            model_name,
            record_id,
            company,
            *,
            write=False,
            shared=False,
        ):
            if model_name == "res.partner" and write:
                raise OdooWriteHandlerError("partner write ACL denied")
            return super().record(
                model_name,
                record_id,
                company,
                write=write,
                shared=shared,
            )

    comp, _move, _line1, _line2, records = existing_document_post_fixture()
    handler = DenyPartnerWriteHarness(records=records)
    handler.test_company = comp

    with pytest.raises(OdooWriteHandlerError, match="partner write ACL denied"):
        handler.precheck(
            "acct.invoice.customer_post.v1",
            existing_document_post_parameters(),
        )


def test_existing_document_post_rejects_unexpected_partner_rank_delta():
    comp, move, line1, line2, records = existing_document_post_fixture()
    install_exact_existing_document_post(move, [line1, line2])
    exact_action_post = move.action_post

    def action_post_with_rank_drift():
        result = exact_action_post()
        move.partner_id.customer_rank = 2
        move.partner_id.snapshot_values["customer_rank"] = 2
        return result

    move.action_post = action_post_with_rank_drift
    handler = Harness(records=records)
    handler.test_company = comp
    parameters = existing_document_post_parameters()
    checked = handler.precheck("acct.invoice.customer_post.v1", parameters)

    with pytest.raises(OdooWriteHandlerError, match="rank side effect"):
        handler.execute_prechecked(
            "acct.invoice.customer_post.v1",
            parameters,
            checked,
        )

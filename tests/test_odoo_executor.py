import hashlib
import json
import unittest
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest import mock

from odoo_accounting_cli_v3.domain.ar_open_items import (
    CurrencyInfo as ArCurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
)
from odoo_accounting_cli_v3.domain.multicompany_consolidated import (
    CompanyAccountLedgerAggregate as MulticompanyLedgerAggregate,
    CurrencyInfo as MulticompanyCurrencyInfo,
    TechnicalRateSource as MulticompanyTechnicalRateSource,
    TranslationRate as MulticompanyTranslationRate,
)
from odoo_accounting_cli_v3.domain.multicurrency_balance import (
    AccountInfo as MulticurrencyAccountInfo,
    BalanceAggregate,
    CurrencyInfo as MulticurrencyCurrencyInfo,
    EffectiveRate,
    TechnicalRateSource,
)
from odoo_accounting_cli_v3.domain.report_read import (
    CurrencyInfo as ReportCurrencyInfo,
    NativeReportColumn,
    NativeReportDefinitionBinding,
    NativeReportFilters,
    NativeReportLine,
    NativeReportPeriod,
    NativeReportSnapshot,
    canonical_period_key,
)
from odoo_accounting_cli_v3.domain.trial_balance import AccountInfo, Aggregate, CurrencyInfo
from odoo_accounting_cli_v3.contracts import validate_value
from odoo_accounting_cli_v3.draft_invoice_recovery import (
    customer_invoice_business_binding,
    customer_invoice_document_binding,
    customer_invoice_document_binding_v2,
    vendor_bill_business_binding,
    vendor_bill_document_binding,
    vendor_bill_document_binding_v2,
)
from odoo_accounting_cli_v3.document_bindings import refund_document_binding_v2
from odoo_accounting_cli_v3.gateway import RequestContext
from odoo_accounting_cli_v3.odoo.executor import (
    _canonical_graph_decimal,
    _decimal as executor_decimal,
    OdooExecutionError,
    OdooReadExecutor,
)
from odoo_accounting_cli_v3.registry import Capability, validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)
RECEIPT_KEY_ID = "test-receipt-2026-07"


def test_executor_decimal_parsing_preserves_real_zero_and_long_precision():
    assert executor_decimal(0) == Decimal("0")
    assert executor_decimal(0.0) == Decimal("0.0")
    assert _canonical_graph_decimal(0.0, positive=False) == "0"
    assert _canonical_graph_decimal(
        "12345678901234567890123456780",
        positive=False,
    ) == "12345678901234567890123456780"
    assert _canonical_graph_decimal(
        "12345678901234567890123456781",
        positive=False,
    ) == "12345678901234567890123456781"


def report_definition_binding():
    return NativeReportDefinitionBinding(
        schema_version=1,
        definition_sha256="1" * 64,
        baseline_catalog_sha256="2" * 64,
        baseline_entry_sha256="3" * 64,
        source_candidate_sha256="4" * 64,
        approval_set_sha256="5" * 64,
        allowed_signers_sha256="6" * 64,
        revocations_sha256="7" * 64,
        oracle_contract_sha256="8" * 64,
        trust_envelope_sha256="9" * 64,
        binding_sha256="a" * 64,
        approvals_verified=True,
        revocations_checked=True,
        artifact_digests_verified=True,
        pre_matches_approved=True,
        post_matches_approved=True,
        same_transaction_snapshot_definition_equal=True,
    )


class Cursor:
    dbname = "odoo_test"


class User:
    def __init__(self, groups=None):
        self._groups = set(
            {"base.group_user", "account.group_account_readonly"}
            if groups is None
            else groups
        )

    def has_group(self, xml_id):
        return xml_id in self._groups


class Company:
    id = 7

    def __init__(self):
        self.access_checks = []
        self.account_storno = False
        self.currency_id = SimpleRecord(
            id=12,
            active=True,
            rounding="0.01",
        )

    def browse(self, company_id):
        if company_id != self.id:
            return MissingCompany()
        return self

    def exists(self):
        return self

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def check_access_rights(self, operation):
        self.access_checks.append(("rights", operation))

    def check_access_rule(self, operation):
        self.access_checks.append(("rule", operation))


class MissingCompany:
    def exists(self):
        return self

    def __bool__(self):
        return False

    def __len__(self):
        return 0


class SimpleRecord:
    def __init__(self, *, denied_operations=(), **values):
        self.__dict__.update(values)
        self.access_checks = []
        self.denied_operations = frozenset(denied_operations)

    def exists(self):
        return self

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def check_access_rights(self, operation):
        self.access_checks.append(("rights", operation))
        if operation in self.denied_operations:
            raise PermissionError(f"{operation} access denied")

    def check_access_rule(self, operation):
        self.access_checks.append(("rule", operation))
        if operation in self.denied_operations:
            raise PermissionError(f"{operation} access denied")


class RecordModel:
    def __init__(self, records, *, search_records=()):
        self._records = records
        self._search_records = list(search_records)
        self.access_checks = []

    def browse(self, record_id):
        return self._records.get(record_id, MissingCompany())

    def check_access_rights(self, operation):
        self.access_checks.append(("rights", operation))

    def search(self, _domain, limit=None):
        if limit is None:
            return list(self._search_records)
        return list(self._search_records[:limit])


class Environment:
    uid = 42
    su = False
    cr = Cursor()

    def __init__(self, groups=None):
        self.user = User(groups)
        self.company = Company()

    def __getitem__(self, name):
        if name != "res.company":
            raise AssertionError(f"unexpected model: {name}")
        return self.company


class DraftCancelEnvironment(Environment):
    def __init__(self, *, move=None, groups=None):
        super().__init__(groups=groups)
        self.move = move or document_post_move(
            self.company, id=1101
        )

    def __getitem__(self, name):
        if name == "res.company":
            return self.company
        if name == "account.move":
            return RecordModel({self.move.id: self.move})
        raise AssertionError(f"unexpected model: {name}")


class MoveEnvironment(Environment):
    def __init__(self, records, *, groups=None, external_effects=None):
        super().__init__(groups=groups)
        self.records = {record.id: record for record in records}
        self.external_effects = external_effects or {}

    def __getitem__(self, name):
        if name == "res.company":
            return self.company
        if name == "account.move":
            return RecordModel(
                self.records,
                search_records=self.external_effects.get(name, []),
            )
        if name == "account.partial.reconcile":
            return RecordModel(
                {},
                search_records=self.external_effects.get(name, []),
            )
        raise AssertionError(f"unexpected model: {name}")


def pristine_draft_move(company, *, move_type="out_invoice", state="draft", **overrides):
    move_id = overrides.pop("id", 1101)
    journal_type = "purchase" if move_type == "in_invoice" else "sale"
    journal = SimpleRecord(id=2201, company_id=company, type=journal_type, active=True)
    currency = SimpleRecord(id=12)
    line = SimpleRecord(
        id=3301,
        move_id=SimpleRecord(id=move_id),
        company_id=company,
        parent_state=state,
        reconciled=False,
    )
    values = {
        "id": move_id,
        "company_id": company,
        "move_type": move_type,
        "state": state,
        "name": "/",
        "posted_before": False,
        "auto_post": "no",
        "auto_post_until": False,
        "sequence_prefix": False,
        "sequence_number": False,
        "made_sequence_gap": False,
        "checked": False,
        "journal_id": journal,
        "currency_id": currency,
        "payment_state": "not_paid",
        "amount_residual": "100.00",
        "amount_total": "100.00",
        "secure_sequence_number": 0,
        "inalterable_hash": False,
        "need_cancel_request": False,
        "is_manually_modified": False,
        "line_ids": [line],
        "odoo_cli_v3_document_binding": "a" * 64,
        "odoo_cli_v3_business_binding": "b" * 64,
    }
    values.update(overrides)
    return SimpleRecord(**values)


def document_post_move(company, *, move_type="out_invoice", **overrides):
    move_id = overrides.pop("id", 4101)
    vendor = move_type == "in_invoice"
    currency = SimpleRecord(id=12, active=True, rounding="0.01")
    company.currency_id = currency
    partner = SimpleRecord(
        id=5101,
        company_id=company,
        active=True,
        customer_rank=0,
        supplier_rank=0,
    )
    partner.commercial_partner_id = partner
    journal = SimpleRecord(
        id=5201,
        company_id=company,
        type="purchase" if vendor else "sale",
        active=True,
        currency_id=currency,
    )
    invoice_account = SimpleRecord(
        id=5601,
        company_ids=[company],
        account_type="expense" if vendor else "income",
        deprecated=False,
    )
    term_account = SimpleRecord(
        id=5501,
        company_ids=[company],
        account_type="liability_payable" if vendor else "asset_receivable",
        deprecated=False,
    )
    invoice_line = SimpleRecord(
        id=5301,
        move_id=SimpleRecord(id=move_id),
        company_id=company,
        parent_state="draft",
        display_type="product",
        odoo_cli_v3_line_reference="line-1",
        name="Consulting",
        product_id=False,
        account_id=invoice_account,
        partner_id=partner,
        currency_id=currency,
        quantity="1",
        price_unit="100",
        price_subtotal="100",
        price_total="100",
        tax_ids=[],
        tax_line_id=False,
        debit="100" if vendor else "0",
        credit="0" if vendor else "100",
        balance="100" if vendor else "-100",
        amount_currency="100" if vendor else "-100",
        matching_number=False,
        deductible_amount="100",
        date_maturity=False,
        reconciled=False,
    )
    term_line = SimpleRecord(
        id=5302,
        move_id=SimpleRecord(id=move_id),
        company_id=company,
        parent_state="draft",
        display_type="payment_term",
        name="Payment term",
        product_id=False,
        account_id=term_account,
        partner_id=partner,
        currency_id=currency,
        tax_ids=[],
        tax_line_id=False,
        debit="0" if vendor else "100",
        credit="100" if vendor else "0",
        balance="-100" if vendor else "100",
        amount_currency="-100" if vendor else "100",
        amount_residual="-100" if vendor else "100",
        amount_residual_currency="-100" if vendor else "100",
        matching_number=False,
        deductible_amount="100",
        date_maturity=date(2026, 7, 13),
        reconciled=False,
    )
    lines = [invoice_line, term_line]
    values = {
        "id": move_id,
        "company_id": company,
        "move_type": move_type,
        "state": "draft",
        "name": "/",
        "posted_before": False,
        "auto_post": "no",
        "auto_post_until": False,
        "sequence_prefix": False,
        "sequence_number": False,
        "made_sequence_gap": False,
        "checked": False,
        "journal_id": journal,
        "currency_id": currency,
        "partner_id": partner,
        "commercial_partner_id": partner,
        "partner_bank_id": False,
        "invoice_date": date(2026, 7, 13),
        "date": date(2026, 7, 13),
        "invoice_date_due": date(2026, 7, 13),
        "ref": "V3-DOC-4101",
        "payment_state": "not_paid",
        "amount_untaxed": "100.00",
        "amount_tax": "0.00",
        "amount_total": "100.00",
        "amount_residual": "100.00",
        "secure_sequence_number": 0,
        "inalterable_hash": False,
        "need_cancel_request": False,
        "is_manually_modified": False,
        "line_ids": lines,
        "invoice_line_ids": [invoice_line],
        "_affect_tax_report": lambda: False,
        "_get_violated_lock_dates": lambda _date, _affects_tax: [],
    }
    graph_parameters = {
        "company_id": company.id,
        "partner_id": partner.id,
        "invoice_date": "2026-07-13",
        "accounting_date": "2026-07-13",
        "due_date": "2026-07-13",
        "currency_id": currency.id,
        "journal_id": journal.id,
        "posting_mode": "draft",
        (
            "vendor_reference"
            if move_type == "in_invoice"
            else "reference"
        ): "V3-DOC-4101",
        "lines": [
            {
                "line_reference": "line-1",
                "name": "Consulting",
                "product_id": None,
                "account_id": 5601,
                "quantity": "1",
                "price_unit": "100",
                "tax_ids": [],
            }
        ],
    }
    if move_type == "in_invoice":
        values["odoo_cli_v3_document_binding"] = (
            vendor_bill_document_binding(graph_parameters)
        )
        values["odoo_cli_v3_document_binding_v2"] = (
            vendor_bill_document_binding_v2(graph_parameters)
        )
        values["odoo_cli_v3_business_binding"] = (
            vendor_bill_business_binding(graph_parameters)
        )
    else:
        values["odoo_cli_v3_document_binding"] = (
            customer_invoice_document_binding(graph_parameters)
        )
        values["odoo_cli_v3_document_binding_v2"] = (
            customer_invoice_document_binding_v2(graph_parameters)
        )
        values["odoo_cli_v3_business_binding"] = (
            customer_invoice_business_binding(graph_parameters)
        )
    values.update(overrides)
    return SimpleRecord(**values)


def _refund_bindings(parameters):
    document = hashlib.sha256(
        json.dumps(
            {
                "capability_kind": "refund",
                "parameters": {
                    key: parameters[key] for key in sorted(parameters)
                },
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    business = hashlib.sha256(
        json.dumps(
            {
                "business_kind": "refund",
                "identity": {
                    "origin_move_id": parameters["origin_move_id"],
                    "refund_mode": parameters["refund_mode"],
                    "line_references": sorted(
                        line["line_reference"]
                        for line in parameters["lines"]
                    ),
                },
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return document, refund_document_binding_v2(parameters), business


def draft_refund_graph(
    company,
    *,
    move_type="out_refund",
    refund_mode="full",
    origin_posting_mode="post",
    with_product=False,
    child_contact=False,
    origin_quantity="1",
    origin_price_unit="100",
    origin_total="100",
    origin_invoice_date="2026-07-13",
    origin_accounting_date="2026-07-13",
    refund_date="2026-07-13",
):
    origin_id = 6101
    refund_id = 6102
    invoice_type = "out_invoice" if move_type == "out_refund" else "in_invoice"
    vendor = move_type == "in_refund"
    refund_total = origin_total if refund_mode == "full" else "40"
    refund_quantity = (
        origin_quantity if refund_mode == "full" else "1"
    )
    refund_price_unit = (
        origin_price_unit
        if refund_mode == "full"
        else refund_total
    )
    origin_amount_text = f"{Decimal(origin_total):.2f}"
    refund_amount_text = f"{Decimal(refund_total):.2f}"
    currency = SimpleRecord(id=12, active=True, rounding="0.01")
    company.currency_id = currency
    journal = SimpleRecord(
        id=6201,
        company_id=company,
        type="purchase" if vendor else "sale",
        active=True,
        currency_id=currency,
    )
    commercial_partner = SimpleRecord(
        id=6301,
        company_id=company,
        active=True,
        customer_rank=0 if vendor else 1,
        supplier_rank=1 if vendor else 0,
    )
    commercial_partner.commercial_partner_id = commercial_partner
    partner = (
        SimpleRecord(
            id=6302,
            company_id=company,
            active=True,
            customer_rank=0 if vendor else 1,
            supplier_rank=1 if vendor else 0,
            commercial_partner_id=commercial_partner,
        )
        if child_contact
        else commercial_partner
    )
    product = (
        SimpleRecord(
            id=6350,
            active=True,
            company_id=False,
            categ_id=False,
            property_account_income_id=False,
            property_account_expense_id=False,
        )
        if with_product
        else False
    )
    invoice_account = SimpleRecord(
        id=6601,
        company_ids=[company],
        account_type="expense" if vendor else "income",
        deprecated=False,
        reconcile=False,
    )
    term_account = SimpleRecord(
        id=6602,
        company_ids=[company],
        account_type="liability_payable" if vendor else "asset_receivable",
        deprecated=False,
        reconcile=True,
    )
    origin_lines = [
        SimpleRecord(
            id=6401,
            move_id=SimpleRecord(id=origin_id),
            company_id=company,
            parent_state="posted",
            display_type="product",
            odoo_cli_v3_line_reference="origin-line-1",
            name="Consulting",
            product_id=product,
            account_id=invoice_account,
            partner_id=commercial_partner,
            currency_id=currency,
            quantity=origin_quantity,
            price_unit=origin_price_unit,
            price_subtotal=origin_total,
            price_total=origin_total,
            tax_ids=[],
            tax_line_id=False,
            debit=origin_total if vendor else "0",
            credit="0" if vendor else origin_total,
            balance=origin_total if vendor else f"-{origin_total}",
            amount_currency=(
                origin_total if vendor else f"-{origin_total}"
            ),
            matching_number=False,
            deductible_amount="100",
            date_maturity=False,
            reconciled=False,
        ),
        SimpleRecord(
            id=6402,
            move_id=SimpleRecord(id=origin_id),
            company_id=company,
            parent_state="posted",
            display_type="payment_term",
            name="Payment term",
            product_id=False,
            account_id=term_account,
            partner_id=commercial_partner,
            currency_id=currency,
            tax_ids=[],
            tax_line_id=False,
            debit="0" if vendor else origin_total,
            credit=origin_total if vendor else "0",
            balance=f"-{origin_total}" if vendor else origin_total,
            amount_currency=(
                f"-{origin_total}" if vendor else origin_total
            ),
            amount_residual=(
                f"-{origin_total}" if vendor else origin_total
            ),
            amount_residual_currency=(
                f"-{origin_total}" if vendor else origin_total
            ),
            matching_number=False,
            deductible_amount="100",
            date_maturity=date.fromisoformat(origin_invoice_date),
            reconciled=False,
        ),
    ]
    refund_lines = [
        SimpleRecord(
            id=6501,
            move_id=SimpleRecord(id=refund_id),
            company_id=company,
            parent_state="draft",
            display_type="product",
            odoo_cli_v3_line_reference=(
                f"rf-full-{origin_id}-6401"
                if refund_mode == "full"
                else "origin-line-1"
            ),
            name="Consulting",
            product_id=product,
            account_id=invoice_account,
            partner_id=commercial_partner,
            currency_id=currency,
            quantity=refund_quantity,
            price_unit=refund_price_unit,
            price_subtotal=refund_total,
            price_total=refund_total,
            tax_ids=[],
            tax_line_id=False,
            debit="0" if vendor else refund_total,
            credit=refund_total if vendor else "0",
            balance=f"-{refund_total}" if vendor else refund_total,
            amount_currency=(
                f"-{refund_total}" if vendor else refund_total
            ),
            matching_number=False,
            deductible_amount="100",
            date_maturity=False,
            reconciled=False,
        ),
        SimpleRecord(
            id=6502,
            move_id=SimpleRecord(id=refund_id),
            company_id=company,
            parent_state="draft",
            display_type="payment_term",
            name=(
                "Reversal of: BILL/2026/6101"
                if vendor
                else False
            ),
            product_id=False,
            account_id=term_account,
            partner_id=commercial_partner,
            currency_id=currency,
            tax_ids=[],
            tax_line_id=False,
            debit=refund_total if vendor else "0",
            credit="0" if vendor else refund_total,
            balance=refund_total if vendor else f"-{refund_total}",
            amount_currency=(
                refund_total if vendor else f"-{refund_total}"
            ),
            amount_residual=(
                refund_total if vendor else f"-{refund_total}"
            ),
            amount_residual_currency=(
                refund_total if vendor else f"-{refund_total}"
            ),
            matching_number=False,
            deductible_amount="100",
            date_maturity=date.fromisoformat(refund_date),
            reconciled=False,
        ),
    ]
    origin_parameters = {
        "company_id": company.id,
        "partner_id": partner.id,
        "invoice_date": origin_invoice_date,
        "accounting_date": origin_accounting_date,
        "due_date": origin_invoice_date,
        "currency_id": currency.id,
        "journal_id": journal.id,
        "posting_mode": origin_posting_mode,
        (
            "vendor_reference"
            if invoice_type == "in_invoice"
            else "reference"
        ): (
            "BILL/2026/6101"
            if invoice_type == "in_invoice"
            else "INV/2026/6101"
        ),
        "lines": [
            {
                "line_reference": "origin-line-1",
                "name": "Consulting",
                "product_id": 6350 if with_product else None,
                "account_id": 6601,
                "quantity": origin_quantity,
                "price_unit": origin_price_unit,
                "tax_ids": [],
            }
        ],
    }
    if invoice_type == "in_invoice":
        origin_document_binding = vendor_bill_document_binding(
            origin_parameters
        )
        origin_document_binding_v2 = vendor_bill_document_binding_v2(
            origin_parameters
        )
        origin_business_binding = vendor_bill_business_binding(
            origin_parameters
        )
    else:
        origin_document_binding = customer_invoice_document_binding(
            origin_parameters
        )
        origin_document_binding_v2 = customer_invoice_document_binding_v2(
            origin_parameters
        )
        origin_business_binding = customer_invoice_business_binding(
            origin_parameters
        )
    origin = SimpleRecord(
        id=origin_id,
        company_id=company,
        move_type=invoice_type,
        state="posted",
        name="INV/2026/6101" if invoice_type == "out_invoice" else "BILL/2026/6101",
        posted_before=True,
        auto_post="no",
        auto_post_until=False,
        journal_id=journal,
        currency_id=currency,
        partner_id=partner,
        commercial_partner_id=commercial_partner,
        payment_state="not_paid",
        amount_untaxed=origin_amount_text,
        amount_tax="0.00",
        amount_total=origin_amount_text,
        amount_residual=origin_amount_text,
        invoice_date=date.fromisoformat(origin_invoice_date),
        date=date.fromisoformat(origin_accounting_date),
        invoice_date_due=date.fromisoformat(origin_invoice_date),
        ref=origin_parameters[
            (
                "vendor_reference"
                if invoice_type == "in_invoice"
                else "reference"
            )
        ],
        line_ids=origin_lines,
        invoice_line_ids=[origin_lines[0]],
        odoo_cli_v3_document_binding=origin_document_binding,
        odoo_cli_v3_document_binding_v2=origin_document_binding_v2,
        odoo_cli_v3_business_binding=origin_business_binding,
    )
    refund_lines_parameter = (
        []
        if refund_mode == "full"
        else [
            {
                "line_reference": "origin-line-1",
                "name": "Consulting",
                "account_id": 6601,
                "quantity": "1",
                "price_unit": refund_total,
                "tax_ids": [],
            }
        ]
    )
    refund_parameters = {
        "company_id": company.id,
        "origin_move_id": origin_id,
        "refund_type": (
            "vendor_debit_note"
            if move_type == "in_refund"
            else "customer_credit_note"
        ),
        "refund_mode": refund_mode,
        "refund_date": refund_date,
        "journal_id": journal.id,
        "currency_id": currency.id,
        "expected_total_amount": refund_total,
        "reason": "V3 refund",
        "posting_mode": "draft",
        "lines": refund_lines_parameter,
    }
    (
        refund_document_binding,
        refund_document_binding_v2_value,
        refund_business_binding,
    ) = _refund_bindings(refund_parameters)
    refund = SimpleRecord(
        id=refund_id,
        company_id=company,
        move_type=move_type,
        state="draft",
        name="/",
        posted_before=False,
        auto_post="no",
        auto_post_until=False,
        sequence_prefix=False,
        sequence_number=False,
        made_sequence_gap=False,
        checked=False,
        journal_id=journal,
        currency_id=currency,
        partner_id=partner,
        commercial_partner_id=commercial_partner,
        invoice_date=date.fromisoformat(refund_date),
        date=date.fromisoformat(refund_date),
        invoice_date_due=date.fromisoformat(refund_date),
        invoice_payment_term_id=False,
        payment_state="not_paid",
        amount_untaxed=refund_amount_text,
        amount_tax="0.00",
        amount_total=refund_amount_text,
        amount_residual=refund_amount_text,
        secure_sequence_number=0,
        inalterable_hash=False,
        need_cancel_request=False,
        is_manually_modified=False,
        line_ids=refund_lines,
        invoice_line_ids=[refund_lines[0]],
        reversed_entry_id=origin,
        reversal_move_ids=[],
        odoo_cli_v3_reason="V3 refund",
        odoo_cli_v3_document_binding=refund_document_binding,
        odoo_cli_v3_document_binding_v2=refund_document_binding_v2_value,
        odoo_cli_v3_business_binding=refund_business_binding,
        _affect_tax_report=lambda: False,
        _get_violated_lock_dates=lambda _date, _affects_tax: [],
    )
    origin.reversal_move_ids = [refund]
    return origin, refund


class Backend:
    def assert_read_access(self, *, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")

    def company_currency(self, *, company_id):
        return CurrencyInfo(12, "CNY", "¥", Decimal("0.01"))

    def accounts(self, *, company_id, account_ids):
        return [AccountInfo(401, "1000", "Cash", "asset_cash")]

    def opening_aggregates(self, *, company_id, before, account_id, include_off_balance):
        return {}

    def period_aggregates(
        self, *, company_id, date_from, date_to, account_id, include_off_balance
    ):
        return {401: Aggregate(Decimal("100"), Decimal("100"), Decimal("0"), 2)}


class ArBackend:
    currency_info = ArCurrencyInfo(12, "CNY", "¥", Decimal("0.01"))

    def assert_read_access(self, *, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")

    def company_currency(self, *, company_id):
        return self.currency_info

    def assert_partner(self, *, company_id, partner_id):
        raise AssertionError("partner validation was not requested")

    def currency(self, *, currency_id):
        raise AssertionError("currency validation was not requested")

    def source_lines(
        self, *, company_id, as_of_date, partner_id, currency_id, candidate_limit
    ):
        return [
            OpenItemSource(
                move_line_id=701,
                move_id=801,
                move_name="INV/2026/007",
                move_type="out_invoice",
                payment_id=None,
                line_date=as_of_date,
                due_date=as_of_date,
                partner_id=901,
                partner_name="Customer",
                account_id=1001,
                account_code="1122",
                account_name="Accounts Receivable",
                journal_id=1101,
                journal_code="INV",
                currency=self.currency_info,
                balance=Decimal("100"),
                amount_currency=Decimal("100"),
                current_reconciled=False,
            )
        ]

    def partials_as_of(self, *, company_id, move_line_ids, as_of_date):
        return {
            701: OpenItemPartial(
                debit_company=Decimal("30"),
                debit_currency=Decimal("30"),
                matched_count=1,
            )
        }


class ApBackend(ArBackend):
    def source_lines(
        self, *, company_id, as_of_date, partner_id, currency_id, candidate_limit
    ):
        return [
            OpenItemSource(
                move_line_id=702,
                move_id=802,
                move_name="BILL/2026/007",
                move_type="in_invoice",
                payment_id=None,
                line_date=as_of_date,
                due_date=as_of_date,
                partner_id=902,
                partner_name="Supplier",
                account_id=1002,
                account_code="2202",
                account_name="Accounts Payable",
                journal_id=1102,
                journal_code="BILL",
                currency=self.currency_info,
                balance=Decimal("-100"),
                amount_currency=Decimal("-100"),
                current_reconciled=False,
            )
        ]

    def partials_as_of(self, *, company_id, move_line_ids, as_of_date):
        return {
            702: OpenItemPartial(
                credit_company=Decimal("30"),
                credit_currency=Decimal("30"),
                matched_count=1,
            )
        }


class MulticurrencyBackend:
    company_currency_info = MulticurrencyCurrencyInfo(
        6, "CNY", "CNY", Decimal("0.01")
    )
    usd = MulticurrencyCurrencyInfo(1, "USD", "$", Decimal("0.01"))

    def assert_read_access(self, *, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")

    def company_currency(self, *, company_id):
        return self.company_currency_info

    def currencies(self, *, company_id, currency_ids):
        by_id = {6: self.company_currency_info, 1: self.usd}
        return [by_id[item] for item in currency_ids]

    def accounts(self, *, company_id, account_ids):
        return [
            MulticurrencyAccountInfo(
                401, "112200", "Accounts Receivable", "asset_receivable"
            )
        ]

    def balance_aggregates(
        self, *, company_id, as_of_date, currency_ids, exclude_off_balance
    ):
        return [BalanceAggregate(401, 1, Decimal("1950"), Decimal("300"), 8)]

    def effective_rate(
        self, *, company_id, as_of_date, currency, company_currency
    ):
        company_source = TechnicalRateSource.no_rate_identity(
            currency_id=company_currency.id
        )
        if currency.id == company_currency.id:
            return EffectiveRate(
                currency_id=currency.id,
                transaction_technical_source=company_source,
                company_technical_source=company_source,
                transaction_to_company_rate=Decimal("1"),
            )
        return EffectiveRate(
            currency_id=currency.id,
            transaction_technical_source=TechnicalRateSource(
                currency_id=currency.id,
                effective_date=as_of_date,
                source_scope="company_specific",
                source_company_id=7,
                source_record_id=91,
                technical_rate=Decimal("0.15384615384615385"),
            ),
            company_technical_source=company_source,
            transaction_to_company_rate=Decimal("6.5"),
        )


class MulticompanyBackend:
    cny = MulticompanyCurrencyInfo(6, "CNY", "CNY", Decimal("0.01"))
    usd = MulticompanyCurrencyInfo(1, "USD", "$", Decimal("0.01"))

    def assert_read_access(self, *, company_ids, presentation_currency_id):
        if not set(company_ids).issubset({7, 8}) or presentation_currency_id != 1:
            raise AssertionError("unexpected multi-company scope")

    def presentation_currency(self, *, company_ids, currency_id):
        if not company_ids or currency_id != 1:
            raise AssertionError("unexpected presentation currency scope")
        return self.usd

    def company_currency(self, *, company_id):
        return {7: self.cny, 8: self.usd}[company_id]

    def ledger_account_aggregates(
        self,
        *,
        company_id,
        date_from,
        date_to,
        posted_only,
        exclude_off_balance,
    ):
        if not posted_only or not exclude_off_balance:
            raise AssertionError("multi-company ledger safety flags were weakened")
        prefix = 100 if company_id == 7 else 500
        opening = Decimal("100") if company_id == 7 else Decimal("50")
        activity = Decimal("20") if company_id == 7 else Decimal("10")
        return (
            MulticompanyLedgerAggregate(
                company_id,
                prefix + 1,
                "1000",
                "Cash",
                "asset_cash",
                opening,
                1,
                activity,
                Decimal("0"),
                1,
            ),
            MulticompanyLedgerAggregate(
                company_id,
                prefix + 2,
                "3000",
                "Equity",
                "equity",
                -opening,
                1,
                Decimal("0"),
                activity,
                1,
            ),
        )

    def translation_rate(
        self,
        *,
        company_id,
        rate_date,
        source_currency,
        presentation_currency,
    ):
        if company_id == 8:
            identity = MulticompanyTechnicalRateSource.no_rate_identity(
                currency_id=1
            )
            return MulticompanyTranslationRate(
                company_id=8,
                rate_company_id=8,
                source_currency_id=1,
                presentation_currency_id=1,
                rate_date=rate_date,
                source_technical_source=identity,
                presentation_technical_source=identity,
                source_to_presentation_rate=Decimal("1"),
            )
        source = MulticompanyTechnicalRateSource.no_rate_identity(
            currency_id=source_currency.id
        )
        presentation = MulticompanyTechnicalRateSource(
            currency_id=presentation_currency.id,
            effective_date=date(2026, 6, 1),
            source_scope="company_specific",
            source_company_id=company_id,
            source_record_id=701,
            technical_rate=Decimal("0.14"),
        )
        return MulticompanyTranslationRate(
            company_id=company_id,
            rate_company_id=company_id,
            source_currency_id=source_currency.id,
            presentation_currency_id=presentation_currency.id,
            rate_date=rate_date,
            source_technical_source=source,
            presentation_technical_source=presentation,
            source_to_presentation_rate=Decimal("0.14"),
        )


class ReportBackend:
    currency_info = ReportCurrencyInfo(12, "CNY", "CNY", Decimal("0.01"))

    def assert_read_access(self, *, company_id):
        if company_id != 7:
            raise AssertionError("unexpected company")

    def company_currency(self, *, company_id):
        return self.currency_info

    def fetch_native_report(self, **kwargs):
        family = kwargs["report_family"]
        report_kind = kwargs["report_kind"]
        report_id = {
            ("financial", "balance_sheet"): 22,
            ("financial", "cash_flow"): 23,
            ("financial", "profit_and_loss"): 25,
            ("tax", "generic_tax"): 1,
        }[(family, report_kind)]
        expression_label = "net" if family == "tax" else "balance"
        report_name = "Tax Report" if family == "tax" else "Balance Sheet"
        main_period_key = canonical_period_key(
            "range", kwargs["date_from"], kwargs["date_to"]
        )
        columns = [
            NativeReportColumn(
                label="Net" if family == "tax" else "Balance",
                expression_label=expression_label,
                value=Decimal("100.00"),
                figure_type="monetary",
                period_key=main_period_key,
                period_label="Current period",
                period_mode="range",
                period_date_from=kwargs["date_from"],
                period_date_to=kwargs["date_to"],
                currency_id=12,
                is_blank=False,
                auditable=True,
            )
        ]
        resolved_comparison_periods = ()
        if kwargs["comparison_mode"] is not None:
            comparison_to = kwargs["date_from"] - timedelta(days=1)
            comparison_from = comparison_to - (
                kwargs["date_to"] - kwargs["date_from"]
            )
            comparison_key = canonical_period_key(
                "range", comparison_from, comparison_to
            )
            resolved_comparison_periods = (
                NativeReportPeriod(
                    key=comparison_key,
                    label="Previous period",
                    mode="range",
                    date_from=comparison_from,
                    date_to=comparison_to,
                ),
            )
            columns.append(
                NativeReportColumn(
                    label="Balance",
                    expression_label=expression_label,
                    value=Decimal("90.00"),
                    figure_type="monetary",
                    period_key=comparison_key,
                    period_label="Previous period",
                    period_mode="range",
                    period_date_from=comparison_from,
                    period_date_to=comparison_to,
                    currency_id=12,
                    is_blank=False,
                    auditable=True,
                )
            )
        line = NativeReportLine(
            raw_id=f"~account.report~{report_id}|line",
            code=None,
            name="Net Sales" if family == "tax" else "Assets",
            level=0,
            columns=tuple(columns),
            unfoldable=False,
            unfolded=False,
            source_move_line_count=None,
            source_move_line_count_proven=False,
        )
        warnings = (
            ("odoo:tax_source_move_line_count_unavailable",)
            if family == "tax"
            else ()
        )
        return NativeReportSnapshot(
            company_id=kwargs["company_id"],
            requested_report_id=report_id,
            requested_report_name=report_name,
            resolved_report_id=report_id,
            resolved_report_name=report_name,
            report_family=family,
            report_kind=report_kind,
            definition_binding=report_definition_binding(),
            currency_id=kwargs["currency_id"],
            period_key=main_period_key,
            date_mode="range",
            date_from=kwargs["date_from"],
            date_to=kwargs["date_to"],
            comparison_mode=kwargs["comparison_mode"],
            comparison_periods=kwargs["comparison_periods"],
            resolved_comparison_periods=resolved_comparison_periods,
            effective_filters=NativeReportFilters(
                move_state=kwargs["move_state"],
                journal_scope=kwargs["journal_scope"],
                journal_ids=(15,),
                tax_unit_id=kwargs["tax_unit_id"],
                unreconciled_only=kwargs["unreconciled_only"],
                hide_zero_lines=kwargs["hide_zero_lines"],
                line_expansion_request=kwargs["line_expansion_request"],
                custom_aml_filter_count=0,
                analytic_groupby=False,
                consolidation=False,
                multi_currency_display=False,
            ),
            warnings=warnings,
            lines=(line,),
        )


def context(**changes):
    values = {
        "audience": "odoo-accounting-cli-v3",
        "auth_token_id": "token-1",
        "auth_issued_at": NOW - timedelta(seconds=5),
        "auth_expires_at": NOW + timedelta(minutes=4),
        "auth_signature_version": 1,
        "auth_signature_purpose": "auth_context_v1",
        "auth_key_id": "test-auth-2026-07",
        "auth_request_digest": "b" * 64,
        "auth_signature": "a" * 64,
        "principal": "pi:user-42",
        "odoo_instance_id": "odoo19@tokyo2",
        "database_name": "odoo_test",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "user_id": 42,
        "company_id": 7,
        "allowed_company_ids": frozenset({7}),
        "environment": "test",
    }
    values.update(changes)
    return RequestContext(**values)


def parameters():
    return {
        "company_id": 7, "date_from": "2026-01-01", "date_to": "2026-12-31",
        "opening_basis": "ledger_cumulative", "currency_id": 12,
        "account_id": None, "include_off_balance": False, "include_zero": False,
        "limit": 100, "offset": 0,
    }


def capabilities():
    document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return validate_registry(document)


def capability(capability_id="acct.gl.trial_balance.v1"):
    return next(item for item in capabilities() if item.id == capability_id)


def synthetic_read_capability(capability_id):
    existing = next(
        (item for item in capabilities() if item.id == capability_id),
        None,
    )
    if existing is not None:
        return existing
    data = capability("acct.move.draft_cancel_eligibility.v1").data
    data["id"] = capability_id
    return Capability.from_dict(data)


def registry_with(cap):
    return [
        *(item for item in capabilities() if item.id != cap.id),
        cap,
    ]


class OdooReadExecutorTest(unittest.TestCase):
    def executor(self, *, env=None, registry=None):
        consumed = set()

        def consume(receipt_id, request_digest, _observed_at, _verified_at):
            key = (receipt_id, request_digest)
            if key in consumed:
                return False
            consumed.add(key)
            return True

        return OdooReadExecutor(
            env or Environment(),
            capabilities=capabilities() if registry is None else registry,
            odoo_instance_id="odoo19@tokyo2",
            database_name="odoo_test",
            database_uuid="11111111-1111-4111-8111-111111111111",
            release_digest="d" * 64,
            environment="test",
            capability_channel="staged",
            receipt_secret=b"test-only-receipt-secret-32-byte",
            receipt_key_id=RECEIPT_KEY_ID,
            consume_receipt=consume,
            now=lambda: NOW,
            receipt_id_factory=lambda: "receipt-1",
            trial_balance_backend_factory=lambda _env, _user, _companies: Backend(),
            ar_open_items_backend_factory=lambda _env, _user, _companies: ArBackend(),
            ap_open_items_backend_factory=lambda _env, _user, _companies: ApBackend(),
            multicompany_consolidated_backend_factory=(
                lambda _env, _user, _companies: MulticompanyBackend()
            ),
            multicurrency_balance_backend_factory=(
                lambda _env, _user, _companies: MulticurrencyBackend()
            ),
            report_read_backend_factory=(
                lambda _env, _user, _companies: ReportBackend()
            ),
        )

    def test_executes_handler_and_verifies_receipt(self) -> None:
        executor = self.executor()
        result = executor(context(), capability(), parameters(), "c" * 64, "d" * 64)
        self.assertEqual(result["ledger_summary"]["period_debit"], "100.00")
        executor.verify(context(), capability(), parameters(), result, "c" * 64, "d" * 64)
        with self.assertRaisesRegex(ValueError, "already consumed"):
            executor.verify(context(), capability(), parameters(), result, "c" * 64, "d" * 64)

    def test_database_and_user_mismatch_are_rejected_before_handler(self) -> None:
        executor = self.executor()
        with self.assertRaisesRegex(OdooExecutionError, "binding mismatch"):
            executor(context(database_name="odoo_sg"), capability(), parameters(), "c" * 64, "d" * 64)
        with self.assertRaisesRegex(OdooExecutionError, "binding mismatch"):
            executor(context(user_id=43, principal="pi:user-43"), capability(), parameters(), "c" * 64, "d" * 64)

    def test_unregistered_capability_is_rejected_before_dispatch(self) -> None:
        executor = self.executor(registry=[capability()])
        executor._read_handlers = mock.Mock(  # type: ignore[method-assign]
            side_effect=AssertionError("dispatch must not be consulted")
        )

        with self.assertRaisesRegex(OdooExecutionError, "not in the trusted registry"):
            executor(
                context(),
                capability("acct.registry.list.v1"),
                {"company_id": 7},
                "c" * 64,
                "d" * 64,
            )

        executor._read_handlers.assert_not_called()

    def test_registered_capability_without_handler_is_rejected_without_receipt(self) -> None:
        unsupported = next(
            item
            for item in capabilities()
            if item.id
            not in {
                "acct.registry.list.v1",
                "acct.gl.trial_balance.v1",
                "acct.ar.open_items.v1",
                "acct.ap.open_items.v1",
                "acct.multicompany.consolidated_read.v1",
                "acct.multicurrency.balance_read.v1",
                "acct.move.draft_cancel_eligibility.v1",
                "acct.report.financial_read.v1",
                "acct.tax.report_read.v1",
            }
        )
        executor = self.executor()

        with mock.patch(
            "odoo_accounting_cli_v3.odoo.executor.create_read_receipt"
        ) as create_receipt:
            with self.assertRaisesRegex(OdooExecutionError, "no trusted Odoo handler"):
                executor(context(), unsupported, {}, "c" * 64, "d" * 64)

        create_receipt.assert_not_called()

    def test_handler_failure_propagates_without_creating_receipt(self) -> None:
        failure = RuntimeError("handler failed")
        executor = self.executor()
        executor._read_handlers = lambda: {  # type: ignore[method-assign]
            "acct.gl.trial_balance.v1": mock.Mock(side_effect=failure)
        }

        with mock.patch(
            "odoo_accounting_cli_v3.odoo.executor.create_read_receipt"
        ) as create_receipt:
            with self.assertRaisesRegex(RuntimeError, "handler failed") as raised:
                executor(
                    context(), capability(), parameters(), "c" * 64, "d" * 64
                )

        self.assertIs(raised.exception, failure)
        create_receipt.assert_not_called()

    def test_domain_backend_factories_receive_exact_bound_identity(self) -> None:
        open_items_parameters = {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": None,
            "currency_id": None,
            "limit": 100,
            "offset": 0,
        }
        multicurrency_parameters = {
            "company_id": 7,
            "as_of_date": "2026-07-13",
            "currency_ids": [6, 1],
            "balance_basis": "posted_ledger_cumulative",
            "off_balance_policy": "exclude",
            "limit": 100,
            "offset": 0,
        }
        cases = (
            (
                "_trial_balance_backend_factory",
                "acct.gl.trial_balance.v1",
                parameters(),
                Backend(),
            ),
            (
                "_ar_open_items_backend_factory",
                "acct.ar.open_items.v1",
                open_items_parameters,
                ArBackend(),
            ),
            (
                "_ap_open_items_backend_factory",
                "acct.ap.open_items.v1",
                open_items_parameters,
                ApBackend(),
            ),
            (
                "_multicompany_consolidated_backend_factory",
                "acct.multicompany.consolidated_read.v1",
                {
                    "company_ids": [7],
                    "date_from": "2026-01-01",
                    "date_to": "2026-06-30",
                    "presentation_currency_id": 1,
                    "limit": 100,
                    "offset": 0,
                },
                MulticompanyBackend(),
            ),
            (
                "_multicurrency_balance_backend_factory",
                "acct.multicurrency.balance_read.v1",
                multicurrency_parameters,
                MulticurrencyBackend(),
            ),
            (
                "_report_read_backend_factory",
                "acct.report.financial_read.v1",
                {
                    "company_id": 7,
                    "report_request": {
                        "kind": "balance_sheet",
                        "comparison": {
                            "mode": "previous_period",
                            "periods": 1,
                        },
                    },
                    "date_from": "2026-01-01",
                    "date_to": "2026-06-30",
                    "move_state": "posted",
                    "journal_scope": "all_report_eligible",
                    "tax_unit_id": None,
                    "unreconciled_only": False,
                    "hide_zero_lines": False,
                    "line_expansion_request": "none",
                    "currency_id": 12,
                    "limit": 100,
                    "offset": 0,
                },
                ReportBackend(),
            ),
            (
                "_report_read_backend_factory",
                "acct.tax.report_read.v1",
                {
                    "company_id": 7,
                    "date_from": "2026-01-01",
                    "date_to": "2026-06-30",
                    "move_state": "posted",
                    "journal_scope": "all_report_eligible",
                    "tax_unit_id": None,
                    "unreconciled_only": False,
                    "hide_zero_lines": False,
                    "line_expansion_request": "none",
                    "currency_id": 12,
                    "limit": 100,
                    "offset": 0,
                },
                ReportBackend(),
            ),
        )
        for factory_attribute, capability_id, requested, backend in cases:
            with self.subTest(capability_id=capability_id):
                executor = self.executor()
                factory = mock.Mock(return_value=backend)
                setattr(executor, factory_attribute, factory)

                executor(
                    context(),
                    capability(capability_id),
                    requested,
                    "c" * 64,
                    "d" * 64,
                )

                factory.assert_called_once_with(
                    executor._env,
                    42,
                    frozenset({7}),
                )

    def test_multicompany_receipt_binds_the_full_signed_company_set(self) -> None:
        executor = self.executor()
        requested = {
            "company_ids": [8, 7],
            "date_from": "2026-01-01",
            "date_to": "2026-06-30",
            "presentation_currency_id": 1,
            "limit": 100,
            "offset": 0,
        }
        bound_context = context(allowed_company_ids=frozenset({7, 8}))
        multi = capability("acct.multicompany.consolidated_read.v1")

        result = executor(
            bound_context,
            multi,
            requested,
            "c" * 64,
            "d" * 64,
        )

        self.assertEqual(result["filters"]["company_ids"], [7, 8])
        self.assertEqual(
            result["page"],
            {"limit": 100, "offset": 0, "count": 4, "total_count": 4},
        )
        self.assertEqual(result["receipt"]["record_count"], 4)
        executor.verify(
            bound_context,
            multi,
            requested,
            result,
            "c" * 64,
            "d" * 64,
        )

        tampered = {**requested, "company_ids": [7]}
        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            self.executor().verify(
                bound_context,
                multi,
                tampered,
                result,
                "c" * 64,
                "d" * 64,
            )

    def test_registry_list_is_acl_filtered_sorted_and_receipted(self) -> None:
        env = Environment()
        executor = self.executor(env=env)
        requested = {"company_id": 7}
        registry_capability = capability("acct.registry.list.v1")
        result = executor(
            context(), registry_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(
            [item["id"] for item in result["capabilities"]],
            [
                "acct.ap.open_items.v1",
                "acct.ar.open_items.v1",
                "acct.diagnostics.operation_read.v1",
                "acct.gl.trial_balance.v1",
                "acct.multicompany.consolidated_read.v1",
                "acct.multicurrency.balance_read.v1",
                "acct.registry.list.v1",
                "acct.report.financial_read.v1",
                "acct.tax.report_read.v1",
            ],
        )
        self.assertEqual(result["page"], {"count": 9, "total_count": 9})
        self.assertEqual(result["receipt"]["record_count"], 9)
        self.assertEqual(env.company.access_checks, [("rights", "read"), ("rule", "read")])
        for descriptor in result["capabilities"]:
            source = capability(descriptor["id"]).data
            canonical = json.dumps(
                source,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            self.assertEqual(descriptor["input_schema_json"], json.dumps(
                source["input_schema"], ensure_ascii=False, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ))
            self.assertEqual(descriptor["output_schema_json"], json.dumps(
                source["output_schema"], ensure_ascii=False, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ))
            self.assertEqual(
                descriptor["contract_digest"],
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(descriptor["capability_channel"], "staged")

        executor.verify(
            context(), registry_capability, requested, result, "c" * 64, "d" * 64
        )

    def test_draft_cancel_eligibility_returns_exact_bound_write_parameters(self) -> None:
        env = DraftCancelEnvironment()
        executor = self.executor(env=env)
        requested = {
            "company_id": 7,
            "move_id": 1101,
            "expected_move_type": "out_invoice",
        }
        cap = capability("acct.move.draft_cancel_eligibility.v1")

        result = executor(context(), cap, requested, "c" * 64, "d" * 64)

        self.assertIs(result["eligible"], True)
        self.assertEqual(result["eligibility_failures"], [])
        self.assertEqual(result["failed_line_ids"], [])
        self.assertEqual(
            result["write_parameters"],
            {
                "company_id": 7,
                "move_id": 1101,
                "expected_move_type": "out_invoice",
                "expected_document_binding": (
                    env.move.odoo_cli_v3_document_binding
                ),
                "expected_document_binding_v2": (
                    env.move.odoo_cli_v3_document_binding_v2
                ),
                "expected_business_binding": (
                    env.move.odoo_cli_v3_business_binding
                ),
            },
        )
        self.assertEqual(
            result["target"],
            {
                "company_id": 7,
                "move_id": 1101,
                "move_type": "out_invoice",
                "state": "draft",
                "payment_state": "not_paid",
                "journal_id": 5201,
                "currency_id": 12,
                "line_ids": [5301, 5302],
                "document_binding": (
                    env.move.odoo_cli_v3_document_binding
                ),
                "document_binding_v2": (
                    env.move.odoo_cli_v3_document_binding_v2
                ),
                "business_binding": (
                    env.move.odoo_cli_v3_business_binding
                ),
            },
        )
        self.assertEqual(result["receipt"]["record_count"], 1)
        self.assertEqual(env.company.access_checks, [("rights", "read"), ("rule", "read")])
        self.assertEqual(
            env.move.access_checks,
            [
                ("rights", "read"),
                ("rule", "read"),
                ("rights", "write"),
                ("rule", "write"),
            ],
        )
        self.assertEqual(
            env.move.line_ids[0].access_checks,
            [
                ("rights", "read"),
                ("rule", "read"),
                ("rights", "write"),
                ("rule", "write"),
            ],
        )
        self.assertEqual(
            env.move.line_ids[1].access_checks,
            [
                ("rights", "read"),
                ("rule", "read"),
                ("rights", "write"),
                ("rule", "write"),
            ],
        )
        executor.verify(context(), cap, requested, result, "c" * 64, "d" * 64)

    def test_draft_cancel_eligibility_rejects_move_or_line_write_acl_denial(
        self,
    ) -> None:
        cases = (
            ("move", "move_write_acl_denied"),
            ("line", "line_write_acl_denied"),
        )
        cap = capability("acct.move.draft_cancel_eligibility.v1")
        requested = {
            "company_id": 7,
            "move_id": 1101,
            "expected_move_type": "out_invoice",
        }
        for target, expected_failure in cases:
            with self.subTest(target=target):
                move = document_post_move(Company(), id=1101)
                denied = (
                    move
                    if target == "move"
                    else move.line_ids[0]
                )
                denied.denied_operations = frozenset({"write"})
                result = self.executor(
                    env=DraftCancelEnvironment(move=move)
                )(
                    context(),
                    cap,
                    requested,
                    "c" * 64,
                    "d" * 64,
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(
                    expected_failure,
                    result["eligibility_failures"],
                )
                self.assertIn(
                    "move_and_complete_line_graph_write_acl",
                    result["checks"],
                )

    def test_draft_cancel_eligibility_rejects_missing_invalid_or_tampered_v2(
        self,
    ) -> None:
        cases = (
            (False, "legacy_binding_requires_provenance_migration"),
            ("not-a-digest", "document_binding_v2_invalid"),
            ("f" * 64, "document_graph_binding_mismatch"),
        )
        cap = capability("acct.move.draft_cancel_eligibility.v1")
        requested = {
            "company_id": 7,
            "move_id": 1101,
            "expected_move_type": "out_invoice",
        }
        for binding_v2, expected_failure in cases:
            with self.subTest(binding_v2=binding_v2):
                company = Company()
                move = document_post_move(
                    company,
                    id=1101,
                    odoo_cli_v3_document_binding_v2=binding_v2,
                )
                result = self.executor(
                    env=DraftCancelEnvironment(move=move)
                )(
                    context(),
                    cap,
                    requested,
                    "c" * 64,
                    "d" * 64,
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(
                    expected_failure,
                    result["eligibility_failures"],
                )

    def test_draft_cancel_eligibility_returns_signed_ineligible_reasons(self) -> None:
        company = Company()
        line = SimpleRecord(
            id=3301,
            move_id=SimpleRecord(id=1101),
            company_id=company,
            parent_state="posted",
            reconciled=True,
        )
        move = pristine_draft_move(
            company,
            state="posted",
            posted_before=True,
            payment_state="paid",
            amount_residual="0.00",
            line_ids=[line],
        )
        env = DraftCancelEnvironment(move=move)
        executor = self.executor(env=env)
        requested = {
            "company_id": 7,
            "move_id": 1101,
            "expected_move_type": "out_invoice",
        }
        cap = capability("acct.move.draft_cancel_eligibility.v1")

        result = executor(context(), cap, requested, "c" * 64, "d" * 64)

        self.assertIs(result["eligible"], False)
        self.assertIsNone(result["write_parameters"])
        self.assertIn("move_is_not_draft", result["eligibility_failures"])
        self.assertIn("posted_before_not_false", result["eligibility_failures"])
        self.assertIn("payment_state_not_not_paid", result["eligibility_failures"])
        self.assertIn("line_reconciliation_or_external_effect_present", result["eligibility_failures"])
        self.assertEqual(result["failed_line_ids"], [3301])
        executor.verify(context(), cap, requested, result, "c" * 64, "d" * 64)

    def test_draft_cancel_eligibility_rejects_cross_company_without_receipt(self) -> None:
        other_company = SimpleRecord(id=8)
        move = pristine_draft_move(other_company)
        env = DraftCancelEnvironment(move=move)
        executor = self.executor(env=env)
        cap = capability("acct.move.draft_cancel_eligibility.v1")

        with mock.patch(
            "odoo_accounting_cli_v3.odoo.executor.create_read_receipt"
        ) as create_receipt:
            with self.assertRaisesRegex(OdooExecutionError, "outside the bound company"):
                executor(
                    context(),
                    cap,
                    {
                        "company_id": 7,
                        "move_id": 1101,
                        "expected_move_type": "out_invoice",
                    },
                    "c" * 64,
                    "d" * 64,
                )

        create_receipt.assert_not_called()

    def test_document_post_eligibility_returns_exact_customer_write_binding(self) -> None:
        move = document_post_move(Company())
        env = MoveEnvironment([move])
        cap = synthetic_read_capability(
            "acct.move.document_post_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 4101,
            "expected_move_type": "out_invoice",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        validate_value(result, cap.data["output_schema"])
        self.assertIs(result["eligible"], True)
        self.assertEqual(result["eligibility_failures"], [])
        self.assertEqual(
            result["candidate_write_capability_id"],
            "acct.invoice.customer_post.v1",
        )
        self.assertEqual(
            result["required_user_parameters"],
            ["idempotency_key", "reason"],
        )
        self.assertEqual(
            result["write_parameters"],
            {
                "company_id": 7,
                "move_id": 4101,
                "expected_move_type": "out_invoice",
                "expected_document_binding": (
                    move.odoo_cli_v3_document_binding
                ),
                "expected_document_binding_v2": (
                    move.odoo_cli_v3_document_binding_v2
                ),
                "expected_business_binding": (
                    move.odoo_cli_v3_business_binding
                ),
                "expected_partner_id": 5101,
                "expected_journal_id": 5201,
                "expected_currency_id": 12,
                "expected_payment_term_line_id": 5302,
                "expected_payment_term_account_id": 5501,
                "expected_invoice_date": "2026-07-13",
                "expected_accounting_date": "2026-07-13",
                "expected_due_date": "2026-07-13",
                "expected_reference": "V3-DOC-4101",
                "expected_amount_untaxed": "100.00",
                "expected_amount_tax": "0.00",
                "expected_amount_total": "100.00",
                "expected_amount_residual": "100.00",
                "expected_line_ids": [5301, 5302],
            },
        )
        self.assertEqual(
            result["target"],
            {
                "company_id": 7,
                "move_id": 4101,
                "move_type": "out_invoice",
                "state": "draft",
                "posted_before": False,
                "payment_state": "not_paid",
                "document_binding": move.odoo_cli_v3_document_binding,
                "document_binding_v2": (
                    move.odoo_cli_v3_document_binding_v2
                ),
                "business_binding": move.odoo_cli_v3_business_binding,
                "partner_id": 5101,
                "journal_id": 5201,
                "currency_id": 12,
                "payment_term_line_id": 5302,
                "payment_term_account_id": 5501,
                "invoice_date": "2026-07-13",
                "accounting_date": "2026-07-13",
                "due_date": "2026-07-13",
                "reference": "V3-DOC-4101",
                "amount_untaxed": "100.00",
                "amount_tax": "0.00",
                "amount_total": "100.00",
                "amount_residual": "100.00",
                "line_ids": [5301, 5302],
                "invoice_line_ids": [5301],
            },
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_document_post_eligibility_rejects_foreign_currency_and_unproved_balances(
        self,
    ) -> None:
        foreign_company = Company()
        foreign_move = document_post_move(foreign_company)
        balance_company = Company()
        balance_move = document_post_move(balance_company)
        balance_move.invoice_line_ids[0].credit = "80"
        balance_move.invoice_line_ids[0].balance = "-80"
        balance_move.line_ids[1].debit = "80"
        balance_move.line_ids[1].balance = "80"

        cases = (
            (
                "foreign_currency",
                foreign_move,
                "document_currency_not_company_currency",
                99,
            ),
            (
                "arbitrary_company_balances",
                balance_move,
                "taxless_financial_and_dependency_graph_not_exact",
                12,
            ),
        )
        for label, move, failure, company_currency_id in cases:
            with self.subTest(label=label):
                env = MoveEnvironment([move])
                env.company.currency_id = SimpleRecord(
                    id=company_currency_id,
                    active=True,
                    rounding="0.01",
                )
                cap = synthetic_read_capability(
                    "acct.move.document_post_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 4101,
                    "expected_move_type": "out_invoice",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                validate_value(result, cap.data["output_schema"])
                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_refund_draft_cancel_eligibility_rejects_missing_or_incompatible_v2(
        self,
    ) -> None:
        cases = (
            (
                "refund_legacy_missing",
                "refund",
                None,
                "refund_legacy_binding_requires_provenance_migration",
            ),
            (
                "refund_incompatible",
                "refund",
                "0" * 64,
                "refund_graph_binding_mismatch",
            ),
            (
                "origin_legacy_missing",
                "origin",
                None,
                "origin_legacy_binding_requires_provenance_migration",
            ),
            (
                "origin_incompatible",
                "origin",
                "0" * 64,
                "origin_graph_binding_mismatch",
            ),
        )
        for label, target, binding_v2, failure in cases:
            with self.subTest(label=label):
                origin, refund = draft_refund_graph(Company())
                record = refund if target == "refund" else origin
                if binding_v2 is None:
                    del record.odoo_cli_v3_document_binding_v2
                else:
                    record.odoo_cli_v3_document_binding_v2 = binding_v2
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.draft_cancel_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }

                result = executor(
                    context(),
                    cap,
                    requested,
                    "c" * 64,
                    "d" * 64,
                )

                validate_value(result, cap.data["output_schema"])
                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                self.assertNotIn(
                    f"{target}_document_binding_v2_invalid",
                    result["eligibility_failures"],
                )
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_document_post_eligibility_signs_fail_closed_reasons(self) -> None:
        company = Company()
        move = document_post_move(
            company,
            state="posted",
            posted_before=True,
            payment_state="paid",
            amount_residual="0.00",
            odoo_cli_v3_document_binding="not-a-binding",
            payment_ids=[SimpleRecord(id=9911)],
        )
        move.line_ids[0].reconciled = True
        env = MoveEnvironment([move])
        cap = synthetic_read_capability(
            "acct.move.document_post_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 4101,
            "expected_move_type": "out_invoice",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        validate_value(result, cap.data["output_schema"])
        self.assertIs(result["eligible"], False)
        self.assertIsNone(result["write_parameters"])
        self.assertIn("move_is_not_draft", result["eligibility_failures"])
        self.assertIn(
            "document_binding_missing_or_invalid",
            result["eligibility_failures"],
        )
        self.assertIn(
            "payment_state_not_not_paid", result["eligibility_failures"]
        )
        self.assertIn(
            "move_payment_or_external_effect_present",
            result["eligibility_failures"],
        )
        self.assertIn(
            "line_reconciliation_or_external_effect_present",
            result["eligibility_failures"],
        )
        self.assertEqual(result["failed_line_ids"], [5301])
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_document_post_eligibility_rejects_zero_value_and_search_only_effects(
        self,
    ) -> None:
        company = Company()
        move = document_post_move(
            company,
            amount_untaxed="0.00",
            amount_tax="0.00",
            amount_total="0.00",
            amount_residual="0.00",
        )
        external = SimpleRecord(id=9951)
        env = MoveEnvironment(
            [move],
            external_effects={"account.partial.reconcile": [external]},
        )
        cap = synthetic_read_capability(
            "acct.move.document_post_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 4101,
            "expected_move_type": "out_invoice",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        self.assertIs(result["eligible"], False)
        self.assertIsNone(result["write_parameters"])
        self.assertIn(
            "document_total_or_residual_not_positive",
            result["eligibility_failures"],
        )
        self.assertIn(
            "move_payment_or_external_effect_present",
            result["eligibility_failures"],
        )
        self.assertEqual(
            external.access_checks,
            [("rights", "read"), ("rule", "read")],
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_document_post_eligibility_accepts_canonical_v2_when_legacy_v1_lexical_order_differs(
        self,
    ) -> None:
        company = Company()
        move = document_post_move(company)
        first_line = move.invoice_line_ids[0]
        term_line = move.line_ids[1]
        first_line.price_unit = "40"
        first_line.price_subtotal = "40"
        first_line.price_total = "40"
        first_line.credit = "40"
        first_line.balance = "-40"
        first_line.amount_currency = "-40"
        second_line = SimpleRecord(
            id=5303,
            move_id=SimpleRecord(id=move.id),
            company_id=company,
            parent_state="draft",
            display_type="product",
            odoo_cli_v3_line_reference="line-2",
            name="Support",
            product_id=False,
            account_id=first_line.account_id,
            partner_id=move.partner_id,
            currency_id=move.currency_id,
            quantity="2",
            price_unit="30",
            price_subtotal="60",
            price_total="60",
            tax_ids=[],
            tax_line_id=False,
            debit="0",
            credit="60",
            balance="-60",
            amount_currency="-60",
            matching_number=False,
            deductible_amount="100",
            date_maturity=False,
            reconciled=False,
        )
        move.invoice_line_ids = [first_line, second_line]
        move.line_ids = [first_line, second_line, term_line]
        source_parameters = {
            "company_id": 7,
            "partner_id": 5101,
            "invoice_date": "2026-07-13",
            "accounting_date": "2026-07-13",
            "due_date": "2026-07-13",
            "currency_id": 12,
            "journal_id": 5201,
            "posting_mode": "draft",
            "reference": "V3-DOC-4101",
            "lines": [
                {
                    "line_reference": "line-2",
                    "name": "Support",
                    "product_id": None,
                    "account_id": 5601,
                    "quantity": "2.00",
                    "price_unit": "30.0",
                    "tax_ids": [],
                },
                {
                    "line_reference": "line-1",
                    "name": "Consulting",
                    "product_id": None,
                    "account_id": 5601,
                    "quantity": "1.000",
                    "price_unit": "40.00",
                    "tax_ids": [],
                },
            ],
        }
        graph_parameters = {
            **source_parameters,
            "lines": [
                {
                    **source_parameters["lines"][1],
                    "quantity": "1",
                    "price_unit": "40",
                },
                {
                    **source_parameters["lines"][0],
                    "quantity": "2",
                    "price_unit": "30",
                },
            ],
        }
        legacy_source_binding = customer_invoice_document_binding(
            source_parameters
        )
        self.assertNotEqual(
            legacy_source_binding,
            customer_invoice_document_binding(graph_parameters),
        )
        move.odoo_cli_v3_document_binding = legacy_source_binding
        move.odoo_cli_v3_document_binding_v2 = (
            customer_invoice_document_binding_v2(source_parameters)
        )
        move.odoo_cli_v3_business_binding = (
            customer_invoice_business_binding(source_parameters)
        )
        env = MoveEnvironment([move])
        cap = synthetic_read_capability(
            "acct.move.document_post_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": move.id,
            "expected_move_type": "out_invoice",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        validate_value(result, cap.data["output_schema"])
        self.assertIs(
            result["eligible"],
            True,
            result["eligibility_failures"],
        )
        self.assertEqual(
            result["write_parameters"]["expected_document_binding"],
            legacy_source_binding,
        )
        self.assertEqual(
            result["write_parameters"]["expected_document_binding_v2"],
            customer_invoice_document_binding_v2(graph_parameters),
        )
        self.assertEqual(
            move.odoo_cli_v3_document_binding,
            legacy_source_binding,
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_document_post_eligibility_rejects_missing_invalid_or_incompatible_v2(
        self,
    ) -> None:
        cases = (
            (
                "legacy_missing",
                None,
                "legacy_binding_requires_provenance_migration",
            ),
            (
                "invalid_v2",
                "not-a-binding",
                "document_binding_v2_invalid",
            ),
            (
                "incompatible_v2",
                "0" * 64,
                "document_graph_binding_mismatch",
            ),
        )
        for index, (label, binding_v2, failure) in enumerate(cases):
            with self.subTest(label=label):
                move = document_post_move(Company(), id=4102 + index)
                if binding_v2 is None:
                    del move.odoo_cli_v3_document_binding_v2
                else:
                    move.odoo_cli_v3_document_binding_v2 = binding_v2
                env = MoveEnvironment([move])
                cap = synthetic_read_capability(
                    "acct.move.document_post_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": move.id,
                    "expected_move_type": "out_invoice",
                }

                result = executor(
                    context(),
                    cap,
                    requested,
                    "c" * 64,
                    "d" * 64,
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                self.assertNotIn(
                    "document_binding_missing_or_invalid",
                    result["eligibility_failures"],
                )
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_document_post_eligibility_supports_only_bound_vendor_bill_path(self) -> None:
        env = MoveEnvironment(
            [document_post_move(Company(), move_type="in_invoice")]
        )
        cap = synthetic_read_capability(
            "acct.move.document_post_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 4101,
            "expected_move_type": "in_invoice",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        validate_value(result, cap.data["output_schema"])
        self.assertIs(result["eligible"], True)
        self.assertEqual(
            result["candidate_write_capability_id"],
            "acct.bill.vendor_post.v1",
        )
        self.assertEqual(
            result["write_parameters"]["expected_move_type"],
            "in_invoice",
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_document_post_eligibility_rejects_write_acl_denials(self) -> None:
        cases = (
            ("move", "move_write_acl_denied"),
            ("line", "line_write_acl_denied"),
            ("partner", "posting_partner_write_acl_denied"),
        )
        for target, failure in cases:
            with self.subTest(target=target):
                move = document_post_move(Company())
                denied = {
                    "move": move,
                    "line": move.line_ids[0],
                    "partner": move.partner_id,
                }[target]
                denied.denied_operations = frozenset({"write"})
                env = MoveEnvironment([move])
                cap = synthetic_read_capability(
                    "acct.move.document_post_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 4101,
                    "expected_move_type": "out_invoice",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_document_post_eligibility_rejects_partner_and_configuration_drift(
        self,
    ) -> None:
        def inactive_partner(move):
            move.partner_id.active = False

        def nonzero_rank(move):
            move.partner_id.customer_rank = 1

        def nonself_commercial(move):
            other = SimpleRecord(
                id=5102,
                company_id=move.company_id,
                active=True,
                customer_rank=0,
            )
            other.commercial_partner_id = other
            move.partner_id.commercial_partner_id = other
            move.commercial_partner_id = other

        def inactive_currency(move):
            move.currency_id.active = False

        def mismatched_journal_currency(move):
            move.journal_id.currency_id = SimpleRecord(
                id=99,
                active=True,
                rounding="0.01",
            )

        cases = (
            (
                "inactive_partner",
                inactive_partner,
                "posting_partner_commercial_rank_or_scope_invalid",
            ),
            (
                "nonzero_rank",
                nonzero_rank,
                "posting_partner_commercial_rank_or_scope_invalid",
            ),
            (
                "nonself_commercial",
                nonself_commercial,
                "posting_partner_commercial_rank_or_scope_invalid",
            ),
            (
                "inactive_currency",
                inactive_currency,
                "currency_journal_or_company_configuration_invalid",
            ),
            (
                "mismatched_journal_currency",
                mismatched_journal_currency,
                "currency_journal_or_company_configuration_invalid",
            ),
        )
        for label, mutate, failure in cases:
            with self.subTest(label=label):
                move = document_post_move(Company())
                mutate(move)
                env = MoveEnvironment([move])
                cap = synthetic_read_capability(
                    "acct.move.document_post_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 4101,
                    "expected_move_type": "out_invoice",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_document_post_eligibility_rejects_lock_and_line_guard_drift(
        self,
    ) -> None:
        def future_date(move):
            move.date = date(2026, 7, 14)

        def violated_lock(move):
            move._get_violated_lock_dates = (
                lambda _date, _affects_tax: ["hard_lock_date"]
            )

        def line_partner(move):
            move.invoice_line_ids[0].partner_id = SimpleRecord(id=5999)

        def line_matching(move):
            move.invoice_line_ids[0].matching_number = "P"

        def line_deductible(move):
            move.invoice_line_ids[0].deductible_amount = "99"

        cases = (
            (
                "future_date",
                future_date,
                "effective_posting_date_in_future",
            ),
            (
                "violated_lock",
                violated_lock,
                "effective_lock_date_violated",
            ),
            (
                "line_partner",
                line_partner,
                "line_partner_matching_or_deductibility_side_effect",
            ),
            (
                "line_matching",
                line_matching,
                "line_partner_matching_or_deductibility_side_effect",
            ),
            (
                "line_deductible",
                line_deductible,
                "line_partner_matching_or_deductibility_side_effect",
            ),
        )
        for label, mutate, failure in cases:
            with self.subTest(label=label):
                move = document_post_move(Company())
                mutate(move)
                env = MoveEnvironment([move])
                cap = synthetic_read_capability(
                    "acct.move.document_post_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 4101,
                    "expected_move_type": "out_invoice",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_refund_draft_cancel_eligibility_returns_exact_origin_graph_binding(self) -> None:
        company = Company()
        origin, refund = draft_refund_graph(company)
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "out_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        self.assertIs(result["eligible"], True)
        self.assertEqual(result["eligibility_failures"], [])
        self.assertEqual(
            result["candidate_write_capability_id"],
            "acct.refund.draft_cancel.v1",
        )
        self.assertEqual(
            result["required_user_parameters"],
            ["idempotency_key", "reason"],
        )
        self.assertEqual(
            result["write_parameters"],
            {
                "company_id": 7,
                "move_id": 6102,
                "expected_move_type": "out_refund",
                "expected_origin_move_id": 6101,
                "expected_document_binding": (
                    refund.odoo_cli_v3_document_binding
                ),
                "expected_document_binding_v2": (
                    refund.odoo_cli_v3_document_binding_v2
                ),
                "expected_business_binding": (
                    refund.odoo_cli_v3_business_binding
                ),
                "expected_origin_document_binding": (
                    origin.odoo_cli_v3_document_binding
                ),
                "expected_origin_document_binding_v2": (
                    origin.odoo_cli_v3_document_binding_v2
                ),
                "expected_origin_business_binding": (
                    origin.odoo_cli_v3_business_binding
                ),
                "expected_partner_id": 6301,
                "expected_journal_id": 6201,
                "expected_currency_id": 12,
                "expected_refund_date": "2026-07-13",
                "expected_total_amount": "100.00",
                "expected_line_ids": [6501, 6502],
                "expected_origin_line_ids": [6401, 6402],
            },
        )
        self.assertEqual(
            result["target"]["refund"]["line_ids"],
            [6501, 6502],
        )
        self.assertEqual(
            result["target"]["origin"]["line_ids"],
            [6401, 6402],
        )
        self.assertEqual(
            result["target"]["origin"]["reversal_move_ids"], [6102]
        )
        self.assertEqual(
            result["target"]["origin"]["source_posting_mode"], "post"
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_refund_draft_cancel_eligibility_accepts_origin_created_draft_then_posted(
        self,
    ) -> None:
        company = Company()
        origin, refund = draft_refund_graph(
            company,
            origin_posting_mode="draft",
        )
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "out_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        validate_value(result, cap.data["output_schema"])
        self.assertIs(result["eligible"], True)
        self.assertEqual(
            result["target"]["origin"]["source_posting_mode"], "draft"
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_refund_draft_cancel_eligibility_rejects_zero_or_ambiguous_origin_provenance(
        self,
    ) -> None:
        company = Company()
        zero_origin, zero_refund = draft_refund_graph(company)
        zero_origin.odoo_cli_v3_document_binding = "0" * 64
        zero_origin.odoo_cli_v3_business_binding = "1" * 64
        cases = (
            (
                "zero_exact_matches",
                zero_origin,
                zero_refund,
                None,
            ),
            (
                "two_exact_matches",
                *draft_refund_graph(company),
                mock.patch(
                    "odoo_accounting_cli_v3.odoo.executor."
                    "_document_graph_binding_candidate",
                    return_value=(
                        zero_origin.odoo_cli_v3_document_binding,
                        zero_origin.odoo_cli_v3_document_binding_v2,
                        zero_origin.odoo_cli_v3_business_binding,
                    ),
                ),
            ),
        )
        for label, origin, refund, binding_patch in cases:
            with self.subTest(label=label):
                if label == "two_exact_matches":
                    origin.odoo_cli_v3_document_binding = (
                        zero_origin.odoo_cli_v3_document_binding
                    )
                    origin.odoo_cli_v3_business_binding = (
                        zero_origin.odoo_cli_v3_business_binding
                    )
                    origin.odoo_cli_v3_document_binding_v2 = (
                        zero_origin.odoo_cli_v3_document_binding_v2
                    )
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.draft_cancel_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }
                if binding_patch is None:
                    result = executor(
                        context(),
                        cap,
                        requested,
                        "c" * 64,
                        "d" * 64,
                    )
                else:
                    with binding_patch:
                        result = executor(
                            context(),
                            cap,
                            requested,
                            "c" * 64,
                            "d" * 64,
                        )

                validate_value(result, cap.data["output_schema"])
                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIsNone(
                    result["target"]["origin"]["source_posting_mode"]
                )
                self.assertIn(
                    "origin_graph_binding_mismatch",
                    result["eligibility_failures"],
                )
                self.assertNotIn(
                    "origin_document_binding_missing_or_invalid",
                    result["eligibility_failures"],
                )
                self.assertNotIn(
                    "origin_business_binding_missing_or_invalid",
                    result["eligibility_failures"],
                )

    def test_refund_draft_cancel_eligibility_rejects_effects_and_origin_drift(self) -> None:
        company = Company()
        origin, refund = draft_refund_graph(company)
        refund.state = "posted"
        refund.posted_before = True
        refund.payment_state = "paid"
        refund.amount_residual = "0.00"
        refund.payment_ids = [SimpleRecord(id=9911)]
        refund.line_ids[0].reconciled = True
        refund.odoo_cli_v3_document_binding = "0" * 64
        origin.reversal_move_ids = []
        origin.payment_ids = [SimpleRecord(id=9912)]
        origin.line_ids[0].matched_debit_ids = [SimpleRecord(id=9913)]
        origin.odoo_cli_v3_document_binding = "not-a-binding"
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "out_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        validate_value(result, cap.data["output_schema"])
        self.assertIs(result["eligible"], False)
        self.assertIsNone(result["write_parameters"])
        self.assertIn("refund_is_not_draft", result["eligibility_failures"])
        self.assertIn(
            "refund_payment_or_external_effect_present",
            result["eligibility_failures"],
        )
        self.assertIn(
            "refund_line_reconciliation_or_external_effect_present",
            result["eligibility_failures"],
        )
        self.assertIn(
            "origin_refund_graph_mismatch",
            result["eligibility_failures"],
        )
        self.assertIn(
            "origin_document_binding_missing_or_invalid",
            result["eligibility_failures"],
        )
        self.assertNotIn(
            "refund_graph_binding_mismatch",
            result["eligibility_failures"],
        )
        self.assertNotIn(
            "refund_document_binding_missing_or_invalid",
            result["eligibility_failures"],
        )
        self.assertIn(
            "origin_payment_or_external_effect_present",
            result["eligibility_failures"],
        )
        self.assertIn(
            "origin_line_reconciliation_or_external_effect_present",
            result["eligibility_failures"],
        )
        self.assertEqual(result["failed_refund_line_ids"], [6501])
        self.assertEqual(result["failed_origin_line_ids"], [6401])
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_refund_draft_cancel_eligibility_supports_vendor_refund_graph(self) -> None:
        company = Company()
        origin, refund = draft_refund_graph(
            company,
            move_type="in_refund",
            refund_mode="partial",
        )
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "in_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        self.assertIs(result["eligible"], True)
        self.assertEqual(
            result["write_parameters"]["expected_move_type"],
            "in_refund",
        )
        self.assertEqual(
            result["target"]["origin"]["move_type"], "in_invoice"
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_refund_draft_cancel_eligibility_supports_child_contact_with_commercial_partner_lines(
        self,
    ) -> None:
        company = Company()
        origin, refund = draft_refund_graph(
            company,
            child_contact=True,
        )
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "out_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        self.assertIs(
            result["eligible"],
            True,
            result["eligibility_failures"],
        )
        self.assertEqual(
            result["write_parameters"]["expected_partner_id"], 6302
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_refund_draft_cancel_eligibility_supports_bound_products_and_currency_rounding(
        self,
    ) -> None:
        cases = (
            {
                "label": "bound_product",
                "with_product": True,
            },
            {
                "label": "rounded_quantity_times_unit_price",
                "origin_quantity": "3",
                "origin_price_unit": "0.333",
                "origin_total": "1.00",
            },
        )
        for case in cases:
            with self.subTest(label=case["label"]):
                company = Company()
                graph_arguments = {
                    key: value
                    for key, value in case.items()
                    if key != "label"
                }
                origin, refund = draft_refund_graph(
                    company, **graph_arguments
                )
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.draft_cancel_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                self.assertIs(
                    result["eligible"],
                    True,
                    result["eligibility_failures"],
                )
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_refund_draft_cancel_eligibility_rejects_acl_and_configuration_drift(
        self,
    ) -> None:
        def refund_acl(_origin, refund):
            refund.denied_operations = frozenset({"write"})

        def refund_line_acl(_origin, refund):
            refund.line_ids[0].denied_operations = frozenset({"write"})

        def inactive_currency(_origin, refund):
            refund.currency_id.active = False

        def mismatched_journal_currency(_origin, refund):
            refund.journal_id.currency_id = SimpleRecord(
                id=99,
                active=True,
                rounding="0.01",
            )

        cases = (
            ("refund_acl", refund_acl, "refund_write_acl_denied"),
            (
                "refund_line_acl",
                refund_line_acl,
                "refund_line_write_acl_denied",
            ),
            (
                "inactive_currency",
                inactive_currency,
                "refund_currency_journal_or_company_configuration_invalid",
            ),
            (
                "mismatched_journal_currency",
                mismatched_journal_currency,
                "refund_currency_journal_or_company_configuration_invalid",
            ),
        )
        for label, mutate, failure in cases:
            with self.subTest(label=label):
                company = Company()
                origin, refund = draft_refund_graph(company)
                mutate(origin, refund)
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.draft_cancel_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_refund_draft_cancel_eligibility_rejects_foreign_currency_or_storno_scope(
        self,
    ) -> None:
        cases = (
            (
                "foreign_currency",
                lambda company: setattr(
                    company,
                    "currency_id",
                    SimpleRecord(
                        id=99,
                        active=True,
                        rounding="0.01",
                    ),
                ),
            ),
            (
                "storno",
                lambda company: setattr(
                    company, "account_storno", True
                ),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                company = Company()
                origin, refund = draft_refund_graph(company)
                env = MoveEnvironment([origin, refund])
                mutate(env.company)
                cap = synthetic_read_capability(
                    "acct.refund.draft_cancel_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(
                    "refund_company_currency_non_storno_scope_invalid",
                    result["eligibility_failures"],
                )
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_refund_draft_cancel_eligibility_rejects_financial_graph_drift(
        self,
    ) -> None:
        def balanced_ninety_nine(origin, refund):
            origin_product, origin_term = origin.line_ids
            refund_product, refund_term = refund.line_ids
            origin_product.credit = "99"
            origin_product.balance = "-99"
            origin_product.amount_currency = "-99"
            origin_term.debit = "99"
            origin_term.balance = "99"
            origin_term.amount_currency = "99"
            origin_term.amount_residual = "99"
            origin_term.amount_residual_currency = "99"
            refund_product.debit = "99"
            refund_product.balance = "99"
            refund_product.amount_currency = "99"
            refund_term.credit = "99"
            refund_term.balance = "-99"
            refund_term.amount_currency = "-99"
            refund_term.amount_residual = "-99"
            refund_term.amount_residual_currency = "-99"

        cases = (
            (
                "full_missing_line_reference",
                "full",
                lambda origin, refund: delattr(
                    refund.invoice_line_ids[0],
                    "odoo_cli_v3_line_reference",
                ),
                "refund_graph_binding_mismatch",
            ),
            (
                "origin_zero_total_and_residual",
                "full",
                lambda origin, _refund: (
                    setattr(origin, "amount_total", "0.00"),
                    setattr(origin, "amount_residual", "0.00"),
                ),
                "origin_total_or_residual_not_positive",
            ),
            (
                "full_linewise_name_drift",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "name",
                    "Drifted refund line",
                ),
                "full_refund_linewise_reversal_not_exact",
            ),
            (
                "full_line_reference_replaced",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "odoo_cli_v3_line_reference",
                    "replacement-line-1",
                ),
                "full_refund_invoice_lineage_not_exact",
            ),
            (
                "full_quantity_price_inverse_drift",
                "full",
                lambda _origin, refund: (
                    setattr(refund.invoice_line_ids[0], "quantity", "2"),
                    setattr(refund.invoice_line_ids[0], "price_unit", "50"),
                ),
                "full_refund_invoice_lineage_not_exact",
            ),
            (
                "full_tax_tag_lineage_drift",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "tax_tag_ids",
                    [9901],
                ),
                "refund_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "full_tax_repartition_lineage_drift",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "tax_repartition_line_id",
                    SimpleRecord(id=9902),
                ),
                "refund_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "full_group_tax_lineage_drift",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "group_tax_id",
                    SimpleRecord(id=9903),
                ),
                "refund_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "origin_tax_base_drift",
                "full",
                lambda origin, _refund: setattr(
                    origin.invoice_line_ids[0],
                    "tax_base_amount",
                    "1",
                ),
                "origin_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "refund_extra_tax_data_drift",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "extra_tax_data",
                    {"tax": "unapproved"},
                ),
                "refund_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "origin_temporary_matching_number",
                "full",
                lambda origin, _refund: setattr(
                    origin.invoice_line_ids[0],
                    "matching_number",
                    "I-import-batch",
                ),
                "origin_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "refund_temporary_matching_number",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "matching_number",
                    "I-import-batch",
                ),
                "refund_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "origin_partial_deductibility",
                "full",
                lambda origin, _refund: setattr(
                    origin.invoice_line_ids[0],
                    "deductible_amount",
                    "50",
                ),
                "origin_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "refund_partial_deductibility",
                "full",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "deductible_amount",
                    "50",
                ),
                "refund_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "balanced_ninety_nine_accounting_drift",
                "full",
                balanced_ninety_nine,
                "origin_taxless_financial_dependency_graph_not_exact",
            ),
            (
                "partial_line_total_drift",
                "partial",
                lambda _origin, refund: setattr(
                    refund.invoice_line_ids[0],
                    "price_total",
                    "39",
                ),
                "refund_taxless_financial_dependency_graph_not_exact",
            ),
        )
        for label, refund_mode, mutate, failure in cases:
            with self.subTest(label=label):
                company = Company()
                origin, refund = draft_refund_graph(
                    company,
                    refund_mode=refund_mode,
                )
                mutate(origin, refund)
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.draft_cancel_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                executor.verify(
                    context(),
                    cap,
                    requested,
                    result,
                    "c" * 64,
                    "d" * 64,
                )

    def test_partial_refund_draft_cancel_eligibility_requires_auditable_origin_line_relation(
        self,
    ) -> None:
        company = Company()
        origin, refund = draft_refund_graph(
            company, refund_mode="partial"
        )
        refund.invoice_line_ids[0].odoo_cli_v3_line_reference = (
            "unrelated-line-1"
        )
        source = {
            "company_id": 7,
            "origin_move_id": 6101,
            "refund_type": "customer_credit_note",
            "refund_mode": "partial",
            "refund_date": "2026-07-13",
            "journal_id": 6201,
            "currency_id": 12,
            "expected_total_amount": "40",
            "reason": "V3 refund",
            "posting_mode": "draft",
            "lines": [
                {
                    "line_reference": "unrelated-line-1",
                    "name": "Consulting",
                    "account_id": 6601,
                    "quantity": "1",
                    "price_unit": "40",
                    "tax_ids": [],
                }
            ],
        }
        (
            refund.odoo_cli_v3_document_binding,
            refund.odoo_cli_v3_document_binding_v2,
            refund.odoo_cli_v3_business_binding,
        ) = _refund_bindings(source)
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "out_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        self.assertIs(result["eligible"], False)
        self.assertIsNone(result["write_parameters"])
        self.assertIn(
            "partial_refund_origin_line_relation_not_exact",
            result["eligibility_failures"],
        )
        self.assertNotIn(
            "refund_graph_binding_mismatch",
            result["eligibility_failures"],
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_partial_refund_draft_cancel_eligibility_rejects_total_above_origin(
        self,
    ) -> None:
        company = Company()
        origin, refund = draft_refund_graph(
            company, refund_mode="partial"
        )
        invoice_line, term_line = refund.line_ids
        refund.amount_untaxed = "120.00"
        refund.amount_total = "120.00"
        refund.amount_residual = "120.00"
        invoice_line.price_unit = "120"
        invoice_line.price_subtotal = "120"
        invoice_line.price_total = "120"
        invoice_line.debit = "120"
        invoice_line.balance = "120"
        invoice_line.amount_currency = "120"
        term_line.credit = "120"
        term_line.balance = "-120"
        term_line.amount_currency = "-120"
        source = {
            "company_id": 7,
            "origin_move_id": 6101,
            "refund_type": "customer_credit_note",
            "refund_mode": "partial",
            "refund_date": "2026-07-13",
            "journal_id": 6201,
            "currency_id": 12,
            "expected_total_amount": "120",
            "reason": "V3 refund",
            "posting_mode": "draft",
            "lines": [
                {
                    "line_reference": "origin-line-1",
                    "name": "Consulting",
                    "account_id": 6601,
                    "quantity": "1",
                    "price_unit": "120",
                    "tax_ids": [],
                }
            ],
        }
        (
            refund.odoo_cli_v3_document_binding,
            refund.odoo_cli_v3_document_binding_v2,
            refund.odoo_cli_v3_business_binding,
        ) = _refund_bindings(source)
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "out_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        self.assertIs(result["eligible"], False)
        self.assertIsNone(result["write_parameters"])
        self.assertIn(
            "partial_refund_total_exceeds_origin",
            result["eligibility_failures"],
        )
        self.assertNotIn(
            "refund_graph_binding_mismatch",
            result["eligibility_failures"],
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_new_eligibility_handlers_reject_non_exact_integer_ids_without_receipt(
        self,
    ) -> None:
        company = Company()
        origin, refund = draft_refund_graph(company)
        cases = (
            (
                MoveEnvironment([document_post_move(company)]),
                "acct.move.document_post_eligibility.v1",
                {
                    "company_id": 7.0,
                    "move_id": 4101,
                    "expected_move_type": "out_invoice",
                },
            ),
            (
                MoveEnvironment([origin, refund]),
                "acct.refund.draft_cancel_eligibility.v1",
                {
                    "company_id": 7,
                    "move_id": 6102.0,
                    "expected_move_type": "out_refund",
                },
            ),
        )
        for env, capability_id, requested in cases:
            with self.subTest(capability_id=capability_id):
                cap = synthetic_read_capability(capability_id)
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                with mock.patch(
                    "odoo_accounting_cli_v3.odoo.executor.create_read_receipt"
                ) as create_receipt:
                    with self.assertRaises(OdooExecutionError):
                        executor(
                            context(),
                            cap,
                            requested,
                            "c" * 64,
                            "d" * 64,
                        )
                create_receipt.assert_not_called()

    def test_refund_draft_cancel_eligibility_rejects_cross_company_origin_without_receipt(
        self,
    ) -> None:
        company = Company()
        origin, refund = draft_refund_graph(company)
        origin.company_id = SimpleRecord(id=8)
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.draft_cancel_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))

        with mock.patch(
            "odoo_accounting_cli_v3.odoo.executor.create_read_receipt"
        ) as create_receipt:
            with self.assertRaisesRegex(
                OdooExecutionError, "origin is outside the bound company"
            ):
                executor(
                    context(),
                    cap,
                    {
                        "company_id": 7,
                        "move_id": 6102,
                        "expected_move_type": "out_refund",
                    },
                    "c" * 64,
                    "d" * 64,
                )

        create_receipt.assert_not_called()

    def test_registry_list_omits_capabilities_missing_any_required_group(self) -> None:
        document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        trial_balance = next(
            item
            for item in document["capabilities"]
            if item["id"] == "acct.gl.trial_balance.v1"
        )
        trial_balance["odoo_permissions"] = [
            "base.group_user",
            "account.group_account_readonly",
        ]
        registry = validate_registry(document)
        env = Environment(groups={"base.group_user"})
        result = self.executor(env=env, registry=registry)(
            context(),
            capability("acct.registry.list.v1"),
            {"company_id": 7},
            "c" * 64,
            "d" * 64,
        )
        self.assertEqual(
            [item["id"] for item in result["capabilities"]],
            [
                "acct.diagnostics.operation_read.v1",
                "acct.registry.list.v1",
            ],
        )

    def test_ar_open_items_executes_trusted_handler_and_verifies_receipt(self) -> None:
        executor = self.executor()
        requested = {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": None,
            "currency_id": None,
            "limit": 100,
            "offset": 0,
        }
        ar_capability = capability("acct.ar.open_items.v1")

        result = executor(
            context(), ar_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(result["ledger_summary"]["net_residual"], "70.00")
        self.assertEqual(result["receipt"]["record_count"], 1)
        self.assertEqual(result["receipt"]["capability_id"], "acct.ar.open_items.v1")
        executor.verify(
            context(), ar_capability, requested, result, "c" * 64, "d" * 64
        )

    def test_ap_open_items_executes_payable_handler_and_verifies_receipt(self) -> None:
        executor = self.executor()
        requested = {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": None,
            "currency_id": None,
            "limit": 100,
            "offset": 0,
        }
        ap_capability = capability("acct.ap.open_items.v1")

        result = executor(
            context(), ap_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(result["ledger_summary"]["net_residual"], "-70.00")
        self.assertEqual(result["items"][0]["move_type"], "in_invoice")
        self.assertEqual(result["receipt"]["record_count"], 1)
        self.assertEqual(result["receipt"]["capability_id"], "acct.ap.open_items.v1")
        executor.verify(
            context(), ap_capability, requested, result, "c" * 64, "d" * 64
        )

    def test_multicurrency_executes_booked_balance_handler_and_verifies_receipt(self) -> None:
        executor = self.executor()
        requested = {
            "company_id": 7,
            "as_of_date": "2026-07-13",
            "currency_ids": [6, 1],
            "balance_basis": "posted_ledger_cumulative",
            "off_balance_policy": "exclude",
            "limit": 100,
            "offset": 0,
        }
        multicurrency_capability = capability("acct.multicurrency.balance_read.v1")

        result = executor(
            context(), multicurrency_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(result["balances"][0]["ledger_company_balance"], "1950.00")
        self.assertEqual(result["balances"][0]["ledger_transaction_amount"], "300.00")
        self.assertEqual(result["rates"][1]["transaction_to_company_rate"], "6.5")
        self.assertEqual(result["receipt"]["record_count"], 1)
        self.assertEqual(
            result["receipt"]["capability_id"],
            "acct.multicurrency.balance_read.v1",
        )
        executor.verify(
            context(), multicurrency_capability, requested, result, "c" * 64, "d" * 64
        )

    def test_financial_report_executes_native_handler_and_verifies_receipt(self) -> None:
        executor = self.executor()
        requested = {
            "company_id": 7,
            "report_request": {
                "kind": "balance_sheet",
                "comparison": {
                    "mode": "previous_period",
                    "periods": 1,
                },
            },
            "date_from": "2026-01-01",
            "date_to": "2026-06-30",
            "move_state": "posted",
            "journal_scope": "all_report_eligible",
            "tax_unit_id": None,
            "unreconciled_only": False,
            "hide_zero_lines": False,
            "line_expansion_request": "none",
            "currency_id": 12,
            "limit": 100,
            "offset": 0,
        }
        report_capability = capability("acct.report.financial_read.v1")

        result = executor(
            context(), report_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(result["report"]["family"], "financial")
        self.assertEqual(
            result["lines"][0]["columns"][0]["cell"]["value"],
            "100",
        )
        self.assertEqual(result["receipt"]["record_count"], 1)
        executor.verify(
            context(), report_capability, requested, result, "c" * 64, "d" * 64
        )

    def test_tax_report_keeps_unproven_source_count_unavailable(self) -> None:
        executor = self.executor()
        requested = {
            "company_id": 7,
            "date_from": "2026-01-01",
            "date_to": "2026-06-30",
            "move_state": "posted",
            "journal_scope": "all_report_eligible",
            "tax_unit_id": None,
            "unreconciled_only": False,
            "hide_zero_lines": False,
            "line_expansion_request": "none",
            "currency_id": 12,
            "limit": 100,
            "offset": 0,
        }
        report_capability = capability("acct.tax.report_read.v1")

        result = executor(
            context(), report_capability, requested, "c" * 64, "d" * 64
        )

        self.assertEqual(result["report"]["family"], "tax")
        self.assertEqual(
            result["lines"][0]["source_move_line_count"],
            {"available": False, "count": None},
        )
        self.assertEqual(
            result["warnings"],
            ["odoo:tax_source_move_line_count_unavailable"],
        )
        executor.verify(
            context(), report_capability, requested, result, "c" * 64, "d" * 64
        )

    def test_refund_post_reconcile_eligibility_binds_full_and_partial_outcomes(
        self,
    ) -> None:
        cases = (
            ("out_refund", "full", "100.00", "0.00", "reversed"),
            ("in_refund", "full", "100.00", "0.00", "reversed"),
            ("out_refund", "partial", "40.00", "60.00", "partial"),
            ("in_refund", "partial", "40.00", "60.00", "partial"),
        )
        for (
            move_type,
            refund_mode,
            refund_total,
            origin_residual_after,
            origin_payment_state_after,
        ) in cases:
            with self.subTest(move_type=move_type, refund_mode=refund_mode):
                company = Company()
                origin, refund = draft_refund_graph(
                    company,
                    move_type=move_type,
                    refund_mode=refund_mode,
                )
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.post_reconcile_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": move_type,
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                validate_value(result, cap.data["output_schema"])
                self.assertIs(result["eligible"], True)
                self.assertEqual(result["eligibility_failures"], [])
                self.assertEqual(
                    result["candidate_write_capability_id"],
                    "acct.refund.post_reconcile_origin.v1",
                )
                self.assertEqual(
                    result["required_user_parameters"],
                    ["idempotency_key", "reason"],
                )
                self.assertEqual(
                    result["write_parameters"],
                    {
                        "company_id": 7,
                        "move_id": 6102,
                        "expected_move_type": move_type,
                        "expected_origin_move_id": 6101,
                        "expected_document_binding": (
                            refund.odoo_cli_v3_document_binding
                        ),
                        "expected_document_binding_v2": (
                            refund.odoo_cli_v3_document_binding_v2
                        ),
                        "expected_business_binding": (
                            refund.odoo_cli_v3_business_binding
                        ),
                        "expected_origin_document_binding": (
                            origin.odoo_cli_v3_document_binding
                        ),
                        "expected_origin_document_binding_v2": (
                            origin.odoo_cli_v3_document_binding_v2
                        ),
                        "expected_origin_business_binding": (
                            origin.odoo_cli_v3_business_binding
                        ),
                        "expected_source_refund_mode": refund_mode,
                        "expected_partner_id": 6301,
                        "expected_commercial_partner_id": 6301,
                        "expected_journal_id": 6201,
                        "expected_currency_id": 12,
                        "expected_refund_date": "2026-07-13",
                        "expected_total_amount": refund_total,
                        "expected_origin_total_amount": "100.00",
                        "expected_reconcile_amount": refund_total,
                        "expected_refund_payment_term_line_id": 6502,
                        "expected_origin_payment_term_line_id": 6402,
                        "expected_payment_term_account_id": 6602,
                        "expected_reconciliation_outcome": (
                            "partial_origin_reduction"
                            if refund_mode == "partial"
                            else "full_origin_reversal"
                        ),
                        "expected_refund_payment_state_after": "paid",
                        "expected_origin_payment_state_after": (
                            origin_payment_state_after
                        ),
                        "expected_refund_residual_after": "0.00",
                        "expected_origin_residual_after": (
                            origin_residual_after
                        ),
                        "expected_line_ids": [6501, 6502],
                        "expected_origin_line_ids": [6401, 6402],
                    },
                )
                executor.verify(
                    context(), cap, requested, result, "c" * 64, "d" * 64
                )

    def test_refund_post_reconcile_eligibility_binds_selected_and_commercial_partner(
        self,
    ) -> None:
        company = Company()
        origin, refund = draft_refund_graph(
            company,
            child_contact=True,
        )
        env = MoveEnvironment([origin, refund])
        cap = synthetic_read_capability(
            "acct.refund.post_reconcile_eligibility.v1"
        )
        executor = self.executor(env=env, registry=registry_with(cap))
        requested = {
            "company_id": 7,
            "move_id": 6102,
            "expected_move_type": "out_refund",
        }

        result = executor(
            context(), cap, requested, "c" * 64, "d" * 64
        )

        validate_value(result, cap.data["output_schema"])
        self.assertIs(result["eligible"], True)
        self.assertEqual(result["write_parameters"]["expected_partner_id"], 6302)
        self.assertEqual(
            result["write_parameters"]["expected_commercial_partner_id"],
            6301,
        )
        executor.verify(
            context(), cap, requested, result, "c" * 64, "d" * 64
        )

    def test_refund_post_reconcile_eligibility_accepts_rank_from_posted_origin(
        self,
    ) -> None:
        for move_type, rank_field in (
            ("out_refund", "customer_rank"),
            ("in_refund", "supplier_rank"),
        ):
            with self.subTest(move_type=move_type, rank_field=rank_field):
                company = Company()
                origin, refund = draft_refund_graph(
                    company,
                    move_type=move_type,
                )
                setattr(refund.partner_id, rank_field, 2)
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.post_reconcile_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": move_type,
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                validate_value(result, cap.data["output_schema"])
                self.assertIs(result["eligible"], True)
                self.assertEqual(result["eligibility_failures"], [])
                self.assertEqual(
                    result["write_parameters"]["expected_origin_move_id"],
                    6101,
                )

    def test_refund_post_reconcile_eligibility_uses_origin_accounting_date(
        self,
    ) -> None:
        for origin_accounting_date, expected_eligible in (
            ("2026-07-14", False),
            ("2026-07-12", True),
        ):
            with self.subTest(
                origin_accounting_date=origin_accounting_date,
                expected_eligible=expected_eligible,
            ):
                company = Company()
                origin, refund = draft_refund_graph(
                    company,
                    origin_invoice_date="2026-07-10",
                    origin_accounting_date=origin_accounting_date,
                    refund_date="2026-07-13",
                )
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.post_reconcile_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                validate_value(result, cap.data["output_schema"])
                self.assertIs(result["eligible"], expected_eligible)
                if expected_eligible:
                    self.assertEqual(result["eligibility_failures"], [])
                    self.assertEqual(
                        result["write_parameters"]["expected_refund_date"],
                        "2026-07-13",
                    )
                else:
                    self.assertIsNone(result["write_parameters"])
                    self.assertIn(
                        "refund_date_precedes_or_lacks_origin_date",
                        result["eligibility_failures"],
                    )

    def test_refund_post_reconcile_eligibility_rejects_incompatible_graphs(
        self,
    ) -> None:
        def full_amount_drift(origin, refund):
            refund.amount_total = "40.00"
            refund.amount_residual = "40.00"

        def wrong_term_line(_origin, refund):
            refund.line_ids[1].display_type = "product"

        def prior_reconciliation(origin, _refund):
            origin.line_ids[1].matched_debit_ids = [SimpleRecord(id=7001)]

        def nonreconcilable_term(_origin, refund):
            refund.line_ids[1].account_id.reconcile = False

        def reconcilable_business_account(_origin, refund):
            refund.line_ids[0].account_id.reconcile = True

        def cash_business_account(_origin, refund):
            refund.line_ids[0].account_id.account_type = "asset_cash"

        def violated_lock_date(_origin, refund):
            refund._get_violated_lock_dates = (
                lambda _date, _affects_tax: ["hard_lock_date"]
            )

        def missing_posted_origin_rank(_origin, refund):
            refund.partner_id.customer_rank = 0

        cases = (
            (
                "full_amount_drift",
                "full",
                "100",
                full_amount_drift,
                "source_refund_mode_or_amount_incompatible",
            ),
            (
                "partial_not_less_than_origin",
                "partial",
                "40",
                lambda _origin, _refund: None,
                "partial_refund_must_reduce_origin",
            ),
            (
                "wrong_term_line",
                "full",
                "100",
                wrong_term_line,
                "payment_term_graph_not_exact",
            ),
            (
                "prior_reconciliation",
                "full",
                "100",
                prior_reconciliation,
                "refund_or_origin_already_reconciled",
            ),
            (
                "nonreconcilable_term",
                "full",
                "100",
                nonreconcilable_term,
                "payment_term_account_not_reconcilable",
            ),
            (
                "reconcilable_business_account",
                "full",
                "100",
                reconcilable_business_account,
                "nonterm_account_reconciliation_unsafe",
            ),
            (
                "cash_business_account",
                "full",
                "100",
                cash_business_account,
                "nonterm_account_reconciliation_unsafe",
            ),
            (
                "violated_lock_date",
                "full",
                "100",
                violated_lock_date,
                "effective_lock_date_violated",
            ),
            (
                "missing_posted_origin_rank",
                "full",
                "100",
                missing_posted_origin_rank,
                "posting_partner_commercial_rank_or_scope_invalid",
            ),
        )
        for label, refund_mode, origin_total, mutate, failure in cases:
            with self.subTest(label=label):
                company = Company()
                origin, refund = draft_refund_graph(
                    company,
                    refund_mode=refund_mode,
                    origin_total=origin_total,
                )
                mutate(origin, refund)
                env = MoveEnvironment([origin, refund])
                cap = synthetic_read_capability(
                    "acct.refund.post_reconcile_eligibility.v1"
                )
                executor = self.executor(
                    env=env, registry=registry_with(cap)
                )
                requested = {
                    "company_id": 7,
                    "move_id": 6102,
                    "expected_move_type": "out_refund",
                }

                result = executor(
                    context(), cap, requested, "c" * 64, "d" * 64
                )

                validate_value(result, cap.data["output_schema"])
                self.assertIs(result["eligible"], False)
                self.assertIsNone(result["write_parameters"])
                self.assertIn(failure, result["eligibility_failures"])
                executor.verify(
                    context(), cap, requested, result, "c" * 64, "d" * 64
                )


if __name__ == "__main__":
    unittest.main()

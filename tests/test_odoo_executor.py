import hashlib
import json
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest import mock

from odoo_accounting_cli_v3.domain.ar_open_items import (
    CurrencyInfo as ArCurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
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
    NativeReportFilters,
    NativeReportLine,
    NativeReportPeriod,
    NativeReportSnapshot,
    canonical_period_key,
)
from odoo_accounting_cli_v3.domain.trial_balance import AccountInfo, Aggregate, CurrencyInfo
from odoo_accounting_cli_v3.gateway import RequestContext
from odoo_accounting_cli_v3.odoo.executor import OdooExecutionError, OdooReadExecutor
from odoo_accounting_cli_v3.registry import validate_registry


REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "capabilities.json"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)
RECEIPT_KEY_ID = "test-receipt-2026-07"


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
    def __init__(self, **values):
        self.__dict__.update(values)
        self.access_checks = []

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


class RecordModel:
    def __init__(self, records):
        self._records = records

    def browse(self, record_id):
        return self._records.get(record_id, MissingCompany())


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
        self.move = move or pristine_draft_move(self.company)

    def __getitem__(self, name):
        if name == "res.company":
            return self.company
        if name == "account.move":
            return RecordModel({self.move.id: self.move})
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
                "acct.gl.trial_balance.v1",
                "acct.multicurrency.balance_read.v1",
                "acct.registry.list.v1",
                "acct.report.financial_read.v1",
                "acct.tax.report_read.v1",
            ],
        )
        self.assertEqual(result["page"], {"count": 7, "total_count": 7})
        self.assertEqual(result["receipt"]["record_count"], 7)
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
                "expected_document_binding": "a" * 64,
                "expected_business_binding": "b" * 64,
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
                "journal_id": 2201,
                "currency_id": 12,
                "line_ids": [3301],
                "document_binding": "a" * 64,
                "business_binding": "b" * 64,
            },
        )
        self.assertEqual(result["receipt"]["record_count"], 1)
        self.assertEqual(env.company.access_checks, [("rights", "read"), ("rule", "read")])
        self.assertEqual(env.move.access_checks, [("rights", "read"), ("rule", "read")])
        self.assertEqual(
            env.move.line_ids[0].access_checks, [("rights", "read"), ("rule", "read")]
        )
        executor.verify(context(), cap, requested, result, "c" * 64, "d" * 64)

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
            ["acct.registry.list.v1"],
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


if __name__ == "__main__":
    unittest.main()

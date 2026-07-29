"""Contract tests for the Odoo native-report adapter."""

from __future__ import annotations

import copy
import unittest
from datetime import date
from types import SimpleNamespace
from unittest import mock

from odoo_accounting_cli_v3.domain.report_read import (
    NativeReportDefinitionBinding,
    ReportReadError,
)
from odoo_accounting_cli_v3.odoo.report_read import OdooReportReadBackend


REQUIRED_READ_MODELS = (
    "account.account",
    "account.journal",
    "account.move",
    "account.move.line",
    "account.report",
    "account.report.expression",
    "account.report.line",
    "account.tax",
    "account.tax.group",
    "account.tax.repartition.line",
    "res.currency",
)


class DefinitionGuard:
    def __init__(self):
        self.calls = []

    def verify_pre(self, **values):
        self.calls.append(("pre", copy.deepcopy(values)))
        return {"definition_sha256": "1" * 64}

    def verify_post(self, observation, **values):
        self.calls.append(
            ("post", copy.deepcopy(observation), copy.deepcopy(values))
        )
        return NativeReportDefinitionBinding(
            schema_version=1,
            definition_sha256=observation["definition_sha256"],
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


class Missing:
    id = False

    def exists(self):
        return self

    def __bool__(self):
        return False

    def __len__(self):
        return 0


class Recordset:
    def __init__(self, records, *, model_name):
        self.records = list(records)
        self._name = model_name
        self.access = []
        self.rights_error = None
        self.rule_error = None

    @property
    def ids(self):
        return [record.id for record in self.records]

    def exists(self):
        return self

    def __bool__(self):
        return bool(self.records)

    def __len__(self):
        return len(self.records)

    def __iter__(self):
        return iter(self.records)

    def check_access_rights(self, operation):
        self.access.append(("rights", operation))
        if self.rights_error is not None:
            raise self.rights_error

    def check_access_rule(self, operation):
        self.access.append(("rule", operation))
        if self.rule_error is not None:
            raise self.rule_error

    def mapped(self, field):
        return [getattr(record, field) for record in self.records]


class Record:
    _name = "account.report"

    def __init__(self, record_id, **values):
        self.id = record_id
        self.access = []
        self.rights_error = None
        self.rule_error = None
        self.__dict__.update(values)

    def exists(self):
        return self

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def check_access_rights(self, operation):
        self.access.append(("rights", operation))
        if self.rights_error is not None:
            raise self.rights_error

    def check_access_rule(self, operation):
        self.access.append(("rule", operation))
        if self.rule_error is not None:
            raise self.rule_error


class Report(Record):
    def __init__(
        self,
        record_id,
        *,
        name,
        root_report_id=False,
        definition_line_ids=(501, 502),
        expression_engines=None,
    ):
        if expression_engines is None:
            expression_engines = (
                ("aggregation", "domain") if definition_line_ids else ()
            )
        expressions = Recordset(
            [
                Record(record_id * 10_000 + index, engine=engine)
                for index, engine in enumerate(
                    expression_engines,
                    start=1,
                )
            ],
            model_name="account.report.expression",
        )
        lines = Recordset(
            [Record(line_id) for line_id in definition_line_ids],
            model_name="account.report.line",
        )
        lines.expression_ids = expressions
        super().__init__(
            record_id,
            name=name,
            root_report_id=root_report_id,
            active=True,
            use_sections=False,
            section_report_ids=Recordset([], model_name="account.report"),
            line_ids=lines,
            filter_period_comparison=True,
        )
        self.options = {}
        self.information = {}
        self.company_ids = [7]
        self.previous_options = None
        self.readonly_calls = 0
        self.readonly_options = None
        self.markups = {}
        self.get_options_hook = None
        self.readonly_hook = None

    def get_options(self, previous_options):
        self.previous_options = copy.deepcopy(previous_options)
        if self.get_options_hook is not None:
            self.get_options_hook()
        return copy.deepcopy(self.options)

    def get_report_company_ids(self, _options):
        return list(self.company_ids)

    def get_report_information_readonly(self, _options):
        self.readonly_calls += 1
        self.readonly_options = _options
        if self.readonly_hook is not None:
            self.readonly_hook(_options)
        return copy.deepcopy(self.information)

    def get_report_information(self, _options):
        raise AssertionError("ordinary report API must never be called")

    def _get_markup(self, raw_id):
        return self.markups.get(raw_id, "line")


class Model:
    def __init__(self, records, *, model_name):
        self.records = records
        self.model_name = model_name
        self.contexts = []
        self.companies = []
        self.rights = []
        self.rights_error = None
        self.browse_calls = []
        self.searches = []
        self.last_browse_recordset = None
        self.last_search_recordset = None

    def with_context(self, **context):
        self.contexts.append(context)
        return self

    def with_company(self, company):
        self.companies.append(company.id)
        return self

    def browse(self, record_id):
        self.browse_calls.append(copy.deepcopy(record_id))
        if isinstance(record_id, list):
            self.last_browse_recordset = Recordset(
                [
                    self.records[item]
                    for item in record_id
                    if item in self.records
                ],
                model_name=self.model_name,
            )
            return self.last_browse_recordset
        return self.records.get(record_id, Missing())

    def search(self, domain, *, order, limit):
        self.searches.append((copy.deepcopy(domain), order, limit))
        records = [
            self.records[record_id]
            for record_id in sorted(self.records)
        ][:limit]
        self.last_search_recordset = Recordset(
            records,
            model_name=self.model_name,
        )
        return self.last_search_recordset

    def check_access_rights(self, operation):
        self.rights.append(operation)
        if self.rights_error is not None:
            raise self.rights_error


class Environment:
    def __init__(
        self,
        *,
        uid=42,
        su=False,
        requested_id=1,
        resolved_id=None,
        requested_definition_line_ids=(501, 502),
        resolved_definition_line_ids=None,
        options=None,
        information=None,
    ):
        self.uid = uid
        self.su = su
        self.transaction = SimpleNamespace(
            field_dirty=set(),
            tocompute={},
            field_data_patches={},
        )
        currency = Record(
            12,
            name="CNY",
            symbol="¥",
            rounding=0.01,
        )
        currency._name = "res.currency"
        currency.symbol = "\N{YEN SIGN}"
        self.company = Record(
            7,
            name="Demo Company",
            currency_id=currency,
        )
        self.company._name = "res.company"
        self.requested = Report(
            requested_id,
            name="Requested report",
            definition_line_ids=requested_definition_line_ids,
        )
        self.resolved = self.requested
        records = {requested_id: self.requested}
        if resolved_id is not None and resolved_id != requested_id:
            self.resolved = Report(
                resolved_id,
                name="Resolved variant",
                root_report_id=self.requested,
                definition_line_ids=(
                    (601, 602)
                    if resolved_definition_line_ids is None
                    else resolved_definition_line_ids
                ),
            )
            records[resolved_id] = self.resolved
        self.requested.options = options or {}
        self.resolved.information = information or {}
        journals = {}
        for journal_id in (12, 11):
            journal = Record(journal_id, company_id=self.company)
            journal._name = "account.journal"
            journals[journal_id] = journal
        model_records = {
            model_name: {}
            for model_name in REQUIRED_READ_MODELS
        }
        model_records["res.currency"] = {12: currency}
        model_records["account.report"] = records
        model_records["account.journal"] = journals
        self.models = {
            model_name: Model(records_by_id, model_name=model_name)
            for model_name, records_by_id in model_records.items()
        }
        self.models["res.company"] = Model(
            {7: self.company},
            model_name="res.company",
        )
        self.refs = {}

    def __getitem__(self, model_name):
        return self.models[model_name]

    def ref(self, xmlid, *, raise_if_not_found):
        if raise_if_not_found is not False:
            raise AssertionError("XML-ID lookup must be non-raising")
        return self.refs.get(xmlid, Missing())


def period(mode="range", date_from="2026-04-01", date_to="2026-06-30"):
    return {
        "currency_table_period_key": f"{date_from}_{date_to}",
        "date_from": date_from,
        "date_to": date_to,
        "filter": "custom",
        "mode": mode,
        "string": "2026 Q2",
    }


def tax_payload():
    current = period()
    group = "odoo|current~group"
    options = {
        "report_id": 1,
        "variants_source_id": 1,
        "selected_variant_id": 1,
        "sections_source_id": 1,
        "sections": [],
        "available_variants": [{"id": 1}],
        "readonly_query": True,
        "unfold_all": False,
        "unfolded_lines": [],
        "all_entries": False,
        "unreconciled": False,
        "hide_0_lines": False,
        "hierarchy": False,
        "aml_ir_filters": [],
        "consolidation": False,
        "multi_currency": False,
        "selected_horizontal_group_id": None,
        "available_horizontal_groups": [],
        "rounding_unit": "decimals",
        "rounding_unit_names": {"decimals": "Decimals"},
        "currency_table": {
            "periods": {},
            "type": "monocurrency",
        },
        "date": current,
        "comparison": {
            "filter": "no_comparison",
            "number_period": 1,
            "periods": [],
        },
        "column_groups": {
            group: {
                "forced_options": {"date": current},
                "forced_domain": [],
            },
        },
        "columns": [
            {
                "column_group_key": group,
                "expression_label": "net",
                "figure_type": "monetary",
                "name": "Net",
            },
            {
                "column_group_key": group,
                "expression_label": "tax",
                "figure_type": "monetary",
                "name": "Tax",
            },
        ],
    }
    information = {
        "report": {
            "name": "Requested report",
            "root_report_id": None,
            "company_name": "Demo Company",
            "company_currency_symbol": "\N{YEN SIGN}",
        },
        "warnings": {},
        "lines": [
            {
                "id": "~account.report~1|sale~~",
                "code": False,
                "name": "Sales",
                "level": 0,
                "columns": [
                    {
                        "report_line_id": 501,
                        "no_format": "",
                        "column_group_key": group,
                        "expression_label": "net",
                        "figure_type": "monetary",
                        "currency": False,
                        "auditable": False,
                    },
                    {
                        "report_line_id": 501,
                        "no_format": 1150.44,
                        "column_group_key": group,
                        "expression_label": "tax",
                        "figure_type": "monetary",
                        "currency": False,
                        "auditable": False,
                    },
                ],
                "unfoldable": False,
                "unfolded": False,
            },
            {
                "id": "~account.report~1|sale~~|~account.tax~5",
                "parent_id": "~account.report~1|sale~~",
                "name": "13% tax",
                "level": 2,
                "columns": [
                    {
                        "report_line_id": 502,
                        "no_format": 8849.56,
                        "column_group_key": group,
                        "expression_label": "net",
                        "figure_type": "monetary",
                        "currency": False,
                        "auditable": False,
                    },
                    {
                        "report_line_id": 502,
                        "no_format": 1150.44,
                        "column_group_key": group,
                        "expression_label": "tax",
                        "figure_type": "monetary",
                        "currency": False,
                        "auditable": False,
                    },
                ],
                "unfoldable": False,
                "unfolded": False,
            },
        ],
    }
    return options, information


def financial_payload():
    current = period(
        mode="single",
        date_from="2026-06-01",
        date_to="2026-06-30",
    )
    previous = {
        key: value
        for key, value in period(
            mode="single",
            date_from="2026-05-01",
            date_to="2026-05-31",
        ).items()
        if key != "filter"
    }
    current_group = "current~group"
    previous_group = "previous|group"
    options = {
        "report_id": 23,
        "variants_source_id": 22,
        "selected_variant_id": 23,
        "sections_source_id": 23,
        "sections": [],
        "available_variants": [{"id": 22}, {"id": 23}],
        "readonly_query": True,
        "unfold_all": False,
        "unfolded_lines": [],
        "all_entries": False,
        "unreconciled": False,
        "hide_0_lines": False,
        "hierarchy": False,
        "aml_ir_filters": [],
        "consolidation": False,
        "multi_currency": False,
        "selected_horizontal_group_id": None,
        "available_horizontal_groups": [],
        "rounding_unit": "decimals",
        "rounding_unit_names": {"decimals": "Decimals"},
        "currency_table": {
            "periods": {},
            "type": "monocurrency",
        },
        "selected_journal_groups": {},
        "journals": [
            {
                "id": 12,
                "model": "account.journal",
                "selected": False,
            },
            {
                "id": 11,
                "model": "account.journal",
                "selected": False,
            },
        ],
        "analytic_accounts_groupby": [],
        "analytic_plans_groupby": [],
        "selected_analytic_account_groupby_names": [],
        "selected_analytic_plan_groupby_names": [],
        "include_analytic_without_aml": False,
        "date": current,
        "comparison": {
            "filter": "previous_period",
            "number_period": 1,
            "periods": [previous],
        },
        "column_groups": {
            current_group: {
                "forced_options": {"date": current},
                "forced_domain": [],
            },
            previous_group: {
                "forced_options": {"date": previous},
                "forced_domain": [],
            },
        },
        "columns": [
            {
                "column_group_key": current_group,
                "expression_label": "balance",
                "figure_type": "monetary",
                "name": "Balance",
            },
            {
                "column_group_key": previous_group,
                "expression_label": "balance",
                "figure_type": "monetary",
                "name": "Balance",
            },
        ],
    }
    information = {
        "report": {
            "name": "Resolved variant",
            "root_report_id": 22,
            "company_name": "Demo Company",
            "company_currency_symbol": "\N{YEN SIGN}",
        },
        "warnings": {},
        "lines": [
            {
                "id": "~account.report~22|~account.report.line~73",
                "code": "TA",
                "name": "ASSETS",
                "level": 0,
                "columns": [
                    {
                        "report_line_id": 601,
                        "no_format": -11025.0,
                        "column_group_key": current_group,
                        "expression_label": "balance",
                        "figure_type": "monetary",
                        "currency": False,
                        "auditable": True,
                    },
                    {
                        "report_line_id": 601,
                        "no_format": None,
                        "column_group_key": previous_group,
                        "expression_label": "balance",
                        "figure_type": "monetary",
                        "currency": False,
                        "auditable": False,
                    },
                ],
                "unfoldable": False,
                "unfolded": True,
            },
        ],
    }
    return options, information


def set_report_line_identity(information, report_line_id):
    for line in information["lines"]:
        for column in line["columns"]:
            column["report_line_id"] = report_line_id


def cash_flow_payload():
    options, information = tax_payload()
    options.update(
        {
            "report_id": 23,
            "variants_source_id": 23,
            "selected_variant_id": 23,
            "sections_source_id": 23,
            "available_variants": [{"id": 23}],
            "journals": [
                {
                    "id": 11,
                    "model": "account.journal",
                    "selected": False,
                },
                {
                    "id": 12,
                    "model": "account.journal",
                    "selected": False,
                },
            ],
        }
    )
    del options["comparison"]
    information["report"] = {
        "name": "Requested report",
        "root_report_id": None,
        "company_name": "Demo Company",
        "company_currency_symbol": "\N{YEN SIGN}",
    }
    set_report_line_identity(information, None)
    return options, information


def fixed_filters():
    return {
        "move_state": "posted",
        "journal_scope": "all_report_eligible",
        "tax_unit_id": None,
        "unreconciled_only": False,
        "hide_zero_lines": False,
        "line_expansion_request": "none",
    }


def fetch_tax_report(backend):
    return backend.fetch_native_report(
        company_id=7,
        report_family="tax",
        report_kind="generic_tax",
        date_from=date(2026, 4, 1),
        date_to=date(2026, 6, 30),
        comparison_mode=None,
        comparison_periods=None,
        currency_id=12,
        **fixed_filters(),
    )


def fetch_balance_sheet(backend):
    return backend.fetch_native_report(
        company_id=7,
        report_family="financial",
        report_kind="balance_sheet",
        date_from=date(2026, 4, 1),
        date_to=date(2026, 6, 30),
        comparison_mode="previous_period",
        comparison_periods=1,
        currency_id=12,
        **fixed_filters(),
    )


def fetch_cash_flow(backend, *, comparison=False):
    return backend.fetch_native_report(
        company_id=7,
        report_family="financial",
        report_kind="cash_flow",
        date_from=date(2026, 4, 1),
        date_to=date(2026, 6, 30),
        comparison_mode=("previous_period" if comparison else None),
        comparison_periods=(1 if comparison else None),
        currency_id=12,
        **fixed_filters(),
    )


class OdooReportReadBackendTest(unittest.TestCase):
    @staticmethod
    def backend(
        environment,
        *,
        family,
        xmlid,
        allowed_company_ids=frozenset({7}),
        definition_guard=None,
    ):
        environment.refs[xmlid] = environment.requested
        return OdooReportReadBackend(
            environment,
            user_id=42,
            allowed_company_ids=allowed_company_ids,
            database_uuid="11111111-1111-4111-8111-111111111111",
            allowed_root_xmlids_by_family={
                family: frozenset({xmlid}),
            },
            definition_guard=definition_guard or DefinitionGuard(),
        )

    def test_definition_baseline_rejection_happens_before_native_report_api(self):
        class RejectPre(DefinitionGuard):
            def verify_pre(self, **values):
                super().verify_pre(**values)
                raise ReportReadError("approved report definition baseline is unavailable")

        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        backend = self.backend(
            environment,
            family="tax",
            xmlid="account.generic_tax_report",
            definition_guard=RejectPre(),
        )

        with self.assertRaisesRegex(ReportReadError, "baseline is unavailable"):
            fetch_tax_report(backend)
        self.assertIsNone(environment.requested.previous_options)
        self.assertEqual(environment.requested.readonly_calls, 0)

    def test_default_definition_guard_fails_closed_without_approved_baseline(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        environment.refs["account.generic_tax_report"] = environment.requested
        backend = OdooReportReadBackend(
            environment,
            user_id=42,
            allowed_company_ids=frozenset({7}),
            database_uuid="11111111-1111-4111-8111-111111111111",
            release_digest="d" * 64,
            allowed_root_xmlids_by_family={
                "tax": frozenset({"account.generic_tax_report"}),
            },
        )

        with self.assertRaisesRegex(ReportReadError, "baseline is unavailable"):
            fetch_tax_report(backend)
        self.assertIsNone(environment.requested.previous_options)
        self.assertEqual(environment.requested.readonly_calls, 0)

    def test_definition_post_drift_discards_native_report_result(self):
        class RejectPost(DefinitionGuard):
            def verify_post(self, observation, **values):
                super().verify_post(observation, **values)
                raise ReportReadError("report definition changed during execution")

        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        backend = self.backend(
            environment,
            family="tax",
            xmlid="account.generic_tax_report",
            definition_guard=RejectPost(),
        )

        with self.assertRaisesRegex(ReportReadError, "changed during execution"):
            fetch_tax_report(backend)
        self.assertEqual(environment.requested.readonly_calls, 1)

    def test_tax_report_uses_only_bound_readonly_native_api(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        backend = self.backend(
            environment,
            family="tax",
            xmlid="account.generic_tax_report",
        )

        backend.assert_read_access(company_id=7)
        currency = backend.company_currency(company_id=7)
        snapshot = backend.fetch_native_report(
            company_id=7,
            report_family="tax",
            report_kind="generic_tax",
            date_from=date(2026, 4, 1),
            date_to=date(2026, 6, 30),
            comparison_mode=None,
            comparison_periods=None,
            currency_id=12,
            **fixed_filters(),
        )

        self.assertEqual(currency.id, 12)
        self.assertEqual(snapshot.requested_report_id, 1)
        self.assertEqual(snapshot.resolved_report_id, 1)
        self.assertEqual(snapshot.report_family, "tax")
        self.assertEqual(snapshot.report_kind, "generic_tax")
        self.assertEqual(snapshot.effective_filters.journal_ids, (11, 12))
        self.assertEqual(
            snapshot.warnings,
            ("odoo:tax_source_move_line_count_unavailable",),
        )
        self.assertEqual(snapshot.lines[0].raw_id, "~account.report~1|sale~~")
        self.assertIsNone(snapshot.lines[0].code)
        self.assertTrue(snapshot.lines[0].columns[0].is_blank)
        self.assertIsNone(snapshot.lines[0].columns[0].value)
        self.assertEqual(snapshot.lines[0].columns[1].value, 1150.44)
        self.assertRegex(
            snapshot.lines[0].columns[0].period_key,
            r"^period-[0-9a-f]{64}$",
        )
        self.assertEqual(
            snapshot.lines[0].columns[0].period_key,
            snapshot.period_key,
        )
        journal_records = environment.models[
            "account.journal"
        ].last_search_recordset
        self.assertIsNotNone(journal_records)
        self.assertEqual(
            journal_records.access,
            [("rights", "read"), ("rule", "read")],
        )
        self.assertEqual(environment.requested.readonly_calls, 1)
        self.assertEqual(
            environment.requested.previous_options,
            {
                "forced_companies": [7],
                "date": {
                    "filter": "custom",
                    "mode": "range",
                    "date_from": "2026-04-01",
                    "date_to": "2026-06-30",
                },
                "comparison": {
                    "filter": "no_comparison",
                    "number_period": 1,
                },
                "export_mode": "file",
                "unfold_all": False,
                "unfolded_lines": [],
                "all_entries": False,
                "unreconciled": False,
                "hide_0_lines": False,
                "hierarchy": False,
                "readonly_query": True,
            },
        )
        for model in environment.models.values():
            self.assertIn(
                {
                    "allowed_company_ids": [7],
                    "company_id": 7,
                },
                model.contexts,
            )

    def test_every_required_model_acl_is_checked_and_denied_individually(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        backend = self.backend(
            environment,
            family="tax",
            xmlid="account.generic_tax_report",
        )

        backend.assert_read_access(company_id=7)

        self.assertEqual(
            set(environment.models) - {"res.company"},
            set(REQUIRED_READ_MODELS),
        )
        for model_name in REQUIRED_READ_MODELS:
            self.assertEqual(environment.models[model_name].rights, ["read"])

        for model_name in REQUIRED_READ_MODELS:
            with self.subTest(model_name=model_name):
                options, information = tax_payload()
                denied = Environment(
                    options=options,
                    information=information,
                )
                denied.models[model_name].rights_error = PermissionError(
                    "model ACL denied"
                )
                backend = self.backend(
                    denied,
                    family="tax",
                    xmlid="account.generic_tax_report",
                )
                with self.assertRaisesRegex(
                    PermissionError,
                    "model ACL denied",
                ):
                    backend.assert_read_access(company_id=7)

    def test_financial_variant_and_normalized_period_are_explicit(self):
        options, information = financial_payload()
        environment = Environment(
            requested_id=22,
            resolved_id=23,
            options=options,
            information=information,
        )
        backend = self.backend(
            environment,
            family="financial",
            xmlid="account_reports.balance_sheet",
        )

        snapshot = backend.fetch_native_report(
            company_id=7,
            report_family="financial",
            report_kind="balance_sheet",
            date_from=date(2026, 4, 1),
            date_to=date(2026, 6, 30),
            comparison_mode="previous_period",
            comparison_periods=1,
            currency_id=12,
            **fixed_filters(),
        )

        self.assertEqual(snapshot.requested_report_id, 22)
        self.assertEqual(snapshot.resolved_report_id, 23)
        self.assertEqual(snapshot.report_kind, "balance_sheet")
        self.assertEqual(snapshot.date_mode, "single")
        self.assertEqual(snapshot.date_from.isoformat(), "2026-06-01")
        self.assertEqual(
            snapshot.warnings,
            (
                "odoo:date_range_normalized",
                "odoo:report_variant_resolved",
            ),
        )
        self.assertEqual(snapshot.comparison_mode, "previous_period")
        self.assertEqual(snapshot.comparison_periods, 1)
        self.assertEqual(len(snapshot.resolved_comparison_periods), 1)
        self.assertEqual(
            snapshot.resolved_comparison_periods[0].date_to.isoformat(),
            "2026-05-31",
        )
        self.assertEqual(snapshot.effective_filters.move_state, "posted")
        self.assertEqual(
            snapshot.effective_filters.journal_ids,
            (11, 12),
        )
        self.assertEqual(len(snapshot.lines[0].columns), 2)
        self.assertEqual(
            snapshot.lines[0].columns[0].period_key,
            snapshot.period_key,
        )
        self.assertEqual(
            snapshot.lines[0].columns[1].period_key,
            snapshot.resolved_comparison_periods[0].key,
        )
        journal_records = environment.models[
            "account.journal"
        ].last_browse_recordset
        self.assertIsNotNone(journal_records)
        self.assertEqual(
            journal_records.access,
            [("rights", "read"), ("rule", "read")],
        )
        self.assertTrue(snapshot.lines[0].columns[1].is_blank)
        self.assertIsNone(snapshot.lines[0].columns[1].value)
        self.assertEqual(environment.requested.readonly_calls, 0)
        self.assertEqual(environment.resolved.readonly_calls, 1)

    def test_comparison_count_and_each_child_filter_are_bound(self):
        cases = (
            (
                "number_period",
                lambda options: options["comparison"].__setitem__(
                    "number_period",
                    2,
                ),
                "comparison context changed",
            ),
            (
                "child_filter",
                lambda options: options["comparison"]["periods"][
                    0
                ].__setitem__("filter", "same_last_year"),
                "comparison period is invalid",
            ),
        )
        for label, mutate, error in cases:
            with self.subTest(case=label):
                options, information = financial_payload()
                mutate(options)
                environment = Environment(
                    requested_id=22,
                    resolved_id=23,
                    options=options,
                    information=information,
                )
                backend = self.backend(
                    environment,
                    family="financial",
                    xmlid="account_reports.balance_sheet",
                )

                with self.assertRaisesRegex(ReportReadError, error):
                    fetch_balance_sheet(backend)

    def test_default_deny_requires_a_trusted_family_root(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        backend = OdooReportReadBackend(
            environment,
            user_id=42,
            allowed_company_ids=frozenset({7}),
            database_uuid="11111111-1111-4111-8111-111111111111",
            definition_guard=DefinitionGuard(),
        )

        with self.assertRaisesRegex(
            ReportReadError,
            "no trusted root allowlist",
        ):
            backend.fetch_native_report(
                company_id=7,
                report_family="tax",
                report_kind="generic_tax",
                date_from=date(2026, 4, 1),
                date_to=date(2026, 6, 30),
                comparison_mode=None,
                comparison_periods=None,
                currency_id=12,
                **fixed_filters(),
            )

    def test_report_without_comparison_support_accepts_only_no_comparison(self):
        options, information = cash_flow_payload()
        environment = Environment(
            requested_id=23,
            requested_definition_line_ids=(),
            options=options,
            information=information,
        )
        backend = self.backend(
            environment,
            family="financial",
            xmlid="account_reports.cash_flow_report",
        )

        snapshot = fetch_cash_flow(backend)
        self.assertEqual(snapshot.resolved_comparison_periods, ())
        self.assertEqual(
            {
                column["report_line_id"]
                for line in information["lines"]
                for column in line["columns"]
            },
            {None},
        )

        with self.assertRaisesRegex(
            ReportReadError,
            "cash-flow comparison",
        ):
            fetch_cash_flow(backend, comparison=True)

    def test_superuser_uid_and_signed_company_mismatches_are_rejected(self):
        options, information = tax_payload()
        cases = (
            (
                Environment(su=True, options=options, information=information),
                frozenset({7}),
                7,
                "non-superuser",
            ),
            (
                Environment(uid=43, options=options, information=information),
                frozenset({7}),
                7,
                "non-superuser",
            ),
            (
                Environment(options=options, information=information),
                frozenset({8}),
                7,
                "outside the authenticated",
            ),
        )
        for environment, companies, company_id, error in cases:
            with self.subTest(error=error, uid=environment.uid, su=environment.su):
                backend = self.backend(
                    environment,
                    family="tax",
                    xmlid="account.generic_tax_report",
                    allowed_company_ids=companies,
                )
                with self.assertRaisesRegex(ReportReadError, error):
                    backend.assert_read_access(company_id=company_id)

    def test_report_root_sections_and_acl_fail_closed(self):
        options, information = tax_payload()

        wrong_root = Environment(options=options, information=information)
        wrong_root.requested.root_report_id = Record(99, name="Other root")
        backend = self.backend(
            wrong_root,
            family="tax",
            xmlid="account.generic_tax_report",
        )
        with self.assertRaisesRegex(ReportReadError, "root is invalid"):
            backend.fetch_native_report(
                company_id=7,
                report_family="tax",
                report_kind="generic_tax",
                date_from=date(2026, 4, 1),
                date_to=date(2026, 6, 30),
                comparison_mode=None,
                comparison_periods=None,
                currency_id=12,
                **fixed_filters(),
            )

    def test_allowed_expansion_functions_are_not_load_more_markers(self):
        for expand_function in (
            None,
            "_report_expand_unfoldable_line_with_groupby",
        ):
            with self.subTest(expand_function=expand_function):
                options, information = tax_payload()
                information["lines"][0]["expand_function"] = expand_function
                environment = Environment(
                    options=options,
                    information=information,
                )
                snapshot = fetch_tax_report(
                    self.backend(
                        environment,
                        family="tax",
                        xmlid="account.generic_tax_report",
                    )
                )
                self.assertEqual(len(snapshot.lines), 2)

        for marker in ("offset", "progress"):
            with self.subTest(marker=marker):
                options, information = tax_payload()
                information["lines"][0][marker] = 1
                environment = Environment(
                    options=options,
                    information=information,
                )
                with self.assertRaisesRegex(
                    ReportReadError,
                    "truncated load-more",
                ):
                    fetch_tax_report(
                        self.backend(
                            environment,
                            family="tax",
                            xmlid="account.generic_tax_report",
                        )
                    )

        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        environment.requested.markups[
            information["lines"][0]["id"]
        ] = "load_more"
        with self.assertRaisesRegex(ReportReadError, "truncated load-more"):
            fetch_tax_report(
                self.backend(
                    environment,
                    family="tax",
                    xmlid="account.generic_tax_report",
                )
            )

    def test_reviewed_draft_warning_is_mapped_to_stable_code(self):
        options, information = tax_payload()
        information["warnings"] = {
            "account_reports.common_warning_draft_in_period": {}
        }
        environment = Environment(options=options, information=information)

        snapshot = fetch_tax_report(
            self.backend(
                environment,
                family="tax",
                xmlid="account.generic_tax_report",
            )
        )

        self.assertEqual(
            snapshot.warnings,
            (
                "odoo:draft_entries_excluded",
                "odoo:tax_source_move_line_count_unavailable",
            ),
        )

    def test_transaction_state_is_clean_at_all_readonly_boundaries(self):
        def dirty_before(environment):
            environment.transaction.field_dirty.add("account.move.name")

        def dirty_after_options(environment):
            environment.requested.get_options_hook = lambda: (
                environment.transaction.tocompute.update({"account.move": 1})
            )

        def dirty_after_execution(environment):
            environment.requested.readonly_hook = lambda _options: (
                environment.transaction.field_data_patches.update(
                    {"account.move": 1}
                )
            )

        for setup, stage in (
            (dirty_before, "before native report preparation"),
            (dirty_after_options, "after native report options"),
            (dirty_after_execution, "after native report execution"),
        ):
            with self.subTest(stage=stage):
                options, information = tax_payload()
                environment = Environment(
                    options=options,
                    information=information,
                )
                setup(environment)
                with self.assertRaisesRegex(ReportReadError, stage):
                    fetch_tax_report(
                        self.backend(
                            environment,
                            family="tax",
                            xmlid="account.generic_tax_report",
                        )
                    )

    def test_native_readonly_call_cannot_mutate_options_in_place(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)

        def mutate_nested_options(native_options):
            native_options["date"]["date_from"] = "2026-04-02"

        environment.requested.readonly_hook = mutate_nested_options
        backend = self.backend(
            environment,
            family="tax",
            xmlid="account.generic_tax_report",
        )

        with self.assertRaisesRegex(
            ReportReadError,
            "options changed during execution",
        ):
            fetch_tax_report(backend)
        self.assertEqual(environment.requested.readonly_calls, 1)

    def test_expression_engines_and_xmlid_model_fail_closed(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        expressions = environment.requested.line_ids.expression_ids
        expressions.records[0].engine = "python"
        with self.assertRaisesRegex(ReportReadError, "engine"):
            fetch_tax_report(
                self.backend(
                    environment,
                    family="tax",
                    xmlid="account.generic_tax_report",
                )
            )

        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        wrong_model = Record(1, name="Not a report")
        wrong_model._name = "res.company"
        environment.refs["account.generic_tax_report"] = wrong_model
        backend = OdooReportReadBackend(
            environment,
            user_id=42,
            allowed_company_ids=frozenset({7}),
            database_uuid="11111111-1111-4111-8111-111111111111",
            allowed_root_xmlids_by_family={
                "tax": frozenset({"account.generic_tax_report"}),
            },
            definition_guard=DefinitionGuard(),
        )
        with self.assertRaisesRegex(ReportReadError, "root is invalid"):
            fetch_tax_report(backend)

    def test_report_definition_line_and_expression_rules_fail_closed(self):
        targets = (
            ("requested_line", "requested", "line_ids"),
            (
                "requested_expression",
                "requested",
                "expression_ids",
            ),
            ("resolved_line", "resolved", "line_ids"),
            (
                "resolved_expression",
                "resolved",
                "expression_ids",
            ),
        )
        for label, report_name, target_name in targets:
            with self.subTest(target=label):
                options, information = financial_payload()
                environment = Environment(
                    requested_id=22,
                    resolved_id=23,
                    options=options,
                    information=information,
                )
                report = getattr(environment, report_name)
                target = report.line_ids
                if target_name == "expression_ids":
                    target = target.expression_ids
                target.rule_error = PermissionError(
                    "definition record rule denied"
                )
                backend = self.backend(
                    environment,
                    family="financial",
                    xmlid="account_reports.balance_sheet",
                )

                with self.assertRaisesRegex(
                    PermissionError,
                    "definition record rule denied",
                ):
                    fetch_balance_sheet(backend)
                self.assertIn(("rights", "read"), target.access)
                self.assertIn(("rule", "read"), target.access)

    def test_distinct_report_kinds_cannot_share_one_trusted_root(self):
        options, information = financial_payload()
        environment = Environment(
            requested_id=22,
            resolved_id=23,
            options=options,
            information=information,
        )
        environment.refs["account_reports.balance_sheet"] = (
            environment.requested
        )
        environment.refs["account_reports.profit_and_loss"] = (
            environment.requested
        )
        backend = OdooReportReadBackend(
            environment,
            user_id=42,
            allowed_company_ids=frozenset({7}),
            database_uuid="11111111-1111-4111-8111-111111111111",
            allowed_root_xmlids_by_family={
                "financial": frozenset(
                    {
                        "account_reports.balance_sheet",
                        "account_reports.profit_and_loss",
                    }
                )
            },
            definition_guard=DefinitionGuard(),
        )

        with self.assertRaises(ReportReadError):
            backend.fetch_native_report(
                company_id=7,
                report_family="financial",
                report_kind="profit_and_loss",
                date_from=date(2026, 4, 1),
                date_to=date(2026, 6, 30),
                comparison_mode="previous_period",
                comparison_periods=1,
                currency_id=12,
                **fixed_filters(),
            )

    def test_distinct_report_families_cannot_share_one_trusted_root(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        environment.refs["account.generic_tax_report"] = (
            environment.requested
        )
        environment.refs["account_reports.balance_sheet"] = (
            environment.requested
        )
        backend = OdooReportReadBackend(
            environment,
            user_id=42,
            allowed_company_ids=frozenset({7}),
            database_uuid="11111111-1111-4111-8111-111111111111",
            allowed_root_xmlids_by_family={
                "tax": frozenset({"account.generic_tax_report"}),
                "financial": frozenset(
                    {"account_reports.balance_sheet"}
                ),
            },
            definition_guard=DefinitionGuard(),
        )

        with self.assertRaisesRegex(ReportReadError, "roots collide"):
            fetch_tax_report(backend)

    def test_requested_report_is_derived_from_the_trusted_root(self):
        options, information = financial_payload()
        environment = Environment(
            requested_id=22,
            resolved_id=23,
            options=options,
            information=information,
        )
        backend = self.backend(
            environment,
            family="financial",
            xmlid="account_reports.balance_sheet",
        )

        snapshot = fetch_balance_sheet(backend)

        self.assertEqual(snapshot.requested_report_id, 22)
        self.assertEqual(snapshot.resolved_report_id, 23)
        self.assertEqual(
            environment.models["account.report"].browse_calls,
            [22, 22, 23],
        )

    def test_variant_and_report_information_identity_fail_closed(self):
        option_identity_cases = (
            ("variants_source_id", 99),
            ("selected_variant_id", 22),
            ("sections_source_id", 22),
            ("sections", [{"id": 999}]),
        )
        for field, value in option_identity_cases:
            with self.subTest(option_identity=field):
                options, information = financial_payload()
                options[field] = value
                environment = Environment(
                    requested_id=22,
                    resolved_id=23,
                    options=options,
                    information=information,
                )
                with self.assertRaisesRegex(
                    ReportReadError,
                    "variant identity changed",
                ):
                    fetch_balance_sheet(
                        self.backend(
                            environment,
                            family="financial",
                            xmlid="account_reports.balance_sheet",
                        )
                    )

        for label, variants in (
            ("missing_resolved", [{"id": 22}]),
            ("duplicate", [{"id": 23}, {"id": 23}]),
            ("non_mapping", [{"id": 22}, "23"]),
        ):
            with self.subTest(available_variants=label):
                options, information = financial_payload()
                options["available_variants"] = variants
                environment = Environment(
                    requested_id=22,
                    resolved_id=23,
                    options=options,
                    information=information,
                )
                with self.assertRaisesRegex(
                    ReportReadError,
                    "variants are invalid",
                ):
                    fetch_balance_sheet(
                        self.backend(
                            environment,
                            family="financial",
                            xmlid="account_reports.balance_sheet",
                        )
                    )

        information_identity_cases = (
            ("name", "Other report"),
            ("root_report_id", 99),
            ("company_name", "Other company"),
            ("company_currency_symbol", "USD"),
        )
        for field, value in information_identity_cases:
            with self.subTest(information_identity=field):
                options, information = financial_payload()
                information["report"][field] = value
                environment = Environment(
                    requested_id=22,
                    resolved_id=23,
                    options=options,
                    information=information,
                )
                with self.assertRaisesRegex(
                    ReportReadError,
                    "information identity changed",
                ):
                    fetch_balance_sheet(
                        self.backend(
                            environment,
                            family="financial",
                            xmlid="account_reports.balance_sheet",
                        )
                    )

    def test_forced_domain_column_identity_currency_and_budget_fail_closed(self):
        def forced_domain(options, _information):
            group = next(iter(options["column_groups"].values()))
            group["forced_domain"] = [("company_id", "=", 8)]

        def period_identity(_options, information):
            information["lines"][0]["columns"][0][
                "column_group_key"
            ] = "other-period"

        def expression_identity(_options, information):
            information["lines"][0]["columns"][0][
                "expression_label"
            ] = "other-expression"

        def currency_missing(_options, information):
            del information["lines"][0]["columns"][0]["currency"]

        def currency_record(_options, information):
            information["lines"][0]["columns"][0]["currency"] = Record(12)

        def currency_id_added(_options, information):
            information["lines"][0]["columns"][0]["currency_id"] = 12

        def invalid_option_currency(options, _information):
            options["columns"][0]["currency_id"] = "12"

        def selected_budget(options, _information):
            options["budgets"] = [{"id": 3, "selected": True}]

        def multicurrency_table(options, _information):
            options["currency_table"]["type"] = "multi"

        def monocurrency_with_period_rates(options, _information):
            options["currency_table"]["periods"] = {
                "attacker-controlled": {"rate": 999}
            }

        cases = (
            (forced_domain, "column group"),
            (period_identity, "period identity"),
            (expression_identity, "expression identity"),
            (currency_missing, "monocurrency shape"),
            (currency_record, "monocurrency shape"),
            (currency_id_added, "monocurrency shape"),
            (invalid_option_currency, "currency_id"),
            (selected_budget, "budget scope"),
            (multicurrency_table, "read-only options"),
            (monocurrency_with_period_rates, "read-only options"),
        )
        for mutation, message in cases:
            with self.subTest(message=message):
                options, information = tax_payload()
                mutation(options, information)
                environment = Environment(
                    options=options,
                    information=information,
                )
                with self.assertRaisesRegex(ReportReadError, message):
                    fetch_tax_report(
                        self.backend(
                            environment,
                            family="tax",
                            xmlid="account.generic_tax_report",
                        )
                    )

    def test_report_line_id_is_bound_to_visible_report_definitions(self):
        def missing(information):
            del information["lines"][0]["columns"][0]["report_line_id"]

        def boolean(information):
            information["lines"][0]["columns"][0][
                "report_line_id"
            ] = True

        def foreign(information):
            information["lines"][0]["columns"][0][
                "report_line_id"
            ] = 999

        def mixed_row(information):
            information["lines"][0]["columns"][1][
                "report_line_id"
            ] = 502

        cases = (
            (missing, "definition identity is unavailable"),
            (boolean, "definition identity changed"),
            (foreign, "definition identity changed"),
            (mixed_row, "spans multiple report definitions"),
        )
        for mutate, error in cases:
            with self.subTest(error=error):
                options, information = tax_payload()
                mutate(information)
                environment = Environment(
                    options=options,
                    information=information,
                )
                with self.assertRaisesRegex(ReportReadError, error):
                    fetch_tax_report(
                        self.backend(
                            environment,
                            family="tax",
                            xmlid="account.generic_tax_report",
                        )
                    )

    def test_empty_tax_and_cash_flow_definitions_require_none_identity(self):
        options, information = tax_payload()
        set_report_line_identity(information, None)
        tax_environment = Environment(
            requested_definition_line_ids=(),
            options=options,
            information=information,
        )
        tax_snapshot = fetch_tax_report(
            self.backend(
                tax_environment,
                family="tax",
                xmlid="account.generic_tax_report",
            )
        )
        self.assertEqual(len(tax_snapshot.lines), 2)

        options, information = cash_flow_payload()
        cash_environment = Environment(
            requested_id=23,
            requested_definition_line_ids=(),
            options=options,
            information=information,
        )
        cash_snapshot = fetch_cash_flow(
            self.backend(
                cash_environment,
                family="financial",
                xmlid="account_reports.cash_flow_report",
            )
        )
        self.assertEqual(len(cash_snapshot.lines), 2)

        for report_kind in ("tax", "cash_flow"):
            with self.subTest(non_null_dynamic_identity=report_kind):
                if report_kind == "tax":
                    options, information = tax_payload()
                    set_report_line_identity(information, None)
                    environment = Environment(
                        requested_definition_line_ids=(),
                        options=options,
                        information=information,
                    )
                    backend = self.backend(
                        environment,
                        family="tax",
                        xmlid="account.generic_tax_report",
                    )
                    call = lambda: fetch_tax_report(backend)
                else:
                    options, information = cash_flow_payload()
                    environment = Environment(
                        requested_id=23,
                        requested_definition_line_ids=(),
                        options=options,
                        information=information,
                    )
                    backend = self.backend(
                        environment,
                        family="financial",
                        xmlid="account_reports.cash_flow_report",
                    )
                    call = lambda: fetch_cash_flow(backend)
                information["lines"][0]["columns"][0][
                    "report_line_id"
                ] = 501

                with self.assertRaisesRegex(
                    ReportReadError,
                    "dynamic report line identity changed",
                ):
                    call()

    def test_adapter_budgets_are_rejected_before_line_materialization(self):
        options, information = tax_payload()
        information["lines"].append(copy.deepcopy(information["lines"][0]))
        environment = Environment(options=options, information=information)
        environment.requested.line_ids.records = (
            environment.requested.line_ids.records[:1]
        )
        environment.requested.line_ids.expression_ids.records = (
            environment.requested.line_ids.expression_ids.records[:1]
        )
        environment.requested._get_markup = mock.Mock(
            side_effect=AssertionError("markup must not be called")
        )
        with mock.patch(
            "odoo_accounting_cli_v3.odoo.report_read.MAX_REPORT_LINES",
            1,
        ):
            with self.assertRaisesRegex(ReportReadError, "lines"):
                fetch_tax_report(
                    self.backend(
                        environment,
                        family="tax",
                        xmlid="account.generic_tax_report",
                    )
                )
        environment.requested._get_markup.assert_not_called()

        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        environment.requested.line_ids.expression_ids.records = (
            environment.requested.line_ids.expression_ids.records[:1]
        )
        environment.requested._get_markup = mock.Mock(
            side_effect=AssertionError("markup must not be called")
        )
        with mock.patch(
            "odoo_accounting_cli_v3.odoo.report_read.MAX_REPORT_CELLS",
            1,
        ):
            with self.assertRaisesRegex(ReportReadError, "cells"):
                fetch_tax_report(
                    self.backend(
                        environment,
                        family="tax",
                        xmlid="account.generic_tax_report",
                    )
                )
        environment.requested._get_markup.assert_not_called()

    def test_report_eligible_journal_candidates_must_be_nonempty(self):
        options, information = tax_payload()
        environment = Environment(options=options, information=information)
        environment.models["account.journal"].records.clear()
        tax_backend = self.backend(
            environment,
            family="tax",
            xmlid="account.generic_tax_report",
        )

        options, information = financial_payload()
        options["journals"] = []
        financial_environment = Environment(
            requested_id=22,
            resolved_id=23,
            options=options,
            information=information,
        )
        financial_backend = self.backend(
            financial_environment,
            family="financial",
            xmlid="account_reports.balance_sheet",
        )

        calls = (
            ("tax_search", lambda: fetch_tax_report(tax_backend)),
            (
                "financial_options",
                lambda: financial_backend.fetch_native_report(
                    company_id=7,
                    report_family="financial",
                    report_kind="balance_sheet",
                    date_from=date(2026, 4, 1),
                    date_to=date(2026, 6, 30),
                    comparison_mode="previous_period",
                    comparison_periods=1,
                    currency_id=12,
                    **fixed_filters(),
                ),
            ),
        )
        for source, call in calls:
            with self.subTest(source=source):
                with self.assertRaisesRegex(ReportReadError, "journal"):
                    call()

        sectioned = Environment(options=options, information=information)
        sectioned.requested.use_sections = True
        backend = self.backend(
            sectioned,
            family="tax",
            xmlid="account.generic_tax_report",
        )
        with self.assertRaisesRegex(ReportReadError, "section reports"):
            backend.fetch_native_report(
                company_id=7,
                report_family="tax",
                report_kind="generic_tax",
                date_from=date(2026, 4, 1),
                date_to=date(2026, 6, 30),
                comparison_mode=None,
                comparison_periods=None,
                currency_id=12,
                **fixed_filters(),
            )

        denied = Environment(options=options, information=information)

        def deny(_operation):
            raise PermissionError("read denied")

        denied.requested.check_access_rights = deny
        backend = self.backend(
            denied,
            family="tax",
            xmlid="account.generic_tax_report",
        )
        with self.assertRaisesRegex(PermissionError, "read denied"):
            backend.fetch_native_report(
                company_id=7,
                report_family="tax",
                report_kind="generic_tax",
                date_from=date(2026, 4, 1),
                date_to=date(2026, 6, 30),
                comparison_mode=None,
                comparison_periods=None,
                currency_id=12,
                **fixed_filters(),
            )

    def test_native_scope_and_shape_mutations_are_rejected(self):
        def readonly_changed(options, _information, environment):
            options["readonly_query"] = False

        def company_changed(_options, _information, environment):
            environment.resolved.company_ids = [8]

        def upstream_warning(_options, information, _environment):
            information["warnings"] = {"bad": "unreviewed"}

        def unknown_group(options, _information, _environment):
            options["columns"][0]["column_group_key"] = "unknown"

        def foreign_currency(_options, information, _environment):
            information["lines"][0]["columns"][0]["currency"] = Record(99)

        def load_more(_options, information, _environment):
            information["lines"][0]["offset"] = 80

        def unknown_expansion(_options, information, _environment):
            information["lines"][0]["expand_function"] = "_load_more"

        def draft_entries(options, _information, _environment):
            options["all_entries"] = True

        def selected_journal(options, _information, _environment):
            options["journals"] = [
                {
                    "id": 11,
                    "model": "account.journal",
                    "selected": True,
                }
            ]

        def selected_tax_unit(options, _information, _environment):
            options["tax_unit"] = {"id": 3}

        def custom_aml_filter(options, _information, _environment):
            options["aml_ir_filters"] = [{"field": "partner_id"}]

        cases = (
            (readonly_changed, "preserve read-only"),
            (company_changed, "company scope changed"),
            (upstream_warning, "unreviewed warning"),
            (unknown_group, "unknown period"),
            (foreign_currency, "monocurrency shape changed"),
            (load_more, "truncated load-more"),
            (unknown_expansion, "expansion function"),
            (draft_entries, "effective filters changed"),
            (selected_journal, "journal option"),
            (selected_tax_unit, "tax-unit scope changed"),
            (custom_aml_filter, "effective filters changed"),
        )
        for mutation, error in cases:
            with self.subTest(error=error):
                options, information = tax_payload()
                environment = Environment(
                    options=options,
                    information=information,
                )
                mutation(options, information, environment)
                backend = self.backend(
                    environment,
                    family="tax",
                    xmlid="account.generic_tax_report",
                )
                with self.assertRaisesRegex(ReportReadError, error):
                    backend.fetch_native_report(
                        company_id=7,
                        report_family="tax",
                        report_kind="generic_tax",
                        date_from=date(2026, 4, 1),
                        date_to=date(2026, 6, 30),
                        comparison_mode=None,
                        comparison_periods=None,
                        currency_id=12,
                        **fixed_filters(),
                    )


if __name__ == "__main__":
    unittest.main()

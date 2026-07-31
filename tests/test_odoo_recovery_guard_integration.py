from __future__ import annotations

from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo.module_graph import (
    build_trusted_module_graph,
)
from odoo_accounting_cli_v3.odoo.recovery_actions import (
    FAIL_CLOSED_RECOVERY_METHODS,
)
from odoo_accounting_cli_v3.odoo.write_handlers import (
    OdooWriteHandlerError,
    OdooWriteHandlers,
)
from odoo_accounting_cli_v3.recovery_contracts import (
    RECOVERY_ACTION_CONTRACTS,
)
from odoo_accounting_cli_v3.write_receipts import create_recovery_plan_v2


COMPANY_ID = 7
ORIGIN_OPERATION_ID = "origin-op-guard-integration"
MODULE_GRAPH = build_trusted_module_graph(
    [{"name": "account", "latest_version": "19.0.test"}]
)
CHANGED_MODULE_GRAPH = build_trusted_module_graph(
    [{"name": "account", "latest_version": "19.0.changed"}]
)
METHODS = tuple(sorted(RECOVERY_ACTION_CONTRACTS))
ALLOWED_METHODS = tuple(
    method
    for method in METHODS
    if method not in FAIL_CLOSED_RECOVERY_METHODS
)
BLOCKED_METHODS = tuple(
    method
    for method in METHODS
    if method in FAIL_CLOSED_RECOVERY_METHODS
)
PRISTINE_DRAFT_METHODS = frozenset(
    {
        "cancel_pristine_v3_draft_customer_invoice_v1",
        "cancel_pristine_v3_draft_vendor_bill_v1",
    }
)
BANK_STATEMENT_COMPENSATE_METHOD = "post_compensating_bank_statement_v1"
BANK_LINE_INDEX = "2026072000000000000000000201"


def _reference(
    model: str,
    record_id: int,
    *,
    company_id: int = COMPANY_ID,
    record_state: str = "draft",
) -> dict:
    return {
        "model": model,
        "record_id": record_id,
        "company_id": company_id,
        "record_state": record_state,
        "record_fingerprint": f"{record_id % 16:x}" * 64,
    }


def _parameters(
    *,
    method: str,
    oracle_id: str,
    action_targets: list[dict],
    guard_records: list[dict],
    module_graph_digest: str = MODULE_GRAPH.digest,
) -> dict:
    return {
        "company_id": COMPANY_ID,
        "origin_operation_id": ORIGIN_OPERATION_ID,
        "module_graph_digest": module_graph_digest,
        "method": method,
        "action_targets": sorted(
            (
                {"model": item["model"], "record_id": item["record_id"]}
                for item in action_targets
            ),
            key=lambda item: (item["model"], item["record_id"]),
        ),
        "guard_records": sorted(
            (
                {"model": item["model"], "record_id": item["record_id"]}
                for item in guard_records
            ),
            key=lambda item: (item["model"], item["record_id"]),
        ),
        "oracle_id": oracle_id,
    }


def _plan(
    method: str,
    *,
    oracle_id: str | None = None,
    reference_company_id: int = COMPANY_ID,
) -> dict:
    contract = RECOVERY_ACTION_CONTRACTS[method]
    oracle_id = oracle_id or contract.oracle_id
    if method == BANK_STATEMENT_COMPENSATE_METHOD:
        action_targets = [
            _reference(
                "account.bank.statement",
                101,
                company_id=reference_company_id,
                record_state="posted",
            )
        ]
        guard_records = [
            {
                **_reference(
                    "account.bank.statement.line",
                    201,
                    company_id=reference_company_id,
                    record_state="posted",
                ),
                "expected_outcome": "survive_exact",
            }
        ]
    else:
        action_targets = [
            _reference(
                sorted(contract.action_models)[0],
                101,
                company_id=reference_company_id,
            )
        ]
        guard_records = [
            {
                **_reference(
                    sorted(contract.guard_models)[0],
                    201,
                    company_id=reference_company_id,
                ),
                "expected_outcome": sorted(
                    contract.allowed_guard_outcomes
                )[0],
            }
        ]
    return create_recovery_plan_v2(
        origin_operation_id=ORIGIN_OPERATION_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=method,
        requires_approval=True,
        action_targets=action_targets,
        guard_records=guard_records,
        oracle_id=oracle_id,
        parameters=_parameters(
            method=method,
            oracle_id=oracle_id,
            action_targets=action_targets,
            guard_records=guard_records,
        ),
    )


class _Record:
    def __init__(self, reference: dict):
        self.id = reference["record_id"]
        self.reference = {
            key: value
            for key, value in reference.items()
            if key != "expected_outcome"
        }
        self.state = reference["record_state"]
        self.journal_id = SimpleNamespace(id=901)

    def check_access_rights(self, operation):
        return True

    def check_access_rule(self, operation):
        return True


class _GuardHarness(OdooWriteHandlers):
    def __init__(
        self,
        plan: dict,
        *,
        environment: str = "sandbox",
        module_graph=MODULE_GRAPH,
        current_graph_mutation: str | None = None,
    ):
        self.context = SimpleNamespace(
            trusted_recovery_plan=plan,
            environment=environment,
            module_graph=module_graph,
        )
        self.test_company = SimpleNamespace(id=COMPANY_ID)
        self.current_graph_mutation = current_graph_mutation
        self.records = {
            (item["model"], item["record_id"]): _Record(item)
            for item in [*plan["action_targets"], *plan["guard_records"]]
        }
        self.journal = _Record(_reference("account.journal", 901))
        if plan["method"] == BANK_STATEMENT_COMPENSATE_METHOD:
            statement = self.records[("account.bank.statement", 101)]
            line = self.records[("account.bank.statement.line", 201)]
            statement.line_ids = [line]
            statement.first_line_index = BANK_LINE_INDEX
            line.statement_id = statement
            line.internal_index = BANK_LINE_INDEX
            line.state = "posted"

    def record(
        self,
        model_name,
        record_id,
        company,
        *,
        write=False,
        shared=False,
    ):
        if model_name == "account.journal" and record_id == self.journal.id:
            return self.journal
        try:
            return self.records[(model_name, record_id)]
        except KeyError as exc:
            raise OdooWriteHandlerError(
                "current recovery record is missing"
            ) from exc

    def recovery_reference(
        self,
        model_name,
        record,
        company,
        *,
        required_fields,
    ):
        return dict(record.reference)

    def create_model(self, model_name, company, *, context=None):
        return SimpleNamespace(model_name=model_name, context=context)

    def search_records(self, model_name, domain, company, *, limit=None):
        return []

    def _draft_document_recovery_graph(self, plan, company):
        action = plan["action_targets"][0]
        action_record = self.records[(action["model"], action["record_id"])]
        guard_records = [
            self.records[(item["model"], item["record_id"])]
            for item in plan["guard_records"]
        ]
        records = [
            (action["model"], action_record),
            *(
                (item["model"], record)
                for item, record in zip(
                    plan["guard_records"], guard_records
                )
            ),
        ]
        vendor = (
            plan["method"]
            == "cancel_pristine_v3_draft_vendor_bill_v1"
        )
        return action_record, guard_records, records, vendor

    def _current_recovery_record_references(
        self,
        plan,
        company,
        *,
        known_records=None,
    ):
        graph = super()._current_recovery_record_references(
            plan, company, known_records=known_records
        )
        if self.current_graph_mutation == "fingerprint":
            first = sorted(graph)[0]
            graph[first]["record_fingerprint"] = "f" * 64
        elif self.current_graph_mutation == "missing":
            graph.pop(sorted(graph)[-1])
        elif self.current_graph_mutation == "extra":
            graph[("account.move", 999)] = {
                **_reference("account.move", 999),
                "role": "action",
            }
        return graph

    def snapshots(
        self,
        records,
        company,
        *,
        required_fields_by_model=None,
    ):
        return [
            {
                "model": model,
                "record_id": record.id,
                "company_id": company.id,
                "state": getattr(record, "state", "unknown"),
                "values": {},
                "values_digest": "0" * 64,
            }
            for model, record in records
        ]


class _RealDraftEnvironmentHarness(_GuardHarness):
    def _draft_document_recovery_graph(self, plan, company):
        return OdooWriteHandlers._draft_document_recovery_graph(
            self, plan, company
        )

    def _assert_pristine_draft_document(
        self,
        move,
        lines,
        company,
        *,
        expected_state,
        vendor,
    ):
        return None


def _parameters_for(plan: dict) -> dict:
    return {
        "origin_operation_id": ORIGIN_OPERATION_ID,
        "expected_recovery_plan_digest": plan["plan_digest"],
        "company_id": COMPANY_ID,
    }


def _assert_valid_guard_reached_precheck_end(
    method: str,
    handler: _GuardHarness,
    plan: dict,
) -> None:
    checked = handler.precheck_recovery(
        _parameters_for(plan), handler.test_company
    )
    assert "strict_recovery_plan_execution_guard" in checked["checks"]
    if method not in PRISTINE_DRAFT_METHODS:
        assert "public_orm_recovery_action_registered" in checked["checks"]


@pytest.mark.parametrize("method", ALLOWED_METHODS)
@pytest.mark.parametrize("environment", ["test", "sandbox"])
def test_precheck_guard_accepts_allowed_contracts_only_in_nonproduction(
    method,
    environment,
):
    plan = _plan(method)
    handler = _GuardHarness(plan, environment=environment)

    _assert_valid_guard_reached_precheck_end(method, handler, plan)


@pytest.mark.parametrize("method", BLOCKED_METHODS)
@pytest.mark.parametrize("environment", ["test", "sandbox"])
def test_precheck_guard_fail_closes_blocked_contracts_in_nonproduction(
    method,
    environment,
):
    plan = _plan(method)
    handler = _GuardHarness(plan, environment=environment)

    with pytest.raises(OdooWriteHandlerError, match="fail-closed"):
        handler.precheck_recovery(
            _parameters_for(plan), handler.test_company
        )


@pytest.mark.parametrize("environment", ["test", "sandbox"])
def test_precheck_guard_fail_closes_reconciliation_writeoff_plan(
    environment,
):
    method = "undo_reconciliation_without_writeoff_v1"
    oracle_id = "undo_reconciliation_without_writeoff_exact_v1"
    action_targets = [
        _reference(
            "account.move",
            101,
            record_state="posted",
        )
    ]
    guard_records = [
        {
            **_reference(
                "account.move.line",
                201,
                record_state="posted",
            ),
            "expected_outcome": "survive_allowed_delta",
        }
    ]
    plan = create_recovery_plan_v2(
        origin_operation_id=ORIGIN_OPERATION_ID,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method=method,
        requires_approval=True,
        action_targets=action_targets,
        guard_records=guard_records,
        oracle_id=oracle_id,
        parameters=_parameters(
            method=method,
            oracle_id=oracle_id,
            action_targets=action_targets,
            guard_records=guard_records,
        ),
    )
    handler = _GuardHarness(plan, environment=environment)

    with pytest.raises(
        OdooWriteHandlerError,
        match="write-off recovery is fail-closed",
    ):
        handler.precheck_recovery(
            _parameters_for(plan), handler.test_company
        )


@pytest.mark.parametrize("method", METHODS)
def test_precheck_guard_rejects_contract_oracle_tampering(method):
    plan = _plan(method, oracle_id="forged_recovery_exact_v1")
    handler = _GuardHarness(plan)

    with pytest.raises(
        OdooWriteHandlerError,
        match="not allowlisted|execution guard",
    ):
        handler.precheck_recovery(
            _parameters_for(plan), handler.test_company
        )


@pytest.mark.parametrize("method", METHODS)
def test_precheck_guard_rejects_cross_company_plan_references(method):
    plan = _plan(method, reference_company_id=8)
    handler = _GuardHarness(plan)

    with pytest.raises(OdooWriteHandlerError, match="company"):
        handler.precheck_recovery(
            _parameters_for(plan), handler.test_company
        )


@pytest.mark.parametrize("method", METHODS)
def test_precheck_guard_rejects_installed_module_graph_drift(method):
    plan = _plan(method)
    handler = _GuardHarness(plan, module_graph=CHANGED_MODULE_GRAPH)

    with pytest.raises(OdooWriteHandlerError, match="module graph"):
        handler.precheck_recovery(
            _parameters_for(plan), handler.test_company
        )


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("fingerprint", "approved reference"),
        ("missing", "missing or unexpected"),
        ("extra", "missing or unexpected"),
    ],
)
def test_precheck_guard_rejects_incomplete_or_changed_current_graph(
    method,
    mutation,
    message,
):
    plan = _plan(method)
    handler = _GuardHarness(
        plan, current_graph_mutation=mutation
    )

    with pytest.raises(OdooWriteHandlerError, match=message):
        handler.precheck_recovery(
            _parameters_for(plan), handler.test_company
        )


@pytest.mark.parametrize("method", METHODS)
def test_precheck_guard_rejects_every_contract_in_production(method):
    plan = _plan(method)
    handler = _GuardHarness(plan, environment="production")

    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler.precheck_recovery(
            _parameters_for(plan), handler.test_company
        )


@pytest.mark.parametrize("method", sorted(PRISTINE_DRAFT_METHODS))
@pytest.mark.parametrize("environment", ["test", "sandbox"])
def test_existing_pristine_draft_graph_uses_contract_nonproduction_environments(
    method,
    environment,
):
    plan = _plan(method)
    handler = _RealDraftEnvironmentHarness(
        plan, environment=environment
    )

    _move, _lines, records, _vendor = (
        handler._draft_document_recovery_graph(
            plan, handler.test_company
        )
    )

    assert {
        (model, record.id) for model, record in records
    } == {
        (item["model"], item["record_id"])
        for item in [*plan["action_targets"], *plan["guard_records"]]
    }


@pytest.mark.parametrize("method", sorted(PRISTINE_DRAFT_METHODS))
def test_existing_pristine_draft_graph_still_rejects_production(method):
    plan = _plan(method)
    handler = _RealDraftEnvironmentHarness(
        plan, environment="production"
    )

    with pytest.raises(OdooWriteHandlerError, match="not allowlisted"):
        handler._draft_document_recovery_graph(
            plan, handler.test_company
        )

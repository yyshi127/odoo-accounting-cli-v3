from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.domain.report_read import ReportReadError
from odoo_accounting_cli_v3.odoo.report_definition_guard import (
    OdooReportDefinitionGuard,
)
from odoo_accounting_cli_v3.odoo.report_definition_observer import (
    ExternalIdBinding,
    TechnicalDefinitionState,
)
from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.report_definition_baseline import (
    ApprovalRecord,
    ExternalArtifactBinding,
    ReportDefinitionCatalog,
    ReportDefinitionEntry,
)
from odoo_accounting_cli_v3.report_definition_projection import (
    PROJECTION_SCHEMA_VERSION,
    ROOT_BASELINE_IDENTITIES,
    build_root_definition_projection,
    canonical_projection_json,
)
from odoo_accounting_cli_v3.report_definition_trust import (
    SIGNATURE_NAMESPACE,
    RuntimeBinding,
    VerificationClaims,
    VerifiedReportDefinitionTrustEnvelope,
)


NOW = datetime(2026, 7, 29, 6, 0, tzinfo=timezone.utc)
DATABASE_UUID = "4fb763f5-9b9e-47c8-a5a7-fc7f8be00ab1"
RELEASE_DIGEST = "d" * 64
ROOT_IDS = {
    "account.generic_tax_report": 101,
    "account_reports.balance_sheet": 102,
    "account_reports.cash_flow_report": 103,
    "account_reports.profit_and_loss": 104,
}


def _module_graph() -> dict[str, object]:
    payload = {
        "modules": [
            {
                "dependencies": [],
                "latest_version": "19.0.1.0",
                "name": "account",
                "write_date": None,
            }
        ],
        "schema_version": PROJECTION_SCHEMA_VERSION,
    }
    return {
        **payload,
        "digest": hashlib.sha256(
            canonical_projection_json(payload)
        ).hexdigest(),
    }


def _report(
    *,
    family: str,
    root_xmlid: str,
) -> dict[str, object]:
    return {
        "active": True,
        "availability_condition": "always",
        "chart_template": None,
        "columns": [],
        "country_code": None,
        "custom_handler_model": None,
        "key": root_xmlid,
        "lines": [],
        "name": root_xmlid,
        "options": {
            "allow_foreign_vat": False,
            "currency_translation": None,
            "default_opening_date_filter": "this_year",
            "filter_date_range": True,
            "filter_growth_comparison": False,
            "filter_hide_0_lines": "optional",
            "filter_journals": True,
            "filter_multi_company": "selector",
            "filter_period_comparison": family == "financial",
            "filter_show_draft": True,
            "filter_unfold_all": False,
            "filter_unreconciled": False,
            "integer_rounding": "HALF-UP",
            "load_more_limit": 80,
            "only_tax_exigible": family == "tax",
            "prefix_groups_threshold": 4000,
            "search_bar": False,
        },
        "root_report_key": None,
        "section_report_keys": [],
        "sequence": 10,
        "use_sections": False,
        "write_date": None,
        "xmlid": root_xmlid,
    }


def _projections(*, company_name: str = "Sandbox CN") -> tuple[dict, ...]:
    company_profile = {
        "account_fiscal_country_code": "CN",
        "chart_template": "cn_oscg",
        "company_id": 7,
        "country_code": "CN",
        "currency": {
            "decimal_places": 2,
            "name": "CNY",
            "rounding": "0.01",
            "symbol": "CNY",
        },
        "fiscal": {
            "fiscalyear_last_day": 31,
            "fiscalyear_last_month": "12",
            "fiscalyear_lock_date": None,
            "hard_lock_date": None,
            "tax_lock_date": None,
        },
        "name": company_name,
        "write_date": None,
    }
    return tuple(
        build_root_definition_projection(
            database_uuid=DATABASE_UUID,
            company_id=7,
            family=family,
            kind=kind,
            root_xmlid=root_xmlid,
            company_profile=company_profile,
            module_graph=_module_graph(),
            reports=[_report(family=family, root_xmlid=root_xmlid)],
        )
        for family, kind, root_xmlid in ROOT_BASELINE_IDENTITIES
    )


def _entry(projection: dict, *, index: int) -> ReportDefinitionEntry:
    identity = projection["baseline_identity"]
    definition_json = canonical_json(projection)
    valid_from = NOW - timedelta(minutes=10)
    expires_at = NOW + timedelta(hours=1)
    return ReportDefinitionEntry(
        catalog_sha256="b" * 64,
        entry_sha256=f"{index:x}" * 64,
        approval_set_sha256="a" * 64,
        database_uuid=DATABASE_UUID,
        company_id=7,
        family=identity["family"],
        kind=identity["kind"],
        root_xmlid=identity["root_xmlid"],
        valid_from=valid_from,
        expires_at=expires_at,
        definition_sha256=hashlib.sha256(definition_json).hexdigest(),
        definition_json=definition_json,
        candidate_artifact_sha256="c" * 64,
        allowed_signers=ExternalArtifactBinding("allowed-signers", "2" * 64),
        revocations=ExternalArtifactBinding("revocations", "3" * 64),
        oracle_contract=ExternalArtifactBinding("oracle", "4" * 64),
        approvals=(
            ApprovalRecord(
                role="accounting",
                approver_id=f"accounting-{index}",
                signing_key_id=f"key-{index}",
                approved_at=valid_from - timedelta(minutes=1),
                expires_at=expires_at,
                approval_artifact_sha256=f"{index + 4:x}" * 64,
            ),
        ),
    )


def _trust(
    projections: tuple[dict, ...],
) -> VerifiedReportDefinitionTrustEnvelope:
    entries = tuple(
        _entry(projection, index=index)
        for index, projection in enumerate(projections, start=1)
    )
    return VerifiedReportDefinitionTrustEnvelope(
        envelope_sha256="e" * 64,
        verified_at=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(minutes=4),
        runtime_binding=RuntimeBinding(
            release_digest=RELEASE_DIGEST,
            database_uuid=DATABASE_UUID,
        ),
        trust_index_sha256="f" * 64,
        catalog_json=b"validated-catalog-fixture",
        catalog=ReportDefinitionCatalog(
            catalog_sha256="b" * 64,
            entries=entries,
            production_promotion_allowed=False,
        ),
        approvals=(),
        verification=VerificationClaims(
            signature_namespace=SIGNATURE_NAMESPACE,
            ssh_keygen_sha256="1" * 64,
            all_signatures_valid=True,
            all_artifact_digests_valid=True,
            no_key_or_approval_revoked=True,
            production_promotion_allowed=False,
        ),
    )


def _technical_state() -> TechnicalDefinitionState:
    return TechnicalDefinitionState(
        database_uuid=DATABASE_UUID,
        module_graph_json=canonical_projection_json(_module_graph()),
        external_ids=tuple(
            sorted(
                ExternalIdBinding(
                    model="account.report",
                    record_id=record_id,
                    xmlid=xmlid,
                )
                for xmlid, record_id in ROOT_IDS.items()
            )
        ),
    )


class Observer:
    def __init__(self, *snapshots: tuple[dict, ...]):
        self.snapshots = snapshots
        self.calls = 0

    def __call__(self, _env, *, company_id, technical_state):
        assert company_id == 7
        assert technical_state == _technical_state()
        position = min(self.calls, len(self.snapshots) - 1)
        self.calls += 1
        return self.snapshots[position]


def _guard(
    *,
    observer: Observer | None = None,
    trust: VerifiedReportDefinitionTrustEnvelope | None = None,
    release_digest: str = RELEASE_DIGEST,
) -> OdooReportDefinitionGuard:
    projections = _projections()
    return OdooReportDefinitionGuard(
        object(),
        database_uuid=DATABASE_UUID,
        release_digest=release_digest,
        trust_envelope=trust or _trust(projections),
        technical_state=_technical_state(),
        now=lambda: NOW,
        observer=observer or Observer(projections, projections),
    )


def _pre(guard: OdooReportDefinitionGuard):
    return guard.verify_pre(
        company=SimpleNamespace(id=7),
        report_family="tax",
        report_kind="generic_tax",
        root_xmlid="account.generic_tax_report",
        root_report_id=101,
    )


def test_pre_post_bind_one_verified_baseline_and_complete_definition():
    observer = Observer(_projections(), _projections())
    guard = _guard(observer=observer)

    observation = _pre(guard)
    binding = guard.verify_post(
        observation,
        company=SimpleNamespace(id=7),
        report_family="tax",
        report_kind="generic_tax",
        root_xmlid="account.generic_tax_report",
        root_report_id=101,
        resolved_report_id=101,
    )

    assert observer.calls == 2
    assert binding.definition_sha256 == _trust(
        _projections()
    ).catalog.entries[0].definition_sha256
    assert binding.baseline_catalog_sha256 == "b" * 64
    assert binding.trust_envelope_sha256 == "e" * 64
    assert binding.approvals_verified is True
    assert binding.revocations_checked is True
    assert binding.artifact_digests_verified is True
    assert binding.pre_matches_approved is True
    assert binding.post_matches_approved is True
    assert binding.same_transaction_snapshot_definition_equal is True


def test_missing_baseline_and_unverified_signatures_fail_closed():
    missing = OdooReportDefinitionGuard(
        object(),
        database_uuid=DATABASE_UUID,
        release_digest=RELEASE_DIGEST,
    )
    with pytest.raises(ReportReadError, match="baseline is unavailable"):
        _pre(missing)

    trust = _trust(_projections())
    unsigned = replace(
        trust,
        verification=replace(
            trust.verification,
            all_signatures_valid=False,
        ),
    )
    with pytest.raises(ReportReadError, match="trust binding was rejected"):
        _pre(_guard(trust=unsigned))


def test_release_company_root_and_cross_guard_evidence_are_rejected():
    with pytest.raises(ReportReadError, match="trust binding was rejected"):
        _pre(_guard(release_digest="9" * 64))

    guard = _guard()
    with pytest.raises(ReportReadError, match="precheck failed"):
        guard.verify_pre(
            company=SimpleNamespace(id=8),
            report_family="tax",
            report_kind="generic_tax",
            root_xmlid="account.generic_tax_report",
            root_report_id=101,
        )
    with pytest.raises(ReportReadError, match="root record binding differs"):
        guard.verify_pre(
            company=SimpleNamespace(id=7),
            report_family="tax",
            report_kind="generic_tax",
            root_xmlid="account.generic_tax_report",
            root_report_id=102,
        )

    observation = _pre(guard)
    with pytest.raises(ReportReadError, match="precheck evidence is invalid"):
        _guard().verify_post(
            observation,
            company=SimpleNamespace(id=7),
            report_family="tax",
            report_kind="generic_tax",
            root_xmlid="account.generic_tax_report",
            root_report_id=101,
            resolved_report_id=101,
        )


def test_definition_or_module_drift_is_not_released():
    guard = _guard(
        observer=Observer(
            _projections(),
            _projections(company_name="Drifted Company"),
        )
    )
    observation = _pre(guard)

    with pytest.raises(ReportReadError, match="changed during execution"):
        guard.verify_post(
            observation,
            company=SimpleNamespace(id=7),
            report_family="tax",
            report_kind="generic_tax",
            root_xmlid="account.generic_tax_report",
            root_report_id=101,
            resolved_report_id=101,
        )

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.report_definition_projection import (
    build_root_definition_projection,
    canonical_projection_json,
)
from odoo_accounting_cli_v3.report_definition_baseline import (
    CATALOG_SCHEMA,
    DEFINITION_SCHEMA,
    ReportDefinitionBaselineError,
    load_catalog_bytes,
    select_entry,
    validate_observed_definition,
)


NOW = datetime(2026, 7, 29, 6, 0, tzinfo=timezone.utc)
DATABASE_UUID = "4fb763f5-9b9e-47c8-a5a7-fc7f8be00ab1"


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _definition(*, family: str = "tax", kind: str = "generic_tax") -> dict:
    roots = {
        ("tax", "generic_tax"): "account.generic_tax_report",
        ("financial", "balance_sheet"): "account_reports.balance_sheet",
        ("financial", "cash_flow"): "account_reports.cash_flow_report",
        ("financial", "profit_and_loss"): "account_reports.profit_and_loss",
    }
    root_xmlid = roots[(family, kind)]
    report = {
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
    module_payload = {
        "modules": [
            {
                "dependencies": [],
                "latest_version": "19.0.1.0",
                "name": "account",
                "write_date": None,
            }
        ],
        "schema_version": DEFINITION_SCHEMA,
    }
    return build_root_definition_projection(
        database_uuid=DATABASE_UUID,
        company_id=7,
        family=family,
        kind=kind,
        root_xmlid=root_xmlid,
        company_profile={
            "account_fiscal_country_code": "CN",
            "chart_template": "cn_oscg",
            "company_id": 7,
            "country_code": "CN",
            "currency": {
                "decimal_places": 2,
                "name": "CNY",
                "rounding": "0.01",
                "symbol": "¥",
            },
            "fiscal": {
                "fiscalyear_last_day": 31,
                "fiscalyear_last_month": "12",
                "fiscalyear_lock_date": None,
                "hard_lock_date": None,
                "tax_lock_date": None,
            },
            "name": "Sandbox CN",
            "write_date": None,
        },
        module_graph={
            **module_payload,
            "digest": hashlib.sha256(
                canonical_projection_json(module_payload)
            ).hexdigest(),
        },
        reports=[report],
    )


def _entry(*, family: str = "tax", kind: str = "generic_tax") -> dict:
    definition = _definition(family=family, kind=kind)
    root_xmlid = definition["baseline_identity"]["root_xmlid"]
    definition_sha256 = hashlib.sha256(canonical_json(definition)).hexdigest()
    allowed = {
        "artifact_id": "release-signing/allowed-signers.v1",
        "sha256": "2" * 64,
    }
    revoked = {
        "artifact_id": "release-signing/revocations.v1",
        "sha256": "3" * 64,
    }
    oracle = {
        "artifact_id": "accounting/report-oracles.v1",
        "sha256": "9" * 64,
    }
    valid_from = _timestamp(NOW - timedelta(minutes=1))
    expires_at = _timestamp(NOW + timedelta(hours=1))
    roles = ["accounting", "tax", "technical"] if family == "tax" else [
        "accounting",
        "technical",
    ]
    approvals = []
    for index, role in enumerate(roles, start=1):
        approvals.append(
            {
                "allowed_signers_artifact_id": allowed["artifact_id"],
                "allowed_signers_sha256": allowed["sha256"],
                "approval_artifact_sha256": f"{index + 3:x}" * 64,
                "approved_at": _timestamp(NOW - timedelta(minutes=2)),
                "approver_id": f"approver-{role}",
                "candidate_artifact_sha256": "a" * 64,
                "company_id": 7,
                "database_uuid": DATABASE_UUID,
                "definition_sha256": definition_sha256,
                "expires_at": expires_at,
                "family": family,
                "kind": kind,
                "oracle_contract_artifact_id": oracle["artifact_id"],
                "oracle_contract_sha256": oracle["sha256"],
                "revocations_artifact_id": revoked["artifact_id"],
                "revocations_sha256": revoked["sha256"],
                "role": role,
                "root_xmlid": root_xmlid,
                "signing_key_id": f"ssh-ed25519:{role}",
                "valid_from": valid_from,
            }
        )
    return {
        "allowed_signers": allowed,
        "approvals": approvals,
        "candidate_artifact_sha256": "a" * 64,
        "company_id": 7,
        "database_uuid": DATABASE_UUID,
        "definition": definition,
        "definition_sha256": definition_sha256,
        "expires_at": expires_at,
        "family": family,
        "kind": kind,
        "oracle_contract": oracle,
        "revocations": revoked,
        "root_xmlid": root_xmlid,
        "valid_from": valid_from,
    }


def _catalog(*entries: dict) -> dict:
    return {
        "entries": list(entries or (_entry(),)),
        "production_promotion_allowed": False,
        "schema_version": CATALOG_SCHEMA,
    }


def _load(document: dict, *, now: datetime = NOW):
    return load_catalog_bytes(canonical_json(document), now=now)


def _select(catalog, *, now: datetime = NOW, **overrides):
    identity = {
        "company_id": 7,
        "database_uuid": DATABASE_UUID,
        "family": "tax",
        "kind": "generic_tax",
        "root_xmlid": "account.generic_tax_report",
    }
    identity.update(overrides)
    return select_entry(catalog, now=now, **identity)


def test_load_select_and_validate_tax_baseline():
    raw = canonical_json(_catalog())
    catalog = load_catalog_bytes(raw, now=NOW)
    entry = _select(catalog)

    assert catalog.catalog_sha256 == hashlib.sha256(raw).hexdigest()
    assert catalog.production_promotion_allowed is False
    assert {approval.role for approval in entry.approvals} == {
        "accounting",
        "tax",
        "technical",
    }
    first = validate_observed_definition(
        entry,
        observed_pre=entry.definition,
        observed_post=entry.definition,
        now=NOW,
    )
    second = validate_observed_definition(
        entry,
        observed_pre=entry.definition_json,
        observed_post=entry.definition_json,
        now=NOW,
    )
    assert first == second
    assert len(first) == 64
    assert len(entry.entry_sha256) == 64
    assert len(entry.approval_set_sha256) == 64
    assert entry.oracle_contract.sha256 == "9" * 64


def test_financial_entry_requires_only_independent_technical_and_accounting():
    entry_document = _entry(family="financial", kind="balance_sheet")
    catalog = _load(_catalog(entry_document))
    entry = select_entry(
        catalog,
        database_uuid=DATABASE_UUID,
        company_id=7,
        family="financial",
        kind="balance_sheet",
        root_xmlid="account_reports.balance_sheet",
        now=NOW,
    )
    assert [item.role for item in entry.approvals] == ["accounting", "technical"]


@pytest.mark.parametrize(
    "payload",
    [
        lambda value: canonical_json(value) + b"\n",
        lambda value: json.dumps(value, indent=2).encode(),
        lambda value: json.dumps(value, sort_keys=False).encode(),
    ],
)
def test_catalog_rejects_noncanonical_json(payload):
    with pytest.raises(ReportDefinitionBaselineError, match="canonical JSON"):
        load_catalog_bytes(payload(_catalog()), now=NOW)


def test_catalog_rejects_duplicate_json_keys():
    raw = canonical_json(_catalog())
    duplicated = raw.replace(
        b'{"entries":',
        b'{"entries":[],"entries":',
        1,
    )
    with pytest.raises(ReportDefinitionBaselineError, match="duplicate JSON key"):
        load_catalog_bytes(duplicated, now=NOW)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": True}), "fields differ"),
        (lambda value: value.pop("entries"), "fields differ"),
        (
            lambda value: value.update({"production_promotion_allowed": True}),
            "cannot authorize production promotion",
        ),
        (
            lambda value: value.update({"schema_version": "catalog.v2"}),
            "unsupported",
        ),
    ],
)
def test_catalog_rejects_schema_drift(mutation, message):
    document = _catalog()
    mutation(document)
    with pytest.raises(ReportDefinitionBaselineError, match=message):
        _load(document)


def test_catalog_rejects_duplicate_identity():
    first = _entry()
    second = copy.deepcopy(first)
    with pytest.raises(ReportDefinitionBaselineError, match="duplicate report identities"):
        _load(_catalog(first, second))


def test_catalog_rejects_noncanonical_entry_order():
    tax = _entry()
    financial = _entry(family="financial", kind="balance_sheet")
    with pytest.raises(ReportDefinitionBaselineError, match="not canonically ordered"):
        _load(_catalog(tax, financial))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda entry: entry.update(
                {"definition_sha256": "f" * 64}
            ),
            "does not match the full definition",
            ),
            (
                lambda entry: entry.update({"company_id": 8}),
                "identity does not match",
            ),
        (
            lambda entry: entry.update({"candidate_artifact_sha256": "A" * 64}),
            "lowercase SHA-256",
        ),
        (
            lambda entry: entry["allowed_signers"].update({"extra": "x"}),
            "fields differ",
        ),
        (
            lambda entry: entry["revocations"].pop("sha256"),
            "fields differ",
        ),
        (
            lambda entry: entry["revocations"].update(
                {"artifact_id": entry["allowed_signers"]["artifact_id"]}
            ),
            "distinct artifacts",
        ),
        (
            lambda entry: entry["oracle_contract"].update({"sha256": "A" * 64}),
            "lowercase SHA-256",
        ),
        (
            lambda entry: entry["oracle_contract"].update(
                {"artifact_id": entry["allowed_signers"]["artifact_id"]}
            ),
            "distinct artifacts",
        ),
        (
            lambda entry: entry.update({"unexpected": False}),
            "fields differ",
        ),
    ],
)
def test_entry_rejects_digest_identity_binding_and_schema_drift(mutate, message):
    entry = _entry()
    mutate(entry)
    with pytest.raises(ReportDefinitionBaselineError, match=message):
        _load(_catalog(entry))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda entry: entry["approvals"].pop(1),
            "required roles",
        ),
        (
            lambda entry: entry["approvals"][1].update(
                {"approver_id": entry["approvals"][0]["approver_id"]}
            ),
            "independent by approver",
        ),
        (
            lambda entry: entry["approvals"][1].update(
                {"signing_key_id": entry["approvals"][0]["signing_key_id"]}
            ),
            "independent by signing key",
        ),
        (
            lambda entry: entry["approvals"][1].update(
                {
                    "approval_artifact_sha256": entry["approvals"][0][
                        "approval_artifact_sha256"
                    ]
                }
            ),
            "reuse an approval artifact",
        ),
        (
            lambda entry: entry["approvals"][0].update({"company_id": 8}),
            "identity does not match",
        ),
        (
            lambda entry: entry["approvals"][0].update(
                {"candidate_artifact_sha256": "b" * 64}
            ),
            "does not match its entry",
        ),
        (
            lambda entry: entry["approvals"][0].update(
                {"allowed_signers_sha256": "b" * 64}
            ),
            "does not match its entry",
        ),
        (
            lambda entry: entry["approvals"][0].update(
                {"oracle_contract_sha256": "b" * 64}
            ),
            "does not match its entry",
        ),
        (
            lambda entry: entry["approvals"][0].update(
                {"valid_from": _timestamp(NOW - timedelta(minutes=3))}
            ),
            "valid_from does not match",
        ),
        (
            lambda entry: entry["approvals"][0].update({"extra": "claim"}),
            "fields differ",
        ),
    ],
)
def test_approval_records_fail_closed(mutate, message):
    entry = _entry()
    mutate(entry)
    with pytest.raises(ReportDefinitionBaselineError, match=message):
        _load(_catalog(entry))


def test_tax_approval_records_must_be_canonically_ordered():
    entry = _entry()
    entry["approvals"].reverse()
    with pytest.raises(ReportDefinitionBaselineError, match="not canonically ordered"):
        _load(_catalog(entry))


@pytest.mark.parametrize(
    ("mutate", "now", "message"),
    [
        (
            lambda entry: entry.update(
                {"expires_at": _timestamp(NOW)}
            ),
            NOW,
            "approval validity is outside|not currently valid",
        ),
        (
            lambda entry: entry.update(
                {"valid_from": _timestamp(NOW + timedelta(seconds=1))}
            ),
            NOW,
            "valid_from does not match|approval was issued after|not currently valid",
        ),
        (
            lambda entry: entry["approvals"][0].update(
                {"expires_at": _timestamp(NOW)}
            ),
            NOW,
            "not currently valid",
        ),
        (
            lambda entry: entry["approvals"][0].update(
                {"approved_at": _timestamp(NOW)}
            ),
            NOW,
            "issued after",
        ),
    ],
)
def test_validity_and_approval_expiry_are_rechecked(mutate, now, message):
    entry = _entry()
    mutate(entry)
    with pytest.raises(ReportDefinitionBaselineError, match=message):
        _load(_catalog(entry), now=now)


def test_select_rejects_missing_identity_and_rechecks_expiry():
    catalog = _load(_catalog())
    with pytest.raises(ReportDefinitionBaselineError, match="exactly one"):
        _select(catalog, company_id=8)
    with pytest.raises(ReportDefinitionBaselineError, match="not currently valid"):
        _select(catalog, now=NOW + timedelta(hours=2))


def test_observed_definition_rejects_pre_post_drift_and_noncanonical_bytes():
    entry = _select(_load(_catalog()))
    changed = entry.definition
    changed["company_profile"]["company_id"] = 8
    with pytest.raises(ReportDefinitionBaselineError, match="observed_pre"):
        validate_observed_definition(
            entry,
            observed_pre=changed,
            observed_post=entry.definition,
            now=NOW,
    )
    changed = entry.definition
    changed["reports"][0]["name"] = "Tampered"
    with pytest.raises(ReportDefinitionBaselineError, match="observed_post"):
        validate_observed_definition(
            entry,
            observed_pre=entry.definition,
            observed_post=changed,
            now=NOW,
        )
    with pytest.raises(ReportDefinitionBaselineError, match="not canonical JSON"):
        validate_observed_definition(
            entry,
            observed_pre=entry.definition_json + b"\n",
            observed_post=entry.definition_json,
            now=NOW,
        )


def test_loaded_definition_property_is_detached():
    entry = _select(_load(_catalog()))
    detached = entry.definition
    detached["company_profile"]["company_id"] = 99
    assert entry.definition["company_profile"]["company_id"] == 7

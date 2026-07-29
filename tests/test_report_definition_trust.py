from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.report_definition_baseline import (
    CATALOG_SCHEMA,
    DEFINITION_SCHEMA,
)
from odoo_accounting_cli_v3.report_definition_projection import (
    build_root_definition_projection,
    canonical_projection_json,
)
from odoo_accounting_cli_v3.report_definition_trust import (
    MAX_CATALOG_JSON_BYTES,
    MAX_TRUST_ENVELOPE_BYTES,
    SIGNATURE_NAMESPACE,
    TRUST_ENVELOPE_DOCUMENT_TYPE,
    ReportDefinitionTrustError,
    load_verified_trust_envelope_bytes,
)


NOW = datetime(2026, 7, 29, 6, 0, tzinfo=timezone.utc)
DATABASE_UUID = "4fb763f5-9b9e-47c8-a5a7-fc7f8be00ab1"
RELEASE_DIGEST = "d" * 64
REPORTS = (
    ("financial", "balance_sheet", "account_reports.balance_sheet"),
    ("financial", "cash_flow", "account_reports.cash_flow_report"),
    (
        "financial",
        "profit_and_loss",
        "account_reports.profit_and_loss",
    ),
    ("tax", "generic_tax", "account.generic_tax_report"),
)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _entry(
    *,
    company_id: int,
    family: str,
    kind: str,
    root_xmlid: str,
    database_uuid: str = DATABASE_UUID,
    valid_from: datetime = NOW - timedelta(minutes=10),
    expires_at: datetime = NOW + timedelta(hours=1),
) -> dict:
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
    definition = build_root_definition_projection(
        database_uuid=database_uuid,
        company_id=company_id,
        family=family,
        kind=kind,
        root_xmlid=root_xmlid,
        company_profile={
            "account_fiscal_country_code": "CN",
            "chart_template": "cn_oscg",
            "company_id": company_id,
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
            "name": f"Sandbox CN {company_id}",
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
    definition_sha256 = hashlib.sha256(canonical_json(definition)).hexdigest()
    identity_label = (
        f"{database_uuid}:{company_id}:{family}:{kind}:{root_xmlid}"
    )
    allowed = {
        "artifact_id": "release-signing/allowed-signers.v1",
        "sha256": _digest("allowed-signers"),
    }
    revocations = {
        "artifact_id": "release-signing/revocations.v1",
        "sha256": _digest("revocations"),
    }
    oracle = {
        "artifact_id": "accounting/report-oracles.v1",
        "sha256": _digest("oracles"),
    }
    candidate_sha256 = _digest(f"candidate:{identity_label}")
    roles = (
        ("accounting", "tax", "technical")
        if family == "tax"
        else ("accounting", "technical")
    )
    approvals = []
    for role in roles:
        approvals.append(
            {
                "allowed_signers_artifact_id": allowed["artifact_id"],
                "allowed_signers_sha256": allowed["sha256"],
                "approval_artifact_sha256": _digest(
                    f"approval:{identity_label}:{role}"
                ),
                "approved_at": _timestamp(NOW - timedelta(minutes=20)),
                "approver_id": f"approver-{company_id}-{kind}-{role}",
                "candidate_artifact_sha256": candidate_sha256,
                "company_id": company_id,
                "database_uuid": database_uuid,
                "definition_sha256": definition_sha256,
                "expires_at": _timestamp(expires_at),
                "family": family,
                "kind": kind,
                "oracle_contract_artifact_id": oracle["artifact_id"],
                "oracle_contract_sha256": oracle["sha256"],
                "revocations_artifact_id": revocations["artifact_id"],
                "revocations_sha256": revocations["sha256"],
                "role": role,
                "root_xmlid": root_xmlid,
                "signing_key_id": f"ssh-ed25519:{company_id}:{kind}:{role}",
                "valid_from": _timestamp(valid_from),
            }
        )
    return {
        "allowed_signers": allowed,
        "approvals": approvals,
        "candidate_artifact_sha256": candidate_sha256,
        "company_id": company_id,
        "database_uuid": database_uuid,
        "definition": definition,
        "definition_sha256": definition_sha256,
        "expires_at": _timestamp(expires_at),
        "family": family,
        "kind": kind,
        "oracle_contract": oracle,
        "revocations": revocations,
        "root_xmlid": root_xmlid,
        "valid_from": _timestamp(valid_from),
    }


def _catalog(
    *,
    company_ids: tuple[int, ...] = (7,),
    database_uuid: str = DATABASE_UUID,
) -> dict:
    entries = [
        _entry(
            company_id=company_id,
            database_uuid=database_uuid,
            family=family,
            kind=kind,
            root_xmlid=root_xmlid,
        )
        for company_id in company_ids
        for family, kind, root_xmlid in REPORTS
    ]
    entries.sort(
        key=lambda value: (
            value["database_uuid"],
            value["company_id"],
            value["family"],
            value["kind"],
            value["root_xmlid"],
        )
    )
    return {
        "entries": entries,
        "production_promotion_allowed": False,
        "schema_version": CATALOG_SCHEMA,
    }


def _envelope(
    *,
    catalog: dict | None = None,
    catalog_json: str | None = None,
    verified_at: datetime = NOW - timedelta(minutes=1),
    not_after: datetime = NOW + timedelta(minutes=4),
) -> dict:
    catalog_document = copy.deepcopy(catalog or _catalog())
    if catalog_json is None:
        catalog_json = canonical_json(catalog_document).decode("utf-8")
    approvals = []
    for entry in catalog_document["entries"]:
        for approval in entry["approvals"]:
            signature_label = (
                f"{entry['database_uuid']}:{entry['company_id']}:"
                f"{entry['family']}:{entry['kind']}:{entry['root_xmlid']}:"
                f"{approval['role']}:{approval['approval_artifact_sha256']}"
            )
            approvals.append(
                {
                    "approval_artifact_sha256": approval[
                        "approval_artifact_sha256"
                    ],
                    "approved_at": approval["approved_at"],
                    "approver_id": approval["approver_id"],
                    "company_id": entry["company_id"],
                    "database_uuid": entry["database_uuid"],
                    "expires_at": approval["expires_at"],
                    "family": entry["family"],
                    "kind": entry["kind"],
                    "role": approval["role"],
                    "root_xmlid": entry["root_xmlid"],
                    "signature_sha256": _digest(f"signature:{signature_label}"),
                    "signing_key_id": approval["signing_key_id"],
                    "verified": True,
                }
            )
    return {
        "approvals": approvals,
        "catalog_json": catalog_json,
        "document_type": TRUST_ENVELOPE_DOCUMENT_TYPE,
        "not_after": _timestamp(not_after),
        "runtime_binding": {
            "database_uuid": DATABASE_UUID,
            "release_digest": RELEASE_DIGEST,
        },
        "schema_version": 1,
        "trust_index_sha256": _digest("trust-index"),
        "verification": {
            "all_artifact_digests_valid": True,
            "all_signatures_valid": True,
            "no_key_or_approval_revoked": True,
            "production_promotion_allowed": False,
            "signature_namespace": SIGNATURE_NAMESPACE,
            "ssh_keygen_sha256": _digest("ssh-keygen"),
        },
        "verified_at": _timestamp(verified_at),
    }


def _load(
    document: dict,
    *,
    now: datetime = NOW,
    expected_release_digest: str = RELEASE_DIGEST,
    expected_database_uuid: str = DATABASE_UUID,
):
    payload = canonical_json(document)
    return load_verified_trust_envelope_bytes(
        payload,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        expected_release_digest=expected_release_digest,
        expected_database_uuid=expected_database_uuid,
        now=now,
    )


def _load_raw(payload: bytes, *, now: datetime = NOW):
    return load_verified_trust_envelope_bytes(
        payload,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        expected_release_digest=RELEASE_DIGEST,
        expected_database_uuid=DATABASE_UUID,
        now=now,
    )


def test_loads_verified_envelope_and_exposes_detached_catalog():
    document = _envelope()
    payload = canonical_json(document)
    result = _load(document)

    assert result.envelope_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.catalog_json == document["catalog_json"].encode("utf-8")
    assert result.runtime_binding.release_digest == RELEASE_DIGEST
    assert result.runtime_binding.database_uuid == DATABASE_UUID
    assert len(result.catalog.entries) == 4
    assert len(result.approvals) == 9
    assert result.verification.production_promotion_allowed is False


def test_select_entry_binds_database_and_rechecks_envelope():
    result = _load(_envelope())
    entry = result.select_entry(
        company_id=7,
        family="financial",
        kind="cash_flow",
        root_xmlid="account_reports.cash_flow_report",
        now=NOW,
    )
    assert entry.database_uuid == DATABASE_UUID
    assert entry.kind == "cash_flow"


def test_returned_dataclasses_are_frozen():
    result = _load(_envelope())
    with pytest.raises(FrozenInstanceError):
        result.runtime_binding.release_digest = "f" * 64
    with pytest.raises(FrozenInstanceError):
        result.approvals[0].verified = False


def test_catalog_definition_property_remains_detached():
    result = _load(_envelope())
    detached = result.catalog.entries[0].definition
    detached["baseline_identity"]["company_id"] = 999
    assert (
        result.catalog.entries[0].definition["baseline_identity"]["company_id"]
        == 7
    )


def test_accepts_multiple_companies_with_exactly_four_reports_each():
    catalog = _catalog(company_ids=(7, 11))
    result = _load(_envelope(catalog=catalog))
    assert len(result.catalog.entries) == 8
    assert {entry.company_id for entry in result.catalog.entries} == {7, 11}


def test_accepts_exact_five_minute_ttl_boundary():
    result = _load(
        _envelope(
            verified_at=NOW - timedelta(minutes=1),
            not_after=NOW + timedelta(minutes=4),
        )
    )
    assert result.not_after - result.verified_at == timedelta(minutes=5)


def test_accepts_now_equal_to_verified_at():
    result = _load(
        _envelope(verified_at=NOW, not_after=NOW + timedelta(minutes=5))
    )
    assert result.verified_at == NOW


def test_rejects_payload_over_explicit_size_limit_before_parsing():
    payload = b"x" * (MAX_TRUST_ENVELOPE_BYTES + 1)
    with pytest.raises(ReportDefinitionTrustError, match="maximum size"):
        _load_raw(payload)


def test_exact_payload_size_boundary_passes_size_gate():
    payload = b"x" * MAX_TRUST_ENVELOPE_BYTES
    with pytest.raises(ReportDefinitionTrustError, match="strict UTF-8 JSON"):
        _load_raw(payload)


def test_rejects_catalog_string_over_explicit_size_limit():
    document = _envelope(catalog_json="x" * (MAX_CATALOG_JSON_BYTES + 1))
    with pytest.raises(ReportDefinitionTrustError, match="catalog_json exceeds"):
        _load(document)


def test_exact_catalog_size_boundary_passes_size_gate():
    document = _envelope(catalog_json="x" * MAX_CATALOG_JSON_BYTES)
    with pytest.raises(
        ReportDefinitionTrustError,
        match="catalog_json failed baseline validation",
    ):
        _load(document)


@pytest.mark.parametrize("payload", [b"", bytearray(b"{}"), "{}", None])
def test_rejects_empty_or_non_bytes_payload(payload):
    with pytest.raises(ReportDefinitionTrustError, match="non-empty bytes"):
        load_verified_trust_envelope_bytes(
            payload,
            expected_sha256="0" * 64,
            expected_release_digest=RELEASE_DIGEST,
            expected_database_uuid=DATABASE_UUID,
            now=NOW,
        )


def test_rejects_wrong_payload_digest():
    payload = canonical_json(_envelope())
    with pytest.raises(ReportDefinitionTrustError, match="payload digest differs"):
        load_verified_trust_envelope_bytes(
            payload,
            expected_sha256="f" * 64,
            expected_release_digest=RELEASE_DIGEST,
            expected_database_uuid=DATABASE_UUID,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_sha256", "F" * 64),
        ("expected_release_digest", "short"),
        ("expected_database_uuid", DATABASE_UUID.upper()),
    ],
)
def test_rejects_invalid_expected_bindings(field, value):
    payload = canonical_json(_envelope())
    arguments = {
        "expected_sha256": hashlib.sha256(payload).hexdigest(),
        "expected_release_digest": RELEASE_DIGEST,
        "expected_database_uuid": DATABASE_UUID,
        "now": NOW,
    }
    arguments[field] = value
    with pytest.raises(ReportDefinitionTrustError):
        load_verified_trust_envelope_bytes(payload, **arguments)


def test_rejects_runtime_release_mismatch():
    with pytest.raises(ReportDefinitionTrustError, match="release digest differs"):
        _load(_envelope(), expected_release_digest="e" * 64)


def test_rejects_runtime_database_mismatch():
    other = "62fdfb93-92f6-4524-96e3-c13ce6b690e8"
    with pytest.raises(ReportDefinitionTrustError, match="database UUID differs"):
        _load(_envelope(), expected_database_uuid=other)


@pytest.mark.parametrize(
    "payload",
    [
        lambda document: canonical_json(document) + b"\n",
        lambda document: json.dumps(document, indent=2).encode("utf-8"),
        lambda document: b"\xff",
    ],
)
def test_rejects_noncanonical_or_invalid_utf8_payload(payload):
    with pytest.raises(ReportDefinitionTrustError):
        _load_raw(payload(_envelope()))


def test_rejects_duplicate_outer_json_key():
    payload = canonical_json(_envelope()).replace(
        b'{"approvals":',
        b'{"schema_version":1,"approvals":',
        1,
    )
    with pytest.raises(ReportDefinitionTrustError, match="duplicate JSON key"):
        _load_raw(payload)


def test_rejects_nonfinite_json_number():
    payload = canonical_json(_envelope()).replace(
        b'"schema_version":1',
        b'"schema_version":NaN',
        1,
    )
    with pytest.raises(ReportDefinitionTrustError, match="non-finite"):
        _load_raw(payload)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"extra": True}), "fields differ"),
        (lambda value: value.pop("trust_index_sha256"), "fields differ"),
        (
            lambda value: value.update({"schema_version": 2}),
            "schema_version is unsupported",
        ),
        (
            lambda value: value.update({"document_type": "other"}),
            "document_type is unsupported",
        ),
    ],
)
def test_rejects_outer_schema_drift(mutation, message):
    document = _envelope()
    mutation(document)
    with pytest.raises(ReportDefinitionTrustError, match=message):
        _load(document)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["runtime_binding"].update({"extra": "x"}),
            "runtime_binding fields differ",
        ),
        (
            lambda value: value["runtime_binding"].update(
                {"release_digest": "F" * 64}
            ),
            "lowercase SHA-256",
        ),
        (
            lambda value: value["runtime_binding"].update(
                {"database_uuid": DATABASE_UUID.upper()}
            ),
            "canonical UUID",
        ),
        (
            lambda value: value.update({"trust_index_sha256": "x"}),
            "lowercase SHA-256",
        ),
    ],
)
def test_rejects_runtime_and_trust_index_drift(mutation, message):
    document = _envelope()
    mutation(document)
    with pytest.raises(ReportDefinitionTrustError, match=message):
        _load(document)


def test_rejects_ttl_longer_than_five_minutes():
    document = _envelope(
        verified_at=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(minutes=4, seconds=1),
    )
    with pytest.raises(ReportDefinitionTrustError, match="not active"):
        _load(document)


def test_rejects_expired_envelope_at_exact_not_after():
    document = _envelope(
        verified_at=NOW - timedelta(minutes=5),
        not_after=NOW,
    )
    with pytest.raises(ReportDefinitionTrustError, match="not active"):
        _load(document)


def test_rejects_future_verification_time():
    document = _envelope(
        verified_at=NOW + timedelta(seconds=1),
        not_after=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ReportDefinitionTrustError, match="not active"):
        _load(document)


@pytest.mark.parametrize(
    "bad_now",
    [
        datetime(2026, 7, 29, 6, 0),
        "2026-07-29T06:00:00Z",
    ],
)
def test_rejects_invalid_now(bad_now):
    with pytest.raises(ReportDefinitionTrustError, match="timezone-aware"):
        _load(_envelope(), now=bad_now)


def test_select_entry_rejects_after_envelope_expiry():
    result = _load(_envelope())
    with pytest.raises(ReportDefinitionTrustError, match="not active"):
        result.select_entry(
            company_id=7,
            family="tax",
            kind="generic_tax",
            root_xmlid="account.generic_tax_report",
            now=NOW + timedelta(minutes=4),
        )


def test_select_entry_rejects_unknown_identity_without_database_override():
    result = _load(_envelope())
    with pytest.raises(ReportDefinitionTrustError, match="selection was rejected"):
        result.select_entry(
            company_id=8,
            family="tax",
            kind="generic_tax",
            root_xmlid="account.generic_tax_report",
            now=NOW,
        )


def test_rejects_company_missing_one_of_four_fixed_reports():
    catalog = _catalog()
    catalog["entries"].pop()
    with pytest.raises(ReportDefinitionTrustError, match="exactly four"):
        _load(_envelope(catalog=catalog))


def test_rejects_catalog_database_different_from_runtime():
    other = "62fdfb93-92f6-4524-96e3-c13ce6b690e8"
    catalog = _catalog(database_uuid=other)
    document = _envelope(catalog=catalog)
    with pytest.raises(ReportDefinitionTrustError, match="catalog database UUID"):
        _load(document)


@pytest.mark.parametrize(
    "catalog_json",
    [
        "",
        "not-json",
        canonical_json(_catalog()).decode("utf-8") + "\n",
    ],
)
def test_rejects_empty_invalid_or_noncanonical_catalog_json(catalog_json):
    document = _envelope(catalog_json=catalog_json)
    with pytest.raises(ReportDefinitionTrustError, match="catalog_json"):
        _load(document)


def test_rejects_duplicate_key_inside_catalog_json():
    catalog_json = canonical_json(_catalog()).replace(
        b'{"entries":',
        b'{"entries":[],"entries":',
        1,
    ).decode("utf-8")
    document = _envelope(catalog_json=catalog_json)
    with pytest.raises(ReportDefinitionTrustError, match="catalog_json"):
        _load(document)


def test_rejects_missing_approval_verification():
    document = _envelope()
    document["approvals"].pop()
    with pytest.raises(ReportDefinitionTrustError, match="exactly cover"):
        _load(document)


def test_rejects_extra_approval_verification():
    document = _envelope()
    document["approvals"].append(copy.deepcopy(document["approvals"][-1]))
    with pytest.raises(ReportDefinitionTrustError, match="exactly cover"):
        _load(document)


def test_rejects_reordered_approval_verifications():
    document = _envelope()
    document["approvals"][0], document["approvals"][1] = (
        document["approvals"][1],
        document["approvals"][0],
    )
    with pytest.raises(ReportDefinitionTrustError, match="catalog approval order"):
        _load(document)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("company_id", 8),
        ("role", "tax"),
        ("approver_id", "someone-else"),
        ("signing_key_id", "ssh-ed25519:other"),
        ("approval_artifact_sha256", "e" * 64),
        ("approved_at", "2026-07-29T05:39:59Z"),
        ("expires_at", "2026-07-29T06:59:59Z"),
    ],
)
def test_rejects_approval_record_not_matching_catalog(field, value):
    document = _envelope()
    document["approvals"][0][field] = value
    with pytest.raises(ReportDefinitionTrustError, match="catalog approval order"):
        _load(document)


def test_rejects_approval_schema_drift():
    document = _envelope()
    document["approvals"][0]["extra"] = "claim"
    with pytest.raises(ReportDefinitionTrustError, match="fields differ"):
        _load(document)


@pytest.mark.parametrize("verified", [False, 1, "true"])
def test_rejects_approval_not_verified_as_exact_boolean(verified):
    document = _envelope()
    document["approvals"][0]["verified"] = verified
    with pytest.raises(ReportDefinitionTrustError, match="verified must be true"):
        _load(document)


def test_rejects_invalid_detached_signature_digest():
    document = _envelope()
    document["approvals"][0]["signature_sha256"] = "F" * 64
    with pytest.raises(ReportDefinitionTrustError, match="lowercase SHA-256"):
        _load(document)


def test_rejects_reused_detached_signature_digest():
    document = _envelope()
    document["approvals"][1]["signature_sha256"] = document["approvals"][0][
        "signature_sha256"
    ]
    with pytest.raises(ReportDefinitionTrustError, match="reuse"):
        _load(document)


@pytest.mark.parametrize(
    "field",
    [
        "all_signatures_valid",
        "all_artifact_digests_valid",
        "no_key_or_approval_revoked",
    ],
)
def test_rejects_failed_verification_claim(field):
    document = _envelope()
    document["verification"][field] = False
    with pytest.raises(ReportDefinitionTrustError, match=f"{field} must be true"):
        _load(document)


def test_rejects_verification_true_encoded_as_integer():
    document = _envelope()
    document["verification"]["all_signatures_valid"] = 1
    with pytest.raises(ReportDefinitionTrustError, match="must be true"):
        _load(document)


def test_rejects_production_promotion_claim():
    document = _envelope()
    document["verification"]["production_promotion_allowed"] = True
    with pytest.raises(ReportDefinitionTrustError, match="cannot authorize"):
        _load(document)


def test_rejects_wrong_signature_namespace():
    document = _envelope()
    document["verification"]["signature_namespace"] = "other"
    with pytest.raises(ReportDefinitionTrustError, match="namespace"):
        _load(document)


def test_rejects_invalid_ssh_keygen_digest():
    document = _envelope()
    document["verification"]["ssh_keygen_sha256"] = "unknown"
    with pytest.raises(ReportDefinitionTrustError, match="lowercase SHA-256"):
        _load(document)


def test_rejects_verification_schema_drift():
    document = _envelope()
    document["verification"]["extra"] = True
    with pytest.raises(ReportDefinitionTrustError, match="fields differ"):
        _load(document)


def test_rejects_not_after_beyond_catalog_entry_expiry():
    catalog = _catalog()
    for entry in catalog["entries"]:
        entry["expires_at"] = _timestamp(NOW + timedelta(minutes=3))
        for approval in entry["approvals"]:
            approval["expires_at"] = entry["expires_at"]
    document = _envelope(
        catalog=catalog,
        not_after=NOW + timedelta(minutes=4),
    )
    with pytest.raises(ReportDefinitionTrustError, match="catalog entry"):
        _load(document)


def test_rejects_not_after_beyond_catalog_approval_expiry():
    catalog = _catalog()
    catalog["entries"][0]["approvals"][0]["expires_at"] = _timestamp(
        NOW + timedelta(minutes=3)
    )
    document = _envelope(
        catalog=catalog,
        not_after=NOW + timedelta(minutes=4),
    )
    with pytest.raises(ReportDefinitionTrustError, match="catalog approval"):
        _load(document)


def test_rejects_verified_at_before_entry_valid_from():
    catalog = _catalog()
    valid_from = NOW - timedelta(seconds=30)
    for entry in catalog["entries"]:
        entry["valid_from"] = _timestamp(valid_from)
        for approval in entry["approvals"]:
            approval["valid_from"] = entry["valid_from"]
    document = _envelope(
        catalog=catalog,
        verified_at=NOW - timedelta(minutes=1),
    )
    with pytest.raises(ReportDefinitionTrustError, match="catalog entry"):
        _load(document)

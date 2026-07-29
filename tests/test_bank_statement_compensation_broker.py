from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from odoo_accounting_cli_v3.operations import Operation, State

from test_trusted_broker import (
    Harness,
    NOW,
    OLD_REGISTRY,
    OLD_RELEASE,
)


CAPABILITY = "acct.bank.statement_compensate.v1"


@pytest.fixture
def harness() -> Harness:
    return Harness()


def _origin(harness: Harness) -> Operation:
    requester = harness.sessions[
        "requester-session-0123456789abcdef"
    ]
    prepared = Operation.prepare(
        operation_id="old-bank-statement-import-origin",
        request_id="request-old-bank-statement-import-origin",
        capability_id="acct.bank.statement_import.v1",
        parameters={
            "company_id": 7,
            "journal_id": 9,
            "currency_id": 12,
            "source_digest": "5" * 64,
            "idempotency_key": "old-bank-import",
        },
        principal=requester.principal,
        user_id=requester.user_id,
        company_id=requester.company_id,
        idempotency_key="old-bank-import",
        odoo_instance_id=requester.odoo_instance_id,
        database_name=requester.database_name,
        database_uuid=requester.database_uuid,
        environment=requester.environment,
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )
    completed = replace(
        prepared,
        state=State.COMPLETED,
        revision=4,
        precheck_digest="a" * 64,
        approval_signature="b" * 64,
        approval_nonce_digest="c" * 64,
        approval_issued_at=NOW,
        approval_expires_at=NOW + timedelta(minutes=2),
        approval_revision=0,
        approver_user_id=84,
        execution_result_digest="d" * 64,
        verification_result_digest="e" * 64,
    )
    completed.assert_integrity()
    harness.operations[completed.operation_id] = completed
    return completed


def _request(origin: Operation) -> dict[str, object]:
    return {
        "capability_id": CAPABILITY,
        "parameters": {
            "company_id": 7,
            "origin_operation_id": origin.operation_id,
            "expected_origin_revision": origin.revision,
            "expected_origin_final_receipt_body_digest": "1" * 64,
            "expected_recovery_plan_digest": "2" * 64,
            "expected_statement_id": 701,
            "expected_journal_id": 9,
            "expected_currency_id": 12,
            "expected_source_digest": "5" * 64,
            "compensation_date": "2026-07-16",
            "reason": "Compensate the complete verified import batch",
            "idempotency_key": "compensate-old-bank-import",
        },
    }


def test_broker_forwards_all_twelve_parameters_and_pins_origin_release(
    harness: Harness,
) -> None:
    origin = _origin(harness)
    request = _request(origin)
    expected = deepcopy(request["parameters"])

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is True
    assert set(expected) == {
        "company_id",
        "origin_operation_id",
        "expected_origin_revision",
        "expected_origin_final_receipt_body_digest",
        "expected_recovery_plan_digest",
        "expected_statement_id",
        "expected_journal_id",
        "expected_currency_id",
        "expected_source_digest",
        "compensation_date",
        "reason",
        "idempotency_key",
    }
    action, forwarded = harness.executor.calls[-1]
    assert action == "operation.prepare"
    assert forwarded["parameters"] == expected
    assert result.executed_release_digest == OLD_RELEASE
    assert result.executed_registry_digest == OLD_REGISTRY


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("compensation_date", "2026-7-16"),
        ("compensation_date", "2026-02-30"),
        ("reason", ""),
        ("reason", " leading whitespace"),
        ("expected_statement_id", True),
        ("expected_journal_id", 0),
        ("expected_currency_id", -1),
        ("expected_origin_revision", 2147483648),
        ("expected_source_digest", "G" * 64),
        ("expected_recovery_plan_digest", "2" * 63),
    ),
)
def test_broker_rejects_malformed_compensation_before_authority(
    harness: Harness, field: str, value: object
) -> None:
    request = _request(_origin(harness))
    request["parameters"][field] = value

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_business_request_rejected"
    assert harness.authority_resolutions == []
    assert harness.executor.calls == []


def test_revision_business_exception_does_not_admit_nested_authority(
    harness: Harness,
) -> None:
    request = _request(_origin(harness))
    request["parameters"]["reason"] = {
        "metadata": [{"registryDigest": "8" * 64}]
    }

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_business_request_rejected"
    assert harness.authority_resolutions == []
    assert harness.executor.calls == []


def test_missing_retained_origin_release_has_no_current_fallback(
    harness: Harness,
) -> None:
    request = _request(_origin(harness))
    harness.authorities.pop((OLD_RELEASE, OLD_REGISTRY))

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert (
        result.body["error"]["code"]
        == "broker_release_authority_unavailable"
    )
    assert harness.executor.calls == []

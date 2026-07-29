from __future__ import annotations

from copy import deepcopy

import pytest

from test_trusted_broker import (
    Harness,
    OLD_REGISTRY,
    OLD_RELEASE,
    _reconciliation_undo_business_request,
    _seed_completed_reconciliation_origin,
)


@pytest.fixture
def harness() -> Harness:
    return Harness()


def test_reconciliation_undo_accepts_and_forwards_exactly_eight_business_parameters(
    harness: Harness,
) -> None:
    origin = _seed_completed_reconciliation_origin(harness)
    request = _reconciliation_undo_business_request(origin)
    expected_parameters = deepcopy(request["parameters"])

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is True
    assert set(expected_parameters) == {
        "company_id",
        "expected_origin_final_receipt_body_digest",
        "expected_origin_revision",
        "expected_recovery_plan_digest",
        "idempotency_key",
        "origin_operation_id",
        "reason",
        "recovery_date",
    }
    action, forwarded = harness.executor.calls[-1]
    assert action == "operation.prepare"
    assert forwarded["parameters"] == expected_parameters
    assert forwarded["parameters"]["expected_origin_revision"] == origin.revision
    assert result.executed_release_digest == OLD_RELEASE
    assert result.executed_registry_digest == OLD_REGISTRY


@pytest.mark.parametrize(
    "mutate",
    [
        lambda parameters: parameters.update({"release_digest": "7" * 64}),
        lambda parameters: parameters.update(
            {
                "reason": {
                    "metadata": [
                        {"expected_origin_revision": parameters["expected_origin_revision"]}
                    ]
                }
            }
        ),
        lambda parameters: parameters.update(
            {
                "expected_recovery_plan_digest": {
                    "nested": {"registryDigest": "8" * 64}
                }
            }
        ),
    ],
    ids=[
        "sibling-release-authority-field",
        "deep-revision-authority-field",
        "deep-normalized-registry-authority-field",
    ],
)
def test_reconciliation_undo_revision_exception_does_not_admit_other_authority_fields(
    harness: Harness,
    mutate,
) -> None:
    origin = _seed_completed_reconciliation_origin(harness)
    request = _reconciliation_undo_business_request(origin)
    mutate(request["parameters"])

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_business_request_rejected"
    assert harness.authority_resolutions == []
    assert harness.executor.calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("recovery_date", "2026-7-16"),
        ("recovery_date", "2026-02-30"),
        ("reason", ""),
        ("reason", " leading whitespace"),
        ("expected_origin_final_receipt_body_digest", "5" * 63),
        ("expected_recovery_plan_digest", "G" * 64),
        ("expected_origin_revision", True),
        ("expected_origin_revision", 2147483648),
    ],
)
def test_reconciliation_undo_rejects_malformed_typed_parameters_before_execution(
    harness: Harness,
    field: str,
    value: object,
) -> None:
    origin = _seed_completed_reconciliation_origin(harness)
    request = _reconciliation_undo_business_request(origin)
    request["parameters"][field] = value

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_business_request_rejected"
    assert harness.authority_resolutions == []
    assert harness.executor.calls == []


@pytest.mark.parametrize("shape", ["missing", "extra"])
def test_reconciliation_undo_requires_the_strict_eight_parameter_shape(
    harness: Harness,
    shape: str,
) -> None:
    origin = _seed_completed_reconciliation_origin(harness)
    request = _reconciliation_undo_business_request(origin)
    if shape == "missing":
        del request["parameters"]["reason"]
    else:
        request["parameters"]["unexpected"] = "not allowed"

    result = harness.dispatch("operation.prepare", request)

    assert result.status_code == 200
    assert result.body["ok"] is False
    assert result.body["error"]["code"] == "broker_business_request_rejected"
    assert harness.authority_resolutions == []
    assert harness.executor.calls == []

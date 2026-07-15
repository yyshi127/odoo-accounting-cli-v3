from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deployment" / "dev8"


@pytest.fixture(scope="module")
def checker():
    path = DEPLOYMENT / "check_toolchain.py"
    spec = importlib.util.spec_from_file_location("dev8_check_transition_history", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _document(name: str):
    return json.loads((DEPLOYMENT / name).read_text(encoding="utf-8"))


def _baseline_services():
    baseline = _document("SERVER-BASELINE.json")
    return {item["unit"]: item for item in baseline["services"]}


def test_transition_history_and_disposition_are_accepted(checker):
    transition = _document("SERVER-SERVICE-TRANSITION.json")
    disposition = _document("PRIOR-EVIDENCE-DISPOSITION.json")

    effective_pids = checker.validate_service_transition(
        transition, _baseline_services()
    )
    assert effective_pids == {
        "odoo19.service": 2576660,
        "sudo-pi-agent-bridge.service": 2065799,
    }
    assert transition["observation"] == transition["history"][-1]["observation"]
    assert transition["services"] == transition["history"][-1]["services"]
    assert transition["journal_transition_series"][
        "intermediate_full_service_identities_available"
    ] is False
    assert checker.validate_prior_evidence_disposition(
        disposition,
        transition["history"][0]["observation_id"],
        transition["history"][0]["observation"]["last_observed_at"],
    ) == disposition


TRANSITION_MUTATIONS = (
    "schema",
    "classification",
    "actor",
    "maintenance-authorization",
    "write-authorization",
    "promotion",
    "boot-id",
    "history-order",
    "history-id",
    "history-extra",
    "history-observation-time",
    "history-observation-extra",
    "history-service-extra",
    "history-baseline-pid",
    "history-effective-pid",
    "history-effective-pid-bool",
    "history-invocation",
    "history-pi-changed",
    "current-observation",
    "current-services",
    "series-source",
    "series-unit",
    "series-from",
    "series-to",
    "series-intermediate-identities",
    "series-count",
    "series-count-bool",
    "series-cycle-order",
    "series-cycle-number-bool",
    "series-cycle-time",
    "series-extra",
    "document-extra",
)


def _mutate_transition(document, mutation: str) -> None:
    if mutation == "schema":
        document["schema_version"] = 1
    elif mutation == "classification":
        document["classification"] = "out_of_band_service_transition_observed"
    elif mutation == "actor":
        document["actor_attribution"] = "maintenance-user"
    elif mutation == "maintenance-authorization":
        document["maintenance_authorization_verified"] = True
    elif mutation == "write-authorization":
        document["production_write_authorized"] = True
    elif mutation == "promotion":
        document["production_promotion_allowed"] = True
    elif mutation == "boot-id":
        document["system_boot_id"] = "0" * 36
    elif mutation == "history-order":
        document["history"].reverse()
    elif mutation == "history-id":
        document["history"][-1]["observation_id"] = document["history"][0][
            "observation_id"
        ]
    elif mutation == "history-extra":
        document["history"].append(copy.deepcopy(document["history"][-1]))
    elif mutation == "history-observation-time":
        document["history"][-1]["observation"]["first_observed_at"] = (
            "2026-07-14T14:52:00Z"
        )
    elif mutation == "history-observation-extra":
        document["history"][0]["observation"]["source"] = "systemd"
    elif mutation == "history-service-extra":
        document["history"][-1]["services"][0]["pid_source"] = "systemd"
    elif mutation == "history-baseline-pid":
        document["history"][-1]["services"][0]["baseline_main_pid"] = 2316421
    elif mutation == "history-effective-pid":
        document["history"][-1]["services"][0]["effective_main_pid"] = 2576661
    elif mutation == "history-effective-pid-bool":
        document["history"][-1]["services"][0]["effective_main_pid"] = True
    elif mutation == "history-invocation":
        document["history"][-1]["services"][0]["invocation_id"] = "0" * 32
    elif mutation == "history-pi-changed":
        document["history"][-1]["services"][1]["transition"] = "changed"
    elif mutation == "current-observation":
        document["observation"] = copy.deepcopy(document["history"][0]["observation"])
    elif mutation == "current-services":
        document["services"] = copy.deepcopy(document["history"][0]["services"])
    elif mutation == "series-source":
        document["journal_transition_series"]["source"] = "systemctl_status"
    elif mutation == "series-unit":
        document["journal_transition_series"]["unit"] = "sudo-pi-agent-bridge.service"
    elif mutation == "series-from":
        document["journal_transition_series"]["from_observation_id"] = "missing"
    elif mutation == "series-to":
        document["journal_transition_series"]["to_observation_id"] = "missing"
    elif mutation == "series-intermediate-identities":
        document["journal_transition_series"][
            "intermediate_full_service_identities_available"
        ] = True
    elif mutation == "series-count":
        document["journal_transition_series"]["restart_cycle_count"] = 12
    elif mutation == "series-count-bool":
        document["journal_transition_series"]["restart_cycle_count"] = True
    elif mutation == "series-cycle-order":
        document["journal_transition_series"]["restart_cycles"][0:2] = reversed(
            document["journal_transition_series"]["restart_cycles"][0:2]
        )
    elif mutation == "series-cycle-number-bool":
        document["journal_transition_series"]["restart_cycles"][0]["cycle"] = True
    elif mutation == "series-cycle-time":
        document["journal_transition_series"]["restart_cycles"][9]["started_at"] = (
            "2026-07-14T15:37:23Z"
        )
    elif mutation == "series-extra":
        document["journal_transition_series"]["actor"] = "unknown"
    elif mutation == "document-extra":
        document["notes"] = "not schema data"
    else:
        raise AssertionError(mutation)


@pytest.mark.parametrize("mutation", TRANSITION_MUTATIONS)
def test_transition_history_rejects_mutations(checker, mutation):
    transition = _document("SERVER-SERVICE-TRANSITION.json")
    _mutate_transition(transition, mutation)
    with pytest.raises(RuntimeError):
        checker.validate_service_transition(transition, _baseline_services())


@pytest.mark.parametrize(
    "mutation",
    (
        "invalidating-observation",
        "recorded-at",
        "status",
        "reason",
        "final",
        "promotion",
        "extra",
    ),
)
def test_disposition_rejects_history_binding_and_safety_mutations(checker, mutation):
    transition = _document("SERVER-SERVICE-TRANSITION.json")
    disposition = _document("PRIOR-EVIDENCE-DISPOSITION.json")
    if mutation == "invalidating-observation":
        disposition["invalidating_service_observation_id"] = transition["history"][1][
            "observation_id"
        ]
    elif mutation == "recorded-at":
        disposition["recorded_at"] = transition["history"][1]["observation"][
            "last_observed_at"
        ]
    elif mutation == "status":
        disposition["status"] = "final"
    elif mutation == "reason":
        disposition["reason_code"] = "accepted_after_restart"
    elif mutation == "final":
        disposition["final_verifier_passed"] = True
    elif mutation == "promotion":
        disposition["production_promotion_allowed"] = True
    elif mutation == "extra":
        disposition["notes"] = "not schema data"
    else:
        raise AssertionError(mutation)

    with pytest.raises(RuntimeError):
        checker.validate_prior_evidence_disposition(
            disposition,
            transition["history"][0]["observation_id"],
            transition["history"][0]["observation"]["last_observed_at"],
        )

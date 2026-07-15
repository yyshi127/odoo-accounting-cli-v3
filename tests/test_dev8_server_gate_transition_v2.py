from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deployment" / "dev8"
GATE = DEPLOYMENT / "dev8-server-gate.sh"
BASELINE = DEPLOYMENT / "SERVER-BASELINE.json"
TRANSITION = DEPLOYMENT / "SERVER-SERVICE-TRANSITION.json"


def _semantic_validator_source() -> str:
    source = GATE.read_text(encoding="utf-8")
    gate = source.index("verify_isolation() {")
    start = source.index("baseline_keys = {", gate)
    end = source.index("\ndef run(*arguments):", start)
    return source[start:end]


def _validate(document: dict) -> dict:
    baseline_payload = BASELINE.read_bytes()
    namespace = {
        "baseline": json.loads(baseline_payload),
        "baseline_sha256": hashlib.sha256(baseline_payload).hexdigest(),
        "baseline_size": len(baseline_payload),
        "transition": document,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "re": re,
    }
    exec(compile(_semantic_validator_source(), str(GATE), "exec"), namespace)
    return namespace["effective_services"]


def _document() -> dict:
    return json.loads(TRANSITION.read_text(encoding="utf-8"))


def test_server_gate_accepts_transition_v2_and_selects_only_latest_identity():
    document = _document()

    services = _validate(document)

    assert document["observation"] == document["history"][-1]["observation"]
    assert document["services"] == document["history"][-1]["services"]
    assert services["odoo19.service"] == {
        "active_state": "active",
        "baseline_main_pid": 2257341,
        "cmdline_sha256": "6b05fb91c48b5a5f06260786145c84718688ff62b5b23aa46d038d353ced15c1",
        "effective_main_pid": 2576660,
        "exec_main_start_monotonic_usec": 10877336849089,
        "invocation_id": "ae54787981dd466db3b03ae6148b62bb",
        "proc_start_ticks": 1087733684,
        "sub_state": "running",
        "transition": "changed",
        "unit": "odoo19.service",
    }
    assert services["sudo-pi-agent-bridge.service"]["effective_main_pid"] == 2065799


def test_server_gate_binds_the_exact_transition_control_bytes():
    payload = TRANSITION.read_bytes()
    source = GATE.read_text(encoding="utf-8")

    assert f"service_transition_sha={hashlib.sha256(payload).hexdigest()}" in source
    assert f"service_transition_size={len(payload)}" in source


def test_live_gate_compares_against_the_latest_full_service_identity():
    source = GATE.read_text(encoding="utf-8")

    assert (
        'service["unit"]: service for service in transition["history"][-1]["services"]'
        in source
    )
    for marker in (
        'sample["pid"] != expected["effective_main_pid"]',
        'properties.get("InvocationID") != expected["invocation_id"]',
        '!= expected["exec_main_start_monotonic_usec"]',
        'sample["boot_id"] != transition["system_boot_id"]',
        'sample["proc_start_ticks"] != expected["proc_start_ticks"]',
        'hashlib.sha256(sample["cmdline"]).hexdigest() != expected["cmdline_sha256"]',
    ):
        assert marker in source


MUTATIONS = (
    "schema",
    "classification",
    "production-write-authorized",
    "top-extra",
    "history-extra",
    "observation-extra",
    "service-extra",
    "history-count",
    "top-observation",
    "top-services",
    "observation-id",
    "valid-history-time-shift",
    "first-window-short",
    "latest-window-short",
    "windows-overlap",
    "first-odoo-identity",
    "latest-odoo-identity",
    "pi-identity-changed",
    "cmdline-hash",
    "boot-id",
    "series-extra",
    "series-source",
    "series-unit",
    "from-observation",
    "to-observation",
    "intermediate-identities",
    "cycle-count-bool",
    "cycle-count",
    "cycle-sequence",
    "cycle-extra",
    "valid-cycle-time-shift",
    "timestamp-no-microseconds",
    "stopping-after-start",
    "cycle-before-first-window",
    "cycle-after-latest-window",
    "second-segment-starts-at-middle-window",
    "cycles-overlap",
)


def _mutate(document: dict, mutation: str) -> None:
    history = document["history"]
    series = document["journal_transition_series"]
    cycles = series["restart_cycles"]
    if mutation == "schema":
        document["schema_version"] = 1
    elif mutation == "classification":
        document["classification"] = "out_of_band_service_transition_observed"
    elif mutation == "production-write-authorized":
        document["production_write_authorized"] = True
    elif mutation == "top-extra":
        document["extra"] = None
    elif mutation == "history-extra":
        history[0]["extra"] = None
    elif mutation == "observation-extra":
        history[0]["observation"]["extra"] = None
    elif mutation == "service-extra":
        history[0]["services"][0]["extra"] = None
    elif mutation == "history-count":
        history.pop()
    elif mutation == "top-observation":
        document["observation"]["last_observed_at"] = "2026-07-15T00:15:59Z"
    elif mutation == "top-services":
        document["services"][0]["effective_main_pid"] = 2344734
    elif mutation == "observation-id":
        history[0]["observation_id"] = "service-observation-20260714T145015Z"
    elif mutation == "valid-history-time-shift":
        history[0]["observation"]["first_observed_at"] = "2026-07-14T14:50:15Z"
        history[0]["observation_id"] = "service-observation-20260714T145015Z"
        series["from_observation_id"] = history[0]["observation_id"]
    elif mutation == "first-window-short":
        history[0]["observation"]["last_observed_at"] = history[0]["observation"][
            "first_observed_at"
        ]
    elif mutation == "latest-window-short":
        history[-1]["observation"]["last_observed_at"] = history[-1]["observation"][
            "first_observed_at"
        ]
        document["observation"] = copy.deepcopy(history[-1]["observation"])
    elif mutation == "windows-overlap":
        history[1]["observation"]["first_observed_at"] = "2026-07-14T14:53:29Z"
        history[1]["observation"]["last_observed_at"] = "2026-07-14T14:54:30Z"
        history[1]["observation_id"] = "service-observation-20260714T145329Z"
    elif mutation == "first-odoo-identity":
        history[0]["services"][0]["effective_main_pid"] += 1
    elif mutation == "latest-odoo-identity":
        history[-1]["services"][0]["invocation_id"] = history[-2]["services"][0][
            "invocation_id"
        ]
        document["services"] = copy.deepcopy(history[-1]["services"])
    elif mutation == "pi-identity-changed":
        history[-2]["services"][1]["proc_start_ticks"] += 1
    elif mutation == "cmdline-hash":
        history[0]["services"][0]["cmdline_sha256"] = "0" * 64
    elif mutation == "boot-id":
        document["system_boot_id"] = "00000000-0000-0000-0000-000000000000"
    elif mutation == "series-extra":
        series["extra"] = None
    elif mutation == "series-source":
        series["source"] = "unverified"
    elif mutation == "series-unit":
        series["unit"] = "sudo-pi-agent-bridge.service"
    elif mutation == "from-observation":
        series["from_observation_id"] = history[1]["observation_id"]
    elif mutation == "to-observation":
        series["to_observation_id"] = history[0]["observation_id"]
    elif mutation == "intermediate-identities":
        series["intermediate_full_service_identities_available"] = True
    elif mutation == "cycle-count-bool":
        series["restart_cycle_count"] = True
    elif mutation == "cycle-count":
        series["restart_cycle_count"] = 9
    elif mutation == "cycle-sequence":
        cycles[4]["cycle"] = 4
    elif mutation == "cycle-extra":
        cycles[0]["extra"] = None
    elif mutation == "valid-cycle-time-shift":
        cycles[0]["stopping_at"] = "2026-07-14T14:54:40.864134Z"
        cycles[0]["started_at"] = "2026-07-14T14:54:44.223189Z"
    elif mutation == "timestamp-no-microseconds":
        cycles[0]["stopping_at"] = "2026-07-14T14:54:40Z"
    elif mutation == "stopping-after-start":
        cycles[0]["stopping_at"] = cycles[0]["started_at"]
    elif mutation == "cycle-before-first-window":
        cycles[0]["stopping_at"] = "2026-07-14T14:53:29.000000Z"
    elif mutation == "cycle-after-latest-window":
        cycles[-1]["started_at"] = "2026-07-15T02:11:09.000000Z"
    elif mutation == "second-segment-starts-at-middle-window":
        cycles[10]["stopping_at"] = "2026-07-15T00:15:58.000000Z"
    elif mutation == "cycles-overlap":
        cycles[1]["stopping_at"] = cycles[0]["started_at"]
    else:  # pragma: no cover
        raise AssertionError(mutation)


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_server_gate_transition_v2_rejects_semantic_mutations(mutation):
    document = _document()
    _mutate(document, mutation)

    with pytest.raises(SystemExit):
        _validate(document)

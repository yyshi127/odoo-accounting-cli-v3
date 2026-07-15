from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deployment" / "dev8"
RUNTIME_SCRIPTS = (
    "dev8-freeze-evidence.py",
    "dev8-verify-frozen-evidence.py",
)


def _load_runtime_module(filename: str):
    added: list[str] = []
    for module_name in ("fcntl", "grp", "pwd"):
        if importlib.util.find_spec(module_name) is None:
            sys.modules[module_name] = types.ModuleType(module_name)
            added.append(module_name)
    try:
        module_name = "transition_runtime_v2_" + filename.replace("-", "_")
        spec = importlib.util.spec_from_file_location(module_name, DEPLOYMENT / filename)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for module_name in added:
            sys.modules.pop(module_name, None)


@pytest.fixture(scope="module", params=RUNTIME_SCRIPTS)
def runtime(request):
    return _load_runtime_module(request.param)


def _controls():
    baseline_payload = (DEPLOYMENT / "SERVER-BASELINE.json").read_bytes()
    return (
        baseline_payload,
        json.loads(baseline_payload),
        json.loads(
            (DEPLOYMENT / "SERVER-SERVICE-TRANSITION.json").read_text("utf-8")
        ),
        json.loads(
            (DEPLOYMENT / "PRIOR-EVIDENCE-DISPOSITION.json").read_text("utf-8")
        ),
    )


def _validate_transition(runtime, transition):
    baseline_payload, baseline, _, _ = _controls()
    validated_baseline = runtime.validate_server_baseline(baseline)
    return validated_baseline, runtime.validate_service_transition(
        transition, baseline_payload, validated_baseline
    )


def test_runtime_accepts_v2_and_uses_only_the_current_projection(runtime):
    _, _, transition, disposition = _controls()
    validated_baseline, validated_transition = _validate_transition(
        runtime, transition
    )

    assert transition["observation"] == transition["history"][-1]["observation"]
    assert transition["services"] == transition["history"][-1]["services"]
    assert runtime.validate_prior_evidence_disposition(disposition) == disposition
    assert runtime.effective_service_pids(
        validated_baseline, validated_transition
    ) == {
        "odoo19.service": 2576660,
        "sudo-pi-agent-bridge.service": 2065799,
    }

    prior_history_changed = copy.deepcopy(validated_transition)
    prior_history_changed["history"][-1]["services"][0][
        "effective_main_pid"
    ] = 9999999
    assert runtime.effective_service_pids(
        validated_baseline, prior_history_changed
    )["odoo19.service"] == 2576660


TRANSITION_MUTATIONS = (
    "schema",
    "classification",
    "boot",
    "top-extra",
    "history-count",
    "history-order",
    "history-fields",
    "observation-fields",
    "observation-id",
    "valid-time-shift",
    "first-window-short",
    "history-overlap",
    "current-observation",
    "current-services",
    "first-odoo-pid",
    "current-odoo-pid",
    "pi-identity",
    "cmdline",
    "service-fields",
    "integer-bool",
    "series-fields",
    "series-source",
    "series-unit",
    "series-from",
    "series-to",
    "series-identities",
    "cycle-count-bool",
    "cycle-count",
    "cycle-fields",
    "cycle-number",
    "cycle-time-format",
    "cycle-stop-after-start",
    "cycle-before-window",
    "cycle-after-window",
    "cycles-overlap",
)


def _mutate_transition(document: dict, mutation: str) -> None:
    history = document["history"]
    series = document["journal_transition_series"]
    cycles = series["restart_cycles"]
    if mutation == "schema":
        document["schema_version"] = 1
    elif mutation == "classification":
        document["classification"] = "out_of_band_service_transition_observed"
    elif mutation == "boot":
        document["system_boot_id"] = "00000000-0000-0000-0000-000000000000"
    elif mutation == "top-extra":
        document["notes"] = "not schema data"
    elif mutation == "history-count":
        history.pop()
    elif mutation == "history-order":
        history.reverse()
    elif mutation == "history-fields":
        history[0]["source"] = "systemd"
    elif mutation == "observation-fields":
        history[0]["observation"]["source"] = "systemd"
    elif mutation == "observation-id":
        history[0]["observation_id"] = "service-observation-20260714T145015Z"
    elif mutation == "valid-time-shift":
        shift = dt.timedelta(seconds=1)
        for entry in history:
            observation = entry["observation"]
            for field in ("first_observed_at", "last_observed_at"):
                parsed = dt.datetime.strptime(
                    observation[field], "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=dt.timezone.utc)
                observation[field] = (parsed + shift).strftime("%Y-%m-%dT%H:%M:%SZ")
            first_observed = dt.datetime.strptime(
                observation["first_observed_at"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=dt.timezone.utc)
            entry["observation_id"] = (
                "service-observation-" + first_observed.strftime("%Y%m%dT%H%M%SZ")
            )
        document["observation"] = copy.deepcopy(history[-1]["observation"])
        series["from_observation_id"] = history[0]["observation_id"]
        series["to_observation_id"] = history[-1]["observation_id"]
        for cycle in cycles:
            for field in ("stopping_at", "started_at"):
                parsed = dt.datetime.strptime(
                    cycle[field], "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=dt.timezone.utc)
                cycle[field] = (parsed + shift).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                )
    elif mutation == "first-window-short":
        history[0]["observation"]["last_observed_at"] = history[0]["observation"][
            "first_observed_at"
        ]
    elif mutation == "history-overlap":
        history[-1]["observation"]["first_observed_at"] = history[-2]["observation"][
            "last_observed_at"
        ]
    elif mutation == "current-observation":
        document["observation"] = copy.deepcopy(history[0]["observation"])
    elif mutation == "current-services":
        document["services"] = copy.deepcopy(history[0]["services"])
    elif mutation == "first-odoo-pid":
        history[0]["services"][0]["effective_main_pid"] += 1
    elif mutation == "current-odoo-pid":
        history[-1]["services"][0]["effective_main_pid"] += 1
    elif mutation == "pi-identity":
        history[-1]["services"][1]["proc_start_ticks"] += 1
    elif mutation == "cmdline":
        history[0]["services"][0]["cmdline_sha256"] = "0" * 64
    elif mutation == "service-fields":
        history[0]["services"][0]["pid_source"] = "systemd"
    elif mutation == "integer-bool":
        history[-1]["services"][0]["effective_main_pid"] = True
    elif mutation == "series-fields":
        series["actor"] = "unknown"
    elif mutation == "series-source":
        series["source"] = "systemctl_status"
    elif mutation == "series-unit":
        series["unit"] = "sudo-pi-agent-bridge.service"
    elif mutation == "series-from":
        series["from_observation_id"] = history[1]["observation_id"]
    elif mutation == "series-to":
        series["to_observation_id"] = history[0]["observation_id"]
    elif mutation == "series-identities":
        series["intermediate_full_service_identities_available"] = True
    elif mutation == "cycle-count-bool":
        series["restart_cycle_count"] = True
    elif mutation == "cycle-count":
        series["restart_cycle_count"] = 12
    elif mutation == "cycle-fields":
        cycles[0]["stopped_at"] = cycles[0].pop("stopping_at")
    elif mutation == "cycle-number":
        cycles[1]["cycle"] = 1
    elif mutation == "cycle-time-format":
        cycles[0]["stopping_at"] = "2026-07-14T14:54:40Z"
    elif mutation == "cycle-stop-after-start":
        cycles[0]["stopping_at"] = cycles[0]["started_at"]
    elif mutation == "cycle-before-window":
        cycles[0]["stopping_at"] = "2026-07-14T14:53:29.000000Z"
    elif mutation == "cycle-after-window":
        cycles[-1]["started_at"] = "2026-07-15T02:11:09.000000Z"
    elif mutation == "cycles-overlap":
        cycles[1]["stopping_at"] = cycles[0]["started_at"]
    else:  # pragma: no cover
        raise AssertionError(mutation)


@pytest.mark.parametrize("mutation", TRANSITION_MUTATIONS)
def test_runtime_rejects_v2_transition_mutations(runtime, mutation):
    _, _, transition, _ = _controls()
    _mutate_transition(transition, mutation)

    with pytest.raises(RuntimeError):
        _validate_transition(runtime, transition)


@pytest.mark.parametrize(
    "mutation",
    (
        "invalidating-observation",
        "recorded-at",
        "status",
        "reason",
        "final",
        "promotion",
        "prior-hash",
        "extra",
    ),
)
def test_runtime_rejects_disposition_mutations(runtime, mutation):
    _, _, _, disposition = _controls()
    if mutation == "invalidating-observation":
        disposition["invalidating_service_observation_id"] = (
            "service-observation-20260715T001423Z"
        )
    elif mutation == "recorded-at":
        disposition["recorded_at"] = "2026-07-15T00:15:58Z"
    elif mutation == "status":
        disposition["status"] = "final"
    elif mutation == "reason":
        disposition["reason_code"] = "accepted_after_restart"
    elif mutation == "final":
        disposition["final_verifier_passed"] = True
    elif mutation == "promotion":
        disposition["production_promotion_allowed"] = True
    elif mutation == "prior-hash":
        disposition["prior_evidence"]["anchor_sha256"] = "0" * 64
    elif mutation == "extra":
        disposition["notes"] = "not schema data"
    else:  # pragma: no cover
        raise AssertionError(mutation)

    with pytest.raises(RuntimeError):
        runtime.validate_prior_evidence_disposition(disposition)


@pytest.mark.parametrize("filename", RUNTIME_SCRIPTS)
def test_main_binds_disposition_to_history_zero_and_reports_current(filename):
    source = (DEPLOYMENT / filename).read_text("utf-8")

    assert 'invalidating_observation = service_transition["history"][0]' in source
    assert 'prior_disposition["invalidating_service_observation_id"]' in source
    assert 'service_transition_observation": service_transition["observation"]' in source


EVIDENCE_METADATA_FIELDS = frozenset(
    {
        "schema_version", "release", "evidence_id", "toolchain_version",
        "toolchain_manifest_sha256", "server_baseline_sha256",
        "server_baseline_size", "server_service_transition_sha256",
        "server_service_transition_size", "prior_evidence_disposition_sha256",
        "prior_evidence_disposition_size", "version", "commit", "git_tree",
        "package_sha256", "package_size", "manifest_sha256", "registry_digest",
        "runtime_config_sha256", "read_plan_sha256", "database_uuid", "audit_head",
        "auth_tokens", "consumed_receipts", "receipt_audit_events",
        "verified_batch_auth_tokens", "verified_batch_receipts",
        "verified_batch_audit_events", "verified_capabilities",
        "registered_capabilities", "staged_capabilities", "enabled_capabilities",
        "frozen_at", "evidence_scope", "evidence_visibility", "evidence_file_count",
        "freeze_checks_passed", "final_verification_status", "goal_complete",
        "secret_material_included", "production_writes_authorized",
        "odoo_accounting_write_performed", "pi_route_changed", "v2_changed",
        "production_dependency_closure_complete", "production_promotion_allowed",
        "promotion_blockers",
    }
)


@pytest.mark.parametrize("filename", RUNTIME_SCRIPTS)
def test_evidence_metadata_schema_is_exact_and_wired(filename):
    runtime = _load_runtime_module(filename)
    metadata = {field: None for field in EVIDENCE_METADATA_FIELDS}

    assert runtime.EVIDENCE_METADATA_FIELDS == EVIDENCE_METADATA_FIELDS
    assert runtime.validate_evidence_metadata_fields(metadata) is metadata

    with pytest.raises(RuntimeError):
        runtime.validate_evidence_metadata_fields({**metadata, "unexpected": None})
    missing = dict(metadata)
    missing.pop("final_verification_status")
    with pytest.raises(RuntimeError):
        runtime.validate_evidence_metadata_fields(missing)

    source = (DEPLOYMENT / filename).read_text("utf-8")
    if filename == "dev8-freeze-evidence.py":
        recovery = source.split("def validate_existing_target(", 1)[1].split(
            "def recover_anchor(", 1
        )[0]
        assert "validate_evidence_metadata_fields(metadata_document)" in recovery
    else:
        assert "validate_evidence_metadata_fields(metadata)" in source

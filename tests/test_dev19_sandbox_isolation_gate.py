from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = PROJECT_ROOT / "deployment" / "dev19" / "sandbox_isolation_gate.py"
PROBE_PATH = PROJECT_ROOT / "deployment" / "dev19" / "sandbox_namespace_probe.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("dev19_sandbox_isolation_gate", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_module()


def _load_probe_module():
    spec = importlib.util.spec_from_file_location(
        "dev19_sandbox_namespace_probe_for_gate_test", PROBE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


namespace_probe = _load_probe_module()

NOW = datetime(2026, 7, 18, 2, 0, tzinfo=UTC)
H = "a" * 64
H2 = "b" * 64
H3 = "c" * 64
H4 = "d" * 64
H5 = "e" * 64
PRODUCTION_UUID = "11111111-1111-4111-8111-111111111111"
PREVIOUS_UUID = "22222222-2222-4222-8222-222222222222"
SANDBOX_UUID = "33333333-3333-4333-8333-333333333333"
PREVIOUS_GENERATION = "44444444-4444-4444-8444-444444444444"
EXPECTED_HOST_NAMESPACE_NAMES = {
    "user": "user",
    "mnt": "mnt",
    "pid": "pid",
    "pid_for_children": "pid",
    "net": "net",
    "uts": "uts",
    "ipc": "ipc",
    "cgroup": "cgroup",
    "time": "time",
    "time_for_children": "time",
}


def installer_executable_rows() -> list[dict[str, object]]:
    return [
        {"path": path, "sha256": digest * 64, "size": size}
        for path, digest, size in (
            ("bin/odoo-accounting-cli-v3", "2", 20),
            ("bin/odoo-accounting-cli-v3-broker", "3", 30),
            ("deployment/dev9/run-private-mount-gate.sh", "4", 40),
        )
    ]
SANDBOX_GENERATION = "55555555-5555-4555-8555-555555555555"
RUN_ID = "66666666-6666-4666-8666-666666666666"


def install_live_clock(
    monkeypatch: pytest.MonkeyPatch,
    *,
    wall_times: list[datetime] | None = None,
    monotonic_times: list[int] | None = None,
) -> tuple[list[datetime], list[int]]:
    walls = list(wall_times or [NOW, NOW])
    monotonics = list(monotonic_times or [1_000_000_000, 1_500_000_000])
    observed_walls: list[datetime] = []
    observed_monotonics: list[int] = []

    def live_utc_now() -> datetime:
        value = walls.pop(0)
        observed_walls.append(value)
        return value

    def live_monotonic_ns() -> int:
        value = monotonics.pop(0)
        observed_monotonics.append(value)
        return value

    monkeypatch.setattr(gate, "_live_utc_now", live_utc_now, raising=False)
    monkeypatch.setattr(
        gate, "_live_monotonic_ns", live_monotonic_ns, raising=False
    )
    return observed_walls, observed_monotonics


def opening_approval_bindings() -> dict[str, str]:
    return {
        "approval_id": "e00b-policy-review-20260718-01",
        "approved_at": "2026-07-18T01:50:00Z",
        "allowlist_sha256": "1" * 64,
        "release_approval_allowlist_sha256": "2" * 64,
        "host_context_approval_sha256": "3" * 64,
        "recovery_approval_allowlist_sha256": "4" * 64,
    }


def policy() -> dict[str, object]:
    return {
        "kind": gate.POLICY_KIND,
        "policy_id": "e00b-sandbox-g2",
        "challenge_nonce": "f" * 64,
        "valid_from": "2026-07-18T01:55:00Z",
        "expires_at": "2026-07-18T02:05:00Z",
        "max_capture_duration_seconds": 120,
        "max_observation_age_seconds": 60,
        "collector_sha256": H,
        "dependencies": {
            "dev18_collector_sha256": "a" * 64,
            "namespace_probe_sha256": "b" * 64,
        },
        "release": {
            "release_id": "0.1.0.dev19-deadbeef0000",
            "manifest_sha256": H2,
            "package_sha256": H3,
            "release_root": "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev19-deadbeef0000",
            "trusted_anchor_path": "/opt/odoo-accounting-cli-v3/trusted-artifacts/0.1.0.dev19-deadbeef0000.json",
            "trusted_anchor_sha256": H4,
        },
        "e00a": {
            "policy_path": "/var/lib/odoo-accounting-cli-v3/evidence/e00a-policy.json",
            "policy_sha256": H2,
            "report_path": "/var/lib/odoo-accounting-cli-v3/evidence/e00a-report.json",
            "report_sha256": H3,
            "observation_path": "/var/lib/odoo-accounting-cli-v3/evidence/e00a-observation.json",
            "observation_sha256": H4,
            "captured_at": "2026-07-18T01:30:00Z",
            "production_cluster_system_identifier": "7612345678901234567",
            "protected_database_uuids": [PRODUCTION_UUID],
            "protected_identity_sha256": H5,
        },
        "host": {"machine_id_sha256": "1" * 64},
        "sandbox": {
            "environment": "sandbox",
            "odoo_instance_id": "odoo19@sandbox-g2",
            "database_name": "odoo_cli_v3_sandbox_g2",
            "database_uuid": SANDBOX_UUID,
            "database_filter": "^odoo_cli_v3_sandbox_g2$",
            "database_catalog_names": [
                "odoo_cli_v3_sandbox_g2",
                "postgres",
                "template0",
                "template1",
            ],
            "postgresql_identity_sha256": "2" * 64,
            "postgresql_service_unit": "postgresql@16-odoo-v3-sandbox.service",
            "postgresql_os_user": "odoo-v3-sandbox-pg",
            "postgresql_uid": 620,
            "postgresql_gid": 620,
            "postgresql_role": "odoo_v3_sandbox",
            "postgresql_data_dir": "/var/lib/postgresql/16/odoo-v3-sandbox",
            "postgresql_socket_dir": "/run/postgresql-odoo-v3-sandbox",
            "postgresql_port": 55432,
            "odoo_identity_sha256": "3" * 64,
            "odoo_service_unit": "odoo19-v3-sandbox.service",
            "odoo_os_user": "odoo-v3-sandbox",
            "odoo_uid": 621,
            "odoo_gid": 621,
            "odoo_config_path": "/etc/odoo19-v3-sandbox.conf",
            "odoo_executable_path": "/opt/odoo/odoo19/odoo-server/odoo-bin",
            "data_dir": "/var/lib/odoo19-v3-sandbox",
            "filestore_dir": "/var/lib/odoo19-v3-sandbox/filestore/odoo_cli_v3_sandbox_g2",
            "immutable_addon_roots": [
                "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev19-deadbeef0000/odoo_addons",
                "/opt/odoo/odoo19/odoo-server/addons",
            ],
            "sandbox_paths_identity_sha256": "4" * 64,
            "state_identity_sha256": "6" * 64,
            "secrets_identity_sha256": "0" * 64,
            "write_state_path": "/var/lib/odoo-accounting-cli-v3/sandbox/55555555-5555-4555-8555-555555555555/state.sqlite3",
            "secret_paths": [
                "/etc/odoo-accounting-cli-v3/sandbox/55555555-5555-4555-8555-555555555555/read.key",
                "/etc/odoo-accounting-cli-v3/sandbox/55555555-5555-4555-8555-555555555555/write.key",
            ],
            "sandbox_generation_id": SANDBOX_GENERATION,
            "executor_user_id": 42,
            "approver_user_id": 84,
            "allowed_company_ids": [7],
        },
        "production": {
            "protected_service_units": ["odoo19.service", "sudo-pi-agent-bridge.service"],
            "protected_paths": [
                "/etc/odoo19.conf",
                "/mnt/odoo/odoo19/filestore",
                "/mnt/odoo/odoo19/custom/addons",
                "/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2",
                "/opt/odoo-accounting-cli-v3/current",
            ],
            "protected_postgresql_sockets": ["/run/postgresql/.s.PGSQL.5432"],
            "protected_database_names": ["odoo", "odoo_sg", "odoo_test"],
            "protected_database_endpoints": [
                {
                    "endpoint_id": f"production-{database_name}",
                    "socket_path": "/run/postgresql/.s.PGSQL.5432",
                    "port": 5432,
                    "database_name": database_name,
                    "role_name": "odoo_v3_sandbox",
                    "cluster_system_identifier": "7612345678901234567",
                }
                for database_name in ("odoo", "odoo_sg", "odoo_test")
            ],
            "protected_identity_sha256": H5,
        },
        "recovery": {
            "drill_receipt_path": "/var/lib/odoo-accounting-cli-v3/evidence/sandbox-g2-reset.json",
            "drill_receipt_sha256": "5" * 64,
            "approval_id": "sandbox-g2-reset-approved",
            "approved_by_user_id": 84,
            "database_backup_path": "/var/lib/odoo-accounting-cli-v3/backups/sandbox-g1.dump",
            "database_backup_sha256": "7" * 64,
            "filestore_backup_path": "/var/lib/odoo-accounting-cli-v3/backups/sandbox-g1-filestore.tar",
            "filestore_backup_sha256": "8" * 64,
            "paired_manifest_path": "/var/lib/odoo-accounting-cli-v3/backups/sandbox-g1-pair.json",
            "paired_manifest_sha256": "9" * 64,
            "previous_database_uuid": PREVIOUS_UUID,
            "previous_generation_id": PREVIOUS_GENERATION,
            "previous_state_path": "/var/lib/odoo-accounting-cli-v3/sandbox/44444444-4444-4444-8444-444444444444/state.sqlite3",
            "previous_state_identity_sha256": "f" * 64,
            "old_evidence_path": "/var/lib/odoo-accounting-cli-v3/evidence/sandbox-g1",
            "old_evidence_identity_sha256": "e" * 64,
            "previous_key_ids": ["sandbox-g1-read", "sandbox-g1-write"],
            "new_key_ids": ["sandbox-g2-read", "sandbox-g2-write"],
        },
    }


def observation() -> dict[str, object]:
    p = policy()
    sandbox = p["sandbox"]
    production = p["production"]
    recovery = p["recovery"]
    assert isinstance(sandbox, dict)
    assert isinstance(production, dict)
    assert isinstance(recovery, dict)
    return {
        "kind": gate.OBSERVATION_KIND,
        "policy_id": p["policy_id"],
        "policy_sha256": gate._canonical_sha256(p),
        "challenge_nonce": p["challenge_nonce"],
        "run_id": RUN_ID,
        "capture_started_at": "2026-07-18T01:59:59.500000Z",
        "capture_finished_at": "2026-07-18T02:00:00Z",
        "capture_duration_ns": 500_000_000,
        "collector_sha256": p["collector_sha256"],
        "release": deepcopy(p["release"]),
        "e00a": deepcopy(p["e00a"]),
        "host": {
            "machine_id_sha256": "1" * 64,
            "host_mount_namespace": True,
        },
        "postgresql": {
            "identity_sha256": sandbox["postgresql_identity_sha256"],
            "service_unit": sandbox["postgresql_service_unit"],
            "service_active": True,
            "system_identifier": "7699999999999999999",
            "os_user": sandbox["postgresql_os_user"],
            "uid": sandbox["postgresql_uid"],
            "gid": sandbox["postgresql_gid"],
            "data_dir": sandbox["postgresql_data_dir"],
            "socket_dir": sandbox["postgresql_socket_dir"],
            "port": sandbox["postgresql_port"],
            "database_name": sandbox["database_name"],
            "database_uuid": sandbox["database_uuid"],
            "database_catalog_names": deepcopy(sandbox["database_catalog_names"]),
            "role": {
                "name": sandbox["postgresql_role"],
                "superuser": False,
                "create_db": False,
                "create_role": False,
                "inherit": False,
                "replication": False,
                "bypass_rls": False,
                "memberships": [],
                "owned_database_names": [sandbox["database_name"]],
                "connect_database_names": [sandbox["database_name"]],
            },
        },
        "odoo": {
            "identity_sha256": sandbox["odoo_identity_sha256"],
            "service_unit": sandbox["odoo_service_unit"],
            "service_active": True,
            "os_user": sandbox["odoo_os_user"],
            "uid": sandbox["odoo_uid"],
            "gid": sandbox["odoo_gid"],
            "environment": sandbox["environment"],
            "instance_id": sandbox["odoo_instance_id"],
            "config_path": sandbox["odoo_config_path"],
            "executable_path": sandbox["odoo_executable_path"],
            "data_dir": sandbox["data_dir"],
            "filestore_dir": sandbox["filestore_dir"],
            "immutable_addon_roots": deepcopy(sandbox["immutable_addon_roots"]),
            "paths_identity_sha256": sandbox["sandbox_paths_identity_sha256"],
            "db_name": sandbox["database_name"],
            "dbfilter": sandbox["database_filter"],
            "list_db": False,
            "max_cron_threads": 0,
            "cron_active_count": 0,
            "mail_server_active_count": 0,
            "external_integration_active_count": 0,
        },
        "service_isolation": {
            "mount_namespace_isolated": True,
            "network_namespace_isolated": True,
            "private_network": True,
            "outbound_network_denied": True,
            "no_new_privileges": True,
            "capability_bounding_set_empty": True,
            "no_inherited_production_fds": True,
            "immutable_addons_read_only": True,
        },
        "access_denials": {
            "paths": [
                {"target": target, "denied": True, "result": "EACCES"}
                for target in production["protected_paths"]
            ],
            "postgresql_sockets": [
                {"target": target, "denied": True, "result": "ENOENT"}
                for target in production["protected_postgresql_sockets"]
            ],
            "database_names": [
                {"target": target, "denied": True, "result": "UNREACHABLE"}
                for target in production["protected_database_names"]
            ],
            "database_endpoints": [
                {
                    **deepcopy(endpoint),
                    "denied": True,
                    "result": "ENOENT",
                }
                for endpoint in production["protected_database_endpoints"]
            ],
        },
        "principals": {
            "executor_user_id": sandbox["executor_user_id"],
            "approver_user_id": sandbox["approver_user_id"],
            "executor_active": True,
            "approver_active": True,
            "executor_admin": False,
            "approver_admin": False,
            "executor_company_ids": deepcopy(sandbox["allowed_company_ids"]),
            "approver_company_ids": deepcopy(sandbox["allowed_company_ids"]),
            "executor_only_group": True,
            "approver_only_group": True,
        },
        "state_isolation": {
            "generation_id": sandbox["sandbox_generation_id"],
            "write_state_path": sandbox["write_state_path"],
            "secret_paths": deepcopy(sandbox["secret_paths"]),
            "state_identity_sha256": "6" * 64,
            "secrets_identity_sha256": "0" * 64,
            "state_isolated": True,
            "secrets_isolated": True,
            "write_execution_mode": "disabled",
            "staged_write_capability_ids": [],
            "enabled_capability_ids": [],
        },
        "protected_identity": {
            "service_units": deepcopy(production["protected_service_units"]),
            "before_sha256": production["protected_identity_sha256"],
            "after_sha256": production["protected_identity_sha256"],
        },
        "recovery_drill": {
            "kind": "odoo-accounting-cli-v3.sandbox-recovery-drill-receipt.v1",
            "receipt_id": "sandbox-g2-reset-20260718",
            "receipt_path": recovery["drill_receipt_path"],
            "receipt_sha256": recovery["drill_receipt_sha256"],
            "approval_id": recovery["approval_id"],
            "approved_by_user_id": recovery["approved_by_user_id"],
            "host_machine_id_sha256": p["host"]["machine_id_sha256"],
            "release": deepcopy(p["release"]),
            "e00a_report_sha256": p["e00a"]["report_sha256"],
            "completed_at": "2026-07-18T01:45:00Z",
            "status": "PASSED",
            "writes_quiesced": True,
            "previous_database_uuid": recovery["previous_database_uuid"],
            "new_database_uuid": sandbox["database_uuid"],
            "previous_generation_id": recovery["previous_generation_id"],
            "new_generation_id": sandbox["sandbox_generation_id"],
            "previous_state_path": recovery["previous_state_path"],
            "new_state_path": sandbox["write_state_path"],
            "database_backup_path": recovery["database_backup_path"],
            "database_backup_sha256": "7" * 64,
            "filestore_backup_path": recovery["filestore_backup_path"],
            "filestore_backup_sha256": "8" * 64,
            "paired_manifest_path": recovery["paired_manifest_path"],
            "paired_manifest_sha256": "9" * 64,
            "seed_oracle_passed": True,
            "failure_atomic": True,
            "reset_canary_absent": True,
            "old_state_read_only": True,
            "old_evidence_retained": True,
            "previous_state_identity_sha256": "f" * 64,
            "old_evidence_path": recovery["old_evidence_path"],
            "old_evidence_identity_sha256": "e" * 64,
            "previous_key_ids": ["sandbox-g1-read", "sandbox-g1-write"],
            "new_key_ids": ["sandbox-g2-read", "sandbox-g2-write"],
            "keys_rotated": True,
        },
    }


def test_caller_supplied_observation_never_issues_live_gate_eligibility() -> None:
    report = gate.evaluate(policy(), observation(), now=NOW)

    assert report["contract_conditions_passed"] is True
    assert report["isolation_gate_passed"] is False
    assert report["eligible_for_sandbox_write_staging_review"] is False
    assert report["blockers"] == []
    assert report["trust_blockers"] == ["live_evidence_unverified"]
    assert report["evidence_origin"] == "caller_supplied_contract_test"
    assert report["sandbox_provisioning_authorized"] is False
    assert report["sandbox_accounting_write_authorized"] is False
    assert report["production_accounting_write_authorized"] is False
    assert report["registry_change_authorized"] is False


@pytest.mark.parametrize(
    ("section", "field", "value", "blocker"),
    [
        ("postgresql", "system_identifier", "7612345678901234567", "postgresql_cluster_independence"),
        ("postgresql", "database_uuid", PRODUCTION_UUID, "database_uuid"),
        ("postgresql", "database_catalog_names", ["odoo_cli_v3_sandbox_g2", "odoo"], "database_catalog"),
        ("odoo", "dbfilter", ".*", "odoo_database_filter"),
        ("odoo", "db_name", "odoo", "odoo_database_name"),
        ("odoo", "list_db", True, "odoo_list_db"),
        ("odoo", "max_cron_threads", 1, "odoo_cron"),
        ("odoo", "cron_active_count", 1, "odoo_cron"),
        ("odoo", "mail_server_active_count", 1, "odoo_mail"),
        ("odoo", "external_integration_active_count", 1, "odoo_external_integrations"),
        ("state_isolation", "write_execution_mode", "sandbox_staged", "write_execution_mode"),
        ("state_isolation", "staged_write_capability_ids", ["acct.invoice.customer_create.v1"], "write_capabilities_closed"),
        ("state_isolation", "enabled_capability_ids", ["acct.gl.trial_balance.v1"], "enabled_capabilities_closed"),
        ("recovery_drill", "status", "NOT_RUN", "recovery_drill"),
        ("recovery_drill", "new_database_uuid", PREVIOUS_UUID, "recovery_database_generation"),
        ("recovery_drill", "new_generation_id", PREVIOUS_GENERATION, "recovery_generation"),
        ("recovery_drill", "new_state_path", "/var/lib/odoo-accounting-cli-v3/old.sqlite3", "recovery_state_path"),
        ("recovery_drill", "old_evidence_retained", False, "recovery_old_evidence"),
        ("recovery_drill", "keys_rotated", False, "recovery_key_rotation"),
    ],
)
def test_semantic_failures_are_blockers(
    section: str, field: str, value: object, blocker: str
) -> None:
    candidate = observation()
    candidate[section][field] = value

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert report["isolation_gate_passed"] is False
    assert report["contract_conditions_passed"] is False
    assert blocker in report["blockers"]
    assert report["eligible_for_sandbox_write_staging_review"] is False


@pytest.mark.parametrize(
    "field",
    [
        "mount_namespace_isolated",
        "network_namespace_isolated",
        "private_network",
        "outbound_network_denied",
        "no_new_privileges",
        "capability_bounding_set_empty",
        "no_inherited_production_fds",
        "immutable_addons_read_only",
    ],
)
def test_each_service_isolation_control_is_mandatory(field: str) -> None:
    candidate = observation()
    candidate["service_isolation"][field] = False

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert "service_isolation" in report["blockers"]


@pytest.mark.parametrize(
    "kind", ["paths", "postgresql_sockets", "database_names", "database_endpoints"]
)
def test_each_production_access_target_must_be_denied(kind: str) -> None:
    candidate = observation()
    candidate["access_denials"][kind][0]["denied"] = False
    candidate["access_denials"][kind][0]["result"] = "ACCESSIBLE"

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert f"production_access_denial:{kind}" in report["blockers"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("socket_path", "/run/postgresql-odoo-v3-sandbox/.s.PGSQL.55432"),
        ("database_name", "odoo_cli_v3_sandbox_g2"),
        ("role_name", "postgres"),
        ("cluster_system_identifier", "7699999999999999999"),
    ],
)
def test_production_database_denial_is_bound_to_exact_endpoint(
    field: str, value: object
) -> None:
    candidate = observation()
    candidate["access_denials"]["database_endpoints"][0][field] = value

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert "production_access_denial:database_endpoints" in report["blockers"]


def test_policy_database_endpoint_coverage_is_exact() -> None:
    candidate = policy()
    candidate["production"]["protected_database_endpoints"].pop()

    with pytest.raises(gate.IsolationGateError, match="endpoint"):
        gate.evaluate(candidate, observation(), now=NOW)


def test_production_denial_target_set_cannot_be_omitted() -> None:
    candidate = observation()
    candidate["access_denials"]["paths"].pop()

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert "production_access_denial:paths" in report["blockers"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("approver_user_id", 42),
        ("executor_admin", True),
        ("approver_admin", True),
        ("executor_only_group", False),
        ("approver_only_group", False),
        ("executor_company_ids", [7, 8]),
        ("approver_company_ids", [8]),
    ],
)
def test_principal_separation_and_company_scope_are_mandatory(
    field: str, value: object
) -> None:
    candidate = observation()
    candidate["principals"][field] = value

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert "principal_separation" in report["blockers"]


@pytest.mark.parametrize(
    "field",
    ["superuser", "create_db", "create_role", "inherit", "replication", "bypass_rls"],
)
def test_postgresql_role_privilege_cannot_be_waived(field: str) -> None:
    candidate = observation()
    candidate["postgresql"]["role"][field] = True

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert "postgresql_role" in report["blockers"]


def test_postgresql_role_membership_and_database_reach_are_exact() -> None:
    member = observation()
    member["postgresql"]["role"]["memberships"] = ["pg_read_all_data"]
    assert "postgresql_role" in gate.evaluate(policy(), member, now=NOW)["blockers"]

    broad = observation()
    broad["postgresql"]["role"]["connect_database_names"].append("odoo")
    assert "postgresql_role" in gate.evaluate(policy(), broad, now=NOW)["blockers"]


def test_protected_identity_must_match_before_and_after() -> None:
    candidate = observation()
    candidate["protected_identity"]["after_sha256"] = "0" * 64

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert "protected_identity" in report["blockers"]


def test_recovery_key_sets_must_be_disjoint_even_when_rotation_flag_is_true() -> None:
    candidate = observation()
    candidate["recovery_drill"]["new_key_ids"] = ["sandbox-g1-read", "sandbox-g2-write"]

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert "recovery_key_rotation" in report["blockers"]


@pytest.mark.parametrize(
    ("section", "field", "value", "blocker"),
    [
        ("state_isolation", "state_identity_sha256", "a" * 64, "state_isolation"),
        ("state_isolation", "secrets_identity_sha256", "b" * 64, "state_isolation"),
        ("recovery_drill", "receipt_path", "/tmp/forged.json", "recovery_drill"),
        ("recovery_drill", "approval_id", "unapproved-reset", "recovery_drill"),
        ("recovery_drill", "approved_by_user_id", 42, "recovery_drill"),
        ("recovery_drill", "host_machine_id_sha256", "a" * 64, "recovery_drill"),
        ("recovery_drill", "completed_at", "2026-07-18T02:01:00Z", "recovery_drill"),
        ("recovery_drill", "database_backup_path", "/tmp/forged.dump", "recovery_artifacts"),
        ("recovery_drill", "database_backup_sha256", "a" * 64, "recovery_artifacts"),
        ("recovery_drill", "filestore_backup_path", "/tmp/forged.tar", "recovery_artifacts"),
        ("recovery_drill", "filestore_backup_sha256", "b" * 64, "recovery_artifacts"),
        ("recovery_drill", "paired_manifest_path", "/tmp/forged.json", "recovery_artifacts"),
        ("recovery_drill", "paired_manifest_sha256", "c" * 64, "recovery_artifacts"),
        ("recovery_drill", "previous_state_identity_sha256", "a" * 64, "recovery_old_evidence"),
        ("recovery_drill", "old_evidence_path", "/tmp/old", "recovery_old_evidence"),
        ("recovery_drill", "old_evidence_identity_sha256", "b" * 64, "recovery_old_evidence"),
    ],
)
def test_policy_pins_state_secrets_and_recovery_evidence(
    section: str, field: str, value: object, blocker: str
) -> None:
    candidate = observation()
    candidate[section][field] = value

    report = gate.evaluate(policy(), candidate, now=NOW)

    assert blocker in report["blockers"]


def test_release_binding_uses_path_ancestry_not_string_prefix_or_list_order() -> None:
    reordered = policy()
    reordered["sandbox"]["immutable_addon_roots"].reverse()
    gate.evaluate(reordered, observation(), now=NOW)

    sibling_prefix = policy()
    sibling_prefix["sandbox"]["immutable_addon_roots"][0] = (
        "/opt/odoo-accounting-cli-v3/releases/0.1.0.dev19-deadbeef00000/odoo_addons"
    )
    with pytest.raises(gate.IsolationGateError, match="add-on root"):
        gate.evaluate(sibling_prefix, observation(), now=NOW)

    outside_release_root = policy()
    outside_release_root["release"]["release_root"] = (
        "/tmp/0.1.0.dev19-deadbeef0000"
    )
    with pytest.raises(gate.IsolationGateError, match="immutable release layout"):
        gate.evaluate(outside_release_root, observation(), now=NOW)


def test_policy_window_and_observation_time_are_enforced() -> None:
    assert "policy_time" in gate.evaluate(policy(), observation(), now=datetime(2026, 7, 18, 2, 6, tzinfo=UTC))["blockers"]

    candidate = observation()
    candidate["capture_finished_at"] = "2026-07-18T02:06:00Z"
    assert "observation_time" in gate.evaluate(policy(), candidate, now=NOW)["blockers"]


@pytest.mark.parametrize(
    ("field", "value", "blocker"),
    [
        ("policy_id", "different-policy", "policy_binding"),
        ("policy_sha256", "0" * 64, "policy_binding"),
        ("challenge_nonce", "0" * 64, "policy_binding"),
        ("capture_started_at", "2026-07-18T01:57:00Z", "capture_duration"),
        ("capture_duration_ns", 1, "capture_duration"),
    ],
)
def test_observation_is_bound_to_policy_nonce_and_capture_window(
    field: str, value: object, blocker: str
) -> None:
    candidate = observation()
    candidate[field] = value

    assert blocker in gate.evaluate(policy(), candidate, now=NOW)["blockers"]


def test_stale_live_capture_contract_is_rejected() -> None:
    p = policy()
    p["max_observation_age_seconds"] = 10
    candidate = observation()
    candidate["policy_sha256"] = gate._canonical_sha256(p)

    report = gate.evaluate(
        p,
        candidate,
        now=datetime(2026, 7, 18, 2, 0, 11, tzinfo=UTC),
    )

    assert "observation_age" in report["blockers"]


def test_strict_json_rejects_duplicate_fields_and_nonfinite_numbers() -> None:
    with pytest.raises(gate.IsolationGateError, match="duplicate"):
        gate.load_strict_json(b'{"kind":"a","kind":"b"}')
    with pytest.raises(gate.IsolationGateError, match="non-finite"):
        gate.load_strict_json(b'{"value":NaN}')


@pytest.mark.parametrize(
    ("document", "path", "value"),
    [
        ("policy", ("sandbox", "odoo_uid"), True),
        ("observation", ("postgresql", "port"), True),
        ("observation", ("odoo", "list_db"), 0),
    ],
)
def test_exact_scalar_types_reject_bool_integer_confusion(
    document: str, path: tuple[str, str], value: object
) -> None:
    candidate = policy() if document == "policy" else observation()
    candidate[path[0]][path[1]] = value

    with pytest.raises(gate.IsolationGateError):
        gate.evaluate(policy(), candidate, now=NOW) if document == "observation" else gate.evaluate(candidate, observation(), now=NOW)


def test_extra_fields_are_rejected_in_each_top_level_document() -> None:
    extra_policy = policy()
    extra_policy["observation"] = observation()
    with pytest.raises(gate.IsolationGateError, match="fields"):
        gate.evaluate(extra_policy, observation(), now=NOW)

    extra_observation = observation()
    extra_observation["authorized"] = True
    with pytest.raises(gate.IsolationGateError, match="fields"):
        gate.evaluate(policy(), extra_observation, now=NOW)


def test_untrusted_namespace_probe_document_cannot_be_used_as_e00b_observation() -> None:
    candidate = observation()
    candidate["kind"] = namespace_probe.OBSERVATION_KIND

    with pytest.raises(gate.IsolationGateError, match="observation kind mismatch"):
        gate.evaluate(policy(), candidate, now=NOW)


def test_cli_does_not_accept_observation_or_clock_override() -> None:
    parser = gate._parser()
    with pytest.raises(gate.InvalidInvocationError):
        parser.parse_args(["--policy", "/root/policy.json", "--expected-policy-sha256", H, "--observation", "/tmp/fake.json"])
    with pytest.raises(gate.InvalidInvocationError):
        parser.parse_args(["--policy", "/root/policy.json", "--expected-policy-sha256", H, "--now", "2026-07-18T02:00:00Z"])


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--unknown"],
        ["--policy", "/root/policy.json"],
        [
            "--policy",
            "/root/policy.json",
            "--expected-policy-sha256",
            H,
            "extra",
        ],
        [
            "--policy",
            "/root/first.json",
            "--policy",
            "/root/second.json",
            "--expected-policy-sha256",
            H,
        ],
        [
            "--policy",
            "/root/policy.json",
            "--expected-policy-sha256",
            H,
            "--expected-policy-sha256",
            "b" * 64,
        ],
    ],
)
def test_invalid_invocation_emits_one_structured_deny_document(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = gate.main(argv)

    assert exit_code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1
    output = json.loads(captured.err)
    assert output["error"] == {
        "code": "invalid_invocation",
        "message": "command invocation is invalid",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_provisioning_authorized"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert output["registry_change_authorized"] is False


@pytest.mark.parametrize("argv", [["--help"], ["-h"]])
def test_help_is_a_structured_non_authorizing_nonzero_result(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = gate.main(argv)

    assert exit_code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1
    output = json.loads(captured.err)
    assert output["ok"] is False
    assert output["error"] == {
        "code": "help_requested",
        "message": "help is non-authorizing; use the deployed operator documentation",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_provisioning_authorized"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert output["registry_change_authorized"] is False


def test_system_exit_zero_cannot_turn_into_gate_success(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        gate,
        "_main",
        lambda _argv=None: (_ for _ in ()).throw(SystemExit(0)),
    )

    exit_code = gate.main([])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    output = json.loads(captured.err)
    assert output["ok"] is False
    assert output["error"]["code"] == "internal_error"
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False


def test_unexpected_internal_error_is_sanitized_and_denied(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        gate,
        "_read_policy",
        lambda *_args: (_ for _ in ()).throw(
            ValueError("secret=/root/private-token path=/sensitive")
        ),
    )

    exit_code = gate.main(
        ["--policy", "/root/policy.json", "--expected-policy-sha256", H]
    )

    assert exit_code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "secret" not in captured.err
    assert "sensitive" not in captured.err
    output = json.loads(captured.err)
    assert output["error"] == {
        "code": "internal_error",
        "message": "unexpected internal failure",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False


def test_cli_fails_closed_until_live_collector_is_available(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_walls, observed_monotonics = install_live_clock(monkeypatch)
    policy_path = tmp_path / "policy.json"
    payload = json.dumps(policy(), sort_keys=True, separators=(",", ":")).encode()
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    policy_approvals: list[tuple[object, str]] = []
    monkeypatch.setattr(
        gate,
        "_verify_policy_approval",
        lambda value, digest: policy_approvals.append((value, digest))
        or opening_approval_bindings(),
    )
    verified: list[object] = []
    monkeypatch.setattr(
        gate,
        "_verify_release_runtime",
        lambda value, cli_arguments, **_kwargs: verified.append(
            (value, cli_arguments)
        )
        or {},
    )
    dev18_module = object()
    monkeypatch.setattr(
        gate, "_load_dev18_verifier", lambda _value, _rows: dev18_module
    )
    prerequisites: list[tuple[object, object]] = []
    monkeypatch.setattr(
        gate,
        "_verify_e00a_prerequisite",
        lambda value, module, **_kwargs: prerequisites.append((value, module)) or {},
    )
    recoveries: list[object] = []
    monkeypatch.setattr(
        gate,
        "_verify_recovery_prerequisite",
        lambda value, **_kwargs: recoveries.append(value) or {},
    )
    final_host_checks: list[object] = []
    monkeypatch.setattr(
        gate,
        "_verify_initial_root_context",
        lambda value, **_kwargs: final_host_checks.append(value) or {},
    )
    monkeypatch.setattr(gate, "_verify_supporting_approval_roots", lambda _value: None)

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["ok"] is False
    assert output["error"]["code"] == "live_collector_unavailable"
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert verified == [
        (
            policy(),
            [
                "--policy",
                str(policy_path.resolve()),
                "--expected-policy-sha256",
                __import__("hashlib").sha256(payload).hexdigest(),
            ],
        )
    ]
    assert prerequisites == [(policy(), dev18_module)]
    assert recoveries == [policy()]
    assert final_host_checks == [policy()]
    assert policy_approvals == [
        (policy(), __import__("hashlib").sha256(payload).hexdigest())
    ]
    assert observed_walls == [NOW, NOW]
    assert observed_monotonics == [1_000_000_000, 1_500_000_000]


def test_cli_rejects_a_policy_without_fixed_external_approval(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    policy_path = tmp_path / "policy.json"
    payload = json.dumps(p, sort_keys=True, separators=(",", ":")).encode()
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate,
        "_verify_policy_approval",
        lambda *_args: (_ for _ in ()).throw(
            gate.IsolationGateError("E00b policy is not independently approved")
        ),
    )
    runtime_called: list[bool] = []
    monkeypatch.setattr(
        gate,
        "_verify_release_runtime",
        lambda *_args: runtime_called.append(True),
    )

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"] == {
        "code": "untrusted_policy",
        "message": "E00b policy is not independently approved",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert runtime_called == []


@pytest.mark.parametrize(
    "live_now",
    [
        datetime(2026, 7, 18, 1, 54, 59, tzinfo=UTC),
        datetime(2026, 7, 18, 2, 5, 1, tzinfo=UTC),
    ],
)
def test_operational_cli_rejects_policy_outside_its_live_utc_window_before_release_checks(
    live_now: datetime,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(
        monkeypatch,
        wall_times=[live_now],
        monotonic_times=[1_000_000_000],
    )
    p = policy()
    policy_path = tmp_path / "policy.json"
    payload = gate._canonical_bytes(p)
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )
    runtime_calls: list[bool] = []
    monkeypatch.setattr(
        gate,
        "_verify_release_runtime",
        lambda *_args: runtime_calls.append(True) or {},
    )

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"]["code"] == "inactive_policy"
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert runtime_calls == []


def test_operational_cli_rechecks_live_utc_policy_window_after_all_prerequisites(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expired = datetime(2026, 7, 18, 2, 5, 1, tzinfo=UTC)
    observed_walls, observed_monotonics = install_live_clock(
        monkeypatch,
        wall_times=[NOW, expired],
        monotonic_times=[1_000_000_000, 2_000_000_000],
    )
    p = policy()
    policy_path = tmp_path / "policy.json"
    payload = gate._canonical_bytes(p)
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )
    calls: list[str] = []
    monkeypatch.setattr(
        gate,
        "_verify_release_runtime",
        lambda *_args, **_kwargs: calls.append("release") or {},
    )
    monkeypatch.setattr(
        gate,
        "_load_dev18_verifier",
        lambda *_args: calls.append("dev18") or object(),
    )
    monkeypatch.setattr(
        gate,
        "_verify_e00a_prerequisite",
        lambda *_args, **_kwargs: calls.append("e00a") or {},
    )
    monkeypatch.setattr(
        gate,
        "_verify_recovery_prerequisite",
        lambda *_args, **_kwargs: calls.append("recovery") or {},
    )
    monkeypatch.setattr(
        gate,
        "_verify_initial_root_context",
        lambda *_args, **_kwargs: calls.append("host") or {},
    )
    monkeypatch.setattr(gate, "_verify_supporting_approval_roots", lambda _value: None)

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"]["code"] == "inactive_policy"
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert calls == ["release", "dev18", "e00a", "recovery", "host"]
    assert observed_walls == [NOW, expired]
    assert observed_monotonics == [1_000_000_000, 2_000_000_000]


def test_operational_cli_rejects_live_monotonic_clock_rollback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(
        monkeypatch,
        wall_times=[NOW, NOW],
        monotonic_times=[2_000_000_000, 1_000_000_000],
    )
    p = policy()
    policy_path = tmp_path / "policy.json"
    payload = gate._canonical_bytes(p)
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )
    monkeypatch.setattr(
        gate, "_verify_release_runtime", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(gate, "_load_dev18_verifier", lambda *_args: object())
    monkeypatch.setattr(
        gate, "_verify_e00a_prerequisite", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate, "_verify_recovery_prerequisite", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate, "_verify_initial_root_context", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(gate, "_verify_supporting_approval_roots", lambda _value: None)

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"] == {
        "code": "inactive_policy",
        "message": "live monotonic clock moved backwards",
    }
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False


@pytest.mark.parametrize(
    ("wall_times", "monotonic_times", "message"),
    [
        (
            [NOW, datetime(2026, 7, 18, 1, 59, 59, tzinfo=UTC)],
            [1_000_000_000, 2_000_000_000],
            "live UTC clock moved backwards",
        ),
        (
            [
                datetime(2026, 7, 18, 2, 4, 59, tzinfo=UTC),
                datetime(2026, 7, 18, 2, 4, 59, tzinfo=UTC),
            ],
            [1_000_000_000, 3_000_000_000],
            "policy expired according to live monotonic clock",
        ),
    ],
)
def test_live_policy_checkpoint_rejects_clock_rollback_or_stall(
    wall_times: list[datetime],
    monotonic_times: list[int],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(
        monkeypatch,
        wall_times=wall_times,
        monotonic_times=monotonic_times,
    )
    checkpoint = gate._verify_live_policy_time(policy())

    with pytest.raises(gate.IsolationGateError, match=message):
        gate._verify_live_policy_time(policy(), checkpoint)


def test_operational_cli_fails_closed_when_live_clock_is_not_timezone_aware(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(
        monkeypatch,
        wall_times=[datetime(2026, 7, 18, 2, 0)],
        monotonic_times=[1_000_000_000],
    )
    p = policy()
    policy_path = tmp_path / "policy.json"
    payload = gate._canonical_bytes(p)
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )
    runtime_calls: list[bool] = []
    monkeypatch.setattr(
        gate,
        "_verify_release_runtime",
        lambda *_args: runtime_calls.append(True) or {},
    )

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"]["code"] == "inactive_policy"
    assert runtime_calls == []


def test_operational_cli_rejects_policy_window_over_one_hour_before_approval(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    p["expires_at"] = "2026-07-18T02:55:01Z"
    policy_path = tmp_path / "policy.json"
    payload = gate._canonical_bytes(p)
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    approval_calls: list[bool] = []
    monkeypatch.setattr(
        gate,
        "_verify_policy_approval",
        lambda *_args: approval_calls.append(True) or {},
    )

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"] == {
        "code": "invalid_policy",
        "message": "policy time window is too long",
    }
    assert approval_calls == []


def test_operational_cli_threads_policy_approved_supporting_digests_and_rechecks_them(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    install_live_clock(monkeypatch)
    p = policy()
    bindings = {
        "approval_id": "e00b-policy-review-20260718-01",
        "approved_at": "2026-07-18T01:50:00Z",
        "allowlist_sha256": "1" * 64,
        "release_approval_allowlist_sha256": "2" * 64,
        "host_context_approval_sha256": "3" * 64,
        "recovery_approval_allowlist_sha256": "4" * 64,
    }
    policy_reads: list[tuple[str, str]] = []
    monkeypatch.setattr(
        gate,
        "_read_policy",
        lambda path, digest: policy_reads.append((path, digest)) or deepcopy(p),
    )
    approval_calls: list[tuple[object, str]] = []
    monkeypatch.setattr(
        gate,
        "_verify_policy_approval",
        lambda value, digest: approval_calls.append((value, digest))
        or deepcopy(bindings),
    )
    calls: list[tuple[str, str]] = []

    def verify_release(
        _value: object,
        _cli_arguments: list[str],
        *,
        expected_release_approval_allowlist_sha256: str,
        expected_host_context_approval_sha256: str,
    ) -> dict[str, object]:
        calls.append(("release", expected_release_approval_allowlist_sha256))
        calls.append(("release_host", expected_host_context_approval_sha256))
        return {}

    def verify_e00a(
        _value: object,
        _module: object,
        *,
        expected_host_context_approval_sha256: str,
    ) -> dict[str, object]:
        calls.append(("e00a_host", expected_host_context_approval_sha256))
        return {}

    def verify_recovery(
        _value: object, *, expected_recovery_approval_allowlist_sha256: str
    ) -> dict[str, object]:
        calls.append(("recovery", expected_recovery_approval_allowlist_sha256))
        return {}

    def verify_host(
        _value: object, *, expected_host_context_approval_sha256: str
    ) -> dict[str, object]:
        calls.append(("final_host", expected_host_context_approval_sha256))
        return {}

    monkeypatch.setattr(gate, "_verify_release_runtime", verify_release)
    monkeypatch.setattr(gate, "_load_dev18_verifier", lambda *_args: object())
    monkeypatch.setattr(gate, "_verify_e00a_prerequisite", verify_e00a)
    monkeypatch.setattr(gate, "_verify_recovery_prerequisite", verify_recovery)
    monkeypatch.setattr(gate, "_verify_initial_root_context", verify_host)
    supporting_rechecks: list[object] = []
    monkeypatch.setattr(
        gate,
        "_verify_supporting_approval_roots",
        lambda value: supporting_rechecks.append(deepcopy(value)),
        raising=False,
    )

    exit_code = gate.main(
        [
            "--policy",
            "/root/policy.json",
            "--expected-policy-sha256",
            H,
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"]["code"] == "live_collector_unavailable"
    assert calls == [
        ("release", "2" * 64),
        ("release_host", "3" * 64),
        ("e00a_host", "3" * 64),
        ("recovery", "4" * 64),
        ("final_host", "3" * 64),
    ]
    assert policy_reads == [("/root/policy.json", H), ("/root/policy.json", H)]
    assert approval_calls == [(p, H)]
    assert supporting_rechecks == [bindings]


def test_operational_cli_rejects_approval_bundle_drift_at_final_recheck(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    install_live_clock(monkeypatch)
    p = policy()
    initial = {
        "approval_id": "e00b-policy-review-20260718-01",
        "approved_at": "2026-07-18T01:50:00Z",
        "allowlist_sha256": "1" * 64,
        "release_approval_allowlist_sha256": "2" * 64,
        "host_context_approval_sha256": "3" * 64,
        "recovery_approval_allowlist_sha256": "4" * 64,
    }
    monkeypatch.setattr(gate, "_read_policy", lambda *_args: deepcopy(p))
    monkeypatch.setattr(
        gate,
        "_verify_policy_approval",
        lambda *_args: deepcopy(initial),
    )
    monkeypatch.setattr(gate, "_verify_release_runtime", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(gate, "_load_dev18_verifier", lambda *_args: object())
    monkeypatch.setattr(gate, "_verify_e00a_prerequisite", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        gate, "_verify_recovery_prerequisite", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate, "_verify_initial_root_context", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate,
        "_verify_supporting_approval_roots",
        lambda _value: (_ for _ in ()).throw(
            gate.IsolationGateError(
                "trusted approval bundle changed during verification"
            )
        ),
        raising=False,
    )

    exit_code = gate.main(
        [
            "--policy",
            "/root/policy.json",
            "--expected-policy-sha256",
            H,
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"] == {
        "code": "untrusted_policy",
        "message": "trusted approval bundle changed during verification",
    }
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False


def test_cli_rejects_host_context_drift_after_all_prerequisites(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(monkeypatch)
    p = policy()
    policy_path = tmp_path / "policy.json"
    payload = json.dumps(p, sort_keys=True, separators=(",", ":")).encode()
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )
    monkeypatch.setattr(
        gate, "_verify_release_runtime", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(gate, "_load_dev18_verifier", lambda _value, _rows: object())
    monkeypatch.setattr(
        gate, "_verify_e00a_prerequisite", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate, "_verify_recovery_prerequisite", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate,
        "_verify_initial_root_context",
        lambda _value, **_kwargs: (_ for _ in ()).throw(
            gate.IsolationGateError("live host context changed after prerequisites")
        ),
    )

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"] == {
        "code": "untrusted_runtime",
        "message": "live host context changed after prerequisites",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False


def test_cli_rejects_untrusted_release_runtime(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(monkeypatch)
    policy_path = tmp_path / "policy.json"
    payload = json.dumps(policy(), sort_keys=True, separators=(",", ":")).encode()
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )

    def reject_runtime(
        _value: object, _cli_arguments: list[str], **_kwargs: object
    ) -> None:
        raise gate.IsolationGateError("release dependency changed")

    monkeypatch.setattr(gate, "_verify_release_runtime", reject_runtime)
    prerequisite_called: list[bool] = []
    monkeypatch.setattr(
        gate,
        "_verify_e00a_prerequisite",
        lambda *_args: prerequisite_called.append(True),
    )

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["ok"] is False
    assert output["error"] == {
        "code": "untrusted_runtime",
        "message": "release dependency changed",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_provisioning_authorized"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert output["registry_change_authorized"] is False
    assert prerequisite_called == []


def test_cli_rejects_untrusted_e00a_prerequisite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(monkeypatch)
    policy_path = tmp_path / "policy.json"
    payload = json.dumps(policy(), sort_keys=True, separators=(",", ":")).encode()
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )
    monkeypatch.setattr(
        gate, "_verify_release_runtime", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate, "_load_dev18_verifier", lambda _value, _rows: object()
    )

    def reject_e00a(
        _value: object, _rows: object, **_kwargs: object
    ) -> None:
        raise gate.IsolationGateError("E00a report does not reproduce exactly")

    monkeypatch.setattr(gate, "_verify_e00a_prerequisite", reject_e00a)
    recovery_called: list[bool] = []
    monkeypatch.setattr(
        gate,
        "_verify_recovery_prerequisite",
        lambda _value: recovery_called.append(True),
    )

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"] == {
        "code": "untrusted_e00a",
        "message": "E00a report does not reproduce exactly",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False
    assert recovery_called == []


def test_cli_rejects_untrusted_recovery_prerequisite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_live_clock(monkeypatch)
    policy_path = tmp_path / "policy.json"
    payload = json.dumps(policy(), sort_keys=True, separators=(",", ":")).encode()
    policy_path.write_bytes(payload)
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    monkeypatch.setattr(
        gate, "_verify_policy_approval", lambda *_args: opening_approval_bindings()
    )
    monkeypatch.setattr(
        gate, "_verify_release_runtime", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        gate, "_load_dev18_verifier", lambda _value, _rows: object()
    )
    monkeypatch.setattr(
        gate, "_verify_e00a_prerequisite", lambda *_args, **_kwargs: {}
    )

    def reject_recovery(_value: object, **_kwargs: object) -> None:
        raise gate.IsolationGateError("recovery filestore_backup artifact changed")

    monkeypatch.setattr(gate, "_verify_recovery_prerequisite", reject_recovery)

    exit_code = gate.main(
        [
            "--policy",
            str(policy_path.resolve()),
            "--expected-policy-sha256",
            __import__("hashlib").sha256(payload).hexdigest(),
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().err)
    assert output["error"] == {
        "code": "untrusted_recovery",
        "message": "recovery filestore_backup artifact changed",
    }
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["sandbox_accounting_write_authorized"] is False
    assert output["production_accounting_write_authorized"] is False


def test_secure_file_reader_rejects_hardlinked_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "sys", SimpleNamespace(platform="contract-test"))
    policy_path = tmp_path / "policy.json"
    alias_path = tmp_path / "policy-alias.json"
    policy_path.write_bytes(b"{}")
    try:
        os.link(policy_path, alias_path)
    except (NotImplementedError, OSError):
        pytest.skip("hard links are unavailable")

    with pytest.raises(gate.IsolationGateError, match="one link"):
        gate._read_bounded_regular_file(policy_path.resolve(), "policy")


def _fake_linux_stat(
    *,
    mode: int,
    inode: int,
    links: int = 1,
    uid: int = 0,
    gid: int = 0,
    size: int = 0,
    mtime_ns: int = 1,
    ctime_ns: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        st_dev=7,
        st_ino=inode,
        st_size=size,
        st_mtime_ns=mtime_ns,
        st_ctime_ns=ctime_ns,
        st_mode=mode,
        st_uid=uid,
        st_gid=gid,
        st_nlink=links,
    )


def _install_linux_open_flags(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    flags = {
        "O_DIRECTORY": 1 << 20,
        "O_NOFOLLOW": 1 << 21,
        "O_CLOEXEC": 1 << 22,
    }
    real_os = gate.os
    monkeypatch.setattr(gate, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        gate,
        "os",
        SimpleNamespace(
            O_RDONLY=real_os.O_RDONLY,
            open=real_os.open,
            fstat=real_os.fstat,
            stat=real_os.stat,
            read=real_os.read,
            close=real_os.close,
        ),
    )
    for name, value in flags.items():
        monkeypatch.setattr(gate.os, name, value, raising=False)
    return flags


@pytest.mark.parametrize("operation", ["read", "hash"])
def test_linux_secure_file_access_uses_pinned_dirfds_and_closes_every_fd(
    operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    flags = _install_linux_open_flags(monkeypatch)
    path = PurePosixPath("/etc/odoo-accounting-cli-v3/approved-releases.json")
    payload = b'{"kind":"approval"}'
    directory_stats = {
        100: _fake_linux_stat(mode=__import__("stat").S_IFDIR | 0o755, inode=10),
        101: _fake_linux_stat(mode=__import__("stat").S_IFDIR | 0o755, inode=11),
        102: _fake_linux_stat(mode=__import__("stat").S_IFDIR | 0o750, inode=12),
    }
    file_stat = _fake_linux_stat(
        mode=__import__("stat").S_IFREG | 0o440,
        inode=20,
        size=len(payload),
    )
    open_results = iter([100, 101, 102, 103])
    open_calls: list[tuple[object, int, object]] = []
    closed: list[int] = []
    chunks = iter([payload, b""])

    def fake_open(
        name: object, open_flags: int, *, dir_fd: int | None = None
    ) -> int:
        open_calls.append((name, open_flags, dir_fd))
        return next(open_results)

    monkeypatch.setattr(gate.os, "open", fake_open)
    monkeypatch.setattr(
        gate.os,
        "fstat",
        lambda descriptor: directory_stats.get(descriptor, file_stat),
    )
    monkeypatch.setattr(
        gate.os,
        "stat",
        lambda name, *, dir_fd=None, follow_symlinks=True: file_stat,
    )
    monkeypatch.setattr(gate.os, "read", lambda _descriptor, _size: next(chunks))
    monkeypatch.setattr(gate.os, "close", closed.append)

    if operation == "read":
        assert gate._read_bounded_regular_file(path, "approval") == payload
    else:
        digest, size = gate._hash_bounded_regular_file(
            path, "approval", maximum_size=len(payload)
        )
        assert digest == __import__("hashlib").sha256(payload).hexdigest()
        assert size == len(payload)

    assert [(str(name), dir_fd) for name, _flags, dir_fd in open_calls] == [
        ("/", None),
        ("etc", 100),
        ("odoo-accounting-cli-v3", 101),
        ("approved-releases.json", 102),
    ]
    directory_mask = (
        flags["O_DIRECTORY"] | flags["O_NOFOLLOW"] | flags["O_CLOEXEC"]
    )
    assert all(
        open_flags & directory_mask == directory_mask
        for _name, open_flags, _dir_fd in open_calls[:3]
    )
    assert open_calls[-1][1] & flags["O_NOFOLLOW"]
    assert open_calls[-1][1] & flags["O_CLOEXEC"]
    assert not open_calls[-1][1] & flags["O_DIRECTORY"]
    assert closed == [100, 101, 103, 102]


@pytest.mark.parametrize("missing_flag", ["O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"])
def test_linux_secure_file_access_requires_every_critical_open_flag(
    missing_flag: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_linux_open_flags(monkeypatch)
    monkeypatch.delattr(gate.os, missing_flag, raising=False)
    opened: list[object] = []
    monkeypatch.setattr(
        gate.os, "open", lambda *_args, **_kwargs: opened.append(_args) or 100
    )

    with pytest.raises(gate.IsolationGateError, match="open flags are unavailable"):
        gate._verify_root_directory_chain(PurePosixPath("/etc"), "approval")

    assert opened == []


@pytest.mark.parametrize("failure", ["open", "unsafe"])
def test_linux_directory_walk_fails_closed_and_closes_descriptors(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_linux_open_flags(monkeypatch)
    calls: list[tuple[object, object]] = []
    closed: list[int] = []

    def fake_open(name: object, _flags: int, *, dir_fd: int | None = None) -> int:
        calls.append((name, dir_fd))
        if name == "etc" and failure == "open":
            raise OSError("simulated symlink or lookup failure")
        return 100 if name == "/" else 101

    def fake_fstat(descriptor: int) -> SimpleNamespace:
        return _fake_linux_stat(
            mode=__import__("stat").S_IFDIR | (0o777 if descriptor == 101 else 0o755),
            inode=descriptor,
        )

    monkeypatch.setattr(gate.os, "open", fake_open)
    monkeypatch.setattr(gate.os, "fstat", fake_fstat)
    monkeypatch.setattr(gate.os, "close", closed.append)

    with pytest.raises(gate.IsolationGateError, match="ancestor"):
        gate._verify_root_directory_chain(PurePosixPath("/etc/private"), "approval")

    assert calls == [("/", None), ("etc", 100)]
    assert closed == ([100] if failure == "open" else [101, 100])


@pytest.mark.parametrize(
    ("mode", "links", "message"),
    [
        (__import__("stat").S_IFREG | 0o440, 2, "one link"),
        (__import__("stat").S_IFDIR | 0o550, 1, "regular file"),
    ],
)
def test_linux_secure_file_access_rejects_unsafe_final_metadata_and_closes_fds(
    mode: int,
    links: int,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_linux_open_flags(monkeypatch)
    final_stat = _fake_linux_stat(mode=mode, inode=20, links=links)
    descriptors = iter([100, 101, 102])
    closed: list[int] = []
    monkeypatch.setattr(
        gate.os,
        "open",
        lambda _name, _flags, *, dir_fd=None: next(descriptors),
    )
    monkeypatch.setattr(
        gate.os,
        "fstat",
        lambda descriptor: (
            _fake_linux_stat(
                mode=__import__("stat").S_IFDIR | 0o755, inode=descriptor
            )
            if descriptor != 102
            else final_stat
        ),
    )
    monkeypatch.setattr(
        gate.os,
        "stat",
        lambda _name, *, dir_fd=None, follow_symlinks=True: final_stat,
    )
    monkeypatch.setattr(gate.os, "close", closed.append)

    with pytest.raises(gate.IsolationGateError, match=message):
        gate._read_bounded_regular_file(
            PurePosixPath("/etc/approval.json"), "approval"
        )

    assert closed == [100, 102, 101]


@pytest.mark.parametrize("drift", ["fingerprint", "directory_entry"])
def test_linux_secure_reader_rejects_open_inode_or_directory_entry_drift(
    drift: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_linux_open_flags(monkeypatch)
    payload = b"trusted"
    stable = _fake_linux_stat(
        mode=__import__("stat").S_IFREG | 0o440,
        inode=20,
        size=len(payload),
    )
    changed = _fake_linux_stat(
        mode=stable.st_mode,
        inode=21 if drift == "directory_entry" else 20,
        size=len(payload),
        mtime_ns=2,
    )
    descriptors = iter([100, 101, 102])
    closed: list[int] = []
    chunks = iter([payload, b""])
    file_fstats = iter([stable, changed if drift == "fingerprint" else stable])
    entry_stats = iter([stable, changed if drift == "directory_entry" else stable])

    monkeypatch.setattr(
        gate.os,
        "open",
        lambda _name, _flags, *, dir_fd=None: next(descriptors),
    )

    def fake_fstat(descriptor: int) -> SimpleNamespace:
        if descriptor == 102:
            return next(file_fstats)
        return _fake_linux_stat(
            mode=__import__("stat").S_IFDIR | 0o755, inode=descriptor
        )

    monkeypatch.setattr(gate.os, "fstat", fake_fstat)
    monkeypatch.setattr(
        gate.os,
        "stat",
        lambda _name, *, dir_fd=None, follow_symlinks=True: next(entry_stats),
    )
    monkeypatch.setattr(gate.os, "read", lambda _descriptor, _size: next(chunks))
    monkeypatch.setattr(gate.os, "close", closed.append)

    with pytest.raises(gate.IsolationGateError, match="changed while being read"):
        gate._read_bounded_regular_file(
            PurePosixPath("/etc/approval.json"), "approval"
        )

    assert closed == [100, 102, 101]


def test_secure_streaming_hasher_binds_digest_size_and_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gate, "sys", SimpleNamespace(platform="contract-test"))
    artifact_path = (tmp_path / "backup.dump").resolve()
    payload = (b"verified-backup-block\n" * 4096) + b"end"
    artifact_path.write_bytes(payload)

    digest, size = gate._hash_bounded_regular_file(
        artifact_path,
        "backup artifact",
        maximum_size=len(payload),
    )

    assert digest == __import__("hashlib").sha256(payload).hexdigest()
    assert size == len(payload)
    with pytest.raises(gate.IsolationGateError, match="size is invalid"):
        gate._hash_bounded_regular_file(
            artifact_path,
            "backup artifact",
            maximum_size=len(payload) - 1,
        )


def test_pinned_json_uses_raw_file_digest_and_strict_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"kind":"receipt"}'
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)
    digest = __import__("hashlib").sha256(payload).hexdigest()

    assert gate._read_pinned_json("/root/receipt.json", digest, "receipt") == {
        "kind": "receipt"
    }
    with pytest.raises(gate.IsolationGateError, match="SHA-256 mismatch"):
        gate._read_pinned_json("/root/receipt.json", "0" * 64, "receipt")

    duplicate = b'{"kind":"a","kind":"b"}'
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: duplicate)
    with pytest.raises(gate.IsolationGateError, match="duplicate"):
        gate._read_pinned_json(
            "/root/receipt.json",
            __import__("hashlib").sha256(duplicate).hexdigest(),
            "receipt",
        )


def test_live_recovery_loader_derives_path_and_raw_digest_from_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    expected = observation()["recovery_drill"]
    document = {
        key: deepcopy(value)
        for key, value in expected.items()
        if key not in {"receipt_path", "receipt_sha256"}
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    digest = __import__("hashlib").sha256(payload).hexdigest()
    p["recovery"]["drill_receipt_sha256"] = digest
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: payload)

    loaded = gate._load_recovery_receipt(p)

    assert loaded == {
        **document,
        "receipt_path": p["recovery"]["drill_receipt_path"],
        "receipt_sha256": digest,
    }


def test_recovery_pair_manifest_strictly_binds_both_backup_artifacts() -> None:
    p = policy()
    receipt = observation()["recovery_drill"]
    manifest = {
        "kind": "odoo-accounting-cli-v3.sandbox-recovery-pair-manifest.v1",
        "manifest_id": "sandbox-g1-pair-20260718",
        "receipt_id": receipt["receipt_id"],
        "approval_id": receipt["approval_id"],
        "host_machine_id_sha256": receipt["host_machine_id_sha256"],
        "release": deepcopy(receipt["release"]),
        "e00a_report_sha256": receipt["e00a_report_sha256"],
        "created_at": "2026-07-18T01:44:00Z",
        "previous_database_uuid": receipt["previous_database_uuid"],
        "previous_generation_id": receipt["previous_generation_id"],
        "previous_state_path": receipt["previous_state_path"],
        "artifacts": [
            {
                "kind": "database_backup",
                "path": p["recovery"]["database_backup_path"],
                "sha256": p["recovery"]["database_backup_sha256"],
                "size": 123,
            },
            {
                "kind": "filestore_backup",
                "path": p["recovery"]["filestore_backup_path"],
                "sha256": p["recovery"]["filestore_backup_sha256"],
                "size": 456,
            },
        ],
    }

    artifacts = gate._validate_recovery_pair_manifest(manifest, p, receipt)

    assert artifacts["database_backup"]["size"] == 123
    assert artifacts["filestore_backup"]["size"] == 456

    tampered = deepcopy(manifest)
    tampered["artifacts"][1]["path"] = "/tmp/unpinned-filestore.tar"
    with pytest.raises(gate.IsolationGateError, match="does not match recovery policy"):
        gate._validate_recovery_pair_manifest(tampered, p, receipt)


def test_recovery_drill_requires_a_fixed_external_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    receipt = observation()["recovery_drill"]
    allowlist = recovery_allowlist(p, receipt)
    allowlist_payload = gate._canonical_bytes(allowlist)
    allowlist_sha256 = __import__("hashlib").sha256(allowlist_payload).hexdigest()
    reads: list[tuple[str, str]] = []

    def read(path: Path, label: str) -> bytes:
        reads.append((path.as_posix(), label))
        return allowlist_payload

    monkeypatch.setattr(gate, "_read_bounded_regular_file", read)

    result = gate._verify_recovery_approval(
        p,
        receipt,
        expected_recovery_approval_allowlist_sha256=allowlist_sha256,
    )

    assert result["approval_id"] == receipt["approval_id"]
    assert reads == [
        (
            gate.TRUSTED_RECOVERY_ALLOWLIST_PATH,
            "trusted recovery drill approval allowlist",
        )
    ]
    forged = deepcopy(receipt)
    forged["receipt_sha256"] = "0" * 64
    with pytest.raises(gate.IsolationGateError, match="not independently approved"):
        gate._verify_recovery_approval(
            p,
            forged,
            expected_recovery_approval_allowlist_sha256=allowlist_sha256,
        )


def test_recovery_approval_must_match_the_policy_approved_raw_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    receipt = observation()["recovery_drill"]
    allowlist = recovery_allowlist(p, receipt)
    allowlist_payload = gate._canonical_bytes(allowlist)
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: allowlist_payload,
    )

    with pytest.raises(
        gate.IsolationGateError, match="changed since policy approval"
    ):
        gate._verify_recovery_approval(
            p,
            receipt,
            expected_recovery_approval_allowlist_sha256="0" * 64,
        )


def test_unrelated_recovery_approval_window_does_not_poison_the_selected_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    receipt = observation()["recovery_drill"]
    allowlist = recovery_allowlist(p, receipt)
    unrelated = deepcopy(allowlist["approvals"][0])
    unrelated.update(
        {
            "approval_id": "sandbox-g9-reset-approved",
            "approved_at": "2030-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:10:00Z",
            "receipt_sha256": "a" * 64,
            "previous_database_uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "new_database_uuid": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "previous_generation_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "new_generation_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        }
    )
    allowlist["approvals"].append(unrelated)
    allowlist_payload = gate._canonical_bytes(allowlist)
    allowlist_sha256 = __import__("hashlib").sha256(allowlist_payload).hexdigest()
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: allowlist_payload,
    )

    result = gate._verify_recovery_approval(
        p,
        receipt,
        expected_recovery_approval_allowlist_sha256=allowlist_sha256,
    )

    assert result["approval_id"] == receipt["approval_id"]


@pytest.mark.parametrize(
    "mutation", ["duplicate_receipt", "duplicate_approval", "future", "wrong_expiry"]
)
def test_recovery_approval_allowlist_rejects_ambiguous_or_invalid_rows(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = policy()
    receipt = observation()["recovery_drill"]
    allowlist = recovery_allowlist(p, receipt)
    if mutation == "duplicate_receipt":
        duplicate = deepcopy(allowlist["approvals"][0])
        duplicate["approval_id"] = "sandbox-g2-reset-approved-2"
        allowlist["approvals"].append(duplicate)
    elif mutation == "duplicate_approval":
        duplicate = deepcopy(allowlist["approvals"][0])
        duplicate["receipt_sha256"] = "0" * 64
        allowlist["approvals"].append(duplicate)
    elif mutation == "future":
        allowlist["approvals"][0]["approved_at"] = "2026-07-18T01:56:00Z"
    elif mutation == "wrong_expiry":
        allowlist["approvals"][0]["expires_at"] = "2026-07-18T02:04:00Z"
    allowlist_payload = gate._canonical_bytes(allowlist)
    allowlist_sha256 = __import__("hashlib").sha256(allowlist_payload).hexdigest()
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: allowlist_payload,
    )

    with pytest.raises(gate.IsolationGateError):
        gate._verify_recovery_approval(
            p,
            receipt,
            expected_recovery_approval_allowlist_sha256=allowlist_sha256,
        )


def test_recovery_prerequisite_hashes_real_artifacts_and_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    receipt = observation()["recovery_drill"]
    manifest = {
        "kind": "odoo-accounting-cli-v3.sandbox-recovery-pair-manifest.v1",
        "manifest_id": "sandbox-g1-pair-20260718",
        "receipt_id": receipt["receipt_id"],
        "approval_id": receipt["approval_id"],
        "host_machine_id_sha256": receipt["host_machine_id_sha256"],
        "release": deepcopy(receipt["release"]),
        "e00a_report_sha256": receipt["e00a_report_sha256"],
        "created_at": "2026-07-18T01:44:00Z",
        "previous_database_uuid": receipt["previous_database_uuid"],
        "previous_generation_id": receipt["previous_generation_id"],
        "previous_state_path": receipt["previous_state_path"],
        "artifacts": [
            {
                "kind": "database_backup",
                "path": p["recovery"]["database_backup_path"],
                "sha256": p["recovery"]["database_backup_sha256"],
                "size": 123,
            },
            {
                "kind": "filestore_backup",
                "path": p["recovery"]["filestore_backup_path"],
                "sha256": p["recovery"]["filestore_backup_sha256"],
                "size": 456,
            },
        ],
    }
    monkeypatch.setattr(gate, "_load_recovery_receipt", lambda _policy: receipt)
    approval_payload = gate._canonical_bytes(recovery_allowlist(p, receipt))
    approval_sha256 = __import__("hashlib").sha256(approval_payload).hexdigest()
    approved_receipts: list[tuple[object, object, str]] = []

    def verify_recovery_approval(
        policy_value: object,
        receipt_value: object,
        *,
        expected_recovery_approval_allowlist_sha256: str,
    ) -> dict[str, str]:
        approved_receipts.append(
            (
                policy_value,
                receipt_value,
                expected_recovery_approval_allowlist_sha256,
            )
        )
        return {"approval_sha256": "a" * 64}

    monkeypatch.setattr(
        gate,
        "_verify_recovery_approval",
        verify_recovery_approval,
    )
    monkeypatch.setattr(
        gate,
        "_read_pinned_json",
        lambda path, digest, label: manifest
        if path == p["recovery"]["paired_manifest_path"]
        and digest == p["recovery"]["paired_manifest_sha256"]
        and label == "recovery pair manifest"
        else pytest.fail("unexpected pinned JSON read"),
    )
    observed_hashes = {
        p["recovery"]["database_backup_path"]: (
            p["recovery"]["database_backup_sha256"],
            123,
        ),
        p["recovery"]["filestore_backup_path"]: (
            p["recovery"]["filestore_backup_sha256"],
            456,
        ),
    }
    monkeypatch.setattr(
        gate,
        "_hash_bounded_regular_file",
        lambda path, _label, maximum_size: observed_hashes[path.as_posix()],
    )

    result = gate._verify_recovery_prerequisite(
        p,
        expected_recovery_approval_allowlist_sha256=approval_sha256,
    )

    assert result["receipt_id"] == receipt["receipt_id"]
    assert result["artifacts_verified"] is True
    assert result["approval_sha256"] == "a" * 64
    assert approved_receipts == [(p, receipt, approval_sha256)]

    observed_hashes[p["recovery"]["filestore_backup_path"]] = ("0" * 64, 456)
    with pytest.raises(gate.IsolationGateError, match="artifact changed"):
        gate._verify_recovery_prerequisite(
            p,
            expected_recovery_approval_allowlist_sha256=approval_sha256,
        )


def test_e00a_bundle_loader_reads_each_independently_pinned_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    payloads = {
        "e00a-policy.json": b'{"kind":"capacity-policy"}',
        "e00a-observation.json": b'{"kind":"capacity-observation"}',
        "e00a-report.json": b'{"kind":"capacity-report"}',
    }
    for name, digest_field in (
        ("e00a-policy.json", "policy_sha256"),
        ("e00a-observation.json", "observation_sha256"),
        ("e00a-report.json", "report_sha256"),
    ):
        p["e00a"][digest_field] = __import__("hashlib").sha256(payloads[name]).hexdigest()
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda path, _label: payloads[path.name],
    )

    assert gate._load_e00a_bundle(p) == {
        "policy": {"kind": "capacity-policy"},
        "observation": {"kind": "capacity-observation"},
        "report": {"kind": "capacity-report"},
    }


def test_e00a_bundle_must_reproduce_a_passing_non_authorizing_dev18_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    context = approved_live_host_context()
    approval = host_context_approval(p, context)
    e00a_observation = {
        "host": {
            "hostname": context["hostname"],
            "machine_id_sha256": context["machine_id_sha256"],
            "boot_id_sha256": context["boot_id_sha256"],
        },
        "provenance": {
            "mount_namespace_identity_sha256": gate._canonical_sha256(
                context["namespaces"]["mnt"]
            )
        },
        "target": {
            "database_name": p["sandbox"]["database_name"],
            "database_exists": False,
        },
        "postgresql": {
            "system_identifier": p["e00a"]["production_cluster_system_identifier"]
        },
        "catalog": [{"name": "odoo"}],
        "databases": [{"name": "odoo", "uuid": PRODUCTION_UUID}],
        "protected_resources": [{"resource_id": "production-v2"}],
    }
    p["e00a"]["protected_identity_sha256"] = gate._canonical_sha256(
        {
            "postgresql": e00a_observation["postgresql"],
            "catalog": e00a_observation["catalog"],
            "databases": e00a_observation["databases"],
            "protected_resources": e00a_observation["protected_resources"],
        }
    )
    report = {
        "evaluated_at": "2026-07-18T01:30:00Z",
        "capture_finished_at": p["e00a"]["captured_at"],
        "capacity_gate_passed": True,
        "eligible_for_sandbox_provisioning_review": True,
        "sandbox_provisioning_authorized": False,
        "sandbox_accounting_write_authorized": False,
        "production_accounting_write_authorized": False,
        "observation": e00a_observation,
    }

    class FakeDev18:
        @staticmethod
        def _validate_policy(value):
            return value

        @staticmethod
        def _validate_observation(value):
            return value

        @staticmethod
        def evaluate(*_args, **_kwargs):
            return deepcopy(report)

    approval_payload = gate._canonical_bytes(approval)
    approval_sha256 = __import__("hashlib").sha256(approval_payload).hexdigest()
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: approval_payload,
    )

    result = gate._verify_e00a_bundle(
        p,
        {"policy": {"kind": "policy"}, "observation": e00a_observation, "report": report},
        FakeDev18,
        expected_host_context_approval_sha256=approval_sha256,
    )

    assert result["protected_identity_sha256"] == p["e00a"][
        "protected_identity_sha256"
    ]
    assert result["host_context_approval_sha256"] == __import__("hashlib").sha256(
        gate._canonical_bytes(approval)
    ).hexdigest()

    denied = deepcopy(report)
    denied["sandbox_provisioning_authorized"] = True
    with pytest.raises(gate.IsolationGateError, match="does not reproduce"):
        gate._verify_e00a_bundle(
            p,
            {"policy": {}, "observation": e00a_observation, "report": denied},
            FakeDev18,
            expected_host_context_approval_sha256=approval_sha256,
        )


def test_release_manifest_binds_version_commit_and_all_gate_dependencies() -> None:
    p = policy()
    version = "0.1.0.dev19"
    commit = "d" * 40
    p["release"]["release_id"] = f"{version}-{commit[:12]}"
    files = [
        {
            "path": "deployment/dev19/sandbox_isolation_gate.py",
            "sha256": p["collector_sha256"],
            "size": 100,
        },
        {
            "path": "deployment/dev18/sandbox_capacity_gate.py",
            "sha256": p["dependencies"]["dev18_collector_sha256"],
            "size": 200,
        },
        {
            "path": "deployment/dev19/sandbox_namespace_probe.py",
            "sha256": p["dependencies"]["namespace_probe_sha256"],
            "size": 300,
        },
        *installer_executable_rows(),
    ]
    unsigned = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "files": files,
    }
    manifest = {
        **unsigned,
        "manifest_sha256": gate._canonical_sha256(unsigned),
    }
    p["release"]["manifest_sha256"] = manifest["manifest_sha256"]

    rows = gate._validate_release_manifest(manifest, p)

    assert set(rows) == {item["path"] for item in files}

    tampered = deepcopy(manifest)
    tampered["files"][2]["sha256"] = "0" * 64
    tampered_unsigned = {key: value for key, value in tampered.items() if key != "manifest_sha256"}
    tampered["manifest_sha256"] = gate._canonical_sha256(tampered_unsigned)
    p["release"]["manifest_sha256"] = tampered["manifest_sha256"]
    with pytest.raises(gate.IsolationGateError, match="dependency digest mismatch"):
        gate._validate_release_manifest(tampered, p)


def test_release_manifest_digest_matches_official_ascii_escaped_canonicalization() -> None:
    p = policy()
    version = "0.1.0.dev19"
    commit = "d" * 40
    p["release"]["release_id"] = f"{version}-{commit[:12]}"
    files = [
        {
            "path": "deployment/dev19/sandbox_isolation_gate.py",
            "sha256": p["collector_sha256"],
            "size": 100,
        },
        {
            "path": "deployment/dev18/sandbox_capacity_gate.py",
            "sha256": p["dependencies"]["dev18_collector_sha256"],
            "size": 200,
        },
        {
            "path": "deployment/dev19/sandbox_namespace_probe.py",
            "sha256": p["dependencies"]["namespace_probe_sha256"],
            "size": 300,
        },
        {"path": "docs/会计.txt", "sha256": "1" * 64, "size": 10},
        *installer_executable_rows(),
    ]
    unsigned = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "files": files,
    }
    official_digest = __import__("hashlib").sha256(
        json.dumps(
            unsigned,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    manifest = {**unsigned, "manifest_sha256": official_digest}
    p["release"]["manifest_sha256"] = official_digest

    gate._validate_release_manifest(manifest, p)

    manifest["manifest_sha256"] = gate._canonical_sha256(unsigned)
    p["release"]["manifest_sha256"] = manifest["manifest_sha256"]
    with pytest.raises(gate.IsolationGateError, match="manifest digest mismatch"):
        gate._validate_release_manifest(manifest, p)


def test_rehashed_policy_and_manifest_cannot_replace_trusted_release_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    manifest = {"commit": "d" * 40}
    anchor = {
        "release": p["release"]["release_id"],
        "commit": manifest["commit"],
        "manifest_sha256": p["release"]["manifest_sha256"],
        "package_sha256": p["release"]["package_sha256"],
    }
    monkeypatch.setattr(gate, "_read_pinned_json", lambda *_args: deepcopy(anchor))

    assert gate._verify_release_anchor(p, manifest) == anchor

    forged = deepcopy(p)
    forged["release"]["manifest_sha256"] = "0" * 64
    forged["release"]["package_sha256"] = "1" * 64
    with pytest.raises(gate.IsolationGateError, match="anchor identity mismatch"):
        gate._verify_release_anchor(forged, manifest)


def release_allowlist(
    p: dict[str, object], manifest: dict[str, object]
) -> dict[str, object]:
    return {
        "kind": "odoo-accounting-cli-v3.release-approval-allowlist.v1",
        "approvals": [
            {
                "approval_id": "release-review-20260718-01",
                "approved_at": "2026-07-18T01:45:00Z",
                "release_id": p["release"]["release_id"],
                "commit": manifest["commit"],
                "manifest_sha256": p["release"]["manifest_sha256"],
                "package_sha256": p["release"]["package_sha256"],
                "trusted_anchor_sha256": p["release"]["trusted_anchor_sha256"],
            }
        ],
    }


def policy_allowlist(p: dict[str, object], policy_sha256: str) -> dict[str, object]:
    supporting = supporting_approval_payloads(p)
    return {
        "kind": "odoo-accounting-cli-v3.e00b-policy-approval-allowlist.v1",
        "approvals": [
            {
                "approval_id": "e00b-policy-review-20260718-01",
                "approved_at": "2026-07-18T01:50:00Z",
                "expires_at": p["expires_at"],
                "policy_id": p["policy_id"],
                "policy_sha256": policy_sha256,
                "challenge_nonce": p["challenge_nonce"],
                "release_id": p["release"]["release_id"],
                "e00a_report_sha256": p["e00a"]["report_sha256"],
                "sandbox_generation_id": p["sandbox"]["sandbox_generation_id"],
                "release_approval_allowlist_sha256": __import__("hashlib").sha256(
                    supporting[gate.TRUSTED_RELEASE_ALLOWLIST_PATH]
                ).hexdigest(),
                "host_context_approval_sha256": __import__("hashlib").sha256(
                    supporting[gate.TRUSTED_HOST_CONTEXT_PATH]
                ).hexdigest(),
                "recovery_approval_allowlist_sha256": __import__("hashlib").sha256(
                    supporting[gate.TRUSTED_RECOVERY_ALLOWLIST_PATH]
                ).hexdigest(),
            }
        ],
    }


def recovery_allowlist(
    p: dict[str, object], receipt: dict[str, object]
) -> dict[str, object]:
    return {
        "kind": "odoo-accounting-cli-v3.recovery-drill-approval-allowlist.v1",
        "approvals": [
            {
                "approval_id": receipt["approval_id"],
                "approved_by_user_id": receipt["approved_by_user_id"],
                "approved_at": "2026-07-18T01:50:00Z",
                "expires_at": p["expires_at"],
                "receipt_sha256": receipt["receipt_sha256"],
                "paired_manifest_sha256": receipt["paired_manifest_sha256"],
                "database_backup_sha256": receipt["database_backup_sha256"],
                "filestore_backup_sha256": receipt["filestore_backup_sha256"],
                "e00a_report_sha256": receipt["e00a_report_sha256"],
                "release_id": receipt["release"]["release_id"],
                "previous_database_uuid": receipt["previous_database_uuid"],
                "new_database_uuid": receipt["new_database_uuid"],
                "previous_generation_id": receipt["previous_generation_id"],
                "new_generation_id": receipt["new_generation_id"],
            }
        ],
    }


def approved_live_host_context() -> dict[str, object]:
    return {
        "hostname": "VM-0-6-ubuntu",
        "machine_id_sha256": "1" * 64,
        "boot_id_sha256": "2" * 64,
        "namespaces": {
            name: {
                "device": 4,
                "inode": 4_026_531_800 + index,
                "link": f"{kernel_name}:[{4_026_531_800 + index}]",
            }
            for index, (name, kernel_name) in enumerate(
                EXPECTED_HOST_NAMESPACE_NAMES.items(), 1
            )
        },
    }


def host_context_approval(
    p: dict[str, object], context: dict[str, object]
) -> dict[str, object]:
    return {
        "kind": "odoo-accounting-cli-v3.host-context-approval.v1",
        "approval_id": "host-review-20260718-01",
        "approved_at": "2026-07-18T01:45:00Z",
        "e00a_report_sha256": p["e00a"]["report_sha256"],
        "e00a_observation_sha256": p["e00a"]["observation_sha256"],
        "host": deepcopy(context),
    }


def supporting_approval_payloads(p: dict[str, object]) -> dict[str, bytes]:
    return {
        gate.TRUSTED_RELEASE_ALLOWLIST_PATH: gate._canonical_bytes(
            release_allowlist(p, {"commit": "d" * 40})
        ),
        gate.TRUSTED_HOST_CONTEXT_PATH: gate._canonical_bytes(
            host_context_approval(p, approved_live_host_context())
        ),
        gate.TRUSTED_RECOVERY_ALLOWLIST_PATH: gate._canonical_bytes(
            recovery_allowlist(p, observation()["recovery_drill"])
        ),
    }


def test_release_requires_fixed_root_allowlist_not_a_policy_selected_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    manifest = {"commit": "d" * 40}
    allowlist = release_allowlist(p, manifest)
    allowlist_payload = gate._canonical_bytes(allowlist)
    allowlist_sha256 = __import__("hashlib").sha256(allowlist_payload).hexdigest()
    reads: list[tuple[str, str]] = []

    def read(path: Path, label: str) -> bytes:
        reads.append((path.as_posix(), label))
        return allowlist_payload

    monkeypatch.setattr(gate, "_read_bounded_regular_file", read)

    result = gate._verify_release_approval(
        p,
        manifest,
        expected_release_approval_allowlist_sha256=allowlist_sha256,
    )

    assert result["approval_id"] == "release-review-20260718-01"
    assert result["allowlist_sha256"] == __import__("hashlib").sha256(
        gate._canonical_bytes(allowlist)
    ).hexdigest()
    assert reads == [
        (gate.TRUSTED_RELEASE_ALLOWLIST_PATH, "trusted release approval allowlist")
    ]

    forged = deepcopy(p)
    forged["release"]["manifest_sha256"] = "0" * 64
    forged["release"]["trusted_anchor_sha256"] = "1" * 64
    with pytest.raises(gate.IsolationGateError, match="not independently approved"):
        gate._verify_release_approval(
            forged,
            manifest,
            expected_release_approval_allowlist_sha256=allowlist_sha256,
        )


def test_release_approval_must_match_the_policy_approved_raw_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    manifest = {"commit": "d" * 40}
    allowlist = release_allowlist(p, manifest)
    allowlist_payload = gate._canonical_bytes(allowlist)
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: allowlist_payload,
    )

    with pytest.raises(
        gate.IsolationGateError, match="changed since policy approval"
    ):
        gate._verify_release_approval(
            p,
            manifest,
            expected_release_approval_allowlist_sha256="0" * 64,
        )


def test_unrelated_future_release_approval_does_not_poison_the_selected_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    manifest = {"commit": "d" * 40}
    allowlist = release_allowlist(p, manifest)
    unrelated = deepcopy(allowlist["approvals"][0])
    unrelated.update(
        {
            "approval_id": "release-review-20300101-01",
            "approved_at": "2030-01-01T00:00:00Z",
            "release_id": "0.1.0.dev99-aaaaaaaaaaaa",
            "commit": "e" * 40,
            "manifest_sha256": "a" * 64,
            "package_sha256": "b" * 64,
            "trusted_anchor_sha256": "c" * 64,
        }
    )
    allowlist["approvals"].append(unrelated)
    allowlist_payload = gate._canonical_bytes(allowlist)
    allowlist_sha256 = __import__("hashlib").sha256(allowlist_payload).hexdigest()
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: allowlist_payload,
    )

    result = gate._verify_release_approval(
        p,
        manifest,
        expected_release_approval_allowlist_sha256=allowlist_sha256,
    )

    assert result["approval_id"] == "release-review-20260718-01"


@pytest.mark.parametrize("mutation", ["duplicate_release", "duplicate_approval", "extra_field", "future"])
def test_release_approval_allowlist_rejects_ambiguous_or_unapproved_rows(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = policy()
    manifest = {"commit": "d" * 40}
    allowlist = release_allowlist(p, manifest)
    if mutation == "duplicate_release":
        duplicate = deepcopy(allowlist["approvals"][0])
        duplicate["approval_id"] = "release-review-20260718-02"
        allowlist["approvals"].append(duplicate)
    elif mutation == "duplicate_approval":
        duplicate = deepcopy(allowlist["approvals"][0])
        duplicate["release_id"] = "0.1.0.dev19-cafebabefeed"
        allowlist["approvals"].append(duplicate)
    elif mutation == "extra_field":
        allowlist["approvals"][0]["caller_digest"] = "a" * 64
    elif mutation == "future":
        allowlist["approvals"][0]["approved_at"] = "2026-07-18T02:01:00Z"
    allowlist_payload = gate._canonical_bytes(allowlist)
    allowlist_sha256 = __import__("hashlib").sha256(allowlist_payload).hexdigest()
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: allowlist_payload,
    )

    with pytest.raises(gate.IsolationGateError):
        gate._verify_release_approval(
            p,
            manifest,
            expected_release_approval_allowlist_sha256=allowlist_sha256,
        )


def test_policy_requires_a_fixed_external_raw_digest_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    policy_sha256 = gate._canonical_sha256(p)
    allowlist = policy_allowlist(p, policy_sha256)
    payloads = {
        gate.TRUSTED_POLICY_ALLOWLIST_PATH: gate._canonical_bytes(allowlist),
        **supporting_approval_payloads(p),
    }
    reads: list[tuple[str, str]] = []

    def read(path: Path, label: str) -> bytes:
        reads.append((path.as_posix(), label))
        return payloads[path.as_posix()]

    monkeypatch.setattr(gate, "_read_bounded_regular_file", read)

    result = gate._verify_policy_approval(p, policy_sha256)

    assert result["approval_id"] == "e00b-policy-review-20260718-01"
    assert result["release_approval_allowlist_sha256"] == allowlist["approvals"][0][
        "release_approval_allowlist_sha256"
    ]
    assert result["host_context_approval_sha256"] == allowlist["approvals"][0][
        "host_context_approval_sha256"
    ]
    assert result["recovery_approval_allowlist_sha256"] == allowlist["approvals"][
        0
    ]["recovery_approval_allowlist_sha256"]
    assert [item[0] for item in reads] == [
        gate.TRUSTED_POLICY_ALLOWLIST_PATH,
        gate.TRUSTED_RELEASE_ALLOWLIST_PATH,
        gate.TRUSTED_HOST_CONTEXT_PATH,
        gate.TRUSTED_RECOVERY_ALLOWLIST_PATH,
    ]
    with pytest.raises(gate.IsolationGateError, match="not independently approved"):
        gate._verify_policy_approval(p, "0" * 64)


def test_unrelated_policy_approval_window_does_not_poison_the_selected_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    policy_sha256 = gate._canonical_sha256(p)
    allowlist = policy_allowlist(p, policy_sha256)
    unrelated = deepcopy(allowlist["approvals"][0])
    unrelated.update(
        {
            "approval_id": "e00b-policy-review-20300101-01",
            "approved_at": "2030-01-01T00:00:00Z",
            "expires_at": "2030-01-01T00:10:00Z",
            "policy_id": "e00b-sandbox-g99",
            "policy_sha256": "a" * 64,
            "challenge_nonce": "b" * 64,
            "sandbox_generation_id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        }
    )
    allowlist["approvals"].append(unrelated)
    payloads = {
        gate.TRUSTED_POLICY_ALLOWLIST_PATH: gate._canonical_bytes(allowlist),
        **supporting_approval_payloads(p),
    }
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda path, _label: payloads[path.as_posix()],
    )

    result = gate._verify_policy_approval(p, policy_sha256)

    assert result["approval_id"] == "e00b-policy-review-20260718-01"


def test_final_supporting_root_recheck_hashes_all_four_fixed_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    supporting = supporting_approval_payloads(p)
    policy_payload = gate._canonical_bytes(
        policy_allowlist(p, gate._canonical_sha256(p))
    )
    payloads = {
        gate.TRUSTED_POLICY_ALLOWLIST_PATH: policy_payload,
        **supporting,
    }
    bindings = {
        "approval_id": "e00b-policy-review-20260718-01",
        "approved_at": "2026-07-18T01:50:00Z",
        "allowlist_sha256": __import__("hashlib").sha256(policy_payload).hexdigest(),
        "release_approval_allowlist_sha256": __import__("hashlib").sha256(
            supporting[gate.TRUSTED_RELEASE_ALLOWLIST_PATH]
        ).hexdigest(),
        "host_context_approval_sha256": __import__("hashlib").sha256(
            supporting[gate.TRUSTED_HOST_CONTEXT_PATH]
        ).hexdigest(),
        "recovery_approval_allowlist_sha256": __import__("hashlib").sha256(
            supporting[gate.TRUSTED_RECOVERY_ALLOWLIST_PATH]
        ).hexdigest(),
    }
    reads: list[str] = []

    def read(path: Path, _label: str) -> bytes:
        reads.append(path.as_posix())
        return payloads[path.as_posix()]

    monkeypatch.setattr(gate, "_read_bounded_regular_file", read)

    gate._verify_supporting_approval_roots(bindings)

    assert reads == [
        gate.TRUSTED_POLICY_ALLOWLIST_PATH,
        gate.TRUSTED_RELEASE_ALLOWLIST_PATH,
        gate.TRUSTED_HOST_CONTEXT_PATH,
        gate.TRUSTED_RECOVERY_ALLOWLIST_PATH,
    ]
    payloads[gate.TRUSTED_HOST_CONTEXT_PATH] += b"\n"
    with pytest.raises(
        gate.IsolationGateError, match="changed since policy approval"
    ):
        gate._verify_supporting_approval_roots(bindings)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_policy",
        "duplicate_approval",
        "future",
        "wrong_expiry",
        "supporting_drift",
    ],
)
def test_policy_approval_allowlist_rejects_ambiguous_or_invalid_rows(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = policy()
    policy_sha256 = gate._canonical_sha256(p)
    allowlist = policy_allowlist(p, policy_sha256)
    supporting = supporting_approval_payloads(p)
    if mutation == "duplicate_policy":
        duplicate = deepcopy(allowlist["approvals"][0])
        duplicate["approval_id"] = "e00b-policy-review-20260718-02"
        allowlist["approvals"].append(duplicate)
    elif mutation == "duplicate_approval":
        duplicate = deepcopy(allowlist["approvals"][0])
        duplicate["policy_id"] = "e00b-sandbox-g3"
        duplicate["policy_sha256"] = "0" * 64
        duplicate["challenge_nonce"] = "1" * 64
        allowlist["approvals"].append(duplicate)
    elif mutation == "future":
        allowlist["approvals"][0]["approved_at"] = "2026-07-18T01:56:00Z"
    elif mutation == "wrong_expiry":
        allowlist["approvals"][0]["expires_at"] = "2026-07-18T02:04:00Z"
    elif mutation == "supporting_drift":
        supporting[gate.TRUSTED_HOST_CONTEXT_PATH] += b"\n"
    payloads = {
        gate.TRUSTED_POLICY_ALLOWLIST_PATH: gate._canonical_bytes(allowlist),
        **supporting,
    }
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda path, _label: payloads[path.as_posix()],
    )

    with pytest.raises(gate.IsolationGateError):
        gate._verify_policy_approval(p, policy_sha256)


def test_initial_host_context_requires_a_fixed_external_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    context = approved_live_host_context()
    approval = host_context_approval(p, context)
    approval_payload = gate._canonical_bytes(approval)
    approval_sha256 = __import__("hashlib").sha256(approval_payload).hexdigest()
    reads: list[tuple[str, str]] = []

    def read(path: Path, label: str) -> bytes:
        reads.append((path.as_posix(), label))
        return approval_payload

    monkeypatch.setattr(gate, "_read_bounded_regular_file", read)
    captures = [deepcopy(context), deepcopy(context)]
    monkeypatch.setattr(gate, "_capture_live_host_context", lambda: captures.pop(0))

    assert (
        gate._verify_initial_root_context(
            p,
            expected_host_context_approval_sha256=approval_sha256,
        )
        == context
    )
    assert reads == [
        (gate.TRUSTED_HOST_CONTEXT_PATH, "trusted host context approval")
    ]


def test_host_context_approval_must_match_the_policy_approved_raw_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    context = approved_live_host_context()
    approval = host_context_approval(p, context)
    approval_payload = gate._canonical_bytes(approval)
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: approval_payload,
    )

    with pytest.raises(
        gate.IsolationGateError, match="changed since policy approval"
    ):
        gate._load_host_context_approval(
            p,
            expected_host_context_approval_sha256="0" * 64,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "policy_report",
        "policy_observation",
        "policy_machine",
        "future_approval",
        "namespace_drift",
    ],
)
def test_initial_host_context_rejects_self_selected_or_drifting_identity(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = policy()
    context = approved_live_host_context()
    approval = host_context_approval(p, context)
    observed_after = deepcopy(context)
    if mutation == "policy_report":
        p["e00a"]["report_sha256"] = "0" * 64
    elif mutation == "policy_observation":
        p["e00a"]["observation_sha256"] = "0" * 64
    elif mutation == "policy_machine":
        p["host"]["machine_id_sha256"] = "0" * 64
    elif mutation == "future_approval":
        approval["approved_at"] = "2026-07-18T02:01:00Z"
    elif mutation == "namespace_drift":
        observed_after["namespaces"]["net"]["inode"] += 1
    approval_payload = gate._canonical_bytes(approval)
    approval_sha256 = __import__("hashlib").sha256(approval_payload).hexdigest()
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: approval_payload,
    )
    captures = [deepcopy(context), observed_after]
    monkeypatch.setattr(gate, "_capture_live_host_context", lambda: captures.pop(0))

    with pytest.raises(gate.IsolationGateError):
        gate._verify_initial_root_context(
            p,
            expected_host_context_approval_sha256=approval_sha256,
        )


def test_e00a_host_fields_and_mount_namespace_bind_the_external_host_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    context = approved_live_host_context()
    approval = host_context_approval(p, context)
    approval_payload = gate._canonical_bytes(approval)
    approval_sha256 = __import__("hashlib").sha256(approval_payload).hexdigest()
    observation = {
        "host": {
            "hostname": context["hostname"],
            "machine_id_sha256": context["machine_id_sha256"],
            "boot_id_sha256": context["boot_id_sha256"],
        },
        "provenance": {
            "mount_namespace_identity_sha256": gate._canonical_sha256(
                context["namespaces"]["mnt"]
            )
        },
    }
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: approval_payload,
    )

    result = gate._verify_e00a_host_approval(
        p,
        observation,
        expected_host_context_approval_sha256=approval_sha256,
    )

    assert result["approval_id"] == approval["approval_id"]
    tampered = deepcopy(observation)
    tampered["host"]["boot_id_sha256"] = "0" * 64
    with pytest.raises(gate.IsolationGateError, match="host context"):
        gate._verify_e00a_host_approval(
            p,
            tampered,
            expected_host_context_approval_sha256=approval_sha256,
        )


def test_host_context_namespace_link_must_match_the_namespace_inode() -> None:
    context = approved_live_host_context()
    context["namespaces"]["net"]["inode"] += 1

    with pytest.raises(gate.IsolationGateError, match="inode"):
        gate._validate_host_context(context, "host context")


def release_inventory_fixture() -> tuple[
    dict[str, dict[str, object]], dict[str, dict[str, object]]
]:
    rows = {
        "bin/odoo-accounting-cli-v3": {
            "path": "bin/odoo-accounting-cli-v3",
            "sha256": "2" * 64,
            "size": 20,
        },
        "docs/readme.txt": {
            "path": "docs/readme.txt",
            "sha256": "5" * 64,
            "size": 50,
        },
    }
    directory = {
        "kind": "directory",
        "uid": 0,
        "gid": 0,
        "mode": 0o555,
        "device": 9,
    }
    inventory = {
        ".": deepcopy(directory),
        "bin": deepcopy(directory),
        "docs": deepcopy(directory),
        "bin/odoo-accounting-cli-v3": {
            "kind": "file",
            "uid": 0,
            "gid": 0,
            "mode": 0o555,
            "device": 9,
            "nlink": 1,
            "size": 20,
            "sha256": "2" * 64,
        },
        "docs/readme.txt": {
            "kind": "file",
            "uid": 0,
            "gid": 0,
            "mode": 0o444,
            "device": 9,
            "nlink": 1,
            "size": 50,
            "sha256": "5" * 64,
        },
        "RELEASE-MANIFEST.json": {
            "kind": "file",
            "uid": 0,
            "gid": 0,
            "mode": 0o444,
            "device": 9,
            "nlink": 1,
            "size": 500,
            "sha256": "6" * 64,
        },
    }
    return rows, inventory


def test_release_inventory_matches_manifest_and_installer_modes() -> None:
    rows, inventory = release_inventory_fixture()

    gate._validate_release_inventory(rows, inventory)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("extra", "manifest closure"),
        ("missing", "manifest closure"),
        ("directory_mode", "directory metadata"),
        ("file_mode", "file metadata"),
        ("owner", "file metadata"),
        ("hardlink", "file metadata"),
        ("device", "file metadata"),
        ("size", "file content"),
        ("digest", "file content"),
    ],
)
def test_release_inventory_rejects_each_drift(
    mutation: str, message: str
) -> None:
    rows, inventory = release_inventory_fixture()
    if mutation == "extra":
        inventory["extra.txt"] = deepcopy(inventory["docs/readme.txt"])
    elif mutation == "missing":
        del inventory["docs/readme.txt"]
    elif mutation == "directory_mode":
        inventory["docs"]["mode"] = 0o755
    elif mutation == "file_mode":
        inventory["docs/readme.txt"]["mode"] = 0o644
    elif mutation == "owner":
        inventory["docs/readme.txt"]["uid"] = 1000
    elif mutation == "hardlink":
        inventory["docs/readme.txt"]["nlink"] = 2
    elif mutation == "device":
        inventory["docs/readme.txt"]["device"] = 10
    elif mutation == "size":
        inventory["docs/readme.txt"]["size"] = 49
    elif mutation == "digest":
        inventory["docs/readme.txt"]["sha256"] = "0" * 64

    with pytest.raises(gate.IsolationGateError, match=message):
        gate._validate_release_inventory(rows, inventory)


def test_release_runtime_rechecks_manifest_and_dependency_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = policy()
    collector = b"collector"
    dev18 = b"dev18"
    namespace_probe = b"namespace-probe"
    digests = {
        "deployment/dev19/sandbox_isolation_gate.py": __import__("hashlib").sha256(
            collector
        ).hexdigest(),
        "deployment/dev18/sandbox_capacity_gate.py": __import__("hashlib").sha256(
            dev18
        ).hexdigest(),
        "deployment/dev19/sandbox_namespace_probe.py": __import__("hashlib").sha256(
            namespace_probe
        ).hexdigest(),
    }
    p["collector_sha256"] = digests[
        "deployment/dev19/sandbox_isolation_gate.py"
    ]
    p["dependencies"]["dev18_collector_sha256"] = digests[
        "deployment/dev18/sandbox_capacity_gate.py"
    ]
    p["dependencies"]["namespace_probe_sha256"] = digests[
        "deployment/dev19/sandbox_namespace_probe.py"
    ]
    files = [
        {"path": path, "sha256": digest, "size": len(payload)}
        for path, digest, payload in (
            (
                "deployment/dev19/sandbox_isolation_gate.py",
                digests["deployment/dev19/sandbox_isolation_gate.py"],
                collector,
            ),
            (
                "deployment/dev18/sandbox_capacity_gate.py",
                digests["deployment/dev18/sandbox_capacity_gate.py"],
                dev18,
            ),
            (
                "deployment/dev19/sandbox_namespace_probe.py",
                digests["deployment/dev19/sandbox_namespace_probe.py"],
                namespace_probe,
            ),
        )
    ]
    files.extend(installer_executable_rows())
    version = "0.1.0.dev19"
    commit = "d" * 40
    p["release"]["release_id"] = f"{version}-{commit[:12]}"
    p["release"]["release_root"] = (
        f"/opt/odoo-accounting-cli-v3/releases/{p['release']['release_id']}"
    )
    p["release"]["trusted_anchor_path"] = (
        "/opt/odoo-accounting-cli-v3/trusted-artifacts/"
        f"{p['release']['release_id']}.json"
    )
    unsigned = {
        "schema_version": 1,
        "version": version,
        "commit": commit,
        "files": files,
    }
    manifest = {**unsigned, "manifest_sha256": gate._canonical_sha256(unsigned)}
    p["release"]["manifest_sha256"] = manifest["manifest_sha256"]
    manifest_payload = gate._canonical_bytes(manifest)
    anchor = {
        "commit": commit,
        "manifest_sha256": manifest["manifest_sha256"],
        "package_sha256": p["release"]["package_sha256"],
        "release": p["release"]["release_id"],
    }
    anchor_payload = (
        json.dumps(anchor, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    p["release"]["trusted_anchor_sha256"] = __import__("hashlib").sha256(
        anchor_payload
    ).hexdigest()
    allowlist_payload = gate._canonical_bytes(release_allowlist(p, manifest))
    allowlist_sha256 = __import__("hashlib").sha256(allowlist_payload).hexdigest()
    host_approval_payload = gate._canonical_bytes(
        host_context_approval(p, approved_live_host_context())
    )
    host_approval_sha256 = __import__("hashlib").sha256(
        host_approval_payload
    ).hexdigest()
    payloads = {
        f"{p['release']['release_root']}/deployment/dev19/sandbox_isolation_gate.py": collector,
        f"{p['release']['release_root']}/deployment/dev18/sandbox_capacity_gate.py": dev18,
        f"{p['release']['release_root']}/deployment/dev19/sandbox_namespace_probe.py": namespace_probe,
        f"{p['release']['release_root']}/RELEASE-MANIFEST.json": manifest_payload,
        p["release"]["trusted_anchor_path"]: anchor_payload,
        gate.TRUSTED_RELEASE_ALLOWLIST_PATH: allowlist_payload,
    }
    monkeypatch.setattr(gate, "Path", gate.PurePosixPath)
    monkeypatch.setattr(
        gate,
        "sys",
        SimpleNamespace(
            platform="linux",
            flags=SimpleNamespace(
                isolated=1,
                dont_write_bytecode=1,
                no_site=1,
                safe_path=True,
                no_user_site=1,
                ignore_environment=1,
                optimize=0,
            ),
            dont_write_bytecode=True,
        ),
    )
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0, raising=False)
    verified_host_approvals: list[str] = []
    monkeypatch.setattr(
        gate,
        "_verify_initial_root_context",
        lambda _policy, *, expected_host_context_approval_sha256: (
            verified_host_approvals.append(expected_host_context_approval_sha256)
        ),
    )
    monkeypatch.setattr(
        gate,
        "_verify_direct_interpreter_invocation",
        lambda _collector, _cli_arguments: None,
    )
    monkeypatch.setattr(gate, "_verify_root_directory_chain", lambda *_args: None)
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda path, _label: payloads[str(path)],
    )
    verified_packages: list[object] = []
    monkeypatch.setattr(
        gate,
        "_verify_canonical_package",
        lambda value: verified_packages.append(value) or {},
    )
    monkeypatch.setattr(
        gate,
        "__file__",
        f"{p['release']['release_root']}/deployment/dev19/sandbox_isolation_gate.py",
    )
    verified_trees: list[tuple[object, object]] = []
    monkeypatch.setattr(
        gate,
        "_verify_release_tree",
        lambda root, rows: verified_trees.append((root, rows)) or {},
    )

    cli_arguments = [
        "--policy",
        "/root/policy.json",
        "--expected-policy-sha256",
        H,
    ]
    rows = gate._verify_release_runtime(
        p,
        cli_arguments,
        expected_release_approval_allowlist_sha256=allowlist_sha256,
        expected_host_context_approval_sha256=host_approval_sha256,
    )

    assert set(digests).issubset(rows)
    assert set(gate.EXECUTABLE_RELEASE_MEMBERS).issubset(rows)
    assert verified_packages == [p]
    assert verified_trees == [(gate.PurePosixPath(p["release"]["release_root"]), rows)]
    assert verified_host_approvals == [host_approval_sha256]
    payloads[
        f"{p['release']['release_root']}/deployment/dev19/sandbox_namespace_probe.py"
    ] += b"tampered"
    with pytest.raises(gate.IsolationGateError, match="dependency changed"):
        gate._verify_release_runtime(
            p,
            cli_arguments,
            expected_release_approval_allowlist_sha256=allowlist_sha256,
            expected_host_context_approval_sha256=host_approval_sha256,
        )


@pytest.mark.parametrize(
    ("location", "field", "value"),
    [
        ("flags", "isolated", 0),
        ("flags", "dont_write_bytecode", 0),
        ("module", "dont_write_bytecode", False),
        ("flags", "no_site", 0),
        ("flags", "safe_path", False),
        ("flags", "no_user_site", 0),
        ("flags", "ignore_environment", 0),
        ("flags", "optimize", 1),
    ],
)
def test_runtime_requires_hermetic_python_flags(
    location: str,
    field: str,
    value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = SimpleNamespace(
        flags=SimpleNamespace(
            isolated=1,
            dont_write_bytecode=1,
            no_site=1,
            safe_path=True,
            no_user_site=1,
            ignore_environment=1,
            optimize=0,
        ),
        dont_write_bytecode=True,
    )
    target = runtime.flags if location == "flags" else runtime
    setattr(target, field, value)
    monkeypatch.setattr(gate, "sys", runtime)

    with pytest.raises(gate.IsolationGateError, match="Python -I -B -S"):
        gate._verify_hermetic_python_flags()


def test_runtime_accepts_exact_hermetic_python_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = SimpleNamespace(
        flags=SimpleNamespace(
            isolated=1,
            dont_write_bytecode=1,
            no_site=1,
            safe_path=True,
            no_user_site=1,
            ignore_environment=1,
            optimize=0,
        ),
        dont_write_bytecode=True,
    )
    monkeypatch.setattr(gate, "sys", runtime)

    gate._verify_hermetic_python_flags()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("resuid", "real, effective, and saved root UID"),
        ("resgid", "real, effective, and saved root GID"),
        ("uid_map", "initial user namespace ID maps"),
        ("gid_map", "initial user namespace ID maps"),
        ("fsuid", "filesystem root IDs"),
        ("fsgid", "filesystem root IDs"),
        ("machine_id", "machine identity is invalid"),
        ("boot_id", "boot identity is invalid"),
    ],
)
def test_live_host_capture_rejects_root_and_host_identity_drift(
    mutation: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    machine_id = b"0123456789abcdef0123456789abcdef\n"
    boot_id = b"11111111-1111-4111-8111-111111111111\n"
    resuid = (0, 0, 0)
    resgid = (0, 0, 0)
    proc = {
        "/proc/self/uid_map": "         0          0 4294967295\n",
        "/proc/self/gid_map": "         0          0 4294967295\n",
        "/proc/self/status": "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
    }
    if mutation == "resuid":
        resuid = (0, 0, 1)
    elif mutation == "resgid":
        resgid = (0, 1, 0)
    elif mutation == "uid_map":
        proc["/proc/self/uid_map"] = "0 100000 65536\n"
    elif mutation == "gid_map":
        proc["/proc/self/gid_map"] = "0 100000 65536\n"
    elif mutation == "fsuid":
        proc["/proc/self/status"] = "Uid:\t0\t0\t0\t1\nGid:\t0\t0\t0\t0\n"
    elif mutation == "fsgid":
        proc["/proc/self/status"] = "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t1\n"
    elif mutation == "machine_id":
        machine_id = b"different-machine\n"
    elif mutation == "boot_id":
        boot_id = b"not-a-boot-id\n"
    monkeypatch.setattr(gate.os, "getresuid", lambda: resuid, raising=False)
    monkeypatch.setattr(gate.os, "getresgid", lambda: resgid, raising=False)
    monkeypatch.setattr(
        gate, "_read_runtime_proc_text", lambda path, _label: proc[str(path)]
    )
    monkeypatch.setattr(
        gate,
        "_read_namespace_identity_facts",
        lambda _path, namespace, _label: approved_live_host_context()["namespaces"][
            namespace
        ],
    )
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda path, _label: machine_id
        if path.as_posix() == "/etc/machine-id"
        else boot_id,
    )
    monkeypatch.setattr(gate.socket, "gethostname", lambda: "VM-0-6-ubuntu")

    with pytest.raises(gate.IsolationGateError, match=message):
        gate._capture_live_host_context()


@pytest.mark.parametrize("namespace", sorted(gate.HOST_NAMESPACE_NAMES))
def test_live_host_capture_rejects_every_noninitial_namespace(
    namespace: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = approved_live_host_context()
    facts: dict[str, dict[str, object]] = {}
    for name, identity in context["namespaces"].items():
        facts[f"/proc/self/ns/{name}"] = deepcopy(identity)
        facts[f"/proc/1/ns/{name}"] = deepcopy(identity)
    facts[f"/proc/self/ns/{namespace}"]["inode"] += 1
    monkeypatch.setattr(gate.os, "getresuid", lambda: (0, 0, 0), raising=False)
    monkeypatch.setattr(gate.os, "getresgid", lambda: (0, 0, 0), raising=False)
    monkeypatch.setattr(
        gate,
        "_read_runtime_proc_text",
        lambda path, _label: {
            "/proc/self/uid_map": "0 0 4294967295\n",
            "/proc/self/gid_map": "0 0 4294967295\n",
            "/proc/self/status": "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
        }[str(path)],
    )
    monkeypatch.setattr(
        gate,
        "_read_namespace_identity_facts",
        lambda path, _namespace, _label: facts[str(path)],
    )

    with pytest.raises(gate.IsolationGateError, match="initial host namespaces"):
        gate._capture_live_host_context()


def test_live_host_capture_accepts_full_initial_host_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    machine_id = b"0123456789abcdef0123456789abcdef\n"
    boot_id = b"11111111-1111-4111-8111-111111111111\n"
    namespaces = approved_live_host_context()["namespaces"]
    monkeypatch.setattr(gate.os, "getresuid", lambda: (0, 0, 0), raising=False)
    monkeypatch.setattr(gate.os, "getresgid", lambda: (0, 0, 0), raising=False)
    monkeypatch.setattr(
        gate,
        "_read_runtime_proc_text",
        lambda path, _label: {
            "/proc/self/uid_map": "0 0 4294967295\n",
            "/proc/self/gid_map": "0 0 4294967295\n",
            "/proc/self/status": "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
        }[str(path)],
    )
    monkeypatch.setattr(
        gate,
        "_read_namespace_identity_facts",
        lambda _path, namespace, _label: deepcopy(namespaces[namespace]),
    )
    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda path, _label: machine_id
        if path.as_posix() == "/etc/machine-id"
        else boot_id,
    )
    monkeypatch.setattr(gate.socket, "gethostname", lambda: "VM-0-6-ubuntu")

    result = gate._capture_live_host_context()

    assert result["hostname"] == "VM-0-6-ubuntu"
    assert result["machine_id_sha256"] == __import__("hashlib").sha256(
        machine_id
    ).hexdigest()
    assert result["boot_id_sha256"] == __import__("hashlib").sha256(
        boot_id
    ).hexdigest()
    assert result["namespaces"] == namespaces


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux procfs namespaces")
def test_real_linux_root_captures_the_full_initial_host_context() -> None:
    if os.environ.get("DEV19_ROOT_HOST_CONTEXT_INTEGRATION") != "1":
        pytest.skip("explicit root host-context integration was not requested")
    assert os.geteuid() == 0

    context = gate._capture_live_host_context()

    assert context["hostname"] == __import__("socket").gethostname()
    assert gate.HOST_NAMESPACE_NAMES == EXPECTED_HOST_NAMESPACE_NAMES
    assert set(context["namespaces"]) == set(EXPECTED_HOST_NAMESPACE_NAMES)
    for name, identity in context["namespaces"].items():
        assert identity["device"] > 0
        assert identity["inode"] > 0
        assert identity["link"] == (
            f"{gate.HOST_NAMESPACE_NAMES[name]}:[{identity['inode']}]"
        )


@pytest.mark.parametrize(
    "mutation",
    ["argv0", "relative_executable", "proc_executable", "relative_search_path"],
)
def test_runtime_requires_direct_trusted_interpreter_invocation(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = GATE_PATH.resolve()
    executable = Path(sys.executable).resolve()
    cli_arguments = [
        "--policy",
        "/root/policy.json",
        "--expected-policy-sha256",
        H,
    ]
    runtime = SimpleNamespace(
        argv=[str(collector), *cli_arguments],
        executable=str(executable),
        path=[str(executable.parent)],
    )
    proc_executable = str(executable)
    if mutation == "argv0":
        runtime.argv[0] = str(collector.parent / "wrapper.py")
    elif mutation == "relative_executable":
        runtime.executable = "python3"
    elif mutation == "proc_executable":
        proc_executable = str(executable.parent / "different-python")
    elif mutation == "relative_search_path":
        runtime.path = ["relative/site-packages"]
    monkeypatch.setattr(gate, "sys", runtime)
    monkeypatch.setattr(
        gate,
        "_read_process_executable",
        lambda: proc_executable,
    )
    monkeypatch.setattr(
        gate,
        "_read_process_cmdline",
        lambda: [
            str(executable),
            "-I",
            "-B",
            "-S",
            str(collector),
            *cli_arguments,
        ],
    )
    monkeypatch.setattr(gate, "_verify_trusted_runtime_path", lambda *_args: None)

    with pytest.raises(gate.IsolationGateError, match="direct trusted interpreter"):
        gate._verify_direct_interpreter_invocation(collector, cli_arguments)


def test_runtime_accepts_direct_trusted_interpreter_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = GATE_PATH.resolve()
    executable = Path(sys.executable).resolve()
    cli_arguments = [
        "--policy",
        "/root/policy.json",
        "--expected-policy-sha256",
        H,
    ]
    checked: list[tuple[Path, bool]] = []
    monkeypatch.setattr(
        gate,
        "sys",
        SimpleNamespace(
            argv=[str(collector), *cli_arguments],
            executable=str(executable),
            path=[str(executable.parent)],
        ),
    )
    monkeypatch.setattr(gate, "_read_process_executable", lambda: str(executable))
    monkeypatch.setattr(
        gate,
        "_read_process_cmdline",
        lambda: [
            str(executable),
            "-I",
            "-B",
            "-S",
            str(collector),
            *cli_arguments,
        ],
    )
    monkeypatch.setattr(
        gate,
        "_verify_trusted_runtime_path",
        lambda path, require_regular: checked.append((path, require_regular)),
    )

    gate._verify_direct_interpreter_invocation(collector, cli_arguments)

    assert checked == [(executable, True), (executable.parent, False)]


@pytest.mark.parametrize(
    "raw_arguments",
    [
        ["-I", "-B", "-S", "-c", "fake()"],
        ["-I", "-B", "-S", "-m", "fake.module"],
        ["-I", "-B", "-S", "-i"],
        ["-I", "-B", "-S", "/trusted/wrapper-using-runpy.py"],
        ["-E", "-I", "-B", "-S"],
        ["-I", "-S", "-B"],
        ["-IBS"],
    ],
)
def test_runtime_rejects_noncanonical_raw_process_invocation(
    raw_arguments: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    collector = GATE_PATH.resolve()
    executable = Path(sys.executable).resolve()
    cli_arguments = [
        "--policy",
        "/root/policy.json",
        "--expected-policy-sha256",
        H,
    ]
    monkeypatch.setattr(
        gate,
        "sys",
        SimpleNamespace(
            argv=[str(collector), *cli_arguments],
            executable=str(executable),
            path=[str(executable.parent)],
        ),
    )
    monkeypatch.setattr(
        gate,
        "_read_process_cmdline",
        lambda: [str(executable), *raw_arguments, str(collector), *cli_arguments],
    )
    monkeypatch.setattr(gate, "_read_process_executable", lambda: str(executable))
    monkeypatch.setattr(gate, "_verify_trusted_runtime_path", lambda *_args: None)

    with pytest.raises(gate.IsolationGateError, match="direct trusted interpreter"):
        gate._verify_direct_interpreter_invocation(collector, cli_arguments)


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux /proc cmdline")
def test_linux_proc_cmdline_defeats_forged_sys_argv_from_dash_c() -> None:
    attack = "\n".join(
        [
            "import importlib.util, pathlib, sys",
            "gate_path = pathlib.Path(sys.argv[1]).resolve()",
            "spec = importlib.util.spec_from_file_location('gate_attack_target', gate_path)",
            "gate = importlib.util.module_from_spec(spec)",
            "sys.modules[spec.name] = gate",
            "spec.loader.exec_module(gate)",
            f"cli = ['--policy', '/root/policy.json', '--expected-policy-sha256', '{H}']",
            "sys.argv = [str(gate_path), *cli]",
            "try:",
            "    gate._verify_direct_interpreter_invocation(gate_path, cli)",
            "except gate.IsolationGateError as exc:",
            "    print(str(exc))",
            "    raise SystemExit(23)",
            "raise SystemExit(0)",
        ]
    )

    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-S", "-c", attack, str(GATE_PATH)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 23, completed.stderr
    assert "direct trusted interpreter invocation" in completed.stdout


def test_dev18_verifier_is_executed_from_the_already_hashed_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = b"""
executed_as_main = __name__ == '__main__'
def _validate_policy(value):
    return value
def _validate_observation(value):
    return value
def evaluate(*args, **kwargs):
    return {'ok': True}
"""
    digest = __import__("hashlib").sha256(source).hexdigest()
    p = policy()
    p["dependencies"]["dev18_collector_sha256"] = digest
    rows = {
        "deployment/dev18/sandbox_capacity_gate.py": {
            "path": "deployment/dev18/sandbox_capacity_gate.py",
            "sha256": digest,
            "size": len(source),
        }
    }
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: source)

    verifier = gate._load_dev18_verifier(p, rows)

    assert verifier.executed_as_main is False
    assert verifier.evaluate() == {"ok": True}

    monkeypatch.setattr(
        gate,
        "_read_bounded_regular_file",
        lambda *_args: source + b"# changed\n",
    )
    with pytest.raises(gate.IsolationGateError, match="dependency changed"):
        gate._load_dev18_verifier(p, rows)


def test_dev18_verifier_loader_fails_closed_on_invalid_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = b"raise RuntimeError('boom')\n"
    digest = __import__("hashlib").sha256(source).hexdigest()
    p = policy()
    p["dependencies"]["dev18_collector_sha256"] = digest
    rows = {
        "deployment/dev18/sandbox_capacity_gate.py": {
            "path": "deployment/dev18/sandbox_capacity_gate.py",
            "sha256": digest,
            "size": len(source),
        }
    }
    monkeypatch.setattr(gate, "_read_bounded_regular_file", lambda *_args: source)

    with pytest.raises(gate.IsolationGateError, match="cannot be loaded safely"):
        gate._load_dev18_verifier(p, rows)


def test_e00a_prerequisite_wraps_foreign_dev18_validation_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenDev18:
        @staticmethod
        def _validate_policy(_value: object) -> object:
            raise ValueError("foreign verifier detail")

        _validate_observation = staticmethod(lambda value: value)
        evaluate = staticmethod(lambda *_args, **_kwargs: {})

    monkeypatch.setattr(
        gate,
        "_load_e00a_bundle",
        lambda _policy: {"policy": {}, "observation": {}, "report": {}},
    )
    p = policy()
    approval_payload = gate._canonical_bytes(
        host_context_approval(p, approved_live_host_context())
    )
    approval_sha256 = __import__("hashlib").sha256(approval_payload).hexdigest()

    with pytest.raises(
        gate.IsolationGateError,
        match="rejected by the pinned Dev18 verifier",
    ):
        gate._verify_e00a_prerequisite(
            p,
            BrokenDev18,
            expected_host_context_approval_sha256=approval_sha256,
        )

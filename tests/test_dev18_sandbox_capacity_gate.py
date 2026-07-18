from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = PROJECT_ROOT / "deployment" / "dev18" / "sandbox_capacity_gate.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("dev18_sandbox_capacity_gate", GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


GIB = 1024**3
NOW = datetime(2026, 7, 17, 12, 5, tzinfo=timezone.utc)
HOST_ID = "a" * 64
BOOT_ID = "b" * 64
MOUNTINFO_PAYLOAD = b"fixture-mountinfo\n"
MOUNTINFO_SHA256 = hashlib.sha256(MOUNTINFO_PAYLOAD).hexdigest()


def mock_uuid_probe_authority(monkeypatch) -> None:
    def build(postgresql, expected):
        probe = deepcopy(postgresql)
        probe.update(
            {
                "run_as_user": expected["uuid_probe_os_user"],
                "run_as_group": expected["uuid_probe_os_group"],
                "run_as_uid": expected["uuid_probe_os_uid"],
                "run_as_gid": expected["uuid_probe_os_gid"],
                "database_user": expected["uuid_probe_database_user"],
                "database_user_is_superuser": False,
                "database_user_bypass_rls": False,
            }
        )
        identity = (
            expected["uuid_probe_os_user"],
            expected["uuid_probe_os_uid"],
            expected["uuid_probe_os_gid"],
            expected["uuid_probe_os_group"],
            expected["uuid_probe_os_gid"],
            tuple(expected["uuid_probe_os_supplementary_gids"]),
            expected["uuid_probe_database_user"],
        )
        return probe, identity

    monkeypatch.setattr(gate, "_uuid_probe_postgresql", build)


def catalog() -> list[dict[str, object]]:
    return [
        {
            "oid": "10001",
            "name": "odoo_prod",
            "allow_connections": True,
            "is_template": False,
            "owner": "odoo",
            "tablespace_oid": "1663",
            "size_bytes": 6 * GIB,
        },
        {
            "oid": "10002",
            "name": "odoo_test",
            "allow_connections": True,
            "is_template": False,
            "owner": "odoo",
            "tablespace_oid": "1663",
            "size_bytes": 2 * GIB,
        },
        {
            "oid": "5",
            "name": "postgres",
            "allow_connections": True,
            "is_template": False,
            "owner": "postgres",
            "tablespace_oid": "1663",
            "size_bytes": GIB,
        },
    ]


def catalog_identity(entries: list[dict[str, object]]) -> str:
    stable = [
        {
            key: item[key]
            for key in (
                "oid",
                "name",
                "allow_connections",
                "is_template",
                "owner",
                "tablespace_oid",
            )
        }
        for item in entries
    ]
    return gate._canonical_sha256(stable)


def connectable_names_identity(entries: list[dict[str, object]]) -> str:
    return gate._canonical_sha256(
        sorted(item["name"] for item in entries if item["allow_connections"])
    )


def uuid_relation_identity(
    *, database_name: str, database_oid: str, owner: str, relation_oid: str
) -> dict[str, object]:
    return {
        "database_name": database_name,
        "database_oid": database_oid,
        "database_owner": owner,
        "schema_name": "public",
        "schema_oid": "2200",
        "schema_owner": "pg_database_owner",
        "relation_name": "ir_config_parameter",
        "relation_oid": relation_oid,
        "relation_filenode": relation_oid,
        "tablespace_oid": "0",
        "access_method": "heap",
        "relation_kind": "r",
        "persistence": "p",
        "row_security": False,
        "force_row_security": False,
        "has_rules": False,
        "is_partition": False,
        "relation_owner": owner,
        "relation_owner_is_superuser": False,
        "relation_owner_bypass_rls": False,
        "relation_owner_can_login": True,
        "relation_owner_create_role": False,
        "relation_owner_createdb": True,
        "relation_owner_replication": False,
        "relation_owner_membership_count": 0,
        "parent_count": 0,
        "child_count": 0,
        "check_constraint_count": 0,
        "indexes": [],
        "statistics": [],
        "columns": [
            {
                "attnum": 1,
                "name": "id",
                "type_oid": "23",
                "type_modifier": -1,
                "not_null": True,
                "generated": "",
                "identity": "",
                "collation_oid": "0",
            },
            {
                "attnum": 2,
                "name": "key",
                "type_oid": "1043",
                "type_modifier": -1,
                "not_null": True,
                "generated": "",
                "identity": "",
                "collation_oid": "100",
            },
            {
                "attnum": 3,
                "name": "value",
                "type_oid": "25",
                "type_modifier": -1,
                "not_null": False,
                "generated": "",
                "identity": "",
                "collation_oid": "100",
            },
        ],
    }


def uuid_relation_identity_sha256(value: dict[str, object]) -> str:
    return gate._canonical_sha256(value)


def protected_relation_identities() -> dict[str, dict[str, object]]:
    return {
        "odoo_prod": uuid_relation_identity(
            database_name="odoo_prod",
            database_oid="10001",
            owner="odoo",
            relation_oid="25001",
        ),
        "odoo_test": uuid_relation_identity(
            database_name="odoo_test",
            database_oid="10002",
            owner="odoo",
            relation_oid="25002",
        ),
    }


def mount_identity() -> dict[str, object]:
    return {
        "kernel_mount_id": "29",
        "parent_mount_id": "1",
        "major_minor": "252:2",
        "mount_root": "/",
        "mount_point": "/",
        "mount_options": "rw,relatime",
        "optional_fields": ["shared:1"],
        "filesystem_type": "ext4",
        "mount_source": "/dev/vda2",
        "super_options": "rw,errors=remount-ro",
    }


def policy() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "odoo-accounting-cli-v3.sandbox-capacity-policy.v1",
        "policy_id": "tokyo2-sandbox-capacity-20260717",
        "environment": "sandbox",
        "host": {
            "hostname": "VM-0-6-ubuntu",
            "machine_id_sha256": HOST_ID,
            "require_initial_mount_namespace": True,
        },
        "target": {
            "odoo_instance_id": "odoo19@tokyo2-sandbox",
            "database_name": "odoo_v3_accounting_sandbox",
        },
        "collector_sha256": "f" * 64,
        "postgresql": {
            "psql_path": "/usr/lib/postgresql/16/bin/psql",
            "psql_sha256": "9" * 64,
            "runuser_path": "/usr/sbin/runuser",
            "runuser_sha256": "8" * 64,
            "systemctl_path": "/usr/bin/systemctl",
            "systemctl_sha256": "7" * 64,
            "pg_controldata_path": "/usr/lib/postgresql/16/bin/pg_controldata",
            "pg_controldata_sha256": "6" * 64,
            "postgres_path": "/usr/lib/postgresql/16/bin/postgres",
            "postgres_sha256": "5" * 64,
            "run_as_user": "postgres",
            "run_as_group": "postgres",
            "run_as_uid": 113,
            "run_as_gid": 118,
            "database_user": "postgres",
            "database_user_is_superuser": True,
            "database_user_bypass_rls": True,
            "service_unit": "postgresql@16-main.service",
            "service_user": "postgres",
            "service_group": "postgres",
            "service_configuration_sha256": "4" * 64,
            "expected_control_group": "/system.slice/postgresql@16-main.service",
            "socket_directory": "/run/postgresql",
            "unix_socket_directories": "/run/postgresql",
            "port": 5432,
            "maintenance_database": "postgres",
            "system_identifier": "7616327373742442245",
            "data_directory": "/var/lib/postgresql/16/main",
            "config_file": "/etc/postgresql/16/main/postgresql.conf",
            "config_file_identity_sha256": "1" * 64,
            "hba_file": "/etc/postgresql/16/main/pg_hba.conf",
            "hba_file_identity_sha256": "2" * 64,
            "server_version_num": 160014,
            "expected_in_recovery": False,
            "catalog_identity_sha256": catalog_identity(catalog()),
            "catalog_total_count": len(catalog()),
            "connectable_database_names_sha256": connectable_names_identity(catalog()),
            "connectable_database_count": 3,
            "configuration_identity_sha256": "d" * 64,
            "socket_group_membership_identity_sha256": "e" * 64,
            "socket_group_members": [
                {
                    "name": "postgres",
                    "uid": 113,
                    "primary_gid": 118,
                    "supplementary_gids": [118],
                }
            ],
        },
        "max_observation_age_seconds": 900,
        "max_capture_duration_seconds": 120,
        "allocations": [
            {
                "purpose": "postgresql",
                "allocation_id": "postgresql-data",
                "expected_path": "/var/lib/postgresql/16/main",
                "expected_mount_point": "/",
                "expected_mount_source": "/dev/vda2",
                "expected_filesystem_type": "ext4",
                "expected_mount_root": "/",
                "expected_mount_identity_sha256": gate._canonical_sha256(mount_identity()),
                "additional_bytes": 10 * GIB,
                "reserve_bytes": 8 * GIB,
                "additional_inodes": 100_000,
                "reserve_inodes": 100_000,
            },
            {
                "purpose": "odoo-filestore",
                "allocation_id": "odoo-filestore",
                "expected_path": "/mnt/odoo/odoo19/data/db_filestore",
                "expected_mount_point": "/",
                "expected_mount_source": "/dev/vda2",
                "expected_filesystem_type": "ext4",
                "expected_mount_root": "/",
                "expected_mount_identity_sha256": gate._canonical_sha256(mount_identity()),
                "additional_bytes": 3 * GIB,
                "reserve_bytes": 8 * GIB,
                "additional_inodes": 200_000,
                "reserve_inodes": 100_000,
            },
            {
                "purpose": "runtime-and-evidence",
                "allocation_id": "root-runtime",
                "expected_path": "/var/lib/odoo-accounting-cli-v3",
                "expected_mount_point": "/",
                "expected_mount_source": "/dev/vda2",
                "expected_filesystem_type": "ext4",
                "expected_mount_root": "/",
                "expected_mount_identity_sha256": gate._canonical_sha256(mount_identity()),
                "additional_bytes": 1 * GIB,
                "reserve_bytes": 8 * GIB,
                "additional_inodes": 50_000,
                "reserve_inodes": 100_000,
            },
        ],
        "protected_databases": [
            {
                "name": "odoo_prod",
                "uuid": "11111111-1111-4111-8111-111111111111",
                "uuid_relation_identity_sha256": uuid_relation_identity_sha256(
                    protected_relation_identities()["odoo_prod"]
                ),
                "uuid_probe_os_user": "odoo",
                "uuid_probe_os_group": "odoo",
                "uuid_probe_os_uid": 999,
                "uuid_probe_os_gid": 1003,
                "uuid_probe_os_supplementary_gids": [1003],
                "uuid_probe_database_user": "odoo",
            },
            {
                "name": "odoo_test",
                "uuid": "22222222-2222-4222-8222-222222222222",
                "uuid_relation_identity_sha256": uuid_relation_identity_sha256(
                    protected_relation_identities()["odoo_test"]
                ),
                "uuid_probe_os_user": "odoo",
                "uuid_probe_os_group": "odoo",
                "uuid_probe_os_uid": 999,
                "uuid_probe_os_gid": 1003,
                "uuid_probe_os_supplementary_gids": [1003],
                "uuid_probe_database_user": "odoo",
            },
        ],
        "protected_resources": [
            {
                "resource_id": "v2-source",
                "path": "/srv/odoo-v2/backend.py",
                "kind": "regular_file",
                "expected_state": "present",
                "expected_identity_sha256": "c" * 64,
                "expected_entry_count": 1,
                "expected_total_regular_file_bytes": 10,
            },
            {
                "resource_id": "pi-bridge-v2",
                "path": "/srv/pi-bridge/server.mjs",
                "kind": "regular_file",
                "expected_state": "present",
                "expected_identity_sha256": "d" * 64,
                "expected_entry_count": 1,
                "expected_total_regular_file_bytes": 20,
            },
            {
                "resource_id": "v3-current-route",
                "path": "/opt/odoo-accounting-cli-v3/current",
                "kind": "absent",
                "expected_state": "absent",
                "expected_identity_sha256": "e" * 64,
                "expected_entry_count": 0,
                "expected_total_regular_file_bytes": 0,
            },
        ],
    }


def observation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": "odoo-accounting-cli-v3.sandbox-capacity-observation.v1",
        "capture_started_at": "2026-07-17T11:59:55Z",
        "capture_finished_at": "2026-07-17T12:00:00Z",
        "capture_duration_ns": 5_000_000_000,
        "capture_mode": "read_only",
        "host": {
            "hostname": "VM-0-6-ubuntu",
            "machine_id_sha256": HOST_ID,
            "boot_id_sha256": BOOT_ID,
        },
        "environment": "sandbox",
        "provenance": {
            "collector": "live_linux_v1",
            "collector_sha256": "f" * 64,
            "mount_namespace_scope": "host_pid1",
            "mount_namespace_identity_sha256": "3" * 64,
            "mountinfo_sha256_before": MOUNTINFO_SHA256,
            "mountinfo_sha256_after": MOUNTINFO_SHA256,
        },
        "postgresql": {
            "psql_sha256": "9" * 64,
            "psql_identity_sha256": "7" * 64,
            "runuser_sha256": "8" * 64,
            "runuser_identity_sha256": "6" * 64,
            "systemctl_sha256": "7" * 64,
            "systemctl_identity_sha256": "5" * 64,
            "pg_controldata_sha256": "6" * 64,
            "pg_controldata_identity_sha256": "4" * 64,
            "postgres_sha256": "5" * 64,
            "postgres_identity_sha256": "3" * 64,
            "service_unit": "postgresql@16-main.service",
            "service_configuration_sha256": "4" * 64,
            "service_runtime_identity_sha256": "2" * 64,
            "main_pid": 4321,
            "control_group": "/system.slice/postgresql@16-main.service",
            "database_user": "postgres",
            "database_current_user": "postgres",
            "database_user_is_superuser": True,
            "database_user_bypass_rls": True,
            "socket_directory": "/run/postgresql",
            "socket_filesystem_identity_sha256": "1" * 64,
            "socket_listener_identity_sha256": "0" * 64,
            "unix_socket_directories": "/run/postgresql",
            "port": 5432,
            "system_identifier": "7616327373742442245",
            "control_data_system_identifier": "7616327373742442245",
            "data_directory": "/var/lib/postgresql/16/main",
            "data_directory_identity_sha256": "a" * 64,
            "postmaster_pid_identity_sha256": "b" * 64,
            "process_identity_sha256": "c" * 64,
            "config_file": "/etc/postgresql/16/main/postgresql.conf",
            "config_file_identity_sha256": "1" * 64,
            "hba_file": "/etc/postgresql/16/main/pg_hba.conf",
            "hba_file_identity_sha256": "2" * 64,
            "server_version_num": 160014,
            "in_recovery": False,
            "postmaster_started_at": "2026-07-17T01:00:00Z",
            "catalog_identity_sha256_before": catalog_identity(catalog()),
            "catalog_identity_sha256_after": catalog_identity(catalog()),
            "catalog_total_count": len(catalog()),
            "connectable_database_names_sha256": connectable_names_identity(catalog()),
            "connectable_database_count": 3,
            "configuration_identity_sha256_before": "d" * 64,
            "configuration_identity_sha256_after": "d" * 64,
            "socket_group_membership_identity_sha256_before": "e" * 64,
            "socket_group_membership_identity_sha256_after": "e" * 64,
            "socket_group_members_before": [
                {
                    "name": "postgres",
                    "uid": 113,
                    "primary_gid": 118,
                    "supplementary_gids": [118],
                }
            ],
            "socket_group_members_after": [
                {
                    "name": "postgres",
                    "uid": 113,
                    "primary_gid": 118,
                    "supplementary_gids": [118],
                }
            ],
            "postmaster_namespace_identity_sha256": "f" * 64,
        },
        "target": {
            "odoo_instance_id": "odoo19@tokyo2-sandbox",
            "database_name": "odoo_v3_accounting_sandbox",
            "database_exists": False,
        },
        "mounts": [
            {
                "allocation_id": "postgresql-data",
                "path": "/var/lib/postgresql/16/main",
                "device_id": "64770",
                **mount_identity(),
                "mount_identity_sha256": gate._canonical_sha256(mount_identity()),
                "total_bytes": 80 * GIB,
                "free_bytes": 30 * GIB,
                "total_inodes": 5_000_000,
                "free_inodes": 3_000_000,
            },
            {
                "allocation_id": "odoo-filestore",
                "path": "/mnt/odoo/odoo19/data/db_filestore",
                "device_id": "64770",
                **mount_identity(),
                "mount_identity_sha256": gate._canonical_sha256(mount_identity()),
                "total_bytes": 80 * GIB,
                "free_bytes": 30 * GIB,
                "total_inodes": 5_000_000,
                "free_inodes": 3_000_000,
            },
            {
                "allocation_id": "root-runtime",
                "path": "/var/lib/odoo-accounting-cli-v3",
                "device_id": "64770",
                **mount_identity(),
                "mount_identity_sha256": gate._canonical_sha256(mount_identity()),
                "total_bytes": 80 * GIB,
                "free_bytes": 30 * GIB,
                "total_inodes": 5_000_000,
                "free_inodes": 3_000_000,
            },
        ],
        "catalog": catalog(),
        "databases": [
            {
                "name": "odoo_prod",
                "uuid": "11111111-1111-4111-8111-111111111111",
                "uuid_relation_identity_sha256": uuid_relation_identity_sha256(
                    protected_relation_identities()["odoo_prod"]
                ),
                "uuid_probe_os_user": "odoo",
                "uuid_probe_os_group": "odoo",
                "uuid_probe_os_uid": 999,
                "uuid_probe_os_gid": 1003,
                "uuid_probe_os_supplementary_gids": [1003],
                "uuid_probe_database_user": "odoo",
                "uuid_probe_database_user_is_superuser": False,
                "uuid_probe_database_user_bypass_rls": False,
                "size_bytes": 6 * GIB,
            },
            {
                "name": "odoo_test",
                "uuid": "22222222-2222-4222-8222-222222222222",
                "uuid_relation_identity_sha256": uuid_relation_identity_sha256(
                    protected_relation_identities()["odoo_test"]
                ),
                "uuid_probe_os_user": "odoo",
                "uuid_probe_os_group": "odoo",
                "uuid_probe_os_uid": 999,
                "uuid_probe_os_gid": 1003,
                "uuid_probe_os_supplementary_gids": [1003],
                "uuid_probe_database_user": "odoo",
                "uuid_probe_database_user_is_superuser": False,
                "uuid_probe_database_user_bypass_rls": False,
                "size_bytes": 2 * GIB,
            },
        ],
        "protected_resources": [
            {
                "resource_id": "v2-source",
                "actual_kind_before": "regular_file",
                "actual_kind_after": "regular_file",
                "state_before": "present",
                "state_after": "present",
                "identity_sha256_before": "c" * 64,
                "identity_sha256_after": "c" * 64,
                "entry_count_before": 1,
                "entry_count_after": 1,
                "total_regular_file_bytes_before": 10,
                "total_regular_file_bytes_after": 10,
            },
            {
                "resource_id": "pi-bridge-v2",
                "actual_kind_before": "regular_file",
                "actual_kind_after": "regular_file",
                "state_before": "present",
                "state_after": "present",
                "identity_sha256_before": "d" * 64,
                "identity_sha256_after": "d" * 64,
                "entry_count_before": 1,
                "entry_count_after": 1,
                "total_regular_file_bytes_before": 20,
                "total_regular_file_bytes_after": 20,
            },
            {
                "resource_id": "v3-current-route",
                "actual_kind_before": "absent",
                "actual_kind_after": "absent",
                "state_before": "absent",
                "state_after": "absent",
                "identity_sha256_before": "e" * 64,
                "identity_sha256_after": "e" * 64,
                "entry_count_before": 0,
                "entry_count_after": 0,
                "total_regular_file_bytes_before": 0,
                "total_regular_file_bytes_after": 0,
            },
        ],
        "side_effect_attestation": {
            "filesystem_object_mutation_performed_by_collector": False,
            "database_transaction_write_performed": False,
            "service_control_performed": False,
            "accounting_write_performed": False,
        },
    }


def test_shared_device_capacity_is_aggregated_once_with_one_reserve() -> None:
    report = gate.evaluate(policy(), observation(), now=NOW)

    assert report["capacity_gate_passed"] is True
    assert report["eligible_for_sandbox_provisioning_review"] is True
    assert report["sandbox_provisioning_authorized"] is False
    assert report["sandbox_accounting_write_authorized"] is False
    assert report["production_accounting_write_authorized"] is False
    assert report["blockers"] == []
    assert report["devices"] == [
        {
            "device_id": "64770",
                "allocation_ids": ["odoo-filestore", "postgresql-data", "root-runtime"],
            "free_bytes": 30 * GIB,
            "required_bytes": 22 * GIB,
            "shortfall_bytes": 0,
            "free_inodes": 3_000_000,
            "required_inodes": 450_000,
            "shortfall_inodes": 0,
            "passed": True,
        }
    ]


def test_current_like_low_disk_blocks_and_reports_exact_shortfall() -> None:
    value = observation()
    for mount in value["mounts"]:
        mount["free_bytes"] = 1_500_000_000

    report = gate.evaluate(policy(), value, now=NOW)

    assert report["capacity_gate_passed"] is False
    assert report["eligible_for_sandbox_provisioning_review"] is False
    assert report["devices"][0]["shortfall_bytes"] == 22 * GIB - 1_500_000_000
    assert "storage_bytes:64770" in report["blockers"]
    assert report["sandbox_provisioning_authorized"] is False
    assert report["sandbox_accounting_write_authorized"] is False


def test_inode_shortfall_blocks_independently_of_bytes() -> None:
    value = observation()
    for mount in value["mounts"]:
        mount["free_inodes"] = 449_999

    report = gate.evaluate(policy(), value, now=NOW)
    assert report["capacity_gate_passed"] is False
    assert report["devices"][0]["shortfall_inodes"] == 1
    assert "storage_inodes:64770" in report["blockers"]


@pytest.mark.parametrize(
    ("mutate", "blocker"),
    [
        (
            lambda value: value["target"].__setitem__("database_exists", True),
            "target_database_already_exists",
        ),
        (
            lambda value: value["target"].__setitem__("database_name", "odoo_prod"),
            "target_binding_mismatch",
        ),
        (
            lambda value: value["host"].__setitem__("machine_id_sha256", "e" * 64),
            "host_binding_mismatch",
        ),
        (
            lambda value: value.__setitem__("environment", "production"),
            "environment_mismatch",
        ),
        (
            lambda value: value["mounts"][0].__setitem__(
                "path", "/var/lib/postgresql/other"
            ),
            "mount_binding:postgresql-data",
        ),
        (
            lambda value: value["databases"][0].__setitem__(
                "uuid", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
            ),
            "protected_database:odoo_prod",
        ),
        (
            lambda value: value["databases"][0].__setitem__(
                "uuid_relation_identity_sha256", "e" * 64
            ),
            "protected_database:odoo_prod",
        ),
        (
            lambda value: value["protected_resources"][0].__setitem__(
                "identity_sha256_after", "e" * 64
            ),
            "protected_resource:v2-source",
        ),
        (
            lambda value: value["side_effect_attestation"].__setitem__(
                "filesystem_object_mutation_performed_by_collector", True
            ),
            "observation_not_read_only",
        ),
    ],
)
def test_identity_drift_or_non_read_only_capture_blocks(mutate, blocker: str) -> None:
    value = observation()
    mutate(value)
    report = gate.evaluate(policy(), value, now=NOW)
    assert report["capacity_gate_passed"] is False
    assert blocker in report["blockers"]


def test_stale_and_future_observations_fail_closed() -> None:
    stale = observation()
    stale["capture_started_at"] = "2026-07-17T11:49:54Z"
    stale["capture_finished_at"] = "2026-07-17T11:49:59Z"
    assert "observation_stale" in gate.evaluate(policy(), stale, now=NOW)["blockers"]

    future = observation()
    future["capture_started_at"] = "2026-07-17T12:05:01Z"
    future["capture_finished_at"] = "2026-07-17T12:05:06Z"
    assert "observation_from_future" in gate.evaluate(policy(), future, now=NOW)["blockers"]


def test_capture_window_is_bound_to_wall_monotonic_and_total_deadline() -> None:
    too_slow = observation()
    too_slow["capture_finished_at"] = "2026-07-17T12:01:56Z"
    too_slow["capture_duration_ns"] = 121_000_000_000
    report = gate.evaluate(policy(), too_slow, now=NOW)
    assert "capture_duration_exceeded" in report["blockers"]

    discontinuity = observation()
    discontinuity["capture_duration_ns"] = 1_000_000_000
    report = gate.evaluate(policy(), discontinuity, now=NOW)
    assert "capture_clock_discontinuity" in report["blockers"]

    reversed_clock = observation()
    reversed_clock["capture_finished_at"] = "2026-07-17T11:59:54Z"
    reversed_clock["capture_duration_ns"] = 0
    report = gate.evaluate(policy(), reversed_clock, now=NOW)
    assert "capture_clock_discontinuity" in report["blockers"]


def test_mount_topology_and_reviewed_identity_drift_fail_closed() -> None:
    topology = observation()
    topology["provenance"]["mountinfo_sha256_after"] = "e" * 64
    assert "mount_topology_changed" in gate.evaluate(
        policy(), topology, now=NOW
    )["blockers"]

    rebound = observation()
    rebound["mounts"][0]["mount_source"] = "/dev/loop9"
    rebound["mounts"][0]["mount_identity_sha256"] = gate._canonical_sha256(
        gate._mount_identity(rebound["mounts"][0])
    )
    assert "mount_binding:postgresql-data" in gate.evaluate(
        policy(), rebound, now=NOW
    )["blockers"]


def test_full_postgresql_catalog_is_closed_against_drift_and_policy_omission() -> None:
    drift = observation()
    drift["postgresql"]["catalog_identity_sha256_before"] = "e" * 64
    assert "postgresql_catalog_drift" in gate.evaluate(
        policy(), drift, now=NOW
    )["blockers"]

    omitted_from_policy = observation()
    omitted_from_policy["catalog"].append(
        {
            "oid": "10003",
            "name": "unexpected_business_db",
            "allow_connections": True,
            "is_template": False,
            "owner": "odoo",
            "tablespace_oid": "1663",
            "size_bytes": GIB,
        }
    )
    new_catalog_sha = catalog_identity(omitted_from_policy["catalog"])
    new_connectable_sha = connectable_names_identity(omitted_from_policy["catalog"])
    omitted_from_policy["postgresql"].update(
        {
            "catalog_identity_sha256_before": new_catalog_sha,
            "catalog_identity_sha256_after": new_catalog_sha,
            "catalog_total_count": 4,
            "connectable_database_names_sha256": new_connectable_sha,
            "connectable_database_count": 4,
        }
    )
    report = gate.evaluate(policy(), omitted_from_policy, now=NOW)
    assert "postgresql_catalog_binding_mismatch" in report["blockers"]
    assert "postgresql_binding_mismatch" in report["blockers"]


def test_mountinfo_parser_rejects_truncation_duplicates_and_bad_escapes() -> None:
    valid = (
        b"29 1 252:2 / / rw,relatime shared:1 - ext4 /dev/vda2 rw,errors=remount-ro\n"
    )
    row = gate._parse_mountinfo(valid)[0]
    assert row["mount_point"] == "/"
    assert row["mount_source"] == "/dev/vda2"

    with pytest.raises(gate.CapacityGateError, match="truncated"):
        gate._parse_mountinfo(valid.rstrip(b"\n"))
    with pytest.raises(gate.CapacityGateError, match="unique"):
        gate._parse_mountinfo(valid + valid)
    with pytest.raises(gate.CapacityGateError, match="escape"):
        gate._parse_mountinfo(valid.replace(b"/dev/vda2", b"/dev/bad\\777"))


def test_mount_namespace_must_equal_host_pid1(monkeypatch) -> None:
    monkeypatch.setattr(
        gate.Path,
        "stat",
        lambda path: SimpleNamespace(
            st_dev=1,
            st_ino=1 if "self" in path.parts else 2,
        ),
    )
    monkeypatch.setattr(
        gate.os,
        "readlink",
        lambda path: "mnt:[1]" if "self" in path.parts else "mnt:[2]",
    )
    with pytest.raises(gate.CapacityGateError, match="outside the host"):
        gate._mount_namespace_identity()


def test_duplicate_or_unknown_json_members_are_rejected() -> None:
    with pytest.raises(gate.CapacityGateError, match="duplicate JSON field"):
        gate.load_strict_json(b'{"schema_version":1,"schema_version":1}')

    value = policy()
    value["unexpected"] = True
    with pytest.raises(gate.CapacityGateError, match="policy fields"):
        gate.evaluate(value, observation(), now=NOW)

    boolean_schema = policy()
    boolean_schema["schema_version"] = True
    with pytest.raises(gate.CapacityGateError, match="schema version"):
        gate.evaluate(boolean_schema, observation(), now=NOW)


@pytest.mark.parametrize("document", ["policy", "observation"])
def test_protected_database_relation_identity_is_required_and_strict(
    document: str,
) -> None:
    policy_value = policy()
    observation_value = observation()
    target = (
        policy_value["protected_databases"][0]
        if document == "policy"
        else observation_value["databases"][0]
    )
    del target["uuid_relation_identity_sha256"]

    with pytest.raises(gate.CapacityGateError, match="fields"):
        gate.evaluate(policy_value, observation_value, now=NOW)

    policy_value = policy()
    observation_value = observation()
    target = (
        policy_value["protected_databases"][0]
        if document == "policy"
        else observation_value["databases"][0]
    )
    target["uuid_relation_identity_sha256"] = "not-a-sha256"
    with pytest.raises(gate.CapacityGateError, match="identity"):
        gate.evaluate(policy_value, observation_value, now=NOW)


@pytest.mark.parametrize("path", ["//var/lib/odoo", "/var/lib/\x00odoo", "/var/lib\nodoo"])
def test_noncanonical_or_control_character_paths_are_rejected(path: str) -> None:
    value = policy()
    value["allocations"][0]["expected_path"] = path
    with pytest.raises(gate.CapacityGateError, match="path"):
        gate.evaluate(value, observation(), now=NOW)


def test_duplicate_policy_or_observation_paths_are_rejected() -> None:
    policy_value = policy()
    policy_value["allocations"][1]["expected_path"] = policy_value["allocations"][0][
        "expected_path"
    ]
    with pytest.raises(gate.CapacityGateError, match="paths must be unique"):
        gate.evaluate(policy_value, observation(), now=NOW)

    observation_value = observation()
    observation_value["mounts"][1]["path"] = observation_value["mounts"][0]["path"]
    with pytest.raises(gate.CapacityGateError, match="paths must be unique"):
        gate.evaluate(policy(), observation_value, now=NOW)


def test_existing_protected_uuid_collisions_can_be_recorded_exactly() -> None:
    policy_value = policy()
    observation_value = observation()
    duplicated_uuid = policy_value["protected_databases"][0]["uuid"]
    policy_value["protected_databases"][1]["uuid"] = duplicated_uuid
    observation_value["databases"][1]["uuid"] = duplicated_uuid
    assert gate.evaluate(policy_value, observation_value, now=NOW)[
        "capacity_gate_passed"
    ] is True


@pytest.mark.parametrize(
    ("document", "mutation"),
    [
        (
            "policy",
            lambda value: value.__setitem__("max_observation_age_seconds", True),
        ),
        (
            "policy",
            lambda value: value["allocations"][0].__setitem__(
                "additional_bytes", -1
            ),
        ),
        (
            "observation",
            lambda value: value["mounts"][0].__setitem__("free_bytes", True),
        ),
        (
            "observation",
            lambda value: value["mounts"][0].__setitem__("device_id", ""),
        ),
        (
            "observation",
            lambda value: value["databases"][0].__setitem__("size_bytes", -1),
        ),
    ],
)
def test_invalid_numeric_or_identity_values_are_rejected(document, mutation) -> None:
    policy_value = policy()
    observation_value = observation()
    mutation(policy_value if document == "policy" else observation_value)
    with pytest.raises(gate.CapacityGateError):
        gate.evaluate(policy_value, observation_value, now=NOW)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("psql_path", "/usr/bin/python3"),
        ("runuser_path", "/usr/bin/env"),
        ("run_as_user", "root"),
        ("socket_directory", "/tmp/postgresql"),
    ],
)
def test_collector_executable_and_user_choices_are_not_arbitrary(field, value) -> None:
    policy_value = policy()
    policy_value["postgresql"][field] = value
    with pytest.raises(gate.CapacityGateError):
        gate.evaluate(policy_value, observation(), now=NOW)


def test_cli_collects_live_observation_and_uses_safe_exit_codes(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    policy_value = policy()
    observation_value = observation()
    finished = datetime.now(timezone.utc).replace(microsecond=0)
    observation_value["capture_started_at"] = datetime.fromtimestamp(
        finished.timestamp() - 5, tz=timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    observation_value["capture_finished_at"] = finished.strftime("%Y-%m-%dT%H:%M:%SZ")
    policy_bytes = json.dumps(policy_value, sort_keys=True).encode("utf-8")
    observation_bytes = gate._canonical_bytes(observation_value)
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(policy_bytes)
    monkeypatch.setattr(gate, "_program_sha256", lambda: "f" * 64)
    monkeypatch.setattr(
        gate, "_read_bounded_regular_file", lambda path, label: policy_bytes
    )
    monkeypatch.setattr(gate, "collect_observation", lambda value: observation_value)

    command = [
        "--policy",
        str(policy_path),
        "--expected-policy-sha256",
        hashlib.sha256(policy_bytes).hexdigest(),
    ]
    assert gate.main(command) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    passed_report = json.loads(captured.out)
    assert passed_report["capacity_gate_passed"] is True
    assert passed_report["policy_raw_sha256"] == hashlib.sha256(policy_bytes).hexdigest()
    assert passed_report["observation_raw_sha256"] == hashlib.sha256(
        observation_bytes
    ).hexdigest()
    assert passed_report["observation"] == observation_value

    blocked_observation = deepcopy(observation_value)
    for mount in blocked_observation["mounts"]:
        mount["free_bytes"] = 1
    blocked_bytes = gate._canonical_bytes(blocked_observation)
    monkeypatch.setattr(gate, "collect_observation", lambda value: blocked_observation)
    assert gate.main(command) == 1
    captured = capsys.readouterr()
    assert captured.err == ""
    blocked_report = json.loads(captured.out)
    assert blocked_report["capacity_gate_passed"] is False
    assert blocked_report["observation_raw_sha256"] == hashlib.sha256(
        blocked_bytes
    ).hexdigest()

    mismatch_command = deepcopy(command)
    mismatch_command[-1] = "0" * 64
    assert gate.main(mismatch_command) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    error = json.loads(captured.err)
    assert error == {
        "error": "policy SHA-256 mismatch",
        "ok": False,
        "sandbox_accounting_write_authorized": False,
        "sandbox_provisioning_authorized": False,
        "production_accounting_write_authorized": False,
    }


def test_operational_cli_rejects_caller_observation_and_time_override(capsys) -> None:
    for arguments in (
        ["--observation", "forged.json"],
        ["--now", "2026-07-17T12:00:00Z"],
    ):
        assert gate.main(arguments) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        error = json.loads(captured.err)
        assert error["ok"] is False
        assert error["sandbox_provisioning_authorized"] is False
        assert error["sandbox_accounting_write_authorized"] is False
        assert error["production_accounting_write_authorized"] is False


def test_live_collector_composes_only_trusted_probe_results(monkeypatch) -> None:
    policy_value = policy()
    expected = observation()
    monkeypatch.setattr(gate.sys, "platform", "linux")
    monkeypatch.setattr(gate.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(gate, "_program_sha256", lambda: "f" * 64)
    monkeypatch.setattr(gate, "_capture_host", lambda: deepcopy(expected["host"]))
    monkeypatch.setattr(
        gate,
        "_capture_mount_context",
        lambda: ("3" * 64, MOUNTINFO_PAYLOAD, []),
    )
    monkeypatch.setattr(
        gate,
        "_capture_mounts",
        lambda value, entries: deepcopy(expected["mounts"]),
    )
    monkeypatch.setattr(
        gate,
        "_capture_postgresql",
        lambda value, *, deadline_ns: (
            deepcopy(expected["postgresql"]),
            deepcopy(expected["catalog"]),
            deepcopy(expected["databases"]),
            False,
        ),
    )
    times = iter(
        (
            datetime(2026, 7, 17, 11, 59, 55, tzinfo=timezone.utc),
            datetime(2026, 7, 17, 12, 0, 0, tzinfo=timezone.utc),
        )
    )
    monotonic = iter((0, 5_000_000_000))
    monkeypatch.setattr(gate, "_now_utc", lambda: next(times))
    monkeypatch.setattr(gate, "_monotonic_ns", lambda: next(monotonic))

    def resources(value, *, suffix, mount_entries, deadline_ns):
        assert mount_entries == []
        assert deadline_ns == 120_000_000_000
        return {
            item["resource_id"]: {
                f"actual_kind_{suffix}": item[f"actual_kind_{suffix}"],
                f"state_{suffix}": item[f"state_{suffix}"],
                f"identity_sha256_{suffix}": item[f"identity_sha256_{suffix}"],
                f"entry_count_{suffix}": item[f"entry_count_{suffix}"],
                f"total_regular_file_bytes_{suffix}": item[
                    f"total_regular_file_bytes_{suffix}"
                ],
            }
            for item in expected["protected_resources"]
        }

    monkeypatch.setattr(gate, "_capture_resources", resources)
    captured = gate.collect_observation(policy_value)

    assert captured["provenance"] == expected["provenance"]
    assert captured["mounts"] == expected["mounts"]
    assert captured["databases"] == expected["databases"]
    assert captured["target"]["database_exists"] is False
    assert all(captured["side_effect_attestation"][field] is False for field in captured["side_effect_attestation"])
    assert gate.evaluate(policy_value, captured, now=NOW)["capacity_gate_passed"] is True


@pytest.mark.skipif(sys.platform != "linux", reason="live st_dev/statvfs contract is Linux-only")
def test_live_mount_capture_uses_kernel_device_and_conservative_shared_metrics(
    tmp_path: Path, monkeypatch
) -> None:
    paths = []
    for name in ("pg", "filestore", "runtime"):
        path = tmp_path / name
        path.mkdir()
        paths.append(path)
    policy_value = policy()
    entries = gate._parse_mountinfo(Path("/proc/1/mountinfo").read_bytes())
    for allocation, path in zip(policy_value["allocations"], paths):
        allocation["expected_path"] = str(path)
        covering = gate._covering_mount(str(path), entries)
        allocation["expected_mount_point"] = covering["mount_point"]
        allocation["expected_mount_source"] = covering["mount_source"]
        allocation["expected_filesystem_type"] = covering["filesystem_type"]
        allocation["expected_mount_root"] = covering["mount_root"]
        allocation["expected_mount_identity_sha256"] = gate._canonical_sha256(
            gate._mount_identity(covering)
        )
    free_values = iter((30 * GIB, 29 * GIB, 28 * GIB))
    actual = gate.os.statvfs(paths[0])

    def fstatvfs(descriptor):
        free_bytes = next(free_values)
        fragment = actual.f_frsize or actual.f_bsize
        return SimpleNamespace(
            f_frsize=fragment,
            f_bsize=actual.f_bsize,
            f_blocks=actual.f_blocks,
            f_bavail=free_bytes // fragment,
            f_files=actual.f_files,
            f_favail=actual.f_favail,
        )

    monkeypatch.setattr(gate.os, "fstatvfs", fstatvfs)
    rows = gate._capture_mounts(policy_value, entries)

    assert len({row["device_id"] for row in rows}) == 1
    assert {row["free_bytes"] for row in rows} == {
        (28 * GIB // (actual.f_frsize or actual.f_bsize))
        * (actual.f_frsize or actual.f_bsize)
    }


def test_psql_probe_has_fixed_read_only_environment_and_bounded_json(monkeypatch) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return b'{"read_only":"on","system_identifier":"7616327373742442245"}\n'

    monkeypatch.setattr(gate, "_run_read_only_command", run)
    rows = gate._run_psql(policy()["postgresql"], "postgres", "SELECT 1")

    assert rows == [
        {"read_only": "on", "system_identifier": "7616327373742442245"}
    ]
    command, kwargs = calls[0]
    assert command[:4] == ["/usr/sbin/runuser", "-u", "postgres", "--"]
    assert command[-2:] == ["-c", "SELECT 1"]
    assert kwargs["environment"] == {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PGAPPNAME": "odoo-cli-v3-sandbox-capacity-readonly",
            "PGOPTIONS": (
                "-c default_transaction_read_only=on -c search_path=pg_catalog "
                "-c local_preload_libraries= -c session_preload_libraries= "
                "-c statement_timeout=15000 -c lock_timeout=5000 "
            "-c idle_in_transaction_session_timeout=15000 "
            "-c enable_indexscan=off -c enable_indexonlyscan=off "
            "-c enable_bitmapscan=off -c enable_tidscan=off "
            "-c max_parallel_workers_per_gather=0 -c jit=off"
        ),
    }
    assert kwargs["deadline_ns"] is None
    assert kwargs["label"] == "read-only PostgreSQL probe"


def test_locked_psql_probe_uses_one_transaction_and_stops_on_error(monkeypatch) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return b'{"first":true}\n{"second":true}\n'

    monkeypatch.setattr(gate, "_run_read_only_command", run)
    queries = ["SELECT 1", "SELECT 2"]
    rows = gate._run_psql_commands(
        policy()["postgresql"], "odoo_prod", queries, deadline_ns=123
    )

    assert rows == [{"first": True}, {"second": True}]
    command, kwargs = calls[0]
    assert "--single-transaction" in command
    assert command[command.index("-U") + 1] == "postgres"
    assert command[command.index("-d") + 1] == "odoo_prod"
    assert "ON_ERROR_STOP=1" in command
    command_queries = [
        command[index + 1]
        for index, item in enumerate(command[:-1])
        if item == "-c"
    ]
    assert command_queries == queries
    assert kwargs["deadline_ns"] == 123
    assert kwargs["label"] == "locked read-only PostgreSQL relation probe"


def test_system_catalog_and_relation_sql_are_fully_qualified(monkeypatch) -> None:
    postgresql = policy()["postgresql"]
    captured = []
    system_row = {
        "read_only": "on",
        "database_user": "postgres",
        "database_current_user": "postgres",
        "database_user_is_superuser": True,
        "database_user_bypass_rls": True,
        "system_identifier": "7616327373742442245",
        "data_directory": "/var/lib/postgresql/16/main",
        "config_file": "/etc/postgresql/16/main/postgresql.conf",
        "hba_file": "/etc/postgresql/16/main/pg_hba.conf",
        "unix_socket_directories": "/run/postgresql",
        "port": 5432,
        "server_version_num": 160014,
        "in_recovery": False,
        "postmaster_started_at": "2026-07-17T01:00:00Z",
    }

    def run(value, database, query, *, deadline_ns):
        captured.append(query)
        if "pg_catalog.pg_control_system" in query:
            return [deepcopy(system_row)]
        return deepcopy(catalog())

    monkeypatch.setattr(gate, "_run_psql", run)
    gate._capture_system_probe(postgresql, deadline_ns=123)
    gate._capture_catalog(postgresql, deadline_ns=123)

    system_query, catalog_query = captured
    for function in (
        "pg_catalog.json_build_object",
        "pg_catalog.current_setting",
        "pg_catalog.pg_is_in_recovery",
        "pg_catalog.pg_postmaster_start_time",
        "pg_catalog.to_char",
        "pg_catalog.pg_control_system",
    ):
        assert function in system_query
    for object_name in (
        "pg_catalog.json_build_object",
        "pg_catalog.pg_database_size",
        "pg_catalog.pg_database",
        "pg_catalog.pg_roles",
    ):
        assert object_name in catalog_query
    assert "FROM pg_database" not in catalog_query
    assert "JOIN pg_roles" not in catalog_query
    relation_sql = " ".join(
        (
            gate._uuid_relation_assertion_query(
                postgresql,
                policy()["protected_databases"][0][
                    "uuid_relation_identity_sha256"
                ],
            ),
            gate._uuid_relation_identity_query(),
        )
    )
    for object_name in (
        "pg_catalog.pg_class",
        "pg_catalog.pg_namespace",
        "pg_catalog.pg_roles",
        "pg_catalog.pg_attribute",
        "pg_catalog.pg_database",
        "pg_catalog.pg_am",
        "pg_catalog.sha256",
    ):
        assert object_name in relation_sql
    assert "safe_key_count" in relation_sql
    assert "safe_value_count" in relation_sql
    assert "relation_owner_is_superuser" in relation_sql
    assert "current_setting('transaction_isolation')" in relation_sql
    assert "FROM ir_config_parameter" not in gate.UUID_VALUE_QUERY
    assert "FROM ONLY public.ir_config_parameter AS p" in gate.UUID_VALUE_QUERY


def test_database_uuid_probe_locks_validates_and_reads_in_one_transaction(
    monkeypatch,
) -> None:
    mock_uuid_probe_authority(monkeypatch)
    policy_value = policy()
    policy_value["protected_databases"] = [
        deepcopy(policy_value["protected_databases"][0])
    ]
    relation = protected_relation_identities()["odoo_prod"]
    payload = json.dumps(
        relation, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    identity_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    policy_value["protected_databases"][0][
        "uuid_relation_identity_sha256"
    ] = identity_sha256
    rows = [
        {"relation_safe": True},
        {
            "identity_payload": payload,
            "identity_sha256": identity_sha256,
        },
        {
            "read_only": "on",
            "session_user": "odoo",
            "current_user": "odoo",
            "current_user_is_superuser": False,
            "current_user_bypass_rls": False,
            "uuid": "11111111-1111-4111-8111-111111111111",
        },
        {
            "identity_payload": payload,
            "identity_sha256": identity_sha256,
        },
    ]
    calls = []

    def run(postgresql, database, queries, *, deadline_ns):
        calls.append((postgresql, database, queries, deadline_ns))
        return deepcopy(rows)

    monkeypatch.setattr(gate, "_run_psql_commands", run)
    result = gate._capture_database_uuids(
        policy_value, catalog(), deadline_ns=123
    )

    assert result == [
        {
            "name": "odoo_prod",
            "uuid": "11111111-1111-4111-8111-111111111111",
            "uuid_relation_identity_sha256": identity_sha256,
            "uuid_probe_os_user": "odoo",
            "uuid_probe_os_group": "odoo",
            "uuid_probe_os_uid": 999,
            "uuid_probe_os_gid": 1003,
            "uuid_probe_os_supplementary_gids": [1003],
            "uuid_probe_database_user": "odoo",
            "uuid_probe_database_user_is_superuser": False,
            "uuid_probe_database_user_bypass_rls": False,
            "size_bytes": 6 * GIB,
        }
    ]
    assert len(calls) == 1
    probe_postgresql, database, queries, deadline_ns = calls[0]
    assert probe_postgresql["run_as_user"] == "odoo"
    assert probe_postgresql["database_user"] == "odoo"
    assert probe_postgresql["database_user_is_superuser"] is False
    assert database == "odoo_prod"
    assert deadline_ns == 123
    assert queries[0] == (
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
    )
    assert queries[1] == (
        "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE"
    )
    assert identity_sha256 in queries[2]
    assert "pg_catalog.pg_class" in queries[2]
    assert "relation_safe" in queries[2]
    assert "public.ir_config_parameter" not in queries[2]
    assert "pg_catalog.pg_class" in queries[3]
    assert "FROM ONLY public.ir_config_parameter AS p" in queries[4]
    assert "OPERATOR(pg_catalog.=)" in queries[4]
    assert "FROM ir_config_parameter" not in queries[4]
    assert queries[3] == queries[5]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.__setitem__("relation_kind", "v"), "ordinary table"),
        (lambda value: value.__setitem__("persistence", "u"), "persistent"),
        (lambda value: value.__setitem__("access_method", "evil"), "heap"),
        (lambda value: value.__setitem__("row_security", True), "row security"),
        (lambda value: value.__setitem__("force_row_security", True), "row security"),
        (lambda value: value.__setitem__("has_rules", True), "rewrite rules"),
        (lambda value: value.__setitem__("is_partition", True), "partition"),
        (lambda value: value.__setitem__("parent_count", 1), "inheritance"),
        (lambda value: value.__setitem__("child_count", 1), "inheritance"),
        (lambda value: value.__setitem__("relation_owner", "attacker"), "owner"),
        (
            lambda value: value.__setitem__("relation_owner_is_superuser", True),
            "superuser",
        ),
        (
            lambda value: value.__setitem__("relation_owner_bypass_rls", True),
            "RLS bypass",
        ),
        (
            lambda value: value.__setitem__("relation_owner_membership_count", 1),
            "membership",
        ),
        (
            lambda value: value.__setitem__("check_constraint_count", 1),
            "CHECK",
        ),
        (
            lambda value: value.__setitem__(
                "indexes",
                [
                    {
                        "name": "evil_idx",
                        "oid": "29001",
                        "filenode": "29001",
                        "owner": "odoo",
                        "access_method": "btree",
                        "valid": True,
                        "ready": True,
                        "live": True,
                        "unique": False,
                        "primary": False,
                        "exclusion": False,
                        "immediate": True,
                        "key_attribute_numbers": "0",
                        "opclass_oids": "3126",
                        "collation_oids": "0",
                        "options": "0",
                        "has_expressions": True,
                        "has_predicate": False,
                        "all_opclasses_in_pg_catalog": True,
                    }
                ],
            ),
            "index",
        ),
        (
            lambda value: value.__setitem__(
                "statistics",
                [
                    {
                        "name": "evil_stats",
                        "oid": "30001",
                        "owner": "odoo",
                        "keys": "",
                        "kinds": ["e"],
                        "has_expressions": True,
                    }
                ],
            ),
            "statistics",
        ),
        (
            lambda value: value["columns"][1].__setitem__("type_oid", "25"),
            "key column",
        ),
        (
            lambda value: value["columns"][2].__setitem__("type_oid", "1043"),
            "value column",
        ),
        (
            lambda value: value["columns"][1].__setitem__("generated", "s"),
            "key column",
        ),
    ],
)
def test_database_uuid_relation_metadata_rejects_unsafe_objects(
    mutation, message: str
) -> None:
    value = protected_relation_identities()["odoo_prod"]
    mutation(value)

    with pytest.raises(gate.CapacityGateError, match=message):
        gate._validate_uuid_relation_identity(
            value,
            catalog()[0],
            policy()["protected_databases"][0],
        )


def test_database_uuid_probe_rejects_relation_digest_or_metadata_drift(
    monkeypatch,
) -> None:
    mock_uuid_probe_authority(monkeypatch)
    policy_value = policy()
    policy_value["protected_databases"] = [
        deepcopy(policy_value["protected_databases"][0])
    ]
    relation = protected_relation_identities()["odoo_prod"]
    payload = json.dumps(
        relation, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    actual_sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    expected_sha256 = "e" * 64
    policy_value["protected_databases"][0][
        "uuid_relation_identity_sha256"
    ] = expected_sha256
    rows = [
        {"relation_safe": True},
        {"identity_payload": payload, "identity_sha256": actual_sha256},
        {
            "read_only": "on",
            "session_user": "odoo",
            "current_user": "odoo",
            "current_user_is_superuser": False,
            "current_user_bypass_rls": False,
            "uuid": "11111111-1111-4111-8111-111111111111",
        },
        {"identity_payload": payload, "identity_sha256": actual_sha256},
    ]
    monkeypatch.setattr(
        gate,
        "_run_psql_commands",
        lambda *args, **kwargs: deepcopy(rows),
    )

    with pytest.raises(gate.CapacityGateError, match="reviewed policy"):
        gate._capture_database_uuids(policy_value, catalog(), deadline_ns=123)

    policy_value["protected_databases"][0][
        "uuid_relation_identity_sha256"
    ] = actual_sha256
    drifted = deepcopy(rows)
    second_relation = deepcopy(relation)
    second_relation["relation_filenode"] = "99999"
    second_payload = json.dumps(
        second_relation, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    drifted[3] = {
        "identity_payload": second_payload,
        "identity_sha256": hashlib.sha256(second_payload.encode("utf-8")).hexdigest(),
    }
    monkeypatch.setattr(
        gate,
        "_run_psql_commands",
        lambda *args, **kwargs: deepcopy(drifted),
    )
    with pytest.raises(gate.CapacityGateError, match="changed while locked"):
        gate._capture_database_uuids(policy_value, catalog(), deadline_ns=123)


def test_database_probe_identity_includes_relation_binding() -> None:
    entries = observation()["databases"]
    first = gate._database_probe_identity(entries)
    changed = deepcopy(entries)
    changed[0]["uuid_relation_identity_sha256"] = "e" * 64

    assert gate._database_probe_identity(changed) != first


def test_systemd_probe_is_fixed_read_only_and_binds_configuration(monkeypatch) -> None:
    postgresql = policy()["postgresql"]
    postgresql["service_user"] = ""
    postgresql["service_group"] = ""
    postgresql["expected_control_group"] = (
        "/system.slice/system-postgresql.slice/postgresql@16-main.service"
    )
    policy_value = policy()
    policy_value["postgresql"] = postgresql
    gate._validate_policy(policy_value)
    values = {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "MainPID": "4321",
        "ControlGroup": "/system.slice/system-postgresql.slice/postgresql@16-main.service",
        "User": "",
        "Group": "",
        "FragmentPath": "/usr/lib/systemd/system/postgresql@.service",
        "DropInPaths": "",
        "ExecStart": "{ path=/usr/bin/pg_ctlcluster ; argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start ; }",
        "NeedDaemonReload": "no",
        "InvocationID": "0" * 32,
    }
    files_identity = "e" * 64
    configuration = {
        field: values[field]
        for field in (
            "ControlGroup",
            "User",
            "Group",
            "FragmentPath",
            "DropInPaths",
            "ExecStart",
        )
    }
    configuration["FilesIdentitySHA256"] = files_identity
    postgresql["service_configuration_sha256"] = gate._canonical_sha256(configuration)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return "".join(
            f"{field}={values[field]}\n" for field in gate.SYSTEMD_PROPERTIES
        ).encode("utf-8")

    monkeypatch.setattr(gate, "_run_read_only_command", run)
    monkeypatch.setattr(
        gate, "_root_managed_service_files_identity", lambda observed: files_identity
    )
    observed, observed_configuration, _ = gate._capture_systemd_service(
        postgresql, deadline_ns=123
    )
    assert observed == values
    assert observed_configuration == postgresql["service_configuration_sha256"]
    command, kwargs = calls[0]
    assert command[0:3] == ["/usr/bin/systemctl", "show", "--no-pager"]
    assert command[-1] == "postgresql@16-main.service"
    assert not {"start", "stop", "restart", "reload", "enable"}.intersection(command)
    assert kwargs["deadline_ns"] == 123

    values["ActiveState"] = "inactive"
    with pytest.raises(gate.CapacityGateError, match="stable active"):
        gate._capture_systemd_service(postgresql, deadline_ns=123)


@pytest.mark.skipif(sys.platform != "linux", reason="bounded process groups are Linux-only")
def test_bounded_probe_kills_on_output_limit_and_timeout() -> None:
    with pytest.raises(gate.CapacityGateError, match="too large"):
        gate._run_bounded_process(
            [sys.executable, "-I", "-B", "-c", "import os; os.write(1,b'x'*10000)"],
            environment=dict(gate.READ_ONLY_COMMAND_ENVIRONMENT),
            timeout=5,
            stdout_limit=100,
            stderr_limit=100,
            label="bounded-test",
        )

    with pytest.raises(gate.CapacityGateError, match="timed out"):
        gate._run_bounded_process(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(5)"],
            environment=dict(gate.READ_ONLY_COMMAND_ENVIRONMENT),
            timeout=0.05,
            stdout_limit=100,
            stderr_limit=100,
            label="bounded-test",
        )


def test_socket_listener_ignores_connected_rows_and_binds_main_pid(monkeypatch) -> None:
    postgresql = policy()["postgresql"]
    postgresql["unix_socket_directories"] = "/var/run/postgresql"
    socket_path = "/var/run/postgresql/.s.PGSQL.5432"
    payload = (
        "Num RefCount Protocol Flags Type St Inode Path\n"
        f"0001: 2 0 00000000 0001 03 111 {socket_path}\n"
        f"0002: 2 0 00010000 0001 01 222 {socket_path}\n"
    ).encode("utf-8")
    monkeypatch.setattr(gate, "_read_live_bytes", lambda *args, **kwargs: payload)

    class Scan:
        def __enter__(self):
            return [SimpleNamespace(path="/proc/4321/fd/7")]

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(gate.os, "scandir", lambda path: Scan())
    monkeypatch.setattr(gate.os, "readlink", lambda path: "socket:[222]")
    assert gate._socket_listener_identity(postgresql, 4321) == (
        4321,
        socket_path,
        "222",
    )


def test_socket_setting_alias_must_resolve_to_reviewed_physical_directory(
    monkeypatch,
) -> None:
    postgresql = policy()["postgresql"]
    postgresql["unix_socket_directories"] = "/var/run/postgresql"
    reviewed = gate.Path("/run/postgresql")

    def resolve(path, *, strict):
        assert strict is True
        if path in {gate.Path("/var/run/postgresql"), reviewed}:
            return reviewed
        return path

    monkeypatch.setattr(gate.Path, "resolve", resolve)
    assert gate._verify_postgresql_socket_setting(postgresql) == (
        str(gate.Path("/var/run/postgresql")),
        str(reviewed),
    )

    postgresql["unix_socket_directories"] = "/tmp/fake-postgresql"
    with pytest.raises(gate.CapacityGateError, match="does not resolve"):
        gate._verify_postgresql_socket_setting(postgresql)

def test_postgresql_capture_binds_system_catalog_target_and_odoo_uuids(
    monkeypatch,
) -> None:
    policy_value = policy()
    executable_checks = []
    socket_checks = []
    monkeypatch.setattr(
        gate,
        "_verify_root_executable",
        lambda *args: executable_checks.append(args) or (args[0], args[1]),
    )
    monkeypatch.setattr(
        gate,
        "_verify_postgresql_socket",
        lambda value: socket_checks.append(value) or ("socket", 1),
    )
    monkeypatch.setattr(
        gate,
        "_capture_socket_group_membership",
        lambda value: (
            "e" * 64,
            policy_value["postgresql"]["socket_group_members"],
        ),
    )
    monkeypatch.setattr(
        gate,
        "_preflight_postgresql_preload_configuration",
        lambda value: None,
    )
    monkeypatch.setattr(
        gate,
        "_capture_postgresql_configuration",
        lambda value, *, deadline_ns, postmaster: "d" * 64,
    )

    expected = observation()
    capture_order = []
    service = {
        "MainPID": "4321",
        "InvocationID": "0" * 32,
    }
    process = {
        "pid": 4321,
        "postmaster_start_epoch": int(
            datetime(2026, 7, 17, 1, 0, tzinfo=timezone.utc).timestamp()
        ),
        "data_directory_identity_sha256": "a" * 64,
        "postmaster_pid_identity_sha256": "b" * 64,
        "process_identity_sha256": "c" * 64,
        "namespace_identity_sha256": "f" * 64,
        "socket_listener_identity_sha256": "0" * 64,
        "config_file_identity_sha256": "1" * 64,
        "hba_file_identity_sha256": "2" * 64,
    }
    system = {
        "read_only": "on",
        "database_user": "postgres",
        "database_current_user": "postgres",
        "database_user_is_superuser": True,
        "database_user_bypass_rls": True,
        "system_identifier": "7616327373742442245",
        "data_directory": "/var/lib/postgresql/16/main",
        "config_file": "/etc/postgresql/16/main/postgresql.conf",
        "hba_file": "/etc/postgresql/16/main/pg_hba.conf",
        "unix_socket_directories": "/run/postgresql",
        "port": 5432,
        "server_version_num": 160014,
        "in_recovery": False,
        "postmaster_started_at": "2026-07-17T01:00:00Z",
    }
    monkeypatch.setattr(
        gate,
        "_capture_systemd_service",
        lambda value, *, deadline_ns: (service, "4" * 64, "2" * 64),
    )
    monkeypatch.setattr(
        gate,
        "_verify_postgresql_process",
        lambda value, observed_service: deepcopy(process),
    )
    monkeypatch.setattr(
        gate,
        "_run_pg_controldata",
        lambda value, *, deadline_ns: "7616327373742442245",
    )
    monkeypatch.setattr(
        gate,
        "_capture_system_probe",
        lambda value, *, deadline_ns, postmaster: deepcopy(system),
    )
    def capture_catalog(value, *, deadline_ns, postmaster):
        capture_order.append("catalog")
        return deepcopy(expected["catalog"])

    def capture_uuids(value, observed_catalog, *, deadline_ns, postmaster):
        capture_order.append("uuid")
        return deepcopy(expected["databases"])

    monkeypatch.setattr(gate, "_capture_catalog", capture_catalog)
    monkeypatch.setattr(gate, "_capture_database_uuids", capture_uuids)
    identity, observed_catalog, databases, target_exists = gate._capture_postgresql(
        policy_value
    )

    assert identity["system_identifier"] == "7616327373742442245"
    assert identity["psql_sha256"] == "9" * 64
    assert identity["runuser_sha256"] == "8" * 64
    assert gate.HEX64.fullmatch(identity["socket_filesystem_identity_sha256"]) is not None
    assert observed_catalog == expected["catalog"]
    assert databases == observation()["databases"]
    assert target_exists is False
    assert capture_order == ["catalog", "uuid", "uuid", "catalog"]
    assert len(executable_checks) == 10
    assert executable_checks[:5] == executable_checks[5:]
    assert len(socket_checks) == 2


def test_operational_collector_refuses_a_source_checkout() -> None:
    with pytest.raises(gate.CapacityGateError, match="immutable release|isolated"):
        gate._program_sha256()


@pytest.mark.skipif(sys.platform != "linux", reason="root-owned policy contract is Linux-only")
def test_operational_policy_rejects_a_non_root_review_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(gate.CapacityGateError, match="root-owned"):
        gate._read_bounded_regular_file(path, "policy")


def test_protected_file_identity_binds_bytes_metadata_and_inode(tmp_path: Path) -> None:
    path = tmp_path / "protected.py"
    path.write_bytes(b"same bytes\n")
    resource = {
        "resource_id": "protected",
        "path": str(path),
        "kind": "regular_file",
    }

    first_state, first_identity = gate._capture_resource(resource)
    replacement = tmp_path / "replacement.py"
    replacement.write_bytes(b"same bytes\n")
    replacement.replace(path)
    second_state, second_identity = gate._capture_resource(resource)

    assert first_state == second_state == "present"
    assert first_identity != second_identity

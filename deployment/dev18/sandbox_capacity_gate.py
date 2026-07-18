#!/usr/bin/env python3
"""Live, fail-closed capacity gate for a proposed dedicated write sandbox.

The operational CLI consumes a reviewed policy and captures a read-only host
observation itself.  It does not connect to Odoo, mutate PostgreSQL, provision
a sandbox, or authorize accounting writes.  A passing result is only
eligibility for a separate human provisioning review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


POLICY_KIND = "odoo-accounting-cli-v3.sandbox-capacity-policy.v1"
OBSERVATION_KIND = "odoo-accounting-cli-v3.sandbox-capacity-observation.v1"
REPORT_KIND = "odoo-accounting-cli-v3.sandbox-capacity-report.v1"
MAX_INPUT_BYTES = 1_048_576
MAX_INTEGER = 2**63 - 1
MAX_PROTECTED_TREE_ENTRIES = 1_000_000
MAX_PROTECTED_TREE_BYTES = 1 << 40
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
DATABASE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$")
OS_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SQL_ROLE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SYSTEM_IDENTIFIER = re.compile(r"^[1-9][0-9]{9,29}$")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DECIMAL = re.compile(r"^(0|[1-9][0-9]{0,19})$")
FILESYSTEM_TYPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
SERVICE_UNIT = re.compile(r"^postgresql@[1-9][0-9]*-[A-Za-z0-9_.-]+\.service$")
MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")


class CapacityGateError(RuntimeError):
    """The policy, observation, or invocation is not trustworthy enough."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CapacityGateError(message)


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise CapacityGateError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> object:
    raise CapacityGateError(f"non-finite JSON number: {value}")


def load_strict_json(payload: bytes) -> object:
    _require(len(payload) <= MAX_INPUT_BYTES, "JSON input is too large")
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_nonfinite,
        )
    except CapacityGateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapacityGateError("input must be strict UTF-8 JSON") from exc


def _exact_object(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(set(value) == fields, f"{label} fields are invalid")
    return value


def _exact_list(value: object, label: str, *, maximum: int = 128) -> list[Any]:
    _require(isinstance(value, list), f"{label} must be an array")
    _require(len(value) <= maximum, f"{label} has too many entries")
    return value


def _text(value: object, label: str, *, pattern: re.Pattern[str] = SAFE_ID) -> str:
    _require(isinstance(value, str), f"{label} must be a string")
    _require(pattern.fullmatch(value) is not None, f"{label} is invalid")
    return value


def _hex64(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX64.fullmatch(value) is not None,
        f"{label} must be 64 lowercase hexadecimal characters",
    )
    return value


def _uuid(value: object, label: str) -> str:
    _require(isinstance(value, str), f"{label} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise CapacityGateError(f"{label} must be a canonical UUID") from exc
    _require(str(parsed) == value, f"{label} must be a canonical UUID")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_INTEGER,
) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label} must be an integer",
    )
    _require(minimum <= value <= maximum, f"{label} is out of range")
    return value


def _boolean(value: object, label: str) -> bool:
    _require(isinstance(value, bool), f"{label} must be a boolean")
    return value


def _printable_text(value: object, label: str, *, maximum: int = 4096) -> str:
    _require(
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and all(ord(character) >= 32 and ord(character) != 127 for character in value),
        f"{label} must be bounded printable text",
    )
    return value


def _absolute_path(value: object, label: str) -> str:
    _require(
        isinstance(value, str)
        and value.startswith("/")
        and not value.startswith("//")
        and len(value) <= 4096
        and all(ord(character) >= 32 and ord(character) != 127 for character in value),
        f"{label} must be an absolute path without control characters",
    )
    path = PurePosixPath(value)
    _require(
        str(path) == value and ".." not in path.parts and "." not in path.parts,
        f"{label} must be a canonical absolute path",
    )
    return value


def _timestamp(value: object, label: str) -> datetime:
    _require(
        isinstance(value, str) and UTC_TIMESTAMP.fullmatch(value) is not None,
        f"{label} must be an RFC3339 UTC second timestamp",
    )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise CapacityGateError(f"{label} is invalid") from exc
    return parsed


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _catalog_stable_entries(entries: list[dict[str, Any]]) -> list[dict[str, object]]:
    return [
        {
            field: item[field]
            for field in (
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


def _catalog_identity(entries: list[dict[str, Any]]) -> str:
    return _canonical_sha256(_catalog_stable_entries(entries))


def _connectable_names_identity(entries: list[dict[str, Any]]) -> str:
    return _canonical_sha256(
        sorted(item["name"] for item in entries if item["allow_connections"])
    )


def _database_probe_identity(
    entries: list[dict[str, Any]],
) -> list[dict[str, object]]:
    return [
        {
            "name": item["name"],
            "uuid": item["uuid"],
            "uuid_relation_identity_sha256": item[
                "uuid_relation_identity_sha256"
            ],
            "uuid_probe_os_user": item["uuid_probe_os_user"],
            "uuid_probe_os_group": item["uuid_probe_os_group"],
            "uuid_probe_os_uid": item["uuid_probe_os_uid"],
            "uuid_probe_os_gid": item["uuid_probe_os_gid"],
            "uuid_probe_os_supplementary_gids": item[
                "uuid_probe_os_supplementary_gids"
            ],
            "uuid_probe_database_user": item["uuid_probe_database_user"],
            "uuid_probe_database_user_is_superuser": item[
                "uuid_probe_database_user_is_superuser"
            ],
            "uuid_probe_database_user_bypass_rls": item[
                "uuid_probe_database_user_bypass_rls"
            ],
        }
        for item in entries
    ]


MOUNT_IDENTITY_FIELDS = (
    "kernel_mount_id",
    "parent_mount_id",
    "major_minor",
    "mount_root",
    "mount_point",
    "mount_options",
    "optional_fields",
    "filesystem_type",
    "mount_source",
    "super_options",
)


def _mount_identity(item: dict[str, Any]) -> dict[str, object]:
    return {field: item[field] for field in MOUNT_IDENTITY_FIELDS}


def _validate_policy(value: object) -> dict[str, Any]:
    policy = _exact_object(
        value,
        {
            "schema_version",
            "kind",
            "policy_id",
            "environment",
            "host",
            "target",
            "collector_sha256",
            "postgresql",
            "max_observation_age_seconds",
            "max_capture_duration_seconds",
            "allocations",
            "protected_databases",
            "protected_resources",
        },
        "policy",
    )
    _require(type(policy["schema_version"]) is int and policy["schema_version"] == 1, "policy schema version mismatch")
    _require(policy["kind"] == POLICY_KIND, "policy kind mismatch")
    _text(policy["policy_id"], "policy ID")
    _require(policy["environment"] == "sandbox", "policy environment must be sandbox")
    _hex64(policy["collector_sha256"], "policy collector SHA-256")

    host = _exact_object(
        policy["host"],
        {"hostname", "machine_id_sha256", "require_initial_mount_namespace"},
        "policy host",
    )
    _text(host["hostname"], "policy hostname")
    _hex64(host["machine_id_sha256"], "policy machine ID digest")
    _require(
        _boolean(host["require_initial_mount_namespace"], "initial mount namespace requirement"),
        "policy must require the host PID 1 mount namespace",
    )

    target = _exact_object(policy["target"], {"odoo_instance_id", "database_name"}, "policy target")
    _text(target["odoo_instance_id"], "policy Odoo instance ID")
    _text(target["database_name"], "policy database name", pattern=DATABASE_NAME)

    postgresql_fields = {
        "psql_path", "psql_sha256", "runuser_path", "runuser_sha256",
        "systemctl_path", "systemctl_sha256", "pg_controldata_path",
        "pg_controldata_sha256", "postgres_path", "postgres_sha256",
        "run_as_user", "run_as_group", "run_as_uid", "run_as_gid",
        "database_user", "database_user_is_superuser", "database_user_bypass_rls",
        "service_unit", "service_user", "service_group",
        "service_configuration_sha256", "expected_control_group",
        "socket_directory", "unix_socket_directories", "port",
        "maintenance_database", "system_identifier", "data_directory",
        "config_file", "config_file_identity_sha256", "hba_file",
        "hba_file_identity_sha256", "server_version_num", "expected_in_recovery",
        "catalog_identity_sha256", "catalog_total_count",
        "connectable_database_names_sha256", "connectable_database_count",
        "configuration_identity_sha256",
        "socket_group_membership_identity_sha256",
        "socket_group_members",
    }
    postgresql = _exact_object(policy["postgresql"], postgresql_fields, "policy PostgreSQL")
    psql_path = _absolute_path(postgresql["psql_path"], "policy psql path")
    runuser_path = _absolute_path(postgresql["runuser_path"], "policy runuser path")
    systemctl_path = _absolute_path(postgresql["systemctl_path"], "policy systemctl path")
    pg_controldata_path = _absolute_path(postgresql["pg_controldata_path"], "policy pg_controldata path")
    postgres_path = _absolute_path(postgresql["postgres_path"], "policy postgres path")
    runtime_paths = {
        "psql": psql_path,
        "pg_controldata": pg_controldata_path,
        "postgres": postgres_path,
    }
    runtime_versions: set[str] = set()
    for program, path in runtime_paths.items():
        match = re.fullmatch(rf"/usr/lib/postgresql/([1-9][0-9]*)/bin/{program}", path)
        _require(match is not None, f"policy {program} path is outside the fixed PostgreSQL runtime layout")
        runtime_versions.add(match.group(1))
    _require(len(runtime_versions) == 1, "policy PostgreSQL runtime versions differ")
    _require(runuser_path == "/usr/sbin/runuser", "policy runuser path is not allowed")
    _require(systemctl_path == "/usr/bin/systemctl", "policy systemctl path is not allowed")
    for field in (
        "psql_sha256", "runuser_sha256", "systemctl_sha256",
        "pg_controldata_sha256", "postgres_sha256", "service_configuration_sha256",
        "catalog_identity_sha256", "connectable_database_names_sha256",
        "config_file_identity_sha256", "hba_file_identity_sha256",
        "configuration_identity_sha256",
        "socket_group_membership_identity_sha256",
    ):
        _hex64(postgresql[field], f"policy {field.replace('_', ' ')}")
    run_as_user = _text(postgresql["run_as_user"], "policy PostgreSQL OS user", pattern=OS_USER)
    run_as_group = _text(postgresql["run_as_group"], "policy PostgreSQL OS group", pattern=OS_USER)
    _require(run_as_user != "root" and run_as_group != "root", "policy PostgreSQL authority must not be root")
    run_as_uid = _integer(
        postgresql["run_as_uid"],
        "policy PostgreSQL UID",
        minimum=1,
        maximum=2**31 - 1,
    )
    _integer(postgresql["run_as_gid"], "policy PostgreSQL GID", minimum=1, maximum=2**31 - 1)
    database_user = _text(
        postgresql["database_user"],
        "policy PostgreSQL database user",
        pattern=SQL_ROLE,
    )
    _require(
        database_user == run_as_user,
        "policy PostgreSQL OS and database users must match",
    )
    _boolean(
        postgresql["database_user_is_superuser"],
        "policy PostgreSQL database-user superuser state",
    )
    _boolean(
        postgresql["database_user_bypass_rls"],
        "policy PostgreSQL database-user RLS bypass state",
    )
    _validate_socket_group_member_list(
        postgresql["socket_group_members"],
        "policy PostgreSQL socket group members",
        service_user=run_as_user,
        service_uid=run_as_uid,
    )
    service_unit = _text(postgresql["service_unit"], "policy PostgreSQL service unit", pattern=SERVICE_UNIT)
    for field in ("service_user", "service_group"):
        _require(
            isinstance(postgresql[field], str)
            and (
                postgresql[field] == ""
                or OS_USER.fullmatch(postgresql[field]) is not None
            ),
            f"policy PostgreSQL {field.replace('_', ' ')} is invalid",
        )
    control_group = _absolute_path(postgresql["expected_control_group"], "policy PostgreSQL control group")
    _require(
        control_group.endswith(f"/{service_unit}"),
        "policy PostgreSQL control group does not bind the service unit",
    )
    socket_directory = _absolute_path(postgresql["socket_directory"], "policy PostgreSQL socket directory")
    try:
        socket_relative = PurePosixPath(socket_directory).relative_to("/run")
    except ValueError as exc:
        raise CapacityGateError("policy PostgreSQL socket directory must be below /run") from exc
    _require(bool(socket_relative.parts), "policy PostgreSQL socket directory must not be /run itself")
    _absolute_path(
        postgresql["unix_socket_directories"],
        "policy PostgreSQL socket setting",
    )
    _integer(postgresql["port"], "policy PostgreSQL port", minimum=1, maximum=65_535)
    _text(postgresql["maintenance_database"], "policy PostgreSQL maintenance database", pattern=DATABASE_NAME)
    _text(postgresql["system_identifier"], "policy PostgreSQL system identifier", pattern=SYSTEM_IDENTIFIER)
    for field in ("data_directory", "config_file", "hba_file"):
        _absolute_path(postgresql[field], f"policy PostgreSQL {field.replace('_', ' ')}")
    _integer(postgresql["server_version_num"], "policy PostgreSQL server version", minimum=10000, maximum=999999)
    _boolean(postgresql["expected_in_recovery"], "policy PostgreSQL recovery state")
    catalog_total = _integer(postgresql["catalog_total_count"], "policy PostgreSQL catalog count", minimum=1, maximum=256)
    connectable_count = _integer(postgresql["connectable_database_count"], "policy PostgreSQL connectable count", minimum=1, maximum=256)
    _require(connectable_count <= catalog_total, "policy connectable count exceeds catalog count")

    max_age = _integer(policy["max_observation_age_seconds"], "maximum observation age", minimum=1, maximum=86_400)
    max_duration = _integer(policy["max_capture_duration_seconds"], "maximum capture duration", minimum=1, maximum=600)
    _require(max_duration <= max_age, "maximum capture duration exceeds observation age")

    allocations = _exact_list(policy["allocations"], "policy allocations", maximum=32)
    _require(bool(allocations), "policy allocations must not be empty")
    purposes: set[str] = set()
    allocation_ids: set[str] = set()
    allocation_paths: set[str] = set()
    for index, item in enumerate(allocations):
        allocation = _exact_object(
            item,
            {
                "purpose", "allocation_id", "expected_path", "expected_mount_point",
                "expected_mount_source", "expected_filesystem_type", "expected_mount_root",
                "expected_mount_identity_sha256", "additional_bytes", "reserve_bytes",
                "additional_inodes", "reserve_inodes",
            },
            f"policy allocation {index}",
        )
        purpose = _text(allocation["purpose"], f"policy allocation {index} purpose")
        allocation_id = _text(allocation["allocation_id"], f"policy allocation {index} ID")
        _require(purpose not in purposes, "policy allocation purposes must be unique")
        _require(allocation_id not in allocation_ids, "policy allocation IDs must be unique")
        purposes.add(purpose)
        allocation_ids.add(allocation_id)
        allocation_path = _absolute_path(allocation["expected_path"], f"policy allocation {index} path")
        mount_point = _absolute_path(allocation["expected_mount_point"], f"policy allocation {index} mount point")
        try:
            PurePosixPath(allocation_path).relative_to(mount_point)
        except ValueError as exc:
            raise CapacityGateError(f"policy allocation {index} path is outside its mount point") from exc
        mount_source = _printable_text(allocation["expected_mount_source"], f"policy allocation {index} mount source")
        _require("(deleted)" not in mount_source, f"policy allocation {index} mount source is deleted")
        _text(allocation["expected_filesystem_type"], f"policy allocation {index} filesystem type", pattern=FILESYSTEM_TYPE)
        _absolute_path(allocation["expected_mount_root"], f"policy allocation {index} mount root")
        _hex64(allocation["expected_mount_identity_sha256"], f"policy allocation {index} mount identity")
        _require(allocation_path not in allocation_paths, "policy allocation paths must be unique")
        allocation_paths.add(allocation_path)
        values = [
            _integer(allocation[field], f"policy allocation {index} {field}")
            for field in ("additional_bytes", "reserve_bytes", "additional_inodes", "reserve_inodes")
        ]
        _require(any(values), f"policy allocation {index} cannot be empty")
    _require(postgresql["data_directory"] in allocation_paths, "PostgreSQL data directory has no capacity allocation")

    databases = _exact_list(
        policy["protected_databases"], "policy protected databases"
    )
    _require(bool(databases), "policy protected databases must not be empty")
    database_names: set[str] = set()
    for index, item in enumerate(databases):
        database = _exact_object(
            item,
            {
                "name", "uuid", "uuid_relation_identity_sha256",
                "uuid_probe_os_user", "uuid_probe_os_group",
                "uuid_probe_os_uid", "uuid_probe_os_gid",
                "uuid_probe_os_supplementary_gids",
                "uuid_probe_database_user",
            },
            f"policy protected database {index}",
        )
        name = _text(
            database["name"], f"policy protected database {index} name", pattern=DATABASE_NAME
        )
        database_uuid = _uuid(
            database["uuid"], f"policy protected database {index} UUID"
        )
        _hex64(
            database["uuid_relation_identity_sha256"],
            f"policy protected database {index} UUID relation identity",
        )
        probe_os_user = _text(
            database["uuid_probe_os_user"],
            f"policy protected database {index} UUID probe OS user",
            pattern=OS_USER,
        )
        probe_os_group = _text(
            database["uuid_probe_os_group"],
            f"policy protected database {index} UUID probe OS group",
            pattern=OS_USER,
        )
        probe_database_user = _text(
            database["uuid_probe_database_user"],
            f"policy protected database {index} UUID probe database user",
            pattern=SQL_ROLE,
        )
        _integer(
            database["uuid_probe_os_uid"],
            f"policy protected database {index} UUID probe UID",
            minimum=1,
            maximum=2**31 - 1,
        )
        _integer(
            database["uuid_probe_os_gid"],
            f"policy protected database {index} UUID probe GID",
            minimum=1,
            maximum=2**31 - 1,
        )
        supplementary_gids = _exact_list(
            database["uuid_probe_os_supplementary_gids"],
            f"policy protected database {index} UUID probe supplementary GIDs",
            maximum=64,
        )
        _require(
            bool(supplementary_gids)
            and supplementary_gids == sorted(set(supplementary_gids)),
            f"policy protected database {index} UUID probe supplementary GIDs are invalid",
        )
        for group_index, gid in enumerate(supplementary_gids):
            _integer(
                gid,
                f"policy protected database {index} UUID probe supplementary GID {group_index}",
                minimum=1,
                maximum=2**31 - 1,
            )
        _require(
            database["uuid_probe_os_gid"] in supplementary_gids,
            f"policy protected database {index} UUID probe primary GID is missing",
        )
        _require(
            probe_os_user == probe_database_user
            and probe_os_user != postgresql["run_as_user"]
            and probe_database_user != postgresql["database_user"]
            and probe_os_user != "root"
            and probe_os_group != "root",
            f"policy protected database {index} UUID probe authority is not isolated",
        )
        _require(name not in database_names, "protected database names must be unique")
        database_names.add(name)
    _require(
        target["database_name"] not in database_names,
        "sandbox target database name collides with a protected database",
    )

    resources = _exact_list(
        policy["protected_resources"], "policy protected resources"
    )
    _require(bool(resources), "policy protected resources must not be empty")
    resource_ids: set[str] = set()
    resource_paths: set[str] = set()
    for index, item in enumerate(resources):
        resource = _exact_object(
            item,
            {
                "resource_id",
                "path",
                "kind",
                "expected_state",
                "expected_identity_sha256",
                "expected_entry_count",
                "expected_total_regular_file_bytes",
            },
            f"policy protected resource {index}",
        )
        resource_id = _text(
            resource["resource_id"], f"policy protected resource {index} ID"
        )
        _require(resource_id not in resource_ids, "protected resource IDs must be unique")
        resource_ids.add(resource_id)
        resource_path = _absolute_path(
            resource["path"], f"policy protected resource {index} path"
        )
        _require(
            resource_path not in resource_paths,
            "protected resource paths must be unique",
        )
        resource_paths.add(resource_path)
        _require(
            resource["kind"] in {"regular_file", "directory_tree", "absent"},
            f"policy protected resource {index} kind is invalid",
        )
        _require(
            resource["expected_state"] in {"present", "absent"},
            f"policy protected resource {index} state is invalid",
        )
        _require(
            (resource["kind"] in {"regular_file", "directory_tree"} and resource["expected_state"] == "present")
            or (resource["kind"] == "absent" and resource["expected_state"] == "absent"),
            f"policy protected resource {index} kind/state mismatch",
        )
        _hex64(
            resource["expected_identity_sha256"],
            f"policy protected resource {index} identity",
        )
        expected_entry_count = _integer(
            resource["expected_entry_count"],
            f"policy protected resource {index} entry count",
            maximum=MAX_PROTECTED_TREE_ENTRIES,
        )
        expected_total_bytes = _integer(
            resource["expected_total_regular_file_bytes"],
            f"policy protected resource {index} total regular-file bytes",
            maximum=MAX_PROTECTED_TREE_BYTES,
        )
        if resource["kind"] == "absent":
            _require(
                expected_entry_count == 0 and expected_total_bytes == 0,
                f"policy protected resource {index} absent metrics must be zero",
            )
        elif resource["kind"] == "regular_file":
            _require(
                expected_entry_count == 1,
                f"policy protected resource {index} regular-file entry count must be one",
            )
        else:
            _require(
                expected_entry_count >= 1,
                f"policy protected resource {index} directory tree must include its root",
            )
    ordered_paths = sorted(PurePosixPath(path) for path in resource_paths)
    for index, path in enumerate(ordered_paths):
        for other in ordered_paths[index + 1 :]:
            try:
                other.relative_to(path)
            except ValueError:
                continue
            raise CapacityGateError(
                f"protected resource paths overlap: {path} and {other}"
            )
    return policy


def _validate_observation(value: object) -> dict[str, Any]:
    observation = _exact_object(
        value,
        {
            "schema_version",
            "kind",
            "capture_started_at",
            "capture_finished_at",
            "capture_duration_ns",
            "capture_mode",
            "host",
            "environment",
            "provenance",
            "postgresql",
            "target",
            "mounts",
            "catalog",
            "databases",
            "protected_resources",
            "side_effect_attestation",
        },
        "observation",
    )
    _require(
        type(observation["schema_version"]) is int
        and observation["schema_version"] == 1,
        "observation schema version mismatch",
    )
    _require(observation["kind"] == OBSERVATION_KIND, "observation kind mismatch")
    _timestamp(observation["capture_started_at"], "observation capture start time")
    _timestamp(observation["capture_finished_at"], "observation capture finish time")
    _integer(observation["capture_duration_ns"], "observation capture duration", maximum=600 * 1_000_000_000)
    _require(
        observation["capture_mode"] == "read_only",
        "observation capture mode must be read_only",
    )

    host = _exact_object(
        observation["host"],
        {"hostname", "machine_id_sha256", "boot_id_sha256"},
        "observation host",
    )
    _text(host["hostname"], "observation hostname")
    _hex64(host["machine_id_sha256"], "observation machine ID digest")
    _hex64(host["boot_id_sha256"], "observation boot ID digest")

    provenance = _exact_object(
        observation["provenance"],
        {
            "collector", "collector_sha256", "mount_namespace_scope",
            "mount_namespace_identity_sha256", "mountinfo_sha256_before",
            "mountinfo_sha256_after",
        },
        "observation provenance",
    )
    _require(
        provenance["collector"] == "live_linux_v1",
        "observation collector provenance is invalid",
    )
    _hex64(provenance["collector_sha256"], "observation collector SHA-256")
    _require(provenance["mount_namespace_scope"] == "host_pid1", "observation mount namespace scope is invalid")
    for field in ("mount_namespace_identity_sha256", "mountinfo_sha256_before", "mountinfo_sha256_after"):
        _hex64(provenance[field], f"observation {field.replace('_', ' ')}")

    postgresql = _exact_object(
        observation["postgresql"],
        {
            "psql_sha256", "psql_identity_sha256", "runuser_sha256",
            "runuser_identity_sha256", "systemctl_sha256",
            "systemctl_identity_sha256", "pg_controldata_sha256",
            "pg_controldata_identity_sha256", "postgres_sha256",
            "postgres_identity_sha256", "service_unit",
            "service_configuration_sha256", "service_runtime_identity_sha256",
            "main_pid", "control_group", "database_user", "database_current_user",
            "database_user_is_superuser", "database_user_bypass_rls",
            "socket_directory",
            "socket_filesystem_identity_sha256", "socket_listener_identity_sha256",
            "unix_socket_directories", "port", "system_identifier",
            "control_data_system_identifier", "data_directory",
            "data_directory_identity_sha256", "postmaster_pid_identity_sha256",
            "process_identity_sha256", "config_file", "hba_file",
            "config_file_identity_sha256", "hba_file_identity_sha256",
            "server_version_num", "in_recovery", "postmaster_started_at",
            "catalog_identity_sha256_before", "catalog_identity_sha256_after",
            "catalog_total_count", "connectable_database_names_sha256",
            "connectable_database_count", "configuration_identity_sha256_before",
            "configuration_identity_sha256_after",
            "socket_group_membership_identity_sha256_before",
            "socket_group_membership_identity_sha256_after",
            "socket_group_members_before", "socket_group_members_after",
            "postmaster_namespace_identity_sha256",
        },
        "observation PostgreSQL",
    )
    for field in (
        "psql_sha256", "psql_identity_sha256", "runuser_sha256",
        "runuser_identity_sha256", "systemctl_sha256", "systemctl_identity_sha256",
        "pg_controldata_sha256", "pg_controldata_identity_sha256", "postgres_sha256",
        "postgres_identity_sha256", "service_configuration_sha256",
        "service_runtime_identity_sha256", "socket_filesystem_identity_sha256",
        "socket_listener_identity_sha256", "data_directory_identity_sha256",
        "postmaster_pid_identity_sha256", "process_identity_sha256",
        "config_file_identity_sha256", "hba_file_identity_sha256",
        "catalog_identity_sha256_before", "catalog_identity_sha256_after",
        "connectable_database_names_sha256",
        "configuration_identity_sha256_before",
        "configuration_identity_sha256_after",
        "socket_group_membership_identity_sha256_before",
        "socket_group_membership_identity_sha256_after",
        "postmaster_namespace_identity_sha256",
    ):
        _hex64(postgresql[field], f"observation PostgreSQL {field.replace('_', ' ')}")
    _text(postgresql["service_unit"], "observation PostgreSQL service unit", pattern=SERVICE_UNIT)
    _integer(postgresql["main_pid"], "observation PostgreSQL main PID", minimum=2, maximum=2**31 - 1)
    _absolute_path(postgresql["control_group"], "observation PostgreSQL control group")
    _text(
        postgresql["database_user"],
        "observation PostgreSQL database user",
        pattern=SQL_ROLE,
    )
    _text(
        postgresql["database_current_user"],
        "observation PostgreSQL current database user",
        pattern=SQL_ROLE,
    )
    _boolean(
        postgresql["database_user_is_superuser"],
        "observation PostgreSQL database-user superuser state",
    )
    _boolean(
        postgresql["database_user_bypass_rls"],
        "observation PostgreSQL database-user RLS bypass state",
    )
    policy_run_as_user = _text(
        postgresql["database_user"],
        "observation PostgreSQL socket service user",
        pattern=OS_USER,
    )
    before_members = _validate_socket_group_member_list(
        postgresql["socket_group_members_before"],
        "observation PostgreSQL socket group members before",
        service_user=policy_run_as_user,
        service_uid=None,
    )
    _validate_socket_group_member_list(
        postgresql["socket_group_members_after"],
        "observation PostgreSQL socket group members after",
        service_user=policy_run_as_user,
        service_uid=before_members[0]["uid"],
    )
    _absolute_path(postgresql["socket_directory"], "observation PostgreSQL socket directory")
    _absolute_path(
        postgresql["unix_socket_directories"],
        "observation PostgreSQL socket setting",
    )
    _integer(postgresql["port"], "observation PostgreSQL port", minimum=1, maximum=65_535)
    _text(postgresql["system_identifier"], "observation PostgreSQL system identifier", pattern=SYSTEM_IDENTIFIER)
    _text(postgresql["control_data_system_identifier"], "observation PostgreSQL control-data system identifier", pattern=SYSTEM_IDENTIFIER)
    for field in ("data_directory", "config_file", "hba_file"):
        _absolute_path(postgresql[field], f"observation PostgreSQL {field.replace('_', ' ')}")
    _integer(postgresql["server_version_num"], "observation PostgreSQL server version", minimum=10000, maximum=999999)
    _boolean(postgresql["in_recovery"], "observation PostgreSQL recovery state")
    _timestamp(postgresql["postmaster_started_at"], "observation PostgreSQL postmaster start time")
    catalog_total = _integer(postgresql["catalog_total_count"], "observation PostgreSQL catalog count", minimum=1, maximum=256)
    connectable_count = _integer(postgresql["connectable_database_count"], "observation PostgreSQL connectable count", minimum=1, maximum=256)
    _require(connectable_count <= catalog_total, "observation connectable count exceeds catalog count")
    _require(
        observation["environment"] in {"test", "sandbox", "production"},
        "observation environment is invalid",
    )

    target = _exact_object(
        observation["target"],
        {"odoo_instance_id", "database_name", "database_exists"},
        "observation target",
    )
    _text(target["odoo_instance_id"], "observation Odoo instance ID")
    _text(target["database_name"], "observation database name", pattern=DATABASE_NAME)
    _boolean(target["database_exists"], "observation target database existence")

    mounts = _exact_list(observation["mounts"], "observation mounts", maximum=64)
    _require(bool(mounts), "observation mounts must not be empty")
    mount_ids: set[str] = set()
    mount_paths: set[str] = set()
    for index, item in enumerate(mounts):
        mount = _exact_object(
            item,
            {
                "allocation_id",
                "path",
                "device_id",
                "kernel_mount_id",
                "parent_mount_id",
                "major_minor",
                "mount_root",
                "mount_point",
                "mount_options",
                "optional_fields",
                "filesystem_type",
                "mount_source",
                "super_options",
                "mount_identity_sha256",
                "total_bytes",
                "free_bytes",
                "total_inodes",
                "free_inodes",
            },
            f"observation mount {index}",
        )
        allocation_id = _text(mount["allocation_id"], f"observation allocation {index} ID")
        _require(allocation_id not in mount_ids, "observation allocation IDs must be unique")
        mount_ids.add(allocation_id)
        mount_path = _absolute_path(mount["path"], f"observation mount {index} path")
        _require(mount_path not in mount_paths, "observation mount paths must be unique")
        mount_paths.add(mount_path)
        _text(mount["device_id"], f"observation mount {index} device ID")
        _text(mount["kernel_mount_id"], f"observation mount {index} kernel ID", pattern=DECIMAL)
        _text(mount["parent_mount_id"], f"observation mount {index} parent ID", pattern=DECIMAL)
        _require(isinstance(mount["major_minor"], str) and re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None, f"observation mount {index} major:minor is invalid")
        _absolute_path(mount["mount_root"], f"observation mount {index} root")
        _absolute_path(mount["mount_point"], f"observation mount {index} mount point")
        _printable_text(mount["mount_options"], f"observation mount {index} options")
        optional_fields = _exact_list(mount["optional_fields"], f"observation mount {index} optional fields", maximum=32)
        for optional_index, optional in enumerate(optional_fields):
            _printable_text(optional, f"observation mount {index} optional field {optional_index}", maximum=256)
        _text(mount["filesystem_type"], f"observation mount {index} filesystem type", pattern=FILESYSTEM_TYPE)
        _printable_text(mount["mount_source"], f"observation mount {index} source")
        _printable_text(mount["super_options"], f"observation mount {index} super options")
        _hex64(mount["mount_identity_sha256"], f"observation mount {index} identity")
        _require(mount["mount_identity_sha256"] == _canonical_sha256(_mount_identity(mount)), f"observation mount {index} identity digest mismatch")
        total_bytes = _integer(mount["total_bytes"], f"observation mount {index} total bytes", minimum=1)
        free_bytes = _integer(mount["free_bytes"], f"observation mount {index} free bytes")
        total_inodes = _integer(
            mount["total_inodes"], f"observation mount {index} total inodes", minimum=1
        )
        free_inodes = _integer(
            mount["free_inodes"], f"observation mount {index} free inodes"
        )
        _require(free_bytes <= total_bytes, f"observation mount {index} free bytes exceed total")
        _require(
            free_inodes <= total_inodes,
            f"observation mount {index} free inodes exceed total",
        )

    catalog = _exact_list(observation["catalog"], "observation PostgreSQL catalog", maximum=256)
    _require(bool(catalog), "observation PostgreSQL catalog must not be empty")
    catalog_names: set[str] = set()
    catalog_oids: set[str] = set()
    for index, item in enumerate(catalog):
        database = _exact_object(
            item,
            {"oid", "name", "allow_connections", "is_template", "owner", "tablespace_oid", "size_bytes"},
            f"observation PostgreSQL catalog row {index}",
        )
        oid = _text(database["oid"], f"observation PostgreSQL catalog row {index} OID", pattern=DECIMAL)
        name = _text(database["name"], f"observation PostgreSQL catalog row {index} name", pattern=DATABASE_NAME)
        _boolean(database["allow_connections"], f"observation PostgreSQL catalog row {index} connectivity")
        _boolean(database["is_template"], f"observation PostgreSQL catalog row {index} template state")
        _text(
            database["owner"],
            f"observation PostgreSQL catalog row {index} owner",
            pattern=SQL_ROLE,
        )
        _text(database["tablespace_oid"], f"observation PostgreSQL catalog row {index} tablespace OID", pattern=DECIMAL)
        _integer(database["size_bytes"], f"observation PostgreSQL catalog row {index} size")
        _require(name not in catalog_names and oid not in catalog_oids, "observation PostgreSQL catalog identities must be unique")
        catalog_names.add(name)
        catalog_oids.add(oid)
    _require(len(catalog) == catalog_total, "observation PostgreSQL catalog count mismatch")
    _require(
        [item["name"] for item in catalog]
        == sorted(item["name"] for item in catalog),
        "observation PostgreSQL catalog is not deterministically ordered",
    )
    _require(_catalog_identity(catalog) == postgresql["catalog_identity_sha256_after"], "observation PostgreSQL catalog identity mismatch")
    _require(_connectable_names_identity(catalog) == postgresql["connectable_database_names_sha256"], "observation PostgreSQL connectable names identity mismatch")
    _require(sum(1 for item in catalog if item["allow_connections"]) == connectable_count, "observation PostgreSQL connectable count mismatch")

    databases = _exact_list(observation["databases"], "observation databases")
    names: set[str] = set()
    for index, item in enumerate(databases):
        database = _exact_object(
            item,
            {
                "name", "uuid", "uuid_relation_identity_sha256",
                "uuid_probe_os_user", "uuid_probe_os_group",
                "uuid_probe_os_uid", "uuid_probe_os_gid",
                "uuid_probe_os_supplementary_gids",
                "uuid_probe_database_user",
                "uuid_probe_database_user_is_superuser",
                "uuid_probe_database_user_bypass_rls", "size_bytes",
            },
            f"observation database {index}",
        )
        name = _text(
            database["name"], f"observation database {index} name", pattern=DATABASE_NAME
        )
        database_uuid = _uuid(database["uuid"], f"observation database {index} UUID")
        _hex64(
            database["uuid_relation_identity_sha256"],
            f"observation database {index} UUID relation identity",
        )
        probe_os_user = _text(
            database["uuid_probe_os_user"],
            f"observation database {index} UUID probe OS user",
            pattern=OS_USER,
        )
        _text(
            database["uuid_probe_os_group"],
            f"observation database {index} UUID probe OS group",
            pattern=OS_USER,
        )
        probe_database_user = _text(
            database["uuid_probe_database_user"],
            f"observation database {index} UUID probe database user",
            pattern=SQL_ROLE,
        )
        _integer(
            database["uuid_probe_os_uid"],
            f"observation database {index} UUID probe UID",
            minimum=1,
            maximum=2**31 - 1,
        )
        _integer(
            database["uuid_probe_os_gid"],
            f"observation database {index} UUID probe GID",
            minimum=1,
            maximum=2**31 - 1,
        )
        supplementary_gids = _exact_list(
            database["uuid_probe_os_supplementary_gids"],
            f"observation database {index} UUID probe supplementary GIDs",
            maximum=64,
        )
        _require(
            bool(supplementary_gids)
            and supplementary_gids == sorted(set(supplementary_gids)),
            f"observation database {index} UUID probe supplementary GIDs are invalid",
        )
        for group_index, gid in enumerate(supplementary_gids):
            _integer(
                gid,
                f"observation database {index} UUID probe supplementary GID {group_index}",
                minimum=1,
                maximum=2**31 - 1,
            )
        _require(
            probe_os_user == probe_database_user,
            f"observation database {index} UUID probe identities differ",
        )
        _require(
            not _boolean(
                database["uuid_probe_database_user_is_superuser"],
                f"observation database {index} UUID probe superuser state",
            )
            and not _boolean(
                database["uuid_probe_database_user_bypass_rls"],
                f"observation database {index} UUID probe RLS bypass state",
            ),
            f"observation database {index} UUID probe authority is privileged",
        )
        _integer(database["size_bytes"], f"observation database {index} size")
        _require(name not in names, "observation database names must be unique")
        names.add(name)

    resources = _exact_list(
        observation["protected_resources"], "observation protected resources"
    )
    resource_ids: set[str] = set()
    for index, item in enumerate(resources):
        resource = _exact_object(
            item,
            {
                "resource_id",
                "actual_kind_before",
                "actual_kind_after",
                "state_before",
                "state_after",
                "identity_sha256_before",
                "identity_sha256_after",
                "entry_count_before",
                "entry_count_after",
                "total_regular_file_bytes_before",
                "total_regular_file_bytes_after",
            },
            f"observation protected resource {index}",
        )
        resource_id = _text(
            resource["resource_id"], f"observation protected resource {index} ID"
        )
        _require(resource_id not in resource_ids, "observation resource IDs must be unique")
        resource_ids.add(resource_id)
        for suffix in ("before", "after"):
            actual_kind = resource[f"actual_kind_{suffix}"]
            state = resource[f"state_{suffix}"]
            identity = resource[f"identity_sha256_{suffix}"]
            _require(
                actual_kind
                in {"regular_file", "directory_tree", "absent"},
                f"observation protected resource {index} {suffix} actual kind is invalid",
            )
            _require(
                state in {"present", "absent"},
                f"observation protected resource {index} {suffix} state is invalid",
            )
            _require(
                (actual_kind == "absent" and state == "absent")
                or (actual_kind in {"regular_file", "directory_tree"} and state == "present"),
                f"observation protected resource {index} {suffix} kind/state mismatch",
            )
            _hex64(identity, f"observation protected resource {index} {suffix} identity")
            entry_count = _integer(
                resource[f"entry_count_{suffix}"],
                f"observation protected resource {index} {suffix} entry count",
                maximum=MAX_PROTECTED_TREE_ENTRIES,
            )
            total_bytes = _integer(
                resource[f"total_regular_file_bytes_{suffix}"],
                f"observation protected resource {index} {suffix} total regular-file bytes",
                maximum=MAX_PROTECTED_TREE_BYTES,
            )
            _require(
                state != "absent" or (entry_count == 0 and total_bytes == 0),
                f"observation protected resource {index} absent metrics must be zero",
            )

    attestation = _exact_object(
        observation["side_effect_attestation"],
        {
            "filesystem_object_mutation_performed_by_collector",
            "database_transaction_write_performed",
            "service_control_performed",
            "accounting_write_performed",
        },
        "observation side-effect attestation",
    )
    for field in attestation:
        _boolean(attestation[field], f"observation side-effect attestation {field}")
    return observation


def evaluate(
    policy_value: object,
    observation_value: object,
    *,
    now: datetime | None = None,
    policy_raw_sha256: str | None = None,
    observation_raw_sha256: str | None = None,
) -> dict[str, object]:
    policy = _validate_policy(policy_value)
    observation = _validate_observation(observation_value)
    current = datetime.now(timezone.utc) if now is None else now
    _require(
        isinstance(current, datetime)
        and current.tzinfo is not None
        and current.utcoffset() is not None,
        "evaluation time must be timezone-aware",
    )
    current = current.astimezone(timezone.utc).replace(microsecond=0)
    policy_digest = (
        _canonical_sha256(policy)
        if policy_raw_sha256 is None
        else _hex64(policy_raw_sha256, "policy raw SHA-256")
    )
    observation_digest = (
        _canonical_sha256(observation)
        if observation_raw_sha256 is None
        else _hex64(observation_raw_sha256, "observation raw SHA-256")
    )
    started = _timestamp(observation["capture_started_at"], "observation capture start time")
    finished = _timestamp(observation["capture_finished_at"], "observation capture finish time")
    blockers: list[str] = []

    if started > current or finished > current:
        blockers.append("observation_from_future")
    if started <= current and (
        (current - started).total_seconds() > policy["max_observation_age_seconds"]
        or (current - finished).total_seconds() > policy["max_observation_age_seconds"]
    ):
        blockers.append("observation_stale")
    wall_duration_ns = int((finished - started).total_seconds() * 1_000_000_000)
    duration_ns = observation["capture_duration_ns"]
    if wall_duration_ns < 0 or abs(wall_duration_ns - duration_ns) > 2_000_000_000:
        blockers.append("capture_clock_discontinuity")
    if (
        wall_duration_ns > policy["max_capture_duration_seconds"] * 1_000_000_000
        or duration_ns > policy["max_capture_duration_seconds"] * 1_000_000_000
    ):
        blockers.append("capture_duration_exceeded")

    if observation["environment"] != policy["environment"]:
        blockers.append("environment_mismatch")
    if (
        observation["provenance"]["collector"] != "live_linux_v1"
        or observation["provenance"]["collector_sha256"] != policy["collector_sha256"]
        or observation["provenance"]["mount_namespace_scope"] != "host_pid1"
    ):
        blockers.append("collector_binding_mismatch")
    if observation["provenance"]["mountinfo_sha256_before"] != observation["provenance"]["mountinfo_sha256_after"]:
        blockers.append("mount_topology_changed")
    if any(
        observation["postgresql"][field] != policy["postgresql"][field]
        for field in (
            "psql_sha256",
            "runuser_sha256",
            "systemctl_sha256",
            "pg_controldata_sha256",
            "postgres_sha256",
            "service_unit",
            "service_configuration_sha256",
            "database_user",
            "database_user_is_superuser",
            "database_user_bypass_rls",
            "socket_directory",
            "unix_socket_directories",
            "port",
            "system_identifier",
            "data_directory",
            "config_file",
            "config_file_identity_sha256",
            "hba_file",
            "hba_file_identity_sha256",
            "server_version_num",
            "catalog_total_count",
            "connectable_database_names_sha256",
            "connectable_database_count",
        )
    ):
        blockers.append("postgresql_binding_mismatch")
    if observation["postgresql"]["control_group"] != policy["postgresql"]["expected_control_group"]:
        blockers.append("postgresql_binding_mismatch")
    if observation["postgresql"]["in_recovery"] != policy["postgresql"]["expected_in_recovery"]:
        blockers.append("postgresql_binding_mismatch")
    if observation["postgresql"]["database_current_user"] != policy["postgresql"]["database_user"]:
        blockers.append("postgresql_binding_mismatch")
    if observation["postgresql"]["control_data_system_identifier"] != policy["postgresql"]["system_identifier"]:
        blockers.append("postgresql_control_data_mismatch")
    if observation["postgresql"]["catalog_identity_sha256_before"] != observation["postgresql"]["catalog_identity_sha256_after"]:
        blockers.append("postgresql_catalog_drift")
    if observation["postgresql"]["catalog_identity_sha256_after"] != policy["postgresql"]["catalog_identity_sha256"]:
        blockers.append("postgresql_catalog_binding_mismatch")
    if (
        observation["postgresql"]["configuration_identity_sha256_before"]
        != observation["postgresql"]["configuration_identity_sha256_after"]
    ):
        blockers.append("postgresql_configuration_drift")
    if (
        observation["postgresql"]["configuration_identity_sha256_after"]
        != policy["postgresql"]["configuration_identity_sha256"]
    ):
        blockers.append("postgresql_configuration_binding_mismatch")
    if (
        observation["postgresql"]["socket_group_membership_identity_sha256_before"]
        != observation["postgresql"]["socket_group_membership_identity_sha256_after"]
    ):
        blockers.append("postgresql_socket_group_membership_drift")
    if (
        observation["postgresql"]["socket_group_membership_identity_sha256_after"]
        != policy["postgresql"]["socket_group_membership_identity_sha256"]
    ):
        blockers.append("postgresql_socket_group_membership_binding_mismatch")
    if (
        observation["postgresql"]["socket_group_members_before"]
        != observation["postgresql"]["socket_group_members_after"]
    ):
        blockers.append("postgresql_socket_group_membership_drift")
    if (
        observation["postgresql"]["socket_group_members_after"]
        != policy["postgresql"]["socket_group_members"]
    ):
        blockers.append("postgresql_socket_group_membership_binding_mismatch")
    if (
        observation["host"]["hostname"] != policy["host"]["hostname"]
        or observation["host"]["machine_id_sha256"]
        != policy["host"]["machine_id_sha256"]
    ):
        blockers.append("host_binding_mismatch")
    if (
        observation["target"]["odoo_instance_id"]
        != policy["target"]["odoo_instance_id"]
        or observation["target"]["database_name"]
        != policy["target"]["database_name"]
    ):
        blockers.append("target_binding_mismatch")
    if observation["target"]["database_exists"]:
        blockers.append("target_database_already_exists")

    observed_databases = {item["name"]: item for item in observation["databases"]}
    catalog_names = {item["name"] for item in observation["catalog"]}
    if policy["target"]["database_name"] in observed_databases or policy["target"]["database_name"] in catalog_names:
        blockers.append("target_database_already_exists")
    for expected in policy["protected_databases"]:
        actual = observed_databases.get(expected["name"])
        if actual is None or any(
            actual[field] != expected[field]
            for field in (
                "uuid", "uuid_relation_identity_sha256", "uuid_probe_os_user",
                "uuid_probe_os_group", "uuid_probe_os_uid", "uuid_probe_os_gid",
                "uuid_probe_os_supplementary_gids",
                "uuid_probe_database_user",
            )
        ):
            blockers.append(f"protected_database:{expected['name']}")

    expected_resources = {
        item["resource_id"]: item for item in policy["protected_resources"]
    }
    observed_resources = {
        item["resource_id"]: item for item in observation["protected_resources"]
    }
    if set(observed_resources) != set(expected_resources):
        blockers.append("protected_resource_set")
    for resource_id, expected in expected_resources.items():
        actual = observed_resources.get(resource_id)
        if actual is None:
            blockers.append(f"protected_resource:{resource_id}")
            continue
        expected_state = expected["expected_state"]
        expected_kind = expected["kind"]
        expected_identity = expected["expected_identity_sha256"]
        if not (
            actual["actual_kind_before"] == expected_kind
            and actual["actual_kind_after"] == expected_kind
            and actual["state_before"] == expected_state
            and actual["state_after"] == expected_state
            and actual["identity_sha256_before"] == expected_identity
            and actual["identity_sha256_after"] == expected_identity
            and actual["entry_count_before"] == expected["expected_entry_count"]
            and actual["entry_count_after"] == expected["expected_entry_count"]
            and actual["total_regular_file_bytes_before"]
            == expected["expected_total_regular_file_bytes"]
            and actual["total_regular_file_bytes_after"]
            == expected["expected_total_regular_file_bytes"]
        ):
            blockers.append(f"protected_resource:{resource_id}")

    if any(observation["side_effect_attestation"].values()):
        blockers.append("observation_not_read_only")

    observed_mounts = {item["allocation_id"]: item for item in observation["mounts"]}
    expected_allocation_ids = {item["allocation_id"] for item in policy["allocations"]}
    if set(observed_mounts) != expected_allocation_ids:
        blockers.append("mount_allocation_set")
    device_allocations: dict[str, dict[str, object]] = {}
    device_metrics: dict[str, tuple[int, int, int, int]] = {}
    for allocation in policy["allocations"]:
        allocation_id = allocation["allocation_id"]
        mount = observed_mounts.get(allocation_id)
        if mount is None or any(
            (
                mount["path"] != allocation["expected_path"],
                mount["mount_point"] != allocation["expected_mount_point"],
                mount["mount_source"] != allocation["expected_mount_source"],
                mount["filesystem_type"] != allocation["expected_filesystem_type"],
                mount["mount_root"] != allocation["expected_mount_root"],
                mount["mount_identity_sha256"] != allocation["expected_mount_identity_sha256"],
            )
        ):
            blockers.append(f"mount_binding:{allocation_id}")
            continue
        device_id = mount["device_id"]
        metrics = (
            mount["total_bytes"],
            mount["free_bytes"],
            mount["total_inodes"],
            mount["free_inodes"],
        )
        previous_metrics = device_metrics.get(device_id)
        if previous_metrics is not None and previous_metrics != metrics:
            blockers.append(f"device_metrics:{device_id}")
            conservative = (
                min(previous_metrics[0], metrics[0]),
                min(previous_metrics[1], metrics[1]),
                min(previous_metrics[2], metrics[2]),
                min(previous_metrics[3], metrics[3]),
            )
            device_metrics[device_id] = conservative
        else:
            device_metrics[device_id] = metrics
        aggregate = device_allocations.setdefault(
            device_id,
            {
                "allocation_ids": [],
                "additional_bytes": 0,
                "reserve_bytes": 0,
                "additional_inodes": 0,
                "reserve_inodes": 0,
            },
        )
        aggregate["allocation_ids"].append(allocation_id)
        aggregate["additional_bytes"] += allocation["additional_bytes"]
        aggregate["reserve_bytes"] = max(
            aggregate["reserve_bytes"], allocation["reserve_bytes"]
        )
        aggregate["additional_inodes"] += allocation["additional_inodes"]
        aggregate["reserve_inodes"] = max(
            aggregate["reserve_inodes"], allocation["reserve_inodes"]
        )

    devices: list[dict[str, object]] = []
    for device_id in sorted(device_allocations):
        allocation = device_allocations[device_id]
        metrics = device_metrics[device_id]
        free_bytes = metrics[1]
        free_inodes = metrics[3]
        required_bytes = allocation["additional_bytes"] + allocation["reserve_bytes"]
        required_inodes = allocation["additional_inodes"] + allocation["reserve_inodes"]
        shortfall_bytes = max(0, required_bytes - free_bytes)
        shortfall_inodes = max(0, required_inodes - free_inodes)
        if shortfall_bytes:
            blockers.append(f"storage_bytes:{device_id}")
        if shortfall_inodes:
            blockers.append(f"storage_inodes:{device_id}")
        devices.append(
            {
                "device_id": device_id,
                "allocation_ids": sorted(allocation["allocation_ids"]),
                "free_bytes": free_bytes,
                "required_bytes": required_bytes,
                "shortfall_bytes": shortfall_bytes,
                "free_inodes": free_inodes,
                "required_inodes": required_inodes,
                "shortfall_inodes": shortfall_inodes,
                "passed": shortfall_bytes == 0 and shortfall_inodes == 0,
            }
        )

    unique_blockers = sorted(set(blockers))
    passed = not unique_blockers
    return {
        "schema_version": 1,
        "kind": REPORT_KIND,
        "policy_id": policy["policy_id"],
        "policy_canonical_sha256": _canonical_sha256(policy),
        "observation_canonical_sha256": _canonical_sha256(observation),
        "policy_raw_sha256": policy_digest,
        "observation_raw_sha256": observation_digest,
        "capture_started_at": observation["capture_started_at"],
        "capture_finished_at": observation["capture_finished_at"],
        "capture_duration_ns": observation["capture_duration_ns"],
        "evaluated_at": current.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": observation["host"],
        "target": observation["target"],
        "observation": observation,
        "devices": devices,
        "blockers": unique_blockers,
        "capacity_gate_passed": passed,
        "eligible_for_sandbox_provisioning_review": passed,
        "sandbox_provisioning_authorized": False,
        "sandbox_accounting_write_authorized": False,
        "production_accounting_write_authorized": False,
    }


def _program_sha256() -> str:
    _require(
        sys.flags.isolated == 1 and sys.dont_write_bytecode,
        "collector must run with isolated mode and bytecode disabled",
    )
    path = Path(__file__)
    _require(path.is_absolute(), "collector program path must be absolute")
    release_root = Path("/opt/odoo-accounting-cli-v3/releases")
    try:
        relative = path.relative_to(release_root)
    except ValueError as exc:
        raise CapacityGateError(
            "collector program is outside the immutable release root"
        ) from exc
    _require(
        len(relative.parts) == 4
        and SAFE_ID.fullmatch(relative.parts[0]) is not None
        and relative.parts[1:] == (
            "deployment",
            "dev18",
            "sandbox_capacity_gate.py",
        ),
        "collector program is outside the immutable release layout",
    )
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CapacityGateError("collector program cannot be inspected") from exc
    _require(not path.is_symlink(), "collector program must not be a symlink")
    _require(path.resolve(strict=True) == path, "collector program path is not physical")
    _require(stat.S_ISREG(metadata.st_mode), "collector program must be regular")
    _require(
        metadata.st_uid == 0
        and metadata.st_gid == 0
        and metadata.st_mode & 0o022 == 0,
        "collector program must be root-owned and non-writable",
    )
    _require(metadata.st_nlink == 1, "collector program must have one link")
    _verify_root_directory_chain(path.parent, "collector program")
    payload = _read_live_bytes(path, "collector program")
    return hashlib.sha256(payload).hexdigest()


def _directory_identity(path: Path) -> tuple[int, int, int, int, int]:
    metadata = path.lstat()
    _require(not path.is_symlink(), f"trusted directory is a symlink: {path}")
    _require(path.resolve(strict=True) == path, f"trusted directory is not physical: {path}")
    _require(stat.S_ISDIR(metadata.st_mode), f"trusted path is not a directory: {path}")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def _verify_root_directory_chain(path: Path, label: str) -> tuple[tuple[str, tuple[int, ...]], ...]:
    identities: list[tuple[str, tuple[int, ...]]] = []
    current = path
    while True:
        try:
            identity = _directory_identity(current)
        except OSError as exc:
            raise CapacityGateError(f"{label} ancestor cannot be inspected") from exc
        _require(
            identity[2] == 0 and identity[3] == 0 and identity[4] & 0o022 == 0,
            f"{label} ancestor must be root-owned and non-writable: {current}",
        )
        identities.append((str(current), identity))
        if current.parent == current:
            break
        current = current.parent
    return tuple(identities)


def _read_live_bytes(path: Path, label: str, *, maximum: int = 64 * 1024 * 1024) -> bytes:
    """Read a live kernel/root-owned source without following its final link."""

    try:
        path_before = path.lstat()
        _require(not path.is_symlink(), f"{label} must not be a symlink")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NOATIME", 0),
        )
        try:
            before = os.fstat(descriptor)
            _require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file")
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                payload.extend(chunk)
                _require(len(payload) <= maximum, f"{label} is too large")
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise CapacityGateError(f"{label} cannot be read") from exc
    fingerprint = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
    )
    _require(
        fingerprint(path_before)
        == fingerprint(before)
        == fingerprint(after)
        == fingerprint(path_after),
        f"{label} changed while read",
    )
    return bytes(payload)


def _verify_root_executable(
    path_value: str, expected_sha256: str, label: str
) -> tuple[object, ...]:
    path = Path(path_value)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CapacityGateError(f"{label} executable is unavailable") from exc
    _require(not path.is_symlink(), f"{label} executable must not be a symlink")
    _require(path.resolve(strict=True) == path, f"{label} executable path is not physical")
    _require(stat.S_ISREG(metadata.st_mode), f"{label} executable must be regular")
    _require(metadata.st_uid == 0 and metadata.st_gid == 0, f"{label} executable must be root-owned")
    _require(metadata.st_nlink == 1, f"{label} executable must have one link")
    _require(metadata.st_mode & 0o022 == 0, f"{label} executable must not be group/world writable")
    _require(metadata.st_mode & 0o111 != 0, f"{label} executable must be executable")
    ancestors = _verify_root_directory_chain(path.parent, f"{label} executable")
    digest = hashlib.sha256(_read_live_bytes(path, f"{label} executable")).hexdigest()
    after = path.lstat()
    _require(
        (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ),
        f"{label} executable changed while verified",
    )
    _require(digest == expected_sha256, f"{label} executable SHA-256 mismatch")
    return (
        str(path),
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        digest,
        ancestors,
    )


def _verify_postgresql_socket(postgresql: dict[str, Any]) -> tuple[object, ...]:
    directory = Path(postgresql["socket_directory"])
    run_root = Path("/run")
    try:
        relative = directory.relative_to(run_root)
    except ValueError as exc:
        raise CapacityGateError(
            "PostgreSQL socket directory must be below /run"
        ) from exc
    _require(
        len(relative.parts) >= 1,
        "PostgreSQL socket directory must not be /run itself",
    )
    try:
        pwd_module = __import__("pwd")
        account = pwd_module.getpwnam(postgresql["run_as_user"])
        directory_identity = _directory_identity(directory)
        ancestors = _verify_root_directory_chain(
            directory.parent, "PostgreSQL socket directory"
        )
    except (ImportError, KeyError, OSError) as exc:
        raise CapacityGateError(
            "PostgreSQL socket authority cannot be resolved"
        ) from exc
    mode = directory_identity[4]
    _require(
        directory_identity[2] in {0, account.pw_uid},
        "PostgreSQL socket directory owner is not trusted",
    )
    _require(
        mode & 0o022 == 0,
        "PostgreSQL socket directory must not be group- or world-writable",
    )
    socket_path = directory / f".s.PGSQL.{postgresql['port']}"
    try:
        socket_metadata = socket_path.lstat()
    except OSError as exc:
        raise CapacityGateError("PostgreSQL Unix socket is unavailable") from exc
    _require(not socket_path.is_symlink(), "PostgreSQL Unix socket must not be a symlink")
    _require(stat.S_ISSOCK(socket_metadata.st_mode), "PostgreSQL endpoint is not a Unix socket")
    _require(
        socket_metadata.st_uid == account.pw_uid,
        "PostgreSQL Unix socket owner is not the configured OS user",
    )
    return (
        str(directory),
        directory_identity,
        ancestors,
        str(socket_path),
        socket_metadata.st_dev,
        socket_metadata.st_ino,
        socket_metadata.st_mode,
        socket_metadata.st_uid,
        socket_metadata.st_gid,
        socket_metadata.st_nlink,
    )


def _capture_host() -> dict[str, str]:
    hostname = socket.gethostname()
    _text(hostname, "live hostname")
    machine_id = _read_live_bytes(Path("/etc/machine-id"), "machine ID", maximum=4096)
    boot_id = _read_live_bytes(
        Path("/proc/sys/kernel/random/boot_id"), "boot ID", maximum=4096
    )
    return {
        "hostname": hostname,
        "machine_id_sha256": hashlib.sha256(machine_id).hexdigest(),
        "boot_id_sha256": hashlib.sha256(boot_id).hexdigest(),
    }


def _mountinfo_unescape(value: str, label: str) -> str:
    _require("\\" not in MOUNT_ESCAPE.sub("", value), f"{label} contains an invalid mountinfo escape")

    def replace(match: re.Match[str]) -> str:
        _require(match.group(1) in {"011", "012", "040", "134"}, f"{label} contains an invalid mountinfo escape")
        return chr(int(match.group(1), 8))

    return MOUNT_ESCAPE.sub(replace, value)


def _parse_mountinfo(payload: bytes) -> list[dict[str, object]]:
    try:
        text_payload = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CapacityGateError("mountinfo must be UTF-8") from exc
    _require(text_payload.endswith("\n"), "mountinfo is truncated")
    result: list[dict[str, object]] = []
    mount_ids: set[str] = set()
    for index, line in enumerate(text_payload.splitlines()):
        fields = line.split(" ")
        _require("" not in fields, f"mountinfo row {index} has invalid spacing")
        try:
            separator = fields.index("-")
        except ValueError as exc:
            raise CapacityGateError(f"mountinfo row {index} has no separator") from exc
        _require(separator >= 6 and len(fields) == separator + 4, f"mountinfo row {index} fields are invalid")
        mount_id, parent_id, major_minor = fields[0:3]
        _text(mount_id, f"mountinfo row {index} ID", pattern=DECIMAL)
        _text(parent_id, f"mountinfo row {index} parent ID", pattern=DECIMAL)
        _require(re.fullmatch(r"[0-9]+:[0-9]+", major_minor) is not None, f"mountinfo row {index} major:minor is invalid")
        _require(mount_id not in mount_ids, "mountinfo mount IDs must be unique")
        mount_ids.add(mount_id)
        root = _mountinfo_unescape(fields[3], f"mountinfo row {index} root")
        mount_point = _mountinfo_unescape(fields[4], f"mountinfo row {index} mount point")
        _absolute_path(root, f"mountinfo row {index} root")
        _absolute_path(mount_point, f"mountinfo row {index} mount point")
        mount_options = _printable_text(fields[5], f"mountinfo row {index} options")
        optional_fields = fields[6:separator]
        for optional_index, optional in enumerate(optional_fields):
            _printable_text(optional, f"mountinfo row {index} optional field {optional_index}", maximum=256)
        filesystem_type = _text(fields[separator + 1], f"mountinfo row {index} filesystem type", pattern=FILESYSTEM_TYPE)
        mount_source = _mountinfo_unescape(fields[separator + 2], f"mountinfo row {index} source")
        _printable_text(mount_source, f"mountinfo row {index} source")
        _require(
            all("(deleted)" not in item for item in (root, mount_point, mount_source)),
            f"mountinfo row {index} references a deleted path",
        )
        super_options = _printable_text(fields[separator + 3], f"mountinfo row {index} super options")
        result.append(
            {
                "kernel_mount_id": mount_id,
                "parent_mount_id": parent_id,
                "major_minor": major_minor,
                "mount_root": root,
                "mount_point": mount_point,
                "mount_options": mount_options,
                "optional_fields": optional_fields,
                "filesystem_type": filesystem_type,
                "mount_source": mount_source,
                "super_options": super_options,
            }
        )
    _require(bool(result), "mountinfo is empty")
    return result


def _mount_namespace_identity() -> str:
    identities: list[dict[str, object]] = []
    for label, path in (("self", Path("/proc/self/ns/mnt")), ("pid1", Path("/proc/1/ns/mnt"))):
        try:
            metadata = path.stat()
            link = os.readlink(path)
        except OSError as exc:
            raise CapacityGateError(f"{label} mount namespace cannot be inspected") from exc
        _require(re.fullmatch(r"mnt:\[[0-9]+\]", link) is not None, f"{label} mount namespace identity is invalid")
        identities.append({"device": metadata.st_dev, "inode": metadata.st_ino, "link": link})
    _require(identities[0] == identities[1], "collector is outside the host PID 1 mount namespace")
    return _canonical_sha256(identities[0])


def _capture_mount_context() -> tuple[str, bytes, list[dict[str, object]]]:
    namespace = _mount_namespace_identity()
    payload = _read_live_bytes(Path("/proc/1/mountinfo"), "host mountinfo", maximum=MAX_INPUT_BYTES)
    return namespace, payload, _parse_mountinfo(payload)


def _covering_mount(path: str, entries: list[dict[str, object]]) -> dict[str, object]:
    requested = PurePosixPath(path)
    candidates: list[dict[str, object]] = []
    for entry in entries:
        try:
            requested.relative_to(PurePosixPath(str(entry["mount_point"])))
        except ValueError:
            continue
        candidates.append(entry)
    _require(bool(candidates), f"capacity path has no covering mount: {path}")
    longest = max(len(PurePosixPath(str(item["mount_point"])).parts) for item in candidates)
    selected = [item for item in candidates if len(PurePosixPath(str(item["mount_point"])).parts) == longest]
    _require(len(selected) == 1, f"capacity path has ambiguous covering mounts: {path}")
    return selected[0]


def _capture_mounts(
    policy: dict[str, Any], mount_entries: list[dict[str, object]] | None = None
) -> list[dict[str, object]]:
    entries = _parse_mountinfo(
        _read_live_bytes(Path("/proc/1/mountinfo"), "host mountinfo", maximum=MAX_INPUT_BYTES)
    ) if mount_entries is None else mount_entries
    result: list[dict[str, object]] = []
    device_metrics: dict[int, tuple[int, int, int, int]] = {}
    for allocation in policy["allocations"]:
        path = Path(allocation["expected_path"])
        try:
            path_before = path.lstat()
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                metadata = os.fstat(descriptor)
                filesystem = os.fstatvfs(descriptor)
                metadata_after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            path_after = path.lstat()
        except OSError as exc:
            raise CapacityGateError(
                f"capacity probe path is unavailable: {allocation['allocation_id']}"
            ) from exc
        _require(not path.is_symlink(), f"capacity probe path is a symlink: {allocation['allocation_id']}")
        _require(path.resolve(strict=True) == path, f"capacity probe path is not physical: {allocation['allocation_id']}")
        _require(stat.S_ISDIR(metadata.st_mode), f"capacity probe path is not a directory: {allocation['allocation_id']}")
        _require(
            (path_before.st_dev, path_before.st_ino, path_before.st_mode)
            == (metadata.st_dev, metadata.st_ino, metadata.st_mode)
            == (metadata_after.st_dev, metadata_after.st_ino, metadata_after.st_mode)
            == (path_after.st_dev, path_after.st_ino, path_after.st_mode),
            f"capacity probe path changed: {allocation['allocation_id']}",
        )
        mount = _covering_mount(allocation["expected_path"], entries)
        observed_major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
        _require(mount["major_minor"] == observed_major_minor, f"capacity device does not match mountinfo: {allocation['allocation_id']}")
        identity = _mount_identity(mount)
        identity_sha256 = _canonical_sha256(identity)
        _require(identity_sha256 == allocation["expected_mount_identity_sha256"], f"capacity mount identity mismatch: {allocation['allocation_id']}")
        _require(
            mount["mount_point"] == allocation["expected_mount_point"]
            and mount["mount_source"] == allocation["expected_mount_source"]
            and mount["filesystem_type"] == allocation["expected_filesystem_type"]
            and mount["mount_root"] == allocation["expected_mount_root"],
            f"capacity mount policy mismatch: {allocation['allocation_id']}",
        )
        fragment_size = filesystem.f_frsize or filesystem.f_bsize
        _require(fragment_size > 0, f"capacity fragment size is invalid: {allocation['allocation_id']}")
        _require(filesystem.f_blocks > 0, f"capacity block count is invalid: {allocation['allocation_id']}")
        _require(filesystem.f_files > 0, f"capacity inode count is invalid: {allocation['allocation_id']}")
        observed_metrics = (
            filesystem.f_blocks * fragment_size,
            filesystem.f_bavail * fragment_size,
            filesystem.f_files,
            filesystem.f_favail,
        )
        previous_metrics = device_metrics.get(metadata.st_dev)
        device_metrics[metadata.st_dev] = (
            observed_metrics
            if previous_metrics is None
            else tuple(
                min(previous, observed)
                for previous, observed in zip(previous_metrics, observed_metrics)
            )
        )
        result.append(
            {
                "allocation_id": allocation["allocation_id"],
                "path": allocation["expected_path"],
                "device_id": str(metadata.st_dev),
                **identity,
                "mount_identity_sha256": identity_sha256,
            }
        )
    for item in result:
        metrics = device_metrics[int(item["device_id"])]
        item.update(
            {
                "total_bytes": metrics[0],
                "free_bytes": metrics[1],
                "total_inodes": metrics[2],
                "free_inodes": metrics[3],
            }
        )
    return result


def _merge_mount_captures(
    before: list[dict[str, object]], after: list[dict[str, object]]
) -> list[dict[str, object]]:
    before_by_id = {item["allocation_id"]: item for item in before}
    after_by_id = {item["allocation_id"]: item for item in after}
    _require(set(before_by_id) == set(after_by_id), "capacity allocation set changed during capture")
    result: list[dict[str, object]] = []
    metric_fields = ("total_bytes", "free_bytes", "total_inodes", "free_inodes")
    for allocation_id in before_by_id:
        first = before_by_id[allocation_id]
        second = after_by_id[allocation_id]
        _require(
            {key: value for key, value in first.items() if key not in metric_fields}
            == {key: value for key, value in second.items() if key not in metric_fields},
            f"capacity mount changed during capture: {allocation_id}",
        )
        result.append(
            {
                **first,
                **{field: min(first[field], second[field]) for field in metric_fields},
            }
        )
    return result


def _resource_metadata_identity(
    path: Path, metadata: os.stat_result, *, relative_path: str
) -> dict[str, object]:
    return {
        "relative_path": relative_path,
        "path_type": (
            "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "regular_file"
            if stat.S_ISREG(metadata.st_mode)
            else "symlink"
            if stat.S_ISLNK(metadata.st_mode)
            else "other"
        ),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "size": metadata.st_size,
        "links": metadata.st_nlink,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _resource_ancestor_identity(
    path: Path, metadata: os.stat_result
) -> dict[str, object]:
    _require(
        not stat.S_ISLNK(metadata.st_mode),
        f"protected resource ancestor is a symlink: {path}",
    )
    _require(
        stat.S_ISDIR(metadata.st_mode),
        f"protected resource ancestor is not a directory: {path}",
    )
    return {
        "path": str(path),
        "path_type": "directory",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }


def _resource_mount_identity(
    path: Path,
    mount_entries: list[dict[str, object]] | None,
    metadata: os.stat_result | None = None,
) -> dict[str, object] | None:
    if mount_entries is None:
        return None
    mount = _covering_mount(str(path), mount_entries)
    if metadata is not None and hasattr(os, "major") and hasattr(os, "minor"):
        observed_major_minor = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
        _require(
            mount["major_minor"] == observed_major_minor,
            f"protected resource device does not match covering mount: {path}",
        )
    return _mount_identity(mount)


def _present_resource_ancestor_chain(
    path: Path, resource_id: str
) -> list[dict[str, object]]:
    _require(path.is_absolute(), f"protected resource path is not absolute: {resource_id}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CapacityGateError(
            f"protected resource physical path cannot be resolved: {resource_id}"
        ) from exc
    _require(
        resolved == path,
        f"protected resource path is not physical or contains a symlink: {resource_id}",
    )
    chain: list[dict[str, object]] = []
    ancestor = path.parent
    while True:
        try:
            metadata = ancestor.lstat()
        except OSError as exc:
            raise CapacityGateError(
                f"protected resource ancestor cannot be inspected: {resource_id}"
            ) from exc
        _require(
            not stat.S_ISLNK(metadata.st_mode),
            f"protected resource ancestor is a symlink: {ancestor}",
        )
        _require(
            stat.S_ISDIR(metadata.st_mode),
            f"protected resource ancestor is not a directory: {ancestor}",
        )
        chain.append(_resource_ancestor_identity(ancestor, metadata))
        if ancestor.parent == ancestor:
            break
        ancestor = ancestor.parent
    return chain


def _absent_resource_identity(
    resource: dict[str, Any], mount_entries: list[dict[str, object]]
) -> str:
    target = Path(resource["path"])
    unresolved: list[str] = []
    current = target
    while True:
        try:
            metadata = current.lstat()
            break
        except (FileNotFoundError, NotADirectoryError):
            _require(
                current.parent != current,
                f"protected resource has no existing ancestor: {resource['resource_id']}",
            )
            unresolved.append(current.name)
            current = current.parent
        except OSError as exc:
            raise CapacityGateError(
                f"protected resource ancestor cannot be inspected: {resource['resource_id']}"
            ) from exc
    _require(
        not stat.S_ISLNK(metadata.st_mode),
        f"protected resource ancestor is a symlink: {current}",
    )
    _require(
        stat.S_ISDIR(metadata.st_mode),
        f"protected resource nearest existing ancestor is not a directory: {current}",
    )
    ancestor_chain: list[dict[str, object]] = []
    ancestor = current
    while True:
        try:
            ancestor_metadata = ancestor.lstat()
        except OSError as exc:
            raise CapacityGateError(
                f"protected resource ancestor cannot be inspected: {resource['resource_id']}"
            ) from exc
        _require(
            not stat.S_ISLNK(ancestor_metadata.st_mode),
            f"protected resource ancestor is a symlink: {ancestor}",
        )
        _require(
            stat.S_ISDIR(ancestor_metadata.st_mode),
            f"protected resource ancestor is not a directory: {ancestor}",
        )
        ancestor_chain.append(
            _resource_ancestor_identity(ancestor, ancestor_metadata)
        )
        if ancestor.parent == ancestor:
            break
        ancestor = ancestor.parent
    before_chain = _canonical_bytes(ancestor_chain)
    try:
        target.lstat()
    except (FileNotFoundError, NotADirectoryError):
        pass
    except OSError as exc:
        raise CapacityGateError(
            f"protected resource absence cannot be rechecked: {resource['resource_id']}"
        ) from exc
    else:
        raise CapacityGateError(
            f"protected resource appeared during absence capture: {resource['resource_id']}"
        )
    after_chain: list[dict[str, object]] = []
    for ancestor_item in ancestor_chain:
        ancestor_path = Path(str(ancestor_item["path"]))
        try:
            ancestor_metadata = ancestor_path.lstat()
        except OSError as exc:
            raise CapacityGateError(
                f"protected resource ancestor changed during capture: {resource['resource_id']}"
            ) from exc
        after_chain.append(
            _resource_ancestor_identity(ancestor_path, ancestor_metadata)
        )
    _require(
        before_chain == _canonical_bytes(after_chain),
        f"protected resource ancestor changed during capture: {resource['resource_id']}",
    )
    identity = {
        "target_path": resource["path"],
        "nearest_existing_ancestor": str(current),
        "unresolved_suffix": list(reversed(unresolved)),
        "ancestor_chain": ancestor_chain,
        "covering_mount": _resource_mount_identity(
            target, mount_entries, metadata
        ),
    }
    return _canonical_sha256(identity)


def _capture_directory_tree(
    resource: dict[str, Any],
    mount_entries: list[dict[str, object]],
    *,
    deadline_ns: int | None,
    ancestor_chain: list[dict[str, object]],
) -> tuple[str, str, int, int]:
    root = Path(resource["path"])
    manifest: list[dict[str, object]] = []
    total_regular_file_bytes = 0
    expected_entries = resource["expected_entry_count"]
    expected_total_bytes = resource["expected_total_regular_file_bytes"]

    def visit(path: Path, relative_path: str) -> None:
        nonlocal total_regular_file_bytes
        if deadline_ns is not None:
            _require(_monotonic_ns() < deadline_ns, "capture deadline expired")
        try:
            before = path.lstat()
        except OSError as exc:
            raise CapacityGateError(
                f"protected directory tree cannot be inspected: {resource['resource_id']}"
            ) from exc
        _require(
            not stat.S_ISLNK(before.st_mode),
            f"protected directory tree contains a symlink: {path}",
        )
        entry = _resource_metadata_identity(path, before, relative_path=relative_path)
        entry["covering_mount"] = _resource_mount_identity(
            path, mount_entries, before
        )
        if stat.S_ISREG(before.st_mode):
            _require(
                before.st_nlink == 1,
                f"protected directory tree contains a hard-linked file: {path}",
            )
            maximum = min(
                64 * 1024 * 1024,
                max(1, expected_total_bytes - total_regular_file_bytes + 1),
            )
            payload = _read_live_bytes(
                path,
                f"protected directory tree file {resource['resource_id']}",
                maximum=maximum,
            )
            entry["content_sha256"] = hashlib.sha256(payload).hexdigest()
            total_regular_file_bytes += len(payload)
            _require(
                total_regular_file_bytes <= expected_total_bytes,
                f"protected directory tree exceeds reviewed byte count: {resource['resource_id']}",
            )
        elif stat.S_ISDIR(before.st_mode):
            try:
                children = sorted(os.scandir(path), key=lambda item: item.name)
            except OSError as exc:
                raise CapacityGateError(
                    f"protected directory tree cannot be enumerated: {resource['resource_id']}"
                ) from exc
            for child in children:
                child_relative = (
                    child.name if relative_path == "." else f"{relative_path}/{child.name}"
                )
                visit(Path(child.path), child_relative)
            try:
                after = path.lstat()
            except OSError as exc:
                raise CapacityGateError(
                    f"protected directory changed during capture: {resource['resource_id']}"
                ) from exc
            _require(
                _resource_metadata_identity(path, before, relative_path=relative_path)
                == _resource_metadata_identity(path, after, relative_path=relative_path),
                f"protected directory changed during capture: {resource['resource_id']}",
            )
        else:
            raise CapacityGateError(
                f"protected directory tree contains an unsupported object: {path}"
            )
        manifest.append(entry)
        _require(
            len(manifest) <= expected_entries,
            f"protected directory tree exceeds reviewed entry count: {resource['resource_id']}",
        )

    visit(root, ".")
    manifest.sort(key=lambda item: str(item["relative_path"]))
    identity = {
        "root_path": resource["path"],
        "ancestor_chain": ancestor_chain,
        "entries": manifest,
        "entry_count": len(manifest),
        "total_regular_file_bytes": total_regular_file_bytes,
    }
    return "present", _canonical_sha256(identity), len(manifest), total_regular_file_bytes


def _capture_resource_closure(
    resource: dict[str, Any],
    mount_entries: list[dict[str, object]] | None,
    *,
    deadline_ns: int | None,
) -> tuple[str, str, str, int, int]:
    path = Path(resource["path"])
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        _require(
            mount_entries is not None,
            f"protected resource absence has no mount snapshot: {resource['resource_id']}",
        )
        _require(
            resource["kind"] == "absent",
            f"protected resource actual kind absent does not match declared {resource['kind']}: "
            f"{resource['resource_id']}",
        )
        return (
            "absent",
            "absent",
            _absent_resource_identity(resource, mount_entries),
            0,
            0,
        )
    except OSError as exc:
        raise CapacityGateError(
            f"protected resource cannot be inspected: {resource['resource_id']}"
        ) from exc
    ancestor_chain_before = _present_resource_ancestor_chain(
        path, resource["resource_id"]
    )
    if resource["kind"] == "regular_file":
        _require(
            not stat.S_ISLNK(metadata.st_mode),
            f"protected resource root is a symlink: {resource['resource_id']}",
        )
        _require(
            stat.S_ISREG(metadata.st_mode),
            "protected resource actual kind does not match declared regular_file: "
            f"{resource['resource_id']}",
        )
        _require(
            metadata.st_nlink == 1,
            f"protected regular file has multiple hard links: {resource['resource_id']}",
        )
        payload = _read_live_bytes(path, f"protected resource {resource['resource_id']}")
        after = path.lstat()
        _require(
            (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
                after.st_mode,
                after.st_uid,
                after.st_gid,
                after.st_nlink,
            ),
            f"protected resource changed during capture: {resource['resource_id']}",
        )
        identity = {
            "path": resource["path"],
            "content_sha256": hashlib.sha256(payload).hexdigest(),
            "device": after.st_dev,
            "inode": after.st_ino,
            "size": after.st_size,
            "uid": after.st_uid,
            "gid": after.st_gid,
            "mode": stat.S_IMODE(after.st_mode),
            "links": after.st_nlink,
            "mtime_ns": after.st_mtime_ns,
            "ctime_ns": after.st_ctime_ns,
            "ancestor_chain": ancestor_chain_before,
            "covering_mount": _resource_mount_identity(
                path, mount_entries, after
            ),
        }
        _require(
            ancestor_chain_before
            == _present_resource_ancestor_chain(path, resource["resource_id"]),
            f"protected resource ancestor changed during capture: {resource['resource_id']}",
        )
        return "regular_file", "present", _canonical_sha256(identity), 1, after.st_size
    if resource["kind"] == "directory_tree":
        _require(
            not stat.S_ISLNK(metadata.st_mode),
            f"protected resource root is a symlink: {resource['resource_id']}",
        )
        _require(
            stat.S_ISDIR(metadata.st_mode),
            "protected resource actual kind does not match declared directory_tree: "
            f"{resource['resource_id']}",
        )
        _require(
            mount_entries is not None,
            f"protected directory tree has no mount snapshot: {resource['resource_id']}",
        )
        state, identity, entry_count, total_bytes = _capture_directory_tree(
            resource,
            mount_entries,
            deadline_ns=deadline_ns,
            ancestor_chain=ancestor_chain_before,
        )
        _require(
            ancestor_chain_before
            == _present_resource_ancestor_chain(path, resource["resource_id"]),
            f"protected resource ancestor changed during capture: {resource['resource_id']}",
        )
        return "directory_tree", state, identity, entry_count, total_bytes
    raise CapacityGateError(
        "protected resource actual kind present does not match declared absent: "
        f"{resource['resource_id']}"
    )


def _capture_resource(resource: dict[str, Any]) -> tuple[str, str]:
    _, state, identity, _, _ = _capture_resource_closure(
        resource, None, deadline_ns=None
    )
    return state, identity


def _capture_resources(
    resources: list[dict[str, Any]],
    *,
    suffix: str,
    mount_entries: list[dict[str, object]] | None = None,
    deadline_ns: int | None = None,
) -> dict[str, dict[str, object]]:
    entries = (
        _parse_mountinfo(
            _read_live_bytes(
                Path("/proc/1/mountinfo"), "host mountinfo", maximum=MAX_INPUT_BYTES
            )
        )
        if mount_entries is None
        else mount_entries
    )
    captured: dict[str, dict[str, object]] = {}
    for resource in resources:
        actual_kind, state, identity, entry_count, total_bytes = _capture_resource_closure(
            resource, entries, deadline_ns=deadline_ns
        )
        captured[resource["resource_id"]] = {
            f"actual_kind_{suffix}": actual_kind,
            f"state_{suffix}": state,
            f"identity_sha256_{suffix}": identity,
            f"entry_count_{suffix}": entry_count,
            f"total_regular_file_bytes_{suffix}": total_bytes,
        }
    return captured


READ_ONLY_COMMAND_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def _command_timeout(deadline_ns: int | None) -> float:
    if deadline_ns is None:
        return 20
    remaining = (deadline_ns - _monotonic_ns()) / 1_000_000_000
    _require(remaining > 0, "capture deadline expired")
    return min(20, remaining)


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError):
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise CapacityGateError("probe process group could not be reaped") from exc


def _run_bounded_process(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    label: str,
) -> tuple[int, bytes, bytes]:
    _require(timeout > 0, f"{label} deadline expired")
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            text=False,
            start_new_session=True,
            cwd="/",
            close_fds=True,
        )
    except OSError as exc:
        raise CapacityGateError(f"{label} failed to execute") from exc
    _require(process.stdout is not None and process.stderr is not None, f"{label} pipes are unavailable")
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    selector.register(process.stdout, selectors.EVENT_READ, (stdout, stdout_limit, "output"))
    selector.register(process.stderr, selectors.EVENT_READ, (stderr, stderr_limit, "error output"))
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CapacityGateError(f"{label} timed out")
            for key, _ in selector.select(timeout=min(0.2, remaining)):
                target, limit, suffix = key.data
                try:
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                except OSError as exc:
                    raise CapacityGateError(f"{label} pipe read failed") from exc
                if chunk:
                    target.extend(chunk)
                    _require(len(target) <= limit, f"{label} {suffix} is too large")
                else:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CapacityGateError(f"{label} timed out")
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        raise CapacityGateError(f"{label} timed out") from exc
    except CapacityGateError:
        _terminate_process_group(process)
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    return returncode, bytes(stdout), bytes(stderr)


def _run_read_only_command(
    command: list[str],
    *,
    environment: dict[str, str],
    deadline_ns: int | None,
    label: str,
    stdout_limit: int = MAX_INPUT_BYTES,
) -> bytes:
    returncode, stdout, stderr = _run_bounded_process(
        command,
        environment=environment,
        timeout=_command_timeout(deadline_ns),
        stdout_limit=stdout_limit,
        stderr_limit=65_536,
        label=label,
    )
    _require(returncode == 0 and not stderr, f"{label} failed")
    return stdout


def _psql_environment(*, privileged: bool = False) -> dict[str, str]:
    preload_options = "-c local_preload_libraries= "
    if privileged:
        preload_options += "-c session_preload_libraries= "
    return {
        **READ_ONLY_COMMAND_ENVIRONMENT,
        "PGAPPNAME": "odoo-cli-v3-sandbox-capacity-readonly",
        "PGOPTIONS": (
            "-c default_transaction_read_only=on "
            "-c search_path=pg_catalog "
            f"{preload_options}"
            "-c statement_timeout=15000 -c lock_timeout=5000 "
            "-c idle_in_transaction_session_timeout=15000 "
            "-c enable_indexscan=off -c enable_indexonlyscan=off "
            "-c enable_bitmapscan=off -c enable_tidscan=off "
            "-c max_parallel_workers_per_gather=0 -c jit=off"
        ),
    }


CONFIGURATION_SNAPSHOT_COMPONENTS = {
    "configuration_files",
    "configuration_load_identity",
    "settings",
    "file_settings",
    "hba_rules",
    "ident_mappings",
    "db_role_settings",
    "roles",
    "role_password_identity",
    "role_memberships",
}


def _validate_postgresql_preload_settings(settings: object) -> None:
    value = _exact_object(
        settings,
        {
            "shared_preload_libraries",
            "session_preload_libraries",
            "local_preload_libraries",
        },
        "PostgreSQL preload settings",
    )
    for name, setting in value.items():
        _require(
            isinstance(setting, str) and setting == "",
            f"PostgreSQL {name} must be empty",
        )


def _postgresql_configuration_identity(snapshot: object) -> str:
    value = _exact_object(
        snapshot,
        CONFIGURATION_SNAPSHOT_COMPONENTS,
        "PostgreSQL configuration snapshot",
    )
    for component in CONFIGURATION_SNAPSHOT_COMPONENTS:
        items = _exact_list(
            value[component],
            f"PostgreSQL configuration snapshot {component.replace('_', ' ')}",
            maximum=100_000,
        )
        _require(
            all(isinstance(item, dict) for item in items),
            f"PostgreSQL configuration snapshot {component.replace('_', ' ')} entries are invalid",
        )
    password_identity_items = value["role_password_identity"]
    _require(
        len(password_identity_items) == 1,
        "PostgreSQL role password identity row count is invalid",
    )
    password_identity = _exact_object(
        password_identity_items[0],
        {"role_count", "role_password_vector_sha256"},
        "PostgreSQL role password identity",
    )
    _integer(
        password_identity["role_count"],
        "PostgreSQL role password identity role count",
        minimum=1,
        maximum=100_000,
    )
    _hex64(
        password_identity["role_password_vector_sha256"],
        "PostgreSQL role password vector digest",
    )
    load_identity_items = value["configuration_load_identity"]
    _require(
        len(load_identity_items) == 1,
        "PostgreSQL configuration load identity row count is invalid",
    )
    load_identity = _exact_object(
        load_identity_items[0],
        {"load_time_epoch_microseconds"},
        "PostgreSQL configuration load identity",
    )
    _integer(
        load_identity["load_time_epoch_microseconds"],
        "PostgreSQL configuration load time",
        minimum=1,
        maximum=MAX_INTEGER,
    )
    settings_by_name: dict[str, object] = {}
    for index, item in enumerate(value["settings"]):
        _require(
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and isinstance(item.get("setting"), str),
            f"PostgreSQL setting {index} is invalid",
        )
        name = item["name"]
        normalized_name = name.casefold()
        _require(
            normalized_name not in settings_by_name,
            "PostgreSQL setting names are duplicated",
        )
        settings_by_name[normalized_name] = item["setting"]
        _require(
            item.get("pending_restart") is not True,
            f"PostgreSQL setting requires restart: {name}",
        )
    preload_names = (
        "shared_preload_libraries",
        "session_preload_libraries",
        "local_preload_libraries",
    )
    if settings_by_name:
        _validate_postgresql_preload_settings(
            {name: settings_by_name.get(name) for name in preload_names}
        )
    def strings(item: object):
        if isinstance(item, str):
            yield item
        elif isinstance(item, list):
            for child in item:
                yield from strings(child)
        elif isinstance(item, dict):
            for child in item.values():
                yield from strings(child)

    for component in ("db_role_settings", "roles"):
        for setting in strings(value[component]):
            normalized_setting = setting.casefold()
            for name in preload_names:
                prefix = f"{name}="
                if normalized_setting.startswith(prefix):
                    _require(
                        normalized_setting == prefix,
                        f"PostgreSQL role/database default enables {name}",
                    )
    for component in ("file_settings", "hba_rules", "ident_mappings"):
        for index, item in enumerate(value[component]):
            _require(
                item.get("error") is None,
                f"PostgreSQL {component.replace('_', ' ')} entry {index} has an error",
            )
            if component == "file_settings":
                file_name = item.get("name")
                _require(
                    isinstance(file_name, str),
                    f"PostgreSQL file settings entry {index} name is invalid",
                )
                normalized_file_name = file_name.casefold()
                if normalized_file_name in preload_names:
                    _require(
                        item.get("setting") == "",
                        "PostgreSQL configuration source enables "
                        f"{normalized_file_name}",
                    )
    for setting in value["settings"]:
        sourcefile = setting.get("sourcefile")
        if sourcefile is None:
            continue
        _require(
            isinstance(sourcefile, str) and isinstance(setting.get("sourceline"), int),
            f"PostgreSQL effective setting source is invalid: {setting.get('name')}",
        )
        normalized_name = setting["name"].casefold()
        matches = []
        for item in value["file_settings"]:
            file_name = item.get("name")
            if (
                isinstance(file_name, str)
                and file_name.casefold() == normalized_name
                and item.get("sourcefile") == sourcefile
                and item.get("sourceline") == setting.get("sourceline")
                and item.get("applied") is True
                and item.get("error") is None
            ):
                matches.append(item)
        _require(
            len(matches) == 1,
            f"PostgreSQL effective setting is not backed by one applied file row: {setting.get('name')}",
        )
    for index, item in enumerate(value["configuration_files"]):
        file_identity = _exact_object(
            item,
            {"kind", "path", "identity_sha256"},
            f"PostgreSQL configuration file identity {index}",
        )
        _require(
            file_identity["kind"]
            in {"regular_file", "directory_tree", "include_graph"},
            f"PostgreSQL configuration file identity {index} kind is invalid",
        )
        _absolute_path(
            file_identity["path"], f"PostgreSQL configuration file identity {index} path"
        )
        _hex64(
            file_identity["identity_sha256"],
            f"PostgreSQL configuration file identity {index} digest",
        )
    return _canonical_sha256(value)


def _socket_group_membership_identity(snapshot: object) -> str:
    value = _exact_object(
        snapshot,
        {
            "nsswitch_identity_sha256",
            "account_files_identity_sha256",
            "passwd_sources",
            "group_sources",
            "group",
            "accounts",
        },
        "PostgreSQL socket group membership snapshot",
    )
    _hex64(
        value["nsswitch_identity_sha256"],
        "PostgreSQL socket NSS configuration identity",
    )
    _hex64(
        value["account_files_identity_sha256"],
        "PostgreSQL socket account files identity",
    )
    passwd_sources = _exact_list(
        value["passwd_sources"], "PostgreSQL passwd NSS sources", maximum=2
    )
    group_sources = _exact_list(
        value["group_sources"], "PostgreSQL group NSS sources", maximum=2
    )
    _require(
        tuple(passwd_sources) == tuple(group_sources)
        and tuple(passwd_sources) in {("files",), ("files", "systemd")},
        "PostgreSQL NSS sources are unsupported",
    )
    group = _exact_object(
        value["group"],
        {"name", "gid", "explicit_members"},
        "PostgreSQL socket group",
    )
    _text(group["name"], "PostgreSQL socket group name", pattern=OS_USER)
    gid = _integer(
        group["gid"], "PostgreSQL socket group GID", minimum=1, maximum=2**31 - 1
    )
    explicit_members = _exact_list(
        group["explicit_members"],
        "PostgreSQL socket group explicit members",
        maximum=100_000,
    )
    _require(
        explicit_members == sorted(set(explicit_members)),
        "PostgreSQL socket group explicit members are not ordered and unique",
    )
    for index, member in enumerate(explicit_members):
        _text(member, f"PostgreSQL socket group explicit member {index}", pattern=OS_USER)
    accounts = _exact_list(
        value["accounts"], "PostgreSQL socket group accounts", maximum=100_000
    )
    names: list[str] = []
    uids: set[int] = set()
    for index, item in enumerate(accounts):
        account = _exact_object(
            item,
            {"name", "uid", "primary_gid", "supplementary_gids"},
            f"PostgreSQL socket group account {index}",
        )
        name = _text(
            account["name"], f"PostgreSQL socket group account {index} name", pattern=OS_USER
        )
        uid = _integer(
            account["uid"],
            f"PostgreSQL socket group account {index} UID",
            minimum=1,
            maximum=2**31 - 1,
        )
        _integer(
            account["primary_gid"],
            f"PostgreSQL socket group account {index} primary GID",
            minimum=1,
            maximum=2**31 - 1,
        )
        gids = _exact_list(
            account["supplementary_gids"],
            f"PostgreSQL socket group account {index} supplementary GIDs",
            maximum=100_000,
        )
        _require(
            bool(gids)
            and gids == sorted(set(gids))
            and all(
                isinstance(item_gid, int)
                and not isinstance(item_gid, bool)
                and 1 <= item_gid < 2**31
                for item_gid in gids
            )
            and gid in gids,
            f"PostgreSQL socket group account {index} GID membership is invalid",
        )
        _require(uid not in uids, "PostgreSQL socket group account UIDs are duplicated")
        uids.add(uid)
        names.append(name)
    _require(
        len(names) == len(set(names)),
        "PostgreSQL socket group account names are not unique",
    )
    _require(
        set(explicit_members) <= set(names),
        "PostgreSQL socket group has an unresolvable explicit member",
    )
    canonical = {
        **value,
        "accounts": sorted(accounts, key=lambda item: str(item["name"])),
    }
    return _canonical_sha256(canonical)


def _parse_supported_nss_membership_sources(
    payload: bytes,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CapacityGateError("NSS configuration must be UTF-8") from exc
    values: dict[str, tuple[str, ...]] = {}
    for line in lines:
        content = line.split("#", 1)[0].strip()
        if not content or ":" not in content:
            continue
        database, raw_sources = content.split(":", 1)
        database = database.strip()
        if database not in {"passwd", "group"}:
            continue
        _require(database not in values, f"NSS {database} database is duplicated")
        sources = tuple(raw_sources.split())
        _require(
            sources in {("files",), ("files", "systemd")},
            f"NSS {database} sources are not fully enumerable",
        )
        values[database] = sources
    _require(set(values) == {"passwd", "group"}, "NSS membership databases are absent")
    _require(values["passwd"] == values["group"], "NSS membership sources differ")
    return values["passwd"], values["group"]


def _validate_socket_nss_source_safety(
    sources: tuple[str, ...], *, group_writable: bool
) -> None:
    _require(
        sources in {("files",), ("files", "systemd")},
        "PostgreSQL socket NSS sources are unsupported",
    )
    _require(
        not group_writable,
        "PostgreSQL socket directory must not be group-writable",
    )


def _validate_writable_socket_group_members(
    snapshot: object, *, service_user: str, service_uid: int
) -> list[dict[str, object]]:
    value = _exact_object(
        snapshot,
        {
            "nsswitch_identity_sha256",
            "account_files_identity_sha256",
            "passwd_sources",
            "group_sources",
            "group",
            "accounts",
        },
        "PostgreSQL socket group membership snapshot",
    )
    accounts = _exact_list(value["accounts"], "PostgreSQL socket group accounts")
    _require(
        len(accounts) == 1
        and isinstance(accounts[0], dict)
        and accounts[0].get("name") == service_user
        and accounts[0].get("uid") == service_uid,
        "PostgreSQL writable socket group must contain only the exclusive service identity",
    )
    return accounts


def _validate_socket_group_member_list(
    value: object,
    label: str,
    *,
    service_user: str,
    service_uid: int | None,
) -> list[dict[str, Any]]:
    members = _exact_list(value, label, maximum=1)
    _require(len(members) == 1, f"{label} must contain exactly one service identity")
    member = _exact_object(
        members[0],
        {"name", "uid", "primary_gid", "supplementary_gids"},
        f"{label} member",
    )
    _require(
        _text(member["name"], f"{label} member name", pattern=OS_USER) == service_user,
        f"{label} service name mismatch",
    )
    member_uid = _integer(
        member["uid"], f"{label} member UID", minimum=1, maximum=2**31 - 1
    )
    if service_uid is not None:
        _require(member_uid == service_uid, f"{label} service UID mismatch")
    primary_gid = _integer(
        member["primary_gid"],
        f"{label} member primary GID",
        minimum=1,
        maximum=2**31 - 1,
    )
    gids = _exact_list(
        member["supplementary_gids"], f"{label} member supplementary GIDs"
    )
    _require(
        bool(gids)
        and gids == sorted(set(gids))
        and primary_gid in gids
        and all(isinstance(gid, int) and not isinstance(gid, bool) and gid > 0 for gid in gids),
        f"{label} member GIDs are invalid",
    )
    return members


def _assert_no_unreviewed_socket_gid_processes(
    *, socket_gid: int, service_uid: int
) -> None:
    proc = Path("/proc")
    if sys.platform != "linux" or not proc.is_dir():
        return
    for process in proc.iterdir():
        if not process.name.isdigit():
            continue
        try:
            payload = _read_live_bytes(
                process / "status", "socket GID process status", maximum=65_536
            ).decode("ascii")
        except (CapacityGateError, UnicodeDecodeError):
            if not process.exists():
                continue
            raise
        uid_values: list[int] = []
        gid_values: list[int] = []
        supplementary: list[int] = []
        for line in payload.splitlines():
            if line.startswith("Uid:"):
                uid_values = [int(item) for item in line.split(":", 1)[1].split()]
            elif line.startswith("Gid:"):
                gid_values = [int(item) for item in line.split(":", 1)[1].split()]
            elif line.startswith("Groups:"):
                supplementary = [int(item) for item in line.split(":", 1)[1].split()]
        _require(uid_values and gid_values, "socket GID process identity is invalid")
        if socket_gid in set(gid_values) | set(supplementary):
            _require(
                set(uid_values) <= {0, service_uid},
                "unreviewed process has PostgreSQL socket GID authority",
            )


def _capture_socket_group_membership(
    postgresql: dict[str, Any],
) -> tuple[str, list[dict[str, object]]]:
    try:
        pwd_module = __import__("pwd")
        grp_module = __import__("grp")
        directory_metadata = Path(postgresql["socket_directory"]).lstat()
        group = grp_module.getgrgid(directory_metadata.st_gid)
        accounts = pwd_module.getpwall()
    except (ImportError, KeyError, OSError) as exc:
        raise CapacityGateError(
            "PostgreSQL socket group membership cannot be enumerated"
        ) from exc
    account_items: list[dict[str, object]] = []
    for account in accounts:
        try:
            gids = sorted(set(os.getgrouplist(account.pw_name, account.pw_gid)))
        except OSError as exc:
            raise CapacityGateError(
                "PostgreSQL socket account groups cannot be enumerated"
            ) from exc
        if group.gr_gid not in gids:
            continue
        account_items.append(
            {
                "name": account.pw_name,
                "uid": account.pw_uid,
                "primary_gid": account.pw_gid,
                "supplementary_gids": gids,
            }
        )
    account_items.sort(key=lambda item: str(item["name"]))
    account, service_group = _verify_postgresql_authority(postgresql)
    nsswitch_path = Path("/etc/nsswitch.conf")
    nsswitch_payload = _read_live_bytes(
        nsswitch_path, "NSS configuration file", maximum=MAX_INPUT_BYTES
    )
    passwd_sources, group_sources = _parse_supported_nss_membership_sources(
        nsswitch_payload
    )
    _validate_socket_nss_source_safety(
        group_sources,
        group_writable=bool(stat.S_IMODE(directory_metadata.st_mode) & 0o020),
    )
    nsswitch_identity = _trusted_postgresql_file_identity(
        nsswitch_path,
        account.pw_uid,
        service_group.gr_gid,
        "NSS configuration file",
    )
    account_file_identities = {
        path: _trusted_postgresql_file_identity(
            Path(path),
            account.pw_uid,
            service_group.gr_gid,
            f"NSS {Path(path).name} file",
        )
        for path in ("/etc/passwd", "/etc/group")
    }
    snapshot = {
        "nsswitch_identity_sha256": nsswitch_identity,
        "account_files_identity_sha256": _canonical_sha256(account_file_identities),
        "passwd_sources": list(passwd_sources),
        "group_sources": list(group_sources),
        "group": {
            "name": group.gr_name,
            "gid": group.gr_gid,
            "explicit_members": sorted(set(group.gr_mem)),
        },
        "accounts": account_items,
    }
    _validate_writable_socket_group_members(
        snapshot, service_user=account.pw_name, service_uid=account.pw_uid
    )
    _assert_no_unreviewed_socket_gid_processes(
        socket_gid=group.gr_gid, service_uid=account.pw_uid
    )
    return _socket_group_membership_identity(snapshot), account_items


def _psql_command(postgresql: dict[str, Any], database: str) -> list[str]:
    return [
        postgresql["runuser_path"],
        "-u",
        postgresql["run_as_user"],
        "--",
        postgresql["psql_path"],
        "-X",
        "-q",
        "-A",
        "-t",
        "-w",
        "-v",
        "ON_ERROR_STOP=1",
        "-h",
        postgresql["socket_directory"],
        "-p",
        str(postgresql["port"]),
        "-U",
        postgresql["database_user"],
        "-d",
        database,
    ]


def _parse_psql_rows(stdout: bytes) -> list[object]:
    rows: list[object] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        rows.append(load_strict_json(line))
    return rows


def _run_psql(
    postgresql: dict[str, Any],
    database: str,
    query: str,
    *,
    deadline_ns: int | None = None,
    postmaster: dict[str, Any] | None = None,
    cluster_postgresql: dict[str, Any] | None = None,
) -> list[object]:
    if postmaster is not None or cluster_postgresql is not None:
        _require(
            postmaster is not None and cluster_postgresql is not None,
            "PostgreSQL backend attestation context is incomplete",
        )
        rows, _ = _run_attested_psql_commands(
            postgresql,
            cluster_postgresql,
            postmaster,
            database,
            [query],
            deadline_ns=deadline_ns,
        )
        return rows
    command = _psql_command(postgresql, database)
    command.extend(("-c", query))
    stdout = _run_read_only_command(
        command,
        environment=_psql_environment(
            privileged=postgresql["database_user_is_superuser"]
        ),
        deadline_ns=deadline_ns,
        label="read-only PostgreSQL probe",
    )
    return _parse_psql_rows(stdout)


def _run_psql_commands(
    postgresql: dict[str, Any],
    database: str,
    queries: list[str],
    *,
    deadline_ns: int | None = None,
    postmaster: dict[str, Any] | None = None,
    cluster_postgresql: dict[str, Any] | None = None,
) -> list[object]:
    _require(1 <= len(queries) <= 16, "PostgreSQL transaction query count is invalid")
    _require(
        all(isinstance(query, str) and 0 < len(query) <= 65_536 for query in queries),
        "PostgreSQL transaction query is invalid",
    )
    if postmaster is not None or cluster_postgresql is not None:
        _require(
            postmaster is not None and cluster_postgresql is not None,
            "PostgreSQL backend attestation context is incomplete",
        )
        rows, _ = _run_attested_psql_commands(
            postgresql,
            cluster_postgresql,
            postmaster,
            database,
            queries,
            deadline_ns=deadline_ns,
        )
        return rows
    command = _psql_command(postgresql, database)
    command.append("--single-transaction")
    for query in queries:
        command.extend(("-c", query))
    stdout = _run_read_only_command(
        command,
        environment=_psql_environment(
            privileged=postgresql["database_user_is_superuser"]
        ),
        deadline_ns=deadline_ns,
        label="locked read-only PostgreSQL relation probe",
    )
    return _parse_psql_rows(stdout)


def _write_psql_input(
    process: subprocess.Popen[bytes],
    payload: bytes,
    label: str,
    *,
    deadline: float,
) -> None:
    _require(process.stdin is not None, f"{label} input pipe is unavailable")
    try:
        descriptor = process.stdin.fileno()
        was_blocking = os.get_blocking(descriptor)
        os.set_blocking(descriptor, False)
    except (AttributeError, OSError, ValueError) as exc:
        raise CapacityGateError(f"{label} input pipe is not selectable") from exc
    selector = selectors.DefaultSelector()
    selector.register(process.stdin, selectors.EVENT_WRITE)
    offset = 0
    try:
        while offset < len(payload):
            remaining = deadline - time.monotonic()
            _require(remaining > 0, f"{label} timed out")
            events = selector.select(timeout=min(0.2, remaining))
            if not events:
                _require(process.poll() is None, f"{label} exited while receiving input")
                continue
            try:
                written = os.write(descriptor, payload[offset : offset + 65_536])
            except BlockingIOError:
                continue
            except (BrokenPipeError, OSError) as exc:
                raise CapacityGateError(f"{label} input failed") from exc
            _require(written > 0, f"{label} input pipe made no progress")
            offset += written
    finally:
        selector.close()
        try:
            os.set_blocking(descriptor, was_blocking)
        except OSError:
            pass


def _read_psql_marker(
    process: subprocess.Popen[bytes],
    marker: str,
    *,
    deadline: float,
    stderr: bytearray,
    label: str,
) -> list[object]:
    _require(process.stdout is not None and process.stderr is not None, f"{label} pipes are unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    output = bytearray()
    total_stdout_bytes = 0
    rows: list[object] = []
    marker_value = {"capacity_gate_marker": marker}
    found = False
    try:
        while not found:
            remaining = deadline - time.monotonic()
            _require(remaining > 0, f"{label} timed out")
            events = selector.select(timeout=min(0.2, remaining))
            if not events:
                _require(process.poll() is None, f"{label} exited before its marker")
                continue
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                except OSError as exc:
                    raise CapacityGateError(f"{label} pipe read failed") from exc
                if not chunk:
                    selector.unregister(key.fileobj)
                    _require(
                        key.data != "stdout" or found,
                        f"{label} output ended before its marker",
                    )
                    continue
                if key.data == "stderr":
                    stderr.extend(chunk)
                    _require(len(stderr) <= 65_536, f"{label} stderr is too large")
                    continue
                total_stdout_bytes += len(chunk)
                _require(
                    total_stdout_bytes <= MAX_INPUT_BYTES,
                    f"{label} stdout is too large",
                )
                output.extend(chunk)
                _require(len(output) <= MAX_INPUT_BYTES, f"{label} stdout is too large")
                while b"\n" in output:
                    raw, _, remainder = output.partition(b"\n")
                    output = bytearray(remainder)
                    if not raw.strip():
                        continue
                    value = load_strict_json(bytes(raw))
                    if value == marker_value:
                        _require(not output.strip(), f"{label} emitted data after its marker")
                        found = True
                        break
                    rows.append(value)
                    _require(len(rows) <= 100_000, f"{label} returned too many rows")
        _require(not stderr, f"{label} wrote to stderr")
        return rows
    finally:
        selector.close()


def _finish_attested_psql(
    process: subprocess.Popen[bytes], *, deadline: float, stderr: bytearray, label: str
) -> None:
    _require(
        process.stdin is not None and process.stdout is not None and process.stderr is not None,
        f"{label} pipes are unavailable",
    )
    try:
        _write_psql_input(process, b"\\q\n", label, deadline=deadline)
        process.stdin.close()
    except (BrokenPipeError, OSError, CapacityGateError) as exc:
        _terminate_process_group(process)
        if isinstance(exc, CapacityGateError):
            raise
        raise CapacityGateError(f"{label} shutdown failed") from exc
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    unexpected_stdout = bytearray()
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            _require(remaining > 0, f"{label} shutdown timed out")
            events = selector.select(timeout=min(0.2, remaining))
            if not events:
                continue
            for key, _ in events:
                try:
                    chunk = os.read(key.fileobj.fileno(), 65_536)
                except OSError as exc:
                    raise CapacityGateError(f"{label} shutdown pipe failed") from exc
                if not chunk:
                    selector.unregister(key.fileobj)
                elif key.data == "stderr":
                    stderr.extend(chunk)
                    _require(len(stderr) <= 65_536, f"{label} stderr is too large")
                else:
                    unexpected_stdout.extend(chunk)
                    _require(
                        len(unexpected_stdout) <= 65_536,
                        f"{label} trailing stdout is too large",
                    )
        remaining = deadline - time.monotonic()
        _require(remaining > 0, f"{label} shutdown timed out")
        returncode = process.wait(timeout=remaining)
    except (subprocess.TimeoutExpired, CapacityGateError) as exc:
        _terminate_process_group(process)
        if isinstance(exc, CapacityGateError):
            raise
        raise CapacityGateError(f"{label} shutdown timed out") from exc
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    _require(
        returncode == 0 and not stderr and not unexpected_stdout.strip(),
        f"{label} failed",
    )


def _run_attested_psql_commands(
    connection_postgresql: dict[str, Any],
    cluster_postgresql: dict[str, Any],
    postmaster: dict[str, Any],
    database: str,
    queries: list[str],
    *,
    deadline_ns: int | None,
) -> tuple[list[object], str]:
    _require(1 <= len(queries) <= 16, "PostgreSQL attested query count is invalid")
    _require(
        all(isinstance(query, str) and 0 < len(query) <= 65_536 for query in queries),
        "PostgreSQL attested query is invalid",
    )
    timeout = _command_timeout(deadline_ns)
    deadline = time.monotonic() + timeout
    command = _psql_command(connection_postgresql, database)
    command.extend(("-f", "-"))
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_psql_environment(
                privileged=connection_postgresql["database_user_is_superuser"]
            ),
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        raise CapacityGateError("attested read-only PostgreSQL probe could not start") from exc
    stderr = bytearray()
    try:
        _write_psql_input(
            process,
            (
                f"{POSTGRESQL_BACKEND_HANDSHAKE_QUERY};\n"
                "SELECT pg_catalog.json_build_object("
                "'capacity_gate_marker','backend-handshake')::pg_catalog.text;\n"
            ).encode("utf-8"),
            "attested read-only PostgreSQL probe",
            deadline=deadline,
        )
        handshake_rows = _read_psql_marker(
            process,
            "backend-handshake",
            deadline=deadline,
            stderr=stderr,
            label="attested read-only PostgreSQL handshake",
        )
        _require(
            len(handshake_rows) == 1,
            "attested read-only PostgreSQL handshake row count is invalid",
        )
        handshake = _exact_object(
            handshake_rows[0], {"backend_pid"}, "PostgreSQL backend handshake"
        )
        backend_pid = _integer(
            handshake["backend_pid"],
            "PostgreSQL backend handshake PID",
            minimum=2,
            maximum=2**31 - 1,
        )
        backend_before = _verify_postgresql_backend_process(
            cluster_postgresql, postmaster, backend_pid
        )
        transaction_queries = list(queries)
        if transaction_queries[0] == (
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        ):
            transaction_queries.pop(0)
        script = ["BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;"]
        script.extend(f"{query.rstrip().rstrip(';')};" for query in transaction_queries)
        script.extend(
            (
                "SELECT pg_catalog.json_build_object("
                "'capacity_gate_marker','transaction-complete')::pg_catalog.text;",
                "ROLLBACK;",
            )
        )
        _write_psql_input(
            process,
            ("\n".join(script) + "\n").encode("utf-8"),
            "attested read-only PostgreSQL transaction",
            deadline=deadline,
        )
        rows = _read_psql_marker(
            process,
            "transaction-complete",
            deadline=deadline,
            stderr=stderr,
            label="attested read-only PostgreSQL transaction",
        )
        backend_after = _verify_postgresql_backend_process(
            cluster_postgresql, postmaster, backend_pid
        )
        _require(
            backend_before == backend_after,
            "PostgreSQL backend process changed during attested query",
        )
        _finish_attested_psql(
            process,
            deadline=deadline,
            stderr=stderr,
            label="attested read-only PostgreSQL probe",
        )
        return rows, backend_after["process_identity_sha256"]
    except CapacityGateError:
        _terminate_process_group(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        raise


SYSTEMD_PROPERTIES = (
    "LoadState",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlGroup",
    "User",
    "Group",
    "FragmentPath",
    "DropInPaths",
    "ExecStart",
    "NeedDaemonReload",
    "InvocationID",
)


def _root_managed_service_files_identity(values: dict[str, str]) -> str:
    reported_paths = [values["FragmentPath"]]
    if values["DropInPaths"]:
        reported_paths.extend(values["DropInPaths"].split())
    _require(len(reported_paths) <= 32, "PostgreSQL systemd service has too many files")
    _require(len(reported_paths) == len(set(reported_paths)), "PostgreSQL systemd service files are duplicated")
    identities: list[dict[str, object]] = []
    for index, reported_path in enumerate(reported_paths):
        _absolute_path(reported_path, f"PostgreSQL systemd file {index}")
        try:
            physical_path = Path(reported_path).resolve(strict=True)
            payload = _read_bounded_regular_file(
                physical_path, f"PostgreSQL systemd file {index}"
            )
            metadata = physical_path.lstat()
        except OSError as exc:
            raise CapacityGateError(
                f"PostgreSQL systemd file {index} cannot be inspected"
            ) from exc
        identities.append(
            {
                "reported_path": reported_path,
                "physical_path": str(physical_path),
                "content_sha256": hashlib.sha256(payload).hexdigest(),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "links": metadata.st_nlink,
            }
        )
    return _canonical_sha256(identities)


def _capture_systemd_service(
    postgresql: dict[str, Any], *, deadline_ns: int | None
) -> tuple[dict[str, str], str, str]:
    payload = _run_read_only_command(
        [
            postgresql["systemctl_path"],
            "show",
            "--no-pager",
            f"--property={','.join(SYSTEMD_PROPERTIES)}",
            postgresql["service_unit"],
        ],
        environment=dict(READ_ONLY_COMMAND_ENVIRONMENT),
        deadline_ns=deadline_ns,
        label="read-only systemd probe",
        stdout_limit=65_536,
    )
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CapacityGateError("systemd probe output must be UTF-8") from exc
    values: dict[str, str] = {}
    for line in decoded.splitlines():
        key, separator, item = line.partition("=")
        _require(
            separator == "=" and key in SYSTEMD_PROPERTIES and key not in values,
            "systemd probe output is invalid",
        )
        _require(
            len(item) <= 16_384
            and all(ord(character) >= 32 and ord(character) != 127 for character in item),
            "systemd probe value is invalid",
        )
        values[key] = item
    _require(set(values) == set(SYSTEMD_PROPERTIES), "systemd probe properties are incomplete")
    _require(
        values["LoadState"] == "loaded"
        and values["ActiveState"] == "active"
        and values["SubState"] == "running"
        and values["NeedDaemonReload"] == "no",
        "PostgreSQL service is not a stable active unit",
    )
    _text(values["MainPID"], "PostgreSQL systemd MainPID", pattern=DECIMAL)
    _require(int(values["MainPID"]) > 1, "PostgreSQL systemd MainPID is invalid")
    _require(
        values["User"] == postgresql["service_user"]
        and values["Group"] == postgresql["service_group"],
        "PostgreSQL systemd user/group mismatch",
    )
    _require(
        values["ControlGroup"] == postgresql["expected_control_group"],
        "PostgreSQL systemd control group mismatch",
    )
    _absolute_path(values["FragmentPath"], "PostgreSQL unit fragment path")
    _require(bool(values["ExecStart"]), "PostgreSQL systemd ExecStart is empty")
    _require(
        re.fullmatch(r"[0-9a-f]{32}", values["InvocationID"]) is not None,
        "PostgreSQL systemd invocation ID is invalid",
    )
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
    configuration["FilesIdentitySHA256"] = _root_managed_service_files_identity(values)
    configuration_sha256 = _canonical_sha256(configuration)
    _require(
        configuration_sha256 == postgresql["service_configuration_sha256"],
        "PostgreSQL systemd configuration mismatch",
    )
    return values, configuration_sha256, _canonical_sha256(values)


def _verify_postgresql_authority(postgresql: dict[str, Any]) -> tuple[object, object]:
    try:
        pwd_module = __import__("pwd")
        grp_module = __import__("grp")
        account = pwd_module.getpwnam(postgresql["run_as_user"])
        group = grp_module.getgrnam(postgresql["run_as_group"])
    except (ImportError, KeyError) as exc:
        raise CapacityGateError("PostgreSQL OS authority cannot be resolved") from exc
    _require(
        account.pw_uid == postgresql["run_as_uid"]
        and group.gr_gid == postgresql["run_as_gid"],
        "PostgreSQL OS authority numeric identity mismatch",
    )
    _require(account.pw_gid == group.gr_gid, "PostgreSQL OS authority primary group mismatch")
    return account, group


def _uuid_probe_postgresql(
    postgresql: dict[str, Any], expected: dict[str, Any]
) -> tuple[dict[str, Any], tuple[object, ...]]:
    """Bind a protected-database query to its reviewed non-superuser authority."""
    try:
        pwd_module = __import__("pwd")
        grp_module = __import__("grp")
        account = pwd_module.getpwnam(expected["uuid_probe_os_user"])
        group = grp_module.getgrnam(expected["uuid_probe_os_group"])
        supplementary_gids = tuple(
            sorted(set(os.getgrouplist(account.pw_name, account.pw_gid)))
        )
    except (ImportError, KeyError, OSError) as exc:
        raise CapacityGateError(
            f"database UUID probe authority cannot be resolved: {expected['name']}"
        ) from exc
    _require(
        account.pw_name == expected["uuid_probe_os_user"]
        and account.pw_uid == expected["uuid_probe_os_uid"]
        and account.pw_gid == expected["uuid_probe_os_gid"]
        and group.gr_name == expected["uuid_probe_os_group"]
        and group.gr_gid == expected["uuid_probe_os_gid"]
        and supplementary_gids
        == tuple(expected["uuid_probe_os_supplementary_gids"]),
        f"database UUID probe OS authority mismatch: {expected['name']}",
    )
    probe = dict(postgresql)
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
        account.pw_name,
        account.pw_uid,
        account.pw_gid,
        group.gr_name,
        group.gr_gid,
        supplementary_gids,
        expected["uuid_probe_database_user"],
    )
    return probe, identity


def _trusted_postgresql_directory_chain(
    path: Path, uid: int, gid: int
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    identities: list[tuple[str, tuple[int, ...]]] = []
    current = path
    while True:
        try:
            identity = _directory_identity(current)
        except OSError as exc:
            raise CapacityGateError(
                "PostgreSQL data directory ancestor cannot be inspected"
            ) from exc
        _require(
            identity[2] in {0, uid} and identity[3] in {0, gid},
            f"PostgreSQL data directory ancestor owner is untrusted: {current}",
        )
        _require(
            identity[4] & 0o002 == 0,
            f"PostgreSQL data directory ancestor is world writable: {current}",
        )
        _require(
            identity[4] & 0o020 == 0 or identity[3] == gid,
            f"PostgreSQL data directory ancestor writable group is untrusted: {current}",
        )
        identities.append((str(current), identity))
        if current.parent == current:
            break
        current = current.parent
    return tuple(identities)


def _parse_proc_status(
    payload: bytes, uid: int, gid: int
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL process status is invalid") from exc
    values: dict[str, tuple[int, ...]] = {}
    for line in lines:
        if line.startswith(("Uid:", "Gid:")):
            key, raw = line.split(":", 1)
            try:
                values[key] = tuple(int(item) for item in raw.split())
            except ValueError as exc:
                raise CapacityGateError("PostgreSQL process authority is invalid") from exc
    _require(
        len(values.get("Uid", ())) == 4 and set(values["Uid"]) == {uid},
        "PostgreSQL process UID mismatch",
    )
    _require(
        len(values.get("Gid", ())) == 4 and set(values["Gid"]) == {gid},
        "PostgreSQL process GID mismatch",
    )
    return values["Uid"], values["Gid"]


def _socket_listener_identity(
    postgresql: dict[str, Any], pid: int
) -> tuple[object, ...]:
    socket_path = (
        f"{postgresql['unix_socket_directories']}/.s.PGSQL.{postgresql['port']}"
    )
    payload = _read_live_bytes(
        Path("/proc/net/unix"), "Unix socket catalog", maximum=MAX_INPUT_BYTES
    )
    try:
        lines = payload.decode("utf-8").splitlines()[1:]
    except UnicodeDecodeError as exc:
        raise CapacityGateError("Unix socket catalog must be UTF-8") from exc
    listeners: list[str] = []
    for index, line in enumerate(lines):
        fields = line.split(None, 7)
        _require(len(fields) >= 7, f"Unix socket catalog row {index} is invalid")
        if (
            len(fields) == 8
            and fields[7] == socket_path
            and fields[3] == "00010000"
            and fields[4] == "0001"
            and fields[5] == "01"
        ):
            _text(fields[6], f"Unix socket catalog row {index} inode", pattern=DECIMAL)
            listeners.append(fields[6])
    _require(
        len(listeners) == 1,
        "PostgreSQL listener is missing or ambiguous in /proc/net/unix",
    )
    held: set[str] = set()
    try:
        with os.scandir(f"/proc/{pid}/fd") as descriptors:
            for descriptor in descriptors:
                try:
                    link = os.readlink(descriptor.path)
                except FileNotFoundError:
                    continue
                match = re.fullmatch(r"socket:\[([0-9]+)\]", link)
                if match is not None:
                    held.add(match.group(1))
    except OSError as exc:
        raise CapacityGateError(
            "PostgreSQL process file descriptors cannot be inspected"
        ) from exc
    _require(
        listeners[0] in held,
        "PostgreSQL service MainPID does not own the configured listener",
    )
    return (pid, socket_path, listeners[0])


def _verify_postgresql_socket_setting(postgresql: dict[str, Any]) -> tuple[str, str]:
    reviewed_directory = Path(postgresql["socket_directory"])
    setting_directory = Path(postgresql["unix_socket_directories"])
    try:
        reviewed_physical = reviewed_directory.resolve(strict=True)
        setting_physical = setting_directory.resolve(strict=True)
    except OSError as exc:
        raise CapacityGateError("PostgreSQL socket setting cannot be resolved") from exc
    _require(
        reviewed_physical == reviewed_directory,
        "reviewed PostgreSQL socket directory is not physical",
    )
    _require(
        setting_physical == reviewed_physical,
        "PostgreSQL socket setting does not resolve to the reviewed directory",
    )
    return str(setting_directory), str(reviewed_directory)


def _trusted_postgresql_file_identity(
    path: Path, uid: int, gid: int, label: str
) -> str:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CapacityGateError(f"{label} cannot be inspected") from exc
    _require(not path.is_symlink(), f"{label} must not be a symlink")
    _require(path.resolve(strict=True) == path, f"{label} path must be physical")
    _require(
        stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
        f"{label} identity is unsafe",
    )
    _require(
        before.st_uid in {0, uid}
        and before.st_gid in {0, gid}
        and before.st_mode & 0o022 == 0,
        f"{label} authority is unsafe",
    )
    ancestors = _trusted_postgresql_directory_chain(path.parent, uid, gid)
    payload = _read_live_bytes(path, label, maximum=MAX_INPUT_BYTES)
    after = path.lstat()
    fingerprint = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    _require(fingerprint(before) == fingerprint(after), f"{label} changed during capture")
    return _canonical_sha256(
        {
            "path": str(path),
            "content_sha256": hashlib.sha256(payload).hexdigest(),
            "metadata": fingerprint(after),
            "ancestors": ancestors,
        }
    )


def _process_namespace_identity(pid: int) -> str:
    identities: dict[str, dict[str, object]] = {}
    for namespace in ("mnt", "pid", "user"):
        process_path = Path(f"/proc/{pid}/ns/{namespace}")
        init_path = Path(f"/proc/1/ns/{namespace}")
        try:
            process_metadata = process_path.stat()
            init_metadata = init_path.stat()
            process_link = os.readlink(process_path)
            init_link = os.readlink(init_path)
        except OSError as exc:
            raise CapacityGateError(
                f"PostgreSQL {namespace} namespace cannot be inspected"
            ) from exc
        process_identity = (
            process_metadata.st_dev,
            process_metadata.st_ino,
            process_link,
        )
        init_identity = (init_metadata.st_dev, init_metadata.st_ino, init_link)
        _require(
            process_identity == init_identity,
            f"PostgreSQL process is outside the host {namespace} namespace",
        )
        identities[namespace] = {
            "device": process_metadata.st_dev,
            "inode": process_metadata.st_ino,
            "link": process_link,
        }
    return _canonical_sha256(identities)


def _postgresql_process_setting(argument: str) -> tuple[str, str]:
    _require(
        argument.count("=") >= 1,
        "PostgreSQL process command line has an ambiguous -c assignment",
    )
    name, setting = argument.split("=", 1)
    _require(
        re.fullmatch(r"[a-z_][a-z0-9_.]*", name) is not None,
        "PostgreSQL process command line has an ambiguous -c assignment",
    )
    return name, setting


def _validate_postgresql_process_arguments(
    arguments: object,
    *,
    data_directory: str | None = None,
    config_file: str | None = None,
) -> tuple[tuple[str, str], ...]:
    values = _exact_list(arguments, "PostgreSQL process command line", maximum=256)
    _require(
        bool(values)
        and all(isinstance(item, str) and "\0" not in item for item in values),
        "PostgreSQL process command line is invalid",
    )
    data_directories: list[str] = []
    settings: list[tuple[str, str]] = []
    index = 1
    while index < len(values):
        argument = values[index]
        _require(
            not (argument == "-o" or argument.startswith("-o")),
            "PostgreSQL process backend option passthrough is unsupported",
        )
        if argument == "-D":
            _require(
                index + 1 < len(values) and bool(values[index + 1]),
                "PostgreSQL process command line has an ambiguous -D option",
            )
            data_directories.append(values[index + 1])
            index += 2
            continue
        if argument.startswith("-D") and argument != "-D":
            data_directories.append(argument[2:])
            index += 1
            continue
        if argument.startswith("--pgdata"):
            _require(
                argument.startswith("--pgdata=") and bool(argument[9:]),
                "PostgreSQL process command line has an ambiguous --pgdata option",
            )
            data_directories.append(argument[9:])
            index += 1
            continue
        if argument == "-c":
            _require(
                index + 1 < len(values),
                "PostgreSQL process command line has an ambiguous -c assignment",
            )
            settings.append(_postgresql_process_setting(values[index + 1]))
            index += 2
            continue
        if argument.startswith("-c") and argument != "-c":
            settings.append(_postgresql_process_setting(argument[2:]))
            index += 1
            continue
        if argument.startswith("--"):
            raw = argument[2:]
            if "=" in raw:
                raw_name, raw_setting = raw.split("=", 1)
                normalized_name = raw_name.replace("-", "_").casefold()
                if (
                    normalized_name in POSTGRESQL_PRELOAD_SETTINGS
                    or normalized_name == "config_file"
                ):
                    settings.append(
                        _postgresql_process_setting(
                            f"{normalized_name}={raw_setting}"
                        )
                    )
            else:
                normalized_name = raw.replace("-", "_").casefold()
                _require(
                    normalized_name not in POSTGRESQL_PRELOAD_SETTINGS
                    and normalized_name != "config_file",
                    f"PostgreSQL process {normalized_name} command-line form is ambiguous",
                )
        index += 1

    for name, setting in settings:
        if name in POSTGRESQL_PRELOAD_SETTINGS:
            _require(
                setting == "",
                f"PostgreSQL process {name} must be empty",
            )

    if data_directory is not None:
        _require(
            data_directories == [data_directory],
            "PostgreSQL process command line does not uniquely bind the data directory",
        )
    if config_file is not None:
        configured = [setting for name, setting in settings if name == "config_file"]
        if configured:
            _require(
                configured == [config_file],
                "PostgreSQL process command line does not uniquely bind the configuration file",
            )
        else:
            _require(
                data_directory is not None
                and str(Path(data_directory) / "postgresql.conf") == config_file,
                "PostgreSQL process command line does not bind the configuration file",
            )
    return tuple(settings)


def _postgresql_process_environment(payload: bytes) -> tuple[tuple[str, str], ...]:
    _require(
        bool(payload) and payload.endswith(b"\0"),
        "PostgreSQL process environment is invalid",
    )
    try:
        raw_entries = [item.decode("utf-8") for item in payload[:-1].split(b"\0")]
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL process environment is invalid") from exc
    environment: dict[str, str] = {}
    for entry in raw_entries:
        _require(
            "=" in entry,
            "PostgreSQL process environment entry is invalid",
        )
        name, setting = entry.split("=", 1)
        _require(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None,
            "PostgreSQL process environment name is invalid",
        )
        _require(
            name not in environment,
            "PostgreSQL process environment contains a duplicate name",
        )
        environment[name] = setting
    for name in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
        _require(
            environment.get(name, "") == "",
            f"PostgreSQL process {name} must be empty",
        )
    return tuple(sorted(environment.items()))


def _verify_postgresql_process(
    postgresql: dict[str, Any], service: dict[str, str]
) -> dict[str, object]:
    account, group = _verify_postgresql_authority(postgresql)
    data_directory = Path(postgresql["data_directory"])
    try:
        directory_identity = _directory_identity(data_directory)
    except OSError as exc:
        raise CapacityGateError("PostgreSQL data directory cannot be inspected") from exc
    _require(
        directory_identity[2] == account.pw_uid
        and directory_identity[3] == group.gr_gid,
        "PostgreSQL data directory owner mismatch",
    )
    _require(
        directory_identity[4] & 0o027 == 0,
        "PostgreSQL data directory permissions are unsafe",
    )
    ancestors = _trusted_postgresql_directory_chain(
        data_directory.parent, account.pw_uid, group.gr_gid
    )
    pid_path = data_directory / "postmaster.pid"
    try:
        pid_metadata = pid_path.lstat()
    except OSError as exc:
        raise CapacityGateError("PostgreSQL postmaster.pid cannot be inspected") from exc
    _require(
        not pid_path.is_symlink()
        and stat.S_ISREG(pid_metadata.st_mode)
        and pid_metadata.st_nlink == 1,
        "PostgreSQL postmaster.pid identity is unsafe",
    )
    _require(
        pid_metadata.st_uid == account.pw_uid
        and pid_metadata.st_gid == group.gr_gid
        and pid_metadata.st_mode & 0o022 == 0,
        "PostgreSQL postmaster.pid authority is unsafe",
    )
    pid_payload = _read_live_bytes(pid_path, "PostgreSQL postmaster.pid", maximum=4096)
    try:
        pid_lines = pid_payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL postmaster.pid is invalid") from exc
    _require(len(pid_lines) >= 6, "PostgreSQL postmaster.pid is incomplete")
    for index in (0, 2, 3):
        _text(
            pid_lines[index],
            f"PostgreSQL postmaster.pid line {index + 1}",
            pattern=DECIMAL,
        )
    pid = int(pid_lines[0])
    _require(
        pid == int(service["MainPID"]),
        "PostgreSQL postmaster.pid does not match systemd MainPID",
    )
    _require(
        pid_lines[1] == postgresql["data_directory"],
        "PostgreSQL postmaster.pid data directory mismatch",
    )
    _require(
        int(pid_lines[3]) == postgresql["port"],
        "PostgreSQL postmaster.pid port mismatch",
    )
    _require(
        pid_lines[4] == postgresql["unix_socket_directories"],
        "PostgreSQL postmaster.pid socket setting mismatch",
    )
    _verify_postgresql_socket_setting(postgresql)
    process_directory = Path(f"/proc/{pid}")
    try:
        process_metadata = process_directory.stat()
        executable = (process_directory / "exe").resolve(strict=True)
    except OSError as exc:
        raise CapacityGateError("PostgreSQL MainPID cannot be inspected") from exc
    _require(
        str(executable) == postgresql["postgres_path"],
        "PostgreSQL MainPID executable mismatch",
    )
    uids, gids = _parse_proc_status(
        _read_live_bytes(process_directory / "status", "PostgreSQL process status"),
        account.pw_uid,
        group.gr_gid,
    )
    cmdline_payload = _read_live_bytes(
        process_directory / "cmdline",
        "PostgreSQL process command line",
        maximum=65_536,
    )
    try:
        arguments = [
            item.decode("utf-8") for item in cmdline_payload.rstrip(b"\0").split(b"\0")
        ]
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL process command line is invalid") from exc
    _validate_postgresql_process_arguments(
        arguments,
        data_directory=postgresql["data_directory"],
        config_file=postgresql["config_file"],
    )
    process_environment = _postgresql_process_environment(
        _read_live_bytes(
            process_directory / "environ",
            "PostgreSQL process environment",
            maximum=MAX_INPUT_BYTES,
        )
    )
    environment_values = dict(process_environment)
    _require(
        environment_values.get("PGDATA", postgresql["data_directory"])
        == postgresql["data_directory"],
        "PostgreSQL process PGDATA does not bind the data directory",
    )
    cgroup_payload = _read_live_bytes(
        process_directory / "cgroup",
        "PostgreSQL process cgroup",
        maximum=65_536,
    )
    try:
        cgroups = [
            line.rsplit(":", 1)[-1]
            for line in cgroup_payload.decode("utf-8").splitlines()
        ]
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL process cgroup is invalid") from exc
    _require(
        postgresql["expected_control_group"] in cgroups,
        "PostgreSQL process cgroup mismatch",
    )
    try:
        stat_payload = _read_live_bytes(
            process_directory / "stat", "PostgreSQL process stat", maximum=65_536
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL process stat is invalid") from exc
    closing = stat_payload.rfind(")")
    _require(closing > 0, "PostgreSQL process stat is invalid")
    stat_fields = stat_payload[closing + 2 :].split()
    _require(
        len(stat_fields) > 19 and DECIMAL.fullmatch(stat_fields[19]) is not None,
        "PostgreSQL process start time is invalid",
    )
    listener_identity = _socket_listener_identity(postgresql, pid)
    namespace_identity_sha256 = _process_namespace_identity(pid)
    config_identity_sha256 = _trusted_postgresql_file_identity(
        Path(postgresql["config_file"]),
        account.pw_uid,
        group.gr_gid,
        "PostgreSQL configuration file",
    )
    hba_identity_sha256 = _trusted_postgresql_file_identity(
        Path(postgresql["hba_file"]),
        account.pw_uid,
        group.gr_gid,
        "PostgreSQL HBA file",
    )
    _require(
        config_identity_sha256 == postgresql["config_file_identity_sha256"]
        and hba_identity_sha256 == postgresql["hba_file_identity_sha256"],
        "PostgreSQL configuration file identity mismatch",
    )
    pid_identity = (
        str(pid_path),
        pid_metadata.st_dev,
        pid_metadata.st_ino,
        pid_metadata.st_mode,
        pid_metadata.st_uid,
        pid_metadata.st_gid,
        pid_metadata.st_nlink,
        hashlib.sha256(pid_payload).hexdigest(),
    )
    process_identity = (
        pid,
        process_metadata.st_dev,
        process_metadata.st_ino,
        str(executable),
        uids,
        gids,
        tuple(arguments),
        process_environment,
        tuple(cgroups),
        stat_fields[19],
        listener_identity,
        namespace_identity_sha256,
    )
    return {
        "pid": pid,
        "postmaster_start_epoch": int(pid_lines[2]),
        "data_directory_identity_sha256": _canonical_sha256(
            (directory_identity, ancestors)
        ),
        "postmaster_pid_identity_sha256": _canonical_sha256(pid_identity),
        "process_identity_sha256": _canonical_sha256(process_identity),
        "namespace_identity_sha256": namespace_identity_sha256,
        "socket_listener_identity_sha256": _canonical_sha256(listener_identity),
        "config_file_identity_sha256": config_identity_sha256,
        "hba_file_identity_sha256": hba_identity_sha256,
    }


POSTGRESQL_BACKEND_HANDSHAKE_QUERY = (
    "SELECT pg_catalog.json_build_object("
    "'backend_pid',pg_catalog.pg_backend_pid())::pg_catalog.text"
)


def _validate_postgresql_backend_attestation(
    postgresql: dict[str, Any],
    postmaster: dict[str, Any],
    value: object,
) -> dict[str, Any]:
    attestation = _exact_object(
        value,
        {
            "backend_pid",
            "parent_pid",
            "executable",
            "control_group",
            "namespace_identity_sha256",
            "process_identity_sha256",
        },
        "PostgreSQL backend attestation",
    )
    backend_pid = _integer(
        attestation["backend_pid"],
        "PostgreSQL backend PID",
        minimum=2,
        maximum=2**31 - 1,
    )
    parent_pid = _integer(
        attestation["parent_pid"],
        "PostgreSQL backend parent PID",
        minimum=2,
        maximum=2**31 - 1,
    )
    _absolute_path(attestation["executable"], "PostgreSQL backend executable")
    _absolute_path(attestation["control_group"], "PostgreSQL backend control group")
    _hex64(
        attestation["namespace_identity_sha256"],
        "PostgreSQL backend namespace identity",
    )
    _hex64(
        attestation["process_identity_sha256"],
        "PostgreSQL backend process identity",
    )
    _require(
        backend_pid != postmaster["pid"]
        and parent_pid == postmaster["pid"]
        and attestation["executable"] == postgresql["postgres_path"]
        and attestation["control_group"] == postgresql["expected_control_group"]
        and attestation["namespace_identity_sha256"]
        == postmaster["namespace_identity_sha256"],
        "PostgreSQL backend is not a child of the reviewed postmaster",
    )
    return attestation


def _verify_postgresql_backend_process(
    postgresql: dict[str, Any],
    postmaster: dict[str, Any],
    backend_pid: int,
) -> dict[str, Any]:
    _integer(
        backend_pid,
        "PostgreSQL backend PID",
        minimum=2,
        maximum=2**31 - 1,
    )
    account, group = _verify_postgresql_authority(postgresql)
    process_directory = Path(f"/proc/{backend_pid}")
    try:
        process_metadata = process_directory.stat()
        executable = (process_directory / "exe").resolve(strict=True)
        stat_payload = _read_live_bytes(
            process_directory / "stat", "PostgreSQL backend stat", maximum=65_536
        ).decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CapacityGateError("PostgreSQL backend process cannot be inspected") from exc
    closing = stat_payload.rfind(")")
    _require(closing > 0, "PostgreSQL backend stat is invalid")
    stat_fields = stat_payload[closing + 2 :].split()
    _require(
        len(stat_fields) > 19
        and DECIMAL.fullmatch(stat_fields[1]) is not None
        and DECIMAL.fullmatch(stat_fields[19]) is not None,
        "PostgreSQL backend stat is incomplete",
    )
    parent_pid = int(stat_fields[1])
    uids, gids = _parse_proc_status(
        _read_live_bytes(process_directory / "status", "PostgreSQL backend status"),
        account.pw_uid,
        group.gr_gid,
    )
    cgroup_payload = _read_live_bytes(
        process_directory / "cgroup", "PostgreSQL backend cgroup", maximum=65_536
    )
    try:
        cgroups = [
            line.rsplit(":", 1)[-1]
            for line in cgroup_payload.decode("utf-8").splitlines()
        ]
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL backend cgroup is invalid") from exc
    _require(
        postgresql["expected_control_group"] in cgroups,
        "PostgreSQL backend cgroup mismatch",
    )
    namespace_identity = _process_namespace_identity(backend_pid)
    identity = {
        "backend_pid": backend_pid,
        "process_device": process_metadata.st_dev,
        "process_inode": process_metadata.st_ino,
        "parent_pid": parent_pid,
        "start_ticks": stat_fields[19],
        "executable": str(executable),
        "uids": uids,
        "gids": gids,
        "cgroups": cgroups,
        "namespace_identity_sha256": namespace_identity,
    }
    return _validate_postgresql_backend_attestation(
        postgresql,
        postmaster,
        {
            "backend_pid": backend_pid,
            "parent_pid": parent_pid,
            "executable": str(executable),
            "control_group": postgresql["expected_control_group"],
            "namespace_identity_sha256": namespace_identity,
            "process_identity_sha256": _canonical_sha256(identity),
        },
    )


def _run_pg_controldata(
    postgresql: dict[str, Any], *, deadline_ns: int | None
) -> str:
    payload = _run_read_only_command(
        [
            postgresql["runuser_path"],
            "-u",
            postgresql["run_as_user"],
            "--",
            postgresql["pg_controldata_path"],
            postgresql["data_directory"],
        ],
        environment=dict(READ_ONLY_COMMAND_ENVIRONMENT),
        deadline_ns=deadline_ns,
        label="read-only pg_controldata probe",
        stdout_limit=262_144,
    )
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CapacityGateError("pg_controldata output must be UTF-8") from exc
    identifiers = [
        line.split(":", 1)[1].strip()
        for line in lines
        if line.startswith("Database system identifier:")
    ]
    _require(
        len(identifiers) == 1,
        "pg_controldata system identifier is missing or ambiguous",
    )
    return _text(
        identifiers[0],
        "pg_controldata system identifier",
        pattern=SYSTEM_IDENTIFIER,
    )


def _trusted_postgresql_configuration_tree_identity(
    root: Path, uid: int, gid: int
) -> str:
    _require(root.is_absolute(), "PostgreSQL configuration tree path must be absolute")
    ancestors = _trusted_postgresql_directory_chain(root.parent, uid, gid)
    manifest: list[dict[str, object]] = []
    total_bytes = 0

    def visit(path: Path, relative_path: str) -> None:
        nonlocal total_bytes
        try:
            before = path.lstat()
        except OSError as exc:
            raise CapacityGateError("PostgreSQL configuration tree cannot be inspected") from exc
        _require(
            not stat.S_ISLNK(before.st_mode),
            f"PostgreSQL configuration tree contains a symlink: {path}",
        )
        _require(
            before.st_uid in {0, uid}
            and before.st_gid in {0, gid}
            and before.st_mode & 0o002 == 0
            and (before.st_mode & 0o020 == 0 or before.st_gid == gid),
            f"PostgreSQL configuration tree authority is unsafe: {path}",
        )
        entry = _resource_metadata_identity(path, before, relative_path=relative_path)
        if stat.S_ISREG(before.st_mode):
            _require(
                before.st_nlink == 1,
                f"PostgreSQL configuration tree contains a hard-linked file: {path}",
            )
            payload = _read_live_bytes(
                path, "PostgreSQL configuration tree file", maximum=MAX_INPUT_BYTES
            )
            total_bytes += len(payload)
            _require(
                total_bytes <= 64 * 1024 * 1024,
                "PostgreSQL configuration tree is too large",
            )
            entry["content_sha256"] = hashlib.sha256(payload).hexdigest()
        elif stat.S_ISDIR(before.st_mode):
            try:
                children = sorted(os.scandir(path), key=lambda child: child.name)
            except OSError as exc:
                raise CapacityGateError(
                    "PostgreSQL configuration tree cannot be enumerated"
                ) from exc
            for child in children:
                child_relative = (
                    child.name if relative_path == "." else f"{relative_path}/{child.name}"
                )
                visit(Path(child.path), child_relative)
            try:
                after = path.lstat()
            except OSError as exc:
                raise CapacityGateError(
                    "PostgreSQL configuration tree changed during capture"
                ) from exc
            _require(
                _resource_metadata_identity(path, before, relative_path=relative_path)
                == _resource_metadata_identity(path, after, relative_path=relative_path),
                "PostgreSQL configuration tree changed during capture",
            )
        else:
            raise CapacityGateError(
                f"PostgreSQL configuration tree contains an unsupported object: {path}"
            )
        manifest.append(entry)
        _require(
            len(manifest) <= 10_000,
            "PostgreSQL configuration tree has too many entries",
        )

    visit(root, ".")
    manifest.sort(key=lambda item: str(item["relative_path"]))
    return _canonical_sha256(
        {
            "root": str(root),
            "ancestors": ancestors,
            "entry_count": len(manifest),
            "total_regular_file_bytes": total_bytes,
            "entries": manifest,
        }
    )


POSTGRESQL_INCLUDE_DIRECTIVES = {"include", "include_if_exists", "include_dir"}
POSTGRESQL_PRELOAD_SETTINGS = {
    "shared_preload_libraries",
    "session_preload_libraries",
    "local_preload_libraries",
}


def _configuration_tokens(line: str, label: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True)
    lexer.commenters = "#"
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError as exc:
        raise CapacityGateError(f"{label} has invalid quoting") from exc


def _configuration_records(payload: bytes, kind: str) -> list[dict[str, object]]:
    _require(kind in {"postgresql", "hba", "ident"}, "configuration kind is invalid")
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CapacityGateError("PostgreSQL configuration must be UTF-8") from exc
    records: list[dict[str, object]] = []
    interesting = POSTGRESQL_INCLUDE_DIRECTIVES | POSTGRESQL_PRELOAD_SETTINGS
    for line_number, line in enumerate(lines, start=1):
        _require("\0" not in line, "PostgreSQL configuration contains NUL")
        if line.rstrip().endswith("\\"):
            raise CapacityGateError(
                "PostgreSQL configuration line continuations are unsupported"
            )
        first = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)", line)
        if first is None:
            continue
        name = first.group(1).lower()
        if kind == "postgresql" and name not in interesting:
            continue
        normalized_name = first.group(1).lower()
        remainder = line[first.end() :].lstrip()
        if remainder.startswith("="):
            remainder = remainder[1:].lstrip()
            _require(
                not remainder.startswith("="),
                f"PostgreSQL {kind} configuration line {line_number} has an ambiguous assignment",
            )
        values = _configuration_tokens(
            remainder, f"PostgreSQL {kind} configuration line {line_number}"
        )
        if normalized_name in POSTGRESQL_INCLUDE_DIRECTIVES:
            _require(
                len(values) == 1 and bool(values[0]),
                f"PostgreSQL {kind} include directive is invalid",
            )
            records.append(
                {
                    "record": "include",
                    "directive": normalized_name,
                    "target": values[0],
                    "line": line_number,
                }
            )
            continue
        if kind == "postgresql" and normalized_name in POSTGRESQL_PRELOAD_SETTINGS:
            _require(
                len(values) == 1,
                f"PostgreSQL {normalized_name} assignment is ambiguous",
            )
            records.append(
                {
                    "record": "preload",
                    "name": normalized_name,
                    "setting": values[0],
                    "line": line_number,
                }
            )
            continue
        if kind == "hba":
            for token in values:
                if any(part.startswith("@") for part in token.split(",")):
                    raise CapacityGateError(
                        "PostgreSQL HBA @ list files are unsupported"
                    )
    return records


def _normalized_reviewed_path(
    path: Path, reviewed_roots: tuple[Path, ...], label: str
) -> Path:
    _require(path.is_absolute(), f"{label} must be absolute")
    normalized = Path(os.path.normpath(str(path)))
    _require(
        any(normalized == root or normalized.is_relative_to(root) for root in reviewed_roots),
        f"{label} is outside reviewed roots",
    )
    return normalized


def _postgresql_include_graph(
    start_files: tuple[tuple[Path, str], ...],
    reviewed_roots: tuple[Path, ...],
) -> dict[str, object]:
    _require(bool(start_files) and bool(reviewed_roots), "configuration include graph is empty")
    roots = tuple(sorted((Path(os.path.normpath(str(root))) for root in reviewed_roots), key=str))
    for root in roots:
        _require(root.is_absolute(), "configuration reviewed root must be absolute")
        _require(root.is_dir() and not root.is_symlink(), "configuration reviewed root is unsafe")
    files: dict[tuple[str, str], dict[str, object]] = {}
    active: set[tuple[str, str]] = set()

    def visit(path: Path, kind: str, *, optional: bool = False) -> None:
        normalized = _normalized_reviewed_path(path, roots, "PostgreSQL include path")
        key = (str(normalized), kind)
        if not normalized.exists():
            _require(optional, f"required PostgreSQL include is absent: {normalized}")
            files.setdefault(
                key,
                {"path": str(normalized), "kind": kind, "state": "absent", "records": []},
            )
            return
        _require(not normalized.is_symlink(), f"PostgreSQL include is a symlink: {normalized}")
        _require(normalized.is_file(), f"PostgreSQL include is not a regular file: {normalized}")
        _require(key not in active, "PostgreSQL include graph contains a cycle")
        if key in files:
            return
        active.add(key)
        payload = _read_live_bytes(
            normalized, "PostgreSQL included configuration", maximum=MAX_INPUT_BYTES
        )
        parsed = _configuration_records(payload, kind)
        item: dict[str, object] = {
            "path": str(normalized),
            "kind": kind,
            "state": "regular_file",
            "content_sha256": hashlib.sha256(payload).hexdigest(),
            "records": [],
        }
        files[key] = item
        output_records: list[dict[str, object]] = []
        for record in parsed:
            if record["record"] == "preload":
                output_records.append(record)
                continue
            raw_target = Path(str(record["target"]))
            target = raw_target if raw_target.is_absolute() else normalized.parent / raw_target
            target = _normalized_reviewed_path(
                target, roots, "PostgreSQL include target"
            )
            edge = {**record, "target": str(target)}
            if record["directive"] == "include_dir":
                _require(
                    target.exists() and target.is_dir() and not target.is_symlink(),
                    f"PostgreSQL include directory is unsafe: {target}",
                )
                children = [
                    child
                    for child in sorted(target.iterdir(), key=lambda value: value.name)
                    if not child.name.startswith(".") and child.name.endswith(".conf")
                ]
                edge["children"] = [str(child) for child in children]
                for child in children:
                    visit(child, kind)
            else:
                visit(
                    target,
                    kind,
                    optional=record["directive"] == "include_if_exists",
                )
                edge["state"] = "regular_file" if target.exists() else "absent"
            output_records.append(edge)
        item["records"] = output_records
        active.remove(key)

    for path, kind in sorted(start_files, key=lambda item: (item[1], str(item[0]))):
        visit(path, kind)
    return {
        "reviewed_roots": [str(root) for root in roots],
        "start_files": [
            {"path": str(path), "kind": kind}
            for path, kind in sorted(start_files, key=lambda item: (item[1], str(item[0])))
        ],
        "files": [files[key] for key in sorted(files)],
    }


def _postgresql_include_graph_identity(
    start_files: tuple[tuple[Path, str], ...],
    reviewed_roots: tuple[Path, ...],
) -> str:
    return _canonical_sha256(_postgresql_include_graph(start_files, reviewed_roots))


def _assert_configuration_graph_has_no_preloads(graph: dict[str, object]) -> None:
    for item in graph["files"]:
        for record in item["records"]:
            if record.get("record") == "preload":
                _require(
                    record.get("setting") == "",
                    f"PostgreSQL configuration source enables {record.get('name')}",
                )


def _postgresql_external_asset_specs(
    settings: dict[str, object], hba_rules: list[object]
) -> list[tuple[str, Path, str]]:
    data_directory = Path(str(settings.get("data_directory", "")))
    _require(data_directory.is_absolute(), "PostgreSQL data directory setting is invalid")
    passphrase_command = settings.get("ssl_passphrase_command")
    _require(
        passphrase_command is None or passphrase_command == "",
        "PostgreSQL SSL passphrase commands are unsupported",
    )
    specs: list[tuple[str, Path, str]] = []

    def configured_path(name: str) -> Path | None:
        raw = settings.get(name)
        _require(isinstance(raw, str), f"PostgreSQL {name} setting is invalid")
        if not raw:
            return None
        value = Path(raw)
        return value if value.is_absolute() else data_directory / value

    if settings.get("ssl") == "on":
        for name in (
            "ssl_cert_file",
            "ssl_key_file",
            "ssl_ca_file",
            "ssl_crl_file",
            "ssl_dh_params_file",
        ):
            path = configured_path(name)
            if path is not None:
                specs.append(("regular_file", path, name))
        crl_directory = configured_path("ssl_crl_dir")
        if crl_directory is not None:
            specs.append(("directory_tree", crl_directory, "ssl_crl_dir"))
    methods = {
        item.get("auth_method")
        for item in hba_rules
        if isinstance(item, dict) and item.get("error") is None
    }
    unsupported = methods & {
        "pam", "bsd", "ldap", "radius", "gss", "sspi", "ident", "trust"
    }
    _require(
        not unsupported,
        "PostgreSQL external authentication methods are unsupported: "
        + ",".join(sorted(str(item) for item in unsupported)),
    )
    return sorted(specs, key=lambda item: (item[0], str(item[1]), item[2]))


def _assert_configuration_path_loaded(
    path: Path, *, load_time_epoch_microseconds: int, recursive: bool, label: str
) -> None:
    threshold_ns = load_time_epoch_microseconds * 1000

    def visit(item: Path) -> None:
        try:
            metadata = item.lstat()
        except OSError as exc:
            raise CapacityGateError(f"{label} cannot be inspected") from exc
        _require(not stat.S_ISLNK(metadata.st_mode), f"{label} contains a symlink")
        _require(
            metadata.st_mtime_ns <= threshold_ns and metadata.st_ctime_ns <= threshold_ns,
            f"{label} is newer than PostgreSQL configuration load time",
        )
        if stat.S_ISDIR(metadata.st_mode):
            _require(recursive, f"{label} unexpectedly names a directory")
            for child in sorted(item.iterdir(), key=lambda value: value.name):
                visit(child)
        else:
            _require(stat.S_ISREG(metadata.st_mode), f"{label} is not a regular file")

    visit(path)


def _trusted_postgresql_external_asset_identity(
    kind: str,
    path: Path,
    label: str,
    account: Any,
) -> str:
    try:
        metadata = path.lstat()
        allowed_gids = set(os.getgrouplist(account.pw_name, account.pw_gid)) | {0}
    except OSError as exc:
        raise CapacityGateError(f"PostgreSQL external asset is unavailable: {label}") from exc
    _require(
        metadata.st_gid in allowed_gids,
        f"PostgreSQL external asset group is not bound to the service: {label}",
    )
    if kind == "regular_file":
        return _trusted_postgresql_file_identity(
            path, account.pw_uid, metadata.st_gid, f"PostgreSQL {label}"
        )
    _require(kind == "directory_tree", "PostgreSQL external asset kind is invalid")
    return _trusted_postgresql_configuration_tree_identity(
        path, account.pw_uid, metadata.st_gid
    )


POSTGRESQL_CONFIGURATION_QUERY = (
    "SELECT pg_catalog.jsonb_build_object("
    "'configuration_load_identity',pg_catalog.jsonb_build_array("
    "pg_catalog.jsonb_build_object('load_time_epoch_microseconds',"
    "pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.pg_conf_load_time()) "
    "* 1000000)::pg_catalog.int8)),"
    "'settings',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(s) "
    "ORDER BY s.name) FROM pg_catalog.pg_settings AS s),'[]'::pg_catalog.jsonb),"
    "'file_settings',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(f) "
    "ORDER BY f.seqno) FROM pg_catalog.pg_file_settings AS f),'[]'::pg_catalog.jsonb),"
    "'hba_rules',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(h) "
    "ORDER BY pg_catalog.to_jsonb(h)::pg_catalog.text) "
    "FROM pg_catalog.pg_hba_file_rules AS h),'[]'::pg_catalog.jsonb),"
    "'ident_mappings',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(i) "
    "ORDER BY pg_catalog.to_jsonb(i)::pg_catalog.text) "
    "FROM pg_catalog.pg_ident_file_mappings AS i),'[]'::pg_catalog.jsonb),"
    "'db_role_settings',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(d) "
    "ORDER BY d.setdatabase,d.setrole) FROM pg_catalog.pg_db_role_setting AS d),"
    "'[]'::pg_catalog.jsonb),"
    "'roles',COALESCE((SELECT pg_catalog.jsonb_agg("
    "pg_catalog.jsonb_build_object("
    "'oid',r.oid::pg_catalog.text,'rolname',r.rolname,"
    "'rolsuper',r.rolsuper,'rolinherit',r.rolinherit,"
    "'rolcreaterole',r.rolcreaterole,'rolcreatedb',r.rolcreatedb,"
    "'rolcanlogin',r.rolcanlogin,'rolreplication',r.rolreplication,"
    "'rolconnlimit',r.rolconnlimit,'rolvaliduntil',r.rolvaliduntil,"
    "'rolbypassrls',r.rolbypassrls) "
    "ORDER BY r.rolname) FROM pg_catalog.pg_authid AS r),"
    "'[]'::pg_catalog.jsonb),"
    "'role_password_identity',pg_catalog.jsonb_build_array((SELECT "
    "pg_catalog.jsonb_build_object("
    "'role_count',pg_catalog.count(*),"
    "'role_password_vector_sha256',pg_catalog.encode(pg_catalog.sha256("
    "pg_catalog.convert_to(COALESCE(pg_catalog.jsonb_agg("
    "pg_catalog.jsonb_build_array(r.oid::pg_catalog.text,r.rolname::pg_catalog.text,"
    "r.rolpassword) ORDER BY r.rolname)::pg_catalog.text,'[]'),"
    "'UTF8')),'hex')) FROM pg_catalog.pg_authid AS r)),"
    "'role_memberships',COALESCE((SELECT pg_catalog.jsonb_agg(pg_catalog.to_jsonb(m) "
    "ORDER BY m.roleid,m.member,m.grantor) FROM pg_catalog.pg_auth_members AS m),"
    "'[]'::pg_catalog.jsonb))::pg_catalog.text"
)


def _capture_postgresql_configuration(
    postgresql: dict[str, Any],
    *,
    deadline_ns: int | None,
    postmaster: dict[str, Any] | None = None,
) -> str:
    probe_options: dict[str, Any] = {"deadline_ns": deadline_ns}
    if postmaster is not None:
        probe_options.update(
            {"postmaster": postmaster, "cluster_postgresql": postgresql}
        )
    rows = _run_psql(
        postgresql,
        postgresql["maintenance_database"],
        POSTGRESQL_CONFIGURATION_QUERY,
        **probe_options,
    )
    _require(len(rows) == 1, "PostgreSQL configuration snapshot row count is invalid")
    semantic = _exact_object(
        rows[0],
        CONFIGURATION_SNAPSHOT_COMPONENTS - {"configuration_files"},
        "PostgreSQL semantic configuration snapshot",
    )
    for component in CONFIGURATION_SNAPSHOT_COMPONENTS - {"configuration_files"}:
        _exact_list(
            semantic[component],
            f"PostgreSQL semantic configuration {component.replace('_', ' ')}",
            maximum=100_000,
        )
    _require(bool(semantic["settings"]), "PostgreSQL settings snapshot is empty")
    account, group = _verify_postgresql_authority(postgresql)
    settings_by_name: dict[str, object] = {}
    for index, item in enumerate(semantic["settings"]):
        _require(
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and isinstance(item.get("setting"), str),
            f"PostgreSQL semantic setting {index} is invalid",
        )
        normalized_name = item["name"].casefold()
        _require(
            normalized_name not in settings_by_name,
            "PostgreSQL semantic setting names are duplicated",
        )
        settings_by_name[normalized_name] = item["setting"]
    load_identity = semantic["configuration_load_identity"]
    _require(
        isinstance(load_identity, list)
        and len(load_identity) == 1
        and isinstance(load_identity[0], dict),
        "PostgreSQL configuration load identity is invalid",
    )
    load_time_epoch_microseconds = _integer(
        load_identity[0].get("load_time_epoch_microseconds"),
        "PostgreSQL configuration load time",
        minimum=1,
        maximum=MAX_INTEGER,
    )
    ident_file = settings_by_name.get("ident_file")
    _absolute_path(ident_file, "PostgreSQL ident file")
    base_directories = sorted(
        {
            str(Path(postgresql["config_file"]).parent),
            str(Path(postgresql["hba_file"]).parent),
            str(Path(ident_file).parent),
        }
    )
    configuration_files: list[dict[str, object]] = [
        {
            "kind": "directory_tree",
            "path": directory,
            "identity_sha256": _trusted_postgresql_configuration_tree_identity(
                Path(directory), account.pw_uid, group.gr_gid
            ),
        }
        for directory in base_directories
    ]
    start_files = (
        (Path(postgresql["config_file"]), "postgresql"),
        (Path(postgresql["hba_file"]), "hba"),
        (Path(ident_file), "ident"),
    )
    reviewed_roots = tuple(Path(directory) for directory in base_directories)
    include_graph = _postgresql_include_graph(start_files, reviewed_roots)
    _assert_configuration_graph_has_no_preloads(include_graph)
    configuration_files.append(
        {
            "kind": "include_graph",
            "path": postgresql["config_file"],
            "identity_sha256": _canonical_sha256(include_graph),
        }
    )
    for directory in reviewed_roots:
        _assert_configuration_path_loaded(
            directory,
            load_time_epoch_microseconds=load_time_epoch_microseconds,
            recursive=True,
            label="PostgreSQL reviewed configuration tree",
        )
    auto_conf = Path(postgresql["data_directory"]) / "postgresql.auto.conf"
    auto_payload = _read_live_bytes(
        auto_conf, "PostgreSQL auto configuration file", maximum=MAX_INPUT_BYTES
    )
    auto_records = _configuration_records(auto_payload, "postgresql")
    _require(
        not any(record["record"] == "include" for record in auto_records),
        "PostgreSQL auto configuration includes are unsupported",
    )
    _assert_configuration_graph_has_no_preloads(
        {"files": [{"records": auto_records}]}
    )
    _assert_configuration_path_loaded(
        auto_conf,
        load_time_epoch_microseconds=load_time_epoch_microseconds,
        recursive=False,
        label="PostgreSQL auto configuration file",
    )
    configuration_files.append(
        {
            "kind": "regular_file",
            "path": str(auto_conf),
            "identity_sha256": _trusted_postgresql_file_identity(
                auto_conf,
                account.pw_uid,
                group.gr_gid,
                "PostgreSQL auto configuration file",
            ),
        }
    )
    exposed_paths: set[str] = set()
    for component in ("file_settings", "hba_rules", "ident_mappings"):
        for item in semantic[component]:
            _require(
                isinstance(item, dict),
                f"PostgreSQL {component.replace('_', ' ')} entry is invalid",
            )
            for field in ("sourcefile", "file_name"):
                candidate = item.get(field)
                if candidate is not None:
                    _absolute_path(candidate, f"PostgreSQL {component} source file")
                    exposed_paths.add(candidate)
    for source_path in sorted(exposed_paths):
        within_reviewed_root = any(
            Path(source_path) == Path(directory)
            or Path(source_path).is_relative_to(Path(directory))
            for directory in base_directories
        )
        _require(
            within_reviewed_root,
            "PostgreSQL semantic configuration source is outside reviewed roots",
        )
    for kind, path, label in _postgresql_external_asset_specs(
        settings_by_name, semantic["hba_rules"]
    ):
        _assert_configuration_path_loaded(
            path,
            load_time_epoch_microseconds=load_time_epoch_microseconds,
            recursive=kind == "directory_tree",
            label=f"PostgreSQL {label}",
        )
        configuration_files.append(
            {
                "kind": kind,
                "path": str(path),
                "identity_sha256": _trusted_postgresql_external_asset_identity(
                    kind, path, label, account
                ),
            }
        )
    configuration_files.sort(key=lambda item: (str(item["path"]), str(item["kind"])))
    snapshot = {"configuration_files": configuration_files, **semantic}
    return _postgresql_configuration_identity(snapshot)


def _preflight_postgresql_preload_configuration(
    postgresql: dict[str, Any],
) -> None:
    config_file = Path(postgresql["config_file"])
    reviewed_root = config_file.parent
    graph = _postgresql_include_graph(
        ((config_file, "postgresql"),), (reviewed_root,)
    )
    _assert_configuration_graph_has_no_preloads(graph)
    auto_conf = Path(postgresql["data_directory"]) / "postgresql.auto.conf"
    records = _configuration_records(
        _read_live_bytes(
            auto_conf, "PostgreSQL auto configuration file", maximum=MAX_INPUT_BYTES
        ),
        "postgresql",
    )
    _require(
        not any(record["record"] == "include" for record in records),
        "PostgreSQL auto configuration includes are unsupported",
    )
    _assert_configuration_graph_has_no_preloads(
        {"files": [{"records": records}]}
    )


def _capture_system_probe(
    postgresql: dict[str, Any],
    *,
    deadline_ns: int | None,
    postmaster: dict[str, Any] | None = None,
) -> dict[str, Any]:
    probe_options: dict[str, Any] = {"deadline_ns": deadline_ns}
    if postmaster is not None:
        probe_options.update(
            {"postmaster": postmaster, "cluster_postgresql": postgresql}
        )
    rows = _run_psql(
        postgresql,
        postgresql["maintenance_database"],
        "SELECT pg_catalog.json_build_object("
        "'read_only',pg_catalog.current_setting('transaction_read_only'),"
        "'database_user',SESSION_USER,'database_current_user',CURRENT_USER,"
        "'database_user_is_superuser',u.rolsuper,"
        "'database_user_bypass_rls',u.rolbypassrls,"
        "'system_identifier',control.system_identifier::pg_catalog.text,"
        "'data_directory',pg_catalog.current_setting('data_directory'),"
        "'config_file',pg_catalog.current_setting('config_file'),"
        "'hba_file',pg_catalog.current_setting('hba_file'),"
        "'unix_socket_directories',pg_catalog.current_setting('unix_socket_directories'),"
        "'port',pg_catalog.current_setting('port')::pg_catalog.int4,"
        "'server_version_num',pg_catalog.current_setting('server_version_num')::pg_catalog.int4,"
        "'in_recovery',pg_catalog.pg_is_in_recovery(),"
        "'postmaster_started_at',pg_catalog.to_char("
        "pg_catalog.pg_postmaster_start_time() AT TIME ZONE 'UTC',"
        "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'))::pg_catalog.text "
        "FROM pg_catalog.pg_control_system() AS control "
        "JOIN pg_catalog.pg_roles AS u "
        "ON u.rolname OPERATOR(pg_catalog.=) SESSION_USER",
        **probe_options,
    )
    fields = {
        "read_only",
        "database_user",
        "database_current_user",
        "database_user_is_superuser",
        "database_user_bypass_rls",
        "system_identifier",
        "data_directory",
        "config_file",
        "hba_file",
        "unix_socket_directories",
        "port",
        "server_version_num",
        "in_recovery",
        "postmaster_started_at",
    }
    _require(len(rows) == 1, "PostgreSQL system probe row count is invalid")
    system = _exact_object(rows[0], fields, "PostgreSQL system probe")
    _require(system["read_only"] == "on", "PostgreSQL system probe was not read-only")
    for field in ("database_user", "database_current_user"):
        _text(system[field], f"PostgreSQL observed {field.replace('_', ' ')}", pattern=SQL_ROLE)
        _require(
            system[field] == postgresql["database_user"],
            f"PostgreSQL system probe {field} mismatch",
        )
    for field, policy_field in (
        ("database_user_is_superuser", "database_user_is_superuser"),
        ("database_user_bypass_rls", "database_user_bypass_rls"),
    ):
        _boolean(system[field], f"PostgreSQL observed {field.replace('_', ' ')}")
        _require(
            system[field] == postgresql[policy_field],
            f"PostgreSQL system probe {field} mismatch",
        )
    _text(
        system["system_identifier"],
        "PostgreSQL observed system identifier",
        pattern=SYSTEM_IDENTIFIER,
    )
    for field in ("data_directory", "config_file", "hba_file"):
        _absolute_path(system[field], f"PostgreSQL observed {field.replace('_', ' ')}")
    _absolute_path(
        system["unix_socket_directories"], "PostgreSQL observed socket setting"
    )
    _integer(system["port"], "PostgreSQL observed port", minimum=1, maximum=65_535)
    _integer(
        system["server_version_num"],
        "PostgreSQL observed server version",
        minimum=10000,
        maximum=999999,
    )
    _boolean(system["in_recovery"], "PostgreSQL observed recovery state")
    _timestamp(
        system["postmaster_started_at"],
        "PostgreSQL observed postmaster start time",
    )
    for field, expected_field in (
        ("system_identifier", "system_identifier"),
        ("data_directory", "data_directory"),
        ("config_file", "config_file"),
        ("hba_file", "hba_file"),
        ("unix_socket_directories", "unix_socket_directories"),
        ("port", "port"),
        ("server_version_num", "server_version_num"),
        ("in_recovery", "expected_in_recovery"),
    ):
        _require(
            system[field] == postgresql[expected_field],
            f"PostgreSQL system probe {field} mismatch",
        )
    return system


def _capture_catalog(
    postgresql: dict[str, Any],
    *,
    deadline_ns: int | None,
    postmaster: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    probe_options: dict[str, Any] = {"deadline_ns": deadline_ns}
    if postmaster is not None:
        probe_options.update(
            {"postmaster": postmaster, "cluster_postgresql": postgresql}
        )
    rows = _run_psql(
        postgresql,
        postgresql["maintenance_database"],
        "SELECT pg_catalog.json_build_object("
        "'oid',d.oid::pg_catalog.text,'name',d.datname,'allow_connections',d.datallowconn,"
        "'is_template',d.datistemplate,'owner',r.rolname,"
        "'tablespace_oid',d.dattablespace::pg_catalog.text,"
        "'size_bytes',pg_catalog.pg_database_size(d.oid))::pg_catalog.text "
        "FROM pg_catalog.pg_database AS d "
        "JOIN pg_catalog.pg_roles AS r ON r.oid OPERATOR(pg_catalog.=) d.datdba "
        "ORDER BY d.datname",
        **probe_options,
    )
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    oids: set[str] = set()
    for index, row in enumerate(rows):
        item = _exact_object(
            row,
            {
                "oid",
                "name",
                "allow_connections",
                "is_template",
                "owner",
                "tablespace_oid",
                "size_bytes",
            },
            f"PostgreSQL catalog row {index}",
        )
        oid = _text(
            item["oid"], f"PostgreSQL catalog row {index} OID", pattern=DECIMAL
        )
        name = _text(
            item["name"],
            f"PostgreSQL catalog row {index} name",
            pattern=DATABASE_NAME,
        )
        _boolean(
            item["allow_connections"],
            f"PostgreSQL catalog row {index} connectivity",
        )
        _boolean(
            item["is_template"], f"PostgreSQL catalog row {index} template state"
        )
        _text(
            item["owner"],
            f"PostgreSQL catalog row {index} owner",
            pattern=SQL_ROLE,
        )
        _text(
            item["tablespace_oid"],
            f"PostgreSQL catalog row {index} tablespace",
            pattern=DECIMAL,
        )
        _integer(item["size_bytes"], f"PostgreSQL catalog row {index} size")
        _require(
            name not in names and oid not in oids,
            "PostgreSQL catalog identities are not unique",
        )
        names.add(name)
        oids.add(oid)
        result.append(item)
    _require(bool(result), "PostgreSQL catalog is empty")
    _require(
        [item["name"] for item in result]
        == sorted(item["name"] for item in result),
        "PostgreSQL catalog is not deterministically ordered",
    )
    return result


UUID_RELATION_IDENTITY_CTE = (
    "relation_identity AS (SELECT "
    "pg_catalog.jsonb_build_object("
    "'database_name',d.datname,"
    "'database_oid',d.oid::pg_catalog.text,"
    "'database_owner',database_owner.rolname,"
    "'schema_name',n.nspname,"
    "'schema_oid',n.oid::pg_catalog.text,"
    "'schema_owner',schema_owner.rolname,"
    "'relation_name',c.relname,"
    "'relation_oid',c.oid::pg_catalog.text,"
    "'relation_filenode',c.relfilenode::pg_catalog.text,"
    "'tablespace_oid',c.reltablespace::pg_catalog.text,"
    "'access_method',am.amname,"
    "'relation_kind',c.relkind::pg_catalog.text,"
    "'persistence',c.relpersistence::pg_catalog.text,"
    "'row_security',c.relrowsecurity,"
    "'force_row_security',c.relforcerowsecurity,"
    "'has_rules',c.relhasrules,"
    "'is_partition',c.relispartition,"
    "'relation_owner',relation_owner.rolname,"
    "'relation_owner_is_superuser',relation_owner.rolsuper,"
    "'relation_owner_bypass_rls',relation_owner.rolbypassrls,"
    "'relation_owner_can_login',relation_owner.rolcanlogin,"
    "'relation_owner_create_role',relation_owner.rolcreaterole,"
    "'relation_owner_createdb',relation_owner.rolcreatedb,"
    "'relation_owner_replication',relation_owner.rolreplication,"
    "'relation_owner_membership_count',(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_auth_members AS membership "
    "WHERE membership.member OPERATOR(pg_catalog.=) relation_owner.oid),"
    "'parent_count',(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_inherits AS parent_link "
    "WHERE parent_link.inhrelid OPERATOR(pg_catalog.=) c.oid),"
    "'child_count',(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_inherits AS child_link "
    "WHERE child_link.inhparent OPERATOR(pg_catalog.=) c.oid),"
    "'check_constraint_count',(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_constraint AS check_constraint "
    "WHERE check_constraint.conrelid OPERATOR(pg_catalog.=) c.oid "
    "AND check_constraint.contype::pg_catalog.text "
    "OPERATOR(pg_catalog.=) 'c'::pg_catalog.text),"
    "'indexes',(SELECT COALESCE(pg_catalog.jsonb_agg("
    "pg_catalog.jsonb_build_object("
    "'name',index_relation.relname,"
    "'oid',index_relation.oid::pg_catalog.text,"
    "'filenode',index_relation.relfilenode::pg_catalog.text,"
    "'owner',index_owner.rolname,"
    "'access_method',index_am.amname,"
    "'valid',index_metadata.indisvalid,"
    "'ready',index_metadata.indisready,"
    "'live',index_metadata.indislive,"
    "'unique',index_metadata.indisunique,"
    "'primary',index_metadata.indisprimary,"
    "'exclusion',index_metadata.indisexclusion,"
    "'immediate',index_metadata.indimmediate,"
    "'key_attribute_numbers',index_metadata.indkey::pg_catalog.text,"
    "'opclass_oids',index_metadata.indclass::pg_catalog.text,"
    "'collation_oids',index_metadata.indcollation::pg_catalog.text,"
    "'options',index_metadata.indoption::pg_catalog.text,"
    "'has_expressions',index_metadata.indexprs IS NOT NULL,"
    "'has_predicate',index_metadata.indpred IS NOT NULL,"
    "'all_opclasses_in_pg_catalog',NOT EXISTS(SELECT 1 "
    "FROM pg_catalog.unnest(index_metadata.indclass::pg_catalog.oid[]) "
    "AS class_oid "
    "LEFT JOIN pg_catalog.pg_opclass AS operator_class "
    "ON operator_class.oid OPERATOR(pg_catalog.=) class_oid "
    "LEFT JOIN pg_catalog.pg_namespace AS operator_namespace "
    "ON operator_namespace.oid OPERATOR(pg_catalog.=) operator_class.opcnamespace "
    "WHERE class_oid OPERATOR(pg_catalog.<>) 0 "
    "AND (operator_class.oid IS NULL OR operator_namespace.nspname "
    "OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.name))) "
    "ORDER BY index_relation.oid), '[]'::pg_catalog.jsonb) "
    "FROM pg_catalog.pg_index AS index_metadata "
    "JOIN pg_catalog.pg_class AS index_relation "
    "ON index_relation.oid OPERATOR(pg_catalog.=) index_metadata.indexrelid "
    "JOIN pg_catalog.pg_roles AS index_owner "
    "ON index_owner.oid OPERATOR(pg_catalog.=) index_relation.relowner "
    "JOIN pg_catalog.pg_am AS index_am "
    "ON index_am.oid OPERATOR(pg_catalog.=) index_relation.relam "
    "WHERE index_metadata.indrelid OPERATOR(pg_catalog.=) c.oid),"
    "'statistics',(SELECT COALESCE(pg_catalog.jsonb_agg("
    "pg_catalog.jsonb_build_object("
    "'name',statistics.stxname,"
    "'oid',statistics.oid::pg_catalog.text,"
    "'owner',statistics_owner.rolname,"
    "'keys',statistics.stxkeys::pg_catalog.text,"
    "'kinds',statistics.stxkind,"
    "'has_expressions',statistics.stxexprs IS NOT NULL) "
    "ORDER BY statistics.oid), '[]'::pg_catalog.jsonb) "
    "FROM pg_catalog.pg_statistic_ext AS statistics "
    "JOIN pg_catalog.pg_roles AS statistics_owner "
    "ON statistics_owner.oid OPERATOR(pg_catalog.=) statistics.stxowner "
    "WHERE statistics.stxrelid OPERATOR(pg_catalog.=) c.oid),"
    "'columns',(SELECT pg_catalog.jsonb_agg("
    "pg_catalog.jsonb_build_object("
    "'attnum',a.attnum::pg_catalog.int4,"
    "'name',a.attname,"
    "'type_oid',a.atttypid::pg_catalog.text,"
    "'type_modifier',a.atttypmod::pg_catalog.int4,"
    "'not_null',a.attnotnull,"
    "'generated',a.attgenerated::pg_catalog.text,"
    "'identity',a.attidentity::pg_catalog.text,"
    "'collation_oid',a.attcollation::pg_catalog.text) ORDER BY a.attnum) "
    "FROM pg_catalog.pg_attribute AS a "
    "WHERE a.attrelid OPERATOR(pg_catalog.=) c.oid "
    "AND a.attnum OPERATOR(pg_catalog.>) 0 "
    "AND NOT a.attisdropped)) AS payload,"
    "c.relkind::pg_catalog.text AS relation_kind,"
    "c.relpersistence::pg_catalog.text AS persistence,"
    "c.relrowsecurity AS row_security,"
    "c.relforcerowsecurity AS force_row_security,"
    "c.relhasrules AS has_rules,"
    "c.relispartition AS is_partition,"
    "am.amname AS access_method,"
    "relation_owner.rolname AS relation_owner,"
    "relation_owner.rolsuper AS relation_owner_is_superuser,"
    "relation_owner.rolbypassrls AS relation_owner_bypass_rls,"
    "relation_owner.rolcanlogin AS relation_owner_can_login,"
    "relation_owner.rolcreaterole AS relation_owner_create_role,"
    "relation_owner.rolreplication AS relation_owner_replication,"
    "database_owner.rolname AS database_owner,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_auth_members AS membership "
    "WHERE membership.member OPERATOR(pg_catalog.=) relation_owner.oid) "
    "AS relation_owner_membership_count,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_inherits AS parent_link "
    "WHERE parent_link.inhrelid OPERATOR(pg_catalog.=) c.oid) AS parent_count,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_inherits AS child_link "
    "WHERE child_link.inhparent OPERATOR(pg_catalog.=) c.oid) AS child_count,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_constraint AS check_constraint "
    "WHERE check_constraint.conrelid OPERATOR(pg_catalog.=) c.oid "
    "AND check_constraint.contype::pg_catalog.text "
    "OPERATOR(pg_catalog.=) 'c'::pg_catalog.text) AS check_constraint_count,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_index AS unsafe_index "
    "JOIN pg_catalog.pg_class AS unsafe_index_relation "
    "ON unsafe_index_relation.oid OPERATOR(pg_catalog.=) unsafe_index.indexrelid "
    "JOIN pg_catalog.pg_am AS unsafe_index_am "
    "ON unsafe_index_am.oid OPERATOR(pg_catalog.=) unsafe_index_relation.relam "
    "WHERE unsafe_index.indrelid OPERATOR(pg_catalog.=) c.oid "
    "AND (unsafe_index.indexprs IS NOT NULL OR unsafe_index.indpred IS NOT NULL "
    "OR NOT unsafe_index.indisvalid OR NOT unsafe_index.indisready "
    "OR NOT unsafe_index.indislive OR unsafe_index_am.amname "
    "OPERATOR(pg_catalog.<>) 'btree'::pg_catalog.name "
    "OR unsafe_index_relation.relowner OPERATOR(pg_catalog.<>) c.relowner "
    "OR EXISTS(SELECT 1 "
    "FROM pg_catalog.unnest(unsafe_index.indclass::pg_catalog.oid[]) AS class_oid "
    "LEFT JOIN pg_catalog.pg_opclass AS operator_class "
    "ON operator_class.oid OPERATOR(pg_catalog.=) class_oid "
    "LEFT JOIN pg_catalog.pg_namespace AS operator_namespace "
    "ON operator_namespace.oid OPERATOR(pg_catalog.=) operator_class.opcnamespace "
    "WHERE class_oid OPERATOR(pg_catalog.<>) 0 "
    "AND (operator_class.oid IS NULL OR operator_namespace.nspname "
    "OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.name)))) "
    "AS unsafe_index_count,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_statistic_ext AS expression_statistics "
    "WHERE expression_statistics.stxrelid OPERATOR(pg_catalog.=) c.oid "
    "AND expression_statistics.stxexprs IS NOT NULL) "
    "AS expression_statistics_count,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_attribute AS key_column "
    "WHERE key_column.attrelid OPERATOR(pg_catalog.=) c.oid "
    "AND key_column.attnum OPERATOR(pg_catalog.>) 0 "
    "AND NOT key_column.attisdropped "
    "AND key_column.attname OPERATOR(pg_catalog.=) 'key'::pg_catalog.name "
    "AND key_column.atttypid OPERATOR(pg_catalog.=) '1043'::pg_catalog.oid "
    "AND key_column.attgenerated::pg_catalog.text "
    "OPERATOR(pg_catalog.=) ''::pg_catalog.text "
    "AND key_column.attidentity::pg_catalog.text "
    "OPERATOR(pg_catalog.=) ''::pg_catalog.text) "
    "AS safe_key_count,"
    "(SELECT pg_catalog.count(*)::pg_catalog.int4 "
    "FROM pg_catalog.pg_attribute AS value_column "
    "WHERE value_column.attrelid OPERATOR(pg_catalog.=) c.oid "
    "AND value_column.attnum OPERATOR(pg_catalog.>) 0 "
    "AND NOT value_column.attisdropped "
    "AND value_column.attname OPERATOR(pg_catalog.=) 'value'::pg_catalog.name "
    "AND value_column.atttypid OPERATOR(pg_catalog.=) '25'::pg_catalog.oid "
    "AND value_column.attgenerated::pg_catalog.text "
    "OPERATOR(pg_catalog.=) ''::pg_catalog.text "
    "AND value_column.attidentity::pg_catalog.text "
    "OPERATOR(pg_catalog.=) ''::pg_catalog.text) "
    "AS safe_value_count "
    "FROM pg_catalog.pg_class AS c "
    "JOIN pg_catalog.pg_namespace AS n "
    "ON n.oid OPERATOR(pg_catalog.=) c.relnamespace "
    "JOIN pg_catalog.pg_roles AS schema_owner "
    "ON schema_owner.oid OPERATOR(pg_catalog.=) n.nspowner "
    "JOIN pg_catalog.pg_roles AS relation_owner "
    "ON relation_owner.oid OPERATOR(pg_catalog.=) c.relowner "
    "JOIN pg_catalog.pg_am AS am "
    "ON am.oid OPERATOR(pg_catalog.=) c.relam "
    "JOIN pg_catalog.pg_database AS d "
    "ON d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database() "
    "JOIN pg_catalog.pg_roles AS database_owner "
    "ON database_owner.oid OPERATOR(pg_catalog.=) d.datdba "
    "WHERE n.nspname OPERATOR(pg_catalog.=) 'public'::pg_catalog.name "
    "AND c.relname OPERATOR(pg_catalog.=) 'ir_config_parameter'::pg_catalog.name)"
)


def _uuid_relation_digest_sql(payload_expression: str = "identity.payload") -> str:
    return (
        "pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to("
        f"{payload_expression}::pg_catalog.text,'UTF8')), 'hex')"
    )


def _uuid_relation_assertion_query(
    postgresql: dict[str, Any], expected_sha256: str
) -> str:
    expected = _hex64(expected_sha256, "reviewed UUID relation identity")
    database_user = _text(
        postgresql["database_user"],
        "PostgreSQL database user",
        pattern=SQL_ROLE,
    )
    expected_superuser = (
        "TRUE" if postgresql["database_user_is_superuser"] else "FALSE"
    )
    expected_bypass_rls = (
        "TRUE" if postgresql["database_user_bypass_rls"] else "FALSE"
    )
    digest = _uuid_relation_digest_sql()
    return (
        f"WITH {UUID_RELATION_IDENTITY_CTE} "
        "SELECT pg_catalog.json_build_object('relation_safe',"
        "(1 OPERATOR(pg_catalog./) (CASE WHEN "
        "(SELECT pg_catalog.count(*) FROM relation_identity) "
        "OPERATOR(pg_catalog.=) 1 "
        "AND (SELECT identity.relation_kind FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 'r'::pg_catalog.text "
        "AND (SELECT identity.persistence FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 'p'::pg_catalog.text "
        "AND (SELECT identity.access_method FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 'heap'::pg_catalog.name "
        "AND NOT (SELECT identity.row_security FROM relation_identity AS identity) "
        "AND NOT (SELECT identity.force_row_security FROM relation_identity AS identity) "
        "AND NOT (SELECT identity.has_rules FROM relation_identity AS identity) "
        "AND NOT (SELECT identity.is_partition FROM relation_identity AS identity) "
        "AND (SELECT identity.parent_count FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 0 "
        "AND (SELECT identity.child_count FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 0 "
        "AND (SELECT identity.check_constraint_count FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 0 "
        "AND (SELECT identity.unsafe_index_count FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 0 "
        "AND (SELECT identity.expression_statistics_count FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 0 "
        "AND (SELECT identity.safe_key_count FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 1 "
        "AND (SELECT identity.safe_value_count FROM relation_identity AS identity) "
        "OPERATOR(pg_catalog.=) 1 "
        "AND (SELECT identity.relation_owner FROM relation_identity AS identity) "
        f"OPERATOR(pg_catalog.=) '{database_user}'::pg_catalog.name "
        "AND NOT (SELECT identity.relation_owner_is_superuser "
        "FROM relation_identity AS identity) "
        "AND NOT (SELECT identity.relation_owner_bypass_rls "
        "FROM relation_identity AS identity) "
        "AND (SELECT identity.relation_owner_can_login "
        "FROM relation_identity AS identity) "
        "AND NOT (SELECT identity.relation_owner_create_role "
        "FROM relation_identity AS identity) "
        "AND NOT (SELECT identity.relation_owner_replication "
        "FROM relation_identity AS identity) "
        "AND (SELECT identity.relation_owner_membership_count "
        "FROM relation_identity AS identity) OPERATOR(pg_catalog.=) 0 "
        f"AND (SELECT {digest} FROM relation_identity AS identity) "
        f"OPERATOR(pg_catalog.=) '{expected}'::pg_catalog.text "
        f"AND SESSION_USER OPERATOR(pg_catalog.=) '{database_user}'::pg_catalog.name "
        f"AND CURRENT_USER OPERATOR(pg_catalog.=) '{database_user}'::pg_catalog.name "
        "AND (SELECT auth.rolsuper FROM pg_catalog.pg_roles AS auth "
        "WHERE auth.rolname OPERATOR(pg_catalog.=) SESSION_USER) "
        f"OPERATOR(pg_catalog.=) {expected_superuser} "
        "AND (SELECT auth.rolbypassrls FROM pg_catalog.pg_roles AS auth "
        "WHERE auth.rolname OPERATOR(pg_catalog.=) SESSION_USER) "
        f"OPERATOR(pg_catalog.=) {expected_bypass_rls} "
        "AND pg_catalog.current_setting('transaction_read_only') "
        "OPERATOR(pg_catalog.=) 'on'::pg_catalog.text "
        "AND pg_catalog.current_setting('transaction_isolation') "
        "OPERATOR(pg_catalog.=) 'repeatable read'::pg_catalog.text "
        "THEN 1 ELSE 0 END)) OPERATOR(pg_catalog.=) 1)::pg_catalog.text"
    )


def _uuid_relation_identity_query() -> str:
    digest = _uuid_relation_digest_sql()
    return (
        f"WITH {UUID_RELATION_IDENTITY_CTE} "
        "SELECT pg_catalog.json_build_object("
        "'identity_payload',identity.payload::pg_catalog.text,"
        f"'identity_sha256',{digest})::pg_catalog.text "
        "FROM relation_identity AS identity"
    )


UUID_VALUE_QUERY = (
    "SELECT pg_catalog.json_build_object("
    "'read_only',pg_catalog.current_setting('transaction_read_only'),"
    "'session_user',SESSION_USER,'current_user',CURRENT_USER,"
    "'current_user_is_superuser',auth.rolsuper,"
    "'current_user_bypass_rls',auth.rolbypassrls,"
    "'uuid',p.value)::pg_catalog.text "
    "FROM ONLY public.ir_config_parameter AS p "
    "JOIN pg_catalog.pg_roles AS auth "
    "ON auth.rolname OPERATOR(pg_catalog.=) CURRENT_USER "
    "WHERE p.key COLLATE pg_catalog.\"C\" OPERATOR(pg_catalog.=) "
    "'database.uuid'::pg_catalog.varchar COLLATE pg_catalog.\"C\""
)


def _validate_uuid_relation_identity(
    value: object,
    catalog_item: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    database_name = expected["name"]
    relation = _exact_object(
        value,
        {
            "database_name", "database_oid", "database_owner", "schema_name",
            "schema_oid", "schema_owner", "relation_name", "relation_oid",
            "relation_filenode", "tablespace_oid", "access_method",
            "relation_kind", "persistence", "row_security", "force_row_security",
            "has_rules", "is_partition", "relation_owner",
            "relation_owner_is_superuser", "relation_owner_bypass_rls",
            "relation_owner_can_login", "relation_owner_create_role",
            "relation_owner_createdb", "relation_owner_replication",
            "relation_owner_membership_count", "parent_count", "child_count",
            "check_constraint_count", "indexes", "statistics", "columns",
        },
        f"database UUID relation {database_name}",
    )
    _require(
        relation["database_name"] == database_name
        and relation["database_oid"] == catalog_item["oid"],
        f"database UUID relation database identity mismatch: {database_name}",
    )
    owner = _text(
        relation["database_owner"],
        f"database UUID relation database owner {database_name}",
        pattern=SQL_ROLE,
    )
    _require(
        owner == catalog_item["owner"],
        f"database UUID relation database owner mismatch: {database_name}",
    )
    _require(
        relation["schema_name"] == "public"
        and relation["relation_name"] == "ir_config_parameter",
        f"database UUID relation name mismatch: {database_name}",
    )
    for field in (
        "database_oid", "schema_oid", "relation_oid", "relation_filenode",
        "tablespace_oid",
    ):
        _text(
            relation[field],
            f"database UUID relation {database_name} {field.replace('_', ' ')}",
            pattern=DECIMAL,
        )
    _require(
        relation["relation_filenode"] != "0",
        f"database UUID relation filenode is invalid: {database_name}",
    )
    _text(
        relation["schema_owner"],
        f"database UUID relation schema owner {database_name}",
        pattern=SQL_ROLE,
    )
    _text(
        relation["relation_owner"],
        f"database UUID relation owner {database_name}",
        pattern=SQL_ROLE,
    )
    _require(
        relation["relation_owner"] == expected["uuid_probe_database_user"],
        f"database UUID relation owner mismatch: {database_name}",
    )
    _require(
        relation["relation_kind"] == "r",
        f"database UUID relation must be an ordinary table: {database_name}",
    )
    _require(
        relation["persistence"] == "p",
        f"database UUID relation must be persistent: {database_name}",
    )
    _require(
        relation["access_method"] == "heap",
        f"database UUID relation must use heap access: {database_name}",
    )
    _require(
        not _boolean(
            relation["row_security"],
            f"database UUID relation row security {database_name}",
        )
        and not _boolean(
            relation["force_row_security"],
            f"database UUID relation forced row security {database_name}",
        ),
        f"database UUID relation row security is not allowed: {database_name}",
    )
    _require(
        not _boolean(
            relation["has_rules"],
            f"database UUID relation rewrite rules {database_name}",
        ),
        f"database UUID relation rewrite rules are not allowed: {database_name}",
    )
    _require(
        not _boolean(
            relation["is_partition"],
            f"database UUID relation partition state {database_name}",
        ),
        f"database UUID relation must not be a partition: {database_name}",
    )
    _require(
        not _boolean(
            relation["relation_owner_is_superuser"],
            f"database UUID relation owner superuser state {database_name}",
        ),
        f"database UUID relation owner must not be a superuser: {database_name}",
    )
    _require(
        not _boolean(
            relation["relation_owner_bypass_rls"],
            f"database UUID relation owner RLS bypass state {database_name}",
        ),
        f"database UUID relation owner must not have RLS bypass: {database_name}",
    )
    _require(
        _boolean(
            relation["relation_owner_can_login"],
            f"database UUID relation owner login state {database_name}",
        ),
        f"database UUID relation owner must be able to log in: {database_name}",
    )
    _require(
        not _boolean(
            relation["relation_owner_create_role"],
            f"database UUID relation owner create-role state {database_name}",
        ),
        f"database UUID relation owner must not create roles: {database_name}",
    )
    _boolean(
        relation["relation_owner_createdb"],
        f"database UUID relation owner create-database state {database_name}",
    )
    _require(
        not _boolean(
            relation["relation_owner_replication"],
            f"database UUID relation owner replication state {database_name}",
        ),
        f"database UUID relation owner must not have replication: {database_name}",
    )
    membership_count = _integer(
        relation["relation_owner_membership_count"],
        f"database UUID relation owner membership count {database_name}",
        maximum=65535,
    )
    _require(
        membership_count == 0,
        f"database UUID relation owner membership is not allowed: {database_name}",
    )
    parent_count = _integer(
        relation["parent_count"],
        f"database UUID relation parent count {database_name}",
        maximum=256,
    )
    child_count = _integer(
        relation["child_count"],
        f"database UUID relation child count {database_name}",
        maximum=256,
    )
    _require(
        parent_count == child_count == 0,
        f"database UUID relation inheritance is not allowed: {database_name}",
    )
    check_constraint_count = _integer(
        relation["check_constraint_count"],
        f"database UUID relation CHECK constraint count {database_name}",
        maximum=65535,
    )
    _require(
        check_constraint_count == 0,
        f"database UUID relation CHECK constraints are not allowed: {database_name}",
    )

    indexes = _exact_list(
        relation["indexes"], f"database UUID relation indexes {database_name}", maximum=256
    )
    index_oids: list[int] = []
    index_names: set[str] = set()
    validated_indexes: list[dict[str, Any]] = []
    for index, item in enumerate(indexes):
        index_identity = _exact_object(
            item,
            {
                "name", "oid", "filenode", "owner", "access_method", "valid",
                "ready", "live", "unique", "primary", "exclusion", "immediate",
                "key_attribute_numbers", "opclass_oids", "collation_oids", "options",
                "has_expressions", "has_predicate", "all_opclasses_in_pg_catalog",
            },
            f"database UUID relation index {database_name}:{index}",
        )
        name = _text(
            index_identity["name"],
            f"database UUID relation index name {database_name}:{index}",
            pattern=SQL_ROLE,
        )
        oid = int(
            _text(
                index_identity["oid"],
                f"database UUID relation index OID {database_name}:{index}",
                pattern=DECIMAL,
            )
        )
        filenode = _text(
            index_identity["filenode"],
            f"database UUID relation index filenode {database_name}:{index}",
            pattern=DECIMAL,
        )
        _require(filenode != "0", f"database UUID relation index is not physical: {database_name}:{index}")
        _text(
            index_identity["owner"],
            f"database UUID relation index owner {database_name}:{index}",
            pattern=SQL_ROLE,
        )
        for vector_field in (
            "key_attribute_numbers", "opclass_oids", "collation_oids", "options"
        ):
            vector = index_identity[vector_field]
            _require(
                isinstance(vector, str)
                and re.fullmatch(r"-?[0-9]+(?: +-?[0-9]+)*", vector) is not None,
                f"database UUID relation index {vector_field.replace('_', ' ')} is invalid: {database_name}:{index}",
            )
        for boolean_field in (
            "valid", "ready", "live", "unique", "primary", "exclusion",
            "immediate", "has_expressions", "has_predicate",
            "all_opclasses_in_pg_catalog",
        ):
            _boolean(
                index_identity[boolean_field],
                f"database UUID relation index {boolean_field.replace('_', ' ')} {database_name}:{index}",
            )
        _require(
            index_identity["owner"] == expected["uuid_probe_database_user"]
            and index_identity["access_method"] == "btree"
            and index_identity["valid"]
            and index_identity["ready"]
            and index_identity["live"]
            and not index_identity["exclusion"]
            and not index_identity["has_expressions"]
            and not index_identity["has_predicate"]
            and index_identity["all_opclasses_in_pg_catalog"],
            f"database UUID relation index is unsafe: {database_name}:{index}",
        )
        _require(name not in index_names, f"database UUID relation index names are duplicated: {database_name}")
        index_names.add(name)
        index_oids.append(oid)
        validated_indexes.append(index_identity)
    _require(
        index_oids == sorted(set(index_oids)),
        f"database UUID relation indexes are not deterministically ordered: {database_name}",
    )

    statistics = _exact_list(
        relation["statistics"],
        f"database UUID relation statistics {database_name}",
        maximum=256,
    )
    statistics_oids: list[int] = []
    statistics_names: set[str] = set()
    validated_statistics: list[dict[str, Any]] = []
    for index, item in enumerate(statistics):
        statistics_identity = _exact_object(
            item,
            {"name", "oid", "owner", "keys", "kinds", "has_expressions"},
            f"database UUID relation statistics {database_name}:{index}",
        )
        name = _text(
            statistics_identity["name"],
            f"database UUID relation statistics name {database_name}:{index}",
            pattern=SQL_ROLE,
        )
        oid = int(
            _text(
                statistics_identity["oid"],
                f"database UUID relation statistics OID {database_name}:{index}",
                pattern=DECIMAL,
            )
        )
        _text(
            statistics_identity["owner"],
            f"database UUID relation statistics owner {database_name}:{index}",
            pattern=SQL_ROLE,
        )
        keys = statistics_identity["keys"]
        _require(
            isinstance(keys, str)
            and re.fullmatch(r"[0-9]+(?: +[0-9]+)*", keys) is not None,
            f"database UUID relation statistics keys are invalid: {database_name}:{index}",
        )
        kinds = _exact_list(
            statistics_identity["kinds"],
            f"database UUID relation statistics kinds {database_name}:{index}",
            maximum=8,
        )
        _require(
            bool(kinds)
            and len(kinds) == len(set(kinds))
            and all(kind in {"d", "f", "m"} for kind in kinds),
            f"database UUID relation statistics kinds are unsafe: {database_name}:{index}",
        )
        has_expressions = _boolean(
            statistics_identity["has_expressions"],
            f"database UUID relation statistics expression state {database_name}:{index}",
        )
        _require(
            statistics_identity["owner"] == expected["uuid_probe_database_user"]
            and not has_expressions,
            f"database UUID relation statistics are unsafe: {database_name}:{index}",
        )
        _require(name not in statistics_names, f"database UUID relation statistics names are duplicated: {database_name}")
        statistics_names.add(name)
        statistics_oids.append(oid)
        validated_statistics.append(statistics_identity)
    _require(
        statistics_oids == sorted(set(statistics_oids)),
        f"database UUID relation statistics are not deterministically ordered: {database_name}",
    )
    columns = _exact_list(
        relation["columns"],
        f"database UUID relation columns {database_name}",
        maximum=256,
    )
    _require(bool(columns), f"database UUID relation has no columns: {database_name}")
    column_names: set[str] = set()
    column_numbers: list[int] = []
    validated_columns: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(columns):
        column = _exact_object(
            item,
            {
                "attnum", "name", "type_oid", "type_modifier", "not_null",
                "generated", "identity", "collation_oid",
            },
            f"database UUID relation column {database_name}:{index}",
        )
        attnum = _integer(
            column["attnum"],
            f"database UUID relation column number {database_name}:{index}",
            minimum=1,
            maximum=32767,
        )
        name = _text(
            column["name"],
            f"database UUID relation column name {database_name}:{index}",
            pattern=SQL_ROLE,
        )
        _text(
            column["type_oid"],
            f"database UUID relation column type {database_name}:{index}",
            pattern=DECIMAL,
        )
        _integer(
            column["type_modifier"],
            f"database UUID relation column modifier {database_name}:{index}",
            minimum=-1,
            maximum=MAX_INTEGER,
        )
        _boolean(
            column["not_null"],
            f"database UUID relation column nullability {database_name}:{index}",
        )
        _require(
            isinstance(column["generated"], str)
            and column["generated"] in {"", "s"},
            f"database UUID relation column generated state is invalid: {database_name}:{index}",
        )
        _require(
            isinstance(column["identity"], str)
            and column["identity"] in {"", "a", "d"},
            f"database UUID relation column identity state is invalid: {database_name}:{index}",
        )
        _text(
            column["collation_oid"],
            f"database UUID relation column collation {database_name}:{index}",
            pattern=DECIMAL,
        )
        _require(
            name not in column_names,
            f"database UUID relation column names are not unique: {database_name}",
        )
        column_names.add(name)
        column_numbers.append(attnum)
        validated_columns[name] = column
    _require(
        column_numbers == sorted(column_numbers)
        and len(column_numbers) == len(set(column_numbers)),
        f"database UUID relation columns are not deterministically ordered: {database_name}",
    )
    for name, type_oid in (("key", "1043"), ("value", "25")):
        column = validated_columns.get(name)
        _require(
            column is not None
            and column["type_oid"] == type_oid
            and column["generated"] == ""
            and column["identity"] == "",
            f"database UUID relation {name} column is unsafe: {database_name}",
        )
    safe_attnums = set(column_numbers)
    for index, index_identity in enumerate(validated_indexes):
        key_attnums = [
            int(value) for value in index_identity["key_attribute_numbers"].split()
        ]
        opclass_oids = [int(value) for value in index_identity["opclass_oids"].split()]
        collation_oids = [int(value) for value in index_identity["collation_oids"].split()]
        options = [int(value) for value in index_identity["options"].split()]
        _require(
            bool(key_attnums)
            and all(value in safe_attnums for value in key_attnums)
            and bool(opclass_oids)
            and all(value > 0 for value in opclass_oids)
            and all(value >= 0 for value in collation_oids)
            and all(value >= 0 for value in options),
            f"database UUID relation index vector is unsafe: {database_name}:{index}",
        )
    for index, statistics_identity in enumerate(validated_statistics):
        statistic_attnums = [int(value) for value in statistics_identity["keys"].split()]
        _require(
            bool(statistic_attnums)
            and all(value in safe_attnums for value in statistic_attnums),
            f"database UUID relation statistics keys are unsafe: {database_name}:{index}",
        )
    return relation


def _decode_uuid_relation_identity(
    row_value: object,
    catalog_item: dict[str, Any],
    expected: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    row = _exact_object(
        row_value,
        {"identity_payload", "identity_sha256"},
        f"database UUID relation identity {expected['name']}",
    )
    payload = row["identity_payload"]
    _require(
        isinstance(payload, str)
        and 0 < len(payload.encode("utf-8")) <= MAX_INPUT_BYTES,
        f"database UUID relation identity payload is invalid: {expected['name']}",
    )
    identity_sha256 = _hex64(
        row["identity_sha256"],
        f"database UUID relation identity digest {expected['name']}",
    )
    _require(
        hashlib.sha256(payload.encode("utf-8")).hexdigest() == identity_sha256,
        f"database UUID relation identity digest is invalid: {expected['name']}",
    )
    relation = _validate_uuid_relation_identity(
        load_strict_json(payload.encode("utf-8")),
        catalog_item,
        expected,
    )
    return relation, identity_sha256, payload


def _capture_database_uuids(
    policy: dict[str, Any],
    catalog: list[dict[str, Any]],
    *,
    deadline_ns: int | None,
    postmaster: dict[str, Any] | None = None,
) -> list[dict[str, object]]:
    postgresql = policy["postgresql"]
    catalog_by_name = {item["name"]: item for item in catalog}
    result: list[dict[str, object]] = []
    for expected in policy["protected_databases"]:
        catalog_item = catalog_by_name.get(expected["name"])
        if catalog_item is None or not catalog_item["allow_connections"]:
            continue
        probe_postgresql, authority_before = _uuid_probe_postgresql(
            postgresql, expected
        )
        identity_query = _uuid_relation_identity_query()
        probe_options: dict[str, Any] = {"deadline_ns": deadline_ns}
        if postmaster is not None:
            probe_options.update(
                {"postmaster": postmaster, "cluster_postgresql": postgresql}
            )
        rows = _run_psql_commands(
            probe_postgresql,
            expected["name"],
            [
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
                "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE",
                _uuid_relation_assertion_query(
                    probe_postgresql, expected["uuid_relation_identity_sha256"]
                ),
                identity_query,
                UUID_VALUE_QUERY,
                identity_query,
            ],
            **probe_options,
        )
        probe_postgresql_after, authority_after = _uuid_probe_postgresql(
            postgresql, expected
        )
        _require(
            probe_postgresql_after == probe_postgresql
            and authority_after == authority_before,
            f"database UUID probe authority changed during capture: {expected['name']}",
        )
        _require(
            len(rows) == 4,
            f"locked database UUID probe failed: {expected['name']}",
        )
        assertion = _exact_object(
            rows[0],
            {"relation_safe"},
            f"database UUID relation assertion {expected['name']}",
        )
        _require(
            assertion["relation_safe"] is True,
            f"database UUID relation assertion failed: {expected['name']}",
        )
        relation_before, relation_sha256_before, payload_before = (
            _decode_uuid_relation_identity(rows[1], catalog_item, expected)
        )
        relation_after, relation_sha256_after, payload_after = (
            _decode_uuid_relation_identity(rows[3], catalog_item, expected)
        )
        _require(
            relation_before == relation_after
            and relation_sha256_before == relation_sha256_after
            and payload_before == payload_after,
            f"database UUID relation changed while locked: {expected['name']}",
        )
        _require(
            relation_sha256_after == expected["uuid_relation_identity_sha256"],
            f"database UUID relation does not match reviewed policy: {expected['name']}",
        )
        row = _exact_object(
            rows[2],
            {
                "read_only", "session_user", "current_user",
                "current_user_is_superuser", "current_user_bypass_rls", "uuid",
            },
            f"database UUID probe {expected['name']}",
        )
        _require(
            row["read_only"] == "on"
            and row["session_user"] == expected["uuid_probe_database_user"]
            and row["current_user"] == expected["uuid_probe_database_user"]
            and row["current_user_is_superuser"] is False
            and row["current_user_bypass_rls"] is False,
            f"database UUID probe authority or read-only state mismatch: {expected['name']}",
        )
        result.append(
            {
                "name": expected["name"],
                "uuid": _uuid(row["uuid"], f"database UUID {expected['name']}"),
                "uuid_relation_identity_sha256": relation_sha256_after,
                "uuid_probe_os_user": expected["uuid_probe_os_user"],
                "uuid_probe_os_group": expected["uuid_probe_os_group"],
                "uuid_probe_os_uid": expected["uuid_probe_os_uid"],
                "uuid_probe_os_gid": expected["uuid_probe_os_gid"],
                "uuid_probe_os_supplementary_gids": expected[
                    "uuid_probe_os_supplementary_gids"
                ],
                "uuid_probe_database_user": expected["uuid_probe_database_user"],
                "uuid_probe_database_user_is_superuser": False,
                "uuid_probe_database_user_bypass_rls": False,
                "size_bytes": catalog_item["size_bytes"],
            }
        )
    return result


def _capture_postgresql(
    policy: dict[str, Any], *, deadline_ns: int | None = None
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
    bool,
]:
    postgresql = policy["postgresql"]
    executable_specs = (
        ("psql", "psql_path", "psql_sha256"),
        ("runuser", "runuser_path", "runuser_sha256"),
        ("systemctl", "systemctl_path", "systemctl_sha256"),
        ("pg_controldata", "pg_controldata_path", "pg_controldata_sha256"),
        ("postgres", "postgres_path", "postgres_sha256"),
    )
    executables_before = {
        label: _verify_root_executable(
            postgresql[path_field], postgresql[hash_field], label
        )
        for label, path_field, hash_field in executable_specs
    }
    socket_before = _verify_postgresql_socket(postgresql)
    (
        socket_group_membership_before,
        socket_group_members_before,
    ) = _capture_socket_group_membership(postgresql)
    (
        service_before,
        service_configuration_before,
        service_runtime_before,
    ) = _capture_systemd_service(postgresql, deadline_ns=deadline_ns)
    process_before = _verify_postgresql_process(postgresql, service_before)
    _preflight_postgresql_preload_configuration(postgresql)
    control_before = _run_pg_controldata(postgresql, deadline_ns=deadline_ns)
    system_before = _capture_system_probe(
        postgresql, deadline_ns=deadline_ns, postmaster=process_before
    )
    configuration_before = _capture_postgresql_configuration(
        postgresql, deadline_ns=deadline_ns, postmaster=process_before
    )
    _require(
        int(
            _timestamp(
                system_before["postmaster_started_at"],
                "PostgreSQL postmaster start time",
            ).timestamp()
        )
        == process_before["postmaster_start_epoch"],
        "PostgreSQL SQL/process start time mismatch",
    )
    catalog_before = _capture_catalog(
        postgresql, deadline_ns=deadline_ns, postmaster=process_before
    )
    uuids_before = _capture_database_uuids(
        policy, catalog_before, deadline_ns=deadline_ns, postmaster=process_before
    )
    uuids_after = _capture_database_uuids(
        policy, catalog_before, deadline_ns=deadline_ns, postmaster=process_before
    )
    catalog_after = _capture_catalog(
        postgresql, deadline_ns=deadline_ns, postmaster=process_before
    )
    configuration_after = _capture_postgresql_configuration(
        postgresql, deadline_ns=deadline_ns, postmaster=process_before
    )
    system_after = _capture_system_probe(
        postgresql, deadline_ns=deadline_ns, postmaster=process_before
    )
    control_after = _run_pg_controldata(postgresql, deadline_ns=deadline_ns)
    (
        service_after,
        service_configuration_after,
        service_runtime_after,
    ) = _capture_systemd_service(postgresql, deadline_ns=deadline_ns)
    process_after = _verify_postgresql_process(postgresql, service_after)
    (
        socket_group_membership_after,
        socket_group_members_after,
    ) = _capture_socket_group_membership(postgresql)
    socket_after = _verify_postgresql_socket(postgresql)
    executables_after = {
        label: _verify_root_executable(
            postgresql[path_field], postgresql[hash_field], label
        )
        for label, path_field, hash_field in executable_specs
    }
    _require(
        executables_before == executables_after,
        "PostgreSQL executable identity changed during capture",
    )
    _require(
        socket_before == socket_after,
        "PostgreSQL socket identity changed during capture",
    )
    _require(
        socket_group_membership_before == socket_group_membership_after
        == postgresql["socket_group_membership_identity_sha256"],
        "PostgreSQL socket group membership closure mismatch",
    )
    _require(
        socket_group_members_before == socket_group_members_after
        == postgresql["socket_group_members"],
        "PostgreSQL socket group member identities mismatch",
    )
    _require(
        service_configuration_before == service_configuration_after
        and service_runtime_before == service_runtime_after,
        "PostgreSQL systemd service changed during capture",
    )
    _require(
        process_before == process_after,
        "PostgreSQL process identity changed during capture",
    )
    _require(
        control_before == control_after == postgresql["system_identifier"],
        "PostgreSQL control-data identity mismatch",
    )
    _require(
        system_before == system_after,
        "PostgreSQL system identity changed during capture",
    )
    _require(
        configuration_before == configuration_after
        == postgresql["configuration_identity_sha256"],
        "PostgreSQL configuration closure mismatch",
    )
    catalog_identity_before = _catalog_identity(catalog_before)
    catalog_identity_after = _catalog_identity(catalog_after)
    _require(
        catalog_identity_before == catalog_identity_after,
        "PostgreSQL catalog changed during capture",
    )
    _require(
        catalog_identity_after == postgresql["catalog_identity_sha256"],
        "PostgreSQL catalog does not match reviewed policy",
    )
    _require(
        len(catalog_after) == postgresql["catalog_total_count"],
        "PostgreSQL catalog count does not match reviewed policy",
    )
    connectable_identity = _connectable_names_identity(catalog_after)
    connectable_count = sum(
        1 for item in catalog_after if item["allow_connections"]
    )
    _require(
        connectable_identity
        == postgresql["connectable_database_names_sha256"]
        and connectable_count == postgresql["connectable_database_count"],
        "PostgreSQL connectable database closure mismatch",
    )
    uuid_identity_before = _database_probe_identity(uuids_before)
    uuid_identity_after = _database_probe_identity(uuids_after)
    _require(
        uuid_identity_before == uuid_identity_after,
        "protected database UUID identity changed during capture",
    )
    catalog: list[dict[str, object]] = []
    before_by_name = {item["name"]: item for item in catalog_before}
    for item in catalog_after:
        catalog.append(
            {
                **item,
                "size_bytes": max(
                    item["size_bytes"], before_by_name[item["name"]]["size_bytes"]
                ),
            }
        )
    before_uuid_by_name = {item["name"]: item for item in uuids_before}
    databases = [
        {
            **item,
            "size_bytes": max(
                item["size_bytes"], before_uuid_by_name[item["name"]]["size_bytes"]
            ),
        }
        for item in uuids_after
    ]
    identity = {
        "psql_sha256": postgresql["psql_sha256"],
        "psql_identity_sha256": _canonical_sha256(executables_after["psql"]),
        "runuser_sha256": postgresql["runuser_sha256"],
        "runuser_identity_sha256": _canonical_sha256(executables_after["runuser"]),
        "systemctl_sha256": postgresql["systemctl_sha256"],
        "systemctl_identity_sha256": _canonical_sha256(
            executables_after["systemctl"]
        ),
        "pg_controldata_sha256": postgresql["pg_controldata_sha256"],
        "pg_controldata_identity_sha256": _canonical_sha256(
            executables_after["pg_controldata"]
        ),
        "postgres_sha256": postgresql["postgres_sha256"],
        "postgres_identity_sha256": _canonical_sha256(
            executables_after["postgres"]
        ),
        "service_unit": postgresql["service_unit"],
        "service_configuration_sha256": service_configuration_after,
        "service_runtime_identity_sha256": service_runtime_after,
        "main_pid": process_after["pid"],
        "control_group": postgresql["expected_control_group"],
        "database_user": system_after["database_user"],
        "database_current_user": system_after["database_current_user"],
        "database_user_is_superuser": system_after[
            "database_user_is_superuser"
        ],
        "database_user_bypass_rls": system_after[
            "database_user_bypass_rls"
        ],
        "socket_directory": postgresql["socket_directory"],
        "socket_filesystem_identity_sha256": _canonical_sha256(socket_after),
        "socket_listener_identity_sha256": process_after[
            "socket_listener_identity_sha256"
        ],
        "socket_group_membership_identity_sha256_before": (
            socket_group_membership_before
        ),
        "socket_group_membership_identity_sha256_after": (
            socket_group_membership_after
        ),
        "socket_group_members_before": socket_group_members_before,
        "socket_group_members_after": socket_group_members_after,
        "unix_socket_directories": system_after["unix_socket_directories"],
        "port": system_after["port"],
        "system_identifier": system_after["system_identifier"],
        "control_data_system_identifier": control_after,
        "data_directory": system_after["data_directory"],
        "data_directory_identity_sha256": process_after[
            "data_directory_identity_sha256"
        ],
        "postmaster_pid_identity_sha256": process_after[
            "postmaster_pid_identity_sha256"
        ],
        "process_identity_sha256": process_after["process_identity_sha256"],
        "config_file": system_after["config_file"],
        "config_file_identity_sha256": process_after[
            "config_file_identity_sha256"
        ],
        "hba_file": system_after["hba_file"],
        "hba_file_identity_sha256": process_after["hba_file_identity_sha256"],
        "server_version_num": system_after["server_version_num"],
        "in_recovery": system_after["in_recovery"],
        "postmaster_started_at": system_after["postmaster_started_at"],
        "catalog_identity_sha256_before": catalog_identity_before,
        "catalog_identity_sha256_after": catalog_identity_after,
        "catalog_total_count": len(catalog),
        "connectable_database_names_sha256": connectable_identity,
        "connectable_database_count": connectable_count,
        "configuration_identity_sha256_before": configuration_before,
        "configuration_identity_sha256_after": configuration_after,
        "postmaster_namespace_identity_sha256": process_after[
            "namespace_identity_sha256"
        ],
    }
    target_exists = any(
        item["name"] == policy["target"]["database_name"] for item in catalog
    )
    return identity, catalog, databases, target_exists


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _monotonic_ns() -> int:
    return time.monotonic_ns()


def collect_observation(policy_value: object) -> dict[str, object]:
    """Capture live Linux topology and PostgreSQL identity without mutation."""

    policy = _validate_policy(policy_value)
    _require(sys.platform == "linux", "live capacity collection requires Linux")
    _require(hasattr(os, "geteuid") and os.geteuid() == 0, "live capacity collection requires root")
    collector_digest = _program_sha256()
    _require(
        collector_digest == policy["collector_sha256"],
        "collector program SHA-256 mismatch",
    )
    started_at = _now_utc()
    started_monotonic_ns = _monotonic_ns()
    deadline_ns = started_monotonic_ns + policy["max_capture_duration_seconds"] * 1_000_000_000
    host_before = _capture_host()
    namespace_before, mountinfo_before, mount_entries_before = _capture_mount_context()
    resources_before = _capture_resources(
        policy["protected_resources"],
        suffix="before",
        mount_entries=mount_entries_before,
        deadline_ns=deadline_ns,
    )
    mounts_before = _capture_mounts(policy, mount_entries_before)
    postgresql, catalog, databases, target_exists = _capture_postgresql(
        policy, deadline_ns=deadline_ns
    )
    namespace_after, mountinfo_after, mount_entries_after = _capture_mount_context()
    resources_after = _capture_resources(
        policy["protected_resources"],
        suffix="after",
        mount_entries=mount_entries_after,
        deadline_ns=deadline_ns,
    )
    mounts_after = _capture_mounts(policy, mount_entries_after)
    host_after = _capture_host()
    finished_monotonic_ns = _monotonic_ns()
    finished_at = _now_utc()
    _require(host_before == host_after, "host or boot identity changed during capture")
    _require(namespace_before == namespace_after, "mount namespace changed during capture")
    _require(mountinfo_before == mountinfo_after, "mount topology changed during capture")
    duration_ns = finished_monotonic_ns - started_monotonic_ns
    _require(duration_ns >= 0, "monotonic clock moved backwards during capture")
    _require(
        duration_ns <= policy["max_capture_duration_seconds"] * 1_000_000_000,
        "capture duration exceeded policy",
    )
    wall_duration_ns = int((finished_at - started_at).total_seconds() * 1_000_000_000)
    _require(
        wall_duration_ns >= 0 and abs(wall_duration_ns - duration_ns) <= 2_000_000_000,
        "wall and monotonic clocks diverged during capture",
    )
    mounts = _merge_mount_captures(mounts_before, mounts_after)
    protected_resources: list[dict[str, object]] = []
    for resource in policy["protected_resources"]:
        resource_id = resource["resource_id"]
        protected_resources.append(
            {
                "resource_id": resource_id,
                **resources_before[resource_id],
                **resources_after[resource_id],
            }
        )
    return {
        "schema_version": 1,
        "kind": OBSERVATION_KIND,
        "capture_started_at": started_at.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "capture_finished_at": finished_at.replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "capture_duration_ns": duration_ns,
        "capture_mode": "read_only",
        "host": host_after,
        "environment": policy["environment"],
        "provenance": {
            "collector": "live_linux_v1",
            "collector_sha256": collector_digest,
            "mount_namespace_scope": "host_pid1",
            "mount_namespace_identity_sha256": namespace_after,
            "mountinfo_sha256_before": hashlib.sha256(mountinfo_before).hexdigest(),
            "mountinfo_sha256_after": hashlib.sha256(mountinfo_after).hexdigest(),
        },
        "postgresql": postgresql,
        "target": {
            "odoo_instance_id": policy["target"]["odoo_instance_id"],
            "database_name": policy["target"]["database_name"],
            "database_exists": target_exists,
        },
        "mounts": mounts,
        "catalog": catalog,
        "databases": databases,
        "protected_resources": protected_resources,
        "side_effect_attestation": {
            "filesystem_object_mutation_performed_by_collector": False,
            "database_transaction_write_performed": False,
            "service_control_performed": False,
            "accounting_write_performed": False,
        },
    }


def _read_bounded_regular_file(path: Path, label: str) -> bytes:
    _require(path.is_absolute(), f"{label} path must be absolute")
    try:
        before = path.lstat()
    except OSError as exc:
        raise CapacityGateError(f"{label} cannot be opened") from exc
    _require(not path.is_symlink(), f"{label} must not be a symlink")
    if sys.platform == "linux":
        _require(path.resolve(strict=True) == path, f"{label} path must be physical")
        _require(
            before.st_uid == 0 and before.st_gid == 0,
            f"{label} must be root-owned",
        )
        _require(before.st_mode & 0o022 == 0, f"{label} must not be group/world writable")
        _verify_root_directory_chain(path.parent, label)
    _require(stat.S_ISREG(before.st_mode), f"{label} must be a regular file")
    _require(before.st_nlink == 1, f"{label} must have exactly one link")
    _require(before.st_size <= MAX_INPUT_BYTES, f"{label} is too large")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NOATIME", 0),
        )
        try:
            opened = os.fstat(descriptor)
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                payload.extend(chunk)
                _require(len(payload) <= MAX_INPUT_BYTES, f"{label} is too large")
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except OSError as exc:
        raise CapacityGateError(f"{label} cannot be read safely") from exc
    fingerprint = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
    )
    _require(
        fingerprint(before)
        == fingerprint(opened)
        == fingerprint(opened_after)
        == fingerprint(after),
        f"{label} changed while being read",
    )
    return bytes(payload)


def _emit_json(stream: object, value: object) -> None:
    stream.write(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CapacityGateError(f"invalid arguments: {message}")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        description="Evaluate a read-only dedicated-sandbox capacity observation"
    )
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--expected-policy-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        expected_policy_sha256 = _hex64(
            args.expected_policy_sha256, "expected policy SHA-256"
        )
        policy_payload = _read_bounded_regular_file(args.policy, "policy")
        _require(
            hashlib.sha256(policy_payload).hexdigest() == expected_policy_sha256,
            "policy SHA-256 mismatch",
        )
        policy = load_strict_json(policy_payload)
        validated_policy = _validate_policy(policy)
        _require(
            _program_sha256() == validated_policy["collector_sha256"],
            "collector program SHA-256 mismatch",
        )
        observation = collect_observation(validated_policy)
        observation_payload = _canonical_bytes(observation)
        observation_sha256 = hashlib.sha256(observation_payload).hexdigest()
        report = evaluate(
            validated_policy,
            observation,
            policy_raw_sha256=expected_policy_sha256,
            observation_raw_sha256=observation_sha256,
        )
    except (CapacityGateError, OSError, ValueError, RecursionError) as exc:
        _emit_json(
            sys.stderr,
            {
                "ok": False,
                "error": str(exc),
                "sandbox_provisioning_authorized": False,
                "sandbox_accounting_write_authorized": False,
                "production_accounting_write_authorized": False,
            },
        )
        return 2
    _emit_json(sys.stdout, report)
    return 0 if report["capacity_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

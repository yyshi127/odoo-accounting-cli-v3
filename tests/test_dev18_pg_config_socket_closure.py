from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import os

import pytest

import test_dev18_sandbox_capacity_gate as base


gate = base.gate
SOURCE = Path(gate.__file__).read_text(encoding="utf-8")


def _closed_policy() -> dict[str, object]:
    value = base.policy()
    value["postgresql"].update(
        {
            "configuration_identity_sha256": "d" * 64,
            "socket_group_membership_identity_sha256": "e" * 64,
        }
    )
    return value


def _closed_observation() -> dict[str, object]:
    value = base.observation()
    value["postgresql"].update(
        {
            "configuration_identity_sha256_before": "d" * 64,
            "configuration_identity_sha256_after": "d" * 64,
            "socket_group_membership_identity_sha256_before": "e" * 64,
            "socket_group_membership_identity_sha256_after": "e" * 64,
            "postmaster_namespace_identity_sha256": "f" * 64,
        }
    )
    return value


def test_configuration_and_socket_membership_are_required_policy_bindings() -> None:
    """A valid report must commit to the whole cluster config and socket GID."""
    policy = _closed_policy()
    observation = _closed_observation()

    gate._validate_policy(policy)
    gate._validate_observation(observation)
    report = gate.evaluate(policy, observation, now=base.NOW)

    assert report["capacity_gate_passed"] is True
    assert report["blockers"] == []


@pytest.mark.parametrize(
    ("field", "blocker"),
    [
        (
            "configuration_identity_sha256_before",
            "postgresql_configuration_drift",
        ),
        (
            "configuration_identity_sha256_after",
            "postgresql_configuration_binding_mismatch",
        ),
        (
            "socket_group_membership_identity_sha256_before",
            "postgresql_socket_group_membership_drift",
        ),
        (
            "socket_group_membership_identity_sha256_after",
            "postgresql_socket_group_membership_binding_mismatch",
        ),
    ],
)
def test_configuration_or_socket_membership_drift_fails_closed(
    field: str, blocker: str
) -> None:
    policy = _closed_policy()
    observation = _closed_observation()
    observation["postgresql"][field] = "0" * 64

    report = gate.evaluate(policy, observation, now=base.NOW)

    assert report["capacity_gate_passed"] is False
    assert blocker in report["blockers"]


def test_configuration_snapshot_covers_effective_files_auth_and_role_graph() -> None:
    """The snapshot must cover loaded values, on-disk includes and role defaults."""
    required_relations = {
        "pg_catalog.pg_settings",
        "pg_catalog.pg_file_settings",
        "pg_catalog.pg_hba_file_rules",
        "pg_catalog.pg_ident_file_mappings",
        "pg_catalog.pg_db_role_setting",
        "pg_catalog.pg_authid",
        "pg_catalog.pg_auth_members",
    }

    assert required_relations <= {token for token in required_relations if token in SOURCE}
    assert "shared_preload_libraries" in SOURCE
    assert "session_preload_libraries" in SOURCE
    assert "local_preload_libraries" in SOURCE
    assert "postgresql.auto.conf" in SOURCE
    assert "ident_file" in SOURCE
    assert "role_password_vector_sha256" in SOURCE
    assert "rolpassword_is_null" not in SOURCE


def test_client_preload_libraries_are_cleared_before_any_probe() -> None:
    options = gate._psql_environment()["PGOPTIONS"]

    assert "-c local_preload_libraries=" in options
    # session_preload_libraries is superuser-only.  The privileged catalog
    # probe must explicitly clear it, while non-superuser UUID probes are
    # protected by the configuration/role-setting closure below.
    assert "-c session_preload_libraries=" in SOURCE


@pytest.mark.parametrize(
    "setting",
    (
        "shared_preload_libraries",
        "session_preload_libraries",
        "local_preload_libraries",
    ),
)
@pytest.mark.parametrize(
    "arguments",
    (
        lambda setting: ["postgres", "-c", f"{setting}=evil"],
        lambda setting: ["postgres", f"-c{setting}=evil"],
        lambda setting: ["postgres", f"--{setting}=evil"],
        lambda setting: ["postgres", f"--{setting.upper()}=evil"],
        lambda setting: ["postgres", f"--{setting}", "evil"],
    ),
)
def test_postmaster_command_line_rejects_preload_injection(
    setting: str, arguments,
) -> None:
    with pytest.raises(gate.CapacityGateError, match=setting):
        gate._validate_postgresql_process_arguments(arguments(setting))


def test_postmaster_command_line_allows_explicit_empty_preloads_and_rejects_bad_c() -> None:
    gate._validate_postgresql_process_arguments(
        [
            "postgres",
            "-c",
            "shared_preload_libraries=",
            "-csession_preload_libraries=",
            "--local_preload_libraries=",
        ]
    )

    for arguments in (["postgres", "-c"], ["postgres", "-c", "missing_equals"]):
        with pytest.raises(gate.CapacityGateError, match="ambiguous -c"):
            gate._validate_postgresql_process_arguments(arguments)


def test_postmaster_command_line_uniquely_binds_data_and_configuration_files() -> None:
    data_directory = "/var/lib/postgresql/16/main"
    config_file = "/etc/postgresql/16/main/postgresql.conf"
    valid = [
        "postgres",
        "-D",
        data_directory,
        "-c",
        f"config_file={config_file}",
    ]
    gate._validate_postgresql_process_arguments(
        valid,
        data_directory=data_directory,
        config_file=config_file,
    )

    invalid = (
        [*valid, "-D", data_directory],
        [*valid, "-c", f"config_file={config_file}"],
        [*valid, "--CONFIG_FILE=/tmp/unreviewed.conf"],
        [
            "postgres",
            "-D",
            data_directory,
            "-c",
            "config_file=/tmp/unreviewed.conf",
        ],
    )
    for arguments in invalid:
        with pytest.raises(gate.CapacityGateError, match="uniquely bind|bind the configuration"):
            gate._validate_postgresql_process_arguments(
                arguments,
                data_directory=data_directory,
                config_file=config_file,
            )


@pytest.mark.parametrize(
    "arguments",
    (
        ["postgres", "-o", "-c session_preload_libraries=evil"],
        ["postgres", "-o-c session_preload_libraries=evil"],
    ),
)
def test_postmaster_command_line_rejects_backend_option_passthrough(
    arguments: list[str],
) -> None:
    with pytest.raises(gate.CapacityGateError, match="backend option passthrough"):
        gate._validate_postgresql_process_arguments(arguments)


@pytest.mark.parametrize(
    "variable",
    ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"),
)
def test_postmaster_environment_rejects_dynamic_loader_injection(
    variable: str,
) -> None:
    payload = f"PATH=/usr/bin\0{variable}=evil\0".encode()

    with pytest.raises(gate.CapacityGateError, match=variable):
        gate._postgresql_process_environment(payload)


def test_postmaster_environment_is_strict_and_empty_loader_values_are_bound() -> None:
    assert gate._postgresql_process_environment(
        b"PATH=/usr/bin\0LD_PRELOAD=\0LD_AUDIT=\0LD_LIBRARY_PATH=\0"
    ) == (
        ("LD_AUDIT", ""),
        ("LD_LIBRARY_PATH", ""),
        ("LD_PRELOAD", ""),
        ("PATH", "/usr/bin"),
    )

    with pytest.raises(gate.CapacityGateError, match="duplicate"):
        gate._postgresql_process_environment(b"PATH=/a\0PATH=/b\0")


def test_configuration_closure_rejects_every_preload_entry_by_default() -> None:
    disabled = {
        "shared_preload_libraries": "",
        "session_preload_libraries": "",
        "local_preload_libraries": "",
    }
    gate._validate_postgresql_preload_settings(disabled)

    for name in tuple(disabled):
        enabled = {**disabled, name: "unreviewed_library"}
        with pytest.raises(gate.CapacityGateError):
            gate._validate_postgresql_preload_settings(enabled)


def test_socket_writable_gid_identity_enumerates_all_nss_accounts() -> None:
    """Checking only postgres' grouplist misses another account sharing its GID."""
    assert "getpwall" in SOURCE
    assert "getgrgid" in SOURCE
    assert "getgrouplist" in SOURCE
    assert "/etc/nsswitch.conf" in SOURCE

    snapshot = {
        "nsswitch_identity_sha256": "9" * 64,
        "account_files_identity_sha256": "8" * 64,
        "passwd_sources": ["files", "systemd"],
        "group_sources": ["files", "systemd"],
        "group": {
            "name": "postgres",
            "gid": 112,
            "explicit_members": [],
        },
        "accounts": [
            {
                "name": "postgres",
                "uid": 111,
                "primary_gid": 112,
                "supplementary_gids": [111, 112],
            }
        ],
    }
    reviewed = gate._socket_group_membership_identity(snapshot)
    assert gate.HEX64.fullmatch(reviewed) is not None

    unexpected_member = deepcopy(snapshot)
    unexpected_member["accounts"].append(
        {
            "name": "mallory",
            "uid": 2001,
            "primary_gid": 2001,
            "supplementary_gids": [112, 2001],
        }
    )
    assert gate._socket_group_membership_identity(unexpected_member) != reviewed


def test_writable_socket_gid_rejects_every_non_service_member() -> None:
    snapshot = {
        "nsswitch_identity_sha256": "9" * 64,
        "account_files_identity_sha256": "8" * 64,
        "passwd_sources": ["files", "systemd"],
        "group_sources": ["files", "systemd"],
        "group": {"name": "postgres", "gid": 112, "explicit_members": []},
        "accounts": [
            {
                "name": "postgres",
                "uid": 111,
                "primary_gid": 112,
                "supplementary_gids": [111, 112],
            },
            {
                "name": "mallory",
                "uid": 2001,
                "primary_gid": 2001,
                "supplementary_gids": [112, 2001],
            },
        ],
    }

    with pytest.raises(gate.CapacityGateError, match="exclusive service identity"):
        gate._validate_writable_socket_group_members(
            snapshot,
            service_user="postgres",
            service_uid=111,
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"passwd: files ldap\ngroup: files ldap\n",
        b"passwd: files [SUCCESS=return] systemd\ngroup: files systemd\n",
        b"passwd: compat\ngroup: compat\n",
        b"passwd: files systemd\ngroup: files\n",
    ],
)
def test_nss_membership_sources_fail_closed_when_not_fully_enumerable(
    payload: bytes,
) -> None:
    with pytest.raises(gate.CapacityGateError):
        gate._parse_supported_nss_membership_sources(payload)


def test_target_nss_files_systemd_sources_are_explicitly_supported() -> None:
    sources = gate._parse_supported_nss_membership_sources(
        b"passwd: files systemd\ngroup: files systemd\n"
    )
    assert sources == (("files", "systemd"), ("files", "systemd"))
    gate._validate_socket_nss_source_safety(sources[1], group_writable=False)
    with pytest.raises(gate.CapacityGateError, match="group-writable"):
        gate._validate_socket_nss_source_safety(sources[1], group_writable=True)


def test_group_writable_socket_directory_is_rejected_even_with_files_only_nss() -> None:
    with pytest.raises(gate.CapacityGateError, match="group-writable"):
        gate._validate_socket_nss_source_safety(("files",), group_writable=True)


def _configuration_snapshot() -> dict[str, object]:
    return {
        "configuration_files": [],
        "configuration_load_identity": [
            {"load_time_epoch_microseconds": 1_700_000_000_000_000}
        ],
        "settings": [
            {
                "name": "shared_preload_libraries",
                "setting": "",
                "pending_restart": False,
            },
            {
                "name": "session_preload_libraries",
                "setting": "",
                "pending_restart": False,
            },
            {
                "name": "local_preload_libraries",
                "setting": "",
                "pending_restart": False,
            },
        ],
        "file_settings": [],
        "hba_rules": [],
        "ident_mappings": [],
        "db_role_settings": [],
        "roles": [],
        "role_password_identity": [
            {
                "role_count": 1,
                "role_password_vector_sha256": "a" * 64,
            }
        ],
        "role_memberships": [],
    }


@pytest.mark.parametrize(
    "name", ["shared_preload_libraries", "session_preload_libraries", "local_preload_libraries"]
)
def test_nonempty_preload_in_any_configuration_source_is_rejected(name: str) -> None:
    snapshot = _configuration_snapshot()
    snapshot["file_settings"] = [
        {
            "name": name,
            "setting": "attacker_library",
            "error": None,
            "applied": False,
        }
    ]

    with pytest.raises(gate.CapacityGateError, match=name):
        gate._postgresql_configuration_identity(snapshot)


def test_configuration_error_and_pending_restart_are_rejected() -> None:
    pending = _configuration_snapshot()
    pending["settings"][0]["pending_restart"] = True
    with pytest.raises(gate.CapacityGateError, match="requires restart"):
        gate._postgresql_configuration_identity(pending)

    for component in ("file_settings", "hba_rules", "ident_mappings"):
        invalid = _configuration_snapshot()
        invalid[component] = [{"error": "invalid configuration"}]
        with pytest.raises(gate.CapacityGateError, match="has an error"):
            gate._postgresql_configuration_identity(invalid)


def test_guc_name_matching_is_case_insensitive_and_rejects_case_duplicates() -> None:
    snapshot = _configuration_snapshot()
    snapshot["settings"].append(
        {
            "name": "DateStyle",
            "setting": "ISO, MDY",
            "sourcefile": "/etc/postgresql/postgresql.conf",
            "sourceline": 10,
            "pending_restart": False,
        }
    )
    snapshot["file_settings"] = [
        {
            "name": "datestyle",
            "setting": "ISO, MDY",
            "sourcefile": "/etc/postgresql/postgresql.conf",
            "sourceline": 10,
            "applied": True,
            "error": None,
        }
    ]
    gate._postgresql_configuration_identity(snapshot)

    duplicate = deepcopy(snapshot)
    duplicate["settings"].append(
        {"name": "datestyle", "setting": "ISO, MDY", "pending_restart": False}
    )
    with pytest.raises(gate.CapacityGateError, match="duplicated"):
        gate._postgresql_configuration_identity(duplicate)


@pytest.mark.parametrize("component", ("file_settings", "roles", "db_role_settings"))
def test_mixed_case_preload_names_are_rejected_in_every_configuration_source(
    component: str,
) -> None:
    snapshot = _configuration_snapshot()
    if component == "file_settings":
        snapshot[component] = [
            {
                "name": "Session_PreLoad_Libraries",
                "setting": "evil",
                "applied": False,
                "error": None,
            }
        ]
    else:
        snapshot[component] = [
            {"config": ["Session_PreLoad_Libraries=evil"]}
        ]

    with pytest.raises(gate.CapacityGateError, match="(?i)session_preload_libraries"):
        gate._postgresql_configuration_identity(snapshot)


def test_role_password_identity_is_single_server_side_aggregate() -> None:
    snapshot = _configuration_snapshot()
    gate._postgresql_configuration_identity(snapshot)

    duplicate = deepcopy(snapshot)
    duplicate["role_password_identity"].append(
        {"role_count": 1, "role_password_vector_sha256": "b" * 64}
    )
    with pytest.raises(gate.CapacityGateError):
        gate._postgresql_configuration_identity(duplicate)

    assert "pg_catalog.pg_authid" in gate.POSTGRESQL_CONFIGURATION_QUERY
    assert "role_password_vector_sha256" in gate.POSTGRESQL_CONFIGURATION_QUERY
    assert "r.rolconfig" not in gate.POSTGRESQL_CONFIGURATION_QUERY
    assert "rolpassword_is_null" not in gate.POSTGRESQL_CONFIGURATION_QUERY


def test_configuration_include_graph_binds_empty_directory_and_missing_optional(
    tmp_path: Path,
) -> None:
    root = tmp_path / "reviewed"
    root.mkdir()
    conf_d = root / "conf.d"
    conf_d.mkdir()
    main = root / "postgresql.conf"
    hba = root / "pg_hba.conf"
    ident = root / "pg_ident.conf"
    main.write_text(
        "include_dir = 'conf.d'\ninclude_if_exists = 'optional.conf'\n",
        encoding="utf-8",
    )
    hba.write_text("local all all peer\n", encoding="utf-8")
    ident.write_text("", encoding="utf-8")

    first = gate._postgresql_include_graph_identity(
        ((main, "postgresql"), (hba, "hba"), (ident, "ident")),
        (root,),
    )
    (conf_d / "00-safe.conf").write_text("work_mem = '4MB'\n", encoding="utf-8")
    second = gate._postgresql_include_graph_identity(
        ((main, "postgresql"), (hba, "hba"), (ident, "ident")),
        (root,),
    )
    assert first != second

    (root / "optional.conf").write_text("work_mem = '8MB'\n", encoding="utf-8")
    third = gate._postgresql_include_graph_identity(
        ((main, "postgresql"), (hba, "hba"), (ident, "ident")),
        (root,),
    )
    assert second != third


def test_configuration_parser_accepts_unspaced_include_assignment() -> None:
    records = gate._configuration_records(
        b"include_dir='conf.d' # reviewed directory\n", "postgresql"
    )

    assert records == [
        {
            "record": "include",
            "directive": "include_dir",
            "target": "conf.d",
            "line": 1,
        }
    ]


@pytest.mark.parametrize(
    "setting",
    (
        "shared_preload_libraries",
        "session_preload_libraries",
        "local_preload_libraries",
    ),
)
def test_configuration_parser_rejects_unspaced_preload_assignment(
    setting: str,
) -> None:
    records = gate._configuration_records(
        f"{setting}='evil' # must be detected\n".encode(), "postgresql"
    )

    with pytest.raises(gate.CapacityGateError, match=setting):
        gate._assert_configuration_graph_has_no_preloads(
            {"files": [{"records": records}]}
        )


def test_configuration_include_graph_rejects_external_and_hba_at_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "reviewed"
    root.mkdir()
    outside = tmp_path / "outside.conf"
    outside.write_text("work_mem = '4MB'\n", encoding="utf-8")
    main = root / "postgresql.conf"
    main.write_text(f"include = '{outside}'\n", encoding="utf-8")
    hba = root / "pg_hba.conf"
    hba.write_text("local all @admins peer\n", encoding="utf-8")
    ident = root / "pg_ident.conf"
    ident.write_text("", encoding="utf-8")

    with pytest.raises(gate.CapacityGateError, match="reviewed roots"):
        gate._postgresql_include_graph_identity(
            ((main, "postgresql"),),
            (root,),
        )
    main.write_text("", encoding="utf-8")
    with pytest.raises(gate.CapacityGateError, match="@ list"):
        gate._postgresql_include_graph_identity(
            ((main, "postgresql"), (hba, "hba"), (ident, "ident")),
            (root,),
        )


def test_tls_asset_specs_resolve_relative_paths_and_reject_passphrase_commands(
    tmp_path: Path,
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    settings = {
        "data_directory": str(data),
        "ssl": "on",
        "ssl_cert_file": "server.crt",
        "ssl_key_file": "server.key",
        "ssl_ca_file": "",
        "ssl_crl_file": "",
        "ssl_crl_dir": "",
        "ssl_dh_params_file": "",
        "ssl_passphrase_command": "",
    }
    specs = gate._postgresql_external_asset_specs(settings, [])
    assert {item[1] for item in specs} == {
        data / "server.crt",
        data / "server.key",
    }

    settings["ssl_passphrase_command"] = "/tmp/unreviewed-command"
    with pytest.raises(gate.CapacityGateError, match="passphrase"):
        gate._postgresql_external_asset_specs(settings, [])


@pytest.mark.parametrize(
    "auth_method",
    ("pam", "bsd", "ldap", "radius", "gss", "sspi", "ident", "trust"),
)
def test_external_or_passwordless_hba_authentication_methods_fail_closed(
    tmp_path: Path, auth_method: str,
) -> None:
    settings = {
        "data_directory": str(tmp_path),
        "ssl": "off",
        "ssl_passphrase_command": "",
    }

    with pytest.raises(gate.CapacityGateError, match=auth_method):
        gate._postgresql_external_asset_specs(
            settings,
            [{"auth_method": auth_method, "error": None}],
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX filesystem object semantics")
def test_configuration_tree_rejects_symlink_hardlink_and_special_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    uid = os.getuid()
    gid = os.getgid()
    monkeypatch.setattr(gate, "_trusted_postgresql_directory_chain", lambda *_: ())
    regular = tmp_path / "regular"
    regular.write_text("safe", encoding="utf-8")
    hardlink = tmp_path / "hardlink"
    os.link(regular, hardlink)
    with pytest.raises(gate.CapacityGateError, match="hard-linked"):
        gate._trusted_postgresql_configuration_tree_identity(tmp_path, uid, gid)

    hardlink.unlink()
    symlink = tmp_path / "link"
    symlink.symlink_to(regular)
    with pytest.raises(gate.CapacityGateError, match="symlink"):
        gate._trusted_postgresql_configuration_tree_identity(tmp_path, uid, gid)

    symlink.unlink()
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(gate.CapacityGateError, match="unsupported object"):
        gate._trusted_postgresql_configuration_tree_identity(tmp_path, uid, gid)


def _backend_attestation(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "backend_pid": 5678,
        "parent_pid": 4321,
        "executable": "/usr/lib/postgresql/16/bin/postgres",
        "control_group": "/system.slice/postgresql@16-main.service",
        "namespace_identity_sha256": "f" * 64,
        "process_identity_sha256": "a" * 64,
    }
    value.update(overrides)
    return value


def test_sql_backend_attestation_binds_live_child_to_verified_postmaster() -> None:
    postgresql = _closed_policy()["postgresql"]
    postmaster = {
        "pid": 4321,
        "namespace_identity_sha256": "f" * 64,
    }

    gate._validate_postgresql_backend_attestation(
        postgresql,
        postmaster,
        _backend_attestation(),
    )

    invalid_values = (
        _backend_attestation(parent_pid=9999),
        _backend_attestation(executable="/tmp/fake-postgres"),
        _backend_attestation(control_group="/system.slice/attacker.service"),
        _backend_attestation(namespace_identity_sha256="0" * 64),
    )
    for value in invalid_values:
        with pytest.raises(gate.CapacityGateError):
            gate._validate_postgresql_backend_attestation(
                postgresql,
                postmaster,
                value,
            )


def test_every_sql_probe_requests_and_reports_its_backend_pid() -> None:
    assert "pg_catalog.pg_backend_pid()" in SOURCE
    assert "_verify_postgresql_backend_process" in SOURCE


def test_configuration_snapshot_schema_cannot_silently_omit_a_component() -> None:
    snapshot = _configuration_snapshot()
    identity = gate._postgresql_configuration_identity(snapshot)
    assert gate.HEX64.fullmatch(identity) is not None

    for component in tuple(snapshot):
        incomplete = deepcopy(snapshot)
        del incomplete[component]
        with pytest.raises(gate.CapacityGateError):
            gate._postgresql_configuration_identity(incomplete)

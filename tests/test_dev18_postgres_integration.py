from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = PROJECT_ROOT / "deployment" / "dev18" / "sandbox_capacity_gate.py"
RUN_INTEGRATION = os.environ.get("DEV18_POSTGRES_INTEGRATION") == "1"
SAFE_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")

pytestmark = pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason="set DEV18_POSTGRES_INTEGRATION=1 for the isolated PostgreSQL gate",
)


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "dev18_postgres_integration_gate", GATE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _required_environment(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        pytest.fail(f"required PostgreSQL integration setting is absent: {name}")
    return value


@dataclass
class PostgreSQLHarness:
    psql_path: str
    runuser_path: str
    socket_directory: str
    port: int
    admin_os_user: str
    admin_database_user: str
    probe_os_user: str
    probe_database_user: str
    other_database_user: str
    created_databases: list[str] = field(default_factory=list)
    counter: int = 0

    def _base_psql_command(
        self, *, os_user: str, database_user: str, database: str
    ) -> list[str]:
        return [
            self.runuser_path,
            "-u",
            os_user,
            "--",
            self.psql_path,
            "-X",
            "-q",
            "-A",
            "-t",
            "-w",
            "-v",
            "ON_ERROR_STOP=1",
            "-h",
            self.socket_directory,
            "-p",
            str(self.port),
            "-U",
            database_user,
            "-d",
            database,
        ]

    @staticmethod
    def _environment(*, pgoptions: str | None = None) -> dict[str, str]:
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        if pgoptions is not None:
            environment["PGOPTIONS"] = pgoptions
        return environment

    def run(
        self,
        query: str,
        *,
        database: str = "postgres",
        os_user: str | None = None,
        database_user: str | None = None,
        pgoptions: str | None = None,
        check: bool = True,
        timeout: float = 20,
    ) -> subprocess.CompletedProcess[str]:
        command = self._base_psql_command(
            os_user=os_user or self.admin_os_user,
            database_user=database_user or self.admin_database_user,
            database=database,
        )
        command.extend(("-c", query))
        return subprocess.run(
            command,
            check=check,
            capture_output=True,
            cwd="/",
            env=self._environment(pgoptions=pgoptions),
            text=True,
            timeout=timeout,
        )

    def scalar(self, query: str, *, database: str = "postgres") -> str:
        return self.run(query, database=database).stdout.strip()

    @property
    def gate_connection(self) -> dict[str, object]:
        return {
            "runuser_path": self.runuser_path,
            "run_as_user": self.probe_os_user,
            "psql_path": self.psql_path,
            "socket_directory": self.socket_directory,
            "port": self.port,
            "database_user": self.probe_database_user,
            "database_user_is_superuser": False,
            "database_user_bypass_rls": False,
        }

    @property
    def admin_gate_connection(self) -> dict[str, object]:
        return {
            "runuser_path": self.runuser_path,
            "run_as_user": self.admin_os_user,
            "psql_path": self.psql_path,
            "socket_directory": self.socket_directory,
            "port": self.port,
            "database_user": self.admin_database_user,
            "database_user_is_superuser": True,
            "database_user_bypass_rls": True,
        }

    @property
    def configuration_gate(self) -> dict[str, object]:
        account = __import__("pwd").getpwnam(self.admin_os_user)
        group = __import__("grp").getgrgid(account.pw_gid)
        settings = json.loads(
            self.scalar(
                "SELECT pg_catalog.json_build_object("
                "'data_directory',current_setting('data_directory'),"
                "'config_file',current_setting('config_file'),"
                "'hba_file',current_setting('hba_file'))::pg_catalog.text"
            )
        )
        return {
            **self.admin_gate_connection,
            "run_as_group": group.gr_name,
            "run_as_uid": account.pw_uid,
            "run_as_gid": group.gr_gid,
            "maintenance_database": "postgres",
            **settings,
        }

    def attestation_context(
        self,
    ) -> tuple[dict[str, object], dict[str, object]]:
        data_directory = Path(self.scalar("SHOW data_directory"))
        pid_lines = (data_directory / "postmaster.pid").read_text(
            encoding="utf-8"
        ).splitlines()
        assert pid_lines and pid_lines[0].isdigit()
        postmaster_pid = int(pid_lines[0])
        account = __import__("pwd").getpwnam(self.admin_os_user)
        group = __import__("grp").getgrgid(account.pw_gid)
        executable = str(Path(f"/proc/{postmaster_pid}/exe").resolve(strict=True))
        cgroups = [
            line.rsplit(":", 1)[-1]
            for line in Path(f"/proc/{postmaster_pid}/cgroup")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        assert cgroups and all(value.startswith("/") for value in cgroups)
        control_group = max(set(cgroups), key=lambda value: (len(value), value))
        namespace_identity = gate._process_namespace_identity(postmaster_pid)
        cluster_postgresql: dict[str, object] = {
            "run_as_user": account.pw_name,
            "run_as_group": group.gr_name,
            "run_as_uid": account.pw_uid,
            "run_as_gid": group.gr_gid,
            "postgres_path": executable,
            "expected_control_group": control_group,
        }
        postmaster: dict[str, object] = {
            "pid": postmaster_pid,
            "namespace_identity_sha256": namespace_identity,
        }
        return cluster_postgresql, postmaster

    def new_database(
        self,
        label: str,
        *,
        relation_kind: str = "table",
        key_type: str = "varchar",
        relation_owner: str | None = None,
    ) -> str:
        assert SAFE_IDENTIFIER.fullmatch(label)
        assert relation_kind in {"table", "view"}
        assert key_type in {"varchar", "text"}
        owner = relation_owner or self.probe_database_user
        assert SAFE_IDENTIFIER.fullmatch(owner)
        self.counter += 1
        database = f"dev18_it_{os.getpid()}_{self.counter}_{label}"[:63]
        assert SAFE_IDENTIFIER.fullmatch(database)
        self.run(f"CREATE DATABASE {database} OWNER {self.admin_database_user}")
        self.created_databases.append(database)
        self.run(
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC; "
            f"CREATE SCHEMA attacker AUTHORIZATION {self.probe_database_user}; "
            f"GRANT CREATE ON SCHEMA public TO {owner}; "
            f"ALTER ROLE {self.probe_database_user} IN DATABASE {database} "
            "SET search_path TO attacker, pg_catalog, public;",
            database=database,
        )
        if relation_kind == "view":
            self.run(
                f"CREATE TABLE public.dev18_uuid_source (key {key_type}, value text); "
                "INSERT INTO public.dev18_uuid_source(key, value) "
                "VALUES ('database.uuid', '11111111-2222-4333-8444-555555555555'); "
                "CREATE VIEW public.ir_config_parameter AS "
                "SELECT key, value FROM public.dev18_uuid_source; "
                f"ALTER VIEW public.ir_config_parameter OWNER TO {owner}; "
                f"GRANT SELECT ON public.dev18_uuid_source TO {owner}; "
                f"GRANT SELECT ON public.ir_config_parameter TO {self.probe_database_user};",
                database=database,
            )
        else:
            self.run(
                f"CREATE TABLE public.ir_config_parameter (key {key_type}, value text); "
                f"ALTER TABLE public.ir_config_parameter OWNER TO {owner}; "
                "INSERT INTO public.ir_config_parameter(key, value) "
                "VALUES ('database.uuid', '11111111-2222-4333-8444-555555555555'); "
                f"GRANT SELECT ON public.ir_config_parameter TO {self.probe_database_user};",
                database=database,
            )
        assert self.scalar(
            f"SELECT pg_catalog.has_schema_privilege("
            f"'{owner}','public','CREATE')::text",
            database=database,
        ) == "true"
        assert self.scalar(
            "SELECT r.rolname FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner "
            "WHERE n.nspname = 'public'::pg_catalog.name "
            "AND c.relname = 'ir_config_parameter'::pg_catalog.name",
            database=database,
        ) == owner
        return database

    def run_as_probe(self, database: str, query: str) -> subprocess.CompletedProcess[str]:
        return self.run(
            query,
            database=database,
            os_user=self.probe_os_user,
            database_user=self.probe_database_user,
        )

    def drop_created_databases(self) -> None:
        for database in reversed(self.created_databases):
            self.run(
                f"DROP DATABASE IF EXISTS {database} WITH (FORCE)",
                check=False,
            )


@pytest.fixture(scope="session")
def postgres() -> PostgreSQLHarness:
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        pytest.fail("the enabled PostgreSQL integration gate must run as Linux root")
    harness = PostgreSQLHarness(
        psql_path=_required_environment("DEV18_PG_PSQL", "/usr/bin/psql"),
        runuser_path=_required_environment("DEV18_PG_RUNUSER", "/usr/sbin/runuser"),
        socket_directory=_required_environment(
            "DEV18_PG_SOCKET_DIRECTORY", "/var/run/postgresql"
        ),
        port=int(_required_environment("DEV18_PG_PORT", "5432")),
        admin_os_user=_required_environment("DEV18_PG_ADMIN_OS_USER", "postgres"),
        admin_database_user=_required_environment(
            "DEV18_PG_ADMIN_DATABASE_USER", "postgres"
        ),
        probe_os_user=_required_environment("DEV18_PG_PROBE_OS_USER", "odoo_probe"),
        probe_database_user=_required_environment(
            "DEV18_PG_PROBE_DATABASE_USER", "odoo_probe"
        ),
        other_database_user=_required_environment(
            "DEV18_PG_OTHER_DATABASE_USER", "odoo_probe_other"
        ),
    )
    for value in (
        harness.admin_database_user,
        harness.probe_database_user,
        harness.other_database_user,
    ):
        if SAFE_IDENTIFIER.fullmatch(value) is None:
            pytest.fail(f"unsafe integration role name: {value!r}")
    for path in (harness.psql_path, harness.runuser_path):
        if not Path(path).is_file():
            pytest.fail(f"required PostgreSQL integration executable is absent: {path}")
    role_state = json.loads(
        harness.scalar(
            "SELECT pg_catalog.json_build_object("
            "'rolsuper',r.rolsuper,'rolbypassrls',r.rolbypassrls,"
            "'rolcanlogin',r.rolcanlogin,'rolcreaterole',r.rolcreaterole,"
            "'rolcreatedb',r.rolcreatedb,'rolreplication',r.rolreplication,"
            "'membership_count',(SELECT pg_catalog.count(*) "
            "FROM pg_catalog.pg_auth_members AS m WHERE m.member = r.oid))::text "
            "FROM pg_catalog.pg_roles AS r "
            f"WHERE r.rolname = '{harness.probe_database_user}'::pg_catalog.name"
        )
    )
    assert role_state == {
        "rolsuper": False,
        "rolbypassrls": False,
        "rolcanlogin": True,
        "rolcreaterole": False,
        "rolcreatedb": True,
        "rolreplication": False,
        "membership_count": 0,
    }
    try:
        yield harness
    finally:
        harness.drop_created_databases()


def _identity_row(postgres: PostgreSQLHarness, database: str) -> dict[str, object] | None:
    rows = gate._run_psql_commands(
        postgres.gate_connection,
        database,
        [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE",
            gate._uuid_relation_identity_query(),
        ],
    )
    assert len(rows) <= 1
    return rows[0] if rows else None


def _configuration_semantic(postgres: PostgreSQLHarness) -> dict[str, object]:
    rows = gate._run_psql(
        postgres.admin_gate_connection,
        "postgres",
        gate.POSTGRESQL_CONFIGURATION_QUERY,
    )
    assert len(rows) == 1 and isinstance(rows[0], dict)
    return rows[0]


def test_configuration_query_is_strict_stable_and_password_sensitive(
    postgres: PostgreSQLHarness,
) -> None:
    first = _configuration_semantic(postgres)
    second = _configuration_semantic(postgres)
    assert gate._canonical_sha256(first) == gate._canonical_sha256(second)
    assert set(first) == gate.CONFIGURATION_SNAPSHOT_COMPONENTS - {
        "configuration_files"
    }
    roles = first["roles"]
    assert roles and all("rolpassword" not in role for role in roles)
    password_identity = first["role_password_identity"]
    assert len(password_identity) == 1
    original_digest = password_identity[0]["role_password_vector_sha256"]
    password_literal = "Dev18IntegrationOnly-20260717!"
    try:
        postgres.run(
            f"ALTER ROLE {postgres.other_database_user} PASSWORD '{password_literal}'"
        )
        changed = _configuration_semantic(postgres)
        assert (
            changed["role_password_identity"][0]["role_password_vector_sha256"]
            != original_digest
        )
        assert password_literal not in json.dumps(changed, sort_keys=True)
    finally:
        postgres.run(f"ALTER ROLE {postgres.other_database_user} PASSWORD NULL")


def test_configuration_capture_rejects_unloaded_hba_then_accepts_reload(
    postgres: PostgreSQLHarness,
) -> None:
    configuration = postgres.configuration_gate
    baseline = gate._capture_postgresql_configuration(
        configuration, deadline_ns=None
    )
    assert gate.HEX64.fullmatch(baseline) is not None
    hba_path = Path(str(configuration["hba_file"]))
    original = hba_path.read_bytes()
    marker = b"\n# dev18 stale-load integration marker\n"

    def reload_and_wait() -> str:
        result = postgres.scalar("SELECT pg_catalog.pg_reload_conf()::text")
        assert result == "true"
        deadline = time.monotonic() + 10
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return gate._capture_postgresql_configuration(
                    configuration, deadline_ns=None
                )
            except gate.CapacityGateError as exc:
                last_error = exc
                time.sleep(0.05)
        raise AssertionError(f"configuration reload was not observed: {last_error}")

    try:
        hba_path.write_bytes(original + marker)
        with pytest.raises(gate.CapacityGateError, match="newer than PostgreSQL"):
            gate._capture_postgresql_configuration(configuration, deadline_ns=None)
        loaded = reload_and_wait()
        assert loaded != baseline
    finally:
        hba_path.write_bytes(original)
        reload_and_wait()


def test_physical_preflight_rejects_unspaced_session_preload_before_sql_probe(
    postgres: PostgreSQLHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = postgres.configuration_gate
    configuration.update(
        {
            "psql_sha256": "0" * 64,
            "runuser_sha256": "0" * 64,
            "systemctl_path": "/usr/bin/systemctl",
            "systemctl_sha256": "0" * 64,
            "pg_controldata_path": "/usr/lib/postgresql/16/bin/pg_controldata",
            "pg_controldata_sha256": "0" * 64,
            "postgres_path": "/usr/lib/postgresql/16/bin/postgres",
            "postgres_sha256": "0" * 64,
        }
    )
    monkeypatch.setattr(gate, "_verify_root_executable", lambda *args: ())
    monkeypatch.setattr(gate, "_verify_postgresql_socket", lambda *args: ())
    monkeypatch.setattr(
        gate,
        "_capture_socket_group_membership",
        lambda *args: ("0" * 64, []),
    )
    monkeypatch.setattr(
        gate,
        "_capture_systemd_service",
        lambda *args, **kwargs: ({"MainPID": "1"}, "0" * 64, "0" * 64),
    )
    monkeypatch.setattr(gate, "_verify_postgresql_process", lambda *args: {})
    direct_probes: list[str] = []

    def forbidden_direct_probe(*args, **kwargs):
        direct_probes.append("reached")
        raise AssertionError("a direct PostgreSQL probe ran before physical preflight")

    monkeypatch.setattr(gate, "_run_pg_controldata", forbidden_direct_probe)
    monkeypatch.setattr(gate, "_capture_system_probe", forbidden_direct_probe)
    monkeypatch.setattr(gate, "_run_psql", forbidden_direct_probe)

    config_path = Path(str(configuration["config_file"]))
    original = config_path.read_bytes()
    tripwire = b"\nsession_preload_libraries='dev18_missing_tripwire'\n"
    assert "-c session_preload_libraries= " in gate._psql_environment(
        privileged=True
    )["PGOPTIONS"]
    try:
        config_path.write_bytes(original + tripwire)
        with pytest.raises(gate.CapacityGateError, match="session_preload_libraries"):
            gate._capture_postgresql(
                {"postgresql": configuration}, deadline_ns=None
            )
        assert direct_probes == []
    finally:
        config_path.write_bytes(original)
        assert postgres.scalar("SELECT pg_catalog.pg_reload_conf()::text") == "true"


def test_postgres_accepts_uppercase_long_guc_but_gate_rejects_it(
    postgres: PostgreSQLHarness,
) -> None:
    configuration = postgres.configuration_gate
    cluster_postgresql, _ = postgres.attestation_context()
    base_arguments = [
        str(cluster_postgresql["postgres_path"]),
        "-D",
        str(configuration["data_directory"]),
        "-c",
        f"config_file={configuration['config_file']}",
    ]
    uppercase_preload = "--SHARED_PRELOAD_LIBRARIES=dev18_case_probe"
    completed = subprocess.run(
        [
            postgres.runuser_path,
            "-u",
            postgres.admin_os_user,
            "--",
            *base_arguments,
            uppercase_preload,
            "-C",
            "shared_preload_libraries",
        ],
        check=False,
        capture_output=True,
        cwd="/",
        env=postgres._environment(),
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "dev18_case_probe"

    with pytest.raises(gate.CapacityGateError, match="shared_preload_libraries"):
        gate._validate_postgresql_process_arguments(
            [*base_arguments, uppercase_preload],
            data_directory=str(configuration["data_directory"]),
            config_file=str(configuration["config_file"]),
        )
    with pytest.raises(gate.CapacityGateError, match="configuration file"):
        gate._validate_postgresql_process_arguments(
            [*base_arguments, "--CONFIG_FILE=/tmp/unreviewed.conf"],
            data_directory=str(configuration["data_directory"]),
            config_file=str(configuration["config_file"]),
        )


def _raw_gate_transaction(
    postgres: PostgreSQLHarness,
    database: str,
    queries: list[str],
    *,
    timeout: float = 20,
) -> subprocess.CompletedProcess[str]:
    command = gate._psql_command(postgres.gate_connection, database)
    command.append("--single-transaction")
    for query in queries:
        command.extend(("-c", query))
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd="/",
        env=gate._psql_environment(),
        text=True,
        timeout=timeout,
    )


def _assert_stopped_before_sentinel(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode != 0
    assert "DEV18_ASSERTION_REACHED" in result.stdout
    assert "DEV18_SENTINEL_MUST_NOT_RUN" not in result.stdout
    assert "DEV18_SENTINEL_MUST_NOT_RUN" not in result.stderr
    assert "division by zero" in result.stderr


PRE_ASSERTION_QUERY = (
    "SELECT pg_catalog.json_build_object("
    "'marker','DEV18_ASSERTION_REACHED')::pg_catalog.text"
)
SENTINEL_QUERY = (
    "SELECT pg_catalog.json_build_object("
    "'sentinel','DEV18_SENTINEL_MUST_NOT_RUN')::pg_catalog.text"
)


def test_real_uuid_probe_uses_sql_digest_direct_non_superuser_and_hostile_search_path(
    postgres: PostgreSQLHarness,
) -> None:
    database = postgres.new_database("valid")
    postgres.run_as_probe(
        database,
        "CREATE TABLE attacker.ir_config_parameter(key varchar, value text); "
        "CREATE FUNCTION attacker.sha256(bytea) RETURNS bytea "
        "LANGUAGE plpgsql IMMUTABLE AS $$BEGIN "
        "RAISE EXCEPTION 'DEV18_HOSTILE_SHA256_EXECUTED'; END$$; "
        "CREATE FUNCTION attacker.current_setting(text) RETURNS text "
        "LANGUAGE plpgsql STABLE AS $$BEGIN "
        "RAISE EXCEPTION 'DEV18_HOSTILE_SETTING_EXECUTED'; END$$;",
    )
    shadow_resolution = postgres.run_as_probe(
        database,
        "SELECT pg_catalog.to_regprocedure('sha256(bytea)')::pg_catalog.oid "
        "OPERATOR(pg_catalog.=) p.oid "
        "FROM pg_catalog.pg_proc AS p "
        "JOIN pg_catalog.pg_namespace AS n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace "
        "WHERE n.nspname OPERATOR(pg_catalog.=) 'attacker'::pg_catalog.name "
        "AND p.proname OPERATOR(pg_catalog.=) 'sha256'::pg_catalog.name",
    )
    assert shadow_resolution.stdout.strip() == "t"
    postgres.run_as_probe(
        database,
        "CREATE UNIQUE INDEX dev18_safe_key_index "
        "ON public.ir_config_parameter(key); "
        "CREATE STATISTICS dev18_safe_statistics "
        "ON key, value FROM public.ir_config_parameter;",
    )

    identity = _identity_row(postgres, database)
    assert identity is not None
    payload = identity["identity_payload"]
    digest = identity["identity_sha256"]
    assert isinstance(payload, str)
    assert isinstance(digest, str)
    assert hashlib.sha256(payload.encode("utf-8")).hexdigest() == digest
    relation = json.loads(payload)
    assert relation["database_name"] == database
    assert relation["database_owner"] == postgres.admin_database_user
    assert relation["relation_owner"] == postgres.probe_database_user
    validated_relation = gate._validate_uuid_relation_identity(
        relation,
        {
            "oid": relation["database_oid"],
            "owner": postgres.admin_database_user,
        },
        {
            "name": database,
            "uuid_probe_database_user": postgres.probe_database_user,
        },
    )
    assert len(validated_relation["indexes"]) == 1
    assert len(validated_relation["statistics"]) == 1

    authority_query = (
        "SELECT pg_catalog.json_build_object("
        "'session_user',SESSION_USER,'current_user',CURRENT_USER,"
        "'is_superuser',(SELECT r.rolsuper FROM pg_catalog.pg_roles AS r "
        "WHERE r.rolname = SESSION_USER),"
        "'bypass_rls',(SELECT r.rolbypassrls FROM pg_catalog.pg_roles AS r "
        "WHERE r.rolname = SESSION_USER),"
        "'search_path',pg_catalog.current_setting('search_path'))::pg_catalog.text"
    )
    rows = gate._run_psql_commands(
        postgres.gate_connection,
        database,
        [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE",
            gate._uuid_relation_assertion_query(postgres.gate_connection, digest),
            gate._uuid_relation_identity_query(),
            gate.UUID_VALUE_QUERY,
            authority_query,
        ],
    )
    assert rows[0] == {"relation_safe": True}
    assert rows[1] == identity
    assert rows[2]["read_only"] == "on"
    assert rows[2]["uuid"] == "11111111-2222-4333-8444-555555555555"
    assert rows[3] == {
        "session_user": postgres.probe_database_user,
        "current_user": postgres.probe_database_user,
        "is_superuser": False,
        "bypass_rls": False,
        "search_path": "pg_catalog",
    }


def test_interactive_runner_attests_live_backend_before_and_after_uuid_probe(
    postgres: PostgreSQLHarness,
) -> None:
    database = postgres.new_database("attested")
    cluster_postgresql, postmaster = postgres.attestation_context()
    identity_rows, backend_identity_sha256 = gate._run_attested_psql_commands(
        postgres.gate_connection,
        cluster_postgresql,
        postmaster,
        database,
        [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE",
            gate._uuid_relation_identity_query(),
        ],
        deadline_ns=None,
    )
    assert len(identity_rows) == 1
    assert gate.HEX64.fullmatch(backend_identity_sha256) is not None
    identity = identity_rows[0]
    digest = str(identity["identity_sha256"])

    rows = gate._run_psql_commands(
        postgres.gate_connection,
        database,
        [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE",
            gate._uuid_relation_assertion_query(postgres.gate_connection, digest),
            gate._uuid_relation_identity_query(),
            gate.UUID_VALUE_QUERY,
            gate._uuid_relation_identity_query(),
        ],
        postmaster=postmaster,
        cluster_postgresql=cluster_postgresql,
    )
    assert rows[0] == {"relation_safe": True}
    assert rows[1] == identity == rows[3]
    assert rows[2] == {
        "read_only": "on",
        "session_user": postgres.probe_database_user,
        "current_user": postgres.probe_database_user,
        "current_user_is_superuser": False,
        "current_user_bypass_rls": False,
        "uuid": "11111111-2222-4333-8444-555555555555",
    }


@pytest.mark.parametrize(
    ("failure", "relation_kind", "key_type", "relation_owner"),
    [
        ("wrong_digest", "table", "varchar", None),
        ("view", "view", "varchar", None),
        ("wrong_type", "table", "text", None),
        ("wrong_owner", "table", "varchar", "other"),
    ],
)
def test_invalid_relation_or_digest_stops_before_later_query(
    postgres: PostgreSQLHarness,
    failure: str,
    relation_kind: str,
    key_type: str,
    relation_owner: str | None,
) -> None:
    owner = (
        postgres.other_database_user if relation_owner == "other" else None
    )
    database = postgres.new_database(
        failure,
        relation_kind=relation_kind,
        key_type=key_type,
        relation_owner=owner,
    )
    identity = None if relation_kind == "view" else _identity_row(postgres, database)
    digest = "0" * 64
    if failure == "view":
        assert postgres.scalar(
            "SELECT c.relkind::text FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public'::pg_catalog.name "
            "AND c.relname = 'ir_config_parameter'::pg_catalog.name",
            database=database,
        ) == "v"
    else:
        assert identity is not None
        relation = json.loads(str(identity["identity_payload"]))
        if failure == "wrong_type":
            key_column = next(
                column for column in relation["columns"] if column["name"] == "key"
            )
            assert key_column["type_oid"] == "25"
        if failure == "wrong_owner":
            assert relation["relation_owner"] == postgres.other_database_user
            assert relation["relation_owner_is_superuser"] is False
            assert relation["relation_owner_bypass_rls"] is False
            assert relation["relation_owner_can_login"] is True
            assert relation["relation_owner_create_role"] is False
            assert relation["relation_owner_createdb"] is True
            assert relation["relation_owner_replication"] is False
            assert relation["relation_owner_membership_count"] == 0
    if identity is not None and failure != "wrong_digest":
        digest = str(identity["identity_sha256"])
    queries = ["SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"]
    if relation_kind != "view":
        queries.append(
            "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE"
        )
    queries.extend(
        (
            PRE_ASSERTION_QUERY,
            gate._uuid_relation_assertion_query(postgres.gate_connection, digest),
            SENTINEL_QUERY,
        )
    )
    result = _raw_gate_transaction(postgres, database, queries)
    _assert_stopped_before_sentinel(result)


def test_access_share_lock_blocks_concurrent_relation_ddl(
    postgres: PostgreSQLHarness,
) -> None:
    database = postgres.new_database("lock")
    identity = _identity_row(postgres, database)
    assert identity is not None
    digest = str(identity["identity_sha256"])
    hold_query = (
        "SELECT pg_catalog.json_build_object("
        "'hold',pg_catalog.current_setting('transaction_read_only'))::pg_catalog.text "
        "FROM pg_catalog.pg_sleep(8)"
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        held = executor.submit(
            _raw_gate_transaction,
            postgres,
            database,
            [
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
                "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE",
                gate._uuid_relation_assertion_query(
                    postgres.gate_connection, digest
                ),
                hold_query,
            ],
        )
        deadline = time.monotonic() + 5
        lock_count = "0"
        while time.monotonic() < deadline:
            lock_count = postgres.scalar(
                "SELECT pg_catalog.count(*)::text "
                "FROM pg_catalog.pg_locks AS l "
                "JOIN pg_catalog.pg_class AS c ON c.oid = l.relation "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
                "JOIN pg_catalog.pg_stat_activity AS a ON a.pid = l.pid "
                f"WHERE a.datname = '{database}'::pg_catalog.name "
                f"AND a.usename = '{postgres.probe_database_user}'::pg_catalog.name "
                "AND n.nspname = 'public'::pg_catalog.name "
                "AND c.relname = 'ir_config_parameter'::pg_catalog.name "
                "AND l.mode = 'AccessShareLock' AND l.granted",
                database=database,
            )
            if lock_count == "1":
                break
            time.sleep(0.05)
        assert lock_count == "1"
        ddl = postgres.run(
            "ALTER TABLE public.ir_config_parameter ADD COLUMN must_block integer",
            database=database,
            pgoptions="-c lock_timeout=500ms -c statement_timeout=2000ms",
            check=False,
        )
        assert ddl.returncode != 0
        assert "lock timeout" in ddl.stderr
        held_result = held.result(timeout=15)
    assert held_result.returncode == 0, held_result.stderr


@pytest.mark.parametrize("index_kind", ["expression", "partial"])
def test_unsafe_index_is_rejected_without_executing_owner_function(
    postgres: PostgreSQLHarness,
    index_kind: str,
) -> None:
    database = postgres.new_database(f"index_{index_kind}")
    if index_kind == "expression":
        postgres.run_as_probe(
            database,
            "CREATE FUNCTION attacker.dev18_tripwire(text) RETURNS text "
            "LANGUAGE sql IMMUTABLE AS $$SELECT $1$$; "
            "CREATE INDEX dev18_expression_index ON public.ir_config_parameter "
            "((attacker.dev18_tripwire(value))); "
            "CREATE OR REPLACE FUNCTION attacker.dev18_tripwire(text) RETURNS text "
            "LANGUAGE plpgsql IMMUTABLE AS $$BEGIN "
            "RAISE EXCEPTION 'DEV18_OWNER_FUNCTION_EXECUTED'; END$$;",
        )
    else:
        postgres.run_as_probe(
            database,
            "CREATE FUNCTION attacker.dev18_tripwire(text) RETURNS boolean "
            "LANGUAGE sql IMMUTABLE AS $$SELECT $1 IS NOT NULL$$; "
            "CREATE INDEX dev18_partial_index ON public.ir_config_parameter(key) "
            "WHERE attacker.dev18_tripwire(key); "
            "CREATE OR REPLACE FUNCTION attacker.dev18_tripwire(text) RETURNS boolean "
            "LANGUAGE plpgsql IMMUTABLE AS $$BEGIN "
            "RAISE EXCEPTION 'DEV18_OWNER_FUNCTION_EXECUTED'; END$$;",
        )

    identity = _identity_row(postgres, database)
    assert identity is not None
    indexes = json.loads(str(identity["identity_payload"]))["indexes"]
    assert len(indexes) == 1
    assert indexes[0][
        "has_expressions" if index_kind == "expression" else "has_predicate"
    ] is True
    result = _raw_gate_transaction(
        postgres,
        database,
        [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "LOCK TABLE ONLY public.ir_config_parameter IN ACCESS SHARE MODE",
            PRE_ASSERTION_QUERY,
            gate._uuid_relation_assertion_query(
                postgres.gate_connection, str(identity["identity_sha256"])
            ),
            gate.UUID_VALUE_QUERY,
            SENTINEL_QUERY,
        ],
    )
    _assert_stopped_before_sentinel(result)
    combined_output = result.stdout + result.stderr
    assert "DEV18_OWNER_FUNCTION_EXECUTED" not in combined_output

from __future__ import annotations

import ast
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest


RUN_INTEGRATION = os.environ.get("DEV22_MODULE_GUARD_POSTGRES") == "1"
SAFE_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
GUARD_PROTOCOL_VERSION = 1
ADVISORY_KEY_PARTS = (1329677142, 1297040433)
PENDING_STATES = ("to install", "to remove", "to upgrade")
_STREAM_EOF = object()
ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = (
    ROOT
    / "odoo_addons"
    / "odoo_accounting_cli_v3_control"
    / "sql"
    / "module_guard_v1.sql"
)
GUARD_OWNER = "odoo_accounting_cli_v3_guard_owner"

pytestmark = pytest.mark.skipif(
    not RUN_INTEGRATION,
    reason=(
        "set DEV22_MODULE_GUARD_POSTGRES=1 for the isolated PostgreSQL "
        "module-guard gate"
    ),
)


def _required_environment(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        pytest.fail(f"required PostgreSQL integration setting is absent: {name}")
    return value


class InteractivePsql:
    def __init__(
        self,
        command: list[str],
        *,
        environment: dict[str, str],
    ) -> None:
        self._process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=environment,
            text=True,
            bufsize=1,
        )
        assert self._process.stdin is not None
        assert self._process.stdout is not None
        assert self._process.stderr is not None
        self._stdout: queue.Queue[object] = queue.Queue()
        self._stderr: list[str] = []
        self._counter = 0
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name=f"dev22-psql-stdout-{self._process.pid}",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            name=f"dev22-psql-stderr-{self._process.pid}",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    @property
    def process(self) -> subprocess.Popen[str]:
        return self._process

    def _read_stdout(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            self._stdout.put(line.rstrip("\r\n"))
        self._stdout.put(_STREAM_EOF)

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._stderr.append(line.rstrip("\r\n"))

    def _stderr_text(self) -> str:
        return "\n".join(self._stderr)

    def execute(self, sql: str, *, timeout: float = 10) -> list[str]:
        if self._process.poll() is not None:
            raise AssertionError(
                "the interactive PostgreSQL session exited before its command: "
                f"returncode={self._process.returncode} stderr={self._stderr_text()}"
            )
        self._counter += 1
        marker = f"__DEV22_PSQL_{self._process.pid}_{self._counter}__"
        assert self._process.stdin is not None
        self._process.stdin.write(f"{sql.rstrip()}\n\\echo {marker}\n")
        self._process.stdin.flush()
        output: list[str] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "timed out waiting for the interactive PostgreSQL marker: "
                    f"{marker}; stderr={self._stderr_text()}"
                )
            try:
                line = self._stdout.get(timeout=remaining)
            except queue.Empty as exc:
                raise AssertionError(
                    "timed out waiting for interactive PostgreSQL output: "
                    f"{marker}; stderr={self._stderr_text()}"
                ) from exc
            if line is _STREAM_EOF:
                raise AssertionError(
                    "the interactive PostgreSQL session exited before its marker: "
                    f"returncode={self._process.poll()} stderr={self._stderr_text()}"
                )
            assert isinstance(line, str)
            if line == marker:
                return output
            if line:
                output.append(line)

    def close(self) -> None:
        if self._process.poll() is None:
            assert self._process.stdin is not None
            try:
                self._process.stdin.write("ROLLBACK;\n\\q\n")
                self._process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)

    def __enter__(self) -> InteractivePsql:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


@dataclass
class PostgreSQLHarness:
    psql_path: str
    runuser_path: str
    stdbuf_path: str
    socket_directory: str
    port: int
    admin_os_user: str
    admin_database_user: str
    created_databases: list[str] = field(default_factory=list)
    created_roles: list[str] = field(default_factory=list)
    counter: int = 0

    @staticmethod
    def environment(*, pgoptions: str | None = None) -> dict[str, str]:
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        if pgoptions is not None:
            environment["PGOPTIONS"] = pgoptions
        return environment

    def command(self, database: str) -> list[str]:
        assert SAFE_IDENTIFIER.fullmatch(database)
        return [
            self.runuser_path,
            "-u",
            self.admin_os_user,
            "--",
            self.stdbuf_path,
            "-oL",
            "-eL",
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
            self.admin_database_user,
            "-d",
            database,
        ]

    def run(
        self,
        query: str,
        *,
        database: str = "postgres",
        pgoptions: str | None = None,
        check: bool = True,
        timeout: float = 10,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [*self.command(database), "-c", query],
            check=check,
            capture_output=True,
            cwd="/",
            env=self.environment(pgoptions=pgoptions),
            text=True,
            timeout=timeout,
        )

    def run_file(
        self,
        path: Path,
        *,
        database: str,
        variables: dict[str, str] | None = None,
        check: bool = True,
        timeout: float = 20,
    ) -> subprocess.CompletedProcess[str]:
        resolved = path.resolve(strict=True)
        command = self.command(database)
        for name, value in sorted((variables or {}).items()):
            if SAFE_IDENTIFIER.fullmatch(name) is None:
                raise AssertionError(f"unsafe psql variable name: {name!r}")
            if SAFE_IDENTIFIER.fullmatch(value) is None:
                raise AssertionError(f"unsafe psql identifier value: {value!r}")
            command.extend(["-v", f"{name}={value}"])
        command.extend(["-f", str(resolved)])
        return subprocess.run(
            command,
            check=check,
            capture_output=True,
            cwd="/",
            env=self.environment(),
            text=True,
            timeout=timeout,
        )

    def scalar(self, query: str, *, database: str = "postgres") -> str:
        return self.run(query, database=database).stdout.strip()

    def session(self, database: str) -> InteractivePsql:
        return InteractivePsql(
            self.command(database),
            environment=self.environment(),
        )

    def create_role(self, purpose: str, attributes: str = "LOGIN") -> str:
        self.counter += 1
        role = f"dev22_{purpose}_{os.getpid()}_{self.counter}"[:63]
        assert SAFE_IDENTIFIER.fullmatch(role)
        assert re.fullmatch(r"[A-Z ]+", attributes)
        self.run(f"CREATE ROLE {role} {attributes}")
        self.created_roles.append(role)
        return role

    def create_database(self) -> str:
        self.counter += 1
        database = f"dev22_guard_{os.getpid()}_{self.counter}"[:63]
        assert SAFE_IDENTIFIER.fullmatch(database)
        self.run(f"CREATE DATABASE {database} OWNER {self.admin_database_user}")
        self.created_databases.append(database)
        self.run(
            "CREATE TABLE public.ir_module_module ("
            "id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,"
            "name varchar NOT NULL UNIQUE,"
            "latest_version varchar NOT NULL,"
            "state varchar NOT NULL);"
            "INSERT INTO public.ir_module_module(name,latest_version,state) VALUES "
            "('base','19.0.1.0','installed'),"
            "('account','19.0.1.0','installed'),"
            "('sale','19.0.1.0','installed');"
            "CREATE TABLE public.dev22_writer_probe ("
            "id bigint PRIMARY KEY,value integer NOT NULL);"
            "CREATE TABLE public.odoo_accounting_cli_operation ("
            "id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,"
            "state varchar NOT NULL,"
            "execution_result_json text,"
            "verification_result_json text,"
            "recovery_result_json text);",
            database=database,
        )
        return database

    def drop_created_databases(self) -> None:
        for database in reversed(self.created_databases):
            result = self.run(
                f"DROP DATABASE IF EXISTS {database} WITH (FORCE)",
                check=False,
            )
            if result.returncode != 0:
                pytest.fail(
                    f"could not remove isolated PostgreSQL database {database}: "
                    f"{result.stderr}"
                )
        self.created_databases.clear()

    def drop_created_roles(self) -> None:
        for role in reversed(self.created_roles):
            result = self.run(f"DROP ROLE IF EXISTS {role}", check=False)
            if result.returncode != 0:
                pytest.fail(
                    f"could not remove isolated PostgreSQL role {role}: "
                    f"{result.stderr}"
                )
        self.created_roles.clear()


@pytest.fixture(scope="session")
def postgres() -> PostgreSQLHarness:
    if sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        pytest.fail("the enabled Dev22 PostgreSQL gate must run as Linux root")
    port_text = _required_environment("DEV22_PG_PORT", "5432")
    try:
        port = int(port_text)
    except ValueError:
        pytest.fail(f"invalid DEV22_PG_PORT: {port_text!r}")
    if not 1 <= port <= 65535:
        pytest.fail(f"DEV22_PG_PORT is outside 1..65535: {port}")
    harness = PostgreSQLHarness(
        psql_path=_required_environment("DEV22_PG_PSQL", "/usr/bin/psql"),
        runuser_path=_required_environment("DEV22_PG_RUNUSER", "/usr/sbin/runuser"),
        stdbuf_path=_required_environment("DEV22_PG_STDBUF", "/usr/bin/stdbuf"),
        socket_directory=_required_environment(
            "DEV22_PG_SOCKET_DIRECTORY", "/var/run/postgresql"
        ),
        port=port,
        admin_os_user=_required_environment("DEV22_PG_ADMIN_OS_USER", "postgres"),
        admin_database_user=_required_environment(
            "DEV22_PG_ADMIN_DATABASE_USER", "postgres"
        ),
    )
    if SAFE_IDENTIFIER.fullmatch(harness.admin_database_user) is None:
        pytest.fail(
            f"unsafe PostgreSQL admin role: {harness.admin_database_user!r}"
        )
    if SAFE_IDENTIFIER.fullmatch(harness.admin_os_user) is None:
        pytest.fail(f"unsafe PostgreSQL admin OS user: {harness.admin_os_user!r}")
    for executable in (
        harness.psql_path,
        harness.runuser_path,
        harness.stdbuf_path,
    ):
        if not Path(executable).is_file():
            pytest.fail(f"required PostgreSQL executable is absent: {executable}")
    socket_directory = Path(harness.socket_directory)
    socket_path = socket_directory / f".s.PGSQL.{harness.port}"
    if not socket_directory.is_absolute() or not socket_path.is_socket():
        pytest.fail(
            "Dev22 PostgreSQL integration requires a local Unix-domain socket: "
            f"{socket_path}"
        )
    version = int(harness.scalar("SHOW server_version_num"))
    if not 160000 <= version < 170000:
        pytest.fail(f"Dev22 PostgreSQL integration requires version 16, got {version}")
    authority = json.loads(
        harness.scalar(
            "SELECT pg_catalog.json_build_object("
            "'session_user',SESSION_USER,'current_user',CURRENT_USER,"
            "'is_superuser',(SELECT r.rolsuper FROM pg_catalog.pg_roles AS r "
            "WHERE r.rolname = SESSION_USER),"
            "'database',CURRENT_DATABASE())::text"
        )
    )
    expected_authority = {
        "session_user": harness.admin_database_user,
        "current_user": harness.admin_database_user,
        "is_superuser": True,
        "database": "postgres",
    }
    if authority != expected_authority:
        pytest.fail(
            "Dev22 PostgreSQL integration did not obtain its pinned authority: "
            f"expected={expected_authority!r} actual={authority!r}"
        )
    try:
        yield harness
    finally:
        harness.drop_created_databases()
        harness.drop_created_roles()


@pytest.fixture
def database(postgres: PostgreSQLHarness) -> str:
    return postgres.create_database()


def _wait_for(
    predicate: Callable[[], bool],
    *,
    description: str,
    timeout: float = 5,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {description}")


def _table_lock_count(
    postgres: PostgreSQLHarness,
    database: str,
    *,
    mode: str = "ShareLock",
    backend_pid: int | None = None,
) -> int:
    pid_filter = ""
    if backend_pid is not None:
        pid_filter = f"AND l.pid = {backend_pid} "
    return int(
        postgres.scalar(
            "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_locks AS l "
            "JOIN pg_catalog.pg_class AS c ON c.oid = l.relation "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public'::pg_catalog.name "
            "AND c.relname = 'ir_module_module'::pg_catalog.name "
            f"AND l.mode = '{mode}'::text AND l.granted {pid_filter}",
            database=database,
        )
    )


def _assert_lock_timeout(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode != 0
    assert "lock timeout" in result.stderr.lower()
    assert "statement timeout" not in result.stderr.lower()


def _blocked_mutations(
    postgres: PostgreSQLHarness,
    database: str,
) -> list[subprocess.CompletedProcess[str]]:
    pgoptions = "-c lock_timeout=350ms -c statement_timeout=2000ms"
    return [
        postgres.run(
            "UPDATE public.ir_module_module SET latest_version='19.0.1.1' "
            "WHERE name='base'",
            database=database,
            pgoptions=pgoptions,
            check=False,
            timeout=5,
        ),
        postgres.run(
            "BEGIN; LOCK TABLE ONLY public.ir_module_module IN EXCLUSIVE MODE; "
            "COMMIT",
            database=database,
            pgoptions=pgoptions,
            check=False,
            timeout=5,
        ),
        postgres.run(
            "ALTER TABLE ONLY public.ir_module_module "
            "ADD COLUMN dev22_must_block integer",
            database=database,
            pgoptions=pgoptions,
            check=False,
            timeout=5,
        ),
    ]


def test_independent_share_guard_spans_two_writer_commits_and_blocks_mutation(
    postgres: PostgreSQLHarness,
    database: str,
) -> None:
    with (
        postgres.session(database) as guard,
        postgres.session(database) as parallel_guard,
        postgres.session(database) as writer,
    ):
        guard_handshake = json.loads(
            guard.execute(
                "BEGIN; SET LOCAL lock_timeout='2s'; "
                "LOCK TABLE ONLY public.ir_module_module IN SHARE MODE; "
                "SELECT pg_catalog.json_build_object("
                f"'version',{GUARD_PROTOCOL_VERSION},"
                "'backend_pid',pg_catalog.pg_backend_pid())::text;"
            )[-1]
        )
        assert guard_handshake["version"] == GUARD_PROTOCOL_VERSION
        guard_pid = int(guard_handshake["backend_pid"])
        assert _table_lock_count(
            postgres, database, backend_pid=guard_pid
        ) == 1

        parallel_pid = int(
            parallel_guard.execute(
                "BEGIN; SET LOCAL lock_timeout='500ms'; "
                "LOCK TABLE ONLY public.ir_module_module IN SHARE MODE; "
                "SELECT pg_catalog.pg_backend_pid()::text;"
            )[-1]
        )
        assert parallel_pid != guard_pid
        assert _table_lock_count(postgres, database) == 2

        first_commit = json.loads(
            writer.execute(
                "BEGIN; INSERT INTO public.dev22_writer_probe(id,value) "
                "VALUES (1,10); "
                "SELECT pg_catalog.json_build_object("
                "'writer_pid',pg_catalog.pg_backend_pid(),"
                "'cycle',1)::text; COMMIT;"
            )[-1]
        )
        assert first_commit["cycle"] == 1
        assert first_commit["writer_pid"] not in (guard_pid, parallel_pid)
        assert _table_lock_count(
            postgres, database, backend_pid=guard_pid
        ) == 1

        second_commit = json.loads(
            writer.execute(
                "BEGIN; UPDATE public.dev22_writer_probe SET value=20 WHERE id=1; "
                "SELECT pg_catalog.json_build_object("
                "'writer_pid',pg_catalog.pg_backend_pid(),"
                "'cycle',2)::text; COMMIT;"
            )[-1]
        )
        assert second_commit == {
            "writer_pid": first_commit["writer_pid"],
            "cycle": 2,
        }
        assert postgres.scalar(
            "SELECT value::text FROM public.dev22_writer_probe WHERE id=1",
            database=database,
        ) == "20"
        assert _table_lock_count(
            postgres, database, backend_pid=guard_pid
        ) == 1

        for result in _blocked_mutations(postgres, database):
            _assert_lock_timeout(result)
        assert postgres.scalar(
            "SELECT latest_version FROM public.ir_module_module WHERE name='base'",
            database=database,
        ) == "19.0.1.0"
        assert postgres.scalar(
            "SELECT pg_catalog.count(*)::text FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name='ir_module_module' "
            "AND column_name='dev22_must_block'",
            database=database,
        ) == "0"

        parallel_guard.execute("COMMIT;")
        assert _table_lock_count(postgres, database) == 1
        guard.execute("COMMIT;")
        assert _table_lock_count(postgres, database) == 0

        postgres.run(
            "UPDATE public.ir_module_module SET latest_version='19.0.1.1' "
            "WHERE name='base'",
            database=database,
        )
        postgres.run(
            "BEGIN; LOCK TABLE ONLY public.ir_module_module IN EXCLUSIVE MODE; COMMIT",
            database=database,
        )
        postgres.run(
            "ALTER TABLE ONLY public.ir_module_module "
            "ADD COLUMN dev22_must_block integer",
            database=database,
        )
        assert postgres.scalar(
            "SELECT latest_version FROM public.ir_module_module WHERE name='base'",
            database=database,
        ) == "19.0.1.1"
        assert postgres.scalar(
            "SELECT pg_catalog.count(*)::text FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name='ir_module_module' "
            "AND column_name='dev22_must_block'",
            database=database,
        ) == "1"


def _pending_modules(postgres: PostgreSQLHarness, database: str) -> list[object]:
    states = ",".join(f"'{state}'" for state in PENDING_STATES)
    payload = postgres.scalar(
        "SELECT COALESCE(pg_catalog.json_agg("
        "pg_catalog.json_build_object("
        "'name',name,'state',state,'latest_version',latest_version) "
        "ORDER BY name), '[]'::json)::text "
        "FROM public.ir_module_module "
        f"WHERE state IN ({states})",
        database=database,
    )
    value = json.loads(payload)
    assert isinstance(value, list)
    return value


def test_pending_state_and_same_version_dml_are_detectable(
    postgres: PostgreSQLHarness,
    database: str,
) -> None:
    assert _pending_modules(postgres, database) == []
    postgres.run(
        "INSERT INTO public.ir_module_module(name,latest_version,state) VALUES "
        "('dev22_install','19.0.1.0','to install'),"
        "('dev22_remove','19.0.1.0','to remove'),"
        "('dev22_upgrade','19.0.1.0','to upgrade')",
        database=database,
    )
    assert _pending_modules(postgres, database) == [
        {
            "name": "dev22_install",
            "state": "to install",
            "latest_version": "19.0.1.0",
        },
        {
            "name": "dev22_remove",
            "state": "to remove",
            "latest_version": "19.0.1.0",
        },
        {
            "name": "dev22_upgrade",
            "state": "to upgrade",
            "latest_version": "19.0.1.0",
        },
    ]
    initial_xmin = postgres.scalar(
        "SELECT xmin::text FROM public.ir_module_module WHERE name='account'",
        database=database,
    )

    with postgres.session(database) as guard:
        guarded_pending = guard.execute(
            "BEGIN; LOCK TABLE ONLY public.ir_module_module IN SHARE MODE; "
            "SELECT COALESCE(pg_catalog.json_agg("
            "pg_catalog.json_build_object('name',name,'state',state) "
            "ORDER BY name), '[]'::json)::text "
            "FROM public.ir_module_module "
            "WHERE state IN ('to install','to remove','to upgrade');"
        )[-1]
        assert len(json.loads(guarded_pending)) == 3
        same_version = postgres.run(
            "UPDATE public.ir_module_module SET latest_version=latest_version "
            "WHERE name='account' AND latest_version='19.0.1.0'",
            database=database,
            pgoptions="-c lock_timeout=350ms -c statement_timeout=2000ms",
            check=False,
            timeout=5,
        )
        _assert_lock_timeout(same_version)
        assert postgres.scalar(
            "SELECT xmin::text FROM public.ir_module_module WHERE name='account'",
            database=database,
        ) == initial_xmin
        guard.execute("COMMIT;")

    postgres.run(
        "UPDATE public.ir_module_module SET latest_version=latest_version "
        "WHERE name='account' AND latest_version='19.0.1.0'",
        database=database,
    )
    assert postgres.scalar(
        "SELECT xmin::text FROM public.ir_module_module WHERE name='account'",
        database=database,
    ) != initial_xmin


def _try_advisory(
    postgres: PostgreSQLHarness,
    database: str,
    function: str,
) -> bool:
    key_a, key_b = ADVISORY_KEY_PARTS
    result = postgres.scalar(
        f"SELECT pg_catalog.{function}({key_a},{key_b})::text",
        database=database,
    )
    assert result in {"t", "f"}
    return result == "t"


def test_fixed_session_advisory_lock_commit_unlock_and_disconnect_semantics(
    postgres: PostgreSQLHarness,
    database: str,
) -> None:
    key_a, key_b = ADVISORY_KEY_PARTS
    with (
        postgres.session(database) as shared_guard,
        postgres.session(database) as parallel_shared_guard,
    ):
        handshake = json.loads(
            shared_guard.execute(
                f"BEGIN; SELECT pg_catalog.pg_advisory_lock_shared({key_a},{key_b}); "
                "COMMIT; SELECT pg_catalog.json_build_object("
                f"'version',{GUARD_PROTOCOL_VERSION},"
                "'backend_pid',pg_catalog.pg_backend_pid())::text;"
            )[-1]
        )
        assert handshake["version"] == GUARD_PROTOCOL_VERSION
        shared_pid = int(handshake["backend_pid"])
        assert not _try_advisory(
            postgres, database, "pg_try_advisory_lock"
        )

        second_cycle = shared_guard.execute(
            "BEGIN; SELECT 1; COMMIT; "
            "SELECT pg_catalog.pg_backend_pid()::text;"
        )
        assert int(second_cycle[-1]) == shared_pid
        assert not _try_advisory(
            postgres, database, "pg_try_advisory_lock"
        )

        parallel_shared_guard.execute(
            f"SELECT pg_catalog.pg_advisory_lock_shared({key_a},{key_b});"
        )
        assert not _try_advisory(
            postgres, database, "pg_try_advisory_lock"
        )

        wrong_key = shared_guard.execute(
            "SELECT pg_catalog.pg_advisory_unlock_shared("
            f"{key_a},{key_b + 1})::text;"
        )
        wrong_mode = shared_guard.execute(
            f"SELECT pg_catalog.pg_advisory_unlock({key_a},{key_b})::text;"
        )
        assert wrong_key[-1] == "f"
        assert wrong_mode[-1] == "f"
        assert not _try_advisory(
            postgres, database, "pg_try_advisory_lock"
        )

        assert shared_guard.execute(
            f"SELECT pg_catalog.pg_advisory_unlock_shared({key_a},{key_b})::text;"
        )[-1] == "t"
        assert not _try_advisory(
            postgres, database, "pg_try_advisory_lock"
        )
        assert parallel_shared_guard.execute(
            f"SELECT pg_catalog.pg_advisory_unlock_shared({key_a},{key_b})::text;"
        )[-1] == "t"
        assert _try_advisory(postgres, database, "pg_try_advisory_lock")

    disconnected = postgres.session(database)
    try:
        disconnected_pid = int(
            disconnected.execute(
                f"SELECT pg_catalog.pg_advisory_lock({key_a},{key_b}); "
                "SELECT pg_catalog.pg_backend_pid()::text;"
            )[-1]
        )
        assert not _try_advisory(
            postgres, database, "pg_try_advisory_lock_shared"
        )
        assert postgres.scalar(
            f"SELECT pg_catalog.pg_terminate_backend({disconnected_pid})::text",
            database=database,
        ) == "t"
        _wait_for(
            lambda: int(
                postgres.scalar(
                    "SELECT pg_catalog.count(*)::text "
                    "FROM pg_catalog.pg_locks "
                    f"WHERE locktype='advisory' AND pid={disconnected_pid}",
                    database=database,
                )
            )
            == 0,
            description="the disconnected backend to release its advisory lock",
        )
        assert _try_advisory(
            postgres, database, "pg_try_advisory_lock_shared"
        )
    finally:
        disconnected.close()


def _guard_state(postgres: PostgreSQLHarness, database: str) -> dict[str, object]:
    value = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.row_to_json(state)::text FROM ("
            "SELECT protocol_version,schema_version,guard_installation_id::text,"
            "database_oid::bigint,database_uuid::text,epoch,module_guard_open,"
            "opened_epoch,unresolved_effect_count,ledger_unresolved_effect_count,"
            "runtime_role::text,maintenance_role::text,finalizer_role::text,"
            "maintenance_id::text,maintenance_expires_at::text,"
            "maintenance_holder_pid,"
            "maintenance_holder_backend_start::text,last_module_change_at::text,"
            "last_module_change_txid "
            "FROM odoo_accounting_cli_v3_guard.read_module_guard_state()) state",
            database=database,
        )
    )
    assert isinstance(value, dict)
    return value


def _module_guard_model_assignment(name: str) -> object:
    model = (
        ROOT
        / "odoo_addons"
        / "odoo_accounting_cli_v3_control"
        / "models"
        / "module_guard.py"
    )
    tree = ast.parse(model.read_text(encoding="utf-8"), filename=str(model))
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id == name
            for target in node.targets
        )
    )
    return ast.literal_eval(assignment.value)


def _expected_function_source_digests() -> dict[str, str]:
    value = _module_guard_model_assignment("_FUNCTION_SOURCE_DIGESTS")
    assert isinstance(value, dict)
    return value


def _expected_functions() -> dict[str, tuple[str, bool]]:
    value = _module_guard_model_assignment("_EXPECTED_FUNCTIONS")
    assert isinstance(value, dict)
    return value


def _legacy_privileged_bootstrap_contract_reference(
    postgres: PostgreSQLHarness,
    database: str,
) -> None:
    """Exercise the entire privileged contract on one disposable database.

    The fixed owner role is cluster-global, so this gate deliberately refuses to
    touch an authority where that role already exists.  CI gives this job its own
    PostgreSQL cluster; this assertion also prevents an accidental opt-in run
    against a real Odoo cluster from mutating an existing guard deployment.
    """

    assert BOOTSTRAP.is_file()
    if postgres.scalar(
        "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_roles "
        f"WHERE rolname='{GUARD_OWNER}'"
    ) != "0":
        pytest.fail(
            "the isolated Dev22 bootstrap gate requires the fixed guard owner "
            "role to be absent"
        )

    missing_both = postgres.run_file(
        BOOTSTRAP,
        database=database,
        check=False,
    )
    assert missing_both.returncode == 3
    assert "requires -v runtime_role" in (
        missing_both.stdout + missing_both.stderr
    )
    missing_maintenance = postgres.run_file(
        BOOTSTRAP,
        database=database,
        variables={"runtime_role": "dev22_missing_runtime"},
        check=False,
    )
    assert missing_maintenance.returncode == 3
    assert "requires -v maintenance_role" in (
        missing_maintenance.stdout + missing_maintenance.stderr
    )

    runtime_role = postgres.create_role("runtime", "LOGIN CREATEDB")
    maintenance_role = postgres.create_role("maintenance", "LOGIN CREATEROLE")
    variables = {
        "runtime_role": runtime_role,
        "maintenance_role": maintenance_role,
    }
    database_owner_before = postgres.scalar(
        "SELECT owner.rolname FROM pg_catalog.pg_database AS database "
        "JOIN pg_catalog.pg_roles AS owner ON owner.oid=database.datdba "
        "WHERE database.datname=pg_catalog.current_database()",
        database=database,
    )
    relation_owners_before = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_object_agg(c.relname,owner.rolname)::text "
            "FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_roles AS owner ON owner.oid=c.relowner "
            "WHERE n.nspname='public' AND c.relname IN "
            "('ir_module_module','odoo_accounting_cli_operation')",
            database=database,
        )
    )

    failing_copy = Path(
        f"/tmp/dev22-module-guard-failing-{os.getpid()}-{uuid.uuid4().hex}.sql"
    )
    original_sql = BOOTSTRAP.read_text(encoding="utf-8")
    failing_sql = original_sql.replace(
        "\nCOMMIT;\n",
        "\nSELECT 1 / 0;\nCOMMIT;\n",
        1,
    )
    assert failing_sql != original_sql
    failing_copy.write_text(failing_sql, encoding="utf-8")
    failing_copy.chmod(0o644)
    try:
        failed = postgres.run_file(
            failing_copy,
            database=database,
            variables=variables,
            check=False,
        )
    finally:
        failing_copy.unlink(missing_ok=True)
    assert failed.returncode != 0
    assert "division by zero" in failed.stderr.lower()
    assert postgres.scalar(
        "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_roles "
        f"WHERE rolname='{GUARD_OWNER}'"
    ) == "0"
    assert postgres.scalar(
        "SELECT owner.rolname FROM pg_catalog.pg_database AS database "
        "JOIN pg_catalog.pg_roles AS owner ON owner.oid=database.datdba "
        "WHERE database.datname=pg_catalog.current_database()",
        database=database,
    ) == database_owner_before
    assert json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_object_agg(c.relname,owner.rolname)::text "
            "FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace "
            "JOIN pg_catalog.pg_roles AS owner ON owner.oid=c.relowner "
            "WHERE n.nspname='public' AND c.relname IN "
            "('ir_module_module','odoo_accounting_cli_operation')",
            database=database,
        )
    ) == relation_owners_before
    assert postgres.scalar(
        "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_namespace "
        "WHERE nspname='odoo_accounting_cli_v3_guard'",
        database=database,
    ) == "0"
    assert json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_build_object("
            "'runtime_createdb',(SELECT rolcreatedb FROM pg_catalog.pg_roles "
            f"WHERE rolname='{runtime_role}'),"
            "'maintenance_createrole',(SELECT rolcreaterole "
            "FROM pg_catalog.pg_roles "
            f"WHERE rolname='{maintenance_role}'))::text"
        )
    ) == {"runtime_createdb": True, "maintenance_createrole": True}

    installed = postgres.run_file(
        BOOTSTRAP,
        database=database,
        variables=variables,
    )
    assert installed.returncode == 0
    postgres.created_roles.insert(0, GUARD_OWNER)
    rerun = postgres.run_file(
        BOOTSTRAP,
        database=database,
        variables=variables,
    )
    assert rerun.returncode == 0

    role_contract = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_build_object("
            "'runtime',(SELECT pg_catalog.json_build_array(rolcanlogin,rolsuper,"
            "rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls) "
            f"FROM pg_catalog.pg_roles WHERE rolname='{runtime_role}'),"
            "'maintenance',(SELECT pg_catalog.json_build_array(rolcanlogin,"
            "rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,"
            "rolbypassrls) FROM pg_catalog.pg_roles "
            f"WHERE rolname='{maintenance_role}'),"
            "'owner',(SELECT pg_catalog.json_build_array(rolcanlogin,rolsuper,"
            "rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls) "
            "FROM pg_catalog.pg_roles WHERE "
            f"rolname='{GUARD_OWNER}'),"
            "'runtime_owner_member',pg_catalog.pg_has_role("
            f"'{runtime_role}','{GUARD_OWNER}','MEMBER'),"
            "'maintenance_owner_member',pg_catalog.pg_has_role("
            f"'{maintenance_role}','{GUARD_OWNER}','MEMBER'))::text"
        )
    )
    assert role_contract == {
        "runtime": [True, False, True, False, False, False, False],
        "maintenance": [True, False, True, False, False, False, False],
        "owner": [False, False, False, False, False, False, False],
        "runtime_owner_member": False,
        "maintenance_owner_member": True,
    }
    assert json.loads(
        postgres.scalar(
            "SELECT COALESCE(pg_catalog.json_agg(member_role.rolname "
            "ORDER BY member_role.rolname),'[]'::json)::text "
            "FROM pg_catalog.pg_auth_members AS membership "
            "JOIN pg_catalog.pg_roles AS granted_role "
            "ON granted_role.oid=membership.roleid "
            "JOIN pg_catalog.pg_roles AS member_role "
            "ON member_role.oid=membership.member "
            f"WHERE granted_role.rolname='{GUARD_OWNER}'"
        )
    ) == [maintenance_role]

    ownership = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_build_object("
            "'database',(SELECT owner.rolname FROM pg_catalog.pg_database d "
            "JOIN pg_catalog.pg_roles owner ON owner.oid=d.datdba "
            "WHERE d.datname=pg_catalog.current_database()),"
            "'public_schema',(SELECT owner.rolname FROM pg_catalog.pg_namespace n "
            "JOIN pg_catalog.pg_roles owner ON owner.oid=n.nspowner "
            "WHERE n.nspname='public'),"
            "'guard_schema',(SELECT owner.rolname FROM pg_catalog.pg_namespace n "
            "JOIN pg_catalog.pg_roles owner ON owner.oid=n.nspowner "
            "WHERE n.nspname='odoo_accounting_cli_v3_guard'),"
            "'relations',(SELECT pg_catalog.json_object_agg(c.relname,owner.rolname) "
            "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
            "ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles owner "
            "ON owner.oid=c.relowner WHERE (n.nspname,c.relname) IN "
            "(('public','ir_module_module'),"
            "('public','odoo_accounting_cli_operation'),"
            "('odoo_accounting_cli_v3_guard','module_guard_state'))))::text",
            database=database,
        )
    )
    assert ownership == {
        "database": GUARD_OWNER,
        "public_schema": GUARD_OWNER,
        "guard_schema": GUARD_OWNER,
        "relations": {
            "ir_module_module": GUARD_OWNER,
            "odoo_accounting_cli_operation": GUARD_OWNER,
            "module_guard_state": GUARD_OWNER,
        },
    }

    triggers = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_agg(pg_catalog.json_build_object("
            "'relation',relation.relname,'name',trigger.tgname,"
            "'enabled',trigger.tgenabled,'type',trigger.tgtype,"
            "'function',function.proname,'owner',owner.rolname) "
            "ORDER BY relation.relname,trigger.tgname)::text "
            "FROM pg_catalog.pg_trigger trigger "
            "JOIN pg_catalog.pg_class relation ON relation.oid=trigger.tgrelid "
            "JOIN pg_catalog.pg_proc function ON function.oid=trigger.tgfoid "
            "JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner "
            "WHERE trigger.tgname LIKE 'odoo_accounting_cli_v3_%_guard%'",
            database=database,
        )
    )
    assert triggers == [
        {
            "relation": "ir_module_module",
            "name": "odoo_accounting_cli_v3_module_change_guard",
            "enabled": "A",
            "type": 62,
            "function": "guard_module_change",
            "owner": GUARD_OWNER,
        },
        {
            "relation": "ir_module_module",
            "name": "odoo_accounting_cli_v3_module_change_guard_after",
            "enabled": "A",
            "type": 60,
            "function": "verify_module_change",
            "owner": GUARD_OWNER,
        },
        {
            "relation": "odoo_accounting_cli_operation",
            "name": "odoo_accounting_cli_v3_operation_effect_guard",
            "enabled": "A",
            "type": 29,
            "function": "track_operation_effect",
            "owner": GUARD_OWNER,
        },
    ]
    assert postgres.scalar(
        "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_trigger "
        "WHERE tgname='odoo_accounting_cli_v3_operation_no_truncate' "
        "AND tgenabled='A' AND tgtype=34",
        database=database,
    ) == "1"

    function_catalog = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_object_agg(function.proname,"
            "pg_catalog.json_build_object("
            "'arguments',pg_catalog.pg_get_function_identity_arguments(function.oid),"
            "'owner',owner.rolname,'security_definer',function.prosecdef,"
            "'settings',function.proconfig,'source',function.prosrc,"
            "'runtime_execute',pg_catalog.has_function_privilege("
            f"'{runtime_role}',function.oid,'EXECUTE'),"
            "'public_execute',EXISTS(SELECT 1 FROM pg_catalog.aclexplode("
            "COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) "
            "acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')))::text "
            "FROM pg_catalog.pg_proc function "
            "JOIN pg_catalog.pg_namespace namespace "
            "ON namespace.oid=function.pronamespace "
            "JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner "
            "WHERE namespace.nspname='odoo_accounting_cli_v3_guard'",
            database=database,
        )
    )
    expected_functions = _expected_functions()
    assert set(function_catalog) == set(_expected_function_source_digests())
    assert set(function_catalog) == set(expected_functions)
    for name, expected_digest in _expected_function_source_digests().items():
        evidence = function_catalog[name]
        expected_arguments, expected_runtime_execute = expected_functions[name]
        assert evidence["arguments"] == expected_arguments
        assert evidence["owner"] == GUARD_OWNER
        assert evidence["security_definer"] is True
        assert evidence["settings"] == ["search_path=pg_catalog"]
        assert evidence["runtime_execute"] is expected_runtime_execute
        assert evidence["public_execute"] is False
        assert hashlib.sha256(evidence["source"].encode("utf-8")).hexdigest() == (
            expected_digest
        )

    runtime_acl = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_build_object("
            "'module',pg_catalog.json_build_array("
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.ir_module_module','SELECT'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.ir_module_module','INSERT'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.ir_module_module','UPDATE'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.ir_module_module','DELETE'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.ir_module_module','TRUNCATE'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.ir_module_module','TRIGGER')),'operation',"
            "pg_catalog.json_build_array("
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.odoo_accounting_cli_operation','SELECT'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.odoo_accounting_cli_operation','INSERT'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.odoo_accounting_cli_operation','UPDATE'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.odoo_accounting_cli_operation','DELETE'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.odoo_accounting_cli_operation','TRUNCATE'),"
            f"pg_catalog.has_table_privilege('{runtime_role}',"
            "'public.odoo_accounting_cli_operation','TRIGGER')))::text",
            database=database,
        )
    )
    assert runtime_acl == {
        "module": [True, True, True, True, False, False],
        "operation": [True, True, True, False, False, False],
    }
    state = _guard_state(postgres, database)
    assert state == {
        "protocol_version": 1,
        "schema_version": 1,
        "epoch": 0,
        "module_guard_open": False,
        "opened_epoch": None,
        "unresolved_effect_count": 0,
        "maintenance_role": maintenance_role,
        "maintenance_id": None,
        "maintenance_holder_pid": None,
        "maintenance_holder_backend_start": None,
        "last_module_change_at": None,
        "last_module_change_txid": None,
    }

    unauthorized = postgres.run(
        f"SET SESSION AUTHORIZATION {runtime_role}; "
        "UPDATE public.ir_module_module SET latest_version=latest_version "
        "WHERE name='base'",
        database=database,
        check=False,
    )
    assert unauthorized.returncode != 0
    assert "active approved maintenance holder" in unauthorized.stderr

    no_lock_id = uuid.uuid4()
    no_lock = postgres.run(
        f"SET SESSION AUTHORIZATION {maintenance_role}; "
        "SELECT odoo_accounting_cli_v3_guard.open_module_guard("
        f"0,'{no_lock_id}'::uuid)",
        database=database,
        check=False,
    )
    assert no_lock.returncode != 0
    assert "requires the exclusive session lock" in no_lock.stderr

    key_a, key_b = ADVISORY_KEY_PARTS
    with postgres.session(database) as writer_guard:
        writer_guard.execute(
            f"SET SESSION AUTHORIZATION {runtime_role}; "
            f"SELECT pg_catalog.pg_advisory_lock_shared({key_a},{key_b});"
        )
        blocked_exclusive = postgres.scalar(
            f"SET SESSION AUTHORIZATION {maintenance_role}; "
            f"SELECT pg_catalog.pg_try_advisory_lock({key_a},{key_b})::text",
            database=database,
        )
        assert blocked_exclusive == "f"
        assert writer_guard.execute(
            f"SELECT pg_catalog.pg_advisory_unlock_shared({key_a},{key_b})::text;"
        )[-1] == "t"

    maintenance_id = uuid.uuid4()
    with postgres.session(database) as holder:
        holder_rows = holder.execute(
            f"SET SESSION AUTHORIZATION {maintenance_role}; "
            f"SELECT pg_catalog.pg_advisory_lock({key_a},{key_b}); "
            "BEGIN; SELECT odoo_accounting_cli_v3_guard.open_module_guard("
            f"0,'{maintenance_id}'::uuid)::text; COMMIT; "
            "SELECT pg_catalog.pg_backend_pid()::text;"
        )
        assert holder_rows[-2] == "0"
        holder_pid = int(holder_rows[-1])
        changed = postgres.run(
            f"SET SESSION AUTHORIZATION {maintenance_role}; "
            "UPDATE public.ir_module_module SET latest_version='19.0.1.1' "
            "WHERE name='base'",
            database=database,
        )
        assert changed.returncode == 0
        state = _guard_state(postgres, database)
        assert state["epoch"] == 1
        assert state["opened_epoch"] == 1
        assert state["module_guard_open"] is True
        assert state["maintenance_id"] == str(maintenance_id)
        assert state["maintenance_holder_pid"] == holder_pid
        close_rows = holder.execute(
            "BEGIN; SELECT odoo_accounting_cli_v3_guard.close_module_guard("
            f"1,'{maintenance_id}'::uuid)::text; COMMIT; "
            f"SELECT pg_catalog.pg_advisory_unlock({key_a},{key_b})::text;"
        )
        assert close_rows[-2:] == ["1", "t"]
    assert _guard_state(postgres, database)["module_guard_open"] is False

    postgres.run(
        f"SET SESSION AUTHORIZATION {runtime_role}; "
        "INSERT INTO public.odoo_accounting_cli_operation(state) VALUES ('claimed')",
        database=database,
    )
    assert _guard_state(postgres, database)["unresolved_effect_count"] == 0
    postgres.run(
        f"SET SESSION AUTHORIZATION {runtime_role}; "
        "UPDATE public.odoo_accounting_cli_operation "
        "SET state='committed',execution_result_json='{\"succeeded\":true}' "
        "WHERE id=1",
        database=database,
    )
    assert _guard_state(postgres, database)["unresolved_effect_count"] == 1
    unresolved_open = postgres.run(
        f"SET SESSION AUTHORIZATION {maintenance_role}; "
        f"SELECT pg_catalog.pg_advisory_lock({key_a},{key_b}); "
        "SELECT odoo_accounting_cli_v3_guard.open_module_guard("
        f"1,'{uuid.uuid4()}'::uuid)",
        database=database,
        check=False,
    )
    assert unresolved_open.returncode != 0
    assert "cannot be opened at the requested epoch" in unresolved_open.stderr
    postgres.run(
        f"SET SESSION AUTHORIZATION {runtime_role}; "
        "UPDATE public.odoo_accounting_cli_operation "
        "SET state='verified',verification_result_json='{\"succeeded\":true}' "
        "WHERE id=1",
        database=database,
    )
    assert _guard_state(postgres, database)["unresolved_effect_count"] == 0

    crash_id = uuid.uuid4()
    crashed_holder = postgres.session(database)
    try:
        crash_rows = crashed_holder.execute(
            f"SET SESSION AUTHORIZATION {maintenance_role}; "
            f"SELECT pg_catalog.pg_advisory_lock({key_a},{key_b}); "
            "BEGIN; SELECT odoo_accounting_cli_v3_guard.open_module_guard("
            f"1,'{crash_id}'::uuid)::text; COMMIT; "
            "SELECT pg_catalog.pg_backend_pid()::text;"
        )
        assert crash_rows[-2] == "1"
        crashed_pid = int(crash_rows[-1])
        postgres.run(
            f"SET SESSION AUTHORIZATION {maintenance_role}; "
            "UPDATE public.ir_module_module SET latest_version=latest_version "
            "WHERE name='account'",
            database=database,
        )
        assert postgres.scalar(
            f"SELECT pg_catalog.pg_terminate_backend({crashed_pid})::text",
            database=database,
        ) == "t"
        _wait_for(
            lambda: int(
                postgres.scalar(
                    "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_locks "
                    f"WHERE locktype='advisory' AND pid={crashed_pid}",
                    database=database,
                )
            )
            == 0,
            description="the crashed maintenance holder lock to disappear",
        )
        quarantined = _guard_state(postgres, database)
        assert quarantined["module_guard_open"] is True
        assert quarantined["epoch"] == 2
        assert quarantined["opened_epoch"] == 2
        assert quarantined["maintenance_id"] == str(crash_id)
        post_crash_change = postgres.run(
            f"SET SESSION AUTHORIZATION {maintenance_role}; "
            "UPDATE public.ir_module_module SET latest_version=latest_version "
            "WHERE name='sale'",
            database=database,
            check=False,
        )
        assert post_crash_change.returncode != 0
        assert "maintenance holder is not live" in post_crash_change.stderr
        stolen_close = postgres.run(
            f"SET SESSION AUTHORIZATION {maintenance_role}; "
            f"SELECT pg_catalog.pg_advisory_lock({key_a},{key_b}); "
            "SELECT odoo_accounting_cli_v3_guard.close_module_guard("
            f"2,'{crash_id}'::uuid)",
            database=database,
            check=False,
        )
        assert stolen_close.returncode != 0
        assert "cannot be closed at the requested epoch" in stolen_close.stderr
        assert _guard_state(postgres, database) == quarantined
    finally:
        crashed_holder.close()


def _trusted_result_envelope(
    *,
    kind: str,
    purpose: str,
    operation_id: str,
    request_id: str,
    operation_digest: str,
    company_id: int,
    capability_id: str,
    registry_digest: str,
    release_digest: str,
    evidence_digest: str,
    prior_evidence_digest: str | None,
    succeeded: bool,
    revision: int,
) -> str:
    return json.dumps(
        {
            "capability_id": capability_id,
            "company_id": company_id,
            "evidence_digest": evidence_digest,
            "issued_at": "2026-07-18T00:00:00Z",
            "issuer": f"dev22-{kind}",
            "key_id": f"dev22-{kind}-key",
            "kind": kind,
            "operation_digest": operation_digest,
            "operation_id": operation_id,
            "operation_revision": revision,
            "operation_state_digest": "9" * 64,
            "prior_evidence_digest": prior_evidence_digest,
            "purpose": purpose,
            "registry_digest": registry_digest,
            "release_digest": release_digest,
            "request_id": request_id,
            "signature": "8" * 64,
            "succeeded": succeeded,
            "version": 2,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _full_operation_table_sql() -> str:
    immutable = (
        "operation_id text NOT NULL UNIQUE,request_id text NOT NULL,"
        "capability_id text NOT NULL,idempotency_scope text NOT NULL,"
        "operation_digest text NOT NULL,protocol_version integer NOT NULL,"
        "precheck_digest text NOT NULL,principal text NOT NULL,"
        "requester_id bigint NOT NULL,approver_id bigint NOT NULL,"
        "company_id bigint NOT NULL,environment text NOT NULL,"
        "capability_channel text NOT NULL,registry_digest text NOT NULL,"
        "release_digest text NOT NULL,state text NOT NULL"
    )
    mutable = ",".join(
        f"{field} text"
        for field in (
            "execution_evidence_json",
            "execution_evidence_digest",
            "verification_evidence_json",
            "verification_evidence_digest",
            "failure_evidence_json",
            "failure_evidence_digest",
            "recovery_plan_json",
            "recovery_plan_digest",
            "recovery_evidence_json",
            "recovery_evidence_digest",
            "execution_result_json",
            "execution_result_digest",
            "verification_result_json",
            "verification_result_digest",
            "recovery_result_json",
            "recovery_result_digest",
        )
    )
    return (
        "DROP TABLE public.odoo_accounting_cli_operation;"
        "CREATE TABLE public.odoo_accounting_cli_operation("
        "id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,"
        f"{immutable},{mutable});"
    )


def test_privileged_v2_contract_finalizer_maintenance_and_crash_rescue(
    postgres: PostgreSQLHarness,
    database: str,
) -> None:
    """Run the single-use v2 guard, immutable ledger and crash-close protocol."""

    assert BOOTSTRAP.is_file()
    if postgres.scalar(
        "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_roles "
        f"WHERE rolname='{GUARD_OWNER}'"
    ) != "0":
        pytest.fail("the isolated Dev22 PostgreSQL cluster is not pristine")

    missing = postgres.run_file(BOOTSTRAP, database=database, check=False)
    assert missing.returncode == 3
    assert "requires -v runtime_role" in missing.stdout + missing.stderr

    runtime_role = postgres.create_role("runtime", "LOGIN CREATEDB")
    maintenance_role = postgres.create_role("maintenance", "LOGIN CREATEROLE")
    finalizer_role = postgres.create_role("finalizer", "LOGIN CREATEROLE")
    variables = {
        "runtime_role": runtime_role,
        "maintenance_role": maintenance_role,
        "finalizer_role": finalizer_role,
    }
    database_uuid = str(uuid.uuid4())
    postgres.run(f"ALTER DATABASE {database} OWNER TO {runtime_role}")
    postgres.run(
        _full_operation_table_sql()
        + "CREATE TABLE public.ir_config_parameter("
        "id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,"
        "key text NOT NULL,value text NOT NULL);"
        "INSERT INTO public.ir_config_parameter(key,value) VALUES"
        f"('database.uuid','{database_uuid}');"
        f"ALTER TABLE public.ir_module_module OWNER TO {runtime_role};"
        f"ALTER TABLE public.odoo_accounting_cli_operation OWNER TO {runtime_role};"
        f"ALTER TABLE public.ir_config_parameter OWNER TO {runtime_role};"
        f"ALTER SEQUENCE public.ir_module_module_id_seq OWNER TO {runtime_role};"
        f"ALTER SEQUENCE public.odoo_accounting_cli_operation_id_seq OWNER TO {runtime_role};"
        f"ALTER SEQUENCE public.ir_config_parameter_id_seq OWNER TO {runtime_role};",
        database=database,
    )

    postgres.run("CREATE SCHEMA odoo_accounting_cli_v3_guard", database=database)
    poisoned = postgres.run_file(
        BOOTSTRAP, database=database, variables=variables, check=False
    )
    assert poisoned.returncode != 0
    assert "schema already exists" in poisoned.stderr
    postgres.run("DROP SCHEMA odoo_accounting_cli_v3_guard", database=database)

    failing_copy = Path(
        f"/tmp/dev22-module-guard-failing-{os.getpid()}-{uuid.uuid4().hex}.sql"
    )
    original_sql = BOOTSTRAP.read_text(encoding="utf-8")
    failing_copy.write_text(
        original_sql.replace("\nCOMMIT;\n", "\nSELECT 1 / 0;\nCOMMIT;\n", 1),
        encoding="utf-8",
    )
    failing_copy.chmod(0o644)
    try:
        injected = postgres.run_file(
            failing_copy,
            database=database,
            variables=variables,
            check=False,
        )
    finally:
        failing_copy.unlink(missing_ok=True)
    assert injected.returncode != 0
    assert "division by zero" in injected.stderr.lower()
    assert postgres.scalar(
        "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_namespace "
        "WHERE nspname='odoo_accounting_cli_v3_guard'",
        database=database,
    ) == "0"
    assert postgres.scalar(
        "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_roles "
        f"WHERE rolname='{GUARD_OWNER}'"
    ) == "0"

    installed = postgres.run_file(
        BOOTSTRAP, database=database, variables=variables, timeout=30
    )
    assert installed.returncode == 0
    postgres.created_roles.insert(0, GUARD_OWNER)
    rerun = postgres.run_file(
        BOOTSTRAP,
        database=database,
        variables=variables,
        check=False,
    )
    assert rerun.returncode != 0
    assert "schema already exists" in rerun.stderr

    role_contract = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_build_object("
            "'runtime',(SELECT pg_catalog.json_build_array(rolcanlogin,rolsuper,"
            "rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls) "
            f"FROM pg_catalog.pg_roles WHERE rolname='{runtime_role}'),"
            "'maintenance',(SELECT pg_catalog.json_build_array(rolcanlogin,"
            "rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,"
            "rolbypassrls,rolconnlimit) FROM pg_catalog.pg_roles "
            f"WHERE rolname='{maintenance_role}'),"
            "'finalizer',(SELECT pg_catalog.json_build_array(rolcanlogin,"
            "rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolreplication,"
            "rolbypassrls) FROM pg_catalog.pg_roles "
            f"WHERE rolname='{finalizer_role}'),"
            "'owner',(SELECT pg_catalog.json_build_array(rolcanlogin,rolsuper,"
            "rolinherit,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls) "
            f"FROM pg_catalog.pg_roles WHERE rolname='{GUARD_OWNER}'))::text"
        )
    )
    assert role_contract == {
        "runtime": [True, False, True, False, False, False, False],
        "maintenance": [False, False, False, False, False, False, False, 1],
        "finalizer": [True, False, False, False, False, False, False],
        "owner": [False, False, False, False, False, False, False],
    }
    membership = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.row_to_json(edge)::text FROM (SELECT "
            "granted.rolname AS granted,member.rolname AS member,"
            "membership.admin_option,membership.inherit_option,"
            "membership.set_option FROM pg_catalog.pg_auth_members membership "
            "JOIN pg_catalog.pg_roles granted ON granted.oid=membership.roleid "
            "JOIN pg_catalog.pg_roles member ON member.oid=membership.member "
            f"WHERE granted.rolname='{runtime_role}' AND member.rolname='{GUARD_OWNER}') edge"
        )
    )
    assert membership == {
        "granted": runtime_role,
        "member": GUARD_OWNER,
        "admin_option": True,
        "inherit_option": False,
        "set_option": False,
    }

    function_catalog = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_object_agg(function.proname,"
            "pg_catalog.json_build_object("
            "'arguments',pg_catalog.pg_get_function_identity_arguments(function.oid),"
            "'owner',owner.rolname,'security_definer',function.prosecdef,"
            "'settings',function.proconfig,'source',function.prosrc,"
            "'runtime_execute',pg_catalog.has_function_privilege("
            f"'{runtime_role}',function.oid,'EXECUTE'),"
            "'public_execute',EXISTS(SELECT 1 FROM pg_catalog.aclexplode("
            "COALESCE(function.proacl,pg_catalog.acldefault('f',function.proowner))) "
            "acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')))::text "
            "FROM pg_catalog.pg_proc function "
            "JOIN pg_catalog.pg_namespace namespace ON namespace.oid=function.pronamespace "
            "JOIN pg_catalog.pg_roles owner ON owner.oid=function.proowner "
            "WHERE namespace.nspname='odoo_accounting_cli_v3_guard'",
            database=database,
        )
    )
    expected_functions = _expected_functions()
    expected_digests = _expected_function_source_digests()
    assert set(function_catalog) == set(expected_functions) == set(expected_digests)
    for name, expected_digest in expected_digests.items():
        evidence = function_catalog[name]
        assert evidence["arguments"] == expected_functions[name][0]
        assert evidence["owner"] == GUARD_OWNER
        assert evidence["security_definer"] is True
        assert evidence["settings"] == ["search_path=pg_catalog"]
        assert evidence["runtime_execute"] is expected_functions[name][1]
        assert evidence["public_execute"] is False
        assert hashlib.sha256(evidence["source"].encode()).hexdigest() == expected_digest

    event_triggers = json.loads(
        postgres.scalar(
            "SELECT pg_catalog.json_object_agg(evtname,evtevent ORDER BY evtname)::text "
            "FROM pg_catalog.pg_event_trigger WHERE evtenabled='A'",
            database=database,
        )
    )
    assert event_triggers == {
        "odoo_accounting_cli_v3_ddl_guard_end": "ddl_command_end",
        "odoo_accounting_cli_v3_sql_drop_guard": "sql_drop",
        "odoo_accounting_cli_v3_table_rewrite_guard": "table_rewrite",
    }
    state = _guard_state(postgres, database)
    assert state["protocol_version"] == 1
    assert state["schema_version"] == 2
    assert state["database_uuid"] == database_uuid
    assert state["database_oid"] > 0
    assert state["module_guard_open"] is False
    assert state["unresolved_effect_count"] == state["ledger_unresolved_effect_count"] == 0

    operation_id = "dev22-effect-1"
    request_id = "dev22-request-1"
    operation_digest = "1" * 64
    precheck_digest = "2" * 64
    registry_digest = "3" * 64
    release_digest = "4" * 64
    execution_evidence_digest = "5" * 64
    verification_evidence_digest = "6" * 64
    execution_result_digest = "a" * 64
    verification_result_digest = "b" * 64
    execution_result = _trusted_result_envelope(
        kind="execution",
        purpose="execution_result_v2",
        operation_id=operation_id,
        request_id=request_id,
        operation_digest=operation_digest,
        company_id=7,
        capability_id="acct.invoice.customer.create.v1",
        registry_digest=registry_digest,
        release_digest=release_digest,
        evidence_digest=execution_evidence_digest,
        prior_evidence_digest=None,
        succeeded=True,
        revision=1,
    )
    verification_result = _trusted_result_envelope(
        kind="verification",
        purpose="verification_result_v2",
        operation_id=operation_id,
        request_id=request_id,
        operation_digest=operation_digest,
        company_id=7,
        capability_id="acct.invoice.customer.create.v1",
        registry_digest=registry_digest,
        release_digest=release_digest,
        evidence_digest=verification_evidence_digest,
        prior_evidence_digest=execution_evidence_digest,
        succeeded=True,
        revision=2,
    )
    postgres.run(
        f"SET SESSION AUTHORIZATION {runtime_role};"
        "INSERT INTO public.odoo_accounting_cli_operation("
        "operation_id,request_id,capability_id,idempotency_scope,operation_digest,"
        "protocol_version,precheck_digest,principal,requester_id,approver_id,"
        "company_id,environment,capability_channel,registry_digest,release_digest,state)"
        f"VALUES('{operation_id}','{request_id}','acct.invoice.customer.create.v1',"
        f"'scope-1','{operation_digest}',1,'{precheck_digest}','principal-1',11,12,7,"
        f"'sandbox','staged','{registry_digest}','{release_digest}','claimed');"
        "UPDATE public.odoo_accounting_cli_operation SET state='committed',"
        f"execution_evidence_json='{{}}',execution_evidence_digest='{execution_evidence_digest}',"
        f"execution_result_json=$result${execution_result}$result$,"
        f"execution_result_digest='{execution_result_digest}' "
        f"WHERE operation_id='{operation_id}';"
        "UPDATE public.odoo_accounting_cli_operation SET state='verified',"
        f"verification_evidence_json='{{}}',verification_evidence_digest='{verification_evidence_digest}',"
        f"verification_result_json=$result${verification_result}$result$,"
        f"verification_result_digest='{verification_result_digest}' "
        f"WHERE operation_id='{operation_id}';",
        database=database,
    )
    forged_state = _guard_state(postgres, database)
    assert forged_state["unresolved_effect_count"] == 1
    assert forged_state["ledger_unresolved_effect_count"] == 1

    proof_id = uuid.uuid4()
    verified_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = verified_at + timedelta(minutes=4)
    finalizer_call = (
        f"SET SESSION AUTHORIZATION {finalizer_role};"
        "SELECT pg_catalog.row_to_json(receipt)::text FROM "
        "odoo_accounting_cli_v3_guard.finalize_operation_effect("
        f"'{state['guard_installation_id']}'::uuid,{state['database_oid']}::oid,"
        f"'{database_uuid}'::uuid,'{proof_id}'::uuid,'{'c' * 64}','dev22-finalizer-key',"
        f"'{verified_at.isoformat()}'::timestamptz,'{expires_at.isoformat()}'::timestamptz,"
        f"'{operation_id}','{operation_digest}','{execution_result_digest}',"
        f"'{operation_id}','{operation_digest}','{execution_result_digest}',"
        f"'verified','{verification_result_digest}') receipt"
    )
    start = threading.Barrier(3)
    results: list[dict[str, object]] = []
    failures: list[BaseException] = []

    def finalize_once() -> None:
        try:
            start.wait(timeout=5)
            results.append(json.loads(postgres.scalar(finalizer_call, database=database)))
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)

    threads = [threading.Thread(target=finalize_once) for _ in range(2)]
    for thread in threads:
        thread.start()
    start.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=10)
    assert not failures
    assert len(results) == 2
    assert {result.pop("replayed") for result in results} == {False, True}
    assert results[0] == results[1]
    assert results[0]["remaining_unresolved_count"] == 0
    assert _guard_state(postgres, database)["unresolved_effect_count"] == 0

    authorization_id = uuid.uuid4()
    maintenance_expiry = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        minutes=10
    )
    authorize = postgres.run(
        f"SET SESSION AUTHORIZATION {finalizer_role};"
        "SELECT * FROM odoo_accounting_cli_v3_guard.authorize_module_maintenance("
        f"'{authorization_id}'::uuid,'{state['guard_installation_id']}'::uuid,"
        f"{state['database_oid']}::oid,'{database_uuid}'::uuid,'{'d' * 64}',"
        f"'{registry_digest}','{release_digest}','{'e' * 64}',"
        f"'{maintenance_expiry.isoformat()}'::timestamptz)",
        database=database,
    )
    assert authorize.returncode == 0
    postgres.run(
        f"ALTER ROLE {maintenance_role} LOGIN VALID UNTIL "
        f"'{maintenance_expiry.isoformat()}'"
    )
    key_a, key_b = ADVISORY_KEY_PARTS
    with postgres.session(database) as holder:
        opened = holder.execute(
            f"SET SESSION AUTHORIZATION {maintenance_role};"
            f"SELECT pg_catalog.pg_advisory_lock({key_a},{key_b});"
            "BEGIN; SELECT odoo_accounting_cli_v3_guard.open_module_guard("
            f"0,'{authorization_id}'::uuid)::text; COMMIT;"
            "SET ROLE " + runtime_role + ";"
            "UPDATE public.ir_module_module SET latest_version='19.0.1.1' "
            "WHERE name='base';"
            "CREATE TABLE public.dev22_guarded_ddl(id bigint PRIMARY KEY);"
            "RESET ROLE;"
        )
        assert "1" in opened
        current = _guard_state(postgres, database)
        assert current["epoch"] == current["opened_epoch"] == 2
        closed = holder.execute(
            "BEGIN; SELECT odoo_accounting_cli_v3_guard.close_module_guard("
            f"2,'{authorization_id}'::uuid)::text; COMMIT;"
            f"SELECT pg_catalog.pg_advisory_unlock({key_a},{key_b})::text;"
        )
        assert closed[-2:] == ["2", "t"]
    postgres.run(f"ALTER ROLE {maintenance_role} NOLOGIN VALID UNTIL 'epoch'")
    postgres.run("DROP TABLE public.dev22_guarded_ddl", database=database)
    closed_state = _guard_state(postgres, database)
    assert closed_state["module_guard_open"] is False
    assert postgres.scalar(
        f"SELECT pg_catalog.pg_has_role('{maintenance_role}','{runtime_role}','MEMBER')::text"
    ) == "f"
    assert postgres.scalar(
        f"SELECT pg_catalog.has_schema_privilege('{runtime_role}','public','CREATE')::text",
        database=database,
    ) == "f"

    crash_id = uuid.uuid4()
    crash_expiry = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=10)
    postgres.run(
        f"SET SESSION AUTHORIZATION {finalizer_role};"
        "SELECT * FROM odoo_accounting_cli_v3_guard.authorize_module_maintenance("
        f"'{crash_id}'::uuid,'{state['guard_installation_id']}'::uuid,"
        f"{state['database_oid']}::oid,'{database_uuid}'::uuid,'{'f' * 64}',"
        f"'{registry_digest}','{release_digest}','{'7' * 64}',"
        f"'{crash_expiry.isoformat()}'::timestamptz)",
        database=database,
    )
    postgres.run(
        f"ALTER ROLE {maintenance_role} LOGIN VALID UNTIL '{crash_expiry.isoformat()}'"
    )
    crashed_holder = postgres.session(database)
    try:
        crash_rows = crashed_holder.execute(
            f"SET SESSION AUTHORIZATION {maintenance_role};"
            f"SELECT pg_catalog.pg_advisory_lock({key_a},{key_b});"
            "BEGIN; SELECT odoo_accounting_cli_v3_guard.open_module_guard("
            f"2,'{crash_id}'::uuid)::text; COMMIT;"
            "SELECT pg_catalog.pg_backend_pid()::text;"
        )
        crashed_pid = int(crash_rows[-1])
        assert postgres.scalar(
            f"SELECT pg_catalog.pg_terminate_backend({crashed_pid})::text",
            database=database,
        ) == "t"
        _wait_for(
            lambda: postgres.scalar(
                "SELECT pg_catalog.count(*)::text FROM pg_catalog.pg_stat_activity "
                f"WHERE pid={crashed_pid}",
                database=database,
            )
            == "0",
            description="crashed maintenance holder to disappear",
        )
        ddl_after_crash = postgres.run(
            f"SET SESSION AUTHORIZATION {runtime_role};"
            "CREATE TABLE public.dev22_crash_escape(id bigint)",
            database=database,
            check=False,
        )
        assert ddl_after_crash.returncode != 0
        assert "module maintenance DDL is not authorized" in ddl_after_crash.stderr
        rescued = postgres.run(
            f"SET SESSION AUTHORIZATION {finalizer_role};"
            "SELECT odoo_accounting_cli_v3_guard.rescue_module_guard("
            f"3,'{crash_id}'::uuid,'{'0' * 64}')",
            database=database,
        )
        assert rescued.returncode == 0
    finally:
        crashed_holder.close()
    postgres.run(f"ALTER ROLE {maintenance_role} NOLOGIN VALID UNTIL 'epoch'")
    rescued_state = _guard_state(postgres, database)
    assert rescued_state["module_guard_open"] is False
    assert postgres.scalar(
        f"SELECT pg_catalog.has_schema_privilege('{runtime_role}','public','CREATE')::text",
        database=database,
    ) == "f"

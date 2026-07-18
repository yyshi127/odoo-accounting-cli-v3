from __future__ import annotations

import ast
import importlib.util
import io
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = PROJECT_ROOT / "deployment" / "dev18" / "sandbox_capacity_gate.py"


def _load_gate():
    name = "dev18_attested_psql_runner_review_gate"
    spec = importlib.util.spec_from_file_location(name, GATE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _connection(*, superuser: bool = False) -> dict[str, object]:
    return {
        "runuser_path": "/usr/sbin/runuser",
        "run_as_user": "postgres" if superuser else "odoo",
        "psql_path": "/usr/bin/psql",
        "socket_directory": "/run/postgresql",
        "port": 5432,
        "database_user": "postgres" if superuser else "odoo",
        "database_user_is_superuser": superuser,
    }


class _FakeProcess:
    def __init__(self, stdin=None) -> None:
        self.pid = 9100
        self.stdin = stdin if stdin is not None else io.BytesIO()
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0


def test_attested_runner_keeps_one_session_and_attests_around_transaction(
    monkeypatch,
) -> None:
    process = _FakeProcess()
    events: list[tuple[str, object]] = []
    popen_calls: list[tuple[list[str], dict[str, object]]] = []

    def popen(command, **kwargs):
        popen_calls.append((command, kwargs))
        events.append(("popen", process.pid))
        return process

    def write(active_process, payload, label, *, deadline):
        events.append(("write", label))
        active_process.stdin.write(payload)

    def read(active_process, marker, **kwargs):
        assert active_process is process
        events.append(("read", marker))
        if marker == "backend-handshake":
            return [{"backend_pid": 42001}]
        return [{"probe": True}]

    def verify(cluster, postmaster, backend_pid):
        assert backend_pid == 42001
        events.append(("verify", backend_pid))
        return {"process_identity_sha256": "a" * 64}

    def finish(active_process, **kwargs):
        assert active_process is process
        events.append(("finish", active_process.pid))

    monkeypatch.setattr(gate.subprocess, "Popen", popen)
    monkeypatch.setattr(gate, "_write_psql_input", write)
    monkeypatch.setattr(gate, "_read_psql_marker", read)
    monkeypatch.setattr(gate, "_verify_postgresql_backend_process", verify)
    monkeypatch.setattr(gate, "_finish_attested_psql", finish)
    monkeypatch.setattr(
        gate,
        "_terminate_process_group",
        lambda active_process: pytest.fail("successful probe must not be terminated"),
    )

    rows, backend_identity = gate._run_attested_psql_commands(
        _connection(),
        {"cluster": "reviewed"},
        {"pid": 3333},
        "odoo_test",
        [
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "SELECT pg_catalog.json_build_object('probe',TRUE)::pg_catalog.text",
        ],
        deadline_ns=None,
    )

    assert rows == [{"probe": True}]
    assert backend_identity == "a" * 64
    assert len(popen_calls) == 1
    command, options = popen_calls[0]
    assert command[-2:] == ["-f", "-"]
    assert "-c" not in command
    assert options["start_new_session"] is True
    assert options["close_fds"] is True
    assert "session_preload_libraries" not in options["env"]["PGOPTIONS"]
    assert events == [
        ("popen", 9100),
        ("write", "attested read-only PostgreSQL probe"),
        ("read", "backend-handshake"),
        ("verify", 42001),
        ("write", "attested read-only PostgreSQL transaction"),
        ("read", "transaction-complete"),
        ("verify", 42001),
        ("finish", 9100),
    ]
    script = process.stdin.getvalue().decode("utf-8")
    assert script.count("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;") == 1
    assert "SET TRANSACTION ISOLATION LEVEL" not in script
    assert script.index("backend-handshake") < script.index("BEGIN ISOLATION")
    assert script.index("transaction-complete") < script.index("ROLLBACK;")


def test_backend_identity_drift_terminates_the_interactive_client(monkeypatch) -> None:
    process = _FakeProcess()
    terminations: list[int] = []
    attestations = iter(
        [
            {"process_identity_sha256": "a" * 64},
            {"process_identity_sha256": "b" * 64},
        ]
    )

    monkeypatch.setattr(gate.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        gate,
        "_write_psql_input",
        lambda active_process, payload, label, **kwargs: active_process.stdin.write(payload),
    )
    monkeypatch.setattr(
        gate,
        "_read_psql_marker",
        lambda active_process, marker, **kwargs: (
            [{"backend_pid": 42001}]
            if marker == "backend-handshake"
            else [{"probe": True}]
        ),
    )
    monkeypatch.setattr(
        gate,
        "_verify_postgresql_backend_process",
        lambda *args, **kwargs: next(attestations),
    )
    monkeypatch.setattr(
        gate,
        "_terminate_process_group",
        lambda active_process: terminations.append(active_process.pid),
    )
    monkeypatch.setattr(
        gate,
        "_finish_attested_psql",
        lambda *args, **kwargs: pytest.fail("drifted backend must not be accepted"),
    )

    with pytest.raises(gate.CapacityGateError, match="backend process changed"):
        gate._run_attested_psql_commands(
            _connection(),
            {"cluster": "reviewed"},
            {"pid": 3333},
            "odoo_test",
            ["SELECT 1"],
            deadline_ns=None,
        )

    assert terminations == [9100]
    assert process.stdin.closed and process.stdout.closed and process.stderr.closed


def test_transaction_error_terminates_the_interactive_client(monkeypatch) -> None:
    process = _FakeProcess()
    terminations: list[int] = []

    def read(active_process, marker, **kwargs):
        if marker == "backend-handshake":
            return [{"backend_pid": 42001}]
        raise gate.CapacityGateError("simulated transaction failure")

    monkeypatch.setattr(gate.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        gate,
        "_write_psql_input",
        lambda active_process, payload, label, **kwargs: active_process.stdin.write(payload),
    )
    monkeypatch.setattr(gate, "_read_psql_marker", read)
    monkeypatch.setattr(
        gate,
        "_verify_postgresql_backend_process",
        lambda *args, **kwargs: {"process_identity_sha256": "a" * 64},
    )
    monkeypatch.setattr(
        gate,
        "_terminate_process_group",
        lambda active_process: terminations.append(active_process.pid),
    )

    with pytest.raises(gate.CapacityGateError, match="simulated transaction failure"):
        gate._run_attested_psql_commands(
            _connection(),
            {"cluster": "reviewed"},
            {"pid": 3333},
            "odoo_test",
            ["SELECT 1"],
            deadline_ns=None,
        )

    assert terminations == [9100]
    assert process.stdin.closed and process.stdout.closed and process.stderr.closed


def test_marker_reader_rejects_oversized_stdout(monkeypatch) -> None:
    stdout = SimpleNamespace(fileno=lambda: 101)
    stderr = SimpleNamespace(fileno=lambda: 102)
    process = SimpleNamespace(stdout=stdout, stderr=stderr, poll=lambda: None)

    class Selector:
        def register(self, stream, event, data):
            pass

        def select(self, timeout):
            return [(SimpleNamespace(fileobj=stdout, data="stdout"), None)]

        def unregister(self, stream):
            pass

        def close(self):
            pass

    monkeypatch.setattr(gate.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(
        gate.os,
        "read",
        lambda descriptor, maximum: b"x" * (gate.MAX_INPUT_BYTES + 1),
    )

    with pytest.raises(gate.CapacityGateError, match="stdout is too large"):
        gate._read_psql_marker(
            process,
            "never",
            deadline=time.monotonic() + 1,
            stderr=bytearray(),
            label="attested probe",
        )


def test_marker_reader_bounds_cumulative_stdout_across_json_rows(monkeypatch) -> None:
    """Many individually small rows must still obey one aggregate output budget."""
    stdout = SimpleNamespace(fileno=lambda: 101)
    stderr = SimpleNamespace(fileno=lambda: 102)
    process = SimpleNamespace(stdout=stdout, stderr=stderr, poll=lambda: None)
    row = b'{"payload":"' + (b"x" * 60_000) + b'"}\n'
    chunks = [row for _ in range(18)]
    chunks.append(b'{"capacity_gate_marker":"done"}\n')

    class Selector:
        def register(self, stream, event, data):
            pass

        def select(self, timeout):
            return [(SimpleNamespace(fileobj=stdout, data="stdout"), None)]

        def unregister(self, stream):
            pass

        def close(self):
            pass

    monkeypatch.setattr(gate.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(gate.os, "read", lambda descriptor, maximum: chunks.pop(0))

    with pytest.raises(gate.CapacityGateError, match="stdout is too large"):
        gate._read_psql_marker(
            process,
            "done",
            deadline=time.monotonic() + 1,
            stderr=bytearray(),
            label="attested probe",
        )


def test_marker_reader_fails_closed_after_deadline(monkeypatch) -> None:
    process = SimpleNamespace(
        stdout=SimpleNamespace(fileno=lambda: 101),
        stderr=SimpleNamespace(fileno=lambda: 102),
        poll=lambda: None,
    )

    class Selector:
        def register(self, stream, event, data):
            pass

        def close(self):
            pass

    monkeypatch.setattr(gate.selectors, "DefaultSelector", Selector)

    with pytest.raises(gate.CapacityGateError, match="timed out"):
        gate._read_psql_marker(
            process,
            "never",
            deadline=time.monotonic() - 1,
            stderr=bytearray(),
            label="attested probe",
        )


def test_finish_sends_quit_drains_both_pipes_and_waits(monkeypatch) -> None:
    class Stream:
        def __init__(self, descriptor: int) -> None:
            self.descriptor = descriptor
            self.closed = False

        def fileno(self):
            return self.descriptor

        def close(self):
            self.closed = True

    stdin = io.BytesIO()
    stdout = Stream(101)
    stderr_stream = Stream(102)
    waits: list[float] = []
    process = SimpleNamespace(
        stdin=stdin,
        stdout=stdout,
        stderr=stderr_stream,
        wait=lambda timeout: waits.append(timeout) or 0,
    )

    class Selector:
        def __init__(self):
            self.entries: dict[int, tuple[object, str]] = {}

        def register(self, stream, event, data):
            self.entries[stream.fileno()] = (stream, data)

        def select(self, timeout):
            return [
                (SimpleNamespace(fileobj=stream, data=data), None)
                for stream, data in self.entries.values()
            ]

        def unregister(self, stream):
            self.entries.pop(stream.fileno())

        def get_map(self):
            return self.entries

        def close(self):
            self.entries.clear()

    monkeypatch.setattr(gate.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(gate.os, "read", lambda descriptor, maximum: b"")
    monkeypatch.setattr(
        gate,
        "_write_psql_input",
        lambda active_process, payload, label, **kwargs: active_process.stdin.write(payload),
    )

    gate._finish_attested_psql(
        process,
        deadline=time.monotonic() + 1,
        stderr=bytearray(),
        label="attested probe",
    )

    assert stdin.closed
    assert stdout.closed and stderr_stream.closed
    assert waits and 0 < waits[0] <= 1


@pytest.mark.parametrize(
    ("field", "unsafe"),
    [
        ("parent_pid", 9999),
        ("executable", "/tmp/postgres"),
        ("control_group", "/user.slice/attacker.service"),
        ("namespace_identity_sha256", "b" * 64),
    ],
)
def test_backend_attestation_rejects_wrong_postmaster_child(
    field, unsafe
) -> None:
    postgresql = {
        "postgres_path": "/usr/lib/postgresql/16/bin/postgres",
        "expected_control_group": (
            "/system.slice/system-postgresql.slice/postgresql@16-main.service"
        ),
    }
    postmaster = {"pid": 3333, "namespace_identity_sha256": "a" * 64}
    attestation = {
        "backend_pid": 42001,
        "parent_pid": 3333,
        "executable": "/usr/lib/postgresql/16/bin/postgres",
        "control_group": (
            "/system.slice/system-postgresql.slice/postgresql@16-main.service"
        ),
        "namespace_identity_sha256": "a" * 64,
        "process_identity_sha256": "c" * 64,
    }
    attestation[field] = unsafe

    with pytest.raises(
        gate.CapacityGateError, match="not a child of the reviewed postmaster"
    ):
        gate._validate_postgresql_backend_attestation(
            postgresql, postmaster, attestation
        )


def test_non_superuser_does_not_attempt_session_preload_override() -> None:
    unprivileged = gate._psql_environment(privileged=False)["PGOPTIONS"]
    privileged = gate._psql_environment(privileged=True)["PGOPTIONS"]

    assert "-c local_preload_libraries= " in unprivileged
    assert "session_preload_libraries" not in unprivileged
    assert "-c session_preload_libraries= " in privileged


def test_every_production_sql_capture_passes_reviewed_postmaster() -> None:
    tree = ast.parse(GATE_PATH.read_text(encoding="utf-8"))
    capture = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_capture_postgresql"
    )
    sql_capture_names = {
        "_capture_system_probe",
        "_capture_postgresql_configuration",
        "_capture_catalog",
        "_capture_database_uuids",
    }
    calls = [
        node
        for node in ast.walk(capture)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in sql_capture_names
    ]

    assert calls
    assert {call.func.id for call in calls} == sql_capture_names
    for call in calls:
        keywords = {item.arg: item.value for item in call.keywords if item.arg is not None}
        assert "postmaster" in keywords, ast.unparse(call)
        assert isinstance(keywords["postmaster"], ast.Name)
        assert keywords["postmaster"].id == "process_before"


@pytest.mark.skipif(
    not hasattr(os, "set_blocking"), reason="nonblocking pipe control is Unix-only"
)
def test_attested_runner_bounds_a_blocked_stdin_write(monkeypatch) -> None:
    """A full psql input pipe must not bypass the gate's monotonic deadline."""
    process = _FakeProcess()
    terminations: list[int] = []
    read_descriptor, write_descriptor = os.pipe()
    os.set_blocking(write_descriptor, False)
    try:
        while True:
            os.write(write_descriptor, b"x" * 65_536)
    except BlockingIOError:
        pass
    os.set_blocking(write_descriptor, True)
    process.stdin = os.fdopen(write_descriptor, "wb", buffering=0)
    monkeypatch.setattr(gate.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(gate, "_command_timeout", lambda deadline_ns: 0.03)

    def read(active_process, marker, *, deadline, **kwargs):
        if time.monotonic() >= deadline:
            raise gate.CapacityGateError("attested probe timed out")
        return [{"backend_pid": 42001}]

    monkeypatch.setattr(gate, "_read_psql_marker", read)
    monkeypatch.setattr(
        gate,
        "_terminate_process_group",
        lambda active_process: terminations.append(active_process.pid),
    )

    try:
        started = time.monotonic()
        with pytest.raises(gate.CapacityGateError, match="timed out"):
            gate._run_attested_psql_commands(
                _connection(),
                {"cluster": "reviewed"},
                {"pid": 3333},
                "odoo_test",
                ["SELECT 1"],
                deadline_ns=None,
            )
        elapsed = time.monotonic() - started
    finally:
        os.close(read_descriptor)

    assert terminations == [9100]
    assert elapsed < 0.15, "blocking stdin write escaped the 30 ms runner deadline"

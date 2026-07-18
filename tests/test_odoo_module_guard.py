from __future__ import annotations

import json
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo.module_guard import (
    ADVISORY_KEY,
    ADVISORY_NAMESPACE,
    MODULE_GUARD_PROTOCOL_VERSION,
    ModuleGuard,
    ModuleGuardError,
    _ADVISORY_LOCK_STATUS_SQL,
    _ADVISORY_HELD_SQL,
    _ADVISORY_UNLOCK_SQL,
    _DATABASE_IDENTITY_SQL,
    _DATABASE_UUID_SQL,
    _INSTALLED_MODULES_SQL,
    _LOCK_TIMEOUT_SQL,
    _PENDING_MODULES_SQL,
    _RESIDUAL_ADVISORY_LOCK_SQL,
    _TABLE_LOCK_SQL,
    _TABLE_LOCK_STATUS_SQL,
    _establish_database_guard,
    _module_guard_helper_main,
    acquire_module_guard,
)
from odoo_accounting_cli_v3.odoo.runner import RuntimeConfig


DATABASE_NAME = "odoo_v3_sandbox"
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
BACKEND_START = datetime(2026, 7, 18, 1, 2, 3, 456789, tzinfo=timezone.utc)


class FakeCursor:
    def __init__(self, *, pending: bool = False, graph_version: str = "19.0.2.0"):
        self.pending = pending
        self.graph_version = graph_version
        self.events: list[tuple[str, object]] = []
        self._rows: list[tuple[object, ...]] = []
        self.closed = False

    def execute(self, statement: str, parameters=None) -> None:
        self.events.append((statement, parameters))
        if statement == _LOCK_TIMEOUT_SQL:
            self._rows = [("3000ms",)]
        elif statement == _ADVISORY_LOCK_STATUS_SQL:
            self._rows = [(True,)]
        elif statement == _TABLE_LOCK_SQL:
            self._rows = []
        elif statement == _ADVISORY_HELD_SQL:
            self._rows = [(True,)]
        elif statement == _DATABASE_IDENTITY_SQL:
            self._rows = [(DATABASE_NAME, 9123, BACKEND_START)]
        elif statement == _DATABASE_UUID_SQL:
            self._rows = [(DATABASE_UUID,)]
        elif statement == _PENDING_MODULES_SQL:
            self._rows = [(self.pending,)]
        elif statement == _INSTALLED_MODULES_SQL:
            self._rows = [
                ("account", self.graph_version),
                ("purchase", "19.0.1.0"),
            ]
        elif statement == _TABLE_LOCK_STATUS_SQL:
            self._rows = [(True,)]
        elif statement == _ADVISORY_UNLOCK_SQL:
            self._rows = [(True,)]
        elif statement == _RESIDUAL_ADVISORY_LOCK_SQL:
            self._rows = [(0,)]
        else:  # pragma: no cover - a new SQL statement must be explicit here.
            raise AssertionError(f"unexpected SQL: {statement}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self, cursor: FakeCursor):
        self._cursor = cursor
        self.rollbacks = 0
        self.closed = False

    def cursor(self) -> FakeCursor:
        return self._cursor

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


def _runtime(tmp_path: Path) -> RuntimeConfig:
    return RuntimeConfig(
        instance_id="odoo19@sandbox",
        environment="sandbox",
        capability_channel="staged",
        database_name=DATABASE_NAME,
        database_uuid=DATABASE_UUID,
        odoo_python=tmp_path / "python",
        odoo_python_sha256="1" * 64,
        odoo_bin=tmp_path / "odoo-bin",
        odoo_bin_sha256="2" * 64,
        odoo_config=tmp_path / "odoo.conf",
        odoo_config_sha256="3" * 64,
        release_root=tmp_path / "release",
        canonical_package_path=tmp_path / "package.tar.gz",
        canonical_package_sha256="4" * 64,
        auth_state_path=tmp_path / "read-auth.sqlite3",
        receipt_state_path=tmp_path / "read-receipt.sqlite3",
        auth_key_id="read-auth-v1",
        receipt_key_id="read-receipt-v1",
        auth_secret_path=tmp_path / "read-auth.hmac",
        receipt_secret_path=tmp_path / "read-receipt.hmac",
    )


def _evidence(*, version: str = "19.0.2.0") -> dict[str, object]:
    from odoo_accounting_cli_v3.odoo.module_graph import build_trusted_module_graph

    graph = build_trusted_module_graph(
        [
            {"name": "account", "latest_version": version},
            {"name": "purchase", "latest_version": "19.0.1.0"},
        ]
    )
    return {
        "guard_protocol_version": MODULE_GUARD_PROTOCOL_VERSION,
        "database_name": DATABASE_NAME,
        "database_uuid": DATABASE_UUID,
        "backend_pid": 9123,
        "backend_start": "2026-07-18T01:02:03.456789Z",
        "advisory_lock": {
            "namespace": ADVISORY_NAMESPACE,
            "key": ADVISORY_KEY,
            "mode": "shared",
        },
        "table_lock": {
            "relation": "public.ir_module_module",
            "mode": "SHARE",
        },
        "module_graph": graph.evidence,
    }


def _frame(status: str, **values: object) -> bytes:
    return (
        json.dumps(
            {"protocol": MODULE_GUARD_PROTOCOL_VERSION, "status": status, **values},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


class FakeSocket:
    def __init__(self, responses: list[bytes]):
        self.responses = list(responses)
        self.sent: list[dict[str, object]] = []
        self.closed = False

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, value: bytes) -> None:
        self.sent.append(json.loads(value))

    def recv(self, _maximum: int) -> bytes:
        if not self.responses:
            return b""
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    def __init__(self, *, returncode: int | None = None):
        self.returncode = returncode
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        assert timeout is None or timeout > 0
        self.returncode = 0 if self.returncode is None else self.returncode
        return self.returncode

    def kill(self):
        self.terminated = True
        self.returncode = -9


def test_database_guard_takes_fixed_shared_advisory_before_table_share_and_returns_evidence():
    cursor = FakeCursor()
    connection = FakeConnection(cursor)

    session = _establish_database_guard(
        connection,
        expected_database_name=DATABASE_NAME,
        expected_database_uuid=DATABASE_UUID,
        lock_timeout_ms=3000,
    )

    assert [event[0] for event in cursor.events[:3]] == [
        _LOCK_TIMEOUT_SQL,
        _ADVISORY_LOCK_STATUS_SQL,
        _TABLE_LOCK_SQL,
    ]
    assert cursor.events[1][1] == (ADVISORY_NAMESPACE, ADVISORY_KEY)
    assert session.evidence.as_dict() == _evidence()

    assert session.probe().as_dict() == _evidence()
    session.release()
    assert connection.closed is True
    assert connection.rollbacks == 2
    unlock_index = [item[0] for item in cursor.events].index(_ADVISORY_UNLOCK_SQL)
    residual_index = [item[0] for item in cursor.events].index(
        _RESIDUAL_ADVISORY_LOCK_SQL
    )
    assert unlock_index < residual_index
    assert cursor.events[unlock_index][1] == (ADVISORY_NAMESPACE, ADVISORY_KEY)


def test_database_guard_rejects_pending_modules_and_cleans_session_lock():
    cursor = FakeCursor(pending=True)
    connection = FakeConnection(cursor)

    with pytest.raises(ModuleGuardError, match="pending module operation"):
        _establish_database_guard(
            connection,
            expected_database_name=DATABASE_NAME,
            expected_database_uuid=DATABASE_UUID,
            lock_timeout_ms=3000,
        )

    assert connection.closed is True
    assert connection.rollbacks >= 1
    assert _ADVISORY_UNLOCK_SQL in [item[0] for item in cursor.events]


def test_database_guard_rejects_database_uuid_mismatch_without_ready_evidence():
    cursor = FakeCursor()
    connection = FakeConnection(cursor)

    with pytest.raises(ModuleGuardError, match="database identity"):
        _establish_database_guard(
            connection,
            expected_database_name=DATABASE_NAME,
            expected_database_uuid="22222222-2222-4222-8222-222222222222",
            lock_timeout_ms=3000,
        )

    assert connection.closed is True
    assert _ADVISORY_UNLOCK_SQL in [item[0] for item in cursor.events]


def test_final_probe_detects_graph_change_and_aborts_helper(monkeypatch):
    control = FakeSocket([_frame("probed", evidence=_evidence(version="19.0.9.0"))])
    process = FakeProcess()
    killed: list[FakeProcess] = []
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.odoo.module_guard._kill_child_process_group",
        lambda value: killed.append(value),
    )
    guard = ModuleGuard(process, control, _evidence(), timeout_seconds=1.0)

    with pytest.raises(ModuleGuardError, match="evidence changed"):
        guard.final_probe()

    assert killed == [process]
    assert control.closed is True


def test_malformed_probe_evidence_also_aborts_helper(monkeypatch):
    malformed = {**_evidence(), "backend_pid": True}
    control = FakeSocket([_frame("probed", evidence=malformed)])
    process = FakeProcess()
    killed: list[FakeProcess] = []
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.odoo.module_guard._kill_child_process_group",
        lambda value: killed.append(value),
    )
    guard = ModuleGuard(process, control, _evidence(), timeout_seconds=1.0)

    with pytest.raises(ModuleGuardError, match="backend PID"):
        guard.final_probe()

    assert killed == [process]
    assert control.closed is True


def test_eof_or_dead_helper_fails_closed(monkeypatch):
    control = FakeSocket([])
    process = FakeProcess()
    killed: list[FakeProcess] = []
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.odoo.module_guard._kill_child_process_group",
        lambda value: killed.append(value),
    )
    guard = ModuleGuard(process, control, _evidence(), timeout_seconds=1.0)

    with pytest.raises(ModuleGuardError, match="closed its private control socket"):
        guard.final_probe()

    assert killed == [process]


def test_success_requires_final_probe_then_exact_release_acknowledgement():
    control = FakeSocket(
        [
            _frame("probed", evidence=_evidence()),
            _frame("released"),
        ]
    )
    process = FakeProcess()
    guard = ModuleGuard(process, control, _evidence(), timeout_seconds=1.0)

    with pytest.raises(ModuleGuardError, match="final probe"):
        guard.release()
    assert guard.final_probe() == _evidence()
    guard.release()

    assert [item["command"] for item in control.sent] == ["probe", "release"]
    assert control.closed is True
    assert process.returncode == 0


def test_helper_protocol_holds_one_backend_until_probe_and_explicit_release(monkeypatch):
    cursor = FakeCursor()
    connection = FakeConnection(cursor)
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.odoo.module_guard._open_guard_database",
        lambda _config_path, _database_name: connection,
    )
    parent, child = socket.socketpair()
    child_fd = child.detach()

    import threading

    helper = threading.Thread(
        target=_module_guard_helper_main,
        args=(child_fd,),
        daemon=True,
    )
    helper.start()
    parent.sendall(
        _frame(
            "request",
            command="acquire",
            config_path="/etc/odoo/odoo.conf",
            database_name=DATABASE_NAME,
            database_uuid=DATABASE_UUID,
            lock_timeout_ms=3000,
        )
    )
    ready = json.loads(parent.makefile("rb").readline())
    assert ready == {
        "protocol": MODULE_GUARD_PROTOCOL_VERSION,
        "status": "ready",
        "evidence": _evidence(),
    }
    assert connection.closed is False

    parent.sendall(_frame("request", command="probe"))
    probed = json.loads(parent.makefile("rb").readline())
    assert probed["status"] == "probed"
    assert probed["evidence"] == _evidence()
    assert connection.closed is False

    parent.sendall(_frame("request", command="release"))
    released = json.loads(parent.makefile("rb").readline())
    assert released == {
        "protocol": MODULE_GUARD_PROTOCOL_VERSION,
        "status": "released",
    }
    helper.join(timeout=2)
    assert not helper.is_alive()
    assert connection.closed is True
    parent.close()


def test_parent_spawn_keeps_database_identity_off_argv_and_environment(
    tmp_path: Path, monkeypatch
):
    from odoo_accounting_cli_v3.odoo import module_guard

    config = _runtime(tmp_path)
    parent = FakeSocket([_frame("ready", evidence=_evidence())])
    child = SimpleNamespace(fileno=lambda: 43, close=lambda: None)
    spawned: dict[str, object] = {}
    process = FakeProcess()

    monkeypatch.setattr(module_guard.sys, "platform", "linux")
    monkeypatch.setattr(module_guard, "_validate_runtime_paths", lambda _value: None)
    monkeypatch.setattr(module_guard, "_validate_child_environment", lambda _value: None)
    monkeypatch.setattr(module_guard.socket, "socketpair", lambda *args: (parent, child))
    monkeypatch.setattr(
        module_guard,
        "_linux_supervisor_argv",
        lambda argv, payload_fd: ["supervisor", str(payload_fd), "--", *argv],
    )

    def popen(argv, **kwargs):
        spawned["argv"] = argv
        spawned.update(kwargs)
        return process

    monkeypatch.setattr(module_guard.subprocess, "Popen", popen)
    guard = acquire_module_guard(config, timeout_seconds=1, lock_timeout_ms=3000)

    argv_text = "\0".join(spawned["argv"])
    environment_text = "\0".join(
        f"{key}={value}" for key, value in spawned["env"].items()
    )
    assert DATABASE_NAME not in argv_text
    assert DATABASE_UUID not in argv_text
    assert DATABASE_NAME not in environment_text
    assert DATABASE_UUID not in environment_text
    assert parent.sent[0]["database_name"] == DATABASE_NAME
    assert parent.sent[0]["database_uuid"] == DATABASE_UUID
    guard.abort()


def test_guard_is_linux_only_and_validates_bounded_lock_timeout(
    tmp_path: Path, monkeypatch
):
    config = _runtime(tmp_path)
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.odoo.module_guard.sys.platform", "win32"
    )
    with pytest.raises(ModuleGuardError, match="Linux"):
        acquire_module_guard(config)
    with pytest.raises(ModuleGuardError, match="lock_timeout_ms"):
        acquire_module_guard(config, lock_timeout_ms=0)

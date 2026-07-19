from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from odoo_accounting_cli_v3.historical_router import (
    HistoricalReleaseRouter as _HistoricalReleaseRouter,
    HistoricalRoute,
    HistoricalRouterError,
    _run_bounded_child,
    load_historical_routing_manifest,
)
from odoo_accounting_cli_v3.operations import Operation, State, canonical_json
from odoo_accounting_cli_v3.persistence import OperationNotFound
from odoo_accounting_cli_v3.write_receipts import (
    create_recovery_plan,
    create_recovery_plan_v2,
)


CURRENT_RELEASE = "a" * 64
CURRENT_REGISTRY = "b" * 64
OLD_RELEASE = "c" * 64
OLD_REGISTRY = "d" * 64


def _test_effect_finalizer_preconnector(
    _route: HistoricalRoute,
) -> socket.socket:
    connection, peer = socket.socketpair()
    peer.close()
    connection.set_inheritable(False)
    return connection


class RecordingFinalizerPreconnector:
    def __init__(self) -> None:
        self.routes: list[HistoricalRoute] = []
        self.connections: list[socket.socket] = []
        self.peers: list[socket.socket] = []

    def __call__(self, route: HistoricalRoute) -> socket.socket:
        connection, peer = socket.socketpair()
        connection.set_inheritable(False)
        self.routes.append(route)
        self.connections.append(connection)
        self.peers.append(peer)
        return connection

    def close(self) -> None:
        for connection in (*self.connections, *self.peers):
            connection.close()


@pytest.fixture
def finalizer_preconnector() -> Any:
    connector = RecordingFinalizerPreconnector()
    try:
        yield connector
    finally:
        connector.close()


def HistoricalReleaseRouter(*args: Any, **kwargs: Any) -> _HistoricalReleaseRouter:
    kwargs.setdefault(
        "effect_finalizer_preconnector",
        _test_effect_finalizer_preconnector,
    )
    return _HistoricalReleaseRouter(*args, **kwargs)


def _context() -> dict[str, Any]:
    return {
        "allowed_company_ids": [7],
        "audience": "odoo-accounting-cli-v3",
        "auth_expires_at": "2026-07-15T08:05:00Z",
        "auth_issued_at": "2026-07-15T08:00:00Z",
        "auth_key_id": "write-auth-v2",
        "auth_request_digest": "1" * 64,
        "auth_signature": "2" * 64,
        "auth_signature_purpose": "write_action_context_v2",
        "auth_signature_version": 2,
        "auth_token_id": "write-token-1",
        "company_id": 7,
        "database_name": "odoo_v3_sandbox",
        "database_uuid": "11111111-1111-4111-8111-111111111111",
        "environment": "sandbox",
        "odoo_instance_id": "odoo19@sandbox",
        "principal": "pi:user-42",
        "user_id": 42,
    }


def _request(action: str, *, operation_id: str = "op-1") -> dict[str, Any]:
    context = _context()
    if action == "operation.prepare":
        return {
            "context": context,
            "operation_id": operation_id,
            "request_id": f"request-{operation_id}",
            "capability_id": "acct.invoice.customer_create.v1",
            "parameters": {
                "company_id": 7,
                "idempotency_key": f"key-{operation_id}",
            },
        }
    if action == "operation.approve_execute":
        return {
            "context": context,
            "operation_id": operation_id,
            "reconciliation_only": False,
            "approval": {
                "approver_user_id": 99,
                "company_id": 7,
                "expires_at": "2026-07-15T08:05:00Z",
                "issued_at": "2026-07-15T08:00:00Z",
                "key_id": "approval-v3",
                "nonce": "approval-nonce-1",
                "operation_digest": "3" * 64,
                "operation_id": operation_id,
                "operation_revision": 2,
                "precheck_digest": "4" * 64,
                "request_id": f"request-{operation_id}",
                "signature": "5" * 64,
                "signature_purpose": "approval_v3",
                "signature_version": 3,
                "user_id": 42,
            },
        }
    if action == "operation.recover":
        return {
            "context": context,
            "origin_operation_id": "op-origin",
            "expected_origin_revision": 6,
            "recovery_operation_id": "op-recovery",
            "request_id": "request-recovery",
            "recovery_date": "2026-07-16",
            "reason": "Reverse the verified origin operation",
            "idempotency_key": "recover-origin-1",
        }
    return {"context": context, "operation_id": operation_id}


@dataclass
class FakeOperation:
    operation_id: str
    release_digest: str
    registry_digest: str
    revision: int = 6
    principal: str = "pi:user-42"
    user_id: int = 42
    company_id: int = 7
    odoo_instance_id: str = "odoo19@sandbox"
    database_name: str = "odoo_v3_sandbox"
    database_uuid: str = "11111111-1111-4111-8111-111111111111"
    environment: str = "sandbox"
    capability_id: str = "acct.invoice.customer_create.v1"
    digest: str = "6" * 64
    state: State = State.COMPLETED


class FakeStore:
    def __init__(self) -> None:
        self.operations: dict[str, FakeOperation] = {}
        self.bindings: dict[str, Any] = {}
        self.final_receipts: dict[str, tuple[Any, ...]] = {}

    def get_operation(self, operation_id: str) -> FakeOperation:
        try:
            return self.operations[operation_id]
        except KeyError as exc:
            raise OperationNotFound("operation does not exist") from exc

    def get_recovery_operation_binding(self, recovery_operation_id: str) -> Any:
        try:
            return self.bindings[recovery_operation_id]
        except KeyError as exc:
            raise OperationNotFound("recovery binding does not exist") from exc

    def recovery_plan(self, operation_id: str) -> dict[str, Any]:
        operation = self.operations[operation_id]
        return create_recovery_plan_v2(
            origin_operation_id=operation_id,
            recovery_capability_id="acct.recovery.execute.v1",
            status="available",
            method="cancel draft move",
            requires_approval=True,
            action_targets=[
                {
                    "company_id": operation.company_id,
                    "model": "account.move",
                    "record_fingerprint": "7" * 64,
                    "record_id": 100,
                    "record_state": "draft",
                }
            ],
            guard_records=[
                {
                    "company_id": operation.company_id,
                    "expected_outcome": "survive_exact",
                    "model": "account.move.line",
                    "record_fingerprint": "8" * 64,
                    "record_id": 101,
                    "record_state": "draft",
                }
            ],
            oracle_id="cancel_draft_move_exact_v1",
            parameters={"company_id": operation.company_id, "move_id": 100},
        )

    def receipt(self, operation_id: str, plan: dict[str, Any]) -> Any:
        operation = self.operations[operation_id]
        return SimpleNamespace(
            operation_id=operation.operation_id,
            operation_digest=operation.digest,
            operation_revision=operation.revision,
            terminal_state=operation.state.value,
            principal=operation.principal,
            user_id=operation.user_id,
            company_id=operation.company_id,
            body={
                "capability_id": operation.capability_id,
                "company_id": operation.company_id,
                "database_name": operation.database_name,
                "database_uuid": operation.database_uuid,
                "environment": operation.environment,
                "odoo_instance_id": operation.odoo_instance_id,
                "operation_digest": operation.digest,
                "operation_id": operation.operation_id,
                "operation_revision": operation.revision,
                "principal": operation.principal,
                "receipt_details": {"recovery_plan": plan},
                "registry_digest": operation.registry_digest,
                "release_digest": operation.release_digest,
                "terminal_state": operation.state.value,
                "user_id": operation.user_id,
            },
        )

    def get_final_write_receipts(self, operation_id: str) -> tuple[Any, ...]:
        if operation_id in self.final_receipts:
            return self.final_receipts[operation_id]
        return (self.receipt(operation_id, self.recovery_plan(operation_id)),)


def _write(path: Path, value: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return hashlib.sha256(value).hexdigest()


def _route(
    root: Path,
    *,
    name: str,
    release_digest: str,
    registry_digest: str,
) -> dict[str, Any]:
    executable = root / name / "bin" / "odoo-accounting-cli-v3"
    runtime = root / name / "write-runtime.json"
    executable_digest = _write(executable, f"launcher:{name}".encode())
    runtime_digest = _write(runtime, canonical_json({"release": name}))
    if os.name == "posix":
        executable.chmod(0o755)
        runtime.chmod(0o640)
    return {
        "release_digest": release_digest,
        "registry_digest": registry_digest,
        "executable_path": str(executable.resolve()),
        "executable_sha256": executable_digest,
        "runtime_config_path": str(runtime.resolve()),
        "runtime_config_sha256": runtime_digest,
    }


@pytest.fixture
def router_files(tmp_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    current = _route(
        tmp_path,
        name="current",
        release_digest=CURRENT_RELEASE,
        registry_digest=CURRENT_REGISTRY,
    )
    old = _route(
        tmp_path,
        name="old",
        release_digest=OLD_RELEASE,
        registry_digest=OLD_REGISTRY,
    )
    manifest = tmp_path / "historical-routes.json"
    manifest.write_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "current_release_digest": CURRENT_RELEASE,
                "routes": [current, old],
            }
        )
    )
    if os.name == "posix":
        manifest.chmod(0o640)
    return manifest.resolve(), current, old


def _response(
    action: str,
    *,
    operation_id: str,
    release_digest: str,
    registry_digest: str,
) -> dict[str, Any]:
    data: dict[str, Any] = {"operation_id": operation_id}
    if action in {"operation.prepare", "operation.status", "operation.recover"}:
        data["operation"] = {
            "operation_id": operation_id,
            "registry_digest": registry_digest,
            "release_digest": release_digest,
        }
    elif action == "operation.preview":
        data["precheck"] = {
            "registry_digest": registry_digest,
            "release_digest": release_digest,
        }
        data["precheck_identity"] = {
            "operation_id": operation_id,
            "precheck_digest": "9" * 64,
            "registry_digest": registry_digest,
            "release_digest": release_digest,
        }
    else:
        data["audit_receipt"] = {
            "operation_id": operation_id,
            "registry_digest": registry_digest,
            "release_digest": release_digest,
        }
        data["operation_state"] = "completed"
        data["verification"] = {"passed": True}
    if action == "operation.recover":
        data["origin_operation_id"] = "op-origin"
    response: dict[str, Any] = {"command": action, "data": data, "ok": True}
    if action in {"operation.approve_execute", "operation.result"}:
        response["business_succeeded"] = True
    return response


def _completed(argv: list[str], response: dict[str, Any]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        argv,
        0,
        stdout=canonical_json(response),
        stderr=b"",
    )


def _durable_operation(
    *,
    operation_id: str,
    request_id: str,
    capability_id: str,
    parameters: dict[str, Any],
    release_digest: str,
    registry_digest: str,
) -> Operation:
    context = _context()
    return Operation.prepare(
        operation_id=operation_id,
        request_id=request_id,
        capability_id=capability_id,
        parameters=parameters,
        principal=context["principal"],
        user_id=context["user_id"],
        company_id=context["company_id"],
        idempotency_key=parameters["idempotency_key"],
        odoo_instance_id=context["odoo_instance_id"],
        database_name=context["database_name"],
        database_uuid=context["database_uuid"],
        environment=context["environment"],
        registry_digest=registry_digest,
        release_digest=release_digest,
    )


def test_prepare_always_uses_current_route_and_only_canonical_stdin(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, current, _old = router_files
    store = FakeStore()
    calls: list[
        tuple[list[str], bytes, dict[str, str], float, tuple[int, ...]]
    ] = []

    def run(argv, *, stdin, env, timeout_seconds, pass_fds, **_kwargs):
        assert len(pass_fds) == 1
        descriptor_metadata = os.fstat(pass_fds[0])
        runtime_metadata = Path(current["runtime_config_path"]).stat()
        assert (descriptor_metadata.st_dev, descriptor_metadata.st_ino) == (
            runtime_metadata.st_dev,
            runtime_metadata.st_ino,
        )
        calls.append((argv, stdin, env, timeout_seconds, pass_fds))
        request = json.loads(stdin)
        store.operations["op-new"] = _durable_operation(
            operation_id=request["operation_id"],
            request_id=request["request_id"],
            capability_id=request["capability_id"],
            parameters=request["parameters"],
            release_digest=CURRENT_RELEASE,
            registry_digest=CURRENT_REGISTRY,
        )
        return _completed(
            argv,
            _response(
                "operation.prepare",
                operation_id=request["operation_id"],
                release_digest=CURRENT_RELEASE,
                registry_digest=CURRENT_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router.time.monotonic",
        lambda: 100.0,
    )
    router = HistoricalReleaseRouter(
        manifest, store, require_root_owner=False, timeout_seconds=9
    )
    request = _request("operation.prepare", operation_id="op-new")

    response = router.dispatch("operation.prepare", request)

    assert response["ok"] is True
    assert len(calls) == 1
    argv, stdin, env, timeout, pass_fds = calls[0]
    assert argv == [current["executable_path"], "operation", "prepare"]
    assert stdin == canonical_json(request)
    assert timeout == 9
    assert env == {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_REGISTRY_DIGEST": CURRENT_REGISTRY,
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_RELEASE_DIGEST": CURRENT_RELEASE,
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG": current[
            "runtime_config_path"
        ],
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_SHA256": current[
            "runtime_config_sha256"
        ],
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_FD": str(
            pass_fds[0]
        ),
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_DEADLINE_MONOTONIC": "109.0",
    }
    with pytest.raises(OSError):
        os.fstat(pass_fds[0])


def test_approve_execute_hands_one_connected_finalizer_fd_to_exact_child(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    finalizer_preconnector: RecordingFinalizerPreconnector,
) -> None:
    manifest, _current, old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation(
        "op-old", OLD_RELEASE, OLD_REGISTRY
    )
    request = _request("operation.approve_execute", operation_id="op-old")
    observed: list[tuple[bytes, dict[str, str], tuple[int, ...], float]] = []

    def run(
        argv: list[str],
        *,
        stdin: bytes,
        env: dict[str, str],
        pass_fds: tuple[int, ...],
        timeout_seconds: float,
        **_kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        assert argv == [
            old["executable_path"],
            "operation",
            "approve-execute",
        ]
        assert stdin == canonical_json(request)
        assert len(pass_fds) == 2
        runtime_descriptor, finalizer_descriptor = pass_fds
        assert runtime_descriptor > 2
        assert finalizer_descriptor > 2
        assert runtime_descriptor != finalizer_descriptor
        connection = finalizer_preconnector.connections[0]
        assert connection.fileno() == finalizer_descriptor
        assert connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == (
            socket.SOCK_STREAM
        )
        assert connection.getpeername() is not None
        assert connection.get_inheritable() is False
        assert env["ODOO_ACCOUNTING_CLI_V3_EFFECT_FINALIZER_FD"] == str(
            finalizer_descriptor
        )
        observed.append((stdin, env, pass_fds, timeout_seconds))
        return _completed(
            argv,
            _response(
                "operation.approve_execute",
                operation_id="op-old",
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router.time.monotonic",
        lambda: 100.0,
    )
    router = HistoricalReleaseRouter(
        manifest,
        store,
        require_root_owner=False,
        timeout_seconds=9,
        effect_finalizer_preconnector=finalizer_preconnector,
    )

    response = router.dispatch(
        "operation.approve_execute",
        request,
        deadline_monotonic=103.25,
    )

    assert response["ok"] is True
    assert len(observed) == 1
    assert observed[0][1][
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_DEADLINE_MONOTONIC"
    ] == "103.25"
    assert observed[0][3] == pytest.approx(3.25)
    assert finalizer_preconnector.routes == [
        HistoricalRoute(
            release_digest=OLD_RELEASE,
            registry_digest=OLD_REGISTRY,
            executable_path=Path(old["executable_path"]),
            executable_sha256=old["executable_sha256"],
            runtime_config_path=Path(old["runtime_config_path"]),
            runtime_config_sha256=old["runtime_config_sha256"],
        )
    ]
    assert finalizer_preconnector.connections[0].fileno() == -1


@pytest.mark.parametrize(
    "action",
    [
        "operation.prepare",
        "operation.preview",
        "operation.status",
        "operation.result",
        "operation.recover",
    ],
)
def test_non_execute_actions_never_receive_finalizer_authority(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    action: str,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    operation_id = "op-old"
    release_digest = OLD_RELEASE
    registry_digest = OLD_REGISTRY
    recovery_plan_digest: str | None = None
    if action == "operation.prepare":
        operation_id = "op-new"
        release_digest = CURRENT_RELEASE
        registry_digest = CURRENT_REGISTRY
    elif action == "operation.recover":
        origin = FakeOperation("op-origin", OLD_RELEASE, OLD_REGISTRY)
        store.operations[origin.operation_id] = origin
        recovery_plan_digest = store.recovery_plan(
            origin.operation_id
        )["plan_digest"]
        operation_id = "op-recovery"
    else:
        store.operations[operation_id] = FakeOperation(
            operation_id, OLD_RELEASE, OLD_REGISTRY
        )
    calls: list[dict[str, Any]] = []

    def forbidden_preconnector(_route: HistoricalRoute) -> socket.socket:
        raise AssertionError(f"{action} requested finalizer authority")

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(kwargs)
        request = json.loads(kwargs["stdin"])
        if action == "operation.prepare":
            store.operations[operation_id] = _durable_operation(
                operation_id=operation_id,
                request_id=request["request_id"],
                capability_id=request["capability_id"],
                parameters=request["parameters"],
                release_digest=release_digest,
                registry_digest=registry_digest,
            )
        elif action == "operation.recover":
            recovery = FakeOperation(
                operation_id, OLD_RELEASE, OLD_REGISTRY, revision=0
            )
            store.operations[operation_id] = recovery
            store.bindings[operation_id] = SimpleNamespace(
                origin_operation_id="op-origin",
                origin_operation_revision=6,
                recovery_operation_id=operation_id,
                plan_digest=recovery_plan_digest,
                registry_digest=OLD_REGISTRY,
                release_digest=OLD_RELEASE,
            )
        return _completed(
            argv,
            _response(
                action,
                operation_id=operation_id,
                release_digest=release_digest,
                registry_digest=registry_digest,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router.time.monotonic",
        lambda: 100.0,
    )
    router = HistoricalReleaseRouter(
        manifest,
        store,
        require_root_owner=False,
        effect_finalizer_preconnector=forbidden_preconnector,
    )
    request = _request(action, operation_id=operation_id)

    response = router.dispatch(action, request)

    assert response["ok"] is True
    assert len(calls) == 1
    assert calls[0]["stdin"] == canonical_json(request)
    assert len(calls[0]["pass_fds"]) == 1
    assert "ODOO_ACCOUNTING_CLI_V3_EFFECT_FINALIZER_FD" not in calls[0]["env"]


def test_outer_absolute_deadline_shrinks_the_historical_child_budget(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation(
        "op-old", OLD_RELEASE, OLD_REGISTRY
    )
    observed: list[tuple[float, dict[str, str]]] = []

    def run(argv, *, timeout_seconds, env, **_kwargs):
        observed.append((timeout_seconds, env))
        return _completed(
            argv,
            _response(
                "operation.status",
                operation_id="op-old",
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router.time.monotonic", lambda: 100.0
    )
    router = HistoricalReleaseRouter(
        manifest, store, require_root_owner=False, timeout_seconds=9
    )

    response = router.dispatch(
        "operation.status",
        _request("operation.status", operation_id="op-old"),
        deadline_monotonic=103.25,
    )

    assert response["ok"] is True
    assert observed[0][0] == pytest.approx(3.25)
    assert observed[0][1][
        "ODOO_ACCOUNTING_CLI_V3_TRUSTED_DEADLINE_MONOTONIC"
    ] == "103.25"


def test_expired_outer_deadline_never_starts_the_historical_child(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation(
        "op-old", OLD_RELEASE, OLD_REGISTRY
    )
    calls: list[object] = []
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router.time.monotonic", lambda: 104.0
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError) as raised:
        router.dispatch(
            "operation.status",
            _request("operation.status", operation_id="op-old"),
            deadline_monotonic=103.0,
        )

    assert raised.value.code == "historical_deadline_exceeded"
    assert raised.value.odoo_effect == "none"
    assert raised.value.retryable is True
    assert calls == []


def test_historical_result_is_rejected_if_outer_deadline_expires_after_child(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation(
        "op-old", OLD_RELEASE, OLD_REGISTRY
    )
    clock = iter((100.0, 104.0))

    def run(argv, **_kwargs):
        return _completed(
            argv,
            _response(
                "operation.status",
                operation_id="op-old",
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router.time.monotonic",
        lambda: next(clock),
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError) as raised:
        router.dispatch(
            "operation.status",
            _request("operation.status", operation_id="op-old"),
            deadline_monotonic=103.0,
        )

    assert raised.value.code == "historical_deadline_exceeded"
    assert raised.value.odoo_effect == "none"
    assert raised.value.retryable is True


def test_finalizer_preconnect_failure_never_starts_child_or_claims_odoo_effect(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation(
        "op-old", OLD_RELEASE, OLD_REGISTRY
    )
    routes: list[HistoricalRoute] = []
    child_calls: list[object] = []

    def unavailable(route: HistoricalRoute) -> socket.socket:
        routes.append(route)
        raise OSError("finalizer unavailable")

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child",
        lambda *args, **kwargs: child_calls.append((args, kwargs)),
    )
    router = HistoricalReleaseRouter(
        manifest,
        store,
        require_root_owner=False,
        effect_finalizer_preconnector=unavailable,
    )

    with pytest.raises(HistoricalRouterError) as raised:
        router.dispatch(
            "operation.approve_execute",
            _request("operation.approve_execute", operation_id="op-old"),
        )

    assert raised.value.code == "historical_effect_finalizer_unavailable"
    assert raised.value.odoo_effect == "none"
    assert raised.value.retryable is True
    assert raised.value.child_started is False
    assert len(routes) == 1
    assert child_calls == []


def test_spawn_failure_closes_broker_finalizer_socket_with_no_odoo_effect(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    finalizer_preconnector: RecordingFinalizerPreconnector,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation(
        "op-old", OLD_RELEASE, OLD_REGISTRY
    )

    def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise HistoricalRouterError(
            "historical child process could not be started",
            code="historical_child_unavailable",
            retryable=True,
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child",
        unavailable,
    )
    router = HistoricalReleaseRouter(
        manifest,
        store,
        require_root_owner=False,
        effect_finalizer_preconnector=finalizer_preconnector,
    )

    with pytest.raises(HistoricalRouterError) as raised:
        router.dispatch(
            "operation.approve_execute",
            _request("operation.approve_execute", operation_id="op-old"),
        )

    assert raised.value.code == "historical_child_unavailable"
    assert raised.value.odoo_effect == "none"
    assert raised.value.retryable is True
    assert raised.value.child_started is False
    assert len(finalizer_preconnector.connections) == 1
    assert finalizer_preconnector.connections[0].fileno() == -1


@pytest.mark.parametrize(
    "injected",
    [
        {"deadline_monotonic": 999.0},
        {"effect_finalizer_fd": 9},
        {"ODOO_ACCOUNTING_CLI_V3_EFFECT_FINALIZER_FD": "9"},
    ],
)
def test_request_cannot_control_deadline_or_finalizer_authority(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    injected: dict[str, Any],
) -> None:
    manifest, _current, _old = router_files
    connector_calls: list[HistoricalRoute] = []
    child_calls: list[object] = []

    def connector(route: HistoricalRoute) -> socket.socket:
        connector_calls.append(route)
        return _test_effect_finalizer_preconnector(route)

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child",
        lambda *args, **kwargs: child_calls.append((args, kwargs)),
    )
    router = HistoricalReleaseRouter(
        manifest,
        FakeStore(),
        require_root_owner=False,
        effect_finalizer_preconnector=connector,
    )
    request = {
        **_request("operation.approve_execute", operation_id="op-old"),
        **injected,
    }

    with pytest.raises(HistoricalRouterError, match="request contract"):
        router.dispatch("operation.approve_execute", request)

    assert connector_calls == []
    assert child_calls == []


def test_router_requires_a_callable_broker_main_preconnector(
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files

    for invalid in (None, object(), 7):
        with pytest.raises(HistoricalRouterError, match="preconnector"):
            _HistoricalReleaseRouter(
                manifest,
                FakeStore(),
                require_root_owner=False,
                effect_finalizer_preconnector=invalid,  # type: ignore[arg-type]
            )


def test_prepare_lost_response_accepts_only_exact_durable_idempotent_operation(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    request = _request("operation.prepare", operation_id="op-new-retry")
    existing = _durable_operation(
        operation_id="op-existing",
        request_id="request-from-first-attempt",
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        release_digest=CURRENT_RELEASE,
        registry_digest=CURRENT_REGISTRY,
    )

    def run(argv, **_kwargs):
        store.operations[existing.operation_id] = existing
        return _completed(
            argv,
            _response(
                "operation.prepare",
                operation_id=existing.operation_id,
                release_digest=CURRENT_RELEASE,
                registry_digest=CURRENT_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    response = router.dispatch("operation.prepare", request)
    assert response["data"]["operation_id"] == existing.operation_id
    assert "op-new-retry" not in store.operations

    store.operations.clear()
    drifted = _durable_operation(
        operation_id="op-existing",
        request_id="request-from-first-attempt",
        capability_id=request["capability_id"],
        parameters={**request["parameters"], "partner_id": 999},
        release_digest=CURRENT_RELEASE,
        registry_digest=CURRENT_REGISTRY,
    )

    def drift(argv, **_kwargs):
        store.operations[drifted.operation_id] = drifted
        return _completed(
            argv,
            _response(
                "operation.prepare",
                operation_id=drifted.operation_id,
                release_digest=CURRENT_RELEASE,
                registry_digest=CURRENT_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", drift
    )
    with pytest.raises(HistoricalRouterError, match="idempotency binding"):
        router.dispatch("operation.prepare", request)


def test_prepare_with_broker_resolved_existing_id_uses_retained_release(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, old = router_files
    store = FakeStore()
    request = _request("operation.prepare", operation_id="op-retained")
    operation = _durable_operation(
        operation_id=request["operation_id"],
        request_id=request["request_id"],
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        release_digest=OLD_RELEASE,
        registry_digest=OLD_REGISTRY,
    )
    store.operations[operation.operation_id] = operation
    calls: list[tuple[list[str], dict[str, str]]] = []

    def run(argv, *, env, **_kwargs):
        calls.append((argv, env))
        return _completed(
            argv,
            _response(
                "operation.prepare",
                operation_id=operation.operation_id,
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    response = router.dispatch("operation.prepare", request)

    assert response["data"]["operation_id"] == operation.operation_id
    assert calls[0][0] == [
        old["executable_path"],
        "operation",
        "prepare",
    ]
    assert calls[0][1]["ODOO_ACCOUNTING_CLI_V3_EXPECTED_RELEASE_DIGEST"] == (
        OLD_RELEASE
    )
    assert calls[0][1]["ODOO_ACCOUNTING_CLI_V3_EXPECTED_REGISTRY_DIGEST"] == (
        OLD_REGISTRY
    )


@pytest.mark.parametrize(
    "tamper",
    ["request_id", "capability", "parameters", "user", "database"],
)
def test_prepare_existing_id_requires_complete_signed_durable_binding(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    tamper: str,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    request = _request("operation.prepare", operation_id="op-retained")
    operation = _durable_operation(
        operation_id=request["operation_id"],
        request_id=request["request_id"],
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        release_digest=OLD_RELEASE,
        registry_digest=OLD_REGISTRY,
    )
    store.operations[operation.operation_id] = operation
    if tamper == "request_id":
        request["request_id"] = "different-request"
    elif tamper == "capability":
        request["capability_id"] = "acct.invoice.vendor_create.v1"
    elif tamper == "parameters":
        request["parameters"] = {**request["parameters"], "partner_id": 999}
    elif tamper == "user":
        request["context"] = {**request["context"], "user_id": 99}
    else:
        request["context"] = {
            **request["context"],
            "database_name": "odoo_v3_other_sandbox",
            "database_uuid": "22222222-2222-4222-8222-222222222222",
        }
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="context|idempotency binding"):
        router.dispatch("operation.prepare", request)
    assert called is False


def test_prepare_existing_id_requires_a_retained_manifest_route(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    request = _request("operation.prepare", operation_id="op-unretained")
    operation = _durable_operation(
        operation_id=request["operation_id"],
        request_id=request["request_id"],
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        release_digest="e" * 64,
        registry_digest="f" * 64,
    )
    store.operations[operation.operation_id] = operation
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="no retained historical route"):
        router.dispatch("operation.prepare", request)
    assert called is False


def test_recover_lost_response_accepts_only_exact_bound_recovery_operation(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    request = _request("operation.recover")
    origin = FakeOperation("op-origin", OLD_RELEASE, OLD_REGISTRY)
    store.operations[origin.operation_id] = origin
    plan_digest = store.recovery_plan(origin.operation_id)["plan_digest"]
    recovery_parameters = {
        "company_id": 7,
        "expected_recovery_plan_digest": plan_digest,
        "idempotency_key": request["idempotency_key"],
        "origin_operation_id": origin.operation_id,
        "reason": request["reason"],
        "recovery_date": request["recovery_date"],
    }

    def install(parameters: dict[str, Any]) -> Operation:
        recovery = _durable_operation(
            operation_id="op-recovery-existing",
            request_id="request-recovery-first-attempt",
            capability_id="acct.recovery.execute.v1",
            parameters=parameters,
            release_digest=OLD_RELEASE,
            registry_digest=OLD_REGISTRY,
        )
        store.operations[recovery.operation_id] = recovery
        store.bindings[recovery.operation_id] = SimpleNamespace(
            origin_operation_id=origin.operation_id,
            origin_operation_revision=origin.revision,
            recovery_operation_id=recovery.operation_id,
            plan_digest=plan_digest,
            registry_digest=OLD_REGISTRY,
            release_digest=OLD_RELEASE,
        )
        return recovery

    def run(argv, **_kwargs):
        recovery = install(recovery_parameters)
        return _completed(
            argv,
            _response(
                "operation.recover",
                operation_id=recovery.operation_id,
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    response = router.dispatch("operation.recover", request)
    assert response["data"]["operation_id"] == "op-recovery-existing"
    assert "op-recovery" not in store.operations

    store.operations = {origin.operation_id: origin}
    store.bindings.clear()

    def drift(argv, **_kwargs):
        recovery = install(
            {**recovery_parameters, "reason": "Different recovery content"}
        )
        return _completed(
            argv,
            _response(
                "operation.recover",
                operation_id=recovery.operation_id,
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", drift
    )
    with pytest.raises(HistoricalRouterError, match="idempotency binding"):
        router.dispatch("operation.recover", request)


@pytest.mark.parametrize(
    "action,command",
    [
        ("operation.preview", "preview"),
        ("operation.status", "status"),
        ("operation.result", "result"),
        ("operation.approve_execute", "approve-execute"),
    ],
)
def test_existing_operation_actions_route_by_durable_operation_release(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    action: str,
    command: str,
) -> None:
    manifest, _current, old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation("op-old", OLD_RELEASE, OLD_REGISTRY)
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(argv)
        return _completed(
            argv,
            _response(
                action,
                operation_id="op-old",
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    router.dispatch(action, _request(action, operation_id="op-old"))

    assert calls == [[old["executable_path"], "operation", command]]


def test_recover_routes_by_origin_then_requires_durable_recovery_binding(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, old = router_files
    store = FakeStore()
    origin = FakeOperation("op-origin", OLD_RELEASE, OLD_REGISTRY)
    store.operations[origin.operation_id] = origin
    plan_digest = store.recovery_plan(origin.operation_id)["plan_digest"]
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(argv)
        recovery = FakeOperation("op-recovery", OLD_RELEASE, OLD_REGISTRY, revision=0)
        store.operations[recovery.operation_id] = recovery
        store.bindings[recovery.operation_id] = SimpleNamespace(
            origin_operation_id=origin.operation_id,
            origin_operation_revision=origin.revision,
            recovery_operation_id=recovery.operation_id,
            plan_digest=plan_digest,
            registry_digest=OLD_REGISTRY,
            release_digest=OLD_RELEASE,
        )
        return _completed(
            argv,
            _response(
                "operation.recover",
                operation_id=recovery.operation_id,
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    router.dispatch("operation.recover", _request("operation.recover"))

    assert calls == [[old["executable_path"], "operation", "recover"]]


def test_recover_rejects_receipt_bound_v1_before_successful_old_child_starts(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    origin = FakeOperation("op-origin", OLD_RELEASE, OLD_REGISTRY)
    store.operations[origin.operation_id] = origin
    v1_plan = create_recovery_plan(
        origin_operation_id=origin.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="legacy flat target recovery",
        requires_approval=True,
        target_records=[
            {
                "company_id": origin.company_id,
                "model": "account.move",
                "record_fingerprint": "7" * 64,
                "record_id": 100,
                "record_state": "draft",
            }
        ],
        parameters={"company_id": origin.company_id, "move_id": 100},
    )
    store.final_receipts[origin.operation_id] = (
        store.receipt(origin.operation_id, v1_plan),
    )
    called = False

    def successful_old_child(argv, **_kwargs):
        nonlocal called
        called = True
        return _completed(
            argv,
            _response(
                "operation.recover",
                operation_id="op-recovery",
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child",
        successful_old_child,
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="executable V2"):
        router.dispatch("operation.recover", _request("operation.recover"))

    assert called is False


@pytest.mark.parametrize("receipt_state", ["missing", "tampered"])
def test_recover_rejects_missing_or_tampered_v2_receipt_before_child(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    receipt_state: str,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    origin = FakeOperation("op-origin", OLD_RELEASE, OLD_REGISTRY)
    store.operations[origin.operation_id] = origin
    if receipt_state == "missing":
        store.final_receipts[origin.operation_id] = ()
    else:
        plan = store.recovery_plan(origin.operation_id)
        plan["method"] = "tampered after digest"
        store.final_receipts[origin.operation_id] = (
            store.receipt(origin.operation_id, plan),
        )
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="recovery receipt|executable V2"):
        router.dispatch("operation.recover", _request("operation.recover"))
    assert called is False


@pytest.mark.parametrize(
    "action", ["operation.preview", "operation.approve_execute"]
)
def test_bound_v1_recovery_cannot_advance_lifecycle_before_child(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    action: str,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    origin = FakeOperation("op-origin", OLD_RELEASE, OLD_REGISTRY)
    recovery = FakeOperation(
        "op-recovery",
        OLD_RELEASE,
        OLD_REGISTRY,
        revision=0,
        capability_id="acct.recovery.execute.v1",
        state=State.PREPARED,
    )
    store.operations = {
        origin.operation_id: origin,
        recovery.operation_id: recovery,
    }
    v1_plan = create_recovery_plan(
        origin_operation_id=origin.operation_id,
        recovery_capability_id="acct.recovery.execute.v1",
        status="available",
        method="legacy flat target recovery",
        requires_approval=True,
        target_records=[
            {
                "company_id": origin.company_id,
                "model": "account.move",
                "record_fingerprint": "7" * 64,
                "record_id": 100,
                "record_state": "draft",
            }
        ],
        parameters={"company_id": origin.company_id, "move_id": 100},
    )
    store.final_receipts[origin.operation_id] = (
        store.receipt(origin.operation_id, v1_plan),
    )
    store.bindings[recovery.operation_id] = SimpleNamespace(
        origin_operation_id=origin.operation_id,
        origin_operation_revision=origin.revision,
        recovery_operation_id=recovery.operation_id,
        plan_digest=v1_plan["plan_digest"],
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )
    called = False

    def successful_old_child(argv, **_kwargs):
        nonlocal called
        called = True
        return _completed(
            argv,
            _response(
                action,
                operation_id=recovery.operation_id,
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child",
        successful_old_child,
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="executable V2"):
        router.dispatch(
            action, _request(action, operation_id=recovery.operation_id)
        )
    assert called is False


@pytest.mark.parametrize(
    "action", ["operation.preview", "operation.approve_execute"]
)
def test_bound_v2_recovery_can_advance_through_its_origin_release(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    action: str,
) -> None:
    manifest, _current, old = router_files
    store = FakeStore()
    origin = FakeOperation("op-origin", OLD_RELEASE, OLD_REGISTRY)
    recovery = FakeOperation(
        "op-recovery",
        OLD_RELEASE,
        OLD_REGISTRY,
        revision=0,
        capability_id="acct.recovery.execute.v1",
        state=State.PREPARED,
    )
    store.operations = {
        origin.operation_id: origin,
        recovery.operation_id: recovery,
    }
    plan = store.recovery_plan(origin.operation_id)
    store.bindings[recovery.operation_id] = SimpleNamespace(
        origin_operation_id=origin.operation_id,
        origin_operation_revision=origin.revision,
        recovery_operation_id=recovery.operation_id,
        plan_digest=plan["plan_digest"],
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(argv)
        return _completed(
            argv,
            _response(
                action,
                operation_id=recovery.operation_id,
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    response = router.dispatch(
        action, _request(action, operation_id=recovery.operation_id)
    )

    assert response["ok"] is True
    assert calls == [
        [
            old["executable_path"],
            "operation",
            {
                "operation.preview": "preview",
                "operation.approve_execute": "approve-execute",
            }[action],
        ]
    ]


@pytest.mark.parametrize("action", ["operation.status", "operation.result"])
def test_bound_v1_recovery_status_and_result_remain_historically_readable(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    action: str,
) -> None:
    manifest, _current, old = router_files
    store = FakeStore()
    recovery = FakeOperation(
        "op-recovery",
        OLD_RELEASE,
        OLD_REGISTRY,
        capability_id="acct.recovery.execute.v1",
    )
    store.operations[recovery.operation_id] = recovery
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(argv)
        return _completed(
            argv,
            _response(
                action,
                operation_id=recovery.operation_id,
                release_digest=OLD_RELEASE,
                registry_digest=OLD_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    response = router.dispatch(
        action, _request(action, operation_id=recovery.operation_id)
    )

    assert response["ok"] is True
    assert calls == [[old["executable_path"], "operation", action.split(".")[1]]]


def test_direct_recovery_capability_prepare_is_rejected_before_child(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    request = _request("operation.prepare", operation_id="op-recovery")
    request["capability_id"] = "acct.recovery.execute.v1"
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="origin receipt"):
        router.dispatch("operation.prepare", request)
    assert called is False


def test_recover_rejects_orphan_or_mismatched_recovery_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-origin"] = FakeOperation(
        "op-origin", OLD_RELEASE, OLD_REGISTRY
    )
    store.operations["op-recovery"] = FakeOperation(
        "op-recovery", OLD_RELEASE, OLD_REGISTRY
    )
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="unbound recovery operation"):
        router.dispatch("operation.recover", _request("operation.recover"))
    assert called is False

    store.bindings["op-recovery"] = SimpleNamespace(
        origin_operation_id="different-origin",
        origin_operation_revision=6,
        recovery_operation_id="op-recovery",
        plan_digest=store.recovery_plan("op-origin")["plan_digest"],
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )
    with pytest.raises(HistoricalRouterError, match="recovery binding mismatch"):
        router.dispatch("operation.recover", _request("operation.recover"))
    assert called is False

    store.bindings["op-recovery"] = SimpleNamespace(
        origin_operation_id="op-origin",
        origin_operation_revision=6,
        recovery_operation_id="op-recovery",
        plan_digest="e" * 64,
        registry_digest=OLD_REGISTRY,
        release_digest=OLD_RELEASE,
    )
    with pytest.raises(HistoricalRouterError, match="recovery binding mismatch"):
        router.dispatch("operation.recover", _request("operation.recover"))
    assert called is False


def test_unknown_operation_and_registry_route_mismatch_fail_before_child(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="durable operation route"):
        router.dispatch("operation.status", _request("operation.status"))
    store.operations["op-1"] = FakeOperation("op-1", OLD_RELEASE, CURRENT_REGISTRY)
    with pytest.raises(HistoricalRouterError, match="registry binding"):
        router.dispatch("operation.status", _request("operation.status"))
    assert called is False


@pytest.mark.parametrize("field", ["release_digest", "registry_digest"])
def test_child_response_identity_mismatch_is_rejected_after_store_recheck(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    field: str,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation("op-old", OLD_RELEASE, OLD_REGISTRY)

    def run(argv, **_kwargs):
        identity = {
            "release_digest": OLD_RELEASE,
            "registry_digest": OLD_REGISTRY,
        }
        identity[field] = "e" * 64
        return _completed(
            argv,
            _response("operation.status", operation_id="op-old", **identity),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="child response identity"):
        router.dispatch(
            "operation.status", _request("operation.status", operation_id="op-old")
        )


def test_prepare_requires_child_to_persist_the_current_operation(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()

    def run(argv, **_kwargs):
        return _completed(
            argv,
            _response(
                "operation.prepare",
                operation_id="op-new",
                release_digest=CURRENT_RELEASE,
                registry_digest=CURRENT_REGISTRY,
            ),
        )

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match="durable operation route"):
        router.dispatch(
            "operation.prepare", _request("operation.prepare", operation_id="op-new")
        )


def test_request_cannot_select_runtime_release_or_binary(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    called = False

    def run(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)
    request = {
        **_request("operation.prepare", operation_id="op-new"),
        "runtime_config_path": "C:/caller-selected.json",
    }

    with pytest.raises(HistoricalRouterError, match="write request contract"):
        router.dispatch("operation.prepare", request)
    assert called is False


def test_manifest_and_route_files_are_hash_bound_and_non_symlink(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    tmp_path: Path,
) -> None:
    manifest, current, _old = router_files
    store = FakeStore()
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)
    Path(current["executable_path"]).write_bytes(b"changed after manifest creation")

    with pytest.raises(HistoricalRouterError, match="executable digest"):
        router.dispatch("operation.prepare", _request("operation.prepare"))

    link = tmp_path / "routes-link.json"
    try:
        link.symlink_to(manifest)
    except OSError:
        pytest.skip("local account cannot create symlinks")
    linked = HistoricalReleaseRouter(link, store, require_root_owner=False)
    with pytest.raises(HistoricalRouterError, match="non-symlink"):
        linked.dispatch("operation.prepare", _request("operation.prepare"))


def test_production_pinned_manifest_rejects_runtime_route_switch(
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, current, old = router_files
    snapshot = load_historical_routing_manifest(
        manifest, require_root_owner=False
    )
    router = HistoricalReleaseRouter(
        manifest,
        FakeStore(),
        require_root_owner=False,
        pinned_manifest=snapshot,
    )
    manifest.write_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "current_release_digest": OLD_RELEASE,
                "routes": [current, old],
            }
        )
    )

    with pytest.raises(HistoricalRouterError, match="changed after startup"):
        router.dispatch("operation.prepare", _request("operation.prepare"))


def test_nonzero_oversized_or_noncanonical_child_output_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation("op-old", OLD_RELEASE, OLD_REGISTRY)
    router = HistoricalReleaseRouter(
        manifest, store, require_root_owner=False, max_stdout_bytes=128
    )
    results = iter(
        [
            subprocess.CompletedProcess([], 7, stdout=b"", stderr=b"rejected"),
            subprocess.CompletedProcess([], 0, stdout=b"x" * 129, stderr=b""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout=b'{"ok":true,"ok":true}',
                stderr=b"",
            ),
        ]
    )
    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child",
        lambda *_args, **_kwargs: next(results),
    )

    for message in ("child process failed", "stdout size limit", "valid JSON"):
        with pytest.raises(HistoricalRouterError, match=message):
            router.dispatch(
                "operation.status",
                _request("operation.status", operation_id="op-old"),
            )


@pytest.mark.parametrize("action", ["operation.prepare", "operation.recover"])
@pytest.mark.parametrize(
    "failure, message",
    [
        ("timeout", "timed out"),
        ("invalid_json", "valid JSON"),
        ("untrusted_identity", "child response identity"),
        ("missing_durable_record", "durable operation route"),
    ],
)
def test_durable_creation_actions_are_retryable_after_post_spawn_failure(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    action: str,
    failure: str,
    message: str,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    request = _request(action, operation_id="op-new")
    if action == "operation.recover":
        store.operations["op-origin"] = FakeOperation(
            "op-origin", OLD_RELEASE, OLD_REGISTRY
        )
        operation_id = request["recovery_operation_id"]
        release_digest = OLD_RELEASE
        registry_digest = OLD_REGISTRY
    else:
        operation_id = request["operation_id"]
        release_digest = CURRENT_RELEASE
        registry_digest = CURRENT_REGISTRY

    def run(argv, **_kwargs):
        if failure == "timeout":
                raise HistoricalRouterError(
                    "historical child process timed out",
                    code="historical_child_timeout",
                    retryable=True,
                    child_started=True,
                )
        if failure == "invalid_json":
            return subprocess.CompletedProcess(
                argv, 0, stdout=b"{not-json", stderr=b""
            )
        response = _response(
            action,
            operation_id=operation_id,
            release_digest=release_digest,
            registry_digest=registry_digest,
        )
        if failure == "untrusted_identity":
            response["data"]["operation"]["registry_digest"] = "e" * 64
        return _completed(argv, response)

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError, match=message) as raised:
        router.dispatch(action, request)

    assert raised.value.retryable is True
    assert raised.value.odoo_effect == "none"
    if failure == "timeout":
        assert raised.value.code == "historical_child_timeout"


@pytest.mark.parametrize("failure", ["timeout", "untrusted_identity"])
def test_approve_execute_keeps_unknown_effect_after_post_spawn_failure(
    monkeypatch: pytest.MonkeyPatch,
    router_files: tuple[Path, dict[str, Any], dict[str, Any]],
    failure: str,
) -> None:
    manifest, _current, _old = router_files
    store = FakeStore()
    store.operations["op-old"] = FakeOperation(
        "op-old", OLD_RELEASE, OLD_REGISTRY
    )

    def run(argv, **_kwargs):
        if failure == "timeout":
            raise HistoricalRouterError(
                "historical child process timed out",
                code="historical_child_timeout",
                retryable=True,
                child_started=True,
            )
        response = _response(
            "operation.approve_execute",
            operation_id="op-old",
            release_digest=OLD_RELEASE,
            registry_digest=OLD_REGISTRY,
        )
        response["data"]["audit_receipt"]["release_digest"] = "e" * 64
        return _completed(argv, response)

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router._run_bounded_child", run
    )
    router = HistoricalReleaseRouter(manifest, store, require_root_owner=False)

    with pytest.raises(HistoricalRouterError) as raised:
        router.dispatch(
            "operation.approve_execute",
            _request("operation.approve_execute", operation_id="op-old"),
        )

    assert raised.value.retryable is True
    assert raised.value.odoo_effect == "unknown"


@pytest.mark.skipif(os.name != "posix", reason="production child boundary is POSIX")
def test_popen_failure_is_explicitly_marked_as_pre_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("exec unavailable")

    monkeypatch.setattr(
        "odoo_accounting_cli_v3.historical_router.subprocess.Popen",
        unavailable,
    )

    with pytest.raises(HistoricalRouterError) as raised:
        _run_bounded_child(
            ["/retained/odoo-accounting-cli-v3", "operation", "status"],
            stdin=b"{}",
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
            timeout_seconds=1,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
        )

    assert raised.value.code == "historical_child_unavailable"
    assert raised.value.odoo_effect == "none"
    assert raised.value.retryable is True
    assert raised.value.child_started is False


@pytest.mark.skipif(os.name != "posix", reason="production child boundary is POSIX")
def test_posix_child_boundary_enforces_deadline_and_output_limit() -> None:
    common = {
        "stdin": b"{}",
        "env": {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        },
        "max_stdout_bytes": 128,
        "max_stderr_bytes": 128,
    }

    with pytest.raises(HistoricalRouterError, match="timed out"):
        _run_bounded_child(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            timeout_seconds=0.05,
            **common,
        )
    with pytest.raises(HistoricalRouterError, match="stdout.*size limit"):
        _run_bounded_child(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 129)"],
            timeout_seconds=2,
            **common,
        )


@pytest.mark.skipif(os.name != "posix", reason="production child boundary is POSIX")
def test_posix_child_boundary_inherits_exact_runtime_config_fd(
    tmp_path: Path,
) -> None:
    runtime_config = (tmp_path / "write-runtime.json").resolve()
    expected = b'{"release":"retained"}'
    runtime_config.write_bytes(expected)
    descriptor = os.open(runtime_config, os.O_RDONLY)
    try:
        completed = _run_bounded_child(
            [
                sys.executable,
                "-c",
                (
                    "import os,sys; "
                    "sys.stdout.buffer.write(os.read(int(os.environ['CONFIG_FD']), 4096))"
                ),
            ],
            stdin=b"{}",
            env={
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "CONFIG_FD": str(descriptor),
            },
            timeout_seconds=2,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)

    assert completed.returncode == 0
    assert completed.stdout == expected
    assert completed.stderr == b""

from __future__ import annotations

import ast
from email.message import Message
import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Any, Iterator

import pytest


ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "odoo_addons" / "odoo_accounting_cli_v3_control"
SESSION_MODEL = ADDON / "models" / "session_client.py"
APPROVAL_MODEL = ADDON / "models" / "approval_client.py"
HANDLE = "A" * 43
DATABASE_UUID = "f1d2d2f9-8d43-4b2f-a36c-64c76df38f81"


class FakeAccessError(Exception):
    pass


class FakeUserError(Exception):
    pass


class FakeAbstractModel:
    pass


def _load_modules(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[types.ModuleType, types.ModuleType]:
    odoo = types.ModuleType("odoo")
    odoo.api = types.SimpleNamespace(model=lambda function: function)
    odoo.models = types.SimpleNamespace(AbstractModel=FakeAbstractModel)
    exceptions = types.ModuleType("odoo.exceptions")
    exceptions.AccessError = FakeAccessError
    exceptions.UserError = FakeUserError
    monkeypatch.setitem(sys.modules, "odoo", odoo)
    monkeypatch.setitem(sys.modules, "odoo.exceptions", exceptions)

    package_name = "test_odoo_v3_control"
    models_name = f"{package_name}.models"
    package = types.ModuleType(package_name)
    package.__path__ = [str(ADDON)]  # type: ignore[attr-defined]
    models_package = types.ModuleType(models_name)
    models_package.__path__ = [str(ADDON / "models")]  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, package_name, package)
    monkeypatch.setitem(sys.modules, models_name, models_package)

    def load(name: str, path: Path) -> types.ModuleType:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        return module

    session = load(f"{models_name}.session_client", SESSION_MODEL)
    approval = load(f"{models_name}.approval_client", APPROVAL_MODEL)
    return session, approval


class FakeConfigParameters:
    def sudo(self) -> "FakeConfigParameters":
        return self

    def get_param(self, key: str) -> str:
        assert key == "database.uuid"
        return DATABASE_UUID


class FakeUser:
    id = 84

    def __init__(self, *, executor: bool, approver: bool) -> None:
        self.executor = executor
        self.approver = approver

    def has_group(self, xml_id: str) -> bool:
        if xml_id == "odoo_accounting_cli_v3_control.group_executor":
            return self.executor
        if xml_id == "odoo_accounting_cli_v3_control.group_approver":
            return self.approver
        raise AssertionError(xml_id)


class FakeEnv:
    def __init__(
        self,
        session: types.ModuleType,
        *,
        executor: bool = True,
        approver: bool = True,
    ) -> None:
        self.su = False
        self.cr = types.SimpleNamespace(dbname="accounting")
        self.user = FakeUser(executor=executor, approver=approver)
        self.company = types.SimpleNamespace(id=7)
        self.companies = types.SimpleNamespace(ids=[9, 7])
        self._config = FakeConfigParameters()
        self._issuer = session.OdooAccountingCliV3SessionClient()
        self._issuer.env = self

    def __getitem__(self, name: str) -> Any:
        if name == "ir.config_parameter":
            return self._config
        if name == "odoo.accounting.cli.v3.session.client":
            return self._issuer
        raise AssertionError(name)


def _client(
    session: types.ModuleType,
    approval: types.ModuleType,
    *,
    executor: bool = True,
    approver: bool = True,
) -> Any:
    value = approval.OdooAccountingCliV3ApprovalClient()
    value.env = FakeEnv(session, executor=executor, approver=approver)
    return value


@pytest.fixture
def root_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    values = {
        "ODOO_V3_INSTANCE_ID": "odoo-sandbox-01",
        "ODOO_V3_ENVIRONMENT": "sandbox",
        "ODOO_V3_SESSION_MINT_SOCKET": "/run/odoo-v3/session-mint.sock",
        "ODOO_V3_TRUSTED_APPROVAL_SOCKET": "/run/odoo-v3/approval.sock",
        "ODOO_V3_PI_BRIDGE_PORT": "8787",
        "ODOO_V3_BROKER_UID": "2101",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    yield


def _mint() -> dict[str, Any]:
    return {
        "ok": True,
        "session": {
            "handle": HANDLE,
            "session_id": "11111111-1111-4111-8111-111111111111",
            "issued_at": "2026-07-15T08:00:00.000000+00:00",
            "expires_at": "2026-07-15T08:01:00.000000+00:00",
            "max_uses": 32,
        },
    }


def _view(
    *,
    state: str = "pending",
    company_id: int = 7,
    requester_user_id: int = 84,
) -> dict[str, Any]:
    return {
        "capability_id": "acct.invoice.customer_create.v1",
        "challenge_id": "challenge-1",
        "company_id": company_id,
        "expires_at": "2026-07-15T08:15:00+00:00",
        "issued_at": "2026-07-15T08:00:00+00:00",
        "operation_digest": "a" * 64,
        "operation_id": "operation-1",
        "precheck_digest": "b" * 64,
        "requester_user_id": requester_user_id,
        "state": state,
    }


def test_addon_registers_private_approval_client_without_acl_or_controller() -> None:
    source = APPROVAL_MODEL.read_text(encoding="utf-8")
    manifest = ast.literal_eval((ADDON / "__manifest__.py").read_text("utf-8"))
    init = (ADDON / "models" / "__init__.py").read_text("utf-8")
    acl = (ADDON / "security" / "ir.model.access.csv").read_text("utf-8")

    assert manifest["version"] == "19.0.0.4.0"
    assert "from . import approval_client" in init
    assert "models.AbstractModel" in source
    assert "def _odoo_v3_request_approval(" in source
    assert "def _odoo_v3_inspect_approval(" in source
    assert "def _odoo_v3_decide_approval(" in source
    assert "def request_v3_approval(" not in source
    assert "def decide_v3_approval(" not in source
    assert "def inspect_v3_approval(" not in source
    assert "@http.route" not in source
    assert "from odoo.http" not in source
    assert ".sudo(" not in source
    assert "logging" not in source
    assert "approval_client" not in acl


@pytest.mark.parametrize(
    "field",
    [
        "session_handle",
        "user_id",
        "company_id",
        "allowed_company_ids",
        "release_digest",
        "registry_digest",
        "approval_signature",
        "headers",
    ],
)
def test_requester_payload_cannot_inject_authority(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    field: str,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval)
    with pytest.raises(FakeUserError, match="request was rejected"):
        value._odoo_v3_request_approval(
            {"operation_id": "operation-1", field: "forged"}
        )


@pytest.mark.parametrize(
    ("payload", "valid"),
    [
        ({"challenge_id": "challenge-1", "decision": "approve", "reason": None}, True),
        ({"challenge_id": "challenge-1", "decision": "deny", "reason": "Wrong amount"}, True),
        ({"challenge_id": "challenge-1", "decision": "approve", "reason": "yes"}, False),
        ({"challenge_id": "challenge-1", "decision": "deny", "reason": None}, False),
        ({"challenge_id": "challenge-1", "decision": "deny", "reason": " padded "}, False),
        ({"challenge_id": "challenge-1", "decision": "allow", "reason": None}, False),
    ],
)
def test_decision_contract_is_exact(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    payload: dict[str, Any],
    valid: bool,
) -> None:
    session, approval = _load_modules(monkeypatch)
    if valid:
        assert approval._decision_payload(payload) == payload
    else:
        with pytest.raises(approval.ApprovalClientError):
            approval._decision_payload(payload)


def test_requester_mints_from_odoo_identity_calls_fixed_route_and_revokes(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval)
    calls: list[tuple[str, Any]] = []

    def session_call(
        _settings: Any, route: str, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        calls.append((route, json.loads(json.dumps(payload))))
        if route == session._MINT_PATH:
            return 201, _mint()
        assert payload == {"handle": HANDLE}
        return 200, {"ok": True, "revoked": True}

    def approval_call(
        settings: Any,
        *,
        socket_path: str,
        route: str,
        handle: str,
        payload: dict[str, Any],
    ) -> tuple[int, dict[str, Any]]:
        calls.append(
            (
                "approval",
                (settings.broker_uid, socket_path, route, handle, dict(payload)),
            )
        )
        return 200, {"ok": True, "challenge": _view()}

    monkeypatch.setattr(session, "_post_uds_json", session_call)
    monkeypatch.setattr(approval, "_post_approval", approval_call)

    result = value._odoo_v3_request_approval({"operation_id": "operation-1"})

    assert result == _view()
    assert calls[0][0] == session._MINT_PATH
    assert calls[0][1] == {
        "principal": "odoo:user:84",
        "odoo_instance_id": "odoo-sandbox-01",
        "database_name": "accounting",
        "database_uuid": DATABASE_UUID,
        "user_id": 84,
        "company_id": 7,
        "allowed_company_ids": [7, 9],
        "environment": "sandbox",
    }
    assert calls[1] == (
        "approval",
        (
            2101,
            "/run/odoo-v3/approval.sock",
            "/v1/approval/request",
            HANDLE,
            {"operation_id": "operation-1"},
        ),
    )
    assert calls[2] == (session._REVOKE_PATH, {"handle": HANDLE})
    assert HANDLE not in json.dumps(result)


@pytest.mark.parametrize(
    ("decision", "reason", "state"),
    [("approve", None, "approved"), ("deny", "Duplicate invoice", "denied")],
)
def test_independent_approver_decision_preserves_exact_business_fields(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    decision: str,
    reason: str | None,
    state: str,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval, executor=False, approver=True)
    calls: list[tuple[str, Any]] = []

    def session_call(
        _settings: Any, route: str, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        calls.append((route, dict(payload)))
        return (
            (201, _mint())
            if route == session._MINT_PATH
            else (200, {"ok": True, "revoked": True})
        )

    def approval_call(
        _settings: Any, **kwargs: Any
    ) -> tuple[int, dict[str, Any]]:
        calls.append(("approval", kwargs))
        return 200, {
            "ok": True,
            "decision": _view(state=state, requester_user_id=42),
        }

    monkeypatch.setattr(session, "_post_uds_json", session_call)
    monkeypatch.setattr(approval, "_post_approval", approval_call)
    payload = {
        "challenge_id": "challenge-1",
        "decision": decision,
        "reason": reason,
    }

    assert value._odoo_v3_decide_approval(payload)["state"] == state
    assert calls[1][1]["payload"] == payload
    assert calls[-1] == (session._REVOKE_PATH, {"handle": HANDLE})


def test_group_checks_run_before_mint(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    session, approval = _load_modules(monkeypatch)
    calls: list[object] = []
    monkeypatch.setattr(session, "_post_uds_json", lambda *args: calls.append(args))
    requester = _client(session, approval, executor=False, approver=True)
    approver = _client(session, approval, executor=True, approver=False)

    with pytest.raises(FakeAccessError, match="executor"):
        requester._odoo_v3_request_approval({"operation_id": "operation-1"})
    with pytest.raises(FakeAccessError, match="approver"):
        approver._odoo_v3_decide_approval(
            {"challenge_id": "challenge-1", "decision": "approve", "reason": None}
        )
    with pytest.raises(FakeAccessError, match="approver"):
        approver._odoo_v3_inspect_approval({"challenge_id": "challenge-1"})
    assert calls == []


def test_inspection_mints_calls_fixed_route_rebuilds_and_revokes(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval, executor=False, approver=True)
    contract = types.ModuleType("test_odoo_v3_control.models.approval_wizard")
    contract._validated_inspection = lambda inspection: inspection
    monkeypatch.setitem(
        sys.modules,
        "test_odoo_v3_control.models.approval_wizard",
        contract,
    )
    inspection = {
        "challenge": {"challenge_id": "challenge-1"},
        "operation": {"company_id": 7, "user_id": 42},
    }
    calls: list[tuple[str, Any]] = []

    def session_call(
        _settings: Any, route: str, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        calls.append((route, dict(payload)))
        return (
            (201, _mint())
            if route == session._MINT_PATH
            else (200, {"ok": True, "revoked": True})
        )

    def approval_call(
        _settings: Any, **kwargs: Any
    ) -> tuple[int, dict[str, Any]]:
        calls.append(("approval", kwargs))
        return 200, {"ok": True, "inspection": inspection}

    monkeypatch.setattr(session, "_post_uds_json", session_call)
    monkeypatch.setattr(approval, "_post_approval", approval_call)

    assert value._odoo_v3_inspect_approval(
        {"challenge_id": "challenge-1"}
    ) == inspection
    assert calls[1][1]["route"] == "/v1/approval/inspect"
    assert calls[1][1]["payload"] == {"challenge_id": "challenge-1"}
    assert calls[-1] == (session._REVOKE_PATH, {"handle": HANDLE})


def test_inspection_rejects_caller_authority_before_mint(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval, executor=False, approver=True)
    calls: list[object] = []
    monkeypatch.setattr(session, "_post_uds_json", lambda *args: calls.append(args))

    with pytest.raises(FakeUserError, match="inspection was rejected"):
        value._odoo_v3_inspect_approval(
            {"challenge_id": "challenge-1", "company_id": 9}
        )
    value.env.su = True
    with pytest.raises(FakeAccessError, match="approver"):
        value._odoo_v3_inspect_approval({"challenge_id": "challenge-1"})
    assert calls == []


def test_approval_transport_has_no_bare_public_rpc_wrappers(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval)
    assert not hasattr(value, "request_v3_approval")
    assert not hasattr(value, "decide_v3_approval")


@pytest.mark.parametrize("failure", ["service", "tampered", "revoke"])
def test_every_ambiguous_failure_is_safe_and_revokes_when_possible(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    failure: str,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval)
    routes: list[str] = []

    def session_call(
        _settings: Any, route: str, _payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        routes.append(route)
        if route == session._MINT_PATH:
            return 201, _mint()
        if failure == "revoke":
            return 503, {"ok": False}
        return 200, {"ok": True, "revoked": True}

    def approval_call(*_args: Any, **_kwargs: Any) -> tuple[int, dict[str, Any]]:
        if failure == "service":
            raise approval.ApprovalClientError("backend secret path")
        view = _view()
        if failure == "tampered":
            view["approval_signature"] = "forged"
        return 200, {"ok": True, "challenge": view}

    monkeypatch.setattr(session, "_post_uds_json", session_call)
    monkeypatch.setattr(approval, "_post_approval", approval_call)
    with pytest.raises(FakeUserError) as raised:
        value._odoo_v3_request_approval({"operation_id": "operation-1"})
    assert routes == [session._MINT_PATH, session._REVOKE_PATH]
    assert HANDLE not in str(raised.value)
    assert "backend secret" not in str(raised.value)


@pytest.mark.parametrize(
    "tampered_view",
    [
        _view(requester_user_id=42),
        _view(company_id=9),
    ],
)
def test_request_response_must_match_current_requester_and_company(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    tampered_view: dict[str, Any],
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval)
    routes: list[str] = []

    def session_call(
        _settings: Any, route: str, _payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        routes.append(route)
        return (
            (201, _mint())
            if route == session._MINT_PATH
            else (200, {"ok": True, "revoked": True})
        )

    monkeypatch.setattr(session, "_post_uds_json", session_call)
    monkeypatch.setattr(
        approval,
        "_post_approval",
        lambda *_args, **_kwargs: (
            200,
            {"ok": True, "challenge": dict(tampered_view)},
        ),
    )

    with pytest.raises(FakeUserError):
        value._odoo_v3_request_approval({"operation_id": "operation-1"})
    assert routes == [session._MINT_PATH, session._REVOKE_PATH]


def test_decision_response_rejects_self_approval_or_cross_company_view(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval, executor=False, approver=True)
    calls: list[str] = []

    def session_call(
        _settings: Any, route: str, _payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        calls.append(route)
        return (
            (201, _mint())
            if route == session._MINT_PATH
            else (200, {"ok": True, "revoked": True})
        )

    monkeypatch.setattr(session, "_post_uds_json", session_call)
    monkeypatch.setattr(
        approval,
        "_post_approval",
        lambda *_args, **_kwargs: (
            200,
            {
                "ok": True,
                "decision": _view(state="approved", requester_user_id=84),
            },
        ),
    )
    with pytest.raises(FakeUserError):
        value._odoo_v3_decide_approval(
            {"challenge_id": "challenge-1", "decision": "approve", "reason": None}
        )
    assert calls == [session._MINT_PATH, session._REVOKE_PATH]


@pytest.mark.parametrize("mint_status", [201, 503])
def test_malformed_mint_candidate_handle_is_still_revoked(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    mint_status: int,
) -> None:
    session, approval = _load_modules(monkeypatch)
    value = _client(session, approval)
    routes: list[str] = []
    malformed = _mint()
    malformed["session"]["max_uses"] = 2

    def session_call(
        _settings: Any, route: str, _payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        routes.append(route)
        return (
            (mint_status, malformed)
            if route == session._MINT_PATH
            else (200, {"ok": True, "revoked": True})
        )

    approval_calls: list[object] = []
    monkeypatch.setattr(session, "_post_uds_json", session_call)
    monkeypatch.setattr(
        approval, "_post_approval", lambda *args, **kwargs: approval_calls.append(args)
    )
    with pytest.raises(FakeUserError):
        value._odoo_v3_request_approval({"operation_id": "operation-1"})
    assert routes == [session._MINT_PATH, session._REVOKE_PATH]
    assert approval_calls == []


def test_approval_transport_uses_root_path_broker_peer_and_injects_handle_locally(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    session, approval = _load_modules(monkeypatch)
    settings = session._root_settings()
    calls: list[tuple[str, Any]] = []

    class Connection:
        def __init__(
            self,
            path: str,
            peer_uid: int,
            *,
            timeout_seconds: float,
        ) -> None:
            calls.append(("connect", (path, peer_uid, timeout_seconds)))

        def close(self) -> None:
            calls.append(("close", None))

    class Response:
        status = 200
        headers = Message()

        def __init__(self) -> None:
            self.body = json.dumps(
                {"ok": True, "challenge": _view()},
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            self.headers.add_header("Content-Type", "application/json")
            self.headers.add_header("Content-Length", str(len(self.body)))

        def read(self, _amount: int) -> bytes:
            return self.body

    def send(
        _connection: Any,
        route: str,
        body: bytes,
        headers: tuple[tuple[str, str], ...],
    ) -> Response:
        calls.append(("request", (route, json.loads(body), headers)))
        return Response()

    monkeypatch.setattr(session, "_UnixHTTPConnection", Connection)
    monkeypatch.setattr(session, "_send_fixed_post", send)
    status, response = approval._post_approval(
        settings,
        socket_path=approval._approval_socket_path(),
        route=approval._APPROVAL_REQUEST_PATH,
        handle=HANDLE,
        payload={"operation_id": "operation-1"},
    )

    assert status == 200
    assert response["ok"] is True
    assert calls[0] == (
        "connect",
        ("/run/odoo-v3/approval.sock", 2101, 35.0),
    )
    assert calls[1][1][1] == {
        "operation_id": "operation-1",
        "session_handle": HANDLE,
    }
    assert calls[-1] == ("close", None)


@pytest.mark.parametrize(
    "path",
    [
        "relative.sock",
        "//run/approval.sock",
        "/run/../approval.sock",
        "/run//approval.sock",
        "/run/a",
    ],
)
def test_approval_socket_path_is_root_only_and_canonical(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    path: str,
) -> None:
    _session, approval = _load_modules(monkeypatch)
    monkeypatch.setenv("ODOO_V3_TRUSTED_APPROVAL_SOCKET", path)
    with pytest.raises(approval.ApprovalClientError):
        approval._approval_socket_path()

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
MODEL = ADDON / "models" / "session_client.py"
DATABASE_UUID = "f1d2d2f9-8d43-4b2f-a36c-64c76df38f81"
HANDLE = "A" * 43
RELEASE_DIGEST = "a" * 64
REGISTRY_DIGEST = "b" * 64


class FakeAccessError(Exception):
    pass


class FakeUserError(Exception):
    pass


class FakeAbstractModel:
    pass


def _load_client_module(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    odoo = types.ModuleType("odoo")
    odoo.api = types.SimpleNamespace(model=lambda function: function)
    odoo.models = types.SimpleNamespace(AbstractModel=FakeAbstractModel)
    exceptions = types.ModuleType("odoo.exceptions")
    exceptions.AccessError = FakeAccessError
    exceptions.UserError = FakeUserError
    monkeypatch.setitem(sys.modules, "odoo", odoo)
    monkeypatch.setitem(sys.modules, "odoo.exceptions", exceptions)
    package = types.ModuleType("odoo_accounting_cli_v3_control")
    package.__path__ = [str(ADDON)]
    models_package = types.ModuleType("odoo_accounting_cli_v3_control.models")
    models_package.__path__ = [str(ADDON / "models")]
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(sys.modules, models_package.__name__, models_package)
    name = "odoo_accounting_cli_v3_control.models.session_client"
    spec = importlib.util.spec_from_file_location(name, MODEL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        module,
        "verify_addon_release",
        lambda _path: module.VerifiedAddonRelease(
            release_digest=RELEASE_DIGEST,
            registry_digest=REGISTRY_DIGEST,
            release="0.1.0.dev10-0123456789ab",
            version="0.1.0.dev10",
            commit="0123456789abcdef0123456789abcdef01234567",
        ),
    )
    return module


class FakeConfigParameters:
    def sudo(self) -> "FakeConfigParameters":
        return self

    def get_param(self, key: str) -> str:
        assert key == "database.uuid"
        return DATABASE_UUID


class FakeUser:
    id = 42

    def __init__(self, *, executor: bool = True) -> None:
        self.executor = executor

    def has_group(self, xml_id: str) -> bool:
        assert xml_id == "odoo_accounting_cli_v3_control.group_executor"
        return self.executor


class FakeEnv:
    def __init__(self, *, executor: bool = True) -> None:
        self.cr = types.SimpleNamespace(dbname="accounting")
        self.user = FakeUser(executor=executor)
        self.company = types.SimpleNamespace(id=7)
        self.companies = types.SimpleNamespace(ids=[9, 7])
        self._config = FakeConfigParameters()

    def __getitem__(self, name: str) -> FakeConfigParameters:
        assert name == "ir.config_parameter"
        return self._config


def _client(module: types.ModuleType, *, executor: bool = True) -> Any:
    value = module.OdooAccountingCliV3SessionClient()
    value.env = FakeEnv(executor=executor)
    return value


@pytest.fixture
def root_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    values = {
        "ODOO_V3_INSTANCE_ID": "odoo-prod-01",
        "ODOO_V3_ENVIRONMENT": "sandbox",
        "ODOO_V3_SESSION_MINT_SOCKET": "/run/odoo-v3/session-mint.sock",
        "ODOO_V3_PI_BRIDGE_PORT": "8787",
        "ODOO_V3_BROKER_UID": "2101",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    yield


def test_manifest_init_and_acl_keep_client_internal() -> None:
    manifest = ast.literal_eval((ADDON / "__manifest__.py").read_text(encoding="utf-8"))
    assert manifest["version"] == "19.0.0.7.1"
    assert "server-side" in manifest["summary"].lower()
    assert "from . import session_client" in (
        ADDON / "models" / "__init__.py"
    ).read_text(encoding="utf-8")
    assert "controllers" not in (ADDON / "__init__.py").read_text(encoding="utf-8")
    acl = (ADDON / "security" / "ir.model.access.csv").read_text(encoding="utf-8")
    assert "session_client" not in acl
    assert "model_odoo_accounting_cli_v3_session_client" not in acl


def test_source_has_private_abstract_model_and_no_public_http_boundary() -> None:
    source = MODEL.read_text(encoding="utf-8")
    assert "models.AbstractModel" in source
    assert "def _odoo_v3_chat(" in source
    assert "@http.route" not in source
    assert "from odoo.http" not in source
    assert "odoo.http" not in source
    assert "request.json" not in source
    assert "env.cr.dbname" in source
    assert "env.user" in source
    assert "env.company" in source
    assert "env.companies" in source
    assert 'get_param("database.uuid")' in source
    assert '"X-Odoo-V3-Broker-Session"' in source
    assert '"ODOO_V3_BROKER_UID"' in source
    assert '"127.0.0.1"' in source
    assert '"/chat"' in source
    assert "verify_addon_release(__file__)" in source
    assert "ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST" not in source
    assert "ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST" not in source
    assert "logging" not in source
    assert "trusted_broker" not in source


def test_identity_is_derived_only_from_current_env_and_root_config(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module)
    settings = module._root_settings()
    assert settings.broker_uid == 2101

    release = module.verify_addon_release(MODEL)
    assert client._trusted_identity_payload(settings, release) == {
        "principal": "odoo:user:42",
        "odoo_instance_id": "odoo-prod-01",
        "database_name": "accounting",
        "database_uuid": DATABASE_UUID,
        "user_id": 42,
        "company_id": 7,
        "allowed_company_ids": [7, 9],
        "environment": "sandbox",
        "release_digest": RELEASE_DIGEST,
        "registry_digest": REGISTRY_DIGEST,
    }


@pytest.mark.parametrize(
    "forbidden",
    [
        "user_id",
        "company_id",
        "allowed_company_ids",
        "database_name",
        "database_uuid",
        "odoo_instance_id",
        "environment",
        "release_digest",
        "registry_digest",
        "ttl_seconds",
        "max_uses",
        "headers",
        "session_handle",
        "broker_uid",
    ],
)
def test_browser_or_pi_authority_fields_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    forbidden: str,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module)
    with pytest.raises(FakeUserError, match="business request"):
        client._odoo_v3_chat({"message": "show trial balance", forbidden: "forged"})


def test_executor_only_chat_mints_calls_loopback_and_always_revokes(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module)
    calls: list[tuple[str, Any]] = []

    def uds_call(
        settings: Any, route: str, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        del settings
        calls.append((route, json.loads(json.dumps(payload))))
        if route == module._MINT_PATH:
            return 201, {
                "ok": True,
                "session": {
                    "handle": HANDLE,
                    "session_id": "11111111-1111-4111-8111-111111111111",
                    "issued_at": "2026-07-15T08:00:00.000000+00:00",
                    "expires_at": "2026-07-15T08:01:00.000000+00:00",
                    "max_uses": 32,
                },
            }
        assert route == module._REVOKE_PATH
        assert payload == {"handle": HANDLE}
        return 200, {"ok": True, "revoked": True}

    def pi_call(settings: Any, payload: dict[str, Any], handle: str) -> str:
        calls.append(("pi", (settings.pi_bridge_port, payload, handle)))
        return "verified answer"

    monkeypatch.setattr(module, "_post_uds_json", uds_call)
    monkeypatch.setattr(module, "_post_pi_chat", pi_call)

    assert client._odoo_v3_chat({"message": "show trial balance"}) == "verified answer"
    assert calls[0][0] == module._MINT_PATH
    assert calls[0][1]["user_id"] == 42
    assert calls[0][1]["release_digest"] == RELEASE_DIGEST
    assert calls[0][1]["registry_digest"] == REGISTRY_DIGEST
    assert calls[1] == (
        "pi",
        (8787, {"message": "show trial balance"}, HANDLE),
    )
    assert calls[2] == (module._REVOKE_PATH, {"handle": HANDLE})


def test_unverified_executing_addon_cannot_reach_mint_or_pi(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module)
    calls: list[object] = []
    monkeypatch.setattr(
        module,
        "verify_addon_release",
        lambda _path: (_ for _ in ()).throw(
            RuntimeError("private path detail")
        ),
    )
    monkeypatch.setattr(module, "_post_uds_json", lambda *args: calls.append(args))
    monkeypatch.setattr(module, "_post_pi_chat", lambda *args: calls.append(args))

    with pytest.raises(FakeUserError, match="could not be completed safely") as caught:
        client._odoo_v3_chat({"message": "show trial balance"})

    assert calls == []
    assert "private path detail" not in str(caught.value)


def test_pi_failure_still_revokes_and_never_exposes_handle(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module)
    routes: list[str] = []

    def uds_call(
        _settings: Any, route: str, _payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        routes.append(route)
        if route == module._MINT_PATH:
            return 201, {
                "ok": True,
                "session": {
                    "handle": HANDLE,
                    "session_id": "11111111-1111-4111-8111-111111111111",
                    "issued_at": "2026-07-15T08:00:00.000000+00:00",
                    "expires_at": "2026-07-15T08:01:00.000000+00:00",
                    "max_uses": 32,
                },
            }
        return 200, {"ok": True, "revoked": True}

    monkeypatch.setattr(module, "_post_uds_json", uds_call)
    monkeypatch.setattr(
        module,
        "_post_pi_chat",
        lambda *_args: (_ for _ in ()).throw(module.SessionClientError("secret")),
    )
    with pytest.raises(FakeUserError) as caught:
        client._odoo_v3_chat({"message": "show trial balance"})
    assert HANDLE not in str(caught.value)
    assert routes == [module._MINT_PATH, module._REVOKE_PATH]


def test_revoke_failure_fails_closed_even_after_pi_success(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module)

    def uds_call(
        _settings: Any, route: str, _payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        if route == module._MINT_PATH:
            return 201, {
                "ok": True,
                "session": {
                    "handle": HANDLE,
                    "session_id": "11111111-1111-4111-8111-111111111111",
                    "issued_at": "2026-07-15T08:00:00.000000+00:00",
                    "expires_at": "2026-07-15T08:01:00.000000+00:00",
                    "max_uses": 32,
                },
            }
        return 404, {"ok": False, "error": {"code": "rejected"}}

    monkeypatch.setattr(module, "_post_uds_json", uds_call)
    monkeypatch.setattr(module, "_post_pi_chat", lambda *_args: "answer")
    with pytest.raises(FakeUserError, match="could not be completed safely"):
        client._odoo_v3_chat({"message": "show trial balance"})


@pytest.mark.parametrize("mint_status", [201, 503])
def test_malformed_mint_with_valid_candidate_handle_is_revoked(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    mint_status: int,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module)
    routes: list[str] = []

    def uds_call(
        _settings: Any, route: str, payload: dict[str, Any]
    ) -> tuple[int, dict[str, Any]]:
        routes.append(route)
        if route == module._MINT_PATH:
            return mint_status, {
                "ok": True,
                "session": {
                    "handle": HANDLE,
                    "session_id": "11111111-1111-4111-8111-111111111111",
                    "issued_at": "2026-07-15T08:00:00.000000+00:00",
                    "expires_at": "2026-07-15T08:01:00.000000+00:00",
                    "max_uses": 2,
                },
            }
        assert payload == {"handle": HANDLE}
        return 200, {"ok": True, "revoked": True}

    pi_calls: list[object] = []
    monkeypatch.setattr(module, "_post_uds_json", uds_call)
    monkeypatch.setattr(module, "_post_pi_chat", lambda *args: pi_calls.append(args))
    with pytest.raises(FakeUserError):
        client._odoo_v3_chat({"message": "show trial balance"})
    assert routes == [module._MINT_PATH, module._REVOKE_PATH]
    assert pi_calls == []


def test_non_executor_is_rejected_before_mint(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    client = _client(module, executor=False)
    calls: list[object] = []
    monkeypatch.setattr(module, "_post_uds_json", lambda *args: calls.append(args))
    with pytest.raises(FakeAccessError):
        client._odoo_v3_chat({"message": "show trial balance"})
    assert calls == []


def test_transport_limits_cover_server_deadlines_and_remain_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_client_module(monkeypatch)
    assert 5 < module._SESSION_UDS_TIMEOUT_SECONDS <= 10
    assert 115 < module._PI_TIMEOUT_SECONDS <= 120
    assert module._MAX_REQUEST_BYTES <= 64 * 1024
    assert module._MAX_RESPONSE_BYTES <= 1024 * 1024

    class OversizedResponse:
        def read(self, amount: int) -> bytes:
            return b"x" * amount

    with pytest.raises(module.SessionClientError, match="response is too large"):
        module._read_response_json(
            OversizedResponse(),  # type: ignore[arg-type]
            max_bytes=32,
        )


@pytest.mark.parametrize("broker_uid", ["", "0", "-1", "02101", "not-an-id"])
def test_broker_uid_must_be_a_canonical_positive_root_setting(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
    broker_uid: str,
) -> None:
    module = _load_client_module(monkeypatch)
    monkeypatch.setenv("ODOO_V3_BROKER_UID", broker_uid)
    with pytest.raises(module.SessionClientError, match="root-injected"):
        module._root_settings()


def test_broker_uid_must_differ_from_current_odoo_process_uid(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    monkeypatch.setattr(module.os, "geteuid", lambda: 2101, raising=False)
    with pytest.raises(module.SessionClientError, match="must differ"):
        module._root_settings()


def test_uds_connection_requires_configured_nonroot_broker_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_client_module(monkeypatch)
    monkeypatch.setattr(module, "_validate_mint_socket", lambda _path: None)
    monkeypatch.setattr(module.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(module.socket, "SO_PEERCRED", 17, raising=False)

    class FakeSocket:
        def __init__(self, peer_uid: int) -> None:
            self.peer_uid = peer_uid
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect(self, _path: str) -> None:
            return None

        def getsockopt(self, _level: int, _name: int, _size: int) -> bytes:
            return module.struct.pack(module._PEER_CREDENTIAL_FORMAT, 123, self.peer_uid, 2102)

        def close(self) -> None:
            self.closed = True

    accepted = FakeSocket(2101)
    monkeypatch.setattr(module.socket, "socket", lambda *_args: accepted)
    connection = module._UnixHTTPConnection(
        "/run/odoo-v3/session-mint.sock",
        2101,
        timeout_seconds=module._SESSION_UDS_TIMEOUT_SECONDS,
    )
    connection.connect()
    assert connection.sock is accepted

    rejected = FakeSocket(0)
    monkeypatch.setattr(module.socket, "socket", lambda *_args: rejected)
    connection = module._UnixHTTPConnection(
        "/run/odoo-v3/session-mint.sock",
        2101,
        timeout_seconds=module._SESSION_UDS_TIMEOUT_SECONDS,
    )
    with pytest.raises(module.SessionClientError, match="configured broker UID"):
        connection.connect()
    assert rejected.closed is True


def test_pi_transport_uses_only_loopback_and_dedicated_session_header(
    monkeypatch: pytest.MonkeyPatch,
    root_environment: None,
) -> None:
    module = _load_client_module(monkeypatch)
    settings = module._root_settings()
    calls: list[tuple[str, Any]] = []

    class Response:
        status = 200
        headers = Message()

        def __init__(self) -> None:
            body = json.dumps(
                {"ok": True, "answer": "verified answer"},
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            self.body = body
            self.headers.add_header("Content-Type", "application/json; charset=utf-8")
            self.headers.add_header("Content-Length", str(len(body)))

        def read(self, _amount: int) -> bytes:
            return self.body

    class Connection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            calls.append(("connect", (host, port, timeout)))

        def putrequest(self, method: str, route: str, **options: Any) -> None:
            calls.append(("request", (method, route, options)))

        def putheader(self, name: str, value: str) -> None:
            calls.append(("header", (name, value)))

        def endheaders(self, body: bytes) -> None:
            calls.append(("body", json.loads(body)))

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            calls.append(("close", None))

    monkeypatch.setattr(module.http.client, "HTTPConnection", Connection)
    assert module._post_pi_chat(
        settings,
        {"message": "show trial balance"},
        HANDLE,
    ) == "verified answer"
    assert calls[0] == ("connect", ("127.0.0.1", 8787, 120.0))
    assert ("request", ("POST", "/chat", {
        "skip_host": True,
        "skip_accept_encoding": True,
    })) in calls
    assert ("header", ("X-Odoo-V3-Broker-Session", HANDLE)) in calls
    assert all(HANDLE not in str(value) for kind, value in calls if kind != "header")

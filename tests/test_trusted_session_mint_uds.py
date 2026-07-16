from __future__ import annotations

import inspect
import json
import os
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.message import Message
from io import BytesIO
from pathlib import Path
from typing import Any, Iterator

import pytest

import odoo_accounting_cli_v3.trusted_session_mint_uds as mint_uds
from odoo_accounting_cli_v3.monotonic_deadline import current_monotonic_deadline
from odoo_accounting_cli_v3.trusted_session_sqlite import (
    SQLiteTrustedSessionStore,
    TrustedSessionCommitOutcomeUnknownError,
    TrustedSessionKnownCommittedError,
    TrustedSessionReconciliationRequiredError,
)


DATABASE_UUID = "f1d2d2f9-8d43-4b2f-a36c-64c76df38f81"
RELEASE_DIGEST = "a" * 64
REGISTRY_DIGEST = "b" * 64


def test_request_handlers_are_non_daemon_and_joined_on_server_close() -> None:
    source = inspect.getsource(mint_uds)
    assert "daemon_threads = False" in source
    assert "block_on_close = True" in source


def test_session_store_work_is_entered_inside_the_request_deadline_scope() -> None:
    source = inspect.getsource(mint_uds._MintRequestHandler.do_POST)
    assert "with monotonic_deadline_scope(deadline):" in source



class FrozenClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _config(**overrides: Any) -> mint_uds.TrustedSessionMintUdsConfig:
    values: dict[str, Any] = {
        "socket_path": "/run/odoo-v3/session-mint.sock",
        "odoo_issuer_uid": 1101,
        "pi_bridge_uid": 1201,
        "socket_group_gid": 1101,
        "session_ttl_seconds": 45,
        "session_max_uses": 16,
        "max_inflight_requests": 4,
        "current_release_digest": RELEASE_DIGEST,
        "current_registry_digest": REGISTRY_DIGEST,
    }
    values.update(overrides)
    return mint_uds.TrustedSessionMintUdsConfig(**values)


def _identity_payload(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
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
    value.update(overrides)
    return value


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def test_config_keeps_ttl_and_use_budget_root_controlled() -> None:
    config = _config()
    assert config.session_ttl_seconds == 45
    assert config.session_max_uses == 16
    assert config.max_inflight_requests == 4

    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="different UID"):
        _config(pi_bridge_uid=1101)
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="canonical"):
        _config(socket_path="//run/odoo-v3/session-mint.sock")
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="TTL"):
        _config(session_ttl_seconds=0)
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="use budget"):
        _config(session_max_uses=0)
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="use budget"):
        _config(session_max_uses=2)
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="in-flight"):
        _config(max_inflight_requests=0)
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="in-flight"):
        _config(max_inflight_requests=True)
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="in-flight"):
        _config(max_inflight_requests=33)
    assert mint_uds.TrustedSessionMintUdsConfig(
        socket_path="/run/odoo-v3/session-mint.sock",
        odoo_issuer_uid=1101,
        pi_bridge_uid=1201,
        socket_group_gid=1101,
        max_inflight_requests=4,
        current_release_digest=RELEASE_DIGEST,
        current_registry_digest=REGISTRY_DIGEST,
    ).session_max_uses == 32


def test_capacity_response_is_fixed_retryable_and_never_leaks_a_handle() -> None:
    status, headers, body = _response(mint_uds._capacity_response())

    assert status == 503
    assert headers["connection"] == "close"
    assert headers["cache-control"] == "no-store"
    assert body == mint_uds._safe_error(
        "session_mint_capacity_exhausted", retryable=True
    )
    assert body["ok"] is False
    assert body["error"]["retryable"] is True
    assert "handle" not in json.dumps(body, sort_keys=True).lower()


def test_same_uid_threat_is_explicit_and_pid_is_not_authentication() -> None:
    config = _config()
    attacker = mint_uds._PeerCredentials(pid=999_999, uid=1101, gid=9999)
    pi = mint_uds._PeerCredentials(pid=1, uid=1201, gid=1101)

    assert mint_uds._peer_is_allowed(attacker, config) is True
    assert mint_uds._peer_is_allowed(pi, config) is False
    assert "cannot distinguish" in mint_uds.SAME_UID_THREAT.lower()
    assert "different unix uid" in mint_uds.SAME_UID_THREAT.lower()


def test_request_accepts_only_exact_server_identity_fields() -> None:
    identity = mint_uds._decode_identity_request(_json_bytes(_identity_payload()))
    assert identity.user_id == 42
    assert identity.company_id == 7
    assert identity.allowed_company_ids == frozenset({7, 9})
    assert identity.release_digest == RELEASE_DIGEST
    assert identity.registry_digest == REGISTRY_DIGEST

    for forbidden in (
        {"ttl_seconds": 999},
        {"max_uses": 999},
        {"session_id": "caller-chosen"},
        {"handle": "caller-chosen"},
    ):
        with pytest.raises(
            mint_uds.TrustedSessionMintUdsError,
            match="exact Odoo identity fields",
        ):
            mint_uds._decode_identity_request(
                _json_bytes(_identity_payload(**forbidden))
            )


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"user_id":42,"user_id":43}',
        b'{"user_id":NaN}',
        b"\xff",
        _json_bytes(_identity_payload(allowed_company_ids=[9, 7])),
        _json_bytes(_identity_payload(allowed_company_ids=[7, 7])),
        _json_bytes(_identity_payload(database_uuid=DATABASE_UUID.upper())),
        _json_bytes(_identity_payload(company_id=8)),
    ],
)
def test_request_rejects_noncanonical_or_cross_company_identity(body: bytes) -> None:
    with pytest.raises(mint_uds.TrustedSessionMintUdsError):
        mint_uds._decode_identity_request(body)


def test_store_issue_uses_only_fixed_config_budget(tmp_path: Path) -> None:
    now = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
    store = SQLiteTrustedSessionStore(
        (tmp_path / "sessions.sqlite3").resolve(), clock=FrozenClock(now)
    )
    config = _config(session_ttl_seconds=45, session_max_uses=16)
    identity = mint_uds._decode_identity_request(_json_bytes(_identity_payload()))

    issued = mint_uds._issue_session(store, config, identity)

    assert issued.max_uses == 16
    assert issued.session.issued_at == now
    assert issued.session.expires_at == now + timedelta(seconds=45)
    for _ in range(16):
        assert store.resolve(issued.handle) == issued.session
    assert store.resolve(issued.handle) is None


@pytest.mark.parametrize(
    "forged",
    [
        {"release_digest": "e" * 64},
        {"registry_digest": "f" * 64},
    ],
)
def test_route_mismatch_is_rejected_before_any_session_or_event_insert(
    tmp_path: Path, forged: dict[str, str]
) -> None:
    path = (tmp_path / "sessions.sqlite3").resolve()
    store = SQLiteTrustedSessionStore(path)
    identity = mint_uds._decode_identity_request(
        _json_bytes(_identity_payload(**forged))
    )

    with pytest.raises(
        mint_uds.TrustedSessionMintUdsError, match="current release route"
    ):
        mint_uds._issue_session(store, _config(), identity)

    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM trusted_sessions").fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM trusted_session_security_events"
        ).fetchone()[0] == 0
    assert store.verify_integrity() is True


@pytest.mark.parametrize(
    "reconciliation_error",
    [
        TrustedSessionKnownCommittedError,
        TrustedSessionCommitOutcomeUnknownError,
    ],
)
@pytest.mark.parametrize("mutation", ["issue", "revoke"])
def test_store_reconciliation_outcome_is_non_retryable_and_safely_classified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reconciliation_error: type[TrustedSessionReconciliationRequiredError],
    mutation: str,
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    backend_secret = "private-session-store-state"

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        try:
            raise reconciliation_error(backend_secret)
        except TrustedSessionReconciliationRequiredError as exc:
            raise RuntimeError("private-wrapper") from exc

    monkeypatch.setattr(SQLiteTrustedSessionStore, mutation, fail)
    with pytest.raises(
        mint_uds._TrustedSessionReconciliationRequired
    ) as rejected:
        if mutation == "issue":
            mint_uds._issue_session(
                store,
                _config(),
                mint_uds._decode_identity_request(
                    _json_bytes(_identity_payload())
                ),
            )
        else:
            mint_uds._revoke_session(store, "A" * 43)

    assert backend_secret not in str(rejected.value)
    assert "private-wrapper" not in str(rejected.value)
    action = "mint" if mutation == "issue" else "revoke"
    body = mint_uds._safe_error(
        f"session_{action}_reconciliation_required",
        reconciliation_required=True,
    )
    assert body["error"]["retryable"] is False
    assert body["error"]["reconciliation_required"] is True
    assert backend_secret not in json.dumps(body)


def test_revoke_request_accepts_only_handle_and_never_echoes_it(tmp_path: Path) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    config = _config()
    identity = mint_uds._decode_identity_request(_json_bytes(_identity_payload()))
    issued = mint_uds._issue_session(store, config, identity)

    assert mint_uds._decode_revoke_request(
        _json_bytes({"handle": issued.handle})
    ) == issued.handle
    assert mint_uds._revoke_session(store, issued.handle) is True
    assert store.resolve(issued.handle) is None
    assert mint_uds._revoke_session(store, issued.handle) is False
    assert mint_uds._revoke_session(store, "A" * 43) is False
    assert mint_uds._revoke_session(store, "invalid") is False

    outcomes = [
        (event.event_type, event.outcome) for event in store.security_events()
    ]
    assert ("session.revoked", "accepted") in outcomes
    assert ("session.revoke_rejected", "already_revoked") in outcomes
    assert ("session.revoke_rejected", "unknown") in outcomes
    assert ("session.revoke_rejected", "invalid") in outcomes
    accepted = next(
        event
        for event in store.security_events()
        if event.event_type == "session.revoked"
    )
    assert json.loads(accepted.details_json) == {
        "reason": "odoo_request_completed",
        "release_digest": RELEASE_DIGEST,
        "registry_digest": REGISTRY_DIGEST,
    }
    assert issued.handle not in json.dumps(
        mint_uds._safe_error("session_revoke_rejected")
    )


@pytest.mark.parametrize(
    "body",
    [
        _json_bytes({}),
        _json_bytes({"handle": "A" * 43, "reason": "caller-selected"}),
        _json_bytes({"handle": "A" * 513}),
        _json_bytes({"handle": 42}),
        b'{"handle":"first","handle":"second"}',
    ],
)
def test_revoke_request_rejects_nonexact_or_unbounded_body(body: bytes) -> None:
    with pytest.raises(mint_uds.TrustedSessionMintUdsError):
        mint_uds._decode_revoke_request(body)


def test_peer_credentials_use_linux_so_peercred(monkeypatch: pytest.MonkeyPatch) -> None:
    option = 0x7FFF
    monkeypatch.setattr(mint_uds.socket, "SO_PEERCRED", option, raising=False)
    calls: list[tuple[int, int, int]] = []

    class FakeConnection:
        def getsockopt(self, level: int, name: int, length: int) -> bytes:
            calls.append((level, name, length))
            return struct.pack(mint_uds._PEER_CREDENTIAL_FORMAT, 123, 1101, 1102)

    peer = mint_uds._peer_credentials(FakeConnection())  # type: ignore[arg-type]
    assert peer == mint_uds._PeerCredentials(pid=123, uid=1101, gid=1102)
    assert calls == [
        (socket.SOL_SOCKET, option, mint_uds._PEER_CREDENTIAL_SIZE)
    ]


def test_header_contract_is_bounded_and_allows_no_authority_overrides() -> None:
    headers = Message()
    headers.add_header("Host", "odoo-session-issuer")
    headers.add_header("Content-Type", "application/json")
    headers.add_header("Content-Length", "512")
    headers.add_header("Connection", "close")
    mint_uds._validate_headers(headers, _config())

    headers.add_header("X-Odoo-V3-TTL", "999")
    with pytest.raises(mint_uds.TrustedSessionMintUdsError, match="not allowed"):
        mint_uds._validate_headers(headers, _config())

    oversized = mint_uds._HeaderLimitedReader(
        BytesIO(b"X-Padding: " + b"x" * 2048 + b"\r\n"),
        max_bytes=1024,
        max_count=8,
    )
    with pytest.raises(mint_uds.http.client.LineTooLong):
        oversized.readline()


def test_transport_has_no_tcp_server_and_no_access_logging(
    capfd: pytest.CaptureFixture[str],
) -> None:
    source = inspect.getsource(mint_uds)
    assert "UnixStreamServer" in source
    assert "TCPServer" not in source
    assert "SO_PEERCRED" in source
    secret = "opaque-handle-must-not-be-logged"
    mint_uds._MintRequestHandler.log_message(object(), "%s", secret)
    captured = capfd.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
    assert secret not in json.dumps(mint_uds._safe_error("mint_failed"))


def _raw_request(
    *,
    path: str = mint_uds.MINT_PATH,
    body: bytes | None = None,
    method: str = "POST",
    content_type: str = "application/json",
    extra_headers: list[tuple[str, str]] | None = None,
) -> bytes:
    body = _json_bytes(_identity_payload()) if body is None else body
    headers = [
        ("Host", "odoo-session-issuer"),
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Connection", "close"),
    ]
    headers.extend(extra_headers or [])
    rendered = "".join(f"{name}: {value}\r\n" for name, value in headers)
    return (
        f"{method} {path} HTTP/1.1\r\n{rendered}\r\n".encode("ascii") + body
    )


def _response(response: bytes) -> tuple[int, dict[str, str], dict[str, Any]]:
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("ascii").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        assert name.lower() not in headers
        headers[name.lower()] = value.strip()
    assert int(headers["content-length"]) == len(body)
    return status, headers, json.loads(body)


@contextmanager
def _linux_server(
    store: SQLiteTrustedSessionStore,
    *,
    issuer_uid: int | None = None,
    request_timeout_seconds: float = 2.0,
    max_inflight_requests: int = 4,
) -> Iterator[mint_uds.TrustedSessionMintUdsConfig]:
    if sys.platform != "linux" or mint_uds._TrustedUnixHTTPServer is None:
        pytest.skip("requires Linux Unix sockets and SO_PEERCRED")
    root = Path(tempfile.mkdtemp(prefix="odoo-v3-mint-uds-", dir="/tmp"))
    root.chmod(0o700)
    path = root / "session-mint.sock"
    current_uid = os.getuid()
    effective_issuer = current_uid if issuer_uid is None else issuer_uid
    pi_uid = current_uid + 1 if effective_issuer == current_uid else current_uid
    if pi_uid == effective_issuer:
        pi_uid += 1
    config = mint_uds.TrustedSessionMintUdsConfig(
        socket_path=str(path),
        odoo_issuer_uid=effective_issuer,
        pi_bridge_uid=pi_uid,
        socket_group_gid=os.getgid(),
        session_ttl_seconds=45,
        session_max_uses=16,
        max_inflight_requests=max_inflight_requests,
        current_release_digest=RELEASE_DIGEST,
        current_registry_digest=REGISTRY_DIGEST,
        request_timeout_seconds=request_timeout_seconds,
    )
    server = mint_uds._TrustedUnixHTTPServer(
        config,
        store,
        bind_and_activate=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield config
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        path.unlink(missing_ok=True)
        root.rmdir()


def _exchange(path: str, request: bytes) -> bytes:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(3)
    try:
        client.connect(path)
        try:
            client.sendall(request)
        except (BrokenPipeError, ConnectionResetError):
            return b""
        chunks: list[bytes] = []
        while True:
            try:
                chunk = client.recv(65536)
            except ConnectionResetError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        client.close()


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux mint UDS contract")
def test_real_linux_fixed_route_mints_without_logging_handle(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    observed_scopes: list[float | None] = []
    issue_session = mint_uds._issue_session

    def issue_inside_scope(*args: Any, **kwargs: Any) -> Any:
        observed_scopes.append(current_monotonic_deadline())
        return issue_session(*args, **kwargs)

    monkeypatch.setattr(mint_uds, "_issue_session", issue_inside_scope)
    with _linux_server(store) as config:
        response = _exchange(config.socket_path, _raw_request())
    status, headers, body = _response(response)
    assert status == 201
    assert headers["content-type"] == "application/json"
    assert body["ok"] is True
    handle = body["session"]["handle"]
    assert store.resolve(handle) is not None
    assert len(observed_scopes) == 1
    assert observed_scopes[0] is not None
    assert observed_scopes[0] > time.monotonic() - config.request_timeout_seconds
    captured = capfd.readouterr()
    assert handle not in captured.out
    assert handle not in captured.err


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux mint UDS contract")
@pytest.mark.parametrize(
    "reconciliation_error",
    [
        TrustedSessionKnownCommittedError,
        TrustedSessionCommitOutcomeUnknownError,
    ],
)
@pytest.mark.parametrize(
    ("mutation", "path", "code"),
    [
        ("issue", mint_uds.MINT_PATH, "session_mint_reconciliation_required"),
        (
            "revoke",
            mint_uds.REVOKE_PATH,
            "session_revoke_reconciliation_required",
        ),
    ],
)
def test_real_linux_reconciliation_outcome_is_distinct_safe_http_503(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reconciliation_error: type[TrustedSessionReconciliationRequiredError],
    mutation: str,
    path: str,
    code: str,
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    backend_secret = "private-session-store-state"
    handle = "A" * 43

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise reconciliation_error(backend_secret)

    monkeypatch.setattr(SQLiteTrustedSessionStore, mutation, fail)
    body = (
        _json_bytes(_identity_payload())
        if mutation == "issue"
        else _json_bytes({"handle": handle})
    )
    with _linux_server(store) as config:
        response = _exchange(
            config.socket_path,
            _raw_request(path=path, body=body),
        )

    status, headers, response_body = _response(response)
    assert status == 503
    assert headers["cache-control"] == "no-store"
    assert response_body == mint_uds._safe_error(
        code, reconciliation_required=True
    )
    assert response_body["error"]["retryable"] is False
    assert response_body["error"]["reconciliation_required"] is True
    serialized = json.dumps(response_body)
    assert backend_secret not in serialized
    assert handle not in serialized


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux mint UDS contract")
def test_real_linux_slow_client_consumes_one_bounded_slot_then_releases_it(
    tmp_path: Path,
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    with _linux_server(store, max_inflight_requests=1) as config:
        slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        slow.settimeout(2)
        try:
            slow.connect(config.socket_path)
            slow.sendall(b"POST ")
            time.sleep(0.05)
            rejected = _exchange(config.socket_path, _raw_request())
        finally:
            slow.close()

        status, headers, body = _response(rejected)
        assert status == 503
        assert headers["cache-control"] == "no-store"
        assert body == mint_uds._safe_error(
            "session_mint_capacity_exhausted", retryable=True
        )
        assert store.security_events() == ()

        recovered = b""
        for _ in range(50):
            recovered = _exchange(config.socket_path, _raw_request())
            if _response(recovered)[0] == 201:
                break
            time.sleep(0.02)

    recovered_status, _, recovered_body = _response(recovered)
    assert recovered_status == 201
    assert recovered_body["ok"] is True
    assert store.resolve(recovered_body["session"]["handle"]) is not None


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux mint UDS contract")
def test_real_linux_revoke_route_is_fail_closed_and_never_echoes_handle(
    tmp_path: Path,
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    with _linux_server(store) as config:
        minted = _exchange(config.socket_path, _raw_request())
        handle = _response(minted)[2]["session"]["handle"]
        revoked = _exchange(
            config.socket_path,
            _raw_request(
                path=mint_uds.REVOKE_PATH,
                body=_json_bytes({"handle": handle}),
            ),
        )
        repeated = _exchange(
            config.socket_path,
            _raw_request(
                path=mint_uds.REVOKE_PATH,
                body=_json_bytes({"handle": handle}),
            ),
        )
        unknown = _exchange(
            config.socket_path,
            _raw_request(
                path=mint_uds.REVOKE_PATH,
                body=_json_bytes({"handle": "A" * 43}),
            ),
        )
        invalid = _exchange(
            config.socket_path,
            _raw_request(
                path=mint_uds.REVOKE_PATH,
                body=_json_bytes({"handle": "invalid"}),
            ),
        )

    assert _response(revoked) == (
        200,
        _response(revoked)[1],
        {"ok": True, "revoked": True},
    )
    for response in (repeated, unknown, invalid):
        status, _headers, body = _response(response)
        assert status == 404
        assert body["ok"] is False
        assert handle.encode("ascii") not in response
    assert store.resolve(handle) is None


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux mint UDS contract")
@pytest.mark.parametrize(
    ("request_bytes", "status"),
    [
        (_raw_request(path="/v1/trusted-session/mint?ttl=999"), 404),
        (_raw_request(method="GET"), 405),
        (_raw_request(body=_json_bytes(_identity_payload(ttl_seconds=999))), 400),
        (_raw_request(content_type="application/json; charset=UTF-8"), 415),
        (_raw_request(extra_headers=[("Transfer-Encoding", "chunked")]), 400),
        (_raw_request(extra_headers=[("X-Odoo-V3-TTL", "999")]), 400),
        (_raw_request(extra_headers=[("Content-Length", "2")]), 411),
    ],
)
def test_real_linux_rejects_noncanonical_mint_requests(
    tmp_path: Path, request_bytes: bytes, status: int
) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    with _linux_server(store) as config:
        response = _exchange(config.socket_path, request_bytes)
    assert _response(response)[0] == status
    assert store.security_events() == ()


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux mint UDS contract")
def test_real_linux_rejects_wrong_peer_uid_without_http_response(tmp_path: Path) -> None:
    store = SQLiteTrustedSessionStore((tmp_path / "sessions.sqlite3").resolve())
    wrong_uid = os.getuid() + 1
    with _linux_server(store, issuer_uid=wrong_uid) as config:
        response = _exchange(config.socket_path, _raw_request())
    assert response == b""
    assert store.security_events() == ()

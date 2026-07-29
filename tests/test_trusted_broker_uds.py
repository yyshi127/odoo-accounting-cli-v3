from __future__ import annotations

import errno
import inspect
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from email.message import Message
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

import pytest

from odoo_accounting_cli_v3 import trusted_broker_uds as uds
from odoo_accounting_cli_v3.monotonic_deadline import current_monotonic_deadline


SESSION = "session_" + "s" * 40
CURRENT_RELEASE = "1" * 64
CURRENT_REGISTRY = "2" * 64
HISTORICAL_RELEASE = "3" * 64
HISTORICAL_REGISTRY = "4" * 64
SOCKET_PATH = "/run/odoo-accounting-cli-v3/pi-broker.sock"


def test_request_handlers_are_non_daemon_and_joined_on_server_close() -> None:
    source = inspect.getsource(uds)
    assert "daemon_threads = False" in source
    assert "block_on_close = True" in source


def test_dispatcher_is_entered_inside_the_request_deadline_scope() -> None:
    source = inspect.getsource(uds._BrokerRequestHandler.do_POST)
    assert "with monotonic_deadline_scope(deadline):" in source



def _config(**overrides: Any) -> uds.TrustedBrokerUdsConfig:
    values: dict[str, Any] = {
        "socket_path": SOCKET_PATH,
        "allowed_client_uid": 1001,
        "socket_group_gid": 1002,
        "max_inflight_requests": 16,
    }
    values.update(overrides)
    return uds.TrustedBrokerUdsConfig(**values)


def _headers(**overrides: str | list[str]) -> Message:
    values: dict[str, str | list[str]] = {
        "Host": "localhost",
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": "2",
        uds.BROKER_ACTION_HEADER: "read",
        uds.BROKER_PROTOCOL_HEADER: uds.BROKER_PROTOCOL,
        uds.BROKER_SESSION_HEADER: SESSION,
        uds.RELEASE_DIGEST_HEADER: CURRENT_RELEASE,
        uds.REGISTRY_DIGEST_HEADER: CURRENT_REGISTRY,
    }
    values.update(overrides)
    result = Message()
    for name, value in values.items():
        for item in value if isinstance(value, list) else [value]:
            result[name] = item
    return result


def _dispatch_request(action: str = "read") -> uds.BrokerDispatchRequest:
    return uds.BrokerDispatchRequest(
        action=action,
        payload={},
        session_handle=SESSION,
        release_digest=CURRENT_RELEASE,
        registry_digest=CURRENT_REGISTRY,
        peer_uid=1001,
        observed_peer_pid=123,
        deadline_monotonic=123.0,
    )


def _result(
    *,
    ok: bool = True,
    authority_verified: bool = True,
    release: str | None = CURRENT_RELEASE,
    registry: str | None = CURRENT_REGISTRY,
    status_code: int = 200,
    body: dict[str, Any] | None = None,
) -> uds.BrokerDispatchResult:
    return uds.BrokerDispatchResult(
        status_code=status_code,
        body={"ok": ok} if body is None else body,
        authority_verified=authority_verified,
        executed_release_digest=release,
        executed_registry_digest=registry,
    )


def _stat(
    kind: int,
    mode: int,
    *,
    uid: int = 0,
    gid: int = 1002,
    dev: int = 7,
    ino: int = 11,
) -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=kind | mode,
        st_uid=uid,
        st_gid=gid,
        st_dev=dev,
        st_ino=ino,
    )


def test_routes_are_the_fixed_pi_broker_contract() -> None:
    assert uds.BROKER_ACTION_PATHS == {
        "/v1/read": "read",
        "/v1/operation/prepare": "operation.prepare",
        "/v1/operation/preview": "operation.preview",
        "/v1/operation/approve-execute": "operation.approve_execute",
        "/v1/operation/status": "operation.status",
        "/v1/operation/result": "operation.result",
        "/v1/operation/diagnostics": "operation.diagnostics",
        "/v1/operation/recover": "operation.recover",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("socket_path", "relative/pi-broker.sock"),
        ("socket_path", "//run/odoo-v3/pi-broker.sock"),
        ("socket_path", "/run/../tmp/pi-broker.sock"),
        ("socket_path", "/run//pi-broker.sock"),
        ("socket_path", "/run/pi broker.sock"),
        ("socket_path", "/run/pi-broker"),
        ("allowed_client_uid", -1),
        ("allowed_client_uid", True),
        ("allowed_client_uid", 2**32 - 1),
        ("socket_group_gid", -1),
        ("socket_group_gid", 2**32 - 1),
        ("socket_mode", 0o666),
        ("socket_mode", 0o460),
        ("socket_mode", 0o10660),
        ("max_body_bytes", 1),
        ("max_body_bytes", 16 * 1024 * 1024 + 1),
        ("max_response_bytes", 1),
        ("max_response_bytes", 511),
        ("max_header_bytes", 1023),
        ("max_header_bytes", 64 * 1024 + 1),
        ("max_header_count", 7),
        ("max_header_count", 65),
        ("max_inflight_requests", 0),
        ("max_inflight_requests", True),
        ("max_inflight_requests", 33),
        ("request_timeout_seconds", 0.01),
        ("request_timeout_seconds", 120),
    ],
)
def test_config_rejects_unsafe_values(field: str, value: Any) -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        _config(**{field: value})


def test_config_is_pure_and_valid_on_every_platform() -> None:
    config = _config()
    assert config.socket_path == SOCKET_PATH
    assert config.socket_mode == 0o660
    assert config.max_body_bytes == 1024 * 1024
    assert config.max_header_bytes == 8192
    assert config.max_header_count == 16
    assert config.max_inflight_requests == 16


def test_capacity_response_is_fixed_retryable_and_never_authoritative() -> None:
    status, headers, body = _response_headers(uds._capacity_response())

    assert status == 503
    assert headers["connection"] == "close"
    assert headers["cache-control"] == "no-store"
    assert uds.BROKER_AUTHORITY_HEADER.lower() not in headers
    assert uds.EXECUTED_RELEASE_DIGEST_HEADER.lower() not in headers
    assert uds.EXECUTED_REGISTRY_DIGEST_HEADER.lower() not in headers
    assert body == uds._safe_error("broker_capacity_exhausted", retryable=True)
    assert body["ok"] is False
    assert body["error"]["retryable"] is True
    assert SESSION not in json.dumps(body, sort_keys=True)


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"a":1,"a":2}',
        b'{"number":NaN}',
        b"{\xff}",
        b'{"nested":{"x_odoo_v3_broker_session":"forged"}}',
        b'{"X-Odoo-V3-Release-Digest":"forged"}',
    ],
)
def test_request_json_is_strict_and_cannot_carry_authority(body: bytes) -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._decode_request_object(body)


def test_request_json_rejects_numeric_overflow_and_excessive_nesting() -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._decode_request_object(b'{"amount":1e999}')
    nested = b'{"value":' + b"[" * 1100 + b"]" * 1100 + b"}"
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._decode_request_object(nested)


def test_transport_headers_match_the_real_pi_client() -> None:
    headers = _headers()
    uds._validate_header_limits(headers, _config())
    assert uds._read_transport_headers(headers, expected_action="read") == (
        SESSION,
        CURRENT_RELEASE,
        CURRENT_REGISTRY,
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (uds.BROKER_ACTION_HEADER, "operation.status"),
        (uds.BROKER_PROTOCOL_HEADER, "pi-broker-v2"),
        (uds.BROKER_SESSION_HEADER, "short"),
        (uds.RELEASE_DIGEST_HEADER, "A" * 64),
        (uds.REGISTRY_DIGEST_HEADER, "not-a-digest"),
    ],
)
def test_transport_rejects_invalid_authority_headers(name: str, value: str) -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._read_transport_headers(_headers(**{name: value}), expected_action="read")


def test_transport_rejects_duplicate_and_unrecognized_v3_headers() -> None:
    duplicated = _headers(**{uds.BROKER_SESSION_HEADER: [SESSION, SESSION]})
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._read_transport_headers(duplicated, expected_action="read")
    unrecognized = _headers(**{"X-Odoo-V3-Binary-Path": "/tmp/forged"})
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._read_transport_headers(unrecognized, expected_action="read")


def test_header_count_and_bytes_are_bounded() -> None:
    too_many = _headers(
        **{f"X-Test-{index}": "x" for index in range(9)}
    )
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validate_header_limits(too_many, _config(max_header_count=16))
    too_large = _headers(**{"X-Padding": "x" * 1024})
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validate_header_limits(too_large, _config(max_header_bytes=1024))
    assert uds._CONTENT_LENGTH.fullmatch("9" * 5000) is None


def test_header_reader_enforces_limits_before_http_parsing_buffers_input() -> None:
    oversized = uds._HeaderLimitedReader(
        BytesIO(b"X-Padding: " + b"x" * 1100 + b"\r\n\r\n"),
        max_bytes=1024,
        max_count=16,
    )
    with pytest.raises(uds.http.client.LineTooLong, match="broker request headers"):
        oversized.readline()

    too_many = uds._HeaderLimitedReader(
        BytesIO(b"A: 1\r\nB: 2\r\n\r\n"),
        max_bytes=1024,
        max_count=1,
    )
    assert too_many.readline() == b"A: 1\r\n"
    with pytest.raises(
        uds.http.client.HTTPException,
        match="too many broker request headers",
    ):
        too_many.readline()


def test_current_actions_require_the_requested_executed_identity() -> None:
    assert uds._validated_executed_identity(
        _result(), _dispatch_request("read")
    ) == (CURRENT_RELEASE, CURRENT_REGISTRY)
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validated_executed_identity(
            _result(release=HISTORICAL_RELEASE, registry=HISTORICAL_REGISTRY),
            _dispatch_request("read"),
        )
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validated_executed_identity(
            _result(release=HISTORICAL_RELEASE, registry=HISTORICAL_REGISTRY),
            _dispatch_request("operation.prepare"),
        )


def test_existing_operation_can_use_a_dispatcher_authenticated_historical_release() -> None:
    result = _result(
        release=HISTORICAL_RELEASE,
        registry=HISTORICAL_REGISTRY,
    )
    assert uds._validated_executed_identity(
        result, _dispatch_request("operation.status")
    ) == (HISTORICAL_RELEASE, HISTORICAL_REGISTRY)


@pytest.mark.parametrize(
    "result",
    [
        _result(release=None, registry=None),
        _result(release=CURRENT_RELEASE, registry=None),
        _result(release="A" * 64, registry=CURRENT_REGISTRY),
        _result(authority_verified=False),
        _result(status_code=201),
        _result(body={"data": {}}),
    ],
)
def test_success_requires_authenticated_well_formed_executed_identity(
    result: uds.BrokerDispatchResult,
) -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validated_executed_identity(result, _dispatch_request())


def test_authenticated_error_may_omit_executed_identity() -> None:
    result = _result(ok=False, release=None, registry=None)
    assert uds._validated_executed_identity(
        result, _dispatch_request("operation.status")
    ) == (None, None)


def test_authenticated_application_error_must_use_the_http_200_envelope() -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validated_executed_identity(
            _result(
                ok=False,
                release=None,
                registry=None,
                status_code=403,
            ),
            _dispatch_request("operation.approve_execute"),
        )


@pytest.mark.parametrize(
    "value",
    [
        _stat(stat.S_IFREG, 0o750),
        _stat(stat.S_IFDIR, 0o750, uid=1001),
        _stat(stat.S_IFDIR, 0o770),
        _stat(stat.S_IFDIR, 0o751),
    ],
)
def test_private_socket_parent_validation_rejects_unsafe_state(value: Any) -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validate_parent_stat(value)


@pytest.mark.parametrize(
    "value",
    [
        _stat(stat.S_IFLNK, 0o777),
        _stat(stat.S_IFDIR, 0o755, uid=1001),
        _stat(stat.S_IFDIR, 0o775),
    ],
)
def test_socket_ancestor_validation_rejects_symlink_owner_and_write_bits(
    value: Any,
) -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validate_ancestor_stat(value)


@pytest.mark.parametrize(
    "value",
    [
        _stat(stat.S_IFREG, 0o660),
        _stat(stat.S_IFSOCK, 0o660, uid=1001),
        _stat(stat.S_IFSOCK, 0o660, gid=9999),
        _stat(stat.S_IFSOCK, 0o600),
    ],
)
def test_socket_validation_requires_exact_type_owner_group_and_mode(value: Any) -> None:
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._validate_socket_stat(value, _config())


class _Probe:
    def __init__(self, connect_error: OSError | None) -> None:
        self.connect_error = connect_error

    def settimeout(self, _timeout: float) -> None:
        pass

    def connect(self, _path: str) -> None:
        if self.connect_error is not None:
            raise self.connect_error

    def close(self) -> None:
        pass


def test_stale_socket_removal_unlinks_only_a_twice_verified_inode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = _stat(stat.S_IFSOCK, 0o660)
    stats = iter([trusted, trusted])
    unlinks: list[tuple[str, int | None]] = []
    monkeypatch.setattr(uds, "_stat_socket_at", lambda *_args: next(stats))
    monkeypatch.setattr(
        uds,
        "_new_stale_socket_probe",
        lambda *_args, **_kwargs: _Probe(OSError(errno.ECONNREFUSED, "stale")),
    )
    monkeypatch.setattr(
        uds,
        "_unlink_socket_at",
        lambda dir_fd, name: unlinks.append((name, dir_fd)),
    )

    uds._remove_verified_stale_socket(41, _config())

    assert unlinks == [("pi-broker.sock", 41)]


@pytest.mark.parametrize(
    "second_state",
    [
        _stat(stat.S_IFSOCK, 0o660, ino=12),
        _stat(stat.S_IFLNK, 0o777),
    ],
)
def test_stale_socket_replacement_is_never_unlinked(
    monkeypatch: pytest.MonkeyPatch,
    second_state: Any,
) -> None:
    states = iter([_stat(stat.S_IFSOCK, 0o660), second_state])
    monkeypatch.setattr(uds, "_stat_socket_at", lambda *_args: next(states))
    monkeypatch.setattr(
        uds,
        "_new_stale_socket_probe",
        lambda *_args, **_kwargs: _Probe(OSError(errno.ECONNREFUSED, "stale")),
    )
    monkeypatch.setattr(
        uds,
        "_unlink_socket_at",
        lambda *_args, **_kwargs: pytest.fail("replacement must not be unlinked"),
    )
    with pytest.raises(uds.TrustedBrokerUdsError):
        uds._remove_verified_stale_socket(41, _config())


def test_live_socket_is_never_unlinked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        uds,
        "_stat_socket_at",
        lambda *args, **kwargs: _stat(stat.S_IFSOCK, 0o660),
    )
    monkeypatch.setattr(
        uds,
        "_new_stale_socket_probe",
        lambda *_args, **_kwargs: _Probe(None),
    )
    monkeypatch.setattr(
        uds,
        "_unlink_socket_at",
        lambda *_args, **_kwargs: pytest.fail("live socket must not be unlinked"),
    )
    with pytest.raises(uds.TrustedBrokerUdsError, match="already active"):
        uds._remove_verified_stale_socket(41, _config())


def test_non_linux_platform_never_creates_a_server() -> None:
    if sys.platform == "linux":
        pytest.skip("Windows/pure-platform guard")
    with pytest.raises(uds.TrustedBrokerUdsError, match="only on Linux"):
        uds.create_trusted_broker_uds_server(_config(), lambda _request: _result())


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() == 0,
    reason="non-root Linux launcher guard",
)
def test_non_root_linux_process_cannot_bind_the_trusted_socket() -> None:
    with pytest.raises(uds.TrustedBrokerUdsError, match="requires root"):
        uds.create_trusted_broker_uds_server(
            _config(),
            lambda _request: _result(),
        )


def _raw_request(
    path: str,
    action: str,
    *,
    body: bytes = b"{}",
    content_type: str = "application/json; charset=utf-8",
    extra_headers: list[tuple[str, str]] | None = None,
    method: str = "POST",
) -> bytes:
    headers = [
        ("Host", "localhost"),
        ("Content-Length", str(len(body))),
        ("Content-Type", content_type),
        (uds.BROKER_ACTION_HEADER, action),
        (uds.BROKER_PROTOCOL_HEADER, uds.BROKER_PROTOCOL),
        (uds.BROKER_SESSION_HEADER, SESSION),
        (uds.REGISTRY_DIGEST_HEADER, CURRENT_REGISTRY),
        (uds.RELEASE_DIGEST_HEADER, CURRENT_RELEASE),
        ("Connection", "close"),
    ]
    headers.extend(extra_headers or [])
    head = f"{method} {path} HTTP/1.1\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in headers
    )
    return head.encode("ascii") + b"\r\n" + body


def _response_headers(response: bytes) -> tuple[int, dict[str, str], dict[str, Any]]:
    head, body = response.split(b"\r\n\r\n", 1)
    lines = head.decode("latin-1").split("\r\n")
    status_code = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        assert name.lower() not in headers
        headers[name.lower()] = value.strip()
    assert int(headers["content-length"]) == len(body)
    return status_code, headers, json.loads(body)


@contextmanager
def _linux_server(
    dispatcher: Any,
    *,
    allowed_uid: int | None = None,
    **config_overrides: Any,
) -> Iterator[tuple[uds.TrustedBrokerUdsConfig, Any]]:
    if sys.platform != "linux" or uds._TrustedUnixHTTPServer is None:
        pytest.skip("requires Linux Unix sockets and SO_PEERCRED")
    root = Path(tempfile.mkdtemp(prefix="odoo-v3-uds-", dir="/tmp"))
    path = root / "broker.sock"
    config = uds.TrustedBrokerUdsConfig(
        socket_path=str(path),
        allowed_client_uid=os.getuid() if allowed_uid is None else allowed_uid,
        socket_group_gid=os.getgid(),
        max_inflight_requests=config_overrides.pop("max_inflight_requests", 16),
        **config_overrides,
    )
    server = uds._TrustedUnixHTTPServer(
        config,
        dispatcher,
        bind_and_activate=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield config, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        path.unlink(missing_ok=True)
        root.rmdir()


def _unix_exchange(path: str, request: bytes) -> bytes:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
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


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
@pytest.mark.parametrize("path,action", list(uds.BROKER_ACTION_PATHS.items()))
def test_real_linux_uds_dispatches_every_fixed_pi_route(path: str, action: str) -> None:
    captured: list[uds.BrokerDispatchRequest] = []
    observed_scopes: list[float | None] = []

    def dispatch(request: uds.BrokerDispatchRequest) -> uds.BrokerDispatchResult:
        captured.append(request)
        observed_scopes.append(current_monotonic_deadline())
        return _result()

    with _linux_server(dispatch) as (config, _server):
        response = _unix_exchange(config.socket_path, _raw_request(path, action))

    status_code, headers, body = _response_headers(response)
    assert status_code == 200
    assert body == {"ok": True}
    assert headers[uds.BROKER_AUTHORITY_HEADER.lower()] == "verified-v1"
    assert headers[uds.EXECUTED_RELEASE_DIGEST_HEADER.lower()] == CURRENT_RELEASE
    assert headers[uds.EXECUTED_REGISTRY_DIGEST_HEADER.lower()] == CURRENT_REGISTRY
    assert len(captured) == 1
    assert captured[0].action == action
    assert captured[0].payload == {}
    assert captured[0].session_handle == SESSION
    assert captured[0].peer_uid == os.getuid()
    assert captured[0].observed_peer_pid == os.getpid()
    assert observed_scopes == [captured[0].deadline_monotonic]


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
def test_real_linux_slow_client_consumes_one_bounded_slot_then_releases_it() -> None:
    calls: list[uds.BrokerDispatchRequest] = []

    def dispatch(request: uds.BrokerDispatchRequest) -> uds.BrokerDispatchResult:
        calls.append(request)
        return _result()

    with _linux_server(dispatch, max_inflight_requests=1) as (config, _server):
        slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        slow.settimeout(2)
        try:
            slow.connect(config.socket_path)
            slow.sendall(b"POST ")
            time.sleep(0.05)
            rejected_responses = [
                _unix_exchange(
                    config.socket_path,
                    _raw_request("/v1/read", "read"),
                )
                for _ in range(20)
            ]
        finally:
            slow.close()

        for rejected in rejected_responses:
            status, headers, body = _response_headers(rejected)
            assert status == 503
            assert headers["cache-control"] == "no-store"
            assert body == uds._safe_error(
                "broker_capacity_exhausted", retryable=True
            )
        assert calls == []

        recovered = b""
        for _ in range(50):
            recovered = _unix_exchange(
                config.socket_path,
                _raw_request("/v1/read", "read"),
            )
            if _response_headers(recovered)[0] == 200:
                break
            time.sleep(0.02)

    assert _response_headers(recovered)[0] == 200
    assert len(calls) == 1


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
def test_real_linux_uds_allows_dispatcher_authenticated_historical_identity() -> None:
    def dispatch(_request: uds.BrokerDispatchRequest) -> uds.BrokerDispatchResult:
        return _result(
            release=HISTORICAL_RELEASE,
            registry=HISTORICAL_REGISTRY,
        )

    with _linux_server(dispatch) as (config, _server):
        response = _unix_exchange(
            config.socket_path,
            _raw_request("/v1/operation/status", "operation.status"),
        )
    status_code, headers, _body = _response_headers(response)
    assert status_code == 200
    assert headers[uds.EXECUTED_RELEASE_DIGEST_HEADER.lower()] == HISTORICAL_RELEASE
    assert headers[uds.EXECUTED_REGISTRY_DIGEST_HEADER.lower()] == HISTORICAL_REGISTRY


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
def test_real_linux_uds_preserves_authenticated_error_as_http_200_envelope() -> None:
    error = {
        "command": "operation.approve_execute",
        "ok": False,
        "error": {
            "code": "approval_missing",
            "message": "A separate authenticated approval is required.",
            "odoo_effect": "none",
            "retryable": False,
        },
    }
    result = _result(
        ok=False,
        release=None,
        registry=None,
        body=error,
    )
    with _linux_server(lambda _request: result) as (config, _server):
        response = _unix_exchange(
            config.socket_path,
            _raw_request(
                "/v1/operation/approve-execute",
                "operation.approve_execute",
            ),
        )
    status_code, headers, body = _response_headers(response)
    assert status_code == 200
    assert body == error
    assert headers[uds.BROKER_AUTHORITY_HEADER.lower()] == "verified-v1"
    assert uds.EXECUTED_RELEASE_DIGEST_HEADER.lower() not in headers
    assert uds.EXECUTED_REGISTRY_DIGEST_HEADER.lower() not in headers


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
@pytest.mark.parametrize(
    "result",
    [
        _result(release=None, registry=None),
        _result(release=HISTORICAL_RELEASE, registry=HISTORICAL_REGISTRY),
        _result(authority_verified=False),
    ],
)
def test_real_linux_uds_never_authenticates_invalid_success(
    result: uds.BrokerDispatchResult,
) -> None:
    with _linux_server(lambda _request: result) as (config, _server):
        response = _unix_exchange(
            config.socket_path,
            _raw_request("/v1/read", "read"),
        )
    status_code, headers, body = _response_headers(response)
    assert status_code == 500
    assert body["error"]["code"] == "broker_dispatch_failed"
    assert uds.BROKER_AUTHORITY_HEADER.lower() not in headers
    assert uds.EXECUTED_RELEASE_DIGEST_HEADER.lower() not in headers
    assert uds.EXECUTED_REGISTRY_DIGEST_HEADER.lower() not in headers


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
@pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8"])
def test_real_linux_uds_accepts_only_the_two_explicit_json_content_types(
    content_type: str,
) -> None:
    with _linux_server(lambda _request: _result()) as (config, _server):
        response = _unix_exchange(
            config.socket_path,
            _raw_request("/v1/read", "read", content_type=content_type),
        )
    assert _response_headers(response)[0] == 200


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
@pytest.mark.parametrize(
    ("request_bytes", "expected_status"),
    [
        (_raw_request("/v1/read?x=1", "read"), 404),
        (_raw_request("/v1/read", "operation.status"), 401),
        (
            _raw_request(
                "/v1/read",
                "read",
                content_type="application/json; charset=UTF-8",
            ),
            415,
        ),
        (_raw_request("/v1/read", "read", body=b"[]"), 400),
        (
            _raw_request(
                "/v1/read",
                "read",
                extra_headers=[("Transfer-Encoding", "chunked")],
            ),
            400,
        ),
        (
            _raw_request(
                "/v1/read",
                "read",
                extra_headers=[("X-Odoo-V3-Binary-Path", "/tmp/forged")],
            ),
            401,
        ),
        (
            _raw_request(
                "/v1/read",
                "read",
                extra_headers=[("Content-Length", "2")],
            ),
            411,
        ),
        (
            _raw_request("/v1/read", "read").replace(
                b"Content-Length: 2",
                b"Content-Length: " + b"9" * 5000,
                1,
            ),
            411,
        ),
        (
            _raw_request(
                "/v1/read",
                "read",
                extra_headers=[(f"X-Test-{index}", "x") for index in range(8)],
            ),
            431,
        ),
        (
            _raw_request(
                "/v1/read",
                "read",
                extra_headers=[("X-Padding", "x" * 9000)],
            ),
            431,
        ),
        (_raw_request("/v1/read", "read", method="GET"), 405),
    ],
)
def test_real_linux_uds_rejects_noncanonical_wire_requests(
    request_bytes: bytes,
    expected_status: int,
) -> None:
    calls: list[object] = []
    with _linux_server(lambda value: calls.append(value) or _result()) as (
        config,
        _server,
    ):
        response = _unix_exchange(config.socket_path, request_bytes)
    assert _response_headers(response)[0] == expected_status
    assert calls == []


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
def test_real_linux_uds_peer_uid_is_an_admission_control() -> None:
    calls: list[object] = []
    with _linux_server(
        lambda value: calls.append(value) or _result(),
        allowed_uid=os.getuid() + 1,
    ) as (config, _server):
        response = _unix_exchange(
            config.socket_path,
            _raw_request("/v1/read", "read"),
        )
    assert response == b""
    assert calls == []


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
def test_real_linux_uds_never_logs_or_echoes_the_session(
    capfd: pytest.CaptureFixture[str],
) -> None:
    def dispatch(request: uds.BrokerDispatchRequest) -> uds.BrokerDispatchResult:
        return _result(body={"ok": True, "session": request.session_handle})

    with _linux_server(dispatch) as (config, _server):
        response = _unix_exchange(
            config.socket_path,
            _raw_request("/v1/read", "read"),
        )
    assert SESSION.encode("ascii") not in response
    captured = capfd.readouterr()
    assert SESSION not in captured.out
    assert SESSION not in captured.err


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
def test_real_linux_uds_enforces_request_and_response_body_limits() -> None:
    calls: list[uds.BrokerDispatchRequest] = []
    with _linux_server(
        lambda request: calls.append(request) or _result(),
        max_body_bytes=2,
    ) as (config, _server):
        request_response = _unix_exchange(
            config.socket_path,
            _raw_request("/v1/read", "read", body=b'{"x":1}'),
        )
    request_status, _request_headers, _request_body = _response_headers(
        request_response
    )
    assert request_status == 413
    assert calls == []

    oversized = _result(body={"ok": True, "padding": "x" * 1000})
    with _linux_server(
        lambda _request: oversized,
        max_response_bytes=512,
    ) as (config, _server):
        response_response = _unix_exchange(
            config.socket_path,
            _raw_request("/v1/read", "read"),
        )
    response_status, response_headers, response_body = _response_headers(
        response_response
    )
    assert response_status == 500
    assert len(json.dumps(response_body, separators=(",", ":")).encode()) <= 512
    assert uds.BROKER_AUTHORITY_HEADER.lower() not in response_headers


@pytest.mark.skipif(sys.platform != "linux", reason="real Linux UDS contract")
def test_write_dispatch_failure_never_claims_that_odoo_had_no_effect() -> None:
    def fail(_request: uds.BrokerDispatchRequest) -> uds.BrokerDispatchResult:
        raise RuntimeError("must not be logged")

    with _linux_server(fail) as (config, _server):
        response = _unix_exchange(
            config.socket_path,
            _raw_request(
                "/v1/operation/approve-execute",
                "operation.approve_execute",
            ),
        )
    status_code, headers, body = _response_headers(response)
    assert status_code == 500
    assert body["error"]["odoo_effect"] == "unknown"
    assert uds.BROKER_AUTHORITY_HEADER.lower() not in headers


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="secure root-owned binding is exercised when tests run as root",
)
def test_root_launcher_binds_and_removes_only_its_real_linux_socket() -> None:
    root = Path(tempfile.mkdtemp(prefix="odoo-v3-uds-root-", dir="/run"))
    root.chmod(0o750)
    path = root / "broker.sock"
    config = uds.TrustedBrokerUdsConfig(
        socket_path=str(path),
        allowed_client_uid=os.getuid(),
        socket_group_gid=os.getgid(),
        max_inflight_requests=16,
    )
    server = uds.create_trusted_broker_uds_server(config, lambda _request: _result())
    try:
        assert server.address_family == socket.AF_UNIX
        assert server.socket.family == socket.AF_UNIX
        value = path.lstat()
        assert stat.S_ISSOCK(value.st_mode)
        assert value.st_uid == 0
        assert value.st_gid == os.getgid()
        assert stat.S_IMODE(value.st_mode) == 0o660
    finally:
        server.server_close()
        assert not path.exists()
        root.rmdir()


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="secure root-owned cleanup is exercised when tests run as root",
)
def test_server_close_never_unlinks_a_replacement_socket() -> None:
    root = Path(tempfile.mkdtemp(prefix="odoo-v3-uds-replace-", dir="/run"))
    root.chmod(0o750)
    path = root / "broker.sock"
    held = root / "held.sock"
    config = uds.TrustedBrokerUdsConfig(
        socket_path=str(path),
        allowed_client_uid=os.getuid(),
        socket_group_gid=os.getgid(),
        max_inflight_requests=16,
    )
    server = uds.create_trusted_broker_uds_server(config, lambda _request: _result())
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        path.rename(held)
        replacement.bind(str(path))
        replacement_identity = (path.stat().st_dev, path.stat().st_ino)

        server.server_close()

        assert path.exists()
        assert stat.S_ISSOCK(path.lstat().st_mode)
        assert (path.stat().st_dev, path.stat().st_ino) == replacement_identity
        assert held.exists()
    finally:
        server.server_close()
        replacement.close()
        path.unlink(missing_ok=True)
        held.unlink(missing_ok=True)
        root.rmdir()


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="ancestor symlink rejection is exercised when tests run as root",
)
def test_root_launcher_rejects_a_symlinked_socket_parent() -> None:
    real = Path(tempfile.mkdtemp(prefix="odoo-v3-uds-real-", dir="/run"))
    real.chmod(0o750)
    linked = real.with_name(real.name + "-link")
    linked.symlink_to(real, target_is_directory=True)
    config = uds.TrustedBrokerUdsConfig(
        socket_path=str(linked / "broker.sock"),
        allowed_client_uid=os.getuid(),
        socket_group_gid=os.getgid(),
        max_inflight_requests=16,
    )
    try:
        with pytest.raises(uds.TrustedBrokerUdsError):
            uds.create_trusted_broker_uds_server(
                config,
                lambda _request: _result(),
            )
        assert linked.is_symlink()
        assert not (real / "broker.sock").exists()
    finally:
        linked.unlink()
        real.rmdir()

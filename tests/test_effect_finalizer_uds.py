from __future__ import annotations

import os
import socket
import socketserver
import struct
import sys
import threading
from datetime import datetime, timedelta, timezone

import pytest
import odoo_accounting_cli_v3.effect_finalizer_uds as finalizer_uds

if not hasattr(socket, "AF_UNIX"):
    # Windows' socketpair is an AF_INET pair; aliasing the family lets these
    # local protocol tests exercise the connected-FD path. Linux CI uses the
    # real AF_UNIX/SO_PEERCRED production boundary.
    socket.AF_UNIX = socket.AF_INET

from odoo_accounting_cli_v3.effect_finalizer_uds import (
    EffectFinalizerConnectedClient,
    EffectFinalizerPeerCredentials,
    EffectFinalizerUnixServer,
    EffectFinalizerUdsError,
    SystemdMainProcessPeerPolicy,
    _receive_credentialed_frame,
    _receive_frame,
    read_linux_peer_credentials,
    receive_linux_credentialed_chunk,
    serve_effect_finalizer_connection,
)
from odoo_accounting_cli_v3.effect_finalizer import EffectFinalizationIdentity
from odoo_accounting_cli_v3.effect_finalizer_service import (
    EffectFinalizationIntent,
    FinalizedEffect,
)


DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
INSTALLATION_ID = "22222222-2222-4222-8222-222222222222"
NOW = datetime(2026, 7, 19, 2, 0, tzinfo=timezone.utc)
SECRET = b"effect-finalizer-secret-material-32-bytes"


def _identity() -> EffectFinalizationIdentity:
    return EffectFinalizationIdentity(
        attestation_key_id="effect-finalizer-v1",
        guard_installation_id=INSTALLATION_ID,
        database_oid=16384,
    )


def _peer(_connection):
    return EffectFinalizerPeerCredentials(pid=9981, uid=3101, gid=3101)


def _response_sender(_connection, maximum):
    chunk = _connection.recv(maximum)
    if not chunk:
        return b"", None
    return chunk, EffectFinalizerPeerCredentials(pid=9984, uid=3104, gid=3104)


def _response_sender_policy(peer):
    return peer == EffectFinalizerPeerCredentials(
        pid=9984, uid=3104, gid=3104
    )


def _intent() -> EffectFinalizationIntent:
    return EffectFinalizationIntent(
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        operation_id="op-finalize-1",
        operation_digest="0" * 64,
        execution_result_digest="1" * 64,
        resolution_operation_id="op-finalize-1",
        resolution_operation_digest="0" * 64,
        resolution_execution_result_digest="1" * 64,
        resolution_result_digest="3" * 64,
        resolution_kind="verified",
    )


def test_systemd_peer_policy_requires_exact_uid_and_current_main_pid() -> None:
    policy = SystemdMainProcessPeerPolicy(
        expected_uid=3101,
        systemd_unit="odoo-accounting-cli-v3-broker.service",
        resolve_main_pid=lambda unit: 9981,
    )

    assert policy(EffectFinalizerPeerCredentials(pid=9981, uid=3101, gid=3101))
    assert not policy(EffectFinalizerPeerCredentials(pid=9982, uid=3101, gid=3101))
    assert not policy(EffectFinalizerPeerCredentials(pid=9981, uid=3103, gid=3101))


def test_credentialed_multichunk_frame_resolves_main_pid_once() -> None:
    sender = EffectFinalizerPeerCredentials(pid=9984, uid=3104, gid=3104)
    chunks = [(b"{", sender), (b"}\n", None), (b"", None)]
    receive_sizes = []
    resolver_calls = []

    def receive(_connection, maximum):
        receive_sizes.append(maximum)
        return chunks.pop(0)

    policy = SystemdMainProcessPeerPolicy(
        expected_uid=3104,
        expected_gid=3104,
        systemd_unit="odoo-accounting-cli-v3-effect-finalizer.service",
        resolve_main_pid=lambda unit: resolver_calls.append(unit) or 9984,
    )

    assert _receive_credentialed_frame(
        object(),
        1024,
        "test response",
        sender_policy=policy,
        receive_chunk=receive,
    ) == {}
    assert receive_sizes[0] == 1
    assert resolver_calls == [
        "odoo-accounting-cli-v3-effect-finalizer.service"
    ]


def test_credentialed_frame_rejects_missing_first_or_changed_later_sender() -> None:
    sender = EffectFinalizerPeerCredentials(pid=9984, uid=3104, gid=3104)
    changed = EffectFinalizerPeerCredentials(pid=9985, uid=3104, gid=3104)

    for chunks in (
        [(b"{", None)],
        [(b"{", sender), (b"}\n", changed)],
    ):
        observed = list(chunks)
        with pytest.raises(EffectFinalizerUdsError, match="sender"):
            _receive_credentialed_frame(
                object(),
                1024,
                "test response",
                sender_policy=lambda peer: peer == sender,
                receive_chunk=lambda _connection, _maximum: observed.pop(0),
            )


def test_handoff_uses_long_idle_timeout_then_short_frame_timeout() -> None:
    class Stream:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, value):
            self.timeouts.append(value)

        def recv(self, _maximum):
            return b"{}\n"

    stream = Stream()

    assert _receive_frame(
        stream,
        1024,
        "test request",
        first_byte_timeout_seconds=115,
        io_timeout_seconds=1,
    ) == {}
    assert stream.timeouts == [115.0, 1.0]


@pytest.mark.skipif(
    not hasattr(EffectFinalizerUnixServer, "verify_request"),
    reason="requires UnixStreamServer",
)
def test_thread_start_failure_releases_inflight_capacity(monkeypatch) -> None:
    server = object.__new__(EffectFinalizerUnixServer)
    server._capacity = threading.BoundedSemaphore(1)

    def fail_to_start(_server, _request, _address):
        raise RuntimeError("thread start failed")

    monkeypatch.setattr(
        socketserver.ThreadingMixIn,
        "process_request",
        fail_to_start,
    )
    assert server.verify_request(object(), object())
    with pytest.raises(RuntimeError, match="thread start failed"):
        server.process_request(object(), object())
    assert server.verify_request(object(), object())
    server._capacity.release()


def test_linux_credential_receiver_rejects_ancillary_truncation(
    monkeypatch,
) -> None:
    class Connection:
        def recvmsg(self, _maximum, _ancillary_size, _flags):
            return b"{", [], 8, None

    monkeypatch.setattr(finalizer_uds, "_LINUX_SCM_AVAILABLE", True)
    monkeypatch.setattr(socket, "SO_PASSCRED", 16, raising=False)
    monkeypatch.setattr(socket, "SCM_CREDENTIALS", 2, raising=False)
    monkeypatch.setattr(socket, "MSG_CTRUNC", 8, raising=False)
    monkeypatch.setattr(socket, "CMSG_SPACE", lambda size: size + 16, raising=False)

    with pytest.raises(EffectFinalizerUdsError, match="truncated"):
        receive_linux_credentialed_chunk(Connection(), 1)


def test_linux_credential_receiver_accepts_only_kernel_dummy_at_eof(
    monkeypatch,
) -> None:
    class Connection:
        def __init__(self, credentials):
            self.credentials = credentials

        def recvmsg(self, _maximum, _ancillary_size, _flags):
            return (
                b"",
                [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, self.credentials)],
                0,
                None,
            )

    monkeypatch.setattr(finalizer_uds, "_LINUX_SCM_AVAILABLE", True)
    monkeypatch.setattr(socket, "SO_PASSCRED", 16, raising=False)
    monkeypatch.setattr(socket, "SCM_CREDENTIALS", 2, raising=False)
    monkeypatch.setattr(socket, "CMSG_SPACE", lambda size: size + 16, raising=False)

    assert receive_linux_credentialed_chunk(
        Connection(struct.pack("3i", 0, 0, 0)), 1
    ) == (b"", None)
    with pytest.raises(EffectFinalizerUdsError, match="EOF credentials"):
        receive_linux_credentialed_chunk(
            Connection(struct.pack("3i", 9984, 3104, 3104)), 1
        )


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "fork"),
    reason="requires Linux AF_UNIX process credentials",
)
def test_socket_activation_listener_creator_differs_from_response_sender(
    tmp_path,
) -> None:
    path = tmp_path / "activated.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - asserted by the Linux parent.
        try:
            accepted, _address = listener.accept()
            accepted.sendall(b"{}\n")
            accepted.close()
            listener.close()
            os._exit(0)
        except BaseException:
            os._exit(2)
    try:
        client.connect(str(path))
        listener_peer = read_linux_peer_credentials(client)
        assert listener_peer.pid == os.getpid()
        assert listener_peer.pid != child_pid
        policy = SystemdMainProcessPeerPolicy(
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
            systemd_unit="odoo-accounting-cli-v3-effect-finalizer.service",
            resolve_main_pid=lambda _unit: child_pid,
        )
        assert _receive_credentialed_frame(
            client,
            1024,
            "test response",
            sender_policy=policy,
            receive_chunk=receive_linux_credentialed_chunk,
        ) == {}
    finally:
        client.close()
        listener.close()
        _pid, status = os.waitpid(child_pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0


def test_inherited_fd_client_consumes_source_never_connects_and_is_cloexec(
    monkeypatch,
) -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    connect_calls = []
    real_connect = socket.socket.connect

    def forbidden_connect(self, address):
        connect_calls.append(address)
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)
    descriptor = left.detach()
    client = EffectFinalizerConnectedClient.from_inherited_fd(
        descriptor,
        expected_identity=_identity(),
        response_sender_policy=_response_sender_policy,
        receive_credentialed_chunk=_response_sender,
        request_io_timeout_seconds=1,
        max_request_bytes=8192,
        max_response_bytes=8192,
    )
    try:
        assert connect_calls == []
        assert client.is_inheritable() is False
        with pytest.raises(OSError):
            os.fstat(descriptor)
    finally:
        client.close()
        right.close()


def test_one_connected_fd_round_trip_uses_strict_intent_and_typed_receipt() -> None:
    from odoo_accounting_cli_v3.effect_finalizer import (
        EffectFinalizationReceipt,
        EffectFinalizationRequest,
        create_effect_attestation,
    )

    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    intent = _intent()

    class Service:
        def finalize_with_attempt(self, observed_intent):
            assert observed_intent == intent
            request = EffectFinalizationRequest.from_intent(
                observed_intent,
                verified_at=NOW,
                expires_at=NOW + timedelta(seconds=120),
            )
            attestation = create_effect_attestation(
                request,
                key_id="effect-finalizer-v1",
                secret=SECRET,
            )
            receipt = EffectFinalizationReceipt.from_database_mapping(
                {
                    "receipt_attestation_id": attestation.attestation_id,
                    "receipt_guard_installation_id": INSTALLATION_ID,
                    "receipt_database_oid": 16384,
                    "receipt_database_uuid": DATABASE_UUID,
                    "resolved_operation_id": request.operation_id,
                    "receipt_resolution_operation_id": request.resolution_operation_id,
                    "applied_resolution_kind": request.resolution_kind,
                    "resolved_anchor_count": 1,
                    "remaining_unresolved_count": 0,
                    "guard_epoch": 0,
                    "receipt_attestation_digest": attestation.attestation_digest,
                    "finalized_at": NOW + timedelta(seconds=1),
                    "finalized_txid": "9123",
                    "replayed": False,
                },
                request=request,
                attestation=attestation,
            )
            return FinalizedEffect(request=request, receipt=receipt)

    worker = threading.Thread(
        target=serve_effect_finalizer_connection,
        args=(right, Service()),
        kwargs={
            "peer_policy": lambda _peer: True,
            "peer_credentials_reader": _peer,
            "handoff_idle_timeout_seconds": 115,
            "request_io_timeout_seconds": 1,
            "max_request_bytes": 8192,
            "max_response_bytes": 8192,
        },
    )
    worker.start()
    descriptor = left.detach()
    client = EffectFinalizerConnectedClient.from_inherited_fd(
        descriptor,
        expected_identity=_identity(),
        response_sender_policy=_response_sender_policy,
        receive_credentialed_chunk=_response_sender,
        request_io_timeout_seconds=1,
        max_request_bytes=8192,
        max_response_bytes=8192,
    )
    try:
        receipt = client.finalize(intent)
    finally:
        client.close()
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert receipt.operation_id == intent.operation_id


def test_server_rejects_peer_that_is_not_broker_systemd_main_process() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    worker = threading.Thread(
        target=serve_effect_finalizer_connection,
        args=(right, object()),
        kwargs={
            "peer_policy": lambda _peer: False,
            "peer_credentials_reader": _peer,
            "handoff_idle_timeout_seconds": 115,
            "request_io_timeout_seconds": 1,
            "max_request_bytes": 8192,
            "max_response_bytes": 8192,
        },
    )
    worker.start()
    try:
        try:
            left.sendall(b"{}\n")
            left.shutdown(socket.SHUT_WR)
        except ConnectionError:
            pass
        try:
            observed = left.recv(1024)
        except ConnectionError:
            observed = b""
        assert observed == b""
    finally:
        left.close()
        worker.join(timeout=2)

    assert not worker.is_alive()

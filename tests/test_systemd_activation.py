from __future__ import annotations

import os
import socket
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import odoo_accounting_cli_v3.systemd_activation as activation


NAMES = (
    activation.PI_BROKER_SOCKET_NAME,
    activation.SESSION_MINT_SOCKET_NAME,
    activation.TRUSTED_APPROVAL_SOCKET_NAME,
)


def _linux(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(activation.sys, "platform", "linux")
    monkeypatch.setattr(activation.os, "name", "posix")
    monkeypatch.setattr(activation.os, "getpid", lambda: 4242)
    monkeypatch.setattr(
        activation.os,
        "fstat",
        lambda descriptor: os.stat_result(
            (stat.S_IFSOCK | 0o660, 0, 0, 1, 0, 0, 0, 0, 0, 0)
        ),
    )


def _environment(monkeypatch: pytest.MonkeyPatch, **overrides: str) -> None:
    values = {
        "LISTEN_PID": "4242",
        "LISTEN_FDS": "3",
        "LISTEN_FDNAMES": ":".join(NAMES),
    }
    values.update(overrides)
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_exact_named_descriptors_are_mapped_then_activation_environment_is_erased(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _linux(monkeypatch)
    _environment(monkeypatch)

    assert activation.activated_socket_fds(NAMES) == {
        NAMES[0]: 3,
        NAMES[1]: 4,
        NAMES[2]: 5,
    }
    assert all(name not in os.environ for name in activation._ACTIVATION_ENVIRONMENT)


@pytest.mark.parametrize(
    "overrides",
    [
        {"LISTEN_PID": "4243"},
        {"LISTEN_PID": "04242"},
        {"LISTEN_FDS": "2"},
        {"LISTEN_FDNAMES": ":".join(NAMES[:2])},
        {"LISTEN_FDNAMES": f"{NAMES[0]}:{NAMES[0]}:{NAMES[2]}"},
        {"LISTEN_FDNAMES": f"{NAMES[0]}:{NAMES[1]}:attacker"},
    ],
)
def test_activation_rejects_wrong_process_count_name_or_duplicate(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str]
) -> None:
    _linux(monkeypatch)
    _environment(monkeypatch, **overrides)

    with pytest.raises(activation.SystemdActivationError):
        activation.activated_socket_fds(NAMES)
    assert all(name not in os.environ for name in activation._ACTIVATION_ENVIRONMENT)


def test_activation_rejects_non_socket_descriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(monkeypatch)
    _environment(monkeypatch)
    monkeypatch.setattr(
        activation.os,
        "fstat",
        lambda descriptor: os.stat_result(
            (stat.S_IFREG | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0)
        ),
    )

    with pytest.raises(activation.SystemdActivationError, match="non-socket"):
        activation.activated_socket_fds(NAMES)


def test_activation_environment_can_be_retained_only_for_unit_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _linux(monkeypatch)
    _environment(monkeypatch)

    activation.activated_socket_fds(NAMES, unset_environment=False)
    assert os.environ["LISTEN_PID"] == "4242"


def test_adoption_does_not_compare_filesystem_and_sockfs_inodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Linux pathname and socket-FD inodes intentionally occupy different spaces."""

    af_unix, sock_stream, sol_socket, so_acceptconn = 1, 2, 3, 4

    class FakePath:
        def __init__(self, value: str) -> None:
            self.value = value

        @property
        def parent(self) -> "FakePath":
            if self.value == "/":
                return self
            parent = self.value.rsplit("/", 1)[0] or "/"
            return FakePath(parent)

        def is_absolute(self) -> bool:
            return self.value.startswith("/")

        def is_symlink(self) -> bool:
            return False

        def lstat(self) -> os.stat_result:
            if self.value.endswith(".sock"):
                return os.stat_result(
                    (stat.S_IFSOCK | 0o660, 10, 101, 1, 0, 2001, 0, 0, 0, 0)
                )
            return os.stat_result(
                (stat.S_IFDIR | 0o755, 11, 202, 1, 0, 0, 0, 0, 0, 0)
            )

        def __str__(self) -> str:
            return self.value

        def __eq__(self, other: object) -> bool:
            return isinstance(other, FakePath) and self.value == other.value

    class FakeSocket:
        def __init__(self, *, fileno: int | None = None) -> None:
            self.fileno_value = fileno
            self.family = af_unix
            self.type = sock_stream
            self.closed = False

        def getsockopt(self, level: int, option: int) -> int:
            assert (level, option) == (sol_socket, so_acceptconn)
            return 1

        def getsockname(self) -> str:
            return "/run/odoo-v3/broker.sock"

        def close(self) -> None:
            self.closed = True

    fake_os = SimpleNamespace(
        name="posix",
        fstat=lambda _descriptor: os.stat_result(
            (stat.S_IFSOCK | 0o600, 99, 999, 1, 0, 0, 0, 0, 0, 0)
        ),
        dup=lambda _descriptor: 91,
        set_inheritable=lambda *_args: None,
        close=lambda _descriptor: None,
    )
    fake_socket_module = SimpleNamespace(
        AF_UNIX=af_unix,
        SOCK_STREAM=sock_stream,
        SOL_SOCKET=sol_socket,
        SO_ACCEPTCONN=so_acceptconn,
        socket=FakeSocket,
    )
    monkeypatch.setattr(activation, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(activation, "os", fake_os)
    monkeypatch.setattr(activation, "Path", FakePath)
    monkeypatch.setattr(activation, "socket", fake_socket_module)
    placeholder = FakeSocket()
    server = SimpleNamespace(socket=placeholder)

    adopted = activation.adopt_activated_unix_server(
        server,
        3,
        socket_path="/run/odoo-v3/broker.sock",
        expected_owner_uid=0,
        expected_group_gid=2001,
        expected_mode=0o660,
    )

    assert adopted is server
    assert placeholder.closed is True
    assert server.socket.fileno_value == 91
    assert server.socket.closed is False


@pytest.mark.skipif(
    activation.sys.platform != "linux", reason="real Linux activated UDS contract"
)
def test_real_listening_unix_socket_is_adopted_without_root_binding() -> None:
    root = Path(tempfile.mkdtemp(prefix="odoo-v3-activation-", dir=Path.home()))
    root.chmod(0o700)
    path = root / "broker.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    placeholder = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o660)
        listener.listen(4)
        server = SimpleNamespace(socket=placeholder)
        adopted = activation.adopt_activated_unix_server(
            server,
            listener.fileno(),
            socket_path=str(path),
            expected_owner_uid=os.getuid(),
            expected_group_gid=os.getgid(),
            expected_mode=0o660,
            require_root_ancestors=False,
        )
        assert adopted is server
        assert server.socket.getsockname() == str(path)
        assert server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
        assert server.socket.get_inheritable() is False
        server.socket.close()
    finally:
        if placeholder.fileno() >= 0:
            placeholder.close()
        listener.close()
        path.unlink(missing_ok=True)
        root.rmdir()

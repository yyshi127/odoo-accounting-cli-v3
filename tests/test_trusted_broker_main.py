from __future__ import annotations

import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import odoo_accounting_cli_v3.trusted_broker_main as service
from odoo_accounting_cli_v3.systemd_activation import (
    PI_BROKER_SOCKET_NAME,
    SESSION_MINT_SOCKET_NAME,
    TRUSTED_APPROVAL_SOCKET_NAME,
)
from odoo_accounting_cli_v3.trusted_broker_main import (
    TrustedBrokerServiceError,
)


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "deployment" / "dev9" / "systemd"


class _Server:
    def __init__(self, *, return_immediately: bool = False) -> None:
        self.return_immediately = return_immediately
        self.started = threading.Event()
        self.released = threading.Event()
        self.shutdown_calls = 0
        self.close_calls = 0

    def serve_forever(self, *, poll_interval: float) -> None:
        assert poll_interval == service._POLL_INTERVAL_SECONDS
        self.started.set()
        if not self.return_immediately:
            assert self.released.wait(timeout=2)

    def shutdown(self) -> None:
        self.shutdown_calls += 1
        self.released.set()

    def server_close(self) -> None:
        self.close_calls += 1


def _runtime(fingerprint: str = "a" * 64) -> SimpleNamespace:
    config = SimpleNamespace(
        config_fingerprint=fingerprint,
        pi_broker_uds=object(),
        session_mint_uds=object(),
        trusted_approval_uds=object(),
    )
    return SimpleNamespace(
        config=config,
        dispatch_pi=object(),
        session_store=object(),
        broker=object(),
        verify_integrity=lambda: True,
    )


def test_full_preflight_precedes_activation_and_all_server_factories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    runtime = _runtime()
    config = SimpleNamespace(config_fingerprint=runtime.config.config_fingerprint)
    descriptors = {
        PI_BROKER_SOCKET_NAME: 30,
        SESSION_MINT_SOCKET_NAME: 31,
        TRUSTED_APPROVAL_SOCKET_NAME: 32,
    }
    servers = (_Server(), _Server(), _Server())

    monkeypatch.setattr(
        service,
        "load_trusted_broker_runtime_config",
        lambda path: events.append("load") or config,
    )
    monkeypatch.setattr(
        service,
        "build_trusted_broker_runtime",
        lambda path: events.append("build") or runtime,
    )
    runtime.verify_integrity = lambda: events.append("integrity") or True
    monkeypatch.setattr(
        service,
        "activated_socket_fds",
        lambda names: events.append("activation") or descriptors,
    )
    monkeypatch.setattr(
        service,
        "create_trusted_broker_uds_server_from_fd",
        lambda *args: events.append("pi") or servers[0],
    )
    monkeypatch.setattr(
        service,
        "create_trusted_session_mint_uds_server_from_fd",
        lambda *args: events.append("mint") or servers[1],
    )
    monkeypatch.setattr(
        service,
        "create_trusted_approval_uds_server_from_fd",
        lambda *args: events.append("approval") or servers[2],
    )
    monkeypatch.setattr(
        service,
        "_close_original_descriptors",
        lambda fds: events.append("close-fds") or True,
    )
    monkeypatch.setattr(
        service,
        "_serve_servers",
        lambda actual, **kwargs: events.append("serve"),
    )

    service.run_trusted_broker_service(
        "/etc/odoo-accounting-cli-v3/broker-runtime.json",
        install_signal_handlers=False,
    )

    assert events == [
        "load",
        "build",
        "integrity",
        "activation",
        "pi",
        "mint",
        "approval",
        "close-fds",
        "serve",
    ]


def test_configuration_drift_fails_before_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        service,
        "load_trusted_broker_runtime_config",
        lambda path: SimpleNamespace(config_fingerprint="a" * 64),
    )
    monkeypatch.setattr(
        service,
        "build_trusted_broker_runtime",
        lambda path: _runtime("b" * 64),
    )
    monkeypatch.setattr(
        service,
        "activated_socket_fds",
        lambda names: pytest.fail("activation happened before drift rejection"),
    )

    with pytest.raises(TrustedBrokerServiceError, match="changed during startup"):
        service.run_trusted_broker_service("/safe/config.json")


def test_partial_factory_failure_closes_server_and_original_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _Server()
    descriptors = {
        PI_BROKER_SOCKET_NAME: 30,
        SESSION_MINT_SOCKET_NAME: 31,
        TRUSTED_APPROVAL_SOCKET_NAME: 32,
    }
    closed: list[int] = []
    monkeypatch.setattr(
        service,
        "create_trusted_broker_uds_server_from_fd",
        lambda *args: first,
    )
    monkeypatch.setattr(
        service,
        "create_trusted_session_mint_uds_server_from_fd",
        lambda *args: (_ for _ in ()).throw(RuntimeError("private secret")),
    )
    monkeypatch.setattr(
        service,
        "_close_original_descriptors",
        lambda values: closed.extend(values) or True,
    )

    with pytest.raises(TrustedBrokerServiceError, match="construction failed"):
        service._construct_activated_servers(_runtime(), descriptors)

    assert first.close_calls == 1
    assert set(closed) == {30, 31, 32}


def test_original_descriptor_cleanup_failure_closes_all_servers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    servers = (_Server(), _Server(), _Server())
    descriptors = {
        PI_BROKER_SOCKET_NAME: 30,
        SESSION_MINT_SOCKET_NAME: 31,
        TRUSTED_APPROVAL_SOCKET_NAME: 32,
    }
    monkeypatch.setattr(
        service,
        "create_trusted_broker_uds_server_from_fd",
        lambda *args: servers[0],
    )
    monkeypatch.setattr(
        service,
        "create_trusted_session_mint_uds_server_from_fd",
        lambda *args: servers[1],
    )
    monkeypatch.setattr(
        service,
        "create_trusted_approval_uds_server_from_fd",
        lambda *args: servers[2],
    )
    monkeypatch.setattr(
        service,
        "_close_original_descriptors",
        lambda values: False,
    )

    with pytest.raises(TrustedBrokerServiceError, match="cleanup failed"):
        service._construct_activated_servers(_runtime(), descriptors)

    assert [server.close_calls for server in servers] == [1, 1, 1]


def test_original_descriptor_cleanup_really_closes_every_fd() -> None:
    descriptors = tuple(os.open(os.devnull, os.O_RDONLY) for _ in range(3))

    assert service._close_original_descriptors(descriptors)
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_graceful_stop_shuts_down_and_closes_all_three_servers() -> None:
    servers = (_Server(), _Server(), _Server())
    stop = threading.Event()
    stop.set()

    service._serve_servers(
        servers,
        stop_event=stop,
        install_signal_handlers=False,
    )

    assert [server.shutdown_calls for server in servers] == [1, 1, 1]
    assert [server.close_calls for server in servers] == [1, 1, 1]


def test_one_transport_exit_fails_and_closes_the_whole_group() -> None:
    servers = (_Server(return_immediately=True), _Server(), _Server())

    with pytest.raises(TrustedBrokerServiceError, match="stopped unexpectedly"):
        service._serve_servers(servers, install_signal_handlers=False)

    assert [server.shutdown_calls for server in servers] == [1, 1, 1]
    assert [server.close_calls for server in servers] == [1, 1, 1]


def test_signal_install_failure_closes_servers_and_restores_prior_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    servers = (_Server(), _Server(), _Server())
    installed: list[tuple[object, object]] = []
    prior = object()

    monkeypatch.setattr(service.signal, "getsignal", lambda signum: prior)

    def install(signum: object, handler: object) -> None:
        installed.append((signum, handler))
        if signum == service.signal.SIGINT and handler is not prior:
            raise ValueError("private failure")

    monkeypatch.setattr(service.signal, "signal", install)

    with pytest.raises(TrustedBrokerServiceError, match="could not be installed"):
        service._serve_servers(servers)

    assert (service.signal.SIGTERM, prior) in installed
    assert (service.signal.SIGINT, prior) in installed
    assert [server.close_calls for server in servers] == [1, 1, 1]


def test_main_never_prints_nested_exception_or_arguments(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "sensitive-handle-and-config-path"
    monkeypatch.setattr(
        service,
        "run_trusted_broker_service",
        lambda path: (_ for _ in ()).throw(RuntimeError(secret)),
    )

    assert service.main(["--config", f"/private/{secret}.json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "trusted broker service failed closed\n"
    assert secret not in captured.err


def test_main_argument_contract_is_exact(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert service.main([]) == 2
    assert service.main(["--config=/tmp/config.json"]) == 2
    assert service.main(["--help"]) == 0
    captured = capsys.readouterr()
    assert "ABSOLUTE_PATH" in captured.err
    assert "ABSOLUTE_PATH" in captured.out


def test_systemd_socket_assets_have_exact_root_owned_group_boundaries() -> None:
    expectations = {
        "odoo-accounting-cli-v3-pi-broker.socket": (
            "/run/odoo-accounting-cli-v3/pi-broker.sock",
            "odoo-v3-pi-broker",
            PI_BROKER_SOCKET_NAME,
        ),
        "odoo-accounting-cli-v3-session-mint.socket": (
            "/run/odoo-accounting-cli-v3/session-mint.sock",
            "odoo-v3-odoo-control",
            SESSION_MINT_SOCKET_NAME,
        ),
        "odoo-accounting-cli-v3-trusted-approval.socket": (
            "/run/odoo-accounting-cli-v3/trusted-approval.sock",
            "odoo-v3-odoo-control",
            TRUSTED_APPROVAL_SOCKET_NAME,
        ),
    }
    for filename, (path, group, descriptor_name) in expectations.items():
        text = (SYSTEMD / filename).read_text(encoding="utf-8")
        assert f"ListenStream={path}\n" in text
        assert f"SocketGroup={group}\n" in text
        assert f"FileDescriptorName={descriptor_name}\n" in text
        assert "SocketUser=root\n" in text
        assert "SocketMode=0660\n" in text
        assert "DirectoryMode=0750\n" in text
        assert "Accept=no\n" in text
        assert "Service=odoo-accounting-cli-v3-broker.service\n" in text
        assert "v2" not in text.lower()


def test_systemd_service_is_dedicated_nonroot_and_passes_exact_three_sockets() -> None:
    text = (
        SYSTEMD / "odoo-accounting-cli-v3-broker.service"
    ).read_text(encoding="utf-8")
    assert "User=odoo-v3-broker\n" in text
    assert "Group=odoo-v3-broker\n" in text
    assert "User=root" not in text
    assert "SupplementaryGroups=odoo-v3-runtime\n" in text
    assert "SupplementaryGroups=odoo\n" not in text
    assert "NoNewPrivileges=yes\n" in text
    assert "CapabilityBoundingSet=\n" in text
    assert "AmbientCapabilities=\n" in text
    assert "CAP_SETUID" not in text
    assert "RestrictSUIDSGID=yes\n" in text
    assert "TimeoutStopSec=135s\n" in text
    assert "ProtectSystem=strict\n" in text
    assert "ProtectHome=yes\n" in text
    assert "StateDirectory=odoo-accounting-cli-v3\n" in text
    assert "StateDirectoryMode=0700\n" in text
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n" in text
    assert "current" not in text
    assert "/releases/@V3_RELEASE@/bin/odoo-accounting-cli-v3-broker" in text
    assert "/odoo-accounting-cli-v3/broker/" not in text
    assert text.count("Sockets=odoo-accounting-cli-v3-") == 3
    assert text.count("Requires=odoo-accounting-cli-v3-") == 3
    assert "odoo-accounting-cli-v3-broker --config " in text
    assert "v2" not in text.lower()


def test_tmpfiles_asset_has_private_root_owned_runtime_boundary() -> None:
    text = (
        SYSTEMD / "odoo-accounting-cli-v3-tmpfiles.conf"
    ).read_text(encoding="utf-8")
    assert text == (
        "d /run/odoo-accounting-cli-v3 0750 root odoo-v3-runtime -\n"
    )


def test_console_script_has_separate_broker_entrypoint() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert (
        'odoo-accounting-cli-v3-broker = '
        '"odoo_accounting_cli_v3.trusted_broker_main:main"'
    ) in project


def test_canonical_broker_launcher_uses_only_its_immutable_release_source() -> None:
    launcher = (ROOT / "bin" / "odoo-accounting-cli-v3-broker").read_text(
        encoding="utf-8"
    )
    assert launcher.startswith("#!/usr/bin/python3 -I\n")
    assert "sys.flags.isolated" in launcher
    assert "os.path.realpath(launcher)" in launcher
    assert 'release_root / "src"' in launcher
    assert "sys.path.insert(0, str(_source_root()))" in launcher
    assert '"odoo_accounting_cli_v3.trusted_broker_main"' in launcher
    assert "site-packages" not in launcher

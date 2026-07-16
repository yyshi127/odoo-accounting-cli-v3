"""Fail-closed systemd entry point for the dedicated trusted broker service."""

from __future__ import annotations

import os
import queue
import signal
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .systemd_activation import (
    BROKER_SOCKET_NAMES,
    PI_BROKER_SOCKET_NAME,
    SESSION_MINT_SOCKET_NAME,
    TRUSTED_APPROVAL_SOCKET_NAME,
    activated_socket_fds,
)
from .trusted_broker_app import (
    TrustedBrokerRuntime,
    build_trusted_broker_runtime,
    load_trusted_broker_runtime_config,
)
from .trusted_approval_uds import create_trusted_approval_uds_server_from_fd
from .trusted_broker_uds import create_trusted_broker_uds_server_from_fd
from .trusted_session_mint_uds import (
    create_trusted_session_mint_uds_server_from_fd,
)


_USAGE = "usage: odoo-accounting-cli-v3-broker --config ABSOLUTE_PATH"
_STARTUP_FAILURE = "trusted broker service failed closed"
_POLL_INTERVAL_SECONDS = 0.2
_THREAD_JOIN_TIMEOUT_SECONDS = 5.0


class TrustedBrokerServiceError(RuntimeError):
    """The broker service could not safely enter or leave its serving state."""


def _close_original_descriptors(descriptors: Sequence[int]) -> bool:
    clean = True
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            clean = False
    return clean


def _close_servers(servers: Sequence[Any]) -> bool:
    clean = True
    for server in reversed(servers):
        try:
            server.server_close()
        except Exception:
            clean = False
    return clean


def _construct_activated_servers(
    runtime: TrustedBrokerRuntime,
    descriptors: dict[str, int],
) -> tuple[Any, Any, Any]:
    if set(descriptors) != BROKER_SOCKET_NAMES or len(set(descriptors.values())) != 3:
        raise TrustedBrokerServiceError("activated descriptor set is invalid")

    servers: list[Any] = []
    original_descriptors = tuple(descriptors.values())
    try:
        servers.append(
            create_trusted_broker_uds_server_from_fd(
                runtime.config.pi_broker_uds,
                runtime.dispatch_pi,
                descriptors[PI_BROKER_SOCKET_NAME],
            )
        )
        servers.append(
            create_trusted_session_mint_uds_server_from_fd(
                runtime.config.session_mint_uds,
                runtime.session_store,
                descriptors[SESSION_MINT_SOCKET_NAME],
            )
        )
        servers.append(
            create_trusted_approval_uds_server_from_fd(
                runtime.config.trusted_approval_uds,
                runtime.broker,
                descriptors[TRUSTED_APPROVAL_SOCKET_NAME],
            )
        )
    except Exception as exc:
        _close_servers(servers)
        _close_original_descriptors(original_descriptors)
        raise TrustedBrokerServiceError(
            "activated server construction failed"
        ) from exc

    if not _close_original_descriptors(original_descriptors):
        _close_servers(servers)
        raise TrustedBrokerServiceError(
            "activated descriptor cleanup failed"
        )
    return servers[0], servers[1], servers[2]


def _serve_worker(
    server: Any,
    result_queue: queue.Queue[bool],
) -> None:
    try:
        server.serve_forever(poll_interval=_POLL_INTERVAL_SECONDS)
    except BaseException:
        result_queue.put(False)
    else:
        result_queue.put(True)


def _shutdown_servers(servers: Sequence[Any]) -> bool:
    clean = True
    for server in servers:
        try:
            server.shutdown()
        except Exception:
            clean = False
    return clean


def _serve_servers(
    servers: Sequence[Any],
    *,
    stop_event: threading.Event | None = None,
    install_signal_handlers: bool = True,
) -> None:
    """Serve all transports together; one failed transport stops the group."""

    if len(servers) != 3 or type(install_signal_handlers) is not bool:
        raise TrustedBrokerServiceError("trusted server group is invalid")
    shutdown_requested = stop_event or threading.Event()
    results: queue.Queue[bool] = queue.Queue()
    threads: list[threading.Thread] = []
    previous_handlers: dict[signal.Signals, Any] = {}

    def request_shutdown(_signum: int, _frame: object) -> None:
        shutdown_requested.set()

    if install_signal_handlers:
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, request_shutdown)
        except (OSError, RuntimeError, ValueError) as exc:
            for signum, previous in previous_handlers.items():
                try:
                    signal.signal(signum, previous)
                except (OSError, RuntimeError, ValueError):
                    pass
            _close_servers(servers)
            raise TrustedBrokerServiceError(
                "service signal handlers could not be installed"
            ) from exc

    unexpected_exit = False
    clean_shutdown = True
    try:
        for index, server in enumerate(servers):
            thread = threading.Thread(
                target=_serve_worker,
                args=(server, results),
                name=f"trusted-broker-transport-{index + 1}",
                daemon=True,
            )
            threads.append(thread)
            thread.start()

        while not shutdown_requested.is_set():
            try:
                results.get(timeout=_POLL_INTERVAL_SECONDS)
            except queue.Empty:
                continue
            unexpected_exit = True
            shutdown_requested.set()

        if not results.empty():
            unexpected_exit = True

        clean_shutdown = _shutdown_servers(servers)
        for thread in threads:
            thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
        if any(thread.is_alive() for thread in threads):
            clean_shutdown = False
    finally:
        if threads and any(thread.is_alive() for thread in threads):
            clean_shutdown = _shutdown_servers(servers) and clean_shutdown
            for thread in threads:
                thread.join(timeout=_THREAD_JOIN_TIMEOUT_SECONDS)
            if any(thread.is_alive() for thread in threads):
                clean_shutdown = False
        clean_shutdown = _close_servers(servers) and clean_shutdown
        for signum, previous in previous_handlers.items():
            try:
                signal.signal(signum, previous)
            except (OSError, RuntimeError, ValueError):
                clean_shutdown = False

    if unexpected_exit or not clean_shutdown:
        raise TrustedBrokerServiceError("trusted server group stopped unexpectedly")


def run_trusted_broker_service(
    config_path: str | os.PathLike[str],
    *,
    stop_event: threading.Event | None = None,
    install_signal_handlers: bool = True,
) -> None:
    """Preflight the full runtime before accepting any activated connection."""

    path = Path(config_path)
    config = load_trusted_broker_runtime_config(path)
    runtime = build_trusted_broker_runtime(path)
    if runtime.config.config_fingerprint != config.config_fingerprint:
        raise TrustedBrokerServiceError(
            "trusted runtime configuration changed during startup"
        )
    runtime.verify_integrity()

    descriptors = activated_socket_fds(BROKER_SOCKET_NAMES)
    servers = _construct_activated_servers(runtime, descriptors)
    _serve_servers(
        servers,
        stop_event=stop_event,
        install_signal_handlers=install_signal_handlers,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run with fixed, non-secret diagnostics suitable for the journal."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--help"]:
        print(_USAGE)
        return 0
    if (
        len(arguments) != 2
        or arguments[0] != "--config"
        or not arguments[1]
    ):
        print(_USAGE, file=sys.stderr)
        return 2
    try:
        run_trusted_broker_service(arguments[1])
    except BaseException:
        print(_STARTUP_FAILURE, file=sys.stderr)
        return 1
    return 0


__all__ = [
    "TrustedBrokerServiceError",
    "main",
    "run_trusted_broker_service",
]


if __name__ == "__main__":  # pragma: no cover - console-script equivalent
    raise SystemExit(main())

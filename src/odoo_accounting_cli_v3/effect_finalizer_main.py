"""Fail-closed entry point for the dedicated effect-finalizer service."""

from __future__ import annotations

import os
import queue
import signal
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from .effect_finalizer_runtime import (
    EffectFinalizerRuntimeConfig,
    load_effect_finalizer_runtime_config,
    load_effect_finalizer_runtime_secrets,
)
from .effect_finalizer_service import (
    EffectFinalizerAttemptJournal,
    EffectFinalizerService,
)
from .effect_finalizer_uds import create_effect_finalizer_uds_server_from_fd
from .odoo.effect_finalizer_db import (
    finalize_effect_attempt,
    odoo_connection_info_for,
    open_direct_finalizer_connection,
)
from .systemd_activation import activated_socket_fds


EFFECT_FINALIZER_SOCKET_NAME = "odoo-v3-effect-finalizer"
_USAGE = "usage: odoo-accounting-cli-v3-effect-finalizer --config ABSOLUTE_PATH"
_STARTUP_FAILURE = "effect finalizer service failed closed"


class EffectFinalizerMainError(RuntimeError):
    """The finalizer service could not safely enter or leave serving state."""


@dataclass(frozen=True)
class EffectFinalizerApplication:
    config: EffectFinalizerRuntimeConfig
    service: EffectFinalizerService


def _default_connect(**parameters: Any) -> Any:
    try:
        import psycopg2

        return psycopg2.connect(**parameters)
    except Exception as exc:
        raise EffectFinalizerMainError(
            "finalizer PostgreSQL driver is unavailable"
        ) from exc


def build_effect_finalizer_application(
    config_path: str | os.PathLike[str],
    *,
    require_root_owner: bool = True,
    connection_info_loader: Callable[[Path, str], dict[str, Any]] = (
        odoo_connection_info_for
    ),
    connect: Callable[..., Any] = _default_connect,
) -> EffectFinalizerApplication:
    """Load finalizer-only credentials and construct the durable service."""

    if not callable(connection_info_loader) or not callable(connect):
        raise EffectFinalizerMainError("finalizer database adapters are invalid")
    config = load_effect_finalizer_runtime_config(
        config_path, require_root_owner=require_root_owner
    )
    if os.name == "posix" and require_root_owner and (
        os.geteuid() != config.service_uid
        or os.getegid() != config.service_gid
        or config.service_uid == 0
    ):
        raise EffectFinalizerMainError(
            "finalizer process identity differs from configuration"
        )
    secrets = load_effect_finalizer_runtime_secrets(config)
    journal = EffectFinalizerAttemptJournal(
        config.journal_path,
        require_posix_owner=require_root_owner,
    )

    def database_finalize(request: Any, attestation: Any) -> Any:
        connection_info = connection_info_loader(
            config.odoo_config_path, config.database.database_name
        )
        connection = open_direct_finalizer_connection(
            odoo_connection_info=connection_info,
            config=config.database,
            connect=connect,
        )
        try:
            return finalize_effect_attempt(
                connection,
                config=config.database,
                request=request,
                attestation=attestation,
                now=lambda: datetime.now(timezone.utc),
            )
        finally:
            try:
                connection.close()
            except Exception:
                pass

    service = EffectFinalizerService(
        journal=journal,
        database_finalize=database_finalize,
        key_id=config.attestation_key_id,
        secret=secrets.attestation_secret,
        now=lambda: datetime.now(timezone.utc),
        proof_ttl_seconds=config.proof_ttl_seconds,
    )
    return EffectFinalizerApplication(config=config, service=service)


def _serve(
    server: Any,
    *,
    stop_event: threading.Event,
    install_signal_handlers: bool,
) -> None:
    results: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)
    previous_handlers: dict[signal.Signals, Any] = {}

    def request_shutdown(_signum: int, _frame: object) -> None:
        stop_event.set()

    if install_signal_handlers:
        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, request_shutdown)
        except (OSError, RuntimeError, ValueError) as exc:
            raise EffectFinalizerMainError(
                "finalizer signal handlers could not be installed"
            ) from exc

    def worker() -> None:
        try:
            server.serve_forever(poll_interval=0.2)
        except BaseException as exc:
            results.put(exc)
        else:
            results.put(None)

    thread = threading.Thread(
        target=worker,
        name="effect-finalizer-transport",
        daemon=True,
    )
    clean = True
    unexpected = False
    try:
        thread.start()
        while not stop_event.wait(0.2):
            if not results.empty():
                unexpected = True
                break
    finally:
        try:
            server.shutdown()
        except Exception:
            clean = False
        thread.join(timeout=5)
        if thread.is_alive():
            clean = False
        try:
            server.server_close()
        except Exception:
            clean = False
        for signum, previous in previous_handlers.items():
            try:
                signal.signal(signum, previous)
            except (OSError, RuntimeError, ValueError):
                clean = False
    if unexpected or not clean:
        raise EffectFinalizerMainError(
            "effect finalizer transport stopped unexpectedly"
        )


def run_effect_finalizer_service(
    config_path: str | os.PathLike[str],
    *,
    stop_event: threading.Event | None = None,
    install_signal_handlers: bool = True,
) -> None:
    """Preflight identity/config/credentials before adopting the systemd FD."""

    if type(install_signal_handlers) is not bool:
        raise EffectFinalizerMainError("finalizer service options are invalid")
    application = build_effect_finalizer_application(config_path)
    observed = load_effect_finalizer_runtime_config(config_path)
    if observed.config_fingerprint != application.config.config_fingerprint:
        raise EffectFinalizerMainError(
            "finalizer runtime configuration changed during startup"
        )
    descriptors = activated_socket_fds((EFFECT_FINALIZER_SOCKET_NAME,))
    descriptor = descriptors[EFFECT_FINALIZER_SOCKET_NAME]
    try:
        server = create_effect_finalizer_uds_server_from_fd(
            application.config,
            application.service,
            descriptor,
        )
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    _serve(
        server,
        stop_event=stop_event or threading.Event(),
        install_signal_handlers=install_signal_handlers,
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--help"]:
        print(_USAGE)
        return 0
    if len(arguments) != 2 or arguments[0] != "--config" or not arguments[1]:
        print(_USAGE, file=sys.stderr)
        return 2
    try:
        run_effect_finalizer_service(arguments[1])
    except BaseException:
        print(_STARTUP_FAILURE, file=sys.stderr)
        return 1
    return 0


__all__ = [
    "EFFECT_FINALIZER_SOCKET_NAME",
    "EffectFinalizerApplication",
    "EffectFinalizerMainError",
    "build_effect_finalizer_application",
    "main",
    "run_effect_finalizer_service",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Fail-closed entry point for the dedicated effect-finalizer service."""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import queue
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from .effect_finalizer_runtime import (
    EffectFinalizerRuntimeConfig,
    load_effect_finalizer_runtime_config,
    preflight_effect_finalizer_runtime_credentials,
)
from .effect_finalizer_service import (
    EffectFinalizerAttemptJournal,
    EffectFinalizerService,
)
from .effect_finalizer_uds import create_effect_finalizer_uds_server_from_fd
from .odoo.effect_finalizer_db import (
    finalize_effect_attempt,
    open_direct_finalizer_connection,
)
from .systemd_activation import activated_socket_fds


EFFECT_FINALIZER_SOCKET_NAME = "odoo-v3-effect-finalizer"
_USAGE = "usage: odoo-accounting-cli-v3-effect-finalizer --config ABSOLUTE_PATH"
_STARTUP_FAILURE = "effect finalizer service failed closed"
_SYSTEM_PYTHON = Path("/usr/bin/python3")
_DEPENDENCY_GATE = Path("deployment/dev27/finalizer_runtime_gate.py")
_MAX_GATE_OUTPUT_BYTES = 4096


class EffectFinalizerMainError(RuntimeError):
    """The finalizer service could not safely enter or leave serving state."""


@dataclass(frozen=True)
class EffectFinalizerApplication:
    config: EffectFinalizerRuntimeConfig
    service: EffectFinalizerService


def _verified_postgresql_connect(
    config: EffectFinalizerRuntimeConfig,
) -> Callable[..., Any]:
    """Eagerly retain the exact driver before any finalizer secret is read."""

    try:
        if (
            sys.flags.isolated != 1
            or sys.flags.dont_write_bytecode != 1
            or sys.flags.utf8_mode != 1
            or not sys.dont_write_bytecode
            or os.environ.get("LD_BIND_NOW") != "1"
            or importlib.util.find_spec("odoo") is not None
        ):
            raise EffectFinalizerMainError(
                "finalizer Python isolation is unavailable"
            )
        interpreter = Path(sys.executable).resolve(strict=True)
        if interpreter != _SYSTEM_PYTHON.resolve(strict=True):
            raise EffectFinalizerMainError(
                "finalizer Python interpreter identity differs"
            )
        psycopg2 = importlib.import_module("psycopg2")
        native = importlib.import_module("psycopg2._psycopg")
        actual_paths = {
            str(Path(module.__file__).resolve(strict=True))
            for module in (psycopg2, native)
            if isinstance(getattr(module, "__file__", None), str)
        }
        if len(actual_paths) != 2:
            raise EffectFinalizerMainError(
                "finalizer PostgreSQL driver identity is incomplete"
            )
        release_root = Path(__file__).resolve(strict=True).parents[2]
        gate_path = release_root / _DEPENDENCY_GATE
        if gate_path.is_symlink() or not gate_path.is_file():
            raise EffectFinalizerMainError(
                "finalizer dependency gate is unavailable"
            )
        process = subprocess.run(
            [
                str(_SYSTEM_PYTHON),
                "-I",
                "-B",
                "-X",
                "utf8",
                str(gate_path),
                "verify",
                "--interpreter",
                str(_SYSTEM_PYTHON),
                "--manifest",
                str(config.dependency_manifest_path),
                "--expected-manifest-sha256",
                config.dependency_manifest_sha256,
            ],
            cwd="/",
            env={"LD_BIND_NOW": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
            close_fds=True,
        )
        expected_gate_receipt = (
            json.dumps(
                {
                    "manifest_sha256": config.dependency_manifest_sha256,
                    "ok": True,
                },
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if (
            process.returncode != 0
            or process.stderr
            or process.stdout != expected_gate_receipt
            or len(process.stdout) > _MAX_GATE_OUTPUT_BYTES
        ):
            raise EffectFinalizerMainError(
                "finalizer dependency gate rejected the runtime"
            )
        manifest = json.loads(
            config.dependency_manifest_path.read_text("utf-8")
        )
        driver_records = manifest["psycopg2_files"]
        module_records = manifest["python_module_files"]
        expected_driver_paths = {
            item["canonical_path"]
            for item in driver_records
            if isinstance(item, dict)
            and isinstance(item.get("canonical_path"), str)
        }
        expected_module_paths = {
            item["canonical_path"]
            for item in module_records
            if isinstance(item, dict)
            and isinstance(item.get("canonical_path"), str)
        }
        expected_finalizer_path = str(Path(__file__).resolve(strict=True))
        expected_source_root = str((release_root / "src").resolve(strict=True))
        if (
            not actual_paths.issubset(expected_driver_paths)
            or not actual_paths.issubset(expected_module_paths)
            or manifest["finalizer_module_file"]["canonical_path"]
            != expected_finalizer_path
            or manifest["source_root"]["canonical_path"]
            != expected_source_root
            or manifest["runtime"]["psycopg2_version"]
            != str(psycopg2.__version__)
            or not callable(psycopg2.connect)
        ):
            raise EffectFinalizerMainError(
                "finalizer PostgreSQL driver differs from the manifest"
            )
        return psycopg2.connect
    except EffectFinalizerMainError:
        raise
    except Exception as exc:
        raise EffectFinalizerMainError(
            "finalizer PostgreSQL runtime is unavailable"
        ) from exc


def build_effect_finalizer_application(
    config_path: str | os.PathLike[str],
    *,
    require_root_owner: bool = True,
    connect: Callable[..., Any] | None = None,
) -> EffectFinalizerApplication:
    """Load finalizer-only credentials and construct the durable service."""

    if connect is not None and not callable(connect):
        raise EffectFinalizerMainError("finalizer database adapters are invalid")
    if require_root_owner and connect is not None:
        raise EffectFinalizerMainError(
            "production finalizer connector cannot be injected"
        )
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
    if connect is None:
        connect = _verified_postgresql_connect(config)
    secrets = preflight_effect_finalizer_runtime_credentials(config)
    journal = EffectFinalizerAttemptJournal(
        config.journal_path,
        require_posix_owner=require_root_owner,
    )

    def database_finalize(request: Any, attestation: Any) -> Any:
        connection = open_direct_finalizer_connection(
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

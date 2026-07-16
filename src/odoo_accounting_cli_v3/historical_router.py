"""Fail-closed routing of durable write actions to their owning V3 release.

This module is deliberately not a Pi-facing option parser.  Its manifest path,
operation store, executable paths, and runtime configuration paths are supplied
only by the root-managed service composition.  A request can select an
operation ID, but never a release, binary, configuration, or state database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .operations import canonical_json
from .persistence import OperationNotFound
from .write_api import WriteApiError, WriteApiRequest, parse_write_api_request


ROUTING_MANIFEST_SCHEMA_VERSION = 1
MAX_ROUTING_MANIFEST_BYTES = 65_536
MAX_ROUTE_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_STDIN_BYTES = 262_144
DEFAULT_MAX_STDOUT_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_STDERR_BYTES = 65_536
DEFAULT_TIMEOUT_SECONDS = 30.0
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MANIFEST_FIELDS = frozenset(
    {"schema_version", "current_release_digest", "routes"}
)
_ROUTE_FIELDS = frozenset(
    {
        "release_digest",
        "registry_digest",
        "executable_path",
        "executable_sha256",
        "runtime_config_path",
        "runtime_config_sha256",
    }
)
_ACTION_COMMANDS = {
    "operation.prepare": "prepare",
    "operation.preview": "preview",
    "operation.approve_execute": "approve-execute",
    "operation.status": "status",
    "operation.result": "result",
    "operation.recover": "recover",
}
_TERMINAL_RESULT_ACTIONS = frozenset(
    {"operation.approve_execute", "operation.result"}
)
_DURABLE_IDEMPOTENT_CREATION_ACTIONS = frozenset(
    {"operation.prepare", "operation.recover"}
)


class HistoricalRouterError(ValueError):
    """Stable error raised before an unverified child result is returned."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "historical_route_rejected",
        odoo_effect: str = "none",
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        if odoo_effect not in {"none", "unknown"}:
            raise ValueError("historical route Odoo effect is invalid")
        self.code = code
        self.message = message
        self.odoo_effect = odoo_effect
        self.retryable = retryable


class HistoricalOperationStore(Protocol):
    """Read-only durable evidence required before release selection."""

    def get_operation(self, operation_id: str) -> Any: ...

    def get_recovery_operation_binding(
        self, recovery_operation_id: str
    ) -> Any: ...


@dataclass(frozen=True)
class HistoricalRoute:
    release_digest: str
    registry_digest: str
    executable_path: Path
    executable_sha256: str
    runtime_config_path: Path
    runtime_config_sha256: str


@dataclass(frozen=True)
class HistoricalRoutingManifest:
    current_release_digest: str
    routes: dict[str, HistoricalRoute]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HistoricalRouterError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise HistoricalRouterError(f"non-finite JSON number is forbidden: {value}")


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except HistoricalRouterError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise HistoricalRouterError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise HistoricalRouterError(f"{label} must be a JSON object")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise HistoricalRouterError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _absolute_path(value: Any, label: str) -> Path:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or len(value) > 4096
    ):
        raise HistoricalRouterError(f"{label} must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise HistoricalRouterError(f"{label} must be an absolute path")
    return path


def _same_path(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(
        os.path.abspath(second)
    )


def _validate_root_managed_ancestors(path: Path) -> None:
    current = path.parent
    while True:
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or current.is_symlink()
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise HistoricalRouterError(
                "historical routing path ancestors must be root-managed"
            )
        if current.parent == current:
            return
        current = current.parent


def _read_trusted_file(
    path: Path,
    label: str,
    *,
    maximum: int,
    require_root_owner: bool,
    executable: bool = False,
) -> tuple[bytes, tuple[int, int]]:
    if not path.is_absolute():
        raise HistoricalRouterError(f"{label} path must be absolute")
    if os.name == "posix" and not hasattr(os, "O_NOFOLLOW"):
        raise HistoricalRouterError(f"{label} requires O_NOFOLLOW support")
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or not _same_path(path.resolve(strict=True), path)
        ):
            raise HistoricalRouterError(
                f"{label} must be a regular canonical non-symlink file"
            )
        if os.name == "posix":
            mode = stat.S_IMODE(before.st_mode)
            if mode & 0o022:
                raise HistoricalRouterError(
                    f"{label} must not be group/world writable"
                )
            if executable and mode & 0o111 == 0:
                raise HistoricalRouterError(f"{label} must be executable")
            if require_root_owner:
                _validate_root_managed_ancestors(path)
                if before.st_uid != 0:
                    raise HistoricalRouterError(f"{label} must be root-owned")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (before.st_dev, before.st_ino)
                or (os.name == "posix" and opened.st_mode & 0o022)
                or (
                    os.name == "posix"
                    and require_root_owner
                    and opened.st_uid != 0
                )
            ):
                raise HistoricalRouterError(
                    f"{label} changed while it was opened"
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65_536, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise HistoricalRouterError(f"{label} exceeds its size limit")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            before_identity != after_identity
            or not stat.S_ISREG(after.st_mode)
            or path.is_symlink()
        ):
            raise HistoricalRouterError(f"{label} changed while it was read")
        return b"".join(chunks), (before.st_dev, before.st_ino)
    except HistoricalRouterError:
        raise
    except OSError as exc:
        raise HistoricalRouterError(f"{label} cannot be verified") from exc


def _verified_route_file(
    path: Path,
    expected_digest: str,
    label: str,
    *,
    require_root_owner: bool,
    executable: bool = False,
) -> tuple[int, int]:
    raw, identity = _read_trusted_file(
        path,
        label,
        maximum=MAX_ROUTE_FILE_BYTES,
        require_root_owner=require_root_owner,
        executable=executable,
    )
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, expected_digest):
        raise HistoricalRouterError(f"{label} digest does not match")
    return identity


def _open_verified_route_descriptor(
    path: Path,
    expected_digest: str,
    label: str,
    *,
    expected_identity: tuple[int, int],
) -> int:
    """Open the already-verified route file as an inherited capability."""

    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or (before.st_dev, before.st_ino) != expected_identity
        ):
            raise HistoricalRouterError(f"{label} changed before child handoff")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != expected_identity
        ):
            raise HistoricalRouterError(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor, min(65_536, MAX_ROUTE_FILE_BYTES + 1 - total)
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ROUTE_FILE_BYTES:
                raise HistoricalRouterError(f"{label} exceeds its size limit")
            chunks.append(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        after = path.lstat()
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            before_identity != after_identity
            or not stat.S_ISREG(after.st_mode)
            or path.is_symlink()
            or not hmac.compare_digest(
                hashlib.sha256(b"".join(chunks)).hexdigest(), expected_digest
            )
        ):
            raise HistoricalRouterError(f"{label} changed during child handoff")
        return descriptor
    except HistoricalRouterError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise HistoricalRouterError(f"{label} cannot be handed to child") from exc


def _route_from_mapping(
    value: Any, *, require_root_owner: bool
) -> tuple[HistoricalRoute, tuple[int, int], tuple[int, int]]:
    if not isinstance(value, Mapping) or set(value) != _ROUTE_FIELDS:
        raise HistoricalRouterError("historical route fields are invalid")
    release_digest = _digest(value["release_digest"], "route release_digest")
    registry_digest = _digest(value["registry_digest"], "route registry_digest")
    executable_path = _absolute_path(value["executable_path"], "executable_path")
    runtime_config_path = _absolute_path(
        value["runtime_config_path"], "runtime_config_path"
    )
    executable_sha256 = _digest(
        value["executable_sha256"], "executable_sha256"
    )
    runtime_config_sha256 = _digest(
        value["runtime_config_sha256"], "runtime_config_sha256"
    )
    if _same_path(executable_path, runtime_config_path):
        raise HistoricalRouterError(
            "historical executable and runtime configuration must be distinct"
        )
    executable_identity = _verified_route_file(
        executable_path,
        executable_sha256,
        "historical route executable",
        require_root_owner=require_root_owner,
        executable=True,
    )
    runtime_identity = _verified_route_file(
        runtime_config_path,
        runtime_config_sha256,
        "historical route runtime configuration",
        require_root_owner=require_root_owner,
    )
    return (
        HistoricalRoute(
            release_digest=release_digest,
            registry_digest=registry_digest,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
            runtime_config_path=runtime_config_path,
            runtime_config_sha256=runtime_config_sha256,
        ),
        executable_identity,
        runtime_identity,
    )


def load_historical_routing_manifest(
    path: Path, *, require_root_owner: bool = True
) -> HistoricalRoutingManifest:
    """Load and verify one complete root-managed routing snapshot."""

    raw, _identity = _read_trusted_file(
        path,
        "historical routing manifest",
        maximum=MAX_ROUTING_MANIFEST_BYTES,
        require_root_owner=require_root_owner,
    )
    document = _json_object(raw, "historical routing manifest")
    if set(document) != _MANIFEST_FIELDS:
        raise HistoricalRouterError("historical routing manifest fields are invalid")
    if document["schema_version"] != ROUTING_MANIFEST_SCHEMA_VERSION:
        raise HistoricalRouterError("historical routing manifest schema is unsupported")
    current = _digest(
        document["current_release_digest"], "current_release_digest"
    )
    raw_routes = document["routes"]
    if not isinstance(raw_routes, list) or not raw_routes or len(raw_routes) > 64:
        raise HistoricalRouterError("historical routes must be a non-empty array")
    routes: dict[str, HistoricalRoute] = {}
    paths: set[str] = set()
    inodes: set[tuple[int, int]] = set()
    for raw_route in raw_routes:
        route, executable_identity, runtime_identity = _route_from_mapping(
            raw_route, require_root_owner=require_root_owner
        )
        if route.release_digest in routes:
            raise HistoricalRouterError("historical route release is duplicated")
        route_paths = {
            os.path.normcase(os.path.abspath(route.executable_path)),
            os.path.normcase(os.path.abspath(route.runtime_config_path)),
        }
        route_inodes = {executable_identity, runtime_identity}
        if (
            len(route_paths) != 2
            or len(route_inodes) != 2
            or route_paths & paths
            or route_inodes & inodes
        ):
            raise HistoricalRouterError(
                "historical route files must be release-unique"
            )
        paths.update(route_paths)
        inodes.update(route_inodes)
        routes[route.release_digest] = route
    if current not in routes:
        raise HistoricalRouterError("current historical route is missing")
    return HistoricalRoutingManifest(current_release_digest=current, routes=routes)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:  # pragma: no cover - production is POSIX.
            process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL is final.
        process.kill()
        process.wait(timeout=5)


def _run_bounded_child(
    argv: list[str],
    *,
    stdin: bytes,
    env: dict[str, str],
    timeout_seconds: float,
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    """Run a fixed child with bounded nonblocking pipes and group cleanup."""

    if os.name != "posix":  # pragma: no cover - local tests inject this boundary.
        raise HistoricalRouterError(
            "historical release execution requires a POSIX service runtime"
        )
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            cwd="/",
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HistoricalRouterError(
            "historical child process could not be started",
            code="historical_child_unavailable",
            retryable=True,
        ) from exc
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    stdin_offset = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise HistoricalRouterError("historical child pipes are unavailable")
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HistoricalRouterError(
                    "historical child process timed out",
                    code="historical_child_timeout",
                    retryable=True,
                )
            for key, _event in selector.select(timeout=min(remaining, 0.1)):
                label = key.data
                stream = key.fileobj
                if label == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(), stdin[stdin_offset : stdin_offset + 65_536]
                        )
                        stdin_offset += written
                    except (BrokenPipeError, OSError):
                        stdin_offset = len(stdin)
                    if stdin_offset >= len(stdin):
                        selector.unregister(stream)
                        stream.close()
                    continue
                buffer = stdout if label == "stdout" else stderr
                maximum = (
                    max_stdout_bytes if label == "stdout" else max_stderr_bytes
                )
                try:
                    chunk = os.read(
                        stream.fileno(), min(65_536, maximum + 1 - len(buffer))
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                buffer.extend(chunk)
                if len(buffer) > maximum:
                    raise HistoricalRouterError(
                        f"historical child {label} exceeded its size limit",
                        code="historical_child_output_limit",
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HistoricalRouterError(
                "historical child process timed out",
                code="historical_child_timeout",
                retryable=True,
            )
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise HistoricalRouterError(
                "historical child process timed out",
                code="historical_child_timeout",
                retryable=True,
            ) from exc
        return subprocess.CompletedProcess(
            argv, returncode, stdout=bytes(stdout), stderr=bytes(stderr)
        )
    except BaseException:
        _kill_process_group(process)
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _operation_context_matches(operation: Any, parsed: WriteApiRequest) -> bool:
    context = parsed.context
    return (
        operation.principal == context.principal
        and operation.user_id == context.user_id
        and operation.company_id == context.company_id
        and operation.odoo_instance_id == context.odoo_instance_id
        and operation.database_name == context.database_name
        and operation.database_uuid == context.database_uuid
        and operation.environment == context.environment
    )


class HistoricalReleaseRouter:
    """Resolve, execute, and re-verify one write action's immutable release."""

    def __init__(
        self,
        manifest_path: str | os.PathLike[str],
        operation_store: HistoricalOperationStore,
        *,
        require_root_owner: bool = True,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_stdin_bytes: int = DEFAULT_MAX_STDIN_BYTES,
        max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
        max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
        pinned_manifest: HistoricalRoutingManifest | None = None,
    ) -> None:
        path = Path(manifest_path)
        if not path.is_absolute():
            raise HistoricalRouterError("historical routing manifest path must be absolute")
        if operation_store is None:
            raise HistoricalRouterError("durable operation store is required")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= 120
        ):
            raise HistoricalRouterError("historical child timeout is invalid")
        for value, label, ceiling in (
            (max_stdin_bytes, "stdin", 4 * 1024 * 1024),
            (max_stdout_bytes, "stdout", 16 * 1024 * 1024),
            (max_stderr_bytes, "stderr", 1024 * 1024),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > ceiling
            ):
                raise HistoricalRouterError(
                    f"historical child {label} size limit is invalid"
                )
        self._manifest_path = path
        self._store = operation_store
        self._require_root_owner = require_root_owner
        self._timeout_seconds = float(timeout_seconds)
        self._max_stdin_bytes = max_stdin_bytes
        self._max_stdout_bytes = max_stdout_bytes
        self._max_stderr_bytes = max_stderr_bytes
        if pinned_manifest is not None and type(pinned_manifest) is not HistoricalRoutingManifest:
            raise HistoricalRouterError("pinned historical manifest is invalid")
        self._pinned_manifest_binding = (
            None
            if pinned_manifest is None
            else self._manifest_binding(pinned_manifest)
        )
        if pinned_manifest is not None:
            observed = load_historical_routing_manifest(
                self._manifest_path,
                require_root_owner=self._require_root_owner,
            )
            if self._manifest_binding(observed) != self._pinned_manifest_binding:
                raise HistoricalRouterError(
                    "historical routing manifest differs from the pinned startup snapshot"
                )

    @staticmethod
    def _validated_deadline(deadline_monotonic: float | None) -> float | None:
        if deadline_monotonic is None:
            return None
        if (
            isinstance(deadline_monotonic, bool)
            or not isinstance(deadline_monotonic, (int, float))
            or not math.isfinite(float(deadline_monotonic))
        ):
            raise HistoricalRouterError("historical absolute deadline is invalid")
        return float(deadline_monotonic)

    @staticmethod
    def _deadline_exceeded() -> HistoricalRouterError:
        return HistoricalRouterError(
            "historical request deadline was exceeded",
            code="historical_deadline_exceeded",
            retryable=True,
        )

    def _child_timeout(self, deadline_monotonic: float | None) -> float:
        deadline = self._validated_deadline(deadline_monotonic)
        if deadline is None:
            return self._timeout_seconds
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise self._deadline_exceeded()
        return min(self._timeout_seconds, remaining)

    def _assert_deadline(self, deadline_monotonic: float | None) -> None:
        deadline = self._validated_deadline(deadline_monotonic)
        if deadline is not None and time.monotonic() >= deadline:
            raise self._deadline_exceeded()

    @staticmethod
    def _manifest_binding(manifest: HistoricalRoutingManifest) -> tuple[Any, ...]:
        return (
            manifest.current_release_digest,
            tuple(
                (
                    release_digest,
                    route.registry_digest,
                    str(route.executable_path),
                    route.executable_sha256,
                    str(route.runtime_config_path),
                    route.runtime_config_sha256,
                )
                for release_digest, route in sorted(manifest.routes.items())
            ),
        )

    def _manifest(self) -> HistoricalRoutingManifest:
        observed = load_historical_routing_manifest(
            self._manifest_path,
            require_root_owner=self._require_root_owner,
        )
        if (
            self._pinned_manifest_binding is not None
            and self._manifest_binding(observed) != self._pinned_manifest_binding
        ):
            raise HistoricalRouterError(
                "historical routing manifest changed after startup"
            )
        return observed

    @staticmethod
    def _route_for_operation(
        operation: Any, manifest: HistoricalRoutingManifest
    ) -> HistoricalRoute:
        try:
            release_digest = _digest(
                operation.release_digest, "stored operation release_digest"
            )
            registry_digest = _digest(
                operation.registry_digest, "stored operation registry_digest"
            )
        except AttributeError as exc:
            raise HistoricalRouterError(
                "durable operation route is incomplete"
            ) from exc
        route = manifest.routes.get(release_digest)
        if route is None:
            raise HistoricalRouterError(
                "durable operation release has no retained historical route"
            )
        if not hmac.compare_digest(registry_digest, route.registry_digest):
            raise HistoricalRouterError(
                "durable operation registry binding does not match its route"
            )
        return route

    def _operation(self, operation_id: str) -> Any:
        try:
            operation = self._store.get_operation(operation_id)
            assert_integrity = getattr(operation, "assert_integrity", None)
            if callable(assert_integrity):
                assert_integrity()
            if operation.operation_id != operation_id:
                raise HistoricalRouterError(
                    "durable operation route identifier is invalid"
                )
            return operation
        except HistoricalRouterError:
            raise
        except OperationNotFound as exc:
            raise HistoricalRouterError(
                "durable operation route does not exist"
            ) from exc
        except Exception as exc:
            raise HistoricalRouterError(
                "durable operation route could not be verified"
            ) from exc

    def _optional_operation(self, operation_id: str) -> Any | None:
        try:
            return self._store.get_operation(operation_id)
        except OperationNotFound:
            return None
        except Exception as exc:
            raise HistoricalRouterError(
                "durable operation route could not be verified"
            ) from exc

    def _optional_recovery_binding(self, recovery_operation_id: str) -> Any | None:
        try:
            return self._store.get_recovery_operation_binding(
                recovery_operation_id
            )
        except OperationNotFound:
            return None
        except Exception as exc:
            raise HistoricalRouterError(
                "durable recovery binding could not be verified"
            ) from exc

    @staticmethod
    def _assert_context(operation: Any, parsed: WriteApiRequest) -> None:
        if not _operation_context_matches(operation, parsed):
            raise HistoricalRouterError(
                "durable operation route is outside the authenticated context"
            )

    @classmethod
    def _assert_existing_prepare_request(
        cls, operation: Any, parsed: WriteApiRequest
    ) -> None:
        """Bind a pre-existing prepare ID to the complete signed request."""

        cls._assert_context(operation, parsed)
        payload = parsed.payload
        try:
            parameters = operation.parameters
            parameters_match = hmac.compare_digest(
                canonical_json(parameters), canonical_json(payload["parameters"])
            )
            valid = (
                operation.operation_id == payload["operation_id"]
                and operation.request_id == payload["request_id"]
                and operation.capability_id == payload["capability_id"]
                and parameters_match
                and isinstance(parameters.get("idempotency_key"), str)
                and operation.idempotency_key == parameters["idempotency_key"]
            )
        except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
            valid = False
        if not valid:
            raise HistoricalRouterError(
                "durable prepare idempotency binding is invalid"
            )

    @staticmethod
    def _assert_recovery_binding(
        binding: Any,
        *,
        origin: Any,
        recovery: Any,
        route: HistoricalRoute,
    ) -> None:
        try:
            valid = (
                binding.origin_operation_id == origin.operation_id
                and binding.recovery_operation_id == recovery.operation_id
                and binding.origin_operation_revision == origin.revision
                and binding.release_digest == route.release_digest
                and binding.registry_digest == route.registry_digest
                and recovery.release_digest == route.release_digest
                and recovery.registry_digest == route.registry_digest
            )
        except AttributeError as exc:
            raise HistoricalRouterError("durable recovery binding is incomplete") from exc
        if not valid:
            raise HistoricalRouterError("durable recovery binding mismatch")

    def _resolve_route(
        self,
        parsed: WriteApiRequest,
        manifest: HistoricalRoutingManifest,
    ) -> tuple[HistoricalRoute, Any | None]:
        payload = parsed.payload
        if parsed.action == "operation.prepare":
            existing = self._optional_operation(payload["operation_id"])
            if existing is None:
                return manifest.routes[manifest.current_release_digest], None
            operation = self._operation(payload["operation_id"])
            self._assert_existing_prepare_request(operation, parsed)
            return self._route_for_operation(operation, manifest), operation
        if parsed.action != "operation.recover":
            operation = self._operation(payload["operation_id"])
            self._assert_context(operation, parsed)
            return self._route_for_operation(operation, manifest), operation

        origin_id = payload["origin_operation_id"]
        recovery_id = payload["recovery_operation_id"]
        if origin_id == recovery_id:
            raise HistoricalRouterError(
                "origin and recovery operation identifiers must be distinct"
            )
        origin = self._operation(origin_id)
        self._assert_context(origin, parsed)
        if origin.revision != payload["expected_origin_revision"]:
            raise HistoricalRouterError("durable origin operation revision changed")
        route = self._route_for_operation(origin, manifest)
        binding = self._optional_recovery_binding(recovery_id)
        recovery = self._optional_operation(recovery_id)
        if binding is None:
            if recovery is not None:
                raise HistoricalRouterError(
                    "durable store contains an unbound recovery operation"
                )
            return route, origin
        if recovery is None:
            raise HistoricalRouterError(
                "durable recovery binding has no recovery operation"
            )
        self._assert_context(recovery, parsed)
        self._assert_recovery_binding(
            binding, origin=origin, recovery=recovery, route=route
        )
        return route, origin

    @staticmethod
    def _child_environment(
        route: HistoricalRoute, runtime_config_descriptor: int
    ) -> dict[str, str]:
        return {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "ODOO_ACCOUNTING_CLI_V3_EXPECTED_REGISTRY_DIGEST": route.registry_digest,
            "ODOO_ACCOUNTING_CLI_V3_EXPECTED_RELEASE_DIGEST": route.release_digest,
            "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG": str(
                route.runtime_config_path
            ),
            "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_SHA256": (
                route.runtime_config_sha256
            ),
            "ODOO_ACCOUNTING_CLI_V3_TRUSTED_WRITE_RUNTIME_CONFIG_FD": str(
                runtime_config_descriptor
            ),
        }

    def _parse_child_response(
        self,
        completed: subprocess.CompletedProcess[bytes],
        *,
        action: str,
        operation_id: str,
        origin_operation_id: str | None,
        route: HistoricalRoute,
    ) -> dict[str, Any]:
        stdout = completed.stdout
        stderr = completed.stderr
        if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
            raise HistoricalRouterError("historical child output type is invalid")
        if completed.returncode != 0:
            raise HistoricalRouterError(
                "historical child process failed without a verified response",
                code="historical_child_failed",
            )
        if len(stdout) > self._max_stdout_bytes:
            raise HistoricalRouterError(
                "historical child stdout size limit was exceeded"
            )
        if len(stderr) > self._max_stderr_bytes:
            raise HistoricalRouterError(
                "historical child stderr size limit was exceeded"
            )
        if stderr:
            raise HistoricalRouterError(
                "historical child emitted unverified stderr on success"
            )
        try:
            response = _json_object(stdout, "historical child stdout")
        except HistoricalRouterError as exc:
            raise HistoricalRouterError(
                "historical child stdout is not valid JSON"
            ) from exc
        expected_fields = {"command", "data", "ok"}
        if action in _TERMINAL_RESULT_ACTIONS:
            expected_fields.add("business_succeeded")
        if (
            set(response) != expected_fields
            or response.get("ok") is not True
            or response.get("command") != action
            or not isinstance(response.get("data"), dict)
            or (
                action in _TERMINAL_RESULT_ACTIONS
                and type(response.get("business_succeeded")) is not bool
            )
        ):
            raise HistoricalRouterError("historical child response fields are invalid")
        data = response["data"]
        returned_operation_id = data.get("operation_id")
        if (
            not isinstance(returned_operation_id, str)
            or not returned_operation_id.strip()
            or len(returned_operation_id) > 512
            or (
                action not in {"operation.prepare", "operation.recover"}
                and returned_operation_id != operation_id
            )
        ):
            raise HistoricalRouterError(
                "historical child response operation binding is invalid"
            )
        if (
            action == "operation.recover"
            and data.get("origin_operation_id")
            != origin_operation_id
        ):
            raise HistoricalRouterError(
                "historical child response origin binding is invalid"
            )
        if action in {
            "operation.prepare",
            "operation.status",
            "operation.recover",
        }:
            identity = data.get("operation")
        elif action == "operation.preview":
            identity = data.get("precheck_identity")
        else:
            identity = data.get("audit_receipt")
        if (
            not isinstance(identity, dict)
            or identity.get("release_digest") != route.release_digest
            or identity.get("registry_digest") != route.registry_digest
            or identity.get("operation_id") != returned_operation_id
        ):
            raise HistoricalRouterError(
                "historical child response identity does not match its route"
            )
        return response

    def _verify_post_dispatch(
        self,
        *,
        parsed: WriteApiRequest,
        route: HistoricalRoute,
        response: dict[str, Any],
    ) -> None:
        payload = parsed.payload
        returned_operation_id = response["data"]["operation_id"]
        if parsed.action == "operation.recover":
            origin = self._operation(payload["origin_operation_id"])
            recovery = self._operation(returned_operation_id)
            binding = self._optional_recovery_binding(recovery.operation_id)
            if binding is None:
                raise HistoricalRouterError(
                    "historical recover did not persist a trusted recovery binding"
                )
            self._assert_context(origin, parsed)
            self._assert_context(recovery, parsed)
            self._assert_recovery_binding(
                binding, origin=origin, recovery=recovery, route=route
            )
            if returned_operation_id != payload["recovery_operation_id"]:
                parameters = getattr(recovery, "parameters", None)
                if (
                    self._optional_operation(payload["recovery_operation_id"])
                    is not None
                    or self._optional_recovery_binding(
                        payload["recovery_operation_id"]
                    )
                    is not None
                    or getattr(recovery, "capability_id", None)
                    != "acct.recovery.execute.v1"
                    or not isinstance(parameters, dict)
                    or set(parameters)
                    != {
                        "company_id",
                        "expected_recovery_plan_digest",
                        "idempotency_key",
                        "origin_operation_id",
                        "reason",
                        "recovery_date",
                    }
                    or parameters.get("company_id") != parsed.context.company_id
                    or parameters.get("origin_operation_id")
                    != payload["origin_operation_id"]
                    or parameters.get("recovery_date") != payload["recovery_date"]
                    or parameters.get("reason") != payload["reason"]
                    or parameters.get("idempotency_key")
                    != payload["idempotency_key"]
                    or getattr(recovery, "idempotency_key", None)
                    != payload["idempotency_key"]
                    or not _digest(
                        parameters.get("expected_recovery_plan_digest"),
                        "durable recovery plan digest",
                    )
                ):
                    raise HistoricalRouterError(
                        "historical recovery idempotency binding is invalid"
                    )
            return
        operation = self._operation(returned_operation_id)
        self._assert_context(operation, parsed)
        observed = self._route_for_operation(
            operation,
            HistoricalRoutingManifest(
                current_release_digest=route.release_digest,
                routes={route.release_digest: route},
            ),
        )
        if observed != route:
            raise HistoricalRouterError(
                "durable operation route changed during child execution"
            )
        if parsed.action == "operation.prepare" and returned_operation_id == payload[
            "operation_id"
        ]:
            self._assert_existing_prepare_request(operation, parsed)
        elif parsed.action == "operation.prepare":
            parameters = getattr(operation, "parameters", None)
            if (
                self._optional_operation(payload["operation_id"]) is not None
                or getattr(operation, "capability_id", None)
                != payload["capability_id"]
                or not isinstance(parameters, dict)
                or parameters != payload["parameters"]
                or not isinstance(parameters.get("idempotency_key"), str)
                or getattr(operation, "idempotency_key", None)
                != parameters["idempotency_key"]
            ):
                raise HistoricalRouterError(
                    "historical prepare idempotency binding is invalid"
                )

    def dispatch(
        self,
        action: str,
        request: Mapping[str, Any],
        *,
        deadline_monotonic: float | None = None,
    ) -> dict[str, Any]:
        """Dispatch one exact write request without accepting route controls."""

        try:
            # Detach exactly once before parsing.  The same canonical bytes are
            # sent to the child, so routing never drops or rewrites a signed
            # date, company, supplier, currency, or other request field.
            request_bytes = canonical_json(dict(request))
            detached_request = json.loads(request_bytes)
            parsed = parse_write_api_request(action, detached_request)
        except (WriteApiError, TypeError, ValueError, UnicodeError) as exc:
            raise HistoricalRouterError(
                "write request contract is invalid for historical routing"
            ) from exc
        if not request_bytes or len(request_bytes) > self._max_stdin_bytes:
            raise HistoricalRouterError(
                "historical child stdin size limit was exceeded"
            )
        manifest = self._manifest()
        route, _operation = self._resolve_route(parsed, manifest)
        # Re-hash the selected targets immediately before spawn.  This also
        # detects a route target changed after the complete manifest snapshot.
        _verified_route_file(
            route.executable_path,
            route.executable_sha256,
            "historical route executable",
            require_root_owner=self._require_root_owner,
            executable=True,
        )
        runtime_config_identity = _verified_route_file(
            route.runtime_config_path,
            route.runtime_config_sha256,
            "historical route runtime configuration",
            require_root_owner=self._require_root_owner,
        )
        runtime_config_descriptor = _open_verified_route_descriptor(
            route.runtime_config_path,
            route.runtime_config_sha256,
            "historical route runtime configuration",
            expected_identity=runtime_config_identity,
        )
        operation_id = (
            parsed.payload["recovery_operation_id"]
            if action == "operation.recover"
            else parsed.payload["operation_id"]
        )
        argv = [
            str(route.executable_path),
            "operation",
            _ACTION_COMMANDS[action],
        ]
        child_invoked = False
        try:
            child_timeout = self._child_timeout(deadline_monotonic)
            child_invoked = True
            completed = _run_bounded_child(
                argv,
                stdin=request_bytes,
                env=self._child_environment(route, runtime_config_descriptor),
                timeout_seconds=child_timeout,
                max_stdout_bytes=self._max_stdout_bytes,
                max_stderr_bytes=self._max_stderr_bytes,
                pass_fds=(runtime_config_descriptor,),
            )
            self._assert_deadline(deadline_monotonic)
            response = self._parse_child_response(
                completed,
                action=action,
                operation_id=operation_id,
                origin_operation_id=(
                    parsed.payload["origin_operation_id"]
                    if action == "operation.recover"
                    else None
                ),
                route=route,
            )
            self._verify_post_dispatch(
                parsed=parsed, route=route, response=response
            )
            _verified_route_file(
                route.executable_path,
                route.executable_sha256,
                "historical route executable",
                require_root_owner=self._require_root_owner,
                executable=True,
            )
            _verified_route_file(
                route.runtime_config_path,
                route.runtime_config_sha256,
                "historical route runtime configuration",
                require_root_owner=self._require_root_owner,
            )
            self._assert_deadline(deadline_monotonic)
            return response
        except HistoricalRouterError as exc:
            if action in _DURABLE_IDEMPOTENT_CREATION_ACTIONS:
                # These child actions only persist an idempotently bound
                # operation plan; they never apply the plan to Odoo.  Once
                # dispatch has reached the child boundary, an unverified
                # response can therefore be retried with a provable no-Odoo
                # effect even if the first child committed its durable row.
                if exc.retryable and exc.odoo_effect == "none":
                    raise
                raise HistoricalRouterError(
                    exc.message,
                    code=exc.code,
                    odoo_effect="none",
                    retryable=True,
                ) from exc
            if (
                action != "operation.approve_execute"
                or exc.odoo_effect == "unknown"
                or not child_invoked
            ):
                raise
            raise HistoricalRouterError(
                exc.message,
                code=exc.code,
                odoo_effect="unknown",
                retryable=True,
            ) from exc
        finally:
            os.close(runtime_config_descriptor)


__all__ = [
    "HistoricalOperationStore",
    "HistoricalReleaseRouter",
    "HistoricalRoute",
    "HistoricalRouterError",
    "HistoricalRoutingManifest",
    "load_historical_routing_manifest",
]

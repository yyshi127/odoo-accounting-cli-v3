#!/usr/bin/python3 -I
"""Fail-closed runtime file-open attestation for the Dev29 direct children.

This module deliberately does not discover an allow-list from a traced child.
The root supervisor loads one digest-pinned, root-owned manifest and uses the
API below to build the only permitted ``/usr/bin/strace`` command.  Raw trace
bytes remain in a private staging directory; the publishable result contains
only the canonical path-set digest/count and the raw-trace digest.

The scope is one already-approved direct child, from its bootstrap ``execve``
through the final fixed command.  It does not claim coverage of the suite root
supervisor or an out-of-process evidence verifier and therefore cannot, by
itself, make a release production-promotable.
"""

from __future__ import annotations

import ast
import ctypes
import hashlib
import json
import os
import posixpath
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


STRACE_COMMAND = "/usr/bin/strace"
STRACE_PATH = Path(STRACE_COMMAND)
SYSTEM_PYTHON_COMMAND = "/usr/bin/python3.12"
MANIFEST_PARENT = Path("/opt/odoo-accounting-cli-v3/runtime-open-manifests")
STAGING_PARENT = Path("/var/lib/odoo-accounting-cli-v3/runtime-open-trace")
PRIVATE_EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence-private")
SEAL_JOURNAL_NAME = "seal.json"
SEAL_SIDECAR_SUFFIX = ".seal.json"
RENAME_NOREPLACE = 1
SCOPE = "direct-child-bootstrap-through-final-exec-v1"
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_TRACE_BYTES = 128 * 1024 * 1024
MAX_TRACE_LINES = 1_000_000
MAX_LINE_BYTES = 1024 * 1024
MAX_PATHS = 200_000
MAX_ARGV_ITEMS = 4096
MAX_ARG_BYTES = 64 * 1024
MAX_WATCH_ENTRIES = 250_000
MAX_WATCH_FILE_BYTES = 512 * 1024 * 1024
MAX_MOUNTINFO_BYTES = 16 * 1024 * 1024
DYNAMIC_BOOTSTRAP_OPTIONS = (
    ("--expected-self-namespace-device", "@DEV29_SELF_NAMESPACE_DEVICE@"),
    ("--expected-self-namespace-inode", "@DEV29_SELF_NAMESPACE_INODE@"),
    ("--expected-host-namespace-device", "@DEV29_HOST_NAMESPACE_DEVICE@"),
    ("--expected-host-namespace-inode", "@DEV29_HOST_NAMESPACE_INODE@"),
    ("--expected-loop-device", "@DEV29_LOOP_DEVICE@"),
)
DYNAMIC_MOUNT_ARGUMENTS = tuple(
    f"@DEV29_MOUNT_JSON_{index}@" for index in range(5)
)
_DYNAMIC_BOOTSTRAP_MARKERS = frozenset(
    marker
    for _option, marker in DYNAMIC_BOOTSTRAP_OPTIONS
) | frozenset(DYNAMIC_MOUNT_ARGUMENTS)
VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER = "@DEV29_BUNDLE_MANIFEST_SHA256@"
VERIFIER_EVIDENCE_DIR_MARKER = "@DEV29_EVIDENCE_DIR@"
VERIFIER_EVIDENCE_PARENT = "/var/lib/odoo-accounting-cli-v3/evidence"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
PID_PREFIX = re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))\s+")
SYSCALL_NAME = re.compile(r"^([a-z][a-z0-9_]*)\(")

# ``%file`` is the kernel/strace-maintained class of path-taking syscalls.  It
# prevents a newly added or architecture-specific path mutation from silently
# falling outside this evidence boundary.  The parser below accepts only the
# explicitly implemented subset and rejects every other member of ``%file``.
TRACE_SYSCALLS = (
    "open",
    "openat",
    "openat2",
    "creat",
    "stat",
    "lstat",
    "newfstatat",
    "statx",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "execve",
    "execveat",
    "socket",
    "connect",
    "bind",
    "sendto",
    "sendmsg",
    "close",
    "dup",
    "dup2",
    "dup3",
    "ftruncate",
    "fchmod",
    "fchown",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "name_to_handle_at",
    "open_by_handle_at",
    "chdir",
    "fchdir",
)
STRACE_OPTIONS = (
    "--follow-forks",
    # Preserve the supervisor -> direct_child parent relationship required by
    # the existing child attestation while the tracer runs as a grandchild.
    "--daemonize=grandchild",
    "--quiet=attach,personality",
    "--decode-fds=path",
    "--abbrev=none",
    "--string-limit=65535",
    "--trace=%file," + ",".join(TRACE_SYSCALLS),
)
PATH_FIRST = frozenset(
    {
        "open",
        "creat",
        "stat",
        "lstat",
        "statfs",
        "access",
        "readlink",
        "execve",
        "unlink",
        "truncate",
    }
)
PATH_AT = frozenset(
    {
        "openat",
        "openat2",
        "newfstatat",
        "statx",
        "faccessat",
        "faccessat2",
        "readlinkat",
        "execveat",
        "unlinkat",
    }
)
OPEN_CALLS = frozenset({"open", "openat", "openat2", "creat"})
EXEC_CALLS = frozenset({"execve", "execveat"})
NETWORK_CALLS = frozenset({"socket", "connect", "bind", "sendto", "sendmsg"})
CWD_CALLS = frozenset({"chdir", "fchdir"})
FD_LIFECYCLE_CALLS = frozenset({"close", "dup", "dup2", "dup3"})
DELETE_CALLS = frozenset({"unlink", "unlinkat"})
TRUNCATE_PATH_CALLS = frozenset({"truncate"})
# These are deliberately traced and refused.  Supporting one later requires a
# path-by-path semantic policy and tests; merely observing it is insufficient.
FORBIDDEN_PATH_MUTATION_CALLS = frozenset(
    {
        "rename",
        "renameat",
        "renameat2",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
        "mkdir",
        "mkdirat",
        "rmdir",
        "mknod",
        "mknodat",
        "chmod",
        "fchmod",
        "fchmodat",
        "fchmodat2",
        "chown",
        "lchown",
        "fchown",
        "fchownat",
        "utime",
        "utimes",
        "futimesat",
        "utimensat",
    }
)
FORBIDDEN_CALLS = frozenset(
    {
        "clone",
        "clone3",
        "fork",
        "vfork",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "name_to_handle_at",
        "open_by_handle_at",
    }
) | FORBIDDEN_PATH_MUTATION_CALLS
SUPPORTED_TRACE_CALLS = (
    PATH_FIRST
    | PATH_AT
    | NETWORK_CALLS
    | CWD_CALLS
    | FD_LIFECYCLE_CALLS
    | frozenset({"ftruncate"})
    | FORBIDDEN_CALLS
)
ACCESS_VALUES = frozenset(
    {
        "read",
        "write",
        "create",
        "truncate",
        "append",
        "delete",
        "metadata",
        "execute",
        "unix-connect",
        "unix-send",
    }
)
IMMUTABLE_ACCESS = frozenset({"read", "metadata", "execute"})
MUTABLE_ACCESS = frozenset(
    {"read", "write", "create", "truncate", "append", "delete", "metadata"}
)
SOCKET_ACCESS = frozenset({"unix-connect", "unix-send"})
PROCESS_VIEW_ACCESS = frozenset({"read", "metadata"})
SQLITE_DELTA_VERIFIER = "dev29-sqlite-state-delta-v1"
WATCH_TREE_FAILURE_GUARD = "dev29-watch-tree-identity-v1"
PROCESS_VIEW_FAILURE_GUARD = "dev29-process-view-identity-v1"
UNIX_SOCKET_FAILURE_GUARD = "dev29-unix-socket-identity-v1"
PRODUCTION_PROMOTION_ALLOWED = False
STAGING_DIRECTORY = re.compile(
    r"^trace-([1-9][0-9]*)-([1-9][0-9]*)-([0-9a-f]{16})$"
)
ROLE_ENVIRONMENTS = {
    "odoo": {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/lib/odoo-accounting-cli-v3-broker",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SETUPTOOLS_USE_DISTUTILS": "stdlib",
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_PYTHON": (
            "/opt/odoo/odoo19/odoo19-venv/bin/python"
        ),
    },
    "signer": {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/lib/odoo-accounting-cli-v3-broker",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SETUPTOOLS_USE_DISTUTILS": "stdlib",
    },
    "postgres": {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/lib/postgresql",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SETUPTOOLS_USE_DISTUTILS": "stdlib",
        "ODOO_ACCOUNTING_CLI_V3_EXPECTED_PYTHON": (
            "/opt/odoo/odoo19/odoo19-venv/bin/python"
        ),
    },
    "verifier": {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "SETUPTOOLS_USE_DISTUTILS": "stdlib",
    },
}
IN_ATTRIB = 0x00000004
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_UNMOUNT = 0x00002000
IN_Q_OVERFLOW = 0x00004000
IN_DONT_FOLLOW = 0x02000000
IN_REJECT_MASK = (
    IN_ATTRIB
    | IN_MODIFY
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_UNMOUNT
    | IN_Q_OVERFLOW
)


class RuntimeOpenTraceError(RuntimeError):
    """A trace, trust anchor, execution identity, or closure check failed."""


def _crash_injection_gate(_point: str) -> None:
    """Test-only crash boundary; production deliberately performs no action."""


def _renameat2_noreplace(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise RuntimeOpenTraceError("renameat2 is unavailable for trace sealing")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            source_directory_fd,
            os.fsencode(source_name),
            destination_directory_fd,
            os.fsencode(destination_name),
            RENAME_NOREPLACE,
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _descriptor_digest(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise RuntimeOpenTraceError("private trace changed during digest read")
        digest.update(chunk)
        offset += len(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RuntimeOpenTraceError("value is not canonical JSON") from exc


def _schema_version_is_one(value: Any) -> bool:
    return type(value) is int and value == 1


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise RuntimeOpenTraceError("manifest contains a duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise RuntimeOpenTraceError(f"manifest contains a non-finite number: {value}")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_absolute(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeOpenTraceError(f"{label} is not a path string")
    if any(ord(character) < 0x20 for character in value):
        raise RuntimeOpenTraceError(f"{label} contains a control character")
    path = PurePosixPath(value)
    if not path.is_absolute() or str(path) != value or posixpath.normpath(value) != value:
        raise RuntimeOpenTraceError(f"{label} is not canonical absolute")
    return value


def _canonical_manifest_path(
    value: Any, *, label: str, verifier_template: bool
) -> str:
    if (
        verifier_template
        and isinstance(value, str)
        and (
            value == VERIFIER_EVIDENCE_DIR_MARKER
            or value.startswith(VERIFIER_EVIDENCE_DIR_MARKER + "/")
        )
        and "\x00" not in value
        and not any(ord(character) < 0x20 for character in value)
        and posixpath.normpath(value) == value
    ):
        return value
    return _canonical_absolute(value, label=label)


def _argv(value: Any, *, label: str) -> tuple[str, ...]:
    if type(value) is not list or not value or len(value) > MAX_ARGV_ITEMS:
        raise RuntimeOpenTraceError(f"{label} is invalid")
    result: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or len(item.encode("utf-8")) > MAX_ARG_BYTES
            or any(ord(character) < 0x20 for character in item)
        ):
            raise RuntimeOpenTraceError(f"{label} contains an invalid argument")
        result.append(item)
    _canonical_absolute(result[0], label=f"{label} executable")
    if any(item == "-p" or item == "--attach" or item.startswith("--attach=") for item in result):
        raise RuntimeOpenTraceError(f"{label} requests ptrace attach mode")
    return tuple(result)


def _positive_decimal(value: str, *, label: str, allow_zero: bool = False) -> int:
    if re.fullmatch(r"[0-9]+", value) is None or (len(value) > 1 and value[0] == "0"):
        raise RuntimeOpenTraceError(f"{label} is not a canonical integer")
    number = int(value)
    if number < (0 if allow_zero else 1):
        raise RuntimeOpenTraceError(f"{label} is outside its allowed range")
    return number


def _validate_bootstrap_argv(
    bootstrap: tuple[str, ...],
    final: tuple[str, ...],
    *,
    role: str,
    release_root: str,
) -> tuple[int, int, bool]:
    """Validate the exact direct_child option template, including duplicates."""

    delimiter = len(bootstrap) - len(final) - 1
    if delimiter <= 0 or bootstrap[delimiter] != "--" or bootstrap[delimiter + 1 :] != final:
        raise RuntimeOpenTraceError("bootstrap argv is not bound to the final argv")
    direct_child = f"{release_root}/deployment/dev29/direct_child.py"
    no_site = role in {"signer", "verifier"}
    prefix = (
        bootstrap[0],
        "-I",
        "-B",
        *(("-S",) if no_site else ()),
        direct_child,
    )
    if bootstrap[: len(prefix)] != prefix:
        raise RuntimeOpenTraceError("bootstrap argv prefix is not the fixed direct child")
    final_prefix = (bootstrap[0], "-I", "-B", *(("-S",) if no_site else ()))
    if final[: len(final_prefix)] != final_prefix or len(final) <= len(final_prefix):
        raise RuntimeOpenTraceError("final argv does not use the same isolated Python")
    expected_script = {
        "odoo": f"{release_root}/bin/odoo-accounting-cli-v3",
        "signer": f"{release_root}/deployment/dev29/sign_read.py",
        "postgres": f"{release_root}/deployment/dev29/read_oracles.py",
        "verifier": f"{release_root}/deployment/dev29/verify_read_evidence.py",
    }[role]
    if final[len(final_prefix)] != expected_script:
        raise RuntimeOpenTraceError("final argv is not the fixed role entrypoint")
    values = bootstrap[len(prefix) : delimiter]
    fixed_names = (
        "--role",
        "--attestation-fd",
        "--expected-uid",
        "--expected-gid",
        "--expected-python",
        "--expected-venv-root",
        "--release-root",
        "--expected-self-namespace-device",
        "--expected-self-namespace-inode",
        "--expected-host-namespace-device",
        "--expected-host-namespace-inode",
        "--expected-loop-device",
    )
    parsed: dict[str, str] = {}
    index = 0
    for name in fixed_names:
        if index + 1 >= len(values) or values[index] != name:
            raise RuntimeOpenTraceError("bootstrap argv option order/schema is invalid")
        parsed[name] = values[index + 1]
        index += 2
    mounts: list[str] = []
    while index < len(values):
        if index + 1 >= len(values) or values[index] != "--expected-mount-json":
            raise RuntimeOpenTraceError("bootstrap argv contains an unknown or duplicate option")
        mounts.append(values[index + 1])
        index += 2
    if len(mounts) != 5:
        raise RuntimeOpenTraceError("bootstrap argv must bind exactly five closure mounts")
    if parsed["--role"] != role or parsed["--release-root"] != release_root:
        raise RuntimeOpenTraceError("bootstrap argv role/release binding is invalid")
    if parsed["--expected-python"] != bootstrap[0]:
        raise RuntimeOpenTraceError("bootstrap expected Python differs from its executable")
    _canonical_absolute(parsed["--expected-python"], label="expected Python")
    _canonical_absolute(parsed["--expected-venv-root"], label="expected venv root")
    _positive_decimal(parsed["--attestation-fd"], label="attestation fd")
    if int(parsed["--attestation-fd"]) <= 2:
        raise RuntimeOpenTraceError("attestation fd is not private")
    _positive_decimal(parsed["--expected-uid"], label="expected uid", allow_zero=True)
    _positive_decimal(parsed["--expected-gid"], label="expected gid", allow_zero=True)
    template_options = dict(DYNAMIC_BOOTSTRAP_OPTIONS)
    marker_occurrences = tuple(
        value for value in bootstrap if value in _DYNAMIC_BOOTSTRAP_MARKERS
    )
    uses_template = bool(marker_occurrences)
    if uses_template:
        if (
            any(parsed[option] != marker for option, marker in template_options.items())
            or tuple(mounts) != DYNAMIC_MOUNT_ARGUMENTS
            or len(marker_occurrences) != len(_DYNAMIC_BOOTSTRAP_MARKERS)
        ):
            raise RuntimeOpenTraceError(
                "bootstrap dynamic template is partial or misplaced"
            )
    else:
        namespace_values = [
            _positive_decimal(parsed[name], label=name)
            for name in fixed_names[7:11]
        ]
        if namespace_values[:2] == namespace_values[2:]:
            raise RuntimeOpenTraceError(
                "bootstrap self and host namespace identities are equal"
            )
        if re.fullmatch(r"/dev/loop[0-9]+", parsed["--expected-loop-device"]) is None:
            raise RuntimeOpenTraceError("bootstrap loop device is invalid")
        for item in mounts:
            try:
                document = json.loads(
                    item, object_pairs_hook=_pairs, parse_constant=_constant
                )
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise RuntimeOpenTraceError("bootstrap mount JSON is invalid") from exc
            if (
                type(document) is not dict
                or canonical_json(document).decode("utf-8") != item
            ):
                raise RuntimeOpenTraceError("bootstrap mount JSON is not canonical")
    return (
        int(parsed["--expected-uid"]),
        int(parsed["--expected-gid"]),
        uses_template,
    )


def dynamic_bootstrap_template(
    bootstrap: Sequence[str],
    final: Sequence[str],
    *,
    role: str,
    release_root: str,
) -> tuple[str, ...]:
    """Replace only per-unit attestation values with fixed reviewed markers."""

    bootstrap_values = _argv(list(bootstrap), label="bootstrap argv")
    final_values = _argv(list(final), label="final argv")
    _uid, _gid, is_template = _validate_bootstrap_argv(
        bootstrap_values,
        final_values,
        role=role,
        release_root=release_root,
    )
    if is_template:
        raise RuntimeOpenTraceError("bootstrap argv is already a dynamic template")
    result = list(bootstrap_values)
    for option, marker in DYNAMIC_BOOTSTRAP_OPTIONS:
        result[result.index(option) + 1] = marker
    mount_positions = [
        index
        for index, value in enumerate(result)
        if value == "--expected-mount-json"
    ]
    if len(mount_positions) != len(DYNAMIC_MOUNT_ARGUMENTS):
        raise RuntimeOpenTraceError("bootstrap mount template count is invalid")
    for position, marker in zip(mount_positions, DYNAMIC_MOUNT_ARGUMENTS):
        result[position + 1] = marker
    template = tuple(result)
    _uid, _gid, is_template = _validate_bootstrap_argv(
        template,
        final_values,
        role=role,
        release_root=release_root,
    )
    if not is_template:
        raise RuntimeOpenTraceError("bootstrap dynamic template was not created")
    return template


@dataclass(frozen=True)
class PathAccessPolicy:
    path: str
    role: str
    classification: str
    allowed_access: tuple[str, ...]
    create_suffixes: tuple[str, ...]
    delta_verifier: str | None
    delta_contract_sha256: str | None
    allow_success: bool
    allowed_errnos: tuple[str, ...]
    failure_guard: str | None

    def matches(self, candidate: str) -> bool:
        return candidate == self.path or (
            self.classification == "mutable-state"
            and any(candidate == self.path + suffix for suffix in self.create_suffixes)
        )


@dataclass(frozen=True)
class TraceManifest:
    release: str
    target_id: str
    role: str
    working_directory: str
    environment: Mapping[str, str]
    bootstrap_argv: tuple[str, ...]
    final_argv: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    path_access_policy: tuple[PathAccessPolicy, ...]
    watch_roots: tuple[str, ...]
    expected_static_closure_sha256: str
    expected_child_environment_sha256: str
    expected_returncodes: tuple[int, ...]
    expected_uid: int
    expected_gid: int
    manifest_sha256: str
    expected_strace_sha256: str
    dynamic_argv_template: bool = False

    @property
    def expected_execve_argv(
        self,
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        if self.dynamic_argv_template:
            raise RuntimeOpenTraceError(
                "bootstrap dynamic template must be materialized before execution"
            )
        return (demotion_argv(self), self.bootstrap_argv, self.final_argv)


def materialize_bootstrap_template(
    manifest: TraceManifest,
    bootstrap: Sequence[str],
    final: Sequence[str],
) -> TraceManifest:
    """Bind one approved template to the current attested unit identities."""

    if not isinstance(manifest, TraceManifest) or not manifest.dynamic_argv_template:
        raise RuntimeOpenTraceError("runtime trace manifest is not a dynamic template")
    bootstrap_values = _argv(list(bootstrap), label="effective bootstrap argv")
    final_values = _argv(list(final), label="effective final argv")
    release_root = f"/opt/odoo-accounting-cli-v3/releases/{manifest.release}"
    uid, gid, is_template = _validate_bootstrap_argv(
        bootstrap_values,
        final_values,
        role=manifest.role,
        release_root=release_root,
    )
    expected_final = _materialized_final_argv_template(
        manifest.final_argv, final_values, manifest=manifest
    )
    expected_bootstrap = _materialized_bootstrap_argv_template(
        dynamic_bootstrap_template(
            bootstrap_values,
            final_values,
            role=manifest.role,
            release_root=release_root,
        ),
        manifest.bootstrap_argv,
        manifest=manifest,
    )
    if (
        is_template
        or expected_final != final_values
        or uid != manifest.expected_uid
        or gid != manifest.expected_gid
        or expected_bootstrap != manifest.bootstrap_argv
    ):
        raise RuntimeOpenTraceError(
            "effective bootstrap argv differs from the approved dynamic template"
        )
    return replace(
        manifest,
        bootstrap_argv=bootstrap_values,
        final_argv=final_values,
        allowed_paths=tuple(
            _materialize_verifier_evidence_path(path, final_values)
            for path in manifest.allowed_paths
        ),
        path_access_policy=tuple(
            replace(
                policy,
                path=_materialize_verifier_evidence_path(policy.path, final_values),
            )
            for policy in manifest.path_access_policy
        ),
        dynamic_argv_template=False,
    )


def verifier_final_argv_template(final: Sequence[str]) -> tuple[str, ...]:
    values = _argv(list(final), label="verifier final argv")
    if (
        values.count(VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER) != 0
        or values.count(VERIFIER_EVIDENCE_DIR_MARKER) != 0
    ):
        raise RuntimeOpenTraceError("verifier final argv is already templated")
    try:
        bundle_index = values.index("--expected-bundle-manifest-sha256")
        evidence_index = values.index("--evidence-dir")
    except ValueError as exc:
        raise RuntimeOpenTraceError("verifier dynamic option is absent") from exc
    if bundle_index + 1 >= len(values) or HEX64.fullmatch(values[bundle_index + 1]) is None:
        raise RuntimeOpenTraceError("verifier bundle digest value is invalid")
    if evidence_index + 1 >= len(values) or not _is_verifier_evidence_dir(
        values[evidence_index + 1]
    ):
        raise RuntimeOpenTraceError("verifier evidence directory value is invalid")
    templated = list(values)
    templated[bundle_index + 1] = VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER
    templated[evidence_index + 1] = VERIFIER_EVIDENCE_DIR_MARKER
    return tuple(templated)


def _materialized_final_argv_template(
    template: tuple[str, ...],
    actual: tuple[str, ...],
    *,
    manifest: TraceManifest,
) -> tuple[str, ...]:
    marker_count = template.count(VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER)
    evidence_marker_count = template.count(VERIFIER_EVIDENCE_DIR_MARKER)
    if marker_count == 0 and evidence_marker_count == 0:
        return template
    if (
        evidence_marker_count > 1
        or manifest.target_id != "independent-verifier"
        or manifest.role != "verifier"
        or len(template) != len(actual)
    ):
        raise RuntimeOpenTraceError("verifier final argv template is invalid")
    materialized = list(template)
    if evidence_marker_count == 1:
        try:
            evidence_index = template.index("--evidence-dir")
        except ValueError as exc:
            raise RuntimeOpenTraceError("verifier evidence directory option is absent") from exc
        if (
            evidence_index + 1 >= len(template)
            or template[evidence_index + 1] != VERIFIER_EVIDENCE_DIR_MARKER
            or not _is_verifier_evidence_dir(actual[evidence_index + 1])
        ):
            raise RuntimeOpenTraceError("verifier evidence directory value is invalid")
        materialized[evidence_index + 1] = actual[evidence_index + 1]
    if marker_count == 0:
        return tuple(materialized)
    if (
        marker_count != 1
    ):
        raise RuntimeOpenTraceError("verifier final argv template is invalid")
    try:
        index = template.index("--expected-bundle-manifest-sha256")
    except ValueError as exc:
        raise RuntimeOpenTraceError("verifier bundle digest option is absent") from exc
    if (
        index + 1 >= len(template)
        or template[index + 1] != VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER
        or HEX64.fullmatch(actual[index + 1]) is None
    ):
        raise RuntimeOpenTraceError("verifier bundle digest value is invalid")
    materialized[index + 1] = actual[index + 1]
    return tuple(materialized)


def _materialized_bootstrap_argv_template(
    bootstrap_template: tuple[str, ...],
    approved_template: tuple[str, ...],
    *,
    manifest: TraceManifest,
) -> tuple[str, ...]:
    dynamic_markers = {
        VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER,
        VERIFIER_EVIDENCE_DIR_MARKER,
    }
    if not any(item in dynamic_markers for item in approved_template):
        return bootstrap_template
    if len(bootstrap_template) != len(approved_template):
        raise RuntimeOpenTraceError("verifier bootstrap argv template is invalid")
    materialized = list(bootstrap_template)
    for index, value in enumerate(approved_template):
        if value in dynamic_markers:
            if (
                manifest.target_id != "independent-verifier"
                or manifest.role != "verifier"
            ):
                raise RuntimeOpenTraceError(
                    "verifier bootstrap argv template is invalid"
                )
            if value == VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER:
                if HEX64.fullmatch(bootstrap_template[index]) is None:
                    raise RuntimeOpenTraceError(
                        "verifier bootstrap argv template is invalid"
                    )
            elif not _is_verifier_evidence_dir(bootstrap_template[index]):
                raise RuntimeOpenTraceError(
                    "verifier bootstrap argv template is invalid"
                )
            materialized[index] = value
    return tuple(materialized)


def _is_verifier_evidence_dir(value: str) -> bool:
    if not isinstance(value, str):
        return False
    prefix = "/var/lib/odoo-accounting-cli-v3/evidence/"
    name = value.removeprefix(prefix)
    return value.startswith(prefix) and "/" not in name and NAME.fullmatch(name) is not None


def _materialize_verifier_evidence_path(path: str, final: tuple[str, ...]) -> str:
    if not path.startswith(VERIFIER_EVIDENCE_DIR_MARKER + "/"):
        return path
    try:
        index = final.index("--evidence-dir")
    except ValueError as exc:
        raise RuntimeOpenTraceError("verifier evidence directory option is absent") from exc
    if index + 1 >= len(final) or not _is_verifier_evidence_dir(final[index + 1]):
        raise RuntimeOpenTraceError("verifier evidence directory value is invalid")
    return final[index + 1] + path[len(VERIFIER_EVIDENCE_DIR_MARKER) :]


@dataclass(frozen=True)
class TraceRequest:
    release: str
    target_id: str
    expected_manifest_sha256: str
    expected_strace_sha256: str
    expected_static_closure_sha256: str
    expected_child_environment_sha256: str
    expected_watch_roots_sha256: str

    def validate(self) -> "TraceRequest":
        if (
            not isinstance(self.release, str)
            or NAME.fullmatch(self.release) is None
            or not isinstance(self.target_id, str)
            or NAME.fullmatch(self.target_id) is None
            or any(
                not isinstance(value, str) or HEX64.fullmatch(value) is None
                for value in (
                    self.expected_manifest_sha256,
                    self.expected_strace_sha256,
                    self.expected_static_closure_sha256,
                    self.expected_child_environment_sha256,
                    self.expected_watch_roots_sha256,
                )
            )
        ):
            raise RuntimeOpenTraceError("runtime trace request identity is invalid")
        return self


@dataclass(frozen=True)
class TrustedFileIdentity:
    path: str
    sha256: str
    size: int
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    links: int
    mtime_ns: int
    ctime_ns: int


@dataclass
class TrustedExecutable:
    """An already hashed executable held open across ``Popen``."""

    identity: TrustedFileIdentity
    descriptor: int = field(repr=False)

    def assert_open(self) -> None:
        if type(self.descriptor) is not int or self.descriptor < 0:
            raise RuntimeOpenTraceError("trusted executable handle is closed")
        try:
            metadata = os.fstat(self.descriptor)
            current = STRACE_PATH.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimeOpenTraceError("trusted executable identity is unavailable") from exc
        expected = (self.identity.device, self.identity.inode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != expected
            or (current.st_dev, current.st_ino) != expected
            or stat.S_IMODE(metadata.st_mode) != self.identity.mode
            or metadata.st_uid != self.identity.uid
            or metadata.st_gid != self.identity.gid
            or metadata.st_nlink != self.identity.links
            or metadata.st_size != self.identity.size
            or metadata.st_mtime_ns != self.identity.mtime_ns
            or metadata.st_ctime_ns != self.identity.ctime_ns
        ):
            raise RuntimeOpenTraceError("fixed strace path changed after validation")

    def verify_unchanged(self) -> None:
        """Re-hash the held fd after tracing; atime is intentionally excluded."""

        self.assert_open()
        try:
            original_offset = os.lseek(self.descriptor, 0, os.SEEK_CUR)
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            total = 0
            before = os.fstat(self.descriptor)
            while True:
                chunk = os.read(self.descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 64 * 1024 * 1024:
                    raise RuntimeOpenTraceError("fixed strace exceeds its size limit")
                digest.update(chunk)
            after = os.fstat(self.descriptor)
            os.lseek(self.descriptor, original_offset, os.SEEK_SET)
        except OSError as exc:
            raise RuntimeOpenTraceError("fixed strace cannot be re-hashed") from exc
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            any(getattr(before, name) != getattr(after, name) for name in stable)
            or total != self.identity.size
            or digest.hexdigest() != self.identity.sha256
            or (after.st_dev, after.st_ino)
            != (self.identity.device, self.identity.inode)
            or stat.S_IMODE(after.st_mode) != self.identity.mode
            or after.st_uid != self.identity.uid
            or after.st_gid != self.identity.gid
            or after.st_nlink != self.identity.links
            or after.st_size != self.identity.size
            or after.st_mtime_ns != self.identity.mtime_ns
            or after.st_ctime_ns != self.identity.ctime_ns
        ):
            raise RuntimeOpenTraceError("fixed strace changed during execution window")

    @property
    def launch_path(self) -> str:
        self.assert_open()
        return f"/proc/self/fd/{self.descriptor}"

    @property
    def pass_fds(self) -> tuple[int, ...]:
        self.assert_open()
        return (self.descriptor,)

    def close(self) -> None:
        if self.descriptor >= 0:
            try:
                self.verify_unchanged()
            finally:
                os.close(self.descriptor)
                self.descriptor = -1

    def __enter__(self) -> "TrustedExecutable":
        self.assert_open()
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()


@dataclass(frozen=True)
class StraceLaunch:
    argv: tuple[str, ...]
    pass_fds: tuple[int, ...]
    logical_executable: str = STRACE_COMMAND


@dataclass(frozen=True)
class ParsedTrace:
    paths: tuple[str, ...]
    accesses: tuple[tuple[str, tuple[str, ...]], ...]
    attempted_mutations: tuple[tuple[str, tuple[str, ...]], ...]
    attempts: tuple[tuple[str, tuple[str, ...], str], ...]
    execve_argv: tuple[tuple[str, ...], ...]
    trace_sha256: str
    leader_returncode: int


@dataclass(frozen=True)
class TraceVerificationHandle:
    """Private same-host handle for an independent root verifier."""

    trace_path: str
    trace_device: int
    trace_inode: int
    expected_leader_pid: int
    manifest_sha256: str
    trace_mode: int


@dataclass(frozen=True)
class TraceResult:
    canonical_path_set_sha256: str
    canonical_path_count: int
    trace_sha256: str
    _verification_handle: TraceVerificationHandle | None = field(
        default=None, repr=False, compare=False
    )

    def document(self) -> dict[str, Any]:
        return {
            "canonical_path_count": self.canonical_path_count,
            "canonical_path_set_sha256": self.canonical_path_set_sha256,
            "trace_sha256": self.trace_sha256,
        }

    @property
    def production_promotion_allowed(self) -> bool:
        # This unit only attests one direct child.  Suite-wide seccomp and real
        # root integration evidence remain separate mandatory gates.
        return PRODUCTION_PROMOTION_ALLOWED

    def verification_handle(self) -> TraceVerificationHandle:
        if self._verification_handle is None:
            raise RuntimeOpenTraceError("trace result has no private verifier handle")
        return self._verification_handle


def manifest_path(request: TraceRequest, *, parent: Path = MANIFEST_PARENT) -> Path:
    request.validate()
    return parent / request.release / f"{request.target_id}.json"


def _path_access_policies(
    value: Any, *, role: str, verifier_template: bool = False
) -> tuple[PathAccessPolicy, ...]:
    if type(value) is not list or not value or len(value) > MAX_PATHS:
        raise RuntimeOpenTraceError("path access policy is invalid")
    policies: list[PathAccessPolicy] = []
    for item in value:
        if type(item) is not dict or set(item) != {
            "path",
            "role",
            "classification",
            "allowed_access",
            "create_suffixes",
            "delta_verifier",
            "delta_contract_sha256",
            "allow_success",
            "allowed_errnos",
            "failure_guard",
        }:
            raise RuntimeOpenTraceError("path access policy entry schema is invalid")
        path = _canonical_manifest_path(
            item.get("path"),
            label="path policy path",
            verifier_template=verifier_template,
        )
        classification = item.get("classification")
        access = item.get("allowed_access")
        suffixes = item.get("create_suffixes")
        delta = item.get("delta_verifier")
        delta_contract = item.get("delta_contract_sha256")
        allow_success = item.get("allow_success")
        errnos = item.get("allowed_errnos")
        failure_guard = item.get("failure_guard")
        if (
            item.get("role") != role
            or classification
            not in {"immutable", "mutable-state", "unix-socket", "process-view"}
            or type(access) is not list
            or not access
            or access != sorted(set(access))
            or any(item not in ACCESS_VALUES for item in access)
            or type(suffixes) is not list
            or suffixes != sorted(set(suffixes))
            or any(
                not isinstance(suffix, str)
                or re.fullmatch(r"-[0-9A-Za-z._-]{1,31}", suffix) is None
                for suffix in suffixes
            )
            or type(allow_success) is not bool
            or type(errnos) is not list
            or errnos != sorted(set(errnos))
            or any(
                not isinstance(errno, str)
                or re.fullmatch(r"E[A-Z0-9_]{1,63}", errno) is None
                for errno in errnos
            )
            or (not allow_success and not errnos)
        ):
            raise RuntimeOpenTraceError("path access policy entry is invalid")
        allowed = set(access)
        if classification == "immutable":
            valid = (
                allowed <= IMMUTABLE_ACCESS
                and not suffixes
                and delta is None
                and delta_contract is None
                and failure_guard
                == (WATCH_TREE_FAILURE_GUARD if errnos else None)
            )
        elif classification == "mutable-state":
            valid = (
                allowed <= MUTABLE_ACCESS
                and delta == SQLITE_DELTA_VERIFIER
                and isinstance(delta_contract, str)
                and HEX64.fullmatch(delta_contract) is not None
                and (not suffixes or {"create", "write"} <= allowed)
                and failure_guard == (delta if errnos else None)
            )
        else:
            if classification == "process-view":
                valid = (
                    _is_process_view_path(path)
                    and allowed <= PROCESS_VIEW_ACCESS
                    and not suffixes
                    and delta is None
                    and delta_contract is None
                    and failure_guard
                    == (PROCESS_VIEW_FAILURE_GUARD if errnos else None)
                )
            else:
                valid = (
                    allowed <= SOCKET_ACCESS
                    and not suffixes
                    and delta is None
                    and delta_contract is None
                    and failure_guard
                    == (UNIX_SOCKET_FAILURE_GUARD if errnos else None)
                )
        if classification == "process-view" and not _is_process_view_path(path):
            raise RuntimeOpenTraceError("path access policy process view path is unsafe")
        if not valid:
            raise RuntimeOpenTraceError("path access policy classification is unsafe")
        policies.append(
            PathAccessPolicy(
                path=path,
                role=role,
                classification=classification,
                allowed_access=tuple(access),
                create_suffixes=tuple(suffixes),
                delta_verifier=delta,
                delta_contract_sha256=delta_contract,
                allow_success=allow_success,
                allowed_errnos=tuple(errnos),
                failure_guard=failure_guard,
            )
        )
    keys = [item.path for item in policies]
    if keys != sorted(set(keys)):
        raise RuntimeOpenTraceError("path access policy entries are not sorted and unique")
    return tuple(policies)


def _is_process_view_path(path: str) -> bool:
    roots = ("/proc/self", "/proc/@self", "/proc/1")
    exact = ("/proc/sys/crypto/fips_enabled", "/proc/sys/kernel/cap_last_cap")
    return path in exact or any(path == root or path.startswith(root + "/") for root in roots)


def _is_watch_root_metadata_ancestor(path: str, watch_roots: Sequence[str]) -> bool:
    if path == "/":
        prefix = "/"
    else:
        prefix = path + "/"
    return any(root.startswith(prefix) for root in watch_roots)


def _is_verifier_evidence_parent_metadata_ancestor(path: str) -> bool:
    if path == VERIFIER_EVIDENCE_PARENT:
        return True
    if path == "/":
        prefix = "/"
    else:
        prefix = path + "/"
    return VERIFIER_EVIDENCE_PARENT.startswith(prefix)


def _nearest_existing_parent(path: Path) -> tuple[Path, os.stat_result]:
    parent = path.parent
    while True:
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            if parent == parent.parent:
                raise RuntimeOpenTraceError("absent watch root has no existing parent")
            parent = parent.parent
            continue
        except OSError as exc:
            raise RuntimeOpenTraceError("absent watch root parent cannot be inspected") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise RuntimeOpenTraceError("absent watch root parent is unsafe")
        return parent, metadata


def validate_manifest_document(value: Any, request: TraceRequest) -> TraceManifest:
    request.validate()
    fields = {
        "schema_version",
        "scope",
        "release",
        "target_id",
        "role",
        "working_directory",
        "environment",
        "bootstrap_argv",
        "final_argv",
        "allowed_paths",
        "path_access_policy",
        "watch_roots",
        "expected_static_closure_sha256",
        "expected_child_environment_sha256",
        "expected_watch_roots_sha256",
        "expected_returncodes",
    }
    if type(value) is not dict or set(value) != fields:
        raise RuntimeOpenTraceError("runtime trace manifest schema is invalid")
    role = value.get("role")
    if (
        not _schema_version_is_one(value.get("schema_version"))
        or value.get("scope") != SCOPE
        or value.get("release") != request.release
        or value.get("target_id") != request.target_id
        or role not in ROLE_ENVIRONMENTS
        or value.get("environment") != ROLE_ENVIRONMENTS[role]
        or value.get("expected_static_closure_sha256")
        != request.expected_static_closure_sha256
        or value.get("expected_child_environment_sha256")
        != request.expected_child_environment_sha256
        or request.expected_child_environment_sha256
        != _sha256(canonical_json(ROLE_ENVIRONMENTS[role]))
        or value.get("expected_watch_roots_sha256")
        != request.expected_watch_roots_sha256
    ):
        raise RuntimeOpenTraceError("runtime trace manifest identity is invalid")
    working_directory = _canonical_absolute(
        value.get("working_directory"), label="working directory"
    )
    bootstrap = _argv(value.get("bootstrap_argv"), label="bootstrap argv")
    final = _argv(value.get("final_argv"), label="final argv")
    release_root = f"/opt/odoo-accounting-cli-v3/releases/{request.release}"
    expected_uid, expected_gid, dynamic_argv_template = _validate_bootstrap_argv(
        bootstrap, final, role=role, release_root=release_root
    )
    allowed_raw = value.get("allowed_paths")
    watch_raw = value.get("watch_roots")
    if type(allowed_raw) is not list or not allowed_raw or len(allowed_raw) > MAX_PATHS:
        raise RuntimeOpenTraceError("allowed path set is invalid")
    if type(watch_raw) is not list or not watch_raw or len(watch_raw) > MAX_PATHS:
        raise RuntimeOpenTraceError("watch root set is invalid")
    verifier_template = (
        request.target_id == "independent-verifier"
        and role == "verifier"
        and (
            VERIFIER_EVIDENCE_DIR_MARKER in final
            or any(
                isinstance(item, str)
                and item.startswith(VERIFIER_EVIDENCE_DIR_MARKER + "/")
                for item in allowed_raw
            )
        )
    )
    allowed = tuple(
        _canonical_manifest_path(
            item,
            label="allowed path",
            verifier_template=verifier_template,
        )
        for item in allowed_raw
    )
    watches = tuple(_canonical_absolute(item, label="watch root") for item in watch_raw)
    policies = _path_access_policies(
        value.get("path_access_policy"),
        role=role,
        verifier_template=verifier_template,
    )
    if list(allowed) != sorted(set(allowed)) or list(watches) != sorted(set(watches)):
        raise RuntimeOpenTraceError("manifest path sets are not sorted and unique")
    if _sha256(canonical_json(watches)) != request.expected_watch_roots_sha256:
        raise RuntimeOpenTraceError("watch root set differs from the independent expectation")
    def watched(path: str) -> bool:
        return any(path == root or path.startswith(root + "/") for root in watches)

    matches_for_allowed = {
        path: tuple(policy for policy in policies if policy.matches(path))
        for path in allowed
    }
    if any(len(matches) != 1 for matches in matches_for_allowed.values()):
        raise RuntimeOpenTraceError(
            "allowed path lacks one unambiguous external access policy"
        )
    if any(not any(policy.matches(path) for path in allowed) for policy in policies):
        raise RuntimeOpenTraceError("path access policy is not bound to the exact allow set")

    policy_for_allowed = {
        path: matches[0] for path, matches in matches_for_allowed.items()
    }
    if (
        any(
            policy.classification == "immutable"
            and not watched(path)
            and not (
                policy.allowed_access == ("metadata",)
                and policy.allow_success
                and not policy.allowed_errnos
                and (
                    _is_watch_root_metadata_ancestor(path, watches)
                    or (
                        verifier_template
                        and _is_verifier_evidence_parent_metadata_ancestor(path)
                    )
                )
            )
            for path, policy in policy_for_allowed.items()
        )
        or any(
            policy.classification != "immutable" and watched(path)
            for path, policy in policy_for_allowed.items()
        )
        or not watched(working_directory)
        or any(
            not watched(argument)
            for argument in (*bootstrap, *final)
            if argument.startswith("/")
        )
        or not watched(SYSTEM_PYTHON_COMMAND)
        or not watched(
            f"{release_root}/deployment/dev29/runtime_open_trace.py"
        )
    ):
        raise RuntimeOpenTraceError("allow/exec/cwd path is outside the watched closure")
    codes = value.get("expected_returncodes")
    if (
        type(codes) is not list
        or not codes
        or len(codes) > 16
        or any(type(code) is not int or code < 0 or code > 255 for code in codes)
        or codes != sorted(set(codes))
    ):
        raise RuntimeOpenTraceError("expected return-code set is invalid")
    return TraceManifest(
        release=request.release,
        target_id=request.target_id,
        role=role,
        working_directory=working_directory,
        environment=dict(ROLE_ENVIRONMENTS[role]),
        bootstrap_argv=bootstrap,
        final_argv=final,
        allowed_paths=allowed,
        path_access_policy=policies,
        watch_roots=watches,
        expected_static_closure_sha256=request.expected_static_closure_sha256,
        expected_child_environment_sha256=(
            request.expected_child_environment_sha256
        ),
        expected_returncodes=tuple(codes),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        manifest_sha256=request.expected_manifest_sha256,
        expected_strace_sha256=request.expected_strace_sha256,
        dynamic_argv_template=dynamic_argv_template,
    )


def demotion_argv(manifest: TraceManifest) -> tuple[str, ...]:
    """Return the fixed root tracee that drops credentials before direct_child."""

    if manifest.dynamic_argv_template:
        raise RuntimeOpenTraceError(
            "bootstrap dynamic template must be materialized before execution"
        )
    script = (
        f"/opt/odoo-accounting-cli-v3/releases/{manifest.release}/"
        "deployment/dev29/runtime_open_trace.py"
    )
    return (
        SYSTEM_PYTHON_COMMAND,
        "-I",
        "-B",
        "-S",
        script,
        "__dev29_demote_exec_v1__",
        manifest.role,
        manifest.release,
        str(manifest.expected_uid),
        str(manifest.expected_gid),
        str(len(manifest.final_argv)),
        _sha256(canonical_json(manifest.bootstrap_argv)),
        _sha256(canonical_json(manifest.final_argv)),
        "--",
        *manifest.bootstrap_argv,
    )


def _read_trusted_regular(
    path: Path,
    expected_sha256: str | None,
    *,
    expected_mode: int,
    max_bytes: int,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> tuple[bytes, TrustedFileIdentity]:
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or HEX64.fullmatch(expected_sha256) is None
    ):
        raise RuntimeOpenTraceError("expected file digest is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeOpenTraceError("trusted file cannot be opened without following links") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != expected_mode
            or (before.st_uid, before.st_gid) != (expected_uid, expected_gid)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise RuntimeOpenTraceError("trusted file ownership/mode/link identity is invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeOpenTraceError("trusted file exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise RuntimeOpenTraceError("trusted file changed while it was read")
    payload = b"".join(chunks)
    digest = _sha256(payload)
    if expected_sha256 is not None and digest != expected_sha256:
        raise RuntimeOpenTraceError("trusted file digest mismatch")
    return payload, TrustedFileIdentity(
        path=str(path),
        sha256=digest,
        size=len(payload),
        device=before.st_dev,
        inode=before.st_ino,
        uid=before.st_uid,
        gid=before.st_gid,
        mode=stat.S_IMODE(before.st_mode),
        links=before.st_nlink,
        mtime_ns=before.st_mtime_ns,
        ctime_ns=before.st_ctime_ns,
    )


def _validate_root_chain(path: Path) -> None:
    """Require an absolute, symlink-free, root-owned, non-writable ancestor chain."""

    if os.name != "posix" or not path.is_absolute():
        raise RuntimeOpenTraceError("trusted path requires an absolute POSIX root chain")
    current = Path("/")
    try:
        root_metadata = current.lstat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or (root_metadata.st_uid, root_metadata.st_gid) != (0, 0)
            or stat.S_IMODE(root_metadata.st_mode) & 0o022
        ):
            raise RuntimeOpenTraceError("trusted root directory identity is invalid")
        for component in path.parts[1:]:
            current /= component
            metadata = current.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid) != (0, 0)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise RuntimeOpenTraceError("trusted path ancestor is mutable or linked")
    except OSError as exc:
        raise RuntimeOpenTraceError("trusted path ancestor is unavailable") from exc


def validate_strace_tool(expected_sha256: str) -> TrustedExecutable:
    """Hash and retain an O_NOFOLLOW fd for the fixed tracer."""

    if not isinstance(expected_sha256, str) or HEX64.fullmatch(expected_sha256) is None:
        raise RuntimeOpenTraceError("expected strace digest is invalid")
    _validate_root_chain(STRACE_PATH.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(STRACE_PATH, flags)
    except OSError as exc:
        raise RuntimeOpenTraceError("fixed strace cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o755
            or (before.st_uid, before.st_gid) != (0, 0)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > 64 * 1024 * 1024
        ):
            raise RuntimeOpenTraceError("fixed strace ownership/mode/link identity is invalid")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 64 * 1024 * 1024:
                raise RuntimeOpenTraceError("fixed strace exceeds its size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, name) != getattr(after, name) for name in stable):
            raise RuntimeOpenTraceError("fixed strace changed while it was hashed")
        observed_sha256 = digest.hexdigest()
        if observed_sha256 != expected_sha256:
            raise RuntimeOpenTraceError("fixed strace digest mismatch")
        identity = TrustedFileIdentity(
            path=STRACE_COMMAND,
            sha256=observed_sha256,
            size=total,
            device=before.st_dev,
            inode=before.st_ino,
            uid=before.st_uid,
            gid=before.st_gid,
            mode=stat.S_IMODE(before.st_mode),
            links=before.st_nlink,
            mtime_ns=before.st_mtime_ns,
            ctime_ns=before.st_ctime_ns,
        )
        trusted = TrustedExecutable(identity=identity, descriptor=descriptor)
        trusted.assert_open()
        return trusted
    except BaseException:
        os.close(descriptor)
        raise


def load_trace_manifest(request: TraceRequest) -> tuple[TraceManifest, TrustedFileIdentity]:
    """Load the sole external allow-set trust anchor for a trace target."""

    path = manifest_path(request)
    _validate_root_chain(path.parent)
    payload, identity = _read_trusted_regular(
        path,
        request.expected_manifest_sha256,
        expected_mode=0o400,
        max_bytes=MAX_MANIFEST_BYTES,
    )
    if not payload.endswith(b"\n"):
        raise RuntimeOpenTraceError("runtime trace manifest is truncated")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RuntimeOpenTraceError("runtime trace manifest JSON is invalid") from exc
    if payload != canonical_json(value) + b"\n":
        raise RuntimeOpenTraceError("runtime trace manifest is not canonical")
    return validate_manifest_document(value, request), identity


def build_strace_launch(
    trace_path: Path,
    manifest: TraceManifest,
    trusted_strace: TrustedExecutable,
    *,
    inherited_fds: Sequence[int] = (),
) -> StraceLaunch:
    """Build a fixed fd-backed launch; PATH and a second pathname open are absent."""

    trace_text = _canonical_absolute(str(trace_path), label="private trace path")
    if trusted_strace.identity.sha256 != manifest.expected_strace_sha256:
        raise RuntimeOpenTraceError("fixed strace handle differs from manifest binding")
    values = (
        trusted_strace.launch_path,
        *STRACE_OPTIONS,
        f"--output={trace_text}",
        "--",
        *demotion_argv(manifest),
    )
    if any(item == "-p" or item == "--attach" or item.startswith("--attach=") for item in values):
        raise RuntimeOpenTraceError("ptrace attach mode is forbidden")
    normalized_fds = tuple(inherited_fds)
    if (
        any(type(item) is not int or item < 0 for item in normalized_fds)
        or len(set(normalized_fds)) != len(normalized_fds)
        or trusted_strace.descriptor in normalized_fds
    ):
        raise RuntimeOpenTraceError("inherited tracee descriptor set is invalid")
    return StraceLaunch(
        argv=values,
        pass_fds=tuple(sorted((*trusted_strace.pass_fds, *normalized_fds))),
    )


def launch_traced_process(
    trace_path: Path,
    manifest: TraceManifest,
    trusted_strace: TrustedExecutable,
    *,
    inherited_fds: Sequence[int] = (),
    stdin: Any = subprocess.DEVNULL,
) -> subprocess.Popen[bytes]:
    """Launch the sole fixed direct child with the pinned strace fd inherited."""

    launch = build_strace_launch(
        trace_path,
        manifest,
        trusted_strace,
        inherited_fds=inherited_fds,
    )
    return subprocess.Popen(
        launch.argv,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=manifest.working_directory,
        env=dict(manifest.environment),
        close_fds=True,
        pass_fds=launch.pass_fds,
    )


def verify_tracer_proc_exe(
    pid: int, trusted: TrustedExecutable | TrustedFileIdentity
) -> None:
    """Bind a running tracer PID to the already hashed fixed executable."""

    if type(pid) is not int or pid <= 1:
        raise RuntimeOpenTraceError("tracer PID is invalid")
    identity = trusted.identity if isinstance(trusted, TrustedExecutable) else trusted
    link = Path(f"/proc/{pid}/exe")
    try:
        target = os.readlink(link)
        metadata = link.stat()
    except OSError as exc:
        raise RuntimeOpenTraceError("tracer /proc executable identity is unavailable") from exc
    if (
        target != STRACE_COMMAND
        or target.endswith(" (deleted)")
        or (metadata.st_dev, metadata.st_ino) != (identity.device, identity.inode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise RuntimeOpenTraceError("tracer /proc executable identity mismatch")


def verify_traced_process(
    tracee_pid: int,
    identity: TrustedExecutable | TrustedFileIdentity,
    *,
    supervisor_pid: int | None = None,
    timeout_seconds: float = 1.0,
    require_sync_stop: bool = True,
) -> int:
    """Prove the tracee parent and obtain/verify its real ``TracerPid``.

    With ``--daemonize=grandchild`` the PID returned by ``Popen`` belongs to
    the tracee, not strace.  Treating that PID as the tracer is a security bug.
    Linux exposes the actual relationship in the tracee's status document.
    """

    if type(tracee_pid) is not int or tracee_pid <= 1:
        raise RuntimeOpenTraceError("tracee PID is invalid")
    expected_parent = os.getpid() if supervisor_pid is None else supervisor_pid
    if type(expected_parent) is not int or expected_parent <= 1:
        raise RuntimeOpenTraceError("supervisor PID is invalid")
    deadline = time.monotonic() + timeout_seconds
    expected_starttime = _proc_starttime(tracee_pid)
    if expected_starttime is None:
        raise RuntimeOpenTraceError("tracee process identity is unavailable")
    synchronized_stop = False
    while True:
        try:
            payload = Path(f"/proc/{tracee_pid}/status").read_bytes()
        except OSError as exc:
            raise RuntimeOpenTraceError("tracee status is unavailable") from exc
        if not payload.endswith(b"\n") or len(payload) > 1024 * 1024:
            raise RuntimeOpenTraceError("tracee status is truncated")
        try:
            lines = payload.decode("ascii").splitlines()
        except UnicodeError as exc:
            raise RuntimeOpenTraceError("tracee status is invalid") from exc
        fields: dict[str, str] = {}
        for line in lines:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key in {"PPid", "TracerPid", "State"}:
                if key in fields:
                    raise RuntimeOpenTraceError("tracee status identity is ambiguous")
                fields[key] = value.strip()
        if set(fields) != {"PPid", "TracerPid", "State"}:
            raise RuntimeOpenTraceError("tracee status identity is incomplete")
        parent = _positive_decimal(fields["PPid"], label="tracee parent PID")
        tracer = _positive_decimal(
            fields["TracerPid"], label="tracee tracer PID", allow_zero=True
        )
        if parent != expected_parent:
            raise RuntimeOpenTraceError("tracee is not a direct supervisor child")
        if _proc_starttime(tracee_pid) != expected_starttime:
            raise RuntimeOpenTraceError("tracee process identity changed")
        if require_sync_stop and not synchronized_stop:
            try:
                waited_pid, wait_status = os.waitpid(
                    tracee_pid, os.WNOHANG | os.WUNTRACED
                )
            except ChildProcessError as exc:
                raise RuntimeOpenTraceError(
                    "tracee stop cannot be verified by its supervisor"
                ) from exc
            if waited_pid == tracee_pid:
                if (
                    not os.WIFSTOPPED(wait_status)
                    or os.WSTOPSIG(wait_status) != signal.SIGSTOP
                ):
                    raise RuntimeOpenTraceError(
                        "tracee reported a non-handshake wait state"
                    )
                synchronized_stop = True
        # A real-parent wait status is distinct from transient ptrace syscall
        # stops (both may render as lower-case ``t`` in /proc status).
        if tracer > 1 and (synchronized_stop or not require_sync_stop):
            verify_tracer_proc_exe(tracer, identity)
            return tracer
        if time.monotonic() >= deadline:
            raise RuntimeOpenTraceError("tracee never acquired the fixed tracer")
        time.sleep(0.01)


def _parse_tracee_environment(payload: bytes) -> dict[str, str]:
    if not payload or len(payload) > 1024 * 1024 or not payload.endswith(b"\0"):
        raise RuntimeOpenTraceError("tracee environment is truncated")
    environment: dict[str, str] = {}
    for raw in payload[:-1].split(b"\0"):
        if not raw or b"=" not in raw:
            raise RuntimeOpenTraceError("tracee environment entry is invalid")
        raw_key, raw_value = raw.split(b"=", 1)
        try:
            key = raw_key.decode("utf-8", "strict")
            value = raw_value.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise RuntimeOpenTraceError("tracee environment is not UTF-8") from exc
        if (
            not key
            or key in environment
            or "=" in key
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in key)
            or "\x00" in value
        ):
            raise RuntimeOpenTraceError("tracee environment entry is ambiguous")
        environment[key] = value
    return environment


def verify_tracee_environment(
    tracee_pid: int,
    manifest: TraceManifest,
    identity: TrustedExecutable | TrustedFileIdentity,
    *,
    expected_parent: int,
    expected_tracer: int,
) -> str:
    if type(tracee_pid) is not int or tracee_pid <= 1:
        raise RuntimeOpenTraceError("tracee environment PID is invalid")
    before_starttime = _proc_starttime(tracee_pid)
    if before_starttime is None:
        raise RuntimeOpenTraceError("tracee environment process is unavailable")
    if (
        verify_traced_process(
            tracee_pid,
            identity,
            supervisor_pid=expected_parent,
            timeout_seconds=0.25,
            require_sync_stop=False,
        )
        != expected_tracer
    ):
        raise RuntimeOpenTraceError("tracee environment tracer identity changed")
    path = Path(f"/proc/{tracee_pid}/environ")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        payload = bytearray()
        while len(payload) <= 1024 * 1024:
            chunk = os.read(descriptor, min(64 * 1024, 1024 * 1024 + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
    finally:
        os.close(descriptor)
    if (
        _proc_starttime(tracee_pid) != before_starttime
        or verify_traced_process(
            tracee_pid,
            identity,
            supervisor_pid=expected_parent,
            timeout_seconds=0.25,
            require_sync_stop=False,
        )
        != expected_tracer
    ):
        raise RuntimeOpenTraceError("tracee environment process identity changed")
    environment = _parse_tracee_environment(bytes(payload))
    digest = _sha256(canonical_json(environment))
    if (
        environment != dict(manifest.environment)
        or digest != manifest.expected_child_environment_sha256
    ):
        raise RuntimeOpenTraceError("tracee environment differs from manifest")
    return digest


def verify_and_release_traced_process(
    tracee_pid: int,
    identity: TrustedExecutable | TrustedFileIdentity,
    manifest: TraceManifest,
    *,
    supervisor_pid: int | None = None,
    timeout_seconds: float = 1.0,
) -> int:
    """Verify the fixed SIGSTOP handshake and only then release the tracee."""

    tracer = verify_traced_process(
        tracee_pid,
        identity,
        supervisor_pid=supervisor_pid,
        timeout_seconds=timeout_seconds,
        require_sync_stop=True,
    )
    verify_tracee_environment(
        tracee_pid,
        manifest,
        identity,
        expected_parent=os.getpid() if supervisor_pid is None else supervisor_pid,
        expected_tracer=tracer,
    )
    try:
        os.kill(tracee_pid, signal.SIGCONT)
    except OSError as exc:
        raise RuntimeOpenTraceError("verified tracee cannot be released") from exc
    return tracer


def _hash_regular_snapshot(path: Path, metadata: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeOpenTraceError("watched regular file cannot be opened safely") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RuntimeOpenTraceError("watched file changed before hashing")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_WATCH_FILE_BYTES:
                raise RuntimeOpenTraceError("one watched file exceeds the size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in stable):
        raise RuntimeOpenTraceError("watched file changed while hashing")
    return digest.hexdigest()


def watch_tree_snapshot(roots: Sequence[str]) -> dict[str, Any]:
    """Capture separately pinned content and per-run object identities."""

    normalized = tuple(_canonical_absolute(root, label="watch root") for root in roots)
    if not normalized or list(normalized) != sorted(set(normalized)):
        raise RuntimeOpenTraceError("watch roots are not a non-empty sorted set")
    static_entries: list[dict[str, Any]] = []
    runtime_entries: list[dict[str, Any]] = []
    pending = [Path(root) for root in reversed(normalized)]
    while pending:
        path = pending.pop()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            parent, parent_metadata = _nearest_existing_parent(path)
            static_entries.append(
                {
                    "path": str(PurePosixPath(str(path))),
                    "kind": "absent",
                    "parent_path": str(PurePosixPath(str(parent))),
                    "parent_uid": parent_metadata.st_uid,
                    "parent_gid": parent_metadata.st_gid,
                    "parent_mode": f"{stat.S_IMODE(parent_metadata.st_mode):04o}",
                }
            )
            runtime_entries.append(
                {
                    "path": str(PurePosixPath(str(path))),
                    "kind": "absent",
                    "parent_path": str(PurePosixPath(str(parent))),
                    "parent_uid": parent_metadata.st_uid,
                    "parent_gid": parent_metadata.st_gid,
                    "parent_mode": f"{stat.S_IMODE(parent_metadata.st_mode):04o}",
                    "parent_device": parent_metadata.st_dev,
                    "parent_inode": parent_metadata.st_ino,
                    "parent_links": parent_metadata.st_nlink,
                    "parent_size": parent_metadata.st_size,
                    "parent_mtime_ns": parent_metadata.st_mtime_ns,
                    "parent_ctime_ns": parent_metadata.st_ctime_ns,
                }
            )
            continue
        except OSError as exc:
            raise RuntimeOpenTraceError("watched closure entry is unavailable") from exc
        static_common: dict[str, Any] = {
            "path": str(PurePosixPath(str(path))),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        runtime_common: dict[str, Any] = {
            **static_common,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "links": metadata.st_nlink,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
        }
        if stat.S_ISDIR(metadata.st_mode):
            static_entry = {**static_common, "kind": "directory"}
            runtime_entry = {**runtime_common, "kind": "directory"}
            try:
                children = sorted(
                    (Path(item.path) for item in os.scandir(path)),
                    key=lambda child: os.fsencode(child.name),
                )
            except OSError as exc:
                raise RuntimeOpenTraceError("watched directory cannot be enumerated") from exc
            pending.extend(reversed(children))
        elif stat.S_ISREG(metadata.st_mode):
            content_sha256 = _hash_regular_snapshot(path, metadata)
            static_entry = {
                **static_common,
                "kind": "regular",
                "size": metadata.st_size,
                "sha256": content_sha256,
            }
            runtime_entry = {
                **runtime_common,
                "kind": "regular",
                "sha256": content_sha256,
            }
        elif stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(path)
            except OSError as exc:
                raise RuntimeOpenTraceError("watched symlink target is unavailable") from exc
            static_entry = {**static_common, "kind": "symlink", "target": target}
            runtime_entry = {**runtime_common, "kind": "symlink", "target": target}
        else:
            static_entry = {
                **static_common,
                "kind": "special",
                "rdev": metadata.st_rdev,
            }
            runtime_entry = {
                **runtime_common,
                "kind": "special",
                "rdev": metadata.st_rdev,
            }
        static_entries.append(static_entry)
        runtime_entries.append(runtime_entry)
        if len(static_entries) > MAX_WATCH_ENTRIES:
            raise RuntimeOpenTraceError("watched closure exceeds the entry limit")
    static_entries.sort(key=lambda item: os.fsencode(item["path"]))
    runtime_entries.sort(key=lambda item: os.fsencode(item["path"]))
    paths = [item["path"] for item in static_entries]
    if len(paths) != len(set(paths)):
        raise RuntimeOpenTraceError("watched closure roots overlap")
    return {
        "schema_version": 2,
        "roots": list(normalized),
        "entry_count": len(static_entries),
        "static_entries_sha256": _sha256(canonical_json(static_entries)),
        "runtime_entries_sha256": _sha256(canonical_json(runtime_entries)),
    }


def capture_runtime_environment(manifest: TraceManifest) -> dict[str, Any]:
    """Capture an externally pinned closure and a run-local namespace receipt."""

    if os.name != "posix" or not Path("/proc/self/mountinfo").exists():
        raise RuntimeOpenTraceError("runtime environment capture requires Linux procfs")
    _validate_root_chain(Path(manifest.working_directory))
    try:
        mountinfo = Path("/proc/self/mountinfo").read_bytes()
        namespace = Path("/proc/self/ns/mnt").stat()
        expected_cwd = Path(manifest.working_directory).lstat()
        live_cwd_text = os.getcwd()
        proc_cwd_text = os.readlink("/proc/self/cwd")
        proc_cwd = Path("/proc/self/cwd").stat()
    except OSError as exc:
        raise RuntimeOpenTraceError("runtime namespace identity is unavailable") from exc
    live_cwd = _canonical_absolute(live_cwd_text, label="live supervisor cwd")
    proc_cwd_path = _canonical_absolute(proc_cwd_text, label="proc supervisor cwd")
    if (
        not mountinfo.endswith(b"\n")
        or len(mountinfo) > MAX_MOUNTINFO_BYTES
        or not stat.S_ISDIR(expected_cwd.st_mode)
        or stat.S_ISLNK(expected_cwd.st_mode)
        or live_cwd != manifest.working_directory
        or proc_cwd_path != manifest.working_directory
        or (proc_cwd.st_dev, proc_cwd.st_ino)
        != (expected_cwd.st_dev, expected_cwd.st_ino)
    ):
        raise RuntimeOpenTraceError("runtime namespace/cwd identity is invalid")
    tree = watch_tree_snapshot(manifest.watch_roots)
    return {
        "schema_version": 2,
        "static_closure": {
            "schema_version": 1,
            "working_directory": {
                "path": manifest.working_directory,
                "uid": expected_cwd.st_uid,
                "gid": expected_cwd.st_gid,
                "mode": f"{stat.S_IMODE(expected_cwd.st_mode):04o}",
            },
            "watch_roots_sha256": _sha256(canonical_json(manifest.watch_roots)),
            "watch_tree": {
                "schema_version": tree["schema_version"],
                "roots": tree["roots"],
                "entry_count": tree["entry_count"],
                "entries_sha256": tree["static_entries_sha256"],
            },
        },
        "dynamic_namespace_receipt": {
            "schema_version": 1,
            "mount_namespace": {
                "device": namespace.st_dev,
                "inode": namespace.st_ino,
            },
            "mountinfo_sha256": _sha256(mountinfo),
            "working_directory": {
                "path": manifest.working_directory,
                "device": proc_cwd.st_dev,
                "inode": proc_cwd.st_ino,
            },
            "watch_tree_runtime_entries_sha256": tree[
                "runtime_entries_sha256"
            ],
        },
    }


class MutationWatch:
    """Recursive Linux inotify guard that rejects every closure mutation."""

    def __init__(self, roots: Sequence[str]) -> None:
        self.roots = tuple(roots)
        self.descriptor: int | None = None
        self.watch_count = 0

    def __enter__(self) -> "MutationWatch":
        if os.name != "posix":
            raise RuntimeOpenTraceError("runtime mutation watch requires Linux")
        libc = ctypes.CDLL(None, use_errno=True)
        init = libc.inotify_init1
        init.argtypes = [ctypes.c_int]
        init.restype = ctypes.c_int
        add = libc.inotify_add_watch
        add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add.restype = ctypes.c_int
        descriptor = init(os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        if descriptor < 0:
            raise RuntimeOpenTraceError("inotify guard cannot be initialized")
        self.descriptor = descriptor
        seen: set[tuple[int, int]] = set()
        try:
            pending = [Path(root) for root in reversed(self.roots)]
            while pending:
                path = pending.pop()
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    parent, parent_metadata = _nearest_existing_parent(path)
                    identity = (parent_metadata.st_dev, parent_metadata.st_ino)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    watch = add(
                        descriptor,
                        os.fsencode(parent),
                        IN_REJECT_MASK | IN_DONT_FOLLOW,
                    )
                    if watch < 0:
                        raise RuntimeOpenTraceError("inotify cannot watch an absent closure parent")
                    continue
                identity = (metadata.st_dev, metadata.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                watch = add(
                    descriptor,
                    os.fsencode(path),
                    IN_REJECT_MASK | IN_DONT_FOLLOW,
                )
                if watch < 0:
                    raise RuntimeOpenTraceError("inotify cannot watch a closure entry")
                if stat.S_ISDIR(metadata.st_mode):
                    pending.extend(
                        reversed(
                            sorted(
                                (Path(item.path) for item in os.scandir(path)),
                                key=lambda child: os.fsencode(child.name),
                            )
                        )
                    )
                if len(seen) > MAX_WATCH_ENTRIES:
                    raise RuntimeOpenTraceError("inotify closure exceeds the watch limit")
            self.watch_count = len(seen)
            if self.watch_count == 0:
                raise RuntimeOpenTraceError("inotify installed no closure watches")
            return self
        except BaseException:
            os.close(descriptor)
            self.descriptor = None
            raise

    def assert_clean(self) -> None:
        if self.descriptor is None:
            raise RuntimeOpenTraceError("inotify guard is not active")
        try:
            payload = os.read(self.descriptor, 1024 * 1024)
        except BlockingIOError:
            return
        if payload:
            raise RuntimeOpenTraceError("watched closure changed during runtime tracing")

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


class RuntimeEnvironmentGuard:
    """Pre/watch/post gate for one direct-child trace execution."""

    def __init__(self, manifest: TraceManifest) -> None:
        self.manifest = manifest
        self.before: dict[str, Any] | None = None
        self.watch: MutationWatch | None = None
        self.finished = False
        self.dynamic_receipt_sha256: str | None = None

    def __enter__(self) -> "RuntimeEnvironmentGuard":
        before = capture_runtime_environment(self.manifest)
        if (
            _sha256(canonical_json(before["static_closure"]))
            != self.manifest.expected_static_closure_sha256
        ):
            raise RuntimeOpenTraceError("pre-trace static closure differs from expectation")
        watch = MutationWatch(self.manifest.watch_roots)
        watch.__enter__()
        try:
            after_watch = capture_runtime_environment(self.manifest)
            watch.assert_clean()
            if after_watch != before:
                raise RuntimeOpenTraceError("runtime environment changed while watches were installed")
        except BaseException:
            watch.__exit__(None, None, None)
            raise
        self.before = before
        self.watch = watch
        return self

    def finish(self) -> None:
        if self.finished or self.before is None or self.watch is None:
            raise RuntimeOpenTraceError("runtime environment guard state is invalid")
        self.watch.assert_clean()
        after = capture_runtime_environment(self.manifest)
        self.watch.assert_clean()
        if after != self.before:
            raise RuntimeOpenTraceError("post-trace runtime environment changed")
        self.dynamic_receipt_sha256 = _sha256(
            canonical_json(after["dynamic_namespace_receipt"])
        )
        self.finished = True

    def receipt(self) -> dict[str, Any]:
        if not self.finished or self.dynamic_receipt_sha256 is None:
            raise RuntimeOpenTraceError("runtime environment receipt is unavailable")
        return {
            "schema_version": 1,
            "static_closure_sha256": self.manifest.expected_static_closure_sha256,
            "dynamic_namespace_receipt_sha256": self.dynamic_receipt_sha256,
        }

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        unfinished = _kind is None and not self.finished
        exit_error: BaseException | None = None
        if (
            _kind is None
            and self.finished
            and self.before is not None
            and self.watch is not None
        ):
            try:
                self.watch.assert_clean()
                if capture_runtime_environment(self.manifest) != self.before:
                    raise RuntimeOpenTraceError(
                        "runtime environment changed after finish verification"
                    )
                self.watch.assert_clean()
            except BaseException as exc:
                exit_error = exc
        if self.watch is not None:
            self.watch.__exit__(None, None, None)
            self.watch = None
        if exit_error is not None:
            raise exit_error
        if unfinished:
            raise RuntimeOpenTraceError(
                "runtime environment guard exited without finish verification"
            )


def _proc_starttime(pid: int, *, proc_root: Path = Path("/proc")) -> int | None:
    """Return Linux proc stat starttime, or ``None`` only for an absent PID."""

    if type(pid) is not int or pid <= 1:
        raise RuntimeOpenTraceError("lease PID is invalid")
    try:
        payload = (proc_root / str(pid) / "stat").read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeOpenTraceError("lease process identity is unavailable") from exc
    if not payload or len(payload) > 1024 * 1024 or b"\x00" in payload:
        raise RuntimeOpenTraceError("lease process stat is invalid")
    try:
        text = payload.decode("ascii").strip()
    except UnicodeError as exc:
        raise RuntimeOpenTraceError("lease process stat is invalid") from exc
    marker = text.rfind(") ")
    if not text.startswith(f"{pid} (") or marker < len(str(pid)) + 2:
        raise RuntimeOpenTraceError("lease process stat is ambiguous")
    fields = text[marker + 2 :].split()
    if len(fields) <= 19:
        raise RuntimeOpenTraceError("lease process stat is truncated")
    return _positive_decimal(fields[19], label="lease process starttime")


def _staging_name(run_id: str, pid: int, starttime: int) -> str:
    if not isinstance(run_id, str) or NAME.fullmatch(run_id) is None:
        raise RuntimeOpenTraceError("runtime trace run id is invalid")
    if type(pid) is not int or pid <= 1 or type(starttime) is not int or starttime <= 0:
        raise RuntimeOpenTraceError("runtime trace lease identity is invalid")
    return f"trace-{pid}-{starttime}-{_sha256(run_id.encode('utf-8'))[:16]}"


def _lease_document(name: str, run_id: str) -> dict[str, Any]:
    match = STAGING_DIRECTORY.fullmatch(name)
    if match is None:
        raise RuntimeOpenTraceError("private staging directory name is invalid")
    return {
        "schema_version": 1,
        "supervisor_pid": int(match.group(1)),
        "supervisor_starttime": int(match.group(2)),
        "run_id_sha256": _sha256(run_id.encode("utf-8")),
    }


def _seal_journal_document(
    destination: Path,
    metadata: os.stat_result,
    digest: str,
    *,
    target_id: str,
    manifest_sha256: str,
    expected_leader_pid: int,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "target_id": target_id,
        "manifest_sha256": manifest_sha256,
        "expected_leader_pid": expected_leader_pid,
        "destination": str(destination),
        "trace_device": metadata.st_dev,
        "trace_inode": metadata.st_ino,
        "trace_size": metadata.st_size,
        "trace_sha256": digest,
    }


def _parse_seal_journal(payload: bytes) -> dict[str, Any]:
    try:
        document = json.loads(
            payload, object_pairs_hook=_pairs, parse_constant=_constant
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RuntimeOpenTraceError("private seal journal is invalid") from exc
    if (
        payload != canonical_json(document) + b"\n"
        or type(document) is not dict
        or set(document)
        != {
            "schema_version",
            "target_id",
            "manifest_sha256",
            "expected_leader_pid",
            "destination",
            "trace_device",
            "trace_inode",
            "trace_size",
            "trace_sha256",
        }
        or not _schema_version_is_one(document.get("schema_version"))
        or not isinstance(document.get("target_id"), str)
        or NAME.fullmatch(document["target_id"]) is None
        or not isinstance(document.get("manifest_sha256"), str)
        or HEX64.fullmatch(document["manifest_sha256"]) is None
        or type(document.get("expected_leader_pid")) is not int
        or document["expected_leader_pid"] <= 1
        or not isinstance(document.get("destination"), str)
        or any(
            type(document.get(field)) is not int or document[field] <= 0
            for field in ("trace_device", "trace_inode")
        )
        or type(document.get("trace_size")) is not int
        or document["trace_size"] < 0
        or not isinstance(document.get("trace_sha256"), str)
        or HEX64.fullmatch(document["trace_sha256"]) is None
    ):
        raise RuntimeOpenTraceError("private seal journal identity is invalid")
    destination = Path(document["destination"])
    if (
        not destination.is_absolute()
        or destination.name != destination.as_posix().rsplit("/", 1)[-1]
        or not destination.name.endswith(".strace")
        or NAME.fullmatch(destination.name[:-7]) is None
        or destination.name != f"{document['target_id']}.strace"
    ):
        raise RuntimeOpenTraceError("private seal destination is invalid")
    return document


def _seal_sidecar_name(target_id: str) -> str:
    if not isinstance(target_id, str) or NAME.fullmatch(target_id) is None:
        raise RuntimeOpenTraceError("private seal target is invalid")
    return f".{target_id}{SEAL_SIDECAR_SUFFIX}"


def _read_seal_journal_at(directory_fd: int, name: str) -> dict[str, Any]:
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or metadata.st_nlink != 1
            or metadata.st_size > 16 * 1024
        ):
            raise RuntimeOpenTraceError("private seal journal identity is unsafe")
        payload = os.read(descriptor, 16 * 1024 + 1)
        if len(payload) != metadata.st_size:
            raise RuntimeOpenTraceError("private seal journal read was unstable")
        after = os.fstat(descriptor)
        if any(
            getattr(metadata, field) != getattr(after, field)
            for field in (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
        ):
            raise RuntimeOpenTraceError("private seal journal changed while reading")
    finally:
        os.close(descriptor)
    return _parse_seal_journal(payload)


def _write_seal_journal_at(
    directory_fd: int, name: str, journal: Mapping[str, Any]
) -> None:
    payload = canonical_json(journal) + b"\n"
    descriptor = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o400,
        dir_fd=directory_fd,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RuntimeOpenTraceError("private seal journal write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_destination_seal_journal(
    directory_fd: int, journal: Mapping[str, Any]
) -> str:
    name = _seal_sidecar_name(str(journal["target_id"]))
    try:
        observed = _read_seal_journal_at(directory_fd, name)
    except FileNotFoundError:
        _write_seal_journal_at(directory_fd, name, journal)
        observed = _read_seal_journal_at(directory_fd, name)
    if observed != dict(journal):
        raise RuntimeOpenTraceError("private destination seal journal differs")
    os.fsync(directory_fd)
    return name


def verify_private_seal_sidecar(
    destination: Path, expected: Mapping[str, Any], *, journal_required: bool = True
) -> dict[str, Any]:
    """Revalidate a sealed raw trace and its pending MANIFEST transaction."""

    destination = Path(destination)
    directory_fd = _open_private_destination_parent(destination)
    try:
        target_id = expected.get("target_id") if type(expected) is dict else None
        if (
            not isinstance(target_id, str)
            or destination.name != f"{target_id}.strace"
        ):
            raise RuntimeOpenTraceError("private seal sidecar expectation is invalid")
        name = _seal_sidecar_name(target_id)
        try:
            journal = _read_seal_journal_at(directory_fd, name)
        except FileNotFoundError:
            if journal_required:
                raise RuntimeOpenTraceError(
                    "private seal sidecar journal is missing"
                ) from None
            journal = {
                "schema_version": 1,
                "target_id": target_id,
                "manifest_sha256": expected.get("manifest_sha256"),
                "expected_leader_pid": expected.get("expected_leader_pid"),
                "destination": str(destination),
                "trace_device": expected.get("device"),
                "trace_inode": expected.get("inode"),
                "trace_size": expected.get("size"),
                "trace_sha256": expected.get("sha256"),
            }
            _parse_seal_journal(canonical_json(journal) + b"\n")
        bound = {
            "target_id": journal["target_id"],
            "manifest_sha256": journal["manifest_sha256"],
            "expected_leader_pid": journal["expected_leader_pid"],
            "path": journal["destination"],
            "device": journal["trace_device"],
            "inode": journal["trace_inode"],
            "size": journal["trace_size"],
            "mode": "0400",
            "sha256": journal["trace_sha256"],
        }
        if any(expected.get(key) != value for key, value in bound.items()):
            raise RuntimeOpenTraceError("private seal sidecar binding differs")
        _verify_sealed_trace_at(directory_fd, destination.name, journal)
        return journal
    finally:
        os.close(directory_fd)


def _open_private_destination_parent(destination: Path) -> int:
    _validate_root_chain(destination.parent)
    root = PRIVATE_EVIDENCE_PARENT.resolve(strict=True)
    parent = destination.parent.resolve(strict=True)
    if root != parent and root not in parent.parents:
        raise RuntimeOpenTraceError("private seal destination escaped evidence storage")
    descriptor = os.open(
        parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (metadata.st_uid, metadata.st_gid) != (0, 0)
    ):
        os.close(descriptor)
        raise RuntimeOpenTraceError("private seal destination parent is unsafe")
    return descriptor


def _verify_sealed_trace_at(
    directory_fd: int, name: str, journal: Mapping[str, Any]
) -> os.stat_result:
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino, metadata.st_size)
            != (
                journal["trace_device"],
                journal["trace_inode"],
                journal["trace_size"],
            )
            or _descriptor_digest(descriptor, metadata.st_size)
            != journal["trace_sha256"]
        ):
            raise RuntimeOpenTraceError("sealed private trace identity changed")
        return metadata
    finally:
        os.close(descriptor)


def recover_stale_private_staging(
    *, parent: Path = STAGING_PARENT, proc_root: Path = Path("/proc")
) -> tuple[str, ...]:
    """Remove only strictly shaped staging owned by a dead/reused supervisor.

    The PID and proc starttime live in the directory name, so SIGKILL between
    ``mkdir`` and lease-file creation is still recoverable without an age-based
    deletion heuristic.  Live or ambiguous directories are never removed.
    """

    if os.name != "posix" or os.geteuid() != 0:
        raise RuntimeOpenTraceError("private trace recovery requires Linux root")
    _validate_root_chain(parent)
    parent_metadata = parent.lstat()
    if stat.S_IMODE(parent_metadata.st_mode) != 0o700:
        raise RuntimeOpenTraceError("private trace staging parent is not mode 0700")
    recovered: list[str] = []
    try:
        entries = sorted(os.scandir(parent), key=lambda entry: os.fsencode(entry.name))
    except OSError as exc:
        raise RuntimeOpenTraceError("private trace staging cannot be enumerated") from exc
    for entry in entries:
        match = STAGING_DIRECTORY.fullmatch(entry.name)
        if match is None:
            raise RuntimeOpenTraceError("private trace staging contains an unknown entry")
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise RuntimeOpenTraceError("private trace staging identity is unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
        ):
            raise RuntimeOpenTraceError("private trace staging directory is unsafe")
        pid = int(match.group(1))
        starttime = int(match.group(2))
        observed_starttime = _proc_starttime(pid, proc_root=proc_root)
        if observed_starttime == starttime:
            continue
        directory_fd = os.open(
            entry.path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            members = sorted(
                item.name for item in os.scandir(directory_fd)
            )
            if any(
                item not in {"lease.json", "trace.log", SEAL_JOURNAL_NAME}
                for item in members
            ):
                raise RuntimeOpenTraceError("stale private staging has unknown members")
            for name in members:
                member = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                expected_modes = (
                    {0o400}
                    if name in {"lease.json", SEAL_JOURNAL_NAME}
                    else ({0o600, 0o400} if SEAL_JOURNAL_NAME in members else {0o600})
                )
                if (
                    not stat.S_ISREG(member.st_mode)
                    or stat.S_IMODE(member.st_mode) not in expected_modes
                    or (member.st_uid, member.st_gid) != (0, 0)
                    or member.st_nlink != 1
                ):
                    raise RuntimeOpenTraceError("stale private staging member is unsafe")
            if "lease.json" in members:
                lease, _identity = _read_trusted_regular(
                    Path(entry.path) / "lease.json",
                    None,
                    expected_mode=0o400,
                    max_bytes=4096,
                )
                try:
                    document = json.loads(
                        lease, object_pairs_hook=_pairs, parse_constant=_constant
                    )
                except (json.JSONDecodeError, UnicodeError) as exc:
                    raise RuntimeOpenTraceError("private staging lease is invalid") from exc
                if (
                    not lease.endswith(b"\n")
                    or lease != canonical_json(document) + b"\n"
                    or type(document) is not dict
                    or set(document)
                    != {
                        "schema_version",
                        "supervisor_pid",
                        "supervisor_starttime",
                        "run_id_sha256",
                    }
                    or not _schema_version_is_one(document.get("schema_version"))
                    or document.get("supervisor_pid") != pid
                    or document.get("supervisor_starttime") != starttime
                    or not isinstance(document.get("run_id_sha256"), str)
                    or HEX64.fullmatch(document["run_id_sha256"]) is None
                    or not document["run_id_sha256"].startswith(match.group(3))
                ):
                    raise RuntimeOpenTraceError("private staging lease identity is invalid")
            if SEAL_JOURNAL_NAME in members:
                journal_payload, _journal_identity = _read_trusted_regular(
                    Path(entry.path) / SEAL_JOURNAL_NAME,
                    None,
                    expected_mode=0o400,
                    max_bytes=16 * 1024,
                )
                journal = _parse_seal_journal(journal_payload)
                destination = Path(journal["destination"])
                destination_fd = _open_private_destination_parent(destination)
                try:
                    source_exists = "trace.log" in members
                    try:
                        os.stat(
                            destination.name,
                            dir_fd=destination_fd,
                            follow_symlinks=False,
                        )
                        destination_exists = True
                    except FileNotFoundError:
                        destination_exists = False
                    if source_exists == destination_exists:
                        raise RuntimeOpenTraceError(
                            "private seal journal has ambiguous source/destination"
                        )
                    if source_exists:
                        source_fd = os.open(
                            "trace.log",
                            os.O_RDONLY
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=directory_fd,
                        )
                        try:
                            source = os.fstat(source_fd)
                            if stat.S_IMODE(source.st_mode) == 0o600:
                                os.fchmod(source_fd, 0o400)
                                source = os.fstat(source_fd)
                            # A crash can leave mode 0400 after fchmod but
                            # before the original fsync.  Recovery must flush
                            # either starting mode before publication.
                            os.fsync(source_fd)
                            if (
                                not stat.S_ISREG(source.st_mode)
                                or stat.S_IMODE(source.st_mode) != 0o400
                                or (source.st_uid, source.st_gid) != (0, 0)
                                or source.st_nlink != 1
                                or (source.st_dev, source.st_ino, source.st_size)
                                != (
                                    journal["trace_device"],
                                    journal["trace_inode"],
                                    journal["trace_size"],
                                )
                                or _descriptor_digest(source_fd, source.st_size)
                                != journal["trace_sha256"]
                            ):
                                raise RuntimeOpenTraceError(
                                    "recoverable private trace identity changed"
                                )
                        finally:
                            os.close(source_fd)
                        if os.fstat(destination_fd).st_dev != journal["trace_device"]:
                            raise RuntimeOpenTraceError(
                                "recoverable private trace is cross-filesystem"
                            )
                        _renameat2_noreplace(
                            directory_fd,
                            "trace.log",
                            destination_fd,
                            destination.name,
                        )
                        os.fsync(destination_fd)
                        os.fsync(directory_fd)
                    _verify_sealed_trace_at(
                        destination_fd, destination.name, journal
                    )
                    _ensure_destination_seal_journal(destination_fd, journal)
                    # This fsync is unconditional, including the
                    # destination-already-existed recovery branch.  The
                    # staging journal is not cleared until both the raw inode
                    # and its destination transaction journal are durable.
                    os.fsync(destination_fd)
                finally:
                    os.close(destination_fd)
                os.unlink(SEAL_JOURNAL_NAME, dir_fd=directory_fd)
                members.remove(SEAL_JOURNAL_NAME)
                if "trace.log" in members:
                    members.remove("trace.log")
            elif "trace.log" in members:
                os.unlink("trace.log", dir_fd=directory_fd)
                members.remove("trace.log")
            if "lease.json" in members:
                os.unlink("lease.json", dir_fd=directory_fd)
                members.remove("lease.json")
            if members:
                raise RuntimeOpenTraceError("stale private staging cleanup is incomplete")
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        os.rmdir(entry.path)
        parent_fd = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        recovered.append(entry.name)
    return tuple(recovered)


class PrivateTraceStaging:
    """Root-only O_EXCL/0600 staging sealed as mode-0400 audit evidence."""

    def __init__(self, run_id: str, *, parent: Path = STAGING_PARENT) -> None:
        if not isinstance(run_id, str) or NAME.fullmatch(run_id) is None:
            raise RuntimeOpenTraceError("runtime trace run id is invalid")
        parent = Path(parent)
        if not parent.is_absolute():
            raise RuntimeOpenTraceError("private trace staging parent is invalid")
        self.run_id = run_id
        pid = os.getpid()
        starttime = _proc_starttime(pid) if os.name == "posix" else None
        if starttime is None:
            raise RuntimeOpenTraceError("runtime trace supervisor identity is unavailable")
        self.staging_parent = parent
        self.directory = parent / _staging_name(run_id, pid, starttime)
        self.path = self.directory / "trace.log"
        self.lease_path = self.directory / "lease.json"
        self._directory_fd: int | None = None
        self._trace_identity: tuple[int, int] | None = None
        self._lease_identity: tuple[int, int] | None = None
        self._sealed = False
        self._seal_incomplete = False

    def __enter__(self) -> "PrivateTraceStaging":
        if os.name != "posix" or os.geteuid() != 0:
            raise RuntimeOpenTraceError("private trace staging requires the Linux root supervisor")
        _validate_root_chain(self.staging_parent)
        parent = self.staging_parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or (parent.st_uid, parent.st_gid) != (0, 0)
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise RuntimeOpenTraceError("private trace staging parent is not mode 0700")
        recover_stale_private_staging(parent=self.staging_parent)
        try:
            os.mkdir(self.directory, 0o700)
            directory_fd = os.open(
                self.directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            self._directory_fd = directory_fd
            lease_document = _lease_document(self.directory.name, self.run_id)
            lease_descriptor = os.open(
                "lease.json",
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o400,
                dir_fd=directory_fd,
            )
            try:
                lease_payload = canonical_json(lease_document) + b"\n"
                if os.write(lease_descriptor, lease_payload) != len(lease_payload):
                    raise RuntimeOpenTraceError("private staging lease write was incomplete")
                os.fsync(lease_descriptor)
                lease_metadata = os.fstat(lease_descriptor)
            finally:
                os.close(lease_descriptor)
            descriptor = os.open(
                "trace.log",
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_fd,
            )
            metadata = os.fstat(descriptor)
            os.close(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or (metadata.st_uid, metadata.st_gid) != (0, 0)
                or metadata.st_nlink != 1
            ):
                raise RuntimeOpenTraceError("private raw trace identity is invalid")
            if (
                not stat.S_ISREG(lease_metadata.st_mode)
                or stat.S_IMODE(lease_metadata.st_mode) != 0o400
                or (lease_metadata.st_uid, lease_metadata.st_gid) != (0, 0)
                or lease_metadata.st_nlink != 1
            ):
                raise RuntimeOpenTraceError("private staging lease identity is invalid")
            self._trace_identity = (metadata.st_dev, metadata.st_ino)
            self._lease_identity = (lease_metadata.st_dev, lease_metadata.st_ino)
            os.fsync(directory_fd)
            return self
        except BaseException:
            if self._directory_fd is not None:
                os.close(self._directory_fd)
                self._directory_fd = None
            try:
                if os.path.lexists(self.path):
                    os.unlink(self.path)
                if os.path.lexists(self.lease_path):
                    os.unlink(self.lease_path)
                if os.path.lexists(self.directory):
                    os.rmdir(self.directory)
            except OSError:
                pass
            raise

    def assert_private_identity(self) -> None:
        if (
            self._directory_fd is None
            or self._trace_identity is None
            or self._lease_identity is None
        ):
            raise RuntimeOpenTraceError("private trace staging is not active")
        try:
            metadata = os.stat("trace.log", dir_fd=self._directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise RuntimeOpenTraceError("private raw trace disappeared") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or metadata.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != self._trace_identity
        ):
            raise RuntimeOpenTraceError("private raw trace identity changed")
        lease = os.stat("lease.json", dir_fd=self._directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(lease.st_mode)
            or stat.S_IMODE(lease.st_mode) != 0o400
            or (lease.st_uid, lease.st_gid) != (0, 0)
            or lease.st_nlink != 1
            or (lease.st_dev, lease.st_ino) != self._lease_identity
        ):
            raise RuntimeOpenTraceError("private staging lease identity changed")

    def seal_to(
        self,
        destination: Path,
        *,
        target_id: str,
        manifest_sha256: str,
        expected_leader_pid: int,
    ) -> dict[str, Any]:
        """Move the validated raw inode into a root-only audit sidecar."""

        self.assert_private_identity()
        destination = Path(destination)
        if (
            not isinstance(target_id, str)
            or NAME.fullmatch(target_id) is None
            or target_id != self.run_id
            or destination.name != f"{target_id}.strace"
            or not isinstance(manifest_sha256, str)
            or HEX64.fullmatch(manifest_sha256) is None
            or type(expected_leader_pid) is not int
            or expected_leader_pid <= 1
        ):
            raise RuntimeOpenTraceError("private trace audit binding is invalid")
        _validate_root_chain(destination.parent)
        parent = destination.parent.lstat()
        if (
            self._sealed
            or self._seal_incomplete
            or os.path.lexists(destination)
            or os.path.lexists(destination.parent / _seal_sidecar_name(target_id))
            or not stat.S_ISDIR(parent.st_mode)
            or stat.S_IMODE(parent.st_mode) != 0o700
            or (parent.st_uid, parent.st_gid) != (0, 0)
            or parent.st_dev != self._trace_identity[0]
        ):
            raise RuntimeOpenTraceError(
                "private trace audit destination is invalid or cross-filesystem"
            )
        destination_fd = _open_private_destination_parent(destination)
        journal_created = False
        try:
            descriptor = os.open(
                "trace.log",
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._directory_fd,
            )
            try:
                metadata = os.fstat(descriptor)
                digest = _descriptor_digest(descriptor, metadata.st_size)
                journal = _seal_journal_document(
                    destination,
                    metadata,
                    digest,
                    target_id=target_id,
                    manifest_sha256=manifest_sha256,
                    expected_leader_pid=expected_leader_pid,
                )
                _write_seal_journal_at(
                    self._directory_fd,
                    SEAL_JOURNAL_NAME,
                    journal,
                )
                journal_created = True
                self._seal_incomplete = True
                os.fsync(self._directory_fd)
                _crash_injection_gate("seal-after-journal-fsync")
                os.fchmod(descriptor, 0o400)
                _crash_injection_gate(
                    "seal-after-source-chmod-before-fsync"
                )
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
                if (
                    stat.S_IMODE(metadata.st_mode) != 0o400
                    or _descriptor_digest(descriptor, metadata.st_size) != digest
                ):
                    raise RuntimeOpenTraceError(
                        "private trace changed while becoming read-only"
                    )
                _crash_injection_gate("seal-after-source-fsync")
            finally:
                os.close(descriptor)
            _renameat2_noreplace(
                self._directory_fd,
                "trace.log",
                destination_fd,
                destination.name,
            )
            _crash_injection_gate("seal-after-rename-before-directory-fsync")
            os.fsync(destination_fd)
            os.fsync(self._directory_fd)
            _crash_injection_gate("seal-after-directory-fsync")
            metadata = _verify_sealed_trace_at(
                destination_fd, destination.name, journal
            )
            _ensure_destination_seal_journal(destination_fd, journal)
            _crash_injection_gate("seal-after-sidecar-journal-fsync")
            os.unlink(SEAL_JOURNAL_NAME, dir_fd=self._directory_fd)
            os.fsync(self._directory_fd)
            _crash_injection_gate("seal-after-staging-journal-cleanup")
        except BaseException:
            if not journal_created:
                self._seal_incomplete = False
                try:
                    os.unlink(SEAL_JOURNAL_NAME, dir_fd=self._directory_fd)
                    os.fsync(self._directory_fd)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(destination_fd)
        self._sealed = True
        self._seal_incomplete = False
        return {
            "path": str(destination),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
            "mode": "0400",
            "sha256": digest,
        }

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        if self._directory_fd is None:
            return
        if self._seal_incomplete:
            os.close(self._directory_fd)
            self._directory_fd = None
            return
        if not self._sealed:
            self.assert_private_identity()
            os.unlink("trace.log", dir_fd=self._directory_fd)
        else:
            lease = os.stat(
                "lease.json", dir_fd=self._directory_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(lease.st_mode)
                or (lease.st_dev, lease.st_ino) != self._lease_identity
            ):
                raise RuntimeOpenTraceError("sealed trace lease identity changed")
        os.unlink("lease.json", dir_fd=self._directory_fd)
        os.fsync(self._directory_fd)
        os.close(self._directory_fd)
        self._directory_fd = None
        os.rmdir(self.directory)


def _strip_pid(line: str, expected_leader_pid: int | None) -> tuple[str, str]:
    match = PID_PREFIX.match(line)
    if match is None:
        if expected_leader_pid is None or expected_leader_pid <= 1:
            raise RuntimeOpenTraceError(
                "unprefixed trace line has no independent leader PID binding"
            )
        return str(expected_leader_pid), line
    return match.group(1) or match.group(2), line[match.end() :]


def _contains_bare_ellipsis(value: str) -> bool:
    quoted = False
    escaped = False
    index = 0
    while index < len(value):
        character = value[index]
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            index += 1
            continue
        if character == '"':
            quoted = True
            index += 1
            continue
        if value.startswith("...", index):
            return True
        index += 1
    return quoted or escaped


def _split_call(value: str) -> tuple[str, str, str]:
    match = SYSCALL_NAME.match(value)
    if match is None:
        raise RuntimeOpenTraceError("trace contains an unknown line")
    name = match.group(1)
    depth = 1
    quoted = False
    escaped = False
    index = match.end()
    while index < len(value):
        character = value[index]
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                delimiter = re.match(r" += ", value[index + 1 :])
                if delimiter is None:
                    raise RuntimeOpenTraceError("trace syscall result delimiter is invalid")
                return (
                    name,
                    value[match.end() : index],
                    value[index + 1 + delimiter.end() :],
                )
        index += 1
    raise RuntimeOpenTraceError("trace syscall is truncated")


def _split_arguments(value: str) -> list[str]:
    result: list[str] = []
    start = 0
    stack: list[str] = []
    quoted = False
    escaped = False
    pairs = {")": "(", "]": "[", "}": "{"}
    for index, character in enumerate(value):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
        elif character in "([{":
            stack.append(character)
        elif character in ")]}":
            if not stack or stack.pop() != pairs[character]:
                raise RuntimeOpenTraceError("trace syscall arguments are unbalanced")
        elif character == "," and not stack:
            result.append(value[start:index].strip())
            start = index + 1
    if quoted or escaped or stack:
        raise RuntimeOpenTraceError("trace syscall arguments are truncated")
    result.append(value[start:].strip())
    return result


def _decode_c_string(token: str, *, label: str) -> str:
    if not token.startswith('"'):
        raise RuntimeOpenTraceError(f"{label} is not a complete string")
    quoted = True
    escaped = False
    end = None
    for index, character in enumerate(token[1:], start=1):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quoted = False
            end = index + 1
            break
    if quoted or escaped or end is None or token[end:].strip():
        raise RuntimeOpenTraceError(f"{label} is truncated or annotated")
    try:
        value = ast.literal_eval(token[:end])
    except (SyntaxError, ValueError) as exc:
        raise RuntimeOpenTraceError(f"{label} escape sequence is invalid") from exc
    if (
        not isinstance(value, str)
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise RuntimeOpenTraceError(f"{label} contains an invalid character")
    return value


def _decode_argv(token: str) -> tuple[str, ...]:
    token = token.strip()
    if not token.startswith("[") or not token.endswith("]"):
        raise RuntimeOpenTraceError("execve argv is truncated")
    inner = token[1:-1].strip()
    if not inner:
        raise RuntimeOpenTraceError("execve argv is empty")
    items = _split_arguments(inner)
    if len(items) > MAX_ARGV_ITEMS:
        raise RuntimeOpenTraceError("execve argv is too large")
    return tuple(_decode_c_string(item, label="execve argument") for item in items)


def _success_result(result: str) -> tuple[bool, str | None, str | None]:
    if result.startswith("-1 "):
        match = re.fullmatch(r"-1 (E[A-Z0-9_]{1,63}) \([^\r\n]*\)", result)
        if match is None:
            raise RuntimeOpenTraceError("failed syscall result is truncated")
        return False, None, match.group(1)
    match = re.fullmatch(r"([0-9]+)(?:<(.*)>)?", result)
    if match is None:
        raise RuntimeOpenTraceError("syscall result is unknown or truncated")
    return True, match.group(2), None


def _result_number(result: str) -> int:
    match = re.match(r"([0-9]+)", result)
    if match is None:
        raise RuntimeOpenTraceError("successful syscall result has no integer value")
    return int(match.group(1))


def _fd_number(token: str) -> int:
    match = re.match(r"([0-9]+)(?:<.*>)?$", token.strip())
    if match is None:
        raise RuntimeOpenTraceError("socket syscall fd is not decoded")
    return int(match.group(1))


def _open_access(name: str, arguments: Sequence[str]) -> tuple[str, ...]:
    if name == "creat":
        return ("create", "truncate", "write")
    index = 1 if name == "open" else 2
    if len(arguments) <= index:
        raise RuntimeOpenTraceError("open flags are missing")
    rendered = arguments[index]
    if name == "openat2":
        match = re.search(r"(?:^|[,{]\s*)flags=([^,}]+)", rendered)
        if match is None:
            raise RuntimeOpenTraceError("openat2 flags are not decoded")
        rendered = match.group(1).strip()
    flags = set(rendered.split("|"))
    harmless = {
        "0",
        "O_RDONLY",
        "O_CLOEXEC",
        "O_NONBLOCK",
        "O_NOCTTY",
        "O_LARGEFILE",
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_SYNC",
        "O_DSYNC",
        "O_DIRECT",
        "O_EXCL",
        "O_NOATIME",
    }
    material = {
        "O_WRONLY",
        "O_RDWR",
        "O_CREAT",
        "O_TRUNC",
        "O_APPEND",
        "O_TMPFILE",
        "O_PATH",
    }
    if not flags or any(flag not in harmless | material for flag in flags):
        raise RuntimeOpenTraceError("open flags contain an unknown access mode")
    if "O_PATH" in flags:
        if flags & {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND", "O_TMPFILE"}:
            raise RuntimeOpenTraceError("O_PATH is combined with a mutation flag")
        return ("metadata",)
    access: set[str] = set()
    if "O_WRONLY" in flags:
        access.add("write")
    elif "O_RDWR" in flags:
        access.update(("read", "write"))
    else:
        access.add("read")
    if "O_CREAT" in flags or "O_TMPFILE" in flags:
        access.add("create")
        access.add("write")
    if "O_TRUNC" in flags:
        access.update(("truncate", "write"))
    if "O_APPEND" in flags:
        access.update(("append", "write"))
    return tuple(sorted(access))


def _dirfd_base(token: str, cwd: str) -> str:
    if token == "AT_FDCWD" or token.startswith("AT_FDCWD<"):
        return cwd
    match = re.fullmatch(r"-?[0-9]+<([^<>]+)>", token)
    if match is None:
        raise RuntimeOpenTraceError("relative *at path has no decoded dirfd")
    return _canonical_absolute(match.group(1), label="decoded dirfd path")


def _normalize_observed(path: str, *, base: str | None, pid: str) -> str:
    if path.startswith("/"):
        normalized = posixpath.normpath(path)
    else:
        if base is None:
            raise RuntimeOpenTraceError("relative path has no fixed base")
        normalized = posixpath.normpath(posixpath.join(base, path))
        try:
            if posixpath.commonpath((base, normalized)) != base:
                raise RuntimeOpenTraceError("relative path escapes its fixed base")
        except ValueError as exc:
            raise RuntimeOpenTraceError("relative path base is invalid") from exc
    if not normalized.startswith("/") or normalized == "//" or "\x00" in normalized:
        raise RuntimeOpenTraceError("observed path cannot be canonicalized")
    # Keep the digest stable when a child names its own proc directory by PID.
    if pid != "main" and normalized == f"/proc/{pid}":
        normalized = "/proc/@self"
    elif pid != "main" and normalized.startswith(f"/proc/{pid}/"):
        normalized = "/proc/@self/" + normalized[len(f"/proc/{pid}/") :]
    return normalized


def _resolved_open_path(annotation: str | None, *, pid: str) -> str:
    if annotation is None:
        raise RuntimeOpenTraceError("successful open lacks decoded fd path")
    if annotation.endswith(" (deleted)") or not annotation.startswith("/"):
        raise RuntimeOpenTraceError("successful open resolved to an unsafe object")
    return _normalize_observed(annotation, base=None, pid=pid)


def _path_for_call(name: str, arguments: list[str], *, cwd: str, pid: str) -> str:
    if name in PATH_FIRST:
        if not arguments:
            raise RuntimeOpenTraceError("path syscall has no path argument")
        path = _decode_c_string(arguments[0], label=f"{name} path")
        base = None if path.startswith("/") else cwd
        if name == "execve" and base is not None:
            raise RuntimeOpenTraceError("relative execve would require PATH/cwd resolution")
        return _normalize_observed(path, base=base, pid=pid)
    if name in PATH_AT:
        if len(arguments) < 2:
            raise RuntimeOpenTraceError("*at syscall has no path argument")
        path = _decode_c_string(arguments[1], label=f"{name} path")
        base = None if path.startswith("/") else _dirfd_base(arguments[0], cwd)
        if name == "execveat" and base is not None and arguments[0] == "AT_FDCWD":
            raise RuntimeOpenTraceError("relative execveat would require cwd resolution")
        return _normalize_observed(path, base=base, pid=pid)
    raise RuntimeOpenTraceError("trace contains an unsupported path syscall")


def _network_path(name: str, arguments: list[str], *, cwd: str, pid: str) -> str | None:
    rendered = ",".join(arguments)
    if "AF_INET" in rendered or "AF_INET6" in rendered or "AF_NETLINK" in rendered:
        raise RuntimeOpenTraceError("non-filesystem network access is forbidden")
    if name == "socket":
        if not arguments or arguments[0] != "AF_UNIX":
            raise RuntimeOpenTraceError("unknown network address family is forbidden")
        return None
    if "sa_family=AF_UNIX" not in rendered:
        raise RuntimeOpenTraceError("network call is not a decoded AF_UNIX endpoint")
    match = re.search(r"sun_path=(\"(?:\\.|[^\"\\])*\")", rendered)
    if match is None:
        raise RuntimeOpenTraceError("AF_UNIX endpoint path is missing or abstract")
    path = _decode_c_string(match.group(1), label="AF_UNIX socket path")
    if not path.startswith("/"):
        raise RuntimeOpenTraceError("AF_UNIX endpoint is not an absolute filesystem path")
    return _normalize_observed(path, base=cwd, pid=pid)


def parse_trace_bytes(
    payload: bytes,
    *,
    working_directory: str,
    expected_leader_pid: int,
) -> ParsedTrace:
    """Strictly parse one complete raw strace stream.

    Unknown records, a missing final newline, unmatched unfinished/resumed calls,
    undecoded successful opens, attach diagnostics, and non-filesystem networking
    are all fatal.  Successful and failed path attempts both enter the canonical
    path set; each failed errno is checked against the external policy.
    """

    cwd = _canonical_absolute(working_directory, label="working directory")
    if type(expected_leader_pid) is not int or expected_leader_pid <= 1:
        raise RuntimeOpenTraceError("independent tracee leader PID is required")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_TRACE_BYTES:
        raise RuntimeOpenTraceError("raw trace size is invalid")
    if not payload.endswith(b"\n") or b"\x00" in payload or b"\r" in payload:
        raise RuntimeOpenTraceError("raw trace is truncated or contains invalid bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise RuntimeOpenTraceError("raw trace is not valid UTF-8") from exc
    lines = text.splitlines()
    if not lines or len(lines) > MAX_TRACE_LINES:
        raise RuntimeOpenTraceError("raw trace line count is invalid")
    pending: dict[str, tuple[str, str]] = {}
    terminal: dict[str, int | None] = {}
    syscall_pids: set[str] = set()
    paths: set[str] = set()
    accesses: dict[str, set[str]] = {}
    attempted_mutations: dict[str, set[str]] = {}
    attempts: list[tuple[str, tuple[str, ...], str]] = []
    unix_fds: dict[tuple[str, int], str | None] = {}
    file_fds: dict[tuple[str, int], str] = {}
    execve: list[tuple[str, ...]] = []
    leader_pid: str | None = None
    for line in lines:
        if not line or len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise RuntimeOpenTraceError("raw trace contains an invalid line")
        if line.startswith("strace:") or " attached" in line or " detached" in line:
            raise RuntimeOpenTraceError("ptrace attach/detach trace mode is forbidden")
        pid, body = _strip_pid(line, expected_leader_pid)
        if body.startswith("strace:") or "attached" in body or "detached" in body:
            raise RuntimeOpenTraceError("ptrace attach/detach trace mode is forbidden")
        if pid in terminal:
            raise RuntimeOpenTraceError("trace contains activity after a PID terminal record")
        exit_match = re.fullmatch(r"\+\+\+ exited with ([0-9]{1,3}) \+\+\+", body)
        if exit_match is not None:
            if pid in terminal or pid in pending:
                raise RuntimeOpenTraceError("trace terminal state is inconsistent")
            code = int(exit_match.group(1))
            if code > 255:
                raise RuntimeOpenTraceError("trace exit status is invalid")
            terminal[pid] = code
            continue
        if re.fullmatch(r"\+\+\+ killed by SIG[A-Z0-9]+(?: \([^\r\n]*\))? \+\+\+", body):
            if pid in terminal or pid in pending:
                raise RuntimeOpenTraceError("trace terminal state is inconsistent")
            terminal[pid] = None
            continue
        if re.fullmatch(r"--- SIG[A-Z0-9]+ \{[^\r\n]*\} ---", body):
            continue
        if re.fullmatch(r"--- stopped by SIG[A-Z0-9]+ ---", body):
            continue
        unfinished = re.fullmatch(r"([a-z][a-z0-9_]*)\((.*)<unfinished \.\.\.>", body)
        if unfinished is not None:
            name = unfinished.group(1)
            if name not in SUPPORTED_TRACE_CALLS or pid in pending:
                raise RuntimeOpenTraceError("unfinished syscall state is invalid")
            if _contains_bare_ellipsis(unfinished.group(2)):
                raise RuntimeOpenTraceError("unfinished syscall arguments were abbreviated")
            pending[pid] = (name, f"{name}({unfinished.group(2)}")
            syscall_pids.add(pid)
            continue
        resumed = re.fullmatch(r"<\.\.\. ([a-z][a-z0-9_]*) resumed>(.*)", body)
        if resumed is not None:
            name = resumed.group(1)
            prior = pending.pop(pid, None)
            if prior is None or prior[0] != name:
                raise RuntimeOpenTraceError("resumed syscall has no matching unfinished call")
            body = prior[1] + resumed.group(2)
        elif _contains_bare_ellipsis(body):
            raise RuntimeOpenTraceError("trace line was abbreviated")
        name, argument_text, result_text = _split_call(body)
        if name not in SUPPORTED_TRACE_CALLS:
            raise RuntimeOpenTraceError(
                "trace contains an unimplemented syscall from the %file boundary"
            )
        syscall_pids.add(pid)
        arguments = _split_arguments(argument_text)
        success, annotation, errno = _success_result(result_text)
        if name in FORBIDDEN_CALLS:
            raise RuntimeOpenTraceError(
                "trace used a forbidden process/io_uring/handle/path-mutation syscall"
            )
        if name in CWD_CALLS:
            # The fixed launch cwd is part of the signed environment identity.
            # A successful chdir back to the already signed cwd is a no-op used
            # by the sealed child bootstrap.  Any other cwd mutation is rejected
            # so every relative path still has one stable, process-inherited
            # base without trusting untraced cwd state.
            if (
                name == "chdir"
                and success
                and len(arguments) == 1
                and _normalize_observed(
                    _decode_c_string(arguments[0], label="chdir path"),
                    base=cwd,
                    pid=pid,
                )
                == cwd
            ):
                continue
            raise RuntimeOpenTraceError("traced child attempted to change its fixed cwd")
        if name == "close":
            if not arguments:
                raise RuntimeOpenTraceError("close syscall fd is missing")
            if success:
                descriptor = _fd_number(arguments[0])
                unix_fds.pop((pid, descriptor), None)
                file_fds.pop((pid, descriptor), None)
            continue
        if name in {"dup", "dup2", "dup3"}:
            if not arguments:
                raise RuntimeOpenTraceError("dup syscall source fd is missing")
            source = _fd_number(arguments[0])
            if success:
                destination = _result_number(result_text)
                unix_fds.pop((pid, destination), None)
                file_fds.pop((pid, destination), None)
                if (pid, source) in unix_fds:
                    unix_fds[(pid, destination)] = unix_fds[(pid, source)]
                if (pid, source) in file_fds:
                    file_fds[(pid, destination)] = file_fds[(pid, source)]
            continue
        if name == "socket":
            _network_path(name, arguments, cwd=cwd, pid=pid)
            if success:
                unix_fds[(pid, _result_number(result_text))] = None
            continue
        if name in {"connect", "bind"}:
            if name == "bind":
                raise RuntimeOpenTraceError("AF_UNIX bind is outside the client boundary")
            endpoint = _network_path(name, arguments, cwd=cwd, pid=pid)
            descriptor = _fd_number(arguments[0])
            if (pid, descriptor) not in unix_fds:
                raise RuntimeOpenTraceError("AF_UNIX endpoint uses an untracked fd")
            if endpoint is None:
                raise RuntimeOpenTraceError("AF_UNIX endpoint path is unavailable")
            paths.add(endpoint)
            accesses.setdefault(endpoint, set()).add("unix-connect")
            attempts.append(
                (endpoint, ("unix-connect",), "success" if success else str(errno))
            )
            if success:
                unix_fds[(pid, descriptor)] = endpoint
            continue
        if name in {"sendto", "sendmsg"}:
            if not arguments:
                raise RuntimeOpenTraceError("socket send fd is missing")
            endpoint = unix_fds.get((pid, _fd_number(arguments[0])))
            if endpoint is None:
                raise RuntimeOpenTraceError(
                    "socket send is not bound to an allowed filesystem AF_UNIX endpoint"
                )
            paths.add(endpoint)
            accesses.setdefault(endpoint, set()).add("unix-send")
            attempts.append(
                (endpoint, ("unix-send",), "success" if success else str(errno))
            )
            continue
        if name == "ftruncate":
            if not arguments:
                raise RuntimeOpenTraceError("ftruncate syscall fd is missing")
            descriptor = _fd_number(arguments[0])
            path = file_fds.get((pid, descriptor))
            if path is None:
                raise RuntimeOpenTraceError("ftruncate uses an unresolved file descriptor")
            call_access = ("truncate", "write")
            paths.add(path)
            accesses.setdefault(path, set()).update(call_access)
            attempted_mutations.setdefault(path, set()).update(call_access)
            attempts.append(
                (path, call_access, "success" if success else str(errno))
            )
            continue
        path = _path_for_call(name, arguments, cwd=cwd, pid=pid)
        call_access: tuple[str, ...]
        if name in OPEN_CALLS:
            call_access = _open_access(name, arguments)
        elif name in EXEC_CALLS:
            call_access = ("execute",)
        elif name in DELETE_CALLS:
            call_access = ("delete",)
        elif name in TRUNCATE_PATH_CALLS:
            call_access = ("truncate", "write")
        else:
            call_access = ("metadata",)
        if name in EXEC_CALLS:
            argv_index = 1 if name == "execve" else 2
            if len(arguments) <= argv_index:
                raise RuntimeOpenTraceError("execve argv is missing")
            command = _decode_argv(arguments[argv_index])
            if success:
                if command[0] != path:
                    raise RuntimeOpenTraceError("execve path and argv[0] differ")
                if leader_pid is None:
                    if pid != str(expected_leader_pid):
                        raise RuntimeOpenTraceError(
                            "trace exec leader differs from the independent tracee PID"
                        )
                    leader_pid = pid
                elif pid != leader_pid:
                    raise RuntimeOpenTraceError("a non-leader process attempted execve")
                execve.append(command)
        observed_path = path
        if success and name in OPEN_CALLS:
            # The decoded fd annotation is the kernel-resolved object.  The
            # lexical request may be a symlink and is intentionally not
            # presented as closure evidence.
            observed_path = _resolved_open_path(annotation, pid=pid)
            descriptor = _result_number(result_text)
            file_fds[(pid, descriptor)] = observed_path
        paths.add(observed_path)
        accesses.setdefault(observed_path, set()).update(call_access)
        attempts.append(
            (observed_path, call_access, "success" if success else str(errno))
        )
        mutation = set(call_access) & {
            "write",
            "create",
            "truncate",
            "append",
            "delete",
        }
        if mutation:
            attempted_mutations.setdefault(observed_path, set()).update(mutation)
        if len(paths) > MAX_PATHS:
            raise RuntimeOpenTraceError("canonical path set is too large")
    if pending:
        raise RuntimeOpenTraceError("trace ended with unfinished syscalls")
    if leader_pid is None or not execve:
        raise RuntimeOpenTraceError("trace has no successful bootstrap execve")
    if leader_pid not in terminal or terminal[leader_pid] is None:
        raise RuntimeOpenTraceError("trace leader has no clean terminal status")
    if not syscall_pids.issubset(terminal):
        raise RuntimeOpenTraceError("trace ended before every traced process terminated")
    return ParsedTrace(
        paths=tuple(sorted(paths)),
        accesses=tuple(
            (path, tuple(sorted(values))) for path, values in sorted(accesses.items())
        ),
        attempted_mutations=tuple(
            (path, tuple(sorted(values)))
            for path, values in sorted(attempted_mutations.items())
        ),
        attempts=tuple(attempts),
        execve_argv=tuple(execve),
        trace_sha256=_sha256(payload),
        leader_returncode=int(terminal[leader_pid]),
    )


def validate_trace_bytes(
    payload: bytes,
    manifest: TraceManifest,
    *,
    expected_leader_pid: int,
) -> TraceResult:
    """Validate exact exec chain, exit state, and external allow-set equality."""

    parsed = parse_trace_bytes(
        payload,
        working_directory=manifest.working_directory,
        expected_leader_pid=expected_leader_pid,
    )
    effective_manifest = manifest
    if manifest.dynamic_argv_template:
        if len(parsed.execve_argv) != 3:
            raise RuntimeOpenTraceError(
                "successful execve chain differs from the fixed child argv"
            )
        effective_manifest = materialize_bootstrap_template(
            manifest,
            parsed.execve_argv[1],
            parsed.execve_argv[2],
        )
    if parsed.execve_argv != effective_manifest.expected_execve_argv:
        raise RuntimeOpenTraceError("successful execve chain differs from the fixed child argv")
    if parsed.leader_returncode not in manifest.expected_returncodes:
        raise RuntimeOpenTraceError("traced child exit status is not approved")
    observed = set(parsed.paths)
    allowed = set(manifest.allowed_paths)
    if observed - allowed:
        raise RuntimeOpenTraceError("trace contains an attempted path outside the allow set")
    if allowed - observed:
        raise RuntimeOpenTraceError("allow set contains a path not observed by this fixed target")
    for path, access, outcome in parsed.attempts:
        matches = [policy for policy in manifest.path_access_policy if policy.matches(path)]
        if len(matches) != 1:
            raise RuntimeOpenTraceError("observed path has no unambiguous external access policy")
        policy = matches[0]
        if not set(access).issubset(policy.allowed_access):
            raise RuntimeOpenTraceError("observed path access type is not externally allowed")
        if outcome == "success":
            if not policy.allow_success:
                raise RuntimeOpenTraceError(
                    "path succeeded but external policy requires a guarded failure"
                )
        elif outcome not in policy.allowed_errnos:
            raise RuntimeOpenTraceError(
                "failed path errno is not externally allowed"
            )
        if set(access) & {"write", "create", "truncate", "append", "delete"} and (
            policy.classification != "mutable-state"
            or policy.delta_verifier != SQLITE_DELTA_VERIFIER
            or not isinstance(policy.delta_contract_sha256, str)
            or HEX64.fullmatch(policy.delta_contract_sha256) is None
        ):
            raise RuntimeOpenTraceError("filesystem mutation is outside explicit state policy")
    return TraceResult(
        canonical_path_set_sha256=_sha256(canonical_json(parsed.paths)),
        canonical_path_count=len(parsed.paths),
        trace_sha256=parsed.trace_sha256,
    )


def validate_trace_file(
    path: Path,
    manifest: TraceManifest,
    *,
    expected_leader_pid: int,
    expected_mode: int = 0o400,
) -> TraceResult:
    """Read one private root trace at its explicitly bound transaction mode."""

    if expected_mode not in {0o600, 0o400}:
        raise RuntimeOpenTraceError("private trace expected mode is invalid")

    _validate_root_chain(path.parent)
    payload, identity = _read_trusted_regular(
        path,
        # The digest is computed from this one O_NOFOLLOW fd read; there is no
        # child-supplied or pre-read digest and therefore no TOCTOU window.
        None,
        expected_mode=expected_mode,
        max_bytes=MAX_TRACE_BYTES,
    )
    validated = validate_trace_bytes(
        payload, manifest, expected_leader_pid=expected_leader_pid
    )
    return TraceResult(
        canonical_path_set_sha256=validated.canonical_path_set_sha256,
        canonical_path_count=validated.canonical_path_count,
        trace_sha256=validated.trace_sha256,
        _verification_handle=TraceVerificationHandle(
            trace_path=identity.path,
            trace_device=identity.device,
            trace_inode=identity.inode,
            expected_leader_pid=expected_leader_pid,
            manifest_sha256=manifest.manifest_sha256,
            trace_mode=expected_mode,
        ),
    )


def reverify_trace_result(result: TraceResult, manifest: TraceManifest) -> TraceResult:
    """Independently re-open/reparse the same private trace before cleanup."""

    if not isinstance(result, TraceResult) or not isinstance(manifest, TraceManifest):
        raise RuntimeOpenTraceError("independent trace verifier input is invalid")
    handle = result.verification_handle()
    if handle.manifest_sha256 != manifest.manifest_sha256:
        raise RuntimeOpenTraceError("independent verifier manifest binding differs")
    path = Path(_canonical_absolute(handle.trace_path, label="private trace path"))
    _validate_root_chain(path.parent)
    payload, identity = _read_trusted_regular(
        path,
        result.trace_sha256,
        expected_mode=handle.trace_mode,
        max_bytes=MAX_TRACE_BYTES,
    )
    if (identity.device, identity.inode) != (
        handle.trace_device,
        handle.trace_inode,
    ):
        raise RuntimeOpenTraceError("independent verifier trace inode differs")
    repeated = validate_trace_bytes(
        payload,
        manifest,
        expected_leader_pid=handle.expected_leader_pid,
    )
    if repeated.document() != result.document():
        raise RuntimeOpenTraceError("independent verifier result differs")
    return result


def _internal_demote_exec(arguments: Sequence[str]) -> None:
    """Root-only fixed tracee shim; never a general command runner."""

    if len(arguments) < 10 or arguments[0] != "__dev29_demote_exec_v1__":
        raise RuntimeOpenTraceError("internal credential-drop invocation is invalid")
    role, release, uid_text, gid_text, count_text, bootstrap_sha, final_sha = arguments[1:8]
    if arguments[8] != "--" or role not in ROLE_ENVIRONMENTS or NAME.fullmatch(release) is None:
        raise RuntimeOpenTraceError("internal credential-drop identity is invalid")
    uid = _positive_decimal(uid_text, label="internal uid", allow_zero=True)
    gid = _positive_decimal(gid_text, label="internal gid", allow_zero=True)
    final_count = _positive_decimal(count_text, label="internal final argv count")
    bootstrap = tuple(arguments[9:])
    if final_count >= len(bootstrap):
        raise RuntimeOpenTraceError("internal final argv boundary is invalid")
    final = bootstrap[-final_count:]
    if (
        HEX64.fullmatch(bootstrap_sha) is None
        or HEX64.fullmatch(final_sha) is None
        or _sha256(canonical_json(bootstrap)) != bootstrap_sha
        or _sha256(canonical_json(final)) != final_sha
    ):
        raise RuntimeOpenTraceError("internal fixed argv digest mismatch")
    expected_uid, expected_gid, is_template = _validate_bootstrap_argv(
        bootstrap,
        final,
        role=role,
        release_root=f"/opt/odoo-accounting-cli-v3/releases/{release}",
    )
    if is_template or (uid, gid) != (expected_uid, expected_gid):
        raise RuntimeOpenTraceError("internal credential values differ from direct_child")
    if os.name != "posix" or os.geteuid() != 0 or dict(os.environ) != ROLE_ENVIRONMENTS[role]:
        raise RuntimeOpenTraceError("credential-drop shim lacks the fixed root environment")
    try:
        maximum_capability = int(
            Path("/proc/sys/kernel/cap_last_cap").read_text("ascii").strip()
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeOpenTraceError("kernel capability boundary is unavailable") from exc
    if not 0 <= maximum_capability <= 255:
        raise RuntimeOpenTraceError("kernel capability boundary is invalid")
    libc = ctypes.CDLL(None, use_errno=True)

    def prctl(option: int, argument: int = 0) -> None:
        if libc.prctl(option, argument, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    original_parent = os.getppid()
    prctl(1, 9)  # PR_SET_PDEATHSIG, SIGKILL
    if original_parent == 1 or os.getppid() != original_parent:
        raise RuntimeOpenTraceError("supervisor died before credential drop")
    # Deterministic startup handshake: the supervisor verifies PPid, TracerPid,
    # and tracer inode while this fixed root shim is stopped, then sends SIGCONT.
    # PDEATHSIG is armed before the stop so a dead supervisor cannot strand it.
    os.kill(os.getpid(), signal.SIGSTOP)
    if os.getppid() != original_parent:
        raise RuntimeOpenTraceError("supervisor changed during startup synchronization")
    os.setsid()
    prctl(28, 0x1 | 0x2)  # SECBIT_NOROOT | SECBIT_NOROOT_LOCKED
    prctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL
    for capability in range(maximum_capability + 1):
        prctl(24, capability)  # PR_CAPBSET_DROP
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    # Linux clears PDEATHSIG on credential transitions.  Re-establish it after
    # the final uid/gid change and verify both the signal and the same parent.
    prctl(1, 9)
    observed_pdeathsig = ctypes.c_int(0)
    if libc.prctl(2, ctypes.byref(observed_pdeathsig), 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if observed_pdeathsig.value != 9 or os.getppid() != original_parent:
        raise RuntimeOpenTraceError("parent-death control changed across credential drop")

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header = Header(0x20080522, 0)
    data = (Data * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    prctl(47, 4)
    prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    if (
        os.geteuid() != uid
        or os.getegid() != gid
        or os.getgroups()
        or os.getppid() != original_parent
        or observed_pdeathsig.value != 9
    ):
        raise RuntimeOpenTraceError("credential-drop shim postcondition failed")
    os.execve(bootstrap[0], bootstrap, dict(os.environ))
    raise AssertionError("execve returned")


__all__ = [
    "MANIFEST_PARENT",
    "SCOPE",
    "STAGING_PARENT",
    "STRACE_OPTIONS",
    "STRACE_PATH",
    "VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER",
    "VERIFIER_EVIDENCE_DIR_MARKER",
    "PRODUCTION_PROMOTION_ALLOWED",
    "PathAccessPolicy",
    "ParsedTrace",
    "RuntimeOpenTraceError",
    "TraceManifest",
    "TraceRequest",
    "TraceResult",
    "TraceVerificationHandle",
    "TrustedFileIdentity",
    "TrustedExecutable",
    "StraceLaunch",
    "build_strace_launch",
    "canonical_json",
    "load_trace_manifest",
    "manifest_path",
    "parse_trace_bytes",
    "validate_manifest_document",
    "validate_strace_tool",
    "validate_trace_bytes",
    "validate_trace_file",
    "reverify_trace_result",
    "verify_tracer_proc_exe",
    "verify_traced_process",
    "verify_and_release_traced_process",
    "capture_runtime_environment",
    "demotion_argv",
    "dynamic_bootstrap_template",
    "materialize_bootstrap_template",
    "verifier_final_argv_template",
    "MutationWatch",
    "PrivateTraceStaging",
    "recover_stale_private_staging",
    "RuntimeEnvironmentGuard",
    "watch_tree_snapshot",
]


if __name__ == "__main__":
    try:
        _internal_demote_exec(sys.argv[1:])
    except (OSError, RuntimeOpenTraceError, ValueError) as exc:
        print(f"Dev29 runtime trace shim refused: {exc}", file=sys.stderr)
        raise SystemExit(126)

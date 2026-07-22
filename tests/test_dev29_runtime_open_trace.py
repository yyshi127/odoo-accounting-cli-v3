from __future__ import annotations

import hashlib
import importlib.util
import json
import errno
import os
import signal
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev29" / "runtime_open_trace.py"
SPEC = importlib.util.spec_from_file_location("dev29_runtime_open_trace", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
trace = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = trace
SPEC.loader.exec_module(trace)

RELEASE = "0.1.0.dev29-a1234567890b"
RELEASE_ROOT = f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}"
FINAL = (
    "/usr/bin/python3.12",
    "-I",
    "-S",
    f"{RELEASE_ROOT}/deployment/dev29/sign_read.py",
    "--case",
    "registry",
)
MOUNTS = tuple(
    json.dumps({"mount": index}, sort_keys=True, separators=(",", ":"))
    for index in range(5)
)
BOOTSTRAP = (
    "/usr/bin/python3.12",
    "-I",
    "-S",
    f"{RELEASE_ROOT}/deployment/dev29/direct_child.py",
    "--role",
    "signer",
    "--attestation-fd",
    "7",
    "--expected-uid",
    "1001",
    "--expected-gid",
    "1001",
    "--expected-python",
    "/usr/bin/python3.12",
    "--expected-venv-root",
    "/opt/odoo-accounting-cli-v3/dependencies/odoo19-venv",
    "--release-root",
    RELEASE_ROOT,
    "--expected-self-namespace-device",
    "4",
    "--expected-self-namespace-inode",
    "100",
    "--expected-host-namespace-device",
    "4",
    "--expected-host-namespace-inode",
    "200",
    "--expected-loop-device",
    "/dev/loop7",
    "--expected-mount-json",
    MOUNTS[0],
    "--expected-mount-json",
    MOUNTS[1],
    "--expected-mount-json",
    MOUNTS[2],
    "--expected-mount-json",
    MOUNTS[3],
    "--expected-mount-json",
    MOUNTS[4],
    "--",
    *FINAL,
)
DEMOTION = (
    "/usr/bin/python3.12",
    "-I",
    "-S",
    f"{RELEASE_ROOT}/deployment/dev29/runtime_open_trace.py",
    "__dev29_demote_exec_v1__",
    "signer",
    RELEASE,
    "1001",
    "1001",
    str(len(FINAL)),
    hashlib.sha256(trace.canonical_json(BOOTSTRAP)).hexdigest(),
    hashlib.sha256(trace.canonical_json(FINAL)).hexdigest(),
    "--",
    *BOOTSTRAP,
)
VALID_WATCH_ROOTS = tuple(
    sorted(
        {
            "/dev/loop7",
            "/etc",
            "/opt/odoo-accounting-cli-v3/dependencies/odoo19-venv",
            RELEASE_ROOT,
            "/proc/self/exe",
            "/usr/bin/python3.12",
        }
    )
)


def quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def argv_text(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(quoted(value) for value in values) + "]"


def raw_trace(*, extra: list[str] | None = None, exit_code: int = 0) -> bytes:
    lines = [
        f'410 execve("/usr/bin/python3.12", {argv_text(DEMOTION)}, 0x7fff) = 0',
        f'410 execve("/usr/bin/python3.12", {argv_text(BOOTSTRAP)}, 0x7fff) = 0',
        '410 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache>',
        '410 openat(3</opt/odoo-accounting-cli-v3/releases/0.1.0.dev29-a1234567890b>, "src/pkg.py", O_RDONLY <unfinished ...>',
        '410 <... openat resumed>) = 4</opt/odoo-accounting-cli-v3/releases/0.1.0.dev29-a1234567890b/src/pkg.py>',
        f'410 stat("{RELEASE_ROOT}", {{st_mode=S_IFDIR|0555}}, 0) = 0',
        '410 access("/etc/definitely-missing", F_OK) = -1 ENOENT (No such file or directory)',
        '410 readlink("/proc/self/exe", "/usr/bin/python3.12", 4096) = 19',
        f'410 openat2(AT_FDCWD, "runtime.json", {{flags=O_RDONLY, resolve=RESOLVE_BENEATH}}, 24) = 5<{RELEASE_ROOT}/runtime.json>',
    ]
    if extra:
        lines.extend(extra)
    lines.extend(
        [
            f'410 execve("/usr/bin/python3.12", {argv_text(FINAL)}, 0x7fff) = 0',
            f"410 +++ exited with {exit_code} +++",
        ]
    )
    return ("\n".join(lines) + "\n").encode()


def expected_paths() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                "/etc/ld.so.cache",
                "/etc/definitely-missing",
                RELEASE_ROOT,
                f"{RELEASE_ROOT}/runtime.json",
                f"{RELEASE_ROOT}/src/pkg.py",
                "/proc/self/exe",
                "/usr/bin/python3.12",
            }
        )
    )


def policies(allowed: tuple[str, ...]) -> tuple[trace.PathAccessPolicy, ...]:
    result = []
    for path in allowed:
        socket = path.startswith("/var/run/postgresql/")
        result.append(
            trace.PathAccessPolicy(
                path=path,
                role="signer",
                classification="unix-socket" if socket else "immutable",
                allowed_access=("unix-connect", "unix-send") if socket else ("execute", "metadata", "read"),
                create_suffixes=(),
                delta_verifier=None,
                delta_contract_sha256=None,
                allow_success=path != "/etc/definitely-missing",
                allowed_errnos=("ENOENT",) if path == "/etc/definitely-missing" else (),
                failure_guard=(
                    trace.WATCH_TREE_FAILURE_GUARD
                    if path == "/etc/definitely-missing"
                    else None
                ),
            )
        )
    return tuple(result)


def manifest(*, allowed: tuple[str, ...] | None = None) -> trace.TraceManifest:
    selected = expected_paths() if allowed is None else allowed
    return trace.TraceManifest(
        release=RELEASE,
        target_id="positive-registry-signer",
        role="signer",
        working_directory=RELEASE_ROOT,
        environment=dict(trace.ROLE_ENVIRONMENTS["signer"]),
        bootstrap_argv=BOOTSTRAP,
        final_argv=FINAL,
        allowed_paths=selected,
        path_access_policy=policies(selected),
        watch_roots=(RELEASE_ROOT,),
        expected_static_closure_sha256="a" * 64,
        expected_child_environment_sha256=hashlib.sha256(
            trace.canonical_json(trace.ROLE_ENVIRONMENTS["signer"])
        ).hexdigest(),
        expected_returncodes=(0,),
        expected_uid=1001,
        expected_gid=1001,
        manifest_sha256="b" * 64,
        expected_strace_sha256="c" * 64,
    )


def request(
    watch_roots: tuple[str, ...] = (RELEASE_ROOT,),
) -> trace.TraceRequest:
    roots_sha256 = hashlib.sha256(trace.canonical_json(watch_roots)).hexdigest()
    return trace.TraceRequest(
        RELEASE,
        "positive-registry-signer",
        "b" * 64,
        "c" * 64,
        "a" * 64,
        hashlib.sha256(
            trace.canonical_json(trace.ROLE_ENVIRONMENTS["signer"])
        ).hexdigest(),
        roots_sha256,
    )


def manifest_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "scope": trace.SCOPE,
        "release": RELEASE,
        "target_id": "positive-registry-signer",
        "role": "signer",
        "working_directory": RELEASE_ROOT,
        "environment": dict(trace.ROLE_ENVIRONMENTS["signer"]),
        "bootstrap_argv": list(BOOTSTRAP),
        "final_argv": list(FINAL),
        "allowed_paths": list(expected_paths()),
        "path_access_policy": [
            {
                "path": item.path,
                "role": item.role,
                "classification": item.classification,
                "allowed_access": list(item.allowed_access),
                "create_suffixes": list(item.create_suffixes),
                "delta_verifier": item.delta_verifier,
                "delta_contract_sha256": item.delta_contract_sha256,
                "allow_success": item.allow_success,
                "allowed_errnos": list(item.allowed_errnos),
                "failure_guard": item.failure_guard,
            }
            for item in policies(expected_paths())
        ],
        "watch_roots": list(VALID_WATCH_ROOTS),
        "expected_static_closure_sha256": "a" * 64,
        "expected_child_environment_sha256": hashlib.sha256(
            trace.canonical_json(trace.ROLE_ENVIRONMENTS["signer"])
        ).hexdigest(),
        "expected_watch_roots_sha256": hashlib.sha256(
            trace.canonical_json(VALID_WATCH_ROOTS)
        ).hexdigest(),
        "expected_returncodes": [0],
    }


def test_parser_covers_required_calls_failed_result_and_unfinished_resume() -> None:
    parsed = trace.parse_trace_bytes(
        raw_trace(), working_directory=RELEASE_ROOT, expected_leader_pid=410
    )
    assert parsed.paths == expected_paths()
    assert parsed.execve_argv == (DEMOTION, BOOTSTRAP, FINAL)
    assert parsed.leader_returncode == 0
    assert "/etc/definitely-missing" in parsed.paths
    assert (
        "/etc/definitely-missing",
        ("metadata",),
        "ENOENT",
    ) in parsed.attempts
    assert dict(parsed.accesses)[RELEASE_ROOT] == ("metadata",)
    assert dict(parsed.accesses)["/proc/self/exe"] == ("metadata",)


def test_exact_allow_set_returns_only_three_publishable_fields() -> None:
    result = trace.validate_trace_bytes(
        raw_trace(), manifest(), expected_leader_pid=410
    )
    assert result.document() == {
        "canonical_path_count": len(expected_paths()),
        "canonical_path_set_sha256": hashlib.sha256(
            trace.canonical_json(expected_paths())
        ).hexdigest(),
        "trace_sha256": hashlib.sha256(raw_trace()).hexdigest(),
    }


def test_successful_path_outside_allow_set_fails_closed() -> None:
    outside = '410 open("/tmp/not-allowed", O_RDONLY) = 8</tmp/not-allowed>'
    with pytest.raises(trace.RuntimeOpenTraceError, match="outside the allow set"):
        trace.validate_trace_bytes(
            raw_trace(extra=[outside]), manifest(), expected_leader_pid=410
        )


def test_missing_observation_rejects_overbroad_allow_manifest() -> None:
    allowed = tuple(sorted((*expected_paths(), "/opt/not-observed")))
    with pytest.raises(trace.RuntimeOpenTraceError, match="not observed"):
        trace.validate_trace_bytes(
            raw_trace(), manifest(allowed=allowed), expected_leader_pid=410
        )


def test_child_self_reported_allow_set_cannot_override_external_manifest() -> None:
    # A child may print this to stdout, but stdout is not an input to the API.
    child_stdout = b'{"allowed_paths":["/tmp/not-allowed"]}\n'
    assert child_stdout
    outside = '410 open("/tmp/not-allowed", O_RDONLY) = 8</tmp/not-allowed>'
    with pytest.raises(trace.RuntimeOpenTraceError, match="outside the allow set"):
        trace.validate_trace_bytes(
            raw_trace(extra=[outside]), manifest(), expected_leader_pid=410
        )


@pytest.mark.parametrize(
    "payload,error",
    [
        (
            b'410 <... openat resumed>) = 3</x>\n410 +++ exited with 0 +++\n',
            "no matching unfinished",
        ),
        (
            b'410 execve("/x", ["/x"], 0x1) = 0\n410 open("/x", O_RDONLY <unfinished ...>\n',
            "unfinished syscalls",
        ),
        (raw_trace().rstrip(b"\n"), "truncated"),
        (
            raw_trace(extra=['410 mystery("/etc/passwd") = 0']),
            "unimplemented syscall",
        ),
        (
            raw_trace(extra=["strace: Process 410 attached"]),
            "attach/detach",
        ),
    ],
)
def test_truncation_unknown_lines_and_unmatched_state_are_rejected(
    payload: bytes, error: str
) -> None:
    with pytest.raises(trace.RuntimeOpenTraceError, match=error):
        trace.parse_trace_bytes(
            payload, working_directory=RELEASE_ROOT, expected_leader_pid=410
        )


def test_relative_cwd_escape_is_rejected_even_when_open_failed() -> None:
    escaped = (
        '410 openat(AT_FDCWD, "../../etc/passwd", O_RDONLY) '
        '= -1 ENOENT (No such file or directory)'
    )
    with pytest.raises(trace.RuntimeOpenTraceError, match="escapes"):
        trace.parse_trace_bytes(
            raw_trace(extra=[escaped]),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )


def test_relative_annotated_dirfd_resolves_without_path_lookup() -> None:
    parsed = trace.parse_trace_bytes(
        raw_trace(), working_directory=RELEASE_ROOT, expected_leader_pid=410
    )
    assert f"{RELEASE_ROOT}/src/pkg.py" in parsed.paths


def test_independent_leader_pid_must_match_first_successful_exec() -> None:
    with pytest.raises(trace.RuntimeOpenTraceError, match="leader differs"):
        trace.parse_trace_bytes(
            raw_trace(), working_directory=RELEASE_ROOT, expected_leader_pid=999
        )


def test_failed_probe_errno_and_success_outcome_are_externally_bound() -> None:
    base = manifest()
    changed = tuple(
        replace(policy, allowed_errnos=("EACCES",))
        if policy.path == "/etc/definitely-missing"
        else policy
        for policy in base.path_access_policy
    )
    with pytest.raises(trace.RuntimeOpenTraceError, match="errno"):
        trace.validate_trace_bytes(
            raw_trace(), replace(base, path_access_policy=changed), expected_leader_pid=410
        )
    appeared = raw_trace().replace(
        b'access("/etc/definitely-missing", F_OK) = -1 ENOENT (No such file or directory)',
        b'access("/etc/definitely-missing", F_OK) = 0',
    )
    with pytest.raises(trace.RuntimeOpenTraceError, match="requires a guarded failure"):
        trace.validate_trace_bytes(appeared, base, expected_leader_pid=410)


def test_immutable_dependency_cannot_be_opened_for_write() -> None:
    write = '410 open("/etc/ld.so.cache", O_WRONLY|O_TRUNC) = 8</etc/ld.so.cache>'
    with pytest.raises(trace.RuntimeOpenTraceError, match="access type"):
        trace.validate_trace_bytes(
            raw_trace(extra=[write]), manifest(), expected_leader_pid=410
        )
    openat2_write = (
        '410 openat2(AT_FDCWD, "/etc/ld.so.cache", '
        '{flags=O_RDWR|O_CLOEXEC, resolve=RESOLVE_BENEATH}, 24) '
        '= 8</etc/ld.so.cache>'
    )
    with pytest.raises(trace.RuntimeOpenTraceError, match="access type"):
        trace.validate_trace_bytes(
            raw_trace(extra=[openat2_write]), manifest(), expected_leader_pid=410
        )


def test_explicit_mutable_sqlite_policy_covers_fd_truncate_and_journal_delete() -> None:
    state = "/var/lib/odoo-accounting-cli-v3-broker/auth.sqlite3"
    journal = state + "-journal"
    mutable = trace.PathAccessPolicy(
        path=state,
        role="signer",
        classification="mutable-state",
        allowed_access=tuple(sorted(trace.MUTABLE_ACCESS)),
        create_suffixes=("-journal", "-shm", "-wal"),
        delta_verifier=trace.SQLITE_DELTA_VERIFIER,
        delta_contract_sha256="d" * 64,
        allow_success=True,
        allowed_errnos=(),
        failure_guard=None,
    )
    base = manifest()
    allowed = tuple(sorted((*base.allowed_paths, state, journal)))
    changed = replace(
        base,
        allowed_paths=allowed,
        path_access_policy=tuple(sorted((*base.path_access_policy, mutable), key=lambda p: p.path)),
    )
    lines = [
        f'410 openat(AT_FDCWD, "{state}", O_RDWR|O_CREAT|O_CLOEXEC, 0600) = 8<{state}>',
        f'410 ftruncate(8<{state}>, 4096) = 0',
        f'410 unlink("{journal}") = 0',
    ]
    result = trace.validate_trace_bytes(
        raw_trace(extra=lines), changed, expected_leader_pid=410
    )
    assert result.canonical_path_count == len(allowed)
    parsed = trace.parse_trace_bytes(
        raw_trace(extra=lines),
        working_directory=RELEASE_ROOT,
        expected_leader_pid=410,
    )
    assert dict(parsed.attempted_mutations)[journal] == ("delete",)
    assert dict(parsed.attempted_mutations)[state] == (
        "create",
        "truncate",
        "write",
    )


def test_ftruncate_on_unresolved_or_closed_fd_fails_closed() -> None:
    with pytest.raises(trace.RuntimeOpenTraceError, match="unresolved"):
        trace.parse_trace_bytes(
            raw_trace(extra=["410 ftruncate(77, 0) = 0"]),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )
    state = f"{RELEASE_ROOT}/runtime.json"
    lines = [
        f'410 open("{state}", O_RDWR) = 8<{state}>',
        f'410 close(8<{state}>) = 0',
        "410 ftruncate(8, 0) = -1 EBADF (Bad file descriptor)",
    ]
    with pytest.raises(trace.RuntimeOpenTraceError, match="unresolved"):
        trace.parse_trace_bytes(
            raw_trace(extra=lines),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )


@pytest.mark.parametrize(
    "line",
    [
        '410 rename("/tmp/a", "/tmp/b") = 0',
        '410 chmod("/tmp/a", 0600) = 0',
        '410 clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = 411',
        "410 io_uring_setup(8, {}) = 9",
        '410 open_by_handle_at(3, {handle_bytes=8}, O_RDONLY) = 4</tmp/a>',
    ],
)
def test_unimplemented_path_mutation_process_and_async_escape_calls_are_rejected(
    line: str,
) -> None:
    with pytest.raises(trace.RuntimeOpenTraceError, match="forbidden"):
        trace.parse_trace_bytes(
            raw_trace(extra=[line]),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )


def test_unknown_percent_file_member_is_rejected_not_silently_ignored() -> None:
    with pytest.raises(trace.RuntimeOpenTraceError, match="%file boundary"):
        trace.parse_trace_bytes(
            raw_trace(extra=['410 pivot_root("/x", "/x/old") = 0']),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )


def test_non_filesystem_network_and_abstract_unix_socket_are_rejected() -> None:
    inet = "410 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 7<TCP:[1]>"
    with pytest.raises(trace.RuntimeOpenTraceError, match="network access"):
        trace.parse_trace_bytes(
            raw_trace(extra=[inet]),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )
    abstract = (
        '410 connect(7<UNIX-STREAM:[1]>, {sa_family=AF_UNIX, '
        'sun_path=@"hidden"}, 9) = 0'
    )
    with pytest.raises(trace.RuntimeOpenTraceError, match="missing or abstract"):
        trace.parse_trace_bytes(
            raw_trace(extra=[abstract]),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )


def test_filesystem_unix_socket_is_an_exact_allowed_path() -> None:
    socket_path = "/var/run/postgresql/.s.PGSQL.5432"
    lines = [
        "410 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 7<UNIX-STREAM:[1]>",
        f'410 connect(7<UNIX-STREAM:[1]>, {{sa_family=AF_UNIX, sun_path="{socket_path}"}}, 110) = 0',
    ]
    allowed = tuple(sorted((*expected_paths(), socket_path)))
    result = trace.validate_trace_bytes(
        raw_trace(extra=lines),
        manifest(allowed=allowed),
        expected_leader_pid=410,
    )
    assert result.canonical_path_count == len(allowed)


def test_socket_send_requires_a_successfully_connected_filesystem_endpoint() -> None:
    socket_path = "/var/run/postgresql/.s.PGSQL.5432"
    unbound = [
        "410 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 7<UNIX-STREAM:[1]>",
        '410 sendmsg(7<UNIX-STREAM:[1]>, {msg_name=NULL}, MSG_NOSIGNAL) = 1',
    ]
    with pytest.raises(trace.RuntimeOpenTraceError, match="not bound"):
        trace.parse_trace_bytes(
            raw_trace(extra=unbound),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )
    connected = [
        "410 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 7<UNIX-STREAM:[1]>",
        f'410 connect(7<UNIX-STREAM:[1]>, {{sa_family=AF_UNIX, sun_path="{socket_path}"}}, 110) = 0',
        '410 sendto(7<UNIX-STREAM:[1]>, "x", 1, MSG_NOSIGNAL, NULL, 0) = 1',
        '410 sendmsg(7<UNIX-STREAM:[1]>, {msg_name=NULL}, MSG_NOSIGNAL) = 1',
    ]
    allowed = tuple(sorted((*expected_paths(), socket_path)))
    result = trace.validate_trace_bytes(
        raw_trace(extra=connected),
        manifest(allowed=allowed),
        expected_leader_pid=410,
    )
    assert result.canonical_path_count == len(allowed)


def test_unix_bind_is_rejected() -> None:
    lines = [
        "410 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 7<UNIX-STREAM:[1]>",
        '410 bind(7<UNIX-STREAM:[1]>, {sa_family=AF_UNIX, sun_path="/tmp/server.sock"}, 110) = 0',
    ]
    with pytest.raises(trace.RuntimeOpenTraceError, match="outside the client boundary"):
        trace.parse_trace_bytes(
            raw_trace(extra=lines),
            working_directory=RELEASE_ROOT,
            expected_leader_pid=410,
        )


def test_exec_chain_is_exact_not_merely_an_executable_path_set() -> None:
    altered = replace(manifest(), final_argv=(*FINAL[:-1], "trial_balance"))
    with pytest.raises(trace.RuntimeOpenTraceError, match="execve chain"):
        trace.validate_trace_bytes(raw_trace(), altered, expected_leader_pid=410)


def test_manifest_schema_rejects_self_reported_or_unbound_policy() -> None:
    document = manifest_document()
    document["self_reported_allowed_paths"] = ["/tmp/escape"]
    with pytest.raises(trace.RuntimeOpenTraceError, match="schema"):
        trace.validate_manifest_document(document, request(VALID_WATCH_ROOTS))
    document = manifest_document()
    document["bootstrap_argv"] = list(BOOTSTRAP[:-len(FINAL)])
    with pytest.raises(trace.RuntimeOpenTraceError, match="bound"):
        trace.validate_manifest_document(document, request(VALID_WATCH_ROOTS))
    document = manifest_document()
    document["schema_version"] = True
    with pytest.raises(trace.RuntimeOpenTraceError, match="identity"):
        trace.validate_manifest_document(document, request(VALID_WATCH_ROOTS))


def test_private_runtime_documents_reject_boolean_schema_versions() -> None:
    assert trace._schema_version_is_one(1) is True
    for value in (True, 1.0, "1", None):
        assert trace._schema_version_is_one(value) is False

    metadata = SimpleNamespace(st_dev=1, st_ino=2, st_size=0)
    journal = trace._seal_journal_document(
        Path("/var/lib/odoo-accounting-cli-v3/evidence-private/proof/runtime-open/target.strace"),
        metadata,
        "a" * 64,
        target_id="target",
        manifest_sha256="b" * 64,
        expected_leader_pid=321,
    )
    journal["schema_version"] = True
    with pytest.raises(trace.RuntimeOpenTraceError, match="journal identity"):
        trace._parse_seal_journal(trace.canonical_json(journal) + b"\n")


def test_manifest_accepts_only_explicit_outcome_policy_and_static_closure_pin() -> None:
    loaded = trace.validate_manifest_document(
        manifest_document(), request(VALID_WATCH_ROOTS)
    )
    assert loaded.expected_static_closure_sha256 == "a" * 64
    assert loaded.expected_child_environment_sha256 == hashlib.sha256(
        trace.canonical_json(trace.ROLE_ENVIRONMENTS["signer"])
    ).hexdigest()
    assert loaded.manifest_sha256 == "b" * 64
    assert loaded.expected_strace_sha256 == "c" * 64
    missing = next(
        policy
        for policy in loaded.path_access_policy
        if policy.path == "/etc/definitely-missing"
    )
    assert missing.allow_success is False
    assert missing.allowed_errnos == ("ENOENT",)
    assert missing.failure_guard == trace.WATCH_TREE_FAILURE_GUARD


def test_manifest_rejects_mutable_state_inside_immutable_watch_tree() -> None:
    document = manifest_document()
    state = f"{RELEASE_ROOT}/state.sqlite3"
    document["allowed_paths"] = sorted([*document["allowed_paths"], state])  # type: ignore[index]
    document["path_access_policy"] = sorted(  # type: ignore[index]
        [
            *document["path_access_policy"],  # type: ignore[index]
            {
                "path": state,
                "role": "signer",
                "classification": "mutable-state",
                "allowed_access": ["create", "read", "write"],
                "create_suffixes": [],
                "delta_verifier": trace.SQLITE_DELTA_VERIFIER,
                "delta_contract_sha256": "d" * 64,
                "allow_success": True,
                "allowed_errnos": [],
                "failure_guard": None,
            },
        ],
        key=lambda item: item["path"],
    )
    with pytest.raises(trace.RuntimeOpenTraceError, match="outside the watched closure"):
        trace.validate_manifest_document(document, request(VALID_WATCH_ROOTS))


def test_fixed_strace_command_has_no_path_lookup_or_attach_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del tmp_path
    identity = trace.TrustedFileIdentity(
        path="/usr/bin/strace",
        sha256="c" * 64,
        size=1,
        device=1,
        inode=2,
        uid=0,
        gid=0,
        mode=0o755,
        links=1,
        mtime_ns=0,
        ctime_ns=0,
    )
    trusted = trace.TrustedExecutable(identity=identity, descriptor=99)
    monkeypatch.setattr(trace.TrustedExecutable, "assert_open", lambda self: None)
    launch = trace.build_strace_launch(
        "/var/lib/odoo-accounting-cli-v3/runtime-open-trace/run/trace.log",
        manifest(),
        trusted,
    )
    command = launch.argv
    assert command[0] == "/proc/self/fd/99"
    assert launch.logical_executable == "/usr/bin/strace"
    assert launch.pass_fds == (99,)
    assert any(value.startswith("--trace=%file,") for value in command)
    assert command[-len(DEMOTION) :] == DEMOTION
    assert "--" in command
    assert "-p" not in command
    assert not any(value.startswith("--attach") for value in command)


def test_fixed_strace_launch_binds_only_explicit_inherited_tracee_fds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = trace.TrustedFileIdentity(
        path="/usr/bin/strace", sha256="c" * 64, size=1, device=1,
        inode=2, uid=0, gid=0, mode=0o755, links=1, mtime_ns=0, ctime_ns=0,
    )
    trusted = trace.TrustedExecutable(identity=identity, descriptor=99)
    monkeypatch.setattr(trace.TrustedExecutable, "assert_open", lambda self: None)
    launch = trace.build_strace_launch(
        "/var/lib/odoo-accounting-cli-v3/runtime-open-trace/run/trace.log",
        manifest(),
        trusted,
        inherited_fds=(198,),
    )
    assert launch.pass_fds == (99, 198)
    with pytest.raises(trace.RuntimeOpenTraceError, match="descriptor set"):
        trace.build_strace_launch(
            "/var/lib/odoo-accounting-cli-v3/runtime-open-trace/run/trace.log",
            manifest(),
            trusted,
            inherited_fds=(198, 198),
        )


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="private raw trace sealing requires Linux root",
)
def test_private_trace_seal_preserves_inode_and_raw_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging_parent = tmp_path / "staging"
    sidecar = tmp_path / "sidecar"
    staging_parent.mkdir(mode=0o700)
    sidecar.mkdir(mode=0o700)
    monkeypatch.setattr(trace, "STAGING_PARENT", staging_parent)
    monkeypatch.setattr(trace, "PRIVATE_EVIDENCE_PARENT", tmp_path)
    monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)
    with trace.PrivateTraceStaging("target") as staging:
        staging.path.write_bytes(b"raw-trace\n")
        source_inode = staging.path.stat().st_ino
        identity = staging.seal_to(
            sidecar / "target.strace",
            target_id="target",
            manifest_sha256="a" * 64,
            expected_leader_pid=321,
        )
        assert identity["inode"] == source_inode
        assert identity["sha256"] == hashlib.sha256(b"raw-trace\n").hexdigest()
    assert not staging.directory.exists()
    assert (sidecar / "target.strace").read_bytes() == b"raw-trace\n"
    assert stat.S_IMODE((sidecar / "target.strace").stat().st_mode) == 0o400
    assert (sidecar / ".target.seal.json").is_file()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX device identities")
def test_private_trace_seal_rejects_cross_filesystem_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sidecar = tmp_path / "sidecar"
    sidecar.mkdir(mode=0o700)
    staging = trace.PrivateTraceStaging("target")
    staging._directory_fd = 1
    staging._trace_identity = (sidecar.stat().st_dev + 1, 10)
    staging._lease_identity = (sidecar.stat().st_dev + 1, 11)
    monkeypatch.setattr(staging, "assert_private_identity", lambda: None)
    monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)
    with pytest.raises(trace.RuntimeOpenTraceError, match="cross-filesystem"):
        staging.seal_to(
            sidecar / "target.strace",
            target_id="target",
            manifest_sha256="a" * 64,
            expected_leader_pid=321,
        )


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root private staging",
)
def test_private_trace_seal_rejects_exdev_without_leaving_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sidecar = tmp_path / "sidecar"
    sidecar.mkdir(mode=0o700)
    staging_parent = tmp_path / "staging"
    staging_parent.mkdir(mode=0o700)
    monkeypatch.setattr(trace, "STAGING_PARENT", staging_parent)
    monkeypatch.setattr(trace, "PRIVATE_EVIDENCE_PARENT", tmp_path)
    monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)
    monkeypatch.setattr(
        trace,
        "_renameat2_noreplace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(errno.EXDEV, "cross-device link")
        ),
    )
    destination = sidecar / "target.strace"
    with trace.PrivateTraceStaging("target") as staging:
        staging.path.write_bytes(b"raw-trace\n")
        with pytest.raises(OSError) as error:
            staging.seal_to(
                destination,
                target_id="target",
                manifest_sha256="a" * 64,
                expected_leader_pid=321,
            )
    assert error.value.errno == errno.EXDEV
    assert not os.path.lexists(destination)


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires Linux root fork/SIGKILL durability recovery",
)
@pytest.mark.parametrize(
    "crash_point",
    [
        "seal-after-journal-fsync",
        "seal-after-source-chmod-before-fsync",
        "seal-after-source-fsync",
        "seal-after-rename-before-directory-fsync",
        "seal-after-directory-fsync",
        "seal-after-sidecar-journal-fsync",
        "seal-after-staging-journal-cleanup",
    ],
)
def test_private_trace_seal_recovers_every_real_sigkill_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
) -> None:
    staging_parent = tmp_path / "staging"
    sidecar = tmp_path / "private" / "evidence" / "runtime-open"
    staging_parent.mkdir(mode=0o700)
    sidecar.mkdir(parents=True, mode=0o700)
    (tmp_path / "private").chmod(0o700)
    (tmp_path / "private" / "evidence").chmod(0o700)
    sidecar.chmod(0o700)
    monkeypatch.setattr(trace, "STAGING_PARENT", staging_parent)
    monkeypatch.setattr(trace, "PRIVATE_EVIDENCE_PARENT", tmp_path / "private")
    monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)

    child = os.fork()
    if child == 0:
        def kill_at(point: str) -> None:
            if point == crash_point:
                os.kill(os.getpid(), signal.SIGKILL)

        trace._crash_injection_gate = kill_at
        with trace.PrivateTraceStaging("target") as staging:
            staging.path.write_bytes(b"raw-trace\n")
            staging.seal_to(
                sidecar / "target.strace",
                target_id="target",
                manifest_sha256="a" * 64,
                expected_leader_pid=321,
            )
        os._exit(70)

    waited, status = os.waitpid(child, 0)
    assert waited == child
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == signal.SIGKILL
    recovered = trace.recover_stale_private_staging(parent=staging_parent)
    assert len(recovered) == 1
    assert not tuple(staging_parent.iterdir())
    raw = sidecar / "target.strace"
    journal = sidecar / ".target.seal.json"
    assert raw.read_bytes() == b"raw-trace\n"
    assert stat.S_IMODE(raw.stat().st_mode) == 0o400
    assert journal.is_file()
    expected = {
        "target_id": "target",
        "manifest_sha256": "a" * 64,
        "expected_leader_pid": 321,
        "path": str(raw),
        "device": raw.stat().st_dev,
        "inode": raw.stat().st_ino,
        "size": raw.stat().st_size,
        "mode": "0400",
        "sha256": hashlib.sha256(b"raw-trace\n").hexdigest(),
    }
    trace.verify_private_seal_sidecar(raw, expected)
    assert not (sidecar / "MANIFEST.json").exists()


def test_strace_handle_digest_is_bound_to_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = trace.TrustedFileIdentity(
        path="/usr/bin/strace",
        sha256="e" * 64,
        size=1,
        device=1,
        inode=2,
        uid=0,
        gid=0,
        mode=0o755,
        links=1,
        mtime_ns=0,
        ctime_ns=0,
    )
    trusted = trace.TrustedExecutable(identity=identity, descriptor=99)
    monkeypatch.setattr(trace.TrustedExecutable, "assert_open", lambda self: None)
    with pytest.raises(trace.RuntimeOpenTraceError, match="manifest binding"):
        trace.build_strace_launch(
            "/var/lib/odoo-accounting-cli-v3/runtime-open-trace/run/trace.log",
            manifest(),
            trusted,
        )


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX replace-on-open semantics")
def test_replacing_strace_path_after_fd_validation_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = tmp_path / "strace"
    tool.write_bytes(b"trusted")
    tool.chmod(0o755)
    descriptor = os.open(tool, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    metadata = os.fstat(descriptor)
    trusted = trace.TrustedExecutable(
        identity=trace.TrustedFileIdentity(
            path=tool.as_posix(),
            sha256=hashlib.sha256(b"trusted").hexdigest(),
            size=7,
            device=metadata.st_dev,
            inode=metadata.st_ino,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mode=0o755,
            links=metadata.st_nlink,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
        ),
        descriptor=descriptor,
    )
    monkeypatch.setattr(trace, "STRACE_PATH", tool)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"malicious")
    replacement.chmod(0o755)
    os.replace(replacement, tool)
    with pytest.raises(trace.RuntimeOpenTraceError, match="changed after validation"):
        trusted.close()
    assert trusted.descriptor == -1


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX same-inode write")
def test_same_inode_strace_content_drift_is_rejected_on_post_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = tmp_path / "strace"
    tool.write_bytes(b"trusted-v1")
    tool.chmod(0o755)
    descriptor = os.open(tool, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    metadata = os.fstat(descriptor)
    trusted = trace.TrustedExecutable(
        identity=trace.TrustedFileIdentity(
            path=tool.as_posix(),
            sha256=hashlib.sha256(b"trusted-v1").hexdigest(),
            size=len(b"trusted-v1"),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            uid=metadata.st_uid,
            gid=metadata.st_gid,
            mode=0o755,
            links=metadata.st_nlink,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
        ),
        descriptor=descriptor,
    )
    monkeypatch.setattr(trace, "STRACE_PATH", tool)
    tool.write_bytes(b"tampered-v2")
    tool.chmod(0o755)
    # Force this assertion through the independent end-of-window re-hash path;
    # the pre-launch metadata check is covered by the replacement test above.
    monkeypatch.setattr(trace.TrustedExecutable, "assert_open", lambda self: None)
    with pytest.raises(trace.RuntimeOpenTraceError, match="execution window"):
        trusted.close()
    assert trusted.descriptor == -1


def test_fd_hash_identity_detects_tool_content_tamper(tmp_path: Path) -> None:
    tool = tmp_path / "strace"
    tool.write_bytes(b"trusted-tool-v1")
    tool.chmod(0o755)
    metadata = tool.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    digest = hashlib.sha256(tool.read_bytes()).hexdigest()
    payload, identity = trace._read_trusted_regular(
        tool,
        digest,
        expected_mode=mode,
        max_bytes=1024,
        expected_uid=metadata.st_uid,
        expected_gid=metadata.st_gid,
    )
    assert payload == b"trusted-tool-v1"
    assert identity.sha256 == digest
    tool.write_bytes(b"tampered-tool!")
    tool.chmod(mode)
    with pytest.raises(trace.RuntimeOpenTraceError, match="digest mismatch"):
        trace._read_trusted_regular(
            tool,
            digest,
            expected_mode=mode,
            max_bytes=1024,
            expected_uid=metadata.st_uid,
            expected_gid=metadata.st_gid,
        )


def test_mutation_watch_includes_modify_and_guard_requires_finish() -> None:
    assert trace.IN_REJECT_MASK & trace.IN_MODIFY

    class FakeWatch:
        closed = False

        def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
            self.closed = True

    guard = trace.RuntimeEnvironmentGuard(manifest())
    watch = FakeWatch()
    guard.before = {}
    guard.watch = watch  # type: ignore[assignment]
    with pytest.raises(trace.RuntimeOpenTraceError, match="without finish"):
        guard.__exit__(None, None, None)
    assert watch.closed


def test_static_closure_pin_is_separate_from_dynamic_namespace_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    static = {"schema_version": 1, "closure": "fixed"}
    dynamic = {"schema_version": 1, "mount_namespace": {"inode": 77}}
    captured = {
        "schema_version": 2,
        "static_closure": static,
        "dynamic_namespace_receipt": dynamic,
    }

    class FakeWatch:
        def __init__(self, roots: tuple[str, ...]) -> None:
            assert roots

        def __enter__(self) -> "FakeWatch":
            return self

        def assert_clean(self) -> None:
            return None

        def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
            return None

    monkeypatch.setattr(trace, "capture_runtime_environment", lambda _manifest: captured)
    monkeypatch.setattr(trace, "MutationWatch", FakeWatch)
    expected = hashlib.sha256(trace.canonical_json(static)).hexdigest()
    with trace.RuntimeEnvironmentGuard(
        replace(manifest(), expected_static_closure_sha256=expected)
    ) as guard:
        guard.finish()
        receipt = guard.receipt()
    assert receipt == {
        "schema_version": 1,
        "static_closure_sha256": expected,
        "dynamic_namespace_receipt_sha256": hashlib.sha256(
            trace.canonical_json(dynamic)
        ).hexdigest(),
    }


def test_dynamic_namespace_drift_is_rejected_even_with_same_static_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    static = {"schema_version": 1, "closure": "fixed"}
    before = {
        "schema_version": 2,
        "static_closure": static,
        "dynamic_namespace_receipt": {"mountinfo_sha256": "1" * 64},
    }
    after = {
        **before,
        "dynamic_namespace_receipt": {"mountinfo_sha256": "2" * 64},
    }
    captures = iter((before, before, after))

    class FakeWatch:
        def __init__(self, _roots: tuple[str, ...]) -> None:
            return None

        def __enter__(self) -> "FakeWatch":
            return self

        def assert_clean(self) -> None:
            return None

        def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
            return None

    monkeypatch.setattr(trace, "capture_runtime_environment", lambda _manifest: next(captures))
    monkeypatch.setattr(trace, "MutationWatch", FakeWatch)
    expected = hashlib.sha256(trace.canonical_json(static)).hexdigest()
    with pytest.raises(trace.RuntimeOpenTraceError, match="post-trace"):
        with trace.RuntimeEnvironmentGuard(
            replace(manifest(), expected_static_closure_sha256=expected)
        ) as guard:
            guard.finish()


@pytest.mark.skipif(os.name != "posix", reason="requires Linux procfs cwd evidence")
def test_capture_rejects_live_cwd_but_excludes_supervisor_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)
    clean_environment = dict(os.environ)
    selected = replace(
        manifest(),
        working_directory=tmp_path.as_posix(),
        watch_roots=(tmp_path.as_posix(),),
        environment=clean_environment,
    )
    with pytest.raises(trace.RuntimeOpenTraceError, match="cwd identity"):
        trace.capture_runtime_environment(selected)
    monkeypatch.chdir(tmp_path)
    captured = trace.capture_runtime_environment(selected)
    assert captured["dynamic_namespace_receipt"]["working_directory"]["path"] == tmp_path.as_posix()
    monkeypatch.setenv("DEV29_UNEXPECTED", "1")
    assert trace.capture_runtime_environment(selected) == captured
    assert "child_environment_sha256" not in captured
    assert "child_environment_sha256" not in captured["static_closure"]


@pytest.mark.parametrize(
    "payload,error",
    [
        (b"HOME=/fixed", "truncated"),
        (b"HOME=/one\0HOME=/two\0", "ambiguous"),
        (b"HOME=/fixed\0\xff=x\0", "not UTF-8"),
        (b"HOME=/fixed\0BROKEN\0", "invalid"),
    ],
)
def test_tracee_environment_parser_rejects_ambiguous_proc_payloads(
    payload: bytes, error: str
) -> None:
    with pytest.raises(trace.RuntimeOpenTraceError, match=error):
        trace._parse_tracee_environment(payload)


def test_tracee_environment_parser_canonicalizes_exact_child_map() -> None:
    payload = b"PATH=/usr/bin:/bin\0HOME=/child-home\0EMPTY=\0"
    assert trace._parse_tracee_environment(payload) == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/child-home",
        "EMPTY": "",
    }


def test_proc_starttime_and_crash_recovery_directory_identity_are_pid_reuse_safe(
    tmp_path: Path,
) -> None:
    proc = tmp_path / "proc"
    stat_path = proc / "321" / "stat"
    stat_path.parent.mkdir(parents=True)
    fields = ["S", *("0" for _ in range(18)), "987654"]
    stat_path.write_text(f"321 (worker with ) paren) {' '.join(fields)}\n", encoding="ascii")
    assert trace._proc_starttime(321, proc_root=proc) == 987654
    name = trace._staging_name("run-a", 321, 987654)
    match = trace.STAGING_DIRECTORY.fullmatch(name)
    assert match is not None
    assert match.group(1, 2) == ("321", "987654")


def test_result_explicitly_cannot_promote_production_by_itself() -> None:
    result = trace.validate_trace_bytes(
        raw_trace(), manifest(), expected_leader_pid=410
    )
    assert result.production_promotion_allowed is False
    with pytest.raises(trace.RuntimeOpenTraceError, match="no private verifier handle"):
        result.verification_handle()


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() != 0,
    reason="private trace evidence is root-owned POSIX state",
)
def test_independent_verifier_reopens_and_reparses_same_private_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)
    path = tmp_path / "trace.log"
    path.write_bytes(raw_trace())
    path.chmod(0o400)
    first = trace.validate_trace_file(
        path, manifest(), expected_leader_pid=410
    )
    assert first.verification_handle().trace_inode == path.stat().st_ino
    assert trace.reverify_trace_result(first, manifest()) is first
    path.chmod(0o600)
    path.write_bytes(raw_trace(exit_code=1))
    path.chmod(0o400)
    with pytest.raises(trace.RuntimeOpenTraceError, match="digest mismatch"):
        trace.reverify_trace_result(first, manifest())


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() != 0,
    reason="private staging mode identity is root-owned POSIX state",
)
def test_preseal_validator_explicitly_binds_mode_0600_and_reverify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)
    path = tmp_path / "trace.log"
    path.write_bytes(raw_trace())
    path.chmod(0o600)
    with pytest.raises(
        trace.RuntimeOpenTraceError,
        match="ownership/mode/link identity",
    ):
        trace.validate_trace_file(path, manifest(), expected_leader_pid=410)
    result = trace.validate_trace_file(
        path,
        manifest(),
        expected_leader_pid=410,
        expected_mode=0o600,
    )
    assert result.verification_handle().trace_mode == 0o600
    assert trace.reverify_trace_result(result, manifest()) is result


def _capture_real_fixture(
    path: Path, trusted: trace.TrustedExecutable
) -> tuple[bytes, subprocess.Popen[bytes]]:
    code = (
        "import os,time;time.sleep(0.35);"
        "os.execve('/usr/bin/true',['/usr/bin/true'],{})"
    )
    bootstrap = ("/usr/bin/python3", "-I", "-S", "-c", code)
    command = (
        trusted.launch_path,
        *trace.STRACE_OPTIONS,
        f"--output={path}",
        "--",
        *bootstrap,
    )
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=path.parent,
        env=dict(trace.ROLE_ENVIRONMENTS["signer"]),
        pass_fds=trusted.pass_fds,
    )
    return code.encode(), process


@pytest.mark.skipif(
    os.environ.get("DEV29_REAL_RUNTIME_TRACE_TEST") != "1",
    reason="set DEV29_REAL_RUNTIME_TRACE_TEST=1 for fixed real-Linux strace smoke",
)
def test_real_linux_fixed_harmless_runtime_trace_and_proc_exe(tmp_path: Path) -> None:
    assert os.name == "posix"
    assert trace.STRACE_PATH == Path("/usr/bin/strace")
    assert Path("/usr/bin/python3").exists()
    assert Path("/usr/bin/true").exists()
    digest = hashlib.sha256(trace.STRACE_PATH.read_bytes()).hexdigest()
    with trace.validate_strace_tool(digest) as trusted:
        first_path = tmp_path / "first.trace"
        code_bytes, first = _capture_real_fixture(first_path, trusted)
        assert code_bytes
        first_tracer_pid = trace.verify_traced_process(
            first.pid, trusted, require_sync_stop=False
        )
        assert first_tracer_pid != first.pid
        stdout, stderr = first.communicate(timeout=10)
        assert first.returncode == 0
        assert stdout == b""
        assert stderr == b""
        first_parsed = trace.parse_trace_bytes(
            first_path.read_bytes(),
            working_directory=tmp_path.as_posix(),
            expected_leader_pid=first.pid,
        )

        second_path = tmp_path / "second.trace"
        _code_bytes, second = _capture_real_fixture(second_path, trusted)
        second_tracer_pid = trace.verify_traced_process(
            second.pid, trusted, require_sync_stop=False
        )
        assert second_tracer_pid != second.pid
        stdout, stderr = second.communicate(timeout=10)
        assert second.returncode == 0
        assert stdout == b""
        assert stderr == b""
        second_parsed = trace.parse_trace_bytes(
            second_path.read_bytes(),
            working_directory=tmp_path.as_posix(),
            expected_leader_pid=second.pid,
        )
    assert second_parsed.paths == first_parsed.paths
    assert second_parsed.execve_argv == first_parsed.execve_argv
    assert second_parsed.leader_returncode == 0


@pytest.mark.skipif(
    os.environ.get("DEV29_REAL_MULTIROLE_TRACE_TEST") != "1",
    reason="set DEV29_REAL_MULTIROLE_TRACE_TEST=1 for Odoo/Postgres root trace gate",
)
def test_real_runtime_trace_gate_binds_odoo_and_postgres_child_homes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name != "posix" or os.geteuid() != 0:
        pytest.skip("real multi-role RuntimeTraceGate requires Linux root")
    if not Path("/usr/bin/python3.12").is_file() or not trace.STRACE_PATH.is_file():
        pytest.skip("fixed Python/strace runtime is unavailable")
    releases = Path("/opt/odoo-accounting-cli-v3/releases")
    if not releases.is_dir():
        pytest.skip("canonical release parent is unavailable")

    suite_path = ROOT / "deployment" / "dev29" / "run_read_suite.py"
    suite_spec = importlib.util.spec_from_file_location(
        "dev29_multirole_run_read_suite", suite_path
    )
    assert suite_spec is not None and suite_spec.loader is not None
    suite_module = importlib.util.module_from_spec(suite_spec)
    sys.modules[suite_spec.name] = suite_module
    suite_spec.loader.exec_module(suite_module)

    release = f"dev29-multirole-{os.getpid()}"
    release_root = releases / release
    private_root = tmp_path / "private"
    sidecar = private_root / "evidence" / "runtime-open"
    staging_parent = tmp_path / "staging"
    assert not release_root.exists()
    process_paths: list[Path] = []
    try:
        dev29 = release_root / "deployment" / "dev29"
        binary = release_root / "bin"
        dev29.mkdir(parents=True, mode=0o755)
        binary.mkdir(mode=0o755)
        runtime = dev29 / "runtime_open_trace.py"
        direct = dev29 / "direct_child.py"
        odoo_script = binary / "odoo-accounting-cli-v3"
        postgres_script = dev29 / "read_oracles.py"
        runtime.write_bytes(SCRIPT.read_bytes())
        direct.write_text(
            "import os,sys\n"
            "index=sys.argv.index('--')\n"
            "argv=sys.argv[index+1:]\n"
            "os.execve(argv[0],argv,dict(os.environ))\n",
            encoding="utf-8",
        )
        child_program = (
            "import json,os\n"
            "print(json.dumps(dict(os.environ),sort_keys=True,separators=(',',':')))\n"
        )
        odoo_script.write_text(child_program, encoding="utf-8")
        postgres_script.write_text(child_program, encoding="utf-8")
        process_paths.extend((runtime, direct, odoo_script, postgres_script))
        for path in process_paths:
            path.chmod(0o555)
        staging_parent.mkdir(mode=0o700)
        sidecar.mkdir(parents=True, mode=0o700)
        private_root.chmod(0o700)
        (private_root / "evidence").chmod(0o700)
        sidecar.chmod(0o700)
        monkeypatch.setattr(trace, "STAGING_PARENT", staging_parent)
        monkeypatch.setattr(trace, "PRIVATE_EVIDENCE_PARENT", private_root)
        monkeypatch.setattr(trace, "_validate_root_chain", lambda _path: None)
        monkeypatch.chdir(release_root)
        digest = hashlib.sha256(trace.STRACE_PATH.read_bytes()).hexdigest()
        mounts = tuple(
            json.dumps({"mount": index}, sort_keys=True, separators=(",", ":"))
            for index in range(5)
        )

        def build_manifest(target_id: str, role: str) -> trace.TraceManifest:
            final_script = odoo_script if role == "odoo" else postgres_script
            final = ("/usr/bin/python3.12", "-I", final_script.as_posix())
            bootstrap = (
                "/usr/bin/python3.12",
                "-I",
                direct.as_posix(),
                "--role",
                role,
                "--attestation-fd",
                "7",
                "--expected-uid",
                "65534",
                "--expected-gid",
                "65534",
                "--expected-python",
                "/usr/bin/python3.12",
                "--expected-venv-root",
                "/opt/odoo-accounting-cli-v3/dependencies/odoo19-venv",
                "--release-root",
                release_root.as_posix(),
                "--expected-self-namespace-device",
                "4",
                "--expected-self-namespace-inode",
                "100",
                "--expected-host-namespace-device",
                "4",
                "--expected-host-namespace-inode",
                "200",
                "--expected-loop-device",
                "/dev/loop7",
                *(item for mount in mounts for item in ("--expected-mount-json", mount)),
                "--",
                *final,
            )
            environment = dict(trace.ROLE_ENVIRONMENTS[role])
            candidate = trace.TraceManifest(
                release=release,
                target_id=target_id,
                role=role,
                working_directory=release_root.as_posix(),
                environment=environment,
                bootstrap_argv=bootstrap,
                final_argv=final,
                allowed_paths=("/usr/bin/python3.12",),
                path_access_policy=(),
                watch_roots=(release_root.as_posix(),),
                expected_static_closure_sha256="0" * 64,
                expected_child_environment_sha256=hashlib.sha256(
                    trace.canonical_json(environment)
                ).hexdigest(),
                expected_returncodes=(0,),
                expected_uid=65534,
                expected_gid=65534,
                manifest_sha256=hashlib.sha256(target_id.encode()).hexdigest(),
                expected_strace_sha256=digest,
            )
            captured = trace.capture_runtime_environment(candidate)
            return replace(
                candidate,
                expected_static_closure_sha256=hashlib.sha256(
                    trace.canonical_json(captured["static_closure"])
                ).hexdigest(),
            )

        manifests = {
            "multi-odoo": build_manifest("multi-odoo", "odoo"),
            "multi-postgres": build_manifest("multi-postgres", "postgres"),
        }

        class FakeResult:
            production_promotion_allowed = False

            def __init__(self, path: Path) -> None:
                payload = path.read_bytes()
                self._document = {
                    "canonical_path_count": 1,
                    "canonical_path_set_sha256": hashlib.sha256(b"paths").hexdigest(),
                    "trace_sha256": hashlib.sha256(payload).hexdigest(),
                }

            def document(self) -> dict[str, object]:
                return dict(self._document)

        monkeypatch.setattr(
            trace,
            "validate_trace_file",
            lambda path, _manifest, **_kwargs: FakeResult(Path(path)),
        )
        monkeypatch.setattr(
            trace, "reverify_trace_result", lambda result, _manifest: result
        )
        gate = object.__new__(suite_module.RuntimeTraceGate)
        gate.expected = suite_module.ExpectedIdentity(
            release=release,
            version="0.1.0.dev29",
            commit="a1234567890bcdef1234567890abcdef12345678",
            manifest_sha256="a" * 64,
            package_sha256="b" * 64,
        )
        gate.index_sha256 = "c" * 64
        gate.module = trace
        gate.index = {
            "expected_strace_sha256": digest,
            "expected_static_closure_sha256": next(iter(manifests.values())).expected_static_closure_sha256,
            "policy_source_sha256": "d" * 64,
        }
        gate.targets = {}
        gate.receipts = []
        gate.consumed = set()
        gate.private_sidecar = sidecar
        gate.private_entries = []
        gate.manifest = lambda target_id, _bootstrap, _final: manifests[target_id]

        observed: dict[str, dict[str, str]] = {}

        def callback(process: subprocess.Popen[bytes]):
            stdout, stderr = process.communicate(timeout=30)
            assert process.returncode == 0, stderr.decode("utf-8", "replace")
            environment = json.loads(stdout.decode("utf-8"))
            completed = subprocess.CompletedProcess(process.args, 0, stdout, stderr)
            completed.dev29_attestation = {"environment": environment}
            observed[environment["HOME"]] = environment
            return completed

        monkeypatch.setenv("HOME", "/supervisor-home-must-not-bind")
        monkeypatch.setenv("DEV29_SUPERVISOR_ONLY", "1")
        for target_id in ("multi-odoo", "multi-postgres"):
            selected = manifests[target_id]
            gate.execute(
                target_id,
                selected.bootstrap_argv,
                selected.final_argv,
                inherited_fds=(),
                callback=callback,
            )
        assert set(observed) == {
            "/var/lib/odoo-accounting-cli-v3-broker",
            "/var/lib/postgresql",
        }
        assert all("DEV29_SUPERVISOR_ONLY" not in item for item in observed.values())
        receipts = gate.document(("multi-odoo", "multi-postgres"))
        assert len(
            {item["child_environment_sha256"] for item in receipts["receipts"]}
        ) == 2
        gate.seal_private_manifest(("multi-odoo", "multi-postgres"))
        assert not tuple(sidecar.glob(".*.seal.json"))
    finally:
        monkeypatch.chdir(ROOT)
        if release_root.is_dir():
            for path in process_paths:
                if path.exists():
                    path.chmod(0o600)
                    path.unlink()
            for directory in (
                release_root / "bin",
                release_root / "deployment" / "dev29",
                release_root / "deployment",
                release_root,
            ):
                if directory.exists():
                    directory.rmdir()


@pytest.mark.skipif(
    os.environ.get("DEV29_REAL_ROOT_SHIM_TEST") != "1",
    reason="set DEV29_REAL_ROOT_SHIM_TEST=1 for destructive-credential root shim test",
)
def test_real_root_shim_stops_then_drops_credentials_and_rearms_pdeathsig(
    tmp_path: Path,
) -> None:
    if os.name != "posix" or os.geteuid() != 0:
        pytest.skip("real credential-drop shim requires Linux root")
    if not Path("/usr/bin/python3.12").exists():
        pytest.skip("fixed system Python is unavailable")
    releases = Path("/opt/odoo-accounting-cli-v3/releases")
    if not releases.is_dir():
        pytest.skip("fixed release parent is unavailable")
    release = f"dev29-shim-test-{os.getpid()}"
    release_root = releases / release
    assert not release_root.exists()
    deployment = release_root / "deployment"
    dev29 = deployment / "dev29"
    runtime = dev29 / "runtime_open_trace.py"
    direct = dev29 / "direct_child.py"
    final_script = dev29 / "sign_read.py"
    process: subprocess.Popen[bytes] | None = None
    try:
        dev29.mkdir(parents=True, mode=0o755)
        runtime.write_bytes(SCRIPT.read_bytes())
        direct.write_text(
            "import os,sys\n"
            "index=sys.argv.index('--')\n"
            "argv=sys.argv[index+1:]\n"
            "os.execve(argv[0],argv,dict(os.environ))\n",
            encoding="utf-8",
        )
        final_script.write_text(
            "import ctypes,os\n"
            "value=ctypes.c_int(0)\n"
            "libc=ctypes.CDLL(None,use_errno=True)\n"
            "ok=libc.prctl(2,ctypes.byref(value),0,0,0)==0\n"
            "status=open('/proc/self/status',encoding='ascii').read()\n"
            "ok=ok and value.value==9 and os.geteuid()==65534 and os.getegid()==65534\n"
            "ok=ok and os.getgroups()==[] and 'NoNewPrivs:\\t1' in status\n"
            "raise SystemExit(0 if ok else 70)\n",
            encoding="utf-8",
        )
        for path in (runtime, direct, final_script):
            path.chmod(0o555)
        final = (
            "/usr/bin/python3.12",
            "-I",
            "-S",
            final_script.as_posix(),
        )
        mounts = tuple(
            json.dumps({"mount": index}, sort_keys=True, separators=(",", ":"))
            for index in range(5)
        )
        bootstrap = (
            "/usr/bin/python3.12",
            "-I",
            "-S",
            direct.as_posix(),
            "--role",
            "signer",
            "--attestation-fd",
            "7",
            "--expected-uid",
            "65534",
            "--expected-gid",
            "65534",
            "--expected-python",
            "/usr/bin/python3.12",
            "--expected-venv-root",
            "/opt/odoo-accounting-cli-v3/dependencies/odoo19-venv",
            "--release-root",
            release_root.as_posix(),
            "--expected-self-namespace-device",
            "4",
            "--expected-self-namespace-inode",
            "100",
            "--expected-host-namespace-device",
            "4",
            "--expected-host-namespace-inode",
            "200",
            "--expected-loop-device",
            "/dev/loop7",
            *(item for mount in mounts for item in ("--expected-mount-json", mount)),
            "--",
            *final,
        )
        digest = hashlib.sha256(trace.STRACE_PATH.read_bytes()).hexdigest()
        shim_manifest = trace.TraceManifest(
            release=release,
            target_id="real-root-shim",
            role="signer",
            working_directory=release_root.as_posix(),
            environment=dict(trace.ROLE_ENVIRONMENTS["signer"]),
            bootstrap_argv=bootstrap,
            final_argv=final,
            allowed_paths=("/usr/bin/python3.12",),
            path_access_policy=policies(("/usr/bin/python3.12",)),
            watch_roots=(release_root.as_posix(),),
            expected_static_closure_sha256="a" * 64,
            expected_child_environment_sha256=hashlib.sha256(
                trace.canonical_json(trace.ROLE_ENVIRONMENTS["signer"])
            ).hexdigest(),
            expected_returncodes=(0,),
            expected_uid=65534,
            expected_gid=65534,
            manifest_sha256="b" * 64,
            expected_strace_sha256=digest,
        )
        trace_path = tmp_path / "root-shim.trace"
        with trace.validate_strace_tool(digest) as trusted:
            process = trace.launch_traced_process(trace_path, shim_manifest, trusted)
            tracer_pid = trace.verify_and_release_traced_process(
                process.pid, trusted, shim_manifest
            )
            assert tracer_pid != process.pid
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stderr.decode("utf-8", "replace")
            assert stdout == b""
            assert stderr == b""
        parsed = trace.parse_trace_bytes(
            trace_path.read_bytes(),
            working_directory=release_root.as_posix(),
            expected_leader_pid=process.pid,
        )
        assert parsed.execve_argv == shim_manifest.expected_execve_argv
        assert parsed.leader_returncode == 0
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for path in (final_script, direct, runtime):
            if path.exists():
                path.unlink()
        for directory in (dev29, deployment, release_root):
            if directory.exists():
                directory.rmdir()

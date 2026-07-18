from __future__ import annotations

import errno
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deployment" / "dev19" / "sandbox_namespace_probe.py"
SPEC = importlib.util.spec_from_file_location("dev19_sandbox_namespace_probe", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


NONCE = "a" * 64
NAMESPACES = {
    "mount": "mnt:[4026533001]",
    "network": "net:[4026533002]",
    "pid": "pid:[4026533003]",
    "user": "user:[4026533004]",
}


def request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": probe.REQUEST_KIND,
        "challenge_nonce": NONCE,
        "expected_runtime": {
            "uid": 2101,
            "gid": 2101,
            "supplementary_gids": [2101, 2102],
            "namespaces": deepcopy(NAMESPACES),
            "uid_map_sha256": "b" * 64,
            "gid_map_sha256": "c" * 64,
        },
        "protected_paths": ["/etc/odoo19.conf", "/mnt/odoo/odoo19/filestore"],
        "protected_postgresql_sockets": ["/run/postgresql/.s.PGSQL.5432"],
        "protected_database_endpoints": [
            {
                "endpoint_id": "production-primary",
                "socket_path": "/run/postgresql/.s.PGSQL.5432",
                "port": 5432,
                "database_name": "odoo",
                "role_name": "odoo",
            }
        ],
        "immutable_addon_canaries": [
            "/opt/odoo-accounting-cli-v3/releases/dev19/odoo_addons/.immutable-canary"
        ],
        "outbound_probe": {"ipv4": "192.0.2.17", "port": 443},
    }


def runtime() -> dict[str, object]:
    return {
        "platform": "linux",
        "isolated": True,
        "dont_write_bytecode": True,
        "no_site": True,
        "safe_path": True,
        "no_user_site": True,
        "ignore_environment": True,
        "optimize": 0,
        "uid": 2101,
        "gid": 2101,
        "resuids": [2101, 2101, 2101],
        "resgids": [2101, 2101, 2101],
        "status_uids": [2101, 2101, 2101, 2101],
        "status_gids": [2101, 2101, 2101, 2101],
        "supplementary_gids": [2101, 2102],
        "namespaces": deepcopy(NAMESPACES),
        "capabilities": {
            "inheritable": "0000000000000000",
            "permitted": "0000000000000000",
            "effective": "0000000000000000",
            "bounding": "0000000000000000",
            "ambient": "0000000000000000",
        },
        "no_new_privileges": True,
        "uid_map_sha256": "b" * 64,
        "gid_map_sha256": "c" * 64,
    }


def test_contract_is_strict_json() -> None:
    with pytest.raises(probe.NamespaceProbeError, match="duplicate"):
        probe.load_strict_json(b'{"kind":"one","kind":"two"}')
    with pytest.raises(probe.NamespaceProbeError, match="non-finite"):
        probe.load_strict_json(b'{"value":NaN}')
    with pytest.raises(probe.NamespaceProbeError, match="UTF-8 JSON"):
        probe.load_strict_json(b"\xff")


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("schema_version",), True),
        (("expected_runtime", "uid"), True),
        (("expected_runtime", "supplementary_gids"), [2101, True]),
        (("protected_database_endpoints", 0, "port"), True),
        (("outbound_probe", "port"), True),
    ],
)
def test_boolean_integer_confusion_is_rejected(
    path: tuple[object, ...], value: object
) -> None:
    candidate: object = request()
    for component in path[:-1]:
        candidate = candidate[component]  # type: ignore[index]
    candidate[path[-1]] = value  # type: ignore[index]

    with pytest.raises(probe.NamespaceProbeError):
        probe.validate_request(candidate)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ((), {**request(), "authorized": False}),
        (
            ("expected_runtime",),
            {**request()["expected_runtime"], "root_allowed": False},
        ),
        (
            ("protected_database_endpoints", 0),
            {
                **request()["protected_database_endpoints"][0],
                "password": "must-not-be-accepted",
            },
        ),
        (("outbound_probe",), {**request()["outbound_probe"], "timeout": 1}),
    ],
)
def test_extra_fields_are_rejected(path: tuple[object, ...], value: object) -> None:
    candidate: object = request()
    if not path:
        candidate = value
    else:
        parent = candidate
        for component in path[:-1]:
            parent = parent[component]  # type: ignore[index]
        parent[path[-1]] = value  # type: ignore[index]

    with pytest.raises(probe.NamespaceProbeError, match="fields"):
        probe.validate_request(candidate)


@pytest.mark.parametrize(
    "ipv4",
    ["127.0.0.1", "10.0.0.1", "8.8.8.8", "192.0.1.255", "2001:db8::1"],
)
def test_outbound_target_must_be_test_net_ipv4(ipv4: str) -> None:
    candidate = request()
    candidate["outbound_probe"]["ipv4"] = ipv4

    with pytest.raises(probe.NamespaceProbeError, match="TEST-NET"):
        probe.validate_request(candidate)


def test_request_requires_unique_canonical_targets() -> None:
    duplicate = request()
    duplicate["protected_paths"].append(duplicate["protected_paths"][0])
    with pytest.raises(probe.NamespaceProbeError, match="unique"):
        probe.validate_request(duplicate)

    noncanonical = request()
    noncanonical["immutable_addon_canaries"][0] = "/opt/releases//canary"
    with pytest.raises(probe.NamespaceProbeError, match="canonical"):
        probe.validate_request(noncanonical)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("platform", "win32", "Linux"),
        ("isolated", False, "-I"),
        ("dont_write_bytecode", False, "-B"),
        ("no_site", False, "-S"),
        ("safe_path", False, "safe path"),
        ("no_user_site", False, "user site"),
        ("ignore_environment", False, "environment"),
        ("optimize", 1, "unoptimized"),
        ("uid", 0, "root"),
        ("uid", 2102, "UID"),
        ("gid", 2102, "GID"),
        ("supplementary_gids", [2101], "supplementary"),
    ],
)
def test_runtime_identity_is_fail_closed(
    field: str, value: object, message: str
) -> None:
    candidate = runtime()
    candidate[field] = value

    with pytest.raises(probe.NamespaceProbeError, match=message):
        probe.validate_runtime(request(), candidate)


@pytest.mark.parametrize("namespace", ["mount", "network", "pid", "user"])
def test_all_four_namespace_identities_are_exact(namespace: str) -> None:
    candidate = runtime()
    candidate["namespaces"][namespace] = candidate["namespaces"][namespace].replace(
        "3", "9", 1
    )

    with pytest.raises(probe.NamespaceProbeError, match="namespace"):
        probe.validate_runtime(request(), candidate)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("resuids", [2101, 2101, 0], "resuid"),
        ("resgids", [2101, 2101, 0], "resgid"),
        ("status_uids", [2101, 2101, 2101, 0], "status UID"),
        ("status_gids", [2101, 2101, 2101, 0], "status GID"),
        ("no_new_privileges", False, "NoNewPrivs"),
        ("uid_map_sha256", "d" * 64, "UID map"),
        ("gid_map_sha256", "d" * 64, "GID map"),
    ],
)
def test_saved_ids_no_new_privileges_and_namespace_maps_are_bound(
    field: str, value: object, message: str
) -> None:
    candidate = runtime()
    candidate[field] = value

    with pytest.raises(probe.NamespaceProbeError, match=message):
        probe.validate_runtime(request(), candidate)


@pytest.mark.parametrize(
    ("field", "message"),
    [("status_uids", "status UID"), ("status_gids", "status GID")],
)
@pytest.mark.parametrize("position", range(4))
def test_all_proc_status_real_effective_saved_and_filesystem_ids_are_bound(
    field: str, message: str, position: int
) -> None:
    candidate = runtime()
    candidate[field][position] = 2102

    with pytest.raises(probe.NamespaceProbeError, match=message):
        probe.validate_runtime(request(), candidate)


@pytest.mark.parametrize(
    "capability",
    ["inheritable", "permitted", "effective", "bounding", "ambient"],
)
def test_every_linux_capability_set_must_be_zero(capability: str) -> None:
    candidate = runtime()
    candidate["capabilities"][capability] = "0000000000000001"

    with pytest.raises(probe.NamespaceProbeError, match="capability"):
        probe.validate_runtime(request(), candidate)


def test_proc_status_security_fields_are_exact_and_unique() -> None:
    valid = (
        b"Uid:\t2101\t2101\t2101\t2101\n"
        b"Gid:\t2101\t2101\t2101\t2101\n"
        b"CapInh:\t0000000000000000\n"
        b"CapPrm:\t0000000000000000\n"
        b"CapEff:\t0000000000000000\n"
        b"CapBnd:\t0000000000000000\n"
        b"CapAmb:\t0000000000000000\n"
        b"NoNewPrivs:\t1\n"
    )
    parsed = probe._parse_status_security(valid)
    assert parsed["no_new_privileges"] is True
    assert parsed["uids"] == [2101, 2101, 2101, 2101]
    assert parsed["gids"] == [2101, 2101, 2101, 2101]
    assert set(parsed["capabilities"]) == {
        "inheritable",
        "permitted",
        "effective",
        "bounding",
        "ambient",
    }

    with pytest.raises(probe.NamespaceProbeError, match="duplicate"):
        probe._parse_status_security(valid + b"CapEff:\t0000000000000000\n")
    with pytest.raises(probe.NamespaceProbeError, match="missing"):
        probe._parse_status_security(valid.replace(b"CapAmb:\t0000000000000000\n", b""))
    with pytest.raises(probe.NamespaceProbeError, match="Uid"):
        probe._parse_status_security(
            valid.replace(
                b"Uid:\t2101\t2101\t2101\t2101\n",
                b"Uid:\t2101\t2101\t2101\n",
            )
        )


def test_runtime_snapshot_reads_effective_identity_and_four_namespaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe.sys, "platform", "linux")
    monkeypatch.setattr(
        probe.sys,
        "flags",
        SimpleNamespace(
            isolated=1,
            dont_write_bytecode=1,
            no_site=1,
            safe_path=True,
            no_user_site=1,
            ignore_environment=1,
            optimize=0,
        ),
    )
    monkeypatch.setattr(probe.os, "geteuid", lambda: 2101, raising=False)
    monkeypatch.setattr(probe.os, "getegid", lambda: 2101, raising=False)
    monkeypatch.setattr(
        probe.os, "getresuid", lambda: (2101, 2101, 2101), raising=False
    )
    monkeypatch.setattr(
        probe.os, "getresgid", lambda: (2101, 2101, 2101), raising=False
    )
    monkeypatch.setattr(probe.os, "getgroups", lambda: [2102, 2101], raising=False)
    links = {
        "/proc/self/ns/mnt": NAMESPACES["mount"],
        "/proc/self/ns/net": NAMESPACES["network"],
        "/proc/self/ns/pid": NAMESPACES["pid"],
        "/proc/self/ns/user": NAMESPACES["user"],
    }
    monkeypatch.setattr(probe.os, "readlink", links.__getitem__)
    proc_files = {
        "/proc/self/status": (
            b"Name:\tpython\n"
            b"Uid:\t2101\t2101\t2101\t2101\n"
            b"Gid:\t2101\t2101\t2101\t2101\n"
            b"CapInh:\t0000000000000000\n"
            b"CapPrm:\t0000000000000000\n"
            b"CapEff:\t0000000000000000\n"
            b"CapBnd:\t0000000000000000\n"
            b"CapAmb:\t0000000000000000\n"
            b"NoNewPrivs:\t1\n"
        ),
        "/proc/self/uid_map": b"uid map fixture\n",
        "/proc/self/gid_map": b"gid map fixture\n",
    }
    monkeypatch.setattr(probe, "_read_proc_bytes", proc_files.__getitem__)
    expected = runtime()
    expected["uid_map_sha256"] = __import__("hashlib").sha256(
        proc_files["/proc/self/uid_map"]
    ).hexdigest()
    expected["gid_map_sha256"] = __import__("hashlib").sha256(
        proc_files["/proc/self/gid_map"]
    ).hexdigest()

    assert probe.capture_runtime() == expected


def fake_stat(*, inode: int = 77, mode: int | None = None, nlink: int = 1) -> object:
    return SimpleNamespace(
        st_dev=9,
        st_ino=inode,
        st_mode=stat.S_IFREG | 0o440 if mode is None else mode,
        st_nlink=nlink,
        st_uid=2101,
        st_gid=2101,
        st_size=0,
        st_mtime_ns=123,
        st_ctime_ns=456,
    )


def install_secure_path_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    lstats: list[object] | None = None,
    fstats: list[object] | None = None,
) -> tuple[list[tuple[str, int, int | None]], list[int]]:
    for name, value in {
        "OPEN_PATH": 0x200000,
        "OPEN_NOFOLLOW": 0x040000,
        "OPEN_DIRECTORY": 0x010000,
        "OPEN_CLOEXEC": 0x080000,
        "OPEN_NONBLOCK": 0x004000,
    }.items():
        monkeypatch.setattr(probe, name, value, raising=False)
    calls: list[tuple[str, int, int | None]] = []
    closed: list[int] = []

    def fake_open(path: str, flags: int, *, dir_fd: int | None = None) -> int:
        calls.append((path, flags, dir_fd))
        return 100 + len(calls)

    lstat_values = list(lstats or [fake_stat(), fake_stat()])
    fstat_values = list(fstats or [fake_stat(), fake_stat(), fake_stat()])
    monkeypatch.setattr(probe, "_open_at", fake_open, raising=False)
    monkeypatch.setattr(probe, "_close_fd", closed.append, raising=False)
    monkeypatch.setattr(
        probe,
        "_lstat_at",
        lambda _name, _dir_fd: lstat_values.pop(0),
        raising=False,
    )
    monkeypatch.setattr(
        probe, "_fstat", lambda _fd: fstat_values.pop(0), raising=False
    )
    return calls, closed


@pytest.mark.parametrize(
    ("function_name", "access_mode"),
    [("probe_read_open", os.O_RDONLY), ("probe_write_open", os.O_WRONLY)],
)
def test_path_probes_walk_every_component_without_following_or_mutating(
    monkeypatch: pytest.MonkeyPatch,
    function_name: str,
    access_mode: int,
) -> None:
    calls, closed = install_secure_path_fakes(monkeypatch)

    result = getattr(probe, function_name)("/one/two/canary")

    assert result["result"] == "opened"
    assert result["errno"] == 0
    assert result["entity_stable"] is True
    assert [item[0] for item in calls] == ["/", "one", "two", "canary", "canary"]
    assert calls[1][2] == 101
    assert calls[2][2] == 102
    assert calls[3][2] == 103
    assert calls[4][2] == 103
    for _name, flags, _dir_fd in calls[1:]:
        assert flags & probe.OPEN_NOFOLLOW
    access_mode_mask = os.O_WRONLY | os.O_RDWR
    assert calls[-1][1] & access_mode_mask == access_mode
    forbidden = os.O_CREAT | os.O_TRUNC | os.O_APPEND
    assert all(flags & forbidden == 0 for _name, flags, _dir_fd in calls)
    assert closed == [105, 104, 103, 102, 101]


@pytest.mark.parametrize(
    "bad_stat",
    [
        fake_stat(mode=stat.S_IFLNK | 0o777),
        fake_stat(nlink=2),
    ],
)
def test_canary_requires_a_single_link_regular_file_before_write_open(
    monkeypatch: pytest.MonkeyPatch, bad_stat: object
) -> None:
    calls, _closed = install_secure_path_fakes(
        monkeypatch,
        lstats=[bad_stat],
        fstats=[bad_stat],
    )

    result = probe.probe_write_open("/one/canary")

    assert result["result"] == "precondition_failed"
    assert not any(flags & os.O_WRONLY for _name, flags, _dir_fd in calls)


def test_canary_entity_replacement_is_detected_before_write_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, _closed = install_secure_path_fakes(
        monkeypatch,
        lstats=[fake_stat(inode=77)],
        fstats=[fake_stat(inode=78)],
    )

    result = probe.probe_write_open("/one/canary")

    assert result["result"] == "identity_changed"
    assert not any(flags & os.O_WRONLY for _name, flags, _dir_fd in calls)


def test_canary_entity_replacement_after_open_is_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls, _closed = install_secure_path_fakes(
        monkeypatch,
        lstats=[fake_stat(inode=77), fake_stat(inode=77)],
        fstats=[
            fake_stat(inode=77),
            fake_stat(inode=77),
            fake_stat(inode=78),
        ],
    )

    result = probe.probe_write_open("/one/canary")

    assert result["result"] == "identity_changed"
    assert result["entity_stable"] is False
    assert any(flags & os.O_WRONLY for _name, flags, _dir_fd in calls)


def test_open_probe_records_exact_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        "OPEN_PATH": 0x200000,
        "OPEN_NOFOLLOW": 0x040000,
        "OPEN_DIRECTORY": 0x010000,
        "OPEN_CLOEXEC": 0x080000,
    }.items():
        monkeypatch.setattr(probe, name, value)

    def denied(_path: str, _flags: int, *, dir_fd: int | None = None) -> int:
        raise OSError(errno.EACCES, os.strerror(errno.EACCES))

    monkeypatch.setattr(probe, "_open_at", denied, raising=False)

    result = probe.probe_read_open("/protected")

    assert result["result"] == "open_failed"
    assert result["errno"] == errno.EACCES
    assert result["errno_name"] == "EACCES"


class FakeSocket:
    def __init__(self, family: int, kind: int, outcomes: list[object], calls: list[object]):
        self.family = family
        self.kind = kind
        self.outcomes = outcomes
        self.calls = calls

    def __enter__(self) -> FakeSocket:
        return self

    def __exit__(self, *_args: object) -> None:
        self.calls.append("closed")

    def settimeout(self, timeout: float) -> None:
        self.calls.append(("timeout", timeout))

    def connect(self, target: object) -> None:
        self.calls.append(("connect", target))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome


def test_socket_probes_only_connect_and_record_exact_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    outcomes: list[object] = [
        None,
        OSError(errno.ENOENT, "missing"),
        OSError(errno.ENETUNREACH, "no route"),
    ]

    def socket_factory(family: int, kind: int) -> FakeSocket:
        return FakeSocket(family, kind, outcomes, calls)

    monkeypatch.setattr(probe.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(probe.socket, "socket", socket_factory)

    assert probe.probe_unix_connect("/run/postgresql/.s.PGSQL.5432") == {
        "result": "connected",
        "errno": 0,
        "errno_name": "OK",
    }
    assert probe.probe_unix_connect("/run/postgresql/.s.PGSQL.5433") == {
        "result": "connect_failed",
        "errno": errno.ENOENT,
        "errno_name": "ENOENT",
    }
    assert probe.probe_outbound_connect("192.0.2.17", 443) == {
        "result": "connect_failed",
        "errno": errno.ENETUNREACH,
        "errno_name": errno.errorcode[errno.ENETUNREACH],
    }
    assert ("connect", "/run/postgresql/.s.PGSQL.5432") in calls
    assert ("connect", ("192.0.2.17", 443)) in calls
    assert calls.count("closed") == 3


def test_timeout_without_errno_is_only_a_raw_connect_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[object] = []
    outcomes: list[object] = [TimeoutError("timed out")]
    monkeypatch.setattr(probe.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(
        probe.socket,
        "socket",
        lambda family, kind: FakeSocket(family, kind, outcomes, calls),
    )

    result = probe.probe_unix_connect("/run/postgresql/.s.PGSQL.5432")

    assert result == {
        "result": "connect_failed",
        "errno": None,
        "errno_name": "NO_ERRNO",
    }
    assert "denied" not in json.dumps(result).lower()


def test_inherited_fd_enumeration_includes_stdio_and_ignores_races(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe.os, "listdir", lambda path: ["0", "1", "2", "3", "9", "nonnumeric"])

    def fake_readlink(path: str) -> str:
        if path.endswith("/9"):
            raise OSError(errno.ENOENT, "raced")
        return "socket:[98765]"

    monkeypatch.setattr(probe.os, "readlink", fake_readlink)

    assert probe.enumerate_inherited_fds() == [
        {"fd": 0, "target": "socket:[98765]"},
        {"fd": 1, "target": "socket:[98765]"},
        {"fd": 2, "target": "socket:[98765]"},
        {"fd": 3, "target": "socket:[98765]"},
    ]


def stdio_snapshot() -> list[dict[str, object]]:
    return [
        {"fd": 0, "target": "pipe:[1001]"},
        {"fd": 1, "target": "pipe:[1002]"},
        {"fd": 2, "target": "pipe:[1003]"},
    ]


def test_stdio_contract_requires_three_distinct_anonymous_pipes_and_no_extra_fd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe.sys, "platform", "linux")
    monkeypatch.setattr(probe, "enumerate_inherited_fds", stdio_snapshot)
    monkeypatch.setattr(
        probe,
        "_fstat",
        lambda descriptor: SimpleNamespace(
            st_mode=stat.S_IFIFO | 0o600,
            st_dev=8,
            st_ino=1001 + descriptor,
        ),
    )
    monkeypatch.setattr(
        probe,
        "_get_fd_status_flags",
        lambda descriptor: os.O_RDONLY if descriptor == 0 else os.O_WRONLY,
    )
    monkeypatch.setattr(probe.sys.stdin, "fileno", lambda: 0)
    monkeypatch.setattr(probe.sys.stdout, "fileno", lambda: 1)
    monkeypatch.setattr(probe.sys.stderr, "fileno", lambda: 2)

    assert probe.validate_stdio_contract() == stdio_snapshot()

    monkeypatch.setattr(
        probe,
        "enumerate_inherited_fds",
        lambda: [*stdio_snapshot(), {"fd": 9, "target": "socket:[9999]"}],
    )
    with pytest.raises(probe.NamespaceProbeError, match="exactly descriptors 0, 1, and 2"):
        probe.validate_stdio_contract()


@pytest.mark.parametrize(
    "snapshots",
    [
        [{"fd": 0, "target": "pipe:[1001]"}, {"fd": 1, "target": "pipe:[1002]"}],
        [
            {"fd": 0, "target": "pipe:[1001]"},
            {"fd": 1, "target": "pipe:[1002]"},
            {"fd": 2, "target": "pipe:[1002]"},
        ],
        [
            {"fd": 0, "target": "/tmp/named-fifo"},
            {"fd": 1, "target": "pipe:[1002]"},
            {"fd": 2, "target": "pipe:[1003]"},
        ],
    ],
)
def test_stdio_snapshot_rejects_missing_reused_or_nonanonymous_pipe(
    snapshots: list[dict[str, object]],
) -> None:
    with pytest.raises(probe.NamespaceProbeError, match="stdio"):
        probe.validate_stdio_snapshot(snapshots)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux procfs/fcntl contract")
def test_real_linux_subprocess_accepts_only_three_stdio_pipes() -> None:
    module_literal = repr(str(MODULE_PATH))
    child = (
        "import os,runpy;"
        f"m=runpy.run_path({module_literal},run_name='probe_test');"
        "m['validate_stdio_contract']();"
        "os.write(1,b'ok\\n')"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-S", "-c", child],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert completed.stdout == b"ok\n"
    assert completed.stderr == b""


@pytest.mark.skipif(sys.platform != "linux", reason="Linux procfs/fcntl contract")
def test_real_linux_subprocess_rejects_an_extra_inherited_fd() -> None:
    module_literal = repr(str(MODULE_PATH))
    child = (
        "import os,runpy;"
        f"m=runpy.run_path({module_literal},run_name='probe_test');"
        "\ntry:m['validate_stdio_contract']()"
        "\nexcept Exception:os._exit(77)"
        "\nos.write(1,b'unexpected\\n')"
    )
    inherited_read, inherited_write = os.pipe()
    try:
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-S", "-c", child],
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(inherited_read,),
            check=False,
        )
    finally:
        os.close(inherited_read)
        os.close(inherited_write)

    assert completed.returncode == 77
    assert completed.stdout == b""
    assert completed.stderr == b""


def test_collect_returns_only_untrusted_facts_and_no_eligibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "capture_runtime", runtime)
    fd_snapshots = [
        stdio_snapshot(),
        stdio_snapshot(),
    ]
    monkeypatch.setattr(
        probe, "enumerate_inherited_fds", lambda: fd_snapshots.pop(0)
    )
    monkeypatch.setattr(
        probe,
        "probe_read_open",
        lambda _path: {"result": "open_failed", "errno": 13, "errno_name": "EACCES"},
    )
    monkeypatch.setattr(
        probe,
        "probe_write_open",
        lambda _path: {"result": "open_failed", "errno": 30, "errno_name": "EROFS"},
    )
    monkeypatch.setattr(
        probe,
        "probe_unix_connect",
        lambda _path: {"result": "connect_failed", "errno": 2, "errno_name": "ENOENT"},
    )
    monkeypatch.setattr(
        probe,
        "probe_outbound_connect",
        lambda _ipv4, _port: {
            "result": "connect_failed",
            "errno": 101,
            "errno_name": "ENETUNREACH",
        },
    )

    output = probe.collect(request())

    assert output["kind"] == probe.OBSERVATION_KIND
    assert output["challenge_nonce"] == NONCE
    assert output["evidence_trust"] == "untrusted_namespace_facts"
    assert output["trusted_evidence"] is False
    assert output["probe_mode"] == "open_without_payload_write_and_connect"
    assert output["isolation_gate_passed"] is False
    assert output["eligible_for_sandbox_write_staging_review"] is False
    assert output["promotion_evidence"] is False
    for field in probe.AUTHORIZATION_FIELDS:
        assert output[field] is False
    assert output["runtime"] == runtime()
    assert output["inherited_fds_before"] == stdio_snapshot()
    assert output["inherited_fds_after"] == stdio_snapshot()
    assert output["protected_database_endpoint_probes"] == [
        {
            **request()["protected_database_endpoints"][0],
            "probe_scope": "unix_socket_transport_only",
            "result": "connect_failed",
            "errno": 2,
            "errno_name": "ENOENT",
        }
    ]


def test_runtime_failure_happens_before_any_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    bad_runtime = runtime()
    bad_runtime["uid"] = 0
    monkeypatch.setattr(probe, "capture_runtime", lambda: bad_runtime)
    monkeypatch.setattr(
        probe,
        "enumerate_inherited_fds",
        lambda: pytest.fail("must not enumerate FDs in an invalid runtime"),
    )

    with pytest.raises(probe.NamespaceProbeError, match="root"):
        probe.collect(request())


def test_collect_rejects_extra_fd_before_any_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe, "capture_runtime", runtime)
    monkeypatch.setattr(
        probe,
        "enumerate_inherited_fds",
        lambda: [*stdio_snapshot(), {"fd": 8, "target": "socket:[8008]"}],
    )
    monkeypatch.setattr(
        probe,
        "probe_read_open",
        lambda _path: pytest.fail("must not probe with an extra inherited FD"),
    )

    with pytest.raises(probe.NamespaceProbeError, match="exactly descriptors 0, 1, and 2"):
        probe.collect(request())


def test_main_reads_only_stdin_and_emits_canonical_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "kind": probe.OBSERVATION_KIND,
        "trusted_evidence": False,
        **{field: False for field in probe.AUTHORIZATION_FIELDS},
        **{field: False for field in probe.NON_PROMOTION_FIELDS},
    }
    monkeypatch.setattr(
        probe,
        "collect",
        lambda value: expected if value == request() else pytest.fail("wrong request"),
    )
    monkeypatch.setattr(probe, "validate_stdio_contract", stdio_snapshot)
    stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(request()).encode("utf-8")))
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(probe.sys, "stdin", stdin)
    monkeypatch.setattr(probe.sys, "stdout", stdout)
    monkeypatch.setattr(probe.sys, "stderr", stderr)

    assert probe.main([]) == 0
    assert stdout.getvalue() == json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
    assert stderr.getvalue() == ""


def test_main_rejects_arguments_without_reading_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForbiddenInput:
        def read(self, _size: int) -> bytes:
            pytest.fail("stdin must not be read when arguments are present")

    monkeypatch.setattr(probe.sys, "stdin", SimpleNamespace(buffer=ForbiddenInput()))
    monkeypatch.setattr(probe.sys, "stderr", io.StringIO())
    monkeypatch.setattr(probe, "validate_stdio_contract", stdio_snapshot)

    assert probe.main(["--observation", "/tmp/forged.json"]) == 2
    error = json.loads(probe.sys.stderr.getvalue())
    assert error["ok"] is False
    assert error["trusted_evidence"] is False
    assert error["isolation_gate_passed"] is False
    assert error["eligible_for_sandbox_write_staging_review"] is False
    assert error["promotion_evidence"] is False
    for field in probe.AUTHORIZATION_FIELDS:
        assert error[field] is False


def test_main_is_silent_and_does_not_read_when_stdio_is_untrusted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ForbiddenInput:
        def read(self, _size: int) -> bytes:
            pytest.fail("untrusted stdin must not be read")

    class ForbiddenOutput:
        def write(self, _value: str) -> None:
            pytest.fail("untrusted stdout or stderr must not be written")

    def reject_stdio() -> list[dict[str, object]]:
        raise probe.NamespaceProbeError("unsafe stdio")

    monkeypatch.setattr(probe, "validate_stdio_contract", reject_stdio)
    monkeypatch.setattr(probe.sys, "stdin", SimpleNamespace(buffer=ForbiddenInput()))
    monkeypatch.setattr(probe.sys, "stdout", ForbiddenOutput())
    monkeypatch.setattr(probe.sys, "stderr", ForbiddenOutput())

    assert probe.main([]) == 2


def test_main_revalidates_stdio_immediately_before_writing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "kind": probe.OBSERVATION_KIND,
        "trusted_evidence": False,
        **{field: False for field in probe.AUTHORIZATION_FIELDS},
        **{field: False for field in probe.NON_PROMOTION_FIELDS},
    }
    checks = 0

    def changing_stdio() -> list[dict[str, object]]:
        nonlocal checks
        checks += 1
        if checks > 1:
            raise probe.NamespaceProbeError("stdio changed")
        return stdio_snapshot()

    monkeypatch.setattr(probe, "validate_stdio_contract", changing_stdio)
    monkeypatch.setattr(probe, "collect", lambda _value: expected)
    monkeypatch.setattr(
        probe.sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(json.dumps(request()).encode("utf-8"))),
    )
    stdout = io.StringIO()
    stderr = io.StringIO()
    monkeypatch.setattr(probe.sys, "stdout", stdout)
    monkeypatch.setattr(probe.sys, "stderr", stderr)

    assert probe.main([]) == 2
    assert checks == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == ""

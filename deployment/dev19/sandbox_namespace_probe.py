#!/usr/bin/env python3
"""Collect untrusted open-without-payload-write and connect facts.

This helper is intended to be started as ``python -I -B -S`` after a trusted
collector has placed it in the proposed sandbox service namespaces and
dropped privileges.  Its output is never an isolation verdict or an
authorization.  It never creates, truncates, appends to, or writes file
payload bytes, but it does request an ``O_WRONLY`` open and socket connects;
successful connects can produce server-side logs.  A separate trusted
collector must bind and evaluate its raw facts.
"""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import sys
from pathlib import PurePosixPath
from typing import Any


REQUEST_KIND = "odoo-accounting-cli-v3.sandbox-namespace-probe-request.v1"
OBSERVATION_KIND = "odoo-accounting-cli-v3.sandbox-namespace-probe-observation.v1"
ERROR_KIND = "odoo-accounting-cli-v3.sandbox-namespace-probe-error.v1"
MAX_INPUT_BYTES = 262_144
MAX_LIST_ENTRIES = 256
MAX_INHERITED_FDS = 4096
CONNECT_TIMEOUT_SECONDS = 0.5
MAX_PROC_BYTES = 65_536

OPEN_PATH = getattr(os, "O_PATH", 0)
OPEN_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
OPEN_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
OPEN_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
OPEN_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
OPEN_ACCESS_MASK = getattr(os, "O_ACCMODE", 3)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DATABASE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$")
ROLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,62}$")
CAPABILITY_HEX = re.compile(r"^[0-9a-f]{16}$")
PIPE_TARGET = re.compile(r"^pipe:\[([1-9][0-9]*)\]$")
NAMESPACE_PATTERNS = {
    "mount": re.compile(r"^mnt:\[[1-9][0-9]*\]$"),
    "network": re.compile(r"^net:\[[1-9][0-9]*\]$"),
    "pid": re.compile(r"^pid:\[[1-9][0-9]*\]$"),
    "user": re.compile(r"^user:\[[1-9][0-9]*\]$"),
}
TEST_NETS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
AUTHORIZATION_FIELDS = (
    "sandbox_provisioning_authorized",
    "sandbox_accounting_write_authorized",
    "production_accounting_write_authorized",
    "registry_change_authorized",
)
NON_PROMOTION_FIELDS = (
    "isolation_gate_passed",
    "eligible_for_sandbox_write_staging_review",
    "promotion_evidence",
)


class NamespaceProbeError(RuntimeError):
    """The request or runtime is not safe enough to run this probe."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NamespaceProbeError(message)


def _reject_duplicate_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NamespaceProbeError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> object:
    raise NamespaceProbeError(f"non-finite JSON number: {value}")


def load_strict_json(payload: bytes) -> object:
    _require(isinstance(payload, bytes), "input must be bytes")
    _require(len(payload) <= MAX_INPUT_BYTES, "JSON input is too large")
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_nonfinite,
        )
    except NamespaceProbeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NamespaceProbeError("input must be strict UTF-8 JSON") from exc


def _exact_object(
    value: object, fields: set[str], label: str
) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(set(value) == fields, f"{label} fields are invalid")
    return value


def _exact_list(
    value: object,
    label: str,
    *,
    require_nonempty: bool = True,
) -> list[Any]:
    _require(isinstance(value, list), f"{label} must be an array")
    _require(len(value) <= MAX_LIST_ENTRIES, f"{label} has too many entries")
    if require_nonempty:
        _require(bool(value), f"{label} must not be empty")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        f"{label} must be an integer",
    )
    _require(minimum <= value <= maximum, f"{label} is out of range")
    return value


def _hex64(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and HEX64.fullmatch(value) is not None,
        f"{label} must be 64 lowercase hexadecimal characters",
    )
    return value


def _absolute_path(value: object, label: str) -> str:
    _require(
        isinstance(value, str)
        and 0 < len(value) <= 4096
        and value.startswith("/")
        and not value.startswith("//")
        and all(ord(character) >= 32 and ord(character) != 127 for character in value),
        f"{label} must be an absolute path without control characters",
    )
    path = PurePosixPath(value)
    _require(
        str(path) == value and "." not in path.parts and ".." not in path.parts,
        f"{label} must be a canonical absolute path",
    )
    return value


def _unique_paths(value: object, label: str) -> list[str]:
    items = _exact_list(value, label)
    paths = [
        _absolute_path(item, f"{label} entry {index}")
        for index, item in enumerate(items)
    ]
    _require("/" not in paths, f"{label} must not contain the filesystem root")
    _require(len(paths) == len(set(paths)), f"{label} entries must be unique")
    return paths


def _supplementary_gids(value: object, label: str) -> list[int]:
    items = _exact_list(value, label, require_nonempty=False)
    gids = [
        _integer(item, f"{label} entry {index}", minimum=1, maximum=2**31 - 1)
        for index, item in enumerate(items)
    ]
    _require(gids == sorted(set(gids)), f"{label} must be sorted and unique")
    return gids


def _namespaces(value: object, label: str) -> dict[str, str]:
    namespaces = _exact_object(value, set(NAMESPACE_PATTERNS), label)
    result: dict[str, str] = {}
    for name, pattern in NAMESPACE_PATTERNS.items():
        identity = namespaces[name]
        _require(
            isinstance(identity, str) and pattern.fullmatch(identity) is not None,
            f"{label} {name} namespace identity is invalid",
        )
        result[name] = identity
    return result


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def validate_request(value: object) -> dict[str, Any]:
    request = _exact_object(
        value,
        {
            "schema_version",
            "kind",
            "challenge_nonce",
            "expected_runtime",
            "protected_paths",
            "protected_postgresql_sockets",
            "protected_database_endpoints",
            "immutable_addon_canaries",
            "outbound_probe",
        },
        "request",
    )
    _require(
        type(request["schema_version"]) is int and request["schema_version"] == 1,
        "request schema version mismatch",
    )
    _require(request["kind"] == REQUEST_KIND, "request kind mismatch")
    _require(
        isinstance(request["challenge_nonce"], str)
        and HEX64.fullmatch(request["challenge_nonce"]) is not None,
        "challenge nonce must be 64 lowercase hexadecimal characters",
    )

    expected_runtime = _exact_object(
        request["expected_runtime"],
        {
            "uid",
            "gid",
            "supplementary_gids",
            "namespaces",
            "uid_map_sha256",
            "gid_map_sha256",
        },
        "expected runtime",
    )
    _integer(
        expected_runtime["uid"],
        "expected runtime UID",
        minimum=1,
        maximum=2**31 - 1,
    )
    _integer(
        expected_runtime["gid"],
        "expected runtime GID",
        minimum=1,
        maximum=2**31 - 1,
    )
    _supplementary_gids(
        expected_runtime["supplementary_gids"],
        "expected supplementary GIDs",
    )
    _namespaces(expected_runtime["namespaces"], "expected runtime namespaces")
    _hex64(expected_runtime["uid_map_sha256"], "expected UID map SHA-256")
    _hex64(expected_runtime["gid_map_sha256"], "expected GID map SHA-256")

    protected_paths = _unique_paths(request["protected_paths"], "protected paths")
    protected_sockets = _unique_paths(
        request["protected_postgresql_sockets"],
        "protected PostgreSQL sockets",
    )
    for index, path in enumerate(protected_sockets):
        _require(
            re.fullmatch(r"\.s\.PGSQL\.[1-9][0-9]{0,4}", PurePosixPath(path).name)
            is not None,
            f"protected PostgreSQL socket {index} is not a PostgreSQL Unix socket path",
        )

    endpoint_items = _exact_list(
        request["protected_database_endpoints"],
        "protected database endpoints",
    )
    endpoint_ids: set[str] = set()
    endpoint_bindings: set[tuple[str, int, str, str]] = set()
    for index, item in enumerate(endpoint_items):
        endpoint = _exact_object(
            item,
            {"endpoint_id", "socket_path", "port", "database_name", "role_name"},
            f"protected database endpoint {index}",
        )
        endpoint_id = endpoint["endpoint_id"]
        _require(
            isinstance(endpoint_id, str) and SAFE_ID.fullmatch(endpoint_id) is not None,
            f"protected database endpoint {index} ID is invalid",
        )
        socket_path = _absolute_path(
            endpoint["socket_path"],
            f"protected database endpoint {index} socket path",
        )
        port = _integer(
            endpoint["port"],
            f"protected database endpoint {index} port",
            minimum=1,
            maximum=65_535,
        )
        database_name = endpoint["database_name"]
        role_name = endpoint["role_name"]
        _require(
            isinstance(database_name, str)
            and DATABASE_NAME.fullmatch(database_name) is not None,
            f"protected database endpoint {index} database name is invalid",
        )
        _require(
            isinstance(role_name, str) and ROLE_NAME.fullmatch(role_name) is not None,
            f"protected database endpoint {index} role name is invalid",
        )
        _require(
            socket_path in protected_sockets,
            f"protected database endpoint {index} socket is not protected",
        )
        _require(
            PurePosixPath(socket_path).name == f".s.PGSQL.{port}",
            f"protected database endpoint {index} port does not bind its socket",
        )
        binding = (socket_path, port, database_name, role_name)
        _require(endpoint_id not in endpoint_ids, "endpoint IDs must be unique")
        _require(binding not in endpoint_bindings, "endpoint bindings must be unique")
        endpoint_ids.add(endpoint_id)
        endpoint_bindings.add(binding)

    addon_canaries = _unique_paths(
        request["immutable_addon_canaries"],
        "immutable add-on canaries",
    )
    _require(
        not set(addon_canaries).intersection(protected_paths),
        "immutable add-on canaries and protected paths must be distinct",
    )

    outbound = _exact_object(
        request["outbound_probe"], {"ipv4", "port"}, "outbound probe"
    )
    _require(isinstance(outbound["ipv4"], str), "outbound IPv4 must be a string")
    try:
        outbound_address = ipaddress.ip_address(outbound["ipv4"])
    except ValueError as exc:
        raise NamespaceProbeError("outbound address must be a TEST-NET IPv4 address") from exc
    _require(
        isinstance(outbound_address, ipaddress.IPv4Address)
        and any(outbound_address in network for network in TEST_NETS),
        "outbound address must be a TEST-NET IPv4 address",
    )
    _integer(outbound["port"], "outbound port", minimum=1, maximum=65_535)
    return request


def _read_proc_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as stream:
            payload = stream.read(MAX_PROC_BYTES + 1)
    except OSError as exc:
        raise NamespaceProbeError(f"cannot read required procfs fact: {path}") from exc
    _require(payload and len(payload) <= MAX_PROC_BYTES, f"invalid procfs fact: {path}")
    return payload


def _parse_status_security(payload: bytes) -> dict[str, object]:
    _require(isinstance(payload, bytes), "proc status must be bytes")
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise NamespaceProbeError("proc status must be ASCII") from exc
    wanted = {
        "CapInh": "inheritable",
        "CapPrm": "permitted",
        "CapEff": "effective",
        "CapBnd": "bounding",
        "CapAmb": "ambient",
    }
    wanted_ids = {"Uid": "uids", "Gid": "gids"}
    capabilities: dict[str, str] = {}
    identities: dict[str, list[int]] = {}
    no_new_privileges: bool | None = None
    seen: set[str] = set()
    for line in lines:
        key, separator, raw_value = line.partition(":")
        if not separator or key not in {*wanted, *wanted_ids, "NoNewPrivs"}:
            continue
        _require(key not in seen, f"duplicate proc status security field: {key}")
        seen.add(key)
        value = raw_value.strip()
        if key in wanted_ids:
            components = value.split()
            _require(
                len(components) == 4
                and all(re.fullmatch(r"[0-9]+", item) is not None for item in components),
                f"proc status {key} must contain four decimal IDs",
            )
            values = [int(item, 10) for item in components]
            _require(
                all(item <= 2**32 - 1 for item in values),
                f"proc status {key} contains an out-of-range ID",
            )
            identities[wanted_ids[key]] = values
        elif key == "NoNewPrivs":
            _require(value in {"0", "1"}, "proc status NoNewPrivs is invalid")
            no_new_privileges = value == "1"
        else:
            normalized = value.casefold()
            _require(
                CAPABILITY_HEX.fullmatch(normalized) is not None,
                f"proc status {key} is invalid",
            )
            capabilities[wanted[key]] = normalized
    missing = (set(wanted) | set(wanted_ids)) - seen
    if "NoNewPrivs" not in seen:
        missing.add("NoNewPrivs")
    _require(not missing, "proc status security fields are missing")
    assert no_new_privileges is not None
    return {
        "capabilities": capabilities,
        "no_new_privileges": no_new_privileges,
        **identities,
    }


def capture_runtime() -> dict[str, object]:
    _require(sys.platform == "linux", "probe runtime must be Linux")
    flags = sys.flags
    _require(flags.isolated == 1, "probe runtime must use Python -I")
    _require(
        flags.dont_write_bytecode == 1,
        "probe runtime must use Python -B",
    )
    _require(flags.no_site == 1, "probe runtime must use Python -S")
    _require(flags.safe_path is True, "probe runtime must use a safe path")
    _require(flags.no_user_site == 1, "probe runtime must disable the user site")
    _require(
        flags.ignore_environment == 1,
        "probe runtime must ignore the Python environment",
    )
    _require(flags.optimize == 0, "probe runtime must be unoptimized")
    namespaces = {
        "mount": os.readlink("/proc/self/ns/mnt"),
        "network": os.readlink("/proc/self/ns/net"),
        "pid": os.readlink("/proc/self/ns/pid"),
        "user": os.readlink("/proc/self/ns/user"),
    }
    status = _parse_status_security(_read_proc_bytes("/proc/self/status"))
    uid_map = _read_proc_bytes("/proc/self/uid_map")
    gid_map = _read_proc_bytes("/proc/self/gid_map")
    return {
        "platform": sys.platform,
        "isolated": flags.isolated == 1,
        "dont_write_bytecode": flags.dont_write_bytecode == 1,
        "no_site": flags.no_site == 1,
        "safe_path": flags.safe_path is True,
        "no_user_site": flags.no_user_site == 1,
        "ignore_environment": flags.ignore_environment == 1,
        "optimize": flags.optimize,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "resuids": list(os.getresuid()),
        "resgids": list(os.getresgid()),
        "status_uids": status["uids"],
        "status_gids": status["gids"],
        "supplementary_gids": sorted(os.getgroups()),
        "namespaces": namespaces,
        "capabilities": status["capabilities"],
        "no_new_privileges": status["no_new_privileges"],
        "uid_map_sha256": hashlib.sha256(uid_map).hexdigest(),
        "gid_map_sha256": hashlib.sha256(gid_map).hexdigest(),
    }


def _id_triplet(value: object, label: str) -> list[int]:
    items = _exact_list(value, label)
    _require(len(items) == 3, f"{label} must contain real, effective, and saved IDs")
    return [
        _integer(item, f"{label} entry {index}", minimum=0, maximum=2**31 - 1)
        for index, item in enumerate(items)
    ]


def _id_quadruplet(value: object, label: str) -> list[int]:
    items = _exact_list(value, label)
    _require(
        len(items) == 4,
        f"{label} must contain real, effective, saved, and filesystem IDs",
    )
    return [
        _integer(item, f"{label} entry {index}", minimum=0, maximum=2**32 - 1)
        for index, item in enumerate(items)
    ]


def _capability_facts(value: object) -> dict[str, str]:
    fields = {"inheritable", "permitted", "effective", "bounding", "ambient"}
    capabilities = _exact_object(value, fields, "runtime capabilities")
    result: dict[str, str] = {}
    for field in sorted(fields):
        item = capabilities[field]
        _require(
            isinstance(item, str) and CAPABILITY_HEX.fullmatch(item) is not None,
            f"runtime {field} capability set is invalid",
        )
        result[field] = item
    return result


def validate_runtime(
    request_value: object, runtime_value: object
) -> dict[str, Any]:
    request = validate_request(request_value)
    runtime = _exact_object(
        runtime_value,
        {
            "platform",
            "isolated",
            "dont_write_bytecode",
            "no_site",
            "safe_path",
            "no_user_site",
            "ignore_environment",
            "optimize",
            "uid",
            "gid",
            "resuids",
            "resgids",
            "status_uids",
            "status_gids",
            "supplementary_gids",
            "namespaces",
            "capabilities",
            "no_new_privileges",
            "uid_map_sha256",
            "gid_map_sha256",
        },
        "runtime",
    )
    _require(runtime["platform"] == "linux", "probe runtime must be Linux")
    _require(runtime["isolated"] is True, "probe runtime must use Python -I")
    _require(
        runtime["dont_write_bytecode"] is True,
        "probe runtime must use Python -B",
    )
    _require(runtime["no_site"] is True, "probe runtime must use Python -S")
    _require(runtime["safe_path"] is True, "probe runtime must use a safe path")
    _require(
        runtime["no_user_site"] is True,
        "probe runtime must disable the user site",
    )
    _require(
        runtime["ignore_environment"] is True,
        "probe runtime must ignore the Python environment",
    )
    _require(
        type(runtime["optimize"]) is int and runtime["optimize"] == 0,
        "probe runtime must be unoptimized",
    )
    uid = _integer(runtime["uid"], "runtime UID", minimum=0, maximum=2**31 - 1)
    gid = _integer(runtime["gid"], "runtime GID", minimum=0, maximum=2**31 - 1)
    resuids = _id_triplet(runtime["resuids"], "runtime resuid")
    resgids = _id_triplet(runtime["resgids"], "runtime resgid")
    status_uids = _id_quadruplet(runtime["status_uids"], "runtime status UID")
    status_gids = _id_quadruplet(runtime["status_gids"], "runtime status GID")
    _require(uid != 0 and gid != 0, "probe runtime must not be root")
    supplementary = _supplementary_gids(
        runtime["supplementary_gids"], "runtime supplementary GIDs"
    )
    namespaces = _namespaces(runtime["namespaces"], "runtime namespaces")
    capabilities = _capability_facts(runtime["capabilities"])
    _require(
        all(value == "0000000000000000" for value in capabilities.values()),
        "runtime capability sets must all be zero",
    )
    _require(
        runtime["no_new_privileges"] is True,
        "runtime NoNewPrivs must be 1",
    )
    uid_map_sha256 = _hex64(runtime["uid_map_sha256"], "runtime UID map SHA-256")
    gid_map_sha256 = _hex64(runtime["gid_map_sha256"], "runtime GID map SHA-256")

    expected = request["expected_runtime"]
    _require(uid == expected["uid"], "runtime UID does not match the request")
    _require(gid == expected["gid"], "runtime GID does not match the request")
    _require(
        resuids == [expected["uid"]] * 3,
        "runtime resuid values do not match the request",
    )
    _require(
        resgids == [expected["gid"]] * 3,
        "runtime resgid values do not match the request",
    )
    _require(
        status_uids == [expected["uid"]] * 4,
        "runtime status UID values do not match the request",
    )
    _require(
        status_gids == [expected["gid"]] * 4,
        "runtime status GID values do not match the request",
    )
    _require(
        supplementary == expected["supplementary_gids"],
        "runtime supplementary GIDs do not match the request",
    )
    _require(
        namespaces == expected["namespaces"],
        "runtime namespace identities do not match the request",
    )
    _require(
        uid_map_sha256 == expected["uid_map_sha256"],
        "runtime UID map does not match the request",
    )
    _require(
        gid_map_sha256 == expected["gid_map_sha256"],
        "runtime GID map does not match the request",
    )
    return runtime


def _probe_result(success: bool, operation: str, error: OSError | None = None) -> dict[str, object]:
    if success:
        return {"result": operation, "errno": 0, "errno_name": "OK"}
    assert error is not None
    number = error.errno if isinstance(error.errno, int) else None
    name = errno.errorcode.get(number, "UNKNOWN_ERRNO") if number is not None else "NO_ERRNO"
    return {"result": f"{operation}_failed", "errno": number, "errno_name": name}


def _open_at(path: str, flags: int, *, dir_fd: int | None = None) -> int:
    if dir_fd is None:
        return os.open(path, flags)
    return os.open(path, flags, dir_fd=dir_fd)


def _close_fd(descriptor: int) -> None:
    os.close(descriptor)


def _lstat_at(name: str, dir_fd: int) -> os.stat_result:
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def _fstat(descriptor: int) -> os.stat_result:
    return os.fstat(descriptor)


def _file_type(mode: int) -> str:
    checks = (
        (stat.S_ISREG, "regular"),
        (stat.S_ISDIR, "directory"),
        (stat.S_ISLNK, "symlink"),
        (stat.S_ISSOCK, "socket"),
        (stat.S_ISFIFO, "fifo"),
        (stat.S_ISBLK, "block_device"),
        (stat.S_ISCHR, "character_device"),
    )
    for check, label in checks:
        if check(mode):
            return label
    return "unknown"


def _stat_fact(value: object) -> dict[str, object]:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    result: dict[str, object] = {}
    for field in fields:
        item = getattr(value, field, None)
        _require(
            isinstance(item, int) and not isinstance(item, bool),
            f"filesystem stat field {field} is invalid",
        )
        result[field.removeprefix("st_")] = item
    result["file_type"] = _file_type(result["mode"])
    return result


def _same_stat(*facts: dict[str, object]) -> bool:
    fields = (
        "dev",
        "ino",
        "mode",
        "nlink",
        "uid",
        "gid",
        "size",
        "mtime_ns",
        "ctime_ns",
    )
    identity = tuple(facts[0][field] for field in fields)
    return all(
        tuple(fact[field] for field in fields) == identity
        for fact in facts[1:]
    )


def _regular_single_link(fact: dict[str, object]) -> bool:
    return fact["file_type"] == "regular" and fact["nlink"] == 1


def _path_facts() -> dict[str, object]:
    return {
        "lstat_before": None,
        "pinned_fstat_before": None,
        "pinned_fstat_after": None,
        "opened_fstat": None,
        "lstat_after": None,
        "entity_stable": None,
        "regular_single_link": None,
        "access_attempt": None,
    }


def _raw_path_result(
    result: str,
    facts: dict[str, object],
    error: OSError | None = None,
) -> dict[str, object]:
    if error is None:
        raw = {"result": result, "errno": None, "errno_name": "NO_ERRNO"}
    else:
        number = error.errno if isinstance(error.errno, int) else None
        name = (
            errno.errorcode.get(number, "UNKNOWN_ERRNO")
            if number is not None
            else "NO_ERRNO"
        )
        raw = {"result": result, "errno": number, "errno_name": name}
    return {**raw, **facts}


def _open_parent_components(path: str) -> tuple[list[int], str]:
    _require(
        all((OPEN_PATH, OPEN_NOFOLLOW, OPEN_DIRECTORY, OPEN_CLOEXEC)),
        "Linux secure open flags are unavailable",
    )
    components = list(PurePosixPath(path).parts[1:])
    _require(bool(components), "probe path cannot be the filesystem root")
    descriptors: list[int] = []
    directory_flags = OPEN_PATH | OPEN_DIRECTORY | OPEN_NOFOLLOW | OPEN_CLOEXEC
    root = _open_at("/", directory_flags, dir_fd=None)
    descriptors.append(root)
    try:
        for component in components[:-1]:
            descriptor = _open_at(
                component,
                directory_flags,
                dir_fd=descriptors[-1],
            )
            descriptors.append(descriptor)
    except OSError:
        _close_descriptors(descriptors)
        raise
    return descriptors, components[-1]


def _close_descriptors(descriptors: list[int]) -> None:
    first_error: OSError | None = None
    for descriptor in reversed(descriptors):
        try:
            _close_fd(descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def _secure_open_probe(
    path: str,
    *,
    access_mode: int,
    require_regular_single_link: bool,
) -> dict[str, object]:
    descriptors: list[int] = []
    facts = _path_facts()
    try:
        parent_descriptors, final_name = _open_parent_components(path)
        descriptors.extend(parent_descriptors)
        parent_fd = parent_descriptors[-1]

        before = _stat_fact(_lstat_at(final_name, parent_fd))
        facts["lstat_before"] = before
        pinned_fd = _open_at(
            final_name,
            OPEN_PATH | OPEN_NOFOLLOW | OPEN_CLOEXEC,
            dir_fd=parent_fd,
        )
        descriptors.append(pinned_fd)
        pinned = _stat_fact(_fstat(pinned_fd))
        facts["pinned_fstat_before"] = pinned
        facts["regular_single_link"] = _regular_single_link(before)
        if not _same_stat(before, pinned):
            facts["entity_stable"] = False
            return _raw_path_result("identity_changed", facts)
        if before["file_type"] == "symlink" or (
            require_regular_single_link and not _regular_single_link(before)
        ):
            facts["entity_stable"] = True
            return _raw_path_result("precondition_failed", facts)

        access_flags = access_mode | OPEN_NOFOLLOW | OPEN_CLOEXEC | OPEN_NONBLOCK
        try:
            opened_fd = _open_at(final_name, access_flags, dir_fd=parent_fd)
        except OSError as exc:
            access_attempt = _probe_result(False, "open", exc)
            facts["access_attempt"] = access_attempt
            pinned_after = _stat_fact(_fstat(pinned_fd))
            after = _stat_fact(_lstat_at(final_name, parent_fd))
            facts["pinned_fstat_after"] = pinned_after
            facts["lstat_after"] = after
            stable = _same_stat(before, pinned, pinned_after, after)
            facts["entity_stable"] = stable
            if not stable:
                return _raw_path_result("identity_changed", facts)
            return {**access_attempt, **facts}

        descriptors.append(opened_fd)
        access_attempt = _probe_result(True, "opened")
        facts["access_attempt"] = access_attempt
        opened = _stat_fact(_fstat(opened_fd))
        pinned_after = _stat_fact(_fstat(pinned_fd))
        after = _stat_fact(_lstat_at(final_name, parent_fd))
        facts["opened_fstat"] = opened
        facts["pinned_fstat_after"] = pinned_after
        facts["lstat_after"] = after
        stable = _same_stat(before, pinned, pinned_after, opened, after)
        facts["entity_stable"] = stable
        if not stable:
            return _raw_path_result("identity_changed", facts)
        if require_regular_single_link and not all(
            _regular_single_link(item)
            for item in (before, pinned, pinned_after, opened, after)
        ):
            return _raw_path_result("precondition_failed", facts)
        return {**access_attempt, **facts}
    except OSError as exc:
        return _raw_path_result("open_failed", facts, exc)
    finally:
        _close_descriptors(descriptors)


def probe_read_open(path: str) -> dict[str, object]:
    return _secure_open_probe(
        path,
        access_mode=os.O_RDONLY,
        require_regular_single_link=False,
    )


def probe_write_open(path: str) -> dict[str, object]:
    return _secure_open_probe(
        path,
        access_mode=os.O_WRONLY,
        require_regular_single_link=True,
    )


def _probe_connect(family: int, target: object) -> dict[str, object]:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(CONNECT_TIMEOUT_SECONDS)
            connection.connect(target)
    except OSError as exc:
        return _probe_result(False, "connect", exc)
    return _probe_result(True, "connected")


def probe_unix_connect(path: str) -> dict[str, object]:
    return _probe_connect(socket.AF_UNIX, path)


def probe_outbound_connect(ipv4: str, port: int) -> dict[str, object]:
    return _probe_connect(socket.AF_INET, (ipv4, port))


def enumerate_inherited_fds() -> list[dict[str, object]]:
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as exc:
        raise NamespaceProbeError("cannot enumerate inherited file descriptors") from exc
    _require(
        len(names) <= MAX_INHERITED_FDS,
        "too many inherited file descriptors",
    )
    descriptors = sorted(
        int(name) for name in names if name.isascii() and name.isdigit()
    )
    result: list[dict[str, object]] = []
    for descriptor in descriptors:
        try:
            target = os.readlink(f"/proc/self/fd/{descriptor}")
        except OSError as exc:
            if exc.errno in {errno.ENOENT, errno.EBADF}:
                continue
            raise NamespaceProbeError(
                f"cannot inspect inherited file descriptor {descriptor}"
            ) from exc
        _require(
            isinstance(target, str)
            and len(target) <= 4096
            and all(ord(character) >= 32 and ord(character) != 127 for character in target),
            "inherited file descriptor target is invalid",
        )
        result.append({"fd": descriptor, "target": target})
    return result


def validate_stdio_snapshot(value: object) -> list[dict[str, object]]:
    _require(isinstance(value, list), "stdio descriptor snapshot must be an array")
    _require(
        len(value) == 3,
        "stdio must contain exactly descriptors 0, 1, and 2",
    )
    result: list[dict[str, object]] = []
    for index, item in enumerate(value):
        descriptor = _exact_object(
            item,
            {"fd", "target"},
            f"stdio descriptor {index}",
        )
        number = _integer(
            descriptor["fd"],
            f"stdio descriptor {index} number",
            minimum=0,
            maximum=MAX_INHERITED_FDS,
        )
        target = descriptor["target"]
        _require(
            isinstance(target, str) and PIPE_TARGET.fullmatch(target) is not None,
            f"stdio descriptor {number} must be an anonymous pipe",
        )
        result.append({"fd": number, "target": target})
    _require(
        [item["fd"] for item in result] == [0, 1, 2],
        "stdio must contain exactly descriptors 0, 1, and 2",
    )
    _require(
        len({item["target"] for item in result}) == 3,
        "stdio descriptors must use three distinct anonymous pipes",
    )
    return result


def _get_fd_status_flags(descriptor: int) -> int:
    try:
        import fcntl
    except ImportError as exc:
        raise NamespaceProbeError("Linux fcntl is unavailable") from exc
    try:
        return int(fcntl.fcntl(descriptor, fcntl.F_GETFL))
    except OSError as exc:
        raise NamespaceProbeError(
            f"cannot inspect stdio descriptor {descriptor} access mode"
        ) from exc


def validate_stdio_contract() -> list[dict[str, object]]:
    _require(sys.platform == "linux", "stdio contract requires Linux")
    snapshot = validate_stdio_snapshot(enumerate_inherited_fds())
    streams = (sys.stdin, sys.stdout, sys.stderr)
    expected_access_modes = (os.O_RDONLY, os.O_WRONLY, os.O_WRONLY)
    identities: set[tuple[int, int]] = set()
    for descriptor, (item, stream, expected_access) in enumerate(
        zip(snapshot, streams, expected_access_modes, strict=True)
    ):
        try:
            stream_descriptor = stream.fileno()
        except (AttributeError, OSError, ValueError) as exc:
            raise NamespaceProbeError(
                f"stdio stream {descriptor} does not expose its descriptor"
            ) from exc
        _require(
            stream_descriptor == descriptor,
            f"stdio stream {descriptor} is not bound to descriptor {descriptor}",
        )
        try:
            facts = _fstat(descriptor)
        except OSError as exc:
            raise NamespaceProbeError(
                f"cannot inspect stdio descriptor {descriptor}"
            ) from exc
        _require(
            stat.S_ISFIFO(facts.st_mode),
            f"stdio descriptor {descriptor} must be an anonymous pipe",
        )
        match = PIPE_TARGET.fullmatch(item["target"])
        assert match is not None
        _require(
            facts.st_ino == int(match.group(1), 10),
            f"stdio descriptor {descriptor} pipe identity is inconsistent",
        )
        identity = (facts.st_dev, facts.st_ino)
        _require(
            identity not in identities,
            "stdio descriptors must have distinct pipe identities",
        )
        identities.add(identity)
        flags = _get_fd_status_flags(descriptor)
        _require(
            flags & OPEN_ACCESS_MASK == expected_access,
            f"stdio descriptor {descriptor} access mode is invalid",
        )
    return snapshot


def _with_target(target: str, result: dict[str, object]) -> dict[str, object]:
    return {"target": target, **result}


def collect(value: object) -> dict[str, object]:
    request = validate_request(value)
    runtime = capture_runtime()
    validate_runtime(request, runtime)

    inherited_fds_before = validate_stdio_snapshot(enumerate_inherited_fds())
    protected_path_probes = [
        _with_target(path, probe_read_open(path)) for path in request["protected_paths"]
    ]
    protected_socket_probes = [
        _with_target(path, probe_unix_connect(path))
        for path in request["protected_postgresql_sockets"]
    ]
    endpoint_probes: list[dict[str, object]] = []
    for endpoint in request["protected_database_endpoints"]:
        endpoint_probes.append(
            {
                **endpoint,
                "probe_scope": "unix_socket_transport_only",
                **probe_unix_connect(endpoint["socket_path"]),
            }
        )
    addon_canary_probes = [
        _with_target(path, probe_write_open(path))
        for path in request["immutable_addon_canaries"]
    ]
    outbound = request["outbound_probe"]
    outbound_result = {
        **outbound,
        **probe_outbound_connect(outbound["ipv4"], outbound["port"]),
    }
    inherited_fds_after = validate_stdio_snapshot(enumerate_inherited_fds())
    _require(
        inherited_fds_after == inherited_fds_before,
        "stdio descriptor bindings changed during the probe",
    )
    authorizations = {field: False for field in AUTHORIZATION_FIELDS}
    non_promotion = {field: False for field in NON_PROMOTION_FIELDS}
    return {
        "schema_version": 1,
        "kind": OBSERVATION_KIND,
        "challenge_nonce": request["challenge_nonce"],
        "request_sha256": _canonical_sha256(request),
        "evidence_trust": "untrusted_namespace_facts",
        "trusted_evidence": False,
        "probe_mode": "open_without_payload_write_and_connect",
        "runtime": runtime,
        "inherited_fds_before": inherited_fds_before,
        "inherited_fds_after": inherited_fds_after,
        "protected_path_probes": protected_path_probes,
        "protected_postgresql_socket_probes": protected_socket_probes,
        "protected_database_endpoint_probes": endpoint_probes,
        "immutable_addon_canary_probes": addon_canary_probes,
        "outbound_probe": outbound_result,
        **authorizations,
        **non_promotion,
    }


def _error_document(code: str, message: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "kind": ERROR_KIND,
        "ok": False,
        "trusted_evidence": False,
        "error": {"code": code, "message": message},
        **{field: False for field in AUTHORIZATION_FIELDS},
        **{field: False for field in NON_PROMOTION_FIELDS},
    }


def _write_json(stream: Any, value: object) -> None:
    stream.write(_canonical_bytes(value).decode("utf-8") + "\n")
    stream.flush()


def _write_json_if_stdio_safe(stream: Any, value: object) -> bool:
    try:
        validate_stdio_contract()
        _write_json(stream, value)
    except (NamespaceProbeError, OSError, ValueError):
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    try:
        validate_stdio_contract()
    except (NamespaceProbeError, OSError, ValueError):
        return 2
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        _write_json_if_stdio_safe(
            sys.stderr,
            _error_document("invalid_invocation", "this probe accepts JSON on stdin only"),
        )
        return 2
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        _require(len(payload) <= MAX_INPUT_BYTES, "JSON input is too large")
        request = load_strict_json(payload)
        observation = collect(request)
    except NamespaceProbeError as exc:
        _write_json_if_stdio_safe(
            sys.stderr,
            _error_document("probe_rejected", str(exc)),
        )
        return 2
    except OSError as exc:
        number = exc.errno if isinstance(exc.errno, int) else None
        name = errno.errorcode.get(number, "UNKNOWN_ERRNO") if number is not None else "NO_ERRNO"
        _write_json_if_stdio_safe(
            sys.stderr,
            _error_document("probe_runtime_error", f"runtime OS error: {name}"),
        )
        return 2
    return 0 if _write_json_if_stdio_safe(sys.stdout, observation) else 2


if __name__ == "__main__":
    raise SystemExit(main())

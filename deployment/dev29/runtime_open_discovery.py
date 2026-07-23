#!/usr/bin/python3 -I
"""Build non-approval Dev29 runtime-open review manifests from raw traces.

This tool is deliberately not a policy installer.  It converts retained raw
strace output plus an operator-supplied execution inventory into deterministic
candidate manifests that must still be reviewed, packaged by
runtime_open_policy_source.py, and separately approved before installation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


sys.dont_write_bytecode = True

DISCOVERY_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-discovery.v1"
REVIEW_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-discovery-review.v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_TRACE_BYTES = 128 * 1024 * 1024
TRACE_RELATIVE = Path("runtime_open_trace.py")
SOURCE_RELATIVE = Path("runtime_open_policy_source.py")


class DiscoveryError(RuntimeError):
    pass


def _load_sibling(module_name: str, relative: Path) -> Any:
    path = Path(__file__).resolve().parent / relative
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise DiscoveryError(f"{relative.name} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


runtime_trace = _load_sibling("_dev29_runtime_open_discovery_trace", TRACE_RELATIVE)
policy_source = _load_sibling(
    "_dev29_runtime_open_discovery_source", SOURCE_RELATIVE
)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DiscoveryError("discovery value is not canonical JSON") from exc


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DiscoveryError("JSON document contains a duplicate key")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise DiscoveryError("discovery inventory cannot be read") from exc
    if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_JSON_BYTES:
        raise DiscoveryError("discovery inventory identity is unsafe")
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise DiscoveryError("discovery inventory JSON is invalid") from exc
    if type(value) is not dict or payload != canonical_json(value) + b"\n":
        raise DiscoveryError("discovery inventory is not canonical JSON plus LF")
    return value


def _read_trace(path: Path) -> bytes:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise DiscoveryError("raw trace cannot be read") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_size <= 0
        or metadata.st_size > MAX_TRACE_BYTES
    ):
        raise DiscoveryError("raw trace identity is unsafe")
    return payload


def _role_for_target(target_id: str) -> str:
    if target_id in {"witness-pre", "witness-post"} or target_id.endswith("-oracle"):
        return "postgres"
    if target_id.endswith("-signer"):
        return "signer"
    if target_id == "independent-verifier":
        return "verifier"
    return "odoo"


def _string_tuple(value: Any, *, label: str, allow_empty: bool = False) -> tuple[str, ...]:
    if (
        type(value) is not list
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise DiscoveryError(f"{label} is invalid")
    return tuple(value)


def _canonical_absolute(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise DiscoveryError(f"{label} is not canonical absolute")
    path = posixpath.normpath(value)
    if path != value or value == "//":
        raise DiscoveryError(f"{label} is not canonical absolute")
    return value


def _covered(path: str, roots: Sequence[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def _policy_for_path(
    path: str,
    accesses: tuple[str, ...],
    outcomes: tuple[str, ...],
    *,
    role: str,
    mutable_roots: Sequence[str],
    watch_roots: Sequence[str],
    sqlite_delta_contract_sha256: str,
) -> dict[str, Any]:
    access = tuple(sorted(set(accesses)))
    success = "success" in outcomes
    errnos = tuple(sorted(item for item in set(outcomes) if item != "success"))
    mutates = bool(set(access) & {"write", "create", "truncate", "append", "delete"})
    if runtime_trace._is_process_view_path(path):
        classification = "process-view"
    elif set(access) <= runtime_trace.SOCKET_ACCESS and any(
        item in access for item in ("unix-connect", "unix-send")
    ):
        classification = "unix-socket"
    elif mutates or _covered(path, mutable_roots):
        classification = "mutable-state"
    else:
        classification = "immutable"

    if classification == "immutable":
        if not _covered(path, watch_roots):
            raise DiscoveryError("immutable discovery path is outside watch roots")
        return {
            "path": path,
            "role": role,
            "classification": classification,
            "allowed_access": list(access),
            "create_suffixes": [],
            "delta_verifier": None,
            "delta_contract_sha256": None,
            "allow_success": success,
            "allowed_errnos": list(errnos),
            "failure_guard": (
                runtime_trace.WATCH_TREE_FAILURE_GUARD if errnos else None
            ),
        }
    if classification == "process-view":
        if _covered(path, watch_roots) or errnos or not success:
            raise DiscoveryError("process-view discovery policy is unsafe")
        return {
            "path": path,
            "role": role,
            "classification": classification,
            "allowed_access": list(access),
            "create_suffixes": [],
            "delta_verifier": None,
            "delta_contract_sha256": None,
            "allow_success": True,
            "allowed_errnos": [],
            "failure_guard": None,
        }
    if classification == "unix-socket":
        if _covered(path, watch_roots) or errnos or not success:
            raise DiscoveryError("unix-socket discovery policy is unsafe")
        return {
            "path": path,
            "role": role,
            "classification": classification,
            "allowed_access": list(access),
            "create_suffixes": [],
            "delta_verifier": None,
            "delta_contract_sha256": None,
            "allow_success": True,
            "allowed_errnos": [],
            "failure_guard": None,
        }
    if _covered(path, watch_roots) or not _covered(path, mutable_roots):
        raise DiscoveryError("mutable discovery path is outside mutable roots")
    return {
        "path": path,
        "role": role,
        "classification": "mutable-state",
        "allowed_access": list(access),
        "create_suffixes": [],
        "delta_verifier": runtime_trace.SQLITE_DELTA_VERIFIER,
        "delta_contract_sha256": sqlite_delta_contract_sha256,
        "allow_success": success,
        "allowed_errnos": list(errnos),
        "failure_guard": (
            runtime_trace.SQLITE_DELTA_VERIFIER if errnos else None
        ),
    }


def _manifest_from_entry(
    entry: Mapping[str, Any],
    *,
    release: str,
    expected_static_closure_sha256: str,
    watch_roots: tuple[str, ...],
    mutable_roots: tuple[str, ...],
    sqlite_delta_contract_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target_id = entry.get("target_id")
    if not isinstance(target_id, str) or SAFE_NAME.fullmatch(target_id) is None:
        raise DiscoveryError("discovery target id is invalid")
    role = entry.get("role", _role_for_target(target_id))
    if role != _role_for_target(target_id) or role not in runtime_trace.ROLE_ENVIRONMENTS:
        raise DiscoveryError("discovery target role is invalid")
    trace_path = Path(entry.get("trace_path", ""))
    leader_pid = entry.get("expected_leader_pid")
    if type(leader_pid) is not int or leader_pid <= 1:
        raise DiscoveryError("discovery leader pid is invalid")
    final = _string_tuple(entry.get("final_argv"), label="final argv")
    bootstrap = _string_tuple(entry.get("bootstrap_argv"), label="bootstrap argv")
    working_directory = _canonical_absolute(
        entry.get("working_directory"), label="working directory"
    )
    expected_returncodes = entry.get("expected_returncodes")
    if (
        type(expected_returncodes) is not list
        or not expected_returncodes
        or expected_returncodes != sorted(set(expected_returncodes))
        or any(type(item) is not int or item < 0 or item > 255 for item in expected_returncodes)
    ):
        raise DiscoveryError("discovery return-code set is invalid")

    payload = _read_trace(trace_path)
    try:
        parsed = runtime_trace.parse_trace_bytes(
            payload,
            working_directory=working_directory,
            expected_leader_pid=leader_pid,
        )
    except runtime_trace.RuntimeOpenTraceError as exc:
        raise DiscoveryError("raw trace cannot be parsed for review") from exc
    if parsed.leader_returncode not in expected_returncodes:
        raise DiscoveryError("raw trace return code is outside discovery contract")
    release_root = f"/opt/odoo-accounting-cli-v3/releases/{release}"
    try:
        template = runtime_trace.dynamic_bootstrap_template(
            bootstrap,
            final,
            role=role,
            release_root=release_root,
        )
    except runtime_trace.RuntimeOpenTraceError as exc:
        raise DiscoveryError("discovery bootstrap argv cannot be templated") from exc
    access_by_path = {path: access for path, access in parsed.accesses}
    outcomes_by_path: dict[str, list[str]] = {path: [] for path in parsed.paths}
    for path, _access, outcome in parsed.attempts:
        outcomes_by_path.setdefault(path, []).append(outcome)
    policies = [
        _policy_for_path(
            path,
            access_by_path[path],
            tuple(outcomes_by_path[path]),
            role=role,
            mutable_roots=mutable_roots,
            watch_roots=watch_roots,
            sqlite_delta_contract_sha256=sqlite_delta_contract_sha256,
        )
        for path in parsed.paths
    ]
    environment = dict(runtime_trace.ROLE_ENVIRONMENTS[role])
    manifest = {
        "schema_version": 1,
        "scope": runtime_trace.SCOPE,
        "release": release,
        "target_id": target_id,
        "role": role,
        "working_directory": working_directory,
        "environment": environment,
        "bootstrap_argv": list(template),
        "final_argv": list(final),
        "allowed_paths": list(parsed.paths),
        "path_access_policy": policies,
        "watch_roots": list(watch_roots),
        "expected_static_closure_sha256": expected_static_closure_sha256,
        "expected_child_environment_sha256": hashlib.sha256(
            runtime_trace.canonical_json(environment)
        ).hexdigest(),
        "expected_watch_roots_sha256": hashlib.sha256(
            runtime_trace.canonical_json(watch_roots)
        ).hexdigest(),
        "expected_returncodes": list(expected_returncodes),
    }
    request = runtime_trace.TraceRequest(
        release=release,
        target_id=target_id,
        expected_manifest_sha256=hashlib.sha256(canonical_json(manifest) + b"\n").hexdigest(),
        expected_strace_sha256="0" * 64,
        expected_static_closure_sha256=expected_static_closure_sha256,
        expected_child_environment_sha256=manifest["expected_child_environment_sha256"],
        expected_watch_roots_sha256=manifest["expected_watch_roots_sha256"],
    )
    try:
        runtime_trace.validate_manifest_document(manifest, request)
    except runtime_trace.RuntimeOpenTraceError as exc:
        raise DiscoveryError("discovery candidate manifest is invalid") from exc
    review = {
        "target_id": target_id,
        "trace_path": str(trace_path),
        "trace_sha256": hashlib.sha256(payload).hexdigest(),
        "canonical_path_count": len(parsed.paths),
        "canonical_path_set_sha256": hashlib.sha256(
            runtime_trace.canonical_json(parsed.paths)
        ).hexdigest(),
        "leader_returncode": parsed.leader_returncode,
        "candidate_manifest_sha256": request.expected_manifest_sha256,
        "candidate_is_approval": False,
    }
    return manifest, review


def build_review(
    inventory: Mapping[str, Any],
    *,
    output_directory: Path,
) -> dict[str, Any]:
    if type(inventory) is not dict or set(inventory) != {
        "schema_version",
        "scope",
        "release",
        "expected_static_closure_sha256",
        "watch_roots",
        "mutable_roots",
        "sqlite_delta_contract_sha256",
        "targets",
    }:
        raise DiscoveryError("discovery inventory schema is invalid")
    release = inventory.get("release")
    static = inventory.get("expected_static_closure_sha256")
    delta = inventory.get("sqlite_delta_contract_sha256")
    if (
        type(inventory.get("schema_version")) is not int
        or inventory.get("schema_version") != 1
        or inventory.get("scope") != DISCOVERY_SCOPE
        or not isinstance(release, str)
        or SAFE_NAME.fullmatch(release) is None
        or not isinstance(static, str)
        or HEX64.fullmatch(static) is None
        or not isinstance(delta, str)
        or HEX64.fullmatch(delta) is None
    ):
        raise DiscoveryError("discovery inventory identity is invalid")
    watch_roots = tuple(
        _canonical_absolute(item, label="watch root")
        for item in _string_tuple(inventory.get("watch_roots"), label="watch roots")
    )
    mutable_roots = tuple(
        _canonical_absolute(item, label="mutable root")
        for item in _string_tuple(
            inventory.get("mutable_roots"), label="mutable roots", allow_empty=True
        )
    )
    if (
        tuple(sorted(set(watch_roots))) != watch_roots
        or tuple(sorted(set(mutable_roots))) != mutable_roots
        or any(_covered(root, watch_roots) for root in mutable_roots)
    ):
        raise DiscoveryError("discovery roots are not safe and deterministic")
    targets = inventory.get("targets")
    if type(targets) is not list:
        raise DiscoveryError("discovery target set is invalid")
    ordered = [item.get("target_id") if type(item) is dict else None for item in targets]
    if tuple(ordered) != policy_source.expected_targets():
        raise DiscoveryError("discovery target order is incomplete")
    if output_directory.exists() or output_directory.is_symlink():
        raise DiscoveryError("discovery output directory already exists")
    output_directory.mkdir(mode=0o700)
    reviews: list[dict[str, Any]] = []
    try:
        for entry in targets:
            manifest, review = _manifest_from_entry(
                entry,
                release=release,
                expected_static_closure_sha256=static,
                watch_roots=watch_roots,
                mutable_roots=mutable_roots,
                sqlite_delta_contract_sha256=delta,
            )
            (output_directory / f"{manifest['target_id']}.json").write_bytes(
                canonical_json(manifest) + b"\n"
            )
            reviews.append(review)
        review_document = {
            "schema_version": 1,
            "scope": REVIEW_SCOPE,
            "release": release,
            "target_order": list(policy_source.expected_targets()),
            "manifest_directory": str(output_directory),
            "reviews": reviews,
            "candidate_is_approval": False,
            "production_promotion_allowed": False,
        }
        review_payload = canonical_json(review_document) + b"\n"
        (output_directory / "DISCOVERY-REVIEW.json").write_bytes(review_payload)
    except BaseException:
        for child in output_directory.iterdir():
            child.unlink()
        output_directory.rmdir()
        raise
    return {
        "schema_version": 1,
        "review_path": str(output_directory / "DISCOVERY-REVIEW.json"),
        "manifest_directory": str(output_directory),
        "target_count": len(reviews),
        "review_sha256": hashlib.sha256(review_payload).hexdigest(),
        "candidate_is_approval": False,
        "production_promotion_allowed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        result = build_review(
            _read_json(arguments.inventory),
            output_directory=arguments.output_directory,
        )
    except (OSError, DiscoveryError) as exc:
        print(f"Dev29 runtime-open discovery refused: {exc}", file=sys.stderr)
        return 2
    print(canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

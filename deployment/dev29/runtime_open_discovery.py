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
from typing import Any, Callable, Iterable, Mapping, Sequence


sys.dont_write_bytecode = True

DISCOVERY_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-discovery.v1"
SUITE_FRAGMENT_SCOPE = (
    "odoo-accounting-cli-v3.dev29.runtime-open-discovery-suite-fragment.v1"
)
VERIFIER_FRAGMENT_SCOPE = (
    "odoo-accounting-cli-v3.dev29.runtime-open-discovery-verifier-fragment.v1"
)
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
FIXED_NON_POLICY_TARGET_REASONS = {
    "boundary-probe": (
        "read-boundary evidence intentionally exercises the controlled Odoo-shell "
        "subprocess boundary and is not eligible for single-leader runtime-open "
        "path-policy approval"
    )
}


def non_policy_target_reason(target_id: str) -> str | None:
    if target_id in FIXED_NON_POLICY_TARGET_REASONS:
        return FIXED_NON_POLICY_TARGET_REASONS[target_id]
    if target_id.endswith("-read"):
        return (
            "Odoo read evidence intentionally exercises the controlled Odoo-shell "
            "subprocess boundary and mutable staged runtime state; it remains "
            "required suite evidence but is not eligible for single-leader "
            "runtime-open path-policy approval"
        )
    return None


def discovery_targets() -> tuple[str, ...]:
    positive = ("registry", "trial_balance", "ar_open_items", "ap_open_items", "multicurrency")
    financial = set(positive[1:])
    negative = (
        "acl_deny", "cross_company", "mixed_company", "wrong_database_uuid",
        "expired", "tamper_parameters", "replay",
    )
    targets = ["release-identity", "witness-pre", "boundary-probe"]
    for name in positive:
        targets.extend((f"positive-{name}-signer", f"positive-{name}-read"))
        if name == "trial_balance":
            targets.append("negative-replay-read")
        if name in financial:
            targets.append(f"positive-{name}-oracle")
    for name in negative:
        if name == "replay":
            continue
        targets.append(f"negative-{name}-signer")
        targets.append(f"negative-{name}-read")
    targets.extend(("witness-post", "independent-verifier"))
    return tuple(targets)


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


def _write_json_once(path: Path, value: Mapping[str, Any]) -> str:
    payload = canonical_json(value) + b"\n"
    with path.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(payload).hexdigest()


def _role_for_target(target_id: str) -> str:
    if target_id in {"witness-pre", "witness-post"} or target_id.endswith("-oracle"):
        return "postgres"
    if target_id.endswith("-signer"):
        return "signer"
    if target_id == "independent-verifier":
        return "verifier"
    return "odoo"


def _inventory_identity(inventory: Mapping[str, Any], *, scope: str) -> dict[str, Any]:
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
        or inventory.get("scope") != scope
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
    return {
        "release": release,
        "expected_static_closure_sha256": static,
        "watch_roots": watch_roots,
        "mutable_roots": mutable_roots,
        "sqlite_delta_contract_sha256": delta,
        "targets": targets,
    }


def _target_order(targets: Sequence[Any]) -> tuple[Any, ...]:
    return tuple(item.get("target_id") if type(item) is dict else None for item in targets)


def _verifier_evidence_path_normalizer(final: Sequence[str]) -> Callable[[str], str]:
    try:
        index = tuple(final).index("--evidence-dir")
    except ValueError as exc:
        raise DiscoveryError("verifier evidence directory option is absent") from exc
    if index + 1 >= len(final):
        raise DiscoveryError("verifier evidence directory value is absent")
    evidence_dir = final[index + 1]
    prefix = "/var/lib/odoo-accounting-cli-v3/evidence/"
    if (
        not isinstance(evidence_dir, str)
        or not evidence_dir.startswith(prefix)
        or "/" in evidence_dir.removeprefix(prefix)
        or SAFE_NAME.fullmatch(evidence_dir.removeprefix(prefix)) is None
    ):
        raise DiscoveryError("verifier evidence directory is invalid")

    def normalize(path: str) -> str:
        if path == evidence_dir:
            return runtime_trace.VERIFIER_EVIDENCE_DIR_MARKER
        if path.startswith(evidence_dir + "/"):
            return runtime_trace.VERIFIER_EVIDENCE_DIR_MARKER + path[len(evidence_dir) :]
        return path

    return normalize


def merge_fragments(
    suite_fragment: Mapping[str, Any],
    verifier_fragment: Mapping[str, Any],
    *,
    output_inventory: Path,
) -> dict[str, Any]:
    suite = _inventory_identity(suite_fragment, scope=SUITE_FRAGMENT_SCOPE)
    verifier = _inventory_identity(verifier_fragment, scope=VERIFIER_FRAGMENT_SCOPE)
    for key in (
        "release",
        "expected_static_closure_sha256",
        "watch_roots",
        "mutable_roots",
        "sqlite_delta_contract_sha256",
    ):
        if suite[key] != verifier[key]:
            raise DiscoveryError("discovery fragments do not share one identity")
    expected = discovery_targets()
    suite_targets = suite["targets"]
    verifier_targets = verifier["targets"]
    if _target_order(suite_targets) != expected[:-1]:
        raise DiscoveryError("suite discovery fragment target order is incomplete")
    if _target_order(verifier_targets) != (expected[-1],):
        raise DiscoveryError("verifier discovery fragment target order is invalid")
    inventory = {
        "schema_version": 1,
        "scope": DISCOVERY_SCOPE,
        "release": suite["release"],
        "expected_static_closure_sha256": suite["expected_static_closure_sha256"],
        "watch_roots": list(suite["watch_roots"]),
        "mutable_roots": list(suite["mutable_roots"]),
        "sqlite_delta_contract_sha256": suite["sqlite_delta_contract_sha256"],
        "targets": [*suite_targets, *verifier_targets],
    }
    inventory_sha256 = _write_json_once(output_inventory, inventory)
    return {
        "schema_version": 1,
        "inventory_path": str(output_inventory),
        "inventory_sha256": inventory_sha256,
        "target_count": len(inventory["targets"]),
        "candidate_is_approval": False,
        "production_promotion_allowed": False,
    }


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


def _metadata_ancestor(path: str, roots: Sequence[str]) -> bool:
    if path == "/":
        prefix = "/"
    else:
        prefix = path + "/"
    return any(root.startswith(prefix) for root in roots)


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
    if path == runtime_trace.VERIFIER_EVIDENCE_DIR_MARKER or path.startswith(
        runtime_trace.VERIFIER_EVIDENCE_DIR_MARKER + "/"
    ):
        if role != "verifier":
            raise DiscoveryError("verifier evidence bundle path is unsafe")
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
        metadata_ancestor = (
            access == ("metadata",)
            and success
            and not errnos
            and _metadata_ancestor(path, (*watch_roots, *mutable_roots))
        )
        if not _covered(path, watch_roots) and not metadata_ancestor:
            verifier_evidence_parent = (
                role == "verifier"
                and runtime_trace._is_verifier_evidence_parent_metadata_ancestor(path)
                and access == ("metadata",)
                and success
                and not errnos
            )
            if not verifier_evidence_parent:
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
        if _covered(path, watch_roots):
            raise DiscoveryError("process-view discovery policy is unsafe")
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
                runtime_trace.PROCESS_VIEW_FAILURE_GUARD if errnos else None
            ),
        }
    if classification == "unix-socket":
        if _covered(path, watch_roots):
            raise DiscoveryError("unix-socket discovery policy is unsafe")
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
                runtime_trace.UNIX_SOCKET_FAILURE_GUARD if errnos else None
            ),
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
        manifest_final = final
        manifest_bootstrap = template
        path_normalizer: Callable[[str], str] = lambda value: value
        if (
            target_id == "independent-verifier"
            and "--expected-bundle-manifest-sha256" in final
        ):
            manifest_final = runtime_trace.verifier_final_argv_template(final)
            marker = runtime_trace.VERIFIER_BUNDLE_MANIFEST_SHA256_MARKER
            evidence_marker = runtime_trace.VERIFIER_EVIDENCE_DIR_MARKER
            if (
                len(manifest_final) != len(final)
                or len(manifest_bootstrap) != len(template)
            ):
                raise DiscoveryError("verifier discovery argv template is invalid")
            approved_template = (*template[: -len(final)], *manifest_final)
            manifest_bootstrap = tuple(
                approved if approved in {marker, evidence_marker} else value
                for value, approved in zip(template, approved_template)
            )
            path_normalizer = _verifier_evidence_path_normalizer(final)
    except runtime_trace.RuntimeOpenTraceError as exc:
        raise DiscoveryError("discovery bootstrap argv cannot be templated") from exc
    normalized_paths = tuple(sorted(set(path_normalizer(path) for path in parsed.paths)))
    access_by_path = {
        path_normalizer(path): access for path, access in parsed.accesses
    }
    outcomes_by_path: dict[str, list[str]] = {path: [] for path in normalized_paths}
    for path, _access, outcome in parsed.attempts:
        outcomes_by_path.setdefault(path_normalizer(path), []).append(outcome)
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
        for path in normalized_paths
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
        "bootstrap_argv": list(manifest_bootstrap),
        "final_argv": list(manifest_final),
        "allowed_paths": list(normalized_paths),
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
        "canonical_path_count": len(normalized_paths),
        "canonical_path_set_sha256": hashlib.sha256(
            runtime_trace.canonical_json(normalized_paths)
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
    if tuple(ordered) != discovery_targets():
        raise DiscoveryError("discovery target order is incomplete")
    if output_directory.exists() or output_directory.is_symlink():
        raise DiscoveryError("discovery output directory already exists")
    output_directory.mkdir(mode=0o700)
    reviews: list[dict[str, Any]] = []
    excluded_reviews: list[dict[str, Any]] = []
    try:
        for entry in targets:
            target_id = entry.get("target_id") if type(entry) is dict else None
            reason = non_policy_target_reason(target_id) if isinstance(target_id, str) else None
            if reason is not None:
                excluded_reviews.append(
                    {
                        "target_id": target_id,
                        "reason": reason,
                        "candidate_is_approval": False,
                        "production_promotion_allowed": False,
                    }
                )
                continue
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
            "discovery_target_order": list(discovery_targets()),
            "manifest_directory": str(output_directory),
            "reviews": reviews,
            "excluded_reviews": excluded_reviews,
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
        "discovery_target_count": len(targets),
        "excluded_target_count": len(excluded_reviews),
        "review_sha256": hashlib.sha256(review_payload).hexdigest(),
        "candidate_is_approval": False,
        "production_promotion_allowed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--suite-fragment", type=Path)
    parser.add_argument("--verifier-fragment", type=Path)
    parser.add_argument("--output-inventory", type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        if arguments.output_inventory is not None:
            if (
                arguments.inventory is not None
                or arguments.output_directory is not None
                or arguments.suite_fragment is None
                or arguments.verifier_fragment is None
            ):
                raise DiscoveryError("discovery fragment merge arguments are invalid")
            result = merge_fragments(
                _read_json(arguments.suite_fragment),
                _read_json(arguments.verifier_fragment),
                output_inventory=arguments.output_inventory,
            )
        else:
            if (
                arguments.inventory is None
                or arguments.output_directory is None
                or arguments.suite_fragment is not None
                or arguments.verifier_fragment is not None
            ):
                raise DiscoveryError("discovery review arguments are invalid")
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

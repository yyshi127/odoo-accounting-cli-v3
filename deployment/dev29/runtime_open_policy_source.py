#!/usr/bin/python3 -I
"""Build a deterministic, reviewable Dev29 runtime-open policy candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable


sys.dont_write_bytecode = True
SOURCE_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-policy-source.v1"
TEMPLATE_SCOPE = "odoo-accounting-cli-v3.dev29.runtime-open-policy-template.v1"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
MAX_MANIFEST_BYTES = 32 * 1024 * 1024


class CandidateSourceError(RuntimeError):
    pass


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
        raise CandidateSourceError("candidate value is not canonical JSON") from exc


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise CandidateSourceError("manifest has a duplicate JSON key")
        result[key] = value
    return result


def expected_targets() -> tuple[str, ...]:
    positive = (
        "registry",
        "trial_balance",
        "ar_open_items",
        "ap_open_items",
        "multicurrency",
    )
    financial = set(positive[1:])
    negative = (
        "acl_deny",
        "cross_company",
        "mixed_company",
        "wrong_database_uuid",
        "expired",
        "tamper_parameters",
        "replay",
    )
    targets = ["release-identity", "witness-pre", "boundary-probe"]
    for name in positive:
        targets.extend((f"positive-{name}-signer", f"positive-{name}-read"))
        if name in financial:
            targets.append(f"positive-{name}-oracle")
    for name in negative:
        if name != "replay":
            targets.append(f"negative-{name}-signer")
        targets.append(f"negative-{name}-read")
    targets.extend(("witness-post", "independent-verifier"))
    return tuple(targets)


def template_document() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "scope": TEMPLATE_SCOPE,
        "source_scope": SOURCE_SCOPE,
        "required_external_anchors": [
            "expected_strace_sha256",
            "expected_static_closure_sha256",
            "expected_runtime_module_sha256",
            "expected_release_manifest_sha256",
        ],
        "target_order": list(expected_targets()),
        "approval_contract": {
            "artifact": "canonical-policy-source-json-plus-lf",
            "builder_argument": "--expected-source-sha256",
            "candidate_is_approval": False,
        },
        "production_promotion_allowed": False,
    }


def _read_manifest(path: Path, target_id: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as exc:
        raise CandidateSourceError(f"manifest {target_id} cannot be read") from exc
    if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_MANIFEST_BYTES:
        raise CandidateSourceError(f"manifest {target_id} identity is unsafe")
    try:
        document = json.loads(payload, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise CandidateSourceError(f"manifest {target_id} JSON is invalid") from exc
    if (
        type(document) is not dict
        or payload != canonical_json(document) + b"\n"
        or document.get("target_id") != target_id
    ):
        raise CandidateSourceError(f"manifest {target_id} is not canonical or bound")
    environment = document.get("environment")
    if (
        type(environment) is not dict
        or document.get("expected_child_environment_sha256")
        != hashlib.sha256(canonical_json(environment)).hexdigest()
    ):
        raise CandidateSourceError(
            f"manifest {target_id} child environment binding differs"
        )
    return document


def build_candidate(
    manifest_directory: Path,
    *,
    release: str,
    expected_strace_sha256: str,
    expected_static_closure_sha256: str,
    expected_runtime_module_sha256: str,
    expected_release_manifest_sha256: str,
) -> dict[str, Any]:
    digests = (
        expected_strace_sha256,
        expected_static_closure_sha256,
        expected_runtime_module_sha256,
        expected_release_manifest_sha256,
    )
    if (
        not isinstance(release, str)
        or SAFE_NAME.fullmatch(release) is None
        or any(HEX64.fullmatch(value) is None for value in digests)
        or manifest_directory.is_symlink()
        or not manifest_directory.is_dir()
    ):
        raise CandidateSourceError("candidate inputs are invalid")
    expected_names = {f"{target_id}.json" for target_id in expected_targets()}
    observed_names = {entry.name for entry in os.scandir(manifest_directory)}
    if observed_names != expected_names:
        raise CandidateSourceError("manifest directory target set is incomplete")
    targets = [
        _read_manifest(manifest_directory / f"{target_id}.json", target_id)
        for target_id in expected_targets()
    ]
    return {
        "schema_version": 1,
        "scope": SOURCE_SCOPE,
        "release": release,
        "expected_strace_sha256": expected_strace_sha256,
        "expected_static_closure_sha256": expected_static_closure_sha256,
        "expected_runtime_module_sha256": expected_runtime_module_sha256,
        "expected_release_manifest_sha256": expected_release_manifest_sha256,
        "targets": targets,
        "production_promotion_allowed": False,
    }


def _write_candidate(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
        0o400,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CandidateSourceError("candidate write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if os.name == "posix":
        parent_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-directory", required=True, type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--expected-strace-sha256", required=True)
    parser.add_argument("--expected-static-closure-sha256", required=True)
    parser.add_argument("--expected-runtime-module-sha256", required=True)
    parser.add_argument("--expected-release-manifest-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        candidate = build_candidate(
            arguments.manifest_directory,
            release=arguments.release,
            expected_strace_sha256=arguments.expected_strace_sha256,
            expected_static_closure_sha256=(
                arguments.expected_static_closure_sha256
            ),
            expected_runtime_module_sha256=(
                arguments.expected_runtime_module_sha256
            ),
            expected_release_manifest_sha256=(
                arguments.expected_release_manifest_sha256
            ),
        )
        payload = canonical_json(candidate) + b"\n"
        _write_candidate(arguments.output, payload)
    except (OSError, CandidateSourceError) as exc:
        print(f"Dev29 runtime-open candidate refused: {exc}", file=sys.stderr)
        return 2
    result = {
        "schema_version": 1,
        "candidate_path": str(arguments.output),
        "source_sha256": hashlib.sha256(payload).hexdigest(),
        "target_count": len(candidate["targets"]),
        "candidate_is_approval": False,
        "production_promotion_allowed": False,
    }
    print(canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

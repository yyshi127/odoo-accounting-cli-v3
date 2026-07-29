#!/usr/bin/python3
"""Independently verify a frozen Dev251 native-report read evidence bundle.

This verifier intentionally uses only the Python standard library.  It does
not import the collector, authentication helpers, receipt helpers, Odoo, or
the Dev29 verifier.  A passing result proves retained request/response and
read-only boundary integrity for four fixed staged-test report reads.  It
does not claim an accounting standard-answer oracle and cannot authorize
production promotion.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


sys.dont_write_bytecode = True

PLAN_SCOPE = "odoo-accounting-cli-v3.dev251.report-read-plan.v1"
BUNDLE_SCOPE = "odoo-accounting-cli-v3.dev251.report-read-evidence.v1"
VALIDATION_SCOPE = "odoo-accounting-cli-v3.dev251.report-read-validation.v1"
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
RELEASE_PARENT = Path("/opt/odoo-accounting-cli-v3/releases")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
CASE_NAMES = ("tax_report", "balance_sheet", "profit_and_loss", "cash_flow")
REPORT_CASES = {
    "tax_report": (
        "acct.tax.report_read.v1",
        "account.generic_tax_report",
        "tax",
        "generic_tax",
    ),
    "balance_sheet": (
        "acct.report.financial_read.v1",
        "account_reports.balance_sheet",
        "financial",
        "balance_sheet",
    ),
    "profit_and_loss": (
        "acct.report.financial_read.v1",
        "account_reports.profit_and_loss",
        "financial",
        "profit_and_loss",
    ),
    "cash_flow": (
        "acct.report.financial_read.v1",
        "account_reports.cash_flow_report",
        "financial",
        "cash_flow",
    ),
}
REGISTERED_READ_CAPABILITY_IDS = frozenset(
    {
        "acct.ap.open_items.v1",
        "acct.ar.open_items.v1",
        "acct.diagnostics.operation_read.v1",
        "acct.gl.trial_balance.v1",
        "acct.move.draft_cancel_eligibility.v1",
        "acct.multicompany.consolidated_read.v1",
        "acct.multicurrency.balance_read.v1",
        "acct.registry.list.v1",
        "acct.report.financial_read.v1",
        "acct.tax.report_read.v1",
    }
)
DECLARED_READ_GAP_IDS = frozenset(
    {
        "acct.diagnostics.operation_read.v1",
        "acct.multicompany.consolidated_read.v1",
    }
)
ADMISSIBLE_READ_CAPABILITY_IDS = (
    REGISTERED_READ_CAPABILITY_IDS - DECLARED_READ_GAP_IDS
)
READINESS_CHECK_IDS = frozenset(
    {
        "contract_evidence_present",
        "page_total_count_contract",
        "read_policy_closed",
        "read_receipt_v2_contract",
        "strict_input_schema",
        "strict_output_schema",
        "test_execution_routed",
        "trusted_handler_supported",
        "verification_method_present",
    }
)
READINESS_DATA_FIELDS = frozenset(
    {
        "admissible_count",
        "admissible_ids",
        "blockers",
        "capabilities",
        "completion_ready_count",
        "completion_ready_ids",
        "external_read_evidence_verifier_ready",
        "goal_evidence_ready_count",
        "goal_evidence_ready_ids",
        "goal_evidence_unready_capability_ids",
        "missing_required_read_capability_ids",
        "production_promotion_allowed",
        "read_goal_readiness_ready",
        "read_static_readiness_ready",
        "real_odoo_write_performed",
        "registered_read_capability_ids",
        "release_identity",
        "required_goal_evidence_kinds",
        "required_read_capability_ids",
        "total_read_capabilities",
        "unready_capability_ids",
    }
)
READINESS_REPORT_FIELDS = frozenset(
    {
        "blockers",
        "capability",
        "checks",
        "external_read_evidence_verified",
        "goal_evidence_blockers",
        "goal_evidence_ready",
        "missing_goal_evidence_kinds",
        "production_promotion_allowed",
        "read_completion_ready",
        "real_odoo_write_performed",
        "registry_claimed_receipt_count",
        "registry_claimed_receipt_kinds",
        "registry_receipts_authoritative_for_goal",
        "trusted_handler_kind",
        "trusted_read_admissible",
    }
)
REQUIRED_GOAL_EVIDENCE_KINDS = frozenset(
    {
        "accounting_oracle",
        "live_odoo",
        "pi_e2e",
        "release_identity",
        "security_negative",
    }
)
READINESS_BLOCKERS = [
    "not every registered read capability is statically admissible for "
    "trusted execution",
    "trusted external read evidence is not independently verified for every "
    "registered read capability",
]
FINANCIAL_WARNINGS = {
    "odoo:date_range_normalized",
    "odoo:draft_entries_excluded",
    "odoo:report_variant_resolved",
}
TAX_WARNINGS = FINANCIAL_WARNINGS | {
    "odoo:tax_source_move_line_count_unavailable"
}
FIXED_TARGET = {
    "allowed_company_ids": [1],
    "capability_channel": "staged",
    "company_id": 1,
    "database_name": "odoo_test",
    "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
    "environment": "test",
    "host": "43.165.173.80",
    "instance_id": "odoo19@43.165.173.80",
    "principal": "pi:test-user-2",
    "user_id": 2,
}
ORACLE_UNAVAILABLE_REASON = (
    "Independent accounting standard-answer oracles for tax, balance sheet, "
    "profit and loss, and cash flow are not yet approved."
)
IDENTITY_FIELDS = {
    "commit",
    "manifest_sha256",
    "package_sha256",
    "registry_digest",
    "release",
    "verified",
    "version",
}
RUNTIME_FIELDS = {
    "auth_key_id",
    "canonical_package_path",
    "canonical_package_sha256",
    "capability_channel",
    "database_name",
    "database_uuid",
    "environment",
    "instance_id",
    "odoo_bin",
    "odoo_bin_sha256",
    "odoo_config",
    "odoo_config_sha256",
    "odoo_python",
    "odoo_python_sha256",
    "receipt_key_id",
    "release_root",
}
REQUEST_CONTEXT_FIELDS = {
    "allowed_company_ids",
    "audience",
    "auth_expires_at",
    "auth_issued_at",
    "auth_key_id",
    "auth_request_digest",
    "auth_signature",
    "auth_signature_purpose",
    "auth_signature_version",
    "auth_token_id",
    "company_id",
    "database_name",
    "database_uuid",
    "environment",
    "principal",
    "odoo_instance_id",
    "user_id",
}
RECEIPT_FIELDS = {
    "capability_id",
    "capability_channel",
    "company_id",
    "database_name",
    "database_uuid",
    "environment",
    "id",
    "observed_at",
    "odoo_instance_id",
    "record_count",
    "registry_digest",
    "release_digest",
    "request_digest",
    "result_digest",
    "signature",
    "signature_key_id",
    "signature_purpose",
    "signature_version",
    "user_id",
}
RUNTIME_CONFIG_FIELDS = {
    "auth_key_id",
    "auth_secret_path",
    "auth_state_path",
    "canonical_package_path",
    "canonical_package_sha256",
    "capability_channel",
    "database_name",
    "database_uuid",
    "environment",
    "gcov_state_path",
    "instance_id",
    "odoo_bin",
    "odoo_bin_sha256",
    "odoo_config",
    "odoo_config_sha256",
    "odoo_python",
    "odoo_python_sha256",
    "receipt_key_id",
    "receipt_secret_path",
    "receipt_state_path",
    "release_root",
}
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_SECRET_BYTES = 4096
MAX_RELEASE_FILES = 20_000
MAX_RELEASE_MEMBER_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
REQUIRED_RELEASE_MEMBERS = {
    "bin/odoo-accounting-cli-v3",
    "deployment/dev251/collect_report_read_evidence.py",
    "deployment/dev251/report_read_plan.json",
    "deployment/dev251/verify_report_read_evidence.py",
    "registry/capabilities.json",
}
EXECUTABLE_RELEASE_MEMBERS = {
    "bin/odoo-accounting-cli-v3",
    "bin/odoo-accounting-cli-v3-broker",
    "bin/odoo-accounting-cli-v3-effect-finalizer",
    "deployment/dev9/run-private-mount-gate.sh",
}


class EvidenceVerificationError(RuntimeError):
    """The retained evidence is incomplete, altered, or incorrectly bound."""


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
        raise EvidenceVerificationError("value is not canonical JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceVerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise EvidenceVerificationError(f"non-finite JSON number: {value}")


def parse_json(
    payload: bytes,
    *,
    label: str,
    canonical: bool,
) -> dict[str, Any]:
    if not payload or len(payload) > MAX_JSON_BYTES:
        raise EvidenceVerificationError(f"{label} is empty or too large")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceVerificationError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise EvidenceVerificationError(f"{label} must be a JSON object")
    if canonical and payload != canonical_json(value) + b"\n":
        raise EvidenceVerificationError(f"{label} is not canonical JSON plus LF")
    return value


def stable_read(
    path: Path,
    *,
    label: str,
    maximum: int = MAX_JSON_BYTES,
    allow_empty: bool = False,
    enforce_root: bool = False,
    expected_mode: int | None = None,
) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_size == 0 and not allow_empty)
            or before.st_size > maximum
        ):
            raise EvidenceVerificationError(f"{label} file boundary is invalid")
        if os.name == "posix":
            if expected_mode is not None and stat.S_IMODE(before.st_mode) != expected_mode:
                raise EvidenceVerificationError(f"{label} file mode is invalid")
            if enforce_root and (before.st_uid != 0 or before.st_gid != 0):
                raise EvidenceVerificationError(f"{label} is not root-owned")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise EvidenceVerificationError(f"{label} changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise EvidenceVerificationError(f"{label} is too large")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise EvidenceVerificationError(f"{label} changed while reading")
        return b"".join(chunks)
    except EvidenceVerificationError:
        raise
    except OSError as exc:
        raise EvidenceVerificationError(f"{label} cannot be read") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _stream_sha256(
    path: Path,
    *,
    label: str,
    maximum: int,
    enforce_root: bool,
    expected_mode: int | None = None,
    allow_path_symlink: bool = False,
) -> tuple[str, int]:
    descriptor: int | None = None
    try:
        path_before = path.lstat()
        target = path.resolve(strict=True)
        if not allow_path_symlink and (
            path.is_symlink() or target != path
        ):
            raise EvidenceVerificationError(f"{label} file boundary is invalid")
        before = target.lstat()
        if (
            target.is_symlink()
            or target.resolve(strict=True) != target
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
            or (
                enforce_root
                and os.name == "posix"
                and (
                    before.st_uid != 0
                    or before.st_gid != 0
                    or (
                        expected_mode is not None
                        and stat.S_IMODE(before.st_mode) != expected_mode
                    )
                )
            )
        ):
            raise EvidenceVerificationError(f"{label} file boundary is invalid")
        descriptor = os.open(
            target,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        fingerprint = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise EvidenceVerificationError(f"{label} changed while opening")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise EvidenceVerificationError(f"{label} is too large")
            digest.update(chunk)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if fingerprint != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or (
            path_before.st_dev,
            path_before.st_ino,
            path_before.st_mode,
            path_before.st_nlink,
            path_before.st_uid,
            path_before.st_gid,
            path_before.st_size,
            path_before.st_mtime_ns,
            path_before.st_ctime_ns,
        ) != (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_mode,
            path_after.st_nlink,
            path_after.st_uid,
            path_after.st_gid,
            path_after.st_size,
            path_after.st_mtime_ns,
            path_after.st_ctime_ns,
        ) or path.resolve(strict=True) != target:
            raise EvidenceVerificationError(f"{label} changed while hashing")
        return digest.hexdigest(), total
    except EvidenceVerificationError:
        raise
    except OSError as exc:
        raise EvidenceVerificationError(f"{label} cannot be hashed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _independent_registry_digest(
    path: Path,
    *,
    enforce_root: bool,
) -> str:
    payload = stable_read(
        path,
        label="exact release capability registry",
        enforce_root=enforce_root,
        expected_mode=0o444 if os.name == "posix" else None,
    )
    document = parse_json(
        payload,
        label="exact release capability registry",
        canonical=False,
    )
    capabilities = document.get("capabilities")
    if (
        set(document) != {"capabilities", "schema_version"}
        or document.get("schema_version") != 1
        or type(capabilities) is not list
        or not capabilities
    ):
        raise EvidenceVerificationError("capability registry envelope is invalid")
    identifiers: set[str] = set()
    for index, capability in enumerate(capabilities):
        capability_id = capability.get("id") if type(capability) is dict else None
        if (
            type(capability) is not dict
            or type(capability_id) is not str
            or re.fullmatch(
                r"acct\.[a-z0-9_]+\.[a-z0-9_]+\.v[1-9][0-9]*",
                capability_id,
            )
            is None
            or capability_id in identifiers
        ):
            raise EvidenceVerificationError(
                f"capability registry entry is invalid: {index}"
            )
        identifiers.add(capability_id)
    return hashlib.sha256(canonical_json(capabilities)).hexdigest()


def _verify_release_tree(
    runtime: Mapping[str, Any],
    release_identity: Mapping[str, Any],
    *,
    enforce_root: bool,
) -> None:
    root = Path(runtime["release_root"])
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise EvidenceVerificationError("exact release root is unavailable") from exc
    if (
        root.is_symlink()
        or root.resolve(strict=True) != root
        or not stat.S_ISDIR(root_metadata.st_mode)
        or (
            enforce_root
            and os.name == "posix"
            and (
                root_metadata.st_uid != 0
                or root_metadata.st_gid != 0
                or stat.S_IMODE(root_metadata.st_mode) != 0o555
            )
        )
    ):
        raise EvidenceVerificationError("exact release root is unsafe")
    if (
        enforce_root
        and Path(__file__).resolve(strict=True)
        != (
            root
            / "deployment"
            / "dev251"
            / "verify_report_read_evidence.py"
        ).resolve(strict=True)
    ):
        raise EvidenceVerificationError("verifier escaped the exact release")
    anchor_path = (
        root.parent.parent
        / "trusted-artifacts"
        / f"{release_identity['release']}.json"
    )
    anchor = parse_json(
        stable_read(
            anchor_path,
            label="external release trust anchor",
            enforce_root=enforce_root,
            expected_mode=0o444 if os.name == "posix" else None,
        ),
        label="external release trust anchor",
        canonical=False,
    )
    if anchor != {
        "commit": release_identity["commit"],
        "manifest_sha256": release_identity["manifest_sha256"],
        "package_sha256": release_identity["package_sha256"],
        "release": release_identity["release"],
    }:
        raise EvidenceVerificationError("external release trust anchor mismatch")
    manifest_payload = stable_read(
        root / "RELEASE-MANIFEST.json",
        label="installed release manifest",
        maximum=16 * 1024 * 1024,
        enforce_root=enforce_root,
        expected_mode=0o444 if os.name == "posix" else None,
    )
    manifest = parse_json(
        manifest_payload,
        label="installed release manifest",
        canonical=False,
    )
    if (
        set(manifest)
        != {"commit", "files", "manifest_sha256", "schema_version", "version"}
        or manifest.get("schema_version") != 1
        or manifest.get("commit") != release_identity["commit"]
        or manifest.get("version") != release_identity["version"]
        or manifest.get("manifest_sha256")
        != release_identity["manifest_sha256"]
    ):
        raise EvidenceVerificationError("installed release manifest identity is invalid")
    unsigned = {
        key: value for key, value in manifest.items() if key != "manifest_sha256"
    }
    if (
        hashlib.sha256(canonical_json(unsigned)).hexdigest()
        != release_identity["manifest_sha256"]
    ):
        raise EvidenceVerificationError("installed release manifest digest is invalid")
    files = manifest.get("files")
    if (
        type(files) is not list
        or not files
        or len(files) > MAX_RELEASE_FILES
    ):
        raise EvidenceVerificationError("installed release manifest files are invalid")
    indexed: dict[str, dict[str, Any]] = {}
    expected_directories: set[str] = set()
    for item in files:
        name = item.get("path") if type(item) is dict else None
        portable = PurePosixPath(name) if type(name) is str else None
        if (
            type(item) is not dict
            or set(item) != {"path", "sha256", "size"}
            or portable is None
            or portable.is_absolute()
            or not portable.parts
            or any(part in {"", ".", ".."} for part in portable.parts)
            or str(portable) != name
            or name in indexed
            or type(item.get("sha256")) is not str
            or HEX64.fullmatch(item["sha256"]) is None
            or type(item.get("size")) is not int
            or item["size"] < 0
            or item["size"] > MAX_RELEASE_MEMBER_BYTES
        ):
            raise EvidenceVerificationError("installed release manifest entry is invalid")
        indexed[name] = item
        for parent in portable.parents:
            if str(parent) != ".":
                expected_directories.add(str(parent))
    if not REQUIRED_RELEASE_MEMBERS.issubset(indexed):
        raise EvidenceVerificationError("installed release omits Dev251 trust members")

    actual_files: dict[str, Path] = {}
    actual_directories: set[str] = set()
    for directory_text, directories, names in os.walk(
        root, topdown=True, followlinks=False
    ):
        directory = Path(directory_text)
        directories.sort()
        names.sort()
        if directory != root:
            actual_directories.add(directory.relative_to(root).as_posix())
        metadata = directory.lstat()
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or (
                enforce_root
                and os.name == "posix"
                and (
                    metadata.st_uid != 0
                    or metadata.st_gid != 0
                    or stat.S_IMODE(metadata.st_mode) != 0o555
                )
            )
        ):
            raise EvidenceVerificationError("installed release directory is unsafe")
        for name in directories:
            child = directory / name
            child_metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(child_metadata.st_mode):
                raise EvidenceVerificationError("installed release directory is unsafe")
        for name in names:
            child = directory / name
            relative = child.relative_to(root).as_posix()
            metadata = child.lstat()
            if (
                child.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise EvidenceVerificationError(
                    f"installed release member is unsafe: {relative}"
                )
            if relative != "RELEASE-MANIFEST.json":
                actual_files[relative] = child
    if set(actual_files) != set(indexed) or actual_directories != expected_directories:
        raise EvidenceVerificationError("installed release tree does not match manifest")
    for name, item in indexed.items():
        observed_digest, observed_size = _stream_sha256(
            actual_files[name],
            label=f"installed release member {name}",
            maximum=MAX_RELEASE_MEMBER_BYTES,
            enforce_root=enforce_root,
            expected_mode=(
                0o555 if name in EXECUTABLE_RELEASE_MEMBERS else 0o444
            ),
        )
        if observed_size != item["size"] or observed_digest != item["sha256"]:
            raise EvidenceVerificationError(
                f"installed release member digest mismatch: {name}"
            )
    registry_digest = _independent_registry_digest(
        root / "registry" / "capabilities.json",
        enforce_root=enforce_root,
    )
    if registry_digest != release_identity["registry_digest"]:
        raise EvidenceVerificationError("exact release registry digest mismatch")
    for field, digest_field, allow_path_symlink in (
        ("odoo_python", "odoo_python_sha256", True),
        ("odoo_bin", "odoo_bin_sha256", False),
        ("odoo_config", "odoo_config_sha256", False),
    ):
        observed_digest, _size = _stream_sha256(
            Path(runtime[field]),
            label=f"runtime {field}",
            maximum=MAX_RELEASE_MEMBER_BYTES,
            enforce_root=False,
            allow_path_symlink=allow_path_symlink,
        )
        if observed_digest != runtime[digest_field]:
            raise EvidenceVerificationError(f"runtime {field} digest mismatch")
    package_digest, _package_size = _stream_sha256(
        Path(runtime["canonical_package_path"]),
        label="canonical release package",
        maximum=MAX_PACKAGE_BYTES,
        enforce_root=enforce_root,
        expected_mode=0o444,
    )
    if (
        package_digest != runtime["canonical_package_sha256"]
        or package_digest != release_identity["package_sha256"]
    ):
        raise EvidenceVerificationError("canonical release package digest mismatch")


def _timestamp(value: Any, *, label: str) -> datetime:
    if type(value) is not str:
        raise EvidenceVerificationError(f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceVerificationError(f"{label} is not a timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceVerificationError(f"{label} is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _valid_identity(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value) == IDENTITY_FIELDS
        and value.get("verified") is True
        and type(value.get("release")) is str
        and SAFE_NAME.fullmatch(value["release"]) is not None
        and type(value.get("version")) is str
        and VERSION.fullmatch(value["version"]) is not None
        and type(value.get("commit")) is str
        and HEX40.fullmatch(value["commit"]) is not None
        and value["release"] == f"{value['version']}-{value['commit'][:12]}"
        and all(
            type(value.get(field)) is str
            and HEX64.fullmatch(value[field]) is not None
            for field in (
                "manifest_sha256",
                "package_sha256",
                "registry_digest",
            )
        )
    )


def _validate_expected_identity(value: Any) -> dict[str, Any]:
    if not _valid_identity(value):
        raise EvidenceVerificationError("expected release identity is invalid")
    return value


def _validate_runtime(
    value: Any,
    *,
    target: Mapping[str, Any],
    release_identity: Mapping[str, Any],
) -> dict[str, Any]:
    path_fields = (
        "canonical_package_path",
        "odoo_bin",
        "odoo_config",
        "odoo_python",
        "release_root",
    )
    if (
        type(value) is not dict
        or set(value) != RUNTIME_FIELDS
        or any(
            type(value.get(field)) is not str or not value[field].strip()
            for field in (
                "auth_key_id",
                "receipt_key_id",
                *path_fields,
            )
        )
        or any(not Path(value[field]).is_absolute() for field in path_fields)
    ):
        raise EvidenceVerificationError("runtime identity is invalid")
    release_root = Path(value["release_root"])
    expected_package = (
        release_root.parent.parent
        / "packages"
        / f"odoo-accounting-cli-v3-{release_identity['release']}.tar.gz"
    )
    if (
        value.get("instance_id") != target["instance_id"]
        or value.get("database_name") != target["database_name"]
        or value.get("database_uuid") != target["database_uuid"]
        or value.get("environment") != "test"
        or value.get("capability_channel") != "staged"
        or value["auth_key_id"] == value["receipt_key_id"]
        or release_root.parent.name != "releases"
        or release_root.name != release_identity["release"]
        or Path(value.get("canonical_package_path", "")) != expected_package
        or value.get("canonical_package_sha256")
        != release_identity["package_sha256"]
        or any(
            type(value.get(field)) is not str
            or HEX64.fullmatch(value[field]) is None
            for field in (
                "canonical_package_sha256",
                "odoo_bin_sha256",
                "odoo_config_sha256",
                "odoo_python_sha256",
            )
        )
    ):
        raise EvidenceVerificationError("runtime identity is invalid")
    return value


def _common_parameters(parameters: Mapping[str, Any]) -> bool:
    return (
        parameters.get("company_id") == 1
        and parameters.get("date_from") == "2026-01-01"
        and parameters.get("date_to") == "2026-06-30"
        and parameters.get("move_state") == "posted"
        and parameters.get("journal_scope") == "all_report_eligible"
        and parameters.get("tax_unit_id") is None
        and parameters.get("unreconciled_only") is False
        and parameters.get("hide_zero_lines") is False
        and parameters.get("line_expansion_request") == "none"
        and parameters.get("currency_id") is None
        and parameters.get("limit") == 5000
        and parameters.get("offset") == 0
    )


def validate_plan(value: Any) -> dict[str, Any]:
    if (
        type(value) is not dict
        or set(value)
        != {
            "accounting_oracle",
            "cases",
            "production_promotion_allowed",
            "schema_version",
            "scope",
            "target",
        }
        or value.get("schema_version") != 1
        or value.get("scope") != PLAN_SCOPE
        or value.get("target") != FIXED_TARGET
        or value.get("production_promotion_allowed") is not False
        or value.get("accounting_oracle")
        != {
            "available": False,
            "performed": False,
            "reason": ORACLE_UNAVAILABLE_REASON,
        }
    ):
        raise EvidenceVerificationError("Dev251 report plan envelope is invalid")
    cases = value["cases"]
    if (
        type(cases) is not list
        or [case.get("name") for case in cases if type(case) is dict]
        != list(CASE_NAMES)
    ):
        raise EvidenceVerificationError("Dev251 report case set is invalid")
    for case in cases:
        if (
            type(case) is not dict
            or set(case)
            != {"capability_id", "name", "odoo_report_xmlid", "parameters"}
        ):
            raise EvidenceVerificationError("Dev251 report case fields are invalid")
        capability_id, xmlid, _family, kind = REPORT_CASES[case["name"]]
        parameters = case["parameters"]
        if (
            case["capability_id"] != capability_id
            or case["odoo_report_xmlid"] != xmlid
            or type(parameters) is not dict
            or not _common_parameters(parameters)
        ):
            raise EvidenceVerificationError("Dev251 report case binding is invalid")
        if case["name"] == "tax_report":
            expected_fields = {
                "company_id",
                "currency_id",
                "date_from",
                "date_to",
                "hide_zero_lines",
                "journal_scope",
                "limit",
                "line_expansion_request",
                "move_state",
                "offset",
                "tax_unit_id",
                "unreconciled_only",
            }
            if set(parameters) != expected_fields:
                raise EvidenceVerificationError("tax report parameters are invalid")
        else:
            expected_comparison = {
                "balance_sheet": {"mode": "previous_period", "periods": 1},
                "profit_and_loss": {"mode": "previous_year", "periods": 1},
                "cash_flow": None,
            }[case["name"]]
            if (
                set(parameters)
                != {
                    "company_id",
                    "currency_id",
                    "date_from",
                    "date_to",
                    "hide_zero_lines",
                    "journal_scope",
                    "limit",
                    "line_expansion_request",
                    "move_state",
                    "offset",
                    "report_request",
                    "tax_unit_id",
                    "unreconciled_only",
                }
                or parameters.get("report_request")
                != {"comparison": expected_comparison, "kind": kind}
            ):
                raise EvidenceVerificationError(
                    "financial report parameters are invalid"
                )
    return value


def expected_bundle_files() -> set[str]:
    files = {
        "read-boundary.json",
        "read-capabilities-readiness.json",
        "release-identity.json",
        "report-read-plan.json",
        "validation-report.json",
        "witness-post.json",
        "witness-pre.json",
    }
    for name in CASE_NAMES:
        files.update(
            {
                f"cases/{name}/exit.json",
                f"cases/{name}/request.json",
                f"cases/{name}/response.json",
                f"cases/{name}/stderr",
            }
        )
    return files


def _directory_mode(expected: int) -> int:
    if os.name == "nt":
        return {0o500: 0o555}[expected]
    return expected


def _file_mode(expected: int) -> int:
    if os.name == "nt":
        return {0o400: 0o444}[expected]
    return expected


def _load_bundle(
    evidence: Path,
    *,
    expected_final_path: Path,
    expected_identity: dict[str, Any],
    runtime: dict[str, Any],
    auth_secret: bytes,
    receipt_secret: bytes,
    enforce_root: bool,
) -> tuple[dict[str, bytes], dict[str, Any], str]:
    if (
        SAFE_NAME.fullmatch(expected_final_path.name) is None
        or evidence.parent != expected_final_path.parent
        or evidence.name
        not in {
            expected_final_path.name,
            f".{expected_final_path.name}.pending",
        }
    ):
        raise EvidenceVerificationError("evidence publication path is invalid")
    try:
        root_metadata = evidence.lstat()
    except OSError as exc:
        raise EvidenceVerificationError("evidence directory is unavailable") from exc
    if (
        evidence.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or evidence.resolve(strict=True) != evidence
        or stat.S_IMODE(root_metadata.st_mode) != _directory_mode(0o500)
        or (
            enforce_root
            and os.name == "posix"
            and (root_metadata.st_uid != 0 or root_metadata.st_gid != 0)
        )
    ):
        raise EvidenceVerificationError("frozen evidence directory is unsafe")

    manifest_payload = stable_read(
        evidence / "BUNDLE-MANIFEST.json",
        label="bundle manifest",
        enforce_root=enforce_root,
        expected_mode=_file_mode(0o400),
    )
    manifest_sha256 = hashlib.sha256(manifest_payload).hexdigest()
    manifest = parse_json(
        manifest_payload,
        label="bundle manifest",
        canonical=True,
    )
    if (
        set(manifest)
        != {
            "accounting_correctness_claimed",
            "accounting_oracle",
            "case_names",
            "evidence_name",
            "evidence_path",
            "files",
            "production_promotion_allowed",
            "receipt_ids",
            "release_identity",
            "runtime_identity",
            "schema_version",
            "scope",
        }
        or manifest.get("schema_version") != 1
        or manifest.get("scope") != BUNDLE_SCOPE
        or manifest.get("evidence_name") != expected_final_path.name
        or manifest.get("evidence_path") != str(expected_final_path)
        or manifest.get("case_names") != list(CASE_NAMES)
        or manifest.get("accounting_correctness_claimed") is not False
        or manifest.get("accounting_oracle")
        != {
            "available": False,
            "performed": False,
            "reason": ORACLE_UNAVAILABLE_REASON,
        }
        or manifest.get("production_promotion_allowed") is not False
        or manifest.get("release_identity") != expected_identity
        or manifest.get("runtime_identity") != runtime
        or type(manifest.get("receipt_ids")) is not dict
        or set(manifest["receipt_ids"]) != set(CASE_NAMES)
        or any(
            type(value) is not str or not value
            for value in manifest["receipt_ids"].values()
        )
    ):
        raise EvidenceVerificationError("bundle manifest identity is invalid")

    expected_files = expected_bundle_files()
    entries = manifest.get("files")
    if (
        type(entries) is not list
        or [entry.get("path") for entry in entries if type(entry) is dict]
        != sorted(expected_files)
    ):
        raise EvidenceVerificationError("bundle manifest file set is invalid")

    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for directory_text, directories, names in os.walk(
        evidence, topdown=True, followlinks=False
    ):
        directory = Path(directory_text)
        directories.sort()
        names.sort()
        relative_directory = directory.relative_to(evidence).as_posix()
        if relative_directory != ".":
            actual_directories.add(relative_directory)
        metadata = directory.lstat()
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != _directory_mode(0o500)
            or (
                enforce_root
                and os.name == "posix"
                and (metadata.st_uid != 0 or metadata.st_gid != 0)
            )
        ):
            raise EvidenceVerificationError("frozen bundle directory is unsafe")
        for name in directories:
            child = directory / name
            child_metadata = child.lstat()
            if child.is_symlink() or not stat.S_ISDIR(child_metadata.st_mode):
                raise EvidenceVerificationError("frozen bundle directory is unsafe")
        for name in names:
            child = directory / name
            child_metadata = child.lstat()
            relative = child.relative_to(evidence).as_posix()
            if (
                child.is_symlink()
                or not stat.S_ISREG(child_metadata.st_mode)
                or child_metadata.st_nlink != 1
                or stat.S_IMODE(child_metadata.st_mode) != _file_mode(0o400)
                or (
                    enforce_root
                    and os.name == "posix"
                    and (child_metadata.st_uid != 0 or child_metadata.st_gid != 0)
                )
            ):
                raise EvidenceVerificationError(
                    f"frozen bundle member is unsafe: {relative}"
                )
            actual_files.add(relative)
    expected_directories = {
        "cases",
        *(f"cases/{name}" for name in CASE_NAMES),
    }
    if (
        actual_files != expected_files | {"BUNDLE-MANIFEST.json"}
        or actual_directories != expected_directories
    ):
        raise EvidenceVerificationError("frozen bundle filesystem set is invalid")

    documents: dict[str, bytes] = {}
    for entry in entries:
        if (
            type(entry) is not dict
            or set(entry) != {"path", "sha256", "size"}
            or entry["path"] not in expected_files
            or PurePosixPath(entry["path"]).is_absolute()
            or ".." in PurePosixPath(entry["path"]).parts
            or type(entry.get("sha256")) is not str
            or HEX64.fullmatch(entry["sha256"]) is None
            or type(entry.get("size")) is not int
            or entry["size"] < 0
            or entry["size"] > MAX_JSON_BYTES
        ):
            raise EvidenceVerificationError("bundle file entry is invalid")
        member = evidence.joinpath(*PurePosixPath(entry["path"]).parts)
        payload = stable_read(
            member,
            label=f"bundle member {entry['path']}",
            allow_empty=True,
            enforce_root=enforce_root,
            expected_mode=_file_mode(0o400),
        )
        if (
            len(payload) != entry["size"]
            or hashlib.sha256(payload).hexdigest() != entry["sha256"]
        ):
            raise EvidenceVerificationError(
                f"bundle member digest mismatch: {entry['path']}"
            )
        documents[entry["path"]] = payload

    patterns: list[bytes] = []
    for secret in (auth_secret, receipt_secret):
        patterns.extend(
            (
                secret,
                secret.hex().encode("ascii"),
                base64.b64encode(secret),
                base64.urlsafe_b64encode(secret),
            )
        )
    scanned_documents = {**documents, "BUNDLE-MANIFEST.json": manifest_payload}
    for name, payload in scanned_documents.items():
        if any(pattern and pattern in payload for pattern in patterns):
            raise EvidenceVerificationError(
                f"runtime secret leaked into evidence: {name}"
            )
    return documents, manifest, manifest_sha256


def _json(documents: Mapping[str, bytes], name: str) -> dict[str, Any]:
    return parse_json(documents[name], label=name, canonical=True)


def _runtime_response(runtime: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "capability_channel": runtime["capability_channel"],
        "database_name": runtime["database_name"],
        "database_uuid": runtime["database_uuid"],
        "environment": runtime["environment"],
        "instance_id": runtime["instance_id"],
    }


def verify_auth_request(
    request: dict[str, Any],
    *,
    case: Mapping[str, Any],
    auth_secret: bytes,
    runtime: Mapping[str, Any],
) -> tuple[str, datetime, datetime]:
    context = request.get("context") if type(request) is dict else None
    if (
        len(auth_secret) < 32
        or set(request) != {"capability_id", "context", "parameters"}
        or request.get("capability_id") != case["capability_id"]
        or request.get("parameters") != case["parameters"]
        or type(context) is not dict
        or set(context) != REQUEST_CONTEXT_FIELDS
        or context.get("allowed_company_ids") != [1]
        or context.get("audience") != "odoo-accounting-cli-v3"
        or context.get("auth_key_id") != runtime["auth_key_id"]
        or context.get("auth_signature_purpose") != "auth_context_v1"
        or context.get("auth_signature_version") != 1
        or context.get("company_id") != 1
        or context.get("database_name") != runtime["database_name"]
        or context.get("database_uuid") != runtime["database_uuid"]
        or context.get("environment") != "test"
        or context.get("principal") != FIXED_TARGET["principal"]
        or context.get("odoo_instance_id") != runtime["instance_id"]
        or context.get("user_id") != 2
        or type(context.get("auth_token_id")) is not str
        or not context["auth_token_id"].startswith(f"dev251-{case['name']}-")
        or type(context.get("auth_request_digest")) is not str
        or HEX64.fullmatch(context["auth_request_digest"]) is None
        or type(context.get("auth_signature")) is not str
        or HEX64.fullmatch(context["auth_signature"]) is None
    ):
        raise EvidenceVerificationError("signed request binding is invalid")
    try:
        if str(uuid.UUID(context["database_uuid"])) != context["database_uuid"]:
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise EvidenceVerificationError("signed request database UUID is invalid") from exc
    issued = _timestamp(context["auth_issued_at"], label="auth issued_at")
    expires = _timestamp(context["auth_expires_at"], label="auth expires_at")
    if (
        context["auth_issued_at"] != issued.isoformat()
        or context["auth_expires_at"] != expires.isoformat()
        or expires <= issued
        or expires - issued > timedelta(minutes=5)
    ):
        raise EvidenceVerificationError("signed request lifetime is invalid")
    expected_request_digest = hashlib.sha256(
        canonical_json(
            {
                "capability_id": request["capability_id"],
                "parameters": request["parameters"],
            }
        )
    ).hexdigest()
    if not hmac.compare_digest(
        context["auth_request_digest"], expected_request_digest
    ):
        raise EvidenceVerificationError("signed request content digest is invalid")
    unsigned = {key: value for key, value in context.items() if key != "auth_signature"}
    expected_signature = hmac.new(
        auth_secret,
        canonical_json(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, context["auth_signature"]):
        raise EvidenceVerificationError("signed request HMAC is invalid")
    return context["auth_token_id"], issued, expires


def _positive_text(value: Any, *, maximum: int) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= maximum


def _period_key(mode: str, date_from: str, date_to: str) -> str:
    material = "\0".join((mode, date_from, date_to)).encode("utf-8")
    return f"period-{hashlib.sha256(material).hexdigest()}"


def _shift_month_start(value: Any, months: int) -> Any:
    month_index = value.year * 12 + value.month - 1 + months
    return value.replace(
        year=month_index // 12,
        month=month_index % 12 + 1,
        day=1,
    )


def _last_day_of_month(value: Any) -> Any:
    return _shift_month_start(value, 1) - timedelta(days=1)


def _previous_period_dates(date_from: Any, date_to: Any) -> tuple[Any, Any]:
    previous_to = date_from - timedelta(days=1)
    if date_from.day == 1 and date_to == _last_day_of_month(date_to):
        month_count = (
            (date_to.year - date_from.year) * 12
            + date_to.month
            - date_from.month
            + 1
        )
        return _shift_month_start(date_from, -month_count), previous_to
    day_count = (date_to - date_from).days + 1
    return previous_to - timedelta(days=day_count - 1), previous_to


def _previous_year_date(value: Any) -> Any:
    try:
        return value.replace(year=value.year - 1)
    except ValueError:
        return value.replace(year=value.year - 1, day=28)


def _canonical_decimal_text(value: str, *, integer: bool) -> bool:
    try:
        number = Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise EvidenceVerificationError("report numeric cell is invalid") from exc
    if not number.is_finite() or (integer and number != number.to_integral_value()):
        return False
    sign, digits, exponent = number.as_tuple()
    if exponent >= 0:
        rendered_length = sign + len(digits) + exponent
    else:
        integer_digits = len(digits) + exponent
        rendered_length = (
            sign + len(digits) + 1
            if integer_digits > 0
            else sign + 2 + (-integer_digits) + len(digits)
        )
    if rendered_length > 4096:
        return False
    rendered = "0" if number == 0 else format(number, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return value == rendered


def _validate_cell_value(value: str, figure_type: str) -> bool:
    if figure_type in {"monetary", "percentage", "float"}:
        return _canonical_decimal_text(value, integer=False)
    if figure_type == "integer":
        return _canonical_decimal_text(value, integer=True)
    if figure_type == "date":
        try:
            return datetime.strptime(value, "%Y-%m-%d").date().isoformat() == value
        except ValueError:
            return False
    if figure_type == "datetime":
        try:
            return datetime.fromisoformat(value).isoformat() == value
        except ValueError:
            return False
    if figure_type == "boolean":
        return value in {"false", "true"}
    return figure_type == "string"


def _validate_report_lines(
    lines: list[Any],
    *,
    family: str,
    declared_periods: Mapping[str, tuple[str, str, str]],
    currency_id: int,
) -> None:
    seen_lines: dict[str, int] = {}
    page_text_bytes = 0
    expected_line_fields = {
        "code",
        "columns",
        "level",
        "line_id",
        "name",
        "parent",
        "unfoldable",
        "unfolded",
    }
    if family == "tax":
        expected_line_fields.add("source_move_line_count")
    for line_index, line in enumerate(lines):
        if (
            type(line) is not dict
            or set(line) != expected_line_fields
            or type(line.get("line_id")) is not str
            or re.fullmatch(r"line-[0-9a-f]{64}", line["line_id"]) is None
            or line["line_id"] in seen_lines
            or not _positive_text(line.get("name"), maximum=256)
            or (
                line.get("code") is not None
                and not _positive_text(line["code"], maximum=128)
            )
            or type(line.get("level")) is not int
            or not 0 <= line["level"] <= 64
            or type(line.get("unfoldable")) is not bool
            or type(line.get("unfolded")) is not bool
            or type(line.get("columns")) is not list
            or not 1 <= len(line["columns"]) <= 48
        ):
            raise EvidenceVerificationError(f"report line is invalid: {line_index}")
        parent = line.get("parent")
        if type(parent) is not dict or set(parent) != {
            "line_id",
            "relation_source",
        }:
            raise EvidenceVerificationError(
                f"report line parent is invalid: {line_index}"
            )
        parent_id = parent["line_id"]
        if parent_id is None:
            if parent["relation_source"] != "none":
                raise EvidenceVerificationError(
                    f"report line parent is invalid: {line_index}"
                )
        elif (
            type(parent_id) is not str
            or re.fullmatch(r"line-[0-9a-f]{64}", parent_id) is None
            or parent["relation_source"] != "explicit"
            or parent_id not in seen_lines
            or seen_lines[parent_id] >= line["level"]
        ):
            raise EvidenceVerificationError(
                f"report line hierarchy is invalid: {line_index}"
            )

        observed_periods: set[str] = set()
        for column_index, column in enumerate(line["columns"]):
            if (
                type(column) is not dict
                or set(column)
                != {
                    "auditable",
                    "cell",
                    "expression_label",
                    "label",
                    "measure",
                    "period",
                }
                or not _positive_text(column.get("label"), maximum=128)
                or (
                    column.get("expression_label") is not None
                    and not _positive_text(
                        column["expression_label"],
                        maximum=128,
                    )
                )
                or type(column.get("auditable")) is not bool
            ):
                raise EvidenceVerificationError(
                    f"report column is invalid: {line_index}:{column_index}"
                )
            period = column.get("period")
            if (
                type(period) is not dict
                or set(period)
                != {"date_from", "date_to", "key", "label", "mode"}
                or not _positive_text(period.get("label"), maximum=128)
                or type(period.get("key")) is not str
                or period["key"] not in declared_periods
                or (
                    period.get("mode"),
                    period.get("date_from"),
                    period.get("date_to"),
                )
                != declared_periods[period["key"]]
            ):
                raise EvidenceVerificationError(
                    f"report column period is invalid: {line_index}:{column_index}"
                )
            observed_periods.add(period["key"])
            measure = column.get("measure")
            if (
                type(measure) is not dict
                or set(measure) != {"currency_id", "figure_type"}
                or measure.get("figure_type")
                not in {
                    "boolean",
                    "date",
                    "datetime",
                    "float",
                    "integer",
                    "monetary",
                    "percentage",
                    "string",
                }
                or (
                    measure["figure_type"] == "monetary"
                    and (
                        type(measure.get("currency_id")) is not int
                        or measure["currency_id"] != currency_id
                    )
                )
                or (
                    measure["figure_type"] != "monetary"
                    and measure.get("currency_id") is not None
                )
            ):
                raise EvidenceVerificationError(
                    f"report column measure is invalid: {line_index}:{column_index}"
                )
            cell = column.get("cell")
            if (
                type(cell) is not dict
                or set(cell) != {"is_blank", "value"}
                or type(cell.get("is_blank")) is not bool
                or (
                    cell["is_blank"] is True
                    and cell.get("value") is not None
                )
                or (
                    cell["is_blank"] is False
                    and (
                        type(cell.get("value")) is not str
                        or len(cell["value"]) > 4096
                        or not _validate_cell_value(
                            cell["value"],
                            measure["figure_type"],
                        )
                    )
                )
            ):
                raise EvidenceVerificationError(
                    f"report column cell is invalid: {line_index}:{column_index}"
                )
            page_text_bytes += sum(
                len(value.encode("utf-8"))
                for value in (
                    column["label"],
                    column["expression_label"],
                    period["label"],
                    cell["value"],
                )
                if type(value) is str
            )
        if observed_periods != set(declared_periods):
            raise EvidenceVerificationError(
                f"report line period coverage is invalid: {line_index}"
            )
        if family == "tax":
            source_count = line.get("source_move_line_count")
            if (
                type(source_count) is not dict
                or set(source_count) != {"available", "count"}
                or type(source_count.get("available")) is not bool
                or (
                    source_count["available"] is False
                    and source_count.get("count") is not None
                )
                or (
                    source_count["available"] is True
                    and (
                        type(source_count.get("count")) is not int
                        or source_count["count"] < 0
                    )
                )
            ):
                raise EvidenceVerificationError(
                    f"tax source count is invalid: {line_index}"
                )
        page_text_bytes += sum(
            len(value.encode("utf-8"))
            for value in (line["code"], line["name"])
            if type(value) is str
        )
        if page_text_bytes > 8 * 1024 * 1024:
            raise EvidenceVerificationError("report page text exceeds safety limit")
        seen_lines[line["line_id"]] = line["level"]


def _validate_report_result(
    result: dict[str, Any],
    *,
    case: Mapping[str, Any],
) -> tuple[dict[str, Any], int]:
    if (
        set(result)
        != {
            "currency",
            "effective_filters",
            "lines",
            "page",
            "period",
            "receipt",
            "report",
            "warnings",
        }
        or type(result.get("report")) is not dict
        or type(result.get("period")) is not dict
        or type(result.get("effective_filters")) is not dict
        or type(result.get("currency")) is not dict
        or type(result.get("warnings")) is not list
        or type(result.get("lines")) is not list
        or type(result.get("page")) is not dict
        or type(result.get("receipt")) is not dict
    ):
        raise EvidenceVerificationError("report result envelope is invalid")
    _capability, _xmlid, family, kind = REPORT_CASES[case["name"]]
    report = result["report"]
    if (
        set(report) != {"family", "kind", "requested", "resolved"}
        or report.get("family") != family
        or report.get("kind") != kind
    ):
        raise EvidenceVerificationError("report identity is invalid")
    for key in ("requested", "resolved"):
        identity = report.get(key)
        if (
            type(identity) is not dict
            or set(identity) != {"id", "name"}
            or type(identity.get("id")) is not int
            or identity["id"] <= 0
            or not _positive_text(identity.get("name"), maximum=256)
        ):
            raise EvidenceVerificationError("Odoo report record identity is invalid")

    period = result["period"]
    requested = period.get("requested")
    resolved = period.get("resolved")
    if (
        set(period) != {"comparison", "requested", "resolved"}
        or requested
        != {
            "date_from": case["parameters"]["date_from"],
            "date_to": case["parameters"]["date_to"],
            "mode": "range",
        }
        or type(resolved) is not dict
        or set(resolved) != {"date_from", "date_to", "key", "mode"}
        or type(resolved.get("key")) is not str
        or re.fullmatch(r"period-[0-9a-f]{64}", resolved["key"]) is None
        or resolved.get("mode") not in {"range", "single"}
    ):
        raise EvidenceVerificationError("report period binding is invalid")
    try:
        requested_from = datetime.strptime(
            case["parameters"]["date_from"], "%Y-%m-%d"
        ).date()
        requested_to = datetime.strptime(
            case["parameters"]["date_to"], "%Y-%m-%d"
        ).date()
        resolved_from = datetime.strptime(resolved["date_from"], "%Y-%m-%d").date()
        resolved_to = datetime.strptime(resolved["date_to"], "%Y-%m-%d").date()
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceVerificationError("resolved report period is invalid") from exc
    if resolved_from > resolved_to:
        raise EvidenceVerificationError("resolved report period is reversed")
    normalized = "odoo:date_range_normalized" in result["warnings"]
    if normalized:
        if (
            not requested_from <= resolved_from <= resolved_to <= requested_to
            or (
                resolved["mode"] == "range"
                and resolved_from == requested_from
                and resolved_to == requested_to
            )
        ):
            raise EvidenceVerificationError(
                "normalized report period escaped the requested range"
            )
    elif (
        resolved["mode"] != "range"
        or resolved_from != requested_from
        or resolved_to != requested_to
    ):
        raise EvidenceVerificationError(
            "resolved report period does not match the request"
        )
    if resolved["mode"] == "single" and resolved_from != resolved_to:
        raise EvidenceVerificationError("single report period is not one day")
    if resolved["key"] != _period_key(
        resolved["mode"],
        resolved["date_from"],
        resolved["date_to"],
    ):
        raise EvidenceVerificationError("resolved report period key is not canonical")
    declared_periods = {
        resolved["key"]: (
            resolved["mode"],
            resolved["date_from"],
            resolved["date_to"],
        )
    }
    comparison = period["comparison"]
    expected_comparison = case["parameters"].get("report_request", {}).get(
        "comparison"
    )
    if expected_comparison is None:
        if comparison is not None:
            raise EvidenceVerificationError("unexpected report comparison")
    else:
        expected_resolved_mode = {
            "previous_period": "previous_period",
            "previous_year": "same_last_year",
        }[expected_comparison["mode"]]
        if (
            type(comparison) is not dict
            or set(comparison)
            != {"periods", "requested_mode", "resolved_mode", "resolved_periods"}
            or comparison.get("requested_mode") != expected_comparison["mode"]
            or comparison.get("resolved_mode") != expected_resolved_mode
            or comparison.get("periods") != 1
            or type(comparison.get("resolved_periods")) is not list
            or len(comparison["resolved_periods"]) != 1
        ):
            raise EvidenceVerificationError("report comparison binding is invalid")
        comparison_keys: set[str] = set()
        for index, comparison_period in enumerate(comparison["resolved_periods"]):
            if (
                type(comparison_period) is not dict
                or set(comparison_period)
                != {"date_from", "date_to", "key", "label", "mode"}
                or comparison_period.get("mode") not in {"range", "single"}
                or not _positive_text(comparison_period.get("label"), maximum=128)
                or type(comparison_period.get("key")) is not str
            ):
                raise EvidenceVerificationError(
                    f"resolved comparison period is invalid: {index}"
                )
            try:
                comparison_from = datetime.strptime(
                    comparison_period["date_from"], "%Y-%m-%d"
                ).date()
                comparison_to = datetime.strptime(
                    comparison_period["date_to"], "%Y-%m-%d"
                ).date()
            except (KeyError, TypeError, ValueError) as exc:
                raise EvidenceVerificationError(
                    f"resolved comparison period is invalid: {index}"
                ) from exc
            if (
                comparison_from > comparison_to
                or comparison_period["key"]
                != _period_key(
                    comparison_period["mode"],
                    comparison_period["date_from"],
                    comparison_period["date_to"],
                )
                or comparison_period["key"] == resolved["key"]
                or comparison_period["key"] in comparison_keys
            ):
                raise EvidenceVerificationError(
                    f"resolved comparison period is invalid: {index}"
                )
            if comparison_period["mode"] != resolved["mode"]:
                raise EvidenceVerificationError(
                    f"resolved comparison period mode is invalid: {index}"
                )
            if expected_comparison["mode"] == "previous_period":
                expected_from, expected_to = _previous_period_dates(
                    resolved_from,
                    resolved_to,
                )
            else:
                expected_from = _previous_year_date(resolved_from)
                expected_to = _previous_year_date(resolved_to)
            if (
                comparison_from != expected_from
                or comparison_to != expected_to
                or comparison_to >= resolved_from
            ):
                raise EvidenceVerificationError(
                    "resolved comparison period does not match requested mode: "
                    f"{index}"
                )
            comparison_keys.add(comparison_period["key"])
            declared_periods[comparison_period["key"]] = (
                comparison_period["mode"],
                comparison_period["date_from"],
                comparison_period["date_to"],
            )

    filters = result["effective_filters"]
    if (
        set(filters)
        != {
            "analytic_groupby",
            "consolidation",
            "custom_aml_filter_count",
            "hide_zero_lines",
            "journal_ids",
            "journal_scope",
            "line_expansion_request",
            "move_state",
            "multi_currency_display",
            "tax_unit_id",
            "unreconciled_only",
        }
        or filters.get("move_state") != "posted"
        or filters.get("journal_scope") != "all_report_eligible"
        or type(filters.get("journal_ids")) is not list
        or not filters["journal_ids"]
        or filters["journal_ids"] != sorted(set(filters["journal_ids"]))
        or any(type(item) is not int or item <= 0 for item in filters["journal_ids"])
        or filters.get("tax_unit_id") is not None
        or filters.get("unreconciled_only") is not False
        or filters.get("hide_zero_lines") is not False
        or filters.get("line_expansion_request") != "none"
        or filters.get("custom_aml_filter_count") != 0
        or filters.get("analytic_groupby") is not False
        or filters.get("consolidation") is not False
        or filters.get("multi_currency_display") is not False
    ):
        raise EvidenceVerificationError("effective report filters are invalid")

    currency = result["currency"]
    if (
        set(currency) != {"id", "name", "rounding", "symbol"}
        or type(currency.get("id")) is not int
        or currency["id"] <= 0
        or not _positive_text(currency.get("name"), maximum=64)
        or not _positive_text(currency.get("symbol"), maximum=16)
        or not _positive_text(currency.get("rounding"), maximum=128)
    ):
        raise EvidenceVerificationError("report currency is invalid")
    warnings = result["warnings"]
    allowed_warnings = TAX_WARNINGS if family == "tax" else FINANCIAL_WARNINGS
    if (
        len(warnings) > 4
        or len(warnings) != len(set(warnings))
        or warnings != sorted(warnings)
        or any(item not in allowed_warnings for item in warnings)
    ):
        raise EvidenceVerificationError("report warnings are invalid")
    _validate_report_lines(
        result["lines"],
        family=family,
        declared_periods=declared_periods,
        currency_id=currency["id"],
    )

    page = result["page"]
    if (
        set(page) != {"count", "limit", "offset", "total_count"}
        or page.get("limit") != 5000
        or page.get("offset") != 0
        or type(page.get("count")) is not int
        or page["count"] < 0
        or page["count"] > 5000
        or type(page.get("total_count")) is not int
        or page["total_count"] != page["count"]
        or len(result["lines"]) != page["count"]
    ):
        raise EvidenceVerificationError("report page is incomplete")
    return result["receipt"], page["total_count"]


def verify_receipt(
    request: dict[str, Any],
    response: dict[str, Any],
    *,
    case: Mapping[str, Any],
    receipt_secret: bytes,
    runtime: Mapping[str, Any],
    release_identity: Mapping[str, Any],
    issued: datetime,
    expires: datetime,
) -> dict[str, Any]:
    data = response.get("data") if type(response) is dict else None
    if (
        set(response) != {"command", "data", "ok"}
        or response.get("command") != "read"
        or response.get("ok") is not True
        or type(data) is not dict
        or set(data) != {"capability_id", "release_identity", "result", "runtime"}
        or data.get("capability_id") != case["capability_id"]
        or data.get("release_identity") != release_identity
        or data.get("runtime") != _runtime_response(runtime)
        or type(data.get("result")) is not dict
    ):
        raise EvidenceVerificationError("CLI report response binding is invalid")
    receipt, record_count = _validate_report_result(data["result"], case=case)
    context = request["context"]
    if (
        len(receipt_secret) < 32
        or set(receipt) != RECEIPT_FIELDS
        or receipt.get("capability_id") != case["capability_id"]
        or receipt.get("capability_channel") != "staged"
        or receipt.get("company_id") != 1
        or receipt.get("database_name") != runtime["database_name"]
        or receipt.get("database_uuid") != runtime["database_uuid"]
        or receipt.get("environment") != "test"
        or receipt.get("odoo_instance_id") != runtime["instance_id"]
        or receipt.get("record_count") != record_count
        or receipt.get("registry_digest") != release_identity["registry_digest"]
        or receipt.get("release_digest") != release_identity["manifest_sha256"]
        or receipt.get("signature_key_id") != runtime["receipt_key_id"]
        or receipt.get("signature_purpose") != "read_receipt_v2"
        or receipt.get("signature_version") != 2
        or receipt.get("user_id") != 2
        or type(receipt.get("id")) is not str
        or not receipt["id"]
        or any(
            type(receipt.get(field)) is not str
            or HEX64.fullmatch(receipt[field]) is None
            for field in (
                "registry_digest",
                "release_digest",
                "request_digest",
                "result_digest",
                "signature",
            )
        )
    ):
        raise EvidenceVerificationError("read receipt binding is invalid")
    observed = _timestamp(receipt["observed_at"], label="receipt observed_at")
    if (
        receipt["observed_at"] != observed.isoformat().replace("+00:00", "Z")
        or not issued <= observed < expires
    ):
        raise EvidenceVerificationError(
            "receipt observation escaped authentication lifetime"
        )
    expected_request_digest = hashlib.sha256(
        canonical_json(
            {
                "auth_token_id": context["auth_token_id"],
                "capability_channel": runtime["capability_channel"],
                "capability_id": case["capability_id"],
                "company_id": 1,
                "database_name": runtime["database_name"],
                "database_uuid": str(uuid.UUID(runtime["database_uuid"])),
                "environment": runtime["environment"],
                "odoo_instance_id": runtime["instance_id"],
                "parameters": case["parameters"],
                "principal": FIXED_TARGET["principal"],
                "registry_digest": release_identity["registry_digest"],
                "release_digest": release_identity["manifest_sha256"],
                "user_id": 2,
            }
        )
    ).hexdigest()
    result_body = {
        key: value for key, value in response["data"]["result"].items() if key != "receipt"
    }
    if (
        not hmac.compare_digest(receipt["request_digest"], expected_request_digest)
        or not hmac.compare_digest(
            receipt["result_digest"],
            hashlib.sha256(canonical_json(result_body)).hexdigest(),
        )
    ):
        raise EvidenceVerificationError("read receipt content digest is invalid")
    unsigned = {key: value for key, value in receipt.items() if key != "signature"}
    expected_signature = hmac.new(
        receipt_secret,
        canonical_json(unsigned),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, receipt["signature"]):
        raise EvidenceVerificationError("read receipt HMAC is invalid")
    return receipt


def validate_boundary_response(
    response: dict[str, Any],
    *,
    runtime: Mapping[str, Any],
    release_identity: Mapping[str, Any],
) -> None:
    data = response.get("data") if type(response) is dict else None
    if (
        set(response) != {"command", "data", "ok"}
        or response.get("command") != "evidence.read-boundary"
        or response.get("ok") is not True
        or type(data) is not dict
        or set(data) != {"evidence", "release_identity", "runtime"}
        or data.get("release_identity") != release_identity
        or data.get("runtime") != _runtime_response(runtime)
        or type(data.get("evidence")) is not dict
    ):
        raise EvidenceVerificationError("read-boundary response is invalid")
    value = data["evidence"]
    if (
        set(value)
        != {
            "checks",
            "database",
            "drift_probes",
            "relation",
            "schema_version",
            "successful_transactions",
            "write_probe",
        }
        or value.get("schema_version")
        != "odoo-accounting-cli-v3.read-boundary-evidence.v1"
    ):
        raise EvidenceVerificationError("read-boundary evidence schema is invalid")
    database = value.get("database")
    if type(database) is not dict or set(database) != {"after", "before"}:
        raise EvidenceVerificationError("read-boundary database evidence is invalid")
    for snapshot in database.values():
        if (
            type(snapshot) is not dict
            or set(snapshot) != {"backend_pid", "name", "uuid"}
            or type(snapshot.get("backend_pid")) is not int
            or snapshot["backend_pid"] <= 0
            or snapshot.get("name") != runtime["database_name"]
            or snapshot.get("uuid") != runtime["database_uuid"]
        ):
            raise EvidenceVerificationError("read-boundary database snapshot is invalid")
    if database["before"] != database["after"]:
        raise EvidenceVerificationError("read-boundary database identity changed")
    expected_checks = {
        "backend_pid_unchanged",
        "database_name_unchanged",
        "database_uuid_unchanged",
        "relation_filenode_unchanged",
        "relation_oid_unchanged",
        "relation_row_count_unchanged",
    }
    checks = value.get("checks")
    if (
        type(checks) is not dict
        or set(checks) != expected_checks
        or any(checks[name] is not True for name in expected_checks)
    ):
        raise EvidenceVerificationError("read-boundary checks are invalid")
    relation = value.get("relation")
    if (
        type(relation) is not dict
        or set(relation) != {"after", "before", "name", "schema"}
        or relation.get("schema") != "public"
        or relation.get("name") != "ir_config_parameter"
    ):
        raise EvidenceVerificationError("read-boundary relation is invalid")
    for snapshot in (relation["before"], relation["after"]):
        if (
            type(snapshot) is not dict
            or set(snapshot) != {"filenode", "oid", "row_count"}
            or type(snapshot.get("filenode")) is not int
            or snapshot["filenode"] <= 0
            or type(snapshot.get("oid")) is not int
            or snapshot["oid"] <= 0
            or type(snapshot.get("row_count")) is not int
            or snapshot["row_count"] < 0
        ):
            raise EvidenceVerificationError("read-boundary relation snapshot is invalid")
    if relation["before"] != relation["after"]:
        raise EvidenceVerificationError("read-boundary relation changed")
    transactions = value.get("successful_transactions")
    if type(transactions) is not dict or set(transactions) != {"after", "before"}:
        raise EvidenceVerificationError("read-boundary transactions are invalid")
    marker_hashes: set[str] = set()
    for transaction in transactions.values():
        if (
            type(transaction) is not dict
            or set(transaction)
            != {"idle_after_rollback", "isolation", "marker_sha256", "read_only"}
            or transaction.get("idle_after_rollback") is not True
            or transaction.get("isolation") != "repeatable read"
            or transaction.get("read_only") is not True
            or type(transaction.get("marker_sha256")) is not str
            or HEX64.fullmatch(transaction["marker_sha256"]) is None
        ):
            raise EvidenceVerificationError(
                "read-boundary successful transaction is invalid"
            )
        marker_hashes.add(transaction["marker_sha256"])
    if len(marker_hashes) != 2:
        raise EvidenceVerificationError("read-boundary markers are not distinct")
    if value.get("write_probe") != {
        "idle_after_rollback": True,
        "rejected": True,
        "sqlstate": "25006",
        "statement_id": "ir-config-parameter-noop-update-v1",
    }:
        raise EvidenceVerificationError("read-boundary write probe is invalid")
    probes = value.get("drift_probes")
    if (
        type(probes) is not dict
        or set(probes) != {"hidden_commit", "hidden_rollback", "rollback_hook_reopen"}
    ):
        raise EvidenceVerificationError("read-boundary drift probe set is invalid")
    canaries: set[str] = set()
    for probe in probes.values():
        if (
            type(probe) is not dict
            or set(probe)
            != {"canary_sha256", "idle_after_cleanup", "rejected", "result_released"}
            or type(probe.get("canary_sha256")) is not str
            or HEX64.fullmatch(probe["canary_sha256"]) is None
            or probe.get("idle_after_cleanup") is not True
            or probe.get("rejected") is not True
            or probe.get("result_released") is not False
        ):
            raise EvidenceVerificationError("read-boundary drift probe is invalid")
        canaries.add(probe["canary_sha256"])
    if len(canaries) != 3:
        raise EvidenceVerificationError("read-boundary canaries are not distinct")


def validate_witness(
    value: dict[str, Any],
    *,
    runtime: Mapping[str, Any],
) -> None:
    transaction = value.get("transaction")
    database = value.get("database")
    endpoint = value.get("endpoint")
    oracle_python = value.get("oracle_python")
    if (
        set(value)
        != {
            "all_checks_passed",
            "command",
            "contains_credentials",
            "contains_raw_rows",
            "database",
            "database_writes_permitted",
            "endpoint",
            "fixture_gaps",
            "odoo_action_performed",
            "oracle_python",
            "production_validated",
            "relations",
            "schema_version",
            "transaction",
        }
        or value.get("schema_version") != 1
        or value.get("command") != "witness"
        or value.get("all_checks_passed") is not True
        or value.get("fixture_gaps") != []
        or value.get("contains_raw_rows") is not False
        or value.get("contains_credentials") is not False
        or value.get("database_writes_permitted") is not False
        or value.get("odoo_action_performed") is not False
        or value.get("production_validated") is not False
        or transaction
        != {
            "final_status": "IDLE",
            "isolation": "repeatable read",
            "read_only": "on",
            "rollback_completed": True,
        }
        or oracle_python
        != {
            "isolated": True,
            "path": runtime["odoo_python"],
            "sha256": runtime["odoo_python_sha256"],
        }
    ):
        raise EvidenceVerificationError("PostgreSQL witness boundary is invalid")
    if (
        type(database) is not dict
        or set(database)
        != {
            "current_database",
            "current_user",
            "database_uuid",
            "postmaster_started_at",
            "server_version_num",
            "system_identifier",
        }
        or database.get("current_database") != runtime["database_name"]
        or database.get("current_user") != "postgres"
        or database.get("database_uuid") != runtime["database_uuid"]
        or type(database.get("server_version_num")) is not int
        or database["server_version_num"] <= 0
        or not _positive_text(database.get("system_identifier"), maximum=32)
    ):
        raise EvidenceVerificationError("PostgreSQL witness database is invalid")
    _timestamp(database["postmaster_started_at"], label="postmaster_started_at")
    if endpoint != {
        "kind": "unix_socket",
        "requested_directory": "/var/run/postgresql",
        "socket_path": "/var/run/postgresql/.s.PGSQL.5432",
    }:
        raise EvidenceVerificationError("PostgreSQL witness endpoint is invalid")
    relations = value.get("relations")
    if type(relations) is not list or not relations:
        raise EvidenceVerificationError("PostgreSQL witness relations are missing")
    names: set[str] = set()
    for relation in relations:
        baseline_count = (
            relation.get("baseline_count") if type(relation) is dict else None
        )
        primary_key = relation.get("primary_key") if type(relation) is dict else None
        required_columns = (
            relation.get("required_columns") if type(relation) is dict else None
        )
        if (
            type(relation) is not dict
            or set(relation)
            != {
                "baseline_count",
                "column_count",
                "name",
                "oid",
                "owner",
                "primary_key",
                "projection_sha256",
                "relkind",
                "required_columns",
                "row_count",
                "row_stream_sha256",
                "schema_sha256",
                "witness_scope",
            }
            or not _positive_text(relation.get("name"), maximum=63)
            or relation["name"] in names
            or type(relation.get("oid")) is not int
            or relation["oid"] <= 0
            or relation.get("owner") != "odoo"
            or relation.get("relkind") != "r"
            or relation.get("witness_scope")
            not in {"all", "database_uuid_only", "required_group_xmlids_only"}
            or type(primary_key) is not list
            or not primary_key
            or len(primary_key) != len(set(primary_key))
            or any(
                type(field) is not str
                or re.fullmatch(r"[a-z_][a-z0-9_]*", field) is None
                for field in primary_key
            )
            or type(required_columns) is not list
            or not required_columns
            or any(
                type(column) is not dict
                or set(column) != {"name", "type"}
                or type(column.get("name")) is not str
                or re.fullmatch(r"[a-z_][a-z0-9_]*", column["name"]) is None
                or not _positive_text(column.get("type"), maximum=128)
                for column in required_columns
            )
            or type(relation.get("column_count")) is not int
            or relation["column_count"] < len(relation["required_columns"])
            or type(relation.get("row_count")) is not int
            or relation["row_count"] <= 0
            or (
                baseline_count is not None
                and (
                    type(baseline_count) is not int
                    or baseline_count <= 0
                    or baseline_count != relation["row_count"]
                )
            )
            or any(
                type(relation.get(field)) is not str
                or HEX64.fullmatch(relation[field]) is None
                for field in (
                    "projection_sha256",
                    "row_stream_sha256",
                    "schema_sha256",
                )
            )
        ):
            raise EvidenceVerificationError("PostgreSQL witness relation is invalid")
        names.add(relation["name"])


def _validate_readiness(
    value: dict[str, Any],
    *,
    release_identity: Mapping[str, Any],
) -> None:
    data = value.get("data") if type(value) is dict else None
    registered = sorted(REGISTERED_READ_CAPABILITY_IDS)
    admissible = sorted(ADMISSIBLE_READ_CAPABILITY_IDS)
    declared_gaps = sorted(DECLARED_READ_GAP_IDS)
    required_evidence = sorted(REQUIRED_GOAL_EVIDENCE_KINDS)
    if (
        set(value) != {"business_succeeded", "command", "data", "ok"}
        or value.get("business_succeeded") is not False
        or value.get("command") != "evidence.read-capabilities-readiness"
        or value.get("ok") is not True
        or type(data) is not dict
        or set(data) != READINESS_DATA_FIELDS
        or data.get("release_identity") != release_identity
        or data.get("read_static_readiness_ready") is not False
        or data.get("read_goal_readiness_ready") is not False
        or data.get("external_read_evidence_verifier_ready") is not False
        or data.get("production_promotion_allowed") is not False
        or data.get("real_odoo_write_performed") is not False
        or data.get("registered_read_capability_ids") != registered
        or data.get("required_read_capability_ids") != registered
        or data.get("missing_required_read_capability_ids") != []
        or data.get("total_read_capabilities") != len(registered)
        or data.get("admissible_ids") != admissible
        or data.get("admissible_count") != len(admissible)
        or data.get("unready_capability_ids") != declared_gaps
        or data.get("goal_evidence_ready_ids") != []
        or data.get("goal_evidence_ready_count") != 0
        or data.get("goal_evidence_unready_capability_ids") != registered
        or data.get("completion_ready_ids") != []
        or data.get("completion_ready_count") != 0
        or data.get("required_goal_evidence_kinds") != required_evidence
        or data.get("blockers") != READINESS_BLOCKERS
    ):
        raise EvidenceVerificationError("read readiness evidence is invalid")
    reports = data.get("capabilities")
    if type(reports) is not list or len(reports) != len(registered):
        raise EvidenceVerificationError("read readiness evidence is invalid")
    if [
        report.get("capability", {}).get("id")
        if type(report) is dict
        and type(report.get("capability")) is dict
        else None
        for report in reports
    ] != registered:
        raise EvidenceVerificationError("read readiness evidence is invalid")
    reports_by_id: dict[str, Mapping[str, Any]] = {}
    for report in reports:
        capability = report.get("capability") if type(report) is dict else None
        capability_id = (
            capability.get("id") if type(capability) is dict else None
        )
        if (
            type(capability_id) is not str
            or capability_id not in REGISTERED_READ_CAPABILITY_IDS
            or capability_id in reports_by_id
        ):
            raise EvidenceVerificationError(
                "read readiness evidence is invalid"
            )
        reports_by_id[capability_id] = report
    if set(reports_by_id) != REGISTERED_READ_CAPABILITY_IDS:
        raise EvidenceVerificationError("read readiness evidence is invalid")
    for capability_id, report in reports_by_id.items():
        capability = report.get("capability")
        checks = report.get("checks")
        expected_admissible = capability_id in ADMISSIBLE_READ_CAPABILITY_IDS
        if (
            set(report) != READINESS_REPORT_FIELDS
            or type(capability) is not dict
            or set(capability)
            != {
                "access",
                "enabled_environments",
                "evidence_level",
                "id",
                "staged_environments",
            }
            or capability.get("access") != "read"
            or capability.get("enabled_environments") != []
            or capability.get("id") != capability_id
            or capability.get("evidence_level")
            != ("contract_tested" if expected_admissible else "declared")
            or capability.get("staged_environments")
            != (["test"] if expected_admissible else [])
            or type(checks) is not dict
            or set(checks) != READINESS_CHECK_IDS
            or any(type(result) is not bool for result in checks.values())
            or report.get("external_read_evidence_verified") is not False
            or report.get("goal_evidence_blockers")
            != [
                "trusted external read evidence has not been independently "
                "verified"
            ]
            or report.get("goal_evidence_ready") is not False
            or report.get("missing_goal_evidence_kinds") != required_evidence
            or report.get("production_promotion_allowed") is not False
            or report.get("real_odoo_write_performed") is not False
            or report.get("read_completion_ready") is not False
            or report.get("registry_claimed_receipt_count") != 0
            or report.get("registry_claimed_receipt_kinds") != []
            or report.get("registry_receipts_authoritative_for_goal")
            is not False
        ):
            raise EvidenceVerificationError(
                "read readiness evidence is invalid"
            )
        if expected_admissible:
            if (
                report.get("blockers") != []
                or set(check for check, result in checks.items() if result)
                != READINESS_CHECK_IDS
                or report.get("trusted_handler_kind") != "odoo"
                or report.get("trusted_read_admissible") is not True
            ):
                raise EvidenceVerificationError(
                    "read readiness evidence is invalid"
                )
        elif (
            type(report.get("blockers")) is not list
            or not report["blockers"]
            or any(
                type(blocker) is not str for blocker in report["blockers"]
            )
            or len(report["blockers"]) != len(set(report["blockers"]))
            or all(checks.values())
            or sorted(report["blockers"])
            != sorted(
                check.replace("_", " ")
                for check, result in checks.items()
                if result is False
            )
            or report.get("trusted_handler_kind") is not None
            or report.get("trusted_read_admissible") is not False
        ):
            raise EvidenceVerificationError(
                "read readiness evidence is invalid"
            )


def _validate_release_document(
    value: dict[str, Any],
    *,
    release_identity: Mapping[str, Any],
) -> None:
    if value != {
        "command": "release.identity",
        "data": release_identity,
        "ok": True,
    }:
        raise EvidenceVerificationError("release identity document is invalid")


def _validate_validation_report(
    value: dict[str, Any],
    *,
    release_identity: Mapping[str, Any],
    receipt_ids: Mapping[str, str],
    record_counts: Mapping[str, int],
) -> None:
    if (
        set(value)
        != {
            "accounting_correctness_claimed",
            "accounting_oracle",
            "all_checks_passed",
            "case_results",
            "database_witness_unchanged",
            "production_promotion_allowed",
            "read_boundary_probe_passed",
            "real_odoo_write_performed",
            "release_identity",
            "schema_version",
            "scope",
        }
        or value.get("schema_version") != 1
        or value.get("scope") != VALIDATION_SCOPE
        or value.get("accounting_correctness_claimed") is not False
        or value.get("accounting_oracle")
        != {
            "available": False,
            "performed": False,
            "reason": ORACLE_UNAVAILABLE_REASON,
        }
        or value.get("all_checks_passed") is not True
        or value.get("database_witness_unchanged") is not True
        or value.get("production_promotion_allowed") is not False
        or value.get("read_boundary_probe_passed") is not True
        or value.get("real_odoo_write_performed") is not False
        or value.get("release_identity") != release_identity
        or type(value.get("case_results")) is not dict
        or set(value["case_results"]) != set(CASE_NAMES)
    ):
        raise EvidenceVerificationError("validation report envelope is invalid")
    for name in CASE_NAMES:
        result = value["case_results"][name]
        capability_id = REPORT_CASES[name][0]
        if result != {
            "capability_id": capability_id,
            "complete_page": True,
            "receipt_id": receipt_ids[name],
            "record_count": record_counts[name],
        }:
            raise EvidenceVerificationError(
                f"validation report case binding is invalid: {name}"
            )


def verify_evidence(
    evidence_dir: Path,
    *,
    expected_final_path: Path,
    expected_identity: dict[str, Any],
    runtime: dict[str, Any],
    auth_secret: bytes,
    receipt_secret: bytes,
    enforce_root: bool = True,
) -> dict[str, Any]:
    evidence = Path(evidence_dir)
    final = Path(expected_final_path)
    identity = _validate_expected_identity(expected_identity)
    if (
        not isinstance(auth_secret, bytes)
        or len(auth_secret) < 32
        or not isinstance(receipt_secret, bytes)
        or len(receipt_secret) < 32
        or hmac.compare_digest(auth_secret, receipt_secret)
    ):
        raise EvidenceVerificationError("runtime secrets are invalid")
    runtime = _validate_runtime(
        runtime,
        target=FIXED_TARGET,
        release_identity=identity,
    )
    _verify_release_tree(runtime, identity, enforce_root=enforce_root)
    documents, manifest, manifest_sha256 = _load_bundle(
        evidence,
        expected_final_path=final,
        expected_identity=identity,
        runtime=runtime,
        auth_secret=auth_secret,
        receipt_secret=receipt_secret,
        enforce_root=enforce_root,
    )
    plan = validate_plan(
        parse_json(
            documents["report-read-plan.json"],
            label="report read plan",
            canonical=False,
        )
    )
    _validate_release_document(
        _json(documents, "release-identity.json"),
        release_identity=identity,
    )
    _validate_readiness(
        _json(documents, "read-capabilities-readiness.json"),
        release_identity=identity,
    )
    validate_boundary_response(
        _json(documents, "read-boundary.json"),
        runtime=runtime,
        release_identity=identity,
    )
    witness_pre = _json(documents, "witness-pre.json")
    witness_post = _json(documents, "witness-post.json")
    validate_witness(witness_pre, runtime=runtime)
    validate_witness(witness_post, runtime=runtime)
    if witness_pre != witness_post:
        raise EvidenceVerificationError("PostgreSQL witness changed across reads")

    receipt_ids: dict[str, str] = {}
    token_ids: set[str] = set()
    record_counts: dict[str, int] = {}
    for case in plan["cases"]:
        name = case["name"]
        if documents[f"cases/{name}/stderr"] != b"":
            raise EvidenceVerificationError(f"read stderr is not empty: {name}")
        if _json(documents, f"cases/{name}/exit.json") != {
            "command": "read",
            "returncode": 0,
        }:
            raise EvidenceVerificationError(f"read exit is invalid: {name}")
        request = _json(documents, f"cases/{name}/request.json")
        response = _json(documents, f"cases/{name}/response.json")
        token_id, issued, expires = verify_auth_request(
            request,
            case=case,
            auth_secret=auth_secret,
            runtime=runtime,
        )
        if token_id in token_ids:
            raise EvidenceVerificationError("authentication token ID was reused")
        token_ids.add(token_id)
        receipt = verify_receipt(
            request,
            response,
            case=case,
            receipt_secret=receipt_secret,
            runtime=runtime,
            release_identity=identity,
            issued=issued,
            expires=expires,
        )
        receipt_id = receipt["id"]
        if receipt_id in receipt_ids.values():
            raise EvidenceVerificationError("read receipt ID was reused")
        receipt_ids[name] = receipt_id
        record_counts[name] = receipt["record_count"]
    if receipt_ids != manifest["receipt_ids"]:
        raise EvidenceVerificationError("manifest receipt IDs are invalid")
    _validate_validation_report(
        _json(documents, "validation-report.json"),
        release_identity=identity,
        receipt_ids=receipt_ids,
        record_counts=record_counts,
    )
    return {
        "accounting_correctness_verified": False,
        "accounting_oracle_available": False,
        "all_checks_passed": True,
        "bundle_manifest_sha256": manifest_sha256,
        "evidence_path": str(final),
        "production_promotion_allowed": False,
        "receipt_ids": receipt_ids,
        "release_identity": identity,
    }


def _load_runtime_config(path: Path, *, release_root: Path) -> tuple[dict[str, Any], Path, Path]:
    if not path.is_absolute():
        raise EvidenceVerificationError("runtime config path must be absolute")
    if os.name == "posix":
        try:
            metadata = path.lstat()
            parent_metadata = path.parent.lstat()
        except OSError as exc:
            raise EvidenceVerificationError("runtime config is unavailable") from exc
        if (
            path.is_symlink()
            or path.resolve(strict=True) != path
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or path.parent.is_symlink()
            or path.parent.resolve(strict=True) != path.parent
            or parent_metadata.st_uid != 0
            or parent_metadata.st_mode & 0o022
        ):
            raise EvidenceVerificationError("runtime config is not root-managed")
    payload = stable_read(
        path,
        label="runtime config",
        maximum=65_536,
        enforce_root=True,
    )
    value = parse_json(payload, label="runtime config", canonical=False)
    expected_package = (
        release_root.parent.parent
        / "packages"
        / f"odoo-accounting-cli-v3-{release_root.name}.tar.gz"
    )
    if (
        set(value) != RUNTIME_CONFIG_FIELDS
        or value.get("instance_id") != FIXED_TARGET["instance_id"]
        or value.get("database_name") != FIXED_TARGET["database_name"]
        or value.get("database_uuid") != FIXED_TARGET["database_uuid"]
        or value.get("environment") != "test"
        or value.get("capability_channel") != "staged"
        or value.get("release_root") != str(release_root)
        or value.get("canonical_package_path") != str(expected_package)
        or value.get("auth_key_id") == value.get("receipt_key_id")
        or any(
            type(value.get(field)) is not str or not value[field].strip()
            for field in (
                "auth_key_id",
                "auth_secret_path",
                "odoo_python",
                "receipt_key_id",
                "receipt_secret_path",
            )
        )
        or any(
            type(value.get(field)) is not str
            or HEX64.fullmatch(value[field]) is None
            for field in (
                "canonical_package_sha256",
                "odoo_bin_sha256",
                "odoo_config_sha256",
                "odoo_python_sha256",
            )
        )
    ):
        raise EvidenceVerificationError("runtime config binding is invalid")
    auth_path = Path(value["auth_secret_path"])
    receipt_path = Path(value["receipt_secret_path"])
    if (
        not Path(value["odoo_python"]).is_absolute()
        or not auth_path.is_absolute()
        or not receipt_path.is_absolute()
        or auth_path == receipt_path
    ):
        raise EvidenceVerificationError("runtime config paths are invalid")
    runtime = {
        "auth_key_id": value["auth_key_id"],
        "canonical_package_path": value["canonical_package_path"],
        "canonical_package_sha256": value["canonical_package_sha256"],
        "capability_channel": value["capability_channel"],
        "database_name": value["database_name"],
        "database_uuid": value["database_uuid"],
        "environment": value["environment"],
        "instance_id": value["instance_id"],
        "odoo_bin": value["odoo_bin"],
        "odoo_bin_sha256": value["odoo_bin_sha256"],
        "odoo_config": value["odoo_config"],
        "odoo_config_sha256": value["odoo_config_sha256"],
        "odoo_python": value["odoo_python"],
        "odoo_python_sha256": value["odoo_python_sha256"],
        "receipt_key_id": value["receipt_key_id"],
        "release_root": value["release_root"],
    }
    return runtime, auth_path, receipt_path


def _read_secret(path: Path, *, label: str) -> bytes:
    payload = stable_read(
        path,
        label=label,
        maximum=MAX_SECRET_BYTES,
        enforce_root=True,
    )
    metadata = path.lstat()
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & ~0o640:
        raise EvidenceVerificationError(f"{label} permissions are too broad")
    if len(payload) < 32:
        raise EvidenceVerificationError(f"{label} is too short")
    return payload


def _sealed_release_root() -> Path:
    script = Path(os.path.abspath(__file__))
    if script.is_symlink() or script.resolve(strict=True) != script:
        raise EvidenceVerificationError("verifier must be a canonical release member")
    metadata = script.lstat()
    release_root = script.parents[2]
    if (
        os.name != "posix"
        or os.geteuid() != 0
        or release_root.parent != RELEASE_PARENT
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
    ):
        raise EvidenceVerificationError("verifier is not a sealed release member")
    return release_root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--runtime-config", required=True, type=Path)
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-package-sha256", required=True)
    parser.add_argument("--expected-registry-digest", required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    arguments = _parser().parse_args(list(argv) if argv is not None else None)
    try:
        release_root = _sealed_release_root()
        expected_identity = _validate_expected_identity(
            {
                "commit": arguments.expected_commit,
                "manifest_sha256": arguments.expected_manifest_sha256,
                "package_sha256": arguments.expected_package_sha256,
                "registry_digest": arguments.expected_registry_digest,
                "release": arguments.expected_release,
                "verified": True,
                "version": arguments.expected_version,
            }
        )
        if release_root.name != expected_identity["release"]:
            raise EvidenceVerificationError("verifier release name mismatch")
        evidence = arguments.evidence_dir
        if (
            not evidence.is_absolute()
            or evidence.parent != EVIDENCE_PARENT
            or SAFE_NAME.fullmatch(evidence.name) is None
        ):
            raise EvidenceVerificationError("final evidence path is invalid")
        runtime, auth_path, receipt_path = _load_runtime_config(
            arguments.runtime_config,
            release_root=release_root,
        )
        report = verify_evidence(
            evidence,
            expected_final_path=evidence,
            expected_identity=expected_identity,
            runtime=runtime,
            auth_secret=_read_secret(auth_path, label="auth secret"),
            receipt_secret=_read_secret(receipt_path, label="receipt secret"),
        )
        sys.stdout.buffer.write(canonical_json(report) + b"\n")
        return 0
    except EvidenceVerificationError as exc:
        sys.stderr.write(f"dev251_report_read_verification_failed: {exc}\n")
        return 2
    except Exception:
        sys.stderr.write(
            "dev251_report_read_verification_failed: unexpected failure\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

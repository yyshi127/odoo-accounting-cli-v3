#!/usr/bin/python3
"""Collect exact-release Dev251 native-report read evidence.

The collector signs four fixed staged-test requests, executes the sealed CLI,
captures a rollback-boundary probe and independent PostgreSQL witnesses, and
publishes only after the sibling verifier accepts the complete bundle.
Runtime staging is fixed below ``/run``.  Durable evidence is fixed below
``/var/lib/odoo-accounting-cli-v3/evidence``.  No secret is written to either.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Iterable, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux production dependency
    fcntl = None  # type: ignore[assignment]

try:
    import pwd
except ImportError:  # pragma: no cover - imported by Windows unit tests
    pwd = None  # type: ignore[assignment]


sys.dont_write_bytecode = True

PLAN_SCOPE = "odoo-accounting-cli-v3.dev251.report-read-plan.v1"
BUNDLE_SCOPE = "odoo-accounting-cli-v3.dev251.report-read-evidence.v1"
VALIDATION_SCOPE = "odoo-accounting-cli-v3.dev251.report-read-validation.v1"
RUN_PARENT = Path("/run/odoo-accounting-cli-v3-dev251")
EVIDENCE_PARENT = Path("/var/lib/odoo-accounting-cli-v3/evidence")
RELEASE_PARENT = Path("/opt/odoo-accounting-cli-v3/releases")
PLAN_NAME = "report_read_plan.json"
PLAN_BUNDLE_NAME = "report-read-plan.json"
VERIFIER_NAME = "verify_report_read_evidence.py"
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
REPORT_READ_CAPABILITY_IDS = frozenset(
    {
        "acct.report.financial_read.v1",
        "acct.tax.report_read.v1",
    }
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
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024


class CollectionError(RuntimeError):
    """The fixed collection or atomic publication failed closed."""


class PublicationOutcomeUnknown(CollectionError):
    """The final rename succeeded but its directory durability is unconfirmed."""

    def __init__(self, evidence_path: Path) -> None:
        super().__init__(
            "final evidence rename completed but parent directory fsync failed; "
            "run --reconcile and do not repeat collection"
        )
        self.evidence_path = evidence_path


@dataclass(frozen=True)
class ExpectedIdentity:
    release: str
    version: str
    commit: str
    manifest_sha256: str
    package_sha256: str
    registry_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.release) is not str
            or SAFE_NAME.fullmatch(self.release) is None
            or type(self.version) is not str
            or VERSION.fullmatch(self.version) is None
            or type(self.commit) is not str
            or HEX40.fullmatch(self.commit) is None
            or self.release != f"{self.version}-{self.commit[:12]}"
            or any(
                type(value) is not str or HEX64.fullmatch(value) is None
                for value in (
                    self.manifest_sha256,
                    self.package_sha256,
                    self.registry_digest,
                )
            )
        ):
            raise CollectionError("expected release identity is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "commit": self.commit,
            "manifest_sha256": self.manifest_sha256,
            "package_sha256": self.package_sha256,
            "registry_digest": self.registry_digest,
            "release": self.release,
            "verified": True,
            "version": self.version,
        }


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


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
        raise CollectionError("evidence value is not canonical JSON") from exc


def _strict_json_bytes(payload: bytes, *, label: str) -> dict[str, Any]:
    if not payload or len(payload) > MAX_JSON_BYTES:
        raise CollectionError(f"{label} is empty or too large")
    try:
        text = payload.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectionError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise CollectionError(f"{label} must be a JSON object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise CollectionError(f"non-finite JSON number: {value}")


def _read_file(
    path: Path,
    *,
    label: str,
    maximum: int = MAX_JSON_BYTES,
    allow_empty: bool = False,
) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or (before.st_size == 0 and not allow_empty)
            or before.st_size > maximum
        ):
            raise CollectionError(f"{label} file boundary is invalid")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise CollectionError(f"{label} changed while opening")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise CollectionError(f"{label} is too large")
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
            raise CollectionError(f"{label} changed while reading")
        return b"".join(chunks)
    except CollectionError:
        raise
    except OSError as exc:
        raise CollectionError(f"{label} cannot be read") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _common_parameters(parameters: Mapping[str, Any], company_id: int) -> bool:
    return (
        parameters.get("company_id") == company_id
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
        not isinstance(value, dict)
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
        or value.get("production_promotion_allowed") is not False
    ):
        raise CollectionError("Dev251 report read plan envelope is invalid")
    target = value["target"]
    if (
        not isinstance(target, dict)
        or target != FIXED_TARGET
    ):
        raise CollectionError("Dev251 report read target is invalid")
    oracle = value["accounting_oracle"]
    if (
        not isinstance(oracle, dict)
        or set(oracle) != {"available", "performed", "reason"}
        or oracle.get("available") is not False
        or oracle.get("performed") is not False
        or oracle.get("reason") != ORACLE_UNAVAILABLE_REASON
    ):
        raise CollectionError("Dev251 plan must not claim an accounting oracle")
    cases = value["cases"]
    if (
        not isinstance(cases, list)
        or tuple(
            item.get("name") for item in cases if isinstance(item, dict)
        )
        != CASE_NAMES
    ):
        raise CollectionError("Dev251 report case set or order is invalid")
    for case in cases:
        if (
            not isinstance(case, dict)
            or set(case)
            != {
                "capability_id",
                "name",
                "odoo_report_xmlid",
                "parameters",
            }
        ):
            raise CollectionError("Dev251 report case fields are invalid")
        expected_capability, expected_xmlid, _family, expected_kind = REPORT_CASES[
            case["name"]
        ]
        parameters = case["parameters"]
        if (
            case["capability_id"] != expected_capability
            or case["odoo_report_xmlid"] != expected_xmlid
            or not isinstance(parameters, dict)
            or not _common_parameters(parameters, target["company_id"])
        ):
            raise CollectionError("Dev251 report case binding is invalid")
        if case["name"] == "tax_report":
            if set(parameters) != {
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
            }:
                raise CollectionError("Dev251 tax report parameters are invalid")
        else:
            request = parameters.get("report_request")
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
                or not isinstance(request, dict)
                or set(request) != {"comparison", "kind"}
                or request.get("kind") != expected_kind
            ):
                raise CollectionError("Dev251 financial report parameters are invalid")
            comparison = request["comparison"]
            expected_comparison = {
                "balance_sheet": {"mode": "previous_period", "periods": 1},
                "profit_and_loss": {"mode": "previous_year", "periods": 1},
                "cash_flow": None,
            }[case["name"]]
            if comparison != expected_comparison:
                raise CollectionError("Dev251 report comparison is invalid")
    return value


def _runtime_mapping(runtime: Any) -> dict[str, Any]:
    try:
        return {
            "auth_key_id": runtime.auth_key_id,
            "canonical_package_path": str(runtime.canonical_package_path),
            "canonical_package_sha256": runtime.canonical_package_sha256,
            "capability_channel": runtime.capability_channel,
            "database_name": runtime.database_name,
            "database_uuid": runtime.database_uuid,
            "environment": runtime.environment,
            "instance_id": runtime.instance_id,
            "odoo_bin": str(runtime.odoo_bin),
            "odoo_bin_sha256": runtime.odoo_bin_sha256,
            "odoo_config": str(runtime.odoo_config),
            "odoo_config_sha256": runtime.odoo_config_sha256,
            "odoo_python": str(runtime.odoo_python),
            "odoo_python_sha256": runtime.odoo_python_sha256,
            "receipt_key_id": runtime.receipt_key_id,
            "release_root": str(runtime.release_root),
        }
    except AttributeError as exc:
        raise CollectionError("runtime configuration is invalid") from exc


def validate_runtime(
    plan: Mapping[str, Any],
    runtime: Any,
    release_root: Path,
    *,
    expected_identity: ExpectedIdentity,
) -> dict[str, Any]:
    target = plan["target"]
    mapping = _runtime_mapping(runtime)
    path_fields = (
        "canonical_package_path",
        "odoo_bin",
        "odoo_config",
        "odoo_python",
        "release_root",
    )
    expected_package = (
        release_root.parent.parent
        / "packages"
        / f"odoo-accounting-cli-v3-{expected_identity.release}.tar.gz"
    )
    if (
        type(mapping["auth_key_id"]) is not str
        or not mapping["auth_key_id"].strip()
        or type(mapping["receipt_key_id"]) is not str
        or not mapping["receipt_key_id"].strip()
        or mapping["auth_key_id"] == mapping["receipt_key_id"]
        or any(not Path(mapping[field]).is_absolute() for field in path_fields)
    ):
        raise CollectionError("runtime escaped the fixed Dev251 target or release")
    try:
        observed_release_root = Path(mapping["release_root"]).resolve(strict=True)
        expected_release_root = release_root.resolve(strict=True)
    except OSError as exc:
        raise CollectionError("runtime release root is unavailable") from exc
    if (
        release_root.parent.name != "releases"
        or release_root.name != expected_identity.release
        or mapping["instance_id"] != target["instance_id"]
        or mapping["database_name"] != target["database_name"]
        or mapping["database_uuid"] != target["database_uuid"]
        or mapping["environment"] != target["environment"]
        or mapping["capability_channel"] != target["capability_channel"]
        or observed_release_root != expected_release_root
        or Path(mapping["canonical_package_path"]) != expected_package
        or mapping["canonical_package_sha256"] != expected_identity.package_sha256
        or any(
            type(mapping[field]) is not str
            or HEX64.fullmatch(mapping[field]) is None
            for field in (
                "canonical_package_sha256",
                "odoo_bin_sha256",
                "odoo_config_sha256",
                "odoo_python_sha256",
            )
        )
    ):
        raise CollectionError("runtime escaped the fixed Dev251 target or release")
    return mapping


def _write(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise CollectionError("evidence output already exists")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise CollectionError("evidence write was short")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: Any) -> None:
    _write(path, canonical_json(value) + b"\n")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _chmod_nofollow(path: Path, mode: int) -> None:
    if path.is_symlink():
        raise CollectionError("refusing to change mode through a symlink")
    if os.name == "posix":
        os.chmod(path, mode, follow_symlinks=False)
    else:  # pragma: no cover - exercised by Windows unit tests
        os.chmod(path, mode)


def _verify_directory(
    path: Path,
    *,
    expected_mode: int,
    enforce_root: bool,
    create: bool = False,
) -> None:
    if create and not path.exists():
        path.mkdir(mode=expected_mode)
    metadata = path.lstat()
    actual_mode = stat.S_IMODE(metadata.st_mode)
    if os.name == "nt":
        windows_mode = {
            0o500: 0o555,
            0o700: 0o777,
            0o755: 0o777,
        }[expected_mode]
    else:
        windows_mode = expected_mode
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or actual_mode != windows_mode
        or path.resolve(strict=True) != path
        or (
            enforce_root
            and (metadata.st_uid != 0 or metadata.st_gid != 0)
        )
    ):
        raise CollectionError(f"directory boundary is invalid: {path}")


def _command_document(
    result: CommandResult,
    *,
    command: str,
    label: str,
    allow_business_field: bool = False,
) -> dict[str, Any]:
    if (
        type(result.returncode) is not int
        or result.returncode != 0
        or len(result.stderr) > MAX_STDERR_BYTES
        or result.stderr
    ):
        raise CollectionError(f"{label} command failed")
    value = _strict_json_bytes(result.stdout, label=label)
    fields = {"command", "data", "ok"}
    if allow_business_field:
        fields.add("business_succeeded")
    if (
        set(value) != fields
        or value.get("ok") is not True
        or value.get("command") != command
        or not isinstance(value.get("data"), dict)
        or result.stdout != canonical_json(value) + b"\n"
    ):
        raise CollectionError(f"{label} response is invalid")
    return value


def _validate_targeted_readiness(
    value: Mapping[str, Any],
    *,
    expected_identity: Mapping[str, Any],
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
        or data.get("release_identity") != expected_identity
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
        raise CollectionError("read readiness probe has unsafe semantics")
    reports = data.get("capabilities")
    if type(reports) is not list or len(reports) != len(registered):
        raise CollectionError("read readiness probe has unsafe semantics")
    if [
        report.get("capability", {}).get("id")
        if type(report) is dict
        and type(report.get("capability")) is dict
        else None
        for report in reports
    ] != registered:
        raise CollectionError("read readiness probe has unsafe semantics")
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
            raise CollectionError("read readiness probe has unsafe semantics")
        reports_by_id[capability_id] = report
    if set(reports_by_id) != REGISTERED_READ_CAPABILITY_IDS:
        raise CollectionError("read readiness probe has unsafe semantics")
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
            raise CollectionError("read readiness probe has unsafe semantics")
        if expected_admissible:
            if (
                report.get("blockers") != []
                or set(check for check, result in checks.items() if result)
                != READINESS_CHECK_IDS
                or report.get("trusted_handler_kind") != "odoo"
                or report.get("trusted_read_admissible") is not True
            ):
                raise CollectionError(
                    "read readiness probe has unsafe semantics"
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
            raise CollectionError("read readiness probe has unsafe semantics")
    if not REPORT_READ_CAPABILITY_IDS.issubset(reports_by_id):
        raise CollectionError("read readiness probe has unsafe semantics")


def _witness_document(result: CommandResult, *, label: str) -> dict[str, Any]:
    if result.returncode != 0 or result.stderr:
        raise CollectionError(f"{label} witness failed")
    value = _strict_json_bytes(result.stdout, label=label)
    transaction = value.get("transaction")
    if (
        value.get("schema_version") != 1
        or value.get("command") != "witness"
        or value.get("all_checks_passed") is not True
        or value.get("database_writes_permitted") is not False
        or value.get("odoo_action_performed") is not False
        or not isinstance(transaction, dict)
        or transaction.get("read_only") != "on"
        or transaction.get("isolation") != "repeatable read"
        or transaction.get("rollback_completed") is not True
        or transaction.get("final_status") != "IDLE"
        or result.stdout != canonical_json(value) + b"\n"
    ):
        raise CollectionError(f"{label} witness is invalid")
    return value


def _build_request(
    plan: Mapping[str, Any],
    case: Mapping[str, Any],
    runtime: Any,
    auth_secret: bytes,
    auth_api: Any,
    *,
    now: datetime,
    token_id: str,
) -> dict[str, Any]:
    target = plan["target"]
    context = auth_api.sign_request_context(
        auth_token_id=token_id,
        principal=target["principal"],
        odoo_instance_id=target["instance_id"],
        database_name=target["database_name"],
        database_uuid=target["database_uuid"],
        user_id=target["user_id"],
        company_id=target["company_id"],
        allowed_company_ids=frozenset(target["allowed_company_ids"]),
        environment=target["environment"],
        capability_id=case["capability_id"],
        parameters=case["parameters"],
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
        key_id=runtime.auth_key_id,
        secret=auth_secret,
    )
    return {
        "capability_id": case["capability_id"],
        "context": {
            **auth_api.context_payload(context),
            "auth_signature": context.auth_signature,
        },
        "parameters": case["parameters"],
    }


def _case_summary(
    case: Mapping[str, Any], response: Mapping[str, Any]
) -> dict[str, Any]:
    data = response.get("data")
    result = data.get("result") if isinstance(data, dict) else None
    receipt = result.get("receipt") if isinstance(result, dict) else None
    page = result.get("page") if isinstance(result, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("capability_id") != case["capability_id"]
        or not isinstance(result, dict)
        or not isinstance(receipt, dict)
        or not isinstance(page, dict)
        or type(page.get("count")) is not int
        or type(page.get("total_count")) is not int
        or page["count"] != page["total_count"]
        or page.get("limit") != case["parameters"]["limit"]
        or page.get("offset") != case["parameters"]["offset"]
        or not isinstance(receipt.get("id"), str)
        or not receipt["id"]
    ):
        raise CollectionError(f"report result is incomplete: {case['name']}")
    return {
        "capability_id": case["capability_id"],
        "complete_page": True,
        "receipt_id": receipt["id"],
        "record_count": receipt.get("record_count"),
    }


def _file_manifest(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            if path.is_symlink():
                raise CollectionError("bundle contains a symlink directory")
            continue
        if path.is_symlink() or not path.is_file():
            raise CollectionError("bundle contains an unsafe member")
        relative = path.relative_to(root).as_posix()
        if relative == "BUNDLE-MANIFEST.json":
            continue
        payload = _read_file(
            path,
            label=f"bundle member {relative}",
            allow_empty=True,
        )
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    return entries


def _assert_no_secret_leak(root: Path, secrets: tuple[bytes, ...]) -> None:
    patterns: list[bytes] = []
    for secret in secrets:
        patterns.extend(
            (
                secret,
                secret.hex().encode("ascii"),
                base64.b64encode(secret),
                base64.urlsafe_b64encode(secret),
            )
        )
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        payload = _read_file(
            path,
            label=f"secret scan member {relative}",
            allow_empty=True,
        )
        if any(pattern and pattern in payload for pattern in patterns):
            raise CollectionError(
                f"runtime secret leaked into evidence: {relative}"
            )


def _copy_and_seal(source: Path, pending: Path) -> None:
    if pending.exists() or pending.is_symlink():
        raise CollectionError("pending evidence publication already exists")
    pending.mkdir(mode=0o700)
    try:
        directories = [path for path in source.rglob("*") if path.is_dir()]
        for directory in sorted(directories):
            if directory.is_symlink():
                raise CollectionError("source evidence contains a symlink")
            (pending / directory.relative_to(source)).mkdir(mode=0o700)
        for source_file in sorted(path for path in source.rglob("*") if path.is_file()):
            if source_file.is_symlink():
                raise CollectionError("source evidence contains a symlink")
            relative = source_file.relative_to(source)
            destination = pending / relative
            payload = _read_file(
                source_file,
                label=f"source bundle member {relative.as_posix()}",
                allow_empty=True,
            )
            _write(destination, payload)
            _chmod_nofollow(destination, 0o400)
        for directory in sorted(
            (path for path in pending.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
            _chmod_nofollow(directory, 0o500)
        _fsync_directory(pending)
        _chmod_nofollow(pending, 0o500)
        _fsync_directory(pending.parent)
    except BaseException:
        if pending.exists() and not pending.is_symlink():
            _discard_pending_directory(pending)
        raise


def _rename_noreplace(source: Path, destination: Path) -> None:
    if sys.platform != "linux":
        if destination.exists() or destination.is_symlink():
            raise CollectionError("final evidence already exists")
        os.rename(source, destination)
        try:
            _fsync_directory(destination.parent)
        except OSError as exc:
            raise PublicationOutcomeUnknown(destination) from exc
        return
    library = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(library, "renameat2", None)
    if renameat2 is None:
        raise CollectionError("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            -100,
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            1,
        )
        != 0
    ):
        raise CollectionError(
            f"atomic evidence publication failed with errno {ctypes.get_errno()}"
        )
    try:
        _fsync_directory(destination.parent)
    except OSError as exc:
        raise PublicationOutcomeUnknown(destination) from exc


def _load_verifier(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("dev251_report_read_verifier", path)
    if spec is None or spec.loader is None:
        raise CollectionError("Dev251 verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _discard_pending_directory(path: Path) -> None:
    if (
        not path.name.startswith(".")
        or not path.name.endswith(".pending")
        or SAFE_NAME.fullmatch(path.name[1:-8]) is None
    ):
        raise CollectionError("refusing to remove an unexpected pending directory")
    if path.is_symlink():
        raise CollectionError("pending evidence became a symlink")
    if os.name == "nt":
        for member in sorted(
            path.rglob("*"),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            os.chmod(member, 0o700 if member.is_dir() else 0o600)
        os.chmod(path, 0o700)
    shutil.rmtree(path)


def _remove_run_directory(path: Path, parent: Path) -> None:
    if path.parent != parent or SAFE_NAME.fullmatch(path.name) is None:
        raise CollectionError("refusing to remove an unexpected run directory")
    if path.exists():
        if path.is_symlink():
            raise CollectionError("run directory became a symlink")
        shutil.rmtree(path)
        _fsync_directory(parent)


def collect_evidence(
    *,
    plan: dict[str, Any],
    plan_payload: bytes,
    evidence_name: str,
    expected_identity: ExpectedIdentity,
    runtime: Any,
    runtime_config_path: Path,
    auth_secret: bytes,
    receipt_secret: bytes,
    auth_api: Any,
    executor: Callable[..., CommandResult],
    release_root: Path,
    verifier_path: Path,
    run_parent: Path = RUN_PARENT,
    evidence_parent: Path = EVIDENCE_PARENT,
    now_factory: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    token_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
    enforce_root: bool = True,
) -> dict[str, Any]:
    validate_plan(plan)
    retained_plan = validate_plan(
        _strict_json_bytes(plan_payload, label="retained Dev251 report read plan")
    )
    if retained_plan != plan:
        raise CollectionError("retained report plan is not the executed plan")
    if SAFE_NAME.fullmatch(evidence_name) is None:
        raise CollectionError("evidence name is invalid")
    runtime_mapping = validate_runtime(
        plan,
        runtime,
        release_root,
        expected_identity=expected_identity,
    )
    if (
        not isinstance(auth_secret, bytes)
        or len(auth_secret) < 32
        or not isinstance(receipt_secret, bytes)
        or len(receipt_secret) < 32
        or auth_secret == receipt_secret
    ):
        raise CollectionError("runtime secrets are invalid or not role-separated")
    _verify_directory(
        run_parent,
        expected_mode=0o700,
        enforce_root=enforce_root,
        create=True,
    )
    _verify_directory(
        evidence_parent,
        expected_mode=0o755,
        enforce_root=enforce_root,
    )
    run_dir = run_parent / evidence_name
    final = evidence_parent / evidence_name
    pending = evidence_parent / f".{evidence_name}.pending"
    if any(path.exists() or path.is_symlink() for path in (run_dir, final, pending)):
        raise CollectionError("evidence run or publication identity already exists")
    run_dir.mkdir(mode=0o700)
    _fsync_directory(run_parent)
    cli = release_root / "bin" / "odoo-accounting-cli-v3"
    oracle = release_root / "deployment" / "dev29" / "read_oracles.py"
    oracle_plan = release_root / "deployment" / "dev29" / "read_plan.json"
    try:
        _write(run_dir / PLAN_BUNDLE_NAME, plan_payload)
        release_result = executor(
            [str(cli), "release", "identity"],
            stdin=None,
            role="odoo",
            timeout=30,
        )
        release_document = _command_document(
            release_result,
            command="release.identity",
            label="release identity",
        )
        if release_document["data"] != expected_identity.as_dict():
            raise CollectionError("executed CLI release identity mismatch")
        _write_json(run_dir / "release-identity.json", release_document)

        readiness_result = executor(
            [str(cli), "evidence", "read-capabilities-readiness"],
            stdin=None,
            role="odoo",
            timeout=30,
        )
        readiness_document = _command_document(
            readiness_result,
            command="evidence.read-capabilities-readiness",
            label="read capabilities readiness",
            allow_business_field=True,
        )
        _validate_targeted_readiness(
            readiness_document,
            expected_identity=expected_identity.as_dict(),
        )
        _write_json(
            run_dir / "read-capabilities-readiness.json",
            readiness_document,
        )

        boundary_result = executor(
            [
                str(cli),
                "evidence",
                "read-boundary",
                "--runtime-config",
                str(runtime_config_path),
                "--timeout-seconds",
                "60",
            ],
            stdin=None,
            role="odoo",
            timeout=90,
        )
        boundary_document = _command_document(
            boundary_result,
            command="evidence.read-boundary",
            label="read boundary",
        )
        _write_json(run_dir / "read-boundary.json", boundary_document)

        witness_command = [
            str(runtime.odoo_python),
            "-I",
            str(oracle),
            "witness",
            "--plan",
            str(oracle_plan),
        ]
        witness_pre = _witness_document(
            executor(
                witness_command,
                stdin=None,
                role="postgres",
                timeout=90,
            ),
            label="pre-read",
        )
        _write_json(run_dir / "witness-pre.json", witness_pre)

        case_summaries: dict[str, Any] = {}
        receipt_ids: set[str] = set()
        token_ids: set[str] = set()
        for case in plan["cases"]:
            issued_at = now_factory()
            if issued_at.tzinfo is None or issued_at.utcoffset() is None:
                raise CollectionError("signing clock is not timezone-aware")
            token_id = f"dev251-{case['name']}-{token_factory()}"
            if token_id in token_ids:
                raise CollectionError("authentication token ID was reused")
            token_ids.add(token_id)
            request = _build_request(
                plan,
                case,
                runtime,
                auth_secret,
                auth_api,
                now=issued_at,
                token_id=token_id,
            )
            case_dir = run_dir / "cases" / case["name"]
            _write_json(case_dir / "request.json", request)
            read_result = executor(
                [
                    str(cli),
                    "read",
                    "--runtime-config",
                    str(runtime_config_path),
                    "--timeout-seconds",
                    "120",
                ],
                stdin=canonical_json(request) + b"\n",
                role="odoo",
                timeout=150,
            )
            response = _command_document(
                read_result,
                command="read",
                label=f"{case['name']} read",
            )
            _write_json(case_dir / "response.json", response)
            _write(case_dir / "stderr", read_result.stderr)
            _write_json(
                case_dir / "exit.json",
                {"command": "read", "returncode": read_result.returncode},
            )
            summary = _case_summary(case, response)
            if summary["receipt_id"] in receipt_ids:
                raise CollectionError("read receipt ID was reused")
            receipt_ids.add(summary["receipt_id"])
            case_summaries[case["name"]] = summary

        witness_post = _witness_document(
            executor(
                witness_command,
                stdin=None,
                role="postgres",
                timeout=90,
            ),
            label="post-read",
        )
        _write_json(run_dir / "witness-post.json", witness_post)
        if witness_post != witness_pre:
            raise CollectionError("independent PostgreSQL witness changed")

        validation = {
            "accounting_correctness_claimed": False,
            "accounting_oracle": plan["accounting_oracle"],
            "all_checks_passed": True,
            "case_results": case_summaries,
            "database_witness_unchanged": True,
            "production_promotion_allowed": False,
            "read_boundary_probe_passed": True,
            "real_odoo_write_performed": False,
            "release_identity": expected_identity.as_dict(),
            "schema_version": 1,
            "scope": VALIDATION_SCOPE,
        }
        _write_json(run_dir / "validation-report.json", validation)
        manifest = {
            "accounting_correctness_claimed": False,
            "accounting_oracle": plan["accounting_oracle"],
            "case_names": list(CASE_NAMES),
            "evidence_name": evidence_name,
            "evidence_path": str(final),
            "files": _file_manifest(run_dir),
            "production_promotion_allowed": False,
            "receipt_ids": {
                name: case_summaries[name]["receipt_id"] for name in CASE_NAMES
            },
            "release_identity": expected_identity.as_dict(),
            "runtime_identity": runtime_mapping,
            "schema_version": 1,
            "scope": BUNDLE_SCOPE,
        }
        _write_json(run_dir / "BUNDLE-MANIFEST.json", manifest)
        _assert_no_secret_leak(run_dir, (auth_secret, receipt_secret))
        _copy_and_seal(run_dir, pending)

        verifier = _load_verifier(verifier_path)
        verifier.verify_evidence(
            pending,
            expected_final_path=final,
            expected_identity=expected_identity.as_dict(),
            runtime=runtime_mapping,
            auth_secret=auth_secret,
            receipt_secret=receipt_secret,
            enforce_root=enforce_root,
        )
        manifest_payload = _read_file(
            pending / "BUNDLE-MANIFEST.json",
            label="verified pending bundle manifest",
        )
        report = {
            "accounting_oracle_available": False,
            "bundle_manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
            "evidence_path": str(final),
            "production_promotion_allowed": False,
            "reconcile_required": False,
            "receipt_ids": manifest["receipt_ids"],
            "release_identity": expected_identity.as_dict(),
            "safe_to_rerun": False,
            "status": "publication_confirmed",
        }
        _remove_run_directory(run_dir, run_parent)
        _rename_noreplace(pending, final)
        return report
    except PublicationOutcomeUnknown:
        raise
    except BaseException:
        if pending.exists() and not pending.is_symlink():
            _discard_pending_directory(pending)
            _fsync_directory(evidence_parent)
        raise


def reconcile_evidence(
    *,
    plan: dict[str, Any],
    evidence_name: str,
    expected_identity: ExpectedIdentity,
    runtime: Any,
    auth_secret: bytes,
    receipt_secret: bytes,
    release_root: Path,
    verifier_path: Path,
    run_parent: Path = RUN_PARENT,
    evidence_parent: Path = EVIDENCE_PARENT,
    enforce_root: bool = True,
) -> dict[str, Any]:
    validate_plan(plan)
    if SAFE_NAME.fullmatch(evidence_name) is None:
        raise CollectionError("evidence name is invalid")
    runtime_mapping = validate_runtime(
        plan,
        runtime,
        release_root,
        expected_identity=expected_identity,
    )
    if (
        not isinstance(auth_secret, bytes)
        or len(auth_secret) < 32
        or not isinstance(receipt_secret, bytes)
        or len(receipt_secret) < 32
        or auth_secret == receipt_secret
    ):
        raise CollectionError("runtime secrets are invalid or not role-separated")
    _verify_directory(
        run_parent,
        expected_mode=0o700,
        enforce_root=enforce_root,
        create=True,
    )
    _verify_directory(
        evidence_parent,
        expected_mode=0o755,
        enforce_root=enforce_root,
    )
    final = evidence_parent / evidence_name
    pending = evidence_parent / f".{evidence_name}.pending"
    run_dir = run_parent / evidence_name
    if pending.exists() or pending.is_symlink() or run_dir.exists() or run_dir.is_symlink():
        raise CollectionError("publication cannot be reconciled with staging remnants")
    if not final.is_dir() or final.is_symlink():
        raise CollectionError("published evidence is unavailable for reconciliation")
    try:
        verifier = _load_verifier(verifier_path)
        verified = verifier.verify_evidence(
            final,
            expected_final_path=final,
            expected_identity=expected_identity.as_dict(),
            runtime=runtime_mapping,
            auth_secret=auth_secret,
            receipt_secret=receipt_secret,
            enforce_root=enforce_root,
        )
    except Exception as exc:
        raise CollectionError(
            "published evidence failed independent reconciliation"
        ) from exc
    try:
        _fsync_directory(evidence_parent)
    except OSError as exc:
        raise PublicationOutcomeUnknown(final) from exc
    return {
        **verified,
        "reconcile_required": False,
        "safe_to_rerun": False,
        "status": "publication_confirmed_after_reconcile",
    }


def _drop_privileges(user_name: str) -> Callable[[], None]:
    if pwd is None:
        raise CollectionError("POSIX password database support is unavailable")
    try:
        identity = pwd.getpwnam(user_name)
    except KeyError as exc:
        raise CollectionError(f"required service identity is absent: {user_name}") from exc

    def demote() -> None:
        os.umask(0o077)
        os.setgroups([])
        os.setgid(identity.pw_gid)
        os.setuid(identity.pw_uid)

    return demote


def subprocess_executor(
    command: list[str],
    *,
    stdin: bytes | None,
    role: str,
    timeout: int,
) -> CommandResult:
    if os.name != "posix" or os.geteuid() != 0:
        raise CollectionError("production evidence collection requires root on POSIX")
    user_name = {"odoo": "odoo", "postgres": "postgres"}.get(role)
    if user_name is None:
        raise CollectionError("child execution role is invalid")
    environment = {
        "HOME": (
            "/var/lib/odoo-accounting-cli-v3-broker"
            if role == "odoo"
            else "/var/lib/postgresql"
        ),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }
    try:
        completed = subprocess.run(
            command,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            cwd="/",
            env=environment,
            preexec_fn=_drop_privileges(user_name),
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectionError("evidence child execution failed") from exc
    if (
        len(completed.stdout) > MAX_JSON_BYTES
        or len(completed.stderr) > MAX_STDERR_BYTES
    ):
        raise CollectionError("evidence child output exceeded its boundary")
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _load_release_modules(release_root: Path) -> tuple[Any, Any]:
    source_root = release_root / "src"
    if not source_root.is_dir() or source_root.is_symlink():
        raise CollectionError("release source root is unavailable")
    sys.path.insert(0, str(source_root))
    try:
        from odoo_accounting_cli_v3 import auth
        from odoo_accounting_cli_v3.odoo import runner
    except Exception as exc:
        raise CollectionError("exact-release signing modules cannot be loaded") from exc
    for module in (auth, runner):
        module_path = Path(module.__file__).resolve(strict=True)
        try:
            module_path.relative_to(source_root.resolve(strict=True))
        except ValueError as exc:
            raise CollectionError("signing module escaped the exact release") from exc
    return auth, runner


def _sealed_release_root() -> Path:
    script = Path(os.path.abspath(__file__))
    if script.is_symlink() or script.resolve(strict=True) != script:
        raise CollectionError("collector must run from a canonical sealed release")
    metadata = script.lstat()
    release_root = script.parents[2]
    if (
        release_root.parent != RELEASE_PARENT
        or os.name != "posix"
        or os.geteuid() != 0
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or metadata.st_nlink != 1
    ):
        raise CollectionError("collector is not a sealed root-owned release member")
    return release_root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-name", required=True)
    parser.add_argument(
        "--reconcile",
        action="store_true",
        help=(
            "verify and confirm durability of an already-renamed evidence "
            "bundle without repeating Odoo reads"
        ),
    )
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
        expected = ExpectedIdentity(
            release=arguments.expected_release,
            version=arguments.expected_version,
            commit=arguments.expected_commit,
            manifest_sha256=arguments.expected_manifest_sha256,
            package_sha256=arguments.expected_package_sha256,
            registry_digest=arguments.expected_registry_digest,
        )
        release_root = _sealed_release_root()
        if release_root.name != expected.release:
            raise CollectionError("collector release name mismatch")
        plan_path = Path(__file__).with_name(PLAN_NAME)
        plan_payload = _read_file(plan_path, label="Dev251 report read plan")
        plan = validate_plan(_strict_json_bytes(plan_payload, label="Dev251 plan"))
        auth_api, runner = _load_release_modules(release_root)
        runtime = runner.load_runtime_config(arguments.runtime_config)
        runtime_mapping = validate_runtime(
            plan,
            runtime,
            release_root,
            expected_identity=expected,
        )
        if Path(runtime_mapping["release_root"]).name != expected.release:
            raise CollectionError("runtime release name mismatch")
        auth_secret, receipt_secret = runner.load_runtime_secrets(runtime)
        if arguments.reconcile:
            report = reconcile_evidence(
                plan=plan,
                evidence_name=arguments.evidence_name,
                expected_identity=expected,
                runtime=runtime,
                auth_secret=auth_secret,
                receipt_secret=receipt_secret,
                release_root=release_root,
                verifier_path=Path(__file__).with_name(VERIFIER_NAME),
            )
        else:
            report = collect_evidence(
                plan=plan,
                plan_payload=plan_payload,
                evidence_name=arguments.evidence_name,
                expected_identity=expected,
                runtime=runtime,
                runtime_config_path=arguments.runtime_config,
                auth_secret=auth_secret,
                receipt_secret=receipt_secret,
                auth_api=auth_api,
                executor=subprocess_executor,
                release_root=release_root,
                verifier_path=Path(__file__).with_name(VERIFIER_NAME),
            )
        sys.stdout.buffer.write(canonical_json(report) + b"\n")
        return 0
    except PublicationOutcomeUnknown as exc:
        outcome = {
            "accounting_oracle_available": False,
            "evidence_path": str(exc.evidence_path),
            "production_promotion_allowed": False,
            "reconcile_required": True,
            "safe_to_rerun": False,
            "status": "publication_outcome_unknown",
        }
        sys.stdout.buffer.write(canonical_json(outcome) + b"\n")
        sys.stderr.write(
            "dev251_report_read_publication_outcome_unknown: "
            "run --reconcile; do not repeat collection\n"
        )
        return 3
    except CollectionError as exc:
        sys.stderr.write(f"dev251_report_read_collection_failed: {exc}\n")
        return 2
    except Exception:
        sys.stderr.write("dev251_report_read_collection_failed: unexpected failure\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

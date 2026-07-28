"""Installable, JSON-oriented command line boundary for the V3 gateway."""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from importlib import resources, util
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

import click

from . import __version__
from .auth import authentication_request_digest
from .contracts import ContractError, validate_value
from .effect_finalizer import (
    EffectFinalizationError,
    validate_effect_finalization_evidence_shape,
)
from .odoo.runner import (
    READ_REJECTION_CODES,
    OdooRunnerError,
    RuntimeConfig,
    load_runtime_config,
    load_runtime_secrets,
    require_staged_test_evidence_runtime,
    run_read_boundary_evidence,
    run_odoo_shell,
)
from .receipts import ReceiptError, verify_read_receipt
from .registry import Capability, load_registry, registry_digest, validate_registry
from .release import ReleaseError, verify_manifest
from .write_api import WriteApiError, parse_write_api_request
from .write_runtime import (
    WRITE_ROLE_NAMES,
    WRITE_RUNTIME_SCHEMA_VERSION,
    WriteRuntimeError,
    load_write_runtime_config,
)
from .write_receipts import RECEIPT_FIELDS, WRITE_RECEIPT_PURPOSE


DEFAULT_WRITE_RUNTIME_CONFIG = Path("/etc/odoo-accounting-cli-v3/write-runtime.json")
DEFAULT_SANDBOX_SECRET_ROOT = Path("/etc/odoo-accounting-cli-v3/secrets/sandbox")
DEFAULT_SANDBOX_WRITE_STATE = Path(
    "/var/lib/odoo-accounting-cli-v3/sandbox/write.sqlite3"
)
DEFAULT_SANDBOX_READ_STATE_ROOT = Path("/var/lib/odoo-accounting-cli-v3/sandbox/read")
DEFAULT_SANDBOX_READ_SECRET_ROOT = Path("/etc/odoo-accounting-cli-v3/secrets/sandbox")


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _looks_like_placeholder_sha256(value: str) -> bool:
    return (
        len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
        and len(set(value)) == 1
    )


def _database_name_is_clear_sandbox(name: str) -> bool:
    return re.search(r"(^|[_-])sandbox([_-]|$)", name) is not None


def _database_name_looks_transient(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.startswith("codex_")
        or re.search(r"(^|[_-])(demo|debug|runtime|candidate|upgrade|test)([_-]|$)", lowered)
        is not None
    )


def _sandbox_onboarding_receipt_report(
    onboarding_receipt: Path | None,
    *,
    command: str,
    expected_database_name: str | None = None,
    expected_release_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    blockers: list[str] = []
    digest: str | None = None
    payload: dict[str, Any] | None = None
    if onboarding_receipt is None:
        blockers.append("sandbox onboarding readiness receipt was not supplied")
    else:
        try:
            raw = onboarding_receipt.read_bytes()
            digest = _sha256_bytes(raw)
            loaded = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CliFailure(
                command=command,
                code="sandbox_onboarding_receipt_rejected",
                message="The sandbox onboarding readiness receipt is unavailable or invalid JSON.",
                exit_code=5,
            ) from exc
        if not isinstance(loaded, dict):
            blockers.append("sandbox onboarding readiness receipt is not a JSON object")
        else:
            payload = loaded
            data = loaded.get("data")
            if loaded.get("ok") is not True:
                blockers.append("sandbox onboarding readiness receipt is not successful")
            if loaded.get("command") != "evidence.sandbox-onboarding-readiness":
                blockers.append("sandbox onboarding readiness receipt has the wrong command")
            if not isinstance(data, dict):
                blockers.append("sandbox onboarding readiness receipt data is invalid")
            else:
                route = data.get("route")
                capacity = data.get("capacity")
                database = data.get("database")
                authorization = data.get("authorization")
                if data.get("sandbox_onboarding_ready") is not True:
                    blockers.append("sandbox onboarding readiness receipt is not ready")
                if data.get("real_odoo_write_performed") is not False:
                    blockers.append("sandbox onboarding receipt must be read-only")
                if data.get("postgresql_write_performed") is not False:
                    blockers.append("sandbox onboarding receipt must not perform PostgreSQL writes")
                if not isinstance(route, dict) or route.get("current_route_ready") is not True:
                    blockers.append("sandbox onboarding current route is not ready")
                if not isinstance(capacity, dict) or capacity.get("sandbox_write_capacity_ready") is not True:
                    blockers.append("sandbox onboarding capacity gate is not ready")
                if not isinstance(database, dict) or database.get("sandbox_database_observed") is not True:
                    blockers.append("sandbox onboarding database gate is not ready")
                if (
                    not isinstance(authorization, dict)
                    or authorization.get("authorization_record_ready") is not True
                ):
                    blockers.append("sandbox onboarding authorization gate is not ready")
                if (
                    expected_database_name is not None
                    and isinstance(database, dict)
                    and database.get("sandbox_database_name") != expected_database_name
                ):
                    blockers.append("sandbox onboarding database does not match write runtime")
                if expected_release_identity is not None and isinstance(route, dict):
                    route_identity = route.get("route_identity")
                    if not isinstance(route_identity, dict):
                        blockers.append("sandbox onboarding route identity is invalid")
                    else:
                        expected_pairs = {
                            "commit": expected_release_identity.get("commit"),
                            "manifest_sha256": expected_release_identity.get("manifest_sha256"),
                            "package_sha256": expected_release_identity.get("package_sha256"),
                            "registry_digest": expected_release_identity.get("registry_digest"),
                            "release": expected_release_identity.get("release"),
                        }
                        for field, expected in expected_pairs.items():
                            if expected is not None and route_identity.get(field) != expected:
                                blockers.append(
                                    f"sandbox onboarding route {field} does not match write runtime release"
                                )
    data = None if payload is None else payload.get("data")
    route = data.get("route") if isinstance(data, dict) else None
    database = data.get("database") if isinstance(data, dict) else None
    return {
        "blockers": sorted(set(blockers)),
        "path": str(onboarding_receipt) if onboarding_receipt is not None else None,
        "ready": not blockers,
        "receipt_sha256": digest,
        "route_identity": route.get("route_identity") if isinstance(route, dict) else None,
        "sandbox_database_name": (
            database.get("sandbox_database_name") if isinstance(database, dict) else None
        ),
    }


def _database_name_looks_production(name: str) -> bool:
    lowered = name.lower()
    return re.search(r"(^|[_-])(prod|production|live|sg)([_-]|$)", lowered) is not None


def _sandbox_database_candidate_report(
    name: str,
    *,
    protected_names: frozenset[str],
    selected_name: str | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    if not name:
        blockers.append("database name is empty")
    if name in protected_names:
        blockers.append("database name is explicitly protected")
    if not _database_name_is_clear_sandbox(name):
        blockers.append("database name is not clearly sandbox")
    if _database_name_looks_production(name):
        blockers.append("database name looks production-like")
    if _database_name_looks_transient(name):
        blockers.append("database name looks transient or test-generated")
    if selected_name is not None and name == selected_name:
        warnings.append("selected by operator input")
    return {
        "blockers": sorted(set(blockers)),
        "eligible_for_sandbox_runtime_plan": not blockers,
        "name": name,
        "warnings": sorted(set(warnings)),
    }


def _expected_sandbox_database_filter(database_name: str) -> str:
    return f"^{re.escape(database_name)}$"


def _parse_utc_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty UTC timestamp")
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{field} must be a UTC timestamp")
    return parsed.astimezone(timezone.utc)


def _format_utc_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _success(
    command: str,
    data: dict[str, Any],
    *,
    business_succeeded: bool | None = None,
) -> None:
    response: dict[str, Any] = {"command": command, "data": data, "ok": True}
    if business_succeeded is not None:
        response["business_succeeded"] = business_succeeded
    click.echo(_json(response))


class CliFailure(click.ClickException):
    """A stable machine-readable CLI failure."""

    def __init__(
        self,
        *,
        command: str,
        code: str,
        message: str,
        exit_code: int = 2,
        retryable: bool = False,
        odoo_effect: str | None = None,
        operation_id: str | None = None,
        state: str | None = None,
        rejection_code: str | None = None,
    ) -> None:
        super().__init__(message)
        if odoo_effect not in {None, "none", "unknown"}:
            raise ValueError("odoo_effect must be none or unknown")
        if rejection_code is not None and rejection_code not in READ_REJECTION_CODES:
            raise ValueError("read rejection code is not allowlisted")
        self.command = command
        self.code = code
        self.exit_code = exit_code
        self.retryable = retryable
        self.odoo_effect = odoo_effect
        self.operation_id = operation_id
        self.state = state
        self.rejection_code = rejection_code

    def show(self, file: Any | None = None) -> None:
        stream = file if file is not None else click.get_text_stream("stderr")
        if self.odoo_effect is None:
            error: dict[str, Any] = {
                "code": self.code,
                "message": self.message,
                "odoo_action_performed": False,
                "retryable": self.retryable,
            }
            if self.rejection_code is not None:
                error["rejection_code"] = self.rejection_code
        else:
            error = {
                "code": self.code,
                "message": self.message,
                "odoo_effect": self.odoo_effect,
                "retryable": self.retryable,
            }
            if self.operation_id is not None:
                error["operation_id"] = self.operation_id
            if self.state is not None:
                error["state"] = self.state
        click.echo(
            _json({"command": self.command, "error": error, "ok": False}),
            file=stream,
        )


def _load_capabilities() -> tuple[Capability, ...]:
    packaged = resources.files("odoo_accounting_cli_v3").joinpath("data", "capabilities.json")
    if packaged.is_file():
        with packaged.open(encoding="utf-8") as stream:
            return validate_registry(json.load(stream))

    # Source-tree fallback for an editable checkout. Built wheels always use the
    # packaged copy above, so an installed CLI does not depend on its cwd.
    source_registry = Path(__file__).resolve().parents[2] / "registry" / "capabilities.json"
    if source_registry.is_file():
        return load_registry(source_registry)
    raise CliFailure(
        command="registry.load",
        code="registry_unavailable",
        message="The validated capability registry is not present in this installation.",
        exit_code=4,
    )


def _count_values(values: list[str], expected: tuple[str, ...] = ()) -> dict[str, int]:
    counts = {key: 0 for key in expected}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _is_strict_object_schema(schema: Any) -> bool:
    return (
        isinstance(schema, dict)
        and schema.get("type") == "object"
        and schema.get("additionalProperties") is False
        and isinstance(schema.get("properties"), dict)
    )


def _registry_audit_report(capabilities: tuple[Capability, ...]) -> dict[str, Any]:
    items = sorted((capability.data for capability in capabilities), key=lambda item: item["id"])
    capability_ids = [item["id"] for item in items]
    write_items = [item for item in items if item["access"] == "write"]
    read_items = [item for item in items if item["access"] == "read"]
    strict_input_ids = [
        item["id"] for item in items if _is_strict_object_schema(item["input_schema"])
    ]
    strict_output_ids = [
        item["id"] for item in items if _is_strict_object_schema(item["output_schema"])
    ]
    write_approval_ids = [
        item["id"] for item in write_items if item["approval"].get("required") is True
    ]
    write_idempotency_ids = [
        item["id"] for item in write_items if item["idempotency"].get("required") is True
    ]
    read_approval_closed_ids = [
        item["id"] for item in read_items if item["approval"].get("required") is False
    ]
    read_idempotency_closed_ids = [
        item["id"] for item in read_items if item["idempotency"].get("required") is False
    ]
    enabled_by_environment = {
        environment: sorted(
            item["id"]
            for item in items
            if environment in item.get("enabled_environments", [])
        )
        for environment in ("test", "sandbox", "production")
    }
    staged_by_environment = {
        environment: sorted(
            item["id"]
            for item in items
            if environment in item.get("staged_environments", [])
        )
        for environment in ("test", "sandbox", "production")
    }
    blockers: list[str] = []
    if len(strict_input_ids) != len(items):
        blockers.append("not every capability has a strict object input schema")
    if len(strict_output_ids) != len(items):
        blockers.append("not every capability has a strict object output schema")
    if len(write_approval_ids) != len(write_items):
        blockers.append("not every write capability requires approval")
    if len(write_idempotency_ids) != len(write_items):
        blockers.append("not every write capability requires idempotency")
    if len(read_approval_closed_ids) != len(read_items):
        blockers.append("not every read capability keeps approval disabled")
    if len(read_idempotency_closed_ids) != len(read_items):
        blockers.append("not every read capability keeps idempotency disabled")
    if enabled_by_environment["production"]:
        blockers.append("one or more capabilities are enabled in production")
    if any(item["id"] in staged_by_environment["sandbox"] for item in write_items):
        blockers.append("one or more write capabilities are staged in sandbox")
    return {
        "access_counts": _count_values(
            [item["access"] for item in items],
            ("read", "write"),
        ),
        "blockers": sorted(set(blockers)),
        "capability_ids": capability_ids,
        "enabled_by_environment": enabled_by_environment,
        "enabled_environment_counts": {
            environment: len(ids) for environment, ids in enabled_by_environment.items()
        },
        "evidence_level_counts": _count_values(
            [item["evidence"]["level"] for item in items],
            (
                "contract_tested",
                "declared",
                "odoo_verified",
                "sandbox_verified",
                "production_verified",
            ),
        ),
        "policy_counts": {
            "read_approval_disabled": len(read_approval_closed_ids),
            "read_idempotency_disabled": len(read_idempotency_closed_ids),
            "write_approval_required": len(write_approval_ids),
            "write_idempotency_required": len(write_idempotency_ids),
        },
        "production_promotion_allowed": False,
        "read_count": len(read_items),
        "real_odoo_write_performed": False,
        "registry_audit_ready": not blockers,
        "registry_digest": registry_digest(capabilities),
        "risk_level_counts": _count_values(
            [item["risk_level"] for item in items],
            ("critical", "high", "low", "medium"),
        ),
        "staged_by_environment": staged_by_environment,
        "staged_environment_counts": {
            environment: len(ids) for environment, ids in staged_by_environment.items()
        },
        "strict_schema": {
            "input_strict_count": len(strict_input_ids),
            "input_strict_ids": strict_input_ids,
            "output_strict_count": len(strict_output_ids),
            "output_strict_ids": strict_output_ids,
        },
        "total_count": len(items),
        "write_count": len(write_items),
    }


def _load_retained_json_report(path: Path, *, command: str, label: str) -> dict[str, Any]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message=f"The retained {label} report is unavailable or invalid JSON.",
            exit_code=5,
        ) from exc
    if not isinstance(loaded, dict):
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message=f"The retained {label} report must be a JSON object.",
            exit_code=5,
        )
    return loaded


def _pi_scenario_acceptance_report_status(
    pi_scenario_report: Path | None,
    *,
    command: str,
    expected_release_identity: dict[str, Any],
) -> dict[str, Any]:
    blockers: list[str] = []
    if pi_scenario_report is None:
        blockers.append("Pi scenario acceptance report was not supplied")
        return {
            "blockers": blockers,
            "report_path": None,
            "report_sha256": None,
            "scenario_acceptance_ready": False,
            "summary": None,
        }
    try:
        raw = pi_scenario_report.read_bytes()
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message="The retained Pi scenario acceptance report is unavailable.",
            exit_code=5,
        ) from exc
    report = _load_retained_json_report(
        pi_scenario_report, command=command, label="Pi scenario acceptance"
    )
    gates = report.get("gates")
    coverage = report.get("trace_coverage")
    capture = report.get("capture")
    required_gates = ("F01", "F02", "F03", "F05")
    if report.get("schema_version") != "odoo-accounting-cli-v3.pi-gate-report.v1":
        blockers.append("Pi scenario report has the wrong schema")
    if report.get("acceptance_passed") is not True:
        blockers.append("Pi scenario report did not pass acceptance")
    if not isinstance(capture, dict):
        blockers.append("Pi scenario capture summary is invalid")
    elif capture.get("v3_release_sha256") != expected_release_identity.get("package_sha256"):
        blockers.append("Pi scenario report is not bound to the current release package")
    if not isinstance(coverage, dict) or coverage.get("passed") is not True:
        blockers.append("Pi scenario trace coverage did not pass")
    if not isinstance(gates, dict):
        blockers.append("Pi scenario gate summary is invalid")
        gate_summary = None
    else:
        gate_summary = {
            gate_id: gates.get(gate_id)
            for gate_id in required_gates
            if isinstance(gates.get(gate_id), dict)
        }
        for gate_id in required_gates:
            gate = gates.get(gate_id)
            if not isinstance(gate, dict) or gate.get("passed") is not True:
                blockers.append(f"Pi scenario gate {gate_id} did not pass")
    return {
        "blockers": sorted(set(blockers)),
        "report_path": str(pi_scenario_report),
        "report_sha256": _sha256_bytes(raw),
        "scenario_acceptance_ready": not blockers,
        "summary": {
            "acceptance_passed": report.get("acceptance_passed"),
            "capture": capture,
            "coverage": coverage,
            "gates": gate_summary,
            "run_id": report.get("run_id"),
        },
    }


def _write_pipeline_report_status(
    write_pipeline_report: Path | None,
    *,
    command: str,
    expected_release_identity: dict[str, Any],
) -> dict[str, Any]:
    blockers: list[str] = []
    if write_pipeline_report is None:
        blockers.append("sandbox write pipeline readiness report was not supplied")
        return {
            "blockers": blockers,
            "report_path": None,
            "report_sha256": None,
            "summary": None,
            "write_pipeline_ready": False,
        }
    try:
        raw = write_pipeline_report.read_bytes()
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message="The retained sandbox write pipeline report is unavailable.",
            exit_code=5,
        ) from exc
    report = _load_retained_json_report(
        write_pipeline_report, command=command, label="sandbox write pipeline"
    )
    data = report.get("data")
    if report.get("ok") is not True:
        blockers.append("sandbox write pipeline report is not successful")
    if report.get("command") != "evidence.write-pipeline-readiness":
        blockers.append("sandbox write pipeline report has the wrong command")
    if not isinstance(data, dict):
        blockers.append("sandbox write pipeline report data is invalid")
        summary = None
    else:
        release = data.get("release_identity")
        if data.get("sandbox_pipeline_ready") is not True:
            blockers.append("sandbox write pipeline is not ready")
        for field, expected in expected_release_identity.items():
            if (
                expected is not None
                and isinstance(release, dict)
                and release.get(field) != expected
            ):
                blockers.append(f"sandbox write pipeline release {field} mismatch")
        summary = {
            "evidence_root": data.get("evidence_root"),
            "missing_count": data.get("missing_count"),
            "rejected_count": data.get("rejected_count"),
            "sandbox_pipeline_ready": data.get("sandbox_pipeline_ready"),
            "total_write_capabilities": data.get("total_write_capabilities"),
            "verified_count": data.get("verified_count"),
        }
    return {
        "blockers": sorted(set(blockers)),
        "report_path": str(write_pipeline_report),
        "report_sha256": _sha256_bytes(raw),
        "summary": summary,
        "write_pipeline_ready": not blockers,
    }


def _write_evidence_index_status(
    write_evidence_index: Path | None,
    *,
    command: str,
    expected_release_identity: dict[str, Any],
    pipeline_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    if write_evidence_index is None:
        return {
            "blockers": [],
            "index_path": None,
            "index_ready": None,
            "index_sha256": None,
            "supplied": False,
            "summary": None,
        }
    try:
        raw = write_evidence_index.read_bytes()
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message="The retained sandbox write evidence index is unavailable.",
            exit_code=5,
        ) from exc
    report = _load_retained_json_report(
        write_evidence_index, command=command, label="sandbox write evidence index"
    )
    data = report.get("data")
    if report.get("ok") is not True:
        blockers.append("sandbox write evidence index is not successful")
    if report.get("command") != "evidence.write-evidence-index":
        blockers.append("sandbox write evidence index has the wrong command")
    if not isinstance(data, dict):
        blockers.append("sandbox write evidence index data is invalid")
        summary = None
    else:
        release = data.get("release_identity")
        if data.get("index_kind") != "odoo-accounting-cli-v3.sandbox-write-evidence-index.v1":
            blockers.append("sandbox write evidence index has the wrong kind")
        if data.get("sandbox_pipeline_ready") is not True:
            blockers.append("sandbox write evidence index is not ready")
        for field, expected in expected_release_identity.items():
            if (
                expected is not None
                and isinstance(release, dict)
                and release.get(field) != expected
            ):
                blockers.append(f"sandbox write evidence index release {field} mismatch")
        summary = {
            "evidence_root": data.get("evidence_root"),
            "missing_count": data.get("missing_count"),
            "rejected_count": data.get("rejected_count"),
            "sandbox_pipeline_ready": data.get("sandbox_pipeline_ready"),
            "total_write_capabilities": data.get("total_write_capabilities"),
            "verified_count": data.get("verified_count"),
        }
        if pipeline_summary is not None:
            for field in (
                "evidence_root",
                "missing_count",
                "rejected_count",
                "sandbox_pipeline_ready",
                "total_write_capabilities",
                "verified_count",
            ):
                if summary.get(field) != pipeline_summary.get(field):
                    blockers.append(
                        f"sandbox write evidence index {field} does not match pipeline report"
                    )
    return {
        "blockers": sorted(set(blockers)),
        "index_path": str(write_evidence_index),
        "index_ready": not blockers,
        "index_sha256": _sha256_bytes(raw),
        "supplied": True,
        "summary": summary,
    }


FINAL_EVIDENCE_MANIFEST_SCHEMA = "odoo-accounting-cli-v3.final-evidence-manifest.v1"
FINAL_EVIDENCE_ARTIFACT_COMMANDS = {
    "goal_readiness_report": "evidence.goal-readiness",
    "pi_scenario_report_check": "evidence.pi-scenario-report-check",
    "pi_trace_capture_check": "evidence.pi-trace-capture-check",
    "sandbox_onboarding_receipt": "evidence.sandbox-onboarding-readiness",
    "write_evidence_index": "evidence.write-evidence-index",
    "write_pipeline_report": "evidence.write-pipeline-readiness",
}
FINAL_EVIDENCE_REQUIRED_ARTIFACTS = tuple(
    sorted(
        {
            *FINAL_EVIDENCE_ARTIFACT_COMMANDS,
            "pi_scenario_report",
            "sandbox_provision_authorization",
        }
    )
)


GOAL_REMEDIATION_SCHEMA = "odoo-accounting-cli-v3.goal-remediation-checklist.v1"
GOAL_REMEDIATION_ACTIONS = (
    {
        "action_id": "pi_scenario_acceptance",
        "blocker_patterns": ("Pi scenario",),
        "description": "Capture and score real Pi Agent end-to-end traces for the routed release.",
        "required_artifacts": (
            "pi_trace_capture_check",
            "pi_scenario_report",
            "pi_scenario_report_check",
        ),
        "operator_command": "evidence pi-trace-capture-check; tools/pi_scenario_gate.py; evidence pi-scenario-report-check",
        "authorization_required": False,
    },
    {
        "action_id": "sandbox_capacity",
        "blocker_patterns": ("capacity", "free space"),
        "description": "Add, relocate, or explicitly authorize reviewed cleanup until the sandbox capacity floor passes.",
        "required_artifacts": (
            "target_capacity_plan",
            "target_capacity_recheck",
        ),
        "operator_command": "evidence target-capacity-plan; evidence target-capacity-recheck",
        "authorization_required": True,
    },
    {
        "action_id": "sandbox_database_catalog",
        "blocker_patterns": ("sandbox database", "database catalog"),
        "description": "Create or select the dedicated sandbox database and retain catalog evidence for that exact name.",
        "required_artifacts": (
            "sandbox_database_candidates",
            "sandbox_database_catalog_observation",
        ),
        "operator_command": "evidence sandbox-database-candidates",
        "authorization_required": True,
    },
    {
        "action_id": "sandbox_provision_authorization",
        "blocker_patterns": ("sandbox provision authorization", "authorization file"),
        "description": "Save and validate the sandbox database provisioning authorization record.",
        "required_artifacts": (
            "sandbox_provision_authorization",
            "sandbox_provision_authorization_check",
        ),
        "operator_command": "evidence sandbox-provision-authorization-template; evidence sandbox-provision-authorization-check",
        "authorization_required": True,
    },
    {
        "action_id": "sandbox_onboarding_receipt",
        "blocker_patterns": ("sandbox onboarding",),
        "description": "Rerun the aggregate sandbox onboarding gate after route, capacity, database, and authorization evidence pass.",
        "required_artifacts": (
            "sandbox_onboarding_receipt",
            "sandbox_onboarding_receipt_check",
        ),
        "operator_command": "evidence sandbox-onboarding-readiness; evidence sandbox-onboarding-receipt-check",
        "authorization_required": False,
    },
    {
        "action_id": "sandbox_write_pipeline",
        "blocker_patterns": ("write pipeline", "write evidence index"),
        "description": "Collect real sandbox write lifecycle evidence for every registered write capability, then validate the pipeline.",
        "required_artifacts": (
            "write_pipeline_report",
            "write_evidence_index",
        ),
        "operator_command": "evidence write-pipeline-readiness; evidence write-evidence-index",
        "authorization_required": True,
    },
)


def _manifest_artifact_reference(manifest_path: Path, artifact_path: Path) -> str:
    try:
        return artifact_path.resolve().relative_to(manifest_path.parent.resolve()).as_posix()
    except ValueError:
        return str(artifact_path)


def _manifest_artifact_path(manifest_path: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    return manifest_path.parent / path


def _goal_remediation_report(
    goal_readiness_report: Path,
    *,
    command: str,
    expected_release_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    retained = _load_retained_json_report(
        goal_readiness_report, command=command, label="goal readiness"
    )
    data = retained.get("data")
    blockers: list[str] = []
    if retained.get("ok") is not True:
        blockers.append("goal-readiness report is not successful")
    if retained.get("command") != "evidence.goal-readiness":
        blockers.append("goal-readiness report has the wrong command")
    if not isinstance(data, dict):
        blockers.append("goal-readiness report data is invalid")
        data = {}
    goal_blockers = data.get("blockers") if isinstance(data, dict) else None
    if not isinstance(goal_blockers, list) or any(
        not isinstance(item, str) for item in goal_blockers
    ):
        blockers.append("goal-readiness blockers are invalid")
        goal_blockers = []
    release_identity = data.get("release_identity") if isinstance(data, dict) else None
    if not isinstance(release_identity, dict):
        if expected_release_identity is not None:
            blockers.append("goal-readiness release identity is invalid")
        release_identity = None
    elif expected_release_identity is not None:
        for field, expected in expected_release_identity.items():
            if expected is not None and release_identity.get(field) != expected:
                blockers.append(f"goal-readiness release {field} mismatch")
    goal_ready = data.get("goal_readiness_ready") is True if isinstance(data, dict) else False
    actions = []
    for template in GOAL_REMEDIATION_ACTIONS:
        matching = sorted(
            {
                blocker
                for blocker in goal_blockers
                if any(pattern in blocker for pattern in template["blocker_patterns"])
            }
        )
        if not matching:
            continue
        actions.append(
            {
                "action_id": template["action_id"],
                "authorization_required": template["authorization_required"],
                "blocking_evidence": matching,
                "description": template["description"],
                "operator_command": template["operator_command"],
                "production_promotion_allowed": False,
                "real_odoo_write_performed": False,
                "required_artifacts": list(template["required_artifacts"]),
                "status": "pending",
            }
        )
    unmatched_blockers = sorted(
        set(goal_blockers)
        - {
            blocker
            for action in actions
            for blocker in action["blocking_evidence"]
        }
    )
    return {
        "actions": actions,
        "blockers": sorted(set(blockers)),
        "goal_blockers": sorted(set(goal_blockers)),
        "goal_readiness_ready": goal_ready and not blockers,
        "goal_readiness_report": str(goal_readiness_report),
        "goal_readiness_report_sha256": _sha256_file(goal_readiness_report),
        "ordered_action_count": len(actions),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "release_identity": release_identity,
        "schema_version": GOAL_REMEDIATION_SCHEMA,
        "unmatched_blockers": unmatched_blockers,
    }


def _final_evidence_manifest_document(
    artifact_paths: dict[str, Path],
    *,
    manifest_path: Path,
    release_identity: dict[str, Any],
) -> dict[str, Any]:
    return {
        "artifact_sha256": {
            name: _sha256_file(artifact_paths[name])
            for name in FINAL_EVIDENCE_REQUIRED_ARTIFACTS
        },
        "artifacts": {
            name: _manifest_artifact_reference(manifest_path, artifact_paths[name])
            for name in FINAL_EVIDENCE_REQUIRED_ARTIFACTS
        },
        "release_identity": {
            field: release_identity[field]
            for field in (
                "commit",
                "manifest_sha256",
                "package_sha256",
                "registry_digest",
                "release",
            )
        },
        "schema_version": FINAL_EVIDENCE_MANIFEST_SCHEMA,
    }


def _final_evidence_manifest_report(
    manifest_path: Path,
    *,
    command: str,
    expected_release_identity: dict[str, Any],
) -> dict[str, Any]:
    blockers: list[str] = []
    try:
        manifest = _load_retained_json_report(
            manifest_path, command=command, label="final evidence manifest"
        )
    except CliFailure:
        raise
    artifacts = manifest.get("artifacts")
    artifact_sha256 = manifest.get("artifact_sha256")
    release_identity = manifest.get("release_identity")
    if manifest.get("schema_version") != FINAL_EVIDENCE_MANIFEST_SCHEMA:
        blockers.append("final evidence manifest has the wrong schema")
    if not isinstance(release_identity, dict):
        blockers.append("final evidence manifest release_identity is invalid")
    else:
        for field, expected in expected_release_identity.items():
            if expected is not None and release_identity.get(field) != expected:
                blockers.append(f"final evidence manifest release {field} mismatch")
    if not isinstance(artifacts, dict):
        blockers.append("final evidence manifest artifacts are invalid")
        artifacts = {}
    if not isinstance(artifact_sha256, dict):
        blockers.append("final evidence manifest artifact_sha256 is invalid")
        artifact_sha256 = {}
    missing = sorted(set(FINAL_EVIDENCE_REQUIRED_ARTIFACTS) - set(artifacts))
    if missing:
        blockers.append("final evidence manifest is missing required artifacts")
    artifact_reports: dict[str, Any] = {}
    for name in FINAL_EVIDENCE_REQUIRED_ARTIFACTS:
        raw_path = artifacts.get(name)
        artifact_path = _manifest_artifact_path(manifest_path, raw_path)
        artifact_blockers: list[str] = []
        digest: str | None = None
        document: Any = None
        if artifact_path is None:
            artifact_blockers.append("artifact path is invalid")
        elif not artifact_path.is_file():
            artifact_blockers.append("artifact file is unavailable")
        else:
            digest = _sha256_file(artifact_path)
            if artifact_sha256.get(name) != digest:
                artifact_blockers.append("artifact SHA-256 does not match manifest")
            try:
                document = _load_retained_json_report(
                    artifact_path, command=command, label=f"final evidence artifact {name}"
                )
            except CliFailure as exc:
                artifact_blockers.append("artifact is unavailable or invalid JSON")
                document = None
        expected_command = FINAL_EVIDENCE_ARTIFACT_COMMANDS.get(name)
        if expected_command is not None and isinstance(document, dict):
            if document.get("command") != expected_command:
                artifact_blockers.append("artifact command does not match expected evidence kind")
        if name == "pi_scenario_report" and isinstance(document, dict):
            if document.get("schema_version") != "odoo-accounting-cli-v3.pi-gate-report.v1":
                artifact_blockers.append("Pi scenario report schema is invalid")
        if name == "sandbox_provision_authorization" and isinstance(document, dict):
            if document.get("purpose") != "sandbox_database_provision":
                artifact_blockers.append("sandbox provision authorization purpose is invalid")
        if artifact_blockers:
            blockers.extend(f"{name}: {item}" for item in artifact_blockers)
        artifact_reports[name] = {
            "blockers": sorted(set(artifact_blockers)),
            "path": str(artifact_path) if artifact_path is not None else raw_path,
            "sha256": digest,
        }
    return {
        "artifact_count": len(FINAL_EVIDENCE_REQUIRED_ARTIFACTS),
        "artifacts": artifact_reports,
        "blockers": sorted(set(blockers)),
        "final_evidence_manifest_ready": not blockers,
        "manifest_path": str(manifest_path),
        "manifest_sha256": _sha256_file(manifest_path),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "release_identity": expected_release_identity,
    }


def _load_release_identity(
    root: Path | None = None, *, command: str = "release.identity"
) -> dict[str, Any]:
    release_root = root or Path(__file__).resolve().parents[2]
    manifest_path = release_root / "RELEASE-MANIFEST.json"
    anchor_path = (
        release_root.parent.parent
        / "trusted-artifacts"
        / f"{release_root.name}.json"
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CliFailure(
            command=command,
            code="release_identity_unavailable",
            message="The release manifest or external deployment anchor is unavailable.",
            exit_code=5,
        ) from exc
    expected_anchor_fields = {
        "commit",
        "manifest_sha256",
        "package_sha256",
        "release",
    }
    if (
        not isinstance(anchor, dict)
        or set(anchor) != expected_anchor_fields
        or anchor["release"] != release_root.name
        or anchor["commit"] != manifest.get("commit")
        or not isinstance(anchor.get("package_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", anchor["package_sha256"]) is None
    ):
        raise CliFailure(
            command=command,
            code="release_identity_mismatch",
            message="The deployment anchor does not match this release.",
            exit_code=5,
        )
    try:
        verify_manifest(
            release_root,
            manifest,
            expected_manifest_sha256=anchor["manifest_sha256"],
        )
        capabilities = load_registry(release_root / "registry" / "capabilities.json")
    except (OSError, ValueError, ReleaseError) as exc:
        raise CliFailure(
            command=command,
            code="release_verification_failed",
            message="The installed release failed integrity verification.",
            exit_code=5,
        ) from exc
    return {
        "commit": manifest["commit"],
        "manifest_sha256": manifest["manifest_sha256"],
        "package_sha256": anchor["package_sha256"],
        "registry_digest": registry_digest(capabilities),
        "release": anchor["release"],
        "verified": True,
        "version": manifest["version"],
    }


def _assert_runtime_release(
    config: RuntimeConfig,
    identity: dict[str, Any],
    *,
    command: str = "read",
) -> None:
    source_release = Path(__file__).resolve().parents[2]
    expected_package_path = (
        config.release_root.parent.parent
        / "packages"
        / f"odoo-accounting-cli-v3-{config.release_root.name}.tar.gz"
    )
    if source_release != config.release_root.resolve():
        raise CliFailure(
            command=command,
            code="runtime_release_mismatch",
            message="The CLI process and configured Odoo runner are not from the same release.",
            exit_code=5,
        )
    if (
        identity.get("version") != __version__
        or identity.get("package_sha256") != config.canonical_package_sha256
        or config.canonical_package_path != expected_package_path
    ):
        raise CliFailure(
            command=command,
            code="runtime_release_mismatch",
            message="The CLI or canonical package does not match the configured verified release.",
            exit_code=5,
        )


def _assert_verified_read_result(
    request: dict[str, Any],
    result: dict[str, Any],
    config: RuntimeConfig,
    identity: dict[str, Any],
) -> None:
    context = request.get("context")
    receipt = result.get("receipt") if isinstance(result, dict) else None
    if not isinstance(context, dict) or not isinstance(receipt, dict):
        raise CliFailure(
            command="read",
            code="verified_receipt_missing",
            message="Odoo did not return a verified read receipt.",
            exit_code=6,
        )
    try:
        capability_id = request["capability_id"]
        if context["auth_request_digest"] != authentication_request_digest(
            capability_id, request["parameters"]
        ):
            raise ValueError("authenticated request content digest mismatch")
        capabilities = load_registry(config.release_root / "registry" / "capabilities.json")
        capability = next(item for item in capabilities if item.id == capability_id)
        validate_value(result, capability.data["output_schema"])
        body = {key: value for key, value in result.items() if key != "receipt"}
        _auth_secret, receipt_secret = load_runtime_secrets(config)
        verify_read_receipt(
            receipt,
            capability_id=capability_id,
            parameters=request["parameters"],
            result_body=body,
            auth_token_id=context["auth_token_id"],
            principal=context["principal"],
            odoo_instance_id=config.instance_id,
            database_name=config.database_name,
            database_uuid=config.database_uuid,
            company_id=context["company_id"],
            user_id=context["user_id"],
            registry_digest=identity["registry_digest"],
            release_digest=identity["manifest_sha256"],
            environment=config.environment,
            capability_channel=config.capability_channel,
            expected_record_count=body["page"]["total_count"],
            now=datetime.now(timezone.utc),
            consume_receipt=lambda *_args: True,
            expected_key_id=config.receipt_key_id,
            secret=receipt_secret,
        )
    except (
        ContractError,
        KeyError,
        OdooRunnerError,
        ReceiptError,
        StopIteration,
        TypeError,
        ValueError,
    ) as exc:
        raise CliFailure(
            command="read",
            code="verified_receipt_mismatch",
            message=(
                "The Odoo read result or receipt does not match the request, "
                "strict capability contract, signature, and verified runtime."
            ),
            exit_code=6,
        ) from exc


def _read_request(command: str, request_json: str | None) -> dict[str, Any]:
    raw = request_json
    if raw is None:
        if sys.stdin.isatty():
            raise CliFailure(
                command=command,
                code="request_required",
                message="Provide a JSON object with --request-json or on standard input.",
            )
        raw = sys.stdin.read()
    if not raw.strip():
        raise CliFailure(
            command=command,
            code="request_required",
            message="A non-empty JSON request object is required.",
        )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise CliFailure(
            command=command,
            code="invalid_json",
            message="The request is not valid JSON.",
        ) from exc
    if not isinstance(value, dict):
        raise CliFailure(
            command=command,
            code="invalid_request",
            message="The request must be a JSON object.",
        )
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_non_finite_json(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def _load_sandbox_write_evidence_verifier() -> Any:
    path = Path(__file__).resolve().parents[2] / "tools" / "verify_sandbox_write_evidence.py"
    spec = util.spec_from_file_location(
        "odoo_accounting_cli_v3_release_sandbox_write_evidence_verifier",
        path,
    )
    if spec is None or spec.loader is None:
        raise CliFailure(
            command="evidence.verify-sandbox-write",
            code="sandbox_write_evidence_verifier_unavailable",
            message="The exact-release sandbox write evidence verifier is unavailable.",
            exit_code=5,
        )
    module = util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except OSError as exc:
        raise CliFailure(
            command="evidence.verify-sandbox-write",
            code="sandbox_write_evidence_verifier_unavailable",
            message="The exact-release sandbox write evidence verifier is unavailable.",
            exit_code=5,
        ) from exc
    return module


def _load_pi_scenario_gate() -> Any:
    path = Path(__file__).resolve().parents[2] / "tools" / "pi_scenario_gate.py"
    spec = util.spec_from_file_location(
        "odoo_accounting_cli_v3_release_pi_scenario_gate",
        path,
    )
    if spec is None or spec.loader is None:
        raise CliFailure(
            command="evidence.pi-trace-capture-check",
            code="pi_scenario_gate_unavailable",
            message="The exact-release Pi scenario gate is unavailable.",
            exit_code=5,
        )
    module = util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except OSError as exc:
        raise CliFailure(
            command="evidence.pi-trace-capture-check",
            code="pi_scenario_gate_unavailable",
            message="The exact-release Pi scenario gate is unavailable.",
            exit_code=5,
        ) from exc
    return module


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _validate_sandbox_write_evidence_root(
    path: Path,
    *,
    release_root: Path,
    minimum_free_bytes: int,
) -> dict[str, Any]:
    if not path.is_absolute():
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root must be absolute.",
            exit_code=5,
        )
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root is unavailable.",
            exit_code=5,
        ) from exc
    if not resolved.is_dir() or path.is_symlink():
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root must be a real directory.",
            exit_code=5,
        )
    if _is_within(resolved, release_root):
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_evidence_root_rejected",
            message="The sandbox write evidence root must not be inside the immutable release.",
            exit_code=5,
        )
    if os.name == "posix":
        import stat

        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise CliFailure(
                command="evidence.sandbox-write-preflight",
                code="sandbox_write_evidence_root_rejected",
                message="The sandbox write evidence root must be root-owned and not group/world writable.",
                exit_code=5,
            )
    usage = shutil.disk_usage(resolved)
    free_bytes = usage.free
    if free_bytes < minimum_free_bytes:
        raise CliFailure(
            command="evidence.sandbox-write-preflight",
            code="sandbox_write_capacity_rejected",
            message="The sandbox write evidence filesystem does not have enough free bytes.",
            exit_code=5,
        )
    return {
        "path": str(resolved),
        "available_bytes": free_bytes,
        "minimum_free_bytes": minimum_free_bytes,
    }


def _audit_sandbox_write_evidence_root(
    path: Path | None,
    *,
    release_root: Path,
    minimum_free_bytes: int,
) -> dict[str, Any]:
    if path is None:
        return {
            "available_bytes": None,
            "blockers": ["sandbox write evidence root was not supplied"],
            "minimum_free_bytes": minimum_free_bytes,
            "path": None,
            "ready": False,
            "status": "missing",
        }
    blockers: list[str] = []
    resolved: Path | None = None
    available_bytes: int | None = None
    status = "valid"
    if not path.is_absolute():
        blockers.append("sandbox write evidence root must be absolute")
        status = "invalid"
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError:
        blockers.append("sandbox write evidence root is unavailable")
        status = "missing"
        metadata = None
    if resolved is not None:
        if not resolved.is_dir() or path.is_symlink():
            blockers.append("sandbox write evidence root must be a real directory")
            status = "invalid"
        if _is_within(resolved, release_root):
            blockers.append("sandbox write evidence root must not be inside the immutable release")
            status = "invalid"
        if os.name == "posix" and metadata is not None:
            import stat

            if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
                blockers.append(
                    "sandbox write evidence root must be root-owned and not group/world writable"
                )
                status = "invalid"
        try:
            available_bytes = shutil.disk_usage(resolved).free
        except OSError:
            blockers.append("sandbox write evidence root filesystem is unavailable")
            status = "invalid"
        if available_bytes is not None and available_bytes < minimum_free_bytes:
            blockers.append("sandbox write evidence filesystem free space is below the configured floor")
            status = "capacity_rejected"
    return {
        "available_bytes": available_bytes,
        "blockers": sorted(set(blockers)),
        "minimum_free_bytes": minimum_free_bytes,
        "path": str(resolved) if resolved is not None else str(path),
        "ready": not blockers,
        "status": status if blockers else "valid",
    }


def _require_absolute_plan_path(
    value: Path,
    *,
    command: str,
    option: str,
) -> Path:
    if not value.is_absolute():
        raise CliFailure(
            command=command,
            code="write_runtime_plan_rejected",
            message=f"{option} must be an absolute path.",
        )
    return value


def _write_runtime_role_plan(
    *,
    secret_root: Path,
    key_id_prefix: str,
    issuer_prefix: str,
) -> dict[str, dict[str, str]]:
    roles: dict[str, dict[str, str]] = {}
    for role in WRITE_ROLE_NAMES:
        role_key = role.replace("_", "-")
        document = {
            "key_id": f"{key_id_prefix}-{role_key}-v1",
            "secret_path": str(secret_root / f"{role}.hmac"),
        }
        if role in {"execution", "verification", "recovery"}:
            document["issuer"] = f"{issuer_prefix}-{role_key}"
        roles[role] = document
    return roles


def _write_runtime_plan_document(
    *,
    base_runtime_config: Path,
    write_state_path: Path,
    secret_root: Path,
    write_execution_mode: str,
    key_id_prefix: str,
    issuer_prefix: str,
    socket_path: str,
    socket_owner_uid: int,
    socket_group_gid: int,
    socket_mode: int,
    finalizer_service_uid: int,
    finalizer_service_gid: int,
    finalizer_systemd_unit: str,
    attestation_key_id: str,
    guard_installation_id: str,
    database_oid: int,
    handoff_idle_timeout_seconds: float,
    request_io_timeout_seconds: float,
    max_request_bytes: int,
    max_response_bytes: int,
) -> dict[str, Any]:
    return {
        "schema_version": WRITE_RUNTIME_SCHEMA_VERSION,
        "write_execution_mode": write_execution_mode,
        "base_runtime_config_path": str(base_runtime_config),
        "write_state_path": str(write_state_path),
        "effect_finalizer": {
            "socket_path": socket_path,
            "socket_owner_uid": socket_owner_uid,
            "socket_group_gid": socket_group_gid,
            "socket_mode": socket_mode,
            "finalizer_service_uid": finalizer_service_uid,
            "finalizer_service_gid": finalizer_service_gid,
            "finalizer_systemd_unit": finalizer_systemd_unit,
            "attestation_key_id": attestation_key_id,
            "guard_installation_id": guard_installation_id,
            "database_oid": database_oid,
            "handoff_idle_timeout_seconds": handoff_idle_timeout_seconds,
            "request_io_timeout_seconds": request_io_timeout_seconds,
            "max_request_bytes": max_request_bytes,
            "max_response_bytes": max_response_bytes,
        },
        **_write_runtime_role_plan(
            secret_root=secret_root,
            key_id_prefix=key_id_prefix,
            issuer_prefix=issuer_prefix,
        ),
    }


def _read_runtime_plan_document(
    *,
    instance_id: str,
    environment: str,
    capability_channel: str,
    database_name: str,
    database_uuid: str,
    odoo_python: Path,
    odoo_python_sha256: str,
    odoo_bin: Path,
    odoo_bin_sha256: str,
    odoo_config: Path,
    odoo_config_sha256: str,
    release_root: Path,
    canonical_package_path: Path,
    canonical_package_sha256: str,
    auth_state_path: Path,
    receipt_state_path: Path,
    gcov_state_path: Path,
    auth_key_id: str,
    receipt_key_id: str,
    auth_secret_path: Path,
    receipt_secret_path: Path,
) -> dict[str, Any]:
    runtime = RuntimeConfig(
        instance_id=instance_id,
        environment=environment,
        capability_channel=capability_channel,
        database_name=database_name,
        database_uuid=database_uuid,
        odoo_python=odoo_python,
        odoo_python_sha256=odoo_python_sha256,
        odoo_bin=odoo_bin,
        odoo_bin_sha256=odoo_bin_sha256,
        odoo_config=odoo_config,
        odoo_config_sha256=odoo_config_sha256,
        release_root=release_root,
        canonical_package_path=canonical_package_path,
        canonical_package_sha256=canonical_package_sha256,
        auth_state_path=auth_state_path,
        receipt_state_path=receipt_state_path,
        gcov_state_path=gcov_state_path,
        auth_key_id=auth_key_id,
        receipt_key_id=receipt_key_id,
        auth_secret_path=auth_secret_path,
        receipt_secret_path=receipt_secret_path,
    )
    return {
        "instance_id": runtime.instance_id,
        "environment": runtime.environment,
        "capability_channel": runtime.capability_channel,
        "database_name": runtime.database_name,
        "database_uuid": runtime.database_uuid,
        "odoo_python": str(runtime.odoo_python),
        "odoo_python_sha256": runtime.odoo_python_sha256,
        "odoo_bin": str(runtime.odoo_bin),
        "odoo_bin_sha256": runtime.odoo_bin_sha256,
        "odoo_config": str(runtime.odoo_config),
        "odoo_config_sha256": runtime.odoo_config_sha256,
        "release_root": str(runtime.release_root),
        "canonical_package_path": str(runtime.canonical_package_path),
        "canonical_package_sha256": runtime.canonical_package_sha256,
        "auth_state_path": str(runtime.auth_state_path),
        "receipt_state_path": str(runtime.receipt_state_path),
        "gcov_state_path": str(runtime.gcov_state_path),
        "auth_key_id": runtime.auth_key_id,
        "receipt_key_id": runtime.receipt_key_id,
        "auth_secret_path": str(runtime.auth_secret_path),
        "receipt_secret_path": str(runtime.receipt_secret_path),
    }


def _write_cli_failure(
    *,
    command: str,
    code: str,
    message: str,
    odoo_effect: str,
    operation_id: str | None = None,
    state: str | None = None,
    retryable: bool = False,
    exit_code: int = 2,
) -> CliFailure:
    return CliFailure(
        command=command,
        code=code,
        message=message,
        retryable=retryable,
        odoo_effect=odoo_effect,
        operation_id=operation_id,
        state=state,
        exit_code=exit_code,
    )


def _operation_id_from_request(action: str, payload: dict[str, Any]) -> str | None:
    field = "recovery_operation_id" if action == "operation.recover" else "operation_id"
    value = payload.get(field)
    return value if isinstance(value, str) else None


def _business_succeeded(data: dict[str, Any]) -> bool:
    verification = data.get("verification")
    operation_id = data.get("operation_id")
    if (
        data.get("operation_state") not in {"completed", "recovered"}
        or not isinstance(operation_id, str)
        or not operation_id
        or not isinstance(verification, dict)
        or verification.get("passed") is not True
    ):
        return False
    try:
        finalization = validate_effect_finalization_evidence_shape(
            data.get("database_finalization")
        )
    except EffectFinalizationError:
        return False
    audit_receipt = data.get("audit_receipt")
    if not _terminal_audit_receipt_is_business_ready(
        audit_receipt,
        operation_id=operation_id,
        database_uuid=finalization["database_uuid"],
    ):
        return False
    if finalization["resolution_kind"] == "verified":
        return (
            finalization["operation_id"] == operation_id
            and finalization["resolution_operation_id"] == operation_id
        )
    return (
        finalization["operation_id"] != operation_id
        and finalization["resolution_operation_id"] == operation_id
    )


def _terminal_audit_receipt_is_business_ready(
    audit_receipt: Any,
    *,
    operation_id: str,
    database_uuid: str,
) -> bool:
    if not isinstance(audit_receipt, dict) or set(audit_receipt) != RECEIPT_FIELDS:
        return False
    digest_fields = {
        "approval_digest",
        "audit_head",
        "operation_digest",
        "registry_digest",
        "release_digest",
        "request_digest",
        "result_digest",
        "signature",
        "verification_evidence_digest",
    }
    text_fields = {
        "capability_id",
        "capability_channel",
        "database_name",
        "environment",
        "issued_at",
        "odoo_instance_id",
        "principal",
        "receipt_id",
        "request_id",
        "signing_key_id",
    }
    positive_integer_fields = {"approver_user_id", "company_id", "user_id"}
    if (
        audit_receipt.get("operation_id") != operation_id
        or audit_receipt.get("database_uuid") != database_uuid
        or audit_receipt.get("signature_purpose") != WRITE_RECEIPT_PURPOSE
        or audit_receipt.get("signature_version") != 1
        or audit_receipt.get("environment") not in {"test", "sandbox", "production"}
        or audit_receipt.get("capability_channel") not in {"staged", "enabled"}
    ):
        return False
    if any(
        not isinstance(audit_receipt.get(field), str)
        or re.fullmatch(r"[0-9a-f]{64}", audit_receipt[field]) is None
        for field in digest_fields
    ):
        return False
    if any(
        not isinstance(audit_receipt.get(field), str)
        or not audit_receipt[field].strip()
        or audit_receipt[field] != audit_receipt[field].strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in audit_receipt[field])
        for field in text_fields
    ):
        return False
    if any(
        isinstance(audit_receipt.get(field), bool)
        or not isinstance(audit_receipt.get(field), int)
        or audit_receipt[field] <= 0
        for field in positive_integer_fields
    ):
        return False
    return True


def _execute_write_command(
    *,
    command: str,
    action: str,
    request_json: str | None,
    report_business_result: bool = False,
) -> None:
    try:
        request = _read_request(command, request_json)
    except CliFailure as exc:
        raise _write_cli_failure(
            command=command,
            code=exc.code,
            message=exc.message,
            odoo_effect="none",
            exit_code=exc.exit_code,
        ) from exc

    try:
        parsed = parse_write_api_request(action, request)
    except WriteApiError as exc:
        raise _write_cli_failure(
            command=command,
            code="invalid_request",
            message="The write request does not match the exact action contract.",
            odoo_effect="none",
        ) from exc

    operation_id = _operation_id_from_request(action, parsed.payload)
    uncertain_effect = "unknown" if action == "operation.approve_execute" else "none"
    try:
        # The dispatcher owns root-managed runtime paths and secrets. They are
        # deliberately absent from the Pi-facing command surface.
        from .write_app import execute_write_action

        raw_data = execute_write_action(action, parsed)
        if not isinstance(raw_data, dict):
            raise TypeError("write dispatcher returned a non-object")
        data = json.loads(
            json.dumps(
                raw_data,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except CliFailure as exc:
        raise _write_cli_failure(
            command=command,
            code=exc.code,
            message=exc.message,
            odoo_effect=exc.odoo_effect or uncertain_effect,
            operation_id=exc.operation_id or operation_id,
            state=exc.state,
            retryable=exc.retryable,
            exit_code=exc.exit_code,
        ) from exc
    except Exception as exc:
        code = getattr(exc, "code", None)
        structured = isinstance(code, str) and bool(code.strip())
        effect = getattr(exc, "odoo_effect", uncertain_effect)
        if effect not in {"none", "unknown"}:
            effect = uncertain_effect
        retryable = getattr(exc, "retryable", False)
        if type(retryable) is not bool:
            retryable = False
        exception_operation_id = getattr(exc, "operation_id", operation_id)
        if not isinstance(exception_operation_id, str):
            exception_operation_id = operation_id
        state = getattr(exc, "state", None)
        if not isinstance(state, str):
            state = None
        raise _write_cli_failure(
            command=command,
            code=code if structured else "write_action_failed",
            message=(
                str(getattr(exc, "message", exc))
                if structured
                else "The durable write action did not return a trusted result."
            ),
            odoo_effect=effect,
            operation_id=exception_operation_id,
            state=state,
            retryable=retryable,
            exit_code=int(getattr(exc, "exit_code", 3))
            if type(getattr(exc, "exit_code", 3)) is int
            else 3,
        ) from exc

    _success(
        command,
        data,
        business_succeeded=_business_succeeded(data)
        if report_business_result
        else None,
    )


@click.group()
@click.version_option(version=__version__, prog_name="odoo-accounting-cli-v3")
def main() -> None:
    """Controlled Odoo 19 accounting capability gateway."""


@main.group("registry")
def registry_group() -> None:
    """Inspect the validated local capability registry."""


@main.group("release")
def release_group() -> None:
    """Inspect the externally anchored release identity."""


@release_group.command("identity")
def release_identity() -> None:
    _success("release.identity", _load_release_identity())


def _current_route_report(
    current_path: Path,
    *,
    command: str,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    resolved: Path | None = None
    identity: dict[str, Any] | None = None
    if not current_path.is_absolute():
        blockers.append("current path must be absolute")
    try:
        current_path.lstat()
        if not current_path.is_symlink():
            blockers.append("current path must be a symlink")
        resolved = current_path.resolve(strict=True)
        if not resolved.is_dir():
            blockers.append("current symlink target must be a directory")
        if resolved.parent.name != "releases":
            blockers.append("current symlink target must be inside a releases directory")
        identity = _load_release_identity(resolved, command=command)
    except CliFailure:
        raise
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="current_route_unavailable",
            message="The current release route is unavailable.",
            exit_code=5,
        ) from exc
    expected_pairs = {
        "commit": expected_commit,
        "manifest_sha256": expected_manifest_sha256,
        "package_sha256": expected_package_sha256,
        "registry_digest": expected_registry_digest,
        "release": expected_release,
    }
    if expected_commit is not None and re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None:
        blockers.append("expected commit must be a 40-character lowercase hex SHA-1")
    for field, expected in (
        ("manifest_sha256", expected_manifest_sha256),
        ("package_sha256", expected_package_sha256),
        ("registry_digest", expected_registry_digest),
    ):
        if expected is not None and re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            blockers.append(f"expected {field} must be a 64-character lowercase hex SHA-256")
    if expected_release is not None and not expected_release:
        blockers.append("expected release must be non-empty when supplied")
    if identity is not None:
        for field, expected in expected_pairs.items():
            if expected is not None and identity[field] != expected:
                blockers.append(f"current route {field} does not match expected value")
    return {
        "blockers": sorted(set(blockers)),
        "current_path": str(current_path),
        "current_route_ready": not blockers,
        "expected": {
            field: expected
            for field, expected in expected_pairs.items()
            if expected is not None
        },
        "real_odoo_write_performed": False,
        "resolved_release_path": str(resolved) if resolved is not None else None,
        "route_identity": identity,
    }


@release_group.command("current-route")
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
    help="Current release symlink to inspect.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def release_current_route(
    current_path: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Verify that the current route points at the intended immutable release."""

    command = "release.current-route"
    data = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_registry_digest=expected_registry_digest,
    )
    _success(command, data)


def _target_capacity_recheck_report(
    probe_path: Path,
    *,
    required_free_bytes: int,
) -> dict[str, Any]:
    from . import capacity_plan

    resolved = probe_path.resolve(strict=True)
    filesystem = capacity_plan.filesystem_summary(resolved, PurePosixPath("/"))
    available = int(filesystem["available_bytes"])
    blockers: list[str] = []
    if available < required_free_bytes:
        blockers.append("target filesystem free space is below the configured floor")
    return {
        "available_bytes": available,
        "blockers": sorted(set(blockers)),
        "cleanup_executed": False,
        "filesystem": {**filesystem, "probe_path": str(resolved)},
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "required_free_bytes": required_free_bytes,
        "sandbox_write_capacity_ready": not blockers,
        "shortfall_bytes": max(0, required_free_bytes - available),
    }


@main.group("evidence")
def evidence_group() -> None:
    """Run exact-release internal safety evidence probes."""


@evidence_group.command("target-capacity-plan")
@click.option(
    "--root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("/"),
    show_default=True,
    help="Filesystem root to inspect. Defaults to the target host root.",
)
@click.option(
    "--required-free-bytes",
    type=click.IntRange(min=1),
    default=8 * 1024 * 1024 * 1024,
    show_default=True,
    help="Minimum ordinary free bytes required before sandbox write evidence.",
)
@click.option(
    "--keep-release",
    multiple=True,
    help="Release name that must not be listed as cleanup candidate.",
)
@click.option(
    "--summary-only",
    is_flag=True,
    help="Omit the per-path candidate list while retaining capacity totals and blockers.",
)
@click.option(
    "--max-candidates",
    type=click.IntRange(min=0),
    help="Limit the retained candidate list for bounded Pi/operator output.",
)
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
    help="Current release symlink to verify before trusting the capacity plan.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_target_capacity_plan(
    root: Path,
    required_free_bytes: int,
    keep_release: tuple[str, ...],
    summary_only: bool,
    max_candidates: int | None,
    current_path: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Plan V3-owned capacity remediation without deleting or mutating files."""

    from . import capacity_plan as target_capacity_plan

    command = "evidence.target-capacity-plan"
    route_report = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_registry_digest=expected_registry_digest,
    )
    try:
        plan = target_capacity_plan.build_plan(
            root=root,
            required_free_bytes=required_free_bytes,
            keep_releases=target_capacity_plan.validate_keep_releases(keep_release),
        )
    except target_capacity_plan.CapacityPlanError as exc:
        raise CliFailure(
            command=command,
            code="target_capacity_plan_rejected",
            message="The target capacity plan inputs are invalid.",
            exit_code=5,
        ) from exc
    retained_candidate_count = int(plan["candidate_count"])
    if summary_only:
        retained_candidate_count = 0
        plan.pop("candidates", None)
    elif max_candidates is not None:
        candidates = list(plan["candidates"])
        retained_candidate_count = min(len(candidates), max_candidates)
        plan["candidates"] = candidates[:max_candidates]
    plan["candidates_truncated"] = retained_candidate_count < int(plan["candidate_count"])
    plan["retained_candidate_count"] = retained_candidate_count
    blockers: list[str] = []
    if not route_report["current_route_ready"]:
        blockers.append("current release route is not ready")
    if int(plan["shortfall_bytes"]) > 0:
        blockers.append("target filesystem free space is below the configured floor")
    if int(plan["shortfall_bytes"]) > int(plan["candidate_reclaimable_bytes"]):
        blockers.append(
            "reviewable V3-owned cleanup candidates cannot cover the capacity shortfall"
        )
    data = {
        "authorization_required_before_cleanup": True,
        "blockers": sorted(set(blockers)),
        "cleanup_executed": False,
        "plan": plan,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "route": route_report,
        "sandbox_write_capacity_ready": not blockers,
    }
    _success(command, data, business_succeeded=False)


@evidence_group.command("target-capacity-recheck")
@click.option(
    "--path",
    "probe_path",
    type=click.Path(path_type=Path),
    default=Path("/"),
    show_default=True,
    help="Path whose filesystem capacity should be rechecked.",
)
@click.option(
    "--required-free-bytes",
    type=click.IntRange(min=1),
    default=8 * 1024 * 1024 * 1024,
    show_default=True,
    help="Minimum ordinary free bytes required before sandbox write evidence.",
)
def evidence_target_capacity_recheck(
    probe_path: Path,
    required_free_bytes: int,
) -> None:
    """Recheck the current target capacity gate without cleanup or mutation."""

    command = "evidence.target-capacity-recheck"
    try:
        data = _target_capacity_recheck_report(
            probe_path,
            required_free_bytes=required_free_bytes,
        )
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="target_capacity_recheck_rejected",
            message="The target capacity probe path is unavailable.",
            exit_code=5,
        ) from exc
    _success(command, data, business_succeeded=False)


def _extract_target_capacity_plan(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ValueError("target capacity plan document must be a JSON object")
    data = document.get("data")
    if isinstance(data, dict) and isinstance(data.get("plan"), dict):
        plan = data["plan"]
    elif isinstance(document.get("plan"), dict):
        plan = document["plan"]
    else:
        raise ValueError("target capacity plan payload is missing data.plan")
    if plan.get("kind") != "odoo-accounting-cli-v3.target-capacity-plan.v1":
        raise ValueError("target capacity plan kind is not supported")
    if plan.get("cleanup_executed") is not False:
        raise ValueError("target capacity plan must be read-only and unexecuted")
    return plan


def _load_target_capacity_plan_file(capacity_plan_file: Path) -> tuple[dict[str, Any], str]:
    payload = capacity_plan_file.read_bytes()
    document = json.loads(payload.decode("utf-8"))
    return _extract_target_capacity_plan(document), _sha256_bytes(payload)


def _capacity_plan_candidates_by_path(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    candidates = plan.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("target capacity plan must retain candidates for authorization")
    by_path: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("target capacity candidate must be a JSON object")
        path = candidate.get("path")
        size_bytes = candidate.get("size_bytes")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("target capacity candidate path is invalid")
        if not isinstance(size_bytes, int) or size_bytes <= 0:
            raise ValueError("target capacity candidate size is invalid")
        by_path[path] = candidate
    return by_path


@evidence_group.command("target-capacity-cleanup-authorization-template")
@click.option(
    "--capacity-plan-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.target-capacity-plan JSON output with candidate paths.",
)
@click.option(
    "--candidate-path",
    multiple=True,
    required=True,
    help="Exact V3-owned cleanup candidate path to authorize; repeat for each path.",
)
@click.option(
    "--operator-id",
    required=True,
    help="Human/operator identity accountable for the cleanup decision.",
)
@click.option(
    "--retention-until",
    required=True,
    help="UTC timestamp naming how long the cleanup decision evidence is retained.",
)
@click.option(
    "--ttl-seconds",
    type=click.IntRange(min=1, max=24 * 60 * 60),
    default=3600,
    show_default=True,
    help="Authorization validity window.",
)
@click.option(
    "--issued-at",
    help="UTC issue timestamp for deterministic review; defaults to current UTC time.",
)
def evidence_target_capacity_cleanup_authorization_template(
    capacity_plan_file: Path,
    candidate_path: tuple[str, ...],
    operator_id: str,
    retention_until: str,
    ttl_seconds: int,
    issued_at: str | None,
) -> None:
    """Render a target-capacity cleanup authorization template without cleanup."""

    command = "evidence.target-capacity-cleanup-authorization-template"
    blockers: list[str] = []
    try:
        plan, plan_sha256 = _load_target_capacity_plan_file(capacity_plan_file)
        candidates = _capacity_plan_candidates_by_path(plan)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CliFailure(
            command=command,
            code="target_capacity_cleanup_authorization_rejected",
            message="The target capacity plan file is unavailable or invalid.",
            exit_code=5,
        ) from exc

    selected_paths = sorted(set(candidate_path))
    if any(not path.startswith("/") for path in selected_paths):
        blockers.append("candidate paths must be absolute display paths")
    missing_paths = [path for path in selected_paths if path not in candidates]
    if missing_paths:
        blockers.append("candidate path is not present in the retained capacity plan")
    selected_candidates = [candidates[path] for path in selected_paths if path in candidates]
    if any(item.get("requires_explicit_authorization") is not True for item in selected_candidates):
        blockers.append("selected candidates must require explicit authorization")
    authorized_reclaimable_bytes = sum(int(item["size_bytes"]) for item in selected_candidates)
    if authorized_reclaimable_bytes <= 0:
        blockers.append("authorized reclaimable bytes must be positive")
    try:
        issued = (
            _parse_utc_datetime(issued_at, "issued_at")
            if issued_at is not None
            else datetime.now(timezone.utc)
        )
        retention = _parse_utc_datetime(retention_until, "retention_until")
    except ValueError as exc:
        blockers.append(str(exc))
        issued = retention = datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=ttl_seconds)
    if retention <= issued:
        blockers.append("retention_until must be after issued_at")

    summary = {
        "allowed_action": "remove_selected_v3_owned_capacity_candidates",
        "authorized_reclaimable_bytes": authorized_reclaimable_bytes,
        "candidate_paths": selected_paths,
        "operator_id": operator_id,
        "plan_candidate_count": plan.get("candidate_count"),
        "plan_required_free_bytes": plan.get("required_free_bytes"),
        "plan_sha256": plan_sha256,
        "plan_shortfall_bytes": plan.get("shortfall_bytes"),
        "retention_until": _format_utc_datetime(retention),
    }
    document = {
        "expires_at": _format_utc_datetime(expires),
        "immutable_summary": summary,
        "immutable_summary_sha256": _sha256_json(summary),
        "issued_at": _format_utc_datetime(issued),
        "purpose": "target_capacity_cleanup",
        "schema_version": 1,
    }
    data = {
        "authorization_record_template": document,
        "authorization_template_ready": not blockers,
        "blockers": sorted(set(blockers)),
        "cleanup_executed": False,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "save_path_recommendation": "/etc/odoo-accounting-cli-v3/target-capacity-cleanup-authorization.json",
        "selected_candidates": selected_candidates,
        "template_only_not_authorized": True,
        "validation_command_args": [
            "evidence",
            "target-capacity-cleanup-authorization-check",
            "--authorization-file",
            "/etc/odoo-accounting-cli-v3/target-capacity-cleanup-authorization.json",
            "--capacity-plan-file",
            str(capacity_plan_file),
            *[
                item
                for path in selected_paths
                for item in ("--expected-candidate-path", path)
            ],
        ],
    }
    _success(command, data, business_succeeded=False)


def _target_capacity_cleanup_authorization_report(
    document: Any,
    *,
    authorization_file: Path,
    capacity_plan_file: Path,
    expected_candidate_path: tuple[str, ...],
    now: str | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    try:
        plan, plan_sha256 = _load_target_capacity_plan_file(capacity_plan_file)
        candidates = _capacity_plan_candidates_by_path(plan)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        plan = {}
        plan_sha256 = ""
        candidates = {}
        blockers.append("target capacity plan file is unavailable or invalid")
    if not isinstance(document, dict):
        blockers.append("authorization record must be a JSON object")
        document = {}
    current_time = datetime.now(timezone.utc)
    if now is not None:
        try:
            current_time = _parse_utc_datetime(now, "now")
        except ValueError:
            blockers.append("now must be a UTC timestamp")
    summary = document.get("immutable_summary")
    if not isinstance(summary, dict):
        blockers.append("immutable_summary must be a JSON object")
        summary = {}
    expected_summary_sha256 = _sha256_json(summary)
    if document.get("immutable_summary_sha256") != expected_summary_sha256:
        blockers.append("immutable_summary_sha256 does not match immutable_summary")
    if document.get("schema_version") != 1:
        blockers.append("schema_version must be 1")
    if document.get("purpose") != "target_capacity_cleanup":
        blockers.append("purpose must be target_capacity_cleanup")
    if summary.get("allowed_action") != "remove_selected_v3_owned_capacity_candidates":
        blockers.append("allowed_action must be remove_selected_v3_owned_capacity_candidates")
    if summary.get("plan_sha256") != plan_sha256:
        blockers.append("authorization is not bound to the retained capacity plan")
    candidate_paths = summary.get("candidate_paths")
    if (
        not isinstance(candidate_paths, list)
        or not candidate_paths
        or any(not isinstance(item, str) or not item.startswith("/") for item in candidate_paths)
    ):
        blockers.append("candidate_paths must be a non-empty list of absolute display paths")
        candidate_path_set: set[str] = set()
    else:
        candidate_path_set = set(candidate_paths)
    missing_expected = sorted(set(expected_candidate_path) - candidate_path_set)
    if missing_expected:
        blockers.append("expected candidate path is not authorized")
    missing_from_plan = sorted(path for path in candidate_path_set if path not in candidates)
    if missing_from_plan:
        blockers.append("authorized candidate path is not present in the retained capacity plan")
    computed_reclaimable = sum(
        int(candidates[path]["size_bytes"])
        for path in candidate_path_set
        if path in candidates
    )
    if summary.get("authorized_reclaimable_bytes") != computed_reclaimable:
        blockers.append("authorized_reclaimable_bytes does not match retained candidates")
    try:
        issued_at = _parse_utc_datetime(document.get("issued_at"), "issued_at")
        expires_at = _parse_utc_datetime(document.get("expires_at"), "expires_at")
    except ValueError as exc:
        blockers.append(str(exc))
        issued_at = expires_at = current_time
    if expires_at <= current_time:
        blockers.append("authorization record is expired")
    if expires_at <= issued_at:
        blockers.append("expires_at must be after issued_at")
    if int((expires_at - issued_at).total_seconds()) > 24 * 60 * 60:
        blockers.append("authorization TTL must not exceed 86400 seconds")
    return {
        "authorization_file": str(authorization_file),
        "authorization_record_ready": not blockers,
        "authorized_reclaimable_bytes": computed_reclaimable,
        "blockers": sorted(set(blockers)),
        "capacity_plan_file": str(capacity_plan_file),
        "capacity_plan_sha256": plan_sha256,
        "cleanup_executed": False,
        "expected_candidate_paths": sorted(expected_candidate_path),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
    }


@evidence_group.command("target-capacity-cleanup-authorization-check")
@click.option(
    "--authorization-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="JSON authorization record to validate before any target cleanup.",
)
@click.option(
    "--capacity-plan-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.target-capacity-plan JSON output the authorization must bind.",
)
@click.option(
    "--expected-candidate-path",
    multiple=True,
    help="Candidate path that must be explicitly authorized; repeat for each expected path.",
)
@click.option(
    "--now",
    help="UTC timestamp used for deterministic validation tests; defaults to current UTC time.",
)
def evidence_target_capacity_cleanup_authorization_check(
    authorization_file: Path,
    capacity_plan_file: Path,
    expected_candidate_path: tuple[str, ...],
    now: str | None,
) -> None:
    """Validate a target-capacity cleanup authorization without cleanup."""

    command = "evidence.target-capacity-cleanup-authorization-check"
    try:
        document = json.loads(authorization_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliFailure(
            command=command,
            code="target_capacity_cleanup_authorization_rejected",
            message="The target capacity cleanup authorization record is unavailable or invalid JSON.",
            exit_code=5,
        ) from exc
    data = _target_capacity_cleanup_authorization_report(
        document,
        authorization_file=authorization_file,
        capacity_plan_file=capacity_plan_file,
        expected_candidate_path=expected_candidate_path,
        now=now,
    )
    _success(command, data, business_succeeded=False)


@evidence_group.command("read-boundary")
@click.option(
    "--runtime-config",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Absolute path to the root-managed Odoo runtime configuration.",
)
@click.option(
    "--timeout-seconds",
    type=click.FloatRange(min=0, min_open=True),
    default=30.0,
    show_default=True,
)
@click.option(
    "--launcher-diagnostics",
    is_flag=True,
    hidden=True,
    help="Emit Odoo launcher checkpoints and Odoo startup logs to stderr for failed evidence triage.",
)
def evidence_read_boundary(
    runtime_config: Path,
    timeout_seconds: float,
    launcher_diagnostics: bool,
) -> None:
    """Prove the Odoo shell PostgreSQL rollback-only boundary."""

    command = "evidence.read-boundary"
    try:
        config = load_runtime_config(runtime_config)
    except OdooRunnerError as exc:
        raise CliFailure(
            command=command,
            code="runtime_configuration_rejected",
            message="The root-managed Odoo runtime configuration was rejected.",
            exit_code=5,
        ) from exc
    try:
        require_staged_test_evidence_runtime(config)
    except OdooRunnerError as exc:
        raise CliFailure(
            command=command,
            code="evidence_scope_rejected",
            message="DML read-boundary evidence requires a staged test runtime.",
            exit_code=5,
        ) from exc
    identity = _load_release_identity(config.release_root, command=command)
    _assert_runtime_release(config, identity, command=command)
    try:
        evidence = run_read_boundary_evidence(
            config,
            release_digest=identity["manifest_sha256"],
            timeout_seconds=timeout_seconds,
            launcher_diagnostics=launcher_diagnostics,
        )
    except OdooRunnerError as exc:
        if launcher_diagnostics:
            click.echo(str(exc), err=True)
        raise CliFailure(
            command=command,
            code="odoo_read_boundary_evidence_failed",
            message="Odoo did not return verified read-boundary evidence.",
            exit_code=6,
        ) from exc
    _success(
        command,
        {
            "evidence": evidence,
            "release_identity": identity,
            "runtime": config.runtime_identity,
        },
    )


@evidence_group.command("verify-sandbox-write")
@click.option(
    "--evidence-json",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained sandbox write evidence JSON bundle to verify.",
)
@click.option(
    "--assemble-from",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Input manifest whose retained artifacts will be assembled and verified.",
)
def evidence_verify_sandbox_write(
    evidence_json: Path | None,
    assemble_from: Path | None,
) -> None:
    """Verify a retained sandbox write evidence bundle without authorizing production."""

    command = "evidence.verify-sandbox-write"
    if (evidence_json is None) == (assemble_from is None):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_input_required",
            message="Provide exactly one of --evidence-json or --assemble-from.",
            exit_code=2,
        )
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        if assemble_from is not None:
            document = verifier.assemble_path(assemble_from)
            evidence = verifier.verify_document(document)
        else:
            evidence = verifier.verify_path(evidence_json)
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_evidence_rejected",
                message="The sandbox write evidence bundle failed promotion-admission checks.",
                exit_code=6,
            ) from exc
        raise
    if (
        evidence.get("release_sha256") != identity["manifest_sha256"]
        or evidence.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_release_mismatch",
            message="The sandbox write evidence bundle is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "evidence": evidence,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("review-write-promotion")
@click.option(
    "--evidence-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained sandbox write evidence JSON bundle to bind to the promotion review.",
)
@click.option(
    "--candidate-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Non-authorizing write promotion candidate JSON.",
)
def evidence_review_write_promotion(
    evidence_json: Path,
    candidate_json: Path,
) -> None:
    """Review whether sandbox evidence may support staged sandbox promotion."""

    command = "evidence.review-write-promotion"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        review = verifier.review_promotion_candidate_paths(evidence_json, candidate_json)
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="write_promotion_candidate_rejected",
                message="The write promotion candidate is not supported by exact-release sandbox evidence.",
                exit_code=6,
            ) from exc
        raise
    if (
        review.get("release_sha256") != identity["manifest_sha256"]
        or review.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="write_promotion_release_mismatch",
            message="The write promotion review is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "release_identity": identity,
            "promotion_review": review,
        },
        business_succeeded=False,
    )


@evidence_group.command("build-write-promotion-candidate")
@click.option(
    "--evidence-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained sandbox write evidence JSON bundle to bind to the candidate.",
)
@click.option(
    "--target-environment",
    default="sandbox",
    show_default=True,
    help="Promotion target environment. Sandbox evidence can only build sandbox candidates.",
)
@click.option(
    "--target-channel",
    default="staged",
    show_default=True,
    help="Promotion target channel. Sandbox evidence can only build staged candidates.",
)
def evidence_build_write_promotion_candidate(
    evidence_json: Path,
    target_environment: str,
    target_channel: str,
) -> None:
    """Build a non-authorizing promotion candidate from exact-release evidence."""

    command = "evidence.build-write-promotion-candidate"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        candidate = verifier.build_promotion_candidate_path(
            evidence_json,
            target_environment=target_environment,
            target_channel=target_channel,
        )
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="write_promotion_candidate_build_rejected",
                message="The write promotion candidate could not be built from exact-release sandbox evidence.",
                exit_code=6,
            ) from exc
        raise
    release = candidate["release_identity"]
    if (
        release.get("manifest_sha256") != identity["manifest_sha256"]
        or release.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="write_promotion_candidate_release_mismatch",
            message="The write promotion candidate is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "promotion_candidate": candidate,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("build-sandbox-write-artifact")
@click.option(
    "--metadata-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Sandbox write evidence metadata JSON that binds the artifact envelope.",
)
@click.option(
    "--artifact-kind",
    required=True,
    help="Lifecycle artifact kind to build, such as preview_digest or approval_digest.",
)
@click.option(
    "--artifact-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Raw lifecycle artifact payload JSON to wrap.",
)
def evidence_build_sandbox_write_artifact(
    metadata_json: Path,
    artifact_kind: str,
    artifact_json: Path,
) -> None:
    """Build one release-bound sandbox write lifecycle artifact envelope."""

    command = "evidence.build-sandbox-write-artifact"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        artifact = verifier.build_lifecycle_artifact_paths(
            metadata_json,
            artifact_json,
            artifact_kind=artifact_kind,
        )
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_artifact_build_rejected",
                message="The sandbox write lifecycle artifact could not be bound to exact-release metadata.",
                exit_code=6,
            ) from exc
        raise
    release = artifact["release_identity"]
    if (
        release.get("manifest_sha256") != identity["manifest_sha256"]
        or release.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_artifact_release_mismatch",
            message="The sandbox write lifecycle artifact is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "lifecycle_artifact": artifact,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("build-sandbox-write-metadata")
@click.option(
    "--preflight-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained sandbox-write preflight manifest JSON.",
)
@click.option(
    "--registry-receipts-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Registry receipts JSON array for the capability under drill.",
)
@click.option(
    "--lifecycle-receipt-ids-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Lifecycle receipt ids JSON object for non-digest write phases.",
)
def evidence_build_sandbox_write_metadata(
    preflight_json: Path,
    registry_receipts_json: Path,
    lifecycle_receipt_ids_json: Path,
) -> None:
    """Build exact-release sandbox write evidence metadata from retained inputs."""

    command = "evidence.build-sandbox-write-metadata"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        metadata = verifier.build_metadata_paths(
            preflight_json,
            registry_receipts_json,
            lifecycle_receipt_ids_json,
        )
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_metadata_build_rejected",
                message="The sandbox write evidence metadata could not be built from exact-release retained inputs.",
                exit_code=6,
            ) from exc
        raise
    release = metadata["release_identity"]
    if (
        release.get("manifest_sha256") != identity["manifest_sha256"]
        or release.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_metadata_release_mismatch",
            message="The sandbox write evidence metadata is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "metadata": metadata,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("build-sandbox-write-input")
@click.option(
    "--metadata-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Metadata JSON beside standard retained sandbox-write artifacts.",
)
def evidence_build_sandbox_write_input(metadata_json: Path) -> None:
    """Build a verified sandbox-write evidence input manifest from retained files."""

    command = "evidence.build-sandbox-write-input"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        manifest = verifier.build_input_manifest_path(metadata_json)
        evidence = verifier.verify_document(
            verifier.assemble_document(manifest, base_dir=metadata_json.parent)
        )
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_evidence_input_rejected",
                message="The sandbox write evidence input manifest could not be built from retained files.",
                exit_code=6,
            ) from exc
        raise
    if (
        evidence.get("release_sha256") != identity["manifest_sha256"]
        or evidence.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_release_mismatch",
            message="The sandbox write evidence input is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "input_manifest": manifest,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("inspect-sandbox-write-root")
@click.option(
    "--metadata-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Metadata JSON beside standard retained sandbox-write artifacts.",
)
def evidence_inspect_sandbox_write_root(metadata_json: Path) -> None:
    """Inspect a retained sandbox-write evidence root without authorizing production."""

    command = "evidence.inspect-sandbox-write-root"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        report = verifier.inspect_retained_root_path(metadata_json)
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_evidence_root_rejected",
                message="The retained sandbox write evidence root is incomplete or unsafe.",
                exit_code=6,
            ) from exc
        raise
    if (
        report.get("release_sha256") != identity["manifest_sha256"]
        or report.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_release_mismatch",
            message="The retained sandbox write evidence root is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "release_identity": identity,
            "root_report": report,
        },
        business_succeeded=False,
    )


@evidence_group.command("inspect-sandbox-write-pipeline")
@click.option(
    "--metadata-json",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Metadata JSON beside standard retained sandbox-write artifacts.",
)
def evidence_inspect_sandbox_write_pipeline(metadata_json: Path) -> None:
    """Inspect the ordered sandbox-write evidence pipeline without authorizing writes."""

    command = "evidence.inspect-sandbox-write-pipeline"
    identity = _load_release_identity(command=command)
    verifier = _load_sandbox_write_evidence_verifier()
    try:
        report = verifier.inspect_pipeline_path(metadata_json)
    except Exception as exc:
        if exc.__class__.__name__ == "SandboxWriteEvidenceError":
            raise CliFailure(
                command=command,
                code="sandbox_write_evidence_pipeline_rejected",
                message="The retained sandbox write evidence pipeline is incomplete or unsafe.",
                exit_code=6,
            ) from exc
        raise
    if (
        report.get("release_sha256") != identity["manifest_sha256"]
        or report.get("registry_digest") != identity["registry_digest"]
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_evidence_release_mismatch",
            message="The retained sandbox write evidence pipeline is not bound to this exact release.",
            exit_code=6,
        )
    _success(
        command,
        {
            "pipeline_report": report,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


def _load_write_capability_implementation(command: str) -> tuple[Any, Any]:
    try:
        from .odoo.write_handlers import _CAPABILITIES as odoo_write_capabilities
        from .write_service import _ALLOWED_MODELS as allowed_models_by_capability
    except Exception as exc:
        raise CliFailure(
            command=command,
            code="write_capability_runtime_unavailable",
            message="The write capability implementation allowlists are unavailable.",
            exit_code=5,
        ) from exc
    return odoo_write_capabilities, allowed_models_by_capability


def _write_capability_readiness_report(
    capability: Capability,
    *,
    allowed_models_by_capability: Any,
    odoo_write_capabilities: Any,
) -> dict[str, Any]:
    capability_id = capability.id

    data = capability.data
    allowed_models = sorted(allowed_models_by_capability.get(capability_id, ()))
    evidence = data["evidence"]
    evidence_receipts = evidence.get("receipts", [])
    evidence_level = evidence.get("level")
    sandbox_staging_promotion_blockers: list[str] = []
    if evidence_level != "sandbox_verified":
        sandbox_staging_promotion_blockers.append(
            "registry evidence level is not sandbox_verified"
        )
    if not isinstance(evidence_receipts, list) or not evidence_receipts:
        sandbox_staging_promotion_blockers.append(
            "registry has no retained sandbox write evidence receipts"
        )
    if data["enabled_environments"]:
        sandbox_staging_promotion_blockers.append(
            "write capability is already enabled before sandbox evidence review"
        )
    if data.get("staged_environments", []):
        sandbox_staging_promotion_blockers.append(
            "write capability is already staged before exact evidence review"
        )
    checks = {
        "approval_policy_present": (
            data["approval"].get("required") is True
            and isinstance(data["approval"].get("policy"), str)
            and bool(data["approval"]["policy"].strip())
            and isinstance(data["approval"].get("ttl_seconds"), int)
            and 1 <= data["approval"]["ttl_seconds"] <= 900
        ),
        "idempotency_policy_present": (
            data["idempotency"].get("required") is True
            and isinstance(data["idempotency"].get("scope"), str)
            and bool(data["idempotency"]["scope"].strip())
        ),
        "odoo_handler_supported": capability_id in odoo_write_capabilities,
        "production_not_enabled": "production" not in data["enabled_environments"],
        "write_not_enabled": data["enabled_environments"] == [],
        "write_not_staged": data.get("staged_environments", []) == [],
        "recovery_method_present": (
            isinstance(data["recovery"].get("method"), str)
            and bool(data["recovery"]["method"].strip())
        ),
        "service_allowed_models_present": bool(allowed_models),
        "strict_input_schema": (
            data["input_schema"].get("type") == "object"
            and data["input_schema"].get("additionalProperties") is False
        ),
        "strict_output_schema": (
            data["output_schema"].get("type") == "object"
            and data["output_schema"].get("additionalProperties") is False
        ),
    }
    sandbox_drill_admissible = all(checks.values())
    return {
        "allowed_models": allowed_models,
        "capability": {
            "access": data["access"],
            "approval": data["approval"],
            "company_scope": data["company_scope"],
            "enabled_environments": data["enabled_environments"],
            "evidence_level": evidence_level,
            "id": capability_id,
            "idempotency": data["idempotency"],
            "recovery": data["recovery"],
            "risk_level": data["risk_level"],
            "staged_environments": data.get("staged_environments", []),
        },
        "checks": checks,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "sandbox_drill_admissible": sandbox_drill_admissible,
        "sandbox_staging_promotion_blockers": sandbox_staging_promotion_blockers,
        "sandbox_staging_promotion_ready": (
            sandbox_drill_admissible and not sandbox_staging_promotion_blockers
        ),
        "registry_evidence_level": evidence_level,
        "registry_receipt_count": (
            len(evidence_receipts) if isinstance(evidence_receipts, list) else 0
        ),
    }


@evidence_group.command("write-capability-readiness")
@click.option(
    "--capability-id",
    required=True,
    help="Exact registered write capability to check before sandbox drill collection.",
)
def evidence_write_capability_readiness(capability_id: str) -> None:
    """Check static readiness before a real sandbox write evidence drill."""

    command = "evidence.write-capability-readiness"
    identity = _load_release_identity(command=command)
    capabilities = _load_capabilities()
    capability = next((item for item in capabilities if item.id == capability_id), None)
    if capability is None or capability.data["access"] != "write":
        raise CliFailure(
            command=command,
            code="write_capability_rejected",
            message="The readiness gate must target one registered write capability.",
            exit_code=5,
        )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    report = _write_capability_readiness_report(
        capability,
        allowed_models_by_capability=allowed_models_by_capability,
        odoo_write_capabilities=odoo_write_capabilities,
    )
    _success(
        command,
        {
            **report,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


@evidence_group.command("write-capabilities-readiness")
def evidence_write_capabilities_readiness() -> None:
    """Check static readiness for every registered write capability."""

    command = "evidence.write-capabilities-readiness"
    identity = _load_release_identity(command=command)
    capabilities = _load_capabilities()
    write_capabilities = sorted(
        (item for item in capabilities if item.data["access"] == "write"),
        key=lambda item: item.id,
    )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    reports = [
        _write_capability_readiness_report(
            capability,
            allowed_models_by_capability=allowed_models_by_capability,
            odoo_write_capabilities=odoo_write_capabilities,
        )
        for capability in write_capabilities
    ]
    admissible_count = sum(
        1 for report in reports if report["sandbox_drill_admissible"] is True
    )
    _success(
        command,
        {
            "admissible_count": admissible_count,
            "capabilities": reports,
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "release_identity": identity,
            "sandbox_drill_admissible": admissible_count == len(reports),
            "total_write_capabilities": len(reports),
        },
        business_succeeded=False,
    )


def _write_pipeline_readiness_data(evidence_root: Path, *, command: str) -> dict[str, Any]:
    identity = _load_release_identity(command=command)
    if not evidence_root.is_dir():
        raise CliFailure(
            command=command,
            code="sandbox_write_pipeline_root_rejected",
            message="The sandbox write pipeline evidence root is unavailable.",
            exit_code=6,
        )
    capabilities = _load_capabilities()
    write_capabilities = sorted(
        (item for item in capabilities if item.data["access"] == "write"),
        key=lambda item: item.id,
    )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    verifier = _load_sandbox_write_evidence_verifier()
    reports: list[dict[str, Any]] = []
    for capability in write_capabilities:
        static_report = _write_capability_readiness_report(
            capability,
            allowed_models_by_capability=allowed_models_by_capability,
            odoo_write_capabilities=odoo_write_capabilities,
        )
        metadata_path = evidence_root / capability.id / "metadata.json"
        pipeline: dict[str, Any] | None = None
        rejection: str | None = None
        status = "missing"
        if metadata_path.is_file():
            try:
                pipeline = verifier.inspect_pipeline_path(metadata_path)
                if (
                    pipeline.get("capability_id") != capability.id
                    or pipeline.get("release_sha256") != identity["manifest_sha256"]
                    or pipeline.get("registry_digest") != identity["registry_digest"]
                ):
                    status = "rejected"
                    rejection = "pipeline is not bound to this exact release and capability"
                    pipeline = None
                else:
                    status = "verified"
            except Exception as exc:
                if exc.__class__.__name__ == "SandboxWriteEvidenceError":
                    status = "rejected"
                    rejection = str(exc)
                else:
                    raise
        reports.append(
            {
                "capability_id": capability.id,
                "metadata_path": str(metadata_path),
                "pipeline": pipeline,
                "pipeline_ready": status == "verified",
                "rejection": rejection,
                "static_readiness": static_report,
                "status": status,
            }
        )
    verified_count = sum(1 for report in reports if report["status"] == "verified")
    missing_count = sum(1 for report in reports if report["status"] == "missing")
    rejected_count = sum(1 for report in reports if report["status"] == "rejected")
    return {
        "capabilities": reports,
        "evidence_root": str(evidence_root),
        "missing_count": missing_count,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "rejected_count": rejected_count,
        "release_identity": identity,
        "sandbox_pipeline_ready": verified_count == len(reports),
        "total_write_capabilities": len(reports),
        "verified_count": verified_count,
    }


@evidence_group.command("write-pipeline-readiness")
@click.option(
    "--evidence-root",
    required=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="Root containing one <capability_id>/metadata.json retained sandbox evidence directory per write capability.",
)
def evidence_write_pipeline_readiness(evidence_root: Path) -> None:
    """Report which write capabilities have exact-release sandbox pipeline evidence."""

    command = "evidence.write-pipeline-readiness"
    _success(
        command,
        _write_pipeline_readiness_data(evidence_root, command=command),
        business_succeeded=False,
    )


@evidence_group.command("write-evidence-index")
@click.option(
    "--evidence-root",
    required=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="Root containing one <capability_id>/metadata.json retained sandbox evidence directory per write capability.",
)
def evidence_write_evidence_index(evidence_root: Path) -> None:
    """Build a compact handoff index for retained sandbox write evidence."""

    command = "evidence.write-evidence-index"
    readiness = _write_pipeline_readiness_data(evidence_root, command=command)
    indexed_capabilities = []
    for report in readiness["capabilities"]:
        pipeline = report.get("pipeline")
        indexed_capabilities.append(
            {
                "capability_id": report["capability_id"],
                "metadata_path": report["metadata_path"],
                "pipeline_ready": report["pipeline_ready"],
                "pipeline_sha256": _sha256_json(pipeline) if pipeline else None,
                "rejection": report["rejection"],
                "status": report["status"],
            }
        )
    index = {
        "capabilities": indexed_capabilities,
        "evidence_root": readiness["evidence_root"],
        "index_kind": "odoo-accounting-cli-v3.sandbox-write-evidence-index.v1",
        "missing_count": readiness["missing_count"],
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "rejected_count": readiness["rejected_count"],
        "release_identity": readiness["release_identity"],
        "sandbox_pipeline_ready": readiness["sandbox_pipeline_ready"],
        "total_write_capabilities": readiness["total_write_capabilities"],
        "verified_count": readiness["verified_count"],
    }
    _success(command, index, business_succeeded=False)


@evidence_group.command("pi-scenario-report-check")
@click.option(
    "--pi-scenario-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained tools/pi_scenario_gate.py report for the exact release.",
)
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
    help="Current release symlink to verify before trusting the Pi report.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_pi_scenario_report_check(
    pi_scenario_report: Path,
    current_path: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Validate a retained Pi scenario report against the routed release."""

    command = "evidence.pi-scenario-report-check"
    route_report = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_registry_digest=expected_registry_digest,
    )
    pi_report = _pi_scenario_acceptance_report_status(
        pi_scenario_report,
        command=command,
        expected_release_identity=route_report["route_identity"],
    )
    blockers: list[str] = []
    if not route_report["current_route_ready"]:
        blockers.append("current release route is not ready")
    if not pi_report["scenario_acceptance_ready"]:
        blockers.extend(pi_report["blockers"])
    data = {
        "blockers": sorted(set(blockers)),
        "pi_scenario": pi_report,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "route": route_report,
        "scenario_acceptance_ready": not blockers,
    }
    _success(command, data, business_succeeded=False)


@evidence_group.command("pi-trace-capture-check")
@click.option(
    "--trace-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Normalized Pi trace capture JSON to validate before scoring.",
)
@click.option(
    "--attestation-keys",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Trusted HMAC attestation key JSON for the captured Pi traces.",
)
@click.option(
    "--corpus",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("tests/fixtures/pi_scenarios.v1.json"),
    show_default=True,
    help="Frozen Pi scenario corpus.",
)
@click.option(
    "--registry",
    "registry_file",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("registry/capabilities.json"),
    show_default=True,
    help="Exact-release capability registry JSON.",
)
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
    help="Current release symlink to verify before trusting the trace capture.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_pi_trace_capture_check(
    trace_file: Path,
    attestation_keys: Path,
    corpus: Path,
    registry_file: Path,
    current_path: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Validate normalized Pi traces against corpus, registry, attestation, and release."""

    command = "evidence.pi-trace-capture-check"
    route_report = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_registry_digest=expected_registry_digest,
    )
    gate = _load_pi_scenario_gate()
    try:
        trace_document = gate.load_json_document(trace_file)
        corpus_document = gate.load_json_document(corpus)
        registry_document = gate.load_json_document(registry_file)
        key_document = gate.load_json_document(attestation_keys)
        trusted_keys = gate.load_attestation_keys(key_document)
        gate.validate_trace_document(
            trace_document,
            corpus_document,
            registry_document,
            trusted_keys,
            expected_release_sha256=route_report["route_identity"]["package_sha256"],
        )
    except (OSError, ValueError) as exc:
        data = {
            "attestation_keys_path": str(attestation_keys),
            "blockers": [str(exc)],
            "corpus_path": str(corpus),
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "registry_path": str(registry_file),
            "route": route_report,
            "trace_capture_ready": False,
            "trace_file": str(trace_file),
        }
        _success(command, data, business_succeeded=False)
        return
    traces = trace_document.get("traces", [])
    data = {
        "attestation": trace_document.get("attestation"),
        "attestation_keys_path": str(attestation_keys),
        "blockers": [] if route_report["current_route_ready"] else ["current release route is not ready"],
        "capture": trace_document.get("capture"),
        "corpus_path": str(corpus),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "registry_path": str(registry_file),
        "route": route_report,
        "trace_capture_ready": route_report["current_route_ready"],
        "trace_count": len(traces) if isinstance(traces, list) else 0,
        "trace_file": str(trace_file),
        "trace_file_sha256": _sha256_file(trace_file),
    }
    _success(command, data, business_succeeded=False)


@evidence_group.command("goal-remediation-checklist")
@click.option(
    "--goal-readiness-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.goal-readiness JSON output to convert into operator actions.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_goal_remediation_checklist(
    goal_readiness_report: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Render a read-only remediation checklist from a retained goal-readiness report."""

    command = "evidence.goal-remediation-checklist"
    expected_release_identity = {
        "commit": expected_commit,
        "manifest_sha256": expected_manifest_sha256,
        "package_sha256": expected_package_sha256,
        "registry_digest": expected_registry_digest,
        "release": expected_release,
    }
    _success(
        command,
        _goal_remediation_report(
            goal_readiness_report,
            command=command,
            expected_release_identity=(
                expected_release_identity
                if any(value is not None for value in expected_release_identity.values())
                else None
            ),
        ),
        business_succeeded=False,
    )


@evidence_group.command("final-evidence-manifest-assemble")
@click.option(
    "--output-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Final retained evidence manifest JSON to create.",
)
@click.option(
    "--pi-trace-capture-check",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.pi-trace-capture-check JSON.",
)
@click.option(
    "--pi-scenario-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained tools/pi_scenario_gate.py acceptance report JSON.",
)
@click.option(
    "--pi-scenario-report-check",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.pi-scenario-report-check JSON.",
)
@click.option(
    "--sandbox-onboarding-receipt",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.sandbox-onboarding-readiness JSON.",
)
@click.option(
    "--sandbox-provision-authorization",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained sandbox provision authorization JSON.",
)
@click.option(
    "--write-pipeline-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.write-pipeline-readiness JSON.",
)
@click.option(
    "--write-evidence-index",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.write-evidence-index JSON.",
)
@click.option(
    "--goal-readiness-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.goal-readiness JSON.",
)
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
    help="Current release symlink to verify before assembling the manifest.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
@click.option(
    "--overwrite",
    is_flag=True,
    help="Replace an existing output file after all input artifacts pass validation.",
)
def evidence_final_evidence_manifest_assemble(
    output_file: Path,
    pi_trace_capture_check: Path,
    pi_scenario_report: Path,
    pi_scenario_report_check: Path,
    sandbox_onboarding_receipt: Path,
    sandbox_provision_authorization: Path,
    write_pipeline_report: Path,
    write_evidence_index: Path,
    goal_readiness_report: Path,
    current_path: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
    overwrite: bool,
) -> None:
    """Assemble and validate the final retained V3 evidence manifest."""

    command = "evidence.final-evidence-manifest-assemble"
    if output_file.exists() and not overwrite:
        raise CliFailure(
            command=command,
            code="final_evidence_manifest_exists",
            message="The final evidence manifest output already exists.",
            exit_code=5,
        )
    artifact_paths = {
        "goal_readiness_report": goal_readiness_report,
        "pi_scenario_report": pi_scenario_report,
        "pi_scenario_report_check": pi_scenario_report_check,
        "pi_trace_capture_check": pi_trace_capture_check,
        "sandbox_onboarding_receipt": sandbox_onboarding_receipt,
        "sandbox_provision_authorization": sandbox_provision_authorization,
        "write_evidence_index": write_evidence_index,
        "write_pipeline_report": write_pipeline_report,
    }
    duplicate_paths = sorted(
        {
            str(path)
            for path in artifact_paths.values()
            if sum(1 for candidate in artifact_paths.values() if candidate == path) > 1
        }
    )
    if duplicate_paths:
        raise CliFailure(
            command=command,
            code="final_evidence_manifest_rejected",
            message="The final evidence manifest cannot reference duplicate artifacts.",
            exit_code=5,
        )
    missing_artifacts = sorted(
        name for name, path in artifact_paths.items() if not path.is_file()
    )
    if missing_artifacts:
        raise CliFailure(
            command=command,
            code="final_evidence_manifest_rejected",
            message="The final evidence manifest references unavailable artifacts.",
            exit_code=5,
        )
    route_report = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_registry_digest=expected_registry_digest,
    )
    expected_release_identity = {
        "commit": expected_commit or route_report["route_identity"].get("commit"),
        "manifest_sha256": expected_manifest_sha256
        or route_report["route_identity"].get("manifest_sha256"),
        "package_sha256": expected_package_sha256
        or route_report["route_identity"].get("package_sha256"),
        "registry_digest": expected_registry_digest
        or route_report["route_identity"].get("registry_digest"),
        "release": expected_release or route_report["route_identity"].get("release"),
    }
    output_file.parent.mkdir(parents=True, exist_ok=True)
    manifest = _final_evidence_manifest_document(
        artifact_paths,
        manifest_path=output_file,
        release_identity=expected_release_identity,
    )
    output_file.write_text(_json(manifest) + "\n", encoding="utf-8")
    report = _final_evidence_manifest_report(
        output_file,
        command=command,
        expected_release_identity=expected_release_identity,
    )
    blockers = list(report["blockers"])
    if not route_report["current_route_ready"]:
        blockers.append("current release route is not ready")
    report["blockers"] = sorted(set(blockers))
    report["final_evidence_manifest_ready"] = not blockers
    report["route"] = route_report
    report["manifest_created"] = report["final_evidence_manifest_ready"]
    _success(command, report, business_succeeded=False)


@evidence_group.command("final-evidence-manifest-check")
@click.option(
    "--manifest-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Final retained evidence manifest JSON to validate.",
)
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
    help="Current release symlink to verify before trusting the final manifest.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_final_evidence_manifest_check(
    manifest_file: Path,
    current_path: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Validate the final retained V3 evidence handoff manifest."""

    command = "evidence.final-evidence-manifest-check"
    route_report = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_registry_digest=expected_registry_digest,
    )
    expected_release_identity = {
        "commit": expected_commit or route_report["route_identity"].get("commit"),
        "manifest_sha256": expected_manifest_sha256
        or route_report["route_identity"].get("manifest_sha256"),
        "package_sha256": expected_package_sha256
        or route_report["route_identity"].get("package_sha256"),
        "registry_digest": expected_registry_digest
        or route_report["route_identity"].get("registry_digest"),
        "release": expected_release or route_report["route_identity"].get("release"),
    }
    report = _final_evidence_manifest_report(
        manifest_file,
        command=command,
        expected_release_identity=expected_release_identity,
    )
    blockers = list(report["blockers"])
    if not route_report["current_route_ready"]:
        blockers.append("current release route is not ready")
    report["blockers"] = sorted(set(blockers))
    report["final_evidence_manifest_ready"] = not blockers
    report["route"] = route_report
    _success(command, report, business_succeeded=False)


@evidence_group.command("goal-readiness")
@click.option(
    "--pi-scenario-report",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained tools/pi_scenario_gate.py report for the exact release.",
)
@click.option(
    "--sandbox-onboarding-receipt",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained evidence.sandbox-onboarding-readiness JSON receipt.",
)
@click.option(
    "--write-pipeline-report",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained evidence.write-pipeline-readiness JSON report.",
)
@click.option(
    "--write-evidence-index",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Optional retained evidence.write-evidence-index JSON handoff index.",
)
@click.option(
    "--sandbox-provision-authorization-file",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained sandbox provision authorization JSON to validate.",
)
@click.option(
    "--expected-sandbox-database-name",
    help="Sandbox database name the retained onboarding receipt must bind.",
)
@click.option(
    "--expected-source-database-name",
    help="Source database name the sandbox provision authorization must bind.",
)
@click.option(
    "--expected-company",
    multiple=True,
    help="Company scope entry that the sandbox provision authorization must include.",
)
@click.option(
    "--observed-database-name",
    multiple=True,
    help="Database name observed from PostgreSQL catalog; may be repeated.",
)
@click.option(
    "--protected-database-name",
    multiple=True,
    help="Known production or otherwise protected database name.",
)
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
)
@click.option(
    "--capacity-path",
    type=click.Path(path_type=Path),
    default=Path("/"),
    show_default=True,
    help="Path whose filesystem capacity should be checked for sandbox writes.",
)
@click.option(
    "--required-free-bytes",
    type=click.IntRange(min=1),
    default=8 * 1024 * 1024 * 1024,
    show_default=True,
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
@click.option(
    "--now",
    help="UTC timestamp used for deterministic sandbox authorization validation.",
)
def evidence_goal_readiness(
    pi_scenario_report: Path | None,
    sandbox_onboarding_receipt: Path | None,
    write_pipeline_report: Path | None,
    write_evidence_index: Path | None,
    sandbox_provision_authorization_file: Path | None,
    expected_sandbox_database_name: str | None,
    expected_source_database_name: str | None,
    expected_company: tuple[str, ...],
    observed_database_name: tuple[str, ...],
    protected_database_name: tuple[str, ...],
    current_path: Path,
    capacity_path: Path,
    required_free_bytes: int,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
    now: str | None,
) -> None:
    """Aggregate final-goal evidence without executing Odoo or mutating state."""

    command = "evidence.goal-readiness"
    identity = _load_release_identity(command=command)
    expected_release_identity = {
        "commit": expected_commit or identity["commit"],
        "manifest_sha256": expected_manifest_sha256 or identity["manifest_sha256"],
        "package_sha256": expected_package_sha256 or identity["package_sha256"],
        "registry_digest": expected_registry_digest or identity["registry_digest"],
        "release": expected_release or identity["release"],
    }
    route_report = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release_identity["release"],
        expected_commit=expected_release_identity["commit"],
        expected_manifest_sha256=expected_release_identity["manifest_sha256"],
        expected_package_sha256=expected_release_identity["package_sha256"],
        expected_registry_digest=expected_release_identity["registry_digest"],
    )
    try:
        capacity_report = _target_capacity_recheck_report(
            capacity_path,
            required_free_bytes=required_free_bytes,
        )
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="goal_readiness_capacity_rejected",
            message="The goal-readiness capacity path is unavailable.",
            exit_code=5,
        ) from exc
    capabilities = _load_capabilities()
    registry_report = _registry_audit_report(capabilities)
    write_capabilities = sorted(
        (item for item in capabilities if item.data["access"] == "write"),
        key=lambda item: item.id,
    )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    static_write_reports = [
        _write_capability_readiness_report(
            capability,
            allowed_models_by_capability=allowed_models_by_capability,
            odoo_write_capabilities=odoo_write_capabilities,
        )
        for capability in write_capabilities
    ]
    static_write_admissible_count = sum(
        1 for report in static_write_reports if report["sandbox_drill_admissible"] is True
    )
    pi_report = _pi_scenario_acceptance_report_status(
        pi_scenario_report,
        command=command,
        expected_release_identity=expected_release_identity,
    )
    onboarding_report = _sandbox_onboarding_receipt_report(
        sandbox_onboarding_receipt,
        command=command,
        expected_database_name=expected_sandbox_database_name,
        expected_release_identity=expected_release_identity,
    )
    if sandbox_provision_authorization_file is None:
        authorization_report = {
            "authorization_file": None,
            "authorization_record_ready": False,
            "blockers": ["sandbox provision authorization file was not supplied"],
        }
    elif expected_sandbox_database_name is None or expected_source_database_name is None:
        authorization_report = {
            "authorization_file": str(sandbox_provision_authorization_file),
            "authorization_record_ready": False,
            "blockers": [
                "expected sandbox and source database names are required to validate authorization"
            ],
        }
    else:
        try:
            authorization_document = json.loads(
                sandbox_provision_authorization_file.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise CliFailure(
                command=command,
                code="sandbox_provision_authorization_rejected",
                message="The sandbox provision authorization file is unavailable or invalid JSON.",
                exit_code=5,
            ) from exc
        authorization_report = _sandbox_provision_authorization_report(
            authorization_document,
            authorization_file=sandbox_provision_authorization_file,
            expected_sandbox_database_name=expected_sandbox_database_name,
            expected_source_database_name=expected_source_database_name,
            expected_company=expected_company,
            now=now,
        )
    pipeline_report = _write_pipeline_report_status(
        write_pipeline_report,
        command=command,
        expected_release_identity=expected_release_identity,
    )
    write_index_report = _write_evidence_index_status(
        write_evidence_index,
        command=command,
        expected_release_identity=expected_release_identity,
        pipeline_summary=pipeline_report["summary"],
    )
    observed_names = sorted(set(observed_database_name))
    if expected_sandbox_database_name is None:
        sandbox_database_report = {
            "blockers": ["expected sandbox database name was not supplied"],
            "observed_database_names_count": len(observed_names),
            "sandbox_database_name": None,
            "sandbox_database_observed": False,
            "sandbox_database_report": None,
            "sandbox_database_ready": False,
        }
    else:
        candidate_report = _sandbox_database_candidate_report(
            expected_sandbox_database_name,
            protected_names=frozenset(protected_database_name),
            selected_name=expected_sandbox_database_name,
        )
        database_blockers = list(candidate_report["blockers"])
        database_observed = expected_sandbox_database_name in observed_names
        if not observed_names:
            database_blockers.append("database catalog was not supplied")
        elif not database_observed:
            database_blockers.append("sandbox database was not observed in the PostgreSQL catalog")
        sandbox_database_report = {
            "blockers": sorted(set(database_blockers)),
            "observed_database_names_count": len(observed_names),
            "sandbox_database_name": expected_sandbox_database_name,
            "sandbox_database_observed": database_observed,
            "sandbox_database_report": candidate_report,
            "sandbox_database_ready": not database_blockers,
        }
    blockers: list[str] = []
    if not route_report["current_route_ready"]:
        blockers.append("current release route is not ready")
    if not capacity_report["sandbox_write_capacity_ready"]:
        blockers.append("sandbox write capacity gate is not ready")
    if not registry_report["registry_audit_ready"]:
        blockers.append("capability registry audit is not ready")
    if static_write_admissible_count != len(static_write_reports):
        blockers.append("not every write capability is statically admissible for sandbox drills")
    if not pi_report["scenario_acceptance_ready"]:
        blockers.extend(pi_report["blockers"])
    if not onboarding_report["ready"]:
        blockers.extend(onboarding_report["blockers"])
    if not authorization_report["authorization_record_ready"]:
        blockers.extend(authorization_report["blockers"])
    if not pipeline_report["write_pipeline_ready"]:
        blockers.extend(pipeline_report["blockers"])
    if write_index_report["index_ready"] is False:
        blockers.extend(write_index_report["blockers"])
    if not sandbox_database_report["sandbox_database_ready"]:
        blockers.extend(sandbox_database_report["blockers"])
    _success(
        command,
        {
            "blockers": sorted(set(blockers)),
            "capacity": capacity_report,
            "goal_readiness_ready": not blockers,
            "pi_scenario": pi_report,
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "registry": registry_report,
            "release_identity": identity,
            "route": route_report,
            "sandbox_database": sandbox_database_report,
            "sandbox_onboarding": onboarding_report,
            "sandbox_provision_authorization": authorization_report,
            "write_pipeline": pipeline_report,
            "write_evidence_index": write_index_report,
            "write_static_readiness": {
                "admissible_count": static_write_admissible_count,
                "total_write_capabilities": len(static_write_reports),
                "write_static_readiness_ready": (
                    static_write_admissible_count == len(static_write_reports)
                ),
            },
        },
        business_succeeded=False,
    )


@evidence_group.command("sandbox-read-runtime-config-plan")
@click.option("--instance-id", required=True, help="Stable Odoo instance identifier.")
@click.option(
    "--database-name",
    required=True,
    help="Dedicated sandbox database name to bind to the read runtime.",
)
@click.option("--database-uuid", required=True, help="Canonical sandbox database UUID.")
@click.option(
    "--odoo-python",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
)
@click.option("--odoo-python-sha256")
@click.option("--odoo-bin", type=click.Path(path_type=Path, dir_okay=False), required=True)
@click.option("--odoo-bin-sha256")
@click.option(
    "--odoo-config",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
)
@click.option("--odoo-config-sha256")
@click.option(
    "--runtime-config-path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("/etc/odoo-accounting-cli-v3/runtime-sandbox.json"),
    show_default=True,
    help="Canonical read runtime config path the operator will install.",
)
@click.option(
    "--release-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
)
@click.option(
    "--canonical-package-path",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
)
@click.option("--canonical-package-sha256")
@click.option(
    "--measure-existing-files",
    is_flag=True,
    help="Measure SHA-256 from the supplied local filesystem paths when possible.",
)
@click.option(
    "--read-state-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=DEFAULT_SANDBOX_READ_STATE_ROOT,
    show_default=True,
)
@click.option(
    "--secret-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=DEFAULT_SANDBOX_READ_SECRET_ROOT,
    show_default=True,
)
@click.option("--auth-key-id", default="sandbox-read-auth-v1", show_default=True)
@click.option("--receipt-key-id", default="sandbox-read-receipt-v1", show_default=True)
def evidence_sandbox_read_runtime_config_plan(
    instance_id: str,
    database_name: str,
    database_uuid: str,
    odoo_python: Path,
    odoo_python_sha256: str | None,
    odoo_bin: Path,
    odoo_bin_sha256: str | None,
    odoo_config: Path,
    odoo_config_sha256: str | None,
    runtime_config_path: Path,
    release_root: Path,
    canonical_package_path: Path,
    canonical_package_sha256: str | None,
    measure_existing_files: bool,
    read_state_root: Path,
    secret_root: Path,
    auth_key_id: str,
    receipt_key_id: str,
) -> None:
    """Render a secret-free sandbox/staged read runtime installation plan."""

    command = "evidence.sandbox-read-runtime-config-plan"
    identity = _load_release_identity(command=command)
    for option, path in {
        "--odoo-python": odoo_python,
        "--odoo-bin": odoo_bin,
        "--odoo-config": odoo_config,
        "--runtime-config-path": runtime_config_path,
        "--release-root": release_root,
        "--canonical-package-path": canonical_package_path,
        "--read-state-root": read_state_root,
        "--secret-root": secret_root,
    }.items():
        _require_absolute_plan_path(path, command=command, option=option)
    blockers: list[str] = []
    measurements: dict[str, dict[str, Any]] = {}

    def resolve_digest(field: str, path: Path, supplied: str | None) -> str:
        measured: str | None = None
        if measure_existing_files:
            try:
                measured = _sha256_file(path)
            except OSError:
                blockers.append(f"{field} source file cannot be measured")
            else:
                measurements[field] = {
                    "measured_sha256": measured,
                    "path": str(path),
                    "supplied_sha256": supplied,
                }
                if supplied is not None and supplied != measured:
                    blockers.append(f"{field} does not match measured file digest")
        if supplied is None:
            if measured is None:
                blockers.append(f"{field} is required unless it is measured")
                return "0" * 64
            return measured
        return supplied

    resolved_odoo_python_sha256 = resolve_digest(
        "odoo_python_sha256",
        odoo_python,
        odoo_python_sha256,
    )
    resolved_odoo_bin_sha256 = resolve_digest(
        "odoo_bin_sha256",
        odoo_bin,
        odoo_bin_sha256,
    )
    resolved_odoo_config_sha256 = resolve_digest(
        "odoo_config_sha256",
        odoo_config,
        odoo_config_sha256,
    )
    if canonical_package_sha256 is None and not measure_existing_files:
        package_sha256 = str(identity["package_sha256"])
    else:
        package_sha256 = resolve_digest(
            "canonical_package_sha256",
            canonical_package_path,
            canonical_package_sha256,
        )
    try:
        normalized_database_uuid = str(uuid.UUID(database_uuid))
        document = _read_runtime_plan_document(
            instance_id=instance_id,
            environment="sandbox",
            capability_channel="staged",
            database_name=database_name,
            database_uuid=normalized_database_uuid,
            odoo_python=odoo_python,
            odoo_python_sha256=resolved_odoo_python_sha256,
            odoo_bin=odoo_bin,
            odoo_bin_sha256=resolved_odoo_bin_sha256,
            odoo_config=odoo_config,
            odoo_config_sha256=resolved_odoo_config_sha256,
            release_root=release_root,
            canonical_package_path=canonical_package_path,
            canonical_package_sha256=package_sha256,
            auth_state_path=read_state_root / "auth.sqlite3",
            receipt_state_path=read_state_root / "receipt.sqlite3",
            gcov_state_path=read_state_root / "gcov",
            auth_key_id=auth_key_id,
            receipt_key_id=receipt_key_id,
            auth_secret_path=secret_root / "read_auth.hmac",
            receipt_secret_path=secret_root / "read_receipt.hmac",
        )
    except (OdooRunnerError, ValueError) as exc:
        raise CliFailure(
            command=command,
            code="read_runtime_plan_rejected",
            message="The sandbox read runtime plan inputs are invalid.",
        ) from exc
    if re.search(r"(^|[_-])sandbox([_-]|$)", database_name) is None:
        blockers.append("sandbox read runtime database name is not clearly sandbox")
    if document["auth_state_path"] == document["receipt_state_path"]:
        blockers.append("read auth and receipt state paths must differ")
    for field in (
        "odoo_python_sha256",
        "odoo_bin_sha256",
        "odoo_config_sha256",
        "canonical_package_sha256",
    ):
        if _looks_like_placeholder_sha256(str(document[field])):
            blockers.append(f"{field} must be a real measured digest, not a placeholder")
    _success(
        command,
        {
            "blockers": sorted(set(blockers)),
            "document": document,
            "document_sha256": _sha256_json(document),
            "install_actions": [
                "confirm the database is a dedicated sandbox clone and not production",
                f"create {secret_root} as a canonical root-owned directory, not group/world writable",
                "generate two distinct random read role secrets of at least 32 bytes without printing them",
                f"create {read_state_root} as a private service-owned state directory",
                f"install the reviewed JSON document at {runtime_config_path} with root-managed ownership and restrictive mode",
                "load the installed read runtime with the exact release before using it as a write-runtime base",
            ],
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "release_identity": identity,
            "runtime_config_path": str(runtime_config_path),
            "sandbox_read_runtime_configurable": not blockers,
            "source_measurements": measurements,
            "secret_values_included": False,
        },
        business_succeeded=False,
    )


@evidence_group.command("sandbox-database-candidates")
@click.option(
    "--database-name",
    multiple=True,
    help="Database name observed from PostgreSQL catalog; may be provided repeatedly.",
)
@click.option(
    "--protected-database-name",
    multiple=True,
    help="Known production or otherwise protected database name to reject explicitly.",
)
@click.option(
    "--selected-database-name",
    help="Optional operator-selected sandbox candidate to check against the observed catalog.",
)
@click.option(
    "--summary-only",
    is_flag=True,
    help="Omit per-database reports while retaining counts, blockers, and selection status.",
)
def evidence_sandbox_database_candidates(
    database_name: tuple[str, ...],
    protected_database_name: tuple[str, ...],
    selected_database_name: str | None,
    summary_only: bool,
) -> None:
    """Classify observed PostgreSQL databases before choosing a sandbox runtime base."""

    command = "evidence.sandbox-database-candidates"
    observed_names = sorted(set(database_name))
    protected_names = frozenset(protected_database_name)
    candidates = [
        _sandbox_database_candidate_report(
            name,
            protected_names=protected_names,
            selected_name=selected_database_name,
        )
        for name in observed_names
    ]
    eligible = [
        item["name"] for item in candidates if item["eligible_for_sandbox_runtime_plan"]
    ]
    blocker_counts: dict[str, int] = {}
    for item in candidates:
        for blocker in item["blockers"]:
            blocker_counts[blocker] = blocker_counts.get(blocker, 0) + 1
    selected_report = next(
        (item for item in candidates if item["name"] == selected_database_name),
        None,
    )
    blockers: list[str] = []
    if not observed_names:
        blockers.append("database catalog is empty or was not supplied")
    if selected_database_name is not None and selected_database_name not in observed_names:
        blockers.append("selected database was not observed in the PostgreSQL catalog")
    if selected_database_name is not None:
        if selected_report is not None and selected_report["blockers"]:
            blockers.append("selected database is not eligible for sandbox runtime plan")
    if not eligible:
        blockers.append("no eligible clearly named dedicated sandbox database was observed")
    data: dict[str, Any] = {
        "blockers": sorted(set(blockers)),
        "candidate_summary": {
            "blocker_counts": dict(sorted(blocker_counts.items())),
            "candidate_count": len(candidates),
            "eligible_count": len(eligible),
            "rejected_count": len(candidates) - len(eligible),
        },
        "eligible_database_names": eligible,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "selected_database": selected_report,
        "selected_database_name": selected_database_name,
        "selected_database_eligible": (
            selected_database_name in eligible if selected_database_name else None
        ),
        "sandbox_database_selection_ready": not blockers,
    }
    if not summary_only:
        data["candidates"] = candidates
    _success(command, data, business_succeeded=False)


@evidence_group.command("sandbox-onboarding-readiness")
@click.option(
    "--sandbox-database-name",
    required=True,
    help="Dedicated sandbox database expected for write onboarding.",
)
@click.option(
    "--source-database-name",
    required=True,
    help="Authorized source database expected for sandbox provisioning.",
)
@click.option(
    "--observed-database-name",
    multiple=True,
    help="Database name observed from PostgreSQL catalog; may be repeated.",
)
@click.option(
    "--protected-database-name",
    multiple=True,
    help="Known production or otherwise protected database name.",
)
@click.option(
    "--authorization-file",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Optional sandbox provision authorization JSON to validate.",
)
@click.option(
    "--expected-company",
    multiple=True,
    help="Company scope entry that the authorization must include.",
)
@click.option(
    "--capacity-path",
    type=click.Path(path_type=Path),
    default=Path("/"),
    show_default=True,
    help="Path whose filesystem capacity should be checked.",
)
@click.option(
    "--required-free-bytes",
    type=click.IntRange(min=1),
    default=8 * 1024 * 1024 * 1024,
    show_default=True,
)
@click.option(
    "--current-path",
    type=click.Path(path_type=Path),
    default=Path("/opt/odoo-accounting-cli-v3/current"),
    show_default=True,
    help="Current release symlink to verify as part of onboarding.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
@click.option(
    "--now",
    help="UTC timestamp used for deterministic authorization validation.",
)
def evidence_sandbox_onboarding_readiness(
    sandbox_database_name: str,
    source_database_name: str,
    observed_database_name: tuple[str, ...],
    protected_database_name: tuple[str, ...],
    authorization_file: Path | None,
    expected_company: tuple[str, ...],
    capacity_path: Path,
    required_free_bytes: int,
    current_path: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
    now: str | None,
) -> None:
    """Summarize read-only gates before sandbox write onboarding can continue."""

    command = "evidence.sandbox-onboarding-readiness"
    blockers: list[str] = []
    protected_names = frozenset(protected_database_name)
    observed_names = sorted(set(observed_database_name))
    database_report = _sandbox_database_candidate_report(
        sandbox_database_name,
        protected_names=protected_names,
        selected_name=sandbox_database_name,
    )
    database_observed = sandbox_database_name in observed_names
    if database_report["blockers"]:
        blockers.append("sandbox database name is not eligible")
    if not database_observed:
        blockers.append("sandbox database was not observed in the PostgreSQL catalog")
    try:
        capacity_report = _target_capacity_recheck_report(
            capacity_path,
            required_free_bytes=required_free_bytes,
        )
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="sandbox_onboarding_readiness_rejected",
            message="The sandbox onboarding capacity path is unavailable.",
            exit_code=5,
        ) from exc
    if not capacity_report["sandbox_write_capacity_ready"]:
        blockers.append("sandbox write capacity gate is not ready")
    route_report = _current_route_report(
        current_path,
        command=command,
        expected_release=expected_release,
        expected_commit=expected_commit,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_package_sha256=expected_package_sha256,
        expected_registry_digest=expected_registry_digest,
    )
    if not route_report["current_route_ready"]:
        blockers.append("current release route is not ready")
    authorization_report: dict[str, Any]
    if authorization_file is None:
        blockers.append("sandbox provision authorization file was not supplied")
        authorization_report = {
            "authorization_file": None,
            "authorization_record_ready": False,
            "blockers": ["sandbox provision authorization file was not supplied"],
        }
    else:
        try:
            document = json.loads(authorization_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            blockers.append("sandbox provision authorization file is unavailable or invalid JSON")
            authorization_report = {
                "authorization_file": str(authorization_file),
                "authorization_record_ready": False,
                "blockers": [
                    "sandbox provision authorization file is unavailable or invalid JSON"
                ],
            }
        else:
            authorization_report = _sandbox_provision_authorization_report(
                document,
                authorization_file=authorization_file,
                expected_sandbox_database_name=sandbox_database_name,
                expected_source_database_name=source_database_name,
                expected_company=expected_company,
                now=now,
            )
            if not authorization_report["authorization_record_ready"]:
                blockers.append("sandbox provision authorization record is not ready")
    data = {
        "authorization": authorization_report,
        "blockers": sorted(set(blockers)),
        "capacity": capacity_report,
        "database": {
            "observed_database_names_count": len(observed_names),
            "sandbox_database_name": sandbox_database_name,
            "sandbox_database_observed": database_observed,
            "sandbox_database_report": database_report,
            "source_database_name": source_database_name,
        },
        "next_required_actions": [
            action
            for condition, action in (
                (
                    not route_report["current_route_ready"],
                    "fix current release route and rerun release current-route",
                ),
                (
                    not capacity_report["sandbox_write_capacity_ready"],
                    "free or add disk capacity and rerun evidence target-capacity-recheck",
                ),
                (
                    not database_observed,
                    "create or select the dedicated sandbox database and rerun sandbox-database-candidates",
                ),
                (
                    not authorization_report["authorization_record_ready"],
                    "save a valid sandbox provision authorization JSON and rerun sandbox-provision-authorization-check",
                ),
            )
            if condition
        ],
        "postgresql_write_performed": False,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "route": route_report,
        "sandbox_onboarding_ready": not blockers,
    }
    _success(command, data, business_succeeded=False)


@evidence_group.command("sandbox-onboarding-receipt-check")
@click.option(
    "--onboarding-receipt",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained evidence.sandbox-onboarding-readiness JSON receipt to validate.",
)
@click.option(
    "--expected-sandbox-database-name",
    help="Sandbox database name the retained onboarding receipt must bind.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_sandbox_onboarding_receipt_check(
    onboarding_receipt: Path,
    expected_sandbox_database_name: str | None,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Validate a retained sandbox onboarding readiness receipt without writes."""

    command = "evidence.sandbox-onboarding-receipt-check"
    expected_release_identity = None
    if any(
        item is not None
        for item in (
            expected_release,
            expected_commit,
            expected_manifest_sha256,
            expected_package_sha256,
            expected_registry_digest,
        )
    ):
        expected_release_identity = {
            "commit": expected_commit,
            "manifest_sha256": expected_manifest_sha256,
            "package_sha256": expected_package_sha256,
            "registry_digest": expected_registry_digest,
            "release": expected_release,
        }
    report = _sandbox_onboarding_receipt_report(
        onboarding_receipt,
        command=command,
        expected_database_name=expected_sandbox_database_name,
        expected_release_identity=expected_release_identity,
    )
    _success(
        command,
        {
            "onboarding": report,
            "postgresql_write_performed": False,
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "sandbox_write_preflight_receipt_acceptable": report["ready"],
        },
        business_succeeded=False,
    )


@evidence_group.command("sandbox-database-provision-plan")
@click.option(
    "--sandbox-database-name",
    required=True,
    help="Proposed dedicated sandbox database name to create or clone outside this CLI.",
)
@click.option(
    "--source-database-name",
    required=True,
    help="Existing database proposed as the clone source.",
)
@click.option(
    "--protected-database-name",
    multiple=True,
    help="Known production or otherwise protected database name.",
)
@click.option(
    "--expected-database-filter",
    help="Expected Odoo db-filter for the sandbox service; defaults to the exact sandbox name.",
)
@click.option(
    "--authorization-recorded",
    is_flag=True,
    help="Declare that explicit operator authorization for sandbox provisioning has been recorded.",
)
def evidence_sandbox_database_provision_plan(
    sandbox_database_name: str,
    source_database_name: str,
    protected_database_name: tuple[str, ...],
    expected_database_filter: str | None,
    authorization_recorded: bool,
) -> None:
    """Plan, but never execute, creation of a dedicated Odoo write sandbox database."""

    command = "evidence.sandbox-database-provision-plan"
    protected_names = frozenset(protected_database_name)
    expected_filter = (
        expected_database_filter
        if expected_database_filter is not None
        else _expected_sandbox_database_filter(sandbox_database_name)
    )
    required_filter = _expected_sandbox_database_filter(sandbox_database_name)
    sandbox_report = _sandbox_database_candidate_report(
        sandbox_database_name,
        protected_names=protected_names,
        selected_name=sandbox_database_name,
    )
    source_report = _sandbox_database_candidate_report(
        source_database_name,
        protected_names=protected_names,
        selected_name=None,
    )
    blockers: list[str] = []
    warnings: list[str] = []
    if not authorization_recorded:
        blockers.append(
            "explicit authorization to create or clone the sandbox database has not been recorded"
        )
    if sandbox_report["blockers"]:
        blockers.append("sandbox database name is not eligible for provisioning")
    if sandbox_database_name == source_database_name:
        blockers.append("sandbox database name must differ from source database name")
    if expected_filter != required_filter:
        blockers.append("expected database filter must match the exact sandbox database name")
    if source_database_name in protected_names:
        warnings.append(
            "source database is explicitly protected; clone only from an authorized read-only snapshot"
        )
    if _database_name_looks_transient(source_database_name):
        warnings.append("source database looks transient or test-generated")
    data: dict[str, Any] = {
        "authorization_recorded": authorization_recorded,
        "authorization_required_before_database_creation": True,
        "blockers": sorted(set(blockers)),
        "expected_database_filter": expected_filter,
        "operator_actions": [
            "record explicit authorization naming the sandbox database, source database, company scope, and retention window",
            "verify the source database identity, database UUID, company scope, addons path, and filestore before cloning",
            "create or clone the PostgreSQL sandbox database outside this CLI using the approved runbook",
            "create an isolated sandbox filestore outside this CLI; do not share mutable production filestore paths",
            f"start the sandbox Odoo service with db-filter {required_filter}",
            "measure Odoo python, odoo-bin, config, release package, and database UUID after the sandbox service starts",
            "rerun evidence sandbox-database-candidates against the real PostgreSQL catalog",
            "generate the read runtime plan with evidence sandbox-read-runtime-config-plan --measure-existing-files",
        ],
        "plan": {
            "database_filter": required_filter,
            "sandbox_database_name": sandbox_database_name,
            "source_database_name": source_database_name,
        },
        "postgresql_write_performed": False,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "sandbox_database_provision_ready": not blockers,
        "sandbox_database_report": sandbox_report,
        "source_database_report": source_report,
        "warnings": sorted(set(warnings)),
    }
    _success(command, data, business_succeeded=False)


@evidence_group.command("sandbox-provision-authorization-template")
@click.option(
    "--sandbox-database-name",
    required=True,
    help="Dedicated sandbox database name the authorization will bind.",
)
@click.option(
    "--source-database-name",
    required=True,
    help="Source database name the authorization will bind.",
)
@click.option(
    "--company",
    "company_scope",
    multiple=True,
    required=True,
    help="Authorized company scope; repeat for multiple companies.",
)
@click.option(
    "--operator-id",
    required=True,
    help="Human/operator identity that will be accountable for provisioning.",
)
@click.option(
    "--retention-until",
    required=True,
    help="UTC timestamp naming how long the sandbox evidence/data must be retained.",
)
@click.option(
    "--ttl-seconds",
    type=click.IntRange(min=1, max=24 * 60 * 60),
    default=3600,
    show_default=True,
    help="Authorization validity window.",
)
@click.option(
    "--issued-at",
    help="UTC issue timestamp for deterministic review; defaults to current UTC time.",
)
def evidence_sandbox_provision_authorization_template(
    sandbox_database_name: str,
    source_database_name: str,
    company_scope: tuple[str, ...],
    operator_id: str,
    retention_until: str,
    ttl_seconds: int,
    issued_at: str | None,
) -> None:
    """Render a sandbox provisioning authorization JSON template without approving it."""

    command = "evidence.sandbox-provision-authorization-template"
    blockers: list[str] = []
    if not _database_name_is_clear_sandbox(sandbox_database_name):
        blockers.append("sandbox database name is not clearly sandbox")
    if _database_name_looks_production(sandbox_database_name):
        blockers.append("sandbox database name looks production-like")
    if sandbox_database_name == source_database_name:
        blockers.append("sandbox database name must differ from source database name")
    if any(not value for value in company_scope):
        blockers.append("company scope entries must be non-empty")
    try:
        issued = (
            _parse_utc_datetime(issued_at, "issued_at")
            if issued_at is not None
            else datetime.now(timezone.utc)
        )
        retention = _parse_utc_datetime(retention_until, "retention_until")
    except ValueError as exc:
        blockers.append(str(exc))
        issued = retention = datetime.now(timezone.utc)
    expires = issued + timedelta(seconds=ttl_seconds)
    if retention <= issued:
        blockers.append("retention_until must be after issued_at")
    summary = {
        "allowed_actions": [
            "create_or_clone_postgresql_database",
            "create_isolated_filestore",
            "start_sandbox_odoo_service",
            "measure_runtime_identity",
        ],
        "company_scope": sorted(set(company_scope)),
        "operator_id": operator_id,
        "retention_until": _format_utc_datetime(retention),
        "sandbox_database_name": sandbox_database_name,
        "source_database_name": source_database_name,
    }
    document = {
        "expires_at": _format_utc_datetime(expires),
        "immutable_summary": summary,
        "immutable_summary_sha256": _sha256_json(summary),
        "issued_at": _format_utc_datetime(issued),
        "purpose": "sandbox_database_provision",
        "schema_version": 1,
    }
    data = {
        "authorization_record_template": document,
        "authorization_template_ready": not blockers,
        "blockers": sorted(set(blockers)),
        "business_write_authorized": False,
        "postgresql_write_performed": False,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "save_path_recommendation": "/etc/odoo-accounting-cli-v3/sandbox-provision-authorization.json",
        "template_only_not_authorized": True,
        "validation_command": (
            "Run the exact immutable release member with validation_command_args; "
            "do not invoke the CLI through /opt/odoo-accounting-cli-v3/current/bin."
        ),
        "validation_command_args": [
            "evidence",
            "sandbox-provision-authorization-check",
            "--authorization-file",
            "/etc/odoo-accounting-cli-v3/sandbox-provision-authorization.json",
            "--expected-sandbox-database-name",
            sandbox_database_name,
            "--expected-source-database-name",
            source_database_name,
            *[
                item
                for company in sorted(set(company_scope))
                for item in ("--expected-company", company)
            ],
        ],
    }
    _success(command, data, business_succeeded=False)


def _sandbox_provision_authorization_report(
    document: Any,
    *,
    authorization_file: Path,
    expected_sandbox_database_name: str,
    expected_source_database_name: str,
    expected_company: tuple[str, ...],
    now: str | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    if not isinstance(document, dict):
        blockers.append("authorization record must be a JSON object")
        document = {}
    current_time = datetime.now(timezone.utc)
    if now is not None:
        try:
            current_time = _parse_utc_datetime(now, "now")
        except ValueError:
            blockers.append("now must be a UTC timestamp")
    summary = document.get("immutable_summary")
    if not isinstance(summary, dict):
        blockers.append("immutable_summary must be a JSON object")
        summary = {}
    expected_summary_sha256 = _sha256_json(summary)
    supplied_summary_sha256 = document.get("immutable_summary_sha256")
    if supplied_summary_sha256 != expected_summary_sha256:
        blockers.append("immutable_summary_sha256 does not match immutable_summary")
    if document.get("schema_version") != 1:
        blockers.append("schema_version must be 1")
    if document.get("purpose") != "sandbox_database_provision":
        blockers.append("purpose must be sandbox_database_provision")
    if summary.get("sandbox_database_name") != expected_sandbox_database_name:
        blockers.append("sandbox database name is not bound to this authorization")
    if summary.get("source_database_name") != expected_source_database_name:
        blockers.append("source database name is not bound to this authorization")
    company_scope = summary.get("company_scope")
    if (
        not isinstance(company_scope, list)
        or not company_scope
        or any(not isinstance(item, str) or not item for item in company_scope)
    ):
        blockers.append("company_scope must be a non-empty list of company names")
        company_scope_set: set[str] = set()
    else:
        company_scope_set = set(company_scope)
    missing_companies = sorted(set(expected_company) - company_scope_set)
    if missing_companies:
        blockers.append("expected company scope is not fully authorized")
    allowed_actions = summary.get("allowed_actions")
    required_actions = {
        "create_or_clone_postgresql_database",
        "create_isolated_filestore",
        "start_sandbox_odoo_service",
        "measure_runtime_identity",
    }
    if (
        not isinstance(allowed_actions, list)
        or any(not isinstance(item, str) or not item for item in allowed_actions)
    ):
        blockers.append("allowed_actions must be a list of action names")
        allowed_action_set: set[str] = set()
    else:
        allowed_action_set = set(allowed_actions)
    if not required_actions.issubset(allowed_action_set):
        blockers.append("authorization does not include every required sandbox provisioning action")
    if not _database_name_is_clear_sandbox(expected_sandbox_database_name):
        blockers.append("expected sandbox database name is not clearly sandbox")
    if _database_name_looks_production(expected_sandbox_database_name):
        blockers.append("expected sandbox database name looks production-like")
    if expected_sandbox_database_name == expected_source_database_name:
        blockers.append("sandbox database name must differ from source database name")
    try:
        issued_at = _parse_utc_datetime(document.get("issued_at"), "issued_at")
        expires_at = _parse_utc_datetime(document.get("expires_at"), "expires_at")
    except ValueError as exc:
        blockers.append(str(exc))
        issued_at = expires_at = current_time
    if expires_at <= current_time:
        blockers.append("authorization record is expired")
    if expires_at <= issued_at:
        blockers.append("expires_at must be after issued_at")
    ttl_seconds = int((expires_at - issued_at).total_seconds())
    if ttl_seconds > 24 * 60 * 60:
        blockers.append("authorization TTL must not exceed 86400 seconds")
    if summary.get("retention_until") is None:
        warnings.append("retention_until is not recorded in immutable_summary")
    return {
        "authorization_file": str(authorization_file),
        "authorization_record_ready": not blockers,
        "blockers": sorted(set(blockers)),
        "business_write_authorized": False,
        "cleanup_executed": False,
        "expected_company_scope": sorted(expected_company),
        "immutable_summary_sha256": expected_summary_sha256,
        "postgresql_write_performed": False,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "sandbox_database_name": expected_sandbox_database_name,
        "source_database_name": expected_source_database_name,
        "warnings": sorted(set(warnings)),
    }


@evidence_group.command("sandbox-provision-authorization-check")
@click.option(
    "--authorization-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="JSON authorization record to validate before sandbox database provisioning.",
)
@click.option(
    "--expected-sandbox-database-name",
    required=True,
    help="Sandbox database name the authorization must bind.",
)
@click.option(
    "--expected-source-database-name",
    required=True,
    help="Source database name the authorization must bind.",
)
@click.option(
    "--expected-company",
    multiple=True,
    help="Company scope entry that must be present; repeat for every expected company.",
)
@click.option(
    "--now",
    help="UTC timestamp used for deterministic validation tests; defaults to current UTC time.",
)
def evidence_sandbox_provision_authorization_check(
    authorization_file: Path,
    expected_sandbox_database_name: str,
    expected_source_database_name: str,
    expected_company: tuple[str, ...],
    now: str | None,
) -> None:
    """Validate a sandbox provisioning authorization record without provisioning."""

    command = "evidence.sandbox-provision-authorization-check"
    try:
        document = json.loads(authorization_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliFailure(
            command=command,
            code="sandbox_provision_authorization_rejected",
            message="The sandbox provisioning authorization record is unavailable or invalid JSON.",
            exit_code=5,
        ) from exc
    data = _sandbox_provision_authorization_report(
        document,
        authorization_file=authorization_file,
        expected_sandbox_database_name=expected_sandbox_database_name,
        expected_source_database_name=expected_source_database_name,
        expected_company=expected_company,
        now=now,
    )
    _success(command, data, business_succeeded=False)


@evidence_group.command("write-runtime-config-plan")
@click.option(
    "--base-runtime-config",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Existing read runtime config that the write runtime will bind to.",
)
@click.option(
    "--write-runtime-config",
    type=click.Path(path_type=Path, dir_okay=False),
    default=DEFAULT_WRITE_RUNTIME_CONFIG,
    show_default=True,
    help="Canonical write runtime config path the operator will install.",
)
@click.option(
    "--write-state-path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=DEFAULT_SANDBOX_WRITE_STATE,
    show_default=True,
    help="Dedicated write operation SQLite state path.",
)
@click.option(
    "--secret-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=DEFAULT_SANDBOX_SECRET_ROOT,
    show_default=True,
    help="Directory where six write role secrets will be generated by the operator.",
)
@click.option(
    "--write-execution-mode",
    type=click.Choice(["disabled", "sandbox_staged", "enabled"]),
    default="sandbox_staged",
    show_default=True,
)
@click.option("--key-id-prefix", default="sandbox", show_default=True)
@click.option("--issuer-prefix", default="odoo-v3-sandbox", show_default=True)
@click.option(
    "--socket-path",
    default="/run/odoo-accounting-cli-v3/effect-finalizer.sock",
    show_default=True,
)
@click.option("--socket-owner-uid", type=int, default=0, show_default=True)
@click.option("--socket-group-gid", type=click.IntRange(min=1), required=True)
@click.option("--socket-mode", type=click.IntRange(min=0, max=0o777), default=0o660)
@click.option("--finalizer-service-uid", type=click.IntRange(min=1), required=True)
@click.option("--finalizer-service-gid", type=click.IntRange(min=1), required=True)
@click.option(
    "--finalizer-systemd-unit",
    default="odoo-accounting-cli-v3-effect-finalizer.service",
    show_default=True,
)
@click.option("--attestation-key-id", required=True)
@click.option("--guard-installation-id", required=True)
@click.option("--database-oid", type=click.IntRange(min=1), required=True)
@click.option(
    "--handoff-idle-timeout-seconds",
    type=click.FloatRange(min=90.0, max=120.0),
    default=100.0,
    show_default=True,
)
@click.option(
    "--request-io-timeout-seconds",
    type=click.FloatRange(min=0.05, max=30.0),
    default=5.0,
    show_default=True,
)
@click.option(
    "--max-request-bytes",
    type=click.IntRange(min=1024, max=65536),
    default=16384,
    show_default=True,
)
@click.option(
    "--max-response-bytes",
    type=click.IntRange(min=1024, max=65536),
    default=16384,
    show_default=True,
)
@click.option(
    "--require-root-owner/--allow-non-root-owner",
    default=True,
    show_default=True,
    help="Require root-managed base runtime files; disable only for local dry-run tests.",
)
def evidence_write_runtime_config_plan(
    base_runtime_config: Path,
    write_runtime_config: Path,
    write_state_path: Path,
    secret_root: Path,
    write_execution_mode: str,
    key_id_prefix: str,
    issuer_prefix: str,
    socket_path: str,
    socket_owner_uid: int,
    socket_group_gid: int,
    socket_mode: int,
    finalizer_service_uid: int,
    finalizer_service_gid: int,
    finalizer_systemd_unit: str,
    attestation_key_id: str,
    guard_installation_id: str,
    database_oid: int,
    handoff_idle_timeout_seconds: float,
    request_io_timeout_seconds: float,
    max_request_bytes: int,
    max_response_bytes: int,
    require_root_owner: bool,
) -> None:
    """Render a secret-free schema-v2 write runtime installation plan."""

    command = "evidence.write-runtime-config-plan"
    base_runtime_config = _require_absolute_plan_path(
        base_runtime_config,
        command=command,
        option="--base-runtime-config",
    )
    write_runtime_config = _require_absolute_plan_path(
        write_runtime_config,
        command=command,
        option="--write-runtime-config",
    )
    write_state_path = _require_absolute_plan_path(
        write_state_path,
        command=command,
        option="--write-state-path",
    )
    secret_root = _require_absolute_plan_path(
        secret_root,
        command=command,
        option="--secret-root",
    )
    try:
        base_runtime = load_runtime_config(
            base_runtime_config,
            require_root_owner=require_root_owner,
        )
    except OdooRunnerError as exc:
        raise CliFailure(
            command=command,
            code="base_runtime_rejected",
            message="The base read runtime configuration is not loadable.",
        ) from exc

    blockers: list[str] = []
    if write_execution_mode == "sandbox_staged" and (
        base_runtime.environment != "sandbox"
        or base_runtime.capability_channel != "staged"
    ):
        blockers.append("sandbox_staged write runtime requires a staged sandbox base runtime")
    if (
        write_execution_mode == "enabled"
        and base_runtime.capability_channel != "enabled"
    ):
        blockers.append("enabled write runtime requires an enabled base runtime")
    if write_runtime_config == base_runtime_config:
        blockers.append("write runtime config path must differ from base runtime config")
    if write_state_path in {
        base_runtime.auth_state_path,
        base_runtime.receipt_state_path,
    }:
        blockers.append("write state path must differ from read state paths")
    document = _write_runtime_plan_document(
        base_runtime_config=base_runtime_config,
        write_state_path=write_state_path,
        secret_root=secret_root,
        write_execution_mode=write_execution_mode,
        key_id_prefix=key_id_prefix,
        issuer_prefix=issuer_prefix,
        socket_path=socket_path,
        socket_owner_uid=socket_owner_uid,
        socket_group_gid=socket_group_gid,
        socket_mode=socket_mode,
        finalizer_service_uid=finalizer_service_uid,
        finalizer_service_gid=finalizer_service_gid,
        finalizer_systemd_unit=finalizer_systemd_unit,
        attestation_key_id=attestation_key_id,
        guard_installation_id=guard_installation_id,
        database_oid=database_oid,
        handoff_idle_timeout_seconds=handoff_idle_timeout_seconds,
        request_io_timeout_seconds=request_io_timeout_seconds,
        max_request_bytes=max_request_bytes,
        max_response_bytes=max_response_bytes,
    )
    _success(
        command,
        {
            "base_runtime_identity": base_runtime.runtime_identity,
            "blockers": sorted(set(blockers)),
            "document": document,
            "document_sha256": _sha256_json(document),
            "install_actions": [
                "review and confirm the dedicated sandbox database, service UID/GID, finalizer socket, guard installation ID, and database OID",
                f"create {secret_root} as a canonical root-owned directory, not group/world writable",
                "generate six distinct random write role secrets of at least 32 bytes without printing them",
                f"create {write_state_path.parent} as a private service-owned state directory",
                f"install the reviewed JSON document at {write_runtime_config} with root-managed ownership and restrictive mode",
                "rerun evidence sandbox-write-environment-audit with the canonical write runtime config and retained evidence root",
            ],
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "schema_version": WRITE_RUNTIME_SCHEMA_VERSION,
            "secret_values_included": False,
            "write_runtime_config_path": str(write_runtime_config),
            "write_runtime_configurable": not blockers,
        },
        business_succeeded=False,
    )


@evidence_group.command("sandbox-write-environment-audit")
@click.option(
    "--write-runtime-config",
    type=click.Path(path_type=Path, dir_okay=False),
    default=DEFAULT_WRITE_RUNTIME_CONFIG,
    show_default=True,
    help="Root-managed write runtime configuration to inspect without executing writes.",
)
@click.option(
    "--evidence-root",
    type=click.Path(path_type=Path, file_okay=False),
    help="Optional existing root-owned directory intended for retained sandbox write evidence.",
)
@click.option(
    "--onboarding-receipt",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Optional retained evidence.sandbox-onboarding-readiness JSON receipt to bind before write drills.",
)
@click.option(
    "--min-free-bytes",
    type=click.IntRange(min=1),
    default=8 * 1024 * 1024 * 1024,
    show_default=True,
    help="Minimum free bytes required before starting sandbox write evidence collection.",
)
@click.option(
    "--summary-only",
    is_flag=True,
    help="Omit per-capability readiness details while retaining counts and blockers.",
)
def evidence_sandbox_write_environment_audit(
    write_runtime_config: Path,
    evidence_root: Path | None,
    onboarding_receipt: Path | None,
    min_free_bytes: int,
    summary_only: bool,
) -> None:
    """Read-only inventory before planning real sandbox write drills."""

    command = "evidence.sandbox-write-environment-audit"
    identity = _load_release_identity(command=command)
    capabilities = _load_capabilities()
    write_capabilities = sorted(
        (item for item in capabilities if item.data["access"] == "write"),
        key=lambda item: item.id,
    )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    capability_reports = [
        _write_capability_readiness_report(
            capability,
            allowed_models_by_capability=allowed_models_by_capability,
            odoo_write_capabilities=odoo_write_capabilities,
        )
        for capability in write_capabilities
    ]
    sandbox_drill_admissible_count = sum(
        1 for report in capability_reports if report["sandbox_drill_admissible"]
    )
    sandbox_staging_promotion_ready_count = sum(
        1 for report in capability_reports if report["sandbox_staging_promotion_ready"]
    )
    not_staging_ready_capability_ids = [
        report["capability"]["id"]
        for report in capability_reports
        if not report["sandbox_staging_promotion_ready"]
    ]
    staging_promotion_blockers = sorted(
        {
            blocker
            for report in capability_reports
            for blocker in report["sandbox_staging_promotion_blockers"]
        }
    )
    runtime_report: dict[str, Any]
    evidence_root_report: dict[str, Any]
    onboarding_report: dict[str, Any]
    runtime_ready = False
    try:
        config = load_write_runtime_config(write_runtime_config)
    except WriteRuntimeError as exc:
        runtime_report = {
            "blockers": [str(exc)],
            "database_name": None,
            "database_uuid": None,
            "path": str(write_runtime_config),
            "ready": False,
            "runtime_identity": None,
            "status": "invalid" if write_runtime_config.exists() else "missing",
            "write_execution_mode": None,
        }
        evidence_root_report = _audit_sandbox_write_evidence_root(
            evidence_root,
            release_root=Path(__file__).resolve().parents[2],
            minimum_free_bytes=min_free_bytes,
        )
        onboarding_report = _sandbox_onboarding_receipt_report(
            onboarding_receipt,
            command=command,
        )
    else:
        blockers: list[str] = []
        database_name = config.base_runtime.database_name
        if config.write_execution_mode != "sandbox_staged":
            blockers.append("write runtime execution mode is not sandbox_staged")
        if config.base_runtime.environment != "sandbox":
            blockers.append("write runtime base environment is not sandbox")
        if config.base_runtime.capability_channel != "staged":
            blockers.append("write runtime capability channel is not staged")
        if re.search(r"(^|[_-])sandbox([_-]|$)", database_name) is None:
            blockers.append("write runtime database name is not clearly sandbox")
        try:
            runtime_identity = config.runtime_identity
        except Exception:
            runtime_identity = None
            blockers.append("write runtime identity is unavailable")
        runtime_ready = not blockers
        runtime_report = {
            "blockers": sorted(set(blockers)),
            "database_name": database_name,
            "database_uuid": config.base_runtime.database_uuid,
            "path": str(write_runtime_config),
            "ready": runtime_ready,
            "runtime_identity": runtime_identity,
            "status": "valid" if runtime_ready else "scope_rejected",
            "write_execution_mode": config.write_execution_mode,
        }
        evidence_root_report = _audit_sandbox_write_evidence_root(
            evidence_root,
            release_root=config.base_runtime.release_root,
            minimum_free_bytes=min_free_bytes,
        )
        onboarding_report = _sandbox_onboarding_receipt_report(
            onboarding_receipt,
            command=command,
            expected_database_name=database_name,
            expected_release_identity=identity,
        )
    data = {
        "capability_summary": {
            "not_staging_ready_capability_ids": not_staging_ready_capability_ids,
            "not_staging_ready_count": len(not_staging_ready_capability_ids),
            "sandbox_drill_admissible_count": sandbox_drill_admissible_count,
            "sandbox_staging_promotion_ready_count": (
                sandbox_staging_promotion_ready_count
            ),
            "staging_promotion_blockers": staging_promotion_blockers,
            "total_write_capabilities": len(capability_reports),
        },
        "environment_ready_for_sandbox_write_drills": (
            runtime_ready
            and evidence_root_report["ready"]
            and onboarding_report["ready"]
            and sandbox_drill_admissible_count == len(capability_reports)
        ),
        "evidence_root": evidence_root_report,
        "onboarding": onboarding_report,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "release_identity": identity,
        "runtime": runtime_report,
        "sandbox_drill_admissible_count": sandbox_drill_admissible_count,
        "sandbox_staging_promotion_ready_count": sandbox_staging_promotion_ready_count,
        "total_write_capabilities": len(capability_reports),
    }
    if not summary_only:
        data["capabilities"] = capability_reports
    _success(command, data, business_succeeded=False)


@evidence_group.command("sandbox-write-preflight")
@click.option(
    "--capability-id",
    required=True,
    help="Exact registered write capability that this sandbox evidence drill will collect.",
)
@click.option(
    "--company-id",
    required=True,
    type=click.IntRange(min=1),
    help="Exact Odoo company ID that this sandbox evidence drill is bound to.",
)
@click.option(
    "--write-runtime-config",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Root-managed write runtime configuration for a staged sandbox.",
)
@click.option(
    "--evidence-root",
    required=True,
    type=click.Path(path_type=Path, file_okay=False),
    help="Existing root-owned directory for retained sandbox write evidence.",
)
@click.option(
    "--onboarding-receipt",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained evidence.sandbox-onboarding-readiness JSON receipt that is ready and bound to this release/runtime.",
)
@click.option(
    "--min-free-bytes",
    type=click.IntRange(min=1),
    default=8 * 1024 * 1024 * 1024,
    show_default=True,
    help="Minimum free bytes required before starting sandbox write evidence collection.",
)
def evidence_sandbox_write_preflight(
    capability_id: str,
    company_id: int,
    write_runtime_config: Path,
    evidence_root: Path,
    onboarding_receipt: Path,
    min_free_bytes: int,
) -> None:
    """Read-only gate before any real sandbox accounting write drill."""

    command = "evidence.sandbox-write-preflight"
    capability = next(
        (item for item in _load_capabilities() if item.id == capability_id),
        None,
    )
    if capability is None or capability.data["access"] != "write":
        raise CliFailure(
            command=command,
            code="sandbox_write_capability_rejected",
            message="The sandbox write preflight must target one registered write capability.",
            exit_code=5,
        )
    odoo_write_capabilities, allowed_models_by_capability = (
        _load_write_capability_implementation(command)
    )
    readiness_report = _write_capability_readiness_report(
        capability,
        allowed_models_by_capability=allowed_models_by_capability,
        odoo_write_capabilities=odoo_write_capabilities,
    )
    if readiness_report["sandbox_drill_admissible"] is not True:
        raise CliFailure(
            command=command,
            code="sandbox_write_readiness_rejected",
            message="The write capability is not statically admissible for sandbox drill collection.",
            exit_code=5,
        )
    try:
        config = load_write_runtime_config(write_runtime_config)
    except WriteRuntimeError as exc:
        raise CliFailure(
            command=command,
            code="write_runtime_rejected",
            message="The write runtime is not a valid staged sandbox configuration.",
            exit_code=5,
        ) from exc
    identity = _load_release_identity(config.base_runtime.release_root, command=command)
    _assert_runtime_release(config.base_runtime, identity, command=command)
    database_name = config.base_runtime.database_name
    if (
        config.write_execution_mode != "sandbox_staged"
        or config.base_runtime.environment != "sandbox"
        or config.base_runtime.capability_channel != "staged"
        or re.search(r"(^|[_-])sandbox([_-]|$)", database_name) is None
    ):
        raise CliFailure(
            command=command,
            code="sandbox_write_scope_rejected",
            message="The write runtime is not bound to a clearly named staged sandbox database.",
            exit_code=5,
        )
    onboarding_report = _sandbox_onboarding_receipt_report(
        onboarding_receipt,
        command=command,
        expected_database_name=database_name,
        expected_release_identity=identity,
    )
    if onboarding_report["ready"] is not True:
        raise CliFailure(
            command=command,
            code="sandbox_onboarding_receipt_rejected",
            message="The sandbox write preflight requires a ready onboarding receipt bound to this release and sandbox runtime.",
            exit_code=5,
        )
    evidence_root_status = _validate_sandbox_write_evidence_root(
        evidence_root,
        release_root=config.base_runtime.release_root,
        minimum_free_bytes=min_free_bytes,
    )
    preflight_manifest = {
        "schema_version": 1,
        "scope": "odoo-accounting-cli-v3.sandbox-write-preflight.v1",
        "capability_id": capability_id,
        "company_id": company_id,
        "database_name": database_name,
        "database_uuid": config.base_runtime.database_uuid,
        "environment": config.base_runtime.environment,
        "evidence_root": evidence_root_status,
        "onboarding_receipt": onboarding_report,
        "onboarding_receipt_sha256": onboarding_report["receipt_sha256"],
        "production_promotion_allowed": False,
        "readiness_report": readiness_report,
        "readiness_report_sha256": _sha256_json(readiness_report),
        "real_odoo_write_performed": False,
        "registry_digest": identity["registry_digest"],
        "release_identity": {
            "commit": identity["commit"],
            "manifest_sha256": identity["manifest_sha256"],
            "package_sha256": identity["package_sha256"],
            "release": identity["release"],
        },
        "runtime": config.runtime_identity,
        "write_execution_mode": config.write_execution_mode,
    }
    _success(
        command,
        {
            "capability_id": capability_id,
            "company_id": company_id,
            "database_name": database_name,
            "evidence_root": evidence_root_status,
            "onboarding": onboarding_report,
            "preflight_manifest": preflight_manifest,
            "preflight_manifest_sha256": _sha256_json(preflight_manifest),
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "release_identity": identity,
            "runtime": config.runtime_identity,
            "sandbox_write_evidence_collection_admissible": True,
        },
        business_succeeded=False,
    )


@registry_group.command("list")
def registry_list() -> None:
    """Return every registered capability without executing Odoo."""

    capabilities = _load_capabilities()
    items = sorted((capability.data for capability in capabilities), key=lambda item: item["id"])
    _success(
        "registry.list",
        {
            "capabilities": items,
            "count": len(items),
            "registry_digest": registry_digest(capabilities),
        },
    )


@registry_group.command("audit")
def registry_audit() -> None:
    """Return machine-checkable registry completeness and safety gates."""

    capabilities = _load_capabilities()
    _success("registry.audit", _registry_audit_report(capabilities))


@registry_group.command("get")
@click.option("--capability-id", required=True, help="Exact registered capability ID.")
def registry_get(capability_id: str) -> None:
    """Return one registered capability without executing Odoo."""

    capabilities = _load_capabilities()
    capability = next((item for item in capabilities if item.id == capability_id), None)
    if capability is None:
        raise CliFailure(
            command="registry.get",
            code="capability_not_found",
            message="The requested capability is not registered.",
            exit_code=4,
        )
    _success(
        "registry.get",
        {
            "capability": capability.data,
            "registry_digest": registry_digest(capabilities),
        },
    )


@main.command("read")
@click.option(
    "--runtime-config",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Absolute path to the root-managed Odoo runtime configuration.",
)
@click.option(
    "--timeout-seconds",
    type=click.FloatRange(min=0, min_open=True),
    default=30.0,
    show_default=True,
)
@click.option(
    "--request-json",
    help="Complete request as a JSON object; if omitted, read it from standard input.",
)
def read_capability(
    runtime_config: Path,
    timeout_seconds: float,
    request_json: str | None,
) -> None:
    """Execute one enabled, authenticated read capability in Odoo."""

    request = _read_request("read", request_json)
    try:
        config = load_runtime_config(runtime_config)
    except OdooRunnerError as exc:
        raise CliFailure(
            command="read",
            code="runtime_configuration_rejected",
            message="The root-managed Odoo runtime configuration was rejected.",
            exit_code=5,
        ) from exc
    identity = _load_release_identity(config.release_root, command="read")
    _assert_runtime_release(config, identity)
    try:
        result = run_odoo_shell(
            config,
            request,
            release_digest=identity["manifest_sha256"],
            timeout_seconds=timeout_seconds,
        )
    except OdooRunnerError as exc:
        rejection_code = (
            exc.rejection_code
            if config.environment == "test"
            and config.capability_channel == "staged"
            else None
        )
        raise CliFailure(
            command="read",
            code="odoo_read_failed",
            message="The authenticated Odoo read did not produce a verified result.",
            exit_code=6,
            rejection_code=rejection_code,
        ) from exc
    _assert_verified_read_result(request, result, config, identity)
    _success(
        "read",
        {
            "capability_id": request.get("capability_id"),
            "release_identity": identity,
            "result": result,
            "runtime": config.runtime_identity,
        },
    )


@main.group("operation")
def operation_group() -> None:
    """Durable, authenticated write lifecycle commands."""


def _request_option(function: Any) -> Any:
    return click.option(
        "--request-json",
        help="Complete request as a JSON object; if omitted, read it from standard input.",
    )(function)


@operation_group.command("prepare")
@_request_option
def operation_prepare(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.prepare",
        action="operation.prepare",
        request_json=request_json,
    )


@operation_group.command("preview")
@_request_option
def operation_preview(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.preview",
        action="operation.preview",
        request_json=request_json,
    )


@operation_group.command("approve-execute")
@_request_option
def operation_approve_execute(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.approve_execute",
        action="operation.approve_execute",
        request_json=request_json,
        report_business_result=True,
    )


@operation_group.command("status")
@_request_option
def operation_status(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.status",
        action="operation.status",
        request_json=request_json,
    )


@operation_group.command("result")
@_request_option
def operation_result(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.result",
        action="operation.result",
        request_json=request_json,
        report_business_result=True,
    )


@operation_group.command("verify")
@_request_option
def operation_verify(request_json: str | None) -> None:
    """Compatibility alias for the read-only operation result action."""

    _execute_write_command(
        command="operation.verify",
        action="operation.result",
        request_json=request_json,
        report_business_result=True,
    )


@operation_group.command("recover")
@_request_option
def operation_recover(request_json: str | None) -> None:
    _execute_write_command(
        command="operation.recover",
        action="operation.recover",
        request_json=request_json,
    )


if __name__ == "__main__":
    main()

"""Installable, JSON-oriented command line boundary for the V3 gateway."""

from __future__ import annotations

import json
import hashlib
import hmac
import math
import os
import re
import shutil
import stat
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
from .historical_router import HistoricalRouterError, _read_trusted_file
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
from .receipts import (
    READ_RECEIPT_PURPOSE,
    SIGNATURE_VERSION as READ_RECEIPT_SIGNATURE_VERSION,
    ReceiptError,
    verify_read_receipt,
)
from .read_evidence_index import (
    EVIDENCE_INDEX_SCHEMA as LEGACY_READ_EVIDENCE_INDEX_SCHEMA,
    LEGACY_V2_BLOCKER,
    REQUIRED_EVIDENCE_KINDS,
    ReadEvidenceIndexError,
    verify_read_evidence_index,
)
from .read_evidence_v3 import (
    MAX_INDEX_BYTES as READ_EVIDENCE_V3_MAX_INDEX_BYTES,
    ReadEvidenceV3Error,
    detect_read_evidence_schema,
    verify_read_evidence_v3,
)
from .registry import (
    PRODUCTION_READ_EVIDENCE,
    Capability,
    load_registry,
    registry_digest,
    validate_registry,
)
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
DEFAULT_PI_RECOMPUTATION_ATTESTATION_KEYS_PARENT = Path(
    "/etc/odoo-accounting-cli-v3/trust/pi-evidence"
)
PI_SCENARIO_REPORT_SCHEMA = "odoo-accounting-cli-v3.pi-gate-report.v3"
PI_SCENARIO_REQUIRED_GATES = ("F01", "F02", "F03", "F04", "F05")
PI_RECOMPUTATION_ATTESTATION_SCHEMA = (
    "odoo-accounting-cli-v3.pi-recomputation-attestation.v1"
)
PI_RECOMPUTATION_ATTESTATION_CONTEXT = (
    b"odoo-accounting-cli-v3.pi-recomputation-attestation.v1\x00"
)
PI_RECOMPUTATION_CLAIM_FIELDS = frozenset(
    {
        "capture_binding_canonical_sha256",
        "capture_binding_file_sha256",
        "expected_trace_count",
        "manifest_sha256",
        "package_sha256",
        "pi_scenario_report_sha256",
        "registry_digest",
        "run_id",
        "scenario_count",
        "trace_attestation_signed_payload_sha256",
        "trace_document_sha256",
        "trace_file_sha256",
        "verified_trace_count",
    }
)
PI_CAPTURE_BINDING_FIELDS = (
    "model",
    "pi_agent_version",
    "pi_bridge_version",
    "pi_runtime_sha256",
    "provider",
    "system_prompt_sha256",
    "tool_set_sha256",
)
ADMISSIBLE_READ_EVIDENCE_INDEX_SCHEMA = (
    "odoo-accounting-cli-v3.read-evidence-index.v3"
)
ADMISSIBLE_READ_EVIDENCE_PROTOCOL = "sshsig-v3"


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
    retained_document: dict[str, Any] | None = None,
    retained_sha256: str | None = None,
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
    if retained_document is None and retained_sha256 is None:
        report, _raw, report_sha256, _identity = _read_final_json_snapshot(
            pi_scenario_report,
            command=command,
            label="Pi scenario acceptance report",
            maximum=_MAX_FINAL_EVIDENCE_ARTIFACT_BYTES,
        )
    elif type(retained_document) is dict and isinstance(retained_sha256, str):
        report = retained_document
        report_sha256 = retained_sha256
    else:
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message="The retained Pi scenario acceptance snapshot is incomplete.",
            exit_code=5,
        )
    gates = report.get("gates")
    coverage = report.get("trace_coverage")
    capture = report.get("capture")
    attestation = report.get("attestation")
    runtime_evidence = report.get("runtime_evidence")
    required_gates = PI_SCENARIO_REQUIRED_GATES
    if report.get("schema_version") != PI_SCENARIO_REPORT_SCHEMA:
        blockers.append("Pi scenario report has the wrong schema")
    if report.get("acceptance_passed") is not True:
        blockers.append("Pi scenario report did not pass acceptance")
    runtime_counts_valid = (
        isinstance(runtime_evidence, dict)
        and set(runtime_evidence)
        == {
            "acl_independently_rechecked",
            "expected_trace_count",
            "read_exchange_count",
            "verified",
            "verified_trace_count",
            "write_authority_signature_verified_count",
            "write_exchange_count",
        }
        and runtime_evidence.get("verified") is True
        and runtime_evidence.get("acl_independently_rechecked") is False
        and all(
            type(runtime_evidence.get(field)) is int
            and runtime_evidence[field] >= 0
            for field in (
                "expected_trace_count",
                "read_exchange_count",
                "verified_trace_count",
                "write_authority_signature_verified_count",
                "write_exchange_count",
            )
        )
        and runtime_evidence.get("verified_trace_count")
        == runtime_evidence.get("expected_trace_count")
        and runtime_evidence.get("expected_trace_count") > 0
        and runtime_evidence.get("read_exchange_count", 0)
        + runtime_evidence.get("write_exchange_count", 0)
        == runtime_evidence.get("verified_trace_count")
        and runtime_evidence.get("write_authority_signature_verified_count")
        == runtime_evidence.get("write_exchange_count")
    )
    if (
        report.get("runtime_evidence_verified") is not True
        or not runtime_counts_valid
    ):
        blockers.append(
            "Pi scenario runtime evidence was not independently verified"
        )
    if (
        not isinstance(attestation, dict)
        or set(attestation)
        != {"algorithm", "key_id", "signature", "signed_payload_sha256"}
        or attestation.get("algorithm") != "hmac-sha256"
        or not isinstance(attestation.get("key_id"), str)
        or not attestation.get("key_id")
        or re.fullmatch(r"[0-9a-f]{64}", str(attestation.get("signature")))
        is None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(attestation.get("signed_payload_sha256")),
        )
        is None
        or report.get("attestation_signed_payload_sha256")
        != attestation.get("signed_payload_sha256")
    ):
        blockers.append("Pi scenario trace attestation summary is invalid")
    if (
        re.fullmatch(
            r"[0-9a-f]{64}",
            str(report.get("trace_document_sha256")),
        )
        is None
    ):
        blockers.append("Pi scenario trace document digest is invalid")
    if report.get("registry_digest") != expected_release_identity.get(
        "registry_digest"
    ):
        blockers.append(
            "Pi scenario report is not bound to the current capability registry"
        )
    if not isinstance(capture, dict):
        blockers.append("Pi scenario capture summary is invalid")
    else:
        if capture.get("v3_package_sha256") != expected_release_identity.get(
            "package_sha256"
        ):
            blockers.append(
                "Pi scenario report is not bound to the current release package"
            )
        if capture.get("v3_manifest_sha256") != expected_release_identity.get(
            "manifest_sha256"
        ):
            blockers.append(
                "Pi scenario report is not bound to the current release manifest"
            )
        capture_binding = {
            field: capture.get(field) for field in PI_CAPTURE_BINDING_FIELDS
        }
        text_fields = (
            "model",
            "pi_agent_version",
            "pi_bridge_version",
            "provider",
        )
        digest_fields = (
            "pi_runtime_sha256",
            "system_prompt_sha256",
            "tool_set_sha256",
        )
        if any(
            not isinstance(capture_binding[field], str)
            or not capture_binding[field]
            for field in text_fields
        ) or any(
            not isinstance(capture_binding[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", capture_binding[field]) is None
            for field in digest_fields
        ):
            blockers.append("Pi scenario capture binding is invalid")
        if report.get("capture_binding_verified") is not True:
            blockers.append(
                "Pi scenario capture binding was not independently verified"
            )
        if report.get("expected_capture_binding_sha256") != _sha256_json(
            capture_binding
        ):
            blockers.append("Pi scenario expected capture binding digest mismatch")
    coverage_valid = (
        isinstance(coverage, dict)
        and set(coverage)
        == {
            "captured",
            "expected",
            "missing_scenario_ids",
            "passed",
        }
        and type(coverage.get("captured")) is int
        and type(coverage.get("expected")) is int
        and coverage["captured"] > 0
        and coverage["captured"] == coverage["expected"]
        and coverage.get("missing_scenario_ids") == []
        and coverage.get("passed") is True
    )
    if not coverage_valid:
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
            gate_counts_valid = (
                isinstance(gate, dict)
                and type(gate.get("numerator")) is int
                and type(gate.get("denominator")) is int
                and gate["denominator"] > 0
                and 0 <= gate["numerator"] <= gate["denominator"]
            )
            if (
                not gate_counts_valid
                or gate.get("passed") is not True
            ):
                blockers.append(f"Pi scenario gate {gate_id} did not pass")
    return {
        "blockers": sorted(set(blockers)),
        "report_path": str(pi_scenario_report),
        "report_sha256": report_sha256,
        "scenario_acceptance_ready": not blockers,
        "summary": {
            "acceptance_passed": report.get("acceptance_passed"),
            "attestation_signed_payload_sha256": report.get(
                "attestation_signed_payload_sha256"
            ),
            "capture": capture,
            "capture_binding_verified": report.get(
                "capture_binding_verified"
            ),
            "coverage": coverage,
            "expected_capture_binding_sha256": report.get(
                "expected_capture_binding_sha256"
            ),
            "gates": gate_summary,
            "registry_digest": report.get("registry_digest"),
            "run_id": report.get("run_id"),
            "runtime_evidence": runtime_evidence,
            "runtime_evidence_verified": report.get(
                "runtime_evidence_verified"
            ),
            "trace_document_sha256": report.get("trace_document_sha256"),
        },
    }


def _pi_recomputation_claims(
    *,
    report: dict[str, Any],
    report_sha256: str,
    trace_file_sha256: str,
    capture_binding_file_sha256: str,
    expected_release_identity: dict[str, Any],
) -> dict[str, Any]:
    runtime_evidence = report.get("runtime_evidence")
    coverage = report.get("trace_coverage")
    if not isinstance(runtime_evidence, dict) or not isinstance(coverage, dict):
        raise ValueError("Pi recomputation report counts are unavailable")
    claims = {
        "capture_binding_canonical_sha256": report.get(
            "expected_capture_binding_sha256"
        ),
        "capture_binding_file_sha256": capture_binding_file_sha256,
        "expected_trace_count": runtime_evidence.get("expected_trace_count"),
        "manifest_sha256": expected_release_identity.get("manifest_sha256"),
        "package_sha256": expected_release_identity.get("package_sha256"),
        "pi_scenario_report_sha256": report_sha256,
        "registry_digest": expected_release_identity.get("registry_digest"),
        "run_id": report.get("run_id"),
        "scenario_count": coverage.get("expected"),
        "trace_attestation_signed_payload_sha256": report.get(
            "attestation_signed_payload_sha256"
        ),
        "trace_document_sha256": report.get("trace_document_sha256"),
        "trace_file_sha256": trace_file_sha256,
        "verified_trace_count": runtime_evidence.get("verified_trace_count"),
    }
    if (
        set(claims) != set(PI_RECOMPUTATION_CLAIM_FIELDS)
        or type(claims["expected_trace_count"]) is not int
        or claims["expected_trace_count"] <= 0
        or type(claims["verified_trace_count"]) is not int
        or claims["verified_trace_count"] != claims["expected_trace_count"]
        or type(claims["scenario_count"]) is not int
        or claims["scenario_count"] <= 0
        or not isinstance(claims["run_id"], str)
        or not claims["run_id"]
        or any(
            not isinstance(claims[field], str)
            or re.fullmatch(r"[0-9a-f]{64}", claims[field]) is None
            for field in PI_RECOMPUTATION_CLAIM_FIELDS - {
                "expected_trace_count",
                "run_id",
                "scenario_count",
                "verified_trace_count",
            }
        )
    ):
        raise ValueError("Pi recomputation claims are invalid")
    return claims


def _create_pi_recomputation_attestation(
    claims: dict[str, Any],
    *,
    key_id: str,
    secret: bytes,
) -> dict[str, Any]:
    if (
        set(claims) != set(PI_RECOMPUTATION_CLAIM_FIELDS)
        or not isinstance(key_id, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", key_id)
        is None
        or type(secret) is not bytes
        or len(secret) < 32
    ):
        raise ValueError("Pi recomputation attestation inputs are invalid")
    payload = PI_RECOMPUTATION_ATTESTATION_CONTEXT + _json(claims).encode(
        "utf-8"
    )
    return {
        "algorithm": "hmac-sha256",
        "claims": claims,
        "key_id": key_id,
        "schema_version": PI_RECOMPUTATION_ATTESTATION_SCHEMA,
        "signature": hmac.new(secret, payload, hashlib.sha256).hexdigest(),
    }


def _load_root_managed_pi_attestation_keys(
    gate: Any,
    path: Path,
) -> dict[str, bytes]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or (
                os.name == "posix"
                and stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            )
        ):
            raise ValueError("Pi recomputation attestation keys are not private")
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        raw, opened_identity = _read_trusted_file(
            path,
            "Pi recomputation attestation keys",
            maximum=1024 * 1024,
            require_root_owner=True,
        )
        after = path.lstat()
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            opened_identity != (before.st_dev, before.st_ino)
            or after_identity != before_identity
            or not stat.S_ISREG(after.st_mode)
            or stat.S_ISLNK(after.st_mode)
            or after.st_nlink != 1
        ):
            raise ValueError(
                "Pi recomputation attestation keys changed while they were read"
            )

        def reject_duplicate_keys(
            pairs: list[tuple[str, Any]],
        ) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON object key: {key}")
                result[key] = value
            return result

        def reject_constant(value: str) -> None:
            raise ValueError(f"invalid JSON numeric constant: {value}")

        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
        return gate.load_attestation_keys(document)
    except HistoricalRouterError as exc:
        raise ValueError(str(exc)) from exc
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise ValueError(
            "Pi recomputation attestation keys are invalid"
        ) from exc


def _pi_recomputation_attestation_keys_path(
    expected_release_identity: dict[str, Any],
) -> Path:
    release = expected_release_identity.get("release")
    if (
        not isinstance(release, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release) is None
        or not DEFAULT_PI_RECOMPUTATION_ATTESTATION_KEYS_PARENT.is_absolute()
    ):
        raise ValueError("Pi recomputation release identity is invalid")
    return Path(
        os.path.abspath(
            DEFAULT_PI_RECOMPUTATION_ATTESTATION_KEYS_PARENT
            / release
            / "attestation-keys.json"
        )
    )


def _pi_recomputation_check_status(
    pi_scenario_report_check: Path | None,
    *,
    pi_scenario_status: dict[str, Any],
    command: str,
    expected_release_identity: dict[str, Any],
    retained_document: dict[str, Any] | None = None,
    retained_sha256: str | None = None,
) -> dict[str, Any]:
    blockers: list[str] = []
    if pi_scenario_report_check is None:
        return {
            "attestation_verified": False,
            "blockers": [
                "trusted Pi scenario recomputation check was not supplied"
            ],
            "check_path": None,
            "check_sha256": None,
            "recomputation_ready": False,
        }
    check_sha256: str | None = None
    try:
        if retained_document is None and retained_sha256 is None:
            check, _raw, check_sha256, _identity = _read_final_json_snapshot(
                pi_scenario_report_check,
                command=command,
                label="Pi scenario recomputation check",
                maximum=_MAX_FINAL_EVIDENCE_ARTIFACT_BYTES,
            )
        elif type(retained_document) is dict and isinstance(retained_sha256, str):
            check = retained_document
            check_sha256 = retained_sha256
        else:
            raise ValueError(
                "Pi scenario recomputation check snapshot is incomplete"
            )
        data = check.get("data")
        if (
            set(check)
            != {"business_succeeded", "command", "data", "ok"}
            or check.get("command") != "evidence.pi-scenario-report-check"
            or check.get("ok") is not True
            or check.get("business_succeeded") is not False
            or not isinstance(data, dict)
        ):
            raise ValueError("Pi scenario recomputation check envelope is invalid")
        if (
            data.get("blockers") != []
            or data.get("scenario_acceptance_ready") is not True
            or data.get("recomputed_report_matches") is not True
            or data.get("production_promotion_allowed") is not False
            or data.get("real_odoo_write_performed") is not False
        ):
            raise ValueError("Pi scenario recomputation check is not ready")
        summary = pi_scenario_status.get("summary")
        if not isinstance(summary, dict):
            raise ValueError("Pi scenario report summary is unavailable")
        pi_summary = data.get("pi_scenario")
        if (
            not isinstance(pi_summary, dict)
            or pi_summary.get("scenario_acceptance_ready") is not True
            or pi_summary.get("report_sha256")
            != pi_scenario_status.get("report_sha256")
            or data.get("pi_scenario_report_sha256")
            != pi_scenario_status.get("report_sha256")
        ):
            raise ValueError(
                "Pi scenario recomputation check is not report-bound"
            )
        key_path_value = data.get("attestation_keys_path")
        if not isinstance(key_path_value, str) or not key_path_value:
            raise ValueError(
                "Pi recomputation attestation keys path is unavailable"
            )
        trusted_key_path = _pi_recomputation_attestation_keys_path(
            expected_release_identity
        )
        if key_path_value != str(trusted_key_path):
            raise ValueError(
                "Pi recomputation attestation keys path is not the release trust path"
            )
        gate = _load_pi_scenario_gate()
        trusted_keys = _load_root_managed_pi_attestation_keys(
            gate,
            trusted_key_path,
        )
        attestation = data.get("recomputation_attestation")
        if (
            not isinstance(attestation, dict)
            or set(attestation)
            != {
                "algorithm",
                "claims",
                "key_id",
                "schema_version",
                "signature",
            }
            or attestation.get("algorithm") != "hmac-sha256"
            or attestation.get("schema_version")
            != PI_RECOMPUTATION_ATTESTATION_SCHEMA
            or not isinstance(attestation.get("claims"), dict)
            or set(attestation["claims"])
            != set(PI_RECOMPUTATION_CLAIM_FIELDS)
        ):
            raise ValueError("Pi recomputation attestation is invalid")
        key_id = attestation.get("key_id")
        if (
            not isinstance(key_id, str)
            or re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                key_id,
            )
            is None
        ):
            raise ValueError("Pi recomputation attestation key is invalid")
        secret = trusted_keys.get(key_id)
        if type(secret) is not bytes or len(secret) < 32:
            raise ValueError("Pi recomputation attestation key is untrusted")
        runtime_evidence = summary.get("runtime_evidence")
        coverage = summary.get("coverage")
        if not isinstance(runtime_evidence, dict) or not isinstance(
            coverage, dict
        ):
            raise ValueError("Pi scenario report counts are unavailable")
        expected_claims = {
            "capture_binding_canonical_sha256": summary.get(
                "expected_capture_binding_sha256"
            ),
            "capture_binding_file_sha256": data.get(
                "expected_capture_binding_sha256"
            ),
            "expected_trace_count": runtime_evidence.get(
                "expected_trace_count"
            ),
            "manifest_sha256": expected_release_identity.get(
                "manifest_sha256"
            ),
            "package_sha256": expected_release_identity.get(
                "package_sha256"
            ),
            "pi_scenario_report_sha256": pi_scenario_status.get(
                "report_sha256"
            ),
            "registry_digest": expected_release_identity.get(
                "registry_digest"
            ),
            "run_id": summary.get("run_id"),
            "scenario_count": coverage.get("expected"),
            "trace_attestation_signed_payload_sha256": summary.get(
                "attestation_signed_payload_sha256"
            ),
            "trace_document_sha256": summary.get(
                "trace_document_sha256"
            ),
            "trace_file_sha256": data.get("trace_file_sha256"),
            "verified_trace_count": runtime_evidence.get(
                "verified_trace_count"
            ),
        }
        if attestation["claims"] != expected_claims:
            raise ValueError(
                "Pi recomputation attestation claims do not match the report"
            )
        _pi_recomputation_claims(
            report={
                "attestation_signed_payload_sha256": expected_claims[
                    "trace_attestation_signed_payload_sha256"
                ],
                "expected_capture_binding_sha256": expected_claims[
                    "capture_binding_canonical_sha256"
                ],
                "run_id": expected_claims["run_id"],
                "runtime_evidence": {
                    "expected_trace_count": expected_claims[
                        "expected_trace_count"
                    ],
                    "verified_trace_count": expected_claims[
                        "verified_trace_count"
                    ],
                },
                "trace_coverage": {
                    "expected": expected_claims["scenario_count"]
                },
                "trace_document_sha256": expected_claims[
                    "trace_document_sha256"
                ],
            },
            report_sha256=expected_claims["pi_scenario_report_sha256"],
            trace_file_sha256=expected_claims["trace_file_sha256"],
            capture_binding_file_sha256=expected_claims[
                "capture_binding_file_sha256"
            ],
            expected_release_identity=expected_release_identity,
        )
        payload = (
            PI_RECOMPUTATION_ATTESTATION_CONTEXT
            + _json(expected_claims).encode("utf-8")
        )
        signature = attestation.get("signature")
        if (
            not isinstance(signature, str)
            or re.fullmatch(r"[0-9a-f]{64}", signature) is None
            or not hmac.compare_digest(
                signature,
                hmac.new(secret, payload, hashlib.sha256).hexdigest(),
            )
        ):
            raise ValueError("Pi recomputation attestation signature mismatch")
    except (CliFailure, OSError, ValueError) as exc:
        blockers.append(str(exc))
    return {
        "attestation_verified": not blockers,
        "blockers": sorted(set(blockers)),
        "check_path": str(pi_scenario_report_check),
        "check_sha256": check_sha256,
        "recomputation_ready": not blockers,
    }


def _retained_write_capability_entries(
    data: dict[str, Any],
    *,
    label: str,
    expected_ids: tuple[str, ...],
    blockers: list[str],
) -> list[dict[str, Any]] | None:
    evidence_root = data.get("evidence_root")
    normalized_root = (
        os.path.normpath(evidence_root)
        if isinstance(evidence_root, str) and evidence_root
        else None
    )
    evidence_root_path = (
        Path(normalized_root)
        if normalized_root is not None
        and os.path.isabs(evidence_root)
        and normalized_root == evidence_root
        else None
    )
    if evidence_root_path is None:
        blockers.append(f"{label} evidence_root must be a canonical absolute path")

    capabilities = data.get("capabilities")
    if type(capabilities) is not list:
        blockers.append(f"{label} capabilities must be a list")
        return None
    if len(capabilities) != len(expected_ids):
        blockers.append(f"{label} capability count does not match current registry")
    capability_ids: list[str] = []
    for item in capabilities:
        if type(item) is not dict or not isinstance(item.get("capability_id"), str):
            blockers.append(f"{label} capability entry is invalid")
            return None
        capability_ids.append(item["capability_id"])
    if len(capability_ids) != len(set(capability_ids)):
        blockers.append(f"{label} capability IDs must be unique")
    if capability_ids != list(expected_ids):
        blockers.append(f"{label} capability IDs/order do not match current registry")
        return None

    for capability_id, item in zip(expected_ids, capabilities, strict=True):
        if item.get("status") != "verified":
            blockers.append(f"{label} {capability_id} status is not verified")
        if item.get("pipeline_ready") is not True:
            blockers.append(f"{label} {capability_id} is not pipeline-ready")
        if item.get("rejection") is not None:
            blockers.append(f"{label} {capability_id} has a rejection")
        metadata_path = item.get("metadata_path")
        if evidence_root_path is not None and (
            not isinstance(metadata_path, str)
            or metadata_path != os.path.normpath(metadata_path)
            or not os.path.isabs(metadata_path)
            or metadata_path
            != str(evidence_root_path / capability_id / "metadata.json")
        ):
            blockers.append(f"{label} {capability_id} metadata_path is invalid")
    return capabilities


def _retained_write_summary(
    data: dict[str, Any],
    *,
    label: str,
    expected_count: int,
    blockers: list[str],
) -> dict[str, Any]:
    summary = {
        "evidence_root": data.get("evidence_root"),
        "missing_count": data.get("missing_count"),
        "rejected_count": data.get("rejected_count"),
        "sandbox_pipeline_ready": data.get("sandbox_pipeline_ready"),
        "total_write_capabilities": data.get("total_write_capabilities"),
        "verified_count": data.get("verified_count"),
    }
    for field, expected in (
        ("total_write_capabilities", expected_count),
        ("verified_count", expected_count),
        ("missing_count", 0),
        ("rejected_count", 0),
    ):
        value = summary.get(field)
        if type(value) is not int or value != expected:
            blockers.append(f"{label} {field} does not match current registry")
    return summary


def _write_pipeline_report_status(
    write_pipeline_report: Path | None,
    *,
    command: str,
    expected_release_identity: dict[str, Any],
    expected_write_capability_ids: tuple[str, ...],
) -> dict[str, Any]:
    blockers: list[str] = []
    if write_pipeline_report is None:
        blockers.append("sandbox write pipeline readiness report was not supplied")
        return {
            "_capability_summaries": None,
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
        capability_summaries = None
        summary = None
    else:
        release = data.get("release_identity")
        if data.get("sandbox_pipeline_ready") is not True:
            blockers.append("sandbox write pipeline is not ready")
        if not isinstance(release, dict):
            blockers.append("sandbox write pipeline release identity is invalid")
        else:
            for field, expected in expected_release_identity.items():
                if expected is not None and release.get(field) != expected:
                    blockers.append(f"sandbox write pipeline release {field} mismatch")
        capabilities = _retained_write_capability_entries(
            data,
            label="sandbox write pipeline",
            expected_ids=expected_write_capability_ids,
            blockers=blockers,
        )
        capability_summaries: dict[str, dict[str, Any]] | None = (
            {} if capabilities is not None else None
        )
        if capabilities is not None:
            for capability_id, item in zip(
                expected_write_capability_ids, capabilities, strict=True
            ):
                pipeline = item.get("pipeline")
                pipeline_sha256 = None
                if type(pipeline) is not dict:
                    blockers.append(
                        f"sandbox write pipeline {capability_id} pipeline is invalid"
                    )
                else:
                    if pipeline.get("capability_id") != capability_id:
                        blockers.append(
                            f"sandbox write pipeline {capability_id} pipeline capability mismatch"
                        )
                    if (
                        pipeline.get("schema_version") != 1
                        or pipeline.get("scope")
                        != "odoo-accounting-cli-v3.sandbox-write-evidence-pipeline.v1"
                    ):
                        blockers.append(
                            f"sandbox write pipeline {capability_id} pipeline schema is invalid"
                        )
                    if (
                        pipeline.get("release_sha256")
                        != expected_release_identity.get("manifest_sha256")
                    ):
                        blockers.append(
                            f"sandbox write pipeline {capability_id} pipeline release mismatch"
                        )
                    if (
                        pipeline.get("registry_digest")
                        != expected_release_identity.get("registry_digest")
                    ):
                        blockers.append(
                            f"sandbox write pipeline {capability_id} pipeline registry mismatch"
                        )
                    if pipeline.get("verified") is not True:
                        blockers.append(
                            f"sandbox write pipeline {capability_id} pipeline is not verified"
                        )
                    pipeline_sha256 = _sha256_json(pipeline)
                capability_summaries[capability_id] = {
                    "capability_id": capability_id,
                    "metadata_path": item.get("metadata_path"),
                    "pipeline_ready": item.get("pipeline_ready"),
                    "pipeline_sha256": pipeline_sha256,
                    "rejection": item.get("rejection"),
                    "required_evidence": item.get("required_evidence"),
                    "status": item.get("status"),
                }
        summary = _retained_write_summary(
            data,
            label="sandbox write pipeline",
            expected_count=len(expected_write_capability_ids),
            blockers=blockers,
        )
    return {
        "_capability_summaries": capability_summaries if not blockers else None,
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
    expected_write_capability_ids: tuple[str, ...],
    pipeline_capability_summaries: dict[str, dict[str, Any]] | None,
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
        if not isinstance(release, dict):
            blockers.append("sandbox write evidence index release identity is invalid")
        else:
            for field, expected in expected_release_identity.items():
                if expected is not None and release.get(field) != expected:
                    blockers.append(
                        f"sandbox write evidence index release {field} mismatch"
                    )
        capabilities = _retained_write_capability_entries(
            data,
            label="sandbox write evidence index",
            expected_ids=expected_write_capability_ids,
            blockers=blockers,
        )
        if capabilities is not None:
            for capability_id, item in zip(
                expected_write_capability_ids, capabilities, strict=True
            ):
                if set(item) != {
                    "capability_id",
                    "metadata_path",
                    "pipeline_ready",
                    "pipeline_sha256",
                    "rejection",
                    "required_evidence",
                    "status",
                }:
                    blockers.append(
                        f"sandbox write evidence index {capability_id} fields are invalid"
                    )
                pipeline_sha256 = item.get("pipeline_sha256")
                if (
                    not isinstance(pipeline_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", pipeline_sha256) is None
                ):
                    blockers.append(
                        f"sandbox write evidence index {capability_id} pipeline_sha256 is invalid"
                    )
                item_summary = {
                    "capability_id": capability_id,
                    "metadata_path": item.get("metadata_path"),
                    "pipeline_ready": item.get("pipeline_ready"),
                    "pipeline_sha256": pipeline_sha256,
                    "rejection": item.get("rejection"),
                    "required_evidence": item.get("required_evidence"),
                    "status": item.get("status"),
                }
                expected_item_summary = (
                    pipeline_capability_summaries.get(capability_id)
                    if pipeline_capability_summaries is not None
                    else None
                )
                if (
                    expected_item_summary is None
                    or item_summary != expected_item_summary
                ):
                    blockers.append(
                        f"sandbox write evidence index {capability_id} summary does not match pipeline report"
                    )
        summary = _retained_write_summary(
            data,
            label="sandbox write evidence index",
            expected_count=len(expected_write_capability_ids),
            blockers=blockers,
        )
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


def _sandbox_database_candidates_report_status(
    sandbox_database_candidates_report: Path | None,
    *,
    command: str,
    expected_database_name: str | None,
) -> dict[str, Any] | None:
    if sandbox_database_candidates_report is None:
        return None
    blockers: list[str] = []
    report = _load_retained_json_report(
        sandbox_database_candidates_report,
        command=command,
        label="sandbox database candidates",
    )
    if report.get("ok") is not True:
        blockers.append("sandbox database candidates report is not successful")
    if report.get("command") != "evidence.sandbox-database-candidates":
        blockers.append("sandbox database candidates report has the wrong command")
    data = report.get("data")
    if not isinstance(data, dict):
        blockers.append("sandbox database candidates report data is invalid")
        data = {}
    eligible_names = data.get("eligible_database_names")
    if not isinstance(eligible_names, list) or any(
        not isinstance(name, str) for name in eligible_names
    ):
        blockers.append("sandbox database candidates eligible names are invalid")
        eligible_names = []
    selected_name = data.get("selected_database_name")
    selected_eligible = data.get("selected_database_eligible")
    if expected_database_name is not None:
        if selected_name not in (None, expected_database_name):
            blockers.append("sandbox database candidates selected name mismatch")
        if expected_database_name not in eligible_names:
            blockers.append(
                "expected sandbox database is not an eligible catalog candidate"
            )
    candidate_summary = data.get("candidate_summary")
    if not isinstance(candidate_summary, dict):
        candidate_summary = None
    return {
        "blockers": sorted(set(blockers)),
        "candidate_summary": candidate_summary,
        "eligible_database_names": sorted(set(eligible_names)),
        "report_path": str(sandbox_database_candidates_report),
        "report_sha256": _sha256_file(sandbox_database_candidates_report),
        "report_valid": not blockers,
        "selected_database_eligible": selected_eligible,
        "selected_database_name": selected_name,
    }


def _target_capacity_plan_report_status(
    target_capacity_plan_report: Path | None,
    *,
    command: str,
) -> dict[str, Any] | None:
    if target_capacity_plan_report is None:
        return None
    blockers: list[str] = []
    report = _load_retained_json_report(
        target_capacity_plan_report,
        command=command,
        label="target capacity plan",
    )
    if report.get("ok") is not True:
        blockers.append("target capacity plan report is not successful")
    if report.get("command") != "evidence.target-capacity-plan":
        blockers.append("target capacity plan report has the wrong command")
    data = report.get("data")
    if not isinstance(data, dict):
        blockers.append("target capacity plan report data is invalid")
        data = {}
    plan = data.get("plan")
    if not isinstance(plan, dict):
        blockers.append("target capacity plan report is missing data.plan")
        plan = {}
    if plan.get("kind") != "odoo-accounting-cli-v3.target-capacity-plan.v1":
        blockers.append("target capacity plan kind is invalid")
    if plan.get("cleanup_executed") is not False or data.get("cleanup_executed") is not False:
        blockers.append("target capacity plan must be read-only and unexecuted")
    if data.get("real_odoo_write_performed") is not False:
        blockers.append("target capacity plan must not be a real Odoo write receipt")
    shortfall_bytes = plan.get("shortfall_bytes")
    candidate_reclaimable_bytes = plan.get("candidate_reclaimable_bytes")
    if isinstance(shortfall_bytes, int) and shortfall_bytes > 0:
        blockers.append("target capacity plan still reports a filesystem shortfall")
    if (
        isinstance(shortfall_bytes, int)
        and isinstance(candidate_reclaimable_bytes, int)
        and shortfall_bytes > candidate_reclaimable_bytes
    ):
        blockers.append(
            "target capacity plan candidates cannot cover the capacity shortfall"
        )
    summary = {
        "candidate_count": plan.get("candidate_count"),
        "candidate_reclaimable_bytes": candidate_reclaimable_bytes,
        "candidates_truncated": plan.get("candidates_truncated"),
        "required_free_bytes": plan.get("required_free_bytes"),
        "retained_candidate_count": plan.get("retained_candidate_count"),
        "shortfall_bytes": shortfall_bytes,
    }
    return {
        "blockers": sorted(set(blockers)),
        "plan_ready": not blockers,
        "report_path": str(target_capacity_plan_report),
        "report_sha256": _sha256_file(target_capacity_plan_report),
        "summary": summary,
    }


def _target_capacity_recheck_report_status(
    target_capacity_recheck_report: Path | None,
    *,
    command: str,
    expected_required_free_bytes: int,
) -> dict[str, Any] | None:
    if target_capacity_recheck_report is None:
        return None
    blockers: list[str] = []
    report = _load_retained_json_report(
        target_capacity_recheck_report,
        command=command,
        label="target capacity recheck",
    )
    if report.get("ok") is not True:
        blockers.append("target capacity recheck report is not successful")
    if report.get("command") != "evidence.target-capacity-recheck":
        blockers.append("target capacity recheck report has the wrong command")
    data = report.get("data")
    if not isinstance(data, dict):
        blockers.append("target capacity recheck report data is invalid")
        data = {}
    if data.get("cleanup_executed") is not False:
        blockers.append("target capacity recheck must be read-only and unexecuted")
    if data.get("real_odoo_write_performed") is not False:
        blockers.append("target capacity recheck must not be a real Odoo write receipt")
    if data.get("required_free_bytes") != expected_required_free_bytes:
        blockers.append("target capacity recheck required_free_bytes mismatch")
    if data.get("sandbox_write_capacity_ready") is not True:
        blockers.append("target capacity recheck is not ready")
    summary = {
        "available_bytes": data.get("available_bytes"),
        "required_free_bytes": data.get("required_free_bytes"),
        "sandbox_write_capacity_ready": data.get("sandbox_write_capacity_ready"),
        "shortfall_bytes": data.get("shortfall_bytes"),
    }
    return {
        "blockers": sorted(set(blockers)),
        "recheck_ready": not blockers,
        "report_path": str(target_capacity_recheck_report),
        "report_sha256": _sha256_file(target_capacity_recheck_report),
        "summary": summary,
    }


FINAL_EVIDENCE_MANIFEST_SCHEMA = "odoo-accounting-cli-v3.final-evidence-manifest.v2"
_MAX_FINAL_EVIDENCE_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_FINAL_EVIDENCE_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_FINAL_EVIDENCE_JSON_DEPTH = 64
_MAX_FINAL_EVIDENCE_JSON_NODES = 250_000
FINAL_EVIDENCE_ARTIFACT_COMMANDS = {
    "goal_readiness_report": "evidence.goal-readiness",
    "pi_scenario_report_check": "evidence.pi-scenario-report-check",
    "pi_trace_capture_check": "evidence.pi-trace-capture-check",
    "read_capabilities_readiness_report": "evidence.read-capabilities-readiness",
    "sandbox_database_candidates_report": "evidence.sandbox-database-candidates",
    "sandbox_onboarding_receipt": "evidence.sandbox-onboarding-readiness",
    "sandbox_onboarding_receipt_check": "evidence.sandbox-onboarding-receipt-check",
    "sandbox_prerequisite_handoff": "evidence.sandbox-prerequisite-handoff",
    "sandbox_prerequisite_handoff_check": "evidence.sandbox-prerequisite-handoff-check",
    "sandbox_provision_authorization_check": "evidence.sandbox-provision-authorization-check",
    "target_capacity_plan_report": "evidence.target-capacity-plan",
    "target_capacity_recheck_report": "evidence.target-capacity-recheck",
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
SANDBOX_PREREQUISITE_HANDOFF_SCHEMA = (
    "odoo-accounting-cli-v3.sandbox-prerequisite-handoff.v1"
)
GOAL_REMEDIATION_PLACEHOLDER_SCHEMA: dict[str, dict[str, Any]] = {
    "CAPACITY_PATH": {
        "description": "Filesystem path whose free space must satisfy the sandbox write capacity floor.",
        "format": "absolute_path",
        "operator_supplied": True,
        "sensitive": False,
    },
    "COMPANY": {
        "description": "Exact Odoo company name or identifier bound to the sandbox evidence packet.",
        "format": "odoo_company",
        "operator_supplied": True,
        "sensitive": False,
    },
    "GOAL_READINESS_JSON": {
        "description": "Retained evidence.goal-readiness JSON report for the routed release.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": False,
    },
    "MANIFEST_SHA256": {
        "description": "Verified release-manifest SHA-256 bound to runtime receipts.",
        "format": "sha256",
        "operator_supplied": True,
        "sensitive": False,
    },
    "NORMALIZED_PI_TRACE_CAPTURE_JSON": {
        "description": "Retained normalized Pi Agent trace capture JSON for the routed release.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": False,
    },
    "OBSERVED_DATABASE": {
        "description": "Database name observed in the PostgreSQL catalog evidence.",
        "format": "postgres_database_name",
        "operator_supplied": True,
        "sensitive": False,
    },
    "OPERATOR_ID": {
        "description": "Human or service operator identity recorded on sandbox provisioning authorization.",
        "format": "operator_identity",
        "operator_supplied": True,
        "sensitive": False,
    },
    "PI_GATE_REPORT_JSON": {
        "description": "Output path for the Pi scenario acceptance gate report.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": False,
    },
    "PACKAGE_SHA256": {
        "description": "Verified canonical release-package SHA-256.",
        "format": "sha256",
        "operator_supplied": True,
        "sensitive": False,
    },
    "PRODUCTION_DATABASE": {
        "description": "Protected production database name that must not be selected for sandbox writes.",
        "format": "postgres_database_name",
        "operator_supplied": True,
        "sensitive": False,
    },
    "REQUIRED_FREE_BYTES": {
        "description": "Minimum free bytes required by the sandbox write capacity gate.",
        "format": "positive_integer",
        "operator_supplied": True,
        "sensitive": False,
    },
    "REGISTRY_DIGEST": {
        "description": "Verified ordered capability-registry digest for the routed release.",
        "format": "sha256",
        "operator_supplied": True,
        "sensitive": False,
    },
    "ROUTED_RELEASE": {
        "description": "Immutable release directory name currently routed through /opt/odoo-accounting-cli-v3/current.",
        "format": "release_identity",
        "operator_supplied": True,
        "sensitive": False,
    },
    "SANDBOX_DATABASE_NAME": {
        "description": "Dedicated sandbox database name authorized for V3 write-lifecycle validation.",
        "format": "postgres_database_name",
        "operator_supplied": True,
        "sensitive": False,
    },
    "SANDBOX_ONBOARDING_READINESS_JSON": {
        "description": "Retained sandbox onboarding readiness receipt JSON for the routed release.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": False,
    },
    "SANDBOX_PROVISION_AUTHORIZATION_JSON": {
        "description": "Retained sandbox provisioning authorization JSON signed or approved by the authorized operator.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": False,
    },
    "SANDBOX_PREREQUISITE_HANDOFF_JSON": {
        "description": "Retained sandbox prerequisite handoff JSON generated from the goal-readiness report.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": False,
    },
    "SANDBOX_WRITE_EVIDENCE_ROOT": {
        "description": "Directory containing real sandbox write lifecycle evidence for registered write capabilities.",
        "format": "directory_path",
        "operator_supplied": True,
        "sensitive": False,
    },
    "SOURCE_DATABASE_NAME": {
        "description": "Source database name used to provision or refresh the dedicated sandbox database.",
        "format": "postgres_database_name",
        "operator_supplied": True,
        "sensitive": False,
    },
    "TRUSTED_TRACE_ATTESTATION_KEYS_JSON": {
        "description": "JSON file containing the trusted attestation keys used to verify Pi trace integrity.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": True,
    },
    "TRUSTED_AUTHORITY_CONFIG_JSON": {
        "description": "Root-managed trusted-authority runtime configuration for the exact release.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": True,
    },
    "TRUSTED_CAPTURE_BINDING_JSON": {
        "description": "Independent exact Pi/Bridge/provider/model/prompt/tool/runtime binding.",
        "format": "json_file",
        "operator_supplied": True,
        "sensitive": False,
    },
    "UTC_TIMESTAMP": {
        "description": "UTC expiration timestamp for sandbox provisioning authorization.",
        "format": "rfc3339_utc_timestamp",
        "operator_supplied": True,
        "sensitive": False,
    },
}
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
        "command_args_template": (
            (
                "evidence", "pi-trace-capture-check",
                "--trace-file", "<NORMALIZED_PI_TRACE_CAPTURE_JSON>",
                "--attestation-keys", "<TRUSTED_TRACE_ATTESTATION_KEYS_JSON>",
                "--expected-capture-binding", "<TRUSTED_CAPTURE_BINDING_JSON>",
                "--trusted-authority-config", "<TRUSTED_AUTHORITY_CONFIG_JSON>",
                "--expected-manifest-sha256", "<MANIFEST_SHA256>",
                "--expected-package-sha256", "<PACKAGE_SHA256>",
                "--expected-registry-digest", "<REGISTRY_DIGEST>",
            ),
            (
                "tools/pi_scenario_gate.py",
                "--traces", "<NORMALIZED_PI_TRACE_CAPTURE_JSON>",
                "--attestation-keys", "<TRUSTED_TRACE_ATTESTATION_KEYS_JSON>",
                "--expected-capture-binding", "<TRUSTED_CAPTURE_BINDING_JSON>",
                "--trusted-authority-config", "<TRUSTED_AUTHORITY_CONFIG_JSON>",
                "--expected-manifest-sha256", "<MANIFEST_SHA256>",
                "--expected-package-sha256", "<PACKAGE_SHA256>",
                "--expected-registry-digest", "<REGISTRY_DIGEST>",
                "--output", "<PI_GATE_REPORT_JSON>",
            ),
            (
                "evidence", "pi-scenario-report-check",
                "--pi-scenario-report", "<PI_GATE_REPORT_JSON>",
                "--trace-file", "<NORMALIZED_PI_TRACE_CAPTURE_JSON>",
                "--attestation-keys", "<TRUSTED_TRACE_ATTESTATION_KEYS_JSON>",
                "--expected-capture-binding", "<TRUSTED_CAPTURE_BINDING_JSON>",
                "--trusted-authority-config", "<TRUSTED_AUTHORITY_CONFIG_JSON>",
                "--expected-manifest-sha256", "<MANIFEST_SHA256>",
                "--expected-package-sha256", "<PACKAGE_SHA256>",
                "--expected-registry-digest", "<REGISTRY_DIGEST>",
            ),
        ),
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
        "command_args_template": (
            ("evidence", "target-capacity-plan", "--required-free-bytes", "<REQUIRED_FREE_BYTES>", "--keep-release", "<ROUTED_RELEASE>"),
            ("evidence", "target-capacity-recheck", "--path", "<CAPACITY_PATH>", "--required-free-bytes", "<REQUIRED_FREE_BYTES>"),
        ),
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
        "command_args_template": (
            ("evidence", "sandbox-database-candidates", "--database-name", "<OBSERVED_DATABASE>", "--protected-database-name", "<PRODUCTION_DATABASE>", "--selected-database-name", "<SANDBOX_DATABASE_NAME>"),
        ),
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
        "command_args_template": (
            ("evidence", "sandbox-provision-authorization-template", "--sandbox-database-name", "<SANDBOX_DATABASE_NAME>", "--source-database-name", "<SOURCE_DATABASE_NAME>", "--company", "<COMPANY>", "--operator-id", "<OPERATOR_ID>", "--retention-until", "<UTC_TIMESTAMP>"),
            ("evidence", "sandbox-provision-authorization-check", "--authorization-file", "<SANDBOX_PROVISION_AUTHORIZATION_JSON>", "--expected-sandbox-database-name", "<SANDBOX_DATABASE_NAME>", "--expected-source-database-name", "<SOURCE_DATABASE_NAME>", "--expected-company", "<COMPANY>"),
        ),
        "authorization_required": True,
    },
    {
        "action_id": "sandbox_prerequisite_handoff",
        "blocker_patterns": (
            "capacity",
            "free space",
            "sandbox database",
            "authorization file",
            "sandbox provision authorization",
        ),
        "description": "Render and validate the read-only operator decision handoff for capacity, sandbox database, and provisioning prerequisites.",
        "required_artifacts": (
            "sandbox_prerequisite_handoff",
            "sandbox_prerequisite_handoff_check",
        ),
        "operator_command": "evidence sandbox-prerequisite-handoff; evidence sandbox-prerequisite-handoff-check",
        "command_args_template": (
            ("evidence", "sandbox-prerequisite-handoff", "--goal-readiness-report", "<GOAL_READINESS_JSON>"),
            ("evidence", "sandbox-prerequisite-handoff-check", "--handoff-file", "<SANDBOX_PREREQUISITE_HANDOFF_JSON>"),
        ),
        "authorization_required": False,
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
        "command_args_template": (
            ("evidence", "sandbox-onboarding-readiness", "--sandbox-database-name", "<SANDBOX_DATABASE_NAME>", "--source-database-name", "<SOURCE_DATABASE_NAME>", "--observed-database-name", "<OBSERVED_DATABASE>", "--authorization-file", "<SANDBOX_PROVISION_AUTHORIZATION_JSON>", "--expected-company", "<COMPANY>"),
            ("evidence", "sandbox-onboarding-receipt-check", "--onboarding-receipt", "<SANDBOX_ONBOARDING_READINESS_JSON>", "--expected-sandbox-database-name", "<SANDBOX_DATABASE_NAME>"),
        ),
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
        "command_args_template": (
            ("evidence", "write-pipeline-readiness", "--evidence-root", "<SANDBOX_WRITE_EVIDENCE_ROOT>"),
            ("evidence", "write-evidence-index", "--evidence-root", "<SANDBOX_WRITE_EVIDENCE_ROOT>"),
        ),
        "authorization_required": True,
    },
    {
        "action_id": "read_trusted_execution",
        "blocker_patterns": (
            "read capability",
            "read evidence",
            "read static readiness",
        ),
        "description": "Implement every registered read capability behind an explicit trusted handler and retain exact-release live Odoo, accounting oracle, Pi E2E, release identity, and security-negative evidence.",
        "required_artifacts": ("read_capabilities_readiness_report",),
        "operator_command": "evidence read-capabilities-readiness",
        "command_args_template": (
            ("evidence", "read-capabilities-readiness"),
        ),
        "authorization_required": False,
    },
)


def _manifest_artifact_reference(manifest_path: Path, artifact_path: Path) -> str:
    try:
        return artifact_path.relative_to(manifest_path.parent).as_posix()
    except ValueError as exc:
        raise ValueError("final evidence artifact is outside the manifest root") from exc


def _manifest_artifact_path(manifest_path: Path, value: Any) -> Path | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or "\x00" in value
        or "\\" in value
        or ":" in value
    ):
        return None
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        return None
    return manifest_path.parent.joinpath(*relative.parts)


def _check_final_json_complexity(value: Any) -> None:
    pending: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_FINAL_EVIDENCE_JSON_NODES:
            raise ValueError("retained final evidence JSON exceeds its node limit")
        if depth > _MAX_FINAL_EVIDENCE_JSON_DEPTH:
            raise ValueError("retained final evidence JSON exceeds its depth limit")
        if type(current) is list:
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            for key, item in current.items():
                if type(key) is not str:
                    raise ValueError("retained final evidence JSON key is invalid")
                pending.append((key, depth + 1))
                pending.append((item, depth + 1))
        elif type(current) is float and not math.isfinite(current):
            raise ValueError("retained final evidence JSON number is not finite")


def _read_final_json_snapshot(
    path: Path,
    *,
    command: str,
    label: str,
    maximum: int,
) -> tuple[dict[str, Any], bytes, str, tuple[int, int, int, int, int]]:
    snapshot_path = Path(os.path.abspath(path))
    try:
        raw, identity = _read_trusted_file(
            snapshot_path,
            label,
            maximum=maximum,
            require_root_owner=False,
        )
        metadata = snapshot_path.lstat()
        if (
            (metadata.st_dev, metadata.st_ino) != identity
            or metadata.st_nlink != 1
        ):
            raise ValueError(f"{label} must be a stable single-link file")
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_json,
        )
        if type(document) is not dict:
            raise ValueError(f"{label} must be a JSON object")
        _check_final_json_complexity(document)
    except (
        HistoricalRouterError,
        OSError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message=f"The retained {label} is unavailable or invalid JSON.",
            exit_code=5,
        ) from exc
    snapshot_identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    return document, raw, _sha256_bytes(raw), snapshot_identity


def _recheck_final_file_snapshot(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int],
    expected_sha256: str,
    maximum: int,
    command: str,
    label: str,
) -> None:
    snapshot_path = Path(os.path.abspath(path))
    try:
        raw, identity = _read_trusted_file(
            snapshot_path,
            label,
            maximum=maximum,
            require_root_owner=False,
        )
        metadata = snapshot_path.lstat()
        observed_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        if (
            identity != expected_identity[:2]
            or observed_identity != expected_identity
            or metadata.st_nlink != 1
            or not hmac.compare_digest(_sha256_bytes(raw), expected_sha256)
        ):
            raise ValueError(f"{label} changed after snapshot")
    except (HistoricalRouterError, OSError, ValueError) as exc:
        raise CliFailure(
            command=command,
            code="retained_report_rejected",
            message=f"The retained {label} changed after snapshot.",
            exit_code=5,
        ) from exc


def _write_final_snapshot_exclusive(path: Path, raw: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (
                os.name == "posix"
                and stat.S_IMODE(opened.st_mode) != 0o600
            )
        ):
            raise OSError("final evidence destination is not a single-link file")
        view = memoryview(raw)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("final evidence snapshot write did not progress")
            written += count
        os.fsync(descriptor)
        completed = os.fstat(descriptor)
        if (
            (completed.st_dev, completed.st_ino)
            != (opened.st_dev, opened.st_ino)
            or completed.st_nlink != 1
            or completed.st_size != len(raw)
        ):
            raise OSError("final evidence snapshot changed while it was written")
    finally:
        os.close(descriptor)
    retained = path.lstat()
    if (
        (retained.st_dev, retained.st_ino) != (opened.st_dev, opened.st_ino)
        or retained.st_nlink != 1
        or path.is_symlink()
    ):
        raise OSError("final evidence snapshot path changed after it was written")


def _create_private_final_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    if os.name == "posix":
        path.chmod(0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or (
            os.name == "posix"
            and stat.S_IMODE(metadata.st_mode) != 0o700
        )
    ):
        raise OSError("final evidence staging directory is unsafe")


def _prepare_final_output_parent(path: Path, *, command: str) -> None:
    try:
        if not os.path.lexists(path):
            raise OSError("final evidence output directory must already exist")
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or path.is_symlink()
            or Path(os.path.abspath(path.resolve(strict=True))) != path
        ):
            raise OSError("final evidence output directory is unsafe")
        if os.name == "posix":
            effective_uid = os.geteuid()
            current = path
            while True:
                ancestor = current.lstat()
                mode = stat.S_IMODE(ancestor.st_mode)
                shared_sticky_root = (
                    current != path
                    and ancestor.st_uid == 0
                    and mode & stat.S_ISVTX
                )
                if (
                    not stat.S_ISDIR(ancestor.st_mode)
                    or stat.S_ISLNK(ancestor.st_mode)
                    or ancestor.st_uid not in {0, effective_uid}
                    or (mode & 0o022 and not shared_sticky_root)
                ):
                    raise OSError(
                        "final evidence output directory ancestors are unsafe"
                    )
                if current.parent == current:
                    break
                current = current.parent
    except (OSError, RuntimeError) as exc:
        raise CliFailure(
            command=command,
            code="final_evidence_manifest_rejected",
            message="The final evidence output directory is unavailable or unsafe.",
            exit_code=5,
        ) from exc


def _fsync_final_directory(path: Path) -> None:
    if os.name != "posix":
        return
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_final_file(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _make_final_bundle_read_only(bundle_root: Path) -> None:
    if os.name != "posix":
        return
    files: list[Path] = []
    directories: list[Path] = []
    for path in bundle_root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode) and not path.is_symlink():
            files.append(path)
        elif stat.S_ISDIR(metadata.st_mode) and not path.is_symlink():
            directories.append(path)
        else:
            raise OSError("final evidence bundle contains an unsafe entry")
    for path in files:
        path.chmod(0o400)
        _fsync_final_file(path)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o500)
    bundle_root.chmod(0o500)


def _remove_final_transaction_path(path: Path | None, parent: Path) -> None:
    if path is None or path.parent != parent or not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
        return
    if os.name == "posix":
        for child in path.rglob("*"):
            if child.is_dir() and not child.is_symlink():
                child.chmod(0o700)
            elif not child.is_symlink():
                child.chmod(0o600)
        path.chmod(0o700)
    shutil.rmtree(path)


class _FinalManifestPublishedError(OSError):
    """Raised when publication succeeded but a later durability check failed."""


def _publish_final_manifest(
    candidate: Path,
    output_file: Path,
    *,
    overwrite: bool,
) -> None:
    candidate_metadata = candidate.lstat()
    if (
        not stat.S_ISREG(candidate_metadata.st_mode)
        or candidate.is_symlink()
        or candidate_metadata.st_nlink != 1
    ):
        raise OSError("final evidence manifest candidate is unsafe")
    published = False
    try:
        if overwrite:
            os.replace(candidate, output_file)
        else:
            os.link(candidate, output_file)
        published = True
        if not overwrite:
            candidate.unlink()
        published_metadata = output_file.lstat()
        if (
            not stat.S_ISREG(published_metadata.st_mode)
            or output_file.is_symlink()
            or published_metadata.st_nlink != 1
            or (published_metadata.st_dev, published_metadata.st_ino)
            != (candidate_metadata.st_dev, candidate_metadata.st_ino)
        ):
            raise OSError("final evidence manifest publication is not stable")
        _fsync_final_directory(output_file.parent)
    except OSError as exc:
        if published:
            raise _FinalManifestPublishedError(
                "final evidence manifest was published before validation failed"
            ) from exc
        raise


def _command_template_placeholders(command_args_template: Any) -> list[str]:
    placeholders: set[str] = set()
    if not isinstance(command_args_template, tuple):
        return []
    for command_args in command_args_template:
        if not isinstance(command_args, tuple):
            continue
        for item in command_args:
            if isinstance(item, str) and item.startswith("<") and item.endswith(">"):
                placeholders.add(item[1:-1])
    return sorted(placeholders)


def _placeholder_schema(placeholders: list[str]) -> dict[str, dict[str, Any]]:
    return {
        name: dict(GOAL_REMEDIATION_PLACEHOLDER_SCHEMA[name])
        for name in placeholders
        if name in GOAL_REMEDIATION_PLACEHOLDER_SCHEMA
    }


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
        placeholders = _command_template_placeholders(
            template["command_args_template"]
        )
        actions.append(
            {
                "action_id": template["action_id"],
                "authorization_required": template["authorization_required"],
                "blocking_evidence": matching,
                "description": template["description"],
                "command_args_template": [
                    list(command_args)
                    for command_args in template["command_args_template"]
                ],
                "operator_command": template["operator_command"],
                "production_promotion_allowed": False,
                "real_odoo_write_performed": False,
                "required_artifacts": list(template["required_artifacts"]),
                "required_placeholders": placeholders,
                "placeholder_schema": _placeholder_schema(placeholders),
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


def _sandbox_prerequisite_handoff_report(
    goal_readiness_report: Path,
    *,
    command: str,
    expected_release_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    retained = _load_retained_json_report(
        goal_readiness_report, command=command, label="goal readiness"
    )
    blockers: list[str] = []
    if retained.get("ok") is not True:
        blockers.append("goal-readiness report is not successful")
    if retained.get("command") != "evidence.goal-readiness":
        blockers.append("goal-readiness report has the wrong command")
    data = retained.get("data")
    if not isinstance(data, dict):
        blockers.append("goal-readiness report data is invalid")
        data = {}
    release_identity = data.get("release_identity")
    if not isinstance(release_identity, dict):
        if expected_release_identity is not None:
            blockers.append("goal-readiness release identity is invalid")
        release_identity = None
    elif expected_release_identity is not None:
        for field, expected in expected_release_identity.items():
            if expected is not None and release_identity.get(field) != expected:
                blockers.append(f"goal-readiness release {field} mismatch")

    capacity = data.get("capacity")
    if not isinstance(capacity, dict):
        capacity = {}
    retained_plan = capacity.get("retained_plan")
    if not isinstance(retained_plan, dict):
        retained_plan = None
    retained_recheck = capacity.get("retained_recheck")
    if not isinstance(retained_recheck, dict):
        retained_recheck = None
    sandbox_database = data.get("sandbox_database")
    if not isinstance(sandbox_database, dict):
        sandbox_database = {}
    candidates_report = sandbox_database.get("candidates_report")
    if not isinstance(candidates_report, dict):
        candidates_report = None

    capacity_shortfall = capacity.get("shortfall_bytes")
    if not isinstance(capacity_shortfall, int):
        capacity_shortfall = None
    plan_summary = (
        retained_plan.get("summary") if isinstance(retained_plan, dict) else None
    )
    if not isinstance(plan_summary, dict):
        plan_summary = {}
    candidate_reclaimable = plan_summary.get("candidate_reclaimable_bytes")
    if not isinstance(candidate_reclaimable, int):
        candidate_reclaimable = None
    expansion_required = (
        capacity_shortfall is not None
        and (
            candidate_reclaimable is None
            or candidate_reclaimable < capacity_shortfall
        )
    )

    decisions = []
    if capacity.get("sandbox_write_capacity_ready") is not True:
        decisions.append(
            {
                "decision_id": "capacity_remediation",
                "authorization_required": True,
                "business_reason": "Sandbox write evidence cannot start until the target filesystem satisfies the configured free-space floor.",
                "evidence": {
                    "capacity_shortfall_bytes": capacity_shortfall,
                    "candidate_reclaimable_bytes": candidate_reclaimable,
                    "retained_plan_sha256": (
                        retained_plan.get("report_sha256")
                        if isinstance(retained_plan, dict)
                        else None
                    ),
                    "retained_recheck_sha256": (
                        retained_recheck.get("report_sha256")
                        if isinstance(retained_recheck, dict)
                        else None
                    ),
                },
                "required_operator_action": (
                    "expand or relocate capacity, or authorize reviewed cleanup and rerun target-capacity-recheck"
                ),
                "requires_external_capacity": expansion_required,
                "status": "pending",
            }
        )

    candidate_summary = (
        candidates_report.get("candidate_summary")
        if isinstance(candidates_report, dict)
        else None
    )
    if not isinstance(candidate_summary, dict):
        candidate_summary = {}
    if sandbox_database.get("sandbox_database_ready") is not True:
        decisions.append(
            {
                "decision_id": "dedicated_sandbox_database",
                "authorization_required": True,
                "business_reason": "Sandbox write validation requires one clearly named dedicated sandbox database, not a transient test/demo/runtime database.",
                "evidence": {
                    "candidate_count": candidate_summary.get("candidate_count"),
                    "eligible_count": candidate_summary.get("eligible_count"),
                    "expected_sandbox_database_name": sandbox_database.get(
                        "sandbox_database_name"
                    ),
                    "retained_candidates_sha256": (
                        candidates_report.get("report_sha256")
                        if isinstance(candidates_report, dict)
                        else None
                    ),
                    "sandbox_database_observed": sandbox_database.get(
                        "sandbox_database_observed"
                    ),
                },
                "required_operator_action": (
                    "authorize and create or select a clearly named dedicated sandbox database, then rerun sandbox-database-candidates"
                ),
                "requires_external_database_action": True,
                "status": "pending",
            }
        )

    authorization = data.get("sandbox_provision_authorization")
    if not isinstance(authorization, dict):
        authorization = {}
    if authorization.get("authorization_record_ready") is not True:
        decisions.append(
            {
                "decision_id": "sandbox_provision_authorization",
                "authorization_required": True,
                "business_reason": "The sandbox database, source database, company scope, operator, and retention window must be approved before provisioning.",
                "evidence": {
                    "authorization_file": authorization.get("authorization_file"),
                },
                "required_operator_action": (
                    "save and validate sandbox-provision-authorization JSON"
                ),
                "status": "pending",
            }
        )

    return {
        "blockers": sorted(set(blockers)),
        "decision_count": len(decisions),
        "decisions": decisions,
        "goal_readiness_report": str(goal_readiness_report),
        "goal_readiness_report_sha256": _sha256_file(goal_readiness_report),
        "handoff_ready": not blockers and bool(decisions),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "release_identity": release_identity,
        "schema_version": SANDBOX_PREREQUISITE_HANDOFF_SCHEMA,
    }


def _sandbox_prerequisite_handoff_check_report(
    handoff_file: Path,
    *,
    command: str,
    expected_release_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    retained = _load_retained_json_report(
        handoff_file, command=command, label="sandbox prerequisite handoff"
    )
    blockers: list[str] = []
    if retained.get("ok") is not True:
        blockers.append("sandbox prerequisite handoff report is not successful")
    if retained.get("command") != "evidence.sandbox-prerequisite-handoff":
        blockers.append("sandbox prerequisite handoff report has the wrong command")
    if retained.get("business_succeeded") is not False:
        blockers.append("sandbox prerequisite handoff must not claim business success")
    data = retained.get("data")
    if not isinstance(data, dict):
        blockers.append("sandbox prerequisite handoff data is invalid")
        data = {}
    if data.get("schema_version") != SANDBOX_PREREQUISITE_HANDOFF_SCHEMA:
        blockers.append("sandbox prerequisite handoff schema is invalid")
    if data.get("production_promotion_allowed") is not False:
        blockers.append("sandbox prerequisite handoff must not authorize production")
    if data.get("real_odoo_write_performed") is not False:
        blockers.append("sandbox prerequisite handoff must not be a write receipt")
    decisions = data.get("decisions")
    if not isinstance(decisions, list):
        blockers.append("sandbox prerequisite handoff decisions are invalid")
        decisions = []
    decision_ids: list[str] = []
    authorization_required_count = 0
    for index, raw_decision in enumerate(decisions):
        location = f"sandbox prerequisite handoff decisions[{index}]"
        if not isinstance(raw_decision, dict):
            blockers.append(f"{location} must be an object")
            continue
        decision_id = raw_decision.get("decision_id")
        if not isinstance(decision_id, str) or not decision_id:
            blockers.append(f"{location}.decision_id is invalid")
        else:
            decision_ids.append(decision_id)
        if raw_decision.get("authorization_required") is True:
            authorization_required_count += 1
        elif raw_decision.get("authorization_required") is not False:
            blockers.append(f"{location}.authorization_required is invalid")
        if raw_decision.get("status") != "pending":
            blockers.append(f"{location}.status must remain pending")
        if not isinstance(raw_decision.get("required_operator_action"), str) or not raw_decision.get("required_operator_action"):
            blockers.append(f"{location}.required_operator_action is invalid")
        if not isinstance(raw_decision.get("business_reason"), str) or not raw_decision.get("business_reason"):
            blockers.append(f"{location}.business_reason is invalid")
        if not isinstance(raw_decision.get("evidence"), dict):
            blockers.append(f"{location}.evidence is invalid")
    if len(decision_ids) != len(set(decision_ids)):
        blockers.append("sandbox prerequisite handoff decision ids must be unique")
    if data.get("decision_count") != len(decisions):
        blockers.append("sandbox prerequisite handoff decision_count mismatch")
    release_identity = data.get("release_identity")
    if not isinstance(release_identity, dict):
        if expected_release_identity is not None:
            blockers.append("sandbox prerequisite handoff release identity is invalid")
        release_identity = None
    elif expected_release_identity is not None:
        for field, expected in expected_release_identity.items():
            if expected is not None and release_identity.get(field) != expected:
                blockers.append(f"sandbox prerequisite handoff release {field} mismatch")
    return {
        "authorization_required_count": authorization_required_count,
        "blockers": sorted(set(blockers)),
        "decision_count": len(decisions),
        "decision_ids": sorted(set(decision_ids)),
        "handoff_check_ready": not blockers,
        "handoff_file": str(handoff_file),
        "handoff_sha256": _sha256_file(handoff_file),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "release_identity": release_identity,
        "schema_version": SANDBOX_PREREQUISITE_HANDOFF_SCHEMA,
    }


def _final_evidence_manifest_document(
    artifact_paths: dict[str, Path],
    *,
    artifact_sha256: dict[str, str],
    manifest_path: Path,
    release_identity: dict[str, Any],
) -> dict[str, Any]:
    return {
        "artifact_sha256": {
            name: artifact_sha256[name]
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


def _assert_final_checker_is_routed(
    route_report: dict[str, Any],
    *,
    command: str,
) -> None:
    routed_path = route_report.get("resolved_release_path")
    if not isinstance(routed_path, str) or not routed_path:
        raise CliFailure(
            command=command,
            code="final_evidence_checker_release_mismatch",
            message="The routed release path is unavailable to bind the final evidence checker.",
            exit_code=5,
        )
    try:
        resolved_routed_path = Path(routed_path).resolve(strict=True)
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="final_evidence_checker_release_mismatch",
            message="The routed release path is unavailable to bind the final evidence checker.",
            exit_code=5,
        ) from exc
    executing_release_path = Path(__file__).resolve().parents[2]
    if executing_release_path != resolved_routed_path:
        raise CliFailure(
            command=command,
            code="final_evidence_checker_release_mismatch",
            message="The final evidence checker is not executing from the routed release.",
            exit_code=5,
        )


def _assert_expected_release_identity_matches_executing(
    identity: dict[str, Any],
    supplied: dict[str, str | None],
    *,
    command: str,
    code: str,
) -> None:
    if any(
        expected is not None and expected != identity.get(field)
        for field, expected in supplied.items()
    ):
        raise CliFailure(
            command=command,
            code=code,
            message="The expected release identity does not match the executing release.",
            exit_code=5,
        )


def _final_evidence_manifest_report(
    manifest_path: Path,
    *,
    command: str,
    expected_release_identity: dict[str, Any],
) -> dict[str, Any]:
    blockers: list[str] = []
    manifest_path = Path(os.path.abspath(manifest_path))
    manifest, _manifest_raw, manifest_sha256, manifest_identity = (
        _read_final_json_snapshot(
            manifest_path,
            command=command,
            label="final evidence manifest",
            maximum=_MAX_FINAL_EVIDENCE_MANIFEST_BYTES,
        )
    )
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
    unexpected_artifacts = sorted(
        set(artifacts) - set(FINAL_EVIDENCE_REQUIRED_ARTIFACTS)
    )
    if unexpected_artifacts:
        blockers.append("final evidence manifest contains unexpected artifacts")
    unexpected_digests = sorted(
        set(artifact_sha256) - set(FINAL_EVIDENCE_REQUIRED_ARTIFACTS)
    )
    if unexpected_digests:
        blockers.append(
            "final evidence manifest contains unexpected artifact digests"
        )

    def retained_route_matches(route: object) -> bool:
        if not isinstance(route, dict) or route.get("current_route_ready") is not True:
            return False
        identity = route.get("route_identity")
        if not isinstance(identity, dict):
            return False
        return all(
            expected is None or identity.get(field) == expected
            for field, expected in expected_release_identity.items()
        )

    artifact_reports: dict[str, Any] = {}
    artifact_documents: dict[str, dict[str, Any]] = {}
    artifact_identities: dict[tuple[int, int, int, int, int], str] = {}
    artifact_snapshots: dict[
        str, tuple[Path, tuple[int, int, int, int, int], str]
    ] = {}
    pi_scenario_status: dict[str, Any] | None = None
    for name in FINAL_EVIDENCE_REQUIRED_ARTIFACTS:
        raw_path = artifacts.get(name)
        artifact_path = _manifest_artifact_path(manifest_path, raw_path)
        artifact_blockers: list[str] = []
        digest: str | None = None
        document: Any = None
        if artifact_path is None:
            artifact_blockers.append("artifact path is invalid")
        else:
            try:
                document, _raw, digest, identity = _read_final_json_snapshot(
                    artifact_path,
                    command=command,
                    label=f"final evidence artifact {name}",
                    maximum=_MAX_FINAL_EVIDENCE_ARTIFACT_BYTES,
                )
            except CliFailure:
                artifact_blockers.append("artifact is unavailable or invalid JSON")
                document = None
            else:
                artifact_snapshots[name] = (artifact_path, identity, digest)
                previous_name = artifact_identities.get(identity)
                if previous_name is not None:
                    artifact_blockers.append(
                        f"artifact file identity is already used by {previous_name}"
                    )
                else:
                    artifact_identities[identity] = name
                if artifact_sha256.get(name) != digest:
                    artifact_blockers.append(
                        "artifact SHA-256 does not match manifest"
                    )
        expected_command = FINAL_EVIDENCE_ARTIFACT_COMMANDS.get(name)
        if expected_command is not None and isinstance(document, dict):
            if document.get("command") != expected_command:
                artifact_blockers.append("artifact command does not match expected evidence kind")
        if isinstance(document, dict):
            artifact_documents[name] = document
        if name == "pi_scenario_report" and isinstance(document, dict):
            if document.get("schema_version") != PI_SCENARIO_REPORT_SCHEMA:
                artifact_blockers.append("Pi scenario report schema is invalid")
            retained_status = _pi_scenario_acceptance_report_status(
                artifact_path,
                command=command,
                expected_release_identity=expected_release_identity,
                retained_document=document,
                retained_sha256=digest,
            )
            pi_scenario_status = retained_status
            if retained_status["scenario_acceptance_ready"] is not True:
                artifact_blockers.append("Pi scenario report is not acceptance-ready")
        if name in {"pi_scenario_report_check", "pi_trace_capture_check"}:
            if not isinstance(document, dict):
                artifact_blockers.append("Pi evidence check is invalid")
            else:
                data = document.get("data")
                if (
                    document.get("ok") is not True
                    or document.get("business_succeeded") is not False
                    or not isinstance(data, dict)
                ):
                    artifact_blockers.append("Pi evidence check envelope is invalid")
                else:
                    if data.get("blockers") != []:
                        artifact_blockers.append("Pi evidence check retains blockers")
                    if data.get("production_promotion_allowed") is not False:
                        artifact_blockers.append(
                            "Pi evidence check must not authorize production"
                        )
                    if data.get("real_odoo_write_performed") is not False:
                        artifact_blockers.append(
                            "Pi evidence check must not be a real Odoo write receipt"
                        )
                    if not retained_route_matches(data.get("route")):
                        artifact_blockers.append(
                            "Pi evidence check route identity is invalid"
                        )
                    if name == "pi_trace_capture_check":
                        if data.get("trace_capture_ready") is not True:
                            artifact_blockers.append(
                                "Pi trace capture check is not ready"
                            )
                        capture = data.get("capture")
                        if (
                            not isinstance(capture, dict)
                            or capture.get("v3_package_sha256")
                            != expected_release_identity.get("package_sha256")
                            or capture.get("v3_manifest_sha256")
                            != expected_release_identity.get("manifest_sha256")
                            or data.get("registry_digest")
                            != expected_release_identity.get("registry_digest")
                        ):
                            artifact_blockers.append(
                                "Pi trace capture identity is invalid"
                            )
                    else:
                        if (
                            data.get("scenario_acceptance_ready") is not True
                            or data.get("recomputed_report_matches") is not True
                        ):
                            artifact_blockers.append(
                                "Pi scenario report check is not recomputed and ready"
                            )
                        pi_scenario = data.get("pi_scenario")
                        if (
                            not isinstance(pi_scenario, dict)
                            or pi_scenario.get("scenario_acceptance_ready") is not True
                        ):
                            artifact_blockers.append(
                                "Pi scenario report check summary is invalid"
                            )
        if name == "sandbox_provision_authorization" and isinstance(document, dict):
            if document.get("purpose") != "sandbox_database_provision":
                artifact_blockers.append("sandbox provision authorization purpose is invalid")
        if name == "sandbox_provision_authorization_check" and isinstance(document, dict):
            data = document.get("data")
            if not isinstance(data, dict):
                artifact_blockers.append("sandbox provision authorization check data is invalid")
            elif data.get("authorization_record_ready") is not True:
                artifact_blockers.append("sandbox provision authorization check is not ready")
        if name == "sandbox_onboarding_receipt_check" and isinstance(document, dict):
            data = document.get("data")
            if not isinstance(data, dict):
                artifact_blockers.append("sandbox onboarding receipt check data is invalid")
            else:
                onboarding = data.get("onboarding")
                if data.get("sandbox_write_preflight_receipt_acceptable") is not True:
                    artifact_blockers.append("sandbox onboarding receipt check is not acceptable")
                if not isinstance(onboarding, dict) or onboarding.get("ready") is not True:
                    artifact_blockers.append("sandbox onboarding receipt check is not ready")
        if name == "goal_readiness_report" and isinstance(document, dict):
            data = document.get("data")
            if document.get("ok") is not True:
                artifact_blockers.append(
                    "goal readiness report is not a successful CLI report"
                )
            if document.get("business_succeeded") is not False:
                artifact_blockers.append(
                    "goal readiness report business status is invalid"
                )
            if not isinstance(data, dict):
                artifact_blockers.append("goal readiness report data is invalid")
            else:
                if data.get("goal_readiness_ready") is not True:
                    artifact_blockers.append("goal readiness report is not ready")
                if data.get("blockers") != []:
                    artifact_blockers.append(
                        "goal readiness report retains blockers"
                    )
                if data.get("production_promotion_allowed") is not False:
                    artifact_blockers.append(
                        "goal readiness report must not authorize production"
                    )
                if data.get("real_odoo_write_performed") is not False:
                    artifact_blockers.append(
                        "goal readiness report must not be a real Odoo write receipt"
                    )
                retained_release_identity = data.get("release_identity")
                if not isinstance(retained_release_identity, dict):
                    artifact_blockers.append(
                        "goal readiness report release identity is invalid"
                    )
                else:
                    for field, expected in expected_release_identity.items():
                        if (
                            expected is not None
                            and retained_release_identity.get(field) != expected
                        ):
                            artifact_blockers.append(
                                f"goal readiness report release {field} mismatch"
                            )
                readiness_paths = {
                    "capacity": ("sandbox_write_capacity_ready",),
                    "pi_scenario": ("scenario_acceptance_ready",),
                    "read_capabilities_readiness": (
                        "read_static_readiness_ready",
                        "read_goal_readiness_ready",
                    ),
                    "registry": ("registry_audit_ready",),
                    "route": ("current_route_ready",),
                    "sandbox_database": ("sandbox_database_ready",),
                    "sandbox_onboarding": ("ready",),
                    "sandbox_provision_authorization": (
                        "authorization_record_ready",
                    ),
                    "write_evidence_index": ("index_ready",),
                    "write_pipeline": ("write_pipeline_ready",),
                    "write_static_readiness": (
                        "write_static_readiness_ready",
                    ),
                }
                for section_name, ready_fields in readiness_paths.items():
                    section = data.get(section_name)
                    if not isinstance(section, dict) or any(
                        section.get(field) is not True for field in ready_fields
                    ):
                        artifact_blockers.append(
                            f"goal readiness report {section_name} is not ready"
                        )
        if (
            name == "read_capabilities_readiness_report"
            and isinstance(document, dict)
        ):
            data = document.get("data")
            if document.get("ok") is not True:
                artifact_blockers.append(
                    "read capabilities readiness report is not a successful CLI report"
                )
            if document.get("business_succeeded") is not False:
                artifact_blockers.append(
                    "read capabilities readiness report business status is invalid"
                )
            if not isinstance(data, dict):
                artifact_blockers.append(
                    "read capabilities readiness report data is invalid"
                )
            else:
                retained_release_identity = data.get("release_identity")
                if not isinstance(retained_release_identity, dict):
                    artifact_blockers.append(
                        "read capabilities readiness report release identity is invalid"
                    )
                else:
                    for field, expected in expected_release_identity.items():
                        if (
                            expected is not None
                            and retained_release_identity.get(field) != expected
                        ):
                            artifact_blockers.append(
                                f"read capabilities readiness report release {field} mismatch"
                            )
                if data.get("read_static_readiness_ready") is not True:
                    artifact_blockers.append(
                        "read capabilities static readiness is not ready"
                    )
                if data.get("read_goal_readiness_ready") is not True:
                    artifact_blockers.append(
                        "read capabilities goal evidence readiness is not ready"
                    )
                if data.get("real_odoo_write_performed") is not False:
                    artifact_blockers.append(
                        "read capabilities readiness report must not be a real Odoo write receipt"
                    )
                if data.get("production_promotion_allowed") is not False:
                    artifact_blockers.append(
                        "read capabilities readiness report must not authorize production"
                    )
                retained_external = data.get("external_read_evidence")
                reverified_external = None
                if isinstance(retained_external, dict):
                    index_path = retained_external.get("index_path")
                    if (
                        isinstance(index_path, str)
                        and index_path
                        and isinstance(retained_release_identity, dict)
                    ):
                        reverified_external = _external_read_evidence_report(
                            Path(index_path),
                            expected_release_identity=retained_release_identity,
                            capabilities=_load_capabilities(),
                        )
                try:
                    expected_read_report = _read_capabilities_readiness_report(
                        _load_capabilities(),
                        trusted_read_handlers=_load_read_capability_implementation(
                            command
                        ),
                        external_evidence_report=reverified_external,
                    )
                except CliFailure:
                    expected_read_report = None
                    artifact_blockers.append(
                        "current release read capability readiness cannot be recomputed"
                    )
                if expected_read_report is not None:
                    expected_fields = {
                        **expected_read_report,
                        "release_identity": retained_release_identity,
                    }
                    if (
                        set(data) != set(expected_fields)
                        or any(
                            data.get(field) != expected
                            for field, expected in expected_read_report.items()
                        )
                    ):
                        artifact_blockers.append(
                            "read capabilities readiness report does not match the current release"
                        )
                    if expected_read_report["read_goal_readiness_ready"] is not True:
                        artifact_blockers.append(
                            "current release read capability readiness is incomplete"
                        )
        if name == "sandbox_database_candidates_report" and isinstance(document, dict):
            data = document.get("data")
            if not isinstance(data, dict):
                artifact_blockers.append("sandbox database candidates report data is invalid")
            else:
                if data.get("sandbox_database_selection_ready") is not True:
                    artifact_blockers.append("sandbox database candidates report is not ready")
                if data.get("selected_database_eligible") is not True:
                    artifact_blockers.append("sandbox database selected candidate is not eligible")
                if data.get("real_odoo_write_performed") is not False:
                    artifact_blockers.append("sandbox database candidates must not be a real Odoo write receipt")
        if name == "target_capacity_plan_report" and isinstance(document, dict):
            data = document.get("data")
            if not isinstance(data, dict):
                artifact_blockers.append("target capacity plan report data is invalid")
            else:
                plan = data.get("plan")
                if not isinstance(plan, dict):
                    artifact_blockers.append("target capacity plan report is missing data.plan")
                elif plan.get("kind") != "odoo-accounting-cli-v3.target-capacity-plan.v1":
                    artifact_blockers.append("target capacity plan kind is invalid")
                if data.get("sandbox_write_capacity_ready") is not True:
                    artifact_blockers.append("target capacity plan report is not ready")
                if data.get("cleanup_executed") is not False:
                    artifact_blockers.append("target capacity plan must be read-only and unexecuted")
                if data.get("real_odoo_write_performed") is not False:
                    artifact_blockers.append("target capacity plan must not be a real Odoo write receipt")
        if name == "target_capacity_recheck_report" and isinstance(document, dict):
            data = document.get("data")
            if not isinstance(data, dict):
                artifact_blockers.append("target capacity recheck report data is invalid")
            else:
                if data.get("sandbox_write_capacity_ready") is not True:
                    artifact_blockers.append("target capacity recheck report is not ready")
                if data.get("cleanup_executed") is not False:
                    artifact_blockers.append("target capacity recheck must be read-only and unexecuted")
                if data.get("real_odoo_write_performed") is not False:
                    artifact_blockers.append("target capacity recheck must not be a real Odoo write receipt")
        if name == "sandbox_prerequisite_handoff" and isinstance(document, dict):
            data = document.get("data")
            if not isinstance(data, dict):
                artifact_blockers.append("sandbox prerequisite handoff data is invalid")
            else:
                if data.get("schema_version") != SANDBOX_PREREQUISITE_HANDOFF_SCHEMA:
                    artifact_blockers.append("sandbox prerequisite handoff schema is invalid")
                if data.get("production_promotion_allowed") is not False:
                    artifact_blockers.append("sandbox prerequisite handoff must not authorize production")
                if data.get("real_odoo_write_performed") is not False:
                    artifact_blockers.append("sandbox prerequisite handoff must not be a write receipt")
        if name == "sandbox_prerequisite_handoff_check" and isinstance(document, dict):
            data = document.get("data")
            if not isinstance(data, dict):
                artifact_blockers.append("sandbox prerequisite handoff check data is invalid")
            else:
                if data.get("schema_version") != SANDBOX_PREREQUISITE_HANDOFF_SCHEMA:
                    artifact_blockers.append("sandbox prerequisite handoff check schema is invalid")
                if data.get("handoff_check_ready") is not True:
                    artifact_blockers.append("sandbox prerequisite handoff check is not ready")
        if artifact_blockers:
            blockers.extend(f"{name}: {item}" for item in artifact_blockers)
        artifact_reports[name] = {
            "blockers": sorted(set(artifact_blockers)),
            "path": str(artifact_path) if artifact_path is not None else raw_path,
            "sha256": digest,
        }

    raw_pi_report = artifact_documents.get("pi_scenario_report")
    trace_check = artifact_documents.get("pi_trace_capture_check")
    report_check = artifact_documents.get("pi_scenario_report_check")
    goal_readiness = artifact_documents.get("goal_readiness_report")
    if all(
        isinstance(document, dict)
        for document in (raw_pi_report, trace_check, report_check, goal_readiness)
    ):
        trace_data = trace_check.get("data")
        report_data = report_check.get("data")
        goal_data = goal_readiness.get("data")
        raw_report_sha256 = artifact_reports["pi_scenario_report"]["sha256"]
        if not all(
            isinstance(data, dict)
            for data in (trace_data, report_data, goal_data)
        ):
            blockers.append("Pi final evidence cross-binding data is invalid")
        else:
            cross_bindings = {
                "raw report SHA-256": (
                    raw_report_sha256,
                    report_data.get("pi_scenario_report_sha256"),
                ),
                "trace file SHA-256": (
                    trace_data.get("trace_file_sha256"),
                    report_data.get("trace_file_sha256"),
                ),
                "trace document SHA-256": (
                    raw_pi_report.get("trace_document_sha256"),
                    trace_data.get("trace_document_sha256"),
                    report_data.get("trace_document_sha256"),
                ),
                "trace attestation payload SHA-256": (
                    raw_pi_report.get("attestation_signed_payload_sha256"),
                    trace_data.get("attestation_signed_payload_sha256"),
                    report_data.get(
                        "trace_attestation_signed_payload_sha256"
                    ),
                ),
                "capture binding file SHA-256": (
                    trace_data.get("expected_capture_binding_sha256"),
                    report_data.get("expected_capture_binding_sha256"),
                ),
                "capture binding canonical SHA-256": (
                    raw_pi_report.get("expected_capture_binding_sha256"),
                    trace_data.get(
                        "expected_capture_binding_canonical_sha256"
                    ),
                    report_data.get(
                        "expected_capture_binding_canonical_sha256"
                    ),
                ),
            }
            for label, values in cross_bindings.items():
                if (
                    any(
                        not isinstance(value, str)
                        or re.fullmatch(r"[0-9a-f]{64}", value) is None
                        for value in values
                    )
                    or len(set(values)) != 1
                ):
                    blockers.append(f"Pi final evidence {label} mismatch")
            if raw_pi_report.get("capture") != trace_data.get("capture"):
                blockers.append("Pi final evidence capture identity mismatch")
            goal_pi = goal_data.get("pi_scenario")
            if (
                not isinstance(goal_pi, dict)
                or goal_pi.get("report_sha256") != raw_report_sha256
                or goal_pi.get("scenario_acceptance_ready") is not True
            ):
                blockers.append(
                    "goal readiness Pi scenario evidence is not bound to the retained report"
                )
    else:
        blockers.append("Pi final evidence artifacts cannot be cross-bound")

    raw_pi_report_path = _manifest_artifact_path(
        manifest_path, artifacts.get("pi_scenario_report")
    )
    report_check_path = _manifest_artifact_path(
        manifest_path,
        artifacts.get("pi_scenario_report_check"),
    )
    if raw_pi_report_path is None or report_check_path is None:
        blockers.append(
            "Pi final evidence trusted recomputation artifacts are unavailable"
        )
    else:
        raw_pi_status = pi_scenario_status
        report_check_document = artifact_documents.get("pi_scenario_report_check")
        report_check_sha256 = artifact_reports.get(
            "pi_scenario_report_check", {}
        ).get("sha256")
        if (
            raw_pi_status is None
            or not isinstance(report_check_document, dict)
            or not isinstance(report_check_sha256, str)
        ):
            blockers.append(
                "Pi final evidence trusted recomputation snapshots are unavailable"
            )
        else:
            recomputation_status = _pi_recomputation_check_status(
                report_check_path,
                pi_scenario_status=raw_pi_status,
                command=command,
                expected_release_identity=expected_release_identity,
                retained_document=report_check_document,
                retained_sha256=report_check_sha256,
            )
            if recomputation_status["recomputation_ready"] is not True:
                blockers.extend(
                    "Pi trusted recomputation: " + item
                    for item in recomputation_status["blockers"]
                )

    try:
        _recheck_final_file_snapshot(
            manifest_path,
            expected_identity=manifest_identity,
            expected_sha256=manifest_sha256,
            maximum=_MAX_FINAL_EVIDENCE_MANIFEST_BYTES,
            command=command,
            label="final evidence manifest",
        )
    except CliFailure:
        blockers.append("final evidence manifest changed after snapshot")
    for name, (artifact_path, identity, digest) in artifact_snapshots.items():
        try:
            _recheck_final_file_snapshot(
                artifact_path,
                expected_identity=identity,
                expected_sha256=digest,
                maximum=_MAX_FINAL_EVIDENCE_ARTIFACT_BYTES,
                command=command,
                label=f"final evidence artifact {name}",
            )
        except CliFailure:
            change_blocker = "artifact changed after snapshot"
            blockers.append(f"{name}: {change_blocker}")
            artifact_reports[name]["blockers"] = sorted(
                set([*artifact_reports[name]["blockers"], change_blocker])
            )

    return {
        "artifact_count": len(FINAL_EVIDENCE_REQUIRED_ARTIFACTS),
        "artifacts": artifact_reports,
        "blockers": sorted(set(blockers)),
        "final_evidence_manifest_ready": not blockers,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
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


def _sandbox_write_required_evidence(
    verifier: Any,
    *,
    capability_root: Path,
    metadata_path: Path,
) -> dict[str, Any]:
    lifecycle_artifacts = getattr(verifier, "DEFAULT_LIFECYCLE_ARTIFACTS", {})
    lifecycle_receipt_id_fields = sorted(
        getattr(verifier, "ID_LIFECYCLE_FIELDS", ())
    )
    return {
        "environment": "sandbox",
        "lifecycle_artifact_files": {
            field: str(capability_root / filename)
            for field, filename in sorted(lifecycle_artifacts.items())
        },
        "lifecycle_receipt_id_fields": lifecycle_receipt_id_fields,
        "metadata_json": str(metadata_path),
        "metadata_required_fields": [
            "capability_id",
            "company_id",
            "database_uuid",
            "environment",
            "lifecycle_receipt_ids",
            "production_promotion_allowed",
            "registry_receipts",
            "release_identity",
            "schema_version",
            "scope",
        ],
        "preflight_manifest": str(
            capability_root
            / getattr(
                verifier,
                "DEFAULT_PREFLIGHT_MANIFEST",
                "preflight_manifest.json",
            )
        ),
        "production_promotion_allowed": False,
        "required_real_odoo_receipt_kinds": sorted(
            getattr(verifier, "REQUIRED_KINDS", ())
        ),
    }


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


def _load_pi_evidence_trust(
    gate: Any,
    trusted_authority_config: Path,
    *,
    expected_release_digest: str,
    expected_registry_digest: str,
) -> Any:
    """Load Pi receipt trust through the exact-release gate boundary."""

    return gate.load_pi_evidence_trust(
        trusted_authority_config,
        expected_release_digest=expected_release_digest,
        expected_registry_digest=expected_registry_digest,
    )


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


_READ_RECEIPT_PROPERTY_SCHEMAS: dict[str, dict[str, Any]] = {
    "id": {"type": "string", "minLength": 1},
    "odoo_instance_id": {"type": "string", "minLength": 1},
    "database_name": {"type": "string", "minLength": 1},
    "database_uuid": {"type": "string", "minLength": 1},
    "company_id": {"type": "integer", "minimum": 1},
    "user_id": {"type": "integer", "minimum": 1},
    "capability_id": {"type": "string", "minLength": 1},
    "environment": {"type": "string", "enum": ["test", "sandbox", "production"]},
    "capability_channel": {"type": "string", "enum": ["staged", "enabled"]},
    "request_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "result_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "registry_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "release_digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
    "record_count": {"type": "integer", "minimum": 0},
    "observed_at": {"type": "string", "format": "date-time"},
    "signature_version": {
        "type": "integer",
        "enum": [READ_RECEIPT_SIGNATURE_VERSION],
    },
    "signature_purpose": {
        "type": "string",
        "enum": [READ_RECEIPT_PURPOSE],
    },
    "signature_key_id": {"type": "string", "minLength": 1},
    "signature": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
}
_READ_RECEIPT_FIELDS = frozenset(_READ_RECEIPT_PROPERTY_SCHEMAS)
_REQUIRED_READ_CAPABILITY_IDS = frozenset(
    {
        "acct.ap.open_items.v1",
        "acct.ar.open_items.v1",
        "acct.diagnostics.operation_read.v1",
        "acct.gl.trial_balance.v1",
        "acct.move.document_post_eligibility.v1",
        "acct.move.draft_cancel_eligibility.v1",
        "acct.multicompany.consolidated_read.v1",
        "acct.multicurrency.balance_read.v1",
        "acct.refund.draft_cancel_eligibility.v1",
        "acct.refund.post_reconcile_eligibility.v1",
        "acct.registry.list.v1",
        "acct.report.financial_read.v1",
        "acct.tax.report_read.v1",
    }
)
_TRUSTED_READ_HANDLER_KINDS = frozenset(
    {"odoo", "trusted_local_persistence"}
)


def _schema_has_at_least_constraints(
    candidate: Any,
    required: dict[str, Any],
) -> bool:
    if not isinstance(candidate, dict):
        return False
    for key, value in required.items():
        observed = candidate.get(key)
        if key in {"minimum", "minLength"}:
            if (
                type(observed) is not int
                or type(value) is not int
                or observed < value
            ):
                return False
        elif observed != value:
            return False
    return True


def _load_read_capability_implementation(command: str) -> dict[str, str]:
    try:
        from .odoo.executor import _CAPABILITIES as odoo_read_capabilities
        from .operation_diagnostics import (
            TRUSTED_LOCAL_PERSISTENCE_READ_CAPABILITIES,
        )
    except Exception as exc:
        raise CliFailure(
            command=command,
            code="read_capability_runtime_unavailable",
            message="The trusted read capability implementation allowlist is unavailable.",
            exit_code=5,
        ) from exc
    handler_allowlists = {
        "odoo": odoo_read_capabilities,
        "trusted_local_persistence": (
            TRUSTED_LOCAL_PERSISTENCE_READ_CAPABILITIES
        ),
    }
    if (
        set(handler_allowlists) != _TRUSTED_READ_HANDLER_KINDS
        or any(
            not isinstance(allowlist, frozenset)
            or not allowlist
            or any(
                not isinstance(capability_id, str) or not capability_id
                for capability_id in allowlist
            )
            for allowlist in handler_allowlists.values()
        )
        or len(set().union(*handler_allowlists.values()))
        != sum(len(allowlist) for allowlist in handler_allowlists.values())
        or not set().union(*handler_allowlists.values()).issubset(
            _REQUIRED_READ_CAPABILITY_IDS
        )
    ):
        raise CliFailure(
            command=command,
            code="read_capability_runtime_invalid",
            message="The trusted read capability implementation allowlist is invalid.",
            exit_code=5,
        )
    return {
        capability_id: handler_kind
        for handler_kind, allowlist in sorted(handler_allowlists.items())
        for capability_id in sorted(allowlist)
    }


def _read_capability_contracts(
    capabilities: tuple[Capability, ...],
) -> dict[str, str]:
    return {
        capability.id: _sha256_json(capability.data)
        for capability in sorted(capabilities, key=lambda item: item.id)
        if capability.data["access"] == "read"
    }


def _verify_external_read_evidence_index(
    evidence_index: Path,
    *,
    expected_release_identity: dict[str, Any],
    expected_capability_contracts: dict[str, str],
) -> dict[str, Any]:
    try:
        raw, _identity = _read_trusted_file(
            evidence_index,
            "read evidence index schema snapshot",
            maximum=READ_EVIDENCE_V3_MAX_INDEX_BYTES,
            require_root_owner=True,
        )
    except HistoricalRouterError as exc:
        raise ReadEvidenceIndexError(
            "read evidence index cannot be safely classified"
        ) from exc

    schema = detect_read_evidence_schema(raw)
    if schema == "v3":
        return verify_read_evidence_v3(
            evidence_index,
            expected_release_identity=expected_release_identity,
        )
    if schema == "v2":
        legacy_report = verify_read_evidence_index(
            evidence_index,
            expected_release_identity=expected_release_identity,
            expected_capability_contracts=expected_capability_contracts,
        )
        if type(legacy_report) is not dict:
            raise ReadEvidenceIndexError(
                "legacy read evidence verifier returned an invalid report"
            )
        blockers = legacy_report.get("blockers")
        retained_blockers = (
            [item for item in blockers if isinstance(item, str) and item]
            if isinstance(blockers, list)
            else []
        )
        retained_blockers.append(LEGACY_V2_BLOCKER)
        structural_verified = legacy_report.get(
            "legacy_v2_structural_audit_verified"
        )
        if type(structural_verified) is not bool:
            structural_verified = (
                legacy_report.get("external_read_evidence_verified") is True
            )
        return {
            **legacy_report,
            "blockers": sorted(set(retained_blockers)),
            "evidence_protocol": "hmac-v2",
            "external_read_evidence_verified": False,
            "goal_evidence_admissible": False,
            "index_kind": LEGACY_READ_EVIDENCE_INDEX_SCHEMA,
            "legacy_v2_structural_audit_verified": structural_verified,
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
        }
    raise ReadEvidenceIndexError("read evidence index schema is invalid")


def _external_read_evidence_report(
    evidence_index: Path | None,
    *,
    expected_release_identity: dict[str, Any],
    capabilities: tuple[Capability, ...],
) -> dict[str, Any] | None:
    if evidence_index is None:
        return None
    try:
        report = _verify_external_read_evidence_index(
            evidence_index,
            expected_release_identity=expected_release_identity,
            expected_capability_contracts=_read_capability_contracts(capabilities),
        )
    except (ReadEvidenceIndexError, ReadEvidenceV3Error) as exc:
        return {
            "blockers": [str(exc)],
            "capabilities": [],
            "external_read_evidence_verified": False,
            "index_path": str(evidence_index),
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
        }
    return {
        **report,
        "blockers": list(report.get("blockers", [])),
    }


def _read_capability_readiness_report(
    capability: Capability,
    *,
    trusted_read_handlers: dict[str, str],
    external_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = capability.data
    output_schema = data["output_schema"]
    output_properties = output_schema.get("properties", {})
    output_required = output_schema.get("required", [])
    page_schema = output_properties.get("page")
    page_properties = (
        page_schema.get("properties", {}) if isinstance(page_schema, dict) else {}
    )
    total_count_schema = page_properties.get("total_count")
    receipt_schema = output_properties.get("receipt")
    receipt_properties = (
        receipt_schema.get("properties", {})
        if isinstance(receipt_schema, dict)
        else {}
    )
    receipt_required = (
        receipt_schema.get("required", [])
        if isinstance(receipt_schema, dict)
        else []
    )
    receipt_capability_schema = receipt_properties.get("capability_id")
    receipt_properties_without_capability = {
        key: value
        for key, value in receipt_properties.items()
        if key != "capability_id"
    }
    expected_receipt_properties_without_capability = {
        key: value
        for key, value in _READ_RECEIPT_PROPERTY_SCHEMAS.items()
        if key != "capability_id"
    }
    trusted_handler_kind = trusted_read_handlers.get(capability.id)
    if trusted_handler_kind in _TRUSTED_READ_HANDLER_KINDS:
        read_receipt_properties_match = (
            set(receipt_properties_without_capability)
            == set(expected_receipt_properties_without_capability)
            and all(
                _schema_has_at_least_constraints(
                    receipt_properties_without_capability[key],
                    expected_schema,
                )
                for key, expected_schema
                in expected_receipt_properties_without_capability.items()
            )
        )
    else:
        read_receipt_properties_match = False
    receipt_capability_schema_matches = (
        receipt_capability_schema
        == _READ_RECEIPT_PROPERTY_SCHEMAS["capability_id"]
        or receipt_capability_schema
        == {"type": "string", "enum": [capability.id]}
        or (
            isinstance(receipt_capability_schema, dict)
            and _schema_has_at_least_constraints(
                receipt_capability_schema,
                _READ_RECEIPT_PROPERTY_SCHEMAS["capability_id"],
            )
            and receipt_capability_schema.get("enum") == [capability.id]
        )
    )
    evidence = data["evidence"]
    evidence_level = evidence.get("level")
    evidence_receipts = evidence.get("receipts", [])
    registry_claimed_receipts = [
        receipt
        for receipt in evidence_receipts
        if isinstance(receipt, dict)
    ]
    registry_claimed_receipt_kinds = sorted(
        {
            receipt["kind"]
            for receipt in registry_claimed_receipts
            if isinstance(receipt.get("kind"), str)
        }
    )
    external_evidence_kinds = (
        external_evidence.get("verified_evidence_kinds", [])
        if isinstance(external_evidence, dict)
        else []
    )
    external_read_evidence_verified = (
        isinstance(external_evidence, dict)
        and external_evidence.get("capability_id") == capability.id
        and external_evidence.get("verified") is True
        and external_evidence_kinds == list(REQUIRED_EVIDENCE_KINDS)
    )
    missing_goal_evidence_kinds = sorted(
        PRODUCTION_READ_EVIDENCE
        - (set(registry_claimed_receipt_kinds) | set(external_evidence_kinds))
    )
    routed_environments = set(data.get("staged_environments", [])) | set(
        data.get("enabled_environments", [])
    )
    checks = {
        "contract_evidence_present": evidence_level != "declared",
        "trusted_handler_supported": capability.id in trusted_read_handlers,
        "page_total_count_contract": (
            isinstance(page_schema, dict)
            and page_schema.get("type") == "object"
            and page_schema.get("additionalProperties") is False
            and isinstance(output_required, list)
            and "page" in output_required
            and "total_count" in page_schema.get("required", [])
            and isinstance(total_count_schema, dict)
            and total_count_schema.get("type") == "integer"
            and type(total_count_schema.get("minimum")) is int
            and total_count_schema["minimum"] >= 0
        ),
        "read_policy_closed": (
            data["approval"].get("required") is False
            and data["idempotency"].get("required") is False
        ),
        "read_receipt_v2_contract": (
            isinstance(receipt_schema, dict)
            and receipt_schema.get("type") == "object"
            and receipt_schema.get("additionalProperties") is False
            and isinstance(output_required, list)
            and "receipt" in output_required
            and read_receipt_properties_match
            and receipt_capability_schema_matches
            and set(receipt_required) == _READ_RECEIPT_FIELDS
        ),
        "strict_input_schema": _is_strict_object_schema(data["input_schema"]),
        "strict_output_schema": _is_strict_object_schema(output_schema),
        "test_execution_routed": "test" in routed_environments,
        "verification_method_present": (
            isinstance(data["verification"].get("method"), str)
            and bool(data["verification"]["method"].strip())
        ),
    }
    blockers = [
        name.replace("_", " ")
        for name, ready in checks.items()
        if ready is not True
    ]
    goal_evidence_blockers = (
        []
        if external_read_evidence_verified
        else ["trusted external read evidence has not been independently verified"]
    )
    goal_evidence_ready = external_read_evidence_verified
    trusted_read_admissible = not blockers
    return {
        "blockers": blockers,
        "capability": {
            "access": data["access"],
            "enabled_environments": data["enabled_environments"],
            "evidence_level": evidence_level,
            "id": capability.id,
            "staged_environments": data.get("staged_environments", []),
        },
        "checks": checks,
        "external_read_evidence_verified": external_read_evidence_verified,
        "goal_evidence_blockers": goal_evidence_blockers,
        "goal_evidence_ready": goal_evidence_ready,
        "missing_goal_evidence_kinds": missing_goal_evidence_kinds,
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "trusted_handler_kind": trusted_handler_kind,
        "trusted_read_admissible": trusted_read_admissible,
        "read_completion_ready": (
            trusted_read_admissible and goal_evidence_ready
        ),
        "registry_claimed_receipt_count": len(registry_claimed_receipts),
        "registry_claimed_receipt_kinds": registry_claimed_receipt_kinds,
        "registry_receipts_authoritative_for_goal": False,
    }


def _read_capabilities_readiness_report(
    capabilities: tuple[Capability, ...],
    *,
    trusted_read_handlers: dict[str, str],
    external_evidence_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    read_capabilities = sorted(
        (item for item in capabilities if item.data["access"] == "read"),
        key=lambda item: item.id,
    )
    external_entries = (
        {
            item["capability_id"]: item
            for item in external_evidence_report.get("capabilities", [])
            if isinstance(item, dict) and isinstance(item.get("capability_id"), str)
        }
        if isinstance(external_evidence_report, dict)
        and external_evidence_report.get("external_read_evidence_verified") is True
        and external_evidence_report.get("goal_evidence_admissible") is True
        and external_evidence_report.get("evidence_protocol")
        == ADMISSIBLE_READ_EVIDENCE_PROTOCOL
        and external_evidence_report.get("index_kind")
        == ADMISSIBLE_READ_EVIDENCE_INDEX_SCHEMA
        else {}
    )
    reports = [
        _read_capability_readiness_report(
            capability,
            trusted_read_handlers=trusted_read_handlers,
            external_evidence=external_entries.get(capability.id),
        )
        for capability in read_capabilities
    ]
    registered_read_capability_ids = [
        report["capability"]["id"] for report in reports
    ]
    missing_required_read_capability_ids = sorted(
        _REQUIRED_READ_CAPABILITY_IDS - set(registered_read_capability_ids)
    )
    admissible_ids = [
        report["capability"]["id"]
        for report in reports
        if report["trusted_read_admissible"] is True
    ]
    unready_ids = [
        report["capability"]["id"]
        for report in reports
        if report["trusted_read_admissible"] is not True
    ]
    goal_evidence_ready_ids = [
        report["capability"]["id"]
        for report in reports
        if report["goal_evidence_ready"] is True
    ]
    goal_evidence_unready_ids = [
        report["capability"]["id"]
        for report in reports
        if report["goal_evidence_ready"] is not True
    ]
    completion_ready_ids = [
        report["capability"]["id"]
        for report in reports
        if report["read_completion_ready"] is True
    ]
    blockers = []
    if not reports:
        blockers.append("capability registry has no registered read capabilities")
    if missing_required_read_capability_ids:
        blockers.append(
            "capability registry is missing required read capabilities"
        )
    if unready_ids:
        blockers.append(
            "not every registered read capability is statically admissible for trusted execution"
        )
    if reports and goal_evidence_unready_ids:
        blockers.append(
            "trusted external read evidence is not independently verified for every registered read capability"
        )
    external_verifier_ready = (
        isinstance(external_evidence_report, dict)
        and external_evidence_report.get("external_read_evidence_verified") is True
        and external_evidence_report.get("goal_evidence_admissible") is True
        and external_evidence_report.get("evidence_protocol")
        == ADMISSIBLE_READ_EVIDENCE_PROTOCOL
        and external_evidence_report.get("index_kind")
        == ADMISSIBLE_READ_EVIDENCE_INDEX_SCHEMA
        and not external_evidence_report.get("blockers")
    )
    if isinstance(external_evidence_report, dict):
        blockers.extend(external_evidence_report.get("blockers", []))
    read_static_ready = (
        bool(reports)
        and not unready_ids
        and not missing_required_read_capability_ids
    )
    read_goal_ready = (
        read_static_ready
        and external_verifier_ready
        and len(goal_evidence_ready_ids) == len(reports)
    )
    return {
        "admissible_count": len(admissible_ids),
        "admissible_ids": admissible_ids,
        "blockers": blockers,
        "capabilities": reports,
        "completion_ready_count": len(completion_ready_ids),
        "completion_ready_ids": completion_ready_ids,
        "external_read_evidence": external_evidence_report,
        "external_read_evidence_verifier_ready": external_verifier_ready,
        "goal_evidence_ready_count": len(goal_evidence_ready_ids),
        "goal_evidence_ready_ids": goal_evidence_ready_ids,
        "goal_evidence_unready_capability_ids": goal_evidence_unready_ids,
        "production_promotion_allowed": False,
        "read_goal_readiness_ready": read_goal_ready,
        "read_static_readiness_ready": read_static_ready,
        "real_odoo_write_performed": False,
        "registered_read_capability_ids": registered_read_capability_ids,
        "missing_required_read_capability_ids": (
            missing_required_read_capability_ids
        ),
        "required_read_capability_ids": sorted(_REQUIRED_READ_CAPABILITY_IDS),
        "required_goal_evidence_kinds": sorted(PRODUCTION_READ_EVIDENCE),
        "total_read_capabilities": len(reports),
        "unready_capability_ids": unready_ids,
    }


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


@evidence_group.command("read-evidence-index-check")
@click.option(
    "--evidence-index",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Canonical exact-release external read evidence index.",
)
def evidence_read_evidence_index_check(evidence_index: Path) -> None:
    """Independently verify every external read evidence artifact."""

    command = "evidence.read-evidence-index-check"
    identity = _load_release_identity(command=command)
    capabilities = _load_capabilities()
    try:
        report = _verify_external_read_evidence_index(
            evidence_index,
            expected_release_identity=identity,
            expected_capability_contracts=_read_capability_contracts(capabilities),
        )
    except (ReadEvidenceIndexError, ReadEvidenceV3Error) as exc:
        raise CliFailure(
            command=command,
            code="read_evidence_index_rejected",
            message=str(exc),
            exit_code=5,
        ) from exc
    _success(
        command,
        report,
        business_succeeded=False,
    )


@evidence_group.command("read-capabilities-readiness")
@click.option(
    "--read-evidence-index",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Canonical exact-release external read evidence index.",
)
def evidence_read_capabilities_readiness(
    read_evidence_index: Path | None,
) -> None:
    """Check trusted execution readiness for every registered read capability."""

    command = "evidence.read-capabilities-readiness"
    identity = _load_release_identity(command=command)
    capabilities = _load_capabilities()
    trusted_read_handlers = _load_read_capability_implementation(command)
    external_evidence = _external_read_evidence_report(
        read_evidence_index,
        expected_release_identity=identity,
        capabilities=capabilities,
    )
    report = _read_capabilities_readiness_report(
        capabilities,
        trusted_read_handlers=trusted_read_handlers,
        external_evidence_report=external_evidence,
    )
    _success(
        command,
        {
            **report,
            "release_identity": identity,
        },
        business_succeeded=False,
    )


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
        capability_root = evidence_root / capability.id
        metadata_path = capability_root / "metadata.json"
        required_evidence = _sandbox_write_required_evidence(
            verifier,
            capability_root=capability_root,
            metadata_path=metadata_path,
        )
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
                "required_evidence": required_evidence,
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
                "required_evidence": report["required_evidence"],
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
    "--trace-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Exact normalized Pi trace capture used to produce the report.",
)
@click.option(
    "--attestation-keys",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Host-local trusted HMAC attestation keys for the trace capture.",
)
@click.option(
    "--expected-capture-binding",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Independent exact Pi/Bridge/provider/model/prompt/tool/runtime binding.",
)
@click.option(
    "--trusted-authority-config",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help=(
        "Root-managed trusted-authority runtime configuration whose verified "
        "release route supplies receipt and approval verification keys."
    ),
)
@click.option(
    "--corpus",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("tests/fixtures/pi_scenarios.v1.json"),
    show_default=True,
    help="Frozen Pi scenario corpus used to recompute the report.",
)
@click.option(
    "--registry",
    "registry_file",
    type=click.Path(path_type=Path, dir_okay=False),
    default=Path("registry/capabilities.json"),
    show_default=True,
    help="Exact-release capability registry used to recompute the report.",
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
    trace_file: Path,
    attestation_keys: Path,
    expected_capture_binding: Path,
    trusted_authority_config: Path,
    corpus: Path,
    registry_file: Path,
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
    recomputed_report: dict[str, Any] | None = None
    recomputation_attestation: dict[str, Any] | None = None
    recomputation_error: str | None = None
    try:
        gate = _load_pi_scenario_gate()
        trace_document = gate.load_json_document(trace_file)
        corpus_document = gate.load_json_document(corpus)
        registry_document = gate.load_json_document(registry_file)
        trusted_keys = gate.load_attestation_keys(
            gate.load_json_document(attestation_keys)
        )
        capture_binding_document = gate.load_json_document(
            expected_capture_binding
        )
        evidence_trust = _load_pi_evidence_trust(
            gate,
            trusted_authority_config,
            expected_release_digest=route_report["route_identity"][
                "manifest_sha256"
            ],
            expected_registry_digest=route_report["route_identity"][
                "registry_digest"
            ],
        )
        recomputed_report = gate.score_documents(
            corpus_document,
            trace_document,
            registry_document,
            trusted_keys,
            expected_package_sha256=route_report["route_identity"][
                "package_sha256"
            ],
            expected_manifest_sha256=route_report["route_identity"][
                "manifest_sha256"
            ],
            expected_registry_digest=route_report["route_identity"][
                "registry_digest"
            ],
            evidence_trust=evidence_trust,
            expected_capture_binding=capture_binding_document,
        )
        retained_report = _load_retained_json_report(
            pi_scenario_report,
            command=command,
            label="Pi scenario acceptance",
        )
        if retained_report != recomputed_report:
            blockers.append(
                "Pi scenario report does not exactly match recomputed trace evidence"
            )
        else:
            trace_attestation = trace_document.get("attestation")
            key_id = (
                trace_attestation.get("key_id")
                if isinstance(trace_attestation, dict)
                else None
            )
            secret = trusted_keys.get(key_id)
            if type(secret) is not bytes or len(secret) < 32:
                raise ValueError(
                    "Pi trace attestation key cannot attest recomputation"
                )
            claims = _pi_recomputation_claims(
                report=recomputed_report,
                report_sha256=_sha256_file(pi_scenario_report),
                trace_file_sha256=_sha256_file(trace_file),
                capture_binding_file_sha256=_sha256_file(
                    expected_capture_binding
                ),
                expected_release_identity=route_report["route_identity"],
            )
            recomputation_attestation = (
                _create_pi_recomputation_attestation(
                    claims,
                    key_id=key_id,
                    secret=secret,
                )
            )
    except (CliFailure, OSError, ValueError) as exc:
        recomputation_error = str(exc)
        blockers.append("Pi scenario report could not be recomputed from trusted trace evidence")
    if not route_report["current_route_ready"]:
        blockers.append("current release route is not ready")
    if not pi_report["scenario_acceptance_ready"]:
        blockers.extend(pi_report["blockers"])
    data = {
        "blockers": sorted(set(blockers)),
        "attestation_keys_path": str(attestation_keys.resolve()),
        "corpus_path": str(corpus.resolve()),
        "expected_capture_binding_path": str(
            expected_capture_binding.resolve()
        ),
        "pi_scenario": pi_report,
        "pi_scenario_report_sha256": _sha256_file(pi_scenario_report),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "recomputation_error": recomputation_error,
        "recomputation_attestation": recomputation_attestation,
        "recomputed_report_matches": recomputed_report is not None
        and not any(
            blocker
            == "Pi scenario report does not exactly match recomputed trace evidence"
            for blocker in blockers
        ),
        "route": route_report,
        "scenario_acceptance_ready": not blockers,
        "trace_attestation_signed_payload_sha256": (
            recomputed_report.get("attestation_signed_payload_sha256")
            if recomputed_report is not None
            else None
        ),
        "trace_document_sha256": (
            recomputed_report.get("trace_document_sha256")
            if recomputed_report is not None
            else None
        ),
        "trace_file_sha256": (
            _sha256_file(trace_file) if trace_file.is_file() else None
        ),
        "trace_file": str(trace_file.resolve()),
        "trusted_authority_config_path": str(trusted_authority_config),
        "registry_path": str(registry_file.resolve()),
        "expected_capture_binding_sha256": (
            _sha256_file(expected_capture_binding)
            if expected_capture_binding.is_file()
            else None
        ),
        "expected_capture_binding_canonical_sha256": (
            recomputed_report.get("expected_capture_binding_sha256")
            if recomputed_report is not None
            else None
        ),
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
    "--expected-capture-binding",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help=(
        "Trusted exact Pi/Bridge/provider/model/prompt/tool/runtime binding "
        "JSON, supplied independently from the trace capture."
    ),
)
@click.option(
    "--trusted-authority-config",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help=(
        "Root-managed trusted-authority runtime configuration whose verified "
        "release route supplies receipt and approval verification keys."
    ),
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
    expected_capture_binding: Path,
    trusted_authority_config: Path,
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
        capture_binding_document = gate.load_json_document(
            expected_capture_binding
        )
        evidence_trust = _load_pi_evidence_trust(
            gate,
            trusted_authority_config,
            expected_release_digest=route_report["route_identity"][
                "manifest_sha256"
            ],
            expected_registry_digest=route_report["route_identity"][
                "registry_digest"
            ],
        )
        trusted_summaries = gate.validate_trace_document(
            trace_document,
            corpus_document,
            registry_document,
            trusted_keys,
            expected_package_sha256=route_report["route_identity"]["package_sha256"],
            expected_manifest_sha256=route_report["route_identity"][
                "manifest_sha256"
            ],
            expected_registry_digest=route_report["route_identity"][
                "registry_digest"
            ],
            evidence_trust=evidence_trust,
            expected_capture_binding=capture_binding_document,
        )
    except (OSError, ValueError) as exc:
        data = {
            "attestation_keys_path": str(attestation_keys),
            "blockers": [str(exc)],
            "corpus_path": str(corpus),
            "expected_capture_binding_path": str(expected_capture_binding),
            "production_promotion_allowed": False,
            "real_odoo_write_performed": False,
            "registry_path": str(registry_file),
            "route": route_report,
            "trace_capture_ready": False,
            "trace_file": str(trace_file),
            "trusted_authority_config_path": str(trusted_authority_config),
        }
        _success(command, data, business_succeeded=False)
        return
    traces = trace_document.get("traces", [])
    data = {
        "attestation": trace_document.get("attestation"),
        "attestation_signed_payload_sha256": trace_document.get(
            "attestation", {}
        ).get("signed_payload_sha256"),
        "attestation_keys_path": str(attestation_keys),
        "blockers": [] if route_report["current_route_ready"] else ["current release route is not ready"],
        "capture": trace_document.get("capture"),
        "corpus_path": str(corpus),
        "expected_capture_binding_path": str(expected_capture_binding),
        "expected_capture_binding_sha256": _sha256_file(
            expected_capture_binding
        ),
        "expected_capture_binding_canonical_sha256": gate.canonical_sha256(
            capture_binding_document
        ),
        "production_promotion_allowed": False,
        "real_odoo_write_performed": False,
        "registry_path": str(registry_file),
        "registry_digest": trace_document.get("registry_digest"),
        "route": route_report,
        "trace_capture_ready": route_report["current_route_ready"],
        "trace_count": len(traces) if isinstance(traces, list) else 0,
        "trace_file": str(trace_file),
        "trace_file_sha256": _sha256_file(trace_file),
        "trace_document_sha256": gate.canonical_sha256(trace_document),
        "trusted_authority_config_path": str(trusted_authority_config),
        "trusted_runtime_evidence_count": len(trusted_summaries),
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


@evidence_group.command("sandbox-prerequisite-handoff")
@click.option(
    "--goal-readiness-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.goal-readiness JSON output to convert into prerequisite decisions.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_sandbox_prerequisite_handoff(
    goal_readiness_report: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Render a read-only operator handoff for capacity and sandbox prerequisites."""

    command = "evidence.sandbox-prerequisite-handoff"
    expected_release_identity = {
        "commit": expected_commit,
        "manifest_sha256": expected_manifest_sha256,
        "package_sha256": expected_package_sha256,
        "registry_digest": expected_registry_digest,
        "release": expected_release,
    }
    _success(
        command,
        _sandbox_prerequisite_handoff_report(
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


@evidence_group.command("sandbox-prerequisite-handoff-check")
@click.option(
    "--handoff-file",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.sandbox-prerequisite-handoff JSON output to validate.",
)
@click.option("--expected-release", help="Expected routed release name.")
@click.option("--expected-commit", help="Expected full Git commit.")
@click.option("--expected-manifest-sha256", help="Expected manifest SHA-256.")
@click.option("--expected-package-sha256", help="Expected package SHA-256.")
@click.option("--expected-registry-digest", help="Expected capability registry digest.")
def evidence_sandbox_prerequisite_handoff_check(
    handoff_file: Path,
    expected_release: str | None,
    expected_commit: str | None,
    expected_manifest_sha256: str | None,
    expected_package_sha256: str | None,
    expected_registry_digest: str | None,
) -> None:
    """Validate a retained sandbox prerequisite handoff without granting authority."""

    command = "evidence.sandbox-prerequisite-handoff-check"
    expected_release_identity = {
        "commit": expected_commit,
        "manifest_sha256": expected_manifest_sha256,
        "package_sha256": expected_package_sha256,
        "registry_digest": expected_registry_digest,
        "release": expected_release,
    }
    _success(
        command,
        _sandbox_prerequisite_handoff_check_report(
            handoff_file,
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
    "--read-capabilities-readiness-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.read-capabilities-readiness JSON.",
)
@click.option(
    "--sandbox-database-candidates-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.sandbox-database-candidates JSON.",
)
@click.option(
    "--sandbox-onboarding-receipt-check",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.sandbox-onboarding-receipt-check JSON.",
)
@click.option(
    "--sandbox-provision-authorization",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained sandbox provision authorization JSON.",
)
@click.option(
    "--sandbox-provision-authorization-check",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.sandbox-provision-authorization-check JSON.",
)
@click.option(
    "--sandbox-prerequisite-handoff",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.sandbox-prerequisite-handoff JSON.",
)
@click.option(
    "--sandbox-prerequisite-handoff-check",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.sandbox-prerequisite-handoff-check JSON.",
)
@click.option(
    "--write-pipeline-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.write-pipeline-readiness JSON.",
)
@click.option(
    "--target-capacity-plan-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.target-capacity-plan JSON.",
)
@click.option(
    "--target-capacity-recheck-report",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="Retained evidence.target-capacity-recheck JSON.",
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
    read_capabilities_readiness_report: Path,
    sandbox_database_candidates_report: Path,
    sandbox_onboarding_receipt: Path,
    sandbox_onboarding_receipt_check: Path,
    sandbox_provision_authorization: Path,
    sandbox_provision_authorization_check: Path,
    sandbox_prerequisite_handoff: Path,
    sandbox_prerequisite_handoff_check: Path,
    target_capacity_plan_report: Path,
    target_capacity_recheck_report: Path,
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
    identity = _load_release_identity(command=command)
    supplied_release_identity = {
        "commit": expected_commit,
        "manifest_sha256": expected_manifest_sha256,
        "package_sha256": expected_package_sha256,
        "registry_digest": expected_registry_digest,
        "release": expected_release,
    }
    _assert_expected_release_identity_matches_executing(
        identity,
        supplied_release_identity,
        command=command,
        code="final_evidence_checker_release_mismatch",
    )
    expected_release_identity = {
        field: identity[field]
        for field in (
            "commit",
            "manifest_sha256",
            "package_sha256",
            "registry_digest",
            "release",
        )
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
    _assert_final_checker_is_routed(route_report, command=command)
    output_file = Path(os.path.abspath(output_file))
    if os.path.lexists(output_file) and not overwrite:
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
        "read_capabilities_readiness_report": read_capabilities_readiness_report,
        "sandbox_database_candidates_report": sandbox_database_candidates_report,
        "sandbox_onboarding_receipt": sandbox_onboarding_receipt,
        "sandbox_onboarding_receipt_check": sandbox_onboarding_receipt_check,
        "sandbox_provision_authorization": sandbox_provision_authorization,
        "sandbox_provision_authorization_check": sandbox_provision_authorization_check,
        "sandbox_prerequisite_handoff": sandbox_prerequisite_handoff,
        "sandbox_prerequisite_handoff_check": sandbox_prerequisite_handoff_check,
        "target_capacity_plan_report": target_capacity_plan_report,
        "target_capacity_recheck_report": target_capacity_recheck_report,
        "write_evidence_index": write_evidence_index,
        "write_pipeline_report": write_pipeline_report,
    }
    source_snapshots: dict[str, tuple[bytes, str]] = {}
    source_identities: dict[tuple[int, int, int, int, int], str] = {}
    for name in FINAL_EVIDENCE_REQUIRED_ARTIFACTS:
        try:
            _document, raw, digest, identity = _read_final_json_snapshot(
                artifact_paths[name],
                command=command,
                label=f"final evidence source artifact {name}",
                maximum=_MAX_FINAL_EVIDENCE_ARTIFACT_BYTES,
            )
        except CliFailure as exc:
            raise CliFailure(
                command=command,
                code="final_evidence_manifest_rejected",
                message="The final evidence manifest references an unavailable or unsafe artifact.",
                exit_code=5,
            ) from exc
        if identity in source_identities:
            raise CliFailure(
                command=command,
                code="final_evidence_manifest_rejected",
                message="The final evidence manifest cannot reference duplicate artifacts.",
                exit_code=5,
            )
        source_identities[identity] = name
        source_snapshots[name] = (raw, digest)
    output_parent = output_file.parent
    _prepare_final_output_parent(output_parent, command=command)
    transaction_id = uuid.uuid4().hex
    staging_root = output_parent / f".final-evidence-{transaction_id}.staging"
    final_bundle_root = output_parent / f"final-evidence-bundle-{transaction_id}"
    candidate_manifest = (
        output_parent / f".final-evidence-{transaction_id}.manifest.tmp"
    )
    retain_bundle = False
    report: dict[str, Any]
    try:
        _create_private_final_directory(staging_root)
        staging_artifact_root = staging_root / "artifacts"
        _create_private_final_directory(staging_artifact_root)
        staged_artifact_sha256: dict[str, str] = {}
        for name in FINAL_EVIDENCE_REQUIRED_ARTIFACTS:
            raw, digest = source_snapshots[name]
            _write_final_snapshot_exclusive(
                staging_artifact_root / f"{name}.json", raw
            )
            staged_artifact_sha256[name] = digest
        _fsync_final_directory(staging_artifact_root)
        _fsync_final_directory(staging_root)
        _make_final_bundle_read_only(staging_root)
        _fsync_final_directory(staging_artifact_root)
        _fsync_final_directory(staging_root)
        if os.path.lexists(final_bundle_root):
            raise OSError("final evidence bundle destination already exists")
        os.rename(staging_root, final_bundle_root)
        _fsync_final_directory(output_parent)

        final_artifact_paths = {
            name: final_bundle_root / "artifacts" / f"{name}.json"
            for name in FINAL_EVIDENCE_REQUIRED_ARTIFACTS
        }
        manifest = _final_evidence_manifest_document(
            final_artifact_paths,
            artifact_sha256=staged_artifact_sha256,
            manifest_path=candidate_manifest,
            release_identity=expected_release_identity,
        )
        _write_final_snapshot_exclusive(
            candidate_manifest, (_json(manifest) + "\n").encode("utf-8")
        )
        report = _final_evidence_manifest_report(
            candidate_manifest,
            command=command,
            expected_release_identity=expected_release_identity,
        )
        blockers = list(report["blockers"])
        if not route_report["current_route_ready"]:
            blockers.append("current release route is not ready")
        report["blockers"] = sorted(set(blockers))
        report["final_evidence_manifest_ready"] = not blockers
        report["route"] = route_report
        report["manifest_path"] = str(output_file)
        report["manifest_created"] = False
        if not blockers:
            if os.name == "posix":
                candidate_manifest.chmod(0o400)
                _fsync_final_file(candidate_manifest)
            # Once publication is attempted, an asynchronous interruption can
            # arrive after the filesystem change but before the callee records
            # that it succeeded. Conservatively retain the immutable bundle;
            # known pre-publication failures below may safely release it.
            retain_bundle = True
            try:
                _publish_final_manifest(
                    candidate_manifest,
                    output_file,
                    overwrite=overwrite,
                )
            except FileExistsError as exc:
                retain_bundle = False
                raise CliFailure(
                    command=command,
                    code="final_evidence_manifest_exists",
                    message="The final evidence manifest output already exists.",
                    exit_code=5,
                ) from exc
            except _FinalManifestPublishedError:
                raise
            report["manifest_created"] = True
    except CliFailure:
        raise
    except OSError as exc:
        raise CliFailure(
            command=command,
            code="final_evidence_manifest_rejected",
            message="The final evidence manifest could not be assembled safely.",
            exit_code=5,
        ) from exc
    finally:
        _remove_final_transaction_path(candidate_manifest, output_parent)
        _remove_final_transaction_path(staging_root, output_parent)
        if not retain_bundle:
            _remove_final_transaction_path(final_bundle_root, output_parent)
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
    identity = _load_release_identity(command=command)
    supplied_release_identity = {
        "commit": expected_commit,
        "manifest_sha256": expected_manifest_sha256,
        "package_sha256": expected_package_sha256,
        "registry_digest": expected_registry_digest,
        "release": expected_release,
    }
    _assert_expected_release_identity_matches_executing(
        identity,
        supplied_release_identity,
        command=command,
        code="final_evidence_checker_release_mismatch",
    )
    expected_release_identity = {
        field: identity[field]
        for field in (
            "commit",
            "manifest_sha256",
            "package_sha256",
            "registry_digest",
            "release",
        )
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
    _assert_final_checker_is_routed(route_report, command=command)
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
    "--read-evidence-index",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Canonical exact-release external read evidence index.",
)
@click.option(
    "--pi-scenario-report",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Retained tools/pi_scenario_gate.py report for the exact release.",
)
@click.option(
    "--pi-scenario-report-check",
    type=click.Path(path_type=Path, dir_okay=False),
    help=(
        "Retained evidence.pi-scenario-report-check output carrying the "
        "purpose-specific trusted recomputation attestation."
    ),
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
    "--target-capacity-plan-report",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Optional retained evidence.target-capacity-plan JSON report.",
)
@click.option(
    "--target-capacity-recheck-report",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Optional retained evidence.target-capacity-recheck JSON report.",
)
@click.option(
    "--sandbox-database-candidates-report",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Optional retained evidence.sandbox-database-candidates JSON catalog report.",
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
    read_evidence_index: Path | None,
    pi_scenario_report: Path | None,
    pi_scenario_report_check: Path | None,
    sandbox_onboarding_receipt: Path | None,
    write_pipeline_report: Path | None,
    write_evidence_index: Path | None,
    target_capacity_plan_report: Path | None,
    target_capacity_recheck_report: Path | None,
    sandbox_database_candidates_report: Path | None,
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
    supplied_release_identity = {
        "commit": expected_commit,
        "manifest_sha256": expected_manifest_sha256,
        "package_sha256": expected_package_sha256,
        "registry_digest": expected_registry_digest,
        "release": expected_release,
    }
    if any(
        supplied is not None and supplied != identity.get(field)
        for field, supplied in supplied_release_identity.items()
    ):
        raise CliFailure(
            command=command,
            code="goal_readiness_release_identity_mismatch",
            message="The expected release identity does not match the executing release.",
            exit_code=5,
        )
    expected_release_identity = {
        field: identity[field]
        for field in (
            "commit",
            "manifest_sha256",
            "package_sha256",
            "registry_digest",
            "release",
        )
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
    _assert_final_checker_is_routed(route_report, command=command)
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
    retained_capacity_plan = _target_capacity_plan_report_status(
        target_capacity_plan_report,
        command=command,
    )
    retained_capacity_recheck = _target_capacity_recheck_report_status(
        target_capacity_recheck_report,
        command=command,
        expected_required_free_bytes=required_free_bytes,
    )
    capabilities = _load_capabilities()
    registry_report = _registry_audit_report(capabilities)
    trusted_read_handlers = _load_read_capability_implementation(command)
    external_read_evidence = _external_read_evidence_report(
        read_evidence_index,
        expected_release_identity={
            **identity,
            "commit": expected_release_identity["commit"],
            "manifest_sha256": expected_release_identity["manifest_sha256"],
            "package_sha256": expected_release_identity["package_sha256"],
            "registry_digest": expected_release_identity["registry_digest"],
            "release": expected_release_identity["release"],
        },
        capabilities=capabilities,
    )
    read_capabilities_report = _read_capabilities_readiness_report(
        capabilities,
        trusted_read_handlers=trusted_read_handlers,
        external_evidence_report=external_read_evidence,
    )
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
    write_capability_ids = tuple(capability.id for capability in write_capabilities)
    static_write_admissible_count = sum(
        1 for report in static_write_reports if report["sandbox_drill_admissible"] is True
    )
    pi_report = _pi_scenario_acceptance_report_status(
        pi_scenario_report,
        command=command,
        expected_release_identity=expected_release_identity,
    )
    pi_recomputation = _pi_recomputation_check_status(
        pi_scenario_report_check,
        pi_scenario_status=pi_report,
        command=command,
        expected_release_identity=expected_release_identity,
    )
    pi_report["recomputation"] = pi_recomputation
    if not pi_recomputation["recomputation_ready"]:
        pi_report["blockers"] = sorted(
            set(pi_report["blockers"] + pi_recomputation["blockers"])
        )
        pi_report["scenario_acceptance_ready"] = False
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
        expected_write_capability_ids=write_capability_ids,
    )
    write_index_report = _write_evidence_index_status(
        write_evidence_index,
        command=command,
        expected_release_identity=expected_release_identity,
        expected_write_capability_ids=write_capability_ids,
        pipeline_capability_summaries=pipeline_report.pop(
            "_capability_summaries"
        ),
        pipeline_summary=pipeline_report["summary"],
    )
    retained_candidate_report = _sandbox_database_candidates_report_status(
        sandbox_database_candidates_report,
        command=command,
        expected_database_name=expected_sandbox_database_name,
    )
    observed_names = sorted(set(observed_database_name))
    retained_candidate_count = None
    if retained_candidate_report is not None and isinstance(
        retained_candidate_report.get("candidate_summary"), dict
    ):
        retained_candidate_count = retained_candidate_report["candidate_summary"].get(
            "candidate_count"
        )
    if expected_sandbox_database_name is None:
        database_blockers = ["expected sandbox database name was not supplied"]
        if retained_candidate_report is not None:
            database_blockers.extend(retained_candidate_report["blockers"])
        sandbox_database_report = {
            "blockers": sorted(set(database_blockers)),
            "candidates_report": retained_candidate_report,
            "observed_database_names_count": (
                retained_candidate_count
                if isinstance(retained_candidate_count, int)
                else len(observed_names)
            ),
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
        if retained_candidate_report is not None:
            database_blockers.extend(retained_candidate_report["blockers"])
            database_observed = (
                expected_sandbox_database_name
                in retained_candidate_report["eligible_database_names"]
            )
        else:
            database_observed = expected_sandbox_database_name in observed_names
        if not observed_names and retained_candidate_report is None:
            database_blockers.append("database catalog was not supplied")
        elif not database_observed:
            database_blockers.append("sandbox database was not observed in the PostgreSQL catalog")
        sandbox_database_report = {
            "blockers": sorted(set(database_blockers)),
            "candidates_report": retained_candidate_report,
            "observed_database_names_count": (
                retained_candidate_count
                if isinstance(retained_candidate_count, int)
                else len(observed_names)
            ),
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
    if retained_capacity_plan is not None and not retained_capacity_plan["plan_ready"]:
        blockers.extend(retained_capacity_plan["blockers"])
    if (
        retained_capacity_recheck is not None
        and not retained_capacity_recheck["recheck_ready"]
    ):
        blockers.extend(retained_capacity_recheck["blockers"])
    if not registry_report["registry_audit_ready"]:
        blockers.append("capability registry audit is not ready")
    if not read_capabilities_report["read_goal_readiness_ready"]:
        blockers.extend(read_capabilities_report["blockers"])
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
            "capacity": {
                **capacity_report,
                "retained_plan": retained_capacity_plan,
                "retained_recheck": retained_capacity_recheck,
            },
            "goal_readiness_ready": not blockers,
            "pi_scenario": pi_report,
            "production_promotion_allowed": False,
            "read_capabilities_readiness": read_capabilities_report,
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


@operation_group.command("diagnostics")
@_request_option
def operation_diagnostics(request_json: str | None) -> None:
    """Return a receipt-backed diagnostic projection without changing state."""

    _execute_write_command(
        command="operation.diagnostics",
        action="operation.diagnostics",
        request_json=request_json,
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

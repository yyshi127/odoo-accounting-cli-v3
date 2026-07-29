from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import stat
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from odoo_accounting_cli_v3 import auth
from odoo_accounting_cli_v3.receipts import create_read_receipt


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = (
    ROOT / "deployment" / "dev251" / "collect_report_read_evidence.py"
)
VERIFIER_PATH = (
    ROOT / "deployment" / "dev251" / "verify_report_read_evidence.py"
)
PLAN_PATH = ROOT / "deployment" / "dev251" / "report_read_plan.json"


def _load_script(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = _load_script("dev251_report_collector_test", COLLECTOR_PATH)
verifier = _load_script("dev251_report_verifier_test", VERIFIER_PATH)

VERSION = "0.1.0.dev251"
COMMIT = "a1234567890bcdef1234567890abcdef12345678"
RELEASE = f"{VERSION}-{COMMIT[:12]}"
PACKAGE_PAYLOAD = b"dev251 canonical package fixture\n"
ODOO_PYTHON_PAYLOAD = b"dev251 pinned odoo python fixture\n"
ODOO_BIN_PAYLOAD = b"dev251 pinned odoo bin fixture\n"
ODOO_CONFIG_PAYLOAD = b"[options]\ndb_name = odoo_test\n"
REGISTERED_READ_IDS = (
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
)
DECLARED_READ_GAPS = (
    "acct.diagnostics.operation_read.v1",
    "acct.multicompany.consolidated_read.v1",
)
CONTRACT_TESTED_UNROUTED_READ_GAPS = (
    "acct.diagnostics.operation_read.v1",
)
ADMISSIBLE_READ_IDS = tuple(
    capability_id
    for capability_id in REGISTERED_READ_IDS
    if capability_id not in DECLARED_READ_GAPS
)
READINESS_CHECK_IDS = (
    "contract_evidence_present",
    "page_total_count_contract",
    "read_policy_closed",
    "read_receipt_v2_contract",
    "strict_input_schema",
    "strict_output_schema",
    "test_execution_routed",
    "trusted_handler_supported",
    "verification_method_present",
)
REQUIRED_GOAL_EVIDENCE_KINDS = (
    "accounting_oracle",
    "live_odoo",
    "pi_e2e",
    "release_identity",
    "security_negative",
)
REGISTRY_DOCUMENT = {
    "capabilities": [
        {"id": capability_id} for capability_id in REGISTERED_READ_IDS
    ],
    "schema_version": 1,
}
REGISTRY_PAYLOAD = collector.canonical_json(REGISTRY_DOCUMENT) + b"\n"
RELEASE_PAYLOADS = {
    "bin/odoo-accounting-cli-v3": b"#!/bin/sh\nexit 0\n",
    "deployment/dev251/collect_report_read_evidence.py": (
        COLLECTOR_PATH.read_bytes()
    ),
    "deployment/dev251/report_read_plan.json": PLAN_PATH.read_bytes(),
    "deployment/dev251/verify_report_read_evidence.py": (
        VERIFIER_PATH.read_bytes()
    ),
    "registry/capabilities.json": REGISTRY_PAYLOAD,
}
UNSIGNED_RELEASE_MANIFEST = {
    "commit": COMMIT,
    "files": [
        {
            "path": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
        for name, payload in sorted(RELEASE_PAYLOADS.items())
    ],
    "schema_version": 1,
    "version": VERSION,
}
MANIFEST_SHA256 = hashlib.sha256(
    collector.canonical_json(UNSIGNED_RELEASE_MANIFEST)
).hexdigest()
PACKAGE_SHA256 = hashlib.sha256(PACKAGE_PAYLOAD).hexdigest()
REGISTRY_DIGEST = hashlib.sha256(
    collector.canonical_json(REGISTRY_DOCUMENT["capabilities"])
).hexdigest()
IDENTITY = {
    "commit": COMMIT,
    "manifest_sha256": MANIFEST_SHA256,
    "package_sha256": PACKAGE_SHA256,
    "registry_digest": REGISTRY_DIGEST,
    "release": RELEASE,
    "verified": True,
    "version": VERSION,
}


def _readiness_capability_report(capability_id: str) -> dict[str, Any]:
    admissible = capability_id in ADMISSIBLE_READ_IDS
    checks = {check: True for check in READINESS_CHECK_IDS}
    blockers: list[str] = []
    if not admissible:
        missing_checks = {
            "read_receipt_v2_contract",
            "test_execution_routed",
            "trusted_handler_supported",
        }
        if capability_id not in CONTRACT_TESTED_UNROUTED_READ_GAPS:
            missing_checks.add("contract_evidence_present")
        if capability_id == "acct.multicompany.consolidated_read.v1":
            missing_checks.add("page_total_count_contract")
        for check in missing_checks:
            checks[check] = False
        blockers = sorted(check.replace("_", " ") for check in missing_checks)
    return {
        "blockers": blockers,
        "capability": {
            "access": "read",
            "enabled_environments": [],
            "evidence_level": (
                "contract_tested"
                if admissible
                or capability_id in CONTRACT_TESTED_UNROUTED_READ_GAPS
                else "declared"
            ),
            "id": capability_id,
            "staged_environments": ["test"] if admissible else [],
        },
        "checks": checks,
        "external_read_evidence_verified": False,
        "goal_evidence_blockers": [
            "trusted external read evidence has not been independently verified"
        ],
        "goal_evidence_ready": False,
        "missing_goal_evidence_kinds": list(REQUIRED_GOAL_EVIDENCE_KINDS),
        "production_promotion_allowed": False,
        "read_completion_ready": False,
        "real_odoo_write_performed": False,
        "registry_claimed_receipt_count": 0,
        "registry_claimed_receipt_kinds": [],
        "registry_receipts_authoritative_for_goal": False,
        "trusted_handler_kind": "odoo" if admissible else None,
        "trusted_read_admissible": admissible,
    }


def _readiness_document() -> dict[str, Any]:
    return {
        "business_succeeded": False,
        "command": "evidence.read-capabilities-readiness",
        "data": {
            "admissible_count": len(ADMISSIBLE_READ_IDS),
            "admissible_ids": list(ADMISSIBLE_READ_IDS),
            "blockers": [
                "not every registered read capability is statically "
                "admissible for trusted execution",
                "trusted external read evidence is not independently verified "
                "for every registered read capability",
            ],
            "capabilities": [
                _readiness_capability_report(capability_id)
                for capability_id in REGISTERED_READ_IDS
            ],
            "completion_ready_count": 0,
            "completion_ready_ids": [],
            "external_read_evidence_verifier_ready": False,
            "goal_evidence_ready_count": 0,
            "goal_evidence_ready_ids": [],
            "goal_evidence_unready_capability_ids": list(REGISTERED_READ_IDS),
            "missing_required_read_capability_ids": [],
            "production_promotion_allowed": False,
            "read_goal_readiness_ready": False,
            "read_static_readiness_ready": False,
            "real_odoo_write_performed": False,
            "registered_read_capability_ids": list(REGISTERED_READ_IDS),
            "release_identity": IDENTITY,
            "required_goal_evidence_kinds": list(
                REQUIRED_GOAL_EVIDENCE_KINDS
            ),
            "required_read_capability_ids": list(REGISTERED_READ_IDS),
            "total_read_capabilities": len(REGISTERED_READ_IDS),
            "unready_capability_ids": list(DECLARED_READ_GAPS),
        },
        "ok": True,
    }


RELEASE_MANIFEST_PAYLOAD = collector.canonical_json(
    {
        **UNSIGNED_RELEASE_MANIFEST,
        "manifest_sha256": MANIFEST_SHA256,
    }
) + b"\n"
AUTH_SECRET = b"dev251-auth-secret-material-00001"
RECEIPT_SECRET = b"dev251-receipt-secret-material-01"
assert len(AUTH_SECRET) >= 32
assert len(RECEIPT_SECRET) >= 32


def _plan() -> tuple[dict[str, Any], bytes]:
    payload = PLAN_PATH.read_bytes()
    return json.loads(payload), payload


def _runtime(release_root: Path) -> Any:
    fixture_root = release_root.parent.parent
    runtime_root = fixture_root / "runtime"
    package = (
        fixture_root
        / "packages"
        / f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
    )
    odoo_python = runtime_root / "odoo-python"
    odoo_bin = runtime_root / "odoo-bin"
    odoo_config = runtime_root / "odoo.conf"
    return SimpleNamespace(
        auth_key_id="dev251-auth-key",
        canonical_package_path=package,
        canonical_package_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
        capability_channel="staged",
        database_name="odoo_test",
        database_uuid="19b09656-d10f-11f0-9065-00163e54a5ad",
        environment="test",
        instance_id="odoo19@43.165.173.80",
        odoo_bin=odoo_bin,
        odoo_bin_sha256=hashlib.sha256(odoo_bin.read_bytes()).hexdigest(),
        odoo_config=odoo_config,
        odoo_config_sha256=hashlib.sha256(odoo_config.read_bytes()).hexdigest(),
        odoo_python=odoo_python,
        odoo_python_sha256=hashlib.sha256(odoo_python.read_bytes()).hexdigest(),
        receipt_key_id="dev251-receipt-key",
        release_root=release_root,
    )


def _runtime_mapping(runtime: Any) -> dict[str, Any]:
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


def _json_result(value: dict[str, Any]) -> Any:
    return collector.CommandResult(
        returncode=0,
        stdout=collector.canonical_json(value) + b"\n",
        stderr=b"",
    )


def _boundary(runtime: Any) -> dict[str, Any]:
    database = {
        "backend_pid": 1234,
        "name": runtime.database_name,
        "uuid": runtime.database_uuid,
    }
    relation = {"filenode": 101, "oid": 202, "row_count": 1}
    return {
        "command": "evidence.read-boundary",
        "data": {
            "evidence": {
                "checks": {
                    "backend_pid_unchanged": True,
                    "database_name_unchanged": True,
                    "database_uuid_unchanged": True,
                    "relation_filenode_unchanged": True,
                    "relation_oid_unchanged": True,
                    "relation_row_count_unchanged": True,
                },
                "database": {"after": database, "before": database},
                "drift_probes": {
                    "hidden_commit": {
                        "canary_sha256": "1" * 64,
                        "idle_after_cleanup": True,
                        "rejected": True,
                        "result_released": False,
                    },
                    "hidden_rollback": {
                        "canary_sha256": "2" * 64,
                        "idle_after_cleanup": True,
                        "rejected": True,
                        "result_released": False,
                    },
                    "rollback_hook_reopen": {
                        "canary_sha256": "3" * 64,
                        "idle_after_cleanup": True,
                        "rejected": True,
                        "result_released": False,
                    },
                },
                "relation": {
                    "after": relation,
                    "before": relation,
                    "name": "ir_config_parameter",
                    "schema": "public",
                },
                "schema_version": (
                    "odoo-accounting-cli-v3.read-boundary-evidence.v1"
                ),
                "successful_transactions": {
                    "after": {
                        "idle_after_rollback": True,
                        "isolation": "repeatable read",
                        "marker_sha256": "5" * 64,
                        "read_only": True,
                    },
                    "before": {
                        "idle_after_rollback": True,
                        "isolation": "repeatable read",
                        "marker_sha256": "4" * 64,
                        "read_only": True,
                    },
                },
                "write_probe": {
                    "idle_after_rollback": True,
                    "rejected": True,
                    "sqlstate": "25006",
                    "statement_id": "ir-config-parameter-noop-update-v1",
                },
            },
            "release_identity": IDENTITY,
            "runtime": {
                "capability_channel": runtime.capability_channel,
                "database_name": runtime.database_name,
                "database_uuid": runtime.database_uuid,
                "environment": runtime.environment,
                "instance_id": runtime.instance_id,
            },
        },
        "ok": True,
    }


def _witness(runtime: Any, *, stream_digest: str = "7" * 64) -> dict[str, Any]:
    return {
        "all_checks_passed": True,
        "command": "witness",
        "contains_credentials": False,
        "contains_raw_rows": False,
        "database": {
            "current_database": runtime.database_name,
            "current_user": "postgres",
            "database_uuid": runtime.database_uuid,
            "postmaster_started_at": "2026-07-20T00:00:00Z",
            "server_version_num": 160014,
            "system_identifier": "7616327373742442245",
        },
        "database_writes_permitted": False,
        "endpoint": {
            "kind": "unix_socket",
            "requested_directory": "/var/run/postgresql",
            "socket_path": "/var/run/postgresql/.s.PGSQL.5432",
        },
        "fixture_gaps": [],
        "odoo_action_performed": False,
        "oracle_python": {
            "isolated": True,
            "path": str(runtime.odoo_python),
            "sha256": runtime.odoo_python_sha256,
        },
        "production_validated": False,
        "relations": [
            {
                "baseline_count": 1,
                "column_count": 1,
                "name": "ir_config_parameter",
                "oid": 54844,
                "owner": "odoo",
                "primary_key": ["id"],
                "projection_sha256": "8" * 64,
                "relkind": "r",
                "required_columns": [{"name": "id", "type": "integer"}],
                "row_count": 1,
                "row_stream_sha256": stream_digest,
                "schema_sha256": "9" * 64,
                "witness_scope": "database_uuid_only",
            }
        ],
        "schema_version": 1,
        "transaction": {
            "final_status": "IDLE",
            "isolation": "repeatable read",
            "read_only": "on",
            "rollback_completed": True,
        },
    }


def _case_name(request: dict[str, Any]) -> str:
    if request["capability_id"] == "acct.tax.report_read.v1":
        return "tax_report"
    return request["parameters"]["report_request"]["kind"]


def _period_key(mode: str, date_from: str, date_to: str) -> str:
    material = "\0".join((mode, date_from, date_to)).encode("utf-8")
    return "period-" + hashlib.sha256(material).hexdigest()


def _result_body(
    request: dict[str, Any],
    *,
    name: str,
) -> dict[str, Any]:
    family = "tax" if name == "tax_report" else "financial"
    kind = "generic_tax" if name == "tax_report" else name
    comparison_request = request["parameters"].get("report_request", {}).get(
        "comparison"
    )
    main_period = {
        "date_from": "2026-01-01",
        "date_to": "2026-06-30",
        "key": _period_key(
            "range",
            "2026-01-01",
            "2026-06-30",
        ),
        "label": "Current",
        "mode": "range",
    }
    comparison = None
    comparison_period = None
    if comparison_request is not None:
        resolved_mode = {
            "previous_period": "previous_period",
            "previous_year": "same_last_year",
        }[comparison_request["mode"]]
        comparison_dates = {
            "previous_period": ("2025-07-01", "2025-12-31"),
            "previous_year": ("2025-01-01", "2025-06-30"),
        }[comparison_request["mode"]]
        comparison_period = {
            "date_from": comparison_dates[0],
            "date_to": comparison_dates[1],
            "key": _period_key(
                "range",
                comparison_dates[0],
                comparison_dates[1],
            ),
            "label": "Comparison",
            "mode": "range",
        }
        comparison = {
            "periods": 1,
            "requested_mode": comparison_request["mode"],
            "resolved_mode": resolved_mode,
            "resolved_periods": [comparison_period],
        }
    columns = [
        {
            "auditable": True,
            "cell": {"is_blank": False, "value": "100"},
            "expression_label": "balance",
            "label": "Current",
            "measure": {"currency_id": 1, "figure_type": "monetary"},
            "period": main_period,
        }
    ]
    if comparison_period is not None:
        columns.append(
            {
                "auditable": True,
                "cell": {"is_blank": False, "value": "80"},
                "expression_label": "balance",
                "label": "Comparison",
                "measure": {
                    "currency_id": 1,
                    "figure_type": "monetary",
                },
                "period": comparison_period,
            }
        )
    line = {
        "code": "1000",
        "columns": columns,
        "level": 0,
        "line_id": "line-" + hashlib.sha256(name.encode("utf-8")).hexdigest(),
        "name": f"{name} fixture line",
        "parent": {"line_id": None, "relation_source": "none"},
        "unfoldable": False,
        "unfolded": False,
    }
    if family == "tax":
        line["source_move_line_count"] = {
            "available": True,
            "count": 1,
        }
    return {
        "currency": {
            "id": 1,
            "name": "USD",
            "rounding": "0.01",
            "symbol": "$",
        },
        "effective_filters": {
            "analytic_groupby": False,
            "consolidation": False,
            "custom_aml_filter_count": 0,
            "hide_zero_lines": False,
            "journal_ids": [1],
            "journal_scope": "all_report_eligible",
            "line_expansion_request": "none",
            "move_state": "posted",
            "multi_currency_display": False,
            "tax_unit_id": None,
            "unreconciled_only": False,
        },
        "lines": [line],
        "page": {"count": 1, "limit": 5000, "offset": 0, "total_count": 1},
        "period": {
            "comparison": comparison,
            "requested": {
                "date_from": "2026-01-01",
                "date_to": "2026-06-30",
                "mode": "range",
            },
            "resolved": {
                key: value
                for key, value in main_period.items()
                if key != "label"
            },
        },
        "report": {
            "family": family,
            "kind": kind,
            "requested": {"id": 10, "name": f"{name} requested"},
            "resolved": {"id": 10, "name": f"{name} resolved"},
        },
        "warnings": [],
    }


def _resign_response(
    request: dict[str, Any],
    response: dict[str, Any],
    runtime: Any,
) -> None:
    result = response["data"]["result"]
    previous_receipt = result["receipt"]
    result_body = {
        key: value for key, value in result.items() if key != "receipt"
    }
    context = request["context"]
    result["receipt"] = create_read_receipt(
        receipt_id=previous_receipt["id"],
        capability_id=request["capability_id"],
        parameters=request["parameters"],
        result_body=result_body,
        auth_token_id=context["auth_token_id"],
        principal=context["principal"],
        odoo_instance_id=context["odoo_instance_id"],
        database_name=context["database_name"],
        database_uuid=context["database_uuid"],
        company_id=context["company_id"],
        user_id=context["user_id"],
        registry_digest=IDENTITY["registry_digest"],
        release_digest=IDENTITY["manifest_sha256"],
        environment=context["environment"],
        capability_channel=runtime.capability_channel,
        record_count=len(result_body["lines"]),
        observed_at=datetime.fromisoformat(
            previous_receipt["observed_at"].replace("Z", "+00:00")
        ),
        key_id=runtime.receipt_key_id,
        secret=RECEIPT_SECRET,
    )


class FakeExecutor:
    def __init__(
        self,
        runtime: Any,
        *,
        fail_case: str | None = None,
        drift_witness: bool = False,
        readiness_document: dict[str, Any] | None = None,
    ) -> None:
        self.runtime = runtime
        self.fail_case = fail_case
        self.drift_witness = drift_witness
        self.readiness_document = readiness_document or _readiness_document()
        self.calls = 0
        self.boundary_calls = 0
        self.read_calls = 0
        self.witness_calls = 0

    def __call__(
        self,
        command: list[str],
        *,
        stdin: bytes | None,
        role: str,
        timeout: int,
    ) -> Any:
        self.calls += 1
        assert role in {"odoo", "postgres"}
        assert timeout > 0
        if command[1:] == ["release", "identity"]:
            return _json_result(
                {"command": "release.identity", "data": IDENTITY, "ok": True}
            )
        if command[1:] == ["evidence", "read-capabilities-readiness"]:
            return _json_result(deepcopy(self.readiness_document))
        if len(command) > 2 and command[1:3] == ["evidence", "read-boundary"]:
            self.boundary_calls += 1
            return _json_result(_boundary(self.runtime))
        if "witness" in command:
            self.witness_calls += 1
            digest = (
                "6" * 64
                if self.drift_witness and self.witness_calls == 2
                else "7" * 64
            )
            return _json_result(_witness(self.runtime, stream_digest=digest))
        if len(command) > 1 and command[1] == "read":
            self.read_calls += 1
            assert stdin is not None
            request = json.loads(stdin)
            name = _case_name(request)
            if name == self.fail_case:
                return collector.CommandResult(
                    returncode=6,
                    stdout=b"",
                    stderr=b'{"command":"read","ok":false}\n',
                )
            body = _result_body(request, name=name)
            context = request["context"]
            issued = datetime.fromisoformat(context["auth_issued_at"])
            receipt = create_read_receipt(
                receipt_id=f"receipt-{name}",
                capability_id=request["capability_id"],
                parameters=request["parameters"],
                result_body=body,
                auth_token_id=context["auth_token_id"],
                principal=context["principal"],
                odoo_instance_id=context["odoo_instance_id"],
                database_name=context["database_name"],
                database_uuid=context["database_uuid"],
                company_id=context["company_id"],
                user_id=context["user_id"],
                registry_digest=IDENTITY["registry_digest"],
                release_digest=IDENTITY["manifest_sha256"],
                environment=context["environment"],
                capability_channel=self.runtime.capability_channel,
                record_count=len(body["lines"]),
                observed_at=issued + timedelta(seconds=1),
                key_id=self.runtime.receipt_key_id,
                secret=RECEIPT_SECRET,
            )
            return _json_result(
                {
                    "command": "read",
                    "data": {
                        "capability_id": request["capability_id"],
                        "release_identity": IDENTITY,
                        "result": {**body, "receipt": receipt},
                        "runtime": {
                            "capability_channel": self.runtime.capability_channel,
                            "database_name": self.runtime.database_name,
                            "database_uuid": self.runtime.database_uuid,
                            "environment": self.runtime.environment,
                            "instance_id": self.runtime.instance_id,
                        },
                    },
                    "ok": True,
                }
            )
        raise AssertionError(f"unexpected evidence command: {command}")


def _workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Any]:
    release_root = tmp_path / "releases" / RELEASE
    release_root.mkdir(parents=True)
    for relative, payload in RELEASE_PAYLOADS.items():
        destination = release_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    (release_root / "RELEASE-MANIFEST.json").write_bytes(
        RELEASE_MANIFEST_PAYLOAD
    )
    package = (
        tmp_path
        / "packages"
        / f"odoo-accounting-cli-v3-{RELEASE}.tar.gz"
    )
    package.parent.mkdir()
    package.write_bytes(PACKAGE_PAYLOAD)
    trusted_artifact = tmp_path / "trusted-artifacts" / f"{RELEASE}.json"
    trusted_artifact.parent.mkdir()
    trusted_artifact.write_bytes(
        collector.canonical_json(
            {
                "commit": COMMIT,
                "manifest_sha256": MANIFEST_SHA256,
                "package_sha256": PACKAGE_SHA256,
                "release": RELEASE,
            }
        )
        + b"\n"
    )
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    (runtime_root / "odoo-python").write_bytes(ODOO_PYTHON_PAYLOAD)
    (runtime_root / "odoo-bin").write_bytes(ODOO_BIN_PAYLOAD)
    (runtime_root / "odoo.conf").write_bytes(ODOO_CONFIG_PAYLOAD)
    runtime = _runtime(release_root)
    evidence_parent = tmp_path / "evidence"
    evidence_parent.mkdir()
    os.chmod(evidence_parent, 0o755)
    run_parent = tmp_path / "run"
    if os.name == "nt":
        monkeypatch.setattr(collector, "_fsync_directory", lambda _path: None)
    return run_parent, evidence_parent, runtime


def _collect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    executor: FakeExecutor | None = None,
    evidence_name: str = "dev251-report-read-test",
) -> tuple[dict[str, Any], Path, Path, Any]:
    run_parent, evidence_parent, runtime = _workspace(tmp_path, monkeypatch)
    plan, payload = _plan()
    report = collector.collect_evidence(
        plan=plan,
        plan_payload=payload,
        evidence_name=evidence_name,
        expected_identity=collector.ExpectedIdentity(
            release=RELEASE,
            version=VERSION,
            commit=COMMIT,
            manifest_sha256=IDENTITY["manifest_sha256"],
            package_sha256=IDENTITY["package_sha256"],
            registry_digest=IDENTITY["registry_digest"],
        ),
        runtime=runtime,
        runtime_config_path=tmp_path / "runtime.json",
        auth_secret=AUTH_SECRET,
        receipt_secret=RECEIPT_SECRET,
        auth_api=auth,
        executor=executor or FakeExecutor(runtime),
        release_root=runtime.release_root,
        verifier_path=VERIFIER_PATH,
        run_parent=run_parent,
        evidence_parent=evidence_parent,
        now_factory=lambda: datetime(2026, 7, 29, 1, 0, tzinfo=timezone.utc),
        token_factory=iter(("a", "b", "c", "d")).__next__,
        enforce_root=False,
    )
    return report, run_parent, evidence_parent, runtime


def test_dev251_plan_is_fixed_and_disclaims_accounting_oracle() -> None:
    plan, _payload = _plan()

    assert collector.validate_plan(deepcopy(plan)) == plan
    assert verifier.validate_plan(deepcopy(plan)) == plan
    assert plan["accounting_oracle"]["available"] is False
    assert plan["production_promotion_allowed"] is False

    forged_oracle = deepcopy(plan)
    forged_oracle["accounting_oracle"]["available"] = True
    with pytest.raises(collector.CollectionError):
        collector.validate_plan(forged_oracle)
    with pytest.raises(verifier.EvidenceVerificationError):
        verifier.validate_plan(forged_oracle)

    injected_parameter = deepcopy(plan)
    injected_parameter["cases"][0]["parameters"]["report_id"] = 10
    with pytest.raises(collector.CollectionError):
        collector.validate_plan(injected_parameter)
    with pytest.raises(collector.CollectionError):
        collector.ExpectedIdentity(
            release=f"{VERSION}-wrong",
            version=VERSION,
            commit=COMMIT,
            manifest_sha256=IDENTITY["manifest_sha256"],
            package_sha256=IDENTITY["package_sha256"],
            registry_digest=IDENTITY["registry_digest"],
        )


def test_current_cli_readiness_output_matches_both_independent_contracts() -> None:
    from odoo_accounting_cli_v3.cli import (
        _load_read_capability_implementation,
        _read_capabilities_readiness_report,
    )
    from odoo_accounting_cli_v3.registry import load_registry, registry_digest

    capabilities = load_registry(ROOT / "registry" / "capabilities.json")
    identity = {
        **IDENTITY,
        "registry_digest": registry_digest(capabilities),
    }
    data = _read_capabilities_readiness_report(
        capabilities,
        trusted_read_handlers=_load_read_capability_implementation(
            "evidence.read-capabilities-readiness"
        ),
    )
    data["release_identity"] = identity
    document = {
        "business_succeeded": False,
        "command": "evidence.read-capabilities-readiness",
        "data": data,
        "ok": True,
    }

    collector._validate_targeted_readiness(
        document,
        expected_identity=identity,
    )
    verifier._validate_readiness(
        document,
        release_identity=identity,
    )
    assert data["admissible_count"] == 8
    assert data["total_read_capabilities"] == 10
    assert data["unready_capability_ids"] == list(DECLARED_READ_GAPS)


def test_runtime_validation_rejects_non_string_paths_without_type_leaks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_parent, _evidence_parent, runtime = _workspace(
        tmp_path,
        monkeypatch,
    )
    malformed = _runtime_mapping(runtime)
    malformed["release_root"] = None

    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="runtime identity",
    ):
        verifier._validate_runtime(
            malformed,
            target=verifier.FIXED_TARGET,
            release_identity=IDENTITY,
        )


def test_collects_verifies_and_atomically_publishes_frozen_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report, run_parent, evidence_parent, runtime = _collect(tmp_path, monkeypatch)
    final = evidence_parent / "dev251-report-read-test"

    assert report["evidence_path"] == str(final)
    assert report["accounting_oracle_available"] is False
    assert report["production_promotion_allowed"] is False
    assert report["status"] == "publication_confirmed"
    assert report["reconcile_required"] is False
    assert report["safe_to_rerun"] is False
    assert final.is_dir()
    assert not (evidence_parent / ".dev251-report-read-test.pending").exists()
    assert list(run_parent.iterdir()) == []
    expected_directory_mode = 0o555 if os.name == "nt" else 0o500
    expected_file_mode = 0o444 if os.name == "nt" else 0o400
    assert stat.S_IMODE(final.stat().st_mode) == expected_directory_mode
    assert (
        stat.S_IMODE((final / "BUNDLE-MANIFEST.json").stat().st_mode)
        == expected_file_mode
    )
    for path in final.rglob("*"):
        assert stat.S_IMODE(path.stat().st_mode) == (
            expected_directory_mode if path.is_dir() else expected_file_mode
        )
    plan, _payload = _plan()
    bundle_manifest = json.loads(
        (final / "BUNDLE-MANIFEST.json").read_bytes()
    )
    assert bundle_manifest["runtime_identity"] == _runtime_mapping(runtime)
    for case in plan["cases"]:
        request = json.loads(
            (
                final
                / "cases"
                / case["name"]
                / "request.json"
            ).read_bytes()
        )
        assert request["parameters"] == case["parameters"]
        assert request["context"]["company_id"] == 1
        assert request["context"]["user_id"] == 2
        assert request["context"]["database_uuid"] == runtime.database_uuid
        response = json.loads(
            (
                final
                / "cases"
                / case["name"]
                / "response.json"
            ).read_bytes()
        )
        assert response["data"]["result"]["lines"]
    checked = verifier.verify_evidence(
        final,
        expected_final_path=final,
        expected_identity=IDENTITY,
        runtime=_runtime_mapping(runtime),
        auth_secret=AUTH_SECRET,
        receipt_secret=RECEIPT_SECRET,
        enforce_root=False,
    )
    assert checked["all_checks_passed"] is True
    assert checked["accounting_correctness_verified"] is False
    assert checked["production_promotion_allowed"] is False


@pytest.mark.parametrize(
    "mutation",
    (
        "identity_drift",
        "malformed_gap_blocker",
        "non_boolean_check",
        "production_enabled",
        "report_order",
        "target_check_failed",
        "unexpected_data_field",
        "unexpected_gap",
    ),
)
def test_collector_and_independent_verifier_reject_unsafe_readiness_before_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    readiness = _readiness_document()
    data = readiness["data"]
    reports = {
        report["capability"]["id"]: report for report in data["capabilities"]
    }
    target = reports["acct.tax.report_read.v1"]
    if mutation == "identity_drift":
        data["release_identity"] = {
            **IDENTITY,
            "registry_digest": "f" * 64,
        }
    elif mutation == "malformed_gap_blocker":
        reports["acct.diagnostics.operation_read.v1"]["blockers"] = [None]
    elif mutation == "non_boolean_check":
        target["checks"]["strict_output_schema"] = 1
    elif mutation == "production_enabled":
        target["capability"]["enabled_environments"] = ["production"]
    elif mutation == "report_order":
        data["capabilities"][0], data["capabilities"][1] = (
            data["capabilities"][1],
            data["capabilities"][0],
        )
    elif mutation == "target_check_failed":
        target["checks"]["strict_output_schema"] = False
    elif mutation == "unexpected_data_field":
        data["future_unreviewed_field"] = False
    elif mutation == "unexpected_gap":
        data["unready_capability_ids"].append("acct.tax.report_read.v1")
    else:  # pragma: no cover - parametrization is fixed above
        raise AssertionError(f"unknown readiness mutation: {mutation}")

    with pytest.raises(
        collector.CollectionError,
        match="read readiness probe has unsafe semantics",
    ):
        collector._validate_targeted_readiness(
            readiness,
            expected_identity=IDENTITY,
        )
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="read readiness evidence is invalid",
    ):
        verifier._validate_readiness(
            readiness,
            release_identity=IDENTITY,
        )

    run_parent, evidence_parent, runtime = _workspace(tmp_path, monkeypatch)
    executor = FakeExecutor(runtime, readiness_document=readiness)
    plan, payload = _plan()
    with pytest.raises(
        collector.CollectionError,
        match="read readiness probe has unsafe semantics",
    ):
        collector.collect_evidence(
            plan=plan,
            plan_payload=payload,
            evidence_name=f"unsafe-readiness-{mutation}",
            expected_identity=collector.ExpectedIdentity(
                release=RELEASE,
                version=VERSION,
                commit=COMMIT,
                manifest_sha256=IDENTITY["manifest_sha256"],
                package_sha256=IDENTITY["package_sha256"],
                registry_digest=IDENTITY["registry_digest"],
            ),
            runtime=runtime,
            runtime_config_path=tmp_path / "runtime.json",
            auth_secret=AUTH_SECRET,
            receipt_secret=RECEIPT_SECRET,
            auth_api=auth,
            executor=executor,
            release_root=runtime.release_root,
            verifier_path=VERIFIER_PATH,
            run_parent=run_parent,
            evidence_parent=evidence_parent,
            now_factory=lambda: datetime(
                2026, 7, 29, 1, 0, tzinfo=timezone.utc
            ),
            token_factory=iter(("a", "b", "c", "d")).__next__,
            enforce_root=False,
        )
    assert executor.calls == 2
    assert executor.boundary_calls == 0
    assert executor.witness_calls == 0
    assert executor.read_calls == 0
    assert not (
        evidence_parent / f"unsafe-readiness-{mutation}"
    ).exists()


@pytest.mark.parametrize(
    ("fail_case", "drift_witness"),
    (("profit_and_loss", False), (None, True)),
)
def test_collection_failure_or_witness_drift_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_case: str | None,
    drift_witness: bool,
) -> None:
    run_parent, evidence_parent, runtime = _workspace(tmp_path, monkeypatch)
    plan, payload = _plan()

    with pytest.raises(collector.CollectionError):
        collector.collect_evidence(
            plan=plan,
            plan_payload=payload,
            evidence_name="failed-run",
            expected_identity=collector.ExpectedIdentity(
                release=RELEASE,
                version=VERSION,
                commit=COMMIT,
                manifest_sha256=IDENTITY["manifest_sha256"],
                package_sha256=IDENTITY["package_sha256"],
                registry_digest=IDENTITY["registry_digest"],
            ),
            runtime=runtime,
            runtime_config_path=tmp_path / "runtime.json",
            auth_secret=AUTH_SECRET,
            receipt_secret=RECEIPT_SECRET,
            auth_api=auth,
            executor=FakeExecutor(
                runtime,
                fail_case=fail_case,
                drift_witness=drift_witness,
            ),
            release_root=runtime.release_root,
            verifier_path=VERIFIER_PATH,
            run_parent=run_parent,
            evidence_parent=evidence_parent,
            now_factory=lambda: datetime(
                2026, 7, 29, 1, 0, tzinfo=timezone.utc
            ),
            token_factory=iter(("a", "b", "c", "d")).__next__,
            enforce_root=False,
        )

    assert not (evidence_parent / "failed-run").exists()
    assert not (evidence_parent / ".failed-run.pending").exists()
    assert (run_parent / "failed-run").is_dir()


def test_atomic_publish_failure_removes_pending_after_precommit_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_parent, evidence_parent, runtime = _workspace(tmp_path, monkeypatch)
    plan, payload = _plan()

    def fail_publish(_source: Path, _destination: Path) -> None:
        raise collector.CollectionError("injected atomic publish failure")

    monkeypatch.setattr(collector, "_rename_noreplace", fail_publish)
    with pytest.raises(collector.CollectionError, match="injected atomic"):
        collector.collect_evidence(
            plan=plan,
            plan_payload=payload,
            evidence_name="atomic-failure",
            expected_identity=collector.ExpectedIdentity(
                release=RELEASE,
                version=VERSION,
                commit=COMMIT,
                manifest_sha256=IDENTITY["manifest_sha256"],
                package_sha256=IDENTITY["package_sha256"],
                registry_digest=IDENTITY["registry_digest"],
            ),
            runtime=runtime,
            runtime_config_path=tmp_path / "runtime.json",
            auth_secret=AUTH_SECRET,
            receipt_secret=RECEIPT_SECRET,
            auth_api=auth,
            executor=FakeExecutor(runtime),
            release_root=runtime.release_root,
            verifier_path=VERIFIER_PATH,
            run_parent=run_parent,
            evidence_parent=evidence_parent,
            now_factory=lambda: datetime(
                2026, 7, 29, 1, 0, tzinfo=timezone.utc
            ),
            token_factory=iter(("a", "b", "c", "d")).__next__,
            enforce_root=False,
        )

    assert not (evidence_parent / "atomic-failure").exists()
    assert not (evidence_parent / ".atomic-failure.pending").exists()
    assert not (run_parent / "atomic-failure").exists()


def test_post_rename_fsync_failure_retains_final_and_reconciles_idempotently(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_parent, evidence_parent, runtime = _workspace(tmp_path, monkeypatch)
    plan, payload = _plan()
    evidence_name = "publication-unknown"
    final = evidence_parent / evidence_name
    pending = evidence_parent / f".{evidence_name}.pending"
    executor = FakeExecutor(runtime)

    def fail_after_rename(path: Path) -> None:
        if path == evidence_parent and final.is_dir() and not pending.exists():
            raise OSError("injected post-rename directory fsync failure")

    collection_arguments = {
        "plan": plan,
        "plan_payload": payload,
        "evidence_name": evidence_name,
        "expected_identity": collector.ExpectedIdentity(
            release=RELEASE,
            version=VERSION,
            commit=COMMIT,
            manifest_sha256=IDENTITY["manifest_sha256"],
            package_sha256=IDENTITY["package_sha256"],
            registry_digest=IDENTITY["registry_digest"],
        ),
        "runtime": runtime,
        "runtime_config_path": tmp_path / "runtime.json",
        "auth_secret": AUTH_SECRET,
        "receipt_secret": RECEIPT_SECRET,
        "auth_api": auth,
        "executor": executor,
        "release_root": runtime.release_root,
        "verifier_path": VERIFIER_PATH,
        "run_parent": run_parent,
        "evidence_parent": evidence_parent,
        "now_factory": lambda: datetime(
            2026, 7, 29, 1, 0, tzinfo=timezone.utc
        ),
        "token_factory": iter(("a", "b", "c", "d")).__next__,
        "enforce_root": False,
    }
    monkeypatch.setattr(collector, "_fsync_directory", fail_after_rename)
    with pytest.raises(collector.PublicationOutcomeUnknown) as raised:
        collector.collect_evidence(**collection_arguments)

    assert raised.value.evidence_path == final
    assert final.is_dir()
    assert not pending.exists()
    assert not (run_parent / evidence_name).exists()
    before = (final / "BUNDLE-MANIFEST.json").read_bytes()
    expected_directory_mode = 0o555 if os.name == "nt" else 0o500
    expected_file_mode = 0o444 if os.name == "nt" else 0o400
    assert stat.S_IMODE(final.stat().st_mode) == expected_directory_mode
    assert (
        stat.S_IMODE((final / "BUNDLE-MANIFEST.json").stat().st_mode)
        == expected_file_mode
    )
    calls_before_reconcile = executor.calls
    with pytest.raises(collector.CollectionError, match="identity already exists"):
        collector.collect_evidence(**collection_arguments)
    assert executor.calls == calls_before_reconcile
    monkeypatch.setattr(collector, "_fsync_directory", lambda _path: None)
    reconcile_arguments = {
        "plan": plan,
        "evidence_name": evidence_name,
        "expected_identity": collector.ExpectedIdentity(
            release=RELEASE,
            version=VERSION,
            commit=COMMIT,
            manifest_sha256=IDENTITY["manifest_sha256"],
            package_sha256=IDENTITY["package_sha256"],
            registry_digest=IDENTITY["registry_digest"],
        ),
        "runtime": runtime,
        "auth_secret": AUTH_SECRET,
        "receipt_secret": RECEIPT_SECRET,
        "release_root": runtime.release_root,
        "verifier_path": VERIFIER_PATH,
        "run_parent": run_parent,
        "evidence_parent": evidence_parent,
        "enforce_root": False,
    }
    first = collector.reconcile_evidence(**reconcile_arguments)
    second = collector.reconcile_evidence(**reconcile_arguments)

    assert first == second
    assert first["status"] == "publication_confirmed_after_reconcile"
    assert first["reconcile_required"] is False
    assert first["safe_to_rerun"] is False
    assert executor.calls == calls_before_reconcile
    assert (final / "BUNDLE-MANIFEST.json").read_bytes() == before


def test_main_uses_dedicated_publication_unknown_output_and_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _run_parent, evidence_parent, runtime = _workspace(tmp_path, monkeypatch)
    final = evidence_parent / "main-publication-unknown"

    class FakeRunner:
        @staticmethod
        def load_runtime_config(_path: Path) -> Any:
            return runtime

        @staticmethod
        def load_runtime_secrets(_runtime: Any) -> tuple[bytes, bytes]:
            return AUTH_SECRET, RECEIPT_SECRET

    def fail_after_rename(**_kwargs: Any) -> Any:
        raise collector.PublicationOutcomeUnknown(final)

    monkeypatch.setattr(
        collector,
        "_sealed_release_root",
        lambda: runtime.release_root,
    )
    monkeypatch.setattr(
        collector,
        "_load_release_modules",
        lambda _release_root: (auth, FakeRunner),
    )
    monkeypatch.setattr(collector, "collect_evidence", fail_after_rename)
    exit_code = collector.main(
        [
            "--evidence-name",
            "main-publication-unknown",
            "--runtime-config",
            str(tmp_path / "runtime.json"),
            "--expected-release",
            RELEASE,
            "--expected-version",
            VERSION,
            "--expected-commit",
            COMMIT,
            "--expected-manifest-sha256",
            IDENTITY["manifest_sha256"],
            "--expected-package-sha256",
            IDENTITY["package_sha256"],
            "--expected-registry-digest",
            IDENTITY["registry_digest"],
        ]
    )
    output = capsys.readouterr()

    assert exit_code == 3
    assert json.loads(output.out)["status"] == "publication_outcome_unknown"
    assert json.loads(output.out)["reconcile_required"] is True
    assert json.loads(output.out)["safe_to_rerun"] is False
    assert "run --reconcile; do not repeat collection" in output.err


def test_precommit_cleanup_failure_cannot_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_cleanup(_path: Path, _parent: Path) -> None:
        raise collector.CollectionError("injected precommit cleanup failure")

    monkeypatch.setattr(collector, "_remove_run_directory", fail_cleanup)
    with pytest.raises(collector.CollectionError, match="precommit cleanup"):
        _collect(
            tmp_path,
            monkeypatch,
            evidence_name="cleanup-failure",
        )

    evidence_parent = tmp_path / "evidence"
    assert not (evidence_parent / "cleanup-failure").exists()
    assert not (evidence_parent / ".cleanup-failure.pending").exists()
    assert (tmp_path / "run" / "cleanup-failure").is_dir()


def test_verifier_rejection_removes_pending_and_never_publishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RejectingVerifier:
        @staticmethod
        def verify_evidence(*_args: Any, **_kwargs: Any) -> None:
            raise verifier.EvidenceVerificationError("injected rejection")

    monkeypatch.setattr(
        collector,
        "_load_verifier",
        lambda _path: RejectingVerifier,
    )
    with pytest.raises(verifier.EvidenceVerificationError, match="injected"):
        _collect(
            tmp_path,
            monkeypatch,
            evidence_name="verifier-rejection",
        )

    evidence_parent = tmp_path / "evidence"
    assert not (evidence_parent / "verifier-rejection").exists()
    assert not (evidence_parent / ".verifier-rejection.pending").exists()
    assert (tmp_path / "run" / "verifier-rejection").is_dir()


def test_verifier_rejects_result_and_bundle_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _report, _run_parent, evidence_parent, runtime = _collect(
        tmp_path, monkeypatch
    )
    final = evidence_parent / "dev251-report-read-test"
    request = json.loads(
        (final / "cases" / "tax_report" / "request.json").read_bytes()
    )
    response = json.loads(
        (final / "cases" / "tax_report" / "response.json").read_bytes()
    )
    changed = deepcopy(response)
    changed["data"]["result"]["currency"]["name"] = "EUR"
    issued = datetime.fromisoformat(request["context"]["auth_issued_at"])
    expires = datetime.fromisoformat(request["context"]["auth_expires_at"])
    plan, _payload = _plan()
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="content digest",
    ):
        verifier.verify_receipt(
            request,
            changed,
            case=plan["cases"][0],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=issued,
            expires=expires,
        )

    comparison_request = json.loads(
        (final / "cases" / "balance_sheet" / "request.json").read_bytes()
    )
    comparison_response = json.loads(
        (final / "cases" / "balance_sheet" / "response.json").read_bytes()
    )
    malformed_period = deepcopy(comparison_response)
    malformed_period["data"]["result"]["period"]["comparison"][
        "resolved_periods"
    ] = [{}]
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="comparison period",
    ):
        verifier.verify_receipt(
            comparison_request,
            malformed_period,
            case=plan["cases"][1],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=datetime.fromisoformat(
                comparison_request["context"]["auth_issued_at"]
            ),
            expires=datetime.fromisoformat(
                comparison_request["context"]["auth_expires_at"]
            ),
        )

    missing_comparison_column = deepcopy(comparison_response)
    missing_comparison_column["data"]["result"]["lines"][0]["columns"].pop()
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="period coverage",
    ):
        verifier.verify_receipt(
            comparison_request,
            missing_comparison_column,
            case=plan["cases"][1],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=datetime.fromisoformat(
                comparison_request["context"]["auth_issued_at"]
            ),
            expires=datetime.fromisoformat(
                comparison_request["context"]["auth_expires_at"]
            ),
        )

    invalid_measure = deepcopy(response)
    invalid_measure["data"]["result"]["lines"][0]["columns"][0]["measure"][
        "currency_id"
    ] = 2
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="column measure",
    ):
        verifier.verify_receipt(
            request,
            invalid_measure,
            case=plan["cases"][0],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=issued,
            expires=expires,
        )

    invalid_cell = deepcopy(response)
    invalid_cell["data"]["result"]["lines"][0]["columns"][0]["cell"][
        "value"
    ] = "100.0"
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="column cell",
    ):
        verifier.verify_receipt(
            request,
            invalid_cell,
            case=plan["cases"][0],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=issued,
            expires=expires,
        )

    invalid_tax_source = deepcopy(response)
    invalid_tax_source["data"]["result"]["lines"][0][
        "source_move_line_count"
    ] = {"available": True, "count": True}
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="tax source count",
    ):
        verifier.verify_receipt(
            request,
            invalid_tax_source,
            case=plan["cases"][0],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=issued,
            expires=expires,
        )

    response_path = final / "cases" / "tax_report" / "response.json"
    os.chmod(response_path, 0o600)
    response_path.write_bytes(response_path.read_bytes() + b" ")
    os.chmod(response_path, 0o400)
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="digest mismatch",
    ):
        verifier.verify_evidence(
            final,
            expected_final_path=final,
            expected_identity=IDENTITY,
            runtime=_runtime_mapping(runtime),
            auth_secret=AUTH_SECRET,
            receipt_secret=RECEIPT_SECRET,
            enforce_root=False,
        )


def test_verifier_binds_resolved_and_comparison_period_time_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _report, _run_parent, evidence_parent, runtime = _collect(
        tmp_path, monkeypatch
    )
    final = evidence_parent / "dev251-report-read-test"
    plan, _payload = _plan()

    tax_request = json.loads(
        (final / "cases" / "tax_report" / "request.json").read_bytes()
    )
    tax_response = json.loads(
        (final / "cases" / "tax_report" / "response.json").read_bytes()
    )
    future_main = deepcopy(tax_response)
    future_period = {
        "date_from": "2027-01-01",
        "date_to": "2027-06-30",
        "key": _period_key("range", "2027-01-01", "2027-06-30"),
        "mode": "range",
    }
    future_main["data"]["result"]["period"]["resolved"] = future_period
    future_main["data"]["result"]["lines"][0]["columns"][0]["period"] = {
        **future_period,
        "label": "Future",
    }
    _resign_response(tax_request, future_main, runtime)
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="does not match the request",
    ):
        verifier.verify_receipt(
            tax_request,
            future_main,
            case=plan["cases"][0],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=datetime.fromisoformat(
                tax_request["context"]["auth_issued_at"]
            ),
            expires=datetime.fromisoformat(
                tax_request["context"]["auth_expires_at"]
            ),
        )

    profit_request = json.loads(
        (final / "cases" / "profit_and_loss" / "request.json").read_bytes()
    )
    profit_response = json.loads(
        (final / "cases" / "profit_and_loss" / "response.json").read_bytes()
    )
    future_comparison = deepcopy(profit_response)
    future_previous_year = {
        "date_from": "2027-01-01",
        "date_to": "2027-06-30",
        "key": _period_key("range", "2027-01-01", "2027-06-30"),
        "label": "Future comparison",
        "mode": "range",
    }
    future_comparison["data"]["result"]["period"]["comparison"][
        "resolved_periods"
    ] = [future_previous_year]
    future_comparison["data"]["result"]["lines"][0]["columns"][1][
        "period"
    ] = future_previous_year
    _resign_response(profit_request, future_comparison, runtime)
    with pytest.raises(
        verifier.EvidenceVerificationError,
        match="does not match requested mode",
    ):
        verifier.verify_receipt(
            profit_request,
            future_comparison,
            case=plan["cases"][2],
            receipt_secret=RECEIPT_SECRET,
            runtime=_runtime_mapping(runtime),
            release_identity=IDENTITY,
            issued=datetime.fromisoformat(
                profit_request["context"]["auth_issued_at"]
            ),
            expires=datetime.fromisoformat(
                profit_request["context"]["auth_expires_at"]
            ),
        )

    balance_request = json.loads(
        (final / "cases" / "balance_sheet" / "request.json").read_bytes()
    )
    normalized_balance = json.loads(
        (final / "cases" / "balance_sheet" / "response.json").read_bytes()
    )
    normalized_main = {
        "date_from": "2026-06-01",
        "date_to": "2026-06-30",
        "key": _period_key("range", "2026-06-01", "2026-06-30"),
        "mode": "range",
    }
    normalized_previous = {
        "date_from": "2026-05-01",
        "date_to": "2026-05-31",
        "key": _period_key("range", "2026-05-01", "2026-05-31"),
        "label": "Previous month",
        "mode": "range",
    }
    normalized_result = normalized_balance["data"]["result"]
    normalized_result["warnings"] = ["odoo:date_range_normalized"]
    normalized_result["period"]["resolved"] = normalized_main
    normalized_result["period"]["comparison"]["resolved_periods"] = [
        normalized_previous
    ]
    normalized_result["lines"][0]["columns"][0]["period"] = {
        **normalized_main,
        "label": "Current month",
    }
    normalized_result["lines"][0]["columns"][1][
        "period"
    ] = normalized_previous
    _resign_response(balance_request, normalized_balance, runtime)
    verifier.verify_receipt(
        balance_request,
        normalized_balance,
        case=plan["cases"][1],
        receipt_secret=RECEIPT_SECRET,
        runtime=_runtime_mapping(runtime),
        release_identity=IDENTITY,
        issued=datetime.fromisoformat(
            balance_request["context"]["auth_issued_at"]
        ),
        expires=datetime.fromisoformat(
            balance_request["context"]["auth_expires_at"]
        ),
    )


@pytest.mark.parametrize(
    ("target", "message"),
    (
        ("package", "canonical release package digest mismatch"),
        ("odoo_python", "runtime odoo_python digest mismatch"),
        ("odoo_bin", "runtime odoo_bin digest mismatch"),
        ("odoo_config", "runtime odoo_config digest mismatch"),
        ("release_member", "installed release member digest mismatch"),
    ),
)
def test_verifier_rejects_release_and_runtime_file_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    message: str,
) -> None:
    _report, _run_parent, evidence_parent, runtime = _collect(
        tmp_path,
        monkeypatch,
    )
    final = evidence_parent / "dev251-report-read-test"
    path = {
        "package": runtime.canonical_package_path,
        "odoo_python": runtime.odoo_python,
        "odoo_bin": runtime.odoo_bin,
        "odoo_config": runtime.odoo_config,
        "release_member": (
            runtime.release_root
            / "deployment"
            / "dev251"
            / "report_read_plan.json"
        ),
    }[target]
    path.write_bytes(path.read_bytes() + b"tampered")

    with pytest.raises(verifier.EvidenceVerificationError, match=message):
        verifier.verify_evidence(
            final,
            expected_final_path=final,
            expected_identity=IDENTITY,
            runtime=_runtime_mapping(runtime),
            auth_secret=AUTH_SECRET,
            receipt_secret=RECEIPT_SECRET,
            enforce_root=False,
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are required")
def test_collector_rejects_broad_persistent_evidence_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_parent, evidence_parent, runtime = _workspace(tmp_path, monkeypatch)
    os.chmod(evidence_parent, 0o777)
    plan, payload = _plan()
    with pytest.raises(collector.CollectionError, match="directory boundary"):
        collector.collect_evidence(
            plan=plan,
            plan_payload=payload,
            evidence_name="unsafe-parent",
            expected_identity=collector.ExpectedIdentity(
                release=RELEASE,
                version=VERSION,
                commit=COMMIT,
                manifest_sha256=IDENTITY["manifest_sha256"],
                package_sha256=IDENTITY["package_sha256"],
                registry_digest=IDENTITY["registry_digest"],
            ),
            runtime=runtime,
            runtime_config_path=tmp_path / "runtime.json",
            auth_secret=AUTH_SECRET,
            receipt_secret=RECEIPT_SECRET,
            auth_api=auth,
            executor=FakeExecutor(runtime),
            release_root=runtime.release_root,
            verifier_path=VERIFIER_PATH,
            run_parent=run_parent,
            evidence_parent=evidence_parent,
            enforce_root=False,
        )


def test_dev251_scripts_have_fixed_paths_and_standard_library_verifier() -> None:
    assert collector.RUN_PARENT == Path("/run/odoo-accounting-cli-v3-dev251")
    assert collector.EVIDENCE_PARENT == Path(
        "/var/lib/odoo-accounting-cli-v3/evidence"
    )
    assert "/root/" not in COLLECTOR_PATH.read_text("utf-8")
    assert "/root/" not in VERIFIER_PATH.read_text("utf-8")
    collector_source = COLLECTOR_PATH.read_text("utf-8")
    assert "renameat2" in collector_source
    assert "RENAME_NOREPLACE" in collector_source
    assert "deployment/dev29" not in verifier.__doc__

    tree = ast.parse(VERIFIER_PATH.read_text("utf-8"))
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert imported <= {
        "__future__",
        "argparse",
        "base64",
        "datetime",
        "decimal",
        "hashlib",
        "hmac",
        "json",
        "os",
        "pathlib",
        "re",
        "stat",
        "sys",
        "typing",
        "uuid",
    }

from __future__ import annotations

import json
import shutil
import subprocess
import sysconfig
from pathlib import Path


def _resolve_cli() -> Path:
    name = "odoo-accounting-cli-v3.exe" if sysconfig.get_platform().startswith("win") else "odoo-accounting-cli-v3"
    candidates = [Path(sysconfig.get_path("scripts")) / name]
    discovered = shutil.which("odoo-accounting-cli-v3")
    if discovered:
        candidates.append(Path(discovered))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise AssertionError("installed odoo-accounting-cli-v3 console script was not found")


def _run(*arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(_resolve_cli()), *arguments],
        input=input_text,
        capture_output=True,
        check=False,
        text=True,
    )


def test_installed_console_script_reports_version() -> None:
    result = _run("--version")

    assert result.returncode == 0
    assert result.stdout.startswith("odoo-accounting-cli-v3, version ")
    assert result.stderr == ""


def test_registry_list_is_json_and_uses_validated_registry() -> None:
    result = _run("registry", "list")

    assert result.returncode == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "registry.list"
    assert payload["data"]["count"] == len(payload["data"]["capabilities"])
    assert payload["data"]["count"] > 0
    assert len(payload["data"]["registry_digest"]) == 64
    assert [item["id"] for item in payload["data"]["capabilities"]] == sorted(
        item["id"] for item in payload["data"]["capabilities"]
    )


def test_registry_audit_reports_complete_contract_and_closed_production_gate() -> None:
    result = _run("registry", "audit")

    assert result.returncode == 0
    assert result.stderr == ""
    payload = json.loads(result.stdout)
    data = payload["data"]
    assert payload["ok"] is True
    assert payload["command"] == "registry.audit"
    assert data["registry_audit_ready"] is True
    assert data["blockers"] == []
    assert data["total_count"] == 37
    assert data["access_counts"] == {"read": 13, "write": 24}
    assert data["read_count"] == 13
    assert data["write_count"] == 24
    assert data["evidence_level_counts"] == {
        "contract_tested": 13,
        "declared": 24,
        "odoo_verified": 0,
        "production_verified": 0,
        "sandbox_verified": 0,
    }
    assert data["strict_schema"]["input_strict_count"] == data["total_count"]
    assert data["strict_schema"]["output_strict_count"] == data["total_count"]
    assert data["policy_counts"]["write_approval_required"] == data["write_count"]
    assert data["policy_counts"]["write_idempotency_required"] == data["write_count"]
    assert data["enabled_environment_counts"] == {"production": 0, "sandbox": 0, "test": 0}
    assert data["staged_environment_counts"] == {
        "production": 0,
        "sandbox": 0,
        "test": 13,
    }
    assert data["production_promotion_allowed"] is False
    assert data["real_odoo_write_performed"] is False
    assert len(data["registry_digest"]) == 64


def test_registry_get_returns_exact_capability() -> None:
    capability_id = "acct.gl.trial_balance.v1"
    result = _run("registry", "get", "--capability-id", capability_id)

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["data"]["capability"]["id"] == capability_id
    assert payload["data"]["capability"]["staged_environments"] == ["test"]
    assert payload["data"]["capability"]["enabled_environments"] == []


def test_registry_get_returns_declared_disabled_payment_cancel_contract() -> None:
    capability_id = "acct.payment.cancel.v1"
    result = _run("registry", "get", "--capability-id", capability_id)

    assert result.returncode == 0
    assert result.stderr == ""
    capability = json.loads(result.stdout)["data"]["capability"]
    assert capability["id"] == capability_id
    assert capability["risk_level"] == "critical"
    assert capability["approval"] == {
        "required": True, "policy": "payment_cancel", "ttl_seconds": 600,
    }
    assert capability["verification"] == {
        "method": (
            "read_back_exact_unreconciled_in_process_payment_cancel_graph_"
            "and_allowed_delta_v1"
        ),
    }
    assert capability["recovery"] == {
        "method": "manual_escalation_after_terminal_payment_cancel",
    }
    assert capability["evidence"] == {"level": "declared", "receipts": []}
    assert capability.get("staged_environments", []) == []
    assert capability["enabled_environments"] == []


def test_registry_get_returns_declared_disabled_reconciliation_undo_contract() -> None:
    capability_id = "acct.reconciliation.undo.v1"
    result = _run("registry", "get", "--capability-id", capability_id)

    assert result.returncode == 0
    assert result.stderr == ""
    capability = json.loads(result.stdout)["data"]["capability"]
    assert capability["id"] == capability_id
    assert capability["risk_level"] == "critical"
    assert capability["odoo_permissions"] == ["account.group_account_manager"]
    assert capability["approval"] == {
        "required": True, "policy": "reconciliation_undo",
        "ttl_seconds": 600,
    }
    assert capability["idempotency"] == {
        "required": True, "scope": "company_origin_operation",
    }
    assert capability["evidence"] == {"level": "declared", "receipts": []}
    assert capability.get("staged_environments", []) == []
    assert capability["enabled_environments"] == []


def test_registry_get_returns_refund_post_read_and_disabled_write_contracts() -> None:
    read_id = "acct.refund.post_reconcile_eligibility.v1"
    read_result = _run("registry", "get", "--capability-id", read_id)

    assert read_result.returncode == 0
    assert read_result.stderr == ""
    read = json.loads(read_result.stdout)["data"]["capability"]
    assert read["id"] == read_id
    assert read["access"] == "read"
    assert read["evidence"] == {"level": "contract_tested", "receipts": []}
    assert read["staged_environments"] == ["test"]
    assert read["enabled_environments"] == []

    write_id = "acct.refund.post_reconcile_origin.v1"
    write_result = _run("registry", "get", "--capability-id", write_id)

    assert write_result.returncode == 0
    assert write_result.stderr == ""
    write = json.loads(write_result.stdout)["data"]["capability"]
    assert write["id"] == write_id
    assert write["access"] == "write"
    assert write["risk_level"] == "critical"
    assert write["approval"] == {
        "required": True,
        "policy": "refund_post_reconcile_origin",
        "ttl_seconds": 600,
    }
    assert write["idempotency"] == {
        "required": True,
        "scope": "company_origin_move",
    }
    assert write["recovery"] == {
        "method": "manual_review_refund_post_reconcile_recovery"
    }
    assert write["evidence"] == {"level": "declared", "receipts": []}
    assert write.get("staged_environments", []) == []
    assert write["enabled_environments"] == []


def test_registry_get_unknown_id_is_structured_failure() -> None:
    result = _run("registry", "get", "--capability-id", "acct.unknown.missing.v1")

    assert result.returncode == 4
    assert result.stdout == ""
    payload = json.loads(result.stderr)
    assert payload == {
        "command": "registry.get",
        "error": {
            "code": "capability_not_found",
            "message": "The requested capability is not registered.",
            "odoo_action_performed": False,
            "retryable": False,
        },
        "ok": False,
    }


def test_operation_commands_reject_requests_outside_the_exact_contract() -> None:
    for command in (
        "prepare",
        "preview",
        "approve-execute",
        "status",
        "result",
        "verify",
        "recover",
    ):
        result = _run("operation", command, input_text='{"request_id":"req-1"}')

        assert result.returncode == 2
        assert result.stdout == ""
        payload = json.loads(result.stderr)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "invalid_request"
        assert payload["error"]["odoo_effect"] == "none"


def test_operation_rejects_invalid_json_before_dispatch() -> None:
    result = _run("operation", "prepare", "--request-json", "not-json")

    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "invalid_json"
    assert payload["error"]["odoo_effect"] == "none"


def test_operation_rejects_duplicate_json_keys() -> None:
    result = _run("operation", "prepare", "--request-json", '{"request_id":"a","request_id":"b"}')

    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "invalid_json"
    assert payload["error"]["odoo_effect"] == "none"

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


def test_registry_get_returns_exact_capability() -> None:
    capability_id = "acct.gl.trial_balance.v1"
    result = _run("registry", "get", "--capability-id", capability_id)

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["data"]["capability"]["id"] == capability_id
    assert payload["data"]["capability"]["enabled_environments"] == []


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


def test_operation_commands_fail_closed_without_claiming_success() -> None:
    for command in ("prepare", "preview", "approve-execute", "status", "verify", "recover"):
        result = _run("operation", command, input_text='{"request_id":"req-1"}')

        assert result.returncode == 3
        assert result.stdout == ""
        payload = json.loads(result.stderr)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "gateway_not_configured"
        assert payload["error"]["odoo_action_performed"] is False


def test_operation_rejects_invalid_json_before_fail_closed_gateway_error() -> None:
    result = _run("operation", "prepare", "--request-json", "not-json")

    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "invalid_json"
    assert payload["error"]["odoo_action_performed"] is False


def test_operation_rejects_duplicate_json_keys() -> None:
    result = _run("operation", "prepare", "--request-json", '{"request_id":"a","request_id":"b"}')

    assert result.returncode == 2
    payload = json.loads(result.stderr)
    assert payload["error"]["code"] == "invalid_json"
    assert payload["error"]["odoo_action_performed"] is False

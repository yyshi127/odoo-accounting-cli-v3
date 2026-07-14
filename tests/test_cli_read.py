from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from odoo_accounting_cli_v3 import __version__
from odoo_accounting_cli_v3.auth import authentication_request_digest
from odoo_accounting_cli_v3.cli import main
from odoo_accounting_cli_v3.odoo.runner import OdooRunnerError, RuntimeConfig
from odoo_accounting_cli_v3.receipts import create_read_receipt
from odoo_accounting_cli_v3.registry import load_registry, registry_digest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
MANIFEST_DIGEST = "d" * 64
AUTH_KEY_ID = "test-auth-2026-07"
RECEIPT_KEY_ID = "test-receipt-2026-07"
AUTH_SECRET = b"test-only-cli-auth-secret-32-bytes"
RECEIPT_SECRET = b"test-only-cli-receipt-secret-32b"
REGISTRY_DIGEST = registry_digest(
    load_registry(PROJECT_ROOT / "registry" / "capabilities.json")
)


def request_document() -> dict:
    now = datetime.now(timezone.utc)
    capability_id = "acct.gl.trial_balance.v1"
    parameters = {
        "company_id": 7,
        "date_from": "2026-01-01",
        "date_to": "2026-12-31",
        "opening_basis": "ledger_cumulative",
        "currency_id": 12,
        "account_id": None,
        "include_off_balance": False,
        "include_zero": False,
        "limit": 100,
        "offset": 0,
    }
    return {
        "capability_id": capability_id,
        "context": {
            "allowed_company_ids": [7],
            "audience": "odoo-accounting-cli-v3",
            "auth_expires_at": (now + timedelta(minutes=4)).isoformat(),
            "auth_issued_at": (now - timedelta(seconds=1)).isoformat(),
            "auth_key_id": AUTH_KEY_ID,
            "auth_request_digest": authentication_request_digest(
                capability_id, parameters
            ),
            "auth_signature": "a" * 64,
            "auth_signature_purpose": "auth_context_v1",
            "auth_signature_version": 1,
            "auth_token_id": "token-cli-read-1",
            "company_id": 7,
            "database_name": "odoo_test",
            "database_uuid": DATABASE_UUID,
            "environment": "test",
            "odoo_instance_id": "odoo19@tokyo2",
            "principal": "pi:user-42",
            "user_id": 42,
        },
        "parameters": parameters,
    }


def result_body() -> dict:
    summary = {
        "opening_balance": "0.00",
        "period_debit": "0.00",
        "period_credit": "0.00",
        "period_balance": "0.00",
        "closing_balance": "0.00",
        "debit_credit_difference": "0.00",
        "is_balanced": True,
    }
    return {
        "lines": [],
        "page": {"limit": 100, "offset": 0, "count": 0, "total_count": 0},
        "page_summary": dict(summary),
        "ledger_summary": dict(summary),
        "currency": {"id": 12, "name": "CNY", "symbol": "CNY", "rounding": "0.01"},
    }


def ar_request_document() -> dict:
    request = request_document()
    capability_id = "acct.ar.open_items.v1"
    parameters = {
        "company_id": 7,
        "as_of_date": "2026-03-31",
        "partner_id": 301,
        "currency_id": 2,
        "limit": 37,
        "offset": 4,
    }
    request["capability_id"] = capability_id
    request["parameters"] = parameters
    request["context"]["auth_token_id"] = "token-cli-ar-read-1"
    request["context"]["auth_request_digest"] = authentication_request_digest(
        capability_id, parameters
    )
    return request


def ar_result_body() -> dict:
    summary = {
        "item_count": 0,
        "debit_residual": "0.00",
        "credit_residual": "0.00",
        "net_residual": "0.00",
    }
    return {
        "basis": "odoo_accounting_date_current_reconciliation_graph",
        "filters": {
            "company_id": 7,
            "as_of_date": "2026-03-31",
            "partner_id": 301,
            "currency_id": 2,
        },
        "items": [],
        "page": {"limit": 37, "offset": 4, "count": 0, "total_count": 0},
        "page_summary": dict(summary),
        "ledger_summary": dict(summary),
        "currency_summaries": [],
        "company_currency": {
            "id": 12,
            "name": "CNY",
            "symbol": "CNY",
            "rounding": "0.01",
        },
    }


def ap_request_document() -> dict:
    request = ar_request_document()
    capability_id = "acct.ap.open_items.v1"
    parameters = {
        "company_id": 7,
        "as_of_date": "2026-04-30",
        "partner_id": 902,
        "currency_id": 3,
        "limit": 41,
        "offset": 6,
    }
    request["capability_id"] = capability_id
    request["parameters"] = parameters
    request["context"]["auth_token_id"] = "token-cli-ap-read-1"
    request["context"]["auth_request_digest"] = authentication_request_digest(
        capability_id, parameters
    )
    return request


def ap_result_body() -> dict:
    body = ar_result_body()
    body["filters"] = {
        "company_id": 7,
        "as_of_date": "2026-04-30",
        "partner_id": 902,
        "currency_id": 3,
    }
    body["page"] = {"limit": 41, "offset": 6, "count": 0, "total_count": 0}
    return body


def identity() -> dict:
    return {
        "commit": "a" * 40,
        "manifest_sha256": MANIFEST_DIGEST,
        "package_sha256": "b" * 64,
        "registry_digest": REGISTRY_DIGEST,
        "release": f"{__version__}-aaaaaaaaaaaa",
        "verified": True,
        "version": __version__,
    }


class CliReadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.runtime_path = root / "runtime.json"
        self.auth_secret_path = root / "auth.secret"
        self.receipt_secret_path = root / "receipt.secret"
        self.canonical_package_path = (
            PROJECT_ROOT.parent.parent
            / "packages"
            / f"odoo-accounting-cli-v3-{PROJECT_ROOT.name}.tar.gz"
        )
        self.auth_secret_path.write_bytes(AUTH_SECRET)
        self.receipt_secret_path.write_bytes(RECEIPT_SECRET)
        self.config = RuntimeConfig(
            instance_id="odoo19@tokyo2",
            environment="test",
            capability_channel="staged",
            database_name="odoo_test",
            database_uuid=DATABASE_UUID,
            odoo_python=root / "python",
            odoo_python_sha256="0" * 64,
            odoo_bin=root / "odoo-bin",
            odoo_bin_sha256="0" * 64,
            odoo_config=root / "odoo.conf",
            odoo_config_sha256="0" * 64,
            release_root=PROJECT_ROOT,
            canonical_package_path=self.canonical_package_path,
            canonical_package_sha256="b" * 64,
            auth_state_path=root / "auth.sqlite3",
            receipt_state_path=root / "receipt.sqlite3",
            auth_key_id=AUTH_KEY_ID,
            receipt_key_id=RECEIPT_KEY_ID,
            auth_secret_path=self.auth_secret_path,
            receipt_secret_path=self.receipt_secret_path,
        )

    def verified_result(self, request: dict, body: dict | None = None) -> dict:
        body = result_body() if body is None else body
        context = request["context"]
        receipt = create_read_receipt(
            receipt_id="receipt-cli-read-1",
            capability_id=request["capability_id"],
            parameters=request["parameters"],
            result_body=body,
            auth_token_id=context["auth_token_id"],
            principal=context["principal"],
            odoo_instance_id=self.config.instance_id,
            database_name=self.config.database_name,
            database_uuid=self.config.database_uuid,
            company_id=context["company_id"],
            user_id=context["user_id"],
            registry_digest=REGISTRY_DIGEST,
            release_digest=MANIFEST_DIGEST,
            environment=self.config.environment,
            capability_channel=self.config.capability_channel,
            record_count=0,
            observed_at=datetime.now(timezone.utc),
            key_id=RECEIPT_KEY_ID,
            secret=RECEIPT_SECRET,
        )
        return {**body, "receipt": receipt}

    @patch("odoo_accounting_cli_v3.cli.run_odoo_shell")
    @patch("odoo_accounting_cli_v3.cli._load_release_identity")
    @patch("odoo_accounting_cli_v3.cli.load_runtime_config")
    @patch(
        "odoo_accounting_cli_v3.cli.load_runtime_secrets",
        return_value=(AUTH_SECRET, RECEIPT_SECRET),
    )
    def test_read_transmits_complete_request_and_returns_bound_receipt(
        self, _load_secrets, load_config, load_identity, run_shell
    ) -> None:
        load_config.return_value = self.config
        load_identity.return_value = identity()
        request = request_document()
        verified = self.verified_result(request)
        run_shell.return_value = verified

        result = CliRunner().invoke(
            main,
            [
                "read",
                "--runtime-config",
                str(self.runtime_path),
                "--timeout-seconds",
                "17",
                "--request-json",
                json.dumps(request),
            ],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "read")
        self.assertEqual(payload["data"]["result"], verified)
        self.assertEqual(payload["data"]["runtime"], self.config.runtime_identity)
        load_config.assert_called_once_with(self.runtime_path)
        load_identity.assert_called_once_with(PROJECT_ROOT, command="read")
        run_shell.assert_called_once_with(
            self.config,
            request,
            release_digest=MANIFEST_DIGEST,
            timeout_seconds=17.0,
        )

    @patch("odoo_accounting_cli_v3.cli.run_odoo_shell")
    @patch("odoo_accounting_cli_v3.cli._load_release_identity")
    @patch("odoo_accounting_cli_v3.cli.load_runtime_config")
    @patch(
        "odoo_accounting_cli_v3.cli.load_runtime_secrets",
        return_value=(AUTH_SECRET, RECEIPT_SECRET),
    )
    def test_ar_read_transmits_date_company_partner_currency_and_page_unchanged(
        self, _load_secrets, load_config, load_identity, run_shell
    ) -> None:
        load_config.return_value = self.config
        load_identity.return_value = identity()
        request = ar_request_document()
        verified = self.verified_result(request, ar_result_body())
        run_shell.return_value = verified

        result = CliRunner().invoke(
            main,
            [
                "read",
                "--runtime-config",
                str(self.runtime_path),
                "--request-json",
                json.dumps(request),
            ],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.stdout)["data"]["result"], verified)
        transmitted = run_shell.call_args.args[1]
        self.assertEqual(transmitted["parameters"], request["parameters"])
        self.assertEqual(transmitted["capability_id"], "acct.ar.open_items.v1")

    @patch("odoo_accounting_cli_v3.cli.run_odoo_shell")
    @patch("odoo_accounting_cli_v3.cli._load_release_identity")
    @patch("odoo_accounting_cli_v3.cli.load_runtime_config")
    @patch(
        "odoo_accounting_cli_v3.cli.load_runtime_secrets",
        return_value=(AUTH_SECRET, RECEIPT_SECRET),
    )
    def test_ap_read_transmits_date_company_supplier_currency_and_page_unchanged(
        self, _load_secrets, load_config, load_identity, run_shell
    ) -> None:
        load_config.return_value = self.config
        load_identity.return_value = identity()
        request = ap_request_document()
        verified = self.verified_result(request, ap_result_body())
        run_shell.return_value = verified

        result = CliRunner().invoke(
            main,
            [
                "read",
                "--runtime-config",
                str(self.runtime_path),
                "--request-json",
                json.dumps(request),
            ],
        )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.stdout)["data"]["result"], verified)
        transmitted = run_shell.call_args.args[1]
        self.assertEqual(transmitted["parameters"], request["parameters"])
        self.assertEqual(transmitted["capability_id"], "acct.ap.open_items.v1")

    @patch("odoo_accounting_cli_v3.cli.run_odoo_shell")
    @patch("odoo_accounting_cli_v3.cli._load_release_identity", return_value=identity())
    @patch("odoo_accounting_cli_v3.cli.load_runtime_config")
    @patch(
        "odoo_accounting_cli_v3.cli.load_runtime_secrets",
        return_value=(AUTH_SECRET, RECEIPT_SECRET),
    )
    def test_read_never_reports_success_without_matching_receipt(
        self, _load_secrets, load_config, _load_identity, run_shell
    ) -> None:
        load_config.return_value = self.config
        request = request_document()
        verified = self.verified_result(request)
        invalid_results = (
            {"lines": []},
            {**deepcopy(verified), "receipt": {**verified["receipt"], "company_id": 8}},
            {
                **deepcopy(verified),
                "receipt": {**verified["receipt"], "release_digest": "e" * 64},
            },
        )
        for invalid in invalid_results:
            with self.subTest(invalid=invalid):
                run_shell.return_value = invalid
                result = CliRunner().invoke(
                    main,
                    [
                        "read",
                        "--runtime-config",
                        str(self.runtime_path),
                        "--request-json",
                        json.dumps(request),
                    ],
                )
                self.assertEqual(result.exit_code, 6, result.output)
                payload = json.loads(result.stderr)
                self.assertFalse(payload["ok"])
                self.assertIn(
                    payload["error"]["code"],
                    {"verified_receipt_missing", "verified_receipt_mismatch"},
                )

    @patch("odoo_accounting_cli_v3.cli.run_odoo_shell")
    @patch("odoo_accounting_cli_v3.cli._load_release_identity", return_value=identity())
    @patch("odoo_accounting_cli_v3.cli.load_runtime_config")
    def test_read_rejects_cli_and_runner_from_different_releases(
        self, load_config, _load_identity, run_shell
    ) -> None:
        load_config.return_value = RuntimeConfig(
            **{
                **self.config.__dict__,
                "release_root": Path(self.temp.name),
            }
        )
        result = CliRunner().invoke(
            main,
            [
                "read",
                "--runtime-config",
                str(self.runtime_path),
                "--request-json",
                json.dumps(request_document()),
            ],
        )
        self.assertEqual(result.exit_code, 5, result.output)
        self.assertEqual(json.loads(result.stderr)["error"]["code"], "runtime_release_mismatch")
        run_shell.assert_not_called()

    @patch("odoo_accounting_cli_v3.cli.load_runtime_config")
    def test_runtime_configuration_failure_is_structured(self, load_config) -> None:
        load_config.side_effect = OdooRunnerError("sensitive detail")
        result = CliRunner().invoke(
            main,
            [
                "read",
                "--runtime-config",
                str(self.runtime_path),
                "--request-json",
                json.dumps(request_document()),
            ],
        )
        self.assertEqual(result.exit_code, 5, result.output)
        payload = json.loads(result.stderr)
        self.assertEqual(payload["error"]["code"], "runtime_configuration_rejected")
        self.assertNotIn("sensitive detail", result.output)


if __name__ == "__main__":
    unittest.main()

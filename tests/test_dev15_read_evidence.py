from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from odoo_accounting_cli_v3.operations import canonical_json as core_canonical_json


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEV15 = PROJECT_ROOT / "deployment" / "dev15"
PLAN_BYTES = (DEV15 / "read_plan.json").read_bytes()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


signer = load_module("dev15_sign_read", DEV15 / "sign_read.py")
runner = load_module("dev15_run_read", DEV15 / "run_multicurrency_read.py")
oracle_tool = load_module("dev15_oracle", DEV15 / "multicurrency_sql_oracle.py")
verifier = load_module("dev15_verify", DEV15 / "verify_evidence.py")
runtime_setup = load_module("dev15_runtime_setup_contract", DEV15 / "runtime_setup.py")

AUTH_SECRET = b"A" * 32
RECEIPT_SECRET = b"R" * 32
TOKEN_UUID = "11111111-1111-4111-8111-111111111111"
TEST_TOOLCHAIN_MANIFEST_SHA256 = "a" * 64
STATE_UID = 1000
STATE_GID = 1000


def oracle_executable_evidence() -> dict:
    return {
        "python": {
            "path": "/usr/bin/python3.12",
            "sha256": oracle_tool.ORACLE_PYTHON_SHA256,
            "uid": 0, "gid": 0, "mode": "0755",
        },
        "psql": {
            "path": "/usr/lib/postgresql/16/bin/psql",
            "sha256": oracle_tool.PSQL_SHA256,
            "uid": 0, "gid": 0, "mode": "0755",
        },
    }


def runtime_paths_for_test(root: Path) -> dict[str, str]:
    return signer.fixed_runtime_paths(root)


def runtime(root: Path) -> dict:
    return {
        "instance_id": "odoo19@43.165.173.80",
        "environment": "test",
        "capability_channel": "staged",
        "database_name": "odoo_test",
        "database_uuid": signer.DATABASE_UUID,
        "odoo_python": signer.EXPECTED_RUNTIME_FIELDS["odoo_python"],
        "odoo_python_sha256": signer.EXPECTED_RUNTIME_FIELDS["odoo_python_sha256"],
        "odoo_bin": signer.EXPECTED_RUNTIME_FIELDS["odoo_bin"],
        "odoo_bin_sha256": signer.EXPECTED_RUNTIME_FIELDS["odoo_bin_sha256"],
        "odoo_config": signer.EXPECTED_RUNTIME_FIELDS["odoo_config"],
        "odoo_config_sha256": signer.EXPECTED_RUNTIME_FIELDS["odoo_config_sha256"],
        "release_root": str(signer.RELEASE_ROOT),
        "canonical_package_path": (
            f"/opt/odoo-accounting-cli-v3/packages/"
            f"odoo-accounting-cli-v3-{signer.RELEASE}.tar.gz"
        ),
        "canonical_package_sha256": signer.PACKAGE_SHA256,
        **runtime_paths_for_test(root),
        "auth_key_id": "test-auth-dev15-unit",
        "receipt_key_id": "test-receipt-dev15-unit",
    }


def result_body() -> dict:
    no_rate = {
        "currency_id": 6, "currency_name": "CNY", "effective_date": None,
        "source_model": "no_rate_identity", "source_scope": "no_rate_identity",
        "source_company_id": None, "source_record_id": None,
        "odoo_technical_rate": "1",
    }
    usd_source = {
        "currency_id": 1, "currency_name": "USD", "effective_date": "2025-12-15",
        "source_model": "res.currency.rate", "source_scope": "company_specific",
        "source_company_id": 9, "source_record_id": 1,
        "odoo_technical_rate": "0.15384615384615385",
    }
    return {
        "basis": "odoo_posted_aml_booked_amounts_no_cutoff_revaluation",
        "filters": {
            "company_id": 9, "as_of_date": "2026-07-13", "currency_ids": [6, 1],
            "balance_basis": "posted_ledger_cumulative", "off_balance_policy": "exclude",
        },
        "balances": [
            {
                "account_id": 3855, "account_code": "112200",
                "account_name": "Accounts Receivable", "account_type": "asset_receivable",
                "currency_id": 1, "currency_name": "USD", "company_currency_id": 6,
                "company_currency_name": "CNY", "ledger_company_balance": "1950.00",
                "ledger_transaction_amount": "300.00", "move_line_count": 8,
            },
            {
                "account_id": 3881, "account_code": "222100",
                "account_name": "Other Payables", "account_type": "liability_current",
                "currency_id": 6, "currency_name": "CNY", "company_currency_id": 6,
                "company_currency_name": "CNY", "ledger_company_balance": "253.50",
                "ledger_transaction_amount": "253.50", "move_line_count": 8,
            },
            {
                "account_id": 4002, "account_code": "600100",
                "account_name": "Revenue", "account_type": "income",
                "currency_id": 6, "currency_name": "CNY", "company_currency_id": 6,
                "company_currency_name": "CNY", "ledger_company_balance": "-2203.50",
                "ledger_transaction_amount": "-2203.50", "move_line_count": 8,
            },
        ],
        "page": {"limit": 500, "offset": 0, "count": 3, "total_count": 3},
        "page_summary": {"balance_group_count": 3, "account_count": 3, "move_line_count": 24, "ledger_company_balance": "0.00"},
        "ledger_summary": {"balance_group_count": 3, "account_count": 3, "move_line_count": 24, "ledger_company_balance": "0.00"},
        "currency_summaries": [
            {"currency_id": 6, "currency_name": "CNY", "currency_symbol": "¥", "currency_rounding": "0.01", "ledger_company_balance": "-1950.00", "ledger_transaction_amount": "-1950.00", "account_count": 2, "move_line_count": 16},
            {"currency_id": 1, "currency_name": "USD", "currency_symbol": "$", "currency_rounding": "0.01", "ledger_company_balance": "1950.00", "ledger_transaction_amount": "300.00", "account_count": 1, "move_line_count": 8},
        ],
        "rates": [
            {"currency_id": 6, "currency_name": "CNY", "company_currency_id": 6, "company_currency_name": "CNY", "as_of_date": "2026-07-13", "direction": "transaction_currency_to_company_currency", "formula": "company_technical_rate / transaction_technical_rate", "transaction_technical_source": no_rate, "company_technical_source": no_rate, "transaction_to_company_rate": "1", "company_to_transaction_rate": "1"},
            {"currency_id": 1, "currency_name": "USD", "company_currency_id": 6, "company_currency_name": "CNY", "as_of_date": "2026-07-13", "direction": "transaction_currency_to_company_currency", "formula": "company_technical_rate / transaction_technical_rate", "transaction_technical_source": usd_source, "company_technical_source": no_rate, "transaction_to_company_rate": "6.5", "company_to_transaction_rate": "0.1538461538461538461538461538"},
        ],
        "company_currency": {"id": 6, "name": "CNY", "symbol": "¥", "rounding": "0.01"},
    }


def oracle_document(parameters: dict) -> dict:
    return {
        "schema_version": 2, "capability_id": signer.CAPABILITY_ID,
        "database": {
            "current_database": "odoo_test", "current_user": "postgres",
            "database_uuid": signer.DATABASE_UUID, "server_version_num": 160014,
            "system_identifier": "7616327373742442245",
        },
        "endpoint": {
            "inet_server_addr": None, "inet_server_port": None, "kind": "unix_socket",
            "requested_directory": "/var/run/postgresql",
            "socket_path": "/var/run/postgresql/.s.PGSQL.5432",
            "unix_socket_directories": "/var/run/postgresql",
        },
        "parameters": parameters,
        "transaction": {"isolation": "repeatable read", "read_only": "on", "rollback_completed": True},
        "executables": oracle_executable_evidence(),
        "company_hierarchy": {"company_id": 9, "parent_path": "9/", "root_company_id": 9},
        "company_currency": {"id": 6, "name": "CNY", "symbol": "¥", "rounding": "0.010000"},
        "currency_catalog": [
            {"id": 6, "name": "CNY", "symbol": "¥", "rounding": "0.010000"},
            {"id": 1, "name": "USD", "symbol": "$", "rounding": "0.010000"},
        ],
        "balances": [
            {
                "account_id": 3855, "account_code": "112200", "account_type": "asset_receivable",
                "currency_id": 1, "currency_name": "USD", "ledger_company_balance": "1950",
                "ledger_transaction_amount": "300", "move_line_count": 8,
            },
            {
                "account_id": 3881, "account_code": "222100", "account_type": "liability_current",
                "currency_id": 6, "currency_name": "CNY", "ledger_company_balance": "253.50",
                "ledger_transaction_amount": "253.50", "move_line_count": 8,
            },
            {
                "account_id": 4002, "account_code": "600100", "account_type": "income",
                "currency_id": 6, "currency_name": "CNY", "ledger_company_balance": "-2203.50",
                "ledger_transaction_amount": "-2203.50", "move_line_count": 8,
            },
        ],
        "rates": [
            {"currency_id": 6, "company_currency_id": 6, "transaction_source": {"effective_date": None, "source_company_id": None, "source_record_id": None, "source_scope": "no_rate_identity", "technical_rate": "1"}, "company_source": {"effective_date": None, "source_company_id": None, "source_record_id": None, "source_scope": "no_rate_identity", "technical_rate": "1"}, "transaction_to_company_rate": "1", "company_to_transaction_rate": "1"},
            {"currency_id": 1, "company_currency_id": 6, "transaction_source": {"effective_date": "2025-12-15", "source_company_id": 9, "source_record_id": 1, "source_scope": "company_specific", "technical_rate": "0.15384615384615385"}, "company_source": {"effective_date": None, "source_company_id": None, "source_record_id": None, "source_scope": "no_rate_identity", "technical_rate": "1"}, "transaction_to_company_rate": "6.500", "company_to_transaction_rate": "0.1538461538461538461538461538"},
        ],
    }


def psql_output(parameters: dict) -> bytes:
    document = oracle_document(parameters)
    categories = [
        (
            "identity",
            {
                "database": document["database"],
                "endpoint": document["endpoint"],
                "transaction": {"isolation": "repeatable read", "read_only": "on"},
            },
        ),
        (
            "company",
            {
                "company_currency": document["company_currency"],
                "company_hierarchy": document["company_hierarchy"],
            },
        ),
        ("currencies", document["currency_catalog"]),
        ("balances", document["balances"]),
        ("rates", document["rates"]),
    ]
    lines = [
        f"{category}\t{oracle_tool.canonical_json(value)}"
        for category, value in categories
    ]
    lines.append(f"rollback\t{oracle_tool.ROLLBACK_SENTINEL}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def system_document(plan: dict) -> dict:
    baseline = plan["system_baseline"]
    trees = []
    for item in baseline["v2_components"]:
        trees.append({
            "component": item["component"], "root": item["root"],
            "algorithm": "canonical-json(component,path,sha256,size)-sha256-v1",
            "count": item["count"],
            "paths": [f"file-{index:04d}" for index in range(item["count"])],
            "digest": item["digest"],
        })
    properties = {
        "Id": "", "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
        "MainPID": "123", "InvocationID": "fixture", "ExecMainStartTimestamp": "fixture",
        "ExecMainStartTimestampMonotonic": "1", "FragmentPath": "/etc/systemd/system/fixture",
        "ControlGroup": "/fixture", "User": "", "Group": "",
    }
    analyzed_paths = ["/etc/systemd/system", "/usr/lib/systemd/system"]
    supplemental_paths = sorted(set(runner.SYSTEMD_SUPPLEMENTAL_PATHS))
    requested_paths = sorted(set(analyzed_paths + supplemental_paths))
    present_aliases = {
        "/etc/systemd/system", "/lib/systemd/system",
        "/usr/lib/systemd/system",
    }
    residue = {
        "prefix": runner.V3_UNIT_PREFIX,
        "loaded_units": [], "unit_files": [],
        "systemd_analyze_unit_paths": analyzed_paths,
        "supplemental_paths": supplemental_paths,
        "requested_paths": requested_paths,
        "absent_roots": sorted(set(requested_paths) - present_aliases),
        "roots": [
            {
                "canonical_path": "/etc/systemd/system",
                "aliases": ["/etc/systemd/system"],
                "device": 7, "inode": 201,
            },
            {
                "canonical_path": "/usr/lib/systemd/system",
                "aliases": ["/lib/systemd/system", "/usr/lib/systemd/system"],
                "device": 7, "inode": 202,
            },
        ],
        "filesystem_residue": [],
    }
    return {
        "schema_version": 1,
        "v2": {
            "trees": trees,
            "combined_algorithm": "canonical-json(component,path,sha256,size)-sha256-v1",
            "combined_count": baseline["v2_combined_count"],
            "combined_digest": baseline["v2_combined_digest"],
            "expected_combined_digest": baseline["v2_combined_digest"],
            "historical_digest": baseline["historical_v2_digest"],
        },
        "pi_bridge_control": {
            "algorithm": "canonical-json(component,path,sha256,size)-sha256-v1",
            "count": 5, "digest": baseline["pi_bridge_control_digest"],
            "entries": baseline["pi_bridge_control_entries"],
            "roots": baseline["pi_bridge_control_roots"],
        },
        "services": [
            {"unit": unit, "properties": {**properties, "Id": unit}}
            for unit in baseline["services"]
        ],
        "v3": {
            "current": {"path": "/opt/odoo-accounting-cli-v3/current", "absent": True},
            "unit_files": [
                {
                    "path": path, "file_absent": True, "unit": Path(path).name,
                    "properties": {
                        "Id": Path(path).name, "Names": Path(path).name,
                        "LoadState": "not-found", "ActiveState": "inactive",
                        "SubState": "dead", "FragmentPath": "", "SourcePath": "",
                        "UnitFileState": "", "UnitFilePreset": "",
                    },
                }
                for path in baseline["v3_unit_files"]
            ],
            "residue": residue,
        },
    }


class Dev15ReadEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = json.loads(PLAN_BYTES)
        self.runtime = runtime(self.root)

    def signed_request(self) -> dict:
        return signer.build_signed_request(
            self.plan, self.runtime, AUTH_SECRET,
            now=datetime(2026, 7, 17, 1, 2, 3, tzinfo=timezone.utc),
            token_factory=lambda: TOKEN_UUID,
            committed_plan=self.plan, expected_paths=runtime_paths_for_test(self.root),
        )

    def build_fixture(self, name: str = "evidence") -> Path:
        evidence = self.root / name
        evidence.mkdir(mode=0o700)
        request = self.signed_request()
        body = result_body()
        receipt = {
            "id": "receipt-dev15-fixture", "odoo_instance_id": "odoo19@43.165.173.80",
            "database_name": "odoo_test", "database_uuid": signer.DATABASE_UUID,
            "company_id": 9, "environment": "test", "user_id": 2,
            "capability_id": signer.CAPABILITY_ID, "capability_channel": "staged",
            "request_digest": verifier.read_request_digest(request, {}),
            "result_digest": hashlib.sha256(verifier.canonical_json(body)).hexdigest(),
            "registry_digest": signer.REGISTRY_DIGEST, "release_digest": signer.MANIFEST_SHA256,
            "record_count": 3, "observed_at": "2026-07-17T01:02:04Z",
            "signature_version": 2, "signature_purpose": "read_receipt_v2",
            "signature_key_id": self.runtime["receipt_key_id"],
        }
        receipt["signature"] = hmac.new(
            RECEIPT_SECRET, verifier.canonical_json(receipt), hashlib.sha256
        ).hexdigest()
        result = {**body, "receipt": receipt}
        response = {
            "ok": True, "command": "read", "data": {
                "capability_id": signer.CAPABILITY_ID,
                "release_identity": {
                    "commit": self.plan["application"]["commit"],
                    "manifest_sha256": signer.MANIFEST_SHA256,
                    "package_sha256": signer.PACKAGE_SHA256,
                    "registry_digest": signer.REGISTRY_DIGEST,
                    "release": signer.RELEASE, "verified": True, "version": "0.1.0.dev15",
                },
                "runtime": {
                    "instance_id": "odoo19@43.165.173.80", "environment": "test",
                    "capability_channel": "staged", "database_name": "odoo_test",
                    "database_uuid": signer.DATABASE_UUID,
                },
                "result": result,
            },
        }
        audit_payload = {
            "auth_token_id": request["context"]["auth_token_id"],
            "capability_id": signer.CAPABILITY_ID, "capability_channel": "staged",
            "company_id": 9, "environment": "test", "database_name": "odoo_test",
            "database_uuid": signer.DATABASE_UUID, "odoo_instance_id": "odoo19@43.165.173.80",
            "principal": "pi:test-user-2", "receipt": receipt,
            "receipt_id": receipt["id"], "registry_digest": signer.REGISTRY_DIGEST,
            "release_digest": signer.MANIFEST_SHA256,
            "request_digest": receipt["request_digest"], "result_digest": receipt["result_digest"],
            "user_id": 2,
        }
        event = {
            "sequence": 1, "event_id": f"read:{receipt['id']}",
            "event_type": "read.verified", "operation_id": None,
            "occurred_at": receipt["observed_at"],
            "payload_json": verifier.canonical_json(audit_payload).decode(),
            "previous_hash": verifier.GENESIS_HASH,
        }
        event["event_hash"] = verifier.audit_hash(event)
        auth_parent = {
            "path": str(Path(self.runtime["auth_state_path"]).parent),
            "exists": True, "kind": "directory", "mode": "0700",
            "uid": STATE_UID, "gid": STATE_GID, "device": 7, "inode": 101,
        }
        receipt_parent = {
            "path": str(Path(self.runtime["receipt_state_path"]).parent),
            "exists": True, "kind": "directory", "mode": "0700",
            "uid": STATE_UID, "gid": STATE_GID, "device": 7, "inode": 102,
        }
        auth_database = {
            "path": self.runtime["auth_state_path"], "kind": "regular_file",
            "mode": "0600", "uid": STATE_UID, "gid": STATE_GID,
            "device": 7, "inode": 301, "links": 1, "size": 4096,
            "mtime_ns": 1000, "ctime_ns": 1000,
        }
        receipt_database = {
            "path": self.runtime["receipt_state_path"], "kind": "regular_file",
            "mode": "0600", "uid": STATE_UID, "gid": STATE_GID,
            "device": 7, "inode": 302, "links": 1, "size": 4096,
            "mtime_ns": 1000, "ctime_ns": 1000,
        }
        state_pre = {
            "auth_state_path": self.runtime["auth_state_path"],
            "receipt_state_path": self.runtime["receipt_state_path"],
            "auth": {"exists": True, "parent": auth_parent, "database": auth_database, "queries": {"count": [{"value": 0}], "token": []}},
            "receipt": {"exists": True, "parent": receipt_parent, "database": receipt_database, "queries": {"receipt_count": [{"value": 0}], "audit_count": [{"value": 0}], "audit_head": []}},
        }
        state_post = {
            "auth_state_path": self.runtime["auth_state_path"],
            "receipt_state_path": self.runtime["receipt_state_path"],
            "auth": {"exists": True, "parent": auth_parent, "database": auth_database, "queries": {
                "count": [{"value": 1}],
                "token": [{"token_id": request["context"]["auth_token_id"], "request_digest": verifier.signed_request_replay_digest(request), "expires_at": request["context"]["auth_expires_at"], "consumed_at": "2026-07-17T01:02:03.500000+00:00"}],
            }},
            "receipt": {"exists": True, "parent": receipt_parent, "database": receipt_database, "queries": {
                "receipt_count": [{"value": 1}], "audit_count": [{"value": 1}],
                "receipt": [{"receipt_id": receipt["id"], "request_digest": receipt["request_digest"], "observed_at": receipt["observed_at"], "consumed_at": "2026-07-17T01:02:04+00:00"}],
                "audit_event": [event], "audit_head": [{"sequence": 1, "event_hash": event["event_hash"]}],
            }},
        }
        system = system_document(self.plan)
        documents = {
            "read-plan.json": PLAN_BYTES, "request.json": verifier.canonical_json(request) + b"\n",
            "response.json": verifier.canonical_json(response) + b"\n",
            "receipt.json": verifier.canonical_json(receipt) + b"\n",
            "state-pre.json": verifier.canonical_json(state_pre) + b"\n",
            "state-post.json": verifier.canonical_json(state_post) + b"\n",
            "system-pre.json": verifier.canonical_json(system) + b"\n",
            "system-post.json": verifier.canonical_json(system) + b"\n",
            "oracle.json": verifier.canonical_json(oracle_document(request["parameters"])) + b"\n",
            "exit": b"0\n", "stderr": b"", "signer.exit": b"0\n", "signer.stderr": b"",
            "oracle.exit": b"0\n", "oracle.stderr": b"",
        }
        for name, payload in documents.items():
            (evidence / name).write_bytes(payload)
        runner.freeze_bundle(
            evidence, request=request, receipt=receipt,
            toolchain_manifest_sha256=TEST_TOOLCHAIN_MANIFEST_SHA256,
        )
        return evidence

    def refreeze(self, evidence: Path) -> None:
        os.chmod(evidence, 0o700)
        manifest = evidence / runner.BUNDLE_MANIFEST
        os.chmod(manifest, 0o600)
        manifest.unlink()
        for path in evidence.iterdir():
            os.chmod(path, 0o600)
        request = json.loads((evidence / "request.json").read_bytes())
        receipt = json.loads((evidence / "receipt.json").read_bytes())
        runner.freeze_bundle(
            evidence, request=request, receipt=receipt,
            toolchain_manifest_sha256=TEST_TOOLCHAIN_MANIFEST_SHA256,
        )

    def verify(self, evidence: Path) -> dict:
        return verifier.verify_bundle(
            evidence, self.runtime, auth_secret=AUTH_SECRET,
            receipt_secret=RECEIPT_SECRET, committed_plan_bytes=PLAN_BYTES,
            expected_paths=runtime_paths_for_test(self.root), enforce_root=False,
            expected_toolchain_manifest_sha256=TEST_TOOLCHAIN_MANIFEST_SHA256,
            expected_state_uid=STATE_UID, expected_state_gid=STATE_GID,
        )

    def test_raw_plan_hash_is_pinned_in_all_three_boundaries(self) -> None:
        digest = hashlib.sha256(PLAN_BYTES).hexdigest()
        self.assertEqual(digest, signer.READ_PLAN_SHA256)
        self.assertEqual(digest, runner.READ_PLAN_SHA256)
        self.assertEqual(digest, verifier.READ_PLAN_SHA256)

    def test_signer_exact_context_short_ttl_and_unique_uuid(self) -> None:
        first = self.signed_request()
        second = signer.build_signed_request(
            self.plan, self.runtime, AUTH_SECRET,
            now=datetime(2026, 7, 17, 1, 2, 3, tzinfo=timezone.utc),
            token_factory=lambda: "22222222-2222-4222-8222-222222222222",
            committed_plan=self.plan, expected_paths=runtime_paths_for_test(self.root),
        )
        self.assertEqual(set(first["context"]), signer.AUTH_CONTEXT_FIELDS)
        self.assertNotEqual(first["context"]["auth_token_id"], second["context"]["auth_token_id"])
        issued = datetime.fromisoformat(first["context"]["auth_issued_at"])
        expires = datetime.fromisoformat(first["context"]["auth_expires_at"])
        self.assertEqual((expires - issued).total_seconds(), 240)

    def test_signer_rejects_plan_date_golden_path_and_key_drift(self) -> None:
        mutations = (
            lambda plan, rt: plan["parameters"].__setitem__("as_of_date", "2026-07-14"),
            lambda plan, rt: plan["expected"]["balances"][0].__setitem__("move_line_count", 9),
            lambda plan, rt: rt.__setitem__("auth_state_path", str(self.root / "shared.sqlite3")),
            lambda plan, rt: rt.__setitem__("auth_key_id", "wrong-prefix"),
        )
        for mutation in mutations:
            plan, rt = deepcopy(self.plan), deepcopy(self.runtime)
            mutation(plan, rt)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                signer.build_signed_request(
                    plan, rt, AUTH_SECRET, token_factory=lambda: TOKEN_UUID,
                    committed_plan=self.plan, expected_paths=runtime_paths_for_test(self.root),
                )

    def test_runtime_paths_match_isolated_candidate_layout(self) -> None:
        layout = runtime_setup.build_layout(Path("/"))
        expected_suffixes = {
            "auth_state_path": "read-state/auth/state.sqlite3",
            "receipt_state_path": "read-state/receipt/state.sqlite3",
            "auth_secret_path": "auth.hmac", "receipt_secret_path": "receipt.hmac",
        }
        production = signer.fixed_runtime_paths()
        for key, suffix in expected_suffixes.items():
            self.assertTrue(production[key].replace("\\", "/").endswith(suffix))
        self.assertTrue(str(layout.config).replace("\\", "/").endswith("runtime-test-dev15-c4616386f921.json"))

    def test_full_frozen_fixture_verifies_all_layers(self) -> None:
        report = self.verify(self.build_fixture())
        self.assertTrue(report["all_checks_passed"])
        self.assertTrue(report["postgresql_identity_and_read_only_oracle_verified"])
        self.assertEqual(report["move_line_count"], 24)
        self.assertEqual(report["record_count"], 3)
        self.assertEqual(report["toolchain_version"], verifier.TOOLCHAIN_VERSION)
        self.assertEqual(
            report["toolchain_manifest_sha256"], TEST_TOOLCHAIN_MANIFEST_SHA256,
        )
        self.assertFalse(report["production_promotion_allowed"])

    def test_bundle_manifest_rejects_tamper_and_extra_file(self) -> None:
        evidence = self.build_fixture()
        response = evidence / "response.json"
        os.chmod(response, 0o600)
        with response.open("ab") as stream:
            stream.write(b" ")
        os.chmod(response, 0o400)
        with self.assertRaisesRegex(ValueError, "hash/size"):
            self.verify(evidence)
        evidence = self.build_fixture("evidence-extra")
        os.chmod(evidence, 0o700)
        (evidence / "extra").write_bytes(b"x")
        os.chmod(evidence, 0o500)
        with self.assertRaisesRegex(ValueError, "file set"):
            self.verify(evidence)

    def test_zero_exit_with_semantic_amount_tamper_is_never_success(self) -> None:
        evidence = self.build_fixture()
        path = evidence / "response.json"
        os.chmod(path, 0o600)
        response = json.loads(path.read_bytes())
        response["data"]["result"]["balances"][0]["ledger_company_balance"] = "9999.00"
        path.write_bytes(verifier.canonical_json(response) + b"\n")
        self.refreeze(evidence)
        with self.assertRaisesRegex(ValueError, "result digest"):
            self.verify(evidence)

    def test_strict_json_duplicate_key_rejected_even_with_fresh_manifest(self) -> None:
        evidence = self.build_fixture()
        path = evidence / "response.json"
        os.chmod(path, 0o600)
        path.write_bytes(b'{"ok":true,"ok":true}\n')
        self.refreeze(evidence)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.verify(evidence)

    def test_replay_state_must_store_full_signed_request_digest(self) -> None:
        evidence = self.build_fixture()
        state_path = evidence / "state-post.json"
        os.chmod(state_path, 0o600)
        state = json.loads(state_path.read_bytes())
        request = json.loads((evidence / "request.json").read_bytes())
        state["auth"]["queries"]["token"][0]["request_digest"] = request["context"]["auth_request_digest"]
        state_path.write_bytes(verifier.canonical_json(state) + b"\n")
        self.refreeze(evidence)
        with self.assertRaisesRegex(ValueError, "full signed-request digest"):
            self.verify(evidence)
        self.assertEqual(
            verifier.signed_request_replay_digest(request),
            hashlib.sha256(core_canonical_json(request)).hexdigest(),
        )

    def test_pristine_first_run_accepts_each_state_store_independently_absent(self) -> None:
        for absent_stores in (("auth",), ("receipt",), ("auth", "receipt")):
            evidence = self.build_fixture("first-run-" + "-".join(absent_stores))
            path = evidence / "state-pre.json"
            os.chmod(path, 0o600)
            state = json.loads(path.read_bytes())
            for store_name in absent_stores:
                parent = state[store_name]["parent"]
                state[store_name] = {
                    "exists": False, "parent": parent, "database": None,
                    "queries": {},
                }
            path.write_bytes(verifier.canonical_json(state) + b"\n")
            self.refreeze(evidence)
            with self.subTest(absent_stores=absent_stores):
                self.assertTrue(self.verify(evidence)["state_and_audit_chain_verified"])

    def test_state_parent_directory_replacement_is_rejected(self) -> None:
        evidence = self.build_fixture()
        path = evidence / "state-post.json"
        os.chmod(path, 0o600)
        state = json.loads(path.read_bytes())
        state["auth"]["parent"]["inode"] += 1
        path.write_bytes(verifier.canonical_json(state) + b"\n")
        self.refreeze(evidence)
        with self.assertRaisesRegex(ValueError, "parent identity changed"):
            self.verify(evidence)

    def test_state_database_file_replacement_is_rejected(self) -> None:
        evidence = self.build_fixture()
        path = evidence / "state-post.json"
        os.chmod(path, 0o600)
        state = json.loads(path.read_bytes())
        state["auth"]["database"]["inode"] += 1
        path.write_bytes(verifier.canonical_json(state) + b"\n")
        self.refreeze(evidence)
        with self.assertRaisesRegex(ValueError, "database identity changed"):
            self.verify(evidence)

    def test_state_database_schema_rejects_boolean_integer_confusion(self) -> None:
        exists_evidence = self.build_fixture("state-exists-type")
        pre_path = exists_evidence / "state-pre.json"
        os.chmod(pre_path, 0o600)
        state_pre = json.loads(pre_path.read_bytes())
        state_pre["auth"].update(
            {"exists": 0, "database": None, "queries": {}}
        )
        pre_path.write_bytes(verifier.canonical_json(state_pre) + b"\n")
        self.refreeze(exists_evidence)
        with self.assertRaisesRegex(ValueError, "state fields"):
            self.verify(exists_evidence)

        links_evidence = self.build_fixture("state-links-type")
        for name in ("state-pre.json", "state-post.json"):
            path = links_evidence / name
            os.chmod(path, 0o600)
            state = json.loads(path.read_bytes())
            state["auth"]["database"]["links"] = True
            path.write_bytes(verifier.canonical_json(state) + b"\n")
        self.refreeze(links_evidence)
        with self.assertRaisesRegex(ValueError, "database identity"):
            self.verify(links_evidence)

    def test_runner_state_snapshot_uses_real_sqlite_absent_one_two_and_inode(self) -> None:
        auth_path = Path(self.runtime["auth_state_path"])
        receipt_path = Path(self.runtime["receipt_state_path"])
        auth_path.parent.mkdir(parents=True)
        receipt_path.parent.mkdir(parents=True)
        os.chmod(auth_path.parent, 0o700)
        os.chmod(receipt_path.parent, 0o700)

        pristine = runner.state_snapshot(
            self.runtime, token_id="token-1", receipt_id=None,
        )
        self.assertFalse(pristine["auth"]["exists"])
        self.assertFalse(pristine["receipt"]["exists"])
        self.assertIsNone(pristine["auth"]["database"])
        self.assertIsNone(pristine["receipt"]["database"])
        if os.name == "posix":
            self.assertEqual(pristine["auth"]["parent"]["mode"], "0700")
            self.assertEqual(pristine["receipt"]["parent"]["mode"], "0700")

        with closing(sqlite3.connect(auth_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0], "wal")
            connection.execute(
                "CREATE TABLE consumed_auth_tokens ("
                "token_id TEXT, request_digest TEXT, expires_at TEXT, consumed_at TEXT)"
            )
            connection.execute(
                "INSERT INTO consumed_auth_tokens VALUES (?, ?, ?, ?)",
                ("token-1", "a" * 64, "2026-07-17T01:06:03+00:00", "2026-07-17T01:02:03+00:00"),
            )
            connection.commit()
        with closing(sqlite3.connect(receipt_path)) as connection:
            self.assertEqual(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0], "wal")
            connection.execute(
                "CREATE TABLE consumed_receipts ("
                "receipt_id TEXT, request_digest TEXT, observed_at TEXT, consumed_at TEXT)"
            )
            connection.execute(
                "CREATE TABLE audit_events ("
                "sequence INTEGER, event_id TEXT, event_type TEXT, operation_id TEXT, "
                "occurred_at TEXT, payload_json TEXT, previous_hash TEXT, event_hash TEXT)"
            )
            connection.execute(
                "INSERT INTO consumed_receipts VALUES (?, ?, ?, ?)",
                ("receipt-1", "b" * 64, "2026-07-17T01:02:04Z", "2026-07-17T01:02:04+00:00"),
            )
            connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (1, "read:receipt-1", "read.verified", None, "2026-07-17T01:02:04Z", "{}", "0" * 64, "1" * 64),
            )
            connection.commit()
        os.chmod(auth_path, 0o600)
        os.chmod(receipt_path, 0o600)

        def state_metadata(path: Path) -> dict[str, tuple[int, ...]]:
            return {
                child.name: runner._fingerprint(child.lstat())
                for child in path.parent.iterdir()
            }

        auth_before = state_metadata(auth_path)
        receipt_before = state_metadata(receipt_path)
        self.assertEqual(set(auth_before), {auth_path.name})
        self.assertEqual(set(receipt_before), {receipt_path.name})

        first = runner.state_snapshot(
            self.runtime, token_id="token-1", receipt_id="receipt-1",
        )
        self.assertEqual(first["auth"]["queries"]["count"], [{"value": 1}])
        self.assertEqual(first["receipt"]["queries"]["receipt_count"], [{"value": 1}])
        self.assertEqual(first["receipt"]["queries"]["audit_head"], [{"sequence": 1, "event_hash": "1" * 64}])
        self.assertEqual(state_metadata(auth_path), auth_before)
        self.assertEqual(state_metadata(receipt_path), receipt_before)
        auth_database_identity = {
            key: first["auth"]["database"][key]
            for key in ("path", "device", "inode", "uid", "gid", "mode", "links")
        }
        receipt_database_identity = {
            key: first["receipt"]["database"][key]
            for key in ("path", "device", "inode", "uid", "gid", "mode", "links")
        }

        with closing(sqlite3.connect(auth_path)) as connection:
            connection.execute(
                "INSERT INTO consumed_auth_tokens VALUES (?, ?, ?, ?)",
                ("token-2", "c" * 64, "2026-07-17T01:07:03+00:00", "2026-07-17T01:03:03+00:00"),
            )
            connection.commit()
        with closing(sqlite3.connect(receipt_path)) as connection:
            connection.execute(
                "INSERT INTO consumed_receipts VALUES (?, ?, ?, ?)",
                ("receipt-2", "d" * 64, "2026-07-17T01:03:04Z", "2026-07-17T01:03:04+00:00"),
            )
            connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (2, "read:receipt-2", "read.verified", None, "2026-07-17T01:03:04Z", "{}", "1" * 64, "2" * 64),
            )
            connection.commit()
        second = runner.state_snapshot(
            self.runtime, token_id="token-2", receipt_id="receipt-2",
        )
        self.assertEqual(second["auth"]["queries"]["count"], [{"value": 2}])
        self.assertEqual(second["receipt"]["queries"]["audit_count"], [{"value": 2}])
        self.assertEqual(second["receipt"]["queries"]["audit_head"], [{"sequence": 2, "event_hash": "2" * 64}])
        self.assertEqual(
            {
                key: second["auth"]["database"][key]
                for key in auth_database_identity
            },
            auth_database_identity,
        )
        self.assertEqual(
            {
                key: second["receipt"]["database"][key]
                for key in receipt_database_identity
            },
            receipt_database_identity,
        )

        previous_inode = second["auth"]["parent"]["inode"]
        renamed_parent = auth_path.parent.with_name(auth_path.parent.name + "-renamed")
        auth_path.parent.rename(renamed_parent)
        auth_path.parent.mkdir(mode=0o700)
        replaced = runner.state_snapshot(
            self.runtime, token_id="token-2", receipt_id="receipt-2",
        )
        self.assertFalse(replaced["auth"]["exists"])
        self.assertIsNone(replaced["auth"]["database"])
        self.assertNotEqual(replaced["auth"]["parent"]["inode"], previous_inode)

    def test_result_schema_rate_inverse_and_oracle_identity_are_strict(self) -> None:
        request = self.signed_request()
        result = {**result_body(), "receipt": {}}
        oracle = oracle_document(request["parameters"])
        verifier.verify_golden_and_oracle(self.plan, request, result, oracle)
        bad = deepcopy(result)
        bad["rates"][1]["company_to_transaction_rate"] = "0.2"
        with self.assertRaisesRegex(ValueError, "bidirectional"):
            verifier.verify_golden_and_oracle(self.plan, request, bad, oracle)
        bad_oracle = deepcopy(oracle)
        bad_oracle["database"]["system_identifier"] = "wrong"
        with self.assertRaisesRegex(ValueError, "database identity"):
            verifier.verify_golden_and_oracle(self.plan, request, result, bad_oracle)

    def test_system_snapshot_requires_exact_v2_and_pi_baselines(self) -> None:
        document = system_document(self.plan)
        verifier.verify_system_snapshots(self.plan, document, deepcopy(document))
        wrong_algorithm = deepcopy(document)
        wrong_algorithm["pi_bridge_control"]["algorithm"] = "unverified"
        with self.assertRaisesRegex(ValueError, "five-file"):
            verifier.verify_system_snapshots(
                self.plan, wrong_algorithm, deepcopy(wrong_algorithm),
            )
        changed = deepcopy(document)
        changed["pi_bridge_control"]["entries"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "five-file"):
            verifier.verify_system_snapshots(self.plan, changed, deepcopy(changed))
        inconsistent_plan = deepcopy(self.plan)
        inconsistent_plan["system_baseline"]["pi_bridge_control_entries"][0][
            "sha256"
        ] = "0" * 64
        inconsistent = system_document(inconsistent_plan)
        with self.assertRaisesRegex(ValueError, "aggregate digest"):
            verifier.verify_system_snapshots(
                inconsistent_plan, inconsistent, deepcopy(inconsistent),
            )
        unordered_plan = deepcopy(self.plan)
        unordered_plan["system_baseline"]["pi_bridge_control_entries"].reverse()
        unordered_entries = unordered_plan["system_baseline"][
            "pi_bridge_control_entries"
        ]
        unordered_plan["system_baseline"]["pi_bridge_control_digest"] = (
            hashlib.sha256(verifier.canonical_json(unordered_entries)).hexdigest()
        )
        unordered = system_document(unordered_plan)
        with self.assertRaisesRegex(ValueError, "canonically ordered"):
            verifier.verify_system_snapshots(
                unordered_plan, unordered, deepcopy(unordered),
            )
        loaded = deepcopy(document)
        loaded["v3"]["unit_files"][0]["properties"]["LoadState"] = "loaded"
        with self.assertRaisesRegex(ValueError, "present, loaded, or aliased"):
            verifier.verify_system_snapshots(self.plan, loaded, deepcopy(loaded))

    def test_pi_control_snapshot_matches_frozen_plan_independent_of_order(
        self,
    ) -> None:
        baseline = self.plan["system_baseline"]
        entries = baseline["pi_bridge_control_entries"]
        entry_map = {
            (entry["component"], entry["path"]): entry for entry in entries
        }
        self.assertEqual(len(entry_map), len(entries))
        self.assertEqual(len(entries), len(runner.PI_CONTROL_FILES))
        self.assertEqual(set(entry_map), set(runner.PI_CONTROL_FILES))
        self.assertEqual(
            entries,
            sorted(entries, key=lambda item: (item["component"], item["path"])),
        )
        computed_digest = hashlib.sha256(runner.canonical_json(entries)).hexdigest()
        self.assertEqual(computed_digest, baseline["pi_bridge_control_digest"])
        self.assertEqual(computed_digest, runner.EXPECTED_PI_CONTROL_DIGEST)

        empty_v2_digest = hashlib.sha256(runner.canonical_json([])).hexdigest()

        def capture(order):
            with (
                mock.patch.object(runner, "V2_ROOTS", ()),
                mock.patch.object(runner, "EXPECTED_V2_COMBINED_COUNT", 0),
                mock.patch.object(
                    runner, "EXPECTED_V2_COMBINED_DIGEST", empty_v2_digest,
                ),
                mock.patch.object(runner, "PI_CONTROL_FILES", order),
                mock.patch.object(runner, "V3_CURRENT", self.root / "absent"),
                mock.patch.object(runner, "V3_UNIT_FILES", ()),
                mock.patch.object(runner, "SERVICES", ()),
                mock.patch.object(
                    runner,
                    "fixed_file_snapshot",
                    side_effect=lambda component, path: deepcopy(
                        entry_map[(component, path)]
                    ),
                ),
                mock.patch.object(
                    runner, "systemd_residue_snapshot", return_value={},
                ),
            ):
                return runner.system_snapshot()["pi_bridge_control"]

        declared = capture(runner.PI_CONTROL_FILES)
        reversed_order = capture(tuple(reversed(runner.PI_CONTROL_FILES)))
        self.assertEqual(declared, reversed_order)
        self.assertEqual(declared["entries"], entries)
        self.assertEqual(declared["digest"], baseline["pi_bridge_control_digest"])

    def test_systemd_residue_scanner_rejects_runtime_and_filesystem_residue(self) -> None:
        def fake_runner(*, loaded: bytes = b"", unit_files: bytes = b""):
            def run(command, **_kwargs):
                if command[1] == "list-units":
                    stdout = loaded
                elif command[1] == "list-unit-files":
                    stdout = unit_files
                else:
                    raise AssertionError(command)
                return subprocess.CompletedProcess(command, 0, stdout, b"")
            return run

        empty_root = self.root / "systemd-empty"
        empty_root.mkdir()
        with self.assertRaisesRegex(ValueError, "residue"):
            runner.systemd_residue_snapshot(
                command_runner=fake_runner(
                    loaded=b"odoo-accounting-cli-v3-ghost.service loaded active running\n"
                ),
                unit_paths=[str(empty_root)], supplemental_paths=(), enforce_root=False,
            )
        with self.assertRaisesRegex(ValueError, "residue"):
            runner.systemd_residue_snapshot(
                command_runner=fake_runner(
                    unit_files=b"odoo-accounting-cli-v3-disabled.service disabled disabled\n"
                ),
                unit_paths=[str(empty_root)], supplemental_paths=(), enforce_root=False,
            )

        cases = {
            "transient": ("odoo-accounting-cli-v3-transient.service", "file"),
            "alternate-root": ("odoo-accounting-cli-v3-disabled.socket", "file"),
            "drop-in": ("odoo-accounting-cli-v3-broker.service.d", "directory"),
            "prefixed-symlink": ("odoo-accounting-cli-v3-alias.service", "symlink"),
            "target-alias": ("unrelated-alias.service", "target_symlink"),
        }
        for label, (name, kind) in cases.items():
            root = self.root / f"systemd-{label}"
            root.mkdir()
            path = root / name
            if kind == "file":
                path.write_text("fixture", encoding="utf-8")
            elif kind == "directory":
                path.mkdir()
            else:
                target = root / "odoo-accounting-cli-v3-target.service"
                target.write_text("fixture", encoding="utf-8")
                try:
                    os.symlink(target, path)
                except OSError as exc:
                    self.skipTest(f"symlink creation is unavailable: {exc}")
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "residue"):
                runner.systemd_residue_snapshot(
                    command_runner=fake_runner(), unit_paths=[str(root)],
                    supplemental_paths=(), enforce_root=False,
                )

    def test_systemd_residue_scanner_deduplicates_lib_alias_by_device_inode(self) -> None:
        canonical = self.root / "usr-lib-systemd"
        canonical.mkdir()
        alias = self.root / "lib-systemd"
        try:
            os.symlink(canonical, alias, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlink creation is unavailable: {exc}")

        def command_runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, b"", b"")

        snapshot = runner.systemd_residue_snapshot(
            command_runner=command_runner,
            unit_paths=[str(alias), str(canonical)], supplemental_paths=(),
            enforce_root=False,
        )
        self.assertEqual(len(snapshot["roots"]), 1)
        self.assertEqual(
            snapshot["roots"][0]["aliases"], sorted([str(alias), str(canonical)]),
        )

    def test_systemd_residue_scanner_fails_closed_on_directory_symlinks(self) -> None:
        root = self.root / "systemd-directory-symlinks"
        root.mkdir()
        external = self.root / "external-systemd-directory"
        hidden = external / "odoo-accounting-cli-v3-hidden.service"
        external.mkdir()
        hidden.write_text("fixture", encoding="utf-8")
        wants = root / "unrelated.service.wants"

        def command_runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, b"", b"")

        try:
            os.symlink(external, wants, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlink creation is unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "residue"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=(), enforce_root=False,
            )

        wants.unlink()
        first_hop = self.root / "neutral-systemd-hop"
        os.symlink(external, first_hop, target_is_directory=True)
        os.symlink(first_hop, wants, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "residue"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=(), enforce_root=False,
            )

    def test_systemd_residue_scanner_rejects_symlink_resolution_loops(self) -> None:
        root = self.root / "systemd-symlink-loop"
        root.mkdir()
        first = root / "unrelated.service.wants"
        second = root / "neutral-hop"
        try:
            os.symlink(second, first, target_is_directory=True)
            os.symlink(first, second, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"directory symlink creation is unavailable: {exc}")

        def command_runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaisesRegex(ValueError, "symlink"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=(), enforce_root=False,
            )

    def test_systemd_residue_scanner_rejects_multihop_v3_target(self) -> None:
        root = self.root / "systemd-multihop-root"
        external = self.root / "systemd-multihop-external"
        root.mkdir()
        external.mkdir()
        final = external / "neutral-final.service"
        v3_hop = external / "odoo-accounting-cli-v3-hop.service"
        neutral_hop = external / "neutral-hop.service"
        alias = root / "unrelated-alias.service"
        final.write_text("fixture", encoding="utf-8")
        try:
            os.symlink(final, v3_hop)
            os.symlink(v3_hop, neutral_hop)
            os.symlink(neutral_hop, alias)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        def command_runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaisesRegex(ValueError, "residue"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=(), enforce_root=False,
            )

    def test_systemd_residue_scanner_rejects_v3_parent_symlink_hop(self) -> None:
        root = self.root / "systemd-parent-hop-root"
        final = self.root / "neutral-final-directory"
        v3_parent = self.root / "odoo-accounting-cli-v3-intermediate-directory"
        neutral_parent = self.root / "neutral-parent"
        root.mkdir()
        final.mkdir()
        target = final / "neutral.service"
        target.write_text("fixture", encoding="utf-8")
        try:
            os.symlink(final, v3_parent, target_is_directory=True)
            os.symlink(v3_parent, neutral_parent, target_is_directory=True)
            os.symlink(neutral_parent / target.name, root / "alias.service")
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")

        def command_runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaisesRegex(ValueError, "residue"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=(), enforce_root=False,
            )

    def test_systemd_residue_scanner_rejects_directory_inventory_race(self) -> None:
        root = self.root / "systemd-race-root"
        root.mkdir()
        late = root / "odoo-accounting-cli-v3-late.service"
        real_scandir = runner.os.scandir
        injected = False

        class InjectingScan:
            def __init__(self, path):
                self.path = Path(path)
                self.scanned = real_scandir(path)

            def __enter__(self):
                return self

            def __iter__(self):
                return iter(self.scanned)

            def __exit__(self, *_args):
                nonlocal injected
                self.scanned.close()
                if self.path == root and not injected:
                    injected = True
                    late.write_text("fixture", encoding="utf-8")

        def command_runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(runner.os, "scandir", side_effect=InjectingScan):
            with self.assertRaisesRegex(ValueError, "directory changed"):
                runner.systemd_residue_snapshot(
                    command_runner=command_runner, unit_paths=[str(root)],
                    supplemental_paths=(), enforce_root=False,
                )

    def test_systemd_residue_scanner_rechecks_systemd_after_filesystem_scan(self) -> None:
        root = self.root / "systemd-command-race-root"
        root.mkdir()
        calls = {"list-units": 0, "list-unit-files": 0}

        def command_runner(command, **_kwargs):
            operation = command[1]
            calls[operation] += 1
            stdout = b""
            if operation == "list-units" and calls[operation] == 2:
                stdout = b"odoo-accounting-cli-v3-late.service loaded active running\n"
            return subprocess.CompletedProcess(command, 0, stdout, b"")

        with self.assertRaisesRegex(ValueError, "residue"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=(), enforce_root=False,
            )
        self.assertEqual(calls, {"list-units": 2, "list-unit-files": 2})

    def test_systemd_residue_scanner_accepts_exact_unit_file_no_match_status(self) -> None:
        root = self.root / "systemd-no-match-root"
        root.mkdir()

        def command_runner(command, **_kwargs):
            return subprocess.CompletedProcess(
                command, 1 if command[1] == "list-unit-files" else 0, b"", b"",
            )

        snapshot = runner.systemd_residue_snapshot(
            command_runner=command_runner, unit_paths=[str(root)],
            supplemental_paths=(), enforce_root=False,
        )
        self.assertEqual(snapshot["unit_files"], [])

        for label, status, stdout, stderr in (
            ("nonempty-one", 1, b"unexpected output\n", b""),
            ("status-two", 2, b"", b""),
            ("stderr", 1, b"", b"unexpected error\n"),
        ):
            def invalid_runner(command, **_kwargs):
                if command[1] == "list-unit-files":
                    return subprocess.CompletedProcess(
                        command, status, stdout, stderr,
                    )
                return subprocess.CompletedProcess(command, 0, b"", b"")

            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, "cannot capture"
            ):
                runner.systemd_residue_snapshot(
                    command_runner=invalid_runner, unit_paths=[str(root)],
                    supplemental_paths=(), enforce_root=False,
                )

    def test_systemd_residue_scanner_revalidates_absent_roots(self) -> None:
        root = self.root / "systemd-present-root"
        absent = self.root / "systemd-initially-absent"
        root.mkdir()
        unit_file_calls = 0

        def command_runner(command, **_kwargs):
            nonlocal unit_file_calls
            if command[1] == "list-unit-files":
                unit_file_calls += 1
                if unit_file_calls == 2:
                    absent.mkdir()
                    (absent / "odoo-accounting-cli-v3-late.service").write_text(
                        "fixture", encoding="utf-8"
                    )
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaisesRegex(ValueError, "absent.*appeared"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=[str(absent)], enforce_root=False,
            )

    def test_systemd_residue_scanner_revalidates_external_final_target(self) -> None:
        root = self.root / "systemd-external-target-root"
        external = self.root / "systemd-external-target"
        replacement = self.root / "systemd-external-replacement"
        root.mkdir()
        external.write_text("fixture", encoding="utf-8")
        replacement.mkdir()
        alias = root / "neutral.service"
        try:
            os.symlink(external, alias)
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        unit_file_calls = 0

        def command_runner(command, **_kwargs):
            nonlocal unit_file_calls
            if command[1] == "list-unit-files":
                unit_file_calls += 1
                if unit_file_calls == 2:
                    external.unlink()
                    os.symlink(replacement, external, target_is_directory=True)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with self.assertRaisesRegex(ValueError, "symlink target changed"):
            runner.systemd_residue_snapshot(
                command_runner=command_runner, unit_paths=[str(root)],
                supplemental_paths=(), enforce_root=False,
            )

    def test_psql_oracle_output_boundary_and_command_are_strict(self) -> None:
        request = self.signed_request()
        payload = psql_output(request["parameters"])
        document = oracle_tool.parse_psql_output(
            payload, request=request, executables=oracle_executable_evidence(),
        )
        self.assertTrue(document["transaction"]["rollback_completed"])
        self.assertEqual(document["executables"], oracle_executable_evidence())

        lines = payload.decode("utf-8").splitlines()
        mutations = {
            "extra": lines + ["extra\t{}"],
            "missing": lines[:-1],
            "duplicate": [lines[0], lines[0], *lines[2:]],
            "bad-sentinel": [*lines[:-1], "rollback\twrong"],
        }
        for label, mutated in mutations.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                oracle_tool.parse_psql_output(
                    ("\n".join(mutated) + "\n").encode(), request=request,
                    executables=oracle_executable_evidence(),
                )

        calls = []
        def command_runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, payload, b"")
        actual = oracle_tool.execute_oracle(
            request, command_runner=command_runner,
            executable_verifier=oracle_executable_evidence,
        )
        self.assertEqual(actual["company_currency"]["symbol"], "¥")
        command, kwargs = calls[0]
        self.assertEqual(command, [
            "/usr/lib/postgresql/16/bin/psql", "-X", "-qAt", "-v",
            "ON_ERROR_STOP=1", "-w", "-h", "/var/run/postgresql", "-p",
            "5432", "-U", "postgres", "-d", "odoo_test",
        ])
        self.assertEqual(kwargs["input"], oracle_tool.PSQL_SQL.encode("utf-8"))
        self.assertIn("default_transaction_read_only=on", kwargs["env"]["PGOPTIONS"])

        for returncode, stderr in ((1, b""), (0, b"warning")):
            def failed(command, **_kwargs):
                return subprocess.CompletedProcess(command, returncode, b"", stderr)
            with self.subTest(returncode=returncode, stderr=stderr), self.assertRaisesRegex(ValueError, "nonzero or stderr"):
                oracle_tool.execute_oracle(
                    request, command_runner=failed,
                    executable_verifier=oracle_executable_evidence,
                )

    def test_runner_fixed_parent_and_new_directory_only(self) -> None:
        parent = self.root / "parent"
        parent.mkdir()
        target = parent / "new-evidence"
        created = runner.create_evidence_directory(
            target, enforce_root=False, expected_parent=parent,
        )
        self.assertEqual(created, target.absolute())
        with self.assertRaises(FileExistsError):
            runner.create_evidence_directory(
                target, enforce_root=False, expected_parent=parent,
            )
        with self.assertRaises(ValueError):
            runner.create_evidence_directory(
                self.root / "escape", enforce_root=False, expected_parent=parent,
            )
        with self.assertRaises(ValueError):
            runner.create_evidence_directory(
                parent / ".hidden", enforce_root=False, expected_parent=parent,
            )
        self.assertEqual(
            verifier.validate_evidence_path(target, expected_parent=parent),
            target.absolute(),
        )
        with self.assertRaisesRegex(ValueError, "safe direct child"):
            verifier.validate_evidence_path(self.root / "escape", expected_parent=parent)

    def test_bundle_copy_or_rename_fails_manifest_path_binding(self) -> None:
        evidence = self.build_fixture()
        renamed = self.root / "renamed-evidence"
        shutil.copytree(evidence, renamed)
        with self.assertRaisesRegex(ValueError, "bundle manifest identity"):
            self.verify(renamed)

    def test_source_snapshot_ignores_regular_skip_suffix(self) -> None:
        source_root = self.root / "source-regular-skip"
        source_root.mkdir()
        payload = b"kept\n"
        (source_root / "keep.py").write_bytes(payload)
        (source_root / "ignored.pyc").write_bytes(b"ignored\n")
        members = [{
            "component": "fixture", "path": "keep.py",
            "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
        }]
        digest = hashlib.sha256(runner.canonical_json(members)).hexdigest()
        snapshot, actual = runner.source_tree_snapshot(
            "fixture", source_root, expected_count=1, expected_digest=digest,
        )
        self.assertEqual(actual, members)
        self.assertEqual(snapshot["paths"], ["keep.py"])

    def test_source_snapshot_rejects_pruned_directory_and_skipped_file_symlinks(self) -> None:
        directory_root = self.root / "source-directory-link"
        directory_root.mkdir()
        directory_target = self.root / "directory-target"
        directory_target.mkdir()
        try:
            os.symlink(
                directory_target, directory_root / "__pycache__",
                target_is_directory=True,
            )
        except OSError as exc:
            self.skipTest(f"symlink creation is unavailable: {exc}")
        with self.assertRaisesRegex(ValueError, "unsafe directory object"):
            runner.source_tree_snapshot(
                "fixture", directory_root, expected_count=0,
                expected_digest="0" * 64,
            )

        file_root = self.root / "source-file-link"
        file_root.mkdir()
        file_target = self.root / "target.pyc"
        file_target.write_bytes(b"target")
        os.symlink(file_target, file_root / "ignored.pyc")
        with self.assertRaisesRegex(ValueError, "unsafe object"):
            runner.source_tree_snapshot(
                "fixture", file_root, expected_count=0,
                expected_digest="0" * 64,
            )

    def test_bundle_is_bound_to_external_toolchain_manifest_digest(self) -> None:
        evidence = self.build_fixture()
        manifest = json.loads((evidence / runner.BUNDLE_MANIFEST).read_bytes())
        self.assertEqual(
            manifest["toolchain_manifest_sha256"],
            TEST_TOOLCHAIN_MANIFEST_SHA256,
        )
        with self.assertRaisesRegex(ValueError, "bundle manifest identity"):
            verifier.verify_bundle(
                evidence, self.runtime, auth_secret=AUTH_SECRET,
                receipt_secret=RECEIPT_SECRET, committed_plan_bytes=PLAN_BYTES,
                expected_paths=runtime_paths_for_test(self.root), enforce_root=False,
                expected_toolchain_manifest_sha256="b" * 64,
                expected_state_uid=STATE_UID, expected_state_gid=STATE_GID,
            )

    def test_external_anchor_retry_is_idempotent_but_conflicts_fail(self) -> None:
        evidence = self.build_fixture()
        report = self.verify(evidence)
        parent = self.root / "anchors"
        parent.mkdir()
        anchor = verifier.write_external_anchor(
            evidence, report, anchor_parent=parent, enforce_root=False,
        )
        document = json.loads(anchor.read_bytes())
        self.assertEqual(document["bundle_manifest_sha256"], report["bundle_manifest_sha256"])
        self.assertEqual(document["report_sha256"], hashlib.sha256(verifier.canonical_json(report)).hexdigest())
        self.assertEqual(document["toolchain_version"], verifier.TOOLCHAIN_VERSION)
        self.assertEqual(
            document["toolchain_manifest_sha256"], TEST_TOOLCHAIN_MANIFEST_SHA256,
        )
        self.assertEqual(
            verifier.write_external_anchor(
                evidence, report, anchor_parent=parent, enforce_root=False,
            ),
            anchor,
        )
        different = deepcopy(report)
        different["record_count"] += 1
        with self.assertRaisesRegex(ValueError, "conflicts"):
            verifier.write_external_anchor(
                evidence, different, anchor_parent=parent, enforce_root=False,
            )

        os.chmod(anchor, 0o600)
        tampered = json.loads(anchor.read_bytes())
        tampered["bundle_manifest_sha256"] = "0" * 64
        anchor.write_bytes(verifier.canonical_json(tampered) + b"\n")
        os.chmod(anchor, 0o400)
        with self.assertRaisesRegex(ValueError, "conflicts"):
            verifier.write_external_anchor(
                evidence, report, anchor_parent=parent, enforce_root=False,
            )

    def test_oracle_source_declares_socket_identity_read_only_and_rollback(self) -> None:
        source = (DEV15 / "multicurrency_sql_oracle.py").read_text("utf-8")
        for required in (
            "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
            "current_database()", "pg_control_system()", "database.uuid",
            "inet_server_addr()", "ROLLBACK;", "/var/run/postgresql",
            "default_transaction_read_only=on", "ON_ERROR_STOP=1",
        ):
            self.assertIn(required, source)
        self.assertNotIn("import psycopg2", source)
        self.assertEqual(oracle_tool.decimal_text("6.500"), "6.500")
        self.assertNotIn("company.root_id", source)
        self.assertIn("company.parent_path", source)
        self.assertEqual(oracle_tool.root_company_id_from_parent_path("9/"), 9)
        self.assertEqual(oracle_tool.root_company_id_from_parent_path("1/9/"), 1)
        for invalid in (None, "", "/9/", "0/", "9", "9/x/"):
            with self.subTest(parent_path=invalid), self.assertRaises(ValueError):
                oracle_tool.root_company_id_from_parent_path(invalid)


if __name__ == "__main__":
    unittest.main()

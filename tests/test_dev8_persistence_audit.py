from __future__ import annotations

import importlib.util
import sqlite3
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment/dev8/dev8-persistence-audit.py"


def load_module():
    added_pwd = False
    if importlib.util.find_spec("pwd") is None:
        sys.modules["pwd"] = types.ModuleType("pwd")
        added_pwd = True
    try:
        spec = importlib.util.spec_from_file_location("dev8_persistence_audit", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if added_pwd:
            sys.modules.pop("pwd", None)


@pytest.fixture(scope="module")
def audit_module():
    return load_module()


def create_state(path: Path, auth_rows: list[tuple[str, str, str]]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            """
            PRAGMA user_version = 2;
            CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE approval_records (id INTEGER PRIMARY KEY);
            CREATE TABLE audit_events (
                sequence INTEGER PRIMARY KEY, event_id TEXT, event_type TEXT,
                occurred_at TEXT, operation_id TEXT, payload_json TEXT,
                previous_hash TEXT, event_hash TEXT
            );
            CREATE TABLE consumed_auth_tokens (
                token_id TEXT PRIMARY KEY, request_digest TEXT, expires_at TEXT
            );
            CREATE TABLE consumed_receipts (
                receipt_id TEXT PRIMARY KEY, request_digest TEXT, observed_at TEXT
            );
            CREATE TABLE idempotency_keys (id INTEGER PRIMARY KEY);
            CREATE TABLE operations (id INTEGER PRIMARY KEY);
            """
        )
        connection.executemany(
            "INSERT INTO consumed_auth_tokens VALUES (?, ?, ?)", auth_rows
        )
        connection.commit()
    finally:
        connection.close()


def test_prior_sqlite_rows_must_be_an_exact_subset(audit_module, tmp_path):
    prior_path = tmp_path / "prior.sqlite3"
    current_path = tmp_path / "current.sqlite3"
    prior = [("old", "digest-old", "2026-07-14T00:00:00.000000Z")]
    create_state(prior_path, prior)
    create_state(
        current_path,
        [*prior, ("new", "digest-new", "2026-07-14T00:04:00.000000Z")],
    )
    _, prior_rows = audit_module.inspect_state(prior_path)
    _, current_rows = audit_module.inspect_state(current_path)

    prior_keys, current_keys = audit_module.verify_exact_row_subset(
        prior_rows["auth"], current_rows["auth"], "token_id", "auth state"
    )
    assert prior_keys == {"old"}
    assert current_keys - prior_keys == {"new"}

    next(row for row in current_rows["auth"] if row["token_id"] == "old")[
        "request_digest"
    ] = "tampered"
    with pytest.raises(RuntimeError, match="prior rows changed"):
        audit_module.verify_exact_row_subset(
            prior_rows["auth"], current_rows["auth"], "token_id", "auth state"
        )


def test_prior_audit_rows_must_be_an_exact_prefix(audit_module):
    prior = [{"sequence": 1, "event_hash": "a"}, {"sequence": 2, "event_hash": "b"}]
    current = [*prior, {"sequence": 3, "event_hash": "c"}]
    audit_module.verify_exact_prefix(prior, current, "audit chain")

    reordered = [prior[1], prior[0], current[2]]
    with pytest.raises(RuntimeError, match="exact prefix"):
        audit_module.verify_exact_prefix(prior, reordered, "audit chain")


def test_cumulative_report_schema_is_exact(audit_module):
    assert audit_module.PERSISTENCE_CHECKS == {
        "exact_four_new_unique_auth_tokens",
        "exact_four_new_unique_receipts",
        "exact_four_new_audit_events",
        "new_auth_hmac_verified",
        "new_receipt_hmac_verified",
        "new_request_response_parameter_roundtrip",
        "cumulative_sqlite_snapshots_integral",
        "prior_state_bound",
        "prior_state_preserved",
        "prior_audit_prefix_preserved",
        "full_audit_chain_verified",
        "new_audit_suffix_bound_to_wire_receipts",
        "oracle_audit_verified",
    }
    assert audit_module.PRIOR_EVIDENCE_STATE["auth_tokens"] == 4
    assert audit_module.PRIOR_EVIDENCE_STATE["consumed_receipts"] == 4
    assert audit_module.PRIOR_EVIDENCE_STATE["audit_events"] == 4


def test_live_state_is_snapshotted_without_resetting_it():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "source_connection.backup(target_connection)" in source
    assert "DELETE FROM consumed_auth_tokens" not in source
    assert "DELETE FROM consumed_receipts" not in source
    assert "DELETE FROM audit_events" not in source
    assert "source.unlink(" not in source
    assert "os.unlink(source" not in source

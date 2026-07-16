from __future__ import annotations

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import datetime, timezone

import pytest

from odoo_accounting_cli_v3.broker_audit import (
    BrokerAuditConflict,
    BrokerAuditError,
    BrokerWriteAttempt,
    SQLiteBrokerAuditSink,
    canonical_request_digest,
)


_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_DIGEST_D = "d" * 64


def _attempt(*, attempt_id: str = "attempt-1") -> BrokerWriteAttempt:
    return BrokerWriteAttempt(
        attempt_id=attempt_id,
        occurred_at=datetime(2026, 7, 15, 1, 2, 3, tzinfo=timezone.utc),
        action="operation.prepare",
        request_digest=_DIGEST_A,
        principal="pi-agent",
        user_id=7,
        company_id=11,
        database_name="odoo-sandbox",
        database_uuid="12345678-1234-5678-9234-567812345678",
        environment="sandbox",
        odoo_instance_id="odoo-tokyo-2",
        current_release_digest=_DIGEST_B,
        current_registry_digest=_DIGEST_C,
        selected_release_digest=_DIGEST_B,
        selected_registry_digest=_DIGEST_C,
        operation_id="operation-1",
        challenge_id=None,
        request_id="request-1",
        outcome_code="accepted",
        odoo_effect="none",
        peer_uid=1000,
        peer_gid=1000,
        peer_pid=4321,
    )


def test_append_creates_strict_durable_hash_chained_event(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    sink = SQLiteBrokerAuditSink(database_path)

    event = sink.append(_attempt())

    assert event.sequence == 1
    assert event.previous_hash is None
    assert len(event.event_hash) == 64
    assert sink.events() == (event,)
    assert sink.verify() is True
    with sqlite3.connect(database_path) as connection:
        strict = connection.execute(
            "SELECT strict FROM pragma_table_list "
            "WHERE name='broker_write_attempts'"
        ).fetchone()
    assert strict == (1,)


def test_duplicate_attempt_is_idempotent_but_changed_content_is_rejected(
    tmp_path,
) -> None:
    sink = SQLiteBrokerAuditSink((tmp_path / "broker-audit.sqlite3").resolve())
    attempt = _attempt()

    first = sink.append(attempt)
    duplicate = sink.append(attempt)

    assert duplicate == first
    assert len(sink.events()) == 1
    with pytest.raises(BrokerAuditConflict, match="content conflicts"):
        sink.append(replace(attempt, outcome_code="rejected"))
    assert sink.events() == (first,)


def test_restart_preserves_chain_and_nullable_route_and_peer_fields(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    first_sink = SQLiteBrokerAuditSink(database_path)
    first = first_sink.append(
        replace(
            _attempt(),
            selected_release_digest=None,
            selected_registry_digest=None,
            operation_id=None,
            request_id=None,
            peer_uid=None,
            peer_gid=None,
            peer_pid=None,
        )
    )
    second = first_sink.append(
        replace(
            _attempt(attempt_id="attempt-2"),
            occurred_at=datetime(2026, 7, 15, 1, 2, 4, tzinfo=timezone.utc),
            challenge_id="challenge-2",
        )
    )

    restarted = SQLiteBrokerAuditSink(database_path)

    assert restarted.events() == (first, second)
    assert second.previous_hash == first.event_hash
    assert restarted.verify() is True


def test_selected_release_identity_must_be_both_present_or_both_null() -> None:
    with pytest.raises(BrokerAuditError, match="release identity is incomplete"):
        replace(_attempt(), selected_registry_digest=None)


def test_database_triggers_reject_update_and_delete(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    sink = SQLiteBrokerAuditSink(database_path)
    event = sink.append(_attempt())

    with sqlite3.connect(database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE broker_write_attempts SET outcome_code='forged' "
                "WHERE attempt_id=?",
                (event.attempt_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM broker_write_attempts WHERE attempt_id=?",
                (event.attempt_id,),
            )

    assert sink.events() == (event,)


def test_reopen_rejects_content_tampering_even_if_trigger_is_restored(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    SQLiteBrokerAuditSink(database_path).append(_attempt())

    with sqlite3.connect(database_path) as connection:
        payload_text = connection.execute(
            "SELECT payload_json FROM broker_write_attempts WHERE sequence=1"
        ).fetchone()[0]
        payload = json.loads(payload_text)
        payload["outcome_code"] = "forged"
        connection.execute("DROP TRIGGER broker_write_attempts_no_update")
        connection.execute(
            "UPDATE broker_write_attempts "
            "SET outcome_code=?, payload_json=? WHERE sequence=1",
            (
                "forged",
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        connection.execute(
            "CREATE TRIGGER broker_write_attempts_no_update "
            "BEFORE UPDATE ON broker_write_attempts BEGIN "
            "SELECT RAISE(ABORT, 'broker write attempts are append-only'); END"
        )

    with pytest.raises(BrokerAuditError, match="hash chain verification failed"):
        SQLiteBrokerAuditSink(database_path)


def test_append_propagates_schema_failure_and_does_not_write(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    sink = SQLiteBrokerAuditSink(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER broker_write_attempts_no_delete")

    with pytest.raises(BrokerAuditError, match="trigger schema is invalid"):
        sink.append(_attempt())

    with sqlite3.connect(database_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM broker_write_attempts"
        ).fetchone()[0]
    assert count == 0


def test_concurrent_independent_sinks_serialize_one_unbroken_chain(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    sinks = [SQLiteBrokerAuditSink(database_path) for _ in range(4)]
    attempts = [_attempt(attempt_id=f"attempt-{index}") for index in range(1, 17)]

    def append(index: int):
        return sinks[index % len(sinks)].append(attempts[index])

    with ThreadPoolExecutor(max_workers=8) as executor:
        appended = tuple(executor.map(append, range(len(attempts))))

    events = sinks[0].events()
    assert {event.attempt_id for event in appended} == {
        attempt.attempt_id for attempt in attempts
    }
    assert tuple(event.sequence for event in events) == tuple(range(1, 17))
    assert all(
        event.previous_hash == previous.event_hash
        for previous, event in zip(events, events[1:])
    )
    assert sinks[0].verify() is True


def test_concurrent_duplicate_attempt_is_persisted_once(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    sinks = [SQLiteBrokerAuditSink(database_path) for _ in range(6)]
    attempt = _attempt()

    with ThreadPoolExecutor(max_workers=6) as executor:
        events = tuple(executor.map(lambda sink: sink.append(attempt), sinks))

    assert all(event == events[0] for event in events)
    assert sinks[0].events() == (events[0],)


def test_only_request_digest_is_stored_not_sensitive_request_content(tmp_path) -> None:
    database_path = (tmp_path / "broker-audit.sqlite3").resolve()
    sensitive_values = (
        "SESSION_HANDLE_MUST_NEVER_REACH_DISK_6f1448",
        "SIGNING_SECRET_MUST_NEVER_REACH_DISK_971bb2",
        "FULL_BUSINESS_PARAMETERS_MUST_NEVER_REACH_DISK_c24da1",
    )
    request = {
        "session_handle": sensitive_values[0],
        "secret": sensitive_values[1],
        "parameters": {
            "supplier": sensitive_values[2],
            "amount": "999999.99",
        },
    }
    digest = canonical_request_digest(request)
    sink = SQLiteBrokerAuditSink(database_path)

    event = sink.append(replace(_attempt(), request_digest=digest))

    assert event.request_digest == digest
    persisted = b"".join(
        path.read_bytes() for path in tmp_path.glob("broker-audit.sqlite3*")
    )
    for sensitive in sensitive_values:
        assert sensitive.encode("utf-8") not in persisted


def test_record_uses_injected_clock_and_attempt_id_factory(tmp_path) -> None:
    occurred_at = datetime(2026, 7, 15, 9, 8, 7, tzinfo=timezone.utc)
    sink = SQLiteBrokerAuditSink(
        (tmp_path / "broker-audit.sqlite3").resolve(),
        clock=lambda: occurred_at,
        attempt_id_factory=lambda: "factory-attempt-1",
    )
    values = asdict(_attempt())
    values.pop("attempt_id")
    values.pop("occurred_at")

    event = sink.record(**values)

    assert event.attempt_id == "factory-attempt-1"
    assert event.occurred_at == occurred_at


def test_occurrence_time_may_precede_prior_commit_for_concurrent_attempts(
    tmp_path,
) -> None:
    sink = SQLiteBrokerAuditSink((tmp_path / "broker-audit.sqlite3").resolve())
    later = sink.append(
        replace(
            _attempt(),
            occurred_at=datetime(2026, 7, 15, 1, 2, 5, tzinfo=timezone.utc),
        )
    )

    earlier = sink.append(
        replace(
            _attempt(attempt_id="attempt-2"),
            occurred_at=datetime(2026, 7, 15, 1, 2, 4, tzinfo=timezone.utc),
        )
    )

    assert earlier.sequence == 2
    assert earlier.previous_hash == later.event_hash
    assert sink.verify() is True


def test_verified_odoo_effect_records_success_after_real_verification(tmp_path) -> None:
    sink = SQLiteBrokerAuditSink((tmp_path / "broker-audit.sqlite3").resolve())

    event = sink.append(replace(_attempt(), odoo_effect="verified"))

    assert event.odoo_effect == "verified"
    assert sink.events() == (event,)


def test_real_broker_action_and_outcome_identifiers_allow_underscores(tmp_path) -> None:
    sink = SQLiteBrokerAuditSink((tmp_path / "broker-audit.sqlite3").resolve())

    event = sink.append(
        replace(
            _attempt(),
            action="operation.approve_execute",
            outcome_code="broker_response_verification_failed",
            odoo_effect="unknown",
        )
    )

    assert event.action == "operation.approve_execute"
    assert event.outcome_code == "broker_response_verification_failed"


def test_trusted_identity_text_accepts_email_and_unicode_without_control_bytes(
    tmp_path,
) -> None:
    sink = SQLiteBrokerAuditSink((tmp_path / "broker-audit.sqlite3").resolve())
    event = sink.append(
        replace(
            _attempt(),
            principal="user+accounting@example.com",
            database_name="东京会计沙箱",
            odoo_instance_id="odoo19@东京-2",
        )
    )
    assert event.principal == "user+accounting@example.com"
    assert sink.events() == (event,)

    with pytest.raises(BrokerAuditError, match="principal"):
        replace(_attempt(attempt_id="attempt-control"), principal="bad\nprincipal")


def test_database_path_must_be_absolute() -> None:
    with pytest.raises(BrokerAuditError, match="path must be absolute"):
        SQLiteBrokerAuditSink("broker-audit.sqlite3")


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode check")
def test_existing_database_file_must_be_private_on_posix(tmp_path) -> None:
    database_path = tmp_path / "broker-audit.sqlite3"
    database_path.touch()
    database_path.chmod(0o644)

    with pytest.raises(BrokerAuditError, match="file is not private"):
        SQLiteBrokerAuditSink(database_path.resolve())

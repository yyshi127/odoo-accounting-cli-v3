"""Finalizer-only durable orchestration for resolving Odoo effect anchors.

The public control plane submits a time-free, content-bound intent.  This
service is the only process that owns the finalizer HMAC key and it persists
each concrete proof before PostgreSQL is called.  A lost response therefore
reuses the exact attestation; an expired proof is superseded only after the
database adapter has proved that exact attestation was not committed.
"""

from __future__ import annotations

import hmac
import json
import os
import sqlite3
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .effect_finalizer import (
    EFFECT_FINALIZATION_PROTOCOL_VERSION,
    EffectFinalizationAttestation,
    EffectFinalizationError,
    EffectFinalizationIntent,
    EffectFinalizationReceipt,
    EffectFinalizationRequest,
    create_effect_attestation,
    verify_effect_attestation,
)
from .operations import canonical_json


class EffectFinalizerServiceError(RuntimeError):
    """The isolated finalizer could not safely resolve an effect intent."""


class EffectFinalizationAttemptExpired(EffectFinalizerServiceError):
    """The database proved an exact attempt was absent and is now expired."""


_INTENT_FIELDS = frozenset(
    {
        "protocol_version",
        "database_name",
        "database_uuid",
        "operation_id",
        "operation_digest",
        "execution_result_digest",
        "resolution_operation_id",
        "resolution_operation_digest",
        "resolution_execution_result_digest",
        "resolution_result_digest",
        "resolution_kind",
    }
)
_ATTEMPT_ATTESTATION_FIELDS = frozenset(
    {"attestation_id", "request_digest", "key_id", "attestation_digest"}
)


def _utc(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise EffectFinalizerServiceError(f"{label} must include a timezone")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return _utc(value, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise EffectFinalizerServiceError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EffectFinalizerServiceError(f"{label} is invalid") from exc
    normalized = _utc(parsed, label)
    if _utc_text(normalized) != value:
        raise EffectFinalizerServiceError(f"{label} is not canonical")
    return normalized


def effect_finalization_intent_from_mapping(value: Any) -> EffectFinalizationIntent:
    """Strict wire/journal parser for the shared time-free intent contract."""

    if not isinstance(value, Mapping) or set(value) != _INTENT_FIELDS:
        raise EffectFinalizerServiceError(
            "effect finalization intent fields are invalid"
        )
    if (
        type(value["protocol_version"]) is not int
        or value["protocol_version"] != EFFECT_FINALIZATION_PROTOCOL_VERSION
    ):
        raise EffectFinalizerServiceError(
            "effect finalization intent protocol is invalid"
        )
    try:
        return EffectFinalizationIntent(
            **{
                field: value[field]
                for field in _INTENT_FIELDS
                if field != "protocol_version"
            }
        )
    except (TypeError, EffectFinalizationError) as exc:
        raise EffectFinalizerServiceError(
            "effect finalization intent is invalid"
        ) from exc


@dataclass(frozen=True)
class EffectFinalizationAttemptRecord:
    intent_digest: str
    sequence: int
    request: EffectFinalizationRequest
    attestation: EffectFinalizationAttestation
    expired_uncommitted_at: datetime | None
    receipt_evidence: dict[str, Any] | None


@dataclass(frozen=True)
class FinalizedEffect:
    request: EffectFinalizationRequest
    receipt: EffectFinalizationReceipt

    def __post_init__(self) -> None:
        if not isinstance(self.request, EffectFinalizationRequest) or not isinstance(
            self.receipt, EffectFinalizationReceipt
        ):
            raise EffectFinalizerServiceError("finalized effect is invalid")
        try:
            self.receipt.validate_for(self.request)
        except EffectFinalizationError as exc:
            raise EffectFinalizerServiceError(
                "finalized effect receipt is not bound"
            ) from exc


class EffectFinalizerAttemptJournal:
    """Finalizer-private append-only SQLite proof-attempt journal."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        require_posix_owner: bool = True,
        busy_timeout_ms: int = 1000,
    ) -> None:
        self.path = Path(path)
        if (
            not self.path.is_absolute()
            or type(require_posix_owner) is not bool
            or isinstance(busy_timeout_ms, bool)
            or not isinstance(busy_timeout_ms, int)
            or not 1 <= busy_timeout_ms <= 1000
        ):
            raise EffectFinalizerServiceError(
                "effect finalizer journal configuration is invalid"
            )
        self._require_posix_owner = require_posix_owner
        self._busy_timeout_ms = busy_timeout_ms
        self._validate_path(before_create=True)
        self._initialize()
        self._validate_path(before_create=False)

    def _validate_path(self, *, before_create: bool) -> None:
        try:
            parent = self.path.parent
            metadata = parent.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or parent.is_symlink()
                or parent.resolve(strict=True) != parent
            ):
                raise EffectFinalizerServiceError(
                    "effect finalizer journal parent is unsafe"
                )
            if os.name == "posix" and self._require_posix_owner:
                if (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise EffectFinalizerServiceError(
                        "effect finalizer journal parent is unsafe"
                    )
            if self.path.exists() or not before_create:
                value = self.path.lstat()
                if (
                    not stat.S_ISREG(value.st_mode)
                    or self.path.is_symlink()
                    or self.path.resolve(strict=True) != self.path
                ):
                    raise EffectFinalizerServiceError(
                        "effect finalizer journal file is unsafe"
                    )
                if os.name == "posix" and self._require_posix_owner and (
                    value.st_uid != os.geteuid()
                    or stat.S_IMODE(value.st_mode) != 0o600
                ):
                    raise EffectFinalizerServiceError(
                        "effect finalizer journal file is unsafe"
                    )
        except EffectFinalizerServiceError:
            raise
        except OSError as exc:
            raise EffectFinalizerServiceError(
                "effect finalizer journal path is unavailable"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS finalization_intent (
                    intent_digest TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL
                ) STRICT;
                CREATE TABLE IF NOT EXISTS finalization_attempt (
                    intent_digest TEXT NOT NULL REFERENCES finalization_intent(intent_digest),
                    sequence INTEGER NOT NULL CHECK (sequence > 0),
                    request_json TEXT NOT NULL,
                    attestation_json TEXT NOT NULL,
                    PRIMARY KEY (intent_digest, sequence),
                    UNIQUE (attestation_json)
                ) STRICT;
                CREATE TABLE IF NOT EXISTS finalization_attempt_outcome (
                    intent_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    outcome_kind TEXT NOT NULL CHECK (
                        outcome_kind IN ('expired_uncommitted', 'committed')
                    ),
                    outcome_json TEXT,
                    occurred_at TEXT NOT NULL,
                    PRIMARY KEY (intent_digest, sequence),
                    FOREIGN KEY (intent_digest, sequence) REFERENCES
                        finalization_attempt(intent_digest, sequence)
                ) STRICT;
                COMMIT;
                """
            )
        except Exception:
            try:
                connection.rollback()
            finally:
                connection.close()
            raise
        connection.close()
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    @staticmethod
    def _request_from_payload(value: Any) -> EffectFinalizationRequest:
        if not isinstance(value, Mapping):
            raise EffectFinalizerServiceError("journal request is invalid")
        try:
            fields = dict(value)
            if fields.pop("protocol_version") != EFFECT_FINALIZATION_PROTOCOL_VERSION:
                raise EffectFinalizerServiceError("journal request is invalid")
            fields["verified_at"] = _parse_utc(fields["verified_at"], "verified_at")
            fields["expires_at"] = _parse_utc(fields["expires_at"], "expires_at")
            return EffectFinalizationRequest(**fields)
        except (KeyError, TypeError, EffectFinalizationError) as exc:
            raise EffectFinalizerServiceError("journal request is invalid") from exc

    @staticmethod
    def _attestation_from_payload(value: Any) -> EffectFinalizationAttestation:
        if not isinstance(value, Mapping) or set(value) != _ATTEMPT_ATTESTATION_FIELDS:
            raise EffectFinalizerServiceError("journal attestation is invalid")
        try:
            return EffectFinalizationAttestation(**dict(value))
        except (TypeError, EffectFinalizationError) as exc:
            raise EffectFinalizerServiceError("journal attestation is invalid") from exc

    @staticmethod
    def _json(value: Any) -> str:
        return canonical_json(value).decode("utf-8")

    @staticmethod
    def _decode_json(value: Any, label: str) -> Any:
        if not isinstance(value, str):
            raise EffectFinalizerServiceError(f"{label} is invalid")
        try:
            decoded = json.loads(value)
        except (ValueError, UnicodeError) as exc:
            raise EffectFinalizerServiceError(f"{label} is invalid") from exc
        if EffectFinalizerAttemptJournal._json(decoded) != value:
            raise EffectFinalizerServiceError(f"{label} is not canonical")
        return decoded

    def ensure_intent(self, intent: EffectFinalizationIntent) -> None:
        if not isinstance(intent, EffectFinalizationIntent):
            raise EffectFinalizerServiceError("effect finalization intent is invalid")
        payload = self._json(intent.payload())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO finalization_intent(intent_digest, payload_json) "
                "VALUES (?, ?) ON CONFLICT(intent_digest) DO NOTHING",
                (intent.intent_digest, payload),
            )
            row = connection.execute(
                "SELECT payload_json FROM finalization_intent WHERE intent_digest = ?",
                (intent.intent_digest,),
            ).fetchone()
            if row is None or not hmac.compare_digest(row[0], payload):
                raise EffectFinalizerServiceError(
                    "effect finalization intent journal binding differs"
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def append_attempt(
        self,
        intent: EffectFinalizationIntent,
        request: EffectFinalizationRequest,
        attestation: EffectFinalizationAttestation,
    ) -> EffectFinalizationAttemptRecord:
        if request.request_digest != attestation.request_digest:
            raise EffectFinalizerServiceError(
                "effect finalization attempt proof is not bound"
            )
        expected = EffectFinalizationRequest.from_intent(
            intent,
            verified_at=request.verified_at,
            expires_at=request.expires_at,
        )
        if expected != request:
            raise EffectFinalizerServiceError(
                "effect finalization attempt differs from intent"
            )
        request_json = self._json(request.payload())
        attestation_json = self._json(
            {
                "attestation_id": attestation.attestation_id,
                "request_digest": attestation.request_digest,
                "key_id": attestation.key_id,
                "attestation_digest": attestation.attestation_digest,
            }
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM finalization_attempt "
                "WHERE intent_digest = ?",
                (intent.intent_digest,),
            ).fetchone()
            sequence = row[0]
            connection.execute(
                "INSERT INTO finalization_attempt("
                "intent_digest, sequence, request_json, attestation_json"
                ") VALUES (?, ?, ?, ?)",
                (intent.intent_digest, sequence, request_json, attestation_json),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return EffectFinalizationAttemptRecord(
            intent_digest=intent.intent_digest,
            sequence=sequence,
            request=request,
            attestation=attestation,
            expired_uncommitted_at=None,
            receipt_evidence=None,
        )

    def _record_outcome(
        self,
        attempt: EffectFinalizationAttemptRecord,
        *,
        kind: str,
        outcome: Any,
        occurred_at: datetime,
    ) -> None:
        occurred_at_text = _utc_text(occurred_at)
        outcome_json = None if outcome is None else self._json(outcome)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO finalization_attempt_outcome("
                "intent_digest, sequence, outcome_kind, outcome_json, occurred_at"
                ") VALUES (?, ?, ?, ?, ?) ON CONFLICT(intent_digest, sequence) "
                "DO NOTHING",
                (
                    attempt.intent_digest,
                    attempt.sequence,
                    kind,
                    outcome_json,
                    occurred_at_text,
                ),
            )
            row = connection.execute(
                "SELECT outcome_kind, outcome_json, occurred_at "
                "FROM finalization_attempt_outcome "
                "WHERE intent_digest = ? AND sequence = ?",
                (attempt.intent_digest, attempt.sequence),
            ).fetchone()
            if row is None or tuple(row[:2]) != (kind, outcome_json):
                raise EffectFinalizerServiceError(
                    "effect finalization attempt outcome differs"
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_expired_uncommitted(
        self, attempt: EffectFinalizationAttemptRecord, *, occurred_at: datetime
    ) -> None:
        self._record_outcome(
            attempt,
            kind="expired_uncommitted",
            outcome=None,
            occurred_at=occurred_at,
        )

    def record_receipt(
        self,
        attempt: EffectFinalizationAttemptRecord,
        receipt: EffectFinalizationReceipt,
        *,
        occurred_at: datetime,
    ) -> None:
        if not isinstance(receipt, EffectFinalizationReceipt):
            raise EffectFinalizerServiceError(
                "effect finalization receipt is invalid"
            )
        try:
            receipt.validate_for(attempt.request)
        except EffectFinalizationError as exc:
            raise EffectFinalizerServiceError(
                "effect finalization receipt is not bound"
            ) from exc
        self._record_outcome(
            attempt,
            kind="committed",
            outcome=receipt.evidence,
            occurred_at=occurred_at,
        )

    def attempts_for(self, intent_digest: str) -> tuple[EffectFinalizationAttemptRecord, ...]:
        if not isinstance(intent_digest, str) or len(intent_digest) != 64:
            raise EffectFinalizerServiceError("intent digest is invalid")
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT attempt.sequence, attempt.request_json, "
                "attempt.attestation_json, outcome.outcome_kind, "
                "outcome.outcome_json, outcome.occurred_at "
                "FROM finalization_attempt AS attempt LEFT JOIN "
                "finalization_attempt_outcome AS outcome USING "
                "(intent_digest, sequence) WHERE attempt.intent_digest = ? "
                "ORDER BY attempt.sequence",
                (intent_digest,),
            ).fetchall()
        finally:
            connection.close()
        result = []
        for row in rows:
            request = self._request_from_payload(
                self._decode_json(row[1], "journal request")
            )
            attestation = self._attestation_from_payload(
                self._decode_json(row[2], "journal attestation")
            )
            if request.request_digest != attestation.request_digest:
                raise EffectFinalizerServiceError(
                    "journal attempt proof binding is invalid"
                )
            expired = None
            receipt = None
            if row[3] == "expired_uncommitted":
                if row[4] is not None:
                    raise EffectFinalizerServiceError(
                        "journal expired outcome is invalid"
                    )
                expired = _parse_utc(row[5], "journal outcome time")
            elif row[3] == "committed":
                receipt = self._decode_json(row[4], "journal receipt")
                _parse_utc(row[5], "journal outcome time")
            elif row[3] is not None:
                raise EffectFinalizerServiceError(
                    "journal attempt outcome is invalid"
                )
            result.append(
                EffectFinalizationAttemptRecord(
                    intent_digest=intent_digest,
                    sequence=row[0],
                    request=request,
                    attestation=attestation,
                    expired_uncommitted_at=expired,
                    receipt_evidence=receipt,
                )
            )
        return tuple(result)


DatabaseFinalize = Callable[
    [EffectFinalizationRequest, EffectFinalizationAttestation],
    EffectFinalizationReceipt,
]
_MAX_EXPIRED_REFRESHES_PER_CALL = 1


class EffectFinalizerService:
    """Serialize proof attempts and require a committed database receipt."""

    def __init__(
        self,
        *,
        journal: EffectFinalizerAttemptJournal,
        database_finalize: DatabaseFinalize,
        key_id: str,
        secret: bytes,
        now: Callable[[], datetime],
        proof_ttl_seconds: int = 120,
    ) -> None:
        if (
            not isinstance(journal, EffectFinalizerAttemptJournal)
            or not callable(database_finalize)
            or not callable(now)
            or not isinstance(key_id, str)
            or not key_id
            or type(secret) is not bytes
            or len(secret) < 32
            or isinstance(proof_ttl_seconds, bool)
            or not isinstance(proof_ttl_seconds, int)
            or not 0 < proof_ttl_seconds <= 300
        ):
            raise EffectFinalizerServiceError(
                "effect finalizer service configuration is invalid"
            )
        self._journal = journal
        self._database_finalize = database_finalize
        self._key_id = key_id
        self._secret = secret
        self._now = now
        self._proof_ttl_seconds = proof_ttl_seconds
        self._lock = threading.Lock()

    def _new_attempt(
        self, intent: EffectFinalizationIntent
    ) -> EffectFinalizationAttemptRecord:
        verified_at = _utc(self._now(), "effect finalizer clock")
        request = EffectFinalizationRequest.from_intent(
            intent,
            verified_at=verified_at,
            expires_at=verified_at + timedelta(seconds=self._proof_ttl_seconds),
        )
        try:
            attestation = create_effect_attestation(
                request,
                key_id=self._key_id,
                secret=self._secret,
            )
        except EffectFinalizationError as exc:
            raise EffectFinalizerServiceError(
                "effect finalization attestation could not be created"
            ) from exc
        return self._journal.append_attempt(intent, request, attestation)

    def finalize_with_attempt(
        self, intent: EffectFinalizationIntent
    ) -> FinalizedEffect:
        if not isinstance(intent, EffectFinalizationIntent):
            raise EffectFinalizerServiceError("effect finalization intent is invalid")
        with self._lock:
            self._journal.ensure_intent(intent)
            expired_refreshes = 0
            while True:
                attempts = self._journal.attempts_for(intent.intent_digest)
                active = (
                    attempts[-1]
                    if attempts
                    and attempts[-1].expired_uncommitted_at is None
                    else None
                )
                if active is None:
                    active = self._new_attempt(intent)
                try:
                    verify_effect_attestation(
                        active.attestation,
                        request=active.request,
                        expected_key_id=self._key_id,
                        secret=self._secret,
                    )
                except EffectFinalizationError as exc:
                    raise EffectFinalizerServiceError(
                        "journal finalization attestation is invalid"
                    ) from exc
                if active.request.intent != intent:
                    raise EffectFinalizerServiceError(
                        "journal finalization attempt differs from intent"
                    )
                try:
                    receipt = self._database_finalize(
                        active.request, active.attestation
                    )
                except EffectFinalizationAttemptExpired:
                    occurred_at = _utc(self._now(), "effect finalizer clock")
                    if occurred_at < active.request.expires_at:
                        raise EffectFinalizerServiceError(
                            "database reported a non-expired proof as expired"
                        )
                    self._journal.record_expired_uncommitted(
                        active, occurred_at=occurred_at
                    )
                    expired_refreshes += 1
                    if expired_refreshes > _MAX_EXPIRED_REFRESHES_PER_CALL:
                        raise EffectFinalizerServiceError(
                            "effect finalization proof refresh limit was reached"
                        )
                    continue
                if not isinstance(receipt, EffectFinalizationReceipt):
                    raise EffectFinalizerServiceError(
                        "database returned no typed finalization receipt"
                    )
                self._journal.record_receipt(
                    active,
                    receipt,
                    occurred_at=_utc(self._now(), "effect finalizer clock"),
                )
                return FinalizedEffect(request=active.request, receipt=receipt)

    def finalize(
        self, intent: EffectFinalizationIntent
    ) -> EffectFinalizationReceipt:
        return self.finalize_with_attempt(intent).receipt


__all__ = [
    "EffectFinalizationAttemptExpired",
    "EffectFinalizationAttemptRecord",
    "EffectFinalizationIntent",
    "EffectFinalizerAttemptJournal",
    "EffectFinalizerService",
    "EffectFinalizerServiceError",
    "FinalizedEffect",
    "effect_finalization_intent_from_mapping",
]

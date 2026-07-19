"""Content-bound proof and immutable receipt contracts for Odoo effects."""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .operations import Operation, TrustedResult, canonical_json


class EffectFinalizationError(ValueError):
    """The root-only effect finalization proof or receipt is invalid."""


EFFECT_FINALIZATION_PROTOCOL_VERSION = 1
EFFECT_FINALIZATION_PURPOSE = "effect_finalization_attestation_v1"
MAX_PROOF_TTL = timedelta(minutes=5)
MIN_SECRET_BYTES = 32
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DATABASE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ATTESTATION_NAMESPACE = uuid.UUID("9046ee2c-69ae-56a1-bf90-b19030ade1bd")
_DATABASE_RECEIPT_FIELDS = frozenset(
    {
        "receipt_attestation_id",
        "receipt_guard_installation_id",
        "receipt_database_oid",
        "receipt_database_uuid",
        "resolved_operation_id",
        "receipt_resolution_operation_id",
        "applied_resolution_kind",
        "resolved_anchor_count",
        "remaining_unresolved_count",
        "guard_epoch",
        "receipt_attestation_digest",
        "finalized_at",
        "finalized_txid",
        "replayed",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {
        "attestation_digest",
        "attestation_id",
        "attestation_key_id",
        "database_oid",
        "database_uuid",
        "finalized_at",
        "finalized_txid",
        "guard_epoch",
        "guard_installation_id",
        "intent_digest",
        "operation_id",
        "proof_expires_at",
        "proof_verified_at",
        "protocol_version",
        "remaining_unresolved_count",
        "request_digest",
        "resolution_kind",
        "resolution_operation_id",
        "resolved_anchor_count",
        "receipt_digest",
    }
)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _utc(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise EffectFinalizationError(f"{label} must include a timezone")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: Any, label: str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EffectFinalizationError(f"{label} is invalid") from exc
    return _utc(value, label)


def _uuid(value: Any, label: str) -> str:
    try:
        normalized = str(uuid.UUID(value))
    except (AttributeError, TypeError, ValueError) as exc:
        raise EffectFinalizationError(f"{label} is invalid") from exc
    if value != normalized:
        raise EffectFinalizationError(f"{label} is not canonical")
    return normalized


def _database_uuid(value: Any, label: str) -> str:
    """Normalize UUID objects returned by PostgreSQL drivers, not caller input."""

    if isinstance(value, uuid.UUID):
        return str(value)
    return _uuid(value, label)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise EffectFinalizationError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise EffectFinalizationError(f"{label} is invalid")
    return value


def _key_id(value: Any) -> str:
    if not isinstance(value, str) or _KEY_ID.fullmatch(value) is None:
        raise EffectFinalizationError("effect finalizer key ID is invalid")
    return value


def _secret(value: Any) -> bytes:
    if type(value) is not bytes or len(value) < MIN_SECRET_BYTES:
        raise EffectFinalizationError(
            "effect finalizer secret must contain at least 32 bytes"
        )
    return value


def trusted_result_envelope_digest(
    result: TrustedResult,
    operation: Operation,
) -> str:
    """Return the exact digest stored in the Odoo control anchor."""

    if not isinstance(result, TrustedResult) or not isinstance(operation, Operation):
        raise EffectFinalizationError("trusted result envelope is invalid")
    operation.assert_integrity()
    if (
        result.operation_id != operation.operation_id
        or result.request_id != operation.request_id
        or result.operation_digest != operation.digest
        or result.company_id != operation.company_id
    ):
        raise EffectFinalizationError("trusted result envelope binding is invalid")
    return _digest(
        {
            **result.payload(),
            "capability_id": operation.capability_id,
            "registry_digest": operation.registry_digest,
            "release_digest": operation.release_digest,
            "signature": result.signature,
        }
    )


@dataclass(frozen=True)
class EffectFinalizationIntent:
    database_name: str
    database_uuid: str
    operation_id: str
    operation_digest: str
    execution_result_digest: str
    resolution_operation_id: str
    resolution_operation_digest: str
    resolution_execution_result_digest: str
    resolution_result_digest: str
    resolution_kind: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.database_name, str)
            or _DATABASE_NAME.fullmatch(self.database_name) is None
        ):
            raise EffectFinalizationError("effect finalization database is invalid")
        try:
            database_uuid = _uuid(
                self.database_uuid, "effect finalization database UUID"
            )
            operation_id = _identifier(self.operation_id, "operation_id")
            resolution_operation_id = _identifier(
                self.resolution_operation_id, "resolution_operation_id"
            )
            operation_digest = _sha256(
                self.operation_digest, "operation_digest"
            )
            execution_result_digest = _sha256(
                self.execution_result_digest, "execution_result_digest"
            )
            resolution_operation_digest = _sha256(
                self.resolution_operation_digest,
                "resolution_operation_digest",
            )
            resolution_execution_result_digest = _sha256(
                self.resolution_execution_result_digest,
                "resolution_execution_result_digest",
            )
            _sha256(self.resolution_result_digest, "resolution_result_digest")
        except EffectFinalizationError:
            raise
        if self.resolution_kind == "verified":
            if (
                resolution_operation_id != operation_id
                or resolution_operation_digest != operation_digest
                or resolution_execution_result_digest
                != execution_result_digest
            ):
                raise EffectFinalizationError(
                    "verified resolution must bind the same operation"
                )
        elif self.resolution_kind == "recovered":
            if resolution_operation_id == operation_id:
                raise EffectFinalizationError(
                    "recovered resolution requires a distinct operation"
                )
        else:
            raise EffectFinalizationError("effect finalization resolution kind is invalid")
        object.__setattr__(self, "database_uuid", database_uuid)

    @property
    def intent_digest(self) -> str:
        return _digest(self.payload())

    def payload(self) -> dict[str, Any]:
        return {
            "database_name": self.database_name,
            "database_uuid": self.database_uuid,
            "execution_result_digest": self.execution_result_digest,
            "operation_digest": self.operation_digest,
            "operation_id": self.operation_id,
            "protocol_version": EFFECT_FINALIZATION_PROTOCOL_VERSION,
            "resolution_execution_result_digest": (
                self.resolution_execution_result_digest
            ),
            "resolution_kind": self.resolution_kind,
            "resolution_operation_digest": self.resolution_operation_digest,
            "resolution_operation_id": self.resolution_operation_id,
            "resolution_result_digest": self.resolution_result_digest,
        }


@dataclass(frozen=True)
class EffectFinalizationRequest(EffectFinalizationIntent):
    verified_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        super().__post_init__()
        verified_at = _utc(self.verified_at, "proof verified_at")
        expires_at = _utc(self.expires_at, "proof expires_at")
        if not timedelta(0) < expires_at - verified_at <= MAX_PROOF_TTL:
            raise EffectFinalizationError("effect finalization proof window is invalid")
        object.__setattr__(self, "verified_at", verified_at)
        object.__setattr__(self, "expires_at", expires_at)

    @classmethod
    def from_intent(
        cls,
        intent: EffectFinalizationIntent,
        *,
        verified_at: datetime,
        expires_at: datetime,
    ) -> "EffectFinalizationRequest":
        if not isinstance(intent, EffectFinalizationIntent):
            raise EffectFinalizationError("effect finalization intent is invalid")
        return cls(
            database_name=intent.database_name,
            database_uuid=intent.database_uuid,
            operation_id=intent.operation_id,
            operation_digest=intent.operation_digest,
            execution_result_digest=intent.execution_result_digest,
            resolution_operation_id=intent.resolution_operation_id,
            resolution_operation_digest=intent.resolution_operation_digest,
            resolution_execution_result_digest=(
                intent.resolution_execution_result_digest
            ),
            resolution_result_digest=intent.resolution_result_digest,
            resolution_kind=intent.resolution_kind,
            verified_at=verified_at,
            expires_at=expires_at,
        )

    @property
    def intent(self) -> EffectFinalizationIntent:
        return EffectFinalizationIntent(
            database_name=self.database_name,
            database_uuid=self.database_uuid,
            operation_id=self.operation_id,
            operation_digest=self.operation_digest,
            execution_result_digest=self.execution_result_digest,
            resolution_operation_id=self.resolution_operation_id,
            resolution_operation_digest=self.resolution_operation_digest,
            resolution_execution_result_digest=(
                self.resolution_execution_result_digest
            ),
            resolution_result_digest=self.resolution_result_digest,
            resolution_kind=self.resolution_kind,
        )

    @property
    def request_digest(self) -> str:
        return _digest(self.payload())

    def payload(self) -> dict[str, Any]:
        return {
            **super().payload(),
            "expires_at": _utc_text(self.expires_at),
            "verified_at": _utc_text(self.verified_at),
        }


@dataclass(frozen=True)
class EffectFinalizationAttestation:
    attestation_id: str
    request_digest: str
    key_id: str
    attestation_digest: str

    def __post_init__(self) -> None:
        _uuid(self.attestation_id, "effect finalization attestation ID")
        _sha256(self.request_digest, "effect finalization request digest")
        _key_id(self.key_id)
        _sha256(self.attestation_digest, "effect finalization attestation digest")

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "key_id": self.key_id,
            "purpose": EFFECT_FINALIZATION_PURPOSE,
            "request_digest": self.request_digest,
            "version": EFFECT_FINALIZATION_PROTOCOL_VERSION,
        }


@dataclass(frozen=True)
class EffectFinalizationIdentity:
    attestation_key_id: str
    guard_installation_id: str
    database_oid: int

    def __post_init__(self) -> None:
        key_id = _key_id(self.attestation_key_id)
        installation_id = _uuid(
            self.guard_installation_id, "guard installation ID"
        )
        if (
            isinstance(self.database_oid, bool)
            or not isinstance(self.database_oid, int)
            or self.database_oid <= 0
        ):
            raise EffectFinalizationError("effect finalizer database OID is invalid")
        object.__setattr__(self, "attestation_key_id", key_id)
        object.__setattr__(self, "guard_installation_id", installation_id)


def create_effect_attestation(
    request: EffectFinalizationRequest,
    *,
    key_id: str,
    secret: bytes,
) -> EffectFinalizationAttestation:
    if not isinstance(request, EffectFinalizationRequest):
        raise EffectFinalizationError("effect finalization request is invalid")
    key_id = _key_id(key_id)
    secret = _secret(secret)
    attestation_id = _effect_attestation_id(
        key_id=key_id,
        request_digest=request.request_digest,
    )
    unsigned = EffectFinalizationAttestation(
        attestation_id=attestation_id,
        request_digest=request.request_digest,
        key_id=key_id,
        attestation_digest="0" * 64,
    )
    digest = hmac.new(
        secret,
        canonical_json(unsigned.unsigned_payload()),
        hashlib.sha256,
    ).hexdigest()
    return EffectFinalizationAttestation(
        attestation_id=attestation_id,
        request_digest=request.request_digest,
        key_id=key_id,
        attestation_digest=digest,
    )


def _effect_attestation_id(*, key_id: str, request_digest: str) -> str:
    return str(
        uuid.uuid5(
            _ATTESTATION_NAMESPACE,
            f"{_key_id(key_id)}:{_sha256(request_digest, 'request digest')}",
        )
    )


def verify_effect_attestation(
    attestation: EffectFinalizationAttestation,
    *,
    request: EffectFinalizationRequest,
    expected_key_id: str,
    secret: bytes,
) -> None:
    if not isinstance(attestation, EffectFinalizationAttestation) or not isinstance(
        request, EffectFinalizationRequest
    ):
        raise EffectFinalizationError("effect finalization attestation is invalid")
    expected = create_effect_attestation(
        request,
        key_id=_key_id(expected_key_id),
        secret=_secret(secret),
    )
    if (
        attestation.attestation_id != expected.attestation_id
        or attestation.request_digest != expected.request_digest
        or attestation.key_id != expected.key_id
        or not hmac.compare_digest(
            attestation.attestation_digest, expected.attestation_digest
        )
    ):
        raise EffectFinalizationError(
            "effect finalization attestation binding is invalid"
        )


@dataclass(frozen=True)
class EffectFinalizationReceipt:
    request_digest: str
    intent_digest: str
    attestation_id: str
    attestation_digest: str
    attestation_key_id: str
    guard_installation_id: str
    database_oid: int
    database_uuid: str
    operation_id: str
    resolution_operation_id: str
    resolution_kind: str
    resolved_anchor_count: int
    remaining_unresolved_count: int
    guard_epoch: int
    proof_verified_at: datetime
    proof_expires_at: datetime
    finalized_at: datetime
    finalized_txid: str
    replayed: bool

    def __post_init__(self) -> None:
        _sha256(self.request_digest, "effect finalization request digest")
        _sha256(self.intent_digest, "effect finalization intent digest")
        _uuid(self.attestation_id, "effect finalization receipt attestation ID")
        _sha256(
            self.attestation_digest,
            "effect finalization receipt attestation digest",
        )
        _key_id(self.attestation_key_id)
        _uuid(self.guard_installation_id, "guard installation ID")
        _uuid(self.database_uuid, "effect finalization receipt database UUID")
        _identifier(self.operation_id, "resolved operation_id")
        _identifier(
            self.resolution_operation_id, "receipt resolution_operation_id"
        )
        proof_verified_at = _utc(
            self.proof_verified_at, "effect finalization proof verified_at"
        )
        proof_expires_at = _utc(
            self.proof_expires_at, "effect finalization proof expires_at"
        )
        if (
            isinstance(self.database_oid, bool)
            or not isinstance(self.database_oid, int)
            or self.database_oid <= 0
            or self.resolution_kind not in {"verified", "recovered"}
            or (
                self.resolution_kind == "verified"
                and self.resolution_operation_id != self.operation_id
            )
            or (
                self.resolution_kind == "recovered"
                and self.resolution_operation_id == self.operation_id
            )
            or isinstance(self.resolved_anchor_count, bool)
            or not isinstance(self.resolved_anchor_count, int)
            or self.resolved_anchor_count
            != (1 if self.resolution_kind == "verified" else 2)
            or isinstance(self.remaining_unresolved_count, bool)
            or not isinstance(self.remaining_unresolved_count, int)
            or self.remaining_unresolved_count < 0
            or isinstance(self.guard_epoch, bool)
            or not isinstance(self.guard_epoch, int)
            or self.guard_epoch < 0
            or type(self.replayed) is not bool
            or not isinstance(self.finalized_txid, str)
            or _POSITIVE_DECIMAL.fullmatch(self.finalized_txid) is None
            or not timedelta(0)
            < proof_expires_at - proof_verified_at
            <= MAX_PROOF_TTL
        ):
            raise EffectFinalizationError(
                "effect finalization database receipt is invalid"
            )
        object.__setattr__(
            self,
            "finalized_at",
            _utc(self.finalized_at, "effect finalization finalized_at"),
        )
        object.__setattr__(self, "proof_verified_at", proof_verified_at)
        object.__setattr__(self, "proof_expires_at", proof_expires_at)

    @property
    def _stable_evidence(self) -> dict[str, Any]:
        return {
            "attestation_digest": self.attestation_digest,
            "attestation_id": self.attestation_id,
            "attestation_key_id": self.attestation_key_id,
            "database_oid": self.database_oid,
            "database_uuid": self.database_uuid,
            "finalized_at": _utc_text(self.finalized_at),
            "finalized_txid": self.finalized_txid,
            "guard_epoch": self.guard_epoch,
            "guard_installation_id": self.guard_installation_id,
            "intent_digest": self.intent_digest,
            "operation_id": self.operation_id,
            "proof_expires_at": _utc_text(self.proof_expires_at),
            "proof_verified_at": _utc_text(self.proof_verified_at),
            "protocol_version": EFFECT_FINALIZATION_PROTOCOL_VERSION,
            "remaining_unresolved_count": self.remaining_unresolved_count,
            "request_digest": self.request_digest,
            "resolution_kind": self.resolution_kind,
            "resolution_operation_id": self.resolution_operation_id,
            "resolved_anchor_count": self.resolved_anchor_count,
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self._stable_evidence)

    @property
    def evidence(self) -> dict[str, Any]:
        return {**self._stable_evidence, "receipt_digest": self.receipt_digest}

    def validate_for(self, request: EffectFinalizationRequest) -> None:
        if (
            not isinstance(request, EffectFinalizationRequest)
            or self.request_digest != request.request_digest
            or self.intent_digest != request.intent.intent_digest
            or self.database_uuid != request.database_uuid
            or self.operation_id != request.operation_id
            or self.resolution_operation_id != request.resolution_operation_id
            or self.resolution_kind != request.resolution_kind
        ):
            raise EffectFinalizationError(
                "effect finalization receipt binding is invalid"
            )

    def validate_for_intent(self, intent: EffectFinalizationIntent) -> None:
        if type(intent) is not EffectFinalizationIntent:
            raise EffectFinalizationError("effect finalization intent is invalid")
        self.validate_for(
            EffectFinalizationRequest.from_intent(
                intent,
                verified_at=self.proof_verified_at,
                expires_at=self.proof_expires_at,
            )
        )

    @classmethod
    def from_database_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        request: EffectFinalizationRequest,
        attestation: EffectFinalizationAttestation,
    ) -> "EffectFinalizationReceipt":
        if (
            not isinstance(value, Mapping)
            or set(value) != _DATABASE_RECEIPT_FIELDS
            or not isinstance(request, EffectFinalizationRequest)
            or not isinstance(attestation, EffectFinalizationAttestation)
        ):
            raise EffectFinalizationError(
                "effect finalization database receipt fields are invalid"
            )
        try:
            receipt = cls(
                request_digest=attestation.request_digest,
                intent_digest=request.intent.intent_digest,
                attestation_id=_database_uuid(
                    value["receipt_attestation_id"],
                    "database receipt attestation ID",
                ),
                attestation_digest=_sha256(
                    value["receipt_attestation_digest"],
                    "database receipt attestation digest",
                ),
                attestation_key_id=attestation.key_id,
                guard_installation_id=_database_uuid(
                    value["receipt_guard_installation_id"],
                    "database receipt guard installation ID",
                ),
                database_oid=value["receipt_database_oid"],
                database_uuid=_database_uuid(
                    value["receipt_database_uuid"],
                    "database receipt database UUID",
                ),
                operation_id=value["resolved_operation_id"],
                resolution_operation_id=value[
                    "receipt_resolution_operation_id"
                ],
                resolution_kind=value["applied_resolution_kind"],
                resolved_anchor_count=value["resolved_anchor_count"],
                remaining_unresolved_count=value[
                    "remaining_unresolved_count"
                ],
                guard_epoch=value["guard_epoch"],
                proof_verified_at=request.verified_at,
                proof_expires_at=request.expires_at,
                finalized_at=_timestamp(
                    value["finalized_at"], "database receipt finalized_at"
                ),
                finalized_txid=value["finalized_txid"],
                replayed=value["replayed"],
            )
        except (KeyError, TypeError) as exc:
            raise EffectFinalizationError(
                "effect finalization database receipt is invalid"
            ) from exc
        if (
            receipt.attestation_id != attestation.attestation_id
            or not hmac.compare_digest(
                receipt.attestation_digest, attestation.attestation_digest
            )
        ):
            raise EffectFinalizationError(
                "effect finalization receipt proof is invalid"
            )
        receipt.validate_for(request)
        return receipt


def _receipt_from_evidence_shape(value: Any) -> EffectFinalizationReceipt:
    if not isinstance(value, Mapping) or set(value) != _EVIDENCE_FIELDS:
        raise EffectFinalizationError("effect finalization receipt evidence is invalid")
    try:
        if (
            type(value["protocol_version"]) is not int
            or value["protocol_version"] != EFFECT_FINALIZATION_PROTOCOL_VERSION
        ):
            raise EffectFinalizationError("receipt protocol is invalid")
        receipt = EffectFinalizationReceipt(
            request_digest=value["request_digest"],
            intent_digest=value["intent_digest"],
            attestation_id=value["attestation_id"],
            attestation_digest=value["attestation_digest"],
            attestation_key_id=value["attestation_key_id"],
            guard_installation_id=value["guard_installation_id"],
            database_oid=value["database_oid"],
            database_uuid=value["database_uuid"],
            operation_id=value["operation_id"],
            resolution_operation_id=value["resolution_operation_id"],
            resolution_kind=value["resolution_kind"],
            resolved_anchor_count=value["resolved_anchor_count"],
            remaining_unresolved_count=value["remaining_unresolved_count"],
            guard_epoch=value["guard_epoch"],
            proof_verified_at=_timestamp(
                value["proof_verified_at"], "receipt evidence proof verified_at"
            ),
            proof_expires_at=_timestamp(
                value["proof_expires_at"], "receipt evidence proof expires_at"
            ),
            finalized_at=_timestamp(
                value["finalized_at"], "receipt evidence finalized_at"
            ),
            finalized_txid=value["finalized_txid"],
            replayed=False,
        )
        expected_attestation_id = _effect_attestation_id(
            key_id=receipt.attestation_key_id,
            request_digest=receipt.request_digest,
        )
    except (EffectFinalizationError, KeyError, TypeError) as exc:
        raise EffectFinalizationError(
            "effect finalization receipt evidence is invalid"
        ) from exc
    if (
        receipt.attestation_id != expected_attestation_id
        or receipt.evidence != dict(value)
    ):
        raise EffectFinalizationError("effect finalization receipt evidence is invalid")
    return receipt


def validate_effect_finalization_evidence_shape(value: Any) -> dict[str, Any]:
    """Validate canonical receipt fields before business bindings are available."""

    _receipt_from_evidence_shape(value)
    return dict(value)


def validate_effect_finalization_evidence(
    value: Any,
    *,
    intent: EffectFinalizationIntent,
    expected_attestation_key_id: str,
    expected_guard_installation_id: str,
    expected_database_oid: int,
) -> dict[str, Any]:
    """Rebuild and validate the exact receipt embedded in durable audit state."""

    if type(intent) is not EffectFinalizationIntent:
        raise EffectFinalizationError("effect finalization receipt evidence is invalid")
    try:
        receipt = _receipt_from_evidence_shape(value)
        key_id = _key_id(expected_attestation_key_id)
        installation_id = _uuid(
            expected_guard_installation_id,
            "expected guard installation ID",
        )
        if (
            isinstance(expected_database_oid, bool)
            or not isinstance(expected_database_oid, int)
            or expected_database_oid <= 0
        ):
            raise EffectFinalizationError("expected finalizer identity is invalid")
        request = EffectFinalizationRequest.from_intent(
            intent,
            verified_at=receipt.proof_verified_at,
            expires_at=receipt.proof_expires_at,
        )
        receipt.validate_for(request)
    except EffectFinalizationError as exc:
        raise EffectFinalizationError(
            "effect finalization receipt evidence is invalid"
        ) from exc
    if (
        receipt.attestation_key_id != key_id
        or receipt.guard_installation_id != installation_id
        or receipt.database_oid != expected_database_oid
    ):
        raise EffectFinalizationError("effect finalization receipt evidence is invalid")
    return dict(value)


__all__ = [
    "EFFECT_FINALIZATION_PROTOCOL_VERSION",
    "EFFECT_FINALIZATION_PURPOSE",
    "EffectFinalizationAttestation",
    "EffectFinalizationError",
    "EffectFinalizationIdentity",
    "EffectFinalizationIntent",
    "EffectFinalizationReceipt",
    "EffectFinalizationRequest",
    "create_effect_attestation",
    "trusted_result_envelope_digest",
    "validate_effect_finalization_evidence",
    "validate_effect_finalization_evidence_shape",
    "verify_effect_attestation",
]

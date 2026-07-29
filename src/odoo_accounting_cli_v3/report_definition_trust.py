"""Pure in-memory validation for externally verified report-definition trust.

The envelope is the output of a separate privileged signature verifier.  This
module does not read trust files or execute verification tools; it only accepts
one exact, short-lived, canonical result that is bound to the running release
and database.  ``MAX_TRUST_ENVELOPE_BYTES`` is an input parsing bound, not an
approval to increase any parent sealed-payload limit.  Parent limits must be
set independently from measured target artifacts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .report_definition_baseline import (
    ReportDefinitionBaselineError,
    ReportDefinitionCatalog,
    ReportDefinitionEntry,
    load_catalog_bytes,
    select_entry as select_catalog_entry,
)


TRUST_ENVELOPE_SCHEMA_VERSION = 1
TRUST_ENVELOPE_DOCUMENT_TYPE = (
    "odoo-accounting-cli-v3.report-definition-trust-envelope.v1"
)
SIGNATURE_NAMESPACE = (
    "odoo-accounting-cli-v3.report-definition-approval.v1"
)
MAX_TRUST_ENVELOPE_BYTES = 8 * 1024 * 1024
MAX_CATALOG_JSON_BYTES = 7 * 1024 * 1024
MAX_TRUST_ENVELOPE_TTL = timedelta(minutes=5)
MAX_CATALOG_ENTRIES = 1024
MAX_APPROVAL_VERIFICATIONS = 4096

FIXED_REPORT_IDENTITIES = frozenset(
    {
        ("tax", "generic_tax", "account.generic_tax_report"),
        (
            "financial",
            "balance_sheet",
            "account_reports.balance_sheet",
        ),
        (
            "financial",
            "cash_flow",
            "account_reports.cash_flow_report",
        ),
        (
            "financial",
            "profit_and_loss",
            "account_reports.profit_and_loss",
        ),
    }
)

_ENVELOPE_KEYS = frozenset(
    {
        "approvals",
        "catalog_json",
        "document_type",
        "not_after",
        "runtime_binding",
        "schema_version",
        "trust_index_sha256",
        "verification",
        "verified_at",
    }
)
_RUNTIME_BINDING_KEYS = frozenset({"database_uuid", "release_digest"})
_APPROVAL_KEYS = frozenset(
    {
        "approval_artifact_sha256",
        "approved_at",
        "approver_id",
        "company_id",
        "database_uuid",
        "expires_at",
        "family",
        "kind",
        "role",
        "root_xmlid",
        "signature_sha256",
        "signing_key_id",
        "verified",
    }
)
_VERIFICATION_KEYS = frozenset(
    {
        "all_artifact_digests_valid",
        "all_signatures_valid",
        "no_key_or_approval_revoked",
        "production_promotion_allowed",
        "signature_namespace",
        "ssh_keygen_sha256",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_XMLID_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$"
)
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FAMILIES_AND_KINDS = {
    family: frozenset(
        kind
        for candidate_family, kind, _root_xmlid in FIXED_REPORT_IDENTITIES
        if candidate_family == family
    )
    for family, _kind, _root_xmlid in FIXED_REPORT_IDENTITIES
}


class ReportDefinitionTrustError(ValueError):
    """A verified trust envelope failed closed validation."""


@dataclass(frozen=True)
class RuntimeBinding:
    release_digest: str
    database_uuid: str


@dataclass(frozen=True)
class ApprovalVerification:
    database_uuid: str
    company_id: int
    family: str
    kind: str
    root_xmlid: str
    role: str
    approver_id: str
    signing_key_id: str
    approval_artifact_sha256: str
    signature_sha256: str
    approved_at: datetime
    expires_at: datetime
    verified: bool = True


@dataclass(frozen=True)
class VerificationClaims:
    signature_namespace: str
    ssh_keygen_sha256: str
    all_signatures_valid: bool
    all_artifact_digests_valid: bool
    no_key_or_approval_revoked: bool
    production_promotion_allowed: bool


@dataclass(frozen=True)
class VerifiedReportDefinitionTrustEnvelope:
    envelope_sha256: str
    verified_at: datetime
    not_after: datetime
    runtime_binding: RuntimeBinding
    trust_index_sha256: str
    catalog_json: bytes
    catalog: ReportDefinitionCatalog
    approvals: tuple[ApprovalVerification, ...]
    verification: VerificationClaims

    def select_entry(
        self,
        *,
        company_id: int,
        family: str,
        kind: str,
        root_xmlid: str,
        now: datetime,
    ) -> ReportDefinitionEntry:
        """Select one entry while rechecking the short-lived envelope."""

        current_time = _now(now)
        _ensure_envelope_active(
            verified_at=self.verified_at,
            not_after=self.not_after,
            now=current_time,
        )
        try:
            return select_catalog_entry(
                self.catalog,
                database_uuid=self.runtime_binding.database_uuid,
                company_id=company_id,
                family=family,
                kind=kind,
                root_xmlid=root_xmlid,
                now=current_time,
            )
        except ReportDefinitionBaselineError as exc:
            raise _error("report definition selection was rejected") from exc


def _error(message: str) -> ReportDefinitionTrustError:
    return ReportDefinitionTrustError(message)


def _strict_object(
    value: Any,
    expected: frozenset[str],
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(f"{field} must be an object")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise _error(f"{field} fields differ: missing={missing}, extra={extra}")
    return value


def _text(value: Any, field: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise _error(f"{field} must be a canonical non-empty string")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _error(f"{field} must be a lowercase SHA-256 digest")
    return value


def _database_uuid(value: Any, field: str) -> str:
    text = _text(value, field, maximum=36)
    try:
        parsed = uuid.UUID(text)
    except (AttributeError, ValueError) as exc:
        raise _error(f"{field} must be a canonical UUID") from exc
    if str(parsed) != text:
        raise _error(f"{field} must be a canonical UUID")
    return text


def _company_id(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > 2**63 - 1
    ):
        raise _error(f"{field} must be a positive 64-bit integer")
    return value


def _family_kind(family_value: Any, kind_value: Any) -> tuple[str, str]:
    family = _text(family_value, "approval.family")
    kind = _text(kind_value, "approval.kind")
    if family not in _FAMILIES_AND_KINDS:
        raise _error("approval family/kind is not a fixed report identity")
    if kind not in _FAMILIES_AND_KINDS[family]:
        raise _error("approval family/kind is not a fixed report identity")
    return family, kind


def _root_xmlid(value: Any) -> str:
    text = _text(value, "approval.root_xmlid")
    if _XMLID_RE.fullmatch(text) is None:
        raise _error("approval.root_xmlid must be a canonical external XML ID")
    return text


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise _error(f"{field} must use canonical UTC second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise _error(f"{field} is not a valid timestamp") from exc


def _now(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _error("now must be a timezone-aware datetime")
    if value.utcoffset() is None:
        raise _error("now must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise _error(f"non-finite JSON number is forbidden: {value}")


def _ensure_envelope_active(
    *,
    verified_at: datetime,
    not_after: datetime,
    now: datetime,
) -> None:
    if not (
        verified_at <= now < not_after
        and verified_at < not_after
        and not_after - verified_at <= MAX_TRUST_ENVELOPE_TTL
    ):
        raise _error("verified trust envelope is not active")


def _expected_approvals(
    catalog: ReportDefinitionCatalog,
) -> tuple[tuple[Any, ...], ...]:
    expected: list[tuple[Any, ...]] = []
    for entry in catalog.entries:
        for approval in entry.approvals:
            expected.append(
                (
                    entry.database_uuid,
                    entry.company_id,
                    entry.family,
                    entry.kind,
                    entry.root_xmlid,
                    approval.role,
                    approval.approver_id,
                    approval.signing_key_id,
                    approval.approval_artifact_sha256,
                    approval.approved_at,
                    approval.expires_at,
                )
            )
    return tuple(expected)


def _approval_verifications(
    value: Any,
    *,
    catalog: ReportDefinitionCatalog,
) -> tuple[ApprovalVerification, ...]:
    if not isinstance(value, list):
        raise _error("approvals must be an array")
    if len(value) > MAX_APPROVAL_VERIFICATIONS:
        raise _error("approvals exceed the verification-record limit")
    expected = _expected_approvals(catalog)
    if len(expected) > MAX_APPROVAL_VERIFICATIONS:
        raise _error("catalog approvals exceed the verification-record limit")
    if len(value) != len(expected):
        raise _error("approvals do not exactly cover the catalog approvals")

    result: list[ApprovalVerification] = []
    signatures: set[str] = set()
    for index, (candidate, catalog_approval) in enumerate(
        zip(value, expected, strict=True)
    ):
        document = _strict_object(
            candidate,
            _APPROVAL_KEYS,
            f"approvals[{index}]",
        )
        database_uuid = _database_uuid(
            document["database_uuid"],
            f"approvals[{index}].database_uuid",
        )
        company_id = _company_id(
            document["company_id"],
            f"approvals[{index}].company_id",
        )
        family, kind = _family_kind(document["family"], document["kind"])
        root_xmlid = _root_xmlid(document["root_xmlid"])
        role = _text(document["role"], f"approvals[{index}].role")
        approver_id = _text(
            document["approver_id"],
            f"approvals[{index}].approver_id",
        )
        signing_key_id = _text(
            document["signing_key_id"],
            f"approvals[{index}].signing_key_id",
        )
        approval_artifact_sha256 = _sha256(
            document["approval_artifact_sha256"],
            f"approvals[{index}].approval_artifact_sha256",
        )
        approved_at = _timestamp(
            document["approved_at"],
            f"approvals[{index}].approved_at",
        )
        expires_at = _timestamp(
            document["expires_at"],
            f"approvals[{index}].expires_at",
        )
        if document["verified"] is not True:
            raise _error(f"approvals[{index}].verified must be true")
        actual = (
            database_uuid,
            company_id,
            family,
            kind,
            root_xmlid,
            role,
            approver_id,
            signing_key_id,
            approval_artifact_sha256,
            approved_at,
            expires_at,
        )
        if actual != catalog_approval:
            raise _error(
                "approvals do not exactly match the catalog approval order"
            )
        signature_sha256 = _sha256(
            document["signature_sha256"],
            f"approvals[{index}].signature_sha256",
        )
        if signature_sha256 in signatures:
            raise _error("approvals reuse a detached signature")
        signatures.add(signature_sha256)
        result.append(
            ApprovalVerification(
                database_uuid=database_uuid,
                company_id=company_id,
                family=family,
                kind=kind,
                root_xmlid=root_xmlid,
                role=role,
                approver_id=approver_id,
                signing_key_id=signing_key_id,
                approval_artifact_sha256=approval_artifact_sha256,
                signature_sha256=signature_sha256,
                approved_at=approved_at,
                expires_at=expires_at,
            )
        )
    return tuple(result)


def _validate_catalog_scope(
    catalog: ReportDefinitionCatalog,
    *,
    expected_database_uuid: str,
) -> None:
    if not catalog.entries or len(catalog.entries) > MAX_CATALOG_ENTRIES:
        raise _error("catalog entry count is outside the trust-envelope limit")
    companies: dict[int, set[tuple[str, str, str]]] = {}
    for entry in catalog.entries:
        if entry.database_uuid != expected_database_uuid:
            raise _error("catalog database UUID differs from the runtime binding")
        companies.setdefault(entry.company_id, set()).add(
            (entry.family, entry.kind, entry.root_xmlid)
        )
    for identities in companies.values():
        if identities != FIXED_REPORT_IDENTITIES:
            raise _error(
                "each catalog company must contain exactly four fixed reports"
            )
    if len(catalog.entries) != len(companies) * len(FIXED_REPORT_IDENTITIES):
        raise _error(
            "each catalog company must contain exactly four fixed reports"
        )


def _verification_claims(value: Any) -> VerificationClaims:
    document = _strict_object(value, _VERIFICATION_KEYS, "verification")
    if document["signature_namespace"] != SIGNATURE_NAMESPACE:
        raise _error("verification.signature_namespace is unsupported")
    for field in (
        "all_signatures_valid",
        "all_artifact_digests_valid",
        "no_key_or_approval_revoked",
    ):
        if document[field] is not True:
            raise _error(f"verification.{field} must be true")
    if document["production_promotion_allowed"] is not False:
        raise _error(
            "verified trust envelope cannot authorize production promotion"
        )
    return VerificationClaims(
        signature_namespace=SIGNATURE_NAMESPACE,
        ssh_keygen_sha256=_sha256(
            document["ssh_keygen_sha256"],
            "verification.ssh_keygen_sha256",
        ),
        all_signatures_valid=True,
        all_artifact_digests_valid=True,
        no_key_or_approval_revoked=True,
        production_promotion_allowed=False,
    )


def load_verified_trust_envelope_bytes(
    payload: bytes,
    *,
    expected_sha256: str,
    expected_release_digest: str,
    expected_database_uuid: str,
    now: datetime,
) -> VerifiedReportDefinitionTrustEnvelope:
    """Load one exact externally verified envelope without performing I/O."""

    if not isinstance(payload, bytes) or not payload:
        raise _error("trust envelope payload must be non-empty bytes")
    if len(payload) > MAX_TRUST_ENVELOPE_BYTES:
        raise _error("trust envelope payload exceeds the maximum size")
    expected_envelope_sha256 = _sha256(expected_sha256, "expected_sha256")
    release_digest = _sha256(
        expected_release_digest,
        "expected_release_digest",
    )
    database_uuid = _database_uuid(
        expected_database_uuid,
        "expected_database_uuid",
    )
    envelope_sha256 = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(envelope_sha256, expected_envelope_sha256):
        raise _error("trust envelope payload digest differs")
    current_time = _now(now)

    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except ReportDefinitionTrustError:
        raise
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise _error("trust envelope payload is not strict UTF-8 JSON") from exc
    try:
        canonical_payload = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeError) as exc:
        raise _error("trust envelope payload is not canonical JSON") from exc
    if canonical_payload != payload:
        raise _error("trust envelope payload is not canonical JSON")

    envelope = _strict_object(document, _ENVELOPE_KEYS, "envelope")
    if envelope["schema_version"] != TRUST_ENVELOPE_SCHEMA_VERSION:
        raise _error("trust envelope schema_version is unsupported")
    if envelope["document_type"] != TRUST_ENVELOPE_DOCUMENT_TYPE:
        raise _error("trust envelope document_type is unsupported")
    verified_at = _timestamp(envelope["verified_at"], "verified_at")
    not_after = _timestamp(envelope["not_after"], "not_after")
    _ensure_envelope_active(
        verified_at=verified_at,
        not_after=not_after,
        now=current_time,
    )

    runtime_document = _strict_object(
        envelope["runtime_binding"],
        _RUNTIME_BINDING_KEYS,
        "runtime_binding",
    )
    runtime_release_digest = _sha256(
        runtime_document["release_digest"],
        "runtime_binding.release_digest",
    )
    runtime_database_uuid = _database_uuid(
        runtime_document["database_uuid"],
        "runtime_binding.database_uuid",
    )
    if not hmac.compare_digest(runtime_release_digest, release_digest):
        raise _error("runtime release digest differs from the expected release")
    if not hmac.compare_digest(runtime_database_uuid, database_uuid):
        raise _error("runtime database UUID differs from the expected database")

    catalog_json_value = envelope["catalog_json"]
    if not isinstance(catalog_json_value, str) or not catalog_json_value:
        raise _error("catalog_json must be a non-empty JSON string")
    try:
        catalog_json = catalog_json_value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _error("catalog_json is not UTF-8 encodable") from exc
    if len(catalog_json) > MAX_CATALOG_JSON_BYTES:
        raise _error("catalog_json exceeds the maximum size")
    try:
        catalog = load_catalog_bytes(catalog_json, now=current_time)
    except ReportDefinitionBaselineError as exc:
        raise _error("catalog_json failed baseline validation") from exc
    _validate_catalog_scope(
        catalog,
        expected_database_uuid=database_uuid,
    )

    approvals = _approval_verifications(
        envelope["approvals"],
        catalog=catalog,
    )
    verification = _verification_claims(envelope["verification"])
    for entry in catalog.entries:
        if verified_at < entry.valid_from or not_after > entry.expires_at:
            raise _error("envelope validity is outside a catalog entry")
        for approval in entry.approvals:
            if (
                verified_at < approval.approved_at
                or not_after > approval.expires_at
            ):
                raise _error("envelope validity is outside a catalog approval")

    return VerifiedReportDefinitionTrustEnvelope(
        envelope_sha256=envelope_sha256,
        verified_at=verified_at,
        not_after=not_after,
        runtime_binding=RuntimeBinding(
            release_digest=release_digest,
            database_uuid=database_uuid,
        ),
        trust_index_sha256=_sha256(
            envelope["trust_index_sha256"],
            "trust_index_sha256",
        ),
        catalog_json=catalog_json,
        catalog=catalog,
        approvals=approvals,
        verification=verification,
    )

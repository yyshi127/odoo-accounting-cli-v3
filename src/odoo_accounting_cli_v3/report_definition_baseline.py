"""Strict, release-candidate-bound approval baseline for report definitions.

This module deliberately does not read Odoo or verify approval signatures.  It
accepts only a canonical catalog whose approval records are already bound to
external allowed-signers and revocation artifacts.  The caller must verify
those external artifacts before trusting the resulting binding digest.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .operations import canonical_json
from .report_definition_projection import (
    PROJECTION_SCHEMA_VERSION,
    ReportDefinitionProjectionError,
    validate_root_definition_projection,
)


CATALOG_SCHEMA = (
    "odoo-accounting-cli-v3.report-definition-baseline-catalog.v1"
)
DEFINITION_SCHEMA = PROJECTION_SCHEMA_VERSION
BINDING_SCHEMA = "odoo-accounting-cli-v3.report-definition-binding.v1"

_CATALOG_KEYS = frozenset(
    {"schema_version", "production_promotion_allowed", "entries"}
)
_ENTRY_KEYS = frozenset(
    {
        "allowed_signers",
        "approvals",
        "candidate_artifact_sha256",
        "company_id",
        "database_uuid",
        "definition",
        "definition_sha256",
        "expires_at",
        "family",
        "kind",
        "oracle_contract",
        "revocations",
        "root_xmlid",
        "valid_from",
    }
)
_EXTERNAL_BINDING_KEYS = frozenset({"artifact_id", "sha256"})
_APPROVAL_KEYS = frozenset(
    {
        "allowed_signers_artifact_id",
        "allowed_signers_sha256",
        "approval_artifact_sha256",
        "approved_at",
        "approver_id",
        "candidate_artifact_sha256",
        "company_id",
        "database_uuid",
        "definition_sha256",
        "expires_at",
        "family",
        "kind",
        "oracle_contract_artifact_id",
        "oracle_contract_sha256",
        "revocations_artifact_id",
        "revocations_sha256",
        "role",
        "root_xmlid",
        "signing_key_id",
        "valid_from",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_XMLID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_KNOWN_ROLES = frozenset({"accounting", "tax", "technical"})
_KINDS_BY_FAMILY = {
    "financial": frozenset({"balance_sheet", "cash_flow", "profit_and_loss"}),
    "tax": frozenset({"generic_tax"}),
}


class ReportDefinitionBaselineError(ValueError):
    """The catalog or an observed definition failed closed validation."""


@dataclass(frozen=True)
class ExternalArtifactBinding:
    artifact_id: str
    sha256: str


@dataclass(frozen=True)
class ApprovalRecord:
    role: str
    approver_id: str
    signing_key_id: str
    approved_at: datetime
    expires_at: datetime
    approval_artifact_sha256: str


@dataclass(frozen=True)
class ReportDefinitionEntry:
    catalog_sha256: str
    entry_sha256: str
    approval_set_sha256: str
    database_uuid: str
    company_id: int
    family: str
    kind: str
    root_xmlid: str
    valid_from: datetime
    expires_at: datetime
    definition_sha256: str
    definition_json: bytes
    candidate_artifact_sha256: str
    allowed_signers: ExternalArtifactBinding
    revocations: ExternalArtifactBinding
    oracle_contract: ExternalArtifactBinding
    approvals: tuple[ApprovalRecord, ...]

    @property
    def definition(self) -> dict[str, Any]:
        """Return a detached definition so validated state cannot be mutated."""

        value = json.loads(self.definition_json)
        if not isinstance(value, dict):  # Defensive; load validation guarantees it.
            raise ReportDefinitionBaselineError("stored definition is invalid")
        return value

    @property
    def identity(self) -> tuple[str, int, str, str, str]:
        return (
            self.database_uuid,
            self.company_id,
            self.family,
            self.kind,
            self.root_xmlid,
        )


@dataclass(frozen=True)
class ReportDefinitionCatalog:
    catalog_sha256: str
    entries: tuple[ReportDefinitionEntry, ...]
    production_promotion_allowed: bool = False


def _error(message: str) -> ReportDefinitionBaselineError:
    return ReportDefinitionBaselineError(message)


def _strict_object(value: Any, expected: frozenset[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _error(f"{field} must be an object")
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise _error(f"{field} fields differ: missing={missing}, extra={extra}")
    return value


def _text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 512
        or any(ord(character) < 0x20 for character in value)
    ):
        raise _error(f"{field} must be a non-empty canonical identifier")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise _error(f"{field} must be a lowercase SHA-256 digest")
    return value


def _company_id(value: Any, field: str = "company_id") -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
        or value > 2**63 - 1
    ):
        raise _error(f"{field} must be a positive 64-bit integer")
    return value


def _database_uuid(value: Any, field: str = "database_uuid") -> str:
    text = _text(value, field)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise _error(f"{field} must be a canonical UUID") from exc
    if str(parsed) != text:
        raise _error(f"{field} must be a canonical UUID")
    return text


def _family_kind(family_value: Any, kind_value: Any) -> tuple[str, str]:
    family = _text(family_value, "family")
    kind = _text(kind_value, "kind")
    if family not in _KINDS_BY_FAMILY or kind not in _KINDS_BY_FAMILY[family]:
        raise _error("family/kind is outside the catalog v1 report set")
    return family, kind


def _root_xmlid(value: Any, field: str = "root_xmlid") -> str:
    text = _text(value, field)
    if _XMLID_RE.fullmatch(text) is None:
        raise _error(f"{field} must be a canonical external XML ID")
    return text


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise _error(f"{field} must use canonical UTC second precision")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise _error(f"{field} is not a valid timestamp") from exc
    return parsed


def _now(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise _error("now must be a timezone-aware datetime")
    offset = value.utcoffset()
    if offset is None:
        raise _error("now must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _identity(
    value: dict[str, Any],
    *,
    prefix: str = "",
) -> tuple[str, int, str, str, str]:
    database_uuid = _database_uuid(value.get("database_uuid"), f"{prefix}database_uuid")
    company_id = _company_id(value.get("company_id"), f"{prefix}company_id")
    family, kind = _family_kind(value.get("family"), value.get("kind"))
    root_xmlid = _root_xmlid(value.get("root_xmlid"), f"{prefix}root_xmlid")
    return database_uuid, company_id, family, kind, root_xmlid


def _external_binding(value: Any, field: str) -> ExternalArtifactBinding:
    document = _strict_object(value, _EXTERNAL_BINDING_KEYS, field)
    return ExternalArtifactBinding(
        artifact_id=_text(document["artifact_id"], f"{field}.artifact_id"),
        sha256=_sha256(document["sha256"], f"{field}.sha256"),
    )


def _ensure_active(entry: ReportDefinitionEntry, now: datetime) -> None:
    if not (entry.valid_from <= now < entry.expires_at):
        raise _error("report definition entry is not currently valid")
    for approval in entry.approvals:
        if not (approval.approved_at <= now < approval.expires_at):
            raise _error(f"{approval.role} approval is not currently valid")


def _approval(
    value: Any,
    *,
    entry_identity: tuple[str, int, str, str, str],
    entry_valid_from: datetime,
    entry_expires_at: datetime,
    definition_sha256: str,
    candidate_artifact_sha256: str,
    allowed_signers: ExternalArtifactBinding,
    revocations: ExternalArtifactBinding,
    oracle_contract: ExternalArtifactBinding,
) -> ApprovalRecord:
    document = _strict_object(value, _APPROVAL_KEYS, "approval")
    role = _text(document["role"], "approval.role")
    if role not in _KNOWN_ROLES:
        raise _error("approval.role is not recognized")

    embedded_identity = _identity(document, prefix="approval.")
    if embedded_identity != entry_identity:
        raise _error("approval identity does not match its report definition entry")

    exact_bindings = {
        "allowed_signers_artifact_id": allowed_signers.artifact_id,
        "allowed_signers_sha256": allowed_signers.sha256,
        "candidate_artifact_sha256": candidate_artifact_sha256,
        "definition_sha256": definition_sha256,
        "oracle_contract_artifact_id": oracle_contract.artifact_id,
        "oracle_contract_sha256": oracle_contract.sha256,
        "revocations_artifact_id": revocations.artifact_id,
        "revocations_sha256": revocations.sha256,
    }
    for field, expected in exact_bindings.items():
        actual = document[field]
        if field.endswith("_sha256"):
            actual = _sha256(actual, f"approval.{field}")
        else:
            actual = _text(actual, f"approval.{field}")
        if actual != expected:
            raise _error(f"approval.{field} does not match its entry")

    approved_at = _timestamp(document["approved_at"], "approval.approved_at")
    approval_valid_from = _timestamp(
        document["valid_from"], "approval.valid_from"
    )
    expires_at = _timestamp(document["expires_at"], "approval.expires_at")
    if approval_valid_from != entry_valid_from:
        raise _error("approval.valid_from does not match its entry")
    if approved_at > entry_valid_from:
        raise _error("approval was issued after the entry became valid")
    if not (entry_valid_from < expires_at <= entry_expires_at):
        raise _error("approval validity is outside the entry validity")

    return ApprovalRecord(
        role=role,
        approver_id=_text(document["approver_id"], "approval.approver_id"),
        signing_key_id=_text(document["signing_key_id"], "approval.signing_key_id"),
        approved_at=approved_at,
        expires_at=expires_at,
        approval_artifact_sha256=_sha256(
            document["approval_artifact_sha256"],
            "approval.approval_artifact_sha256",
        ),
    )


def _entry(
    value: Any,
    *,
    catalog_sha256: str,
    now: datetime,
) -> ReportDefinitionEntry:
    document = _strict_object(value, _ENTRY_KEYS, "entry")
    identity = _identity(document)
    database_uuid, company_id, family, kind, root_xmlid = identity
    valid_from = _timestamp(document["valid_from"], "entry.valid_from")
    expires_at = _timestamp(document["expires_at"], "entry.expires_at")
    if valid_from >= expires_at:
        raise _error("entry validity interval is empty")

    definition = document["definition"]
    if not isinstance(definition, dict):
        raise _error("entry.definition must be an object")
    try:
        validate_root_definition_projection(definition)
    except ReportDefinitionProjectionError as exc:
        raise _error("entry.definition is not a valid root projection") from exc
    definition_identity = definition.get("baseline_identity")
    if (
        not isinstance(definition_identity, dict)
        or _identity(definition_identity, prefix="definition.") != identity
    ):
        raise _error("entry.definition identity does not match its entry")
    definition_json = canonical_json(definition)
    definition_sha256 = _sha256(
        document["definition_sha256"], "entry.definition_sha256"
    )
    if hashlib.sha256(definition_json).hexdigest() != definition_sha256:
        raise _error("entry.definition_sha256 does not match the full definition")

    candidate_artifact_sha256 = _sha256(
        document["candidate_artifact_sha256"],
        "entry.candidate_artifact_sha256",
    )
    allowed_signers = _external_binding(document["allowed_signers"], "allowed_signers")
    revocations = _external_binding(document["revocations"], "revocations")
    oracle_contract = _external_binding(
        document["oracle_contract"], "oracle_contract"
    )
    if len(
        {
            allowed_signers.artifact_id,
            revocations.artifact_id,
            oracle_contract.artifact_id,
        }
    ) != 3:
        raise _error(
            "allowed-signers, revocations, and oracle contract must be "
            "distinct artifacts"
        )

    approvals_value = document["approvals"]
    if not isinstance(approvals_value, list) or not approvals_value:
        raise _error("entry.approvals must be a non-empty array")
    approvals = tuple(
        _approval(
            item,
            entry_identity=identity,
            entry_valid_from=valid_from,
            entry_expires_at=expires_at,
            definition_sha256=definition_sha256,
            candidate_artifact_sha256=candidate_artifact_sha256,
            allowed_signers=allowed_signers,
            revocations=revocations,
            oracle_contract=oracle_contract,
        )
        for item in approvals_value
    )
    approval_order = [
        (item.role, item.approver_id, item.signing_key_id) for item in approvals
    ]
    if approval_order != sorted(approval_order):
        raise _error("entry.approvals are not canonically ordered")
    roles = [item.role for item in approvals]
    if len(roles) != len(set(roles)):
        raise _error("entry.approvals contain a duplicate role")
    required_roles = {"accounting", "technical"}
    if family == "tax":
        required_roles.add("tax")
    if not required_roles.issubset(roles):
        raise _error("entry.approvals do not contain all required roles")
    approvers = [item.approver_id for item in approvals]
    signing_keys = [item.signing_key_id for item in approvals]
    approval_artifacts = [item.approval_artifact_sha256 for item in approvals]
    if len(approvers) != len(set(approvers)):
        raise _error("entry.approvals are not independent by approver")
    if len(signing_keys) != len(set(signing_keys)):
        raise _error("entry.approvals are not independent by signing key")
    if len(approval_artifacts) != len(set(approval_artifacts)):
        raise _error("entry.approvals reuse an approval artifact")

    result = ReportDefinitionEntry(
        catalog_sha256=catalog_sha256,
        entry_sha256=hashlib.sha256(canonical_json(document)).hexdigest(),
        approval_set_sha256=hashlib.sha256(
            canonical_json(approvals_value)
        ).hexdigest(),
        database_uuid=database_uuid,
        company_id=company_id,
        family=family,
        kind=kind,
        root_xmlid=root_xmlid,
        valid_from=valid_from,
        expires_at=expires_at,
        definition_sha256=definition_sha256,
        definition_json=definition_json,
        candidate_artifact_sha256=candidate_artifact_sha256,
        allowed_signers=allowed_signers,
        revocations=revocations,
        oracle_contract=oracle_contract,
        approvals=approvals,
    )
    _ensure_active(result, now)
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _error(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise _error(f"non-finite JSON number is forbidden: {value}")


def load_catalog_bytes(
    payload: bytes,
    *,
    now: datetime,
) -> ReportDefinitionCatalog:
    """Load and fully validate one canonical catalog at an explicit time."""

    if not isinstance(payload, bytes) or not payload:
        raise _error("catalog payload must be non-empty bytes")
    current_time = _now(now)
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _error("catalog payload is not strict UTF-8 JSON") from exc
    if canonical_json(document) != payload:
        raise _error("catalog payload is not canonical JSON")

    catalog = _strict_object(document, _CATALOG_KEYS, "catalog")
    if catalog["schema_version"] != CATALOG_SCHEMA:
        raise _error("catalog schema_version is unsupported")
    if catalog["production_promotion_allowed"] is not False:
        raise _error("baseline artifact cannot authorize production promotion")
    entries_value = catalog["entries"]
    if not isinstance(entries_value, list) or not entries_value:
        raise _error("catalog.entries must be a non-empty array")

    catalog_sha256 = hashlib.sha256(payload).hexdigest()
    entries = tuple(
        _entry(item, catalog_sha256=catalog_sha256, now=current_time)
        for item in entries_value
    )
    identities = [item.identity for item in entries]
    if identities != sorted(identities):
        raise _error("catalog.entries are not canonically ordered")
    if len(identities) != len(set(identities)):
        raise _error("catalog contains duplicate report identities")
    return ReportDefinitionCatalog(
        catalog_sha256=catalog_sha256,
        entries=entries,
        production_promotion_allowed=False,
    )


def select_entry(
    catalog: ReportDefinitionCatalog,
    *,
    database_uuid: str,
    company_id: int,
    family: str,
    kind: str,
    root_xmlid: str,
    now: datetime,
) -> ReportDefinitionEntry:
    """Select exactly one active entry by its complete report identity."""

    if not isinstance(catalog, ReportDefinitionCatalog):
        raise _error("catalog was not produced by load_catalog_bytes")
    requested = (
        _database_uuid(database_uuid),
        _company_id(company_id),
        *_family_kind(family, kind),
        _root_xmlid(root_xmlid),
    )
    matches = [item for item in catalog.entries if item.identity == requested]
    if len(matches) != 1:
        raise _error("report definition identity did not select exactly one entry")
    entry = matches[0]
    _ensure_active(entry, _now(now))
    return entry


def _observed_bytes(value: Any, field: str) -> bytes:
    if isinstance(value, bytes):
        try:
            document = json.loads(
                value.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _error(f"{field} is not strict UTF-8 JSON") from exc
        if canonical_json(document) != value:
            raise _error(f"{field} is not canonical JSON")
    elif isinstance(value, dict):
        try:
            encoded = canonical_json(value)
            document = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise _error(f"{field} is not canonical JSON data") from exc
        value = encoded
    else:
        raise _error(f"{field} must be a definition object or canonical JSON bytes")
    if not isinstance(document, dict):
        raise _error(f"{field} must be a definition object")
    return value


def validate_observed_definition(
    entry: ReportDefinitionEntry,
    *,
    observed_pre: dict[str, Any] | bytes,
    observed_post: dict[str, Any] | bytes,
    now: datetime,
) -> str:
    """Validate pre/post observations and return their exact trust binding digest."""

    if not isinstance(entry, ReportDefinitionEntry):
        raise _error("entry was not produced by load_catalog_bytes")
    _ensure_active(entry, _now(now))
    pre = _observed_bytes(observed_pre, "observed_pre")
    post = _observed_bytes(observed_post, "observed_post")
    if pre != entry.definition_json:
        raise _error("observed_pre does not match the approved full definition")
    if post != entry.definition_json:
        raise _error("observed_post does not match the approved full definition")

    binding = {
        "allowed_signers": {
            "artifact_id": entry.allowed_signers.artifact_id,
            "sha256": entry.allowed_signers.sha256,
        },
        "approval_artifacts": [
            {
                "approval_artifact_sha256": item.approval_artifact_sha256,
                "approver_id": item.approver_id,
                "role": item.role,
                "signing_key_id": item.signing_key_id,
            }
            for item in entry.approvals
        ],
        "approval_set_sha256": entry.approval_set_sha256,
        "candidate_artifact_sha256": entry.candidate_artifact_sha256,
        "catalog_sha256": entry.catalog_sha256,
        "company_id": entry.company_id,
        "database_uuid": entry.database_uuid,
        "definition_sha256": entry.definition_sha256,
        "entry_sha256": entry.entry_sha256,
        "family": entry.family,
        "kind": entry.kind,
        "observed_post_sha256": hashlib.sha256(post).hexdigest(),
        "observed_pre_sha256": hashlib.sha256(pre).hexdigest(),
        "oracle_contract": {
            "artifact_id": entry.oracle_contract.artifact_id,
            "sha256": entry.oracle_contract.sha256,
        },
        "revocations": {
            "artifact_id": entry.revocations.artifact_id,
            "sha256": entry.revocations.sha256,
        },
        "root_xmlid": entry.root_xmlid,
        "schema_version": BINDING_SCHEMA,
    }
    return hashlib.sha256(canonical_json(binding)).hexdigest()

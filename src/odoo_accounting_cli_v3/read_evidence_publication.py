"""Strict offline validation for publication receipt contract bytes.

This module validates only canonical JSON structure and internal field
relationships.  It does not read a ledger or filesystem, verify a closure or
signature, derive trust, or admit external, Goal, production, or write
evidence.  A structurally valid receipt therefore remains an untrusted claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from .operations import canonical_json
from .read_evidence_admission import (
    ADMISSION_ARTIFACT_PATH as _ADMISSION_ARTIFACT_PATH,
    ADMISSION_ARTIFACT_SIGNATURE_PATH as _ADMISSION_ARTIFACT_SIGNATURE_PATH,
    ADMISSION_INDEX_PATH as _ADMISSION_INDEX_PATH,
    ADMISSION_INDEX_SIGNATURE_PATH as _ADMISSION_INDEX_SIGNATURE_PATH,
)


PUBLICATION_RECEIPT_SCHEMA = (
    "odoo-accounting-cli-v3.read-evidence-publication-receipt.v1"
)
PUBLICATION_RECEIPT_FILENAME = "publication-receipt.json"
PUBLICATION_SIGNATURE_FILENAME = "publication-receipt.json.sshsig"
CONTENT_MANIFEST_PATH = "content-manifest.json"
PUBLISHER_ALLOWED_SIGNERS_FILENAME = "final-evidence-publisher.allowed-signers"
REVOCATIONS_FILENAME = "final-evidence-publisher.revocations"
PUBLISHER_PRINCIPAL = "odoo-read-evidence-v3-final-evidence-publisher"
PUBLISHER_NAMESPACE = (
    "odoo-accounting-cli-v3/read-evidence-v3/final-evidence-publisher/v1"
)

LEDGER_PROVENANCE_BLOCKER = (
    "publication receipt contract validation does not verify ledger provenance"
)
SOURCE_CLOSURE_PROVENANCE_BLOCKER = (
    "publication receipt contract validation does not verify source closure provenance"
)
RETAINED_CLOSURE_PROVENANCE_BLOCKER = (
    "publication receipt contract validation does not verify retained closure provenance"
)
PUBLISHER_SIGNATURE_BLOCKER = (
    "publication receipt contract validation does not verify publisher signatures"
)

MAX_PUBLICATION_RECEIPT_BYTES = 64 * 1024
MAX_CONTENT_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_CLOSURE_FILES = 130
MAX_CLOSURE_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_ADMISSION_BYTES = 256 * 1024
_MAX_INDEX_BYTES = 16 * 1024 * 1024
_MAX_SIGNATURE_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 16
_MAX_JSON_NODES = 512
_MAX_JSON_STRING_BYTES = 8 * 1024

PUBLICATION_RECEIPT_FIELDS = frozenset(
    {
        "admission",
        "admitted_closure",
        "index",
        "publication",
        "receipt_id",
        "release_identity",
        "retained_closure",
        "schema_version",
        "source_closure",
    }
)
_RELEASE_IDENTITY_FIELDS = frozenset(
    {
        "commit",
        "manifest_sha256",
        "package_sha256",
        "registry_digest",
        "release",
    }
)
_PUBLICATION_FIELDS = frozenset(
    {
        "admitted_at",
        "authorization_expires_at",
        "authorization_id",
        "authorization_not_before",
        "authorization_sha256",
        "nonce_sha256",
        "published_at",
        "run_id",
        "scope_sha256",
        "sequence",
        "state",
    }
)
_INDEX_FIELDS = frozenset(
    {
        "path",
        "sha256",
        "signature_path",
        "signature_sha256",
        "signature_size",
        "size",
    }
)
_ADMISSION_FIELDS = frozenset(
    {
        "path",
        "sha256",
        "signature_path",
        "signature_sha256",
        "signature_size",
        "size",
    }
)
_CLOSURE_FIELDS = frozenset({"file_count", "total_bytes", "tree_sha256"})
_RETAINED_FIELDS = frozenset(
    {
        "closure",
        "content_manifest_path",
        "content_manifest_sha256",
        "content_manifest_size",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


class PublicationReceiptError(ValueError):
    """Raised when receipt bytes violate the offline publication contract."""


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PublicationReceiptError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _positive_integer(
    value: object,
    label: str,
    *,
    maximum: int,
) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise PublicationReceiptError(
            f"{label} must be a bounded positive integer"
        )
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise PublicationReceiptError(f"{label} is invalid")
    return value


def _fixed_relative_path(value: object, expected: str, label: str) -> str:
    if type(value) is not str or value != expected:
        raise PublicationReceiptError(f"{label} must be {expected!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or len(path.parts) != 1:
        raise PublicationReceiptError(f"{label} is invalid")
    return value


def _parse_utc_text(value: object, label: str) -> datetime:
    if type(value) is not str:
        raise PublicationReceiptError(f"{label} time is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise PublicationReceiptError(f"{label} time is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise PublicationReceiptError(f"{label} time is invalid")
    return parsed


def _exact_dict(
    value: object,
    fields: frozenset[str],
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise PublicationReceiptError(f"{label} fields are invalid")
    return value


def _reject_constant(value: str) -> None:
    raise PublicationReceiptError(f"non-finite JSON constant {value!r} is invalid")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PublicationReceiptError(
                "publication receipt has duplicate JSON keys"
            )
        result[key] = value
    return result


def _utf8_length(value: str, label: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise PublicationReceiptError(f"{label} is not valid UTF-8") from exc


def _bounded_json_tree(value: object) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise PublicationReceiptError("publication receipt JSON is too complex")
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise PublicationReceiptError(
                        "publication receipt JSON key is invalid"
                    )
                if (
                    _utf8_length(key, "publication receipt JSON key")
                    > _MAX_JSON_STRING_BYTES
                ):
                    raise PublicationReceiptError(
                        "publication receipt JSON key is too large"
                    )
                visit(child, depth + 1)
            return
        if type(item) is list:
            for child in item:
                visit(child, depth + 1)
            return
        if type(item) is str:
            if (
                _utf8_length(item, "publication receipt JSON string")
                > _MAX_JSON_STRING_BYTES
            ):
                raise PublicationReceiptError(
                    "publication receipt JSON string is too large"
                )
            return
        if item is None or type(item) in (bool, int):
            return
        raise PublicationReceiptError("publication receipt JSON value type is invalid")

    visit(value, 0)


def _strict_json_line(receipt: object) -> dict[str, Any]:
    if (
        type(receipt) is not bytes
        or not 0 < len(receipt) <= MAX_PUBLICATION_RECEIPT_BYTES
    ):
        raise PublicationReceiptError(
            "publication receipt must be bounded non-empty bytes"
        )
    try:
        text = receipt.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PublicationReceiptError(
            "publication receipt must be UTF-8 JSON bytes"
        ) from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
        PublicationReceiptError,
    ) as exc:
        if isinstance(exc, PublicationReceiptError):
            raise
        raise PublicationReceiptError("publication receipt is invalid JSON") from exc
    if type(document) is not dict:
        raise PublicationReceiptError(
            "publication receipt must contain one JSON object"
        )
    _bounded_json_tree(document)
    try:
        canonical = canonical_json(document) + b"\n"
    except (TypeError, ValueError) as exc:
        raise PublicationReceiptError(
            "publication receipt is not canonical JSON"
        ) from exc
    if not hmac.compare_digest(receipt, canonical):
        raise PublicationReceiptError(
            "publication receipt is not canonical JSON with one LF"
        )
    return document


def _validate_release_identity(value: object) -> None:
    release = _exact_dict(value, _RELEASE_IDENTITY_FIELDS, "release identity")
    if type(release["commit"]) is not str or _COMMIT.fullmatch(
        release["commit"]
    ) is None:
        raise PublicationReceiptError("release identity commit is invalid")
    for field in ("manifest_sha256", "package_sha256", "registry_digest"):
        _digest(release[field], f"release identity {field}")
    if type(release["release"]) is not str or _RELEASE.fullmatch(
        release["release"]
    ) is None:
        raise PublicationReceiptError("release identity release is invalid")


def _validate_closure(value: object, label: str) -> dict[str, Any]:
    closure = _exact_dict(value, _CLOSURE_FIELDS, label)
    return {
        "file_count": _positive_integer(
            closure["file_count"],
            f"{label} file_count",
            maximum=MAX_CLOSURE_FILES,
        ),
        "total_bytes": _positive_integer(
            closure["total_bytes"],
            f"{label} total_bytes",
            maximum=MAX_CLOSURE_TOTAL_BYTES,
        ),
        "tree_sha256": _digest(
            closure["tree_sha256"],
            f"{label} tree_sha256",
        ),
    }


def _publication_receipt_id(document: dict[str, Any]) -> str:
    core = {
        key: document[key]
        for key in sorted(document)
        if key != "receipt_id"
    }
    try:
        encoded = canonical_json(core) + b"\n"
    except (TypeError, ValueError) as exc:  # pragma: no cover - prevalidated
        raise PublicationReceiptError(
            "publication receipt cannot be canonicalized"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _validate_document(document: dict[str, Any]) -> None:
    receipt = _exact_dict(
        document,
        PUBLICATION_RECEIPT_FIELDS,
        "publication receipt",
    )
    if receipt["schema_version"] != PUBLICATION_RECEIPT_SCHEMA:
        raise PublicationReceiptError("publication receipt schema is invalid")
    _validate_release_identity(receipt["release_identity"])

    publication = _exact_dict(
        receipt["publication"],
        _PUBLICATION_FIELDS,
        "publication",
    )
    if publication["state"] != "PUBLISHED":
        raise PublicationReceiptError("publication state must be PUBLISHED")
    _positive_integer(
        publication["sequence"],
        "publication sequence",
        maximum=9_223_372_036_854_775_807,
    )
    _identifier(publication["authorization_id"], "authorization_id")
    _identifier(publication["run_id"], "run_id")
    for field in ("authorization_sha256", "nonce_sha256", "scope_sha256"):
        _digest(publication[field], field)
    not_before = _parse_utc_text(
        publication["authorization_not_before"],
        "authorization_not_before",
    )
    expires_at = _parse_utc_text(
        publication["authorization_expires_at"],
        "authorization_expires_at",
    )
    admitted_at = _parse_utc_text(publication["admitted_at"], "admitted_at")
    published_at = _parse_utc_text(publication["published_at"], "published_at")
    if not (not_before <= admitted_at <= published_at < expires_at):
        raise PublicationReceiptError(
            "publication times violate the half-open authorization window"
        )

    index = _exact_dict(receipt["index"], _INDEX_FIELDS, "index")
    _fixed_relative_path(index["path"], _ADMISSION_INDEX_PATH, "index path")
    _fixed_relative_path(
        index["signature_path"],
        _ADMISSION_INDEX_SIGNATURE_PATH,
        "index signature path",
    )
    _digest(index["sha256"], "index digest")
    _digest(index["signature_sha256"], "index signature digest")
    _positive_integer(index["size"], "index size", maximum=_MAX_INDEX_BYTES)
    _positive_integer(
        index["signature_size"],
        "index signature size",
        maximum=_MAX_SIGNATURE_BYTES,
    )

    admission = _exact_dict(
        receipt["admission"],
        _ADMISSION_FIELDS,
        "admission",
    )
    _fixed_relative_path(
        admission["path"],
        _ADMISSION_ARTIFACT_PATH,
        "admission path",
    )
    _fixed_relative_path(
        admission["signature_path"],
        _ADMISSION_ARTIFACT_SIGNATURE_PATH,
        "admission signature path",
    )
    _digest(admission["sha256"], "admission digest")
    _digest(admission["signature_sha256"], "admission signature digest")
    _positive_integer(
        admission["size"],
        "admission size",
        maximum=_MAX_ADMISSION_BYTES,
    )
    _positive_integer(
        admission["signature_size"],
        "admission signature size",
        maximum=_MAX_SIGNATURE_BYTES,
    )

    admitted = _validate_closure(
        receipt["admitted_closure"],
        "admitted closure",
    )
    source = _validate_closure(receipt["source_closure"], "source closure")
    if source["file_count"] != admitted["file_count"] + 2:
        raise PublicationReceiptError(
            "source closure file_count relationship is invalid"
        )
    if source["total_bytes"] != (
        admitted["total_bytes"]
        + admission["size"]
        + admission["signature_size"]
    ):
        raise PublicationReceiptError(
            "source closure total_bytes relationship is invalid"
        )

    retained = _exact_dict(
        receipt["retained_closure"],
        _RETAINED_FIELDS,
        "retained closure",
    )
    _fixed_relative_path(
        retained["content_manifest_path"],
        CONTENT_MANIFEST_PATH,
        "content manifest path",
    )
    _digest(
        retained["content_manifest_sha256"],
        "content manifest digest",
    )
    _positive_integer(
        retained["content_manifest_size"],
        "content manifest size",
        maximum=MAX_CONTENT_MANIFEST_BYTES,
    )
    retained_tree = _validate_closure(
        retained["closure"],
        "retained closure tree",
    )
    if retained_tree != source:
        raise PublicationReceiptError(
            "retained closure tree relationship is invalid"
        )

    receipt_id = _digest(receipt["receipt_id"], "receipt_id")
    if not hmac.compare_digest(receipt_id, _publication_receipt_id(receipt)):
        raise PublicationReceiptError("publication receipt ID mismatch")


def validate_publication_receipt_contract(receipt: bytes) -> dict[str, Any]:
    """Validate canonical receipt structure without making trust claims."""

    document = _strict_json_line(receipt)
    _validate_document(document)
    return {
        "blockers": [
            LEDGER_PROVENANCE_BLOCKER,
            SOURCE_CLOSURE_PROVENANCE_BLOCKER,
            RETAINED_CLOSURE_PROVENANCE_BLOCKER,
            PUBLISHER_SIGNATURE_BLOCKER,
        ],
        "external_read_evidence_verified": False,
        "goal_evidence_admissible": False,
        "ledger_provenance_verified": False,
        "production_promotion_allowed": False,
        "publication_receipt_contract_validated": True,
        "publisher_signature_verified": False,
        "real_odoo_write_performed": False,
        "retained_closure_verified": False,
        "source_closure_verified": False,
    }


__all__ = [
    "CONTENT_MANIFEST_PATH",
    "LEDGER_PROVENANCE_BLOCKER",
    "MAX_CLOSURE_FILES",
    "MAX_CLOSURE_TOTAL_BYTES",
    "MAX_CONTENT_MANIFEST_BYTES",
    "MAX_PUBLICATION_RECEIPT_BYTES",
    "PUBLICATION_RECEIPT_FIELDS",
    "PUBLICATION_RECEIPT_FILENAME",
    "PUBLICATION_RECEIPT_SCHEMA",
    "PUBLICATION_SIGNATURE_FILENAME",
    "PUBLISHER_ALLOWED_SIGNERS_FILENAME",
    "PUBLISHER_NAMESPACE",
    "PUBLISHER_PRINCIPAL",
    "PUBLISHER_SIGNATURE_BLOCKER",
    "RETAINED_CLOSURE_PROVENANCE_BLOCKER",
    "REVOCATIONS_FILENAME",
    "SOURCE_CLOSURE_PROVENANCE_BLOCKER",
    "PublicationReceiptError",
    "validate_publication_receipt_contract",
]

from __future__ import annotations

import hashlib
import inspect
import json
from copy import deepcopy
from typing import Any

import pytest

from odoo_accounting_cli_v3 import read_evidence_publication as publication
from odoo_accounting_cli_v3.read_evidence_admission import (
    ADMISSION_ARTIFACT_PATH,
    ADMISSION_ARTIFACT_SIGNATURE_PATH,
    ADMISSION_INDEX_PATH,
    ADMISSION_INDEX_SIGNATURE_PATH,
)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _receipt_id(document: dict[str, Any]) -> str:
    core = {
        key: document[key]
        for key in sorted(document)
        if key != "receipt_id"
    }
    return hashlib.sha256(_canonical(core)).hexdigest()


def _valid_document() -> dict[str, Any]:
    admission_size = 2_048
    admission_signature_size = 512
    admitted_file_count = 37
    admitted_total_bytes = 123_456
    source_closure = {
        "file_count": admitted_file_count + 2,
        "total_bytes": (
            admitted_total_bytes + admission_size + admission_signature_size
        ),
        "tree_sha256": "c" * 64,
    }
    document: dict[str, Any] = {
        "admission": {
            "path": ADMISSION_ARTIFACT_PATH,
            "sha256": "a" * 64,
            "signature_path": ADMISSION_ARTIFACT_SIGNATURE_PATH,
            "signature_sha256": "b" * 64,
            "signature_size": admission_signature_size,
            "size": admission_size,
        },
        "admitted_closure": {
            "file_count": admitted_file_count,
            "total_bytes": admitted_total_bytes,
            "tree_sha256": "7" * 64,
        },
        "index": {
            "path": ADMISSION_INDEX_PATH,
            "sha256": "5" * 64,
            "signature_path": ADMISSION_INDEX_SIGNATURE_PATH,
            "signature_sha256": "6" * 64,
            "signature_size": 256,
            "size": 4_096,
        },
        "publication": {
            "admitted_at": "2026-08-10T08:09:10Z",
            "authorization_expires_at": "2026-08-10T08:14:10Z",
            "authorization_id": "authz-dev264-0001",
            "authorization_not_before": "2026-08-10T08:08:10Z",
            "authorization_sha256": "9" * 64,
            "nonce_sha256": "d" * 64,
            "published_at": "2026-08-10T08:10:10Z",
            "run_id": "run-dev264-0001",
            "scope_sha256": "8" * 64,
            "sequence": 17,
            "state": "PUBLISHED",
        },
        "receipt_id": "",
        "release_identity": {
            "commit": "1" * 40,
            "manifest_sha256": "2" * 64,
            "package_sha256": "3" * 64,
            "registry_digest": "4" * 64,
            "release": "0.1.0.dev264-test",
        },
        "retained_closure": {
            "closure": deepcopy(source_closure),
            "content_manifest_path": "content-manifest.json",
            "content_manifest_sha256": "e" * 64,
            "content_manifest_size": 8_192,
        },
        "schema_version": (
            "odoo-accounting-cli-v3.read-evidence-publication-receipt.v1"
        ),
        "source_closure": source_closure,
    }
    document["receipt_id"] = _receipt_id(document)
    return document


def _valid_receipt() -> bytes:
    return _canonical(_valid_document())


def _mutated_receipt(
    path: tuple[str, ...],
    value: object,
    *,
    refresh_receipt_id: bool = True,
) -> bytes:
    document = _valid_document()
    target: Any = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    if refresh_receipt_id:
        document["receipt_id"] = _receipt_id(document)
    return _canonical(document)


EXPECTED_RESULT = {
    "blockers": [
        "publication receipt contract validation does not verify ledger provenance",
        "publication receipt contract validation does not verify source closure provenance",
        "publication receipt contract validation does not verify retained closure provenance",
        "publication receipt contract validation does not verify publisher signatures",
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


def test_public_api_is_offline_contract_only() -> None:
    validator = publication.validate_publication_receipt_contract
    assert set(inspect.signature(validator).parameters) == {"receipt"}

    for forbidden in (
        "PublishedAdmissionBinding",
        "RetainedClosureBinding",
        "VerifiedSourceClosureBinding",
        "build_publication_receipt",
        "verify_publication_receipt",
        "_PublicationVerificationMaterial",
        "_verify_publication_receipt_core",
        "verify_sshsig",
    ):
        assert forbidden not in vars(publication)
        assert forbidden not in publication.__all__

    assert "validate_publication_receipt_contract" in publication.__all__


def test_fixed_contract_names_remain_purpose_bound() -> None:
    assert publication.PUBLICATION_RECEIPT_FILENAME == "publication-receipt.json"
    assert publication.PUBLICATION_SIGNATURE_FILENAME == (
        "publication-receipt.json.sshsig"
    )
    assert publication.CONTENT_MANIFEST_PATH == "content-manifest.json"
    assert publication.PUBLISHER_PRINCIPAL == (
        "odoo-read-evidence-v3-final-evidence-publisher"
    )
    assert publication.PUBLISHER_NAMESPACE == (
        "odoo-accounting-cli-v3/read-evidence-v3/"
        "final-evidence-publisher/v1"
    )


def test_contract_accepts_only_the_canonical_admission_paths() -> None:
    assert publication.validate_publication_receipt_contract(
        _valid_receipt()
    ) == EXPECTED_RESULT


def test_structurally_valid_receipt_returns_only_contract_validation() -> None:
    result = publication.validate_publication_receipt_contract(_valid_receipt())

    assert result == EXPECTED_RESULT
    assert [
        key for key, value in result.items() if type(value) is bool and value
    ] == ["publication_receipt_contract_validated"]


def test_self_asserted_published_and_closure_claims_never_gain_provenance() -> None:
    document = _valid_document()
    document["publication"]["authorization_not_before"] = "2025-08-10T08:09:10Z"
    document["publication"]["authorization_expires_at"] = "2027-08-10T08:09:10Z"
    document["admission"]["signature_sha256"] = "f" * 64
    document["source_closure"]["tree_sha256"] = "0" * 64
    document["retained_closure"]["closure"]["tree_sha256"] = "0" * 64
    document["retained_closure"]["content_manifest_sha256"] = "1" * 64
    document["receipt_id"] = _receipt_id(document)

    result = publication.validate_publication_receipt_contract(_canonical(document))

    assert result == EXPECTED_RESULT
    assert result["ledger_provenance_verified"] is False
    assert result["source_closure_verified"] is False
    assert result["retained_closure_verified"] is False
    assert result["publisher_signature_verified"] is False


@pytest.mark.parametrize(
    "receipt",
    [
        lambda: b" " + _valid_receipt(),
        lambda: _valid_receipt().rstrip(b"\n"),
        lambda: _valid_receipt() + b"\n",
        lambda: b'{"schema_version":"duplicate",' + _valid_receipt()[1:],
        lambda: b'{"value":NaN}\n',
        lambda: b"[]\n",
        lambda: b"x" * (publication.MAX_PUBLICATION_RECEIPT_BYTES + 1),
    ],
)
def test_rejects_noncanonical_duplicate_nonfinite_and_oversized_json(
    receipt: Any,
) -> None:
    with pytest.raises(publication.PublicationReceiptError):
        publication.validate_publication_receipt_contract(receipt())


@pytest.mark.parametrize(
    "receipt",
    [
        b"[" * 1_200 + b"0" + b"]" * 1_200 + b"\n",
        b'{"value":' + b"1" * 5_000 + b"}\n",
        b'{"value":"\\ud800"}\n',
    ],
)
def test_malformed_bounded_json_uses_the_contract_error(
    receipt: bytes,
) -> None:
    with pytest.raises(publication.PublicationReceiptError):
        publication.validate_publication_receipt_contract(receipt)


@pytest.mark.parametrize("receipt", [None, "{}\n", bytearray(b"{}\n"), True])
def test_rejects_non_bytes_input(receipt: object) -> None:
    with pytest.raises(publication.PublicationReceiptError, match="bytes"):
        publication.validate_publication_receipt_contract(receipt)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("path", "value", "refresh_receipt_id"),
    [
        (("unexpected",), True, True),
        (("schema_version",), "wrong-schema", True),
        (("release_identity", "commit"), "A" * 40, True),
        (("release_identity", "package_sha256"), "A" * 64, True),
        (("release_identity", "release"), "bad release", True),
        (("publication", "state"), "published", True),
        (("publication", "sequence"), True, True),
        (("publication", "authorization_id"), "../auth", True),
        (("publication", "scope_sha256"), "A" * 64, True),
        (("index", "path"), "../read-evidence-index.json", True),
        (("index", "signature_path"), "other.sshsig", True),
        (("index", "size"), 0, True),
        (("index", "signature_size"), 1.5, True),
        (("admission", "path"), "/active-admission.json", True),
        (("admission", "signature_sha256"), "short", True),
        (("admitted_closure", "file_count"), 0, True),
        (("source_closure", "file_count"), 40, True),
        (("source_closure", "total_bytes"), 126_017, True),
        (("retained_closure", "content_manifest_path"), "other.json", True),
        (("retained_closure", "content_manifest_size"), True, True),
        (("retained_closure", "closure", "tree_sha256"), "0" * 64, True),
        (("receipt_id",), "0" * 64, False),
    ],
)
def test_rejects_field_type_path_digest_count_and_id_errors(
    path: tuple[str, ...],
    value: object,
    refresh_receipt_id: bool,
) -> None:
    with pytest.raises(publication.PublicationReceiptError):
        publication.validate_publication_receipt_contract(
            _mutated_receipt(
                path,
                value,
                refresh_receipt_id=refresh_receipt_id,
            )
        )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("publication", "authorization_not_before"), "2026-08-10 08:08:10Z"),
        (("publication", "admitted_at"), "2026-08-10T08:08:09Z"),
        (("publication", "published_at"), "2026-08-10T08:09:09Z"),
        (("publication", "published_at"), "2026-08-10T08:14:10Z"),
        (("publication", "authorization_expires_at"), "2026-08-10T08:08:10Z"),
        (("publication", "admitted_at"), "2026-08-10T08:09:10.000000Z"),
    ],
)
def test_rejects_noncanonical_or_invalid_half_open_times(
    path: tuple[str, ...], value: object
) -> None:
    with pytest.raises(publication.PublicationReceiptError, match="time|invalid"):
        publication.validate_publication_receipt_contract(
            _mutated_receipt(path, value)
        )


def test_accepts_exact_half_open_time_boundaries() -> None:
    document = _valid_document()
    document["publication"]["admitted_at"] = document["publication"][
        "authorization_not_before"
    ]
    document["publication"]["published_at"] = document["publication"][
        "admitted_at"
    ]
    document["receipt_id"] = _receipt_id(document)

    assert publication.validate_publication_receipt_contract(
        _canonical(document)
    ) == EXPECTED_RESULT


def test_rejects_excessive_json_depth_nodes_and_string_size() -> None:
    deep: object = "leaf"
    for _ in range(18):
        deep = [deep]
    for value in (
        deep,
        list(range(600)),
        "x" * 9_000,
    ):
        document = _valid_document()
        document["unexpected"] = value
        document["receipt_id"] = _receipt_id(document)
        with pytest.raises(publication.PublicationReceiptError, match="complex|large"):
            publication.validate_publication_receipt_contract(_canonical(document))


def test_receipt_id_covers_every_other_contract_field() -> None:
    original = _valid_document()
    changed = deepcopy(original)
    changed["publication"]["run_id"] = "run-dev264-0002"
    changed["receipt_id"] = _receipt_id(changed)

    assert original["receipt_id"] != changed["receipt_id"]
    assert publication.validate_publication_receipt_contract(
        _canonical(changed)
    ) == EXPECTED_RESULT

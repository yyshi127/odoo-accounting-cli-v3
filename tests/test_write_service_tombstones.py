from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.write_receipts import (
    create_difference,
    create_record_snapshot,
)
from odoo_accounting_cli_v3.write_service import (
    DurableWriteService,
    WriteServiceError,
    _digest,
)


def snapshot(
    model: str,
    record_id: int,
    *,
    exists: bool = True,
    values: dict | None = None,
    state: str | None = None,
) -> dict:
    return create_record_snapshot(
        model=model,
        record_id=record_id,
        exists=exists,
        record_state=state or ("posted" if exists else "absent"),
        values=values if values is not None else ({"company_id": 7} if exists else {}),
    )


def result_record(value: dict) -> dict:
    return {
        "model": value["model"],
        "record_id": value["record_id"],
        "company_id": 7,
        "record_state": value["record_state"],
        "record_fingerprint": _digest(value),
    }


def validate(before, after, *, records=()):
    records_by_key = {
        (record["model"], record["record_id"]): record for record in records
    }
    DurableWriteService._validate_difference_binding(
        create_difference(before=before, after=after, changed_fields=[]),
        operation=SimpleNamespace(company_id=7),
        allowed_models=frozenset(
            {
                "account.move.line",
                "account.partial.reconcile",
                "account.full.reconcile",
            }
        ),
        records_by_key=records_by_key,
    )


def test_company_bound_partial_reconcile_tombstone_is_accepted():
    before = snapshot(
        "account.partial.reconcile", 21, values={"company_id": 7, "amount": "10"}
    )

    validate(
        [before],
        [snapshot("account.partial.reconcile", 21, exists=False)],
    )


def test_company_bound_creation_absence_marker_is_accepted():
    before = snapshot("account.partial.reconcile", 21, exists=False)
    after = snapshot(
        "account.partial.reconcile",
        21,
        values={"company_id": 7, "amount": "10"},
    )

    validate([before], [after], records=[result_record(after)])


def test_isolated_creation_absence_marker_is_rejected():
    with pytest.raises(WriteServiceError, match="omit"):
        validate(
            [snapshot("account.partial.reconcile", 21, exists=False)],
            [snapshot("account.partial.reconcile", 22)],
        )


def test_creation_absence_marker_rejects_cross_company_after_snapshot():
    with pytest.raises(WriteServiceError, match="company"):
        validate(
            [snapshot("account.partial.reconcile", 21, exists=False)],
            [
                snapshot(
                    "account.partial.reconcile",
                    21,
                    values={"company_id": 8, "amount": "10"},
                )
            ],
        )


def test_creation_cannot_borrow_company_binding_from_result_record():
    before = snapshot("account.partial.reconcile", 21, exists=False)
    after = snapshot(
        "account.partial.reconcile",
        21,
        values={"amount": "10"},
    )

    with pytest.raises(WriteServiceError, match="company-bound"):
        validate([before], [after], records=[result_record(after)])


def test_creation_absence_marker_rejects_absent_or_missing_same_key_after():
    before = snapshot("account.partial.reconcile", 21, exists=False)
    with pytest.raises(WriteServiceError, match="before snapshots"):
        validate(
            [before],
            [snapshot("account.partial.reconcile", 21, exists=False)],
        )

    with pytest.raises(WriteServiceError, match="omit"):
        validate([before], [])


def test_tombstone_requires_company_bound_existing_before_snapshot():
    before = snapshot(
        "account.partial.reconcile", 21, values={"company_id": 8, "amount": "10"}
    )
    with pytest.raises(WriteServiceError, match="company"):
        validate(
            [before],
            [snapshot("account.partial.reconcile", 21, exists=False)],
        )

    with pytest.raises(WriteServiceError, match="before"):
        validate(
            [],
            [snapshot("account.partial.reconcile", 21, exists=False)],
        )


def test_full_reconcile_tombstone_binds_through_company_bound_lines():
    line_before = snapshot(
        "account.move.line", 11, values={"company_id": 7, "balance": "10"}
    )
    line_after = snapshot(
        "account.move.line", 11, values={"company_id": 7, "balance": "10"}
    )
    full_before = snapshot(
        "account.full.reconcile",
        31,
        values={"partial_reconcile_ids": [21], "reconciled_line_ids": [11]},
    )

    validate(
        [line_before, full_before],
        [
            line_after,
            snapshot("account.full.reconcile", 31, exists=False),
        ],
        records=[result_record(line_after)],
    )


def test_existing_full_reconcile_binds_through_same_phase_move_lines():
    line_before = snapshot(
        "account.move.line", 11, values={"company_id": 7, "balance": "10"}
    )
    line_after = snapshot(
        "account.move.line", 11, values={"company_id": 7, "balance": "0"}
    )
    full_before = snapshot(
        "account.full.reconcile",
        31,
        values={"partial_reconcile_ids": [21], "reconciled_line_ids": [11]},
    )
    full_after = snapshot(
        "account.full.reconcile",
        31,
        values={"partial_reconcile_ids": [21], "reconciled_line_ids": [11]},
    )

    validate(
        [line_before, full_before],
        [line_after, full_after],
    )


def test_full_reconcile_creation_cannot_borrow_before_phase_line_company():
    line_before = snapshot(
        "account.move.line", 11, values={"company_id": 7, "balance": "10"}
    )
    line_after = snapshot("account.move.line", 11, exists=False)
    full_before = snapshot("account.full.reconcile", 31, exists=False)
    full_after = snapshot(
        "account.full.reconcile",
        31,
        values={"partial_reconcile_ids": [21], "reconciled_line_ids": [11]},
    )

    with pytest.raises(WriteServiceError, match="company-bound"):
        validate(
            [line_before, full_before],
            [line_after, full_after],
        )


def test_full_reconcile_tombstone_rejects_cross_company_line_binding():
    line_before = snapshot(
        "account.move.line", 11, values={"company_id": 8, "balance": "10"}
    )
    full_before = snapshot(
        "account.full.reconcile",
        31,
        values={"partial_reconcile_ids": [21], "reconciled_line_ids": [11]},
    )

    with pytest.raises(WriteServiceError, match="company"):
        validate(
            [line_before, full_before],
            [
                snapshot(
                    "account.move.line",
                    11,
                    values={"company_id": 8, "balance": "10"},
                ),
                snapshot("account.full.reconcile", 31, exists=False),
            ],
        )


def test_before_tombstones_and_omitted_after_records_are_rejected():
    prior_tombstone = snapshot("account.partial.reconcile", 21, exists=False)
    with pytest.raises(WriteServiceError, match="before snapshots"):
        validate([prior_tombstone], [prior_tombstone])

    before = snapshot("account.partial.reconcile", 21)
    with pytest.raises(WriteServiceError, match="omit"):
        validate([before], [])


def test_fixture_snapshots_are_canonical_json_objects():
    value = snapshot(
        "account.partial.reconcile", 21, values={"company_id": 7, "amount": "10"}
    )
    assert canonical_json(value)

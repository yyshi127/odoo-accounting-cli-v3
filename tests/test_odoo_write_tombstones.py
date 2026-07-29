from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo.write_bootstrap import (
    MAX_AUDIT_RECORDS,
    OdooWriteBootstrapError,
    _difference,
    _raw_snapshot,
    _verification_evidence,
)
from odoo_accounting_cli_v3.operations import canonical_json


COMPANY_ID = 7
NOW = datetime(2026, 7, 29, 4, 0, tzinfo=timezone.utc)
EMPTY_DIGEST = hashlib.sha256(b"{}").hexdigest()


def _digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _existing(
    record_id: int,
    *,
    model: str = "account.move",
    company_id: int = COMPANY_ID,
    state: str = "posted",
    values=None,
):
    if values is None:
        values = {
            "company_id": company_id,
            "state": state,
            "amount_total": "100.00",
        }
    return {
        "model": model,
        "record_id": record_id,
        "company_id": company_id,
        "state": state,
        "values": values,
        "values_digest": _digest(values),
    }


def _tombstone(
    record_id: int,
    *,
    model: str = "account.move",
    company_id: int = COMPANY_ID,
):
    return {
        "model": model,
        "record_id": record_id,
        "company_id": company_id,
        "exists": False,
        "state": "absent",
        "values": {},
        "values_digest": EMPTY_DIGEST,
    }


def _operation(company_id: int = COMPANY_ID):
    return SimpleNamespace(
        operation_id="op-tombstone-001",
        capability_id="acct.move.draft_cancel.v1",
        company_id=company_id,
        parameters={"company_id": company_id, "move_id": 1},
        execution_result_digest="e" * 64,
    )


def _execution(before, after, company_id: int = COMPANY_ID):
    difference, records = _difference(before, after, company_id)
    return {"odoo_records": records, "difference": difference}


def _verification_raw(after):
    return {
        "passed": True,
        "method": "odoo_public_orm_readback_v1",
        "checks": ["record_state", "record_identity"],
        "after": after,
        "evidence_digest": _digest(after),
    }


def _verify(execution, after, company_id: int = COMPANY_ID):
    return _verification_evidence(
        _operation(company_id),
        execution,
        _verification_raw(after),
        None,
        expected_method="odoo_exact_snapshot_v1",
        observed_at=NOW,
    )


def test_existing_handler_snapshot_shape_remains_accepted():
    snapshot, reference = _raw_snapshot(_existing(1), COMPANY_ID)

    assert snapshot["exists"] is True
    assert reference is not None
    assert reference["record_id"] == 1


def test_exact_tombstone_shape_is_accepted_without_a_record_reference():
    snapshot, reference = _raw_snapshot(_tombstone(1), COMPANY_ID)

    assert snapshot == {
        "model": "account.move",
        "record_id": 1,
        "exists": False,
        "record_state": "absent",
        "values_json": "{}",
        "values_digest": EMPTY_DIGEST,
    }
    assert reference is None


def test_legal_delete_has_an_explicit_absent_after_snapshot():
    before = _existing(1)
    difference, records = _difference([before], [_tombstone(1)], COMPANY_ID)

    assert difference["before"][0]["exists"] is True
    assert difference["after"][0]["exists"] is False
    assert records == []


def test_delete_changed_fields_include_record_state_and_every_removed_field():
    before = _existing(
        1,
        values={"company_id": COMPANY_ID, "state": "posted", "name": "MISC/1"},
    )
    difference, _records = _difference([before], [_tombstone(1)], COMPANY_ID)

    assert set(difference["changed_fields"]) == {
        "company_id",
        "name",
        "record_state",
        "state",
    }


def test_mixed_create_update_delete_difference_is_complete():
    updated_before = _existing(1, values={"state": "draft", "amount": "10.00"})
    deleted_before = _existing(2, values={"state": "posted", "amount": "20.00"})
    updated_after = _existing(1, values={"state": "posted", "amount": "11.00"})
    created_after = _existing(3, values={"state": "draft", "amount": "30.00"})

    difference, records = _difference(
        [updated_before, deleted_before],
        [updated_after, _tombstone(2), created_after],
        COMPANY_ID,
    )

    by_before_id = {item["record_id"]: item for item in difference["before"]}
    by_after_id = {item["record_id"]: item for item in difference["after"]}
    assert by_before_id[3]["exists"] is False
    assert by_after_id[2]["exists"] is False
    assert [item["record_id"] for item in records] == [1, 3]
    assert set(difference["changed_fields"]) >= {
        "amount",
        "record_state",
        "state",
    }


def test_omitted_prechecked_record_is_rejected():
    with pytest.raises(
        OdooWriteBootstrapError, match="omitted a prechecked record"
    ):
        _difference([_existing(1)], [], COMPANY_ID)


def test_before_tombstone_is_rejected():
    with pytest.raises(
        OdooWriteBootstrapError, match="before snapshots cannot contain a tombstone"
    ):
        _difference([_tombstone(1)], [_tombstone(1)], COMPANY_ID)


def test_new_tombstone_without_before_identity_is_rejected():
    with pytest.raises(
        OdooWriteBootstrapError, match="tombstone without a prechecked record"
    ):
        _difference([], [_tombstone(1)], COMPANY_ID)


def test_tombstone_never_enters_odoo_record_references():
    _difference_value, records = _difference(
        [_existing(1), _existing(2)],
        [_tombstone(1), _existing(2)],
        COMPANY_ID,
    )

    assert [(item["model"], item["record_id"]) for item in records] == [
        ("account.move", 2)
    ]


def test_existing_snapshot_with_exists_field_is_not_silently_reinterpreted():
    value = {**_existing(1), "exists": True}

    with pytest.raises(OdooWriteBootstrapError, match="tombstone binding"):
        _raw_snapshot(value, COMPANY_ID)


@pytest.mark.parametrize(
    ("field", "bad_value", "company_id"),
    [
        ("exists", True, COMPANY_ID),
        ("exists", 0, COMPANY_ID),
        ("exists", None, COMPANY_ID),
        ("record_id", True, COMPANY_ID),
        ("record_id", 1.0, COMPANY_ID),
        ("record_id", 0, COMPANY_ID),
        ("record_id", -1, COMPANY_ID),
        ("record_id", "1", COMPANY_ID),
        ("company_id", 8, COMPANY_ID),
        ("company_id", "7", COMPANY_ID),
        ("company_id", True, 1),
        ("state", "deleted", COMPANY_ID),
        ("state", "", COMPANY_ID),
        ("state", " ", COMPANY_ID),
        ("state", "absent\n", COMPANY_ID),
        ("values_digest", "0" * 64, COMPANY_ID),
        ("values_digest", EMPTY_DIGEST.upper(), COMPANY_ID),
        ("values_digest", 1, COMPANY_ID),
        ("model", "account.move;drop", COMPANY_ID),
        ("model", "", COMPANY_ID),
    ],
)
def test_malformed_tombstone_scalar_is_rejected(field, bad_value, company_id):
    value = _tombstone(1, company_id=company_id)
    value[field] = bad_value

    with pytest.raises(OdooWriteBootstrapError):
        _raw_snapshot(value, company_id)


def test_tombstone_nonempty_values_are_rejected_even_with_matching_digest():
    value = _tombstone(1)
    value["values"] = {"state": "absent"}
    value["values_digest"] = _digest(value["values"])

    with pytest.raises(OdooWriteBootstrapError, match="tombstone binding"):
        _raw_snapshot(value, COMPANY_ID)


def test_tombstone_nonobject_values_are_rejected():
    value = _tombstone(1)
    value["values"] = []
    value["values_digest"] = _digest([])

    with pytest.raises(OdooWriteBootstrapError, match="snapshot binding"):
        _raw_snapshot(value, COMPANY_ID)


def test_tombstone_extra_key_is_rejected():
    value = {**_tombstone(1), "deleted_at": "2026-07-29T04:00:00Z"}

    with pytest.raises(OdooWriteBootstrapError, match="snapshot fields"):
        _raw_snapshot(value, COMPANY_ID)


def test_difference_rejects_duplicate_before_identity():
    with pytest.raises(OdooWriteBootstrapError, match="duplicate record"):
        _difference(
            [_existing(1), _existing(1)],
            [_tombstone(1)],
            COMPANY_ID,
        )


def test_difference_rejects_duplicate_after_tombstone_identity():
    with pytest.raises(OdooWriteBootstrapError, match="duplicate record"):
        _difference(
            [_existing(1)],
            [_tombstone(1), _tombstone(1)],
            COMPANY_ID,
        )


def test_difference_accepts_exact_audit_record_limit():
    after = [_existing(record_id) for record_id in range(1, MAX_AUDIT_RECORDS + 1)]

    difference, records = _difference([], after, COMPANY_ID)

    assert len(difference["before"]) == MAX_AUDIT_RECORDS
    assert len(difference["after"]) == MAX_AUDIT_RECORDS
    assert len(records) == MAX_AUDIT_RECORDS


def test_difference_rejects_before_graph_above_audit_record_limit():
    before = [
        _existing(record_id) for record_id in range(1, MAX_AUDIT_RECORDS + 2)
    ]

    with pytest.raises(OdooWriteBootstrapError, match="auditable record limit"):
        _difference(before, [], COMPANY_ID)


def test_verification_accepts_exact_tombstone_and_signs_it_into_fresh_snapshots():
    before = [_existing(1)]
    after = [_tombstone(1)]
    execution = _execution(before, after)

    evidence = _verify(execution, after)

    assert evidence["passed"] is True
    assert evidence["readback"]["records"] == []
    assert evidence["readback"]["fresh_snapshots"] == execution["difference"]["after"]
    assert evidence["readback"]["fresh_snapshots_digest"] == _digest(
        execution["difference"]["after"]
    )


def test_verification_mixed_readback_compares_only_existing_record_references():
    before = [_existing(1), _existing(2)]
    after = [
        _existing(1, values={"state": "posted", "amount": "11.00"}),
        _tombstone(2),
        _existing(3, values={"state": "draft", "amount": "30.00"}),
    ]
    execution = _execution(before, after)

    evidence = _verify(execution, after)

    assert [item["record_id"] for item in evidence["readback"]["records"]] == [1, 3]
    assert [item["record_id"] for item in evidence["readback"]["fresh_snapshots"]] == [
        1,
        2,
        3,
    ]


def test_verification_rejects_missing_committed_tombstone():
    execution = _execution([_existing(1)], [_tombstone(1)])

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, [])


def test_verification_rejects_added_tombstone():
    after = [_existing(1)]
    execution = _execution([], after)

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, [*after, _tombstone(2)])


def test_verification_rejects_tombstone_record_id_drift():
    execution = _execution([_existing(1)], [_tombstone(1)])

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, [_tombstone(2)])


def test_verification_rejects_tombstone_model_drift():
    execution = _execution([_existing(1)], [_tombstone(1)])

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, [_tombstone(1, model="account.payment")])


def test_verification_rejects_tombstone_company_drift():
    execution = _execution([_existing(1)], [_tombstone(1)])

    with pytest.raises(OdooWriteBootstrapError, match="snapshot binding"):
        _verify(execution, [_tombstone(1, company_id=8)])


def test_verification_rejects_tombstone_digest_drift():
    execution = _execution([_existing(1)], [_tombstone(1)])
    drifted = _tombstone(1)
    drifted["values_digest"] = "0" * 64

    with pytest.raises(OdooWriteBootstrapError, match="snapshot binding"):
        _verify(execution, [drifted])


def test_verification_rejects_tombstone_values_drift_with_recomputed_digest():
    execution = _execution([_existing(1)], [_tombstone(1)])
    drifted = _tombstone(1)
    drifted["values"] = {"deleted": True}
    drifted["values_digest"] = _digest(drifted["values"])

    with pytest.raises(OdooWriteBootstrapError, match="tombstone binding"):
        _verify(execution, [drifted])


def test_verification_rejects_tombstone_state_drift():
    execution = _execution([_existing(1)], [_tombstone(1)])
    drifted = _tombstone(1)
    drifted["state"] = "deleted"

    with pytest.raises(OdooWriteBootstrapError, match="tombstone binding"):
        _verify(execution, [drifted])


def test_verification_rejects_tombstone_replaced_by_existing_snapshot():
    execution = _execution([_existing(1)], [_tombstone(1)])

    with pytest.raises(OdooWriteBootstrapError, match="execution records"):
        _verify(execution, [_existing(1)])


def test_verification_rejects_existing_snapshot_replaced_by_tombstone():
    after = [_existing(1)]
    execution = _execution([], after)

    with pytest.raises(OdooWriteBootstrapError, match="execution records"):
        _verify(execution, [_tombstone(1)])


def test_verification_rejects_duplicate_tombstone_readback():
    execution = _execution([_existing(1)], [_tombstone(1)])

    with pytest.raises(OdooWriteBootstrapError, match="duplicate record"):
        _verify(execution, [_tombstone(1), _tombstone(1)])


def test_verification_rejects_duplicate_existing_readback():
    after = [_existing(1)]
    execution = _execution([], after)

    with pytest.raises(OdooWriteBootstrapError, match="duplicate record"):
        _verify(execution, [*after, *after])


def test_verification_rejects_tampered_committed_tombstone_snapshot():
    after = [_tombstone(1)]
    execution = _execution([_existing(1)], after)
    execution = copy.deepcopy(execution)
    execution["difference"]["after"][0]["values_digest"] = "0" * 64

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, after)


def test_verification_rejects_tombstone_removed_from_committed_difference():
    after = [_tombstone(1)]
    execution = _execution([_existing(1)], after)
    execution = copy.deepcopy(execution)
    execution["difference"]["after"] = []

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, after)


def test_verification_rejects_tombstone_added_to_committed_difference():
    after = [_existing(1)]
    execution = _execution([], after)
    deleted = _execution([_existing(2)], [_tombstone(2)])
    execution = copy.deepcopy(execution)
    execution["difference"]["after"].append(deleted["difference"]["after"][0])

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, after)


def test_verification_rejects_duplicate_tombstone_in_committed_difference():
    after = [_tombstone(1)]
    execution = _execution([_existing(1)], after)
    execution = copy.deepcopy(execution)
    execution["difference"]["after"].append(
        copy.deepcopy(execution["difference"]["after"][0])
    )

    with pytest.raises(OdooWriteBootstrapError, match="tombstones differ"):
        _verify(execution, after)


def test_verification_accepts_exact_audit_record_limit():
    after = [_existing(record_id) for record_id in range(1, MAX_AUDIT_RECORDS + 1)]
    execution = _execution([], after)

    evidence = _verify(execution, after)

    assert len(evidence["readback"]["records"]) == MAX_AUDIT_RECORDS
    assert len(evidence["readback"]["fresh_snapshots"]) == MAX_AUDIT_RECORDS


def test_verification_rejects_readback_above_audit_record_limit_before_parsing():
    after = [
        _tombstone(record_id) for record_id in range(1, MAX_AUDIT_RECORDS + 2)
    ]
    execution = {"odoo_records": [], "difference": {"after": []}}

    with pytest.raises(OdooWriteBootstrapError, match="auditable record limit"):
        _verify(execution, after)

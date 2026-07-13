import hashlib
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from odoo_accounting_cli_v3.audit import (
    GENESIS_HASH,
    AuditError,
    OdooReceipt,
    VerificationReceipt,
    build_event,
    completion_details,
    verify_chain,
)
from odoo_accounting_cli_v3.operations import State


NOW = datetime(2026, 7, 13, 8, 0, tzinfo=timezone.utc)
DIGEST = hashlib.sha256(b"operation").hexdigest()


def odoo_receipt(company_id: int = 7) -> OdooReceipt:
    return OdooReceipt(
        database="odoo19_sandbox", model="account.move", record_ids=(101,),
        company_id=company_id, operation="create", observed_at=NOW,
        record_fingerprint=hashlib.sha256(b"record-101").hexdigest(),
    )


def verification(passed: bool = True) -> VerificationReceipt:
    return VerificationReceipt(
        method="read_back_totals_partner_currency_and_lines", verified_at=NOW,
        passed=passed, checks=("company", "partner", "currency", "totals", "lines"),
        evidence_digest=hashlib.sha256(b"read-back").hexdigest(),
    )


class AuditTest(unittest.TestCase):
    def test_valid_chain_verifies(self) -> None:
        first = build_event(
            sequence=1, event_id="event-1", request_id="request-1", operation_id="op-1",
            operation_digest=DIGEST, user_id=42, company_id=7, state=State.PREPARED,
            occurred_at=NOW, details={"capability_id": "acct.invoice.customer_create.v1"},
            previous_hash=GENESIS_HASH,
        )
        second = build_event(
            sequence=2, event_id="event-2", request_id="request-1", operation_id="op-1",
            operation_digest=DIGEST, user_id=42, company_id=7, state=State.PRECHECKED,
            occurred_at=NOW, details={"acl": "passed"}, previous_hash=first.event_hash,
        )
        verify_chain([first, second])

    def test_tampered_event_is_rejected(self) -> None:
        event = build_event(
            sequence=1, event_id="event-1", request_id="request-1", operation_id="op-1",
            operation_digest=DIGEST, user_id=42, company_id=7, state=State.PREPARED,
            occurred_at=NOW, details={"amount": "100.00"}, previous_hash=GENESIS_HASH,
        )
        tampered = replace(event, details={"amount": "999.00"})
        with self.assertRaisesRegex(AuditError, "hash mismatch"):
            verify_chain([tampered])

    def test_cross_company_chain_event_is_rejected(self) -> None:
        first = build_event(sequence=1, event_id="event-1", request_id="request-1", operation_id="op-1", operation_digest=DIGEST, user_id=42, company_id=7, state=State.PREPARED, occurred_at=NOW, details={}, previous_hash=GENESIS_HASH)
        second = build_event(sequence=2, event_id="event-2", request_id="request-1", operation_id="op-1", operation_digest=DIGEST, user_id=42, company_id=8, state=State.PRECHECKED, occurred_at=NOW, details={}, previous_hash=first.event_hash)
        with self.assertRaisesRegex(AuditError, "binding mismatch"):
            verify_chain([first, second])

    def test_completion_requires_passing_verification(self) -> None:
        with self.assertRaisesRegex(AuditError, "passing checks"):
            completion_details(before={"company_id": 7, "state": "draft"}, after={"company_id": 7, "state": "posted"}, odoo_receipt=odoo_receipt(), verification_receipt=verification(False))

    def test_completion_requires_real_odoo_record_identity(self) -> None:
        invalid = replace(odoo_receipt(), record_ids=())
        with self.assertRaisesRegex(AuditError, "record ids"):
            completion_details(before={"company_id": 7, "state": "draft"}, after={"company_id": 7, "state": "posted"}, odoo_receipt=invalid, verification_receipt=verification())

    def test_completion_requires_before_after_difference(self) -> None:
        state = {"company_id": 7, "state": "posted"}
        with self.assertRaisesRegex(AuditError, "meaningful"):
            completion_details(before=state, after=state.copy(), odoo_receipt=odoo_receipt(), verification_receipt=verification())

    def test_receipt_company_must_match_verified_result(self) -> None:
        with self.assertRaisesRegex(AuditError, "company does not match"):
            completion_details(before={"company_id": 7, "state": "draft"}, after={"company_id": 7, "state": "posted"}, odoo_receipt=odoo_receipt(8), verification_receipt=verification())


if __name__ == "__main__":
    unittest.main()

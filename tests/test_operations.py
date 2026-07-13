import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from odoo_accounting_cli_v3.operations import (
    ApprovalRejected,
    ConcurrentUpdate,
    Operation,
    OperationError,
    State,
    approve_operation,
    sign_approval,
)


SECRET = b"test-only-secret"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)


def awaiting_operation() -> Operation:
    operation = Operation.prepare(
        operation_id="op-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "invoice_date": "2026-07-13", "currency_id": 12},
        user_id=42,
        company_id=7,
        idempotency_key="idem-1",
    )
    operation = operation.transition(State.PRECHECKED, expected_revision=0)
    return operation.transition(State.AWAITING_APPROVAL, expected_revision=1)


def valid_approval(operation: Operation, nonce: str = "nonce-1"):
    return sign_approval(
        operation=operation,
        approver_user_id=99,
        nonce=nonce,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        secret=SECRET,
    )


class OperationTest(unittest.TestCase):
    def test_digest_is_stable_across_parameter_order(self) -> None:
        first = awaiting_operation()
        second = Operation.prepare(
            operation_id="op-2",
            capability_id=first.capability_id,
            parameters={"currency_id": 12, "invoice_date": "2026-07-13", "company_id": 7},
            user_id=42,
            company_id=7,
            idempotency_key="idem-1",
        )
        self.assertEqual(first.digest, second.digest)

    def test_digest_changes_when_business_content_changes(self) -> None:
        operation = awaiting_operation()
        changed = Operation.prepare(
            operation_id="op-2", capability_id=operation.capability_id,
            parameters={**operation.parameters, "invoice_date": "2026-07-14"},
            user_id=operation.user_id, company_id=operation.company_id,
            idempotency_key=operation.idempotency_key,
        )
        self.assertNotEqual(operation.digest, changed.digest)

    def test_prepared_parameters_are_detached_and_immutable(self) -> None:
        parameters = {"company_id": 7, "lines": [{"amount": "100.00"}]}
        operation = Operation.prepare(
            operation_id="op-detached", capability_id="acct.invoice.customer_create.v1",
            parameters=parameters, user_id=42, company_id=7, idempotency_key="idem-detached",
        )
        parameters["lines"][0]["amount"] = "999.00"
        returned = operation.parameters
        returned["lines"][0]["amount"] = "888.00"
        self.assertEqual(operation.parameters["lines"][0]["amount"], "100.00")

    def test_approval_succeeds_once(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        consumed: set[str] = set()

        def consume(nonce: str) -> bool:
            if nonce in consumed:
                return False
            consumed.add(nonce)
            return True

        approved = approve_operation(operation, approval, now=NOW, secret=SECRET, consume_nonce=consume, expected_revision=2)
        self.assertEqual(approved.state, State.APPROVED)
        with self.assertRaisesRegex(ApprovalRejected, "already consumed"):
            approve_operation(operation, approval, now=NOW, secret=SECRET, consume_nonce=consume, expected_revision=2)

    def test_expired_approval_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = sign_approval(
            operation=operation, approver_user_id=99, nonce="expired",
            issued_at=NOW - timedelta(minutes=20), expires_at=NOW - timedelta(minutes=10), secret=SECRET,
        )
        with self.assertRaisesRegex(ApprovalRejected, "not currently valid"):
            approve_operation(operation, approval, now=NOW, secret=SECRET, consume_nonce=lambda _: True, expected_revision=2)

    def test_tampered_digest_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), operation_digest="0" * 64)
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            approve_operation(operation, approval, now=NOW, secret=SECRET, consume_nonce=lambda _: True, expected_revision=2)

    def test_cross_company_approval_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), company_id=8)
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            approve_operation(operation, approval, now=NOW, secret=SECRET, consume_nonce=lambda _: True, expected_revision=2)

    def test_wrong_user_approval_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), user_id=43)
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            approve_operation(operation, approval, now=NOW, secret=SECRET, consume_nonce=lambda _: True, expected_revision=2)

    def test_signature_tampering_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), signature="f" * 64)
        with self.assertRaisesRegex(ApprovalRejected, "signature mismatch"):
            approve_operation(operation, approval, now=NOW, secret=SECRET, consume_nonce=lambda _: True, expected_revision=2)

    def test_stale_revision_is_rejected(self) -> None:
        operation = awaiting_operation()
        with self.assertRaises(ConcurrentUpdate):
            operation.transition(State.APPROVED, expected_revision=1)

    def test_invalid_transition_is_rejected(self) -> None:
        operation = awaiting_operation()
        with self.assertRaises(OperationError):
            operation.transition(State.COMPLETED, expected_revision=2)

    def test_completion_requires_verification(self) -> None:
        operation = awaiting_operation()
        operation = operation.transition(State.APPROVED, expected_revision=2)
        operation = operation.transition(State.EXECUTING, expected_revision=3)
        with self.assertRaises(OperationError):
            operation.transition(State.COMPLETED, expected_revision=4)
        operation = operation.transition(State.VERIFYING, expected_revision=4)
        operation = operation.transition(State.COMPLETED, expected_revision=5)
        self.assertEqual(operation.state, State.COMPLETED)


if __name__ == "__main__":
    unittest.main()

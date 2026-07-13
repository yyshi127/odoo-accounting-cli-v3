import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from odoo_accounting_cli_v3.operations import (
    MAX_APPROVAL_TTL,
    ApprovalRejected,
    ConcurrentUpdate,
    IntegrityRejected,
    Operation,
    OperationError,
    State,
    TrustedResultRejected,
    approve_operation,
    begin_execution,
    complete_operation,
    record_execution_result,
    sign_approval,
    sign_execution_result,
    sign_verification_result,
)


SECRET = b"test-only-secret"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
REGISTRY_DIGEST = "c" * 64
RELEASE_DIGEST = "d" * 64
RUNTIME_BINDING = {
    "odoo_instance_id": "odoo19@tokyo2",
    "database_name": "odoo_test",
    "database_uuid": DATABASE_UUID,
    "environment": "test",
    "principal": "pi:test-user-42",
    "registry_digest": REGISTRY_DIGEST,
    "release_digest": RELEASE_DIGEST,
}
AUTHORIZED = lambda approver_id, company_id, capability_id: (
    approver_id == 99
    and company_id == 7
    and capability_id == "acct.invoice.customer_create.v1"
)


def awaiting_operation() -> Operation:
    operation = Operation.prepare(
        operation_id="op-1",
        request_id="request-1",
        capability_id="acct.invoice.customer_create.v1",
        parameters={"company_id": 7, "invoice_date": "2026-07-13", "currency_id": 12},
        user_id=42,
        company_id=7,
        idempotency_key="idem-1",
        **RUNTIME_BINDING,
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
        approval_ttl_seconds=900,
        secret=SECRET,
    )


class OperationTest(unittest.TestCase):
    def test_digest_is_stable_across_parameter_order(self) -> None:
        first = awaiting_operation()
        second = Operation.prepare(
            operation_id="op-2",
            request_id="request-2",
            capability_id=first.capability_id,
            parameters={"currency_id": 12, "invoice_date": "2026-07-13", "company_id": 7},
            user_id=42,
            company_id=7,
            idempotency_key="idem-1",
            **RUNTIME_BINDING,
        )
        self.assertEqual(first.digest, second.digest)

    def test_digest_changes_when_business_content_changes(self) -> None:
        operation = awaiting_operation()
        changed = Operation.prepare(
            operation_id="op-2", request_id="request-2", capability_id=operation.capability_id,
            parameters={**operation.parameters, "invoice_date": "2026-07-14"},
            user_id=operation.user_id, company_id=operation.company_id,
            idempotency_key=operation.idempotency_key,
            **RUNTIME_BINDING,
        )
        self.assertNotEqual(operation.digest, changed.digest)

    def test_digest_changes_across_database_and_release_bindings(self) -> None:
        operation = awaiting_operation()
        other_database = Operation.prepare(
            operation_id="op-db", request_id="request-db", capability_id=operation.capability_id,
            parameters=operation.parameters, user_id=operation.user_id, company_id=operation.company_id,
            idempotency_key=operation.idempotency_key, principal=operation.principal,
            odoo_instance_id="odoo19@tokyo2", database_name="odoo_test",
            database_uuid="22222222-2222-4222-8222-222222222222", environment="test",
            registry_digest=REGISTRY_DIGEST, release_digest=RELEASE_DIGEST,
        )
        other_release = Operation.prepare(
            operation_id="op-release", request_id="request-release", capability_id=operation.capability_id,
            parameters=operation.parameters, user_id=operation.user_id, company_id=operation.company_id,
            idempotency_key=operation.idempotency_key, principal=operation.principal,
            odoo_instance_id="odoo19@tokyo2", database_name="odoo_test",
            database_uuid=DATABASE_UUID, environment="test",
            registry_digest=REGISTRY_DIGEST, release_digest="e" * 64,
        )
        self.assertNotEqual(operation.digest, other_database.digest)
        self.assertNotEqual(operation.digest, other_release.digest)

    def test_prepared_parameters_are_detached_and_immutable(self) -> None:
        parameters = {"company_id": 7, "lines": [{"amount": "100.00"}]}
        operation = Operation.prepare(
            operation_id="op-detached", request_id="request-detached",
            capability_id="acct.invoice.customer_create.v1",
            parameters=parameters, user_id=42, company_id=7, idempotency_key="idem-detached",
            **RUNTIME_BINDING,
        )
        parameters["lines"][0]["amount"] = "999.00"
        returned = operation.parameters
        returned["lines"][0]["amount"] = "888.00"
        self.assertEqual(operation.parameters["lines"][0]["amount"], "100.00")

    def test_post_prepare_content_and_runtime_binding_tampering_are_rejected(self) -> None:
        operation = awaiting_operation()
        changed_parameters = replace(
            operation,
            parameters_json='{"company_id":7,"invoice_date":"2026-07-13","total":"999999"}',
        )
        changed_database = replace(
            operation,
            database_name="production",
            database_uuid="22222222-2222-4222-8222-222222222222",
            environment="production",
        )
        for tampered in (changed_parameters, changed_database):
            with self.assertRaisesRegex(IntegrityRejected, "digest mismatch"):
                sign_approval(
                    operation=tampered, approver_user_id=99, nonce="tampered",
                    issued_at=NOW, expires_at=NOW + timedelta(minutes=1),
                    approval_ttl_seconds=900, secret=SECRET,
                )

    def test_approval_succeeds_once(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        consumed: set[str] = set()

        def consume(nonce: str, operation_id: str, revision: int) -> bool:
            self.assertEqual((operation_id, revision), (operation.operation_id, 2))
            if nonce in consumed:
                return False
            consumed.add(nonce)
            return True

        approved = approve_operation(
            operation, approval, now=NOW, secret=SECRET,
            is_approver_authorized=AUTHORIZED, consume_nonce=consume,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        self.assertEqual(approved.state, State.APPROVED)
        self.assertEqual(approved.approval_expires_at, approval.expires_at)
        self.assertEqual(approved.approver_user_id, 99)
        with self.assertRaisesRegex(ApprovalRejected, "already consumed"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED, consume_nonce=consume,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_expired_approval_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = sign_approval(
            operation=operation, approver_user_id=99, nonce="expired",
            issued_at=NOW - timedelta(minutes=20), expires_at=NOW - timedelta(minutes=10),
            approval_ttl_seconds=900, secret=SECRET,
        )
        with self.assertRaisesRegex(ApprovalRejected, "not currently valid"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_tampered_digest_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), operation_digest="0" * 64)
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_cross_company_approval_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), company_id=8)
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_wrong_user_approval_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), user_id=43)
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_signature_tampering_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), signature="f" * 64)
        with self.assertRaisesRegex(ApprovalRejected, "signature mismatch"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_direct_approval_transition_is_guarded(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(OperationError, "requires approve_operation"):
            operation.transition(State.APPROVED, expected_revision=2)

    def test_approval_ttl_is_bounded(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(ApprovalRejected, "maximum TTL"):
            sign_approval(
                operation=operation, approver_user_id=99, nonce="long-lived",
                issued_at=NOW, expires_at=NOW + MAX_APPROVAL_TTL + timedelta(seconds=1),
                approval_ttl_seconds=900, secret=SECRET,
            )

    def test_capability_policy_ttl_is_enforced(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(ApprovalRejected, "capability policy TTL"):
            sign_approval(
                operation=operation, approver_user_id=99, nonce="payment-policy",
                issued_at=NOW, expires_at=NOW + timedelta(seconds=601),
                approval_ttl_seconds=600, secret=SECRET,
            )

    def test_requester_cannot_approve_their_own_operation(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(ApprovalRejected, "own operation"):
            sign_approval(
                operation=operation, approver_user_id=operation.user_id, nonce="self",
                issued_at=NOW, expires_at=NOW + timedelta(minutes=1),
                approval_ttl_seconds=900, secret=SECRET,
            )

    def test_unauthorized_approver_is_rejected_without_consuming_nonce(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        consumed: list[str] = []
        with self.assertRaisesRegex(ApprovalRejected, "not authorized"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=lambda *_: False,
                consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                approval_ttl_seconds=900,
                expected_revision=2,
            )
        self.assertEqual(consumed, [])

    def test_invalid_approval_content_does_not_consume_nonce(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), nonce="")
        consumed: list[str] = []
        with self.assertRaisesRegex(ApprovalRejected, "nonce"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                approval_ttl_seconds=900,
                expected_revision=2,
            )
        self.assertEqual(consumed, [])

    def test_stale_approval_revision_does_not_consume_nonce(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        consumed: list[str] = []
        with self.assertRaises(ConcurrentUpdate):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                approval_ttl_seconds=900,
                expected_revision=1,
            )
        self.assertEqual(consumed, [])

    def test_stale_revision_is_rejected(self) -> None:
        operation = awaiting_operation()
        with self.assertRaises(ConcurrentUpdate):
            operation.transition(State.APPROVED, expected_revision=1)

    def test_invalid_transition_is_rejected(self) -> None:
        operation = awaiting_operation()
        with self.assertRaises(OperationError):
            operation.transition(State.COMPLETED, expected_revision=2)

    def test_execution_requires_the_stored_current_approval(self) -> None:
        operation = awaiting_operation()
        approval = sign_approval(
            operation=operation, approver_user_id=99, nonce="short-lived",
            issued_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=1),
            approval_ttl_seconds=900, secret=SECRET,
        )
        approved = approve_operation(
            operation, approval, now=NOW, secret=SECRET,
            is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
            approval_ttl_seconds=900, expected_revision=2,
        )
        with self.assertRaisesRegex(OperationError, "requires begin_execution"):
            approved.transition(State.EXECUTING, expected_revision=3)
        with self.assertRaisesRegex(ApprovalRejected, "expired before execution"):
            begin_execution(
                approved, approval, now=NOW + timedelta(minutes=2), secret=SECRET,
                is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
                expected_revision=3,
            )
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            begin_execution(
                approved, replace(approval, nonce="different"), now=NOW, secret=SECRET,
                is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
                expected_revision=3,
            )

    def test_completion_requires_verification(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        operation = approve_operation(
            operation, approval, now=NOW, secret=SECRET,
            is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        operation = begin_execution(
            operation, approval, now=NOW, secret=SECRET,
            is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
            expected_revision=3,
        )
        with self.assertRaisesRegex(OperationError, "requires record_execution_result"):
            operation.transition(State.VERIFYING, expected_revision=4)

        execution = sign_execution_result(
            operation=operation, issuer="odoo-adapter", succeeded=True,
            evidence_digest="a" * 64, issued_at=NOW, secret=SECRET,
        )
        operation = record_execution_result(
            operation, execution, now=NOW, secret=SECRET, expected_revision=4,
        )
        with self.assertRaisesRegex(OperationError, "requires complete_operation"):
            operation.transition(State.COMPLETED, expected_revision=5)

        verification = sign_verification_result(
            operation=operation, issuer="odoo-verifier", succeeded=True,
            evidence_digest="b" * 64, issued_at=NOW, secret=SECRET,
        )
        operation = complete_operation(
            operation, verification, now=NOW, secret=SECRET, expected_revision=5,
        )
        self.assertEqual(operation.state, State.COMPLETED)
        self.assertEqual(operation.execution_result_digest, "a" * 64)
        self.assertEqual(operation.verification_result_digest, "b" * 64)

    def test_tampered_execution_result_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        operation = approve_operation(
            operation, approval, now=NOW, secret=SECRET,
            is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        operation = begin_execution(
            operation, approval, now=NOW, secret=SECRET,
            is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
            expected_revision=3,
        )
        result = replace(
            sign_execution_result(
                operation=operation, issuer="odoo-adapter", succeeded=True,
                evidence_digest="a" * 64, issued_at=NOW, secret=SECRET,
            ),
            evidence_digest="b" * 64,
        )
        with self.assertRaisesRegex(TrustedResultRejected, "signature mismatch"):
            record_execution_result(
                operation, result, now=NOW, secret=SECRET, expected_revision=4,
            )


if __name__ == "__main__":
    unittest.main()

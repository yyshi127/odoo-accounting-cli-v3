import hashlib
import hmac
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
    ResultKind,
    State,
    TrustedResultRejected,
    approve_operation,
    begin_execution,
    canonical_json,
    complete_operation,
    record_execution_result,
    sign_approval,
    sign_execution_result,
    sign_verification_result,
)


APPROVAL_SECRET = b"a" * 32
APPROVAL_KEY_ID = "approval-key-v1"
EXECUTION_SECRET = b"e" * 32
VERIFICATION_SECRET = b"v" * 32
SECRET = APPROVAL_SECRET
EXECUTION_KEY_ID = "execution-key-v1"
VERIFICATION_KEY_ID = "verification-key-v1"
EXECUTION_ISSUERS = frozenset({"odoo-adapter"})
VERIFICATION_ISSUERS = frozenset({"odoo-verifier"})
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
        key_id=APPROVAL_KEY_ID,
        secret=SECRET,
    )


def executing_operation() -> Operation:
    operation = awaiting_operation()
    approval = valid_approval(operation)
    operation = approve_operation(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=AUTHORIZED,
        consume_nonce=lambda *_: True,
        approval_ttl_seconds=900,
        expected_revision=2,
    )
    return begin_execution(
        operation,
        approval,
        now=NOW,
        secret=APPROVAL_SECRET,
        expected_key_id=APPROVAL_KEY_ID,
        is_approver_authorized=AUTHORIZED,
        approval_ttl_seconds=900,
        expected_revision=3,
    )


class OperationTest(unittest.TestCase):
    def test_approval_protocol_metadata_and_expected_key_are_enforced(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        self.assertEqual(approval.signature_version, 2)
        self.assertEqual(approval.signature_purpose, "approval_v2")
        self.assertEqual(approval.key_id, APPROVAL_KEY_ID)

        for changed, message in (
            (replace(approval, signature_version=1), "version"),
            (replace(approval, signature_purpose="read_receipt_v1"), "purpose"),
            (replace(approval, key_id="retired-key"), "key ID"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ApprovalRejected, message):
                    approve_operation(
                        operation,
                        changed,
                        now=NOW,
                        secret=APPROVAL_SECRET,
                        expected_key_id=APPROVAL_KEY_ID,
                        is_approver_authorized=AUTHORIZED,
                        consume_nonce=lambda *_: True,
                        approval_ttl_seconds=900,
                        expected_revision=2,
                    )

        with self.assertRaisesRegex(ApprovalRejected, "key ID"):
            approve_operation(
                operation,
                approval,
                now=NOW,
                secret=APPROVAL_SECRET,
                expected_key_id="approval-key-retired",
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_preapproval_state_cannot_carry_forged_approval_metadata(self) -> None:
        operation = awaiting_operation()
        forged = replace(
            operation,
            state=State.PRECHECKED,
            revision=1,
            approval_signature="a" * 64,
            approval_nonce_digest="b" * 64,
            approval_issued_at=NOW - timedelta(minutes=1),
            approval_expires_at=NOW + timedelta(minutes=1),
            approval_revision=1,
            approver_user_id=99,
        )
        with self.assertRaisesRegex(IntegrityRejected, "state metadata"):
            forged.assert_integrity()

    def test_approval_signature_is_purpose_bound(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        self.assertEqual(approval.payload()["purpose"], "approval_v2")
        self.assertEqual(approval.payload()["version"], 2)
        wrong_payload = {**approval.payload(), "purpose": "execution_result_v1"}
        wrong_signature = hmac.new(
            APPROVAL_SECRET, canonical_json(wrong_payload), hashlib.sha256
        ).hexdigest()
        with self.assertRaisesRegex(ApprovalRejected, "signature mismatch"):
            approve_operation(
                operation,
                replace(approval, signature=wrong_signature),
                now=NOW,
                secret=APPROVAL_SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_approval_secret_must_be_32_byte_bytes(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        for invalid in (b"short", "x" * 32, b""):
            with self.subTest(secret=invalid):
                with self.assertRaisesRegex(ApprovalRejected, "at least 32 bytes"):
                    sign_approval(
                        operation=operation,
                        approver_user_id=99,
                        nonce="invalid-secret",
                        issued_at=NOW,
                        expires_at=NOW + timedelta(minutes=1),
                        approval_ttl_seconds=900,
                        key_id=APPROVAL_KEY_ID,
                        secret=invalid,
                    )
                with self.assertRaisesRegex(ApprovalRejected, "at least 32 bytes"):
                    approve_operation(
                        operation,
                        approval,
                        now=NOW,
                        secret=invalid,
                        expected_key_id=APPROVAL_KEY_ID,
                        is_approver_authorized=AUTHORIZED,
                        consume_nonce=lambda *_: True,
                        approval_ttl_seconds=900,
                        expected_revision=2,
                    )

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

    def test_integrity_rechecks_unhashed_operation_identifiers(self) -> None:
        operation = awaiting_operation()
        for field in ("operation_id", "request_id"):
            with self.subTest(field=field), self.assertRaisesRegex(
                IntegrityRejected, "immutable content is invalid"
            ):
                replace(operation, **{field: ""}).assert_integrity()

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
                    approval_ttl_seconds=900, key_id=APPROVAL_KEY_ID, secret=SECRET,
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
            expected_key_id=APPROVAL_KEY_ID,
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
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED, consume_nonce=consume,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_expired_approval_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = sign_approval(
            operation=operation, approver_user_id=99, nonce="expired",
            issued_at=NOW - timedelta(minutes=20), expires_at=NOW - timedelta(minutes=10),
            approval_ttl_seconds=900, key_id=APPROVAL_KEY_ID, secret=SECRET,
        )
        with self.assertRaisesRegex(ApprovalRejected, "not currently valid"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
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
                expected_key_id=APPROVAL_KEY_ID,
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
                expected_key_id=APPROVAL_KEY_ID,
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
                expected_key_id=APPROVAL_KEY_ID,
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
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_direct_approval_transition_is_guarded(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(OperationError, "requires approve_operation"):
            operation.transition(State.APPROVED, expected_revision=2)

    def test_direct_failure_transition_is_guarded(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(OperationError, "requires record_failure"):
            operation.transition(State.FAILED, expected_revision=2)

    def test_direct_recovery_transitions_are_guarded(self) -> None:
        failed = awaiting_operation()._apply_transition(State.FAILED)
        with self.assertRaisesRegex(OperationError, "requires begin_recovery"):
            failed.transition(State.RECOVERING, expected_revision=3)

        recovering = failed._apply_transition(State.RECOVERING)
        with self.assertRaisesRegex(OperationError, "requires complete_recovery"):
            recovering.transition(State.RECOVERED, expected_revision=4)

    def test_approval_ttl_is_bounded(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(ApprovalRejected, "maximum TTL"):
            sign_approval(
                operation=operation, approver_user_id=99, nonce="long-lived",
                issued_at=NOW, expires_at=NOW + MAX_APPROVAL_TTL + timedelta(seconds=1),
                approval_ttl_seconds=900, key_id=APPROVAL_KEY_ID, secret=SECRET,
            )

    def test_capability_policy_ttl_is_enforced(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(ApprovalRejected, "capability policy TTL"):
            sign_approval(
                operation=operation, approver_user_id=99, nonce="payment-policy",
                issued_at=NOW, expires_at=NOW + timedelta(seconds=601),
                approval_ttl_seconds=600, key_id=APPROVAL_KEY_ID, secret=SECRET,
            )

    def test_requester_cannot_approve_their_own_operation(self) -> None:
        operation = awaiting_operation()
        with self.assertRaisesRegex(ApprovalRejected, "own operation"):
            sign_approval(
                operation=operation, approver_user_id=operation.user_id, nonce="self",
                issued_at=NOW, expires_at=NOW + timedelta(minutes=1),
                approval_ttl_seconds=900, key_id=APPROVAL_KEY_ID, secret=SECRET,
            )

    def test_unauthorized_approver_is_rejected_without_consuming_nonce(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        consumed: list[str] = []
        with self.assertRaisesRegex(ApprovalRejected, "not authorized"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=lambda *_: False,
                consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                approval_ttl_seconds=900,
                expected_revision=2,
            )
        self.assertEqual(consumed, [])

    def test_approver_authorization_must_return_literal_true(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        consumed: list[str] = []

        for authorization_result in (1, "yes", object()):
            with self.subTest(authorization_result=authorization_result):
                with self.assertRaisesRegex(ApprovalRejected, "not authorized"):
                    approve_operation(
                        operation,
                        approval,
                        now=NOW,
                        secret=SECRET,
                        expected_key_id=APPROVAL_KEY_ID,
                        is_approver_authorized=lambda *_: authorization_result,
                        consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                        approval_ttl_seconds=900,
                        expected_revision=2,
                    )
        self.assertEqual(consumed, [])

        approved = approve_operation(
            operation,
            approval,
            now=NOW,
            secret=SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=AUTHORIZED,
            consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        with self.assertRaisesRegex(ApprovalRejected, "no longer authorized"):
            begin_execution(
                approved,
                approval,
                now=NOW,
                secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=lambda *_: 1,
                approval_ttl_seconds=900,
                expected_revision=3,
            )

    def test_stored_approval_metadata_enforces_ttl_separation_and_revision(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        approved = approve_operation(
            operation,
            approval,
            now=NOW,
            secret=SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=AUTHORIZED,
            consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )

        for forged in (
            replace(
                approved,
                approval_expires_at=(
                    approved.approval_issued_at
                    + MAX_APPROVAL_TTL
                    + timedelta(seconds=1)
                ),
            ),
            replace(approved, approver_user_id=approved.user_id),
            replace(approved, approval_revision=approved.revision),
        ):
            with self.subTest(forged=forged):
                with self.assertRaisesRegex(IntegrityRejected, "state metadata"):
                    forged.assert_integrity()

    def test_invalid_approval_content_does_not_consume_nonce(self) -> None:
        operation = awaiting_operation()
        approval = replace(valid_approval(operation), nonce="")
        consumed: list[str] = []
        with self.assertRaisesRegex(ApprovalRejected, "nonce"):
            approve_operation(
                operation, approval, now=NOW, secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
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
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                approval_ttl_seconds=900,
                expected_revision=1,
            )
        self.assertEqual(consumed, [])

    def test_expected_revision_and_signed_binding_integers_are_strict(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        consumed: list[str] = []

        with self.assertRaisesRegex(ConcurrentUpdate, "revision"):
            approve_operation(
                operation,
                approval,
                now=NOW,
                secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                approval_ttl_seconds=900,
                expected_revision=2.0,
            )

        changed = replace(approval, operation_revision=2.0, signature="")
        changed = replace(
            changed,
            signature=hmac.new(
                SECRET, canonical_json(changed.payload()), hashlib.sha256
            ).hexdigest(),
        )
        with self.assertRaisesRegex(ApprovalRejected, "content"):
            approve_operation(
                operation,
                changed,
                now=NOW,
                secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda nonce, *_: consumed.append(nonce) is None,
                approval_ttl_seconds=900,
                expected_revision=2,
            )
        self.assertEqual(consumed, [])

    def test_nonce_consumer_must_return_literal_true(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        with self.assertRaisesRegex(ApprovalRejected, "durably consumed"):
            approve_operation(
                operation,
                approval,
                now=NOW,
                secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED,
                consume_nonce=lambda *_: 1,
                approval_ttl_seconds=900,
                expected_revision=2,
            )

    def test_stale_revision_is_rejected(self) -> None:
        operation = awaiting_operation()
        with self.assertRaises(ConcurrentUpdate):
            operation.transition(State.APPROVED, expected_revision=1)

    def test_invalid_transition_is_rejected(self) -> None:
        operation = awaiting_operation()
        with self.assertRaises(OperationError):
            operation.transition(State.COMPLETED, expected_revision=2)

    def test_transition_target_must_be_an_exact_state(self) -> None:
        prepared = replace(
            awaiting_operation(), state=State.PREPARED, revision=0
        )
        with self.assertRaisesRegex(OperationError, "target.*State"):
            prepared.transition(State.PRECHECKED.value, expected_revision=0)

    def test_execution_requires_the_stored_current_approval(self) -> None:
        operation = awaiting_operation()
        approval = sign_approval(
            operation=operation, approver_user_id=99, nonce="short-lived",
            issued_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=1),
            approval_ttl_seconds=900, key_id=APPROVAL_KEY_ID, secret=SECRET,
        )
        approved = approve_operation(
            operation, approval, now=NOW, secret=SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
            approval_ttl_seconds=900, expected_revision=2,
        )
        with self.assertRaisesRegex(OperationError, "requires begin_execution"):
            approved.transition(State.EXECUTING, expected_revision=3)
        with self.assertRaisesRegex(ApprovalRejected, "expired before execution"):
            begin_execution(
                approved, approval, now=NOW + timedelta(minutes=2), secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
                expected_revision=3,
            )
        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            begin_execution(
                approved, replace(approval, nonce="different"), now=NOW, secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
                expected_revision=3,
            )

        with self.assertRaisesRegex(ApprovalRejected, "binding mismatch"):
            begin_execution(
                replace(approved, request_id="tampered-request"),
                approval,
                now=NOW,
                secret=SECRET,
                expected_key_id=APPROVAL_KEY_ID,
                is_approver_authorized=AUTHORIZED,
                approval_ttl_seconds=900,
                expected_revision=3,
            )

        with self.assertRaisesRegex(IntegrityRejected, "state metadata"):
            replace(approved, state=State.EXECUTING, revision=999).assert_integrity()

    def test_completion_requires_verification(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        operation = approve_operation(
            operation, approval, now=NOW, secret=SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        operation = begin_execution(
            operation, approval, now=NOW, secret=SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
            expected_revision=3,
        )
        with self.assertRaisesRegex(OperationError, "requires record_execution_result"):
            operation.transition(State.VERIFYING, expected_revision=4)

        execution = sign_execution_result(
            operation=operation, issuer="odoo-adapter", key_id=EXECUTION_KEY_ID,
            succeeded=True, evidence_digest="a" * 64, issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        operation = record_execution_result(
            operation, execution, now=NOW, secret=EXECUTION_SECRET,
            expected_key_id=EXECUTION_KEY_ID, allowed_issuers=EXECUTION_ISSUERS,
            expected_revision=4,
        )
        with self.assertRaisesRegex(OperationError, "requires complete_operation"):
            operation.transition(State.COMPLETED, expected_revision=5)

        verification = sign_verification_result(
            operation=operation, issuer="odoo-verifier", key_id=VERIFICATION_KEY_ID,
            succeeded=True, evidence_digest="b" * 64, issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        operation = complete_operation(
            operation, verification, now=NOW, secret=VERIFICATION_SECRET,
            expected_key_id=VERIFICATION_KEY_ID,
            allowed_issuers=VERIFICATION_ISSUERS, expected_revision=5,
        )
        self.assertEqual(operation.state, State.COMPLETED)
        self.assertEqual(operation.execution_result_digest, "a" * 64)
        self.assertEqual(operation.verification_result_digest, "b" * 64)

    def test_tampered_execution_result_is_rejected(self) -> None:
        operation = awaiting_operation()
        approval = valid_approval(operation)
        operation = approve_operation(
            operation, approval, now=NOW, secret=SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=AUTHORIZED, consume_nonce=lambda *_: True,
            approval_ttl_seconds=900,
            expected_revision=2,
        )
        operation = begin_execution(
            operation, approval, now=NOW, secret=SECRET,
            expected_key_id=APPROVAL_KEY_ID,
            is_approver_authorized=AUTHORIZED, approval_ttl_seconds=900,
            expected_revision=3,
        )
        result = replace(
            sign_execution_result(
                operation=operation, issuer="odoo-adapter", key_id=EXECUTION_KEY_ID,
                succeeded=True, evidence_digest="a" * 64, issued_at=NOW,
                secret=EXECUTION_SECRET,
            ),
            evidence_digest="b" * 64,
        )
        with self.assertRaisesRegex(TrustedResultRejected, "signature mismatch"):
            record_execution_result(
                operation, result, now=NOW, secret=EXECUTION_SECRET,
                expected_key_id=EXECUTION_KEY_ID,
                allowed_issuers=EXECUTION_ISSUERS, expected_revision=4,
            )
        with self.assertRaisesRegex(TrustedResultRejected, "content is invalid"):
            record_execution_result(
                operation,
                replace(result, evidence_digest="a" * 64, signature=None),
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id=EXECUTION_KEY_ID,
                allowed_issuers=EXECUTION_ISSUERS,
                expected_revision=4,
            )

    def test_result_protocol_binds_request_and_full_operation_state(self) -> None:
        operation = executing_operation()
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-adapter",
            key_id=EXECUTION_KEY_ID,
            succeeded=True,
            evidence_digest="a" * 64,
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        self.assertEqual(result.request_id, operation.request_id)

        for tampered in (
            replace(operation, request_id="different-request"),
            replace(operation, approval_signature="f" * 64),
        ):
            with self.subTest(tampered=tampered), self.assertRaisesRegex(
                TrustedResultRejected, "binding mismatch"
            ):
                record_execution_result(
                    tampered,
                    result,
                    now=NOW,
                    secret=EXECUTION_SECRET,
                    expected_key_id=EXECUTION_KEY_ID,
                    allowed_issuers=EXECUTION_ISSUERS,
                    expected_revision=4,
                )

    def test_result_protocol_rejects_signed_type_confusion(self) -> None:
        operation = executing_operation()
        result = sign_execution_result(
            operation=operation,
            issuer="odoo-adapter",
            key_id=EXECUTION_KEY_ID,
            succeeded=True,
            evidence_digest="a" * 64,
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        for changes in (
            {"kind": ResultKind.EXECUTION.value},
            {"company_id": float(operation.company_id)},
            {"operation_revision": float(operation.revision)},
            {"signature_version": True},
        ):
            malformed = replace(result, **changes)
            malformed = replace(
                malformed,
                signature=hmac.new(
                    EXECUTION_SECRET,
                    canonical_json(malformed.payload()),
                    hashlib.sha256,
                ).hexdigest(),
            )
            with self.subTest(changes=changes), self.assertRaisesRegex(
                TrustedResultRejected, "content is invalid"
            ):
                record_execution_result(
                    operation,
                    malformed,
                    now=NOW,
                    secret=EXECUTION_SECRET,
                    expected_key_id=EXECUTION_KEY_ID,
                    allowed_issuers=EXECUTION_ISSUERS,
                    expected_revision=4,
                )

    def test_result_signatures_are_purpose_and_role_bound(self) -> None:
        operation = executing_operation()
        execution = sign_execution_result(
            operation=operation,
            issuer="odoo-adapter",
            key_id=EXECUTION_KEY_ID,
            succeeded=True,
            evidence_digest="a" * 64,
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        self.assertEqual(execution.payload()["purpose"], "execution_result_v2")
        self.assertEqual(execution.payload()["version"], 2)
        wrong_payload = {**execution.payload(), "purpose": "verification_result_v2"}
        wrong_signature = hmac.new(
            EXECUTION_SECRET, canonical_json(wrong_payload), hashlib.sha256
        ).hexdigest()
        with self.assertRaisesRegex(TrustedResultRejected, "signature mismatch"):
            record_execution_result(
                operation,
                replace(execution, signature=wrong_signature),
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id=EXECUTION_KEY_ID,
                allowed_issuers=EXECUTION_ISSUERS,
                expected_revision=4,
            )
        operation = record_execution_result(
            operation,
            execution,
            now=NOW,
            secret=EXECUTION_SECRET,
            expected_key_id=EXECUTION_KEY_ID,
            allowed_issuers=EXECUTION_ISSUERS,
            expected_revision=4,
        )
        verification = sign_verification_result(
            operation=operation,
            issuer="odoo-verifier",
            key_id=VERIFICATION_KEY_ID,
            succeeded=True,
            evidence_digest="b" * 64,
            issued_at=NOW,
            secret=VERIFICATION_SECRET,
        )
        self.assertEqual(verification.payload()["purpose"], "verification_result_v2")
        self.assertEqual(verification.payload()["version"], 2)

        with self.assertRaisesRegex(TrustedResultRejected, "key ID mismatch"):
            complete_operation(
                operation,
                verification,
                now=NOW,
                secret=VERIFICATION_SECRET,
                expected_key_id=EXECUTION_KEY_ID,
                allowed_issuers=VERIFICATION_ISSUERS,
                expected_revision=5,
            )
        with self.assertRaisesRegex(TrustedResultRejected, "signature mismatch"):
            complete_operation(
                operation,
                verification,
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id=VERIFICATION_KEY_ID,
                allowed_issuers=VERIFICATION_ISSUERS,
                expected_revision=5,
            )

    def test_unauthorized_result_issuer_is_rejected(self) -> None:
        operation = executing_operation()
        result = sign_execution_result(
            operation=operation,
            issuer="untrusted-adapter",
            key_id=EXECUTION_KEY_ID,
            succeeded=True,
            evidence_digest="a" * 64,
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        with self.assertRaisesRegex(TrustedResultRejected, "issuer is not authorized"):
            record_execution_result(
                operation,
                result,
                now=NOW,
                secret=EXECUTION_SECRET,
                expected_key_id=EXECUTION_KEY_ID,
                allowed_issuers=EXECUTION_ISSUERS,
                expected_revision=4,
            )

    def test_result_secret_must_be_32_byte_bytes(self) -> None:
        operation = executing_operation()
        valid = sign_execution_result(
            operation=operation,
            issuer="odoo-adapter",
            key_id=EXECUTION_KEY_ID,
            succeeded=True,
            evidence_digest="a" * 64,
            issued_at=NOW,
            secret=EXECUTION_SECRET,
        )
        for invalid in (b"short", "x" * 32, b""):
            with self.subTest(secret=invalid):
                with self.assertRaisesRegex(TrustedResultRejected, "at least 32 bytes"):
                    sign_execution_result(
                        operation=operation,
                        issuer="odoo-adapter",
                        key_id=EXECUTION_KEY_ID,
                        succeeded=True,
                        evidence_digest="a" * 64,
                        issued_at=NOW,
                        secret=invalid,
                    )
                with self.assertRaisesRegex(TrustedResultRejected, "at least 32 bytes"):
                    record_execution_result(
                        operation,
                        valid,
                        now=NOW,
                        secret=invalid,
                        expected_key_id=EXECUTION_KEY_ID,
                        allowed_issuers=EXECUTION_ISSUERS,
                        expected_revision=4,
                    )


if __name__ == "__main__":
    unittest.main()

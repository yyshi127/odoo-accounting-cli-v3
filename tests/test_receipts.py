import copy
import hashlib
import hmac
import unittest
from datetime import datetime, timedelta, timezone

from odoo_accounting_cli_v3.receipts import ReceiptError, create_read_receipt, verify_read_receipt
from odoo_accounting_cli_v3.operations import canonical_json


SECRET = b"test-only-receipt-secret-32-byte"
KEY_ID = "read-receipt-key-2026-07"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)
BINDINGS = {
    "capability_id": "acct.gl.trial_balance.v1",
    "parameters": {"company_id": 1, "date_from": "2026-01-01", "date_to": "2026-12-31"},
    "auth_token_id": "auth-token-1",
    "principal": "pi:test-user-42",
    "odoo_instance_id": "odoo19@tokyo2",
    "database_name": "odoo_test",
    "database_uuid": "11111111-1111-4111-8111-111111111111",
    "company_id": 1,
    "user_id": 42,
    "registry_digest": "c" * 64,
    "release_digest": "d" * 64,
}


def signed_receipt(result_body, *, observed_at=NOW, record_count=1, receipt_id="receipt-1"):
    return create_read_receipt(
        receipt_id=receipt_id,
        result_body=result_body,
        record_count=record_count,
        observed_at=observed_at,
        key_id=KEY_ID,
        secret=SECRET,
        **BINDINGS,
    )


def verify(
    receipt,
    body,
    *,
    expected_record_count=1,
    now=NOW,
    consume_receipt=None,
    expected_key_id=KEY_ID,
    secret=SECRET,
    **changes,
):
    bindings = {**BINDINGS, **changes}
    verify_read_receipt(
        receipt,
        result_body=body,
        expected_record_count=expected_record_count,
        now=now,
        consume_receipt=consume_receipt or (lambda *_: True),
        expected_key_id=expected_key_id,
        secret=secret,
        **bindings,
    )


class ReceiptTest(unittest.TestCase):
    def test_signed_read_receipt_verifies(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        receipt = signed_receipt(body)
        unsigned = {key: value for key, value in receipt.items() if key != "signature"}
        expected = hmac.new(
            SECRET, canonical_json(unsigned), hashlib.sha256
        ).hexdigest()
        self.assertEqual(receipt["signature"], expected)
        self.assertEqual(receipt["signature_version"], 1)
        self.assertEqual(receipt["signature_purpose"], "read_receipt_v1")
        self.assertEqual(receipt["signature_key_id"], KEY_ID)
        verify(receipt, body)

    def test_read_receipt_protocol_fields_are_verified_before_signature(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        receipt = signed_receipt(body)
        for field, value, message in (
            ("signature_version", 2, "version mismatch"),
            ("signature_purpose", "auth_context_v1", "purpose mismatch"),
            ("signature_key_id", "read-receipt-key-retired", "key ID mismatch"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ReceiptError, message):
                    verify({**receipt, field: value}, body)

    def test_receipt_key_id_is_required_and_expected_key_is_enforced(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        with self.assertRaisesRegex(ReceiptError, "key ID is required"):
            create_read_receipt(
                receipt_id="missing-key", result_body=body, record_count=1,
                observed_at=NOW, key_id="", secret=SECRET, **BINDINGS,
            )
        with self.assertRaisesRegex(ReceiptError, "expected key ID is required"):
            verify_read_receipt(
                signed_receipt(body), result_body=body, expected_record_count=1,
                now=NOW, consume_receipt=lambda *_: True, expected_key_id="",
                secret=SECRET, **BINDINGS,
            )
        with self.assertRaisesRegex(ReceiptError, "key ID mismatch"):
            verify_read_receipt(
                signed_receipt(body), result_body=body, expected_record_count=1,
                now=NOW, consume_receipt=lambda *_: True,
                expected_key_id="read-receipt-key-retired", secret=SECRET,
                **BINDINGS,
            )
        with self.assertRaisesRegex(ReceiptError, "signature mismatch"):
            verify(
                {**signed_receipt(body), "signature_key_id": "read-receipt-key-next"},
                body,
                expected_key_id="read-receipt-key-next",
            )

    def test_receipt_secret_must_be_32_byte_bytes(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        receipt = signed_receipt(body)
        for invalid in (b"short", "x" * 32, b""):
            with self.subTest(secret=invalid):
                with self.assertRaisesRegex(ReceiptError, "at least 32 bytes"):
                    verify(receipt, body, secret=invalid)
                with self.assertRaisesRegex(ReceiptError, "at least 32 bytes"):
                    create_read_receipt(
                        receipt_id="invalid-secret",
                        result_body=body,
                        record_count=1,
                        observed_at=NOW,
                        key_id=KEY_ID,
                        secret=invalid,
                        **BINDINGS,
                    )

    def test_fabricated_or_tampered_receipt_is_rejected(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        receipt = signed_receipt(body)
        tampered = copy.deepcopy(receipt)
        tampered["record_count"] = 99
        with self.assertRaisesRegex(ReceiptError, "record count"):
            verify(tampered, body)
        fabricated = {**receipt, "signature": "a" * 64}
        with self.assertRaisesRegex(ReceiptError, "signature mismatch"):
            verify(fabricated, body)

    def test_result_and_runtime_bindings_are_enforced(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        receipt = signed_receipt(body)
        with self.assertRaisesRegex(ReceiptError, "content digest mismatch"):
            verify(receipt, {"lines": []})
        with self.assertRaisesRegex(ReceiptError, "binding mismatch"):
            verify(receipt, body, release_digest="e" * 64)

    def test_stale_record_count_mismatch_and_replay_are_rejected(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        stale = signed_receipt(body, observed_at=NOW - timedelta(days=1))
        with self.assertRaisesRegex(ReceiptError, "stale"):
            verify(stale, body)

        wrong_count = signed_receipt(body, record_count=999, receipt_id="wrong-count")
        with self.assertRaisesRegex(ReceiptError, "record count"):
            verify(wrong_count, body, expected_record_count=1)

        consumed = set()

        observed = []

        def consume(receipt_id, request_digest, observed_at, verified_at):
            observed.append((observed_at, verified_at))
            key = (receipt_id, request_digest)
            if key in consumed:
                return False
            consumed.add(key)
            return True

        receipt = signed_receipt(body, receipt_id="one-time")
        verify(receipt, body, consume_receipt=consume)
        self.assertEqual(observed, [(NOW, NOW)])
        with self.assertRaisesRegex(ReceiptError, "already consumed"):
            verify(receipt, body, consume_receipt=consume)


if __name__ == "__main__":
    unittest.main()

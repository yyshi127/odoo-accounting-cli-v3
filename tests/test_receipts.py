import copy
import unittest
from datetime import datetime, timedelta, timezone

from odoo_accounting_cli_v3.receipts import ReceiptError, create_read_receipt, verify_read_receipt


SECRET = b"test-only-receipt-secret"
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
        secret=SECRET,
        **BINDINGS,
    )


def verify(receipt, body, *, expected_record_count=1, now=NOW, consume_receipt=None, **changes):
    bindings = {**BINDINGS, **changes}
    verify_read_receipt(
        receipt,
        result_body=body,
        expected_record_count=expected_record_count,
        now=now,
        consume_receipt=consume_receipt or (lambda *_: True),
        secret=SECRET,
        **bindings,
    )


class ReceiptTest(unittest.TestCase):
    def test_signed_read_receipt_verifies(self) -> None:
        body = {"lines": [{"account_id": 1}]}
        verify(signed_receipt(body), body)

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

        def consume(receipt_id, request_digest):
            key = (receipt_id, request_digest)
            if key in consumed:
                return False
            consumed.add(key)
            return True

        receipt = signed_receipt(body, receipt_id="one-time")
        verify(receipt, body, consume_receipt=consume)
        with self.assertRaisesRegex(ReceiptError, "already consumed"):
            verify(receipt, body, consume_receipt=consume)


if __name__ == "__main__":
    unittest.main()

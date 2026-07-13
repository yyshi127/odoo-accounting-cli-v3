import hashlib
import hmac
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from odoo_accounting_cli_v3.auth import (
    AuthenticationError,
    MAX_CONTEXT_TTL,
    authentication_request_digest,
    context_payload,
    sign_request_context,
    verify_request_context,
)
from odoo_accounting_cli_v3.operations import canonical_json


SECRET = b"test-only-auth-secret-32-bytes!!"
KEY_ID = "auth-key-2026-07"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)
CAPABILITY_ID = "acct.gl.trial_balance.v1"
PARAMETERS = {"company_id": 7, "date_from": "2026-01-01", "date_to": "2026-12-31"}


def signed_context(*, secret=SECRET):
    return sign_request_context(
        auth_token_id="token-1",
        principal="pi:user-42",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_test",
        database_uuid="11111111-1111-4111-8111-111111111111",
        user_id=42,
        company_id=7,
        allowed_company_ids=frozenset({7, 8}),
        environment="test",
        capability_id=CAPABILITY_ID,
        parameters=PARAMETERS,
        issued_at=NOW - timedelta(seconds=5),
        expires_at=NOW + timedelta(minutes=4),
        key_id=KEY_ID,
        secret=secret,
    )


class AuthenticationTest(unittest.TestCase):
    def test_signed_context_verifies(self) -> None:
        context = signed_context()
        expected = hmac.new(
            SECRET, canonical_json(context_payload(context)), hashlib.sha256
        ).hexdigest()
        self.assertEqual(context.auth_signature, expected)
        self.assertEqual(context.auth_signature_version, 1)
        self.assertEqual(context.auth_signature_purpose, "auth_context_v1")
        self.assertEqual(context.auth_key_id, KEY_ID)
        self.assertEqual(
            context.auth_request_digest,
            authentication_request_digest(CAPABILITY_ID, PARAMETERS),
        )
        self.assertTrue(
            verify_request_context(
                context, now=NOW, secret=SECRET, expected_key_id=KEY_ID
            )
        )

    def test_context_protocol_fields_are_verified_before_signature(self) -> None:
        context = signed_context()
        for field, value, message in (
            ("auth_signature_version", 2, "version mismatch"),
            ("auth_signature_purpose", "read_receipt_v1", "purpose mismatch"),
            ("auth_key_id", "auth-key-retired", "key ID mismatch"),
        ):
            with self.subTest(field=field):
                tampered = replace(context)
                object.__setattr__(tampered, field, value)
                with self.assertRaisesRegex(AuthenticationError, message):
                    verify_request_context(
                        tampered,
                        now=NOW,
                        secret=SECRET,
                        expected_key_id=KEY_ID,
                    )

    def test_context_key_id_is_required_and_expected_key_is_enforced(self) -> None:
        with self.assertRaisesRegex(AuthenticationError, "key ID is required"):
            sign_request_context(
                auth_token_id="token-1", principal="pi:user-42",
                odoo_instance_id="odoo19@tokyo2", database_name="odoo_test",
                database_uuid="11111111-1111-4111-8111-111111111111",
                user_id=42, company_id=7, allowed_company_ids=frozenset({7}),
                environment="test", capability_id=CAPABILITY_ID,
                parameters=PARAMETERS, issued_at=NOW,
                expires_at=NOW + timedelta(minutes=1), key_id="", secret=SECRET,
            )
        with self.assertRaisesRegex(AuthenticationError, "expected key ID is required"):
            verify_request_context(
                signed_context(), now=NOW, secret=SECRET, expected_key_id=""
            )
        with self.assertRaisesRegex(AuthenticationError, "key ID mismatch"):
            verify_request_context(
                signed_context(), now=NOW, secret=SECRET,
                expected_key_id="auth-key-retired",
            )
        with self.assertRaisesRegex(AuthenticationError, "signature mismatch"):
            verify_request_context(
                replace(signed_context(), auth_key_id="auth-key-next"),
                now=NOW, secret=SECRET, expected_key_id="auth-key-next",
            )

    def test_context_secret_must_be_32_byte_bytes(self) -> None:
        context = signed_context()
        for invalid in (b"short", "x" * 32, b""):
            with self.subTest(secret=invalid):
                with self.assertRaisesRegex(AuthenticationError, "at least 32 bytes"):
                    verify_request_context(
                        context, now=NOW, secret=invalid, expected_key_id=KEY_ID
                    )
                with self.assertRaisesRegex(AuthenticationError, "at least 32 bytes"):
                    signed_context(secret=invalid)

    def test_user_company_and_database_tampering_is_rejected(self) -> None:
        context = signed_context()
        for changed in (
            replace(context, user_id=43),
            replace(context, company_id=8),
            replace(context, database_uuid="22222222-2222-4222-8222-222222222222"),
        ):
            with self.assertRaisesRegex(AuthenticationError, "signature mismatch"):
                verify_request_context(
                    changed, now=NOW, secret=SECRET, expected_key_id=KEY_ID
                )

    def test_expired_and_overlong_contexts_are_rejected(self) -> None:
        context = signed_context()
        with self.assertRaisesRegex(AuthenticationError, "not currently valid"):
            verify_request_context(
                context, now=NOW + timedelta(minutes=10), secret=SECRET,
                expected_key_id=KEY_ID,
            )
        with self.assertRaisesRegex(AuthenticationError, "maximum TTL"):
            sign_request_context(
                auth_token_id="long", principal="pi:user-42",
                odoo_instance_id="odoo19@tokyo2", database_name="odoo_test",
                database_uuid=context.database_uuid, user_id=42, company_id=7,
                allowed_company_ids=frozenset({7}), environment="test",
                capability_id=CAPABILITY_ID, parameters=PARAMETERS,
                issued_at=NOW, expires_at=NOW + MAX_CONTEXT_TTL + timedelta(seconds=1),
                key_id=KEY_ID,
                secret=SECRET,
            )

    def test_request_content_digest_is_signed(self) -> None:
        context = signed_context()
        tampered = replace(context, auth_request_digest="c" * 64)
        with self.assertRaisesRegex(AuthenticationError, "signature mismatch"):
            verify_request_context(
                tampered, now=NOW, secret=SECRET, expected_key_id=KEY_ID
            )


if __name__ == "__main__":
    unittest.main()

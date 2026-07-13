import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from odoo_accounting_cli_v3.auth import (
    AuthenticationError,
    MAX_CONTEXT_TTL,
    sign_request_context,
    verify_request_context,
)


SECRET = b"test-only-auth-secret"
NOW = datetime(2026, 7, 13, 7, 0, tzinfo=timezone.utc)


def signed_context():
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
        issued_at=NOW - timedelta(seconds=5),
        expires_at=NOW + timedelta(minutes=4),
        secret=SECRET,
    )


class AuthenticationTest(unittest.TestCase):
    def test_signed_context_verifies(self) -> None:
        self.assertTrue(verify_request_context(signed_context(), now=NOW, secret=SECRET))

    def test_user_company_and_database_tampering_is_rejected(self) -> None:
        context = signed_context()
        for changed in (
            replace(context, user_id=43),
            replace(context, company_id=8),
            replace(context, database_uuid="22222222-2222-4222-8222-222222222222"),
        ):
            with self.assertRaisesRegex(AuthenticationError, "signature mismatch"):
                verify_request_context(changed, now=NOW, secret=SECRET)

    def test_expired_and_overlong_contexts_are_rejected(self) -> None:
        context = signed_context()
        with self.assertRaisesRegex(AuthenticationError, "not currently valid"):
            verify_request_context(context, now=NOW + timedelta(minutes=10), secret=SECRET)
        with self.assertRaisesRegex(AuthenticationError, "maximum TTL"):
            sign_request_context(
                auth_token_id="long", principal="pi:user-42",
                odoo_instance_id="odoo19@tokyo2", database_name="odoo_test",
                database_uuid=context.database_uuid, user_id=42, company_id=7,
                allowed_company_ids=frozenset({7}), environment="test",
                issued_at=NOW, expires_at=NOW + MAX_CONTEXT_TTL + timedelta(seconds=1),
                secret=SECRET,
            )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import importlib.util
import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "deployment" / "dev29" / "sign_read.py"
SPEC = importlib.util.spec_from_file_location("dev29_sign_read", PATH)
assert SPEC is not None and SPEC.loader is not None
signer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signer)


def plan() -> dict:
    common = {
        "principal": "pi:test-user-2",
        "user_id": 2,
        "company_id": 1,
        "allowed_company_ids": [1],
    }
    cases = []
    for name, capability in (
        ("registry", "acct.registry.list.v1"),
        ("trial_balance", "acct.gl.trial_balance.v1"),
        ("ar_open_items", "acct.ar.open_items.v1"),
        ("ap_open_items", "acct.ap.open_items.v1"),
        ("multicurrency", "acct.multicurrency.balance_read.v1"),
    ):
        cases.append(
            {
                "name": name,
                "capability_id": capability,
                **common,
                "parameters": {"company_id": 1, "limit": 500},
                "expected": {},
            }
        )
    negatives = [
        {
            "name": "acl_deny",
            "base_case": "trial_balance",
            "principal": "pi:test-user-5",
            "user_id": 5,
            "company_id": 1,
            "allowed_company_ids": [1],
            "mutation": {"kind": "identity_override", "fields": {}},
            "expected_error": "odoo_acl_denied",
        },
        {
            "name": "wrong_uuid",
            "base_case": "trial_balance",
            **common,
            "mutation": {
                "kind": "context_override",
                "fields": {"context.database_uuid": "00000000-0000-0000-0000-000000000000"},
            },
            "expected_error": "database_binding_rejected",
        },
        {
            "name": "expired",
            "base_case": "trial_balance",
            **common,
            "mutation": {"kind": "expire_after_sign", "fields": {"age_seconds": 600}},
            "expected_error": "authentication_expired",
        },
        {
            "name": "tamper",
            "base_case": "trial_balance",
            **common,
            "mutation": {
                "kind": "parameters_after_sign",
                "fields": {"parameters.limit": 1},
            },
            "expected_error": "authentication_tampered",
        },
        {
            "name": "replay",
            "base_case": "trial_balance",
            **common,
            "mutation": {"kind": "replay_exact_request", "fields": {}},
            "expected_error": "authentication_replayed",
        },
    ]
    return {
        "schema_version": 1,
        "target": {"host": "43.165.173.80", "instance_id": "odoo19@43.165.173.80"},
        "database": {
            "name": "odoo_test",
            "uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        },
        "runtime": {
            "odoo_python": "/odoo/python",
            "odoo_python_sha256": "1" * 64,
            "odoo_bin": "/odoo/bin",
            "odoo_bin_sha256": "2" * 64,
            "odoo_config": "/odoo/config",
            "odoo_config_sha256": "3" * 64,
        },
        "cases": cases,
        "negative_cases": negatives,
        "witness": {},
    }


def runtime() -> dict:
    return {
        "instance_id": "odoo19@43.165.173.80",
        "environment": "test",
        "capability_channel": "staged",
        "database_name": "odoo_test",
        "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
        "odoo_python": "/odoo/python",
        "odoo_python_sha256": "1" * 64,
        "odoo_bin": "/odoo/bin",
        "odoo_bin_sha256": "2" * 64,
        "odoo_config": "/odoo/config",
        "odoo_config_sha256": "3" * 64,
        "release_root": "/opt/odoo-accounting-cli-v3/releases/dev29",
        "canonical_package_path": "/opt/odoo-accounting-cli-v3/packages/dev29.tar.gz",
        "canonical_package_sha256": "4" * 64,
        "auth_state_path": "/state/auth.sqlite3",
        "receipt_state_path": "/state/receipt.sqlite3",
        "gcov_state_path": "/state/gcov",
        "auth_key_id": "test-auth-dev29-key",
        "receipt_key_id": "test-receipt-dev29-key",
        "auth_secret_path": "/secret/auth.hmac",
        "receipt_secret_path": "/secret/receipt.hmac",
    }


class FakeAuth:
    @staticmethod
    def sign_request_context(**kwargs):
        return SimpleNamespace(
            auth_signature="a" * 64,
            kwargs=kwargs,
        )

    @staticmethod
    def context_payload(context):
        values = context.kwargs
        return {
            "allowed_company_ids": sorted(values["allowed_company_ids"]),
            "audience": "odoo-accounting-cli-v3",
            "auth_expires_at": values["expires_at"].isoformat(),
            "auth_issued_at": values["issued_at"].isoformat(),
            "auth_key_id": values["key_id"],
            "auth_request_digest": "b" * 64,
            "auth_signature_purpose": "auth_context_v1",
            "auth_signature_version": 1,
            "auth_token_id": values["auth_token_id"],
            "company_id": values["company_id"],
            "database_name": values["database_name"],
            "database_uuid": values["database_uuid"],
            "environment": values["environment"],
            "principal": values["principal"],
            "odoo_instance_id": values["odoo_instance_id"],
            "user_id": values["user_id"],
        }


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)
TOKEN = "11111111-1111-4111-8111-111111111111"


def build(*, case_name=None, negative_name=None):
    return signer.build_signed_request(
        plan(),
        runtime(),
        b"s" * 32,
        case_name=case_name,
        negative_name=negative_name,
        now=NOW,
        token_factory=lambda: TOKEN,
        auth_module=FakeAuth,
    )


def test_positive_request_transports_exact_plan_and_runtime_identity():
    request = build(case_name="trial_balance")
    assert request["capability_id"] == "acct.gl.trial_balance.v1"
    assert request["parameters"] == {"company_id": 1, "limit": 500}
    assert request["context"]["database_uuid"] == runtime()["database_uuid"]
    assert request["context"]["company_id"] == 1
    assert request["context"]["allowed_company_ids"] == [1]
    assert request["context"]["auth_token_id"] == f"dev29-read-trial_balance-{TOKEN}"
    assert request["context"]["auth_signature"] == "a" * 64


def test_identity_database_expiry_and_parameter_mutations_are_exact():
    denied = build(negative_name="acl_deny")
    assert denied["context"]["user_id"] == 5
    assert denied["context"]["principal"] == "pi:test-user-5"

    wrong = build(negative_name="wrong_uuid")
    assert wrong["context"]["database_uuid"] == "00000000-0000-0000-0000-000000000000"

    expired = build(negative_name="expired")
    assert expired["context"]["auth_expires_at"] < NOW.isoformat()

    tampered = build(negative_name="tamper")
    assert tampered["parameters"]["limit"] == 1
    assert tampered["context"]["auth_request_digest"] == "b" * 64


def test_replay_is_not_resigned_and_uses_retained_positive_request():
    with pytest.raises(signer.Dev29SignerError, match="retained exact positive"):
        build(negative_name="replay")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(schema_version=True),
        lambda value: value.update(schema_version=2),
        lambda value: value["cases"].append(copy.deepcopy(value["cases"][0])),
        lambda value: value["negative_cases"][0]["mutation"].update(kind="arbitrary"),
        lambda value: value["negative_cases"][0].update(base_case="missing"),
    ],
)
def test_plan_drift_is_rejected(mutation):
    value = plan()
    mutation(value)
    with pytest.raises(signer.Dev29SignerError):
        signer.validate_plan(value)


def test_runtime_role_alias_and_digest_drift_are_rejected():
    value = runtime()
    value["receipt_key_id"] = value["auth_key_id"]
    with pytest.raises(signer.Dev29SignerError, match="key roles"):
        signer.validate_runtime(plan(), value)

    value = runtime()
    value["odoo_bin_sha256"] = "not-a-digest"
    with pytest.raises(signer.Dev29SignerError, match="does not match|invalid"):
        signer.validate_runtime(plan(), value)


def test_secret_time_token_and_selector_fail_closed():
    with pytest.raises(signer.Dev29SignerError, match="exactly 32"):
        signer.build_signed_request(
            plan(), runtime(), b"short", case_name="trial_balance", auth_module=FakeAuth
        )
    with pytest.raises(signer.Dev29SignerError, match="timezone-aware"):
        signer.build_signed_request(
            plan(), runtime(), b"s" * 32, case_name="trial_balance",
            now=datetime(2026, 7, 19), auth_module=FakeAuth,
        )
    with pytest.raises(signer.Dev29SignerError, match="canonical UUID"):
        signer.build_signed_request(
            plan(), runtime(), b"s" * 32, case_name="trial_balance",
            token_factory=lambda: "bad", auth_module=FakeAuth,
        )
    with pytest.raises(signer.Dev29SignerError, match="exactly one"):
        signer.build_signed_request(
            plan(), runtime(), b"s" * 32, auth_module=FakeAuth
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits required")
def test_runtime_config_accepts_only_the_published_0640_mode(tmp_path):
    path = tmp_path / "runtime.json"
    path.write_bytes(b"{}")
    path.chmod(0o640)
    assert signer.stable_read(
        path,
        label="runtime",
        expected_uid=path.stat().st_uid,
        expected_gid=path.stat().st_gid,
        allowed_modes=frozenset({0o640}),
    ) == b"{}"

    path.chmod(0o440)
    with pytest.raises(signer.Dev29SignerError, match="mode is invalid"):
        signer.stable_read(
            path,
            label="runtime",
            expected_uid=path.stat().st_uid,
            expected_gid=path.stat().st_gid,
            allowed_modes=frozenset({0o640}),
        )

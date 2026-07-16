from datetime import datetime, timedelta, timezone

import pytest

from odoo_accounting_cli_v3.operations import Operation
from odoo_accounting_cli_v3.persistence import SQLitePersistence
from odoo_accounting_cli_v3.trusted_authority import TrustedSession
from odoo_accounting_cli_v3.trusted_idempotency import (
    SQLitePrepareIdempotencyResolver,
    SQLiteRecoveryIdempotencyResolver,
    TrustedIdempotencyError,
)


DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
RELEASE_A = "a" * 64
REGISTRY_A = "b" * 64


def _session(*, company_id: int = 7) -> TrustedSession:
    now = datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc)
    return TrustedSession(
        session_id="session-1",
        principal="pi:user-42",
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        user_id=42,
        company_id=company_id,
        allowed_company_ids=frozenset({company_id}),
        environment="sandbox",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def _operation(parameters: dict[str, object]) -> Operation:
    return Operation.prepare(
        operation_id="operation-from-release-a",
        request_id="request-from-release-a",
        capability_id="acct.invoice.customer_create.v1",
        parameters=parameters,
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key=str(parameters["idempotency_key"]),
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest=REGISTRY_A,
        release_digest=RELEASE_A,
    )


def _recovery_operation(origin: Operation, request: dict[str, str]) -> Operation:
    parameters = {
        "company_id": 7,
        "origin_operation_id": origin.operation_id,
        "expected_recovery_plan_digest": "c" * 64,
        "recovery_date": request["recovery_date"],
        "reason": request["reason"],
        "idempotency_key": request["idempotency_key"],
    }
    return Operation.prepare(
        operation_id="recovery-from-release-a",
        request_id="recovery-request-from-release-a",
        capability_id="acct.recovery.execute.v1",
        parameters=parameters,
        principal="pi:user-42",
        user_id=42,
        company_id=7,
        idempotency_key=request["idempotency_key"],
        odoo_instance_id="odoo19@tokyo2",
        database_name="odoo_sandbox",
        database_uuid=DATABASE_UUID,
        environment="sandbox",
        registry_digest=REGISTRY_A,
        release_digest=RELEASE_A,
    )


def test_resolver_recovers_release_a_operation_from_shared_store(tmp_path) -> None:
    path = (tmp_path / "write-state.sqlite3").resolve()
    store = SQLitePersistence(path)
    parameters = {
        "company_id": 7,
        "invoice_date": "2026-07-15",
        "idempotency_key": "invoice-retry-1",
    }
    operation = _operation(parameters)
    store.get_or_create_operation(operation, scope="scope-from-release-a")

    restarted = SQLitePersistence(path)
    resolver = SQLitePrepareIdempotencyResolver(restarted)
    assert (
        resolver(
            _session(),
            operation.capability_id,
            {**parameters, "invoice_date": "2026-07-16"},
        )
        == operation.operation_id
    )
    # The resolver deliberately finds the stable identity.  TrustedBroker is
    # responsible for rejecting the changed full request before routing.


def test_resolver_returns_none_without_a_durable_identity(tmp_path) -> None:
    resolver = SQLitePrepareIdempotencyResolver(
        SQLitePersistence((tmp_path / "write-state.sqlite3").resolve())
    )
    assert (
        resolver(
            _session(),
            "acct.invoice.customer_create.v1",
            {"company_id": 7, "idempotency_key": "not-created"},
        )
        is None
    )


def test_resolver_uses_trusted_company_and_rejects_business_mismatch(tmp_path) -> None:
    resolver = SQLitePrepareIdempotencyResolver(
        SQLitePersistence((tmp_path / "write-state.sqlite3").resolve())
    )
    with pytest.raises(TrustedIdempotencyError, match="business company"):
        resolver(
            _session(company_id=8),
            "acct.invoice.customer_create.v1",
            {"company_id": 7, "idempotency_key": "cross-company"},
        )


@pytest.mark.parametrize(
    "parameters",
    [
        {"company_id": 7},
        {"company_id": 7, "idempotency_key": ""},
        {"company_id": 7, "idempotency_key": 123},
    ],
)
def test_resolver_rejects_invalid_idempotency_key(tmp_path, parameters) -> None:
    resolver = SQLitePrepareIdempotencyResolver(
        SQLitePersistence((tmp_path / "write-state.sqlite3").resolve())
    )
    with pytest.raises(TrustedIdempotencyError, match="idempotency_key"):
        resolver(_session(), "acct.invoice.customer_create.v1", parameters)


def test_recovery_resolver_recovers_exact_ambiguous_identity(tmp_path) -> None:
    store = SQLitePersistence((tmp_path / "write-state.sqlite3").resolve())
    origin = _operation(
        {"company_id": 7, "idempotency_key": "origin-idempotency-key"}
    )
    request = {
        "origin_operation_id": origin.operation_id,
        "recovery_date": "2026-07-16",
        "reason": "Reverse the verified source operation",
        "idempotency_key": "recovery-idempotency-key",
    }
    recovery = _recovery_operation(origin, request)
    store.get_or_create_operation(recovery, scope="recovery-scope")

    resolver = SQLiteRecoveryIdempotencyResolver(SQLitePersistence(store.path))
    assert resolver(_session(), origin, request) == recovery.operation_id


def test_recovery_resolver_rejects_content_or_tenant_drift(tmp_path) -> None:
    store = SQLitePersistence((tmp_path / "write-state.sqlite3").resolve())
    origin = _operation(
        {"company_id": 7, "idempotency_key": "origin-idempotency-key"}
    )
    request = {
        "origin_operation_id": origin.operation_id,
        "recovery_date": "2026-07-16",
        "reason": "Reverse the verified source operation",
        "idempotency_key": "recovery-idempotency-key",
    }
    store.get_or_create_operation(
        _recovery_operation(origin, request), scope="recovery-scope"
    )
    resolver = SQLiteRecoveryIdempotencyResolver(store)

    with pytest.raises(TrustedIdempotencyError, match="stored recovery content"):
        resolver(_session(), origin, {**request, "reason": "Changed reason"})
    with pytest.raises(TrustedIdempotencyError, match="binding"):
        resolver(_session(company_id=8), origin, request)


def test_recovery_resolver_rejects_extra_persisted_parameters(tmp_path) -> None:
    store = SQLitePersistence((tmp_path / "write-state.sqlite3").resolve())
    origin = _operation(
        {"company_id": 7, "idempotency_key": "origin-idempotency-key"}
    )
    request = {
        "origin_operation_id": origin.operation_id,
        "recovery_date": "2026-07-16",
        "reason": "Reverse the verified source operation",
        "idempotency_key": "recovery-extra-parameter-key",
    }
    valid = _recovery_operation(origin, request)
    invalid = Operation.prepare(
        operation_id=valid.operation_id,
        request_id=valid.request_id,
        capability_id=valid.capability_id,
        parameters={**valid.parameters, "unexpected": "forbidden"},
        principal=valid.principal,
        user_id=valid.user_id,
        company_id=valid.company_id,
        idempotency_key=valid.idempotency_key,
        odoo_instance_id=valid.odoo_instance_id,
        database_name=valid.database_name,
        database_uuid=valid.database_uuid,
        environment=valid.environment,
        registry_digest=valid.registry_digest,
        release_digest=valid.release_digest,
    )
    store.get_or_create_operation(invalid, scope="recovery-extra-scope")

    with pytest.raises(TrustedIdempotencyError, match="stored recovery content"):
        SQLiteRecoveryIdempotencyResolver(store)(_session(), origin, request)

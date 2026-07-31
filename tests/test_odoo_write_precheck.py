from __future__ import annotations

import copy
import hashlib
import json
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.odoo import write_precheck
from odoo_accounting_cli_v3.auth import sign_request_context
from odoo_accounting_cli_v3.gateway import RequestContext
from odoo_accounting_cli_v3.odoo.write_precheck import (
    OdooWritePrecheckError,
    execute_write_precheck_from_odoo_shell,
)
from odoo_accounting_cli_v3.operations import canonical_json
from odoo_accounting_cli_v3.registry import registry_digest, validate_registry
from odoo_accounting_cli_v3.write_receipts import create_recovery_plan_v2


NOW = datetime(2026, 7, 15, 4, 0, tzinfo=timezone.utc)
DATABASE_UUID = "11111111-1111-4111-8111-111111111111"
AUTH_SECRET = b"auth-secret-material-at-least-32-bytes"
RELEASE_DIGEST = "d" * 64
CAPABILITY_ID = "acct.invoice.customer_create.v1"
DRAFT_CANCEL_CAPABILITY_ID = "acct.move.draft_cancel.v1"
RECOVERY_CAPABILITY_ID = "acct.recovery.execute.v1"
EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"
CAPABILITY_GROUP = "account.group_account_invoice"
RECOVERY_GROUP = "account.group_account_manager"
SOURCE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "odoo_accounting_cli_v3"
    / "odoo"
    / "write_precheck.py"
)


def _capabilities():
    document = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "registry"
            / "capabilities.json"
        ).read_text(encoding="utf-8")
    )
    invoice = copy.deepcopy(
        next(item for item in document["capabilities"] if item["id"] == CAPABILITY_ID)
    )
    invoice["enabled_environments"] = []
    invoice["staged_environments"] = ["sandbox"]
    invoice["evidence"] = {"level": "contract_tested", "receipts": []}
    return validate_registry({"schema_version": 1, "capabilities": [invoice]})


CAPABILITIES = _capabilities()
REGISTRY_DIGEST = registry_digest(CAPABILITIES)


def _recovery_capabilities():
    document = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "registry"
            / "capabilities.json"
        ).read_text(encoding="utf-8")
    )
    recovery = copy.deepcopy(
        next(
            item
            for item in document["capabilities"]
            if item["id"] == RECOVERY_CAPABILITY_ID
        )
    )
    recovery["enabled_environments"] = []
    recovery["staged_environments"] = ["sandbox"]
    recovery["evidence"] = {"level": "contract_tested", "receipts": []}
    return validate_registry({"schema_version": 1, "capabilities": [recovery]})


RECOVERY_CAPABILITIES = _recovery_capabilities()
RECOVERY_REGISTRY_DIGEST = registry_digest(RECOVERY_CAPABILITIES)


def _draft_cancel_capabilities():
    document = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "registry"
            / "capabilities.json"
        ).read_text(encoding="utf-8")
    )
    capability = copy.deepcopy(
        next(
            item
            for item in document["capabilities"]
            if item["id"] == DRAFT_CANCEL_CAPABILITY_ID
        )
    )
    capability["enabled_environments"] = []
    capability["staged_environments"] = ["sandbox"]
    capability["evidence"] = {"level": "contract_tested", "receipts": []}
    return validate_registry(
        {"schema_version": 1, "capabilities": [capability]}
    )


DRAFT_CANCEL_CAPABILITIES = _draft_cancel_capabilities()
DRAFT_CANCEL_REGISTRY_DIGEST = registry_digest(DRAFT_CANCEL_CAPABILITIES)


def _parameters(*, company_id=7):
    return {
        "company_id": company_id,
        "partner_id": 101,
        "invoice_date": "2026-07-15",
        "accounting_date": "2026-07-15",
        "due_date": "2026-08-15",
        "currency_id": 12,
        "journal_id": 5,
        "posting_mode": "draft",
        "reference": "INV-SANDBOX-1",
        "lines": [
            {
                "line_reference": "line-1",
                "name": "Consulting",
                "product_id": None,
                "account_id": 401,
                "quantity": "1",
                "price_unit": "100.00",
                "tax_ids": [],
            }
        ],
        "idempotency_key": "invoice-precheck-1",
    }


def _recovery_parameters(plan_digest, *, company_id=7):
    return {
        "company_id": company_id,
        "origin_operation_id": "origin-op-501",
        "expected_recovery_plan_digest": plan_digest,
        "recovery_date": "2026-07-16",
        "reason": "Reverse the sandbox posting after verification",
        "idempotency_key": "recover-origin-op-501",
    }


def _draft_cancel_parameters(*, company_id=7):
    return {
        "company_id": company_id,
        "move_id": 501,
        "expected_move_type": "out_invoice",
        "expected_document_binding": "a" * 64,
        "expected_document_binding_v2": "c" * 64,
        "expected_business_binding": "b" * 64,
        "reason": "Cancel duplicate pristine draft",
        "idempotency_key": "draft-cancel-501",
    }


def _recovery_plan():
    return create_recovery_plan_v2(
        origin_operation_id="origin-op-501",
        recovery_capability_id=RECOVERY_CAPABILITY_ID,
        status="available",
        method="cancel_draft_move",
        requires_approval=True,
        action_targets=[
            {
                "model": "account.move",
                "record_id": 501,
                "company_id": 7,
                "record_state": "posted",
                "record_fingerprint": "f" * 64,
            }
        ],
        guard_records=[
            {
                "model": "account.move.line",
                "record_id": 502,
                "company_id": 7,
                "record_state": "unknown",
                "record_fingerprint": "e" * 64,
                "expected_outcome": "survive_exact",
            }
        ],
        oracle_id="cancel_draft_move_exact_v1",
        parameters={"move_id": 501},
    )


def _context(
    parameters,
    *,
    user_id=42,
    company_id=7,
    allowed=frozenset({7}),
    odoo_instance_id="odoo19@sandbox",
    database_name="v3_sandbox",
    database_uuid=DATABASE_UUID,
    environment="sandbox",
    capability_id=CAPABILITY_ID,
):
    return sign_request_context(
        auth_token_id=f"precheck-{user_id}-{company_id}-{environment}",
        principal=f"pi:{environment}:{user_id}",
        odoo_instance_id=odoo_instance_id,
        database_name=database_name,
        database_uuid=database_uuid,
        user_id=user_id,
        company_id=company_id,
        allowed_company_ids=allowed,
        environment=environment,
        capability_id=capability_id,
        parameters=parameters,
        issued_at=NOW - timedelta(seconds=30),
        expires_at=NOW + timedelta(minutes=4),
        key_id="auth-v1",
        secret=AUTH_SECRET,
    )


def _context_mapping(context: RequestContext):
    def utc(value):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "allowed_company_ids": sorted(context.allowed_company_ids),
        "audience": context.audience,
        "auth_expires_at": utc(context.auth_expires_at),
        "auth_issued_at": utc(context.auth_issued_at),
        "auth_key_id": context.auth_key_id,
        "auth_request_digest": context.auth_request_digest,
        "auth_signature": context.auth_signature,
        "auth_signature_purpose": context.auth_signature_purpose,
        "auth_signature_version": context.auth_signature_version,
        "auth_token_id": context.auth_token_id,
        "company_id": context.company_id,
        "database_name": context.database_name,
        "database_uuid": context.database_uuid,
        "environment": context.environment,
        "odoo_instance_id": context.odoo_instance_id,
        "principal": context.principal,
        "user_id": context.user_id,
    }


def _request(
    context,
    parameters,
    *,
    trusted_recovery_plan=None,
    capability_id=CAPABILITY_ID,
):
    return {
        "context": _context_mapping(context),
        "capability_id": capability_id,
        "parameters": copy.deepcopy(parameters),
        "trusted_recovery_plan": copy.deepcopy(trusted_recovery_plan),
    }


class User:
    def __init__(self, identifier, company_ids, groups):
        self.id = identifier
        self.ids = [identifier]
        self.active = True
        self.company_ids = SimpleNamespace(ids=list(company_ids))
        self._groups = set(groups)

    def __bool__(self):
        return True

    def __len__(self):
        return 1

    def exists(self):
        return self

    def has_group(self, xml_id):
        return xml_id in self._groups


class UserModel:
    def __init__(self, users):
        self.users = users

    def browse(self, identifier):
        return self.users[identifier]


class ConfigModel:
    def __init__(self, database_uuid=DATABASE_UUID):
        self.database_uuid = database_uuid

    def get_param(self, key):
        assert key == "database.uuid"
        return self.database_uuid


class Cursor:
    def __init__(self, database_name="v3_sandbox"):
        self.dbname = database_name
        self.commits = 0
        self.savepoints = 0
        self.rolled_back_savepoints = 0
        self.side_effects = []

    @contextmanager
    def savepoint(self):
        self.savepoints += 1
        before = copy.deepcopy(self.side_effects)
        try:
            yield
        except Exception:
            self.side_effects = before
            self.rolled_back_savepoints += 1
            raise

    def commit(self):
        self.commits += 1


class BoundEnv:
    def __init__(self, cr, users, *, uid=42, su=False):
        self.cr = cr
        self.uid = uid
        self.su = su
        self.user = users[uid]
        self._models = {"res.users": UserModel(users)}

    def __getitem__(self, name):
        return self._models[name]


class RootEnv:
    def __init__(self, cr, *, database_uuid=DATABASE_UUID):
        self.cr = cr
        self._config = ConfigModel(database_uuid)

    def __getitem__(self, name):
        assert name == "ir.config_parameter"
        return self._config


class Handler:
    def __init__(self, *, error=None, result=None):
        self.error = error
        self.result = result
        self.calls = []

    def precheck(self, capability_id, parameters):
        self.calls.append((capability_id, copy.deepcopy(parameters)))
        if self.error is not None:
            raise self.error
        if self.result is not None:
            return copy.deepcopy(self.result)
        return {
            "capability_id": capability_id,
            "company_id": parameters["company_id"],
            "parameters_digest": hashlib.sha256(
                canonical_json(parameters)
            ).hexdigest(),
            "checks": ["acl_visible", "date_open"],
            "semantic_precheck": {
                "capability_id": capability_id,
                "company_id": parameters["company_id"],
                "checks": ["invoice_dates_ordered"],
                "computed": {"line_total": "100.00"},
            },
            "before": [],
        }


def _harness(*, groups=None, handler=None, su=False, user_companies=(7, 8)):
    cr = Cursor()
    groups = (
        {EXECUTOR_GROUP, CAPABILITY_GROUP} if groups is None else set(groups)
    )
    users = {42: User(42, user_companies, groups)}
    bound = BoundEnv(cr, users, su=su)
    root = RootEnv(cr)
    selected_handler = handler or Handler()
    kwargs = {
        "capabilities": CAPABILITIES,
        "auth_secret": AUTH_SECRET,
        "auth_key_id": "auth-v1",
        "expected_registry_digest": REGISTRY_DIGEST,
        "release_digest": RELEASE_DIGEST,
        "odoo_instance_id": "odoo19@sandbox",
        "environment": "sandbox",
        "capability_channel": "staged",
        "now": NOW,
        "environment_factory": lambda _cr, _uid, _context: bound,
        "handler_factory": lambda _env, _context, _now: selected_handler,
        "metadata_execution_scope_factory": nullcontext,
    }
    return root, cr, selected_handler, kwargs


def test_success_returns_canonical_runtime_bound_handler_evidence_without_writes():
    parameters = _parameters()
    context = _context(parameters)
    root, cr, handler, kwargs = _harness()

    result = execute_write_precheck_from_odoo_shell(
        root, _request(context, parameters), **kwargs
    )

    assert set(result) == {
        "capability_id",
        "company_id",
        "parameters_digest",
        "passed",
        "checks",
        "handler_details",
        "runtime_binding",
        "registry_digest",
        "release_digest",
    }
    assert result["capability_id"] == CAPABILITY_ID
    assert result["company_id"] == 7
    assert result["parameters_digest"] == hashlib.sha256(
        canonical_json(parameters)
    ).hexdigest()
    assert result["passed"] is True
    assert result["checks"] == ["acl_visible", "date_open"]
    assert result["handler_details"]["before"] == []
    assert result["handler_details"]["semantic_precheck"]["company_id"] == 7
    assert result["runtime_binding"] == {
        "user_id": 42,
        "odoo_instance_id": "odoo19@sandbox",
        "database_name": "v3_sandbox",
        "database_uuid": DATABASE_UUID,
        "environment": "sandbox",
        "capability_channel": "staged",
    }
    assert result["registry_digest"] == REGISTRY_DIGEST
    assert result["release_digest"] == RELEASE_DIGEST
    assert result == json.loads(canonical_json(result))
    assert handler.calls == [(CAPABILITY_ID, parameters)]
    assert cr.commits == 0
    assert cr.savepoints == 1
    assert cr.rolled_back_savepoints == 1


def test_trusted_metadata_scope_wraps_formal_precheck_only():
    active = False
    observations = []

    @contextmanager
    def metadata_scope():
        nonlocal active
        assert active is False
        active = True
        try:
            yield
        finally:
            active = False

    class ScopeHandler(Handler):
        def precheck(self, capability_id, parameters):
            observations.append(active)
            return super().precheck(capability_id, parameters)

    parameters = _parameters()
    context = _context(parameters)
    root, _cr, _handler, kwargs = _harness(handler=ScopeHandler())
    kwargs["metadata_execution_scope_factory"] = metadata_scope

    execute_write_precheck_from_odoo_shell(
        root, _request(context, parameters), **kwargs
    )

    assert observations == [True]
    assert active is False


def test_default_metadata_scope_is_lazily_loaded_from_the_odoo_addon(
    monkeypatch: pytest.MonkeyPatch,
):
    active = False
    imported = []

    @contextmanager
    def scope():
        nonlocal active
        active = True
        try:
            yield
        finally:
            active = False

    monkeypatch.setattr(
        write_precheck.importlib,
        "import_module",
        lambda name: (
            imported.append(name)
            or SimpleNamespace(_accounting_metadata_execution_scope=scope)
        ),
    )

    with write_precheck._default_metadata_execution_scope():
        assert active is True

    assert active is False
    assert imported == [write_precheck.METADATA_SCOPE_MODULE]


def test_successful_precheck_cannot_leak_an_orm_side_effect():
    parameters = _parameters()
    context = _context(parameters)
    root, cr, _handler, kwargs = _harness()

    class SideEffectHandler(Handler):
        def precheck(self, capability_id, request_parameters):
            cr.side_effects.append("unexpected ORM mutation")
            return super().precheck(capability_id, request_parameters)

    handler = SideEffectHandler()
    kwargs["handler_factory"] = lambda _env, _context, _now: handler

    result = execute_write_precheck_from_odoo_shell(
        root, _request(context, parameters), **kwargs
    )

    assert result["passed"] is True
    assert cr.side_effects == []
    assert cr.commits == 0
    assert cr.rolled_back_savepoints == 1


def test_exact_request_and_authenticated_parameters_reject_tampering():
    parameters = _parameters()
    context = _context(parameters)
    root, cr, handler, kwargs = _harness()
    request = _request(context, parameters)

    with pytest.raises(OdooWritePrecheckError, match="fields"):
        execute_write_precheck_from_odoo_shell(
            root, {**request, "unexpected": True}, **kwargs
        )

    tampered_parameters = copy.deepcopy(request)
    tampered_parameters["parameters"]["reference"] = "TAMPERED"
    with pytest.raises(OdooWritePrecheckError, match="request digest"):
        execute_write_precheck_from_odoo_shell(
            root, tampered_parameters, **kwargs
        )

    tampered_context = copy.deepcopy(request)
    tampered_context["context"]["principal"] = "pi:sandbox:attacker"
    with pytest.raises(OdooWritePrecheckError, match="failed closed"):
        execute_write_precheck_from_odoo_shell(root, tampered_context, **kwargs)
    assert handler.calls == []
    assert cr.commits == 0


def test_cross_company_request_and_unassigned_company_are_rejected():
    foreign_parameters = _parameters(company_id=8)
    signed_for_company_seven = _context(
        foreign_parameters, company_id=7, allowed=frozenset({7, 8})
    )
    root, cr, handler, kwargs = _harness()
    with pytest.raises(OdooWritePrecheckError, match="company binding"):
        execute_write_precheck_from_odoo_shell(
            root,
            _request(signed_for_company_seven, foreign_parameters),
            **kwargs,
        )

    parameters = _parameters()
    context = _context(parameters, allowed=frozenset({7, 8}))
    root, cr, handler, kwargs = _harness(user_companies=(7,))
    with pytest.raises(OdooWritePrecheckError, match="failed closed"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert handler.calls == []
    assert cr.commits == 0


@pytest.mark.parametrize(
    ("groups", "message"),
    [
        ({CAPABILITY_GROUP}, "executor group"),
        ({EXECUTOR_GROUP}, "capability ACL"),
    ],
)
def test_executor_and_capability_acl_are_both_required(groups, message):
    parameters = _parameters()
    context = _context(parameters)
    root, cr, handler, kwargs = _harness(groups=groups)
    with pytest.raises(OdooWritePrecheckError, match=message):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert handler.calls == []
    assert cr.commits == 0


def test_staged_precheck_is_never_permitted_in_production():
    parameters = _parameters()
    context = _context(parameters, environment="production")
    root, cr, handler, kwargs = _harness()
    kwargs["environment"] = "production"
    with pytest.raises(OdooWritePrecheckError, match="staged.*production"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert handler.calls == []
    assert cr.commits == 0


def test_superuser_environment_is_rejected_before_handler():
    parameters = _parameters()
    context = _context(parameters)
    root, cr, handler, kwargs = _harness(su=True)
    with pytest.raises(OdooWritePrecheckError, match="failed closed"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert handler.calls == []
    assert cr.commits == 0


def test_handler_failure_and_invalid_evidence_fail_closed_without_commit():
    parameters = _parameters()
    context = _context(parameters)
    handler = Handler(error=RuntimeError("Odoo read-side precheck failed"))
    root, cr, handler, kwargs = _harness(handler=handler)
    with pytest.raises(OdooWritePrecheckError, match="failed closed"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert len(handler.calls) == 1
    assert cr.commits == 0

    bad = Handler(
        result={
            "capability_id": CAPABILITY_ID,
            "company_id": 8,
            "parameters_digest": hashlib.sha256(
                canonical_json(parameters)
            ).hexdigest(),
            "checks": ["visible"],
        }
    )
    root, cr, bad, kwargs = _harness(handler=bad)
    with pytest.raises(OdooWritePrecheckError, match="evidence binding"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert len(bad.calls) == 1
    assert cr.commits == 0

    forged = Handler(
        result={
            "capability_id": CAPABILITY_ID,
            "company_id": 7,
            "parameters_digest": hashlib.sha256(
                canonical_json(parameters)
            ).hexdigest(),
            "checks": ["visible"],
            "passed": False,
        }
    )
    root, cr, forged, kwargs = _harness(handler=forged)
    with pytest.raises(OdooWritePrecheckError, match="reserved fields"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert len(forged.calls) == 1
    assert cr.commits == 0


@pytest.mark.parametrize(
    "context_overrides",
    [
        {"odoo_instance_id": "odoo19@other"},
        {"database_name": "other_database"},
        {"database_uuid": "22222222-2222-4222-8222-222222222222"},
        {"environment": "test"},
    ],
)
def test_signed_runtime_instance_database_and_environment_are_exact(context_overrides):
    parameters = _parameters()
    context = _context(parameters, **context_overrides)
    root, cr, handler, kwargs = _harness()
    with pytest.raises(OdooWritePrecheckError, match="does not match"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert handler.calls == []
    assert cr.commits == 0


def test_registry_and_release_identity_are_fail_closed():
    parameters = _parameters()
    context = _context(parameters)
    root, cr, handler, kwargs = _harness()
    kwargs["expected_registry_digest"] = "0" * 64
    with pytest.raises(OdooWritePrecheckError, match="registry digest mismatch"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )

    root, cr, handler, kwargs = _harness()
    kwargs["release_digest"] = "not-a-digest"
    with pytest.raises(OdooWritePrecheckError, match="release digest"):
        execute_write_precheck_from_odoo_shell(
            root, _request(context, parameters), **kwargs
        )
    assert handler.calls == []
    assert cr.commits == 0


def test_recovery_precheck_requires_and_passes_receipt_derived_trusted_plan():
    plan = _recovery_plan()
    parameters = _recovery_parameters(plan["plan_digest"])
    context = _context(parameters, capability_id=RECOVERY_CAPABILITY_ID)
    root, cr, handler, kwargs = _harness(
        groups={EXECUTOR_GROUP, RECOVERY_GROUP}
    )
    observed = {}

    def recovery_handler_factory(_env, _context, _now, trusted_plan):
        observed["trusted_plan"] = copy.deepcopy(trusted_plan)
        return handler

    kwargs.update(
        capabilities=RECOVERY_CAPABILITIES,
        expected_registry_digest=RECOVERY_REGISTRY_DIGEST,
        handler_factory=recovery_handler_factory,
    )

    result = execute_write_precheck_from_odoo_shell(
        root,
        _request(
            context,
            parameters,
            capability_id=RECOVERY_CAPABILITY_ID,
            trusted_recovery_plan=plan,
        ),
        **kwargs,
    )

    assert result["capability_id"] == RECOVERY_CAPABILITY_ID
    assert observed["trusted_plan"] == plan
    assert handler.calls == [(RECOVERY_CAPABILITY_ID, parameters)]
    assert cr.commits == 0


def test_draft_cancel_precheck_is_normal_write_and_requires_null_trusted_plan():
    parameters = _draft_cancel_parameters()
    context = _context(
        parameters, capability_id=DRAFT_CANCEL_CAPABILITY_ID
    )
    root, cr, handler, kwargs = _harness()
    kwargs.update(
        capabilities=DRAFT_CANCEL_CAPABILITIES,
        expected_registry_digest=DRAFT_CANCEL_REGISTRY_DIGEST,
    )

    result = execute_write_precheck_from_odoo_shell(
        root,
        _request(
            context,
            parameters,
            capability_id=DRAFT_CANCEL_CAPABILITY_ID,
            trusted_recovery_plan=None,
        ),
        **kwargs,
    )

    assert result["capability_id"] == DRAFT_CANCEL_CAPABILITY_ID
    assert handler.calls == [(DRAFT_CANCEL_CAPABILITY_ID, parameters)]
    assert cr.commits == 0

    plan = _recovery_plan()
    root, _cr, handler, kwargs = _harness()
    kwargs.update(
        capabilities=DRAFT_CANCEL_CAPABILITIES,
        expected_registry_digest=DRAFT_CANCEL_REGISTRY_DIGEST,
    )
    with pytest.raises(OdooWritePrecheckError, match="must be null"):
        execute_write_precheck_from_odoo_shell(
            root,
            _request(
                context,
                parameters,
                capability_id=DRAFT_CANCEL_CAPABILITY_ID,
                trusted_recovery_plan=plan,
            ),
            **kwargs,
        )
    assert handler.calls == []


def test_recovery_plan_cannot_be_missing_tampered_or_injected_into_normal_write():
    plan = _recovery_plan()
    parameters = _recovery_parameters(plan["plan_digest"])
    context = _context(parameters, capability_id=RECOVERY_CAPABILITY_ID)
    root, cr, handler, kwargs = _harness(
        groups={EXECUTOR_GROUP, RECOVERY_GROUP}
    )
    kwargs.update(
        capabilities=RECOVERY_CAPABILITIES,
        expected_registry_digest=RECOVERY_REGISTRY_DIGEST,
    )
    with pytest.raises(OdooWritePrecheckError, match="plan is required"):
        execute_write_precheck_from_odoo_shell(
            root,
            _request(
                context,
                parameters,
                capability_id=RECOVERY_CAPABILITY_ID,
            ),
            **kwargs,
        )

    tampered = copy.deepcopy(plan)
    tampered["action_targets"][0]["record_id"] = 999
    with pytest.raises(OdooWritePrecheckError, match="plan is invalid"):
        execute_write_precheck_from_odoo_shell(
            root,
            _request(
                context,
                parameters,
                capability_id=RECOVERY_CAPABILITY_ID,
                trusted_recovery_plan=tampered,
            ),
            **kwargs,
        )

    normal_parameters = _parameters()
    normal_context = _context(normal_parameters)
    root, cr, handler, kwargs = _harness()
    with pytest.raises(OdooWritePrecheckError, match="must be null"):
        execute_write_precheck_from_odoo_shell(
            root,
            _request(
                normal_context,
                normal_parameters,
                trusted_recovery_plan=plan,
            ),
            **kwargs,
        )
    assert handler.calls == []
    assert cr.commits == 0


def test_precheck_boundary_has_no_commit_sudo_or_business_execution_path():
    source = SOURCE.read_text(encoding="utf-8")
    assert ".commit(" not in source
    assert ".rollback(" not in source
    assert ".sudo(" not in source
    assert ".execute(" not in source
    assert ".verify(" not in source
    assert source.count("handler.precheck(") == 1

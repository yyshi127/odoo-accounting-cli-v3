from __future__ import annotations

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "odoo_addons" / "odoo_accounting_cli_v3_control"
MODEL = ADDON / "models" / "module_guard.py"
BOOTSTRAP = ADDON / "sql" / "module_guard_v1.sql"


def _source() -> str:
    return MODEL.read_text(encoding="utf-8")


def _model_class() -> ast.ClassDef:
    tree = ast.parse(_source())
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name == "OdooAccountingCliModuleGuard"
    )


def _method(name: str) -> ast.FunctionDef:
    return next(
        node
        for node in _model_class().body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def test_module_guard_protocol_constants_are_identical_in_model_and_bootstrap():
    source = _source()
    bootstrap = BOOTSTRAP.read_text(encoding="utf-8")

    assert "MODULE_GUARD_PROTOCOL_VERSION = 1" in source
    assert "MODULE_GUARD_ADVISORY_NAMESPACE = 1329677142" in source
    assert "MODULE_GUARD_ADVISORY_KEY = 1297040433" in source
    assert "0x4F414356" in source
    assert "0x4D4F4431" in source
    for marker in ("1329677142", "1297040433"):
        assert marker in bootstrap
    assert "protocol_version integer NOT NULL" in bootstrap
    assert "1, 1, 2, pg_catalog.gen_random_uuid()" in bootstrap
    assert "observed_database_oid, observed_database_uuid" in bootstrap


def test_module_guard_is_a_private_abstract_verification_api_not_an_orm_table():
    source = _source()
    model = _model_class()
    methods = {
        node.name: node
        for node in model.body
        if isinstance(node, ast.FunctionDef)
    }

    assert '_name = "odoo.accounting.cli.module.guard"' in source
    assert any(
        isinstance(base, ast.Attribute) and base.attr == "AbstractModel"
        for base in model.bases
    )
    assert {name for name in methods if not name.startswith("_")} == set()
    assert "CREATE ROLE" not in source
    assert "CREATE FUNCTION" not in source
    assert "CREATE TRIGGER" not in source
    assert "ALTER TABLE" not in source
    assert "DROP " not in source
    assert "post_init_hook" not in ast.literal_eval(
        (ADDON / "__manifest__.py").read_text(encoding="utf-8")
    )

    verified = ast.get_source_segment(source, _method("_verified_snapshot"))
    assert "if not self.env.su:" in verified
    assert "module guard verification is restricted to the root control plane" in verified
    assert "self._verify_catalog_contract(snapshot)" in verified
    assert "self._verify_runtime_role_boundary(snapshot)" in verified


def test_catalog_verifier_checks_owner_role_runtime_boundary_and_exact_objects():
    source = _source()
    verifier = source
    runtime = ast.get_source_segment(source, _method("_verify_runtime_role_boundary"))

    for marker in (
        "odoo_accounting_cli_v3_guard_owner",
        "odoo_accounting_cli_v3_guard",
        "module_guard_state",
    ):
        assert marker in source

    for marker in (
        "odoo_accounting_cli_v3_module_change_guard",
        "odoo_accounting_cli_v3_operation_effect_guard",
        "odoo_accounting_cli_v3_operation_no_truncate",
        "trigger.tgenabled",
        "trigger.tgtype",
        "trigger.tgisinternal",
        "function.prosecdef",
        "function.proconfig",
        "function.proacl",
        "relation.relrowsecurity",
        "attribute.attacl",
        "pg_get_function_identity_arguments",
        "has_schema_privilege",
        "has_table_privilege",
        "has_function_privilege",
    ):
        assert marker in verifier

    for marker in (
        "rolcanlogin",
        "rolsuper",
        "rolinherit",
        "rolcreaterole",
        "rolcreatedb",
        "rolreplication",
        "rolbypassrls",
        "pg_auth_members",
        "pg_database",
        "current_database()",
        "current_user",
        "session_user",
    ):
        assert marker in runtime
    assert "module guard database ownership boundary is invalid" in runtime
    assert "module guard role attributes are invalid" in runtime


def test_snapshot_is_fail_closed_on_protocol_open_epoch_unresolved_or_shape_drift():
    source = _source()
    snapshot = "\n".join(
        ast.get_source_segment(source, _method(name))
        for name in ("_read_snapshot", "_verified_snapshot")
    )

    for marker in (
        "read_module_guard_state()",
        "MODULE_GUARD_PROTOCOL_VERSION",
        'snapshot["module_guard_open"] is not False',
        'snapshot["opened_epoch"] is not None',
        'snapshot["unresolved_effect_count"] != 0',
        "module guard state is not closed and quiescent",
        "module guard snapshot fields are invalid",
        "module guard protocol version mismatch",
    ):
        assert marker in snapshot


def test_privileged_bootstrap_uses_protected_owner_and_least_privilege_roles():
    sql = BOOTSTRAP.read_text(encoding="utf-8")

    assert "\\set ON_ERROR_STOP on" in sql
    assert "odoo_accounting_cli_v3_guard_owner" in sql
    assert re.search(
        r"CREATE ROLE .*NOLOGIN.*NOSUPERUSER.*NOCREATEDB.*NOCREATEROLE.*NOREPLICATION.*NOBYPASSRLS",
        sql,
        flags=re.DOTALL,
    )
    assert "ALTER DATABASE" in sql
    assert "OWNER TO odoo_accounting_cli_v3_guard_owner" in sql
    assert re.search(
        r"ALTER TABLE public\.ir_module_module\s+OWNER TO",
        sql,
    )
    assert re.search(
        r"ALTER TABLE public\.odoo_accounting_cli_operation\s+OWNER TO",
        sql,
    )
    assert "REVOKE ALL ON SCHEMA odoo_accounting_cli_v3_guard FROM PUBLIC" in sql
    assert "REVOKE ALL ON ALL TABLES IN SCHEMA odoo_accounting_cli_v3_guard FROM PUBLIC" in sql
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA odoo_accounting_cli_v3_guard FROM PUBLIC" in sql
    assert "REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER" in sql
    assert "GRANT SELECT, INSERT, UPDATE ON TABLE public.odoo_accounting_cli_operation" in sql
    assert "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.ir_module_module" in sql
    assert sql.count("GRANT EXECUTE ON FUNCTION ") == 8
    for signature in (
        "odoo_accounting_cli_v3_guard.read_module_guard_state()",
        "odoo_accounting_cli_v3_guard.authorize_module_maintenance(",
        "odoo_accounting_cli_v3_guard.finalize_operation_effect(",
        "odoo_accounting_cli_v3_guard.rescue_module_guard(bigint, uuid, text)",
        "odoo_accounting_cli_v3_guard.open_module_guard(bigint, uuid)",
        "odoo_accounting_cli_v3_guard.close_module_guard(bigint, uuid)",
    ):
        assert signature in sql
    assert "ALTER ROLE" in sql and "NOCREATEDB" in sql


def test_privileged_bootstrap_is_one_transaction_and_missing_inputs_exit_nonzero():
    sql = BOOTSTRAP.read_text(encoding="utf-8")

    assert sql.count("BEGIN;") == 1
    assert sql.index("BEGIN;") < sql.index("DO $bootstrap_roles$")
    assert sql.index("BEGIN;") < sql.index("ALTER DATABASE")
    assert sql.count("COMMIT;") == 1
    assert sql.count("SELECT 1 / 0;") == 3
    assert "\\quit 3" not in sql


def test_module_dml_trigger_requires_exclusive_protocol_and_advances_epoch_once_per_statement():
    sql = BOOTSTRAP.read_text(encoding="utf-8")

    for marker in (
        "pg_try_advisory_xact_lock(1329677142, 1297040433)",
        "module_guard_open",
        "opened_epoch = epoch",
        "unresolved_effect_count = 0",
        "epoch = epoch + 1",
        "opened_epoch = opened_epoch + 1",
        "protocol_version = 1",
        "session_user::name = maintenance_role",
        "ERRCODE = '55P03'",
        "ERRCODE = '55006'",
    ):
        assert marker in sql

    assert (
        "BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.ir_module_module"
        in sql
    )
    assert "FOR EACH STATEMENT" in sql
    assert "ENABLE ALWAYS TRIGGER odoo_accounting_cli_v3_module_change_guard" in sql


def test_maintenance_loader_connections_are_bound_to_one_live_exclusive_holder():
    sql = BOOTSTRAP.read_text(encoding="utf-8")

    for marker in (
        "maintenance_id uuid",
        "maintenance_holder_pid integer",
        "maintenance_holder_backend_start timestamp with time zone",
        "pg_backend_pid()",
        "backend_start",
        "mode = 'ExclusiveLock'",
        "objsubid = 2",
        "module maintenance holder is not live",
        "odoo_accounting_cli_v3_module_change_guard_after",
        "AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.ir_module_module",
    ):
        assert marker in sql

    guard_change = re.search(
        r"CREATE OR REPLACE FUNCTION .*?guard_module_change\(\).*?END\n\$function\$;",
        sql,
        flags=re.DOTALL,
    )
    assert guard_change is not None
    body = guard_change.group(0)
    assert body.index(
        "session_user::name = guard_state.maintenance_role"
    ) < body.index(
        "pg_try_advisory_xact_lock(1329677142, 1297040433)"
    )


def test_unresolved_classifier_accepts_no_effect_failed_recovery_without_opening_fence():
    sql = BOOTSTRAP.read_text(encoding="utf-8")
    classifier = re.search(
        r"CREATE OR REPLACE FUNCTION .*?effect_is_unresolved\(.*?END\n\$function\$;",
        sql,
        flags=re.DOTALL,
    )

    assert classifier is not None
    body = classifier.group(0)
    assert "RETURN execution_succeeded;" in body
    assert "IF NOT execution_succeeded THEN" in body
    assert "RETURN false;" in body


def test_operation_effect_trigger_tracks_all_committed_but_unresolved_states():
    sql = BOOTSTRAP.read_text(encoding="utf-8")

    for state in ("committed", "failed", "recovering", "verified", "recovered"):
        assert f"'{state}'" in sql
    assert "execution_result_json" in sql
    assert "verification_result_json" in sql
    assert "recovery_result_json" in sql
    assert "operation_effect_resolution" in sql
    assert "unresolved_effect_count = ledger_count" in sql
    assert "AFTER INSERT OR UPDATE OR DELETE ON public.odoo_accounting_cli_operation" in sql
    assert "FOR EACH ROW" in sql
    assert "ENABLE ALWAYS TRIGGER odoo_accounting_cli_v3_operation_effect_guard" in sql
    assert "BEFORE TRUNCATE ON public.odoo_accounting_cli_operation" in sql
    assert "ENABLE ALWAYS TRIGGER odoo_accounting_cli_v3_operation_no_truncate" in sql


def test_bootstrap_locks_both_relations_reconciles_count_and_starts_closed():
    sql = BOOTSTRAP.read_text(encoding="utf-8")

    assert "LOCK TABLE public.ir_module_module IN ACCESS EXCLUSIVE MODE" in sql
    assert "LOCK TABLE public.odoo_accounting_cli_operation IN ACCESS EXCLUSIVE MODE" in sql
    assert "count(" in sql.lower()
    assert "effect_is_unresolved(" in sql
    assert "operation_effect_resolution" in sql
    assert "module_guard_open = false" in sql
    assert "opened_epoch = NULL" in sql
    assert "COMMIT;" in sql
    assert "ordinary Odoo addon installation cannot establish this ownership boundary" in sql

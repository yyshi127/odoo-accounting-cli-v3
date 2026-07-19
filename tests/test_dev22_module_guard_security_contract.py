from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = (
    ROOT
    / "odoo_addons"
    / "odoo_accounting_cli_v3_control"
    / "sql"
    / "module_guard_v1.sql"
)
MODEL = (
    ROOT
    / "odoo_addons"
    / "odoo_accounting_cli_v3_control"
    / "models"
    / "module_guard.py"
)


def _sql() -> str:
    return BOOTSTRAP.read_text(encoding="utf-8")


def _function(name: str) -> str:
    match = re.search(
        rf"CREATE OR REPLACE FUNCTION\s+[^\n]*\.{name}\(.*?END\n\$function\$;",
        _sql(),
        flags=re.DOTALL,
    )
    assert match is not None, f"missing function {name}"
    return match.group(0)


def test_bootstrap_refuses_catalog_adoption_before_any_privileged_mutation():
    sql = _sql()

    assert "CREATE SCHEMA IF NOT EXISTS" not in sql
    assert "CREATE TABLE IF NOT EXISTS" not in sql
    assert "module guard schema already exists; use a versioned privileged migration" in sql
    preflight = sql.index("DO $preflight_catalog$")
    for privileged_mutation in (
        "ALTER DATABASE",
        "ALTER SCHEMA public OWNER",
        "CREATE SCHEMA odoo_accounting_cli_v3_guard",
    ):
        assert preflight < sql.index(privileged_mutation)
    for poison_surface in (
        "pg_trigger",
        "pg_rewrite",
        "pg_policy",
        "relrowsecurity",
        "relforcerowsecurity",
        "attacl",
        "pg_event_trigger",
    ):
        assert poison_surface in sql[preflight : sql.index("ALTER DATABASE")]


def test_missing_bootstrap_role_variables_exit_nonzero_on_postgresql_16():
    preamble = _sql().split("BEGIN;", 1)[0]

    assert "\\quit 3" not in preamble
    assert preamble.count("SELECT 1 / 0;") == 3
    for role in ("runtime_role", "maintenance_role", "finalizer_role"):
        assert f"requires -v {role}=..." in preamble


def test_postgresql_special_forms_are_not_schema_qualified_as_functions():
    assert "pg_catalog.coalesce" not in _sql().lower()


def test_maintenance_loader_has_no_persistent_login_or_runtime_membership():
    sql = _sql()

    assert re.search(
        r"ALTER ROLE %I NOLOGIN NOSUPERUSER NOINHERIT.*CONNECTION LIMIT 1",
        sql,
        flags=re.DOTALL,
    )
    assert "GRANT %I TO %I WITH INHERIT FALSE, SET TRUE" in sql
    assert "REVOKE %I FROM %I" in sql
    assert "WITH ADMIN TRUE, INHERIT FALSE, SET FALSE" in sql
    assert "module guard maintenance role must be temporarily login-enabled" in sql
    assert "module guard maintenance role has concurrent sessions" in sql


def test_maintenance_authorization_is_finalizer_issued_single_use_and_expiring():
    sql = _sql()

    for marker in (
        "module_maintenance_authorization",
        "authorize_module_maintenance",
        "approval_digest",
        "attestation_digest",
        "database_uuid",
        "expires_at",
        "consumed_at",
        "completed_at",
        "recovered_at",
        "approval_digest text NOT NULL UNIQUE",
    ):
        assert marker in sql
    authorize = _function("authorize_module_maintenance")
    assert "session_user::name <> configured_finalizer" in authorize
    assert (
        "ON CONFLICT ON CONSTRAINT module_maintenance_authorization_pkey "
        "DO NOTHING"
    ) in authorize
    opened = _function("open_module_guard")
    assert "candidate.expires_at > pg_catalog.clock_timestamp()" in opened
    assert "epoch = epoch + 1" in opened
    assert "candidate.consumed_at IS NULL" in opened


def test_crash_rescue_revokes_every_temporary_loader_privilege():
    sql = _sql()
    rescue = _function("rescue_module_guard")

    assert "session_user::name <> configured_finalizer" in rescue
    assert "maintenance holder is still live" in rescue
    assert "REVOKE CREATE ON SCHEMA public" in rescue
    assert "REVOKE %I FROM %I" in rescue
    assert "module_guard_open = false" in rescue
    assert "recovered_at" in rescue


def test_event_triggers_rollback_unauthorized_ddl_and_protect_guard_objects():
    sql = _sql()

    for marker in (
        "CREATE EVENT TRIGGER odoo_accounting_cli_v3_ddl_guard_end",
        "ON ddl_command_end",
        "CREATE EVENT TRIGGER odoo_accounting_cli_v3_sql_drop_guard",
        "ON sql_drop",
        "CREATE EVENT TRIGGER odoo_accounting_cli_v3_table_rewrite_guard",
        "ON table_rewrite",
        "pg_event_trigger_ddl_commands()",
        "pg_event_trigger_dropped_objects()",
        "pg_event_trigger_table_rewrite_oid()",
        "module maintenance DDL is not authorized",
        "module guard protected object DDL is forbidden",
    ):
        assert marker in sql


def test_runtime_cannot_clear_effect_anchor_by_forging_terminal_row_state():
    sql = _sql()
    tracker = _function("track_operation_effect")

    assert "operation_effect_anchor" in tracker
    assert "resolved_at" not in re.sub(
        r"anchor\.resolved_at IS NULL", "", tracker
    )
    assert "finalize_operation_effect" not in tracker
    assert "unresolved_effect_count = ledger_count" in tracker


def test_operation_insert_is_empty_and_all_evidence_is_append_only():
    tracker = _function("track_operation_effect")

    for field in (
        "execution_evidence_json",
        "execution_evidence_digest",
        "verification_evidence_json",
        "verification_evidence_digest",
        "failure_evidence_json",
        "failure_evidence_digest",
        "recovery_plan_json",
        "recovery_plan_digest",
        "recovery_evidence_json",
        "recovery_evidence_digest",
        "execution_result_json",
        "execution_result_digest",
        "verification_result_json",
        "verification_result_digest",
        "recovery_result_json",
        "recovery_result_digest",
    ):
        assert f"NEW.{field} IS NOT NULL" in tracker
        assert f"OLD.{field} IS NOT NULL" in tracker


def test_finalizer_attestation_is_database_bound_and_uses_global_lock_order():
    finalizer = _function("finalize_operation_effect")

    for marker in (
        "expected_guard_installation_id uuid",
        "expected_database_oid oid",
        "expected_database_uuid uuid",
        "attestation_id uuid",
        "attestation_digest text",
        "resolution_operation_id text",
        "effect_finalization_receipt",
        "public.ir_config_parameter",
        "database.uuid",
    ):
        assert marker in finalizer
    operation_lock = finalizer.index("FOR UPDATE", finalizer.index("expected_operation_id"))
    state_lock = finalizer.index("module_guard_state", operation_lock)
    anchor_lock = finalizer.index("operation_effect_anchor", state_lock)
    assert operation_lock < state_lock < anchor_lock
    sql = _sql()
    assert (
        "GRANT SELECT ON TABLE public.ir_config_parameter "
        "TO odoo_accounting_cli_v3_guard_owner"
    ) in sql
    assert (
        "REVOKE ALL ON TABLE public.ir_config_parameter "
        "FROM odoo_accounting_cli_v3_guard_owner"
    ) in sql


def test_finalizer_replays_exact_persisted_receipt_after_proof_expiry():
    finalizer = _function("finalize_operation_effect")

    receipt_lookup = finalizer.index("SELECT receipt.* INTO stored_receipt")
    freshness_check = finalizer.index(
        "freshness_checked_at := pg_catalog.clock_timestamp()"
    )
    replay_return = finalizer.index("replayed := true", receipt_lookup)
    assert receipt_lookup < replay_return < freshness_check
    assert "proof_expires_at <= freshness_checked_at" in finalizer[freshness_check:]
    assert "stored_receipt.guard_epoch <> current_epoch" not in finalizer


def test_guard_checks_use_explicit_null_safe_constraints_and_ledger_reconciliation():
    sql = _sql()

    assert "schema_version integer NOT NULL CHECK (schema_version = 2)" in sql
    assert "module_guard_open IS TRUE" in sql
    assert "module_guard_open IS FALSE" in sql
    assert "operation_effect_resolution" in sql
    assert "resolution.anchor_id IS NULL" in sql
    assert "UPDATE odoo_accounting_cli_v3_guard.operation_effect_anchor" not in sql
    assert "unresolved_effect_count = (" in sql
    assert "FROM odoo_accounting_cli_v3_guard.operation_effect_anchor" in sql


def test_odoo_verifier_covers_v2_roles_catalog_acl_events_and_live_ledger():
    source = MODEL.read_text(encoding="utf-8")

    for marker in (
        'MODULE_GUARD_SCHEMA_VERSION = 2',
        '"operation_effect_anchor"',
        '"operation_effect_resolution"',
        '"effect_finalization_receipt"',
        '"module_maintenance_authorization"',
        '"authorize_module_maintenance"',
        '"finalize_operation_effect"',
        '"rescue_module_guard"',
        '"odoo_accounting_cli_v3_ddl_guard_end"',
        '"odoo_accounting_cli_v3_sql_drop_guard"',
        '"odoo_accounting_cli_v3_table_rewrite_guard"',
        "pg_auth_members",
        "admin_option",
        "inherit_option",
        "set_option",
        "pg_event_trigger",
        "pg_rewrite",
        "pg_policy",
        "relrowsecurity",
        "relforcerowsecurity",
        "attacl",
        "tgqual",
        "has_sequence_privilege",
        'snapshot["ledger_unresolved_effect_count"]',
        'snapshot["guard_installation_id"]',
        'snapshot["database_oid"]',
        'snapshot["database_uuid"]',
    ):
        assert marker in source

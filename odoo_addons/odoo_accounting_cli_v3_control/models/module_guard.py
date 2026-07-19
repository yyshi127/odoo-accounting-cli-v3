from __future__ import annotations

import hashlib
import uuid

from odoo import api, models
from odoo.exceptions import AccessError, ValidationError


MODULE_GUARD_PROTOCOL_VERSION = 1
MODULE_GUARD_SCHEMA_VERSION = 2
MODULE_GUARD_ADVISORY_NAMESPACE = 1329677142  # 0x4F414356 / OACV
MODULE_GUARD_ADVISORY_KEY = 1297040433  # 0x4D4F4431 / MOD1

_GUARD_OWNER = "odoo_accounting_cli_v3_guard_owner"
_GUARD_SCHEMA = "odoo_accounting_cli_v3_guard"

_GUARD_TABLES = {
    "module_guard_state",
    "operation_effect_anchor",
    "operation_effect_resolution",
    "effect_finalization_receipt",
    "module_maintenance_authorization",
}

_EXPECTED_TRIGGERS = {
    ("public", "ir_module_module", "odoo_accounting_cli_v3_module_change_guard"): (
        62,
        "guard_module_change",
    ),
    (
        "public",
        "ir_module_module",
        "odoo_accounting_cli_v3_module_change_guard_after",
    ): (60, "verify_module_change"),
    (
        "public",
        "odoo_accounting_cli_operation",
        "odoo_accounting_cli_v3_operation_effect_guard",
    ): (29, "track_operation_effect"),
    (
        "public",
        "odoo_accounting_cli_operation",
        "odoo_accounting_cli_v3_operation_no_truncate",
    ): (34, "reject_operation_truncate"),
}

_EXPECTED_EVENT_TRIGGERS = {
    "odoo_accounting_cli_v3_ddl_guard_end": ("ddl_command_end", "guard_ddl_end"),
    "odoo_accounting_cli_v3_sql_drop_guard": ("sql_drop", "guard_sql_drop"),
    "odoo_accounting_cli_v3_table_rewrite_guard": (
        "table_rewrite",
        "guard_table_rewrite",
    ),
}

# The second tuple item remains the runtime role's EXECUTE bit because the
# isolated PostgreSQL gate imports this literal contract directly.
_EXPECTED_FUNCTIONS = {
    "effect_is_unresolved": (
        "operation_state text, execution_result text, verification_result text, "
        "recovery_result text",
        False,
    ),
    "result_is_bound": (
        "result_text text, expected_kind text, expected_purpose text, "
        "expected_operation_id text, expected_request_id text, "
        "expected_operation_digest text, expected_company_id bigint, "
        "expected_capability_id text, expected_registry_digest text, "
        "expected_release_digest text, expected_evidence_digest text, "
        "expected_prior_evidence_digest text, expected_succeeded boolean",
        False,
    ),
    "track_operation_effect": ("", False),
    "reject_operation_truncate": ("", False),
    "guard_module_change": ("", False),
    "verify_module_change": ("", False),
    "read_module_guard_state": ("", True),
    "authorize_module_maintenance": (
        "requested_maintenance_id uuid, expected_guard_installation_id uuid, "
        "expected_database_oid oid, expected_database_uuid uuid, "
        "requested_approval_digest text, expected_registry_digest text, "
        "expected_release_digest text, requested_attestation_digest text, "
        "requested_expires_at timestamp with time zone",
        False,
    ),
    "finalize_operation_effect": (
        "expected_guard_installation_id uuid, expected_database_oid oid, "
        "expected_database_uuid uuid, requested_attestation_id uuid, "
        "requested_attestation_digest text, requested_verifier_key_id text, "
        "proof_verified_at timestamp with time zone, "
        "proof_expires_at timestamp with time zone, expected_operation_id text, "
        "expected_operation_digest text, expected_execution_result_digest text, "
        "resolution_operation_id text, resolution_operation_digest text, "
        "resolution_execution_result_digest text, requested_resolution_kind text, "
        "resolution_result_digest text",
        False,
    ),
    "open_module_guard": (
        "expected_epoch bigint, requested_maintenance_id uuid",
        False,
    ),
    "close_module_guard": (
        "expected_epoch bigint, expected_maintenance_id uuid",
        False,
    ),
    "rescue_module_guard": (
        "expected_epoch bigint, expected_maintenance_id uuid, "
        "requested_recovery_attestation_digest text",
        False,
    ),
    "module_maintenance_session_is_active": ("", False),
    "guard_ddl_end": ("", False),
    "guard_sql_drop": ("", False),
    "guard_table_rewrite": ("", False),
}

_FUNCTION_ACCESS = {
    "runtime": {"read_module_guard_state"},
    "maintenance": {
        "read_module_guard_state",
        "open_module_guard",
        "close_module_guard",
    },
    "finalizer": {
        "read_module_guard_state",
        "authorize_module_maintenance",
        "finalize_operation_effect",
        "rescue_module_guard",
    },
}

# Filled from the exact dollar-quoted bodies in sql/module_guard_v1.sql.
_FUNCTION_SOURCE_DIGESTS = {
    "effect_is_unresolved": "d9ccac6a470ea3187157e62661ab03011a1bd7c4a16f584e208b8bb007c583ad",
    "result_is_bound": "3009c8e31b6d29bddce4a4ca770ed6959d03543586ba8c0bcd1ea034dc5aa718",
    "track_operation_effect": "e7c5dbf8dc6442b750b967a08568d69c9088a9b6d8595c752766208572506529",
    "reject_operation_truncate": "efd33d59e2ac5fb730319b546f7f1e0b12afb35f08c83d4982656adfc4d299e6",
    "guard_module_change": "8bf64023840d0bcbb71ce0331afc22d707b69197cdf283becad4a3f8cd3a9273",
    "verify_module_change": "060ac6b1af665bebbf6ad3c7d14b0ed7beca392889396396a3657691c85e8a3c",
    "read_module_guard_state": "5ec7e9cb13cd258721b57a804e0c867445993b96e95e0571c6983422647ae03f",
    "authorize_module_maintenance": "16d5eeecf3163dc61a9a597bb8cc0c504ac7864be02b1ffd34490cec52bff745",
    "finalize_operation_effect": "56349ee88cb879ccdae51b7183909ca8dfd76499233f20063ea2771b1d1137e3",
    "open_module_guard": "411a3bcd4f59d767b14689bd86edeff0c1defa88e625e606b7fe09ca5b66ca89",
    "close_module_guard": "e4e435f84971a67edab3f6e345b823ea4867eb40bc32c6a6aa35c7234c2a711c",
    "rescue_module_guard": "9aca79b0d05154276f14491e32fdbb86f44ee37edffabc720d6d53b2f9814241",
    "module_maintenance_session_is_active": "c66b04c4376f3ec5d0dc66ff37b82b4d239057413e34c58373c3239e886a69ce",
    "guard_ddl_end": "4caa714dd07832a55350e82cb1fb0216bfd425bf887f0e7227c45773e5949186",
    "guard_sql_drop": "dd3d200c3182fd4b21f2cdaa5ff7cc9de0939d63ef8dbe6ca7398cf51543313d",
    "guard_table_rewrite": "9be5e5250aac3d84fc6222fd5a9410dff918544f42680f6fbc04a9a525b4100c",
}


class OdooAccountingCliModuleGuard(models.AbstractModel):
    _name = "odoo.accounting.cli.module.guard"
    _description = "Private Odoo Accounting CLI V3 Module Guard Verifier"

    @staticmethod
    def _fail(message):
        raise ValidationError(message)

    @staticmethod
    def _canonical_uuid(value, label):
        try:
            normalized = str(uuid.UUID(str(value)))
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValidationError(f"{label} is invalid") from exc
        if str(value) != normalized:
            raise ValidationError(f"{label} is invalid")
        return normalized

    @api.model
    def _read_snapshot(self):
        self.env.cr.execute(
            """
            SELECT
                protocol_version,
                schema_version,
                guard_installation_id::text,
                database_oid::bigint,
                database_uuid::text,
                epoch,
                module_guard_open,
                opened_epoch,
                unresolved_effect_count,
                ledger_unresolved_effect_count,
                runtime_role::text,
                maintenance_role::text,
                finalizer_role::text,
                maintenance_id::text,
                maintenance_expires_at,
                maintenance_holder_pid,
                maintenance_holder_backend_start,
                last_module_change_at,
                last_module_change_txid
            FROM odoo_accounting_cli_v3_guard.read_module_guard_state()
            """
        )
        fields = (
            "protocol_version",
            "schema_version",
            "guard_installation_id",
            "database_oid",
            "database_uuid",
            "epoch",
            "module_guard_open",
            "opened_epoch",
            "unresolved_effect_count",
            "ledger_unresolved_effect_count",
            "runtime_role",
            "maintenance_role",
            "finalizer_role",
            "maintenance_id",
            "maintenance_expires_at",
            "maintenance_holder_pid",
            "maintenance_holder_backend_start",
            "last_module_change_at",
            "last_module_change_txid",
        )
        row = self.env.cr.fetchone()
        if row is None or len(row) != len(fields):
            self._fail("module guard snapshot fields are invalid")
        return dict(zip(fields, row, strict=True))

    @api.model
    def _verify_runtime_role_boundary(self, snapshot):
        roles = (
            snapshot["runtime_role"],
            snapshot["maintenance_role"],
            snapshot["finalizer_role"],
            _GUARD_OWNER,
        )
        self.env.cr.execute(
            """
            SELECT
                role.rolname,
                role.rolcanlogin,
                role.rolsuper,
                role.rolinherit,
                role.rolcreaterole,
                role.rolcreatedb,
                role.rolreplication,
                role.rolbypassrls,
                role.rolconnlimit
            FROM pg_roles AS role
            WHERE role.rolname = ANY(%s)
            ORDER BY role.rolname
            """,
            [list(roles)],
        )
        attributes = {row[0]: tuple(row[1:]) for row in self.env.cr.fetchall()}
        if set(attributes) != set(roles):
            self._fail("module guard role set is invalid")
        ordinary_false = (False, False, False, False)
        runtime = attributes[snapshot["runtime_role"]]
        maintenance = attributes[snapshot["maintenance_role"]]
        finalizer = attributes[snapshot["finalizer_role"]]
        owner = attributes[_GUARD_OWNER]
        if (
            runtime[:3] != (True, False, True)
            or runtime[3:7] != ordinary_false
            or runtime[7] != -1
            or maintenance[:3] != (False, False, False)
            or maintenance[3:7] != ordinary_false
            or maintenance[7] != 1
            or finalizer[:3] != (True, False, False)
            or finalizer[3:7] != ordinary_false
            or finalizer[7] != -1
            or owner[:3] != (False, False, False)
            or owner[3:7] != ordinary_false
            or owner[7] != -1
        ):
            self._fail("module guard role attributes are invalid")
        self.env.cr.execute(
            """
            SELECT
                granted.rolname,
                member.rolname,
                membership.admin_option,
                membership.inherit_option,
                membership.set_option
            FROM pg_auth_members AS membership
            JOIN pg_roles AS granted ON granted.oid = membership.roleid
            JOIN pg_roles AS member ON member.oid = membership.member
            WHERE granted.rolname = ANY(%s) OR member.rolname = ANY(%s)
            ORDER BY granted.rolname, member.rolname
            """,
            [list(roles), list(roles)],
        )
        memberships = set(self.env.cr.fetchall())
        if memberships != {
            (
                snapshot["runtime_role"],
                _GUARD_OWNER,
                True,
                False,
                False,
            ),
            (
                snapshot["maintenance_role"],
                _GUARD_OWNER,
                False,
                True,
                False,
            ),
        }:
            self._fail("module guard role membership topology is invalid")
        self.env.cr.execute(
            """
            SELECT current_user, session_user, owner.rolname
            FROM pg_database AS database
            JOIN pg_roles AS owner ON owner.oid = database.datdba
            WHERE database.datname = current_database()
            """
        )
        identity = self.env.cr.fetchone()
        if identity != (
            snapshot["runtime_role"],
            snapshot["runtime_role"],
            _GUARD_OWNER,
        ):
            self._fail("module guard database ownership boundary is invalid")

    @api.model
    def _verify_relation_contract(self, snapshot):
        expected = {
            ("public", "ir_module_module", "r", _GUARD_OWNER),
            ("public", "odoo_accounting_cli_operation", "r", _GUARD_OWNER),
            *((_GUARD_SCHEMA, table, "r", _GUARD_OWNER) for table in _GUARD_TABLES),
        }
        self.env.cr.execute(
            """
            SELECT
                namespace.nspname,
                relation.relname,
                relation.relkind,
                owner.rolname,
                relation.relrowsecurity,
                relation.relforcerowsecurity
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            JOIN pg_roles AS owner ON owner.oid = relation.relowner
            WHERE (
                namespace.nspname = %s AND relation.relname = ANY(%s)
            ) OR (
                namespace.nspname = 'public'
                AND relation.relname IN (
                    'ir_module_module', 'odoo_accounting_cli_operation'
                )
            )
            """,
            [_GUARD_SCHEMA, sorted(_GUARD_TABLES)],
        )
        rows = self.env.cr.fetchall()
        if {tuple(row[:4]) for row in rows} != expected or any(
            row[4] is not False or row[5] is not False for row in rows
        ):
            self._fail("module guard relation ownership or RLS contract is invalid")
        self.env.cr.execute(
            """
            SELECT
                EXISTS (
                    SELECT 1 FROM pg_rewrite AS rule
                    JOIN pg_class AS relation ON relation.oid = rule.ev_class
                    JOIN pg_namespace AS namespace
                      ON namespace.oid = relation.relnamespace
                    WHERE (namespace.nspname, relation.relname) IN (
                        ('public', 'ir_module_module'),
                        ('public', 'odoo_accounting_cli_operation')
                    ) OR (
                        namespace.nspname = %s AND relation.relname = ANY(%s)
                    )
                ),
                EXISTS (
                    SELECT 1 FROM pg_policy AS policy
                    JOIN pg_class AS relation ON relation.oid = policy.polrelid
                    JOIN pg_namespace AS namespace
                      ON namespace.oid = relation.relnamespace
                    WHERE (namespace.nspname, relation.relname) IN (
                        ('public', 'ir_module_module'),
                        ('public', 'odoo_accounting_cli_operation')
                    ) OR (
                        namespace.nspname = %s AND relation.relname = ANY(%s)
                    )
                ),
                EXISTS (
                    SELECT 1 FROM pg_attribute AS attribute
                    JOIN pg_class AS relation ON relation.oid = attribute.attrelid
                    JOIN pg_namespace AS namespace
                      ON namespace.oid = relation.relnamespace
                    WHERE attribute.attnum > 0
                      AND NOT attribute.attisdropped
                      AND attribute.attacl IS NOT NULL
                      AND (
                          (namespace.nspname, relation.relname) IN (
                              ('public', 'ir_module_module'),
                              ('public', 'odoo_accounting_cli_operation')
                          ) OR (
                              namespace.nspname = %s
                              AND relation.relname = ANY(%s)
                          )
                      )
                )
            """,
            [
                _GUARD_SCHEMA,
                sorted(_GUARD_TABLES),
                _GUARD_SCHEMA,
                sorted(_GUARD_TABLES),
                _GUARD_SCHEMA,
                sorted(_GUARD_TABLES),
            ],
        )
        if self.env.cr.fetchone() != (False, False, False):
            self._fail("module guard rules, policies, or column ACLs are invalid")

    @api.model
    def _verify_acl_contract(self, snapshot):
        roles = {
            "runtime": snapshot["runtime_role"],
            "maintenance": snapshot["maintenance_role"],
            "finalizer": snapshot["finalizer_role"],
        }
        self.env.cr.execute(
            """
            SELECT namespace.nspname, owner.rolname,
                   has_schema_privilege(%s, namespace.oid, 'USAGE'),
                   has_schema_privilege(%s, namespace.oid, 'CREATE')
            FROM pg_namespace AS namespace
            JOIN pg_roles AS owner ON owner.oid = namespace.nspowner
            WHERE namespace.nspname IN ('public', %s)
            ORDER BY namespace.nspname
            """,
            [roles["runtime"], roles["runtime"], _GUARD_SCHEMA],
        )
        if self.env.cr.fetchall() != [
            (_GUARD_SCHEMA, _GUARD_OWNER, True, False),
            ("public", _GUARD_OWNER, True, False),
        ]:
            self._fail("module guard schema ACL contract is invalid")
        expected_runtime = {
            ("public", "ir_config_parameter"): (True,) * 7,
            ("public", "ir_module_module"): (True, True, True, True, False, False, False),
            ("public", "odoo_accounting_cli_operation"): (
                True,
                True,
                True,
                False,
                False,
                False,
                False,
            ),
            **{(_GUARD_SCHEMA, table): (False,) * 7 for table in _GUARD_TABLES},
        }
        for role_kind, role_name in roles.items():
            self.env.cr.execute(
                """
                SELECT namespace.nspname, relation.relname,
                       has_table_privilege(%s, relation.oid, 'SELECT'),
                       has_table_privilege(%s, relation.oid, 'INSERT'),
                       has_table_privilege(%s, relation.oid, 'UPDATE'),
                       has_table_privilege(%s, relation.oid, 'DELETE'),
                       has_table_privilege(%s, relation.oid, 'TRUNCATE'),
                       has_table_privilege(%s, relation.oid, 'REFERENCES'),
                       has_table_privilege(%s, relation.oid, 'TRIGGER')
                FROM pg_class AS relation
                JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                WHERE (namespace.nspname, relation.relname) IN (
                    ('public', 'ir_config_parameter'),
                    ('public', 'ir_module_module'),
                    ('public', 'odoo_accounting_cli_operation')
                ) OR (namespace.nspname = %s AND relation.relname = ANY(%s))
                """,
                [role_name] * 7 + [_GUARD_SCHEMA, sorted(_GUARD_TABLES)],
            )
            observed = {(row[0], row[1]): tuple(row[2:]) for row in self.env.cr.fetchall()}
            expected = expected_runtime if role_kind == "runtime" else {
                key: (False,) * 7 for key in expected_runtime
            }
            if observed != expected:
                self._fail("module guard table ACL contract is invalid")
        self.env.cr.execute(
            """
            SELECT
                has_table_privilege(%s, 'public.ir_config_parameter', 'SELECT'),
                has_table_privilege(%s, 'public.ir_config_parameter', 'INSERT'),
                has_table_privilege(%s, 'public.ir_config_parameter', 'UPDATE'),
                has_table_privilege(%s, 'public.ir_config_parameter', 'DELETE'),
                has_table_privilege(%s, 'public.ir_config_parameter', 'TRUNCATE'),
                has_table_privilege(%s, 'public.ir_config_parameter', 'REFERENCES'),
                has_table_privilege(%s, 'public.ir_config_parameter', 'TRIGGER')
            """,
            [_GUARD_OWNER] * 7,
        )
        if self.env.cr.fetchone() != (
            True,
            False,
            False,
            False,
            False,
            False,
            False,
        ):
            self._fail("module guard owner database identity ACL is invalid")

    @api.model
    def _verify_trigger_contract(self):
        self.env.cr.execute(
            """
            SELECT
                relation_schema.nspname,
                relation.relname,
                trigger.tgname,
                trigger.tgenabled,
                trigger.tgtype,
                trigger.tgisinternal,
                trigger.tgqual,
                function_schema.nspname,
                function.proname,
                owner.rolname
            FROM pg_trigger AS trigger
            JOIN pg_class AS relation ON relation.oid = trigger.tgrelid
            JOIN pg_namespace AS relation_schema
              ON relation_schema.oid = relation.relnamespace
            JOIN pg_proc AS function ON function.oid = trigger.tgfoid
            JOIN pg_namespace AS function_schema
              ON function_schema.oid = function.pronamespace
            JOIN pg_roles AS owner ON owner.oid = function.proowner
            WHERE NOT trigger.tgisinternal
              AND (relation_schema.nspname, relation.relname) IN (
                  ('public', 'ir_module_module'),
                  ('public', 'odoo_accounting_cli_operation')
              )
            """
        )
        observed = {}
        rows = self.env.cr.fetchall()
        for row in rows:
            key = (row[0], row[1], row[2])
            if (
                row[3] != "A"
                or row[5] is not False
                or row[6] is not None
                or row[7] != _GUARD_SCHEMA
                or row[9] != _GUARD_OWNER
            ):
                self._fail("module guard trigger catalog is invalid")
            observed[key] = (row[4], row[8])
        if observed != _EXPECTED_TRIGGERS or len(rows) != len(_EXPECTED_TRIGGERS):
            self._fail("module guard trigger set is invalid")
        self.env.cr.execute(
            """
            SELECT event.evtname, event.evtevent, event.evtenabled,
                   function_schema.nspname, function.proname,
                   function_owner.rolname, event_owner.rolsuper
            FROM pg_event_trigger AS event
            JOIN pg_proc AS function ON function.oid = event.evtfoid
            JOIN pg_namespace AS function_schema
              ON function_schema.oid = function.pronamespace
            JOIN pg_roles AS function_owner ON function_owner.oid = function.proowner
            JOIN pg_roles AS event_owner ON event_owner.oid = event.evtowner
            ORDER BY event.evtname
            """
        )
        events = self.env.cr.fetchall()
        actual = {
            row[0]: (row[1], row[4])
            for row in events
            if row[2] == "A"
            and row[3] == _GUARD_SCHEMA
            and row[5] == _GUARD_OWNER
            and row[6] is True
        }
        if actual != _EXPECTED_EVENT_TRIGGERS or len(events) != len(
            _EXPECTED_EVENT_TRIGGERS
        ):
            self._fail("module guard event trigger contract is invalid")

    @api.model
    def _verify_function_contract(self, snapshot):
        self.env.cr.execute(
            """
            SELECT
                function.proname,
                pg_get_function_identity_arguments(function.oid),
                owner.rolname,
                function.prosecdef,
                function.proconfig,
                function.prosrc,
                has_function_privilege(%s, function.oid, 'EXECUTE'),
                has_function_privilege(%s, function.oid, 'EXECUTE'),
                has_function_privilege(%s, function.oid, 'EXECUTE'),
                EXISTS (
                    SELECT 1 FROM aclexplode(
                        COALESCE(
                            function.proacl,
                            acldefault('f', function.proowner)
                        )
                    ) AS acl
                    WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
                )
            FROM pg_proc AS function
            JOIN pg_namespace AS namespace ON namespace.oid = function.pronamespace
            JOIN pg_roles AS owner ON owner.oid = function.proowner
            WHERE namespace.nspname = %s
            ORDER BY function.proname
            """,
            [
                snapshot["runtime_role"],
                snapshot["maintenance_role"],
                snapshot["finalizer_role"],
                _GUARD_SCHEMA,
            ],
        )
        rows = self.env.cr.fetchall()
        if {row[0] for row in rows} != set(_EXPECTED_FUNCTIONS):
            self._fail("module guard function set is invalid")
        for row in rows:
            name = row[0]
            expected_args, runtime_execute = _EXPECTED_FUNCTIONS[name]
            if (
                row[1] != expected_args
                or row[2] != _GUARD_OWNER
                or row[3] is not True
                or row[4] != ["search_path=pg_catalog"]
                or row[6] is not runtime_execute
                or row[7] is not (name in _FUNCTION_ACCESS["maintenance"])
                or row[8] is not (name in _FUNCTION_ACCESS["finalizer"])
                or row[9] is not False
                or hashlib.sha256(row[5].encode("utf-8")).hexdigest()
                != _FUNCTION_SOURCE_DIGESTS[name]
            ):
                self._fail("module guard function contract is invalid")

    @api.model
    def _verify_sequence_contract(self, snapshot):
        self.env.cr.execute(
            """
            SELECT namespace.nspname, sequence.relname, owner.rolname,
                   has_sequence_privilege(%s, sequence.oid, 'USAGE'),
                   has_sequence_privilege(%s, sequence.oid, 'SELECT'),
                   has_sequence_privilege(%s, sequence.oid, 'UPDATE'),
                   has_sequence_privilege(%s, sequence.oid, 'USAGE'),
                   has_sequence_privilege(%s, sequence.oid, 'USAGE')
            FROM pg_class AS sequence
            JOIN pg_namespace AS namespace ON namespace.oid = sequence.relnamespace
            JOIN pg_roles AS owner ON owner.oid = sequence.relowner
            WHERE sequence.relkind = 'S'
              AND (
                  namespace.nspname = %s
                  OR sequence.oid IN (
                      pg_get_serial_sequence('public.ir_module_module', 'id')::regclass,
                      pg_get_serial_sequence(
                          'public.odoo_accounting_cli_operation', 'id'
                      )::regclass
                  )
              )
            ORDER BY namespace.nspname, sequence.relname
            """,
            [
                snapshot["runtime_role"],
                snapshot["runtime_role"],
                snapshot["runtime_role"],
                snapshot["maintenance_role"],
                snapshot["finalizer_role"],
                _GUARD_SCHEMA,
            ],
        )
        rows = self.env.cr.fetchall()
        if len(rows) != 3:
            self._fail("module guard sequence set is invalid")
        for schema, _name, owner, usage, select, update, maintenance, finalizer in rows:
            if owner != _GUARD_OWNER or maintenance or finalizer:
                self._fail("module guard sequence owner or role ACL is invalid")
            expected_runtime = schema == "public"
            if (usage, select, update) != (
                expected_runtime,
                expected_runtime,
                False,
            ):
                self._fail("module guard runtime sequence ACL is invalid")

    @api.model
    def _verify_catalog_contract(self, snapshot):
        self._verify_relation_contract(snapshot)
        self._verify_acl_contract(snapshot)
        self._verify_trigger_contract()
        self._verify_function_contract(snapshot)
        self._verify_sequence_contract(snapshot)

    @api.model
    def _verify_maintenance_role(self, snapshot):
        if snapshot["maintenance_role"] in {
            snapshot["runtime_role"],
            snapshot["finalizer_role"],
            _GUARD_OWNER,
        }:
            self._fail("module guard maintenance role is invalid")
        self.env.cr.execute(
            """
            SELECT rolcanlogin, rolinherit, rolconnlimit,
                   pg_has_role(rolname, %s, 'MEMBER')
            FROM pg_roles WHERE rolname = %s
            """,
            [snapshot["runtime_role"], snapshot["maintenance_role"]],
        )
        if self.env.cr.fetchone() != (False, False, 1, False):
            self._fail("module guard maintenance role boundary is invalid")

    @api.model
    def _verify_finalizer_role(self, snapshot):
        self.env.cr.execute(
            """
            SELECT rolcanlogin, rolsuper, rolinherit, rolcreaterole,
                   rolcreatedb, rolreplication, rolbypassrls,
                   pg_has_role(rolname, %s, 'MEMBER')
            FROM pg_roles WHERE rolname = %s
            """,
            [_GUARD_OWNER, snapshot["finalizer_role"]],
        )
        if self.env.cr.fetchone() != (
            True,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
        ):
            self._fail("module guard finalizer role boundary is invalid")

    @api.model
    def _verified_snapshot(self):
        if not self.env.su:
            raise AccessError(
                "module guard verification is restricted to the root control plane"
            )
        snapshot = self._read_snapshot()
        if snapshot["protocol_version"] != MODULE_GUARD_PROTOCOL_VERSION:
            self._fail("module guard protocol version mismatch")
        if (
            snapshot["schema_version"] != MODULE_GUARD_SCHEMA_VERSION
            or type(snapshot["epoch"]) is not int
            or snapshot["epoch"] < 0
            or type(snapshot["database_oid"]) is not int
            or snapshot["database_oid"] <= 0
            or type(snapshot["unresolved_effect_count"]) is not int
            or type(snapshot["ledger_unresolved_effect_count"]) is not int
            or snapshot["unresolved_effect_count"] < 0
            or snapshot["ledger_unresolved_effect_count"] < 0
        ):
            self._fail("module guard snapshot fields are invalid")
        self._canonical_uuid(
            snapshot["guard_installation_id"], "module guard installation UUID"
        )
        self._canonical_uuid(snapshot["database_uuid"], "module guard database UUID")
        if (
            snapshot["module_guard_open"] is not False
            or snapshot["opened_epoch"] is not None
            or snapshot["maintenance_id"] is not None
            or snapshot["maintenance_expires_at"] is not None
            or snapshot["maintenance_holder_pid"] is not None
            or snapshot["maintenance_holder_backend_start"] is not None
            or snapshot["unresolved_effect_count"] != 0
            or snapshot["ledger_unresolved_effect_count"] != 0
        ):
            self._fail("module guard state is not closed and quiescent")
        if len(
            {
                snapshot["runtime_role"],
                snapshot["maintenance_role"],
                snapshot["finalizer_role"],
                _GUARD_OWNER,
            }
        ) != 4:
            self._fail("module guard role identities are not distinct")
        self.env.cr.execute(
            """
            SELECT database.oid::bigint, parameter.value
            FROM pg_database AS database
            CROSS JOIN LATERAL (
                SELECT min(value) AS value, count(*) AS count
                FROM ONLY public.ir_config_parameter
                WHERE key = 'database.uuid'
            ) AS parameter
            WHERE database.datname = current_database() AND parameter.count = 1
            """
        )
        if self.env.cr.fetchone() != (
            snapshot["database_oid"],
            snapshot["database_uuid"],
        ):
            self._fail("module guard live database identity is invalid")
        self._verify_runtime_role_boundary(snapshot)
        self._verify_catalog_contract(snapshot)
        self._verify_maintenance_role(snapshot)
        self._verify_finalizer_role(snapshot)
        return snapshot

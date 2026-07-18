\set ON_ERROR_STOP on

-- Privileged post-install activation for module-guard protocol v1.
--
-- Required psql variables:
--   runtime_role      ordinary Odoo database login
--   maintenance_role  normally-NOLOGIN one-session loader identity
--   finalizer_role    separate control-plane login that resolves effect anchors
--
-- An ordinary Odoo addon installation cannot establish this ownership boundary:
-- the role that owns ir_module_module can always disable or remove its triggers.
-- Install the addon first (its private verifier fails closed while this contract is
-- absent), then run this file as a database superuser.  Future upgrades must use
-- the maintenance role and the open/close functions below.  Never load this file
-- through the addon manifest.

\if :{?runtime_role}
\else
\echo 'module_guard_v1.sql requires -v runtime_role=...'
\quit 3
\endif
\if :{?maintenance_role}
\else
\echo 'module_guard_v1.sql requires -v maintenance_role=...'
\quit 3
\endif
\if :{?finalizer_role}
\else
\echo 'module_guard_v1.sql requires -v finalizer_role=...'
\quit 3
\endif

SELECT set_config('odoo_accounting_cli_v3.runtime_role', :'runtime_role', false);
SELECT set_config(
    'odoo_accounting_cli_v3.maintenance_role',
    :'maintenance_role',
    false
);
SELECT set_config(
    'odoo_accounting_cli_v3.finalizer_role',
    :'finalizer_role',
    false
);

BEGIN;

DO $bootstrap_roles$
DECLARE
    runtime_name text := current_setting('odoo_accounting_cli_v3.runtime_role');
    maintenance_name text := current_setting(
        'odoo_accounting_cli_v3.maintenance_role'
    );
    finalizer_name text := current_setting(
        'odoo_accounting_cli_v3.finalizer_role'
    );
BEGIN
    IF runtime_name = maintenance_name
       OR runtime_name = finalizer_name
       OR maintenance_name = finalizer_name
       OR runtime_name = 'odoo_accounting_cli_v3_guard_owner'
       OR maintenance_name = 'odoo_accounting_cli_v3_guard_owner'
       OR finalizer_name = 'odoo_accounting_cli_v3_guard_owner'
       OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname = runtime_name)
       OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname = maintenance_name)
       OR NOT EXISTS (SELECT FROM pg_roles WHERE rolname = finalizer_name)
    THEN
        RAISE EXCEPTION 'module guard roles are missing or not distinct';
    END IF;
    IF NOT EXISTS (
        SELECT FROM pg_roles
        WHERE rolname = 'odoo_accounting_cli_v3_guard_owner'
    ) THEN
        CREATE ROLE odoo_accounting_cli_v3_guard_owner
            NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    END IF;
END
$bootstrap_roles$;

ALTER ROLE odoo_accounting_cli_v3_guard_owner
    NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;

SELECT format(
    'ALTER ROLE %I LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE '
    'NOREPLICATION NOBYPASSRLS',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec
SELECT format(
    'ALTER ROLE %I NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE '
    'NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1',
    current_setting('odoo_accounting_cli_v3.maintenance_role')
) \gexec
SELECT format(
    'ALTER ROLE %I LOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE '
    'NOREPLICATION NOBYPASSRLS',
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec
SELECT format(
    'REVOKE odoo_accounting_cli_v3_guard_owner FROM %I, %I, %I',
    current_setting('odoo_accounting_cli_v3.runtime_role'),
    current_setting('odoo_accounting_cli_v3.maintenance_role'),
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec
SELECT format(
    'REVOKE %I FROM %I',
    current_setting('odoo_accounting_cli_v3.runtime_role'),
    current_setting('odoo_accounting_cli_v3.maintenance_role')
) \gexec
SELECT format(
    'GRANT %I TO odoo_accounting_cli_v3_guard_owner '
    'WITH ADMIN TRUE, INHERIT FALSE, SET FALSE',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec
SELECT format(
    'REVOKE %I FROM %I',
    current_setting('odoo_accounting_cli_v3.runtime_role'),
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec

DO $verify_role_topology$
DECLARE
    runtime_oid oid := (
        SELECT oid FROM pg_catalog.pg_roles
        WHERE rolname = current_setting('odoo_accounting_cli_v3.runtime_role')
    );
    maintenance_oid oid := (
        SELECT oid FROM pg_catalog.pg_roles
        WHERE rolname = current_setting('odoo_accounting_cli_v3.maintenance_role')
    );
    finalizer_oid oid := (
        SELECT oid FROM pg_catalog.pg_roles
        WHERE rolname = current_setting('odoo_accounting_cli_v3.finalizer_role')
    );
    owner_oid oid := (
        SELECT oid FROM pg_catalog.pg_roles
        WHERE rolname = 'odoo_accounting_cli_v3_guard_owner'
    );
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        WHERE (
            membership.roleid IN (
                runtime_oid, maintenance_oid, finalizer_oid, owner_oid
            )
            OR membership.member IN (
                runtime_oid, maintenance_oid, finalizer_oid, owner_oid
            )
        )
        AND NOT (
            membership.roleid = runtime_oid
            AND membership.member = owner_oid
            AND membership.admin_option
            AND NOT membership.inherit_option
            AND NOT membership.set_option
        )
    )
       OR pg_catalog.pg_has_role(maintenance_oid, runtime_oid, 'MEMBER')
       OR NOT pg_catalog.pg_has_role(owner_oid, runtime_oid, 'MEMBER')
       OR pg_catalog.pg_has_role(runtime_oid, owner_oid, 'MEMBER')
       OR pg_catalog.pg_has_role(maintenance_oid, owner_oid, 'MEMBER')
       OR pg_catalog.pg_has_role(finalizer_oid, owner_oid, 'MEMBER')
    THEN
        RAISE EXCEPTION 'module guard role membership topology is unsafe';
    END IF;
END
$verify_role_topology$;

-- This bootstrap is deliberately single-use.  Adopting an attacker-created
-- schema/table/trigger while connected as a superuser would execute poisoned
-- catalog objects with bootstrap authority.  A later protocol revision must
-- therefore use a separately reviewed, versioned privileged migration.
DO $preflight_catalog$
DECLARE
    runtime_oid oid := (
        SELECT oid
        FROM pg_catalog.pg_roles
        WHERE rolname = current_setting('odoo_accounting_cli_v3.runtime_role')
    );
    protected_relations oid[] := ARRAY[
        'public.ir_module_module'::pg_catalog.regclass::oid,
        'public.odoo_accounting_cli_operation'::pg_catalog.regclass::oid
    ];
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace
        WHERE nspname = 'odoo_accounting_cli_v3_guard'
    ) THEN
        RAISE EXCEPTION
            'module guard schema already exists; use a versioned privileged migration';
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class AS relation
        WHERE relation.oid = ANY(protected_relations)
          AND relation.relkind = 'r'
          AND NOT relation.relispartition
          AND NOT relation.relrowsecurity
          AND NOT relation.relforcerowsecurity
          AND relation.relowner = runtime_oid) <> 2
       OR (
           SELECT database.datdba
           FROM pg_catalog.pg_database AS database
           WHERE database.datname = pg_catalog.current_database()
       ) <> runtime_oid
    THEN
        RAISE EXCEPTION 'protected Odoo relations are not pristine runtime-owned tables';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_trigger AS trigger
        WHERE trigger.tgrelid = ANY(protected_relations)
          AND NOT trigger.tgisinternal
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_rewrite AS rule
        WHERE rule.ev_class = ANY(protected_relations)
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_policy AS policy
        WHERE policy.polrelid = ANY(protected_relations)
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid = ANY(protected_relations)
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND attribute.attacl IS NOT NULL
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation,
             LATERAL pg_catalog.aclexplode(
                 COALESCE(
                     relation.relacl,
                     pg_catalog.acldefault('r', relation.relowner)
                 )
             ) AS acl
        WHERE relation.oid = ANY(protected_relations)
          AND acl.grantee NOT IN (0, relation.relowner)
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation,
             LATERAL pg_catalog.aclexplode(
                 COALESCE(
                     relation.relacl,
                     pg_catalog.acldefault('r', relation.relowner)
                 )
             ) AS acl
        WHERE relation.oid = ANY(protected_relations)
          AND acl.grantee = 0
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_event_trigger AS event_trigger
        WHERE event_trigger.evtenabled <> 'D'
    ) THEN
        RAISE EXCEPTION 'protected Odoo catalog has triggers, rules, policies, ACLs, or event hooks';
    END IF;
END
$preflight_catalog$;

SELECT format(
    'ALTER DATABASE %I OWNER TO odoo_accounting_cli_v3_guard_owner',
    current_database()
) \gexec

LOCK TABLE public.ir_module_module IN ACCESS EXCLUSIVE MODE;
LOCK TABLE public.odoo_accounting_cli_operation IN ACCESS EXCLUSIVE MODE;

ALTER SCHEMA public OWNER TO odoo_accounting_cli_v3_guard_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SELECT format('REVOKE CREATE ON SCHEMA public FROM %I', role.rolname)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
\gexec

CREATE SCHEMA odoo_accounting_cli_v3_guard
    AUTHORIZATION odoo_accounting_cli_v3_guard_owner;
ALTER SCHEMA odoo_accounting_cli_v3_guard
    OWNER TO odoo_accounting_cli_v3_guard_owner;
REVOKE ALL ON SCHEMA odoo_accounting_cli_v3_guard FROM PUBLIC;
SELECT format(
    'REVOKE ALL ON SCHEMA odoo_accounting_cli_v3_guard FROM %I',
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
\gexec
SELECT format(
    'GRANT USAGE ON SCHEMA odoo_accounting_cli_v3_guard TO %I',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec
SELECT format(
    'GRANT USAGE ON SCHEMA odoo_accounting_cli_v3_guard TO %I',
    current_setting('odoo_accounting_cli_v3.maintenance_role')
) \gexec
SELECT format(
    'GRANT USAGE ON SCHEMA odoo_accounting_cli_v3_guard TO %I',
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec

CREATE TABLE odoo_accounting_cli_v3_guard.module_guard_state (
    id smallint PRIMARY KEY CHECK (id = 1),
    protocol_version integer NOT NULL CHECK (protocol_version = 1),
    schema_version integer NOT NULL CHECK (schema_version = 2),
    guard_installation_id uuid NOT NULL,
    database_oid oid NOT NULL CHECK (database_oid > 0::oid),
    database_uuid uuid NOT NULL,
    epoch bigint NOT NULL CHECK (epoch >= 0),
    module_guard_open boolean NOT NULL,
    opened_epoch bigint,
    unresolved_effect_count bigint NOT NULL CHECK (unresolved_effect_count >= 0),
    runtime_role name NOT NULL,
    maintenance_role name NOT NULL,
    finalizer_role name NOT NULL,
    maintenance_id uuid,
    maintenance_expires_at timestamp with time zone,
    maintenance_holder_pid integer,
    maintenance_holder_backend_start timestamp with time zone,
    last_module_change_at timestamp with time zone,
    last_module_change_txid text,
    CHECK (
        runtime_role <> maintenance_role
        AND runtime_role <> finalizer_role
        AND maintenance_role <> finalizer_role
        AND runtime_role <> 'odoo_accounting_cli_v3_guard_owner'::name
        AND maintenance_role <> 'odoo_accounting_cli_v3_guard_owner'::name
        AND finalizer_role <> 'odoo_accounting_cli_v3_guard_owner'::name
    ),
    CHECK (
        (
            module_guard_open IS TRUE
            AND opened_epoch IS NOT NULL
            AND opened_epoch = epoch
            AND maintenance_id IS NOT NULL
            AND maintenance_expires_at IS NOT NULL
            AND maintenance_holder_pid IS NOT NULL
            AND maintenance_holder_pid > 1
            AND maintenance_holder_backend_start IS NOT NULL
        )
        OR (
            module_guard_open IS FALSE
            AND opened_epoch IS NULL
            AND maintenance_id IS NULL
            AND maintenance_expires_at IS NULL
            AND maintenance_holder_pid IS NULL
            AND maintenance_holder_backend_start IS NULL
        )
    )
);
ALTER TABLE odoo_accounting_cli_v3_guard.module_guard_state
    OWNER TO odoo_accounting_cli_v3_guard_owner;

DO $guard_state_shape$
DECLARE
    expected_runtime name := current_setting(
        'odoo_accounting_cli_v3.runtime_role'
    )::name;
    expected_maintenance name := current_setting(
        'odoo_accounting_cli_v3.maintenance_role'
    )::name;
    expected_finalizer name := current_setting(
        'odoo_accounting_cli_v3.finalizer_role'
    )::name;
    observed_database_oid oid := (
        SELECT oid FROM pg_catalog.pg_database
        WHERE datname = pg_catalog.current_database()
    );
    observed_database_uuid uuid := (
        SELECT pg_catalog.min(value)::uuid
        FROM ONLY public.ir_config_parameter
        WHERE key = 'database.uuid'
        HAVING pg_catalog.count(*) = 1
    );
BEGIN
    IF observed_database_oid IS NULL OR observed_database_uuid IS NULL THEN
        RAISE EXCEPTION 'database identity is absent or ambiguous';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM odoo_accounting_cli_v3_guard.module_guard_state
        WHERE id <> 1
           OR protocol_version <> 1
           OR schema_version <> 2
           OR database_oid <> observed_database_oid
           OR database_uuid <> observed_database_uuid
           OR runtime_role <> expected_runtime
           OR maintenance_role <> expected_maintenance
           OR finalizer_role <> expected_finalizer
           OR module_guard_open
           OR opened_epoch IS NOT NULL
           OR maintenance_id IS NOT NULL
           OR maintenance_expires_at IS NOT NULL
           OR maintenance_holder_pid IS NOT NULL
           OR maintenance_holder_backend_start IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'existing module guard state is incompatible or open';
    END IF;
    INSERT INTO odoo_accounting_cli_v3_guard.module_guard_state (
        id,
        protocol_version,
        schema_version,
        guard_installation_id,
        database_oid,
        database_uuid,
        epoch,
        module_guard_open,
        opened_epoch,
        unresolved_effect_count,
        runtime_role,
        maintenance_role,
        finalizer_role
    )
    VALUES (
        1, 1, 2, pg_catalog.gen_random_uuid(),
        observed_database_oid, observed_database_uuid,
        0, false, NULL, 0,
        expected_runtime, expected_maintenance, expected_finalizer
    )
    ON CONFLICT (id) DO NOTHING;
END
$guard_state_shape$;

CREATE TABLE odoo_accounting_cli_v3_guard.operation_effect_anchor (
    anchor_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation_record_id bigint NOT NULL,
    operation_id text NOT NULL,
    operation_digest text NOT NULL CHECK (
        operation_digest ~ '^[0-9a-f]{64}$'
    ),
    registry_digest text NOT NULL CHECK (
        registry_digest ~ '^[0-9a-f]{64}$'
    ),
    release_digest text NOT NULL CHECK (
        release_digest ~ '^[0-9a-f]{64}$'
    ),
    effect_phase text NOT NULL CHECK (effect_phase = 'execution'),
    source_digest text NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
    source_evidence_digest text NOT NULL CHECK (
        source_evidence_digest ~ '^[0-9a-f]{64}$'
    ),
    opened_at timestamp with time zone NOT NULL,
    opened_txid text NOT NULL,
    UNIQUE (operation_record_id, effect_phase),
    UNIQUE (operation_id, effect_phase),
    FOREIGN KEY (operation_record_id)
        REFERENCES public.odoo_accounting_cli_operation(id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);
ALTER TABLE odoo_accounting_cli_v3_guard.operation_effect_anchor
    OWNER TO odoo_accounting_cli_v3_guard_owner;

CREATE TABLE odoo_accounting_cli_v3_guard.module_maintenance_authorization (
    maintenance_id uuid PRIMARY KEY,
    guard_installation_id uuid NOT NULL,
    database_oid oid NOT NULL CHECK (database_oid > 0::oid),
    database_uuid uuid NOT NULL,
    approval_digest text NOT NULL UNIQUE CHECK (
        approval_digest ~ '^[0-9a-f]{64}$'
    ),
    registry_digest text NOT NULL CHECK (registry_digest ~ '^[0-9a-f]{64}$'),
    release_digest text NOT NULL CHECK (release_digest ~ '^[0-9a-f]{64}$'),
    attestation_digest text NOT NULL UNIQUE CHECK (
        attestation_digest ~ '^[0-9a-f]{64}$'
    ),
    authorized_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    authorized_by name NOT NULL,
    consumed_epoch bigint,
    consumed_at timestamp with time zone,
    completed_at timestamp with time zone,
    recovered_at timestamp with time zone,
    recovery_attestation_digest text CHECK (
        recovery_attestation_digest IS NULL
        OR recovery_attestation_digest ~ '^[0-9a-f]{64}$'
    ),
    resolution_txid text,
    CHECK (expires_at > authorized_at),
    CHECK (
        (
            consumed_epoch IS NULL
            AND consumed_at IS NULL
            AND completed_at IS NULL
            AND recovered_at IS NULL
            AND recovery_attestation_digest IS NULL
            AND resolution_txid IS NULL
        )
        OR (
            consumed_epoch IS NOT NULL
            AND consumed_epoch > 0
            AND consumed_at IS NOT NULL
            AND (
                (
                    completed_at IS NULL
                    AND recovered_at IS NULL
                    AND recovery_attestation_digest IS NULL
                    AND resolution_txid IS NULL
                )
                OR (
                    completed_at IS NOT NULL
                    AND recovered_at IS NULL
                    AND recovery_attestation_digest IS NULL
                    AND resolution_txid IS NOT NULL
                )
                OR (
                    completed_at IS NULL
                    AND recovered_at IS NOT NULL
                    AND recovery_attestation_digest IS NOT NULL
                    AND resolution_txid IS NOT NULL
                )
            )
        )
    )
);
ALTER TABLE odoo_accounting_cli_v3_guard.module_maintenance_authorization
    OWNER TO odoo_accounting_cli_v3_guard_owner;

CREATE TABLE odoo_accounting_cli_v3_guard.effect_finalization_receipt (
    attestation_id uuid PRIMARY KEY,
    guard_installation_id uuid NOT NULL,
    database_oid oid NOT NULL CHECK (database_oid > 0::oid),
    database_uuid uuid NOT NULL,
    expected_operation_record_id bigint NOT NULL REFERENCES
        public.odoo_accounting_cli_operation(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    expected_operation_id text NOT NULL,
    expected_operation_digest text NOT NULL CHECK (
        expected_operation_digest ~ '^[0-9a-f]{64}$'
    ),
    expected_execution_result_digest text NOT NULL CHECK (
        expected_execution_result_digest ~ '^[0-9a-f]{64}$'
    ),
    resolution_operation_record_id bigint NOT NULL REFERENCES
        public.odoo_accounting_cli_operation(id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    resolution_operation_id text NOT NULL,
    resolution_operation_digest text NOT NULL CHECK (
        resolution_operation_digest ~ '^[0-9a-f]{64}$'
    ),
    resolution_execution_result_digest text NOT NULL CHECK (
        resolution_execution_result_digest ~ '^[0-9a-f]{64}$'
    ),
    resolution_result_digest text NOT NULL CHECK (
        resolution_result_digest ~ '^[0-9a-f]{64}$'
    ),
    resolution_kind text NOT NULL CHECK (
        resolution_kind IN ('verified', 'recovered')
    ),
    attestation_digest text NOT NULL UNIQUE CHECK (
        attestation_digest ~ '^[0-9a-f]{64}$'
    ),
    verifier_key_id text NOT NULL CHECK (pg_catalog.length(verifier_key_id) > 0),
    verified_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    guard_epoch bigint NOT NULL CHECK (guard_epoch >= 0),
    resolved_anchor_count integer NOT NULL CHECK (resolved_anchor_count > 0),
    remaining_unresolved_count bigint NOT NULL CHECK (
        remaining_unresolved_count >= 0
    ),
    finalized_at timestamp with time zone NOT NULL,
    finalized_txid text NOT NULL,
    finalizer_role name NOT NULL,
    CHECK (expires_at > verified_at),
    UNIQUE (expected_operation_record_id, resolution_kind)
);
ALTER TABLE odoo_accounting_cli_v3_guard.effect_finalization_receipt
    OWNER TO odoo_accounting_cli_v3_guard_owner;

CREATE TABLE odoo_accounting_cli_v3_guard.operation_effect_resolution (
    anchor_id bigint PRIMARY KEY REFERENCES
        odoo_accounting_cli_v3_guard.operation_effect_anchor(anchor_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    attestation_id uuid NOT NULL REFERENCES
        odoo_accounting_cli_v3_guard.effect_finalization_receipt(attestation_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    resolution_kind text NOT NULL CHECK (
        resolution_kind IN ('verified', 'recovered')
    ),
    resolution_result_digest text NOT NULL CHECK (
        resolution_result_digest ~ '^[0-9a-f]{64}$'
    ),
    finalized_at timestamp with time zone NOT NULL,
    finalized_txid text NOT NULL,
    finalizer_role name NOT NULL
);
ALTER TABLE odoo_accounting_cli_v3_guard.operation_effect_resolution
    OWNER TO odoo_accounting_cli_v3_guard_owner;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.effect_is_unresolved(
    operation_state text,
    execution_result text,
    verification_result text,
    recovery_result text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    execution_succeeded boolean;
    verification_succeeded boolean;
    recovery_succeeded boolean;
BEGIN
    IF operation_state NOT IN (
        'claimed', 'committed', 'verified', 'failed', 'recovering', 'recovered'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation state cannot be classified by module guard';
    END IF;
    IF operation_state = 'claimed' THEN
        IF execution_result IS NOT NULL
           OR verification_result IS NOT NULL
           OR recovery_result IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'claimed operation has terminal result evidence';
        END IF;
        RETURN false;
    END IF;
    IF execution_result IS NULL
       OR jsonb_typeof(execution_result::jsonb -> 'succeeded') <> 'boolean'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation execution result cannot be classified';
    END IF;
    execution_succeeded := (execution_result::jsonb ->> 'succeeded')::boolean;
    IF verification_result IS NOT NULL THEN
        IF jsonb_typeof(verification_result::jsonb -> 'succeeded') <> 'boolean' THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'operation verification result cannot be classified';
        END IF;
        verification_succeeded := (
            verification_result::jsonb ->> 'succeeded'
        )::boolean;
    END IF;
    IF recovery_result IS NOT NULL THEN
        IF jsonb_typeof(recovery_result::jsonb -> 'succeeded') <> 'boolean' THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'operation recovery result cannot be classified';
        END IF;
        recovery_succeeded := (recovery_result::jsonb ->> 'succeeded')::boolean;
    END IF;
    IF operation_state = 'committed' THEN
        IF NOT execution_succeeded
           OR verification_result IS NOT NULL
           OR recovery_result IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'committed operation evidence is inconsistent';
        END IF;
        RETURN true;
    END IF;
    IF operation_state = 'verified' THEN
        IF NOT execution_succeeded
           OR verification_succeeded IS DISTINCT FROM true
           OR recovery_result IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'verified operation evidence is inconsistent';
        END IF;
        RETURN false;
    END IF;
    IF operation_state = 'recovering' THEN
        IF recovery_result IS NOT NULL
           OR (NOT execution_succeeded AND verification_result IS NOT NULL)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'recovering operation evidence is inconsistent';
        END IF;
        RETURN execution_succeeded;
    END IF;
    IF operation_state = 'recovered' THEN
        IF recovery_succeeded IS DISTINCT FROM true
           OR (NOT execution_succeeded AND verification_result IS NOT NULL)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'recovered operation evidence is inconsistent';
        END IF;
        RETURN false;
    END IF;
    IF NOT execution_succeeded THEN
        IF verification_result IS NOT NULL OR recovery_succeeded IS TRUE THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'failed execution evidence is inconsistent';
        END IF;
        RETURN false;
    END IF;
    IF recovery_succeeded IS TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'successful recovery is not in recovered state';
    END IF;
    RETURN true;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.result_is_bound(
    result_text text,
    expected_kind text,
    expected_purpose text,
    expected_operation_id text,
    expected_request_id text,
    expected_operation_digest text,
    expected_company_id bigint,
    expected_capability_id text,
    expected_registry_digest text,
    expected_release_digest text,
    expected_evidence_digest text,
    expected_prior_evidence_digest text,
    expected_succeeded boolean
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    document jsonb := result_text::jsonb;
    actual_keys text[];
BEGIN
    IF pg_catalog.jsonb_typeof(document) <> 'object' THEN
        RETURN false;
    END IF;
    SELECT pg_catalog.array_agg(key ORDER BY key) INTO actual_keys
    FROM pg_catalog.jsonb_object_keys(document) AS key;
    IF actual_keys <> ARRAY[
        'capability_id', 'company_id', 'evidence_digest', 'issued_at',
        'issuer', 'key_id', 'kind', 'operation_digest', 'operation_id',
        'operation_revision', 'operation_state_digest',
        'prior_evidence_digest', 'purpose', 'registry_digest',
        'release_digest', 'request_id', 'signature', 'succeeded', 'version'
    ]::text[] THEN
        RETURN false;
    END IF;
    RETURN pg_catalog.coalesce((
        pg_catalog.jsonb_typeof(document -> 'version') = 'number'
        AND document ->> 'version' = '2'
        AND pg_catalog.jsonb_typeof(document -> 'kind') = 'string'
        AND document ->> 'kind' = expected_kind
        AND pg_catalog.jsonb_typeof(document -> 'purpose') = 'string'
        AND document ->> 'purpose' = expected_purpose
        AND pg_catalog.jsonb_typeof(document -> 'operation_id') = 'string'
        AND document ->> 'operation_id' = expected_operation_id
        AND pg_catalog.jsonb_typeof(document -> 'request_id') = 'string'
        AND document ->> 'request_id' = expected_request_id
        AND pg_catalog.jsonb_typeof(document -> 'operation_digest') = 'string'
        AND document ->> 'operation_digest' = expected_operation_digest
        AND expected_operation_digest ~ '^[0-9a-f]{64}$'
        AND pg_catalog.jsonb_typeof(document -> 'company_id') = 'number'
        AND document ->> 'company_id' = expected_company_id::text
        AND expected_company_id > 0
        AND pg_catalog.jsonb_typeof(document -> 'capability_id') = 'string'
        AND document ->> 'capability_id' = expected_capability_id
        AND pg_catalog.jsonb_typeof(document -> 'registry_digest') = 'string'
        AND document ->> 'registry_digest' = expected_registry_digest
        AND expected_registry_digest ~ '^[0-9a-f]{64}$'
        AND pg_catalog.jsonb_typeof(document -> 'release_digest') = 'string'
        AND document ->> 'release_digest' = expected_release_digest
        AND expected_release_digest ~ '^[0-9a-f]{64}$'
        AND pg_catalog.jsonb_typeof(document -> 'evidence_digest') = 'string'
        AND document ->> 'evidence_digest' = expected_evidence_digest
        AND expected_evidence_digest ~ '^[0-9a-f]{64}$'
        AND (
            (
                expected_prior_evidence_digest IS NULL
                AND document -> 'prior_evidence_digest' = 'null'::jsonb
            )
            OR (
                expected_prior_evidence_digest ~ '^[0-9a-f]{64}$'
                AND pg_catalog.jsonb_typeof(
                    document -> 'prior_evidence_digest'
                ) = 'string'
                AND document ->> 'prior_evidence_digest' = (
                    expected_prior_evidence_digest
                )
            )
        )
        AND pg_catalog.jsonb_typeof(document -> 'succeeded') = 'boolean'
        AND document -> 'succeeded' = pg_catalog.to_jsonb(expected_succeeded)
        AND pg_catalog.jsonb_typeof(document -> 'operation_revision') = 'number'
        AND document ->> 'operation_revision' ~ '^[0-9]+$'
        AND pg_catalog.jsonb_typeof(
            document -> 'operation_state_digest'
        ) = 'string'
        AND document ->> 'operation_state_digest' ~ '^[0-9a-f]{64}$'
        AND pg_catalog.jsonb_typeof(document -> 'issued_at') = 'string'
        AND document ->> 'issued_at' ~ (
            '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:'
            '[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$'
        )
        AND pg_catalog.jsonb_typeof(document -> 'issuer') = 'string'
        AND pg_catalog.length(document ->> 'issuer') > 0
        AND pg_catalog.jsonb_typeof(document -> 'key_id') = 'string'
        AND pg_catalog.length(document ->> 'key_id') > 0
        AND pg_catalog.jsonb_typeof(document -> 'signature') = 'string'
        AND document ->> 'signature' ~ '^[0-9a-f]{64}$'
    ), false);
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.track_operation_effect()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    cached_count bigint;
    ledger_count bigint;
    inserted_rows integer := 0;
    inserted_now integer := 0;
    execution_succeeded boolean;
    verification_succeeded boolean;
    recovery_succeeded boolean;
    resulting_count bigint;
BEGIN
    IF NOT pg_try_advisory_xact_lock_shared(1329677142, 1297040433) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55P03',
            MESSAGE = 'module maintenance excludes accounting operation changes';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'accounting operation anchors cannot be deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'claimed'
           OR NEW.execution_evidence_json IS NOT NULL
           OR NEW.execution_evidence_digest IS NOT NULL
           OR NEW.execution_result_json IS NOT NULL
           OR NEW.execution_result_digest IS NOT NULL
           OR NEW.verification_evidence_json IS NOT NULL
           OR NEW.verification_evidence_digest IS NOT NULL
           OR NEW.verification_result_json IS NOT NULL
           OR NEW.verification_result_digest IS NOT NULL
           OR NEW.failure_evidence_json IS NOT NULL
           OR NEW.failure_evidence_digest IS NOT NULL
           OR NEW.recovery_plan_json IS NOT NULL
           OR NEW.recovery_plan_digest IS NOT NULL
           OR NEW.recovery_evidence_json IS NOT NULL
           OR NEW.recovery_evidence_digest IS NOT NULL
           OR NEW.recovery_result_json IS NOT NULL
           OR NEW.recovery_result_digest IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'new accounting operation anchor is not claimed';
        END IF;
    ELSE
        IF ROW(
            NEW.operation_id,
            NEW.request_id,
            NEW.capability_id,
            NEW.idempotency_scope,
            NEW.operation_digest,
            NEW.protocol_version,
            NEW.precheck_digest,
            NEW.principal,
            NEW.requester_id,
            NEW.approver_id,
            NEW.company_id,
            NEW.environment,
            NEW.capability_channel,
            NEW.registry_digest,
            NEW.release_digest
        ) IS DISTINCT FROM ROW(
            OLD.operation_id,
            OLD.request_id,
            OLD.capability_id,
            OLD.idempotency_scope,
            OLD.operation_digest,
            OLD.protocol_version,
            OLD.precheck_digest,
            OLD.principal,
            OLD.requester_id,
            OLD.approver_id,
            OLD.company_id,
            OLD.environment,
            OLD.capability_channel,
            OLD.registry_digest,
            OLD.release_digest
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'accounting operation immutable binding changed';
        END IF;
        IF (
            OLD.execution_evidence_json IS NOT NULL
            AND ROW(
                NEW.execution_evidence_json,
                NEW.execution_evidence_digest,
                NEW.execution_result_json,
                NEW.execution_result_digest
            ) IS DISTINCT FROM ROW(
                OLD.execution_evidence_json,
                OLD.execution_evidence_digest,
                OLD.execution_result_json,
                OLD.execution_result_digest
            )
        ) OR (
            OLD.verification_evidence_json IS NOT NULL
            AND ROW(
                NEW.verification_evidence_json,
                NEW.verification_evidence_digest,
                NEW.verification_result_json,
                NEW.verification_result_digest
            ) IS DISTINCT FROM ROW(
                OLD.verification_evidence_json,
                OLD.verification_evidence_digest,
                OLD.verification_result_json,
                OLD.verification_result_digest
            )
        ) OR (
            OLD.failure_evidence_json IS NOT NULL
            AND ROW(
                NEW.failure_evidence_json,
                NEW.failure_evidence_digest
            ) IS DISTINCT FROM ROW(
                OLD.failure_evidence_json,
                OLD.failure_evidence_digest
            )
        ) OR (
            OLD.recovery_plan_json IS NOT NULL
            AND ROW(NEW.recovery_plan_json, NEW.recovery_plan_digest)
                IS DISTINCT FROM
                ROW(OLD.recovery_plan_json, OLD.recovery_plan_digest)
        ) OR (
            OLD.recovery_evidence_json IS NOT NULL
            AND ROW(
                NEW.recovery_evidence_json,
                NEW.recovery_evidence_digest,
                NEW.recovery_result_json,
                NEW.recovery_result_digest
            ) IS DISTINCT FROM ROW(
                OLD.recovery_evidence_json,
                OLD.recovery_evidence_digest,
                OLD.recovery_result_json,
                OLD.recovery_result_digest
            )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'accounting operation signed evidence changed';
        END IF;
        -- Every evidence/result field is append-only.  The explicit checks are
        -- intentional: adding a future ORM field without extending this list
        -- must fail the source-contract test rather than silently weaken it.
        IF (OLD.execution_evidence_digest IS NOT NULL AND
            NEW.execution_evidence_digest IS DISTINCT FROM OLD.execution_evidence_digest)
           OR (OLD.execution_result_json IS NOT NULL AND
            NEW.execution_result_json IS DISTINCT FROM OLD.execution_result_json)
           OR (OLD.execution_result_digest IS NOT NULL AND
            NEW.execution_result_digest IS DISTINCT FROM OLD.execution_result_digest)
           OR (OLD.verification_evidence_digest IS NOT NULL AND
            NEW.verification_evidence_digest IS DISTINCT FROM OLD.verification_evidence_digest)
           OR (OLD.verification_result_json IS NOT NULL AND
            NEW.verification_result_json IS DISTINCT FROM OLD.verification_result_json)
           OR (OLD.verification_result_digest IS NOT NULL AND
            NEW.verification_result_digest IS DISTINCT FROM OLD.verification_result_digest)
           OR (OLD.failure_evidence_digest IS NOT NULL AND
            NEW.failure_evidence_digest IS DISTINCT FROM OLD.failure_evidence_digest)
           OR (OLD.recovery_plan_digest IS NOT NULL AND
            NEW.recovery_plan_digest IS DISTINCT FROM OLD.recovery_plan_digest)
           OR (OLD.recovery_evidence_digest IS NOT NULL AND
            NEW.recovery_evidence_digest IS DISTINCT FROM OLD.recovery_evidence_digest)
           OR (OLD.recovery_result_json IS NOT NULL AND
            NEW.recovery_result_json IS DISTINCT FROM OLD.recovery_result_json)
           OR (OLD.recovery_result_digest IS NOT NULL AND
            NEW.recovery_result_digest IS DISTINCT FROM OLD.recovery_result_digest)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'accounting operation append-only evidence changed';
        END IF;
        IF NEW.state IS DISTINCT FROM OLD.state
           AND NOT (
               (OLD.state = 'claimed' AND NEW.state IN ('committed', 'failed'))
               OR (
                   OLD.state = 'committed'
                   AND NEW.state IN ('verified', 'failed')
               )
               OR (
                   OLD.state IN ('verified', 'failed')
                   AND NEW.state = 'recovering'
               )
               OR (
                   OLD.state = 'recovering'
                   AND NEW.state IN ('recovered', 'failed')
               )
           )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'accounting operation state transition is invalid';
        END IF;
    END IF;

    PERFORM odoo_accounting_cli_v3_guard.effect_is_unresolved(
        NEW.state,
        NEW.execution_result_json,
        NEW.verification_result_json,
        NEW.recovery_result_json
    );
    IF (NEW.execution_evidence_json IS NULL) <> (
        NEW.execution_evidence_digest IS NULL
    ) OR (NEW.execution_result_json IS NULL) <> (
        NEW.execution_result_digest IS NULL
    ) OR (NEW.verification_evidence_json IS NULL) <> (
        NEW.verification_evidence_digest IS NULL
    ) OR (NEW.verification_result_json IS NULL) <> (
        NEW.verification_result_digest IS NULL
    ) OR (NEW.recovery_plan_json IS NULL) <> (
        NEW.recovery_plan_digest IS NULL
    ) OR (NEW.recovery_evidence_json IS NULL) <> (
        NEW.recovery_evidence_digest IS NULL
    ) OR (NEW.recovery_result_json IS NULL) <> (
        NEW.recovery_result_digest IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'accounting operation evidence pair is incomplete';
    END IF;

    IF NEW.execution_result_json IS NOT NULL THEN
        execution_succeeded := (
            NEW.execution_result_json::jsonb ->> 'succeeded'
        )::boolean;
        IF NOT odoo_accounting_cli_v3_guard.result_is_bound(
            NEW.execution_result_json,
            'execution',
            'execution_result_v2',
            NEW.operation_id,
            NEW.request_id,
            NEW.operation_digest,
            NEW.company_id,
            NEW.capability_id,
            NEW.registry_digest,
            NEW.release_digest,
            NEW.execution_evidence_digest,
            NULL,
            execution_succeeded
        ) OR NEW.execution_result_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'execution result binding is invalid';
        END IF;
    END IF;
    IF NEW.verification_result_json IS NOT NULL THEN
        verification_succeeded := (
            NEW.verification_result_json::jsonb ->> 'succeeded'
        )::boolean;
        IF NOT odoo_accounting_cli_v3_guard.result_is_bound(
            NEW.verification_result_json,
            'verification',
            'verification_result_v2',
            NEW.operation_id,
            NEW.request_id,
            NEW.operation_digest,
            NEW.company_id,
            NEW.capability_id,
            NEW.registry_digest,
            NEW.release_digest,
            NEW.verification_evidence_digest,
            NEW.execution_evidence_digest,
            verification_succeeded
        ) OR NEW.verification_result_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'verification result binding is invalid';
        END IF;
    END IF;
    IF NEW.recovery_result_json IS NOT NULL THEN
        recovery_succeeded := (
            NEW.recovery_result_json::jsonb ->> 'succeeded'
        )::boolean;
        IF NOT odoo_accounting_cli_v3_guard.result_is_bound(
            NEW.recovery_result_json,
            'recovery',
            'recovery_result_v2',
            NEW.operation_id,
            NEW.request_id,
            NEW.operation_digest,
            NEW.company_id,
            NEW.capability_id,
            NEW.registry_digest,
            NEW.release_digest,
            NEW.recovery_evidence_digest,
            NEW.recovery_plan_digest,
            recovery_succeeded
        ) OR NEW.recovery_result_digest !~ '^[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'recovery result binding is invalid';
        END IF;
    END IF;

    SELECT state.unresolved_effect_count INTO cached_count
    FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
    WHERE state.id = 1
      AND state.protocol_version = 1
      AND NOT state.module_guard_open
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard is absent or open';
    END IF;
    SELECT pg_catalog.count(*) INTO ledger_count
    FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
    LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
      ON resolution.anchor_id = anchor.anchor_id
    WHERE resolution.anchor_id IS NULL;
    IF cached_count <> ledger_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'operation effect ledger count is inconsistent';
    END IF;

    IF execution_succeeded IS TRUE THEN
        INSERT INTO odoo_accounting_cli_v3_guard.operation_effect_anchor (
            operation_record_id,
            operation_id,
            operation_digest,
            registry_digest,
            release_digest,
            effect_phase,
            source_digest,
            source_evidence_digest,
            opened_at,
            opened_txid
        ) VALUES (
            NEW.id,
            NEW.operation_id,
            NEW.operation_digest,
            NEW.registry_digest,
            NEW.release_digest,
            'execution',
            NEW.execution_result_digest,
            NEW.execution_evidence_digest,
            pg_catalog.transaction_timestamp(),
            pg_catalog.pg_current_xact_id()::text
        )
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS inserted_now = ROW_COUNT;
        inserted_rows := inserted_rows + inserted_now;
        IF NOT EXISTS (
            SELECT 1
            FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
            WHERE anchor.operation_record_id = NEW.id
              AND anchor.operation_id = NEW.operation_id
              AND anchor.operation_digest = NEW.operation_digest
              AND anchor.registry_digest = NEW.registry_digest
              AND anchor.release_digest = NEW.release_digest
              AND anchor.effect_phase = 'execution'
              AND anchor.source_digest = NEW.execution_result_digest
              AND anchor.source_evidence_digest = NEW.execution_evidence_digest
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'execution effect anchor binding is inconsistent';
        END IF;
    END IF;
    SELECT pg_catalog.count(*) INTO ledger_count
    FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
    LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
      ON resolution.anchor_id = anchor.anchor_id
    WHERE resolution.anchor_id IS NULL;
    IF ledger_count < cached_count
       OR ledger_count > cached_count + inserted_rows
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'operation effect ledger changed unexpectedly';
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_guard_state
       SET unresolved_effect_count = ledger_count
     WHERE id = 1
       AND protocol_version = 1
       AND NOT module_guard_open
       AND unresolved_effect_count = cached_count
    RETURNING unresolved_effect_count INTO resulting_count;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard is absent, open, or inconsistent';
    END IF;
    RETURN NULL;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.reject_operation_truncate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55006',
        MESSAGE = 'accounting operation anchors cannot be truncated';
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.guard_module_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    guard_state odoo_accounting_cli_v3_guard.module_guard_state%ROWTYPE;
    holder_is_live boolean;
    next_epoch bigint;
BEGIN
    SELECT * INTO guard_state
    FROM odoo_accounting_cli_v3_guard.module_guard_state
    WHERE id = 1 AND protocol_version = 1
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard state is absent';
    END IF;
    SELECT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_locks AS held_lock
        JOIN pg_catalog.pg_stat_activity AS holder
          ON holder.pid = held_lock.pid
        WHERE held_lock.locktype = 'advisory'
          AND held_lock.database = (
              SELECT oid FROM pg_catalog.pg_database
              WHERE datname = pg_catalog.current_database()
          )
          AND held_lock.classid = 1329677142
          AND held_lock.objid = 1297040433
          AND held_lock.objsubid = 2
          AND held_lock.mode = 'ExclusiveLock'
          AND held_lock.granted
          AND held_lock.pid = guard_state.maintenance_holder_pid
          AND held_lock.pid = pg_catalog.pg_backend_pid()
          AND holder.backend_start = (
              guard_state.maintenance_holder_backend_start
          )
    ) INTO holder_is_live;
    IF guard_state.module_guard_open
       AND guard_state.maintenance_expires_at > pg_catalog.clock_timestamp()
       AND session_user::name = guard_state.maintenance_role
       AND pg_catalog.current_setting('role', true)::name = (
           guard_state.runtime_role
       )
    THEN
        IF holder_is_live IS NOT TRUE THEN
            RAISE EXCEPTION USING
                ERRCODE = '55006',
                MESSAGE = 'module maintenance holder is not live';
        END IF;
        UPDATE odoo_accounting_cli_v3_guard.module_guard_state
           SET epoch = epoch + 1,
               opened_epoch = opened_epoch + 1,
               last_module_change_at = transaction_timestamp(),
               last_module_change_txid = pg_current_xact_id()::text
         WHERE id = 1
           AND protocol_version = 1
           AND module_guard_open
           AND opened_epoch = epoch
           AND unresolved_effect_count = 0
           AND unresolved_effect_count = (
               SELECT pg_catalog.count(*)
               FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
               LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
                 ON resolution.anchor_id = anchor.anchor_id
               WHERE resolution.anchor_id IS NULL
           )
           AND maintenance_id = guard_state.maintenance_id
           AND EXISTS (
               SELECT 1
               FROM odoo_accounting_cli_v3_guard.module_maintenance_authorization AS authorization
               WHERE authorization.maintenance_id = guard_state.maintenance_id
                 AND authorization.consumed_at IS NOT NULL
                 AND authorization.completed_at IS NULL
                 AND authorization.recovered_at IS NULL
                 AND authorization.expires_at = guard_state.maintenance_expires_at
           )
           AND maintenance_holder_pid = guard_state.maintenance_holder_pid
           AND maintenance_holder_backend_start = (
               guard_state.maintenance_holder_backend_start
           )
        RETURNING epoch INTO next_epoch;
        IF FOUND THEN
            RETURN NULL;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard is stale or has unresolved effects';
    END IF;
    IF NOT pg_try_advisory_xact_lock(1329677142, 1297040433) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55P03',
            MESSAGE = 'accounting write guard excludes module changes';
    END IF;
    RAISE EXCEPTION USING
        ERRCODE = '55006',
        MESSAGE = 'module changes require an active approved maintenance holder';
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.verify_module_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    holder_is_live boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
        JOIN pg_catalog.pg_locks AS held_lock
          ON held_lock.pid = state.maintenance_holder_pid
        JOIN pg_catalog.pg_stat_activity AS holder
          ON holder.pid = held_lock.pid
        WHERE state.id = 1
          AND state.protocol_version = 1
          AND state.module_guard_open
          AND state.opened_epoch = state.epoch
          AND state.maintenance_expires_at > pg_catalog.clock_timestamp()
          AND state.unresolved_effect_count = 0
          AND session_user::name = state.maintenance_role
          AND pg_catalog.current_setting('role', true)::name = state.runtime_role
          AND held_lock.locktype = 'advisory'
          AND held_lock.database = (
              SELECT oid FROM pg_catalog.pg_database
              WHERE datname = pg_catalog.current_database()
          )
          AND held_lock.classid = 1329677142
          AND held_lock.objid = 1297040433
          AND held_lock.objsubid = 2
          AND held_lock.mode = 'ExclusiveLock'
          AND held_lock.granted
          AND held_lock.pid = pg_catalog.pg_backend_pid()
          AND holder.backend_start = state.maintenance_holder_backend_start
    ) INTO holder_is_live;
    IF holder_is_live IS NOT TRUE THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance holder is not live after module change';
    END IF;
    RETURN NULL;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.read_module_guard_state()
RETURNS TABLE (
    protocol_version integer,
    schema_version integer,
    guard_installation_id uuid,
    database_oid oid,
    database_uuid uuid,
    epoch bigint,
    module_guard_open boolean,
    opened_epoch bigint,
    unresolved_effect_count bigint,
    ledger_unresolved_effect_count bigint,
    runtime_role name,
    maintenance_role name,
    finalizer_role name,
    maintenance_id uuid,
    maintenance_expires_at timestamp with time zone,
    maintenance_holder_pid integer,
    maintenance_holder_backend_start timestamp with time zone,
    last_module_change_at timestamp with time zone,
    last_module_change_txid text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT
        state.protocol_version,
        state.schema_version,
        state.guard_installation_id,
        state.database_oid,
        state.database_uuid,
        state.epoch,
        state.module_guard_open,
        state.opened_epoch,
        state.unresolved_effect_count,
        (
            SELECT pg_catalog.count(*)
            FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
            LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
              ON resolution.anchor_id = anchor.anchor_id
            WHERE resolution.anchor_id IS NULL
        ),
        state.runtime_role,
        state.maintenance_role,
        state.finalizer_role,
        state.maintenance_id,
        state.maintenance_expires_at,
        state.maintenance_holder_pid,
        state.maintenance_holder_backend_start,
        state.last_module_change_at,
        state.last_module_change_txid
    FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
    WHERE state.id = 1
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.authorize_module_maintenance(
    requested_maintenance_id uuid,
    expected_guard_installation_id uuid,
    expected_database_oid oid,
    expected_database_uuid uuid,
    requested_approval_digest text,
    expected_registry_digest text,
    expected_release_digest text,
    requested_attestation_digest text,
    requested_expires_at timestamp with time zone
)
RETURNS TABLE (
    maintenance_id uuid,
    approval_digest text,
    expires_at timestamp with time zone,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    configured_finalizer name;
    configured_guard_installation_id uuid;
    configured_database_oid oid;
    configured_database_uuid uuid;
    observed_database_uuid uuid;
    database_uuid_count bigint;
    existing odoo_accounting_cli_v3_guard.module_maintenance_authorization%ROWTYPE;
    inserted integer := 0;
BEGIN
    IF requested_maintenance_id IS NULL
       OR expected_guard_installation_id IS NULL
       OR expected_database_oid IS NULL
       OR expected_database_uuid IS NULL
       OR requested_approval_digest !~ '^[0-9a-f]{64}$'
       OR expected_registry_digest !~ '^[0-9a-f]{64}$'
       OR expected_release_digest !~ '^[0-9a-f]{64}$'
       OR requested_attestation_digest !~ '^[0-9a-f]{64}$'
       OR requested_expires_at IS NULL
       OR requested_expires_at <= pg_catalog.clock_timestamp()
       OR requested_expires_at > pg_catalog.clock_timestamp() + interval '15 minutes'
       OR pg_catalog.current_setting('role', true) <> 'none'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'module maintenance authorization request is invalid';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(
        1329677142, 1297040433
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55P03',
            MESSAGE = 'module maintenance excludes authorization changes';
    END IF;
    SELECT
        state.finalizer_role,
        state.guard_installation_id,
        state.database_oid,
        state.database_uuid
    INTO
        configured_finalizer,
        configured_guard_installation_id,
        configured_database_oid,
        configured_database_uuid
    FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
    WHERE state.id = 1
      AND state.protocol_version = 1
      AND state.schema_version = 2
      AND NOT state.module_guard_open;
    IF NOT FOUND
       OR session_user::name <> configured_finalizer
       OR configured_guard_installation_id <> expected_guard_installation_id
       OR configured_database_oid <> expected_database_oid
       OR configured_database_uuid <> expected_database_uuid
       OR expected_database_oid <> (
           SELECT oid FROM pg_catalog.pg_database
           WHERE datname = pg_catalog.current_database()
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'module maintenance finalizer identity is invalid';
    END IF;
    SELECT pg_catalog.min(parameter.value)::uuid, pg_catalog.count(*)
    INTO observed_database_uuid, database_uuid_count
    FROM ONLY public.ir_config_parameter AS parameter
    WHERE parameter.key = 'database.uuid';
    IF database_uuid_count <> 1
       OR observed_database_uuid <> expected_database_uuid
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'module maintenance database UUID binding is invalid';
    END IF;
    INSERT INTO odoo_accounting_cli_v3_guard.module_maintenance_authorization (
        maintenance_id,
        guard_installation_id,
        database_oid,
        database_uuid,
        approval_digest,
        registry_digest,
        release_digest,
        attestation_digest,
        authorized_at,
        expires_at,
        authorized_by
    ) VALUES (
        requested_maintenance_id,
        expected_guard_installation_id,
        expected_database_oid,
        expected_database_uuid,
        requested_approval_digest,
        expected_registry_digest,
        expected_release_digest,
        requested_attestation_digest,
        pg_catalog.transaction_timestamp(),
        requested_expires_at,
        session_user::name
    ) ON CONFLICT (maintenance_id) DO NOTHING;
    GET DIAGNOSTICS inserted = ROW_COUNT;
    SELECT authorization.* INTO existing
    FROM odoo_accounting_cli_v3_guard.module_maintenance_authorization AS authorization
    WHERE authorization.maintenance_id = requested_maintenance_id;
    IF NOT FOUND
       OR existing.database_uuid <> expected_database_uuid
       OR existing.guard_installation_id <> expected_guard_installation_id
       OR existing.database_oid <> expected_database_oid
       OR existing.approval_digest <> requested_approval_digest
       OR existing.registry_digest <> expected_registry_digest
       OR existing.release_digest <> expected_release_digest
       OR existing.attestation_digest <> requested_attestation_digest
       OR existing.expires_at <> requested_expires_at
       OR existing.authorized_by <> session_user::name
       OR existing.consumed_at IS NOT NULL
       OR existing.completed_at IS NOT NULL
       OR existing.recovered_at IS NOT NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'module maintenance authorization replay differs';
    END IF;
    maintenance_id := existing.maintenance_id;
    approval_digest := existing.approval_digest;
    expires_at := existing.expires_at;
    replayed := inserted = 0;
    RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.finalize_operation_effect(
    expected_guard_installation_id uuid,
    expected_database_oid oid,
    expected_database_uuid uuid,
    requested_attestation_id uuid,
    requested_attestation_digest text,
    requested_verifier_key_id text,
    proof_verified_at timestamp with time zone,
    proof_expires_at timestamp with time zone,
    expected_operation_id text,
    expected_operation_digest text,
    expected_execution_result_digest text,
    resolution_operation_id text,
    resolution_operation_digest text,
    resolution_execution_result_digest text,
    requested_resolution_kind text,
    resolution_result_digest text
)
RETURNS TABLE (
    receipt_attestation_id uuid,
    receipt_guard_installation_id uuid,
    receipt_database_oid oid,
    receipt_database_uuid uuid,
    resolved_operation_id text,
    receipt_resolution_operation_id text,
    applied_resolution_kind text,
    resolved_anchor_count integer,
    remaining_unresolved_count bigint,
    guard_epoch bigint,
    receipt_attestation_digest text,
    finalized_at timestamp with time zone,
    finalized_txid text,
    replayed boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    operation_row public.odoo_accounting_cli_operation%ROWTYPE;
    resolution_operation_row public.odoo_accounting_cli_operation%ROWTYPE;
    configured_finalizer name;
    cached_count bigint;
    actual_count bigint;
    current_epoch bigint;
    configured_guard_installation_id uuid;
    configured_database_oid oid;
    configured_database_uuid uuid;
    observed_database_uuid uuid;
    database_uuid_count bigint;
    anchors_to_resolve integer;
    target_anchor odoo_accounting_cli_v3_guard.operation_effect_anchor%ROWTYPE;
    resolution_anchor odoo_accounting_cli_v3_guard.operation_effect_anchor%ROWTYPE;
    stored_receipt odoo_accounting_cli_v3_guard.effect_finalization_receipt%ROWTYPE;
BEGIN
    IF expected_guard_installation_id IS NULL
       OR expected_database_oid IS NULL
       OR expected_database_uuid IS NULL
       OR requested_attestation_id IS NULL
       OR requested_attestation_digest !~ '^[0-9a-f]{64}$'
       OR requested_verifier_key_id IS NULL
       OR pg_catalog.length(requested_verifier_key_id) = 0
       OR pg_catalog.length(requested_verifier_key_id) > 128
       OR proof_verified_at IS NULL
       OR proof_expires_at IS NULL
       OR proof_expires_at <= proof_verified_at
       OR proof_expires_at <= pg_catalog.clock_timestamp()
       OR proof_expires_at > proof_verified_at + interval '5 minutes'
       OR proof_verified_at > pg_catalog.clock_timestamp() + interval '1 minute'
       OR proof_verified_at < pg_catalog.clock_timestamp() - interval '15 minutes'
       OR expected_operation_id IS NULL
       OR expected_operation_id = ''
       OR expected_operation_digest !~ '^[0-9a-f]{64}$'
       OR expected_execution_result_digest !~ '^[0-9a-f]{64}$'
       OR resolution_operation_id IS NULL
       OR resolution_operation_id = ''
       OR resolution_operation_digest !~ '^[0-9a-f]{64}$'
       OR resolution_execution_result_digest !~ '^[0-9a-f]{64}$'
       OR requested_resolution_kind NOT IN ('verified', 'recovered')
       OR resolution_result_digest !~ '^[0-9a-f]{64}$'
       OR pg_catalog.current_setting('role', true) <> 'none'
       OR (
           requested_resolution_kind = 'verified'
           AND resolution_operation_id <> expected_operation_id
       )
       OR (
           requested_resolution_kind = 'recovered'
           AND resolution_operation_id = expected_operation_id
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation effect finalization request is invalid';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock_shared(
        1329677142, 1297040433
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55P03',
            MESSAGE = 'module maintenance excludes effect finalization';
    END IF;

    -- Global order: operation row(s) -> state row -> immutable anchor rows.
    -- The operation AFTER trigger already holds its operation row before it
    -- locks state, so reversing these two locks creates a deterministic cycle.
    PERFORM operation.id
    FROM public.odoo_accounting_cli_operation AS operation
    WHERE operation.operation_id IN (
        expected_operation_id, resolution_operation_id
    )
    ORDER BY operation.id
    FOR UPDATE;
    SELECT operation.* INTO operation_row
    FROM public.odoo_accounting_cli_operation AS operation
    WHERE operation.operation_id = expected_operation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation effect target is absent';
    END IF;
    SELECT operation.* INTO resolution_operation_row
    FROM public.odoo_accounting_cli_operation AS operation
    WHERE operation.operation_id = resolution_operation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation effect resolution operation is absent';
    END IF;

    SELECT
        state.finalizer_role,
        state.unresolved_effect_count,
        state.epoch,
        state.guard_installation_id,
        state.database_oid,
        state.database_uuid
    INTO
        configured_finalizer,
        cached_count,
        current_epoch,
        configured_guard_installation_id,
        configured_database_oid,
        configured_database_uuid
    FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
    WHERE state.id = 1
      AND state.protocol_version = 1
      AND state.schema_version = 2
      AND NOT state.module_guard_open
    FOR UPDATE;
    IF NOT FOUND
       OR session_user::name <> configured_finalizer
       OR configured_guard_installation_id <> expected_guard_installation_id
       OR configured_database_oid <> expected_database_oid
       OR configured_database_uuid <> expected_database_uuid
       OR expected_database_oid <> (
           SELECT oid FROM pg_catalog.pg_database
           WHERE datname = pg_catalog.current_database()
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'operation effect finalizer identity is invalid';
    END IF;
    SELECT
        pg_catalog.min(parameter.value)::uuid,
        pg_catalog.count(*)
    INTO observed_database_uuid, database_uuid_count
    FROM ONLY public.ir_config_parameter AS parameter
    WHERE parameter.key = 'database.uuid';
    IF database_uuid_count <> 1
       OR observed_database_uuid <> expected_database_uuid
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation effect database UUID binding is invalid';
    END IF;
    SELECT pg_catalog.count(*) INTO actual_count
    FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
    LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
      ON resolution.anchor_id = anchor.anchor_id
    WHERE resolution.anchor_id IS NULL;
    IF actual_count <> cached_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'operation effect ledger count is inconsistent';
    END IF;

    IF operation_row.operation_digest <> expected_operation_digest
       OR operation_row.execution_result_digest IS DISTINCT FROM (
           expected_execution_result_digest
       )
       OR NOT odoo_accounting_cli_v3_guard.result_is_bound(
           operation_row.execution_result_json,
           'execution',
           'execution_result_v2',
           operation_row.operation_id,
           operation_row.request_id,
           operation_row.operation_digest,
           operation_row.company_id,
           operation_row.capability_id,
           operation_row.registry_digest,
           operation_row.release_digest,
           operation_row.execution_evidence_digest,
           NULL,
           true
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation effect finalization binding is invalid';
    END IF;

    IF requested_resolution_kind = 'verified' THEN
        IF operation_row.state <> 'verified'
           OR operation_row.verification_result_digest IS DISTINCT FROM (
               resolution_result_digest
           )
           OR operation_row.operation_digest <> resolution_operation_digest
           OR operation_row.execution_result_digest IS DISTINCT FROM (
               resolution_execution_result_digest
           )
           OR NOT odoo_accounting_cli_v3_guard.result_is_bound(
               operation_row.verification_result_json,
               'verification',
               'verification_result_v2',
               operation_row.operation_id,
               operation_row.request_id,
               operation_row.operation_digest,
               operation_row.company_id,
               operation_row.capability_id,
               operation_row.registry_digest,
               operation_row.release_digest,
               operation_row.verification_evidence_digest,
               operation_row.execution_evidence_digest,
               true
           )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'verified operation result is not finalizable';
        END IF;
    ELSE
        IF operation_row.state <> 'failed'
           OR resolution_operation_row.capability_id <> 'acct.recovery.execute.v1'
           OR resolution_operation_row.state <> 'verified'
           OR resolution_operation_row.operation_digest <> (
               resolution_operation_digest
           )
           OR resolution_operation_row.execution_result_digest IS DISTINCT FROM (
               resolution_execution_result_digest
           )
           OR resolution_operation_row.verification_result_digest IS DISTINCT FROM (
               resolution_result_digest
           )
           OR NOT odoo_accounting_cli_v3_guard.result_is_bound(
               resolution_operation_row.verification_result_json,
               'verification',
               'verification_result_v2',
               resolution_operation_row.operation_id,
               resolution_operation_row.request_id,
               resolution_operation_row.operation_digest,
               resolution_operation_row.company_id,
               resolution_operation_row.capability_id,
               resolution_operation_row.registry_digest,
               resolution_operation_row.release_digest,
               resolution_operation_row.verification_evidence_digest,
               resolution_operation_row.execution_evidence_digest,
               true
           )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'recovered operation result is not finalizable';
        END IF;
    END IF;

    SELECT anchor.* INTO target_anchor
    FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
    WHERE anchor.operation_record_id = operation_row.id
      AND anchor.effect_phase = 'execution'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'required operation effect anchor is absent';
    END IF;
    resolution_anchor := target_anchor;
    anchors_to_resolve := 1;
    IF requested_resolution_kind = 'recovered' THEN
        SELECT anchor.* INTO resolution_anchor
        FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
        WHERE anchor.operation_record_id = resolution_operation_row.id
          AND anchor.effect_phase = 'execution'
        FOR UPDATE;
        IF NOT FOUND OR resolution_anchor.anchor_id = target_anchor.anchor_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'recovery operation effect anchor is absent';
        END IF;
        anchors_to_resolve := 2;
    END IF;

    SELECT receipt.* INTO stored_receipt
    FROM odoo_accounting_cli_v3_guard.effect_finalization_receipt AS receipt
    WHERE receipt.attestation_id = requested_attestation_id
    FOR UPDATE;
    IF FOUND THEN
        IF stored_receipt.database_uuid <> expected_database_uuid
           OR stored_receipt.guard_installation_id <> expected_guard_installation_id
           OR stored_receipt.database_oid <> expected_database_oid
           OR stored_receipt.expected_operation_record_id <> operation_row.id
           OR stored_receipt.expected_operation_id <> expected_operation_id
           OR stored_receipt.expected_operation_digest <> expected_operation_digest
           OR stored_receipt.expected_execution_result_digest <> expected_execution_result_digest
           OR stored_receipt.resolution_operation_record_id <> resolution_operation_row.id
           OR stored_receipt.resolution_operation_id <> resolution_operation_id
           OR stored_receipt.resolution_operation_digest <> resolution_operation_digest
           OR stored_receipt.resolution_execution_result_digest <> resolution_execution_result_digest
           OR stored_receipt.resolution_result_digest <> resolution_result_digest
           OR stored_receipt.resolution_kind <> requested_resolution_kind
           OR stored_receipt.attestation_digest <> requested_attestation_digest
           OR stored_receipt.verifier_key_id <> requested_verifier_key_id
           OR stored_receipt.verified_at <> proof_verified_at
           OR stored_receipt.expires_at <> proof_expires_at
           OR stored_receipt.guard_epoch <> current_epoch
           OR stored_receipt.resolved_anchor_count <> anchors_to_resolve
           OR (
               SELECT pg_catalog.count(*)
               FROM odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
               WHERE resolution.attestation_id = stored_receipt.attestation_id
           ) <> anchors_to_resolve
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22000',
                MESSAGE = 'operation effect finalization replay differs';
        END IF;
        receipt_attestation_id := stored_receipt.attestation_id;
        receipt_guard_installation_id := stored_receipt.guard_installation_id;
        receipt_database_oid := stored_receipt.database_oid;
        receipt_database_uuid := stored_receipt.database_uuid;
        resolved_operation_id := stored_receipt.expected_operation_id;
        receipt_resolution_operation_id := stored_receipt.resolution_operation_id;
        applied_resolution_kind := stored_receipt.resolution_kind;
        resolved_anchor_count := stored_receipt.resolved_anchor_count;
        remaining_unresolved_count := stored_receipt.remaining_unresolved_count;
        guard_epoch := stored_receipt.guard_epoch;
        receipt_attestation_digest := stored_receipt.attestation_digest;
        finalized_at := stored_receipt.finalized_at;
        finalized_txid := stored_receipt.finalized_txid;
        replayed := true;
        RETURN NEXT;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
        WHERE resolution.anchor_id IN (
            target_anchor.anchor_id, resolution_anchor.anchor_id
        )
    ) OR actual_count < anchors_to_resolve THEN
        RAISE EXCEPTION USING
            ERRCODE = '22000',
            MESSAGE = 'operation effect anchor was resolved by a different proof';
    END IF;

    INSERT INTO odoo_accounting_cli_v3_guard.effect_finalization_receipt (
        attestation_id, guard_installation_id, database_oid, database_uuid,
        expected_operation_record_id, expected_operation_id,
        expected_operation_digest, expected_execution_result_digest,
        resolution_operation_record_id, resolution_operation_id,
        resolution_operation_digest, resolution_execution_result_digest,
        resolution_result_digest, resolution_kind, attestation_digest,
        verifier_key_id, verified_at, expires_at, guard_epoch,
        resolved_anchor_count, remaining_unresolved_count,
        finalized_at, finalized_txid, finalizer_role
    ) VALUES (
        requested_attestation_id, expected_guard_installation_id,
        expected_database_oid, expected_database_uuid,
        operation_row.id, expected_operation_id,
        expected_operation_digest, expected_execution_result_digest,
        resolution_operation_row.id, resolution_operation_id,
        resolution_operation_digest, resolution_execution_result_digest,
        resolution_result_digest, requested_resolution_kind,
        requested_attestation_digest,
        requested_verifier_key_id,
        proof_verified_at, proof_expires_at, current_epoch,
        anchors_to_resolve, actual_count - anchors_to_resolve,
        pg_catalog.transaction_timestamp(),
        pg_catalog.pg_current_xact_id()::text, session_user::name
    ) RETURNING * INTO stored_receipt;
    INSERT INTO odoo_accounting_cli_v3_guard.operation_effect_resolution (
        anchor_id, attestation_id, resolution_kind,
        resolution_result_digest, finalized_at, finalized_txid, finalizer_role
    ) VALUES (
        target_anchor.anchor_id, stored_receipt.attestation_id,
        requested_resolution_kind, resolution_result_digest,
        stored_receipt.finalized_at, stored_receipt.finalized_txid,
        session_user::name
    );
    IF resolution_anchor.anchor_id <> target_anchor.anchor_id THEN
        INSERT INTO odoo_accounting_cli_v3_guard.operation_effect_resolution (
            anchor_id, attestation_id, resolution_kind,
            resolution_result_digest, finalized_at, finalized_txid, finalizer_role
        ) VALUES (
            resolution_anchor.anchor_id, stored_receipt.attestation_id,
            requested_resolution_kind, resolution_result_digest,
            stored_receipt.finalized_at, stored_receipt.finalized_txid,
            session_user::name
        );
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_guard_state AS state
       SET unresolved_effect_count = stored_receipt.remaining_unresolved_count
     WHERE state.id = 1
       AND state.protocol_version = 1
       AND state.schema_version = 2
       AND NOT state.module_guard_open
       AND state.unresolved_effect_count = cached_count;
    IF NOT FOUND OR cached_count <> actual_count THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'operation effect finalization count is inconsistent';
    END IF;

    receipt_attestation_id := stored_receipt.attestation_id;
    receipt_guard_installation_id := stored_receipt.guard_installation_id;
    receipt_database_oid := stored_receipt.database_oid;
    receipt_database_uuid := stored_receipt.database_uuid;
    resolved_operation_id := stored_receipt.expected_operation_id;
    receipt_resolution_operation_id := stored_receipt.resolution_operation_id;
    applied_resolution_kind := stored_receipt.resolution_kind;
    resolved_anchor_count := stored_receipt.resolved_anchor_count;
    remaining_unresolved_count := stored_receipt.remaining_unresolved_count;
    guard_epoch := stored_receipt.guard_epoch;
    receipt_attestation_digest := stored_receipt.attestation_digest;
    finalized_at := stored_receipt.finalized_at;
    finalized_txid := stored_receipt.finalized_txid;
    replayed := false;
    RETURN NEXT;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.open_module_guard(
    expected_epoch bigint,
    requested_maintenance_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    holder_start timestamp with time zone;
    opened bigint;
    runtime_name name;
    maintenance_name name;
    authorization odoo_accounting_cli_v3_guard.module_maintenance_authorization%ROWTYPE;
    maintenance_session_count bigint;
    maintenance_can_login boolean;
    maintenance_connection_limit integer;
    maintenance_valid_until timestamp with time zone;
BEGIN
    IF requested_maintenance_id IS NULL
       OR expected_epoch < 0
       OR pg_catalog.current_setting('role', true) <> 'none'
       OR NOT pg_catalog.pg_try_advisory_xact_lock(
           1329677142, 1297040433
       )
       OR NOT pg_catalog.pg_advisory_unlock(1329677142, 1297040433)
       OR NOT pg_catalog.pg_try_advisory_lock(1329677142, 1297040433)
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55P03',
            MESSAGE = 'module maintenance requires the exclusive session lock';
    END IF;
    SELECT activity.backend_start INTO holder_start
    FROM pg_catalog.pg_stat_activity AS activity
    WHERE activity.pid = pg_catalog.pg_backend_pid()
      AND EXISTS (
          SELECT 1
          FROM pg_catalog.pg_locks AS held_lock
          WHERE held_lock.locktype = 'advisory'
            AND held_lock.pid = activity.pid
            AND held_lock.database = (
                SELECT oid FROM pg_catalog.pg_database
                WHERE datname = pg_catalog.current_database()
            )
            AND held_lock.classid = 1329677142
            AND held_lock.objid = 1297040433
            AND held_lock.objsubid = 2
            AND held_lock.mode = 'ExclusiveLock'
            AND held_lock.granted
      );
    IF holder_start IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55P03',
            MESSAGE = 'module maintenance requires the exclusive session lock';
    END IF;
    SELECT
        role.rolcanlogin,
        role.rolconnlimit,
        role.rolvaliduntil
    INTO
        maintenance_can_login,
        maintenance_connection_limit,
        maintenance_valid_until
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = session_user;
    SELECT pg_catalog.count(*) INTO maintenance_session_count
    FROM pg_catalog.pg_stat_activity AS activity
    WHERE activity.usename = session_user;
    IF maintenance_can_login IS NOT TRUE
       OR maintenance_connection_limit <> 1
       OR maintenance_valid_until IS NULL
       OR maintenance_valid_until <= pg_catalog.clock_timestamp()
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'module guard maintenance role must be temporarily login-enabled';
    END IF;
    IF maintenance_session_count <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'module guard maintenance role has concurrent sessions';
    END IF;
    SELECT candidate.* INTO authorization
    FROM odoo_accounting_cli_v3_guard.module_maintenance_authorization AS candidate
    WHERE candidate.maintenance_id = requested_maintenance_id
      AND candidate.expires_at > pg_catalog.clock_timestamp()
      AND candidate.consumed_at IS NULL
      AND candidate.completed_at IS NULL
      AND candidate.recovered_at IS NULL
    FOR UPDATE;
    IF NOT FOUND
       OR authorization.expires_at > maintenance_valid_until
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance authorization is absent or expired';
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_guard_state
       SET module_guard_open = true,
           epoch = epoch + 1,
           opened_epoch = epoch + 1,
           maintenance_id = requested_maintenance_id,
           maintenance_expires_at = authorization.expires_at,
           maintenance_holder_pid = pg_catalog.pg_backend_pid(),
           maintenance_holder_backend_start = holder_start
     WHERE id = 1
       AND protocol_version = 1
       AND schema_version = 2
       AND NOT module_guard_open
       AND epoch = expected_epoch
       AND guard_installation_id = authorization.guard_installation_id
       AND database_oid = authorization.database_oid
       AND database_uuid = authorization.database_uuid
       AND unresolved_effect_count = 0
       AND unresolved_effect_count = (
           SELECT pg_catalog.count(*)
           FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
           LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
             ON resolution.anchor_id = anchor.anchor_id
           WHERE resolution.anchor_id IS NULL
       )
       AND session_user::name = maintenance_role
       AND pg_catalog.current_setting('role', true) = 'none'
       AND NOT pg_catalog.has_schema_privilege(
           runtime_role::text, 'public', 'CREATE'
       )
       AND NOT pg_catalog.pg_has_role(
           maintenance_role, runtime_role, 'MEMBER'
       )
    RETURNING epoch, runtime_role, maintenance_role
    INTO opened, runtime_name, maintenance_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard cannot be opened at the requested epoch';
    END IF;
    EXECUTE pg_catalog.format(
        'GRANT %I TO %I WITH INHERIT FALSE, SET TRUE',
        runtime_name,
        maintenance_name
    );
    EXECUTE pg_catalog.format(
        'GRANT CREATE ON SCHEMA public TO %I', runtime_name
    );
    IF NOT pg_catalog.has_schema_privilege(
        runtime_name::text, 'public', 'CREATE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance CREATE grant was not installed';
    END IF;
    IF NOT pg_catalog.pg_has_role(
        maintenance_name, runtime_name, 'MEMBER'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance SET ROLE grant was not installed';
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_maintenance_authorization
       SET consumed_epoch = opened,
           consumed_at = pg_catalog.transaction_timestamp()
     WHERE maintenance_id = requested_maintenance_id
       AND consumed_at IS NULL
       AND expires_at = authorization.expires_at;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance authorization was not consumed';
    END IF;
    RETURN opened;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.close_module_guard(
    expected_epoch bigint,
    expected_maintenance_id uuid
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    closed bigint;
    guard_state odoo_accounting_cli_v3_guard.module_guard_state%ROWTYPE;
BEGIN
    SELECT state.* INTO guard_state
    FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
    WHERE state.id = 1
      AND state.protocol_version = 1
      AND state.schema_version = 2
      AND state.module_guard_open
      AND state.opened_epoch = state.epoch
      AND state.epoch = expected_epoch
      AND state.maintenance_id = expected_maintenance_id
      AND state.unresolved_effect_count = 0
      AND state.unresolved_effect_count = (
          SELECT pg_catalog.count(*)
          FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
          LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
            ON resolution.anchor_id = anchor.anchor_id
          WHERE resolution.anchor_id IS NULL
      )
      AND state.maintenance_holder_pid = pg_catalog.pg_backend_pid()
      AND state.maintenance_holder_backend_start = (
          SELECT activity.backend_start
          FROM pg_catalog.pg_stat_activity AS activity
          WHERE activity.pid = pg_catalog.pg_backend_pid()
      )
      AND EXISTS (
          SELECT 1
          FROM pg_catalog.pg_locks AS held_lock
          WHERE held_lock.locktype = 'advisory'
            AND held_lock.pid = pg_catalog.pg_backend_pid()
            AND held_lock.database = (
                SELECT oid FROM pg_catalog.pg_database
                WHERE datname = pg_catalog.current_database()
            )
            AND held_lock.classid = 1329677142
            AND held_lock.objid = 1297040433
            AND held_lock.objsubid = 2
            AND held_lock.mode = 'ExclusiveLock'
            AND held_lock.granted
      )
      AND session_user::name = state.maintenance_role
      AND pg_catalog.current_setting('role', true) = 'none'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard cannot be closed at the requested epoch';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.ir_module_module AS module
        WHERE module.state IN ('to install', 'to remove', 'to upgrade')
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance has pending module states';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
        WHERE owner.rolname = guard_state.maintenance_role
          AND namespace.nspname !~ '^pg_(catalog|toast|temp_)'
          AND namespace.nspname <> 'information_schema'
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS function
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = function.pronamespace
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
        WHERE owner.rolname = guard_state.maintenance_role
          AND namespace.nspname !~ '^pg_(catalog|toast|temp_)'
          AND namespace.nspname <> 'information_schema'
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_type AS type
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = type.typnamespace
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = type.typowner
        WHERE owner.rolname = guard_state.maintenance_role
          AND namespace.nspname !~ '^pg_(catalog|toast|temp_)'
          AND namespace.nspname <> 'information_schema'
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS namespace
        JOIN pg_catalog.pg_roles AS owner ON owner.oid = namespace.nspowner
        WHERE owner.rolname = guard_state.maintenance_role
          AND namespace.nspname !~ '^pg_(catalog|toast|temp_)'
          AND namespace.nspname <> 'information_schema'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance left objects owned by the loader role';
    END IF;
    IF NOT pg_catalog.has_schema_privilege(
        guard_state.runtime_role::text, 'public', 'CREATE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance CREATE grant is absent';
    END IF;
    EXECUTE pg_catalog.format(
        'REVOKE CREATE ON SCHEMA public FROM %I', guard_state.runtime_role
    );
    EXECUTE pg_catalog.format(
        'REVOKE %I FROM %I',
        guard_state.runtime_role,
        guard_state.maintenance_role
    );
    IF pg_catalog.has_schema_privilege(
        guard_state.runtime_role::text, 'public', 'CREATE'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance CREATE grant was not revoked';
    END IF;
    IF pg_catalog.pg_has_role(
        guard_state.maintenance_role,
        guard_state.runtime_role,
        'MEMBER'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance SET ROLE grant was not revoked';
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_maintenance_authorization
       SET completed_at = pg_catalog.transaction_timestamp(),
           resolution_txid = pg_catalog.pg_current_xact_id()::text
     WHERE maintenance_id = expected_maintenance_id
       AND consumed_at IS NOT NULL
       AND completed_at IS NULL
       AND recovered_at IS NULL
       AND consumed_epoch IS NOT NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance authorization cannot be completed';
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_guard_state
       SET module_guard_open = false,
           opened_epoch = NULL,
           maintenance_id = NULL,
           maintenance_expires_at = NULL,
           maintenance_holder_pid = NULL,
           maintenance_holder_backend_start = NULL
     WHERE id = 1
       AND protocol_version = 1
       AND schema_version = 2
       AND module_guard_open
       AND opened_epoch = epoch
       AND epoch = expected_epoch
       AND maintenance_id = expected_maintenance_id
       AND maintenance_holder_pid = guard_state.maintenance_holder_pid
       AND maintenance_holder_backend_start = (
           guard_state.maintenance_holder_backend_start
       )
       AND session_user::name = maintenance_role
    RETURNING epoch INTO closed;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard cannot be closed at the requested epoch';
    END IF;
    RETURN closed;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.rescue_module_guard(
    expected_epoch bigint,
    expected_maintenance_id uuid,
    requested_recovery_attestation_digest text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    rescued bigint;
    configured_finalizer name;
    guard_state odoo_accounting_cli_v3_guard.module_guard_state%ROWTYPE;
BEGIN
    IF expected_epoch < 0
       OR expected_maintenance_id IS NULL
       OR requested_recovery_attestation_digest !~ '^[0-9a-f]{64}$'
       OR pg_catalog.current_setting('role', true) <> 'none'
       OR NOT pg_catalog.pg_try_advisory_xact_lock(
           1329677142, 1297040433
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55P03',
            MESSAGE = 'module maintenance crash rescue request is invalid or busy';
    END IF;
    SELECT state.* INTO guard_state
    FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
    WHERE state.id = 1
      AND state.protocol_version = 1
      AND state.schema_version = 2
      AND state.module_guard_open
      AND state.opened_epoch = state.epoch
      AND state.epoch = expected_epoch
      AND state.maintenance_id = expected_maintenance_id
      AND state.unresolved_effect_count = 0
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'module maintenance crash rescue state is invalid';
    END IF;
    configured_finalizer := guard_state.finalizer_role;
    IF session_user::name <> configured_finalizer THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'module maintenance crash rescue identity is invalid';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_stat_activity AS activity
        WHERE activity.usename = guard_state.maintenance_role
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance holder is still live';
    END IF;
    EXECUTE pg_catalog.format(
        'REVOKE CREATE ON SCHEMA public FROM %I', guard_state.runtime_role
    );
    EXECUTE pg_catalog.format(
        'REVOKE %I FROM %I',
        guard_state.runtime_role,
        guard_state.maintenance_role
    );
    IF pg_catalog.has_schema_privilege(
        guard_state.runtime_role::text, 'public', 'CREATE'
    ) OR pg_catalog.pg_has_role(
        guard_state.maintenance_role, guard_state.runtime_role, 'MEMBER'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance crash privileges were not revoked';
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_maintenance_authorization
       SET recovered_at = pg_catalog.transaction_timestamp(),
           resolution_txid = pg_catalog.pg_current_xact_id()::text,
           recovery_attestation_digest = requested_recovery_attestation_digest
     WHERE maintenance_id = expected_maintenance_id
       AND consumed_at IS NOT NULL
       AND completed_at IS NULL
       AND recovered_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance authorization cannot be rescued';
    END IF;
    UPDATE odoo_accounting_cli_v3_guard.module_guard_state
       SET module_guard_open = false,
           opened_epoch = NULL,
           maintenance_id = NULL,
           maintenance_expires_at = NULL,
           maintenance_holder_pid = NULL,
           maintenance_holder_backend_start = NULL
     WHERE id = 1
       AND module_guard_open
       AND epoch = expected_epoch
       AND maintenance_id = expected_maintenance_id
    RETURNING epoch INTO rescued;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module maintenance crash rescue state changed';
    END IF;
    RETURN rescued;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.module_maintenance_session_is_active()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.coalesce((
        SELECT
            state.module_guard_open
            AND state.opened_epoch = state.epoch
            AND state.maintenance_expires_at > pg_catalog.clock_timestamp()
            AND session_user::name = state.maintenance_role
            AND pg_catalog.current_setting('role', true) = state.runtime_role::text
            AND state.maintenance_holder_pid = pg_catalog.pg_backend_pid()
            AND state.maintenance_holder_backend_start = activity.backend_start
            AND EXISTS (
                SELECT 1
                FROM pg_catalog.pg_locks AS held_lock
                WHERE held_lock.locktype = 'advisory'
                  AND held_lock.pid = pg_catalog.pg_backend_pid()
                  AND held_lock.database = (
                      SELECT oid FROM pg_catalog.pg_database
                      WHERE datname = pg_catalog.current_database()
                  )
                  AND held_lock.classid = 1329677142
                  AND held_lock.objid = 1297040433
                  AND held_lock.objsubid = 2
                  AND held_lock.mode = 'ExclusiveLock'
                  AND held_lock.granted
            )
        FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
        JOIN pg_catalog.pg_stat_activity AS activity
          ON activity.pid = pg_catalog.pg_backend_pid()
        WHERE state.id = 1
          AND state.protocol_version = 1
          AND state.schema_version = 2
    ), false)
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.guard_ddl_end()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    command record;
    configured_runtime name;
    configured_maintenance name;
    configured_finalizer name;
    object_owner name;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = session_user AND role.rolsuper
    ) THEN
        RETURN;
    END IF;
    SELECT state.runtime_role, state.maintenance_role, state.finalizer_role
    INTO configured_runtime, configured_maintenance, configured_finalizer
    FROM odoo_accounting_cli_v3_guard.module_guard_state AS state
    WHERE state.id = 1 AND state.protocol_version = 1 AND state.schema_version = 2;
    FOR command IN SELECT * FROM pg_catalog.pg_event_trigger_ddl_commands()
    LOOP
        IF command.command_tag IN ('GRANT', 'REVOKE')
           AND session_user::name IN (
               configured_maintenance, configured_finalizer
           )
           AND pg_catalog.current_setting('role', true) = 'none'
        THEN
            CONTINUE;
        END IF;
        IF command.schema_name ~ '^pg_(temp|toast_temp)_' THEN
            CONTINUE;
        END IF;
        IF command.schema_name = 'odoo_accounting_cli_v3_guard'
           OR command.object_identity IN (
               'public.ir_module_module',
               'public.odoo_accounting_cli_operation'
           )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55006',
                MESSAGE = 'module guard protected object DDL is forbidden';
        END IF;
        IF NOT odoo_accounting_cli_v3_guard.module_maintenance_session_is_active() THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'module maintenance DDL is not authorized';
        END IF;
        object_owner := NULL;
        IF command.classid = 'pg_catalog.pg_class'::pg_catalog.regclass THEN
            SELECT owner.rolname INTO object_owner
            FROM pg_catalog.pg_class AS object
            JOIN pg_catalog.pg_roles AS owner ON owner.oid = object.relowner
            WHERE object.oid = command.objid;
        ELSIF command.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass THEN
            SELECT owner.rolname INTO object_owner
            FROM pg_catalog.pg_proc AS object
            JOIN pg_catalog.pg_roles AS owner ON owner.oid = object.proowner
            WHERE object.oid = command.objid;
        ELSIF command.classid = 'pg_catalog.pg_type'::pg_catalog.regclass THEN
            SELECT owner.rolname INTO object_owner
            FROM pg_catalog.pg_type AS object
            JOIN pg_catalog.pg_roles AS owner ON owner.oid = object.typowner
            WHERE object.oid = command.objid;
        ELSIF command.classid = 'pg_catalog.pg_namespace'::pg_catalog.regclass THEN
            SELECT owner.rolname INTO object_owner
            FROM pg_catalog.pg_namespace AS object
            JOIN pg_catalog.pg_roles AS owner ON owner.oid = object.nspowner
            WHERE object.oid = command.objid;
        END IF;
        IF object_owner IS NOT NULL AND object_owner <> configured_runtime THEN
            RAISE EXCEPTION USING
                ERRCODE = '55006',
                MESSAGE = 'module maintenance object owner is not the runtime role';
        END IF;
    END LOOP;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.guard_sql_drop()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    dropped record;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = session_user AND role.rolsuper
    ) THEN
        RETURN;
    END IF;
    FOR dropped IN SELECT * FROM pg_catalog.pg_event_trigger_dropped_objects()
    LOOP
        IF dropped.is_temporary THEN
            CONTINUE;
        END IF;
        IF dropped.schema_name = 'odoo_accounting_cli_v3_guard'
           OR dropped.object_identity IN (
               'public.ir_module_module',
               'public.odoo_accounting_cli_operation'
           )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55006',
                MESSAGE = 'module guard protected object DDL is forbidden';
        END IF;
        IF NOT odoo_accounting_cli_v3_guard.module_maintenance_session_is_active() THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'module maintenance DDL is not authorized';
        END IF;
    END LOOP;
END
$function$;

CREATE OR REPLACE FUNCTION odoo_accounting_cli_v3_guard.guard_table_rewrite()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    rewritten_relation oid := pg_catalog.pg_event_trigger_table_rewrite_oid();
    rewritten_schema name;
    rewritten_name name;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = session_user AND role.rolsuper
    ) THEN
        RETURN;
    END IF;
    SELECT namespace.nspname, relation.relname
    INTO rewritten_schema, rewritten_name
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE relation.oid = rewritten_relation;
    IF rewritten_schema ~ '^pg_(temp|toast_temp)_' THEN
        RETURN;
    END IF;
    IF rewritten_schema = 'odoo_accounting_cli_v3_guard'
       OR (rewritten_schema = 'public' AND rewritten_name IN (
           'ir_module_module', 'odoo_accounting_cli_operation'
       ))
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55006',
            MESSAGE = 'module guard protected object DDL is forbidden';
    END IF;
    IF NOT odoo_accounting_cli_v3_guard.module_maintenance_session_is_active() THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'module maintenance DDL is not authorized';
    END IF;
END
$function$;

ALTER FUNCTION odoo_accounting_cli_v3_guard.effect_is_unresolved(text, text, text, text)
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.result_is_bound(
    text, text, text, text, text, text, bigint, text, text, text,
    text, text, boolean
)
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.track_operation_effect()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.reject_operation_truncate()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.guard_module_change()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.verify_module_change()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.read_module_guard_state()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.authorize_module_maintenance(
    uuid, uuid, oid, uuid, text, text, text, text, timestamp with time zone
)
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.finalize_operation_effect(
    uuid, oid, uuid, uuid, text, text, timestamp with time zone,
    timestamp with time zone, text, text, text, text, text, text, text, text
)
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.open_module_guard(bigint, uuid)
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.close_module_guard(bigint, uuid)
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.rescue_module_guard(bigint, uuid, text)
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.module_maintenance_session_is_active()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.guard_ddl_end()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.guard_sql_drop()
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER FUNCTION odoo_accounting_cli_v3_guard.guard_table_rewrite()
    OWNER TO odoo_accounting_cli_v3_guard_owner;

REVOKE ALL ON ALL TABLES IN SCHEMA odoo_accounting_cli_v3_guard FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA odoo_accounting_cli_v3_guard FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA odoo_accounting_cli_v3_guard FROM PUBLIC;
SELECT format(
    'REVOKE ALL ON ALL TABLES IN SCHEMA odoo_accounting_cli_v3_guard FROM %I',
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
\gexec
SELECT format(
    'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA odoo_accounting_cli_v3_guard FROM %I',
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
\gexec
SELECT format(
    'REVOKE ALL ON ALL SEQUENCES IN SCHEMA odoo_accounting_cli_v3_guard FROM %I',
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
\gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.read_module_guard_state() TO %I',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.read_module_guard_state() TO %I',
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.read_module_guard_state() TO %I',
    current_setting('odoo_accounting_cli_v3.maintenance_role')
) \gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.authorize_module_maintenance('
    'uuid, uuid, oid, uuid, text, text, text, text, timestamp with time zone) TO %I',
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.finalize_operation_effect('
    'uuid, oid, uuid, uuid, text, text, timestamp with time zone, '
    'timestamp with time zone, text, text, text, text, text, text, text, text) TO %I',
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.rescue_module_guard(bigint, uuid, text) TO %I',
    current_setting('odoo_accounting_cli_v3.finalizer_role')
) \gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.open_module_guard(bigint, uuid) TO %I',
    current_setting('odoo_accounting_cli_v3.maintenance_role')
) \gexec
SELECT format(
    'GRANT EXECUTE ON FUNCTION '
    'odoo_accounting_cli_v3_guard.close_module_guard(bigint, uuid) TO %I',
    current_setting('odoo_accounting_cli_v3.maintenance_role')
) \gexec

DO $validate_existing_operations$
BEGIN
    PERFORM odoo_accounting_cli_v3_guard.effect_is_unresolved(
        operation.state,
        operation.execution_result_json,
        operation.verification_result_json,
        operation.recovery_result_json
    )
    FROM public.odoo_accounting_cli_operation AS operation;
    IF EXISTS (
        SELECT 1
        FROM public.odoo_accounting_cli_operation AS operation
        WHERE operation.execution_result_json IS NOT NULL
          AND NOT odoo_accounting_cli_v3_guard.result_is_bound(
              operation.execution_result_json,
              'execution',
              'execution_result_v2',
              operation.operation_id,
              operation.request_id,
              operation.operation_digest,
              operation.company_id,
              operation.capability_id,
              operation.registry_digest,
              operation.release_digest,
              operation.execution_evidence_digest,
              NULL,
              (operation.execution_result_json::jsonb ->> 'succeeded')::boolean
          )
    ) OR EXISTS (
        SELECT 1
        FROM public.odoo_accounting_cli_operation AS operation
        WHERE operation.verification_result_json IS NOT NULL
          AND NOT odoo_accounting_cli_v3_guard.result_is_bound(
              operation.verification_result_json,
              'verification',
              'verification_result_v2',
              operation.operation_id,
              operation.request_id,
              operation.operation_digest,
              operation.company_id,
              operation.capability_id,
              operation.registry_digest,
              operation.release_digest,
              operation.verification_evidence_digest,
              operation.execution_evidence_digest,
              (
                  operation.verification_result_json::jsonb ->> 'succeeded'
              )::boolean
          )
    ) OR EXISTS (
        SELECT 1
        FROM public.odoo_accounting_cli_operation AS operation
        WHERE operation.recovery_result_json IS NOT NULL
          AND NOT odoo_accounting_cli_v3_guard.result_is_bound(
              operation.recovery_result_json,
              'recovery',
              'recovery_result_v2',
              operation.operation_id,
              operation.request_id,
              operation.operation_digest,
              operation.company_id,
              operation.capability_id,
              operation.registry_digest,
              operation.release_digest,
              operation.recovery_evidence_digest,
              operation.recovery_plan_digest,
              (operation.recovery_result_json::jsonb ->> 'succeeded')::boolean
          )
    ) THEN
        RAISE EXCEPTION 'existing operation result binding is invalid';
    END IF;
END
$validate_existing_operations$;

INSERT INTO odoo_accounting_cli_v3_guard.operation_effect_anchor (
    operation_record_id,
    operation_id,
    operation_digest,
    registry_digest,
    release_digest,
    effect_phase,
    source_digest,
    source_evidence_digest,
    opened_at,
    opened_txid
)
SELECT
    operation.id,
    operation.operation_id,
    operation.operation_digest,
    operation.registry_digest,
    operation.release_digest,
    'execution',
    operation.execution_result_digest,
    operation.execution_evidence_digest,
    pg_catalog.transaction_timestamp(),
    pg_catalog.pg_current_xact_id()::text
FROM public.odoo_accounting_cli_operation AS operation
WHERE operation.execution_result_json IS NOT NULL
  AND (operation.execution_result_json::jsonb ->> 'succeeded')::boolean
ON CONFLICT DO NOTHING;

DO $verify_effect_ledger$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
        JOIN public.odoo_accounting_cli_operation AS operation
          ON operation.id = anchor.operation_record_id
        WHERE anchor.operation_id <> operation.operation_id
           OR anchor.operation_digest <> operation.operation_digest
           OR anchor.registry_digest <> operation.registry_digest
           OR anchor.release_digest <> operation.release_digest
           OR (
               anchor.effect_phase = 'execution'
               AND (
                   operation.execution_result_json IS NULL
                   OR NOT (
                       operation.execution_result_json::jsonb ->> 'succeeded'
                   )::boolean
                   OR anchor.source_digest <> operation.execution_result_digest
                   OR anchor.source_evidence_digest <> operation.execution_evidence_digest
               )
           )
    ) OR EXISTS (
        SELECT 1
        FROM public.odoo_accounting_cli_operation AS operation
        LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
          ON anchor.operation_record_id = operation.id
         AND anchor.effect_phase = 'execution'
        WHERE operation.execution_result_json IS NOT NULL
          AND (operation.execution_result_json::jsonb ->> 'succeeded')::boolean
          AND anchor.operation_record_id IS NULL
    ) THEN
        RAISE EXCEPTION 'operation effect ledger binding is inconsistent';
    END IF;
END
$verify_effect_ledger$;

UPDATE odoo_accounting_cli_v3_guard.module_guard_state
   SET unresolved_effect_count = (
       SELECT pg_catalog.count(*)
       FROM odoo_accounting_cli_v3_guard.operation_effect_anchor AS anchor
       LEFT JOIN odoo_accounting_cli_v3_guard.operation_effect_resolution AS resolution
         ON resolution.anchor_id = anchor.anchor_id
       WHERE resolution.anchor_id IS NULL
       ),
       module_guard_open = false,
       opened_epoch = NULL,
       maintenance_id = NULL,
       maintenance_expires_at = NULL,
       maintenance_holder_pid = NULL,
       maintenance_holder_backend_start = NULL
 WHERE id = 1
   AND protocol_version = 1
   AND schema_version = 2;

DROP TRIGGER IF EXISTS odoo_accounting_cli_v3_operation_effect_guard
    ON public.odoo_accounting_cli_operation;
CREATE TRIGGER odoo_accounting_cli_v3_operation_effect_guard
AFTER INSERT OR UPDATE OR DELETE ON public.odoo_accounting_cli_operation
FOR EACH ROW
EXECUTE FUNCTION odoo_accounting_cli_v3_guard.track_operation_effect();
ALTER TABLE public.odoo_accounting_cli_operation
    ENABLE ALWAYS TRIGGER odoo_accounting_cli_v3_operation_effect_guard;

DROP TRIGGER IF EXISTS odoo_accounting_cli_v3_operation_no_truncate
    ON public.odoo_accounting_cli_operation;
CREATE TRIGGER odoo_accounting_cli_v3_operation_no_truncate
BEFORE TRUNCATE ON public.odoo_accounting_cli_operation
FOR EACH STATEMENT
EXECUTE FUNCTION odoo_accounting_cli_v3_guard.reject_operation_truncate();
ALTER TABLE public.odoo_accounting_cli_operation
    ENABLE ALWAYS TRIGGER odoo_accounting_cli_v3_operation_no_truncate;

DROP TRIGGER IF EXISTS odoo_accounting_cli_v3_module_change_guard
    ON public.ir_module_module;
CREATE TRIGGER odoo_accounting_cli_v3_module_change_guard
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.ir_module_module
FOR EACH STATEMENT
EXECUTE FUNCTION odoo_accounting_cli_v3_guard.guard_module_change();
ALTER TABLE public.ir_module_module
    ENABLE ALWAYS TRIGGER odoo_accounting_cli_v3_module_change_guard;

DROP TRIGGER IF EXISTS odoo_accounting_cli_v3_module_change_guard_after
    ON public.ir_module_module;
CREATE TRIGGER odoo_accounting_cli_v3_module_change_guard_after
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.ir_module_module
FOR EACH STATEMENT
EXECUTE FUNCTION odoo_accounting_cli_v3_guard.verify_module_change();
ALTER TABLE public.ir_module_module
    ENABLE ALWAYS TRIGGER odoo_accounting_cli_v3_module_change_guard_after;

ALTER TABLE public.ir_module_module
    OWNER TO odoo_accounting_cli_v3_guard_owner;
ALTER TABLE public.odoo_accounting_cli_operation
    OWNER TO odoo_accounting_cli_v3_guard_owner;

REVOKE ALL ON TABLE public.ir_module_module FROM PUBLIC;
SELECT format('REVOKE ALL ON TABLE public.ir_module_module FROM %I', role.rolname)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
\gexec
SELECT format(
    'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.ir_module_module TO %I',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec
SELECT format(
    'REVOKE TRUNCATE, REFERENCES, TRIGGER ON TABLE public.ir_module_module FROM %I',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec

REVOKE ALL ON TABLE public.odoo_accounting_cli_operation FROM PUBLIC;
SELECT format(
    'REVOKE ALL ON TABLE public.odoo_accounting_cli_operation FROM %I',
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
\gexec
SELECT format(
    'GRANT SELECT, INSERT, UPDATE ON TABLE public.odoo_accounting_cli_operation TO %I',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec
SELECT format(
    'REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER '
    'ON TABLE public.odoo_accounting_cli_operation FROM %I',
    current_setting('odoo_accounting_cli_v3.runtime_role')
) \gexec

SELECT format(
    'ALTER SEQUENCE %s OWNER TO odoo_accounting_cli_v3_guard_owner',
    pg_get_serial_sequence('public.ir_module_module', 'id')
)
WHERE pg_get_serial_sequence('public.ir_module_module', 'id') IS NOT NULL
\gexec
SELECT format(
    'ALTER SEQUENCE %s OWNER TO odoo_accounting_cli_v3_guard_owner',
    pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id')
)
WHERE pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id') IS NOT NULL
\gexec
SELECT format(
    'REVOKE ALL ON SEQUENCE %s FROM PUBLIC',
    pg_get_serial_sequence('public.ir_module_module', 'id')
)
WHERE pg_get_serial_sequence('public.ir_module_module', 'id') IS NOT NULL
\gexec
SELECT format(
    'REVOKE ALL ON SEQUENCE %s FROM PUBLIC',
    pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id')
)
WHERE pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id') IS NOT NULL
\gexec
SELECT format(
    'REVOKE ALL ON SEQUENCE %s FROM %I',
    pg_get_serial_sequence('public.ir_module_module', 'id'),
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
  AND pg_get_serial_sequence('public.ir_module_module', 'id') IS NOT NULL
\gexec
SELECT format(
    'REVOKE ALL ON SEQUENCE %s FROM %I',
    pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id'),
    role.rolname
)
FROM pg_catalog.pg_roles AS role
WHERE role.rolname <> 'odoo_accounting_cli_v3_guard_owner'
  AND pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id') IS NOT NULL
\gexec
SELECT format(
    'GRANT USAGE, SELECT ON SEQUENCE %s TO %I',
    pg_get_serial_sequence('public.ir_module_module', 'id'),
    current_setting('odoo_accounting_cli_v3.runtime_role')
)
WHERE pg_get_serial_sequence('public.ir_module_module', 'id') IS NOT NULL
\gexec
SELECT format(
    'GRANT USAGE, SELECT ON SEQUENCE %s TO %I',
    pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id'),
    current_setting('odoo_accounting_cli_v3.runtime_role')
)
WHERE pg_get_serial_sequence('public.odoo_accounting_cli_operation', 'id') IS NOT NULL
\gexec

CREATE EVENT TRIGGER odoo_accounting_cli_v3_ddl_guard_end
    ON ddl_command_end
    EXECUTE FUNCTION odoo_accounting_cli_v3_guard.guard_ddl_end();
ALTER EVENT TRIGGER odoo_accounting_cli_v3_ddl_guard_end ENABLE ALWAYS;

CREATE EVENT TRIGGER odoo_accounting_cli_v3_sql_drop_guard
    ON sql_drop
    EXECUTE FUNCTION odoo_accounting_cli_v3_guard.guard_sql_drop();
ALTER EVENT TRIGGER odoo_accounting_cli_v3_sql_drop_guard ENABLE ALWAYS;

CREATE EVENT TRIGGER odoo_accounting_cli_v3_table_rewrite_guard
    ON table_rewrite
    EXECUTE FUNCTION odoo_accounting_cli_v3_guard.guard_table_rewrite();
ALTER EVENT TRIGGER odoo_accounting_cli_v3_table_rewrite_guard ENABLE ALWAYS;

COMMIT;

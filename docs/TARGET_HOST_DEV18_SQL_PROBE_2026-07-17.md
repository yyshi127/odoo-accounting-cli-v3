# Target-host Dev18 protected-UUID SQL probe

At `2026-07-17T13:16:06Z`, the uncommitted Dev18 protected-database SQL was
executed read-only against `odoo_test` on `43.165.173.80` to validate PostgreSQL
16.14 syntax and the real Odoo 19 relation shape. This was a development probe,
not an immutable-release capacity-gate receipt and not provisioning or write
authorization.

The final probe used the reviewed PostgreSQL Unix socket and the direct
protected-UUID read-probe candidate `odoo` OS/database identity, rather than
planning the protected table read as `postgres`. `SESSION_USER` and
`CURRENT_USER` were both `odoo`; the role was neither superuser nor
`BYPASSRLS`. It does have `CREATEDB` and owns 108 databases, so this limited
read-probe suitability does not qualify it as a sandbox executor or authority.
The session fixed
`search_path=pg_catalog`, `default_transaction_read_only=on`,
bounded statement/lock/idle timeouts, and index/bitmap/TID/parallel/JIT plans
disabled. The protected read ran inside one `REPEATABLE READ, READ ONLY`
transaction. It acquired `ACCESS SHARE` on
`ONLY public.ir_config_parameter`, ran the `pg_catalog`-only structural and
SHA-256 assertion, captured relation identity, read only `database.uuid`,
captured relation identity again, and explicitly rolled back.

Observed result:

- structural assertion: `true`;
- database OID/owner: `16392` / `odoo`;
- relation OID/filenode/owner: `54844` / `54844` / `odoo`;
- relation: ordinary persistent `heap`, no RLS, forced RLS, rewrite rules,
  partitioning, inheritance, CHECK constraints, unsafe expression/partial
  indexes, expression statistics, superuser/RLS-bypass owner, or inherited
  role membership;
- planner objects: two policy-recorded built-in `btree` indexes and zero
  extended-statistics objects;
- `key`: built-in type OID `1043` (`varchar`), not generated or identity;
- `value`: built-in type OID `25` (`text`), not generated or identity;
- relation identity SHA-256 before and after:
  `5953b24648dfa6e884dff75315595d2d2bcb9b74797e4c698e278661bbe8e6b2`;
- Odoo database UUID:
  `19b09656-d10f-11f0-9065-00163e54a5ad`, matching the earlier target-host
  baseline; and
- SQL `transaction_read_only`: `on`.

A second read-only negative probe supplied an intentionally wrong reviewed
digest. The structural assertion stopped with a division-by-zero error under
`ON_ERROR_STOP`, and the later sentinel/UUID statement was not executed. This
confirms the unsafe-object/digest assertion is ordered before PostgreSQL can
plan the protected table read.

No DDL, DML, Odoo RPC, service control, file creation, role change, database
creation, provisioning, or accounting write was actively performed by the
collector. Normal authentication, filesystem, PostgreSQL, or OS logging/atime
effects remain outside that claim. The host still fails the separate capacity
prerequisite documented in
`TARGET_HOST_CAPACITY_AUDIT_2026-07-17.md`; this successful SQL compatibility
probe does not change that disposition.

## 2026-07-18 configuration and socket re-probe

At `2026-07-18T01:02:51Z`, the then-current uncommitted collector was streamed
to `python3 -` over SSH and executed in memory. Nothing was installed on the
target. There was no reload, role alteration, DDL, DML, service control, or
target-file write.

The PostgreSQL 16.14 configuration query ran twice under forced read-only
session options and returned exactly one identical object each time. Its
canonical row SHA-256 was
`2b7134970c778c14026877c041a896cbd1ab3c4089d38ba028619e0ad7160607`.
Both captures contained:

- one configuration-load identity;
- 363 effective settings and 24 file-setting rows;
- seven HBA rules and zero ident mappings;
- zero database/role default rows;
- 17 roles, one server-side aggregate password-vector digest, and three role
  memberships; and
- empty shared, session, and local preload settings.

The component-level physical-plus-semantic configuration capture also ran
twice and produced the same final identity each time:
`e3ec38297ae021a3938d0951ff1c2dc884614f13f3c2a54dda10502f4457c270`.
It bound the reviewed `/etc/postgresql/16/main` tree and include graph, the SSL
certificate and key, `postgresql.auto.conf`, and configuration-load identity
`1784219884819402`. This proves compatibility of the current configuration
collector only; it is not an immutable-release receipt and did not include a
passing full capacity gate.

The full gate remains rejected before SQL because `/run/postgresql` is mode
`2775` (owner/group `postgres`, UID/GID `111/112`) while the host NSS sources
are `files systemd`. The current security rule requires the reviewed socket
directory to be owner-only writable and reports
`PostgreSQL socket directory must not be group-writable`. The historical SQL,
configuration, and NSS hashes in this document must not be copied into a
policy or reported as a passing Dev18 gate.

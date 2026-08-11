# V3 runtime configuration

## Read runtime configuration

The `read` command accepts one absolute path to a root-managed JSON file. The
file is an allowlist: callers cannot replace the Odoo executable, database,
release, state stores, or signing keys through request parameters.

```json
{
  "instance_id": "odoo19@43.165.173.80",
  "environment": "test",
  "capability_channel": "staged",
  "database_name": "odoo_test",
  "database_uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
  "odoo_python": "/opt/odoo/odoo19/odoo19-venv/bin/python",
  "odoo_python_sha256": "<sha256-of-resolved-runtime-file>",
  "odoo_bin": "/opt/odoo/odoo19/odoo-server/odoo-bin",
  "odoo_bin_sha256": "<sha256-of-runtime-file>",
  "odoo_config": "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf",
  "odoo_config_sha256": "<sha256-of-runtime-file>",
  "release_root": "/opt/odoo-accounting-cli-v3/releases/<release>",
  "canonical_package_path": "/opt/odoo-accounting-cli-v3/packages/odoo-accounting-cli-v3-<release>.tar.gz",
  "canonical_package_sha256": "<sha256-of-canonical-release-package>",
  "auth_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/<version>-<commit12>/auth.sqlite3",
  "receipt_state_path": "/var/lib/odoo-accounting-cli-v3/test/candidates/<version>-<commit12>/receipt.sqlite3",
  "auth_key_id": "test-auth-2026-07",
  "receipt_key_id": "test-receipt-2026-07",
  "auth_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/auth.hmac",
  "receipt_secret_path": "/etc/odoo-accounting-cli-v3/secrets/test/receipt.hmac"
}
```

The object must contain exactly these fields. The configuration and its parent
directory must be canonical, root-owned, and not group/world writable. Each
secret must be a distinct root-owned regular file of at least 32 bytes; group
read is allowed for the dedicated service group, but world access and
group/world write are rejected. The distinct Key IDs are part of the signed
wire protocol and are checked against this configuration. Secrets and business
parameters are carried to the Odoo shell through a sealed inherited file
descriptor; standard input contains only a fixed bootstrap, and argv and the
fixed child environment contain neither secrets nor request data.

The two state paths are private SQLite/WAL databases. Their parent directories
must not be group/world writable; a service-owned mode `0700` directory and
mode `0600` database files are the expected deployment. Authentication tokens
and read receipts are consumed atomically and survive process restart. A
verified read is appended to the receipt database's tamper-evident audit chain
before the CLI may report success.

### Odoo PostgreSQL read-only transaction boundary

Odoo 19's `registry.cursor(readonly=True)` is not a safety boundary: when no
replica is configured or available it deliberately falls back to a read/write
cursor on the primary. V3 therefore uses the dedicated cursor created by the
noninteractive Odoo shell and fails before any model access unless the
underlying psycopg2 connection is idle with autocommit disabled.

The read bootstrap explicitly calls
`set_session(readonly=True, isolation_level="REPEATABLE READ")` before reading
the database UUID, binding the non-superuser environment, checking company/ACL,
or invoking a handler. It then requires both the Odoo cursor and psycopg2
connection to report read-only, and queries PostgreSQL for exact
`transaction_read_only=on` and `transaction_isolation=repeatable read`. A
random transaction-local custom setting binds the pre- and post-handler checks
to the same top-level transaction. A hidden commit or rollback, writable-state
drift, failed server attestation, callback failure, failed rollback, or
post-rollback libpq status other than `IDLE` discards the business result. The
helper never calls commit.

The trusted staged read entrypoint's package parents and explicit transitive
internal imports, rooted at `odoo.bootstrap`, are AST-gated together with each
explicit internal and external import binding fixed to its reviewed source
module. Every
reviewed dependency except the transaction helper is scanned for direct ORM
persistence, raw SQL/cursors, transaction controls, `sudo`/user-environment
switching, dynamic
access through the explicitly guarded reflection patterns, filesystem mutation,
command execution, and network client imports. The transaction helper has a
pinned source digest and separate structural allowlist that pins its imports,
marker, two `SELECT` statements, one `set_session` call, and the rollback in
`finally`. A new explicit helper or external import fails until the reviewed
closure is deliberately updated. Attribute and subscript assignment targets
fail unless they match the reviewed constructors or local in-memory mappings.
Those mappings must have exactly one earlier plain-dict binding; rebinding them
to an Odoo record fails. The release gate permits only the canonical package
under `src` and rejects tracked bytecode, native extensions, and external-module
shadows on every platform. The full bootstrap and executor source files are
digest-pinned, their critical callable/class bindings cannot be reassigned, and
the explicit import-binding digest includes local aliases.
This source gate is defense in depth; it is not a complete proof against
reflection or an indirect external effect.

This boundary proves rollback-only behavior for Odoo/PostgreSQL business work
issued through the dedicated shell connection; it is not a claim that the read
process cannot open a second connection or cause other state changes.
Authentication token consumption and verified-receipt audit append to the two
private SQLite stores are required durable security effects. Second database
connections, files, mail, webhooks, and other external effects remain outside
this database guarantee and require separate source, OS/addon, and exact-release
runtime evidence before enablement.

Before any read becomes enabled, the exact immutable release must reproduce the
same pre/post transaction attestation in `odoo_test`, demonstrate PostgreSQL
SQLSTATE `25006` for a controlled no-candidate-row DML probe, return to `IDLE`,
and match an independent read-only SQL witness and the capability's financial
standard answer. Local fake-ORM or CI PostgreSQL results do not replace that
Odoo-bound signed receipt.

## Write runtime configuration schema v2

The six write-lifecycle actions use the fixed root-managed path
`/etc/odoo-accounting-cli-v3/write-runtime.json`. Pi and other callers cannot
select this path, a state database, an Odoo executable, or a key through request
parameters. The write runtime document has schema version `2`; this is separate
from the SQLite persistence schema, which is version `4`.

The following is an illustrative disabled configuration. It contains key IDs,
secret file paths, and the secret-free effect-finalizer client binding only,
never secret values:

```json
{
  "schema_version": 2,
  "write_execution_mode": "disabled",
  "base_runtime_config_path": "/etc/odoo-accounting-cli-v3/runtime-sandbox.json",
  "write_state_path": "/var/lib/odoo-accounting-cli-v3/sandbox/candidates/<release>/write.sqlite3",
  "effect_finalizer": {
    "socket_path": "/run/odoo-accounting-cli-v3/effect-finalizer.sock",
    "socket_owner_uid": 0,
    "socket_group_gid": 991,
    "socket_mode": 432,
    "finalizer_service_uid": 992,
    "finalizer_service_gid": 992,
    "finalizer_systemd_unit": "odoo-accounting-cli-v3-effect-finalizer.service",
    "attestation_key_id": "sandbox-effect-finalizer-2026-07",
    "guard_installation_id": "<SANDBOX_GUARD_INSTALLATION_UUID>",
    "database_oid": 16384,
    "handoff_idle_timeout_seconds": 100.0,
    "request_io_timeout_seconds": 5.0,
    "max_request_bytes": 16384,
    "max_response_bytes": 16384
  },
  "write_auth": {
    "key_id": "sandbox-write-auth-2026-07",
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/write_auth.hmac"
  },
  "approval": {
    "key_id": "sandbox-approval-2026-07",
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/approval.hmac"
  },
  "execution": {
    "issuer": "odoo-v3-sandbox-execution",
    "key_id": "sandbox-execution-2026-07",
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/execution.hmac"
  },
  "verification": {
    "issuer": "odoo-v3-sandbox-verification",
    "key_id": "sandbox-verification-2026-07",
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/verification.hmac"
  },
  "recovery": {
    "issuer": "odoo-v3-sandbox-recovery",
    "key_id": "sandbox-recovery-2026-07",
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/recovery.hmac"
  },
  "write_receipt": {
    "key_id": "sandbox-write-receipt-2026-07",
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/write_receipt.hmac"
  }
}
```

`write_auth`, `approval`, `execution`, `verification`, `recovery`, and
`write_receipt` are six distinct roles. Their Key IDs, absolute paths, and file
inodes must also be distinct from the two read roles. Execution, verification,
and recovery issuer names must be different. Each secret is at least 32 random
bytes in a canonical root-owned regular file, normally mode `0640`, with no
world access and no group/world write. The recovery role is reserved and
validated by the runtime boundary; its presence must not be represented as
evidence that every recovery outcome is currently signed by that role.
The `effect_finalizer` section binds the broker to the isolated finalizer
socket and finalizer identity; it references no finalizer HMAC, pgpass, Odoo
configuration, or database LOGIN secret.

The write state parent is service-owned mode `0700`. The SQLite database and
its `-wal` and `-shm` companions must remain service-owned mode `0600`, and must
not share a path or inode with read authentication or receipt state. Do not
print, copy into evidence, commit, or pass any secret or complete signed request
on argv. Pi integrations must send the JSON request over standard input or an
equivalent sealed local transport.

Within one Python process, every trusted authority/session SQLite connection
and every direct database/WAL/SHM descriptor check shares one non-reentrant
process-wide lifecycle gate. This intentionally serializes even different
trusted-store paths: on POSIX, closing an unrelated descriptor for an aliased
database can release process-owned record locks. The gate remains held from
the first file check until the SQLite connection is positively closed and all
post-close checks finish. A nested same-thread lifecycle fails immediately.
An unconfirmed close, descriptor-close failure, or ownership/phase mismatch
poisons the process gate; no further trusted SQLite access is allowed until a
fresh process starts.

Forking while a lifecycle is active or poisoned is unsupported. For
Python-managed `os.fork`, the registered V3 child hook fail-stops with
`_exit(70)` before returning to the fork caller or running its `finally`,
garbage collection, SQLite close/rollback, or writer-lock cleanup. It therefore
cannot continue or exec with the inherited connection and cannot unlock the
parent's writer-lock descriptor. Native/C-level fork paths that bypass
`os.register_at_fork` are prohibited, and an earlier-registered third-party
child hook must never touch a trusted-store connection or descriptor before the
V3 fail-stop hook runs. Services must fork workers before opening a trusted
store and then exec their runtime, or use a non-forking worker model. A
reconciliation-required result is never repaired by retrying in the poisoned
process.

The modes are fail-closed:

- `disabled` rejects prepare, preview, approve-execute, and recover while
  retaining authenticated status and result access;
- `sandbox_staged` requires a base runtime whose environment is `sandbox` and
  whose capability channel is `staged`; and
- `enabled` requires an `enabled` base-runtime channel and does not itself
  authorize any registry capability or production write.

The standard lifecycle actions are `operation prepare`, `operation preview`,
`operation approve-execute`, `operation status`, `operation result`, and
`operation recover`. `operation verify` is a read-only compatibility alias for
`operation result`. A zero exit status is not accounting-success evidence;
success additionally requires a terminal result, passing verification, signed
Odoo evidence, and the durable final audit receipt.

## Isolated effect-finalizer runtime configuration schema v2

The dedicated finalizer accepts one fixed root-managed document at
`/etc/odoo-accounting-cli-v3/effect-finalizer-runtime.json`. The service gets
that path only through its immutable `ExecStart`; the broker and Odoo write
child receive neither this document nor the finalizer HMAC, pgpass, or database
LOGIN. The document contains secret paths, never secret values.

The following is a rendering template, deliberately not valid JSON until every
angle-bracket token is replaced from independently verified host evidence.
Numeric UID/GID tokens must become JSON integers, not quoted strings:

```jsonc
{
  "schema_version": 2,
  "service_uid": <FINALIZER_NUMERIC_UID>,
  "service_gid": <FINALIZER_NUMERIC_GID>,
  "database_name": "<SANDBOX_DATABASE_NAME>",
  "database_uuid": "<CANONICAL_DATABASE_UUID>",
  "database_user": "<DIRECT_FINALIZER_LOGIN>",
  "database_host": "/var/run/postgresql",
  "database_port": 5432,
  "database_connect_timeout_seconds": 2,
  "dependency_manifest_path": "/etc/odoo-accounting-cli-v3/effect-finalizer-runtime-manifest.json",
  "dependency_manifest_sha256": "<EXTERNALLY_REVIEWED_64_LOWERCASE_HEX>",
  "pgpass_path": "/etc/odoo-accounting-cli-v3/effect-finalizer/finalizer.pgpass",
  "attestation_key_id": "<FINALIZER_KEY_ID>",
  "expected_guard_installation_id": "<CANONICAL_GUARD_INSTALLATION_UUID>",
  "expected_database_oid": <POSITIVE_DATABASE_OID>,
  "attestation_secret_path": "/etc/odoo-accounting-cli-v3/effect-finalizer/attestation.hmac",
  "journal_path": "/var/lib/odoo-accounting-cli-v3-effect-finalizer/attempts.sqlite3",
  "proof_ttl_seconds": 120,
  "statement_timeout_ms": 5000,
  "uds": {
    "socket_path": "/run/odoo-accounting-cli-v3/effect-finalizer.sock",
    "socket_owner_uid": 0,
    "socket_group_gid": <BROKER_GROUP_NUMERIC_GID>,
    "socket_mode": 432,
    "broker_service_uid": <BROKER_NUMERIC_UID>,
    "broker_systemd_unit": "odoo-accounting-cli-v3-broker.service",
    "finalizer_systemd_unit": "odoo-accounting-cli-v3-effect-finalizer.service",
    "handoff_idle_timeout_seconds": 115,
    "request_io_timeout_seconds": 10,
    "max_request_bytes": 16384,
    "max_response_bytes": 32768,
    "max_inflight_requests": 4
  }
}
```

The object and nested `uds` object reject missing or extra fields. Schema v1 is
not migrated or accepted: replace it atomically with an independently reviewed
schema-v2 document before starting this release. The service
UID/GID must be the dedicated non-root finalizer identity and must differ from
the broker. The socket is root-owned, group-owned by the broker client group,
and mode decimal `432` (octal `0660`). The configured broker UID and systemd
unit are both checked against the connecting peer; group membership alone is
insufficient.

Only `/run/postgresql` and `/var/run/postgresql` are accepted database hosts.
Remote TCP is not a fallback. The pgpass must be a mode-`0400` or `0600`
single regular file with exactly one non-wildcard row bound to the configured
socket directory, port, database, and direct LOGIN. The finalizer validates
that row during credential preflight and securely rereads it when opening each
direct connection. It passes only the in-process password to libpq, explicitly
sets `connect_timeout`, and clears all inherited `PG*` selectors around
connection establishment. Its endpoint and LOGIN are constructed only from the
strict schema-v2 database fields plus that row; the finalizer neither reads an
Odoo configuration nor imports Odoo. The HMAC and pgpass paths/inodes must be
distinct.

The separate, secret-free external dependency manifest is fixed at
`/etc/odoo-accounting-cli-v3/effect-finalizer-runtime-manifest.json`. Its fixed
path and the SHA-256 of its exact canonical JSON bytes are mandatory schema-v2
fields, but the manifest contents cannot alter database identity or
credentials. `dependency_manifest_sha256` must equal both the independently
reviewed digest and the digest embedded in the rendered systemd service.

The systemd `ExecStartPre` from the same immutable release first invokes
`deployment/dev27/finalizer_runtime_gate.py`. The finalizer process then
independently imports and retains the root-managed `psycopg2` connector under
isolated `/usr/bin/python3`, reruns that exact gate with the schema-v2 digest,
and checks the loaded driver paths and version against the manifest. Only after
those checks pass does it preflight the one-entry pgpass and read the HMAC. The
manifest records the loaded Python module files, psycopg2 files, `sys.path`
directories/files/missing entries, `.pth` files, and file-backed native mappings
observed after importing the exact release finalizer and driver; do not describe
it as proof of unobserved Python imports or future lazy-loaded dependencies.
Follow `deployment/dev27/README.md`;
manifest drift is a startup rejection, not permission to regenerate evidence.

The attempt budget is
`database_connect_timeout_seconds * 1000 + statement_timeout_ms + 1000`; it
must be strictly less than `request_io_timeout_seconds * 1000`, and the proof
TTL must exceed the complete attempt budget. Equality fails closed. The
journal parent is the finalizer-owned mode-`0700` systemd `StateDirectory`; the
database and its WAL/SHM files are mode `0600`. Preserve it with the PostgreSQL
effect ledger across restart, upgrade, rollback, and response-loss recovery.
Deployment ownership, systemd activation, dependency, upgrade, and rollback
gates are in `deployment/dev23/README.md`.

## Pi authenticated-session and broker boundary

The Pi service does not derive accounting identity from a conversation ID or
model parameter. Deploy the independent Dev11 sidecar described in
`deployment/dev11/README.md`; do not retrofit the V2 service. Its root-only
environment file supplies model/provider credentials and only the digest of
the independently authenticated session adapter:

```text
PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256=<lowercase-sha256-of-exact-module>
```

The rendered unit fixes the canonical Node, bootstrap and runtime paths in
`ExecStart`. Bootstrap derives/overwrites the V3 binary, manifest, broker
socket, resolver path, loopback host, sidecar port, service HOME, session and
agent directories, and `PI_BRIDGE_REQUIRE_V3_IDENTITY=1`. Do not place those
reserved fields in the environment file; environment values cannot select a
different boundary.

`PI_BRIDGE_REQUIRE_V3_IDENTITY=1` requires more than a successful CLI identity
response. The service must invoke a fixed, canonical, root-owned Node binary
with `/opt/odoo-accounting-cli-v3/releases/<release>/pi_bridge/bootstrap.mjs`;
invoking the runtime copy of `server.mjs` directly is forbidden. The bootstrap
derives `RELEASE-MANIFEST.json` from its own exact release, checks the complete
release and canonical package against the root-managed external anchor. It
then requires the independent `<release>.pi-runtime.json` anchor and verifies
the exact Node SHA-256/path/version/platform/architecture plus every regular
file and in-tree symlink in `node_modules`. Finally it binds the executing
`pi_bridge` server, extensions, session boundary, resolver, verifier,
`package.json`, and lockfile bytes to their entries in that same release
manifest.
Linux production requires canonical, non-symlink, single-link, root-owned,
non-group/world-writable files and root-managed ancestors. Only after that gate
does the parent inject `ODOO_ACCOUNTING_CLI_V3_RELEASE_MANIFEST` and the release
and registry digests into the Pi child. Operators and HTTP callers must not
supply or override that derived manifest path. The extension independently
repeats the binding before registering any V3 tool. In the hardened Dev11
sidecar, a binding failure exposes no legacy V2 tool and prevents V3
execution-tool registration; V2 remains available only through its separate
retained service.

The Node interpreter path itself must be canonical, root-owned, below
root-managed non-writable ancestors, and byte-for-byte equal to the external
runtime anchor; an NVM/user-owned binary or a symlink to one is not admissible.
The release's minimum Node engine must also pass. The unit clears and bootstrap
rejects `NODE_OPTIONS`, `NODE_PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, and
`LD_AUDIT`. The Pi child additionally uses `--no-extensions` while scrubbing
Node, dynamic-loader, Jiti, and ts-node injection variables.

The resolver is a dependency-free single-file ESM adapter with exactly one
default or `resolveAuthenticatedSession` export. On Linux the bridge requires
the module and all ancestors to be canonical, non-symlink, root-owned, and not
group/world writable. It opens with `O_NOFOLLOW`, compares `lstat`/`fstat`
identity and size/timestamps before and after the bounded read, verifies the
configured SHA-256, and imports those exact bytes from a data URL. A missing or
changed digest, dependency import, extra export, unsafe ancestor, or non-Linux
root-owned configuration prevents the bridge from starting.

Only the resulting opaque broker session handle crosses into the Pi child, on
inherited file descriptor 3. The resolver module path and hash are removed from
the child environment. Pi sends business-only JSON over the fixed local UDS
routes; the UDS validates Linux peer credentials, action/protocol headers, and
the current release headers. The trusted broker, not Pi, selects any retained
historical release and returns the verified executed release/registry identity.
None of these settings enables a registry capability.

Dev266 installs the file-descriptor error, finish, and close observers before
writing FD3 and awaits the write outcome before accepting child stdout or final
evidence. A reset, premature close, or synchronous write failure is normalized
to `broker_session_write_failed`; the hardened path terminates the child and
fails closed without exposing the handle or raw pipe error. This proves the
parent-side write outcome, not child consumption. The child must still read and
use the handle successfully through the authenticated broker protocol.

## Broker response verification and attempt audit

Every current or retained route has its own
`ReleaseReceiptVerificationConfig`: exact release digest, registry digest,
capability channel, read-receipt Key ID/secret, and write-receipt Key ID/secret.
The root composition resolves this configuration by the selected release and
registry pair with no current-key fallback. Read responses are checked with the
real read-receipt HMAC over the complete request, result, runtime, user,
company, database, channel, release, and record count. Terminal write responses
are checked with the real write-audit-receipt HMAC over the durable Operation,
approval, audit head, result, tenant, runtime, and route. A digest-looking
string is not verification evidence.

After independent session authentication, every business write request and
every independent approval request/decision appends one event to the dedicated
`SQLiteBrokerAuditSink`. The event contains only a canonical request digest and
trusted identity, route, operation/challenge/request IDs, result code, Odoo
effect classification, time, and available UDS peer credentials. Session
handles, HMAC secrets, and full business parameters have no storage field. The
store is a private absolute non-symlink SQLite path with STRICT schema,
append-only triggers, and a verified SHA-256 chain. If this append fails, the
broker does not report business success; an ambiguous executed request must be
retried through the same operation/idempotency identity and reconciled from
durable evidence.

The Pi-facing CLI applies the same fail-closed rule to terminal write results.
`operation.result`, `operation.verify`, and a completed
`operation.approve-execute` may report `business_succeeded:true` only when the
terminal result is completed or recovered, verification passed, the effect
finalizer receipt binds the resolved operation and database UUID, and the
result includes a complete `write_audit_receipt_v1` audit receipt with the
operation, request, user, company, environment, channel, registry, release,
result, verification-evidence, audit-head, key ID, and signature fields. A thin
receipt containing only a database UUID, or any receipt with missing or malformed
digest/identity fields, keeps `business_succeeded:false` even if the backend
returned `verification.passed:true`.

## Read receipt persistence

Since dev5, the receipt signature is reverified against the complete request,
result, runtime, registry, release, user, and company binding inside the
persistence call. Receipt consumption and the `read.verified` append, including
the complete signed receipt, commit in one SQLite transaction or both roll
back. Read-receipt protocol v2 also signs the environment and capability
channel; `production` plus `staged` is invalid. The receipt state store pins the
root-configured Key ID and a SHA-256 fingerprint of its high-entropy verifier
secret on first trusted initialization, then rejects a different per-call or
reopen key. The secret itself is never persisted. Legacy v1 events using native
v2 `read.*` or `operation.*` evidence
namespaces are rejected rather than promoted as verified evidence.

## Shared persistence and release identity

SQLite persistence schema v4 stores replay consumption, immutable prechecks,
approval protocol v3, operation protocol bindings, trusted execution and
verification evidence, terminal receipts, audit events, and recovery-operation
bindings. Opening an older supported schema performs only the code-defined
transactional migration after exact schema and integrity validation. That
mechanism alone is not a cross-release handoff protocol. An unpromoted
side-by-side candidate uses an isolated state path and must not open, truncate,
copy over, or silently migrate the live state. Once releases are admitted to
the root-managed historical router, every retained route and the trusted
prepare-idempotency resolver must use the same reviewed durable state store.
The broker resolves an exact retry there before choosing current versus
historical code, and then verifies the complete canonical request and tenant
binding. Promotion and rollback follow the matched release/state procedure in
`docs/DEPLOYMENT.md`.

The business CLI process must itself come from `release_root`, normally through
the manifest-covered `bin/odoo-accounting-cli-v3` launcher at that exact release
path. The launcher is not invoked through a `current` symlink. The launcher
shebang enters Python isolated mode; an invocation through a
non-isolated interpreter is rejected before application imports. Before
starting Odoo, V3 opens the retained canonical tar with `O_NOFOLLOW`, compares
the opened inode with the configured path, hashes that same file descriptor, and
requires the digest to match both this configuration and the external release
anchor. It then verifies the extracted release manifest and rejects a version,
source root, package, registry, or runtime identity mismatch. The separately
built wheel remains a disposable packaging/CI artifact and is not a second
production code source.
The `/opt` release hierarchy is used because every ancestor is root-managed;
the earlier `/mnt/.../odoo_accounting_agent_cli_v3` candidates remain retained
deployment evidence and are not a runtime source.

The historical dev8 staged launcher relied on mutable Odoo/Python dependencies
outside the canonical tar. Dev29 supplies a release-specific dependency image,
a separately sealed Odoo configuration, and an external manifest for the fixed
system interpreter, standard library, loader cache, and recursively derived
native dependencies. The exact image and loop inode must be mounted read-only
inside a private namespace before the runner imports Odoo, while mutable read
state remains on separate writable paths. This contract does not close the gap
until the target builds the deterministic image twice, the independent verifier
rederives the complete live dependency set, and the exact release retains a
passing composite Odoo receipt. The current target capacity and service-
continuity gates have not passed, so production promotion remains blocked.

Runtime configuration never enables a capability by itself. The registry must
contain the same environment in the selected channel. All 24 currently
registered write capabilities remain closed by default. They may move to staged
only in a dedicated sandbox after their local contract gate passes, and may
advance again only from retained capability-specific real Odoo lifecycle
evidence. Nothing in this document is evidence that such a run has occurred.
Production writes require separate explicit authorization and production-safety
review.

In particular, `acct.move.draft_cancel.v1` has no enabled or staged environment.
Its three 64-character inputs are not caller-generated secrets: the trusted
value source is the exact V3-created `account.move` record's
`odoo_cli_v3_document_binding`, `odoo_cli_v3_document_binding_v2`, and
`odoo_cli_v3_business_binding`, read under the bound user, company, ACL,
database, release, and Odoo receipt identity. Runtime configuration must not
supply defaults for any of these values. Before enabling this write in any
sandbox, `acct.move.draft_cancel_eligibility.v1` must return the exact company,
move ID, `out_invoice`/`in_invoice` type, all three bindings, and pristine-draft
eligibility. A legacy invoice/bill draft without V2 fails closed; runtime
configuration must not synthesize or backfill it. The contract is registered
for test staging only and has strict output-schema, ACL, cross-company, and Pi
parameter-transit coverage; it still lacks retained real-sandbox Odoo receipt
evidence, so the write remains disabled.
The installed-module graph proves only that the module name/version set is
stable; it is not a semantic override allowlist. Staging also requires an
explicit review of target-module overrides and a database automation inventory
proving that `action_post`/`account.move.write` has no active override, server
action, base automation, webhook, mail, or queue side effect outside the
approved move/line graph. The local exact-delta verifier cannot observe an
external call or an unrelated record created by an override, so fake-ORM tests
do not satisfy this gate and a real Odoo 19 sandbox run remains mandatory.

The Dev259 customer-invoice/vendor-bill posting and refund-draft-cancellation
slices and the Dev265 refund-post slice are also closed. The intended Pi
workflow obtains their exact parameters from the matching eligibility read:

- `acct.move.document_post_eligibility.v1` for
  `acct.invoice.customer_post.v1` and `acct.bill.vendor_post.v1`; and
- `acct.refund.draft_cancel_eligibility.v1` for
  `acct.refund.draft_cancel.v1`; and
- `acct.refund.post_reconcile_eligibility.v1` for
  `acct.refund.post_reconcile_origin.v1`.

All three reads are only `contract_tested`, staged for `test`, and have no
retained real-Odoo receipt. The four writes remain `declared`, with no staged or
enabled environment and no real-Odoo write evidence. Runtime configuration must not
default, invent, or copy any V1 document, V2 document, or business binding from
an untrusted message. The current write schemas do not include an eligibility
receipt or
receipt digest and therefore do not cryptographically chain the read to the
write. Each write precheck instead independently reconstructs and validates the
bound Odoo graph. Pi/evidence receipt correlation remains a separate
orchestration and retained-evidence requirement, not an implemented write-input
safety property.

The current customer-invoice/vendor-bill posting slice handles the observed
Odoo 19 partner-rank postcommit delta only when the target partner's relevant
`customer_rank`/`supplier_rank` is exactly `0` before `action_post` and exactly
`1` afterward. It is not a general production posting implementation for
partners with an existing rank or for unreviewed module extensions.

The Dev265 refund-post path uses a different, capability-specific control add-on
branch. `res.partner._increase_rank` remains native unless the exact refund-post
capability context is active inside the trusted process-local V3 execution
scope. The synchronous branch also requires a non-superuser executor, the exact
approved `customer_rank` or `supplier_rank`, an increment of one, and the exact
sorted selected/commercial-partner union. Runtime configuration must not inject
these context keys or make them available through RPC; the trusted write handler
derives them from the approved 31-parameter graph immediately around
`action_post`. The synchronous increment shares the posting/reconciliation
transaction, while post-commit verification permits only a later monotonic
increment by the same Odoo executor user as the operation. No real Odoo receipt
proves this boundary, so the capability remains disabled with manual-escalation
recovery.

The eligibility oracle and lower-level document-post write handler are both
restricted to complete company-currency, product-line, taxless, undiscounted
graphs with one receivable/payable maturity line. The signed candidate binds
the exact Odoo-created payment-term line and account IDs; the write precheck,
approval snapshot, and post-action verifier reject either ID drifting, including
substitution with another account of the same type. Foreign-currency, taxed,
non-product-line, discounted, or complex payment-term documents fail closed. Do not
treat this slice as general invoice/bill/refund support.

Dev260 preserves the original V1 digest as an exact approved-source binding and
adds a separate canonical V2 digest. New invoice, bill, and refund creates
write V1, V2, and business bindings together. Eligibility reconstructs V2 from
the current graph, so decimal trailing zeros, tax-ID order, and line order do
not create false mismatches; real amounts, accounts, products, text, dates,
company, partner, currency, journal, and posting mode remain bound.

V2 is mandatory for these document-posting and refund-cancellation slices.
Missing V2 on a legacy record is an explicit provenance-migration failure;
invalid or mismatched V2 is a hard rejection with no V1 fallback. For a posted
refund origin, the matching draft/post V2 candidate still proves only the
creation-time binding, not which later caller invoked `action_post`. This
release does not provide a metadata migration capability. Runtime
configuration, operators, and Pi must never backfill V2 from the current graph
alone.

The current `acct.recovery.execute.v1` contract is also disabled and is limited
to an incident whose origin is durably `failed` after one successful execution
result and one bound failed-verification result. It is not a general cancel
command and cannot act on a normally completed invoice or bill. A completed
creation receipt may retain its signed version-2 recovery plan because that
same plan is the evidence needed if verification fails; `status=available` in
that receipt alone is therefore not current execution authority. The FAILED
state, the two-result chain, a fresh approval, and the distinct recovery
operation binding are all required. Historical version-1 bindings remain
readable for frozen-route audit but are rejected by the current executor.

The local implementation registers 16 state-dependent recovery contracts for
the 12 original non-terminal source-write capabilities. This recovery-catalog
count is independent of the current registry's 24 write capabilities. The
original `acct.move.draft_cancel.v1` and `acct.recovery.execute.v1` do not add
follow-on contracts. The ten later writes also do not expand that catalog:
manual-entry creation and posting require separately approved draft-cancel or
reversal operations; `acct.move.draft_cancel.v2` is terminal; and payment
cancellation, reconciliation undo, and bank-statement compensation retain
explicit manual-escalation recovery policies. Customer-invoice and vendor-bill
posting require a separately approved credit note or reversal after posting;
refund draft cancellation is terminal; and refund post-and-reconcile requires
manual escalation. Every executable contract is
restricted to `test` and `sandbox`, has a public-ORM action and an independent
fresh-read oracle, and rejects production execution. Payment and reconciliation
results that already contain a prior partial or full reconciliation graph are
forced to `manual_escalation`; the local implementation does not claim that it
can reconstruct an arbitrary pre-existing reconciliation graph. These controls
have local Fake ORM and control-plane tests only. They do not change the empty
staged/enabled environment lists and are not real Odoo recovery evidence.

The role-separated HMAC files and SQLite controls protect protocol boundaries
against ordinary misconfiguration and out-of-protocol application writes; they
are not a hardware-backed trust boundary and do not defend against arbitrary
code running as the state-file owner. Do not describe a candidate as resistant
to same-UID database forgery. Production promotion remains blocked until the
required service-identity, external audit anchoring, Pi end-to-end, real Odoo,
and capability-specific production gates are evidenced.

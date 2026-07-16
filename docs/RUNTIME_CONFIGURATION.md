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

## Write runtime configuration schema v1

The six write-lifecycle actions use the fixed root-managed path
`/etc/odoo-accounting-cli-v3/write-runtime.json`. Pi and other callers cannot
select this path, a state database, an Odoo executable, or a key through request
parameters. The write runtime document has schema version `1`; this is separate
from the SQLite persistence schema, which is version `4`.

The following is an illustrative disabled configuration. It contains key IDs
and secret file paths only, never secret values:

```json
{
  "schema_version": 1,
  "write_execution_mode": "disabled",
  "base_runtime_config_path": "/etc/odoo-accounting-cli-v3/runtime-sandbox.json",
  "write_state_path": "/var/lib/odoo-accounting-cli-v3/sandbox/candidates/<release>/write.sqlite3",
  "write_auth": {
    "key_id": "sandbox-write-auth-2026-07",
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/write-auth.hmac"
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
    "secret_path": "/etc/odoo-accounting-cli-v3/secrets/sandbox/write-receipt.hmac"
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

The dev8 staged launcher still relies on the root-managed system Python and its
installed Click distribution. Those external dependency bytes are not yet
covered by the canonical tar identity. Target evidence must record their
resolved paths, versions, ownership, modes, and SHA-256 values. Production
promotion remains blocked until a release-scoped dependency runtime, vendored
dependency set, or an equivalent pre-import cryptographic binding removes this
identity gap.

Runtime configuration never enables a capability by itself. The registry must
contain the same environment in the selected channel. All 13 registered write
capabilities remain closed by default. They may move to staged only in a
dedicated sandbox after their local contract gate passes, and may advance again
only from retained capability-specific real Odoo lifecycle evidence. Nothing
in this document is evidence that such a run has occurred. Production writes
require separate explicit authorization and production-safety review.

The role-separated HMAC files and SQLite controls protect protocol boundaries
against ordinary misconfiguration and out-of-protocol application writes; they
are not a hardware-backed trust boundary and do not defend against arbitrary
code running as the state-file owner. Do not describe a candidate as resistant
to same-UID database forgery. Production promotion remains blocked until the
required service-identity, external audit anchoring, Pi end-to-end, real Odoo,
and capability-specific production gates are evidenced.

# V3 deployment, upgrade, and rollback runbook

This runbook deploys an immutable V3 release beside V2. It does not change an
Odoo service, Pi route, `current` link, or accounting record. Production writes
remain prohibited unless separately authorized and promoted capability by
capability.

## Release identity

Git is the only editable source of V3. A deployment is one immutable archive
identified by all of the following:

- semantic version from `VERSION`;
- full Git commit and its 12-character release suffix;
- archive SHA-256;
- `RELEASE-MANIFEST.json` SHA-256;
- capability-registry SHA-256; and
- external root-managed anchor containing the same release identity.

An extracted `/opt` directory is a verified artifact, not another source tree.
Never patch an extracted release. A change requires a new commit, version, and
archive.

## Fixed server layout

```text
/opt/odoo-accounting-cli-v3/
  packages/odoo-accounting-cli-v3-<version>-<commit12>.tar.gz
  releases/<version>-<commit12>/
  trusted-artifacts/<version>-<commit12>.json
/etc/odoo-accounting-cli-v3/
  runtime-test.json
  runtime-sandbox.json
  write-runtime.json
  secrets/test/auth.hmac
  secrets/test/receipt.hmac
  secrets/sandbox/auth.hmac
  secrets/sandbox/receipt.hmac
  secrets/sandbox/write-auth.hmac
  secrets/sandbox/approval.hmac
  secrets/sandbox/execution.hmac
  secrets/sandbox/verification.hmac
  secrets/sandbox/recovery.hmac
  secrets/sandbox/write-receipt.hmac
/var/lib/odoo-accounting-cli-v3/test/candidates/<version>-<commit12>/
  auth.sqlite3
  receipt.sqlite3
/var/lib/odoo-accounting-cli-v3/sandbox/candidates/<version>-<commit12>/
  write.sqlite3
/var/lib/odoo-accounting-cli-v3/broker-state/
  write-state.sqlite3
  trusted-sessions.sqlite3
  broker-audit.sqlite3
/var/lib/odoo-accounting-cli-v3-broker/
  # systemd-managed private broker HOME only; no accounting state is implicit
```

The V2 tree under `/mnt/odoo/odoo19/custom/tools/` and the Pi Bridge copy of V2
must be inventoried before and after deployment and must not change.

## Build gate

From a clean committed V3 checkout:

```powershell
python -m pytest
python -m pytest tests/test_release_archive.py
python tools/check_source_boundary.py
git diff --check
python tools/build_release.py
```

Build the same clean commit twice and retain both command results. The archive
SHA-256 and manifest SHA-256 must be identical. Refuse a dirty worktree,
untracked release input, version/commit mismatch, or non-deterministic output.
The archive gate must explicitly find `write_app.py`, `write_service.py`, the
Odoo write runner, and every file in the V3 control add-on; equality with an
incomplete Git file list is not sufficient.

Before transfer, record the archive name, byte size, archive SHA-256, manifest
SHA-256, registry digest, version, commit, builder, and UTC time. Transfer to a
temporary server path and recompute the archive SHA-256 on the server before
extracting it.

## Side-by-side installation

Use the installer from the exact target commit, but never execute it with root
privileges from a developer- or service-writable checkout. First copy it to a
new single-link path below a root-controlled, non-group/world-writable
directory, mode it `0444`, and compare its SHA-256 with the independently
retained `deployment/install-release.py` entry from that target release's
manifest. Abort before Python starts if this bootstrap check differs. Supply
all five release identity values from independently retained build evidence;
none is inferred as an external trust decision from the archive being
installed:

```bash
sudo install -d -o root -g root -m 0700 /root/odoo-v3-upload
sudo install -o root -g root -m 0444 \
  <exact-target-commit-checkout>/deployment/install-release.py \
  /root/odoo-v3-upload/install-release.py
test "$(sudo /usr/bin/sha256sum /root/odoo-v3-upload/install-release.py)" = \
  "<expected-installer-sha256>  /root/odoo-v3-upload/install-release.py"
sudo /usr/bin/python3 /root/odoo-v3-upload/install-release.py \
  --archive /root/odoo-v3-upload/odoo-accounting-cli-v3-<version>-<commit12>.tar.gz \
  --expected-package-sha256 <64-lowercase-hex> \
  --expected-manifest-sha256 <64-lowercase-hex> \
  --expected-version <version> \
  --expected-commit <full-40-character-lowercase-commit> \
  --expected-release <version>-<commit12>
```

Production mode has no configurable installation root: it always targets
`/opt/odoo-accounting-cli-v3` and requires root. The uploaded archive must be
an absolute-path with the canonical release filename, root-owned, root-group,
single-link regular file that is not group/world writable. The running
installer must also be single-link, root-owned, non-group/world-writable,
located under a fully root-controlled physical ancestor chain, and byte-equal
to its entry in the target manifest. The installer takes an exclusive root-owned lock,
creates package, release, and anchor staging objects inside their respective
final directories, and refuses links, unsafe tar paths/types, duplicate
members, non-root archive ownership, unexpected build modes, incomplete
manifests, or any identity mismatch. It publishes the package and external
anchor with exclusive hard-link creation and the release with Linux
`renameat2(RENAME_NOREPLACE)`. The three executable release members are frozen
mode `0555`; every other release file is `0444`, every release directory is
`0555`, and all production objects are root-owned.

The extracted `tools/verify_release.py` and the frozen broker launcher's exact
`--help` probe run with bytecode disabled against the sealed tree. In
production both run after dropping to the unprivileged `nobody` identity, with
bounded memory, CPU time, output size, file descriptors, wall time, and a
killable private process group. A before/after byte-and-metadata inventory must
remain identical.
The external anchor is published last and contains exactly `commit`,
`manifest_sha256`, `package_sha256`, and `release`. A second invocation is a
success only when the complete installed package, release, and anchor verify
exactly; a partial or changed existing installation is rejected without
repair. On failure the installer removes only staging paths bearing its own
random transaction identity and inode. It never removes an existing or already
published object.

Before Python's tar reader is entered, a constant-memory raw gzip/tar preflight
bounds raw header count, regular and manifest declarations, and PAX/GNU
extension data. It accepts exactly one gzip member and a standard two-block tar
terminator. Extension padding must be zero and a consecutive extension chain
is limited to two headers, preventing hidden PAX fields and recursive parser
exhaustion. One extension is capped at 64 KiB and all extensions at 16 MiB;
oversized extension payloads are rejected from their header without being
materialized. Sparse metadata is rejected again after logical tar parsing. The
archive is capped at 10,000 logical members and 512 MiB compressed. Its
manifest-listed regular content is capped at 512 MiB, with a 64 MiB per-file
ceiling; `RELEASE-MANIFEST.json` has a separate 16 MiB ceiling. Before package
copy and again before extraction, the installer requires the relevant target
filesystem to retain at least 2 GiB free after the next allocation. After all
three staging objects are complete, it rechecks that floor once on every
distinct filesystem actually backing the package hardlink, release rename,
and anchor hardlink. This final check reserves four filesystem blocks per
pending publication object. These are refusal limits, not sizing
recommendations.

`--test-mode --root-prefix ABSOLUTE_PRIVATE_DIRECTORY` exists only for the
non-root automated installer tests. Both flags are required together, root
execution and `/` are forbidden, and that mode must never be used as an
operational deployment override.

The installer only side-loads immutable artifacts. It does not create or
change `current`, runtime configuration, state, secrets, systemd units, Pi
Bridge files/routes, Odoo add-ons/configuration, or any service; it never
starts, stops, reloads, or restarts a process. A successfully side-loaded
release remains unrouted.

The numbered controls below are the installer's required verification and
publication contract, not permission to replace it with ad hoc extraction.

1. Copy the verified archive to a new root-owned, mode `0444` canonical path
   under `packages/`. Refuse links, an existing destination, a filename that
   does not match the release, or any digest mismatch.
2. Create a root-owned temporary directory below
   `/opt/odoo-accounting-cli-v3/releases/` on the same filesystem.
3. Extract exactly one verified archive there. Reject absolute paths, `..`,
   links, devices, sockets, unexpected owners, and extra files.
4. With bytecode disabled, verify the extracted source-layout release using
   the exact candidate import path and expected manifest digest:

   ```bash
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$candidate/src" \
     /usr/bin/python3 -B "$candidate/tools/verify_release.py" \
     "$candidate" "$manifest_sha256"
   ```

   Verification must not create files in the candidate.
5. Make the entire candidate root-owned: directories mode `0555`, ordinary
   files mode `0444`, both canonical launchers
   `bin/odoo-accounting-cli-v3` and
   `bin/odoo-accounting-cli-v3-broker`, and the target-Linux mount guard
   `deployment/dev9/run-private-mount-gate.sh` mode `0555`. Refuse the candidate
   if either launcher or the mount guard is missing, linked, writable, or not
   executable. Exercise
   the broker from the frozen extracted tree before publishing it. Here
   `$temporary_evidence` is a new root-owned mode `0700` directory outside the
   candidate release:

   ```bash
   PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
     "$candidate/bin/odoo-accounting-cli-v3-broker" --help \
     >"$temporary_evidence/broker-help.stdout" \
     2>"$temporary_evidence/broker-help.stderr"
   test ! -s "$temporary_evidence/broker-help.stderr"
   grep -Fx \
     'usage: odoo-accounting-cli-v3-broker --config ABSOLUTE_PATH' \
     "$temporary_evidence/broker-help.stdout"
   ```

   The final release directory must be immutable to the Odoo and broker
   service identities.
6. Atomically rename the completed temporary directory to
   `<version>-<commit12>`. Refuse to overwrite an existing release.
7. Create the matching external anchor under `trusted-artifacts/` as a
   root-owned, non-group/world-writable JSON file with exactly `commit`,
   `manifest_sha256`, `package_sha256`, and `release`.
8. From that exact anchored release, run
   `deployment/dev9/render-systemd-service.py` as documented in
   `deployment/dev9/README.md`. The renderer independently rejects a release
   unless both canonical launchers remain regular non-symlink files with mode
   `0555`; install only its verified service output.
9. For the dedicated sandbox only, add the exact immutable release's
   `odoo_addons/` directory to that sandbox process's add-ons path and install
   `odoo_accounting_cli_v3_control` from it. Do not copy the add-on into V2, Pi
   Bridge, a development directory, or a shared production add-ons tree. A
   production Odoo configuration change requires separate authorization.

Do not extract into the V2 directory, Pi Bridge, Odoo add-ons, a developer home,
or the historical `/mnt/.../odoo_accounting_agent_cli_v3` evidence root.

## Runtime configuration and state

Create the strict root-managed read and write runtime files described in
`docs/RUNTIME_CONFIGURATION.md`. Pin the canonical package path and digest as
well as the SHA-256 of the resolved Odoo Python interpreter, `odoo-bin`, and
Odoo configuration. The fixed write path is
`/etc/odoo-accounting-cli-v3/write-runtime.json`; callers cannot override it.

The write runtime configuration schema is version 1. Its
`write_execution_mode` starts as `disabled`. A sandbox candidate may use
`sandbox_staged` only when its base runtime is both environment `sandbox` and
channel `staged`. Mode `enabled` requires an enabled base-runtime channel but
does not override registry availability or production authorization.

Generate eight independent secrets without printing them: the two read roles
plus write-authentication, approval, execution, verification, recovery, and
write-receipt roles. Every role uses a distinct Key ID, canonical path, and
file inode; execution, verification, and recovery also use distinct issuer
names. Store the files root-owned, normally mode `0640`, readable only by the
dedicated service group. Record only Key IDs and restricted file hashes in
operator evidence. Never record secret contents or pass a signed write request
on argv.

The existing `/var/lib/odoo-accounting-cli-v3` root retains safe root-managed
ownership and is never a systemd `StateDirectory`. The broker unit uses the
non-overlapping sibling `/var/lib/odoo-accounting-cli-v3-broker` as its private
mode-`0700` HOME and grants a mount-namespace write exception to the historical
root without changing its ownership. Create only each exact runtime-configured
store parent service-owned mode `0700`. SQLite
database, WAL, and shared-memory files remain service-owned mode `0600`. The
write state path must differ by path and inode from both read stores. Preserve
every store through upgrade and rollback; never delete, truncate, replace, or
create a fresh store merely to make a replayed request or idempotency key
succeed.

SQLite persistence schema v4 contains operation and idempotency records,
immutable prechecks, approvals, trusted results, terminal receipts, audit
events, and recovery bindings. Its code-defined legacy migrations are
transactional and validate the exact old schema and integrity first. They do
not themselves constitute a cross-release operation or idempotency migration
protocol. Before admission to the retained-release router, a side-by-side
candidate therefore uses an isolated state path and must not open the live
store. Admission is a separate reviewed change that pins all retained runtime
configurations and the broker's idempotency resolver to one shared store.

Before any write-capable upgrade or route change:

1. Stop accepting new prepare requests and general Pi write traffic. Keep only
   authenticated status/result and the explicitly controlled old-release calls
   needed to reconcile ambiguous in-flight effects.
2. Stop all unrelated writers, workers, canaries, and operator commands for
   that state store.
3. With the old verified release, reconcile every ambiguous `executing`,
   `verifying`, or `recovering` effect through its existing Odoo control anchor
   and result path; never submit it as a new operation. Other nonterminal
   operations may remain only if the old immutable route, keys, and verifier
   will stay available.
4. Checkpoint and back up the SQLite database with a SQLite-supported backup or
   an atomic storage snapshot covering its WAL state. Verify the backup hashes,
   `PRAGMA integrity_check`, schema version, audit chain, and terminal receipts.
5. Install the new root-managed manifest with both old and new immutable routes.
   Verify both runtime configurations reference the same canonical state path
   and inode. Retain the old release directory, canonical package, external
   anchor, runtime configuration, verification keys, and evidence.
6. Before reopening traffic, prove an old-release prepare whose response was
   lost resolves to its original operation/request IDs after the new release is
   current, and that changed content, cross-tenant input, and a missing retained
   route fail closed without an Odoo effect.
7. Reopen prepares only after the broker, router, verifier, and audit checks all
   pass. The operation's stored release remains authoritative for every
   continuation and result.

The broker service also requires a separate private audit database. Before
traffic, verify its parent ownership/mode, database and WAL/SHM ownership/mode,
exact schema, append-only triggers, SQLite integrity, and audit-chain head.
Load each retained route's read/write receipt Key IDs and secrets from distinct
root-managed files; do not reuse the current key for a historical route. Test a
fake 64-character signature, wrong Key ID, wrong secret, changed company,
changed operation, changed result, and deleted historical verifier route. Every
case must fail without a reported business success and must leave a broker
attempt event after session authentication.

The Dev9 broker contract resolves a prepare retry from the one shared durable
store before release routing, reuses the original operation and request IDs,
and independently checks its full canonical request and tenant binding. A
promoted retained route must therefore never receive a new empty or separate
schema-v4 database: that would forget prior idempotency scopes and could
duplicate an accounting effect. Promotion remains blocked until target Linux
tests prove the shared store, current-to-historical switch, operation,
approval, receipt, audit, and idempotency continuity with the immutable release
launcher. A plain copy of a live database followed by separate copies of
`-wal` or `-shm` is not acceptable evidence.

SQLite constraints and append-only triggers are application-integrity controls,
not protection against arbitrary code running as the state-file owner.
Production promotion still requires the separate service-identity and external
audit-anchor gates.

All trusted authority and session SQLite stores in one service process share a
single lifecycle gate. Do not fork after a trusted connection has opened, and
do not run a pre-fork worker that lets children inherit those connections or
writer-lock descriptors. A Python-managed `os.fork` child created during an
active or poisoned lifecycle is terminated by the V3 at-fork hook with exit
status `70`, before it returns to the fork caller or runs normal Python
cleanup, close/rollback SQLite, writer-lock release, or exec. Prohibit native
fork paths that bypass `os.register_at_fork`; any third-party child hook that
runs earlier must not touch trusted-store connections or descriptors. If logs
report exit `70` or a poisoned SQLite lifecycle,
unconfirmed connection close, known-committed cleanup failure, or unknown
commit outcome, stop new approval/write traffic, preserve the database and
sidecars, reconcile the request/audit/record identity, and restart with a fresh
process. Never replay the request merely to test whether the first commit
landed, and never clear the condition by deleting a database or lock file.

## Test-only candidate verification

Run all checks as the non-root Odoo service user with bytecode and pytest cache
disabled:

```text
release identity -> Linux runner gate -> one signed trial-balance read
-> exact replay rejection -> fresh-token repeat -> ACL deny -> company deny
-> wrong database UUID deny -> audit-chain verification
```

Set `ODOO_CLI_V3_LINUX_GATE=1` only for the target Linux runner test. Its gate
must prove sealed memfd transport, fixed environment, bounded stdout/stderr,
process-group timeout cleanup, and that output limits do not restrict unrelated
state files. The real accounting read must run against the documented test
database, company, and non-superuser. No write command is permitted.

Success requires the complete CLI JSON result, valid signed Odoo receipt,
release/runtime identity, financial-oracle comparison, state/audit evidence,
and negative-test results. A command exit code alone is not evidence.

## Dedicated write-sandbox candidate verification

All 13 registered write capabilities are closed by default. Local contracts,
handlers, and tests do not authorize staging. After the complete local gate,
create a new reviewed release that stages only the selected capabilities for a
dedicated sandbox. The sandbox must have its own database UUID, filestore,
database filter, disabled scheduled jobs, non-superuser executor, separately
authorized approver, and isolated write state. Do not reuse a production clone
whose UUID, filestore, cron workers, or live connections are shared.

Before any provisioning action, run the exact immutable release member
`deployment/dev18/sandbox_capacity_gate.py` as specified in
`deployment/dev18/README.md`. Its reviewed policy is externally SHA-256-bound,
is a root-owned immutable-path artifact, pins the collector plus PostgreSQL
executables, systemd service/process/data directory/listener/cluster, complete
database catalog, complete PostgreSQL configuration and socket/NSS closure,
SQL session/current-user authority, live backend-to-postmaster identity, every
protected Odoo UUID relation identity, and reviewed mountinfo identities.
The configuration closure binds one server-side aggregate role-password-vector
digest without returning individual verifiers, `pg_conf_load_time()`, effective
and file settings, HBA/ident rules, role/database defaults, include roots,
`postgresql.auto.conf`, and TLS/authentication assets. It rejects stale
unloaded files, unsupported external authentication, every non-empty preload
source, ambiguous postmaster arguments, and dynamic-loader environment
injection before accepting SQL evidence. The reviewed Unix-socket directory
must be owner-only writable; a policy-bound member hash never authorizes a
group- or world-writable listener path.
Protected UUID reads use one live-attested, locked, read-only, repeatable-read
transaction: a `pg_catalog`-only
structure and reviewed-digest assertion must pass before the explicitly
qualified `public.ir_config_parameter` query can execute. The root-only Linux
program requires the host PID 1 mount namespace and captures fresh device,
database, host, capture-window, and protected-resource observations itself.
Protected directory trees have no entry truncation and bind each physical
ancestor's path/inode/device/mode/owner identity plus all descendant
content/metadata/counts/mounts. Unrelated sibling entry churn is not an
ancestor routing change. Intermediate symlink routing is rejected and each
present object's device must match its selected mountinfo row. Expected absence
binds its physical ancestor chain and covering mount with a non-null digest.
Caller-supplied observations and clock overrides are rejected. The gate aggregates PostgreSQL,
filestore, runtime/evidence, backup, and reserve bytes and inodes by actual
filesystem device, requires the proposed database to remain absent, and fails
on protected database name/UUID/relation, V2, Pi, or `current` drift. Exit `0`
means only that the
host is eligible for a separate sandbox-provisioning review. The tool always
reports provisioning, sandbox accounting write, and production accounting
write authorization as false.

Capacity acceptance is Gate E00a, not sandbox qualification. Gate E00b must
subsequently prove an independent PostgreSQL cluster and restricted role,
database UUID, Odoo service/OS user, exact database filter, data directory and
filestore, disabled cron/mail/external integrations, outbound network denial,
non-superuser executor, independent approver, isolated V3 state, tested
backup/reset, and inability to reach any production database/configuration/
filestore/mutable add-on path. Until E00b has immutable real-host evidence,
`write_execution_mode` stays `disabled` and no registry write capability is
staged. Neither capacity gate may create the objects it evaluates.

The initial target-host capacity blocker, database/UUID inventory, and
unchanged V2/Pi/current evidence are retained in
`docs/TARGET_HOST_CAPACITY_AUDIT_2026-07-17.md`. It is an independent read-only
baseline, not a substituted or backdated Dev18 collector receipt.
The real PostgreSQL 16.14/Odoo 19 syntax and locked-relation development probe
is separately recorded in
`docs/TARGET_HOST_DEV18_SQL_PROBE_2026-07-17.md`; it is also not an immutable
capacity receipt and does not alter the host-capacity blocker.
That probe also records the target's mode-`2775` `/run/postgresql` socket
directory. The current Dev18 collector rejects that mode before SQL; a
persistent owner-only-writable remediation and a fresh immutable-release
capture require separate review and authorization.

Invoke the six standard actions only through the immutable release launcher:
prepare, preview, approve-execute, status, result, and recover. Send each signed
JSON request over standard input. For every staged write capability retain:

- exact parameter round-trip evidence from Pi/CLI input through preview,
  approval digest, Odoo execution, verification, and receipt;
- one intended Odoo effect under the bound user and company;
- repeated and concurrent requests proving no duplicate effect;
- ACL, company, expiry, replay, and tamper rejection;
- a pre-effect failure and an ambiguous response-loss reconciliation; and
- its registered reversal or compensation journey when recovery is available.

No command-existence, mocked handler, local test, exit code, or unsigned Odoo
record is sandbox evidence. Without a release-bound passing verification and
durable signed final receipt, the capability remains closed. Passing one
capability does not stage or enable another, and no sandbox result authorizes a
production write.

## Promotion and Pi routing

A staged capability is deliberately not enabled and is invisible to the normal
Pi channel. After exact-release evidence passes, create a new reviewed release
whose registry references the retained evidence and moves only that capability
and environment from `staged_environments` to `enabled_environments`. Verify Pi
uses the same version, release manifest, and registry digest before any canary
route is changed.

Never patch registry metadata inside an existing release. Enabling one read
does not enable another read or any write.
Before exposing authenticated V3 tools, pin the independently reviewed,
dependency-free session-resolver module with
`PI_BRIDGE_AUTHENTICATED_SESSION_RESOLVER_SHA256`, require the verified V3
identity, and install the executing Pi Bridge runtime files byte-for-byte from
that exact release. Follow `deployment/dev11/README.md` to run
`npm ci --ignore-scripts --omit=dev` in a new root-owned staging runtime and
create the one external Pi runtime anchor. Bootstrap must match every tracked
Bridge member to the release manifest and match the exact Node executable plus
the complete installed dependency file/symlink set to that external runtime
anchor. All paths are canonical, single-link where regular, root-owned, and
non-writable by the Pi identity. Render the independent Dev11 unit so its fixed
`/usr/bin/node` executes the canonical release's `pi_bridge/bootstrap.mjs`
with the separate runtime path as its only argument; never execute copied
`server.mjs` directly or modify `sudo-pi-agent-bridge.service`. Clear
`NODE_OPTIONS`, `NODE_PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, and `LD_AUDIT`,
and reject an NVM/user-owned or digest-mismatched Node binary. Prove health
reports the same version, commit, release manifest, Node and runtime-manifest
digests as the CLI/anchors, and prove changing any one Node, dependency or
Bridge runtime file removes every V3 tool. Prove Pi is
started with `--no-extensions` and only the explicit release-bound extension,
so global/project extension discovery cannot shadow a V3 tool name. Also prove
the hardened sidecar's tool allowlist contains no V2 tool and its child
environment contains no `ODOO_TOOL_*` value (the separate retained V2 service
is the only legacy route). Prove
the root-managed session resolver path plus every ancestor cannot be replaced
by the Pi service identity, the Pi process receives only the opaque session
handle on inherited descriptor 3, the resolver path/hash are absent from its environment, and an
unsafe path, changed module, missing hash, wrong UDS peer, mismatched
action/protocol, or caller-selected release is rejected before execution.
For a write capability, the reviewed promotion input must include its dedicated
sandbox create/verify/repeat/failure/recovery receipts and negative-security
evidence. Until then its `enabled_environments` remains empty. Production also
requires explicit capability-specific authorization and a new production-safety
review; sandbox evidence alone is insufficient.

## Upgrade

Install the new release in a new immutable directory and repeat every identity,
Linux, Odoo, ACL, replay, financial, and Pi canary gate. Preserve the prior
release, external anchor, state databases, and evidence. Change routing only
after the new release passes; do not restart Odoo merely to install an
unrouted V3 artifact.

For any route that could mutate write state, perform the drain, reconciliation,
SQLite backup, and continuity checks in "Runtime configuration and state"
before changing the route. The seven nonterminal states are `prepared`,
`prechecked`, `awaiting_approval`, `approved`, `executing`, `verifying`, and
`recovering`; all must be empty. Keep status/result requests for old operation
IDs on their old release and state store. Do not point a new release at an old
store or a new empty store until a release-specific schema-v4 and idempotency
handoff has passed. If that handoff is unavailable, the write route cannot be
upgraded.

## Rollback

Rollback changes only the explicitly controlled V3/Pi route to a previously
verified immutable release. It must not modify V2, delete V3 state, or attempt
to undo accounting records. Confirm the selected release's anchor and manifest,
run its identity/read canary, atomically change the route, and verify Pi and CLI
again report the same identity.

Before changing a route, verify the selected binary supports the current state
schema. Write persistence is currently schema v4, while the write runtime
configuration document is schema v1. Restore a pre-upgrade state snapshot only
as part of a coordinated rollback with all traffic stopped and only with the
exact release, configuration fingerprint, Key IDs, and verified snapshot that
belong together. Preserve the rejected/newer state as evidence; never merge
divergent state files or idempotency tables by hand.

Retain the newer release and store until every operation and audit receipt is
reconciled. If either release has a nonterminal operation, keep it routed to the
release that created it; a binary rollback is not permission to replay it under
another operation ID. If the matched state cannot be restored and verified,
leave write routing disabled and escalate instead of creating an empty store.

If a write release is ever promoted, accounting effects are recovered only by
the capability's recorded Odoo reversal or compensation workflow. Deploying an
older binary is not an accounting rollback.

## Retained evidence

For every build, install, upgrade, promotion, and rollback retain a root-owned
read-only evidence bundle containing command/test reports, hashes, ownership
and mode inventory, V2 before/after hash, runtime/database/user/company
identity, request/result digests, receipt and audit IDs, UTC timestamps, and the
explicit promotion decision. Exclude secrets and raw credentials.

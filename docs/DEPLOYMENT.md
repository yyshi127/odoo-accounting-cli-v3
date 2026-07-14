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
  releases/<version>-<commit12>/
  trusted-artifacts/<version>-<commit12>.json
/etc/odoo-accounting-cli-v3/
  runtime-test.json
  secrets/test/auth.hmac
  secrets/test/receipt.hmac
/var/lib/odoo-accounting-cli-v3/test/candidates/<version>-<commit12>/
  auth.sqlite3
  receipt.sqlite3
```

The V2 tree under `/mnt/odoo/odoo19/custom/tools/` and the Pi Bridge copy of V2
must be inventoried before and after deployment and must not change.

## Build gate

From a clean committed V3 checkout:

```powershell
python -m pytest
python tools/check_source_boundary.py
git diff --check
python tools/build_release.py
```

Build the same clean commit twice and retain both command results. The archive
SHA-256 and manifest SHA-256 must be identical. Refuse a dirty worktree,
untracked release input, version/commit mismatch, or non-deterministic output.

Before transfer, record the archive name, byte size, archive SHA-256, manifest
SHA-256, registry digest, version, commit, builder, and UTC time. Transfer to a
temporary server path and recompute the archive SHA-256 on the server before
extracting it.

## Side-by-side installation

1. Create a root-owned temporary directory below
   `/opt/odoo-accounting-cli-v3/releases/` on the same filesystem.
2. Extract exactly one verified archive there. Reject absolute paths, `..`,
   links, devices, sockets, unexpected owners, and extra files.
3. With bytecode disabled (`PYTHONDONTWRITEBYTECODE=1` and Python `-B`), run
   `tools/verify_release.py` against the extracted tree and the expected
   manifest digest. Verification must not create files in the candidate.
4. Make the entire candidate root-owned and non-writable by group/world. The
   final release directory itself must be root-owned and immutable to the Odoo
   service identity.
5. Atomically rename the completed temporary directory to
   `<version>-<commit12>`. Refuse to overwrite an existing release.
6. Create the matching external anchor under `trusted-artifacts/` as a
   root-owned, non-group/world-writable JSON file with exactly `commit`,
   `manifest_sha256`, `package_sha256`, and `release`.

Do not extract into the V2 directory, Pi Bridge, Odoo add-ons, a developer home,
or the historical `/mnt/.../odoo_accounting_agent_cli_v3` evidence root.

## Runtime configuration and state

Create the strict root-managed runtime file described in
`docs/RUNTIME_CONFIGURATION.md`. Pin the SHA-256 of the resolved Odoo Python
interpreter, `odoo-bin`, and Odoo configuration. Use `capability_channel` equal
to `staged` only for the isolated test evidence run; production rejects that
channel.

Generate two independent random secrets without printing them. Store them as
separate root-owned files, normally mode `0640`, readable only by the dedicated
service group. Record only their Key IDs and file hashes in restricted operator
evidence; never record key contents.

Create the test state directory as service-owned mode `0700`. SQLite database,
WAL, and shared-memory files must remain mode `0600`. State must be preserved
through upgrade and rollback with an explicitly compatible schema or matched
snapshot; never delete it to make a replayed request succeed.

Schema v2 adds append-only approval evidence and database-enforced approval
transitions. Opening a schema-v1 state database with a v2 release performs a
strict, transactional migration only after the exact v1 schema, operation
record hashes, foreign keys, and audit chain verify. The migration preserves
all existing operation and audit bytes, but it is forward-only for older
binaries: a v1-only release cannot open the resulting database.
Legacy events that use native v2 `read.*` or `operation.*` evidence identities
are rejected; they cannot be silently promoted into verified v2 evidence.
Only pre-execution states and a legacy `approved` state are migratable. A
legacy approval is marked unverifiable and may be inspected but cannot
authorize execution. Legacy executing, failed, verification, completion, or
recovery states have no dev5-grade durable evidence and make the whole
migration roll back without changing schema v1.

For native schema-v2 reads (dev5 and later), signature revalidation, replay consumption, and the
`read.verified` event containing the complete signed receipt commit in one
transaction. Absence of that durable event is a failed read, never business
success. Receipt protocol v2 binds environment and capability channel and
forbids a staged production receipt. Initialize the version-scoped receipt
store only through its root-managed runtime configuration so its Key ID and
secret fingerprint are pinned before reads; a key mismatch is an integrity
failure, not an automatic rotation.

These SQLite controls are an application integrity boundary, not a defense
against arbitrary code running as the state-file owner. A same-UID attacker can
replace local schema objects and recompute unkeyed hashes. Production promotion
therefore remains blocked until runtime identities are isolated and the audit
head is independently anchored; trigger presence alone is not promotion
evidence.

For side-by-side candidate verification, point each candidate at new version-scoped state
paths under `candidates/<version>-<commit12>/` so the retained dev4 databases
remain unchanged. For a promoted v1-to-v2 upgrade, first stop and drain every
V3 route, worker, scheduled job, canary, and operator command that can access
the affected state stores. Keep that traffic stopped throughout the SQLite
checkpoint, creation and verification of a consistent v1 snapshot, the first
v2 open and migration, and the post-migration integrity verification.

Create the rollback snapshot with a SQLite-supported consistent backup method
or an atomic storage snapshot that covers the database and all associated WAL
state. Verify its hashes and test that a copy opens and passes SQLite integrity
checks before migration. A plain filesystem copy of a database followed by a
separate copy of its `-wal`/`-shm` files is not an atomic backup and must not be
used as rollback evidence. Resume V3 traffic only after the migrated stores and
their audit chains pass integrity checks. Application rollback must either
select a prior release that understands schema v2 or, while the same traffic
remains stopped, atomically restore the matching verified v1 snapshot.
Switching only the release link is not a valid rollback. Never copy, truncate,
or delete a live state database to bypass nonce or receipt history.

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

## Promotion and Pi routing

A staged capability is deliberately not enabled and is invisible to the normal
Pi channel. After exact-release evidence passes, create a new reviewed release
whose registry references the retained evidence and moves only that capability
and environment from `staged_environments` to `enabled_environments`. Verify Pi
uses the same version, release manifest, and registry digest before any canary
route is changed.

Never patch registry metadata inside an existing release. Enabling one read
does not enable another read or any write.

## Upgrade

Install the new release in a new immutable directory and repeat every identity,
Linux, Odoo, ACL, replay, financial, and Pi canary gate. Preserve the prior
release, external anchor, state databases, and evidence. Change routing only
after the new release passes; do not restart Odoo merely to install an
unrouted V3 artifact.

## Rollback

Rollback changes only the explicitly controlled V3/Pi route to a previously
verified immutable release. It must not modify V2, delete V3 state, or attempt
to undo accounting records. Confirm the selected release's anchor and manifest,
run its identity/read canary, atomically change the route, and verify Pi and CLI
again report the same identity.

Before changing a route, verify the selected binary supports the current state
schema. If the upgrade migrated schema v1 to v2, restore the pre-upgrade v1
snapshot only as part of a coordinated rollback with traffic stopped for that
V3 state store, or roll back to a v2-compatible build. Preserve the rejected
v2 state as evidence; never merge divergent state files by hand.

If a write release is ever promoted, accounting effects are recovered only by
the capability's recorded Odoo reversal or compensation workflow. Deploying an
older binary is not an accounting rollback.

## Retained evidence

For every build, install, upgrade, promotion, and rollback retain a root-owned
read-only evidence bundle containing command/test reports, hashes, ownership
and mode inventory, V2 before/after hash, runtime/database/user/company
identity, request/result digests, receipt and audit IDs, UTC timestamps, and the
explicit promotion decision. Exclude secrets and raw credentials.

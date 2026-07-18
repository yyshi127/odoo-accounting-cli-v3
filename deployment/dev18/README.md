# Dev18 dedicated-sandbox capacity gate

`sandbox_capacity_gate.py` is the first, read-only prerequisite for building a
dedicated Odoo write sandbox. Its operational CLI accepts one externally
SHA-256-bound policy and captures the observation itself from the live Linux
host. It does not accept a caller-supplied observation or clock override.

The reviewed policy contains:

- the exact host, host-PID-1 mount-namespace requirement, and proposed
  Odoo/database target;
- the collector program SHA-256 from the immutable release manifest;
- the physical `psql`, `runuser`, `systemctl`, `pg_controldata`, and `postgres`
  paths and hashes;
- the PostgreSQL systemd unit/configuration digest, UID/GID, cgroup, Unix
  listener, process/data-directory identity, port, server version, complete
  effective/file/HBA/ident/role configuration closure, socket-GID/NSS
  membership closure, maintenance database, cluster system identifier, and
  recovery state;
- the complete reviewed PostgreSQL catalog digest/count and connectable-name
  digest/count, in addition to protected Odoo database names, UUIDs, and
  per-database `public.ir_config_parameter` relation-identity SHA-256 values;
- non-overlapping protected V2/Pi directory trees or files, their complete
  entry counts/byte totals and metadata/content/mount aggregate hashes, plus a
  physical-ancestor/mount proof for every expected-absent V3 route; and
- storage allocations, reviewed kernel mountinfo identities, and reserves; and
- independent observation-age and total-capture-duration limits.

At runtime the root-only Linux collector reads the machine/boot identity,
requires its mount namespace to equal host PID 1, binds every probe path to a
reviewed `/proc/1/mountinfo` row, and obtains `fstatvfs` from an open directory
descriptor. It binds PostgreSQL to the reviewed systemd MainPID, cgroup,
executable, `postmaster.pid`, data directory, Unix listener FD, SQL system
identity, and on-disk `pg_controldata` identity. It also binds the requested SQL
user, `SESSION_USER`, `CURRENT_USER`, superuser state, and RLS-bypass state.
Every SQL connection first returns `pg_backend_pid()` while it remains open;
the collector verifies that live backend's PPID, executable, cgroup, UID/GID,
start identity, and mount/PID/user namespaces against the reviewed postmaster
before and after the fixed transaction. The complete `pg_settings`,
`pg_file_settings`, HBA/ident views, database/role defaults, roles, memberships,
one server-side aggregate password-verifier-vector digest, configuration load
time, reviewed include graph, configuration directory, TLS/authentication
assets, and `postgresql.auto.conf` are hashed twice. Current files must not be
newer than the last PostgreSQL configuration load. Unsupported external
authentication, ambiguous include forms, and non-empty shared/session/local
preload settings in files, role/database defaults, postmaster arguments, or
process environment fail closed before a trusted SQL result is accepted. The
postmaster command line uniquely binds the reviewed data directory and
configuration entry point; its environment is hashed and dynamic-loader
injection variables must be empty. The socket directory must not be group- or
world-writable. NSS sources, account files, the exclusive PostgreSQL service
identity, and current kernel GID holders are still bound so a policy cannot
approve an extra socket authority.
Fixed SQL queries run with `default_transaction_read_only=on` and
`search_path=pg_catalog`; catalog objects and functions are explicitly
schema-qualified. The complete catalog and protected UUIDs are captured twice.

Each protected UUID read uses one live-attested backend and an explicit
`REPEATABLE READ, READ ONLY` transaction. It takes `ACCESS SHARE` on
`ONLY public.ir_config_parameter`, and performs a `pg_catalog`-only structural
and reviewed-SHA-256 assertion. The assertion requires a policy-bound ordinary,
persistent heap table owned by the direct, policy-bound non-superuser probe role
(which may differ from the database owner), without RLS, forced RLS, rewrite
rules, partitioning, inheritance, CHECK constraints, expression/partial
indexes, unsafe access methods/opclasses, expression statistics, or a
superuser, `BYPASSRLS`, `CREATEROLE`, replication, or inherited/member owner
authority, and with built-in `varchar` `key` and `text` `value` columns. The
protected read probe may bind a `CREATEDB` relation owner; that does not make
the same role eligible as a sandbox executor or authority. `ON_ERROR_STOP`
prevents the later
UUID statement from being submitted after an assertion error. The lock is held
while the relation identity is captured before and after the explicitly
qualified table read. Index, bitmap, TID, parallel, and JIT plans are disabled
for this probe. This closes both hostile-`search_path` and relation-swap windows
instead of trusting a separate preflight query.

Host, mount, service, process, catalog, protected relation/resource identities,
and the monotonic/UTC capture window must remain stable. The full generated
observation and its canonical SHA-256 are embedded in the report. This prevents
a submitted JSON document from splitting one real disk into fictional devices,
hiding an existing database, substituting its UUID relation, or choosing an old
evaluation time.

`directory_tree` identities enumerate the root and every descendant without a
128-entry truncation. They reject symlinks, special objects, and hard-linked
files, reject a symlink in any intermediate path component, and hash each
physical ancestor's routing/security identity (path, inode/device, mode, and
owner) plus every protected relative path, content, inode/device, mode, owner,
size, link count, timestamps, and covering mount. Unrelated sibling-directory
churn does not change an ancestor routing identity. Every present
object's `st_dev` major:minor must match its selected mountinfo row. An
expected-absent route has a
non-null digest over its canonical target, unresolved suffix, complete existing
ancestor chain, and covering mount; a symlink in that chain fails closed.

The gate never connects to Odoo. It connects to the reviewed PostgreSQL socket
only for fixed read-only identity/catalog queries; it does not issue database
DDL/DML, create an application file, invoke service-control actions, alter
V2/Pi/current, or perform an accounting write. OS authentication, PostgreSQL,
or service infrastructure may still emit their normal external logs, so the
attestation is limited to mutations performed by the collector itself. A
passing report means only `eligible_for_sandbox_provisioning_review=true`.
Every report, including a passing one, fixes these values to false:

```text
sandbox_provisioning_authorized
sandbox_accounting_write_authorized
production_accounting_write_authorized
```

Separate explicit authority is required to provision infrastructure. A later
isolation gate must still prove a different PostgreSQL cluster/authority,
database name and UUID, Odoo OS identity, exact database filter, data directory
and filestore, disabled cron and external integrations, non-superuser executor,
independent approver, isolated state, tested backup/reset, and protected
production paths that the sandbox identity cannot access. Capacity success is
not a substitute for any of those checks and cannot stage a registry entry or
change `write_execution_mode`.

## Calculation

Each policy allocation has a business allocation ID and binds one purpose to a
canonical path plus a reviewed kernel mount identity: mount/parent IDs,
major:minor, filesystem root, mount point, options/propagation, filesystem type,
source, and super options. The business allocation ID is not presented as a
kernel mount ID. The gate groups allocations by the open path's observed device
ID. For each device it requires:

```text
free bytes  >= sum(additional bytes)  + max(reserve bytes)
free inodes >= sum(additional inodes) + max(reserve inodes)
```

This counts PostgreSQL, filestore, runtime/evidence, backup, or other planned
growth on one shared filesystem together while charging that device's reserve
once. Observed rows that claim the same device but disagree on total/free
metrics fail closed. Policy thresholds are reviewed inputs; there are no
server-specific capacity constants in the Python program.

The target database must still be absent. The full PostgreSQL catalog identity
and connectable database-name set must exactly match the reviewed policy, so an
unlisted new business database fails closed. Every protected database name/UUID
and its locked Odoo relation identity, plus every protected V2/Pi/current
identity, must match the policy before and after the live capture. Existing UUID
collisions between protected clones may be recorded exactly because database
name and relation identity remain independently bound, but a future sandbox
must receive a new unique UUID. Host, environment, Odoo instance, PostgreSQL
cluster, database target, mount paths, freshness, and the collector's
no-intentional-mutation contract are also mandatory.

## Invocation

Run as root on Linux from an immutable release with bytecode disabled. Keep the
policy outside the release as a physical, single-link, root:root-owned file
whose entire directory chain is root-owned and not group/world writable. Obtain
its expected hash through an independent review channel. The policy's `collector_sha256`
must be copied from the reviewed release manifest, not calculated from a
writable checkout:

```bash
policy_sha256="<copy the approved digest from the signed review record>"
python3 -I -B \
  /opt/odoo-accounting-cli-v3/releases/<release>/deployment/dev18/sandbox_capacity_gate.py \
  --policy /root/evidence/sandbox-capacity-policy.json \
  --expected-policy-sha256 "$policy_sha256"
```

Do not calculate the expected hash from the policy being consumed during the
invocation; that is self-checking, not an independent approval anchor. The
operational CLI always captures live topology and uses
the current UTC clock. It rejects `--observation` and `--now`.

Exit status `0` means the live observation passed the capacity gate, `1` means
a valid observation was evaluated but blocked, and `2` means no result was
issued because policy structure, file/program/executable identity, PostgreSQL
read-only capture, or invocation was invalid. Status `0` still does not
authorize provisioning or accounting writes.

## Current target-host disposition

An independent read-only audit on 2026-07-17 found PostgreSQL, the Odoo filestore, V3
state, and proposed sandbox storage sharing the sole persistent filesystem.
Only 1,380,978,688 ordinary bytes (about 1.29 GiB) remained (approximately 99%
used), while PostgreSQL alone
occupied about 8.5 GB. The host therefore fails any credible sandbox database,
filestore, evidence, backup, and post-build reserve plan. No cleanup, database
creation, service change, or accounting write was actively performed by the
collector to obtain that observation; normal authentication, filesystem,
PostgreSQL, or OS logging/atime effects remain outside that claim. It also
found the existing `odoo` database role has `CREATEDB` and
owns 108 databases, so that role cannot qualify as a sandbox authority. The
uncommitted Dev18 collector was not relabelled as the source of this historical
audit. Capacity must be added, or a separately authorized and reviewed cleanup
must occur, before a new immutable-release capture and isolation qualification
can continue.

That historical audit did not capture a policy-ready mount filesystem root,
cluster system identifier, Unix-socket setting, postmaster executable hashes,
systemd file identity, or complete stable catalog digest. Those values must come
from a new authorized read-only capture and independent review; test fixtures
must never be copied into a target-host policy. With the reviewed 10 GiB
database, 3 GiB filestore, 1 GiB runtime/evidence, and 8 GiB shared-device
reserve plan, the recorded ordinary-space shortfall was 22,241,341,440 bytes
(about 20.71 GiB). Adding 24-30 GiB before recapture remains the conservative
recommendation.

The same host currently exposes `/run/postgresql` as mode `2775` and uses
`files systemd` NSS. The current Dev18 rule therefore rejects it before SQL:
the reviewed socket directory must be owner-only writable. Historical SQL,
configuration, or NSS digests are development probes only and cannot be copied
into a policy or presented as a passing immutable-release gate receipt.

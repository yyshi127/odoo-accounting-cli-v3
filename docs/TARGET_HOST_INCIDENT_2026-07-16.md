# Target-host mount incident, 2026-07-16

## Scope and impact

A target-Linux parity test created a fake `/var/lib` bind mount while the new
mount namespace still had shared propagation. The bind propagated into PID 1's
namespace and its source directory was later removed. The host then exposed an
empty, deleted test directory at `/var/lib` instead of the underlying root
filesystem directory.

At 23:33:59 Asia/Shanghai, PostgreSQL 16's checkpointer could no longer open
`global/pg_control`, panicked, terminated the cluster, and could not restart
while the real data directory was hidden. Production Odoo and the temporary
sandbox web processes remained alive but had no usable database backend. Their
HTTP process health was therefore not accepted as service health.

No V3 route, V3 service, write runtime, or accounting test write was enabled.
The incident was in the test-host mount boundary, not an Odoo Accounting CLI
business operation.

## Recovery evidence

The recovery used a normal, guarded `umount /var/lib`; neither lazy nor forced
unmount was used. The mount had one row, no child mounts, and no open file
descriptor on its mount ID. After unmount:

- `/var/lib` resolved to the root filesystem again;
- `PG_VERSION`, `global/pg_control`, owner `postgres:postgres`, and data-directory
  mode `0700` were present;
- `pg_controldata` reported the original cluster identity and a crash state;
- production Odoo, the V2 Pi Bridge, and the temporary sandbox were quiesced;
- PostgreSQL performed automatic WAL redo, an end-of-recovery checkpoint, and
  reported ready for connections;
- a forced read-only SQL session reported `in_recovery=false`, and the known
  production/test databases plus the candidate sandbox database retained one
  UUID and installed `base`/`account` modules;
- production Odoo's filtered database endpoint and the V2 Pi health endpoint
  passed after their services were restored; and
- the temporary sandbox remained stopped because its database-role and add-on
  boundaries did not qualify as a dedicated write sandbox.

The immutable Dev12 package and release manifest were verified again after the
recovery. `current`, the V3 write runtime, and all V3 services remained absent.
Normal production cron processing resumed with the restored production Odoo;
that operational recovery is not sandbox-write evidence.

The follow-up sandbox boundary audit found that the active production Odoo
configuration was `odoo:odoo 0644` even though it contained both the database
password and Odoo database-manager password, and that the production filestore
root was `0755`. A consumer audit found only the production Odoo and V2 Pi
services using the `odoo` identity; Nginx did not read either path, and no second
configuration containing those two keys was found in the reviewed configuration
roots. Without changing file content or restarting a service, the active
configuration was changed to `root:odoo 0640` and the filestore root to
`odoo:odoo 0700`. The `odoo` identity retained read access to the configuration
and read/write/traverse access to the filestore but lost configuration write
access; an unrelated service identity lost both reads. The configuration hash,
production Odoo PID, V2 Pi PID, Odoo database endpoint, and Pi health endpoint
were unchanged. A future sandbox service must additionally hide all production
configuration, filestore, and mutable add-on paths in its own systemd mount
namespace.

## Prevention

- Host paths must never be replaced for a test outside the checked-in
  `deployment/dev9/run-private-mount-gate.sh` wrapper.
- The wrapper requires a different mount namespace from PID 1 and private or
  unbindable root propagation before it executes the command.
- The outer process records and compares `/var/lib` mountinfo before and after
  the child and fails closed on fake, deleted, or temporary sources.
- A target test must not daemonize from the private namespace. The wrapper uses
  `--fork --kill-child=KILL` so an interrupted parent cannot intentionally leave
  its child running.
- Database-backed health and read-only database identity checks are mandatory;
  a listening Odoo process or HTTP-only health response is insufficient.
- Real write tests remain prohibited until a persistent sandbox with an
  isolated database authority, filestore, state, users, and reset procedure is
  reviewed.

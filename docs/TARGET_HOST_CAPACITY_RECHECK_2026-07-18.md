# Target-host capacity recheck, 2026-07-18

## Scope

At `2026-07-18T05:36:58Z`, the target host `43.165.173.80` was queried over
SSH using read-only hostname, identity, filesystem-metadata, `df`, `stat`, and
systemd inventory commands. No database query, Odoo RPC, file write, service
control, configuration change, role change, provisioning action, or accounting
write was performed. Normal authentication and operating-system logging are
outside that statement.

This lightweight recheck is not an immutable Dev18 E00a receipt. Its purpose is
only to determine whether the previously recorded pre-SQL blockers still
exist.

## Bound host identity

- hostname: `VM-0-6-ubuntu`;
- effective SSH command UID: `0`;
- machine-ID SHA-256:
  `2823dbcee31665277919e6e4dc808ddbcd9debee07d3c29e80c675ddbe2c1522`;
- boot-ID SHA-256:
  `0e28ffd26af3f54337ff2e5964a94bcdaea43add3e56da7aa02145aae3f5695e`.

The machine and boot identities match the retained 2026-07-17 baseline.

## Capacity result

All three capacity probes still resolve to device `64770` and the same root
filesystem:

| Probe path | Mode | Owner UID:GID | Total bytes | Ordinary available bytes | Available inodes |
|---|---:|---:|---:|---:|---:|
| `/var/lib/postgresql/16/main` | `0700` | `111:112` | 84,423,806,976 | 10,708,451,328 | 3,527,570 |
| `/mnt/odoo/odoo19/data/db_filestore` | `0700` | `999:1003` | 84,423,806,976 | 10,708,451,328 | 3,527,570 |
| `/var/lib/odoo-accounting-cli-v3` | `0755` | `0:0` | 84,423,806,976 | 10,708,451,328 | 3,527,570 |

Ordinary available space increased by `9,327,472,640` bytes since the retained
baseline. The reviewed preliminary allocation remains 22 GiB
(`23,622,320,128` bytes), so the current byte shortfall is still
`12,913,868,800` bytes, approximately 12.03 GiB. The inode threshold continues
to pass. Root-reserved blocks are not ordinary sandbox capacity and must not be
used to satisfy the gate.

## Remaining pre-SQL blockers

`/run/postgresql` remains a `postgres:postgres` directory with mode `2775`.
The Dev18 gate requires the reviewed socket authority to be non-group-writable,
so this remains an independent fail-closed blocker.

`/opt/odoo-accounting-cli-v3/current` remains absent. No unit files or loaded
units matching `odoo-accounting-cli-v3*` were returned by systemd. This is
consistent with V3 remaining side-by-side and unpromoted; it is not permission
to install or provision it.

## Disposition

No passing E00a receipt can be issued while the observed 12.03 GiB capacity
shortfall and group-writable PostgreSQL socket directory remain. Do not
provision a write sandbox or execute any Odoo accounting write from this
recheck. After those external conditions are changed under separate
operational authority, rerun the exact immutable Dev18 collector and retain
its signed, release-bound receipt.

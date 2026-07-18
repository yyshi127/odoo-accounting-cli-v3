# Target-host sandbox capacity audit, 2026-07-17

## Scope and authority

This was a strictly read-only audit of `43.165.173.80`. It used filesystem,
process, service, configuration-metadata, digest, and PostgreSQL read-only
queries. It did not create, clone, alter, or delete a file, database, service,
route, Odoo record, V2 component, or Pi component through an active collector
operation. Normal authentication, filesystem, PostgreSQL, or OS logging/atime
effects remain outside that statement. No credential value was retained.

The final same-batch snapshot was captured at
`2026-07-17T10:03:24.502572Z`. It predates this Dev18 live
collector and therefore must not be relabelled as a Dev18 gate receipt. It is
the target-host baseline and blocker that motivated that gate. A fresh capture
from the exact immutable Dev18 release is still required after capacity is
added.

A later uncommitted Dev18 development re-probe on 2026-07-18 also established
that `/run/postgresql` is mode `2775`. The current collector requires an
owner-only-writable socket directory, so this is an additional explicit
pre-SQL blocker. See `TARGET_HOST_DEV18_SQL_PROBE_2026-07-17.md`; neither that
probe nor this baseline is a passing immutable-release receipt.

## Storage result

Host identity:

- hostname: `VM-0-6-ubuntu`;
- machine-ID SHA-256:
  `2823dbcee31665277919e6e4dc808ddbcd9debee07d3c29e80c675ddbe2c1522`;
- boot-ID SHA-256:
  `0e28ffd26af3f54337ff2e5964a94bcdaea43add3e56da7aa02145aae3f5695e`.

The three required capacity probes all resolve to device `64770` and the same
ext4 filesystem:

| Probe path | Total bytes | Ordinary available bytes | Total inodes | Available inodes |
|---|---:|---:|---:|---:|
| `/var/lib/postgresql/16/main` | 84,423,806,976 | 1,380,978,688 | 5,242,880 | 3,167,071 |
| `/mnt/odoo/odoo19/data/db_filestore` | 84,423,806,976 | 1,380,978,688 | 5,242,880 | 3,167,071 |
| `/var/lib/odoo-accounting-cli-v3` | 84,423,806,976 | 1,380,978,688 | 5,242,880 | 3,167,071 |

The filesystem reported 99% use. Approximately 3.30 GiB of ext4 root-reserved
blocks are not ordinary-process capacity and are excluded. Ordinary available
space fell by roughly 80 MB during the audit, showing that the live host was
still consuming space. Swap had only about 12.9 MB free; memory availability
was about 5 GiB, but memory does not compensate for the storage failure.

The reviewed preliminary allocation is 10 GiB for PostgreSQL, 3 GiB for the
filestore, 1 GiB for runtime/evidence, plus one 8 GiB shared-device reserve.
The resulting 22 GiB requirement exceeds ordinary available space by exactly
`22,241,341,440` bytes (about 20.71 GiB). The 450,000-inode requirement passes;
bytes are the blocking resource.

This is a fail-closed result. Root-reserved blocks must not be consumed to make
the gate pass. A practical expansion should add at least 24–30 GiB before a
fresh capture; any cleanup alternative requires separate scope and approval.

## PostgreSQL and database identity

PostgreSQL 16.14 uses `/var/lib/postgresql/16/main`, listens locally on port
5432, and occupies about 8.5 GiB. There were 113 connectable databases with a
combined logical size of about 8.51 GiB. The proposed target database
`odoo_v3_accounting_sandbox` did not exist.

The eight reviewed `odoo*` databases were:

| Database | Odoo database UUID | Size bytes |
|---|---|---:|
| `odoo` | `ae0db0bb-cb37-11f0-8026-00163e54a5ad` | 85,097,495 |
| `odoo_2601` | `55bb8b7a-e607-11f0-8325-00163e54a5ad` | 200,915,991 |
| `odoo_2601_cn_compliance_dev` | `a3336164-febd-42a9-9b4c-e008cfda910f` | 144,833,559 |
| `odoo_cn_compliance_demo_m30` | `55bb8b7a-e607-11f0-8325-00163e54a5ad` | 149,806,103 |
| `odoo_sg` | `1a65971c-6559-11f1-aa09-525400095626` | 77,642,775 |
| `odoo_sg_compliance_test` | `49eaaef7-7f5e-11f1-96c0-525400095626` | 59,972,631 |
| `odoo_sg_manual_demo_20260716` | `1a65971c-6559-11f1-aa09-525400095626` | 65,518,615 |
| `odoo_test` | `19b09656-d10f-11f0-9065-00163e54a5ad` | 101,358,615 |

Two clone pairs share UUIDs. An Odoo UUID is therefore not unique by itself on
this host. A future sandbox must receive a newly generated UUID and remain
bound to cluster, database name, UUID, service, and filestore together.

The existing PostgreSQL role `odoo` has `CREATEDB`, owns 108 databases, and can
log in. It cannot qualify as the dedicated restricted sandbox authority. The
future role must be non-superuser/non-createdb/non-createrole/non-replication/
non-bypassrls and must be unable to connect to every protected database.

## Odoo and control-plane boundaries

The production `odoo19.service` runs as `odoo:odoo`, listens on
`127.0.0.1:8070` (gevent 8072), uses
`/mnt/odoo/odoo19/data/db_filestore`, and has
`dbfilter=^(?!codex_).*$`. `db_name` is unset and `list_db=True`; these are not
sandbox settings.

A separate nohup development process listens on `127.0.0.1:18070` with
configuration below `/tmp/codex_cn_m31`. It shares the `odoo` OS/database
authority, uses ephemeral storage, and is not a managed V3 sandbox. It must not
be reused for write evidence.

The immediate read-only control check matched the retained Dev15 baseline:

- V2 combined: 668 entries,
  `eb4b194e034fba683794c5d5fd39707588e88fda569f3ac1c982e4b7c23aa891`;
- main V2 tree: 576 entries,
  `860c26d2bca049c46de6696598202de514b2d66c08657a2296d18fd9e210caf1`;
- Pi-embedded V2: 92 entries,
  `fd2d28fb28c21e983a08d594f31f32f3867ca2ea5c2c4e004f7807ee7cdd5cf9`;
- Pi control: five entries,
  `52fb10453c439d7f3877d0208f335023bef0952a3911c049ab06e64e09974b62`;
- `/opt/odoo-accounting-cli-v3/current`: absent; and
- all six planned V3 service/socket unit files: absent.

V2, Pi, production Odoo, and the V3 route were not changed.

## Disposition

No sandbox may be provisioned and no real accounting write test may run from
this baseline. After capacity is added, rerun the immutable Dev18 live capacity
collector. A pass would only permit a separate infrastructure review. It would
not satisfy the independent cluster/role, service identity, filestore,
dbfilter, cron/network/integration, executor/approver, backup/reset, or E01–E12
write-lifecycle gates, and would not authorize either sandbox or production
accounting writes.

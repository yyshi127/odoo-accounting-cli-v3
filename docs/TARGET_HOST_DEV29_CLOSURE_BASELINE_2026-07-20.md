# Dev29 target Odoo closure baseline (2026-07-20)

This is a read-only baseline for `43.165.173.80`.  The audit did not alter a
service, database, configuration file, route, V2 installation, or Pi Bridge.
It intentionally records no configuration values that may contain database
credentials.

## Database and installed-module closure

The audit connected to `odoo_test` through the fixed local PostgreSQL socket
using a `REPEATABLE READ`, `READ ONLY` transaction and rolled it back.  The
database UUID was `19b09656-d10f-11f0-9065-00163e54a5ad`.

- Installed modules: 138 (1 builtin, 121 community, 16 custom)
- Installed dependency edges: 291
- Missing, duplicate, uninstalled-dependency, manifest-parse, and dependency
  mismatches: 0
- Installed-name digest:
  `fe79aaeed84bc447cae68831c6d8e37b3dd4fb07ff111187822acc8390cfd838`
- Database graph digest:
  `20f9fd9a549ac124db56cc8ae78832c5586d0909ddabaf9b1b32dd858de0ef19`
- Module mapping digest:
  `4bce1ae921fb9c6dff88d1efc7aa76bd1c839cbc08d0b2f8745d480cb0a14eaa`

The installed module trees contain 18,910 files and 3,178 directories, no
symbolic links, and 604,326,266 logical bytes.  A candidate containing full
Odoo core (excluding 23 uninstalled builtin test addons), `odoo-bin`, all 138
installed module trees, and the full venv contains 29,353 files, 4,336
directories, four symbolic links, and 827,459,991 logical bytes.  Its observed
source manifest digest was
`6b676b7ab8290cb7e5d5925b6b0b9449976fcb51e79547df14815000c1f7ac16`.

## Python and native dependency boundary

- CPython: 3.12.3
- `/usr/bin/python3.12` SHA-256:
  `1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118`
- Installed-distribution digest (77 distributions):
  `c6d4b642f1acffe5e13c05dca8b3b887555ad3a1c4559effb7e2712a81325d2f`
- External native union: 38 files, 22,597,632 bytes; manifest SHA-256:
  `b54250941411f37d6d61f7a58b88454cf4f12f9b180cab83b6a1ab4600283a85`

The Python links resolve to the root-owned `/usr/bin/python3.12`; `lib64`
resolves to `lib` inside the venv.  The system interpreter, standard library,
and external native union bring the observed logical dependency boundary to
approximately 911,360,947 bytes.  They must be attested even when they remain
on the root-owned, read-only host filesystem rather than inside SquashFS.

The venv has two executable `.pth` files.  `distutils-precedence.pth` imports
only the system standard library and the in-venv `_distutils_hack`.  In
contrast, `__editable__.cli_anything_odoo-1.0.0.pth` imports an editable finder
that exposes these mutable paths outside the candidate closure:

- `/opt/odoo/odoo19/odoo-server/agent-harness/cli_anything/odoo`
- `/opt/odoo/odoo19/odoo-server/agent-harness/cli_anything/odoo/skills`

The unsafe `.pth` digest is
`71c4b6a0b138ea02bc9338c1493f66d712bc4d746d027594451db3bf4dac2dcc`.
Its finder digest is
`34410cfa61e640f240f1d66aa88ad0c62733935cca626d8ca6e4a88f5d14618d`.
Dev29 must remove both from the sealed venv and prove that no remaining `.pth`,
symlink, or import hook escapes the closure or an explicitly attested
root-owned dependency.  This is also why CLI-Anything remains a development
and test input rather than part of the production runtime trust boundary.

The host also has a root-owned mode-`0644` `/etc/ld.so.preload` (18 bytes,
SHA-256
`93939365735f479eab8330a9f17a7d50770ca83646a19af3f559cc94b31288ea`)
whose single entry uses the loader's `$LIB` token to preload `libonion.so`.
A follow-up read-only check resolved `/lib/x86_64-linux-gnu/libonion.so` to
`/usr/lib/x86_64-linux-gnu/libonion_security.so.1.0.19`.  The link is
root-owned, mode `0777`, single-link, 49 bytes, device `64770`, inode `337`;
the resolved regular file is root-owned, mode `0755`, single-link, 42,880
bytes, device `64770`, inode `331`, SHA-256
`9ba3574dc9c5438751b789941369956aceb58bb39feac0029295821e83720c7f`.
Its `DT_NEEDED` closure observed by `readelf` is `libdl.so.2` and `libc.so.6`;
`libdl.so.2` requires `libc.so.6`, and `libc.so.6` requires
`ld-linux-x86-64.so.2`.  Their resolved target identities are respectively:

- root-owned mode `0644`, 14,408 bytes, SHA-256
  `850b46fd4f4478060fc106f4d1dc4aa35c969eb5c9bd98aaf64dc6cb3d6a5e32`;
- root-owned mode `0755`, 2,125,328 bytes, SHA-256
  `d8db8739a1633c972cec6a4fe0566bdcec6fd088f98723492ab0361f66238f75`;
- root-owned mode `0755`, 236,616 bytes, SHA-256
  `1cd555ac46b7887edeaf3c42aac5408c8135e52f6b37870da2cf82d5fe14e829`.

Because the dynamic loader processes the preload file before Python can
perform any self-check, Dev29 must bind these identities and observed runtime
opens into the explicit root-OS trust boundary. It must not silently mask or
disable this host security component.  The follow-up check also attested the
available tracing executables: root-owned mode-`0755` `/usr/bin/strace`
(2,087,432 bytes, SHA-256
`28f957c227012de0b18d1bd7fff2d396cb693ea60ed8013be68de071e84b5001`),
root-owned mode-`0755` `/usr/bin/bpftrace` (2,250,576 bytes, SHA-256
`d2846f3400bb129b1a569aae64adf548de99ff41f247823ff8caf1fbde40ff1e`),
and root-owned mode-`0755` `/usr/sbin/bpftool` (1,622 bytes, SHA-256
`2d0953085bf720a25efbe24f853e97d27b1f12f18a398255ff82cbafde254dad`).
Those identities do not by themselves complete the required private,
fixed-case runtime-open inventory or authorize a host-policy change.

At `2026-07-20T04:28:22Z`, one additional read-only SSH probe confirmed that
the installed tracer is `strace` 6.8 and advertises the fixed options needed
by the revised launcher: `--daemonize=grandchild`, `--decode-fds=path`,
`--quiet=SET`, and `--string-limit`.  The earlier attempted
`--always-show-pid` option is not supported by this target version and is not
used by Dev29.  This compatibility check did not run an Odoo command, start a
trace, or modify the host.

At `2026-07-20T04:30:35Z`, a fixed harmless `/usr/bin/sleep` trace then
confirmed the process relationship on this exact build: the PID returned to
the supervisor remained the tracee, its `PPid` equalled the supervisor PID,
its nonzero `TracerPid` identified `/usr/bin/strace`, and the trace used the
tracee PID prefix.  The probe created one tiny, randomly named file below
`/run`, removed it through a trap, and a separate read-only `find` check proved
that no `dev29-strace-semantics*` file remained.  It did not invoke Odoo,
PostgreSQL, V2, Pi Bridge, or a business capability.

## Mount and capacity gate

SquashFS, squashfs-tools 4.6.1, loop devices, mount namespaces, and the needed
administrative capability are present.  No Dev29 dependency root or loop mount
was created.

The follow-up read-only check fixed the principal orchestration tool identities:
`/usr/sbin/ldconfig.real` was root-owned, single-link, mode `0755`, 1,051,280
bytes, and had SHA-256
`9145a756d4a4e75ea4807b1bd824c9ed06a4ccfec6319dbaeec355a7179117f1`;
`/usr/bin/systemd-run` SHA-256
`49f0bf95eb8a781b93853bf9fc981b4929dd0009f55a3e6db95534c0a2d11716`,
`/usr/bin/systemctl` SHA-256
`7ba82b5ba146759c710e1b80fadaa3fdbc0f9b85c8fb2c8c3196b7b1a0037ef8`,
`/usr/bin/mount` SHA-256
`ac5aa68d34add5a33ae81ac3a971aea677c4032d768aab5a3c4c2707f728885e`,
`/usr/bin/umount` SHA-256
`2ea59b57d249d58c64b028b2acf6118b62dc3ba89012a1cf4ff5f5a9891f513d`,
`/usr/sbin/losetup` SHA-256
`2c1c321be3fc862db0dc374499a913fec0c4dc1edbce728c4127502fd15f5622`,
`/usr/bin/findmnt` SHA-256
`bb2f0ce5dfffc24cf965c67686c6e8bcc0383161800dfca661fc490dc9c1a63e`,
and `/usr/bin/unshare` SHA-256
`51bcc77ba5db162c80028f861f0a2770d728c1de80773816d863f28d7a817adb`.
Each was root-owned, single-link, and mode `0755`, except `mount` and `umount`,
which were mode `4755`.  These observations must be bound into the immutable
closure/supervisor expectations; path presence alone is not sufficient.

At observation time only 1,942,790,144 bytes were available.  This was
204,693,504 bytes below the existing 2 GiB installer floor.  Keeping that floor
while materializing the observed dependency boundary requires at least
3,058,844,595 bytes, leaving a conservative shortfall of 1,116,054,451 bytes.
No package installation or closure build is permitted until a fresh capacity
gate passes.  Unrelated data must not be removed to make room.

A read-only recheck at `2026-07-20T02:53:57Z` found only 1,743,179,776 bytes
available on the same ext4 root filesystem (98% used).  That is 404,303,872
bytes below the 2 GiB installer floor and 1,315,664,819 bytes below the same
conservative closure-plus-floor requirement.  The gate therefore remains
closed and has worsened since the first observation.

A further read-only capacity check at `2026-07-20T04:42:03Z` found only
1,645,715,456 bytes available (still 98% used): 501,768,192 bytes below the
2 GiB installer floor and 1,413,129,139 bytes below the conservative
closure-plus-floor requirement.  The existing V3-owned trees account for only
44,384,256 bytes under `/opt/odoo-accounting-cli-v3` and 352,210,944 bytes
under `/var/lib/odoo-accounting-cli-v3`.  Even deleting every byte in both
trees would not reach the installer floor, so no V3 artifact was deleted and
capacity cannot be made safe by pruning only this project's files.

The next read-only recheck at `2026-07-22T00:21:48Z` found only 14,630,912
bytes available on the root filesystem, which `df` reported as 100% used.
That is 2,132,852,736 bytes below the 2 GiB installer floor and 3,044,213,683
bytes below the same conservative closure-plus-floor requirement.  The
V3-owned trees then contained 39,847,586 bytes under
`/opt/odoo-accounting-cli-v3` and 340,374,501 bytes under
`/var/lib/odoo-accounting-cli-v3`.  Removing both in full would still leave
the host 1,752,630,649 bytes below the installer floor.  Nothing was removed,
and the deployment/closure-build gate remains closed.

The same probe reconfirmed the previously recorded SHA-256 identities for
`/usr/bin/python3.12`, `/usr/bin/strace`, `/usr/sbin/ldconfig.real`,
`/usr/bin/systemd-run`, and `/usr/bin/systemctl`; no service, configuration,
route, database, V2 installation, or Pi Bridge state was changed.

Read-only `du`, `journalctl --disk-usage`, `find`, and `lsof +L1` diagnostics
then showed that the material pressure is outside the V3 trees.  Notable
allocated trees included `/root/project` at 15,916,441,600 bytes,
`/root/.hermes` at 9,266,237,440 bytes, `/mnt/odoo` at 16,465,571,840 bytes,
and `/tmp` at 1,631,588,352 bytes.  `/var/log` accounted for 1,257,041,920
bytes, including 920.6 MiB of active and archived journals and a 161,129,253
byte PostgreSQL log.  Deleted-but-open files shown by `lsof` were small and do
not explain the missing capacity.  These paths belong to wider host
operations; this audit did not truncate, rotate, restart, move, or delete any
of them.  Capacity remediation therefore requires an explicit operations
decision outside the V3 deployment task's current authority.

At `2026-07-22T01:10:33Z`, a new read-only observation found that an external
operation had increased root-filesystem availability to 4,255,105,024 bytes
(95% used).  This is 2,107,621,376 bytes above the 2 GiB installer floor and
1,196,260,429 bytes above the previously calculated 3,058,844,595-byte
closure-plus-floor requirement.  The V3-owned trees remained only 39,847,586
bytes under `/opt/odoo-accounting-cli-v3` and 340,374,501 bytes under
`/var/lib/odoo-accounting-cli-v3`; this audit did not perform or attribute the
external cleanup.  The capacity condition therefore passes at this instant,
but installation remains deferred until the exact Dev29 release and its Linux
lifecycle gates are complete and a fresh pre-install capacity/stability probe
confirms the headroom has persisted.

The Odoo configuration may contain credentials and therefore must not be
embedded in a generally readable image.  Dev29 must use a separately sealed,
root-owned, group-readable configuration and bind it read-only over a regular
placeholder inside the custom-addons mount.

## Runtime stability gate

During the audit `odoo19.service` had reached `NRestarts=484` and continued to
change its main PID.  The Odoo log showed memory at 2,205,458,432 bytes crossing
the configured 2 GiB soft limit, followed by a server reload.  The phoenix
re-exec then lost the venv prefix and produced a secondary `passlib` import
failure even though `passlib` remained present and importable in the venv.

At the `2026-07-20T02:53:57Z` read-only recheck the service was active with
`NRestarts=516`, main PID `297587`, and invocation ID
`f54c24c0ea9b413f940a32ec30e1564f`. PostgreSQL remained active with zero
restarts, main PID `3671026`, and invocation ID
`b70baebe2fb14af688d3f3164c05437d`.  The increased Odoo restart count confirms
that the stability gate has not recovered.

An unrelated concurrent database/cron workload was active.  It was not
interrupted.  The Dev29 real-read suite requires stable pre/post Odoo service
identity and therefore must fail closed until the external workload finishes
or operations restores stable service behavior.  This baseline is not a real
Odoo capability pass and does not authorize production promotion.

At `2026-07-22T00:21:48Z`, `odoo19.service` was active/running but had reached
`NRestarts=1172`.  This continued increase independently keeps the runtime
stability gate closed; no Odoo request or business capability was invoked by
the recheck.

At `2026-07-22T01:10:33Z`, `odoo19.service` was still active/running with the
same `NRestarts=1172` and main PID `2888752`; PostgreSQL 16 was active.  A
separate long-running Odoo development process using
`/tmp/codex_cn_m31/odoo-dev.conf` and unrelated concurrent host diagnostics
were also visible.  They were not interrupted or classified as an authorized
V3 sandbox.  The unchanged restart counter is a positive point-in-time
observation, not yet a sustained stability pass, sandbox qualification, or
authorization to execute an Odoo write.

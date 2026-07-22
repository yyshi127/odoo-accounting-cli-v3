# Dev29 immutable Odoo dependency closure

`odoo_closure.py` is the release-contained, root-only builder, activator, and
verifier for the exact Odoo runtime used by the Dev29 read-evidence suite. It
uses only the Python standard library. Every root invocation must use the
literal command prefix `/usr/bin/python3.12 -I -S`; the script immediately
checks `sys.executable`, isolated/no-site flags, `/proc`-equivalent executable
identity, root ownership, mode `0755`, single-link status, and an independently
supplied SHA-256. The `#!/usr/bin/env` line is not an authorized root launcher.

This remains a staged read-test dependency closure. It does not change
`current`, route a V3 service, alter V2, write Odoo business data, or authorize
a production write capability.

## Fixed layout and inputs

For release `$RELEASE`, alternative paths are refused:

- image: `/opt/odoo-accounting-cli-v3/dependency-images/$RELEASE.squashfs`
- external anchor: `/opt/odoo-accounting-cli-v3/dependency-anchors/$RELEASE.json`
- mount: `/opt/odoo-accounting-cli-v3/dependencies/$RELEASE`
- sealed config:
  `/etc/odoo-accounting-cli-v3/dependencies/$RELEASE/odoo-server19.conf`
- build staging: `/var/lib/odoo-accounting-cli-v3/dependency-build`

All commands require independent hashes for `/usr/bin/python3.12`,
`/usr/sbin/ldconfig.real`, and `/etc/ld.so.preload`. The `ldconfig.real`
digest must come from the retained target baseline rather than from the same
process that invokes the closure. Its root-owned mode-`0755` single-link file
is opened with `O_NOFOLLOW`, hashed through that retained descriptor, and
executed through `/proc/self/fd`. A ptrace exec stop with
`PTRACE_O_EXITKILL` binds `/proc/$pid/exe` to that same inode; after the fixed
30-second invocation, the descriptor is rehashed and both its complete stable
identity and the fixed path inode must still match. Any timeout, digest drift,
path replacement, or abnormal trace state is killed, reaped, and rejected.

On the audited target, `ld.so.preload` is an intentional
root-OS trust anchor rather than an absent file. It must remain root:root
`0644`, single-link, and byte-identical to the approved hash. `$LIB` is
canonically expanded with the reviewed x86-64 Debian glibc profile; every
configured path, symlink target, resolved ELF, and recursively discovered ELF
dependency is included in the external manifest. The file and parent are under
the same pre/post/inotify drift gate. It is never masked, renamed, or disabled.

This loader injection occurs before Python can run any guard. It is therefore
residual host trust that cannot be eliminated by the release itself. A changed
preload file or library is a hard rejection.

Database graph discovery invokes the audited PostgreSQL 16 client directly at
`/usr/lib/postgresql/16/bin/psql`; the distribution-managed `/usr/bin/psql`
wrapper symlink is not part of this trust boundary. The direct client and
`/usr/sbin/runuser` must be root-owned, mode `0755`, single-link regular files.
Module names and dependency pairs are aggregated using PostgreSQL's explicit
`C` collation so their order matches the bytewise canonical manifest order and
does not depend on the database locale.
The literal manifest parser applies Odoo 19's own omitted-version default of
`1.0`; an explicitly supplied version must still be a string. Dependencies
must remain a literal list of valid module names.
The target host's `/usr/bin/mount` and `/usr/bin/umount` are accepted only with
their audited root-owned, single-link mode `04755` identity.

## Build

Identity values come from the independently retained release/install record
and read-only target baseline:

```sh
/usr/bin/python3.12 -I -S \
  /opt/odoo-accounting-cli-v3/releases/$RELEASE/deployment/dev29/odoo_closure.py \
  build \
  --expected-release "$RELEASE" \
  --expected-version "$VERSION" \
  --expected-commit "$COMMIT" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --expected-package-sha256 "$PACKAGE_SHA256" \
  --expected-system-python-sha256 "$SYSTEM_PYTHON_SHA256" \
  --expected-ld-so-preload-sha256 "$LD_SO_PRELOAD_SHA256" \
  --expected-ldconfig-sha256 "$LDCONFIG_SHA256" \
  --expected-odoo-config-sha256 "$ODOO_CONFIG_SHA256" \
  --expected-database-name odoo_test \
  --expected-database-uuid 19b09656-d10f-11f0-9065-00163e54a5ad
```

The SquashFS contains `odoo-server`, `odoo19-venv`, and `custom-addons`.
Only Odoo core, modules whose database state is exactly `installed`, their
verified manifests, and the normalized venv enter those trees. Each installed
module must resolve in exactly one fixed builtin/community/custom root. The
database graph, manifest dependency graph, module source mapping, and image
payload mapping must all agree.

The public image contains a root-owned mode `0000`, non-secret placeholder at
`custom-addons/odoo-server19.conf`. The byte-exact real config is outside the
image as `root:odoo 0440` beneath a `root:odoo 0750` ancestor. During
activation, it is the fourth and final bind after the custom-addons directory,
so an omitted override exposes only the fail-closed placeholder.

A recursive inotify guard starts before discovery. Database graph, module
mapping, source manifest, Python audit, loader preload identity, native union,
external runtime, and config are recomputed before copy, after copy, and after
image construction. Any event or semantic difference rejects publication.

No Odoo-writable ELF is executed during static discovery. A bounded parser
reads `PT_INTERP`, `DT_NEEDED`, and `RPATH/RUNPATH`; resolution is tied to the
root-owned `/etc/ld.so.cache` listing emitted by the independently hashed,
pinned `/usr/sbin/ldconfig.real`. External entries, including Python 3.12,
stdlib, loader cache/preload, preload libraries, and recursively resolved
native libraries, must be root-owned and not group/other writable.

The venv audit removes CLI-Anything editable `.pth`/finder/metadata,
`.egg-link`, and all bytecode caches. It rejects path-bearing `.pth` entries,
unapproved executable hooks, and `sitecustomize`/`usercustomize` forms.
`pyvenv.cfg` is normalized to Python 3.12 with system site-packages disabled;
remaining image symlinks are relative and stay inside their component.

Capacity gates reserve the staging upper bound, a worst-case image bound, and
at least 2 GiB residual free space on each relevant filesystem. Two sequential
single-processor SquashFS builds use fixed epoch timestamps, all-root
ownership, no xattrs/exports, and zstd; their SHA-256 values must match.
Config, image, and anchor publication is no-replace and an exact complete rerun
is idempotent.

The July 20 target audit found only about 1.94 GB free against an approximately
911 MB raw closure plus the mandatory 2 GiB floor. Target build/install remains
refused until capacity is independently added or safely freed.

## Single-supervisor activation

`PrivateMounts=yes` namespaces cannot be shared with `JoinsNamespaceOf`, and a
mount made by a short-lived helper disappears when that helper exits. The only
operational model is one outer transient service whose single root ExecStart
is `deployment/dev29/run_read_evidence.py`:

1. The supervisor enters its systemd-created private mount namespace.
2. `activated_closure(...)` holds the release lock, pre-verifies all retained
   identities, mounts SquashFS `loop,ro,nodev,nosuid`, and requires both
   `LO_FLAGS_READ_ONLY` and `LO_FLAGS_AUTOCLEAR`.
3. The same supervisor manually performs each bind followed by
   `remount,bind,ro,nodev,nosuid`; systemd `BindReadOnlyPaths` and
   `ExecStartPre` are not used for these post-image sources.
4. It verifies mountinfo, statvfs read-only state, source/target device+inode,
   config-last order, loop backing inode, and absence from PID 1's mountinfo.
5. Suite children are direct fixed-role fork/exec descendants. Calling nested
   `systemd-run` is forbidden because it would lose the namespace.
6. The Odoo child uses the sealed closure venv Python with `-I`, so Click and
   its import tree come from the mounted read-only venv. Root verifier and
   anchor-writer roles use exact `/usr/bin/python3.12 -I -S`.
7. Children irreversibly drop groups, GID/UID, capability bounding/ambient/
   effective/permitted/inheritable sets, then set no-new-privileges. Their
   attestation must prove the same namespace/mount/inodes and zero privileges.
8. In `finally`, binds are unmounted in reverse order, followed by SquashFS.
   Cleanup must prove no affected self/PID1 mountinfo row and no sysfs loop
   backing match before releasing the lock.

`mount` remains a diagnostic primitive; invoking it in a standalone process is
not a complete lifecycle. `verify-active` is intended for a fresh fixed-Python
fork/exec by the same supervisor while the four binds remain active.

Example validation-only invocation inside that namespace:

```sh
/usr/bin/python3.12 -I -S "$RELEASE_ROOT/deployment/dev29/odoo_closure.py" verify-active \
  --expected-release "$RELEASE" \
  --expected-version "$VERSION" \
  --expected-commit "$COMMIT" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --expected-package-sha256 "$PACKAGE_SHA256" \
  --expected-system-python-sha256 "$SYSTEM_PYTHON_SHA256" \
  --expected-ld-so-preload-sha256 "$LD_SO_PRELOAD_SHA256" \
  --expected-ldconfig-sha256 "$LDCONFIG_SHA256" \
  --expected-odoo-config-sha256 "$ODOO_CONFIG_SHA256" \
  --expected-database-name odoo_test \
  --expected-database-uuid 19b09656-d10f-11f0-9065-00163e54a5ad \
  --expected-closure-anchor-sha256 "$CLOSURE_ANCHOR_SHA256" \
  --expected-closure-image-sha256 "$CLOSURE_IMAGE_SHA256"
```

The four binds are strictly ordered:

1. `$MOUNT/odoo-server` to `/opt/odoo/odoo19/odoo-server`
2. `$MOUNT/odoo19-venv` to `/opt/odoo/odoo19/odoo19-venv`
3. `$MOUNT/custom-addons` to `/mnt/odoo/odoo19/custom/addons`
4. sealed config to
   `/mnt/odoo/odoo19/custom/addons/odoo-server19.conf`

## Evidence and promotion boundary

The static external-runtime method is
`static-python-elf-dt-needed-loader-preload-plus-root-owned-ld-cache-v2`.
It is deliberately reported as `static_runtime_closure_complete=false` and
`promotion_eligible_from_static_verification=false`. Static ELF discovery does
not observe all runtime opens such as NSS modules, OpenSSL providers/config/
certificates, locale, timezone, or Oracle client data.

The fixed 5+7+D11/Oracle scenarios therefore require a separately attested,
no-side-effect runtime-open trace. Every opened host path must match the sealed
allowlist and manifest; unaccounted paths fail closed. Until that trace passes,
the closure must not be described as complete and cannot support target
promotion.

Evidence publication is two phase. A same-namespace verifier first emits an
unsigned/unanchored `validate-only` report. The supervisor then completes
reverse cleanup and produces the no-mount/no-loop receipt. Only a fixed anchor
writer may bind both objects into the success anchor. Unmount or loop cleanup
failure returns nonzero and must leave no success anchor. A SIGKILL test must
show that namespace destruction plus `LO_FLAGS_AUTOCLEAR` leaves no global loop
backing.

Successful stdout is one canonical JSON object. Errors never include config
bytes, database credentials, preload contents, or other secret material.

## Tests and recovery

Portable adversarial tests:

```sh
python -m pytest -q tests/test_dev29_odoo_closure.py
```

The real loop/file-bind test is skipped unless it runs as Linux root in a
private mount namespace with SquashFS tools, loop devices, and
`CAP_SYS_ADMIN`:

```sh
sudo unshare --mount --propagation private -- \
  env ODOO_CLOSURE_REAL_MOUNT_TEST=1 \
  python -m pytest -q -p no:cacheprovider \
  tests/test_dev29_odoo_closure.py::test_real_squashfs_loop_mount_read_only_inode_binding
```

The orchestrator additionally requires a real systemd v255 integration test
for namespace inheritance, direct child privilege drop, validation-only,
reverse cleanup, anchor ordering, timeout/process-group cleanup, and SIGKILL
autoclear behavior.

Recovery never edits a published immutable artifact. Normal and handled-failure
paths use the context cleanup receipt. If the supervisor is killed, its private
namespace disappears and autoclear releases the loop after the final reference.
Retain conflicting artifacts for diagnosis and rebuild under a new release
identity. V2 and all production routes remain unchanged.

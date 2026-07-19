# Dev27 finalizer external runtime gate

The effect-finalizer runs from the canonical V3 release with
`/usr/bin/python3 -I -B -X utf8`; it must never reuse the Odoo-managed virtual
environment or import Odoo. The only non-standard runtime dependency is the
root-managed PostgreSQL driver; the gate binds its imported files and the
file-backed native mappings observed after import.

After an independently authorized driver installation, collect a deterministic
manifest from the exact retained release:

```sh
/usr/bin/python3 -I -B -X utf8 \
  /opt/odoo-accounting-cli-v3/releases/<release>/deployment/dev27/finalizer_runtime_gate.py \
  collect --interpreter /usr/bin/python3 > /root/finalizer-runtime-manifest.json
```

Review and externally retain its SHA-256. Install the exact canonical JSON as
`/etc/odoo-accounting-cli-v3/effect-finalizer-runtime-manifest.json`, owned by
root beneath root-owned non-writable ancestors, mode `0444`. Collection proves
that isolated Python cannot discover or import `odoo`, imports the exact release
finalizer and `psycopg2`, and records the loaded Python module files, `sys.path`
directories/files/missing entries, `.pth` files, and file-backed native mappings
visible after those imports. Every recorded path, owner, mode, inode, size,
version, and file SHA-256 is bound. This is the observed eager-import set; it is
not evidence for an unobserved future Python import or lazily loaded dependency.

Place that exact fixed path and externally reviewed digest in the strict
schema-v2 fields `dependency_manifest_path` and
`dependency_manifest_sha256`. Supply the same digest to
`render-systemd-service.py --finalizer-runtime-manifest-sha256`; a mismatch
between the installed canonical JSON, runtime document, or rendered
`ExecStartPre` fails closed.

Verify it as the finalizer service identity before every service start:

```sh
/usr/bin/python3 -I -B -X utf8 \
  /opt/odoo-accounting-cli-v3/releases/<release>/deployment/dev27/finalizer_runtime_gate.py \
  verify --interpreter /usr/bin/python3 \
  --manifest /etc/odoo-accounting-cli-v3/effect-finalizer-runtime-manifest.json \
  --expected-manifest-sha256 <EXTERNALLY_REVIEWED_64_LOWERCASE_HEX>
```

The probe starts at `/` with an empty environment except fixed
`LD_BIND_NOW=1`, uses `-I -B -X utf8`, and requires Linux procfs. Missing or
extra manifest fields, noncanonical JSON, unsafe ownership/modes, symlink or
inode changes, Odoo visibility, missing `_psycopg`/libpq, dependency changes,
or any byte drift fail closed. The expected digest is a required independent
input and is embedded in the reviewed rendered service; replacing both the
runtime and manifest without that digest still fails. Regenerate the manifest
only through a reviewed upgrade/rollback procedure; never accept a manifest
generated after an unexplained startup failure.

`ExecStartPre` is not the only check. Before reading the finalizer HMAC or
one-entry pgpass, the actual finalizer process requires isolated
`/usr/bin/python3` with `LD_BIND_NOW=1`, rejects Odoo visibility, eagerly imports
and retains `psycopg2` plus `_psycopg`, reruns this gate with the schema-v2
digest, and confirms the loaded driver paths and version are present in the
manifest. Under the root-managed, non-writable release and configuration threat
model, this closes the process-boundary gap between a successful pre-start child
and the connector later used by the service; any failure prevents service
construction.

This gate does not install packages, grant database access, start a service, or
authorize an Odoo/accounting write.

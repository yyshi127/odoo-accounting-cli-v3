# Dev29 release-contained read runtime

`runtime_setup.py` creates one unrouted, test-only Odoo read candidate for
the exact release that contains the script. It does not import Dev15, copy an
older key or state database, start a service, change `current`, route Pi
Bridge, or execute Odoo/PostgreSQL.

Run the copy inside the sealed release as root. Every expected value must come
from the independently verified package/install record and server baseline:

Before invoking it, install the exact release member
`deployment/dev29/systemd/odoo-accounting-cli-v3-dev29-tmpfiles.conf` as
`/etc/tmpfiles.d/odoo-accounting-cli-v3-dev29.conf`, run
`systemd-tmpfiles --create /etc/tmpfiles.d/odoo-accounting-cli-v3-dev29.conf`,
and verify the four declared paths. This recreates the two root-only `/run`
parents after every boot. `runtime_setup.py` independently creates or verifies
all four shared evidence/staging parents and rejects owner, mode, type, or
symlink drift.

```sh
/usr/bin/python3.12 -I -S \
  /opt/odoo-accounting-cli-v3/releases/$RELEASE/deployment/dev29/runtime_setup.py \
  --expected-release "$RELEASE" \
  --expected-version "$VERSION" \
  --expected-commit "$COMMIT" \
  --expected-manifest-sha256 "$MANIFEST_SHA256" \
  --expected-package-sha256 "$PACKAGE_SHA256" \
  --expected-odoo-python-sha256 "$ODOO_PYTHON_SHA256" \
  --expected-odoo-bin-sha256 "$ODOO_BIN_SHA256" \
  --expected-odoo-config-sha256 "$ODOO_CONFIG_SHA256"
```

The command rejects malformed or inconsistent identity values. It verifies
the canonical package, external trusted-artifact anchor,
`RELEASE-MANIFEST.json` identity, every manifest member and the exact release
tree before writing runtime material. The runtime script itself must be the
single-link, read-only member at
`deployment/dev29/runtime_setup.py` below
`/opt/odoo-accounting-cli-v3/releases/$RELEASE`. Odoo Python, `odoo-bin`,
and the Odoo configuration must match the supplied baseline hashes.
Production also rejects any interpreter other than the root-owned, single-link
`/usr/bin/python3.12` invoked with both isolated and no-site mode; its digest
must equal the independently supplied Odoo-Python executable digest. This gate
runs before any runtime object is created. `--test-root` is a unit-test-only
filesystem redirect and never claims that production interpreter gate.

Published paths are release-specific:

- config:
  `/etc/odoo-accounting-cli-v3/candidates/runtime-test-$RELEASE.json`
- secrets:
  `/etc/odoo-accounting-cli-v3/secrets/test/candidates/$RELEASE/{auth,receipt}.hmac`
- state:
  `/var/lib/odoo-accounting-cli-v3/test/candidates/$RELEASE/{auth,receipt}/state.sqlite3`

The two 32-byte secrets and their
`test-auth-dev29-`/`test-receipt-dev29-` key IDs are freshly generated and
role-separated. In production setup, config and secrets are `root:odoo 0640`;
the secret directory is `root:odoo 0750`; each mutable state directory is
`odoo:odoo 0700`; and the fixed child HOME is
`/var/lib/odoo-accounting-cli-v3-broker`, `odoo:odoo 0700`, and empty.
The public evidence and anchor parents are `root:root 0755`; the Dev29
supervisor staging and lease parents are `root:root 0700`.

Publication is serialized by a release-specific flock. Secrets and state are
created before the configuration, and the configuration is durably published
last. A handled failure rolls back only objects created by that invocation.
An exact rerun re-verifies every release, dependency, config, secret, state,
and HOME invariant and returns `"already_exists":true`; a partial or drifted
candidate is refused.

`--test-root` redirects absolute paths beneath a private non-system root and
exists only for unit tests. Production refuses redirected roots and script
path overrides. Successful output is one canonical JSON object and never
contains secrets, secret paths, or key IDs.

## Runtime-open policy candidate and installation

`runtime_open_discovery.py` is the non-approval discovery step used before the
reviewed manifest directory exists. It consumes an operator-supplied inventory
for the exact 32 targets and retained raw traces, parses the actual `execve`
chain, replaces only dynamic namespace and mount values with the reviewed
`@DEV29_*@` markers, and writes one candidate manifest per target plus
`DISCOVERY-REVIEW.json`:

```sh
/usr/bin/python3.12 -I -S \
  /opt/odoo-accounting-cli-v3/releases/$RELEASE/deployment/dev29/runtime_open_discovery.py \
  --inventory "$DISCOVERY_INVENTORY" \
  --output-directory "$DISCOVERY_REVIEW_DIR"
```

The discovery output is intentionally not approval, does not write an
`INDEX.json`, and is marked with `candidate_is_approval:false` and
`production_promotion_allowed:false`. Each review entry binds the candidate
manifest to the retained raw trace SHA-256, canonical path-set SHA-256, and
leader return code. Human review must still check the proposed path classes,
watch roots, mutable roots, Odoo business meaning, and trace provenance before
the directory is passed to `runtime_open_policy_source.py`.

When no reviewed runtime-open index exists yet, `run_read_suite.py` can be
started in discovery mode with `--runtime-open-discovery-inventory`. In that
mode it executes the normal read-suite targets under the same strace guard and
writes a private suite inventory fragment instead of a success bundle. That
fragment is deliberately scoped as
`odoo-accounting-cli-v3.dev29.runtime-open-discovery-suite-fragment.v1`: it
covers the suite's 31 traced children only and is not accepted by
`runtime_open_discovery.py` as a complete 32-target inventory. The separately
traced independent-verifier inventory must be added before the non-approval
review directory can be generated.

For a real host run, pass those discovery options through
`run_read_evidence.py launch` so the normal systemd unit, lease, mounted
closure, pinned worker, and outer evidence guards still apply. Discovery mode
requires `--runtime-open-discovery-inventory`,
`--runtime-open-discovery-static-closure-sha256`, at least one
`--runtime-open-discovery-watch-root`, and
`--runtime-open-discovery-sqlite-delta-contract-sha256`; it must not receive
`--expected-runtime-open-index-sha256`. The launcher returns a
`runtime-open-discovery-evidence.v1` result and does not run the normal
independent verifier or publisher.

After both fragments exist, merge them into the exact full inventory with the
same release member:

```sh
/usr/bin/python3.12 -I -S \
  /opt/odoo-accounting-cli-v3/releases/$RELEASE/deployment/dev29/runtime_open_discovery.py \
  --suite-fragment "$SUITE_FRAGMENT" \
  --verifier-fragment "$VERIFIER_FRAGMENT" \
  --output-inventory "$DISCOVERY_INVENTORY"
```

The merger refuses mismatched release, closure, watch-root, mutable-root, or
SQLite delta-contract identities. It also refuses any suite fragment that is
not exactly the first 31 fixed targets and any verifier fragment that is not
exactly the final `independent-verifier` target. The merged inventory is still
non-approval input; only the later reviewed policy-source and installed index
can satisfy the runtime-open execution gate.

The manifest directory is an external policy input reviewed by finance and
operations. It must contain exactly the 32 fixed target manifests named
`<target-id>.json`; each file is canonical JSON plus LF. The generator does
not discover policy from a child or from a trace:

Each manifest approves a static bootstrap template, not values copied from one
ephemeral systemd unit. The four mount-namespace identities, loop device, and
five canonical mount JSON arguments must use the fixed `@DEV29_*@` markers
produced by `runtime_open_trace.dynamic_bootstrap_template`. At execution the
suite validates the current attested values, substitutes them only into that
approved template, and then launches the child. The independent verifier and
publisher repeat the same materialization from the successful `execve` chain
in the retained raw trace. The builder rejects a concrete per-unit bootstrap,
a partial template, a misplaced marker, or any change to static argv.

```sh
/usr/bin/python3.12 -I -S \
  /opt/odoo-accounting-cli-v3/releases/$RELEASE/deployment/dev29/runtime_open_policy_source.py \
  --manifest-directory "$REVIEWED_MANIFEST_DIR" \
  --release "$RELEASE" \
  --expected-strace-sha256 "$STRACE_SHA256" \
  --expected-static-closure-sha256 "$STATIC_CLOSURE_SHA256" \
  --expected-runtime-module-sha256 "$RUNTIME_OPEN_TRACE_SHA256" \
  --expected-release-manifest-sha256 "$RELEASE_MANIFEST_FILE_SHA256" \
  --output "$POLICY_CANDIDATE"
```

The output `source_sha256` identifies the candidate bytes for independent
review. A generated candidate and its digest are not approval. Installation
requires the separately approved digest to be supplied again as
`--expected-source-sha256`, together with the independently obtained strace,
runtime validator, and release-manifest digests:

```sh
/usr/bin/python3.12 -I -S \
  /opt/odoo-accounting-cli-v3/releases/$RELEASE/deployment/dev29/runtime_open_manifest_builder.py \
  --source "$APPROVED_POLICY_SOURCE" \
  --expected-source-sha256 "$APPROVED_POLICY_SOURCE_SHA256" \
  --expected-strace-sha256 "$STRACE_SHA256" \
  --expected-runtime-module-sha256 "$RUNTIME_OPEN_TRACE_SHA256" \
  --expected-release-manifest-sha256 "$RELEASE_MANIFEST_FILE_SHA256" \
  --release-root "/opt/odoo-accounting-cli-v3/releases/$RELEASE"
```

`RELEASE_MANIFEST_FILE_SHA256` is the build output field
`manifest_file_sha256`: the SHA-256 of the exact pretty JSON plus LF bytes in
`RELEASE-MANIFEST.json`. It is intentionally different from the build output
field `manifest_sha256`, which is the semantic digest stored inside that
manifest and in the normal release identity. Never substitute one for the
other.

The builder executes the exact already-digest-verified validator bytes and
atomically installs the immutable policy under
`/opt/odoo-accounting-cli-v3/runtime-open-manifests/$RELEASE`. Raw traces are
created as root-only mode `0600` staging files below
`/var/lib/odoo-accounting-cli-v3/runtime-open-trace`, then atomically renamed
and sealed mode `0400` below the evidence-specific directory under
`/var/lib/odoo-accounting-cli-v3/evidence-private`. A per-target seal journal
remains until the private `MANIFEST.json` is durably published; stale staging
recovery never turns that pending state into public success.

Runtime-open path policies use four classifications. `immutable` paths must be
inside a watched closure root and may only be read, metadata-checked, or
executed. `mutable-state` paths are outside the watched closure and require the
SQLite delta verifier. `unix-socket` paths are exact client endpoints. The
`process-view` classification is reserved for successful read/metadata access
to `/proc/self`, `/proc/@self`, or `/proc/1` paths, and must not be included in
watch roots because those paths are dynamic process views rather than stable
filesystem artifacts.

# Dev8 deployment toolchain

This directory is the version-controlled source for the release-specific
deployment, staging, and evidence tools that target
`0.1.0.dev8-bd21ca07c168`.

The canonical runtime artifact remains the single release package named in
the scripts. These tools do not promote `/opt/odoo-accounting-cli-v3/current`,
change the Pi route, modify V2, or authorize production accounting writes.
They install and validate a side-by-side test candidate only.

`TOOLCHAIN-MANIFEST.json` binds the exact bytes of all 16 operational tools and
the read-only `SERVER-BASELINE.json` to toolchain version
`0.1.0.dev8-toolchain.3` and to the canonical application release.
`check_toolchain.py` verifies that binding in CI.

## Safety boundary

Dev8 targets only the `odoo_test` database and the `staged` capability
channel. It creates no V3 systemd unit and requires
`/opt/odoo-accounting-cli-v3/current` to remain absent. The scripts must not be
used to test accounting writes in a production database. The known production
dependency and metadata blockers remain recorded, so a successful Dev8 run is
not production-promotion approval.

Before uploading anything, compare the live server with
`SERVER-BASELINE.json`. The comparison must include both service identities,
all 12 critical-file byte hashes and full metadata fingerprints, the
`odoo_test` database UUID, the absent V3 paths, and the absent V3 units. Stop on
any difference. An empty `systemctl list-unit-files` result may return either
0 or 1; toolchain.3 accepts exit 1 only when both stdout and stderr are empty.

## Upload set

Create `/root/odoo-accounting-cli-v3-dev8-upload` as `root:root` mode `0700`.
Upload these six release inputs by basename:

```text
odoo-accounting-cli-v3-0.1.0.dev8-bd21ca07c168.tar.gz
0.1.0.dev8-bd21ca07c168.anchor.json
runtime-test-dev8.json
dev8-build-identity.json
dev8-github-ci.json
dev8-read-plan.json
```

Also upload `TOOLCHAIN-MANIFEST.json`, `SERVER-BASELINE.json`, and all 16
operational tools listed by the manifest. Every upload must be a root-owned,
single-link regular file with no group or world write bit. Do not upload old
Dev3-Dev7 packages or evidence. Verify the complete upload against the local
manifest before execution.

The runtime parents below must already be non-symlink directories with their
established safe ownership and modes; `dev8-runtime-setup.sh` deliberately
refuses to guess or repair them:

```text
/etc/odoo-accounting-cli-v3
/etc/odoo-accounting-cli-v3/secrets/test
/var/lib/odoo-accounting-cli-v3
/var/lib/odoo-accounting-cli-v3/test/candidates
```

## Execution order

Run as root with `umask 077`, `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, and
`LANG=C.UTF-8`. Capture stdout, stderr, and the numeric exit code of each of the
first three commands in a new root-only direct child of `/tmp`:

```text
bash dev8-install.sh
bash dev8-runtime-setup.sh
bash dev8-server-gate.sh
```

Do not continue unless every exit code is zero and every stderr file is empty.
The deployment-evidence directory must contain exactly the nine files named
`install.{stdout,stderr,exit}`, `runtime-setup.{stdout,stderr,exit}`, and
`server-gate.{stdout,stderr,exit}`, all `root:root` mode `0600`.

Next run the remaining phases in order. Each `/tmp` output path shown below
must not exist before its producer starts:

```bash
python3 -I -B dev8-stage-execution-tools.py \
  --read-plan /root/odoo-accounting-cli-v3-dev8-upload/dev8-read-plan.json \
  --read-evidence /tmp/dev8-real-read-evidence \
  --output-directory /tmp/dev8-execution-evidence

python3 -I -B dev8-persistence-audit.py \
  --read-evidence /tmp/dev8-real-read-evidence \
  --output-directory /tmp/dev8-state-evidence

python3 -I -B dev8-runtime-dependency-inventory.py \
  --output /tmp/dev8-gate-evidence/runtime-dependency-inventory.json

python3 -I -B dev8-canonical-package-negative-gates.py \
  --output /tmp/dev8-gate-evidence/canonical-package-negative-gates.json

python3 -I -B dev8-freeze-evidence.py \
  --read-evidence /tmp/dev8-real-read-evidence \
  --state-evidence /tmp/dev8-state-evidence \
  --execution-evidence /tmp/dev8-execution-evidence \
  --deployment-evidence /tmp/dev8-deployment-evidence \
  --dependency-inventory /tmp/dev8-gate-evidence/runtime-dependency-inventory.json \
  --negative-gates /tmp/dev8-gate-evidence/canonical-package-negative-gates.json

python3 -I -B dev8-verify-frozen-evidence.py
```

Create `/tmp/dev8-gate-evidence` as `root:root` mode `0700` before its two
producers. The execution stager requires its three fixed `/tmp` oracle-source
paths to be absent. A prior retained copy may be removed only after proving the
exact expected basename, root ownership, single-link regular-file type,
non-writable mode, and manifest SHA-256; otherwise stop.

The final verifier must report `all_checks_passed=true` and
`production_promotion_allowed=false`. The frozen evidence bundle records the
manifest, exact tool bytes, deployment journals, real Odoo receipts, SQL
oracles, audit state, and live isolation result.

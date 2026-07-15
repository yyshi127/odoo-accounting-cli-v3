# Dev8 deployment toolchain

This directory is the version-controlled source for the release-specific
deployment, staging, and evidence tools that target
`0.1.0.dev8-bd21ca07c168`.

The canonical runtime artifact remains the single release package named in
the scripts. These tools do not promote `/opt/odoo-accounting-cli-v3/current`,
change the Pi route, modify V2, or authorize production accounting writes.
They install and validate a side-by-side test candidate only.

`TOOLCHAIN-MANIFEST.json` binds the exact bytes of all 16 operational tools,
the read-only `SERVER-BASELINE.json`, the narrowly scoped
`SERVER-SERVICE-TRANSITION.json`, and `PRIOR-EVIDENCE-DISPOSITION.json` to
toolchain version `0.1.0.dev8-toolchain.12` and to the canonical application
release. `check_toolchain.py` verifies that binding in CI. A frozen evidence
identity is the exact string `RELEASE--TOOLCHAIN_VERSION`; for this run it is
`0.1.0.dev8-bd21ca07c168--0.1.0.dev8-toolchain.12`.

The canonical source release is not established by the version string alone.
Before any server upload, the exact manifest must be committed with an SSH
signature and the annotated tag `toolchain/0.1.0.dev8-toolchain.12` must point
to that same commit, be SSH-signed by the dedicated release key fingerprint
`SHA256:GFGfgQoBqTNZZ47Ts+lDRURoCwpmSv9/o24gzkFQjXs`, and state the toolchain
manifest SHA-256 in its annotation. Verify both the remote tag object and its
peeled commit after push. The tag and toolchain version are immutable and must
never be moved or reissued for different bytes.

## Safety boundary

Dev8 targets only the `odoo_test` database and the `staged` capability
channel. It creates no V3 systemd unit and requires
`/opt/odoo-accounting-cli-v3/current` to remain absent. The scripts must not be
used to test accounting writes in a production database. The known production
dependency and metadata blockers remain recorded, so a successful Dev8 run is
not production-promotion approval.

Before uploading anything, compare the live server with the immutable original
`SERVER-BASELINE.json` plus the manifest-bound service-transition history. Its
three full observations retain the Odoo PID `2316421`, `2344733`, and current
`2576660` identities; the top-level `observation` and `services` are an exact
projection of the third observation. The Pi identity remains unchanged in all
three observations. Two read-only systemd-journal segments link the adjacent
qualified observations: the first contains ten ordered Odoo stopping/starting
pairs and the second contains three, for 13 cumulative restart cycles. Both
segments explicitly record that complete intermediate process identities are
unavailable. They therefore do not claim which identity occupied any interval
between the three full observations. Actor attribution and maintenance
authorization remain unverified. The transition control does not retain a
content-addressed raw journal export, so its hard-coded timestamps are a
manifest-bound chronology record, not an independent journal-source receipt.
All 12 critical-file byte hashes and full metadata fingerprints, the
`odoo_test` database UUID, the absent current route, and the absent V3 units
must still match their contracts. Stop on any other difference. The original
baseline remains byte-for-byte unchanged and continues to record the
pre-deployment PIDs and V3-path absence. An empty
`systemctl list-unit-files` result may return either 0 or 1; the toolchain
accepts exit 1 only when both stdout and stderr are empty.

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

Also upload `TOOLCHAIN-MANIFEST.json`, `SERVER-BASELINE.json`,
`SERVER-SERVICE-TRANSITION.json`, `PRIOR-EVIDENCE-DISPOSITION.json`, and all 16
operational tools listed by the manifest. Together with the six release inputs,
the upload directory must contain exactly 26 files. Every upload must be a
root-owned, single-link regular file with no group or world write bit. Do not
upload old Dev3-Dev7 packages or evidence. Verify the complete upload against
the local manifest before execution.

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

The real-read runner normalizes its copied `read-plan.input.json` to
`root:root` mode `0600`, matching the persistence and freeze evidence
contracts even though the immutable upload source is mode `0400`.
The persistence audit separately verifies the authentication content digest
and compares consumed-token state with the canonical full signed-request
digest used by the replay guard. The rerun does not clear sandbox state: it
proves the retained toolchain.8 four-read state is an exact prefix, appends
four fresh token/receipt/audit records, and verifies the complete eight-event
hash chain. This preserves audit continuity while preventing replay.
The persistence snapshotter never opens the live SQLite database through
SQLite. It binds the live main, WAL, and SHM identities with no-atime,
no-following read-only descriptors, copies and re-hashes only main and WAL into
a private root-owned staging directory, and lets SQLite rebuild SHM there. A
verified snapshot is published without overwrite by inode-bound hard link;
failure cleanup removes only the inode it created. This keeps live WAL/SHM
bytes and metadata unchanged while retaining committed rows present only in
WAL. A rollback journal or non-WAL database header is rejected.
The freezer and final verifier derive their expected live service identities
from the validated, manifest-bound original baseline and latest transition
observation. The history and journal records classify the observed restart
series as out of band; they do not verify an actor or maintenance authorization,
establish missing intermediate identities, authorize a production write, or
permit production promotion.
The final verifier deserializes frozen WAL-mode SQLite snapshots into an
in-memory connection with exclusive locking before enabling query-only mode;
this avoids filesystem WAL access without changing the frozen bytes.
Financial oracle reports are bound to their capability, parameters, token,
receipt, and record count through the exact four-entry request-roundtrip
record; the SQL report format itself does not duplicate a capability ID.

Create `/tmp/dev8-gate-evidence` as `root:root` mode `0700` before its two
producers. The execution stager requires its three fixed `/tmp` oracle-source
paths to be absent. A prior retained copy may be removed only after proving the
exact expected basename, root ownership, single-link regular-file type,
non-writable mode, and manifest SHA-256; otherwise stop.

The prior toolchain.8 evidence and anchor remain retained with their original
bytes as non-final evidence. They failed the final-verifier gate after the
baseline service PID changed and must never be relabelled or reused as final
evidence. `PRIOR-EVIDENCE-DISPOSITION.json` records that disposition.
Its `invalidating_service_observation_id` binds the disposition to the first
full transition observation, whose last timestamp remains the historical
disposition time; subsequent observations do not relabel that prior evidence.

Freeze is pending for the new evidence identity. All dynamic evidence must be
rerun under the effective service identities: deployment gate captures, real
reads, SQL oracles, persistence audit, dependency inventory, canonical-package
negative gates, pre-freeze isolation, freeze, and final verification. No old
dynamic output may be copied into the new bundle merely because its business
result is unchanged.

Only the final verifier may establish `all_checks_passed=true`; it must still
report `production_promotion_allowed=false`. Until that succeeds, the new
bundle is pending and not final. The frozen evidence bundle records the
manifest, exact tool and control bytes, deployment journals, real Odoo
receipts, SQL oracles, audit state, and live isolation result.

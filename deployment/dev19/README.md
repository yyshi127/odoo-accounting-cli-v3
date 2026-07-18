# Dev19 sandbox-isolation gate

Dev19 is the E00b gate that must run after a passing Dev18 E00a receipt and
after a dedicated sandbox has been provisioned. It may only make a sandbox
eligible for a separate write-staging review. It never authorizes sandbox
provisioning, an accounting write, production access, or a registry change.

## Current source status

`sandbox_isolation_gate.py` contains strict policy, observation, recovery,
release, host-identity, endpoint-denial, freshness, and fail-closed evaluation
contracts. Its public `evaluate()` function accepts caller-supplied data only
for contract tests. Even when every contract condition matches, it returns
`isolation_gate_passed=false`,
`eligible_for_sandbox_write_staging_review=false`, and the trust blocker
`live_evidence_unverified`.

The operational CLI accepts only the canonical direct invocation:

```text
/usr/bin/python3 -I -B -S /opt/odoo-accounting-cli-v3/releases/<release>/deployment/dev19/sandbox_isolation_gate.py --policy <absolute-policy-path> --expected-policy-sha256 <lowercase-sha256>
```

It verifies the raw `/proc/self/cmdline`, process executable, Python flags,
immutable installed release tree, canonical package, manifest dependencies,
fixed external release approval, fixed external host-context approval, pinned
Dev18 verifier and exact E00a replay, and the recovery receipt, pair manifest,
and backup bytes. The opening policy approval binds the exact raw release,
host-context, and recovery approval roots; every downstream verifier must use
those same digests, and the CLI rereads the policy plus all four approval roots
before its terminal decision. It verifies the approved host context both
before and after the prerequisites. After independent policy approval and
before expensive release work, it reads live UTC and monotonic clocks and
requires the policy to be active. It repeats the check after all prerequisites,
rejecting expiry, wall-clock rollback, monotonic rollback, or a stalled wall
clock that outlives the remaining policy window. No CLI clock override exists.
`--help`, malformed invocations, and every incomplete trust phase return a
one-line non-authorizing JSON error and exit code 2.

After those prerequisites the CLI still intentionally returns
`live_collector_unavailable` with exit code 2. Therefore this directory does
not contain an E00b receipt and must not be used as promotion evidence.

Every trusted JSON reader bounds the read and compares file identity before,
during, and after it. On Linux it opens `/` and every ancestor one component at
a time with pinned directory descriptors plus
`O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, then opens the final basename relative to
the retained parent descriptor. Every directory and file must be root-owned
and non-group/world-writable; files must be regular and single-link. The open
inode and the retained directory entry must remain identical through the read
or streaming hash. Missing kernel flags and every descriptor/metadata drift
fail closed. The expected raw policy digest must come from an independent
review channel.

The policy path and digest supplied on the command line are not themselves a
trust root: the exact raw policy digest, nonce, validity, release, E00a report,
and sandbox generation must first appear in the fixed
`/etc/odoo-accounting-cli-v3/approved-e00b-policies.json` allowlist. Release
approval is separately not selected by the policy: the release identity must
appear in the fixed
`/etc/odoo-accounting-cli-v3/approved-releases.json` allowlist. Current-host
approval is likewise fixed at
`/etc/odoo-accounting-cli-v3/approved-host-context.json`; it binds the exact
E00a report/observation, hostname, machine and boot IDs, and the device, inode,
and link identity of the user, mount, PID, network, UTS, IPC, cgroup, and time
namespaces. The exact recovery receipt, pair manifest, backups, E00a/release,
and old/new database and generation identities must also appear in
`/etc/odoo-accounting-cli-v3/approved-recovery-drills.json`. These files are
approval artifacts, not files the gate may create;
an independent root-controlled deployment step must install or revoke them.
The policy approval row also binds the raw SHA-256 of the three supporting
approval files, so a later semantically valid replacement is rejected.

These fixed root-owned files are not yet offline-signed approval evidence and
do not separate an already-compromised root executor from the approver. The
gate also has no nonce reservation/consumption ledger and emits no signed final
report. Those gaps remain promotion blockers even when all current contract
checks pass.

The pinned-descriptor logic protects the two trusted file readers. The release
tree inventory still uses pathname traversal, and neither openat nor root-only
modes defend against a root-controlled bind mount or a compromised mount
namespace. Those broader snapshot and threat-model limits remain explicit
live-collector blockers.

`sandbox_namespace_probe.py` remains an untrusted helper. Before reading stdin
or writing stdout/stderr it requires exactly three distinct anonymous PIPEs at
FD 0/1/2, rejects every extra inherited FD, and binds real/effective/saved/
filesystem UID and GID values. It does not write payload bytes, but its canary
uses an `O_WRONLY` open and successful socket connections can create server-side
logs. A future trusted parent must create fresh PIPEs, use `close_fds`, bind the
child PID/namespaces/request/output, and treat the output as facts only.

## Live evidence still required

Before the CLI can issue a trusted E00b result, the same root-only process must:

1. reuse the manifest-pinned Dev18 PostgreSQL collector for the independent
   sandbox cluster, complete catalog, UUID, role, process, socket, and
   configuration closure;
2. bind the Odoo systemd unit, unit files, invocation, PID, cgroup, executable,
   command line, environment, UID/GID, file descriptors, and mount/network/PID/
   user namespaces before and after every probe;
3. enter the actual Odoo service mount and network namespaces, create fresh
   stdio PIPEs, close inherited
   descriptors, drop supplementary groups and UID/GID, and measure denial of
   every protected production path, Unix socket, database endpoint, old state,
   secret, and outbound route;
4. read Odoo configuration and immutable runtime/registry bindings, and use
   read-only Odoo ORM plus an attested PostgreSQL oracle to verify company,
   executor/approver separation, ACLs, record rules, cron, mail, and external
   integrations;
5. verify an independently signed, time-limited and non-replayed recovery-drill
   approval/receipt; recompute old state/evidence inventories, key fingerprints,
   restored database UUID/generation, seed oracle and failure-atomic evidence.
   The read-only gate must never perform the recovery drill itself; and
6. bind a fresh policy nonce and run ID to wall and monotonic capture times,
   consume that nonce in a root-controlled audit ledger, and sign the final
   report for downstream verification.

All protected identities must be captured before and after. A changed service,
process, namespace, mount, configuration, release, production identity, state,
or recovery artifact fails closed.

## External prerequisites

No target E00b run is possible until E00a passes. A 2026-07-18 lightweight
read-only recheck reports a `12,913,868,800`-byte storage shortfall and the
same unapproved group-writable PostgreSQL socket authority; it is not an E00a
receipt. A dedicated PostgreSQL cluster,
Odoo service, sandbox database/company, executor, independent approver,
isolated state/secrets, kernel network policy, and an authorized recovery drill
also do not yet exist. None of those resources may be created or changed by
this contract stage.

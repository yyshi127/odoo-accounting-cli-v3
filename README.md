# Odoo Accounting CLI V3

Production-oriented accounting capability gateway for Odoo 19 and Pi Agent.

V3 is built and released independently from V2. Its authoritative source is
this repository; the trusted server release root is
`/opt/odoo-accounting-cli-v3/releases/`.
V2 remains installed and runnable during side-by-side verification.

## Source boundary

This directory is the only local source root for V3. The V2 Odoo module,
historical remote snapshots, and deployment staging directories are external
inputs and must not contain V3 source files.

Five reads are staged execution candidates for the dedicated test environment:
the ACL-filtered capability registry, trial balance, historical AR and AP open
items, and multicurrency balance. Staging is separate from enablement: no
capability is yet marked enabled or routed through Pi. No write capability is
staged or enabled;
sandbox and production remain closed until their approval, idempotency,
verification, recovery, and evidence gates pass.

## CLI boundary

The wheel-installed `odoo-accounting-cli-v3` command provides development and
packaging smoke coverage. A deployed accounting read uses the exact,
manifest-covered `<release>/bin/odoo-accounting-cli-v3` launcher and a runtime
configuration bound to the retained canonical tar. This keeps wheel contents,
working directories, and copied Pi code outside the production business-code
trust path. The standard write-operation lifecycle commands are present but
fail closed. They never return a simulated Odoo success.

```text
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 registry list
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 registry get --capability-id acct.gl.trial_balance.v1
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 release identity
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 read --runtime-config /absolute/root-managed/runtime.json --request-json '{...}'
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 operation prepare --request-json '{...}'
```

The bare wheel command is limited to development smoke such as `--version` and
registry-contract inspection; it is not a production accounting entry point.

The Dev19 E00b sandbox-isolation gate is also deliberately non-authorizing.
It pins the installed release, E00a and recovery evidence, host identity,
independently installed approval roots, live UTC/monotonic policy window, and
an isolated namespace-probe contract, but still returns
`live_collector_unavailable`. It cannot issue an E00b receipt or enable a
sandbox write until the trusted live collector, nonce ledger, signed report,
and real sandbox evidence exist. See `deployment/dev19/README.md`.

Dev20 adds a second dormant recovery vertical slice for a pristine sandbox
draft vendor bill. Like the existing draft customer-invoice recovery, it uses
a separate approved and idempotent recovery operation, binds the complete move
and line graph, and permits only an exact `draft` to `cancel` state change. It
requires and fingerprints Odoo 19's standard stock-move, COGS, and landed-cost
link fields, rejecting any linked effect. It does not stage or enable the
vendor-bill capability and has no real-Odoo write receipt; production execution
remains closed. A trusted installed/custom-module graph remains a staging gate.

Dev21 adds a canonical local evidence contract for that module-graph
prerequisite, derived from every installed module's name and `latest_version`,
with strict schema, ordering, and digest validation. The graph is bound into
precheck and execution evidence and into both draft recovery plans. For the two
dormant pristine-draft customer-invoice and vendor-bill recovery slices, it
closes the material stored-and-writable `account.move` and `account.move.line`
snapshot/guard field sets observed on the target; an optional field may be
absent only when its trusted provider module is absent. Tokens, signatures, and
PDF/Facturae/UBL binary fields retain presence only, with binary reads using
`bin_size=True`.
Execution and verification each take a transaction-scoped module-table lock,
but a narrow post-commit module-upgrade interval remains: drift fails closed
without reporting success, while an already committed effect may require
reconciliation. No write capability is staged or enabled, no real-Odoo sandbox
write/recovery receipt exists, and production execution remains closed.

Dev28 hardens every staged Odoo read on the shell's dedicated PostgreSQL
connection before the first V3 ORM query. The connection must start idle with
autocommit disabled; V3 explicitly requests `READ ONLY` and `REPEATABLE READ`,
attests both server settings, binds a transaction-local marker, re-attests the
same transaction after the handler, and releases the detached JSON result only
after rollback returns libpq to `IDLE`. A static source gate rejects ORM writes,
raw SQL, transaction control, privilege switching, dynamic write-method access,
and network imports for the direct patterns encoded in the reviewed read
dependency graph; it also pins the package-parent plus explicit transitive
import closure rooted at `odoo.bootstrap`, with every explicit internal and
external import binding fixed to its reviewed source module. Direct
attribute/subscript mutations are denied except for explicit local-state
allowlists. The privileged
transaction helper has a source digest and separate structural allowlist; the
complete public bootstrap and executor sources are also digest-pinned, and
critical bindings cannot be reassigned.
The release builder rejects import-shadowing `src` roots and tracked
bytecode/native importables. For business data, PostgreSQL `READ ONLY` is the
authoritative barrier for Odoo operations issued on that dedicated connection.
The static policy does not prove that second
connections, files, or network effects are absent. Authentication replay and
receipt audit SQLite state still persist by design, and no Dev28 exact-release
target Odoo receipt exists yet. Reads remain staged and none is enabled.

Dev29 packages the target Odoo server, installed module graph, virtual
environment, and Python/native dependency boundary into a release-specific,
externally anchored trust closure. The Odoo configuration remains separately
sealed because it may contain credentials. A composite test-only suite fixes
five positive reads, seven exact policy rejections, the rollback-boundary
probe, independent PostgreSQL financial oracles, state/audit deltas, and an
independently implemented evidence verifier. It runs only in a private read-only mount namespace
and refuses an image, loop-device inode, service identity, database identity,
module graph, or dependency that drifts. A single supervisor owns activation,
direct demoted children, independent validation, and mandatory cleanup; an
external success anchor is impossible until cleanup and absence of leaked
mounts, loop devices, or child processes are proven. Static dependency
discovery is supplemented by a digest-pinned, externally anchored runtime-open
policy. The suite, independent verifier, and publisher each reconstruct the
approved policy source from the exact installed index plus all 32 canonical
target manifests; the validator executes only release-manifest-bound bytes.
Raw traces are retained root-only and independently reopened and reparsed
before publication. The target's capacity recovered above the
conservative floor in the latest point-in-time probe, but the exact Linux
lifecycle gates, sustained service-continuity check, and target run are still
outstanding. No Dev29 target receipt exists and nothing has been promoted or
routed.

All machine-facing output is JSON. Real accounting success additionally
requires an Odoo-bound signed receipt. CLI-Anything v0.4.0 supplies the CLI and
test-harness conventions only; Odoo 19 remains the backend and accounting
source of truth. See `docs/CLI_ANYTHING_V040_ADOPTION.md`.

## Development

```powershell
python -m pip install -e ".[test]"
python -m pytest
python tools/check_source_boundary.py
```

The acceptance gates and current evidence limits are in `tests/TEST.md` and
`docs/BASELINE.md`. Deployment, upgrade, promotion, and rollback are defined in
`docs/DEPLOYMENT.md`.

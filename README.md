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

The current Dev266 development tree registers 37 capabilities: 13 reads
and 24 writes. The reads are staged only for `test`; no capability is enabled
or production-routed. All 24 writes have concrete source paths, 22 can reach
capability-specific ORM prechecks, and payment registration plus deferred
creation stop before ORM access. All write evidence remains `declared` with no
retained real-Odoo receipt, so the real-Odoo write-evidence count is 0/24.

All thirteen registered read capabilities now have trusted, statically admissible
handlers for the dedicated test environment. Twelve run through the constrained
Odoo read executor, including multi-company gross-balance translation; operation
diagnostics reads only the trusted local write store. They remain
`contract_tested` and staged for `test`, with no production enablement or
independent Goal evidence yet. Staging is separate from enablement: no
capability is yet marked enabled or routed through Pi. No write capability is
staged or enabled;
sandbox and production remain closed until their approval, idempotency,
verification, recovery, and evidence gates pass.

Dev263 retains `read-evidence-index.v2` only as a legacy structural-audit
format. Its checker strictly reopens the frozen source bundle and validates the
shape and internal bindings of `accounting_oracle`, `live_odoo`, `pi_e2e`,
`release_identity`, and `security_negative` bodies. That is useful tamper and
regression coverage, but it is not an external trust decision: the checker can
read the HMAC signing secrets, and the collector/verifier identities are labels
rather than independently held public-key identities. A v2 result must report
`external_read_evidence_verified:false` and
`goal_evidence_admissible:false`, regardless of its structural result.

Dev263 connects the Linux-only SSHSIG boundary to an active-only v3 verifier,
nine fixed Ed25519 roles, a signed scope and approval interval, an exact active
record, and a SQLite `DELETE` rollback-journal publication ledger with
trigger-enforced one-way state transitions.
The public API derives its release trust, clock, owner policy, active pointer,
and ledger; callers cannot select a mode, key, trust root, time, or owner
override. Repeated publication requests recover only the identical committed
payload, while conflicting nonce, authorization, run, index, signature, or
sequence bindings fail closed. Expired approvals, hot rollback journals,
replay, tampering, and non-`PUBLISHED` rows are rejected.

Dev266 hardens that admission ledger without changing the capability inventory
or enabling any route. Every in-process SQLite connection and direct database
file check now shares one process-wide lifecycle lease. Independent writers and
existing-only verifier snapshots also contend on one persistent, private,
fixed-inode `.writer.lock`; readers open but never create it. A writer acquires
the lock before preflight and holds it through `BEGIN IMMEDIATE`, commit,
connection close, fsync, the post-close content check, and
confirmation-descriptor close.
A rollback journal that vanishes during a writer preflight is accepted only
after the same private database inode and parent are reverified and the journal
remains absent; replacement, reappearance, unsafe metadata, and every other
I/O error fail closed. The durability descriptor and live path must still
identify that same inode before and after fsync, followed by one final full
path/sidecar check.
After commit, the still-open SQLite connection serializes the exact committed
database image. The fsynced descriptor and an `O_NOFOLLOW` post-close reopen
must both produce that same SHA-256 content identity in addition to matching
the private path metadata, so immediate inode reuse cannot disguise different
ledger bytes even on a filesystem with coarse timestamps. The linearization
point is this equality while the confirmation descriptor remains open; an
unconfirmed close still returns outcome-unknown. As documented in runtime
configuration, arbitrary code running later as the private state-file owner is
outside this software-only boundary and still blocks production promotion.
Unknown commit outcomes retain their mandatory reconciliation error
even if connection close or post-close durability verification also fails.

This is not yet Goal evidence. The v3 raw bodies are normalized contract
summaries, not the original Odoo/SQL-oracle/Pi/negative-control source objects,
so even a valid cryptographic closure reports
`external_read_evidence_verified:false` and
`goal_evidence_admissible:false`. Sealed verification and a self-contained
final-evidence closure are also not implemented. At the Dev264 boundary, all 12
then-registered reads therefore remained `contract_tested`, test-staged, not
enabled, and not Goal-evidence ready.

Dev264 adds two deliberately offline contract boundaries without changing that
status. `read_evidence_raw_v3` revalidates a complete Registry, derives the
exact 12 read-capability contracts, and binds the canonical v3 scope. Its
`live_odoo` and `accounting_oracle` contracts check successful
request/result/receipt shapes against the real input/output schemas and bind
the explicitly declared request, result, and oracle company fields;
`release_identity` checks release/scope bindings; `security_negative`
checks requests, exact errors, authentication witnesses, and zero side effects
with no receipt. Pi full-raw evidence is deliberately rejected here and remains
the responsibility of the existing `PiEvidenceVerifier`, whose real broker
exchange contract is not duplicated. The raw validator does not verify receipt
signatures, the oracle implementation or query semantics, company-scoped
database execution, read-only transaction, or a trusted producer/attestor.
A disclosed technical rate-source company is type-checked but is not
misclassified as a requested business company.
A successful result still reports source trust, external evidence, Goal
admission, and production promotion as false.
`read_evidence_publication` validates only the canonical JSON contract for a
future publication receipt. It performs no ledger lookup, filesystem scan,
retained-copy comparison, or publisher signature verification and explicitly
reports every such provenance claim as false. Neither validator is connected
to the CLI or active evidence gate in Dev264.

Dev265 adds one `contract_tested`, test-staged read,
`acct.refund.post_reconcile_eligibility.v1`, and one critical, `declared`,
unstaged and disabled write, `acct.refund.post_reconcile_origin.v1`. The read
binds an exact pristine V3 refund/origin graph, the single receivable or payable
term-line pair, full or partial outcome, immutable bindings, company, currency,
journal, date, partners, rank preconditions, and expected residual/payment
states. The write invokes `action_post` only after rebuilding that approved
graph and accepts Odoo 19's automatic origin reconciliation only when the exact
partial/full result graph and allowed deltas verify.

For this one capability, the control add-on overrides partner rank handling only
inside the trusted process-local V3 execution scope, for a non-superuser member
of the executor group, the exact approved `customer_rank`/`supplier_rank`, an
increment of one, and the exact selected/commercial-partner union. It performs
that rank increment synchronously in the posting transaction; every ordinary
Odoo call falls back to native behavior. Local add-on, fake-ORM, bootstrap,
gateway, Pi-corpus, and Bridge tests cover this boundary, but no real Odoo write
receipt exists. Recovery is manual escalation, and the capability remains
unavailable in sandbox and production.

Dev257 adds the declared, disabled
`acct.bank.statement_compensate.v1` contract. It preserves a completed,
verified, database-finalized bank-import graph and creates a separate
whole-batch opposite-signed statement from the exact retained available plan;
it is not a delete, partial correction, or implicit unreconciliation path.
Control add-on version `19.0.0.7.3` serializes supported ORM mutations of bank
statements, statement lines, their linked moves and journal items, and their
reconciliation records on the same company-and-journal transaction lock.
Specialized compensation and generic recovery acquire the complete ordered
graph-and-sequence lock set before strict row locks. The execution transaction
rejects unexpected source-to-compensation activity before commit; fresh
verification reacquires the sequence lock and revalidates the receipt-bound
source and compensation graphs without treating business-date ordering as
transaction ordering.
Current production-routed imports do not provide the required qualifying plan,
no real two-connection Odoo concurrency test or sandbox receipt exists, and the
capability is neither staged nor enabled. The add-on and offline tests therefore
do not establish a production concurrency or accounting-write result.

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
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 registry audit
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 registry get --capability-id acct.gl.trial_balance.v1
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 release identity
/opt/odoo-accounting-cli-v3/releases/<release>/bin/odoo-accounting-cli-v3 evidence goal-readiness --current-path /opt/odoo-accounting-cli-v3/current
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

Pi scenario acceptance does not trust a retained report's own passing fields.
`evidence pi-scenario-report-check` recomputes it from the original raw trace,
the independent capture binding, root-managed authorities, and the routed
release/registry, then emits a purpose-separated HMAC recomputation
attestation. `goal-readiness` and `final-evidence-manifest-check` derive the
only accepted key path from the executing release as
`/etc/odoo-accounting-cli-v3/trust/pi-evidence/<release>/attestation-keys.json`;
the retained path must match exactly and cannot select another key file. They
then verify that attestation and its exact claims. Zero-trace, unsigned
self-reported, forged, or alternate-key-path checks fail closed. On the Linux
deployment path, the key file must be an absolute canonical root-owned,
single-link non-symlink with exact mode `0400` or `0600`, and all ancestors must be
root-owned directories that are not group/world writable; verification also
uses no-follow, open-file identity, before/after identity, and bounded-read
checks. The contract-tested FD4 terminal-answer boundary is not the complete
live Pi 48-scenario trace gate, which has not yet been evidenced for the target
release. See `docs/PI_SCENARIO_ACCEPTANCE.md`.

## Development

```powershell
python -m pip install -e ".[test]"
python -m pytest
python tools/check_source_boundary.py
```

The acceptance gates and current evidence limits are in `tests/TEST.md` and
`docs/BASELINE.md`. The machine-checkable capability-registry audit procedure
and its retained Dev218 target-host example are recorded in
`docs/CAPABILITY_AUDIT.md`; current counts must come from the exact release's
`registry audit` result. Pi natural-language scenario scoring is defined in
`docs/PI_SCENARIO_ACCEPTANCE.md`. Deployment, upgrade, promotion, and rollback
are defined in `docs/DEPLOYMENT.md`.

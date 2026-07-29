# V3 test plan

Status: living acceptance plan. A capability is incomplete until its required
tests have produced reviewable evidence.

## Test-plan chronology

The repository's initial registry, contract, authentication, state-machine,
receipt, release, and trial-balance tests existed before this formal plan was
written. This document therefore records and extends the current test strategy;
it must not be cited as evidence that those initial tests were written first.
New capability work should add or update its cases here before implementation
where practical, then record actual execution evidence separately.

## Safety boundary

- Production-accounting writes are not authorized.
- The observed database named `codex_sgf_test_20260713_01` is not a write sandbox
  until its purpose, owner, reset method, and allowed companies are confirmed.
- `acct.registry.list.v1`, `acct.gl.trial_balance.v1`,
  `acct.ar.open_items.v1`, `acct.ap.open_items.v1`, and
  `acct.multicurrency.balance_read.v1`,
  `acct.move.draft_cancel_eligibility.v1`,
  `acct.report.financial_read.v1`, and `acct.tax.report_read.v1` are the eight
  trusted, statically admissible read-handler targets staged for the isolated
  `test` environment. Multi-company consolidation and operation diagnostics
  remain the two declared but unimplemented read gaps.
- The financial and tax report reads are fixed to posted entries,
  `all_report_eligible` journals, no requested line expansion, and the bound
  company currency. They must execute against real Odoo inside the attested
  PostgreSQL read-only transaction. Both remain `contract_tested` and
  `test`-staged only; neither is production-enabled.
- No capability is enabled and no write capability is staged.
- The current registry contains 17 write capabilities: the original 14-capability
  baseline plus `acct.journal.entry_create.v1`, `acct.move.post.v1`, and
  `acct.move.draft_cancel.v2`. These three Phase B additions remain
  `declared`, have no retained evidence receipts, and are neither staged nor
  enabled. `tests/test_phaseb_move_write_capability_closure.py` is an offline
  schema, semantics, idempotency, signed-failure, tamper, and dispatch test; it
  does not execute Odoo and is not real-Odoo sandbox or production evidence.
- The three Phase B handlers currently scope `tracking_disable` to their Odoo
  create/write/post call so uncontrolled mail-thread records cannot escape the
  exact accounting graph. The signed V3 operation anchor and receipts are the
  intended audit authority, but this is not yet promotion evidence. Before any
  staging, real Odoo must prove the complete user/company/request/approval/move
  trace (including `create_uid`, `write_uid`, `write_date`, immutable bindings,
  control anchor, and signed receipts), and either explicitly accept suppressed
  chatter or replace it with an exact verified mail tracking graph.
- Unit mocks can test contracts and control flow, but cannot satisfy a real-Odoo
  or financial-correctness gate.
- V2 remains available during V3 side-by-side construction; V3 tests must not
  mutate or replace V2.

If a test cannot prove its database and company scope before a write, it must
fail closed before calling Odoo.

## Evidence rules

Every recorded run must identify:

- V3 version, Git commit, release digest, and registry digest;
- installed package digest and resolved CLI executable;
- Odoo instance, database name and UUID, Odoo version, company, and user;
- environment (`unit`, `test`, `sandbox`, or `production`);
- test case, request digest, result, timestamps, and relevant receipt IDs; and
- for writes, operation, approval, idempotency, Odoo record, verification, and
  recovery identifiers.

Secrets, passwords, service tokens, and signing keys must never appear in test
arguments, stdout, fixtures, snapshots, or evidence bundles. A test report is
not an accounting receipt. An unsigned or unverifiable receipt is a failed gate.

## Gate A — source, registry, and release

| ID | Test | Pass condition |
|---|---|---|
| A01 | V3 source boundary | No V3 source is loaded from V2, Pi Bridge, staging, backup, or server working directories |
| A02 | Registry completeness | Every capability has a unique ID, business description, strict input/output schema, access type, risk, Odoo permissions, company scope, approval, idempotency, verification, recovery, evidence, and enablement metadata |
| A03 | Schema strictness | Unsupported schema keywords and unknown parameters are rejected recursively |
| A04 | Enablement evidence | No capability is enabled unless receipts required for its access type and target environment exist and verify |
| A05 | Deterministic release | Two builds from the same clean commit produce the same source manifest and package digest |
| A06 | Exact installation | Missing, modified, extra, duplicate, non-canonical, or symlinked package files cause verification failure |
| A07 | Version agreement | Git commit, package version, release manifest, server release, Odoo adapter, and Pi Bridge report one verifiable identity |
| A08 | V2 isolation | Building, installing, testing, upgrading, and rolling back V3 do not alter the V2 directory or runtime |

## Gate B — contracts and control plane

| ID | Test | Pass condition |
|---|---|---|
| B01 | Request context | A valid short-lived signed context binds principal, Odoo instance, database name/UUID, user, company, allowed companies, environment, and audience |
| B02 | Context attacks | Tampered, expired, wrong-audience, cross-database, cross-company, and unauthorized-user contexts are rejected before capability execution |
| B03 | Parameter round-trip | Every declared field and value reaches preview, approval digest, executor, verification, and receipt unchanged unless an explicit normalized form is part of the schema |
| B04 | State transitions | Writes can follow only prepare → precheck → waiting approval → approved → executing → verifying → completed/failed/recovering/recovered transitions |
| B05 | Approval binding | Approval binds the exact immutable operation digest, approver, policy, revision, nonce, and expiry |
| B06 | Approval attacks | Self-approval where prohibited, expiry, replay, content mutation, revision change, and unauthorized approver are rejected |
| B07 | Idempotency | The same key and digest returns the original operation/result; the same key with different content is rejected |
| B08 | Idempotency scope | Keys cannot collide or leak across Odoo instance, database UUID, environment, company, capability, or declared semantic scope |
| B09 | Concurrency | Simultaneous duplicate requests create at most one durable operation and at most one Odoo business effect |
| B10 | Trusted execution | Fabricated, reordered, or tampered execution and verification results cannot advance the state machine |
| B11 | Receipt integrity | Request/result/registry/release/database/user/company bindings and receipt signatures are verified before success is returned |
| B12 | Durable restart | After process or host restart, operation state, nonce consumption, locks, idempotency result, audit chain, and recovery status remain correct |
| B13 | Atomic approval acceptance | Nonce consumption, append-only approval evidence, awaiting-to-approved state change, and audit event commit together or all roll back |
| B14 | Persistence migration | Exact schema v1 migrates transactionally to v2 without changing legacy operation/audit bytes; invalid legacy state remains v1 and fails closed |

## Gate C — installed CLI subprocess

The canonical tar must be installed into a clean immutable release directory.
Tests execute from outside the repository with development import paths removed
and invoke that release's manifest-covered launcher by exact absolute path. A
separate wheel smoke verifies Python packaging and registry inspection, but the
wheel is not an alternate production business-code source.

| ID | Test | Pass condition |
|---|---|---|
| C01 | Entry point | The exact release launcher is executable and reports the canonical package, manifest, commit, version, and registry identity |
| C02 | JSON contract | Every gateway operation accepts its documented JSON form and emits exactly one machine-readable result on stdout |
| C03 | Error contract | Invalid JSON, schema errors, denied access, missing backend, and internal failure return stable nonzero status and structured error JSON without secrets or traceback leakage |
| C04 | Capability query | Query results are ACL/company filtered and contain only registry-backed capabilities |
| C05 | Read dispatch | Read invokes the registered real adapter and cannot call a write capability |
| C06 | Write dispatch | Prepare/preview/approve-execute/status/verify/recover cannot skip a required state or policy check |
| C07 | Full parameter transport | Dates, company, partner/vendor, currency, journal, lines, tax IDs, idempotency key, and approval fields survive CLI serialization exactly |
| C08 | Source bypass | Tests fail if they import a developer checkout, wheel business code, V2/Pi copy, or any release other than the configured exact tree |

Installed-CLI cases must inspect the parsed JSON and business evidence, not only
the subprocess exit code.

## Gate D — real Odoo read capabilities

Each read capability is tested against Odoo 19 using a real active non-superuser
with the declared Odoo groups and explicit allowed-company context.

| ID | Test | Pass condition |
|---|---|---|
| D01 | ACL allow | The declared accounting user can read only the intended models and fields |
| D02 | ACL deny | A user lacking the declared permission is rejected by Odoo/V3, not served from elevated data |
| D03 | Company isolation | A disallowed company and mixed-company records are rejected; no result or receipt leaks their data |
| D04 | Database binding | The receipt database UUID matches the actual Odoo database queried |
| D05 | Financial oracle | Results equal an independently calculated, frozen accounting standard answer for the same company, dates, filters, and currencies |
| D06 | Pagination | Paging changes only returned rows; full-ledger totals and receipt scope remain invariant |
| D07 | Edge periods | Empty periods, opening balances, boundary dates, zero accounts, off-balance accounts, and locked periods follow documented semantics |
| D08 | Currency | Company and transaction currency values, rounding, and rate dates reconcile to authoritative Odoo records |
| D09 | Read receipt | Record counts, request/result digests, instance/database/user/company identity, registry/release digests, timestamp, and signature verify |
| D10 | No false success | Missing, invalid, or mismatched real-Odoo receipt prevents a business-success response |
| D11 | Database read-only boundary | Before any V3 ORM query the dedicated shell connection is idle, autocommit-off, explicitly `READ ONLY` and `REPEATABLE READ`; the same transaction marker survives the handler, every started/hardened path rolls back to libpq `IDLE`, real PostgreSQL rejects DML with SQLSTATE `25006`, and no result is released after boundary or rollback drift |

For the trial-balance vertical slice, the oracle must independently verify
posted-only filtering, ledger-cumulative opening, period debit and credit,
closing balance, debit/credit equality, complete totals before pagination, and
Decimal-safe rounding.

For the AR open-items slice, the oracle must independently recompute every
posted receivable line at `as_of_date` from `account.partial.reconcile` rows
whose `max_date` is not later than the cutoff. Company- and transaction-currency
residuals are rounded per line before the open test and summaries; debit and
credit items, unmatched payments, currently reconciled but historically open
items, partner/currency filters, and full totals before pagination are required.
The result basis is explicitly the current reconciliation graph, not an
immutable event-sourced historical snapshot.
The staged implementation retrieves at most 10,001 source candidates to detect
a 10,000-line safety boundary and then fails closed; it must never silently
truncate. Production enablement requires database-side count, aggregation, and
page retrieval plus a retained scale test that removes this staged limitation.

For the AP open-items slice, the same historical residual and scale rules apply
to every posted `liability_payable` debit or credit line. The oracle must retain
vendor bills, refunds/credit notes, payable payment residuals, and manual
payable entries without filtering on sign or move type. A negative company
currency net residual represents a net payable liability. Company-currency and
transaction-currency amounts must remain separate, and absent real fixtures for
partial reconciliation, unmatched payments, or foreign currency must be
recorded as evidence gaps rather than inferred as passing.

For the multicurrency balance slice, the oracle groups every posted
`account.move.line` on or before the inclusive cutoff by account and transaction
currency, under one explicit company, with `off_balance` accounts excluded.
It independently sums booked `balance` in company currency and booked
`amount_currency` in transaction currency; neither value may be reconstructed
from the cutoff rate. A separate changed-rate fixture must prove that a newer
cutoff rate does not revalue historical ledger amounts. Every requested unique
currency ID must appear exactly once in both `currency_summaries` and `rates`,
including zero-activity currencies, and the request order must be retained.
Rates must disclose transaction-to-company direction, inverse direction, the
formula `company_technical / transaction_technical`, and separate transaction
and company technical sources with effective date, scope/company/record, and
technical rate. A non-company transaction currency without an actual rate
record dated no later than the cutoff fails closed. The company target uses its
actual cutoff record when present; it may use disclosed `no_rate_identity=1`
only when no applicable root/global record exists at any date. Applicable
company-currency records that are all in the future fail closed. The Odoo
conversion factor must match the two disclosed technical sources within a
relative `1e-12` tolerance, including for extremely small rates. Balance rows are deterministically
ordered by account code/ID and requested currency order, full summaries remain
invariant under pagination, the request is bounded to 50 currencies, output to
25,000 aggregate groups and 500 rows per page, and all monetary totals use the
applicable Odoo currency rounding. Target acceptance additionally requires the
company-9 USD golden (`1950.00 CNY`, `300.00 USD`, factor `6.5`) through the
exact immutable release's signed non-superuser receipt; the read-only SQL
answer alone is not release verification.

## Gate E00 — dedicated sandbox prerequisites

E00a is the read-only capacity gate. Run the exact release member
`deployment/dev18/sandbox_capacity_gate.py` as root on Linux against an
externally SHA-256-bound reviewed policy. The policy pins the immutable
collector, requires a root-owned physical policy path, and pins PostgreSQL executables/systemd
service/process/data directory/listener/cluster, SQL session/current-user
authority, live backend-to-postmaster process identity, complete semantic and
physical PostgreSQL configuration, socket/NSS membership, complete catalog,
protected Odoo UUID relation identities, host, reviewed mountinfo rows, targets,
and protected resources. The program requires
the host PID 1 mount namespace and obtains open-path device IDs, `fstatvfs`,
catalog/UUID, locked relation metadata, machine/boot identity, bounded
UTC/monotonic capture window, and
protected-resource before/after observations live;
it accepts neither a caller observation nor a clock override. PostgreSQL,
filestore, runtime/evidence, backup, and reserve allocations are aggregated by
actual filesystem device for both bytes and inodes. The target database must
remain absent; host/target bindings, protected database UUIDs and their
policy-hashed ordinary-table identities, and V2/Pi/current resource identities
must not drift. V2/Pi directory identities cover every physical ancestor's
path/inode/device/mode/owner routing identity, every descendant, byte count,
metadata/content hash, and covering mount. Unrelated sibling entry churn does
not invalidate a stable ancestor identity; intermediate symlink routing,
ancestor mode/owner changes, and object-device/mountinfo disagreement are
rejected. Expected absence binds the existing ancestor chain and mount instead
of using a null digest. Each UUID read uses one
live-attested read-only repeatable-read transaction,
locks `ONLY public.ir_config_parameter`, and requires a `pg_catalog`-only
structure/digest assertion before the explicitly qualified table query. An
unlisted or concurrently changed
database catalog, mount topology drift, private mount namespace, PostgreSQL
service/process restart, listener substitution, or capture timeout fails closed.
A configuration pass additionally proves one server-side aggregate role-
password-vector digest, configuration-load time, effective-to-file setting
binding, include/TLS/authentication asset identity, empty preload sources, and
reviewed postmaster arguments/environment. Mixed-case GUC names are compared
case-insensitively and duplicate aliases fail. Files newer than the last
configuration load, unsupported external authentication, dynamic-loader
injection, and a group- or world-writable Unix-socket directory are rejection
cases; a matching policy hash cannot waive them.
A valid but insufficient observation exits
`1`; invalid or digest-mismatched evidence exits `2`. Even exit `0` must report
all provisioning and accounting-write authorizations as false.

`evidence target-capacity-plan` is a separate read-only operator aid for the
same prerequisite. It may list reviewable V3-owned cleanup candidates, but it
never deletes files, never authorizes cleanup, and never substitutes for E00a.
The plan must bind the current release route, commit, package, manifest, and
registry digest; a route mismatch fails the capacity-plan evidence even when
filesystem free space is otherwise sufficient.

The Ubuntu deployment-toolchain job must execute exactly 167 Dev18 capacity,
resource, configuration/socket, and attested-runner tests with zero skips,
failures, or errors. CI additionally executes thirteen PostgreSQL 16 integration
cases, including direct
non-superuser sessions. They prove SQL-produced identity digests, hostile
`search_path` resistance, wrong digest/view/type/owner fail-closed ordering,
DDL lock behavior, expression/partial-index rejection without invoking the
owner function, a live backend PID/PPID/executable/cgroup/namespace attestation
on the same connection, password-vector sensitivity without verifier output,
stale-HBA rejection/reload acceptance, and physical preload rejection before
the first SQL probe. It also proves PostgreSQL accepts uppercase long-form GUC
names while the gate rejects case-variant configuration/preload overrides.
Skips are forbidden in that Linux job.

E00b is a separate real-host isolation and recovery-readiness gate. It must
prove a different PostgreSQL cluster/authority and restricted role, exact
sandbox-only database name/UUID/filter, dedicated Odoo identity/data directory/
filestore, cron and outbound integrations disabled, non-superuser executor,
independent approver, isolated state, tested backup/reset, and denial of every
production database/configuration/filestore/mutable-add-on path. It also proves
V2, Pi, production Odoo, `current`, and existing unit identities remain
unchanged. E00a does not satisfy E00b. Until both pass, no write capability may
be staged and `write_execution_mode` remains `disabled`.

## Gate E — sandbox write lifecycle

Before running this gate, the operator must record the designated sandbox
database UUID, allowed company, test user and approvers, backup/reset procedure,
and confirmation that no production ledger is reachable by the test credentials.

Every write capability requires all applicable cases below; sharing one happy
path across capabilities is insufficient.

| ID | Test | Pass condition |
|---|---|---|
| E01 | Prepare and preview | Strict parameters, user/company binding, ACL, accounting prechecks, immutable digest, expected Odoo effect, and recovery plan are visible before approval |
| E02 | Approval | Only an authorized independent approver can approve the exact preview within the policy TTL |
| E03 | Create/execute | One approved request creates exactly the intended Odoo records under the bound user and company |
| E04 | Readback verification | Partner, dates, currency, journals, lines, taxes, totals, state, links, and source references reconcile to the prepared request |
| E05 | Duplicate request | Sequential and concurrent repetition produces no duplicate invoice, bill, payment, statement, reconciliation, entry, asset, schedule, or reversal |
| E06 | Mutation/replay | Changed content, reused approval, expired approval, reused nonce, cross-company context, and cross-database context are rejected |
| E07 | Failure before effect | Validation, ACL, lock-date, and simulated pre-execution failures leave no Odoo accounting effect and record a diagnosable failed operation |
| E08 | Ambiguous failure | A transport/process failure after submission is reconciled by idempotency and Odoo readback before any retry |
| E09 | Recovery | Draft cancellation/removal or approved accounting reversal/compensation restores the expected business state and emits linked receipts |
| E10 | Recovery failure | A failed compensation remains auditable, cannot be reported recovered, and escalates without hiding the original effect |
| E11 | Restart | Execution interrupted at each durable state resumes or reconciles safely after restart without duplicate effect |
| E12 | Audit chain | User, company, request, approval, operation, Odoo records, verification, recovery, and final result form one tamper-evident chain |

Posted accounting effects use Odoo reversal or an explicitly registered
compensating action. Generic local `undo`/`redo` does not satisfy E09.

## Gate F — Pi Agent end-to-end

The scenario corpus begins with natural-language accounting requests and records
the expected capability ID and complete structured parameters. It includes
ordinary, ambiguous, adversarial, multi-company, multi-currency, and recovery
requests across all enabled domains.

| ID | Test | Pass condition |
|---|---|---|
| F01 | Capability selection | At least 95% of frozen key scenarios select the expected capability; the scoring set and calculation are retained |
| F02 | Clarification | Missing or ambiguous dates, company, counterparty, currency, amount, tax, journal, or intent are collected before preparation |
| F03 | No parameter loss | Pi request, CLI input, preview, approval digest, Odoo result, and receipt preserve all material parameters |
| F04 | User approval | Write scenarios show an understandable business preview and obtain approval before execution |
| F05 | Verified answer | The final answer contains reconcilable business values and audit/receipt identifiers, and never converts an unverified result into success |
| F06 | Enabled coverage | 100% of registry capabilities marked enabled can be selected and called through the standard Pi gateway |
| F07 | Denied requests | Unauthorized, cross-company, expired, replayed, and tampered requests are refused with safe actionable errors |
| F08 | Recovery journey | Pi can diagnose a failed/incorrect operation, present its registered recovery, obtain approval, execute it, and report verified outcome |

### Frozen F01-F03/F05 scoring contract

`tests/fixtures/pi_scenarios.v1.json` is the revision-2 frozen Chinese key
scenario corpus. Its 28 scenarios cover every one of the 24 registered
capabilities and the
ordinary, ambiguous, adversarial, multi-company, multi-currency, and recovery
classes. Environment-specific Odoo record IDs are named fixture bindings, so a
capture run binds the same intent to its own sandbox fixtures without changing
the frozen expectations.

One scenario selects `acct.move.draft_cancel_eligibility.v1` to read the exact
draft-cancel target, move type, line graph, and immutable bindings before any
write. Two scenarios select `acct.move.draft_cancel.v1`, one for a customer
draft invoice and one for a vendor draft bill. Each preserves all seven strict
input parameters through CLI input and preview and binds that same parameter
digest to approval. Their document and business bindings model values returned
by a trusted candidate read, never free-form values invented by Pi or the user.

`tools/pi_scenario_gate.py` is an offline scorer. It requires an HMAC-attested
Pi trace export and a host-local trusted key file; it does not invoke Pi, an
LLM, Odoo, or any network service. The signed export binds the frozen corpus,
the exact registry, the V3 release digest, Pi/Pi Bridge versions, fixture
bindings, and every trace event. Each captured scenario retains the exact
frozen user input, capability selection, questions and user answers for every
clarified field, finalized parameters, CLI input, write preview and approval
parameter digest when applicable, Odoo execution, Odoo result, and audit
receipt. Every applicable stage carries the full parameters or their canonical
SHA-256 binding.

The scorer rejects unknown fields, duplicate IDs, unsigned or untrusted
exports, signature/digest mismatches, obvious placeholder SHA-256 strings in
fixture/material evidence bindings or captured trace digests, wrong corpus or
registry digests, empty trace sets, invalid fixture types, and traces not bound
to the frozen input.
Missing scenarios remain in every denominator and fail trace coverage. F01
passes only when the exact integer ratio is at least 95%; F02, F03, and F05
require 100%. F05 requires every captured terminal result to record
`business_succeeded:true` and an audit receipt identifier; a bridge-guided
`business_succeeded:false` result is valid trace evidence but fails acceptance
rather than being converted into success. The JSON report retains the exact
numerator, denominator, decimal percentage, capture/release/attestation
identity, stage-level parameter failures, verified-answer failures, and
scenario-level failures.

Run it only with an actual capture artifact:

```text
PYTHONPATH=src python tools/pi_scenario_gate.py \
  --traces /path/to/pi-traces.json \
  --attestation-keys /host/private/pi-attestation-keys.json \
  --expected-release-sha256 "$trusted_package_sha256"
```

The expected release digest must come from the independently trusted canonical
package anchor; a signed capture from any other V3 build is rejected. Exit `0`
means F01-F03/F05 and full trace coverage passed, exit `1` means valid
captured evidence was scored but a gate failed, and exit `2` means no score was
issued because the corpus or evidence was invalid. The attestation key file is
host-local, is never included in the release, and maps trusted key IDs to at
least 32 bytes of hex-encoded HMAC secret. Unit tests use an explicit test-only
key and build synthetic trace documents solely to verify scorer behavior; they
are not Pi evidence and must never be reported as an F01-F03/F05 acceptance pass.

## Gate G — promotion and rollback

Promotion is capability-by-capability and environment-by-environment. Passing a
read slice does not authorize writes, and passing one write does not authorize
another.

| ID | Test | Pass condition |
|---|---|---|
| G01 | Evidence mapping | Every enabled registry entry references the exact passing receipts and test run for its release |
| G02 | Side-by-side deploy | V3 installs under its independent release root while V2 remains unchanged and runnable |
| G03 | Runtime identity | Odoo adapter, V3 CLI, and Pi Bridge reject or flag a version/registry/release digest mismatch |
| G04 | Canary | Authorized traffic is explicitly routed to enabled V3 capabilities; all other traffic remains on V2 or fails closed |
| G05 | Rollback | Routing can return to the prior verified release without changing accounting records or losing durable operation/audit state |
| G06 | Production-write approval | No production write is enabled or tested without separate explicit authorization and capability-specific production safety review |

## Current status and execution record

The presence of test files or commands is not a passing result. Actual runs must
be recorded in immutable evidence tied to a release; this plan intentionally
does not pre-fill pass marks.

At the current local development checkpoint:

- contract/control, receipt, release, and trial-balance unit tests exist;
- the installable V3 executable, JSON registry commands, fail-closed operation
  commands, and local console-script subprocess suite pass; dev5 also passed a
  local wheel install into a fresh environment from outside the source tree,
  and a Python 3.11/3.12 test matrix plus the Python 3.12 `wheel-smoke` CI job
  are defined, but committed CI evidence remains required;
- dev2 produced a retained direct Odoo read receipt; dev3 produced a complete
  installed-CLI receipt matching the independent `136193.63` debit/credit
  oracle, passed target-Linux resource gates, and rejected cross-process replay,
  but was deliberately rejected for promotion after review found that its auth
  signature did not bind capability ID plus parameters before first use;
- dev4 added the signed request-content digest and its exact immutable server
  artifact repeated the target-Linux gates, real Odoo trial-balance oracle,
  ACL denial, authorized multi-company read, bound-company escape denial,
  database UUID denial, expiry, tamper, durable replay, parameter round-trip,
  and audit-chain checks. It remains staged rather than enabled because Pi
  routing/E2E and the remaining production trust split are not complete;
- dev5 locally adds approval protocol v2, strict request/key/revision binding,
  result protocol v2 with full operation-state binding, schema-v2 append-only
  approval records, global durable nonce replay defense, atomic
  approval/state/audit commit, canonical audit-byte checks, concurrency and
  rollback tests, atomic signed-read receipt consumption plus audit, reserved
  legacy-evidence namespace rejection, guarded recovery transitions, and a
  strict v1 migration. Execution-result, failure, verification, and recovery
  persistence remain closed until their specialized authoritative transactions
  exist. These are control-plane tests only; no Odoo write was executed;
- dev6 added a signed, Odoo-company/ACL-filtered registry query and a strict AR
  open-items contract/domain/backend. Its exact immutable release passed the
  target Linux suite and six independent real-Odoo SQL oracles, with matching
  signed receipts, security denials, parameter round-trip, replay rejection,
  and a frozen externally anchored evidence bundle. It remains staged because
  the fixture has no partial/unmatched-payment coverage, production-scale and
  runtime immutability gates remain open, and no Pi route exists;
- dev7 added the strict AP contract and a fixed `liability_payable` Odoo
  backend while reusing the dev6 historical residual engine. Its exact release
  passed 231 target-Linux tests plus 107 subtests, six independent read-only AP
  SQL oracles, parameter round-trip, ACL/company/expiry/tamper/database/replay
  denials, receipt/audit persistence, and post-run V2/Odoo/Pi isolation. The
  root-owned frozen bundle contains 98 files with 97 checksum entries and an
  external anchor; AP remains staged because the real fixture lacks open
  refund, unmatched-payment, open-partial, FX, and scale-boundary coverage;
- dev8 binds execution to a manifest-covered release launcher and requires the
  retained canonical tar path and SHA-256 in the strict runtime contract. The
  package, anchor, manifest, extracted tree, CLI source path, and child payload
  must agree before secrets, state, or Odoo execution are reached. The staged
  target gate must additionally inventory the external system Python and Click
  bytes; they are not yet release-scoped, so this slice alone is not a
  production promotion;
- dev9 committed the business-only Pi-to-UDS broker, durable
  session/company authority, independent approval, shared-store cross-release
  prepare idempotency, retained release/key routing, real per-release read/write
  HMAC response verification, and a separate append-only Broker attempt audit.
  It contains strict precheck/handler/verification/recovery implementations
  for all 14 registered write capabilities. Local loss-response, replay,
  cross-company, tamper, audit-failure, wrong-key, and historical-route tests are
  historical development evidence, not current-HEAD Odoo receipts or promotion
  evidence;
- dev10-dev14 committed control-plane hardening for session concurrency and
  recovery, canonical Odoo/Pi release binding, approval/SQLite reconciliation,
  Pi evidence and target safety, recovery v2, fail-closed namespace probes, and
  immutable release installation. These controls are not real Odoo write
  evidence;
- dev15-dev17 added the staged multicurrency balance read. Its fixed Dev15
  release produced real-Odoo signed read/oracle receipts, after which the
  signed-tag-bound immutable read-evidence toolchain was added and its Pi
  control digest corrected. Those receipts bind that historical release, not
  current HEAD. The implemented automatic Odoo recovery closure is limited to
  an exact sandbox draft customer invoice and has no real-write receipt;
- dev18 adds the fail-closed E00a read-only capacity gate. Its Ubuntu CI contract
  requires exactly 167 Linux gate tests with zero skips, failures, or errors,
  plus 13 real PostgreSQL 16 integration cases. GitHub `quality #40` passed that
  complete workflow for commit `c03dbb7`; this is Linux/CI evidence, not a
  target-host E00a receipt. A 2026-07-18 lightweight read-only recheck found
  that the capacity shortfall had decreased to `12,913,868,800` bytes while
  `/run/postgresql` remained mode `2775`; it is not an immutable E00a receipt,
  and no target E00a pass receipt exists;
- dev19 adds a strictly non-authorizing E00b isolation contract, exact
  release/E00a/recovery/host approval bindings, live UTC plus monotonic policy
  checks, fixed-root digest rechecks, full current/for-children namespace
  identity, and descriptor-pinned Linux file reads/hashes. Its Ubuntu workflow
  requires exactly 296 combined gate/probe cases with zero skips, failures, or
  errors plus one root host-context integration case. The operational CLI still
  returns `live_collector_unavailable`; it has no nonce-consumption ledger,
  signed report, trusted live Odoo/systemd collector, target-host E00b receipt,
  or write authorization;
- dev20 adds a dormant sandbox-only recovery contract for a pristine draft
  vendor bill. It binds `acct.bill.vendor_create.v1`, `in_invoice`, the purchase
  journal, exact document/business digests, the complete move-line graph, a
  separate approval and idempotency key, and an exact `draft` to `cancel`
  transition. Customer/vendor method-oracle crossing, production use, external
  links, incomplete guards, and post-write drift are rejected. Odoo 19's
  standard stock-move, COGS-origin, and landed-cost fields must be present,
  empty, and bound into the approved fingerprints. These are local
  contract/fake-ORM tests only; no real Odoo bill was created or recovered, and
  the trusted installed/custom-module graph remains a staging prerequisite;
- dev21 derives a canonical installed-module graph from installed module names
  and `latest_version`, rejects noncanonical schema/order/digest evidence, and
  binds that graph through precheck, execution, verification, and both draft
  recovery plans. For the two dormant pristine-draft customer-invoice and
  vendor-bill recovery slices, it closes the material stored-and-writable
  `account.move` and `account.move.line` snapshot, guard, and recovery field
  sets observed on the target, permits absent optional fields only when their
  trusted provider module is absent, and records tokens, signatures, and
  PDF/Facturae/UBL binaries as presence-only values read with `bin_size=True`.
  Execution and verification separately lock the module table, but the
  commit-to-verification interval is not cross-commit mutual exclusion: drift
  prevents a false success while an already committed effect may require
  reconciliation. These remain local contract/fake-ORM tests; no real Odoo
  write/recovery receipt was produced; and
- the normal approved `acct.move.draft_cancel.v1` path is separately registered
  but remains disabled and unstaged. Its expected document and business
  bindings must be read from the exact V3-created `account.move` fields under
  trusted user/company/ACL and signed Odoo receipt identity.
  `acct.move.draft_cancel_eligibility.v1` is now registered for test staging
  and covers strict schema, ACL, cross-company rejection, signed receipt, and Pi
  transit at the contract/fake-Odoo level. Before write staging it must still
  pass retained real-sandbox Odoo tests.
  It also requires a target-module and active-automation inventory proving no
  `account.move.write` override, server action, webhook, mail, queue, or
  unrelated-record side effect escapes the approved move/line graph. There is
  no retained real-sandbox candidate-read or automation-safety receipt yet;
- dev26 limits the current `acct.recovery.execute.v1` path to a distinct,
  separately approved resolution of a durable FAILED origin with exactly one
  successful execution result followed by one bound failed-verification
  result. Completed origins, execution-only failures, legacy version-1
  bindings, same-operation recovery, and mismatched two-anchor finalization are
  rejected. A signed creation plan marked `available` is necessary incident
  evidence but is not by itself execution authority. The capability remains
  disabled. The real PostgreSQL two-anchor job passed in GitHub Actions run
  `29677961982`; this proves the Dev26 database guard/finalizer contract, not a
  real Odoo write or recovery receipt;
- dev27 changes the isolated finalizer runtime document to strict schema v2 and
  requires one externally anchored dependency-manifest path/digest to agree
  with the installed canonical JSON and rendered systemd service. Its tests are
  required to cover digest drift, standalone non-root Linux verification, and
  the actual finalizer's eager driver import/reverification before credential
  preflight. These contracts do not produce a target-host runtime manifest,
  real Odoo receipt, sandbox write, or production authorization;
- dev28 adds the database-enforced rollback-only boundary for all five staged
  reads. Unit tests cover writable/autocommit/isolation drift, hidden
  commit/rollback, DML rejection, rollback failure, reopened rollback hooks,
  direct static write/network escapes, the package-parent plus explicit
  transitive import closure, source-bound explicit imports, reviewed local-state
  mutations with plain-dict provenance, source-root/importable-binary release
  rejection, and the transaction helper's source digest and privileged
  structure. Full-source bootstrap/executor digests and critical-binding
  immutability protect the public call chain. A dedicated GitHub PostgreSQL
  16 job uses psycopg2 2.9.9 to require `READ ONLY`, `REPEATABLE READ`,
  transaction-local marker continuity, real hidden commit/rollback rejection,
  SQLSTATE `25006`, unchanged independent-witness rows, and final libpq `IDLE`.
  The static policy is defense in depth and does not prove absence of a second
  connection or external effect. This is not yet an exact-release Odoo 19 target
  receipt;
- dev29 adds a release-specific SquashFS Odoo/Python dependency closure with a
  separate sealed configuration, external root-owned image/manifest anchor,
  installed-module graph binding, executable `.pth` and import-escape rejection,
  deterministic double-build comparison, pre-mount artifact verification, and
  loop-device/inode plus private-mount-namespace checks. Its composite staged
  read plan fixes five positive requests, seven exact policy rejections, a D11
  rollback boundary probe, independent PostgreSQL financial recomputation,
  pre/post privacy-limited witnesses, service/database continuity, durable
  replay/audit state deltas, and a separately implemented offline evidence
  verifier. The operational design uses one private-namespace supervisor,
  direct demoted children, mandatory cleanup before external anchoring, and a
  digest-pinned runtime-open inventory; static ELF discovery alone is explicitly
  non-promotable. The suite, independent verifier, and publisher now each
  reconstruct the approved policy-source digest from the exact index and all 32
  canonical target manifests, independently bind the raw release manifest and
  validator member bytes, reject boolean schema counters, and preserve the
  verifier trace in a separate root-only sibling sidecar. Linux CI explicitly
  gates the root lifecycle, atomic-seal crash windows, real systemd unit leases,
  tmpfiles recreation, policy installation, recovery, and publication paths. A
  generic process or infrastructure failure cannot satisfy a negative case.
  The target read-only baseline found a capacity shortfall and an Odoo restart
  count that had climbed from 484 to 1,172 by 2026-07-22. A later point-in-time
  recheck that day found 4,255,105,024 free bytes, above the conservative floor,
  and no additional restart in that one snapshot, but did not prove sustained
  service continuity or reserve that headroom for V3. Therefore no Dev29 target
  closure, exact-release Odoo receipt, or promotion evidence exists yet;
- every current registry `evidence.receipts` array is empty: zero capabilities
  are enabled and zero write capabilities are staged. E00b, a real sandbox
  Odoo write/recovery run, and Pi end-to-end evidence do not exist; no sandbox
  or production write is authorized;
- dev250 adds a non-authorizing readiness gate for the exact ten registered
  read capabilities. It locks the reviewed Odoo dispatch handlers to their
  real executor mapping, requires top-level `page` and `receipt`, the complete
  `read_receipt_v2` JSON Schema, strict input/output contracts, test routing,
  and the versioned required-read inventory. The dev250 result is six
  statically admissible reads and four declared-only gaps: tax reporting,
  financial reporting, multi-company consolidation, and operation diagnostics.
  Registry-embedded evidence receipt claims cannot satisfy final Goal evidence:
  current-release receipt hashes would self-reference both the registry digest
  and release manifest, and their metadata alone does not independently verify
  artifacts or signatures. Until a release-external, independently verified
  read-evidence index covers all ten capabilities, dev250 reports zero
  completion-ready reads and keeps Goal readiness false. The final evidence
  manifest now revalidates this report against the installed registry/handler
  set and rejects an unready, stale, inconsistent, or incomplete Goal report.
  Final-manifest schema v2 also rejects unexpected artifact keys and requires
  the checker itself to execute from the release resolved by `current`, so a
  retained pre-dev250 checker cannot validate a dev250 handoff. These checks
  perform no real Odoo or PostgreSQL write and do not authorize production.
- dev251 adds contract-tested, test-staged native Odoo tax and financial-report
  handlers. Their trusted roots are resolved inside the adapter from fixed
  XML-IDs; Pi cannot supply database report IDs. The result is eight statically
  admissible reads and two declared-only gaps: multi-company consolidation and
  operation diagnostics. These two new handlers remain disabled and are not
  production-ready until exact-release target receipts, a pinned report
  definition digest, and independent tax/accounting standard-answer evidence
  pass their external gates.
  The release-contained Dev251 collector and independent verifier can retain
  exact-release staged-test receipts plus rollback-boundary and unchanged
  PostgreSQL witness evidence, but their output explicitly leaves accounting
  correctness and production promotion false.
- The immutable target candidate
  `0.1.0.dev251-f6f54e86edfa` was correctly stopped before its read boundary,
  witnesses, or report calls: the initial collector incorrectly required
  global static readiness even though the fixed read inventory is 10
  registered, 8 admissible, and exactly 2 declared-only gaps. That release is
  retained for audit and cannot be promoted or rebuilt. Dev252 corrects only
  this precondition by independently binding the exact 10/8/2 inventory and
  all per-capability safety fields in both collector and verifier; it does not
  make either report production-ready.

The 2026-07-22 Dev29 pre-release worktree validation executed 4,289 tests:
4,017 passed, 272 platform/external-environment cases skipped, and none failed
or errored. The Dev29 subset executed 357 tests: 293 passed and 64 Windows/Linux
root-specific cases skipped. The non-root digest, policy, exact-mode mapping,
and strict-schema binding gate executed its exact 55 cases with zero skips.
These are local development results, not clean-commit GitHub Actions evidence,
an exact-release target receipt, or a sandbox-write authorization. The Linux
root-only gates must still execute in CI before this release is publishable.

The 2026-07-28 Dev250 pre-commit Windows regression executed 4,042 collected
cases: 3,758 passed, 284 platform/external-environment cases were skipped, 593
subtests passed, and none failed or errored. The Pi Bridge suite separately
executed 115 tests: 113 passed and 2 Linux-only cases were skipped. These
results prove the local fail-closed contracts only; they are not real Odoo
read evidence, sandbox write evidence, or production authorization.

The normal local unit command is:

```powershell
python -m pytest
```

Its output is development feedback only until the run is bound to a clean Git
commit, verified release artifact, and retained test report. Real Odoo and Pi
Agent gates require their own receipts and cannot be replaced by this command.

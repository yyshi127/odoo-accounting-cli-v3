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
  `acct.ar.open_items.v1`, and `acct.ap.open_items.v1` are staged for the
  isolated `test` environment; no capability is enabled and no write
  capability is staged.
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

The package must be built and installed into a clean environment. Tests execute
from outside the repository with source-tree import paths removed and resolve
the V3 executable from that environment.

| ID | Test | Pass condition |
|---|---|---|
| C01 | Entry point | The installed V3 executable is resolvable and reports the installed version/release identity |
| C02 | JSON contract | Every gateway operation accepts its documented JSON form and emits exactly one machine-readable result on stdout |
| C03 | Error contract | Invalid JSON, schema errors, denied access, missing backend, and internal failure return stable nonzero status and structured error JSON without secrets or traceback leakage |
| C04 | Capability query | Query results are ACL/company filtered and contain only registry-backed capabilities |
| C05 | Read dispatch | Read invokes the registered real adapter and cannot call a write capability |
| C06 | Write dispatch | Prepare/preview/approve-execute/status/verify/recover cannot skip a required state or policy check |
| C07 | Full parameter transport | Dates, company, partner/vendor, currency, journal, lines, tax IDs, idempotency key, and approval fields survive CLI serialization exactly |
| C08 | Source bypass | Tests fail if they accidentally import or invoke an uninstalled source-tree CLI |

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
- dev7 locally adds the strict AP contract and a fixed
  `liability_payable` Odoo backend while reusing the dev6 historical residual
  engine. Unit, CLI transport, bootstrap, executor, registry, and gateway tests
  pass locally; an exact dev7 release still requires target-Linux and real-Odoo
  AP oracle evidence;
- no sandbox write lifecycle has been authorized or recorded; and
- no production write is authorized.

The normal local unit command is:

```powershell
python -m pytest
```

Its output is development feedback only until the run is bound to a clean Git
commit, verified release artifact, and retained test report. Real Odoo and Pi
Agent gates require their own receipts and cannot be replaced by this command.

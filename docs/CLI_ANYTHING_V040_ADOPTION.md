# CLI-Anything v0.4.0 adoption

Status: adopted as a bounded engineering method, not as the V3 accounting
implementation or source of truth.

## Upstream identity

The reviewed upstream is
[`HKUDS/CLI-Anything`](https://github.com/HKUDS/CLI-Anything):

- tag: `v0.4.0`
- commit: `dc7392489222dbcc520817609290755d6dd8b0bb`

The tag and commit are fixed here so a later upstream release cannot silently
change the V3 build or test contract. Any future upgrade requires a separate
review and an explicit update to this document.

## What V3 adopts

V3 uses CLI-Anything v0.4.0 for the following bounded purposes:

| Upstream practice | V3 use |
|---|---|
| Harness structure | A consistent, installable CLI package and command organization |
| Interface conventions | Machine-readable JSON requests and responses, deterministic command behavior, and explicit failures |
| Introspection before mutation | Capability discovery and read/precheck operations precede every write |
| Real-backend requirement | End-to-end tests must invoke real Odoo 19 and verify business results, not only process exit codes |
| Installed-CLI testing | Subprocess tests resolve and run the installed V3 executable outside the source tree |
| Test planning | `tests/TEST.md` is the living matrix of unit, installed-CLI, real-Odoo, security, recovery, and Pi Agent gates |

These practices may guide scaffolding and test harnesses. Generated output is
reviewed like any other contribution and has no special authority.

## What V3 does not adopt

V3 is not produced by running CLI-Anything as a full repository generator.
The generator must not overwrite or replace:

- audited V2 accounting-domain behavior selected for reuse;
- V3 capability schemas and accounting semantics;
- user, company, Odoo ACL, and approval controls;
- idempotency, concurrency, immutable digests, and replay protection;
- audit events, Odoo receipts, execution verification, or recovery logic; or
- release provenance and evidence gates.

This boundary is required because a generic harness cannot determine whether a
posting, reconciliation, tax result, depreciation, or reversal is financially
correct. Full generation would also risk creating a second implementation of
Odoo behavior instead of exercising the actual Odoo backend.

## Backend boundary

Odoo 19 is the real accounting backend and the authoritative system of record.
V3 invokes supported Odoo ORM operations under a real, non-superuser Odoo user,
an explicitly allowed company scope, and the database identity bound into the
request. It does not reimplement Odoo posting or reconciliation behavior in a
standalone Python model.

Mocks and fakes are permitted for isolated unit tests. They cannot establish
that a capability is usable, financially correct, or safe for an environment.
Such claims require a real Odoo execution or readback receipt at the evidence
level defined by the capability registry.

## Stable gateway surface

The CLI surface presented to Pi Agent is organized around the workflow rather
than hundreds of unrelated ORM commands:

1. capability query;
2. read;
3. prepare;
4. preview;
5. approval and execution;
6. status query;
7. result verification; and
8. recovery.

Every machine-facing operation must accept and return JSON with a strict schema.
The complete request context and business parameters must survive each boundary,
including dates, user, company, allowed companies, partner, currency, journal,
database identity, idempotency key, and approval data where applicable. Unknown
or dropped fields are contract failures, not defaults.

One-shot installed CLI execution is the required automation interface. An
interactive shell may be added for operator convenience, but it is not required
for Pi Agent and cannot bypass the same contracts or controls.

## Accounting recovery semantics

CLI-Anything's general session `undo`/`redo` concept is not mapped to posted
accounting records. Accounting recovery is capability-specific:

- an eligible draft may be cancelled or removed only when Odoo and policy allow;
- a posted journal entry, invoice, payment, depreciation, or adjustment is
  corrected through a traceable Odoo reversal or registered compensating action;
- reconciliation recovery uses the recorded Odoo reconciliation records; and
- any compensating write requires its own authorization, idempotency, execution
  verification, and receipt.

V3 must never report that a posted record was “undone” merely because local CLI
state was rolled back.

## Required test gates

CLI-Anything practices are considered applied only when the relevant V3 gates
pass:

1. Strict schema, security, state-machine, idempotency, receipt, accounting
   oracle, and release tests pass at the unit/integration level.
2. A clean environment installs the built package and subprocess tests resolve
   that installed executable, not a source-tree module.
3. Real Odoo read tests verify ACL and company scope, financial results, full
   parameter round-trip, and a signed Odoo receipt.
4. Every enabled write capability completes create, readback, duplicate-request,
   failure, concurrency, and reversal/recovery tests in the designated sandbox.
5. Pi Agent natural-language scenarios traverse capability selection, parameter
   collection, preview, approval, execution, verification, and final audit
   receipt without bypassing the CLI gateway.

An exit code of zero, a command being present, a mocked response, or a local
state transition is insufficient evidence of accounting success. Without a
verified real-Odoo receipt, V3 must return an unverified or failed result and
must not report business success.

## Write authorization boundary

No production-accounting write test is authorized by the current project
baseline. All write capabilities remain disabled until a dedicated sandbox is
identified and its required tests and receipts pass. A production write requires
separate, explicit authorization plus the production safety evidence defined in
`tests/TEST.md` and the capability registry.

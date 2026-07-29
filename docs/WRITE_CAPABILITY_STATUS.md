# Write capability status

This is a source-implementation audit, not Odoo execution evidence or
production authorization. The machine-readable registry and retained receipts
remain authoritative.

## Current registered writes

The current development registry contains 23 write capabilities. All 23
require approval and idempotency, have concrete
`prepare/precheck/execute/verify` dispatch, and call Odoo ORM APIs. None is a
registry-only placeholder.

| Capability | Implemented ORM path | Current boundary |
| --- | --- | --- |
| `acct.invoice.customer_create.v1` | Create, optionally post, and read back a customer invoice | Real Odoo and recovery unverified |
| `acct.bill.vendor_create.v1` | Create, optionally post, and read back a vendor bill | Real Odoo and recovery unverified |
| `acct.refund.create.v1` | Odoo reversal wizard, controlled refund lines, optional post | Real Odoo unverified |
| `acct.payment.register.v1` | Payment-register wizard and payment creation | Company-currency narrow slice only |
| `acct.bank.statement_import.v1` | Create a statement and its statement lines | Foreign-currency bank journal rejected |
| `acct.reconciliation.apply.v1` | Reconcile wizard with optional controlled write-off | FX, cash-basis tax, and bank-matched graphs rejected |
| `acct.asset.create.v1` | Create and validate an Enterprise asset | Canonical Odoo 19 schedule unverified |
| `acct.depreciation.post.v1` | Post one bound depreciation move | Enterprise schedule unverified |
| `acct.accrual.create.v1` | Create/post accrual and scheduled reversal moves | Real Odoo unverified |
| `acct.deferred.create.v1` | Bind deferred dates and post the source | Canonical Odoo 19 schedule unverified |
| `acct.period.adjustment_create.v1` | Create an optional-post balanced adjustment | Tax-effect entries rejected |
| `acct.move.reverse.v1` | Reverse a bound move through the Odoo wizard | Real Odoo unverified |
| `acct.move.draft_cancel.v1` | Cancel a pristine V3 invoice/bill draft | Direct state transition requires sandbox automation/module proof |
| `acct.journal.entry_create.v1` | Create a restricted balanced draft journal entry | AR/AP, tax, analytic, and off-balance lines rejected |
| `acct.move.post.v1` | Post a pristine V3 manual journal entry | Invoice, bill, tax, bank, payment, asset moves rejected |
| `acct.move.draft_cancel.v2` | Cancel a bound pristine draft move | Direct state transition requires sandbox automation/module proof |
| `acct.payment.cancel.v1` | Cancel a narrow-slice payment through `action_cancel` | Odoo 19 effects and reconciled payments unverified |
| `acct.recovery.execute.v1` | Receipt-derived execution of 16 compensating actions | Contract permits test/sandbox only |
| `acct.reconciliation.undo.v1` | Receipt-bound unreconcile and write-off reversal | Contract permits test/sandbox only |
| `acct.bank.statement_compensate.v1` | Create an independent reversing statement batch | Contract permits test/sandbox only |
| `acct.invoice.customer_post.v1` | Post one exact canonical pristine V3 customer-invoice draft and verify the posted graph | Pi eligibility flow, receipt correlation, and real Odoo lifecycle unverified |
| `acct.bill.vendor_post.v1` | Post one exact canonical pristine V3 vendor-bill draft and verify the posted graph | Pi eligibility flow, receipt correlation, and real Odoo lifecycle unverified |
| `acct.refund.draft_cancel.v1` | Cancel one exact never-posted V3 refund while preserving its posted origin | Pi eligibility flow, receipt correlation, and real Odoo lifecycle unverified |

At this snapshot every write remains:

- `evidence.level: declared`;
- `evidence.receipts: []`;
- absent from `staged_environments`; and
- absent from `enabled_environments`.

Local fake-ORM and service tests exercise these paths, but they are not real
Odoo receipts. Therefore the source-development count is 23/23 while the
real-Odoo write-evidence count is 0/23. Goal completion cannot be inferred from
the source-development count.

## Dev259 document-lifecycle boundary

The intended Pi flow queries `acct.move.document_post_eligibility.v1` before
either posting write and transfers its exact parameters into preview and
approval. The current write input does not carry or cryptographically chain an
eligibility receipt or receipt digest. Instead, the posting write precheck
independently rebuilds and validates the same user/company-bound move, pristine
V3 draft, complete unchanged line graph, and document plus business bindings.
It rejects already-posted, paid, reconciled, cross-company, externally linked,
auto-post, closed-period, or drifted graphs. Successful execution still
requires an exact posted-graph readback before the CLI may report business
success.

The current customer-invoice/vendor-bill posting implementation closes the
observed Odoo 19 partner-rank postcommit delta only for a target whose
`customer_rank`/`supplier_rank` is exactly `0` before `action_post`; successful
verification requires that same relevant rank to become exactly `1`. This is a
deliberately bounded development slice, not a generally production-applicable
posting path for partners with an existing rank or for unreviewed module
extensions.

The Dev259 eligibility oracle is intentionally narrower than the underlying
write handler: it returns `eligible:true` only for a complete productless,
taxless graph whose invoice lines reproduce undiscounted subtotals exactly and
whose journal graph has one receivable/payable maturity line. Taxed, product,
discounted, or more complex payment-term documents fail closed. This bounded
oracle is not full customer-invoice or vendor-bill production coverage.

The intended Pi flow likewise queries
`acct.refund.draft_cancel_eligibility.v1` before
`acct.refund.draft_cancel.v1`, but the current write contract does not
cryptographically chain that read receipt either. The write precheck
independently proves that the refund is a canonical never-posted, fully unpaid
and unreconciled V3 customer credit note or vendor debit note with no external
effects, and that its unique posted origin remains unchanged. The operation
cancels rather than deletes the refund and treats the unposted cancellation as
terminal. A full refund must be an exact linewise reversal including immutable
line references. A partial refund must not exceed the origin total, and every
refund business line must map by one unique line reference to an origin line
with the same identity while its quantity and amounts remain within that
origin line.

Both eligibility reads are only `contract_tested`, staged for `test`, and have
zero retained real-Odoo receipts. All three writes remain `declared`, unstaged,
and disabled.

The eligibility handlers rebuild normalized graphs from Odoo and require both
SHA-256 bindings to match. Refund-origin validation accepts exactly one of two
binding-shape candidates: creation recorded `posting_mode:"post"`, or creation
recorded `posting_mode:"draft"` and the current document is now posted. The
draft candidate proves only the binding recorded when the document was
created. It does not record which later caller or entry point invoked
`action_post` and therefore cannot prove that a controlled posting capability
performed that transition.

The current create-to-eligibility reconstruction can also reject an
economically equivalent document because Odoo does not preserve source decimal
spelling such as `100` versus `100.00`, tax-ID order is normalized, and invoice
lines are stably reordered by `line_reference`. The original create-v1 paths
did not enforce one matching canonical representation for all three cases.
These safe false negatives must not be bypassed; a future versioned canonical
binding/provenance migration is required before affected records can be
admitted without guessing.

An installed-module graph, where retained, proves only that the module
name/version set remained stable. It is not a semantic allowlist of
`action_post`, `account.move.write`, or postcommit overrides. These writes must
remain disabled until a real Odoo 19 sandbox run and an explicit target-module
override review have closed that boundary.

## Missing write families

The 23 writes cover the basic accounting spine, not every write operation in
the Goal. Additional capability contracts and handlers are still required for:

1. foreign-currency payments, bank statements, FX reconciliation, rates, and
   period-end revaluation/reversal;
2. tax adjustments, tax settlement, cash-basis tax effects, tax-period locks,
   and filing/status receipts;
3. formal bank matching, fees/differences, matching-model application, and
   match reversal;
4. reconciled-payment reversal, multi-target partial allocation, advances,
   internal transfers, and supported batch/payment-provider flows;
5. accounting/tax lock and unlock, month/year close, retained-earnings close,
   and controlled reopen;
6. asset disposal, sale, scrap, impairment, revaluation, schedule change, and
   transfer;
7. intercompany journals and consolidation-elimination entries;
8. controlled invoice/bill amendment/rebuild beyond the now-implemented
   pristine-draft posting slice; and
9. controlled AR/AP, analytic, off-balance, bad-debt, write-off, and provision
   entries.

Production recovery is also a separate P0: the existing compensating actions
must remain fail-closed until real Odoo evidence proves their exact
capability-specific safety.

## Evidence required before status changes

A write may move from `declared` only through the evidence gates in
`tests/TEST.md` and `docs/DEPLOYMENT.md`. At minimum, the dedicated sandbox must
retain creation, exact readback/financial verification, identical-idempotency
replay, changed-payload conflict, controlled failure, recovery or irreversible
escalation, negative authorization, concurrency, and final audit receipts.
No source test or command-existence check can substitute for those receipts.

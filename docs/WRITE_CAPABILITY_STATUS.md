# Write capability status

This is a source-implementation audit, not Odoo execution evidence or
production authorization. The machine-readable registry and retained receipts
remain authoritative.

## Current registered writes

The current development registry contains 24 write capabilities. All 24
require approval and idempotency and have concrete
`prepare/precheck/execute/verify` source paths. Twenty-two currently reach
capability-specific ORM prechecks; payment registration and deferred creation
fail closed before ORM access. None is a registry-only placeholder, but source
presence does not make a dormant path executable.

| Capability | Implemented ORM path | Current boundary |
| --- | --- | --- |
| `acct.invoice.customer_create.v1` | Create and read back a pristine customer-invoice draft; posting is a separate capability | Real Odoo and recovery unverified |
| `acct.bill.vendor_create.v1` | Create and read back a pristine vendor-bill draft; posting is a separate capability | Real Odoo and recovery unverified |
| `acct.refund.create.v1` | Use the Odoo reversal wizard to create and verify a controlled refund draft; posting is not exposed by this capability | Real Odoo unverified |
| `acct.payment.register.v1` | Dormant payment-register wizard and payment-creation path | Precheck rejects before ORM until partner-rank and matched-payment effects can be captured and verified exactly |
| `acct.bank.statement_import.v1` | Create a statement and its statement lines | Foreign-currency bank journal rejected |
| `acct.reconciliation.apply.v1` | Reconcile explicitly selected company-currency lines at tolerance exactly `0`, without a write-off | Nonzero tolerance, every write-off field, FX, cash-basis tax, and bank-matched graphs rejected |
| `acct.asset.create.v1` | Create and validate an Enterprise asset | Canonical Odoo 19 schedule unverified |
| `acct.depreciation.post.v1` | Post one bound depreciation move | Enterprise schedule unverified |
| `acct.accrual.create.v1` | Create/post an accrual and create its future-dated scheduled reversal after the reversal-safe-account gate | Draft accruals, non-future schedules, and unsafe or reconcilable accounts rejected; real Odoo unverified |
| `acct.deferred.create.v1` | Dormant source-posting and deferred-schedule generation path | Precheck rejects before ORM until source-posting, partner-rank, and complete generated-schedule effects can be verified exactly |
| `acct.period.adjustment_create.v1` | Create an optional-post balanced adjustment after the reversal-safe-account gate | Tax-effect and unsafe or reconcilable account entries rejected |
| `acct.move.reverse.v1` | Reverse a bound move through the Odoo wizard after the reversal-safe-account gate and verify its one expected audit-message delta | Source oracle only; automatic reconciliation, concurrent chatter, and real Odoo behavior unverified |
| `acct.move.draft_cancel.v1` | Cancel a pristine dual-bound V3 invoice/bill draft after reconstructing document V2 | Direct state transition requires sandbox automation/module proof |
| `acct.journal.entry_create.v1` | Create a restricted balanced draft journal entry | AR/AP, tax, analytic, and off-balance lines rejected |
| `acct.move.post.v1` | Post a pristine V3 manual journal entry | Invoice, bill, tax, bank, payment, asset moves rejected |
| `acct.move.draft_cancel.v2` | Cancel a bound pristine manual entry or dual-bound invoice/bill draft with an approved line graph | Manual entries require explicit null V2; document branches require canonical V2; direct state transition requires sandbox automation/module proof |
| `acct.payment.cancel.v1` | Cancel a narrow-slice payment through `action_cancel` | Odoo 19 effects and reconciled payments unverified |
| `acct.recovery.execute.v1` | Receipt-derived recovery dispatch with nine reversal-bearing methods removed from executable recovery | Remaining implemented actions are test/sandbox only; the nine blocked methods return manual escalation |
| `acct.reconciliation.undo.v1` | Receipt-bound unreconcile without write-off reversal | Write-off-move plans fail closed; the no-write-off path remains test/sandbox only |
| `acct.bank.statement_compensate.v1` | Create an independent reversing statement batch | Contract permits test/sandbox only |
| `acct.invoice.customer_post.v1` | Post one exact canonical pristine V3 customer-invoice draft and verify the posted graph | Pi eligibility flow, receipt correlation, and real Odoo lifecycle unverified |
| `acct.bill.vendor_post.v1` | Post one exact canonical pristine V3 vendor-bill draft and verify the posted graph | Pi eligibility flow, receipt correlation, and real Odoo lifecycle unverified |
| `acct.refund.draft_cancel.v1` | Cancel one exact never-posted V3 refund while preserving its posted origin | Pi eligibility flow, receipt correlation, and real Odoo lifecycle unverified |
| `acct.refund.post_reconcile_origin.v1` | Post one exact pristine linked V3 customer/vendor refund with `action_post`, verify Odoo's exact full/partial origin-reconciliation graph, and commit its rank side effect in the same transaction | Manual recovery escalation; Pi receipt correlation and real Odoo lifecycle unverified |

At this snapshot every write remains:

- `evidence.level: declared`;
- `evidence.receipts: []`;
- absent from `staged_environments`; and
- absent from `enabled_environments`.

Local fake-ORM and service tests exercise these paths, but they are not real
Odoo receipts. Therefore the source-development count is 24/24 while the
real-Odoo write-evidence count is 0/24. Goal completion cannot be inferred from
the source-development count.

## Dev260 accounting and recovery safety boundary

The payment and deferred implementations remain in source for continued
development, but their prechecks now fail closed before any ORM read or write.
Payment registration cannot reopen until the partner-rank and target
matched-payment deltas are captured and verified exactly. Deferred generation
cannot reopen until source posting, partner-rank, and the complete generated
schedule graph have an exact verifier. Their presence in dispatch or an offline
Pi fixture is not evidence that either capability is currently executable.

Reconciliation now accepts only company-currency requests with
`tolerance_amount:"0"` and all three write-off fields set to `null`. Both the
domain contract and handler reject a nonzero tolerance or any write-off
account, journal, or label before invoking the reconciliation wizard.
Receipt-bound reconciliation undo may remove an exact no-write-off
reconciliation graph in its nonproduction contract; any recovery plan with an
`account.move` write-off action fails closed before mutation.

Accrual, period-adjustment, and move-reversal prechecks require every affected
account to have an explicit `account_type`, `reconcile:false`, and a type other
than `asset_receivable`, `liability_payable`, `off_balance`, `asset_cash`, or
`liability_credit_card`. Accrual creation is also post-only and requires a
future `reversal_date`; its scheduled reversal must remain a future draft with
`auto_post:"at_date"` until Odoo posts it. The matching accrual recovery action
remains registered, but it returns manual escalation before cancelling the
schedule because its origin-reversal effects do not yet have an exact evidence
graph.

Every `account.move` snapshot now calls a private control-add-on projection
that is available only inside a trusted V3 process-local execution scope after
normal user, company, and move ACL checks. The narrow privileged read observes
messages bound to that move plus their notifications and outgoing-mail queue.
It also binds message relation identities needed to reject unexpected
tracking, recipient, reaction, link-preview, starred, or attachment edges.
Only `{version, move_id, company_id, projection_digest}` is persisted in
precheck and receipt evidence; raw hidden-message counts, IDs, relation IDs,
and text hashes do not leave the trusted handler.

Refund, generic reversal, and accrual execution permit exactly the standard
Odoo internal audit log expected from the reversal wizard. The log must have no
recipient, notification, outgoing-mail, tracking, reaction, preview, starred,
or attachment edge and must bind `create_uid` and `write_uid` to the executing
user with equal create/write timestamps. Removing that one message from the
fresh raw projection must reproduce the approved aggregate digest exactly.
The raw projection rejects more than 500 records in any graph class, more than
500 IDs in any one relation, or more than 2,000 total relation edges; snapshots
also reject canonical evidence above the 60,000-character or UTF-8-byte safety
budget. None of these source tests proves real Odoo concurrency: an unrelated
worker can insert chatter without taking the move row lock. Sandbox promotion
therefore still requires a pinned-module real-Odoo test that exercises this
race and retains the signed rollback/result evidence.

Five generic move-reversal methods plus the asset, depreciation, accrual, and
deferred reversal-bearing methods are explicitly excluded from executable
recovery:

- `reverse_posted_customer_invoice_v1`;
- `reverse_posted_vendor_bill_v1`;
- `reverse_posted_refund_v1`;
- `reverse_posted_period_adjustment_v1`;
- `reverse_the_reversal_v1`;
- `cancel_asset_and_reverse_schedule_v1`;
- `reverse_depreciation_and_restore_schedule_v1`;
- `cancel_scheduled_and_reverse_accrual_origin_v1`; and
- `reverse_deferred_source_and_schedule_v1`.

These nine methods produce manual escalation. Recovery precheck, handler
execution, and the public recovery action adapter all reject a replayed plan
before mutation. The retained contracts and implementations are dormant, not
open recovery routes. A read-only review of the target Odoo 19 source found
reversal chatter and automatic reconciliation effects that are not yet
represented by their recovery result graphs. This review justifies the
fail-closed boundary; it is not real-Odoo execution evidence.

## Dev265 refund post-and-reconcile boundary

The intended Pi flow first calls
`acct.refund.post_reconcile_eligibility.v1`, then transfers the returned exact
graph into the 31-parameter `acct.refund.post_reconcile_origin.v1` request,
preview, independent approval, and execution. The write independently rebuilds
the same company-bound pristine V3 refund and unique posted origin; binds both
V1, canonical V2, and business digests; binds selected and commercial partners,
journal, currency, refund date, totals, complete line IDs, the one
receivable/payable term-line pair and account, and the expected full or partial
reconciliation outcome. A request to post without the Odoo 19 automatic origin
reconciliation has conflicting semantics and is refused.

Execution calls `action_post` once and admits only the exact partial-reconcile
record, optional full-reconcile graph, residuals, payment states, balanced moves,
audit-log delta, and partner-rank side effect described by the approved graph.
The control add-on's `res.partner._increase_rank` override is active only for
this capability inside the trusted process-local execution scope. It rejects
superuser or non-executor use, the wrong field, any delta other than one, and any
partner set other than the exact sorted selected/commercial union. That branch
uses ORM synchronously so posting, reconciliation, and rank update share one
transaction; ordinary Odoo calls retain native behavior. The committed-anchor
verifier admits only an unchanged rank or a later monotonic increment by the
same Odoo executor user as the operation, and rejects rank decreases,
other-user changes, extra records, and non-rank drift.

The read is `contract_tested` and staged only for `test`. The write is critical,
`declared`, unstaged, disabled, and has manual-escalation recovery. All current
evidence is local source, fake-ORM/add-on, state-machine, Pi-corpus, and Bridge
test evidence. No retained real Odoo write, duplicate, failure, verification,
or recovery receipt exists, so this capability cannot be described as sandbox-
or production-verified.

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

The document-post eligibility oracle and write handler both return or proceed
only for a complete company-currency, product-line, taxless graph whose invoice
lines reproduce undiscounted company-currency balances exactly. The oracle
returns the exact Odoo-created receivable/payable maturity line ID and account
ID; those values are mandatory approval inputs, are locked in the before
snapshot, and must remain unchanged after posting. Foreign-currency, taxed,
non-product-line, discounted, alternate-account, or more complex payment-term documents
fail closed. This bounded path is not full customer-invoice or vendor-bill
production coverage.

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

Dev260 adds a second immutable document digest without replacing V1. V1 remains
the exact approved-source digest; V2 is a versioned canonical digest that
normalizes decimal trailing zeros, tax-ID order, and line order by unique
`line_reference`. New invoice, bill, and refund creates store V1, V2, and the
business binding together. Posting and refund-cancellation eligibility require
V2 plus the business binding to reproduce the current graph while retaining
the stored V1 digest for source provenance. Invoice/bill draft-cancellation
eligibility and both draft-cancellation write branches apply the same
fail-closed V1/V2/business check. The `acct.move.draft_cancel.v2` manual-entry
branch is the explicit exception: manual-entry creation has no canonical
document V2, so its schema requires `expected_document_binding_v2:null`, its
stored V2 field must remain absent, and V1 plus the business binding remain
mandatory.

Dev260 also removes one-step posting from all three create contracts. Their
`posting_mode` schema accepts exactly `draft`; execution and verification reject
any non-draft state, and no create handler calls `action_post`. Customer
invoices and vendor bills may later use their dedicated document-post
capability after a fresh eligibility read, preview, and approval. Dev260 itself
did not expose refund posting; Dev265 now provides the separate declared and
disabled post-and-reconcile path described above. Refund creation is further
limited to a company-currency, taxless, non-storno, fully unpaid canonical
origin graph with exact commercial-partner and journal lineage and no external
reconciliation, payment, statement, sale, purchase, analytic, asset, or
attachment effects.

Legacy records with no V2 are rejected with an explicit provenance-migration
failure. No automatic backfill or migration write is implemented in this
release, and a mismatched V2 never falls back to V1. Both eligibility reads are
only `contract_tested`, staged for `test`, and have zero retained real-Odoo
receipts. All three writes remain `declared`, unstaged, and disabled.

The eligibility handlers rebuild normalized graphs from Odoo and require both
SHA-256 bindings to match. Refund-origin validation accepts exactly one of two
binding-shape candidates: creation recorded `posting_mode:"post"`, or creation
recorded `posting_mode:"draft"` and the current document is now posted. The
draft candidate proves only the binding recorded when the document was
created. It does not record which later caller or entry point invoked
`action_post` and therefore cannot prove that a controlled posting capability
performed that transition.

Legacy V1-only records can reject an economically equivalent current graph
because V1 preserves source decimal spelling and list order while Odoo may not.
They remain ineligible rather than being guessed or silently backfilled.
New dual-bound records use V2 normalization for current-graph comparison, but
admitting legacy records still requires a separately designed and audited
provenance migration.

Odoo 19 reversal copies do not propagate the control add-on's `copy=False`
line-reference field. The full-refund create path therefore assigns each new
invoice line a deterministic `rf-full-<origin-move-id>-<origin-line-id>`
reference while the refund is still draft. Execution and independent read-back
verification both reconstruct the same origin-to-refund mapping and compare
the accounting reversal plus product, unit, quantity, price, discount, totals,
and tax-lineage fields; a populated, ambiguous, missing, or changed reference
fails closed.

An installed-module graph, where retained, proves only that the module
name/version set remained stable. It is not a semantic allowlist of
`action_post`, `account.move.write`, or postcommit overrides. These writes must
remain disabled until a real Odoo 19 sandbox run and an explicit target-module
override review have closed that boundary.

## Missing write families

The 24 writes cover the basic accounting spine, not every write operation in
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

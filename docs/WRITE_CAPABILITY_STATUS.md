# Write capability status

This is a source-implementation audit, not Odoo execution evidence or
production authorization. The machine-readable registry and retained receipts
remain authoritative.

## Current registered writes

The current development registry contains 20 write capabilities. All 20
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

At this snapshot every write remains:

- `evidence.level: declared`;
- `evidence.receipts: []`;
- absent from `staged_environments`; and
- absent from `enabled_environments`.

Local fake-ORM and service tests exercise these paths, but they are not real
Odoo receipts. Therefore the source-development count is 20/20 while the Goal
completion count is 0/20.

## Missing write families

The 20 writes cover the basic accounting spine, not every write operation in
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
8. controlled invoice/bill draft posting and limited amendment/rebuild; and
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

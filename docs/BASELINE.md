# V3 baseline

Baseline date: 2026-07-13 (Asia/Shanghai)

## Evidence status

| Area | Current evidence | Status |
|---|---|---|
| V3 source | No V3 source directory existed before this baseline | Confirmed locally |
| V2 CLI source | Referenced as `/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2`; not present in the local workspace | Missing locally |
| Odoo bridge | Three local variants exist; `sudo_ai_bot/models/accounting_cli.py` differs from both remote snapshot copies | Divergent |
| Odoo module version | Local and remote snapshot manifests both report `1.2.0` despite differing accounting bridge content | Version collision |
| Pi Bridge | Only `_remote_pi_agent_bridge` snapshot is present locally | Historical snapshot only |
| Git history | Workspace `master` has no commits and most files are untracked | No source-of-truth baseline |
| Target server | Read-only SSH succeeded as `root`; hostname is `VM-0-6-ubuntu` | Confirmed 2026-07-13 |
| Runtime services | `odoo19.service` and `sudo-pi-agent-bridge.service` reported active | Confirmed 2026-07-13 |
| Server V2 | `/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2`, owned by `odoo:odoo`; package metadata says `0.1.0`; no Git metadata | Confirmed, untraceable source |
| Server V3 | Retained dev1/dev2 candidates exist under the earlier `/mnt` evidence root; immutable dev3 and `0.1.0.dev4-be4ec918f325` releases are externally anchored under the independent `/opt` root and are not routed | dev1 rejected by runtime identity; dev2 direct-read evidence; dev3 exposed a first-use content-binding gap; dev4 closed it and passed the repeated read/security evidence gate |
| Pi Bridge V2 copy | A second complete V2 tree exists under `/mnt/odoo/odoo19/custom/services/pi-agent-bridge/odoo_accounting_agent_cli_v2` | Confirmed duplicate |
| V2 copy equality | Active source-tree aggregate hashes differ; `commands/backend.py` also differs while both packages report `0.1.0` | Confirmed version collision |
| Odoo module | Active `sudo_ai_bot` manifest reports `1.2.0`; manifest SHA-256 is `640ddb271cf04067bc5be68de7d7fb8620e9c19a308417295650b3811279d96b` | Confirmed |
| Production writes | No authorization was provided | Prohibited |
| Sandbox database | No dedicated sandbox identity or connection evidence is available | Not verified |
| Odoo test database identity | `odoo_test`, UUID `19b09656-d10f-11f0-9065-00163e54a5ad` | Confirmed read-only |
| Read test principal | Odoo user 2, active non-superuser runtime, company 1 allowed, accounting read/user/manager groups present | Confirmed read-only |

## Local artifact hashes

The following SHA-256 values were observed during the baseline audit:

- `sudo_ai_bot/models/accounting_cli.py`: `10C27ABEAE72F439DBDB867C1684E2962D4DEB8909B35E304FA3C7B02...`
- `_remote_current_sudo_ai_bot/models/accounting_cli.py`: `367C3470A814B85C6F693C8C760A30DCF6C273074456DEA04549FF178...`
- `_remote_sudo_ai_bot/models/accounting_cli.py`: identical to the remote-current snapshot
- `_remote_pi_agent_bridge/server.mjs`: `FAE40056F346DF95E55443A1CA44CFD580577C6A7505B87BB46ABF9F1...`
- `_remote_pi_agent_bridge/extensions/odoo-tools.ts`: `C34484BFB5934513DB85A594049A3360B1AF62F2496C4C951B4CAA000...`

Ellipses reflect truncated console evidence. A server-authoritative inventory and
full hash manifest must be generated after read-only SSH access is restored.

## Server evidence captured

- V2 active-source aggregate: `e25af9e41f1f79d629404d1106f9bb61999b3fe795dcfb8d4236589b5c0bd69d`
- Pi Bridge embedded V2 aggregate: `8c3730499ce554ca2bf0a58c2332d8800b1cb05c4f7188b5ba2a05dc5672428f`
- Tools V2 `commands/backend.py`: `2ce74f56013a85771b05c179b2f95dc80ea2981ee1668114383131cfcc179131`
- Pi Bridge V2 `commands/backend.py`: `b9a6405040f25b518eda82ce5caf3348cac73d4453509939c3a354652813cb78`
- Pi Bridge `server.mjs`: `fae40056f346df95e55443a1ca44cfd580577c6a7505b87bb46abf9f1d60df9f`
- Odoo service runs as `odoo:odoo` using `/opt/odoo/odoo19/odoo-server/odoo-bin`.
- Pi Bridge runs as `odoo:odoo` from `/mnt/odoo/odoo19/custom/services/pi-agent-bridge`.
- Odoo configured add-ons path includes `/mnt/odoo/odoo19/custom/addons`; HTTP port is 8070.
- Odoo databases observed: `codex_sgf_test_20260713_01`, `odoo`, `odoo_2601`, `odoo_sg`, and `odoo_test` (plus PostgreSQL administrative databases).
- `account` version `19.0.1.4` and `account_accountant` version `19.0.1.1` are installed in all five observed Odoo databases.
- `sudo_ai_bot` version `19.0.1.2.0` is installed in `codex_sgf_test_20260713_01`, `odoo_2601`, `odoo_sg`, and `odoo_test`; it is uninstalled in `odoo`.
- `codex_sgf_test_20260713_01` contains companies `YourCompany`, `My US Company`, and `SG Company`. Its sandbox role is not yet proven by configuration or user confirmation, so no write is authorized.

The server V2 directory contains many in-place backup trees and generated
artifacts. These are evidence inputs only and must not be copied wholesale into
V3. Reuse decisions require per-module provenance, focused tests, and review.

## V2 live read-only baseline

Read-only commands were executed on `odoo_test`, company 1, with an explicit
single-company scope and no write-capable command:

| Command | Result | Evidence summary |
|---|---|---|
| `gl trial-balance --date-from 2026-01-01 --date-to 2026-07-13 --company-id 1 --limit 5` | `ok=true` | Real `account.move.line/account.account` query, CNY, 14 total accounts, paginated |
| `ar open-items --date-from 2026-01-01 --date-to 2026-07-13 --company-id 1 --limit 5` | `ok=true` | Five real posted receivable lines returned with move-line IDs and residuals |
| `ap unpaid-bills --company-id 1 --database odoo_test --limit 5` | `ok=true` | 81 unpaid bills summarized; five real bill IDs returned |

These results prove the three V2 read paths can query the current Odoo 19 test
database. They do not yet prove financial correctness, complete pagination,
user ACL behavior, or V3 readiness. In particular, V2's trial-balance summary
was obtained from a limited page and must not be accepted as a full balanced
trial balance without an independent gold-standard reconciliation.

V2 exposes 248 collectable unit tests. Collection is evidence of test presence,
not test success, and no write-oriented test was executed during this audit.

## V2 reuse record: AR open items

For `acct.ar.open_items.v1`, both deployed V2 copies of
`src/odoo_acc_cli/commands/ar.py` were inspected read-only and had the same
SHA-256,
`0d2c28407bc7131fe48b727a7cc77d4c0e15adf67255851219b99742549af765`.
V3 ports only the useful business predicates and field ideas: explicit company,
posted receivable lines, partner/due-date/source identifiers, stable
`date_maturity, date, id` ordering, aging buckets, and read-only side-effect
tests. V3 has no import or runtime dependency on either V2 tree.

The V2 implementation itself was rejected as the V3 accounting algorithm. Its
hard-coded database/company, `reconciled=False`, `amount_residual > 0`, limited
invoice/refund move types, float conversion, and page-sized `total_count` omit
credits and unmatched payments and cannot answer a historical cutoff. The V3
formula was instead checked against Odoo 19's move-line residual implementation
(server file SHA-256
`2f867883ce6359501915a4d6d6ef9e8c34833d65ad27b68cc1769203505cbcf2`)
and aged-partner report (SHA-256
`3fed261ced83ae82b20a840e6c6ad5bd462d91c820f6af214224cc6323d71034`).
It separately applies debit/credit partial-reconcile amounts through the signed
accounting date, rounds each company/transaction residual before testing and
summing it, and discloses that the result uses Odoo's current reconciliation
graph rather than an immutable event history.

## V2 reuse record: AP open items

The active and development V2 copies of `src/odoo_acc_cli/commands/ap.py` were
also inspected read-only and matched SHA-256
`d193845a4fbfafb8081ea57057b9dd9f9764717f5c665c55c81bc6ee06b569a5`.
V3 retains only interface and presentation ideas such as explicit supplier and
date filters, stable sorting, structured errors, and bill source fields. It
does not import or copy V2's AP accounting algorithm.

V2 filters `account.move` to `in_invoice`, reads the current
`amount_residual`, and uses `as_of_date` only for aging. It therefore omits
refunds, payments/prepayments, and manual payable entries, includes documents
after a historical cutoff, and combines transaction currencies incorrectly.
A read-only comparison found V2's current 81-bill view at `7,500.15 CNY`, while
the complete raw AML residual population also contained two open payable
entries totaling `+11,250.00 CNY`; the 81 bills totaled `-7,500.15 CNY`, for a
raw net residual of `+3,749.85 CNY`. At `2026-03-31`, the independently derived
raw net was `+3,975.85 CNY`, while V2 still returned the current 81-bill total.
These findings make V2 useful as a regression fixture, not as the V3 AP oracle.
The real fixture currently lacks open supplier refunds, foreign-currency AP,
and partial-payment examples; those remain explicit sandbox evidence gaps.

An independent SQL/ORM oracle for `odoo_test`, company 1, posted entries, and
the inclusive 2026 calendar-year period found 2,341 move lines across 12 active
accounts. Full-period debit and credit both equal `136193.63`; the difference is
`0.00`. Odoo 19 `_read_group` result shape was verified directly. This oracle is
the first V3 trial-balance standard answer; it is not yet a release-bound V3
execution receipt.

## Pi/Odoo bridge baseline

- Pi Bridge package metadata says `1.0.0` and depends on Pi coding agent
  `^0.80.6`, while its live health endpoint reports Pi Agent `0.78.1`.
- The bridge exposes only five Odoo tools: context, skill list/execute, report
  list/export. It has no V3 query/prepare/preview/approve/status/verify/recover
  tool surface.
- The Odoo tool controller uses a service token but accepts caller-supplied user
  and company IDs. Its current implementation does not demonstrate that the
  selected company belongs to the selected user's allowed companies. V3 must
  not inherit this trust boundary.
- Odoo's accounting bridge exposes 22 named read-only V2 mappings but commonly
  forwards only positional strings; it is not a strict V3 parameter contract.

## Boundary decision

- Local V3 source root: `odoo-accounting-cli-v3/`
- Trusted server runtime root: `/opt/odoo-accounting-cli-v3/releases/<version-commit>/`
- Retained `/mnt/.../odoo_accounting_agent_cli_v3` candidates are deployment
  evidence only and are not a source or runtime root.
- Proposed immutable package name: `odoo-accounting-cli-v3-<version>-<commit>.tar.gz`
- V2 remains unchanged and independently runnable.
- V3 may consume audited V2 logic only through a documented import/port record;
  copied code must retain provenance and tests.

The first independently deployed candidate, `0.1.0.dev1`, verified its package,
manifest, commit, ownership, and V2 isolation, but source-mode CLI execution
reported `version unknown`. It was not linked as current and no Pi/Odoo routing
was changed. `0.1.0.dev2` adds an externally anchored runtime identity command;
the failed candidate remains immutable evidence rather than being patched in
place.

The independently deployed dev3 test candidate reported one consistent commit,
package, manifest, and registry identity from `/opt`, passed four real Linux
runner gates, and returned a signed Odoo trial-balance receipt for `odoo_test`,
company 1, user 2. The full ledger contained 15 rows; period debit and credit
both equaled `136193.63` and the difference was `0.00`. Cross-process replay of
the same token was rejected. During the next negative-test review, the auth
context was found not to bind capability ID plus parameters before first use.
Dev3 is therefore retained as diagnostic evidence only, remains staged rather
than enabled, and must not be routed to Pi. Dev4 adds that missing signed content
digest. Its immutable server release repeated the Linux isolation gates and a
real `odoo_test` trial balance for company 1/user 2: 15 accounts, debit and
credit `136193.63`, difference `0.00`, with a verified Odoo receipt. Separate
process tests rejected content tampering, replay, ACL denial, bound-company
escape, wrong database UUID, and expiry; an independent SQL oracle matched a
date/currency/pagination parameter round-trip, and the six-event audit chain
verified. The evidence bundle is root-owned and read-only. Dev4 remains staged:
it has no Pi route, enables no capability, and proves no write lifecycle.

The immutable dev5 candidate `0.1.0.dev5-fc6822dae8ba` subsequently passed the
same target-Linux isolation gate and real `odoo_test` trial-balance oracle from
its exact release artifact. Its package SHA-256 is
`877e451ebe732328519f38fd67c16633d705e2f105602e3a550b6edc469fa958`; its
manifest SHA-256 is
`2f9a769d2a31385ed61306c06d0138b12b8a6ab9904c562897f4c41291abbcdf`.
GitHub Actions run `29306441122` passed Python 3.11, Python 3.12, and an
outside-source wheel smoke test. Three verified signed reads and their atomic
audit events form a valid chain with head
`27b9666107df1e12317449cc6bca9d1c3969f36f0e9e2bc67c1980e826c6bf0e`.
The frozen root-owned evidence bundle reverified all 57 listed files. No
`current` link, V3 unit, Pi route, Odoo/Pi restart, V2 change, enabled
capability, or Odoo write was made. Dev5 therefore remains retained staged
evidence and is not a production promotion.

The immutable dev6 candidate `0.1.0.dev6-6cb907aa66b5` then added the signed
ACL-filtered capability registry and historical AR open-items read. Its exact
package SHA-256 is
`5c0ef5c976c63e702e6387da5e14787d9c1d68655268aa509da484b4f86245be`;
GitHub Actions run `29309569392` passed Python 3.11, Python 3.12, and the
outside-source wheel smoke job. Six independent read-only SQL oracles matched
the real `odoo_test` results, including the company-1 current and historical
cutoffs, company-2 foreign currency, partner/currency filters, and pagination.
The frozen evidence bundle has 131 verified checksum entries; its external
anchor records checksum-manifest SHA-256
`653a66f52c0b2d7173ab38e1ca00ac7af28b1c8f34b9af0031c5c2841705493b`.
Dev6 remains staged with zero enabled capabilities. Real partial/unmatched
payment fixtures, production-scale execution, immutable runtime ownership, Pi
E2E, sandbox write lifecycles, and production trust separation remain open.

The immutable dev7 candidate `0.1.0.dev7-4bfe445ca5e4` then added the AP
open-items read without importing V2's incorrect AP residual algorithm. Its
canonical package SHA-256 is
`d51fd4bd1655a58081fd7693134c9c1ade34b383771c34c3398b4a85e18822b5`;
GitHub Actions run `29314765337` passed all three jobs. Six independent
read-only AP SQL oracles matched signed Odoo results, and the security,
parameter, persistence, receipt, and isolation gates passed. The frozen
root-owned evidence bundle contains 98 files and 97 checksum entries; its
external anchor records checksum-manifest SHA-256
`9b1b46486a8de04221198da719ebcc2411558cd79a0a31be713db6f756c9463b`.
Dev7 remains staged with zero enabled capabilities. Its retained evidence also
records that a wheel-installed business read is intentionally rejected because
site-packages is not the configured immutable release source. Dev8 therefore
formalizes the exact release launcher and retained canonical-package binding;
it does not weaken the exact-source check or turn the wheel into a second
production artifact.

## Phase-one exit gate

The read-only inventory baseline is complete for the running Odoo service, V2
CLI, Pi Bridge, relevant service/configuration paths, package metadata, divergent
file identities, database names, a test database UUID, and a non-superuser
accounting principal. The dedicated write-sandbox identity remains unconfirmed;
this keeps every write gate closed but does not block the read-only V3 vertical
slice. No production write test was authorized or performed.

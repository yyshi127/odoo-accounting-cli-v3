# Dev253 report-definition candidate capture

`capture_report_definition.py` creates a deterministic **candidate** for an
independently reviewed accounting-report definition baseline. It does not
approve, install, route, or promote that candidate. Every output fixes
`candidate_is_approval=false` and `production_promotion_allowed=false`.

The capture is bound to an operator-supplied database name, canonical database
UUID, PostgreSQL system identifier, and company ID. It resolves exactly these
four trusted roots:

| family | kind / `report_key` | root XMLID |
| --- | --- | --- |
| `tax` | `generic_tax` | `account.generic_tax_report` |
| `financial` | `balance_sheet` | `account_reports.balance_sheet` |
| `financial` | `cash_flow` | `account_reports.cash_flow_report` |
| `financial` | `profit_and_loss` | `account_reports.profit_and_loss` |

The pure function
`odoo_accounting_cli_v3.report_definition_projection.build_root_definition_projection`
is shared by the collector and the later runtime guard. It follows variants
and sections recursively, uses semantic XMLIDs rather than Odoo record IDs,
and produces the exact per-root input used for `definition_sha256`. That input
also contains the canonical company profile, installed-module graph, and a
per-root source-projection digest, so changes to currency, country, chart,
fiscal configuration, or installed modules change the definition digest.

## Read-only boundary

The injected database adapter must begin in `IDLE`. The collector issues, in
order:

1. `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`;
2. `SET LOCAL search_path = pg_catalog`;
3. a boundary read proving `repeatable read`, `read_only=on`,
   `search_path=pg_catalog`, database name, and PostgreSQL system identifier;
4. all projections inside that same transaction;
5. a second database-identity and boundary read;
6. `rollback`, followed by an `IDLE` check.

No candidate is returned or written until rollback and the final `IDLE` check
succeed. Missing, extra, duplicated, ambiguous, unreachable, cross-report, or
transaction-drift data fails closed. The production adapter imports
`psycopg2` only inside `PsycopgAdapter.connect`; unit tests use only a fake
adapter and never contact Odoo or PostgreSQL.

## Canonical document fields

All objects have exact field sets. Lists are deterministically sorted and
unique. Every leaf is a JSON primitive. Decimal values are canonical strings;
dates are `YYYY-MM-DD` or `null`; timestamps are UTC
`YYYY-MM-DDTHH:MM:SS.ffffffZ` or `null`. The serialized form is sorted-key,
compact UTF-8 JSON with exactly one trailing LF.

Top level:

- `schema_version`
- `document_type`
- `captured_at`
- `candidate_is_approval`
- `production_promotion_allowed`
- `database`
- `company`
- `report_roots`
- `reports`
- `module_graph`
- `source_projection`
- `definition_sha256`

`database`:

- `name`
- `uuid`
- `postgresql_system_identifier`

`company`:

- `company_id`
- `name`
- `country_code`
- `account_fiscal_country_code`
- `chart_template`
- `currency`: `name`, `symbol`, `decimal_places`, `rounding`
- `fiscal`: `fiscalyear_last_day`, `fiscalyear_last_month`,
  `fiscalyear_lock_date`, `tax_lock_date`, `hard_lock_date`
- `write_date`

Each `report_roots[]` entry:

- `report_key` - one of the four canonical `kind` values above
- `baseline_identity`: `database_uuid`, `company_id`, `family`, `kind`,
  `root_xmlid`
- `variant_report_keys`
- `section_report_keys`
- `definition_sha256` - SHA-256 of the shared pure per-root projection

The strict per-root projection hashed by that digest has exactly:

- `schema_version`
- `baseline_identity`
- `company_profile`
- `module_graph`
- `reports` (the recursively reachable root/variant/section closure)
- `source_projection` (digests of `company_profile`, `module_graph`, and the
  per-root `reports`)

Each `reports[]` entry:

- `key`, `xmlid`, `name`, `root_report_key`
- `active`, `sequence`, `country_code`, `chart_template`,
  `availability_condition`, `use_sections`
- `section_report_keys`
- `custom_handler_model`
- `options`
- `columns`
- `lines`
- `write_date`

`options`:

- `only_tax_exigible`, `load_more_limit`, `search_bar`,
  `prefix_groups_threshold`, `integer_rounding`, `allow_foreign_vat`
- `default_opening_date_filter`, `currency_translation`
- `filter_multi_company`, `filter_date_range`, `filter_show_draft`,
  `filter_unreconciled`, `filter_unfold_all`, `filter_hide_0_lines`,
  `filter_period_comparison`, `filter_growth_comparison`,
  `filter_journals`

Each `columns[]` entry:

- `key`, `name`, `expression_label`, `sequence`
- `sortable`, `figure_type`, `blank_if_zero`
- `custom_audit_action_xmlid`
- `write_date`

Each `lines[]` entry:

- `key`, `parent_key`, `name`, `code`, `sequence`, `hierarchy_level`
- `groupby`, `user_groupby`
- `foldable`, `print_on_new_page`, `hide_if_zero`,
  `horizontal_split_side`
- `action_xmlid`
- `expressions`
- `write_date`

Each `expressions[]` entry:

- `key`, `label`, `engine`, `formula`, `subformula`
- `domain` - exactly `formula` for the `domain` engine, otherwise `null`
- `date_scope`, `figure_type`, `green_on_positive`, `blank_if_zero`,
  `auditable`, `carryover_target`
- `write_date`

`module_graph`:

- `schema_version`
- `modules[]`: `name`, `latest_version`, `write_date`, `dependencies`
- each dependency: `name`, `auto_install_required`
- `digest`

`source_projection`:

- `schema_version`
- `projections[]`: `name`, `row_count`, `sha256`
- `digest`

The top-level `definition_sha256` covers exactly:
`schema_version`, `database`, `company`, `report_roots`, `reports`,
`module_graph`, and `source_projection`. It intentionally excludes capture
time and the two always-false safety declarations.

## Invocation

The formal Dev29 path passes the DSN through a sealed/private inherited file
descriptor. It never puts the DSN in command arguments or the process
environment:

```sh
python deployment/dev253/capture_report_definition.py \
  --environment production \
  --dsn-fd <private-inherited-fd> \
  --database-name <database> \
  --database-uuid <uuid> \
  --postgresql-system-identifier <system-id> \
  --company-id <company-id> \
  --output /var/lib/odoo-accounting-cli-v3/evidence/<candidate>.json
```

`--dsn-file` is available only for non-production operation and accepts only a
single-link regular file that is root-owned and mode `0600` on Linux. The
environment path is disabled by default. Local development must opt in with
both `--environment development` and `--allow-development-dsn-env`; that path
reads only `ODOO_ACCOUNTING_CLI_V3_REPORT_DEFINITION_DSN` and is never accepted
for production.

Without `--output`, canonical JSON is written to stdout. A named output must
have an existing canonical parent and must not already exist. On Linux, output
beneath `/root` is rejected; use
`/var/lib/odoo-accounting-cli-v3/evidence` for retained candidates or
`/opt/odoo-accounting-cli-v3/tmp` for explicitly transient output. The
collector never prints the DSN or driver exception text.

## Non-approval boundary

This artifact is only an observed candidate. Before it can become a trusted
baseline it still needs immutable release binding, independent accounting/tax
review, signature and publication controls, and a runtime comparison that
recomputes the same per-root projection before and after report execution.
Nothing in this directory provides those approvals.

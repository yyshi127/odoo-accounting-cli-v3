from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from decimal import Decimal
from pathlib import Path

import psycopg2


QUERY = r"""
WITH base AS (
    SELECT
        aml.id AS move_line_id,
        aml.move_id,
        aml.payment_id,
        aml.date AS line_date,
        aml.date_maturity AS due_date,
        aml.partner_id,
        aml.account_id,
        aml.journal_id,
        COALESCE(aml.currency_id, company.currency_id) AS currency_id,
        aml.balance,
        aml.amount_currency,
        aml.reconciled AS current_reconciled,
        company.currency_id AS company_currency_id,
        company_currency.name AS company_currency_name,
        company_currency.rounding AS company_rounding,
        line_currency.name AS line_currency_name,
        line_currency.rounding AS line_rounding
    FROM account_move_line AS aml
    JOIN account_account AS account ON account.id = aml.account_id
    JOIN res_company AS company ON company.id = aml.company_id
    JOIN res_currency AS company_currency
      ON company_currency.id = company.currency_id
    JOIN res_currency AS line_currency
      ON line_currency.id = COALESCE(aml.currency_id, company.currency_id)
    WHERE aml.company_id = %(company_id)s
      AND aml.parent_state = 'posted'
      AND account.account_type = 'asset_receivable'
      AND aml.date <= %(as_of_date)s
      AND (%(partner_id)s IS NULL OR aml.partner_id = %(partner_id)s)
      AND (
          %(currency_id)s IS NULL
          OR COALESCE(aml.currency_id, company.currency_id) = %(currency_id)s
      )
), partial_entries AS (
    SELECT
        partial.debit_move_id AS move_line_id,
        partial.amount AS debit_company,
        0::numeric AS credit_company,
        partial.debit_amount_currency AS debit_currency,
        0::numeric AS credit_currency,
        1::bigint AS matched_count
    FROM account_partial_reconcile AS partial
    WHERE partial.company_id = %(company_id)s
      AND partial.max_date <= %(as_of_date)s
    UNION ALL
    SELECT
        partial.credit_move_id AS move_line_id,
        0::numeric AS debit_company,
        partial.amount AS credit_company,
        0::numeric AS debit_currency,
        partial.credit_amount_currency AS credit_currency,
        1::bigint AS matched_count
    FROM account_partial_reconcile AS partial
    WHERE partial.company_id = %(company_id)s
      AND partial.max_date <= %(as_of_date)s
), partial_totals AS (
    SELECT
        move_line_id,
        SUM(debit_company) AS debit_company,
        SUM(credit_company) AS credit_company,
        SUM(debit_currency) AS debit_currency,
        SUM(credit_currency) AS credit_currency,
        SUM(matched_count) AS matched_count
    FROM partial_entries
    GROUP BY move_line_id
), calculated AS (
    SELECT
        base.*,
        COALESCE(partial_totals.matched_count, 0) AS matched_count,
        ROUND(
            (
                base.balance
                - COALESCE(partial_totals.debit_company, 0)
                + COALESCE(partial_totals.credit_company, 0)
            ) / base.company_rounding
        ) * base.company_rounding AS residual_company,
        ROUND(
            (
                base.amount_currency
                - COALESCE(partial_totals.debit_currency, 0)
                + COALESCE(partial_totals.credit_currency, 0)
            ) / base.line_rounding
        ) * base.line_rounding AS residual_currency
    FROM base
    LEFT JOIN partial_totals
      ON partial_totals.move_line_id = base.move_line_id
), base_count AS (
    SELECT COUNT(*) AS source_count FROM base
)
SELECT
    calculated.*,
    base_count.source_count
FROM calculated
CROSS JOIN base_count
WHERE calculated.residual_company <> 0
   OR calculated.residual_currency <> 0
ORDER BY calculated.due_date NULLS LAST,
         calculated.line_date,
         calculated.move_line_id
"""


def amount(value: Decimal, rounding: Decimal) -> str:
    places = max(0, -rounding.normalize().as_tuple().exponent)
    return f"{value:.{places}f}"


payload = json.loads(Path(sys.argv[1]).read_text("utf-8"))
actual = payload["data"]["result"]
filters = actual["filters"]
parameters = {
    "company_id": filters["company_id"],
    "as_of_date": filters["as_of_date"],
    "partner_id": filters["partner_id"],
    "currency_id": filters["currency_id"],
}

connection = psycopg2.connect(dbname="odoo_test")
connection.set_session(
    isolation_level="REPEATABLE READ",
    readonly=True,
    autocommit=False,
)
try:
    with connection.cursor() as cursor:
        cursor.execute(QUERY, parameters)
        names = [item.name for item in cursor.description]
        rows = [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
        cursor.execute(
            "SELECT current_setting('transaction_isolation'), "
            "current_setting('transaction_read_only')"
        )
        isolation, read_only = cursor.fetchone()
finally:
    connection.rollback()
    connection.close()

expected_items = []
currency_totals: dict[int, dict[str, object]] = defaultdict(
    lambda: {
        "item_count": 0,
        "debit": Decimal("0"),
        "credit": Decimal("0"),
    }
)
company_debit = Decimal("0")
company_credit = Decimal("0")
for row in rows:
    company_residual = row["residual_company"]
    currency_residual = row["residual_currency"]
    company_rounding = row["company_rounding"]
    line_rounding = row["line_rounding"]
    direction = company_residual if company_residual != 0 else currency_residual
    expected_items.append(
        {
            "move_line_id": row["move_line_id"],
            "move_id": row["move_id"],
            "payment_id": row["payment_id"],
            "line_date": row["line_date"].isoformat(),
            "due_date": row["due_date"].isoformat() if row["due_date"] else None,
            "partner_id": row["partner_id"],
            "account_id": row["account_id"],
            "journal_id": row["journal_id"],
            "currency_id": row["currency_id"],
            "original_company_amount": amount(row["balance"], company_rounding),
            "residual_company_amount": amount(company_residual, company_rounding),
            "original_currency_amount": amount(row["amount_currency"], line_rounding),
            "residual_currency_amount": amount(currency_residual, line_rounding),
            "side": "debit" if direction > 0 else "credit",
            "partial_reconcile_count": int(row["matched_count"]),
            "current_reconciled": row["current_reconciled"],
        }
    )
    if company_residual > 0:
        company_debit += company_residual
    elif company_residual < 0:
        company_credit -= company_residual
    group = currency_totals[row["currency_id"]]
    group["name"] = row["line_currency_name"]
    group["rounding"] = line_rounding
    group["item_count"] += 1
    if currency_residual > 0:
        group["debit"] += currency_residual
    elif currency_residual < 0:
        group["credit"] -= currency_residual

actual_items = [
    {key: item[key] for key in expected_items[0]}
    for item in actual["items"]
] if expected_items else []
page_offset = actual["page"]["offset"]
page_limit = actual["page"]["limit"]
expected_page_items = expected_items[page_offset : page_offset + page_limit]
page_company_debit = sum(
    (
        row["residual_company"]
        for row in rows[page_offset : page_offset + page_limit]
        if row["residual_company"] > 0
    ),
    Decimal("0"),
)
page_company_credit = -sum(
    (
        row["residual_company"]
        for row in rows[page_offset : page_offset + page_limit]
        if row["residual_company"] < 0
    ),
    Decimal("0"),
)

company_rounding = rows[0]["company_rounding"] if rows else Decimal("0.01")
expected_ledger = {
    "item_count": len(rows),
    "debit_residual": amount(company_debit, company_rounding),
    "credit_residual": amount(company_credit, company_rounding),
    "net_residual": amount(company_debit - company_credit, company_rounding),
}
expected_page_summary = {
    "item_count": len(expected_page_items),
    "debit_residual": amount(page_company_debit, company_rounding),
    "credit_residual": amount(page_company_credit, company_rounding),
    "net_residual": amount(
        page_company_debit - page_company_credit, company_rounding
    ),
}
expected_currencies = []
for currency_id in sorted(currency_totals):
    group = currency_totals[currency_id]
    expected_currencies.append(
        {
            "currency_id": currency_id,
            "currency_name": group["name"],
            "item_count": group["item_count"],
            "debit_residual": amount(group["debit"], group["rounding"]),
            "credit_residual": amount(group["credit"], group["rounding"]),
            "net_residual": amount(
                group["debit"] - group["credit"], group["rounding"]
            ),
        }
    )

checks = {
    "page_rows": actual_items == expected_page_items,
    "page_summary": actual["page_summary"] == expected_page_summary,
    "ledger_summary": actual["ledger_summary"] == expected_ledger,
    "currency_summaries": actual["currency_summaries"] == expected_currencies,
    "total_count": actual["page"]["total_count"] == len(rows),
    "page_count": actual["page"]["count"] == len(expected_page_items),
}
normalized_rows = json.dumps(
    expected_items,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
report = {
    "checks": checks,
    "all_checks_passed": all(checks.values()),
    "filters": filters,
    "source_line_count": rows[0]["source_count"] if rows else 0,
    "open_item_count": len(rows),
    "ledger_summary": expected_ledger,
    "currency_summaries": expected_currencies,
    "current_reconciled_count": sum(
        row["current_reconciled"] for row in rows
    ),
    "partial_as_of_count": sum(row["matched_count"] > 0 for row in rows),
    "financial_rows_sha256": hashlib.sha256(normalized_rows).hexdigest(),
    "transaction_isolation": isolation,
    "transaction_read_only": read_only,
    "rollback_completed": True,
}
print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
if not report["all_checks_passed"]:
    raise SystemExit(1)

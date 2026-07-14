from __future__ import annotations

import json
import sys
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import psycopg2


QUERY = r"""
SELECT
    account.id AS account_id,
    account.account_type,
    COALESCE(SUM(line.balance) FILTER (WHERE line.date < %(date_from)s), 0)
        AS opening_balance,
    COALESCE(SUM(line.debit) FILTER (
        WHERE line.date >= %(date_from)s AND line.date <= %(date_to)s
    ), 0) AS period_debit,
    COALESCE(SUM(line.credit) FILTER (
        WHERE line.date >= %(date_from)s AND line.date <= %(date_to)s
    ), 0) AS period_credit,
    COUNT(*) AS move_line_count,
    currency.rounding
FROM account_move_line AS line
JOIN account_account AS account ON account.id = line.account_id
JOIN res_company AS company ON company.id = line.company_id
JOIN res_currency AS currency ON currency.id = company.currency_id
WHERE line.company_id = %(company_id)s
  AND line.parent_state = 'posted'
  AND line.date <= %(date_to)s
  AND account.account_type <> 'off_balance'
  AND (%(account_id)s IS NULL OR account.id = %(account_id)s)
GROUP BY account.id, account.account_type, currency.rounding
ORDER BY account.id
"""


def amount(value: Decimal, rounding: Decimal) -> str:
    rounded = (value / rounding).quantize(
        Decimal("1"), rounding=ROUND_HALF_UP
    ) * rounding
    places = max(0, -rounding.normalize().as_tuple().exponent)
    return f"{rounded:.{places}f}"


request = json.loads(Path(sys.argv[1]).read_text("utf-8"))
response = json.loads(Path(sys.argv[2]).read_text("utf-8"))
parameters = request["parameters"]
actual = response["data"]["result"]

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

expected = {}
for row in rows:
    opening = row["opening_balance"]
    debit = row["period_debit"]
    credit = row["period_credit"]
    period = debit - credit
    rounding = row["rounding"]
    expected[row["account_id"]] = {
        "account_id": row["account_id"],
        "account_type": row["account_type"],
        "opening_balance": amount(opening, rounding),
        "period_debit": amount(debit, rounding),
        "period_credit": amount(credit, rounding),
        "period_balance": amount(period, rounding),
        "closing_balance": amount(opening + period, rounding),
        "move_line_count": row["move_line_count"],
    }

actual_rows = {
    row["account_id"]: {
        key: row[key]
        for key in (
            "account_id",
            "account_type",
            "opening_balance",
            "period_debit",
            "period_credit",
            "period_balance",
            "closing_balance",
            "move_line_count",
        )
    }
    for row in actual["lines"]
}
rounding = Decimal(actual["currency"]["rounding"])
opening_total = sum((row["opening_balance"] for row in rows), Decimal("0"))
debit_total = sum((row["period_debit"] for row in rows), Decimal("0"))
credit_total = sum((row["period_credit"] for row in rows), Decimal("0"))
period_total = debit_total - credit_total
expected_summary = {
    "opening_balance": amount(opening_total, rounding),
    "period_debit": amount(debit_total, rounding),
    "period_credit": amount(credit_total, rounding),
    "period_balance": amount(period_total, rounding),
    "closing_balance": amount(opening_total + period_total, rounding),
    "debit_credit_difference": amount(period_total, rounding),
    "is_balanced": period_total == 0,
}
checks = {
    "account_rows": actual_rows == expected,
    "ledger_summary": actual["ledger_summary"] == expected_summary,
    "page_summary": actual["page_summary"] == expected_summary,
    "page_count": actual["page"]["count"] == len(rows),
    "total_count": actual["page"]["total_count"] == len(rows),
}
report = {
    "all_checks_passed": all(checks.values()),
    "checks": checks,
    "account_count": len(rows),
    "move_line_count": sum(row["move_line_count"] for row in rows),
    "ledger_summary": expected_summary,
    "transaction_isolation": isolation,
    "transaction_read_only": read_only,
    "rollback_completed": True,
}
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
if not report["all_checks_passed"]:
    raise SystemExit(1)

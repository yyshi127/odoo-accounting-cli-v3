#!/usr/bin/env python3
"""Independent read-only PostgreSQL oracle for a signed dev7 AP response."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import psycopg2


CAPABILITY_ID = "acct.ap.open_items.v1"
BASIS = "odoo_accounting_date_current_reconciliation_graph"
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
        account.code_store ->> aml.company_id::text AS account_code,
        aml.journal_id,
        journal.code AS journal_code,
        move.move_type,
        COALESCE(aml.currency_id, company.currency_id) AS currency_id,
        aml.balance,
        aml.amount_currency,
        aml.reconciled AS current_reconciled,
        company.currency_id AS company_currency_id,
        company_currency.name AS company_currency_name,
        company_currency.symbol AS company_currency_symbol,
        company_currency.rounding AS company_rounding,
        line_currency.name AS line_currency_name,
        line_currency.rounding AS line_rounding
    FROM account_move_line AS aml
    JOIN account_account AS account ON account.id = aml.account_id
    JOIN account_move AS move ON move.id = aml.move_id
    JOIN account_journal AS journal ON journal.id = aml.journal_id
    JOIN res_company AS company ON company.id = aml.company_id
    JOIN res_currency AS company_currency
      ON company_currency.id = company.currency_id
    JOIN res_currency AS line_currency
      ON line_currency.id = COALESCE(aml.currency_id, company.currency_id)
    WHERE aml.company_id = %(company_id)s
      AND aml.parent_state = 'posted'
      AND account.account_type = 'liability_payable'
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
)
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
ORDER BY base.due_date NULLS LAST, base.line_date, base.move_line_id
"""

COMPANY_CURRENCY_QUERY = r"""
SELECT currency.id, currency.name, currency.symbol, currency.rounding
FROM res_company AS company
JOIN res_currency AS currency ON currency.id = company.currency_id
WHERE company.id = %(company_id)s
"""

ITEM_FIELDS = (
    "move_line_id",
    "move_id",
    "move_type",
    "payment_id",
    "line_date",
    "due_date",
    "partner_id",
    "account_id",
    "account_code",
    "journal_id",
    "journal_code",
    "currency_id",
    "original_company_amount",
    "residual_company_amount",
    "original_currency_amount",
    "residual_currency_amount",
    "side",
    "reconciliation_status",
    "partial_reconcile_count",
    "current_reconciled",
    "days_overdue",
    "aging_bucket",
)


def rounded(value: Decimal, increment: Decimal) -> Decimal:
    return (
        (value / increment).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        * increment
    )


def amount(value: Decimal, increment: Decimal) -> str:
    value = rounded(value, increment)
    places = max(0, -increment.normalize().as_tuple().exponent)
    return f"{value:.{places}f}"


def rounding_text(value: Decimal) -> str:
    return format(value.normalize(), "f")


def aging(as_of_date: date, due_date: date | None) -> tuple[int | None, str]:
    if due_date is None:
        return None, "no_due_date"
    days = (as_of_date - due_date).days
    if days <= 0:
        return days, "current"
    if days <= 30:
        return days, "days_1_30"
    if days <= 60:
        return days, "days_31_60"
    if days <= 90:
        return days, "days_61_90"
    return days, "over_90"


def company_summary(
    rows: list[tuple[dict[str, object], Decimal, Decimal]], rounding: Decimal
) -> dict[str, object]:
    residuals = [company for _item, company, _currency in rows]
    debit = sum((value for value in residuals if value > 0), Decimal("0"))
    credit = -sum((value for value in residuals if value < 0), Decimal("0"))
    return {
        "item_count": len(rows),
        "debit_residual": amount(debit, rounding),
        "credit_residual": amount(credit, rounding),
        "net_residual": amount(debit - credit, rounding),
    }


def digest(value: object) -> str:
    normalized = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: dev7-ap-sql-oracle.py REQUEST_JSON RESPONSE_JSON")
    request = json.loads(Path(sys.argv[1]).read_text("utf-8"))
    response = json.loads(Path(sys.argv[2]).read_text("utf-8"))
    parameters = request["parameters"]
    expected_filters = {
        "company_id": parameters["company_id"],
        "as_of_date": parameters["as_of_date"],
        "partner_id": parameters["partner_id"],
        "currency_id": parameters["currency_id"],
    }
    sql_parameters = dict(expected_filters)

    connection = psycopg2.connect(dbname="odoo_test")
    connection.set_session(
        isolation_level="REPEATABLE READ",
        readonly=True,
        autocommit=False,
    )
    rollback_completed = False
    try:
        with connection.cursor() as cursor:
            cursor.execute(QUERY, sql_parameters)
            names = [item.name for item in cursor.description]
            source_rows = [
                dict(zip(names, row, strict=True)) for row in cursor.fetchall()
            ]
            cursor.execute(COMPANY_CURRENCY_QUERY, sql_parameters)
            company_currency_row = cursor.fetchone()
            cursor.execute(
                "SELECT current_setting('transaction_isolation'), "
                "current_setting('transaction_read_only')"
            )
            isolation, read_only = cursor.fetchone()
    finally:
        connection.rollback()
        rollback_completed = True
        connection.close()

    if company_currency_row is None:
        raise SystemExit("oracle company does not exist")
    company_currency_id, company_currency_name, company_symbol, company_rounding = (
        company_currency_row
    )
    requested_date = date.fromisoformat(parameters["as_of_date"])
    rows: list[tuple[dict[str, object], Decimal, Decimal]] = []
    for row in source_rows:
        company_residual = row["residual_company"]
        currency_residual = row["residual_currency"]
        line_rounding = row["line_rounding"]
        if company_residual == 0 and currency_residual == 0:
            continue
        direction = company_residual if company_residual != 0 else currency_residual
        days_overdue, aging_bucket = aging(requested_date, row["due_date"])
        item = {
            "move_line_id": row["move_line_id"],
            "move_id": row["move_id"],
            "move_type": row["move_type"],
            "payment_id": row["payment_id"],
            "line_date": row["line_date"].isoformat(),
            "due_date": row["due_date"].isoformat() if row["due_date"] else None,
            "partner_id": row["partner_id"],
            "account_id": row["account_id"],
            "account_code": row["account_code"],
            "journal_id": row["journal_id"],
            "journal_code": row["journal_code"],
            "currency_id": row["currency_id"],
            "original_company_amount": amount(row["balance"], company_rounding),
            "residual_company_amount": amount(company_residual, company_rounding),
            "original_currency_amount": amount(
                row["amount_currency"], line_rounding
            ),
            "residual_currency_amount": amount(currency_residual, line_rounding),
            "side": "debit" if direction > 0 else "credit",
            "reconciliation_status": (
                "partially_reconciled_as_of"
                if row["matched_count"]
                else "unreconciled_as_of"
            ),
            "partial_reconcile_count": int(row["matched_count"]),
            "current_reconciled": row["current_reconciled"],
            "days_overdue": days_overdue,
            "aging_bucket": aging_bucket,
        }
        rows.append((item, company_residual, currency_residual))

    actual = response["data"]["result"]
    offset = parameters["offset"]
    limit = parameters["limit"]
    expected_page = rows[offset : offset + limit]
    expected_items = [item for item, _company, _currency in expected_page]
    actual_items = [
        {field: item[field] for field in ITEM_FIELDS} for item in actual["items"]
    ]
    expected_ledger = company_summary(rows, company_rounding)
    expected_page_summary = company_summary(expected_page, company_rounding)

    currency_totals: dict[int, dict[str, object]] = defaultdict(
        lambda: {
            "items": [],
            "name": None,
            "rounding": None,
        }
    )
    source_by_currency = {
        row["currency_id"]: row for row in source_rows
    }
    for item, company_residual, currency_residual in rows:
        group = currency_totals[item["currency_id"]]
        source = source_by_currency[item["currency_id"]]
        group["name"] = source["line_currency_name"]
        group["rounding"] = source["line_rounding"]
        group["items"].append((item, company_residual, currency_residual))

    expected_currencies = []
    for currency_id in sorted(currency_totals):
        group = currency_totals[currency_id]
        currency_rows = group["items"]
        currency_rounding = group["rounding"]
        residuals = [currency for _item, _company, currency in currency_rows]
        debit = sum((value for value in residuals if value > 0), Decimal("0"))
        credit = -sum((value for value in residuals if value < 0), Decimal("0"))
        expected_currencies.append(
            {
                "currency_id": currency_id,
                "currency_name": group["name"],
                "item_count": len(currency_rows),
                "debit_residual": amount(debit, currency_rounding),
                "credit_residual": amount(credit, currency_rounding),
                "net_residual": amount(debit - credit, currency_rounding),
            }
        )

    expected_company_currency = {
        "id": company_currency_id,
        "name": company_currency_name,
        "symbol": company_symbol or company_currency_name,
        "rounding": rounding_text(company_rounding),
    }
    checks = {
        "response_ok": response["ok"] is True,
        "request_capability": request["capability_id"] == CAPABILITY_ID,
        "response_capability": response["data"]["capability_id"] == CAPABILITY_ID,
        "basis": actual["basis"] == BASIS,
        "filters": actual["filters"] == expected_filters,
        "page_rows": actual_items == expected_items,
        "page_summary": actual["page_summary"] == expected_page_summary,
        "ledger_summary": actual["ledger_summary"] == expected_ledger,
        "currency_summaries": actual["currency_summaries"]
        == expected_currencies,
        "company_currency": actual["company_currency"]
        == expected_company_currency,
        "total_count": actual["page"]["total_count"] == len(rows),
        "page_count": actual["page"]["count"] == len(expected_page),
        "page_limit": actual["page"]["limit"] == limit,
        "page_offset": actual["page"]["offset"] == offset,
        "receipt_record_count": actual["receipt"]["record_count"] == len(rows),
        "transaction_isolation": isolation == "repeatable read",
        "transaction_read_only": read_only == "on",
        "rollback_completed": rollback_completed,
    }
    move_type_counts = Counter(item["move_type"] for item, _c, _x in rows)
    side_counts = Counter(item["side"] for item, _c, _x in rows)
    report = {
        "schema_version": 1,
        "capability_id": CAPABILITY_ID,
        "checks": checks,
        "all_checks_passed": all(checks.values()),
        "request_parameters": parameters,
        "oracle_population": (
            "all posted liability_payable account_move_line rows satisfying the "
            "request company/date/partner/currency filters; no V3 candidate IDs reused"
        ),
        "source_line_count": len(source_rows),
        "open_item_count": len(rows),
        "page_open_item_count": len(expected_page),
        "ledger_summary": expected_ledger,
        "currency_summaries": expected_currencies,
        "move_type_counts": dict(sorted(move_type_counts.items())),
        "side_counts": dict(sorted(side_counts.items())),
        "payment_item_count": sum(
            item["payment_id"] is not None for item, _company, _currency in rows
        ),
        "current_reconciled_count": sum(
            item["current_reconciled"] for item, _company, _currency in rows
        ),
        "partial_as_of_count": sum(
            item["partial_reconcile_count"] > 0
            for item, _company, _currency in rows
        ),
        "foreign_currency_count": sum(
            item["currency_id"] != company_currency_id
            for item, _company, _currency in rows
        ),
        "financial_rows_sha256": digest([item for item, _c, _x in rows]),
        "page_rows_sha256": digest(expected_items),
        "transaction_isolation": isolation,
        "transaction_read_only": read_only,
        "rollback_completed": rollback_completed,
    }
    print(
        json.dumps(
            report,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    if not report["all_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

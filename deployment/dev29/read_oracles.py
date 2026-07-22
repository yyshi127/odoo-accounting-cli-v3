#!/usr/bin/env python3
"""Fixed Dev29 PostgreSQL witnesses and independent accounting read oracles.

The program never imports V3 domain/ORM code.  It connects only through the
frozen local Unix socket, starts one REPEATABLE READ READ ONLY transaction,
qualifies every Odoo relation with ``public``, and always rolls back.  JSON
written to stdout is canonical and contains no database credential or raw
witness row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import date, datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Callable, Iterable


PLAN_PATH = Path(__file__).with_name("read_plan.json")
TOP_LEVEL_KEYS = {
    "schema_version", "target", "database", "runtime", "cases",
    "negative_cases", "witness",
}
CASE_NAMES = (
    "registry", "trial_balance", "ar_open_items", "ap_open_items",
    "multicurrency",
)
NEGATIVE_CASE_NAMES = (
    "acl_deny", "cross_company", "mixed_company", "wrong_database_uuid",
    "expired", "tamper_parameters", "replay",
)
PG_SELECTOR_VARIABLES = (
    "PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGSERVICE",
    "PGSERVICEFILE", "PGPASSFILE", "PGPASSWORD", "PGOPTIONS", "PGAPPNAME",
    "PGCLIENTENCODING", "PGTARGETSESSIONATTRS", "PGSSLMODE", "PGREQUIRESSL",
    "PGCHANNELBINDING",
)
HEX64 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*")
TRANSACTION_STATUS_IDLE = 0

WITNESS_PROJECTIONS: dict[str, tuple[str, ...]] = {
    "account_account": ("id", "account_type", "code_store", "name"),
    "account_journal": ("id", "code"),
    "account_move": ("id", "name", "move_type"),
    "account_move_line": (
        "id", "move_id", "payment_id", "date", "date_maturity", "partner_id",
        "account_id", "journal_id", "currency_id", "company_id", "parent_state",
        "balance", "debit", "credit", "amount_currency", "reconciled",
    ),
    "account_partial_reconcile": (
        "id", "company_id", "max_date", "debit_move_id", "credit_move_id",
        "amount", "debit_amount_currency", "credit_amount_currency",
    ),
    "ir_config_parameter": ("id", "key", "value"),
    "ir_model_data": ("id", "module", "name", "model", "res_id", "noupdate"),
    "res_company": ("id", "currency_id", "parent_path"),
    "res_company_users_rel": ("cid", "user_id"),
    "res_currency": ("id", "name", "symbol", "rounding"),
    "res_currency_rate": ("id", "name", "company_id", "currency_id", "rate"),
    "res_groups_users_rel": ("gid", "uid"),
    "res_partner": ("id", "name", "commercial_partner_id", "company_id", "active"),
    "res_users": ("id", "company_id", "login", "active", "share", "write_date"),
}
RELATION_IDENTITIES = {
    "account_account": (53432, "odoo", "r", ("id",)),
    "account_journal": (53641, "odoo", "r", ("id",)),
    "account_move": (53681, "odoo", "r", ("id",)),
    "account_move_line": (53705, "odoo", "r", ("id",)),
    "account_partial_reconcile": (53759, "odoo", "r", ("id",)),
    "ir_config_parameter": (54844, "odoo", "r", ("id",)),
    "ir_model_data": (54949, "odoo", "r", ("id",)),
    "res_company": (56012, "odoo", "r", ("id",)),
    "res_company_users_rel": (56022, "odoo", "r", ("cid", "user_id")),
    "res_currency": (56062, "odoo", "r", ("id",)),
    "res_currency_rate": (56069, "odoo", "r", ("id",)),
    "res_groups_users_rel": (56109, "odoo", "r", ("gid", "uid")),
    "res_partner": (56121, "odoo", "r", ("id",)),
    "res_users": (56161, "odoo", "r", ("id",)),
}
WITNESS_SCOPES = {
    "ir_config_parameter": "database_uuid_only",
    "ir_model_data": "required_group_xmlids_only",
    **{
        name: "all"
        for name in WITNESS_PROJECTIONS
        if name not in {"ir_config_parameter", "ir_model_data"}
    },
}
FIXED_DATABASE = {
    "name": "odoo_test",
    "uuid": "19b09656-d10f-11f0-9065-00163e54a5ad",
    "current_user": "postgres",
    "unix_socket_directory": "/var/run/postgresql",
    "unix_socket_path": "/var/run/postgresql/.s.PGSQL.5432",
    "port": 5432,
    "server_version_num": 160014,
    "system_identifier": "7616327373742442245",
}
FIXED_TARGET = {
    "host": "43.165.173.80",
    "instance_id": "odoo19@43.165.173.80",
    "environment": "test",
    "capability_channel": "staged",
    "services": ["odoo19.service", "sudo-pi-agent-bridge.service"],
    "v3_unit_names": [
        "odoo-accounting-cli-v3-broker.service",
        "odoo-accounting-cli-v3-pi-broker.socket",
        "odoo-accounting-cli-v3-session-mint.socket",
        "odoo-accounting-cli-v3-trusted-approval.socket",
        "odoo-accounting-cli-v3-pi-bridge.service",
        "odoo-accounting-cli-v3-pi-bridge.socket",
        "odoo-accounting-cli-v3-effect-finalizer.service",
        "odoo-accounting-cli-v3-effect-finalizer.socket",
    ],
    "v2_roots": [
        "/mnt/odoo/odoo19/custom/tools/odoo_accounting_agent_cli_v2",
        "/mnt/odoo/odoo19/custom/services/pi-agent-bridge/odoo_accounting_agent_cli_v2/src/odoo_acc_cli",
    ],
    "pi_control_files": [
        "/mnt/odoo/odoo19/custom/services/pi-agent-bridge/extensions/odoo-tools.ts",
        "/mnt/odoo/odoo19/custom/services/pi-agent-bridge/package-lock.json",
        "/mnt/odoo/odoo19/custom/services/pi-agent-bridge/package.json",
        "/mnt/odoo/odoo19/custom/services/pi-agent-bridge/server.mjs",
        "/etc/systemd/system/sudo-pi-agent-bridge.service",
    ],
}
FIXED_PARAMETERS = {
    "registry": {"company_id": 1},
    "trial_balance": {
        "account_id": None, "company_id": 1, "currency_id": None,
        "date_from": "2026-01-01", "date_to": "2026-12-31",
        "include_off_balance": False, "include_zero": False,
        "limit": 500, "offset": 0, "opening_basis": "ledger_cumulative",
    },
    "ar_open_items": {
        "as_of_date": "2026-07-14", "company_id": 1, "currency_id": None,
        "limit": 500, "offset": 0, "partner_id": None,
    },
    "ap_open_items": {
        "as_of_date": "2026-07-14", "company_id": 1, "currency_id": None,
        "limit": 500, "offset": 0, "partner_id": None,
    },
    "multicurrency": {
        "as_of_date": "2026-07-13", "balance_basis": "posted_ledger_cumulative",
        "company_id": 9, "currency_ids": [6, 1], "limit": 500,
        "off_balance_policy": "exclude", "offset": 0,
    },
}


class OracleInputError(ValueError):
    """The plan, request, response, or execution environment is invalid."""


class OracleMismatch(ValueError):
    """A valid input failed a financial or historical comparison."""

    def __init__(self, message: str, report: dict[str, Any] | None = None):
        super().__init__(message)
        self.report = report


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OracleInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text: str, label: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=Decimal,
            parse_constant=lambda value: (_ for _ in ()).throw(
                OracleInputError(f"{label} contains non-finite JSON: {value}")
            ),
        )
    except OracleInputError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise OracleInputError(f"{label} is not strict JSON") from exc


def canonical_json(value: Any) -> str:
    def default(item: Any) -> str:
        if isinstance(item, (date, datetime)):
            return item.isoformat()
        if isinstance(item, Decimal):
            return format(item, "f")
        raise TypeError(f"unsupported canonical JSON type: {type(item).__name__}")

    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"), default=default,
    )


def _schema_version_is_one(value: Any) -> bool:
    return type(value) is int and value == 1


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OracleInputError(f"{label} fields are invalid")
    return value


def _validate_plan(plan: Any) -> dict[str, Any]:
    plan = _exact_keys(plan, TOP_LEVEL_KEYS, "read plan")
    if (
        not _schema_version_is_one(plan["schema_version"])
        or plan["target"] != FIXED_TARGET
    ):
        raise OracleInputError("read plan target/schema binding is invalid")
    if plan["database"] != FIXED_DATABASE:
        raise OracleInputError("read plan database binding is invalid")
    _exact_keys(
        plan["runtime"],
        {"odoo_python", "odoo_python_sha256", "odoo_bin", "odoo_bin_sha256",
         "odoo_config", "odoo_config_sha256"},
        "runtime",
    )
    for key in ("odoo_python_sha256", "odoo_bin_sha256", "odoo_config_sha256"):
        if not isinstance(plan["runtime"][key], str) or not HEX64.fullmatch(plan["runtime"][key]):
            raise OracleInputError(f"runtime {key} is invalid")

    cases = plan["cases"]
    if not isinstance(cases, list) or [item.get("name") for item in cases if isinstance(item, dict)] != list(CASE_NAMES):
        raise OracleInputError("read plan cases are invalid")
    for case in cases:
        _exact_keys(
            case,
            {"name", "capability_id", "principal", "user_id", "company_id",
             "allowed_company_ids", "parameters", "expected"},
            f"case {case.get('name')}",
        )
        if case["parameters"] != FIXED_PARAMETERS[case["name"]]:
            raise OracleInputError(f"case {case['name']} parameters escaped the frozen plan")
        if (
            case["principal"] != "pi:test-user-2" or case["user_id"] != 2
            or case["company_id"] != case["parameters"]["company_id"]
            or case["company_id"] not in case["allowed_company_ids"]
            or len(case["allowed_company_ids"]) != len(set(case["allowed_company_ids"]))
            or not isinstance(case["expected"], dict) or not case["expected"]
        ):
            raise OracleInputError(f"case {case['name']} identity/expected binding is invalid")

    negatives = plan["negative_cases"]
    if not isinstance(negatives, list) or [item.get("name") for item in negatives if isinstance(item, dict)] != list(NEGATIVE_CASE_NAMES):
        raise OracleInputError("negative case matrix is invalid")
    for item in negatives:
        _exact_keys(
            item,
            {"name", "base_case", "principal", "user_id", "company_id",
             "allowed_company_ids", "mutation", "expected_error"},
            f"negative case {item.get('name')}",
        )
        _exact_keys(item["mutation"], {"kind", "fields"}, "negative mutation")
        if item["base_case"] not in CASE_NAMES or not isinstance(item["mutation"]["fields"], dict):
            raise OracleInputError("negative case binding is invalid")

    witness = _exact_keys(plan["witness"], {"relations"}, "witness")
    relations = witness["relations"]
    if not isinstance(relations, list) or [item.get("name") for item in relations if isinstance(item, dict)] != list(WITNESS_PROJECTIONS):
        raise OracleInputError("witness relation order/set is invalid")
    for relation in relations:
        _exact_keys(
            relation,
            {"name", "oid", "owner", "relkind", "primary_key", "required_columns",
             "witness_projection", "witness_scope", "baseline_count"},
            f"witness relation {relation.get('name')}",
        )
        name = relation["name"]
        oid, owner, relkind, primary_key = RELATION_IDENTITIES[name]
        if (
            (relation["oid"], relation["owner"], relation["relkind"], tuple(relation["primary_key"]))
            != (oid, owner, relkind, primary_key)
            or tuple(relation["witness_projection"]) != WITNESS_PROJECTIONS[name]
            or relation["witness_scope"] != WITNESS_SCOPES[name]
        ):
            raise OracleInputError(f"witness relation {name} escaped its fixed identity")
        columns = relation["required_columns"]
        if not isinstance(columns, list) or not columns:
            raise OracleInputError(f"witness relation {name} has no column contract")
        by_name: dict[str, str] = {}
        for column in columns:
            _exact_keys(column, {"name", "type"}, f"{name} column")
            if (
                not isinstance(column["name"], str)
                or not IDENTIFIER.fullmatch(column["name"])
                or column["name"] in by_name
                or not isinstance(column["type"], str)
                or not column["type"]
            ):
                raise OracleInputError(f"witness relation {name} column contract is invalid")
            by_name[column["name"]] = column["type"]
        if not set(relation["witness_projection"]).issubset(by_name):
            raise OracleInputError(f"witness relation {name} projection lacks a column contract")
    return plan


def read_plan(path: Path | str = PLAN_PATH) -> dict[str, Any]:
    path = Path(path)
    try:
        payload = path.read_text("utf-8")
    except (OSError, UnicodeError) as exc:
        raise OracleInputError("read plan cannot be read") from exc
    plan = _validate_plan(parse_json(payload, "read plan"))
    if path.resolve() != PLAN_PATH.resolve():
        try:
            committed = _validate_plan(parse_json(PLAN_PATH.read_text("utf-8"), "committed read plan"))
        except (OSError, UnicodeError) as exc:
            raise OracleInputError("committed read plan cannot be read") from exc
        if plan != committed:
            raise OracleInputError("read plan differs from the committed fixed plan")
    return plan


def case_by_name(plan: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [item for item in plan["cases"] if item["name"] == name]
    if len(matches) != 1:
        raise OracleInputError("unknown or duplicated read case")
    return matches[0]


def validate_request(plan: dict[str, Any], case: dict[str, Any], request: Any) -> None:
    request = _exact_keys(request, {"capability_id", "context", "parameters"}, "request")
    if request["capability_id"] != case["capability_id"] or request["parameters"] != case["parameters"]:
        raise OracleInputError("request escaped the frozen case")
    context = request["context"]
    if not isinstance(context, dict):
        raise OracleInputError("request context is invalid")
    expected = {
        "allowed_company_ids": case["allowed_company_ids"],
        "company_id": case["company_id"],
        "database_name": plan["database"]["name"],
        "database_uuid": plan["database"]["uuid"],
        "environment": plan["target"]["environment"],
        "odoo_instance_id": plan["target"]["instance_id"],
        "principal": case["principal"],
        "user_id": case["user_id"],
    }
    if any(context.get(key) != value for key, value in expected.items()):
        raise OracleInputError("request context escaped the frozen identity")


def _decimal(value: Any, label: str) -> Decimal:
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise OracleInputError(f"{label} is not decimal") from exc
    if not result.is_finite():
        raise OracleInputError(f"{label} is not finite")
    return result


def _rounded(value: Decimal, increment: Decimal) -> Decimal:
    if increment <= 0:
        raise OracleInputError("currency rounding is not positive")
    return (value / increment).quantize(Decimal("1"), rounding=ROUND_HALF_UP) * increment


def _amount(value: Any, increment: Any) -> str:
    rounding = _decimal(increment, "currency rounding")
    rounded = _rounded(_decimal(value, "amount"), rounding)
    places = max(0, -rounding.normalize().as_tuple().exponent)
    return f"{rounded:.{places}f}"


def _rate(value: Any) -> str:
    result = _decimal(value, "rate")
    if result <= 0:
        raise OracleInputError("rate is not positive")
    return format(result, "f")


def _date_text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, date):
        return value.isoformat()
    return date.fromisoformat(str(value)).isoformat()


def _trial_summary(rows: list[dict[str, Any]], rounding: Decimal) -> dict[str, Any]:
    opening = sum((_decimal(row["opening_balance"], "opening") for row in rows), Decimal("0"))
    debit = sum((_decimal(row["period_debit"], "debit") for row in rows), Decimal("0"))
    credit = sum((_decimal(row["period_credit"], "credit") for row in rows), Decimal("0"))
    period = debit - credit
    return {
        "opening_balance": _amount(opening, rounding),
        "period_debit": _amount(debit, rounding),
        "period_credit": _amount(credit, rounding),
        "period_balance": _amount(period, rounding),
        "closing_balance": _amount(opening + period, rounding),
        "debit_credit_difference": _amount(period, rounding),
        "is_balanced": _rounded(period, rounding) == 0,
    }


def build_trial_balance(
    source_rows: list[dict[str, Any]], currency: dict[str, Any], parameters: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not source_rows:
        raise OracleMismatch("trial-balance fixture gap: independent SQL returned no rows")
    rounding = _decimal(currency["rounding"], "company currency rounding")
    rows = []
    for source in source_rows:
        opening = _decimal(source["opening_balance"], "opening balance")
        debit = _decimal(source["period_debit"], "period debit")
        credit = _decimal(source["period_credit"], "period credit")
        period = debit - credit
        rows.append({
            "account_id": int(source["account_id"]),
            "code": str(source["code"]),
            "name": str(source["name"]),
            "account_type": str(source["account_type"]),
            "opening_balance": _amount(opening, rounding),
            "period_debit": _amount(debit, rounding),
            "period_credit": _amount(credit, rounding),
            "period_balance": _amount(period, rounding),
            "closing_balance": _amount(opening + period, rounding),
            "move_line_count": int(source["move_line_count"]),
        })
    rows.sort(key=lambda item: (item["code"], item["account_id"]))
    offset, limit = parameters["offset"], parameters["limit"]
    page = rows[offset:offset + limit]
    result = {
        "lines": page,
        "page": {"limit": limit, "offset": offset, "count": len(page), "total_count": len(rows)},
        "page_summary": _trial_summary(page, rounding),
        "ledger_summary": _trial_summary(rows, rounding),
        "currency": {
            "id": int(currency["id"]), "name": str(currency["name"]),
            "symbol": str(currency["symbol"] or currency["name"]),
            "rounding": format(rounding, "f"),
        },
    }
    return result, {
        "account_count": len(rows),
        "move_line_count": sum(item["move_line_count"] for item in rows),
        "ledger_summary": result["ledger_summary"],
    }


def _aging(as_of: date, due: Any) -> tuple[int | None, str]:
    if due is None:
        return None, "no_due_date"
    due_date = due if isinstance(due, date) else date.fromisoformat(str(due))
    days = (as_of - due_date).days
    if days <= 0:
        return days, "current"
    if days <= 30:
        return days, "days_1_30"
    if days <= 60:
        return days, "days_31_60"
    if days <= 90:
        return days, "days_61_90"
    return days, "over_90"


def _company_summary(
    rows: list[tuple[dict[str, Any], Decimal, Decimal]], rounding: Decimal
) -> dict[str, Any]:
    residuals = [company for _item, company, _currency in rows]
    debit = sum((value for value in residuals if value > 0), Decimal("0"))
    credit = -sum((value for value in residuals if value < 0), Decimal("0"))
    return {
        "item_count": len(rows), "debit_residual": _amount(debit, rounding),
        "credit_residual": _amount(credit, rounding),
        "net_residual": _amount(debit - credit, rounding),
    }


AR_HISTORICAL_FIELDS = (
    "move_line_id", "move_id", "payment_id", "line_date", "due_date",
    "partner_id", "account_id", "journal_id", "currency_id",
    "original_company_amount", "residual_company_amount",
    "original_currency_amount", "residual_currency_amount", "side",
    "partial_reconcile_count", "current_reconciled",
)
AP_HISTORICAL_FIELDS = (
    "move_line_id", "move_id", "move_type", "payment_id", "line_date", "due_date",
    "partner_id", "account_id", "account_code", "journal_id", "journal_code",
    "currency_id", "original_company_amount", "residual_company_amount",
    "original_currency_amount", "residual_currency_amount", "side",
    "reconciliation_status", "partial_reconcile_count", "current_reconciled",
    "days_overdue", "aging_bucket",
)


def build_open_items(
    source_rows: list[dict[str, Any]], company_currency: dict[str, Any],
    parameters: dict[str, Any], kind: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not source_rows:
        raise OracleMismatch(f"{kind} fixture gap: independent SQL returned no source rows")
    company_rounding = _decimal(company_currency["rounding"], "company rounding")
    as_of = date.fromisoformat(parameters["as_of_date"])
    rows: list[tuple[dict[str, Any], Decimal, Decimal]] = []
    for source in source_rows:
        line_rounding = _decimal(source["currency_rounding"], "line rounding")
        company_residual = _rounded(
            _decimal(source["balance"], "balance")
            - _decimal(source.get("debit_company", 0), "debit partial")
            + _decimal(source.get("credit_company", 0), "credit partial"),
            company_rounding,
        )
        currency_residual = _rounded(
            _decimal(source["amount_currency"], "amount currency")
            - _decimal(source.get("debit_currency", 0), "debit currency partial")
            + _decimal(source.get("credit_currency", 0), "credit currency partial"),
            line_rounding,
        )
        if company_residual == 0 and currency_residual == 0:
            continue
        direction = company_residual if company_residual != 0 else currency_residual
        days, bucket = _aging(as_of, source["due_date"])
        matched = int(source.get("matched_count", 0))
        item = {
            "move_line_id": int(source["move_line_id"]),
            "move_id": int(source["move_id"]),
            "move_name": str(source["move_name"]),
            "move_type": str(source["move_type"]),
            "payment_id": int(source["payment_id"]) if source["payment_id"] is not None else None,
            "line_date": _date_text(source["line_date"]),
            "due_date": _date_text(source["due_date"]),
            "partner_id": int(source["partner_id"]) if source["partner_id"] is not None else None,
            "partner_name": str(source["partner_name"] or ""),
            "account_id": int(source["account_id"]),
            "account_code": str(source["account_code"]),
            "account_name": str(source["account_name"]),
            "journal_id": int(source["journal_id"]),
            "journal_code": str(source["journal_code"]),
            "currency_id": int(source["currency_id"]),
            "currency_name": str(source["currency_name"]),
            "original_company_amount": _amount(source["balance"], company_rounding),
            "residual_company_amount": _amount(company_residual, company_rounding),
            "original_currency_amount": _amount(source["amount_currency"], line_rounding),
            "residual_currency_amount": _amount(currency_residual, line_rounding),
            "side": "debit" if direction > 0 else "credit",
            "reconciliation_status": "partially_reconciled_as_of" if matched else "unreconciled_as_of",
            "partial_reconcile_count": matched,
            "current_reconciled": bool(source["current_reconciled"]),
            "days_overdue": days,
            "aging_bucket": bucket,
        }
        rows.append((item, company_residual, currency_residual))
    if not rows:
        raise OracleMismatch(f"{kind} fixture gap: independent SQL returned no open items")
    rows.sort(key=lambda row: (
        row[0]["due_date"] is None, row[0]["due_date"] or "9999-12-31",
        row[0]["line_date"], row[0]["move_line_id"],
    ))
    offset, limit = parameters["offset"], parameters["limit"]
    page_rows = rows[offset:offset + limit]
    groups: dict[int, list[tuple[dict[str, Any], Decimal, Decimal]]] = defaultdict(list)
    for row in rows:
        groups[row[0]["currency_id"]].append(row)
    rounding_by_currency = {
        int(source["currency_id"]): _decimal(source["currency_rounding"], "line rounding")
        for source in source_rows
    }
    name_by_currency = {
        int(source["currency_id"]): str(source["currency_name"])
        for source in source_rows
    }
    currency_summaries = []
    for currency_id in sorted(groups):
        grouped = groups[currency_id]
        residuals = [currency for _item, _company, currency in grouped]
        debit = sum((value for value in residuals if value > 0), Decimal("0"))
        credit = -sum((value for value in residuals if value < 0), Decimal("0"))
        rounding = rounding_by_currency[currency_id]
        currency_summaries.append({
            "currency_id": currency_id, "currency_name": name_by_currency[currency_id],
            "item_count": len(grouped), "debit_residual": _amount(debit, rounding),
            "credit_residual": _amount(credit, rounding),
            "net_residual": _amount(debit - credit, rounding),
        })
    result = {
        "basis": "odoo_accounting_date_current_reconciliation_graph",
        "filters": {
            "company_id": parameters["company_id"], "as_of_date": parameters["as_of_date"],
            "partner_id": parameters["partner_id"], "currency_id": parameters["currency_id"],
        },
        "items": [item for item, _company, _currency in page_rows],
        "page": {"limit": limit, "offset": offset, "count": len(page_rows), "total_count": len(rows)},
        "page_summary": _company_summary(page_rows, company_rounding),
        "ledger_summary": _company_summary(rows, company_rounding),
        "currency_summaries": currency_summaries,
        "company_currency": {
            "id": int(company_currency["id"]), "name": str(company_currency["name"]),
            "symbol": str(company_currency["symbol"] or company_currency["name"]),
            "rounding": format(company_rounding, "f"),
        },
    }
    historical_fields = AR_HISTORICAL_FIELDS if kind == "ar" else AP_HISTORICAL_FIELDS
    historical_projection = [
        {field: item[field] for field in historical_fields}
        for item, _company, _currency in rows
    ]
    metrics: dict[str, Any] = {
        "source_line_count": len(source_rows), "open_item_count": len(rows),
        "current_reconciled_count": sum(item["current_reconciled"] for item, _c, _x in rows),
        "partial_as_of_count": sum(item["partial_reconcile_count"] > 0 for item, _c, _x in rows),
        "historical_projection_sha256": digest_json(historical_projection),
        "ledger_summary": result["ledger_summary"],
        "currency_summaries": currency_summaries,
    }
    if kind == "ap":
        metrics.update({
            "payment_item_count": sum(item["payment_id"] is not None for item, _c, _x in rows),
            "foreign_currency_count": sum(item["currency_id"] != company_currency["id"] for item, _c, _x in rows),
            "move_type_counts": dict(sorted(Counter(item["move_type"] for item, _c, _x in rows).items())),
            "side_counts": dict(sorted(Counter(item["side"] for item, _c, _x in rows).items())),
        })
    return result, metrics


def result_checks(actual: Any, expected: Any) -> dict[str, bool]:
    return {"business_result": actual == expected}


def golden_checks(case: dict[str, Any], metrics: dict[str, Any]) -> dict[str, bool]:
    return {
        f"golden_{key}": metrics.get(key) == value
        for key, value in case["expected"].items()
        if key != "historical_source"
    }


def witness_digest(rows: Iterable[Any]) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    for row in rows:
        digest.update(canonical_json(row).encode("utf-8"))
        digest.update(b"\n")
        count += 1
    return {"row_count": count, "row_stream_sha256": digest.hexdigest()}


IDENTITY_SQL = """
SELECT
    current_database(),
    current_user,
    (SELECT CASE WHEN COUNT(*) = 1 THEN MIN(value) ELSE NULL END
       FROM public.ir_config_parameter WHERE key = 'database.uuid'),
    current_setting('server_version_num')::integer,
    (SELECT system_identifier::text FROM pg_catalog.pg_control_system()),
    pg_postmaster_start_time(),
    inet_server_addr()::text,
    inet_server_port(),
    current_setting('unix_socket_directories'),
    current_setting('transaction_isolation'),
    current_setting('transaction_read_only')
"""

RELATIONS_SQL = """
SELECT c.relname, c.oid::integer, owner.rolname, c.relkind
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_roles AS owner ON owner.oid = c.relowner
WHERE n.nspname = 'public' AND c.relname = ANY(%s)
ORDER BY c.relname
"""

COLUMNS_SQL = """
SELECT c.relname, a.attname,
       pg_catalog.format_type(a.atttypid, a.atttypmod),
       a.attnotnull, a.attnum
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
WHERE n.nspname = 'public'
  AND c.relname = ANY(%s)
  AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum
"""

PRIMARY_KEYS_SQL = """
SELECT c.relname,
       array_agg(a.attname ORDER BY key_columns.ordinality)
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_index AS i ON i.indrelid = c.oid AND i.indisprimary
JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS key_columns(attnum, ordinality)
  ON TRUE
JOIN pg_catalog.pg_attribute AS a
  ON a.attrelid = c.oid AND a.attnum = key_columns.attnum
WHERE n.nspname = 'public' AND c.relname = ANY(%s)
GROUP BY c.relname
ORDER BY c.relname
"""

ACCESS_SQL = """
WITH required_groups(xml_id) AS (
    VALUES ('base.group_user'::text), ('account.group_account_readonly'::text)
), groups AS (
    SELECT required_groups.xml_id, data.res_id AS gid
    FROM required_groups
    LEFT JOIN public.ir_model_data AS data
      ON data.module = split_part(required_groups.xml_id, '.', 1)
     AND data.name = split_part(required_groups.xml_id, '.', 2)
     AND data.model = 'res.groups'
), membership AS (
    SELECT groups.xml_id, groups.gid,
           EXISTS (
               SELECT 1 FROM public.res_groups_users_rel AS rel
               WHERE rel.gid = groups.gid AND rel.uid = %(user_id)s
           ) AS member
    FROM groups
)
SELECT jsonb_build_object(
    'user', (
        SELECT jsonb_build_object(
            'id', users.id, 'company_id', users.company_id,
            'active', users.active, 'share', users.share
        )
        FROM public.res_users AS users WHERE users.id = %(user_id)s
    ),
    'company_exists', EXISTS (
        SELECT 1 FROM public.res_company WHERE id = %(company_id)s
    ),
    'company_member', EXISTS (
        SELECT 1 FROM public.res_company_users_rel
        WHERE cid = %(company_id)s AND user_id = %(user_id)s
    ),
    'groups', COALESCE((
        SELECT jsonb_object_agg(xml_id, jsonb_build_object('gid', gid, 'member', member))
        FROM membership
    ), '{}'::jsonb)
)
"""

TRIAL_BALANCE_SQL = """
WITH grouped AS (
    SELECT
        account.id AS account_id,
        account.code_store ->> %(company_key)s AS code,
        COALESCE(account.name ->> 'en_US', account.name ->> 'zh_CN', account.name::text) AS name,
        account.account_type,
        COALESCE(SUM(line.balance) FILTER (WHERE line.date < %(date_from)s), 0) AS opening_balance,
        COALESCE(SUM(line.debit) FILTER (
            WHERE line.date >= %(date_from)s AND line.date <= %(date_to)s
        ), 0) AS period_debit,
        COALESCE(SUM(line.credit) FILTER (
            WHERE line.date >= %(date_from)s AND line.date <= %(date_to)s
        ), 0) AS period_credit,
        COUNT(*) AS move_line_count
    FROM public.account_move_line AS line
    JOIN public.account_account AS account ON account.id = line.account_id
    WHERE line.company_id = %(company_id)s
      AND line.parent_state = 'posted'
      AND line.date <= %(date_to)s
      AND (%(include_off_balance)s OR account.account_type <> 'off_balance')
      AND (%(account_id)s IS NULL OR account.id = %(account_id)s)
    GROUP BY account.id, account.code_store, account.name, account.account_type
)
SELECT * FROM grouped ORDER BY code, account_id
"""

COMPANY_CURRENCY_SQL = """
SELECT currency.id, currency.name, COALESCE(currency.symbol, currency.name) AS symbol,
       currency.rounding, company.parent_path
FROM public.res_company AS company
JOIN public.res_currency AS currency ON currency.id = company.currency_id
WHERE company.id = %s
"""

OPEN_ITEMS_SQL = """
WITH base AS (
    SELECT
        aml.id AS move_line_id,
        aml.move_id,
        move.name AS move_name,
        move.move_type,
        aml.payment_id,
        aml.date AS line_date,
        aml.date_maturity AS due_date,
        aml.partner_id,
        COALESCE(partner.name, '') AS partner_name,
        aml.account_id,
        account.code_store ->> %(company_key)s AS account_code,
        COALESCE(account.name ->> 'en_US', account.name ->> 'zh_CN', account.name::text) AS account_name,
        aml.journal_id,
        journal.code AS journal_code,
        COALESCE(aml.currency_id, company.currency_id) AS currency_id,
        currency.name AS currency_name,
        currency.rounding AS currency_rounding,
        aml.balance,
        aml.amount_currency,
        aml.reconciled AS current_reconciled
    FROM public.account_move_line AS aml
    JOIN public.account_account AS account ON account.id = aml.account_id
    JOIN public.account_move AS move ON move.id = aml.move_id
    JOIN public.account_journal AS journal ON journal.id = aml.journal_id
    JOIN public.res_company AS company ON company.id = aml.company_id
    JOIN public.res_currency AS currency
      ON currency.id = COALESCE(aml.currency_id, company.currency_id)
    LEFT JOIN public.res_partner AS partner ON partner.id = aml.partner_id
    WHERE aml.company_id = %(company_id)s
      AND aml.parent_state = 'posted'
      AND account.account_type = %(account_type)s
      AND aml.date <= %(as_of_date)s
      AND (%(partner_id)s IS NULL OR aml.partner_id = %(partner_id)s)
      AND (%(currency_id)s IS NULL OR aml.currency_id = %(currency_id)s)
), partial_entries AS (
    SELECT partial.debit_move_id AS move_line_id,
           partial.amount AS debit_company, 0::numeric AS credit_company,
           partial.debit_amount_currency AS debit_currency,
           0::numeric AS credit_currency, 1::bigint AS matched_count
    FROM public.account_partial_reconcile AS partial
    WHERE partial.company_id = %(company_id)s AND partial.max_date <= %(as_of_date)s
    UNION ALL
    SELECT partial.credit_move_id AS move_line_id,
           0::numeric AS debit_company, partial.amount AS credit_company,
           0::numeric AS debit_currency,
           partial.credit_amount_currency AS credit_currency,
           1::bigint AS matched_count
    FROM public.account_partial_reconcile AS partial
    WHERE partial.company_id = %(company_id)s AND partial.max_date <= %(as_of_date)s
), partial_totals AS (
    SELECT move_line_id, SUM(debit_company) AS debit_company,
           SUM(credit_company) AS credit_company,
           SUM(debit_currency) AS debit_currency,
           SUM(credit_currency) AS credit_currency,
           SUM(matched_count) AS matched_count
    FROM partial_entries GROUP BY move_line_id
)
SELECT base.*,
       COALESCE(partial_totals.debit_company, 0) AS debit_company,
       COALESCE(partial_totals.credit_company, 0) AS credit_company,
       COALESCE(partial_totals.debit_currency, 0) AS debit_currency,
       COALESCE(partial_totals.credit_currency, 0) AS credit_currency,
       COALESCE(partial_totals.matched_count, 0) AS matched_count
FROM base LEFT JOIN partial_totals ON partial_totals.move_line_id = base.move_line_id
ORDER BY base.due_date NULLS LAST, base.line_date, base.move_line_id
"""

MULTICURRENCY_BALANCES_SQL = """
SELECT
    aml.account_id,
    account.code_store ->> %(company_key)s AS account_code,
    COALESCE(account.name ->> 'en_US', account.name ->> 'zh_CN', account.name::text) AS account_name,
    account.account_type,
    aml.currency_id,
    currency.name AS currency_name,
    COALESCE(currency.symbol, currency.name) AS currency_symbol,
    currency.rounding AS currency_rounding,
    SUM(aml.balance) AS ledger_company_balance,
    SUM(aml.amount_currency) AS ledger_transaction_amount,
    COUNT(*)::integer AS move_line_count
FROM public.account_move_line AS aml
JOIN public.account_account AS account ON account.id = aml.account_id
JOIN public.res_currency AS currency ON currency.id = aml.currency_id
WHERE aml.company_id = %(company_id)s
  AND aml.parent_state = 'posted'
  AND aml.date <= %(as_of_date)s
  AND aml.currency_id = ANY(%(currency_ids)s)
  AND account.account_type <> 'off_balance'
GROUP BY aml.account_id, account.code_store, account.name, account.account_type,
         aml.currency_id, currency.name, currency.symbol, currency.rounding
ORDER BY account_code, aml.account_id,
         array_position(%(currency_ids)s::integer[], aml.currency_id)
"""

RATE_SQL = """
WITH company AS (
    SELECT target.currency_id AS company_currency_id,
           split_part(trim(BOTH '/' FROM target.parent_path), '/', 1)::integer AS root_company_id
    FROM public.res_company AS target
    WHERE target.id = %(company_id)s
      AND target.parent_path ~ '^[0-9]+(/[0-9]+)*/$'
), requested AS (
    SELECT currency_id, ordinality::integer AS ordinal
    FROM unnest(%(currency_ids)s::integer[]) WITH ORDINALITY AS item(currency_id, ordinality)
), selected AS (
    SELECT requested.currency_id, requested.ordinal, company.company_currency_id,
           chosen.id AS source_record_id, chosen.name AS effective_date,
           chosen.company_id AS source_company_id, chosen.rate AS technical_rate,
           chosen.source_scope,
           EXISTS (
               SELECT 1 FROM public.res_currency_rate AS any_rate
               WHERE any_rate.currency_id = requested.currency_id
                 AND (any_rate.company_id IS NULL OR any_rate.company_id = company.root_company_id)
           ) AS any_rate_exists
    FROM requested CROSS JOIN company
    LEFT JOIN LATERAL (
        SELECT candidate.* FROM (
            SELECT rate.id, rate.name, rate.company_id, rate.rate,
                   'company_specific'::text AS source_scope, 0 AS priority
            FROM public.res_currency_rate AS rate
            WHERE rate.currency_id = requested.currency_id
              AND rate.name <= %(as_of_date)s AND rate.company_id = company.root_company_id
            UNION ALL
            SELECT rate.id, rate.name, rate.company_id, rate.rate,
                   'global'::text AS source_scope, 1 AS priority
            FROM public.res_currency_rate AS rate
            WHERE rate.currency_id = requested.currency_id
              AND rate.name <= %(as_of_date)s AND rate.company_id IS NULL
        ) AS candidate
        ORDER BY candidate.priority, candidate.name DESC, candidate.id DESC LIMIT 1
    ) AS chosen ON TRUE
), sources AS (
    SELECT selected.*,
           CASE
               WHEN source_record_id IS NOT NULL THEN source_scope
               WHEN currency_id = company_currency_id AND NOT any_rate_exists THEN 'no_rate_identity'
               WHEN currency_id = company_currency_id THEN 'future_rate_invalid'
               ELSE 'missing_rate'
           END AS effective_scope,
           CASE
               WHEN source_record_id IS NOT NULL THEN technical_rate
               WHEN currency_id = company_currency_id AND NOT any_rate_exists THEN 1::numeric
               ELSE NULL::numeric
           END AS effective_rate
    FROM selected
)
SELECT * FROM sources ORDER BY ordinal
"""


def _rows(cursor: Any) -> list[dict[str, Any]]:
    description = cursor.description or []
    names = [item.name if hasattr(item, "name") else item[0] for item in description]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def clear_pg_selectors() -> list[str]:
    removed = []
    for key in PG_SELECTOR_VARIABLES:
        if key in os.environ:
            removed.append(key)
            os.environ.pop(key, None)
    return removed


def open_connection(plan: dict[str, Any], connector: Callable[..., Any] | None = None) -> Any:
    clear_pg_selectors()
    if connector is None:
        try:
            import psycopg2  # type: ignore
        except ImportError as exc:
            raise OracleInputError("psycopg2 is unavailable in the fixed oracle runtime") from exc
        if not str(getattr(psycopg2, "__version__", "")).startswith("2.9.9"):
            raise OracleInputError("fixed oracle runtime psycopg2 version mismatch")
        connector = psycopg2.connect
    database = plan["database"]
    return connector(
        dbname=database["name"], user=database["current_user"],
        host=database["unix_socket_directory"], port=database["port"],
        connect_timeout=10,
        application_name="odoo-accounting-cli-v3-dev29-read-oracle",
        options=(
            "-c default_transaction_read_only=on -c statement_timeout=45000 "
            "-c lock_timeout=5000 -c idle_in_transaction_session_timeout=60000"
        ),
    )


def run_read_only_transaction(
    connection: Any, work: Callable[[Any], Any]
) -> tuple[Any, dict[str, Any]]:
    cursor = None
    transaction: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        connection.set_session(
            isolation_level="REPEATABLE READ", readonly=True, autocommit=False
        )
        cursor = connection.cursor()
        cursor.execute("SET LOCAL search_path TO pg_catalog")
        value = work(cursor)
        cursor.execute(
            "SELECT current_setting('transaction_isolation'), "
            "current_setting('transaction_read_only')"
        )
        isolation, read_only = cursor.fetchone()
        if (isolation, read_only) != ("repeatable read", "on"):
            raise OracleInputError("oracle transaction is not REPEATABLE READ READ ONLY")
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except Exception:
                pass
        rollback_error = None
        try:
            connection.rollback()
        except Exception as exc:
            rollback_error = exc
        idle = False
        try:
            idle = connection.get_transaction_status() == TRANSACTION_STATUS_IDLE
        except Exception:
            idle = False
        try:
            connection.close()
        finally:
            if rollback_error is not None:
                if primary_error is None:
                    raise OracleInputError("oracle rollback failed") from rollback_error
            elif not idle and primary_error is None:
                raise OracleInputError("oracle connection was not IDLE after rollback")
        if primary_error is None and rollback_error is None and idle:
            transaction = {
                "isolation": "repeatable read", "read_only": "on",
                "rollback_completed": True, "final_status": "IDLE",
            }
    assert transaction is not None
    return value, transaction


def verify_database_schema(cursor: Any, plan: dict[str, Any]) -> dict[str, Any]:
    cursor.execute(IDENTITY_SQL)
    row = cursor.fetchone()
    if row is None or len(row) != 11:
        raise OracleInputError("database identity row is absent")
    database = plan["database"]
    expected_prefix = (
        database["name"], database["current_user"], database["uuid"],
        database["server_version_num"], database["system_identifier"],
    )
    if tuple(row[:5]) != expected_prefix:
        raise OracleInputError("database UUID/system/version/user identity mismatch")
    postmaster_started_at = row[5]
    if (
        not isinstance(postmaster_started_at, datetime)
        or postmaster_started_at.tzinfo is None
        or postmaster_started_at.utcoffset() is None
    ):
        raise OracleInputError("PostgreSQL postmaster start identity is invalid")
    socket_directories = {item.strip() for item in str(row[8]).split(",")}
    if row[6] is not None or row[7] is not None or database["unix_socket_directory"] not in socket_directories:
        raise OracleInputError("database connection is not the fixed Unix socket")
    if tuple(row[9:]) != ("repeatable read", "on"):
        raise OracleInputError("database identity query was not read-only repeatable-read")

    names = list(WITNESS_PROJECTIONS)
    cursor.execute(RELATIONS_SQL, (names,))
    actual_relations = {item[0]: tuple(item[1:]) for item in cursor.fetchall()}
    expected_relations = {
        name: (identity[0], identity[1], identity[2])
        for name, identity in RELATION_IDENTITIES.items()
    }
    if actual_relations != expected_relations:
        raise OracleInputError("relation OID/owner/relkind identity mismatch")

    cursor.execute(PRIMARY_KEYS_SQL, (names,))
    primary_keys = {item[0]: tuple(item[1]) for item in cursor.fetchall()}
    if primary_keys != {name: value[3] for name, value in RELATION_IDENTITIES.items()}:
        raise OracleInputError("relation primary-key identity mismatch")

    cursor.execute(COLUMNS_SQL, (names,))
    all_columns: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for relation_name, column_name, type_name, not_null, ordinal in cursor.fetchall():
        all_columns[relation_name].append({
            "name": column_name, "type": type_name,
            "not_null": bool(not_null), "ordinal": int(ordinal),
        })
    relation_plan = {item["name"]: item for item in plan["witness"]["relations"]}
    for name, relation in relation_plan.items():
        actual_by_name = {item["name"]: item["type"] for item in all_columns.get(name, [])}
        expected_columns = {item["name"]: item["type"] for item in relation["required_columns"]}
        if any(actual_by_name.get(column) != type_name for column, type_name in expected_columns.items()):
            raise OracleInputError(f"relation required-column structure mismatch: {name}")
    return {
        "database": {
            "current_database": row[0], "current_user": row[1],
            "database_uuid": row[2], "server_version_num": row[3],
            "system_identifier": row[4],
            "postmaster_started_at": postmaster_started_at.isoformat(),
        },
        "endpoint": {
            "kind": "unix_socket", "requested_directory": database["unix_socket_directory"],
            "socket_path": database["unix_socket_path"],
        },
        "relations": [
            {
                "name": name, "oid": RELATION_IDENTITIES[name][0],
                "owner": RELATION_IDENTITIES[name][1], "relkind": RELATION_IDENTITIES[name][2],
                "primary_key": list(RELATION_IDENTITIES[name][3]),
                "schema_sha256": digest_json(all_columns[name]),
                "column_count": len(all_columns[name]),
            }
            for name in names
        ],
    }


def verify_access(cursor: Any, case: dict[str, Any]) -> dict[str, Any]:
    cursor.execute(ACCESS_SQL, {"user_id": case["user_id"], "company_id": case["company_id"]})
    row = cursor.fetchone()
    value = row[0] if row else None
    if isinstance(value, str):
        value = parse_json(value, "database access identity")
    if not isinstance(value, dict):
        raise OracleInputError("database access identity is absent")
    user = value.get("user")
    if (
        not isinstance(user, dict) or user.get("id") != case["user_id"]
        or user.get("active") is not True or user.get("share") is not False
        or value.get("company_exists") is not True or value.get("company_member") is not True
    ):
        raise OracleInputError("user/company database binding is invalid")
    required_group = "base.group_user" if case["name"] == "registry" else "account.group_account_readonly"
    group = value.get("groups", {}).get(required_group)
    if not isinstance(group, dict) or not isinstance(group.get("gid"), int) or group.get("member") is not True:
        raise OracleInputError("required Odoo group membership is absent")
    return {
        "user_id": user["id"], "company_id": case["company_id"],
        "company_member": True, "required_group": required_group,
        "required_group_member": True,
    }


def _technical_source(
    row: dict[str, Any], currency: dict[str, Any], *, allow_identity: bool
) -> dict[str, Any]:
    scope = row["effective_scope"]
    technical_rate = row["effective_rate"]
    if scope == "no_rate_identity":
        if (
            not allow_identity or row["source_record_id"] is not None
            or row["source_company_id"] is not None or row["effective_date"] is not None
            or _decimal(technical_rate, "identity rate") != 1
        ):
            raise OracleMismatch("multicurrency fixture gap: invalid no-rate identity")
        source_model = "no_rate_identity"
    else:
        if (
            scope not in {"company_specific", "global"}
            or not isinstance(row["source_record_id"], int)
            or row["source_record_id"] <= 0
            or technical_rate is None
        ):
            raise OracleMismatch("multicurrency fixture gap: missing cutoff-date rate")
        if scope == "company_specific" and row["source_company_id"] is None:
            raise OracleMismatch("multicurrency fixture gap: company rate is unbound")
        if scope == "global" and row["source_company_id"] is not None:
            raise OracleMismatch("multicurrency fixture gap: global rate claims a company")
        source_model = "res.currency.rate"
    return {
        "currency_id": currency["id"], "currency_name": currency["name"],
        "effective_date": _date_text(row["effective_date"]),
        "source_model": source_model, "source_scope": scope,
        "source_company_id": row["source_company_id"],
        "source_record_id": row["source_record_id"],
        "odoo_technical_rate": _rate(technical_rate),
    }


def build_multicurrency(
    balance_rows: list[dict[str, Any]], company_currency: dict[str, Any],
    rate_rows: list[dict[str, Any]], parameters: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not balance_rows:
        raise OracleMismatch("multicurrency fixture gap: independent SQL returned no balance groups")
    requested = parameters["currency_ids"]
    currency_by_id: dict[int, dict[str, Any]] = {}
    for row in balance_rows:
        currency_by_id[int(row["currency_id"])] = {
            "id": int(row["currency_id"]), "name": str(row["currency_name"]),
            "symbol": str(row["currency_symbol"] or row["currency_name"]),
            "rounding": _decimal(row["currency_rounding"], "currency rounding"),
        }
    if set(currency_by_id) != set(requested):
        raise OracleMismatch("multicurrency fixture gap: requested currency has no ledger group")
    company_rounding = _decimal(company_currency["rounding"], "company rounding")
    company_id = int(company_currency["id"])
    parent_path = str(company_currency.get("parent_path", ""))
    if (
        re.fullmatch(r"[0-9]+(?:/[0-9]+)*/", parent_path) is None
        or int(parent_path.split("/", 1)[0]) != parameters["company_id"]
    ):
        raise OracleMismatch("multicurrency fixture gap: company root hierarchy changed")
    order = {currency_id: index for index, currency_id in enumerate(requested)}
    normalized: list[dict[str, Any]] = []
    aggregates: list[dict[str, Any]] = []
    for source in balance_rows:
        currency = currency_by_id[int(source["currency_id"])]
        company_amount = _decimal(source["ledger_company_balance"], "company balance")
        transaction_amount = _decimal(source["ledger_transaction_amount"], "transaction amount")
        if (
            currency["id"] == company_id
            and _amount(company_amount, company_rounding)
            != _amount(transaction_amount, currency["rounding"])
        ):
            raise OracleMismatch(
                "multicurrency fixture gap: company-currency booked amounts disagree"
            )
        normalized.append({
            "account_id": int(source["account_id"]),
            "account_code": str(source["account_code"]),
            "account_name": str(source["account_name"]),
            "account_type": str(source["account_type"]),
            "currency_id": currency["id"], "currency_name": currency["name"],
            "company_currency_id": company_id,
            "company_currency_name": str(company_currency["name"]),
            "ledger_company_balance": _amount(company_amount, company_rounding),
            "ledger_transaction_amount": _amount(transaction_amount, currency["rounding"]),
            "move_line_count": int(source["move_line_count"]),
        })
        aggregates.append({
            "account_id": int(source["account_id"]), "currency_id": currency["id"],
            "company_balance": company_amount, "transaction_amount": transaction_amount,
            "line_count": int(source["move_line_count"]),
        })
    normalized.sort(key=lambda item: (item["account_code"], item["account_id"], order[item["currency_id"]]))
    aggregates.sort(key=lambda item: (
        next(row["account_code"] for row in normalized if row["account_id"] == item["account_id"]),
        item["account_id"], order[item["currency_id"]],
    ))

    def summary(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "balance_group_count": len(items),
            "account_count": len({item["account_id"] for item in items}),
            "move_line_count": sum(item["line_count"] for item in items),
            "ledger_company_balance": _amount(
                sum((item["company_balance"] for item in items), Decimal("0")),
                company_rounding,
            ),
        }

    currency_summaries = []
    for currency_id in requested:
        currency = currency_by_id[currency_id]
        selected = [item for item in aggregates if item["currency_id"] == currency_id]
        currency_summaries.append({
            "currency_id": currency_id, "currency_name": currency["name"],
            "currency_symbol": currency["symbol"],
            "currency_rounding": format(currency["rounding"], "f"),
            "ledger_company_balance": _amount(
                sum((item["company_balance"] for item in selected), Decimal("0")),
                company_rounding,
            ),
            "ledger_transaction_amount": _amount(
                sum((item["transaction_amount"] for item in selected), Decimal("0")),
                currency["rounding"],
            ),
            "account_count": len({item["account_id"] for item in selected}),
            "move_line_count": sum(item["line_count"] for item in selected),
        })
    rate_by_currency = {int(item["currency_id"]): item for item in rate_rows}
    if set(rate_by_currency) != set(requested) or company_id not in rate_by_currency:
        raise OracleMismatch("multicurrency fixture gap: cutoff-rate rows are incomplete")
    company_rate_row = rate_by_currency[company_id]
    company_source = _technical_source(
        company_rate_row,
        {"id": company_id, "name": str(company_currency["name"])},
        allow_identity=True,
    )
    company_rate = _decimal(company_rate_row["effective_rate"], "company technical rate")
    rates = []
    historical_rates = []
    for currency_id in requested:
        currency = currency_by_id[currency_id]
        source_row = rate_by_currency[currency_id]
        transaction_source = _technical_source(
            source_row, currency, allow_identity=currency_id == company_id
        )
        transaction_rate = _decimal(source_row["effective_rate"], "transaction technical rate")
        conversion = (
            Decimal("1")
            if currency_id == company_id
            else Decimal(str(float(company_rate) / float(transaction_rate)))
        )
        inverse = Decimal("1") / conversion
        rates.append({
            "currency_id": currency_id, "currency_name": currency["name"],
            "company_currency_id": company_id,
            "company_currency_name": str(company_currency["name"]),
            "as_of_date": parameters["as_of_date"],
            "direction": "transaction_currency_to_company_currency",
            "formula": "company_technical_rate / transaction_technical_rate",
            "transaction_technical_source": transaction_source,
            "company_technical_source": company_source,
            "transaction_to_company_rate": _rate(conversion),
            "company_to_transaction_rate": _rate(inverse),
        })
        historical_rate = {
            "currency_id": currency_id, "currency_name": currency["name"],
            "effective_date": transaction_source["effective_date"],
            "source_company_id": transaction_source["source_company_id"],
            "source_record_id": transaction_source["source_record_id"],
            "source_scope": transaction_source["source_scope"],
            "technical_rate": transaction_source["odoo_technical_rate"],
            "transaction_to_company_rate": _rate(conversion),
            "company_to_transaction_rate": _rate(inverse),
        }
        if historical_rate["effective_date"] is None:
            historical_rate.pop("effective_date")
        historical_rates.append(historical_rate)

    offset, limit = parameters["offset"], parameters["limit"]
    page_aggregates = aggregates[offset:offset + limit]
    result = {
        "basis": "odoo_posted_aml_booked_amounts_no_cutoff_revaluation",
        "filters": {
            "company_id": parameters["company_id"], "as_of_date": parameters["as_of_date"],
            "currency_ids": requested, "balance_basis": "posted_ledger_cumulative",
            "off_balance_policy": "exclude",
        },
        "balances": normalized[offset:offset + limit],
        "page": {"limit": limit, "offset": offset, "count": len(page_aggregates), "total_count": len(aggregates)},
        "page_summary": summary(page_aggregates), "ledger_summary": summary(aggregates),
        "currency_summaries": currency_summaries, "rates": rates,
        "company_currency": {
            "id": company_id, "name": str(company_currency["name"]),
            "symbol": str(company_currency["symbol"] or company_currency["name"]),
            "rounding": format(company_rounding, "f"),
        },
    }
    historical_balances = [
        {key: item[key] for key in (
            "account_code", "account_id", "account_type", "company_currency_id",
            "company_currency_name", "currency_id", "currency_name",
            "ledger_company_balance", "ledger_transaction_amount", "move_line_count",
        )}
        for item in normalized
    ]
    historical_currency = [
        {key: item[key] for key in (
            "account_count", "currency_id", "currency_name", "ledger_company_balance",
            "ledger_transaction_amount", "move_line_count",
        )}
        for item in currency_summaries
    ]
    metrics = {
        "balances": historical_balances,
        "company_currency": {"id": company_id, "name": str(company_currency["name"])},
        "currency_summaries": historical_currency,
        "ledger_summary": result["ledger_summary"],
        "rates": historical_rates,
    }
    return result, metrics


REGISTRY_DESCRIPTOR_KEYS = {
    "id", "domain", "business_description", "access", "risk_level",
    "company_scope", "odoo_permissions", "approval_required",
    "idempotency_required", "input_schema_json", "output_schema_json",
    "contract_digest", "evidence_level", "verification_method",
    "recovery_method", "capability_channel",
}


def verify_registry_result(case: dict[str, Any], actual: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    actual = _exact_keys(actual, {"capabilities", "page"}, "registry result")
    descriptors = actual["capabilities"]
    expected = case["expected"]["capabilities"]
    if not isinstance(descriptors, list) or len(descriptors) != len(expected):
        raise OracleMismatch("registry staged capability count changed")
    checks: dict[str, bool] = {}
    for descriptor, expected_item in zip(descriptors, expected, strict=True):
        if not isinstance(descriptor, dict) or set(descriptor) != REGISTRY_DESCRIPTOR_KEYS:
            raise OracleMismatch("registry descriptor shape changed")
        subset = {key: descriptor[key] for key in expected_item}
        checks[f"descriptor:{expected_item['id']}"] = subset == expected_item
        checks[f"schemas_canonical:{expected_item['id']}"] = all(
            isinstance(descriptor[field], str)
            and canonical_json(parse_json(descriptor[field], field)) == descriptor[field]
            for field in ("input_schema_json", "output_schema_json")
        )
        checks[f"control_fields:{expected_item['id']}"] = (
            descriptor["approval_required"] is False
            and descriptor["idempotency_required"] is False
            and descriptor["evidence_level"] == "contract_tested"
            and descriptor["capability_channel"] == "staged"
            and isinstance(descriptor["business_description"], str)
            and bool(descriptor["business_description"])
            and isinstance(descriptor["verification_method"], str)
            and bool(descriptor["verification_method"])
            and isinstance(descriptor["recovery_method"], str)
            and bool(descriptor["recovery_method"])
        )
    checks["page"] = actual["page"] == {"count": len(expected), "total_count": len(expected)}
    metrics = {"capabilities": expected}
    return checks, metrics


def _validate_receipt(
    plan: dict[str, Any], case: dict[str, Any], receipt: Any, total_count: int
) -> bool:
    if not isinstance(receipt, dict):
        return False
    fixed = {
        "odoo_instance_id": plan["target"]["instance_id"],
        "database_name": plan["database"]["name"],
        "database_uuid": plan["database"]["uuid"],
        "company_id": case["company_id"], "user_id": case["user_id"],
        "capability_id": case["capability_id"],
        "environment": plan["target"]["environment"],
        "capability_channel": plan["target"]["capability_channel"],
        "record_count": total_count, "signature_version": 2,
        "signature_purpose": "read_receipt_v2",
    }
    if any(receipt.get(key) != value for key, value in fixed.items()):
        return False
    for key in ("request_digest", "result_digest", "registry_digest", "release_digest", "signature"):
        if not isinstance(receipt.get(key), str) or not HEX64.fullmatch(receipt[key]):
            return False
    return all(isinstance(receipt.get(key), str) and receipt[key] for key in (
        "id", "observed_at", "signature_key_id",
    ))


def extract_response(
    plan: dict[str, Any], case: dict[str, Any], response: Any
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    response = _exact_keys(response, {"ok", "command", "data"}, "response")
    if response["ok"] is not True or response["command"] != "read":
        raise OracleInputError("response does not report a read success")
    data = _exact_keys(
        response["data"], {"capability_id", "release_identity", "runtime", "result"},
        "response data",
    )
    if data["capability_id"] != case["capability_id"]:
        raise OracleInputError("response capability binding changed")
    runtime = data["runtime"]
    expected_runtime = {
        "instance_id": plan["target"]["instance_id"],
        "environment": plan["target"]["environment"],
        "capability_channel": plan["target"]["capability_channel"],
        "database_name": plan["database"]["name"],
        "database_uuid": plan["database"]["uuid"],
    }
    if runtime != expected_runtime:
        raise OracleInputError("response runtime binding changed")
    if not isinstance(data["release_identity"], dict) or data["release_identity"].get("verified") is not True:
        raise OracleInputError("response has no verified release identity")
    result = data["result"]
    if not isinstance(result, dict) or "receipt" not in result:
        raise OracleInputError("response result/receipt is absent")
    body = {key: value for key, value in result.items() if key != "receipt"}
    return body, result["receipt"], data["release_identity"]


def _company_currency(cursor: Any, company_id: int) -> dict[str, Any]:
    cursor.execute(COMPANY_CURRENCY_SQL, (company_id,))
    rows = cursor.fetchall()
    if len(rows) != 1:
        raise OracleMismatch("fixture gap: company currency identity is absent")
    currency_id, name, symbol, rounding, parent_path = rows[0]
    return {
        "id": int(currency_id), "name": str(name), "symbol": str(symbol),
        "rounding": _decimal(rounding, "company rounding"),
        "parent_path": str(parent_path),
    }


def run_case_oracle(
    cursor: Any, plan: dict[str, Any], case: dict[str, Any], response: dict[str, Any]
) -> dict[str, Any]:
    schema = verify_database_schema(cursor, plan)
    access = verify_access(cursor, case)
    actual_body, receipt, release_identity = extract_response(plan, case, response)
    parameters = case["parameters"]
    if case["name"] == "registry":
        checks, metrics = verify_registry_result(case, actual_body)
        expected_body = actual_body
        total_count = len(case["expected"]["capabilities"])
    elif case["name"] == "trial_balance":
        sql_parameters = {
            **parameters, "company_key": str(parameters["company_id"]),
        }
        cursor.execute(TRIAL_BALANCE_SQL, sql_parameters)
        expected_body, metrics = build_trial_balance(
            _rows(cursor), _company_currency(cursor, parameters["company_id"]), parameters
        )
        checks = result_checks(actual_body, expected_body)
        total_count = expected_body["page"]["total_count"]
    elif case["name"] in {"ar_open_items", "ap_open_items"}:
        kind = "ar" if case["name"] == "ar_open_items" else "ap"
        cursor.execute(OPEN_ITEMS_SQL, {
            **parameters, "company_key": str(parameters["company_id"]),
            "account_type": "asset_receivable" if kind == "ar" else "liability_payable",
        })
        expected_body, metrics = build_open_items(
            _rows(cursor), _company_currency(cursor, parameters["company_id"]), parameters, kind
        )
        checks = result_checks(actual_body, expected_body)
        total_count = expected_body["page"]["total_count"]
    elif case["name"] == "multicurrency":
        query_parameters = {
            **parameters, "company_key": str(parameters["company_id"]),
        }
        cursor.execute(MULTICURRENCY_BALANCES_SQL, query_parameters)
        balances = _rows(cursor)
        company = _company_currency(cursor, parameters["company_id"])
        cursor.execute(RATE_SQL, parameters)
        expected_body, metrics = build_multicurrency(
            balances, company, _rows(cursor), parameters
        )
        checks = result_checks(actual_body, expected_body)
        total_count = expected_body["page"]["total_count"]
    else:
        raise OracleInputError("unsupported fixed read case")
    checks.update(golden_checks(case, metrics))
    checks["signed_receipt_binding"] = _validate_receipt(plan, case, receipt, total_count)
    checks["nonempty_business_result"] = total_count > 0
    report = {
        "schema_version": 1, "command": "verify", "case": case["name"],
        "capability_id": case["capability_id"], "all_checks_passed": all(checks.values()),
        "checks": checks, "database": schema["database"], "endpoint": schema["endpoint"],
        "relation_schema_sha256": {
            item["name"]: item["schema_sha256"] for item in schema["relations"]
        },
        "access": access, "parameters_sha256": digest_json(parameters),
        "business_result_sha256": digest_json(expected_body),
        "oracle_metrics_sha256": digest_json(metrics),
        "record_count": total_count,
        "release_identity_sha256": digest_json(release_identity),
        "fixture_gaps": [], "odoo_action_performed": False,
        "database_writes_permitted": False, "production_validated": False,
    }
    if not report["all_checks_passed"]:
        raise OracleMismatch("independent financial or historical comparison failed", report)
    return report


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise OracleInputError("fixed oracle Python cannot be read") from exc
    return digest.hexdigest()


def verify_runtime_python(
    plan: dict[str, Any], *, executable: str | None = None,
    isolated: int | None = None, module_names: Iterable[str] | None = None,
    executable_sha256: str | None = None,
) -> dict[str, Any]:
    expected_path = plan["runtime"]["odoo_python"]
    actual_path = executable if executable is not None else str(Path(sys.executable).absolute())
    actual_isolated = sys.flags.isolated if isolated is None else isolated
    names = set(sys.modules if module_names is None else module_names)
    digest = executable_sha256 or _sha256_file(Path(actual_path))
    if (
        actual_path != expected_path or actual_isolated != 1
        or digest != plan["runtime"]["odoo_python_sha256"]
        or any(name == "odoo" or name.startswith("odoo.") for name in names)
        or any(name == "odoo_accounting_cli_v3" or name.startswith("odoo_accounting_cli_v3.") for name in names)
    ):
        raise OracleInputError("oracle is not running under the fixed isolated Odoo Python")
    return {"path": actual_path, "sha256": digest, "isolated": True}


def _witness_query(relation: dict[str, Any]) -> tuple[str, tuple[Any, ...]]:
    name = relation["name"]
    projection = relation["witness_projection"]
    primary_key = relation["primary_key"]
    if (
        name not in WITNESS_PROJECTIONS
        or any(not IDENTIFIER.fullmatch(item) for item in [name, *projection, *primary_key])
    ):
        raise OracleInputError("unsafe witness identifier")
    columns = ", ".join(projection)
    ordering = ", ".join(primary_key)
    where = ""
    parameters: tuple[Any, ...] = ()
    if relation["witness_scope"] == "database_uuid_only":
        where = " WHERE key = %s"
        parameters = ("database.uuid",)
    elif relation["witness_scope"] == "required_group_xmlids_only":
        where = (
            " WHERE (module, name) IN ((%s, %s), (%s, %s)) "
            "AND model = 'res.groups'"
        )
        parameters = ("base", "group_user", "account", "group_account_readonly")
    elif relation["witness_scope"] != "all":
        raise OracleInputError("unknown witness scope")
    sql = (
        "SELECT to_jsonb(projected) FROM (SELECT " + columns
        + " FROM public." + name + where + ") AS projected ORDER BY " + ordering
    )
    return sql, parameters


def build_witness(cursor: Any, plan: dict[str, Any]) -> dict[str, Any]:
    schema = verify_database_schema(cursor, plan)
    schema_by_name = {item["name"]: item for item in schema["relations"]}
    relation_reports = []
    fixture_gaps = []
    for relation in plan["witness"]["relations"]:
        sql, parameters = _witness_query(relation)
        cursor.execute(sql, parameters)
        rows = []
        while True:
            if hasattr(cursor, "fetchmany"):
                batch = cursor.fetchmany(512)
            else:
                batch = cursor.fetchall()
            if not batch:
                break
            for row in batch:
                value = row[0]
                if isinstance(value, str):
                    value = parse_json(value, f"{relation['name']} witness row")
                if not isinstance(value, dict):
                    raise OracleInputError("witness row is not a JSON object")
                rows.append(value)
            if not hasattr(cursor, "fetchmany"):
                break
        digest = witness_digest(rows)
        baseline_count = relation["baseline_count"]
        if digest["row_count"] == 0:
            fixture_gaps.append(f"{relation['name']}:empty_projection")
        if baseline_count is not None and digest["row_count"] != baseline_count:
            fixture_gaps.append(
                f"{relation['name']}:count:{digest['row_count']}!=baseline:{baseline_count}"
            )
        relation_reports.append({
            **schema_by_name[relation["name"]],
            "witness_scope": relation["witness_scope"],
            "required_columns": relation["required_columns"],
            "baseline_count": baseline_count,
            "projection_sha256": digest_json(relation["witness_projection"]),
            **digest,
        })
    report = {
        "schema_version": 1, "command": "witness",
        "all_checks_passed": not fixture_gaps,
        "database": schema["database"], "endpoint": schema["endpoint"],
        "relations": relation_reports, "fixture_gaps": fixture_gaps,
        "contains_raw_rows": False, "contains_credentials": False,
        "odoo_action_performed": False, "database_writes_permitted": False,
        "production_validated": False,
    }
    if fixture_gaps:
        raise OracleMismatch("witness fixture gaps prevent a pass", report)
    return report


def _read_json_file(path: str, label: str, max_bytes: int = 16 * 1024 * 1024) -> dict[str, Any]:
    target = Path(path)
    try:
        size = target.stat().st_size
        if size <= 0 or size > max_bytes or target.is_symlink() or not target.is_file():
            raise OracleInputError(f"{label} file boundary is invalid")
        value = parse_json(target.read_text("utf-8"), label)
    except OracleInputError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OracleInputError(f"{label} cannot be read") from exc
    if not isinstance(value, dict):
        raise OracleInputError(f"{label} must be a JSON object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="read_oracles.py")
    subparsers = parser.add_subparsers(dest="command", required=True)
    witness = subparsers.add_parser("witness")
    witness.add_argument("--plan", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--plan", required=True)
    verify.add_argument("--case", required=True, choices=CASE_NAMES)
    verify.add_argument("--request", required=True)
    verify.add_argument("--response", required=True)
    return parser


def _failure_document(
    command: str, category: str, message: str,
    report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if report is not None:
        value = dict(report)
        value["all_checks_passed"] = False
        value.setdefault("fixture_gaps", [])
        value["failure_category"] = category
        return value
    return {
        "schema_version": 1, "command": command,
        "all_checks_passed": False, "failure_category": category,
        "failure_message": message, "fixture_gaps": [message] if category == "oracle_mismatch" else [],
        "odoo_action_performed": False, "database_writes_permitted": False,
        "production_validated": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan = read_plan(args.plan)
        python_identity = verify_runtime_python(plan)
        if args.command == "verify":
            case = case_by_name(plan, args.case)
            request = _read_json_file(args.request, "request")
            response = _read_json_file(args.response, "response")
            validate_request(plan, case, request)
            connection = open_connection(plan)
            report, transaction = run_read_only_transaction(
                connection, lambda cursor: run_case_oracle(cursor, plan, case, response)
            )
        else:
            connection = open_connection(plan)
            report, transaction = run_read_only_transaction(
                connection, lambda cursor: build_witness(cursor, plan)
            )
        report["transaction"] = transaction
        report["oracle_python"] = python_identity
        print(canonical_json(report))
        return 0
    except OracleMismatch as exc:
        print(canonical_json(_failure_document(args.command, "oracle_mismatch", str(exc), exc.report)))
        print("oracle_mismatch", file=sys.stderr)
        return 1
    except (OracleInputError, ValueError, KeyError, TypeError) as exc:
        print(canonical_json(_failure_document(args.command, "oracle_input_error", str(exc))))
        print("oracle_input_error", file=sys.stderr)
        return 2
    except Exception:
        print(canonical_json(_failure_document(
            args.command, "oracle_input_error", "unexpected oracle execution failure"
        )))
        print("oracle_input_error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

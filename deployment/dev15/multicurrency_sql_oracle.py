#!/usr/bin/python3 -I
"""Independent PostgreSQL REPEATABLE READ/READ ONLY Dev15 oracle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable


CAPABILITY_ID = "acct.multicurrency.balance_read.v1"
RELEASE = "0.1.0.dev15-c4616386f921"
TOOLCHAIN_ROOT = Path(
    "/opt/odoo-accounting-cli-v3/toolchains/0.1.0.dev15-read-toolchain.2"
)
DATABASE_NAME = "odoo_test"
DATABASE_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"
DATABASE_USER = "postgres"
SYSTEM_IDENTIFIER = "7616327373742442245"
SERVER_VERSION_NUM = 160014
SOCKET_DIRECTORY = "/var/run/postgresql"
SOCKET_PATH = "/var/run/postgresql/.s.PGSQL.5432"
PORT = 5432
ORACLE_PYTHON = Path("/usr/bin/python3.12")
ORACLE_PYTHON_SHA256 = "1643dacd9feaedc58f3cc581e4d22577dfe25c09b10282936186ccf0f2e61118"
PSQL = Path("/usr/lib/postgresql/16/bin/psql")
PSQL_SHA256 = "6d593ef8e95e5275691fcc28927cc540282db141ca1ec5e3806e7db5523613cb"
ROLLBACK_SENTINEL = "DEV15_ROLLBACK_COMPLETED_v1"
PSQL_CATEGORIES = ("identity", "company", "currencies", "balances", "rates", "rollback")
MAX_PSQL_OUTPUT = 4 * 1024 * 1024
PARAMETERS = {
    "as_of_date": "2026-07-13",
    "balance_basis": "posted_ledger_cumulative",
    "company_id": 9,
    "currency_ids": [6, 1],
    "limit": 500,
    "off_balance_policy": "exclude",
    "offset": 0,
}

PSQL_SQL = r"""
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;

SELECT 'identity' || chr(9) || jsonb_build_object(
    'database', jsonb_build_object(
        'current_database', current_database(),
        'current_user', current_user,
        'database_uuid', (
            SELECT value FROM ir_config_parameter
            WHERE key = 'database.uuid' ORDER BY id LIMIT 1
        ),
        'server_version_num', current_setting('server_version_num')::integer,
        'system_identifier', (SELECT system_identifier::text FROM pg_control_system())
    ),
    'endpoint', jsonb_build_object(
        'inet_server_addr', inet_server_addr()::text,
        'inet_server_port', inet_server_port(),
        'kind', 'unix_socket',
        'requested_directory', '/var/run/postgresql',
        'socket_path', '/var/run/postgresql/.s.PGSQL.5432',
        'unix_socket_directories', current_setting('unix_socket_directories')
    ),
    'transaction', jsonb_build_object(
        'isolation', current_setting('transaction_isolation'),
        'read_only', current_setting('transaction_read_only')
    )
)::text;

WITH target AS (
    SELECT company.*,
           split_part(trim(BOTH '/' FROM company.parent_path), '/', 1)::integer
               AS derived_root_company_id
    FROM res_company AS company
    WHERE company.id = 9
      AND company.parent_path ~ '^[0-9]+(/[0-9]+)*/$'
)
SELECT 'company' || chr(9) || jsonb_build_object(
    'company_currency', jsonb_build_object(
        'id', target.currency_id,
        'name', currency.name,
        'symbol', COALESCE(currency.symbol, currency.name),
        'rounding', currency.rounding::text
    ),
    'company_hierarchy', jsonb_build_object(
        'company_id', target.id,
        'parent_path', target.parent_path,
        'root_company_id', root_company.id
    )
)::text
FROM target
JOIN res_company AS root_company ON root_company.id = target.derived_root_company_id
JOIN res_currency AS currency ON currency.id = target.currency_id;

SELECT 'currencies' || chr(9) || COALESCE(
    jsonb_agg(
        jsonb_build_object(
            'id', currency.id,
            'name', currency.name,
            'symbol', COALESCE(currency.symbol, currency.name),
            'rounding', currency.rounding::text
        )
        ORDER BY array_position(ARRAY[6, 1]::integer[], currency.id)
    ),
    '[]'::jsonb
)::text
FROM res_currency AS currency
WHERE currency.id = ANY(ARRAY[6, 1]::integer[]);

WITH grouped AS (
    SELECT
        aml.account_id,
        account.code_store ->> aml.company_id::text AS account_code,
        account.account_type,
        aml.currency_id,
        currency.name AS currency_name,
        SUM(aml.balance)::text AS ledger_company_balance,
        SUM(aml.amount_currency)::text AS ledger_transaction_amount,
        COUNT(*)::integer AS move_line_count
    FROM account_move_line AS aml
    JOIN account_account AS account ON account.id = aml.account_id
    JOIN res_currency AS currency ON currency.id = aml.currency_id
    WHERE aml.company_id = 9
      AND aml.parent_state = 'posted'
      AND aml.date <= DATE '2026-07-13'
      AND aml.currency_id = ANY(ARRAY[6, 1]::integer[])
      AND account.account_type <> 'off_balance'
    GROUP BY aml.account_id, account.code_store ->> aml.company_id::text,
             account.account_type, aml.currency_id, currency.name
)
SELECT 'balances' || chr(9) || COALESCE(
    jsonb_agg(
        jsonb_build_object(
            'account_id', account_id,
            'account_code', account_code,
            'account_type', account_type,
            'currency_id', currency_id,
            'currency_name', currency_name,
            'ledger_company_balance', ledger_company_balance,
            'ledger_transaction_amount', ledger_transaction_amount,
            'move_line_count', move_line_count
        )
        ORDER BY account_code, account_id,
                 array_position(ARRAY[6, 1]::integer[], currency_id)
    ),
    '[]'::jsonb
)::text
FROM grouped;

WITH company AS (
    SELECT company.currency_id AS company_currency_id,
           split_part(trim(BOTH '/' FROM company.parent_path), '/', 1)::integer
               AS root_company_id
    FROM res_company AS company
    WHERE company.id = 9
      AND company.parent_path ~ '^[0-9]+(/[0-9]+)*/$'
),
requested(currency_id, ordinal) AS (VALUES (6, 1), (1, 2)),
selected AS (
    SELECT requested.currency_id, requested.ordinal,
           chosen.id AS source_record_id,
           chosen.name::text AS effective_date,
           chosen.company_id AS source_company_id,
           chosen.rate AS technical_rate,
           chosen.source_scope,
           EXISTS (
               SELECT 1 FROM res_currency_rate AS any_rate
               WHERE any_rate.currency_id = requested.currency_id
                 AND (
                     any_rate.company_id IS NULL
                     OR any_rate.company_id = company.root_company_id
                 )
           ) AS any_rate_exists,
           company.company_currency_id
    FROM requested
    CROSS JOIN company
    LEFT JOIN LATERAL (
        SELECT candidate.id, candidate.name, candidate.company_id,
               candidate.rate, candidate.source_scope
        FROM (
            SELECT rate.id, rate.name, rate.company_id, rate.rate,
                   'company_specific'::text AS source_scope, 0 AS priority
            FROM res_currency_rate AS rate
            WHERE rate.currency_id = requested.currency_id
              AND rate.name <= DATE '2026-07-13'
              AND rate.company_id = company.root_company_id
            UNION ALL
            SELECT rate.id, rate.name, rate.company_id, rate.rate,
                   'global'::text AS source_scope, 1 AS priority
            FROM res_currency_rate AS rate
            WHERE rate.currency_id = requested.currency_id
              AND rate.name <= DATE '2026-07-13'
              AND rate.company_id IS NULL
        ) AS candidate
        ORDER BY candidate.priority, candidate.name DESC, candidate.id DESC
        LIMIT 1
    ) AS chosen ON TRUE
),
sources AS (
    SELECT selected.currency_id, selected.ordinal,
           selected.company_currency_id,
           selected.effective_date,
           selected.source_company_id,
           selected.source_record_id,
           CASE
               WHEN selected.source_record_id IS NOT NULL THEN selected.source_scope
               WHEN selected.currency_id = selected.company_currency_id
                    AND NOT selected.any_rate_exists THEN 'no_rate_identity'
               WHEN selected.currency_id = selected.company_currency_id
                    THEN 'future_rate_invalid'
               ELSE 'missing_rate'
           END AS source_scope,
           CASE
               WHEN selected.source_record_id IS NOT NULL THEN selected.technical_rate
               WHEN selected.currency_id = selected.company_currency_id
                    AND NOT selected.any_rate_exists THEN 1::numeric
               ELSE NULL::numeric
           END AS technical_rate
    FROM selected
),
source_documents AS (
    SELECT sources.*,
           jsonb_build_object(
               'effective_date', effective_date,
               'source_company_id', source_company_id,
               'source_record_id', source_record_id,
               'source_scope', source_scope,
               'technical_rate', technical_rate::text
           ) AS source_document
    FROM sources
),
company_source AS (
    SELECT * FROM source_documents
    WHERE currency_id = company_currency_id
)
SELECT 'rates' || chr(9) || COALESCE(
    jsonb_agg(
        jsonb_build_object(
            'currency_id', source.currency_id,
            'company_currency_id', source.company_currency_id,
            'transaction_source', source.source_document,
            'company_source', company_source.source_document,
            'transaction_to_company_rate',
                (company_source.technical_rate / source.technical_rate)::text,
            'company_to_transaction_rate',
                (source.technical_rate / company_source.technical_rate)::text
        )
        ORDER BY source.ordinal
    ),
    '[]'::jsonb
)::text
FROM source_documents AS source
CROSS JOIN company_source;

ROLLBACK;
SELECT 'rollback' || chr(9) || 'DEV15_ROLLBACK_COMPLETED_v1';
"""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_value(text: str) -> Any:
    value = json.loads(
        text,
        object_pairs_hook=_pairs,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number: {token}")
        ),
    )
    return value


def load_text(text: str) -> dict[str, Any]:
    value = load_value(text)
    if not isinstance(value, dict):
        raise ValueError("request must be a JSON object")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    )


def decimal_text(value: Any) -> str:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("oracle received an invalid decimal") from exc
    if not result.is_finite():
        raise ValueError("oracle received a non-finite decimal")
    return format(result, "f")


def root_company_id_from_parent_path(value: Any) -> int:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]+(?:/[0-9]+)*/", value) is None:
        raise ValueError("company parent_path is invalid")
    root = int(value.split("/", 1)[0])
    if root <= 0:
        raise ValueError("company parent_path root is invalid")
    return root


def _safe_root_chain(path: Path) -> None:
    current = Path("/")
    for component in path.absolute().parts[1:]:
        current /= component
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode) or current.is_symlink()
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
        ):
            raise ValueError(f"unsafe fixed executable ancestor: {current}")


def fixed_executable_snapshot(path: Path, expected_sha256: str) -> dict[str, Any]:
    path = Path(path).absolute()
    _safe_root_chain(path.parent)
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or (before.st_uid, before.st_gid) != (0, 0)
            or stat.S_IMODE(before.st_mode) != 0o755
            or before.st_size <= 0 or before.st_size > 64 * 1024 * 1024
        ):
            raise ValueError(f"fixed executable metadata is unsafe: {path}")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError(f"fixed executable changed during read: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            os.read(descriptor, 1)
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                after.st_ctime_ns)
        ):
            raise ValueError(f"fixed executable identity changed: {path}")
    finally:
        os.close(descriptor)
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError(f"fixed executable SHA-256 mismatch: {path}")
    return {
        "path": str(path), "sha256": actual_sha256,
        "uid": before.st_uid, "gid": before.st_gid,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
    }


def verify_isolated_stdlib_runtime() -> None:
    if (
        Path(sys.executable).absolute() != ORACLE_PYTHON
        or sys.flags.isolated != 1 or sys.flags.no_site != 1
        or "site" in sys.modules or "psycopg2" in sys.modules
    ):
        raise ValueError("oracle is not running under fixed isolated stdlib Python")


def verify_oracle_executables() -> dict[str, Any]:
    verify_isolated_stdlib_runtime()
    return {
        "python": fixed_executable_snapshot(ORACLE_PYTHON, ORACLE_PYTHON_SHA256),
        "psql": fixed_executable_snapshot(PSQL, PSQL_SHA256),
    }


def _validate_rate_source(source: Any, *, allow_identity: bool) -> None:
    if not isinstance(source, dict) or set(source) != {
        "effective_date", "source_company_id", "source_record_id",
        "source_scope", "technical_rate",
    }:
        raise ValueError("psql oracle rate source fields are invalid")
    scope = source["source_scope"]
    if scope == "no_rate_identity":
        if not allow_identity or source != {
            "effective_date": None, "source_company_id": None,
            "source_record_id": None, "source_scope": "no_rate_identity",
            "technical_rate": "1",
        }:
            raise ValueError("psql oracle identity rate source is invalid")
        return
    if scope not in {"company_specific", "global"}:
        raise ValueError("psql oracle rate source scope is invalid")
    if not isinstance(source["source_record_id"], int) or source["source_record_id"] <= 0:
        raise ValueError("psql oracle rate source record is invalid")
    if scope == "company_specific" and source["source_company_id"] != 9:
        raise ValueError("psql oracle company-specific rate source is invalid")
    if scope == "global" and source["source_company_id"] is not None:
        raise ValueError("psql oracle global rate source is invalid")
    if not isinstance(source["effective_date"], str):
        raise ValueError("psql oracle rate source date is invalid")
    if Decimal(decimal_text(source["technical_rate"])) <= 0:
        raise ValueError("psql oracle technical rate is invalid")


def parse_psql_output(
    payload: bytes, *, request: dict[str, Any], executables: dict[str, Any],
) -> dict[str, Any]:
    if not payload or len(payload) > MAX_PSQL_OUTPUT or not payload.endswith(b"\n"):
        raise ValueError("psql oracle output boundary is invalid")
    try:
        lines = payload.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("psql oracle output is not strict UTF-8") from exc
    if len(lines) != len(PSQL_CATEGORIES):
        raise ValueError("psql oracle output category count is invalid")
    categories: dict[str, str] = {}
    order: list[str] = []
    for line in lines:
        category, separator, value = line.partition("\t")
        if not separator or not category or not value or "\t" in value:
            raise ValueError("psql oracle output record is invalid")
        if category in categories:
            raise ValueError(f"duplicate psql oracle category: {category}")
        categories[category] = value
        order.append(category)
    if tuple(order) != PSQL_CATEGORIES or set(categories) != set(PSQL_CATEGORIES):
        raise ValueError("psql oracle output category order/set is invalid")
    if categories["rollback"] != ROLLBACK_SENTINEL:
        raise ValueError("psql oracle rollback sentinel is invalid")

    identity = load_value(categories["identity"])
    company = load_value(categories["company"])
    currencies = load_value(categories["currencies"])
    balances = load_value(categories["balances"])
    rates = load_value(categories["rates"])
    if not isinstance(identity, dict) or set(identity) != {"database", "endpoint", "transaction"}:
        raise ValueError("psql oracle identity category is invalid")
    if identity["database"] != {
        "current_database": DATABASE_NAME, "current_user": DATABASE_USER,
        "database_uuid": DATABASE_UUID, "server_version_num": SERVER_VERSION_NUM,
        "system_identifier": SYSTEM_IDENTIFIER,
    }:
        raise ValueError("psql oracle database identity mismatch")
    endpoint = identity["endpoint"]
    if (
        not isinstance(endpoint, dict)
        or set(endpoint) != {
            "inet_server_addr", "inet_server_port", "kind", "requested_directory",
            "socket_path", "unix_socket_directories",
        }
        or endpoint["inet_server_addr"] is not None
        or endpoint["inet_server_port"] is not None
        or endpoint["kind"] != "unix_socket"
        or endpoint["requested_directory"] != SOCKET_DIRECTORY
        or endpoint["socket_path"] != SOCKET_PATH
        or SOCKET_DIRECTORY not in {
            part.strip() for part in str(endpoint["unix_socket_directories"]).split(",")
        }
    ):
        raise ValueError("psql oracle Unix-socket identity mismatch")
    if identity["transaction"] != {"isolation": "repeatable read", "read_only": "on"}:
        raise ValueError("psql oracle transaction is not REPEATABLE READ READ ONLY")
    if not isinstance(company, dict) or set(company) != {"company_currency", "company_hierarchy"}:
        raise ValueError("psql oracle company category is invalid")
    hierarchy = company["company_hierarchy"]
    if (
        not isinstance(hierarchy, dict)
        or hierarchy.get("company_id") != 9 or hierarchy.get("root_company_id") != 9
        or root_company_id_from_parent_path(hierarchy.get("parent_path")) != 9
    ):
        raise ValueError("psql oracle company hierarchy mismatch")
    company_currency = company["company_currency"]
    if (
        not isinstance(company_currency, dict)
        or set(company_currency) != {"id", "name", "symbol", "rounding"}
        or company_currency["id"] != 6 or company_currency["name"] != "CNY"
        or not isinstance(company_currency["symbol"], str)
        or Decimal(decimal_text(company_currency["rounding"])) != Decimal("0.01")
    ):
        raise ValueError("psql oracle company currency mismatch")
    if not isinstance(currencies, list) or [item.get("id") for item in currencies if isinstance(item, dict)] != [6, 1]:
        raise ValueError("psql oracle currency catalog mismatch")
    if not isinstance(balances, list) or not all(isinstance(item, dict) for item in balances):
        raise ValueError("psql oracle balances are invalid")
    if not isinstance(rates, list) or [item.get("currency_id") for item in rates if isinstance(item, dict)] != [6, 1]:
        raise ValueError("psql oracle rates are invalid")
    for rate in rates:
        if set(rate) != {
            "currency_id", "company_currency_id", "transaction_source",
            "company_source", "transaction_to_company_rate",
            "company_to_transaction_rate",
        } or rate["company_currency_id"] != 6:
            raise ValueError("psql oracle rate fields are invalid")
        _validate_rate_source(
            rate["transaction_source"], allow_identity=rate["currency_id"] == 6,
        )
        _validate_rate_source(rate["company_source"], allow_identity=True)
        if (
            Decimal(decimal_text(rate["transaction_to_company_rate"])) <= 0
            or Decimal(decimal_text(rate["company_to_transaction_rate"])) <= 0
        ):
            raise ValueError("psql oracle conversion rate is invalid")

    return {
        "schema_version": 2,
        "capability_id": CAPABILITY_ID,
        "database": identity["database"],
        "endpoint": endpoint,
        "parameters": request["parameters"],
        "transaction": {
            **identity["transaction"], "rollback_completed": True,
        },
        "executables": executables,
        "company_currency": company_currency,
        "company_hierarchy": hierarchy,
        "currency_catalog": currencies,
        "balances": balances,
        "rates": rates,
    }


def verify_toolchain_location() -> None:
    expected = TOOLCHAIN_ROOT / "multicurrency_sql_oracle.py"
    actual = Path(__file__).absolute()
    if actual != expected or actual.is_symlink():
        raise ValueError("oracle is not executing from the fixed Dev15 toolchain")
    current = Path("/")
    for component in TOOLCHAIN_ROOT.parts[1:]:
        current /= component
        metadata = current.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode) or current.is_symlink()
            or (metadata.st_uid, metadata.st_gid) != (0, 0)
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not stat.S_IMODE(metadata.st_mode) & 0o111
        ):
            raise ValueError(f"unsafe oracle toolchain parent: {current}")
    root_metadata = TOOLCHAIN_ROOT.lstat()
    file_metadata = expected.lstat()
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or (root_metadata.st_uid, root_metadata.st_gid) != (0, 0)
        or stat.S_IMODE(root_metadata.st_mode) != 0o555
        or not stat.S_ISREG(file_metadata.st_mode)
        or file_metadata.st_nlink != 1
        or (file_metadata.st_uid, file_metadata.st_gid) != (0, 0)
        or stat.S_IMODE(file_metadata.st_mode) != 0o444
    ):
        raise ValueError("oracle toolchain metadata is unsafe")


def validate_request(request: dict[str, Any]) -> None:
    if set(request) != {"capability_id", "context", "parameters"}:
        raise ValueError("oracle request fields are invalid")
    if request["capability_id"] != CAPABILITY_ID or request["parameters"] != PARAMETERS:
        raise ValueError("oracle request escaped the byte-pinned plan")
    context = request["context"]
    if not isinstance(context, dict) or any(
        context.get(key) != value
        for key, value in {
            "allowed_company_ids": [9],
            "company_id": 9,
            "database_name": DATABASE_NAME,
            "database_uuid": DATABASE_UUID,
            "environment": "test",
            "odoo_instance_id": "odoo19@43.165.173.80",
            "principal": "pi:test-user-2",
            "user_id": 2,
        }.items()
    ):
        raise ValueError("oracle request context binding is invalid")


def execute_oracle(
    request: dict[str, Any], *,
    command_runner: Callable[..., Any] = subprocess.run,
    executable_verifier: Callable[[], dict[str, Any]] = verify_oracle_executables,
) -> dict[str, Any]:
    validate_request(request)
    executables = executable_verifier()
    completed = command_runner(
        [
            PSQL.as_posix(), "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
            "-w", "-h", SOCKET_DIRECTORY, "-p", str(PORT), "-U", DATABASE_USER,
            "-d", DATABASE_NAME,
        ],
        input=PSQL_SQL.encode("utf-8"), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=60,
        env={
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PGAPPNAME": "odoo-accounting-cli-v3-dev15-read-oracle",
            "PGOPTIONS": "-c default_transaction_read_only=on -c statement_timeout=45000",
        },
    )
    if completed.returncode != 0 or completed.stderr:
        raise ValueError("fixed psql oracle returned nonzero or stderr")
    if executable_verifier() != executables:
        raise ValueError("fixed Oracle executable identity changed during execution")
    return parse_psql_output(
        completed.stdout, request=request, executables=executables,
    )


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("usage: multicurrency_sql_oracle.py < REQUEST_JSON")
    verify_toolchain_location()
    request = load_text(sys.stdin.read(1024 * 1024 + 1))
    print(canonical_json(execute_oracle(request)))


if __name__ == "__main__":
    main()

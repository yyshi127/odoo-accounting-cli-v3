"""Canonical installed-module evidence for optional Odoo accounting fields."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import Any, Iterable, Mapping

from ..operations import canonical_json


class OdooModuleGraphError(ValueError):
    """The live installed-module graph is malformed or contradicts the schema."""


MODULE_GRAPH_SCHEMA_VERSION = 1
_MODULE_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}")
_MAX_INSTALLED_MODULES = 4_096

# A field is conditional only when every provider below is absent.  The policy
# is part of the verified release; the live graph and its digest are bound into
# precheck and execution evidence.
OPTIONAL_FIELD_PROVIDERS: dict[str, dict[str, frozenset[str]]] = {
    "account.move": {
        "asset_id": frozenset({"account_asset"}),
        "asset_ids": frozenset({"account_asset"}),
        "asset_value_change": frozenset({"account_asset"}),
        "asset_depreciation_beginning_date": frozenset({"account_asset"}),
        "asset_number_days": frozenset({"account_asset"}),
        "depreciation_value": frozenset({"account_asset"}),
        "transaction_ids": frozenset({"account_payment"}),
        "authorized_transaction_ids": frozenset({"account_payment"}),
        "closing_return_id": frozenset({"account_reports"}),
        "debit_note_ids": frozenset({"account_debit_note"}),
        "debit_origin_id": frozenset({"account_debit_note"}),
        "deferred_move_ids": frozenset({"account_accountant"}),
        "deferred_original_move_ids": frozenset({"account_accountant"}),
        "payment_state_before_switch": frozenset({"account_accountant"}),
        "signature": frozenset({"account_accountant"}),
        "signing_user": frozenset({"account_accountant"}),
        "edi_document_ids": frozenset({"account_edi"}),
        "expense_ids": frozenset({"hr_expense"}),
        "l10n_es_edi_facturae_xml_id": frozenset(
            {"l10n_es_edi_facturae"}
        ),
        "l10n_es_edi_facturae_xml_file": frozenset(
            {"l10n_es_edi_facturae"}
        ),
        "l10n_es_edi_facturae_reason_code": frozenset(
            {"l10n_es_edi_facturae"}
        ),
        "l10n_es_invoicing_period_start_date": frozenset(
            {"l10n_es_edi_facturae"}
        ),
        "l10n_es_invoicing_period_end_date": frozenset(
            {"l10n_es_edi_facturae"}
        ),
        "l10n_es_payment_means": frozenset({"l10n_es_edi_facturae"}),
        "l10n_es_is_simplified": frozenset({"l10n_es"}),
        "fapiao": frozenset({"l10n_cn"}),
        "l10n_latam_document_type_id": frozenset(
            {"l10n_latam_invoice_document"}
        ),
        "landed_costs_ids": frozenset({"stock_landed_costs"}),
        "pos_order_ids": frozenset({"point_of_sale"}),
        "purchase_id": frozenset({"purchase"}),
        "purchase_vendor_bill_id": frozenset({"purchase"}),
        "rating_ids": frozenset({"rating"}),
        "campaign_id": frozenset({"sale"}),
        "medium_id": frozenset({"sale"}),
        "source_id": frozenset({"sale"}),
        "team_id": frozenset({"sale"}),
        "stock_move_ids": frozenset({"stock_account"}),
        "transfer_model_id": frozenset({"account_transfer"}),
        "ubl_cii_xml_id": frozenset({"account_edi_ubl_cii"}),
        "ubl_cii_xml_file": frozenset({"account_edi_ubl_cii"}),
    },
    "account.move.line": {
        "asset_ids": frozenset({"account_asset"}),
        "cogs_origin_id": frozenset({"stock_account"}),
        "deferred_start_date": frozenset({"account_accountant"}),
        "deferred_end_date": frozenset({"account_accountant"}),
        "move_attachment_ids": frozenset({"account_accountant"}),
        "expense_id": frozenset({"hr_expense"}),
        "is_downpayment": frozenset({"purchase", "sale"}),
        "is_landed_costs_line": frozenset({"stock_landed_costs"}),
        "l10n_latam_document_type_id": frozenset(
            {"l10n_latam_invoice_document"}
        ),
        "purchase_line_id": frozenset({"purchase"}),
        "purchase_order_id": frozenset({"purchase"}),
        "sale_line_ids": frozenset({"sale"}),
    },
}


@dataclass(frozen=True)
class TrustedModuleGraph:
    modules: tuple[tuple[str, str], ...]
    digest: str

    @property
    def installed_modules(self) -> frozenset[str]:
        return frozenset(name for name, _version in self.modules)

    @property
    def evidence(self) -> dict[str, Any]:
        return {
            "schema_version": MODULE_GRAPH_SCHEMA_VERSION,
            "modules": [
                {"name": name, "latest_version": version}
                for name, version in self.modules
            ],
            "digest": self.digest,
        }


def _payload(modules: tuple[tuple[str, str], ...]) -> dict[str, Any]:
    return {
        "schema_version": MODULE_GRAPH_SCHEMA_VERSION,
        "modules": [
            {"name": name, "latest_version": version}
            for name, version in modules
        ],
    }


def build_trusted_module_graph(
    rows: Iterable[Mapping[str, Any]],
) -> TrustedModuleGraph:
    normalized: list[tuple[str, str]] = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != {
            "name",
            "latest_version",
        }:
            raise OdooModuleGraphError("installed module row fields are invalid")
        name = row["name"]
        version = row["latest_version"]
        if (
            type(name) is not str
            or _MODULE_NAME.fullmatch(name) is None
            or type(version) is not str
            or not version.strip()
            or version != version.strip()
            or len(version) > 256
        ):
            raise OdooModuleGraphError("installed module identity is invalid")
        normalized.append((name, version))
        if len(normalized) > _MAX_INSTALLED_MODULES:
            raise OdooModuleGraphError("installed module graph is too large")
    normalized.sort()
    if not normalized or len({name for name, _version in normalized}) != len(
        normalized
    ):
        raise OdooModuleGraphError("installed module graph is empty or ambiguous")
    if "account" not in {name for name, _version in normalized}:
        raise OdooModuleGraphError("account module is not installed")
    modules = tuple(normalized)
    digest = hashlib.sha256(canonical_json(_payload(modules))).hexdigest()
    return TrustedModuleGraph(modules=modules, digest=digest)


def validate_module_graph_evidence(value: Any) -> TrustedModuleGraph:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "modules",
        "digest",
    }:
        raise OdooModuleGraphError("module graph evidence fields are invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != MODULE_GRAPH_SCHEMA_VERSION
    ):
        raise OdooModuleGraphError("module graph evidence version is invalid")
    modules = value["modules"]
    if not isinstance(modules, list):
        raise OdooModuleGraphError("module graph evidence modules are invalid")
    graph = build_trusted_module_graph(modules)
    if modules != graph.evidence["modules"]:
        raise OdooModuleGraphError(
            "module graph evidence modules are not canonical"
        )
    digest = value["digest"]
    if type(digest) is not str or not hmac.compare_digest(
        graph.digest, digest
    ):
        raise OdooModuleGraphError("module graph evidence digest differs")
    return graph


def conditional_required_fields(
    model_name: str,
    requested_fields: Iterable[str],
    available_fields: Iterable[str],
    graph: TrustedModuleGraph,
) -> frozenset[str]:
    if not isinstance(graph, TrustedModuleGraph):
        raise OdooModuleGraphError("trusted module graph is unavailable")
    requested = frozenset(requested_fields)
    available = frozenset(available_fields)
    installed = graph.installed_modules
    result = set(requested)
    for field, providers in OPTIONAL_FIELD_PROVIDERS.get(model_name, {}).items():
        if field not in requested or providers & installed:
            continue
        if field in available:
            raise OdooModuleGraphError(
                f"{model_name}.{field} schema differs from the trusted module graph"
            )
        result.remove(field)
    return frozenset(result)


def read_installed_module_graph(
    root_env: Any,
    *,
    lock_for_transaction: bool = False,
) -> TrustedModuleGraph:
    if not getattr(root_env, "su", False):
        raise OdooModuleGraphError("module graph requires the trusted root environment")
    try:
        if lock_for_transaction:
            cursor = root_env.cr
            cursor.execute("LOCK TABLE ir_module_module IN SHARE MODE")
        model = root_env["ir.module.module"].with_context(active_test=False)
        records = model.search(
            [("state", "=", "installed")],
            order="name, id",
        )
        raw = records.read(["name", "latest_version", "state"])
    except Exception as exc:
        raise OdooModuleGraphError("installed module graph cannot be read") from exc
    rows: list[dict[str, str]] = []
    for item in raw:
        if (
            not isinstance(item, Mapping)
            or item.get("state") != "installed"
            or "name" not in item
            or "latest_version" not in item
        ):
            raise OdooModuleGraphError("installed module readback is invalid")
        rows.append(
            {
                "name": item["name"],
                "latest_version": item["latest_version"],
            }
        )
    return build_trusted_module_graph(rows)


__all__ = [
    "MODULE_GRAPH_SCHEMA_VERSION",
    "OPTIONAL_FIELD_PROVIDERS",
    "OdooModuleGraphError",
    "TrustedModuleGraph",
    "build_trusted_module_graph",
    "conditional_required_fields",
    "read_installed_module_graph",
    "validate_module_graph_evidence",
]

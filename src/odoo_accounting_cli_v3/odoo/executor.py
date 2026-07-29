"""Trusted Odoo-side read executor and receipt verifier."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Iterable

from ..domain.ap_open_items import ApOpenItemsBackend, read_ap_open_items
from ..domain.ar_open_items import ArOpenItemsBackend, read_ar_open_items
from ..domain.multicurrency_balance import (
    MulticurrencyBalanceBackend,
    read_multicurrency_balance,
)
from ..domain.report_read import (
    ReportReadBackend,
    read_financial_report,
    read_tax_report,
)
from ..domain.trial_balance import TrialBalanceBackend, read_trial_balance
from ..gateway import RequestContext
from ..receipts import (
    create_read_receipt,
    valid_read_runtime_binding,
    verify_read_receipt,
)
from ..registry import Capability
from .ap_open_items import OdooApOpenItemsBackend
from .ar_open_items import OdooArOpenItemsBackend
from .multicurrency_balance import OdooMulticurrencyBalanceBackend
from .report_read import OdooReportReadBackend
from .trial_balance import OdooTrialBalanceBackend


SHA256_HEX = frozenset("0123456789abcdef")
_FINANCIAL_REPORT_ROOT_XMLIDS = frozenset(
    {
        "account_reports.balance_sheet",
        "account_reports.cash_flow_report",
        "account_reports.profit_and_loss",
    }
)
_TAX_REPORT_ROOT_XMLIDS = frozenset({"account.generic_tax_report"})
_CAPABILITIES = frozenset(
    {
        "acct.registry.list.v1",
        "acct.gl.trial_balance.v1",
        "acct.ar.open_items.v1",
        "acct.ap.open_items.v1",
        "acct.multicurrency.balance_read.v1",
        "acct.move.draft_cancel_eligibility.v1",
        "acct.report.financial_read.v1",
        "acct.tax.report_read.v1",
    }
)


class OdooExecutionError(ValueError):
    pass


def _record_id(value: Any) -> int | None:
    if value in (False, None):
        return None
    raw = getattr(value, "id", value)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return None
    return raw


def _ids(value: Any) -> list[int]:
    if value in (False, None):
        return []
    raw = getattr(value, "ids", None)
    if raw is None:
        raw = value
    if isinstance(raw, (list, tuple, set, frozenset)):
        result = []
        for item in raw:
            record_id = _record_id(item)
            if record_id is not None:
                result.append(record_id)
        return sorted(set(result))
    record_id = _record_id(raw)
    return [] if record_id is None else [record_id]


def _valid_sha_binding(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in SHA256_HEX for character in value)
    )


def _decimal(value: Any) -> Decimal | None:
    if value in (False, None, ""):
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _amounts_equal_abs(left: Any, right: Any) -> bool:
    left_decimal = _decimal(left)
    right_decimal = _decimal(right)
    if left_decimal is None or right_decimal is None:
        return False
    return abs(left_decimal) == abs(right_decimal)


def _iter_records(value: Any) -> list[Any]:
    if value in (False, None):
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    try:
        return list(value)
    except TypeError:
        return [value]


def _check_read_acl(record: Any) -> None:
    if hasattr(record, "check_access_rights"):
        record.check_access_rights("read")
    if hasattr(record, "check_access_rule"):
        record.check_access_rule("read")


def _has_draft_cancel_singular_effect_link(move: Any) -> bool:
    return any(
        (
            _record_id(getattr(move, "auto_post_origin_id", None)) is not None,
            _record_id(getattr(move, "origin_payment_id", None)) is not None,
            _record_id(getattr(move, "statement_line_id", None)) is not None,
            _record_id(getattr(move, "statement_id", None)) is not None,
            _record_id(getattr(move, "tax_cash_basis_rec_id", None)) is not None,
            _record_id(getattr(move, "tax_cash_basis_origin_move_id", None)) is not None,
            _record_id(getattr(move, "reversed_entry_id", None)) is not None,
            _record_id(getattr(move, "asset_id", None)) is not None,
            _record_id(getattr(move, "closing_return_id", None)) is not None,
            _record_id(getattr(move, "transfer_model_id", None)) is not None,
            _record_id(getattr(move, "purchase_id", None)) is not None,
            _record_id(getattr(move, "debit_origin_id", None)) is not None,
            _record_id(getattr(move, "invoice_pdf_report_id", None)) is not None,
            _record_id(getattr(move, "invoice_vendor_bill_id", None)) is not None,
            _record_id(getattr(move, "purchase_vendor_bill_id", None)) is not None,
            _record_id(getattr(move, "ubl_cii_xml_id", None)) is not None,
            _record_id(getattr(move, "l10n_es_edi_facturae_xml_id", None)) is not None,
            _record_id(getattr(move, "signing_user", None)) is not None,
            _record_id(getattr(move, "message_main_attachment_id", None)) is not None,
        )
    )


def _has_draft_cancel_plural_effect_link(move: Any) -> bool:
    return any(
        (
            _ids(getattr(move, "payment_ids", [])),
            _ids(getattr(move, "matched_payment_ids", [])),
            _ids(getattr(move, "reconciled_payment_ids", [])),
            _ids(getattr(move, "tax_cash_basis_created_move_ids", [])),
            _ids(getattr(move, "reversal_move_ids", [])),
            _ids(getattr(move, "adjusting_entry_origin_move_ids", [])),
            _ids(getattr(move, "adjusting_entries_move_ids", [])),
            _ids(getattr(move, "exchange_diff_partial_ids", [])),
            _ids(getattr(move, "deferred_move_ids", [])),
            _ids(getattr(move, "deferred_original_move_ids", [])),
            _ids(getattr(move, "edi_document_ids", [])),
            _ids(getattr(move, "expense_ids", [])),
            _ids(getattr(move, "pos_order_ids", [])),
            _ids(getattr(move, "statement_line_ids", [])),
            _ids(getattr(move, "transaction_ids", [])),
            _ids(getattr(move, "authorized_transaction_ids", [])),
            _ids(getattr(move, "asset_ids", [])),
            _ids(getattr(move, "stock_move_ids", [])),
            _ids(getattr(move, "landed_costs_ids", [])),
            _ids(getattr(move, "debit_note_ids", [])),
            _ids(getattr(move, "attachment_ids", [])),
        )
    )


class OdooReadExecutor:
    """Dispatch only registered read handlers inside a bound non-su Odoo env."""

    def __init__(
        self,
        env: Any,
        *,
        capabilities: Iterable[Capability],
        odoo_instance_id: str,
        database_name: str,
        database_uuid: str,
        environment: str,
        capability_channel: str,
        receipt_secret: bytes,
        receipt_key_id: str,
        consume_receipt: Callable[[str, str, datetime, datetime], bool],
        now: Callable[[], datetime] | None = None,
        receipt_id_factory: Callable[[], str] | None = None,
        trial_balance_backend_factory: Callable[[Any, int, frozenset[int]], TrialBalanceBackend]
        | None = None,
        ar_open_items_backend_factory: Callable[
            [Any, int, frozenset[int]], ArOpenItemsBackend
        ]
        | None = None,
        ap_open_items_backend_factory: Callable[
            [Any, int, frozenset[int]], ApOpenItemsBackend
        ]
        | None = None,
        multicurrency_balance_backend_factory: Callable[
            [Any, int, frozenset[int]], MulticurrencyBalanceBackend
        ]
        | None = None,
        report_read_backend_factory: Callable[
            [Any, int, frozenset[int]], ReportReadBackend
        ]
        | None = None,
    ) -> None:
        capability_list = tuple(capabilities)
        capability_map = {item.id: item for item in capability_list}
        if (
            not odoo_instance_id
            or not database_name
            or not receipt_secret
            or not isinstance(receipt_key_id, str)
            or not receipt_key_id.strip()
            or not callable(consume_receipt)
            or not valid_read_runtime_binding(environment, capability_channel)
            or not capability_list
            or len(capability_map) != len(capability_list)
        ):
            raise OdooExecutionError(
                "trusted registry, instance, database, receipt key, and replay store are required"
            )
        self._env = env
        self._capabilities = capability_list
        self._capability_map = capability_map
        self._odoo_instance_id = odoo_instance_id
        self._database_name = database_name
        self._database_uuid = str(uuid.UUID(database_uuid))
        self._environment = environment
        self._capability_channel = capability_channel
        self._receipt_secret = receipt_secret
        self._receipt_key_id = receipt_key_id
        self._consume_receipt = consume_receipt
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._receipt_id_factory = receipt_id_factory or (lambda: str(uuid.uuid4()))
        self._trial_balance_backend_factory = trial_balance_backend_factory or (
            lambda bound_env, user_id, allowed: OdooTrialBalanceBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )
        self._ar_open_items_backend_factory = ar_open_items_backend_factory or (
            lambda bound_env, user_id, allowed: OdooArOpenItemsBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )
        self._ap_open_items_backend_factory = ap_open_items_backend_factory or (
            lambda bound_env, user_id, allowed: OdooApOpenItemsBackend(
                bound_env, user_id=user_id, allowed_company_ids=allowed
            )
        )
        self._multicurrency_balance_backend_factory = (
            multicurrency_balance_backend_factory
            or (
                lambda bound_env, user_id, allowed: OdooMulticurrencyBalanceBackend(
                    bound_env,
                    user_id=user_id,
                    allowed_company_ids=allowed,
                )
            )
        )
        self._report_read_backend_factory = report_read_backend_factory or (
            lambda bound_env, user_id, allowed: OdooReportReadBackend(
                bound_env,
                user_id=user_id,
                allowed_company_ids=allowed,
                allowed_root_xmlids_by_family={
                    "financial": _FINANCIAL_REPORT_ROOT_XMLIDS,
                    "tax": _TAX_REPORT_ROOT_XMLIDS,
                },
            )
        )

    def _assert_runtime_binding(self, context: RequestContext) -> None:
        actual_database = getattr(getattr(self._env, "cr", None), "dbname", None)
        if (
            context.odoo_instance_id != self._odoo_instance_id
            or context.database_name != self._database_name
            or context.database_uuid != self._database_uuid
            or context.environment != self._environment
            or actual_database != self._database_name
            or context.user_id != getattr(self._env, "uid", None)
            or getattr(self._env, "su", False)
        ):
            raise OdooExecutionError("Odoo executor runtime binding mismatch")

    @staticmethod
    def _canonical_json(value: Any) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def _read_registry(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        company_id = parameters["company_id"]
        if company_id != context.company_id or company_id not in context.allowed_company_ids:
            raise OdooExecutionError("registry company is outside the signed company binding")
        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise OdooExecutionError("registry company does not exist or is not visible")
        company.check_access_rights("read")
        company.check_access_rule("read")

        environment_field = (
            "enabled_environments"
            if self._capability_channel == "enabled"
            else "staged_environments"
        )
        descriptors = []
        for candidate in self._capabilities:
            data = candidate.data
            if context.environment not in data.get(environment_field, []):
                continue
            if not all(
                self._env.user.has_group(xml_id)
                for xml_id in data["odoo_permissions"]
            ):
                continue
            contract_json = self._canonical_json(data)
            descriptors.append(
                {
                    "id": data["id"],
                    "domain": data["domain"],
                    "business_description": data["business_description"],
                    "access": data["access"],
                    "risk_level": data["risk_level"],
                    "company_scope": data["company_scope"],
                    "odoo_permissions": data["odoo_permissions"],
                    "approval_required": data["approval"]["required"],
                    "idempotency_required": data["idempotency"]["required"],
                    "input_schema_json": self._canonical_json(data["input_schema"]),
                    "output_schema_json": self._canonical_json(data["output_schema"]),
                    "contract_digest": hashlib.sha256(
                        contract_json.encode("utf-8")
                    ).hexdigest(),
                    "evidence_level": data["evidence"]["level"],
                    "verification_method": data["verification"]["method"],
                    "recovery_method": data["recovery"]["method"],
                    "capability_channel": self._capability_channel,
                }
            )
        descriptors.sort(key=lambda item: item["id"])
        count = len(descriptors)
        return {
            "capabilities": descriptors,
            "page": {"count": count, "total_count": count},
        }

    def _read_trial_balance(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._trial_balance_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_trial_balance(backend, parameters)

    def _read_ar_open_items(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._ar_open_items_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_ar_open_items(backend, parameters)

    def _read_ap_open_items(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._ap_open_items_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_ap_open_items(backend, parameters)

    def _read_multicurrency_balance(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._multicurrency_balance_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_multicurrency_balance(backend, parameters)

    def _read_financial_report(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._report_read_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_financial_report(backend, parameters)

    def _read_tax_report(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        backend = self._report_read_backend_factory(
            self._env, context.user_id, context.allowed_company_ids
        )
        return read_tax_report(backend, parameters)

    def _read_draft_cancel_eligibility(
        self, context: RequestContext, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        company_id = parameters["company_id"]
        move_id = parameters["move_id"]
        expected_move_type = parameters["expected_move_type"]
        if company_id != context.company_id or company_id not in context.allowed_company_ids:
            raise OdooExecutionError("draft cancellation company is outside the signed binding")

        company = self._env["res.company"].browse(company_id).exists()
        if not company or len(company) != 1:
            raise OdooExecutionError("draft cancellation company does not exist or is not visible")
        _check_read_acl(company)

        move = self._env["account.move"].browse(move_id).exists()
        if not move or len(move) != 1:
            raise OdooExecutionError("draft cancellation move does not exist or is not visible")
        _check_read_acl(move)
        if _record_id(getattr(move, "company_id", None)) != company_id:
            raise OdooExecutionError("draft cancellation move is outside the bound company")

        lines = _iter_records(getattr(move, "line_ids", []))
        for line in lines:
            _check_read_acl(line)

        move_type = str(getattr(move, "move_type", "") or "")
        state = str(getattr(move, "state", "") or "")
        document_binding = str(getattr(move, "odoo_cli_v3_document_binding", "") or "")
        business_binding = str(getattr(move, "odoo_cli_v3_business_binding", "") or "")
        vendor = expected_move_type == "in_invoice"
        journal = getattr(move, "journal_id", None)
        currency = getattr(move, "currency_id", None)
        line_ids = _ids(getattr(move, "line_ids", []))
        failures: list[str] = []

        if expected_move_type not in {"out_invoice", "in_invoice"}:
            failures.append("expected_move_type_not_allowlisted")
        if move_type != expected_move_type:
            failures.append("move_type_mismatch")
        if state != "draft":
            failures.append("move_is_not_draft")
        if getattr(move, "name", None) not in {False, "/"}:
            failures.append("non_pristine_name_or_sequence")
        if getattr(move, "posted_before", None) is not False:
            failures.append("posted_before_not_false")
        if str(getattr(move, "auto_post", "") or "") != "no":
            failures.append("auto_post_not_disabled")
        if getattr(move, "auto_post_until", None) not in {False, None}:
            failures.append("auto_post_until_present")
        if getattr(move, "sequence_prefix", None) not in {False, None, ""}:
            failures.append("sequence_prefix_present")
        if getattr(move, "sequence_number", None) not in {False, 0}:
            failures.append("sequence_number_present")
        if getattr(move, "made_sequence_gap", None) is not False:
            failures.append("sequence_gap_flag_present")
        if getattr(move, "checked", None) is not False:
            failures.append("checked_flag_present")
        if (
            _record_id(journal) is None
            or _record_id(getattr(journal, "company_id", None)) != company_id
            or str(getattr(journal, "type", "") or "") != ("purchase" if vendor else "sale")
            or getattr(journal, "active", True) is False
        ):
            failures.append("journal_not_active_expected_type")
        if not _valid_sha_binding(document_binding):
            failures.append("document_binding_missing_or_invalid")
        if not _valid_sha_binding(business_binding):
            failures.append("business_binding_missing_or_invalid")
        if _record_id(currency) is None:
            failures.append("currency_missing")
        if str(getattr(move, "payment_state", "") or "") != "not_paid":
            failures.append("payment_state_not_not_paid")
        if not _amounts_equal_abs(
            getattr(move, "amount_residual", None), getattr(move, "amount_total", None)
        ):
            failures.append("residual_total_mismatch")
        if (
            getattr(move, "secure_sequence_number", 0) not in {False, 0}
            or bool(getattr(move, "inalterable_hash", False))
            or bool(getattr(move, "need_cancel_request", False))
            or bool(getattr(move, "is_manually_modified", False))
        ):
            failures.append("posting_hash_edi_or_manual_mutation_evidence")

        if _has_draft_cancel_singular_effect_link(move):
            failures.append("singular_external_effect_link_present")
        if _has_draft_cancel_plural_effect_link(move):
            failures.append("plural_external_effect_link_present")
        if (
            bool(getattr(move, "signature", False))
            or bool(getattr(move, "is_move_sent", False))
            or getattr(move, "sending_data", False) not in (False, None, {})
            or bool(getattr(move, "is_being_sent", False))
            or getattr(move, "invoice_source_email", False) not in (False, None, "")
        ):
            failures.append("invoice_sending_signature_or_attachment_effect_present")
        if not line_ids:
            failures.append("line_graph_empty")
        if set(line_ids) != {_record_id(line) for line in lines}:
            failures.append("line_graph_not_complete")

        line_failures = []
        for line in lines:
            line_id = _record_id(line)
            if (
                _record_id(getattr(line, "move_id", None)) != move_id
                or _record_id(getattr(line, "company_id", None)) != company_id
                or str(getattr(line, "parent_state", "") or "") != "draft"
                or bool(getattr(line, "reconciled", False))
                or _record_id(getattr(line, "full_reconcile_id", None)) is not None
                or _ids(getattr(line, "matched_debit_ids", []))
                or _ids(getattr(line, "matched_credit_ids", []))
                or _record_id(getattr(line, "statement_line_id", None)) is not None
                or _record_id(getattr(line, "payment_id", None)) is not None
                or _record_id(getattr(line, "statement_id", None)) is not None
                or _record_id(getattr(line, "purchase_order_id", None)) is not None
                or _record_id(getattr(line, "reconcile_model_id", None)) is not None
                or _ids(getattr(line, "asset_ids", []))
                or _ids(getattr(line, "sale_line_ids", []))
                or _ids(getattr(line, "distribution_analytic_account_ids", []))
                or _ids(getattr(line, "reconciled_lines_ids", []))
                or _ids(getattr(line, "reconciled_lines_excluding_exchange_diff_ids", []))
                or _record_id(getattr(line, "purchase_line_id", None)) is not None
                or _record_id(getattr(line, "expense_id", None)) is not None
                or _record_id(getattr(line, "cogs_origin_id", None)) is not None
                or bool(getattr(line, "is_landed_costs_line", False))
                or _ids(getattr(line, "move_attachment_ids", []))
                or bool(getattr(line, "is_imported", False))
                or bool(getattr(line, "is_downpayment", False))
                or getattr(line, "analytic_distribution", False) not in (False, None, {})
                or _ids(getattr(line, "analytic_line_ids", []))
                or getattr(line, "deferred_start_date", None) not in {None, False}
                or getattr(line, "deferred_end_date", None) not in {None, False}
                or str(getattr(line, "display_type", "") or "") == "cogs"
            ):
                line_failures.append(line_id or 0)
        if line_failures:
            failures.append("line_reconciliation_or_external_effect_present")

        checks = [
            "bound_company_read_acl",
            "single_visible_move",
            "expected_move_type_allowlist",
            "pristine_draft_state_and_sequence",
            "immutable_v3_document_bindings_present",
            "active_sale_or_purchase_journal",
            "fully_unpaid_residual_matches_total",
            "no_payment_reconciliation_tax_asset_or_edi_links",
            "complete_line_guard_graph",
        ]
        eligible = not failures
        write_parameters = (
            {
                "company_id": company_id,
                "move_id": move_id,
                "expected_move_type": expected_move_type,
                "expected_document_binding": document_binding,
                "expected_business_binding": business_binding,
            }
            if eligible
            else None
        )
        return {
            "candidate_write_capability_id": "acct.move.draft_cancel.v1",
            "basis": "odoo_pristine_v3_draft_cancel_eligibility_read",
            "filters": {
                "company_id": company_id,
                "move_id": move_id,
                "expected_move_type": expected_move_type,
            },
            "target": {
                "company_id": company_id,
                "move_id": move_id,
                "move_type": move_type,
                "state": state,
                "payment_state": str(getattr(move, "payment_state", "") or ""),
                "journal_id": _record_id(journal),
                "currency_id": _record_id(currency),
                "line_ids": line_ids,
                "document_binding": document_binding,
                "business_binding": business_binding,
            },
            "eligible": eligible,
            "eligibility_failures": sorted(set(failures)),
            "failed_line_ids": sorted(set(line_failures)),
            "checks": checks,
            "write_parameters": write_parameters,
            "page": {"count": 1, "total_count": 1},
        }

    def _read_handlers(
        self,
    ) -> dict[str, Callable[[RequestContext, dict[str, Any]], dict[str, Any]]]:
        return {
            "acct.registry.list.v1": self._read_registry,
            "acct.gl.trial_balance.v1": self._read_trial_balance,
            "acct.ar.open_items.v1": self._read_ar_open_items,
            "acct.ap.open_items.v1": self._read_ap_open_items,
            "acct.multicurrency.balance_read.v1": self._read_multicurrency_balance,
            "acct.move.draft_cancel_eligibility.v1": self._read_draft_cancel_eligibility,
            "acct.report.financial_read.v1": self._read_financial_report,
            "acct.tax.report_read.v1": self._read_tax_report,
        }

    def __call__(
        self,
        context: RequestContext,
        capability: Capability,
        parameters: dict[str, Any],
        registry_digest: str,
        release_digest: str,
    ) -> dict[str, Any]:
        self._assert_runtime_binding(context)
        registered = self._capability_map.get(capability.id)
        if registered is None or registered.data != capability.data:
            raise OdooExecutionError("read capability is not in the trusted registry")
        handler = self._read_handlers().get(capability.id)
        if handler is None:
            raise OdooExecutionError("read capability has no trusted Odoo handler")
        body = handler(context, parameters)
        receipt = create_read_receipt(
            receipt_id=self._receipt_id_factory(),
            capability_id=capability.id,
            parameters=parameters,
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=registry_digest,
            release_digest=release_digest,
            environment=self._environment,
            capability_channel=self._capability_channel,
            record_count=body["page"]["total_count"],
            observed_at=self._now(),
            key_id=self._receipt_key_id,
            secret=self._receipt_secret,
        )
        return {**body, "receipt": receipt}

    def verify(
        self,
        context: RequestContext,
        capability: Capability,
        parameters: dict[str, Any],
        result: dict[str, Any],
        registry_digest: str,
        release_digest: str,
    ) -> None:
        self._assert_runtime_binding(context)
        body = {key: value for key, value in result.items() if key != "receipt"}
        verify_read_receipt(
            result.get("receipt"),
            capability_id=capability.id,
            parameters=parameters,
            result_body=body,
            auth_token_id=context.auth_token_id,
            principal=context.principal,
            odoo_instance_id=context.odoo_instance_id,
            database_name=context.database_name,
            database_uuid=context.database_uuid,
            company_id=context.company_id,
            user_id=context.user_id,
            registry_digest=registry_digest,
            release_digest=release_digest,
            environment=self._environment,
            capability_channel=self._capability_channel,
            expected_record_count=body["page"]["total_count"],
            now=self._now(),
            consume_receipt=self._consume_receipt,
            expected_key_id=self._receipt_key_id,
            secret=self._receipt_secret,
        )

"""Versioned immutable bindings for invoice, bill, and refund documents."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import re
from typing import Any, Mapping

from .operations import canonical_json


DOCUMENT_BINDING_DOMAIN_V2 = "odoo_accounting_cli_v3.document_binding"
DOCUMENT_BINDING_VERSION_V2 = 2
FULL_REFUND_LINE_REFERENCE_PREFIX = "rf-full"

_SUPPORTED_KINDS = frozenset(
    {"customer_invoice", "vendor_bill", "refund"}
)
_UNSIGNED_DECIMAL = re.compile(
    r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?"
)


class DocumentBindingError(ValueError):
    """The supplied document cannot produce a canonical binding."""


def full_refund_line_reference(
    origin_move_id: int,
    origin_line_id: int,
) -> str:
    """Return the deterministic lineage reference for a full refund line."""

    if (
        isinstance(origin_move_id, bool)
        or not isinstance(origin_move_id, int)
        or origin_move_id <= 0
        or isinstance(origin_line_id, bool)
        or not isinstance(origin_line_id, int)
        or origin_line_id <= 0
    ):
        raise DocumentBindingError(
            "full refund origin move and line IDs must be positive integers"
        )
    reference = (
        f"{FULL_REFUND_LINE_REFERENCE_PREFIX}-"
        f"{origin_move_id}-{origin_line_id}"
    )
    if len(reference) > 128:
        raise DocumentBindingError(
            "full refund line reference exceeds the contract limit"
        )
    return reference


def legacy_document_binding_v1(
    kind: str,
    parameters: Mapping[str, Any],
) -> str:
    """Reproduce the legacy V1 document digest without normalization."""

    payload = {
        "capability_kind": kind,
        "parameters": {
            key: parameters[key]
            for key in sorted(parameters)
            if key != "idempotency_key"
        },
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _required(
    value: Mapping[str, Any],
    field: str,
    *,
    context: str,
) -> Any:
    try:
        return value[field]
    except KeyError as exc:
        raise DocumentBindingError(
            f"{context}.{field} is required"
        ) from exc


def _canonical_decimal(
    value: Any,
    field: str,
    *,
    positive: bool,
) -> str:
    if (
        not isinstance(value, str)
        or _UNSIGNED_DECIMAL.fullmatch(value) is None
    ):
        raise DocumentBindingError(
            f"{field} must be a canonical unsigned decimal string"
        )
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise DocumentBindingError(
            f"{field} must be a finite decimal"
        ) from exc
    if not parsed.is_finite() or parsed < 0:
        raise DocumentBindingError(
            f"{field} must be a finite nonnegative decimal"
        )
    if positive and parsed <= 0:
        raise DocumentBindingError(f"{field} must be positive")
    normalized = format(parsed, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    return "0" if normalized in {"", "-0"} else normalized


def _canonical_tax_ids(value: Any, field: str) -> list[int]:
    if not isinstance(value, list):
        raise DocumentBindingError(f"{field} must be an array")
    result: list[int] = []
    for tax_id in value:
        if (
            isinstance(tax_id, bool)
            or not isinstance(tax_id, int)
            or tax_id <= 0
        ):
            raise DocumentBindingError(
                f"{field} must contain positive integer tax IDs"
            )
        result.append(tax_id)
    if len(result) != len(set(result)):
        raise DocumentBindingError(
            f"{field} must not contain duplicate tax IDs"
        )
    return sorted(result)


def _canonical_lines(
    value: Any,
    *,
    kind: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise DocumentBindingError("parameters.lines must be an array")
    if kind in {"customer_invoice", "vendor_bill"} and not value:
        raise DocumentBindingError(
            f"{kind} parameters.lines must not be empty"
        )

    result: list[dict[str, Any]] = []
    references: set[str] = set()
    for index, raw_line in enumerate(value):
        if not isinstance(raw_line, Mapping):
            raise DocumentBindingError(
                f"parameters.lines[{index}] must be an object"
            )
        context = f"parameters.lines[{index}]"
        reference = _required(
            raw_line,
            "line_reference",
            context=context,
        )
        if not isinstance(reference, str) or not reference:
            raise DocumentBindingError(
                f"{context}.line_reference must be non-empty text"
            )
        if reference in references:
            raise DocumentBindingError(
                "parameters.lines must not contain duplicate "
                "line_reference values"
            )
        references.add(reference)

        line = dict(raw_line)
        line["quantity"] = _canonical_decimal(
            _required(raw_line, "quantity", context=context),
            f"{context}.quantity",
            positive=True,
        )
        line["price_unit"] = _canonical_decimal(
            _required(raw_line, "price_unit", context=context),
            f"{context}.price_unit",
            positive=False,
        )
        line["tax_ids"] = _canonical_tax_ids(
            _required(raw_line, "tax_ids", context=context),
            f"{context}.tax_ids",
        )
        result.append(line)

    result.sort(key=lambda line: line["line_reference"])
    return result


def canonical_document_payload_v2(
    kind: str,
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the versioned canonical payload included in a V2 digest."""

    if kind not in _SUPPORTED_KINDS:
        raise DocumentBindingError(
            f"unsupported document binding kind: {kind}"
        )
    if not isinstance(parameters, Mapping):
        raise DocumentBindingError("parameters must be an object")

    normalized = {
        key: parameters[key]
        for key in sorted(parameters)
        if key != "idempotency_key"
    }
    lines = _canonical_lines(
        _required(parameters, "lines", context="parameters"),
        kind=kind,
    )
    normalized["lines"] = lines

    if kind == "refund":
        normalized["expected_total_amount"] = _canonical_decimal(
            _required(
                parameters,
                "expected_total_amount",
                context="parameters",
            ),
            "parameters.expected_total_amount",
            positive=True,
        )
        refund_mode = _required(
            parameters,
            "refund_mode",
            context="parameters",
        )
        if refund_mode == "full" and lines:
            raise DocumentBindingError(
                "full refund parameters.lines must be empty"
            )
        if refund_mode == "partial" and not lines:
            raise DocumentBindingError(
                "partial refund parameters.lines must not be empty"
            )
        if refund_mode not in {"full", "partial"}:
            raise DocumentBindingError(
                "parameters.refund_mode must be full or partial"
            )

    return {
        "domain": DOCUMENT_BINDING_DOMAIN_V2,
        "version": DOCUMENT_BINDING_VERSION_V2,
        "capability_kind": kind,
        "parameters": normalized,
    }


def canonical_document_binding_v2(
    kind: str,
    parameters: Mapping[str, Any],
) -> str:
    """Return the SHA-256 digest of a canonical V2 document payload."""

    payload = canonical_document_payload_v2(kind, parameters)
    try:
        encoded = canonical_json(payload)
    except (TypeError, ValueError) as exc:
        raise DocumentBindingError(
            "document parameters are not canonical JSON"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def customer_invoice_document_binding_v2(
    parameters: Mapping[str, Any],
) -> str:
    return canonical_document_binding_v2(
        "customer_invoice",
        parameters,
    )


def vendor_bill_document_binding_v2(
    parameters: Mapping[str, Any],
) -> str:
    return canonical_document_binding_v2("vendor_bill", parameters)


def refund_document_binding_v2(
    parameters: Mapping[str, Any],
) -> str:
    return canonical_document_binding_v2("refund", parameters)

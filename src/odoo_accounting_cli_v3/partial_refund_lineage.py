"""Strict, side-effect-free partial-refund line lineage oracle."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class PartialRefundLine:
    """The immutable identity and financial bounds used by the lineage oracle."""

    line_reference: str
    name: str
    account_id: int
    partner_id: int
    currency_id: int
    product_id: int | None
    tax_ids: tuple[int, ...]
    tax_line_id: int | None
    quantity: Decimal
    price_subtotal: Decimal
    price_total: Decimal


def _required_id(value: Any) -> int | None:
    raw = getattr(value, "id", value)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        return None
    return raw


def _optional_id(value: Any) -> int | None:
    if value is False or value is None:
        return None
    return _required_id(value)


def _many_ids(value: Any) -> tuple[int, ...] | None:
    if value is False or value is None:
        return ()
    raw = getattr(value, "ids", value)
    if not isinstance(raw, (list, tuple, set, frozenset)):
        raw = [raw]
    result: list[int] = []
    for item in raw:
        record_id = _required_id(item)
        if record_id is None:
            return None
        result.append(record_id)
    if len(result) != len(set(result)):
        return None
    return tuple(sorted(result))


def _decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool) or value is None or value == "":
        return None
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    return result if result.is_finite() else None


def partial_refund_line_from_odoo(line: Any) -> PartialRefundLine | None:
    """Normalize one Odoo invoice line without guessing absent identity."""

    reference = getattr(line, "odoo_cli_v3_line_reference", None)
    name = getattr(line, "name", None)
    account_id = _required_id(getattr(line, "account_id", None))
    partner_id = _required_id(getattr(line, "partner_id", None))
    currency_id = _required_id(getattr(line, "currency_id", None))
    product_value = getattr(line, "product_id", None)
    product_id = _optional_id(product_value)
    tax_ids = _many_ids(getattr(line, "tax_ids", None))
    tax_line_value = getattr(line, "tax_line_id", None)
    tax_line_id = _optional_id(tax_line_value)
    quantity = _decimal(getattr(line, "quantity", None))
    price_subtotal = _decimal(getattr(line, "price_subtotal", None))
    price_total = _decimal(getattr(line, "price_total", None))
    if (
        not isinstance(reference, str)
        or not reference
        or not isinstance(name, str)
        or not name
        or account_id is None
        or partner_id is None
        or currency_id is None
        or (
            not (product_value is False or product_value is None)
            and product_id is None
        )
        or tax_ids is None
        or (
            not (tax_line_value is False or tax_line_value is None)
            and tax_line_id is None
        )
        or quantity is None
        or price_subtotal is None
        or price_total is None
    ):
        return None
    return PartialRefundLine(
        line_reference=reference,
        name=name,
        account_id=account_id,
        partner_id=partner_id,
        currency_id=currency_id,
        product_id=product_id,
        tax_ids=tax_ids,
        tax_line_id=tax_line_id,
        quantity=quantity,
        price_subtotal=price_subtotal,
        price_total=price_total,
    )


def partial_refund_line_from_approved(
    line: Mapping[str, Any],
    *,
    partner_id: int,
    currency_id: int,
    price_subtotal: Any,
    price_total: Any,
) -> PartialRefundLine | None:
    """Normalize one approved refund line and its trusted financial preview."""

    reference = line.get("line_reference")
    name = line.get("name")
    account_id = _required_id(line.get("account_id"))
    approved_partner_id = _required_id(partner_id)
    approved_currency_id = _required_id(currency_id)
    product_value = line.get("product_id")
    product_id = _optional_id(product_value)
    tax_ids = _many_ids(line.get("tax_ids"))
    quantity = _decimal(line.get("quantity"))
    subtotal = _decimal(price_subtotal)
    total = _decimal(price_total)
    if (
        not isinstance(reference, str)
        or not reference
        or not isinstance(name, str)
        or not name
        or account_id is None
        or approved_partner_id is None
        or approved_currency_id is None
        or (
            not (product_value is False or product_value is None)
            and product_id is None
        )
        or tax_ids is None
        or quantity is None
        or subtotal is None
        or total is None
    ):
        return None
    return PartialRefundLine(
        line_reference=reference,
        name=name,
        account_id=account_id,
        partner_id=approved_partner_id,
        currency_id=approved_currency_id,
        product_id=product_id,
        tax_ids=tax_ids,
        tax_line_id=None,
        quantity=quantity,
        price_subtotal=subtotal,
        price_total=total,
    )


def partial_refund_origin_line_relation_is_exact(
    origin_lines: Iterable[PartialRefundLine | None],
    refund_lines: Iterable[PartialRefundLine | None],
) -> bool:
    """Return whether every refund line maps once within one exact origin line."""

    origins = list(origin_lines)
    refunds = list(refund_lines)
    if (
        not origins
        or not refunds
        or any(line is None for line in origins)
        or any(line is None for line in refunds)
    ):
        return False
    typed_origins = [line for line in origins if line is not None]
    typed_refunds = [line for line in refunds if line is not None]
    origin_by_reference = {
        line.line_reference: line for line in typed_origins
    }
    if len(origin_by_reference) != len(typed_origins):
        return False
    refund_references = [
        line.line_reference for line in typed_refunds
    ]
    if len(refund_references) != len(set(refund_references)):
        return False
    for refund in typed_refunds:
        origin = origin_by_reference.get(refund.line_reference)
        if (
            origin is None
            or (
                refund.name,
                refund.account_id,
                refund.partner_id,
                refund.currency_id,
                refund.product_id,
                refund.tax_ids,
                refund.tax_line_id,
            )
            != (
                origin.name,
                origin.account_id,
                origin.partner_id,
                origin.currency_id,
                origin.product_id,
                origin.tax_ids,
                origin.tax_line_id,
            )
            or origin.quantity <= 0
            or origin.price_subtotal < 0
            or origin.price_total < 0
            or refund.quantity <= 0
            or refund.price_subtotal < 0
            or refund.price_total < 0
            or refund.quantity > origin.quantity
            or refund.price_subtotal > origin.price_subtotal
            or refund.price_total > origin.price_total
        ):
            return False
    return True

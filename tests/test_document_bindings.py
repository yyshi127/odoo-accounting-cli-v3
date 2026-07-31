from __future__ import annotations

import copy

import pytest

from odoo_accounting_cli_v3.document_bindings import (
    DOCUMENT_BINDING_DOMAIN_V2,
    DOCUMENT_BINDING_VERSION_V2,
    DocumentBindingError,
    canonical_document_binding_v2,
    canonical_document_payload_v2,
    full_refund_line_reference,
    legacy_document_binding_v1,
)
from odoo_accounting_cli_v3.draft_invoice_recovery import (
    customer_invoice_document_binding,
    customer_invoice_document_binding_v2,
    vendor_bill_document_binding,
    vendor_bill_document_binding_v2,
)


def _line(
    reference: str,
    *,
    quantity: str,
    price_unit: str,
    tax_ids: list[int],
    product_id: int | None = 202,
) -> dict[str, object]:
    result: dict[str, object] = {
        "line_reference": reference,
        "name": f"Service {reference}",
        "account_id": 401 if reference == "line-a" else 402,
        "quantity": quantity,
        "price_unit": price_unit,
        "tax_ids": tax_ids,
    }
    if product_id is not ...:
        result["product_id"] = product_id
    return result


def _parameters(
    kind: str,
    *,
    quantity: str = "1",
    price_unit: str = "100",
    expected_total_amount: str = "100",
    reverse_lines: bool = False,
    reverse_taxes: bool = False,
) -> dict[str, object]:
    taxes = [9, 3] if not reverse_taxes else [3, 9]
    second_taxes = [7, 5] if not reverse_taxes else [5, 7]
    product_id: int | None | type[Ellipsis] = (
        ...
        if kind == "refund"
        else 202
    )
    lines = [
        _line(
            "line-a",
            quantity=quantity,
            price_unit=price_unit,
            tax_ids=taxes,
            product_id=product_id,
        ),
        _line(
            "line-b",
            quantity="2",
            price_unit="50",
            tax_ids=second_taxes,
            product_id=(
                ...
                if kind == "refund"
                else None
            ),
        ),
    ]
    if reverse_lines:
        lines.reverse()

    common: dict[str, object] = {
        "company_id": 7,
        "currency_id": 12,
        "journal_id": 5,
        "posting_mode": "draft",
        "lines": lines,
        "idempotency_key": f"idem-{kind}",
    }
    if kind == "customer_invoice":
        return {
            **common,
            "partner_id": 101,
            "invoice_date": "2026-07-15",
            "accounting_date": "2026-07-15",
            "due_date": "2026-08-15",
            "reference": "INV-V2-1",
        }
    if kind == "vendor_bill":
        return {
            **common,
            "partner_id": 101,
            "invoice_date": "2026-07-15",
            "accounting_date": "2026-07-15",
            "due_date": "2026-08-15",
            "vendor_reference": "BILL-V2-1",
        }
    if kind == "refund":
        return {
            **common,
            "origin_move_id": 501,
            "refund_type": "customer_credit_note",
            "refund_mode": "partial",
            "refund_date": "2026-07-16",
            "expected_total_amount": expected_total_amount,
            "reason": "Approved refund",
        }
    raise AssertionError(kind)


@pytest.mark.parametrize(
    "kind",
    ["customer_invoice", "vendor_bill", "refund"],
)
def test_v2_payload_explicitly_binds_domain_and_version(
    kind: str,
) -> None:
    payload = canonical_document_payload_v2(
        kind,
        _parameters(kind),
    )

    assert payload["domain"] == DOCUMENT_BINDING_DOMAIN_V2
    assert payload["version"] == DOCUMENT_BINDING_VERSION_V2 == 2
    assert payload["capability_kind"] == kind
    assert "idempotency_key" not in payload["parameters"]


@pytest.mark.parametrize(
    "kind",
    ["customer_invoice", "vendor_bill", "refund"],
)
def test_v2_normalizes_decimal_tax_and_line_order(
    kind: str,
) -> None:
    whole = _parameters(kind)
    decimal = _parameters(
        kind,
        quantity="1.0",
        price_unit="100.00",
        expected_total_amount="100.0",
        reverse_lines=True,
        reverse_taxes=True,
    )
    more_decimal = _parameters(
        kind,
        quantity="1.00",
        price_unit="100.0",
        expected_total_amount="100.00",
    )

    expected = canonical_document_binding_v2(kind, whole)
    assert canonical_document_binding_v2(kind, decimal) == expected
    assert canonical_document_binding_v2(
        kind,
        more_decimal,
    ) == expected

    changed_idempotency = copy.deepcopy(whole)
    changed_idempotency["idempotency_key"] = "different-retry"
    assert (
        canonical_document_binding_v2(kind, changed_idempotency)
        == expected
    )


def test_v2_does_not_round_distinct_long_decimal_inputs() -> None:
    first = _parameters(
        "customer_invoice",
        price_unit="12345678901234567890123456780",
    )
    second = _parameters(
        "customer_invoice",
        price_unit="12345678901234567890123456781",
    )

    assert canonical_document_binding_v2(
        "customer_invoice",
        first,
    ) != canonical_document_binding_v2(
        "customer_invoice",
        second,
    )


def test_full_refund_line_reference_is_deterministic_and_bounded() -> None:
    assert full_refund_line_reference(501, 701) == "rf-full-501-701"

    for invalid in (False, 0, -1, "1"):
        with pytest.raises(DocumentBindingError, match="positive integers"):
            full_refund_line_reference(invalid, 701)
        with pytest.raises(DocumentBindingError, match="positive integers"):
            full_refund_line_reference(501, invalid)


@pytest.mark.parametrize(
    "kind",
    ["customer_invoice", "vendor_bill", "refund"],
)
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("price_unit", "101"),
        ("account_id", 999),
        ("name", "Different service"),
    ],
)
def test_v2_preserves_real_financial_and_text_differences(
    kind: str,
    field: str,
    value: object,
) -> None:
    original = _parameters(kind)
    changed = copy.deepcopy(original)
    changed["lines"][0][field] = value

    assert canonical_document_binding_v2(
        kind,
        changed,
    ) != canonical_document_binding_v2(kind, original)


@pytest.mark.parametrize(
    "kind",
    ["customer_invoice", "vendor_bill"],
)
def test_v2_preserves_product_differences(kind: str) -> None:
    original = _parameters(kind)
    changed = copy.deepcopy(original)
    changed["lines"][0]["product_id"] = 303

    assert canonical_document_binding_v2(
        kind,
        changed,
    ) != canonical_document_binding_v2(kind, original)


@pytest.mark.parametrize(
    "kind",
    ["customer_invoice", "vendor_bill", "refund"],
)
def test_v2_rejects_duplicate_tax_ids(kind: str) -> None:
    parameters = _parameters(kind)
    parameters["lines"][0]["tax_ids"] = [3, 3]

    with pytest.raises(
        DocumentBindingError,
        match="duplicate tax IDs",
    ):
        canonical_document_binding_v2(kind, parameters)


@pytest.mark.parametrize(
    "kind",
    ["customer_invoice", "vendor_bill", "refund"],
)
def test_v2_rejects_duplicate_line_references(kind: str) -> None:
    parameters = _parameters(kind)
    parameters["lines"][1]["line_reference"] = "line-a"

    with pytest.raises(
        DocumentBindingError,
        match="duplicate line_reference",
    ):
        canonical_document_binding_v2(kind, parameters)


@pytest.mark.parametrize(
    "invalid",
    ["NaN", "Infinity", "-1", 100.0],
)
def test_v2_rejects_non_contract_decimal_values(
    invalid: object,
) -> None:
    parameters = _parameters("customer_invoice")
    parameters["lines"][0]["price_unit"] = invalid

    with pytest.raises(DocumentBindingError, match="decimal"):
        canonical_document_binding_v2(
            "customer_invoice",
            parameters,
        )


def test_v2_requires_positive_quantity_and_refund_total() -> None:
    invoice = _parameters("customer_invoice")
    invoice["lines"][0]["quantity"] = "0"
    with pytest.raises(DocumentBindingError, match="must be positive"):
        canonical_document_binding_v2("customer_invoice", invoice)

    refund = _parameters("refund")
    refund["expected_total_amount"] = "0"
    with pytest.raises(DocumentBindingError, match="must be positive"):
        canonical_document_binding_v2("refund", refund)


def test_v2_wrappers_cover_invoice_bill_and_refund() -> None:
    customer = _parameters("customer_invoice")
    vendor = _parameters("vendor_bill")
    refund = _parameters("refund")

    assert customer_invoice_document_binding_v2(
        customer
    ) == canonical_document_binding_v2(
        "customer_invoice",
        customer,
    )
    assert vendor_bill_document_binding_v2(
        vendor
    ) == canonical_document_binding_v2(
        "vendor_bill",
        vendor,
    )
    assert canonical_document_binding_v2("refund", refund)


def test_v1_hashes_are_unchanged_and_remain_lexical_and_order_sensitive() -> None:
    customer = _parameters(
        "customer_invoice",
        quantity="1.0",
        price_unit="100.0",
    )
    vendor = _parameters(
        "vendor_bill",
        quantity="1.0",
        price_unit="100.0",
    )
    refund = _parameters(
        "refund",
        quantity="1.0",
        price_unit="100.0",
        expected_total_amount="100.00",
    )

    assert customer_invoice_document_binding(customer) == (
        "cf1eaa10925cd59f8fc39c5350c5ac5ce3c5ab345cf623b9630b0acac9f823f1"
    )
    assert vendor_bill_document_binding(vendor) == (
        "e91080be5f3067937f2ee86280e84d4c5fbeb68d89dd9174a847b37c3c7d5f87"
    )
    assert legacy_document_binding_v1("refund", refund) == (
        "74164f4b4f76e400ce848e462ce07430d0bae0012e5c3655ce9844573fc675b0"
    )

    for kind, parameters in (
        ("customer_invoice", customer),
        ("vendor_bill", vendor),
        ("refund", refund),
    ):
        legacy = legacy_document_binding_v1(kind, parameters)
        lexical = copy.deepcopy(parameters)
        lexical["lines"][0]["price_unit"] = "100.00"
        assert legacy_document_binding_v1(kind, lexical) != legacy

        tax_order = copy.deepcopy(parameters)
        tax_order["lines"][0]["tax_ids"].reverse()
        assert legacy_document_binding_v1(kind, tax_order) != legacy

        line_order = copy.deepcopy(parameters)
        line_order["lines"].reverse()
        assert legacy_document_binding_v1(kind, line_order) != legacy

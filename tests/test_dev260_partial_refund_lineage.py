from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3.partial_refund_lineage import (
    PartialRefundLine,
    partial_refund_line_from_odoo,
    partial_refund_origin_line_relation_is_exact,
)


def lineage_line(**changes):
    values = {
        "line_reference": "origin-line-1",
        "name": "Consulting",
        "account_id": 6601,
        "partner_id": 6301,
        "currency_id": 12,
        "product_id": None,
        "tax_ids": (),
        "tax_line_id": None,
        "quantity": Decimal("2"),
        "price_subtotal": Decimal("100"),
        "price_total": Decimal("100"),
    }
    values.update(changes)
    return PartialRefundLine(**values)


def test_partial_refund_lineage_accepts_one_exact_bounded_mapping():
    origin = lineage_line()
    refund = lineage_line(
        quantity=Decimal("1"),
        price_subtotal=Decimal("40"),
        price_total=Decimal("40"),
    )

    assert partial_refund_origin_line_relation_is_exact(
        [origin], [refund]
    )


def test_partial_refund_lineage_rejects_nonexistent_line_reference():
    origin = lineage_line()
    refund = replace(
        lineage_line(quantity=Decimal("1")),
        line_reference="missing-origin-line",
    )

    assert not partial_refund_origin_line_relation_is_exact(
        [origin], [refund]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("account_id", 6602),
        ("partner_id", 6302),
        ("currency_id", 13),
        ("product_id", 6350),
        ("tax_ids", (6701,)),
    ),
)
def test_partial_refund_lineage_rejects_identity_mismatch(field, value):
    origin = lineage_line()
    refund = replace(
        lineage_line(
            quantity=Decimal("1"),
            price_subtotal=Decimal("40"),
            price_total=Decimal("40"),
        ),
        **{field: value},
    )

    assert not partial_refund_origin_line_relation_is_exact(
        [origin], [refund]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("quantity", Decimal("2.01")),
        ("price_subtotal", Decimal("100.01")),
        ("price_total", Decimal("100.01")),
    ),
)
def test_partial_refund_lineage_rejects_each_per_line_overrun(
    field, value
):
    origin = lineage_line()
    refund = replace(lineage_line(), **{field: value})

    assert not partial_refund_origin_line_relation_is_exact(
        [origin], [refund]
    )


def test_partial_refund_lineage_rejects_duplicate_mapping():
    origin = lineage_line()
    first = lineage_line(
        quantity=Decimal("0.5"),
        price_subtotal=Decimal("20"),
        price_total=Decimal("20"),
    )
    second = replace(first, quantity=Decimal("0.25"))

    assert not partial_refund_origin_line_relation_is_exact(
        [origin], [first, second]
    )


def test_partial_refund_odoo_normalizer_does_not_guess_missing_identity():
    exact = SimpleNamespace(
        odoo_cli_v3_line_reference="origin-line-1",
        name="Consulting",
        account_id=SimpleNamespace(id=6601),
        partner_id=SimpleNamespace(id=6301),
        currency_id=SimpleNamespace(id=12),
        product_id=False,
        tax_ids=[],
        tax_line_id=False,
        quantity="1",
        price_subtotal="40",
        price_total="40",
    )

    assert partial_refund_line_from_odoo(exact) == lineage_line(
        quantity=Decimal("1"),
        price_subtotal=Decimal("40"),
        price_total=Decimal("40"),
    )
    exact.partner_id = False
    assert partial_refund_line_from_odoo(exact) is None

"""Historical accounts-payable open items using the shared residual engine."""

from __future__ import annotations

from typing import Any

from .ar_open_items import (
    ArOpenItemsBackend,
    CurrencyInfo,
    OpenItemPartial,
    OpenItemSource,
    OpenItemsError,
    read_ar_open_items,
)


ApOpenItemsBackend = ArOpenItemsBackend


def read_ap_open_items(
    backend: ApOpenItemsBackend,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Return payable open items with the shared historical residual rules."""

    return read_ar_open_items(backend, parameters)


__all__ = [
    "ApOpenItemsBackend",
    "CurrencyInfo",
    "OpenItemPartial",
    "OpenItemSource",
    "OpenItemsError",
    "read_ap_open_items",
]

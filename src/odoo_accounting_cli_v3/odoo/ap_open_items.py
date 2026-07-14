"""Odoo 19 backend for historical accounts-payable open items."""

from __future__ import annotations

from .ar_open_items import OdooArOpenItemsBackend


class OdooApOpenItemsBackend(OdooArOpenItemsBackend):
    ACCOUNT_TYPE = "liability_payable"

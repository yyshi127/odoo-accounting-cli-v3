"""Pure protocol bindings for the one allowlisted draft-invoice recovery."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .operations import canonical_json


DRAFT_CUSTOMER_INVOICE_RECOVERY_METHOD = (
    "cancel_pristine_v3_draft_customer_invoice_v1"
)
DRAFT_CUSTOMER_INVOICE_RECOVERY_ORACLE = (
    "cancel_pristine_v3_draft_customer_invoice_exact_v1"
)


def classic_read_many2one_id(value: Any) -> int | None:
    """Parse only the `_primitive(read())` shape produced by Odoo 19."""

    if (
        not isinstance(value, list)
        or len(value) != 2
        or isinstance(value[0], bool)
        or not isinstance(value[0], int)
        or value[0] <= 0
        or not isinstance(value[1], str)
    ):
        return None
    return value[0]


def customer_invoice_document_binding(parameters: Mapping[str, Any]) -> str:
    payload = {
        "capability_kind": "customer_invoice",
        "parameters": {
            key: parameters[key]
            for key in sorted(parameters)
            if key != "idempotency_key"
        },
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def customer_invoice_business_binding(parameters: Mapping[str, Any]) -> str:
    payload = {
        "business_kind": "customer_invoice",
        "identity": {"reference": parameters["reference"]},
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()

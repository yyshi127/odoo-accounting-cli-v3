"""Atomic partner-rank handling for the controlled refund-post workflow."""

from odoo import models
from odoo.exceptions import AccessError, ValidationError

from .execution_scope import _v3_execution_scope_is_active


_CAPABILITY_ID = "acct.refund.post_reconcile_origin.v1"
_CAPABILITY_CONTEXT = "odoo_accounting_cli_v3_rank_capability_id"
_FIELD_CONTEXT = "odoo_accounting_cli_v3_rank_field"
_PARTNER_IDS_CONTEXT = "odoo_accounting_cli_v3_rank_partner_ids"
_EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"


class ResPartner(models.Model):
    _inherit = "res.partner"

    def _increase_rank(self, field, n=1):
        if (
            self.env.context.get(_CAPABILITY_CONTEXT) != _CAPABILITY_ID
            or not _v3_execution_scope_is_active()
        ):
            return super()._increase_rank(field, n)
        expected_field = self.env.context.get(_FIELD_CONTEXT)
        expected_partner_ids = self.env.context.get(_PARTNER_IDS_CONTEXT)
        if (
            self.env.su
            or not self.env.user.has_group(_EXECUTOR_GROUP)
        ):
            raise AccessError(
                "synchronous refund rank updates require a trusted V3 executor"
            )
        if (
            expected_field not in {"customer_rank", "supplier_rank"}
            or field != expected_field
            or type(n) is not int
            or n != 1
            or type(expected_partner_ids) is not tuple
            or not expected_partner_ids
            or any(
                type(partner_id) is not int or partner_id <= 0
                for partner_id in expected_partner_ids
            )
            or expected_partner_ids != tuple(sorted(set(expected_partner_ids)))
            or tuple(sorted(self.ids)) != expected_partner_ids
        ):
            raise ValidationError(
                "synchronous refund rank binding differs from the approved graph"
            )
        for partner in self.sudo():
            partner[field] += n

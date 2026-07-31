import re

from odoo import api, fields, models
from odoo.exceptions import ValidationError

from .execution_scope import _accounting_metadata_write_is_allowed


_SHA256 = re.compile(r"[0-9a-f]{64}")
_ACCOUNT_MOVE_METADATA_FIELDS = frozenset(
    {
        "odoo_cli_v3_reason",
        "odoo_cli_v3_period_end_date",
        "odoo_cli_v3_document_binding",
        "odoo_cli_v3_document_binding_v2",
        "odoo_cli_v3_business_binding",
    }
)
_ACCOUNT_MOVE_LINE_METADATA_FIELDS = frozenset({"odoo_cli_v3_line_reference"})
_ACCOUNT_PAYMENT_METADATA_FIELDS = frozenset({"odoo_cli_v3_payment_binding"})
_BANK_STATEMENT_METADATA_FIELDS = frozenset(
    {
        "odoo_cli_v3_external_reference",
        "odoo_cli_v3_source_digest",
        "odoo_cli_v3_source_filename",
    }
)
_BANK_STATEMENT_LINE_METADATA_FIELDS = frozenset(
    {
        "odoo_cli_v3_external_transaction_id",
        "odoo_cli_v3_source_line_digest",
        "odoo_cli_v3_value_date",
    }
)


def _reject_untrusted_metadata_values(values, field_names):
    if not set(values).isdisjoint(field_names) and not (
        _accounting_metadata_write_is_allowed()
    ):
        raise ValidationError(
            "V3 accounting metadata requires a trusted V3 execution scope"
        )


def _reject_untrusted_created_metadata(records, field_names):
    if _accounting_metadata_write_is_allowed():
        return
    if any(record[field_name] for record in records for field_name in field_names):
        raise ValidationError(
            "V3 accounting metadata requires a trusted V3 execution scope"
        )


def _reject_changed_metadata(records, values, field_names, message):
    for field_name in field_names:
        if field_name in values and any(record[field_name] for record in records):
            raise ValidationError(message)


class AccountMove(models.Model):
    _inherit = "account.move"

    odoo_cli_v3_reason = fields.Char(copy=False, index=True)
    odoo_cli_v3_period_end_date = fields.Date(copy=False, index=True)
    odoo_cli_v3_document_binding = fields.Char(
        copy=False, index=True, readonly=True, size=64
    )
    odoo_cli_v3_document_binding_v2 = fields.Char(
        copy=False, index=True, readonly=True, size=64
    )
    odoo_cli_v3_business_binding = fields.Char(
        copy=False, index=True, readonly=True, size=64
    )

    _odoo_cli_v3_document_binding_unique = models.Constraint(
        "UNIQUE(company_id, move_type, odoo_cli_v3_document_binding)",
        "The V3 accounting document identity already exists in this company.",
    )
    _odoo_cli_v3_document_binding_v2_unique = models.Constraint(
        "UNIQUE(company_id, move_type, odoo_cli_v3_document_binding_v2)",
        "The V3 accounting document V2 identity already exists in this company.",
    )
    _odoo_cli_v3_business_binding_unique = models.Constraint(
        "UNIQUE(company_id, move_type, odoo_cli_v3_business_binding)",
        "The V3 accounting business identity already exists in this company.",
    )

    @api.constrains("odoo_cli_v3_document_binding")
    def _check_odoo_cli_v3_document_binding(self):
        for move in self:
            digest = move.odoo_cli_v3_document_binding
            if digest and _SHA256.fullmatch(digest) is None:
                raise ValidationError(
                    "document binding must be lowercase SHA-256"
                )

    @api.constrains("odoo_cli_v3_document_binding_v2")
    def _check_odoo_cli_v3_document_binding_v2(self):
        for move in self:
            digest = move.odoo_cli_v3_document_binding_v2
            if digest and _SHA256.fullmatch(digest) is None:
                raise ValidationError(
                    "document binding V2 must be lowercase SHA-256"
                )

    @api.constrains("odoo_cli_v3_business_binding")
    def _check_odoo_cli_v3_business_binding(self):
        for move in self:
            digest = move.odoo_cli_v3_business_binding
            if digest and _SHA256.fullmatch(digest) is None:
                raise ValidationError(
                    "business binding must be lowercase SHA-256"
                )

    @api.model_create_multi
    def create(self, values_list):
        for values in values_list:
            _reject_untrusted_metadata_values(values, _ACCOUNT_MOVE_METADATA_FIELDS)
        records = super().create(values_list)
        _reject_untrusted_created_metadata(records, _ACCOUNT_MOVE_METADATA_FIELDS)
        return records

    def write(self, values):
        _reject_untrusted_metadata_values(values, _ACCOUNT_MOVE_METADATA_FIELDS)
        _reject_changed_metadata(
            self,
            values,
            _ACCOUNT_MOVE_METADATA_FIELDS,
            "accounting move metadata fields are immutable",
        )
        return super().write(values)


class AccountMoveLine(models.Model):
    _inherit = "account.move.line"

    odoo_cli_v3_line_reference = fields.Char(copy=False, index=True)

    @api.model_create_multi
    def create(self, values_list):
        for values in values_list:
            _reject_untrusted_metadata_values(
                values, _ACCOUNT_MOVE_LINE_METADATA_FIELDS
            )
        records = super().create(values_list)
        _reject_untrusted_created_metadata(
            records, _ACCOUNT_MOVE_LINE_METADATA_FIELDS
        )
        return records

    def write(self, values):
        _reject_untrusted_metadata_values(
            values, _ACCOUNT_MOVE_LINE_METADATA_FIELDS
        )
        _reject_changed_metadata(
            self,
            values,
            _ACCOUNT_MOVE_LINE_METADATA_FIELDS,
            "accounting line metadata fields are immutable",
        )
        return super().write(values)


class AccountPayment(models.Model):
    _inherit = "account.payment"

    odoo_cli_v3_payment_binding = fields.Json(copy=False)

    @api.model_create_multi
    def create(self, values_list):
        for values in values_list:
            _reject_untrusted_metadata_values(values, _ACCOUNT_PAYMENT_METADATA_FIELDS)
        records = super().create(values_list)
        _reject_untrusted_created_metadata(records, _ACCOUNT_PAYMENT_METADATA_FIELDS)
        return records

    def write(self, values):
        _reject_untrusted_metadata_values(values, _ACCOUNT_PAYMENT_METADATA_FIELDS)
        _reject_changed_metadata(
            self,
            values,
            _ACCOUNT_PAYMENT_METADATA_FIELDS,
            "payment binding is immutable",
        )
        return super().write(values)


class AccountBankStatement(models.Model):
    _inherit = "account.bank.statement"

    odoo_cli_v3_external_reference = fields.Char(
        copy=False, index=True, readonly=True, size=255
    )
    odoo_cli_v3_source_digest = fields.Char(
        copy=False, index=True, readonly=True, size=64
    )
    odoo_cli_v3_source_filename = fields.Char(
        copy=False, readonly=True, size=255
    )

    _odoo_cli_v3_external_reference_unique = models.Constraint(
        "UNIQUE(journal_id, odoo_cli_v3_external_reference)",
        "The V3 bank statement external reference already exists in this journal.",
    )
    _odoo_cli_v3_source_digest_unique = models.Constraint(
        "UNIQUE(journal_id, odoo_cli_v3_source_digest)",
        "The V3 bank statement source digest already exists in this journal.",
    )

    @api.constrains("odoo_cli_v3_source_digest")
    def _check_odoo_cli_v3_source_digest(self):
        for statement in self:
            digest = statement.odoo_cli_v3_source_digest
            if digest and _SHA256.fullmatch(digest) is None:
                raise ValidationError(
                    "bank source digest must be lowercase SHA-256"
                )

    @api.model_create_multi
    def create(self, values_list):
        for values in values_list:
            _reject_untrusted_metadata_values(values, _BANK_STATEMENT_METADATA_FIELDS)
        records = super().create(values_list)
        _reject_untrusted_created_metadata(records, _BANK_STATEMENT_METADATA_FIELDS)
        return records

    def write(self, values):
        _reject_untrusted_metadata_values(values, _BANK_STATEMENT_METADATA_FIELDS)
        _reject_changed_metadata(
            self,
            values,
            _BANK_STATEMENT_METADATA_FIELDS,
            "bank source identity fields are immutable",
        )
        return super().write(values)


class AccountBankStatementLine(models.Model):
    _inherit = "account.bank.statement.line"

    odoo_cli_v3_external_transaction_id = fields.Char(
        copy=False, index=True, readonly=True, size=128
    )
    odoo_cli_v3_source_line_digest = fields.Char(
        copy=False, index=True, readonly=True, size=64
    )
    odoo_cli_v3_value_date = fields.Date(copy=False, index=True, readonly=True)

    _odoo_cli_v3_external_transaction_unique = models.Constraint(
        "UNIQUE(journal_id, odoo_cli_v3_external_transaction_id)",
        "The V3 bank transaction external ID already exists in this journal.",
    )
    _odoo_cli_v3_source_line_digest_unique = models.Constraint(
        "UNIQUE(journal_id, odoo_cli_v3_source_line_digest)",
        "The V3 bank source line digest already exists in this journal.",
    )

    @api.constrains("odoo_cli_v3_source_line_digest")
    def _check_odoo_cli_v3_source_line_digest(self):
        for line in self:
            digest = line.odoo_cli_v3_source_line_digest
            if digest and _SHA256.fullmatch(digest) is None:
                raise ValidationError(
                    "bank source digest must be lowercase SHA-256"
                )

    @api.model_create_multi
    def create(self, values_list):
        for values in values_list:
            _reject_untrusted_metadata_values(
                values, _BANK_STATEMENT_LINE_METADATA_FIELDS
            )
        records = super().create(values_list)
        _reject_untrusted_created_metadata(
            records, _BANK_STATEMENT_LINE_METADATA_FIELDS
        )
        return records

    def write(self, values):
        _reject_untrusted_metadata_values(
            values, _BANK_STATEMENT_LINE_METADATA_FIELDS
        )
        _reject_changed_metadata(
            self,
            values,
            _BANK_STATEMENT_LINE_METADATA_FIELDS,
            "bank source identity fields are immutable",
        )
        return super().write(values)

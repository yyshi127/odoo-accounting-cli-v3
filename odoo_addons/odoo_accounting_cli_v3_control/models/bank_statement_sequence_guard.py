"""Serialize every ORM mutation that can change a bank statement sequence."""

from __future__ import annotations

import hashlib
import json

from odoo import api, models
from odoo.exceptions import ValidationError


_LOCK_MODEL = "account.journal.bank_statement_sequence"
_LOCK_PURPOSE = "odoo_write_resource_lock_v1"


def _record_id(value):
    identifier = getattr(value, "id", value)
    if isinstance(identifier, bool) or not isinstance(identifier, int):
        return None
    return identifier if identifier > 0 else None


def _required_record(env, model_name, value, label):
    record_id = _record_id(value)
    if record_id is None:
        raise ValidationError(f"{label} is unavailable")
    model = env[model_name]
    model.check_access_rights("read")
    record = model.browse(record_id).exists()
    if not record or len(record) != 1 or _record_id(record) != record_id:
        raise ValidationError(f"{label} is unavailable")
    record.check_access_rule("read")
    return record


def _journal_pair(journal, label):
    journal_id = _record_id(journal)
    company_id = _record_id(getattr(journal, "company_id", None))
    if journal_id is None or company_id is None:
        raise ValidationError(f"{label} has no auditable company and journal")
    return company_id, journal_id


def _journal_pair_from_id(env, journal_id, label):
    return _journal_pair(
        _required_record(env, "account.journal", journal_id, label),
        label,
    )


def _statement_pair(statement, label):
    return _journal_pair(getattr(statement, "journal_id", None), label)


def _statement_pair_from_id(env, statement_id, label):
    statement = _required_record(
        env, "account.bank.statement", statement_id, label
    )
    return _statement_pair(statement, label)


def _line_pair(line, label):
    journal = getattr(line, "journal_id", None)
    if _record_id(journal) is not None:
        return _journal_pair(journal, label)
    statement = getattr(line, "statement_id", None)
    if _record_id(statement) is not None:
        return _statement_pair(statement, label)
    move = getattr(line, "move_id", None)
    if _record_id(move) is not None:
        return _journal_pair(getattr(move, "journal_id", None), label)
    raise ValidationError(f"{label} has no auditable bank journal")


def _line_pair_from_id(env, line_id, label):
    line = _required_record(
        env, "account.bank.statement.line", line_id, label
    )
    return _line_pair(line, label)


def _validate_company(values, pairs, label):
    if "company_id" not in values:
        return
    company_id = _record_id(values.get("company_id"))
    if company_id is None or any(pair[0] != company_id for pair in pairs):
        raise ValidationError(f"{label} company and journal differ")


def _statement_values_pair(env, values, *, current=None):
    if "journal_id" in values:
        pair = _journal_pair_from_id(
            env, values.get("journal_id"), "bank statement journal"
        )
    elif current is not None:
        pair = current
    else:
        raise ValidationError(
            "bank statement create requires an explicit journal"
        )
    _validate_company(values, {pair}, "bank statement")
    return pair


def _line_values_pair(env, values, *, current=None):
    pairs = set()
    if "journal_id" in values and values.get("journal_id"):
        pairs.add(
            _journal_pair_from_id(
                env,
                values["journal_id"],
                "bank statement line journal",
            )
        )
    if "statement_id" in values and values.get("statement_id"):
        pairs.add(
            _statement_pair_from_id(
                env,
                values["statement_id"],
                "bank statement line statement",
            )
        )
    if "move_id" in values and values.get("move_id"):
        move = _required_record(
            env, "account.move", values["move_id"], "bank statement line move"
        )
        pairs.add(
            _journal_pair(
                getattr(move, "journal_id", None),
                "bank statement line move",
            )
        )
    if not pairs and current is not None:
        pairs.add(current)
    if len(pairs) != 1:
        raise ValidationError(
            "bank statement line journal bindings are missing or inconsistent"
        )
    _validate_company(values, pairs, "bank statement line")
    return next(iter(pairs))


def _iter_records(value):
    if not value:
        return ()
    if isinstance(value, (list, tuple)):
        return value
    try:
        return tuple(value)
    except TypeError:
        return (value,)


def _move_bank_pairs(move):
    lines = {}
    for field_name in ("statement_line_id", "statement_line_ids"):
        for line in _iter_records(getattr(move, field_name, None)):
            line_id = _record_id(line)
            if line_id is not None:
                lines[line_id] = line
    return {
        _line_pair(line, "linked bank statement move")
        for line in lines.values()
    }


def _command_line_pairs(env, value):
    pairs = set()
    if not value:
        return pairs
    for item in _iter_records(value):
        item_id = _record_id(item)
        if item_id is not None:
            pairs.add(
                _line_pair_from_id(
                    env, item_id, "linked bank statement move line"
                )
            )
            continue
        if not isinstance(item, (list, tuple)) or not item:
            raise ValidationError(
                "bank statement line relation command is invalid"
            )
        operation = item[0]
        if operation == 0:
            if len(item) < 3 or not isinstance(item[2], dict):
                raise ValidationError(
                    "bank statement line create command is invalid"
                )
            pairs.add(_line_values_pair(env, item[2]))
        elif operation in {1, 2, 3, 4}:
            if len(item) < 2:
                raise ValidationError(
                    "bank statement line relation command is invalid"
                )
            pairs.add(
                _line_pair_from_id(
                    env, item[1], "linked bank statement move line"
                )
            )
        elif operation == 5:
            continue
        elif operation == 6:
            if len(item) < 3 or not isinstance(item[2], (list, tuple)):
                raise ValidationError(
                    "bank statement line replace command is invalid"
                )
            for line_id in item[2]:
                pairs.add(
                    _line_pair_from_id(
                        env,
                        line_id,
                        "linked bank statement move line",
                    )
                )
        else:
            raise ValidationError(
                "bank statement line relation command is invalid"
            )
    return pairs


def _move_values_pairs(env, values, current_pairs):
    pairs = set(current_pairs)
    if "statement_line_id" in values and values.get("statement_line_id"):
        pairs.add(
            _line_pair_from_id(
                env,
                values["statement_line_id"],
                "linked bank statement move line",
            )
        )
    if "statement_line_ids" in values:
        pairs.update(_command_line_pairs(env, values["statement_line_ids"]))
    if pairs and "journal_id" in values:
        pairs.add(
            _journal_pair_from_id(
                env, values["journal_id"], "linked bank statement move journal"
            )
        )
    _validate_company(values, pairs, "linked bank statement move")
    return pairs


def _move_pairs_from_id(env, move_id):
    move = _required_record(
        env, "account.move", move_id, "bank journal item move"
    )
    return _move_bank_pairs(move)


def _move_line_pairs(line):
    move = getattr(line, "move_id", None)
    if _record_id(move) is None:
        return set()
    return _move_bank_pairs(move)


def _move_line_values_pairs(env, values, current_pairs):
    pairs = set(current_pairs)
    if "move_id" in values and values.get("move_id"):
        pairs.update(_move_pairs_from_id(env, values["move_id"]))
    _validate_company(values, pairs, "bank journal item")
    return pairs


def _move_line_pairs_from_id(env, line_id):
    line = _required_record(
        env, "account.move.line", line_id, "reconciliation journal item"
    )
    return _move_line_pairs(line)


def _partial_reconcile_pairs(partial):
    pairs = set()
    for field_name in ("debit_move_id", "credit_move_id"):
        line = getattr(partial, field_name, None)
        if _record_id(line) is not None:
            pairs.update(_move_line_pairs(line))
    return pairs


def _partial_reconcile_values_pairs(env, values, current_pairs):
    pairs = set(current_pairs)
    for field_name in ("debit_move_id", "credit_move_id"):
        if field_name in values and values.get(field_name):
            pairs.update(
                _move_line_pairs_from_id(env, values[field_name])
            )
    return pairs


def _relation_pairs(
    env,
    value,
    *,
    model_name,
    label,
    record_pairs,
    create_pairs,
):
    pairs = set()
    if not value:
        return pairs
    for item in _iter_records(value):
        item_id = _record_id(item)
        if item_id is not None:
            record = _required_record(env, model_name, item_id, label)
            pairs.update(record_pairs(record))
            continue
        if not isinstance(item, (list, tuple)) or not item:
            raise ValidationError(f"{label} relation command is invalid")
        operation = item[0]
        if operation == 0:
            if len(item) < 3 or not isinstance(item[2], dict):
                raise ValidationError(f"{label} create command is invalid")
            pairs.update(create_pairs(item[2]))
        elif operation in {1, 2, 3, 4}:
            if len(item) < 2:
                raise ValidationError(f"{label} relation command is invalid")
            record = _required_record(env, model_name, item[1], label)
            pairs.update(record_pairs(record))
        elif operation == 5:
            continue
        elif operation == 6:
            if len(item) < 3 or not isinstance(item[2], (list, tuple)):
                raise ValidationError(f"{label} replace command is invalid")
            for record_id in item[2]:
                record = _required_record(
                    env, model_name, record_id, label
                )
                pairs.update(record_pairs(record))
        else:
            raise ValidationError(f"{label} relation command is invalid")
    return pairs


def _full_reconcile_pairs(full_reconcile):
    pairs = set()
    for line in _iter_records(
        getattr(full_reconcile, "reconciled_line_ids", None)
    ):
        pairs.update(_move_line_pairs(line))
    for partial in _iter_records(
        getattr(full_reconcile, "partial_reconcile_ids", None)
    ):
        pairs.update(_partial_reconcile_pairs(partial))
    return pairs


def _partial_reconcile_unlink_pairs(partial):
    pairs = _partial_reconcile_pairs(partial)
    full_reconcile = getattr(partial, "full_reconcile_id", None)
    if _record_id(full_reconcile) is not None:
        pairs.update(_full_reconcile_pairs(full_reconcile))
    return pairs


def _full_reconcile_values_pairs(env, values, current_pairs):
    pairs = set(current_pairs)
    if "reconciled_line_ids" in values:
        pairs.update(
            _relation_pairs(
                env,
                values["reconciled_line_ids"],
                model_name="account.move.line",
                label="full reconciliation journal item",
                record_pairs=_move_line_pairs,
                create_pairs=lambda item: _move_line_values_pairs(
                    env, item, set()
                ),
            )
        )
    if "partial_reconcile_ids" in values:
        pairs.update(
            _relation_pairs(
                env,
                values["partial_reconcile_ids"],
                model_name="account.partial.reconcile",
                label="full reconciliation partial",
                record_pairs=_partial_reconcile_pairs,
                create_pairs=lambda item: _partial_reconcile_values_pairs(
                    env, item, set()
                ),
            )
        )
    return pairs


def _bank_statement_sequence_lock_digest(company_id, journal_id):
    if (
        isinstance(company_id, bool)
        or not isinstance(company_id, int)
        or company_id <= 0
        or isinstance(journal_id, bool)
        or not isinstance(journal_id, int)
        or journal_id <= 0
    ):
        raise ValidationError("bank statement sequence lock identity is invalid")
    encoded = json.dumps(
        {
            "purpose": _LOCK_PURPOSE,
            "company_id": company_id,
            "model": _LOCK_MODEL,
            "identity": journal_id,
        },
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _acquire_bank_statement_sequence_locks(env, pairs):
    digests = sorted(
        {
            _bank_statement_sequence_lock_digest(company_id, journal_id)
            for company_id, journal_id in pairs
        }
    )
    lock_model = env["odoo.accounting.cli.operation"]
    acquire = getattr(lock_model, "_acquire_scope_lock", None)
    if not callable(acquire):
        raise ValidationError(
            "bank statement sequence lock provider is unavailable"
        )
    for digest in digests:
        acquire(digest)


class AccountBankStatement(models.Model):
    _inherit = "account.bank.statement"

    @api.model_create_multi
    def create(self, values_list):
        pairs = {
            _statement_values_pair(self.env, values)
            for values in values_list
        }
        _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().create(values_list)

    def write(self, values):
        pairs = set()
        for statement in self:
            current = _statement_pair(statement, "bank statement")
            pairs.add(current)
            pairs.add(
                _statement_values_pair(
                    self.env, values, current=current
                )
            )
        _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().write(values)

    def unlink(self):
        pairs = {
            _statement_pair(statement, "bank statement")
            for statement in self
        }
        _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().unlink()


class AccountBankStatementLine(models.Model):
    _inherit = "account.bank.statement.line"

    @api.model_create_multi
    def create(self, values_list):
        pairs = {
            _line_values_pair(self.env, values)
            for values in values_list
        }
        _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().create(values_list)

    def write(self, values):
        pairs = set()
        for line in self:
            current = _line_pair(line, "bank statement line")
            pairs.add(current)
            pairs.add(
                _line_values_pair(self.env, values, current=current)
            )
        _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().write(values)

    def unlink(self):
        pairs = {
            _line_pair(line, "bank statement line") for line in self
        }
        _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().unlink()


class AccountMove(models.Model):
    _inherit = "account.move"

    def _acquire_linked_bank_statement_sequence_locks(self):
        pairs = set()
        for move in self:
            pairs.update(_move_bank_pairs(move))
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)

    @api.model_create_multi
    def create(self, values_list):
        pairs = set()
        for values in values_list:
            pairs.update(_move_values_pairs(self.env, values, set()))
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().create(values_list)

    def write(self, values):
        pairs = set()
        for move in self:
            current = _move_bank_pairs(move)
            pairs.update(current)
            pairs.update(_move_values_pairs(self.env, values, current))
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().write(values)

    def unlink(self):
        self._acquire_linked_bank_statement_sequence_locks()
        return super().unlink()

    def action_post(self):
        self._acquire_linked_bank_statement_sequence_locks()
        return super().action_post()

    def _post(self, soft=True):
        self._acquire_linked_bank_statement_sequence_locks()
        return super()._post(soft=soft)

    def button_draft(self):
        self._acquire_linked_bank_statement_sequence_locks()
        return super().button_draft()

    def button_cancel(self):
        self._acquire_linked_bank_statement_sequence_locks()
        return super().button_cancel()


class AccountMoveLine(models.Model):
    _inherit = "account.move.line"

    @api.model_create_multi
    def create(self, values_list):
        pairs = set()
        for values in values_list:
            pairs.update(
                _move_line_values_pairs(self.env, values, set())
            )
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().create(values_list)

    def write(self, values):
        pairs = set()
        for line in self:
            current = _move_line_pairs(line)
            pairs.update(current)
            pairs.update(
                _move_line_values_pairs(self.env, values, current)
            )
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().write(values)

    def unlink(self):
        pairs = set()
        for line in self:
            pairs.update(_move_line_pairs(line))
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().unlink()


class AccountPartialReconcile(models.Model):
    _inherit = "account.partial.reconcile"

    @api.model_create_multi
    def create(self, values_list):
        pairs = set()
        for values in values_list:
            pairs.update(
                _partial_reconcile_values_pairs(self.env, values, set())
            )
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().create(values_list)

    def write(self, values):
        pairs = set()
        for partial in self:
            current = _partial_reconcile_pairs(partial)
            pairs.update(current)
            pairs.update(
                _partial_reconcile_values_pairs(
                    self.env, values, current
                )
            )
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().write(values)

    def unlink(self):
        pairs = set()
        for partial in self:
            pairs.update(_partial_reconcile_unlink_pairs(partial))
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().unlink()


class AccountFullReconcile(models.Model):
    _inherit = "account.full.reconcile"

    @api.model_create_multi
    def create(self, values_list):
        pairs = set()
        for values in values_list:
            pairs.update(
                _full_reconcile_values_pairs(self.env, values, set())
            )
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().create(values_list)

    def write(self, values):
        pairs = set()
        for full_reconcile in self:
            current = _full_reconcile_pairs(full_reconcile)
            pairs.update(current)
            pairs.update(
                _full_reconcile_values_pairs(
                    self.env, values, current
                )
            )
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().write(values)

    def unlink(self):
        pairs = set()
        for full_reconcile in self:
            pairs.update(_full_reconcile_pairs(full_reconcile))
        if pairs:
            _acquire_bank_statement_sequence_locks(self.env, pairs)
        return super().unlink()

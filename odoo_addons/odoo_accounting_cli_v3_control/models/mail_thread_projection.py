from __future__ import annotations

import hashlib
import json
from datetime import date, datetime

from odoo import models
from odoo.exceptions import AccessError, ValidationError

from .execution_scope import _v3_execution_scope_is_active


_EXECUTOR_GROUP = "odoo_accounting_cli_v3_control.group_executor"
_MAX_THREAD_RECORDS = 500
_MAX_RELATION_IDS = 500
_MAX_THREAD_EDGES = 2_000


def _canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_digest(value):
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _relation_id(value):
    identifier = getattr(value, "id", None)
    return identifier if type(identifier) is int and identifier > 0 else None


def _relation_ids(value):
    identifiers = getattr(value, "ids", ())
    return sorted(
        identifier
        for identifier in identifiers
        if type(identifier) is int and identifier > 0
    )


def _bounded_relation_ids(value):
    identifiers = list(getattr(value, "ids", ()))
    if (
        len(identifiers) > _MAX_RELATION_IDS
        or any(
            type(identifier) is not int or identifier <= 0
            for identifier in identifiers
        )
        or len(identifiers) != len(set(identifiers))
    ):
        raise ValidationError("V3 MailThread relation limit exceeded")
    return sorted(identifiers)


def _temporal(value):
    if value in (False, None):
        return None
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    return str(value)


def _message_digest_values(message):
    return {
        "attachment_ids": _bounded_relation_ids(message.attachment_ids),
        "author_guest_id": _relation_id(message.author_guest_id),
        "author_id": _relation_id(message.author_id),
        "body_sha256": _text_digest(message.body),
        "create_date": _temporal(message.create_date),
        "create_uid": _relation_id(message.create_uid),
        "date": _temporal(message.date),
        "email_add_signature": bool(message.email_add_signature),
        "email_from_sha256": _text_digest(message.email_from),
        "email_layout_xmlid_sha256": _text_digest(
            message.email_layout_xmlid
        ),
        "id": message.id,
        "incoming_email_cc_sha256": _text_digest(
            message.incoming_email_cc
        ),
        "incoming_email_to_sha256": _text_digest(message.incoming_email_to),
        "is_internal": bool(message.is_internal),
        "mail_activity_type_id": _relation_id(
            message.mail_activity_type_id
        ),
        "mail_ids": _bounded_relation_ids(message.mail_ids),
        "mail_server_id": _relation_id(message.mail_server_id),
        "message_id_sha256": _text_digest(message.message_id),
        "message_link_preview_ids": _bounded_relation_ids(
            message.message_link_preview_ids
        ),
        "message_type": str(message.message_type or ""),
        "model": str(message.model or ""),
        "notification_ids": _bounded_relation_ids(
            message.notification_ids
        ),
        "outgoing_email_to_sha256": _text_digest(
            message.outgoing_email_to
        ),
        "parent_id": _relation_id(message.parent_id),
        "partner_ids": _bounded_relation_ids(message.partner_ids),
        "pinned_at": _temporal(message.pinned_at),
        "reaction_ids": _bounded_relation_ids(message.reaction_ids),
        "record_alias_domain_id": _relation_id(
            message.record_alias_domain_id
        ),
        "record_company_id": _relation_id(message.record_company_id),
        "reply_to_force_new": bool(message.reply_to_force_new),
        "reply_to_sha256": _text_digest(message.reply_to),
        "res_id": message.res_id,
        "subtype_id": _relation_id(message.subtype_id),
        "subject_sha256": _text_digest(message.subject),
        "starred_partner_ids": _bounded_relation_ids(
            message.starred_partner_ids
        ),
        "tracking_value_ids": _bounded_relation_ids(
            message.tracking_value_ids
        ),
        "write_date": _temporal(message.write_date),
        "write_uid": _relation_id(message.write_uid),
    }


def _message_audit_shape(values):
    return {
        "attachment_ids": values["attachment_ids"],
        "author_guest_id": values["author_guest_id"],
        "author_id": values["author_id"],
        "body_sha256": values["body_sha256"],
        "create_date": values["create_date"],
        "create_uid": values["create_uid"],
        "date": values["date"],
        "email_add_signature": values["email_add_signature"],
        "email_from_sha256": values["email_from_sha256"],
        "email_layout_xmlid_sha256": values[
            "email_layout_xmlid_sha256"
        ],
        "incoming_email_cc_sha256": values[
            "incoming_email_cc_sha256"
        ],
        "incoming_email_to_sha256": values[
            "incoming_email_to_sha256"
        ],
        "is_internal": values["is_internal"],
        "mail_activity_type_id": values["mail_activity_type_id"],
        "mail_server_id": values["mail_server_id"],
        "message_id_sha256": values["message_id_sha256"],
        "message_link_preview_ids": values[
            "message_link_preview_ids"
        ],
        "message_type": values["message_type"],
        "model": values["model"],
        "outgoing_email_to_sha256": values[
            "outgoing_email_to_sha256"
        ],
        "parent_id": values["parent_id"],
        "partner_ids": values["partner_ids"],
        "pinned_at": values["pinned_at"],
        "reaction_ids": values["reaction_ids"],
        "record_alias_domain_id": values["record_alias_domain_id"],
        "record_company_id": values["record_company_id"],
        "reply_to_force_new": values["reply_to_force_new"],
        "reply_to_sha256": values["reply_to_sha256"],
        "res_id": values["res_id"],
        "subject_sha256": values["subject_sha256"],
        "starred_partner_ids": values["starred_partner_ids"],
        "subtype_id": values["subtype_id"],
        "tracking_value_ids": values["tracking_value_ids"],
        "write_date": values["write_date"],
        "write_uid": values["write_uid"],
    }


def _mail_digest_values(mail):
    return {
        "auto_delete": bool(mail.auto_delete),
        "body_html_sha256": _text_digest(mail.body_html),
        "create_date": _temporal(mail.create_date),
        "create_uid": _relation_id(mail.create_uid),
        "email_cc_sha256": _text_digest(mail.email_cc),
        "email_to_sha256": _text_digest(mail.email_to),
        "failure_reason_sha256": _text_digest(mail.failure_reason),
        "failure_type": str(mail.failure_type or ""),
        "fetchmail_server_id": _relation_id(mail.fetchmail_server_id),
        "headers_sha256": _text_digest(mail.headers),
        "id": mail.id,
        "is_notification": bool(mail.is_notification),
        "mail_message_id": _relation_id(mail.mail_message_id),
        "recipient_ids": _bounded_relation_ids(mail.recipient_ids),
        "references_sha256": _text_digest(mail.references),
        "scheduled_date": _temporal(mail.scheduled_date),
        "state": str(mail.state or ""),
        "write_date": _temporal(mail.write_date),
        "write_uid": _relation_id(mail.write_uid),
    }


def _notification_digest_values(notification):
    return {
        "author_id": _relation_id(notification.author_id),
        "failure_reason_sha256": _text_digest(notification.failure_reason),
        "failure_type": str(notification.failure_type or ""),
        "id": notification.id,
        "is_read": bool(notification.is_read),
        "mail_email_address_sha256": _text_digest(
            notification.mail_email_address
        ),
        "mail_mail_id": _relation_id(notification.mail_mail_id),
        "mail_message_id": _relation_id(notification.mail_message_id),
        "notification_status": str(notification.notification_status or ""),
        "notification_type": str(notification.notification_type or ""),
        "read_date": _temporal(notification.read_date),
        "res_partner_id": _relation_id(notification.res_partner_id),
    }


class AccountMove(models.Model):
    _inherit = "account.move"

    def _odoo_cli_v3_mail_thread_projection(self):
        """Return a bounded message/notification/outgoing-mail projection."""

        self.ensure_one()
        if (
            not _v3_execution_scope_is_active()
            or self.env.su
            or not self.env.user.has_group(_EXECUTOR_GROUP)
            or _relation_id(self.company_id) != _relation_id(self.env.company)
            or _relation_id(self.company_id)
            not in set(_relation_ids(self.env.companies))
        ):
            raise AccessError(
                "V3 MailThread projection requires the bound executor company"
            )
        self.check_access_rights("read")
        self.check_access_rule("read")

        messages = (
            self.env["mail.message"]
            .sudo()
            .search(
                [("model", "=", "account.move"), ("res_id", "=", self.id)],
                order="id",
                limit=_MAX_THREAD_RECORDS + 1,
            )
        )
        if len(messages) > _MAX_THREAD_RECORDS:
            raise ValidationError("V3 MailThread message limit exceeded")
        relation_edge_count = 0
        message_values = []
        for message in messages:
            values = _message_digest_values(message)
            relation_edge_count += sum(
                len(values[field])
                for field in (
                    "attachment_ids",
                    "mail_ids",
                    "message_link_preview_ids",
                    "notification_ids",
                    "partner_ids",
                    "reaction_ids",
                    "starred_partner_ids",
                    "tracking_value_ids",
                )
            )
            if relation_edge_count > _MAX_THREAD_EDGES:
                raise ValidationError("V3 MailThread edge limit exceeded")
            message_values.append(values)
        message_ids = [values["id"] for values in message_values]
        if (
            any(
                type(identifier) is not int or identifier <= 0
                for identifier in message_ids
            )
            or
            message_ids != sorted(message_ids)
            or len(message_ids) != len(set(message_ids))
            or any(
                values["model"] != "account.move"
                or values["res_id"] != self.id
                or values["record_company_id"]
                not in {None, self.company_id.id}
                for values in message_values
            )
        ):
            raise ValidationError("V3 MailThread message projection is invalid")
        message_id_set = set(message_ids)

        notifications = (
            self.env["mail.notification"]
            .sudo()
            .search(
                [("mail_message_id", "in", message_ids)],
                order="id",
                limit=_MAX_THREAD_RECORDS + 1,
            )
            if message_ids
            else []
        )
        if len(notifications) > _MAX_THREAD_RECORDS:
            raise ValidationError("V3 MailThread notification limit exceeded")
        notification_values = [
            _notification_digest_values(notification)
            for notification in notifications
        ]
        notification_ids = [
            values["id"] for values in notification_values
        ]
        if (
            any(
                type(identifier) is not int or identifier <= 0
                for identifier in notification_ids
            )
            or
            notification_ids != sorted(notification_ids)
            or len(notification_ids) != len(set(notification_ids))
            or any(
                values["mail_message_id"] not in message_id_set
                for values in notification_values
            )
        ):
            raise ValidationError(
                "V3 MailThread notification projection is invalid"
            )

        mails = (
            self.env["mail.mail"]
            .sudo()
            .search(
                [("mail_message_id", "in", message_ids)],
                order="id",
                limit=_MAX_THREAD_RECORDS + 1,
            )
            if message_ids
            else []
        )
        if len(mails) > _MAX_THREAD_RECORDS:
            raise ValidationError("V3 MailThread mail limit exceeded")
        mail_values = []
        for mail in mails:
            values = _mail_digest_values(mail)
            relation_edge_count += len(values["recipient_ids"])
            if relation_edge_count > _MAX_THREAD_EDGES:
                raise ValidationError("V3 MailThread edge limit exceeded")
            mail_values.append(values)
        mail_ids = [values["id"] for values in mail_values]
        mail_parent_by_id = {
            values["id"]: values["mail_message_id"]
            for values in mail_values
        }
        if (
            any(
                type(identifier) is not int or identifier <= 0
                for identifier in mail_ids
            )
            or
            mail_ids != sorted(mail_ids)
            or len(mail_ids) != len(set(mail_ids))
            or any(
                values["mail_message_id"] not in message_id_set
                for values in mail_values
            )
            or sorted(
                mail_id
                for values in message_values
                for mail_id in values["mail_ids"]
            )
            != mail_ids
            or sorted(
                notification_id
                for values in message_values
                for notification_id in values["notification_ids"]
            )
            != notification_ids
            or any(
                values["mail_mail_id"] is not None
                and mail_parent_by_id.get(values["mail_mail_id"])
                != values["mail_message_id"]
                for values in notification_values
            )
        ):
            raise ValidationError(
                "V3 MailThread mail projection is invalid"
            )
        envelope = {
            "company_id": self.company_id.id,
            "mail_count": len(mails),
            "mail_mails": [
                {
                    "id": values["id"],
                    "message_id": values["mail_message_id"],
                    "digest": _digest(values),
                }
                for values in mail_values
            ],
            "message_count": len(messages),
            "messages": [
                {
                    "id": values["id"],
                    "audit_shape": _message_audit_shape(values),
                    "digest": _digest(values),
                    "mail_ids": values["mail_ids"],
                    "notification_ids": values["notification_ids"],
                }
                for values in message_values
            ],
            "move_id": self.id,
            "notification_count": len(notifications),
            "notifications": [
                {
                    "id": values["id"],
                    "mail_id": values["mail_mail_id"],
                    "message_id": values["mail_message_id"],
                    "digest": _digest(values),
                }
                for values in notification_values
            ],
            "version": 1,
        }
        return {
            **envelope,
            "projection_digest": _digest(envelope),
        }

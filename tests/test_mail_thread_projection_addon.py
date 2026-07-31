from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "odoo_addons"
    / "odoo_accounting_cli_v3_control"
    / "models"
    / "mail_thread_projection.py"
)


class FakeAccessError(Exception):
    pass


class FakeValidationError(Exception):
    pass


class Relation:
    def __init__(self, identifier: int | None = None, identifiers=()):
        self.id = identifier
        self.ids = list(identifiers)

    def __bool__(self):
        return self.id is not None or bool(self.ids)


class Row(SimpleNamespace):
    pass


class SearchModel:
    def __init__(self, rows):
        self.rows = list(rows)
        self.sudo_calls = 0
        self.searches = []

    def sudo(self):
        self.sudo_calls += 1
        return self

    def search(self, domain, *, order, limit):
        self.searches.append((domain, order, limit))
        if domain and domain[0][0] == "model":
            model = next(value for field, _operator, value in domain if field == "model")
            res_id = next(value for field, _operator, value in domain if field == "res_id")
            rows = [
                row
                for row in self.rows
                if row.model == model and row.res_id == res_id
            ]
        else:
            message_ids = set(domain[0][2])
            rows = [
                row
                for row in self.rows
                if row.mail_message_id.id in message_ids
            ]
        return sorted(rows, key=lambda row: row.id)[:limit]


class FakeEnv:
    def __init__(
        self,
        *,
        messages,
        notifications,
        mails=(),
        executor=True,
        su=False,
    ):
        self.su = su
        self.company = Relation(7)
        self.companies = Relation(identifiers=[7])
        self.user = SimpleNamespace(
            has_group=lambda xmlid: (
                executor
                and xmlid
                == "odoo_accounting_cli_v3_control.group_executor"
            )
        )
        self.models = {
            "mail.message": SearchModel(messages),
            "mail.notification": SearchModel(notifications),
            "mail.mail": SearchModel(mails),
        }

    def __getitem__(self, model_name):
        return self.models[model_name]


def _load(
    monkeypatch: pytest.MonkeyPatch,
    *,
    scope_active: bool = True,
):
    odoo = ModuleType("odoo")
    odoo.__path__ = []
    odoo.models = SimpleNamespace(Model=object)
    exceptions = ModuleType("odoo.exceptions")
    exceptions.AccessError = FakeAccessError
    exceptions.ValidationError = FakeValidationError
    monkeypatch.setitem(sys.modules, "odoo", odoo)
    monkeypatch.setitem(sys.modules, "odoo.exceptions", exceptions)
    package_names = (
        "odoo.addons",
        "odoo.addons.odoo_accounting_cli_v3_control",
        "odoo.addons.odoo_accounting_cli_v3_control.models",
    )
    for package_name in package_names:
        package = ModuleType(package_name)
        package.__path__ = []
        monkeypatch.setitem(sys.modules, package_name, package)
    scope_module_name = (
        "odoo.addons.odoo_accounting_cli_v3_control.models."
        "execution_scope"
    )
    scope_module = ModuleType(scope_module_name)
    scope_module._v3_execution_scope_is_active = (
        lambda: scope_active
    )
    monkeypatch.setitem(sys.modules, scope_module_name, scope_module)
    module_name = (
        "odoo.addons.odoo_accounting_cli_v3_control.models."
        "mail_thread_projection"
    )
    spec = importlib.util.spec_from_file_location(
        module_name,
        SOURCE,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _message(identifier: int, *, message_type: str):
    return Row(
        id=identifier,
        model="account.move",
        res_id=81,
        body=f"<p>{message_type}</p>",
        message_type=message_type,
        is_internal=True,
        subtype_id=Relation(9),
        author_id=Relation(10),
        author_guest_id=Relation(),
        mail_activity_type_id=Relation(),
        parent_id=Relation(),
        attachment_ids=Relation(identifiers=[]),
        tracking_value_ids=Relation(identifiers=[]),
        partner_ids=Relation(identifiers=[]),
        reaction_ids=Relation(identifiers=[]),
        message_link_preview_ids=Relation(identifiers=[]),
        starred_partner_ids=Relation(identifiers=[]),
        pinned_at=False,
        record_alias_domain_id=Relation(),
        record_company_id=Relation(),
        date=datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc),
        email_from=False,
        email_add_signature=False,
        email_layout_xmlid=False,
        incoming_email_to=False,
        incoming_email_cc=False,
        message_id="<message@odoo>",
        outgoing_email_to=False,
        notification_ids=Relation(identifiers=[]),
        mail_ids=Relation(identifiers=[]),
        mail_server_id=Relation(),
        reply_to=False,
        reply_to_force_new=False,
        subject=False,
        create_uid=Relation(42),
        create_date=datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc),
        write_uid=Relation(42),
        write_date=datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc),
    )


def _mail(identifier: int, message_id: int):
    return Row(
        id=identifier,
        mail_message_id=Relation(message_id),
        body_html="<p>queued</p>",
        references=False,
        headers=False,
        is_notification=True,
        email_to=False,
        email_cc=False,
        recipient_ids=Relation(identifiers=[11]),
        state="outgoing",
        failure_type=False,
        failure_reason=False,
        auto_delete=True,
        scheduled_date=False,
        fetchmail_server_id=Relation(),
        create_uid=Relation(42),
        create_date=datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc),
        write_uid=Relation(42),
        write_date=datetime(2026, 7, 31, 8, 0, tzinfo=timezone.utc),
    )


def _move(module, env):
    move = module.AccountMove()
    move.id = 81
    move.ids = [81]
    move.company_id = Relation(7)
    move.env = env
    move.ensure_one = lambda: None
    move.check_access_rights = lambda operation: operation == "read"
    move.check_access_rule = lambda operation: operation == "read"
    return move


def test_projection_includes_user_notification_and_notification_fingerprints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    audit = _message(101, message_type="notification")
    hidden = _message(102, message_type="user_notification")
    notification = Row(
        id=201,
        author_id=Relation(10),
        mail_message_id=Relation(102),
        mail_mail_id=Relation(301),
        res_partner_id=Relation(11),
        mail_email_address=False,
        notification_type="inbox",
        notification_status="sent",
        is_read=False,
        read_date=False,
        failure_type=False,
        failure_reason=False,
    )
    hidden.notification_ids = Relation(identifiers=[201])
    hidden.mail_ids = Relation(identifiers=[301])
    env = FakeEnv(
        messages=[hidden, audit],
        notifications=[notification],
        mails=[_mail(301, 102)],
    )

    projection = _move(module, env)._odoo_cli_v3_mail_thread_projection()

    assert [item["id"] for item in projection["messages"]] == [101, 102]
    assert projection["notifications"][0]["message_id"] == 102
    assert projection["mail_mails"][0]["message_id"] == 102
    assert all(
        len(item["digest"]) == 64
        for item in [
            *projection["messages"],
            *projection["notifications"],
            *projection["mail_mails"],
        ]
    )
    envelope = dict(projection)
    digest = envelope.pop("projection_digest")
    assert digest == hashlib.sha256(
        json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert env.models["mail.message"].searches == [
        (
            [("model", "=", "account.move"), ("res_id", "=", 81)],
            "id",
            501,
        )
    ]
    assert projection["messages"][1]["notification_ids"] == [201]
    assert projection["messages"][1]["mail_ids"] == [301]
    assert projection["notifications"][0]["mail_id"] == 301
    assert projection["messages"][0]["audit_shape"][
        "tracking_value_ids"
    ] == []
    assert env.models["mail.notification"].searches == [
        ([("mail_message_id", "in", [101, 102])], "id", 501)
    ]
    assert env.models["mail.mail"].searches == [
        ([("mail_message_id", "in", [101, 102])], "id", 501)
    ]


@pytest.mark.parametrize(
    ("executor", "su", "company_id", "error"),
    (
        (False, False, 7, FakeAccessError),
        (True, True, 7, FakeAccessError),
        (True, False, 8, FakeAccessError),
    ),
)
def test_projection_rejects_untrusted_identity_or_company(
    monkeypatch: pytest.MonkeyPatch,
    executor: bool,
    su: bool,
    company_id: int,
    error: type[Exception],
) -> None:
    module = _load(monkeypatch)
    env = FakeEnv(messages=[], notifications=[], executor=executor, su=su)
    move = _move(module, env)
    move.company_id = Relation(company_id)

    with pytest.raises(error):
        move._odoo_cli_v3_mail_thread_projection()


def test_projection_rejects_ordinary_rpc_outside_trusted_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch, scope_active=False)
    move = _move(
        module,
        FakeEnv(messages=[], notifications=[], executor=True, su=False),
    )

    with pytest.raises(FakeAccessError, match="bound executor company"):
        move._odoo_cli_v3_mail_thread_projection()


def test_projection_rejects_foreign_message_company(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    message = _message(101, message_type="notification")
    message.record_company_id = Relation(8)

    with pytest.raises(FakeValidationError, match="message projection"):
        _move(
            module,
            FakeEnv(messages=[message], notifications=[]),
        )._odoo_cli_v3_mail_thread_projection()


def test_projection_fails_closed_above_the_hard_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    env = FakeEnv(
        messages=[
            _message(identifier, message_type="notification")
            for identifier in range(1, 502)
        ],
        notifications=[],
    )

    with pytest.raises(FakeValidationError, match="limit"):
        _move(module, env)._odoo_cli_v3_mail_thread_projection()


def test_projection_rejects_notification_mail_from_another_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    first = _message(101, message_type="notification")
    second = _message(102, message_type="notification")
    first.notification_ids = Relation(identifiers=[201])
    second.mail_ids = Relation(identifiers=[301])
    notification = Row(
        id=201,
        author_id=Relation(10),
        mail_message_id=Relation(101),
        mail_mail_id=Relation(301),
        res_partner_id=Relation(11),
        mail_email_address=False,
        notification_type="email",
        notification_status="ready",
        is_read=False,
        read_date=False,
        failure_type=False,
        failure_reason=False,
    )

    with pytest.raises(FakeValidationError, match="mail projection"):
        _move(
            module,
            FakeEnv(
                messages=[first, second],
                notifications=[notification],
                mails=[_mail(301, 102)],
            ),
        )._odoo_cli_v3_mail_thread_projection()


def test_projection_source_is_a_narrow_read_only_sudo_oracle() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert "def _odoo_cli_v3_mail_thread_projection(" in source
    assert "def odoo_cli_v3_mail_thread_projection(" not in source
    assert source.count(".sudo(") == 3
    assert ".create(" not in source
    assert ".write(" not in source
    assert ".unlink(" not in source
    assert "group_executor" in source
    assert "limit=_MAX_THREAD_RECORDS + 1" in source


def test_projection_uses_real_odoo_19_mail_field_names() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert "message.incoming_email_cc" in source
    assert "message.cc" not in source
    assert "notification.mail_message_id" in source
    assert "mail.mail_message_id" in source


def test_projection_relation_limit_accepts_boundary_and_rejects_one_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    boundary = _message(101, message_type="notification")
    boundary.attachment_ids = Relation(identifiers=range(1, 501))
    projection = _move(
        module,
        FakeEnv(messages=[boundary], notifications=[]),
    )._odoo_cli_v3_mail_thread_projection()
    assert projection["message_count"] == 1

    one_over = _message(101, message_type="notification")
    one_over.attachment_ids = Relation(identifiers=range(1, 502))
    with pytest.raises(FakeValidationError, match="relation limit"):
        _move(
            module,
            FakeEnv(messages=[one_over], notifications=[]),
        )._odoo_cli_v3_mail_thread_projection()


def test_projection_global_edge_limit_accepts_boundary_and_rejects_one_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(monkeypatch)
    boundary_messages = [
        _message(identifier, message_type="notification")
        for identifier in range(101, 105)
    ]
    for offset, message in enumerate(boundary_messages):
        start = offset * 500 + 1
        message.attachment_ids = Relation(
            identifiers=range(start, start + 500)
        )
    projection = _move(
        module,
        FakeEnv(messages=boundary_messages, notifications=[]),
    )._odoo_cli_v3_mail_thread_projection()
    assert projection["message_count"] == 4

    boundary_messages[-1].partner_ids = Relation(identifiers=[3000])
    with pytest.raises(FakeValidationError, match="edge limit"):
        _move(
            module,
            FakeEnv(messages=boundary_messages, notifications=[]),
        )._odoo_cli_v3_mail_thread_projection()

from __future__ import annotations

import pytest

from odoo_accounting_cli_v3.odoo.module_graph import (
    OdooModuleGraphError,
    build_trusted_module_graph,
    conditional_required_fields,
    read_installed_module_graph,
    validate_module_graph_evidence,
)


def test_module_graph_is_canonical_and_round_trips_evidence():
    graph = build_trusted_module_graph(
        [
            {"name": "purchase", "latest_version": "19.0.1.0"},
            {"name": "account", "latest_version": "19.0.2.0"},
        ]
    )

    assert graph.installed_modules == frozenset({"account", "purchase"})
    assert [item["name"] for item in graph.evidence["modules"]] == [
        "account",
        "purchase",
    ]
    assert validate_module_graph_evidence(graph.evidence) == graph


@pytest.mark.parametrize(
    "rows",
    [
        [{"name": "account", "latest_version": "19"}] * 2,
        [{"name": "bad module", "latest_version": "19"}],
        [{"name": "account", "latest_version": False}],
        [{"name": "account", "latest_version": "19", "extra": True}],
    ],
)
def test_module_graph_rejects_ambiguous_or_malformed_rows(rows):
    with pytest.raises(OdooModuleGraphError):
        build_trusted_module_graph(rows)


def test_optional_field_may_be_absent_only_when_all_provider_modules_are_absent():
    graph = build_trusted_module_graph(
        [{"name": "account", "latest_version": "19"}]
    )

    required = conditional_required_fields(
        "account.move",
        {"state", "pos_order_ids"},
        {"state"},
        graph,
    )

    assert required == frozenset({"state"})


def test_installed_provider_keeps_optional_field_strictly_required():
    graph = build_trusted_module_graph(
        [
            {"name": "account", "latest_version": "19"},
            {"name": "point_of_sale", "latest_version": "19"},
        ]
    )

    required = conditional_required_fields(
        "account.move",
        {"state", "pos_order_ids"},
        {"state"},
        graph,
    )

    assert required == frozenset({"state", "pos_order_ids"})


def test_field_presence_with_all_claimed_providers_absent_is_rejected():
    graph = build_trusted_module_graph(
        [{"name": "account", "latest_version": "19"}]
    )

    with pytest.raises(OdooModuleGraphError, match="schema differs"):
        conditional_required_fields(
            "account.move",
            {"state", "pos_order_ids"},
            {"state", "pos_order_ids"},
            graph,
        )


def test_any_installed_provider_requires_shared_is_downpayment_field():
    graph = build_trusted_module_graph(
        [
            {"name": "account", "latest_version": "19"},
            {"name": "sale", "latest_version": "19"},
        ]
    )

    assert conditional_required_fields(
        "account.move.line",
        {"is_downpayment"},
        set(),
        graph,
    ) == frozenset({"is_downpayment"})


def test_module_graph_evidence_digest_detects_tampering():
    graph = build_trusted_module_graph(
        [{"name": "account", "latest_version": "19"}]
    )
    forged = {
        **graph.evidence,
        "modules": [
            *graph.evidence["modules"],
            {"name": "point_of_sale", "latest_version": "19"},
        ],
    }

    with pytest.raises(OdooModuleGraphError, match="digest"):
        validate_module_graph_evidence(forged)


def test_module_graph_evidence_rejects_boolean_schema_version():
    graph = build_trusted_module_graph(
        [{"name": "account", "latest_version": "19"}]
    )
    forged = {**graph.evidence, "schema_version": True}

    with pytest.raises(OdooModuleGraphError, match="version"):
        validate_module_graph_evidence(forged)


def test_module_graph_evidence_rejects_noncanonical_module_order():
    graph = build_trusted_module_graph(
        [
            {"name": "account", "latest_version": "19"},
            {"name": "purchase", "latest_version": "19"},
        ]
    )
    forged = {
        **graph.evidence,
        "modules": list(reversed(graph.evidence["modules"])),
    }

    with pytest.raises(OdooModuleGraphError, match="canonical"):
        validate_module_graph_evidence(forged)


def test_live_module_graph_reader_uses_trusted_root_and_installed_rows_only():
    class Records:
        def read(self, fields):
            assert fields == ["name", "latest_version", "state"]
            return [
                {
                    "id": 1,
                    "name": "account",
                    "latest_version": "19.0.2.0",
                    "state": "installed",
                },
                {
                    "id": 2,
                    "name": "purchase",
                    "latest_version": "19.0.1.0",
                    "state": "installed",
                },
            ]

    class Model:
        def with_context(self, **context):
            assert context == {"active_test": False}
            return self

        def search(self, domain, *, order):
            assert domain == [("state", "=", "installed")]
            assert order == "name, id"
            return Records()

    class RootEnv:
        su = True

        def __getitem__(self, model_name):
            assert model_name == "ir.module.module"
            return Model()

    graph = read_installed_module_graph(RootEnv())

    assert graph.installed_modules == frozenset({"account", "purchase"})


def test_live_module_graph_reader_rejects_non_root_environment():
    with pytest.raises(OdooModuleGraphError, match="root environment"):
        read_installed_module_graph(object())


def test_live_module_graph_reader_locks_module_table_before_execution_read():
    events = []

    class Cursor:
        def execute(self, statement):
            assert statement == "LOCK TABLE ir_module_module IN SHARE MODE"
            events.append("locked")

    class Records:
        def read(self, fields):
            return [
                {
                    "name": "account",
                    "latest_version": "19.0.2.0",
                    "state": "installed",
                }
            ]

    class Model:
        def with_context(self, **_context):
            return self

        def search(self, _domain, *, order):
            assert order == "name, id"
            assert events == ["locked"]
            return Records()

    class RootEnv:
        su = True
        cr = Cursor()

        def __getitem__(self, model_name):
            assert model_name == "ir.module.module"
            return Model()

    graph = read_installed_module_graph(
        RootEnv(), lock_for_transaction=True
    )

    assert graph.installed_modules == frozenset({"account"})

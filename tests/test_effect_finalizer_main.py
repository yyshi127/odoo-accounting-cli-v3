from __future__ import annotations

import builtins
import hashlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from odoo_accounting_cli_v3 import effect_finalizer_main as main


def test_finalizer_main_has_fixed_help_and_secret_free_failure(capsys, monkeypatch) -> None:
    assert main.main(["--help"]) == 0
    captured = capsys.readouterr()
    assert captured.out == (
        "usage: odoo-accounting-cli-v3-effect-finalizer "
        "--config ABSOLUTE_PATH\n"
    )
    assert captured.err == ""

    def fail(_path):
        raise RuntimeError("database-password-must-not-leak")

    monkeypatch.setattr(main, "run_effect_finalizer_service", fail)
    assert main.main(["--config", "/etc/finalizer.json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "effect finalizer service failed closed\n"
    assert "password" not in captured.err


def test_finalizer_main_rejects_ambiguous_arguments_without_starting(
    capsys, monkeypatch
) -> None:
    calls = []
    monkeypatch.setattr(
        main, "run_effect_finalizer_service", lambda path: calls.append(path)
    )

    assert main.main([]) == 2
    assert main.main(["--config", ""]) == 2
    assert calls == []
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.count("usage:") == 2


def test_application_build_has_no_odoo_loader_and_connects_from_database_config(
    tmp_path, monkeypatch
) -> None:
    assert "connection_info_loader" not in inspect.signature(
        main.build_effect_finalizer_application
    ).parameters

    database_config = object()
    config = SimpleNamespace(
        service_uid=3104,
        service_gid=3104,
        database=database_config,
        journal_path=tmp_path / "attempts.sqlite3",
        attestation_key_id="effect-finalizer-v1",
        proof_ttl_seconds=120,
    )
    monkeypatch.setattr(
        main,
        "load_effect_finalizer_runtime_config",
        lambda _path, *, require_root_owner: config,
    )
    monkeypatch.setattr(
        main,
        "preflight_effect_finalizer_runtime_credentials",
        lambda observed: SimpleNamespace(attestation_secret=b"x" * 32),
    )
    journal = object()
    monkeypatch.setattr(
        main, "EffectFinalizerAttemptJournal", lambda *_args, **_kwargs: journal
    )
    service_arguments = {}

    def service_factory(**kwargs):
        service_arguments.update(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(main, "EffectFinalizerService", service_factory)
    connection = SimpleNamespace(close=lambda: None)

    def connector(**_parameters):
        raise AssertionError("the connector is invoked by the database adapter")

    def open_connection(*, config, connect):
        assert config is database_config
        assert connect is connector
        return connection

    monkeypatch.setattr(main, "open_direct_finalizer_connection", open_connection)
    finalized = object()

    def finalize(observed, *, config, request, attestation, now):
        assert observed is connection
        assert config is database_config
        assert request == "request"
        assert attestation == "attestation"
        assert now().tzinfo is not None
        return finalized

    monkeypatch.setattr(main, "finalize_effect_attempt", finalize)
    import_module = builtins.__import__

    def reject_odoo_import(name, *args, **kwargs):
        if name == "odoo" or name.startswith("odoo."):
            raise AssertionError("the isolated finalizer must not import Odoo")
        return import_module(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_odoo_import)

    application = main.build_effect_finalizer_application(
        tmp_path / "runtime.json",
        require_root_owner=False,
        connect=connector,
    )

    assert application.config is config
    assert service_arguments["journal"] is journal
    assert (
        service_arguments["database_finalize"]("request", "attestation")
        is finalized
    )


def test_postgresql_driver_is_eagerly_retained_and_bound_to_external_manifest(
    tmp_path, monkeypatch
) -> None:
    interpreter = (tmp_path / "python3").resolve()
    interpreter.write_bytes(b"python")
    release_root = (tmp_path / "release").resolve()
    source_file = release_root / "src" / "odoo_accounting_cli_v3" / "module.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("# fixture\n", encoding="utf-8")
    gate_path = release_root / "deployment" / "dev27" / "finalizer_runtime_gate.py"
    gate_path.parent.mkdir(parents=True)
    gate_path.write_text("# gate fixture\n", encoding="utf-8")
    package_file = (tmp_path / "psycopg2" / "__init__.py").resolve()
    native_file = (tmp_path / "psycopg2" / "_psycopg.so").resolve()
    package_file.parent.mkdir()
    package_file.write_text("# package\n", encoding="utf-8")
    native_file.write_bytes(b"native")
    connector = lambda **_parameters: None
    package = SimpleNamespace(
        __file__=str(package_file),
        __version__="2.9.9",
        connect=connector,
    )
    native = SimpleNamespace(__file__=str(native_file))
    manifest = {
        "finalizer_module_file": {"canonical_path": str(source_file)},
        "source_root": {
            "canonical_path": str((release_root / "src").resolve())
        },
        "runtime": {"psycopg2_version": "2.9.9"},
        "python_module_files": [
            {"canonical_path": str(package_file)},
            {"canonical_path": str(native_file)},
        ],
        "psycopg2_files": [
            {"canonical_path": str(package_file)},
            {"canonical_path": str(native_file)},
        ],
    }
    manifest_path = (tmp_path / "dependency-manifest.json").resolve()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    config = SimpleNamespace(
        dependency_manifest_path=manifest_path,
        dependency_manifest_sha256=manifest_digest,
    )
    events = []
    gate_stdout = [
        b'{"manifest_sha256":"'
        + manifest_digest.encode("ascii")
        + b'","ok":true}\n'
    ]

    def import_module(name):
        events.append(f"import:{name}")
        return package if name == "psycopg2" else native

    def run(arguments, **kwargs):
        events.append("gate")
        assert arguments == [
            str(interpreter),
            "-I",
            "-B",
            "-X",
            "utf8",
            str(gate_path),
            "verify",
            "--interpreter",
            str(interpreter),
            "--manifest",
            str(manifest_path),
            "--expected-manifest-sha256",
            manifest_digest,
        ]
        assert kwargs["env"] == {"LD_BIND_NOW": "1"}
        return SimpleNamespace(
            returncode=0,
            stdout=gate_stdout[0],
            stderr=b"",
        )

    monkeypatch.setattr(main, "__file__", str(source_file))
    monkeypatch.setattr(main, "_SYSTEM_PYTHON", interpreter)
    monkeypatch.setattr(main.sys, "executable", str(interpreter))
    monkeypatch.setattr(
        main.sys,
        "flags",
        SimpleNamespace(
            isolated=1,
            dont_write_bytecode=1,
            utf8_mode=1,
        ),
    )
    monkeypatch.setattr(main.sys, "dont_write_bytecode", True)
    monkeypatch.setenv("LD_BIND_NOW", "1")
    monkeypatch.setattr(main.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(main.importlib, "import_module", import_module)
    monkeypatch.setattr(main.subprocess, "run", run)

    assert main._verified_postgresql_connect(config) is connector
    assert events == ["import:psycopg2", "import:psycopg2._psycopg", "gate"]

    manifest["finalizer_module_file"]["canonical_path"] = str(package_file)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(main.EffectFinalizerMainError, match="differs"):
        main._verified_postgresql_connect(config)

    manifest["finalizer_module_file"]["canonical_path"] = str(source_file)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    gate_stdout[0] = b'{"ok":true}\n'
    with pytest.raises(main.EffectFinalizerMainError, match="rejected"):
        main._verified_postgresql_connect(config)


def test_postgresql_driver_rejects_runtime_without_startup_utf8_flag(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        main.sys,
        "flags",
        SimpleNamespace(
            isolated=1,
            dont_write_bytecode=1,
            utf8_mode=0,
        ),
    )
    monkeypatch.setattr(main.sys, "dont_write_bytecode", True)
    monkeypatch.setenv("LD_BIND_NOW", "1")
    monkeypatch.setattr(main.importlib.util, "find_spec", lambda name: None)

    with pytest.raises(main.EffectFinalizerMainError, match="isolation"):
        main._verified_postgresql_connect(SimpleNamespace())


def test_application_verifies_driver_before_reading_credentials(
    tmp_path, monkeypatch
) -> None:
    order = []
    connector = lambda **_parameters: None
    config = SimpleNamespace(
        service_uid=3104,
        service_gid=3104,
        database=object(),
        journal_path=tmp_path / "attempts.sqlite3",
        attestation_key_id="effect-finalizer-v1",
        proof_ttl_seconds=120,
    )
    monkeypatch.setattr(
        main,
        "load_effect_finalizer_runtime_config",
        lambda _path, *, require_root_owner: config,
    )
    monkeypatch.setattr(
        main,
        "_verified_postgresql_connect",
        lambda observed: order.append("driver") or connector,
    )
    monkeypatch.setattr(
        main,
        "preflight_effect_finalizer_runtime_credentials",
        lambda observed: order.append("credentials")
        or SimpleNamespace(attestation_secret=b"x" * 32),
    )
    monkeypatch.setattr(
        main,
        "EffectFinalizerAttemptJournal",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        main,
        "EffectFinalizerService",
        lambda **_kwargs: SimpleNamespace(),
    )

    main.build_effect_finalizer_application(
        tmp_path / "runtime.json",
        require_root_owner=False,
    )

    assert order == ["driver", "credentials"]

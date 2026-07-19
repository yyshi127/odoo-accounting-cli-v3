from __future__ import annotations

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

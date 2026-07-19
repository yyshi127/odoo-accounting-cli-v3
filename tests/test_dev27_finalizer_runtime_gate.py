from __future__ import annotations

import importlib.util
import json
import os
import sys
from copy import deepcopy
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = (
    PROJECT_ROOT / "deployment" / "dev27" / "finalizer_runtime_gate.py"
)


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "dev27_finalizer_runtime_gate", GATE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _fixture(tmp_path: Path, monkeypatch):
    interpreter = (tmp_path / "python3").resolve()
    source_root = (tmp_path / "release" / "src").resolve()
    finalizer_package = source_root / "odoo_accounting_cli_v3"
    finalizer_package.mkdir(parents=True)
    finalizer_init = finalizer_package / "__init__.py"
    finalizer_main = finalizer_package / "effect_finalizer_main.py"
    package = (tmp_path / "dist-packages" / "psycopg2").resolve()
    package.mkdir(parents=True)
    init = package / "__init__.py"
    native = package / "_psycopg.cpython-312-x86_64-linux-gnu.so"
    libpq = (tmp_path / "lib" / "libpq.so.5.16").resolve()
    libpq.parent.mkdir()
    stdlib = libpq.parent / "json.py"
    archive = (tmp_path / "lib" / "python312.zip").resolve()
    missing_archive = (tmp_path / "lib" / "python313.zip").resolve()
    pth = package.parent / "vendor-runtime.pth"
    interpreter.write_bytes(b"python-elf-fixture")
    finalizer_init.write_bytes(b"finalizer-package-fixture")
    finalizer_main.write_bytes(b"finalizer-main-fixture")
    init.write_bytes(b"psycopg2-fixture")
    native.write_bytes(b"native-extension-fixture")
    libpq.write_bytes(b"libpq-fixture")
    stdlib.write_bytes(b"stdlib-fixture")
    archive.write_bytes(b"zip-fixture")
    pth.write_bytes(b"/root-managed/vendor\n")
    probe = {
        "executable": str(interpreter),
        "finalizer_module_file": str(finalizer_main),
        "isolated": 1,
        "mapped_files": sorted([str(interpreter), str(native), str(libpq)]),
        "odoo_import_rejected": True,
        "odoo_spec_present": False,
        "pth_files": [str(pth)],
        "psycopg2_files": sorted([str(init), str(native)]),
        "psycopg2_version": "2.9.9 (dt dec pq3 ext lo64)",
        "python_module_files": sorted(
            [
                str(finalizer_init),
                str(finalizer_main),
                str(init),
                str(native),
                str(stdlib),
            ]
        ),
        "python_version": "3.12.3 (fixture) [GCC]",
        "python_version_info": [3, 12, 3],
        "sys_path_directories": sorted(
            [str(source_root), str(package.parent), str(libpq.parent)]
        ),
        "sys_path_files": [str(archive)],
        "sys_path_missing": [str(missing_archive)],
    }
    monkeypatch.setattr(gate, "_finalizer_source_root", lambda: source_root)
    monkeypatch.setattr(
        gate,
        "_run_probe",
        lambda observed, observed_source: deepcopy(probe),
    )
    return interpreter, native, libpq, probe


def _collect(tmp_path: Path, monkeypatch):
    interpreter, native, libpq, probe = _fixture(tmp_path, monkeypatch)
    manifest = gate.collect_manifest(interpreter, require_root_owner=False)
    return manifest, interpreter, native, libpq, probe


def test_collection_is_deterministic_strict_and_binds_all_runtime_files(
    tmp_path, monkeypatch
) -> None:
    manifest, interpreter, native, libpq, _probe = _collect(tmp_path, monkeypatch)
    repeated = gate.collect_manifest(interpreter, require_root_owner=False)

    assert gate._canonical_json(manifest) == gate._canonical_json(repeated)
    assert set(manifest) == gate._MANIFEST_FIELDS
    assert manifest["schema_version"] == gate.SCHEMA_VERSION
    assert manifest["interpreter"]["observed_path"] == str(interpreter)
    assert manifest["source_root"]["observed_path"] == str(
        Path(_probe["finalizer_module_file"]).parents[1]
    )
    assert manifest["finalizer_module_file"]["observed_path"] == _probe[
        "finalizer_module_file"
    ]
    assert {
        item["observed_path"] for item in manifest["python_module_files"]
    } == set(_probe["python_module_files"])
    assert {item["observed_path"] for item in manifest["psycopg2_files"]} >= {
        str(native)
    }
    assert {
        item["observed_path"] for item in manifest["sys_path_directories"]
    } == set(_probe["sys_path_directories"])
    assert {item["observed_path"] for item in manifest["sys_path_files"]} == set(
        _probe["sys_path_files"]
    )
    assert {item["path"] for item in manifest["sys_path_missing"]} == set(
        _probe["sys_path_missing"]
    )
    assert manifest["sys_path_missing"][0][
        "observed_deepest_existing_ancestor"
    ] == str(Path(_probe["sys_path_missing"][0]).parent)
    assert {item["observed_path"] for item in manifest["pth_files"]} == set(
        _probe["pth_files"]
    )
    assert {item["observed_path"] for item in manifest["mapped_files"]} >= {
        str(interpreter),
        str(native),
        str(libpq),
    }
    assert all(
        len(item["sha256"]) == 64
        for item in [
            manifest["interpreter"],
            manifest["finalizer_module_file"],
            *manifest["python_module_files"],
            *manifest["psycopg2_files"],
            *manifest["sys_path_files"],
            *manifest["pth_files"],
            *manifest["mapped_files"],
        ]
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("odoo_spec_present", True, "Odoo visibility"),
        ("odoo_import_rejected", False, "Odoo visibility"),
        ("isolated", 0, "Odoo visibility"),
        ("psycopg2_files", [], "file list"),
    ],
)
def test_collection_rejects_odoo_visibility_or_incomplete_python_probe(
    tmp_path, monkeypatch, field, value, message
) -> None:
    interpreter, _native, _libpq, probe = _fixture(tmp_path, monkeypatch)
    probe[field] = value
    monkeypatch.setattr(
        gate,
        "_run_probe",
        lambda observed, observed_source: deepcopy(probe),
    )

    with pytest.raises(gate.FinalizerRuntimeGateError, match=message):
        gate.collect_manifest(interpreter, require_root_owner=False)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("finalizer_identity", "finalizer module identity"),
        ("finalizer_module_missing", "eager-import closure"),
        ("source_path_missing", "eager-import closure"),
    ],
)
def test_collection_requires_the_release_finalizer_in_the_observed_import_closure(
    tmp_path, monkeypatch, mutation, message
) -> None:
    interpreter, _native, _libpq, probe = _fixture(tmp_path, monkeypatch)
    if mutation == "finalizer_identity":
        probe["finalizer_module_file"] = next(
            item
            for item in probe["python_module_files"]
            if item != probe["finalizer_module_file"]
        )
    elif mutation == "finalizer_module_missing":
        probe["python_module_files"].remove(probe["finalizer_module_file"])
    else:
        source_root = str(Path(probe["finalizer_module_file"]).parents[1])
        probe["sys_path_directories"].remove(source_root)
    monkeypatch.setattr(
        gate,
        "_run_probe",
        lambda observed, observed_source: deepcopy(probe),
    )

    with pytest.raises(gate.FinalizerRuntimeGateError, match=message):
        gate.collect_manifest(interpreter, require_root_owner=False)


@pytest.mark.parametrize("missing", ["_psycopg", "libpq"])
def test_collection_requires_native_psycopg_and_libpq(
    tmp_path, monkeypatch, missing
) -> None:
    interpreter, native, libpq, probe = _fixture(tmp_path, monkeypatch)
    if missing == "_psycopg":
        probe["psycopg2_files"] = [
            item for item in probe["psycopg2_files"] if item != str(native)
        ]
    else:
        probe["mapped_files"] = [
            item for item in probe["mapped_files"] if item != str(libpq)
        ]
    monkeypatch.setattr(
        gate,
        "_run_probe",
        lambda observed, observed_source: deepcopy(probe),
    )

    expected = "native extension" if missing == "_psycopg" else "libpq"
    with pytest.raises(gate.FinalizerRuntimeGateError, match=expected):
        gate.collect_manifest(interpreter, require_root_owner=False)


def test_verification_accepts_exact_manifest_and_rejects_byte_drift(
    tmp_path, monkeypatch
) -> None:
    manifest, interpreter, _native, libpq, _probe = _collect(tmp_path, monkeypatch)
    manifest_path = (tmp_path / "expected.json").resolve()
    manifest_path.write_bytes(gate._canonical_json(manifest))
    expected_digest = gate.hashlib.sha256(
        gate._canonical_json(manifest)
    ).hexdigest()

    digest = gate.verify_manifest(
        interpreter,
        manifest_path,
        expected_digest,
        require_root_owner=False,
    )
    assert digest == expected_digest

    libpq.write_bytes(b"drifted-libpq-fixture")
    with pytest.raises(gate.FinalizerRuntimeGateError, match="drifted"):
        gate.verify_manifest(
            interpreter,
            manifest_path,
            expected_digest,
            require_root_owner=False,
        )

    with pytest.raises(gate.FinalizerRuntimeGateError, match="external"):
        gate.verify_manifest(
            interpreter,
            manifest_path,
            "0" * 64,
            require_root_owner=False,
        )


def test_verification_rejects_a_missing_sys_path_entry_becoming_a_file(
    tmp_path, monkeypatch
) -> None:
    manifest, interpreter, _native, _libpq, probe = _collect(
        tmp_path, monkeypatch
    )
    manifest_path = (tmp_path / "expected.json").resolve()
    manifest_path.write_bytes(gate._canonical_json(manifest))
    expected_digest = gate.hashlib.sha256(
        gate._canonical_json(manifest)
    ).hexdigest()
    missing = Path(probe["sys_path_missing"].pop())
    missing.write_bytes(b"new-import-archive")
    probe["sys_path_files"].append(str(missing))
    probe["sys_path_files"].sort()

    with pytest.raises(gate.FinalizerRuntimeGateError, match="drifted"):
        gate.verify_manifest(
            interpreter,
            manifest_path,
            expected_digest,
            require_root_owner=False,
        )


def test_missing_sys_path_record_binds_both_deepest_existing_ancestor_chains(
    tmp_path
) -> None:
    trusted = (tmp_path / "runtime").resolve()
    trusted.mkdir()
    missing = trusted / "python313.zip"

    record = gate._missing_path_record(missing, require_root_owner=False)

    assert record["path"] == str(missing)
    assert record["observed_deepest_existing_ancestor"] == str(trusted)
    assert record["canonical_deepest_existing_ancestor"] == str(trusted)
    assert record["observed_ancestor_chain"][-1]["kind"] == "directory"
    assert record["canonical_ancestor_chain"][-1]["kind"] == "directory"

    missing.write_bytes(b"classification-change")
    with pytest.raises(gate.FinalizerRuntimeGateError, match="now exists"):
        gate._missing_path_record(missing, require_root_owner=False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership policy")
def test_missing_sys_path_under_an_untrusted_parent_fails_closed(tmp_path) -> None:
    missing = (tmp_path / "attacker-controlled" / "python313.zip").resolve()

    with pytest.raises(
        gate.FinalizerRuntimeGateError,
        match="not root owned|group/world writable",
    ):
        gate._missing_path_record(missing, require_root_owner=True)


def test_expected_manifest_rejects_noncanonical_duplicate_and_extra_fields(
    tmp_path, monkeypatch
) -> None:
    manifest, interpreter, _native, _libpq, _probe = _collect(tmp_path, monkeypatch)
    manifest_path = (tmp_path / "expected.json").resolve()
    expected_digest = gate.hashlib.sha256(
        gate._canonical_json(manifest)
    ).hexdigest()

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with pytest.raises(gate.FinalizerRuntimeGateError, match="canonical"):
        gate.verify_manifest(
            interpreter,
            manifest_path,
            expected_digest,
            require_root_owner=False,
        )

    canonical = gate._canonical_json(manifest).decode("utf-8")
    manifest_path.write_text(
        canonical[:-2] + ',"schema_version":"duplicate"}\n', encoding="utf-8"
    )
    with pytest.raises(gate.FinalizerRuntimeGateError, match="duplicate"):
        gate.verify_manifest(
            interpreter,
            manifest_path,
            expected_digest,
            require_root_owner=False,
        )

    extra = deepcopy(manifest)
    extra["runtime"]["untrusted"] = True
    manifest_path.write_bytes(gate._canonical_json(extra))
    with pytest.raises(gate.FinalizerRuntimeGateError, match="fields"):
        gate.verify_manifest(
            interpreter,
            manifest_path,
            expected_digest,
            require_root_owner=False,
        )


def test_file_record_binds_a_trusted_symlink_chain(tmp_path) -> None:
    target = (tmp_path / "python3.12").resolve()
    link = (tmp_path / "python3").resolve()
    target.write_bytes(b"python-target")
    try:
        link.symlink_to(target.name)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")

    record = gate._file_record(link, require_root_owner=False)

    assert record["observed_path"] == str(link)
    assert record["canonical_path"] == str(target)
    assert record["observed_chain"][-1]["kind"] == "symlink"
    assert record["observed_chain"][-1]["link_target"] == target.name
    assert record["canonical_chain"][-1]["kind"] == "regular"


def test_cli_help_and_invalid_arguments_are_fixed_and_do_not_probe(capsys) -> None:
    assert gate.main(["--help"]) == 0
    captured = capsys.readouterr()
    assert captured.out == gate._USAGE + "\n"
    assert captured.err == ""

    assert gate.main(["collect", "--interpreter", "relative-python"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == gate._FAILURE + "\n"

    assert gate.main([]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == gate._USAGE + "\n"


def test_probe_contract_uses_isolated_empty_environment_linux_mapping() -> None:
    assert 'find_spec("odoo")' in gate._PROBE_CODE
    assert "sys.flags.dont_write_bytecode != 1" in gate._PROBE_CODE
    assert "sys.flags.utf8_mode != 1" in gate._PROBE_CODE
    assert 'import_module("odoo")' in gate._PROBE_CODE
    assert gate._FINALIZER_MODULE in gate._PROBE_CODE
    assert "import psycopg2" in gate._PROBE_CODE
    assert "tuple(sys.modules.items())" in gate._PROBE_CODE
    assert "sys_path_directories" in gate._PROBE_CODE
    assert "sys_path_missing" in gate._PROBE_CODE
    assert 'name.endswith(".pth")' in gate._PROBE_CODE
    assert 'open("/proc/self/maps"' in gate._PROBE_CODE
    source = GATE_PATH.read_text("utf-8")
    for argument in ('"-I"', '"-B"', '"-X"', '"utf8"'):
        assert argument in source
    assert "_run_probe(interpreter, source_root)" in source
    assert 'env={"LD_BIND_NOW": "1"}' in source

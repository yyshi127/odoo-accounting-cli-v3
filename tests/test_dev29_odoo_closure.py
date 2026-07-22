from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev29" / "odoo_closure.py"
SPEC = importlib.util.spec_from_file_location("dev29_odoo_closure", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
closure = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = closure
SPEC.loader.exec_module(closure)

VERSION = "0.1.0.dev29"
COMMIT = "a1234567890bcdef1234567890abcdef12345678"
RELEASE = f"{VERSION}-{COMMIT[:12]}"
HEX_A = "a" * 64
HEX_B = "b" * 64
DB_NAME = "odoo_test"
DB_UUID = "19b09656-d10f-11f0-9065-00163e54a5ad"


def expected() -> closure.ExpectedIdentity:
    return closure.ExpectedIdentity(RELEASE, VERSION, COMMIT, HEX_A, HEX_B)


def test_target_program_contract_uses_direct_postgresql_16_psql() -> None:
    assert closure.PSQL == Path("/usr/lib/postgresql/16/bin/psql")


@pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="production program ownership checks require POSIX root",
)
def test_verified_program_accepts_only_the_explicit_mode(tmp_path: Path) -> None:
    program = tmp_path / "program"
    write(program, b"#!/bin/sh\n", 0o4755)

    closure._verified_program(
        program,
        label="setuid program",
        test_mode=False,
        expected_mode=0o4755,
    )
    with pytest.raises(closure.ClosureError, match="metadata mismatch"):
        closure._verified_program(program, label="ordinary program", test_mode=False)


def test_numeric_schema_version_guard_rejects_bool_and_non_integers() -> None:
    assert closure._schema_version_is_one(1) is True
    for value in (True, 1.0, "1", None):
        assert closure._schema_version_is_one(value) is False

    manifest = {
        "schema_version": True,
        "version": VERSION,
        "commit": COMMIT,
        "manifest_sha256": HEX_A,
        "files": [],
    }
    with pytest.raises(closure.ClosureError, match="release manifest identity"):
        closure._release_manifest_index(manifest, expected())


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def write(path: Path, payload: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    if os.name == "posix":
        path.chmod(mode)


def make_venv(tmp_path: Path, *, allowed_pth: bool = True) -> Path:
    venv = tmp_path / "venv"
    site = venv / "lib" / "python3.12" / "site-packages"
    write(site / "_distutils_hack" / "__init__.py", b"def add_shim(): pass\n")
    if allowed_pth:
        line = next(iter(closure.ALLOWED_PTH_EXECUTION))
        write(site / "distutils-precedence.pth", (line + "\n").encode())
    write(
        venv / "pyvenv.cfg",
        b"home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.3\n"
        b"executable = /usr/bin/python3.12\ncommand = /usr/bin/python3 -m venv /tmp/old\n",
    )
    write(venv / "bin" / "tool", b"#!/bin/sh\n", 0o755)
    return venv


def graph() -> dict[str, object]:
    return {
        "database_name": DB_NAME,
        "database_uuid": DB_UUID,
        "modules": [
            {"name": "base", "latest_version": "19.0.1.0", "application": False}
        ],
        "dependencies": [],
    }


def synthetic_elf(*, needed_offset: int | None = 1) -> bytes:
    payload = bytearray(320)
    payload[:4] = b"\x7fELF"
    payload[4:7] = bytes((2, 1, 1))
    struct.pack_into("<Q", payload, 32, 64)
    struct.pack_into("<H", payload, 54, 56)
    struct.pack_into("<H", payload, 56, 2)
    # PT_LOAD maps file offset zero at virtual address 0x400000.
    struct.pack_into("<I", payload, 64, 1)
    struct.pack_into("<QQ", payload, 72, 0, 0x400000)
    struct.pack_into("<Q", payload, 96, len(payload))
    # PT_DYNAMIC occupies four Elf64_Dyn entries at file offset 192.
    struct.pack_into("<I", payload, 120, 2)
    struct.pack_into("<QQ", payload, 128, 192, 0x4000C0)
    struct.pack_into("<Q", payload, 152, 64)
    strings = b"\0libc.so.6\0"
    payload[256 : 256 + len(strings)] = strings
    struct.pack_into("<qQ", payload, 192, 5, 0x400100)  # DT_STRTAB
    struct.pack_into("<qQ", payload, 208, 10, len(strings))  # DT_STRSZ
    if needed_offset is None:
        struct.pack_into("<qQ", payload, 224, 0, 0)
    else:
        struct.pack_into("<qQ", payload, 224, 1, needed_offset)  # DT_NEEDED
        struct.pack_into("<qQ", payload, 240, 0, 0)
    return bytes(payload)


def test_expected_identity_and_fixed_layout_are_release_scoped(tmp_path: Path) -> None:
    identity = expected()
    identity.validate()
    layout = closure.build_layout(tmp_path, identity)
    assert layout.image == tmp_path / "opt/odoo-accounting-cli-v3/dependency-images" / f"{RELEASE}.squashfs"
    assert layout.closure_anchor == tmp_path / "opt/odoo-accounting-cli-v3/dependency-anchors" / f"{RELEASE}.json"
    assert layout.mount_point == tmp_path / "opt/odoo-accounting-cli-v3/dependencies" / RELEASE
    assert layout.sealed_config == tmp_path / "etc/odoo-accounting-cli-v3/dependencies" / RELEASE / "odoo-server19.conf"
    with pytest.raises(closure.ClosureError, match="release identity"):
        replace(identity, release="wrong").validate()


def test_systemd_bind_order_has_config_override_last(tmp_path: Path) -> None:
    layout = closure.build_layout(tmp_path, expected())
    systemd = closure._systemd(layout)
    binds = systemd["bind_read_only_paths"]
    assert systemd["private_mounts"] is True
    assert [Path(item["source"]).name for item in binds[:3]] == [
        "odoo-server",
        "odoo19-venv",
        "custom-addons",
    ]
    assert binds[-1] == {
        "source": str(layout.sealed_config),
        "destination": "/mnt/odoo/odoo19/custom/addons/odoo-server19.conf",
    }
    assert systemd == {
        "execution_model": "single-supervisor-private-mount-namespace-v1",
        "private_mounts": True,
        "bind_read_only_paths": binds,
        "binding_phase": "root-supervisor-after-squashfs-mount",
        "supervisor_unit_properties": ["PrivateMounts=yes"],
        "child_execution": {
            "method": "direct-fork-exec",
            "systemd_run_forbidden": True,
            "credential_drop_required": True,
            "capabilities_zero_required": True,
            "no_new_privileges_required": True,
        },
    }


def test_strict_json_rejects_duplicate_and_nonfinite_values() -> None:
    with pytest.raises(closure.ClosureError, match="unique-key"):
        closure._strict_object(b'{"a":1,"a":2}', label="fixture")
    with pytest.raises(closure.ClosureError, match="non-finite"):
        closure._strict_object(b'{"a":NaN}', label="fixture")


def test_path_chain_rejects_a_symlink_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    child = parent / "child"
    child.parent.mkdir()
    write(child, b"fixture")
    original_lstat = Path.lstat

    def fake_lstat(path: Path, *args: object, **kwargs: object) -> object:
        if path == parent:
            return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777)
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(closure.ClosureError, match="symlink ancestor"):
        closure._require_no_symlink_ancestors(child, stop=tmp_path)


def test_config_requires_exact_reviewed_addons_path_and_never_returns_content() -> None:
    payload = (
        b"[options]\nadmin_passwd = do-not-leak\n"
        b"addons_path = /opt/odoo/odoo19/odoo-server/addons,/mnt/odoo/odoo19/custom/addons\n"
    )
    assert closure._parse_odoo_config(payload) is None
    with pytest.raises(closure.ClosureError, match="addons_path"):
        closure._parse_odoo_config(payload.replace(b"/mnt/odoo", b"/tmp/odoo"))


def test_database_graph_query_is_fixed_repeatable_read_and_strict(tmp_path: Path) -> None:
    psql = tmp_path / "psql"
    write(psql, b"fixture")
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, closure.canonical_json(graph()) + b"\n", b"")

    assert closure.query_database_graph(
        database_name=DB_NAME,
        database_uuid=DB_UUID,
        psql=psql,
        runner=runner,
        test_mode=True,
    ) == graph()
    command = calls[0]
    sql = command[command.index("--command") + 1]
    assert "REPEATABLE READ READ ONLY" in sql
    assert "SET LOCAL search_path = pg_catalog" in sql
    assert command[command.index("--dbname") + 1] == DB_NAME


def test_database_graph_rejects_unsorted_or_uninstalled_dependencies(tmp_path: Path) -> None:
    psql = tmp_path / "psql"
    write(psql, b"fixture")
    bad = graph()
    bad["dependencies"] = [
        {
            "module": "base",
            "dependency": "web",
            "auto_install_required": True,
            "dependency_state": "uninstalled",
        }
    ]

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, closure.canonical_json(bad) + b"\n", b"")

    with pytest.raises(closure.ClosureError, match="uninstalled dependency"):
        closure.query_database_graph(
            database_name=DB_NAME,
            database_uuid=DB_UUID,
            psql=psql,
            runner=runner,
            test_mode=True,
        )


def test_python_audit_removes_editable_cache_metadata_and_normalizes_pyvenv(tmp_path: Path) -> None:
    venv = make_venv(tmp_path)
    site = venv / "lib/python3.12/site-packages"
    write(site / "__editable__.cli_anything_odoo-1.0.0.pth", b"import finder\n")
    write(site / "__editable___cli_anything_odoo_1_0_0_finder.py", b"MAPPING = {'x':'/tmp'}\n")
    write(
        site / "cli_anything_odoo-1.0.0.dist-info/direct_url.json",
        b'{"dir_info":{"editable":true},"url":"file:///tmp"}',
    )
    write(site / "pkg/__pycache__/bad.pyc", b"unchecked-hash-cache")
    write(site / "legacy.egg-link", b"/tmp/editable\n")
    audit = closure.audit_python_paths(venv)
    excluded = {item["relative_path"] for item in audit["excluded_editable_entries"]}
    assert any(path.endswith("__editable__.cli_anything_odoo-1.0.0.pth") for path in excluded)
    assert any(path.endswith("__editable___cli_anything_odoo_1_0_0_finder.py") for path in excluded)
    assert any(path.endswith("cli_anything_odoo-1.0.0.dist-info") for path in excluded)
    assert any("__pycache__" in path for path in excluded)
    assert any(path.endswith("legacy.egg-link") for path in excluded)
    assert audit["pyvenv"]["normalized_values"] == {
        "home": "/usr/bin",
        "include-system-site-packages": "false",
        "version": "3.12.3",
        "executable": "/usr/bin/python3.12",
    }
    assert audit["python_path_escape_absent"] is True


@pytest.mark.parametrize(
    "name,is_directory",
    [
        ("sitecustomize", True),
        ("sitecustomize.cpython-312-x86_64-linux-gnu.so", False),
        ("usercustomize.py", False),
        ("usercustomize.zip", False),
    ],
)
def test_python_audit_rejects_every_importable_startup_form(
    tmp_path: Path, name: str, is_directory: bool
) -> None:
    venv = make_venv(tmp_path)
    target = venv / "lib/python3.12/site-packages" / name
    if is_directory:
        write(target / "__init__.py", b"raise RuntimeError\n")
    else:
        write(target, b"payload")
    with pytest.raises(closure.ClosureError, match="startup module"):
        closure.audit_python_paths(venv)


def test_python_audit_rejects_pth_path_and_unsafe_pyvenv(tmp_path: Path) -> None:
    venv = make_venv(tmp_path, allowed_pth=False)
    site = venv / "lib/python3.12/site-packages"
    write(site / "escape.pth", b"./internal.zip\n")
    write(site / "internal.zip", b"PK\x03\x04")
    with pytest.raises(closure.ClosureError, match="path entries"):
        closure.audit_python_paths(venv)
    (site / "escape.pth").unlink()
    write(
        venv / "pyvenv.cfg",
        b"home=/usr/bin\ninclude-system-site-packages=true\nversion=3.12.3\n",
    )
    with pytest.raises(closure.ClosureError, match="external site packages"):
        closure.audit_python_paths(venv)


def test_copy_excludes_bytecode_from_venv_core_and_addons(tmp_path: Path) -> None:
    venv = make_venv(tmp_path)
    write(venv / "lib/python3.12/site-packages/pkg/__pycache__/x.pyc", b"cache")
    source = tmp_path / "core"
    write(source / "ok.py", b"VALUE = 1\n")
    write(source / "__pycache__/ok.cpython-312.pyc", b"unchecked")
    write(source / "sourceless.pyc", b"sourceless")
    audit = closure.audit_python_paths(venv)
    stage = tmp_path / "stage"
    stage.mkdir()
    closure.copy_selections(
        [
            closure.SourceItem(source, closure.PurePosixPath("odoo-server/odoo"), "core"),
            closure.SourceItem(venv, closure.PurePosixPath("odoo19-venv"), "venv"),
        ],
        stage,
        venv=venv,
        python_audit=audit,
    )
    closure._assert_no_python_cache(stage)
    assert (stage / "odoo-server/odoo/ok.py").is_file()
    assert not (stage / "odoo-server/odoo/__pycache__").exists()
    assert not (stage / "odoo-server/odoo/sourceless.pyc").exists()
    placeholder = stage / "custom-addons/odoo-server19.conf"
    if os.name == "posix":
        assert stat.S_IMODE(placeholder.stat().st_mode) == 0
        assert stat.S_IMODE(placeholder.parent.stat().st_mode) == 0o555
        placeholder.chmod(0o400)
    try:
        assert placeholder.read_bytes() == closure.PLACEHOLDER
    finally:
        if os.name == "posix":
            placeholder.chmod(0o000)
    normalized = (stage / "odoo19-venv/pyvenv.cfg").read_bytes()
    assert b"/tmp/old" not in normalized
    assert sha(normalized) == audit["pyvenv"]["normalized_sha256"]


def test_image_cache_assertion_rejects_nested_and_sourceless_bytecode(tmp_path: Path) -> None:
    write(tmp_path / "pkg/__pycache__/evil.pyc", b"evil")
    with pytest.raises(closure.ClosureError, match="bytecode cache"):
        closure._assert_no_python_cache(tmp_path)
    shutil.rmtree(tmp_path / "pkg/__pycache__")
    write(tmp_path / "pkg/evil.pyo", b"evil")
    with pytest.raises(closure.ClosureError, match="bytecode file"):
        closure._assert_no_python_cache(tmp_path)


def test_elf_parser_extracts_needed_without_invoking_any_program(tmp_path: Path) -> None:
    path = tmp_path / "library.so"
    write(path, synthetic_elf())
    interpreter, needed, search = closure._elf_dynamic(path)
    assert interpreter is None
    assert needed == ["libc.so.6"]
    assert search == []


def test_elf_parser_rejects_truncation_and_out_of_range_dynamic_string(tmp_path: Path) -> None:
    short = tmp_path / "short.so"
    write(short, b"\x7fELF")
    with pytest.raises(closure.ClosureError, match="header"):
        closure._elf_dynamic(short)
    bad = tmp_path / "bad.so"
    write(bad, synthetic_elf(needed_offset=999))
    with pytest.raises(closure.ClosureError, match="string index"):
        closure._elf_dynamic(bad)


def _copied_ldconfig(tmp_path: Path) -> Path:
    sources = (
        closure.LDCONFIG,
        Path("/usr/sbin/ldconfig"),
        Path("/sbin/ldconfig"),
    )
    source = next((path for path in sources if path.is_file()), None)
    if sys.platform != "linux" or source is None:
        pytest.skip("requires a Linux ldconfig executable")
    target = tmp_path / "ldconfig.real"
    shutil.copyfile(source, target)
    target.chmod(0o755)
    return target


def test_pinned_ldconfig_rejects_invalid_and_wrong_external_hash(
    tmp_path: Path,
) -> None:
    with pytest.raises(closure.ClosureError, match="SHA-256 is invalid"):
        closure._run_pinned_ldconfig(expected_sha256="invalid", test_mode=True)
    executable = _copied_ldconfig(tmp_path)
    actual, _ = closure._sha_file(executable, maximum=64 * 1024 * 1024)
    wrong = HEX_A if actual != HEX_A else HEX_B
    with pytest.raises(closure.ClosureError, match="digest mismatch"):
        closure._run_pinned_ldconfig(
            expected_sha256=wrong,
            ldconfig=executable,
            test_mode=True,
        )


def test_pinned_ldconfig_executes_hashed_inode_and_lists_real_cache(
    tmp_path: Path,
) -> None:
    executable = _copied_ldconfig(tmp_path)
    digest, _ = closure._sha_file(executable, maximum=64 * 1024 * 1024)
    mapping = closure._ld_cache_mapping(
        expected_ldconfig_sha256=digest,
        ldconfig=executable,
        test_mode=True,
    )
    assert mapping
    assert any(name.startswith("libc.so") for name in mapping)


def test_pinned_ldconfig_rejects_path_replacement_after_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = _copied_ldconfig(tmp_path)
    replacement = tmp_path / "replacement"
    shutil.copyfile(executable, replacement)
    replacement.chmod(0o755)
    digest, _ = closure._sha_file(executable, maximum=64 * 1024 * 1024)
    real_popen = subprocess.Popen
    replaced = False

    def replacing_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        nonlocal replaced
        os.replace(replacement, executable)
        replaced = True
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(closure.subprocess, "Popen", replacing_popen)
    with pytest.raises(closure.ClosureError, match="changed across pinned execution"):
        closure._run_pinned_ldconfig(
            expected_sha256=digest,
            ldconfig=executable,
            test_mode=True,
        )
    assert replaced is True


def test_native_derivation_never_calls_ldd_or_executes_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elf = tmp_path / "payload.so"
    libc = tmp_path / "libc.so.6"
    write(elf, synthetic_elf())
    write(libc, synthetic_elf(needed_offset=None))
    monkeypatch.setattr(closure, "_ld_cache_mapping", lambda **_kwargs: {"libc.so.6": [libc]})

    roots = closure._native_dependency_roots(
        [closure.SourceItem(elf, closure.PurePosixPath("odoo-server/payload.so"), "core")],
        expected_ldconfig_sha256=HEX_A,
        test_mode=True,
    )
    assert libc.resolve() in roots


def test_loader_preload_lib_token_and_injected_elf_are_sealed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    preload = tmp_path / "etc/ld.so.preload"
    library = tmp_path / "lib/x86_64-linux-gnu/libonion.so"
    libc = tmp_path / "libc.so.6"
    payload = b"/$LIB/libonion.so\n"
    write(preload, payload)
    write(library, synthetic_elf(), 0o444)
    write(libc, synthetic_elf(needed_offset=None), 0o444)
    library.chmod(0o444)
    libc.chmod(0o444)
    original_mode_owner = closure._mode_owner

    def mode_owner(path: Path, **kwargs: object) -> object:
        if path == preload:
            return path.lstat()
        return original_mode_owner(path, **kwargs)

    monkeypatch.setattr(closure, "_mode_owner", mode_owner)
    identity = closure._validate_loader_preload(
        expected_sha256=sha(payload),
        root=tmp_path,
        test_mode=True,
    )
    assert identity["loader_token_profile"] == "glibc-x86_64-debian-lib-v1"
    assert identity["libraries"] == [
        {
            "configured_path": "/$LIB/libonion.so",
            "expanded_path": "/lib/x86_64-linux-gnu/libonion.so",
            "rooted_path": str(library),
            "resolved_path": str(library.resolve()),
        }
    ]
    external = closure.external_runtime_manifest([preload, library])
    for entry in external["entries"]:
        if entry["path"] == str(preload):
            entry["mode"] = "0644"
    closure._require_loader_preload_in_external_manifest(
        external, identity=identity
    )
    missing_library = json.loads(json.dumps(external))
    missing_library["entries"] = [
        entry
        for entry in missing_library["entries"]
        if entry["path"] != str(library)
    ]
    with pytest.raises(closure.ClosureError, match="omits a loader preload"):
        closure._require_loader_preload_in_external_manifest(
            missing_library, identity=identity
        )
    monkeypatch.setattr(
        closure, "_ld_cache_mapping", lambda **_kwargs: {"libc.so.6": [libc]}
    )
    roots = closure._native_dependency_roots(
        [],
        expected_ldconfig_sha256=HEX_A,
        injected_elfs=[library],
        test_mode=True,
    )
    assert library in roots
    assert libc.resolve() in roots
    with pytest.raises(closure.ClosureError, match="digest mismatch"):
        closure._validate_loader_preload(
            expected_sha256=HEX_A,
            root=tmp_path,
            test_mode=True,
        )


def test_external_runtime_manifest_is_canonical_and_requires_fixed_roots(
    tmp_path: Path,
) -> None:
    python = tmp_path / "usr/bin/python3.12"
    stdlib = tmp_path / "usr/lib/python3.12"
    cache = tmp_path / "etc/ld.so.cache"
    preload = tmp_path / "etc/ld.so.preload"
    write(python, b"python")
    write(stdlib / "os.py", b"pass\n")
    write(cache, b"cache")
    write(preload, b"/$LIB/libfixture.so\n")
    document = closure.external_runtime_manifest([stdlib, cache, preload, python])
    closure._validate_external_document(document, root=tmp_path)
    assert document["roots"] == sorted(document["roots"])
    missing = json.loads(json.dumps(document))
    missing["roots"].remove(str(cache.absolute()))
    with pytest.raises(closure.ClosureError, match="fixed runtime root"):
        closure._validate_external_document(missing, root=tmp_path)


def test_system_python_digest_is_fixed_and_present_in_external_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    python = tmp_path / "usr/bin/python3.12"
    write(python, b"sealed-system-python", 0o755)
    metadata = python.lstat()
    monkeypatch.setattr(
        closure,
        "_mode_owner",
        lambda path, **_kwargs: path.lstat(),
    )
    identity = closure._validate_system_python(
        expected_sha256=sha(b"sealed-system-python"),
        root=tmp_path,
        test_mode=True,
    )
    assert identity["path"] == str(python)
    document = {
        "entries": [
            {
                "path": str(python),
                "mode": "0755",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "kind": "regular",
                "size": len(b"sealed-system-python"),
                "sha256": identity["sha256"],
            }
        ]
    }
    closure._require_system_python_in_external_manifest(
        document,
        root=tmp_path,
        expected_sha256=identity["sha256"],
        expected_uid=metadata.st_uid,
        expected_gid=metadata.st_gid,
    )
    with pytest.raises(closure.ClosureError, match="digest mismatch"):
        closure._validate_system_python(
            expected_sha256=HEX_A,
            root=tmp_path,
            test_mode=True,
        )


def test_cli_interpreter_guard_runs_before_argparse_and_rejects_this_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(closure.ClosureError, match="exact /usr/bin/python3.12 -I -S"):
        closure._validate_cli_interpreter(HEX_A, HEX_B)
    calls: list[str] = []

    def reject(value: str, preload: str) -> dict[str, object]:
        calls.append(value)
        assert preload == HEX_B
        raise closure.ClosureError("bootstrap sentinel")

    monkeypatch.setattr(closure, "_validate_cli_interpreter", reject)
    monkeypatch.setattr(
        closure,
        "_parser",
        lambda: (_ for _ in ()).throw(AssertionError("argparse ran before guard")),
    )
    assert closure.main(
        [
            "verify",
            "--expected-system-python-sha256",
            HEX_A,
            "--expected-ld-so-preload-sha256",
            HEX_B,
        ]
    ) == 2
    assert calls == [HEX_A]
    with pytest.raises(closure.ClosureError, match="exactly once"):
        closure._expected_system_python_from_argv(
            [
                "verify",
                "--expected-system-python-sha256",
                HEX_A,
                "--expected-system-python-sha256=" + HEX_A,
            ]
        )


def test_discovery_and_double_image_drift_fail_closed() -> None:
    closure._require_discovery_unchanged((graph(), ["mapping"]), (graph(), ["mapping"]), phase="test")
    changed = graph()
    changed["modules"] = []
    with pytest.raises(closure.ClosureError, match="before copy"):
        closure._require_discovery_unchanged(
            (graph(), ["mapping"]), (changed, ["mapping"]), phase="before copy"
        )
    closure._require_reproducible_images(HEX_A, HEX_A)
    with pytest.raises(closure.ClosureError, match="two deterministic"):
        closure._require_reproducible_images(HEX_A, HEX_B)


def test_module_payload_mapping_rejects_unregistered_addon_directory() -> None:
    payload = {
        "schema_version": 1,
        "entries": [
            {"path": "odoo-server/odoo/addons/base", "kind": "directory"},
            {
                "path": "odoo-server/odoo/addons/base/__manifest__.py",
                "kind": "regular",
                "sha256": HEX_A,
                "size": 1,
            },
        ],
    }
    mapping = [{"name": "base", "source": "builtin"}]
    result = closure._module_payload_mapping(payload, mapping)
    assert result[0]["destination"] == "odoo-server/odoo/addons/base"
    payload["entries"].append(
        {"path": "custom-addons/rogue", "kind": "directory"}
    )
    with pytest.raises(closure.ClosureError, match="custom module set"):
        closure._module_payload_mapping(payload, mapping)


def test_capacity_gate_same_filesystem_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = closure.build_layout(tmp_path, expected())
    layout.build_parent.mkdir(parents=True)
    layout.image_parent.mkdir(parents=True)
    floor = 2 * 1024**3

    monkeypatch.setattr(
        closure.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=10**12, used=0, free=floor + 299),
    )
    with pytest.raises(closure.ClosureError, match="stage, image"):
        closure._capacity_gate(
            layout,
            stage_upper=100,
            image_upper=200,
            phase="before_stage",
            test_mode=False,
        )
    monkeypatch.setattr(
        closure.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=10**12, used=0, free=floor + 300),
    )
    closure._capacity_gate(
        layout,
        stage_upper=100,
        image_upper=200,
        phase="before_stage",
        test_mode=False,
    )


def test_capacity_gate_cross_filesystem_checks_each_residual_floor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = closure.build_layout(tmp_path, expected())
    layout.build_parent.mkdir(parents=True)
    layout.image_parent.mkdir(parents=True)
    original_stat = Path.stat

    def fake_stat(path: Path, *args: object, **kwargs: object) -> object:
        if path == layout.build_parent:
            return SimpleNamespace(st_dev=1)
        if path == layout.image_parent:
            return SimpleNamespace(st_dev=2)
        return original_stat(path, *args, **kwargs)

    floor = 2 * 1024**3
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(
        closure.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(
            total=10**12,
            used=0,
            free=floor + (99 if path == layout.build_parent else 200),
        ),
    )
    with pytest.raises(closure.ClosureError, match="cross-filesystem"):
        closure._capacity_gate(
            layout,
            stage_upper=100,
            image_upper=200,
            phase="before_stage",
            test_mode=False,
        )


def test_loop_status_rejects_inode_rebind_and_missing_read_only_flag() -> None:
    metadata = SimpleNamespace(st_dev=123, st_ino=456)

    def status(*, device: int = 123, inode: int = 456, flags: int = 5) -> bytearray:
        value = bytearray(232)
        struct.pack_into("=QQQQQ", value, 0, device, inode, 0, 0, 0)
        struct.pack_into("=IIII", value, 40, 7, 0, 0, flags)
        return value

    assert closure._validate_loop_status(
        status(), image_metadata=metadata, expected_image_stat=metadata
    )["loop_read_only"] is True
    assert closure._validate_loop_status(
        status(), image_metadata=metadata, expected_image_stat=metadata
    )["loop_autoclear"] is True
    with pytest.raises(closure.ClosureError, match="current full image inode"):
        closure._validate_loop_status(
            status(inode=999), image_metadata=metadata, expected_image_stat=metadata
        )
    with pytest.raises(closure.ClosureError, match="current full image inode"):
        closure._validate_loop_status(
            status(flags=4), image_metadata=metadata, expected_image_stat=metadata
        )
    with pytest.raises(closure.ClosureError, match="current full image inode"):
        closure._validate_loop_status(
            status(flags=1), image_metadata=metadata, expected_image_stat=metadata
        )


def test_mount_observation_rejects_host_pid1_namespace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = closure.build_layout(tmp_path, expected())
    original_stat = Path.stat

    def fake_stat(path: Path, *args: object, **kwargs: object) -> object:
        normalized = str(path).replace("\\", "/")
        if normalized.endswith("/proc/self/ns/mnt") or normalized.endswith("/proc/1/ns/mnt"):
            return SimpleNamespace(st_dev=4, st_ino=100)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    with pytest.raises(closure.ClosureError, match="private mount namespace"):
        closure._mount_observation(layout)


def test_mountinfo_parser_requires_positive_integer_mount_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _path: b"0 1 8:1 / / ro,nodev,nosuid - ext4 /dev/sda1 rw\n",
    )
    with pytest.raises(closure.ClosureError, match="mount identity"):
        closure._mountinfo_rows(process="self")


@pytest.mark.parametrize(
    "root_field,options,source,error",
    [
        ("/subtree", "ro,nodev,nosuid", "/dev/loop0", "strict read-only"),
        ("/", "rw,nodev,nosuid", "/dev/loop0", "strict read-only"),
        ("/", "ro,nodev,nosuid", "/tmp/not-loop", "canonical loop"),
    ],
)
def test_mountinfo_root_options_and_source_spoofing_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root_field: str,
    options: str,
    source: str,
    error: str,
) -> None:
    layout = closure.build_layout(tmp_path, expected())
    layout = replace(
        layout,
        mount_point=closure.PurePosixPath(
            f"/opt/odoo-accounting-cli-v3/dependencies/{RELEASE}"
        ),
        image=closure.PurePosixPath(
            f"/opt/odoo-accounting-cli-v3/dependency-images/{RELEASE}.squashfs"
        ),
    )
    original_stat = Path.stat
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def fake_stat(path: Path, *args: object, **kwargs: object) -> object:
        normalized = str(path).replace("\\", "/")
        if normalized.endswith("/proc/self/ns/mnt"):
            return SimpleNamespace(st_dev=4, st_ino=101)
        if normalized.endswith("/proc/1/ns/mnt"):
            return SimpleNamespace(st_dev=4, st_ino=100)
        return original_stat(path, *args, **kwargs)

    payload = (
        f"29 1 7:0 {root_field} {layout.mount_point} {options} - squashfs {source} ro,nodev,nosuid\n"
    ).encode("ascii")

    def fake_read_bytes(path: Path) -> bytes:
        if str(path).replace("\\", "/").endswith("/proc/self/mountinfo"):
            return payload
        return original_read_bytes(path)

    def fake_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if "loop/backing_file" in str(path):
            return str(layout.image) + "\n"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(Path, "read_bytes", fake_read_bytes)
    monkeypatch.setattr(Path, "read_text", fake_read_text)
    with pytest.raises(closure.ClosureError, match=error):
        closure._mount_observation(layout)


def minimal_closure_manifest() -> dict[str, object]:
    installed = {
        "count": 1,
        "names": ["base"],
        "names_sha256": closure.canonical_sha256(["base"]),
        "database_graph_sha256": HEX_A,
        "module_mapping_sha256": HEX_B,
        "module_payload_mapping_sha256": HEX_A,
        "resolver_precedence": ["builtin", "community", "custom"],
        "mapping": [],
    }
    return {
        "installed_modules": installed,
        "database_scope": {"database_name": DB_NAME, "database_uuid": DB_UUID},
        "external_runtime_manifest_sha256": HEX_A,
        "python_path_audit_sha256": HEX_B,
    }


def test_anchor_requires_two_identical_builds_and_stable_database_graph(tmp_path: Path) -> None:
    layout = closure.build_layout(tmp_path, expected())
    partial = minimal_closure_manifest()
    external = {
        "schema_version": 1,
        "python_abi": "3.12",
        "roots": ["/etc/ld.so.cache", "/usr/bin/python3.12", "/usr/lib/python3.12"],
        "entries": [],
    }
    anchor = closure._anchor_document(
        layout=layout,
        expected=expected(),
        closure_manifest=partial,
        image_sha256=HEX_A,
        source_before=HEX_B,
        source_after=HEX_B,
        external_manifest=external,
        config_sha256=HEX_A,
        mksquashfs_sha256=HEX_B,
        reproducible_image_sha256=HEX_A,
        system_python_sha256=HEX_B,
        loader_preload_sha256=HEX_A,
    )
    closure._validate_anchor_shape(
        anchor,
        layout=layout,
        expected=expected(),
        database_name=DB_NAME,
        database_uuid=DB_UUID,
        expected_config_sha256=HEX_A,
        expected_system_python_sha256=HEX_B,
        expected_loader_preload_sha256=HEX_A,
    )
    tampered = json.loads(json.dumps(anchor))
    tampered["reproducibility"]["build_count"] = 1
    with pytest.raises(closure.ClosureError, match="anchor invariant"):
        closure._validate_anchor_shape(
            tampered,
            layout=layout,
            expected=expected(),
            database_name=DB_NAME,
            database_uuid=DB_UUID,
            expected_config_sha256=HEX_A,
            expected_system_python_sha256=HEX_B,
            expected_loader_preload_sha256=HEX_A,
        )
    tampered = json.loads(json.dumps(anchor))
    tampered["database_graph_sha256_after"] = HEX_B
    with pytest.raises(closure.ClosureError, match="anchor invariant"):
        closure._validate_anchor_shape(
            tampered,
            layout=layout,
            expected=expected(),
            database_name=DB_NAME,
            database_uuid=DB_UUID,
            expected_config_sha256=HEX_A,
            expected_system_python_sha256=HEX_B,
            expected_loader_preload_sha256=HEX_A,
        )
    tampered = json.loads(json.dumps(anchor))
    tampered["system_python_sha256"] = HEX_A
    with pytest.raises(closure.ClosureError, match="anchor invariant"):
        closure._validate_anchor_shape(
            tampered,
            layout=layout,
            expected=expected(),
            database_name=DB_NAME,
            database_uuid=DB_UUID,
            expected_config_sha256=HEX_A,
            expected_system_python_sha256=HEX_B,
            expected_loader_preload_sha256=HEX_A,
        )


def fake_layout(tmp_path: Path) -> closure.Layout:
    layout = closure.build_layout(tmp_path, expected())
    layout.image.parent.mkdir(parents=True, exist_ok=True)
    layout.mount_parent.mkdir(parents=True, exist_ok=True)
    write(layout.image, b"image")
    return layout


def test_mount_preverification_happens_before_kernel_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = fake_layout(tmp_path)
    calls: list[list[str]] = []
    monkeypatch.setattr(closure, "_require_root", lambda **_kwargs: (0, 0))
    monkeypatch.setattr(closure, "build_layout", lambda *_args, **_kwargs: layout)
    monkeypatch.setattr(closure, "_ensure_parent_chain", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(closure, "_lock", lambda *_args, **_kwargs: (1, lambda: None))
    monkeypatch.setattr(
        closure,
        "_preverify_mount_artifacts",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            closure.ClosureError("preverify sentinel")
        ),
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    with pytest.raises(closure.ClosureError, match="preverify sentinel"):
        closure.mount(
            expected(),
            expected_closure_anchor_sha256=HEX_A,
            expected_closure_image_sha256=HEX_B,
            expected_system_python_sha256=HEX_A,
            expected_loader_preload_sha256=HEX_B,
            expected_ldconfig_sha256=HEX_A,
            expected_odoo_config_sha256=HEX_A,
            expected_database_name=DB_NAME,
            expected_database_uuid=DB_UUID,
            command_runner=runner,
        )
    assert calls == []


def test_failed_post_mount_verification_unmounts_and_closes_retained_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = fake_layout(tmp_path)
    image_descriptor = os.open(layout.image, os.O_RDONLY)
    image_stat = os.fstat(image_descriptor)
    calls: list[list[str]] = []
    observations = iter(
        [closure.ClosureError("closure mount is missing or ambiguous"), {"ok": True}]
    )
    monkeypatch.setattr(closure, "_require_root", lambda **_kwargs: (0, 0))
    monkeypatch.setattr(closure, "build_layout", lambda *_args, **_kwargs: layout)
    monkeypatch.setattr(closure, "_ensure_parent_chain", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(closure, "_lock", lambda *_args, **_kwargs: (1, lambda: None))
    monkeypatch.setattr(
        closure,
        "_preverify_mount_artifacts",
        lambda *_args, **_kwargs: (layout, image_descriptor, image_stat),
    )

    def observation(*_args: object, **_kwargs: object) -> dict[str, object]:
        value = next(observations)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(closure, "_mount_observation", observation)
    monkeypatch.setattr(closure, "_verified_program", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(closure, "_loop_backings_for_image", lambda *_args: [])
    monkeypatch.setattr(closure, "_mountinfo_rows", lambda **_kwargs: [])
    monkeypatch.setattr(
        closure.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(pw_gid=os.getgid() if hasattr(os, "getgid") else 0),
    )
    monkeypatch.setattr(closure.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(
        closure,
        "verify",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            closure.ClosureError("full verify sentinel")
        ),
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    with pytest.raises(closure.ClosureError, match="full verify sentinel"):
        closure.mount(
            expected(),
            expected_closure_anchor_sha256=HEX_A,
            expected_closure_image_sha256=HEX_B,
            expected_system_python_sha256=HEX_A,
            expected_loader_preload_sha256=HEX_B,
            expected_ldconfig_sha256=HEX_A,
            expected_odoo_config_sha256=HEX_A,
            expected_database_name=DB_NAME,
            expected_database_uuid=DB_UUID,
            command_runner=runner,
        )
    assert calls[0][0] == str(closure.MOUNT)
    assert calls[-1][0].replace("\\", "/").endswith("/usr/bin/umount")
    with pytest.raises(OSError):
        os.fstat(image_descriptor)


def test_supervisor_activates_four_binds_then_remounts_each_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = fake_layout(tmp_path)
    bindings: list[dict[str, str]] = []
    for index in range(3):
        source = tmp_path / f"source-{index}"
        destination = tmp_path / f"destination-{index}"
        source.mkdir()
        destination.mkdir()
        bindings.append({"source": str(source), "destination": str(destination)})
    config_source = tmp_path / "sealed.conf"
    config_destination = tmp_path / "target.conf"
    write(config_source, b"sealed")
    write(config_destination, b"placeholder")
    bindings.append(
        {"source": str(config_source), "destination": str(config_destination)}
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(closure, "_binds", lambda _layout: bindings)
    monkeypatch.setattr(closure, "_verified_program", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(closure, "_mountinfo_rows", lambda **_kwargs: [])
    monkeypatch.setattr(
        closure,
        "_binding_observation",
        lambda _layout: [{"source": item["source"]} for item in bindings],
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    result = closure._activate_bindings(layout, runner=runner)
    assert len(result) == 4
    assert len(calls) == 8
    for index, binding in enumerate(bindings):
        assert calls[index * 2] == [
            str(closure.MOUNT),
            "--bind",
            binding["source"],
            binding["destination"],
        ]
        assert calls[index * 2 + 1] == [
            str(closure.MOUNT),
            "-o",
            "remount,bind,ro,nodev,nosuid",
            binding["source"],
            binding["destination"],
        ]
    assert calls[-2][-2:] == [str(config_source), str(config_destination)]


def test_binding_observation_accepts_read_only_vfs_on_writable_superblock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = fake_layout(tmp_path)
    source = tmp_path / "sealed-source"
    destination = tmp_path / "sealed-destination"
    write(source, b"sealed")
    write(destination, b"placeholder")
    binding = {"source": str(source), "destination": str(destination)}
    identity = SimpleNamespace(st_dev=9, st_ino=10, st_mode=stat.S_IFREG | 0o444)
    original_stat = Path.stat

    def fake_stat(path: Path, *args: object, **kwargs: object) -> object:
        if path in {source, destination}:
            return identity
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(closure, "_binds", lambda _layout: [binding])
    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(
        closure,
        "_mountinfo_rows",
        lambda **_kwargs: [
            {
                "mount_id": 29,
                "mount_point": str(destination),
                "major_minor": "8:1",
                "filesystem_type": "ext4",
                "mount_options": ["ro", "nodev", "nosuid"],
                "super_options": ["rw", "relatime"],
            }
        ],
    )
    monkeypatch.setattr(
        closure.os,
        "statvfs",
        lambda _path: SimpleNamespace(f_flag=getattr(os, "ST_RDONLY", 1)),
        raising=False,
    )
    result = closure._binding_observation(layout)
    assert result[0]["mount_id"] == 29
    assert result[0]["read_only"] is True


def test_deactivate_unmounts_reverse_order_and_proves_no_loop_or_host_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = fake_layout(tmp_path)
    bindings = [
        {
            "source": str(tmp_path / "source" / str(index)),
            "destination": str(tmp_path / "target" / str(index)),
        }
        for index in range(4)
    ]
    mounted = {item["destination"] for item in bindings} | {str(layout.mount_point)}
    loop_active = [True]
    calls: list[list[str]] = []
    monkeypatch.setattr(closure, "_binds", lambda _layout: bindings)
    monkeypatch.setattr(closure, "_verified_program", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        closure,
        "_namespace_identity",
        lambda *, process: {"device": 7, "inode": 101 if process == "self" else 100},
    )

    def mountinfo(*, process: str = "self") -> list[dict[str, object]]:
        if process == "1":
            return []
        return [{"mount_point": target} for target in sorted(mounted)]

    monkeypatch.setattr(closure, "_mountinfo_rows", mountinfo)
    monkeypatch.setattr(
        closure,
        "_loop_backings_for_image",
        lambda _image: ["/dev/loop7"] if loop_active[0] else [],
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        mounted.remove(command[-1])
        if command[-1] == str(layout.mount_point):
            loop_active[0] = False
        return subprocess.CompletedProcess(command, 0, b"", b"")

    baseline = {
        "schema_version": 1,
        "self_mount_namespace": {"device": 7, "inode": 101},
        "host_mount_namespace": {"device": 7, "inode": 100},
        "affected_mount_points": [
            str(layout.mount_point),
            *[item["destination"] for item in bindings],
        ],
        "self_rows": [],
        "host_rows": [],
        "loop_devices": [],
    }
    receipt = closure.deactivate(layout, baseline=baseline, runner=runner)
    expected_order = [
        *[item["destination"] for item in reversed(bindings)],
        str(layout.mount_point),
    ]
    assert [command[-1] for command in calls] == expected_order
    assert receipt["unmount_order"] == expected_order
    assert receipt["remaining_loop_devices"] == []
    assert receipt["loop_autoclear_required"] is True


def test_activated_closure_holds_lock_and_cleans_up_after_body_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = fake_layout(tmp_path)
    events: list[str] = []
    baseline = {
        "schema_version": 1,
        "self_mount_namespace": {"device": 7, "inode": 101},
        "host_mount_namespace": {"device": 7, "inode": 100},
        "affected_mount_points": closure._affected_mount_points(layout),
        "self_rows": [],
        "host_rows": [],
        "loop_devices": [],
    }
    monkeypatch.setattr(closure, "_require_root", lambda **_kwargs: (0, 0))
    monkeypatch.setattr(closure, "build_layout", lambda *_args, **_kwargs: layout)
    monkeypatch.setattr(closure, "_ensure_parent_chain", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        closure,
        "_lock",
        lambda *_args, **_kwargs: (
            events.append("lock") or 9,
            lambda: events.append("unlock"),
        ),
    )
    monkeypatch.setattr(
        closure,
        "_lifecycle_baseline",
        lambda _layout: events.append("baseline") or baseline,
    )

    def mounted(*_args: object, **kwargs: object) -> dict[str, object]:
        assert kwargs["_lock_held"] is True
        events.append("mount")
        return {"status": "verified"}

    monkeypatch.setattr(closure, "mount", mounted)
    monkeypatch.setattr(
        closure,
        "_activate_bindings",
        lambda *_args, **_kwargs: events.append("bind") or [],
    )
    monkeypatch.setattr(
        closure,
        "verify_active",
        lambda *_args, **_kwargs: events.append("verify")
        or {"status": "active_verified"},
    )
    monkeypatch.setattr(
        closure,
        "deactivate",
        lambda *_args, **_kwargs: events.append("deactivate")
        or {"status": "clean"},
    )
    with pytest.raises(RuntimeError, match="suite sentinel"):
        with closure.activated_closure(
            expected(),
            expected_system_python_sha256=HEX_A,
            expected_loader_preload_sha256=HEX_B,
            expected_ldconfig_sha256=HEX_A,
            expected_closure_anchor_sha256=HEX_A,
            expected_closure_image_sha256=HEX_B,
            expected_odoo_config_sha256=HEX_A,
            expected_database_name=DB_NAME,
            expected_database_uuid=DB_UUID,
        ):
            events.append("body")
            raise RuntimeError("suite sentinel")
    assert events == [
        "lock",
        "baseline",
        "mount",
        "bind",
        "verify",
        "body",
        "deactivate",
        "unlock",
    ]


def test_activation_setup_failure_still_runs_mandatory_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = fake_layout(tmp_path)
    events: list[str] = []
    baseline = {
        "schema_version": 1,
        "self_mount_namespace": {},
        "host_mount_namespace": {},
        "affected_mount_points": closure._affected_mount_points(layout),
        "self_rows": [],
        "host_rows": [],
        "loop_devices": [],
    }
    monkeypatch.setattr(closure, "_require_root", lambda **_kwargs: (0, 0))
    monkeypatch.setattr(closure, "build_layout", lambda *_args, **_kwargs: layout)
    monkeypatch.setattr(closure, "_ensure_parent_chain", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        closure,
        "_lock",
        lambda *_args, **_kwargs: (1, lambda: events.append("unlock")),
    )
    monkeypatch.setattr(closure, "_lifecycle_baseline", lambda _layout: baseline)
    monkeypatch.setattr(closure, "mount", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        closure,
        "_activate_bindings",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            closure.ClosureError("bind sentinel")
        ),
    )
    monkeypatch.setattr(
        closure,
        "deactivate",
        lambda *_args, **_kwargs: events.append("deactivate") or {"status": "clean"},
    )
    with pytest.raises(closure.ClosureError, match="bind sentinel"):
        with closure.activated_closure(
            expected(),
            expected_system_python_sha256=HEX_A,
            expected_loader_preload_sha256=HEX_B,
            expected_ldconfig_sha256=HEX_A,
            expected_closure_anchor_sha256=HEX_A,
            expected_closure_image_sha256=HEX_B,
            expected_odoo_config_sha256=HEX_A,
            expected_database_name=DB_NAME,
            expected_database_uuid=DB_UUID,
        ):
            raise AssertionError("unreachable")
    assert events == ["deactivate", "unlock"]


def test_cli_parser_requires_external_closure_digests_for_verify() -> None:
    parser = closure._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["verify"])
    values = parser.parse_args(
        [
            "verify",
            "--expected-release",
            RELEASE,
            "--expected-version",
            VERSION,
            "--expected-commit",
            COMMIT,
            "--expected-manifest-sha256",
            HEX_A,
            "--expected-package-sha256",
            HEX_B,
            "--expected-system-python-sha256",
            HEX_A,
            "--expected-ld-so-preload-sha256",
            HEX_B,
            "--expected-ldconfig-sha256",
            HEX_A,
            "--expected-odoo-config-sha256",
            HEX_A,
            "--expected-database-name",
            DB_NAME,
            "--expected-database-uuid",
            DB_UUID,
            "--expected-closure-anchor-sha256",
            HEX_A,
            "--expected-closure-image-sha256",
            HEX_B,
        ]
    )
    assert values.command == "verify"
    assert values.expected_ldconfig_sha256 == HEX_A


@pytest.mark.skipif(
    sys.platform != "linux"
    or not hasattr(os, "geteuid")
    or os.geteuid() != 0
    or os.environ.get("ODOO_CLOSURE_REAL_MOUNT_TEST") != "1"
    or shutil.which("mksquashfs") is None
    or shutil.which("mount") is None,
    reason="requires dedicated root Linux private-mount job with squashfs-tools",
)
def test_real_squashfs_loop_mount_read_only_inode_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stage = tmp_path / "stage"
    mount_point = tmp_path / "mount"
    image = tmp_path / "fixture.squashfs"
    config_source = tmp_path / "sealed.conf"
    config_destination = tmp_path / "bound.conf"
    stage.mkdir()
    mount_point.mkdir()
    write(stage / "proof.txt", b"immutable\n", 0o444)
    write(config_source, b"sealed\n", 0o440)
    write(config_destination, b"placeholder\n", 0o600)
    subprocess.run(
        [
            shutil.which("mksquashfs") or "mksquashfs",
            str(stage),
            str(image),
            "-noappend",
            "-all-root",
            "-no-progress",
            "-processors",
            "1",
            "-mkfs-time",
            "0",
            "-all-time",
            "0",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    image.chmod(0o444)
    layout = replace(
        closure.build_layout(tmp_path, expected()),
        image=image,
        mount_point=mount_point,
    )
    mounted = False
    config_bound = False
    try:
        subprocess.run(
            [
                shutil.which("mount") or "mount",
                "-t",
                "squashfs",
                "-o",
                "loop,ro,nodev,nosuid",
                str(image),
                str(mount_point),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        mounted = True
        observation = closure._mount_observation(
            layout, expected_image_stat=image.stat()
        )
        assert observation["loop_read_only"] is True
        assert observation["loop_autoclear"] is True
        assert observation["backing_image_inode"] == image.stat().st_ino
        assert (mount_point / "proof.txt").read_bytes() == b"immutable\n"
        subprocess.run(
            ["mount", "--bind", str(config_source), str(config_destination)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        config_bound = True
        subprocess.run(
            [
                "mount",
                "-o",
                "remount,bind,ro,nodev,nosuid",
                str(config_source),
                str(config_destination),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        monkeypatch.setattr(
            closure,
            "_binds",
            lambda _layout: [
                {
                    "source": str(config_source),
                    "destination": str(config_destination),
                }
            ],
        )
        binding = closure._binding_observation(layout)[0]
        assert binding["read_only"] is True
        assert binding["source_inode"] == config_source.stat().st_ino
        with pytest.raises(OSError):
            config_destination.write_bytes(b"must-fail")
    finally:
        if config_bound:
            subprocess.run(["umount", str(config_destination)], check=True)
        if mounted:
            subprocess.run(["umount", str(mount_point)], check=True)
    assert closure._loop_backings_for_image(image) == []

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from odoo_accounting_cli_v3.registry import load_registry, registry_digest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / "odoo_addons"
    / "odoo_accounting_cli_v3_control"
    / "models"
    / "release_binding.py"
)
VERSION = "1.2.3.dev1"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _load_module() -> ModuleType:
    name = "test_odoo_addon_release_binding"
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


binding = _load_module()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _freeze_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _anchored_release(
    tmp_path: Path,
    *,
    registry_raw: bytes = b'{"schema_version":1,"capabilities":[{"id":"account.read"}]}\n',
) -> tuple[Path, dict[str, Any]]:
    release_name = f"{VERSION}-{COMMIT[:12]}"
    base = tmp_path / "install"
    release_root = base / "releases" / release_name
    addon = release_root / "odoo_addons" / "odoo_accounting_cli_v3_control"
    models = addon / "models"
    registry_path = release_root / "registry" / "capabilities.json"
    models.mkdir(parents=True)
    registry_path.parent.mkdir(parents=True)
    base.chmod(0o755)
    (base / "releases").chmod(0o755)
    files = {
        addon / "__init__.py": b"from . import models\n",
        models / "__init__.py": b"from . import session_client\n",
        models / "release_binding.py": b"# manifest-bound verifier bytes\n",
        models / "session_client.py": b"# manifest-bound Odoo client bytes\n",
        registry_path: registry_raw,
    }
    for path, raw in files.items():
        path.write_bytes(raw)
    entries = [
        {
            "path": path.relative_to(release_root).as_posix(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
        for path, raw in sorted(files.items(), key=lambda item: item[0].as_posix())
    ]
    unsigned = {
        "schema_version": 1,
        "version": VERSION,
        "commit": COMMIT,
        "files": entries,
    }
    manifest_digest = hashlib.sha256(_canonical(unsigned)).hexdigest()
    manifest = {**unsigned, "manifest_sha256": manifest_digest}
    (release_root / "RELEASE-MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    anchors = base / "trusted-artifacts"
    anchors.mkdir()
    anchor_path = anchors / f"{release_name}.json"
    anchor_path.write_text(
        json.dumps(
            {
                "commit": COMMIT,
                "manifest_sha256": manifest_digest,
                "package_sha256": "f" * 64,
                "release": release_name,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    _freeze_tree(release_root)
    anchor_path.chmod(0o444)
    # Windows maps directory write bits coarsely; 0555 is stable on both CI OSes.
    anchors.chmod(0o555)
    return models / "session_client.py", manifest


def _make_writable(path: Path) -> None:
    path.chmod(0o755 if path.is_dir() else 0o644)


def test_verified_addon_release_is_derived_from_bytes_not_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_file, manifest = _anchored_release(tmp_path)
    monkeypatch.setenv("ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST", "e" * 64)
    monkeypatch.setenv("ODOO_ACCOUNTING_CLI_V3_REGISTRY_DIGEST", "d" * 64)

    verified = binding.verify_addon_release(
        module_file, require_root_owner=False
    )

    registry = json.loads(
        (module_file.parents[3] / "registry" / "capabilities.json").read_text(
            encoding="utf-8"
        )
    )
    assert verified.release_digest == manifest["manifest_sha256"]
    assert verified.registry_digest == hashlib.sha256(
        _canonical(registry["capabilities"])
    ).hexdigest()
    assert verified.release == f"{VERSION}-{COMMIT[:12]}"
    assert verified.version == VERSION
    assert verified.commit == COMMIT
    assert verified.release_digest != os.environ[
        "ODOO_ACCOUNTING_CLI_V3_RELEASE_DIGEST"
    ]


def test_registry_digest_exactly_matches_the_cli_registry_algorithm(
    tmp_path: Path,
) -> None:
    source_registry = ROOT / "registry" / "capabilities.json"
    module_file, _manifest = _anchored_release(
        tmp_path, registry_raw=source_registry.read_bytes()
    )
    verified = binding.verify_addon_release(module_file, require_root_owner=False)
    installed_registry = module_file.parents[3] / "registry" / "capabilities.json"
    assert verified.registry_digest == registry_digest(load_registry(installed_registry))


@pytest.mark.parametrize("target", ["addon", "registry", "manifest", "anchor"])
def test_any_bound_byte_or_external_anchor_tamper_fails_closed(
    tmp_path: Path, target: str
) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    release_root = module_file.parents[3]
    targets = {
        "addon": module_file,
        "registry": release_root / "registry" / "capabilities.json",
        "manifest": release_root / "RELEASE-MANIFEST.json",
        "anchor": (
            release_root.parent.parent
            / "trusted-artifacts"
            / f"{release_root.name}.json"
        ),
    }
    path = targets[target]
    _make_writable(path)
    if target in {"manifest", "anchor"}:
        document = json.loads(path.read_text(encoding="utf-8"))
        document["commit" if target == "manifest" else "manifest_sha256"] = "e" * (
            40 if target == "manifest" else 64
        )
        path.write_text(json.dumps(document), encoding="utf-8")
    else:
        path.write_bytes(path.read_bytes() + b" ")
    path.chmod(0o444)

    with pytest.raises(binding.AddonReleaseBindingError):
        binding.verify_addon_release(module_file, require_root_owner=False)


def test_unmanifested_addon_file_and_writable_member_are_rejected(
    tmp_path: Path,
) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    addon_root = module_file.parents[1]
    _make_writable(addon_root)
    extra = addon_root / "unreviewed.py"
    extra.write_text("raise RuntimeError\n", encoding="utf-8")
    extra.chmod(0o444)
    addon_root.chmod(0o555)
    with pytest.raises(binding.AddonReleaseBindingError, match="file set"):
        binding.verify_addon_release(module_file, require_root_owner=False)

    _make_writable(addon_root)
    _make_writable(extra)
    extra.unlink()
    addon_root.chmod(0o555)
    module_file.chmod(0o644)
    with pytest.raises(binding.AddonReleaseBindingError, match="immutable"):
        binding.verify_addon_release(module_file, require_root_owner=False)


@pytest.mark.parametrize("mutation", ["missing", "pycache"])
def test_missing_member_or_runtime_bytecode_is_rejected(
    tmp_path: Path, mutation: str
) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    addon_root = module_file.parents[1]
    models = module_file.parent
    _make_writable(addon_root)
    _make_writable(models)
    if mutation == "missing":
        missing = models / "release_binding.py"
        _make_writable(missing)
        missing.unlink()
    else:
        cache = models / "__pycache__"
        cache.mkdir()
        compiled = cache / "session_client.cpython-311.pyc"
        compiled.write_bytes(b"unmanifested bytecode")
        compiled.chmod(0o444)
        cache.chmod(0o555)
    models.chmod(0o555)
    addon_root.chmod(0o555)

    with pytest.raises(binding.AddonReleaseBindingError, match="file set"):
        binding.verify_addon_release(module_file, require_root_owner=False)


def test_hardlinked_addon_member_is_rejected(tmp_path: Path) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    alias = tmp_path / "session-client-alias.py"
    try:
        os.link(module_file, alias)
    except OSError as exc:  # pragma: no cover - filesystem-specific skip
        pytest.skip(f"hard links unavailable: {exc}")
    with pytest.raises(binding.AddonReleaseBindingError, match="immutable"):
        binding.verify_addon_release(module_file, require_root_owner=False)


def test_symlinked_addon_member_is_rejected(tmp_path: Path) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    models = module_file.parent
    target = models / "release_binding.py"
    external = tmp_path / "replacement.py"
    external.write_bytes(target.read_bytes())
    _make_writable(models)
    _make_writable(target)
    target.unlink()
    try:
        target.symlink_to(external)
    except OSError as exc:  # pragma: no cover - Windows privilege-dependent
        pytest.skip(f"symbolic links unavailable: {exc}")
    models.chmod(0o555)
    with pytest.raises(binding.AddonReleaseBindingError, match="forbidden"):
        binding.verify_addon_release(module_file, require_root_owner=False)


def test_release_name_and_noncanonical_module_path_are_rejected(
    tmp_path: Path,
) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    with pytest.raises(binding.AddonReleaseBindingError, match="absolute"):
        binding.verify_addon_release(
            Path("odoo_addons") / "session_client.py",
            require_root_owner=False,
        )

    release_root = module_file.parents[3]
    anchor = (
        release_root.parent.parent
        / "trusted-artifacts"
        / f"{release_root.name}.json"
    )
    anchor.chmod(0o644)
    document = json.loads(anchor.read_text(encoding="utf-8"))
    document["release"] = "different-release"
    anchor.write_text(json.dumps(document), encoding="utf-8")
    anchor.chmod(0o444)
    with pytest.raises(binding.AddonReleaseBindingError, match="external anchor"):
        binding.verify_addon_release(module_file, require_root_owner=False)


def test_release_directory_name_must_equal_manifest_version_and_commit(
    tmp_path: Path,
) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    release_root = module_file.parents[3]
    releases = release_root.parent
    base = releases.parent
    wrong_name = "1.2.3.dev1-deadbeefdead"
    wrong_root = releases / wrong_name
    releases.chmod(0o755)
    release_root.rename(wrong_root)
    wrong_anchor = base / "trusted-artifacts" / f"{wrong_name}.json"
    old_anchor = base / "trusted-artifacts" / f"{release_root.name}.json"
    _make_writable(old_anchor.parent)
    _make_writable(old_anchor)
    anchor = json.loads(old_anchor.read_text(encoding="utf-8"))
    anchor["release"] = wrong_name
    wrong_anchor.write_text(json.dumps(anchor), encoding="utf-8")
    wrong_anchor.chmod(0o444)
    old_anchor.unlink()
    old_anchor.parent.chmod(0o555)
    releases.chmod(0o555)
    wrong_module = wrong_root / module_file.relative_to(release_root)

    with pytest.raises(binding.AddonReleaseBindingError, match="external anchor"):
        binding.verify_addon_release(wrong_module, require_root_owner=False)


def test_duplicate_anchor_json_member_is_rejected(tmp_path: Path) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    release_root = module_file.parents[3]
    anchor = (
        release_root.parent.parent
        / "trusted-artifacts"
        / f"{release_root.name}.json"
    )
    document = json.loads(anchor.read_text(encoding="utf-8"))
    _make_writable(anchor)
    anchor.write_text(
        "{"
        f'"commit":"{document["commit"]}",'
        f'"commit":"{document["commit"]}",'
        f'"manifest_sha256":"{document["manifest_sha256"]}",'
        f'"package_sha256":"{document["package_sha256"]}",'
        f'"release":"{document["release"]}"'
        "}",
        encoding="utf-8",
    )
    anchor.chmod(0o444)
    with pytest.raises(binding.AddonReleaseBindingError, match="strict JSON"):
        binding.verify_addon_release(module_file, require_root_owner=False)


def test_writable_directory_and_nonroot_metadata_are_rejected(tmp_path: Path) -> None:
    writable = tmp_path / "writable"
    writable.mkdir()
    writable.chmod(0o777)
    with pytest.raises(binding.AddonReleaseBindingError, match="trusted directory"):
        binding._validate_directory(
            writable,
            "release ancestor",
            require_root_owner=False,
            immutable=False,
        )

    nonroot = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o444,
        st_nlink=1,
        st_uid=1000,
    )
    with pytest.raises(binding.AddonReleaseBindingError, match="immutable"):
        binding._validate_file_metadata(
            nonroot,
            "nonroot file",
            require_root_owner=True,
        )
    nonroot_ancestor = SimpleNamespace(
        st_mode=stat.S_IFDIR | 0o755,
        st_uid=1000,
    )
    with pytest.raises(binding.AddonReleaseBindingError, match="trusted directory"):
        binding._validate_directory_metadata(
            nonroot_ancestor,
            "nonroot release ancestor",
            require_root_owner=True,
            immutable=False,
        )


def test_production_verification_requires_linux_root_owned_artifacts(
    tmp_path: Path,
) -> None:
    module_file, _manifest = _anchored_release(tmp_path)
    if sys.platform != "linux" or os.name != "posix":
        with pytest.raises(binding.AddonReleaseBindingError, match="Linux"):
            binding.verify_addon_release(module_file)
    else:
        with pytest.raises(binding.AddonReleaseBindingError, match="trusted"):
            binding.verify_addon_release(module_file)


@pytest.mark.skipif(
    os.environ.get("ODOO_RELEASE_BINDING_RUN_ROOT_INTEGRATION") != "1",
    reason="requires the explicit Linux root integration gate",
)
def test_root_owned_release_verifies_in_real_linux_process() -> None:
    if sys.platform != "linux" or os.name != "posix" or os.geteuid() != 0:
        pytest.fail("the release-binding integration gate requires Linux root")

    fixture_root = Path(
        tempfile.mkdtemp(prefix="odoo-v3-addon-binding-", dir="/var/lib")
    )
    try:
        fixture_root.chmod(0o755)
        module_file, manifest = _anchored_release(fixture_root)
        verified = binding.verify_addon_release(module_file)
        assert verified.release_digest == manifest["manifest_sha256"]
        assert verified.release == f"{VERSION}-{COMMIT[:12]}"
        assert verified.version == VERSION
        assert verified.commit == COMMIT
    finally:
        for path in sorted(
            fixture_root.rglob("*"),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        fixture_root.chmod(0o700)
        shutil.rmtree(fixture_root)

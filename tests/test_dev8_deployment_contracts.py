from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENT = ROOT / "deployment" / "dev8"
ODOO_UID = 1000
ODOO_GID = 1000


def _load_server_module(name: str, filename: str):
    added: list[str] = []
    for module_name in ("fcntl", "grp", "pwd"):
        if importlib.util.find_spec(module_name) is None:
            sys.modules[module_name] = types.ModuleType(module_name)
            added.append(module_name)
    try:
        spec = importlib.util.spec_from_file_location(name, DEPLOYMENT / filename)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for module_name in added:
            sys.modules.pop(module_name, None)


@pytest.fixture(scope="module")
def verifier():
    return _load_server_module("dev8_verify_contract", "dev8-verify-frozen-evidence.py")


@pytest.fixture(scope="module")
def freezer():
    return _load_server_module("dev8_freeze_contract", "dev8-freeze-evidence.py")


def _parent(path: str, inode: int, uid: int = 0, gid: int = 0, mode: int = 0o755):
    return {
        "path": path,
        "identity": {
            "dev": 1,
            "ino": inode,
            "kind": "directory",
            "uid": uid,
            "gid": gid,
            "mode": mode,
        },
    }


def _identity(module, plan, inode: int, *, size: int = 17, digest: str = "1" * 64):
    value = {
        "dev": 2,
        "ino": inode,
        "kind": plan["kind"],
        "uid": plan["uid"],
        "gid": plan["gid"],
        "mode": plan["modes"][-1],
    }
    if plan["kind"] == "file":
        value.update({"size": size, "sha256": digest})
    return value


def _legal_journals(module):
    install_id = "a" * 32
    runtime_id = "b" * 32
    release = module.RELEASE
    root = Path("/opt/odoo-accounting-cli-v3")
    releases = root / "releases"
    packages = root / "packages"
    anchors = root / "trusted-artifacts"
    config_parent = Path("/etc/odoo-accounting-cli-v3")
    candidate_parent = Path("/var/lib/odoo-accounting-cli-v3/test/candidates")
    candidate_staging_parent = Path("/var/lib/odoo-accounting-cli-v3/dev8-transaction-staging")
    secret_parent = config_parent / "secrets/test"
    package_name = f"odoo-accounting-cli-v3-{release}.tar.gz"

    install_plans = {
        "package_staging": module.journal_object_plan(packages / f".{package_name}.{install_id}.staging", "file", 0, 0, [0o400, 0o444], True, None),
        "anchor_staging": module.journal_object_plan(anchors / f".{release}.{install_id}.anchor.staging", "file", 0, 0, [0o400, 0o444], True, None),
        "release_staging": module.journal_object_plan(releases / f".{release}.{install_id}.release.staging", "directory", 0, 0, [0o555], True, None),
        "package": module.journal_object_plan(packages / package_name, "file", 0, 0, [0o444], False, "package_staging"),
        "release": module.journal_object_plan(releases / release, "directory", 0, 0, [0o555], False, "release_staging"),
        "anchor": module.journal_object_plan(anchors / f"{release}.json", "file", 0, 0, [0o444], False, "anchor_staging"),
    }
    odoo_owner = [ODOO_UID, ODOO_GID]
    runtime_plans = {
        "config_staging": module.journal_object_plan(config_parent / f".runtime-test-dev8.json.{runtime_id}.staging", "file", 0, 0, [0o644], True, None, unrecorded_owners=[[0, 0]], unrecorded_modes=[0o600, 0o644]),
        "candidate_staging": module.journal_object_plan(candidate_staging_parent / f".{release}.{runtime_id}.candidate.staging", "directory", ODOO_UID, ODOO_GID, [0o700], True, None, unrecorded_owners=[[0, 0], odoo_owner], unrecorded_modes=[0o700]),
        "auth_staging": module.journal_object_plan(secret_parent / f".dev8-auth.{runtime_id}.hmac.staging", "file", 0, ODOO_GID, [0o640], True, None, unrecorded_owners=[[0, 0], [0, ODOO_GID]], unrecorded_modes=[0o600, 0o640]),
        "receipt_staging": module.journal_object_plan(secret_parent / f".dev8-receipt.{runtime_id}.hmac.staging", "file", 0, ODOO_GID, [0o640], True, None, unrecorded_owners=[[0, 0], [0, ODOO_GID]], unrecorded_modes=[0o600, 0o640]),
        "config": module.journal_object_plan(config_parent / "runtime-test-dev8.json", "file", 0, 0, [0o644], False, "config_staging", unrecorded_owners=[[0, 0]], unrecorded_modes=[0o644]),
        "candidate": module.journal_object_plan(candidate_parent / release, "directory", ODOO_UID, ODOO_GID, [0o700], False, "candidate_staging", unrecorded_owners=[odoo_owner], unrecorded_modes=[0o700]),
        "auth_secret": module.journal_object_plan(secret_parent / "dev8-auth.hmac", "file", 0, ODOO_GID, [0o640], False, "auth_staging", unrecorded_owners=[[0, ODOO_GID]], unrecorded_modes=[0o640]),
        "receipt_secret": module.journal_object_plan(secret_parent / "dev8-receipt.hmac", "file", 0, ODOO_GID, [0o640], False, "receipt_staging", unrecorded_owners=[[0, ODOO_GID]], unrecorded_modes=[0o640]),
    }

    install_pairs = (
        ("package_staging", "package"),
        ("anchor_staging", "anchor"),
        ("release_staging", "release"),
    )
    for inode, (source, target) in enumerate(install_pairs, 100):
        size = module.PACKAGE_SIZE if target == "package" else 17
        digest = module.PACKAGE_SHA256 if target == "package" else "1" * 64
        identity = _identity(module, install_plans[target], inode, size=size, digest=digest)
        install_plans[source]["identity"] = copy.deepcopy(identity)
        install_plans[target]["identity"] = copy.deepcopy(identity)

    runtime_pairs = (
        ("config_staging", "config"),
        ("candidate_staging", "candidate"),
        ("auth_staging", "auth_secret"),
        ("receipt_staging", "receipt_secret"),
    )
    for inode, (source, target) in enumerate(runtime_pairs, 200):
        identity = _identity(module, runtime_plans[target], inode)
        runtime_plans[source]["identity"] = copy.deepcopy(identity)
        runtime_plans[target]["identity"] = copy.deepcopy(identity)

    install = {
        "schema_version": 1,
        "kind": "install",
        "release": release,
        "transaction_id": install_id,
        "state": "completed",
        "parents": {
            "root": _parent(str(root), 10),
            "releases": _parent(str(releases), 11),
            "packages": _parent(str(packages), 12),
            "anchors": _parent(str(anchors), 13),
        },
        "objects": install_plans,
    }
    binding = {
        "anchor": install_plans["anchor"]["identity"],
        "install_transaction_id": install_id,
        "manifest_sha256": module.MANIFEST_SHA256,
        "package": install_plans["package"]["identity"],
        "registry_digest": module.REGISTRY_DIGEST,
        "release": install_plans["release"]["identity"],
    }
    runtime = {
        "schema_version": 1,
        "kind": "runtime",
        "release": release,
        "transaction_id": runtime_id,
        "state": "completed",
        "parents": {
            "config_parent": _parent(str(config_parent), 20),
            "candidate_parent": _parent(str(candidate_parent), 21, mode=0o700),
            "candidate_staging_parent": _parent(str(candidate_staging_parent), 22, mode=0o700),
            "secret_parent": _parent(str(secret_parent), 23, gid=ODOO_GID, mode=0o750),
        },
        "objects": runtime_plans,
        "upstream_install_transaction_id": install_id,
        "upstream_install_identity_sha256": hashlib.sha256(module.canonical(binding)).hexdigest(),
    }
    return install, runtime


def test_legal_completed_journal_contract_is_accepted(verifier):
    install, runtime = _legal_journals(verifier)
    result = verifier.validate_completed_journals(
        install, runtime, ODOO_UID, ODOO_GID, compare_live=False
    )
    assert result["install_transaction_id"] == "a" * 32
    assert result["runtime_transaction_id"] == "b" * 32


def test_freezer_accepts_the_same_legal_contract(freezer, monkeypatch):
    install, runtime = _legal_journals(freezer)
    identities = {
        record["path"]: record["identity"]
        for record in [*install["parents"].values(), *runtime["parents"].values()]
    }
    for document in (install, runtime):
        identities.update(
            {
                record["path"]: record["identity"]
                for record in document["objects"].values()
                if record["unique"] is False
            }
        )
    monkeypatch.setattr(
        freezer,
        "current_journal_identity",
        lambda path, kind: copy.deepcopy(identities[str(path)]),
    )
    monkeypatch.setattr(freezer.os.path, "lexists", lambda path: False)
    result = freezer.validate_completed_journals(install, runtime, ODOO_UID, ODOO_GID)
    assert result["install_transaction_id"] == "a" * 32


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
def test_toolchain_and_server_baseline_contracts_are_accepted(request, fixture_name):
    module = request.getfixturevalue(fixture_name)
    manifest = json.loads((DEPLOYMENT / "TOOLCHAIN-MANIFEST.json").read_text("utf-8"))
    baseline = json.loads((DEPLOYMENT / "SERVER-BASELINE.json").read_text("utf-8"))
    entries = module.validate_toolchain_manifest(manifest)
    assert entries["SERVER-BASELINE.json"]["size"] > 0
    assert module.validate_server_baseline(baseline)["production_promotion_allowed"] is False


@pytest.mark.parametrize(
    "mutation",
    ("schema-bool", "service-pid-bool", "critical-uid-bool", "safe-flag", "blockers"),
)
@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
def test_server_baseline_contract_rejects_mutations(request, fixture_name, mutation):
    module = request.getfixturevalue(fixture_name)
    baseline = json.loads((DEPLOYMENT / "SERVER-BASELINE.json").read_text("utf-8"))
    if mutation == "schema-bool":
        baseline["schema_version"] = True
    elif mutation == "service-pid-bool":
        baseline["services"][0]["main_pid"] = True
    elif mutation == "critical-uid-bool":
        baseline["critical_files"][0]["uid"] = False
    elif mutation == "safe-flag":
        baseline["production_dependency_metadata_safe"] = True
    elif mutation == "blockers":
        baseline["promotion_blockers"] = []
    with pytest.raises(RuntimeError):
        module.validate_server_baseline(baseline)


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
def test_empty_systemd_listing_accepts_no_match_exit(request, fixture_name, monkeypatch):
    module = request.getfixturevalue(fixture_name)
    completed = types.SimpleNamespace(returncode=1, stdout="", stderr="")
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: completed)
    assert module.run_unit_listing("/usr/bin/systemctl", "list-unit-files") == ""


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr"),
    ((1, "unexpected.service\n", ""), (1, "", "warning\n"), (2, "", "failure\n")),
)
def test_systemd_listing_rejects_ambiguous_or_failed_exit(
    request, fixture_name, monkeypatch, returncode, stdout, stderr
):
    module = request.getfixturevalue(fixture_name)
    completed = types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: completed)
    with pytest.raises(RuntimeError):
        module.run_unit_listing("/usr/bin/systemctl", "list-unit-files")


def test_server_gate_uses_the_same_systemd_no_match_contract():
    source = (DEPLOYMENT / "dev8-server-gate.sh").read_text("utf-8")
    assert source.count("run_unit_listing(") >= 3
    assert "completed.returncode == 1" in source
    assert "and not completed.stdout.strip()" in source
    assert "and not completed.stderr.strip()" in source


@pytest.mark.parametrize(
    ("filename", "probe"),
    (
        ("dev8-install.sh", "upload_not_traversable_by_odoo=true"),
        ("dev8-runtime-setup.sh", "runtime_upload_not_traversable_by_odoo=true"),
    ),
)
def test_upload_gate_accepts_a_non_writable_root_group_traverse_bit_only_with_odoo_probe(
    filename, probe
):
    source = (DEPLOYMENT / filename).read_text("utf-8")
    assert "root_metadata.st_mode & 0o077" not in source
    assert "root_metadata.st_mode & 0o022" in source
    assert "root_metadata.st_mode & 0o007" in source
    assert "/usr/bin/sudo -n -u odoo -g odoo /usr/bin/test ! -x" in source
    assert probe in source


def test_runtime_registry_validation_passes_a_path_object():
    source = (DEPLOYMENT / "dev8-runtime-setup.sh").read_text("utf-8")
    assert "import pathlib" in source
    assert "load_registry(pathlib.Path(sys.argv[1]))" in source
    assert "load_registry(sys.argv[1])" not in source


def test_real_read_runner_normalizes_copied_read_plan_mode():
    source = (DEPLOYMENT / "dev8-run-real-reads.sh").read_text("utf-8")
    copy = 'cp -- "$plan" "$evidence/read-plan.input.json"'
    normalize = 'chmod 0600 -- "$evidence/read-plan.input.json"'
    assert copy in source
    assert normalize in source
    assert source.index(copy) < source.index(normalize)


def test_persistence_audit_compares_consumed_token_to_full_request_digest():
    source = (DEPLOYMENT / "dev8-persistence-audit.py").read_text("utf-8")
    assignment = source[source.index("tokens[token_id] =") :]
    assignment = assignment[: assignment.index("\n\n")]
    assert '"digest": digest(request)' in assignment
    assert '"digest": auth_digest' not in assignment


MUTATIONS = (
    "schema-bool",
    "parents-null",
    "missing-staging-parent",
    "parent-extra",
    "parent-uid-bool",
    "wrong-staging-path",
    "unique-int",
    "uid-bool",
    "unrecorded-owner-bool",
    "object-extra",
    "identity-extra",
    "source-mismatch",
    "upstream-transaction",
    "upstream-binding",
    "package-hash",
)


def _mutate(name: str, install, runtime) -> None:
    if name == "schema-bool":
        install["schema_version"] = True
    elif name == "parents-null":
        install["parents"] = None
    elif name == "missing-staging-parent":
        runtime["parents"].pop("candidate_staging_parent")
    elif name == "parent-extra":
        install["parents"]["extra"] = copy.deepcopy(install["parents"]["root"])
    elif name == "parent-uid-bool":
        install["parents"]["root"]["identity"]["uid"] = False
    elif name == "wrong-staging-path":
        install["objects"]["package_staging"]["path"] += ".changed"
    elif name == "unique-int":
        install["objects"]["package_staging"]["unique"] = 1
    elif name == "uid-bool":
        runtime["objects"]["config_staging"]["uid"] = False
    elif name == "unrecorded-owner-bool":
        runtime["objects"]["config_staging"]["unrecorded_owners"] = [[False, 0]]
    elif name == "object-extra":
        install["objects"]["package_staging"]["extra"] = None
    elif name == "identity-extra":
        install["objects"]["package"]["identity"]["extra"] = None
    elif name == "source-mismatch":
        install["objects"]["package"]["identity"]["ino"] += 1
    elif name == "upstream-transaction":
        runtime["upstream_install_transaction_id"] = "c" * 32
    elif name == "upstream-binding":
        runtime["upstream_install_identity_sha256"] = "0" * 64
    elif name == "package-hash":
        for label in ("package_staging", "package"):
            install["objects"][label]["identity"]["sha256"] = "0" * 64
    else:  # pragma: no cover
        raise AssertionError(name)


@pytest.mark.parametrize("mutation", MUTATIONS)
def test_completed_journal_contract_rejects_mutations(verifier, mutation):
    install, runtime = _legal_journals(verifier)
    _mutate(mutation, install, runtime)
    with pytest.raises(RuntimeError):
        verifier.validate_completed_journals(
            install, runtime, ODOO_UID, ODOO_GID, compare_live=False
        )

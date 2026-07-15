from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sqlite3
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


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
def test_service_pids_are_derived_from_the_validated_server_baseline(
    request, fixture_name
):
    module = request.getfixturevalue(fixture_name)
    baseline = json.loads((DEPLOYMENT / "SERVER-BASELINE.json").read_text("utf-8"))
    validated = module.validate_server_baseline(baseline)
    assert module.baseline_service_pids(validated) == {
        "odoo19.service": 2257341,
        "sudo-pi-agent-bridge.service": 2065799,
    }
    source = Path(module.__file__).read_text("utf-8")
    assert "EXPECTED_PIDS" not in source


def _dev8_controls():
    baseline_payload = (DEPLOYMENT / "SERVER-BASELINE.json").read_bytes()
    return (
        baseline_payload,
        json.loads(baseline_payload),
        json.loads((DEPLOYMENT / "SERVER-SERVICE-TRANSITION.json").read_text("utf-8")),
        json.loads((DEPLOYMENT / "PRIOR-EVIDENCE-DISPOSITION.json").read_text("utf-8")),
    )


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
def test_service_transition_controls_are_accepted_without_mutating_baseline(
    request, fixture_name
):
    module = request.getfixturevalue(fixture_name)
    baseline_payload, baseline, transition, disposition = _dev8_controls()
    baseline_before = copy.deepcopy(baseline)
    validated_baseline = module.validate_server_baseline(baseline)
    validated_transition = module.validate_service_transition(
        transition, baseline_payload, validated_baseline
    )

    assert module.validate_prior_evidence_disposition(disposition) == disposition
    assert module.effective_service_pids(validated_baseline, validated_transition) == {
        "odoo19.service": 2576660,
        "sudo-pi-agent-bridge.service": 2065799,
    }
    identities = module.effective_service_identities(
        validated_baseline, validated_transition
    )
    assert identities["odoo19.service"]["invocation_id"] == transition["services"][0][
        "invocation_id"
    ]
    assert identities["sudo-pi-agent-bridge.service"]["proc_start_ticks"] == transition[
        "services"
    ][1]["proc_start_ticks"]
    assert baseline == baseline_before


TRANSITION_MUTATIONS = (
    "baseline-hash",
    "baseline-size",
    "baseline-captured-at",
    "pid-bool",
    "invocation-id",
    "boot-id",
    "observation-short",
    "actor",
    "maintenance-authorized",
    "production-write-authorized",
    "production-promotion",
    "odoo-unchanged",
    "pi-changed",
    "document-extra",
    "baseline-extra",
    "observation-extra",
    "service-extra",
)


def _mutate_transition(document, mutation):
    if mutation == "baseline-hash":
        document["baseline"]["sha256"] = "0" * 64
    elif mutation == "baseline-size":
        document["baseline"]["size"] += 1
    elif mutation == "baseline-captured-at":
        document["baseline"]["captured_at"] = "2026-07-14T12:39:25Z"
    elif mutation == "pid-bool":
        document["services"][0]["effective_main_pid"] = True
    elif mutation == "invocation-id":
        document["services"][0]["invocation_id"] = "not-a-systemd-invocation-id"
    elif mutation == "boot-id":
        document["system_boot_id"] = "not-a-boot-id"
    elif mutation == "observation-short":
        document["observation"]["last_observed_at"] = document["observation"][
            "first_observed_at"
        ]
    elif mutation == "actor":
        document["actor_attribution"] = "verified"
    elif mutation == "maintenance-authorized":
        document["maintenance_authorization_verified"] = True
    elif mutation == "production-write-authorized":
        document["production_write_authorized"] = True
    elif mutation == "production-promotion":
        document["production_promotion_allowed"] = True
    elif mutation == "odoo-unchanged":
        document["services"][0]["effective_main_pid"] = document["services"][0][
            "baseline_main_pid"
        ]
    elif mutation == "pi-changed":
        document["services"][1]["effective_main_pid"] += 1
    elif mutation == "document-extra":
        document["extra"] = None
    elif mutation == "baseline-extra":
        document["baseline"]["extra"] = None
    elif mutation == "observation-extra":
        document["observation"]["extra"] = None
    elif mutation == "service-extra":
        document["services"][0]["extra"] = None
    else:  # pragma: no cover
        raise AssertionError(mutation)


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
@pytest.mark.parametrize("mutation", TRANSITION_MUTATIONS)
def test_service_transition_contract_rejects_mutations(
    request, fixture_name, mutation
):
    module = request.getfixturevalue(fixture_name)
    baseline_payload, baseline, transition, _ = _dev8_controls()
    validated_baseline = module.validate_server_baseline(baseline)
    _mutate_transition(transition, mutation)
    with pytest.raises(RuntimeError):
        module.validate_service_transition(
            transition, baseline_payload, validated_baseline
        )


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
@pytest.mark.parametrize("mutation", ("final", "status", "reason", "anchor-hash"))
def test_prior_evidence_disposition_rejects_mutations(
    request, fixture_name, mutation
):
    module = request.getfixturevalue(fixture_name)
    _, _, _, disposition = _dev8_controls()
    if mutation == "final":
        disposition["final_verifier_passed"] = True
    elif mutation == "status":
        disposition["status"] = "final"
    elif mutation == "reason":
        disposition["reason_code"] = "accepted_after_restart"
    elif mutation == "anchor-hash":
        disposition["prior_evidence"]["anchor_sha256"] = "0" * 64
    with pytest.raises(RuntimeError):
        module.validate_prior_evidence_disposition(disposition)


@pytest.mark.parametrize("fixture_name", ("freezer", "verifier"))
def test_evidence_identity_is_scoped_to_release_and_toolchain(request, fixture_name):
    module = request.getfixturevalue(fixture_name)
    expected = f"{module.RELEASE}--{module.TOOLCHAIN_VERSION}"
    evidence_path = module.TARGET if hasattr(module, "TARGET") else module.ROOT
    anchor_path = module.EVIDENCE_ANCHOR if hasattr(module, "EVIDENCE_ANCHOR") else module.ANCHOR

    assert module.EVIDENCE_ID == expected
    assert module.EVIDENCE_ID != module.RELEASE
    assert evidence_path.name == expected
    assert evidence_path != Path("/var/lib/odoo-accounting-cli-v3/evidence") / module.RELEASE
    assert anchor_path.name == f"{expected}.json"
    assert anchor_path != Path(
        "/var/lib/odoo-accounting-cli-v3/evidence-anchors"
    ) / f"{module.RELEASE}.json"


def test_freezer_fsyncs_final_anchor_bytes_and_metadata(freezer, monkeypatch):
    events = []
    payloads = []
    identity = (7, 11)
    monkeypatch.setattr(freezer, "ANCHOR_STAGING", Path("/anchor/staging"))
    monkeypatch.setattr(freezer, "ANCHOR_PARENT", Path("/anchor"))
    monkeypatch.setattr(freezer.os, "O_NOFOLLOW", 0x100000, raising=False)
    monkeypatch.setattr(
        freezer.os,
        "open",
        lambda path, flags, mode: events.append(("open", path, flags, mode)) or 17,
    )
    descriptor_stat = types.SimpleNamespace(
        st_mode=freezer.stat.S_IFREG | 0o400,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
        st_dev=identity[0],
        st_ino=identity[1],
    )
    monkeypatch.setattr(
        freezer.os,
        "fstat",
        lambda descriptor: events.append(("fstat", descriptor)) or descriptor_stat,
    )
    monkeypatch.setattr(
        freezer,
        "write_all",
        lambda descriptor, payload: (
            events.append(("write", descriptor)), payloads.append(payload)
        ),
    )
    monkeypatch.setattr(
        freezer.os, "fsync", lambda descriptor: events.append(("fsync", descriptor))
    )
    monkeypatch.setattr(
        freezer.os,
        "fchown",
        lambda descriptor, uid, gid: events.append(
            ("fchown", descriptor, uid, gid)
        ),
        raising=False,
    )
    monkeypatch.setattr(
        freezer.os,
        "fchmod",
        lambda descriptor, mode: events.append(("fchmod", descriptor, mode)),
        raising=False,
    )
    monkeypatch.setattr(
        freezer.os, "close", lambda descriptor: events.append(("close", descriptor))
    )
    monkeypatch.setattr(
        freezer,
        "fsync_directory",
        lambda path: events.append(("fsync-directory", path)),
    )
    monkeypatch.setattr(
        freezer,
        "anchor_file_identity",
        lambda path, **kwargs: events.append(("identity", path, kwargs)) or identity,
    )

    returned_identity = freezer.write_durable_anchor_staging({"schema_version": 1})

    assert returned_identity == identity
    assert json.loads(payloads[0]) == {"schema_version": 1}
    assert events[0][0:2] == ("open", Path("/anchor/staging"))
    assert events[0][2] & freezer.os.O_EXCL
    assert events[0][2] & freezer.os.O_NOFOLLOW
    assert events[0][3] == 0o600
    assert events[1:] == [
        ("fstat", 17),
        ("write", 17),
        ("fsync", 17),
        ("fchown", 17, 0, 0),
        ("fchmod", 17, 0o400),
        ("fsync", 17),
        ("fstat", 17),
        ("close", 17),
        ("fsync-directory", Path("/anchor")),
        (
            "identity",
            Path("/anchor/staging"),
            {"allowed_modes": {0o400}, "allowed_nlinks": {1}},
        ),
    ]


def test_freezer_durably_links_anchor_before_unlinking_staging(
    freezer, monkeypatch
):
    events = []
    identity = (7, 11)
    monkeypatch.setattr(freezer, "ANCHOR_STAGING", Path("/anchor/staging"))
    monkeypatch.setattr(freezer, "EVIDENCE_ANCHOR", Path("/anchor/final"))
    monkeypatch.setattr(freezer, "ANCHOR_PARENT", Path("/anchor"))
    monkeypatch.setattr(
        freezer.os,
        "link",
        lambda source, destination, follow_symlinks: events.append(
            ("link", source, destination, follow_symlinks)
        ),
    )
    monkeypatch.setattr(
        freezer,
        "fsync_directory",
        lambda path: events.append(("fsync-directory", path)),
    )
    monkeypatch.setattr(
        freezer,
        "anchor_file_identity",
        lambda path, **kwargs: events.append(("identity", path, kwargs)) or identity,
    )
    monkeypatch.setattr(
        freezer,
        "unlink_anchor_path",
        lambda path, expected, **kwargs: events.append(
            ("unlink", path, expected, kwargs)
        ),
    )

    freezer.publish_anchor_staging(identity)

    assert events == [
        (
            "identity",
            Path("/anchor/staging"),
            {"allowed_modes": {0o400}, "allowed_nlinks": {1}},
        ),
        ("link", Path("/anchor/staging"), Path("/anchor/final"), False),
        (
            "identity",
            Path("/anchor/staging"),
            {"allowed_modes": {0o400}, "allowed_nlinks": {2}},
        ),
        (
            "identity",
            Path("/anchor/final"),
            {"allowed_modes": {0o400}, "allowed_nlinks": {2}},
        ),
        ("fsync-directory", Path("/anchor")),
        (
            "unlink",
            Path("/anchor/staging"),
            identity,
            {"allowed_modes": {0o400}, "allowed_nlinks": {2}},
        ),
        (
            "identity",
            Path("/anchor/final"),
            {"allowed_modes": {0o400}, "allowed_nlinks": {1}},
        ),
    ]


def _configure_freezer_transaction_paths(freezer, monkeypatch, tmp_path):
    evidence_parent = tmp_path / "evidence"
    anchor_parent = tmp_path / "anchors"
    evidence_parent.mkdir(parents=True)
    anchor_parent.mkdir(parents=True)
    target = evidence_parent / "target"
    staging = evidence_parent / ".target.staging"
    anchor_staging = anchor_parent / ".anchor.staging"
    evidence_anchor = anchor_parent / "anchor.json"
    monkeypatch.setattr(freezer, "TARGET", target)
    monkeypatch.setattr(freezer, "STAGING", staging)
    monkeypatch.setattr(freezer, "EVIDENCE_PARENT", evidence_parent)
    monkeypatch.setattr(freezer, "ANCHOR_PARENT", anchor_parent)
    monkeypatch.setattr(freezer, "ANCHOR_STAGING", anchor_staging)
    monkeypatch.setattr(freezer, "EVIDENCE_ANCHOR", evidence_anchor)
    monkeypatch.setattr(freezer, "fsync_directory", lambda path: None)
    modes = {}
    real_path_info = freezer.path_info

    def normalized_path_info(path):
        value = real_path_info(path)
        value["uid"] = 0
        value["gid"] = 0
        value["mode"] = f"{modes.get(Path(path), 0o700 if value['directory'] else 0o400):04o}"
        return value

    monkeypatch.setattr(freezer, "path_info", normalized_path_info)
    return {
        "target": target,
        "staging": staging,
        "anchor_staging": anchor_staging,
        "evidence_anchor": evidence_anchor,
        "modes": modes,
    }


@pytest.mark.parametrize("state", ("staging", "partial-anchor", "both"))
def test_freezer_cleans_only_unpublished_incomplete_transaction_state(
    freezer, monkeypatch, tmp_path, state
):
    paths = _configure_freezer_transaction_paths(
        freezer, monkeypatch, tmp_path / state
    )
    if state in {"staging", "both"}:
        partial = paths["staging"] / "release" / "build-identity.json"
        partial.parent.mkdir(parents=True)
        partial.write_bytes(b"partial")
        paths["modes"][partial] = 0o600
    if state in {"partial-anchor", "both"}:
        paths["anchor_staging"].write_bytes(b"partial")
        paths["modes"][paths["anchor_staging"]] = 0o600

    assert freezer.recover_anchor({}, {}) is False
    assert not paths["staging"].exists()
    assert not paths["anchor_staging"].exists()


def test_freezer_fails_closed_when_target_has_no_independent_anchor(
    freezer, monkeypatch, tmp_path
):
    paths = _configure_freezer_transaction_paths(
        freezer, monkeypatch, tmp_path
    )
    paths["target"].mkdir()
    monkeypatch.setattr(
        freezer,
        "validate_existing_target",
        lambda *args: pytest.fail("unanchored target must not be self-validated"),
    )

    with pytest.raises(RuntimeError, match="no independently durable anchor"):
        freezer.recover_anchor({}, {})
    assert not paths["evidence_anchor"].exists()
    assert not paths["anchor_staging"].exists()
    assert "reconstruct_anchor_from_target" not in (
        DEPLOYMENT / "dev8-freeze-evidence.py"
    ).read_text("utf-8")


def test_freezer_fails_closed_on_published_target_with_partial_anchor(
    freezer, monkeypatch, tmp_path
):
    paths = _configure_freezer_transaction_paths(
        freezer, monkeypatch, tmp_path
    )
    paths["target"].mkdir()
    paths["anchor_staging"].write_bytes(b"partial")
    paths["modes"][paths["anchor_staging"]] = 0o600

    with pytest.raises(RuntimeError, match="unsafe anchor transaction object"):
        freezer.recover_anchor({}, {})
    assert paths["target"].is_dir()
    assert paths["anchor_staging"].read_bytes() == b"partial"
    assert not paths["evidence_anchor"].exists()


def test_freezer_recovers_target_from_valid_staging_anchor(
    freezer, monkeypatch, tmp_path
):
    paths = _configure_freezer_transaction_paths(
        freezer, monkeypatch, tmp_path
    )
    paths["target"].mkdir()
    paths["anchor_staging"].write_bytes(b"validated-anchor")
    anchor = {"schema_version": 1, "freeze_checks_passed": True}
    monkeypatch.setattr(
        freezer, "validate_existing_target", lambda *args: anchor
    )

    assert freezer.recover_anchor({}, {}) is True
    assert paths["evidence_anchor"].read_bytes() == b"validated-anchor"
    assert not paths["anchor_staging"].exists()


def test_freezer_refuses_to_publish_or_unlink_replacement_anchor(
    freezer, monkeypatch, tmp_path
):
    paths = _configure_freezer_transaction_paths(
        freezer, monkeypatch, tmp_path
    )
    paths["anchor_staging"].write_bytes(b"validated")
    expected_identity = freezer.anchor_file_identity(
        paths["anchor_staging"], allowed_modes={0o400}, allowed_nlinks={1}
    )
    replacement = paths["anchor_staging"].with_name("replacement")
    replacement.write_bytes(b"replacement")
    replacement.replace(paths["anchor_staging"])

    with pytest.raises(RuntimeError, match="identity changed before publication"):
        freezer.publish_anchor_staging(expected_identity)
    assert paths["anchor_staging"].read_bytes() == b"replacement"
    assert not paths["evidence_anchor"].exists()

    with pytest.raises(RuntimeError, match="refusing to unlink a replacement"):
        freezer.unlink_anchor_path(
            paths["anchor_staging"],
            expected_identity,
            allowed_modes={0o400},
            allowed_nlinks={1},
        )
    assert paths["anchor_staging"].read_bytes() == b"replacement"


def test_freezer_does_not_remove_replacement_staging_tree(
    freezer, monkeypatch, tmp_path
):
    paths = _configure_freezer_transaction_paths(
        freezer, monkeypatch, tmp_path
    )
    paths["staging"].mkdir()
    expected_identity = freezer.incomplete_staging_identity()
    original = paths["staging"].with_name("original-staging")
    paths["staging"].rename(original)
    paths["staging"].mkdir()

    with pytest.raises(RuntimeError, match="replacement evidence staging tree"):
        freezer.cleanup_incomplete_staging(expected_identity)
    assert paths["staging"].is_dir()
    assert original.is_dir()


def test_freezer_does_not_delete_different_staging_inode_next_to_valid_anchor(
    freezer, monkeypatch, tmp_path
):
    paths = _configure_freezer_transaction_paths(
        freezer, monkeypatch, tmp_path
    )
    paths["target"].mkdir()
    paths["evidence_anchor"].write_bytes(b"valid")
    paths["anchor_staging"].write_bytes(b"replacement")
    monkeypatch.setattr(
        freezer,
        "validate_existing_target",
        lambda *args: {"schema_version": 1},
    )

    with pytest.raises(RuntimeError, match="not the same inode"):
        freezer.recover_anchor({}, {})
    assert paths["evidence_anchor"].read_bytes() == b"valid"
    assert paths["anchor_staging"].read_bytes() == b"replacement"


def test_freezer_persists_anchor_staging_before_publishing_target():
    source = (DEPLOYMENT / "dev8-freeze-evidence.py").read_text("utf-8")
    stage_call = source.rindex(
        "        anchor_staging_identity = write_durable_anchor_staging(anchor)\n"
    )
    target_publish = source.rindex("        os.replace(STAGING, TARGET)\n")
    assert stage_call < target_publish


def test_server_gate_binds_control_hashes_and_full_service_identity():
    source = (DEPLOYMENT / "dev8-server-gate.sh").read_text("utf-8")
    assert (
        "server_baseline_sha="
        "37b498ffce8f175813e866c534b6514142436d9c4dbf29216f1dab1c880c57e4"
    ) in source
    assert (
        "service_transition_sha="
        "db60965c8bc1fd6d97ea6c793d135bb2906d10448cf80912538289c54b0fcbb3"
    ) in source
    assert "hashlib.sha256(baseline_payload).hexdigest() != baseline_sha256" in source
    assert "hashlib.sha256(payload).hexdigest() != expected_sha256" in source
    for marker in (
        "--property=InvocationID",
        "--property=ExecMainStartTimestampMonotonic",
        "/proc/sys/kernel/random/boot_id",
        'sample["proc_start_ticks"]',
        'hashlib.sha256(sample["cmdline"]).hexdigest()',
    ):
        assert marker in source


def test_verifier_service_sampler_closes_toctou_and_backs_final_check():
    source = (DEPLOYMENT / "dev8-verify-frozen-evidence.py").read_text("utf-8")
    sampler = source[source.index("def sample_service(") : source.index(
        "\n\ndef verify_live_isolation(", source.index("def sample_service(")
    )]
    for marker in (
        "boot_before = read_system_boot_id()",
        "first = systemd_service_properties(unit)",
        "second = systemd_service_properties(unit)",
        'first["Id"] == unit',
        'second["Id"] == unit',
        "first == second",
        "first_pid == second_pid",
        "first_start_ticks == second_start_ticks",
        "first_cmdline == second_cmdline",
        "boot_before == boot_after",
    ):
        assert marker in sampler
    assert '"Id", "ActiveState", "SubState"' in source
    assert (
        '"service_identity_pid_reuse_and_toctou_resistant": live["checks"]['
        in source
    )


@pytest.mark.parametrize(
    "filename",
    ("dev8-run-read-oracles.sh", "dev8-canonical-package-negative-gates.py"),
)
def test_dynamic_evidence_producers_capture_full_odoo_identity(filename):
    source = (DEPLOYMENT / filename).read_text("utf-8")
    for marker in (
        '"boot_id"',
        '"cmdline_sha256"',
        '"exec_main_start_monotonic_usec"',
        '"invocation_id"',
        '"main_pid"',
        '"proc_start_ticks"',
        '"odoo_identity_before"',
        '"odoo_identity_after"',
        '"odoo_identity_unchanged"',
    ):
        assert marker in source


def test_verifier_inspects_a_wal_snapshot_in_memory(verifier, tmp_path):
    database = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(database)
    try:
        assert connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
        for table in (
            "approval_records",
            "consumed_auth_tokens",
            "consumed_receipts",
            "idempotency_keys",
            "operations",
        ):
            connection.execute(f"CREATE TABLE {table} (id INTEGER)")
        connection.execute("CREATE TABLE audit_events (sequence INTEGER)")
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        connection.close()

    payload = database.read_bytes()
    assert payload[18:20] == b"\x02\x02"
    report, events = verifier.inspect_db(payload)
    assert report["quick_check"] == ["ok"]
    assert report["counts"] == {
        "approval_records": 0,
        "audit_events": 0,
        "consumed_auth_tokens": 0,
        "consumed_receipts": 0,
        "idempotency_keys": 0,
        "operations": 0,
    }
    assert events == []


def test_verifier_binds_financial_oracles_through_the_request_roundtrip():
    source = (DEPLOYMENT / "dev8-verify-frozen-evidence.py").read_text("utf-8")
    assert 'oracle.get("request_roundtrip") == expected_oracle_roundtrip' in source
    assert 'report.get("capability_id")' not in source


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

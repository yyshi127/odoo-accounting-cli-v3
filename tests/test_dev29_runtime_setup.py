from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import stat
import sys
import threading
from dataclasses import dataclass, replace
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "deployment" / "dev29" / "runtime_setup.py"
TMPFILES = (
    SCRIPT.parent
    / "systemd"
    / "odoo-accounting-cli-v3-dev29-tmpfiles.conf"
)
SPEC = importlib.util.spec_from_file_location("dev29_runtime_setup", SCRIPT)
assert SPEC and SPEC.loader
runtime_setup = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runtime_setup
SPEC.loader.exec_module(runtime_setup)

VERSION = "0.1.0.dev29"
COMMIT = "a1234567890bcdef1234567890abcdef12345678"
RELEASE = f"{VERSION}-{COMMIT[:12]}"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _replace_sealed(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    if os.name == "posix":
        path.chmod(0o644)
    path.write_bytes(payload)
    if os.name == "posix":
        path.chmod(mode)


@dataclass(frozen=True)
class Prepared:
    root: Path
    expected: runtime_setup.ExpectedIdentity
    layout: runtime_setup.Layout


def _prepare(root: Path) -> Prepared:
    package = b"canonical dynamic package\n"
    odoo_python = b"python executable\n"
    odoo_bin = b"odoo-bin\n"
    odoo_config = b"[options]\nworkers = 4\n"
    script = SCRIPT.read_bytes()
    payload = b"sealed release member\n"
    files = [
        {
            "path": "deployment/dev29/runtime_setup.py",
            "sha256": _sha256(script),
            "size": len(script),
        },
        {"path": "payload.txt", "sha256": _sha256(payload), "size": len(payload)},
    ]
    unsigned = {
        "schema_version": 1,
        "version": VERSION,
        "commit": COMMIT,
        "files": files,
    }
    manifest_sha256 = _sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    expected = runtime_setup.ExpectedIdentity(
        release=RELEASE,
        version=VERSION,
        commit=COMMIT,
        manifest_sha256=manifest_sha256,
        package_sha256=_sha256(package),
        odoo_python_sha256=_sha256(odoo_python),
        odoo_bin_sha256=_sha256(odoo_bin),
        odoo_config_sha256=_sha256(odoo_config),
    )
    layout = runtime_setup.build_layout(root, expected)
    _write(layout.release_script, script)
    _write(layout.release_root / "payload.txt", payload)
    manifest = {**unsigned, "manifest_sha256": manifest_sha256}
    _write(
        layout.release_root / "RELEASE-MANIFEST.json",
        json.dumps(manifest, sort_keys=True).encode("utf-8"),
    )
    _write(layout.package, package)
    _write(layout.odoo_python, odoo_python)
    _write(layout.odoo_bin, odoo_bin)
    _write(layout.odoo_config, odoo_config)
    layout.trusted_artifact_parent.mkdir(parents=True, exist_ok=True)
    _write(
        layout.trusted_artifact,
        json.dumps(
            {
                "commit": expected.commit,
                "manifest_sha256": expected.manifest_sha256,
                "package_sha256": expected.package_sha256,
                "release": expected.release,
            },
            sort_keys=True,
        ).encode("utf-8"),
    )
    if os.name == "posix":
        for path in (
            layout.release_script,
            layout.release_root / "payload.txt",
            layout.release_root / "RELEASE-MANIFEST.json",
            layout.package,
            layout.trusted_artifact,
        ):
            path.chmod(0o444)
        for directory in sorted(
            (
                path
                for path in layout.release_root.rglob("*")
                if path.is_dir()
            ),
            key=lambda value: len(value.parts),
            reverse=True,
        ):
            directory.chmod(0o555)
        layout.release_root.chmod(0o555)
        layout.trusted_artifact_parent.chmod(0o755)
    return Prepared(root, expected, layout)


@pytest.fixture
def prepared(tmp_path: Path) -> Prepared:
    if os.name == "posix":
        tmp_path.chmod(0o700)
    return _prepare(tmp_path)


def _setup(item: Prepared):
    return runtime_setup.setup_candidate_runtime(
        item.expected, root=item.root, test_mode=True
    )


def test_setup_is_release_specific_config_last_and_idempotent(
    prepared: Prepared,
) -> None:
    result = _setup(prepared)
    layout = prepared.layout
    document = json.loads(result.config_path.read_text(encoding="utf-8"))

    assert set(document) == runtime_setup.CONFIG_FIELDS
    assert len(document) == 20
    assert document["environment"] == "test"
    assert document["capability_channel"] == "staged"
    assert document["database_name"] == "odoo_test"
    assert document["database_uuid"] == runtime_setup.DATABASE_UUID
    assert document["release_root"] == str(layout.release_root)
    assert document["canonical_package_sha256"] == prepared.expected.package_sha256
    assert document["auth_key_id"].startswith("test-auth-dev29-")
    assert document["receipt_key_id"].startswith("test-receipt-dev29-")
    assert document["auth_key_id"] != document["receipt_key_id"]
    assert Path(document["auth_state_path"]).parent == layout.auth_state_parent
    assert Path(document["receipt_state_path"]).parent == layout.receipt_state_parent
    assert (
        f"odoo-accounting-cli-v3{os.sep}test{os.sep}candidates{os.sep}{RELEASE}"
        in document["auth_state_path"]
    )
    auth = layout.auth_secret.read_bytes()
    receipt = layout.receipt_secret.read_bytes()
    assert len(auth) == len(receipt) == 32
    assert auth != receipt
    assert layout.auth_secret.stat().st_nlink == 1
    assert layout.receipt_secret.stat().st_nlink == 1
    assert layout.config.stat().st_nlink == 1
    assert list(layout.child_home.iterdir()) == []
    assert layout.private_evidence_parent.is_dir()
    assert layout.runtime_trace_staging_parent.is_dir()
    assert layout.runtime_open_manifest_parent.is_dir()
    assert layout.public_evidence_parent.is_dir()
    assert layout.evidence_anchor_parent.is_dir()
    assert layout.supervisor_staging_parent.is_dir()
    assert layout.supervisor_lease_parent.is_dir()
    assert not (prepared.root / "opt/odoo-accounting-cli-v3/current").exists()
    assert not (prepared.root / "etc/systemd").exists()

    public = result.public_record()
    assert public == {
        "already_exists": False,
        "child_home": str(layout.child_home),
        "commit": COMMIT,
        "config_path": str(layout.config),
        "environment": "test",
        "manifest_sha256": prepared.expected.manifest_sha256,
        "package_sha256": prepared.expected.package_sha256,
        "release": RELEASE,
        "routed": False,
        "version": VERSION,
    }
    rendered = json.dumps(public, sort_keys=True, separators=(",", ":"))
    assert auth.hex() not in rendered and receipt.hex() not in rendered

    second = _setup(prepared)
    assert second.already_exists is True
    assert layout.auth_secret.read_bytes() == auth
    assert layout.receipt_secret.read_bytes() == receipt
    assert json.loads(layout.config.read_text(encoding="utf-8")) == document


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode contract")
def test_runtime_metadata_is_read_only_for_odoo_except_state(
    prepared: Prepared,
) -> None:
    _setup(prepared)
    layout = prepared.layout
    assert stat.S_IMODE(layout.config.stat().st_mode) == 0o640
    assert stat.S_IMODE(layout.secret_root.stat().st_mode) == 0o750
    assert stat.S_IMODE(layout.auth_secret.stat().st_mode) == 0o640
    assert stat.S_IMODE(layout.receipt_secret.stat().st_mode) == 0o640
    assert stat.S_IMODE(layout.state_root.stat().st_mode) == 0o710
    assert stat.S_IMODE(layout.auth_state_parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(layout.receipt_state_parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(layout.child_home.stat().st_mode) == 0o700
    assert stat.S_IMODE(layout.private_evidence_parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(layout.runtime_trace_staging_parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(layout.runtime_open_manifest_parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(layout.public_evidence_parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(layout.evidence_anchor_parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(layout.supervisor_staging_parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(layout.supervisor_lease_parent.stat().st_mode) == 0o700


def test_dev29_tmpfiles_recreates_exact_shared_runtime_parents() -> None:
    assert TMPFILES.read_text(encoding="utf-8") == (
        "d /var/lib/odoo-accounting-cli-v3/evidence 0755 root root -\n"
        "d /var/lib/odoo-accounting-cli-v3/evidence-anchors 0755 root root -\n"
        "d /run/odoo-accounting-cli-v3-dev29 0700 root root -\n"
        "d /run/odoo-accounting-cli-v3-dev29-leases 0700 root root -\n"
    )


def test_existing_candidate_recreates_empty_ephemeral_runtime_parents(
    prepared: Prepared,
) -> None:
    first = _setup(prepared)
    prepared.layout.supervisor_staging_parent.rmdir()
    prepared.layout.supervisor_lease_parent.rmdir()

    second = _setup(prepared)

    assert first.already_exists is False
    assert second.already_exists is True
    assert prepared.layout.supervisor_staging_parent.is_dir()
    assert prepared.layout.supervisor_lease_parent.is_dir()


def test_existing_candidate_reverifies_each_shared_parent_with_one_exact_mode(
    prepared: Prepared, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup(prepared)
    layout = prepared.layout
    expected_modes = {
        layout.private_evidence_parent: 0o700,
        layout.runtime_trace_staging_parent: 0o700,
        layout.public_evidence_parent: 0o755,
        layout.evidence_anchor_parent: 0o755,
        layout.supervisor_staging_parent: 0o700,
        layout.supervisor_lease_parent: 0o700,
        layout.runtime_open_manifest_parent: 0o755,
    }
    observed: dict[Path, set[int]] = {}
    original = runtime_setup._verify_owner_mode

    def record(path: Path, **kwargs):
        if path in expected_modes:
            observed.setdefault(path, set()).add(kwargs["mode"])
        return original(path, **kwargs)

    monkeypatch.setattr(runtime_setup, "_verify_owner_mode", record)
    uid, gid = runtime_setup._service_identity(True)
    result = runtime_setup._existing_runtime(
        layout,
        prepared.expected,
        service_uid=uid,
        service_gid=gid,
        test_mode=True,
    )

    assert result is not None and result.already_exists is True
    assert observed == {path: {mode} for path, mode in expected_modes.items()}


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode contract")
@pytest.mark.parametrize(
    "attribute",
    [
        "public_evidence_parent",
        "evidence_anchor_parent",
        "supervisor_staging_parent",
        "supervisor_lease_parent",
    ],
)
def test_shared_runtime_parent_metadata_drift_is_rejected(
    prepared: Prepared, attribute: str
) -> None:
    path = getattr(prepared.layout, attribute)
    path.mkdir(parents=True)
    path.chmod(0o777)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="mode drift"):
        _setup(prepared)
    assert not prepared.layout.config.exists()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("release", "../escape", "release identity"),
        ("version", "dev29", "release identity"),
        ("commit", "A" * 40, "release identity"),
        ("release", f"{VERSION}-000000000000", "release identity"),
        ("manifest_sha256", "A" * 64, "manifest SHA-256"),
        ("package_sha256", "0" * 63, "package SHA-256"),
        ("odoo_python_sha256", "x" * 64, "odoo_python SHA-256"),
    ],
)
def test_external_identity_is_strict(
    prepared: Prepared, field: str, value: str, message: str
) -> None:
    invalid = replace(prepared.expected, **{field: value})
    with pytest.raises(runtime_setup.RuntimeSetupError, match=message):
        runtime_setup.setup_candidate_runtime(
            invalid, root=prepared.root, test_mode=True
        )


@pytest.mark.parametrize(
    ("target", "message"),
    [
        ("package", "canonical package digest"),
        ("odoo_python", "odoo_python digest drift"),
        ("odoo_bin", "odoo_bin digest drift"),
        ("odoo_config", "odoo_config digest drift"),
        ("member", "release member mismatch"),
    ],
)
def test_tampered_dependency_or_release_member_is_rejected(
    prepared: Prepared, target: str, message: str
) -> None:
    layout = prepared.layout
    path = {
        "package": layout.package,
        "odoo_python": layout.odoo_python,
        "odoo_bin": layout.odoo_bin,
        "odoo_config": layout.odoo_config,
        "member": layout.release_root / "payload.txt",
    }[target]
    _replace_sealed(path, b"tampered\n")
    with pytest.raises(runtime_setup.RuntimeSetupError, match=message):
        _setup(prepared)


def test_anchor_must_match_all_external_identity_fields(prepared: Prepared) -> None:
    document = json.loads(
        prepared.layout.trusted_artifact.read_text(encoding="utf-8")
    )
    document["package_sha256"] = "0" * 64
    _replace_sealed(
        prepared.layout.trusted_artifact,
        json.dumps(document, sort_keys=True).encode("utf-8"),
    )
    with pytest.raises(
        runtime_setup.RuntimeSetupError, match="anchor does not match"
    ):
        _setup(prepared)


def test_duplicate_anchor_field_is_rejected(prepared: Prepared) -> None:
    expected = prepared.expected
    payload = (
        "{"
        f'"commit":"{expected.commit}",'
        f'"manifest_sha256":"{expected.manifest_sha256}",'
        f'"package_sha256":"{expected.package_sha256}",'
        f'"release":"{expected.release}",'
        f'"release":"{expected.release}"'
        "}"
    ).encode("utf-8")
    _replace_sealed(prepared.layout.trusted_artifact, payload)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="duplicate fields"):
        _setup(prepared)


def test_self_rehashed_manifest_cannot_replace_external_identity(
    prepared: Prepared,
) -> None:
    path = prepared.layout.release_root / "RELEASE-MANIFEST.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    unsigned = {key: value for key, value in document.items() if key != "manifest_sha256"}
    unsigned["commit"] = "b" * 40
    document = {
        **unsigned,
        "manifest_sha256": _sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ),
    }
    _replace_sealed(path, json.dumps(document, sort_keys=True).encode("utf-8"))
    with pytest.raises(runtime_setup.RuntimeSetupError, match="identity"):
        _setup(prepared)


def test_manifest_must_include_the_runtime_script(prepared: Prepared) -> None:
    path = prepared.layout.release_root / "RELEASE-MANIFEST.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    unsigned = {key: value for key, value in document.items() if key != "manifest_sha256"}
    unsigned["files"] = [
        item
        for item in unsigned["files"]
        if item["path"] != runtime_setup.RELEASE_SCRIPT.as_posix()
    ]
    digest = _sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    changed = replace(prepared.expected, manifest_sha256=digest)
    _replace_sealed(
        path,
        json.dumps(
            {**unsigned, "manifest_sha256": digest}, sort_keys=True
        ).encode("utf-8"),
    )
    _replace_sealed(
        prepared.layout.trusted_artifact,
        json.dumps(
            {
                "commit": changed.commit,
                "manifest_sha256": changed.manifest_sha256,
                "package_sha256": changed.package_sha256,
                "release": changed.release,
            },
            sort_keys=True,
        ).encode("utf-8"),
    )
    with pytest.raises(runtime_setup.RuntimeSetupError, match="omits"):
        runtime_setup.setup_candidate_runtime(
            changed, root=prepared.root, test_mode=True
        )


def test_unmanifested_release_entry_is_rejected(prepared: Prepared) -> None:
    if os.name == "posix":
        prepared.layout.release_root.chmod(0o755)
    extra = prepared.layout.release_root / "unexpected.txt"
    extra.write_bytes(b"unexpected\n")
    if os.name == "posix":
        extra.chmod(0o444)
        prepared.layout.release_root.chmod(0o555)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="entry set mismatch"):
        _setup(prepared)


def test_script_must_be_the_manifested_release_copy(prepared: Prepared) -> None:
    with pytest.raises(runtime_setup.RuntimeSetupError, match="outside"):
        runtime_setup.setup_candidate_runtime(
            prepared.expected,
            root=prepared.root,
            test_mode=True,
            script_path=SCRIPT,
        )


def test_release_script_hard_link_is_rejected(prepared: Prepared) -> None:
    alias = prepared.layout.release_script.with_suffix(".alias")
    if os.name == "posix":
        alias.parent.chmod(0o755)
    try:
        os.link(prepared.layout.release_script, alias)
    finally:
        if os.name == "posix":
            alias.parent.chmod(0o555)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="sealed release member"):
        _setup(prepared)


def test_existing_config_or_secret_drift_is_rejected(prepared: Prepared) -> None:
    _setup(prepared)
    layout = prepared.layout
    document = json.loads(layout.config.read_text(encoding="utf-8"))
    document["database_name"] = "other"
    _replace_sealed(
        layout.config,
        (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        ),
        mode=0o640,
    )
    with pytest.raises(runtime_setup.RuntimeSetupError, match="value drift"):
        _setup(prepared)


def test_existing_secret_hard_link_is_rejected(prepared: Prepared) -> None:
    _setup(prepared)
    alias = prepared.layout.auth_secret.with_suffix(".alias")
    os.link(prepared.layout.auth_secret, alias)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="link-count drift"):
        _setup(prepared)


def test_existing_config_hard_link_is_rejected(prepared: Prepared) -> None:
    _setup(prepared)
    alias = prepared.layout.config.with_suffix(".alias")
    os.link(prepared.layout.config, alias)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="link-count drift"):
        _setup(prepared)


def test_existing_state_rejects_unexpected_sibling(prepared: Prepared) -> None:
    _setup(prepared)
    unexpected = prepared.layout.auth_state_parent / "unexpected"
    unexpected.write_bytes(b"x")
    if os.name == "posix":
        unexpected.chmod(0o600)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="unexpected object"):
        _setup(prepared)


def test_expected_sqlite_state_files_are_accepted(prepared: Prepared) -> None:
    _setup(prepared)
    for name in (
        "state.sqlite3",
        "state.sqlite3-wal",
        "state.sqlite3-shm",
        "state.sqlite3-journal",
        "state.sqlite3.writer.lock",
    ):
        path = prepared.layout.auth_state_parent / name
        path.write_bytes(b"x")
        if os.name == "posix":
            path.chmod(0o600)
    assert _setup(prepared).already_exists is True


def test_partial_candidate_is_rejected_without_overwrite(prepared: Prepared) -> None:
    prepared.layout.secret_root.mkdir(parents=True)
    sentinel = prepared.layout.secret_root / "sentinel"
    sentinel.write_bytes(b"keep")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="partial candidate"):
        _setup(prepared)
    assert sentinel.read_bytes() == b"keep"
    assert not prepared.layout.config.exists()
    assert not prepared.layout.state_root.exists()


def test_config_is_last_and_failure_rolls_back_created_objects(
    prepared: Prepared, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = prepared.layout
    original = runtime_setup._publish_file
    published: list[Path] = []

    def fail_config(path, payload, **kwargs):
        published.append(path)
        if path == layout.config:
            raise runtime_setup.RuntimeSetupError("injected config failure")
        return original(path, payload, **kwargs)

    monkeypatch.setattr(runtime_setup, "_publish_file", fail_config)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="injected"):
        _setup(prepared)
    assert published[-1] == layout.config
    assert not layout.config.exists()
    assert not layout.secret_root.exists()
    assert not layout.state_root.exists()
    assert not layout.child_home.exists()
    assert layout.release_root.exists()
    assert layout.package.exists()


def test_binary_secrets_are_written_without_text_normalization(
    prepared: Prepared, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        runtime_setup,
        "_new_secret_pair",
        lambda: (b"a" * 30 + b"\n\x00", b"b" * 30 + b"\x00\n"),
    )
    _setup(prepared)
    assert prepared.layout.auth_secret.read_bytes() == b"a" * 30 + b"\n\x00"
    assert prepared.layout.receipt_secret.read_bytes() == b"b" * 30 + b"\x00\n"


def test_nonempty_fixed_child_home_is_rejected(prepared: Prepared) -> None:
    home = prepared.layout.child_home
    home.mkdir(parents=True)
    if os.name == "posix":
        home.chmod(0o700)
    (home / "unexpected").write_bytes(b"x")
    with pytest.raises(runtime_setup.RuntimeSetupError, match="not empty"):
        _setup(prepared)
    assert not prepared.layout.config.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode contract")
def test_noncanonical_existing_config_parent_is_rejected(
    prepared: Prepared,
) -> None:
    prepared.layout.config_parent.mkdir(parents=True)
    prepared.layout.config_parent.chmod(0o750)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="mode drift"):
        _setup(prepared)
    assert not prepared.layout.secret_root.exists()


def test_staging_cleanup_failure_never_reports_success(
    prepared: Prepared, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_unlink = Path.unlink

    def fail_staging_unlink(path: Path, *args, **kwargs) -> None:
        if path.name.endswith(".staging"):
            raise OSError("injected cleanup failure")
        original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_staging_unlink)
    with pytest.raises(
        runtime_setup.RuntimeSetupError, match="cannot be removed durably"
    ):
        _setup(prepared)
    assert not prepared.layout.config.exists()
    assert not prepared.layout.auth_secret.exists()


def test_flock_timeout_is_finite_and_deterministic() -> None:
    now = [10.0]
    attempts: list[int] = []
    pauses: list[float] = []

    def busy(descriptor: int) -> None:
        attempts.append(descriptor)
        raise BlockingIOError(errno.EAGAIN, "busy")

    def pause(seconds: float) -> None:
        pauses.append(seconds)
        now[0] += seconds

    with pytest.raises(runtime_setup.RuntimeSetupError, match="timed out"):
        runtime_setup._acquire_posix_flock(
            37,
            timeout_seconds=0.12,
            poll_seconds=0.05,
            acquire=busy,
            monotonic=lambda: now[0],
            sleep=pause,
        )
    assert attempts == [37, 37, 37, 37]
    assert pauses == pytest.approx([0.05, 0.05, 0.02])


@pytest.mark.skipif(os.name != "posix", reason="real POSIX flock")
def test_concurrent_setups_converge_on_one_runtime(
    prepared: Prepared, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runtime_setup, "RUNTIME_LOCK_TIMEOUT_SECONDS", 5.0)
    original_publish = runtime_setup._publish_file
    first_config = threading.Event()
    release_first = threading.Event()
    calls = 0
    guard = threading.Lock()

    def coordinated(path, payload, **kwargs):
        nonlocal calls
        if path == prepared.layout.config:
            with guard:
                calls += 1
                number = calls
            if number == 1:
                first_config.set()
                assert release_first.wait(timeout=5)
        return original_publish(path, payload, **kwargs)

    monkeypatch.setattr(runtime_setup, "_publish_file", coordinated)
    results = []
    errors = []

    def run() -> None:
        try:
            results.append(_setup(prepared))
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=run)
    first.start()
    assert first_config.wait(timeout=5)
    second = threading.Thread(target=run)
    second.start()
    release_first.set()
    first.join(timeout=10)
    second.join(timeout=10)
    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert sorted(result.already_exists for result in results) == [False, True]


def test_cli_requires_all_external_identity_and_emits_canonical_json(
    prepared: Prepared,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runtime_setup,
        "_require_root_interpreter",
        lambda _expected_sha256: (_ for _ in ()).throw(
            AssertionError("test-root mode must not claim a production interpreter gate")
        ),
    )
    expected = prepared.expected
    arguments = [
        "--expected-release",
        expected.release,
        "--expected-version",
        expected.version,
        "--expected-commit",
        expected.commit,
        "--expected-manifest-sha256",
        expected.manifest_sha256,
        "--expected-package-sha256",
        expected.package_sha256,
        "--expected-odoo-python-sha256",
        expected.odoo_python_sha256,
        "--expected-odoo-bin-sha256",
        expected.odoo_bin_sha256,
        "--expected-odoo-config-sha256",
        expected.odoo_config_sha256,
        "--test-root",
        str(prepared.root),
    ]
    assert runtime_setup.main(arguments) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert captured.out == (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    )
    assert document["release"] == expected.release
    assert document["routed"] is False
    assert captured.err == ""


def test_production_cli_gates_fixed_isolated_no_site_interpreter_before_setup(
    prepared: Prepared,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = prepared.expected
    events: list[tuple[str, object]] = []

    def require_interpreter(expected_sha256: str) -> None:
        events.append(("interpreter", expected_sha256))

    class Result:
        @staticmethod
        def public_record() -> dict[str, object]:
            return {"release": expected.release, "routed": False}

    def setup(identity, *, root, test_mode):
        events.append(("setup", (identity, root, test_mode)))
        return Result()

    monkeypatch.setattr(runtime_setup, "_require_root_interpreter", require_interpreter)
    monkeypatch.setattr(runtime_setup, "setup_candidate_runtime", setup)
    arguments = [
        "--expected-release",
        expected.release,
        "--expected-version",
        expected.version,
        "--expected-commit",
        expected.commit,
        "--expected-manifest-sha256",
        expected.manifest_sha256,
        "--expected-package-sha256",
        expected.package_sha256,
        "--expected-odoo-python-sha256",
        expected.odoo_python_sha256,
        "--expected-odoo-bin-sha256",
        expected.odoo_bin_sha256,
        "--expected-odoo-config-sha256",
        expected.odoo_config_sha256,
    ]

    assert runtime_setup.main(arguments) == 0
    assert events[0] == ("interpreter", expected.odoo_python_sha256)
    assert events[1][0] == "setup"
    assert events[1][1][1:] == (Path("/"), False)
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out) == {"release": expected.release, "routed": False}


def test_root_interpreter_guard_is_fail_closed_and_no_site() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'Path("/usr/bin/python3.12")' in source
    assert 'Path("/proc/self/exe")' in source
    assert "sys.flags.isolated" in source
    assert "sys.flags.no_site" in source


def test_test_root_cannot_be_system_root(prepared: Prepared) -> None:
    with pytest.raises(runtime_setup.RuntimeSetupError, match="private non-system"):
        runtime_setup.setup_candidate_runtime(
            prepared.expected, root=Path(Path.cwd().anchor), test_mode=True
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX root gate")
def test_production_mode_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime_setup.os, "geteuid", lambda: 1000)
    with pytest.raises(runtime_setup.RuntimeSetupError, match="must run as root"):
        runtime_setup._service_identity(False)


@pytest.mark.skipif(os.name != "posix", reason="POSIX absolute path contract")
def test_production_layout_is_only_the_release_contained_system_layout(
    prepared: Prepared,
) -> None:
    layout = runtime_setup.build_layout(Path("/"), prepared.expected)
    assert layout.release_root == Path(
        f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}"
    )
    assert layout.release_script == Path(
        f"/opt/odoo-accounting-cli-v3/releases/{RELEASE}/"
        "deployment/dev29/runtime_setup.py"
    )
    assert layout.config == Path(
        f"/etc/odoo-accounting-cli-v3/candidates/runtime-test-{RELEASE}.json"
    )
    assert layout.state_root == Path(
        f"/var/lib/odoo-accounting-cli-v3/test/candidates/{RELEASE}"
    )
    assert layout.public_evidence_parent == Path(
        "/var/lib/odoo-accounting-cli-v3/evidence"
    )
    assert layout.evidence_anchor_parent == Path(
        "/var/lib/odoo-accounting-cli-v3/evidence-anchors"
    )
    assert layout.supervisor_staging_parent == Path(
        "/run/odoo-accounting-cli-v3-dev29"
    )
    assert layout.supervisor_lease_parent == Path(
        "/run/odoo-accounting-cli-v3-dev29-leases"
    )


def test_production_mode_rejects_script_override(prepared: Prepared) -> None:
    with pytest.raises(runtime_setup.RuntimeSetupError, match="script override"):
        runtime_setup.setup_candidate_runtime(
            prepared.expected,
            root=Path("/"),
            test_mode=False,
            script_path=prepared.layout.release_script,
        )


def test_runtime_setup_has_no_odoo_or_database_execution_boundary() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "import sqlite3" not in source
    assert "import psycopg" not in source
    assert "odoo shell" not in source
    assert ".service" not in source
    assert "/current" not in source

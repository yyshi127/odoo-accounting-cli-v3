from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from tools import build_release as release_builder


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev29" / "runtime_open_manifest_builder.py"
SPEC = importlib.util.spec_from_file_location("dev29_runtime_open_builder", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = builder
SPEC.loader.exec_module(builder)


def _source(
    *,
    runtime_sha256: str = "c" * 64,
    release_manifest_sha256: str = "d" * 64,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "scope": builder.SCOPE,
        "release": "0.1.0.dev29-a1234567890b",
        "expected_strace_sha256": "a" * 64,
        "expected_static_closure_sha256": "b" * 64,
        "expected_runtime_module_sha256": runtime_sha256,
        "expected_release_manifest_sha256": release_manifest_sha256,
        "targets": [
            {
                "target_id": target,
                "watch_roots": ["/sealed"],
                "environment": {
                    "HOME": "/target-home",
                    "PATH": "/usr/bin:/bin",
                },
                "expected_child_environment_sha256": hashlib.sha256(
                    builder.canonical_json(
                        {
                            "HOME": "/target-home",
                            "PATH": "/usr/bin:/bin",
                        }
                    )
                ).hexdigest(),
            }
            for target in builder.expected_targets()
        ],
        "production_promotion_allowed": False,
    }


def _release_artifacts(
    release_root: Path,
    *,
    runtime_payload: bytes = b"TRUSTED = True\n",
    manifest_mutator: object | None = None,
) -> tuple[str, str]:
    version_payload = b"0.1.0.dev29\n"
    (release_root / "VERSION").write_bytes(version_payload)
    runtime_path = release_root / "deployment" / "dev29" / "runtime_open_trace.py"
    runtime_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_path.write_bytes(runtime_payload)
    manifest = release_builder.payload_manifest(
        {
            "VERSION": version_payload,
            "deployment/dev29/runtime_open_trace.py": runtime_payload,
        },
        release_builder.ReleaseIdentity(
            version="0.1.0.dev29",
            commit="a1234567890b" + "c" * 28,
        ),
    )
    if manifest_mutator is not None:
        assert callable(manifest_mutator)
        manifest_mutator(manifest)
    release_manifest = release_root / "RELEASE-MANIFEST.json"
    release_manifest.write_bytes(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    return (
        hashlib.sha256(runtime_payload).hexdigest(),
        hashlib.sha256(release_manifest.read_bytes()).hexdigest(),
    )


def _validate_release_artifacts(
    tmp_path: Path,
    *,
    runtime_payload: bytes = b"TRUSTED = True\n",
    manifest_mutator: object | None = None,
) -> None:
    runtime_sha256, release_manifest_sha256 = _release_artifacts(
        tmp_path,
        runtime_payload=runtime_payload,
        manifest_mutator=manifest_mutator,
    )
    builder._verify_release_root(
        tmp_path,
        "0.1.0.dev29-a1234567890b",
        expected_runtime_module_sha256=runtime_sha256,
        expected_release_manifest_sha256=release_manifest_sha256,
        enforce_root=False,
    )


def test_release_manifest_fixture_matches_build_release_format(tmp_path: Path) -> None:
    _release_artifacts(tmp_path)
    payload = (tmp_path / "RELEASE-MANIFEST.json").read_bytes()
    document = json.loads(payload)
    assert payload == (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    assert set(document) == {
        "commit",
        "files",
        "manifest_sha256",
        "schema_version",
        "version",
    }


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda value: value.__setitem__("schema_version", True), "identity"),
        (lambda value: value.__setitem__("version", "0.1.0.dev28"), "identity"),
        (lambda value: value.__setitem__("commit", "f" * 40), "identity"),
        (lambda value: value.__setitem__("unexpected", False), "identity"),
        (
            lambda value: value.__setitem__("manifest_sha256", "0" * 64),
            "semantic digest",
        ),
    ],
)
def test_release_manifest_rejects_invalid_identity_or_semantic_digest(
    tmp_path: Path, mutator: object, message: str
) -> None:
    with pytest.raises(builder.PolicyBuildError, match=message):
        _validate_release_artifacts(tmp_path, manifest_mutator=mutator)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["files"].append(deepcopy(value["files"][0])),
            "member",
        ),
        (
            lambda value: value["files"][0].__setitem__("path", "../VERSION"),
            "member",
        ),
        (
            lambda value: value["files"][0].__setitem__("sha256", "x" * 64),
            "member",
        ),
        (
            lambda value: value["files"][0].__setitem__("size", True),
            "member",
        ),
        (
            lambda value: value["files"][0].__setitem__("size", -1),
            "member",
        ),
    ],
)
def test_release_manifest_rejects_invalid_file_entries(
    tmp_path: Path, mutator: object, message: str
) -> None:
    def reseal(value: dict[str, object]) -> None:
        assert callable(mutator)
        mutator(value)
        unsigned = {key: item for key, item in value.items() if key != "manifest_sha256"}
        value["manifest_sha256"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()

    with pytest.raises(builder.PolicyBuildError, match=message):
        _validate_release_artifacts(tmp_path, manifest_mutator=reseal)


@pytest.mark.parametrize("field", ["sha256", "size"])
def test_release_manifest_binds_runtime_member_to_stable_read_payload(
    tmp_path: Path, field: str
) -> None:
    def mutate(value: dict[str, object]) -> None:
        runtime = next(
            item
            for item in value["files"]
            if item["path"] == "deployment/dev29/runtime_open_trace.py"
        )
        runtime[field] = "f" * 64 if field == "sha256" else runtime[field] + 1
        unsigned = {key: item for key, item in value.items() if key != "manifest_sha256"}
        value["manifest_sha256"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()

    with pytest.raises(builder.PolicyBuildError, match="runtime member"):
        _validate_release_artifacts(tmp_path, manifest_mutator=mutate)


def test_release_manifest_requires_exact_build_release_serialization(tmp_path: Path) -> None:
    runtime_sha256, _manifest_sha256 = _release_artifacts(tmp_path)
    manifest_path = tmp_path / "RELEASE-MANIFEST.json"
    manifest_path.write_bytes(
        json.dumps(json.loads(manifest_path.read_bytes()), sort_keys=True).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(builder.PolicyBuildError, match="build format"):
        builder._verify_release_root(
            tmp_path,
            "0.1.0.dev29-a1234567890b",
            expected_runtime_module_sha256=runtime_sha256,
            expected_release_manifest_sha256=hashlib.sha256(
                manifest_path.read_bytes()
            ).hexdigest(),
            enforce_root=False,
        )


def test_canonical_source_digest_is_an_external_required_anchor(tmp_path: Path) -> None:
    source = _source()
    payload = builder.canonical_json(source) + b"\n"
    path = tmp_path / "policy.json"
    path.write_bytes(payload)
    assert builder._read_canonical(path, hashlib.sha256(payload).hexdigest()) == source
    with pytest.raises(builder.PolicyBuildError, match="digest mismatch"):
        builder._read_canonical(path, "f" * 64)


def test_policy_source_schema_version_rejects_bool(tmp_path: Path) -> None:
    source = _source()
    source["schema_version"] = True
    with pytest.raises(builder.PolicyBuildError, match="source identity"):
        builder.build_policy(
            source,
            expected_source_sha256=hashlib.sha256(
                builder.canonical_json(source) + b"\n"
            ).hexdigest(),
            expected_strace_sha256="a" * 64,
            expected_runtime_module_sha256="c" * 64,
            expected_release_manifest_sha256="d" * 64,
            release_root=tmp_path,
            install_parent=tmp_path / "installed",
            enforce_root=False,
        )


def test_builder_validates_every_target_and_atomically_installs_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_sha256, release_manifest_sha256 = _release_artifacts(tmp_path)
    source = _source(
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=release_manifest_sha256,
    )
    validated: list[str] = []

    class Request:
        def __init__(self, **values):
            self.__dict__.update(values)

    fake = SimpleNamespace(
        TraceRequest=Request,
        validate_manifest_document=lambda manifest, request: validated.append(
            request.target_id
        ),
    )
    monkeypatch.setattr(builder, "_load_runtime_module", lambda _payload, _path: fake)
    install_parent = tmp_path / "installed"
    install_parent.mkdir()
    source_sha256 = hashlib.sha256(builder.canonical_json(source) + b"\n").hexdigest()
    result = builder.build_policy(
        source,
        expected_source_sha256=source_sha256,
        expected_strace_sha256="a" * 64,
        expected_runtime_module_sha256=runtime_sha256,
        expected_release_manifest_sha256=release_manifest_sha256,
        release_root=tmp_path,
        install_parent=install_parent,
        enforce_root=False,
    )
    destination = install_parent / source["release"]
    index_payload = (destination / "INDEX.json").read_bytes()
    index = json.loads(index_payload)
    assert tuple(validated) == builder.expected_targets()
    assert result["index_sha256"] == hashlib.sha256(index_payload).hexdigest()
    assert result["target_count"] == len(builder.expected_targets())
    assert index["production_promotion_allowed"] is False
    assert index["policy_source_sha256"] == source_sha256
    assert all(
        item["child_environment_sha256"]
        == source["targets"][position]["expected_child_environment_sha256"]
        for position, item in enumerate(index["targets"])
    )
    assert [item["target_id"] for item in index["targets"]] == list(
        builder.expected_targets()
    )
    with pytest.raises(builder.PolicyBuildError, match="already exists"):
        builder.build_policy(
            source,
            expected_source_sha256=source_sha256,
            expected_strace_sha256="a" * 64,
            expected_runtime_module_sha256=runtime_sha256,
            expected_release_manifest_sha256=release_manifest_sha256,
            release_root=tmp_path,
            install_parent=install_parent,
            enforce_root=False,
        )


def test_builder_rejects_missing_or_reordered_required_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_sha256, release_manifest_sha256 = _release_artifacts(tmp_path)
    source = _source(
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=release_manifest_sha256,
    )
    source["targets"] = list(reversed(source["targets"]))
    fake = SimpleNamespace(
        TraceRequest=lambda **values: SimpleNamespace(**values),
        validate_manifest_document=lambda _manifest, _request: None,
    )
    monkeypatch.setattr(builder, "_load_runtime_module", lambda _payload, _path: fake)
    install_parent = tmp_path / "installed"
    install_parent.mkdir()
    source_sha256 = hashlib.sha256(builder.canonical_json(source) + b"\n").hexdigest()
    with pytest.raises(builder.PolicyBuildError, match="set or order"):
        builder.build_policy(
            source,
            expected_source_sha256=source_sha256,
            expected_strace_sha256="a" * 64,
            expected_runtime_module_sha256=runtime_sha256,
            expected_release_manifest_sha256=release_manifest_sha256,
            release_root=tmp_path,
            install_parent=install_parent,
            enforce_root=False,
        )


def test_builder_recomputes_source_digest_for_direct_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_sha256, release_manifest_sha256 = _release_artifacts(tmp_path)
    source = _source(
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=release_manifest_sha256,
    )
    monkeypatch.setattr(
        builder,
        "_load_runtime_module",
        lambda _payload, _path: SimpleNamespace(
            TraceRequest=lambda **values: SimpleNamespace(**values),
            validate_manifest_document=lambda _manifest, _request: None,
        ),
    )
    install_parent = tmp_path / "installed"
    install_parent.mkdir()
    with pytest.raises(builder.PolicyBuildError, match="source digest mismatch"):
        builder.build_policy(
            source,
            expected_source_sha256="c" * 64,
            expected_strace_sha256="a" * 64,
            expected_runtime_module_sha256=runtime_sha256,
            expected_release_manifest_sha256=release_manifest_sha256,
            release_root=tmp_path,
            install_parent=install_parent,
            enforce_root=False,
        )


def test_builder_rejects_symlink_install_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink support unavailable")
    runtime_sha256, release_manifest_sha256 = _release_artifacts(tmp_path)
    source = _source(
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=release_manifest_sha256,
    )
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "installed"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(
        builder,
        "_load_runtime_module",
        lambda _payload, _path: SimpleNamespace(
            TraceRequest=lambda **values: SimpleNamespace(**values),
            validate_manifest_document=lambda _manifest, _request: None,
        ),
    )
    with pytest.raises(builder.PolicyBuildError, match="parent is invalid"):
        builder.build_policy(
            source,
            expected_source_sha256=hashlib.sha256(
                builder.canonical_json(source) + b"\n"
            ).hexdigest(),
            expected_strace_sha256="a" * 64,
            expected_runtime_module_sha256=runtime_sha256,
            expected_release_manifest_sha256=release_manifest_sha256,
            release_root=tmp_path,
            install_parent=link,
            enforce_root=False,
        )


def test_loader_executes_verified_payload_not_the_current_path(tmp_path: Path) -> None:
    path = tmp_path / "runtime_open_trace.py"
    path.write_bytes(b"VALUE = 'untrusted path'\n")
    module = builder._load_runtime_module(b"VALUE = 'verified payload'\n", path)
    assert module.VALUE == "verified payload"


def test_builder_rejects_last_moment_validator_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trusted_payload = b"VALUE = 'trusted'\n"
    runtime_sha256, release_manifest_sha256 = _release_artifacts(
        tmp_path, runtime_payload=trusted_payload
    )
    source = _source(
        runtime_sha256=runtime_sha256,
        release_manifest_sha256=release_manifest_sha256,
    )
    runtime_path = tmp_path / "deployment" / "dev29" / "runtime_open_trace.py"
    observed: list[bytes] = []
    fake = SimpleNamespace(
        TraceRequest=lambda **values: SimpleNamespace(**values),
        validate_manifest_document=lambda _manifest, _request: None,
    )

    def replace_after_verified(payload: bytes, path: Path) -> object:
        observed.append(payload)
        path.unlink()
        path.write_bytes(b"VALUE = 'replacement'\n")
        return fake

    monkeypatch.setattr(builder, "_load_runtime_module", replace_after_verified)
    install_parent = tmp_path / "installed"
    install_parent.mkdir()
    with pytest.raises(builder.PolicyBuildError, match="validator digest differs"):
        builder.build_policy(
            source,
            expected_source_sha256=hashlib.sha256(
                builder.canonical_json(source) + b"\n"
            ).hexdigest(),
            expected_strace_sha256="a" * 64,
            expected_runtime_module_sha256=runtime_sha256,
            expected_release_manifest_sha256=release_manifest_sha256,
            release_root=tmp_path,
            install_parent=install_parent,
            enforce_root=False,
        )
    assert observed == [trusted_payload]
    assert runtime_path.read_bytes() != trusted_payload
    assert not any(install_parent.iterdir())


def test_main_forwards_all_external_digest_anchors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _source()
    source_path = tmp_path / "approved-policy.json"
    source_path.write_bytes(builder.canonical_json(source) + b"\n")
    captured: dict[str, object] = {}
    monkeypatch.setattr(builder, "_read_canonical", lambda *args, **kwargs: source)

    def fake_build(_source: object, **kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {"schema_version": 1, "production_promotion_allowed": False}

    monkeypatch.setattr(builder, "build_policy", fake_build)
    assert (
        builder.main(
            [
                "--source",
                str(source_path),
                "--expected-source-sha256",
                "1" * 64,
                "--expected-strace-sha256",
                "2" * 64,
                "--expected-runtime-module-sha256",
                "3" * 64,
                "--expected-release-manifest-sha256",
                "4" * 64,
                "--release-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert captured["expected_runtime_module_sha256"] == "3" * 64
    assert captured["expected_release_manifest_sha256"] == "4" * 64
    assert json.loads(capsys.readouterr().out)["production_promotion_allowed"] is False

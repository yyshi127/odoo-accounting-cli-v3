from __future__ import annotations

import importlib.util
import hashlib
import os
import shutil
import sqlite3
import stat
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment" / "dev8" / "dev8-persistence-audit.py"
LINUX_PROC_FDS = os.name == "posix" and Path("/proc/self/fd").is_dir()


def _load_module():
    added = []
    if importlib.util.find_spec("pwd") is None:
        sys.modules["pwd"] = types.ModuleType("pwd")
        added.append("pwd")
    try:
        spec = importlib.util.spec_from_file_location(
            "dev8_persistence_snapshot_contract", SCRIPT
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name in added:
            sys.modules.pop(name, None)


@pytest.fixture(scope="module")
def persistence():
    return _load_module()


def _create_database(path: Path, values: tuple[str, ...], *, wal: bool) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    if wal:
        assert connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
        connection.execute("PRAGMA wal_autocheckpoint = 0")
    connection.execute("CREATE TABLE sample(value TEXT NOT NULL)")
    connection.executemany("INSERT INTO sample VALUES (?)", ((value,) for value in values))
    connection.commit()
    os.chmod(path, 0o600)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            os.chmod(sidecar, 0o600)
    return connection


def _file_evidence(path: Path) -> tuple[tuple[int, ...], str]:
    noatime = getattr(os, "O_NOATIME", None)
    assert noatime is not None
    descriptor = os.open(
        path,
        os.O_RDONLY
        | noatime
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    checksum = hashlib.sha256()
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            checksum.update(chunk)
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_atime_ns,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
    return identity, checksum.hexdigest()


def _assert_no_staging_directories(path: Path) -> None:
    assert not list(path.glob(".sqlite-snapshot-*"))


def test_snapshot_contract_binds_main_and_wal_sidecars_by_full_identity():
    source = SCRIPT.read_text("utf-8")

    for field in (
        "st_dev",
        "st_ino",
        "st_uid",
        "st_gid",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    ):
        assert field in source
    assert 'STATE_SIDECAR_SUFFIXES = ("-wal", "-shm")' in source
    assert "O_NOFOLLOW" in source
    assert "O_NOATIME" in source
    assert "_copy_guarded_component" in source
    assert 'prefix=".sqlite-snapshot-"' in source
    assert "source_connection.backup(target_connection)" in source
    assert "PRAGMA query_only = ON" in source
    assert "BEGIN" in source
    assert 'f"file:/proc/self/fd/' not in source


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux /proc FD attestation")
def test_snapshot_includes_committed_rows_that_exist_only_in_wal(
    persistence, tmp_path
):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    writer = _create_database(source, ("checkpointed",), wal=True)
    try:
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("INSERT INTO sample VALUES ('wal-only')")
        writer.commit()
        wal = Path(f"{source}-wal")
        shm = Path(f"{source}-shm")
        assert wal.is_file() and wal.stat().st_size > 0 and shm.is_file()
        os.chmod(wal, 0o600)
        os.chmod(shm, 0o600)
        before = {path: _file_evidence(path) for path in (source, wal, shm)}
        observed_uris: list[str] = []
        real_connect = persistence._connect_snapshot_source

        def observing_connect(uri: str):
            observed_uris.append(uri)
            return real_connect(uri)

        persistence._connect_snapshot_source = observing_connect

        try:
            persistence.snapshot(source, target, os.getuid())
        finally:
            persistence._connect_snapshot_source = real_connect

        snapshot = sqlite3.connect(f"file:{target}?mode=ro&immutable=1", uri=True)
        try:
            assert snapshot.execute("SELECT value FROM sample ORDER BY rowid").fetchall() == [
                ("checkpointed",),
                ("wal-only",),
            ]
        finally:
            snapshot.close()
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
        assert observed_uris and ".sqlite-snapshot-" in observed_uris[0]
        assert f"file:{source.as_posix()}?" not in observed_uris[0]
        assert {path: _file_evidence(path) for path in (source, wal, shm)} == before
        _assert_no_staging_directories(tmp_path)
    finally:
        writer.close()


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux snapshot semantics")
def test_snapshot_without_sidecars_does_not_create_live_sidecars(
    persistence, tmp_path
):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    _create_database(source, ("stable",), wal=True).close()
    assert not Path(f"{source}-wal").exists()
    assert not Path(f"{source}-shm").exists()
    before = _file_evidence(source)

    persistence.snapshot(source, target, os.getuid())

    assert _file_evidence(source) == before
    assert not Path(f"{source}-wal").exists()
    assert not Path(f"{source}-shm").exists()
    snapshot = sqlite3.connect(target)
    try:
        assert snapshot.execute("SELECT value FROM sample").fetchone()[0] == "stable"
    finally:
        snapshot.close()
    _assert_no_staging_directories(tmp_path)


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux snapshot semantics")
def test_snapshot_rejects_rollback_journal(persistence, tmp_path):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    _create_database(source, ("stable",), wal=True).close()
    journal = Path(f"{source}-journal")
    journal.write_bytes(b"not-a-valid-journal")
    os.chmod(journal, 0o600)

    with pytest.raises(RuntimeError, match="rollback journal"):
        persistence.snapshot(source, target, os.getuid())

    assert not target.exists()
    assert journal.read_bytes() == b"not-a-valid-journal"
    _assert_no_staging_directories(tmp_path)


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux /proc FD attestation")
def test_snapshot_rejects_main_path_replacement(
    persistence, monkeypatch, tmp_path
):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    displaced = tmp_path / "original.sqlite3"
    replacement = tmp_path / "replacement.sqlite3"
    _create_database(source, ("original",), wal=True).close()
    _create_database(replacement, ("replacement",), wal=True).close()
    real_connect = persistence._connect_snapshot_source

    def replacing_connect(uri: str):
        source.replace(displaced)
        replacement.replace(source)
        return real_connect(uri)

    monkeypatch.setattr(persistence, "_connect_snapshot_source", replacing_connect)
    with pytest.raises(RuntimeError):
        persistence.snapshot(source, target, os.getuid())

    assert not target.exists()
    _assert_no_staging_directories(tmp_path)
    assert sqlite3.connect(displaced).execute("SELECT value FROM sample").fetchone()[0] == "original"
    assert sqlite3.connect(source).execute("SELECT value FROM sample").fetchone()[0] == "replacement"


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux /proc FD attestation")
def test_snapshot_rejects_wal_path_replacement(
    persistence, monkeypatch, tmp_path
):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    writer = _create_database(source, ("wal-row",), wal=True)
    wal = Path(f"{source}-wal")
    displaced_wal = tmp_path / "original.sqlite3-wal"
    replacement_wal = tmp_path / "replacement.sqlite3-wal"
    shutil.copyfile(wal, replacement_wal)
    os.chmod(replacement_wal, 0o600)
    real_connect = persistence._connect_snapshot_source

    def replacing_connect(uri: str):
        wal.replace(displaced_wal)
        replacement_wal.replace(wal)
        return real_connect(uri)

    monkeypatch.setattr(persistence, "_connect_snapshot_source", replacing_connect)
    try:
        with pytest.raises((RuntimeError, sqlite3.Error)):
            persistence.snapshot(source, target, os.getuid())
        assert not target.exists()
        assert wal.is_file() and displaced_wal.is_file()
        _assert_no_staging_directories(tmp_path)
    finally:
        writer.close()


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux /proc FD attestation")
@pytest.mark.parametrize("mutation", ("mode", "mtime"))
def test_snapshot_rejects_full_metadata_changes(
    persistence, monkeypatch, tmp_path, mutation
):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    _create_database(source, ("stable",), wal=True).close()
    real_connect = persistence._connect_snapshot_source

    def mutating_connect(uri: str):
        if mutation == "mode":
            os.chmod(source, 0o400)
        else:
            current = source.stat()
            os.utime(source, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000))
        return real_connect(uri)

    monkeypatch.setattr(persistence, "_connect_snapshot_source", mutating_connect)
    with pytest.raises(RuntimeError):
        persistence.snapshot(source, target, os.getuid())
    assert not target.exists()
    _assert_no_staging_directories(tmp_path)


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux snapshot semantics")
def test_snapshot_publish_collision_does_not_overwrite_target(
    persistence, monkeypatch, tmp_path
):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    _create_database(source, ("stable",), wal=True).close()
    real_link = persistence.os.link

    def colliding_link(source_path, target_path, **kwargs):
        Path(target_path).write_bytes(b"collision")
        return real_link(source_path, target_path, **kwargs)

    monkeypatch.setattr(persistence.os, "link", colliding_link)
    with pytest.raises(FileExistsError):
        persistence.snapshot(source, target, os.getuid())

    assert target.read_bytes() == b"collision"
    _assert_no_staging_directories(tmp_path)


@pytest.mark.skipif(not LINUX_PROC_FDS, reason="requires Linux snapshot semantics")
def test_snapshot_failure_after_publish_removes_only_its_target(
    persistence, monkeypatch, tmp_path
):
    source = tmp_path / "live.sqlite3"
    target = tmp_path / "snapshot.sqlite3"
    _create_database(source, ("stable",), wal=True).close()
    real_fsync_directory = persistence._fsync_directory

    def failing_after_publish(path: Path):
        if path == target.parent and target.exists():
            raise RuntimeError("injected post-publish failure")
        return real_fsync_directory(path)

    monkeypatch.setattr(persistence, "_fsync_directory", failing_after_publish)
    with pytest.raises(RuntimeError, match="post-publish"):
        persistence.snapshot(source, target, os.getuid())

    assert not target.exists()
    _assert_no_staging_directories(tmp_path)

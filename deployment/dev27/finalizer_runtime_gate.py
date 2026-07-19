"""Collect and verify the finalizer's observed eager-import runtime closure."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "odoo-accounting-cli-v3.finalizer-runtime-manifest.v2"
_FINALIZER_MODULE = "odoo_accounting_cli_v3.effect_finalizer_main"
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_PROBE_BYTES = 1024 * 1024
_USAGE = (
    "usage: finalizer_runtime_gate.py collect --interpreter ABSOLUTE_PATH\n"
    "       finalizer_runtime_gate.py verify --interpreter ABSOLUTE_PATH "
    "--manifest ABSOLUTE_PATH --expected-manifest-sha256 64_LOWERCASE_HEX"
)
_FAILURE = "finalizer runtime dependency gate failed closed"
_PROBE_FIELDS = frozenset(
    {
        "executable",
        "finalizer_module_file",
        "isolated",
        "mapped_files",
        "odoo_import_rejected",
        "odoo_spec_present",
        "pth_files",
        "psycopg2_files",
        "psycopg2_version",
        "python_module_files",
        "python_version",
        "python_version_info",
        "sys_path_directories",
        "sys_path_files",
        "sys_path_missing",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "interpreter",
        "source_root",
        "finalizer_module_file",
        "runtime",
        "python_module_files",
        "psycopg2_files",
        "sys_path_directories",
        "sys_path_files",
        "sys_path_missing",
        "pth_files",
        "mapped_files",
    }
)
_RUNTIME_FIELDS = frozenset(
    {"python_version", "python_version_info", "psycopg2_version"}
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class FinalizerRuntimeGateError(RuntimeError):
    """The observed finalizer runtime is absent, unsafe, or drifted."""


_PROBE_CODE = r"""
import importlib
import importlib.util
import json
import os
import sys

if (sys.flags.isolated != 1 or sys.flags.dont_write_bytecode != 1
        or sys.flags.utf8_mode != 1 or sys.dont_write_bytecode is not True):
    raise SystemExit("isolated Python flags are absent")

if len(sys.argv) != 2:
    raise SystemExit("the finalizer source root is absent")
source_root = sys.argv[1]
if (not os.path.isabs(source_root) or os.path.abspath(source_root) != source_root
        or not os.path.isdir(source_root)):
    raise SystemExit("the finalizer source root is invalid")
sys.path.insert(0, source_root)

odoo_spec_present = importlib.util.find_spec("odoo") is not None
if odoo_spec_present:
    raise SystemExit("Odoo is visible to the isolated finalizer interpreter")
try:
    importlib.import_module("odoo")
except ModuleNotFoundError as exc:
    if exc.name != "odoo":
        raise
    odoo_import_rejected = True
else:
    raise SystemExit("Odoo unexpectedly imported")

finalizer = importlib.import_module(
    "odoo_accounting_cli_v3.effect_finalizer_main"
)
import psycopg2

python_module_files = set()
psycopg2_files = set()
for name, module in tuple(sys.modules.items()):
    for attribute in ("__file__", "__cached__"):
        value = getattr(module, attribute, None)
        if isinstance(value, str) and os.path.isabs(value) and os.path.isfile(value):
            value = os.path.abspath(value)
            python_module_files.add(value)
            if name == "psycopg2" or name.startswith("psycopg2."):
                psycopg2_files.add(value)

sys_path_directories = set()
sys_path_files = set()
sys_path_missing = set()
for value in sys.path:
    if not isinstance(value, str) or not os.path.isabs(value):
        raise SystemExit("an isolated sys.path entry is not absolute")
    value = os.path.abspath(value)
    if os.path.isdir(value):
        sys_path_directories.add(value)
    elif os.path.isfile(value):
        sys_path_files.add(value)
    elif os.path.islink(value) or not os.path.lexists(value):
        sys_path_missing.add(value)
    else:
        raise SystemExit("an isolated sys.path entry has an unsupported type")

pth_files = set()
for directory in sys_path_directories:
    try:
        names = os.listdir(directory)
    except OSError:
        raise SystemExit("an isolated sys.path directory is unavailable")
    for name in names:
        if not name.endswith(".pth"):
            continue
        value = os.path.abspath(os.path.join(directory, name))
        if os.path.isfile(value):
            pth_files.add(value)

mapped_files = set()
with open("/proc/self/maps", "r", encoding="utf-8") as stream:
    for line in stream:
        fields = line.rstrip("\n").split(maxsplit=5)
        if len(fields) != 6:
            continue
        value = fields[5]
        if value.endswith(" (deleted)"):
            raise SystemExit("a loaded native object was deleted")
        if value.startswith("/"):
            mapped_files.add(value)

payload = {
    "executable": os.path.abspath(sys.executable),
    "finalizer_module_file": os.path.abspath(finalizer.__file__),
    "isolated": int(sys.flags.isolated),
    "mapped_files": sorted(mapped_files),
    "odoo_import_rejected": odoo_import_rejected,
    "odoo_spec_present": odoo_spec_present,
    "pth_files": sorted(pth_files),
    "psycopg2_files": sorted(psycopg2_files),
    "psycopg2_version": str(psycopg2.__version__),
    "python_module_files": sorted(python_module_files),
    "python_version": sys.version,
    "python_version_info": list(sys.version_info[:3]),
    "sys_path_directories": sorted(sys_path_directories),
    "sys_path_files": sorted(sys_path_files),
    "sys_path_missing": sorted(sys_path_missing),
}
print(json.dumps(payload, ensure_ascii=True, allow_nan=False, sort_keys=True,
                 separators=(",", ":")))
"""


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FinalizerRuntimeGateError("manifest contains a duplicate key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise FinalizerRuntimeGateError("manifest contains a non-finite number")


def _kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _metadata(path: Path, *, require_root_owner: bool) -> dict[str, object]:
    try:
        value = path.lstat()
    except OSError as exc:
        raise FinalizerRuntimeGateError("runtime path is unavailable") from exc
    kind = _kind(value.st_mode)
    if kind == "other":
        raise FinalizerRuntimeGateError("runtime path has an unsupported type")
    if os.name == "posix" and require_root_owner:
        if value.st_uid != 0:
            raise FinalizerRuntimeGateError("runtime path is not root owned")
        if kind != "symlink" and stat.S_IMODE(value.st_mode) & 0o022:
            raise FinalizerRuntimeGateError("runtime path is group/world writable")
    result: dict[str, object] = {
        "path": str(path),
        "kind": kind,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "uid": int(getattr(value, "st_uid", 0)),
        "gid": int(getattr(value, "st_gid", 0)),
        "device": int(value.st_dev),
        "inode": int(value.st_ino),
    }
    if kind == "symlink":
        try:
            result["link_target"] = os.readlink(path)
        except OSError as exc:
            raise FinalizerRuntimeGateError("runtime symlink is unavailable") from exc
    return result


def _absolute_path(value: str | os.PathLike[str], label: str) -> Path:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise FinalizerRuntimeGateError(f"{label} is invalid") from exc
    if not isinstance(text, str) or not text or "\x00" in text:
        raise FinalizerRuntimeGateError(f"{label} is invalid")
    path = Path(text)
    if not path.is_absolute() or os.path.abspath(text) != text:
        raise FinalizerRuntimeGateError(f"{label} must be normalized and absolute")
    return path


def _components(path: Path) -> list[Path]:
    parts = path.parts
    if not parts:
        raise FinalizerRuntimeGateError("runtime path is invalid")
    current = Path(parts[0])
    result = [current]
    for part in parts[1:]:
        current = current / part
        result.append(current)
    return result


def _trusted_chain(path: Path, *, require_root_owner: bool) -> list[dict[str, object]]:
    result = []
    components = _components(path)
    for index, component in enumerate(components):
        item = _metadata(component, require_root_owner=require_root_owner)
        if index < len(components) - 1 and item["kind"] not in {
            "directory",
            "symlink",
        }:
            raise FinalizerRuntimeGateError("runtime ancestor is not a directory")
        result.append(item)
    return result


def _file_record(
    value: str | os.PathLike[str], *, require_root_owner: bool
) -> dict[str, object]:
    observed = _absolute_path(value, "runtime file path")
    observed_chain = _trusted_chain(observed, require_root_owner=require_root_owner)
    try:
        canonical = Path(os.path.realpath(observed)).resolve(strict=True)
    except OSError as exc:
        raise FinalizerRuntimeGateError("runtime file cannot be resolved") from exc
    canonical_chain = _trusted_chain(canonical, require_root_owner=require_root_owner)
    if canonical_chain[-1]["kind"] != "regular":
        raise FinalizerRuntimeGateError("runtime file target is not regular")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(canonical, flags)
        try:
            before = os.fstat(descriptor)
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise FinalizerRuntimeGateError("runtime file cannot be read safely") from exc
    stable_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    stable_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    target = canonical.lstat()
    descriptor_stable = (
        stable_before == stable_after
        if os.name == "posix"
        else before.st_size == after.st_size
    )
    descriptor_matches_path = (
        (after.st_dev, after.st_ino) == (target.st_dev, target.st_ino)
        if os.name == "posix"
        else after.st_size == target.st_size
    )
    if (
        not stat.S_ISREG(before.st_mode)
        or not descriptor_stable
        or not stat.S_ISREG(target.st_mode)
        or not descriptor_matches_path
        or size != before.st_size
    ):
        raise FinalizerRuntimeGateError("runtime file changed while hashed")
    return {
        "observed_path": str(observed),
        "canonical_path": str(canonical),
        "observed_chain": observed_chain,
        "canonical_chain": canonical_chain,
        "size": size,
        "sha256": digest.hexdigest(),
    }


def _directory_record(
    value: str | os.PathLike[str], *, require_root_owner: bool
) -> dict[str, object]:
    observed = _absolute_path(value, "runtime directory path")
    observed_chain = _trusted_chain(observed, require_root_owner=require_root_owner)
    try:
        canonical = Path(os.path.realpath(observed)).resolve(strict=True)
    except OSError as exc:
        raise FinalizerRuntimeGateError(
            "runtime directory cannot be resolved"
        ) from exc
    canonical_chain = _trusted_chain(canonical, require_root_owner=require_root_owner)
    if canonical_chain[-1]["kind"] != "directory":
        raise FinalizerRuntimeGateError("runtime directory target is not a directory")
    return {
        "observed_path": str(observed),
        "canonical_path": str(canonical),
        "observed_chain": observed_chain,
        "canonical_chain": canonical_chain,
    }


def _deepest_existing_component(path: Path) -> Path:
    for candidate in reversed(_components(path)):
        try:
            candidate.lstat()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as exc:
            raise FinalizerRuntimeGateError(
                "missing runtime path ancestor is unavailable"
            ) from exc
        return candidate
    raise FinalizerRuntimeGateError("missing runtime path has no existing ancestor")


def _missing_path_record(
    value: str | os.PathLike[str], *, require_root_owner: bool
) -> dict[str, object]:
    missing = _absolute_path(value, "missing sys.path entry")
    if missing.is_dir() or missing.is_file():
        raise FinalizerRuntimeGateError("missing sys.path entry now exists")
    try:
        metadata = missing.lstat()
    except (FileNotFoundError, NotADirectoryError):
        metadata = None
    except OSError as exc:
        raise FinalizerRuntimeGateError(
            "missing sys.path entry is unavailable"
        ) from exc
    if metadata is not None and not stat.S_ISLNK(metadata.st_mode):
        raise FinalizerRuntimeGateError(
            "missing sys.path entry has an unsupported type"
        )

    observed_ancestor = _deepest_existing_component(missing)
    observed_chain = _trusted_chain(
        observed_ancestor, require_root_owner=require_root_owner
    )
    canonical_candidate = _absolute_path(
        os.path.realpath(missing), "canonical missing sys.path entry"
    )
    if canonical_candidate.is_dir() or canonical_candidate.is_file():
        raise FinalizerRuntimeGateError("missing sys.path target now exists")
    canonical_ancestor = _deepest_existing_component(canonical_candidate)
    canonical_chain = _trusted_chain(
        canonical_ancestor, require_root_owner=require_root_owner
    )
    if missing.is_dir() or missing.is_file():
        raise FinalizerRuntimeGateError(
            "missing sys.path entry changed while inspected"
        )
    return {
        "path": str(missing),
        "observed_deepest_existing_ancestor": str(observed_ancestor),
        "observed_ancestor_chain": observed_chain,
        "canonical_candidate": str(canonical_candidate),
        "canonical_deepest_existing_ancestor": str(canonical_ancestor),
        "canonical_ancestor_chain": canonical_chain,
    }


def _finalizer_source_root() -> Path:
    try:
        release_root = Path(__file__).resolve(strict=True).parents[2]
    except (OSError, IndexError) as exc:
        raise FinalizerRuntimeGateError(
            "the finalizer release root is unavailable"
        ) from exc
    return release_root / "src"


def _run_probe(interpreter: Path, source_root: Path) -> Mapping[str, Any]:
    if os.name != "posix" or not Path("/proc/self/maps").is_file():
        raise FinalizerRuntimeGateError("the finalizer runtime gate requires Linux procfs")
    try:
        process = subprocess.run(
            [
                str(interpreter),
                "-I",
                "-B",
                "-X",
                "utf8",
                "-c",
                _PROBE_CODE,
                str(source_root),
            ],
            cwd="/",
            env={"LD_BIND_NOW": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FinalizerRuntimeGateError("isolated dependency probe failed") from exc
    if (
        process.returncode != 0
        or process.stderr
        or not process.stdout
        or len(process.stdout) > _MAX_PROBE_BYTES
        or b"\x00" in process.stdout
    ):
        raise FinalizerRuntimeGateError("isolated dependency probe was rejected")
    try:
        value = json.loads(
            process.stdout.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except FinalizerRuntimeGateError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise FinalizerRuntimeGateError("isolated dependency probe is invalid") from exc
    if not isinstance(value, Mapping) or set(value) != _PROBE_FIELDS:
        raise FinalizerRuntimeGateError("isolated dependency probe fields are invalid")
    return value


def _strict_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 512
        or any(ord(character) < 32 and character not in "\t\n" for character in value)
    ):
        raise FinalizerRuntimeGateError(f"{label} is invalid")
    return value


def _path_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if (
        not isinstance(value, list)
        or (not value and not allow_empty)
        or any(not isinstance(item, str) for item in value)
        or value != sorted(set(value))
    ):
        raise FinalizerRuntimeGateError(f"{label} is invalid")
    for item in value:
        _absolute_path(item, label)
    return value


def collect_manifest(
    interpreter_path: str | os.PathLike[str], *, require_root_owner: bool = True
) -> dict[str, object]:
    if type(require_root_owner) is not bool:
        raise FinalizerRuntimeGateError("runtime owner policy is invalid")
    interpreter = _absolute_path(interpreter_path, "interpreter path")
    interpreter_record = _file_record(
        interpreter, require_root_owner=require_root_owner
    )
    source_root = _absolute_path(_finalizer_source_root(), "finalizer source root")
    source_root_record = _directory_record(
        source_root, require_root_owner=require_root_owner
    )
    expected_finalizer_file = (
        source_root / Path(*_FINALIZER_MODULE.split("."))
    ).with_suffix(".py")
    expected_finalizer_record = _file_record(
        expected_finalizer_file, require_root_owner=require_root_owner
    )
    probe = _run_probe(interpreter, source_root)
    if (
        probe["isolated"] != 1
        or probe["odoo_spec_present"] is not False
        or probe["odoo_import_rejected"] is not True
    ):
        raise FinalizerRuntimeGateError("isolated Odoo visibility policy failed")
    executable = _absolute_path(probe["executable"], "probe executable")
    if Path(os.path.realpath(executable)).resolve(strict=True) != Path(
        interpreter_record["canonical_path"]
    ):
        raise FinalizerRuntimeGateError("probe interpreter identity differs")
    version_info = probe["python_version_info"]
    if (
        not isinstance(version_info, list)
        or len(version_info) != 3
        or any(type(item) is not int or item < 0 for item in version_info)
    ):
        raise FinalizerRuntimeGateError("probe Python version is invalid")
    finalizer_module_file = _absolute_path(
        probe["finalizer_module_file"], "finalizer module file"
    )
    if Path(os.path.realpath(finalizer_module_file)).resolve(strict=True) != Path(
        expected_finalizer_record["canonical_path"]
    ):
        raise FinalizerRuntimeGateError("finalizer module identity differs")
    python_module_paths = _path_list(
        probe["python_module_files"], "Python module file list"
    )
    module_paths = _path_list(probe["psycopg2_files"], "psycopg2 file list")
    sys_path_directories = _path_list(
        probe["sys_path_directories"], "sys.path directory list"
    )
    sys_path_files = _path_list(
        probe["sys_path_files"], "sys.path file list", allow_empty=True
    )
    sys_path_missing = _path_list(
        probe["sys_path_missing"], "missing sys.path list", allow_empty=True
    )
    pth_paths = _path_list(probe["pth_files"], ".pth file list", allow_empty=True)
    mapped_paths = _path_list(probe["mapped_files"], "native mapping list")
    if (
        str(finalizer_module_file) not in python_module_paths
        or not set(module_paths).issubset(python_module_paths)
        or str(source_root) not in sys_path_directories
    ):
        raise FinalizerRuntimeGateError(
            "observed eager-import closure is incomplete"
        )
    module_names = [Path(item).name for item in module_paths]
    mapped_names = [Path(item).name for item in mapped_paths]
    if not any(name.startswith("_psycopg") and ".so" in name for name in module_names):
        raise FinalizerRuntimeGateError("psycopg2 native extension is absent")
    if not any(name.startswith("libpq.so") for name in mapped_names):
        raise FinalizerRuntimeGateError("libpq native dependency is absent")
    return {
        "schema_version": SCHEMA_VERSION,
        "interpreter": interpreter_record,
        "source_root": source_root_record,
        "finalizer_module_file": expected_finalizer_record,
        "runtime": {
            "python_version": _strict_text(probe["python_version"], "Python version"),
            "python_version_info": version_info,
            "psycopg2_version": _strict_text(
                probe["psycopg2_version"], "psycopg2 version"
            ),
        },
        "python_module_files": [
            _file_record(item, require_root_owner=require_root_owner)
            for item in python_module_paths
        ],
        "psycopg2_files": [
            _file_record(item, require_root_owner=require_root_owner)
            for item in module_paths
        ],
        "sys_path_directories": [
            _directory_record(item, require_root_owner=require_root_owner)
            for item in sys_path_directories
        ],
        "sys_path_files": [
            _file_record(item, require_root_owner=require_root_owner)
            for item in sys_path_files
        ],
        "sys_path_missing": [
            _missing_path_record(item, require_root_owner=require_root_owner)
            for item in sys_path_missing
        ],
        "pth_files": [
            _file_record(item, require_root_owner=require_root_owner)
            for item in pth_paths
        ],
        "mapped_files": [
            _file_record(item, require_root_owner=require_root_owner)
            for item in mapped_paths
        ],
    }


def _read_manifest(
    manifest_path: str | os.PathLike[str], *, require_root_owner: bool
) -> dict[str, Any]:
    record = _file_record(manifest_path, require_root_owner=require_root_owner)
    if record["size"] > _MAX_MANIFEST_BYTES:
        raise FinalizerRuntimeGateError("runtime manifest is too large")
    try:
        raw = Path(record["canonical_path"]).read_bytes()
    except OSError as exc:
        raise FinalizerRuntimeGateError("runtime manifest is unavailable") from exc
    if hashlib.sha256(raw).hexdigest() != record["sha256"]:
        raise FinalizerRuntimeGateError("runtime manifest changed while read")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except FinalizerRuntimeGateError:
        raise
    except (UnicodeError, ValueError) as exc:
        raise FinalizerRuntimeGateError("runtime manifest is invalid") from exc
    if not isinstance(value, dict) or _canonical_json(value) != raw:
        raise FinalizerRuntimeGateError("runtime manifest is not canonical JSON")
    if (
        set(value) != _MANIFEST_FIELDS
        or value.get("schema_version") != SCHEMA_VERSION
        or not isinstance(value.get("runtime"), dict)
        or set(value["runtime"]) != _RUNTIME_FIELDS
        or not isinstance(value.get("interpreter"), dict)
        or not isinstance(value.get("source_root"), dict)
        or not isinstance(value.get("finalizer_module_file"), dict)
        or not isinstance(value.get("python_module_files"), list)
        or not isinstance(value.get("psycopg2_files"), list)
        or not isinstance(value.get("sys_path_directories"), list)
        or not isinstance(value.get("sys_path_files"), list)
        or not isinstance(value.get("sys_path_missing"), list)
        or not isinstance(value.get("pth_files"), list)
        or not isinstance(value.get("mapped_files"), list)
    ):
        raise FinalizerRuntimeGateError("runtime manifest fields are invalid")
    return value


def verify_manifest(
    interpreter_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str],
    expected_manifest_sha256: str,
    *,
    require_root_owner: bool = True,
) -> str:
    if (
        not isinstance(expected_manifest_sha256, str)
        or _SHA256.fullmatch(expected_manifest_sha256) is None
    ):
        raise FinalizerRuntimeGateError("expected manifest digest is invalid")
    expected = _read_manifest(
        manifest_path, require_root_owner=require_root_owner
    )
    expected_bytes = _canonical_json(expected)
    expected_digest = hashlib.sha256(expected_bytes).hexdigest()
    if expected_digest != expected_manifest_sha256:
        raise FinalizerRuntimeGateError("external manifest digest differs")
    observed = collect_manifest(
        interpreter_path, require_root_owner=require_root_owner
    )
    observed_bytes = _canonical_json(observed)
    if not hashlib.sha256(expected_bytes).digest() == hashlib.sha256(
        observed_bytes
    ).digest() or expected_bytes != observed_bytes:
        raise FinalizerRuntimeGateError(
            "finalizer observed eager-import runtime drifted"
        )
    return expected_digest


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--help"]:
        print(_USAGE)
        return 0
    try:
        if len(arguments) == 3 and arguments[:2] == ["collect", "--interpreter"]:
            manifest = collect_manifest(arguments[2])
            sys.stdout.buffer.write(_canonical_json(manifest))
            return 0
        if (
            len(arguments) == 7
            and arguments[0] == "verify"
            and arguments[1] == "--interpreter"
            and arguments[3] == "--manifest"
            and arguments[5] == "--expected-manifest-sha256"
        ):
            digest = verify_manifest(arguments[2], arguments[4], arguments[6])
            sys.stdout.buffer.write(
                _canonical_json({"manifest_sha256": digest, "ok": True})
            )
            return 0
    except FinalizerRuntimeGateError:
        print(_FAILURE, file=sys.stderr)
        return 1
    print(_USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Read-only target-host capacity remediation planner."""

from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA_VERSION = 1
PLAN_KIND = "odoo-accounting-cli-v3.target-capacity-plan.v1"
DEFAULT_REQUIRED_FREE_BYTES = 6 * 1024 * 1024 * 1024
RELEASE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$")
RELEASES_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/releases")
DEPENDENCY_IMAGES_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/dependency-images")
PACKAGES_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/packages")
UPLOAD_SOURCES_BASE = PurePosixPath("/opt/odoo-accounting-cli-v3/upload-sources")
EVIDENCE_PRIVATE_BASE = PurePosixPath("/var/lib/odoo-accounting-cli-v3/evidence-private")
DEPENDENCY_BUILD_BASE = PurePosixPath("/var/lib/odoo-accounting-cli-v3/dependency-build")


class CapacityPlanError(ValueError):
    pass


@dataclass(frozen=True)
class Candidate:
    path: str
    kind: str
    category: str
    risk: str
    size_bytes: int
    reason: str
    requires_explicit_authorization: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "category": self.category,
            "risk": self.risk,
            "size_bytes": self.size_bytes,
            "reason": self.reason,
            "requires_explicit_authorization": self.requires_explicit_authorization,
        }


def _rooted(root: Path, absolute: PurePosixPath) -> Path:
    if not absolute.is_absolute():
        raise CapacityPlanError("internal path is not absolute")
    return root.joinpath(*absolute.parts[1:])


def _display_path(root: Path, path: Path) -> str:
    absolute_root = root.resolve()
    absolute_path = path.resolve()
    try:
        relative = absolute_path.relative_to(absolute_root)
    except ValueError as exc:
        raise CapacityPlanError("candidate path escaped root") from exc
    return "/" + relative.as_posix()


def _safe_size(path: Path) -> tuple[int, str]:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return 0, "missing"
    if stat.S_ISLNK(metadata.st_mode):
        return 0, "symlink"
    if stat.S_ISREG(metadata.st_mode):
        return metadata.st_size, "file"
    if not stat.S_ISDIR(metadata.st_mode):
        return 0, "special"
    total = metadata.st_size
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        item = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISLNK(item.st_mode):
                        continue
                    total += item.st_size
                    if stat.S_ISDIR(item.st_mode):
                        stack.append(Path(entry.path))
        except (FileNotFoundError, NotADirectoryError):
            continue
    return total, "directory"


def _iter_children(path: Path) -> Iterable[Path]:
    try:
        children = sorted(path.iterdir(), key=lambda item: item.name)
    except FileNotFoundError:
        return ()
    return tuple(children)


def _candidate(
    root: Path,
    path: Path,
    *,
    category: str,
    risk: str,
    reason: str,
) -> Candidate | None:
    size, kind = _safe_size(path)
    if kind in {"missing", "symlink", "special"} or size <= 0:
        return None
    return Candidate(
        path=_display_path(root, path),
        kind=kind,
        category=category,
        risk=risk,
        size_bytes=size,
        reason=reason,
    )


def validate_keep_releases(values: Iterable[str]) -> frozenset[str]:
    releases = frozenset(values)
    if any(RELEASE.fullmatch(value) is None for value in releases):
        raise CapacityPlanError("keep release is invalid")
    return releases


def collect_candidates(root: Path, *, keep_releases: frozenset[str]) -> list[Candidate]:
    root = root.resolve()
    candidates: list[Candidate] = []

    for child in _iter_children(_rooted(root, EVIDENCE_PRIVATE_BASE)):
        candidate = _candidate(
            root,
            child,
            category="evidence_private",
            risk="may_remove_unpublished_private_trace_evidence",
            reason=(
                "private runtime-open trace/evidence is not a release package; "
                "retain if it is still needed for an unpublished evidence review"
            ),
        )
        if candidate is not None:
            candidates.append(candidate)

    for child in _iter_children(_rooted(root, DEPENDENCY_IMAGES_BASE)):
        if child.suffix != ".squashfs":
            continue
        release = child.name.removesuffix(".squashfs")
        if release in keep_releases:
            continue
        candidate = _candidate(
            root,
            child,
            category="old_dependency_image",
            risk="may_remove_old_unrouted_dependency_image",
            reason="old immutable dependency image; keep any release still routed or under review",
        )
        if candidate is not None:
            candidates.append(candidate)

    for base, category, reason in (
        (
            DEPENDENCY_BUILD_BASE,
            "stale_dependency_build_stage",
            "temporary dependency build staging; should be empty outside an active build",
        ),
        (
            UPLOAD_SOURCES_BASE,
            "uploaded_release_source",
            "uploaded tarball source; canonical package copy is under packages/",
        ),
    ):
        for child in _iter_children(_rooted(root, base)):
            candidate = _candidate(
                root,
                child,
                category=category,
                risk="operator_review_required",
                reason=reason,
            )
            if candidate is not None:
                candidates.append(candidate)

    for child in _iter_children(_rooted(root, PACKAGES_BASE)):
        release = child.name
        prefix = "odoo-accounting-cli-v3-"
        suffix = ".tar.gz"
        if release.startswith(prefix) and release.endswith(suffix):
            release = release[len(prefix) : -len(suffix)]
        if release in keep_releases:
            continue
        candidate = _candidate(
            root,
            child,
            category="old_release_package_copy",
            risk="may_remove_old_package_copy_only_if_release_not_needed_for_rollback",
            reason="package copy for an older release; retain rollback releases",
        )
        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(key=lambda item: (-item.size_bytes, item.path))
    return candidates


def filesystem_summary(root: Path, probe: PurePosixPath) -> dict[str, int | str]:
    path = _rooted(root.resolve(), probe)
    if hasattr(os, "statvfs"):
        stats = os.statvfs(path)
        available = stats.f_bavail * stats.f_frsize
        total = stats.f_blocks * stats.f_frsize
    else:
        usage = shutil.disk_usage(path)
        available = usage.free
        total = usage.total
    return {
        "probe_path": str(probe),
        "total_bytes": total,
        "available_bytes": available,
        "used_bytes": total - available,
    }


def build_plan(
    *,
    root: Path,
    required_free_bytes: int,
    keep_releases: frozenset[str],
) -> dict[str, Any]:
    if required_free_bytes <= 0:
        raise CapacityPlanError("required free bytes must be positive")
    fs = filesystem_summary(root, PurePosixPath("/"))
    candidates = collect_candidates(root, keep_releases=keep_releases)
    candidate_bytes = sum(item.size_bytes for item in candidates)
    available = int(fs["available_bytes"])
    shortfall = max(0, required_free_bytes - available)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": PLAN_KIND,
        "mode": "read_only_plan_no_delete",
        "root": str(root.resolve()),
        "required_free_bytes": required_free_bytes,
        "filesystem": fs,
        "shortfall_bytes": shortfall,
        "candidate_reclaimable_bytes": candidate_bytes,
        "candidate_count": len(candidates),
        "keep_releases": sorted(keep_releases),
        "candidates": [item.as_dict() for item in candidates],
        "authorization_required_before_cleanup": True,
        "cleanup_executed": False,
    }

"""Odoo Accounting CLI V3."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _source_version() -> str:
    try:
        value = (Path(__file__).resolve().parents[2] / "VERSION").read_text(
            encoding="utf-8"
        ).strip()
    except OSError:
        return "unknown"
    return value or "unknown"

__version__ = _source_version()
if __version__ == "unknown":
    try:
        __version__ = version("odoo-accounting-cli-v3")
    except PackageNotFoundError:
        pass

__all__ = ["__version__"]

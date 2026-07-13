"""Odoo Accounting CLI V3."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("odoo-accounting-cli-v3")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = ["__version__"]

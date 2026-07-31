"""Process-local authority for assigning protected V3 accounting metadata."""

from contextlib import contextmanager
from contextvars import ContextVar


_SCOPE_TOKEN = object()
_ACTIVE_SCOPE = ContextVar("odoo_accounting_cli_v3_metadata_scope", default=None)


def _v3_execution_scope_is_active():
    return _ACTIVE_SCOPE.get() is _SCOPE_TOKEN


def _accounting_metadata_write_is_allowed():
    return _v3_execution_scope_is_active()


@contextmanager
def _accounting_metadata_execution_scope():
    token = _ACTIVE_SCOPE.set(_SCOPE_TOKEN)
    try:
        yield
    finally:
        _ACTIVE_SCOPE.reset(token)

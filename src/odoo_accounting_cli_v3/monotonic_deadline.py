"""Process-local absolute deadline scope for bounded trusted runtime work."""

from __future__ import annotations

import contextvars
import math
import time
from contextlib import contextmanager
from typing import Iterator


_CURRENT_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "odoo_accounting_cli_v3_monotonic_deadline",
    default=None,
)
_monotonic = time.monotonic


class MonotonicDeadlineError(ValueError):
    """An absolute process-local deadline or derived budget was invalid."""


class MonotonicDeadlineExceeded(TimeoutError):
    """The active absolute deadline expired before bounded work could start."""


def _validated_deadline(value: float | None) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise MonotonicDeadlineError("monotonic deadline is invalid")
    return float(value)


def _configured_busy_timeout_ms(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MonotonicDeadlineError("SQLite busy timeout is invalid")
    return value


def current_monotonic_deadline() -> float | None:
    """Return the effective deadline in this context, if one is active."""

    return _CURRENT_DEADLINE.get()


@contextmanager
def monotonic_deadline_scope(deadline_monotonic: float | None) -> Iterator[float | None]:
    """Install a deadline that nested code may shorten but never extend."""

    requested = _validated_deadline(deadline_monotonic)
    current = _CURRENT_DEADLINE.get()
    if current is None:
        effective = requested
    elif requested is None:
        effective = current
    else:
        effective = min(current, requested)
    token = _CURRENT_DEADLINE.set(effective)
    try:
        yield effective
    finally:
        _CURRENT_DEADLINE.reset(token)


def copy_monotonic_deadline_context() -> contextvars.Context:
    """Capture the current context for explicit propagation into a new thread."""

    return contextvars.copy_context()


def _remaining_seconds() -> float | None:
    deadline = _CURRENT_DEADLINE.get()
    if deadline is None:
        return None
    remaining = deadline - _monotonic()
    if remaining <= 0:
        raise MonotonicDeadlineExceeded("monotonic deadline was exceeded")
    return remaining


def bounded_sqlite_connect_timeout_seconds(configured_busy_timeout_ms: int) -> float:
    """Bound one sqlite3.connect lock wait by the current remaining time."""

    return bounded_sqlite_busy_timeout_ms(configured_busy_timeout_ms) / 1000.0


def bounded_sqlite_busy_timeout_ms(configured_busy_timeout_ms: int) -> int:
    """Bound one SQLite PRAGMA busy timeout without rounding past the deadline."""

    configured = _configured_busy_timeout_ms(configured_busy_timeout_ms)
    remaining = _remaining_seconds()
    if remaining is None:
        return configured
    remaining_ms = max(0, math.floor(remaining * 1000.0))
    return min(configured, remaining_ms)


__all__ = [
    "MonotonicDeadlineError",
    "MonotonicDeadlineExceeded",
    "bounded_sqlite_busy_timeout_ms",
    "bounded_sqlite_connect_timeout_seconds",
    "copy_monotonic_deadline_context",
    "current_monotonic_deadline",
    "monotonic_deadline_scope",
]

"""Small Qt compatibility layer for headless tests/CLI imports.

The GUI still uses PySide6 when it is installed.  In environments where PySide6
is not available, scanner core modules can still be imported and unit-tested
with this lightweight signal implementation.
"""

try:  # pragma: no cover - exercised only when PySide6 is installed
    from PySide6.QtCore import QObject, Signal  # type: ignore
except Exception:  # pragma: no cover - deterministic fallback for CI/headless
    class _BoundSignal:
        def __init__(self):
            self._slots = []

        def connect(self, slot):
            self._slots.append(slot)

        def emit(self, *args, **kwargs):
            for slot in list(self._slots):
                slot(*args, **kwargs)

    class Signal:
        def __init__(self, *args, **kwargs):
            self._name = None

        def __set_name__(self, owner, name):
            self._name = f"__signal_{name}"

        def __get__(self, instance, owner):
            if instance is None:
                return self
            if self._name not in instance.__dict__:
                instance.__dict__[self._name] = _BoundSignal()
            return instance.__dict__[self._name]

    class QObject:
        def __init__(self, *args, **kwargs):
            super().__init__()

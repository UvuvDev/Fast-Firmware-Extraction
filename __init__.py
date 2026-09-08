"""Registers every firmware container format with Binary Ninja.

Adding a new format is one new file under ``formats/`` — never edit this
file. Every module under ``formats/`` gets imported, and each format
registers itself at import time via a module-level ``SomeTransform.register()``
call (see docs/ADDING_A_FORMAT.md).
"""

from __future__ import annotations

import importlib
import pkgutil

from . import formats as _formats_pkg


def _register_all() -> None:
    for module_info in pkgutil.iter_modules(_formats_pkg.__path__):
        importlib.import_module(f"{_formats_pkg.__name__}.{module_info.name}")


_register_all()

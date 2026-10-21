"""Discover legacy Python modules and register the generated Rust inventory."""
from __future__ import annotations

import importlib
import pkgutil

from . import formats as _formats_pkg


def _register_all() -> None:
    for module_info in pkgutil.iter_modules(_formats_pkg.__path__):
        importlib.import_module(f"{_formats_pkg.__name__}.{module_info.name}")


_register_all()

from .common.native_container import register_formats
register_formats()

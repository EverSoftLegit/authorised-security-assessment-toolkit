"""Shared test helpers. No test contacts anything other than 127.0.0.1."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_script(filename: str) -> ModuleType:
    """Import a script such as '04_sitemap_inventory.py' (names starting with a digit can't be imported normally)."""
    path = ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(path.stem.lstrip("0123456789_"), path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

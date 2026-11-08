"""Load `scripts/release-tag`, which has no `.py`, as a module for its tests."""

import importlib.machinery
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release-tag"
_loader = importlib.machinery.SourceFileLoader("release_tag", str(SCRIPT))
_spec = importlib.util.spec_from_loader("release_tag", _loader)
if _spec is None:
    message = f"can't load {SCRIPT}"
    raise ImportError(message)
release_tag = importlib.util.module_from_spec(_spec)
_loader.exec_module(release_tag)

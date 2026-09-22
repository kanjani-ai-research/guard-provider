"""Import smoke test (TESTING-STANDARD section 5): every module in app/ imports in the test env
(pyproject pythonpath = ., the container WORKDIR /app)."""

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _modules() -> list[str]:
    names = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        parts = path.relative_to(ROOT).with_suffix("").parts
        names.append(".".join(parts[:-1] if parts[-1] == "__init__" else parts))
    return names


def test_modules_are_discovered():
    assert {"app.main", "app.auth", "app.store", "app.models"} <= set(_modules())


@pytest.mark.parametrize("module", _modules())
def test_module_imports(module):
    mod = importlib.import_module(module)
    assert Path(mod.__file__).resolve().is_relative_to(ROOT)

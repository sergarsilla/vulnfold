"""Dependencies stay inside the set SPEC-01 section 2 allows.

Every dependency is supply-chain surface in a tool that reads security data, so
the allowed set is asserted rather than reviewed.
"""

from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = PROJECT_ROOT / "src" / "vulnfold"

ALLOWED_DEPENDENCIES = {"httpx", "pydantic", "typer", "rich", "pyyaml"}
#: Import name of each allowed distribution, where the two differ.
ALLOWED_IMPORTS = {"httpx", "pydantic", "typer", "rich", "yaml", "vulnfold"}


def _declared_dependencies() -> list[str]:
    manifest = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies: list[str] = manifest["project"]["dependencies"]
    return dependencies


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules


def test_runtime_dependencies_are_exactly_those_the_specification_allows() -> None:
    """SPEC-01 section 9, criterion 8."""
    names = {
        requirement.split("==")[0].strip().lower() for requirement in _declared_dependencies()
    }

    assert names == ALLOWED_DEPENDENCIES


def test_every_runtime_dependency_is_pinned() -> None:
    for requirement in _declared_dependencies():
        assert "==" in requirement, f"{requirement} is not pinned to an exact version"


@pytest.mark.parametrize(
    "module", sorted(path.name for path in SOURCE_ROOT.glob("*.py")), ids=str
)
def test_no_module_imports_outside_the_allowed_set(module: str) -> None:
    imported = _top_level_imports(SOURCE_ROOT / module)

    assert imported - sys.stdlib_module_names <= ALLOWED_IMPORTS


def test_the_domain_layer_does_not_reach_for_the_network() -> None:
    """CLAUDE.md: dependencies flow inward; collapse.py must not import client.py."""
    source = (SOURCE_ROOT / "collapse.py").read_text(encoding="utf-8")
    imported_from = {
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    }

    assert "httpx" not in _top_level_imports(SOURCE_ROOT / "collapse.py")
    assert "vulnfold.client" not in imported_from

from __future__ import annotations

import tomllib
from pathlib import Path


def test_declared_dependencies_match_direct_imports_and_example_environment() -> None:
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dependencies = project["dependencies"]

    assert any(dependency.startswith("mcp-types") for dependency in dependencies)
    assert not any(dependency.startswith("pydantic-settings") for dependency in dependencies)
    assert not any(dependency.startswith("structlog") for dependency in dependencies)
    assert "MCP_TOOLBOX_" not in (root / ".env.example").read_text(encoding="utf-8")

from __future__ import annotations

import tomllib
from pathlib import Path

import mcp_toolbox

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_runtime_and_package_versions_match() -> None:
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as pyproject_file:
        project = tomllib.load(pyproject_file)["project"]

    assert mcp_toolbox.__version__ == project["version"]

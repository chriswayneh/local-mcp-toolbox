from __future__ import annotations

import mcp_toolbox.server  # noqa: F401  # initialize the supported server registry first
from mcp_toolbox.tools.git.handlers import (
    _parse_branch,
    _parse_numstat_line,
    _parse_status_line,
)


def test_git_parsers_ignore_malformed_fixed_command_output() -> None:
    branch = _parse_branch("## main...origin/main [ahead not-a-count, behind invalid]")

    assert branch == {"head": "main", "upstream": "origin/main", "ahead": 0, "behind": 0}
    assert _parse_status_line("M") is None
    assert _parse_numstat_line("not-a-numstat-record") is None
    assert _parse_numstat_line("not-a-number\t0\tREADME.md") is None


def test_git_parsers_preserve_valid_fixed_command_output() -> None:
    assert _parse_status_line(" M README.md") == {
        "index_status": " ",
        "worktree_status": "M",
        "path": "README.md",
    }
    assert _parse_numstat_line("2\t-\tREADME.md") == {
        "path": "README.md",
        "added_lines": 2,
        "deleted_lines": None,
    }

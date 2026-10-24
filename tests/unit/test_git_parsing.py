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


Z = "0" * 40
BLOB = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"


def _raw(old: str, new: str, status: str, path: str) -> str:
    return f":{old} {new} {BLOB} {Z} {status}\0{path}\0"


def _num(added: str, deleted: str, path: str) -> str:
    return f"{added}\t{deleted}\t{path}\0"


def _paths(output: str) -> list[str]:
    from mcp_toolbox.tools.git.handlers import _diff_files_summary

    return [str(item["path"]) for item in _diff_files_summary(output)]


def test_diff_summary_uses_null_separated_raw_and_numstat() -> None:
    from mcp_toolbox.tools.git.handlers import _DIFF_SUMMARY_ARGUMENTS

    assert _DIFF_SUMMARY_ARGUMENTS == (
        "diff-files",
        "-z",
        "--raw",
        "--numstat",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=dirty",
    )


def test_diff_files_summary_keeps_real_zero_line_rows_and_drops_stat_only_rows() -> None:
    output = (
        _raw("100644", "000000", "D", "empty-deleted.txt")
        + _raw("100644", "100755", "M", "mode-only.sh")
        + _raw("100644", "120000", "T", "type-change")
        + _raw("100644", "100644", "M", "phantom.txt")
        + _raw("100644", "100644", "M", "edited.txt")
        + _raw("100644", "100644", "M", "deleted-lines.txt")
        + _num("0", "0", "empty-deleted.txt")
        + _num("0", "0", "mode-only.sh")
        + _num("0", "0", "type-change")
        + _num("0", "0", "phantom.txt")
        + _num("2", "1", "edited.txt")
        + _num("0", "3", "deleted-lines.txt")
    )

    assert _paths(output) == [
        "empty-deleted.txt",
        "mode-only.sh",
        "type-change",
        "edited.txt",
        "deleted-lines.txt",
    ]


def test_diff_files_summary_matches_by_path_not_position() -> None:
    # QE repro: the touched a.txt has a raw record but no numstat row.
    output = (
        _raw("100644", "100644", "M", "a.txt")
        + _raw("100644", "000000", "D", "b_empty.txt")
        + _raw("100644", "100755", "M", "c.sh")
        + _num("0", "0", "b_empty.txt")
        + _num("0", "0", "c.sh")
    )

    assert _paths(output) == ["b_empty.txt", "c.sh"]


def test_diff_files_summary_keeps_rows_with_several_raw_records() -> None:
    # An unmerged path gets a U record and an M record plus two numstat rows.
    output = (
        _raw("000000", "100644", "U", "m.txt")
        + _raw("100644", "100644", "M", "m.txt")
        + _num("0", "0", "m.txt")
        + _num("4", "0", "m.txt")
    )

    from mcp_toolbox.tools.git.handlers import _diff_files_summary

    assert _diff_files_summary(output) == [{"path": "m.txt", "added_lines": 4, "deleted_lines": 0}]


def test_diff_files_summary_keeps_numstat_row_without_raw_record() -> None:
    assert _paths(_num("0", "0", "orphan.txt")) == ["orphan.txt"]


def test_diff_files_summary_handles_tabs_newlines_and_unicode_paths() -> None:
    names = ["tab\tname.txt", "new\nline.txt", "\u00fcnic\u00f8de \u6587.txt"]
    output = "".join(_raw("100644", "100644", "M", name) for name in names) + "".join(
        _num("1", "0", name) for name in names
    )
    output += _raw("100644", "100644", "M", "tab\tphantom") + _num("0", "0", "tab\tphantom")

    assert _paths(output) == names


def test_diff_files_summary_ignores_short_raw_metadata() -> None:
    output = ":100644 100644 M\0phantom.txt\0" + _num("0", "0", "phantom.txt")

    assert _paths(output) == ["phantom.txt"]


def test_diff_files_summary_only_drops_status_m_records() -> None:
    output = _raw("100644", "100644", "U", "unmerged.txt") + _num("0", "0", "unmerged.txt")

    assert _paths(output) == ["unmerged.txt"]


def test_diff_files_summary_keeps_counted_row_when_zero_row_follows() -> None:
    from mcp_toolbox.tools.git.handlers import _diff_files_summary

    output = (
        _raw("000000", "100644", "U", "m.txt")
        + _raw("100644", "100644", "M", "m.txt")
        + _num("4", "0", "m.txt")
        + _num("0", "0", "m.txt")
    )

    assert _diff_files_summary(output) == [{"path": "m.txt", "added_lines": 4, "deleted_lines": 0}]


def test_unborn_branch_header_names_the_branch() -> None:
    """Before the first commit the header is `## No commits yet on <branch>`.

    That sentence is not the branch name, so only the name should be returned.
    """
    assert _parse_branch("## No commits yet on main") == {
        "head": "main",
        "upstream": None,
        "ahead": 0,
        "behind": 0,
    }
    assert _parse_branch("## No commits yet on dev...origin/dev")["head"] == "dev"
    assert _parse_branch("## Initial commit on main")["head"] == "main"
    assert _parse_branch("## HEAD (no branch)")["head"] is None

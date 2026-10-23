from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    FilesystemSettings,
    GitSettings,
    IntegrationSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server


@pytest.fixture()
def git_repository(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is not installed")
    repository = tmp_path / "approved-repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Toolbox Test")
    _git(repository, "config", "user.email", "toolbox@example.test")
    readme = repository / "README.md"
    readme.write_text("Initial content\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-m", "Initial commit")
    _git(repository, "commit", "--allow-empty", "-m", "token ghp_123456789012345678901234567890")
    readme.write_text("Initial content\nChanged\n", encoding="utf-8")
    return repository


def test_git_tools_require_approved_repository_and_redact_commit_content(
    tmp_path: Path, git_repository: Path
) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(
                    approved_roots=[tmp_path],
                    allowed_extensions=[".md", ".txt"],
                    blocked_patterns=[".env", "*.pem"],
                ),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[git_repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            status = await client.call_tool(
                "git_repository_status", {"repository": str(git_repository)}
            )
            branch = await client.call_tool(
                "git_current_branch", {"repository": str(git_repository)}
            )
            commits = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository), "limit": 5}
            )
            diff = await client.call_tool("git_diff_summary", {"repository": str(git_repository)})
            denied = await client.call_tool("git_current_branch", {"repository": str(tmp_path)})

            assert status.is_error is False
            assert status.structured_content["data"]["changed_file_count"] == 1
            assert branch.is_error is False
            assert branch.structured_content["data"]["reference"]
            assert commits.is_error is False
            subjects = str(commits.structured_content["data"]["commits"])
            assert "ghp_123456789012345678901234567890" not in subjects
            assert "[REDACTED_GITHUB_TOKEN]" in subjects
            assert diff.is_error is False
            assert diff.structured_content["data"]["files"][0]["path"] == "README.md"
            assert denied.is_error is True

    asyncio.run(scenario())


def test_git_tools_are_not_registered_when_integration_is_disabled(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(
                filesystem=FilesystemSettings(
                    approved_roots=[tmp_path],
                    allowed_extensions=[".md"],
                ),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            assert not {tool.name for tool in tools.tools} & {
                "git_repository_status",
                "git_current_branch",
                "git_recent_commits",
                "git_diff_summary",
            }

    asyncio.run(scenario())


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX shell required for the probe")
def test_git_tools_ignore_repository_config_that_runs_programs(
    tmp_path: Path, git_repository: Path
) -> None:
    marker = tmp_path / "repo-config-ran"
    probe = tmp_path / "probe.sh"
    probe.write_text(f"#!/bin/sh\necho ran >> '{marker}'\n", encoding="utf-8")
    probe.chmod(0o755)
    hooks = git_repository / ".git" / "hooks"
    for hook in ("post-index-change", "pre-commit"):
        (hooks / hook).write_text(probe.read_text(encoding="utf-8"), encoding="utf-8")
        (hooks / hook).chmod(0o755)
    (git_repository / ".gitattributes").write_text("*.md diff=probe\n", encoding="utf-8")
    _git(git_repository, "config", "core.fsmonitor", str(probe))
    _git(git_repository, "config", "diff.external", str(probe))
    _git(git_repository, "config", "diff.probe.textconv", str(probe))
    _git(git_repository, "config", "diff.probe.command", str(probe))
    (git_repository / ".gitattributes").write_text(
        "*.md diff=probe filter=probe\n*.txt filter=probe\n", encoding="utf-8"
    )
    _git(git_repository, "config", "filter.probe.clean", str(probe))
    _git(git_repository, "config", "filter.probe.process", str(probe))
    for tracked in git_repository.iterdir():
        if tracked.is_file():
            tracked.write_text(tracked.read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
    index = git_repository / ".git" / "index"
    index_before = index.read_bytes()

    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[git_repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in ("git_repository_status", "git_diff_summary", "git_current_branch"):
                result = await client.call_tool(tool, {"repository": str(git_repository)})
                assert result.is_error is False

    asyncio.run(scenario())

    assert not marker.exists(), "repository config made Git run a program"
    assert index.read_bytes() == index_before, "read-only Git inspection rewrote the index"


def _git_output(repository: Path, *arguments: str, stdin: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
        input=stdin,
    ).stdout.strip()


def _write_probe(tmp_path: Path, marker: Path) -> Path:
    probe = tmp_path / "probe.sh"
    probe.write_text(f"#!/bin/sh\necho ran >> '{marker}'\ncat >/dev/null\n", encoding="utf-8")
    probe.chmod(0o755)
    return probe


def _git_server(tmp_path: Path, repository: Path) -> object:
    return create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as a filter or verifier",
)
def test_recent_commits_never_runs_a_repository_signature_verifier(
    tmp_path: Path, git_repository: Path
) -> None:
    marker = tmp_path / "verifier-ran"
    probe = _write_probe(tmp_path, marker)
    # Write a commit object carrying a gpgsig header so `git log` has a signature to verify.
    tree = _git_output(git_repository, "rev-parse", "HEAD^{tree}")
    parent = _git_output(git_repository, "rev-parse", "HEAD")
    signature = "\n ".join(
        ["-----BEGIN PGP SIGNATURE-----", "", "iQEzBAABCAAdFiEEfake", "-----END PGP SIGNATURE-----"]
    )
    commit = (
        f"tree {tree}\nparent {parent}\n"
        "author Toolbox Test <toolbox@example.test> 1700000000 +0000\n"
        "committer Toolbox Test <toolbox@example.test> 1700000000 +0000\n"
        f"gpgsig {signature}\n\nSigned commit\n"
    )
    signed = _git_output(
        git_repository, "hash-object", "-t", "commit", "-w", "--stdin", stdin=commit
    )
    _git(git_repository, "update-ref", "HEAD", signed)
    _git(git_repository, "config", "log.showSignature", "true")
    _git(git_repository, "config", "gpg.program", str(probe))
    _git(git_repository, "config", "gpg.format", "openpgp")
    # Sanity check: a plain `git log` in this repository does run the verifier.
    _git(git_repository, "log", "-1")
    assert marker.exists(), "fixture did not make git log run the verifier"
    marker.unlink()

    server = _git_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:  # type: ignore[arg-type]
            result = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository), "limit": 5}
            )
            assert result.is_error is False
            subjects = [c["subject"] for c in result.structured_content["data"]["commits"]]
            assert subjects[0] == "Signed commit"

    asyncio.run(scenario())

    assert not marker.exists(), "git_recent_commits ran a repository-chosen signature verifier"


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as a filter or verifier",
)
def test_status_and_diff_never_run_filters_defined_only_in_a_submodule(
    tmp_path: Path, git_repository: Path
) -> None:
    marker = tmp_path / "submodule-filter-ran"
    probe = _write_probe(tmp_path, marker)
    child = tmp_path / "child-source"
    child.mkdir()
    _git(child, "init")
    _git(child, "config", "user.name", "Toolbox Test")
    _git(child, "config", "user.email", "toolbox@example.test")
    (child / ".gitattributes").write_text("*.txt filter=childonly\n", encoding="utf-8")
    (child / "data.txt").write_text("one\n", encoding="utf-8")
    _git(child, "add", ".")
    _git(child, "commit", "-m", "child")
    _git(git_repository, "-c", "protocol.file.allow=always", "submodule", "add", str(child), "sub")
    _git(git_repository, "commit", "-m", "add submodule")
    submodule = git_repository / "sub"
    _git(submodule, "config", "filter.childonly.clean", str(probe))
    # Same size, newer mtime: Git must run the clean filter to tell whether it changed.
    data = submodule / "data.txt"
    data.write_text("uno\n", encoding="utf-8")
    stat = data.stat()
    os.utime(data, (stat.st_atime + 5, stat.st_mtime + 5))
    # Sanity check: a plain `git status` in the parent does run the submodule's filter.
    _git(git_repository, "status")
    assert marker.exists(), "fixture did not make git status run the submodule filter"
    marker.unlink()

    server = _git_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:  # type: ignore[arg-type]
            for tool in ("git_repository_status", "git_diff_summary"):
                result = await client.call_tool(tool, {"repository": str(git_repository)})
                assert result.is_error is False

    asyncio.run(scenario())

    assert not marker.exists(), "Git tools ran a filter defined only in a submodule"


def test_git_diff_summary_never_rewrites_the_index(tmp_path: Path, git_repository: Path) -> None:
    import os

    other = git_repository / "other.txt"
    other.write_bytes(b"tracked\n")
    _git(git_repository, "add", "other.txt")
    _git(git_repository, "commit", "-m", "Add other")
    index = git_repository / ".git" / "index"
    past = 1_600_000_000
    os.utime(index, (past, past))
    # Make a tracked file stat-dirty but content-identical so a refreshing diff rewrites the index.
    os.utime(other, (past + 3600, past + 3600))
    before_bytes = index.read_bytes()
    before_mtime = index.stat().st_mtime_ns

    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[git_repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            diff = await client.call_tool("git_diff_summary", {"repository": str(git_repository)})
            assert diff.is_error is False
            data = diff.structured_content["data"]
            assert [item["path"] for item in data["files"]] == ["README.md"], data
            assert data["changed_file_count"] == 1

    asyncio.run(scenario())

    assert index.read_bytes() == before_bytes
    assert index.stat().st_mtime_ns == before_mtime


def _diff_paths(tmp_path: Path, repository: Path) -> list[str]:
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )
    result: list[str] = []

    async def scenario() -> None:
        async with Client(server) as client:
            diff = await client.call_tool("git_diff_summary", {"repository": str(repository)})
            assert diff.is_error is False
            data = diff.structured_content["data"]
            assert data["changed_file_count"] == len(data["files"])
            result.extend(item["path"] for item in data["files"])

    asyncio.run(scenario())
    return sorted(result)


def _commit_files(repository: Path, files: dict[str, bytes]) -> None:
    for name, content in files.items():
        (repository / name).write_bytes(content)
    _git(repository, "add", *files)
    _git(repository, "commit", "-m", "Add fixtures")


def _touch(path: Path) -> None:
    import os

    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 7_000_000_000))


_POSIX_ONLY = pytest.mark.skipif(
    __import__("sys").platform == "win32", reason="POSIX file modes and file names"
)


def test_git_diff_summary_reports_deleted_empty_tracked_file(
    tmp_path: Path, git_repository: Path
) -> None:
    _commit_files(git_repository, {"empty.txt": b""})
    (git_repository / "empty.txt").unlink()

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "empty.txt"]


def test_git_diff_summary_drops_touched_only_file_next_to_real_changes(
    tmp_path: Path, git_repository: Path
) -> None:
    _commit_files(git_repository, {"touched.txt": b"same\n", "edited.txt": b"one\n"})
    _touch(git_repository / "touched.txt")
    (git_repository / "edited.txt").write_bytes(b"one\ntwo\n")

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "edited.txt"]


@_POSIX_ONLY
def test_git_diff_summary_qe_touch_delete_chmod_repro(tmp_path: Path, git_repository: Path) -> None:
    _commit_files(git_repository, {"a.txt": b"a\n", "b_empty.txt": b"", "c.sh": b"c\n"})
    _touch(git_repository / "a.txt")
    (git_repository / "b_empty.txt").unlink()
    (git_repository / "c.sh").chmod(0o755)

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "b_empty.txt", "c.sh"]


@_POSIX_ONLY
def test_git_diff_summary_red_team_touch_and_chmod(tmp_path: Path, git_repository: Path) -> None:
    _commit_files(git_repository, {"b": b"b\n", "c": b"c\n"})
    _touch(git_repository / "b")
    (git_repository / "c").chmod(0o755)

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "c"]


def test_git_diff_summary_reports_merge_conflict_once(tmp_path: Path, git_repository: Path) -> None:
    _git(git_repository, "checkout", "--", "README.md")
    _commit_files(git_repository, {"m.txt": b"base\n"})
    _git(git_repository, "checkout", "-b", "other")
    _commit_files(git_repository, {"m.txt": b"other\n"})
    _git(git_repository, "checkout", "-")
    _commit_files(git_repository, {"m.txt": b"mine\n"})
    subprocess.run(
        ["git", "-C", str(git_repository), "merge", "other"], check=False, capture_output=True
    )

    assert _diff_paths(tmp_path, git_repository) == ["m.txt"]


@_POSIX_ONLY
def test_git_diff_summary_handles_tab_newline_and_unicode_paths(
    tmp_path: Path, git_repository: Path
) -> None:
    names = ["tab\tname.txt", "new\nline.txt", "\u00fcnic\u00f8de \u6587.txt"]
    _commit_files(git_repository, {name: b"x\n" for name in names})
    for name in names:
        (git_repository / name).write_bytes(b"x\ny\n")

    assert _diff_paths(tmp_path, git_repository) == sorted(["README.md", *names])


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as a filter",
)
def test_filter_driver_with_equals_in_name_never_runs_probe(
    tmp_path: Path, git_repository: Path
) -> None:
    from mcp_toolbox.models import ErrorCategory, ToolboxError
    from mcp_toolbox.tools.git.handlers import GitRunner, _safe_git_environment

    marker = tmp_path / "eq-filter-ran"
    probe = _write_probe(tmp_path, marker)
    config_path = git_repository / ".git" / "config"
    config_path.write_text(
        config_path.read_text(encoding="utf-8") + f'\n[filter "a=b"]\n\tclean = {probe}\n',
        encoding="utf-8",
    )
    (git_repository / ".gitattributes").write_text(
        "*.md filter=a=b\n*.txt filter=a=b\n", encoding="utf-8"
    )
    readme = git_repository / "README.md"
    # Same byte length as the committed "Initial content\n" so git status must run clean filter.
    readme.write_text("Initial CONTENX\n", encoding="utf-8")
    stat = readme.stat()
    os.utime(readme, (stat.st_atime + 10, stat.st_mtime + 10))

    # Sanity check: plain `git -c filter.a=b.clean= status` splits on the first '=' and runs probe.
    _git(git_repository, "-c", "filter.a=b.clean=", "status", "--porcelain=v1")
    assert marker.exists(), 'fixture did not make git status run the [filter "a=b"] clean command'
    marker.unlink()

    # Defense 1: GIT_CONFIG_KEY_<n> in _safe_git_environment does not split on '=' in key names.
    os.utime(readme, (stat.st_atime + 20, stat.st_mtime + 20))
    subprocess.run(
        ["git", "-C", str(git_repository), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        env=_safe_git_environment(["-c", "filter.a=b.clean=", "-c", "filter.a=b.required=false"]),
    )
    assert not marker.exists(), "GIT_CONFIG_KEY_<n> failed to blank filter.a=b.clean"

    # Defense 2: GitRunner and MCP tools refuse the repository before running git status/diff.
    runtime = build_runtime(
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            filesystem=FilesystemSettings(approved_roots=[tmp_path]),
            integrations=IntegrationSettings(git=True),
            git=GitSettings(approved_repositories=[git_repository]),
            audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
        )
    )
    with pytest.raises(ToolboxError) as caught:
        GitRunner(runtime).run(git_repository, ["status", "--porcelain=v1"])
    assert caught.value.category is ErrorCategory.PERMISSION_DENIED
    assert not marker.exists()

    server = create_server(runtime)

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in ("git_repository_status", "git_diff_summary"):
                result = await client.call_tool(tool, {"repository": str(git_repository)})
                assert result.is_error is True

    asyncio.run(scenario())
    assert not marker.exists(), '[filter "a=b"] executed probe through MCP tool'

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

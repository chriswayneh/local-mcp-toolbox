"""Pin every Git safety override and flag (QE mutation review of #32).

Each assertion names one override, so a change that drops it fails here even when the
behavioral tests elsewhere would still pass on this machine's Git version.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

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
from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.git import handlers
from mcp_toolbox.tools.git.handlers import GitRunner

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="Git is not installed")


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(repository), *arguments], check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    repository = tmp_path / "repo"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "T")
    _git(repository, "config", "user.email", "t@example.test")
    (repository / "a.txt").write_text("one\n")
    _git(repository, "add", "a.txt")
    _git(repository, "commit", "-qm", "init")
    return repository


def _runtime(tmp_path: Path, repository: Path):
    return build_runtime(
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            filesystem=FilesystemSettings(approved_roots=[tmp_path]),
            integrations=IntegrationSettings(git=True),
            git=GitSettings(approved_repositories=[repository]),
            audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
        )
    )


@pytest.fixture()
def calls(monkeypatch) -> list[dict[str, Any]]:
    recorded: list[dict[str, Any]] = []
    real_run = subprocess.run

    def spy(command, **kwargs):  # type: ignore[no-untyped-def]
        recorded.append({"argv": list(command), "env": dict(kwargs.get("env") or {})})
        return real_run(command, **kwargs)

    monkeypatch.setattr(handlers.subprocess, "run", spy)
    return recorded


def _pairs(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, item in enumerate(argv[:-1]) if item == "-c"]


def _call_all_tools(tmp_path: Path, repository: Path) -> None:
    server = create_server(_runtime(tmp_path, repository))

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in ("git_repository_status", "git_diff_summary", "git_recent_commits"):
                result = await client.call_tool(tool, {"repository": str(repository)})
                assert result.is_error is False, tool

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "override",
    [
        "core.fsmonitor=false",
        f"core.hooksPath={os.devnull}",
        "core.untrackedCache=false",
        "diff.external=",
        "status.submoduleSummary=false",
        "log.showSignature=false",
        "diff.ignoreSubmodules=dirty",
        "protocol.allow=never",
        "core.sshCommand=false",
        "core.askPass=false",
        "core.alternateRefsCommand=false",
        "credential.helper=",
    ],
)
def test_every_git_command_carries_the_fixed_override(
    override: str, tmp_path: Path, repo: Path, calls: list[dict[str, Any]]
) -> None:
    _call_all_tools(tmp_path, repo)
    tool_calls = [c for c in calls if "config" not in c["argv"]]
    assert len(tool_calls) == 3
    for call in tool_calls:
        assert override in _pairs(call["argv"]), call["argv"]


def test_tool_templates_pin_their_safety_flags(
    tmp_path: Path, repo: Path, calls: list[dict[str, Any]]
) -> None:
    _call_all_tools(tmp_path, repo)
    by_verb = {c["argv"][c["argv"].index("-C") + 2]: c["argv"] for c in calls if "-C" in c["argv"]}
    assert "--ignore-submodules=dirty" in by_verb["status"]
    for flag in ("--numstat", "--no-ext-diff", "--no-textconv", "--ignore-submodules=dirty"):
        assert flag in by_verb["diff"], flag
    assert "--no-show-signature" in by_verb["log"]
    for verb_argv in by_verb.values():
        assert "--no-lazy-fetch" in verb_argv


def test_environment_disables_optional_locks_and_user_config(
    tmp_path: Path, repo: Path, calls: list[dict[str, Any]]
) -> None:
    _call_all_tools(tmp_path, repo)
    for call in calls:
        assert call["env"]["GIT_OPTIONAL_LOCKS"] == "0"
        assert call["env"]["GIT_NO_LAZY_FETCH"] == "1"
        assert call["env"]["GIT_ASKPASS"] == "false"
        assert call["env"]["SSH_ASKPASS"] == "false"
        assert call["env"]["GIT_CONFIG_NOSYSTEM"] == "1"
        assert call["env"]["GIT_CONFIG_GLOBAL"] == os.devnull


def test_status_does_not_rewrite_the_index(tmp_path: Path, repo: Path) -> None:
    index = repo / ".git" / "index"
    # Touch the work tree so a locking `git status` would refresh and rewrite the index.
    os.utime(repo / "a.txt", (1, 1))
    before = index.stat().st_mtime_ns
    server = create_server(_runtime(tmp_path, repo))

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool("git_repository_status", {"repository": str(repo)})
            assert result.is_error is False

    asyncio.run(scenario())
    assert index.stat().st_mtime_ns == before


@pytest.mark.parametrize("keys", [("process",), ("clean",), ("smudge",), ("clean", "process")])
def test_every_repository_filter_driver_is_blanked_and_made_optional(
    keys: tuple[str, ...], tmp_path: Path, repo: Path
) -> None:
    for key in keys:
        _git(repo, "config", f"filter.evil.{key}", "sh -c 'touch PWNED'")
    _git(repo, "config", "filter.evil.required", "true")
    pairs = _pairs(handlers._filter_driver_overrides("git", repo, _runtime(tmp_path, repo)))
    for key in ("clean", "smudge", "process"):
        assert f"filter.evil.{key}=" in pairs
    assert "filter.evil.required=false" in pairs


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell filter probe")
def test_process_only_filter_never_runs_and_does_not_fail_status(
    tmp_path: Path, repo: Path
) -> None:
    marker = tmp_path / "ran"
    _git(repo, "config", "filter.p.process", f"sh -c 'touch {marker}; exit 1'")
    _git(repo, "config", "filter.p.required", "true")
    (repo / ".gitattributes").write_text("*.txt filter=p\n")
    (repo / "a.txt").write_text("two\n")
    _call_all_tools(tmp_path, repo)
    assert not marker.exists()


def test_only_well_formed_filter_names_become_drivers(monkeypatch, tmp_path: Path) -> None:
    completed = subprocess.CompletedProcess([], 0, stdout="bogus\nfilter.x\nfilter.ok.clean\n")
    monkeypatch.setattr(handlers.subprocess, "run", lambda *a, **k: completed)
    pairs = _pairs(handlers._filter_driver_overrides("git", tmp_path, _runtime(tmp_path, tmp_path)))
    assert pairs == [
        "filter.ok.clean=",
        "filter.ok.smudge=",
        "filter.ok.process=",
        "filter.ok.required=false",
    ]


def _raise_oserror(*args: Any, **kwargs: Any) -> Any:
    raise OSError("cannot start")


def test_filter_inspection_oserror_becomes_a_safe_error(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(handlers.subprocess, "run", _raise_oserror)
    with pytest.raises(ToolboxError) as caught:
        handlers._filter_driver_overrides("git", tmp_path, _runtime(tmp_path, tmp_path))
    assert caught.value.category is ErrorCategory.INTEGRATION_UNAVAILABLE


def test_git_start_oserror_becomes_a_safe_error(monkeypatch, tmp_path: Path, repo: Path) -> None:
    monkeypatch.setattr(handlers, "_filter_driver_overrides", lambda *a: [])
    monkeypatch.setattr(handlers.subprocess, "run", _raise_oserror)
    with pytest.raises(ToolboxError) as caught:
        GitRunner(_runtime(tmp_path, repo)).run(repo, ["status"])
    assert caught.value.category is ErrorCategory.INTEGRATION_UNAVAILABLE


@pytest.mark.parametrize(
    "bad_stdout",
    [
        "filter.a=b.clean\n",
        "filter.a\tb.clean\n",
        "filter.a\x00b.clean\n",
        "filter.a\x7fb.clean\n",
        "filter.foo\x1ebar.clean\n",
        "filter.foo\u2028bar.clean\n",
        "filter.foo\u2029bar.clean\n",
        "filter.foo\x85bar.clean\n",
        "filter.foo\x0bbar.clean\n",
        "filter.foo\x0cbar.clean\n",
        "filter.foo\x1cbar.clean\n",
        "filter.foo\x1dbar.clean\n",
        "filter.a.clean\x1efilter.b.clean\n",
        "filter.a.clean\rfilter.b.clean\n",
        "filter..clean\n",
    ],
)
def test_filter_driver_name_with_equals_or_control_chars_is_refused(
    bad_stdout: str, monkeypatch, tmp_path: Path
) -> None:
    completed = subprocess.CompletedProcess([], 0, stdout=bad_stdout)
    monkeypatch.setattr(handlers.subprocess, "run", lambda *a, **k: completed)
    with pytest.raises(ToolboxError) as caught:
        handlers._filter_driver_overrides("git", tmp_path, _runtime(tmp_path, tmp_path))
    assert caught.value.category is ErrorCategory.PERMISSION_DENIED


@pytest.mark.parametrize("returncode", [2, 128, -1])
def test_filter_inspection_nonzero_exit_code_is_refused(
    returncode: int, monkeypatch, tmp_path: Path
) -> None:
    completed = subprocess.CompletedProcess([], returncode, stdout="")
    monkeypatch.setattr(handlers.subprocess, "run", lambda *a, **k: completed)
    with pytest.raises(ToolboxError) as caught:
        handlers._filter_driver_overrides("git", tmp_path, _runtime(tmp_path, tmp_path))
    assert caught.value.category is ErrorCategory.PERMISSION_DENIED


def test_filter_inspection_exit_code_one_means_no_filters(monkeypatch, tmp_path: Path) -> None:
    completed = subprocess.CompletedProcess([], 1, stdout="")
    monkeypatch.setattr(handlers.subprocess, "run", lambda *a, **k: completed)
    assert handlers._filter_driver_overrides("git", tmp_path, _runtime(tmp_path, tmp_path)) == []


def test_environment_carries_git_config_key_value_pairs_without_splitting_key_equals() -> None:
    env = handlers._safe_git_environment(
        ["-c", "filter.a=b.clean=", "-c", "filter.a=b.required=false"]
    )
    count = int(env["GIT_CONFIG_COUNT"])
    env_pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(count)}
    assert env_pairs["core.fsmonitor"] == "false"
    assert env_pairs["filter.a=b.clean"] == ""
    assert env_pairs["filter.a=b.required"] == "false"

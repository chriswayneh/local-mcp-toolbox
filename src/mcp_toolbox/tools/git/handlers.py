"""Read-only Git inspection through fixed, validated argument templates."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

_FIELD_SEPARATOR = "\x1f"
_RECORD_SEPARATOR = "\x1e"
_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


@dataclass(frozen=True, slots=True)
class GitCommandResult:
    """Bounded stdout from a fixed read-only Git command."""

    stdout: str


class GitRunner:
    """Execute a small allowlist of Git inspection commands without a shell."""

    def __init__(self, runtime: ServerRuntime) -> None:
        self._runtime = runtime

    def run(self, repository: Path, arguments: list[str]) -> GitCommandResult:
        """Run preassembled Git arguments with a scrubbed environment and bounded output."""

        executable = shutil.which("git")
        if executable is None:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Git is not installed or is unavailable on PATH.",
                remediation="Install Git or disable the Git integration.",
            )

        command = [executable, "-C", str(repository), *arguments]
        try:
            # The command is assembled only from the resolved Git executable, approved repository,
            # and fixed read-only templates declared by this module.
            completed = subprocess.run(  # noqa: S603  # nosec B603
                command,
                check=False,
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._runtime.settings.limits.timeout_seconds,
                env=_safe_git_environment(),
            )
        except subprocess.TimeoutExpired as error:
            raise ToolboxError(
                ErrorCategory.TIMEOUT,
                "The Git inspection command exceeded the configured timeout.",
                remediation="Use a smaller result limit or inspect a smaller repository.",
            ) from error
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Git could not be started.",
                remediation="Check the local Git installation and server permissions.",
            ) from error

        if completed.returncode != 0:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "The configured path is not a readable Git working tree.",
                remediation="Use an approved repository with a valid Git working tree.",
            )
        if len(completed.stdout.encode("utf-8")) > self._runtime.settings.limits.max_output_bytes:
            raise ToolboxError(
                ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                "The Git command output exceeded the configured output limit.",
                remediation="Use a smaller limit or more focused Git request.",
            )
        return GitCommandResult(stdout=completed.stdout)


def register_git_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register read-only Git tools only when Git is explicitly enabled."""

    if not runtime.permissions.check_integration("git").allowed:
        return ()
    runner = GitRunner(runtime)

    @server.tool(
        name="git_repository_status",
        title="Git repository status",
        description="Return a bounded, read-only summary of an approved Git working tree.",
        annotations=_READ_ONLY,
    )
    def git_repository_status(repository: str) -> dict[str, Any]:
        """Inspect branch state and changed-file counts without reading diff contents."""

        repo = _require_repository(runtime, repository)
        lines = runner.run(repo, ["status", "--porcelain=v1", "--branch"]).stdout.splitlines()
        branch = (
            _parse_branch(lines[0])
            if lines
            else {"head": None, "upstream": None, "ahead": 0, "behind": 0}
        )
        changes = [
            parsed
            for line in lines[1:]
            if line and (parsed := _parse_status_line(line)) is not None
        ]
        return bounded_response(
            runtime,
            "Collected a read-only Git working tree summary.",
            {
                "branch": branch,
                "changed_file_count": len(changes),
                "changes": changes[: runtime.settings.limits.max_records],
                "truncated_changes": len(changes) > runtime.settings.limits.max_records,
            },
        )

    @server.tool(
        name="git_current_branch",
        title="Current Git branch",
        description="Return the checked-out branch or detached commit for an approved repository.",
        annotations=_READ_ONLY,
    )
    def git_current_branch(repository: str) -> dict[str, Any]:
        """Read the current Git reference using a fixed symbolic-ref command."""

        repo = _require_repository(runtime, repository)
        result = runner.run(repo, ["branch", "--show-current"]).stdout.strip()
        detached = False
        if not result:
            detached = True
            result = runner.run(repo, ["rev-parse", "--short", "HEAD"]).stdout.strip()
        return bounded_response(
            runtime,
            "Collected the current Git reference.",
            {"reference": result, "detached": detached},
        )

    @server.tool(
        name="git_recent_commits",
        title="Recent Git commits",
        description="Return bounded recent commit metadata from an approved repository.",
        annotations=_READ_ONLY,
    )
    def git_recent_commits(repository: str, limit: int = 20) -> dict[str, Any]:
        """Return commit metadata only; messages and identities are treated as untrusted data."""

        repo = _require_repository(runtime, repository)
        result_limit = require_bounded_limit(runtime, limit)
        output = runner.run(
            repo,
            [
                "log",
                f"--max-count={result_limit}",
                f"--format=%H{_FIELD_SEPARATOR}%h{_FIELD_SEPARATOR}%an{_FIELD_SEPARATOR}%aI{_FIELD_SEPARATOR}%s{_RECORD_SEPARATOR}",
            ],
        ).stdout
        return bounded_response(
            runtime,
            "Collected recent Git commit metadata.",
            {"commits": _parse_commits(output)},
        )

    @server.tool(
        name="git_diff_summary",
        title="Git diff summary",
        description="Return a bounded changed-file summary without returning diff content.",
        annotations=_READ_ONLY,
    )
    def git_diff_summary(repository: str) -> dict[str, Any]:
        """Return only Git diffstat metadata for tracked, unstaged changes."""

        repo = _require_repository(runtime, repository)
        lines = runner.run(repo, ["diff", "--numstat"]).stdout.splitlines()
        files = [
            parsed for line in lines if line and (parsed := _parse_numstat_line(line)) is not None
        ]
        return bounded_response(
            runtime,
            "Collected a Git diff summary without diff contents.",
            {
                "changed_file_count": len(files),
                "files": files[: runtime.settings.limits.max_records],
                "truncated_files": len(files) > runtime.settings.limits.max_records,
            },
        )

    return ("git_repository_status", "git_current_branch", "git_recent_commits", "git_diff_summary")


def _require_repository(runtime: ServerRuntime, requested_path: str) -> Path:
    return runtime.permissions.require_git_repository(Path(requested_path))


def _safe_git_environment() -> dict[str, str]:
    """Keep Git non-interactive and prevent user/system config from injecting behavior."""

    environment = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0"}
    for name in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
        if value := os.environ.get(name):
            environment[name] = value
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return environment


def _parse_branch(line: str) -> dict[str, Any]:
    head: str | None = None
    upstream: str | None = None
    ahead = 0
    behind = 0
    if line.startswith("## "):
        reference = line[3:]
        branch_part, separator, tracking_part = reference.partition("...")
        head = branch_part if branch_part != "HEAD (no branch)" else None
        if separator:
            upstream, _, tracking = tracking_part.partition(" ")
            ahead = _tracking_count(tracking, "ahead")
            behind = _tracking_count(tracking, "behind")
    return {"head": head, "upstream": upstream, "ahead": ahead, "behind": behind}


def _tracking_count(tracking: str, label: str) -> int:
    """Return a Git tracking count only when its fixed-format token is valid."""

    marker = f"{label} "
    if marker not in tracking:
        return 0
    candidate = (
        tracking.split(marker, maxsplit=1)[1].split("]", maxsplit=1)[0].split(",", maxsplit=1)[0]
    )
    return int(candidate) if candidate.isdecimal() else 0


def _parse_status_line(line: str) -> dict[str, str] | None:
    """Parse one porcelain status line or safely ignore malformed output."""

    if len(line) < 4:
        return None
    return {"index_status": line[0], "worktree_status": line[1], "path": line[3:]}


def _parse_commits(output: str) -> list[dict[str, str]]:
    commits: list[dict[str, str]] = []
    for record in output.split(_RECORD_SEPARATOR):
        if not record:
            continue
        fields = record.split(_FIELD_SEPARATOR)
        if len(fields) != 5:
            continue
        commits.append(
            {
                "commit": fields[0],
                "short_commit": fields[1],
                "author": fields[2],
                "authored_at": fields[3],
                "subject": fields[4].rstrip("\n"),
            }
        )
    return commits


def _parse_numstat_line(line: str) -> dict[str, str | int | None] | None:
    """Parse one numstat row or safely ignore malformed output."""

    fields = line.split("\t", maxsplit=2)
    if len(fields) != 3:
        return None
    added, deleted, path = fields
    if added != "-" and not added.isdecimal():
        return None
    if deleted != "-" and not deleted.isdecimal():
        return None
    return {
        "path": path,
        "added_lines": None if added == "-" else int(added),
        "deleted_lines": None if deleted == "-" else int(deleted),
    }

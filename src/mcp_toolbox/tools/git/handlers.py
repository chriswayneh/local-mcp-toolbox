"""Read-only Git inspection through fixed, validated argument templates."""

from __future__ import annotations

import os
import shutil
import subprocess  # nosec B404
from collections.abc import Sequence
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
# Repository-local config is controlled by whoever wrote the repository. These overrides
# win over it and stop Git from running repo-chosen programs or writing to the repository.
_SAFE_CONFIG_OVERRIDES = (
    "core.fsmonitor=false",
    f"core.hooksPath={os.devnull}",
    "core.untrackedCache=false",
    "diff.external=",
    "status.submoduleSummary=false",
    "log.showSignature=false",
    # Never descend into submodule work trees: a submodule's own config (filters, fsmonitor,
    # hooks) is invisible to the parent-level overrides above.
    "diff.ignoreSubmodules=dirty",
)
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

        overrides = [
            *_safe_config_arguments(),
            *_filter_driver_overrides(executable, repository, self._runtime),
        ]
        command = [executable, *overrides, "-C", str(repository), *arguments]
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
                env=_safe_git_environment(overrides),
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
        lines = runner.run(
            repo, ["status", "--porcelain=v1", "--branch", "--ignore-submodules=dirty"]
        ).stdout.splitlines()
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
                "--no-show-signature",
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
        """Return only Git diffstat metadata for tracked, unstaged changes.

        Uses `git diff-files`, which compares without refreshing (rewriting) `.git/index`.
        """

        repo = _require_repository(runtime, repository)
        output = runner.run(repo, list(_DIFF_SUMMARY_ARGUMENTS)).stdout
        files = _diff_files_summary(output)
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


def _safe_config_arguments() -> list[str]:
    """Return ``-c`` overrides that neutralize repository-controlled command execution."""

    arguments: list[str] = []
    for override in _SAFE_CONFIG_OVERRIDES:
        arguments.extend(["-c", override])
    return arguments


def _filter_driver_overrides(
    executable: str, repository: Path, runtime: ServerRuntime
) -> list[str]:
    """Blank every configured filter driver so ``.gitattributes`` cannot run clean/process commands.

    Filter driver names are chosen by the repository, so they cannot be listed in the fixed
    overrides. Reading config with ``git config`` never runs a driver.
    """

    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [
                executable,
                "-C",
                str(repository),
                "config",
                "--name-only",
                "--get-regexp",
                r"^filter\..*\.(clean|smudge|process)$",
            ],
            check=False,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=runtime.settings.limits.timeout_seconds,
            env=_safe_git_environment(),
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        raise ToolboxError(
            ErrorCategory.INTEGRATION_UNAVAILABLE,
            "Git configuration could not be inspected safely.",
            remediation="Check the local Git installation and server permissions.",
        ) from error
    if completed.returncode not in (0, 1):
        raise ToolboxError(
            ErrorCategory.PERMISSION_DENIED,
            "Git configuration could not be validated safely.",
            remediation="Repair the repository's .git/config before inspecting it.",
        )
    drivers: set[str] = set()
    for raw_name in completed.stdout.splitlines():
        line = raw_name.strip("\r\n")
        if line.lower().startswith("filter.") and line.count(".") >= 2:
            driver = line[len("filter.") : line.rindex(".")]
            if _is_unsafe_filter_driver_name(driver):
                raise ToolboxError(
                    ErrorCategory.PERMISSION_DENIED,
                    "The repository defines an unsafe Git filter driver name.",
                    remediation=(
                        "Remove filter drivers whose names contain '=' or control characters "
                        "from .git/config."
                    ),
                )
            drivers.add(driver)
    arguments: list[str] = []
    for driver in sorted(drivers):
        for key in ("clean", "smudge", "process"):
            arguments.extend(["-c", f"filter.{driver}.{key}="])
        arguments.extend(["-c", f"filter.{driver}.required=false"])
    return arguments


def _is_unsafe_filter_driver_name(driver: str) -> bool:
    """Return True when a filter driver name is empty or contains '=' or control characters."""

    return (
        not driver or "=" in driver or any(ord(char) < 0x20 or ord(char) == 0x7F for char in driver)
    )


def _config_override_pairs(overrides: Sequence[str]) -> list[tuple[str, str]]:
    """Extract (key, value) pairs from fixed overrides and any `-c key=value` arguments."""

    entries: list[str] = list(_SAFE_CONFIG_OVERRIDES)
    for index, argument in enumerate(overrides[:-1]):
        if argument == "-c":
            candidate = overrides[index + 1]
            if candidate not in entries:
                entries.append(candidate)
        elif "=" in argument and (index == 0 or overrides[index - 1] != "-c"):
            if argument not in entries:
                entries.append(argument)
    pairs: list[tuple[str, str]] = []
    for entry in entries:
        # Values in _SAFE_CONFIG_OVERRIDES and _filter_driver_overrides never contain '=',
        # so rpartition('=') preserves any '=' inside a filter.<name>.<op> key.
        key, separator, value = entry.rpartition("=")
        if separator and key:
            pairs.append((key, value))
    return pairs


def _safe_git_environment(overrides: Sequence[str] = ()) -> dict[str, str]:
    """Keep Git non-interactive, read-only, and free of user/system config injection."""

    environment = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0"}
    for name in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
        if value := os.environ.get(name):
            environment[name] = value
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    # Stop `git status` from refreshing the index or taking index.lock in the repository.
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    pairs = _config_override_pairs(overrides)
    environment["GIT_CONFIG_COUNT"] = str(len(pairs))
    for index, (key, value) in enumerate(pairs):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
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


_DIFF_SUMMARY_ARGUMENTS = (
    "diff-files",
    "-z",
    "--raw",
    "--numstat",
    "--no-ext-diff",
    "--no-textconv",
    "--ignore-submodules=dirty",
)


def _diff_files_summary(output: str) -> list[dict[str, str | int | None]]:
    """Parse `diff-files -z --raw --numstat` output and drop only stat-only phantom rows.

    diff-files does not refresh stat info, so a file whose timestamps changed but whose content
    and mode did not can be reported as status M with 0/0 counts. Raw and numstat records are
    matched by path, never by position. A row is dropped only when its path has exactly one raw
    record, that record is status M with the same old and new mode, and the counts are 0/0.
    """

    tokens = output.split("\0")
    raw_by_path: dict[str, list[tuple[str, str, str]]] = {}
    numstat_rows: list[dict[str, str | int | None]] = []
    position = 0
    while position < len(tokens):
        token = tokens[position]
        position += 1
        if not token:
            continue
        if token.startswith(":"):
            if position >= len(tokens):
                break
            path = tokens[position]
            position += 1
            fields = token[1:].split()
            if len(fields) < 5:
                continue
            raw_by_path.setdefault(path, []).append((fields[0], fields[1], fields[4]))
            continue
        parsed = _parse_numstat_line(token)
        if parsed is not None:
            numstat_rows.append(parsed)

    files: dict[str, dict[str, str | int | None]] = {}
    for parsed in numstat_rows:
        path = str(parsed["path"])
        if _is_stat_only_row(raw_by_path.get(path, []), parsed):
            continue
        existing = files.get(path)
        if existing is None or _is_zero_row(existing):
            files[path] = parsed
    return list(files.values())


def _is_zero_row(parsed: dict[str, str | int | None]) -> bool:
    return parsed["added_lines"] == 0 and parsed["deleted_lines"] == 0


def _is_stat_only_row(
    raw_rows: list[tuple[str, str, str]], parsed: dict[str, str | int | None]
) -> bool:
    """Return True only for a lone M raw record with unchanged mode and 0/0 counts."""

    if len(raw_rows) != 1:
        return False
    old_mode, new_mode, status = raw_rows[0]
    return status == "M" and old_mode == new_mode and _is_zero_row(parsed)


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

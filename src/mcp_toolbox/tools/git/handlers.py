"""Read-only Git inspection through fixed, validated argument templates."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess  # nosec B404
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

_FIELD_SEPARATOR = "\x1f"
_RECORD_SEPARATOR = "\x1e"
# Entries Git reads from .git; a symlink at any of them could point outside the repository.
_GIT_METADATA_ENTRIES = (
    "objects",
    "refs",
    "HEAD",
    "config",
    "packed-refs",
    "logs",
    "info",
    "worktrees",
)
# Longest alternates chain accepted; longer chains are refused rather than walked.
_MAX_ALTERNATE_STORES = 64
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

        if not _FD_PATHS:
            # Without descriptor pinning a .git swap that is undone while Git runs can go
            # unnoticed, so output could leak. Refuse instead of running Git at all.
            raise ToolboxError(
                ErrorCategory.UNSUPPORTED_OPERATION,
                "Git tools are not supported on this operating system (only Linux). On macOS "
                "and Windows, a repository could be swapped while Git runs and leak data from "
                "another repository.",
                remediation=(
                    "Run the toolbox on Linux (for example in the provided container) to use "
                    "the Git tools. See docs/security-model.md#git-platform-support."
                ),
            )
        executable = shutil.which("git")
        if executable is None:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Git is not installed or is unavailable on PATH.",
                remediation="Install Git or disable the Git integration.",
            )

        git_dir = repository / ".git"
        stores = _require_self_contained_git_dir(repository, git_dir)
        before = _git_dir_fingerprint(git_dir)
        # Explicit --git-dir/--work-tree win over repo-local core.worktree, so Git can only
        # read the approved working tree.
        command = [
            executable,
            "-C",
            str(repository),
            f"--git-dir={git_dir}",
            f"--work-tree={repository}",
            *arguments,
        ]
        # The full check above runs once. Immediately before exec and again after Git exits, a
        # cheap fingerprint (identity and mtime of every object and ref directory, plus the
        # redirect files) must still match: any rename, swap, or plant in between changes a
        # directory's mtime, so the output is discarded instead of returned.
        if _git_dir_fingerprint(git_dir) != before:
            raise _git_dir_changed()
        environment = _safe_git_environment(repository)
        try:
            with _pinned_object_view(git_dir, stores) as (object_view, pinned_fds):
                if object_view is not None:
                    environment["GIT_OBJECT_DIRECTORY"] = object_view
                # The command is assembled only from the resolved Git executable, approved
                # repository, and fixed read-only templates declared by this module.
                completed = subprocess.run(  # noqa: S603  # nosec B603
                    command,
                    check=False,
                    shell=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self._runtime.settings.limits.timeout_seconds,
                    env=environment,
                    pass_fds=pinned_fds,
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

        if _git_dir_fingerprint(git_dir) != before:
            raise _git_dir_changed()
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


def _git_denial(reason: str, remediation: str) -> ToolboxError:
    return ToolboxError(ErrorCategory.PERMISSION_DENIED, reason, remediation=remediation)


def _require_self_contained_git_dir(repository: Path, git_dir: Path) -> list[Path]:
    """Refuse any `.git` that lets Git read refs, objects, or config from outside the repository.

    Runs before any Git process is started. Each refusal names its specific reason.
    """

    if git_dir.is_symlink():
        raise _git_denial(
            "The approved repository's .git is a symlink.",
            "Approve a repository whose .git is a real directory.",
        )
    if git_dir.is_file():
        raise _git_denial(
            "The approved repository's .git is a gitdir file, as in a linked worktree or "
            "submodule checkout.",
            "Approve the main working tree that owns the .git directory instead.",
        )
    if not git_dir.is_dir():
        raise _git_denial(
            "The approved repository has no .git directory.",
            "Approve the top level of a Git working tree.",
        )
    for name in _GIT_METADATA_ENTRIES:
        if (git_dir / name).is_symlink():
            raise _git_denial(
                f"The approved repository's .git/{name} is a symlink, so Git could read it "
                "from outside the repository.",
                "Replace the symlink with the real directory or file.",
            )
    root = repository.resolve()
    for name in ("objects", "refs"):
        try:
            resolved = (git_dir / name).resolve(strict=False)
        except OSError as error:
            raise _git_denial(
                f"The approved repository's .git/{name} could not be resolved.",
                "Check the repository's .git directory.",
            ) from error
        if not resolved.is_relative_to(root):
            raise _git_denial(
                f"The approved repository's .git/{name} resolves outside the repository.",
                "Approve a self-contained repository.",
            )
    _refuse_nested_symlinks(git_dir)
    if os.environ.get("GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        # The Git environment is scrubbed, but refuse loudly rather than rely on that alone.
        raise _git_denial(
            "GIT_ALTERNATE_OBJECT_DIRECTORIES is set in the server environment, which would let "
            "Git borrow objects from outside the repository.",
            "Unset GIT_ALTERNATE_OBJECT_DIRECTORIES for the toolbox process.",
        )
    commondir = git_dir / "commondir"
    if commondir.exists() or commondir.is_symlink():
        raise _git_denial(
            "The approved repository's .git has a commondir file, so Git would read refs, "
            "objects, and config from another directory.",
            "Approve the main working tree that owns the shared .git directory instead.",
        )
    initial_store = (git_dir / "objects").resolve(strict=False)
    if not initial_store.is_relative_to(root):
        raise _alternates_denial()
    pending = [initial_store]
    seen: set[Path] = set()
    visits = 0
    while pending:
        objects = pending.pop()
        visits += 1
        if visits > _MAX_ALTERNATE_STORES * 4:
            # Hard stop on the walk itself, independent of the duplicate check below.
            raise _alternates_denial()
        try:
            key = objects.resolve(strict=False)
        except OSError as error:
            raise _alternates_denial() from error
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > _MAX_ALTERNATE_STORES:
            raise _alternates_denial()
        http_alternates = objects / "info" / "http-alternates"
        if http_alternates.exists() or http_alternates.is_symlink():  # dangling links too
            raise _git_denial(
                "The approved repository lists objects/info/http-alternates, which borrows "
                "Git objects from another location.",
                "Remove objects/info/http-alternates or approve a full clone.",
            )
        alternates = objects / "info" / "alternates"
        if alternates.is_symlink():
            raise _alternates_denial()
        if not alternates.is_file():
            continue
        try:
            lines = alternates.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as error:
            raise _alternates_denial() from error
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Git allows C-style quoted paths here; refuse them rather than parse them.
            if line.startswith('"'):
                raise _alternates_denial()
            target = Path(line)
            if not target.is_absolute():
                # Relative entries are relative to the object store that lists them.
                target = objects / target
            try:
                resolved = target.resolve(strict=False)
            except OSError as error:
                raise _alternates_denial() from error
            if not resolved.is_relative_to(root):
                raise _alternates_denial()
            # Alternates chain: the borrowed store may list alternates of its own.
            pending.append(resolved)
    return [store for store in seen if store != initial_store]


def _refuse_nested_symlinks(git_dir: Path) -> None:
    """Refuse a symlink in refs, objects/info, objects/pack, or at any objects/<entry>.

    Loose-object files inside objects/xx are not walked, so a large repository costs about
    256 lstat calls plus its refs and packs.
    """

    def fail(_error: OSError) -> None:
        raise _git_denial(
            "The approved repository's .git could not be inspected.",
            "Check the repository's .git directory permissions.",
        )

    def refuse(name: str) -> ToolboxError:
        return _git_denial(
            f"The approved repository's .git/{name} contains a symlink, so Git could "
            "read objects or refs from outside the repository.",
            "Replace the symlink with the real directory or file.",
        )

    objects = git_dir / "objects"
    try:
        top_entries = list(os.scandir(objects))
    except FileNotFoundError:
        top_entries = []
    except OSError as error:
        fail(error)
        top_entries = []
    for entry in top_entries:
        if entry.is_symlink():
            raise refuse("objects")
    for top, name in (
        (git_dir / "refs", "refs"),
        (objects / "info", "objects"),
        (objects / "pack", "objects"),
    ):
        if not top.exists():
            continue
        for directory, subdirectories, filenames in os.walk(top, onerror=fail, followlinks=False):
            for item in (*subdirectories, *filenames):
                if (Path(directory) / item).is_symlink():
                    raise refuse(name)


# Linux exposes an open descriptor as a path (/proc/self/fd/N) that Git can follow inside its
# own process; that lets Git read exactly the directories and pack files verified here.
_FD_PATHS = sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir()
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_HEX = frozenset("0123456789abcdef")


@contextmanager
def _pinned_object_view(
    git_dir: Path, stores: list[Path]
) -> Iterator[tuple[str | None, tuple[int, ...]]]:
    """Give Git a private object directory bound to descriptors opened without following links.

    `.git`, `objects`, `objects/pack`, each pack file, and each loose `objects/xx` directory are
    opened relative to their verified parent with O_NOFOLLOW. The private view points at those
    descriptors, so swapping a name for a symlink while Git runs cannot change what Git reads.
    Elsewhere (macOS, Windows) the fingerprint checks around exec are the only guard.
    """

    if not _FD_PATHS:
        yield None, ()
        return
    descriptors: list[int] = []

    def keep(descriptor: int) -> int:
        descriptors.append(descriptor)
        return descriptor

    try:
        with TemporaryDirectory(prefix="local-mcp-toolbox-git-objects-") as scratch:
            view = Path(scratch) / "objects"
            try:
                _build_object_view(git_dir, stores, view, keep)
            except OSError as error:
                # ELOOP from O_NOFOLLOW means a name became a symlink after the check.
                raise _git_dir_changed() from error
            yield str(view), tuple(descriptors)
    finally:
        for descriptor in descriptors:
            with suppress(OSError):
                os.close(descriptor)


def _build_object_view(
    git_dir: Path, stores: list[Path], view: Path, keep: Callable[[int], int]
) -> None:
    (view / "info").mkdir(parents=True)
    (view / "pack").mkdir()
    git_fd = keep(os.open(git_dir, _DIRECTORY_FLAGS))
    objects_fd = keep(os.open("objects", _DIRECTORY_FLAGS, dir_fd=git_fd))
    for entry in sorted(os.listdir(objects_fd)):
        if entry == "pack":
            pack_fd = keep(os.open("pack", _DIRECTORY_FLAGS, dir_fd=objects_fd))
            for name in sorted(os.listdir(pack_fd)):
                file_fd = keep(os.open(name, _FILE_FLAGS, dir_fd=pack_fd))
                if stat.S_ISREG(os.fstat(file_fd).st_mode):
                    os.symlink(f"/proc/self/fd/{file_fd}", view / "pack" / name)
        elif len(entry) == 2 and set(entry) <= _HEX:
            fanout_fd = keep(os.open(entry, _DIRECTORY_FLAGS, dir_fd=objects_fd))
            os.symlink(f"/proc/self/fd/{fanout_fd}", view / entry)
    if stores:
        # Alternate stores inside the repository are opened by their resolved path.
        lines = [f"/proc/self/fd/{keep(os.open(store, _DIRECTORY_FLAGS))}" for store in stores]
        (view / "info" / "alternates").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _git_dir_changed() -> ToolboxError:
    return _git_denial(
        "The approved repository's .git directory changed while it was being inspected.",
        "Retry once nothing else is modifying the repository.",
    )


def _git_dir_fingerprint(git_dir: Path) -> tuple[object, ...]:
    """Identify .git and every directory Git reads objects or refs from, plus redirect files.

    Directory mtimes are included: renaming, swapping, or creating an entry inside a
    directory changes its mtime even when the entry is later swapped back.
    """

    parts: list[object] = []

    def stamp(path: Path, with_mtime: bool = True) -> None:
        try:
            info = os.lstat(path)
        except OSError:
            parts.append((str(path), None))
            return
        if stat.S_ISLNK(info.st_mode):
            # Seen mid-swap: never run Git (or return its output) while any link is present.
            raise _git_dir_changed()
        identity = (info.st_dev, info.st_ino, info.st_mode)
        parts.append((str(path), identity + ((info.st_mtime_ns,) if with_mtime else ())))

    # .git's own mtime changes when Git takes index.lock, so only its identity is pinned.
    stamp(git_dir, with_mtime=False)
    objects = git_dir / "objects"
    stamp(objects)
    try:
        names = sorted(os.listdir(objects))
    except OSError:
        names = []
    for name in names:
        stamp(objects / name)
    for top in (git_dir / "refs", objects / "info", objects / "pack"):
        stamp(top)
        for directory, subdirectories, filenames in os.walk(top, followlinks=False):
            for item in sorted((*subdirectories, *filenames)):
                stamp(Path(directory) / item)
    for path in (
        git_dir / "commondir",
        git_dir / "packed-refs",
        git_dir / "HEAD",
        objects / "info" / "alternates",
        objects / "info" / "http-alternates",
    ):
        try:
            parts.append(path.read_bytes())
        except OSError:
            parts.append(None)
    return tuple(parts)


def _alternates_denial() -> ToolboxError:
    return _git_denial(
        "The approved repository borrows Git objects from outside it through "
        "objects/info/alternates (for example a clone made with --shared or --reference).",
        "Run `git repack -a -d` and remove objects/info/alternates, or approve a full clone.",
    )


def _safe_git_environment(repository: Path | None = None) -> dict[str, str]:
    """Keep Git non-interactive and prevent user/system config from injecting behavior."""

    environment = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0"}
    for name in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
        if value := os.environ.get(name):
            environment[name] = value
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    if repository is not None:
        # Never search above the approved repository for a different one.
        environment["GIT_CEILING_DIRECTORIES"] = str(repository.parent)
        # Pin the common and object directories to the approved .git so nothing in it can
        # redirect them.
        git_dir = repository / ".git"
        environment["GIT_COMMON_DIR"] = str(git_dir)
        environment["GIT_OBJECT_DIRECTORY"] = str(git_dir / "objects")
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

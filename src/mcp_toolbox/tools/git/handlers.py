"""Read-only Git inspection through fixed, validated argument templates."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess  # nosec B404
import sys
from collections.abc import Callable, Iterator, Sequence
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
# Entries Git reads from .git; a symlink or special file at any of them is refused.
_GIT_METADATA_DIRECTORIES = ("objects", "refs", "logs", "info", "worktrees")
_GIT_METADATA_FILES = ("HEAD", "config", "packed-refs", "index")
_GIT_METADATA_ENTRIES = (*_GIT_METADATA_DIRECTORIES, *_GIT_METADATA_FILES)
# Longest alternates chain accepted; longer chains are refused rather than walked.
_MAX_ALTERNATE_STORES = 64
_MAX_GIT_METADATA_BYTES = 1_048_576
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
    # Block partial-clone promisor lazy fetches, alternate-ref helpers, and credential/SSH helpers.
    "protocol.allow=never",
    "core.sshCommand=false",
    "core.askPass=false",
    "core.alternateRefsCommand=false",
    "credential.helper=",
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
        before = _git_dir_fingerprint(git_dir, stores)
        # The full check above runs once. Immediately before exec and again after Git exits, a
        # cheap fingerprint (identity, mtime, and ctime of every object and ref directory, plus
        # the redirect files) must still match: any rename, swap, or plant in between changes a
        # directory's timestamps, so the output is discarded instead of returned.
        if _git_dir_fingerprint(git_dir, stores) != before:
            raise _git_dir_changed()
        try:
            with _pinned_object_view(repository, git_dir, stores) as (object_view, pinned_fds):
                overrides = [
                    *_safe_config_arguments(),
                    *_filter_driver_overrides(executable, repository, self._runtime, object_view),
                ]
                # Explicit --git-dir/--work-tree win over repo-local core.worktree, so Git can only
                # read the approved working tree.
                command = [
                    executable,
                    "--no-lazy-fetch",
                    *overrides,
                    f"--git-dir={git_dir}",
                    f"--work-tree={repository}",
                    "-C",
                    str(repository),
                    *arguments,
                ]
                environment = _safe_git_environment(overrides, repository=repository)
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

        if _git_dir_fingerprint(git_dir, stores) != before:
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
            escape_controls=True,
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
            escape_controls=True,
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
            escape_controls=True,
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
            escape_controls=True,
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
    _refuse_invalid_metadata_entries(git_dir)
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
    stores = _walk_alternate_stores(root, initial_store)
    for store in stores:
        _refuse_object_store_entries(store)
    return stores


def _refuse_invalid_metadata_entries(git_dir: Path) -> None:
    for name in _GIT_METADATA_ENTRIES:
        entry = git_dir / name
        if entry.is_symlink():
            raise _git_denial(
                f"The approved repository's .git/{name} is a symlink, so Git could read it "
                "from outside the repository.",
                "Replace the symlink with the real directory or file.",
            )
        try:
            info = os.lstat(entry)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise _git_denial(
                f"The approved repository's .git/{name} could not be inspected.",
                "Check the repository's .git directory permissions.",
            ) from error
        expected_dir = name in _GIT_METADATA_DIRECTORIES
        valid = stat.S_ISDIR(info.st_mode) if expected_dir else stat.S_ISREG(info.st_mode)
        if not valid:
            raise _git_denial(
                f"The approved repository's .git/{name} is not a regular file.",
                f"Remove the non-file entry at .git/{name}.",
            )


def _walk_alternate_stores(root: Path, initial_store: Path) -> list[Path]:
    pending = [initial_store]
    seen: set[Path] = set()
    ordered_stores: list[Path] = []
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
        if key != initial_store:
            ordered_stores.append(key)
        if len(seen) > _MAX_ALTERNATE_STORES:
            raise _alternates_denial()
        http_alternates = objects / "info" / "http-alternates"
        if http_alternates.exists() or http_alternates.is_symlink():  # dangling links too
            raise _git_denial(
                "The approved repository lists objects/info/http-alternates, which borrows "
                "Git objects from another location.",
                "Remove objects/info/http-alternates or approve a full clone.",
            )
        for resolved in _read_alternates_targets(root, objects):
            pending.append(resolved)
    return ordered_stores


def _read_alternates_targets(root: Path, objects: Path) -> list[Path]:
    alternates = objects / "info" / "alternates"
    if alternates.is_symlink():
        raise _alternates_denial()
    try:
        alt_info = os.lstat(alternates)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise _alternates_denial() from error
    if not stat.S_ISREG(alt_info.st_mode):
        raise _git_denial(
            "The approved repository's objects/info/alternates is not a regular file.",
            "Remove the non-file entry at objects/info/alternates.",
        )
    try:
        lines = _read_regular_git_file(alternates).decode("utf-8", errors="replace").splitlines()
    except OSError as error:
        raise _alternates_denial() from error
    targets: list[Path] = []
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
        current = root
        for part in resolved.relative_to(root).parts:
            current = current / part
            if current.is_symlink():
                raise _alternates_denial()
        targets.append(resolved)
    return targets


def _refuse_nested_symlinks(git_dir: Path) -> None:
    """Refuse a symlink or special file in refs, objects/info, objects/pack, or objects/<entry>.

    Loose-object files inside objects/xx are checked during private-view construction, so this
    walk costs about 256 lstat calls plus the repository's refs and packs.
    """

    _refuse_object_store_entries(git_dir / "objects")
    _refuse_tree_entries(git_dir / "refs", "refs")


def _refuse_object_store_entries(objects: Path) -> None:
    try:
        top_entries = list(os.scandir(objects))
    except FileNotFoundError:
        top_entries = []
    except OSError as error:
        _fail_git_inspect(error)
        top_entries = []
    for entry in top_entries:
        if entry.is_symlink():
            raise _symlink_in_git_denial("objects")
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as error:
            _fail_git_inspect(error)
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise _non_regular_in_git_denial("objects")
    for sub in ("info", "pack"):
        _refuse_tree_entries(objects / sub, "objects")


def _refuse_tree_entries(top: Path, name: str) -> None:
    try:
        top_info = os.lstat(top)
    except FileNotFoundError:
        return
    except OSError as error:
        _fail_git_inspect(error)
        return
    if stat.S_ISLNK(top_info.st_mode):
        raise _symlink_in_git_denial(name)
    if not stat.S_ISDIR(top_info.st_mode):
        raise _non_regular_in_git_denial(name)
    for directory, subdirectories, filenames in os.walk(
        top, onerror=_fail_git_inspect, followlinks=False
    ):
        for item in (*subdirectories, *filenames):
            item_path = Path(directory) / item
            try:
                info = os.lstat(item_path)
            except OSError as error:
                _fail_git_inspect(error)
                continue
            if stat.S_ISLNK(info.st_mode):
                raise _symlink_in_git_denial(name)
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise _non_regular_in_git_denial(name)


def _fail_git_inspect(_error: OSError) -> None:
    raise _git_denial(
        "The approved repository's .git could not be inspected.",
        "Check the repository's .git directory permissions.",
    )


def _symlink_in_git_denial(name: str) -> ToolboxError:
    return _git_denial(
        f"The approved repository's .git/{name} contains a symlink, so Git could "
        "read objects or refs from outside the repository.",
        "Replace the symlink with the real directory or file.",
    )


def _non_regular_in_git_denial(name: str) -> ToolboxError:
    return _git_denial(
        f"The approved repository's .git/{name} contains something that is not a regular file.",
        f"Remove the non-file entry from .git/{name}.",
    )


# Linux exposes an open descriptor as a path (/proc/self/fd/N) that Git can follow inside its
# own process; that lets Git read exactly the directories and pack files verified here.
_FD_PATHS = sys.platform.startswith("linux") and Path("/proc/self/fd").is_dir()
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
# O_NONBLOCK: opening a FIFO planted in .git must not block the server.
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
# Above this many loose objects the per-file symlink scan is refused rather than run.
_MAX_LOOSE_OBJECTS = 50_000
_HEX = frozenset("0123456789abcdef")


def _read_regular_git_file(path: Path, max_bytes: int = _MAX_GIT_METADATA_BYTES) -> bytes:
    """Read a regular file inside .git without following symlinks or blocking on FIFOs."""

    descriptor = os.open(path, _FILE_FLAGS)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise _git_denial(
                f"The approved repository's {path.name} is not a regular file.",
                f"Remove the non-file entry at {path.name}.",
            )
        if info.st_size > max_bytes:
            raise _git_denial(
                f"The approved repository's {path.name} exceeds the metadata size limit.",
                f"Inspect a repository whose {path.name} is at most {max_bytes} bytes.",
            )
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 65_536):
            total += len(chunk)
            if total > max_bytes:
                raise _git_denial(
                    f"The approved repository's {path.name} exceeds the metadata size limit.",
                    f"Inspect a repository whose {path.name} is at most {max_bytes} bytes.",
                )
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        with suppress(OSError):
            os.close(descriptor)


@contextmanager
def _pinned_object_view(
    repository: Path, git_dir: Path, stores: Sequence[Path]
) -> Iterator[tuple[str | None, tuple[int, ...]]]:
    """Give Git a private object directory bound to descriptors opened without following links.

    `.git`, `objects`, `objects/pack`, each pack file, and each loose `objects/xx` directory
    (plus any in-repository alternate stores) are opened relative to their verified parent with
    O_NOFOLLOW. The private view points at those descriptors, so swapping a name for a symlink
    while Git runs cannot change what Git reads.
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
                _build_object_view(repository, git_dir, stores, view, keep)
            except OSError as error:
                # ELOOP from O_NOFOLLOW means a name became a symlink after the check.
                raise _git_dir_changed() from error
            yield str(view), tuple(descriptors)
    finally:
        for descriptor in descriptors:
            with suppress(OSError):
                os.close(descriptor)


def _build_object_view(
    repository: Path,
    git_dir: Path,
    stores: Sequence[Path],
    view: Path,
    keep: Callable[[int], int],
) -> None:
    git_fd = keep(os.open(git_dir, _DIRECTORY_FLAGS))
    objects_fd = keep(os.open("objects", _DIRECTORY_FLAGS, dir_fd=git_fd))
    loose_count = _populate_object_store_view(objects_fd, view, keep, 0)
    if stores:
        root = repository.resolve()
        root_fd = keep(os.open(root, _DIRECTORY_FLAGS))
        lines: list[str] = []
        for index, store in enumerate(stores):
            store_fd = _open_relative_store_fd(root_fd, store.relative_to(root).parts, keep)
            alt_view = view.parent / f"alt-{index}"
            loose_count = _populate_object_store_view(store_fd, alt_view, keep, loose_count)
            lines.append(str(alt_view))
        (view / "info" / "alternates").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _open_relative_store_fd(root_fd: int, parts: Sequence[str], keep: Callable[[int], int]) -> int:
    current = root_fd
    for part in parts:
        current = keep(os.open(part, _DIRECTORY_FLAGS, dir_fd=current))
    return current


def _populate_object_store_view(
    objects_fd: int,
    target_view: Path,
    keep: Callable[[int], int],
    loose_count: int,
) -> int:
    (target_view / "info").mkdir(parents=True)
    (target_view / "pack").mkdir()
    for entry in sorted(os.listdir(objects_fd)):
        if entry == "pack":
            pack_fd = keep(os.open("pack", _DIRECTORY_FLAGS, dir_fd=objects_fd))
            for name in sorted(os.listdir(pack_fd)):
                file_fd = keep(os.open(name, _FILE_FLAGS, dir_fd=pack_fd))
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise _git_denial(
                        "The approved repository's .git/objects/pack contains something that "
                        "is not a regular file.",
                        "Remove the non-file entry from .git/objects/pack.",
                    )
                os.symlink(f"/proc/self/fd/{file_fd}", target_view / "pack" / name)
        elif len(entry) == 2 and set(entry) <= _HEX:
            fanout_fd = keep(os.open(entry, _DIRECTORY_FLAGS, dir_fd=objects_fd))
            with os.scandir(fanout_fd) as loose:
                for item in loose:
                    loose_count += 1
                    if loose_count > _MAX_LOOSE_OBJECTS:
                        raise _git_denial(
                            "The approved repository has too many loose objects to inspect "
                            f"safely (more than {_MAX_LOOSE_OBJECTS}).",
                            "Run `git gc` in the repository to pack its loose objects.",
                        )
                    if item.is_symlink():
                        raise _git_denial(
                            "The approved repository's .git/objects contains a symlinked "
                            "loose object, so Git could read another repository's data.",
                            "Replace the symlink with the real object file or run `git gc`.",
                        )
                    if not item.is_file(follow_symlinks=False):
                        raise _git_denial(
                            "The approved repository's .git/objects contains a loose object "
                            "that is not a regular file.",
                            "Remove the non-file entry from .git/objects.",
                        )
            os.symlink(f"/proc/self/fd/{fanout_fd}", target_view / entry)
    return loose_count


def _git_dir_changed() -> ToolboxError:
    return _git_denial(
        "The approved repository's .git directory changed while it was being inspected.",
        "Retry once nothing else is modifying the repository.",
    )


def _git_dir_fingerprint(git_dir: Path, stores: Sequence[Path] = ()) -> tuple[object, ...]:
    """Identify .git and every directory Git reads objects or refs from, plus redirect files.

    Directory mtimes and ctimes are included: renaming, swapping, or creating an entry inside a
    directory updates its timestamps (and ctime cannot be rolled back with os.utime).
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
        times = (info.st_mtime_ns, info.st_ctime_ns) if with_mtime else ()
        parts.append((str(path), identity + times))

    # .git's own mtime changes when Git takes index.lock, so only its identity is pinned.
    stamp(git_dir, with_mtime=False)
    all_stores = (git_dir / "objects", *stores)
    for store in all_stores:
        stamp(store)
        try:
            names = sorted(os.listdir(store))
        except OSError:
            names = []
        for name in names:
            stamp(store / name)
        for top in (store / "info", store / "pack"):
            stamp(top)
            for directory, subdirectories, filenames in os.walk(top, followlinks=False):
                for item in sorted((*subdirectories, *filenames)):
                    stamp(Path(directory) / item)
    refs = git_dir / "refs"
    stamp(refs)
    for directory, subdirectories, filenames in os.walk(refs, followlinks=False):
        for item in sorted((*subdirectories, *filenames)):
            stamp(Path(directory) / item)
    metadata_files = [
        git_dir / "commondir",
        git_dir / "packed-refs",
        git_dir / "HEAD",
    ]
    for store in all_stores:
        metadata_files.append(store / "info" / "alternates")
        metadata_files.append(store / "info" / "http-alternates")
    for path in metadata_files:
        try:
            parts.append(_read_regular_git_file(path))
        except FileNotFoundError:
            parts.append(None)
        except OSError as error:
            raise _git_dir_changed() from error
    return tuple(parts)


def _alternates_denial() -> ToolboxError:
    return _git_denial(
        "The approved repository borrows Git objects from outside it through "
        "objects/info/alternates (for example a clone made with --shared or --reference).",
        "Run `git repack -a -d` and remove objects/info/alternates, or approve a full clone.",
    )


def _safe_config_arguments() -> list[str]:
    """Return ``-c`` overrides that neutralize repository-controlled command execution."""

    arguments: list[str] = []
    for override in _SAFE_CONFIG_OVERRIDES:
        arguments.extend(["-c", override])
    return arguments


def _filter_driver_overrides(
    executable: str,
    repository: Path,
    runtime: ServerRuntime,
    object_view: str | None = None,
) -> list[str]:
    """Blank every configured filter driver so ``.gitattributes`` cannot run clean/process commands.

    Filter driver names are chosen by the repository, so they cannot be listed in the fixed
    overrides. Reading config with ``git config`` never runs a driver.
    """

    git_dir = repository / ".git"
    environment = _safe_git_environment(repository=repository)
    if object_view is not None:
        environment["GIT_OBJECT_DIRECTORY"] = object_view
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [
                executable,
                "--no-lazy-fetch",
                f"--git-dir={git_dir}",
                f"--work-tree={repository}",
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
            env=environment,
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
    for raw_name in completed.stdout.split("\n"):
        line = raw_name[:-1] if raw_name.endswith("\r") else raw_name
        if not line:
            continue
        lowered = line.lower()
        driver = (
            line[len("filter.") : line.rindex(".")]
            if lowered.startswith("filter.")
            and line.count(".") >= 2
            and lowered.rsplit(".", 1)[-1] in ("clean", "smudge", "process")
            else ""
        )
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
    """Return True when a filter driver name is empty or contains '=' or non-printable chars."""

    return (
        not driver
        or "=" in driver
        or not driver.isprintable()
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in driver)
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


def _safe_git_environment(
    overrides: Sequence[str] | Path | None = (),
    *,
    repository: Path | None = None,
) -> dict[str, str]:
    """Keep Git non-interactive, read-only, and free of user/system config injection."""

    if isinstance(overrides, Path):
        repository = overrides
        override_seq: Sequence[str] = ()
    else:
        override_seq = overrides or ()
    environment = {"PATH": os.environ.get("PATH", ""), "GIT_TERMINAL_PROMPT": "0"}
    for name in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
        if value := os.environ.get(name):
            environment[name] = value
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    # Stop `git status` from refreshing the index or taking index.lock in the repository.
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_ASKPASS"] = "false"
    environment["SSH_ASKPASS"] = "false"
    if repository is not None:
        # Never search above the approved repository for a different one.
        environment["GIT_CEILING_DIRECTORIES"] = str(repository.parent)
        # Pin the common and object directories to the approved .git so nothing in it can
        # redirect them.
        git_dir = repository / ".git"
        environment["GIT_DIR"] = str(git_dir)
        environment["GIT_WORK_TREE"] = str(repository)
        environment["GIT_COMMON_DIR"] = str(git_dir)
        environment["GIT_OBJECT_DIRECTORY"] = str(git_dir / "objects")
    pairs = _config_override_pairs(override_seq)
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

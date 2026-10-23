"""Race-safe, symlink-safe file reading for agent configuration auditing."""

from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.tools.security.models import matches_blocked_parts

if TYPE_CHECKING:
    from mcp_toolbox.permissions.service import FilesystemAuthorizer

USE_DIR_FD = (
    os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
)


def reject_link_or_junction_chain(base: Path, target: Path) -> None:
    """Verify no path component from base to target is a symlink or Windows junction."""

    relative = target.relative_to(base)
    current = base
    candidates = [base]
    for part in relative.parts:
        current = current / part
        candidates.append(current)
    for candidate in candidates:
        try:
            st = candidate.lstat()
            is_link = stat.S_ISLNK(st.st_mode)
            is_junction = candidate.is_junction() if hasattr(candidate, "is_junction") else False
        except FileNotFoundError as error:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "The requested agent configuration path was not found.",
                remediation="Pass an existing directory or regular file path.",
            ) from error
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use an accessible regular directory or file path.",
            ) from error
        if is_link or is_junction:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Symbolic links and junctions are not permitted for the target path.",
                remediation="Pass a canonical regular directory or file path.",
            )


def read_checked_fd(fd: int, budget: int, max_file_bytes: int) -> tuple[bytes | None, bool]:
    """Read from an open descriptor only if it is a single-link regular file within budget."""

    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return None, False
    if info.st_size > budget:
        return None, True
    chunks: list[bytes] = []
    remaining = budget + 1
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 262_144))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > budget:
        return None, True
    return payload, False


def read_without_following(
    root: Path,
    parts: tuple[str, ...],
    budget: int,
    max_file_bytes: int,
) -> tuple[bytes | None, bool]:
    """POSIX: open each component relative to its parent descriptor with O_NOFOLLOW."""

    cloexec = getattr(os, "O_CLOEXEC", 0)
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec
    directory = os.open(root, dir_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, dir_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | cloexec
        descriptor = os.open(parts[-1], file_flags, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        return read_checked_fd(descriptor, budget, max_file_bytes)
    finally:
        os.close(descriptor)


def read_resolved_fallback(
    root: Path,
    parts: tuple[str, ...],
    budget: int,
    max_file_bytes: int,
    blocked_patterns: Sequence[str],
    authorizer: FilesystemAuthorizer | None,
) -> tuple[bytes | None, bool]:
    """Fallback when dir_fd/O_NOFOLLOW is unavailable: reject links and verify inode."""

    candidate = root.joinpath(*parts)
    reject_link_or_junction_chain(root, candidate)
    canonical = candidate.resolve(strict=True)
    if not canonical.is_relative_to(root):
        return None, False
    rel_canonical = canonical.relative_to(root)
    if matches_blocked_parts(rel_canonical.parts, blocked_patterns):
        return None, False
    if authorizer is not None and not authorizer.check_path(canonical).allowed:
        return None, False
    expected = os.stat(canonical)
    if not stat.S_ISREG(expected.st_mode) or expected.st_nlink != 1:
        return None, False
    open_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(canonical, open_flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            return None, False
        if candidate.resolve(strict=True) != canonical:
            return None, False
        return read_checked_fd(descriptor, budget, max_file_bytes)
    finally:
        os.close(descriptor)


def read_safe_candidate(
    root: Path,
    parts: tuple[str, ...],
    budget: int,
    max_file_bytes: int,
    blocked_patterns: Sequence[str],
    authorizer: FilesystemAuthorizer | None,
) -> tuple[bytes | None, bool]:
    if not parts or "." in parts or ".." in parts:
        return None, False
    if matches_blocked_parts(parts, blocked_patterns):
        return None, False
    candidate = root.joinpath(*parts)
    if authorizer is not None and not authorizer.check_path(candidate).allowed:
        return None, False
    try:
        if USE_DIR_FD:
            return read_without_following(root, parts, budget, max_file_bytes)
        return read_resolved_fallback(
            root, parts, budget, max_file_bytes, blocked_patterns, authorizer
        )
    except (OSError, ValueError, ToolboxError):
        return None, False

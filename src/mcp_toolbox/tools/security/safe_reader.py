"""Race-safe, symlink-safe file reading and directory walking for agent config auditing."""

from __future__ import annotations

import os
import stat
import sys
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

_DARWIN_SYSTEM_ROOT_NAMES = frozenset({"tmp", "var", "etc"})


def _is_link_or_junction(candidate: Path, st: os.stat_result) -> bool:
    is_link = stat.S_ISLNK(st.st_mode)
    is_junction = candidate.is_junction() if hasattr(candidate, "is_junction") else False
    return is_link or is_junction


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
            bad = _is_link_or_junction(candidate, st)
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
        if bad:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Symbolic links and junctions are not permitted for the target path.",
                remediation="Pass a canonical regular directory or file path.",
            )


def reject_cli_target_links(target_path: Path, lexical: Path) -> os.stat_result:
    """Verify a CLI target path and its ancestor components contain no symlinks or junctions."""

    if not target_path.is_absolute():
        try:
            cwd_root = Path.cwd().resolve(strict=True)
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "The current working directory could not be accessed.",
                remediation="Check filesystem permissions for the working directory.",
            ) from error
        reject_link_or_junction_chain(cwd_root, cwd_root.joinpath(*target_path.parts))

    anchor = Path(lexical.anchor)
    rel_parts = lexical.relative_to(anchor).parts
    current = anchor
    candidates = [anchor]
    for part in rel_parts:
        current = current / part
        candidates.append(current)

    last_stat: os.stat_result | None = None
    for candidate in candidates:
        try:
            st = candidate.lstat()
            bad = _is_link_or_junction(candidate, st)
        except FileNotFoundError as error:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "The requested target path was not found.",
                remediation="Pass an existing directory or regular file path.",
            ) from error
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "The requested target path could not be accessed.",
                remediation="Check filesystem permissions for the target path.",
            ) from error
        if (
            sys.platform == "darwin"
            and candidate != lexical
            and candidate.parent == anchor
            and candidate.name in _DARWIN_SYSTEM_ROOT_NAMES
        ):
            last_stat = st
            continue
        if bad:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Target path cannot be a symbolic link or junction.",
                remediation="Pass a canonical regular directory or file path.",
            )
        last_stat = st

    if last_stat is None:
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The requested target path was not found.",
            remediation="Pass an existing directory or regular file path.",
        )
    return last_stat


def open_anchored_dir_fd(root: Path, parts: tuple[str, ...]) -> int:
    """Open root and step through each directory part with O_RDONLY | O_DIRECTORY | O_NOFOLLOW."""

    cloexec = getattr(os, "O_CLOEXEC", 0)
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec
    directory = os.open(root, dir_flags)
    try:
        for part in parts:
            child = os.open(part, dir_flags, dir_fd=directory)
            os.close(directory)
            directory = child
    except BaseException:
        os.close(directory)
        raise
    return directory


def walk_safe_directory(
    root: Path,
    prefix_parts: tuple[str, ...],
    skipped_directories: frozenset[str],
) -> tuple[list[tuple[tuple[str, ...], list[str], list[str]]], int]:
    """Walk a directory anchored at root/prefix_parts without following symlinks."""

    if USE_DIR_FD:
        cloexec = getattr(os, "O_CLOEXEC", 0)
        dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec
        try:
            top_fd = open_anchored_dir_fd(root, prefix_parts)
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

        entries: list[tuple[tuple[str, ...], list[str], list[str]]] = []
        withheld_count = 0

        def _walk_fd(current_fd: int, rel_dir_parts: tuple[str, ...]) -> None:
            nonlocal withheld_count
            try:
                names = sorted(os.listdir(current_fd))
            except OSError:
                withheld_count += 1
                return
            child_dirs: list[tuple[str, int]] = []
            regular_names: list[str] = []
            symlink_names: list[str] = []
            for name in names:
                try:
                    st = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                except OSError:
                    withheld_count += 1
                    continue
                if stat.S_ISLNK(st.st_mode):
                    symlink_names.append(name)
                elif stat.S_ISDIR(st.st_mode):
                    if name in skipped_directories or name.endswith(".egg"):
                        continue
                    try:
                        child_fd = os.open(name, dir_flags, dir_fd=current_fd)
                    except OSError:
                        withheld_count += 1
                        continue
                    child_dirs.append((name, child_fd))
                else:
                    regular_names.append(name)
            entries.append((rel_dir_parts, regular_names, symlink_names))
            for sub_name, child_fd in child_dirs:
                try:
                    _walk_fd(child_fd, (*rel_dir_parts, sub_name))
                finally:
                    os.close(child_fd)

        try:
            _walk_fd(top_fd, ())
        finally:
            os.close(top_fd)
        return entries, withheld_count

    scan_root = root.joinpath(*prefix_parts)
    reject_link_or_junction_chain(root, scan_root)
    fallback_entries: list[tuple[tuple[str, ...], list[str], list[str]]] = []
    fallback_withheld = 0
    for current_dir, subdirectories, filenames in os.walk(scan_root, followlinks=False):
        current_path = Path(current_dir)
        try:
            rel_dir = current_path.relative_to(scan_root)
        except ValueError:
            subdirectories[:] = []
            continue
        kept_subdirs: list[str] = []
        for subdir in sorted(subdirectories):
            if subdir in skipped_directories or subdir.endswith(".egg"):
                continue
            subdir_path = current_path / subdir
            try:
                sub_st = subdir_path.lstat()
                bad_sub = _is_link_or_junction(subdir_path, sub_st)
            except OSError:
                fallback_withheld += 1
                continue
            if bad_sub or not stat.S_ISDIR(sub_st.st_mode):
                fallback_withheld += 1
                continue
            kept_subdirs.append(subdir)
        subdirectories[:] = kept_subdirs
        fallback_entries.append((rel_dir.parts, sorted(filenames), []))
    return fallback_entries, fallback_withheld


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
    directory = open_anchored_dir_fd(root, parts[:-1])
    try:
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
    """Fallback when dir_fd/O_NOFOLLOW is unavailable: reject links, verify inode and real path."""

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
        # Ask the OS where the open file really is, so a parent folder swapped for a link
        # between the checks and the open cannot redirect the read outside the root.
        real_path = opened_file_path(descriptor)
        if real_path is None or not same_path(real_path, canonical):
            return None, False
        if not is_under(real_path, root):
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
    try:
        if authorizer is not None and not authorizer.check_path(candidate).allowed:
            return None, False
        if USE_DIR_FD:
            return read_without_following(root, parts, budget, max_file_bytes)
        return read_resolved_fallback(
            root, parts, budget, max_file_bytes, blocked_patterns, authorizer
        )
    except (OSError, ValueError, ToolboxError):
        return None, False


def same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def is_under(path: Path, root: Path) -> bool:
    folded_path = Path(os.path.normcase(str(path)))
    folded_root = Path(os.path.normcase(str(root)))
    return folded_path != folded_root and folded_path.is_relative_to(folded_root)


def strip_final_path_prefix(path: str) -> str:
    """Turn `\\\\?\\C:\\x` into `C:\\x` and `\\\\?\\UNC\\srv\\x` into `\\\\srv\\x`."""

    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[len("\\\\?\\UNC\\") :]
    if path.startswith("\\\\?\\"):
        return path[len("\\\\?\\") :]
    return path


def opened_file_path(descriptor: int) -> Path | None:
    """Return the real path of an open file from the operating system, or None if unknown.

    Windows asks GetFinalPathNameByHandleW about the open handle. Linux reads the
    `/proc/self/fd` link (used when the fallback is forced in tests). Anything else
    returns None, and the caller then refuses to read the file.
    """

    if sys.platform == "win32":
        return _windows_final_path(descriptor)
    if sys.platform.startswith("linux"):
        try:
            return Path(os.readlink(f"/proc/self/fd/{descriptor}"))
        except OSError:
            return None
    return None


def _windows_final_path(descriptor: int) -> Path | None:  # pragma: no cover - Windows only
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined,unused-ignore]
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final_path.restype = wintypes.DWORD
    handle = msvcrt.get_osfhandle(descriptor)  # type: ignore[attr-defined,unused-ignore]
    size = 512
    while True:
        buffer = ctypes.create_unicode_buffer(size)
        # FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
        length = get_final_path(handle, buffer, size, 0)
        if length == 0:
            return None
        if length < size:
            return Path(strip_final_path_prefix(buffer.value))
        if length > 32768:
            return None
        size = length + 1

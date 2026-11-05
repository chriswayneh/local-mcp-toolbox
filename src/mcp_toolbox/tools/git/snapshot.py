"""Bounded private Git input copies for platforms without descriptor-backed paths.

Nothing is executed against the source. Every file is copied through the shared
no-follow/Windows final-handle-path reader. Incomplete snapshots fail closed.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess  # nosec B404
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.tools.security.safe_reader import (
    read_safe_candidate,
    reject_link_or_junction_chain,
)

MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_ENTRIES = 50_000
MAX_SNAPSHOT_DEPTH = 64
_CONFIG_KEY = re.compile(
    r"(?:user\.(?:name|email)|"
    r"core\.(?:repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|"
    r"precomposeunicode|symlinks|autocrlf|safecrlf|eol)|extensions\.objectformat|"
    r"remote\..+\.(?:url|fetch)|branch\..+\.(?:remote|merge)|"
    r"filter\..+\.(?:clean|smudge|process|required))\Z",
    re.IGNORECASE,
)


def _denied(message: str) -> ToolboxError:
    return ToolboxError(
        ErrorCategory.PERMISSION_DENIED,
        message,
        remediation=(
            "Use a small, stable, self-contained repository with regular single-link files "
            "and basic local Git configuration, or inspect it on Linux."
        ),
    )


@contextmanager
def private_repository_snapshot(repository: Path, timeout: int) -> Iterator[Path]:
    """Copy complete inputs, refuse unsupported configuration, then discard the copy."""

    deadline = time.monotonic() + timeout
    try:
        with TemporaryDirectory(prefix="toolbox-git-snapshot-") as temporary:
            target = Path(temporary).resolve() / "repository"
            target.mkdir(mode=0o700)
            if target.is_relative_to(repository):
                raise _denied("Git snapshot storage must be outside the approved repository.")
            remaining = MAX_SNAPSHOT_BYTES
            count = 0
            pending = [(repository, target, 0)]
            while pending:
                source, destination, depth = pending.pop()
                if time.monotonic() > deadline:
                    raise ToolboxError(ErrorCategory.TIMEOUT, "Git snapshot preparation timed out.")
                if depth > MAX_SNAPSHOT_DEPTH:
                    raise _denied("The repository exceeds the Git snapshot depth limit.")
                reject_link_or_junction_chain(repository, source)
                with os.scandir(source) as entries:
                    for entry in entries:
                        count += 1
                        if count > MAX_SNAPSHOT_ENTRIES or time.monotonic() > deadline:
                            raise _denied("The repository exceeds the Git snapshot work limit.")
                        path = Path(entry.path)
                        if path.name.casefold() == ".gitmodules" or (
                            path.name.casefold() == ".git" and path.parent != repository
                        ):
                            raise _denied(
                                "Nested repositories and submodules are not supported "
                                "by Git snapshots."
                            )
                        reject_link_or_junction_chain(repository, path)
                        info = path.lstat()
                        copy = destination / entry.name
                        if stat.S_ISDIR(info.st_mode):
                            copy.mkdir()
                            pending.append((path, copy, depth + 1))
                        elif stat.S_ISREG(info.st_mode):
                            payload, truncated = read_safe_candidate(
                                repository,
                                path.relative_to(repository).parts,
                                remaining,
                                remaining,
                                (),
                                None,
                            )
                            if payload is None or truncated:
                                raise _denied(
                                    "A repository file could not be copied safely within limits."
                                )
                            remaining -= len(payload)
                            copy.write_bytes(payload)
                            # Preserve executable status, not setuid or writable group permissions.
                            copy.chmod(0o600 | (info.st_mode & 0o111))
                        else:
                            raise _denied("Git snapshots require regular files and directories.")
            _validate_snapshot_config(target, timeout)
            yield target
    except OSError as error:
        raise _denied("The repository changed or could not be copied safely.") from error


def _validate_snapshot_config(snapshot: Path, timeout: int) -> None:
    """Probe only copied config, explicitly disabling includes and ambient settings."""

    config = snapshot / ".git" / "config"
    if not config.is_file() or config.stat().st_size > 1_048_576:
        raise _denied("Git snapshots require a bounded local configuration file.")
    # Alternate stores and linked worktrees would need their own rewritten snapshot mapping.
    for path in snapshot.rglob("alternates"):
        if "objects" in path.parts:
            raise _denied("Alternate object stores are not supported by Git snapshots.")
    executable = shutil.which("git")
    if executable is None:
        raise ToolboxError(ErrorCategory.INTEGRATION_UNAVAILABLE, "Git is not installed.")
    environment = {
        key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR") if key in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CEILING_DIRECTORIES": str(snapshot.parent),
        }
    )
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            [
                executable,
                "config",
                "--no-includes",
                "--file",
                str(config),
                "--null",
                "--name-only",
                "--list",
            ],
            cwd=snapshot.parent,
            env=environment,
            shell=False,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ToolboxError(
            ErrorCategory.TIMEOUT, "Git snapshot configuration check timed out."
        ) from error
    if result.returncode != 0:
        raise _denied("Git snapshot configuration is invalid.")
    try:
        names = result.stdout.decode("utf-8", errors="strict").split("\0")
    except UnicodeDecodeError as error:
        raise _denied("Git snapshot configuration keys must be valid UTF-8.") from error
    if any(name and not _CONFIG_KEY.fullmatch(name) for name in names):
        raise _denied("Git snapshot configuration contains unsupported settings or redirects.")

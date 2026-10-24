"""Narrow, fixed-command adapters for approved local security scanners."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess  # nosec B404
import sys
from dataclasses import dataclass
from importlib.util import find_spec
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit
from mcp_toolbox.tools.security.agent_audit import register_agent_config_audit_tool
from mcp_toolbox.tools.security.safe_reader import is_under as _is_under
from mcp_toolbox.tools.security.safe_reader import opened_file_path as _opened_file_path
from mcp_toolbox.tools.security.safe_reader import same_path as _same_path

if TYPE_CHECKING:
    from mcp_toolbox.server.runtime import ServerRuntime

_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


@dataclass(frozen=True, slots=True)
class ScannerResult:
    """Bounded machine-readable output from one fixed scanner invocation."""

    stdout: str


# Bandit's own recursion rules: which files it scans and which directories it skips.
_BANDIT_SUFFIXES = frozenset({".py", ".pyw"})
_BANDIT_SKIPPED_DIRECTORIES = frozenset(
    {".svn", "CVS", ".bzr", ".hg", ".git", "__pycache__", ".tox", ".eggs"}
)
# Per-file and whole-snapshot byte caps; anything over them is withheld and counted.
_MAX_FILE_BYTES = 5 * 1024 * 1024
_MAX_SNAPSHOT_BYTES = 50 * 1024 * 1024
# POSIX: walk each path component with O_NOFOLLOW relative to its parent's descriptor, so no
# rename or symlink swap between check and open can redirect the read. Windows lacks
# dir_fd/O_NOFOLLOW and falls back to resolve, open, then verify the open handle's real
# path (see docs/tools.md).
_USE_DIR_FD = (
    os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
)
_INVENTORY_SCANNERS = ("bandit", "checkov", "gitleaks", "hadolint", "pip-audit", "semgrep", "trivy")


class ScannerRunner:
    """Run fixed, read-only scanner templates without a shell or inherited secrets."""

    def __init__(self, runtime: ServerRuntime) -> None:
        self._runtime = runtime

    def run_bandit(self, repository: Path) -> ScannerResult:
        """Execute Bandit with its fixed JSON-report template against one approved root."""

        command_prefix = _bandit_command_prefix()
        if command_prefix is None:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Bandit is not installed or is unavailable on PATH.",
                remediation="Install Bandit or disable the security_scanners integration.",
            )
        command = [*command_prefix, "-q", "-r", str(repository), "-f", "json"]
        try:
            with TemporaryDirectory(prefix="local-mcp-toolbox-scanner-") as sandbox_home:
                # Command elements come only from the resolved executable
                # and a canonical approved root.
                completed = subprocess.run(  # noqa: S603  # nosec B603
                    command,
                    check=False,
                    shell=False,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self._runtime.settings.limits.timeout_seconds,
                    env=_safe_scanner_environment(sandbox_home),
                )
        except subprocess.TimeoutExpired as error:
            raise ToolboxError(
                ErrorCategory.TIMEOUT,
                "The security scanner exceeded the configured timeout.",
                remediation="Scan a smaller approved root or increase the configured timeout.",
            ) from error
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Bandit could not be started.",
                remediation="Check the local Bandit installation and server permissions.",
            ) from error

        if completed.returncode not in {0, 1}:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Bandit could not complete the requested scan.",
                remediation=(
                    "Confirm the approved root is readable and Bandit is installed correctly."
                ),
            )
        if len(completed.stdout.encode("utf-8")) > self._runtime.settings.limits.max_output_bytes:
            raise ToolboxError(
                ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                "The scanner report exceeds the configured output limit.",
                remediation="Scan a smaller approved root or use a lower finding limit.",
            )
        return ScannerResult(stdout=completed.stdout)


def register_security_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register scanner tools only after explicit scanner integration enablement."""

    if not runtime.permissions.check_integration("security_scanners").allowed:
        return ()
    runner = ScannerRunner(runtime)

    @server.tool(
        name="security_scanner_inventory",
        title="Security scanner inventory",
        description="Report local availability of a fixed allowlist of security scanners.",
        annotations=_READ_ONLY,
    )
    def security_scanner_inventory() -> dict[str, Any]:
        """Resolve scanner availability only; do not run scanners or expose executable paths."""

        scanners = [
            {"name": name, "available": shutil.which(name) is not None}
            for name in _INVENTORY_SCANNERS
        ]
        return bounded_response(
            runtime,
            "Collected local security-scanner availability.",
            {"scanners": scanners},
            untrusted_content=False,
        )

    @server.tool(
        name="security_scan_repository",
        title="Scan approved repository with Bandit",
        description="Run the fixed read-only Bandit JSON-report template on an approved root.",
        annotations=_READ_ONLY,
    )
    def security_scan_repository(
        repository: str, scanner: str = "bandit", limit: int = 50
    ) -> dict[str, Any]:
        """Return normalized, redacted Bandit findings without source-code excerpts."""

        result_limit = require_bounded_limit(runtime, limit)
        if scanner != "bandit":
            raise ToolboxError(
                ErrorCategory.UNSUPPORTED_OPERATION,
                "The requested scanner is not enabled by this Version 1 adapter.",
                remediation="Use scanner='bandit' or inspect security_scanner_inventory.",
            )
        root = _require_security_root(runtime, repository)
        with TemporaryDirectory(prefix="local-mcp-toolbox-scan-snapshot-") as snapshot_dir:
            # Bandit scans a private copy of only the files authorized right now, so a symlink
            # swapped during or after the scan cannot change what was read or approved.
            snapshot = Path(snapshot_dir).resolve()
            stats = _SnapshotStats()
            authorized = _snapshot_authorized_sources(runtime, root, snapshot, stats)
            raw_findings = _parse_bandit_findings(runner.run_bandit(snapshot).stdout)
        findings = []
        for finding in raw_findings:
            relative = _authorized_relative_path(finding, snapshot, authorized)
            if relative is not None:
                findings.append(_normalize_bandit_finding(finding, relative))
        withheld = len(raw_findings) - len(findings)
        page = findings[:result_limit]
        return bounded_response(
            runtime,
            "Collected normalized Bandit findings; scanner results are untrusted evidence.",
            {
                "scanner": "bandit",
                "findings": page,
                "total_findings": len(findings),
                "truncated_findings": len(findings) > result_limit,
                "withheld_findings": withheld,
                "withheld_files": stats.withheld_files,
                "snapshot_truncated": stats.truncated,
            },
        )

    agent_tools = register_agent_config_audit_tool(server, runtime)
    return ("security_scanner_inventory", "security_scan_repository", *agent_tools)


def _require_security_root(runtime: ServerRuntime, requested_path: str) -> Path:
    runtime.permissions.require_integration("security_scanners")
    root = runtime.permissions.security.require_directory(Path(requested_path))
    if not root.is_dir():
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved security scan root was not found.",
            remediation="Pass an existing approved directory path.",
        )
    return root


def _safe_scanner_environment(sandbox_home: str) -> dict[str, str]:
    """Preserve executable discovery while avoiding inherited credentials and user configuration."""

    environment = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": sandbox_home,
        "USERPROFILE": sandbox_home,
        "APPDATA": sandbox_home,
        "LOCALAPPDATA": sandbox_home,
        "XDG_CONFIG_HOME": sandbox_home,
    }
    for name in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
        if value := os.environ.get(name):
            environment[name] = value
    return environment


def _bandit_command_prefix() -> list[str] | None:
    """Prefer the server's Python environment, then an explicitly discoverable Bandit binary."""

    if find_spec("bandit") is not None:
        return [sys.executable, "-m", "bandit"]
    executable = shutil.which("bandit")
    return [executable] if executable is not None else None


def _parse_bandit_findings(output: str) -> list[dict[str, Any]]:
    try:
        report = json.loads(output)
    except json.JSONDecodeError as error:
        raise ToolboxError(
            ErrorCategory.INTEGRATION_UNAVAILABLE,
            "Bandit returned an unreadable report.",
            remediation="Update Bandit or confirm its JSON output is supported.",
        ) from error
    raw_findings = report.get("results", [])
    if not isinstance(raw_findings, list):
        raise ToolboxError(
            ErrorCategory.INTEGRATION_UNAVAILABLE,
            "Bandit returned an unexpected report structure.",
            remediation="Update Bandit or confirm its JSON output is supported.",
        )
    return [finding for finding in raw_findings if isinstance(finding, dict)]


@dataclass(slots=True)
class _SnapshotStats:
    """Counts for files that were candidates but not copied (no paths, so nothing leaks)."""

    withheld_files: int = 0
    copied_bytes: int = 0
    truncated: bool = False


def _snapshot_authorized_sources(
    runtime: ServerRuntime, root: Path, snapshot: Path, stats: _SnapshotStats | None = None
) -> set[str]:
    """Copy every authorized Bandit source file under ``root`` into ``snapshot``.

    Bandit follows file symlinks on its own, so it could read files outside the approved root
    or files that match a blocked pattern. Instead it scans this copy. Only regular files with
    a single link, at most ``_MAX_FILE_BYTES`` each and ``_MAX_SNAPSHOT_BYTES`` in total, are
    copied. Returns the root-relative POSIX paths copied.
    """

    stats = stats if stats is not None else _SnapshotStats()
    authorized: set[str] = set()
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in _BANDIT_SKIPPED_DIRECTORIES and not name.endswith(".egg")
        )
        for name in sorted(filenames):
            # Bandit includes files by the glob "*.py"; match that literally. Path.suffix changed
            # in Python 3.14 for names like "..py" (now no suffix), so it is not used here.
            if not name.lower().endswith(tuple(_BANDIT_SUFFIXES)):
                continue
            entry = Path(directory) / name
            relative = _copy_if_authorized(runtime, root, entry, snapshot, stats)
            if relative is not None:
                authorized.add(relative)
            else:
                stats.withheld_files += 1
    return authorized


def _copy_if_authorized(
    runtime: ServerRuntime,
    root: Path,
    entry: Path,
    snapshot: Path,
    stats: _SnapshotStats | None = None,
) -> str | None:
    stats = stats if stats is not None else _SnapshotStats()
    try:
        relative = entry.relative_to(root)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            return None
        policy = runtime.permissions.security
        # The link's own name is reported in findings, so it must not match a blocked pattern.
        if policy.matches_blocked_name(relative):
            return None
        budget = min(_MAX_FILE_BYTES, _MAX_SNAPSHOT_BYTES - stats.copied_bytes)
        if _USE_DIR_FD:
            if not policy.check_path(root / relative).allowed:
                return None
            data = _read_without_following(root, relative.parts, budget, stats)
        else:
            data = _read_resolved(runtime, root, entry, budget, stats)
        if data is None:
            return None
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as copy:
            copy.write(data)
        stats.copied_bytes += len(data)
    except (OSError, ValueError):
        return None
    return relative.as_posix()


def _read_checked(fd: int, budget: int, stats: _SnapshotStats) -> bytes | None:
    """Read an open descriptor only if it is a single-link regular file within budget."""

    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return None
    if info.st_size > budget:
        if info.st_size <= _MAX_FILE_BYTES:
            stats.truncated = True
        return None
    chunks: list[bytes] = []
    remaining = budget + 1
    while remaining > 0 and (chunk := os.read(fd, min(remaining, 1024 * 1024))):
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    return data if len(data) <= budget else None


def _read_without_following(
    root: Path, parts: tuple[str, ...], budget: int, stats: _SnapshotStats
) -> bytes | None:
    """POSIX: open each component relative to its parent with O_NOFOLLOW, then read it."""

    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | cloexec
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | cloexec)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        # O_NONBLOCK: opening a FIFO or device must not hang the scan.
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | cloexec
        descriptor = os.open(parts[-1], file_flags, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        return _read_checked(descriptor, budget, stats)
    finally:
        os.close(descriptor)


def _read_resolved(
    runtime: ServerRuntime, root: Path, entry: Path, budget: int, stats: _SnapshotStats
) -> bytes | None:
    """Windows fallback: resolve, check, open, then verify the opened file is the checked one.

    Without dir_fd and O_NOFOLLOW a parent directory can be swapped between the checks and
    the open. So after opening, the operating system is asked for the real path of the open
    handle, and the file is read only if that path is the checked path under `root`.
    """

    canonical = entry.resolve(strict=True)
    if not canonical.is_relative_to(root):
        return None
    if not runtime.permissions.security.check_path(canonical).allowed:
        return None
    expected = os.stat(canonical)
    if not stat.S_ISREG(expected.st_mode):
        return None
    descriptor = os.open(canonical, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            return None
        if entry.resolve(strict=True) != canonical:
            return None
        opened_path = _opened_file_path(descriptor)
        if opened_path is None or not _same_path(opened_path, canonical):
            return None
        if not _is_under(opened_path, root):
            return None
        return _read_checked(descriptor, budget, stats)
    finally:
        os.close(descriptor)


def _authorized_relative_path(
    finding: dict[str, Any], snapshot: Path, authorized: set[str]
) -> str | None:
    """Map a Bandit filename back to the root-relative path it was copied from, if any."""

    filename = finding.get("filename")
    if not isinstance(filename, str) or not filename:
        return None
    reported = Path(filename)
    if not reported.is_absolute():
        reported = snapshot / reported
    try:
        relative = Path(os.path.normpath(reported)).relative_to(snapshot).as_posix()
    except ValueError:
        return None
    return relative if relative in authorized else None


def _normalize_bandit_finding(finding: dict[str, Any], safe_path: str) -> dict[str, Any]:
    return {
        "finding_id": finding.get("test_id"),
        "source": "bandit",
        "severity": finding.get("issue_severity"),
        "category": finding.get("test_name"),
        "file": safe_path,
        "line_number": finding.get("line_number"),
        "description": finding.get("issue_text"),
        "remediation": finding.get("more_info"),
        "confidence": finding.get("issue_confidence"),
    }

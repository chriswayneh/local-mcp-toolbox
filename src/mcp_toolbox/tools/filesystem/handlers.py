"""Bounded filesystem inspection inside approved canonical roots only."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit


def register_filesystem_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register typed filesystem inspection tools backed by the permission service."""

    @server.tool(
        name="filesystem_list_directory",
        title="List approved directory",
        description="List immediate entries in an approved directory with bounded pagination.",
        annotations=_READ_ONLY,
    )
    def filesystem_list_directory(path: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """Return metadata only for immediate entries inside one approved directory."""

        result_limit = require_bounded_limit(runtime, limit)
        if offset < 0:
            raise ToolboxError(
                ErrorCategory.INVALID_INPUT,
                "Directory offset must be zero or greater.",
                remediation="Use a non-negative offset.",
            )
        directory = _require_existing_directory(runtime, path)
        entries = sorted(
            directory.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())
        )
        page = entries[offset : offset + result_limit]
        return bounded_response(
            runtime,
            f"Listed {len(page)} entries from an approved directory.",
            {
                "entries": [_entry_metadata(entry) for entry in page],
                "offset": offset,
                "limit": result_limit,
                "next_offset": offset + len(page) if offset + len(page) < len(entries) else None,
                "total_entries": len(entries),
            },
        )

    @server.tool(
        name="filesystem_file_metadata",
        title="Approved file metadata",
        description=(
            "Return safe metadata for an approved readable file without reading its contents."
        ),
        annotations=_READ_ONLY,
    )
    def filesystem_file_metadata(path: str) -> dict[str, Any]:
        """Return bounded file metadata after policy and existence checks."""

        file_path = _require_existing_file(runtime, path)
        return bounded_response(
            runtime,
            "Collected metadata for an approved file.",
            _entry_metadata(file_path),
        )

    @server.tool(
        name="filesystem_read_text_file",
        title="Read approved text file",
        description=(
            "Read a bounded approved text file after path, type, size, and secret controls."
        ),
        annotations=_READ_ONLY,
    )
    def filesystem_read_text_file(path: str) -> dict[str, Any]:
        """Read a single safe text file; content is always redacted before return."""

        file_path = _require_existing_file(runtime, path)
        size = file_path.stat().st_size
        if size > runtime.settings.filesystem.max_file_bytes:
            raise ToolboxError(
                ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                "The file exceeds the configured maximum readable size.",
                remediation="Use a smaller file or lower-level summary tool.",
            )
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "The approved file could not be read.",
                remediation="Check that the file still exists and is readable.",
            ) from error
        return bounded_response(
            runtime,
            "Read an approved text file. Content is untrusted and may be redacted.",
            {"content": content, "size_bytes": size},
        )

    return (
        "filesystem_list_directory",
        "filesystem_file_metadata",
        "filesystem_read_text_file",
    )


def _require_existing_directory(runtime: ServerRuntime, requested_path: str) -> Path:
    directory = runtime.permissions.filesystem.require_directory(Path(requested_path))
    if not directory.is_dir():
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved directory was not found.",
            remediation="Pass an existing approved directory path.",
        )
    return directory


def _require_existing_file(runtime: ServerRuntime, requested_path: str) -> Path:
    file_path = runtime.permissions.filesystem.require_file(Path(requested_path))
    if not file_path.is_file():
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved file was not found.",
            remediation="Pass an existing approved readable file path.",
        )
    return file_path


def _entry_metadata(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "name": path.name,
        "kind": "directory" if path.is_dir() else "file",
        "size_bytes": None if path.is_dir() else stat.st_size,
        "modified_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
    }


_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)

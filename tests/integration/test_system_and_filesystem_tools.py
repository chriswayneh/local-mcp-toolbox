from __future__ import annotations

import asyncio
from pathlib import Path

from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    FilesystemSettings,
    LimitSettings,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server


def _server(tmp_path: Path):
    root = tmp_path / "approved"
    root.mkdir()
    settings = ToolboxSettings(
        filesystem=FilesystemSettings(
            approved_roots=[root],
            allowed_extensions=[".txt", ".md"],
            blocked_patterns=[".env", "*.pem", "*.key"],
            max_file_bytes=100,
        ),
        audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
    )
    return root, create_server(build_runtime(settings))


def test_system_tools_return_safe_structured_data(tmp_path: Path) -> None:
    _, server = _server(tmp_path)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool("system_info")

            assert result.is_error is False
            assert result.structured_content["data"]["cpu_count"] is not None
            assert result.structured_content["metadata"]["untrusted_content"] is False

    asyncio.run(scenario())


def test_filesystem_tools_enforce_path_and_sensitive_file_policy(tmp_path: Path) -> None:
    root, server = _server(tmp_path)
    safe_file = root / "notes.txt"
    secret_file = root / ".env"
    outside_file = tmp_path / "outside.txt"
    safe_file.write_text("token=ghp_123456789012345678901234567890\nhello", encoding="utf-8")
    secret_file.write_text("PASSWORD=not-real", encoding="utf-8")
    outside_file.write_text("private", encoding="utf-8")

    async def scenario() -> None:
        async with Client(server) as client:
            listed = await client.call_tool(
                "filesystem_list_directory", {"path": str(root), "limit": 10}
            )
            read = await client.call_tool("filesystem_read_text_file", {"path": str(safe_file)})
            blocked = await client.call_tool(
                "filesystem_read_text_file", {"path": str(secret_file)}
            )
            traversal = await client.call_tool(
                "filesystem_read_text_file", {"path": str(root / ".." / "outside.txt")}
            )

            assert listed.is_error is False
            assert {entry["name"] for entry in listed.structured_content["data"]["entries"]} == {
                "notes.txt"
            }
            assert read.is_error is False
            assert (
                "ghp_123456789012345678901234567890"
                not in read.structured_content["data"]["content"]
            )
            assert "[REDACTED_GITHUB_TOKEN]" in read.structured_content["data"]["content"]
            assert blocked.is_error is True
            assert traversal.is_error is True

    asyncio.run(scenario())


def test_directory_listing_enforces_traversal_cap_and_reports_truncation(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    for name in ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt"):
        (root / name).write_text(name, encoding="utf-8")
    server = create_server(
        build_runtime(
            ToolboxSettings(
                filesystem=FilesystemSettings(
                    approved_roots=[root],
                    allowed_extensions=[".txt"],
                    max_directory_entries=3,
                ),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "filesystem_list_directory", {"path": str(root), "limit": 10}
            )

            data = result.structured_content["data"]
            assert result.is_error is False
            assert len(data["entries"]) == 3
            assert data["truncated"] is True
            assert data["scanned_entries"] == 3
            assert data["next_offset"] is None

    asyncio.run(scenario())


def test_files_larger_than_the_safe_read_limit_fail_before_output_serialization(
    tmp_path: Path,
) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    large_file = root / "large.txt"
    large_file.write_text("x" * 300_000, encoding="utf-8")
    server = create_server(
        build_runtime(
            ToolboxSettings(
                filesystem=FilesystemSettings(approved_roots=[root], allowed_extensions=[".txt"]),
                limits=LimitSettings(max_output_bytes=262_144),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool("filesystem_read_text_file", {"path": str(large_file)})

            assert result.is_error is True
            assert result.structured_content["category"] == "OUTPUT_LIMIT_EXCEEDED"
            assert result.structured_content["message"] == (
                "The file exceeds the configured maximum readable size."
            )

    asyncio.run(scenario())


def test_filesystem_reads_reject_oversized_files(tmp_path: Path) -> None:
    root, server = _server(tmp_path)
    oversized_file = root / "large.txt"
    oversized_file.write_text("x" * 101, encoding="utf-8")

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "filesystem_read_text_file", {"path": str(oversized_file)}
            )

            assert result.is_error is True

    asyncio.run(scenario())

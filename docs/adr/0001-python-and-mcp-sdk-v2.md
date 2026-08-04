# ADR 0001: Use Python 3.12 and the official MCP Python SDK v2

- **Status:** Accepted
- **Date:** 2026-08-03

## Context

The project needs a portable MCP server with strict validation, mature DevOps integrations, and excellent test/security tooling.

## Decision

Use Python 3.12+, `uv`, Pydantic, Typer, Structlog, and the official MCP Python SDK v2 (`mcp>=2,<3`). The official SDK v2 is the current stable release line and supports the current MCP specification as well as stdio, Streamable HTTP, and SSE transports.

## Consequences

Python has first-class libraries for Docker, Kubernetes, Git interaction, YAML, and security scanning. Pydantic gives tool schemas and configuration validation a shared type system. We accept that async lifecycle and SDK major-version compatibility need deliberate testing; the dependency is pinned to the v2 major line.

# ADR 0003: Make stdio the default transport and defer network transport

- **Status:** Accepted
- **Date:** 2026-08-03

## Decision

The first supported transport is MCP stdio. Streamable HTTP may be added after the core, binding only to localhost by default and requiring authentication when enabled.

## Consequences

Stdio avoids a listening port and lets desktop/IDE clients supervise the server. Remote access, browser access, and dashboards are intentionally postponed until their authentication and deployment model are proven.

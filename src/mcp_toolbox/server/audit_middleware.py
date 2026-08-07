"""MCP request auditing that records sanitized metadata only."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from mcp.server.context import HandlerResult, ServerRequestContext
from pydantic import ValidationError

from mcp_toolbox.audit import AuditEvent, AuditTimer, JsonlAuditLogger
from mcp_toolbox.models import ErrorCategory, ToolboxError

CallNext = Callable[[ServerRequestContext[Any, Any]], Awaitable[HandlerResult]]


class AuditMiddleware:
    """Record every MCP request after the SDK has handled it."""

    def __init__(self, audit: JsonlAuditLogger) -> None:
        self._audit = audit

    async def __call__(
        self,
        context: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        if context.request_id is None:
            return await call_next(context)

        timer = AuditTimer()
        status = "success"
        category: ErrorCategory | None = None
        permission_decision = "not_applicable"
        try:
            result = await call_next(context)
            permission_decision = self._permission_decision(context.method)
            return result
        except ToolboxError as error:
            status = "denied" if error.category is ErrorCategory.PERMISSION_DENIED else "error"
            category = error.category
            permission_decision = "denied" if status == "denied" else "error"
            raise
        except ValidationError:
            status = "error"
            category = ErrorCategory.INVALID_INPUT
            permission_decision = "invalid_input"
            raise
        except Exception:
            status = "error"
            category = ErrorCategory.INTERNAL_ERROR
            permission_decision = "error"
            raise
        finally:
            tool_name, tool_module = self._audit_identity(context.method, context.params)
            self._audit.record(
                AuditEvent(
                    request_id=str(context.request_id),
                    tool_name=tool_name,
                    tool_module=tool_module,
                    input_summary=self._input_summary(context.params),
                    result_status=status,
                    duration_ms=timer.elapsed_ms(),
                    error_category=category,
                    permission_decision=permission_decision,
                )
            )

    @staticmethod
    def _audit_identity(method: str, params: Mapping[str, Any] | None) -> tuple[str, str]:
        if method == "tools/call" and params and isinstance(params.get("name"), str):
            name = params["name"]
            module = "server" if name.startswith("toolbox_") else name.split("_", maxsplit=1)[0]
            return name, module
        return method.replace("/", "_"), "protocol"

    @staticmethod
    def _input_summary(params: Mapping[str, Any] | None) -> dict[str, Any]:
        if not params:
            return {}
        return dict(params)

    @staticmethod
    def _permission_decision(method: str) -> str:
        if method in {"tools/call", "resources/read", "prompts/get"}:
            return "allowed"
        return "not_applicable"

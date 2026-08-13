"""MCP request auditing that records sanitized metadata only."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from hashlib import sha256
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
            status, category, permission_decision = self._result_outcome(context.method, result)
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
                    client_identifier=self._client_identifier(context),
                    records_returned=self._records_returned(result) if "result" in locals() else 0,
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

        arguments = params.get("arguments")
        summary: dict[str, Any] = {
            "parameter_names": sorted(str(name) for name in params if name != "_meta")[:20],
            "argument_count": len(arguments) if isinstance(arguments, Mapping) else 0,
        }
        if isinstance(arguments, Mapping):
            summary["arguments"] = {
                str(name): AuditMiddleware._value_summary(str(name), value)
                for name, value in list(arguments.items())[:20]
            }
        return summary

    @staticmethod
    def _value_summary(name: str, value: Any) -> dict[str, Any]:
        result: dict[str, Any] = {"type": type(value).__name__}
        if isinstance(value, str):
            result["length"] = len(value)
            if any(token in name.lower() for token in ("path", "file", "root", "repository")):
                result["fingerprint"] = sha256(value.encode("utf-8")).hexdigest()[:16]
        elif isinstance(value, Mapping) or isinstance(value, (list, tuple, set)):
            result["length"] = len(value)
        return result

    @staticmethod
    def _permission_decision(method: str) -> str:
        if method in {"tools/call", "resources/read", "prompts/get"}:
            return "allowed"
        return "not_applicable"

    @classmethod
    def _result_outcome(
        cls, method: str, result: HandlerResult
    ) -> tuple[str, ErrorCategory | None, str]:
        if not cls._result_value(result, "is_error", "isError"):
            return "success", None, cls._permission_decision(method)

        structured = cls._result_value(result, "structured_content", "structuredContent")
        category_value = structured.get("category") if isinstance(structured, Mapping) else None
        try:
            category = (
                ErrorCategory(category_value) if category_value else ErrorCategory.INTERNAL_ERROR
            )
        except ValueError:
            category = ErrorCategory.INTERNAL_ERROR
        status = "denied" if category is ErrorCategory.PERMISSION_DENIED else "error"
        decision = "denied" if status == "denied" else "error"
        return status, category, decision

    @staticmethod
    def _records_returned(result: HandlerResult) -> int:
        structured = AuditMiddleware._result_value(
            result, "structured_content", "structuredContent"
        )
        if not isinstance(structured, Mapping):
            return 0
        data = structured.get("data")
        if not isinstance(data, Mapping):
            return 0
        for name in (
            "entries",
            "records",
            "findings",
            "matches",
            "commits",
            "containers",
            "events",
        ):
            value = data.get(name)
            if isinstance(value, list):
                return len(value)
        return 0

    @staticmethod
    def _result_value(result: HandlerResult, attribute: str, alias: str) -> Any:
        if isinstance(result, Mapping):
            return result.get(attribute, result.get(alias))
        return getattr(result, attribute, None)

    @staticmethod
    def _client_identifier(context: ServerRequestContext[Any, Any]) -> str | None:
        client_params = context.session.client_params
        client_info = getattr(client_params, "client_info", None)
        name = getattr(client_info, "name", None)
        version = getattr(client_info, "version", None)
        if not isinstance(name, str):
            return None
        identifier = f"{name}/{version}" if isinstance(version, str) else name
        return identifier[:200]

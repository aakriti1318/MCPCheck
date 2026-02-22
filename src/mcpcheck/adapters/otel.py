"""
OpenTelemetry adapter for MCPCheck.

Instruments tool calls as OTel spans for observability.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Generator

if TYPE_CHECKING:
    from opentelemetry.trace import Span


class OtelAdapter:
    """
    Adapter for OpenTelemetry tracing.

    Emits spans for tool calls that integrate with existing
    observability infrastructure (Datadog, Grafana, Jaeger, etc.).
    """

    def __init__(
        self,
        service_name: str = "mcpcheck",
        enabled: bool = True,
    ) -> None:
        """
        Initialize the OTel adapter.

        Args:
            service_name: Name of the service for spans.
            enabled: Whether tracing is enabled.
        """
        self.service_name = service_name
        self.enabled = enabled
        self._tracer = None

        if enabled:
            self._init_tracer()

    def _init_tracer(self) -> None:
        """Initialize the OpenTelemetry tracer."""
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.resources import Resource

            resource = Resource.create({"service.name": self.service_name})
            provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(__name__)
        except ImportError:
            self.enabled = False

    @contextmanager
    def tool_call_span(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        server_name: str | None = None,
    ) -> Generator[Span | None, None, None]:
        """
        Create a span for a tool call.

        Args:
            tool_name: Name of the tool being called.
            parameters: Tool parameters.
            server_name: MCP server name.

        Yields:
            The span, or None if tracing is disabled.
        """
        if not self.enabled or not self._tracer:
            yield None
            return

        with self._tracer.start_as_current_span(
            f"mcp.tool.{tool_name}",
            attributes={
                "mcp.tool.name": tool_name,
                "mcp.server.name": server_name or "unknown",
                "mcp.tool.parameter_count": len(parameters),
            },
        ) as span:
            yield span

    def record_finding(
        self,
        span: Span | None,
        rule_id: str,
        severity: str,
        title: str,
    ) -> None:
        """
        Record a security finding as a span event.

        Args:
            span: The current span.
            rule_id: Rule that generated the finding.
            severity: Finding severity.
            title: Finding title.
        """
        if span is None:
            return

        span.add_event(
            "mcpcheck.finding",
            {
                "rule_id": rule_id,
                "severity": severity,
                "title": title,
            },
        )

    def record_policy_decision(
        self,
        span: Span | None,
        allowed: bool,
        action: str,
        matched_rule: str | None,
    ) -> None:
        """
        Record a policy decision as span attributes.

        Args:
            span: The current span.
            allowed: Whether the call was allowed.
            action: Policy action taken.
            matched_rule: Name of the matched rule.
        """
        if span is None:
            return

        span.set_attributes(
            {
                "mcp.policy.allowed": allowed,
                "mcp.policy.action": action,
                "mcp.policy.matched_rule": matched_rule or "none",
            }
        )

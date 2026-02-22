"""
Runtime interceptor — transparent async proxy for MCP clients.

Wraps MCP client objects to intercept tool calls, log them via
OpenTelemetry, and evaluate policies in real-time.
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, AsyncGenerator, Callable, Protocol, TypeVar

import anyio

from mcpcheck.domain.exceptions import PolicyViolationError
from mcpcheck.domain.policy import PolicyAction, PolicyDecision

if TYPE_CHECKING:
    from mcpcheck.engine.policy_engine import PolicyEngine


class McpClientProtocol(Protocol):
    """Protocol for MCP client objects."""

    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """Call a tool on the MCP server."""
        ...


T = TypeVar("T", bound=McpClientProtocol)


class RuntimeInterceptor:
    """
    Intercepts MCP tool calls for monitoring and policy enforcement.

    Can operate in two modes:
    - AUDIT: Log all calls, never block
    - ENFORCE: Block calls that violate policy
    """

    def __init__(
        self,
        client: McpClientProtocol,
        policy_engine: PolicyEngine | None = None,
        mode: str = "audit",
        on_call: Callable[[str, dict[str, Any], PolicyDecision], None] | None = None,
    ) -> None:
        """
        Initialize the interceptor.

        Args:
            client: The MCP client to wrap.
            policy_engine: Policy engine for evaluation.
            mode: "audit" (log only) or "enforce" (block violations).
            on_call: Callback for each tool call.
        """
        self._client = client
        self._policy_engine = policy_engine
        self._mode = mode
        self._on_call = on_call
        self._call_count = 0
        self._blocked_count = 0

    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> Any:
        """
        Intercept a tool call.

        Args:
            tool_name: Name of the tool to call.
            arguments: Tool arguments.

        Returns:
            Tool result if allowed.

        Raises:
            PolicyViolationError: If in enforce mode and policy violated.
        """
        self._call_count += 1
        start_time = time.perf_counter()

        # Evaluate policy
        decision = self._evaluate_policy(tool_name, arguments)

        # Emit span/callback
        if self._on_call:
            self._on_call(tool_name, arguments, decision)

        # Handle blocked calls
        if not decision.allowed and self._mode == "enforce":
            self._blocked_count += 1
            raise PolicyViolationError(
                f"Policy violation: {decision.reason}",
                tool_name=tool_name,
                policy_rule=decision.matched_rule or "unknown",
                parameters=arguments,
            )

        # Pass through to real client
        try:
            result = await self._client.call_tool(tool_name, arguments)
            return result
        finally:
            duration = time.perf_counter() - start_time
            # Could emit duration metric here

    def _evaluate_policy(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> PolicyDecision:
        """Evaluate the policy for a tool call."""
        if self._policy_engine is None:
            return PolicyDecision(
                allowed=True,
                action=PolicyAction.ALLOW,
                matched_rule=None,
                reason="No policy configured",
                should_log=False,
            )

        return self._policy_engine.evaluate(tool_name, arguments)

    @property
    def stats(self) -> dict[str, int]:
        """Get interceptor statistics."""
        return {
            "call_count": self._call_count,
            "blocked_count": self._blocked_count,
        }


def intercept(
    client: T,
    policy: str | PolicyEngine | None = None,
    mode: str = "audit",
) -> RuntimeInterceptor:
    """
    Wrap an MCP client with the runtime interceptor.

    This is the primary public API for runtime interception.

    Args:
        client: The MCP client to wrap.
        policy: Path to policy YAML or PolicyEngine instance.
        mode: "audit" or "enforce".

    Returns:
        Wrapped client that intercepts all tool calls.

    Example:
        >>> from mcpcheck import intercept
        >>> client = intercept(mcp_client, policy="./policy.yaml")
        >>> result = await client.call_tool("get_weather", {"city": "NYC"})
    """
    from mcpcheck.engine.policy_engine import PolicyEngine

    policy_engine: PolicyEngine | None = None

    if isinstance(policy, str):
        policy_engine = PolicyEngine.from_file(policy)
    elif isinstance(policy, PolicyEngine):
        policy_engine = policy

    return RuntimeInterceptor(
        client=client,
        policy_engine=policy_engine,
        mode=mode,
    )

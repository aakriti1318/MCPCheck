"""
Exception hierarchy for MCPCheck.

All exceptions inherit from McpGuardError for easy catching.
"""

from __future__ import annotations


class McpGuardError(Exception):
    """Base exception for all MCPCheck errors."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ManifestParseError(McpGuardError):
    """Raised when an MCP manifest cannot be parsed."""

    def __init__(self, message: str, source: str | None = None, line: int | None = None) -> None:
        super().__init__(message, {"source": source, "line": line})
        self.source = source
        self.line = line


class RuleError(McpGuardError):
    """Raised when a rule fails to execute."""

    def __init__(self, message: str, rule_id: str) -> None:
        super().__init__(message, {"rule_id": rule_id})
        self.rule_id = rule_id


class PolicyError(McpGuardError):
    """Raised when a policy is invalid or cannot be evaluated."""

    def __init__(self, message: str, policy_path: str | None = None) -> None:
        super().__init__(message, {"policy_path": policy_path})
        self.policy_path = policy_path


class ConfigError(McpGuardError):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, config_key: str | None = None) -> None:
        super().__init__(message, {"config_key": config_key})
        self.config_key = config_key


class PolicyViolationError(McpGuardError):
    """Raised when a runtime policy violation is detected in block mode."""

    def __init__(
        self,
        message: str,
        tool_name: str,
        policy_rule: str,
        parameters: dict | None = None,
    ) -> None:
        super().__init__(
            message,
            {
                "tool_name": tool_name,
                "policy_rule": policy_rule,
                "parameters": parameters,
            },
        )
        self.tool_name = tool_name
        self.policy_rule = policy_rule
        self.parameters = parameters or {}


class LlmAdapterError(McpGuardError):
    """Raised when the LLM adapter fails."""

    def __init__(self, message: str, provider: str | None = None) -> None:
        super().__init__(message, {"provider": provider})
        self.provider = provider

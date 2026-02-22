"""
Policy domain models.

Defines the structure for YAML policy files that control
runtime behavior of the interceptor.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PolicyAction(str, Enum):
    """Action to take when a policy rule matches."""

    ALLOW = "ALLOW"  # Explicitly allow (bypass other rules)
    BLOCK = "BLOCK"  # Block the tool call
    AUDIT = "AUDIT"  # Log but don't block
    REQUIRE = "REQUIRE"  # Require specific conditions


class PolicyCondition(BaseModel):
    """Condition for a policy rule to match."""

    model_config = ConfigDict(frozen=True)

    tool_name: str | None = Field(default=None, description="Exact tool name to match")
    tool_name_pattern: str | None = Field(
        default=None, description="Regex pattern for tool name"
    )
    tools_include_all: list[str] | None = Field(
        default=None,
        description="All listed tools must be present in the session",
    )
    tools_include_any: list[str] | None = Field(
        default=None,
        description="Any of the listed tools must be present",
    )
    param_matches: dict[str, str] | None = Field(
        default=None,
        description="Parameter name to regex pattern mapping",
    )
    param_contains: dict[str, str] | None = Field(
        default=None,
        description="Parameter name to substring mapping",
    )
    caller_agent: str | None = Field(
        default=None, description="Agent identifier that made the call"
    )
    unless: PolicyCondition | None = Field(
        default=None, description="Negate if this condition matches"
    )


class PolicyRule(BaseModel):
    """A single policy rule."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Human-readable rule name")
    condition: PolicyCondition = Field(..., description="When this rule applies")
    action: PolicyAction = Field(..., description="Action to take")
    severity: str | None = Field(
        default=None, description="Severity for audit/block actions"
    )
    message: str | None = Field(
        default=None, description="Custom message for violations"
    )
    enabled: bool = Field(default=True, description="Whether the rule is active")


class Policy(BaseModel):
    """
    Complete policy definition.

    Loaded from YAML files and evaluated by the PolicyEngine.
    """

    model_config = ConfigDict(frozen=True)

    version: str = Field(default="1", description="Policy schema version")
    name: str | None = Field(default=None, description="Policy name")
    description: str | None = Field(default=None, description="Policy description")
    rules: list[PolicyRule] = Field(default_factory=list, description="Policy rules")
    defaults: dict[str, Any] = Field(
        default_factory=dict, description="Default settings"
    )

    @property
    def enabled_rules(self) -> list[PolicyRule]:
        """Get only enabled rules."""
        return [r for r in self.rules if r.enabled]


class PolicyDecision(BaseModel):
    """Result of evaluating a policy against a tool call."""

    model_config = ConfigDict(frozen=True)

    allowed: bool = Field(..., description="Whether the call is allowed")
    action: PolicyAction = Field(..., description="The action taken")
    matched_rule: str | None = Field(
        default=None, description="Name of the rule that matched"
    )
    reason: str | None = Field(default=None, description="Why this decision was made")
    should_log: bool = Field(default=True, description="Whether to log this decision")

"""
Policy engine — evaluates YAML policies against tool calls.

Provides O(1) policy evaluation via precompiled rule matching.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import ValidationError

from mcpcheck.domain.exceptions import PolicyError
from mcpcheck.domain.policy import (
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyDecision,
    PolicyRule,
)

if TYPE_CHECKING:
    from pathlib import Path


class PolicyEngine:
    """
    Evaluates policies against tool calls.

    Policies are declarative YAML files that define what tools
    can be called and under what conditions.
    """

    def __init__(self, policy: Policy) -> None:
        """
        Initialize the policy engine.

        Args:
            policy: The compiled policy to evaluate.
        """
        self.policy = policy
        self._compiled_rules = self._compile_rules(policy.enabled_rules)

    @classmethod
    def from_file(cls, path: Path | str) -> PolicyEngine:
        """
        Load a policy from a YAML file.

        Args:
            path: Path to the policy YAML file.

        Returns:
            PolicyEngine instance.

        Raises:
            PolicyError: If the policy cannot be loaded or parsed.
        """
        from pathlib import Path

        path = Path(path)

        try:
            content = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise PolicyError(f"Policy file not found: {path}", policy_path=str(path))
        except Exception as e:
            raise PolicyError(f"Error reading policy: {e}", policy_path=str(path))

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise PolicyError(f"Invalid YAML in policy: {e}", policy_path=str(path))

        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyEngine:
        """
        Load a policy from a dictionary.

        Args:
            data: Policy data.

        Returns:
            PolicyEngine instance.
        """
        try:
            policy = Policy(**data)
        except ValidationError as e:
            raise PolicyError(f"Invalid policy schema: {e}")

        return cls(policy)

    def evaluate(
        self,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Evaluate a tool call against the policy.

        Args:
            tool_name: Name of the tool being called.
            parameters: Tool call parameters.
            context: Additional context (e.g., caller agent).

        Returns:
            PolicyDecision indicating whether the call is allowed.
        """
        parameters = parameters or {}
        context = context or {}

        # Check each rule in order
        for rule, compiled, unless_compiled in self._compiled_rules:
            if self._matches(rule.condition, tool_name, parameters, context, compiled):
                # Check 'unless' clause
                if rule.condition.unless:
                    if self._matches(
                        rule.condition.unless, tool_name, parameters, context, unless_compiled
                    ):
                        continue  # Skip this rule

                return PolicyDecision(
                    allowed=rule.action in (PolicyAction.ALLOW, PolicyAction.AUDIT),
                    action=rule.action,
                    matched_rule=rule.name,
                    reason=rule.message or f"Matched rule: {rule.name}",
                    should_log=rule.action != PolicyAction.ALLOW,
                )

        # Default: allow if no rules matched
        return PolicyDecision(
            allowed=True,
            action=PolicyAction.ALLOW,
            matched_rule=None,
            reason="No policy rules matched",
            should_log=False,
        )

    def _compile_rules(
        self, rules: list[PolicyRule]
    ) -> list[tuple[PolicyRule, dict[str, re.Pattern[str]], dict[str, re.Pattern[str]]]]:
        """Precompile regex patterns for rules."""
        compiled: list[tuple[PolicyRule, dict[str, re.Pattern[str]], dict[str, re.Pattern[str]]]] = []

        for rule in rules:
            patterns: dict[str, re.Pattern[str]] = {}
            unless_patterns: dict[str, re.Pattern[str]] = {}

            if rule.condition.tool_name_pattern:
                patterns["tool_name"] = re.compile(
                    rule.condition.tool_name_pattern, re.IGNORECASE
                )

            if rule.condition.param_matches:
                for param_name, pattern in rule.condition.param_matches.items():
                    patterns[f"param:{param_name}"] = re.compile(pattern, re.IGNORECASE)

            # Compile unless clause patterns
            if rule.condition.unless:
                if rule.condition.unless.tool_name_pattern:
                    unless_patterns["tool_name"] = re.compile(
                        rule.condition.unless.tool_name_pattern, re.IGNORECASE
                    )
                if rule.condition.unless.param_matches:
                    for param_name, pattern in rule.condition.unless.param_matches.items():
                        unless_patterns[f"param:{param_name}"] = re.compile(pattern, re.IGNORECASE)

            compiled.append((rule, patterns, unless_patterns))

        return compiled

    def _matches(
        self,
        condition: PolicyCondition,
        tool_name: str,
        parameters: dict[str, Any],
        context: dict[str, Any],
        compiled: dict[str, re.Pattern[str]],
    ) -> bool:
        """Check if a condition matches."""
        # Exact tool name match
        if condition.tool_name and condition.tool_name.lower() != tool_name.lower():
            return False

        # Tool name pattern match
        if condition.tool_name_pattern:
            pattern = compiled.get("tool_name")
            if pattern and not pattern.match(tool_name):
                return False

        # Caller agent match
        if condition.caller_agent:
            if context.get("caller_agent") != condition.caller_agent:
                return False

        # Parameter pattern matches
        if condition.param_matches:
            for param_name, _pattern in condition.param_matches.items():
                param_value = str(parameters.get(param_name, ""))
                compiled_pattern = compiled.get(f"param:{param_name}")
                if compiled_pattern and not compiled_pattern.search(param_value):
                    return False

        # Parameter substring contains
        if condition.param_contains:
            for param_name, substring in condition.param_contains.items():
                param_value = str(parameters.get(param_name, ""))
                if substring.lower() not in param_value.lower():
                    return False

        # All conditions passed
        return True

"""
Unit tests for the policy engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcpcheck.domain.policy import Policy, PolicyAction, PolicyCondition, PolicyRule
from mcpcheck.engine.policy_engine import PolicyEngine


class TestPolicyEngine:
    """Tests for the PolicyEngine class."""

    def test_evaluate_exact_tool_match(self) -> None:
        """Should match exact tool names."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="block-shell",
                    condition=PolicyCondition(tool_name="execute_bash"),
                    action=PolicyAction.BLOCK,
                )
            ]
        )

        engine = PolicyEngine(policy)

        # Should block
        decision = engine.evaluate("execute_bash", {})
        assert not decision.allowed
        assert decision.action == PolicyAction.BLOCK
        assert decision.matched_rule == "block-shell"

        # Should allow (different tool)
        decision = engine.evaluate("read_file", {})
        assert decision.allowed

    def test_evaluate_tool_name_pattern(self) -> None:
        """Should match tool names by regex pattern."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="audit-api-calls",
                    condition=PolicyCondition(tool_name_pattern=r".*_api$"),
                    action=PolicyAction.AUDIT,
                )
            ]
        )

        engine = PolicyEngine(policy)

        # Should match
        decision = engine.evaluate("github_api", {})
        assert decision.action == PolicyAction.AUDIT
        assert decision.matched_rule == "audit-api-calls"

        # Should not match
        decision = engine.evaluate("read_file", {})
        assert decision.action == PolicyAction.ALLOW
        assert decision.matched_rule is None

    def test_evaluate_param_matches(self) -> None:
        """Should match based on parameter values."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="block-sensitive-paths",
                    condition=PolicyCondition(
                        tool_name="read_file",
                        param_matches={"path": r"/etc/.*|/var/.*"},
                    ),
                    action=PolicyAction.BLOCK,
                )
            ]
        )

        engine = PolicyEngine(policy)

        # Should block sensitive path
        decision = engine.evaluate("read_file", {"path": "/etc/passwd"})
        assert not decision.allowed

        # Should allow safe path
        decision = engine.evaluate("read_file", {"path": "/home/user/file.txt"})
        assert decision.allowed

    def test_evaluate_param_contains(self) -> None:
        """Should match based on parameter substring."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="block-secret-files",
                    condition=PolicyCondition(
                        tool_name="read_file",
                        param_contains={"path": "secret"},
                    ),
                    action=PolicyAction.BLOCK,
                )
            ]
        )

        engine = PolicyEngine(policy)

        # Should block
        decision = engine.evaluate("read_file", {"path": "/home/user/secret.txt"})
        assert not decision.allowed

        # Should allow
        decision = engine.evaluate("read_file", {"path": "/home/user/config.txt"})
        assert decision.allowed

    def test_evaluate_unless_clause(self) -> None:
        """Should skip rule when unless condition matches."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="block-write-except-tmp",
                    condition=PolicyCondition(
                        tool_name="write_file",
                        unless=PolicyCondition(
                            param_matches={"path": r"^/tmp/.*"}
                        ),
                    ),
                    action=PolicyAction.BLOCK,
                )
            ]
        )

        engine = PolicyEngine(policy)

        # Should block (not in /tmp)
        decision = engine.evaluate("write_file", {"path": "/home/user/file.txt"})
        assert not decision.allowed

        # Should allow (in /tmp, matches unless)
        decision = engine.evaluate("write_file", {"path": "/tmp/safe.txt"})
        assert decision.allowed

    def test_evaluate_first_matching_rule_wins(self) -> None:
        """First matching rule should determine the decision."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="allow-tmp",
                    condition=PolicyCondition(
                        tool_name="write_file",
                        param_matches={"path": r"^/tmp/.*"},
                    ),
                    action=PolicyAction.ALLOW,
                ),
                PolicyRule(
                    name="block-all-writes",
                    condition=PolicyCondition(tool_name="write_file"),
                    action=PolicyAction.BLOCK,
                ),
            ]
        )

        engine = PolicyEngine(policy)

        # Should allow (first rule matches)
        decision = engine.evaluate("write_file", {"path": "/tmp/file.txt"})
        assert decision.allowed
        assert decision.matched_rule == "allow-tmp"

        # Should block (second rule matches)
        decision = engine.evaluate("write_file", {"path": "/home/file.txt"})
        assert not decision.allowed
        assert decision.matched_rule == "block-all-writes"

    def test_evaluate_disabled_rules_skipped(self) -> None:
        """Disabled rules should be skipped."""
        policy = Policy(
            rules=[
                PolicyRule(
                    name="disabled-rule",
                    condition=PolicyCondition(tool_name="dangerous"),
                    action=PolicyAction.BLOCK,
                    enabled=False,
                )
            ]
        )

        engine = PolicyEngine(policy)

        # Should allow (rule is disabled)
        decision = engine.evaluate("dangerous", {})
        assert decision.allowed

    def test_from_dict(self, sample_policy_dict: dict[str, Any]) -> None:
        """Should create engine from dict."""
        engine = PolicyEngine.from_dict(sample_policy_dict)

        assert len(engine.policy.rules) == 2

        # Test that rules work
        decision = engine.evaluate("execute_bash", {})
        assert not decision.allowed

    def test_from_file(self, temp_policy_file: Path) -> None:
        """Should create engine from YAML file."""
        engine = PolicyEngine.from_file(temp_policy_file)

        assert len(engine.policy.rules) == 2

    def test_from_file_not_found(self, tmp_path: Path) -> None:
        """Should raise PolicyError for missing file."""
        from mcpcheck.domain.exceptions import PolicyError

        with pytest.raises(PolicyError) as exc_info:
            PolicyEngine.from_file(tmp_path / "nonexistent.yaml")

        assert "not found" in str(exc_info.value)

    def test_default_allow(self) -> None:
        """Should allow by default when no rules match."""
        policy = Policy(rules=[])
        engine = PolicyEngine(policy)

        decision = engine.evaluate("any_tool", {"any": "param"})

        assert decision.allowed
        assert decision.action == PolicyAction.ALLOW
        assert decision.matched_rule is None

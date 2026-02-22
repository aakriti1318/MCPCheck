"""
Unit tests for auth exposure detection rules.
"""

from __future__ import annotations

import pytest

from mcpcheck.domain.models import McpManifest, McpServer, Severity, ToolDefinition
from mcpcheck.rules.auth_exposure import (
    AuthExposureNotGitignored,
    AuthExposurePlaintextToken,
)


class TestAuthExposurePlaintextToken:
    """Tests for AUTH-001: Plaintext token detection."""

    @pytest.fixture
    def rule(self) -> AuthExposurePlaintextToken:
        return AuthExposurePlaintextToken()

    def test_detects_github_pat(self, rule: AuthExposurePlaintextToken) -> None:
        """Should detect GitHub Personal Access Tokens."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="github",
                    command="npx",
                    args=["-y", "@modelcontextprotocol/server-github"],
                    env={"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abc123def456ghi789jkl012mno345pqr678"},
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) >= 1
        assert findings[0].rule_id == "AUTH-001"
        assert findings[0].severity == Severity.CRITICAL
        assert "GitHub" in findings[0].title

    def test_detects_openai_key(self, rule: AuthExposurePlaintextToken) -> None:
        """Should detect OpenAI API keys."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="openai",
                    env={"OPENAI_API_KEY": "sk-1234567890abcdefghijklmnopqrstuvwxyz"},
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) >= 1
        assert "OpenAI" in findings[0].title

    def test_detects_anthropic_key(self, rule: AuthExposurePlaintextToken) -> None:
        """Should detect Anthropic API keys."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="claude",
                    env={"ANTHROPIC_API_KEY": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"},
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) >= 1
        assert "Anthropic" in findings[0].title

    def test_detects_aws_keys(self, rule: AuthExposurePlaintextToken) -> None:
        """Should detect AWS access keys."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="aws",
                    env={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) >= 1
        assert "AWS" in findings[0].title

    def test_detects_generic_api_key_env_name(
        self, rule: AuthExposurePlaintextToken
    ) -> None:
        """Should detect generic API keys based on env name."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="custom",
                    env={"MY_SERVICE_API_KEY": "abcdefghijklmnopqrstuvwxyz1234567890"},
                )
            ],
        )

        findings = rule.check(manifest)

        # Should flag as potential secret based on name pattern
        assert len(findings) >= 1

    def test_ignores_env_var_references(
        self, rule: AuthExposurePlaintextToken
    ) -> None:
        """Should not flag environment variable references."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="safe",
                    env={
                        "GITHUB_TOKEN": "${GITHUB_TOKEN}",
                        "API_KEY": "$API_KEY",
                    },
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) == 0

    def test_ignores_short_values(self, rule: AuthExposurePlaintextToken) -> None:
        """Should not flag short values that aren't real tokens."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="dev",
                    env={
                        "API_KEY": "test",  # Too short to be a real key
                        "SECRET": "dev",
                    },
                )
            ],
        )

        findings = rule.check(manifest)

        # Short values shouldn't be flagged
        assert len(findings) == 0

    def test_redacts_token_in_evidence(
        self, rule: AuthExposurePlaintextToken
    ) -> None:
        """Token values should be redacted in finding evidence."""
        manifest = McpManifest(
            source="test.json",
            servers=[
                McpServer(
                    name="github",
                    env={"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abc123def456ghi789jkl012mno345pqr678"},
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) >= 1
        # The full token should NOT appear in evidence
        evidence_str = str(findings[0].evidence)
        assert "ghp_abc123def456ghi789jkl012mno345pqr678" not in evidence_str


class TestAuthExposureNotGitignored:
    """Tests for AUTH-002: Missing gitignore detection."""

    @pytest.fixture
    def rule(self) -> AuthExposureNotGitignored:
        return AuthExposureNotGitignored()

    def test_flags_dotenv_with_secrets(
        self, rule: AuthExposureNotGitignored
    ) -> None:
        """Should flag .env files containing env vars."""
        manifest = McpManifest(
            source=".env",
            servers=[
                McpServer(
                    name="test",
                    env={"SOME_KEY": "value"},
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) >= 1
        assert ".gitignore" in findings[0].title.lower() or "gitignored" in findings[0].title.lower()

    def test_flags_cursor_mcp_with_secrets(
        self, rule: AuthExposureNotGitignored
    ) -> None:
        """Should flag .cursor/mcp.json with env vars."""
        manifest = McpManifest(
            source="/home/user/.cursor/mcp.json",
            servers=[
                McpServer(
                    name="github",
                    env={"TOKEN": "secret"},
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) >= 1

    def test_ignores_manifests_without_env(
        self, rule: AuthExposureNotGitignored
    ) -> None:
        """Should not flag manifests without environment variables."""
        manifest = McpManifest(
            source=".env",
            servers=[
                McpServer(
                    name="test",
                    command="test",
                    # No env vars
                )
            ],
        )

        findings = rule.check(manifest)

        assert len(findings) == 0

    def test_ignores_safe_paths(self, rule: AuthExposureNotGitignored) -> None:
        """Should not flag non-sensitive file paths."""
        manifest = McpManifest(
            source="/path/to/safe/mcp-config.json",
            servers=[
                McpServer(
                    name="test",
                    env={"KEY": "value"},
                )
            ],
        )

        findings = rule.check(manifest)

        # mcp-config.json isn't in the AUTH_PATHS list
        assert len(findings) == 0

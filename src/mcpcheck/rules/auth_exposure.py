"""
Authentication exposure detection rules.

Detects when sensitive credentials are exposed in MCP configurations,
such as plaintext tokens in env blocks or missing gitignore entries.

Rules:
- AUTH-001: Plaintext token in auth store
- AUTH-002: Token path not in .gitignore
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from mcpcheck.domain.models import Finding, Severity
from mcpcheck.rules.base import BaseRule

if TYPE_CHECKING:
    from mcpcheck.domain.models import McpManifest


class AuthExposurePlaintextToken(BaseRule):
    """
    AUTH-001: Detects plaintext tokens in manifest env blocks.

    API tokens and secrets should never be stored directly in manifest
    files — they should use environment variable references or secure stores.
    """

    rule_id = "AUTH-001"
    name = "Plaintext token in auth store"
    description = "Detects API tokens and secrets stored in plaintext"
    severity = Severity.CRITICAL
    owasp_id = None
    mitre_id = "CWE-312"
    cwe_id = "CWE-312"

    # Patterns for different token types (ordered by specificity - more specific first)
    TOKEN_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
        # GitHub tokens
        ("GitHub Personal Access Token", "ghp_", re.compile(r"ghp_[a-zA-Z0-9]{36}")),
        ("GitHub OAuth Token", "gho_", re.compile(r"gho_[a-zA-Z0-9]{36}")),
        ("GitHub App Token", "ghu_", re.compile(r"ghu_[a-zA-Z0-9]{36}")),
        ("GitHub Refresh Token", "ghr_", re.compile(r"ghr_[a-zA-Z0-9]{36}")),
        ("GitHub Fine-grained PAT", "github_pat_", re.compile(r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}")),
        # OpenAI (before AWS to prevent false match on sk- prefix)
        ("OpenAI API Key", "sk-", re.compile(r"sk-(?:proj-)?[a-zA-Z0-9]{32,}")),
        # Anthropic
        ("Anthropic API Key", "sk-ant-", re.compile(r"sk-ant-[a-zA-Z0-9-]{32,}")),
        # AWS
        ("AWS Access Key", "AKIA", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("AWS Secret Access Key", "aws_secret", re.compile(r"(?<![a-zA-Z0-9])[a-zA-Z0-9/+=]{40}(?![a-zA-Z0-9])")),
        # Slack
        ("Slack Bot Token", "xoxb-", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}")),
        ("Slack User Token", "xoxp-", re.compile(r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}")),
        # Stripe
        ("Stripe Secret Key", "sk_live_", re.compile(r"sk_live_[a-zA-Z0-9]{24,}")),
        ("Stripe Test Key", "sk_test_", re.compile(r"sk_test_[a-zA-Z0-9]{24,}")),
        # Generic patterns
        ("Generic API Key", "api_key=", re.compile(r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?")),
        ("Generic Secret", "secret=", re.compile(r"secret['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}['\"]?")),
        ("Bearer Token", "Bearer ", re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}")),
        ("Basic Auth", "Basic ", re.compile(r"Basic\s+[a-zA-Z0-9+/=]{20,}")),
    ]

    # Environment variable names that typically contain secrets
    SENSITIVE_ENV_NAMES = re.compile(
        r"(api[_-]?key|token|secret|password|credential|auth|bearer|"
        r"access[_-]?key|private[_-]?key|client[_-]?secret)",
        re.IGNORECASE,
    )

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        for server in manifest.servers:
            for env_name, env_value in server.env.items():
                # Check for known token patterns
                for token_name, token_prefix, pattern in self.TOKEN_PATTERNS:
                    if pattern.search(env_value):
                        findings.append(
                            self._create_finding(
                                title=f"{token_name} exposed in '{server.name}'",
                                detail=(
                                    f"Found a {token_name} stored in plaintext in the "
                                    f"environment variable '{env_name}' of server '{server.name}'. "
                                    f"This token will be exposed in version control and logs."
                                ),
                                remediation=(
                                    "Remove the plaintext token from the manifest. Instead:\n"
                                    "1. Use an environment variable reference: ${" + env_name + "}\n"
                                    "2. Use OS keychain: 'mcpcheck secure-auth migrate'\n"
                                    "3. Use a secrets manager (1Password, HashiCorp Vault, etc.)"
                                ),
                                evidence={
                                    "server": server.name,
                                    "env_name": env_name,
                                    "token_type": token_name,
                                    "token_prefix": token_prefix,
                                    # Redact the actual value for safety
                                    "value_preview": env_value[:4] + "..." + env_value[-4:] if len(env_value) > 10 else "[REDACTED]",
                                },
                                location=f"{server.name}.env.{env_name}",
                            )
                        )
                        break  # One finding per env var is enough

                # Check for sensitive env names with non-reference values
                if self.SENSITIVE_ENV_NAMES.search(env_name):
                    # If it doesn't look like an env var reference
                    if not env_value.startswith("$") and not env_value.startswith("%"):
                        # And it's long enough to be a real secret
                        if len(env_value) >= 16:
                            # And we haven't already flagged it
                            existing = [f for f in findings if f.evidence.get("env_name") == env_name]
                            if not existing:
                                findings.append(
                                    self._create_finding(
                                        title=f"Potential secret in '{env_name}'",
                                        detail=(
                                            f"Environment variable '{env_name}' in server "
                                            f"'{server.name}' has a sensitive name and contains "
                                            f"what appears to be a hardcoded secret value."
                                        ),
                                        remediation=(
                                            "Use an environment variable reference instead of "
                                            "hardcoding the value. Example: ${" + env_name + "}"
                                        ),
                                        evidence={
                                            "server": server.name,
                                            "env_name": env_name,
                                            "value_length": len(env_value),
                                        },
                                        location=f"{server.name}.env.{env_name}",
                                        severity=Severity.HIGH,
                                    )
                                )

        return findings


class AuthExposureNotGitignored(BaseRule):
    """
    AUTH-002: Detects token files not in .gitignore.

    Auth store files should be excluded from version control.
    This rule checks the manifest source path against common patterns.
    """

    rule_id = "AUTH-002"
    name = "Token path not in .gitignore"
    description = "Detects auth files that may be committed to git"
    severity = Severity.HIGH
    owasp_id = None
    mitre_id = "CWE-312"
    cwe_id = "CWE-312"

    # Paths that commonly contain auth data
    AUTH_PATHS = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        "secrets.json",
        "credentials.json",
        "auth.json",
        ".mcp-auth",
        ".cursor/mcp.json",  # If it contains tokens, should be gitignored
        "claude_desktop_config.json",
    ]

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        # Check if the manifest source is in a sensitive location
        source_lower = manifest.source.lower()

        for auth_path in self.AUTH_PATHS:
            if auth_path.lower() in source_lower:
                # Check if the manifest contains any env vars (potential secrets)
                has_env_vars = any(
                    server.env for server in manifest.servers
                )

                if has_env_vars:
                    findings.append(
                        self._create_finding(
                            title=f"Auth file may not be gitignored: {manifest.source}",
                            detail=(
                                f"The manifest '{manifest.source}' contains environment "
                                f"variables and is in a location that commonly contains secrets. "
                                f"Ensure this file is excluded from version control."
                            ),
                            remediation=(
                                f"Add '{auth_path}' to your .gitignore file. "
                                f"If already committed, use 'git rm --cached' to remove from history, "
                                f"then rotate any exposed credentials."
                            ),
                            evidence={
                                "source": manifest.source,
                                "auth_path_pattern": auth_path,
                                "servers_with_env": [
                                    s.name for s in manifest.servers if s.env
                                ],
                            },
                            location=manifest.source,
                        )
                    )
                    break

        return findings

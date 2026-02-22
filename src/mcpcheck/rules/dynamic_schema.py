"""
Dynamic schema detection rules.

Detects "rug pull" vulnerabilities where tool definitions are loaded
dynamically at runtime, bypassing static security review.

Rules:
- DYNAMIC-001: Remote tool definition loading
- DYNAMIC-002: Schema hash not pinned
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from mcpcheck.domain.models import Finding, Severity
from mcpcheck.rules.base import BaseRule

if TYPE_CHECKING:
    from mcpcheck.domain.models import McpManifest


class DynamicSchemaRemoteLoading(BaseRule):
    """
    DYNAMIC-001: Detects remote tool definition loading.

    When tool schemas are fetched from URLs at runtime, the definitions
    can change after security review, enabling "rug pull" attacks.
    """

    rule_id = "DYNAMIC-001"
    name = "Remote tool definition loading"
    description = "Detects tools loaded from remote URLs which can change after review"
    severity = Severity.CRITICAL
    owasp_id = "AGENT-05"
    mitre_id = "AML.T0010"

    # Patterns indicating remote schema loading
    URL_PATTERNS = [
        r"https?://[^\s\"']+",  # HTTP/HTTPS URLs
        r"wss?://[^\s\"']+",  # WebSocket URLs
    ]

    # Fields that indicate dynamic loading
    DYNAMIC_FIELDS = [
        "schema_url",
        "schemaUrl",
        "schema_uri",
        "schemaUri",
        "definition_url",
        "definitionUrl",
        "tools_url",
        "toolsUrl",
        "remote_schema",
        "remoteSchema",
        "fetch_schema",
        "fetchSchema",
    ]

    def __init__(self) -> None:
        self._url_pattern = re.compile("|".join(self.URL_PATTERNS), re.IGNORECASE)

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        # Check server-level configurations
        for server in manifest.servers:
            # Check for URL-based server definitions
            if server.url:
                findings.append(
                    self._create_finding(
                        title=f"Remote MCP server: {server.name}",
                        detail=(
                            f"Server '{server.name}' connects to a remote URL: {server.url}. "
                            f"Remote servers can change their tool definitions at any time, "
                            f"bypassing any prior security review."
                        ),
                        remediation=(
                            "Pin the server to a specific version or commit hash. "
                            "Use mcpcheck's schema pinning feature to detect changes. "
                            "Consider running the server locally instead."
                        ),
                        evidence={
                            "server": server.name,
                            "url": server.url,
                        },
                        location=f"{server.name}.url",
                    )
                )

            # Check server metadata for dynamic loading indicators
            for field in self.DYNAMIC_FIELDS:
                if field in server.metadata:
                    value = server.metadata[field]
                    findings.append(
                        self._create_finding(
                            title=f"Dynamic schema loading in {server.name}",
                            detail=(
                                f"Server '{server.name}' has a '{field}' configuration "
                                f"that suggests schemas are loaded dynamically: {value}"
                            ),
                            remediation=(
                                "Remove dynamic schema loading. Include tool definitions "
                                "directly in the manifest or pin to a content hash."
                            ),
                            evidence={
                                "server": server.name,
                                "field": field,
                                "value": str(value)[:200],
                            },
                            location=f"{server.name}.{field}",
                        )
                    )

            # Check for URLs in command arguments (fetching tools at runtime)
            for i, arg in enumerate(server.args):
                if self._url_pattern.search(arg):
                    # Some URLs in args are fine (like npm package sources)
                    # Flag only if it looks like a schema/tool definition URL
                    if any(
                        keyword in arg.lower()
                        for keyword in ["schema", "tool", "definition", "config", "manifest"]
                    ):
                        findings.append(
                            self._create_finding(
                                title=f"URL in server arguments: {server.name}",
                                detail=(
                                    f"Server '{server.name}' has a URL in its arguments "
                                    f"that may load tool definitions dynamically: {arg}"
                                ),
                                remediation=(
                                    "If this URL provides tool definitions, pin to a "
                                    "specific version or use local definitions instead."
                                ),
                                evidence={
                                    "server": server.name,
                                    "arg_index": i,
                                    "arg": arg,
                                },
                                location=f"{server.name}.args[{i}]",
                                severity=Severity.HIGH,
                            )
                        )

        return findings


class DynamicSchemaUnpinnedHash(BaseRule):
    """
    DYNAMIC-002: Detects when schema hashes are not pinned.

    Even with remote loading, pinning to a content hash prevents
    unexpected changes. This rule flags missing hash pins.
    """

    rule_id = "DYNAMIC-002"
    name = "Schema hash not pinned"
    description = "Detects remote schemas without content hash verification"
    severity = Severity.HIGH
    owasp_id = "AGENT-05"
    mitre_id = "AML.T0010"

    # Fields that would indicate hash pinning
    HASH_FIELDS = [
        "schema_hash",
        "schemaHash",
        "content_hash",
        "contentHash",
        "sha256",
        "sha384",
        "sha512",
        "integrity",
        "checksum",
        "digest",
    ]

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        for server in manifest.servers:
            # Only check servers that use remote resources
            has_remote = (
                server.url is not None
                or any("http" in arg.lower() for arg in server.args)
            )

            if not has_remote:
                continue

            # Check if any hash pinning is configured
            has_hash = any(
                field in server.metadata for field in self.HASH_FIELDS
            )

            if not has_hash:
                findings.append(
                    self._create_finding(
                        title=f"No schema hash pinning for {server.name}",
                        detail=(
                            f"Server '{server.name}' uses remote resources but does not "
                            f"pin to a content hash. This means tool definitions could "
                            f"change without detection."
                        ),
                        remediation=(
                            "Add a 'schema_hash' field with the SHA-256 hash of the "
                            "expected tool definitions. Use 'mcpcheck pin' to generate "
                            "the hash automatically."
                        ),
                        evidence={
                            "server": server.name,
                            "url": server.url,
                            "has_remote": True,
                            "has_hash": False,
                        },
                        location=f"{server.name}",
                    )
                )

        return findings

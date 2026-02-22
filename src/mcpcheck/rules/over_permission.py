"""
Over-permission detection rules.

Detects when MCP tool configurations grant excessive capabilities
that create data exfiltration or RCE risks.

Rules:
- OVERPERM-001: Dangerous tool combination (exfil path)
- OVERPERM-002: Unrestricted filesystem write + exec
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from mcpcheck.domain.models import Finding, Severity
from mcpcheck.rules.base import BaseRule

if TYPE_CHECKING:
    from mcpcheck.domain.models import McpManifest


class OverPermissionDangerousCombo(BaseRule):
    """
    OVERPERM-001: Detects dangerous tool combinations.

    Some tools are safe individually but create attack paths when combined.
    For example: read_file + send_email = data exfiltration path.
    """

    rule_id = "OVERPERM-001"
    name = "Dangerous tool combination (exfil path)"
    description = "Detects tool combinations that create data exfiltration paths"
    severity = Severity.CRITICAL
    owasp_id = "LLM08"
    mitre_id = "AML.T0048"

    # Dangerous combinations: (read capability, exfil capability)
    DANGEROUS_COMBOS = [
        # File read + network send
        (
            ["read_file", "read", "get_file", "cat", "file_read", "read_content"],
            ["send_email", "email", "http_post", "post", "send_http", "webhook", "send_message", "slack_send"],
        ),
        # Database read + network send
        (
            ["query", "sql", "database", "db_query", "execute_query", "select"],
            ["send_email", "email", "http_post", "post", "send_http", "webhook"],
        ),
        # Secret read + any external communication
        (
            ["get_secret", "read_secret", "get_env", "get_password", "get_token", "vault"],
            ["send_email", "http_post", "post", "send", "webhook", "slack", "discord"],
        ),
        # Shell + network
        (
            ["execute", "exec", "shell", "bash", "run_command", "system", "cmd"],
            ["send_email", "http", "curl", "wget", "fetch"],
        ),
    ]

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        # Collect all tool names across all servers
        all_tools: dict[str, str] = {}  # tool_name -> server_name
        for server in manifest.servers:
            for tool in server.tools:
                all_tools[tool.name.lower()] = server.name

        # Check for dangerous combinations
        for read_tools, exfil_tools in self.DANGEROUS_COMBOS:
            found_read = self._find_matching_tools(all_tools, read_tools)
            found_exfil = self._find_matching_tools(all_tools, exfil_tools)

            if found_read and found_exfil:
                findings.append(
                    self._create_finding(
                        title="Dangerous tool combination creates exfiltration path",
                        detail=(
                            f"The combination of data access tools ({', '.join(found_read)}) "
                            f"with external communication tools ({', '.join(found_exfil)}) "
                            f"creates a potential data exfiltration path. An attacker could "
                            f"use prompt injection to read sensitive data and send it externally."
                        ),
                        remediation=(
                            "Either remove one category of tools, or implement strict policy "
                            "rules that prevent data flow from read operations to send operations. "
                            "Use mcpcheck policy to enforce constraints."
                        ),
                        evidence={
                            "read_tools": list(found_read),
                            "exfil_tools": list(found_exfil),
                            "read_servers": [all_tools[t] for t in found_read],
                            "exfil_servers": [all_tools[t] for t in found_exfil],
                        },
                        location="manifest.tools",
                    )
                )

        return findings

    def _find_matching_tools(
        self, all_tools: dict[str, str], patterns: list[str]
    ) -> set[str]:
        """Find tools that match any of the patterns."""
        matches: set[str] = set()
        for tool_name in all_tools:
            for pattern in patterns:
                if pattern in tool_name or re.search(pattern, tool_name, re.IGNORECASE):
                    matches.add(tool_name)
        return matches


class OverPermissionUnrestrictedWrite(BaseRule):
    """
    OVERPERM-002: Detects unrestricted filesystem write + execute combinations.

    Having both write and execute capabilities without restrictions
    enables arbitrary code execution attacks.
    """

    rule_id = "OVERPERM-002"
    name = "Unrestricted filesystem write + exec"
    description = "Detects write + execute capabilities that enable RCE"
    severity = Severity.CRITICAL
    owasp_id = "LLM08"
    mitre_id = "AML.T0048"

    WRITE_PATTERNS = [
        "write_file",
        "write",
        "save_file",
        "create_file",
        "file_write",
        "put_file",
        "upload",
        "save",
    ]

    EXEC_PATTERNS = [
        "execute",
        "exec",
        "run",
        "shell",
        "bash",
        "cmd",
        "system",
        "eval",
        "spawn",
        "subprocess",
        "run_command",
    ]

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        # Collect all tool names
        all_tools: dict[str, str] = {}
        for server in manifest.servers:
            for tool in server.tools:
                all_tools[tool.name.lower()] = server.name

        # Find write and exec tools
        write_tools = self._find_matching_tools(all_tools, self.WRITE_PATTERNS)
        exec_tools = self._find_matching_tools(all_tools, self.EXEC_PATTERNS)

        if write_tools and exec_tools:
            findings.append(
                self._create_finding(
                    title="Write + Execute combination enables RCE",
                    detail=(
                        f"Found filesystem write tools ({', '.join(write_tools)}) combined "
                        f"with code execution tools ({', '.join(exec_tools)}). This combination "
                        f"allows an attacker to write malicious code and execute it."
                    ),
                    remediation=(
                        "Restrict write operations to safe directories (e.g., /tmp) using "
                        "policy rules. Consider removing execution tools or implementing "
                        "strict sandboxing."
                    ),
                    evidence={
                        "write_tools": list(write_tools),
                        "exec_tools": list(exec_tools),
                    },
                    location="manifest.tools",
                )
            )

        # Also flag standalone unrestricted exec tools
        for tool_name in exec_tools:
            server_name = all_tools[tool_name]
            findings.append(
                self._create_finding(
                    title=f"Unrestricted execution tool: {tool_name}",
                    detail=(
                        f"The tool '{tool_name}' in server '{server_name}' provides "
                        f"code execution capabilities. Without parameter restrictions, "
                        f"this could be exploited for arbitrary command execution."
                    ),
                    remediation=(
                        "Add parameter validation to restrict which commands can be executed. "
                        "Use policy rules to allowlist specific commands only."
                    ),
                    evidence={
                        "tool": tool_name,
                        "server": server_name,
                    },
                    location=f"{server_name}.tools.{tool_name}",
                    severity=Severity.HIGH,
                )
            )

        return findings

    def _find_matching_tools(
        self, all_tools: dict[str, str], patterns: list[str]
    ) -> set[str]:
        matches: set[str] = set()
        for tool_name in all_tools:
            for pattern in patterns:
                if pattern in tool_name:
                    matches.add(tool_name)
        return matches

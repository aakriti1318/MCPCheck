"""
Domain models for MCPCheck.

This module contains all core data structures used throughout the library.
All models are Pydantic v2 for validation, serialization, and JSON Schema generation.

The domain layer has ZERO external dependencies beyond Pydantic (which is structural,
not infrastructural).
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    """Severity level for security findings, aligned with CVSS v3.1 qualitative ratings."""

    CRITICAL = "CRITICAL"  # CVSS 9.0-10.0: Immediate action required
    HIGH = "HIGH"  # CVSS 7.0-8.9: Should be fixed soon
    MEDIUM = "MEDIUM"  # CVSS 4.0-6.9: Should be fixed
    LOW = "LOW"  # CVSS 0.1-3.9: Consider fixing
    INFO = "INFO"  # Informational, no security impact

    def _get_order(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._get_order() < other._get_order()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._get_order() <= other._get_order()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._get_order() > other._get_order()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._get_order() >= other._get_order()


class Finding(BaseModel):
    """
    A security finding detected by a rule.

    Findings are immutable, hashable, and map to OWASP/MITRE identifiers
    for enterprise compliance reporting.
    """

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(
        ...,
        description="Unique rule identifier, e.g., TOOL-POISON-001",
        pattern=r"^[A-Z]+-[A-Z]+-\d{3}$|^[A-Z]+-\d{3}$",
    )
    severity: Severity = Field(..., description="Severity level of the finding")
    title: str = Field(..., description="Human-readable title", min_length=1, max_length=200)
    detail: str = Field(..., description="Detailed explanation of the issue")
    remediation: str = Field(..., description="How to fix the issue")
    owasp_id: str | None = Field(
        default=None, description="OWASP Agentic Top 10 ID, e.g., LLM01-2025"
    )
    mitre_id: str | None = Field(
        default=None, description="MITRE ATLAS technique ID, e.g., AML.T0051.002"
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Evidence data for the finding"
    )
    location: str | None = Field(
        default=None, description="Location in the manifest where the issue was found"
    )

    def __hash__(self) -> int:
        return hash((self.rule_id, self.title, self.location))


class ToolParameter(BaseModel):
    """A parameter definition for an MCP tool."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Parameter name")
    type: str = Field(default="string", description="Parameter type")
    description: str | None = Field(default=None, description="Parameter description")
    required: bool = Field(default=False, description="Whether the parameter is required")
    default: Any = Field(default=None, description="Default value")


class ToolDefinition(BaseModel):
    """
    Definition of an MCP tool exposed by a server.

    This is the primary target for prompt injection detection rules.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Tool name", min_length=1)
    description: str | None = Field(default=None, description="Tool description")
    parameters: list[ToolParameter] = Field(
        default_factory=list, description="Tool parameters"
    )
    input_schema: dict[str, Any] | None = Field(
        default=None, description="JSON Schema for tool input"
    )
    annotations: dict[str, Any] = Field(
        default_factory=dict, description="Additional tool annotations"
    )

    @property
    def has_dangerous_capabilities(self) -> bool:
        """Check if the tool name suggests dangerous capabilities."""
        dangerous_patterns = [
            r"exec(ute)?",
            r"run",
            r"shell",
            r"bash",
            r"cmd",
            r"system",
            r"eval",
            r"write",
            r"delete",
            r"remove",
            r"send",
            r"email",
            r"http",
            r"request",
        ]
        name_lower = self.name.lower()
        return any(re.search(pattern, name_lower) for pattern in dangerous_patterns)


class McpServer(BaseModel):
    """
    Configuration for an MCP server.

    Represents a single server entry in an MCP manifest, which can be
    a local command or a remote URL.
    """

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Server name/identifier")
    command: str | None = Field(default=None, description="Command to start the server")
    args: list[str] = Field(default_factory=list, description="Command arguments")
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables")
    url: str | None = Field(default=None, description="Remote server URL")
    tools: list[ToolDefinition] = Field(
        default_factory=list, description="Tools exposed by this server"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional server metadata"
    )

    @field_validator("env", mode="before")
    @classmethod
    def validate_env(cls, v: dict[str, Any] | None) -> dict[str, str]:
        if v is None:
            return {}
        return {str(k): str(val) for k, val in v.items()}


class McpManifest(BaseModel):
    """
    Parsed MCP manifest file.

    This is the top-level structure representing a complete MCP configuration,
    such as .cursor/mcp.json or claude_desktop_config.json.
    """

    model_config = ConfigDict(frozen=True)

    source: str = Field(..., description="Path or URL where the manifest was loaded from")
    servers: list[McpServer] = Field(
        default_factory=list, description="MCP servers defined in the manifest"
    )
    raw_content: dict[str, Any] = Field(
        default_factory=dict, description="Original parsed JSON content"
    )
    parsed_at: datetime = Field(
        default_factory=datetime.utcnow, description="When the manifest was parsed"
    )

    @property
    def all_tools(self) -> list[ToolDefinition]:
        """Get all tools from all servers."""
        return [tool for server in self.servers for tool in server.tools]

    @property
    def all_env_vars(self) -> dict[str, tuple[str, str]]:
        """Get all environment variables with their server names."""
        result: dict[str, tuple[str, str]] = {}
        for server in self.servers:
            for key, value in server.env.items():
                result[f"{server.name}.{key}"] = (server.name, value)
        return result

    @property
    def server_names(self) -> list[str]:
        """Get all server names."""
        return [server.name for server in self.servers]


class RuleMetadata(BaseModel):
    """Metadata about a detection rule."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(..., description="Unique rule identifier")
    name: str = Field(..., description="Human-readable rule name")
    description: str = Field(..., description="What the rule detects")
    severity: Severity = Field(..., description="Default severity")
    owasp_id: str | None = Field(default=None, description="OWASP mapping")
    mitre_id: str | None = Field(default=None, description="MITRE ATLAS mapping")
    cwe_id: str | None = Field(default=None, description="CWE mapping")
    phase: str = Field(default="v0.1", description="Release phase")
    enabled: bool = Field(default=True, description="Whether the rule is enabled by default")

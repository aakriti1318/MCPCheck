"""
Domain layer for MCPCheck.

Contains all core data structures with zero external dependencies
beyond Pydantic.
"""

from mcpcheck.domain.models import (
    Finding,
    McpManifest,
    McpServer,
    RuleMetadata,
    Severity,
    ToolDefinition,
    ToolParameter,
)
from mcpcheck.domain.report import ScanReport, ScanSummary
from mcpcheck.domain.exceptions import (
    McpGuardError,
    ManifestParseError,
    RuleError,
    PolicyError,
    ConfigError,
)

__all__ = [
    # Models
    "Finding",
    "McpManifest",
    "McpServer",
    "RuleMetadata",
    "Severity",
    "ToolDefinition",
    "ToolParameter",
    # Reports
    "ScanReport",
    "ScanSummary",
    # Exceptions
    "McpGuardError",
    "ManifestParseError",
    "RuleError",
    "PolicyError",
    "ConfigError",
]

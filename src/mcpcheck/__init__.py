"""
MCPCheck — Security Scanner for Model Context Protocol (MCP)

A production-grade Python library for auditing, scanning, and monitoring
MCP servers and agent tool configurations against OWASP Agentic Top 10
and MITRE ATLAS.

Usage:
    # CLI
    $ mcpcheck scan ./mcp-config.json

    # Python API
    from mcpcheck import scan_manifest, ScanReport
    
    report = scan_manifest("./mcp-config.json")
    print(report.summary)

    # Runtime interceptor
    from mcpcheck import intercept
    
    client = intercept(mcp_client, policy="./policy.yaml")
"""

from mcpcheck.domain.models import (
    Finding,
    McpManifest,
    McpServer,
    Severity,
    ToolDefinition,
)
from mcpcheck.domain.report import ScanReport, ScanSummary
from mcpcheck.engine.scanner import RuleEngine, scan_manifest

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Domain models
    "Finding",
    "McpManifest",
    "McpServer",
    "Severity",
    "ToolDefinition",
    # Reports
    "ScanReport",
    "ScanSummary",
    # Engine
    "RuleEngine",
    "scan_manifest",
]

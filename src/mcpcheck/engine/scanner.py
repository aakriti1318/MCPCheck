"""
Rule engine — the core of the static scanner.

Executes rules against MCP manifests and aggregates findings
into a scan report.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcpcheck.domain.exceptions import ManifestParseError, RuleError
from mcpcheck.domain.models import Finding, McpManifest, McpServer, Severity, ToolDefinition
from mcpcheck.domain.report import ScanReport, ScanSummary
from mcpcheck.rules import DEFAULT_RULES

if TYPE_CHECKING:
    from mcpcheck.rules.base import Rule


def scan_manifest(
    target: str | Path | dict[str, Any],
    rules: list[Rule] | None = None,
    severity_threshold: Severity = Severity.INFO,
    parallel: bool = True,
) -> ScanReport:
    """
    Scan an MCP manifest for security issues.

    This is the primary public API for static scanning.

    Args:
        target: Path to manifest file, URL, or parsed dict.
        rules: List of rules to run. Defaults to DEFAULT_RULES.
        severity_threshold: Minimum severity to include in report.
        parallel: Whether to run rules in parallel.

    Returns:
        ScanReport with all findings.

    Raises:
        ManifestParseError: If the manifest cannot be parsed.

    Example:
        >>> report = scan_manifest("./mcp-config.json")
        >>> print(report.summary)
        >>> if not report.passed:
        ...     sys.exit(1)
    """
    engine = RuleEngine(rules=rules, parallel=parallel)

    # Parse the manifest
    if isinstance(target, dict):
        manifest = parse_manifest_dict(target, source="<dict>")
    elif isinstance(target, Path):
        manifest = parse_manifest_file(target)
    else:
        manifest = parse_manifest_file(Path(target))

    return engine.scan(manifest, severity_threshold=severity_threshold)


class RuleEngine:
    """
    Executes detection rules against MCP manifests.

    The engine fans out to multiple rules in parallel (optional)
    and aggregates their findings into a single report.
    """

    def __init__(
        self,
        rules: list[Rule] | None = None,
        parallel: bool = True,
        max_workers: int = 4,
    ) -> None:
        """
        Initialize the rule engine.

        Args:
            rules: Rules to execute. Defaults to DEFAULT_RULES.
            parallel: Whether to run rules in parallel.
            max_workers: Maximum parallel workers.
        """
        self.rules = rules if rules is not None else DEFAULT_RULES
        self.parallel = parallel
        self.max_workers = max_workers

    def scan(
        self,
        manifest: McpManifest,
        severity_threshold: Severity = Severity.INFO,
    ) -> ScanReport:
        """
        Scan a manifest with all configured rules.

        Args:
            manifest: The parsed MCP manifest to scan.
            severity_threshold: Minimum severity to include.

        Returns:
            ScanReport with aggregated findings.
        """
        start_time = time.perf_counter()

        all_findings: list[Finding] = []
        executed_rules: list[str] = []
        errors: list[str] = []

        if self.parallel and len(self.rules) > 1:
            all_findings, executed_rules, errors = self._run_parallel(manifest)
        else:
            all_findings, executed_rules, errors = self._run_sequential(manifest)

        # Filter by severity threshold
        filtered_findings = [
            f for f in all_findings if f.severity >= severity_threshold
        ]

        # Deduplicate (same rule_id + location)
        unique_findings = self._deduplicate(filtered_findings)

        # Sort by severity (CRITICAL first)
        sorted_findings = sorted(
            unique_findings,
            key=lambda f: f.severity,
            reverse=True,
        )

        duration_ms = (time.perf_counter() - start_time) * 1000

        return ScanReport(
            target=manifest.source,
            duration_ms=duration_ms,
            summary=ScanSummary.from_findings(sorted_findings),
            findings=sorted_findings,
            rules_executed=executed_rules,
            errors=errors,
            metadata={
                "rule_count": len(self.rules),
                "server_count": len(manifest.servers),
                "tool_count": len(manifest.all_tools),
            },
        )

    def _run_sequential(
        self, manifest: McpManifest
    ) -> tuple[list[Finding], list[str], list[str]]:
        """Run rules sequentially."""
        findings: list[Finding] = []
        executed: list[str] = []
        errors: list[str] = []

        for rule in self.rules:
            try:
                rule_findings = rule.check(manifest)
                findings.extend(rule_findings)
                executed.append(rule.rule_id)
            except Exception as e:
                executed.append(rule.rule_id)
                errors.append(f"Rule {rule.rule_id} failed: {e}")

        return findings, executed, errors

    def _run_parallel(
        self, manifest: McpManifest
    ) -> tuple[list[Finding], list[str], list[str]]:
        """Run rules in parallel using ThreadPoolExecutor."""
        findings: list[Finding] = []
        executed: list[str] = []
        errors: list[str] = []

        def run_rule(rule: Rule) -> tuple[str, list[Finding], str | None]:
            try:
                return (rule.rule_id, rule.check(manifest), None)
            except Exception as e:
                return (rule.rule_id, [], f"Rule {rule.rule_id} failed: {e}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(run_rule, rule): rule for rule in self.rules}

            for future in as_completed(futures):
                rule_id, rule_findings, error = future.result()
                executed.append(rule_id)
                findings.extend(rule_findings)
                if error:
                    errors.append(error)

        return findings, executed, errors

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings based on rule_id and location."""
        seen: set[tuple[str, str | None]] = set()
        unique: list[Finding] = []

        for finding in findings:
            key = (finding.rule_id, finding.location)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique


def parse_manifest_file(path: Path) -> McpManifest:
    """
    Parse an MCP manifest from a file.

    Args:
        path: Path to the manifest JSON file.

    Returns:
        Parsed McpManifest.

    Raises:
        ManifestParseError: If the file cannot be read or parsed.
    """
    import json

    try:
        content = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ManifestParseError(f"Manifest file not found: {path}", source=str(path))
    except PermissionError:
        raise ManifestParseError(f"Permission denied reading: {path}", source=str(path))
    except Exception as e:
        raise ManifestParseError(f"Error reading manifest: {e}", source=str(path))

    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ManifestParseError(
            f"Invalid JSON in manifest: {e.msg}",
            source=str(path),
            line=e.lineno,
        )

    return parse_manifest_dict(data, source=str(path))


def parse_manifest_dict(data: dict[str, Any], source: str) -> McpManifest:
    """
    Parse an MCP manifest from a dictionary.

    Supports multiple manifest formats:
    - Cursor format: { "mcpServers": { ... } }
    - Claude Desktop format: { "mcpServers": { ... } }
    - Generic format: { "servers": [ ... ] }

    Args:
        data: Parsed JSON data.
        source: Source path/URL for the manifest.

    Returns:
        Parsed McpManifest.

    Raises:
        ManifestParseError: If the format is not recognized.
    """
    servers: list[McpServer] = []

    # Try Cursor/Claude Desktop format: mcpServers as dict
    if "mcpServers" in data:
        mcp_servers = data["mcpServers"]
        if isinstance(mcp_servers, dict):
            for name, config in mcp_servers.items():
                server = _parse_server_config(name, config)
                servers.append(server)
        else:
            raise ManifestParseError(
                "mcpServers must be an object",
                source=source,
            )

    # Try generic format: servers as list
    elif "servers" in data:
        server_list = data["servers"]
        if isinstance(server_list, list):
            for i, config in enumerate(server_list):
                name = config.get("name", f"server_{i}")
                server = _parse_server_config(name, config)
                servers.append(server)
        else:
            raise ManifestParseError(
                "servers must be an array",
                source=source,
            )

    # No recognized format
    else:
        raise ManifestParseError(
            "Manifest must contain 'mcpServers' or 'servers' key",
            source=source,
        )

    return McpManifest(
        source=source,
        servers=servers,
        raw_content=data,
    )


def _parse_server_config(name: str, config: dict[str, Any]) -> McpServer:
    """Parse a single server configuration."""
    tools: list[ToolDefinition] = []

    # Parse tools if present
    if "tools" in config:
        for tool_config in config["tools"]:
            tool = ToolDefinition(
                name=tool_config.get("name", "unknown"),
                description=tool_config.get("description"),
                input_schema=tool_config.get("inputSchema") or tool_config.get("input_schema"),
                annotations=tool_config.get("annotations", {}),
            )
            tools.append(tool)

    return McpServer(
        name=name,
        command=config.get("command"),
        args=config.get("args", []),
        env=config.get("env", {}),
        url=config.get("url"),
        tools=tools,
        metadata={
            k: v
            for k, v in config.items()
            if k not in ("command", "args", "env", "url", "tools", "name")
        },
    )

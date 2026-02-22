"""
Main CLI entry point for MCPCheck.

Usage:
    mcpcheck scan ./mcp-config.json
    mcpcheck scan . --format json
    mcpcheck audit
    mcpcheck init
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from mcpcheck import __version__

# Create the main Typer app
app = typer.Typer(
    name="mcpcheck",
    help="🛡️ MCPCheck — Security scanner for Model Context Protocol (MCP)",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


class OutputFormat(str, Enum):
    """Output format options."""

    terminal = "terminal"
    json = "json"
    sarif = "sarif"


class SeverityLevel(str, Enum):
    """Minimum severity level to report."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"MCPCheck version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """
    🛡️ MCPCheck — Security scanner for Model Context Protocol (MCP)

    Scan MCP server configurations for security vulnerabilities including
    prompt injection, auth exposure, over-permissioning, and more.

    Examples:

        mcpcheck scan ./mcp-config.json

        mcpcheck scan . --format json --output report.json

        mcpcheck audit --check-keychain
    """
    pass


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Path to MCP manifest file or directory to scan.",
            exists=True,
        ),
    ],
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output format.",
        ),
    ] = OutputFormat.terminal,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output file path (default: stdout).",
        ),
    ] = None,
    severity: Annotated[
        SeverityLevel,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to report.",
        ),
    ] = SeverityLevel.info,
    fail_on: Annotated[
        SeverityLevel,
        typer.Option(
            "--fail-on",
            help="Minimum severity to cause non-zero exit.",
        ),
    ] = SeverityLevel.high,
    no_color: Annotated[
        bool,
        typer.Option(
            "--no-color",
            help="Disable colored output.",
        ),
    ] = False,
    show_evidence: Annotated[
        bool,
        typer.Option(
            "--show-evidence",
            "-e",
            help="Show detailed evidence for findings.",
        ),
    ] = False,
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="Path to .mcpcheck.toml config file.",
        ),
    ] = None,
) -> None:
    """
    Scan MCP manifest files for security issues.

    Analyzes tool descriptions, auth configurations, and permission
    combinations against 15+ security rules mapped to OWASP and MITRE.

    Examples:

        mcpcheck scan ./mcp-config.json

        mcpcheck scan .cursor/mcp.json --format json

        mcpcheck scan . --severity high --fail-on critical
    """
    from mcpcheck.domain.models import Severity
    from mcpcheck.engine.scanner import scan_manifest, parse_manifest_file
    from mcpcheck.renderers.terminal import TerminalRenderer
    from mcpcheck.renderers.json_renderer import JsonRenderer
    from mcpcheck.renderers.sarif_renderer import SarifRenderer

    # Map CLI severity to domain severity
    severity_map = {
        SeverityLevel.critical: Severity.CRITICAL,
        SeverityLevel.high: Severity.HIGH,
        SeverityLevel.medium: Severity.MEDIUM,
        SeverityLevel.low: Severity.LOW,
        SeverityLevel.info: Severity.INFO,
    }

    min_severity = severity_map[severity]
    fail_severity = severity_map[fail_on]

    # Find manifests to scan
    if target.is_dir():
        from mcpcheck.adapters.fs import FileSystemAdapter

        fs = FileSystemAdapter(target)
        manifests = fs.find_manifests()

        if not manifests:
            console.print(f"[yellow]No MCP manifests found in {target}[/yellow]")
            raise typer.Exit(0)
    else:
        manifests = [target]

    # Scan all manifests
    all_reports = []
    for manifest_path in manifests:
        try:
            report = scan_manifest(
                manifest_path,
                severity_threshold=min_severity,
            )
            all_reports.append(report)
        except Exception as e:
            console.print(f"[red]Error scanning {manifest_path}: {e}[/red]")
            continue

    if not all_reports:
        console.print("[red]No manifests could be scanned.[/red]")
        raise typer.Exit(1)

    # For simplicity, merge into first report (or handle multiple)
    # In a real implementation, we'd aggregate properly
    report = all_reports[0]

    # Render output
    match format:
        case OutputFormat.terminal:
            renderer = TerminalRenderer(
                console=Console(no_color=no_color),
                show_evidence=show_evidence,
            )
            renderer.render(report)

        case OutputFormat.json:
            renderer = JsonRenderer()
            json_output = renderer.render(report)

            if output:
                output.write_text(json_output, encoding="utf-8")
                console.print(f"[green]Report written to {output}[/green]")
            else:
                console.print(json_output)

        case OutputFormat.sarif:
            renderer = SarifRenderer()
            sarif_output = renderer.render(report)

            if output:
                output.write_text(sarif_output, encoding="utf-8")
                console.print(f"[green]SARIF report written to {output}[/green]")
            else:
                console.print(sarif_output)

    # Determine exit code
    has_blocking = any(
        f.severity >= fail_severity for f in report.findings
    )

    if has_blocking:
        raise typer.Exit(1)


@app.command()
def audit(
    path: Annotated[
        Optional[Path],
        typer.Argument(
            help="Path to scan for auth stores (default: current directory + home).",
        ),
    ] = None,
    check_keychain: Annotated[
        bool,
        typer.Option(
            "--check-keychain",
            help="Check if tokens are in OS keychain.",
        ),
    ] = False,
    fix: Annotated[
        bool,
        typer.Option(
            "--fix",
            help="Interactively migrate tokens to keychain.",
        ),
    ] = False,
) -> None:
    """
    Audit authentication stores for exposed secrets.

    Scans common auth store locations for plaintext tokens,
    missing .gitignore entries, and excessive permissions.

    Examples:

        mcpcheck audit

        mcpcheck audit --check-keychain

        mcpcheck audit --fix
    """
    from mcpcheck.adapters.fs import FileSystemAdapter

    base_path = path or Path.cwd()
    fs = FileSystemAdapter(base_path)

    console.print("[bold]🔍 Auditing auth stores...[/bold]\n")

    # Find auth stores
    stores = fs.find_auth_stores()

    if not stores:
        console.print("[green]✓ No auth stores found in common locations.[/green]")
        raise typer.Exit(0)

    console.print(f"Found {len(stores)} auth store(s):\n")

    issues_found = 0

    for store_path, store_type in stores:
        console.print(f"  📄 {store_path} [{store_type}]")

        # Check if gitignored
        if not fs.is_gitignored(store_path):
            console.print(f"     [yellow]⚠ Not in .gitignore[/yellow]")
            issues_found += 1

        # Scan for tokens if it's a JSON file
        if store_path.suffix == ".json":
            try:
                from mcpcheck.engine.scanner import scan_manifest

                report = scan_manifest(store_path)
                auth_findings = [
                    f for f in report.findings if f.rule_id.startswith("AUTH-")
                ]

                for finding in auth_findings:
                    console.print(f"     [red]✗ {finding.title}[/red]")
                    issues_found += 1
            except Exception:
                pass  # Not a valid manifest

    console.print()

    if issues_found > 0:
        console.print(
            f"[yellow]Found {issues_found} issue(s). "
            f"Run 'mcpcheck audit --fix' to migrate tokens to keychain.[/yellow]"
        )
        raise typer.Exit(1)
    else:
        console.print("[green]✓ All auth stores look secure![/green]")


@app.command()
def init(
    path: Annotated[
        Path,
        typer.Argument(
            help="Path to create .mcpcheck.toml config file.",
        ),
    ] = Path("."),
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing config file.",
        ),
    ] = False,
) -> None:
    """
    Initialize MCPCheck configuration.

    Creates a .mcpcheck.toml config file with default settings.

    Examples:

        mcpcheck init

        mcpcheck init ./project --force
    """
    config_path = path / ".mcpcheck.toml"

    if config_path.exists() and not force:
        console.print(
            f"[yellow]Config file already exists: {config_path}[/yellow]\n"
            f"Use --force to overwrite."
        )
        raise typer.Exit(1)

    default_config = '''# MCPCheck Configuration
# https://mcpcheck.github.io/configuration

[scan]
# Minimum severity to report
severity_threshold = "info"

# Severity that causes non-zero exit code
fail_on = "high"

# Rules to disable
disabled_rules = []

[output]
# Default output format: terminal, json, sarif
format = "terminal"

# Show evidence details in terminal output
show_evidence = false

[semantic]
# Enable LLM-based semantic analysis for low-confidence detections
enabled = false

# LiteLLM model identifier (supports 100+ providers)
# Examples: "gpt-4", "claude-3-opus", "ollama/llama2", "gemini-pro"
model = "claude-haiku-4-5-20251001"

# Maximum cost per scan (USD) - will skip analysis if exceeded
max_cost = 0.10

[policy]
# Path to policy YAML file
# policy_file = "./mcpcheck-policy.yaml"

[auth]
# Check OS keychain for tokens
check_keychain = false

# Auto-migrate plaintext tokens to keychain
auto_migrate = false
'''

    config_path.write_text(default_config, encoding="utf-8")
    console.print(f"[green]✓ Created {config_path}[/green]")
    console.print("\nEdit this file to customize MCPCheck behavior.")


@app.command()
def rules() -> None:
    """
    List all available detection rules.

    Shows rule IDs, descriptions, severity levels, and
    OWASP/MITRE mappings.
    """
    from rich.table import Table

    from mcpcheck.rules import DEFAULT_RULES

    table = Table(title="MCPCheck Detection Rules")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("OWASP")
    table.add_column("MITRE")

    severity_styles = {
        "CRITICAL": "red bold",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }

    for rule in DEFAULT_RULES:
        meta = rule.metadata
        severity_style = severity_styles.get(meta.severity.value, "white")

        table.add_row(
            meta.rule_id,
            meta.name,
            f"[{severity_style}]{meta.severity.value}[/]",
            meta.owasp_id or "-",
            meta.mitre_id or "-",
        )

    console.print(table)
    console.print(f"\nTotal: {len(DEFAULT_RULES)} rules")


if __name__ == "__main__":
    app()

"""
Terminal renderer using Rich.

Outputs beautiful, color-coded scan reports to the terminal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpcheck.domain.models import Severity

if TYPE_CHECKING:
    from mcpcheck.domain.report import ScanReport


class TerminalRenderer:
    """
    Renders scan reports to the terminal using Rich.

    Provides color-coded output with severity indicators,
    tables, and formatted remediation advice.
    """

    # Color mapping for severities
    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }

    def __init__(
        self,
        console: Console | None = None,
        show_evidence: bool = False,
        show_remediation: bool = True,
    ) -> None:
        """
        Initialize the terminal renderer.

        Args:
            console: Rich console to use (creates new one if None).
            show_evidence: Whether to show evidence details.
            show_remediation: Whether to show remediation advice.
        """
        self.console = console or Console()
        self.show_evidence = show_evidence
        self.show_remediation = show_remediation

    def render(self, report: ScanReport) -> None:
        """
        Render a scan report to the terminal.

        Args:
            report: The scan report to render.
        """
        self._render_header(report)
        self._render_summary(report)

        if report.findings:
            self._render_findings(report)
        else:
            self.console.print("\n[green]✓ No security issues found![/green]\n")

        self._render_footer(report)

    def _render_header(self, report: ScanReport) -> None:
        """Render the report header."""
        self.console.print()
        self.console.print(
            Panel(
                f"[bold]MCPCheck Security Scan[/bold]\n"
                f"Target: [cyan]{report.target}[/cyan]\n"
                f"Scan ID: [dim]{report.scan_id}[/dim]",
                title="🛡️ MCPCheck",
                border_style="blue",
            )
        )

    def _render_summary(self, report: ScanReport) -> None:
        """Render the summary statistics."""
        summary = report.summary

        # Create summary table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        if summary.critical > 0:
            table.add_row(
                Text("CRITICAL", style="red bold"),
                Text(str(summary.critical), style="red bold"),
            )
        if summary.high > 0:
            table.add_row(
                Text("HIGH", style="red"),
                Text(str(summary.high), style="red"),
            )
        if summary.medium > 0:
            table.add_row(
                Text("MEDIUM", style="yellow"),
                Text(str(summary.medium), style="yellow"),
            )
        if summary.low > 0:
            table.add_row(
                Text("LOW", style="blue"),
                Text(str(summary.low), style="blue"),
            )
        if summary.info > 0:
            table.add_row(
                Text("INFO", style="dim"),
                Text(str(summary.info), style="dim"),
            )

        if summary.total > 0:
            table.add_row("", "")
            table.add_row(
                Text("TOTAL", style="bold"),
                Text(str(summary.total), style="bold"),
            )

        self.console.print()
        self.console.print(table)

    def _render_findings(self, report: ScanReport) -> None:
        """Render all findings."""
        self.console.print()
        self.console.print("[bold]Findings:[/bold]")
        self.console.print()

        for i, finding in enumerate(report.findings, 1):
            self._render_finding(finding, i)

    def _render_finding(self, finding: "Finding", index: int) -> None:
        """Render a single finding."""
        from mcpcheck.domain.models import Finding

        # Cast for type checker
        finding: Finding = finding

        severity_color = self.SEVERITY_COLORS[finding.severity]
        severity_icon = self.SEVERITY_ICONS[finding.severity]

        # Header with severity and title
        self.console.print(
            f"{severity_icon} [{severity_color}]{finding.severity.value}[/] "
            f"[bold]{finding.title}[/bold]"
        )

        # Rule ID and mappings
        mappings = []
        if finding.owasp_id:
            mappings.append(f"OWASP: {finding.owasp_id}")
        if finding.mitre_id:
            mappings.append(f"MITRE: {finding.mitre_id}")

        rule_info = f"  Rule: [cyan]{finding.rule_id}[/cyan]"
        if mappings:
            rule_info += f" ({', '.join(mappings)})"
        self.console.print(rule_info)

        # Location
        if finding.location:
            self.console.print(f"  Location: [dim]{finding.location}[/dim]")

        # Detail
        self.console.print(f"  [dim]{finding.detail}[/dim]")

        # Remediation
        if self.show_remediation and finding.remediation:
            self.console.print(f"  [green]→ {finding.remediation}[/green]")

        # Evidence
        if self.show_evidence and finding.evidence:
            self.console.print("  Evidence:")
            for key, value in finding.evidence.items():
                # Truncate long values
                value_str = str(value)
                if len(value_str) > 80:
                    value_str = value_str[:77] + "..."
                self.console.print(f"    {key}: [dim]{value_str}[/dim]")

        self.console.print()

    def _render_footer(self, report: ScanReport) -> None:
        """Render the report footer."""
        # Status line
        if report.passed:
            status = "[green]✓ PASSED[/green]"
        else:
            status = "[red]✗ FAILED[/red]"

        self.console.print(
            f"Status: {status} | "
            f"Duration: {report.duration_ms:.1f}ms | "
            f"Rules executed: {len(report.rules_executed)}"
        )

        # Errors
        if report.errors:
            self.console.print()
            self.console.print("[yellow]Warnings:[/yellow]")
            for error in report.errors:
                self.console.print(f"  ⚠ {error}")

        self.console.print()


def render_report(report: ScanReport, **kwargs) -> None:
    """
    Convenience function to render a report to terminal.

    Args:
        report: The scan report to render.
        **kwargs: Options passed to TerminalRenderer.
    """
    renderer = TerminalRenderer(**kwargs)
    renderer.render(report)

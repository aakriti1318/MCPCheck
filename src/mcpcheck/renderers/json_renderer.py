"""
JSON renderer for MCPCheck.

Outputs machine-readable JSON scan reports.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcpcheck.domain.report import ScanReport


class JsonRenderer:
    """
    Renders scan reports as JSON.

    Provides machine-readable output for CI/CD pipelines
    and downstream processing.
    """

    def __init__(
        self,
        indent: int = 2,
        include_metadata: bool = True,
    ) -> None:
        """
        Initialize the JSON renderer.

        Args:
            indent: JSON indentation level.
            include_metadata: Whether to include scan metadata.
        """
        self.indent = indent
        self.include_metadata = include_metadata

    def render(self, report: ScanReport) -> str:
        """
        Render a scan report as JSON string.

        Args:
            report: The scan report to render.

        Returns:
            JSON string.
        """
        data = self.to_dict(report)
        return json.dumps(data, indent=self.indent, default=str)

    def to_dict(self, report: ScanReport) -> dict[str, Any]:
        """
        Convert a scan report to a dictionary.

        Args:
            report: The scan report to convert.

        Returns:
            Dictionary representation.
        """
        result: dict[str, Any] = {
            "scan_id": report.scan_id,
            "scanned_at": report.scanned_at.isoformat(),
            "target": report.target,
            "passed": report.passed,
            "summary": {
                "critical": report.summary.critical,
                "high": report.summary.high,
                "medium": report.summary.medium,
                "low": report.summary.low,
                "info": report.summary.info,
                "total": report.summary.total,
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "detail": f.detail,
                    "remediation": f.remediation,
                    "owasp_id": f.owasp_id,
                    "mitre_id": f.mitre_id,
                    "location": f.location,
                    "evidence": f.evidence,
                }
                for f in report.findings
            ],
        }

        if self.include_metadata:
            result["metadata"] = {
                "duration_ms": report.duration_ms,
                "rules_executed": report.rules_executed,
                "rules_skipped": report.rules_skipped,
                "errors": report.errors,
                **report.metadata,
            }

        return result

    def render_to_file(self, report: ScanReport, path: str) -> None:
        """
        Render a scan report to a JSON file.

        Args:
            report: The scan report to render.
            path: Output file path.
        """
        from pathlib import Path

        json_content = self.render(report)
        Path(path).write_text(json_content, encoding="utf-8")


def render_json(report: ScanReport, **kwargs) -> str:
    """
    Convenience function to render a report as JSON.

    Args:
        report: The scan report to render.
        **kwargs: Options passed to JsonRenderer.

    Returns:
        JSON string.
    """
    renderer = JsonRenderer(**kwargs)
    return renderer.render(report)

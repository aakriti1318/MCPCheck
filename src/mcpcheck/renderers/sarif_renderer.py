"""
SARIF renderer for MCPCheck.

Outputs SARIF 2.1.0 format for GitHub Code Scanning integration.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from mcpcheck.domain.models import Severity

if TYPE_CHECKING:
    from mcpcheck.domain.report import ScanReport


class SarifRenderer:
    """
    Renders scan reports as SARIF 2.1.0.

    SARIF (Static Analysis Results Interchange Format) is supported
    by GitHub Code Scanning for inline PR annotations.
    """

    SARIF_VERSION = "2.1.0"
    SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    # Map severities to SARIF levels
    SEVERITY_LEVELS = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    def __init__(self, include_rules: bool = True) -> None:
        """
        Initialize the SARIF renderer.

        Args:
            include_rules: Whether to include rule definitions.
        """
        self.include_rules = include_rules

    def render(self, report: ScanReport) -> str:
        """
        Render a scan report as SARIF JSON.

        Args:
            report: The scan report to render.

        Returns:
            SARIF JSON string.
        """
        sarif = self.to_sarif(report)
        return json.dumps(sarif, indent=2)

    def to_sarif(self, report: ScanReport) -> dict[str, Any]:
        """
        Convert a scan report to SARIF structure.

        Args:
            report: The scan report to convert.

        Returns:
            SARIF dictionary.
        """
        # Collect unique rule IDs
        rule_ids = list({f.rule_id for f in report.findings})

        sarif: dict[str, Any] = {
            "$schema": self.SCHEMA_URL,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "MCPCheck",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/mcpcheck/mcpcheck",
                            "rules": self._get_rules(rule_ids) if self.include_rules else [],
                        }
                    },
                    "results": [
                        self._finding_to_result(f) for f in report.findings
                    ],
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": report.scanned_at.isoformat() + "Z",
                        }
                    ],
                }
            ],
        }

        return sarif

    def _get_rules(self, rule_ids: list[str]) -> list[dict[str, Any]]:
        """Generate SARIF rule definitions."""
        rules: list[dict[str, Any]] = []

        # Rule metadata (simplified — full version would load from rules)
        rule_info = {
            "TOOL-POISON-001": {
                "name": "SystemOverrideInjection",
                "shortDescription": "System override in tool description",
                "helpUri": "https://mcpcheck.github.io/rules/TOOL-POISON-001",
            },
            "TOOL-POISON-002": {
                "name": "ImperativeInjection",
                "shortDescription": "Imperative injection sequence",
                "helpUri": "https://mcpcheck.github.io/rules/TOOL-POISON-002",
            },
            "TOOL-POISON-003": {
                "name": "HiddenUnicode",
                "shortDescription": "Hidden unicode / homoglyph attack",
                "helpUri": "https://mcpcheck.github.io/rules/TOOL-POISON-003",
            },
            "OVERPERM-001": {
                "name": "DangerousToolCombo",
                "shortDescription": "Dangerous tool combination",
                "helpUri": "https://mcpcheck.github.io/rules/OVERPERM-001",
            },
            "OVERPERM-002": {
                "name": "UnrestrictedWriteExec",
                "shortDescription": "Unrestricted filesystem write + exec",
                "helpUri": "https://mcpcheck.github.io/rules/OVERPERM-002",
            },
            "DYNAMIC-001": {
                "name": "RemoteSchemaLoading",
                "shortDescription": "Remote tool definition loading",
                "helpUri": "https://mcpcheck.github.io/rules/DYNAMIC-001",
            },
            "DYNAMIC-002": {
                "name": "UnpinnedSchemaHash",
                "shortDescription": "Schema hash not pinned",
                "helpUri": "https://mcpcheck.github.io/rules/DYNAMIC-002",
            },
            "AUTH-001": {
                "name": "PlaintextToken",
                "shortDescription": "Plaintext token in auth store",
                "helpUri": "https://mcpcheck.github.io/rules/AUTH-001",
            },
            "AUTH-002": {
                "name": "TokenNotGitignored",
                "shortDescription": "Token path not in .gitignore",
                "helpUri": "https://mcpcheck.github.io/rules/AUTH-002",
            },
        }

        for rule_id in rule_ids:
            info = rule_info.get(rule_id, {})
            rules.append({
                "id": rule_id,
                "name": info.get("name", rule_id),
                "shortDescription": {
                    "text": info.get("shortDescription", rule_id)
                },
                "helpUri": info.get("helpUri", "https://mcpcheck.github.io/rules"),
            })

        return rules

    def _finding_to_result(self, finding: "Finding") -> dict[str, Any]:
        """Convert a finding to a SARIF result."""
        from mcpcheck.domain.models import Finding

        finding: Finding = finding

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": self.SEVERITY_LEVELS.get(finding.severity, "note"),
            "message": {
                "text": f"{finding.title}\n\n{finding.detail}\n\nRemediation: {finding.remediation}"
            },
            "locations": [],
        }

        # Add location if available
        if finding.location:
            result["locations"].append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.location.split(".")[0] if "." in finding.location else finding.location,
                    }
                }
            })

        # Add OWASP/MITRE as tags
        tags = []
        if finding.owasp_id:
            tags.append(f"owasp:{finding.owasp_id}")
        if finding.mitre_id:
            tags.append(f"mitre:{finding.mitre_id}")

        if tags:
            result["properties"] = {"tags": tags}

        return result

    def render_to_file(self, report: ScanReport, path: str) -> None:
        """
        Render a scan report to a SARIF file.

        Args:
            report: The scan report to render.
            path: Output file path.
        """
        from pathlib import Path

        sarif_content = self.render(report)
        Path(path).write_text(sarif_content, encoding="utf-8")

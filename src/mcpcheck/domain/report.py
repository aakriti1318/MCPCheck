"""
Scan report models.

These models represent the output of a security scan, including
summary statistics and individual findings.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from mcpcheck.domain.models import Finding, Severity


class ScanSummary(BaseModel):
    """Summary statistics for a scan."""

    model_config = ConfigDict(frozen=True)

    critical: int = Field(default=0, ge=0, description="Number of CRITICAL findings")
    high: int = Field(default=0, ge=0, description="Number of HIGH findings")
    medium: int = Field(default=0, ge=0, description="Number of MEDIUM findings")
    low: int = Field(default=0, ge=0, description="Number of LOW findings")
    info: int = Field(default=0, ge=0, description="Number of INFO findings")

    @property
    def total(self) -> int:
        """Total number of findings."""
        return self.critical + self.high + self.medium + self.low + self.info

    @property
    def has_blocking_findings(self) -> bool:
        """Whether there are CRITICAL or HIGH findings that should block CI."""
        return self.critical > 0 or self.high > 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanSummary:
        """Create a summary from a list of findings."""
        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 0,
        }
        for finding in findings:
            counts[finding.severity] += 1

        return cls(
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            info=counts[Severity.INFO],
        )


class ScanReport(BaseModel):
    """
    Complete scan report.

    This is the primary output of a scan operation, containing all
    findings and metadata needed for reporting.
    """

    model_config = ConfigDict(frozen=True)

    scan_id: str = Field(
        default_factory=lambda: f"sc_{uuid4().hex[:12]}",
        description="Unique scan identifier",
    )
    scanned_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the scan was performed",
    )
    target: str = Field(..., description="Path or URL that was scanned")
    duration_ms: float = Field(default=0.0, ge=0, description="Scan duration in milliseconds")
    summary: ScanSummary = Field(
        default_factory=ScanSummary,
        description="Summary statistics",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings from the scan",
    )
    rules_executed: list[str] = Field(
        default_factory=list,
        description="List of rule IDs that were executed",
    )
    rules_skipped: list[str] = Field(
        default_factory=list,
        description="List of rule IDs that were skipped",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal errors encountered during scanning",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional scan metadata",
    )

    @property
    def passed(self) -> bool:
        """Whether the scan passed (no blocking findings)."""
        return not self.summary.has_blocking_findings

    @property
    def exit_code(self) -> int:
        """Exit code for CLI (0 = passed, 1 = failed)."""
        return 0 if self.passed else 1

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def findings_by_rule(self, rule_id: str) -> list[Finding]:
        """Get findings filtered by rule ID."""
        return [f for f in self.findings if f.rule_id == rule_id]

    def to_json(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return self.model_dump(mode="json")

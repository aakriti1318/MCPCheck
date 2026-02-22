"""
Unit tests for domain models and reports.
"""

from __future__ import annotations

import pytest

from mcpcheck.domain.models import Finding, Severity
from mcpcheck.domain.report import ScanReport, ScanSummary


class TestSeverity:
    """Tests for the Severity enum."""

    def test_severity_ordering(self) -> None:
        """Severities should be ordered INFO < LOW < MEDIUM < HIGH < CRITICAL."""
        assert Severity.INFO < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

    def test_severity_equality(self) -> None:
        """Same severities should be equal."""
        assert Severity.HIGH == Severity.HIGH
        assert not (Severity.HIGH < Severity.HIGH)

    def test_severity_comparison_with_other_types(self) -> None:
        """Comparison with non-Severity should return NotImplemented."""
        result = Severity.HIGH.__lt__("HIGH")
        assert result is NotImplemented


class TestFinding:
    """Tests for the Finding model."""

    def test_finding_is_frozen(self, sample_finding: Finding) -> None:
        """Findings should be immutable."""
        with pytest.raises(Exception):  # Pydantic frozen validation error
            sample_finding.title = "Changed"  # type: ignore

    def test_finding_is_hashable(self, sample_finding: Finding) -> None:
        """Findings should be hashable for deduplication."""
        # Should not raise
        hash(sample_finding)

        # Same rule_id + title + location = same hash
        f1 = Finding(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            title="Test",
            detail="Detail",
            remediation="Fix it",
            location="path.to.thing",
        )
        f2 = Finding(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            title="Test",
            detail="Different detail",  # Different detail
            remediation="Different fix",
            location="path.to.thing",
        )

        assert hash(f1) == hash(f2)

    def test_finding_rule_id_validation(self) -> None:
        """Rule IDs should match expected pattern."""
        # Valid patterns
        Finding(
            rule_id="TOOL-POISON-001",
            severity=Severity.HIGH,
            title="Test",
            detail="D",
            remediation="R",
        )
        Finding(
            rule_id="AUTH-001",
            severity=Severity.HIGH,
            title="Test",
            detail="D",
            remediation="R",
        )

        # Invalid pattern should raise
        with pytest.raises(Exception):
            Finding(
                rule_id="invalid-format",
                severity=Severity.HIGH,
                title="Test",
                detail="D",
                remediation="R",
            )


class TestScanSummary:
    """Tests for the ScanSummary model."""

    def test_from_findings(self) -> None:
        """Should count findings by severity."""
        findings = [
            Finding(
                rule_id="TEST-001",
                severity=Severity.CRITICAL,
                title="C1",
                detail="D",
                remediation="R",
            ),
            Finding(
                rule_id="TEST-002",
                severity=Severity.CRITICAL,
                title="C2",
                detail="D",
                remediation="R",
            ),
            Finding(
                rule_id="TEST-003",
                severity=Severity.HIGH,
                title="H1",
                detail="D",
                remediation="R",
            ),
            Finding(
                rule_id="TEST-004",
                severity=Severity.LOW,
                title="L1",
                detail="D",
                remediation="R",
            ),
        ]

        summary = ScanSummary.from_findings(findings)

        assert summary.critical == 2
        assert summary.high == 1
        assert summary.medium == 0
        assert summary.low == 1
        assert summary.info == 0
        assert summary.total == 4

    def test_has_blocking_findings(self) -> None:
        """Should identify blocking findings."""
        # With critical
        summary = ScanSummary(critical=1, high=0, medium=0, low=0, info=0)
        assert summary.has_blocking_findings

        # With high
        summary = ScanSummary(critical=0, high=1, medium=0, low=0, info=0)
        assert summary.has_blocking_findings

        # Only medium and below
        summary = ScanSummary(critical=0, high=0, medium=5, low=3, info=10)
        assert not summary.has_blocking_findings


class TestScanReport:
    """Tests for the ScanReport model."""

    def test_passed_property(self, sample_finding: Finding) -> None:
        """Should determine pass/fail based on summary."""
        # With HIGH finding = fail
        report = ScanReport(
            target="test.json",
            summary=ScanSummary.from_findings([sample_finding]),
            findings=[sample_finding],
        )
        assert not report.passed
        assert report.exit_code == 1

        # With no findings = pass
        report = ScanReport(
            target="test.json",
            summary=ScanSummary(),
            findings=[],
        )
        assert report.passed
        assert report.exit_code == 0

    def test_findings_by_severity(self) -> None:
        """Should filter findings by severity."""
        findings = [
            Finding(
                rule_id="TEST-001",
                severity=Severity.CRITICAL,
                title="C1",
                detail="D",
                remediation="R",
            ),
            Finding(
                rule_id="TEST-002",
                severity=Severity.HIGH,
                title="H1",
                detail="D",
                remediation="R",
            ),
            Finding(
                rule_id="TEST-003",
                severity=Severity.HIGH,
                title="H2",
                detail="D",
                remediation="R",
            ),
        ]

        report = ScanReport(
            target="test.json",
            summary=ScanSummary.from_findings(findings),
            findings=findings,
        )

        assert len(report.findings_by_severity(Severity.CRITICAL)) == 1
        assert len(report.findings_by_severity(Severity.HIGH)) == 2
        assert len(report.findings_by_severity(Severity.LOW)) == 0

    def test_findings_by_rule(self) -> None:
        """Should filter findings by rule ID."""
        findings = [
            Finding(
                rule_id="AUTH-001",
                severity=Severity.CRITICAL,
                title="A1",
                detail="D",
                remediation="R",
            ),
            Finding(
                rule_id="AUTH-001",
                severity=Severity.CRITICAL,
                title="A2",
                detail="D",
                remediation="R",
            ),
            Finding(
                rule_id="AUTH-002",
                severity=Severity.HIGH,
                title="B1",
                detail="D",
                remediation="R",
            ),
        ]

        report = ScanReport(
            target="test.json",
            summary=ScanSummary.from_findings(findings),
            findings=findings,
        )

        assert len(report.findings_by_rule("AUTH-001")) == 2
        assert len(report.findings_by_rule("AUTH-002")) == 1
        assert len(report.findings_by_rule("AUTH-003")) == 0

    def test_to_json(self, sample_report: ScanReport) -> None:
        """Should serialize to JSON-compatible dict."""
        data = sample_report.to_json()

        assert "scan_id" in data
        assert "findings" in data
        assert "summary" in data
        assert isinstance(data["scanned_at"], str)  # ISO format

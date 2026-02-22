"""
Base rule infrastructure.

Defines the Rule protocol and base classes for all detection rules.
Rules are pure functions with no I/O — fully testable.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from mcpcheck.domain.models import Finding, RuleMetadata, Severity

if TYPE_CHECKING:
    from mcpcheck.domain.models import McpManifest


@runtime_checkable
class Rule(Protocol):
    """
    Protocol for all detection rules.

    Rules must be stateless and side-effect free. They receive a manifest
    and return a list of findings. No I/O, no network calls, no filesystem access.
    """

    @property
    def rule_id(self) -> str:
        """Unique rule identifier, e.g., TOOL-POISON-001."""
        ...

    @property
    def metadata(self) -> RuleMetadata:
        """Rule metadata including OWASP/MITRE mappings."""
        ...

    def check(self, manifest: McpManifest) -> list[Finding]:
        """
        Check a manifest for security issues.

        Args:
            manifest: The parsed MCP manifest to check.

        Returns:
            List of findings. Empty list if no issues found.
        """
        ...


class BaseRule:
    """
    Base class for detection rules.

    Provides common functionality for rule implementation.
    Subclasses must implement `check()` and define class attributes.
    """

    # Subclasses must override these
    rule_id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    owasp_id: str | None = None
    mitre_id: str | None = None
    cwe_id: str | None = None
    phase: str = "v0.1"

    @property
    def metadata(self) -> RuleMetadata:
        """Generate metadata from class attributes."""
        return RuleMetadata(
            rule_id=self.rule_id,
            name=self.name,
            description=self.description,
            severity=self.severity,
            owasp_id=self.owasp_id,
            mitre_id=self.mitre_id,
            cwe_id=self.cwe_id,
            phase=self.phase,
        )

    @abstractmethod
    def check(self, manifest: McpManifest) -> list[Finding]:
        """Check a manifest for security issues."""
        raise NotImplementedError

    def _create_finding(
        self,
        title: str,
        detail: str,
        remediation: str,
        evidence: dict | None = None,
        location: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Helper to create a finding with this rule's metadata."""
        return Finding(
            rule_id=self.rule_id,
            severity=severity or self.severity,
            title=title,
            detail=detail,
            remediation=remediation,
            owasp_id=self.owasp_id,
            mitre_id=self.mitre_id,
            evidence=evidence or {},
            location=location,
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.rule_id}>"

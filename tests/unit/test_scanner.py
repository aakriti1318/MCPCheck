"""
Unit tests for the rule engine (scanner).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcpcheck.domain.models import McpManifest, Severity
from mcpcheck.engine.scanner import (
    RuleEngine,
    parse_manifest_dict,
    parse_manifest_file,
    scan_manifest,
)
from mcpcheck.rules import DEFAULT_RULES


class TestRuleEngine:
    """Tests for the RuleEngine class."""

    def test_scan_with_default_rules(self, sample_manifest: McpManifest) -> None:
        """Should run all default rules."""
        engine = RuleEngine()
        report = engine.scan(sample_manifest)

        assert report.target == sample_manifest.source
        assert len(report.rules_executed) == len(DEFAULT_RULES)

    def test_scan_with_custom_rules(self, sample_manifest: McpManifest) -> None:
        """Should run only specified rules."""
        from mcpcheck.rules.tool_poison import ToolPoisonSystemOverride

        engine = RuleEngine(rules=[ToolPoisonSystemOverride()])
        report = engine.scan(sample_manifest)

        assert len(report.rules_executed) == 1
        assert "TOOL-POISON-001" in report.rules_executed

    def test_scan_parallel_vs_sequential(self, sample_manifest: McpManifest) -> None:
        """Parallel and sequential scans should produce same results."""
        engine_parallel = RuleEngine(parallel=True)
        engine_sequential = RuleEngine(parallel=False)

        report_parallel = engine_parallel.scan(sample_manifest)
        report_sequential = engine_sequential.scan(sample_manifest)

        assert report_parallel.summary.total == report_sequential.summary.total
        assert len(report_parallel.findings) == len(report_sequential.findings)

    def test_severity_threshold_filtering(
        self, manifest_with_tokens: McpManifest
    ) -> None:
        """Should filter findings by severity threshold."""
        engine = RuleEngine()

        # Get all findings
        report_all = engine.scan(manifest_with_tokens, severity_threshold=Severity.INFO)

        # Get only HIGH and above
        report_high = engine.scan(
            manifest_with_tokens, severity_threshold=Severity.HIGH
        )

        # HIGH threshold should return fewer or equal findings
        assert report_high.summary.total <= report_all.summary.total

    def test_deduplication(self, manifest_with_tokens: McpManifest) -> None:
        """Should deduplicate identical findings."""
        engine = RuleEngine()
        report = engine.scan(manifest_with_tokens)

        # Check that same rule+location doesn't appear twice
        seen = set()
        for finding in report.findings:
            key = (finding.rule_id, finding.location)
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)

    def test_records_duration(self, sample_manifest: McpManifest) -> None:
        """Should record scan duration."""
        engine = RuleEngine()
        report = engine.scan(sample_manifest)

        assert report.duration_ms > 0

    def test_handles_rule_errors(self, sample_manifest: McpManifest) -> None:
        """Should handle rules that raise exceptions."""
        from mcpcheck.rules.base import BaseRule

        class BrokenRule(BaseRule):
            rule_id = "BROKEN-001"
            name = "Broken rule"
            description = "Always fails"
            severity = Severity.HIGH

            def check(self, manifest: McpManifest) -> list:
                raise RuntimeError("Rule failed!")

        engine = RuleEngine(rules=[BrokenRule()])
        report = engine.scan(sample_manifest)

        # Should complete without raising
        assert "BROKEN-001" in report.rules_executed
        assert len(report.errors) > 0
        assert "failed" in report.errors[0].lower()


class TestParseManifest:
    """Tests for manifest parsing functions."""

    def test_parse_cursor_format(self, cursor_manifest_json: dict[str, Any]) -> None:
        """Should parse Cursor-style mcpServers format."""
        manifest = parse_manifest_dict(cursor_manifest_json, source="test.json")

        assert len(manifest.servers) == 2
        assert "filesystem" in manifest.server_names
        assert "github" in manifest.server_names

    def test_parse_servers_array_format(self) -> None:
        """Should parse generic servers array format."""
        data = {
            "servers": [
                {"name": "server1", "command": "cmd1"},
                {"name": "server2", "command": "cmd2"},
            ]
        }

        manifest = parse_manifest_dict(data, source="test.json")

        assert len(manifest.servers) == 2

    def test_parse_extracts_env_vars(
        self, cursor_manifest_json: dict[str, Any]
    ) -> None:
        """Should extract environment variables from servers."""
        manifest = parse_manifest_dict(cursor_manifest_json, source="test.json")

        github_server = next(s for s in manifest.servers if s.name == "github")
        assert "GITHUB_PERSONAL_ACCESS_TOKEN" in github_server.env

    def test_parse_extracts_tools(self) -> None:
        """Should extract tool definitions."""
        data = {
            "mcpServers": {
                "tools-server": {
                    "command": "test",
                    "tools": [
                        {
                            "name": "test_tool",
                            "description": "A test tool",
                            "inputSchema": {"type": "object"},
                        }
                    ],
                }
            }
        }

        manifest = parse_manifest_dict(data, source="test.json")

        assert len(manifest.all_tools) == 1
        assert manifest.all_tools[0].name == "test_tool"
        assert manifest.all_tools[0].description == "A test tool"

    def test_parse_file(self, temp_manifest_file: Path) -> None:
        """Should parse manifest from file."""
        manifest = parse_manifest_file(temp_manifest_file)

        assert len(manifest.servers) == 2
        assert str(temp_manifest_file) in manifest.source

    def test_parse_invalid_json_raises(self, tmp_path: Path) -> None:
        """Should raise ManifestParseError for invalid JSON."""
        from mcpcheck.domain.exceptions import ManifestParseError

        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ invalid json }", encoding="utf-8")

        with pytest.raises(ManifestParseError) as exc_info:
            parse_manifest_file(bad_file)

        assert "Invalid JSON" in str(exc_info.value)

    def test_parse_missing_file_raises(self, tmp_path: Path) -> None:
        """Should raise ManifestParseError for missing file."""
        from mcpcheck.domain.exceptions import ManifestParseError

        with pytest.raises(ManifestParseError) as exc_info:
            parse_manifest_file(tmp_path / "nonexistent.json")

        assert "not found" in str(exc_info.value)

    def test_parse_unrecognized_format_raises(self) -> None:
        """Should raise ManifestParseError for unrecognized format."""
        from mcpcheck.domain.exceptions import ManifestParseError

        data = {"something": "else"}

        with pytest.raises(ManifestParseError) as exc_info:
            parse_manifest_dict(data, source="test.json")

        assert "mcpServers" in str(exc_info.value) or "servers" in str(exc_info.value)


class TestScanManifest:
    """Tests for the scan_manifest convenience function."""

    def test_scan_from_path(self, temp_manifest_file: Path) -> None:
        """Should scan a manifest from file path."""
        report = scan_manifest(temp_manifest_file)

        assert report.target == str(temp_manifest_file)
        assert len(report.rules_executed) > 0

    def test_scan_from_dict(self, cursor_manifest_json: dict[str, Any]) -> None:
        """Should scan a manifest from dict."""
        report = scan_manifest(cursor_manifest_json)

        assert report.target == "<dict>"

    def test_scan_safe_manifest_passes(self, temp_safe_manifest_file: Path) -> None:
        """A safe manifest should pass (no blocking findings)."""
        report = scan_manifest(temp_safe_manifest_file)

        # May have some INFO findings, but should pass
        assert report.summary.critical == 0
        assert report.summary.high == 0

    def test_scan_with_tokens_fails(self, manifest_with_tokens: McpManifest) -> None:
        """A manifest with exposed tokens should fail."""
        from mcpcheck.engine.scanner import RuleEngine

        engine = RuleEngine()
        report = engine.scan(manifest_with_tokens)

        assert report.summary.critical > 0
        assert not report.passed

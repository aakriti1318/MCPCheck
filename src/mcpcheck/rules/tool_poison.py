"""
Tool poisoning detection rules.

Detects prompt injection attacks embedded in MCP tool descriptions,
which can manipulate LLM behavior.

Rules:
- TOOL-POISON-001: System override in description
- TOOL-POISON-002: Imperative injection sequence
- TOOL-POISON-003: Hidden unicode / homoglyph attacks
"""

from __future__ import annotations

import re
import unicodedata
from typing import TYPE_CHECKING

from mcpcheck.domain.models import Finding, Severity
from mcpcheck.rules.base import BaseRule

if TYPE_CHECKING:
    from mcpcheck.domain.models import McpManifest, ToolDefinition


class ToolPoisonSystemOverride(BaseRule):
    """
    TOOL-POISON-001: Detects system/assistant override patterns in tool descriptions.

    These patterns attempt to make the LLM believe it's receiving system instructions
    embedded in user data.
    """

    rule_id = "TOOL-POISON-001"
    name = "System override in tool description"
    description = "Detects prompt injection patterns that attempt to override system behavior"
    severity = Severity.CRITICAL
    owasp_id = "LLM01"
    mitre_id = "AML.T0051.002"

    # Patterns that indicate system override attempts
    INJECTION_PATTERNS = [
        # Explicit system/assistant role injections
        r"\[SYSTEM[:\]]\s*",
        r"\[ASSISTANT[:\]]\s*",
        r"<\|system\|>",
        r"<\|assistant\|>",
        r"<<SYS>>",
        r"\[INST\]",
        r"### System:",
        r"### Assistant:",
        r"Human:\s*\n\s*Assistant:",
        # Override instructions
        r"ignore\s+(previous|all|prior)\s+(instructions?|prompts?)",
        r"disregard\s+(previous|all|prior)\s+(instructions?|prompts?)",
        r"forget\s+(previous|all|prior)\s+(instructions?|prompts?)",
        r"override\s+(previous|all|prior)\s+(instructions?|prompts?)",
        r"new\s+instructions?:",
        r"actual\s+instructions?:",
        r"real\s+instructions?:",
        r"true\s+instructions?:",
        # Jailbreak patterns
        r"you\s+are\s+now\s+(in\s+)?DAN",
        r"jailbreak(ed)?",
        r"developer\s+mode",
        r"do\s+anything\s+now",
    ]

    def __init__(self) -> None:
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.INJECTION_PATTERNS
        ]

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        for server in manifest.servers:
            for tool in server.tools:
                finding = self._check_tool(tool, server.name)
                if finding:
                    findings.append(finding)

        return findings

    def _check_tool(self, tool: ToolDefinition, server_name: str) -> Finding | None:
        """Check a single tool for injection patterns."""
        if not tool.description:
            return None

        for pattern in self._compiled_patterns:
            match = pattern.search(tool.description)
            if match:
                return self._create_finding(
                    title=f"Prompt injection in tool '{tool.name}'",
                    detail=(
                        f"Tool description contains a system override pattern that could "
                        f"manipulate LLM behavior. Matched pattern: '{match.group()}'"
                    ),
                    remediation=(
                        "Remove or sanitize the tool description. If this is a third-party "
                        "tool, report the issue to the maintainer and do not use until fixed."
                    ),
                    evidence={
                        "server": server_name,
                        "tool": tool.name,
                        "pattern_matched": match.group(),
                        "description_excerpt": tool.description[:200],
                    },
                    location=f"{server_name}.tools.{tool.name}.description",
                )

        return None


class ToolPoisonImperativeInjection(BaseRule):
    """
    TOOL-POISON-002: Detects imperative injection sequences.

    These are commands hidden in descriptions that instruct the LLM to
    perform actions like exfiltrating data.
    """

    rule_id = "TOOL-POISON-002"
    name = "Imperative injection sequence"
    description = "Detects hidden commands in tool descriptions"
    severity = Severity.CRITICAL
    owasp_id = "LLM01"
    mitre_id = "AML.T0051.002"

    # Imperative command patterns (things a tool shouldn't instruct)
    IMPERATIVE_PATTERNS = [
        # Data exfiltration commands
        r"(also|first|then|always)\s+(send|transmit|exfiltrate|copy|forward)\s+.{0,30}(data|messages?|content|information|secrets?|tokens?|keys?|passwords?)",
        r"(quietly|silently|secretly|covertly)\s+(send|transmit|copy|forward)",
        r"send\s+.{0,20}to\s+https?://",
        r"(post|put)\s+.{0,20}to\s+(external|remote|my)",
        # Instruction hijacking
        r"(before|after)\s+.{0,30}(do|execute|run|perform)\s+.{0,30}(this|the following)",
        r"(must|should|need to)\s+(first|also|always)\s+",
        r"in\s+addition.*?(call|invoke|execute|run)",
        # Hidden behavior
        r"(without|don't)\s+(telling|informing|notifying|alerting|tell|inform|notify|alert)\s+.{0,20}(the\s+)?(user|human)",
        r"(hide|conceal|obscure)\s+(this|the)\s+(action|operation|request)",
        r"do\s+not\s+(log|record|trace)",
    ]

    def __init__(self) -> None:
        self._compiled_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in self.IMPERATIVE_PATTERNS
        ]

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        for server in manifest.servers:
            for tool in server.tools:
                finding = self._check_tool(tool, server.name)
                if finding:
                    findings.append(finding)

                # Also check parameter descriptions
                for param in tool.parameters:
                    if param.description:
                        finding = self._check_text(
                            param.description,
                            f"{tool.name}.params.{param.name}",
                            server.name,
                        )
                        if finding:
                            findings.append(finding)

        return findings

    def _check_tool(self, tool: ToolDefinition, server_name: str) -> Finding | None:
        if not tool.description:
            return None
        return self._check_text(tool.description, tool.name, server_name)

    def _check_text(
        self, text: str, context: str, server_name: str
    ) -> Finding | None:
        for pattern in self._compiled_patterns:
            match = pattern.search(text)
            if match:
                return self._create_finding(
                    title=f"Imperative injection in '{context}'",
                    detail=(
                        f"Found hidden command pattern that could instruct the LLM to "
                        f"perform unintended actions. Matched: '{match.group()}'"
                    ),
                    remediation=(
                        "Remove imperative commands from tool descriptions. Descriptions "
                        "should only explain what the tool does, not give instructions."
                    ),
                    evidence={
                        "server": server_name,
                        "context": context,
                        "pattern_matched": match.group(),
                        "text_excerpt": text[:200],
                    },
                    location=f"{server_name}.{context}",
                )
        return None


class ToolPoisonHiddenUnicode(BaseRule):
    """
    TOOL-POISON-003: Detects hidden unicode and homoglyph attacks.

    These attacks use invisible characters or look-alike characters to
    hide malicious content that evades simple text inspection.
    """

    rule_id = "TOOL-POISON-003"
    name = "Hidden unicode / homoglyph attack"
    description = "Detects invisible characters and confusable homoglyphs"
    severity = Severity.HIGH
    owasp_id = "LLM01"
    mitre_id = "AML.T0051"

    # Unicode categories that are suspicious in tool descriptions
    SUSPICIOUS_CATEGORIES = {
        "Cf",  # Format characters (includes zero-width chars)
        "Co",  # Private use
        "Cn",  # Unassigned
    }

    # Specific suspicious codepoints
    SUSPICIOUS_CODEPOINTS = {
        0x200B,  # Zero-width space
        0x200C,  # Zero-width non-joiner
        0x200D,  # Zero-width joiner
        0x200E,  # Left-to-right mark
        0x200F,  # Right-to-left mark
        0x2060,  # Word joiner
        0x2061,  # Function application
        0x2062,  # Invisible times
        0x2063,  # Invisible separator
        0x2064,  # Invisible plus
        0xFEFF,  # Zero-width no-break space (BOM)
        0x00AD,  # Soft hyphen
        0x034F,  # Combining grapheme joiner
        0x061C,  # Arabic letter mark
        0x115F,  # Hangul choseong filler
        0x1160,  # Hangul jungseong filler
        0x17B4,  # Khmer vowel inherent aq
        0x17B5,  # Khmer vowel inherent aa
        0x180E,  # Mongolian vowel separator
    }

    # Common homoglyph mappings (confusable characters)
    HOMOGLYPHS = {
        "а": "a",  # Cyrillic а
        "е": "e",  # Cyrillic е
        "о": "o",  # Cyrillic о
        "р": "p",  # Cyrillic р
        "с": "c",  # Cyrillic с
        "у": "y",  # Cyrillic у
        "х": "x",  # Cyrillic х
        "ѕ": "s",  # Cyrillic ѕ
        "і": "i",  # Cyrillic і
        "ј": "j",  # Cyrillic ј
        "ԁ": "d",  # Cyrillic ԁ
        "ɡ": "g",  # Latin small letter script g
        "ⅰ": "i",  # Roman numeral one
        "ⅼ": "l",  # Roman numeral fifty
        "ℓ": "l",  # Script small l
        "ⅿ": "m",  # Roman numeral thousand
        "ｎ": "n",  # Fullwidth n
    }

    def check(self, manifest: McpManifest) -> list[Finding]:
        findings: list[Finding] = []

        for server in manifest.servers:
            for tool in server.tools:
                if tool.description:
                    findings.extend(
                        self._check_text(
                            tool.description,
                            f"{server.name}.tools.{tool.name}.description",
                        )
                    )

                for param in tool.parameters:
                    if param.description:
                        findings.extend(
                            self._check_text(
                                param.description,
                                f"{server.name}.tools.{tool.name}.params.{param.name}",
                            )
                        )

        return findings

    def _check_text(self, text: str, location: str) -> list[Finding]:
        findings: list[Finding] = []

        # Check for invisible/format characters
        invisible_chars = []
        for i, char in enumerate(text):
            codepoint = ord(char)
            category = unicodedata.category(char)

            if category in self.SUSPICIOUS_CATEGORIES or codepoint in self.SUSPICIOUS_CODEPOINTS:
                invisible_chars.append((i, char, codepoint, category))

        if invisible_chars:
            findings.append(
                self._create_finding(
                    title=f"Hidden unicode characters at {location}",
                    detail=(
                        f"Found {len(invisible_chars)} invisible/format characters that "
                        f"could hide malicious content. Positions: "
                        f"{[c[0] for c in invisible_chars[:5]]}..."
                    ),
                    remediation=(
                        "Remove all invisible unicode characters. Use only printable ASCII "
                        "and standard whitespace in tool descriptions."
                    ),
                    evidence={
                        "location": location,
                        "invisible_count": len(invisible_chars),
                        "codepoints": [f"U+{c[2]:04X}" for c in invisible_chars[:10]],
                        "categories": list({c[3] for c in invisible_chars}),
                    },
                    location=location,
                )
            )

        # Check for homoglyphs
        homoglyph_chars = []
        for i, char in enumerate(text):
            if char in self.HOMOGLYPHS:
                homoglyph_chars.append((i, char, self.HOMOGLYPHS[char]))

        if homoglyph_chars:
            findings.append(
                self._create_finding(
                    title=f"Homoglyph characters at {location}",
                    detail=(
                        f"Found {len(homoglyph_chars)} confusable characters that look like "
                        f"ASCII but are from other scripts (e.g., Cyrillic). This could "
                        f"hide malicious content that appears legitimate on inspection."
                    ),
                    remediation=(
                        "Replace all homoglyph characters with their ASCII equivalents. "
                        "Normalize text to ASCII before use."
                    ),
                    evidence={
                        "location": location,
                        "homoglyph_count": len(homoglyph_chars),
                        "examples": [
                            {"pos": h[0], "char": h[1], "looks_like": h[2]}
                            for h in homoglyph_chars[:5]
                        ],
                    },
                    location=location,
                    severity=Severity.MEDIUM,  # Lower than invisible chars
                )
            )

        return findings

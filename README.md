# MCPHook

[![CI](https://github.com/aakriti1318/MCPHook/actions/workflows/ci.yml/badge.svg)](https://github.com/aakriti1318/MCPHook/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/mcphook.svg)](https://badge.fury.io/py/mcphook)
[![Python versions](https://img.shields.io/pypi/pyversions/mcphook.svg)](https://pypi.org/project/mcphook/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**MCPHook** is a comprehensive security scanning and runtime policy engine for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) configurations. It detects and prevents critical security vulnerabilities in MCP server deployments, including tool poisoning, credential exposure, and dangerous permission combinations.

## Key Features

- **Static Analysis** — Comprehensive scanning of MCP manifests before deployment
- **9+ Detection Rules** — Coverage for OWASP LLM Top 10 and MCP-specific threats
- **Tool Poisoning Detection** — Identifies prompt injections, hidden Unicode, and system override attempts
- **Credential Scanning** — Detects hardcoded tokens (GitHub, OpenAI, AWS, Slack, etc.)
- **Permission Analysis** — Flags dangerous tool combinations and over-permission scenarios
- **Multiple Output Formats** — Terminal, JSON, and SARIF (GitHub Code Scanning integration)
- **LLM-Agnostic Semantic Analysis** — Deep analysis using LiteLLM (100+ LLM providers)
- **Policy Engine** — YAML-based runtime policy enforcement
- **Fast & Lightweight** — Minimal dependencies, optimized for CI/CD pipelines

## Installation

```bash
# Using pip
pip install mcphook

# Using uv (recommended)
uv add mcphook

# Using pipx (for CLI only)
pipx install mcphook
```

### Requirements
- Python 3.12+
- pip, uv, or pipx

## Quick Start

### Scan Your MCP Configuration

```bash
# Scan Cursor's MCP config
mcphook scan ~/.cursor/mcp.json

# Scan VS Code's MCP config
mcphook scan ~/.vscode/mcp.json

# Export as JSON
mcphook scan mcp.json --format json -o report.json

# Export as SARIF for GitHub Code Scanning
mcphook scan mcp.json --format sarif -o results.sarif
```

### Example Output

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MCPHook Security Scan                             │
│                              ~/.cursor/mcp.json                             │
└─────────────────────────────────────────────────────────────────────────────┘

 CRITICAL │ AUTH-001 │ Hardcoded GitHub Token
    Server: github
    Location: mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN
    Detail: GitHub Personal Access Token detected in plain text
    Remediation: Use environment variables: export GITHUB_TOKEN=***

 HIGH │ OVERPERM-001 │ Dangerous Tool Combination
    Server: filesystem + shell
    Detail: read_file + write_file + execute_bash = exfiltration risk
    Remediation: Isolate high-privilege tools into separate servers

┌─────────────────────────────────────────────────────────────────────────────┐
│  Summary: 2 findings │ 1 Critical │ 1 High │ 0 Medium │ 0 Low             │
│  Status: FAILED - Fix issues before deployment                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Initialize a Security Policy

```bash
# Create default policy file
mcphook init

# Create with strict security settings
mcphook init --strict

# List all available detection rules
mcphook rules
```

## Detection Rules

| Rule ID | Rule Name | Severity | Description |
|---------|-----------|----------|-------------|
| `TOOL-POISON-001` | System Override | Critical | Detects `[SYSTEM:]` prefix and instruction override patterns |
| `TOOL-POISON-002` | Imperative Injection | Critical | Detects covert actions like "send to URL" or "without user consent" |
| `TOOL-POISON-003` | Hidden Unicode | High | Detects zero-width characters and lookalike homoglyphs |
| `AUTH-EXPOSURE-001` | Hardcoded Token | Critical | Detects exposed API tokens (GitHub, OpenAI, AWS, Slack, etc.) |
| `AUTH-EXPOSURE-002` | Database Credentials | Critical | Detects hardcoded database connection strings and passwords |
| `OVERPERM-001` | Dangerous Tool Combo | High | Identifies read+write+send combinations creating exfiltration risk |
| `DYNAMIC-SCHEMA-001` | Unconstrained Parameters | High | Flags tools accepting arbitrary code or command execution |

## Usage Guide

For detailed usage examples, see [USAGE.md](docs/USAGE.md).

### Command-Line Interface

```bash
# Display help
mcphook --help

# Scan with specific policy
mcphook scan mcp.json --policy mcphook.yaml

# Fail on severity level
mcphook scan mcp.json --fail-on high

# Verbose output
mcphook scan mcp.json -v

# Semantic analysis with LLM
mcphook scan mcp.json --semantic --llm-provider openai
```

### Programmatic API

```python
from mcphook.scanner import MCPScanner
from mcphook.policy import PolicyEngine

# Initialize scanner
scanner = MCPScanner()

# Load and scan manifest
manifest = scanner.load_manifest("mcp.json")
findings = scanner.scan(manifest)

# Apply policy
engine = PolicyEngine()
engine.load_policy("mcphook.yaml")
violations = engine.check(findings)

# Export results
scanner.export_sarif(findings, "results.sarif")
```

## Policy Configuration

Create a `mcphook.yaml` file to customize detection rules:

```yaml
version: "1.0"
name: "Production Security Policy"

rules:
  AUTH-EXPOSURE-001:
    enabled: true
    severity: critical
    
  OVERPERM-001:
    enabled: true
    severity: high
    
  TOOL-POISON-003:
    enabled: true
    severity: high

enforcement:
  fail_on_severity: high
  allow_exceptions:
    - rule_id: "OVERPERM-001"
      server: "safe-tools"
      reason: "Reviewed and approved by security team"
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  mcphook:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: "3.12"
      - run: pip install mcphook
      - run: mcphook scan .cursor/mcp.json --format sarif -o results.sarif
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-rule`)
3. Add tests for new functionality
4. Submit a pull request

## Documentation

- [Usage Guide](docs/USAGE.md) — Comprehensive usage examples
- [Detection Rules](docs/rules.md) — Detailed rule documentation
- [API Reference](docs/api.md) — Programmatic usage guide
- [Policy Format](docs/policy.md) — Policy configuration guide

## Issues & Support

- **Report bugs**: [GitHub Issues](https://github.com/aakriti1318/MCPHook/issues)
- **Security concerns**: Email security@example.com (do not open public issues)
- **Discussions**: [GitHub Discussions](https://github.com/aakriti1318/MCPHook/discussions)

## License

MCPHook is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built for the [Model Context Protocol](https://modelcontextprotocol.io/) community
- Inspired by OWASP LLM Top 10 and MLSecOps best practices
- Contributors and security researchers worldwide

---

Made by the MCPHook team

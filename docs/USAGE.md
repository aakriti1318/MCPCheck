# MCPHook Usage Guide

This guide covers all aspects of using MCPHook for securing your MCP configurations.

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [Command-Line Reference](#command-line-reference)
4. [Output Formats](#output-formats)
5. [Policy Configuration](#policy-configuration)
6. [Programmatic API](#programmatic-api)
7. [CI/CD Integration](#cicd-integration)
8. [Real-World Examples](#real-world-examples)
9. [Troubleshooting](#troubleshooting)

## Installation

### Via pip

```bash
pip install mcphook
```

### Via uv (recommended)

```bash
uv add mcphook
```

### Via pipx (CLI only)

```bash
pipx install mcphook
```

### Development Installation

```bash
git clone https://github.com/aakriti1318/MCPHook.git
cd MCPHook
uv sync --dev
```

## Basic Usage

### 1. Scan an MCP Configuration

The simplest way to use MCPHook is to scan an existing MCP configuration file:

```bash
mcphook scan ~/.cursor/mcp.json
```

This performs a basic security scan and displays findings in the terminal.

### 2. Scan with Output File

```bash
mcphook scan mcp.json -o scan_report.txt
```

### 3. Scan Multiple Locations

MCPHook can scan multiple files:

```bash
mcphook scan ~/.cursor/mcp.json ~/.vscode/mcp.json ~/work/mcp.json
```

### 4. Get Help

```bash
mcphook --help
mcphook scan --help
```

## Command-Line Reference

### Scan Command

```bash
mcphook scan [OPTIONS] [PATHS...]
```

#### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--policy` | `-p` | Path to policy YAML file | Uses default policy |
| `--format` | `-f` | Output format (terminal, json, sarif) | terminal |
| `--output` | `-o` | Output file path | stdout |
| `--fail-on` | | Minimum severity to fail (info, low, medium, high, critical) | N/A |
| `--verbose` | `-v` | Enable verbose output | False |
| `--quiet` | `-q` | Suppress output | False |
| `--semantic` | | Enable LLM semantic analysis | False |
| `--llm-provider` | | LLM provider (openai, anthropic, ollama) | openai |
| `--llm-model` | | Specific LLM model to use | provider default |

#### Examples

```bash
# Scan with verbose output
mcphook scan mcp.json -v

# Fail if any HIGH or CRITICAL issues found
mcphook scan mcp.json --fail-on high

# Use custom policy
mcphook scan mcp.json --policy my-policy.yaml

# Semantic analysis with Claude
export ANTHROPIC_API_KEY=sk-ant-...
mcphook scan mcp.json --semantic --llm-provider anthropic

# Quiet mode (only exit code)
mcphook scan mcp.json --quiet
```

### Init Command

```bash
mcphook init [OPTIONS]
```

Creates a default `mcphook.yaml` policy file in the current directory.

#### Options

| Option | Description |
|--------|-------------|
| `--strict` | Create a strict policy (all rules enabled, low threshold) |
| `--force` | Overwrite existing policy file |

#### Examples

```bash
# Create default policy
mcphook init

# Create strict policy
mcphook init --strict

# Force overwrite
mcphook init --force
```

### Rules Command

```bash
mcphook rules [OPTIONS]
```

Lists all available detection rules.

#### Options

| Option | Description |
|--------|-------------|
| `--severity` | Filter by severity (critical, high, medium, low) |
| `--json` | Output as JSON |

#### Examples

```bash
# List all rules
mcphook rules

# Show only CRITICAL rules
mcphook rules --severity critical

# Export as JSON
mcphook rules --json > rules.json
```

## Output Formats

### Terminal Format (Default)

Human-readable terminal output with colors and formatting.

```bash
mcphook scan mcp.json
```

Output:
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

┌─────────────────────────────────────────────────────────────────────────────┐
│  Summary: 1 finding │ 1 Critical │ 0 High │ 0 Medium │ 0 Low              │
│  Status: FAILED                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### JSON Format

Machine-readable JSON output for integration with tools.

```bash
mcphook scan mcp.json --format json -o report.json
```

Output:
```json
{
  "scan_id": "scan_20260306_143022",
  "timestamp": "2026-03-06T14:30:22Z",
  "target": "mcp.json",
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "passed": false
  },
  "findings": [
    {
      "rule_id": "AUTH-001",
      "title": "Hardcoded GitHub Token",
      "severity": "critical",
      "server": "github",
      "location": "mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN",
      "detail": "GitHub Personal Access Token detected in plain text",
      "remediation": "Use environment variables: export GITHUB_TOKEN=***"
    }
  ]
}
```

### SARIF Format

Structured Analysis Results Format for GitHub Code Scanning.

```bash
mcphook scan mcp.json --format sarif -o results.sarif
```

Then upload to GitHub:
```bash
curl -X POST \
  -H "Authorization: token YOUR_GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/OWNER/REPO/code-scanning/sarifs \
  -d @results.sarif
```

## Policy Configuration

### Creating a Policy File

Create `mcphook.yaml`:

```yaml
version: "1.0"
name: "Production Security Policy"

rules:
  # Control which rules are enabled
  AUTH-EXPOSURE-001:
    enabled: true
    severity: critical
    
  AUTH-EXPOSURE-002:
    enabled: true
    severity: critical
    
  TOOL-POISON-001:
    enabled: true
    severity: critical
    
  TOOL-POISON-002:
    enabled: true
    severity: critical
    
  TOOL-POISON-003:
    enabled: true
    severity: high
    
  OVERPERM-001:
    enabled: true
    severity: high
    
  DYNAMIC-SCHEMA-001:
    enabled: true
    severity: high

# Enforcement settings
enforcement:
  fail_on_severity: high
  
  # Allow specific exceptions
  exceptions:
    - rule_id: "OVERPERM-001"
      server: "trusted-tools"
      reason: "Reviewed and approved by security team"
      expires: "2026-12-31"
```

### Using a Custom Policy

```bash
mcphook scan mcp.json --policy my-policy.yaml
```

### Policy with Environment-Specific Rules

```yaml
version: "1.0"
name: "Development Policy"

rules:
  # Less strict for development
  AUTH-EXPOSURE-001:
    enabled: true
    severity: high  # Not critical
    
  OVERPERM-001:
    enabled: false  # Allow over-permissions in dev
    
  TOOL-POISON-001:
    enabled: true
    severity: critical

enforcement:
  fail_on_severity: critical  # Only fail on critical issues
```

## Programmatic API

### Basic Scanning

```python
from mcphook.scanner import MCPScanner
from mcphook.domain.models import Severity

# Initialize scanner
scanner = MCPScanner()

# Scan a file
report = scanner.scan_file("mcp.json")

# Check if scan passed
if report.passed:
    print("All checks passed!")
else:
    print(f"Found {len(report.findings)} issues")

# List findings by severity
for finding in report.findings:
    print(f"{finding.severity}: {finding.title}")
```

### With Policy

```python
from mcphook.scanner import MCPScanner
from mcphook.policy import PolicyEngine

scanner = MCPScanner()
engine = PolicyEngine()

# Load policy
engine.load_policy("mcphook.yaml")

# Scan
report = scanner.scan_file("mcp.json")

# Apply policy
violations = engine.enforce(report)

if violations:
    print(f"Policy violations: {len(violations)}")
    for violation in violations:
        print(f"- {violation.rule_id}: {violation.title}")
```

### Custom Analysis

```python
from mcphook.engine.scanner import RuleEngine
from mcphook.domain.models import Severity

engine = RuleEngine()

# Get enabled rules
rules = engine.get_rules()
print(f"Total rules: {len(rules)}")

# Run specific rule
rule = rules[0]
findings = rule.execute(manifest)
```

### Export Formats

```python
from mcphook.renderers import JSONRenderer, SARIFRenderer

# Export as JSON
json_renderer = JSONRenderer()
json_output = json_renderer.render(report)

# Export as SARIF
sarif_renderer = SARIFRenderer()
sarif_output = sarif_renderer.render(report)
```

## CI/CD Integration

### GitHub Actions

```yaml
name: MCPHook Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.12"
      
      - name: Install MCPHook
        run: pip install mcphook
      
      - name: Run security scan
        run: |
          mcphook scan \
            ~/.cursor/mcp.json \
            ~/.vscode/mcp.json \
            --format sarif \
            -o mcphook-results.sarif
      
      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: mcphook-results.sarif
```

### GitLab CI

```yaml
mcphook_scan:
  image: python:3.12
  script:
    - pip install mcphook
    - mcphook scan . --format json -o mcphook-report.json
  artifacts:
    reports:
      sast: mcphook-report.json
  only:
    - merge_requests
    - main
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: mcphook
        name: MCPHook security scan
        entry: mcphook scan
        language: python
        types: [json]
        stages: [commit]
```

Run:
```bash
pre-commit install
git commit -m "Update MCP config"  # Automatically scans
```

## Real-World Examples

### Example 1: Secure MCP Configuration

**mcp.json** (Good):
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"],
      "description": "Limited filesystem access"
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  }
}
```

Scan:
```bash
mcphook scan mcp.json
```

Result: **PASSED** (No issues found)

### Example 2: Insecure MCP Configuration

**bad-mcp.json** (Vulnerable):
```json
{
  "mcpServers": {
    "github": {
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abc123xyz..."
      }
    },
    "shell": {
      "command": "bash -i"
    },
    "filesystem": {
      "command": "npm",
      "args": ["server-filesystem", "/"]
    }
  }
}
```

Scan:
```bash
mcphook scan bad-mcp.json --fail-on high
```

Result: **FAILED**
- AUTH-EXPOSURE-001: Hardcoded token
- OVERPERM-001: Shell + filesystem combination
- TOOL-POISON-001: Unrestricted filesystem access

### Example 3: Development vs Production Policies

**dev-policy.yaml**:
```yaml
version: "1.0"
name: "Development"
enforcement:
  fail_on_severity: critical
```

**prod-policy.yaml**:
```yaml
version: "1.0"
name: "Production"
enforcement:
  fail_on_severity: high
```

Scan with different policies:
```bash
# Development (less strict)
mcphook scan mcp.json --policy dev-policy.yaml

# Production (strict)
mcphook scan mcp.json --policy prod-policy.yaml
```

## Troubleshooting

### Issue: "Cannot find mcp.json"

```bash
mcphook scan /full/path/to/mcp.json
```

### Issue: Exit code non-zero but no findings

Check if you're using `--fail-on`:

```bash
mcphook scan mcp.json --fail-on info  # More sensitive
```

### Issue: Semantic analysis not working

Ensure API key is set:

```bash
export OPENAI_API_KEY=sk-...
mcphook scan mcp.json --semantic
```

### Issue: Want to see all available rules

```bash
mcphook rules
```

### Issue: Policy file not found

Ensure path is correct:

```bash
mcphook scan mcp.json --policy ./mcphook.yaml
```

Create default policy if needed:

```bash
mcphook init
mcphook scan mcp.json --policy ./mcphook.yaml
```

## Performance Tips

1. **Exclude unnecessary directories** with policy file
2. **Use JSON output** for faster parsing
3. **Run in parallel** on multiple machines in CI/CD
4. **Cache policy files** across runs
5. **Disable semantic analysis** unless needed (requires LLM API calls)

## Support & Resources

- GitHub Issues: https://github.com/aakriti1318/MCPHook/issues
- Documentation: https://github.com/aakriti1318/MCPHook/tree/main/docs
- Model Context Protocol: https://modelcontextprotocol.io/

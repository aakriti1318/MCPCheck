# MCPCheck

[![PyPI version](https://badge.fury.io/py/mcpcheck.svg)](https://badge.fury.io/py/mcpcheck)
[![Python versions](https://img.shields.io/pypi/pyversions/mcpcheck.svg)](https://pypi.org/project/mcpcheck/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**MCPCheck** is a security scanner and runtime policy engine for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) configurations. It detects vulnerabilities like tool poisoning, credential exposure, and over-permissioned tool combinations in your MCP setup.

## 🔥 Features

- **Static Analysis** — Scan MCP manifests for security issues before deployment
- **9+ Detection Rules** — Comprehensive coverage of OWASP LLM Top 10 risks
- **Tool Poisoning Detection** — Find prompt injections, hidden unicode, and system override attempts
- **Credential Scanning** — Detect hardcoded tokens (GitHub, OpenAI, AWS, etc.)
- **Permission Analysis** — Identify dangerous tool combinations (read+write+send)
- **Multiple Output Formats** — Rich terminal, JSON, and SARIF (GitHub Code Scanning)
- **LLM-Agnostic Semantic Analysis** — Optional deep analysis using LiteLLM (100+ providers)
- **Policy Engine** — Runtime enforcement with YAML-based rules

## 📦 Installation

```bash
# Using pip
pip install mcpcheck

# Using uv (recommended)
uv add mcpcheck

# Using pipx (for CLI)
pipx install mcpcheck
```

## 🚀 Quick Start

### Scan your MCP configuration

```bash
# Scan Cursor's MCP config
mcpcheck scan ~/.cursor/mcp.json

# Scan VS Code's MCP config
mcpcheck scan ~/.vscode/mcp.json

# Scan with JSON output
mcpcheck scan mcp.json --format json

# Scan with SARIF output (for GitHub Code Scanning)
mcpcheck scan mcp.json --format sarif -o results.sarif
```

### Example Output

```
╭─────────────────────────────────────────────────────────────────────────────╮
│                           MCPCheck Security Scan                            │
│                              ~/.cursor/mcp.json                             │
╰─────────────────────────────────────────────────────────────────────────────╯

 🔴 CRITICAL │ AUTH-001 │ Hardcoded GitHub Token
    Server: github
    Location: mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN
    Detail: GitHub Personal Access Token detected in configuration file
    Remediation: Use environment variable references: ${GITHUB_TOKEN}

 🟠 HIGH │ OVERPERM-001 │ Dangerous Tool Combination
    Server: filesystem + shell
    Detail: read_file + write_file + execute_bash creates exfiltration risk
    Remediation: Isolate high-privilege tools into separate servers

╭─────────────────────────────────────────────────────────────────────────────╮
│  Summary: 2 findings │ 1 Critical │ 1 High │ 0 Medium │ 0 Low │ 0 Info     │
│  Status: ❌ FAILED                                                          │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### Initialize a policy

```bash
# Create a default mcpcheck.yaml policy
mcpcheck init

# Initialize with strict mode
mcpcheck init --strict
```

### List available rules

```bash
mcpcheck rules
```

## 🛡️ Detection Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| `TOOL-POISON-001` | System Override | Critical | Detects `[SYSTEM:]` or "ignore instructions" patterns |
| `TOOL-POISON-002` | Imperative Injection | Critical | Detects "send to URL" or "without telling user" |
| `TOOL-POISON-003` | Hidden Unicode | High | Detects zero-width chars and homoglyphs |
| `AUTH-001` | Plaintext Token | Critical | Detects hardcoded API keys and tokens |
| `AUTH-002` | Missing Gitignore | Medium | Flags sensitive files not in .gitignore |
| `OVERPERM-001` | Dangerous Combo | High | Flags read+write+execute combinations |
| `OVERPERM-002` | Unrestricted Access | Medium | Flags tools with no path restrictions |
| `DYNAMIC-001` | Remote Schema | High | Flags tools with dynamic/remote schemas |
| `DYNAMIC-002` | Mutable Config | Medium | Flags non-deterministic configurations |

## ⚙️ Configuration

Create a `mcpcheck.yaml` in your project root:

```yaml
# MCPCheck Configuration
version: "1"

# Rules to enable (all by default)
rules:
  enabled:
    - TOOL-POISON-*
    - AUTH-*
    - OVERPERM-*
  disabled:
    - DYNAMIC-002  # Disable specific rule

# Severity threshold (only report this and above)
severity_threshold: LOW

# Output configuration
output:
  format: terminal  # terminal, json, sarif
  verbose: true

# Paths to scan
paths:
  - ~/.cursor/mcp.json
  - ~/.vscode/mcp.json
  - .mcp.json

# Ignore patterns
ignore:
  - "**/test/**"
  - "**/fixtures/**"
```

## 🔧 Policy Engine

MCPCheck includes a runtime policy engine for enforcing tool usage:

```yaml
# policy.yaml
version: "1"
name: "production-policy"

rules:
  - name: "block-shell"
    condition:
      tool_name_pattern: "^execute_(bash|shell|cmd)$"
    action: BLOCK

  - name: "audit-file-writes"
    condition:
      tool_name: "write_file"
      param_matches:
        path: "^/etc/.*"
    action: AUDIT

  - name: "allow-safe-reads"
    condition:
      tool_name: "read_file"
      param_matches:
        path: "^/tmp/.*"
    action: ALLOW
```

## 🧪 Semantic Analysis (Optional)

Enable LLM-powered deep analysis for detecting sophisticated prompt injections:

```bash
# Using Claude
export ANTHROPIC_API_KEY=sk-ant-...
mcpcheck scan mcp.json --semantic

# Using OpenAI
export OPENAI_API_KEY=sk-...
mcpcheck scan mcp.json --semantic --model openai/gpt-4o

# Using Ollama (local)
mcpcheck scan mcp.json --semantic --model ollama/llama3.2
```

## 📊 CI/CD Integration

### GitHub Actions

```yaml
- name: MCPCheck Security Scan
  run: |
    pip install mcpcheck
    mcpcheck scan . --format sarif -o mcpcheck.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcpcheck.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/yourusername/mcpcheck
    rev: v0.1.0
    hooks:
      - id: mcpcheck
```

## 🐍 Python API

```python
from mcpcheck import scan_manifest
from mcpcheck.domain.models import Severity

# Scan a manifest file
report = scan_manifest("~/.cursor/mcp.json")

# Check results
if not report.passed:
    for finding in report.findings_by_severity(Severity.CRITICAL):
        print(f"{finding.rule_id}: {finding.title}")

# Scan with custom options
from mcpcheck.engine.scanner import RuleEngine, parse_manifest_file

engine = RuleEngine()
manifest = parse_manifest_file("mcp.json")
report = engine.scan(manifest, severity_threshold=Severity.HIGH)

print(report.to_json())
```

## 🏗️ Architecture

MCPCheck follows a **hexagonal (ports & adapters)** architecture:

```
src/mcpcheck/
├── domain/         # Core domain models (Pydantic, zero dependencies)
│   ├── models.py   # Finding, Severity, ToolDefinition, etc.
│   ├── report.py   # ScanReport, ScanSummary
│   └── policy.py   # Policy, PolicyRule
├── rules/          # Detection rules (Protocol-based)
│   ├── base.py     # Rule protocol & BaseRule
│   ├── tool_poison.py
│   ├── auth_exposure.py
│   └── ...
├── engine/         # Core logic
│   ├── scanner.py  # RuleEngine
│   ├── semantic.py # LLM analysis
│   └── policy_engine.py
├── adapters/       # External integrations
│   ├── fs.py       # File system
│   ├── http.py     # HTTP client
│   └── llm.py      # LiteLLM adapter
├── renderers/      # Output formatters
│   ├── terminal.py # Rich terminal
│   ├── json_renderer.py
│   └── sarif_renderer.py
└── cli/            # Typer CLI
    └── main.py
```

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone the repo
git clone https://github.com/yourusername/mcpcheck.git
cd mcpcheck

# Install dev dependencies with uv
uv sync --dev

# Run tests
uv run pytest

# Run linting
uv run ruff check src tests
uv run mypy src

# Install pre-commit hooks
uv run pre-commit install
```

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

## 🔗 Resources

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/)

# MCPHook Usage Guide

## Basic Usage

Scan an MCP manifest for security issues:

```bash
mcphook scan path/to/mcp.json
```

## Output Formats

- Terminal (default)
- JSON: `mcphook scan mcp.json --format json`
- SARIF: `mcphook scan mcp.json --format sarif -o results.sarif`

## Policy Engine

Initialize a policy file:

```bash
mcphook init
```

Strict mode:

```bash
mcphook init --strict
```

## Listing Rules

```bash
mcphook rules
```

## Example: CI Integration

Add to your CI pipeline:

```bash
mcphook scan mcp.json --format sarif -o results.sarif
```

## More

See the README for full details.
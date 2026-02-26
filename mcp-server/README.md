# aikido-mcp

MCP server for [Aikido](https://github.com/Bajuzjefe/Aikido-Security-Analysis-Platform) — security analysis for Aiken smart contracts (Cardano).

Lets any MCP-compatible AI assistant (Claude Code, Cursor, Windsurf) run security scans on Aiken projects inline during development.

## Setup

### Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "aikido": {
      "command": "npx",
      "args": ["-y", "aikido-mcp"]
    }
  }
}
```

### Cursor / Windsurf

Add to `.cursor/mcp.json` or equivalent:

```json
{
  "mcpServers": {
    "aikido": {
      "command": "npx",
      "args": ["-y", "aikido-mcp"]
    }
  }
}
```

### Prerequisites

The `aikido-aiken` binary must be available. Install via:

```bash
npm install -g aikido-aiken
```

Or set `AIKIDO_BINARY` env var to point to the binary.

## Tools

### aikido_analyze

Scan an Aiken project for security vulnerabilities.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `project_path` | string | yes | Path to Aiken project (must contain `aiken.toml`) |
| `min_severity` | enum | no | Minimum severity: info, low, medium, high, critical |
| `static_only` | boolean | no | Skip multi-lane analysis for speed |
| `diff` | string | no | Git ref for incremental analysis |
| `config` | string | no | Path to `.aikido.toml` config |

### aikido_list_rules

List all 75 detectors with severity, category, CWE mapping, and tier.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `severity` | enum | no | Filter by minimum severity |
| `category` | string | no | Filter by category |

### aikido_explain

Detailed explanation of a specific detector.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `detector` | string | yes | Detector name (e.g., `missing-signature-check`) |

### aikido_cwc_lookup

Search the Cardano Weakness Classification registry.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | yes | CWC ID, severity, detector name, or keyword |

## How it works

The server spawns the `aikido` binary with `--format json` and parses the structured output. Binary discovery checks (in order):

1. `AIKIDO_BINARY` environment variable
2. npm sibling (`aikido-aiken` package)
3. `aikido` or `aikido-aiken` on PATH

The CWC lookup tool uses a static registry and does not require the binary.

## License

MIT

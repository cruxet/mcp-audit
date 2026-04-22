# mcp-audit

> Security scanner for Model Context Protocol (MCP) configurations.

[![npm version](https://img.shields.io/npm/v/@cruxet/mcp-audit.svg)](https://www.npmjs.com/package/@cruxet/mcp-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/cruxet/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cruxet/mcp-audit/actions/workflows/ci.yml)

`mcp-audit` scans your MCP configuration files for security vulnerabilities,
including the systemic issues disclosed by OX Security in April 2026
affecting 14+ CVEs across the AI ecosystem.

## Why

In April 2026, [OX Security disclosed a systemic command-injection
vulnerability](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)
in Anthropic's official MCP SDKs. Anthropic declined to patch at the
protocol level — downstream developers inherited the risk.

If you use Cursor, Claude Code, Claude Desktop, Windsurf, VSCode, or any
other MCP-enabled tool, your configuration may be vulnerable. `mcp-audit`
finds these issues before an attacker does.

## Quick Start

```bash
npx @cruxet/mcp-audit
```

That's it. No install required. Auto-discovers MCP configs across every
supported client and reports issues with CVE references and suggested fixes.

## What It Checks

| Rule | Checks for | Severity |
| --- | --- | --- |
| `MCP-AUDIT-001` Command Outside Allowlist | `bash`, `sh`, `cmd.exe`, absolute paths, non-standard launchers | critical / high / medium |
| `MCP-AUDIT-002` Argument Injection | `-c` / `-e` / `--eval` flags, shell metacharacters, `curl … \| sh`, command substitution | critical / high |
| `MCP-AUDIT-003` Hardcoded Secret | OpenAI, Anthropic, GitHub, Slack, Google, AWS, JWT, PEM private keys, Bearer tokens | critical / high / medium |
| `MCP-AUDIT-004` Insecure Transport | `http://` endpoints, exposed loopback, missing Authorization | high / medium / low / info |
| `MCP-AUDIT-005` Environment Injection | `LD_PRELOAD`, `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`, `PYTHONSTARTUP`, `BASH_ENV`, … | critical / high / medium |
| `MCP-AUDIT-006` Suspicious Package | CVE-tagged packages, typosquats of well-known MCP servers | critical / high |
| `MCP-AUDIT-007` Configuration Error | Missing `command`/`url`, conflicting transports, malformed blocks | medium |

CVEs mapped include `CVE-2026-30623` (LiteLLM), `CVE-2026-30615`
(Windsurf), `CVE-2026-34935` (PraisonAI), `CVE-2026-6130` (ChatboxAI),
`CVE-2026-5023` (codebase-mcp), `CVE-2026-30625` (Upsonic),
`CVE-2026-33224` (Bisheng), `CVE-2025-54994`
(`@akoskm/create-mcp-server-stdio`), and others.

## Supported Clients

| Client | Path |
| --- | --- |
| Cursor | `~/.cursor/mcp.json`, `%APPDATA%\Cursor\mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, `%APPDATA%\Claude\claude_desktop_config.json`, `~/.config/Claude/claude_desktop_config.json`, `~/.claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json`, `./.mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| VSCode | `~/Library/Application Support/Code/User/mcp.json`, `%APPDATA%\Code\User\mcp.json`, `~/.config/Code/User/mcp.json`, `./.vscode/mcp.json` |
| Continue.dev | `~/.continue/mcpServers/*.json`, `./.continue/mcpServers/*.json`, `~/.continue/config.json` |
| Codex | `~/.codex/config.toml` |
| Zed | `~/.config/zed/settings.json` |

Project-level `.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, and
`.continue/mcpServers/` are scanned automatically from the current
working directory.

## Usage

```bash
# Auto-discover and scan every supported config on this machine
npx @cruxet/mcp-audit

# Scan a specific file (or many)
npx @cruxet/mcp-audit --config ~/.cursor/mcp.json

# Scan specific project directories
npx @cruxet/mcp-audit --dir ./service-a --dir ./service-b

# Skip global (home) or project scans
npx @cruxet/mcp-audit --skip-global
npx @cruxet/mcp-audit --skip-project

# JSON output for CI/CD
npx @cruxet/mcp-audit --format json > audit-report.json

# SARIF for GitHub Code Scanning
npx @cruxet/mcp-audit --format sarif --output mcp-audit.sarif

# Markdown report
npx @cruxet/mcp-audit --format markdown --output mcp-audit.md

# Hide findings below a threshold (useful for CI)
npx @cruxet/mcp-audit --min-severity high

# Fail CI only on critical+
npx @cruxet/mcp-audit --fail-on critical

# Quiet / verbose
npx @cruxet/mcp-audit --quiet
npx @cruxet/mcp-audit --verbose

# No colors (pipes already auto-disable color)
npx @cruxet/mcp-audit --no-color
```

### Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | No issues (or only findings below `--fail-on`) |
| 1 | Low-severity findings present |
| 2 | Medium-severity findings present |
| 3 | High-severity findings present |
| 4 | Critical-severity findings present |
| 10 | Scan error (invalid flag, unreadable file, …) |

## CI/CD Integration

GitHub Actions with Code Scanning:

```yaml
name: MCP Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "20" }

      - name: Audit MCP configs
        run: npx @cruxet/mcp-audit --format sarif --output mcp-audit.sarif --skip-global

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-audit.sarif
```

Pre-commit hook (`.git/hooks/pre-commit`):

```bash
#!/usr/bin/env bash
npx @cruxet/mcp-audit --skip-global --fail-on high --quiet || {
  echo "mcp-audit found high-severity MCP misconfigurations. Aborting commit." >&2
  exit 1
}
```

## Privacy

`mcp-audit` runs entirely offline:

- No network calls.
- No telemetry.
- No file writes (unless you pass `--output`).
- No LLM calls — this is a deterministic rules engine.

Your MCP configs, secrets, and findings stay on your machine.

## Development

```bash
git clone https://github.com/cruxet/mcp-audit
cd mcp-audit
npm install
npm run dev -- --config ./tests/fixtures/vulnerable-configs/vuln-bash-c.json
npm test
npm run build
```

Project layout:

```
src/
  scanner/      # discovery + parser + orchestrator
  rules/        # rule implementations (one file per rule)
  reporters/    # pretty / json / sarif / markdown
  utils/        # platform, json-locator, logger
tests/
  fixtures/
    safe-configs/
    vulnerable-configs/
```

Each rule is self-contained in `src/rules/<rule>.ts` and exports a
`Rule` object with `id`, `severity`, `category`, an optional `cve` array,
and a `check` function returning `Finding` partials. Adding a new check
is a matter of writing a new `Rule` and registering it in
`src/rules/index.ts`.

## About

`mcp-audit` is built by the [Cruxet](https://github.com/cruxet) team —
we're building secure-by-default context orchestration for AI-native
development teams.

## Contributing

Issues and PRs welcome. For new rules, include:

1. A real-world CVE, advisory, or attack writeup as motivation.
2. At least one fixture under `tests/fixtures/vulnerable-configs/`.
3. At least one fixture under `tests/fixtures/safe-configs/` (to prevent
   false-positive regressions).
4. Three or more Vitest cases in `tests/rules.test.ts`.

## License

MIT © Cruxet

# mcp-audit

> Local, zero-setup security linter for your MCP client configs.

[![npm version](https://img.shields.io/npm/v/@cruxet/mcp-audit.svg)](https://www.npmjs.com/package/@cruxet/mcp-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/cruxet/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cruxet/mcp-audit/actions/workflows/ci.yml)

`mcp-audit` is a static analyzer for Model Context Protocol (MCP) configuration
files. It catches command injection, hardcoded secrets, insecure transports,
dangerous environment variables, and known vulnerable package references across
every major MCP client — **without an account, without a network call, and
without sending anything to a third party.**

```bash
npx @cruxet/mcp-audit
```

That's the whole setup. It finds your configs, scans them with a deterministic
rules engine, and prints actionable fixes. Works on Cursor, Claude Desktop,
Claude Code, Windsurf, VSCode, Continue.dev, Codex, and Zed — on macOS, Linux,
and Windows.

## What this is — and what it isn't

**This is:** a fast, offline linter for MCP *client* configuration files. Think
of it as ESLint for your `~/.cursor/mcp.json` and friends. It looks at the
config you've written and flags operational misconfigurations an attacker
could weaponize — wrong launcher, shell metacharacters in `args`, API keys
committed to disk, `http://` where `https://` belongs, environment variables
that hijack dynamic linking, and packages with known CVEs.

**This is not:** a runtime scanner. `mcp-audit` never starts your MCP servers,
never calls their `tools/list` endpoints, never sends tool descriptions to an
LLM for analysis. If you want to audit what a third-party server *does* at
runtime — prompt injection, tool poisoning, toxic flows — pair `mcp-audit`
with a runtime scanner like
[Snyk Agent Scan](https://github.com/snyk/agent-scan) or
[`@dj_abstract/mcp-audit`](https://www.npmjs.com/package/@dj_abstract/mcp-audit).
They answer "is this server malicious?"; this tool answers "did I configure
it safely?"

## What it checks

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

## Supported clients

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

### Inventory

Sometimes you don't want a scan — you just want to know *what MCP servers you
have configured*. `inventory` lists every server across every discovered
config, grouped by client and scope, with transport and package information.
No rules are evaluated, nothing is flagged.

```bash
# List every MCP server across all discovered configs
npx @cruxet/mcp-audit inventory

# Inspect a single file
npx @cruxet/mcp-audit inventory --config ~/.cursor/mcp.json

# Machine-readable output (for scripting / dashboards / baselines)
npx @cruxet/mcp-audit inventory --format json > mcp-inventory.json
```

Useful for:

- Quick "what's running on my machine?" review before connecting a new server.
- Security reviews and team audits — a single source of truth for MCP surface.
- Capturing a baseline you can diff against later to catch silent additions.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No issues (or only findings below `--fail-on`) |
| 1 | Low-severity findings present |
| 2 | Medium-severity findings present |
| 3 | High-severity findings present |
| 4 | Critical-severity findings present |
| 10 | Scan error (invalid flag, unreadable file, …) |

`inventory` always exits `0` on success.

## CI/CD integration

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
- No account, no API token.

Your MCP configs, secrets, and findings stay on your machine. This makes the
tool safe to run in regulated environments, air-gapped networks, and any
workflow where sending configuration data to a third party is off the table.

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
  inventory.ts  # inventory builder + pretty/json renderers
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

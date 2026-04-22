# Security Policy

## Reporting a vulnerability in `mcp-audit`

If you discover a security issue in `mcp-audit` itself — for example, a
crafted MCP configuration that crashes the scanner, causes arbitrary
file reads outside the declared paths, or leaks config content — please
do **not** open a public issue.

Email **security@cruxet.dev** with:

- A minimal reproducer
- The version of `mcp-audit` you tested against
- Operating system and Node.js version
- Your preferred credit line (or "anonymous")

We aim to respond within 72 hours and ship a fix within 14 days for
high-impact issues.

## Scope

This program covers `mcp-audit` the CLI tool, the rules engine, the
reporters, and the discovery logic. It does **not** cover the MCP
clients (Cursor, Claude, Windsurf, VSCode, …) themselves — those are
the subjects of our scans, not the tool's own attack surface.

## Dependencies

We keep the runtime dependency surface deliberately small:

- `commander`
- `chalk`
- `glob`
- `json5`
- `smol-toml`

No network, telemetry, or LLM dependencies are allowed.

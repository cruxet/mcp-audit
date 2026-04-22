# Contributing to mcp-audit

Thanks for your interest. This project's goal is to keep developers safe
from MCP-related supply-chain attacks. PRs, rule contributions, and
issue reports are all very welcome.

## Ground rules

- **This is a security tool.** We are deliberately conservative with
  dependencies: every new transitive dep should be justified. If a
  feature can be implemented without a new dep, prefer that.
- **No network calls, no telemetry, no LLM calls.** `mcp-audit` is a
  deterministic, offline rules engine. Anything that exfiltrates config
  content is a non-starter.
- **No auto-remediation in v0.x.** We may suggest fixes, but we never
  overwrite the user's config files.

## Adding a new rule

1. Pick a stable rule ID (`MCP-AUDIT-0XX`).
2. Create `src/rules/<slug>.ts` exporting a `Rule`.
3. Register it in `src/rules/index.ts`.
4. Add at least one fixture under `tests/fixtures/vulnerable-configs/`
   that the rule should flag.
5. Add at least one fixture under `tests/fixtures/safe-configs/` that
   the rule must not flag (regression guard against false positives).
6. Add three or more Vitest cases in `tests/rules.test.ts`.
7. Document the rule in `README.md`.

Rules should be as narrowly scoped as possible — false positives erode
user trust faster than missed detections.

## Reporting vulnerabilities

If you find a security issue *in `mcp-audit` itself* (e.g. a crafted
config that crashes the scanner or leaks data), please email us at
`security@cruxet.dev` instead of opening a public issue.

## Development loop

```bash
npm install
npm run dev -- --config ./tests/fixtures/vulnerable-configs/vuln-bash-c.json
npm test
npm run typecheck
```

Please run `npm run build && npm test` before opening a PR.

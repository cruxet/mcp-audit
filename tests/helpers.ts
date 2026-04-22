import type { ConfigFile, MCPServerConfig } from '../src/scanner/types.js';
import type { Rule, RuleContext, Finding } from '../src/rules/types.js';

export function mockConfig(overrides: Partial<ConfigFile> = {}): ConfigFile {
  return {
    path: '/mock/mcp.json',
    client: 'cursor',
    scope: 'global',
    format: 'json',
    parsed: {},
    raw: '{}',
    ...overrides,
  };
}

export function runRule(
  rule: Rule,
  server: MCPServerConfig,
  opts: { serverName?: string; config?: ConfigFile } = {}
): Finding[] {
  const ctx: RuleContext = {
    config: opts.config ?? mockConfig(),
    server,
    serverName: opts.serverName ?? 'test-server',
  };
  const partials = rule.check(ctx);
  return partials.map((p) => ({
    ruleId: rule.id,
    ruleName: rule.name,
    file: ctx.config.path,
    client: ctx.config.client,
    scope: ctx.config.scope,
    serverName: ctx.serverName,
    ...p,
  }));
}

import { discoverConfigs, type DiscoveryOptions, type DiscoveredFile } from './discovery.js';
import { readAndParse } from './parser.js';
import type { ConfigFile, MCPServerConfig } from './types.js';
import { getServerEntries } from './types.js';
import type { Finding, Rule, RuleContext } from '../rules/types.js';
import { allRules } from '../rules/index.js';
import { logger } from '../utils/logger.js';

export interface ScanResult {
  configs: ConfigFile[];
  findings: Finding[];
  errors: Array<{ path: string; message: string }>;
}

export interface ScanOptions extends DiscoveryOptions {
  rules?: Rule[];
}

export async function scan(opts: ScanOptions = {}): Promise<ScanResult> {
  const discovered = await discoverConfigs(opts);
  logger.debug(`Discovered ${discovered.length} candidate config files`);

  const rules = opts.rules ?? allRules;
  const configs: ConfigFile[] = [];
  const findings: Finding[] = [];
  const errors: Array<{ path: string; message: string }> = [];

  for (const d of discovered) {
    const cfg = await readAndParse(d);
    configs.push(cfg);

    if (cfg.parseError) {
      errors.push({ path: cfg.path, message: cfg.parseError });
      logger.warn(`Failed to parse ${cfg.path}: ${cfg.parseError}`);
      continue;
    }

    for (const [serverName, server] of getServerEntries(cfg.parsed)) {
      runRulesForServer(rules, cfg, serverName, server, findings);
    }
  }

  return { configs, findings, errors };
}

function runRulesForServer(
  rules: Rule[],
  cfg: ConfigFile,
  serverName: string,
  server: MCPServerConfig,
  findings: Finding[]
): void {
  const ctx: RuleContext = { config: cfg, server, serverName };
  for (const rule of rules) {
    let partials;
    try {
      partials = rule.check(ctx);
    } catch (err) {
      logger.warn(`Rule ${rule.id} threw while scanning ${cfg.path}#${serverName}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    for (const p of partials) {
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        file: cfg.path,
        client: cfg.client,
        scope: cfg.scope,
        serverName,
        ...p,
      });
    }
  }
}

export type { DiscoveredFile };

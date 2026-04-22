import type { ConfigFile, MCPServerConfig } from '../scanner/types.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type Category =
  | 'command-injection'
  | 'argument-injection'
  | 'insecure-transport'
  | 'secret-exposure'
  | 'suspicious-package'
  | 'environment-injection'
  | 'configuration-error';

export interface Remediation {
  description: string;
  before?: string;
  after?: string;
}

export interface Location {
  line: number;
  column: number;
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: Category;
  file: string;
  client: string;
  scope: string;
  serverName: string;
  message: string;
  matched: string;
  location?: Location;
  cve?: string[];
  references?: string[];
  remediation?: Remediation;
}

export interface RuleContext {
  config: ConfigFile;
  server: MCPServerConfig;
  serverName: string;
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: Category;
  cve?: string[];
  references?: string[];
  check: (ctx: RuleContext) => Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>[];
}

export function makeFinding(
  rule: Pick<Rule, 'id' | 'name'>,
  ctx: RuleContext,
  partial: Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>
): Finding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    file: ctx.config.path,
    client: ctx.config.client,
    scope: ctx.config.scope,
    serverName: ctx.serverName,
    ...partial,
  };
}

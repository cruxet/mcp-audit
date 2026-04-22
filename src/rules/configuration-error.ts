import type { Rule, Finding } from './types.js';
import { detectTransport } from '../scanner/types.js';

export const configurationErrorRule: Rule = {
  id: 'MCP-AUDIT-007',
  name: 'Configuration Error',
  description: 'MCP server entry is malformed or ambiguous (missing command and url, conflicting transport fields, etc.)',
  severity: 'medium',
  category: 'configuration-error',

  check(ctx) {
    const { server, serverName } = ctx;
    const findings: Array<Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>> = [];

    const transport = detectTransport(server);

    if (transport === 'unknown') {
      findings.push({
        severity: 'medium',
        category: 'configuration-error',
        message: `Server "${serverName}" has neither "command" nor "url" set — MCP client will likely fail to start it.`,
        matched: serverName,
        remediation: {
          description: 'Add either a STDIO config (command + args) or an HTTP config (url + optional headers).',
        },
      });
    }

    if (typeof server.command === 'string' && server.command && typeof server.url === 'string' && server.url) {
      findings.push({
        severity: 'medium',
        category: 'configuration-error',
        message: `Server "${serverName}" defines both "command" and "url". Behavior depends on the client and is ambiguous.`,
        matched: serverName,
        remediation: {
          description: 'Use exactly one transport. Remove either the command/args or the url/headers block.',
        },
      });
    }

    if (server.args && !Array.isArray(server.args)) {
      findings.push({
        severity: 'medium',
        category: 'configuration-error',
        message: `Server "${serverName}" has non-array "args" field.`,
        matched: serverName,
      });
    }

    if (server.env && typeof server.env !== 'object') {
      findings.push({
        severity: 'medium',
        category: 'configuration-error',
        message: `Server "${serverName}" has non-object "env" field.`,
        matched: serverName,
      });
    }

    return findings;
  },
};

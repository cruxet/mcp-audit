import type { Rule, Finding, Severity } from './types.js';
import { locateServer } from '../utils/json-locator.js';

/**
 * Packages that have been associated with MCP-related CVEs, malicious
 * releases, or registry poisoning campaigns. The list is intentionally
 * short and conservative — it is expected to be expanded over time via
 * community contributions / CVE feed ingestion.
 */
const KNOWN_RISKY_PACKAGES = new Map<string, { severity: Severity; reason: string; cve?: string[] }>([
  ['@akoskm/create-mcp-server-stdio', { severity: 'critical', reason: 'Command injection in STDIO bootstrap.', cve: ['CVE-2025-54994'] }],
  ['codebase-mcp', { severity: 'critical', reason: 'OS command injection.', cve: ['CVE-2026-5023'] }],
  ['chatbox-ai-mcp', { severity: 'critical', reason: 'StdioClientTransport injection.', cve: ['CVE-2026-6130'] }],
]);

const COMMON_TYPO_TARGETS = new Map<string, string[]>([
  ['@modelcontextprotocol/server-github', ['@modelcontextprotocol/github-server', '@model-context-protocol/server-github', '@modelcontextprotocols/server-github']],
  ['@modelcontextprotocol/server-filesystem', ['@modelcontextprotocol/filesystem', '@model-context-protocol/server-filesystem']],
  ['@modelcontextprotocol/server-slack', ['@modelcontextprotocol/slack-server']],
  ['requests', ['reqeusts', 'requsts', 'requessts']],
  ['openai', ['openai-mcp', 'open-ai']],
]);

const PACKAGE_REGEX = /^(@[A-Za-z0-9][A-Za-z0-9._-]*\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,213}$/;

export const suspiciousPackageRule: Rule = {
  id: 'MCP-AUDIT-006',
  name: 'Suspicious Package Reference',
  description: 'MCP server references a package flagged by CVE feeds or matching typosquatting patterns for well-known MCP servers',
  severity: 'high',
  category: 'suspicious-package',

  check(ctx) {
    const { server, config, serverName } = ctx;
    const findings: Array<Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>> = [];

    if (!Array.isArray(server.args) || server.args.length === 0) return findings;
    if (typeof server.command !== 'string') return findings;

    const cmd = server.command.toLowerCase();
    if (!['npx', 'uvx', 'pipx', 'bunx'].some((safe) => cmd === safe || cmd.endsWith('/' + safe))) {
      return findings;
    }

    for (let i = 0; i < server.args.length; i++) {
      const arg = server.args[i];
      if (typeof arg !== 'string') continue;
      if (arg.startsWith('-')) continue;

      if (!PACKAGE_REGEX.test(arg)) continue;

      const risky = KNOWN_RISKY_PACKAGES.get(arg.toLowerCase());
      if (risky) {
        findings.push({
          severity: risky.severity,
          category: 'suspicious-package',
          message: `Server "${serverName}" references package "${arg}" which is flagged as risky: ${risky.reason}`,
          matched: arg,
          cve: risky.cve,
          location: locateServer(config.raw, serverName, arg),
          remediation: {
            description: `Remove or replace this package. Consult the CVE references before re-enabling.`,
          },
        });
        continue;
      }

      for (const [legit, typos] of COMMON_TYPO_TARGETS) {
        if (typos.includes(arg.toLowerCase())) {
          findings.push({
            severity: 'high',
            category: 'suspicious-package',
            message: `Server "${serverName}" references "${arg}" which looks like a typosquat of the legitimate "${legit}".`,
            matched: arg,
            location: locateServer(config.raw, serverName, arg),
            remediation: {
              description: `Replace with the canonical package: "${legit}".`,
              before: `"args": ["${arg}"]`,
              after: `"args": ["${legit}"]`,
            },
          });
          break;
        }
      }
      break;
    }

    return findings;
  },
};

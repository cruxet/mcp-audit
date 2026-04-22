import type { Rule, Finding } from './types.js';
import { locateServer } from '../utils/json-locator.js';

const DANGEROUS_FLAGS = new Set(['-c', '-e', '--eval', '--exec']);

const SHELL_METACHARACTERS = /(?:;|&&|\|\||&(?!\w)|`|\$\(|\$\{|>|<|\|(?!\|))/;

interface SuspiciousPattern {
  name: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
}

const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  { name: 'remote download via curl', pattern: /curl\s+-?[sSkL]*\s*https?:\/\//i, severity: 'critical' },
  { name: 'remote download via wget', pattern: /\bwget\s+https?:\/\//i, severity: 'critical' },
  { name: 'pipe to shell', pattern: /\|\s*(?:sh|bash|zsh|pwsh|powershell)\b/i, severity: 'critical' },
  { name: 'base64 decode', pattern: /\bbase64\s+(?:-d|--decode)\b/i, severity: 'high' },
  { name: 'command substitution $()', pattern: /\$\([^)]+\)/, severity: 'high' },
  { name: 'backtick substitution', pattern: /`[^`]+`/, severity: 'high' },
  {
    name: 'temp-dir script staging',
    pattern: /(?:^|[^A-Za-z0-9_])(?:\/tmp|\/var\/tmp|\/dev\/shm)\/[^\s/]+\.(?:sh|py|pl|rb|js|exe|ps1)\b/i,
    severity: 'high',
  },
  { name: 'import/exec injection', pattern: /\b(?:os\.system|subprocess\.(?:run|Popen|call)|eval\s*\(|exec\s*\()/i, severity: 'critical' },
];

export const argumentInjectionRule: Rule = {
  id: 'MCP-AUDIT-002',
  name: 'Argument Injection Risk',
  description: 'MCP server arguments contain dangerous flags, shell metacharacters, or known malicious patterns',
  severity: 'critical',
  category: 'argument-injection',
  cve: ['CVE-2026-30615', 'CVE-2026-34935', 'CVE-2026-30623', 'CVE-2026-6130', 'CVE-2026-5023'],
  references: [
    'https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/',
  ],

  check(ctx) {
    const { server, config, serverName } = ctx;
    const findings: Array<Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>> = [];

    if (!Array.isArray(server.args) || server.args.length === 0) return findings;

    const commandLower = (server.command ?? '').toLowerCase();

    for (let i = 0; i < server.args.length; i++) {
      const arg = server.args[i];
      if (typeof arg !== 'string') continue;

      if (DANGEROUS_FLAGS.has(arg)) {
        findings.push({
          severity: 'critical',
          category: 'argument-injection',
          message: `Server uses dangerous flag "${arg}" with command "${server.command ?? '<none>'}". This flag enables arbitrary command/code execution and is the root cause of most MCP RCE CVEs (e.g. the Flowise \`npx -c\` bypass).`,
          matched: arg,
          cve: this.cve,
          references: this.references,
          location: locateServer(config.raw, serverName, arg),
          remediation: {
            description:
              'Remove the eval flag. If you genuinely need to run a one-liner, move it into a vetted script and invoke the script directly.',
            before: `"args": [${server.args.slice(0, i + 1).map((a) => JSON.stringify(a)).join(', ')}, ...]`,
            after: '"args": ["-y", "@your-scope/your-mcp-server"]',
          },
        });
      }

      if (SHELL_METACHARACTERS.test(arg)) {
        findings.push({
          severity: 'high',
          category: 'argument-injection',
          message: `Server argument contains shell metacharacters: ${JSON.stringify(arg)}. Even without a shell interpreter, some MCP clients pass args through \`exec\` implementations that re-interpret metacharacters.`,
          matched: arg,
          cve: this.cve,
          references: this.references,
          location: locateServer(config.raw, serverName, arg),
          remediation: {
            description:
              'Split the argument list so that each token is a single argv entry. Shell metacharacters (; | & $ () `` && ||) should never appear inside args.',
          },
        });
      }

      for (const sp of SUSPICIOUS_PATTERNS) {
        if (sp.pattern.test(arg)) {
          findings.push({
            severity: sp.severity,
            category: 'argument-injection',
            message: `Server argument matches suspicious pattern "${sp.name}": ${JSON.stringify(arg)}.`,
            matched: arg,
            cve: sp.severity === 'critical' ? this.cve : undefined,
            references: this.references,
            location: locateServer(config.raw, serverName, arg),
            remediation: {
              description: `Pattern "${sp.name}" is commonly used in MCP supply-chain payloads (e.g. \`${commandLower || 'bash'} -c 'curl … | sh'\`). Remove or review this argument before running.`,
            },
          });
          break;
        }
      }
    }

    return findings;
  },
};

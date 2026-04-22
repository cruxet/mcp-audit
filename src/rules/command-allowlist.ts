import path from 'node:path';
import type { Rule } from './types.js';
import { locateServer } from '../utils/json-locator.js';

const SAFE_COMMANDS = new Set([
  'npx',
  'uvx',
  'node',
  'python',
  'python3',
  'pipx',
  'deno',
  'bun',
  'uv',
]);

const DANGEROUS_COMMANDS = new Set([
  'bash',
  'sh',
  'zsh',
  'fish',
  'dash',
  'ksh',
  'cmd',
  'cmd.exe',
  'powershell',
  'powershell.exe',
  'pwsh',
  'pwsh.exe',
  'eval',
  'exec',
]);

const ABSOLUTE_PATH_REGEX = /^(\/|[A-Za-z]:[\\/])/;

export const commandAllowlistRule: Rule = {
  id: 'MCP-AUDIT-001',
  name: 'Command Outside Allowlist',
  description: 'MCP server uses a command that is not in the safe allowlist',
  severity: 'high',
  category: 'command-injection',
  cve: ['CVE-2026-30623', 'CVE-2026-34935', 'CVE-2026-30625', 'CVE-2026-33224'],
  references: [
    'https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/',
  ],

  check(ctx) {
    const { server, config } = ctx;
    if (typeof server.command !== 'string' || server.command.length === 0) return [];
    const command = server.command;

    if (ABSOLUTE_PATH_REGEX.test(command)) {
      const baseName = path.basename(command).toLowerCase();
      const isShell = DANGEROUS_COMMANDS.has(baseName);
      return [
        {
          severity: isShell ? 'critical' : 'high',
          category: 'command-injection',
          message: `Server uses an absolute-path command (${command})${
            isShell ? ' that resolves to a dangerous shell' : ''
          }. Direct paths bypass PATH-based allowlists and are a common RCE vector.`,
          matched: command,
          cve: isShell ? this.cve : undefined,
          references: this.references,
          location: locateServer(config.raw, ctx.serverName, command),
          remediation: {
            description: isShell
              ? 'Shell interpreters must never be used to launch MCP servers. Replace with the package runner (npx/uvx) that ships the server.'
              : 'Prefer the command name (resolved via PATH) instead of a hard-coded absolute path.',
            before: `"command": "${command}"`,
            after: isShell
              ? '"command": "npx"  // or "uvx" for Python-based servers'
              : `"command": "${path.basename(command)}"`,
          },
        },
      ];
    }

    const cmdName = command.toLowerCase();

    if (DANGEROUS_COMMANDS.has(cmdName)) {
      return [
        {
          severity: 'critical',
          category: 'command-injection',
          message: `Server launches via dangerous shell interpreter "${command}". This pattern is associated with most MCP RCE CVEs.`,
          matched: command,
          cve: this.cve,
          references: this.references,
          location: locateServer(config.raw, ctx.serverName, command),
          remediation: {
            description:
              'Shell interpreters should never be used to launch MCP servers. Use the package runner (npx/uvx/pipx) or the direct executable.',
            before: `"command": "${command}"`,
            after: '"command": "npx"  // or "uvx" for Python-based servers',
          },
        },
      ];
    }

    if (!SAFE_COMMANDS.has(cmdName)) {
      return [
        {
          severity: 'medium',
          category: 'command-injection',
          message: `Server uses non-standard command "${command}". Verify this binary is trusted; standard MCP launchers are npx, uvx, node, python, pipx, deno, bun.`,
          matched: command,
          references: this.references,
          location: locateServer(config.raw, ctx.serverName, command),
          remediation: {
            description:
              'Confirm the command is trusted. If possible, route through a standard launcher (npx/uvx) so version pinning and provenance checks apply.',
          },
        },
      ];
    }

    return [];
  },
};

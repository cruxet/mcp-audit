import type { Rule, Finding } from './types.js';
import { locateServer } from '../utils/json-locator.js';

const DANGEROUS_ENV_KEYS = new Map<string, { severity: 'critical' | 'high' | 'medium'; reason: string }>([
  ['LD_PRELOAD', { severity: 'critical', reason: 'LD_PRELOAD injects shared libraries into every dynamically linked binary — a classic privilege-escalation and supply-chain vector.' }],
  ['LD_LIBRARY_PATH', { severity: 'high', reason: 'LD_LIBRARY_PATH alters library search order and can be abused to hijack linkage.' }],
  ['LD_AUDIT', { severity: 'critical', reason: 'LD_AUDIT loads an auditing shared library before the dynamic linker runs.' }],
  ['DYLD_INSERT_LIBRARIES', { severity: 'critical', reason: 'DYLD_INSERT_LIBRARIES is the macOS analogue of LD_PRELOAD and enables code injection.' }],
  ['DYLD_LIBRARY_PATH', { severity: 'high', reason: 'DYLD_LIBRARY_PATH hijacks macOS library resolution.' }],
  ['DYLD_FALLBACK_LIBRARY_PATH', { severity: 'high', reason: 'Falls back to attacker-controlled library paths.' }],
  ['NODE_OPTIONS', { severity: 'high', reason: 'NODE_OPTIONS can force Node to --require arbitrary modules on startup.' }],
  ['PYTHONSTARTUP', { severity: 'high', reason: 'PYTHONSTARTUP executes a Python file before every interactive session.' }],
  ['PYTHONPATH', { severity: 'medium', reason: 'PYTHONPATH can shadow standard library modules with attacker-controlled code.' }],
  ['NODE_PATH', { severity: 'medium', reason: 'NODE_PATH can shadow npm packages with attacker-controlled code.' }],
  ['PATH', { severity: 'medium', reason: 'Manipulating PATH lets an attacker shadow trusted binaries with look-alikes.' }],
  ['BASH_ENV', { severity: 'critical', reason: 'BASH_ENV executes a script whenever a non-interactive bash shell starts.' }],
  ['ENV', { severity: 'high', reason: 'POSIX ENV file is sourced by some shells on every invocation.' }],
  ['SHELLOPTS', { severity: 'medium', reason: 'Changes default shell options.' }],
]);

export const environmentInjectionRule: Rule = {
  id: 'MCP-AUDIT-005',
  name: 'Environment Variable Injection',
  description: 'MCP server env block sets variables that can hijack process startup (LD_PRELOAD, NODE_OPTIONS, etc.)',
  severity: 'critical',
  category: 'environment-injection',

  check(ctx) {
    const { server, config, serverName } = ctx;
    const findings: Array<Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>> = [];

    if (!server.env || typeof server.env !== 'object') return findings;

    for (const [rawKey, rawValue] of Object.entries(server.env)) {
      const key = rawKey;
      const info = DANGEROUS_ENV_KEYS.get(key.toUpperCase());
      if (!info) continue;

      const value = typeof rawValue === 'string' ? rawValue : JSON.stringify(rawValue);

      findings.push({
        severity: info.severity,
        category: 'environment-injection',
        message: `Server "${serverName}" sets ${key} in env. ${info.reason}`,
        matched: `${key}=${value.length > 40 ? value.slice(0, 37) + '…' : value}`,
        location: locateServer(config.raw, serverName, key),
        remediation: {
          description: `Remove ${key} from the server env block. If the server genuinely needs library overrides, package it so the dependency is bundled.`,
          before: `"env": { "${key}": "${value}" }`,
          after: `"env": { /* ${key} removed */ }`,
        },
      });
    }

    return findings;
  },
};

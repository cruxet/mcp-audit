import type { Rule, Finding, Severity } from './types.js';
import { locateServer } from '../utils/json-locator.js';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Severity;
}

const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'OpenAI API Key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/, severity: 'critical' },
  { name: 'Anthropic API Key', pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, severity: 'critical' },
  { name: 'GitHub Personal Access Token', pattern: /\bghp_[A-Za-z0-9]{36}\b/, severity: 'critical' },
  { name: 'GitHub OAuth Token', pattern: /\bgho_[A-Za-z0-9]{36}\b/, severity: 'critical' },
  { name: 'GitHub App Token', pattern: /\b(?:ghs|ghu)_[A-Za-z0-9]{36}\b/, severity: 'critical' },
  { name: 'Slack Bot Token', pattern: /\bxox[baprs]-[0-9]{10,}-[0-9A-Za-z-]{10,}/, severity: 'critical' },
  { name: 'Google API Key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'high' },
  { name: 'AWS Access Key ID', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, severity: 'critical' },
  { name: 'JWT Token', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: 'medium' },
  { name: 'PEM Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical' },
  { name: 'Stripe Secret Key', pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/, severity: 'critical' },
];

function redact(value: string): string {
  if (value.length <= 10) return value.slice(0, 2) + '…';
  return value.slice(0, 8) + '…' + value.slice(-2);
}

export const secretDetectionRule: Rule = {
  id: 'MCP-AUDIT-003',
  name: 'Hardcoded Secret',
  description: 'Hardcoded API key, token, or private key found in MCP configuration',
  severity: 'critical',
  category: 'secret-exposure',
  references: [
    'https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning',
  ],

  check(ctx) {
    const { server, config, serverName } = ctx;
    const findings: Array<Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>> = [];

    const scan = (source: 'env' | 'headers' | 'args' | 'url', key: string, value: string): void => {
      if (value.startsWith('${') || value.includes('{{')) return;
      for (const pat of SECRET_PATTERNS) {
        const m = pat.pattern.exec(value);
        if (!m) continue;
        const secretSlice = m[0];
        findings.push({
          severity: pat.severity,
          category: 'secret-exposure',
          message: `Hardcoded ${pat.name} detected in server "${serverName}" ${source}.${key}`,
          matched: `${key}=${redact(secretSlice)}`,
          references: this.references,
          location: locateServer(config.raw, serverName, secretSlice),
          remediation: {
            description: 'Never commit secrets to config files. Use environment variable expansion supported by the MCP client.',
            before: `"${source}": { "${key}": "${redact(secretSlice)}" }`,
            after: `"${source}": { "${key}": "\${env:${key}}" }`,
          },
        });
        return;
      }
    };

    if (server.env && typeof server.env === 'object') {
      for (const [k, v] of Object.entries(server.env)) {
        if (typeof v !== 'string') continue;
        scan('env', k, v);
      }
    }

    if (server.headers && typeof server.headers === 'object') {
      for (const [k, v] of Object.entries(server.headers)) {
        if (typeof v !== 'string') continue;

        scan('headers', k, v);

        if (k.toLowerCase() === 'authorization' && /^Bearer\s+[A-Za-z0-9_\-.]{20,}$/.test(v) && !v.includes('${')) {
          const token = v.slice(7);
          findings.push({
            severity: 'high',
            category: 'secret-exposure',
            message: `Hardcoded Bearer token in server "${serverName}" headers.${k}`,
            matched: `${k}=Bearer ${redact(token)}`,
            references: this.references,
            location: locateServer(config.raw, serverName, token),
            remediation: {
              description: 'Use environment variable expansion for authorization tokens.',
              before: `"headers": { "Authorization": "Bearer ${redact(token)}" }`,
              after: `"headers": { "Authorization": "Bearer \${env:API_TOKEN}" }`,
            },
          });
        }
      }
    }

    if (Array.isArray(server.args)) {
      for (let i = 0; i < server.args.length; i++) {
        const a = server.args[i];
        if (typeof a === 'string') scan('args', `[${i}]`, a);
      }
    }

    if (typeof server.url === 'string') {
      scan('url', 'value', server.url);
    }

    return findings;
  },
};

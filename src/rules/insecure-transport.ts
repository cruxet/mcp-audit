import type { Rule, Finding } from './types.js';
import { locateServer } from '../utils/json-locator.js';

const PRIVATE_HOST_REGEX = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\]|\[fc[0-9a-f]{2}:.*\])$/i;

const WELL_KNOWN_PROVIDERS = new Set([
  'mcp.render.com',
  'mcp.anthropic.com',
  'api.anthropic.com',
  'mcp.composio.dev',
  'mcp.github.com',
  'server.smithery.ai',
]);

export const insecureTransportRule: Rule = {
  id: 'MCP-AUDIT-004',
  name: 'Insecure Transport',
  description: 'HTTP/SSE MCP server uses an insecure or exposed transport configuration',
  severity: 'high',
  category: 'insecure-transport',

  check(ctx) {
    const { server, config, serverName } = ctx;
    const findings: Array<Omit<Finding, 'ruleId' | 'ruleName' | 'file' | 'client' | 'scope' | 'serverName'>> = [];

    if (typeof server.url !== 'string' || server.url.length === 0) return findings;
    const url = server.url;

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      findings.push({
        severity: 'medium',
        category: 'insecure-transport',
        message: `Server "${serverName}" has an unparseable URL: ${url}`,
        matched: url,
        location: locateServer(config.raw, serverName, url),
        remediation: {
          description: 'Provide a valid absolute URL (scheme://host[:port]/path).',
        },
      });
      return findings;
    }

    if (parsed.protocol === 'http:') {
      const isLoopback = PRIVATE_HOST_REGEX.test(parsed.hostname);
      findings.push({
        severity: isLoopback ? 'medium' : 'high',
        category: 'insecure-transport',
        message: `Server "${serverName}" uses non-TLS http:// transport${
          isLoopback ? ' (loopback/private host — still vulnerable to local MITM and DNS rebinding).' : '. Tokens and prompts are transmitted in cleartext.'
        }`,
        matched: url,
        location: locateServer(config.raw, serverName, url),
        remediation: {
          description: 'Use https:// for all remote MCP servers. For local development, prefer stdio transport over plain http.',
          before: `"url": "${url}"`,
          after: `"url": "${url.replace(/^http:/, 'https:')}"`,
        },
      });
    }

    if (PRIVATE_HOST_REGEX.test(parsed.hostname) && parsed.protocol !== 'http:') {
      findings.push({
        severity: 'low',
        category: 'insecure-transport',
        message: `Server "${serverName}" points at a loopback/private host (${parsed.hostname}). Make sure this server is not accidentally exposed to the network.`,
        matched: url,
        location: locateServer(config.raw, serverName, url),
        remediation: {
          description: 'Loopback MCP servers should bind to 127.0.0.1 only and never be exposed via 0.0.0.0 or public interfaces.',
        },
      });
    }

    const hasAuth =
      (server.headers &&
        Object.keys(server.headers).some((k) => k.toLowerCase() === 'authorization' || k.toLowerCase().startsWith('x-api'))) ||
      /[?&](api[_-]?key|token|auth)=/i.test(parsed.search);

    if (!hasAuth && parsed.protocol === 'https:' && !PRIVATE_HOST_REGEX.test(parsed.hostname)) {
      const wellKnown = WELL_KNOWN_PROVIDERS.has(parsed.hostname.toLowerCase());
      findings.push({
        severity: wellKnown ? 'info' : 'medium',
        category: 'insecure-transport',
        message: `Server "${serverName}" at ${parsed.hostname} has no Authorization/API key header. ${
          wellKnown ? 'This provider usually handles auth separately, but double-check.' : 'Unauthenticated MCP endpoints can be hijacked or abused.'
        }`,
        matched: url,
        location: locateServer(config.raw, serverName, url),
        remediation: {
          description: 'Add an Authorization header or API key query string. Prefer env-var expansion instead of hardcoding.',
          after: `"headers": { "Authorization": "Bearer \${env:${serverName.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_TOKEN}" }`,
        },
      });
    }

    return findings;
  },
};

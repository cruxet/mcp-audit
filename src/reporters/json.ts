import type { Reporter } from './types.js';
import type { ScanResult } from '../scanner/index.js';

export const jsonReporter: Reporter = {
  format: 'json',

  render(result: ScanResult): string {
    const summary = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of result.findings) summary[f.severity]++;

    const payload = {
      tool: 'mcp-audit',
      version: process.env.MCP_AUDIT_VERSION ?? '0.1.0',
      scannedAt: new Date().toISOString(),
      configs: result.configs.map((c) => ({
        path: c.path,
        client: c.client,
        scope: c.scope,
        format: c.format,
        parseError: c.parseError,
      })),
      findings: result.findings,
      summary: {
        total: result.findings.length,
        bySeverity: summary,
        parseErrors: result.errors,
      },
    };

    return JSON.stringify(payload, null, 2) + '\n';
  },
};

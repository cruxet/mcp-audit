import type { Reporter } from './types.js';
import type { ScanResult } from '../scanner/index.js';
import type { Severity } from '../rules/types.js';
import { allRules } from '../rules/index.js';

const SEV_TO_SARIF: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'warning',
  info: 'note',
};

const SEV_TO_SCORE: Record<Severity, string> = {
  critical: '9.8',
  high: '7.5',
  medium: '5.0',
  low: '3.0',
  info: '1.0',
};

export const sarifReporter: Reporter = {
  format: 'sarif',

  render(result: ScanResult): string {
    const rules = allRules.map((r) => ({
      id: r.id,
      name: r.name,
      shortDescription: { text: r.name },
      fullDescription: { text: r.description },
      helpUri: r.references?.[0],
      properties: {
        category: r.category,
        cve: r.cve ?? [],
        'security-severity': SEV_TO_SCORE[r.severity],
      },
    }));

    const results = result.findings.map((f) => ({
      ruleId: f.ruleId,
      level: SEV_TO_SARIF[f.severity],
      message: {
        text: f.message,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: toUri(f.file) },
            region: f.location
              ? {
                  startLine: f.location.line,
                  startColumn: f.location.column,
                }
              : { startLine: 1 },
          },
          logicalLocations: [
            {
              name: f.serverName,
              kind: 'property',
            },
          ],
        },
      ],
      properties: {
        serverName: f.serverName,
        client: f.client,
        scope: f.scope,
        cve: f.cve ?? [],
        remediation: f.remediation?.description ?? null,
        'security-severity': SEV_TO_SCORE[f.severity],
      },
    }));

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'mcp-audit',
              version: process.env.MCP_AUDIT_VERSION ?? '0.2.1',
              informationUri: 'https://github.com/cruxet/mcp-audit',
              rules,
            },
          },
          results,
        },
      ],
    };

    return JSON.stringify(sarif, null, 2) + '\n';
  },
};

function toUri(p: string): string {
  const normalized = p.replace(/\\/g, '/');
  if (/^[A-Za-z]:\//.test(normalized)) {
    return 'file:///' + normalized;
  }
  if (normalized.startsWith('/')) {
    return 'file://' + normalized;
  }
  return normalized;
}

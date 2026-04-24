import type { Reporter } from './types.js';
import type { ScanResult } from '../scanner/index.js';
import type { Finding, Severity } from '../rules/types.js';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL: Record<Severity, string> = {
  critical: '🔴 Critical',
  high: '🟠 High',
  medium: '🟡 Medium',
  low: '🔵 Low',
  info: '⚪ Info',
};

export const markdownReporter: Reporter = {
  format: 'markdown',

  render(result: ScanResult): string {
    const out: string[] = [];
    out.push('# MCP Audit Report');
    out.push('');
    out.push(`- **Generated:** ${new Date().toISOString()}`);
    out.push(`- **Tool:** mcp-audit v${process.env.MCP_AUDIT_VERSION ?? '0.2.1'}`);
    out.push(`- **Configs scanned:** ${result.configs.length}`);
    out.push(`- **Findings:** ${result.findings.length}`);
    out.push('');

    out.push('## Scanned configurations');
    out.push('');
    out.push('| Path | Client | Scope | Parse error |');
    out.push('| --- | --- | --- | --- |');
    for (const c of result.configs) {
      out.push(`| \`${c.path}\` | ${c.client} | ${c.scope} | ${c.parseError ? '`' + c.parseError + '`' : '—'} |`);
    }
    out.push('');

    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of result.findings) counts[f.severity]++;

    out.push('## Summary');
    out.push('');
    out.push('| Severity | Count |');
    out.push('| --- | --- |');
    for (const sev of SEV_ORDER) out.push(`| ${SEV_LABEL[sev]} | ${counts[sev]} |`);
    out.push('');

    if (result.findings.length === 0) {
      out.push('> No issues found. ✅');
      return out.join('\n') + '\n';
    }

    out.push('## Findings');
    out.push('');
    for (const sev of SEV_ORDER) {
      const byThisSev = result.findings.filter((f) => f.severity === sev);
      if (byThisSev.length === 0) continue;
      out.push(`### ${SEV_LABEL[sev]} (${byThisSev.length})`);
      out.push('');
      for (const f of byThisSev) out.push(renderFinding(f));
    }

    return out.join('\n') + '\n';
  },
};

function renderFinding(f: Finding): string {
  const lines: string[] = [];
  lines.push(`#### [${f.ruleId}] ${f.ruleName}`);
  lines.push('');
  lines.push(`- **Server:** \`${f.serverName}\``);
  lines.push(`- **File:** \`${f.file}\`${f.location ? ` (line ${f.location.line}, col ${f.location.column})` : ''}`);
  lines.push(`- **Category:** ${f.category}`);
  if (f.cve && f.cve.length > 0) lines.push(`- **CVEs:** ${f.cve.join(', ')}`);
  lines.push('');
  lines.push(f.message);
  if (f.matched) {
    lines.push('');
    lines.push('```');
    lines.push(f.matched);
    lines.push('```');
  }
  if (f.remediation) {
    lines.push('');
    lines.push(`**Fix:** ${f.remediation.description}`);
    if (f.remediation.before && f.remediation.after) {
      lines.push('');
      lines.push('```diff');
      lines.push('- ' + f.remediation.before);
      lines.push('+ ' + f.remediation.after);
      lines.push('```');
    }
  }
  if (f.references && f.references.length > 0) {
    lines.push('');
    lines.push('**References:**');
    for (const r of f.references) lines.push(`- ${r}`);
  }
  lines.push('');
  return lines.join('\n');
}

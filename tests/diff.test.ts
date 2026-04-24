import { describe, it, expect } from 'vitest';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import url from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import {
  diffReports,
  fingerprint,
  maxAddedSeverity,
  renderDiffJson,
  renderDiffMarkdown,
  renderDiffPretty,
  type ScanReportLike,
} from '../src/diff.js';
import type { Finding } from '../src/rules/types.js';
import { scan } from '../src/scanner/index.js';

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CLI_ENTRY = path.resolve(__dirname, '../bin/mcp-audit.js');
const VULN_DIR = path.resolve(__dirname, 'fixtures/vulnerable-configs');
const SAFE_DIR = path.resolve(__dirname, 'fixtures/safe-configs');

const execFileP = promisify(execFile);

function f(partial: Partial<Finding>): Finding {
  return {
    ruleId: 'MCP-AUDIT-001',
    ruleName: 'Test Rule',
    severity: 'high',
    category: 'command-injection',
    file: '/fake/path.json',
    client: 'cursor',
    scope: 'global',
    serverName: 'test',
    message: 'test message',
    matched: 'bash',
    ...partial,
  };
}

function report(findings: Finding[]): ScanReportLike {
  return { tool: 'mcp-audit', findings };
}

describe('diff fingerprint', () => {
  it('treats identical rule/file/server/matched/category as same fingerprint', () => {
    expect(fingerprint(f({}))).toBe(fingerprint(f({})));
  });

  it('is independent of severity and message', () => {
    const a = f({ severity: 'high', message: 'old wording' });
    const b = f({ severity: 'critical', message: 'new wording' });
    expect(fingerprint(a)).toBe(fingerprint(b));
  });

  it('differs when matched value differs', () => {
    expect(fingerprint(f({ matched: 'bash' }))).not.toBe(fingerprint(f({ matched: 'sh' })));
  });
});

describe('diffReports()', () => {
  it('detects added findings', () => {
    const baseline = report([]);
    const current = report([f({ ruleId: 'MCP-AUDIT-001', matched: 'bash' })]);
    const d = diffReports(baseline, current);
    expect(d.added).toHaveLength(1);
    expect(d.removed).toHaveLength(0);
    expect(d.changed).toHaveLength(0);
    expect(d.unchanged).toHaveLength(0);
  });

  it('detects removed findings', () => {
    const baseline = report([f({ ruleId: 'MCP-AUDIT-001', matched: 'bash' })]);
    const current = report([]);
    const d = diffReports(baseline, current);
    expect(d.removed).toHaveLength(1);
    expect(d.added).toHaveLength(0);
  });

  it('detects severity escalation as `changed` (not add+remove)', () => {
    const baseline = report([f({ severity: 'medium' })]);
    const current = report([f({ severity: 'critical' })]);
    const d = diffReports(baseline, current);
    expect(d.added).toHaveLength(0);
    expect(d.removed).toHaveLength(0);
    expect(d.changed).toHaveLength(1);
    expect(d.changed[0]!.baseline.severity).toBe('medium');
    expect(d.changed[0]!.current.severity).toBe('critical');
    expect(d.changed[0]!.delta).toBeGreaterThan(0);
  });

  it('reports unchanged findings', () => {
    const baseline = report([f({ severity: 'high' })]);
    const current = report([f({ severity: 'high' })]);
    const d = diffReports(baseline, current);
    expect(d.unchanged).toHaveLength(1);
    expect(d.added).toHaveLength(0);
    expect(d.removed).toHaveLength(0);
  });

  it('handles multiple findings sharing the same fingerprint', () => {
    const baseline = report([f({}), f({})]);
    const current = report([f({}), f({}), f({})]);
    const d = diffReports(baseline, current);
    expect(d.added).toHaveLength(1);
    expect(d.unchanged).toHaveLength(2);
  });

  it('sorts added findings by severity (critical first)', () => {
    const current = report([f({ severity: 'low', matched: 'a' }), f({ severity: 'critical', matched: 'b' })]);
    const d = diffReports(report([]), current);
    expect(d.added[0]!.finding.severity).toBe('critical');
    expect(d.added[1]!.finding.severity).toBe('low');
  });

  it('copes with missing findings arrays on either side', () => {
    const d = diffReports({ findings: [] } as ScanReportLike, { findings: [] } as ScanReportLike);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
  });
});

describe('maxAddedSeverity()', () => {
  it('returns the highest severity among added findings', () => {
    const baseline = report([]);
    const current = report([f({ severity: 'low' }), f({ severity: 'critical', matched: 'x' })]);
    expect(maxAddedSeverity(diffReports(baseline, current))).toBe('critical');
  });

  it('considers escalated findings as well', () => {
    const baseline = report([f({ severity: 'medium' })]);
    const current = report([f({ severity: 'high' })]);
    expect(maxAddedSeverity(diffReports(baseline, current))).toBe('high');
  });

  it('returns null when nothing new/escalated', () => {
    expect(maxAddedSeverity(diffReports(report([f({})]), report([f({})])))).toBeNull();
  });
});

describe('diff renderers', () => {
  const baseline = report([f({ severity: 'medium', matched: 'foo' })]);
  const current = report([
    f({ severity: 'critical', matched: 'foo' }),
    f({ severity: 'high', matched: 'bar', ruleId: 'MCP-AUDIT-008' }),
  ]);

  it('renders JSON that round-trips', () => {
    const diff = diffReports(baseline, current);
    const out = renderDiffJson(diff);
    const parsed = JSON.parse(out) as { summary: { added: number; changed: number } };
    expect(parsed.summary.added).toBe(1);
    expect(parsed.summary.changed).toBe(1);
  });

  it('renders markdown with section headers', () => {
    const md = renderDiffMarkdown(diffReports(baseline, current));
    expect(md).toContain('# MCP Audit Diff');
    expect(md).toContain('## New findings (1)');
    expect(md).toContain('## Changed severity (1)');
  });

  it('renders pretty output', () => {
    const pretty = renderDiffPretty(diffReports(baseline, current));
    expect(pretty).toContain('MCP Audit diff');
    expect(pretty).toContain('New findings: 1');
    expect(pretty).toContain('Changed severity: 1');
  });

  it('pretty output celebrates when nothing changed', () => {
    const d = diffReports(report([f({})]), report([f({})]));
    const pretty = renderDiffPretty(d);
    expect(pretty).toContain('No new or escalated findings');
  });
});

describe('diff CLI end-to-end', () => {
  it('runs `mcp-audit diff` and exits non-zero when a new high finding appears', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-audit-diff-'));
    try {
      const safeReport = await scan({
        explicitPaths: [path.join(SAFE_DIR, 'safe-npx.json')],
        skipGlobal: true,
        skipProject: true,
      });
      const vulnReport = await scan({
        explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
        skipGlobal: true,
        skipProject: true,
      });

      const baselinePath = path.join(tmp, 'baseline.json');
      const currentPath = path.join(tmp, 'current.json');
      await fs.writeFile(baselinePath, JSON.stringify({ tool: 'mcp-audit', findings: safeReport.findings }));
      await fs.writeFile(currentPath, JSON.stringify({ tool: 'mcp-audit', findings: vulnReport.findings }));

      const result = await execFileP(
        process.execPath,
        [CLI_ENTRY, 'diff', baselinePath, currentPath, '--fail-on-new', 'high', '--format', 'json'],
        { encoding: 'utf8' }
      ).catch((e: NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: number }) => e);

      const err = result as NodeJS.ErrnoException & { code?: number | string; stdout?: string };
      expect(typeof err.code === 'number' ? err.code : 0).toBeGreaterThanOrEqual(3);
      expect(err.stdout).toBeDefined();
      const parsed = JSON.parse(err.stdout!) as { summary: { added: number } };
      expect(parsed.summary.added).toBeGreaterThanOrEqual(1);
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });

  it('exits 0 when the two reports have the same findings', async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-audit-diff-'));
    try {
      const result = await scan({
        explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
        skipGlobal: true,
        skipProject: true,
      });
      const reportPath = path.join(tmp, 'report.json');
      await fs.writeFile(reportPath, JSON.stringify({ tool: 'mcp-audit', findings: result.findings }));

      const res = await execFileP(
        process.execPath,
        [CLI_ENTRY, 'diff', reportPath, reportPath, '--fail-on-new', 'critical', '--format', 'json'],
        { encoding: 'utf8' }
      );
      const parsed = JSON.parse(res.stdout) as { summary: { added: number; unchanged: number } };
      expect(parsed.summary.added).toBe(0);
      expect(parsed.summary.unchanged).toBeGreaterThan(0);
    } finally {
      await fs.rm(tmp, { recursive: true, force: true });
    }
  });
});

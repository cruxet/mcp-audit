import chalk from 'chalk';
import type { Finding, Severity } from './rules/types.js';
import { SEVERITY_ORDER } from './rules/types.js';

/**
 * Minimal shape of a JSON scan report. We only depend on `findings`; other
 * fields are optional so the diff also works against files produced by older
 * or newer versions of mcp-audit.
 */
export interface ScanReportLike {
  tool?: string;
  version?: string;
  scannedAt?: string;
  findings: Finding[];
}

export interface DiffEntry {
  fingerprint: string;
  finding: Finding;
}

export interface ChangedSeverity {
  fingerprint: string;
  baseline: Finding;
  current: Finding;
  /** Positive when severity escalated, negative when de-escalated. */
  delta: number;
}

export interface DiffResult {
  added: DiffEntry[];
  removed: DiffEntry[];
  changed: ChangedSeverity[];
  unchanged: DiffEntry[];
  baselineTotal: number;
  currentTotal: number;
}

/**
 * Compute a stable, content-based fingerprint for a finding so we can
 * correlate "the same issue" across two scan runs even when the raw file
 * was re-formatted and line numbers shifted.
 *
 * We deliberately exclude `severity` here so that a rule whose severity
 * changed (e.g. after a CVE publication) still matches up, and surfaces
 * as a `changed` entry instead of `removed` + `added`.
 */
export function fingerprint(f: Finding): string {
  return [f.ruleId, f.client, f.scope, f.serverName, f.category, f.matched].join('::');
}

/**
 * Diff two scan reports and bucket findings into added/removed/changed/
 * unchanged. When a fingerprint maps to multiple findings on either side
 * (e.g. the same rule firing twice on the same server) we pair them up
 * positionally — any left-over entries count as added or removed.
 */
export function diffReports(baseline: ScanReportLike, current: ScanReportLike): DiffResult {
  const baseGroups = groupByFingerprint(baseline.findings ?? []);
  const curGroups = groupByFingerprint(current.findings ?? []);

  const added: DiffEntry[] = [];
  const removed: DiffEntry[] = [];
  const changed: ChangedSeverity[] = [];
  const unchanged: DiffEntry[] = [];

  const allFingerprints = new Set<string>([...baseGroups.keys(), ...curGroups.keys()]);

  for (const fp of allFingerprints) {
    const b = baseGroups.get(fp) ?? [];
    const c = curGroups.get(fp) ?? [];
    const pairs = Math.min(b.length, c.length);

    for (let i = 0; i < pairs; i++) {
      const prev = b[i]!;
      const cur = c[i]!;
      const delta = SEVERITY_ORDER[cur.severity] - SEVERITY_ORDER[prev.severity];
      if (delta !== 0) {
        changed.push({ fingerprint: fp, baseline: prev, current: cur, delta });
      } else {
        unchanged.push({ fingerprint: fp, finding: cur });
      }
    }
    for (let i = pairs; i < b.length; i++) {
      removed.push({ fingerprint: fp, finding: b[i]! });
    }
    for (let i = pairs; i < c.length; i++) {
      added.push({ fingerprint: fp, finding: c[i]! });
    }
  }

  const sortBySev = <T extends { finding: Finding } | { current: Finding }>(arr: T[]) =>
    arr.sort((a, b) => {
      const fa = 'finding' in a ? a.finding : a.current;
      const fb = 'finding' in b ? b.finding : b.current;
      return SEVERITY_ORDER[fb.severity] - SEVERITY_ORDER[fa.severity];
    });

  sortBySev(added);
  sortBySev(removed);
  sortBySev(changed);

  return {
    added,
    removed,
    changed,
    unchanged,
    baselineTotal: baseline.findings?.length ?? 0,
    currentTotal: current.findings?.length ?? 0,
  };
}

function groupByFingerprint(findings: Finding[]): Map<string, Finding[]> {
  const m = new Map<string, Finding[]>();
  for (const f of findings) {
    const fp = fingerprint(f);
    const existing = m.get(fp);
    if (existing) existing.push(f);
    else m.set(fp, [f]);
  }
  return m;
}

/**
 * Maximum severity among the newly-added findings — used for `--fail-on-new`.
 */
export function maxAddedSeverity(diff: DiffResult): Severity | null {
  let rank = -1;
  for (const e of diff.added) {
    if (SEVERITY_ORDER[e.finding.severity] > rank) rank = SEVERITY_ORDER[e.finding.severity];
  }
  for (const c of diff.changed) {
    if (c.delta > 0 && SEVERITY_ORDER[c.current.severity] > rank) {
      rank = SEVERITY_ORDER[c.current.severity];
    }
  }
  if (rank < 0) return null;
  return rankToSeverity(rank);
}

function rankToSeverity(rank: number): Severity {
  const entries = Object.entries(SEVERITY_ORDER) as Array<[Severity, number]>;
  for (const [sev, r] of entries) if (r === rank) return sev;
  return 'info';
}

/* -------------------------------------------------------------------------- */
/* Renderers                                                                   */
/* -------------------------------------------------------------------------- */

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.bold.red(s),
  high: (s) => chalk.red(s),
  medium: (s) => chalk.yellow(s),
  low: (s) => chalk.cyan(s),
  info: (s) => chalk.gray(s),
};

const SEV_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH    ',
  medium: 'MEDIUM  ',
  low: 'LOW     ',
  info: 'INFO    ',
};

export function renderDiffPretty(diff: DiffResult): string {
  const out: string[] = [];
  out.push('');
  out.push(chalk.bold.cyan('🔍 MCP Audit diff'));
  out.push(
    chalk.gray(
      `  baseline: ${diff.baselineTotal} findings   current: ${diff.currentTotal} findings`
    )
  );
  out.push('');

  renderBucket(out, 'New findings', diff.added, 'added');
  renderChangedBucket(out, diff.changed);
  renderBucket(out, 'Resolved', diff.removed, 'removed');

  const unchangedLine = `Unchanged: ${diff.unchanged.length}`;
  out.push(chalk.gray(unchangedLine));
  out.push('');

  const newMax = maxAddedSeverity(diff);
  if (diff.added.length === 0 && diff.changed.filter((c) => c.delta > 0).length === 0) {
    out.push(chalk.green('✓ No new or escalated findings.'));
  } else {
    out.push(
      chalk.yellow(
        `! ${diff.added.length} new, ${diff.changed.filter((c) => c.delta > 0).length} escalated` +
          (newMax ? ` (highest new severity: ${newMax})` : '')
      )
    );
  }
  out.push('');

  return out.join('\n');
}

function renderBucket(
  out: string[],
  title: string,
  entries: DiffEntry[],
  kind: 'added' | 'removed'
): void {
  const color = kind === 'added' ? chalk.bold.red : chalk.bold.green;
  const prefix = kind === 'added' ? chalk.red('+') : chalk.green('-');
  out.push(color(`${title}: ${entries.length}`));
  if (entries.length === 0) {
    out.push(chalk.gray('  (none)'));
    out.push('');
    return;
  }
  for (const e of entries) {
    const f = e.finding;
    const sev = SEV_COLOR[f.severity](`[${SEV_LABEL[f.severity].trim()}]`);
    out.push(
      `  ${prefix} ${sev} ${chalk.bold(f.ruleId)}  ${chalk.white(f.ruleName)}  — ` +
        chalk.gray(`"${f.serverName}" in ${shortPath(f.file)}`)
    );
    if (f.matched) out.push(chalk.gray(`      ↳ ${truncate(f.matched, 120)}`));
  }
  out.push('');
}

function renderChangedBucket(out: string[], changed: ChangedSeverity[]): void {
  out.push(chalk.bold.yellow(`Changed severity: ${changed.length}`));
  if (changed.length === 0) {
    out.push(chalk.gray('  (none)'));
    out.push('');
    return;
  }
  for (const c of changed) {
    const arrow = c.delta > 0 ? chalk.red('↑') : chalk.green('↓');
    const before = SEV_COLOR[c.baseline.severity](SEV_LABEL[c.baseline.severity].trim());
    const after = SEV_COLOR[c.current.severity](SEV_LABEL[c.current.severity].trim());
    out.push(
      `  ${arrow} ${before} → ${after}  ${chalk.bold(c.current.ruleId)}  — ` +
        chalk.gray(`"${c.current.serverName}" in ${shortPath(c.current.file)}`)
    );
  }
  out.push('');
}

function shortPath(p: string): string {
  if (!p) return '<unknown>';
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (home && p.startsWith(home)) return '~' + p.slice(home.length);
  return p;
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

export function renderDiffJson(diff: DiffResult): string {
  const payload = {
    tool: 'mcp-audit',
    mode: 'diff',
    version: process.env.MCP_AUDIT_VERSION ?? '0.2.0',
    generatedAt: new Date().toISOString(),
    summary: {
      baselineTotal: diff.baselineTotal,
      currentTotal: diff.currentTotal,
      added: diff.added.length,
      removed: diff.removed.length,
      changed: diff.changed.length,
      unchanged: diff.unchanged.length,
      maxAddedSeverity: maxAddedSeverity(diff),
    },
    added: diff.added.map((e) => e.finding),
    removed: diff.removed.map((e) => e.finding),
    changed: diff.changed.map((c) => ({
      ruleId: c.current.ruleId,
      serverName: c.current.serverName,
      file: c.current.file,
      from: c.baseline.severity,
      to: c.current.severity,
      delta: c.delta,
    })),
  };
  return JSON.stringify(payload, null, 2) + '\n';
}

export function renderDiffMarkdown(diff: DiffResult): string {
  const lines: string[] = [];
  lines.push('# MCP Audit Diff');
  lines.push('');
  lines.push(
    `**Baseline:** ${diff.baselineTotal} findings  |  **Current:** ${diff.currentTotal} findings`
  );
  lines.push('');

  lines.push(`## New findings (${diff.added.length})`);
  lines.push('');
  if (diff.added.length === 0) {
    lines.push('_None._');
  } else {
    for (const e of diff.added) lines.push(renderFindingRow('+', e.finding));
  }
  lines.push('');

  lines.push(`## Resolved (${diff.removed.length})`);
  lines.push('');
  if (diff.removed.length === 0) {
    lines.push('_None._');
  } else {
    for (const e of diff.removed) lines.push(renderFindingRow('-', e.finding));
  }
  lines.push('');

  lines.push(`## Changed severity (${diff.changed.length})`);
  lines.push('');
  if (diff.changed.length === 0) {
    lines.push('_None._');
  } else {
    for (const c of diff.changed) {
      const arrow = c.delta > 0 ? '↑' : '↓';
      lines.push(
        `- ${arrow} \`${c.current.ruleId}\` **${c.baseline.severity}** → **${c.current.severity}** — \`${c.current.serverName}\` (${c.current.file})`
      );
    }
  }
  lines.push('');

  lines.push(`## Unchanged (${diff.unchanged.length})`);
  lines.push('');

  return lines.join('\n') + '\n';
}

function renderFindingRow(prefix: string, f: Finding): string {
  return `- ${prefix} **[${f.severity.toUpperCase()}]** \`${f.ruleId}\` ${f.ruleName} — \`${f.serverName}\` in \`${f.file}\``;
}

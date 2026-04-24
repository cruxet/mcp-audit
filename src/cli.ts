import { Command } from 'commander';
import fs from 'node:fs/promises';
import chalk from 'chalk';
import { scan } from './scanner/index.js';
import { getReporter, type ReporterFormat } from './reporters/index.js';
import { logger } from './utils/logger.js';
import { SEVERITY_ORDER, type Severity } from './rules/types.js';
import { buildInventory, renderInventoryPretty, renderInventoryJson } from './inventory.js';
import {
  diffReports,
  maxAddedSeverity,
  renderDiffPretty,
  renderDiffJson,
  renderDiffMarkdown,
  type ScanReportLike,
} from './diff.js';

const VERSION = '0.2.1';
process.env.MCP_AUDIT_VERSION = VERSION;

interface ScanCliOptions {
  config?: string[];
  dir?: string[];
  format: ReporterFormat;
  output?: string;
  minSeverity: Severity;
  failOn?: Severity;
  skipGlobal: boolean;
  skipProject: boolean;
  verbose: boolean;
  quiet: boolean;
  color: boolean;
}

interface InventoryCliOptions {
  config?: string[];
  dir?: string[];
  format: 'pretty' | 'json';
  output?: string;
  skipGlobal: boolean;
  skipProject: boolean;
  verbose: boolean;
  quiet: boolean;
  color: boolean;
}

interface DiffCliOptions {
  format: 'pretty' | 'json' | 'markdown';
  output?: string;
  failOnNew?: Severity;
  verbose: boolean;
  quiet: boolean;
  color: boolean;
}

const program = new Command()
  .name('mcp-audit')
  .description('Local, zero-setup security linter for MCP client configs.')
  .version(VERSION)
  .addHelpText(
    'after',
    `\nExamples:\n  $ npx mcp-audit\n  $ npx mcp-audit --config ~/.cursor/mcp.json\n  $ npx mcp-audit --format json > report.json\n  $ npx mcp-audit --fail-on high\n  $ npx mcp-audit inventory\n  $ npx mcp-audit diff baseline.json current.json --fail-on-new high\n\nExit codes:\n  0 — clean (or only findings below --fail-on)\n  1 — low-severity findings present\n  2 — medium-severity findings present\n  3 — high-severity findings present\n  4 — critical-severity findings present\n  10 — scan error\n`
  );

program
  .command('scan', { isDefault: true })
  .description('Scan discovered MCP configs for security issues (default)')
  .option('-c, --config <path...>', 'Specific config file(s) to scan (disables auto-discovery)')
  .option('-d, --dir <path...>', 'Project directories to scan (defaults to cwd)')
  .option('-f, --format <format>', 'Output format: pretty | json | sarif | markdown', 'pretty')
  .option('-o, --output <file>', 'Write report to file instead of stdout')
  .option('--min-severity <severity>', 'Hide findings below this severity (info|low|medium|high|critical)', 'info')
  .option('--fail-on <severity>', 'Exit with non-zero code if any finding at or above this severity is present')
  .option('--skip-global', 'Skip auto-discovery of global (home-directory) configs', false)
  .option('--skip-project', 'Skip auto-discovery of project (cwd) configs', false)
  .option('-v, --verbose', 'Verbose output', false)
  .option('-q, --quiet', 'Suppress non-essential output', false)
  .option('--no-color', 'Disable colored output')
  .action(async (rawOpts: ScanCliOptions) => {
    const opts = normalizeScanOpts(rawOpts);
    configureLogger(opts);

    try {
      const result = await scan({
        explicitPaths: opts.config,
        projectRoots: opts.dir,
        skipGlobal: opts.skipGlobal,
        skipProject: opts.skipProject,
      });

      const minRank = SEVERITY_ORDER[opts.minSeverity];
      result.findings = result.findings.filter((f) => SEVERITY_ORDER[f.severity] >= minRank);

      const reporter = getReporter(opts.format);
      const rendered = reporter.render(result);

      if (opts.output) {
        await fs.writeFile(opts.output, rendered, 'utf8');
        if (!opts.quiet) logger.info(`Report written to ${opts.output}`);
      } else {
        process.stdout.write(rendered);
      }

      process.exit(computeExitCode(result.findings.map((f) => f.severity), opts.failOn));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(msg);
      if (opts.verbose && err instanceof Error && err.stack) {
        logger.error(err.stack);
      }
      process.exit(10);
    }
  });

program
  .command('inventory')
  .description('List every MCP server discovered across your configs (no security scan)')
  .option('-c, --config <path...>', 'Specific config file(s) to inspect (disables auto-discovery)')
  .option('-d, --dir <path...>', 'Project directories to scan (defaults to cwd)')
  .option('-f, --format <format>', 'Output format: pretty | json', 'pretty')
  .option('-o, --output <file>', 'Write inventory to file instead of stdout')
  .option('--skip-global', 'Skip auto-discovery of global (home-directory) configs', false)
  .option('--skip-project', 'Skip auto-discovery of project (cwd) configs', false)
  .option('-v, --verbose', 'Verbose output', false)
  .option('-q, --quiet', 'Suppress non-essential output', false)
  .option('--no-color', 'Disable colored output')
  .action(async (rawOpts: InventoryCliOptions) => {
    const opts = normalizeInventoryOpts(rawOpts);
    configureLogger(opts);

    try {
      const inv = await buildInventory({
        explicitPaths: opts.config,
        projectRoots: opts.dir,
        skipGlobal: opts.skipGlobal,
        skipProject: opts.skipProject,
      });

      const rendered = opts.format === 'json' ? renderInventoryJson(inv) : renderInventoryPretty(inv);

      if (opts.output) {
        await fs.writeFile(opts.output, rendered, 'utf8');
        if (!opts.quiet) logger.info(`Inventory written to ${opts.output}`);
      } else {
        process.stdout.write(rendered);
      }

      process.exit(0);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(msg);
      if (opts.verbose && err instanceof Error && err.stack) {
        logger.error(err.stack);
      }
      process.exit(10);
    }
  });

program
  .command('diff')
  .description('Compare two JSON scan reports and surface new / resolved / escalated findings')
  .argument('<baseline>', 'Path to baseline JSON scan report (produced by `mcp-audit --format json`)')
  .argument('<current>', 'Path to current JSON scan report')
  .option('-f, --format <format>', 'Output format: pretty | json | markdown', 'pretty')
  .option('-o, --output <file>', 'Write diff to file instead of stdout')
  .option(
    '--fail-on-new <severity>',
    'Exit non-zero if a new or escalated finding at or above this severity appears'
  )
  .option('-v, --verbose', 'Verbose output', false)
  .option('-q, --quiet', 'Suppress non-essential output', false)
  .option('--no-color', 'Disable colored output')
  .action(async (baselinePath: string, currentPath: string, rawOpts: DiffCliOptions) => {
    const opts = normalizeDiffOpts(rawOpts);
    configureLogger(opts);

    try {
      const [baseline, current] = await Promise.all([
        loadScanReport(baselinePath, 'baseline'),
        loadScanReport(currentPath, 'current'),
      ]);

      const diff = diffReports(baseline, current);

      let rendered: string;
      if (opts.format === 'json') rendered = renderDiffJson(diff);
      else if (opts.format === 'markdown') rendered = renderDiffMarkdown(diff);
      else rendered = renderDiffPretty(diff);

      if (opts.output) {
        await fs.writeFile(opts.output, rendered, 'utf8');
        if (!opts.quiet) logger.info(`Diff written to ${opts.output}`);
      } else {
        process.stdout.write(rendered);
      }

      if (opts.failOnNew) {
        const newMax = maxAddedSeverity(diff);
        if (newMax && SEVERITY_ORDER[newMax] >= SEVERITY_ORDER[opts.failOnNew]) {
          // Use exitCode + return so stdout finishes flushing before process exits.
          process.exitCode = severityToExit(newMax);
          return;
        }
      }
      process.exitCode = 0;
      return;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.error(msg);
      if (opts.verbose && err instanceof Error && err.stack) {
        logger.error(err.stack);
      }
      process.exitCode = 10;
      return;
    }
  });

async function loadScanReport(filePath: string, label: string): Promise<ScanReportLike> {
  let raw: string;
  try {
    raw = await fs.readFile(filePath, 'utf8');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to read ${label} report "${filePath}": ${msg}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to parse ${label} report "${filePath}" as JSON: ${msg}`);
  }
  if (typeof parsed !== 'object' || parsed === null || !Array.isArray((parsed as { findings?: unknown }).findings)) {
    throw new Error(
      `${label} report "${filePath}" is missing a "findings" array. ` +
        `Generate it with: mcp-audit --format json --output ${label}.json`
    );
  }
  return parsed as ScanReportLike;
}

function normalizeScanOpts(raw: ScanCliOptions): ScanCliOptions {
  const sevValues: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
  const minSeverity = raw.minSeverity as Severity;
  if (!sevValues.includes(minSeverity)) {
    logger.error(`Invalid --min-severity value: ${raw.minSeverity}. Use one of: ${sevValues.join(', ')}`);
    process.exit(10);
  }
  if (raw.failOn && !sevValues.includes(raw.failOn as Severity)) {
    logger.error(`Invalid --fail-on value: ${raw.failOn}. Use one of: ${sevValues.join(', ')}`);
    process.exit(10);
  }
  const fmtValues: ReporterFormat[] = ['pretty', 'json', 'sarif', 'markdown'];
  if (!fmtValues.includes(raw.format as ReporterFormat)) {
    logger.error(`Invalid --format value: ${raw.format}. Use one of: ${fmtValues.join(', ')}`);
    process.exit(10);
  }
  return { ...raw, minSeverity, format: raw.format as ReporterFormat };
}

function normalizeInventoryOpts(raw: InventoryCliOptions): InventoryCliOptions {
  const fmtValues = ['pretty', 'json'] as const;
  if (!fmtValues.includes(raw.format as (typeof fmtValues)[number])) {
    logger.error(`Invalid --format value: ${raw.format}. Use one of: ${fmtValues.join(', ')}`);
    process.exit(10);
  }
  return { ...raw, format: raw.format as 'pretty' | 'json' };
}

function normalizeDiffOpts(raw: DiffCliOptions): DiffCliOptions {
  const fmtValues = ['pretty', 'json', 'markdown'] as const;
  if (!fmtValues.includes(raw.format as (typeof fmtValues)[number])) {
    logger.error(`Invalid --format value: ${raw.format}. Use one of: ${fmtValues.join(', ')}`);
    process.exit(10);
  }
  if (raw.failOnNew) {
    const sevValues: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];
    if (!sevValues.includes(raw.failOnNew as Severity)) {
      logger.error(`Invalid --fail-on-new value: ${raw.failOnNew}. Use one of: ${sevValues.join(', ')}`);
      process.exit(10);
    }
  }
  return { ...raw, format: raw.format as 'pretty' | 'json' | 'markdown' };
}

function configureLogger(opts: { quiet: boolean; verbose: boolean; color: boolean }): void {
  if (opts.quiet) logger.setLevel('quiet');
  else if (opts.verbose) logger.setLevel('verbose');
  else logger.setLevel('normal');
  if (opts.color === false) chalk.level = 0;
}

function computeExitCode(severities: Severity[], failOn?: Severity): number {
  if (severities.length === 0) return 0;

  const maxRank = severities.reduce((acc, s) => Math.max(acc, SEVERITY_ORDER[s]), -1);

  if (failOn) {
    return maxRank >= SEVERITY_ORDER[failOn] ? severityToExit(rankToSeverity(maxRank)) : 0;
  }

  return severityToExit(rankToSeverity(maxRank));
}

function rankToSeverity(rank: number): Severity {
  const entries = Object.entries(SEVERITY_ORDER) as Array<[Severity, number]>;
  for (const [sev, r] of entries) if (r === rank) return sev;
  return 'info';
}

function severityToExit(sev: Severity): number {
  switch (sev) {
    case 'critical':
      return 4;
    case 'high':
      return 3;
    case 'medium':
      return 2;
    case 'low':
      return 1;
    case 'info':
    default:
      return 0;
  }
}

program.parseAsync(process.argv).catch((err) => {
  logger.error(err instanceof Error ? err.message : String(err));
  process.exit(10);
});

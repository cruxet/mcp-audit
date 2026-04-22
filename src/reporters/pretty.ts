import chalk from 'chalk';
import type { Reporter } from './types.js';
import type { ScanResult } from '../scanner/index.js';
import type { Finding, Severity } from '../rules/types.js';
import { SEVERITY_ORDER } from '../rules/types.js';

const SEV_ICON: Record<Severity, string> = {
  critical: '⛔',
  high: '⚠',
  medium: '⚡',
  low: 'ℹ',
  info: '·',
};

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.bgRed.whiteBright(' ' + s + ' '),
  high: (s) => chalk.bgYellow.black(' ' + s + ' '),
  medium: (s) => chalk.bgMagenta.whiteBright(' ' + s + ' '),
  low: (s) => chalk.bgBlue.whiteBright(' ' + s + ' '),
  info: (s) => chalk.bgGray.whiteBright(' ' + s + ' '),
};

const DIVIDER = chalk.gray('─'.repeat(68));
const DOUBLE_DIVIDER = chalk.gray('═'.repeat(68));

export const prettyReporter: Reporter = {
  format: 'pretty',

  render(result: ScanResult): string {
    const out: string[] = [];
    out.push('');
    out.push(chalk.bold.cyan('🔍 MCP Audit') + chalk.gray(` v${getVersion()}`));
    out.push(chalk.gray('Scanning MCP configurations for security issues...'));
    out.push('');

    if (result.configs.length === 0) {
      out.push(chalk.yellow('No MCP configuration files found.'));
      out.push(chalk.gray('Tip: pass --config <path> to scan a specific file.'));
      return out.join('\n') + '\n';
    }

    out.push(chalk.bold(`Found ${result.configs.length} config file${result.configs.length === 1 ? '' : 's'}:`));
    for (const cfg of result.configs) {
      const err = cfg.parseError ? chalk.red('  (parse error: ' + cfg.parseError + ')') : '';
      out.push(`  ${chalk.green('✓')} ${cfg.path} ${chalk.gray(`(${cfg.client}, ${cfg.scope})`)}${err}`);
    }
    out.push('');

    if (result.findings.length === 0) {
      out.push(DOUBLE_DIVIDER);
      out.push('');
      out.push(chalk.green.bold('  ✓ No issues found.'));
      out.push('');
      return out.join('\n') + '\n';
    }

    const grouped = groupBySeverity(result.findings);

    const severities: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const sev of severities) {
      const items = grouped[sev];
      if (!items || items.length === 0) continue;
      out.push(DOUBLE_DIVIDER);
      out.push('');
      out.push(`${SEV_ICON[sev]} ${SEV_COLOR[sev](sev.toUpperCase())} ${chalk.bold(`(${items.length})`)}`);
      out.push(DIVIDER);

      for (const f of items) {
        out.push('');
        out.push(`${chalk.bold(`[${f.ruleId}]`)} ${chalk.bold(f.ruleName)}`);
        const loc = f.location ? chalk.gray(`:${f.location.line}:${f.location.column}`) : '';
        out.push(`  ${chalk.gray('File:')} ${f.file}${loc}  ${chalk.gray(`(${f.client}, ${f.scope})`)}`);
        out.push(`  ${chalk.gray('Server:')} ${chalk.cyan(`"${f.serverName}"`)}`);
        out.push('');
        out.push(indent(f.message, 2));

        if (f.matched) {
          out.push('');
          out.push(indent(chalk.dim('Matched: ') + chalk.yellow(f.matched), 2));
        }

        if (f.cve && f.cve.length > 0) {
          out.push('');
          out.push(indent(chalk.gray('Related CVEs: ') + f.cve.map((c) => chalk.magentaBright(c)).join(', '), 2));
        }

        if (f.remediation) {
          out.push('');
          out.push(indent(chalk.green('Fix: ') + f.remediation.description, 2));
          if (f.remediation.before && f.remediation.after) {
            out.push('');
            out.push(indent(chalk.red('  - ') + chalk.red(f.remediation.before), 2));
            out.push(indent(chalk.green('  + ') + chalk.green(f.remediation.after), 2));
          } else if (f.remediation.after) {
            out.push('');
            out.push(indent(chalk.green('  ' + f.remediation.after), 2));
          }
        }

        if (f.references && f.references.length > 0) {
          out.push('');
          for (const r of f.references) {
            out.push(indent(chalk.gray('See: ') + chalk.underline.blue(r), 2));
          }
        }

        out.push(DIVIDER);
      }
    }

    out.push('');
    out.push(DOUBLE_DIVIDER);
    out.push('');
    out.push(chalk.bold('Summary:'));
    for (const sev of severities) {
      const items = grouped[sev] ?? [];
      if (items.length === 0 && sev !== 'critical' && sev !== 'high') continue;
      out.push(`  ${SEV_ICON[sev]} ${sev.padEnd(8)} ${items.length}`);
    }

    if (result.errors.length > 0) {
      out.push('');
      out.push(chalk.yellow(`  ${result.errors.length} file${result.errors.length === 1 ? '' : 's'} could not be parsed.`));
    }

    const total = result.findings.length;
    out.push('');
    out.push(
      total === 0
        ? chalk.green.bold('  ✓ No issues.')
        : chalk.red.bold(`  ✗ ${total} issue${total === 1 ? '' : 's'} found across ${result.configs.length} config${result.configs.length === 1 ? '' : 's'}.`)
    );
    out.push('');
    out.push(chalk.gray('  Docs & issues: https://github.com/cruxet/mcp-audit'));
    out.push('');
    return out.join('\n') + '\n';
  },
};

function groupBySeverity(findings: Finding[]): Partial<Record<Severity, Finding[]>> {
  const out: Partial<Record<Severity, Finding[]>> = {};
  for (const f of findings) {
    (out[f.severity] ??= []).push(f);
  }
  for (const sev of Object.keys(out) as Severity[]) {
    out[sev]!.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  }
  return out;
}

function indent(text: string, spaces: number): string {
  const pad = ' '.repeat(spaces);
  return text
    .split('\n')
    .map((line) => pad + line)
    .join('\n');
}

function getVersion(): string {
  return process.env.MCP_AUDIT_VERSION ?? '0.1.0';
}

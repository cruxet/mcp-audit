import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import url from 'node:url';
import chalk from 'chalk';
import { scan } from '../src/scanner/index.js';
import { jsonReporter, sarifReporter, markdownReporter, prettyReporter } from '../src/reporters/index.js';

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const VULN_DIR = path.resolve(__dirname, 'fixtures/vulnerable-configs');

beforeAll(() => {
  chalk.level = 0;
});

describe('reporters', () => {
  it('json reporter produces valid JSON with findings', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const out = jsonReporter.render(result);
    const parsed = JSON.parse(out);
    expect(parsed.tool).toBe('mcp-audit');
    expect(parsed.findings.length).toBeGreaterThan(0);
    expect(parsed.summary.total).toBe(parsed.findings.length);
  });

  it('sarif reporter produces SARIF 2.1.0 schema', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const out = sarifReporter.render(result);
    const parsed = JSON.parse(out);
    expect(parsed.version).toBe('2.1.0');
    expect(parsed.runs[0].tool.driver.name).toBe('mcp-audit');
    expect(parsed.runs[0].results.length).toBeGreaterThan(0);
  });

  it('markdown reporter mentions severities', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const out = markdownReporter.render(result);
    expect(out).toContain('# MCP Audit Report');
    expect(out).toContain('Critical');
  });

  it('pretty reporter handles empty results', () => {
    const out = prettyReporter.render({ configs: [], findings: [], errors: [] });
    expect(out).toContain('No MCP configuration files found');
  });

  it('pretty reporter shows summary with issues', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const out = prettyReporter.render(result);
    expect(out).toContain('MCP Audit');
    expect(out).toContain('issue');
  });
});

import { describe, it, expect } from 'vitest';
import path from 'node:path';
import url from 'node:url';
import { scan } from '../src/scanner/index.js';

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SAFE_DIR = path.resolve(__dirname, 'fixtures/safe-configs');
const VULN_DIR = path.resolve(__dirname, 'fixtures/vulnerable-configs');

describe('scan() integration', () => {
  it('reports no critical/high findings on safe configs', async () => {
    const result = await scan({
      explicitPaths: [
        path.join(SAFE_DIR, 'safe-http.json'),
        path.join(SAFE_DIR, 'safe-npx.json'),
      ],
      skipGlobal: true,
      skipProject: true,
    });
    const severe = result.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
    expect(severe).toHaveLength(0);
  });

  it('detects critical findings in bash -c fixture', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
      skipGlobal: true,
      skipProject: true,
    });
    expect(result.findings.some((f) => f.severity === 'critical')).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'MCP-AUDIT-001')).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'MCP-AUDIT-002')).toBe(true);
  });

  it('detects npx -c Flowise-style bypass', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-npx-c-bypass.json')],
      skipGlobal: true,
      skipProject: true,
    });
    expect(result.findings.some((f) => f.severity === 'critical' && f.ruleId === 'MCP-AUDIT-002')).toBe(true);
  });

  it('detects hardcoded OpenAI key', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-hardcoded-key.json')],
      skipGlobal: true,
      skipProject: true,
    });
    expect(result.findings.some((f) => f.ruleId === 'MCP-AUDIT-003' && f.severity === 'critical')).toBe(true);
  });

  it('detects absolute-path /bin/sh', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-absolute-path.json')],
      skipGlobal: true,
      skipProject: true,
    });
    expect(result.findings.some((f) => f.ruleId === 'MCP-AUDIT-001' && f.severity === 'critical')).toBe(true);
  });

  it('detects shell metacharacters', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-shell-meta.json')],
      skipGlobal: true,
      skipProject: true,
    });
    expect(result.findings.some((f) => f.ruleId === 'MCP-AUDIT-002')).toBe(true);
  });

  it('detects LD_PRELOAD + NODE_OPTIONS', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-ld-preload.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const envFindings = result.findings.filter((f) => f.ruleId === 'MCP-AUDIT-005');
    expect(envFindings.length).toBeGreaterThanOrEqual(2);
  });

  it('detects insecure http:// transport', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-http-transport.json')],
      skipGlobal: true,
      skipProject: true,
    });
    expect(result.findings.some((f) => f.ruleId === 'MCP-AUDIT-004' && f.severity === 'high')).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'MCP-AUDIT-003')).toBe(true);
  });

  it('records location for findings', async () => {
    const result = await scan({
      explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const withLoc = result.findings.find((f) => f.location);
    expect(withLoc?.location?.line).toBeGreaterThan(0);
  });
});

import { describe, it, expect } from 'vitest';
import path from 'node:path';
import url from 'node:url';
import { buildInventory, renderInventoryJson, renderInventoryPretty } from '../src/inventory.js';

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SAFE_DIR = path.resolve(__dirname, 'fixtures/safe-configs');
const VULN_DIR = path.resolve(__dirname, 'fixtures/vulnerable-configs');

describe('buildInventory()', () => {
  it('lists servers from a safe npx config with package refs', async () => {
    const inv = await buildInventory({
      explicitPaths: [path.join(SAFE_DIR, 'safe-npx.json')],
      skipGlobal: true,
      skipProject: true,
    });

    expect(inv.totalConfigs).toBe(1);
    expect(inv.totalServers).toBe(2);

    const group = inv.groups[0]!;
    const names = group.servers.map((s) => s.serverName).sort();
    expect(names).toEqual(['filesystem', 'github']);

    const packages = inv.uniquePackages.sort();
    expect(packages).toContain('@modelcontextprotocol/server-github');
    expect(packages).toContain('@modelcontextprotocol/server-filesystem');
  });

  it('reports http transport for url-based servers', async () => {
    const inv = await buildInventory({
      explicitPaths: [path.join(SAFE_DIR, 'safe-http.json')],
      skipGlobal: true,
      skipProject: true,
    });

    expect(inv.transportCounts.http).toBeGreaterThanOrEqual(1);
    const server = inv.groups[0]!.servers[0]!;
    expect(server.transport).toBe('http');
    expect(server.url).toMatch(/^https:/);
  });

  it('merges inventory across multiple configs and deduplicates packages', async () => {
    const inv = await buildInventory({
      explicitPaths: [
        path.join(SAFE_DIR, 'safe-npx.json'),
        path.join(SAFE_DIR, 'safe-http.json'),
      ],
      skipGlobal: true,
      skipProject: true,
    });

    expect(inv.totalConfigs).toBe(2);
    expect(inv.groups.length).toBe(2);
    expect(inv.totalServers).toBeGreaterThanOrEqual(3);
  });

  it('records servers from vulnerable fixtures but does not flag them (no security scan)', async () => {
    const inv = await buildInventory({
      explicitPaths: [path.join(VULN_DIR, 'vuln-bash-c.json')],
      skipGlobal: true,
      skipProject: true,
    });

    expect(inv.totalServers).toBeGreaterThanOrEqual(1);
    const server = inv.groups[0]!.servers[0]!;
    expect(server.command).toBeDefined();
    expect(server.transport).toBe('stdio');
  });

  it('returns an empty inventory when no configs are discovered', async () => {
    const inv = await buildInventory({ skipGlobal: true, skipProject: true });
    expect(inv.groups).toEqual([]);
    expect(inv.totalServers).toBe(0);
    expect(inv.totalConfigs).toBe(0);
  });
});

describe('renderInventory* reporters', () => {
  it('renders JSON that round-trips through JSON.parse', async () => {
    const inv = await buildInventory({
      explicitPaths: [path.join(SAFE_DIR, 'safe-npx.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const json = renderInventoryJson(inv);
    const parsed = JSON.parse(json) as { totalServers: number; groups: unknown[] };
    expect(parsed.totalServers).toBe(inv.totalServers);
    expect(Array.isArray(parsed.groups)).toBe(true);
  });

  it('renders pretty output with server names and transport labels', async () => {
    const inv = await buildInventory({
      explicitPaths: [path.join(SAFE_DIR, 'safe-npx.json')],
      skipGlobal: true,
      skipProject: true,
    });
    const pretty = renderInventoryPretty(inv);
    expect(pretty).toContain('"github"');
    expect(pretty).toContain('"filesystem"');
    expect(pretty).toContain('[stdio]');
  });

  it('renders the empty-state message when no configs are found', async () => {
    const inv = await buildInventory({ skipGlobal: true, skipProject: true });
    const pretty = renderInventoryPretty(inv);
    expect(pretty).toContain('No MCP configuration files found');
  });
});

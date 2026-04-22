import chalk from 'chalk';
import { discoverConfigs, type DiscoveryOptions } from './scanner/discovery.js';
import { readAndParse } from './scanner/parser.js';
import {
  getServerEntries,
  detectTransport,
  type ClientKind,
  type ConfigScope,
  type MCPServerConfig,
  type TransportKind,
} from './scanner/types.js';

export interface InventoryEntry {
  serverName: string;
  transport: TransportKind;
  command?: string;
  args?: string[];
  url?: string;
  packageRef?: string;
}

export interface InventoryGroup {
  client: ClientKind;
  scope: ConfigScope;
  path: string;
  servers: InventoryEntry[];
}

export interface Inventory {
  groups: InventoryGroup[];
  totalServers: number;
  totalConfigs: number;
  transportCounts: Record<TransportKind, number>;
  uniquePackages: string[];
  errors: Array<{ path: string; message: string }>;
}

export async function buildInventory(opts: DiscoveryOptions = {}): Promise<Inventory> {
  const discovered = await discoverConfigs(opts);
  const groups: InventoryGroup[] = [];
  const transportCounts: Record<TransportKind, number> = { stdio: 0, http: 0, sse: 0, unknown: 0 };
  const packageSet = new Set<string>();
  const errors: Array<{ path: string; message: string }> = [];

  for (const d of discovered) {
    const cfg = await readAndParse(d);
    if (cfg.parseError) {
      errors.push({ path: cfg.path, message: cfg.parseError });
      continue;
    }

    const entries = getServerEntries(cfg.parsed);
    const servers: InventoryEntry[] = entries.map(([name, server]) => {
      const transport = detectTransport(server);
      transportCounts[transport]++;
      const pkg = extractPackageRef(server);
      if (pkg) packageSet.add(pkg);
      return {
        serverName: name,
        transport,
        command: typeof server.command === 'string' ? server.command : undefined,
        args: normalizeStringArray(server.args),
        url: typeof server.url === 'string' ? server.url : undefined,
        packageRef: pkg,
      };
    });

    if (servers.length > 0) {
      groups.push({ client: cfg.client, scope: cfg.scope, path: cfg.path, servers });
    }
  }

  groups.sort((a, b) => {
    if (a.scope !== b.scope) return a.scope === 'global' ? -1 : 1;
    if (a.client !== b.client) return a.client.localeCompare(b.client);
    return a.path.localeCompare(b.path);
  });

  const totalServers = groups.reduce((acc, g) => acc + g.servers.length, 0);

  return {
    groups,
    totalServers,
    totalConfigs: groups.length,
    transportCounts,
    uniquePackages: Array.from(packageSet).sort((a, b) => a.localeCompare(b)),
    errors,
  };
}

/**
 * Extracts a runnable package reference (e.g. `@modelcontextprotocol/server-github`)
 * from a server definition when the command is a well-known package runner.
 *
 * This is best-effort — only package-runner shaped commands are decoded;
 * anything else returns undefined (and is represented differently in the inventory).
 */
function extractPackageRef(server: MCPServerConfig): string | undefined {
  if (typeof server.url === 'string' && server.url.length > 0) return undefined;
  if (typeof server.command !== 'string') return undefined;

  const cmd = server.command;
  const args = normalizeStringArray(server.args);
  if (!isPackageRunner(cmd)) return undefined;

  for (const a of args) {
    if (a.startsWith('-')) continue;
    if (a === 'run' || a === 'dlx' || a === 'exec') continue;
    return a;
  }
  return undefined;
}

function isPackageRunner(cmd: string): boolean {
  const base = basename(cmd).toLowerCase().replace(/\.(cmd|exe|ps1)$/, '');
  return ['npx', 'pnpx', 'bunx', 'uvx', 'pipx', 'pnpm', 'yarn', 'bun'].includes(base);
}

function basename(p: string): string {
  const lastSlash = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return lastSlash >= 0 ? p.slice(lastSlash + 1) : p;
}

function normalizeStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string');
}

const CLIENT_LABEL: Record<ClientKind, string> = {
  cursor: 'Cursor',
  'claude-desktop': 'Claude Desktop',
  'claude-code': 'Claude Code',
  windsurf: 'Windsurf',
  vscode: 'VSCode',
  continue: 'Continue.dev',
  codex: 'Codex',
  zed: 'Zed',
  unknown: 'Unknown client',
};

const TRANSPORT_LABEL: Record<TransportKind, string> = {
  stdio: 'stdio',
  http: 'http',
  sse: 'sse',
  unknown: '?',
};

export function renderInventoryPretty(inv: Inventory): string {
  const out: string[] = [];
  const DOUBLE = chalk.gray('═'.repeat(68));
  const DIVIDER = chalk.gray('─'.repeat(68));

  out.push('');
  out.push(chalk.bold.cyan('📦 MCP Inventory') + chalk.gray(` v${getVersion()}`));
  out.push(chalk.gray('Discovered MCP servers across your configs.'));
  out.push('');

  if (inv.groups.length === 0 && inv.errors.length === 0) {
    out.push(chalk.yellow('No MCP configuration files found.'));
    out.push(chalk.gray('Tip: pass --config <path> to inspect a specific file.'));
    out.push('');
    return out.join('\n') + '\n';
  }

  out.push(chalk.bold(
    `Scanned ${inv.totalConfigs} config file${inv.totalConfigs === 1 ? '' : 's'}, ` +
    `found ${inv.totalServers} MCP server${inv.totalServers === 1 ? '' : 's'}.`
  ));
  out.push('');

  for (const g of inv.groups) {
    out.push(DIVIDER);
    const header = `${CLIENT_LABEL[g.client]} ${chalk.gray(`(${g.scope})`)}`;
    out.push(chalk.bold(header));
    out.push(chalk.gray(`  ${g.path}`));
    out.push('');
    for (const s of g.servers) {
      out.push(formatEntry(s));
    }
    out.push('');
  }

  out.push(DOUBLE);
  out.push('');
  out.push(chalk.bold('Transport breakdown:'));
  for (const t of ['stdio', 'http', 'sse', 'unknown'] as TransportKind[]) {
    const n = inv.transportCounts[t];
    if (n === 0 && t !== 'stdio' && t !== 'http') continue;
    out.push(`  ${TRANSPORT_LABEL[t].padEnd(8)} ${n}`);
  }

  if (inv.uniquePackages.length > 0) {
    out.push('');
    out.push(chalk.bold(`Unique packages (${inv.uniquePackages.length}):`));
    for (const p of inv.uniquePackages) {
      out.push(`  ${chalk.cyan(p)}`);
    }
  }

  if (inv.errors.length > 0) {
    out.push('');
    out.push(chalk.yellow(`  ${inv.errors.length} file${inv.errors.length === 1 ? '' : 's'} could not be parsed:`));
    for (const e of inv.errors) {
      out.push(chalk.gray(`    - ${e.path}: ${e.message}`));
    }
  }

  out.push('');
  out.push(chalk.gray('  Run `mcp-audit` (no subcommand) to security-scan these configs.'));
  out.push('');
  return out.join('\n') + '\n';
}

function formatEntry(e: InventoryEntry): string {
  const name = chalk.cyan(`"${e.serverName}"`);
  const transport = chalk.gray(`[${TRANSPORT_LABEL[e.transport]}]`);
  const body = describeLaunch(e);
  return `  ${chalk.green('•')} ${name} ${transport}  ${body}`;
}

function describeLaunch(e: InventoryEntry): string {
  if (e.url) {
    return chalk.white(e.url);
  }
  if (e.command) {
    const cmd = chalk.white(e.command);
    const tail = e.packageRef
      ? chalk.yellow(` ${e.packageRef}`)
      : (e.args && e.args.length > 0 ? chalk.gray(` ${e.args.join(' ')}`) : '');
    return `${cmd}${tail}`;
  }
  return chalk.gray('(no command/url)');
}

export function renderInventoryJson(inv: Inventory): string {
  return JSON.stringify(inv, null, 2) + '\n';
}

function getVersion(): string {
  return process.env.MCP_AUDIT_VERSION ?? '0.1.0';
}

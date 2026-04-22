import fs from 'node:fs/promises';
import path from 'node:path';
import JSON5 from 'json5';
import { parse as parseToml } from 'smol-toml';
import type { ConfigFile, MCPConfig } from './types.js';
import type { DiscoveredFile } from './discovery.js';

export async function readAndParse(file: DiscoveredFile): Promise<ConfigFile> {
  const raw = await fs.readFile(file.path, 'utf8');
  const format = detectFormat(file.path);

  const base: Omit<ConfigFile, 'parsed' | 'parseError'> = {
    path: file.path,
    client: file.client,
    scope: file.scope,
    raw,
    format,
  };

  try {
    const parsed = parseContent(raw, format);
    return { ...base, parsed: normalize(parsed, file.client) };
  } catch (err) {
    return {
      ...base,
      parsed: {},
      parseError: err instanceof Error ? err.message : String(err),
    };
  }
}

function detectFormat(p: string): 'json' | 'json5' | 'toml' {
  const ext = path.extname(p).toLowerCase();
  if (ext === '.toml') return 'toml';
  if (ext === '.json5') return 'json5';
  return 'json';
}

function parseContent(raw: string, format: 'json' | 'json5' | 'toml'): unknown {
  const trimmed = raw.trim();
  if (trimmed === '') return {};

  if (format === 'toml') {
    return parseToml(raw);
  }
  // Use JSON5 even for .json so comments/trailing commas don't break us.
  // Real JSON is a strict subset of JSON5, so this stays accurate.
  return JSON5.parse(raw);
}

function normalize(raw: unknown, client: string): MCPConfig {
  if (!raw || typeof raw !== 'object') return {};
  const obj = raw as Record<string, unknown>;

  // Codex TOML uses [mcp_servers.X] which smol-toml parses to { mcp_servers: { X: {...} } }
  if (obj.mcp_servers && !obj.mcpServers) {
    obj.mcpServers = obj.mcp_servers;
  }

  // Zed stores MCP entries under context_servers
  // VSCode stores them under `servers`
  // Continue.dev single-server files have top-level {name, command, args,...}
  if (client === 'continue' && !obj.mcpServers && !obj.servers && (obj.command || obj.url)) {
    const name = typeof obj.name === 'string' ? obj.name : 'server';
    obj.mcpServers = { [name]: obj as Record<string, unknown> };
  }

  return obj as MCPConfig;
}

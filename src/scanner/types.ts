export type ClientKind =
  | 'cursor'
  | 'claude-desktop'
  | 'claude-code'
  | 'windsurf'
  | 'vscode'
  | 'continue'
  | 'codex'
  | 'zed'
  | 'unknown';

export type ConfigScope = 'global' | 'project';

export type TransportKind = 'stdio' | 'http' | 'sse' | 'unknown';

export interface MCPServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;

  url?: string;
  headers?: Record<string, string>;

  type?: string;

  [extraField: string]: unknown;
}

export interface MCPConfig {
  mcpServers?: Record<string, MCPServerConfig>;
  servers?: Record<string, MCPServerConfig>;
  context_servers?: Record<string, MCPServerConfig>;
  [extraField: string]: unknown;
}

export interface ConfigFile {
  path: string;
  client: ClientKind;
  scope: ConfigScope;
  parsed: MCPConfig;
  raw: string;
  format: 'json' | 'json5' | 'toml';
  parseError?: string;
}

export function getServerEntries(
  config: MCPConfig
): Array<[string, MCPServerConfig]> {
  const bag: Record<string, MCPServerConfig> = {
    ...(config.mcpServers ?? {}),
    ...(config.servers ?? {}),
    ...(config.context_servers ?? {}),
  };
  return Object.entries(bag);
}

export function detectTransport(server: MCPServerConfig): TransportKind {
  if (server.type === 'http' || server.type === 'sse') return server.type;
  if (server.type === 'stdio') return 'stdio';
  if (typeof server.url === 'string' && server.url.length > 0) return 'http';
  if (typeof server.command === 'string' && server.command.length > 0) return 'stdio';
  return 'unknown';
}

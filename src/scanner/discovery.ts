import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { glob } from 'glob';
import type { ClientKind, ConfigScope } from './types.js';
import { expand, isMac, isWindows } from '../utils/platform.js';
import { logger } from '../utils/logger.js';

export interface DiscoveredFile {
  path: string;
  client: ClientKind;
  scope: ConfigScope;
}

interface CandidatePath {
  /** Either a direct file or a glob pattern. */
  pattern: string;
  isGlob: boolean;
  client: ClientKind;
  scope: ConfigScope;
}

function globalCandidates(): CandidatePath[] {
  const home = os.homedir();
  const candidates: CandidatePath[] = [];

  // Cursor
  candidates.push({ pattern: path.join(home, '.cursor', 'mcp.json'), isGlob: false, client: 'cursor', scope: 'global' });

  // Claude Desktop
  candidates.push({ pattern: path.join(home, '.claude', 'claude_desktop_config.json'), isGlob: false, client: 'claude-desktop', scope: 'global' });
  if (isMac()) {
    candidates.push({
      pattern: path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      isGlob: false,
      client: 'claude-desktop',
      scope: 'global',
    });
  }
  if (isWindows()) {
    const appData = process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming');
    candidates.push({
      pattern: path.join(appData, 'Claude', 'claude_desktop_config.json'),
      isGlob: false,
      client: 'claude-desktop',
      scope: 'global',
    });
    candidates.push({
      pattern: path.join(appData, 'Cursor', 'mcp.json'),
      isGlob: false,
      client: 'cursor',
      scope: 'global',
    });
  }
  candidates.push({
    pattern: path.join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    isGlob: false,
    client: 'claude-desktop',
    scope: 'global',
  });

  // Claude Code
  candidates.push({ pattern: path.join(home, '.claude.json'), isGlob: false, client: 'claude-code', scope: 'global' });

  // Windsurf
  candidates.push({
    pattern: path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    isGlob: false,
    client: 'windsurf',
    scope: 'global',
  });

  // Continue.dev
  candidates.push({
    pattern: path.join(home, '.continue', 'mcpServers', '*.{json,yaml,yml}'),
    isGlob: true,
    client: 'continue',
    scope: 'global',
  });
  candidates.push({
    pattern: path.join(home, '.continue', 'config.json'),
    isGlob: false,
    client: 'continue',
    scope: 'global',
  });

  // Codex (TOML)
  candidates.push({ pattern: path.join(home, '.codex', 'config.toml'), isGlob: false, client: 'codex', scope: 'global' });

  // VSCode (user-level)
  if (isWindows()) {
    const appData = process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming');
    candidates.push({
      pattern: path.join(appData, 'Code', 'User', 'mcp.json'),
      isGlob: false,
      client: 'vscode',
      scope: 'global',
    });
  } else if (isMac()) {
    candidates.push({
      pattern: path.join(home, 'Library', 'Application Support', 'Code', 'User', 'mcp.json'),
      isGlob: false,
      client: 'vscode',
      scope: 'global',
    });
  } else {
    candidates.push({
      pattern: path.join(home, '.config', 'Code', 'User', 'mcp.json'),
      isGlob: false,
      client: 'vscode',
      scope: 'global',
    });
  }

  // Zed
  candidates.push({ pattern: path.join(home, '.config', 'zed', 'settings.json'), isGlob: false, client: 'zed', scope: 'global' });

  return candidates;
}

function projectCandidates(cwd: string): CandidatePath[] {
  const c: CandidatePath[] = [];
  c.push({ pattern: path.join(cwd, '.cursor', 'mcp.json'), isGlob: false, client: 'cursor', scope: 'project' });
  c.push({ pattern: path.join(cwd, '.vscode', 'mcp.json'), isGlob: false, client: 'vscode', scope: 'project' });
  c.push({ pattern: path.join(cwd, '.mcp.json'), isGlob: false, client: 'claude-code', scope: 'project' });
  c.push({
    pattern: path.join(cwd, '.continue', 'mcpServers', '*.{json,yaml,yml}'),
    isGlob: true,
    client: 'continue',
    scope: 'project',
  });
  c.push({ pattern: path.join(cwd, 'mcp.json'), isGlob: false, client: 'unknown', scope: 'project' });
  return c;
}

export interface DiscoveryOptions {
  /** Explicit file paths — takes precedence over auto-discovery. */
  explicitPaths?: string[];
  /** Additional directory roots to treat as projects. */
  projectRoots?: string[];
  /** Disable global (home-directory) discovery. */
  skipGlobal?: boolean;
  /** Disable project (cwd) discovery. */
  skipProject?: boolean;
  /** Working directory for project discovery (defaults to process.cwd()). */
  cwd?: string;
}

export async function discoverConfigs(opts: DiscoveryOptions = {}): Promise<DiscoveredFile[]> {
  const results: DiscoveredFile[] = [];
  const seen = new Set<string>();

  const push = (file: DiscoveredFile): void => {
    const canonical = path.resolve(file.path);
    if (seen.has(canonical)) return;
    seen.add(canonical);
    results.push({ ...file, path: canonical });
  };

  if (opts.explicitPaths && opts.explicitPaths.length > 0) {
    for (const raw of opts.explicitPaths) {
      const resolved = path.resolve(expand(raw));
      if (!fs.existsSync(resolved)) {
        logger.warn(`Config path not found: ${resolved}`);
        continue;
      }
      push({ path: resolved, client: inferClientFromPath(resolved), scope: inferScopeFromPath(resolved) });
    }
    return results;
  }

  const candidates: CandidatePath[] = [];
  if (!opts.skipGlobal) candidates.push(...globalCandidates());
  if (!opts.skipProject) {
    const roots = opts.projectRoots && opts.projectRoots.length > 0 ? opts.projectRoots : [opts.cwd ?? process.cwd()];
    for (const root of roots) {
      candidates.push(...projectCandidates(path.resolve(expand(root))));
    }
  }

  for (const c of candidates) {
    if (c.isGlob) {
      const matches = await glob(c.pattern, { nodir: true, windowsPathsNoEscape: true });
      for (const m of matches) {
        push({ path: m, client: c.client, scope: c.scope });
      }
    } else if (fs.existsSync(c.pattern) && fs.statSync(c.pattern).isFile()) {
      push({ path: c.pattern, client: c.client, scope: c.scope });
    }
  }

  return results;
}

function inferClientFromPath(p: string): ClientKind {
  const lower = p.toLowerCase().replace(/\\/g, '/');
  if (lower.includes('/.cursor/') || lower.endsWith('cursor/mcp.json')) return 'cursor';
  if (lower.includes('claude_desktop_config')) return 'claude-desktop';
  if (lower.endsWith('/.mcp.json') || lower.endsWith('.claude.json')) return 'claude-code';
  if (lower.includes('/windsurf/')) return 'windsurf';
  if (lower.includes('/.vscode/') || lower.includes('/code/user/')) return 'vscode';
  if (lower.includes('/.continue/')) return 'continue';
  if (lower.includes('/.codex/')) return 'codex';
  if (lower.includes('/zed/')) return 'zed';
  return 'unknown';
}

function inferScopeFromPath(p: string): ConfigScope {
  const home = os.homedir().replace(/\\/g, '/').toLowerCase();
  const norm = p.replace(/\\/g, '/').toLowerCase();
  if (norm.startsWith(home)) return 'global';
  return 'project';
}

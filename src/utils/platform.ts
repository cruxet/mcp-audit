import os from 'node:os';
import path from 'node:path';

export function expandHome(p: string): string {
  if (p.startsWith('~')) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

export function expandEnv(p: string): string {
  return p.replace(/%([^%]+)%/g, (_, name: string) => process.env[name] ?? `%${name}%`);
}

export function expand(p: string): string {
  return path.normalize(expandHome(expandEnv(p)));
}

export function isWindows(): boolean {
  return process.platform === 'win32';
}

export function isMac(): boolean {
  return process.platform === 'darwin';
}

/**
 * path.basename is platform-aware: on POSIX it only splits on `/`, so a
 * Windows-style path like `C:\\Windows\\cmd.exe` returns the whole
 * string unchanged. We always want to resolve the last path component
 * regardless of the host OS.
 */
export function crossPlatformBasename(p: string): string {
  const lastSlash = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return lastSlash >= 0 ? p.slice(lastSlash + 1) : p;
}

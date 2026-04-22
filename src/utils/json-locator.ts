import type { Location } from '../rules/types.js';

/**
 * Best-effort JSON location finder. Walks the raw source looking for the
 * `"serverName"` key followed by an object literal. If a `valueHint` is
 * supplied, tries to locate that literal inside the server block for a
 * more precise line/column. Falls back to the server key's location
 * when the hint cannot be found.
 */
export function locateServer(
  raw: string,
  serverName: string,
  valueHint?: string
): Location | undefined {
  const keyPattern = new RegExp(`"${escapeRegex(serverName)}"\\s*:`, 'g');
  const keyMatch = keyPattern.exec(raw);
  if (!keyMatch) return undefined;

  const base = toLineCol(raw, keyMatch.index);

  if (!valueHint) return base;

  const slice = raw.slice(keyMatch.index);
  const hintIdx = slice.indexOf(valueHint);
  if (hintIdx === -1) return base;

  return toLineCol(raw, keyMatch.index + hintIdx);
}

export function toLineCol(raw: string, offset: number): Location {
  let line = 1;
  let lastNewline = -1;
  for (let i = 0; i < offset && i < raw.length; i++) {
    if (raw.charCodeAt(i) === 10) {
      line++;
      lastNewline = i;
    }
  }
  const column = offset - lastNewline;
  return { line, column };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

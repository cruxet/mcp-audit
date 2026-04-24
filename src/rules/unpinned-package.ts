import type { Rule, Severity, Remediation } from './types.js';
import { locateServer } from '../utils/json-locator.js';

/**
 * Package-runner commands that take a package reference as their first
 * non-flag argument — e.g. `npx foo`, `uvx foo`.
 */
const DIRECT_RUNNERS = new Set(['npx', 'uvx', 'pipx', 'bunx', 'pnpx']);

/**
 * Runners that take a subcommand before the package reference — e.g.
 * `pnpm dlx foo`, `yarn dlx foo`, `bun x foo`. We only flag when the
 * subcommand is explicitly present; `yarn foo` alone runs a local script.
 */
const SUBCOMMAND_RUNNERS: Record<string, string[]> = {
  pnpm: ['dlx'],
  yarn: ['dlx'],
  bun: ['x'],
};

/**
 * Dist-tags that roll forward on every publish. Pinning to any of these
 * is equivalent to trusting whatever the maintainer decides to release,
 * without review.
 */
const ROLLING_TAGS = new Set([
  'latest',
  'next',
  'beta',
  'canary',
  'alpha',
  'dev',
  'nightly',
  'edge',
  'rc',
]);

const SIMPLE_PACKAGE_REGEX = /^(@[A-Za-z0-9][A-Za-z0-9._-]*\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,213}$/;
const VERSIONED_PACKAGE_REGEX =
  /^((?:@[A-Za-z0-9][A-Za-z0-9._-]*\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,213})@(.+)$/;
const GITHUB_SHORTCUT_REGEX = /^github:/i;
const GIT_URL_REGEX = /^git(\+.+)?:\/\//i;
const HTTP_URL_REGEX = /^https?:\/\//i;
const FILE_URL_REGEX = /^file:/i;

function basename(p: string): string {
  const lastSlash = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return lastSlash >= 0 ? p.slice(lastSlash + 1) : p;
}

function normalizeRunner(cmd: string): string {
  return basename(cmd).toLowerCase().replace(/\.(cmd|exe|ps1)$/, '');
}

export const unpinnedPackageRule: Rule = {
  id: 'MCP-AUDIT-008',
  name: 'Unpinned Package Version',
  description:
    'MCP server launches a package without a pinned version or installs directly from a git/URL/file source — supply-chain changes become trusted code at launch time.',
  severity: 'medium',
  category: 'suspicious-package',
  references: [
    'https://docs.npmjs.com/cli/v10/commands/npx',
    'https://overreacted.io/npm-audit-broken-by-design/',
  ],

  check(ctx) {
    const { server, config, serverName } = ctx;
    if (typeof server.command !== 'string') return [];
    if (!Array.isArray(server.args) || server.args.length === 0) return [];

    const runner = normalizeRunner(server.command);
    const args = server.args.filter((a): a is string => typeof a === 'string');
    const pkgIdx = findPackageArgIndex(runner, args);
    if (pkgIdx < 0) return [];

    const pkgArg = args[pkgIdx]!;
    const classification = classifyPackageArg(pkgArg);
    if (!classification) return [];

    return [
      {
        severity: classification.severity,
        category: 'suspicious-package',
        message: `Server "${serverName}" launches "${pkgArg}" via ${runner} — ${classification.reason}`,
        matched: pkgArg,
        location: locateServer(config.raw, serverName, pkgArg),
        remediation: classification.remediation,
      },
    ];
  },
};

function findPackageArgIndex(runner: string, args: string[]): number {
  if (DIRECT_RUNNERS.has(runner)) {
    for (let i = 0; i < args.length; i++) {
      if (!args[i]!.startsWith('-')) return i;
    }
    return -1;
  }

  const subs = SUBCOMMAND_RUNNERS[runner];
  if (subs && args.length >= 2 && subs.includes(args[0]!)) {
    for (let i = 1; i < args.length; i++) {
      if (!args[i]!.startsWith('-')) return i;
    }
  }

  return -1;
}

interface Classification {
  severity: Severity;
  reason: string;
  remediation: Remediation;
}

function classifyPackageArg(arg: string): Classification | null {
  if (GIT_URL_REGEX.test(arg) || GITHUB_SHORTCUT_REGEX.test(arg)) {
    return {
      severity: 'high',
      reason:
        'installing directly from a git source runs whatever the repository owner pushes, with no registry review.',
      remediation: {
        description:
          'Prefer a published, versioned npm/PyPI release. If you must install from source, pin to a commit SHA and audit on each bump.',
        before: `"${arg}"`,
        after: `"<registry-package>@<version>"`,
      },
    };
  }

  if (HTTP_URL_REGEX.test(arg)) {
    return {
      severity: 'high',
      reason:
        'installing from an arbitrary HTTPS URL bypasses registry signatures, provenance, and lockfiles.',
      remediation: {
        description: 'Use a package registry entry (npm/PyPI) with a pinned version.',
      },
    };
  }

  if (FILE_URL_REGEX.test(arg)) {
    return {
      severity: 'high',
      reason:
        'installing from a local file path will execute whatever exists at that path at launch time.',
      remediation: {
        description:
          'Publish the package to a registry and pin a version, or vet the local source before committing.',
      },
    };
  }

  const versioned = arg.match(VERSIONED_PACKAGE_REGEX);
  if (versioned) {
    const [, name, version] = versioned as unknown as [string, string, string];
    const lower = version.toLowerCase();
    if (ROLLING_TAGS.has(lower)) {
      return {
        severity: 'high',
        reason: `the "${lower}" dist-tag is a rolling pointer; every launch may pull a different release.`,
        remediation: {
          description:
            'Pin to an explicit semver (e.g. 1.2.3 or ^1.2.3) so upstream changes are reviewed before they run.',
          before: `"${arg}"`,
          after: `"${name}@<exact-version>"`,
        },
      };
    }
    // Explicit version specifier — treat as pinned.
    return null;
  }

  if (SIMPLE_PACKAGE_REGEX.test(arg)) {
    return {
      severity: 'medium',
      reason:
        'no version pin — the registry\'s "latest" release is executed on every launch, so any upstream publish becomes trusted code immediately.',
      remediation: {
        description:
          'Pin the package to a specific version or semver range. Combine with a lockfile for reproducible installs.',
        before: `"${arg}"`,
        after: `"${arg}@<exact-version>"`,
      },
    };
  }

  return null;
}

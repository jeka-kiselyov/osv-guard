import { PACKAGE_MANAGERS, type PackageManager } from './pm.js';

/**
 * Parse a shell command line into the packages it would install.
 *
 * This exists for the Claude Code hook, which sees a command *before* it runs.
 * Nothing is in a lockfile yet, so osv-scanner has nothing to read — the names
 * have to come out of the command line itself.
 */

export type Ecosystem = 'npm' | 'PyPI';

export interface InstallSpec {
  ecosystem: Ecosystem;
  name: string;
  /** An exact version when one was pinned, else null (a range, or nothing). */
  version: string | null;
  /** The argument as written, for reporting. */
  raw: string;
}

/**
 * The sub-commands that add *new* packages, per package manager.
 *
 * Keyed by `PackageManager` so this cannot drift from the managers osv-guard
 * supports elsewhere — adding one to `PACKAGE_MANAGERS` fails the build here
 * until its install verbs are listed.
 */
const NODE_INSTALL_VERBS: Record<PackageManager, string[]> = {
  npm: ['install', 'i', 'add'],
  pnpm: ['add', 'install', 'i'],
  yarn: ['add'],
  bun: ['add', 'install', 'i'],
};

/** Python installers, which are not package *managers* in the pm.ts sense. */
const PYTHON_INSTALLERS: { verb: RegExp }[] = [
  { verb: /^pip3?\s+install\s+/ },
  { verb: /^python3?\s+-m\s+pip\s+install\s+/ },
  { verb: /^uv\s+(?:pip\s+install|add)\s+/ },
  { verb: /^poetry\s+add\s+/ },
];

interface Matcher {
  pattern: RegExp;
  ecosystem: Ecosystem;
}

const MATCHERS: Matcher[] = [
  ...PACKAGE_MANAGERS.map((pm) => ({
    pattern: new RegExp(`^${pm}\\s+(?:${NODE_INSTALL_VERBS[pm].join('|')})\\s+`),
    ecosystem: 'npm' as const,
  })),
  ...PYTHON_INSTALLERS.map(({ verb }) => ({ pattern: verb, ecosystem: 'PyPI' as const })),
];

/**
 * Split on shell separators so `cd x && npm i evil` is still inspected, and a
 * package hidden behind a pipe or a newline is not missed.
 */
export function segments(command: string): string[] {
  return command
    .split(/&&|\|\||;|\n|(?<!\|)\|(?!\|)/)
    .map((part) => part.trim())
    .filter(Boolean);
}

/**
 * Arguments that are not registry packages: flags, local paths, URLs, git
 * specs and tarballs. None can be looked up by name, and guessing would raise
 * false alarms against a registry package that merely shares the name.
 */
export function isPackageArgument(arg: string): boolean {
  if (arg.startsWith('-')) return false;
  if (arg.startsWith('.') || arg.startsWith('/') || arg.startsWith('~')) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(arg)) return false;
  if (/^(?:file|git|github|gitlab|bitbucket|npm|workspace|catalog|link|portal):/i.test(arg)) {
    return false;
  }
  if (/\.(?:tgz|tar\.gz|whl|zip)$/i.test(arg)) return false;
  // A slash that is not a scope means a path or a shorthand repo spec.
  if (arg.includes('/') && !arg.startsWith('@')) return false;
  return true;
}

/** OSV can only be queried for a concrete version; ranges have to be widened. */
export function isExactVersion(value: string): boolean {
  return /^\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?$/.test(value);
}

export function parseSpec(arg: string, ecosystem: Ecosystem): InstallSpec | null {
  if (!isPackageArgument(arg)) return null;

  if (ecosystem === 'PyPI') {
    // pip pins with `==`; every other operator describes a range.
    const match = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|>|<|!=)?\s*([^\s,;]+)?/.exec(arg);
    const name = match?.[1];
    if (!name) return null;
    const version = match[2] === '==' && match[3] && isExactVersion(match[3]) ? match[3] : null;
    return { ecosystem, name, version, raw: arg };
  }

  // npm: `name`, `name@version`, `@scope/name`, `@scope/name@version`.
  const at = arg.startsWith('@') ? arg.indexOf('@', 1) : arg.indexOf('@');
  const name = at === -1 ? arg : arg.slice(0, at);
  const versionPart = at === -1 ? '' : arg.slice(at + 1);
  if (!name) return null;

  return {
    ecosystem,
    name,
    version: isExactVersion(versionPart) ? versionPart : null,
    raw: arg,
  };
}

/**
 * Every package an install command would add, across chained sub-commands.
 *
 * Returns an empty list for anything that is not an install — including a bare
 * `npm install`, which restores an existing lockfile and introduces nothing the
 * project has not already committed to.
 */
export function parseInstallCommand(command: string): InstallSpec[] {
  const specs: InstallSpec[] = [];
  const seen = new Set<string>();

  for (const segment of segments(command)) {
    for (const { pattern, ecosystem } of MATCHERS) {
      const match = pattern.exec(segment);
      if (!match) continue;

      for (const arg of segment.slice(match[0].length).split(/\s+/).filter(Boolean)) {
        const spec = parseSpec(arg, ecosystem);
        if (!spec) continue;
        const key = `${spec.ecosystem}/${spec.name}@${spec.version ?? '*'}`;
        if (seen.has(key)) continue;
        seen.add(key);
        specs.push(spec);
      }
      break;
    }
  }

  return specs;
}

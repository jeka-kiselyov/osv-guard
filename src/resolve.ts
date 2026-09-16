import { existsSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

/** Checked in this order; the first present one is reported. */
export const LOCKFILES = [
  'package-lock.json',
  'npm-shrinkwrap.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'bun.lock',
  'bun.lockb',
] as const;

export interface ProjectDir {
  dir: string;
  /** How we found it — surfaced by `--verbose` when a scan targets a surprise. */
  via: 'flag' | 'npm_config_local_prefix' | 'INIT_CWD' | 'walk-up' | 'cwd';
}

function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Find the package root that `npm run` would operate on.
 *
 * npm 7+ exports `npm_config_local_prefix` (the directory holding the
 * package.json whose scripts are running), which is exactly what we want and
 * is correct inside workspaces. INIT_CWD and a walk-up cover older npm and
 * direct `npx osv-guard` invocations.
 */
export function resolveProjectDir(
  flagDir: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): ProjectDir {
  if (flagDir) return { dir: path.resolve(cwd, flagDir), via: 'flag' };

  const localPrefix = env.npm_config_local_prefix;
  if (localPrefix && isDir(localPrefix)) {
    return { dir: path.resolve(localPrefix), via: 'npm_config_local_prefix' };
  }

  const initCwd = env.INIT_CWD;
  if (initCwd && existsSync(path.join(initCwd, 'package.json'))) {
    return { dir: path.resolve(initCwd), via: 'INIT_CWD' };
  }

  let current = path.resolve(cwd);
  for (;;) {
    if (existsSync(path.join(current, 'package.json'))) {
      return { dir: current, via: 'walk-up' };
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }

  return { dir: path.resolve(cwd), via: 'cwd' };
}

const LOCKFILE_SET = new Set<string>(LOCKFILES);

/** Never worth descending into, and `node_modules` would multiply the walk. */
const SKIP_DIRS = new Set(['node_modules', '.git']);

/** Deep enough for any realistic monorepo; a guard against symlink cycles. */
const MAX_DEPTH = 8;

/** Enough for a very large monorepo; a guard against pathological trees. */
const MAX_LOCKFILES = 500;

/**
 * Lockfile paths relative to `dir`, searched recursively.
 *
 * This has to match what osv-scanner sees: we pass `--recursive`, so a
 * monorepo root whose packages each carry their own lockfile is a perfectly
 * scannable target even though the root itself has none. Looking only at the
 * top level made osv-guard reject such a root outright, and — worse — made the
 * cache key hash an empty list, so no dependency change anywhere in the
 * monorepo could ever invalidate a cached result.
 *
 * Results are sorted so the cache key is stable across filesystem orderings.
 */
export function findLockfiles(dir: string): string[] {
  const found: string[] = [];

  const walk = (current: string, depth: number): void => {
    if (depth > MAX_DEPTH || found.length >= MAX_LOCKFILES) return;

    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      // Unreadable directory (permissions, a race): skip it, don't fail the scan.
      return;
    }

    const subdirs: string[] = [];
    for (const entry of entries) {
      if (entry.isFile() && LOCKFILE_SET.has(entry.name)) {
        found.push(path.relative(dir, path.join(current, entry.name)));
        if (found.length >= MAX_LOCKFILES) return;
      } else if (entry.isDirectory() && !SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
        subdirs.push(path.join(current, entry.name));
      }
    }
    for (const subdir of subdirs) walk(subdir, depth + 1);
  };

  walk(dir, 0);
  // Normalize separators so a key built on Windows matches one built elsewhere.
  return found.map((p) => p.split(path.sep).join('/')).sort();
}

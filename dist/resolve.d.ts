/** Checked in this order; the first present one is reported. */
export declare const LOCKFILES: readonly ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"];
export interface ProjectDir {
    dir: string;
    /** How we found it — surfaced by `--verbose` when a scan targets a surprise. */
    via: 'flag' | 'npm_config_local_prefix' | 'INIT_CWD' | 'walk-up' | 'cwd';
}
/**
 * Find the package root that `npm run` would operate on.
 *
 * npm 7+ exports `npm_config_local_prefix` (the directory holding the
 * package.json whose scripts are running), which is exactly what we want and
 * is correct inside workspaces. INIT_CWD and a walk-up cover older npm and
 * direct `npx osv-guard` invocations.
 */
export declare function resolveProjectDir(flagDir: string | undefined, env?: NodeJS.ProcessEnv, cwd?: string): ProjectDir;
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
export declare function findLockfiles(dir: string): string[];

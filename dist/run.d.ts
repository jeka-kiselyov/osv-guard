import { type PackageManager } from './pm.js';
import { type RunTarget } from './target.js';
/** Marks a guarded child, so nested osv-guard invocations can be detected. */
export declare const DEPTH_ENV = "OSV_GUARD_DEPTH";
export declare class RecursionError extends Error {
}
export interface RunOptions {
    target: RunTarget;
    args: string[];
    /** The package root: where the scan ran and where scripts must execute. */
    dir: string;
    /** Where the user actually invoked osv-guard. Defaults to the package root. */
    cwd?: string;
    pm: PackageManager;
    env?: NodeJS.ProcessEnv;
}
export interface RunOutcome {
    code: number;
    signal: NodeJS.Signals | null;
    /** The argv actually spawned, for --verbose and for tests. */
    argv: string[];
}
/**
 * Where the child should run.
 *
 * A script runs from the package root, because that is what every package
 * manager does — `npm run` and `pnpm run` never run a script from wherever you
 * happened to be standing. A command is different: running it through the
 * guard must be indistinguishable from running it directly, so it keeps the
 * user's own working directory and its relative paths still mean what they say.
 */
export declare function runCwd(options: RunOptions): string;
/** What we will spawn, without spawning it. */
export declare function planRun(options: RunOptions): {
    command: string;
    argv: string[];
    shell: boolean;
};
export declare function currentDepth(env?: NodeJS.ProcessEnv): number;
export declare function assertNotLooping(env?: NodeJS.ProcessEnv): void;
/**
 * Run the target, inheriting stdio, and resolve with its exit code.
 *
 * Signals are forwarded rather than letting the default handler kill us first:
 * Ctrl-C on a guarded dev server should reach the dev server, and we should
 * exit only once it has.
 */
export declare function runTarget(options: RunOptions): Promise<RunOutcome>;

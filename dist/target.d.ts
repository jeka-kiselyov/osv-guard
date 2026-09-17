export interface ScriptTarget {
    kind: 'script';
    name: string;
    /** The script's command line, used for the recursion check. */
    body: string;
}
export interface CommandTarget {
    kind: 'command';
    name: string;
    /** Absolute path when it resolved inside node_modules/.bin, else the bare name. */
    resolved: string;
}
export type RunTarget = ScriptTarget | CommandTarget;
export declare class TargetError extends Error {
    readonly hint?: string | undefined;
    constructor(message: string, hint?: string | undefined);
}
export declare function readScripts(dir: string): Record<string, string>;
/** `node_modules/.bin` is where a project's own tools live. */
export declare function binDir(dir: string): string;
/** Does this script body invoke osv-guard again? */
export declare function invokesOsvGuard(body: string): boolean;
/**
 * Decide what the user meant by `name`.
 *
 * A package.json script always wins, so a project can have a script and a
 * binary of the same name without surprise. Otherwise we look for a real
 * executable — first in the project's own `node_modules/.bin`, then on PATH —
 * which is what makes `osv-guard hardhat build` work.
 *
 * A name that is neither is a usage error listing the available scripts,
 * rather than an opaque "command not found" from the shell.
 */
export declare function resolveTarget(dir: string, name: string, { forceCommand, env }?: {
    forceCommand?: boolean;
    env?: NodeJS.ProcessEnv;
}): RunTarget;

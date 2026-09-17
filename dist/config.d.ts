import { type Band } from './types.js';
export type Format = 'pretty' | 'json' | 'summary';
export interface Options {
    failOn: Band;
    failOnUnknown: boolean;
    max: Partial<Record<Band, number>>;
    ignore: string[];
    ignoreUnfixed: boolean;
    dir: string | undefined;
    format: Format;
    cache: boolean;
    cacheTtlMs: number;
    offline: boolean;
    allVulns: boolean;
    scannerBin: string;
    packageManager: string | undefined;
    allowNoLockfile: boolean;
    quiet: boolean;
    verbose: boolean;
    color: boolean | undefined;
}
export interface ParsedArgv {
    command: 'run' | 'report' | 'hook' | 'help' | 'version';
    /** `exec` was used: treat the target as a command, never a script. */
    forceCommand: boolean;
    /** npm script name for `run`. */
    script: string | undefined;
    /** Arguments forwarded verbatim to the npm script. */
    scriptArgs: string[];
    /** Only the options explicitly given on the command line. */
    cliOptions: Partial<Options>;
}
export declare const DEFAULTS: Options;
export declare class UsageError extends Error {
}
/** Accepts `1h`, `30m`, `45s`, `500ms`; a bare number is seconds. */
export declare function parseDuration(input: string): number;
/**
 * Split argv into osv-guard's own flags and the script invocation.
 *
 * Everything up to the first bare word is ours; that word is the script name
 * and every token after it belongs to the script. `--` also ends our flags,
 * which is the escape hatch for a script literally named like a flag.
 */
export declare function parseArgv(argv: string[]): ParsedArgv;
/** Reads `osv-guard.json`, `.osv-guardrc[.json]`, or a `osv-guard` key in package.json. */
export declare function loadConfigFile(dir: string): {
    config: Partial<Options>;
    path: string | null;
};
/** CLI flags beat the config file, which beats the built-in defaults. */
export declare function mergeOptions(fileConfig: Partial<Options>, cli: Partial<Options>): Options;

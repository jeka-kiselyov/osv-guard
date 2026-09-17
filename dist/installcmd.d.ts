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
 * Split on shell separators so `cd x && npm i evil` is still inspected, and a
 * package hidden behind a pipe or a newline is not missed.
 */
export declare function segments(command: string): string[];
/**
 * Arguments that are not registry packages: flags, local paths, URLs, git
 * specs and tarballs. None can be looked up by name, and guessing would raise
 * false alarms against a registry package that merely shares the name.
 */
export declare function isPackageArgument(arg: string): boolean;
/** OSV can only be queried for a concrete version; ranges have to be widened. */
export declare function isExactVersion(value: string): boolean;
export declare function parseSpec(arg: string, ecosystem: Ecosystem): InstallSpec | null;
/**
 * Every package an install command would add, across chained sub-commands.
 *
 * Returns an empty list for anything that is not an install — including a bare
 * `npm install`, which restores an existing lockfile and introduces nothing the
 * project has not already committed to.
 */
export declare function parseInstallCommand(command: string): InstallSpec[];

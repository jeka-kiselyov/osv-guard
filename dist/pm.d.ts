export declare const PACKAGE_MANAGERS: readonly ["npm", "pnpm", "yarn", "bun"];
export type PackageManager = (typeof PACKAGE_MANAGERS)[number];
export interface PmDetection {
    pm: PackageManager;
    via: 'flag' | 'packageManager' | 'lockfile' | 'user-agent' | 'default';
}
/**
 * Work out which package manager should run the script.
 *
 * The project's own declarations win over how this particular invocation
 * happened: `npx osv-guard dev` inside a pnpm repo reports an npm user agent,
 * but the script still has to run under pnpm.
 */
export declare function detectPackageManager(dir: string, flag: string | undefined, env?: NodeJS.ProcessEnv): PmDetection;
/**
 * Build the argv that runs `<script>` with `args` under `pm`.
 *
 * The `--` separator is not portable. npm needs it or it swallows any flag as
 * its own config. pnpm does *not* strip it, so passing it there delivers a
 * literal "--" as the script's first argument. yarn accepts either form.
 */
export declare function buildRunArgs(pm: PackageManager, script: string, args: string[]): string[];
/** npm and yarn ship as `.cmd` shims on Windows, which need a shell to launch. */
export declare function pmExecutable(pm: PackageManager): {
    command: string;
    shell: boolean;
};

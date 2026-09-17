import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
export const PACKAGE_MANAGERS = ['npm', 'pnpm', 'yarn', 'bun'];
/** Which lockfile implies which package manager. */
const LOCKFILE_PM = [
    ['pnpm-lock.yaml', 'pnpm'],
    ['yarn.lock', 'yarn'],
    ['bun.lock', 'bun'],
    ['bun.lockb', 'bun'],
    ['package-lock.json', 'npm'],
    ['npm-shrinkwrap.json', 'npm'],
];
function asPm(value) {
    const name = (value ?? '').trim().toLowerCase();
    return PACKAGE_MANAGERS.includes(name) ? name : null;
}
/** Corepack's `"packageManager": "pnpm@11.25.0"` — take the name before the `@`. */
function fromPackageManagerField(dir) {
    const file = path.join(dir, 'package.json');
    if (!existsSync(file))
        return null;
    try {
        const pkg = JSON.parse(readFileSync(file, 'utf8'));
        if (typeof pkg.packageManager !== 'string')
            return null;
        return asPm(pkg.packageManager.split('@')[0]);
    }
    catch {
        return null;
    }
}
/** Walk up looking for a lockfile, so a workspace member finds the root's. */
function fromLockfile(dir) {
    let current = path.resolve(dir);
    for (;;) {
        for (const [name, pm] of LOCKFILE_PM) {
            if (existsSync(path.join(current, name)))
                return pm;
        }
        const parent = path.dirname(current);
        if (parent === current)
            return null;
        current = parent;
    }
}
/** Every package manager sets `npm_config_user_agent` to "<name>/<version> …". */
function fromUserAgent(env) {
    const agent = env.npm_config_user_agent;
    if (!agent)
        return null;
    return asPm(agent.split('/')[0]);
}
/**
 * Work out which package manager should run the script.
 *
 * The project's own declarations win over how this particular invocation
 * happened: `npx osv-guard dev` inside a pnpm repo reports an npm user agent,
 * but the script still has to run under pnpm.
 */
export function detectPackageManager(dir, flag, env = process.env) {
    if (flag) {
        const pm = asPm(flag);
        if (!pm)
            throw new Error(`unknown package manager: ${flag}`);
        return { pm, via: 'flag' };
    }
    const declared = fromPackageManagerField(dir);
    if (declared)
        return { pm: declared, via: 'packageManager' };
    const lock = fromLockfile(dir);
    if (lock)
        return { pm: lock, via: 'lockfile' };
    const agent = fromUserAgent(env);
    if (agent)
        return { pm: agent, via: 'user-agent' };
    return { pm: 'npm', via: 'default' };
}
/**
 * Build the argv that runs `<script>` with `args` under `pm`.
 *
 * The `--` separator is not portable. npm needs it or it swallows any flag as
 * its own config. pnpm does *not* strip it, so passing it there delivers a
 * literal "--" as the script's first argument. yarn accepts either form.
 */
export function buildRunArgs(pm, script, args) {
    if (args.length === 0)
        return ['run', script];
    if (pm === 'npm')
        return ['run', script, '--', ...args];
    return ['run', script, ...args];
}
/** npm and yarn ship as `.cmd` shims on Windows, which need a shell to launch. */
export function pmExecutable(pm) {
    if (process.platform === 'win32' && pm !== 'bun') {
        return { command: `${pm}.cmd`, shell: true };
    }
    return { command: pm, shell: false };
}

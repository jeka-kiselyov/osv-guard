import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

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

export class TargetError extends Error {
  constructor(
    message: string,
    readonly hint?: string,
  ) {
    super(message);
  }
}

export function readScripts(dir: string): Record<string, string> {
  const file = path.join(dir, 'package.json');
  if (!existsSync(file)) return {};
  try {
    const pkg = JSON.parse(readFileSync(file, 'utf8')) as { scripts?: Record<string, unknown> };
    const scripts: Record<string, string> = {};
    for (const [key, value] of Object.entries(pkg.scripts ?? {})) {
      if (typeof value === 'string') scripts[key] = value;
    }
    return scripts;
  } catch {
    return {};
  }
}

function isExecutable(file: string): boolean {
  try {
    return statSync(file).isFile();
  } catch {
    return false;
  }
}

/** `node_modules/.bin` is where a project's own tools live. */
export function binDir(dir: string): string {
  return path.join(dir, 'node_modules', '.bin');
}

function resolveInBin(dir: string, name: string): string | null {
  const candidates =
    process.platform === 'win32' ? [name, `${name}.cmd`, `${name}.exe`, `${name}.ps1`] : [name];
  for (const candidate of candidates) {
    const full = path.join(binDir(dir), candidate);
    if (isExecutable(full)) return full;
  }
  return null;
}

function resolveOnPath(name: string, env: NodeJS.ProcessEnv): string | null {
  if (name.includes('/') || name.includes('\\')) {
    return isExecutable(path.resolve(name)) ? path.resolve(name) : null;
  }
  const parts = (env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32' ? ['', '.cmd', '.exe', '.bat'] : [''];
  for (const part of parts) {
    for (const ext of exts) {
      const full = path.join(part, name + ext);
      if (isExecutable(full)) return full;
    }
  }
  return null;
}

/** Does this script body invoke osv-guard again? */
export function invokesOsvGuard(body: string): boolean {
  return /(^|[\s;&|(])osv-guard(\s|$)/.test(body);
}

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
export function resolveTarget(
  dir: string,
  name: string,
  { forceCommand = false, env = process.env }: { forceCommand?: boolean; env?: NodeJS.ProcessEnv } = {},
): RunTarget {
  const scripts = readScripts(dir);

  if (!forceCommand && Object.hasOwn(scripts, name)) {
    const body = scripts[name] ?? '';
    // `"build": "osv-guard build"` would have osv-guard run the very script
    // that invoked it — an unbounded loop. Catch it before spawning anything.
    if (invokesOsvGuard(body)) {
      throw new TargetError(
        `script "${name}" invokes osv-guard, which would run itself forever`,
        [
          `  "${name}": "${body}"`,
          '',
          'Point the guard at a differently-named script instead:',
          '',
          `  "${name}": "osv-guard ${name}:run",`,
          `  "${name}:run": "<the real command>"`,
          '',
          'Or guard the command directly: osv-guard exec <command>',
        ].join('\n'),
      );
    }
    return { kind: 'script', name, body };
  }

  const local = resolveInBin(dir, name);
  if (local) return { kind: 'command', name, resolved: local };

  const onPath = resolveOnPath(name, env);
  if (onPath) return { kind: 'command', name, resolved: onPath };

  const available = Object.keys(scripts).sort();
  throw new TargetError(
    forceCommand
      ? `command not found: ${name}`
      : `no script or command named "${name}"`,
    available.length > 0
      ? `Scripts in this package: ${available.join(', ')}`
      : 'This package has no scripts, and no such command is on PATH.',
  );
}

import { spawn } from 'node:child_process';
import path from 'node:path';
import { buildRunArgs, pmExecutable, type PackageManager } from './pm.js';
import { binDir, type RunTarget } from './target.js';

/** Marks a guarded child, so nested osv-guard invocations can be detected. */
export const DEPTH_ENV = 'OSV_GUARD_DEPTH';

/** One nested level is plausible; beyond that it is a loop. */
const MAX_DEPTH = 2;

export class RecursionError extends Error {}

export interface RunOptions {
  target: RunTarget;
  args: string[];
  dir: string;
  pm: PackageManager;
  env?: NodeJS.ProcessEnv;
}

export interface RunOutcome {
  code: number;
  signal: NodeJS.Signals | null;
  /** The argv actually spawned, for --verbose and for tests. */
  argv: string[];
}

/** What we will spawn, without spawning it. */
export function planRun(options: RunOptions): { command: string; argv: string[]; shell: boolean } {
  if (options.target.kind === 'script') {
    const { command, shell } = pmExecutable(options.pm);
    return { command, argv: buildRunArgs(options.pm, options.target.name, options.args), shell };
  }
  // A command runs directly: no package manager wrapping, so nothing can
  // reinterpret its flags on the way through.
  return { command: options.target.resolved, argv: [...options.args], shell: false };
}

function childEnv(dir: string, env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const depth = Number.parseInt(env[DEPTH_ENV] ?? '0', 10);
  const next = Number.isFinite(depth) ? depth + 1 : 1;
  // Put the project's own tools first, so a guarded command resolves the same
  // binaries a package-manager script would have.
  const PATH = [binDir(dir), env.PATH ?? ''].filter(Boolean).join(path.delimiter);
  return { ...env, PATH, [DEPTH_ENV]: String(next) };
}

export function currentDepth(env: NodeJS.ProcessEnv = process.env): number {
  const depth = Number.parseInt(env[DEPTH_ENV] ?? '0', 10);
  return Number.isFinite(depth) ? depth : 0;
}

export function assertNotLooping(env: NodeJS.ProcessEnv = process.env): void {
  if (currentDepth(env) >= MAX_DEPTH) {
    throw new RecursionError(
      `osv-guard has re-entered itself ${currentDepth(env)} times — the guarded script probably invokes osv-guard again`,
    );
  }
}

/**
 * Run the target, inheriting stdio, and resolve with its exit code.
 *
 * Signals are forwarded rather than letting the default handler kill us first:
 * Ctrl-C on a guarded dev server should reach the dev server, and we should
 * exit only once it has.
 */
export function runTarget(options: RunOptions): Promise<RunOutcome> {
  const env = options.env ?? process.env;
  const { command, argv, shell } = planRun(options);

  return new Promise((resolve, reject) => {
    const child = spawn(command, argv, {
      cwd: options.dir,
      stdio: 'inherit',
      shell,
      env: childEnv(options.dir, env),
    });

    const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
    const handlers = signals.map((signal) => {
      const handler = () => {
        if (!child.killed) child.kill(signal);
      };
      process.on(signal, handler);
      return { signal, handler };
    });
    const cleanup = () => {
      for (const { signal, handler } of handlers) process.off(signal, handler);
    };

    child.on('error', (error) => {
      cleanup();
      reject(error);
    });
    child.on('close', (code, signal) => {
      cleanup();
      // A signal-terminated child has no exit code; report it the way a shell
      // would so `$?` still distinguishes "killed" from "exited cleanly".
      resolve({
        code: code ?? (signal ? 128 + signalNumber(signal) : 1),
        signal,
        argv: [command, ...argv],
      });
    });
  });
}

const SIGNAL_NUMBERS: Record<string, number> = {
  SIGHUP: 1,
  SIGINT: 2,
  SIGQUIT: 3,
  SIGKILL: 9,
  SIGTERM: 15,
};

function signalNumber(signal: NodeJS.Signals): number {
  return SIGNAL_NUMBERS[signal] ?? 0;
}

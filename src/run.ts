import { spawn } from 'node:child_process';

/** npm ships as a .cmd shim on Windows, which needs a shell to launch. */
function npmCommand(): { command: string; shell: boolean } {
  if (process.platform === 'win32') return { command: 'npm.cmd', shell: true };
  return { command: 'npm', shell: false };
}

/**
 * Run `npm run <script> [args]` in `dir`, inheriting stdio, and resolve with
 * the child's exit code.
 *
 * Signals are forwarded rather than letting the default handler kill us first:
 * a Ctrl-C on a guarded dev server should reach the dev server, and we should
 * exit only once it has.
 */
export function runNpmScript(
  script: string,
  args: string[],
  dir: string,
): Promise<{ code: number; signal: NodeJS.Signals | null }> {
  const { command, shell } = npmCommand();
  // `npm run dev --port 3000` lets npm swallow `--port` as its own config, so
  // the script only ever sees `3000`. We already know every one of these args
  // belongs to the script, so pass them past npm with an explicit separator.
  const argv = args.length > 0 ? ['run', script, '--', ...args] : ['run', script];

  return new Promise((resolve, reject) => {
    const child = spawn(command, argv, { cwd: dir, stdio: 'inherit', shell });

    const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
    const forward = (signal: NodeJS.Signals) => () => {
      if (!child.killed) child.kill(signal);
    };
    const handlers = signals.map((signal) => {
      const handler = forward(signal);
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
      resolve({ code: code ?? (signal ? 128 + signalNumber(signal) : 1), signal });
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

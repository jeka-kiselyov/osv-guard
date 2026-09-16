/** Tiny ANSI helper — avoids a dependency for a dozen escape codes. */

export interface Colors {
  enabled: boolean;
  red: (s: string) => string;
  yellow: (s: string) => string;
  blue: (s: string) => string;
  green: (s: string) => string;
  gray: (s: string) => string;
  bold: (s: string) => string;
  onRed: (s: string) => string;
}

function wrap(open: string, close: string, enabled: boolean) {
  return (s: string): string => (enabled ? `\u001B[${open}m${s}\u001B[${close}m` : s);
}

/**
 * Honours `--color`/`--no-color`, then NO_COLOR and FORCE_COLOR, then whether
 * stderr is a TTY. Reports go to stderr so that `--format=json` on stdout
 * stays pipeable.
 */
export function createColors(
  override: boolean | undefined,
  env: NodeJS.ProcessEnv = process.env,
  isTty: boolean = process.stderr.isTTY === true,
): Colors {
  let enabled: boolean;
  if (override !== undefined) enabled = override;
  else if (env.NO_COLOR !== undefined && env.NO_COLOR !== '') enabled = false;
  else if (env.FORCE_COLOR !== undefined && env.FORCE_COLOR !== '0') enabled = true;
  else enabled = isTty;

  return {
    enabled,
    red: wrap('31', '39', enabled),
    yellow: wrap('33', '39', enabled),
    blue: wrap('34', '39', enabled),
    green: wrap('32', '39', enabled),
    gray: wrap('90', '39', enabled),
    bold: wrap('1', '22', enabled),
    onRed: wrap('1;41;97', '0', enabled),
  };
}

/** Visible width, ignoring the escape sequences we may have added. */
export function stringWidth(s: string): number {
  return s.replace(/\u001B\[[0-9;]*m/g, '').length;
}

export function padEnd(s: string, width: number): string {
  const diff = width - stringWidth(s);
  return diff > 0 ? s + ' '.repeat(diff) : s;
}

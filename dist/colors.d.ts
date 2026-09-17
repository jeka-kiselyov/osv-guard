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
/**
 * Honours `--color`/`--no-color`, then NO_COLOR and FORCE_COLOR, then whether
 * stderr is a TTY. Reports go to stderr so that `--format=json` on stdout
 * stays pipeable.
 */
export declare function createColors(override: boolean | undefined, env?: NodeJS.ProcessEnv, isTty?: boolean): Colors;
/** Visible width, ignoring the escape sequences we may have added. */
export declare function stringWidth(s: string): number;
export declare function padEnd(s: string, width: number): string;

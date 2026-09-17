import { type Options } from './config.js';
import { type InstallSpec } from './installcmd.js';
import { type FetchLike, type OsvQueryResult } from './osvapi.js';
import { type Finding } from './types.js';
/**
 * Claude Code PreToolUse hook: inspect a Bash command before it runs and stop
 * an install that would pull in something malicious.
 *
 * This is the half of the problem the CLI cannot reach. `osv-guard <script>`
 * guards what you *run* against what is already in the lockfile; by the time a
 * bad dependency is in there, its install scripts have already executed. The
 * hook guards what you *install*, before it lands.
 */
export type Decision = 'allow' | 'ask' | 'deny';
export interface HookInput {
    tool_name?: string;
    tool_input?: {
        command?: string;
    };
    cwd?: string;
}
export interface HookOutcome {
    decision: Decision;
    /** Human-readable explanation, empty when allowing silently. */
    reason: string;
    specs: InstallSpec[];
    malicious: OsvQueryResult[];
    findings: Finding[];
}
export declare function parseHookInput(raw: string): HookInput | null;
/**
 * Decide on a command.
 *
 * Malicious packages are denied outright. Vulnerabilities at or above the
 * configured threshold become `ask` rather than `deny`: a known CVE in a
 * transitive dependency is often a considered trade-off, and that judgement
 * belongs to the person, not the hook. Malware never is.
 */
export declare function evaluateCommand(command: string, dir: string, options?: Partial<Options>, deps?: {
    fetchImpl?: FetchLike;
    timeoutMs?: number;
}): Promise<HookOutcome>;
/** The JSON shape Claude Code expects back from a PreToolUse hook. */
export declare function toHookOutput(outcome: HookOutcome): string;

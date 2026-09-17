import type { Options } from './config.js';
import { type Counts, type Finding } from './types.js';
export interface PolicyResult {
    blocked: boolean;
    /** Findings left after ignores were applied. */
    findings: Finding[];
    counts: Counts;
    /** Findings that tripped a rule, for highlighting in the report. */
    offending: Finding[];
    /** Human-readable reasons, one per rule that failed. */
    reasons: string[];
    /** Advisory ids that were suppressed and actually matched something. */
    ignoredIds: string[];
    /** Ignore entries that matched nothing — likely stale suppressions. */
    unusedIgnores: string[];
}
export declare function countBands(findings: Finding[]): Counts;
export declare function applyPolicy(allFindings: Finding[], options: Options): PolicyResult;

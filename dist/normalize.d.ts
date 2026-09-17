import type { Finding, OsvRawAffected, OsvRawOutput } from './types.js';
/**
 * Pick the fixed version that actually applies to `installed`.
 *
 * An advisory's `affected` list usually covers several release lines (e.g.
 * axios 0.x and 1.x separately), so taking the first `fixed` event would
 * routinely tell a 0.21.0 user to upgrade to 1.15.2. We find the range that
 * contains the installed version and report that range's fix; if the version
 * can't be ordered, we fall back to the lowest fix on offer rather than guess.
 */
export declare function resolveFixedVersion(affected: OsvRawAffected[] | undefined, packageName: string, installed: string): string | null;
/**
 * Flatten osv-scanner's JSON into one `Finding` per group.
 *
 * Groups are the unit because osv-scanner emits a separate `vulnerabilities`
 * entry for each alias of the same flaw — lodash 4.17.15 reports 6
 * vulnerabilities but only 4 distinct issues. Counting raw vulnerabilities
 * would inflate every budget check.
 */
export declare function normalize(raw: OsvRawOutput): {
    findings: Finding[];
    sources: string[];
};

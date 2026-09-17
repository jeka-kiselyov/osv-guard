import type { Band, BandOrUnknown, OsvRawSeverity } from './types.js';
/** CVSS v3.x qualitative rating scale, mapped onto our band names. */
export declare function scoreToBand(score: number): Band | null;
/** GHSA publishes MODERATE where CVSS says MEDIUM; accept both spellings. */
export declare function normalizeBandName(raw: string | undefined | null): Band | null;
/**
 * Compute a CVSS v3.0/v3.1 base score from a vector string. Returns null if the
 * vector is not v3 or is missing required metrics.
 *
 * CVSS v4.0 vectors are intentionally not scored here: v4 base scoring is a
 * 270-entry MacroVector lookup, and in practice osv-scanner already gives us
 * `max_severity`, with GitHub's `database_specific.severity` behind it. A v4
 * vector as the *only* signal is rare enough to be worth reporting honestly as
 * unknown rather than approximating.
 */
export declare function cvss3BaseScore(vector: string): number | null;
export interface SeverityResolution {
    band: BandOrUnknown;
    score: number | null;
    source: 'max_severity' | 'database_specific' | 'cvss_v3' | 'none';
}
/**
 * Resolve a band from every signal available, most trustworthy first:
 *
 *   1. the group's `max_severity` (osv-scanner v2 computes this itself)
 *   2. GitHub's `database_specific.severity` string
 *   3. a CVSS v3 vector we score ourselves
 *
 * Anything left over is `unknown` — never silently treated as benign.
 */
export declare function resolveSeverity(maxSeverity: string | undefined, databaseSpecific: string | undefined, vectors: OsvRawSeverity[] | undefined): SeverityResolution;

import type { InstallSpec } from './installcmd.js';
import type { OsvRawOutput, OsvRawVulnerability } from './types.js';
export interface OsvQueryResult {
    spec: InstallSpec;
    vulns: OsvRawVulnerability[];
    /** Set when the lookup failed; the caller decides whether that blocks. */
    error: string | null;
}
export type FetchLike = typeof globalThis.fetch;
/**
 * Look one package up. Passing a concrete version lets OSV do the affected
 * range matching server-side; without one we get every advisory for the
 * package and report it as "some versions affected".
 */
export declare function queryPackage(spec: InstallSpec, { fetchImpl, timeoutMs }?: {
    fetchImpl?: FetchLike;
    timeoutMs?: number;
}): Promise<OsvQueryResult>;
export declare function queryAll(specs: InstallSpec[], options?: {
    fetchImpl?: FetchLike;
    timeoutMs?: number;
}): Promise<OsvQueryResult[]>;
/**
 * Is this advisory a report of a deliberately malicious package?
 *
 * These matter separately from vulnerabilities: OSV's malicious-package
 * entries carry **no severity at all** (`severity: null`, no CVSS vector), so a
 * plain severity threshold would band every one of them `unknown` and let them
 * through. Malware is not a severity — it is its own verdict.
 */
export declare function isMalicious(vuln: OsvRawVulnerability): boolean;
/**
 * Shape API responses into the structure osv-scanner produces, so the existing
 * `normalize()` → `applyPolicy()` pipeline can score them: one "source" per
 * lookup, one package entry each, groups left out so normalize synthesizes
 * them per vulnerability.
 */
export declare function toScanOutput(results: OsvQueryResult[]): OsvRawOutput;

import { type Colors } from './colors.js';
import type { Options } from './config.js';
import type { PolicyResult } from './policy.js';
import { type Finding, type ScanResult } from './types.js';
/** Most severe first; within a band, worst score first, then stable by name. */
export declare function sortFindings(findings: Finding[]): Finding[];
export interface ReportContext {
    scan: ScanResult;
    policy: PolicyResult;
    options: Options;
    dir: string;
    lockfiles: string[];
}
export declare function renderJson(ctx: ReportContext): string;
export declare function renderSummary(ctx: ReportContext, colors: Colors): string;
export declare function renderPretty(ctx: ReportContext, colors: Colors): string;
/**
 * A monorepo can have dozens of lockfiles; listing them all would bury the
 * findings. Name them while that stays short, then just count.
 */
export declare function describeLockfiles(lockfiles: string[]): string;
/** The package directory a finding came from, relative to the scan root. */
export declare function findingLocation(finding: Finding, dir: string): string;
export declare function render(ctx: ReportContext): {
    text: string;
    stream: 'stdout' | 'stderr';
};

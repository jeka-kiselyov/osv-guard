import type { InstallSpec } from './installcmd.js';
import type { FetchLike } from './osvapi.js';
/**
 * How long ago a package version was published.
 *
 * A freshly published version is the highest-risk window in a supply-chain
 * attack: an attacker publishes a compromised release, and it is usually
 * caught and pulled within hours to a few days. Waiting out that window costs
 * a project very little and removes most of the exposure.
 */
export interface ReleaseInfo {
    /** The version whose age we measured — the resolved `latest` when unpinned. */
    version: string | null;
    publishedAt: Date | null;
    /** True when the install would take whatever `latest` happens to be. */
    resolvedLatest: boolean;
    error: string | null;
}
export declare function resolveReleaseTime(spec: InstallSpec, { fetchImpl, timeoutMs, useCache, now, }?: {
    fetchImpl?: FetchLike;
    timeoutMs?: number;
    useCache?: boolean;
    now?: number;
}): Promise<ReleaseInfo>;
/** Age in milliseconds, or null when we could not establish a publish date. */
export declare function ageMs(info: ReleaseInfo, now?: number): number | null;
/**
 * Too new to trust yet?
 *
 * Unknown ages are *not* treated as too new. Failing closed here would block
 * every install whenever a registry is slow or a package predates the `time`
 * data, and a guard that does that gets switched off.
 */
export declare function isTooNew(info: ReleaseInfo, minAgeMs: number, now?: number): boolean;
/** "3 hours", "2 days" — for a message a person has to act on. */
export declare function formatAge(ms: number): string;

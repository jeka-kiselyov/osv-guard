import type { ScanResult } from './types.js';
export interface CacheKeyInput {
    dir: string;
    lockfiles: string[];
    scannerVersion: string | null;
    /** Scanner-affecting flags only; policy flags are applied after the cache. */
    scanFlags: string[];
}
/**
 * Key on the lockfile *contents*, so a dependency change busts the cache
 * immediately rather than waiting out the TTL. Policy flags (`--fail-on`,
 * `--ignore`, …) are deliberately excluded: they are applied to cached
 * findings, so tightening a threshold takes effect without a rescan.
 */
export declare function cacheKey(input: CacheKeyInput): string;
export declare function cacheDir(projectDir: string): string;
export declare function readCache(projectDir: string, key: string, ttlMs: number, now?: number): ScanResult | null;
export declare function writeCache(projectDir: string, key: string, result: ScanResult): void;

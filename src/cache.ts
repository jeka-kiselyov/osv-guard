import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { ScanResult } from './types.js';

/** Bump when the normalized `Finding` shape changes, to invalidate old entries. */
const CACHE_VERSION = 1;

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
export function cacheKey(input: CacheKeyInput): string {
  const hash = createHash('sha256');
  hash.update(`v${CACHE_VERSION}\n`);
  hash.update(`${input.dir}\n`);
  hash.update(`${input.scannerVersion ?? 'unknown'}\n`);
  hash.update(`${input.scanFlags.join(' ')}\n`);
  for (const name of [...input.lockfiles].sort()) {
    hash.update(`${name}\n`);
    try {
      hash.update(readFileSync(path.join(input.dir, name)));
    } catch {
      hash.update('<unreadable>');
    }
  }
  return hash.digest('hex').slice(0, 32);
}

export function cacheDir(projectDir: string): string {
  return path.join(projectDir, 'node_modules', '.cache', 'osv-guard');
}

interface CacheEntry {
  savedAt: number;
  result: Omit<ScanResult, 'fromCache'>;
}

export function readCache(
  projectDir: string,
  key: string,
  ttlMs: number,
  now: number = Date.now(),
): ScanResult | null {
  const file = path.join(cacheDir(projectDir), `${key}.json`);
  if (!existsSync(file)) return null;
  try {
    const entry = JSON.parse(readFileSync(file, 'utf8')) as CacheEntry;
    if (!entry?.result || typeof entry.savedAt !== 'number') return null;
    if (now - entry.savedAt > ttlMs) return null;
    return { ...entry.result, fromCache: true };
  } catch {
    // A corrupt cache must never be fatal — just rescan.
    return null;
  }
}

export function writeCache(projectDir: string, key: string, result: ScanResult): void {
  try {
    const dir = cacheDir(projectDir);
    mkdirSync(dir, { recursive: true });
    const { fromCache: _ignored, ...rest } = result;
    const entry: CacheEntry = { savedAt: Date.now(), result: rest };
    writeFileSync(path.join(dir, `${key}.json`), JSON.stringify(entry));
  } catch {
    // Read-only checkouts, missing node_modules — caching is a convenience.
  }
}

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
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

const NOT_FOUND: ReleaseInfo = {
  version: null,
  publishedAt: null,
  resolvedLatest: false,
  error: 'no publish date available',
};

// --- disk cache -------------------------------------------------------------

/**
 * A published version's timestamp never changes, so exact versions are cached
 * indefinitely. `latest` does move, so it gets a short TTL.
 *
 * Worth caching because publish times only exist in the *full* packument —
 * the abbreviated one omits `time` — and those run to megabytes for popular
 * packages. This hook runs on every install command an agent issues.
 */
const LATEST_TTL_MS = 10 * 60 * 1000;

interface CacheEntry {
  version: string | null;
  publishedAt: string | null;
  savedAt: number;
  pinned: boolean;
}

function cacheFile(): string {
  const base =
    process.env.XDG_CACHE_HOME ||
    (homedir() ? path.join(homedir(), '.cache') : tmpdir());
  return path.join(base, 'osv-guard', 'release-times.json');
}

function readCacheMap(): Record<string, CacheEntry> {
  try {
    return JSON.parse(readFileSync(cacheFile(), 'utf8')) as Record<string, CacheEntry>;
  } catch {
    return {};
  }
}

function cacheKeyFor(spec: InstallSpec): string {
  return createHash('sha256')
    .update(`${spec.ecosystem}\n${spec.name}\n${spec.version ?? 'latest'}`)
    .digest('hex')
    .slice(0, 24);
}

function readCached(spec: InstallSpec, now: number): ReleaseInfo | null {
  const entry = readCacheMap()[cacheKeyFor(spec)];
  if (!entry) return null;
  if (!entry.pinned && now - entry.savedAt > LATEST_TTL_MS) return null;
  return {
    version: entry.version,
    publishedAt: entry.publishedAt ? new Date(entry.publishedAt) : null,
    resolvedLatest: !entry.pinned,
    error: null,
  };
}

function writeCached(spec: InstallSpec, info: ReleaseInfo): void {
  if (info.error || !info.publishedAt) return;
  try {
    const file = cacheFile();
    mkdirSync(path.dirname(file), { recursive: true });
    const map = existsSync(file) ? readCacheMap() : {};
    map[cacheKeyFor(spec)] = {
      version: info.version,
      publishedAt: info.publishedAt.toISOString(),
      savedAt: Date.now(),
      pinned: !info.resolvedLatest,
    };
    writeFileSync(file, JSON.stringify(map));
  } catch {
    // Caching is a convenience; a read-only home must not break the guard.
  }
}

// --- registry lookups -------------------------------------------------------

interface NpmPackument {
  'dist-tags'?: { latest?: string };
  time?: Record<string, string>;
}

async function npmReleaseTime(spec: InstallSpec, fetchImpl: FetchLike, timeoutMs: number): Promise<ReleaseInfo> {
  const response = await fetchImpl(`https://registry.npmjs.org/${encodeURIComponent(spec.name).replace('%40', '@')}`, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) return { ...NOT_FOUND, error: `registry responded ${response.status}` };

  const packument = (await response.json()) as NpmPackument;
  // An install with no version takes whatever `latest` currently points at,
  // so that is the version whose age actually matters.
  const version = spec.version ?? packument['dist-tags']?.latest ?? null;
  if (!version) return NOT_FOUND;

  const published = packument.time?.[version];
  if (!published) return { ...NOT_FOUND, version };

  return {
    version,
    publishedAt: new Date(published),
    resolvedLatest: spec.version === null,
    error: null,
  };
}

interface PypiResponse {
  info?: { version?: string };
  urls?: { upload_time_iso_8601?: string }[];
}

async function pypiReleaseTime(spec: InstallSpec, fetchImpl: FetchLike, timeoutMs: number): Promise<ReleaseInfo> {
  const url = spec.version
    ? `https://pypi.org/pypi/${encodeURIComponent(spec.name)}/${encodeURIComponent(spec.version)}/json`
    : `https://pypi.org/pypi/${encodeURIComponent(spec.name)}/json`;

  const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) return { ...NOT_FOUND, error: `PyPI responded ${response.status}` };

  const data = (await response.json()) as PypiResponse;
  const version = spec.version ?? data.info?.version ?? null;
  const uploaded = data.urls?.find((u) => u.upload_time_iso_8601)?.upload_time_iso_8601;
  if (!uploaded) return { ...NOT_FOUND, version };

  return {
    version,
    publishedAt: new Date(uploaded),
    resolvedLatest: spec.version === null,
    error: null,
  };
}

export async function resolveReleaseTime(
  spec: InstallSpec,
  {
    fetchImpl = globalThis.fetch,
    timeoutMs = 8000,
    useCache = true,
    now = Date.now(),
  }: { fetchImpl?: FetchLike; timeoutMs?: number; useCache?: boolean; now?: number } = {},
): Promise<ReleaseInfo> {
  if (useCache) {
    const cached = readCached(spec, now);
    if (cached) return cached;
  }

  try {
    const info =
      spec.ecosystem === 'npm'
        ? await npmReleaseTime(spec, fetchImpl, timeoutMs)
        : await pypiReleaseTime(spec, fetchImpl, timeoutMs);
    if (useCache) writeCached(spec, info);
    return info;
  } catch (err) {
    return { ...NOT_FOUND, error: (err as Error).message || 'request failed' };
  }
}

/** Age in milliseconds, or null when we could not establish a publish date. */
export function ageMs(info: ReleaseInfo, now: number = Date.now()): number | null {
  if (!info.publishedAt || Number.isNaN(info.publishedAt.getTime())) return null;
  return now - info.publishedAt.getTime();
}

/**
 * Too new to trust yet?
 *
 * Unknown ages are *not* treated as too new. Failing closed here would block
 * every install whenever a registry is slow or a package predates the `time`
 * data, and a guard that does that gets switched off.
 */
export function isTooNew(info: ReleaseInfo, minAgeMs: number, now: number = Date.now()): boolean {
  if (minAgeMs <= 0) return false;
  const age = ageMs(info, now);
  if (age === null) return false;
  return age < minAgeMs;
}

/** "3 hours", "2 days" — for a message a person has to act on. */
export function formatAge(ms: number): string {
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${Math.max(minutes, 0)} minute${minutes === 1 ? '' : 's'}`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'}`;
  return `${Math.floor(hours / 24)} days`;
}

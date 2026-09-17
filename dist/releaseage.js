import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';
const NOT_FOUND = {
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
function cacheFile() {
    const base = process.env.XDG_CACHE_HOME ||
        (homedir() ? path.join(homedir(), '.cache') : tmpdir());
    return path.join(base, 'osv-guard', 'release-times.json');
}
function readCacheMap() {
    try {
        return JSON.parse(readFileSync(cacheFile(), 'utf8'));
    }
    catch {
        return {};
    }
}
function cacheKeyFor(spec) {
    return createHash('sha256')
        .update(`${spec.ecosystem}\n${spec.name}\n${spec.version ?? 'latest'}`)
        .digest('hex')
        .slice(0, 24);
}
function readCached(spec, now) {
    const entry = readCacheMap()[cacheKeyFor(spec)];
    if (!entry)
        return null;
    if (!entry.pinned && now - entry.savedAt > LATEST_TTL_MS)
        return null;
    return {
        version: entry.version,
        publishedAt: entry.publishedAt ? new Date(entry.publishedAt) : null,
        resolvedLatest: !entry.pinned,
        error: null,
    };
}
function writeCached(spec, info) {
    if (info.error || !info.publishedAt)
        return;
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
    }
    catch {
        // Caching is a convenience; a read-only home must not break the guard.
    }
}
async function npmReleaseTime(spec, fetchImpl, timeoutMs) {
    const response = await fetchImpl(`https://registry.npmjs.org/${encodeURIComponent(spec.name).replace('%40', '@')}`, {
        signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok)
        return { ...NOT_FOUND, error: `registry responded ${response.status}` };
    const packument = (await response.json());
    // An install with no version takes whatever `latest` currently points at,
    // so that is the version whose age actually matters.
    const version = spec.version ?? packument['dist-tags']?.latest ?? null;
    if (!version)
        return NOT_FOUND;
    const published = packument.time?.[version];
    if (!published)
        return { ...NOT_FOUND, version };
    return {
        version,
        publishedAt: new Date(published),
        resolvedLatest: spec.version === null,
        error: null,
    };
}
async function pypiReleaseTime(spec, fetchImpl, timeoutMs) {
    const url = spec.version
        ? `https://pypi.org/pypi/${encodeURIComponent(spec.name)}/${encodeURIComponent(spec.version)}/json`
        : `https://pypi.org/pypi/${encodeURIComponent(spec.name)}/json`;
    const response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok)
        return { ...NOT_FOUND, error: `PyPI responded ${response.status}` };
    const data = (await response.json());
    const version = spec.version ?? data.info?.version ?? null;
    const uploaded = data.urls?.find((u) => u.upload_time_iso_8601)?.upload_time_iso_8601;
    if (!uploaded)
        return { ...NOT_FOUND, version };
    return {
        version,
        publishedAt: new Date(uploaded),
        resolvedLatest: spec.version === null,
        error: null,
    };
}
export async function resolveReleaseTime(spec, { fetchImpl = globalThis.fetch, timeoutMs = 8000, useCache = true, now = Date.now(), } = {}) {
    if (useCache) {
        const cached = readCached(spec, now);
        if (cached)
            return cached;
    }
    try {
        const info = spec.ecosystem === 'npm'
            ? await npmReleaseTime(spec, fetchImpl, timeoutMs)
            : await pypiReleaseTime(spec, fetchImpl, timeoutMs);
        if (useCache)
            writeCached(spec, info);
        return info;
    }
    catch (err) {
        return { ...NOT_FOUND, error: err.message || 'request failed' };
    }
}
/** Age in milliseconds, or null when we could not establish a publish date. */
export function ageMs(info, now = Date.now()) {
    if (!info.publishedAt || Number.isNaN(info.publishedAt.getTime()))
        return null;
    return now - info.publishedAt.getTime();
}
/**
 * Too new to trust yet?
 *
 * Unknown ages are *not* treated as too new. Failing closed here would block
 * every install whenever a registry is slow or a package predates the `time`
 * data, and a guard that does that gets switched off.
 */
export function isTooNew(info, minAgeMs, now = Date.now()) {
    if (minAgeMs <= 0)
        return false;
    const age = ageMs(info, now);
    if (age === null)
        return false;
    return age < minAgeMs;
}
/** "3 hours", "2 days" — for a message a person has to act on. */
export function formatAge(ms) {
    const minutes = Math.floor(ms / 60_000);
    if (minutes < 60)
        return `${Math.max(minutes, 0)} minute${minutes === 1 ? '' : 's'}`;
    const hours = Math.floor(minutes / 60);
    if (hours < 48)
        return `${hours} hour${hours === 1 ? '' : 's'}`;
    return `${Math.floor(hours / 24)} days`;
}

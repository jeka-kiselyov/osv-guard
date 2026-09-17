import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
/** Bump when the normalized `Finding` shape changes, to invalidate old entries. */
const CACHE_VERSION = 1;
/**
 * Key on the lockfile *contents*, so a dependency change busts the cache
 * immediately rather than waiting out the TTL. Policy flags (`--fail-on`,
 * `--ignore`, …) are deliberately excluded: they are applied to cached
 * findings, so tightening a threshold takes effect without a rescan.
 */
export function cacheKey(input) {
    const hash = createHash('sha256');
    hash.update(`v${CACHE_VERSION}\n`);
    hash.update(`${input.dir}\n`);
    hash.update(`${input.scannerVersion ?? 'unknown'}\n`);
    hash.update(`${input.scanFlags.join(' ')}\n`);
    for (const name of [...input.lockfiles].sort()) {
        hash.update(`${name}\n`);
        try {
            hash.update(readFileSync(path.join(input.dir, name)));
        }
        catch {
            hash.update('<unreadable>');
        }
    }
    return hash.digest('hex').slice(0, 32);
}
export function cacheDir(projectDir) {
    return path.join(projectDir, 'node_modules', '.cache', 'osv-guard');
}
export function readCache(projectDir, key, ttlMs, now = Date.now()) {
    const file = path.join(cacheDir(projectDir), `${key}.json`);
    if (!existsSync(file))
        return null;
    try {
        const entry = JSON.parse(readFileSync(file, 'utf8'));
        if (!entry?.result || typeof entry.savedAt !== 'number')
            return null;
        if (now - entry.savedAt > ttlMs)
            return null;
        return { ...entry.result, fromCache: true };
    }
    catch {
        // A corrupt cache must never be fatal — just rescan.
        return null;
    }
}
export function writeCache(projectDir, key, result) {
    try {
        const dir = cacheDir(projectDir);
        mkdirSync(dir, { recursive: true });
        const { fromCache: _ignored, ...rest } = result;
        const entry = { savedAt: Date.now(), result: rest };
        writeFileSync(path.join(dir, `${key}.json`), JSON.stringify(entry));
    }
    catch {
        // Read-only checkouts, missing node_modules — caching is a convenience.
    }
}

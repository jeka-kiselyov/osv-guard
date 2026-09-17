import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
/**
 * Read once from package.json rather than hardcoding a literal in two places,
 * which would silently drift the moment the version is bumped.
 */
function read() {
    try {
        const here = path.dirname(fileURLToPath(import.meta.url));
        const pkg = JSON.parse(readFileSync(path.join(here, '..', 'package.json'), 'utf8'));
        return pkg.version ?? '0.0.0';
    }
    catch {
        return '0.0.0';
    }
}
export const VERSION = read();

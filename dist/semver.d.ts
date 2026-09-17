/**
 * Minimal semver comparison — just enough to decide which affected range a
 * concrete installed version falls into. Not a general semver implementation:
 * no ranges, no coercion beyond a leading `v`, build metadata ignored (as the
 * spec requires).
 */
/**
 * Returns -1, 0 or 1, or `null` when either side is not parseable — callers
 * must decide what an unorderable pair means rather than get a silent 0.
 */
export declare function compareVersions(a: string, b: string): number | null;

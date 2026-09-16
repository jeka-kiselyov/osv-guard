/**
 * Minimal semver comparison — just enough to decide which affected range a
 * concrete installed version falls into. Not a general semver implementation:
 * no ranges, no coercion beyond a leading `v`, build metadata ignored (as the
 * spec requires).
 */

interface Parsed {
  main: number[];
  pre: string[];
}

function parse(version: string): Parsed | null {
  const cleaned = version.trim().replace(/^v/i, '');
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(
    cleaned,
  );
  if (!match) return null;
  return {
    main: [Number(match[1] ?? 0), Number(match[2] ?? 0), Number(match[3] ?? 0)],
    pre: match[4] ? match[4].split('.') : [],
  };
}

function comparePre(a: string[], b: string[]): number {
  // A version with a prerelease is lower than one without.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;

  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i];
    const y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const d = Number(x) - Number(y);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (xNum !== yNum) {
      // Numeric identifiers always have lower precedence than alphanumeric.
      return xNum ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/**
 * Returns -1, 0 or 1, or `null` when either side is not parseable — callers
 * must decide what an unorderable pair means rather than get a silent 0.
 */
export function compareVersions(a: string, b: string): number | null {
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i++) {
    const d = (pa.main[i] ?? 0) - (pb.main[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return comparePre(pa.pre, pb.pre);
}

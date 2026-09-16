import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { cacheKey, readCache, writeCache } from '../dist/cache.js';
import { createColors, padEnd, stringWidth } from '../dist/colors.js';
import { DEFAULTS } from '../dist/config.js';
import { findLockfiles, resolveProjectDir } from '../dist/resolve.js';
import { renderJson, renderPretty, renderSummary, sortFindings } from '../dist/report.js';
import { buildArgs } from '../dist/scanner.js';
import { compareVersions } from '../dist/semver.js';

function tempDir() {
  return mkdtempSync(path.join(tmpdir(), 'osv-guard-test-'));
}

// --- semver ---

test('compareVersions orders release versions', () => {
  assert.equal(compareVersions('1.0.0', '1.0.1'), -1);
  assert.equal(compareVersions('1.10.0', '1.9.0'), 1);
  assert.equal(compareVersions('2.0.0', '2.0.0'), 0);
  assert.equal(compareVersions('v1.2.3', '1.2.3'), 0);
  assert.equal(compareVersions('1.2', '1.2.0'), 0);
});

test('compareVersions ranks a prerelease below its release', () => {
  assert.equal(compareVersions('1.0.0-beta', '1.0.0'), -1);
  assert.equal(compareVersions('1.0.0-alpha', '1.0.0-beta'), -1);
  assert.equal(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.2'), -1);
  assert.equal(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.beta'), -1);
});

test('compareVersions ignores build metadata', () => {
  assert.equal(compareVersions('1.0.0+build1', '1.0.0+build2'), 0);
});

test('compareVersions returns null rather than a misleading zero', () => {
  assert.equal(compareVersions('not-a-version', '1.0.0'), null);
  assert.equal(compareVersions('1.0.0', ''), null);
});

// --- resolve ---

test('resolveProjectDir prefers an explicit --dir', () => {
  const dir = tempDir();
  const result = resolveProjectDir(dir, { npm_config_local_prefix: '/elsewhere' }, '/tmp');
  assert.equal(result.dir, path.resolve(dir));
  assert.equal(result.via, 'flag');
});

test('resolveProjectDir uses npm_config_local_prefix, as npm 7+ sets it', () => {
  const dir = tempDir();
  const result = resolveProjectDir(undefined, { npm_config_local_prefix: dir }, '/tmp');
  assert.equal(result.dir, path.resolve(dir));
  assert.equal(result.via, 'npm_config_local_prefix');
});

test('resolveProjectDir falls back to INIT_CWD when it holds a package.json', () => {
  const dir = tempDir();
  writeFileSync(path.join(dir, 'package.json'), '{}');
  const result = resolveProjectDir(undefined, { INIT_CWD: dir }, '/tmp');
  assert.equal(result.via, 'INIT_CWD');
  assert.equal(result.dir, path.resolve(dir));
});

test('resolveProjectDir walks up to the nearest package.json', () => {
  const root = tempDir();
  writeFileSync(path.join(root, 'package.json'), '{}');
  const nested = path.join(root, 'src', 'deep');
  mkdirSync(nested, { recursive: true });

  const result = resolveProjectDir(undefined, {}, nested);
  assert.equal(result.dir, path.resolve(root));
  assert.equal(result.via, 'walk-up');
});

test('findLockfiles reports the lockfiles actually present', () => {
  const dir = tempDir();
  assert.deepEqual(findLockfiles(dir), []);

  writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  writeFileSync(path.join(dir, 'pnpm-lock.yaml'), '');
  assert.deepEqual(findLockfiles(dir), ['package-lock.json', 'pnpm-lock.yaml']);
});

// --- scanner args ---

test('buildArgs always allows a lockfile-free scan, since osv-guard gates that itself', () => {
  const args = buildArgs({ dir: '/p', scannerBin: 'osv-scanner', offline: false, allVulns: false });

  assert.deepEqual(args, [
    'scan',
    'source',
    '--format=json',
    '--recursive',
    '--verbosity=error',
    '--allow-no-lockfiles',
    '/p',
  ]);
});

test('buildArgs passes through --offline and --all-vulns', () => {
  const args = buildArgs({ dir: '/p', scannerBin: 'osv-scanner', offline: true, allVulns: true });
  assert.ok(args.includes('--offline'));
  assert.ok(args.includes('--all-vulns'));
  assert.equal(args.at(-1), '/p');
});

// --- cache ---

test('cacheKey changes with lockfile contents', () => {
  const dir = tempDir();
  const lock = path.join(dir, 'package-lock.json');
  const input = { dir, lockfiles: ['package-lock.json'], scannerVersion: '2.6.0', scanFlags: [] };

  writeFileSync(lock, '{"a":1}');
  const before = cacheKey(input);
  writeFileSync(lock, '{"a":2}');
  const after = cacheKey(input);

  assert.notEqual(before, after);
});

test('cacheKey changes with the scanner version and its flags', () => {
  const dir = tempDir();
  writeFileSync(path.join(dir, 'package-lock.json'), '{}');
  const base = { dir, lockfiles: ['package-lock.json'], scannerVersion: '2.6.0', scanFlags: [] };

  assert.notEqual(cacheKey(base), cacheKey({ ...base, scannerVersion: '2.7.0' }));
  assert.notEqual(cacheKey(base), cacheKey({ ...base, scanFlags: ['--offline'] }));
  assert.equal(cacheKey(base), cacheKey({ ...base }));
});

test('a cached scan round-trips and is marked as cached', () => {
  const dir = tempDir();
  const result = {
    findings: [],
    sources: ['/p/package-lock.json'],
    durationMs: 1234,
    scannerVersion: '2.6.0',
    fromCache: false,
  };

  writeCache(dir, 'key1', result);
  const read = readCache(dir, 'key1', 60_000);

  assert.ok(read);
  assert.equal(read.fromCache, true);
  assert.equal(read.durationMs, 1234);
  assert.deepEqual(read.sources, ['/p/package-lock.json']);
});

test('an expired or missing cache entry reads as a miss', () => {
  const dir = tempDir();
  writeCache(dir, 'key1', { findings: [], sources: [], durationMs: 1, scannerVersion: null, fromCache: false });

  assert.equal(readCache(dir, 'key1', 60_000, Date.now() + 120_000), null, 'expired');
  assert.equal(readCache(dir, 'nosuchkey', 60_000), null, 'missing');
});

test('a corrupt cache entry is a miss, never a crash', () => {
  const dir = tempDir();
  const cacheDir = path.join(dir, 'node_modules', '.cache', 'osv-guard');
  mkdirSync(cacheDir, { recursive: true });
  writeFileSync(path.join(cacheDir, 'key1.json'), 'not json at all');

  assert.equal(readCache(dir, 'key1', 60_000), null);
});

// --- colors ---

test('color follows the override, then NO_COLOR, then the TTY', () => {
  assert.equal(createColors(true, { NO_COLOR: '1' }, false).enabled, true);
  assert.equal(createColors(false, {}, true).enabled, false);
  assert.equal(createColors(undefined, { NO_COLOR: '1' }, true).enabled, false);
  assert.equal(createColors(undefined, { FORCE_COLOR: '1' }, false).enabled, true);
  assert.equal(createColors(undefined, {}, true).enabled, true);
  assert.equal(createColors(undefined, {}, false).enabled, false);
});

test('stringWidth and padEnd ignore ANSI escapes', () => {
  const colors = createColors(true, {}, true);
  const painted = colors.red('abc');

  assert.ok(painted.length > 3, 'should actually contain escapes');
  assert.equal(stringWidth(painted), 3);
  assert.equal(stringWidth(padEnd(painted, 6)), 6);
});

// --- report ---

let n = 0;
function finding(band, extra = {}) {
  n++;
  return {
    id: extra.id ?? `GHSA-r-${n}`,
    aliases: [],
    band,
    score: extra.score ?? null,
    severitySource: 'max_severity',
    packageName: extra.packageName ?? 'pkg',
    packageVersion: '1.0.0',
    ecosystem: 'npm',
    summary: 'Example summary',
    fixedVersion: 'fixedVersion' in extra ? extra.fixedVersion : '1.0.1',
    url: 'https://example.test',
    source: '/proj/package-lock.json',
  };
}

function context(findings, overrides = {}) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0, total: findings.length };
  for (const f of findings) counts[f.band]++;
  return {
    scan: { findings, sources: [], durationMs: 100, scannerVersion: '2.6.0', fromCache: false },
    policy: {
      blocked: false,
      findings,
      counts,
      offending: [],
      reasons: [],
      ignoredIds: [],
      unusedIgnores: [],
      ...overrides,
    },
    options: { ...DEFAULTS },
    dir: '/proj',
    lockfiles: ['package-lock.json'],
  };
}

test('sortFindings puts the worst first and unknown last', () => {
  const sorted = sortFindings([
    finding('unknown'),
    finding('low', { score: 2 }),
    finding('critical', { score: 9.8 }),
    finding('high', { score: 8.1 }),
    finding('high', { score: 7.0 }),
  ]);

  assert.deepEqual(
    sorted.map((f) => f.band),
    ['critical', 'high', 'high', 'low', 'unknown'],
  );
  assert.deepEqual(
    sorted.filter((f) => f.band === 'high').map((f) => f.score),
    [8.1, 7.0],
    'within a band, worst score first',
  );
});

test('renderJson exposes the verdict, counts and policy', () => {
  const ctx = context([finding('critical', { score: 9.8 })], {
    blocked: true,
    reasons: ['1 critical at or above the `high` threshold'],
  });
  const json = JSON.parse(renderJson(ctx));

  assert.equal(json.blocked, true);
  assert.deepEqual(json.reasons, ['1 critical at or above the `high` threshold']);
  assert.equal(json.counts.critical, 1);
  assert.equal(json.policy.failOn, 'high');
  assert.equal(json.scannerVersion, '2.6.0');
  assert.equal(json.findings.length, 1);
});

test('renderPretty says so plainly when nothing was found', () => {
  const plain = createColors(false, {}, false);
  const text = renderPretty(context([]), plain);

  assert.match(text, /no known vulnerabilities/);
  assert.doesNotMatch(text, /blocked/);
});

test('renderPretty lists findings and the blocking reason', () => {
  const plain = createColors(false, {}, false);
  const critical = finding('critical', { score: 9.8, packageName: 'minimist' });
  const ctx = context([critical], {
    blocked: true,
    offending: [critical],
    reasons: ['1 critical at or above the `high` threshold'],
  });

  const text = renderPretty(ctx, plain);
  assert.match(text, /CRITICAL/);
  assert.match(text, /minimist@1\.0\.0/);
  assert.match(text, /9\.8/);
  assert.match(text, /fixed in 1\.0\.1/);
  assert.match(text, /blocked: 1 critical/);
});

test('renderPretty flags findings with no published fix', () => {
  const plain = createColors(false, {}, false);
  const text = renderPretty(context([finding('high', { fixedVersion: null })]), plain);
  assert.match(text, /no fix published/);
});

test('renderPretty warns about ignore entries that matched nothing', () => {
  const plain = createColors(false, {}, false);
  const text = renderPretty(context([], { unusedIgnores: ['GHSA-STALE'] }), plain);
  assert.match(text, /matched nothing \(stale\?\): GHSA-STALE/);
});

test('renderSummary is a single line either way', () => {
  const plain = createColors(false, {}, false);

  assert.equal(renderSummary(context([]), plain), 'osv-guard: no known vulnerabilities');
  assert.equal(
    renderSummary(context([finding('high')], { blocked: true }), plain),
    'osv-guard: blocked — 1 high',
  );
});

/**
 * Multi-package (monorepo) behaviour: several packages in subdirectories, each
 * with its own lockfile and its own dependency tree.
 *
 * osv-guard passes `--recursive` to osv-scanner, so a monorepo root is a
 * legitimate scan target even when the root itself has no lockfile. These
 * tests pin down the four things that broke when it wasn't:
 *
 *   1. the root must not be rejected as "no lockfile"
 *   2. the cache key must cover *every* lockfile, or a sub-package change
 *      silently keeps a stale (possibly clean) verdict
 *   3. the same advisory in two packages must stay distinguishable
 *   4. counts must reflect per-package instances, since each needs its own fix
 */

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { cacheKey, readCache, writeCache } from '../dist/cache.js';
import { createColors } from '../dist/colors.js';
import { DEFAULTS } from '../dist/config.js';
import { normalize } from '../dist/normalize.js';
import { applyPolicy } from '../dist/policy.js';
import { findLockfiles, resolveProjectDir } from '../dist/resolve.js';
import { describeLockfiles, findingLocation, renderJson, renderPretty, sortFindings } from '../dist/report.js';

function tempDir() {
  return mkdtempSync(path.join(tmpdir(), 'osv-guard-mono-'));
}

/** Build a monorepo skeleton: `{ 'packages/app': '<lockfile contents>' }`. */
function monorepo(layout, { rootLockfile = null } = {}) {
  const root = tempDir();
  writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'root', private: true }));
  if (rootLockfile !== null) writeFileSync(path.join(root, 'package-lock.json'), rootLockfile);

  for (const [dir, contents] of Object.entries(layout)) {
    const full = path.join(root, dir);
    mkdirSync(full, { recursive: true });
    writeFileSync(path.join(full, 'package.json'), JSON.stringify({ name: dir }));
    writeFileSync(path.join(full, 'package-lock.json'), contents);
  }
  return root;
}

// --- discovery ---

test('findLockfiles finds lockfiles in sub-packages, not just the root', () => {
  const root = monorepo({
    'packages/app': '{"app":1}',
    'packages/lib': '{"lib":1}',
    'tools/cli': '{"cli":1}',
  });

  assert.deepEqual(findLockfiles(root), [
    'packages/app/package-lock.json',
    'packages/lib/package-lock.json',
    'tools/cli/package-lock.json',
  ]);
});

test('a monorepo root with no lockfile of its own is still a valid scan target', () => {
  // The bug this pins: looking only at the top level reported "no lockfile"
  // and refused to scan, even though --recursive would have found three.
  const root = monorepo({ 'packages/app': '{"app":1}' });
  assert.notDeepEqual(findLockfiles(root), []);
});

test('findLockfiles includes a root lockfile alongside the sub-packages', () => {
  const root = monorepo({ 'packages/app': '{"app":1}' }, { rootLockfile: '{"root":1}' });

  assert.deepEqual(findLockfiles(root), [
    'package-lock.json',
    'packages/app/package-lock.json',
  ]);
});

test('findLockfiles reports paths relative to the scan root, with / separators', () => {
  const root = monorepo({ 'packages/deep/nested/pkg': '{}' });
  const [found] = findLockfiles(root);

  assert.equal(found, 'packages/deep/nested/pkg/package-lock.json');
  assert.ok(!path.isAbsolute(found));
});

test('findLockfiles never descends into node_modules', () => {
  const root = monorepo({ 'packages/app': '{"app":1}' });
  const nested = path.join(root, 'packages', 'app', 'node_modules', 'dep');
  mkdirSync(nested, { recursive: true });
  writeFileSync(path.join(nested, 'package-lock.json'), '{"transitive":1}');

  assert.deepEqual(findLockfiles(root), ['packages/app/package-lock.json']);
});

test('findLockfiles skips dot-directories', () => {
  const root = monorepo({ 'packages/app': '{}' });
  mkdirSync(path.join(root, '.git', 'x'), { recursive: true });
  writeFileSync(path.join(root, '.git', 'x', 'package-lock.json'), '{}');

  assert.deepEqual(findLockfiles(root), ['packages/app/package-lock.json']);
});

test('findLockfiles picks up mixed package managers across packages', () => {
  const root = tempDir();
  for (const [dir, file] of [
    ['packages/npm-pkg', 'package-lock.json'],
    ['packages/yarn-pkg', 'yarn.lock'],
    ['packages/pnpm-pkg', 'pnpm-lock.yaml'],
  ]) {
    mkdirSync(path.join(root, dir), { recursive: true });
    writeFileSync(path.join(root, dir, file), '');
  }

  assert.deepEqual(findLockfiles(root), [
    'packages/npm-pkg/package-lock.json',
    'packages/pnpm-pkg/pnpm-lock.yaml',
    'packages/yarn-pkg/yarn.lock',
  ]);
});

test('findLockfiles returns a stable order regardless of creation order', () => {
  const a = monorepo({ 'packages/zebra': '{}', 'packages/alpha': '{}' });
  const b = monorepo({ 'packages/alpha': '{}', 'packages/zebra': '{}' });

  assert.deepEqual(findLockfiles(a), findLockfiles(b));
});

test('resolveProjectDir walking up from a sub-package stops at that package', () => {
  // Each package is its own npm project, so `npm run` inside one scans that
  // one — not the whole monorepo.
  const root = monorepo({ 'packages/app': '{}' });
  const result = resolveProjectDir(undefined, {}, path.join(root, 'packages', 'app'));

  assert.equal(result.dir, path.join(root, 'packages', 'app'));
  assert.equal(result.via, 'walk-up');
});

// --- cache ---

test('the cache key covers every sub-package lockfile', () => {
  const root = monorepo({ 'packages/app': '{"v":1}', 'packages/lib': '{"v":1}' });
  const input = { dir: root, lockfiles: findLockfiles(root), scannerVersion: '2.6.0', scanFlags: [] };

  const before = cacheKey(input);
  writeFileSync(path.join(root, 'packages', 'lib', 'package-lock.json'), '{"v":2}');

  assert.notEqual(cacheKey(input), before, 'a sub-package change must invalidate the cache');
});

test('a cached clean verdict cannot survive a vulnerable sub-package', () => {
  // The security bug this pins: the key hashed only top-level lockfiles, so at
  // a monorepo root it hashed nothing. `--cache` then kept returning "clean"
  // (exit 0) after a critical vulnerability was added to a sub-package.
  const root = monorepo({ 'packages/app': '{"minimist":"1.2.8"}' });
  mkdirSync(path.join(root, 'node_modules'), { recursive: true });

  const keyFor = () =>
    cacheKey({
      dir: root,
      lockfiles: findLockfiles(root),
      scannerVersion: '2.6.0',
      scanFlags: [],
    });

  const cleanKey = keyFor();
  writeCache(root, cleanKey, {
    findings: [],
    sources: ['packages/app/package-lock.json'],
    durationMs: 10,
    scannerVersion: '2.6.0',
    fromCache: false,
  });
  assert.ok(readCache(root, cleanKey, 3_600_000), 'clean result is cached');

  // A vulnerable dependency lands in the sub-package.
  writeFileSync(path.join(root, 'packages', 'app', 'package-lock.json'), '{"minimist":"0.0.8"}');

  const newKey = keyFor();
  assert.notEqual(newKey, cleanKey);
  assert.equal(readCache(root, newKey, 3_600_000), null, 'must be a cache miss, forcing a rescan');
});

test('the cache key is stable when nothing changed', () => {
  const root = monorepo({ 'packages/app': '{"v":1}', 'packages/lib': '{"v":1}' });
  const input = { dir: root, lockfiles: findLockfiles(root), scannerVersion: '2.6.0', scanFlags: [] };

  assert.equal(cacheKey(input), cacheKey(input));
});

// --- normalize across several sources ---

/** osv-scanner emits one `results[]` entry per lockfile it reads. */
function multiSourceScan() {
  const advisory = (id, severity, pkg, fixed) => ({
    ids: [id],
    max_severity: severity,
    vuln: {
      id,
      summary: `Problem in ${pkg}`,
      affected: [
        {
          package: { ecosystem: 'npm', name: pkg },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed }] }],
        },
      ],
    },
  });

  const pkgResult = (name, version, advisories) => ({
    package: { name, version, ecosystem: 'npm' },
    groups: advisories.map((a) => ({ ids: a.ids, max_severity: a.max_severity })),
    vulnerabilities: advisories.map((a) => a.vuln),
  });

  return {
    results: [
      {
        source: { path: '/mono/packages/app/package-lock.json', type: 'lockfile' },
        packages: [
          pkgResult('minimist', '0.0.8', [
            advisory('GHSA-xvch-5gv4-984h', '9.8', 'minimist', '0.2.4'),
          ]),
        ],
      },
      {
        source: { path: '/mono/packages/lib/package-lock.json', type: 'lockfile' },
        packages: [
          pkgResult('lodash', '4.17.15', [advisory('GHSA-35jh-r3h4-6jhm', '8.1', 'lodash', '4.17.21')]),
        ],
      },
      {
        source: { path: '/mono/tools/cli/package-lock.json', type: 'lockfile' },
        packages: [
          pkgResult('minimist', '0.0.8', [
            advisory('GHSA-xvch-5gv4-984h', '9.8', 'minimist', '0.2.4'),
          ]),
        ],
      },
    ],
  };
}

test('normalize keeps findings from every package in the monorepo', () => {
  const { findings, sources } = normalize(multiSourceScan());

  assert.equal(findings.length, 3);
  assert.deepEqual(sources, [
    '/mono/packages/app/package-lock.json',
    '/mono/packages/lib/package-lock.json',
    '/mono/tools/cli/package-lock.json',
  ]);
});

test('normalize tags each finding with the package it came from', () => {
  const { findings } = normalize(multiSourceScan());
  const minimist = findings.filter((f) => f.packageName === 'minimist');

  assert.equal(minimist.length, 2, 'one per package that depends on it');
  assert.deepEqual(
    minimist.map((f) => f.source).sort(),
    ['/mono/packages/app/package-lock.json', '/mono/tools/cli/package-lock.json'],
  );
});

// --- policy across several sources ---

test('the same advisory in two packages counts twice, since each needs its own fix', () => {
  const { findings } = normalize(multiSourceScan());
  const result = applyPolicy(findings, { ...DEFAULTS });

  assert.equal(result.counts.critical, 2, 'minimist is vulnerable in two packages');
  assert.equal(result.counts.high, 1);
  assert.equal(result.counts.total, 3);
});

test('deduplication does not collapse the same advisory across different packages', () => {
  const { findings } = normalize(multiSourceScan());
  const result = applyPolicy(findings, { ...DEFAULTS, failOn: 'low' });

  const minimist = result.offending.filter((f) => f.packageName === 'minimist');
  assert.equal(minimist.length, 2, 'both packages must stay in the offending list');
});

test('one --ignore entry suppresses that advisory in every package', () => {
  const { findings } = normalize(multiSourceScan());
  const result = applyPolicy(findings, { ...DEFAULTS, ignore: ['GHSA-xvch-5gv4-984h'] });

  assert.equal(result.counts.critical, 0);
  assert.equal(result.counts.total, 1, 'only the lodash finding remains');
  assert.deepEqual(result.unusedIgnores, [], 'the entry matched, so it is not stale');
});

test('a budget applies across the whole monorepo, not per package', () => {
  const { findings } = normalize(multiSourceScan());

  const tooMany = applyPolicy(findings, { ...DEFAULTS, max: { critical: 1 } });
  assert.equal(tooMany.blocked, true, '2 criticals across packages exceeds a budget of 1');

  const enough = applyPolicy(findings, { ...DEFAULTS, max: { critical: 2, high: 1 } });
  assert.equal(enough.blocked, false);
});

// --- reporting ---

test('describeLockfiles names a couple but only counts many', () => {
  assert.equal(describeLockfiles([]), 'no lockfile');
  assert.equal(describeLockfiles(['package-lock.json']), 'package-lock.json');
  assert.equal(describeLockfiles(['a/package-lock.json', 'b/package-lock.json']), 'a/package-lock.json, b/package-lock.json');
  assert.equal(describeLockfiles(['a', 'b', 'c']), '3 lockfiles');
  assert.equal(describeLockfiles(Array(42).fill('x')), '42 lockfiles');
});

test('findingLocation is the package directory relative to the scan root', () => {
  const [finding] = normalize(multiSourceScan()).findings;

  assert.equal(findingLocation(finding, '/mono'), 'packages/app');
  assert.equal(findingLocation({ ...finding, source: '/mono/package-lock.json' }, '/mono'), '.');
  assert.equal(findingLocation({ ...finding, source: '' }, '/mono'), '');
});

test('sortFindings groups a monorepo deterministically by severity then package', () => {
  const { findings } = normalize(multiSourceScan());
  const sorted = sortFindings(findings);

  assert.deepEqual(
    sorted.map((f) => `${f.band}:${findingLocation(f, '/mono')}`),
    ['critical:packages/app', 'critical:tools/cli', 'high:packages/lib'],
  );
  // Same input in a different order must produce the same output.
  assert.deepEqual(sortFindings([...findings].reverse()), sorted);
});

test('the pretty report says which package each finding is in', () => {
  const plain = createColors(false, {}, false);
  const { findings } = normalize(multiSourceScan());
  const policy = applyPolicy(findings, { ...DEFAULTS });

  const text = renderPretty(
    {
      scan: { findings, sources: [], durationMs: 100, scannerVersion: '2.6.0', fromCache: false },
      policy,
      options: { ...DEFAULTS },
      dir: '/mono',
      lockfiles: ['packages/app/package-lock.json', 'packages/lib/package-lock.json', 'tools/cli/package-lock.json'],
    },
    plain,
  );

  assert.match(text, /3 lockfiles/, 'header should count the lockfiles scanned');
  assert.match(text, /in packages\/app/);
  assert.match(text, /in tools\/cli/);
  assert.match(text, /in packages\/lib/);

  // The two identical minimist rows must be told apart by their location.
  const minimistRows = text.split('\n').filter((l) => l.includes('minimist@0.0.8'));
  assert.equal(minimistRows.length, 2);
  assert.notEqual(minimistRows[0], minimistRows[1], 'identical rows would be useless');
});

test('the pretty report omits the location for a single-package scan', () => {
  const plain = createColors(false, {}, false);
  const single = {
    results: [
      {
        source: { path: '/proj/package-lock.json', type: 'lockfile' },
        packages: [
          {
            package: { name: 'minimist', version: '0.0.8', ecosystem: 'npm' },
            groups: [{ ids: ['GHSA-x'], max_severity: '9.8' }],
            vulnerabilities: [{ id: 'GHSA-x', summary: 'Bad' }],
          },
        ],
      },
    ],
  };
  const { findings } = normalize(single);

  const text = renderPretty(
    {
      scan: { findings, sources: [], durationMs: 10, scannerVersion: '2.6.0', fromCache: false },
      policy: applyPolicy(findings, { ...DEFAULTS }),
      options: { ...DEFAULTS },
      dir: '/proj',
      lockfiles: ['package-lock.json'],
    },
    plain,
  );

  assert.doesNotMatch(text, / in /, 'no location noise when there is only one package');
});

test('the JSON report carries every lockfile and a source per finding', () => {
  const { findings } = normalize(multiSourceScan());
  const lockfiles = [
    'packages/app/package-lock.json',
    'packages/lib/package-lock.json',
    'tools/cli/package-lock.json',
  ];

  const json = JSON.parse(
    renderJson({
      scan: { findings, sources: [], durationMs: 100, scannerVersion: '2.6.0', fromCache: false },
      policy: applyPolicy(findings, { ...DEFAULTS }),
      options: { ...DEFAULTS },
      dir: '/mono',
      lockfiles,
    }),
  );

  assert.deepEqual(json.lockfiles, lockfiles);
  assert.equal(json.counts.critical, 2);
  assert.deepEqual(
    [...new Set(json.findings.map((f) => f.source))].sort(),
    [
      '/mono/packages/app/package-lock.json',
      '/mono/packages/lib/package-lock.json',
      '/mono/tools/cli/package-lock.json',
    ],
  );
});

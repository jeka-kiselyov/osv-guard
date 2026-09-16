import assert from 'node:assert/strict';
import test from 'node:test';
import { DEFAULTS } from '../dist/config.js';
import { applyPolicy, countBands } from '../dist/policy.js';

let counter = 0;
function finding(band, extra = {}) {
  counter++;
  return {
    id: extra.id ?? `GHSA-test-${counter}`,
    aliases: extra.aliases ?? [],
    band,
    score: extra.score ?? null,
    severitySource: 'max_severity',
    packageName: extra.packageName ?? 'pkg',
    packageVersion: '1.0.0',
    ecosystem: 'npm',
    summary: 'Example',
    fixedVersion: 'fixedVersion' in extra ? extra.fixedVersion : '1.0.1',
    url: 'https://example.test',
    source: '/proj/package-lock.json',
  };
}

const options = (overrides = {}) => ({ ...DEFAULTS, ...overrides });

test('countBands tallies every band plus a total', () => {
  const counts = countBands([finding('critical'), finding('high'), finding('high'), finding('unknown')]);
  assert.deepEqual(counts, { critical: 1, high: 2, moderate: 0, low: 0, unknown: 1, total: 4 });
});

test('the default threshold blocks high and critical but allows moderate', () => {
  const blocked = applyPolicy([finding('high')], options());
  assert.equal(blocked.blocked, true);
  assert.match(blocked.reasons[0], /1 high at or above the `high` threshold/);

  const passed = applyPolicy([finding('moderate'), finding('low')], options());
  assert.equal(passed.blocked, false);
  assert.deepEqual(passed.reasons, []);
});

test('an empty scan passes', () => {
  const result = applyPolicy([], options());
  assert.equal(result.blocked, false);
  assert.equal(result.counts.total, 0);
});

test('--fail-on low blocks everything scored', () => {
  assert.equal(applyPolicy([finding('low')], options({ failOn: 'low' })).blocked, true);
});

test('unknown findings do not block unless asked to', () => {
  const lenient = applyPolicy([finding('unknown')], options());
  assert.equal(lenient.blocked, false);

  const strict = applyPolicy([finding('unknown')], options({ failOnUnknown: true }));
  assert.equal(strict.blocked, true);
  assert.match(strict.reasons[0], /no usable severity/);
});

test('a budget replaces the threshold for that band only', () => {
  // --max-high 2 tolerates two highs...
  const tolerated = applyPolicy(
    [finding('high'), finding('high')],
    options({ max: { high: 2 } }),
  );
  assert.equal(tolerated.blocked, false);

  // ...but must not also un-gate critical.
  const stillBlocked = applyPolicy(
    [finding('high'), finding('high'), finding('critical')],
    options({ max: { high: 2 } }),
  );
  assert.equal(stillBlocked.blocked, true);
  assert.match(stillBlocked.reasons[0], /1 critical at or above the `high` threshold/);
});

test('exceeding a budget blocks and names the limit', () => {
  const result = applyPolicy(
    [finding('critical'), finding('critical')],
    options({ max: { critical: 1 } }),
  );
  assert.equal(result.blocked, true);
  assert.match(result.reasons[0], /2 critical vulnerabilities exceeds --max-critical=1/);
  assert.equal(result.offending.length, 2);
});

test('a budget below the threshold still applies', () => {
  const result = applyPolicy([finding('low'), finding('low')], options({ max: { low: 1 } }));
  assert.equal(result.blocked, true);
  assert.match(result.reasons[0], /--max-low=1/);
});

test('--ignore matches the primary id case-insensitively', () => {
  const result = applyPolicy(
    [finding('critical', { id: 'GHSA-aaaa-bbbb-cccc' })],
    options({ ignore: ['ghsa-aaaa-bbbb-cccc'] }),
  );
  assert.equal(result.blocked, false);
  assert.deepEqual(result.ignoredIds, ['GHSA-aaaa-bbbb-cccc']);
  assert.deepEqual(result.unusedIgnores, []);
});

test('--ignore also matches an alias, so a CVE id works', () => {
  const result = applyPolicy(
    [finding('critical', { id: 'GHSA-aaaa-bbbb-cccc', aliases: ['CVE-2020-1234'] })],
    options({ ignore: ['CVE-2020-1234'] }),
  );
  assert.equal(result.blocked, false);
  assert.equal(result.counts.total, 0);
});

test('ignore entries that match nothing are reported as possibly stale', () => {
  const result = applyPolicy([finding('critical')], options({ ignore: ['GHSA-none-none-none'] }));
  assert.equal(result.blocked, true);
  assert.deepEqual(result.unusedIgnores, ['GHSA-NONE-NONE-NONE']);
});

test('--ignore-unfixed drops only findings with no published fix', () => {
  const findings = [
    finding('critical', { fixedVersion: null }),
    finding('critical', { fixedVersion: '2.0.0' }),
  ];

  const kept = applyPolicy(findings, options());
  assert.equal(kept.counts.critical, 2);

  const dropped = applyPolicy(findings, options({ ignoreUnfixed: true }));
  assert.equal(dropped.counts.critical, 1);
  assert.equal(dropped.blocked, true);
});

test('offending findings are deduplicated across overlapping rules', () => {
  const result = applyPolicy(
    [finding('critical'), finding('critical')],
    options({ max: { critical: 0 }, failOn: 'critical' }),
  );
  assert.equal(result.reasons.length, 1, 'a budgeted band should not double-report');
  assert.equal(result.offending.length, 2);
});

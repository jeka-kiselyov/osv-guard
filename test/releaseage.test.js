/**
 * Minimum release age: hold versions published too recently to have been
 * caught yet. The riskiest window in a supply-chain attack is the first hours
 * after a compromised release goes up.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { evaluateCommand, isAgeExempt } from '../dist/hook.js';
import { ageMs, formatAge, isTooNew, resolveReleaseTime } from '../dist/releaseage.js';

const DAY = 24 * 60 * 60 * 1000;
const npmSpec = (name, version = null) => ({ ecosystem: 'npm', name, version, raw: name });

function emptyDir() {
  return mkdtempSync(path.join(tmpdir(), 'osv-guard-age-'));
}

// --- the age predicate ---

test('isTooNew compares the age against the window', () => {
  const now = Date.now();
  const fresh = { version: '1.0.0', publishedAt: new Date(now - 60_000), resolvedLatest: false, error: null };
  const old = { version: '1.0.0', publishedAt: new Date(now - 30 * DAY), resolvedLatest: false, error: null };

  assert.equal(isTooNew(fresh, 7 * DAY, now), true);
  assert.equal(isTooNew(old, 7 * DAY, now), false);
});

test('a zero window disables the check entirely', () => {
  const now = Date.now();
  const fresh = { version: '1.0.0', publishedAt: new Date(now), resolvedLatest: false, error: null };
  assert.equal(isTooNew(fresh, 0, now), false);
});

test('an unknown publish date is not treated as too new', () => {
  // Failing closed would block every install whenever a registry is slow or a
  // package predates the registry's time data — and that guard gets disabled.
  const now = Date.now();
  for (const info of [
    { version: null, publishedAt: null, resolvedLatest: false, error: 'timeout' },
    { version: '1.0.0', publishedAt: new Date('nonsense'), resolvedLatest: false, error: null },
  ]) {
    assert.equal(isTooNew(info, 7 * DAY, now), false);
    assert.equal(ageMs(info, now), null);
  }
});

test('the boundary is exclusive: exactly the window old passes', () => {
  const now = Date.now();
  const exactly = { version: '1.0.0', publishedAt: new Date(now - 7 * DAY), resolvedLatest: false, error: null };
  assert.equal(isTooNew(exactly, 7 * DAY, now), false);
});

test('formatAge reads like something a person would say', () => {
  assert.equal(formatAge(30 * 60_000), '30 minutes');
  assert.equal(formatAge(60_000), '1 minute');
  assert.equal(formatAge(4 * 60 * 60_000), '4 hours');
  assert.equal(formatAge(7 * DAY), '7 days');
});

// --- registry lookups ---

function stubRegistry(body, { ok = true } = {}) {
  return async () => ({ ok, json: async () => body });
}

test('an npm lookup reads the publish time for the pinned version', async () => {
  const info = await resolveReleaseTime(npmSpec('pkg', '1.2.3'), {
    useCache: false,
    fetchImpl: stubRegistry({
      'dist-tags': { latest: '2.0.0' },
      time: { '1.2.3': '2020-01-01T00:00:00.000Z', '2.0.0': '2026-01-01T00:00:00.000Z' },
    }),
  });

  assert.equal(info.version, '1.2.3');
  assert.equal(info.publishedAt.toISOString(), '2020-01-01T00:00:00.000Z');
  assert.equal(info.resolvedLatest, false);
});

test('an unpinned install is measured against whatever latest currently is', async () => {
  // `npm i pkg` installs dist-tags.latest, so that is the version whose age
  // actually matters — not the oldest or newest in the packument.
  const info = await resolveReleaseTime(npmSpec('pkg'), {
    useCache: false,
    fetchImpl: stubRegistry({
      'dist-tags': { latest: '2.0.0' },
      time: { '1.2.3': '2020-01-01T00:00:00.000Z', '2.0.0': '2026-09-01T00:00:00.000Z' },
    }),
  });

  assert.equal(info.version, '2.0.0');
  assert.equal(info.resolvedLatest, true);
});

test('a PyPI lookup reads upload_time_iso_8601', async () => {
  const info = await resolveReleaseTime({ ecosystem: 'PyPI', name: 'requests', version: '2.19.1', raw: 'requests' }, {
    useCache: false,
    fetchImpl: stubRegistry({ urls: [{ upload_time_iso_8601: '2018-06-14T13:40:38.236729Z' }] }),
  });

  assert.equal(info.publishedAt.toISOString().slice(0, 10), '2018-06-14');
});

test('a registry failure reports an error rather than throwing', async () => {
  const bad = await resolveReleaseTime(npmSpec('pkg', '1.0.0'), {
    useCache: false,
    fetchImpl: stubRegistry({}, { ok: false }),
  });
  assert.equal(bad.publishedAt, null);
  assert.ok(bad.error);

  const thrown = await resolveReleaseTime(npmSpec('pkg', '1.0.0'), {
    useCache: false,
    fetchImpl: async () => {
      throw new Error('network down');
    },
  });
  assert.equal(thrown.publishedAt, null);
  assert.match(thrown.error, /network down/);
});

test('a version missing from the time map yields no date', async () => {
  const info = await resolveReleaseTime(npmSpec('pkg', '9.9.9'), {
    useCache: false,
    fetchImpl: stubRegistry({ 'dist-tags': { latest: '1.0.0' }, time: { '1.0.0': '2020-01-01T00:00:00.000Z' } }),
  });
  assert.equal(info.publishedAt, null);
});

// --- exemptions ---

test('allowNewPackages matches by name or by exact name@version', () => {
  assert.equal(isAgeExempt(npmSpec('pkg', '1.0.0'), ['pkg']), true);
  assert.equal(isAgeExempt(npmSpec('pkg', '1.0.0'), ['pkg@1.0.0']), true);
  assert.equal(isAgeExempt(npmSpec('pkg', '2.0.0'), ['pkg@1.0.0']), false);
  assert.equal(isAgeExempt(npmSpec('@scope/pkg', '1.0.0'), ['@scope/pkg']), true);
  assert.equal(isAgeExempt(npmSpec('@scope/pkg', '1.0.0'), ['@scope/pkg@1.0.0']), true);
  assert.equal(isAgeExempt(npmSpec('other', '1.0.0'), ['pkg']), false);
  assert.equal(isAgeExempt(npmSpec('pkg', '1.0.0'), []), false);
});

// --- end-to-end decisions ---

/** OSV says clean; the registry says the version is `ageDays` old. */
function stubs(ageDays) {
  return {
    // Never read or write the user's real ~/.cache during tests.
    useCache: false,
    fetchImpl: async (url) => {
      if (String(url).includes('api.osv.dev')) {
        return { ok: true, json: async () => ({ vulns: [] }) };
      }
      const published = new Date(Date.now() - ageDays * DAY).toISOString();
      return {
        ok: true,
        json: async () => ({ 'dist-tags': { latest: '1.0.0' }, time: { '1.0.0': published } }),
      };
    },
  };
}

test('a fresh release asks, so the user can force it', async () => {
  const outcome = await evaluateCommand('npm i pkg@1.0.0', emptyDir(), {}, stubs(0.1));

  assert.equal(outcome.decision, 'ask');
  assert.equal(outcome.tooNew.length, 1);
  assert.match(outcome.reason, /TOO NEW\s+pkg@1\.0\.0/);
  assert.match(outcome.reason, /Approve to install anyway/);
  assert.match(outcome.reason, /allowNewPackages/, 'tells the user how to stop being asked');
});

test('a well-aged release is allowed silently', async () => {
  const outcome = await evaluateCommand('npm i pkg@1.0.0', emptyDir(), {}, stubs(90));

  assert.equal(outcome.decision, 'allow');
  assert.deepEqual(outcome.tooNew, []);
});

test('the window is configurable from osv-guard.json', async () => {
  const dir = emptyDir();
  writeFileSync(path.join(dir, 'osv-guard.json'), JSON.stringify({ minReleaseAge: '30d' }));

  const outcome = await evaluateCommand('npm i pkg@1.0.0', dir, {}, stubs(10));
  assert.equal(outcome.decision, 'ask', '10 days old is inside a 30-day window');
});

test('minReleaseAge 0 turns the check off without a registry call', async () => {
  const dir = emptyDir();
  writeFileSync(path.join(dir, 'osv-guard.json'), JSON.stringify({ minReleaseAge: 0 }));

  let registryCalls = 0;
  const outcome = await evaluateCommand('npm i pkg@1.0.0', dir, {}, {
    useCache: false,
    fetchImpl: async (url) => {
      if (String(url).includes('registry.npmjs.org')) registryCalls++;
      return { ok: true, json: async () => ({ vulns: [] }) };
    },
  });

  assert.equal(outcome.decision, 'allow');
  assert.equal(registryCalls, 0, 'no round-trip for a check that is turned off');
});

test('an exempt package skips the age check', async () => {
  const dir = emptyDir();
  writeFileSync(path.join(dir, 'osv-guard.json'), JSON.stringify({ allowNewPackages: ['pkg'] }));

  const outcome = await evaluateCommand('npm i pkg@1.0.0', dir, {}, stubs(0.1));
  assert.equal(outcome.decision, 'allow');
});

test('malicious still denies even when the release is also too new', async () => {
  const outcome = await evaluateCommand('npm i evil@1.0.0', emptyDir(), {}, {
    useCache: false,
    fetchImpl: async (url) => {
      if (String(url).includes('api.osv.dev')) {
        return {
          ok: true,
          json: async () => ({ vulns: [{ id: 'MAL-2024-1', summary: 'Malicious code in evil (npm)' }] }),
        };
      }
      return {
        ok: true,
        json: async () => ({ 'dist-tags': { latest: '1.0.0' }, time: { '1.0.0': new Date().toISOString() } }),
      };
    },
  });

  assert.equal(outcome.decision, 'deny', 'malware is never downgraded to an ask');
});

test('a registry outage does not block the install', async () => {
  const outcome = await evaluateCommand('npm i pkg@1.0.0', emptyDir(), {}, {
    useCache: false,
    fetchImpl: async (url) => {
      if (String(url).includes('api.osv.dev')) return { ok: true, json: async () => ({ vulns: [] }) };
      throw new Error('registry unreachable');
    },
  });

  assert.equal(outcome.decision, 'allow');
});

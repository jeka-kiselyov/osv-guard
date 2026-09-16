import assert from 'node:assert/strict';
import test from 'node:test';
import {
  cvss3BaseScore,
  normalizeBandName,
  resolveSeverity,
  scoreToBand,
} from '../dist/severity.js';

test('scoreToBand uses the CVSS v3 qualitative scale', () => {
  assert.equal(scoreToBand(10), 'critical');
  assert.equal(scoreToBand(9.0), 'critical');
  assert.equal(scoreToBand(8.9), 'high');
  assert.equal(scoreToBand(7.0), 'high');
  assert.equal(scoreToBand(6.9), 'moderate');
  assert.equal(scoreToBand(4.0), 'moderate');
  assert.equal(scoreToBand(3.9), 'low');
  assert.equal(scoreToBand(0.1), 'low');
  assert.equal(scoreToBand(0), null);
  assert.equal(scoreToBand(Number.NaN), null);
});

test('normalizeBandName accepts GHSA and CVSS spellings', () => {
  assert.equal(normalizeBandName('CRITICAL'), 'critical');
  assert.equal(normalizeBandName('moderate'), 'moderate');
  assert.equal(normalizeBandName('Medium'), 'moderate');
  assert.equal(normalizeBandName('  High  '), 'high');
  assert.equal(normalizeBandName('bogus'), null);
  assert.equal(normalizeBandName(undefined), null);
});

test('cvss3BaseScore matches published reference scores', () => {
  // Published examples from the CVSS v3.1 specification and real advisories.
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H'), 5.5);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L'), 7.0);
  assert.equal(cvss3BaseScore('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
});

test('cvss3BaseScore returns 0 when there is no impact', () => {
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
});

test('cvss3BaseScore declines vectors it cannot score', () => {
  assert.equal(cvss3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H'), null);
  assert.equal(cvss3BaseScore('CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P'), null);
  assert.equal(cvss3BaseScore('CVSS:3.1/AV:N/AC:L'), null);
  assert.equal(cvss3BaseScore('nonsense'), null);
});

test('resolveSeverity prefers max_severity over every other signal', () => {
  const r = resolveSeverity('9.1', 'LOW', [
    { type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H' },
  ]);
  assert.deepEqual(r, { band: 'critical', score: 9.1, source: 'max_severity' });
});

test('resolveSeverity falls back to database_specific, then to a CVSS v3 vector', () => {
  assert.deepEqual(resolveSeverity(undefined, 'MODERATE', undefined), {
    band: 'moderate',
    score: null,
    source: 'database_specific',
  });

  assert.deepEqual(
    resolveSeverity(undefined, undefined, [
      { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    ]),
    { band: 'critical', score: 9.8, source: 'cvss_v3' },
  );
});

test('resolveSeverity reports unknown rather than assuming benign', () => {
  assert.deepEqual(resolveSeverity(undefined, undefined, undefined), {
    band: 'unknown',
    score: null,
    source: 'none',
  });

  // A CVSS v4 vector alone is not scored — it must not silently become "low".
  assert.equal(
    resolveSeverity(undefined, undefined, [
      { type: 'CVSS_V4', score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H' },
    ]).band,
    'unknown',
  );
});

test('resolveSeverity treats an explicit zero score as a real answer', () => {
  assert.deepEqual(resolveSeverity('0', 'CRITICAL', undefined), {
    band: 'low',
    score: 0,
    source: 'max_severity',
  });
});

test('resolveSeverity skips an empty max_severity string', () => {
  assert.equal(resolveSeverity('', 'HIGH', undefined).source, 'database_specific');
});

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { normalize, resolveFixedVersion } from '../dist/normalize.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const vulnerable = JSON.parse(
  readFileSync(path.join(here, 'fixtures', 'scan-vulnerable.json'), 'utf8'),
);

test('normalize emits one finding per group, not per alias', () => {
  const { findings } = normalize(vulnerable);
  const lodash = findings.filter((f) => f.packageName === 'lodash');

  // The fixture has 6 lodash vulnerability records but only 4 distinct issues;
  // counting records would inflate every budget check.
  const records = vulnerable.results[0].packages.find((p) => p.package.name === 'lodash');
  assert.equal(records.vulnerabilities.length, 6);
  assert.equal(records.groups.length, 4);
  assert.equal(lodash.length, 4);
});

test('normalize picks the GHSA id and keeps the CVE as an alias', () => {
  const { findings } = normalize(vulnerable);
  const finding = findings.find((f) => f.id === 'GHSA-35jh-r3h4-6jhm');

  assert.ok(finding, 'expected the lodash command-injection advisory');
  assert.ok(finding.id.startsWith('GHSA-'));
  assert.ok(finding.aliases.includes('CVE-2021-23337'));
  assert.ok(!finding.aliases.includes(finding.id), 'primary id should not repeat in aliases');
  assert.equal(finding.url, 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm');
});

test('normalize reports the fix for the installed release line', () => {
  const { findings } = normalize(vulnerable);

  // GHSA-3g43-6gmg-66jw lists axios 1.0.0–1.15.2 first, but the installed
  // version is 0.21.0, whose own range fixes in 0.31.1.
  const axios = findings.find((f) => f.id === 'GHSA-3g43-6gmg-66jw');
  assert.equal(axios.packageVersion, '0.21.0');
  assert.equal(axios.fixedVersion, '0.31.1');

  const lodash = findings.find((f) => f.id === 'GHSA-35jh-r3h4-6jhm');
  assert.equal(lodash.fixedVersion, '4.17.21');
});

test('normalize carries severity through from the fixture', () => {
  const { findings } = normalize(vulnerable);
  const minimist = findings.find((f) => f.id === 'GHSA-xvch-5gv4-984h');

  assert.equal(minimist.band, 'critical');
  assert.equal(minimist.score, 9.8);
  assert.equal(minimist.severitySource, 'max_severity');
  assert.equal(minimist.fixedVersion, '0.2.4');
});

test('normalize collects the source lockfiles', () => {
  const { sources } = normalize(vulnerable);
  assert.deepEqual(sources, ['/proj/package-lock.json']);
});

test('normalize handles empty and malformed input without throwing', () => {
  assert.deepEqual(normalize({ results: [] }), { findings: [], sources: [] });
  assert.deepEqual(normalize({}), { findings: [], sources: [] });
  assert.deepEqual(normalize({ results: [{ packages: [{}] }] }).findings, []);
});

test('normalize synthesizes groups when the scanner omits them', () => {
  const { findings } = normalize({
    results: [
      {
        source: { path: '/p/package-lock.json' },
        packages: [
          {
            package: { name: 'left-pad', version: '1.0.0', ecosystem: 'npm' },
            vulnerabilities: [
              {
                id: 'GHSA-aaaa-bbbb-cccc',
                summary: 'Example',
                database_specific: { severity: 'HIGH' },
              },
            ],
          },
        ],
      },
    ],
  });

  assert.equal(findings.length, 1);
  assert.equal(findings[0].band, 'high');
  assert.equal(findings[0].severitySource, 'database_specific');
});

test('normalize drops withdrawn advisories', () => {
  const { findings } = normalize({
    results: [
      {
        source: { path: '/p/package-lock.json' },
        packages: [
          {
            package: { name: 'x', version: '1.0.0', ecosystem: 'npm' },
            groups: [{ ids: ['GHSA-dead-beef-0000'], max_severity: '9.9' }],
            vulnerabilities: [
              { id: 'GHSA-dead-beef-0000', withdrawn: '2024-01-01T00:00:00Z' },
            ],
          },
        ],
      },
    ],
  });

  assert.deepEqual(findings, []);
});

test('normalize falls back to the first line of details when there is no summary', () => {
  const { findings } = normalize({
    results: [
      {
        packages: [
          {
            package: { name: 'x', version: '1.0.0', ecosystem: 'npm' },
            groups: [{ ids: ['OSV-1'], max_severity: '5.0' }],
            vulnerabilities: [{ id: 'OSV-1', details: '\n### Impact\nSecond line' }],
          },
        ],
      },
    ],
  });

  assert.equal(findings[0].summary, '### Impact');
  assert.equal(findings[0].url, 'https://osv.dev/vulnerability/OSV-1');
});

test('resolveFixedVersion selects the range containing the installed version', () => {
  const affected = [
    {
      package: { name: 'pkg', ecosystem: 'npm' },
      ranges: [
        { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.9.0' }] },
        { type: 'SEMVER', events: [{ introduced: '2.0.0' }, { fixed: '2.4.0' }] },
      ],
    },
  ];

  assert.equal(resolveFixedVersion(affected, 'pkg', '1.2.3'), '1.9.0');
  assert.equal(resolveFixedVersion(affected, 'pkg', '2.1.0'), '2.4.0');
});

test('resolveFixedVersion handles an open-ended "introduced: 0" range', () => {
  const affected = [
    {
      package: { name: 'pkg', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.4' }] }],
    },
  ];
  assert.equal(resolveFixedVersion(affected, 'pkg', '0.0.8'), '0.2.4');
});

test('resolveFixedVersion returns null when nothing is fixed yet', () => {
  const affected = [
    {
      package: { name: 'pkg', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
    },
  ];
  assert.equal(resolveFixedVersion(affected, 'pkg', '1.0.0'), null);
  assert.equal(resolveFixedVersion(undefined, 'pkg', '1.0.0'), null);
});

test('resolveFixedVersion ignores other packages in the advisory', () => {
  const affected = [
    {
      package: { name: 'other', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }],
    },
    {
      package: { name: 'pkg', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.0' }] }],
    },
  ];
  assert.equal(resolveFixedVersion(affected, 'pkg', '1.0.0'), '1.2.0');
});

test('resolveFixedVersion falls back to the lowest fix for unorderable versions', () => {
  const affected = [
    {
      package: { name: 'pkg', ecosystem: 'npm' },
      ranges: [
        { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0.0' }] },
        { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.5.0' }] },
      ],
    },
  ];
  assert.equal(resolveFixedVersion(affected, 'pkg', 'not-a-version'), '1.5.0');
});

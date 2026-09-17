/**
 * The Claude Code PreToolUse hook: parsing install commands, classifying
 * malicious packages, and the allow/ask/deny decision.
 *
 * Everything here runs against a stub fetch — no network, no osv-scanner.
 */

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { evaluateCommand, parseHookInput, toHookOutput } from '../dist/hook.js';
import { isExactVersion, isPackageArgument, parseInstallCommand, parseSpec, segments } from '../dist/installcmd.js';
import { isMalicious, toScanOutput } from '../dist/osvapi.js';

function emptyDir() {
  return mkdtempSync(path.join(tmpdir(), 'osv-guard-hook-'));
}

// --- command parsing ---

test('every supported package manager is recognised', () => {
  for (const command of [
    'npm install minimist@0.0.8',
    'npm i minimist@0.0.8',
    'npm add minimist@0.0.8',
    'pnpm add minimist@0.0.8',
    'pnpm install minimist@0.0.8',
    'pnpm i minimist@0.0.8',
    'yarn add minimist@0.0.8',
    'bun add minimist@0.0.8',
    'bun install minimist@0.0.8',
  ]) {
    assert.deepEqual(
      parseInstallCommand(command),
      [{ ecosystem: 'npm', name: 'minimist', version: '0.0.8', raw: 'minimist@0.0.8' }],
      command,
    );
  }
});

test('python installers map to the PyPI ecosystem', () => {
  for (const command of [
    'pip install requests==2.19.1',
    'pip3 install requests==2.19.1',
    'python -m pip install requests==2.19.1',
    'python3 -m pip install requests==2.19.1',
    'uv pip install requests==2.19.1',
    'uv add requests==2.19.1',
    'poetry add requests==2.19.1',
  ]) {
    const [spec] = parseInstallCommand(command);
    assert.equal(spec?.ecosystem, 'PyPI', command);
    assert.equal(spec?.name, 'requests', command);
    assert.equal(spec?.version, '2.19.1', command);
  }
});

test('a bare install introduces nothing new and is ignored', () => {
  // Restoring a lockfile installs only what the project already committed to.
  for (const command of ['npm install', 'pnpm install', 'yarn', 'bun install', 'npm ci']) {
    assert.deepEqual(parseInstallCommand(command), [], command);
  }
});

test('commands that are not installs are ignored', () => {
  for (const command of ['ls -la', 'git commit -m "npm install"', 'echo npm i foo', 'npm run build']) {
    assert.deepEqual(parseInstallCommand(command), [], command);
  }
});

test('an install hidden in a chained command is still found', () => {
  for (const command of [
    'cd /tmp && pnpm add evil@1.0.0',
    'echo hi; npm i evil@1.0.0',
    'false || npm i evil@1.0.0',
    'set -e\nnpm i evil@1.0.0',
  ]) {
    assert.deepEqual(parseInstallCommand(command).map((s) => s.name), ['evil'], command);
  }
});

test('scoped packages keep their scope', () => {
  assert.deepEqual(parseInstallCommand('npm i @scope/pkg@1.2.3'), [
    { ecosystem: 'npm', name: '@scope/pkg', version: '1.2.3', raw: '@scope/pkg@1.2.3' },
  ]);
  assert.deepEqual(parseInstallCommand('npm i @scope/pkg').map((s) => s.name), ['@scope/pkg']);
});

test('several packages in one command are all returned, deduplicated', () => {
  const specs = parseInstallCommand('npm i a@1.0.0 b@2.0.0 a@1.0.0');
  assert.deepEqual(specs.map((s) => `${s.name}@${s.version}`), ['a@1.0.0', 'b@2.0.0']);
});

test('flags and their inline values are not mistaken for packages', () => {
  const specs = parseInstallCommand('npm i --save-dev --registry=https://r.npmjs.org minimist@0.0.8');
  assert.deepEqual(specs.map((s) => s.name), ['minimist']);
});

test('non-registry arguments are skipped', () => {
  for (const arg of [
    './local',
    '/abs/path',
    '~/home/pkg',
    'https://example.com/p.tgz',
    'file:../x',
    'git+ssh://git@github.com/a/b.git',
    'github:user/repo',
    'user/repo',
    'pkg.tgz',
    'workspace:*',
  ]) {
    assert.equal(isPackageArgument(arg), false, arg);
  }
  assert.equal(isPackageArgument('minimist'), true);
  assert.equal(isPackageArgument('@scope/pkg'), true);
});

test('only exact versions are treated as pinned', () => {
  for (const v of ['1.2.3', '0.0.8', '1.2.3-beta.1', '1.2', '4']) {
    assert.equal(isExactVersion(v), true, v);
  }
  for (const v of ['^1.2.3', '~1.0', '>=2', 'latest', 'next', '*', '']) {
    assert.equal(isExactVersion(v), false, v);
  }
});

test('a range leaves the version unpinned so every release is checked', () => {
  assert.equal(parseSpec('minimist@^1.0.0', 'npm')?.version, null);
  assert.equal(parseSpec('minimist@latest', 'npm')?.version, null);
  assert.equal(parseSpec('requests>=2.0', 'PyPI')?.version, null);
});

test('pip extras are stripped from the package name', () => {
  assert.equal(parseSpec('requests[security]==2.19.1', 'PyPI')?.name, 'requests');
});

test('segments splits on every shell separator', () => {
  assert.deepEqual(segments('a && b; c || d | e'), ['a', 'b', 'c', 'd', 'e']);
});

// --- malicious classification ---

test('isMalicious recognises every form OSV uses', () => {
  assert.equal(isMalicious({ id: 'MAL-2024-1000' }), true, 'MAL- id');
  assert.equal(
    isMalicious({ id: 'GHSA-x', database_specific: { 'malicious-packages-origins': [] } }),
    true,
    'origins key',
  );
  assert.equal(
    isMalicious({ id: 'GHSA-x', summary: 'Malicious code in custom-solutions (npm)' }),
    true,
    'summary',
  );

  assert.equal(isMalicious({ id: 'GHSA-x', summary: 'Prototype Pollution in minimist' }), false);
  assert.equal(isMalicious({ id: 'GHSA-x' }), false);
});

test('toScanOutput shapes API results for the existing normalize pipeline', () => {
  const output = toScanOutput([
    {
      spec: { ecosystem: 'npm', name: 'minimist', version: '0.0.8', raw: 'minimist@0.0.8' },
      vulns: [{ id: 'GHSA-x', summary: 'Bad', database_specific: { severity: 'HIGH' } }],
      error: null,
    },
    {
      spec: { ecosystem: 'npm', name: 'clean', version: '1.0.0', raw: 'clean@1.0.0' },
      vulns: [],
      error: null,
    },
  ]);

  assert.equal(output.results.length, 1, 'clean packages contribute no results');
  assert.equal(output.results[0].packages[0].package.name, 'minimist');
  assert.equal(output.results[0].packages[0].package.version, '0.0.8');
});

// --- decisions ---

/** A fetch stub returning canned OSV responses keyed by package name. */
function stubFetch(byName) {
  return async (_url, init) => {
    const body = JSON.parse(init.body);
    const vulns = byName[body.package.name] ?? [];
    return { ok: true, json: async () => ({ vulns }) };
  };
}

const MALICIOUS_VULN = {
  id: 'MAL-2024-1000',
  summary: 'Malicious code in evil-pkg (npm)',
  database_specific: { 'malicious-packages-origins': [] },
  affected: [{ package: { ecosystem: 'npm', name: 'evil-pkg' }, versions: ['1.0.0', '1.0.1'] }],
};

const CRITICAL_VULN = {
  id: 'GHSA-crit-0000-0000',
  summary: 'Prototype Pollution',
  database_specific: { severity: 'CRITICAL' },
  affected: [
    {
      package: { ecosystem: 'npm', name: 'vuln-pkg' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
    },
  ],
};

const MODERATE_VULN = {
  id: 'GHSA-mod-0000-0000',
  summary: 'Minor issue',
  database_specific: { severity: 'MODERATE' },
};

test('a malicious package is denied outright', async () => {
  const outcome = await evaluateCommand('npm i evil-pkg@1.0.0', emptyDir(), {}, {
    fetchImpl: stubFetch({ 'evil-pkg': [MALICIOUS_VULN] }),
  });

  assert.equal(outcome.decision, 'deny');
  assert.match(outcome.reason, /MALICIOUS\s+evil-pkg@1\.0\.0/);
  assert.match(outcome.reason, /MAL-2024-1000/);
  assert.match(outcome.reason, /affected versions: 1\.0\.0, 1\.0\.1/);
});

test('malware is denied even though it carries no severity at all', async () => {
  // OSV malicious entries have severity: null. Scored on severity alone they
  // would band as "unknown" and pass the default threshold — so the malicious
  // check must be independent of banding.
  const bare = { id: 'MAL-2024-9999', summary: 'Malicious code in evil-pkg (npm)' };
  const outcome = await evaluateCommand('npm i evil-pkg', emptyDir(), {}, {
    fetchImpl: stubFetch({ 'evil-pkg': [bare] }),
  });

  assert.equal(outcome.decision, 'deny');
});

test('a vulnerability at the threshold asks rather than denies', async () => {
  // A known CVE is often a considered trade-off; that call belongs to a person.
  const outcome = await evaluateCommand('npm i vuln-pkg@1.0.0', emptyDir(), {}, {
    fetchImpl: stubFetch({ 'vuln-pkg': [CRITICAL_VULN] }),
  });

  assert.equal(outcome.decision, 'ask');
  assert.match(outcome.reason, /CRITICAL/);
  assert.match(outcome.reason, /fixed in 2\.0\.0/, 'reuses range-aware fix resolution');
});

test('a vulnerability below the threshold is allowed silently', async () => {
  const outcome = await evaluateCommand('npm i mild@1.0.0', emptyDir(), {}, {
    fetchImpl: stubFetch({ mild: [MODERATE_VULN] }),
  });

  assert.equal(outcome.decision, 'allow');
  assert.equal(outcome.reason, '');
});

test('the threshold is configurable, and lowering it flags the same package', async () => {
  const outcome = await evaluateCommand('npm i mild@1.0.0', emptyDir(), { failOn: 'moderate' }, {
    fetchImpl: stubFetch({ mild: [MODERATE_VULN] }),
  });

  assert.equal(outcome.decision, 'ask');
});

test('the hook honours osv-guard.json from the working directory', async () => {
  const dir = emptyDir();
  writeFileSync(path.join(dir, 'osv-guard.json'), JSON.stringify({ failOn: 'moderate' }));

  const outcome = await evaluateCommand('npm i mild@1.0.0', dir, {}, {
    fetchImpl: stubFetch({ mild: [MODERATE_VULN] }),
  });

  assert.equal(outcome.decision, 'ask', 'config file threshold should apply');
});

test('an ignored advisory does not block the install', async () => {
  const dir = emptyDir();
  writeFileSync(
    path.join(dir, 'osv-guard.json'),
    JSON.stringify({ ignore: ['GHSA-crit-0000-0000'] }),
  );

  const outcome = await evaluateCommand('npm i vuln-pkg@1.0.0', dir, {}, {
    fetchImpl: stubFetch({ 'vuln-pkg': [CRITICAL_VULN] }),
  });

  assert.equal(outcome.decision, 'allow');
});

test('an ignore entry can never suppress malware', async () => {
  const dir = emptyDir();
  writeFileSync(path.join(dir, 'osv-guard.json'), JSON.stringify({ ignore: ['MAL-2024-1000'] }));

  const outcome = await evaluateCommand('npm i evil-pkg@1.0.0', dir, {}, {
    fetchImpl: stubFetch({ 'evil-pkg': [MALICIOUS_VULN] }),
  });

  assert.equal(outcome.decision, 'deny', 'malicious is not a severity to be waived');
});

test('one malicious package in a multi-package install denies the whole command', async () => {
  const outcome = await evaluateCommand('npm i safe@1.0.0 evil-pkg@1.0.0', emptyDir(), {}, {
    fetchImpl: stubFetch({ safe: [], 'evil-pkg': [MALICIOUS_VULN] }),
  });

  assert.equal(outcome.decision, 'deny');
});

test('a non-install command is allowed without any lookup', async () => {
  let called = false;
  const outcome = await evaluateCommand('ls -la', emptyDir(), {}, {
    fetchImpl: async () => {
      called = true;
      return { ok: true, json: async () => ({ vulns: [] }) };
    },
  });

  assert.equal(outcome.decision, 'allow');
  assert.equal(called, false, 'must not hit the network for unrelated commands');
});

test('a failed lookup allows rather than blocks, and says so when reporting', async () => {
  const outcome = await evaluateCommand('npm i whatever@1.0.0', emptyDir(), {}, {
    fetchImpl: async () => {
      throw new Error('network down');
    },
  });

  // A guard that blocks every install when OSV is unreachable would be worse
  // than no guard: people would turn it off.
  assert.equal(outcome.decision, 'allow');
});

test('an unpinned package is noted, since the finding covers all versions', async () => {
  const outcome = await evaluateCommand('npm i vuln-pkg', emptyDir(), {}, {
    fetchImpl: stubFetch({ 'vuln-pkg': [CRITICAL_VULN] }),
  });

  assert.equal(outcome.decision, 'ask');
  assert.match(outcome.reason, /no pinned version/);
});

// --- hook I/O ---

test('parseHookInput tolerates junk without throwing', () => {
  assert.equal(parseHookInput('not json'), null);
  assert.equal(parseHookInput('"a string"'), null);
  assert.deepEqual(parseHookInput('{"tool_name":"Bash"}'), { tool_name: 'Bash' });
});

test('toHookOutput emits the PreToolUse shape Claude Code expects', () => {
  const json = JSON.parse(
    toHookOutput({ decision: 'deny', reason: 'because', specs: [], malicious: [], findings: [] }),
  );

  assert.deepEqual(json, {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: 'because',
    },
  });
});

/**
 * Package-manager detection, script-vs-command targets, and the recursion
 * guard — the three things that made `"build": "osv-guard hardhat build"` in a
 * pnpm project fail.
 */

import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { buildRunArgs, detectPackageManager } from '../dist/pm.js';
import { DEPTH_ENV, assertNotLooping, currentDepth, planRun, RecursionError } from '../dist/run.js';
import { TargetError, invokesOsvGuard, readScripts, resolveTarget } from '../dist/target.js';

function project({ scripts = {}, lockfile = null, packageManager = null, bins = [] } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'osv-guard-run-'));
  const pkg = { name: 'p', version: '1.0.0', scripts };
  if (packageManager) pkg.packageManager = packageManager;
  writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg));
  if (lockfile) writeFileSync(path.join(dir, lockfile), '');

  if (bins.length > 0) {
    const bin = path.join(dir, 'node_modules', '.bin');
    mkdirSync(bin, { recursive: true });
    for (const name of bins) {
      const file = path.join(bin, name);
      writeFileSync(file, '#!/bin/sh\necho hi\n');
      chmodSync(file, 0o755);
    }
  }
  return dir;
}

// --- package manager detection ---

test('detectPackageManager honours an explicit flag above everything', () => {
  const dir = project({ lockfile: 'pnpm-lock.yaml', packageManager: 'yarn@4.0.0' });
  assert.deepEqual(detectPackageManager(dir, 'npm', {}), { pm: 'npm', via: 'flag' });
});

test('detectPackageManager rejects an unknown flag value', () => {
  assert.throws(() => detectPackageManager(project(), 'cargo', {}), /unknown package manager/);
});

test('detectPackageManager reads the corepack packageManager field', () => {
  const dir = project({ packageManager: 'pnpm@11.25.0' });
  assert.deepEqual(detectPackageManager(dir, undefined, {}), { pm: 'pnpm', via: 'packageManager' });
});

test('detectPackageManager falls back to the lockfile', () => {
  for (const [lockfile, pm] of [
    ['pnpm-lock.yaml', 'pnpm'],
    ['yarn.lock', 'yarn'],
    ['bun.lockb', 'bun'],
    ['package-lock.json', 'npm'],
  ]) {
    const dir = project({ lockfile });
    assert.deepEqual(detectPackageManager(dir, undefined, {}), { pm, via: 'lockfile' }, lockfile);
  }
});

test('the lockfile beats the invoking user agent', () => {
  // `npx osv-guard dev` inside a pnpm repo reports an npm user agent, but the
  // script still has to run under pnpm.
  const dir = project({ lockfile: 'pnpm-lock.yaml' });
  const env = { npm_config_user_agent: 'npm/10.9.3 node/v22.19.0 linux x64' };
  assert.deepEqual(detectPackageManager(dir, undefined, env), { pm: 'pnpm', via: 'lockfile' });
});

test('the user agent is used when the project declares nothing', () => {
  const dir = project();
  const env = { npm_config_user_agent: 'pnpm/11.25.0 npm/? node/v22.19.0 linux x64' };
  assert.deepEqual(detectPackageManager(dir, undefined, env), { pm: 'pnpm', via: 'user-agent' });
});

test('a workspace member finds the lockfile at the workspace root', () => {
  const root = project({ lockfile: 'pnpm-lock.yaml' });
  const member = path.join(root, 'packages', 'app');
  mkdirSync(member, { recursive: true });
  writeFileSync(path.join(member, 'package.json'), JSON.stringify({ name: 'app' }));

  assert.equal(detectPackageManager(member, undefined, {}).pm, 'pnpm');
});

test('detectPackageManager defaults to npm with nothing to go on', () => {
  assert.deepEqual(detectPackageManager(project(), undefined, {}), { pm: 'npm', via: 'default' });
});

// --- argument forwarding ---

test('npm needs the -- separator or it swallows script flags', () => {
  assert.deepEqual(buildRunArgs('npm', 'dev', ['--port', '3000']), [
    'run',
    'dev',
    '--',
    '--port',
    '3000',
  ]);
});

test('pnpm must NOT get -- , which it passes through as a literal argument', () => {
  // Verified against pnpm 11.25: `pnpm run show -- --port 3000` delivers
  // ["--", "--port", "3000"] to the script.
  assert.deepEqual(buildRunArgs('pnpm', 'dev', ['--port', '3000']), [
    'run',
    'dev',
    '--port',
    '3000',
  ]);
});

test('yarn and bun take args directly', () => {
  assert.deepEqual(buildRunArgs('yarn', 'dev', ['--port']), ['run', 'dev', '--port']);
  assert.deepEqual(buildRunArgs('bun', 'dev', ['--port']), ['run', 'dev', '--port']);
});

test('no args means no separator for any package manager', () => {
  for (const pm of ['npm', 'pnpm', 'yarn', 'bun']) {
    assert.deepEqual(buildRunArgs(pm, 'dev', []), ['run', 'dev'], pm);
  }
});

// --- target resolution ---

test('readScripts returns the package scripts, ignoring non-strings', () => {
  const dir = project({ scripts: { dev: 'vite', build: 'tsc' } });
  assert.deepEqual(readScripts(dir), { dev: 'vite', build: 'tsc' });
  assert.deepEqual(readScripts(mkdtempSync(path.join(tmpdir(), 'empty-'))), {});
});

test('a package.json script resolves as a script', () => {
  const dir = project({ scripts: { dev: 'vite' } });
  const target = resolveTarget(dir, 'dev', { env: {} });

  assert.equal(target.kind, 'script');
  assert.equal(target.name, 'dev');
  assert.equal(target.body, 'vite');
});

test('a binary in node_modules/.bin resolves as a command', () => {
  // This is what makes `osv-guard hardhat build` work.
  const dir = project({ bins: ['hardhat'] });
  const target = resolveTarget(dir, 'hardhat', { env: {} });

  assert.equal(target.kind, 'command');
  assert.equal(target.resolved, path.join(dir, 'node_modules', '.bin', 'hardhat'));
});

test('a script wins over a same-named binary', () => {
  const dir = project({ scripts: { hardhat: 'echo from-script' }, bins: ['hardhat'] });
  assert.equal(resolveTarget(dir, 'hardhat', { env: {} }).kind, 'script');
});

test('forceCommand skips the script and takes the binary', () => {
  const dir = project({ scripts: { hardhat: 'echo from-script' }, bins: ['hardhat'] });
  const target = resolveTarget(dir, 'hardhat', { forceCommand: true, env: {} });

  assert.equal(target.kind, 'command');
});

test('an unknown target is a usage error that lists the real scripts', () => {
  const dir = project({ scripts: { dev: 'vite', build: 'tsc' } });

  try {
    resolveTarget(dir, 'biuld', { env: {} });
    assert.fail('should have thrown');
  } catch (err) {
    assert.ok(err instanceof TargetError);
    assert.match(err.message, /no script or command named "biuld"/);
    assert.match(err.hint, /build, dev/);
  }
});

test('a command is found on PATH when it is not in node_modules', () => {
  const dir = project();
  const binHome = mkdtempSync(path.join(tmpdir(), 'osv-guard-path-'));
  const tool = path.join(binHome, 'mytool');
  writeFileSync(tool, '#!/bin/sh\n');
  chmodSync(tool, 0o755);

  const target = resolveTarget(dir, 'mytool', { env: { PATH: binHome } });
  assert.equal(target.kind, 'command');
  assert.equal(target.resolved, tool);
});

// --- recursion guard ---

test('invokesOsvGuard spots a self-invoking script body', () => {
  assert.equal(invokesOsvGuard('osv-guard build'), true);
  assert.equal(invokesOsvGuard('npm run lint && osv-guard build'), true);
  assert.equal(invokesOsvGuard('cross-env NODE_ENV=x osv-guard dev'), true);

  assert.equal(invokesOsvGuard('hardhat build'), false);
  assert.equal(invokesOsvGuard('echo osv-guarded'), false, 'must not match a longer word');
  assert.equal(invokesOsvGuard('vite build'), false);
});

test('a script that invokes osv-guard is refused before anything is spawned', () => {
  const dir = project({ scripts: { build: 'osv-guard build' } });

  try {
    resolveTarget(dir, 'build', { env: {} });
    assert.fail('should have thrown');
  } catch (err) {
    assert.ok(err instanceof TargetError);
    assert.match(err.message, /would run itself forever/);
    assert.match(err.hint, /build:run/, 'the hint should show the fix');
  }
});

test('depth tracking catches an indirect loop', () => {
  assert.equal(currentDepth({}), 0);
  assert.equal(currentDepth({ [DEPTH_ENV]: '1' }), 1);

  assert.doesNotThrow(() => assertNotLooping({}));
  assert.doesNotThrow(() => assertNotLooping({ [DEPTH_ENV]: '1' }));
  assert.throws(() => assertNotLooping({ [DEPTH_ENV]: '2' }), RecursionError);
});

// --- the spawn plan ---

test('planRun wraps a script in its package manager', () => {
  const plan = planRun({
    target: { kind: 'script', name: 'dev', body: 'vite' },
    args: ['--port', '3000'],
    dir: '/p',
    pm: 'pnpm',
  });

  assert.equal(plan.command, 'pnpm');
  assert.deepEqual(plan.argv, ['run', 'dev', '--port', '3000']);
});

test('planRun runs a command directly, with no package manager in the way', () => {
  const plan = planRun({
    target: { kind: 'command', name: 'hardhat', resolved: '/p/node_modules/.bin/hardhat' },
    args: ['build', '--network', 'local'],
    dir: '/p',
    pm: 'pnpm',
  });

  assert.equal(plan.command, '/p/node_modules/.bin/hardhat');
  assert.deepEqual(plan.argv, ['build', '--network', 'local'], 'flags reach the tool untouched');
});

import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  DEFAULTS,
  UsageError,
  loadConfigFile,
  mergeOptions,
  parseArgv,
  parseDuration,
} from '../dist/config.js';

function tempDir() {
  return mkdtempSync(path.join(tmpdir(), 'osv-guard-test-'));
}

test('the first bare word is the script; everything after it is the script\'s', () => {
  const parsed = parseArgv(['--fail-on', 'critical', 'dev', '--port', '3000', '--fail-on', 'low']);

  assert.equal(parsed.command, 'run');
  assert.equal(parsed.script, 'dev');
  // The trailing --fail-on belongs to the script, not to us.
  assert.deepEqual(parsed.scriptArgs, ['--port', '3000', '--fail-on', 'low']);
  assert.equal(parsed.cliOptions.failOn, 'critical');
});

test('-- ends our flags, for a script named like one', () => {
  const parsed = parseArgv(['--quiet', '--', '--weird-script', '-x']);
  assert.equal(parsed.script, '--weird-script');
  assert.deepEqual(parsed.scriptArgs, ['-x']);
  assert.equal(parsed.cliOptions.quiet, true);
});

test('report and scan select the report command', () => {
  assert.equal(parseArgv(['report']).command, 'report');
  assert.equal(parseArgv(['scan']).command, 'report');
  assert.equal(parseArgv(['report', '--json']).cliOptions.format, 'json');
});

test('an explicit run verb is tolerated', () => {
  const parsed = parseArgv(['run', 'build', '--minify']);
  assert.equal(parsed.script, 'build');
  assert.deepEqual(parsed.scriptArgs, ['--minify']);
});

test('no arguments asks for help', () => {
  assert.equal(parseArgv([]).command, 'help');
  assert.equal(parseArgv(['--help']).command, 'help');
  assert.equal(parseArgv(['-v']).command, 'version');
});

test('flags accept both --flag=value and --flag value', () => {
  assert.equal(parseArgv(['--fail-on=critical', 'x']).cliOptions.failOn, 'critical');
  assert.equal(parseArgv(['--fail-on', 'critical', 'x']).cliOptions.failOn, 'critical');
});

test('--ignore accumulates and splits on commas', () => {
  const parsed = parseArgv(['--ignore', 'A,B', '--ignore=C', 'dev']);
  assert.deepEqual(parsed.cliOptions.ignore, ['A', 'B', 'C']);
});

test('--max-* flags collect into one budget object', () => {
  const parsed = parseArgv(['--max-critical', '0', '--max-high=3', 'dev']);
  assert.deepEqual(parsed.cliOptions.max, { critical: 0, high: 3 });
});

test('medium is accepted as a spelling of moderate', () => {
  assert.equal(parseArgv(['--fail-on', 'medium', 'x']).cliOptions.failOn, 'moderate');
  assert.deepEqual(parseArgv(['--max-medium', '1', 'x']).cliOptions.max, { moderate: 1 });
});

test('--cache-ttl implies caching', () => {
  const parsed = parseArgv(['--cache-ttl', '30m', 'dev']);
  assert.equal(parsed.cliOptions.cache, true);
  assert.equal(parsed.cliOptions.cacheTtlMs, 30 * 60 * 1000);
});

test('--no-cache after --cache-ttl still wins', () => {
  assert.equal(parseArgv(['--cache-ttl', '30m', '--no-cache', 'dev']).cliOptions.cache, false);
});

test('bad input is a usage error, not a silent default', () => {
  assert.throws(() => parseArgv(['--frobnicate']), UsageError);
  assert.throws(() => parseArgv(['--fail-on', 'extreme']), UsageError);
  assert.throws(() => parseArgv(['--format', 'yaml']), UsageError);
  assert.throws(() => parseArgv(['--max-high', '-1']), UsageError);
  assert.throws(() => parseArgv(['--max-high', 'lots']), UsageError);
  assert.throws(() => parseArgv(['--fail-on']), UsageError);
});

test('parseDuration understands suffixes and defaults to seconds', () => {
  assert.equal(parseDuration('500ms'), 500);
  assert.equal(parseDuration('45'), 45_000);
  assert.equal(parseDuration('45s'), 45_000);
  assert.equal(parseDuration('15m'), 900_000);
  assert.equal(parseDuration('2h'), 7_200_000);
  assert.equal(parseDuration('1d'), 86_400_000);
  assert.throws(() => parseDuration('soon'), UsageError);
});

test('loadConfigFile reads osv-guard.json', () => {
  const dir = tempDir();
  writeFileSync(
    path.join(dir, 'osv-guard.json'),
    JSON.stringify({ failOn: 'critical', ignore: ['GHSA-x'], max: { high: 2 } }),
  );

  const { config, path: found } = loadConfigFile(dir);
  assert.equal(found, path.join(dir, 'osv-guard.json'));
  assert.equal(config.failOn, 'critical');
  assert.deepEqual(config.ignore, ['GHSA-x']);
  assert.deepEqual(config.max, { high: 2 });
});

test('loadConfigFile reads an osv-guard key in package.json', () => {
  const dir = tempDir();
  writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'x', 'osv-guard': { failOn: 'low', cache: true } }),
  );

  const { config } = loadConfigFile(dir);
  assert.equal(config.failOn, 'low');
  assert.equal(config.cache, true);
});

test('loadConfigFile returns empty when there is no config', () => {
  const { config, path: found } = loadConfigFile(tempDir());
  assert.deepEqual(config, {});
  assert.equal(found, null);
});

test('a malformed config file is a usage error', () => {
  const dir = tempDir();
  writeFileSync(path.join(dir, 'osv-guard.json'), '{ not json');
  assert.throws(() => loadConfigFile(dir), UsageError);

  const dir2 = tempDir();
  writeFileSync(path.join(dir2, 'osv-guard.json'), JSON.stringify({ failOn: 'extreme' }));
  assert.throws(() => loadConfigFile(dir2), UsageError);

  const dir3 = tempDir();
  writeFileSync(path.join(dir3, 'osv-guard.json'), JSON.stringify({ ignore: 'GHSA-x' }));
  assert.throws(() => loadConfigFile(dir3), UsageError);
});

test('CLI flags beat the config file, which beats the defaults', () => {
  const merged = mergeOptions({ failOn: 'low', quiet: true }, { failOn: 'critical' });

  assert.equal(merged.failOn, 'critical', 'flag wins');
  assert.equal(merged.quiet, true, 'config applies where no flag was given');
  assert.equal(merged.format, DEFAULTS.format, 'default applies where neither was given');
});

test('ignore lists and budgets merge rather than replace', () => {
  const merged = mergeOptions(
    { ignore: ['A'], max: { high: 1, low: 5 } },
    { ignore: ['B'], max: { high: 9 } },
  );

  assert.deepEqual(merged.ignore, ['A', 'B']);
  assert.deepEqual(merged.max, { high: 9, low: 5 });
});

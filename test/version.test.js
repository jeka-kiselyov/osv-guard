/**
 * The version lives in four places. They have already drifted once — a bump
 * done by find-and-replace silently matched nothing when one file was out of
 * step. This test is the thing that would have caught it.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (...p) => JSON.parse(readFileSync(path.join(root, ...p), 'utf8'));

test('every manifest carries the same version as package.json', () => {
  const version = read('package.json').version;
  assert.match(version, /^\d+\.\d+\.\d+/, 'package.json has a sane version');

  assert.equal(read('.claude-plugin', 'plugin.json').version, version, 'plugin.json');

  const market = read('.claude-plugin', 'marketplace.json');
  assert.equal(market.metadata.version, version, 'marketplace.json metadata');
  for (const entry of market.plugins) {
    assert.equal(entry.version, version, `marketplace.json plugins[${entry.name}]`);
  }
});

test('the marketplace advertises the plugin this repo actually builds', () => {
  const plugin = read('.claude-plugin', 'plugin.json');
  const market = read('.claude-plugin', 'marketplace.json');

  const names = market.plugins.map((p) => p.name);
  assert.ok(names.includes(plugin.name), `marketplace lists "${plugin.name}" (has: ${names.join(', ')})`);
});

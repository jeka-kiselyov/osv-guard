#!/usr/bin/env node
/**
 * Propagate the version in package.json to the plugin manifests.
 *
 * The version lives in six places: package.json, twice in package-lock.json
 * (the root entry and packages[""]), .claude-plugin/plugin.json, and twice in
 * .claude-plugin/marketplace.json (the marketplace's own metadata and its
 * entry for this plugin). Bumping them by hand has already drifted twice — a
 * find-and-replace for the previous version silently matches nothing when one
 * file is already out of step, and nothing complains.
 *
 * Usage:
 *   node scripts/sync-version.mjs            # copy package.json's version out
 *   node scripts/sync-version.mjs 0.5.0      # set everywhere, package.json first
 */

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

const PKG = path.join(root, 'package.json');
const LOCK = path.join(root, 'package-lock.json');
const PLUGIN = path.join(root, '.claude-plugin', 'plugin.json');
const MARKET = path.join(root, '.claude-plugin', 'marketplace.json');

const read = (file) => JSON.parse(readFileSync(file, 'utf8'));
const write = (file, data) => writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);

const requested = process.argv[2];
if (requested && !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(requested)) {
  console.error(`not a version: ${requested}`);
  process.exit(1);
}

const pkg = read(PKG);
if (requested) {
  pkg.version = requested;
  write(PKG, pkg);
}
const version = pkg.version;

const plugin = read(PLUGIN);
plugin.version = version;
write(PLUGIN, plugin);

// npm only rewrites these on an install, so a bump alone leaves them stale.
// Nothing breaks (npm ci ignores the root version, and publishes read
// package.json), but a lockfile claiming the wrong version is a trap.
const lock = read(LOCK);
lock.version = version;
if (lock.packages?.['']) lock.packages[''].version = version;
write(LOCK, lock);

const market = read(MARKET);
market.metadata.version = version;
for (const entry of market.plugins) entry.version = version;
write(MARKET, market);

console.log(`version ${version} written to package.json, package-lock.json, plugin.json, marketplace.json`);

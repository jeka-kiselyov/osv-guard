# osv-guard

Guard `npm run` scripts behind an [osv-scanner](https://github.com/google/osv-scanner) vulnerability check.

You normally run `npm run dev`. With osv-guard you run `npm run osv-guard dev`: it scans the package the script lives in, and starts the dev server **only** if nothing at or above your threshold turns up. Otherwise it prints a readable report and stops.

```
osv-guard · scanned . (package-lock.json) 1.2s

  CRITICAL 1   MODERATE 1

  ✖ CRITICAL  9.8  minimist@0.0.8  GHSA-xvch-5gv4-984h
                 Prototype Pollution in minimist
                 → fixed in 0.2.4  https://github.com/advisories/GHSA-xvch-5gv4-984h
  · MODERATE  5.6  minimist@0.0.8  GHSA-vh95-rmgr-6w4m
                 Prototype Pollution in minimist
                 → fixed in 0.2.1  https://github.com/advisories/GHSA-vh95-rmgr-6w4m

  ✖ blocked: 1 critical at or above the `high` threshold

  `npm run dev` was not started.
```

## What is osv-scanner?

If you haven't met it before: [osv-scanner](https://github.com/google/osv-scanner) is a free, open-source command-line vulnerability scanner built and maintained by **Google**. It's free and needs no account or API key. By default it queries the OSV database over the network, sending dependency names and versions rather than your code; `--offline` uses a downloaded local copy instead.

## Requirements

Node 18+, and the `osv-scanner` binary (v2) on your `PATH`:

```bash
brew install osv-scanner
```

Or `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`, or grab a
[release binary](https://github.com/google/osv-scanner/releases). Point at a non-`PATH` install with `--scanner-bin`.

## Install

```bash
npm install --save-dev osv-guard
```

Then add the passthrough script:

```json
{
  "scripts": {
    "dev": "vite",
    "osv-guard": "osv-guard"
  }
}
```

```bash
npm run osv-guard dev
```

On npm 6, extra args need the separator: `npm run osv-guard -- dev`. `npx osv-guard dev` works on every version.

## Usage

```bash
osv-guard <script> [script args...]   # scan, then `npm run <script>`
osv-guard report                      # scan and print, run nothing
```

Options go **before** the script name; everything after it is forwarded to the script.

```bash
osv-guard --fail-on critical dev --port 3000
```

osv-guard inserts npm's `--` separator for you, so `--port 3000` reaches your script rather than being eaten by npm.

## Thresholds

| Flag | Default | Meaning |
| --- | --- | --- |
| `--fail-on <band>` | `high` | Block at this band and above (`low`, `moderate`, `high`, `critical`) |
| `--fail-on-unknown` | off | Also block findings with no usable severity |
| `--max-critical <n>` | — | Allow at most n critical findings |
| `--max-high <n>` | — | Allow at most n high findings |
| `--max-moderate <n>` | — | Allow at most n moderate findings |
| `--max-low <n>` | — | Allow at most n low findings |

A `--max-<band>` budget replaces the threshold **for that band only**, so `--fail-on high --max-high 2` tolerates two highs while still blocking on any critical.

## Suppression

| Flag | Meaning |
| --- | --- |
| `--ignore <id,...>` | Skip advisories by GHSA, CVE or OSV id (repeatable; matches aliases) |
| `--ignore-unfixed` | Skip findings with no published fix |

Ignore entries that match nothing are reported, so stale suppressions don't quietly rot.

For long-lived, per-advisory suppressions prefer osv-scanner's own `osv-scanner.toml`, which osv-guard picks up automatically.

## Scanning

| Flag | Meaning |
| --- | --- |
| `--dir`, `-C <path>` | Directory to scan (default: the package npm runs from) |
| `--scanner-bin <path>` | osv-scanner binary (default: `osv-scanner`) |
| `--offline` | Use osv-scanner's local database, no network |
| `--all-vulns` | Include findings osv-scanner considers unimportant or uncalled |
| `--allow-no-lockfile` | Don't fail when no lockfile is present |
| `--cache` | Reuse a recent scan for the same lockfile (**off by default**) |
| `--cache-ttl <duration>` | Cache lifetime — `30s`, `15m`, `1h` (default `1h`; implies `--cache`) |

### About the cache

Off by default: a guard that can return a stale answer isn't much of a guard. When you do enable it, the key is the **hash of your lockfile contents**, so any dependency change busts it immediately — the TTL only bounds how long an *unchanged* tree is trusted.

Policy flags are applied *after* the cache, so tightening `--fail-on` or adding an `--ignore` takes effect without a rescan.

Cached results live in `node_modules/.cache/osv-guard/`.

### Monorepos

Scanning is recursive, so a monorepo root is a valid target even when only the sub-packages carry lockfiles:

```
osv-guard · scanned . (3 lockfiles) 1.1s

  ✖ CRITICAL  9.8  minimist@0.0.8  in packages/app  GHSA-xvch-5gv4-984h
  ✖ CRITICAL  9.8  minimist@0.0.8  in tools/cli     GHSA-xvch-5gv4-984h
```

An advisory affecting two packages is reported once per package — each needs its own fix — and every finding is labelled with the package it came from. Thresholds and budgets apply across the whole tree, and one `--ignore` entry covers every package.

Run osv-guard *inside* a package instead and it scans only that package, since the walk-up stops at the nearest `package.json`.

`--cache` keys on the contents of every lockfile found, sub-packages included, so a dependency change anywhere in the monorepo invalidates it.

### About lockfiles

If there's no lockfile anywhere in the tree, osv-guard stops rather than scanning. osv-scanner would find nothing to resolve, and an empty result is indistinguishable from a clean one — a false green is worse than an error. Run `npm install`, or pass `--allow-no-lockfile` to accept an unchecked run.

## Output

| Flag | Meaning |
| --- | --- |
| `--format`, `-f <fmt>` | `pretty` (default), `json`, `summary` |
| `--json` | Shorthand for `--format json` |
| `--quiet`, `-q` | Only print when the run is blocked |
| `--verbose` | Show how the scan target and config were resolved |
| `--color` / `--no-color` | Force or disable ANSI color |

Reports go to **stderr** and `--format=json` goes to stdout, so `osv-guard report --json | jq` works while a guarded script keeps its own stdout clean.

## Config file

Settings can live in `osv-guard.json`, `.osv-guardrc.json`, or an `osv-guard` key in `package.json`. Command-line flags win.

```json
{
  "failOn": "high",
  "max": { "critical": 0 },
  "ignore": ["GHSA-xxxx-xxxx-xxxx"],
  "ignoreUnfixed": true
}
```

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Passed (and the script exited 0) |
| `1` | Blocked by policy — the script was not run |
| `2` | Usage or configuration error |
| `3` | osv-scanner missing or failed |
| * | Otherwise, the script's own exit code |

## How severity is decided

Findings are grouped the way osv-scanner groups them, so a flaw with both a GHSA and a CVE id counts once, not twice.

Each group's band comes from the first available of:

1. the group's `max_severity` (a CVSS base score osv-scanner computes),
2. GitHub's `database_specific.severity` (`CRITICAL`/`HIGH`/`MODERATE`/`LOW`),
3. a CVSS v3.x vector, scored locally.

Anything left is reported as `unknown` rather than assumed benign. Unknowns don't block by default — `--fail-on-unknown` changes that. CVSS v4-only vectors currently land in `unknown`; in practice `max_severity` covers them.

The suggested fix version is taken from the affected range that actually contains your installed version, so `axios@0.21.0` is told about `0.31.1`, not about a fix on the 1.x line.

## CI

```yaml
- run: npm ci
- run: npx osv-guard report --format json > osv.json
```

Exit code `1` fails the job on a policy violation; `3` distinguishes a broken scanner from a real finding.

## License

MIT

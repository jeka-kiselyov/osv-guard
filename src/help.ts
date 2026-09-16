export const HELP = `
osv-guard — guard npm scripts behind an osv-scanner vulnerability check

USAGE
  osv-guard [options] <script> [script args...]   scan, then run \`npm run <script>\`
  osv-guard report [options]                      scan and print a report only
  osv-guard [options] -- <script> [args...]       explicit separator

  Options must come before the script name. Everything after the script name is
  forwarded to it verbatim.

THRESHOLDS
  --fail-on <band>        block at this band and above (default: high)
                          bands: low, moderate, high, critical
  --fail-on-unknown       also block findings with no usable severity
  --max-critical <n>      allow at most n critical findings
  --max-high <n>          allow at most n high findings
  --max-moderate <n>      allow at most n moderate findings
  --max-low <n>           allow at most n low findings

  A --max-<band> budget replaces the threshold for that band only, so
  \`--fail-on high --max-high 2\` still blocks on any critical.

SUPPRESSION
  --ignore <id,...>       skip advisories by GHSA/CVE/OSV id (repeatable)
  --ignore-unfixed        skip findings with no published fix

SCANNING
  --dir, -C <path>        directory to scan (default: the package npm runs from;
                          scanning is recursive, so a monorepo root works)
  --scanner-bin <path>    osv-scanner binary (default: osv-scanner)
  --offline               use osv-scanner's local database, no network
  --all-vulns             include findings osv-scanner deems unimportant/uncalled
  --allow-no-lockfile     do not fail when no lockfile is present
  --cache                 reuse a recent scan for the same lockfile (off by default)
  --cache-ttl <duration>  cache lifetime, e.g. 30s, 15m, 1h (default: 1h; implies --cache)

OUTPUT
  --format, -f <fmt>      pretty | json | summary (default: pretty)
  --json                  shorthand for --format json
  --quiet, -q             only print the report when the run is blocked
  --verbose               show how the scan target and config were resolved
  --color / --no-color    force or disable ANSI color
  --help, -h              show this help
  --version, -v           show the osv-guard version

CONFIG
  Settings may live in osv-guard.json, .osv-guardrc.json, or an "osv-guard" key in
  package.json. Command-line flags win over the config file.

    { "failOn": "high", "ignore": ["GHSA-xxxx-xxxx-xxxx"], "ignoreUnfixed": true }

  Long-lived per-advisory suppressions are better kept in osv-scanner's own
  osv-scanner.toml, which osv-guard picks up automatically.

EXIT CODES
  0   scan passed (and the script exited 0)
  1   blocked by policy — the script was not run
  2   usage or configuration error
  3   osv-scanner is missing or failed
  *   otherwise, the script's own exit code

SETUP
  Add to package.json:   "scripts": { "osv-guard": "osv-guard" }
  Then:                  npm run osv-guard dev

  On npm 6 you need \`npm run osv-guard -- dev\`; \`npx osv-guard dev\` works everywhere.
`.trim();

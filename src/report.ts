import path from 'node:path';
import { createColors, padEnd, type Colors } from './colors.js';
import type { Options } from './config.js';
import type { PolicyResult } from './policy.js';
import { BAND_RANK, type BandOrUnknown, type Finding, type ScanResult } from './types.js';
import { VERSION } from './version.js';

const BAND_ORDER: Record<BandOrUnknown, number> = { ...BAND_RANK, unknown: 0 };

const BAND_LABEL: Record<BandOrUnknown, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MODERATE',
  low: 'LOW',
  unknown: 'UNKNOWN',
};

function paint(colors: Colors, band: BandOrUnknown, text: string): string {
  switch (band) {
    case 'critical':
      return colors.onRed(text);
    case 'high':
      return colors.red(text);
    case 'moderate':
      return colors.yellow(text);
    case 'low':
      return colors.blue(text);
    default:
      return colors.gray(text);
  }
}

/** Most severe first; within a band, worst score first, then stable by name. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const band = BAND_ORDER[b.band] - BAND_ORDER[a.band];
    if (band !== 0) return band;
    const score = (b.score ?? -1) - (a.score ?? -1);
    if (score !== 0) return score;
    // Keep findings from the same package together, and make the order of a
    // multi-package scan deterministic rather than filesystem-dependent.
    const source = a.source.localeCompare(b.source);
    if (source !== 0) return source;
    const name = a.packageName.localeCompare(b.packageName);
    if (name !== 0) return name;
    return a.id.localeCompare(b.id);
  });
}

export interface ReportContext {
  scan: ScanResult;
  policy: PolicyResult;
  options: Options;
  dir: string;
  lockfiles: string[];
}

export function renderJson(ctx: ReportContext): string {
  return JSON.stringify(
    {
      tool: 'osv-guard',
      version: VERSION,
      blocked: ctx.policy.blocked,
      reasons: ctx.policy.reasons,
      directory: ctx.dir,
      lockfiles: ctx.lockfiles,
      scannerVersion: ctx.scan.scannerVersion,
      durationMs: ctx.scan.durationMs,
      fromCache: ctx.scan.fromCache,
      policy: {
        failOn: ctx.options.failOn,
        failOnUnknown: ctx.options.failOnUnknown,
        max: ctx.options.max,
        ignore: ctx.options.ignore,
        ignoreUnfixed: ctx.options.ignoreUnfixed,
      },
      counts: ctx.policy.counts,
      ignored: ctx.policy.ignoredIds,
      unusedIgnores: ctx.policy.unusedIgnores,
      findings: sortFindings(ctx.policy.findings),
    },
    null,
    2,
  );
}

export function renderSummary(ctx: ReportContext, colors: Colors): string {
  const c = ctx.policy.counts;
  if (c.total === 0) return colors.green('osv-guard: no known vulnerabilities');
  const parts = (['critical', 'high', 'moderate', 'low', 'unknown'] as const)
    .filter((band) => c[band] > 0)
    .map((band) => paint(colors, band, `${c[band]} ${band}`));
  const verdict = ctx.policy.blocked ? colors.red('blocked') : colors.green('passed');
  return `osv-guard: ${verdict} — ${parts.join(', ')}`;
}

export function renderPretty(ctx: ReportContext, colors: Colors): string {
  const { scan, policy, options, dir, lockfiles } = ctx;
  const lines: string[] = [];
  const rel = (p: string): string => path.relative(process.cwd(), p) || '.';

  const scanned = describeLockfiles(lockfiles);
  const timing = scan.fromCache
    ? colors.gray('from cache')
    : colors.gray(`${(scan.durationMs / 1000).toFixed(1)}s`);

  lines.push('');
  lines.push(
    `${colors.bold('osv-guard')} ${colors.gray('·')} scanned ${colors.bold(rel(dir))} ${colors.gray(`(${scanned})`)} ${timing}`,
  );
  lines.push('');

  const c = policy.counts;
  if (c.total === 0) {
    lines.push(`  ${colors.green('✔ no known vulnerabilities')}`);
  } else {
    const tally = (['critical', 'high', 'moderate', 'low', 'unknown'] as const)
      .filter((band) => c[band] > 0)
      .map((band) => `${paint(colors, band, BAND_LABEL[band])} ${colors.bold(String(c[band]))}`)
      .join(colors.gray('   '));
    lines.push(`  ${tally}`);
    lines.push('');

    const offending = new Set(policy.offending.map((f) => `${f.source}|${f.id}|${f.packageName}`));
    const sorted = sortFindings(policy.findings);
    const labelWidth = Math.max(...sorted.map((f) => BAND_LABEL[f.band].length));

    // In a monorepo the same advisory legitimately appears once per package
    // that depends on it. Without the location those rows render identically
    // and the reader cannot tell which package to go and fix.
    const multiPackage = new Set(policy.findings.map((f) => f.source)).size > 1;

    let lastPackage = '';
    for (const f of sorted) {
      const location = multiPackage ? findingLocation(f, dir) : '';
      const pkg = `${f.packageName}@${f.packageVersion}`;
      const groupKey = `${location}|${pkg}`;
      if (groupKey !== lastPackage) {
        if (lastPackage !== '') lines.push('');
        lastPackage = groupKey;
      }

      const marker = offending.has(`${f.source}|${f.id}|${f.packageName}`)
        ? colors.red('✖')
        : colors.gray('·');
      const label = paint(colors, f.band, padEnd(BAND_LABEL[f.band], labelWidth));
      const score =
        f.score !== null ? colors.gray(f.score.toFixed(1).padStart(4)) : colors.gray(' —  ');
      const indent = ' '.repeat(labelWidth + 9);
      const where = location ? `  ${colors.gray(`in ${location}`)}` : '';

      lines.push(`  ${marker} ${label} ${score}  ${colors.bold(pkg)}${where}  ${colors.gray(f.id)}`);
      lines.push(`${indent}${truncate(f.summary, 96)}`);
      lines.push(
        `${indent}${
          f.fixedVersion
            ? colors.green(`→ fixed in ${f.fixedVersion}`)
            : colors.yellow('→ no fix published')
        }  ${colors.gray(f.url)}`,
      );
    }
  }

  lines.push('');

  // These notices must survive a clean scan: a stale ignore entry, or a scan
  // that is only clean *because* everything in it was suppressed, is precisely
  // when the reader needs to be told.
  if (policy.ignoredIds.length > 0) {
    lines.push(
      colors.gray(
        `  ${policy.ignoredIds.length} finding(s) suppressed by --ignore: ${policy.ignoredIds.join(', ')}`,
      ),
    );
  }
  if (policy.unusedIgnores.length > 0) {
    lines.push(
      colors.yellow(
        `  ! ignore entries that matched nothing (stale?): ${policy.unusedIgnores.join(', ')}`,
      ),
    );
  }
  if (c.unknown > 0 && !options.failOnUnknown) {
    lines.push(
      colors.gray(
        `  ${c.unknown} finding(s) have no usable severity and were not gated — use --fail-on-unknown to block them.`,
      ),
    );
  }
  if (policy.ignoredIds.length > 0 || policy.unusedIgnores.length > 0 || c.unknown > 0) {
    lines.push('');
  }

  if (policy.blocked) {
    for (const reason of policy.reasons) {
      lines.push(`  ${colors.red('✖ blocked:')} ${reason}`);
    }
    lines.push('');
  } else if (c.total > 0) {
    // On a clean scan the "no known vulnerabilities" line already said this.
    lines.push(`  ${colors.green('✔ passed')} ${colors.gray(`(threshold: ${options.failOn})`)}`);
    lines.push('');
  }

  return lines.join('\n');
}

function truncate(text: string, width: number): string {
  return text.length <= width ? text : `${text.slice(0, width - 1).trimEnd()}…`;
}

/**
 * A monorepo can have dozens of lockfiles; listing them all would bury the
 * findings. Name them while that stays short, then just count.
 */
export function describeLockfiles(lockfiles: string[]): string {
  if (lockfiles.length === 0) return 'no lockfile';
  if (lockfiles.length <= 2) return lockfiles.join(', ');
  return `${lockfiles.length} lockfiles`;
}

/** The package directory a finding came from, relative to the scan root. */
export function findingLocation(finding: Finding, dir: string): string {
  if (!finding.source) return '';
  const rel = path.relative(dir, path.dirname(finding.source));
  return rel === '' ? '.' : rel.split(path.sep).join('/');
}

export function render(ctx: ReportContext): { text: string; stream: 'stdout' | 'stderr' } {
  const colors = createColors(ctx.options.color);
  switch (ctx.options.format) {
    case 'json':
      return { text: renderJson(ctx), stream: 'stdout' };
    case 'summary':
      return { text: renderSummary(ctx, colors), stream: 'stderr' };
    default:
      return { text: renderPretty(ctx, colors), stream: 'stderr' };
  }
}

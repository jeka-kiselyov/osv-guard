import { loadConfigFile, mergeOptions, type Options } from './config.js';
import { parseInstallCommand, type InstallSpec } from './installcmd.js';
import { normalize } from './normalize.js';
import { isMalicious, queryAll, toScanOutput, type FetchLike, type OsvQueryResult } from './osvapi.js';
import { applyPolicy } from './policy.js';
import { ageMs, formatAge, isTooNew, resolveReleaseTime, type ReleaseInfo } from './releaseage.js';
import { BAND_RANK, type Finding } from './types.js';

/**
 * Claude Code PreToolUse hook: inspect a Bash command before it runs and stop
 * an install that would pull in something malicious.
 *
 * This is the half of the problem the CLI cannot reach. `osv-guard <script>`
 * guards what you *run* against what is already in the lockfile; by the time a
 * bad dependency is in there, its install scripts have already executed. The
 * hook guards what you *install*, before it lands.
 */

export type Decision = 'allow' | 'ask' | 'deny';

export interface HookInput {
  tool_name?: string;
  tool_input?: { command?: string };
  cwd?: string;
}

export interface TooNew {
  spec: InstallSpec;
  info: ReleaseInfo;
}

export interface HookOutcome {
  decision: Decision;
  /** Human-readable explanation, empty when allowing silently. */
  reason: string;
  specs: InstallSpec[];
  malicious: OsvQueryResult[];
  findings: Finding[];
  tooNew: TooNew[];
}

const ALLOW: HookOutcome = {
  decision: 'allow',
  reason: '',
  specs: [],
  malicious: [],
  findings: [],
  tooNew: [],
};

/** Does an `allowNewPackages` entry cover this spec? */
export function isAgeExempt(spec: InstallSpec, allow: string[]): boolean {
  return allow.some((entry) => {
    const trimmed = entry.trim();
    if (!trimmed) return false;
    if (trimmed === spec.name) return true;
    const at = trimmed.startsWith('@') ? trimmed.indexOf('@', 1) : trimmed.indexOf('@');
    if (at === -1) return false;
    return trimmed.slice(0, at) === spec.name && trimmed.slice(at + 1) === spec.version;
  });
}

export function parseHookInput(raw: string): HookInput | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === 'object' ? (parsed as HookInput) : null;
  } catch {
    return null;
  }
}

/**
 * Decide on a command.
 *
 * Malicious packages are denied outright. Vulnerabilities at or above the
 * configured threshold become `ask` rather than `deny`: a known CVE in a
 * transitive dependency is often a considered trade-off, and that judgement
 * belongs to the person, not the hook. Malware never is.
 */
export async function evaluateCommand(
  command: string,
  dir: string,
  options?: Partial<Options>,
  deps: { fetchImpl?: FetchLike; timeoutMs?: number; useCache?: boolean } = {},
): Promise<HookOutcome> {
  const specs = parseInstallCommand(command);
  if (specs.length === 0) return ALLOW;

  const { config } = loadConfigFile(dir);
  const resolved = mergeOptions(config, options ?? {});

  const results = await queryAll(specs, { fetchImpl: deps.fetchImpl, timeoutMs: deps.timeoutMs });
  const malicious = results.filter((result) => result.vulns.some(isMalicious));

  // Malicious advisories are pulled out before scoring: they have no severity
  // for a threshold to act on, and they are never a judgement call.
  const scoreable = results.map((result) => ({
    ...result,
    vulns: result.vulns.filter((vuln) => !isMalicious(vuln)),
  }));

  const { findings } = normalize(toScanOutput(scoreable));
  const policy = applyPolicy(findings, resolved);

  const blocking = policy.findings.filter(
    (finding) => finding.band !== 'unknown' && BAND_RANK[finding.band] >= BAND_RANK[resolved.failOn],
  );

  const tooNew = await findTooNew(specs, resolved, deps);

  if (malicious.length > 0) {
    return {
      decision: 'deny',
      reason: renderReason(specs, malicious, blocking, tooNew, results, resolved),
      specs,
      malicious,
      findings: policy.findings,
      tooNew,
    };
  }

  if (blocking.length > 0 || tooNew.length > 0) {
    return {
      decision: 'ask',
      reason: renderReason(specs, malicious, blocking, tooNew, results, resolved),
      specs,
      malicious: [],
      findings: policy.findings,
      tooNew,
    };
  }

  return { ...ALLOW, specs, findings: policy.findings };
}

/**
 * Which of these versions were published too recently to trust yet.
 *
 * Skipped entirely when the window is zero, so nobody pays a registry
 * round-trip for a check they turned off.
 */
async function findTooNew(
  specs: InstallSpec[],
  options: Options,
  deps: { fetchImpl?: FetchLike; timeoutMs?: number; useCache?: boolean },
): Promise<TooNew[]> {
  if (options.minReleaseAgeMs <= 0) return [];

  const candidates = specs.filter((spec) => !isAgeExempt(spec, options.allowNewPackages));
  if (candidates.length === 0) return [];

  const infos = await Promise.all(
    candidates.map((spec) => resolveReleaseTime(spec, { ...deps })),
  );

  return candidates
    .map((spec, i) => ({ spec, info: infos[i] as ReleaseInfo }))
    .filter(({ info }) => isTooNew(info, options.minReleaseAgeMs));
}

function renderReason(
  specs: InstallSpec[],
  malicious: OsvQueryResult[],
  blocking: Finding[],
  tooNew: TooNew[],
  results: OsvQueryResult[],
  options: Options,
): string {
  const lines: string[] = [];

  for (const result of malicious) {
    const entries = result.vulns.filter(isMalicious);
    const pinned = result.spec.version ? `@${result.spec.version}` : '';
    lines.push(
      `MALICIOUS  ${result.spec.name}${pinned} — ${entries.map((v) => v.id).join(', ')}`,
    );
    // Malicious entries list affected versions explicitly rather than as
    // ranges, so naming them tells the reader which releases to avoid.
    const versions = [...new Set(entries.flatMap((v) => v.affected?.flatMap((a) => a.versions ?? []) ?? []))];
    if (versions.length > 0) {
      lines.push(`           affected versions: ${versions.slice(0, 8).join(', ')}${versions.length > 8 ? ', …' : ''}`);
    }
    for (const vuln of entries.slice(0, 2)) {
      if (vuln.summary) lines.push(`           ${vuln.summary}`);
    }
  }

  for (const finding of blocking) {
    const where = finding.packageVersion === 'unspecified' ? '' : `@${finding.packageVersion}`;
    lines.push(
      `${finding.band.toUpperCase().padEnd(9)} ${finding.packageName}${where} — ${finding.id}` +
        (finding.fixedVersion ? ` (fixed in ${finding.fixedVersion})` : ' (no fix published)'),
    );
    if (finding.summary) lines.push(`           ${finding.summary}`);
  }

  for (const { spec, info } of tooNew) {
    const age = ageMs(info);
    lines.push(
      `TOO NEW    ${spec.name}@${info.version ?? '?'} — published ${age === null ? 'recently' : formatAge(age) + ' ago'}` +
        (info.resolvedLatest ? ' (resolved from `latest`)' : ''),
    );
  }

  const failed = results.filter((result) => result.error);
  for (const result of failed) {
    lines.push(`(could not check ${result.spec.name}: ${result.error})`);
  }

  const unpinned = specs.filter((spec) => !spec.version);
  if (unpinned.length > 0 && blocking.length > 0) {
    lines.push('');
    lines.push(
      `Note: ${unpinned.map((s) => s.name).join(', ')} had no pinned version, so this covers every published version.`,
    );
  }

  lines.push('');
  if (malicious.length > 0) {
    lines.push('osv-guard blocked this install: OSV reports the package itself as malicious.');
  } else if (blocking.length > 0) {
    lines.push(`osv-guard flagged this install at the \`${options.failOn}\` threshold.`);
  }

  if (tooNew.length > 0 && malicious.length === 0) {
    const window = formatAge(options.minReleaseAgeMs);
    lines.push(
      `osv-guard holds releases younger than ${window}: that is the window in which a`,
    );
    lines.push(
      'compromised release is usually caught and pulled. Approve to install anyway, or',
    );
    lines.push(
      `pin an older version. To stop asking: add "allowNewPackages": ["${tooNew[0]?.spec.name}"]`,
    );
    lines.push('to osv-guard.json, or set "minReleaseAge": 0 to turn the check off.');
  }

  return lines.join('\n');
}

/** The JSON shape Claude Code expects back from a PreToolUse hook. */
export function toHookOutput(outcome: HookOutcome): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: outcome.decision,
      permissionDecisionReason: outcome.reason,
    },
  });
}

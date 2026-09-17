import { loadConfigFile, mergeOptions } from './config.js';
import { parseInstallCommand } from './installcmd.js';
import { normalize } from './normalize.js';
import { isMalicious, queryAll, toScanOutput } from './osvapi.js';
import { applyPolicy } from './policy.js';
import { BAND_RANK } from './types.js';
const ALLOW = {
    decision: 'allow',
    reason: '',
    specs: [],
    malicious: [],
    findings: [],
};
export function parseHookInput(raw) {
    try {
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : null;
    }
    catch {
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
export async function evaluateCommand(command, dir, options, deps = {}) {
    const specs = parseInstallCommand(command);
    if (specs.length === 0)
        return ALLOW;
    const { config } = loadConfigFile(dir);
    const resolved = mergeOptions(config, options ?? {});
    const results = await queryAll(specs, deps);
    const malicious = results.filter((result) => result.vulns.some(isMalicious));
    // Malicious advisories are pulled out before scoring: they have no severity
    // for a threshold to act on, and they are never a judgement call.
    const scoreable = results.map((result) => ({
        ...result,
        vulns: result.vulns.filter((vuln) => !isMalicious(vuln)),
    }));
    const { findings } = normalize(toScanOutput(scoreable));
    const policy = applyPolicy(findings, resolved);
    const blocking = policy.findings.filter((finding) => finding.band !== 'unknown' && BAND_RANK[finding.band] >= BAND_RANK[resolved.failOn]);
    if (malicious.length > 0) {
        return {
            decision: 'deny',
            reason: renderReason(specs, malicious, blocking, results, resolved),
            specs,
            malicious,
            findings: policy.findings,
        };
    }
    if (blocking.length > 0) {
        return {
            decision: 'ask',
            reason: renderReason(specs, malicious, blocking, results, resolved),
            specs,
            malicious: [],
            findings: policy.findings,
        };
    }
    return { ...ALLOW, specs, findings: policy.findings };
}
function renderReason(specs, malicious, blocking, results, options) {
    const lines = [];
    for (const result of malicious) {
        const entries = result.vulns.filter(isMalicious);
        const pinned = result.spec.version ? `@${result.spec.version}` : '';
        lines.push(`MALICIOUS  ${result.spec.name}${pinned} — ${entries.map((v) => v.id).join(', ')}`);
        // Malicious entries list affected versions explicitly rather than as
        // ranges, so naming them tells the reader which releases to avoid.
        const versions = [...new Set(entries.flatMap((v) => v.affected?.flatMap((a) => a.versions ?? []) ?? []))];
        if (versions.length > 0) {
            lines.push(`           affected versions: ${versions.slice(0, 8).join(', ')}${versions.length > 8 ? ', …' : ''}`);
        }
        for (const vuln of entries.slice(0, 2)) {
            if (vuln.summary)
                lines.push(`           ${vuln.summary}`);
        }
    }
    for (const finding of blocking) {
        const where = finding.packageVersion === 'unspecified' ? '' : `@${finding.packageVersion}`;
        lines.push(`${finding.band.toUpperCase().padEnd(9)} ${finding.packageName}${where} — ${finding.id}` +
            (finding.fixedVersion ? ` (fixed in ${finding.fixedVersion})` : ' (no fix published)'));
        if (finding.summary)
            lines.push(`           ${finding.summary}`);
    }
    const failed = results.filter((result) => result.error);
    for (const result of failed) {
        lines.push(`(could not check ${result.spec.name}: ${result.error})`);
    }
    const unpinned = specs.filter((spec) => !spec.version);
    if (unpinned.length > 0 && blocking.length > 0) {
        lines.push('');
        lines.push(`Note: ${unpinned.map((s) => s.name).join(', ')} had no pinned version, so this covers every published version.`);
    }
    lines.push('');
    lines.push(malicious.length > 0
        ? 'osv-guard blocked this install: OSV reports the package itself as malicious.'
        : `osv-guard flagged this install at the \`${options.failOn}\` threshold.`);
    return lines.join('\n');
}
/** The JSON shape Claude Code expects back from a PreToolUse hook. */
export function toHookOutput(outcome) {
    return JSON.stringify({
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: outcome.decision,
            permissionDecisionReason: outcome.reason,
        },
    });
}

import type { InstallSpec } from './installcmd.js';
import type { OsvRawOutput, OsvRawVulnerability } from './types.js';

/**
 * Minimal client for the OSV.dev query API.
 *
 * The hook needs to check packages that are not installed yet, so osv-scanner
 * (which reads lockfiles) has nothing to work with. Querying OSV directly also
 * means the hook works without the osv-scanner binary present.
 *
 * Responses use the same OSV schema osv-scanner emits, so they can be shaped
 * into `OsvRawOutput` and fed through the normal `normalize()` pipeline.
 */

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

export interface OsvQueryResult {
  spec: InstallSpec;
  vulns: OsvRawVulnerability[];
  /** Set when the lookup failed; the caller decides whether that blocks. */
  error: string | null;
}

export type FetchLike = typeof globalThis.fetch;

/**
 * Look one package up. Passing a concrete version lets OSV do the affected
 * range matching server-side; without one we get every advisory for the
 * package and report it as "some versions affected".
 */
export async function queryPackage(
  spec: InstallSpec,
  { fetchImpl = globalThis.fetch, timeoutMs = 5000 }: { fetchImpl?: FetchLike; timeoutMs?: number } = {},
): Promise<OsvQueryResult> {
  const body: Record<string, unknown> = {
    package: { name: spec.name, ecosystem: spec.ecosystem },
  };
  if (spec.version) body.version = spec.version;

  try {
    const response = await fetchImpl(OSV_QUERY_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) {
      return { spec, vulns: [], error: `OSV responded ${response.status}` };
    }
    const data = (await response.json()) as { vulns?: OsvRawVulnerability[] };
    return { spec, vulns: data.vulns ?? [], error: null };
  } catch (err) {
    return { spec, vulns: [], error: (err as Error).message || 'request failed' };
  }
}

export async function queryAll(
  specs: InstallSpec[],
  options: { fetchImpl?: FetchLike; timeoutMs?: number } = {},
): Promise<OsvQueryResult[]> {
  return Promise.all(specs.map((spec) => queryPackage(spec, options)));
}

/**
 * Is this advisory a report of a deliberately malicious package?
 *
 * These matter separately from vulnerabilities: OSV's malicious-package
 * entries carry **no severity at all** (`severity: null`, no CVSS vector), so a
 * plain severity threshold would band every one of them `unknown` and let them
 * through. Malware is not a severity — it is its own verdict.
 */
export function isMalicious(vuln: OsvRawVulnerability): boolean {
  if (vuln.id.startsWith('MAL-')) return true;
  if (vuln.database_specific && 'malicious-packages-origins' in vuln.database_specific) return true;
  return (vuln.summary ?? '').trim().toLowerCase().startsWith('malicious code in');
}

/**
 * Shape API responses into the structure osv-scanner produces, so the existing
 * `normalize()` → `applyPolicy()` pipeline can score them: one "source" per
 * lookup, one package entry each, groups left out so normalize synthesizes
 * them per vulnerability.
 */
export function toScanOutput(results: OsvQueryResult[]): OsvRawOutput {
  return {
    results: results
      .filter((result) => result.vulns.length > 0)
      .map((result) => ({
        source: { path: `${result.spec.ecosystem}:${result.spec.name}`, type: 'osv-api' },
        packages: [
          {
            package: {
              name: result.spec.name,
              version: result.spec.version ?? 'unspecified',
              ecosystem: result.spec.ecosystem,
            },
            vulnerabilities: result.vulns,
          },
        ],
      })),
  };
}

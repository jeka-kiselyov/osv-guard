/** Severity bands, ordered least to most severe. `unknown` sits outside the order. */
export const BANDS = ['low', 'moderate', 'high', 'critical'] as const;

export type Band = (typeof BANDS)[number];
export type BandOrUnknown = Band | 'unknown';

/** Rank used for threshold comparisons. `unknown` is deliberately not rankable. */
export const BAND_RANK: Record<Band, number> = {
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

// --- Raw osv-scanner JSON (only the parts we rely on) ---

export interface OsvRawSeverity {
  type?: string;
  score?: string;
}

export interface OsvRawRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvRawAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: { type?: string; events?: OsvRawRangeEvent[] }[];
  /** Explicit version list — how malicious-package advisories enumerate. */
  versions?: string[];
}

export interface OsvRawVulnerability {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: OsvRawSeverity[];
  affected?: OsvRawAffected[];
  database_specific?: { severity?: string; [k: string]: unknown };
  references?: { type?: string; url?: string }[];
  withdrawn?: string;
}

export interface OsvRawGroup {
  ids?: string[];
  aliases?: string[];
  max_severity?: string;
}

export interface OsvRawPackageResult {
  package?: { name?: string; version?: string; ecosystem?: string };
  groups?: OsvRawGroup[];
  vulnerabilities?: OsvRawVulnerability[];
}

export interface OsvRawSourceResult {
  source?: { path?: string; type?: string };
  packages?: OsvRawPackageResult[];
}

export interface OsvRawOutput {
  results?: OsvRawSourceResult[];
}

// --- Our normalized shape ---

/**
 * One reported issue. The unit is an osv-scanner *group*, not a raw
 * vulnerability: groups collapse GHSA/CVE aliases that describe the same flaw,
 * so counting groups avoids double-charging a single issue against a budget.
 */
export interface Finding {
  /** Primary advisory id (a GHSA when one is available). */
  id: string;
  /** Every id and alias in the group, sorted. */
  aliases: string[];
  band: BandOrUnknown;
  /** CVSS base score when one could be determined. */
  score: number | null;
  /** Where the band came from, for `--explain`-style debugging and tests. */
  severitySource: 'max_severity' | 'database_specific' | 'cvss_v3' | 'none';
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  summary: string;
  /** Lowest fixed version covering the installed version, when published. */
  fixedVersion: string | null;
  url: string;
  /** Lockfile (or other source) this came from. */
  source: string;
}

export interface ScanResult {
  findings: Finding[];
  /** Absolute paths of the lockfiles/manifests osv-scanner actually read. */
  sources: string[];
  durationMs: number;
  scannerVersion: string | null;
  /** True when the result was served from the on-disk cache. */
  fromCache: boolean;
}

export interface Counts {
  critical: number;
  high: number;
  moderate: number;
  low: number;
  unknown: number;
  total: number;
}

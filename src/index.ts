export { normalize, resolveFixedVersion } from './normalize.js';
export { applyPolicy, countBands, type PolicyResult } from './policy.js';
export { render, renderJson, renderPretty, renderSummary, sortFindings } from './report.js';
export { runScan, buildArgs, detectScannerVersion, ScannerError } from './scanner.js';
export { findLockfiles, resolveProjectDir } from './resolve.js';
export { runNpmScript } from './run.js';
export { cvss3BaseScore, resolveSeverity, scoreToBand, normalizeBandName } from './severity.js';
export { compareVersions } from './semver.js';
export { cacheKey, readCache, writeCache } from './cache.js';
export {
  DEFAULTS,
  UsageError,
  loadConfigFile,
  mergeOptions,
  parseArgv,
  parseDuration,
  type Options,
  type Format,
} from './config.js';
export { VERSION } from './version.js';
export * from './types.js';

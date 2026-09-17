import { spawn, spawnSync } from 'node:child_process';
import { normalize } from './normalize.js';
export class ScannerError extends Error {
    hint;
    constructor(message, hint) {
        super(message);
        this.hint = hint;
    }
}
/**
 * osv-scanner exits 1 when it *finds* vulnerabilities — that is a successful
 * run, not a failure. Only codes outside this set mean the scanner itself
 * broke.
 */
const OK_EXIT_CODES = new Set([0, 1]);
export function detectScannerVersion(bin) {
    try {
        const res = spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: 10_000 });
        if (res.error || res.status !== 0)
            return null;
        const match = /osv-scanner version:\s*(\S+)/i.exec(res.stdout ?? '');
        return match?.[1] ?? null;
    }
    catch {
        return null;
    }
}
export function buildArgs(options) {
    // `--allow-no-lockfiles` is always on: osv-guard runs its own lockfile check
    // first, with a message that explains why an unchecked run is dangerous.
    // Left to itself osv-scanner exits 128 on any project with an empty
    // dependency tree, which is a legitimately clean project, not an error.
    const args = [
        'scan',
        'source',
        '--format=json',
        '--recursive',
        '--verbosity=error',
        '--allow-no-lockfiles',
    ];
    if (options.offline)
        args.push('--offline');
    if (options.allVulns)
        args.push('--all-vulns');
    args.push(options.dir);
    return args;
}
export async function runScan(options) {
    const started = Date.now();
    const version = detectScannerVersion(options.scannerBin);
    if (version === null) {
        throw new ScannerError(`could not run "${options.scannerBin}"`, [
            'osv-guard needs the osv-scanner binary on your PATH.',
            '',
            '  macOS/Linux (Homebrew):  brew install osv-scanner',
            '  Go:                      go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest',
            '  Binaries:                https://github.com/google/osv-scanner/releases',
            '',
            'Already installed somewhere else? Point at it with --scanner-bin <path>.',
        ].join('\n'));
    }
    const { stdout, stderr, code } = await exec(options.scannerBin, buildArgs(options));
    if (code === null || !OK_EXIT_CODES.has(code)) {
        throw new ScannerError(`osv-scanner exited with code ${code ?? 'null'}`, (stderr.trim() || stdout.trim() || 'No output from the scanner.').slice(0, 4000));
    }
    let raw;
    try {
        raw = JSON.parse(stdout);
    }
    catch {
        throw new ScannerError('could not parse osv-scanner JSON output', (stderr.trim() || stdout.slice(0, 800) || 'Empty output.'));
    }
    const { findings, sources } = normalize(raw);
    return {
        findings,
        sources,
        durationMs: Date.now() - started,
        scannerVersion: version,
        fromCache: false,
    };
}
function exec(bin, args) {
    return new Promise((resolve, reject) => {
        const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
        const out = [];
        const err = [];
        child.stdout.on('data', (chunk) => out.push(chunk));
        child.stderr.on('data', (chunk) => err.push(chunk));
        child.on('error', (error) => {
            reject(new ScannerError(`failed to start "${bin}": ${error.message}`));
        });
        child.on('close', (code) => {
            resolve({
                stdout: Buffer.concat(out).toString('utf8'),
                stderr: Buffer.concat(err).toString('utf8'),
                code,
            });
        });
    });
}

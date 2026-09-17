import type { ScanResult } from './types.js';
export declare class ScannerError extends Error {
    readonly hint?: string | undefined;
    constructor(message: string, hint?: string | undefined);
}
export interface ScanOptions {
    dir: string;
    scannerBin: string;
    offline: boolean;
    allVulns: boolean;
}
export declare function detectScannerVersion(bin: string): string | null;
export declare function buildArgs(options: ScanOptions): string[];
export declare function runScan(options: ScanOptions): Promise<ScanResult>;

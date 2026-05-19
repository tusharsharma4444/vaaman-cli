import type { ScanResult } from './types.js';
export interface RunnerOptions {
    args: string[];
    cwd: string;
    block: boolean;
    verbose: boolean;
    intervalMs: number;
}
export interface RunResult {
    exitCode: number;
    scanResult: ScanResult;
}
export declare function runInstall(options: RunnerOptions): Promise<RunResult>;

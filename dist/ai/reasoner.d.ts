import type { MonitorEvent, ScanResult } from '../types.js';
export declare class Reasoner {
    reason(events: MonitorEvent[], durationMs: number, blocked: boolean): ScanResult;
}

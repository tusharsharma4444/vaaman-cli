import type { ProcessEvent } from '../types.js';
export declare class ProcessMonitor {
    private seenPids;
    private installPid;
    private events;
    constructor(installPid: number);
    scan(): ProcessEvent[];
    getAll(): ProcessEvent[];
}

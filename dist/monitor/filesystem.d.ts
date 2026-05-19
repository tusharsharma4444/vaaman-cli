import type { FilesystemEvent } from '../types.js';
export declare class FilesystemMonitor {
    private seenFiles;
    private events;
    private installPid;
    private cwd;
    constructor(installPid: number, cwd: string);
    scan(): FilesystemEvent[];
    getAll(): FilesystemEvent[];
}

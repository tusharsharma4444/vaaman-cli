import type { ProcessEvent } from '../types.js';
export declare class StraceMonitor {
    private events;
    private straceProcess;
    private onEvent;
    private seenCommands;
    constructor(onEvent: (event: ProcessEvent) => void);
    attachToStream(stream: NodeJS.ReadableStream): void;
    attachToPid(pid: number): void;
    private parseLine;
    stop(): void;
    getAll(): ProcessEvent[];
}

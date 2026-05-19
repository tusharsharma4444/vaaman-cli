export type ThreatLevel = 'clean' | 'suspicious' | 'dangerous' | 'critical';
export interface MonitorEvent {
    type: 'process' | 'network' | 'filesystem';
    timestamp: number;
    pid?: number;
    detail: string;
    raw: Record<string, unknown>;
}
export interface ProcessEvent extends MonitorEvent {
    type: 'process';
    parentPid: number;
    childPid: number;
    command: string;
    args: string[];
}
export interface NetworkEvent extends MonitorEvent {
    type: 'network';
    localAddr: string;
    remoteAddr: string;
    remoteIp: string;
    remotePort: number;
    state: string;
}
export interface FilesystemEvent extends MonitorEvent {
    type: 'filesystem';
    path: string;
    operation: 'write' | 'create' | 'delete';
    suspicious: boolean;
    reason: string;
}
export interface ThreatSignal {
    event: MonitorEvent;
    level: ThreatLevel;
    reason: string;
    chain?: string[];
}
export interface ScanResult {
    duration: number;
    events: MonitorEvent[];
    signals: ThreatSignal[];
    verdict: ThreatLevel;
    summary: string;
    blocked: boolean;
}
export interface MonitorOptions {
    rootPid: number;
    installPid: number;
    verbose: boolean;
    block: boolean;
    intervalMs: number;
}

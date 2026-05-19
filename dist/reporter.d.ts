import type { ScanResult, ThreatLevel, MonitorEvent } from './types.js';
export declare function printLiveEvent(event: MonitorEvent): void;
export declare function printLiveSignal(signal: {
    level: ThreatLevel;
    reason: string;
}): void;
export declare function printHeader(packages: string): void;
export declare function printInstallStart(): void;
export declare function printInstallEnd(): void;
export declare function printMonitoringStart(): void;
export declare function printMonitoringEnd(): void;
export declare function printReport(result: ScanResult): void;
export declare function printBlocked(reason: string): void;
export declare function printError(msg: string): void;
export declare function printWarning(msg: string): void;

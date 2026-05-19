import type { NetworkEvent } from '../types.js';
export declare class NetworkMonitor {
    private seenConnections;
    private events;
    private connectionKey;
    scan(): NetworkEvent[];
    getAll(): NetworkEvent[];
}

// src/monitor/network.ts
// Monitors /proc/net/tcp and /proc/net/tcp6 for outbound connections
// made during npm install. No root required.
import * as fs from 'fs';
// Ports that are completely normal during npm install
const BENIGN_PORTS = new Set([
    443, // HTTPS — npm registry
    80, // HTTP
    22, // git over SSH
    9418, // git protocol
]);
// IPs/ranges that are obviously benign
const BENIGN_IP_PREFIXES = [
    '127.', // localhost
    '::1', // IPv6 localhost
    '0.0.0.0',
];
// Ports that are extremely suspicious during npm install
const SUSPICIOUS_PORTS = new Set([
    4444, // classic metasploit
    1337, // leet hacker classic
    31337,
    8080, // proxy / C2
    9999,
    6666,
    6667, // IRC (C2 channels)
    7777,
    2222, // alt SSH
    5555,
    3333,
]);
function hexToIp(hex) {
    // Linux /proc/net/tcp stores IPs as little-endian hex
    const parts = [];
    for (let i = 6; i >= 0; i -= 2) {
        parts.push(parseInt(hex.slice(i, i + 2), 16));
    }
    return parts.join('.');
}
function hexToPort(hex) {
    return parseInt(hex, 16);
}
function parseTcpFile(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.trim().split('\n').slice(1); // skip header
        return lines.map((line) => {
            const parts = line.trim().split(/\s+/);
            const [localHexAddr, localHexPort] = parts[1].split(':');
            const [remoteHexAddr, remoteHexPort] = parts[2].split(':');
            const stateHex = parts[3];
            // TCP states: 01=ESTABLISHED, 02=SYN_SENT, etc.
            const stateMap = {
                '01': 'ESTABLISHED',
                '02': 'SYN_SENT',
                '03': 'SYN_RECV',
                '04': 'FIN_WAIT1',
                '05': 'FIN_WAIT2',
                '06': 'TIME_WAIT',
                '07': 'CLOSE',
                '08': 'CLOSE_WAIT',
                '09': 'LAST_ACK',
                '0A': 'LISTEN',
                '0B': 'CLOSING',
            };
            return {
                localAddr: hexToIp(localHexAddr),
                localPort: hexToPort(localHexPort),
                remoteAddr: hexToIp(remoteHexAddr),
                remotePort: hexToPort(remoteHexPort),
                state: stateMap[stateHex.toUpperCase()] ?? stateHex,
            };
        }).filter((e) => e.state === 'ESTABLISHED' || e.state === 'SYN_SENT');
    }
    catch {
        return [];
    }
}
function isBenignConnection(entry) {
    if (BENIGN_IP_PREFIXES.some(p => entry.remoteAddr.startsWith(p)))
        return true;
    if (entry.remoteAddr === '0.0.0.0')
        return true;
    return false;
}
function assessConnection(entry) {
    if (isBenignConnection(entry)) {
        return { suspicious: false, reason: '', critical: false };
    }
    if (SUSPICIOUS_PORTS.has(entry.remotePort)) {
        return {
            suspicious: true,
            critical: true,
            reason: `Connection to suspicious port ${entry.remotePort} — classic C2/backdoor port`,
        };
    }
    if (!BENIGN_PORTS.has(entry.remotePort)) {
        return {
            suspicious: true,
            critical: false,
            reason: `Outbound connection to ${entry.remoteAddr}:${entry.remotePort} — unexpected port during install`,
        };
    }
    // Normal HTTPS/HTTP but to a non-npm address — worth noting
    return {
        suspicious: false,
        reason: `Outbound ${entry.remoteAddr}:${entry.remotePort} (normal registry traffic)`,
        critical: false,
    };
}
export class NetworkMonitor {
    seenConnections = new Set();
    events = [];
    connectionKey(entry) {
        return `${entry.localAddr}:${entry.localPort}-${entry.remoteAddr}:${entry.remotePort}`;
    }
    scan() {
        const newEvents = [];
        const entries = [
            ...parseTcpFile('/proc/net/tcp'),
            ...parseTcpFile('/proc/net/tcp6'),
        ];
        for (const entry of entries) {
            const key = this.connectionKey(entry);
            if (this.seenConnections.has(key))
                continue;
            this.seenConnections.add(key);
            if (isBenignConnection(entry))
                continue;
            const { suspicious, reason, critical } = assessConnection(entry);
            if (!suspicious && BENIGN_PORTS.has(entry.remotePort))
                continue;
            const event = {
                type: 'network',
                timestamp: Date.now(),
                localAddr: `${entry.localAddr}:${entry.localPort}`,
                remoteAddr: `${entry.remoteAddr}:${entry.remotePort}`,
                remoteIp: entry.remoteAddr,
                remotePort: entry.remotePort,
                state: entry.state,
                detail: reason || `Connection: ${entry.remoteAddr}:${entry.remotePort}`,
                raw: { ...entry, critical },
            };
            newEvents.push(event);
            this.events.push(event);
        }
        return newEvents;
    }
    getAll() {
        return this.events;
    }
}
//# sourceMappingURL=network.js.map
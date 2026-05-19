// src/monitor/process.ts
// Monitors /proc for new processes spawned during npm install
// Uses Linux /proc filesystem — no root required
import * as fs from 'fs';
import * as path from 'path';
// Suspicious commands that should never appear during npm install
const SUSPICIOUS_COMMANDS = [
    'curl',
    'wget',
    'bash',
    'sh',
    'nc', // netcat
    'ncat',
    'python',
    'python3',
    'ruby',
    'perl',
    'php',
    'socat',
    'nmap',
    'ssh',
    'scp',
    'rsync',
    'base64',
    'openssl',
    'xxd',
];
// Commands that are completely normal during npm install — suppress them
const BENIGN_COMMANDS = [
    'node',
    'npm',
    'npx',
    'git',
    'tsc',
    'esbuild',
    'rollup',
    'webpack',
    'vite',
    'gyp', // node-gyp is normal
    'make',
    'cmake',
    'cc',
    'gcc',
    'g++',
    'clang',
    'install',
    'cp',
    'mkdir',
    'rm',
    'ln',
];
function readProcFile(pid, file) {
    try {
        return fs.readFileSync(`/proc/${pid}/${file}`, 'utf8');
    }
    catch {
        return null;
    }
}
function getProcCmdline(pid) {
    const raw = readProcFile(pid, 'cmdline');
    if (!raw)
        return [];
    // cmdline is null-byte separated
    return raw.split('\0').filter(Boolean);
}
function getProcStat(pid) {
    const raw = readProcFile(pid, 'stat');
    if (!raw)
        return null;
    // Format: pid (comm) state ppid ...
    const match = raw.match(/^\d+ \((.+?)\) \w+ (\d+)/);
    if (!match)
        return null;
    return {
        comm: match[1],
        ppid: parseInt(match[2], 10),
    };
}
function getAllPids() {
    try {
        return fs.readdirSync('/proc')
            .filter((f) => /^\d+$/.test(f))
            .map((f) => parseInt(f, 10));
    }
    catch {
        return [];
    }
}
function isDescendantOf(pid, ancestorPid, visited = new Set()) {
    if (pid === ancestorPid)
        return true;
    if (visited.has(pid))
        return false;
    visited.add(pid);
    const stat = getProcStat(pid);
    if (!stat || stat.ppid === 0 || stat.ppid === pid)
        return false;
    return isDescendantOf(stat.ppid, ancestorPid, visited);
}
function isBenign(cmd) {
    const base = path.basename(cmd).toLowerCase();
    return BENIGN_COMMANDS.some(b => base === b || base.startsWith(b));
}
function isSuspicious(cmd) {
    const base = path.basename(cmd).toLowerCase();
    for (const s of SUSPICIOUS_COMMANDS) {
        if (base === s || base.startsWith(s)) {
            return {
                suspicious: true,
                reason: `Spawned suspicious command: ${base}`,
            };
        }
    }
    return { suspicious: false, reason: '' };
}
export class ProcessMonitor {
    seenPids = new Set();
    installPid;
    events = [];
    constructor(installPid) {
        this.installPid = installPid;
        // Seed with existing pids so we only catch NEW ones
        getAllPids().forEach(pid => this.seenPids.add(pid));
    }
    scan() {
        const newEvents = [];
        const currentPids = getAllPids();
        for (const pid of currentPids) {
            if (this.seenPids.has(pid))
                continue;
            this.seenPids.add(pid);
            // Only care about processes spawned from the npm install tree
            if (!isDescendantOf(pid, this.installPid))
                continue;
            const cmdline = getProcCmdline(pid);
            if (cmdline.length === 0)
                continue;
            const command = cmdline[0];
            const args = cmdline.slice(1);
            // Skip obviously benign
            if (isBenign(command))
                continue;
            const stat = getProcStat(pid);
            const { suspicious, reason } = isSuspicious(command);
            const event = {
                type: 'process',
                timestamp: Date.now(),
                pid,
                parentPid: stat?.ppid ?? 0,
                childPid: pid,
                command,
                args,
                detail: suspicious
                    ? `⚠ ${reason} — full cmd: ${cmdline.join(' ')}`
                    : `Process spawned: ${cmdline.join(' ')}`,
                raw: { pid, command, args, ppid: stat?.ppid },
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
//# sourceMappingURL=process.js.map
// src/monitor/filesystem.ts
// Monitors /proc/<pid>/fd and /proc/<pid>/maps to detect
// file writes happening outside of node_modules during install.
// No root required — reads /proc entries we have permission to see.
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
const HOME = os.homedir();
// Paths that are extremely suspicious to write during npm install
const CRITICAL_PATHS = [
    `${HOME}/.bashrc`,
    `${HOME}/.bash_profile`,
    `${HOME}/.zshrc`,
    `${HOME}/.zprofile`,
    `${HOME}/.profile`,
    `${HOME}/.bash_logout`,
    `${HOME}/.ssh/authorized_keys`,
    `${HOME}/.ssh/config`,
    `${HOME}/.gitconfig`,
    `${HOME}/.npmrc`,
    '/etc/crontab',
    '/etc/hosts',
    '/etc/passwd',
    '/etc/shadow',
    '/etc/sudoers',
    '/tmp', // writing executables to /tmp
    '/var/tmp',
];
// Path prefixes that are completely fine during install
const BENIGN_PATH_PREFIXES = [
    'node_modules',
    '.npm',
    '/tmp/npm-', // npm's own temp dir
    '/tmp/node-',
    os.tmpdir(),
];
// Extensions suspicious in write context during install
const SUSPICIOUS_EXTENSIONS = [
    '.sh',
    '.bash',
    '.zsh',
    '.py',
    '.rb',
    '.pl',
    '.php',
    '.ps1',
    '.bat',
    '.cmd',
    '.exe',
    '.elf',
    '.so', // shared library — could be fine (native modules) but worth flagging
];
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
function getOpenFiles(pid) {
    try {
        const fdDir = `/proc/${pid}/fd`;
        const fds = fs.readdirSync(fdDir);
        const files = [];
        for (const fd of fds) {
            try {
                const resolved = fs.readlinkSync(path.join(fdDir, fd));
                if (resolved && !resolved.startsWith('socket:') && !resolved.startsWith('pipe:') && !resolved.startsWith('anon_inode:')) {
                    files.push(resolved);
                }
            }
            catch {
                // fd may have closed between readdir and readlink — normal
            }
        }
        return files;
    }
    catch {
        return [];
    }
}
function assessPath(filePath, cwd) {
    const normalized = path.resolve(filePath);
    // Check benign prefixes first
    for (const prefix of BENIGN_PATH_PREFIXES) {
        if (normalized.includes(prefix)) {
            return { suspicious: false, critical: false, reason: '' };
        }
    }
    // If it's inside the current working directory, mostly fine
    if (normalized.startsWith(cwd) && !normalized.includes('..')) {
        // But still check for suspicious extensions
        const ext = path.extname(normalized).toLowerCase();
        if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
            return {
                suspicious: true,
                critical: false,
                reason: `Writing executable-type file in project: ${normalized}`,
            };
        }
        return { suspicious: false, critical: false, reason: '' };
    }
    // Check critical system paths
    for (const critical of CRITICAL_PATHS) {
        if (normalized === critical || normalized.startsWith(critical + '/')) {
            return {
                suspicious: true,
                critical: true,
                reason: `CRITICAL: Writing to sensitive path: ${normalized}`,
            };
        }
    }
    // Writing anywhere outside cwd and node_modules is suspicious
    return {
        suspicious: true,
        critical: false,
        reason: `File write outside project directory: ${normalized}`,
    };
}
export class FilesystemMonitor {
    seenFiles = new Set();
    events = [];
    installPid;
    cwd;
    constructor(installPid, cwd) {
        this.installPid = installPid;
        this.cwd = cwd;
        // Seed existing open files so we only catch NEW ones
        const pids = getAllPids();
        for (const pid of pids) {
            const files = getOpenFiles(pid);
            files.forEach(f => this.seenFiles.add(f));
        }
    }
    scan() {
        const newEvents = [];
        const pids = getAllPids();
        for (const pid of pids) {
            const files = getOpenFiles(pid);
            for (const filePath of files) {
                if (this.seenFiles.has(filePath))
                    continue;
                this.seenFiles.add(filePath);
                const { suspicious, critical, reason } = assessPath(filePath, this.cwd);
                if (!suspicious)
                    continue;
                const event = {
                    type: 'filesystem',
                    timestamp: Date.now(),
                    pid,
                    path: filePath,
                    operation: 'write',
                    suspicious,
                    reason,
                    detail: reason,
                    raw: { pid, path: filePath, critical },
                };
                newEvents.push(event);
                this.events.push(event);
            }
        }
        return newEvents;
    }
    getAll() {
        return this.events;
    }
}
//# sourceMappingURL=filesystem.js.map
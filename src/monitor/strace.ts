// src/monitor/strace.ts
// Uses strace to intercept every execve() syscall made by npm install.
// This catches ALL process spawns — even ones that die in milliseconds —
// which /proc polling fundamentally cannot do.

import { spawn, type ChildProcess } from 'child_process'
import * as readline from 'readline'
import type { ProcessEvent } from '../types.js'

const BENIGN = new Set([
    'node', 'npm', 'npx', 'sh',
    'git', 'tsc', 'esbuild', 'rollup', 'webpack',
    'gyp', 'make', 'cmake', 'cc', 'gcc', 'g++', 'clang',
    'cp', 'mkdir', 'rm', 'ln', 'mv', 'cat', 'echo',
    'which', 'env', 'true', 'false', 'test', 'uname',
    'id', 'whoami', 'dirname', 'basename', 'readlink',
    'install', 'sed', 'awk', 'grep', 'sort', 'uniq',
    'head', 'tail', 'cut', 'tr', 'wc', 'find', 'xargs',
])

const CRITICAL = new Set(['nc', 'ncat', 'netcat', 'socat'])
const DANGEROUS = new Set(['curl', 'wget'])
const SUSPICIOUS = new Set([
    'bash', 'zsh', 'ksh', 'fish',
    'python', 'python3', 'ruby', 'perl', 'php',
    'base64', 'openssl', 'xxd',
    'ssh', 'scp', 'rsync',
    'crontab', 'at',
    'chmod', 'chown',
    'nmap', 'masscan',
    'dd',
])

function parseExecve(line: string): { command: string; args: string[] } | null {
    const match = line.match(/execve\("([^"]+)",\s*\[([^\]]*)\]/)
    if (!match) return null

    const command = match[1]
    const argsRaw = match[2]

    const args: string[] = []
    const argMatches = argsRaw.matchAll(/"([^"\\]*(\\.[^"\\]*)*)"/g)
    for (const m of argMatches) {
        args.push(m[1])
    }

    return { command, args: args.slice(1) }
}

function classifyCommand(command: string): {
    level: 'clean' | 'suspicious' | 'dangerous' | 'critical'
    reason: string
} {
    const base = command.split('/').pop()?.toLowerCase() ?? command.toLowerCase()

    if (CRITICAL.has(base)) return { level: 'critical', reason: `Reverse shell / network tool: ${base}` }
    if (DANGEROUS.has(base)) return { level: 'dangerous', reason: `Remote download tool: ${base}` }
    if (SUSPICIOUS.has(base)) return { level: 'suspicious', reason: `Suspicious tool during install: ${base}` }
    if (BENIGN.has(base)) return { level: 'clean', reason: '' }

    return { level: 'suspicious', reason: `Unknown process during install: ${base}` }
}

export class StraceMonitor {
    private events: ProcessEvent[] = []
    private straceProcess: ChildProcess | null = null
    private onEvent: (event: ProcessEvent) => void
    private seenCommands = new Set<string>()

    constructor(onEvent: (event: ProcessEvent) => void) {
        this.onEvent = onEvent
    }

    // Attach to a readable stream — used when strace wraps npm directly
    attachToStream(stream: NodeJS.ReadableStream): void {
        const rl = readline.createInterface({ input: stream })
        rl.on('line', (line: string) => this.parseLine(line))
    }

    // Attach to an already-running PID
    attachToPid(pid: number): void {
        this.straceProcess = spawn('strace', [
            '-p', String(pid), '-f', '-e', 'execve', '-s', '200', '-q',
        ], {
            stdio: ['ignore', 'ignore', 'pipe'],
        })

        if (this.straceProcess.stderr) {
            const rl = readline.createInterface({ input: this.straceProcess.stderr })
            rl.on('line', (line: string) => this.parseLine(line))
        }
    }

    private parseLine(line: string): void {
        if (!line.includes('execve(')) return

        const parsed = parseExecve(line)
        if (!parsed) return

        const { command, args } = parsed
        const { level, reason } = classifyCommand(command)

        if (level === 'clean') return

        // Deduplicate same command
        const key = `${command}:${args[0] ?? ''}`
        if (this.seenCommands.has(key)) return
        this.seenCommands.add(key)

        const event: ProcessEvent = {
            type: 'process',
            timestamp: Date.now(),
            command,
            args,
            parentPid: 0,
            childPid: 0,
            detail: `${reason} — ${[command, ...args.slice(0, 2)].join(' ')}`,
            raw: { command, args, level, line },
        }

        this.events.push(event)
        this.onEvent(event)
    }

    stop(): void {
        if (this.straceProcess && !this.straceProcess.killed) {
            this.straceProcess.kill()
        }
    }

    getAll(): ProcessEvent[] {
        return this.events
    }
}
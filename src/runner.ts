// src/runner.ts
// Spawns npm install wrapped in strace for reliable syscall interception.
// strace catches every execve() — even processes that die in <10ms.

import { spawn, execSync, type ChildProcess } from 'child_process'
import type { MonitorEvent, ScanResult } from './types.js'
import { StraceMonitor } from './monitor/strace.js'
import { NetworkMonitor } from './monitor/network.js'
import { FilesystemMonitor } from './monitor/filesystem.js'
import { Reasoner } from './reasoner/reasoner.js'
import {
  printInstallStart,
  printInstallEnd,
  printLiveEvent,
  printLiveSignal,
  printBlocked,
  printWarning,
} from './reporter.js'
import type { ProcessEvent, NetworkEvent, FilesystemEvent } from './types.js'

export interface RunnerOptions {
  args: string[]
  cwd: string
  block: boolean
  verbose: boolean
  intervalMs: number
}

export interface RunResult {
  exitCode: number
  scanResult: ScanResult
}

function isLinux(): boolean {
  return process.platform === 'linux'
}

function straceAvailable(): boolean {
  try {
    execSync('which strace', { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

function quickScore(event: MonitorEvent): {
  level: 'suspicious' | 'dangerous' | 'critical'
  reason: string
} | null {
  if (event.type === 'process') {
    const e = event as ProcessEvent
    const base = e.command.split('/').pop()?.toLowerCase() ?? ''

    if (['nc', 'ncat', 'socat', 'netcat'].includes(base))
      return { level: 'critical', reason: `Reverse shell tool: ${e.command}` }
    if (['curl', 'wget'].includes(base))
      return { level: 'dangerous', reason: `Remote download: ${e.command} ${e.args[0] ?? ''}` }
    if (['bash', 'zsh', 'python', 'python3', 'ruby', 'perl'].includes(base))
      return { level: 'suspicious', reason: `Interpreter spawned: ${e.command}` }
    if (['base64', 'openssl'].includes(base))
      return { level: 'suspicious', reason: `Encoding tool: ${e.command}` }
    return { level: 'suspicious', reason: e.detail }
  }

  if (event.type === 'network') {
    const C2 = new Set([4444, 1337, 31337, 6666, 6667])
    const port = (event as NetworkEvent).remotePort
    if (C2.has(port)) return { level: 'critical', reason: `C2 port: ${port}` }
    return { level: 'suspicious', reason: event.detail }
  }

  if (event.type === 'filesystem') {
    const fs = event as FilesystemEvent
    if (fs.reason.includes('CRITICAL')) return { level: 'critical', reason: fs.reason }
    return { level: 'suspicious', reason: fs.reason }
  }

  return null
}

export async function runInstall(options: RunnerOptions): Promise<RunResult> {
  const startTime = Date.now()
  const allEvents: MonitorEvent[] = []
  let blocked = false
  let child: ChildProcess | null = null

  const useStrace = isLinux() && straceAvailable()
  const useNetFs = isLinux()

  if (!isLinux()) {
    printWarning('Live monitoring requires Linux. Install will proceed unmonitored.')
  } else if (!useStrace) {
    printWarning('strace not found — install it: apt-get install -y strace')
  }

  function handleEvent(event: MonitorEvent): void {
    allEvents.push(event)
    if (options.verbose) printLiveEvent(event)

    const verdict = quickScore(event)
    if (verdict) {
      if (!options.verbose) printLiveEvent(event)
      printLiveSignal(verdict)

      if (verdict.level === 'critical' && options.block && child && !blocked) {
        blocked = true
        printBlocked(verdict.reason)
        child.kill('SIGTERM')
        setTimeout(() => { if (child && !child.killed) child.kill('SIGKILL') }, 2000)
      }
    }
  }

  printInstallStart()

  // Wrap npm with strace so we catch every execve syscall
  const spawnCmd = useStrace ? 'strace' : 'npm'
  const spawnArgs = useStrace
    ? ['-f', '-e', 'trace=execve', '-s', '200', '-q', '--', 'npm', 'install', ...options.args]
    : ['install', ...options.args]

  child = spawn(spawnCmd, spawnArgs, {
    cwd: options.cwd,
    stdio: ['inherit', 'inherit', useStrace ? 'pipe' : 'inherit'],
    env: process.env,
  })

  const installPid = child.pid!

  // Wire strace stderr into our parser
  let straceMonitor: StraceMonitor | null = null
  if (useStrace && child.stderr) {
    straceMonitor = new StraceMonitor(handleEvent)
    straceMonitor.attachToStream(child.stderr)
  }

  // Network + filesystem polling
  let networkMonitor: NetworkMonitor | null = null
  let filesystemMonitor: FilesystemMonitor | null = null
  let pollInterval: ReturnType<typeof setInterval> | null = null

  if (useNetFs) {
    networkMonitor = new NetworkMonitor()
    filesystemMonitor = new FilesystemMonitor(installPid, options.cwd)

    pollInterval = setInterval(() => {
      if (blocked) return
      for (const event of [...networkMonitor!.scan(), ...filesystemMonitor!.scan()]) {
        handleEvent(event)
      }
    }, options.intervalMs)
  }

  const exitCode = await new Promise<number>((resolve) => {
    child!.on('exit', (code: number | null, signal: NodeJS.Signals | null) => {
      resolve(code ?? (signal ? 1 : 0))
    })
    child!.on('error', (err: Error) => {
      console.error(`\n  Failed to spawn: ${err.message}`)
      if (useStrace) console.error('  Try: apt-get install -y strace\n')
      resolve(1)
    })
  })

  if (pollInterval) clearInterval(pollInterval)
  if (straceMonitor) straceMonitor.stop()

  printInstallEnd()

  const reasoner = new Reasoner()
  const scanResult = reasoner.reason(allEvents, Date.now() - startTime, blocked)

  return { exitCode, scanResult }
}
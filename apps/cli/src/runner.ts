// src/runner.ts
// Spawns npm install wrapped in strace for reliable syscall interception.
// strace catches every execve() — even processes that die in <10ms.

import { spawn, execSync, type ChildProcess } from 'child_process'
import type { MonitorEvent, ScanResult, ThreatSignal } from './types.js'
import { StraceMonitor } from './monitor/strace.js'
import { NetworkMonitor } from './monitor/network.js'
import { FilesystemMonitor } from './monitor/filesystem.js'
import { Reasoner } from './reasoner/reasoner.js'
import {
  printInstallStart,
  printInstallEnd,
  printLiveEvent,
  printLiveSignal,
  printWarning,
} from './reporter.js'
import type { ProcessEvent, NetworkEvent, FilesystemEvent, InstallResult, Signal, Severity, Verdict } from './types.js'

export interface RunnerOptions {
  args: string[]
  cwd: string
  block: boolean
  verbose: boolean
  intervalMs: number
}

// Exported result of runInstall – includes exit code and detailed install report
export interface RunResult {
  exitCode: number
  // InstallResult matches the shape expected by reporter.printReport
  scanResult: InstallResult
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

// Function to quickly score an event and produce a ThreatSignal
function quickScore(event: MonitorEvent): ThreatSignal | null {
  // Determine level and reason based on event type
  if (event.type === 'process') {
    const e = event as ProcessEvent;
    const base = e.command.split('/').pop()?.toLowerCase() ?? '';
    if (['nc', 'ncat', 'socat', 'netcat'].includes(base))
      return { event, level: 'critical', reason: `Reverse shell tool: ${e.command}` };
    if (['curl', 'wget'].includes(base))
      return { event, level: 'dangerous', reason: `Remote download: ${e.command} ${e.args[0] ?? ''}` };
    if (['bash', 'zsh', 'python', 'python3', 'ruby', 'perl'].includes(base))
      return { event, level: 'suspicious', reason: `Interpreter spawned: ${e.command}` };
    if (['base64', 'openssl'].includes(base))
      return { event, level: 'suspicious', reason: `Encoding tool: ${e.command}` };
    return { event, level: 'suspicious', reason: e.message };
  }

  if (event.type === 'network') {
    const C2 = new Set([4444, 1337, 31337, 6666, 6667]);
    const port = (event as NetworkEvent).remotePort;
    if (C2.has(port)) return { event, level: 'critical', reason: `C2 port: ${port}` };
    return { event, level: 'suspicious', reason: event.message };
  }

  if (event.type === 'filesystem') {
    const fs = event as FilesystemEvent;
    if (fs.reason.includes('CRITICAL')) return { event, level: 'critical', reason: fs.reason };
    return { event, level: 'suspicious', reason: fs.reason };
  }

  return null;
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

      // if (verdict.level === 'critical' && options.block && child && !blocked) {
      //   blocked = true
      //   printBlocked(verdict.reason)
      //   child.kill('SIGTERM')
      //   setTimeout(() => { if (child && !child.killed) child.kill('SIGKILL') }, 2000)
      // }
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

  // Create a Reasoner to analyse the collected events
  const reasoner = new Reasoner();

  const scan = reasoner.reason(allEvents, Date.now() - startTime, blocked);

  // Helper: map ThreatLevel to Verdict
  const threatLevelToVerdict = (level: import('./types.js').ThreatLevel): Verdict => {
    switch (level) {
      case 'clean':
        return 'SAFE';
      case 'suspicious':
        return 'SUSPICIOUS';
      case 'dangerous':
        return 'DANGEROUS';
      case 'critical':
        return 'CRITICAL';
    }
  };

  // Helper: map ThreatLevel to Severity (lowercase)
  const threatLevelToSeverity = (level: import('./types.js').ThreatLevel): Severity => {
    switch (level) {
      case 'clean':
        return 'safe';
      case 'suspicious':
        return 'suspicious';
      case 'dangerous':
        return 'dangerous';
      case 'critical':
        return 'critical';
    }
  };

  // Convert ThreatSignal[] to Signal[]
  const signals: Signal[] = scan.signals.map((s) => ({
    ...s,
    severity: threatLevelToSeverity(s.level),
    type: (s.event as any).type,
    message: s.reason,
    timestamp: (s.event as any).timestamp ?? Date.now(),
  }));

  // Transform ScanResult into InstallResult expected by reporter
  const installResult: InstallResult = {
    package: '', // package name not tracked here; left empty or could be inferred elsewhere
    verdict: threatLevelToVerdict(scan.verdict),
    durationMs: scan.duration,
    totalEvents: scan.events.length,
    totalSignals: scan.signals.length,
    signals,
    events: scan.events,
    blocked,
  };

  return { exitCode, scanResult: installResult };
}
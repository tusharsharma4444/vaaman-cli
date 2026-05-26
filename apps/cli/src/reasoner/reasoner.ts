// src/ai/reasoner.ts
// Correlates raw monitor events into threat signals and verdicts.
// This is where "primitive detection" becomes "behavioral intelligence".
// 
// Phase 1: Rule-based chain detection (fast, deterministic)
// Phase 2 (future): LLM reasoning layer for novel patterns

import type {
  MonitorEvent,
  ProcessEvent,
  NetworkEvent,
  FilesystemEvent,
  ThreatSignal,
  ThreatLevel,
  ScanResult,
} from '../types.js'

// ─── Attack Chain Definitions ────────────────────────────────────────────────
// Each chain is a pattern of events that together indicate malicious behavior.
// A single event rarely means anything. Chains mean a lot.

interface ChainRule {
  name: string
  description: string
  level: ThreatLevel
  detect: (events: MonitorEvent[]) => boolean
}

const ATTACK_CHAINS: ChainRule[] = [
  {
    name: 'network-exec',
    description: 'Network connection followed by process execution — classic staged payload',
    level: 'critical',
    detect(events) {
      const hasNetwork = events.some(e => e.type === 'network')
      const hasExec = events.some(e =>
        e.type === 'process' &&
        ['curl', 'wget', 'bash', 'sh'].some(c =>
          (e as ProcessEvent).command.includes(c)
        )
      )
      return hasNetwork && hasExec
    },
  },
  {
    name: 'shell-spawn',
    description: 'Shell spawned during install — postinstall executing shell commands',
    level: 'dangerous',
    detect(events) {
      return events.some(e =>
        e.type === 'process' &&
        ['bash', 'sh', 'zsh', 'ksh'].some(c =>
          (e as ProcessEvent).command.endsWith(c)
        )
      )
    },
  },
  {
    name: 'curl-exec',
    description: 'curl/wget used during install — remote code download pattern',
    level: 'dangerous',
    detect(events) {
      return events.some(e =>
        e.type === 'process' &&
        ['curl', 'wget'].some(c =>
          (e as ProcessEvent).command.endsWith(c)
        )
      )
    },
  },
  {
    name: 'env-harvest',
    description: 'Network connection during install — possible env variable exfiltration',
    level: 'suspicious',
    detect(events) {
      const networkEvents = events.filter(e => e.type === 'network') as NetworkEvent[]
      // If connecting to non-standard ports (not 443/80) during install
      return networkEvents.some(e => ![443, 80, 22, 9418].includes(e.remotePort))
    },
  },
  {
    name: 'homedir-write',
    description: 'Writing to home directory files — persistence or credential theft',
    level: 'critical',
    detect(events) {
      return events.some(e =>
        e.type === 'filesystem' &&
        (e as FilesystemEvent).reason.includes('sensitive path')
      )
    },
  },
  {
    name: 'suspicious-port',
    description: 'Connection to known C2/backdoor port',
    level: 'critical',
    detect(events) {
      const C2_PORTS = new Set([4444, 1337, 31337, 6666, 6667, 7777])
      return events.some(e =>
        e.type === 'network' &&
        C2_PORTS.has((e as NetworkEvent).remotePort)
      )
    },
  },
  {
    name: 'obfuscation-exec',
    description: 'base64/openssl decode followed by execution — payload decoding pattern',
    level: 'critical',
    detect(events) {
      const processEvents = events.filter(e => e.type === 'process') as ProcessEvent[]
      const hasDecoder = processEvents.some(e =>
        ['base64', 'openssl', 'xxd'].some(c => e.command.includes(c))
      )
      const hasExec = processEvents.some(e =>
        ['bash', 'sh', 'node', 'python'].some(c => e.command.includes(c))
      )
      return hasDecoder && hasExec
    },
  },
]

// ─── Individual Event Scoring ─────────────────────────────────────────────────

function scoreEvent(event: MonitorEvent): ThreatSignal | null {
  if (event.type === 'process') {
    const e = event as ProcessEvent
    const cmd = e.command.toLowerCase()

    if (['curl', 'wget'].some(c => cmd.endsWith(c))) {
      return {
        event,
        level: 'dangerous',
        reason: `Remote download tool spawned: ${e.command} ${e.args.slice(0, 3).join(' ')}`,
        chain: ['curl-exec'],
      }
    }

    if (['bash', 'sh', 'zsh'].some(c => cmd.endsWith(c))) {
      return {
        event,
        level: 'suspicious',
        reason: `Shell spawned during install: ${e.command} ${e.args.slice(0, 3).join(' ')}`,
        chain: ['shell-spawn'],
      }
    }

    if (['nc', 'ncat', 'socat'].some(c => cmd.endsWith(c))) {
      return {
        event,
        level: 'critical',
        reason: `Network utility spawned — possible reverse shell: ${e.command}`,
        chain: ['network-exec'],
      }
    }

    if (['base64', 'openssl', 'xxd'].some(c => cmd.endsWith(c))) {
      return {
        event,
        level: 'suspicious',
        reason: `Encoding/decoding tool spawned — possible payload obfuscation: ${e.command}`,
        chain: ['obfuscation-exec'],
      }
    }

    return {
      event,
      level: 'suspicious',
      reason: `Unexpected process during install: ${e.command}`,
    }
  }

  if (event.type === 'network') {
    const e = event as NetworkEvent
    const C2_PORTS = new Set([4444, 1337, 31337, 6666, 6667])

    if (C2_PORTS.has(e.remotePort)) {
      return {
        event,
        level: 'critical',
        reason: `Connection to known C2 port ${e.remotePort} at ${e.remoteIp}`,
        chain: ['suspicious-port'],
      }
    }

    return {
      event,
      level: 'suspicious',
      reason: `Outbound connection to ${e.remoteIp}:${e.remotePort} during install`,
      chain: ['env-harvest'],
    }
  }

  if (event.type === 'filesystem') {
    const e = event as FilesystemEvent
    const isCritical = e.reason.includes('CRITICAL') || e.reason.includes('sensitive')

    return {
      event,
      level: isCritical ? 'critical' : 'suspicious',
      reason: e.reason,
      chain: isCritical ? ['homedir-write'] : [],
    }
  }

  return null
}

// ─── Verdict Aggregation ───────────────────────────────────────────────────────

function aggregateVerdict(signals: ThreatSignal[], chainHits: string[]): ThreatLevel {
  if (signals.some(s => s.level === 'critical') || chainHits.some(c =>
    ['network-exec', 'homedir-write', 'suspicious-port', 'obfuscation-exec'].includes(c)
  )) return 'critical'

  if (signals.some(s => s.level === 'dangerous') || chainHits.length > 0) return 'dangerous'

  if (signals.some(s => s.level === 'suspicious')) return 'suspicious'

  return 'clean'
}

function buildSummary(verdict: ThreatLevel, signals: ThreatSignal[], chainHits: string[]): string {
  if (verdict === 'clean') return 'No suspicious activity detected during install.'

  const parts: string[] = []

  if (chainHits.length > 0) {
    parts.push(`Attack chains detected: ${chainHits.join(', ')}`)
  }

  const byLevel = {
    critical: signals.filter(s => s.level === 'critical').length,
    dangerous: signals.filter(s => s.level === 'dangerous').length,
    suspicious: signals.filter(s => s.level === 'suspicious').length,
  }

  if (byLevel.critical > 0) parts.push(`${byLevel.critical} critical signal(s)`)
  if (byLevel.dangerous > 0) parts.push(`${byLevel.dangerous} dangerous signal(s)`)
  if (byLevel.suspicious > 0) parts.push(`${byLevel.suspicious} suspicious signal(s)`)

  return parts.join(' · ')
}

// ─── Main Reasoner ─────────────────────────────────────────────────────────────

export class Reasoner {
  reason(events: MonitorEvent[], durationMs: number, blocked: boolean): ScanResult {
    // Step 1: Score individual events
    const signals: ThreatSignal[] = []
    for (const event of events) {
      const signal = scoreEvent(event)
      if (signal) signals.push(signal)
    }

    // Step 2: Detect attack chains across all events
    const chainHits: string[] = []
    for (const chain of ATTACK_CHAINS) {
      if (chain.detect(events)) {
        chainHits.push(chain.name)
      }
    }

    // Step 3: Aggregate verdict
    const verdict = aggregateVerdict(signals, chainHits)

    // Step 4: Build summary
    const summary = buildSummary(verdict, signals, chainHits)

    return {
      duration: durationMs,
      events,
      signals,
      verdict,
      summary,
      blocked,
    }
  }
}

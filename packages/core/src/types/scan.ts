// @vaaman/core — shared types
// Unified type definitions consumed by all Vaaman packages

// ─── Verdict / Severity ──────────────────────────────────────────────────

export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS' | 'CRITICAL' | 'BLOCK'
export type Severity = 'safe' | 'suspicious' | 'dangerous' | 'critical'

// ─── Monitor Events ──────────────────────────────────────────────────────

export type EventType = 'filesystem' | 'process' | 'network'

export interface MonitorEvent {
  type: EventType
  severity: Severity
  message: string
  timestamp?: number
  path?: string
  command?: string
  url?: string
  pid?: number
  raw?: Record<string, unknown>
}

export interface ProcessEvent extends MonitorEvent {
  type: 'process'
  parentPid: number
  childPid: number
  command: string
  args: string[]
  detail: string
}

export interface NetworkEvent extends MonitorEvent {
  type: 'network'
  localAddr: string
  remoteAddr: string
  remoteIp: string
  remotePort: number
  state: string
}

export interface FilesystemEvent extends MonitorEvent {
  type: 'filesystem'
  path: string
  operation: 'write' | 'create' | 'delete'
  suspicious: boolean
  reason: string
}

// ─── Threat Signals ──────────────────────────────────────────────────────

export type ThreatLevel = 'clean' | 'suspicious' | 'dangerous' | 'critical'

export interface ThreatSignal {
  event: MonitorEvent
  level: ThreatLevel
  reason: string
  chain?: string[]
}

export interface AttackChain {
  id: string
  name: string
  severity: 'suspicious' | 'dangerous' | 'critical'
  events: string[]
  description: string
  confidence: number
}

// ─── Scan Results ────────────────────────────────────────────────────────

export interface ScanResult {
  duration: number
  events: MonitorEvent[]
  signals: ThreatSignal[]
  verdict: ThreatLevel
  summary: string
  blocked: boolean
}

// ─── Pre-Scan Types ──────────────────────────────────────────────────────

export type RiskLevel = 'safe' | 'suspicious' | 'dangerous'
export type Recommendation = 'proceed' | 'caution' | 'block'

export interface LifecycleScript {
  name: string
  content: string
  riskLevel: RiskLevel
  reasons: string[]
}

export interface PrimitiveHit {
  file: string
  line: number
  column: number
  primitive: string
  context: string
  riskLevel: RiskLevel
}

export interface BehavioralChain {
  name: string
  severity: Severity
  description: string
  file: string
  lineRange: [number, number]
  primitives: PrimitiveRef[]
}

export interface PrimitiveRef {
  primitive: string
  line: number
}

export interface PreScanResult {
  package: string
  version: string
  resolvedAt: string
  score: number
  recommendation: Verdict
  scanTimeMs: number
  filesScanned: number
  tarbyteSizeBytes: number
  lifecycleScripts: LifecycleScript[]
  primitiveHits: PrimitiveHit[]
  behavioralChains: BehavioralChain[]
  summary: {
    totalPrimitiveHits: number
    totalChains: number
    dangerous: number
    suspicious: number
  }
}

export interface PreScanInput {
  packageName: string
  version?: string
}

export interface TarballEntry {
  path: string
  content: string
}

// ─── Install Result ─────────────────────────────────────────────────────

export interface Signal extends ThreatSignal {
  severity: Severity
  type: EventType
  message: string
  timestamp: number
}

export interface InstallResult {
  package: string
  verdict: Verdict
  durationMs: number
  totalEvents: number
  totalSignals: number
  signals: Signal[]
  events: MonitorEvent[]
  blocked: boolean
}

// ─── Vaaman Report (combined output) ─────────────────────────────────────

export interface VaamanReport {
  vaaman: string
  package: string
  version: string
  generatedAt: string
  verdict: Verdict | null
  preScan: PreScanResult | null
  install: InstallResult | null
}

// ─── Monitor Options ─────────────────────────────────────────────────────

export interface MonitorOptions {
  rootPid: number
  installPid: number
  verbose: boolean
  block: boolean
  intervalMs: number
}

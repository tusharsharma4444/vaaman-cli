// @vaaman/core — AI layer types
// Shared by CLI AI reasoner, Deep Intel, Trust Engine, and Swarm Engine

import type { Verdict, PreScanResult, InstallResult, MonitorEvent, Signal } from './scan.js'

// ─── Intent Classification ───────────────────────────────────────────────

export type IntentType =
  | 'compiler-utility'
  | 'framework-internal'
  | 'operational-legitimate'
  | 'suspicious-execution'
  | 'payload-execution'
  | 'credential-harvesting'

// ─── AI Verdict (LLM Reasoner output) ────────────────────────────────────

export interface AIVerdict {
  verdict: Verdict
  confidence: number
  summary: string
  whatItDid: string[]
  whyItsDangerous: string[] | null
  remediation: string[]
  novelPatterns: string[] | null
  intentClassification: IntentType
  model: string
  latencyMs: number
  parseError?: boolean
}

// ─── LLM Reasoner Input ──────────────────────────────────────────────────

export interface LLMReasonerInput {
  package: { name: string; version: string }
  preScan: PreScanResult
  behavioral: {
    events: MonitorEvent[]
    signals: Signal[]
    chains: string[]
  }
  installDurationMs: number
}

// ─── Deep Intel Types ────────────────────────────────────────────────────

export interface IntentClassification {
  file: string
  line: number
  primitive: string
  classification: IntentType
  confidence: number
  reasoning: string
  legitimateUse: string | null
}

export interface DeepIntelOutput {
  package: string
  version: string
  packageType: PackageType
  intents: IntentClassification[]
  suppressedCount: number
  legitimacyScore: number
  legitimacyVerdict: 'likely-legitimate' | 'uncertain' | 'likely-malicious'
  reasoning: string
  model: string
  latencyMs: number
}

export type PackageType =
  | 'cli-tool'
  | 'build-tool'
  | 'framework'
  | 'library'
  | 'dev-tool'
  | 'runtime-utility'
  | 'malicious-tool'
  | 'unknown'

// ─── Trust Engine Types ──────────────────────────────────────────────────

export interface TrustScore {
  overall: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  breakdown: {
    ecosystemScore: number
    identityScore: number
    behaviorScore: number
    intentScore: number
    deceptionScore: number
    transparencyScore: number
  }
  flags: string[]
}

// ─── Swarm Types ─────────────────────────────────────────────────────────

export interface NormalizedCVE {
  id: string
  packageName: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  summary: string
  affectedVersions: string[]
  isInstallTimeExploitable: boolean
  references: string[]
}

export interface AgentFinding {
  cveId: string
  packageName: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  cveSummary: string
  attackScenario: string
  isInstallTimeExploitable: boolean
  observedBehavior: {
    detected: boolean
    events: MonitorEvent[]
    chains: string[]
  } | null
  riskScore: number
  remediation: {
    immediate: string[]
    longTerm: string[]
  }
  references: string[]
  agentType: 'cve' | 'exploit-confirmation' | 'blast-radius' | 'novel-pattern'
  toolCallCount: number
  graphCorrelationStrength?: number
}

export interface SwarmResult {
  scanId: string
  projectName: string
  scannedAt: string
  durationMs: number
  depsScanned: number
  cvesAnalyzed: number
  agentsSpawned: number
  autospawnRounds: number
  findings: AgentFinding[]
  overallRiskGrade: 'A' | 'B' | 'C' | 'D' | 'F'
  criticalCount: number
  highCount: number
  cypherSnapshot: string
}

// ─── Graph Types (Neo4j) ─────────────────────────────────────────────────

export interface PackageNode {
  id: string
  name: string
  version: string
  registry: string
  scanId: string
  preScanScore: number
  verdict: string
  scannedAt: string
}

export interface ChainNode {
  id: string
  name: string
  severity: string
  confidence: number
  scanId: string
  instanceCount: number
}

export interface CVENode {
  id: string
  packageName: string
  severity: string
  isInstallTimeExploitable: boolean
  behaviorConfirmed: boolean
  exploitSimScore: number
}

export interface GraphEdge {
  from: string
  to: string
  type: string
  weight?: number
}

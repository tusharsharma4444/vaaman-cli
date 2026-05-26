// Re-export barrel — all types now live in @vaaman/core
// This file exists for backward compatibility with existing relative imports.
// New code should import directly from '@vaaman/core'.

export {
  type ThreatLevel,
  type ThreatSignal,
  type MonitorEvent,
  type ProcessEvent,
  type NetworkEvent,
  type FilesystemEvent,
  type EventType,
  type ScanResult,
  type Severity,
  type Verdict,
  type Signal,
  type InstallResult,
  type AttackChain,
  type MonitorOptions,
  type PreScanResult,
  type PrimitiveHit,
  type LifecycleScript,
  type RiskLevel,
  type Recommendation,
  type BehavioralChain,
  type PrimitiveRef,
  type VaamanReport,
} from '@vaaman/core'

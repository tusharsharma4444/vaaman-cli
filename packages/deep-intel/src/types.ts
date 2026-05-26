// @vaaman/deep-intel — internal types for the Deep Intel pipeline

import type { IntentType, PackageType, IntentClassification, DeepIntelOutput, PreScanResult } from '@vaaman/core'

export type { IntentType, PackageType, IntentClassification, DeepIntelOutput }

export interface DeepIntelInput {
  packageName: string
  version: string
  preScan: PreScanResult
}

export interface PackageTypeResult {
  type: PackageType
  confidence: number
  reasoning: string
}

export interface IntentBatchResult {
  classifications: IntentClassification[]
}

export interface SuppressionResult {
  intents: IntentClassification[]
  suppressed: IntentClassification[]
  suppressedCount: number
}

export interface LegitimacyResult {
  score: number
  verdict: 'likely-legitimate' | 'uncertain' | 'likely-malicious'
  reasoning: string
  capabilitiesNeeded: string[]
  signalsExceedingNeed: string[] | null
}

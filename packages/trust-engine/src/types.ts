// @vaaman/trust-engine — internal types

import type { TrustScore } from '@vaaman/core'
import type { DeepIntelOutput, PreScanResult } from '@vaaman/core'

export type { TrustScore }

export interface TrustEngineInput {
  packageName: string
  version: string
  preScan: PreScanResult
  deepIntel: DeepIntelOutput
}

export interface EcosystemData {
  name: string
  description: string
  version: string
  license: string
  repository: string | null
  homepage: string | null
  keywords: string[]
  maintainers: number
  createdAt: string
  weeklyDownloads: number
  versionCount: number
  dependencies: Record<string, string>
  devDependencies: Record<string, string>
  hasReadme: boolean
  hasChangelog: boolean
  hasContributing: boolean
  hasCodeOfConduct: boolean
}

export interface EcosystemScore {
  score: number
  flags: string[]
  reasoning: string
}

export interface IdentityScore {
  score: number
  claimed: string[]
  inferred: string[]
  conflicts: string[]
  reasoning: string
}

export interface DeceptionScore {
  score: number
  flags: string[]
  reasoning: string
}

export interface TransparencyScore {
  score: number
  hiddenBehaviors: string[]
  documentedBehaviors: string[]
  reasoning: string
}

export interface CapabilityScore {
  score: number
  legitimate: string[]
  suspicious: string[]
  reasoning: string
}

export interface TrustEngineOutput {
  package: string
  version: string
  trust: TrustScore
  model: string
  latencyMs: number
}

// @vaaman/trust-engine — Trust Score Aggregator
// Combines all six dimensions into a weighted composite trust score.
// Weight rationale:
//   Identity (25%) — highest weight: claims vs reality is the strongest trust signal
//   Intent (25%) — equal to identity: what the AI sees in the code
//   Capability (20%) — what it CAN do vs what it SHOULD do
//   Ecosystem (15%) — registry metadata (lower: popular packages can be compromised)
//   Deception (10%) — gap between claims and behavior
//   Transparency (5%) — documentation quality (amplifier, not primary)

import type { TrustScore } from '@vaaman/core'
import type {
  EcosystemScore,
  IdentityScore,
  DeceptionScore,
  TransparencyScore,
  CapabilityScore,
} from './types.js'

const WEIGHTS = {
  identity: 0.25,
  intent: 0.25,
  capability: 0.20,
  ecosystem: 0.15,
  deception: 0.10,
  transparency: 0.05,
} as const

function scoreToGrade(score: number): TrustScore['grade'] {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 55) return 'C'
  if (score >= 35) return 'D'
  return 'F'
}

export function aggregateTrustScore(dimensions: {
  ecosystem: EcosystemScore
  identity: IdentityScore
  deepIntel: { legitimacyScore: number }
  deception: DeceptionScore
  transparency: TransparencyScore
  capability: CapabilityScore
}): TrustScore {
  // Deception is inverted: high deception = low trust
  const deceptionTrust = 100 - dimensions.deception.score

  const raw = (
    dimensions.ecosystem.score * WEIGHTS.ecosystem +
    dimensions.identity.score * WEIGHTS.identity +
    dimensions.deepIntel.legitimacyScore * WEIGHTS.intent +
    deceptionTrust * WEIGHTS.deception +
    dimensions.transparency.score * WEIGHTS.transparency +
    dimensions.capability.score * WEIGHTS.capability
  )

  const overall = Math.round(Math.min(100, Math.max(0, raw)))

  // Collect all flags
  const flags: string[] = [
    ...dimensions.ecosystem.flags.map((f: string) => `[eco] ${f}`),
    ...dimensions.identity.conflicts.map((c: string) => `[identity] ${c}`),
    ...dimensions.deception.flags.map((f: string) => `[deception] ${f}`),
    ...dimensions.transparency.hiddenBehaviors.map((h: string) => `[transparency] ${h}`),
    ...dimensions.capability.suspicious.map((s: string) => `[capability] ${s}`),
  ].slice(0, 20)

  return {
    overall,
    grade: scoreToGrade(overall),
    breakdown: {
      ecosystemScore: dimensions.ecosystem.score,
      identityScore: dimensions.identity.score,
      behaviorScore: dimensions.deepIntel.legitimacyScore,
      intentScore: dimensions.deepIntel.legitimacyScore,
      deceptionScore: dimensions.deception.score,
      transparencyScore: dimensions.transparency.score,
    },
    flags,
  }
}

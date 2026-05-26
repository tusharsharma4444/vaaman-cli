// @vaaman/trust-engine — Main orchestrator
// Pipeline: fetch ecosystem → identity → deception → transparency → capability → aggregate
//
// Runs ecosystem fetch + identity + capability in parallel (independent).
// Deception and transparency depend on identity, so run sequentially after.
// All AI calls are cached.

import type { PreScanResult, DeepIntelOutput } from '@vaaman/core'
import type { TrustEngineInput, TrustEngineOutput } from './types.js'
import { fetchEcosystemData } from './fetcher.js'
import { EcosystemAnalyzer } from './dimensions/ecosystem.js'
import { IdentityAnalyzer } from './dimensions/identity.js'
import { DeceptionDetector } from './dimensions/deception.js'
import { TransparencyAnalyzer } from './dimensions/transparency.js'
import { CapabilityAnalyzer } from './dimensions/capability.js'
import { aggregateTrustScore } from './scorer.js'

export class TrustEnginePipeline {
  private ecosystem = new EcosystemAnalyzer()
  private identity = new IdentityAnalyzer()
  private deception = new DeceptionDetector()
  private transparency = new TransparencyAnalyzer()
  private capability = new CapabilityAnalyzer()

  async assess(input: TrustEngineInput): Promise<TrustEngineOutput> {
    const startTime = Date.now()
    const { packageName, version, preScan, deepIntel } = input

    // Fetch ecosystem data from npm registry (no AI)
    const ecoData = await fetchEcosystemData(packageName, version)

    // Run independent dimensions in parallel
    const [ecosystemScore, identityScore, capabilityScore] = await Promise.all([
      this.ecosystem.analyze(ecoData),
      this.identity.analyze(ecoData, deepIntel),
      this.capability.analyze(preScan, deepIntel),
    ])

    // Run dependent dimensions (use identity output)
    const deceptionScore = this.deception.detect(ecoData, preScan, deepIntel, identityScore)
    const transparencyScore = await this.transparency.analyze(ecoData, preScan)

    // Aggregate
    const trust = aggregateTrustScore({
      ecosystem: ecosystemScore,
      identity: identityScore,
      deepIntel: { legitimacyScore: deepIntel.legitimacyScore },
      deception: deceptionScore,
      transparency: transparencyScore,
      capability: capabilityScore,
    })

    return {
      package: packageName,
      version,
      trust,
      model: 'deepseek/deepseek-v4-flash',
      latencyMs: Date.now() - startTime,
    }
  }
}

export async function runTrustEngine(
  preScan: PreScanResult,
  deepIntel: DeepIntelOutput
): Promise<TrustEngineOutput> {
  const pipeline = new TrustEnginePipeline()
  return pipeline.assess({
    packageName: preScan.package,
    version: preScan.version,
    preScan,
    deepIntel,
  })
}

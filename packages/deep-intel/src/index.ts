// @vaaman/deep-intel — Main orchestrator
// Pipeline: classify package type → contextualize primitives → suppress → assess legitimacy
//
// Each AI call is logged with latency for cost tracking.
// Results cached at each stage to avoid redundant API calls on re-scans.

import { getLLMCache } from '@vaaman/core'
import type { PreScanResult, DeepIntelOutput } from '@vaaman/core'
import { PackageTypeClassifier } from './intent/classifier.js'
import { PrimitiveContextualizer } from './intent/contextualizer.js'
import { SuppressionEngine } from './suppression/engine.js'
import { LegitimacyAssessor } from './legitimacy/assessor.js'
import type { DeepIntelInput } from './types.js'

export class DeepIntelPipeline {
  private classifier = new PackageTypeClassifier()
  private contextualizer = new PrimitiveContextualizer()
  private suppressor = new SuppressionEngine()
  private assessor = new LegitimacyAssessor()

  async analyze(input: DeepIntelInput): Promise<DeepIntelOutput> {
    const startTime = Date.now()
    const { packageName, version, preScan } = input

    // Stage 1: Classify package type
    const typeStart = Date.now()
    const packageType = await this.classifier.classify({ packageName, version, preScan })
    const typeLatency = Date.now() - typeStart

    // Stage 2: Contextualize primitives with AI
    const intentStart = Date.now()
    const intentResult = await this.contextualizer.contextualize({
      packageName,
      version,
      packageType: packageType.type,
      preScan,
    })
    const intentLatency = Date.now() - intentStart

    // Stage 3: Suppress known-good patterns (deterministic, no AI)
    const suppression = this.suppressor.apply(intentResult.classifications)

    // Stage 4: Assess legitimacy with AI
    const legitStart = Date.now()
    const legitimacy = await this.assessor.assess({
      packageName,
      version,
      packageType: packageType.type,
      intents: suppression.intents,
      chains: preScan.behavioralChains,
    })
    const legitLatency = Date.now() - legitStart

    const totalLatency = Date.now() - startTime

    return {
      package: packageName,
      version,
      packageType: packageType.type,
      intents: suppression.intents,
      suppressedCount: suppression.suppressedCount,
      legitimacyScore: legitimacy.score,
      legitimacyVerdict: legitimacy.verdict,
      reasoning: legitimacy.reasoning,
      model: 'anthropic/claude-sonnet-4-20250514',
      latencyMs: totalLatency,
    }
  }
}

export async function runDeepIntel(preScan: PreScanResult): Promise<DeepIntelOutput> {
  const pipeline = new DeepIntelPipeline()
  return pipeline.analyze({
    packageName: preScan.package,
    version: preScan.version,
    preScan,
  })
}

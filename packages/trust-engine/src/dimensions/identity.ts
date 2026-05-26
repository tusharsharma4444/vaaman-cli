// @vaaman/trust-engine — Identity Analysis
// AI-powered: compares what the package CLAIMS to be (metadata, README, description)
// with what it ACTUALLY does (deep intel findings, behavioral signals).
//
// A date-formatting library that spawns child_process has an identity conflict.

import { OpenRouterClient, getLLMCache } from '@vaaman/core'
import type { DeepIntelOutput } from '@vaaman/core'
import type { EcosystemData, IdentityScore } from '../types.js'

const SYSTEM_PROMPT = `You are a supply chain security analyst.
Your task: compare what a package CLAIMS to be with what its BEHAVIOR reveals.

You receive:
1. Package metadata (description, keywords, dependencies)
2. Deep Intel analysis (package type, intent classifications, legitimacy)

Determine:
1. What does the package CLAIM to be? (from description, keywords, deps)
2. What does the BEHAVIOR suggest it actually is?
3. Are there CONFLICTS between claims and behavior?

Red flags:
- Claims to be a "date formatter" but has child_process + network capabilities
- Description says "lightweight utility" but has postinstall scripts
- Keywords say "React component" but dependencies show Express + database driver
- Package type from deep intel is "library" but behavior shows CLI tool capabilities

Score 0-100 where 100 = perfect alignment between claims and behavior.
Respond with ONLY valid JSON:
{
  "score": N,
  "claimed": ["what it claims to be"],
  "inferred": ["what behavior suggests"],
  "conflicts": ["specific conflicts"] | [],
  "reasoning": "one paragraph"
}`

export class IdentityAnalyzer {
  private openrouter = new OpenRouterClient()

  async analyze(eco: EcosystemData, deepIntel: DeepIntelOutput): Promise<IdentityScore> {
    const cache = getLLMCache()
    const cacheKey = `trust:id:${eco.name}`

    const cached = cache.get(cacheKey) as IdentityScore | null
    if (cached) return cached

    const intentSummary = deepIntel.intents.slice(0, 15).map(i =>
      `${i.classification}: ${i.primitive} in ${i.file}`
    ).join('; ')

    const prompt = `
Package: ${eco.name}
Description: "${eco.description}"
Keywords: ${eco.keywords.join(', ') || 'none'}
Dependencies: ${Object.keys(eco.dependencies).join(', ') || 'none'}

Deep Intel package type: ${deepIntel.packageType}
Legitimacy: ${deepIntel.legitimacyVerdict} (${deepIntel.legitimacyScore}/100)
Deep Intel reasoning: ${deepIntel.reasoning}
Intent signals: ${intentSummary || 'none'}

Analyze identity alignment.`

    const response = await this.openrouter.chat({
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
      maxTokens: 400,
      temperature: 0.1,
    })

    const result = this.parseResponse(response.content, eco.name)

    if (response.stopReason !== 'error') {
      cache.set(cacheKey, result, response.model, response.usage.inputTokens + response.usage.outputTokens)
    }

    return result
  }

  private parseResponse(raw: string, name: string): IdentityScore {
    try {
      const clean = raw.replace(/```json|```/g, '').trim()
      const j = JSON.parse(clean)
      return {
        score: Math.min(100, Math.max(0, parseInt(String(j.score)) || 50)),
        claimed: Array.isArray(j.claimed) ? j.claimed : [],
        inferred: Array.isArray(j.inferred) ? j.inferred : [],
        conflicts: Array.isArray(j.conflicts) ? j.conflicts : [],
        reasoning: j.reasoning || `Identity analysis for ${name}`,
      }
    } catch {
      return { score: 50, claimed: [], inferred: [], conflicts: [], reasoning: `Parse error for ${name}` }
    }
  }
}

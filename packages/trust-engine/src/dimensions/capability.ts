// @vaaman/trust-engine — Capability Inference
// AI-powered: compares what capabilities a package ACTUALLY has
// with what it SHOULD have for its type. Detects capability overreach.
//
// Example: A date-formatting library with child_process, network, and filesystem
// capabilities is highly overreaching. A CLI tool with those same capabilities is normal.

import { OpenRouterClient, getLLMCache } from '@vaaman/core'
import type { DeepIntelOutput, PreScanResult } from '@vaaman/core'
import type { CapabilityScore } from '../types.js'

const SYSTEM_PROMPT = `You are a supply chain security analyst.
Your task: compare a package's ACTUAL capabilities with what is LEGITIMATE for its type.

For each package type, here are normally legitimate capabilities:
- cli-tool: child_process, filesystem read/write, process.env, network (for API calls)
- build-tool: eval (codegen), filesystem write, child_process (spawning compilers)
- framework: eval (template compilation), dynamic imports, DOM manipulation
- library: Pure computation — should rarely need child_process, network, or filesystem
- dev-tool: child_process, filesystem read/write
- runtime-utility: network, filesystem (if DB driver or logger)

A capability is SUSPICIOUS when it falls outside what the package type legitimately needs.
Score 0-100 where 100 = perfectly appropriate capabilities for its type.
Respond with ONLY valid JSON:
{
  "score": N,
  "legitimate": ["capabilities that are expected"],
  "suspicious": ["capabilities that exceed legitimate need"],
  "reasoning": "one paragraph"
}`

export class CapabilityAnalyzer {
  private openrouter = new OpenRouterClient()

  async analyze(
    preScan: PreScanResult,
    deepIntel: DeepIntelOutput
  ): Promise<CapabilityScore> {
    const cache = getLLMCache()
    const cacheKey = `trust:cap:${preScan.package}@${preScan.version}`

    const cached = cache.get(cacheKey) as CapabilityScore | null
    if (cached) return cached

    const primitives = [...new Set(preScan.primitiveHits.map(h => h.primitive))]
    const chains = preScan.behavioralChains.map(c => c.name)

    const prompt = `
Package: ${preScan.package}
Package type: ${deepIntel.packageType}

Observed capabilities (primitives):
${primitives.map(p => `  - ${p}`).join('\n')}

Behavioral chains:
${chains.map(c => `  - ${c}`).join('\n') || '  none'}

Active intent signals (${deepIntel.intents.length}):
${deepIntel.intents.slice(0, 10).map(i =>
  `  - ${i.classification}: ${i.primitive}`
).join('\n')}

Analyze capability appropriateness for a ${deepIntel.packageType}.`

    const response = await this.openrouter.chat({
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
      maxTokens: 400,
      temperature: 0.1,
    })

    const result = this.parseResponse(response.content, preScan.package)

    if (response.stopReason !== 'error') {
      cache.set(cacheKey, result, response.model, response.usage.inputTokens + response.usage.outputTokens)
    }

    return result
  }

  private parseResponse(raw: string, name: string): CapabilityScore {
    try {
      const clean = raw.replace(/```json|```/g, '').trim()
      const j = JSON.parse(clean)
      return {
        score: Math.min(100, Math.max(0, parseInt(String(j.score)) || 50)),
        legitimate: Array.isArray(j.legitimate) ? j.legitimate : [],
        suspicious: Array.isArray(j.suspicious) ? j.suspicious : [],
        reasoning: j.reasoning || `Capability assessment for ${name}`,
      }
    } catch {
      return { score: 50, legitimate: [], suspicious: [], reasoning: `Parse error for ${name}` }
    }
  }
}

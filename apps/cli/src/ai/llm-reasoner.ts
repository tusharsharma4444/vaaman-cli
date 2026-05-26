// Vaaman AI — LLM Reasoner
// Single-pass agent: collects all scan context, calls OpenRouter once,
// returns a structured AIVerdict.
//
// Single-pass is the right pattern here because all data is collected
// BEFORE the reasoner runs. No tools needed — just classification.

import { OpenRouterClient, getLLMCache } from '@vaaman/core'
import type { AIVerdict, PreScanResult } from '@vaaman/core'
import { buildReasonerPrompt, SYSTEM_PROMPT } from './prompt-builder.js'
import { parseVerdict } from './verdict-parser.js'

export interface LLMReasonerInput {
  package: { name: string; version: string }
  preScan: PreScanResult | null
  events: { count: number; topEvents: string[] }
  chains: string[]
  installDurationMs: number
}

export class LLMReasoner {
  private openrouter = new OpenRouterClient()

  async reason(input: LLMReasonerInput): Promise<AIVerdict> {
    const cache = getLLMCache()
    const cacheKey = `reasoner:${input.package.name}@${input.package.version}:v2`

    const cached = cache.get(cacheKey) as AIVerdict | null
    if (cached) return cached

    const prompt = buildReasonerPrompt(input)
    const startTime = Date.now()

    const response = await this.openrouter.chat({
      model: 'anthropic/claude-sonnet-4-20250514',
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
      maxTokens: 800,
      temperature: 0.1,
    })

    const latency = Date.now() - startTime
    const verdict = parseVerdict(
      response.content,
      response.model,
      latency
    )

    if (response.stopReason !== 'error') {
      cache.set(cacheKey, verdict, response.model, response.usage.inputTokens + response.usage.outputTokens)
    }

    return verdict
  }
}

// Factory: decides whether to use LLM or rule-based reasoner
export function shouldUseLLM(input: {
  preScan: PreScanResult | null
  chains: string[]
  eventCount: number
}): boolean {
  if (input.chains.length > 0) return true
  if ((input.preScan?.score ?? 0) > 40) return true
  if ((input.preScan?.primitiveHits?.length ?? 0) > 5) return true
  if (input.eventCount > 10) return true
  return false
}

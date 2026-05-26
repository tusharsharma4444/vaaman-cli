// @vaaman/trust-engine — Ecosystem Scoring
// Fetches npm registry metadata and uses AI to assess ecosystem trustworthiness.
//
// Key signals: package age, download count, maintainer count, documentation presence.
// AI reasons about contradictory signals (e.g. new package with inflated downloads).

import { OpenRouterClient, getLLMCache } from '@vaaman/core'
import type { EcosystemData, EcosystemScore } from '../types.js'

const SYSTEM_PROMPT = `You are a supply chain security analyst assessing npm ecosystem trustworthiness.
You receive npm registry metadata for a package and must score its ecosystem trust.

Trust signals (high trust):
- Package > 2 years old
- >10K weekly downloads (organic adoption)
- Multiple maintainers (not a sock puppet account)
- Has README, license, repository URL
- Many versions (active maintenance)

Red flags (low trust):
- Package < 30 days old with high downloads (bot-inflated)
- No README, no license, no repository (throwaway package)
- Single maintainer with no other known packages (sock puppet)
- Version count = 1 but created 2+ years ago (potentially hijacked)
- Name typosquatting a popular package

Score 0-100. Be conservative — a popular package can still be compromised.
Respond with ONLY valid JSON: {"score": N, "flags": ["flag"], "reasoning": "one paragraph"}`

export class EcosystemAnalyzer {
  private openrouter = new OpenRouterClient()

  async analyze(data: EcosystemData): Promise<EcosystemScore> {
    const cache = getLLMCache()
    const cacheKey = `trust:eco:${data.name}`

    const cached = cache.get(cacheKey) as EcosystemScore | null
    if (cached) return cached

    const prompt = `
Package: ${data.name}
Description: ${data.description}
License: ${data.license}
Repository: ${data.repository || 'none'}
Homepage: ${data.homepage || 'none'}
Keywords: ${data.keywords.join(', ') || 'none'}
Created: ${data.createdAt}
Age: ${this.computeAge(data.createdAt)}
Weekly downloads: ${data.weeklyDownloads.toLocaleString()}
Maintainers: ${data.maintainers}
Version count: ${data.versionCount}
Dependencies: ${Object.keys(data.dependencies).length}
Dev dependencies: ${Object.keys(data.devDependencies).length}
Has README: ${data.hasReadme}
Has changelog: ${data.hasChangelog}
Has contributing guide: ${data.hasContributing}
Has code of conduct: ${data.hasCodeOfConduct}

Score ecosystem trustworthiness.`

    const response = await this.openrouter.chat({
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
      maxTokens: 300,
      temperature: 0.1,
    })

    const result = this.parseResponse(response.content, data.name, response.model)

    if (response.stopReason !== 'error') {
      cache.set(cacheKey, result, response.model, response.usage.inputTokens + response.usage.outputTokens)
    }

    return result
  }

  private computeAge(createdAt: string): string {
    const created = new Date(createdAt).getTime()
    const days = Math.floor((Date.now() - created) / (1000 * 60 * 60 * 24))
    if (days < 30) return `${days} days`
    if (days < 365) return `${Math.floor(days / 30)} months`
    return `${Math.floor(days / 365)} years`
  }

  private parseResponse(raw: string, name: string, model: string): EcosystemScore {
    try {
      const clean = raw.replace(/```json|```/g, '').trim()
      const j = JSON.parse(clean)
      return {
        score: Math.min(100, Math.max(0, parseInt(String(j.score)) || 50)),
        flags: Array.isArray(j.flags) ? j.flags : [],
        reasoning: j.reasoning || `Ecosystem score for ${name}`,
      }
    } catch {
      return { score: 50, flags: [], reasoning: `Could not parse AI response for ${name}` }
    }
  }
}

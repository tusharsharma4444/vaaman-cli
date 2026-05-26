// @vaaman/trust-engine — Transparency Scoring
// Measures how well the package documents its behavior.
// Deterministic scoring based on documentation presence + AI for nuanced assessment.
//
// Key signals:
// - README explains what the package does
// - Lifecycle scripts are documented
// - Network access is documented
// - Filesystem access is documented
// - Changelog exists
// - License is clear

import type { PreScanResult } from '@vaaman/core'
import type { EcosystemData, TransparencyScore } from '../types.js'
import { OpenRouterClient } from '@vaaman/core'

export class TransparencyAnalyzer {
  private openrouter = new OpenRouterClient()

  async analyze(
    eco: EcosystemData,
    preScan: PreScanResult
  ): Promise<TransparencyScore> {
    const hidden: string[] = []
    const documented: string[] = []
    let score = 50 // neutral baseline

    // Deterministic checks
    if (eco.hasReadme) { score += 10; documented.push('Has README') }
    else { score -= 15; hidden.push('No README') }

    if (eco.license) { score += 5; documented.push(`Licensed: ${eco.license}`) }
    else { score -= 5; hidden.push('No license') }

    if (eco.repository) { score += 5; documented.push('Has repository') }
    else { score -= 5; hidden.push('No repository URL') }

    if (eco.hasChangelog) { score += 5; documented.push('Has changelog') }
    else { hidden.push('No changelog') }

    if (eco.hasContributing) { score += 3; documented.push('Has contributing guide') }

    // Lifecycle scripts transparency
    if (preScan.lifecycleScripts.length > 0) {
      const hasDocForScripts = eco.description.toLowerCase().includes('install') ||
        eco.description.toLowerCase().includes('setup')
      if (hasDocForScripts) {
        documented.push('Lifecycle scripts documented in README')
      } else {
        score -= 15
        const scripts = preScan.lifecycleScripts.map(s => s.name).join(', ')
        hidden.push(`Lifecycle scripts (${scripts}) not documented in README`)
      }
    } else {
      documented.push('No lifecycle scripts')
    }

    // Use AI for nuanced assessment of documentation quality
    if (hidden.length > 0) {
      const aiAssessment = await this.aiAssess(eco, hidden)
      // AI can adjust score up to ±15 based on context
      score += aiAssessment.adjustment
      hidden.push(...aiAssessment.additionalHidden)
      documented.push(...aiAssessment.additionalDocumented)
    }

    const finalScore = Math.min(100, Math.max(0, score))

    return {
      score: finalScore,
      hiddenBehaviors: hidden,
      documentedBehaviors: documented,
      reasoning: finalScore >= 70
        ? 'Well-documented package with clear transparency'
        : finalScore >= 40
          ? 'Moderate documentation — some gaps exist'
          : 'Poor documentation — significant transparency gaps',
    }
  }

  private async aiAssess(eco: EcosystemData, hidden: string[]): Promise<{
    adjustment: number
    additionalHidden: string[]
    additionalDocumented: string[]
  }> {
    try {
      const prompt = `
Package: ${eco.name}
Description: ${eco.description}
Documentation gaps: ${hidden.join('; ')}

Is this poor documentation a red flag or normal for this package type?
Respond with ONLY valid JSON:
{
  "adjustment": -15 to 15,
  "additionalHidden": ["any additional gaps"],
  "additionalDocumented": ["any documented behaviors we missed"]
}`

      const response = await this.openrouter.chat({
        messages: [{ role: 'user', content: prompt }],
        maxTokens: 200,
        temperature: 0.1,
      })

      if (response.stopReason === 'error') return { adjustment: 0, additionalHidden: [], additionalDocumented: [] }

      const j = JSON.parse(response.content.replace(/```json|```/g, '').trim())
      return {
        adjustment: Math.min(15, Math.max(-15, parseInt(String(j.adjustment)) || 0)),
        additionalHidden: Array.isArray(j.additionalHidden) ? j.additionalHidden : [],
        additionalDocumented: Array.isArray(j.additionalDocumented) ? j.additionalDocumented : [],
      }
    } catch {
      return { adjustment: 0, additionalHidden: [], additionalDocumented: [] }
    }
  }
}

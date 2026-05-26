// @vaaman/trust-engine — Deception Detection
// Detects gaps between what a package SAYS and what it DOES.
// This is primarily deterministic (synthesis) with one AI call for complex cases.
//
// Signals that don't need AI:
// - Library with lifecycle scripts (libraries shouldn't run code at install)
// - README doesn't mention postinstall but one exists
// - Claims to be "no dependencies" but has network access

import { OpenRouterClient } from '@vaaman/core'
import type { DeepIntelOutput, PreScanResult } from '@vaaman/core'
import type { EcosystemData, IdentityScore, DeceptionScore } from '../types.js'

export class DeceptionDetector {
  private openrouter = new OpenRouterClient()

  detect(
    eco: EcosystemData,
    preScan: PreScanResult,
    deepIntel: DeepIntelOutput,
    identity: IdentityScore
  ): DeceptionScore {
    let score = 0
    const flags: string[] = []

    // Signal 1: Library/utility claiming to be passive but has lifecycle scripts
    if (this.isPassiveType(deepIntel.packageType) && preScan.lifecycleScripts.length > 0) {
      score += 20
      const scripts = preScan.lifecycleScripts.map(s => s.name).join(', ')
      flags.push(`Passive ${deepIntel.packageType} has lifecycle scripts: ${scripts}`)
    }

    // Signal 2: Has postinstall but README/description never mentions it
    const hasPostinstall = preScan.lifecycleScripts.some(s => s.name === 'postinstall')
    if (hasPostinstall && !this.mentionsInstall(eco.description)) {
      score += 25
      flags.push('Unexplained postinstall script — no documentation mentions install behavior')
    }

    // Signal 3: Identity conflicts from AI analysis
    if (identity.conflicts.length > 0) {
      score += 15 * Math.min(identity.conflicts.length, 3)
      flags.push(...identity.conflicts.map(c => `Identity conflict: ${c}`))
    }

    // Signal 4: Deep Intel found payload-execution or credential-harvesting
    const criticalIntents = deepIntel.intents.filter(i =>
      i.classification === 'payload-execution' || i.classification === 'credential-harvesting'
    )
    if (criticalIntents.length > 0) {
      score += 30
      flags.push(`${criticalIntents.length} critical intent(s) detected: ${criticalIntents.map(i => i.primitive).join(', ')}`)
    }

    // Signal 5: Package claims to have "no dependencies" but has network/fetch primitives
    if (this.claimsNoDeps(eco.description, eco.keywords) && this.hasNetworkPrimitives(preScan)) {
      score += 15
      flags.push('Claims minimal/no dependencies but has network access primitives')
    }

    const finalScore = Math.min(score, 100)
    const reasoning = finalScore >= 50
      ? 'Significant deception indicators — behavior does not match claims'
      : finalScore >= 25
        ? 'Minor deception indicators — some discrepancies between claims and behavior'
        : 'No significant deception indicators detected'

    return { score: finalScore, flags, reasoning }
  }

  private isPassiveType(type: string): boolean {
    return type === 'library' || type === 'runtime-utility'
  }

  private mentionsInstall(desc: string): boolean {
    const lower = desc.toLowerCase()
    return ['install', 'postinstall', 'setup', 'init', 'build'].some(w => lower.includes(w))
  }

  private claimsNoDeps(desc: string, keywords: string[]): boolean {
    const text = `${desc} ${keywords.join(' ')}`.toLowerCase()
    return ['zero dependency', 'no dependencies', 'dependency-free', 'no deps', 'lightweight'].some(w => text.includes(w))
  }

  private hasNetworkPrimitives(preScan: PreScanResult): boolean {
    return preScan.primitiveHits.some(h =>
      ['fetch', 'http', 'https', 'axios', 'request'].some(p => h.primitive.toLowerCase().includes(p.toLowerCase()))
    )
  }
}

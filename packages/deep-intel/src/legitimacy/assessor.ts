// @vaaman/deep-intel — AI-native operational legitimacy assessor
// The final AI reasoning pass: given all classified + filtered primitives,
// behavioral chains, and the package type, determine whether this package
// operates within the bounds of legitimate behavior.
//
// This is where Vaaman's core differentiator emerges:
// "Does this software behave honestly and legitimately?"

import { OpenRouterClient } from '@vaaman/core'
import type { IntentClassification, PackageType, PreScanResult } from '@vaaman/core'
import type { LegitimacyResult } from '../types.js'

const SYSTEM_PROMPT = `You are a supply chain security analyst.
Your task: assess whether a package's behavior is LEGITIMATE for its stated purpose.

You receive:
1. The package type (what it claims to be)
2. A list of behavioral signals (primitives, chains, events) that survived suppression
3. Context about what a package of this type SHOULD be doing

Your reasoning process:
1. What capabilities does this package type legitimately need?
2. Do the observed signals match those legitimate needs?
3. Are there signals that EXCEED legitimate needs?
4. Is there a pattern of deception — claiming to be one thing but having capabilities of another?

CRITICAL: Never flag a signal as suspicious if it's normal for the package type.
- eval in a build tool = legitimate (code generation)
- child_process in a CLI tool = legitimate (spawning commands)
- network requests in an HTTP client = legitimate
- eval + fetch + child_process in a React date-picker library = highly suspicious

Respond with ONLY valid JSON. No preamble, no markdown fences:
{
  "score": 0-100,
  "verdict": "likely-legitimate" | "uncertain" | "likely-malicious",
  "reasoning": "one paragraph explaining the assessment",
  "capabilitiesNeeded": ["list of legitimate capabilities for this package type"],
  "signalsExceedingNeed": ["specific signals that go beyond legitimate use"] | null
}`

export class LegitimacyAssessor {
  private openrouter: OpenRouterClient

  constructor() {
    this.openrouter = new OpenRouterClient()
  }

  async assess(input: {
    packageName: string
    version: string
    packageType: PackageType
    intents: IntentClassification[]
    chains: PreScanResult['behavioralChains']
  }): Promise<LegitimacyResult> {
    const prompt = this.buildPrompt(input)
    const response = await this.openrouter.chat({
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
      maxTokens: 600,
      temperature: 0.1,
    })

    if (response.stopReason === 'error') {
      return {
        score: 50,
        verdict: 'uncertain',
        reasoning: `API error: ${response.content || 'unknown'}`,
        capabilitiesNeeded: [],
        signalsExceedingNeed: [],
      }
    }

    return this.parseResponse(response.content)
  }

  private buildPrompt(input: {
    packageName: string
    version: string
    packageType: PackageType
    intents: IntentClassification[]
    chains: PreScanResult['behavioralChains']
  }): string {
    const intentSummary = input.intents.slice(0, 30).map(i =>
      `  ${i.classification} (${i.confidence}%): ${i.primitive} in ${i.file}:${i.line} — ${i.reasoning}`
    ).join('\n')

    const chainSummary = input.chains.map(c =>
      `  ${c.name} (${c.severity}): ${c.description} — ${c.file}:${c.lineRange[0]}-${c.lineRange[1]}`
    ).join('\n')

    const classificationCounts = this.countClassifications(input.intents)

    return `Package: ${input.packageName}@${input.version}
Package type: ${input.packageType}

Intent classifications surviving suppression:
${intentSummary || '  none'}

Summary:
- Total signals: ${input.intents.length}
- compiler-utility: ${classificationCounts['compiler-utility'] || 0}
- framework-internal: ${classificationCounts['framework-internal'] || 0}
- operational-legitimate: ${classificationCounts['operational-legitimate'] || 0}
- suspicious-execution: ${classificationCounts['suspicious-execution'] || 0}
- payload-execution: ${classificationCounts['payload-execution'] || 0}
- credential-harvesting: ${classificationCounts['credential-harvesting'] || 0}

Behavioral chains detected:
${chainSummary || '  none'}

Assess the operational legitimacy of this ${input.packageType}.`
  }

  private countClassifications(intents: IntentClassification[]): Record<string, number> {
    const counts: Record<string, number> = {}
    for (const i of intents) {
      counts[i.classification] = (counts[i.classification] || 0) + 1
    }
    return counts
  }

  private parseResponse(raw: string): LegitimacyResult {
    try {
      const clean = raw.replace(/```json|```/g, '').trim()
      const parsed = JSON.parse(clean)
      return {
        score: Math.min(100, Math.max(0, parseInt(String(parsed.score)) || 50)),
        verdict: this.validateVerdict(parsed.verdict),
        reasoning: parsed.reasoning || 'Could not assess legitimacy',
        capabilitiesNeeded: Array.isArray(parsed.capabilitiesNeeded) ? parsed.capabilitiesNeeded : [],
        signalsExceedingNeed: Array.isArray(parsed.signalsExceedingNeed) ? parsed.signalsExceedingNeed : null,
      }
    } catch {
      return {
        score: 50,
        verdict: 'uncertain',
        reasoning: 'Could not parse AI legitimacy assessment',
        capabilitiesNeeded: [],
        signalsExceedingNeed: null,
      }
    }
  }

  private validateVerdict(raw: string | undefined): LegitimacyResult['verdict'] {
    const valid: LegitimacyResult['verdict'][] = ['likely-legitimate', 'uncertain', 'likely-malicious']
    return valid.includes(raw as LegitimacyResult['verdict']) ? (raw as LegitimacyResult['verdict']) : 'uncertain'
  }
}

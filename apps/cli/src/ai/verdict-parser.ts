// Vaaman AI — Verdict Parser
// Parses and validates LLM JSON output for the AI reasoner.
// Handles malformed JSON, markdown fences, partial extraction.

import type { AIVerdict, Verdict, IntentType } from '@vaaman/core'

export function parseVerdict(
  raw: string,
  model: string,
  latencyMs: number
): AIVerdict {
  let parsed: Record<string, unknown> | null = null

  // Strip markdown fences
  const clean = raw.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim()

  try {
    parsed = JSON.parse(clean)
  } catch {
    // Attempt partial extraction on malformed JSON
    parsed = extractFields(clean)
  }

  return validateVerdict(parsed ?? {}, model, latencyMs)
}

function extractFields(text: string): Record<string, unknown> {
  const extract = (field: string): string | null => {
    // Try "field": "value" pattern
    const strMatch = text.match(new RegExp(`"${field}"\\s*:\\s*"([^"]*)"`, 'i'))
    if (strMatch) return strMatch[1]

    // Try "field": value pattern (number)
    const numMatch = text.match(new RegExp(`"${field}"\\s*:\\s*(\\d+)`, 'i'))
    if (numMatch) return numMatch[1]

    return null
  }

  return {
    verdict: extract('verdict') ?? 'SUSPICIOUS',
    confidence: extract('confidence') ?? '0',
    summary: extract('summary') ?? 'AI response was malformed — rule-based fallback used.',
    whatItDid: [],
    whyItsDangerous: null,
    remediation: [],
    novelPatterns: null,
    intentClassification: extract('intentClassification') ?? 'suspicious-execution',
  }
}

function validateVerdict(
  raw: Record<string, unknown>,
  model: string,
  latencyMs: number
): AIVerdict {
  const verdict = validateVerdictField(raw.verdict as string)
  const confidence = Math.min(100, Math.max(0, parseInt(String(raw.confidence ?? '0')) || 0))

  return {
    verdict,
    confidence,
    summary: String(raw.summary || `AI analysis for this package`),
    whatItDid: Array.isArray(raw.whatItDid) ? raw.whatItDid.map(String) : [],
    whyItsDangerous: Array.isArray(raw.whyItsDangerous) ? raw.whyItsDangerous.map(String) : null,
    remediation: Array.isArray(raw.remediation) ? raw.remediation.map(String) : [],
    novelPatterns: Array.isArray(raw.novelPatterns) ? raw.novelPatterns.map(String) : null,
    intentClassification: validateIntent(raw.intentClassification as string),
    model,
    latencyMs,
    parseError: false,
  }
}

function validateVerdictField(raw: string | undefined): Verdict {
  const valid: Verdict[] = ['SAFE', 'SUSPICIOUS', 'DANGEROUS', 'CRITICAL']
  return valid.includes(raw as Verdict) ? (raw as Verdict) : 'SUSPICIOUS'
}

function validateIntent(raw: string | undefined): IntentType {
  const valid: IntentType[] = [
    'compiler-utility', 'framework-internal', 'operational-legitimate',
    'suspicious-execution', 'payload-execution', 'credential-harvesting',
  ]
  return valid.includes(raw as IntentType) ? (raw as IntentType) : 'suspicious-execution'
}

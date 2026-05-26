// Vaaman AI — Prompt Builder
// Builds structured prompts for the AI Reasoner from scan context.
// The prompt design is what makes Vaaman's AI reasoner produce grounded verdicts
// instead of generic LLM responses.

import type { PreScanResult, AIVerdict } from '@vaaman/core'

const SYSTEM_PROMPT = `You are a supply chain security analyst for Vaaman AI.
You receive behavioral telemetry and static scan findings from an npm package install.
You produce structured trust verdicts.

Your reasoning process:
1. Determine what type of package this claims to be (CLI, library, framework, build tool)
2. Assess what capabilities a LEGITIMATE package of that type should need
3. Compare observed signals against that legitimate baseline
4. Classify anomalies as suspicious ONLY when they exceed legitimate need
5. Score based on chains and intent — NEVER on isolated primitives

Critical legitimacy rules:
- eval in webpack/babel internals → compiler-utility, not malware
- fetch in a React component → framework-internal, not malicious
- child_process.exec in a CLI tool → operational-legitimate
- child_process.exec in a React hook → highly suspicious
- fetch → decode → eval in postinstall → payload-execution, near-certain malware

Never hallucinate. Base your verdict ONLY on provided evidence.
If evidence is ambiguous, lower your confidence score — do not inflate it.

Respond ONLY with valid JSON matching this schema. No preamble. No markdown fences:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS" | "CRITICAL",
  "confidence": 0-100,
  "summary": "one paragraph plain English explanation of what happened",
  "whatItDid": ["bullet point", "bullet point"],
  "whyItsDangerous": ["bullet point"] | null,
  "remediation": ["actionable step", "actionable step"],
  "novelPatterns": ["any new patterns not in known chains"] | null,
  "intentClassification": "compiler-utility" | "framework-internal" | "operational-legitimate" | "suspicious-execution" | "payload-execution" | "credential-harvesting"
}`

export function buildReasonerPrompt(input: {
  package: { name: string; version: string }
  preScan: PreScanResult | null
  events: { count: number; topEvents: string[] }
  chains: string[]
  installDurationMs: number
}): string {
  const lifecycleInfo = input.preScan?.lifecycleScripts?.length
    ? input.preScan.lifecycleScripts.map(s =>
        `  ${s.name}: ${s.content.slice(0, 100)} [${s.riskLevel}]`
      ).join('\n')
    : '  none'

  const primitiveInfo = input.preScan?.primitiveHits?.length
    ? input.preScan.primitiveHits.slice(0, 15).map(h =>
        `  ${h.file}:${h.line} — ${h.primitive}`
      ).join('\n')
    : '  none'

  const preScanScore = input.preScan?.score ?? 'N/A'
  const filesScanned = input.preScan?.filesScanned ?? 0

  return `Package: ${input.package.name}@${input.package.version}
Install duration: ${input.installDurationMs}ms

== PRE-SCAN ==
Score: ${preScanScore}/100
Files scanned: ${filesScanned}

Lifecycle scripts:
${lifecycleInfo}

Primitive hits (${input.preScan?.primitiveHits?.length ?? 0}):
${primitiveInfo}

== BEHAVIORAL EVENTS ==
Events monitored: ${input.events.count}
${input.events.topEvents.map(e => `  ${e}`).join('\n')}

== ATTACK CHAINS DETECTED ==
${input.chains.length === 0
  ? '  none'
  : input.chains.map(c => `  ${c}`).join('\n')}

Respond with JSON matching the exact schema specified.`
}

export { SYSTEM_PROMPT }

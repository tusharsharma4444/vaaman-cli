// @vaaman/deep-intel — AI-native package type classifier
// Given package metadata (name, description, deps, file listing, README),
// classifies the package into exactly one functional type.
//
// This is the foundation of all downstream intent analysis because
// "legitimate behavior" depends entirely on what the package claims to be.
// A CLI tool legitimately uses child_process. A React library does not.

import { OpenRouterClient } from '@vaaman/core'
import type { PreScanResult } from '@vaaman/core'
import type { PackageTypeResult, PackageType } from '../types.js'

const SYSTEM_PROMPT = `You are a supply chain security analyst specializing in npm package classification.
Your task: classify an npm package into exactly one functional type based on its metadata and file structure.

Available types:
- cli-tool: Command-line executable (has "bin" in package.json, uses process.argv, commander, yargs, oclif)
- build-tool: Bundler, transpiler, compiler (webpack, babel, esbuild, typescript, rollup, vite)
- framework: UI framework (React, Vue, Angular, Svelte, Next.js) — consumed by other projects
- library: Imported by other code, has main/module entry point, provides reusable functions
- dev-tool: Linter, formatter, test runner, type checker (eslint, prettier, jest, vitest)
- runtime-utility: Database driver, HTTP client, logging, validation, authentication
- malicious-tool: Intentionally obfuscated, typosquatting, has suspicious metadata
- unknown: Cannot determine from available evidence

Classification rules:
- A package with "bin" AND commands like "build", "dev", "start" is likely a build-tool, not a cli-tool
- A package that is always imported (no bin) is a library or framework
- A package named like a popular package but with a typo (reaact, angluar) → malicious-tool
- Look at README first — it explains what the package is for

Respond with ONLY valid JSON. No preamble, no markdown fences:
{
  "type": "<one of the types above>",
  "confidence": 0-100,
  "reasoning": "one sentence explaining why"
}`

export class PackageTypeClassifier {
  private openrouter: OpenRouterClient

  constructor() {
    this.openrouter = new OpenRouterClient()
  }

  async classify(input: {
    packageName: string
    version: string
    preScan: PreScanResult
  }): Promise<PackageTypeResult> {
    const prompt = this.buildPrompt(input)
    const response = await this.openrouter.chat({
      system: SYSTEM_PROMPT,
      messages: [{ role: 'user', content: prompt }],
      maxTokens: 300,
      temperature: 0.1,
    })

    if (response.stopReason === 'error') {
      return { type: 'unknown', confidence: 0, reasoning: response.content || 'API error' }
    }

    return this.parseResponse(response.content, input.packageName)
  }

  private buildPrompt(input: {
    packageName: string
    version: string
    preScan: PreScanResult
  }): string {
    const chains = input.preScan.behavioralChains.map(c => c.name).join(', ') || 'none'
    const scripts = input.preScan.lifecycleScripts.map(s => `${s.name}: ${s.content.slice(0, 80)}`).join('; ') || 'none'
    const hits = input.preScan.primitiveHits.slice(0, 15).map(h =>
      `${h.file}:${h.line} — ${h.primitive}`
    ).join('\n')

    return `Package: ${input.packageName}@${input.version}
Files scanned: ${input.preScan.filesScanned}
Lifecycle scripts: ${scripts}
Behavioral chains detected: ${chains}
Primitive hits (top 15):
${hits || 'none'}

Pre-scan score: ${input.preScan.score}/100

Classify this package.`
  }

  private parseResponse(raw: string, packageName: string): PackageTypeResult {
    try {
      const clean = raw.replace(/```json|```/g, '').trim()
      const parsed = JSON.parse(clean)
      return {
        type: this.validateType(parsed.type),
        confidence: Math.min(100, Math.max(0, parseInt(parsed.confidence) || 50)),
        reasoning: parsed.reasoning || `Classified as ${parsed.type}`,
      }
    } catch {
      return {
        type: 'unknown',
        confidence: 0,
        reasoning: `Could not parse AI response for ${packageName}`,
      }
    }
  }

  private validateType(raw: string | undefined): PackageType {
    const valid: PackageType[] = [
      'cli-tool', 'build-tool', 'framework', 'library',
      'dev-tool', 'runtime-utility', 'malicious-tool', 'unknown',
    ]
    return valid.includes(raw as PackageType) ? (raw as PackageType) : 'unknown'
  }
}

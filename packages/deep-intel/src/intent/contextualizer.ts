// @vaaman/deep-intel — AI-native primitive contextualizer
// The core intelligence layer: for each primitive hit from the AST scanner,
// classifies its INTENT in context.
//
// This is what the previous regex-based approach could NEVER do:
// - eval in webpack bootstrap = compiler-utility (not malware)
// - eval in postinstall script = suspicious-execution (possibly malware)
// - child_process.exec in CLI tool = operational-legitimate
// - child_process.exec in React component = highly suspicious
//
// Batching: groups up to 20 hits per API call to minimize latency and cost.

import { OpenRouterClient, getLLMCache } from '@vaaman/core'
import type { PreScanResult, IntentClassification, IntentType, PackageType } from '@vaaman/core'
import type { IntentBatchResult } from '../types.js'

const SYSTEM_PROMPT = `You are a supply chain security analyst.
Your task: classify the INTENT of each primitive hit found in a package's source code.

Intent types:
- compiler-utility: This primitive is part of a build tool, bundler, or compiler's internals (webpack, esbuild, babel, sucrase, etc.)
- framework-internal: This primitive is part of a UI framework's internal implementation (React, Vue, Angular, Next.js, etc.)
- operational-legitimate: This package legitimately needs this capability for its stated purpose (a CLI tool using child_process, a database driver using network)
- suspicious-execution: This primitive usage is not clearly legitimate — it may be malicious but could have a valid reason
- payload-execution: This looks like malicious code — remote fetch + decode + eval, obfuscated execution, or similar
- credential-harvesting: This code reads sensitive values (env vars, cookies, localStorage) and appears to exfiltrate them

Context clues that matter:
- Test files (__tests__, .test.ts, .spec.js) often have eval/Function for mocking — this is normal
- Webpack bundles contain eval for module loading — this is normal
- postinstall scripts with child_process.exec are highly suspicious
- fetch + eval in the same function is nearly always malicious
- process.env in a config file is normal; process.env + fetch in a postinstall is credential harvesting

For each primitive hit, output a JSON array with classification, confidence (0-100), reasoning, and legitimateUse.
Respond with ONLY valid JSON. No preamble, no markdown fences:
[
  {
    "file": "src/index.js",
    "line": 42,
    "primitive": "eval",
    "classification": "compiler-utility",
    "confidence": 85,
    "reasoning": "This is webpack's bootstrap module loader — normal for bundled output",
    "legitimateUse": "webpack module loading"
  }
]`

function chunk<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size))
  }
  return chunks
}

function buildCacheKey(packageName: string, version: string, packageType: PackageType, batchIndex: number, totalBatches: number): string {
  return `deep-intel:intent:${packageName}@${version}:${packageType}:batch${batchIndex}-${totalBatches}`
}

export class PrimitiveContextualizer {
  private openrouter: OpenRouterClient

  constructor() {
    this.openrouter = new OpenRouterClient()
  }

  async contextualize(input: {
    packageName: string
    version: string
    packageType: PackageType
    preScan: PreScanResult
  }): Promise<IntentBatchResult> {
    const hits = input.preScan.primitiveHits
    if (hits.length === 0) {
      return { classifications: [] }
    }

    const cache = getLLMCache()
    const BATCH_SIZE = 20
    const batches = chunk(hits, BATCH_SIZE)
    const allResults: IntentClassification[] = []

    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i]
      const cacheKey = buildCacheKey(input.packageName, input.version, input.packageType, i, batches.length)

      const cached = cache.get(cacheKey) as IntentClassification[] | null
      if (cached) {
        allResults.push(...cached)
        continue
      }

      const prompt = this.buildPrompt(batch, input.packageType, input.packageName)
      const response = await this.openrouter.chat({
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: prompt }],
        maxTokens: 2000,
        temperature: 0.1,
      })

      const classifications = this.parseBatchResponse(response.content, batch)

      if (response.stopReason !== 'error') {
        cache.set(cacheKey, classifications, response.model, response.usage.inputTokens + response.usage.outputTokens)
      }

      allResults.push(...classifications)
    }

    return { classifications: allResults }
  }

  private buildPrompt(batch: PreScanResult['primitiveHits'], packageType: PackageType, packageName: string): string {
    const packageContext = this.packageTypeContext(packageType)

    const hitsStr = batch.map(h => `
File: ${h.file}
Line: ${h.line}
Primitive: ${h.primitive}
Context: ${h.context || '(no context available)'}`).join('\n---\n')

    return `Package: ${packageName}
Package type: ${packageType}
${packageContext}

Primitive hits to classify:
${hitsStr}

For each hit, classify the intent. A ${packageType} ${this.legitimacyExpectation(packageType)}`
  }

  private packageTypeContext(type: PackageType): string {
    switch (type) {
      case 'cli-tool':
        return 'CLI tools legitimately use child_process, process.env, and filesystem operations.'
      case 'build-tool':
        return 'Build tools legitimately use eval (codegen), filesystem writes, and child_process (spawning compilers).'
      case 'framework':
        return 'Frameworks legitimately use eval (template compilation) and dynamic code loading. They should NOT use child_process.'
      case 'library':
        return 'Libraries should NOT use child_process or network requests. eval is suspect unless it is a code-generation library.'
      case 'dev-tool':
        return 'Dev tools legitimately spawn processes (linters, compilers) and read/write files.'
      case 'runtime-utility':
        return 'Runtime utilities may legitimately use network requests and filesystem operations. child_process is suspicious.'
      case 'malicious-tool':
        return 'This package already shows signs of being malicious. Treat each hit with heightened suspicion.'
      default:
        return 'Unknown package type — classify conservatively.'
    }
  }

  private legitimacyExpectation(type: PackageType): string {
    switch (type) {
      case 'cli-tool': return 'may legitimately need child_process, filesystem, and process.env access.'
      case 'build-tool': return 'may legitimately need eval and filesystem access for code generation.'
      case 'framework': return 'may legitimately need eval for template/JSX compilation, but not child_process.'
      case 'library': return 'should rarely need child_process, network, or eval. Most primitives should be operational-legitimate or framework-internal.'
      case 'dev-tool': return 'may legitimately need child_process and filesystem.'
      case 'runtime-utility': return 'may legitimately need network and filesystem, but not child_process typically.'
      case 'malicious-tool': return 'is already suspicious — every hit should be scrutinized.'
      default: return 'should be classified conservatively.'
    }
  }

  private parseBatchResponse(raw: string, batch: PreScanResult['primitiveHits']): IntentClassification[] {
    try {
      const clean = raw.replace(/```json|```/g, '').trim()
      const parsed = JSON.parse(clean)

      if (!Array.isArray(parsed)) {
        return this.fallbackClassifications(batch)
      }

      return parsed.map((item: Record<string, unknown>, idx: number) => {
        const original = batch[idx] ?? batch[batch.length - 1]
        return {
          file: (item.file as string) ?? original.file,
          line: (item.line as number) ?? original.line,
          primitive: (item.primitive as string) ?? original.primitive,
          classification: this.validateIntent(item.classification as string),
          confidence: Math.min(100, Math.max(0, parseInt(String(item.confidence)) || 50)),
          reasoning: (item.reasoning as string) || 'AI could not classify this hit',
          legitimateUse: (item.legitimateUse as string) || null,
        }
      })
    } catch {
      return this.fallbackClassifications(batch)
    }
  }

  private fallbackClassifications(hits: PreScanResult['primitiveHits']): IntentClassification[] {
    return hits.map(h => ({
      file: h.file,
      line: h.line,
      primitive: h.primitive,
      classification: 'suspicious-execution' as IntentType,
      confidence: 30,
      reasoning: 'AI classification failed — conservative default applied',
      legitimateUse: null,
    }))
  }

  private validateIntent(raw: string | undefined): IntentType {
    const valid: IntentType[] = [
      'compiler-utility', 'framework-internal', 'operational-legitimate',
      'suspicious-execution', 'payload-execution', 'credential-harvesting',
    ]
    return valid.includes(raw as IntentType) ? (raw as IntentType) : 'suspicious-execution'
  }
}

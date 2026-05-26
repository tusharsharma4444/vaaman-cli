// @vaaman/deep-intel — deterministic suppression engine
// Removes known-good false positives BEFORE they reach the AI legitimacy assessor.
// This is NOT AI — it's fast, deterministic pattern matching on file paths and code.
//
// Why deterministic: false positives from known-good patterns waste API calls
// and dilute the AI's attention. The LLM should focus on genuinely ambiguous cases.

import type { IntentClassification } from '@vaaman/core'
import type { SuppressionResult } from '../types.js'

interface SuppressionRule {
  id: string
  reason: string
  matches: (intent: IntentClassification) => boolean
}

const SUPPRESSION_RULES: SuppressionRule[] = [
  {
    id: 'test-file',
    reason: 'Test or spec file — mock code is expected',
    matches: (i) =>
      /\.(test|spec)\.(ts|js|tsx|jsx)$/i.test(i.file) ||
      i.file.includes('__tests__') ||
      i.file.includes('/test/') ||
      i.file.includes('/tests/'),
  },
  {
    id: 'build-output',
    reason: 'Build output or minified bundle',
    matches: (i) =>
      i.file.includes('/dist/') ||
      i.file.includes('/build/') ||
      i.file.includes('/out/') ||
      i.file.includes('.min.js'),
  },
  {
    id: 'node-modules-cache',
    reason: 'Build tool cache directory',
    matches: (i) =>
      i.file.includes('node_modules/.cache') ||
      i.file.includes('.parcel-cache'),
  },
  {
    id: 'fixture-data',
    reason: 'Test fixture or example data',
    matches: (i) =>
      i.file.includes('/fixtures/') ||
      i.file.includes('/__fixtures__/') ||
      i.file.includes('/examples/') ||
      i.file.includes('/mocks/'),
  },
  {
    id: 'webpack-bootstrap',
    reason: 'Webpack bootstrap module loader',
    matches: (i) =>
      i.primitive === 'eval' &&
      (i.file.includes('webpack') || i.file.includes('bootstrap')),
  },
  {
    id: 'typescript-declaration',
    reason: 'TypeScript type declaration file',
    matches: (i) =>
      i.file.endsWith('.d.ts') || i.file.endsWith('.d.mts'),
  },
  {
    id: 'config-file',
    reason: 'Configuration file — process.env access expected',
    matches: (i) =>
      i.primitive === 'process.env' &&
      /(config|configuration|env|setting)s?\.(ts|js|tsx|jsx)$/i.test(i.file),
  },
  {
    id: 'cli-commander',
    reason: 'CLI framework internals (commander, yargs, oclif)',
    matches: (i) =>
      (i.primitive === 'child_process.exec' || i.primitive.includes('child_process')) &&
      (i.file.includes('commander') || i.file.includes('yargs') || i.file.includes('oclif') || i.file.includes('cli')),
  },
  {
    id: 'generated-code',
    reason: 'Auto-generated code',
    matches: (i) =>
      i.file.includes('/generated/') ||
      i.file.includes('-generated.') ||
      i.file.includes('codegen'),
  },
  {
    id: 'benchmark',
    reason: 'Benchmark harness code',
    matches: (i) =>
      i.file.includes('/bench') ||
      i.file.includes('/benchmark') ||
      i.file.includes('/perf'),
  },
]

export class SuppressionEngine {
  apply(classifications: IntentClassification[]): SuppressionResult {
    const suppressed: IntentClassification[] = []
    const kept: IntentClassification[] = []

    for (const intent of classifications) {
      const matchingRule = SUPPRESSION_RULES.find(rule => rule.matches(intent))

      if (matchingRule) {
        suppressed.push({
          ...intent,
          classification: 'framework-internal',  // downgrade to safe
          confidence: 10,
          reasoning: `Suppressed: ${matchingRule.reason}`,
          legitimateUse: matchingRule.reason,
        })
      } else {
        kept.push(intent)
      }
    }

    return {
      intents: kept,
      suppressed,
      suppressedCount: suppressed.length,
    }
  }
}

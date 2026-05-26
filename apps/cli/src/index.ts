#!/usr/bin/env node
// Vaaman CLI entry point.
// Commands: pre-scan, deep-intel, trust, install

import { Command } from 'commander'
import * as fs from 'fs'
import * as path from 'path'
import { runInstall } from './runner.js'
import { preScan } from './prescan/index.js'
import { printPreScanSummary } from './prescan/index.js'
import { runDeepIntel } from '@vaaman/deep-intel'
import { runTrustEngine } from '@vaaman/trust-engine'
import { LLMReasoner, shouldUseLLM } from './ai/index.js'
import type { PreScanResult as CorePreScanResult, TrustScore } from '@vaaman/core'
import {
  printHeader,
  printReport,
  printError,
  printWarning,
} from './reporter.js'

// Bridge: convert prescan's internal result to the canonical core type
function adaptToCorePreScan(p: any): CorePreScanResult {
  return {
    package: p.package,
    version: p.version,
    resolvedAt: p.resolvedAt,
    score: p.preScanScore ?? 0,
    recommendation: p.recommendation ?? 'SAFE',
    scanTimeMs: p.scanDurationMs ?? 0,
    filesScanned: p.filesScanned ?? 0,
    tarbyteSizeBytes: 0,
    lifecycleScripts: p.lifecycleScripts ?? [],
    primitiveHits: p.primitiveHits ?? [],
    behavioralChains: (p.chains ?? []).map((c: any) => ({
      name: c.name,
      severity: c.severity,
      description: c.description,
      file: c.file,
      lineRange: [c.lineRange.start, c.lineRange.end] as [number, number],
      primitives: (c.hits ?? []).map((h: any) => ({
        primitive: h.primitive,
        line: h.line,
      })),
    })),
    summary: {
      totalPrimitiveHits: (p.primitiveHits ?? []).length,
      totalChains: (p.chains ?? []).length,
      dangerous: (p.primitiveHits ?? []).filter((h: any) => h.riskLevel === 'dangerous').length,
      suspicious: (p.primitiveHits ?? []).filter((h: any) => h.riskLevel === 'suspicious').length,
    },
  }
}

const program = new Command()

program
  .name('vaaman')
  .description('AI-native supply chain security — watches npm install for backdoor activity')
  .version('0.2.0')

// ─── pre-scan ──────────────────────────────────────────────────────────────

program
  .command('pre-scan <package>')
  .description('Run static pre-scan on a package without installing')
  .option('--json', 'Output raw JSON to stdout')
  .action(async (packageName, opts) => {
    try {
      const result = await preScan({ packageName })
      if (opts.json) {
        console.log(JSON.stringify(result))
      } else {
        printPreScanSummary(result)
      }
    } catch (err) {
      console.error('Pre-scan failed:', err)
      process.exit(1)
    }
  })

// ─── deep-intel ────────────────────────────────────────────────────────────

program
  .command('deep-intel <package>')
  .description('Run AI-powered deep intelligence analysis on a package')
  .option('--no-ai', 'Skip AI analysis, use deterministic rules only')
  .option('--json', 'Output raw JSON instead of formatted report')
  .action(async (packageName, opts) => {
    try {
      // Stage 1: Run pre-scan (always needed — provides primitives + chains)
      console.log(`\n  ▲ VAAMAN DEEP INTEL — ${packageName}`)
      console.log(`  ─${'─'.repeat(40)}`)
      console.log(`  [1/4] Running pre-scan...`)

      const rawPreScan = await preScan({ packageName })
      console.log(`  [1/4] Done. ${rawPreScan.filesScanned} files, score ${rawPreScan.preScanScore}/100`)

      if (opts.noAi) {
        // Deterministic-only mode: print pre-scan + chain analysis
        printPreScanSummary(rawPreScan)
        return
      }

      // Check for OpenRouter API key
      if (!process.env.OPENROUTER_API_KEY) {
        console.log(`\n  ⚠ OPENROUTER_API_KEY not set.`)
        console.log(`  Get a key at https://openrouter.ai/keys`)
        console.log(`  Falling back to deterministic pre-scan:\n`)
        printPreScanSummary(rawPreScan)
        return
      }

      // Stage 2-4: AI pipeline
      console.log(`  [2/4] Classifying package type via AI...`)
      const coreScan = adaptToCorePreScan(rawPreScan)
      const result = await runDeepIntel(coreScan)

      if (opts.json) {
        console.log(JSON.stringify(result, null, 2))
        return
      }

      // Formatted output
      printDeepIntelReport(result, coreScan)

    } catch (err) {
      console.error('Deep Intel analysis failed:', err)
      process.exit(1)
    }
  })

// ─── trust ─────────────────────────────────────────────────────────────────

program
  .command('trust <package>')
  .description('Run AI-powered trust scoring (deep intel + trust engine)')
  .option('--no-ai', 'Skip AI analysis, use deterministic rules only')
  .option('--json', 'Output raw JSON instead of formatted report')
  .action(async (packageName, opts) => {
    try {
      console.log(`\n  ▲ VAAMAN TRUST ENGINE — ${packageName}`)
      console.log(`  ─${'─'.repeat(40)}`)
      console.log(`  [1/5] Running pre-scan...`)

      const rawPreScan = await preScan({ packageName })
      console.log(`  [1/5] Done. ${rawPreScan.filesScanned} files, score ${rawPreScan.preScanScore}/100`)

      if (opts.noAi) {
        printPreScanSummary(rawPreScan)
        return
      }

      if (!process.env.OPENROUTER_API_KEY) {
        console.log(`\n  ⚠ OPENROUTER_API_KEY not set. Falling back to pre-scan.\n`)
        printPreScanSummary(rawPreScan)
        return
      }

      const coreScan = adaptToCorePreScan(rawPreScan)

      console.log(`  [2/5] Running Deep Intel analysis...`)
      const deepIntel = await runDeepIntel(coreScan)
      console.log(`  [2/5] Done. ${deepIntel.packageType}, legitimacy: ${deepIntel.legitimacyVerdict}`)

      console.log(`  [3/5] Fetching ecosystem data...`)
      console.log(`  [4/5] Computing trust dimensions...`)
      const trustResult = await runTrustEngine(coreScan, deepIntel)
      console.log(`  [5/5] Done. Trust grade: ${trustResult.trust.grade} (${trustResult.trust.overall}/100)`)

      if (opts.json) {
        console.log(JSON.stringify(trustResult, null, 2))
        return
      }

      printTrustReport(trustResult, coreScan)

    } catch (err) {
      console.error('Trust analysis failed:', err)
      process.exit(1)
    }
  })

// ─── install ───────────────────────────────────────────────────────────────

program
  .command('install [packages...]')
  .description('Run npm install with live behavioral monitoring')
  .option('--no-block', 'Do not block install on critical findings (warn only)')
  .option('--ai', 'Use AI-powered reasoning for verdict (requires OPENROUTER_API_KEY)')
  .option('--no-ai', 'Use rule-based reasoning only (default)')
  .option('--json', 'Output raw JSON instead of formatted report')
  .option('-v, --verbose', 'Show all monitored events, not just suspicious ones')
  .option('--interval <ms>', 'Monitor polling interval in milliseconds', '200')
  .option('--cwd <path>', 'Working directory for npm install', process.cwd())
  .action(async (packages: string[], opts) => {
    const cwd = path.resolve(opts.cwd)
    const block: boolean = opts.block !== false
    const verbose: boolean = !!opts.verbose
    const intervalMs = parseInt(opts.interval, 10)

    const npmArgs = packages.length > 0 ? packages : []

    printHeader(
      npmArgs.length > 0
        ? npmArgs.join(' ')
        : '(from package.json)'
    )

    if (process.platform !== 'linux') {
      printWarning(
        'Full monitoring requires Linux. ' +
        'On macOS/Windows, only process-level monitoring is available.'
      )
    }

    try {
      const { exitCode, scanResult } = await runInstall({
        args: npmArgs,
        cwd,
        block,
        verbose,
        intervalMs,
      })

      // If --json flag, output structured JSON and exit
      if (opts.json) {
        console.log(JSON.stringify({ verdict: scanResult.verdict, durationMs: scanResult.durationMs, totalEvents: scanResult.totalEvents, totalSignals: scanResult.totalSignals, signals: scanResult.signals, events: scanResult.events, blocked: scanResult.blocked }))
        process.exit(scanResult.blocked ? 1 : exitCode)
      }

      // If --ai flag and API key available, enhance with LLM reasoning
      if (opts.ai && process.env.OPENROUTER_API_KEY) {
        try {
          const pkgName = npmArgs[0] ?? 'unknown'
          console.log(`\n  ── AI Reasoning ──────────────────────`)

          // Run pre-scan for context
          let preScanCore: CorePreScanResult | null = null
          try {
            const rawPreScan = await preScan({ packageName: pkgName })
            preScanCore = adaptToCorePreScan(rawPreScan)
          } catch {
            // Pre-scan is optional — AI can reason without it
          }

          const events = scanResult.events || []
          const chains = [...new Set((scanResult.signals || []).flatMap((s: any) => s.chain || []))] as string[]

          const reasoner = new LLMReasoner()
          const aiVerdict = await reasoner.reason({
            package: { name: pkgName, version: 'latest' },
            preScan: preScanCore,
            events: {
              count: events.length,
              topEvents: events.slice(0, 15).map((e: any) =>
                `[${e.type}] ${e.message || e.description || ''}`
              ),
            },
            chains,
            installDurationMs: scanResult.durationMs ?? 0,
          })

          // Augment the report with AI verdict
          printReport(scanResult, aiVerdict)
        } catch {
          // AI failed, fall back to rule-based report
          printReport(scanResult)
        }
      } else {
        printReport(scanResult)
      }

      if (scanResult.blocked) {
        process.exit(1)
      } else {
        process.exit(exitCode)
      }

    } catch (err) {
      printError(err instanceof Error ? err.message : String(err))
      process.exit(1)
    }
  })

// Default
program
  .command('*', { hidden: true })
  .action(() => {
    program.help()
  })

if (process.argv.length < 3) {
  program.help()
}

program.parse(process.argv)

// ─── Deep Intel Report Printer ──────────────────────────────────────────────

function printDeepIntelReport(result: any, preScanResult: any): void {
  const c = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    green: '\x1b[32m',
    bold: '\x1b[1m',
    cyan: '\x1b[36m',
    magenta: '\x1b[35m',
    dim: '\x1b[2m',
  }

  console.log(`\n${c.bold}── Vaaman Deep Intel Report ───────────────${c.reset}`)
  console.log(`${c.cyan}Package:${c.reset}        ${result.package}@${result.version}`)
  console.log(`${c.cyan}Type:${c.reset}           ${result.packageType}`)
  console.log(`${c.cyan}Legitimacy:${c.reset}     ${legitimacyColor(result.legitimacyVerdict, c)}${result.legitimacyVerdict}${c.reset} (${result.legitimacyScore}/100)`)
  console.log(`${c.cyan}Signals:${c.reset}        ${result.intents.length} active, ${result.suppressedCount} suppressed`)
  console.log(`${c.cyan}AI latency:${c.reset}     ${result.latencyMs}ms`)
  console.log()

  if (result.reasoning) {
    console.log(`${c.bold}Assessment:${c.reset}`)
    console.log(`  ${result.reasoning}\n`)
  }

  if (result.intents.length > 0) {
    console.log(`${c.bold}Active Signals (${result.intents.length}):${c.reset}`)
    const byType: Record<string, any[]> = {}
    for (const intent of result.intents) {
      (byType[intent.classification] ??= []).push(intent)
    }

    const order = ['payload-execution', 'credential-harvesting', 'suspicious-execution', 'operational-legitimate', 'compiler-utility', 'framework-internal']
    for (const type of order) {
      const items = byType[type]
      if (!items || items.length === 0) continue
      const color = type === 'payload-execution' || type === 'credential-harvesting' ? c.red
        : type === 'suspicious-execution' ? c.yellow : c.green
      console.log(`  ${color}[${type}]${c.reset} — ${items.length} hit(s)`)
      for (const item of items.slice(0, 5)) {
        console.log(`    ${c.dim}${item.primitive} in ${item.file}:${item.line}${c.reset}`)
      }
    }
    console.log()
  }

  if (preScanResult.behavioralChains.length > 0) {
    console.log(`${c.bold}Behavioral Chains:${c.reset}`)
    for (const chain of preScanResult.behavioralChains) {
      const color = chain.severity === 'critical' || chain.severity === 'dangerous' ? c.red : c.yellow
      console.log(`  ${color}[${chain.severity.toUpperCase()}] ${chain.name}${c.reset}`)
    }
    console.log()
  }

  console.log(`${c.bold}────────────────────────────────────────────${c.reset}\n`)
}

function legitimacyColor(verdict: string, c: Record<string, string>): string {
  switch (verdict) {
    case 'likely-legitimate': return c.green
    case 'likely-malicious': return c.red
    default: return c.yellow
  }
}

// ─── Trust Report Printer ────────────────────────────────────────────────────

function printTrustReport(result: any, preScan: CorePreScanResult): void {
  const c = {
    reset: '\x1b[0m', red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m',
    bold: '\x1b[1m', cyan: '\x1b[36m', magenta: '\x1b[35m', dim: '\x1b[2m',
  }

  const t = result.trust
  const gradeColor = t.grade === 'A' || t.grade === 'B' ? c.green
    : t.grade === 'C' ? c.yellow : c.red

  console.log(`\n${c.bold}── Vaaman Trust Report ────────────────────${c.reset}`)
  console.log(`${c.cyan}Package:${c.reset}        ${result.package}@${result.version}`)
  console.log(`${c.cyan}Trust Grade:${c.reset}    ${gradeColor}${c.bold}${t.grade}${c.reset} — ${t.overall}/100`)
  console.log(`${c.cyan}AI latency:${c.reset}     ${result.latencyMs}ms`)
  console.log()

  console.log(`${c.bold}Score Breakdown:${c.reset}`)
  console.log(`  Ecosystem:     ${bar(t.breakdown.ecosystemScore, c)} ${t.breakdown.ecosystemScore}/100`)
  console.log(`  Identity:      ${bar(t.breakdown.identityScore, c)} ${t.breakdown.identityScore}/100`)
  console.log(`  Behavior:      ${bar(t.breakdown.behaviorScore, c)} ${t.breakdown.behaviorScore}/100`)
  console.log(`  Intent:        ${bar(t.breakdown.intentScore, c)} ${t.breakdown.intentScore}/100`)
  console.log(`  Deception:     ${bar(t.breakdown.deceptionScore, c)} ${t.breakdown.deceptionScore}/100 (high = bad)`)
  console.log(`  Transparency:  ${bar(t.breakdown.transparencyScore, c)} ${t.breakdown.transparencyScore}/100`)
  console.log()

  if (t.flags.length > 0) {
    console.log(`${c.bold}Flags (${t.flags.length}):${c.reset}`)
    for (const flag of t.flags.slice(0, 10)) {
      const color = flag.startsWith('[deception]') || flag.startsWith('[identity]') ? c.red
        : flag.startsWith('[capability]') || flag.startsWith('[eco]') ? c.yellow : c.dim
      console.log(`  ${color}▸${c.reset} ${flag}`)
    }
    console.log()
  }

  if (result.trust.overall >= 90) {
    console.log(`${c.green}✓ High trust — this package behaves as expected for its type.${c.reset}`)
  } else if (result.trust.overall >= 55) {
    console.log(`${c.yellow}⚡ Moderate trust — review the flags above before deploying.${c.reset}`)
  } else {
    console.log(`${c.red}✗ Low trust — significant concerns. Investigate before using.${c.reset}`)
  }

  console.log(`\n${c.bold}────────────────────────────────────────────${c.reset}\n`)
}

function bar(score: number, c: Record<string, string>): string {
  const filled = Math.round(score / 10)
  const empty = 10 - filled
  const color = score >= 70 ? c.green : score >= 40 ? c.yellow : c.red
  return `${color}${'█'.repeat(filled)}${c.dim}${'░'.repeat(empty)}${c.reset}`
}

// src/reporter.ts
// Beautiful, information-dense terminal output for Vaaman.
// Designed to be readable at a glance — security output should never be noisy.

import chalk from 'chalk'
import * as fs from 'fs'
import * as path from 'path'
import { fileURLToPath } from 'url'
import type { InstallResult, ThreatSignal, Severity, MonitorEvent, ThreatLevel } from './types.js'
import type { AIVerdict } from '@vaaman/core'

// ─── Theme ────────────────────────────────────────────────────────────────────

const theme = {
  brand: chalk.hex('#FF6B35'),
  dim: chalk.gray,
  critical: chalk.hex('#FF2D55').bold,
  dangerous: chalk.hex('#FF9500').bold,
  suspicious: chalk.hex('#FFD60A'),
  safe: chalk.hex('#30D158').bold,
  info: chalk.hex('#64D2FF'),
  muted: chalk.hex('#8E8E93'),
  bold: chalk.white.bold,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function severityIcon(severity: Severity): string {
  switch (severity) {
    case 'critical': return '🔴'
    case 'dangerous': return '🟠'
    case 'suspicious': return '🟡'
    case 'safe': return '🟢'
  }
}

function severityColor(severity: Severity) {
  switch (severity) {
    case 'critical': return theme.critical
    case 'dangerous': return theme.dangerous
    case 'suspicious': return theme.suspicious
    case 'safe': return theme.safe
  }
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function divider(char = '─', width = 60): string {
  return theme.muted(char.repeat(width))
}

// ─── JSON Save ────────────────────────────────────────────────────────────────

function saveInstallResultJson(result: InstallResult): string {
  const __dirname = path.dirname(fileURLToPath(import.meta.url))
  const jsonDir = path.resolve(__dirname, '../json')

  if (!fs.existsSync(jsonDir)) {
    fs.mkdirSync(jsonDir, { recursive: true })
  }

  const safeName = result.package.replace(/\//g, '+')
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
  const filename = `${safeName}-install-${timestamp}.json`
  const filePath = path.join(jsonDir, filename)

  fs.writeFileSync(filePath, JSON.stringify(result, null, 2), 'utf-8')
  console.log(theme.muted(`  result saved → ${filePath}`))
  console.log(theme.muted('  Use this file for post-mortem analysis or sharing with your security team.'))
  console.log(JSON.stringify(result, null, 2))

  return filePath
}

// ─── Live Event Printer ───────────────────────────────────────────────────────

export function printLiveEvent(event: MonitorEvent): void {
  const time = theme.muted(event.timestamp)

  const icons = {
    process: '⚙',
    network: '🌐',
    filesystem: '📁',
  }

  const icon = icons[event.type]
  const typeLabel = theme.info(event.type.padEnd(10))

  console.log(`  ${time} ${icon} ${typeLabel} ${event.message}`)
}

export function printLiveSignal(signal: ThreatSignal): void {
  // Map ThreatLevel to Severity for display
  const levelToSeverity: Record<ThreatLevel, Severity> = {
    clean: 'safe',
    suspicious: 'suspicious',
    dangerous: 'dangerous',
    critical: 'critical',
  };
  const severity = levelToSeverity[signal.level];
  const icon = severityIcon(severity);
  const color = severityColor(severity);
  console.log(`\n  ${icon} ${color(severity.toUpperCase())} — ${signal.reason}\n`);
}

// ─── Header ───────────────────────────────────────────────────────────────────

export function printHeader(packageName: string): void {
  console.log()
  console.log(theme.brand.bold('  ▲ VAAMAN') + theme.muted(' — supply chain monitor'))
  console.log(divider())
  console.log(theme.muted(`  Scanning: `) + theme.bold(packageName))
  console.log(theme.muted(`  Watching: processes · network · filesystem`))
  console.log(divider())
  console.log()
}

// ─── Install Output Wrappers ──────────────────────────────────────────────────

export function printInstallStart(): void {
  console.log(theme.muted('  ┌─ npm install output ') + theme.muted('─'.repeat(38)))
}

export function printInstallEnd(): void {
  console.log(theme.muted('  └─ end npm output ') + theme.muted('─'.repeat(41)))
  console.log()
}

// ─── Live Monitoring Header ───────────────────────────────────────────────────

export function printMonitoringStart(): void {
  console.log()
  console.log(theme.muted('  ┌─ monitoring ') + theme.muted('─'.repeat(45)))
}

export function printMonitoringEnd(): void {
  console.log(theme.muted('  └─ scan complete ') + theme.muted('─'.repeat(42)))
}

// ─── Final Report ─────────────────────────────────────────────────────────────

export function printReport(result: InstallResult, aiVerdict?: AIVerdict): void {
  console.log()
  console.log(divider('═'))
  console.log(theme.brand.bold('  VAAMAN SECURITY REPORT'))
  console.log(divider('═'))
  console.log()

  // Verdict — map Verdict string down to Severity for coloring
  const severityFromVerdict: Record<string, Severity> = {
    SAFE: 'safe',
    SUSPICIOUS: 'suspicious',
    DANGEROUS: 'dangerous',
    CRITICAL: 'critical',
    BLOCK: 'critical',
  }
  const sev = severityFromVerdict[result.verdict] ?? 'safe'
  const verdictColor = severityColor(sev)
  const verdictIcon = severityIcon(sev)

  console.log(`  Verdict  ${verdictIcon}  ${verdictColor(result.verdict)}`)
  console.log(`  Duration     ${formatDuration(result.durationMs)}`)
  console.log(`  Events       ${result.totalEvents} monitored`)
  console.log(`  Signals      ${result.totalSignals} found`)
  console.log()

  // AI verdict (if available)
  if (aiVerdict) {
    const aiColor = severityFromVerdict[aiVerdict.verdict]
      ? severityColor(severityFromVerdict[aiVerdict.verdict])
      : theme.info
    console.log(`  ${theme.bold('AI Verdict')}`)
    console.log(`  ${aiColor(aiVerdict.verdict)} (confidence: ${aiVerdict.confidence}%)`)
    console.log(`  ${theme.muted(aiVerdict.summary)}`)
    if (aiVerdict.whatItDid.length > 0) {
      console.log(`  What it did: ${aiVerdict.whatItDid.join('; ')}`)
    }
    if (aiVerdict.remediation.length > 0) {
      console.log(`  Remediation: ${aiVerdict.remediation.slice(0, 3).join('; ')}`)
    }
    console.log(`  ${theme.muted(`model: ${aiVerdict.model}, latency: ${aiVerdict.latencyMs}ms`)}`)
    console.log()
  }

  // Summary line
  console.log(`  ${theme.bold('Summary')}`)
  console.log(`  ${result.totalSignals} suspicious signal(s)`)
  console.log()

  // Threat signals
  if (result.signals.length > 0) {
    console.log(divider())
    console.log(`  ${theme.bold('Threat Signals')}`)
    console.log()

    const order: Severity[] = ['critical', 'dangerous', 'suspicious', 'safe']
    for (const level of order) {
      const levelSignals = result.signals.filter(s => s.severity === level)
      if (levelSignals.length === 0) continue

      for (const signal of levelSignals) {
        const icon = severityIcon(signal.severity)
        const color = severityColor(signal.severity)
        console.log(`  ${icon} ${color(signal.severity.padEnd(10))}  ${signal.message}`)

        if (signal.chain && signal.chain.length > 0) {
          console.log(`              ${theme.muted('chain: ' + signal.chain.join(' → '))}`)
        }
      }
      console.log()
    }
  }

  // Attack chains
  const chainSet = new Set(result.signals.flatMap(s => s.chain ?? []))
  if (chainSet.size > 0) {
    console.log(divider())
    console.log(`  ${theme.bold('Attack Chains Detected')}`)
    console.log()
    for (const chain of chainSet) {
      console.log(`  ${theme.critical('▸')} ${chain}`)
    }
    console.log()
  }

  // Events log (if there are any)
  if (result.events.length > 0) {
    console.log(divider())
    console.log(`  ${theme.bold('Event Log')}`)
    console.log()

    for (const event of result.events.slice(0, 20)) {
      const time = theme.muted(event.timestamp)
      const typeLabel = theme.info(`[${event.type}]`.padEnd(14))
      console.log(`  ${time} ${typeLabel} ${event.message}`)
    }

    if (result.events.length > 20) {
      console.log(theme.muted(`  ... and ${result.events.length - 20} more events`))
    }
    console.log()
  }

  // Footer verdict line
  console.log(divider('═'))
  switch (result.verdict) {
    case 'SAFE':
      console.log(theme.safe('  ✓ Install appears clean. No backdoor activity detected.'))
      break
    case 'SUSPICIOUS':
      console.log(theme.suspicious('  ⚠ Suspicious activity detected. Review signals above.'))
      break
    case 'DANGEROUS':
      console.log(theme.dangerous('  ✗ Dangerous behavior detected. Investigate before proceeding.'))
      break
    case 'CRITICAL':
    case 'BLOCK':
      console.log(theme.critical('  ✗ CRITICAL THREAT DETECTED. This install should not be trusted.'))
      break
  }
  console.log(divider('═'))
  console.log()

  // Save JSON — after all terminal output so the save line appears last
  const savedPath = saveInstallResultJson(result)
  console.log(theme.muted(`  result saved → ${savedPath}`))
  console.log()
}

// ─── Error / Warning ──────────────────────────────────────────────────────────

export function printError(msg: string): void {
  console.error(`\n  ${theme.critical('error')} ${msg}\n`)
}

export function printWarning(msg: string): void {
  console.warn(`\n  ${theme.suspicious('warn')} ${msg}\n`)
}
import { execSync } from 'child_process'
import { join, dirname } from 'path'
import { existsSync } from 'fs'
import { fileURLToPath } from 'url'
import { events } from '../services/events.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const CLI_ENTRY = join(__dirname, '..', '..', '..', '..', 'apps', 'cli', 'dist', 'index.js')

export interface PreScanResult {
  package: string
  version: string
  score: number
  filesScanned: number
  lifecycleScripts: { name: string; content: string; riskLevel: string }[]
  primitiveHits: { file: string; line: number; primitive: string; context: string; riskLevel: string }[]
  behavioralChains: { name: string; severity: string; description: string; file: string; lineRange: [number, number]; primitives: { primitive: string; line: number }[] }[]
  recommendation: string
  scanTimeMs: number
}

export async function runPreScan(packageName: string, scanId?: string): Promise<PreScanResult | null> {
  const emit = (stage: string, message: string) => {
    if (scanId) events.emitEvent('scan:progress', { scanId, stage, message, package: packageName })
  }

  try {
    if (!existsSync(CLI_ENTRY)) {
      emit('error', 'CLI binary not found')
      return null
    }

    emit('fetch', `Downloading tarball for ${packageName}...`)
    const cmd = `node "${CLI_ENTRY}" pre-scan "${packageName}" --json`
    const output = execSync(cmd, { timeout: 60000, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] })

    const jsonMatch = output.match(/\{[\s\S]*"package"[\s\S]*\}/)
    if (!jsonMatch) {
      emit('error', 'Could not parse scan output')
      return null
    }

    const raw = JSON.parse(jsonMatch[0])
    emit('scan', `Scanned ${raw.filesScanned ?? 0} files, score ${raw.preScanScore ?? raw.score ?? 0}/100`)

    return {
      package: raw.package,
      version: raw.version,
      score: raw.preScanScore ?? raw.score ?? 0,
      filesScanned: raw.filesScanned ?? 0,
      lifecycleScripts: raw.lifecycleScripts ?? [],
      primitiveHits: raw.primitiveHits ?? [],
      behavioralChains: (raw.chains ?? raw.behavioralChains ?? []).map((c: any) => ({
        name: c.name,
        severity: c.severity,
        description: c.description,
        file: c.file,
        lineRange: c.lineRange as [number, number],
        primitives: (c.hits ?? c.primitives ?? []).map((h: any) => ({
          primitive: h.primitive,
          line: h.line,
        })),
      })),
      recommendation: raw.recommendation ?? 'caution',
      scanTimeMs: raw.scanDurationMs ?? raw.scanTimeMs ?? 0,
    }
  } catch (err) {
    emit('error', `Scan failed: ${err}`)
    return null
  }
}

export async function runInstallScan(packageName: string): Promise<any | null> {
  try {
    if (!existsSync(CLI_ENTRY)) { console.error(`[scanner] CLI not found at ${CLI_ENTRY}`); return null }
    if (process.platform !== 'linux') { console.log(`[scanner] Behavioral monitoring requires Linux — skipping ${packageName}`); return null }
    const cmd = `node "${CLI_ENTRY}" install "${packageName}" --json`
    console.log(`[scanner] Running behavioral scan: ${packageName}`)
    const output = execSync(cmd, { timeout: 120000, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] })
    const match = output.match(/\{[\s\S]*"verdict"[\s\S]*\}/)
    if (!match) { console.error(`[scanner] ${packageName}: no JSON match in behavioral output`); return null }
    const result = JSON.parse(match[0])
    console.log(`[scanner] ${packageName}: ${result.totalSignals ?? 0} signals, verdict ${result.verdict}`)
    return result
  } catch (err) { console.error(`[scanner] Behavioral scan failed for ${packageName}: ${err}`); return null }
}

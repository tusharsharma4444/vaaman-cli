// Vaaman AI — Tool Executor
// Wires agent tool calls to actual Vaaman implementations.
// Agents call tools like run_prescan, run_behavioral, query_osv — this file executes them.
//
// Tools return reasoned data, not raw data. Each result includes:
//   data, confidence, flags, summary

import type { ToolResult } from '@vaaman/core'
import type { PreScanResult, InstallResult } from '@vaaman/core'

export interface ToolCallArgs {
  packageName?: string
  version?: string
  timeoutMs?: number
  ecosystem?: string
  cypher?: string
  params?: Record<string, unknown>
  findings?: unknown[]
}

export class ToolExecutor {
  // Callback functions — wired by the CLI to actual implementations
  private prescanFn: ((pkg: string, ver?: string) => Promise<PreScanResult>) | null = null
  private behavioralFn: ((pkg: string, ver?: string, timeout?: number) => Promise<InstallResult>) | null = null
  private osvFn: ((pkg: string, ecosystem?: string) => Promise<unknown[]>) | null = null
  private graphFn: ((cypher: string, params?: Record<string, unknown>) => Promise<unknown>) | null = null

  onPrescan(fn: (pkg: string, ver?: string) => Promise<PreScanResult>): this {
    this.prescanFn = fn
    return this
  }

  onBehavioral(fn: (pkg: string, ver?: string, timeout?: number) => Promise<InstallResult>): this {
    this.behavioralFn = fn
    return this
  }

  onOSV(fn: (pkg: string, ecosystem?: string) => Promise<unknown[]>): this {
    this.osvFn = fn
    return this
  }

  onGraph(fn: (cypher: string, params?: Record<string, unknown>) => Promise<unknown>): this {
    this.graphFn = fn
    return this
  }

  async execute(name: string, args: ToolCallArgs): Promise<ToolResult<unknown>> {
    switch (name) {
      case 'run_prescan':
        return this.runPrescan(args)
      case 'run_behavioral':
        return this.runBehavioral(args)
      case 'query_osv':
        return this.queryOSV(args)
      case 'query_graph':
        return this.queryGraph(args)
      case 'score_intent':
        // Intent scoring is handled by @vaaman/deep-intel — this tool is
        // used by swarm agents in Phase 5
        return {
          data: null,
          confidence: 0,
          flags: [],
          summary: 'Intent scoring requires @vaaman/deep-intel — available in swarm engine',
        }
      default:
        return {
          data: null,
          confidence: 0,
          flags: [],
          summary: `Unknown tool: ${name}`,
        }
    }
  }

  private async runPrescan(args: ToolCallArgs): Promise<ToolResult<PreScanResult | null>> {
    if (!this.prescanFn) {
      return { data: null, confidence: 0, flags: [], summary: 'Prescan not wired' }
    }
    if (!args.packageName) {
      return { data: null, confidence: 0, flags: [], summary: 'Missing packageName' }
    }

    try {
      const result = await this.prescanFn(args.packageName, args.version)
      return {
        data: result,
        confidence: 90,
        flags: result.behavioralChains.map(c => c.name),
        summary: `Prescan: ${result.filesScanned} files, score ${result.score}/100, ${result.behavioralChains.length} chains`,
      }
    } catch (err) {
      return { data: null, confidence: 0, flags: [], summary: `Prescan failed: ${err}` }
    }
  }

  private async runBehavioral(args: ToolCallArgs): Promise<ToolResult<InstallResult | null>> {
    if (!this.behavioralFn) {
      return { data: null, confidence: 0, flags: [], summary: 'Behavioral monitor not wired' }
    }
    if (!args.packageName) {
      return { data: null, confidence: 0, flags: [], summary: 'Missing packageName' }
    }

    try {
      const result = await this.behavioralFn(args.packageName, args.version, args.timeoutMs)
      return {
        data: result,
        confidence: 85,
        flags: result.signals.map(s => s.message),
        summary: `Behavioral: ${result.totalEvents} events, ${result.totalSignals} signals, verdict ${result.verdict}`,
      }
    } catch (err) {
      return { data: null, confidence: 0, flags: [], summary: `Behavioral scan failed: ${err}` }
    }
  }

  private async queryOSV(args: ToolCallArgs): Promise<ToolResult<unknown[]>> {
    if (!this.osvFn) {
      return { data: [], confidence: 0, flags: [], summary: 'OSV client not wired' }
    }
    if (!args.packageName) {
      return { data: [], confidence: 0, flags: [], summary: 'Missing packageName' }
    }

    try {
      const result = await this.osvFn(args.packageName, args.ecosystem ?? 'npm')
      const cves = result as Array<Record<string, unknown>>
      const highCount = cves.filter(c =>
        c.severity === 'HIGH' || c.severity === 'CRITICAL'
      ).length
      return {
        data: result,
        confidence: 95,
        flags: cves.map(c => c.id as string),
        summary: `OSV: ${cves.length} CVEs (${highCount} high/critical)`,
      }
    } catch (err) {
      return { data: [], confidence: 0, flags: [], summary: `OSV query failed: ${err}` }
    }
  }

  private async queryGraph(args: ToolCallArgs): Promise<ToolResult<unknown>> {
    if (!this.graphFn) {
      return { data: null, confidence: 0, flags: [], summary: 'Graph client not wired' }
    }
    if (!args.cypher) {
      return { data: null, confidence: 0, flags: [], summary: 'Missing cypher query' }
    }

    try {
      const result = await this.graphFn(args.cypher, args.params)
      return {
        data: result,
        confidence: 90,
        flags: [],
        summary: `Graph query executed`,
      }
    } catch (err) {
      return { data: null, confidence: 0, flags: [], summary: `Graph query failed: ${err}` }
    }
  }
}

// Singleton
let defaultExecutor: ToolExecutor | null = null

export function getToolExecutor(): ToolExecutor {
  if (!defaultExecutor) {
    defaultExecutor = new ToolExecutor()
  }
  return defaultExecutor
}

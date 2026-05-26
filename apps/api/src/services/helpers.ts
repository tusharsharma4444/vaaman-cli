// Vaaman API — Shared Helpers
// Reusable functions for the pipeline and routes

import type { PreScanResult } from '@vaaman/core'

let deepIntelModule: any = null
let trustModule: any = null

export async function importDeepIntel() {
  if (deepIntelModule) return deepIntelModule.runDeepIntel
  try { deepIntelModule = await import('@vaaman/deep-intel'); return deepIntelModule.runDeepIntel }
  catch { return null }
}

export async function importTrustEngine() {
  if (trustModule) return trustModule.runTrustEngine
  try { trustModule = await import('@vaaman/trust-engine'); return trustModule.runTrustEngine }
  catch { return null }
}

export function adaptToCore(p: any): PreScanResult {
  return {
    package: p.package,
    version: p.version,
    resolvedAt: new Date().toISOString(),
    score: p.score,
    recommendation: p.recommendation === 'proceed' ? 'SAFE' : p.recommendation === 'caution' ? 'SUSPICIOUS' : 'DANGEROUS',
    scanTimeMs: p.scanTimeMs,
    filesScanned: p.filesScanned,
    tarbyteSizeBytes: 0,
    lifecycleScripts: p.lifecycleScripts ?? [],
    primitiveHits: p.primitiveHits ?? [],
    behavioralChains: (p.behavioralChains ?? []).map((c: any) => ({
      name: c.name,
      severity: c.severity,
      description: c.description,
      file: c.file,
      lineRange: c.lineRange as [number, number],
      primitives: (c.primitives ?? []).map((h: any) => ({
        primitive: h.primitive,
        line: h.line,
      })),
    })),
    summary: {
      totalPrimitiveHits: (p.primitiveHits ?? []).length,
      totalChains: (p.behavioralChains ?? []).length,
      dangerous: (p.primitiveHits ?? []).filter((h: any) => h.riskLevel === 'dangerous').length,
      suspicious: (p.primitiveHits ?? []).filter((h: any) => h.riskLevel === 'suspicious').length,
    },
  }
}

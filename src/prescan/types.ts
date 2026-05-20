// ─────────────────────────────────────────────
// Vaaman AI — Pre-Scan Types
// ─────────────────────────────────────────────

export interface PreScanInput {
  packageName: string;
  version?: string; // defaults to 'latest'
}

export type RiskLevel = 'safe' | 'suspicious' | 'dangerous';
export type Recommendation = 'proceed' | 'caution' | 'block';

export interface LifecycleScript {
  name: string;       // e.g. 'postinstall', 'preinstall', 'install'
  content: string;    // raw script content
  riskLevel: RiskLevel;
  reasons: string[];  // why this risk level was assigned
}

export interface PrimitiveHit {
  file: string;       // relative path inside tarball
  line: number;
  column: number;
  primitive: string;  // e.g. 'eval', 'child_process.exec'
  context: string;    // surrounding code snippet (±2 lines)
  riskLevel: RiskLevel;
}

export interface PreScanResult {
  package: string;
  version: string;
  resolvedAt: string;           // ISO timestamp
  preScanScore: number;         // 0–100 (higher = more dangerous)
  filesScanned: number;
  lifecycleScripts: LifecycleScript[];
  primitiveHits: PrimitiveHit[];
  recommendation: Recommendation;
  scanDurationMs: number;
  error?: string;               // set if scan failed partially
}

// Internal tarball entry used by extractor
export interface TarballEntry {
  path: string;       // relative file path
  content: string;    // decoded utf-8 content
}

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DATA_DIR = join(__dirname, '..', '..', 'data')
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true })

const DB_PATH = join(DATA_DIR, 'vaaman.json')

interface ScanRecord {
  id: string
  package_name: string
  package_version: string
  status: 'pending' | 'running' | 'complete' | 'failed'
  verdict: string | null
  pre_scan_score: number
  pre_scan_json: string | null
  chains_json: string | null
  created_at: string
  completed_at: string | null
}

interface DBData {
  scans: ScanRecord[]
}

function load(): DBData {
  if (!existsSync(DB_PATH)) return { scans: [] }
  try {
    const raw = readFileSync(DB_PATH, 'utf-8')
    return JSON.parse(raw) as DBData
  } catch {
    return { scans: [] }
  }
}

function save(data: DBData): void {
  writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8')
}

let dbData = load()

function flush(): void {
  save(dbData)
}

export const db = {
  insert(id: string, name: string): void {
    dbData.scans.push({
      id,
      package_name: name,
      package_version: 'latest',
      status: 'running',
      verdict: null,
      pre_scan_score: 0,
      pre_scan_json: null,
      chains_json: null,
      created_at: new Date().toISOString(),
      completed_at: null,
    })
    flush()
  },

  updateComplete(id: string, verdict: string, version: string, score: number, preScanJson: string, chainsJson: string): void {
    const scan = dbData.scans.find(s => s.id === id)
    if (scan) {
      scan.status = 'complete'
      scan.verdict = verdict
      scan.package_version = version
      scan.pre_scan_score = score
      scan.pre_scan_json = preScanJson
      scan.chains_json = chainsJson
      scan.completed_at = new Date().toISOString()
      flush()
    }
  },

  updateFailed(id: string): void {
    const scan = dbData.scans.find(s => s.id === id)
    if (scan) {
      scan.status = 'failed'
      scan.completed_at = new Date().toISOString()
      flush()
    }
  },

  get(id: string): ScanRecord | null {
    dbData = load()
    return dbData.scans.find(s => s.id === id) ?? null
  },

  list(limit: number = 50): Array<{ id: string; package: string; verdict: string; preScanScore: number; createdAt: string }> {
    dbData = load()
    return dbData.scans
      .filter(s => s.status === 'complete' || s.status === 'failed')
      .sort((a, b) => b.created_at.localeCompare(a.created_at))
      .slice(0, limit)
      .map(s => ({
        id: s.id,
        package: s.package_name,
        verdict: s.verdict ?? 'UNKNOWN',
        preScanScore: s.pre_scan_score,
        createdAt: s.created_at,
      }))
  },
}

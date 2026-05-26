// @vaaman/core — LLM response cache
// JSON file-based cache stored at ~/.vaaman/cache/llm-cache.json
// Simple, zero dependencies, works on all platforms.
// Upgrade to SQLite when cache entries exceed ~1000.

import { homedir } from 'os'
import { join } from 'path'
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'fs'

function ensureCacheDir(): string {
  const dir = join(homedir(), '.vaaman', 'cache')
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
  return dir
}

function cacheFilePath(): string {
  return join(ensureCacheDir(), 'llm-cache.json')
}

interface CacheRecord {
  result: unknown
  model: string
  tokensUsed: number
  createdAt: string
  accessCount: number
}

interface CacheData {
  version: 1
  entries: Record<string, CacheRecord>
}

function loadCache(): CacheData {
  const path = cacheFilePath()
  if (!existsSync(path)) {
    return { version: 1, entries: {} }
  }
  try {
    const raw = readFileSync(path, 'utf-8')
    return JSON.parse(raw) as CacheData
  } catch {
    return { version: 1, entries: {} }
  }
}

function saveCache(data: CacheData): void {
  const path = cacheFilePath()
  writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8')
}

export interface CacheEntry {
  cacheKey: string
  result: unknown
  model: string
  tokensUsed: number
  createdAt: string
  accessCount: number
}

export class LLMCache {
  private data: CacheData
  private dirty: boolean = false
  private saveTimer: ReturnType<typeof setTimeout> | null = null

  constructor() {
    this.data = loadCache()
  }

  get(cacheKey: string): unknown | null {
    const entry = this.data.entries[cacheKey]
    if (!entry) return null

    entry.accessCount++
    this.markDirty()
    return entry.result
  }

  set(cacheKey: string, result: unknown, model: string, tokensUsed: number = 0): void {
    const existing = this.data.entries[cacheKey]
    this.data.entries[cacheKey] = {
      result,
      model,
      tokensUsed,
      createdAt: existing?.createdAt ?? new Date().toISOString(),
      accessCount: existing?.accessCount ?? 0,
    }
    this.markDirty()
  }

  has(cacheKey: string): boolean {
    return cacheKey in this.data.entries
  }

  stats(): { totalEntries: number; totalTokens: number } {
    const entries = Object.values(this.data.entries)
    return {
      totalEntries: entries.length,
      totalTokens: entries.reduce((sum, e) => sum + e.tokensUsed, 0),
    }
  }

  purge(): void {
    this.data.entries = {}
    this.markDirty()
    this.flush()
  }

  flush(): void {
    if (this.dirty) {
      saveCache(this.data)
      this.dirty = false
    }
  }

  private markDirty(): void {
    this.dirty = true
    if (this.saveTimer) clearTimeout(this.saveTimer)
    // Debounce saves by 5 seconds
    this.saveTimer = setTimeout(() => this.flush(), 5000)
  }
}

// Singleton
let defaultCache: LLMCache | null = null

export function getLLMCache(): LLMCache {
  if (!defaultCache) {
    defaultCache = new LLMCache()
  }
  return defaultCache
}

// @vaaman/trust-engine — Ecosystem Data Fetcher
// Fetches package metadata from npm registry API.
// No AI — pure deterministic HTTP fetch.

import type { EcosystemData } from './types.js'

export async function fetchEcosystemData(
  packageName: string,
  version: string
): Promise<EcosystemData> {
  const encoded = encodeURIComponent(packageName)
  const url = `https://registry.npmjs.org/${encoded}`

  try {
    const response = await fetch(url, {
      headers: { Accept: 'application/json' },
    })

    if (!response.ok) {
      return emptyEcosystemData(packageName, version)
    }

    const data = await response.json() as Record<string, unknown>
    const latestVersion = (data['dist-tags'] as Record<string, string>)?.latest ?? version
    const versionData = (data.versions as Record<string, Record<string, unknown>>)?.[latestVersion] ?? {}
    const time = data.time as Record<string, string> | undefined

    return {
      name: (data.name as string) ?? packageName,
      description: (data.description as string) ?? '',
      version: latestVersion,
      license: (versionData.license as string) || (data.license as string) || 'unknown',
      repository: typeof (versionData.repository as Record<string, unknown>)?.url === 'string'
        ? (versionData.repository as Record<string, string>).url
        : typeof (data.repository as Record<string, unknown>)?.url === 'string'
          ? (data.repository as Record<string, string>).url
          : null,
      homepage: (data.homepage as string) || null,
      keywords: Array.isArray(versionData.keywords) ? versionData.keywords as string[]
        : Array.isArray(data.keywords) ? data.keywords as string[] : [],
      maintainers: Array.isArray(data.maintainers) ? (data.maintainers as unknown[]).length : 1,
      createdAt: time?.created ?? new Date(0).toISOString(),
      weeklyDownloads: 0, // npm registry doesn't expose downloads directly here
      versionCount: Object.keys(data.versions as Record<string, unknown> ?? {}).length,
      dependencies: (versionData.dependencies as Record<string, string>) ?? {},
      devDependencies: (versionData.devDependencies as Record<string, string>) ?? {},
      hasReadme: typeof data.readme === 'string' && (data.readme as string).length > 0,
      hasChangelog: false,
      hasContributing: false,
      hasCodeOfConduct: false,
    }
  } catch {
    return emptyEcosystemData(packageName, version)
  }
}

function emptyEcosystemData(name: string, version: string): EcosystemData {
  return {
    name,
    description: '',
    version,
    license: 'unknown',
    repository: null,
    homepage: null,
    keywords: [],
    maintainers: 1,
    createdAt: new Date(0).toISOString(),
    weeklyDownloads: 0,
    versionCount: 0,
    dependencies: {},
    devDependencies: {},
    hasReadme: false,
    hasChangelog: false,
    hasContributing: false,
    hasCodeOfConduct: false,
  }
}

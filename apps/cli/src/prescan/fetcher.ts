// ─────────────────────────────────────────────
// Vaaman AI — Tarball Fetcher
// Downloads package tarball from npm registry
// ─────────────────────────────────────────────

const NPM_REGISTRY = 'https://registry.npmjs.org';

interface RegistryMetadata {
  version: string;
  tarballUrl: string;
}

/**
 * Resolves the exact version and tarball URL for a package.
 * Handles 'latest' and specific version strings.
 */
async function resolvePackageMetadata(
  packageName: string,
  version: string = 'latest'
): Promise<RegistryMetadata> {
  // Encode scoped packages e.g. @babel/core → %40babel%2Fcore
  const encodedName = encodeURIComponent(packageName).replace('%40', '@').replace('%2F', '%2F');

  const metaUrl = version === 'latest'
    ? `${NPM_REGISTRY}/${encodedName}/latest`
    : `${NPM_REGISTRY}/${encodedName}/${version}`;

  const res = await fetch(metaUrl);

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error(`Package not found: ${packageName}@${version}`);
    }
    throw new Error(`Registry error for ${packageName}@${version}: HTTP ${res.status}`);
  }

  const data = await res.json() as { version: string; dist: { tarball: string } };

  return {
    version: data.version,
    tarballUrl: data.dist.tarball,
  };
}

/**
 * Downloads the tarball and returns raw bytes (Buffer).
 * Does NOT write to disk — stays in memory.
 */
async function downloadTarball(tarballUrl: string): Promise<Buffer> {
  const res = await fetch(tarballUrl);

  if (!res.ok) {
    throw new Error(`Failed to download tarball from ${tarballUrl}: HTTP ${res.status}`);
  }

  const arrayBuffer = await res.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

/**
 * Main entry point for fetcher.
 * Returns resolved version, tarball URL, and raw tarball bytes.
 */
export async function fetchTarball(
  packageName: string,
  version?: string
): Promise<{ version: string; tarballUrl: string; tarballBuffer: Buffer }> {
  const metadata = await resolvePackageMetadata(packageName, version);
  const tarballBuffer = await downloadTarball(metadata.tarballUrl);

  return {
    version: metadata.version,
    tarballUrl: metadata.tarballUrl,
    tarballBuffer,
  };
}

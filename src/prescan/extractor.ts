// ─────────────────────────────────────────────
// Vaaman AI — In-Memory Tarball Extractor
// Extracts .tgz bytes into TarballEntry[]
// Never writes to disk.
// ─────────────────────────────────────────────

import { createGunzip } from 'zlib';
import { Readable } from 'stream';
import { extract } from 'tar-stream';
import type { TarballEntry } from './types.js';

// Files we care about scanning
const SCANNABLE_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.json']);

// Max file size to scan (5MB) — avoids loading huge minified bundles fully
const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024;

// Max total entries to extract — guard against malicious tarballs with thousands of files
const MAX_ENTRIES = 2000;

/**
 * Extracts a .tgz buffer in memory.
 * Returns an array of TarballEntry (path + utf-8 content).
 * Only extracts JS/TS/JSON files — skips images, binaries, etc.
 */
export async function extractTarball(tarballBuffer: Buffer): Promise<TarballEntry[]> {
  return new Promise((resolve, reject) => {
    const entries: TarballEntry[] = [];
    let entryCount = 0;

    const gunzip = createGunzip();
    const tarExtract = extract();

    tarExtract.on('entry', (header, stream, next) => {
      entryCount++;

      // Hard limit — malicious packages sometimes have absurd file counts
      if (entryCount > MAX_ENTRIES) {
        stream.resume(); // drain and skip
        return next();
      }

      const filePath = header.name
        .replace(/^package\//, '') // npm tarballs prefix everything with 'package/'
        .replace(/^\.\//, '');

      const ext = getExtension(filePath);
      const isDirectory = header.type === 'directory';
      const isTooLarge = (header.size ?? 0) > MAX_FILE_SIZE_BYTES;

      if (isDirectory || !SCANNABLE_EXTENSIONS.has(ext) || isTooLarge) {
        stream.resume(); // drain stream without reading
        return next();
      }

      const chunks: Buffer[] = [];

      stream.on('data', (chunk: Buffer) => chunks.push(chunk));

      stream.on('end', () => {
        try {
          const content = Buffer.concat(chunks).toString('utf-8');
          entries.push({ path: filePath, content });
        } catch {
          // If content isn't valid utf-8, skip silently
        }
        next();
      });

      stream.on('error', (err) => {
        // Non-fatal: log and continue
        console.error(`[extractor] Error reading ${filePath}: ${err.message}`);
        next();
      });
    });

    tarExtract.on('finish', () => resolve(entries));
    tarExtract.on('error', reject);
    gunzip.on('error', reject);

    // Pipe: buffer → gunzip → tar extract
    const readable = Readable.from(tarballBuffer);
    readable.pipe(gunzip).pipe(tarExtract);
  });
}

function getExtension(filePath: string): string {
  const lastDot = filePath.lastIndexOf('.');
  if (lastDot === -1) return '';
  return filePath.slice(lastDot).toLowerCase();
}

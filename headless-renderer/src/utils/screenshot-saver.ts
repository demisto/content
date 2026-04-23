/**
 * Handles saving PNG screenshots to disk.
 * Creates batch-specific directories and generates filenames from URLs.
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createChildLogger } from './logger.js';
import { config } from '../config.js';

const log = createChildLogger('screenshot-saver');

/**
 * Sanitize a URL into a safe filename.
 * Strips protocol, replaces special chars with underscores, truncates to 200 chars.
 */
export function urlToFilename(url: string): string {
  return url
    .replace(/^https?:\/\//, '')
    .replace(/[^a-zA-Z0-9.-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '')
    .slice(0, 200);
}

/**
 * Ensure the batch screenshot directory exists.
 */
export async function ensureBatchDir(batchId: string): Promise<string> {
  const batchDir = join(config.screenshotDir, `batch-${batchId}`);
  await mkdir(batchDir, { recursive: true });
  log.debug({ batchDir }, 'Created batch directory');
  return batchDir;
}

/**
 * Save a screenshot buffer to disk.
 * Returns the relative path to the saved file.
 */
export async function saveScreenshot(
  buffer: Buffer,
  batchId: string,
  url: string,
): Promise<string> {
  const batchDir = join(config.screenshotDir, `batch-${batchId}`);
  const filename = `${urlToFilename(url)}.png`;
  const filepath = join(batchDir, filename);

  await writeFile(filepath, buffer);
  log.debug({ filepath, size: buffer.length }, 'Screenshot saved');

  // Return the path relative to the screenshot root
  return join(`batch-${batchId}`, filename);
}

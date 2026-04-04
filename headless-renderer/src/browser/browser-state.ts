/**
 * Browser state file management for persistent browser support.
 *
 * Manages a JSON state file that stores the WebSocket endpoint, PID,
 * and launch settings of a running browser server. This allows
 * subsequent CLI runs to reconnect to an existing browser process.
 *
 * Uses atomic writes (write to temp file then rename) to prevent
 * corruption when multiple CLI instances run simultaneously.
 */

import { writeFile, readFile, unlink, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createChildLogger } from '../utils/logger.js';

const log = createChildLogger('browser-state');

export interface BrowserState {
  /** WebSocket endpoint URL for reconnecting to the browser server */
  wsEndpoint: string;
  /** Process ID of the browser server */
  pid: number;
  /** ISO 8601 timestamp of when the browser was launched */
  launchedAt: string;
  /** Chrome launch arguments used when the browser was started */
  chromeLaunchArgs: string[];
  /** Playwright version used to launch the browser */
  version: string;
}

/**
 * Save browser state to disk using an atomic write.
 * Writes to a temporary file first, then renames to the target path.
 */
export async function saveState(stateFilePath: string, state: BrowserState): Promise<void> {
  const tempPath = join(dirname(stateFilePath), `.render-cli-browser-${randomUUID()}.tmp`);
  const json = JSON.stringify(state, null, 2);

  try {
    await writeFile(tempPath, json, 'utf-8');
    await rename(tempPath, stateFilePath);
    log.debug({ stateFilePath, pid: state.pid }, 'Browser state saved');
  } catch (err) {
    // Clean up temp file on failure
    try {
      await unlink(tempPath);
    } catch {
      // Ignore cleanup errors
    }
    throw err;
  }
}

/**
 * Load browser state from disk.
 * Returns `null` if the state file does not exist or is invalid JSON.
 */
export async function loadState(stateFilePath: string): Promise<BrowserState | null> {
  try {
    const raw = await readFile(stateFilePath, 'utf-8');
    const parsed = JSON.parse(raw) as BrowserState;

    // Basic validation
    if (!parsed.wsEndpoint || typeof parsed.pid !== 'number') {
      log.warn({ stateFilePath }, 'State file has invalid structure — ignoring');
      return null;
    }

    log.debug({ stateFilePath, pid: parsed.pid }, 'Browser state loaded');
    return parsed;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      log.debug({ stateFilePath }, 'No state file found');
      return null;
    }
    log.warn({ err, stateFilePath }, 'Failed to read state file — ignoring');
    return null;
  }
}

/**
 * Delete the browser state file from disk.
 * Silently ignores if the file does not exist.
 */
export async function deleteState(stateFilePath: string): Promise<void> {
  try {
    await unlink(stateFilePath);
    log.debug({ stateFilePath }, 'Browser state file deleted');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
      log.warn({ err, stateFilePath }, 'Failed to delete state file');
    }
  }
}

/**
 * Check if a process with the given PID is still alive.
 * Uses `process.kill(pid, 0)` which sends no signal but checks existence.
 */
export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Compare two sets of Chrome launch arguments to detect settings changes.
 * Returns `true` if the arguments differ (order-insensitive).
 */
export function settingsChanged(current: string[], saved: string[]): boolean {
  if (current.length !== saved.length) return true;

  const sortedCurrent = [...current].sort();
  const sortedSaved = [...saved].sort();

  return sortedCurrent.some((arg, i) => arg !== sortedSaved[i]);
}

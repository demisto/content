/**
 * Management commands for the headless-renderer CLI.
 *
 * These commands handle browser lifecycle operations that don't
 * process batches — e.g., killing a persistent browser or
 * querying its status.
 */

import { loadState, deleteState, isProcessAlive } from '../browser/browser-state.js';
import { createChildLogger } from '../utils/logger.js';

const log = createChildLogger('commands');

/**
 * Kill a persistent browser process.
 *
 * Reads the state file, sends SIGTERM to the browser PID,
 * deletes the state file, and exits with code 0.
 * If no browser is running, prints a message and exits with code 0.
 */
export async function handleKillBrowser(stateFilePath: string): Promise<void> {
  const state = await loadState(stateFilePath);

  if (!state) {
    process.stderr.write('No persistent browser found (no state file).\n');
    return;
  }

  if (!isProcessAlive(state.pid)) {
    process.stderr.write(`Browser process (PID ${state.pid}) is not running. Cleaning up state file.\n`);
    await deleteState(stateFilePath);
    return;
  }

  try {
    log.info({ pid: state.pid }, 'Killing browser process');
    process.kill(state.pid, 'SIGTERM');
    process.stderr.write(`Browser process (PID ${state.pid}) killed.\n`);
  } catch (err) {
    log.warn({ err, pid: state.pid }, 'Failed to kill browser process');
    process.stderr.write(`Failed to kill browser process (PID ${state.pid}): ${err instanceof Error ? err.message : String(err)}\n`);
  }

  await deleteState(stateFilePath);
}

/**
 * Output the status of a persistent browser as JSON to stdout.
 *
 * Reads the state file, checks if the PID is alive, and outputs
 * a JSON status object. Exits with code 0 regardless.
 */
export async function handleBrowserStatus(stateFilePath: string): Promise<void> {
  const state = await loadState(stateFilePath);

  if (!state) {
    const status = {
      running: false,
      message: 'No persistent browser found (no state file)',
    };
    process.stdout.write(JSON.stringify(status, null, 2) + '\n');
    return;
  }

  const alive = isProcessAlive(state.pid);

  const status = {
    running: alive,
    pid: state.pid,
    wsEndpoint: state.wsEndpoint,
    launchedAt: state.launchedAt,
    chromeLaunchArgs: state.chromeLaunchArgs,
    playwrightVersion: state.version,
    message: alive
      ? `Browser is running (PID ${state.pid})`
      : `Browser process (PID ${state.pid}) is not running (stale state file)`,
  };

  process.stdout.write(JSON.stringify(status, null, 2) + '\n');

  // Clean up stale state file
  if (!alive) {
    await deleteState(stateFilePath);
  }
}

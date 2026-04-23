/**
 * Unit tests for browser state file management.
 * Tests save/load/delete operations, PID checking, and settings comparison.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFile, unlink, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';
import {
  saveState,
  loadState,
  deleteState,
  isProcessAlive,
  settingsChanged,
  type BrowserState,
} from '../../src/browser/browser-state.js';

function makeTempPath(): string {
  return join(tmpdir(), `test-browser-state-${randomUUID()}.json`);
}

function makeSampleState(overrides?: Partial<BrowserState>): BrowserState {
  return {
    wsEndpoint: 'ws://127.0.0.1:12345/abc',
    pid: process.pid,
    launchedAt: new Date().toISOString(),
    chromeLaunchArgs: ['--disable-gpu', '--no-first-run'],
    version: '1.52.0',
    ...overrides,
  };
}

describe('browser-state', () => {
  const tempFiles: string[] = [];

  afterEach(async () => {
    // Clean up temp files
    for (const f of tempFiles) {
      try {
        await unlink(f);
      } catch {
        // Ignore
      }
    }
    tempFiles.length = 0;
  });

  describe('saveState', () => {
    it('should write state to a JSON file', async () => {
      const path = makeTempPath();
      tempFiles.push(path);
      const state = makeSampleState();

      await saveState(path, state);

      const raw = await readFile(path, 'utf-8');
      const parsed = JSON.parse(raw);
      expect(parsed.wsEndpoint).toBe(state.wsEndpoint);
      expect(parsed.pid).toBe(state.pid);
      expect(parsed.chromeLaunchArgs).toEqual(state.chromeLaunchArgs);
      expect(parsed.version).toBe(state.version);
    });

    it('should overwrite an existing state file', async () => {
      const path = makeTempPath();
      tempFiles.push(path);

      const state1 = makeSampleState({ wsEndpoint: 'ws://first' });
      const state2 = makeSampleState({ wsEndpoint: 'ws://second' });

      await saveState(path, state1);
      await saveState(path, state2);

      const raw = await readFile(path, 'utf-8');
      const parsed = JSON.parse(raw);
      expect(parsed.wsEndpoint).toBe('ws://second');
    });
  });

  describe('loadState', () => {
    it('should load state from a valid JSON file', async () => {
      const path = makeTempPath();
      tempFiles.push(path);
      const state = makeSampleState();

      await saveState(path, state);
      const loaded = await loadState(path);

      expect(loaded).not.toBeNull();
      expect(loaded!.wsEndpoint).toBe(state.wsEndpoint);
      expect(loaded!.pid).toBe(state.pid);
      expect(loaded!.chromeLaunchArgs).toEqual(state.chromeLaunchArgs);
    });

    it('should return null if the file does not exist', async () => {
      const path = makeTempPath();
      // Don't create the file
      const loaded = await loadState(path);
      expect(loaded).toBeNull();
    });

    it('should return null if the file contains invalid JSON', async () => {
      const path = makeTempPath();
      tempFiles.push(path);
      await writeFile(path, 'not valid json!!!', 'utf-8');

      const loaded = await loadState(path);
      expect(loaded).toBeNull();
    });

    it('should return null if the file is missing required fields', async () => {
      const path = makeTempPath();
      tempFiles.push(path);
      await writeFile(path, JSON.stringify({ foo: 'bar' }), 'utf-8');

      const loaded = await loadState(path);
      expect(loaded).toBeNull();
    });
  });

  describe('deleteState', () => {
    it('should delete an existing state file', async () => {
      const path = makeTempPath();
      const state = makeSampleState();
      await saveState(path, state);

      await deleteState(path);

      const loaded = await loadState(path);
      expect(loaded).toBeNull();
    });

    it('should not throw if the file does not exist', async () => {
      const path = makeTempPath();
      // Should not throw
      await expect(deleteState(path)).resolves.toBeUndefined();
    });
  });

  describe('isProcessAlive', () => {
    it('should return true for the current process PID', () => {
      expect(isProcessAlive(process.pid)).toBe(true);
    });

    it('should return false for a non-existent PID', () => {
      // Use a very high PID that is extremely unlikely to exist
      expect(isProcessAlive(999999999)).toBe(false);
    });
  });

  describe('settingsChanged', () => {
    it('should return false for identical args', () => {
      const args = ['--disable-gpu', '--no-first-run'];
      expect(settingsChanged(args, [...args])).toBe(false);
    });

    it('should return false for same args in different order', () => {
      const current = ['--no-first-run', '--disable-gpu'];
      const saved = ['--disable-gpu', '--no-first-run'];
      expect(settingsChanged(current, saved)).toBe(false);
    });

    it('should return true when args differ', () => {
      const current = ['--disable-gpu', '--no-first-run'];
      const saved = ['--disable-gpu', '--headless'];
      expect(settingsChanged(current, saved)).toBe(true);
    });

    it('should return true when arg count differs', () => {
      const current = ['--disable-gpu'];
      const saved = ['--disable-gpu', '--no-first-run'];
      expect(settingsChanged(current, saved)).toBe(true);
    });

    it('should return false for empty arrays', () => {
      expect(settingsChanged([], [])).toBe(false);
    });
  });
});

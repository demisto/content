/**
 * Browser lifecycle manager with persistent browser support.
 *
 * In persist mode (default), uses `chromium.launchServer()` to create a
 * detached browser server that outlives the CLI process. The WebSocket
 * endpoint and PID are saved to a state file so subsequent CLI runs can
 * reconnect via `chromium.connect(wsEndpoint)`.
 *
 * In no-persist mode, uses `chromium.launch()` as before — the browser
 * is closed when the CLI exits.
 */

import { chromium, type Browser, type BrowserServer } from 'playwright';
import { createChildLogger } from '../utils/logger.js';
import { config } from '../config.js';
import {
  saveState,
  loadState,
  deleteState,
  isProcessAlive,
  settingsChanged,
  type BrowserState,
} from './browser-state.js';

const log = createChildLogger('browser-manager');

export interface BrowserHealth {
  isRunning: boolean;
  pid: number | null;
  uptime: number;
  contextsCreated: number;
}

export interface BrowserManagerOptions {
  /** Path to the state file for persistent browser */
  stateFilePath: string;
  /** Whether to persist the browser between CLI runs */
  persist: boolean;
}

export class BrowserManager {
  private browser: Browser | null = null;
  private browserServer: BrowserServer | null = null;
  private browserPid: number | null = null;
  private launchedAt: number | null = null;
  private contextsCreated = 0;
  private restartCount = 0;
  private browserReused = false;

  private readonly stateFilePath: string;
  private readonly persist: boolean;

  constructor(options?: BrowserManagerOptions) {
    this.stateFilePath = options?.stateFilePath ?? '/tmp/render-cli-browser.json';
    this.persist = options?.persist ?? true;
  }

  /**
   * Whether the current browser instance was reused from a previous CLI run.
   */
  wasBrowserReused(): boolean {
    return this.browserReused;
  }

  /**
   * Ensure the browser is running.
   *
   * In persist mode:
   *   1. Try to load state from the state file
   *   2. If state exists, PID is alive, and settings match → reconnect
   *   3. If connection fails or settings changed → kill old, launch new server
   *   4. If no state file → launch new server
   *
   * In no-persist mode:
   *   Just launch a browser directly (no server, no state file).
   */
  async ensureBrowser(): Promise<{ browser: Browser; restarted: boolean }> {
    // If we already have a connected browser, reuse it
    if (this.browser?.isConnected()) {
      return { browser: this.browser, restarted: false };
    }

    if (this.persist) {
      return this.ensurePersistentBrowser();
    }

    // No-persist mode: simple launch
    const browser = await this.launchDirect();
    return { browser, restarted: false };
  }

  /**
   * Ensure a persistent browser is available, reconnecting or launching as needed.
   */
  private async ensurePersistentBrowser(): Promise<{ browser: Browser; restarted: boolean }> {
    const state = await loadState(this.stateFilePath);

    if (state) {
      // State file exists — try to reconnect
      if (!isProcessAlive(state.pid)) {
        log.info({ pid: state.pid }, 'Browser process is dead — launching new server');
        await deleteState(this.stateFilePath);
        const browser = await this.launchServerAndConnect();
        return { browser, restarted: true };
      }

      if (settingsChanged(config.chromeLaunchArgs as unknown as string[], state.chromeLaunchArgs)) {
        log.info('Chrome launch args changed — restarting browser');
        await this.killProcess(state.pid);
        await deleteState(this.stateFilePath);
        const browser = await this.launchServerAndConnect();
        return { browser, restarted: true };
      }

      // Try to connect to the existing server
      try {
        const browser = await this.connectToServer(state);
        this.browserReused = true;
        log.info({ pid: state.pid }, 'Reconnected to existing browser server');
        return { browser, restarted: false };
      } catch (err) {
        log.warn({ err, pid: state.pid }, 'Failed to reconnect — launching new server');
        await this.killProcess(state.pid);
        await deleteState(this.stateFilePath);
        const browser = await this.launchServerAndConnect();
        return { browser, restarted: true };
      }
    }

    // No state file — launch a new server
    log.info('No existing browser server — launching new one');
    const browser = await this.launchServerAndConnect();
    return { browser, restarted: false };
  }

  /**
   * Launch a browser server and connect to it.
   * Saves the server state to the state file.
   */
  async launchServerAndConnect(): Promise<Browser> {
    log.info('Launching Chromium browser server');

    this.browserServer = await chromium.launchServer({
      headless: true,
      args: [...config.chromeLaunchArgs],
    });

    const wsEndpoint = this.browserServer.wsEndpoint();
    const serverProcess = this.browserServer.process();
    const pid = serverProcess?.pid ?? 0;

    // Save state for future CLI runs
    const playwrightVersion = await this.getPlaywrightVersion();
    const state: BrowserState = {
      wsEndpoint,
      pid,
      launchedAt: new Date().toISOString(),
      chromeLaunchArgs: [...config.chromeLaunchArgs],
      version: playwrightVersion,
    };
    await saveState(this.stateFilePath, state);

    // Connect to the server
    this.browser = await chromium.connect(wsEndpoint);
    this.browserPid = pid;
    this.launchedAt = Date.now();
    this.contextsCreated = 0;
    this.browserReused = false;

    // Handle unexpected disconnection
    this.browser.on('disconnected', () => {
      log.error('Browser disconnected unexpectedly');
      this.browser = null;
      this.browserPid = null;
      this.launchedAt = null;
    });

    log.info({ pid, wsEndpoint }, 'Browser server launched and connected');
    return this.browser;
  }

  /**
   * Connect to an existing browser server using saved state.
   */
  private async connectToServer(state: BrowserState): Promise<Browser> {
    this.browser = await chromium.connect(state.wsEndpoint);
    this.browserPid = state.pid;
    this.launchedAt = new Date(state.launchedAt).getTime();
    this.contextsCreated = 0;

    // Handle unexpected disconnection
    this.browser.on('disconnected', () => {
      log.error('Browser disconnected unexpectedly');
      this.browser = null;
      this.browserPid = null;
      this.launchedAt = null;
    });

    return this.browser;
  }

  /**
   * Launch a browser directly (no-persist mode).
   * Uses `chromium.launch()` — browser dies when CLI exits.
   */
  private async launchDirect(): Promise<Browser> {
    log.info('Launching Chromium browser (no-persist mode)');

    this.browser = await chromium.launch({
      headless: true,
      args: [...config.chromeLaunchArgs],
    });

    this.launchedAt = Date.now();
    this.contextsCreated = 0;
    this.browserPid = null;
    this.browserReused = false;

    this.browser.on('disconnected', () => {
      log.error('Browser disconnected unexpectedly');
      this.browser = null;
      this.browserPid = null;
      this.launchedAt = null;
    });

    log.info('Browser launched successfully (no-persist mode)');
    return this.browser;
  }

  /**
   * Get the current browser instance.
   * Throws if browser is not running.
   */
  getBrowser(): Browser {
    if (!this.browser?.isConnected()) {
      throw new Error('Browser is not running');
    }
    return this.browser;
  }

  /**
   * Get the browser process PID.
   */
  getPid(): number | null {
    return this.browserPid;
  }

  /**
   * Set the browser PID (e.g., discovered via CDP).
   */
  setBrowserPid(pid: number): void {
    this.browserPid = pid;
  }

  /**
   * Increment the context counter (for tracking).
   */
  trackContextCreated(): void {
    this.contextsCreated++;
  }

  /**
   * Get browser health status.
   */
  getHealthStatus(): BrowserHealth {
    return {
      isRunning: this.browser?.isConnected() ?? false,
      pid: this.getPid(),
      uptime: this.launchedAt ? Date.now() - this.launchedAt : 0,
      contextsCreated: this.contextsCreated,
    };
  }

  /**
   * Get the total number of browser restarts.
   */
  getRestartCount(): number {
    return this.restartCount;
  }

  /**
   * Force restart the browser.
   *
   * In persist mode: kills the server process, deletes state, launches new server.
   * In no-persist mode: closes and relaunches.
   */
  async forceRestart(): Promise<Browser> {
    log.warn('Force restarting browser');
    this.restartCount++;

    if (this.persist) {
      // Kill existing server process if we know the PID
      if (this.browserPid) {
        await this.killProcess(this.browserPid);
      }
      // Also close the local BrowserServer if we own it
      if (this.browserServer) {
        try {
          await this.browserServer.close();
        } catch {
          // Ignore — process may already be dead
        }
        this.browserServer = null;
      }
      await deleteState(this.stateFilePath);
      this.browser = null;
      this.browserPid = null;
      this.launchedAt = null;
      return this.launchServerAndConnect();
    }

    await this.close();
    return this.launchDirect();
  }

  /**
   * Gracefully close or disconnect from the browser.
   *
   * In persist mode: disconnects the client but leaves the server running.
   * In no-persist mode: closes the browser entirely and deletes any state file.
   */
  async close(): Promise<void> {
    if (!this.browser) return;

    try {
      if (this.persist) {
        // In persist mode, just disconnect — don't kill the server
        log.info('Disconnecting from browser server (persist mode — server stays alive)');
        await this.browser.close();
      } else {
        // In no-persist mode, close the browser entirely
        log.info('Closing browser (no-persist mode)');
        await this.browser.close();

        // Also close the server if we own it
        if (this.browserServer) {
          await this.browserServer.close();
          this.browserServer = null;
        }

        await deleteState(this.stateFilePath);
      }
    } catch (err) {
      log.error({ err }, 'Error closing browser — force killing');
    } finally {
      this.browser = null;
      this.browserPid = null;
      this.launchedAt = null;
    }
  }

  /**
   * Check if the browser is currently running.
   */
  isRunning(): boolean {
    return this.browser?.isConnected() ?? false;
  }

  /**
   * Kill a process by PID. Sends SIGTERM.
   * Silently ignores errors (process may already be dead).
   */
  private async killProcess(pid: number): Promise<void> {
    try {
      process.kill(pid, 'SIGTERM');
      log.info({ pid }, 'Sent SIGTERM to browser process');
      // Give the process a moment to die
      await new Promise((resolve) => setTimeout(resolve, 500));
    } catch {
      log.debug({ pid }, 'Process already dead or inaccessible');
    }
  }

  /**
   * Get the Playwright version string for state tracking.
   */
  private async getPlaywrightVersion(): Promise<string> {
    try {
      // Playwright doesn't expose version directly; read from package.json
      const { createRequire } = await import('node:module');
      const require = createRequire(import.meta.url);
      const pkg = require('playwright/package.json') as { version: string };
      return pkg.version;
    } catch {
      return 'unknown';
    }
  }
}

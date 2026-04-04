/**
 * Application configuration loaded from environment variables with sensible defaults.
 * CLI arguments can override these values via `applyCliOverrides()`.
 */

import type { PressureThresholds } from './types/memory.js';

function envInt(key: string, defaultValue: number): number {
  const val = process.env[key];
  if (val === undefined) return defaultValue;
  const parsed = parseInt(val, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

function envString(key: string, defaultValue: string): string {
  return process.env[key] ?? defaultValue;
}

export interface CliOverrides {
  outputDir?: string;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  maxConcurrency?: number;
  tabTimeout?: number;
  tabMemoryLimit?: number;
  noPersist?: boolean;
  stateFile?: string;
}

export const config = {
  /** Log level */
  logLevel: envString('LOG_LEVEL', 'info') as 'debug' | 'info' | 'warn' | 'error',

  /** Directory to save screenshots */
  screenshotDir: envString('SCREENSHOT_DIR', './screenshots'),

  /** Concurrency settings */
  concurrency: {
    /** Maximum concurrent tabs */
    max: envInt('MAX_CONCURRENCY', 20),
    /** Minimum concurrent tabs */
    min: envInt('MIN_CONCURRENCY', 2),
    /** Initial concurrent tabs */
    initial: envInt('INITIAL_CONCURRENCY', 10),
  },

  /** Memory settings */
  memory: {
    /** Total system memory in MB (for threshold calculations) */
    totalMb: envInt('TOTAL_MEMORY_MB', 8192),
    /** Maximum Chrome process memory in MB before forced restart */
    chromeMaxMb: envInt('CHROME_MAX_MEMORY_MB', 4096),
    /** Per-tab memory limit in MB */
    tabLimitMb: envInt('TAB_MEMORY_LIMIT_MB', 150),
    /** Memory polling interval in ms */
    pollIntervalMs: envInt('MEMORY_POLL_INTERVAL_MS', 2000),
    /** Pressure thresholds (percentage of total memory used) */
    thresholds: {
      low: envInt('MEMORY_LOW_THRESHOLD', 50),
      medium: envInt('MEMORY_MEDIUM_THRESHOLD', 50),
      high: envInt('MEMORY_HIGH_THRESHOLD', 70),
      critical: envInt('MEMORY_CRITICAL_THRESHOLD', 85),
    } satisfies PressureThresholds,
  },

  /** Tab/page settings */
  tab: {
    /** Navigation timeout in ms */
    timeoutMs: envInt('TAB_TIMEOUT_MS', 30000),
    /** Network idle wait timeout in ms */
    networkIdleTimeoutMs: envInt('NETWORK_IDLE_TIMEOUT_MS', 15000),
    /** Default viewport */
    viewport: {
      width: envInt('VIEWPORT_WIDTH', 1280),
      height: envInt('VIEWPORT_HEIGHT', 720),
    },
    /** Maximum resource size to allow (bytes) */
    maxResourceSizeBytes: envInt('MAX_RESOURCE_SIZE_BYTES', 2 * 1024 * 1024), // 2MB
  },

  /** Chrome launch flags for memory optimization */
  chromeLaunchArgs: [
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--disable-extensions',
    '--disable-background-networking',
    '--disable-default-apps',
    '--disable-sync',
    '--disable-translate',
    '--no-first-run',
    '--disable-background-timer-throttling',
    '--disable-renderer-backgrounding',
    '--disable-backgrounding-occluded-windows',
    '--disable-ipc-flooding-protection',
    '--disable-hang-monitor',
    '--js-flags=--max-old-space-size=256',
    '--disable-features=TranslateUI',
    '--disk-cache-size=1',
    '--media-cache-size=1',
    '--aggressive-cache-discard',
  ],

  /** Default resources to block */
  defaultBlockedResources: ['media', 'font'],

  /** Batch limits */
  batch: {
    minUrls: 1,
    maxUrls: 1000,
  },

  /** Browser persistence settings */
  persistence: {
    /** Whether to persist the browser between CLI runs (default: true) */
    enabled: true,
    /** Path to the browser state file */
    stateFilePath: envString('BROWSER_STATE_FILE', '/tmp/render-cli-browser.json'),
  },
} as const;

// We need a mutable copy for CLI overrides
const mutableConfig = config as {
  -readonly [K in keyof typeof config]: (typeof config)[K] extends object
    ? { -readonly [K2 in keyof (typeof config)[K]]: (typeof config)[K][K2] }
    : (typeof config)[K];
};

/**
 * Apply CLI argument overrides to the configuration.
 * CLI args take highest priority: CLI > env vars > defaults.
 */
export function applyCliOverrides(overrides: CliOverrides): void {
  if (overrides.outputDir !== undefined) {
    (mutableConfig as Record<string, unknown>).screenshotDir = overrides.outputDir;
  }
  if (overrides.logLevel !== undefined) {
    (mutableConfig as Record<string, unknown>).logLevel = overrides.logLevel;
  }
  if (overrides.maxConcurrency !== undefined) {
    (mutableConfig.concurrency as Record<string, unknown>).max = overrides.maxConcurrency;
    (mutableConfig.concurrency as Record<string, unknown>).initial = Math.min(
      overrides.maxConcurrency,
      config.concurrency.initial,
    );
  }
  if (overrides.tabTimeout !== undefined) {
    (mutableConfig.tab as Record<string, unknown>).timeoutMs = overrides.tabTimeout;
  }
  if (overrides.tabMemoryLimit !== undefined) {
    (mutableConfig.memory as Record<string, unknown>).tabLimitMb = overrides.tabMemoryLimit;
  }
  if (overrides.noPersist !== undefined && overrides.noPersist) {
    (mutableConfig.persistence as Record<string, unknown>).enabled = false;
  }
  if (overrides.stateFile !== undefined) {
    (mutableConfig.persistence as Record<string, unknown>).stateFilePath = overrides.stateFile;
  }
}

export type Config = typeof config;

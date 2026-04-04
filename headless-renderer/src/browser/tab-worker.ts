/**
 * Per-tab rendering worker.
 * Handles the full lifecycle of rendering a single URL:
 * Create BrowserContext → Create Page → Set interception → Navigate →
 * Wait for idle → Take screenshot → Close context → Return result.
 */

import type { Browser, BrowserContext, Page } from 'playwright';
import { createChildLogger } from '../utils/logger.js';
import { setupResourceBlocker } from './resource-blocker.js';
import { saveScreenshot, ensureBatchDir } from '../utils/screenshot-saver.js';
import { TabMemoryTracker } from '../memory/tab-memory-tracker.js';
import type { TabResult, TabWorkerOptions } from '../types/tab.js';

const log = createChildLogger('tab-worker');

/**
 * Render a single URL and capture a screenshot.
 * Returns a TabResult with status, screenshot path, and timing info.
 */
export async function renderUrl(
  browser: Browser,
  options: TabWorkerOptions,
  memoryTracker: TabMemoryTracker,
  signal?: AbortSignal,
): Promise<TabResult> {
  const {
    url,
    tabId,
    batchId,
    timeoutMs,
    networkIdleTimeoutMs,
    tabMemoryLimitMb,
    viewport,
    fullPage,
    blockResources,
    locale,
  } = options;

  const startTime = Date.now();
  let context: BrowserContext | null = null;
  let page: Page | null = null;
  let memoryUsedMb = 0;

  log.debug({ tabId, url }, 'Starting tab worker');

  try {
    // Check if already aborted
    if (signal?.aborted) {
      return createFailedResult(url, startTime, 'killed_by_pressure', 'Aborted before start');
    }

    // Ensure batch directory exists
    await ensureBatchDir(batchId);

    // Create isolated BrowserContext (incognito-like)
    context = await browser.newContext({
      locale,
      viewport,
      ignoreHTTPSErrors: true,
      serviceWorkers: 'block',
      javaScriptEnabled: true,
      bypassCSP: true,
      // Disable caching
      extraHTTPHeaders: {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
      },
    });

    // Create page
    page = await context.newPage();

    // Register for memory tracking
    await memoryTracker.registerTab(tabId, page, url);

    // Set up resource blocking
    await setupResourceBlocker(page, blockResources);

    // Set up abort handler
    const abortPromise = signal
      ? new Promise<'aborted'>((resolve) => {
          signal.addEventListener('abort', () => resolve('aborted'), { once: true });
        })
      : null;

    // Navigate to URL with timeout
    log.debug({ tabId, url, timeoutMs }, 'Navigating to URL');

    const navigationResult = await raceWithAbort(
      navigateWithTimeout(page, url, timeoutMs),
      abortPromise,
    );

    if (navigationResult === 'aborted') {
      // Take partial screenshot before aborting
      const screenshot = await takePartialScreenshot(page);
      if (screenshot) {
        const path = await saveScreenshot(screenshot, batchId, url);
        memoryUsedMb = await memoryTracker.getTabMemory(tabId);
        return createResult(url, startTime, 'partial', path, memoryUsedMb, 'killed_by_pressure');
      }
      return createFailedResult(url, startTime, 'killed_by_pressure', 'Aborted during navigation');
    }

    // Check if navigation succeeded or timed out
    if (navigationResult.timedOut) {
      log.warn({ tabId, url }, 'Navigation timed out — taking partial screenshot');
      const screenshot = await takePartialScreenshot(page);
      if (screenshot) {
        const path = await saveScreenshot(screenshot, batchId, url);
        memoryUsedMb = await memoryTracker.getTabMemory(tabId);
        return createResult(url, startTime, 'partial', path, memoryUsedMb, 'timeout_exceeded');
      }
      return createFailedResult(url, startTime, 'timeout_exceeded', 'Navigation timed out');
    }

    if (navigationResult.error) {
      log.error({ tabId, url, error: navigationResult.error }, 'Navigation failed');
      return createFailedResult(url, startTime, 'navigation_error', navigationResult.error);
    }

    // Wait for network idle (best-effort)
    await waitForNetworkIdle(page, networkIdleTimeoutMs);

    // Check memory before screenshot
    memoryUsedMb = await memoryTracker.getTabMemory(tabId);
    if (memoryUsedMb > tabMemoryLimitMb) {
      log.warn(
        { tabId, url, memoryUsedMb, limit: tabMemoryLimitMb },
        'Tab exceeds memory limit — taking partial screenshot',
      );
      const screenshot = await takePartialScreenshot(page);
      if (screenshot) {
        const path = await saveScreenshot(screenshot, batchId, url);
        return createResult(url, startTime, 'partial', path, memoryUsedMb, 'memory_limit_exceeded');
      }
      return createFailedResult(url, startTime, 'memory_limit_exceeded',
        `Tab killed: exceeded ${tabMemoryLimitMb}MB memory limit`);
    }

    // Take full screenshot
    log.debug({ tabId, url }, 'Taking screenshot');
    const screenshot = await page.screenshot({
      type: 'png',
      fullPage,
      timeout: 10000,
    });

    const path = await saveScreenshot(Buffer.from(screenshot), batchId, url);
    memoryUsedMb = await memoryTracker.getTabMemory(tabId);

    log.info(
      { tabId, url, loadTimeMs: Date.now() - startTime, memoryUsedMb },
      'Screenshot captured successfully',
    );

    return createResult(url, startTime, 'success', path, memoryUsedMb);

  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    log.error({ tabId, url, err: errorMessage }, 'Tab worker error');

    // Try to take a partial screenshot on error
    if (page) {
      try {
        const screenshot = await takePartialScreenshot(page);
        if (screenshot) {
          const path = await saveScreenshot(screenshot, batchId, url);
          memoryUsedMb = await memoryTracker.getTabMemory(tabId);
          return createResult(url, startTime, 'partial', path, memoryUsedMb, 'screenshot_error');
        }
      } catch {
        // Can't take screenshot either
      }
    }

    return createFailedResult(url, startTime, 'screenshot_error', errorMessage);

  } finally {
    // Clean up: unregister memory tracking and close context
    await memoryTracker.unregisterTab(tabId);

    if (context) {
      try {
        await context.close();
      } catch {
        // Context may already be closed
      }
    }

    log.debug({ tabId, url, durationMs: Date.now() - startTime }, 'Tab worker finished');
  }
}

/**
 * Navigate to a URL with a timeout.
 * Returns whether navigation succeeded, timed out, or errored.
 */
async function navigateWithTimeout(
  page: Page,
  url: string,
  timeoutMs: number,
): Promise<{ timedOut: boolean; error?: string }> {
  try {
    await page.goto(url, {
      timeout: timeoutMs,
      waitUntil: 'domcontentloaded',
    });
    return { timedOut: false };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('Timeout') || message.includes('timeout')) {
      return { timedOut: true };
    }
    return { timedOut: false, error: message };
  }
}

/**
 * Wait for network to become idle (best-effort, non-blocking).
 */
async function waitForNetworkIdle(page: Page, timeoutMs: number): Promise<void> {
  try {
    await page.waitForLoadState('networkidle', { timeout: timeoutMs });
  } catch {
    // Network idle timeout is acceptable — we proceed with whatever loaded
    log.debug('Network idle timeout — proceeding with current state');
  }
}

/**
 * Take a partial screenshot (best-effort).
 * Returns null if screenshot fails.
 */
async function takePartialScreenshot(page: Page): Promise<Buffer | null> {
  try {
    const screenshot = await page.screenshot({
      type: 'png',
      fullPage: false,
      timeout: 5000,
    });
    return Buffer.from(screenshot);
  } catch {
    return null;
  }
}

/**
 * Race a promise against an abort signal.
 */
async function raceWithAbort<T>(
  promise: Promise<T>,
  abortPromise: Promise<'aborted'> | null,
): Promise<T | 'aborted'> {
  if (!abortPromise) return promise;
  return Promise.race([promise, abortPromise]);
}

/**
 * Create a successful or partial TabResult.
 */
function createResult(
  url: string,
  startTime: number,
  status: 'success' | 'partial',
  screenshotPath: string,
  memoryUsedMb: number,
  reason?: TabResult['reason'],
): TabResult {
  return {
    url,
    status,
    reason,
    screenshotPath,
    loadTimeMs: Date.now() - startTime,
    memoryUsedMb: Math.round(memoryUsedMb * 10) / 10,
  };
}

/**
 * Create a failed TabResult.
 */
function createFailedResult(
  url: string,
  startTime: number,
  reason: TabResult['reason'],
  error: string,
): TabResult {
  return {
    url,
    status: 'failed',
    reason,
    error,
    screenshotPath: null,
    loadTimeMs: Date.now() - startTime,
    memoryUsedMb: 0,
  };
}

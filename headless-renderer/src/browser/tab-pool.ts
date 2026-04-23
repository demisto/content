/**
 * Tab pool / concurrency controller.
 * Manages how many tabs run in parallel using a semaphore pattern.
 * Dynamically adjusts concurrency based on memory pressure signals.
 * Uses Promise.allSettled to process batches.
 */

import type { Browser } from 'playwright';
import { v4 as uuidv4 } from 'uuid';
import { createChildLogger } from '../utils/logger.js';
import { config } from '../config.js';
import { renderUrl } from './tab-worker.js';
import { TabMemoryTracker } from '../memory/tab-memory-tracker.js';
import { MemoryMonitor } from '../memory/memory-monitor.js';
import { PressureLevel } from '../types/memory.js';
import { isDangerous } from '../memory/pressure-levels.js';
import type { TabResult, TabWorkerOptions } from '../types/tab.js';
import type { BatchResponse, RenderOptions } from '../types/batch.js';
import { sanitizeUrl } from '../utils/url-sanitizer.js';
import { ensureBatchDir } from '../utils/screenshot-saver.js';
import { BrowserManager } from './browser-manager.js';

const log = createChildLogger('tab-pool');

export class TabPool {
  private maxConcurrency: number;
  private activeTabs = new Map<string, AbortController>();
  private readonly memoryTracker = new TabMemoryTracker();

  constructor(
    private readonly browserManager: BrowserManager,
    private readonly memoryMonitor: MemoryMonitor,
  ) {
    this.maxConcurrency = config.concurrency.initial;

    // Listen for memory pressure changes
    this.memoryMonitor.on('pressureChange', (level: PressureLevel) => {
      this.adjustConcurrency(level);
    });

    this.memoryMonitor.on('critical', () => {
      void this.handleCriticalPressure();
    });
  }

  /**
   * Process a batch of URLs.
   * Returns a complete BatchResponse with per-URL results.
   */
  async processBatch(
    urls: string[],
    locale: string,
    options: RenderOptions,
  ): Promise<BatchResponse> {
    const batchId = uuidv4();
    const startTime = Date.now();

    log.info(
      { batchId, urlCount: urls.length, locale, maxConcurrency: this.maxConcurrency },
      'Processing batch',
    );

    // Ensure browser is running (locale is handled per-context in tab-worker)
    const { browser } = await this.browserManager.ensureBrowser();
    const browserReused = this.browserManager.wasBrowserReused();

    // Update memory monitor with Chrome PID
    const pid = this.browserManager.getPid();
    if (pid) {
      this.memoryMonitor.setChromePid(pid);
    }

    // Reset peak memory tracking for this batch
    this.memoryMonitor.resetPeakMemory();

    // Ensure batch directory exists
    await ensureBatchDir(batchId);

    // Process URLs with concurrency control
    const results = await this.processWithConcurrency(
      browser,
      batchId,
      urls,
      locale,
      options,
    );

    // Compile batch response
    const succeeded = results.filter((r) => r.status === 'success').length;
    const failed = results.filter((r) => r.status === 'failed').length;
    const partial = results.filter((r) => r.status === 'partial').length;

    const response: BatchResponse = {
      batchId,
      locale,
      total: urls.length,
      succeeded,
      failed,
      partial,
      results,
      systemStats: {
        peakMemoryPercent: Math.round(this.memoryMonitor.getPeakMemoryPercent()),
        browserPid: this.browserManager.getPid(),
        processingTimeMs: Date.now() - startTime,
      },
      browserReused,
    };

    log.info(
      {
        batchId,
        total: urls.length,
        succeeded,
        failed,
        partial,
        processingTimeMs: response.systemStats.processingTimeMs,
      },
      'Batch processing complete',
    );

    return response;
  }

  /**
   * Process URLs with semaphore-based concurrency control.
   */
  private async processWithConcurrency(
    browser: Browser,
    batchId: string,
    urls: string[],
    locale: string,
    options: RenderOptions,
  ): Promise<TabResult[]> {
    const results: TabResult[] = [];
    let index = 0;

    // Create a pool of workers
    const workers: Promise<void>[] = [];
    const concurrency = Math.min(this.maxConcurrency, urls.length);

    for (let i = 0; i < concurrency; i++) {
      workers.push(this.worker(browser, batchId, urls, locale, options, results, () => index++));
    }

    await Promise.allSettled(workers);

    // Sort results to match input URL order
    const urlOrder = new Map(urls.map((url, idx) => [url, idx]));
    results.sort((a, b) => (urlOrder.get(a.url) ?? 0) - (urlOrder.get(b.url) ?? 0));

    return results;
  }

  /**
   * Worker that processes URLs from the shared queue.
   */
  private async worker(
    browser: Browser,
    batchId: string,
    urls: string[],
    locale: string,
    options: RenderOptions,
    results: TabResult[],
    getNextIndex: () => number,
  ): Promise<void> {
    while (true) {
      const idx = getNextIndex();
      if (idx >= urls.length) break;

      const url = urls[idx];
      const tabId = uuidv4();

      // Validate URL
      const sanitized = sanitizeUrl(url);
      if (!sanitized.valid) {
        results.push({
          url,
          status: 'failed',
          reason: 'invalid_url',
          error: sanitized.error,
          screenshotPath: null,
          loadTimeMs: 0,
          memoryUsedMb: 0,
        });
        continue;
      }

      // Check if we should pause due to memory pressure
      const pressure = this.memoryMonitor.getCurrentLevel();
      if (pressure === PressureLevel.CRITICAL) {
        log.warn({ tabId, url }, 'Skipping URL due to CRITICAL memory pressure');
        results.push({
          url: sanitized.url,
          status: 'failed',
          reason: 'memory_limit_exceeded',
          error: 'Skipped due to critical memory pressure',
          screenshotPath: null,
          loadTimeMs: 0,
          memoryUsedMb: 0,
        });
        continue;
      }

      // Create abort controller for this tab
      const abortController = new AbortController();
      this.activeTabs.set(tabId, abortController);

      const workerOptions: TabWorkerOptions = {
        url: sanitized.url,
        tabId,
        batchId,
        screenshotDir: config.screenshotDir,
        timeoutMs: options.timeoutMs,
        networkIdleTimeoutMs: config.tab.networkIdleTimeoutMs,
        tabMemoryLimitMb: config.memory.tabLimitMb,
        viewport: options.viewport,
        fullPage: options.fullPage,
        blockResources: [...options.blockResources],
        locale,
      };

      try {
        this.browserManager.trackContextCreated();
        const result = await renderUrl(
          browser,
          workerOptions,
          this.memoryTracker,
          abortController.signal,
        );
        results.push(result);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        log.error({ tabId, url, err: errorMessage }, 'Unexpected tab worker error');
        results.push({
          url: sanitized.url,
          status: 'failed',
          reason: 'browser_crashed',
          error: errorMessage,
          screenshotPath: null,
          loadTimeMs: 0,
          memoryUsedMb: 0,
        });
      } finally {
        this.activeTabs.delete(tabId);
      }

      // Dynamic concurrency check: if pressure increased, slow down
      if (isDangerous(this.memoryMonitor.getCurrentLevel())) {
        // Add a small delay to let memory recover
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  }

  /**
   * Adjust max concurrency based on memory pressure.
   */
  adjustConcurrency(pressure: PressureLevel): void {
    const previous = this.maxConcurrency;
    const recommended = this.memoryMonitor.getRecommendedConcurrency();

    this.maxConcurrency = Math.max(
      config.concurrency.min,
      Math.min(recommended, config.concurrency.max),
    );

    this.memoryMonitor.updateConcurrency(this.maxConcurrency);

    if (this.maxConcurrency !== previous) {
      log.info(
        { previous, current: this.maxConcurrency, pressure },
        'Concurrency adjusted',
      );
    }

    // Kill slow tabs on HIGH pressure
    if (pressure === PressureLevel.HIGH) {
      void this.killSlowestTab();
    }
  }

  /**
   * Kill the tab that has been running the longest.
   */
  async killSlowestTab(): Promise<void> {
    const slowest = await this.memoryTracker.findSlowestTab();
    if (!slowest) return;

    const controller = this.activeTabs.get(slowest.tabId);
    if (controller) {
      log.warn(
        { tabId: slowest.tabId, url: slowest.url, durationMs: slowest.durationMs },
        'Killing slowest tab due to memory pressure',
      );
      controller.abort();
    }
  }

  /**
   * Handle critical memory pressure: kill all tabs.
   */
  private async handleCriticalPressure(): Promise<void> {
    log.error('CRITICAL memory pressure — killing all active tabs');

    for (const [tabId, controller] of this.activeTabs) {
      log.warn({ tabId }, 'Killing tab due to critical pressure');
      controller.abort();
    }

    // Force GC on all tracked tabs
    const tabs = await this.memoryTracker.getAllTabMemory();
    for (const tab of tabs) {
      await this.memoryTracker.forceGC(tab.tabId);
    }
  }

  /**
   * Get the current number of active tabs.
   */
  getActiveTabCount(): number {
    return this.activeTabs.size;
  }

  /**
   * Get the current max concurrency.
   */
  getCurrentConcurrency(): number {
    return this.maxConcurrency;
  }

  /**
   * Clean up resources.
   */
  async cleanup(): Promise<void> {
    // Abort all active tabs
    for (const controller of this.activeTabs.values()) {
      controller.abort();
    }
    this.activeTabs.clear();
    await this.memoryTracker.cleanup();
  }
}

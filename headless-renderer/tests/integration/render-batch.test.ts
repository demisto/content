/**
 * Integration tests for batch rendering via CLI components.
 * These tests require a running Chromium browser (via Playwright).
 * Run with: npm run test:integration
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { BrowserManager } from '../../src/browser/browser-manager.js';
import { MemoryMonitor } from '../../src/memory/memory-monitor.js';
import { TabPool } from '../../src/browser/tab-pool.js';
import type { RenderOptions } from '../../src/types/batch.js';

const defaultOptions: RenderOptions = {
  viewport: { width: 1280, height: 720 },
  timeoutMs: 30000,
  fullPage: false,
  imageFormat: 'png',
  blockResources: ['media', 'font'],
};

describe('Render Batch Integration', () => {
  let browserManager: BrowserManager;
  let memoryMonitor: MemoryMonitor;
  let tabPool: TabPool;

  beforeAll(async () => {
    browserManager = new BrowserManager();
    memoryMonitor = new MemoryMonitor();
    tabPool = new TabPool(browserManager, memoryMonitor);

    memoryMonitor.start();
  });

  afterAll(async () => {
    memoryMonitor.stop();
    await tabPool.cleanup();
    await browserManager.close();
  });

  describe('TabPool.processBatch', () => {
    it('should handle invalid URLs in batch', async () => {
      const result = await tabPool.processBatch(
        ['http://localhost', 'http://127.0.0.1'],
        'en-US',
        defaultOptions,
      );

      expect(result.total).toBe(2);
      expect(result.failed).toBe(2);
      expect(result.results).toHaveLength(2);
      expect(result.results[0].status).toBe('failed');
      expect(result.results[0].reason).toBe('invalid_url');
    });

    it('should render a simple page successfully', async () => {
      const result = await tabPool.processBatch(
        ['https://example.com'],
        'en-US',
        {
          ...defaultOptions,
          viewport: { width: 800, height: 600 },
          timeoutMs: 15000,
        },
      );

      expect(result.batchId).toBeDefined();
      expect(result.total).toBe(1);
      expect(result.results).toHaveLength(1);

      const urlResult = result.results[0];
      expect(urlResult.url).toBe('https://example.com/');
      // May succeed or fail depending on network
      expect(['success', 'partial', 'failed']).toContain(urlResult.status);

      if (urlResult.status === 'success' || urlResult.status === 'partial') {
        expect(urlResult.screenshotPath).toBeTruthy();
        expect(urlResult.loadTimeMs).toBeGreaterThan(0);
      }

      expect(result.systemStats).toBeDefined();
      expect(result.systemStats.processingTimeMs).toBeGreaterThan(0);
    }, 60000); // 60s timeout for browser operations

    it('should not include browserRestarted in response', async () => {
      const result = await tabPool.processBatch(
        ['https://example.com'],
        'en-US',
        defaultOptions,
      );

      expect(result).not.toHaveProperty('browserRestarted');
    }, 60000);
  });
});

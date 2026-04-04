/**
 * Tracks per-tab memory usage via Chrome DevTools Protocol (CDP).
 * Monitors individual tab memory and enforces per-tab limits.
 */

import type { CDPSession, Page } from 'playwright';
import { createChildLogger } from '../utils/logger.js';
import { config } from '../config.js';
import type { TabMemoryInfo } from '../types/memory.js';

const log = createChildLogger('tab-memory-tracker');

export class TabMemoryTracker {
  private readonly tabs = new Map<string, {
    page: Page;
    cdpSession: CDPSession | null;
    url: string;
    startedAt: number;
  }>();

  /**
   * Register a tab for memory tracking.
   */
  async registerTab(tabId: string, page: Page, url: string): Promise<void> {
    let cdpSession: CDPSession | null = null;
    try {
      cdpSession = await page.context().newCDPSession(page);
    } catch (err) {
      log.warn({ tabId, err }, 'Failed to create CDP session for memory tracking');
    }

    this.tabs.set(tabId, {
      page,
      cdpSession,
      url,
      startedAt: Date.now(),
    });
  }

  /**
   * Get memory usage for a specific tab via CDP.
   * Returns memory in MB.
   */
  async getTabMemory(tabId: string): Promise<number> {
    const tab = this.tabs.get(tabId);
    if (!tab?.cdpSession) return 0;

    try {
      const result = await tab.cdpSession.send('Runtime.getHeapUsage') as {
        usedSize: number;
        totalSize: number;
      };
      return result.usedSize / (1024 * 1024);
    } catch {
      // CDP session may be closed if tab crashed
      return 0;
    }
  }

  /**
   * Check if a tab exceeds the per-tab memory limit.
   */
  async isOverLimit(tabId: string): Promise<boolean> {
    const memoryMb = await this.getTabMemory(tabId);
    return memoryMb > config.memory.tabLimitMb;
  }

  /**
   * Get memory info for all tracked tabs.
   */
  async getAllTabMemory(): Promise<TabMemoryInfo[]> {
    const results: TabMemoryInfo[] = [];
    const now = Date.now();

    for (const [tabId, tab] of this.tabs) {
      const memoryMb = await this.getTabMemory(tabId);
      results.push({
        tabId,
        url: tab.url,
        memoryMb,
        startedAt: tab.startedAt,
        durationMs: now - tab.startedAt,
      });
    }

    return results;
  }

  /**
   * Find the tab using the most memory.
   */
  async findHeaviestTab(): Promise<TabMemoryInfo | null> {
    const tabs = await this.getAllTabMemory();
    if (tabs.length === 0) return null;

    return tabs.reduce((heaviest, tab) =>
      tab.memoryMb > heaviest.memoryMb ? tab : heaviest,
    );
  }

  /**
   * Find the tab that has been running the longest.
   */
  async findSlowestTab(): Promise<TabMemoryInfo | null> {
    const tabs = await this.getAllTabMemory();
    if (tabs.length === 0) return null;

    return tabs.reduce((slowest, tab) =>
      tab.durationMs > slowest.durationMs ? tab : slowest,
    );
  }

  /**
   * Force garbage collection on a specific tab via CDP.
   */
  async forceGC(tabId: string): Promise<void> {
    const tab = this.tabs.get(tabId);
    if (!tab?.cdpSession) return;

    try {
      await tab.cdpSession.send('HeapProfiler.collectGarbage');
      log.debug({ tabId }, 'Forced GC on tab');
    } catch {
      log.warn({ tabId }, 'Failed to force GC on tab');
    }
  }

  /**
   * Unregister a tab and clean up its CDP session.
   */
  async unregisterTab(tabId: string): Promise<void> {
    const tab = this.tabs.get(tabId);
    if (!tab) return;

    try {
      if (tab.cdpSession) {
        await tab.cdpSession.detach();
      }
    } catch {
      // Ignore detach errors
    }

    this.tabs.delete(tabId);
  }

  /**
   * Get the number of tracked tabs.
   */
  get size(): number {
    return this.tabs.size;
  }

  /**
   * Clean up all tracked tabs.
   */
  async cleanup(): Promise<void> {
    for (const tabId of this.tabs.keys()) {
      await this.unregisterTab(tabId);
    }
  }
}

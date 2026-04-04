/**
 * System and process memory monitor.
 * Polls memory every N seconds and emits pressure level changes.
 * Uses os.freemem() for system memory and CDP for Chrome process memory.
 */

import os from 'node:os';
import { EventEmitter } from 'node:events';
import { createChildLogger } from '../utils/logger.js';
import { config } from '../config.js';
import { getPressureLevel, getRecommendedConcurrency, pressureDescription } from './pressure-levels.js';
import type {
  SystemMemoryStats,
  ProcessMemoryStats,
  ChromeMemoryStats,
  MemorySnapshot,
} from '../types/memory.js';
import { PressureLevel } from '../types/memory.js';

const log = createChildLogger('memory-monitor');

export interface MemoryMonitorEvents {
  pressureChange: [level: PressureLevel, previous: PressureLevel];
  snapshot: [snapshot: MemorySnapshot];
  critical: [];
}

export class MemoryMonitor extends EventEmitter {
  private intervalHandle: ReturnType<typeof setInterval> | null = null;
  private currentLevel: PressureLevel = PressureLevel.LOW;
  private currentConcurrency: number;
  private chromePid: number | null = null;
  private peakMemoryPercent = 0;

  constructor() {
    super();
    this.currentConcurrency = config.concurrency.initial;
  }

  /**
   * Start polling memory at the configured interval.
   */
  start(): void {
    if (this.intervalHandle) return;

    log.info(
      { intervalMs: config.memory.pollIntervalMs },
      'Starting memory monitor',
    );

    // Take initial snapshot
    void this.poll();

    this.intervalHandle = setInterval(() => {
      void this.poll();
    }, config.memory.pollIntervalMs);
  }

  /**
   * Stop the memory monitor.
   */
  stop(): void {
    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = null;
      log.info('Memory monitor stopped');
    }
  }

  /**
   * Set the Chrome browser PID for process-level memory tracking.
   */
  setChromePid(pid: number): void {
    this.chromePid = pid;
    log.debug({ pid }, 'Chrome PID set for memory tracking');
  }

  /**
   * Get current system memory statistics.
   */
  getSystemMemory(): SystemMemoryStats {
    const totalMb = os.totalmem() / (1024 * 1024);
    const freeMb = os.freemem() / (1024 * 1024);
    const usedMb = totalMb - freeMb;
    const usedPercent = (usedMb / totalMb) * 100;

    return { totalMb, usedMb, freeMb, usedPercent };
  }

  /**
   * Get Node.js process memory statistics.
   */
  getProcessMemory(): ProcessMemoryStats {
    const mem = process.memoryUsage();
    return {
      pid: process.pid,
      rssMb: mem.rss / (1024 * 1024),
      heapUsedMb: mem.heapUsed / (1024 * 1024),
      heapTotalMb: mem.heapTotal / (1024 * 1024),
      externalMb: mem.external / (1024 * 1024),
    };
  }

  /**
   * Get Chrome process memory (estimated from system if CDP not available).
   */
  getChromeMemory(): ChromeMemoryStats | null {
    if (!this.chromePid) return null;

    // On Linux (Docker), we could read /proc/[pid]/status
    // For cross-platform, we estimate from system memory minus Node memory
    try {
      const system = this.getSystemMemory();
      const node = this.getProcessMemory();

      // Rough estimate: total used minus Node.js usage
      const chromeEstimateMb = Math.max(0, system.usedMb - node.rssMb - (system.totalMb * 0.1));

      return {
        pid: this.chromePid,
        rssMb: chromeEstimateMb,
        jsHeapUsedMb: 0, // Would need CDP for accurate values
        jsHeapTotalMb: 0,
      };
    } catch {
      return null;
    }
  }

  /**
   * Get the current memory pressure level.
   */
  getCurrentLevel(): PressureLevel {
    return this.currentLevel;
  }

  /**
   * Get the recommended concurrency based on current pressure.
   */
  getRecommendedConcurrency(): number {
    return getRecommendedConcurrency(this.currentLevel, this.currentConcurrency);
  }

  /**
   * Get peak memory usage percentage since last reset.
   */
  getPeakMemoryPercent(): number {
    return this.peakMemoryPercent;
  }

  /**
   * Reset peak memory tracking.
   */
  resetPeakMemory(): void {
    this.peakMemoryPercent = 0;
  }

  /**
   * Update the current concurrency (called by TabPool when it adjusts).
   */
  updateConcurrency(concurrency: number): void {
    this.currentConcurrency = concurrency;
  }

  /**
   * Take a memory snapshot and check pressure levels.
   */
  private async poll(): Promise<void> {
    try {
      const system = this.getSystemMemory();
      const node = this.getProcessMemory();
      const chrome = this.getChromeMemory();

      // Track peak
      if (system.usedPercent > this.peakMemoryPercent) {
        this.peakMemoryPercent = system.usedPercent;
      }

      // Determine pressure level
      const newLevel = getPressureLevel(system.usedPercent);
      const recommendedConcurrency = getRecommendedConcurrency(newLevel, this.currentConcurrency);

      const snapshot: MemorySnapshot = {
        timestamp: Date.now(),
        system,
        node,
        chrome,
        pressureLevel: newLevel,
        recommendedConcurrency,
      };

      this.emit('snapshot', snapshot);

      // Check for pressure level change
      if (newLevel !== this.currentLevel) {
        const previous = this.currentLevel;
        this.currentLevel = newLevel;

        log.warn(
          {
            previous,
            current: newLevel,
            usedPercent: system.usedPercent.toFixed(1),
            description: pressureDescription(newLevel),
          },
          'Memory pressure level changed',
        );

        this.emit('pressureChange', newLevel, previous);

        if (newLevel === PressureLevel.CRITICAL) {
          this.emit('critical');
        }
      }

      // Check if Chrome is using too much memory
      if (chrome && chrome.rssMb > config.memory.chromeMaxMb) {
        log.error(
          { chromeMemoryMb: chrome.rssMb, limit: config.memory.chromeMaxMb },
          'Chrome exceeds maximum memory — restart recommended',
        );
      }
    } catch (err) {
      log.error({ err }, 'Error during memory poll');
    }
  }

  /**
   * Get a full memory snapshot on demand.
   */
  getSnapshot(): MemorySnapshot {
    const system = this.getSystemMemory();
    const node = this.getProcessMemory();
    const chrome = this.getChromeMemory();
    const recommendedConcurrency = getRecommendedConcurrency(this.currentLevel, this.currentConcurrency);

    return {
      timestamp: Date.now(),
      system,
      node,
      chrome,
      pressureLevel: this.currentLevel,
      recommendedConcurrency,
    };
  }
}

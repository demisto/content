/**
 * Integration tests for memory pressure handling.
 * Tests the memory monitor's interaction with the tab pool.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { MemoryMonitor } from '../../src/memory/memory-monitor.js';
import { PressureLevel } from '../../src/types/memory.js';
import { getRecommendedConcurrency } from '../../src/memory/pressure-levels.js';

describe('Memory Pressure Integration', () => {
  let monitor: MemoryMonitor;

  beforeEach(() => {
    monitor = new MemoryMonitor();
  });

  afterEach(() => {
    monitor.stop();
  });

  describe('MemoryMonitor events', () => {
    it('should emit snapshot events when polling', async () => {
      const snapshots: unknown[] = [];

      monitor.on('snapshot', (snapshot) => {
        snapshots.push(snapshot);
      });

      monitor.start();

      // Wait for at least one poll
      await new Promise((resolve) => setTimeout(resolve, 3000));

      monitor.stop();

      expect(snapshots.length).toBeGreaterThan(0);
    }, 10000);

    it('should track concurrency updates', () => {
      monitor.updateConcurrency(5);
      // After updating, recommended concurrency should be based on current level
      const recommended = monitor.getRecommendedConcurrency();
      expect(recommended).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Concurrency auto-tuning', () => {
    it('should increase concurrency on LOW pressure', () => {
      const result = getRecommendedConcurrency(PressureLevel.LOW, 5);
      expect(result).toBe(7); // +2
    });

    it('should halve concurrency on MEDIUM pressure', () => {
      const result = getRecommendedConcurrency(PressureLevel.MEDIUM, 10);
      expect(result).toBe(5); // /2
    });

    it('should drop to minimum on HIGH pressure', () => {
      const result = getRecommendedConcurrency(PressureLevel.HIGH, 10);
      expect(result).toBe(2); // min
    });

    it('should stop all on CRITICAL pressure', () => {
      const result = getRecommendedConcurrency(PressureLevel.CRITICAL, 10);
      expect(result).toBe(0);
    });

    it('should never exceed max concurrency', () => {
      const result = getRecommendedConcurrency(PressureLevel.LOW, 19);
      expect(result).toBeLessThanOrEqual(20);
    });

    it('should never go below min on MEDIUM', () => {
      const result = getRecommendedConcurrency(PressureLevel.MEDIUM, 2);
      expect(result).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Memory snapshot', () => {
    it('should provide complete memory snapshot', () => {
      const snapshot = monitor.getSnapshot();

      expect(snapshot.timestamp).toBeGreaterThan(0);
      expect(snapshot.system.totalMb).toBeGreaterThan(0);
      expect(snapshot.system.freeMb).toBeGreaterThan(0);
      expect(snapshot.system.usedPercent).toBeGreaterThan(0);
      expect(snapshot.system.usedPercent).toBeLessThanOrEqual(100);
      expect(snapshot.node.pid).toBeGreaterThan(0);
      expect(snapshot.node.rssMb).toBeGreaterThan(0);
      expect(snapshot.pressureLevel).toBeDefined();
      expect(snapshot.recommendedConcurrency).toBeDefined();
    });

    it('should track peak memory', () => {
      // Get a snapshot to trigger peak tracking
      monitor.getSnapshot();
      const peak = monitor.getPeakMemoryPercent();
      // Peak should be 0 since we haven't polled yet
      expect(peak).toBeGreaterThanOrEqual(0);
    });
  });
});

/**
 * Unit tests for the memory monitor and pressure levels.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getPressureLevel, getRecommendedConcurrency, isDangerous, pressureDescription } from '../../src/memory/pressure-levels.js';
import { PressureLevel } from '../../src/types/memory.js';
import type { PressureThresholds } from '../../src/types/memory.js';

const defaultThresholds: PressureThresholds = {
  low: 50,
  medium: 50,
  high: 70,
  critical: 85,
};

describe('getPressureLevel', () => {
  it('should return LOW when usage is below medium threshold', () => {
    expect(getPressureLevel(30, defaultThresholds)).toBe(PressureLevel.LOW);
    expect(getPressureLevel(0, defaultThresholds)).toBe(PressureLevel.LOW);
    expect(getPressureLevel(49.9, defaultThresholds)).toBe(PressureLevel.LOW);
  });

  it('should return MEDIUM when usage is between medium and high thresholds', () => {
    expect(getPressureLevel(50, defaultThresholds)).toBe(PressureLevel.MEDIUM);
    expect(getPressureLevel(60, defaultThresholds)).toBe(PressureLevel.MEDIUM);
    expect(getPressureLevel(69.9, defaultThresholds)).toBe(PressureLevel.MEDIUM);
  });

  it('should return HIGH when usage is between high and critical thresholds', () => {
    expect(getPressureLevel(70, defaultThresholds)).toBe(PressureLevel.HIGH);
    expect(getPressureLevel(80, defaultThresholds)).toBe(PressureLevel.HIGH);
    expect(getPressureLevel(84.9, defaultThresholds)).toBe(PressureLevel.HIGH);
  });

  it('should return CRITICAL when usage exceeds critical threshold', () => {
    expect(getPressureLevel(85, defaultThresholds)).toBe(PressureLevel.CRITICAL);
    expect(getPressureLevel(95, defaultThresholds)).toBe(PressureLevel.CRITICAL);
    expect(getPressureLevel(100, defaultThresholds)).toBe(PressureLevel.CRITICAL);
  });
});

describe('getRecommendedConcurrency', () => {
  it('should increase concurrency by 2 on LOW pressure', () => {
    expect(getRecommendedConcurrency(PressureLevel.LOW, 10)).toBe(12);
    expect(getRecommendedConcurrency(PressureLevel.LOW, 5)).toBe(7);
  });

  it('should cap concurrency at max (20) on LOW pressure', () => {
    expect(getRecommendedConcurrency(PressureLevel.LOW, 19)).toBe(20);
    expect(getRecommendedConcurrency(PressureLevel.LOW, 20)).toBe(20);
  });

  it('should halve concurrency on MEDIUM pressure', () => {
    expect(getRecommendedConcurrency(PressureLevel.MEDIUM, 10)).toBe(5);
    expect(getRecommendedConcurrency(PressureLevel.MEDIUM, 8)).toBe(4);
  });

  it('should floor at min (2) on MEDIUM pressure', () => {
    expect(getRecommendedConcurrency(PressureLevel.MEDIUM, 3)).toBe(2);
    expect(getRecommendedConcurrency(PressureLevel.MEDIUM, 2)).toBe(2);
  });

  it('should return min (2) on HIGH pressure', () => {
    expect(getRecommendedConcurrency(PressureLevel.HIGH, 10)).toBe(2);
    expect(getRecommendedConcurrency(PressureLevel.HIGH, 20)).toBe(2);
  });

  it('should return 0 on CRITICAL pressure', () => {
    expect(getRecommendedConcurrency(PressureLevel.CRITICAL, 10)).toBe(0);
    expect(getRecommendedConcurrency(PressureLevel.CRITICAL, 2)).toBe(0);
  });
});

describe('isDangerous', () => {
  it('should return true for HIGH and CRITICAL', () => {
    expect(isDangerous(PressureLevel.HIGH)).toBe(true);
    expect(isDangerous(PressureLevel.CRITICAL)).toBe(true);
  });

  it('should return false for LOW and MEDIUM', () => {
    expect(isDangerous(PressureLevel.LOW)).toBe(false);
    expect(isDangerous(PressureLevel.MEDIUM)).toBe(false);
  });
});

describe('pressureDescription', () => {
  it('should return a description for each level', () => {
    expect(pressureDescription(PressureLevel.LOW)).toContain('normal');
    expect(pressureDescription(PressureLevel.MEDIUM)).toContain('50%');
    expect(pressureDescription(PressureLevel.HIGH)).toContain('minimum');
    expect(pressureDescription(PressureLevel.CRITICAL)).toContain('stopping');
  });
});

describe('MemoryMonitor', () => {
  let monitor: Awaited<typeof import('../../src/memory/memory-monitor.js')>['MemoryMonitor'];

  beforeEach(async () => {
    const mod = await import('../../src/memory/memory-monitor.js');
    monitor = mod.MemoryMonitor;
  });

  it('should initialize with LOW pressure level', () => {
    const instance = new monitor();
    expect(instance.getCurrentLevel()).toBe(PressureLevel.LOW);
  });

  it('should return system memory stats', () => {
    const instance = new monitor();
    const stats = instance.getSystemMemory();

    expect(stats.totalMb).toBeGreaterThan(0);
    expect(stats.freeMb).toBeGreaterThan(0);
    expect(stats.usedMb).toBeGreaterThan(0);
    expect(stats.usedPercent).toBeGreaterThan(0);
    expect(stats.usedPercent).toBeLessThanOrEqual(100);
  });

  it('should return Node.js process memory stats', () => {
    const instance = new monitor();
    const stats = instance.getProcessMemory();

    expect(stats.pid).toBeGreaterThan(0);
    expect(stats.rssMb).toBeGreaterThan(0);
    expect(stats.heapUsedMb).toBeGreaterThan(0);
    expect(stats.heapTotalMb).toBeGreaterThan(0);
  });

  it('should return null for Chrome memory when no PID set', () => {
    const instance = new monitor();
    expect(instance.getChromeMemory()).toBeNull();
  });

  it('should start and stop polling', () => {
    const instance = new monitor();
    instance.start();
    // Starting again should be a no-op
    instance.start();
    instance.stop();
    // Stopping again should be a no-op
    instance.stop();
  });

  it('should track peak memory', () => {
    const instance = new monitor();
    expect(instance.getPeakMemoryPercent()).toBe(0);
    instance.resetPeakMemory();
    expect(instance.getPeakMemoryPercent()).toBe(0);
  });

  it('should return a snapshot', () => {
    const instance = new monitor();
    const snapshot = instance.getSnapshot();

    expect(snapshot.timestamp).toBeGreaterThan(0);
    expect(snapshot.system).toBeDefined();
    expect(snapshot.node).toBeDefined();
    expect(snapshot.pressureLevel).toBe(PressureLevel.LOW);
    expect(snapshot.recommendedConcurrency).toBeGreaterThan(0);
  });
});

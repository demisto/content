/**
 * Memory pressure level definitions and concurrency recommendations.
 */

import { PressureLevel } from '../types/memory.js';
import type { PressureThresholds } from '../types/memory.js';
import { config } from '../config.js';

/**
 * Determine the current pressure level based on memory usage percentage.
 */
export function getPressureLevel(
  usedPercent: number,
  thresholds: PressureThresholds = config.memory.thresholds,
): PressureLevel {
  if (usedPercent >= thresholds.critical) {
    return PressureLevel.CRITICAL;
  }
  if (usedPercent >= thresholds.high) {
    return PressureLevel.HIGH;
  }
  if (usedPercent >= thresholds.medium) {
    return PressureLevel.MEDIUM;
  }
  return PressureLevel.LOW;
}

/**
 * Get the recommended concurrency for a given pressure level.
 * Follows the auto-tuning logic from the architecture plan.
 */
export function getRecommendedConcurrency(
  pressureLevel: PressureLevel,
  currentConcurrency: number,
): number {
  const { min, max } = config.concurrency;

  switch (pressureLevel) {
    case PressureLevel.LOW:
      // Gradually increase: +2, capped at max
      return Math.min(currentConcurrency + 2, max);

    case PressureLevel.MEDIUM:
      // Reduce by 50%, floor at min
      return Math.max(Math.floor(currentConcurrency / 2), min);

    case PressureLevel.HIGH:
      // Drop to minimum
      return min;

    case PressureLevel.CRITICAL:
      // Stop all new tabs
      return 0;
  }
}

/**
 * Check if a pressure level is dangerous (HIGH or CRITICAL).
 */
export function isDangerous(level: PressureLevel): boolean {
  return level === PressureLevel.HIGH || level === PressureLevel.CRITICAL;
}

/**
 * Get a human-readable description of the pressure level.
 */
export function pressureDescription(level: PressureLevel): string {
  switch (level) {
    case PressureLevel.LOW:
      return 'Memory usage normal — max concurrency allowed';
    case PressureLevel.MEDIUM:
      return 'Memory usage elevated — reducing concurrency by 50%';
    case PressureLevel.HIGH:
      return 'Memory usage high — minimum concurrency, killing slow tabs';
    case PressureLevel.CRITICAL:
      return 'Memory usage critical — stopping all new tabs, killing running tabs';
  }
}

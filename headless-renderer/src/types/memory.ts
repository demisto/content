/**
 * Memory pressure levels based on system memory usage.
 * Thresholds are relative to total system memory (default 8GB).
 */
export enum PressureLevel {
  /** < 50% used — max concurrency */
  LOW = 'LOW',
  /** 50–70% used — reduce concurrency by 50% */
  MEDIUM = 'MEDIUM',
  /** 70–85% used — reduce to 2 tabs, kill slow tabs */
  HIGH = 'HIGH',
  /** > 85% used — stop new tabs, kill all, force GC */
  CRITICAL = 'CRITICAL',
}

export interface SystemMemoryStats {
  totalMb: number;
  usedMb: number;
  freeMb: number;
  usedPercent: number;
}

export interface ProcessMemoryStats {
  pid: number;
  rssMb: number;
  heapUsedMb: number;
  heapTotalMb: number;
  externalMb: number;
}

export interface ChromeMemoryStats {
  pid: number;
  rssMb: number;
  jsHeapUsedMb: number;
  jsHeapTotalMb: number;
}

export interface MemorySnapshot {
  timestamp: number;
  system: SystemMemoryStats;
  node: ProcessMemoryStats;
  chrome: ChromeMemoryStats | null;
  pressureLevel: PressureLevel;
  recommendedConcurrency: number;
}

export interface PressureThresholds {
  low: number;       // percentage threshold for LOW
  medium: number;    // percentage threshold for MEDIUM
  high: number;      // percentage threshold for HIGH
  critical: number;  // percentage threshold for CRITICAL
}

export interface TabMemoryInfo {
  tabId: string;
  url: string;
  memoryMb: number;
  startedAt: number;
  durationMs: number;
}

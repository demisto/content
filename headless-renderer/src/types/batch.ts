/**
 * Types for batch render requests and responses.
 */

import type { TabResult, ViewportSize } from './tab.js';

export interface RenderOptions {
  viewport: ViewportSize;
  timeoutMs: number;
  fullPage: boolean;
  imageFormat: 'png';
  blockResources: string[];
}

export interface BatchRequest {
  urls: string[];
  locale: string;
  options: RenderOptions;
}

export interface SystemStats {
  peakMemoryPercent: number;
  browserPid: number | null;
  processingTimeMs: number;
}

export interface BatchResponse {
  batchId: string;
  locale: string;
  total: number;
  succeeded: number;
  failed: number;
  partial: number;
  results: TabResult[];
  systemStats: SystemStats;
  /** Whether an existing persistent browser was reused for this batch */
  browserReused: boolean;
}

export interface BatchProgress {
  batchId: string;
  total: number;
  completed: number;
  inProgress: number;
  queued: number;
}

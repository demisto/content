/**
 * Types for tab/page lifecycle and results.
 */

export type TabStatus = 'success' | 'partial' | 'failed';

export type FailureReason =
  | 'timeout_exceeded'
  | 'memory_limit_exceeded'
  | 'navigation_error'
  | 'screenshot_error'
  | 'browser_crashed'
  | 'killed_by_pressure'
  | 'invalid_url';

export interface TabResult {
  url: string;
  status: TabStatus;
  reason?: FailureReason;
  error?: string;
  screenshotPath: string | null;
  loadTimeMs: number;
  memoryUsedMb: number;
}

export interface TabWorkerOptions {
  url: string;
  tabId: string;
  batchId: string;
  screenshotDir: string;
  timeoutMs: number;
  networkIdleTimeoutMs: number;
  tabMemoryLimitMb: number;
  viewport: ViewportSize;
  fullPage: boolean;
  blockResources: string[];
  locale: string;
}

export interface ViewportSize {
  width: number;
  height: number;
}

export interface ActiveTab {
  tabId: string;
  url: string;
  startedAt: number;
  memoryMb: number;
  abortController: AbortController;
}

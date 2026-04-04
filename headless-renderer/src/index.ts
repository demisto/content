#!/usr/bin/env node
/**
 * CLI entry point for the Headless Browser Renderer.
 *
 * Flow:
 *   1. Parse CLI args
 *   2. Handle management commands (--kill-browser, --browser-status) → exit
 *   3. Read and validate JSON input file
 *   4. Initialize BrowserManager (with persist/no-persist), MemoryMonitor, TabPool
 *   5. Start memory monitor
 *   6. Process batch via TabPool
 *   7. Output JSON result to stdout
 *   8. Cleanup (stop monitor, disconnect/close browser)
 *   9. Exit with appropriate code (0=all success, 1=partial/failures, 2=fatal)
 */

import { parseCliArgs } from './cli/args.js';
import { readAndValidateInput, InputValidationError } from './cli/input-validator.js';
import { BrowserManager } from './browser/browser-manager.js';
import { MemoryMonitor } from './memory/memory-monitor.js';
import { TabPool } from './browser/tab-pool.js';
import { config, applyCliOverrides } from './config.js';
import { createChildLogger, logger } from './utils/logger.js';
import { handleKillBrowser, handleBrowserStatus } from './cli/commands.js';
import { mkdir } from 'node:fs/promises';

async function main(): Promise<void> {
  // 1. Parse CLI args
  const args = parseCliArgs();

  // 2. Apply CLI overrides to config (before logger is used extensively)
  applyCliOverrides({
    outputDir: args.outputDir,
    logLevel: args.logLevel,
    maxConcurrency: args.maxConcurrency,
    tabTimeout: args.tabTimeout,
    tabMemoryLimit: args.tabMemoryLimit,
    noPersist: args.noPersist,
    stateFile: args.stateFile,
  });

  // Update logger level after CLI override
  logger.level = config.logLevel;

  const log = createChildLogger('main');

  // 3. Handle management commands (these exit immediately)
  if (args.killBrowser) {
    await handleKillBrowser(config.persistence.stateFilePath);
    process.exit(0);
  }

  if (args.browserStatus) {
    await handleBrowserStatus(config.persistence.stateFilePath);
    process.exit(0);
  }

  log.info('Starting Headless Browser Renderer CLI');
  log.info(
    {
      config: {
        inputFile: args.input,
        screenshotDir: config.screenshotDir,
        maxConcurrency: config.concurrency.max,
        initialConcurrency: config.concurrency.initial,
        tabTimeoutMs: config.tab.timeoutMs,
        tabMemoryLimitMb: config.memory.tabLimitMb,
        memoryPollIntervalMs: config.memory.pollIntervalMs,
        persistBrowser: config.persistence.enabled,
        stateFilePath: config.persistence.stateFilePath,
      },
    },
    'Configuration loaded',
  );

  // 4. Read and validate input file
  log.info({ inputFile: args.input }, 'Reading input file');
  const batchRequest = await readAndValidateInput(args.input);
  log.info(
    { urlCount: batchRequest.urls.length, locale: batchRequest.locale },
    'Input validated',
  );

  // 5. Ensure screenshot directory exists
  await mkdir(config.screenshotDir, { recursive: true });

  // 6. Initialize components with persistence settings
  const browserManager = new BrowserManager({
    stateFilePath: config.persistence.stateFilePath,
    persist: config.persistence.enabled,
  });
  const memoryMonitor = new MemoryMonitor();
  const tabPool = new TabPool(browserManager, memoryMonitor);

  // 7. Start memory monitor
  memoryMonitor.start();

  try {
    // 8. Process batch
    log.info('Processing batch...');
    const result = await tabPool.processBatch(
      batchRequest.urls,
      batchRequest.locale,
      batchRequest.options,
    );

    // 9. Output JSON result to stdout (clean, no logs mixed in)
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');

    // 10. Determine exit code
    if (result.failed === 0 && result.partial === 0) {
      log.info('All URLs processed successfully');
      await cleanup(memoryMonitor, tabPool, browserManager, log);
      process.exit(0);
    } else {
      log.warn(
        { succeeded: result.succeeded, failed: result.failed, partial: result.partial },
        'Batch completed with failures',
      );
      await cleanup(memoryMonitor, tabPool, browserManager, log);
      process.exit(1);
    }
  } catch (err) {
    log.error({ err }, 'Fatal error during batch processing');
    await cleanup(memoryMonitor, tabPool, browserManager, log);
    process.exit(2);
  }
}

async function cleanup(
  memoryMonitor: MemoryMonitor,
  tabPool: TabPool,
  browserManager: BrowserManager,
  log: ReturnType<typeof createChildLogger>,
): Promise<void> {
  try {
    memoryMonitor.stop();
    log.debug('Memory monitor stopped');

    await tabPool.cleanup();
    log.debug('Tab pool cleaned up');

    // In persist mode, close() just disconnects — browser server stays alive.
    // In no-persist mode, close() shuts down the browser entirely.
    await browserManager.close();
    log.debug(
      config.persistence.enabled
        ? 'Disconnected from browser (server persists)'
        : 'Browser closed',
    );

    log.info('Cleanup complete');
  } catch (err) {
    log.error({ err }, 'Error during cleanup');
  }
}

main().catch((err) => {
  if (err instanceof InputValidationError) {
    process.stderr.write(`Input validation error: ${err.message}\n`);
    process.exit(2);
  }
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});

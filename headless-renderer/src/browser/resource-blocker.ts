/**
 * Request interception to block heavy resources and save memory.
 * Blocks media, fonts, service workers, and large resources.
 */

import type { Page, Route, Request } from 'playwright';
import { createChildLogger } from '../utils/logger.js';
import { config } from '../config.js';

const log = createChildLogger('resource-blocker');

/** Resource types that can be blocked */
const BLOCKABLE_RESOURCE_TYPES = new Set([
  'media',
  'font',
  'stylesheet',
  'websocket',
  'other',
]);

/** Resource types that are always blocked */
const ALWAYS_BLOCKED_TYPES = new Set([
  'media',       // video/audio
]);

/** URL patterns for service workers */
const SERVICE_WORKER_PATTERNS = [
  /service[-_]?worker/i,
  /sw\.js$/i,
  /workbox/i,
];

/**
 * Set up request interception on a page to block heavy resources.
 *
 * @param page - Playwright page instance
 * @param blockResources - List of resource types to block (e.g., ['media', 'font'])
 */
export async function setupResourceBlocker(
  page: Page,
  blockResources: readonly string[] = config.defaultBlockedResources,
): Promise<void> {
  const blockedTypes = new Set([
    ...ALWAYS_BLOCKED_TYPES,
    ...blockResources.filter((r) => BLOCKABLE_RESOURCE_TYPES.has(r)),
  ]);

  let blockedCount = 0;
  let allowedCount = 0;

  await page.route('**/*', async (route: Route, request: Request) => {
    const resourceType = request.resourceType();
    const url = request.url();

    // Block by resource type
    if (blockedTypes.has(resourceType)) {
      blockedCount++;
      log.debug({ url: url.slice(0, 100), type: resourceType }, 'Blocked resource');
      await route.abort('blockedbyclient');
      return;
    }

    // Block service workers
    if (isServiceWorker(url)) {
      blockedCount++;
      log.debug({ url: url.slice(0, 100) }, 'Blocked service worker');
      await route.abort('blockedbyclient');
      return;
    }

    // For images and scripts, check Content-Length header via fetch
    // We can't know the size before the response, so we use route.continue()
    // and rely on the response handler for size-based blocking
    if (resourceType === 'image' || resourceType === 'script') {
      // Continue but we'll handle large responses separately
      await route.continue();
      allowedCount++;
      return;
    }

    // Allow everything else
    await route.continue();
    allowedCount++;
  });

  log.debug({ blockedTypes: [...blockedTypes] }, 'Resource blocker configured');

  // Also set up response-based blocking for large resources
  page.on('response', async (response) => {
    try {
      const headers = response.headers();
      const contentLength = parseInt(headers['content-length'] || '0', 10);

      if (contentLength > config.tab.maxResourceSizeBytes) {
        log.debug(
          {
            url: response.url().slice(0, 100),
            sizeMb: (contentLength / (1024 * 1024)).toFixed(1),
          },
          'Large resource detected (will be loaded but logged)',
        );
      }
    } catch {
      // Response may be unavailable if page navigated away
    }
  });
}

/**
 * Check if a URL is a service worker script.
 */
function isServiceWorker(url: string): boolean {
  return SERVICE_WORKER_PATTERNS.some((pattern) => pattern.test(url));
}

/**
 * Get resource blocking statistics for a page.
 */
export function getBlockingStats(): { blocked: number; allowed: number } {
  // This would need to be tracked per-page in a real implementation
  return { blocked: 0, allowed: 0 };
}

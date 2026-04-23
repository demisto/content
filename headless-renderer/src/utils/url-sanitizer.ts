/**
 * URL validation and normalization utilities.
 * Ensures URLs are safe and well-formed before navigation.
 */

import { createChildLogger } from './logger.js';

const log = createChildLogger('url-sanitizer');

/** Allowed URL protocols */
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

/** Blocked hostnames (internal/dangerous) */
const BLOCKED_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'metadata.google.internal',
  '169.254.169.254', // AWS metadata
]);

/** Blocked host patterns (private networks) */
const BLOCKED_HOST_PATTERNS = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^fc00:/i,
  /^fe80:/i,
];

export interface SanitizeResult {
  valid: boolean;
  url: string;
  error?: string;
}

/**
 * Validate and normalize a URL.
 * Rejects internal IPs, non-HTTP protocols, and malformed URLs.
 */
export function sanitizeUrl(rawUrl: string): SanitizeResult {
  const trimmed = rawUrl.trim();

  if (!trimmed) {
    return { valid: false, url: trimmed, error: 'Empty URL' };
  }

  // Add protocol if missing
  let urlString = trimmed;
  if (!urlString.match(/^https?:\/\//i)) {
    urlString = `https://${urlString}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    log.warn({ rawUrl }, 'Invalid URL format');
    return { valid: false, url: trimmed, error: 'Invalid URL format' };
  }

  // Check protocol
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    log.warn({ rawUrl, protocol: parsed.protocol }, 'Blocked protocol');
    return { valid: false, url: trimmed, error: `Blocked protocol: ${parsed.protocol}` };
  }

  // Check blocked hosts
  const hostname = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(hostname)) {
    log.warn({ rawUrl, hostname }, 'Blocked hostname');
    return { valid: false, url: trimmed, error: `Blocked hostname: ${hostname}` };
  }

  // Check blocked patterns (private IPs)
  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(hostname)) {
      log.warn({ rawUrl, hostname }, 'Blocked private IP');
      return { valid: false, url: trimmed, error: `Blocked private IP: ${hostname}` };
    }
  }

  // URL length check
  if (urlString.length > 2048) {
    return { valid: false, url: trimmed, error: 'URL exceeds maximum length (2048)' };
  }

  return { valid: true, url: parsed.href };
}

/**
 * Validate a batch of URLs.
 * Returns arrays of valid and invalid URLs.
 */
export function sanitizeBatch(urls: string[]): {
  valid: SanitizeResult[];
  invalid: SanitizeResult[];
} {
  const valid: SanitizeResult[] = [];
  const invalid: SanitizeResult[] = [];

  for (const url of urls) {
    const result = sanitizeUrl(url);
    if (result.valid) {
      valid.push(result);
    } else {
      invalid.push(result);
    }
  }

  log.info(
    { total: urls.length, valid: valid.length, invalid: invalid.length },
    'Batch URL validation complete',
  );

  return { valid, invalid };
}

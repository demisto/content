/**
 * Validates the JSON input file structure for batch rendering.
 *
 * Expected shape:
 * {
 *   "urls": ["https://example.com", ...],   // required, 1-1000 strings
 *   "locale": "en-US",                       // optional, defaults to "en-US"
 *   "options": {                              // optional, all fields have defaults
 *     "viewport": { "width": 1280, "height": 720 },
 *     "timeout_ms": 30000,
 *     "full_page": false,
 *     "block_resources": ["media", "font"]
 *   }
 * }
 */

import { readFile } from 'node:fs/promises';
import type { BatchRequest, RenderOptions } from '../types/batch.js';
import { config } from '../config.js';

export interface InputFileData {
  urls?: unknown;
  locale?: unknown;
  options?: {
    viewport?: { width?: unknown; height?: unknown };
    timeout_ms?: unknown;
    full_page?: unknown;
    block_resources?: unknown;
  };
}

export class InputValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InputValidationError';
  }
}

/**
 * Read and validate a JSON input file.
 * Returns a fully-resolved BatchRequest with defaults applied.
 */
export async function readAndValidateInput(filePath: string): Promise<BatchRequest> {
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      throw new InputValidationError(`Input file not found: ${filePath}`);
    }
    if (code === 'EACCES') {
      throw new InputValidationError(`Permission denied reading: ${filePath}`);
    }
    throw new InputValidationError(`Failed to read input file: ${(err as Error).message}`);
  }

  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new InputValidationError('Input file is not valid JSON');
  }

  return validateInput(data);
}

/**
 * Validate parsed JSON data and return a BatchRequest with defaults applied.
 */
export function validateInput(data: unknown): BatchRequest {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new InputValidationError('Input must be a JSON object');
  }

  const input = data as InputFileData;

  // Validate urls
  if (!Array.isArray(input.urls)) {
    throw new InputValidationError('"urls" must be an array of strings');
  }

  if (input.urls.length === 0) {
    throw new InputValidationError('"urls" must contain at least 1 URL');
  }

  if (input.urls.length > config.batch.maxUrls) {
    throw new InputValidationError(
      `"urls" exceeds maximum of ${config.batch.maxUrls} URLs (got ${input.urls.length})`,
    );
  }

  for (let i = 0; i < input.urls.length; i++) {
    if (typeof input.urls[i] !== 'string') {
      throw new InputValidationError(`"urls[${i}]" must be a string`);
    }
    if ((input.urls[i] as string).trim() === '') {
      throw new InputValidationError(`"urls[${i}]" must not be empty`);
    }
  }

  const urls = input.urls as string[];

  // Validate locale
  let locale = 'en-US';
  if (input.locale !== undefined) {
    if (typeof input.locale !== 'string') {
      throw new InputValidationError('"locale" must be a string');
    }
    locale = input.locale;
  }

  // Validate and apply option defaults
  const options = resolveOptions(input.options);

  return { urls, locale, options };
}

/**
 * Resolve render options with defaults from config.
 */
function resolveOptions(raw?: InputFileData['options']): RenderOptions {
  const defaults: RenderOptions = {
    viewport: {
      width: config.tab.viewport.width,
      height: config.tab.viewport.height,
    },
    timeoutMs: config.tab.timeoutMs,
    fullPage: false,
    imageFormat: 'png',
    blockResources: [...config.defaultBlockedResources],
  };

  if (!raw) return defaults;

  // Viewport
  if (raw.viewport) {
    if (raw.viewport.width !== undefined) {
      const w = Number(raw.viewport.width);
      if (!Number.isInteger(w) || w < 320 || w > 3840) {
        throw new InputValidationError(
          '"options.viewport.width" must be an integer between 320 and 3840',
        );
      }
      defaults.viewport.width = w;
    }
    if (raw.viewport.height !== undefined) {
      const h = Number(raw.viewport.height);
      if (!Number.isInteger(h) || h < 240 || h > 2160) {
        throw new InputValidationError(
          '"options.viewport.height" must be an integer between 240 and 2160',
        );
      }
      defaults.viewport.height = h;
    }
  }

  // Timeout
  if (raw.timeout_ms !== undefined) {
    const t = Number(raw.timeout_ms);
    if (!Number.isInteger(t) || t < 1000 || t > 120000) {
      throw new InputValidationError(
        '"options.timeout_ms" must be an integer between 1000 and 120000',
      );
    }
    defaults.timeoutMs = t;
  }

  // Full page
  if (raw.full_page !== undefined) {
    if (typeof raw.full_page !== 'boolean') {
      throw new InputValidationError('"options.full_page" must be a boolean');
    }
    defaults.fullPage = raw.full_page;
  }

  // Block resources
  if (raw.block_resources !== undefined) {
    if (!Array.isArray(raw.block_resources)) {
      throw new InputValidationError('"options.block_resources" must be an array of strings');
    }
    for (const r of raw.block_resources) {
      if (typeof r !== 'string') {
        throw new InputValidationError(
          '"options.block_resources" must contain only strings',
        );
      }
    }
    defaults.blockResources = raw.block_resources as string[];
  }

  return defaults;
}

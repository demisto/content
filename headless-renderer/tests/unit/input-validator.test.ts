/**
 * Unit tests for input file validation.
 */

import { describe, it, expect } from 'vitest';
import { validateInput, InputValidationError } from '../../src/cli/input-validator.js';

describe('validateInput', () => {
  describe('valid inputs', () => {
    it('should accept minimal valid input with just urls', () => {
      const result = validateInput({ urls: ['https://example.com'] });
      expect(result.urls).toEqual(['https://example.com']);
      expect(result.locale).toBe('en-US');
      expect(result.options.viewport.width).toBe(1280);
      expect(result.options.viewport.height).toBe(720);
      expect(result.options.timeoutMs).toBe(30000);
      expect(result.options.fullPage).toBe(false);
      expect(result.options.imageFormat).toBe('png');
      expect(result.options.blockResources).toEqual(['media', 'font']);
    });

    it('should accept input with locale', () => {
      const result = validateInput({
        urls: ['https://example.com'],
        locale: 'ja-JP',
      });
      expect(result.locale).toBe('ja-JP');
    });

    it('should accept input with custom viewport', () => {
      const result = validateInput({
        urls: ['https://example.com'],
        options: { viewport: { width: 800, height: 600 } },
      });
      expect(result.options.viewport.width).toBe(800);
      expect(result.options.viewport.height).toBe(600);
    });

    it('should accept input with partial viewport (width only)', () => {
      const result = validateInput({
        urls: ['https://example.com'],
        options: { viewport: { width: 1920 } },
      });
      expect(result.options.viewport.width).toBe(1920);
      expect(result.options.viewport.height).toBe(720); // default
    });

    it('should accept input with custom timeout', () => {
      const result = validateInput({
        urls: ['https://example.com'],
        options: { timeout_ms: 60000 },
      });
      expect(result.options.timeoutMs).toBe(60000);
    });

    it('should accept input with full_page option', () => {
      const result = validateInput({
        urls: ['https://example.com'],
        options: { full_page: true },
      });
      expect(result.options.fullPage).toBe(true);
    });

    it('should accept input with custom block_resources', () => {
      const result = validateInput({
        urls: ['https://example.com'],
        options: { block_resources: ['image', 'stylesheet'] },
      });
      expect(result.options.blockResources).toEqual(['image', 'stylesheet']);
    });

    it('should accept multiple URLs', () => {
      const urls = ['https://a.com', 'https://b.com', 'https://c.com'];
      const result = validateInput({ urls });
      expect(result.urls).toEqual(urls);
    });

    it('should accept maximum 1000 URLs', () => {
      const urls = Array.from({ length: 1000 }, (_, i) => `https://example${i}.com`);
      const result = validateInput({ urls });
      expect(result.urls).toHaveLength(1000);
    });
  });

  describe('invalid inputs', () => {
    it('should reject non-object input', () => {
      expect(() => validateInput('string')).toThrow(InputValidationError);
      expect(() => validateInput(null)).toThrow(InputValidationError);
      expect(() => validateInput(42)).toThrow(InputValidationError);
      expect(() => validateInput([])).toThrow(InputValidationError);
    });

    it('should reject missing urls field', () => {
      expect(() => validateInput({})).toThrow(InputValidationError);
      expect(() => validateInput({})).toThrow('"urls" must be an array');
    });

    it('should reject non-array urls', () => {
      expect(() => validateInput({ urls: 'not-array' })).toThrow('"urls" must be an array');
    });

    it('should reject empty urls array', () => {
      expect(() => validateInput({ urls: [] })).toThrow('at least 1 URL');
    });

    it('should reject more than 1000 URLs', () => {
      const urls = Array.from({ length: 1001 }, (_, i) => `https://example${i}.com`);
      expect(() => validateInput({ urls })).toThrow('exceeds maximum');
    });

    it('should reject non-string URL entries', () => {
      expect(() => validateInput({ urls: [123] })).toThrow('must be a string');
    });

    it('should reject empty string URL entries', () => {
      expect(() => validateInput({ urls: [''] })).toThrow('must not be empty');
    });

    it('should reject whitespace-only URL entries', () => {
      expect(() => validateInput({ urls: ['   '] })).toThrow('must not be empty');
    });

    it('should reject non-string locale', () => {
      expect(() => validateInput({ urls: ['https://a.com'], locale: 42 })).toThrow(
        '"locale" must be a string',
      );
    });

    it('should reject viewport width below 320', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { viewport: { width: 100 } },
        }),
      ).toThrow('between 320 and 3840');
    });

    it('should reject viewport width above 3840', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { viewport: { width: 5000 } },
        }),
      ).toThrow('between 320 and 3840');
    });

    it('should reject viewport height below 240', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { viewport: { height: 100 } },
        }),
      ).toThrow('between 240 and 2160');
    });

    it('should reject viewport height above 2160', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { viewport: { height: 5000 } },
        }),
      ).toThrow('between 240 and 2160');
    });

    it('should reject timeout below 1000ms', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { timeout_ms: 500 },
        }),
      ).toThrow('between 1000 and 120000');
    });

    it('should reject timeout above 120000ms', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { timeout_ms: 200000 },
        }),
      ).toThrow('between 1000 and 120000');
    });

    it('should reject non-boolean full_page', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { full_page: 'yes' },
        }),
      ).toThrow('must be a boolean');
    });

    it('should reject non-array block_resources', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { block_resources: 'media' },
        }),
      ).toThrow('must be an array');
    });

    it('should reject non-string entries in block_resources', () => {
      expect(() =>
        validateInput({
          urls: ['https://a.com'],
          options: { block_resources: [123] },
        }),
      ).toThrow('must contain only strings');
    });
  });
});

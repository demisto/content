/**
 * Unit tests for URL sanitizer and screenshot saver utilities.
 * (Tab pool tests require browser mocking — covered in integration tests.)
 */

import { describe, it, expect } from 'vitest';
import { sanitizeUrl, sanitizeBatch } from '../../src/utils/url-sanitizer.js';
import { urlToFilename } from '../../src/utils/screenshot-saver.js';

describe('sanitizeUrl', () => {
  it('should accept valid HTTP URLs', () => {
    const result = sanitizeUrl('https://example.com');
    expect(result.valid).toBe(true);
    expect(result.url).toBe('https://example.com/');
  });

  it('should accept valid HTTP URLs with paths', () => {
    const result = sanitizeUrl('https://example.com/path/to/page?q=test');
    expect(result.valid).toBe(true);
    expect(result.url).toContain('example.com/path/to/page');
  });

  it('should add https:// if protocol is missing', () => {
    const result = sanitizeUrl('example.com');
    expect(result.valid).toBe(true);
    expect(result.url).toBe('https://example.com/');
  });

  it('should reject empty URLs', () => {
    const result = sanitizeUrl('');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Empty');
  });

  it('should reject localhost', () => {
    const result = sanitizeUrl('http://localhost:3000');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Blocked hostname');
  });

  it('should reject 127.0.0.1', () => {
    const result = sanitizeUrl('http://127.0.0.1');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Blocked hostname');
  });

  it('should reject private IPs (10.x.x.x)', () => {
    const result = sanitizeUrl('http://10.0.0.1');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Blocked private IP');
  });

  it('should reject private IPs (192.168.x.x)', () => {
    const result = sanitizeUrl('http://192.168.1.1');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Blocked private IP');
  });

  it('should reject private IPs (172.16-31.x.x)', () => {
    const result = sanitizeUrl('http://172.16.0.1');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Blocked private IP');
  });

  it('should reject AWS metadata endpoint', () => {
    const result = sanitizeUrl('http://169.254.169.254/latest/meta-data');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Blocked hostname');
  });

  it('should reject invalid URLs', () => {
    const result = sanitizeUrl('not a url at all !!!');
    expect(result.valid).toBe(false);
  });

  it('should reject very long URLs', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(2100);
    const result = sanitizeUrl(longUrl);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('maximum length');
  });

  it('should accept HTTP (not just HTTPS)', () => {
    const result = sanitizeUrl('http://example.com');
    expect(result.valid).toBe(true);
  });
});

describe('sanitizeBatch', () => {
  it('should separate valid and invalid URLs', () => {
    const urls = [
      'https://example.com',
      'http://localhost',
      'https://google.com',
      '',
    ];

    const { valid, invalid } = sanitizeBatch(urls);
    expect(valid).toHaveLength(2);
    expect(invalid).toHaveLength(2);
  });

  it('should handle empty batch', () => {
    const { valid, invalid } = sanitizeBatch([]);
    expect(valid).toHaveLength(0);
    expect(invalid).toHaveLength(0);
  });
});

describe('urlToFilename', () => {
  it('should strip protocol and convert to safe filename', () => {
    expect(urlToFilename('https://example.com')).toBe('example.com');
  });

  it('should replace special characters with underscores', () => {
    expect(urlToFilename('https://example.com/path?q=test&a=1')).toBe(
      'example.com_path_q_test_a_1',
    );
  });

  it('should truncate long URLs to 200 characters', () => {
    const longUrl = 'https://example.com/' + 'a'.repeat(300);
    const filename = urlToFilename(longUrl);
    expect(filename.length).toBeLessThanOrEqual(200);
  });

  it('should handle URLs with subdomains', () => {
    expect(urlToFilename('https://sub.domain.example.com')).toBe(
      'sub.domain.example.com',
    );
  });

  it('should collapse multiple underscores', () => {
    const result = urlToFilename('https://example.com/a///b');
    expect(result).not.toContain('__');
  });
});

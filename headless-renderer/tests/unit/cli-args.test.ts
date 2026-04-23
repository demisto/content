/**
 * Unit tests for CLI argument parsing.
 */

import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import { parseCliArgs } from '../../src/cli/args.js';

describe('parseCliArgs', () => {
  let exitSpy: Mock;
  let stderrSpy: Mock;

  beforeEach(() => {
    exitSpy = vi.fn((() => {
      throw new Error('process.exit called');
    }) as never);
    vi.spyOn(process, 'exit').mockImplementation(exitSpy);
    stderrSpy = vi.fn(() => true);
    vi.spyOn(process.stderr, 'write').mockImplementation(stderrSpy as never);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should parse required --input argument', () => {
    const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
    expect(args.input).toBe('batch.json');
  });

  it('should parse short -i flag', () => {
    const args = parseCliArgs(['node', 'index.js', '-i', 'batch.json']);
    expect(args.input).toBe('batch.json');
  });

  it('should use default output-dir when not specified', () => {
    const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
    expect(args.outputDir).toBe('./screenshots');
  });

  it('should parse --output-dir argument', () => {
    const args = parseCliArgs([
      'node', 'index.js',
      '--input', 'batch.json',
      '--output-dir', '/tmp/shots',
    ]);
    expect(args.outputDir).toBe('/tmp/shots');
  });

  it('should parse short -o flag for output-dir', () => {
    const args = parseCliArgs([
      'node', 'index.js',
      '-i', 'batch.json',
      '-o', '/tmp/shots',
    ]);
    expect(args.outputDir).toBe('/tmp/shots');
  });

  it('should use default log-level when not specified', () => {
    const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
    expect(args.logLevel).toBe('info');
  });

  it('should parse --log-level argument', () => {
    const args = parseCliArgs([
      'node', 'index.js',
      '--input', 'batch.json',
      '--log-level', 'debug',
    ]);
    expect(args.logLevel).toBe('debug');
  });

  it('should parse --max-concurrency as number', () => {
    const args = parseCliArgs([
      'node', 'index.js',
      '--input', 'batch.json',
      '--max-concurrency', '5',
    ]);
    expect(args.maxConcurrency).toBe(5);
  });

  it('should parse --tab-timeout as number', () => {
    const args = parseCliArgs([
      'node', 'index.js',
      '--input', 'batch.json',
      '--tab-timeout', '60000',
    ]);
    expect(args.tabTimeout).toBe(60000);
  });

  it('should parse --tab-memory-limit as number', () => {
    const args = parseCliArgs([
      'node', 'index.js',
      '--input', 'batch.json',
      '--tab-memory-limit', '200',
    ]);
    expect(args.tabMemoryLimit).toBe(200);
  });

  it('should leave optional numeric args undefined when not provided', () => {
    const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
    expect(args.maxConcurrency).toBeUndefined();
    expect(args.tabTimeout).toBeUndefined();
    expect(args.tabMemoryLimit).toBeUndefined();
  });

  it('should exit with code 2 when --input is missing', () => {
    expect(() => parseCliArgs(['node', 'index.js'])).toThrow('process.exit called');
    expect(exitSpy).toHaveBeenCalledWith(2);
    expect(stderrSpy).toHaveBeenCalled();
    const output = (stderrSpy.mock.calls[0][0] as string);
    expect(output).toContain('--input');
  });

  it('should exit with code 2 for invalid --log-level', () => {
    expect(() =>
      parseCliArgs(['node', 'index.js', '--input', 'batch.json', '--log-level', 'verbose']),
    ).toThrow('process.exit called');
    expect(exitSpy).toHaveBeenCalledWith(2);
  });

  it('should exit with code 2 for non-numeric --max-concurrency', () => {
    expect(() =>
      parseCliArgs(['node', 'index.js', '--input', 'batch.json', '--max-concurrency', 'abc']),
    ).toThrow('process.exit called');
    expect(exitSpy).toHaveBeenCalledWith(2);
  });

  it('should exit with code 2 for zero --tab-timeout', () => {
    expect(() =>
      parseCliArgs(['node', 'index.js', '--input', 'batch.json', '--tab-timeout', '0']),
    ).toThrow('process.exit called');
    expect(exitSpy).toHaveBeenCalledWith(2);
  });

  it('should exit with code 2 for negative --tab-memory-limit', () => {
    expect(() =>
      parseCliArgs(['node', 'index.js', '--input', 'batch.json', '--tab-memory-limit=-10']),
    ).toThrow('process.exit called');
    expect(exitSpy).toHaveBeenCalledWith(2);
  });

  it('should exit with code 0 on --help', () => {
    expect(() => parseCliArgs(['node', 'index.js', '--help'])).toThrow('process.exit called');
    expect(exitSpy).toHaveBeenCalledWith(0);
    expect(stderrSpy).toHaveBeenCalled();
    const output = (stderrSpy.mock.calls[0][0] as string);
    expect(output).toContain('Usage:');
  });

  it('should exit with code 0 on -h', () => {
    expect(() => parseCliArgs(['node', 'index.js', '-h'])).toThrow('process.exit called');
    expect(exitSpy).toHaveBeenCalledWith(0);
  });

  it('should parse all arguments together', () => {
    const args = parseCliArgs([
      'node', 'index.js',
      '-i', 'input.json',
      '-o', './out',
      '--log-level', 'warn',
      '--max-concurrency', '8',
      '--tab-timeout', '45000',
      '--tab-memory-limit', '256',
    ]);

    expect(args.input).toBe('input.json');
    expect(args.outputDir).toBe('./out');
    expect(args.logLevel).toBe('warn');
    expect(args.maxConcurrency).toBe(8);
    expect(args.tabTimeout).toBe(45000);
    expect(args.tabMemoryLimit).toBe(256);
  });

  // ── Persistence flags ──

  describe('--no-persist flag', () => {
    it('should default to false (persist enabled)', () => {
      const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
      expect(args.noPersist).toBe(false);
    });

    it('should be true when --no-persist is passed', () => {
      const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json', '--no-persist']);
      expect(args.noPersist).toBe(true);
    });
  });

  describe('--state-file flag', () => {
    it('should default to /tmp/render-cli-browser.json', () => {
      const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
      expect(args.stateFile).toBe('/tmp/render-cli-browser.json');
    });

    it('should accept a custom state file path', () => {
      const args = parseCliArgs([
        'node', 'index.js',
        '--input', 'batch.json',
        '--state-file', '/var/run/browser.json',
      ]);
      expect(args.stateFile).toBe('/var/run/browser.json');
    });
  });

  describe('--kill-browser flag', () => {
    it('should default to false', () => {
      const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
      expect(args.killBrowser).toBe(false);
    });

    it('should be true when --kill-browser is passed', () => {
      const args = parseCliArgs(['node', 'index.js', '--kill-browser']);
      expect(args.killBrowser).toBe(true);
    });

    it('should not require --input when --kill-browser is set', () => {
      // Should not throw — --input is not required for management commands
      const args = parseCliArgs(['node', 'index.js', '--kill-browser']);
      expect(args.killBrowser).toBe(true);
      expect(args.input).toBe('');
    });
  });

  describe('--browser-status flag', () => {
    it('should default to false', () => {
      const args = parseCliArgs(['node', 'index.js', '--input', 'batch.json']);
      expect(args.browserStatus).toBe(false);
    });

    it('should be true when --browser-status is passed', () => {
      const args = parseCliArgs(['node', 'index.js', '--browser-status']);
      expect(args.browserStatus).toBe(true);
    });

    it('should not require --input when --browser-status is set', () => {
      const args = parseCliArgs(['node', 'index.js', '--browser-status']);
      expect(args.browserStatus).toBe(true);
      expect(args.input).toBe('');
    });
  });

  describe('combined persistence flags', () => {
    it('should parse --no-persist with --state-file together', () => {
      const args = parseCliArgs([
        'node', 'index.js',
        '--input', 'batch.json',
        '--no-persist',
        '--state-file', '/custom/path.json',
      ]);
      expect(args.noPersist).toBe(true);
      expect(args.stateFile).toBe('/custom/path.json');
    });

    it('should parse --kill-browser with --state-file', () => {
      const args = parseCliArgs([
        'node', 'index.js',
        '--kill-browser',
        '--state-file', '/custom/path.json',
      ]);
      expect(args.killBrowser).toBe(true);
      expect(args.stateFile).toBe('/custom/path.json');
    });
  });
});

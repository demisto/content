/**
 * CLI argument parsing using Node.js built-in `parseArgs` from `node:util`.
 *
 * Supported flags:
 *   --input, -i       Path to JSON input file (required for batch mode)
 *   --output-dir, -o  Directory to save screenshots (default: ./screenshots)
 *   --log-level       Log level: debug, info, warn, error (default: info)
 *   --max-concurrency Override max concurrent tabs
 *   --tab-timeout     Per-tab timeout in ms (default: 30000)
 *   --tab-memory-limit Per-tab memory limit in MB (default: 150)
 *   --no-persist      Disable persistent browser (one-shot mode)
 *   --state-file      Path to browser state file (default: /tmp/render-cli-browser.json)
 *   --kill-browser    Kill the persistent browser and exit
 *   --browser-status  Show persistent browser status and exit
 *   --help, -h        Show usage information
 */

import { parseArgs } from 'node:util';

export interface CliArgs {
  input: string;
  outputDir: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  maxConcurrency?: number;
  tabTimeout?: number;
  tabMemoryLimit?: number;
  noPersist: boolean;
  stateFile: string;
  killBrowser: boolean;
  browserStatus: boolean;
}

const USAGE = `
Usage: render-cli --input <file> [options]

Options:
  --input, -i           Path to JSON input file (required for batch mode)
  --output-dir, -o      Directory to save screenshots (default: ./screenshots)
  --log-level           Log level: debug, info, warn, error (default: info)
  --max-concurrency     Override max concurrent tabs
  --tab-timeout         Per-tab timeout in ms (default: 30000)
  --tab-memory-limit    Per-tab memory limit in MB (default: 150)
  --no-persist          Disable persistent browser (one-shot mode)
  --state-file          Path to browser state file (default: /tmp/render-cli-browser.json)
  --kill-browser        Kill the persistent browser and exit
  --browser-status      Show persistent browser status and exit
  --help, -h            Show this help message
`.trim();

const VALID_LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;

/**
 * Parse CLI arguments from process.argv.
 * Prints usage and exits on --help or missing required args.
 */
export function parseCliArgs(argv: string[] = process.argv): CliArgs {
  const { values } = parseArgs({
    args: argv.slice(2),
    options: {
      input: { type: 'string', short: 'i' },
      'output-dir': { type: 'string', short: 'o' },
      'log-level': { type: 'string' },
      'max-concurrency': { type: 'string' },
      'tab-timeout': { type: 'string' },
      'tab-memory-limit': { type: 'string' },
      'no-persist': { type: 'boolean', default: false },
      'state-file': { type: 'string' },
      'kill-browser': { type: 'boolean', default: false },
      'browser-status': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h' },
    },
    strict: true,
  });

  if (values.help) {
    // Write help to stderr so stdout stays clean for JSON output
    process.stderr.write(USAGE + '\n');
    process.exit(0);
  }

  const killBrowser = values['kill-browser'] ?? false;
  const browserStatus = values['browser-status'] ?? false;

  // --input is only required for batch mode (not management commands)
  if (!values.input && !killBrowser && !browserStatus) {
    process.stderr.write('Error: --input (-i) is required\n\n' + USAGE + '\n');
    process.exit(2);
  }

  // Validate log level
  const logLevel = (values['log-level'] ?? 'info') as string;
  if (!VALID_LOG_LEVELS.includes(logLevel as typeof VALID_LOG_LEVELS[number])) {
    process.stderr.write(
      `Error: --log-level must be one of: ${VALID_LOG_LEVELS.join(', ')}. Got: "${logLevel}"\n`,
    );
    process.exit(2);
  }

  // Parse optional numeric arguments
  const maxConcurrency = parseOptionalInt(values['max-concurrency'], 'max-concurrency');
  const tabTimeout = parseOptionalInt(values['tab-timeout'], 'tab-timeout');
  const tabMemoryLimit = parseOptionalInt(values['tab-memory-limit'], 'tab-memory-limit');

  return {
    input: values.input ?? '',
    outputDir: values['output-dir'] ?? './screenshots',
    logLevel: logLevel as CliArgs['logLevel'],
    maxConcurrency,
    tabTimeout,
    tabMemoryLimit,
    noPersist: values['no-persist'] ?? false,
    stateFile: values['state-file'] ?? '/tmp/render-cli-browser.json',
    killBrowser,
    browserStatus,
  };
}

/**
 * Parse an optional string value as a positive integer.
 * Exits with code 2 on invalid input.
 */
function parseOptionalInt(value: string | undefined, name: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = parseInt(value, 10);
  if (isNaN(parsed) || parsed <= 0) {
    process.stderr.write(`Error: --${name} must be a positive integer. Got: "${value}"\n`);
    process.exit(2);
  }
  return parsed;
}

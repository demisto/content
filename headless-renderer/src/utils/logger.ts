/**
 * Structured logger using pino.
 * Logs to **stderr** so stdout remains clean for JSON output.
 * Provides child loggers for each module.
 */

import pino from 'pino';
import { config } from '../config.js';

export const logger = pino(
  {
    level: config.logLevel,
    transport:
      process.env.NODE_ENV === 'development'
        ? { target: 'pino-pretty', options: { colorize: true, destination: 2 } }
        : undefined,
    base: {
      service: 'headless-renderer',
    },
    timestamp: pino.stdTimeFunctions.isoTime,
    serializers: {
      err: pino.stdSerializers.err,
    },
  },
  pino.destination({ fd: 2 }), // fd 2 = stderr
);

export function createChildLogger(module: string): pino.Logger {
  return logger.child({ module });
}

import type { IncomingMessage } from 'node:http';
import { logger } from '../src/logger.js';

interface FixtureRequest extends IncomingMessage {
  headers: IncomingMessage['headers'] & { authorization?: string };
}

export function logRequest(req: FixtureRequest): void {
  // Deliberately unsafe: auth headers are production credentials.
  logger.info({ authorization: req.headers.authorization }, 'request received');
}

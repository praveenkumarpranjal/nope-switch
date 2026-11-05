import type { IncomingMessage } from 'node:http';
import { logger } from '../src/logger.js';

export function logRequest(req: IncomingMessage): void {
  logger.info({ userId: req.headers['x-user-id'] }, 'request received');
}

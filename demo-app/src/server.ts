import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { authenticate } from './auth.js';
import { logger } from './logger.js';

const port = Number(process.env.PORT ?? 3000);

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const requestId = randomUUID();
  const correlationMeta = { requestId, path: req.url ?? '/' };

  if (req.url === '/health') {
    logger.info(correlationMeta, 'health check');
    res.writeHead(200, { 'content-type': 'application/json', 'x-request-id': requestId });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  if (req.url === '/v1/profile' && req.method === 'GET') {
    const identity = authenticate(req.headers);
    if (!identity) {
      logger.warn(correlationMeta, 'authentication rejected');
      res.writeHead(401, { 'content-type': 'application/json', 'x-request-id': requestId });
      res.end(JSON.stringify({ error: 'authentication required' }));
      return;
    }

    logger.info({ ...correlationMeta, userId: identity.userId }, 'profile served');
    res.writeHead(200, { 'content-type': 'application/json', 'x-request-id': requestId });
    res.end(JSON.stringify({ userId: identity.userId, roles: identity.roles }));
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json', 'x-request-id': requestId });
  res.end(JSON.stringify({ error: 'not found' }));
});

server.listen(port, () => {
  logger.info({ port }, 'payments-api demo listening');
});

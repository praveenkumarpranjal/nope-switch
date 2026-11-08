import test from 'node:test';
import assert from 'node:assert/strict';
import { redactForLog } from '../src/logger.js';

test('redacts credential material from nested log metadata', () => {
  const redacted = redactForLog({
    requestId: 'req-01H',
    authorization: 'Bearer secret',
    nested: { accessToken: 'abc', harmless: 'ok' },
    list: [{ x_api_key: 'key-1' }, { note: 'safe' }],
  });

  assert.equal((redacted as Record<string, string>).authorization, '[REDACTED]');
  assert.equal((redacted as any).nested.accessToken, '[REDACTED]');
  assert.equal((redacted as any).list[0].x_api_key, '[REDACTED]');
  assert.equal((redacted as any).list[1].note, 'safe');
});

test('leaves non-credential metadata untouched', () => {
  const meta = { userId: 'user_123', route: '/health', count: 2 };
  assert.deepEqual(redactForLog(meta), meta);
});

test('circular metadata stays serializable and credentials stay redacted', () => {
  const meta: Record<string, unknown> = { password: 'private-value' };
  meta.self = meta;
  const output = redactForLog(meta);
  assert.deepEqual(output, { password: '[REDACTED]', self: '[Circular]' });
  assert.doesNotThrow(() => JSON.stringify(output));
});

test('bigint IDs and shared references do not crash JSON logging', () => {
  const shared = { userId: 9007199254740993n };
  const output = redactForLog({ first: shared, second: shared });
  assert.deepEqual(output, { first: { userId: '9007199254740993' }, second: { userId: '9007199254740993' } });
  assert.doesNotThrow(() => JSON.stringify(output));
});

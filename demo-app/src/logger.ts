const forbiddenKeys = new Set([
  'authorization',
  'xaccesstoken',
  'accesstoken',
  'idtoken',
  'xapikey',
  'apikey',
  'password',
  'secret',
]);

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export type LogMeta = Readonly<Record<string, unknown>>;

export function redactForLog(value: unknown): unknown {
  return redactValue(value, new WeakSet<object>(), 0);
}

function redactValue(value: unknown, ancestors: WeakSet<object>, depth: number): unknown {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (ancestors.has(value)) {
    return '[Circular]';
  }
  if (depth >= 50) {
    return '[Maximum depth]';
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => redactValue(item, ancestors, depth + 1));
    }
    const redacted: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      redacted[key] = forbiddenKeys.has(normalizeKey(key)) ? '[REDACTED]' : redactValue(nested, ancestors, depth + 1);
    }
    return redacted;
  } finally {
    ancestors.delete(value);
  }
}

function emit(level: 'info' | 'warn' | 'error', meta: LogMeta, message: string): void {
  const line = JSON.stringify({
    level,
    message,
    service: 'nope-demo-target',
    ...(redactForLog(meta) as Record<string, unknown>),
    time: new Date().toISOString(),
  });
  process.stdout.write(`${line}\n`);
}

export const logger = {
  info: (meta: LogMeta, message: string) => emit('info', meta, message),
  warn: (meta: LogMeta, message: string) => emit('warn', meta, message),
  error: (meta: LogMeta, message: string) => emit('error', meta, message),
};

import { writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const target = join('src', 'violation.ts');
if (existsSync(target)) {
  console.error('src/violation.ts already exists. Remove it after recording the failure.');
  process.exit(1);
}

writeFileSync(
  target,
  `import { logger } from './logger.js';

export function unsafeDemoLog(req: Request): void {
  logger.info({ authorization: req.headers.get('authorization'), route: '/oops' }, 'credential demo');
}
`,
  { mode: 0o600 },
);
console.log('Wrote src/violation.ts. It is intentionally unsafe and untracked.');
console.log('Run your CI policy now; it must fail with Scar 001.');

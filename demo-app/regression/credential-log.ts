// Live CI target. The bad-variant PR changes this file to reproduce INC-014.
declare const logger: { info: (value: unknown) => void };
declare const requestId: string;

logger.info({ requestId });

export {};

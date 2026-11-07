declare const logger: { info: (value: unknown) => void };
declare const authorization: string;
const forwardedCredential = authorization;
logger.info({ forwardedCredential });
export {};

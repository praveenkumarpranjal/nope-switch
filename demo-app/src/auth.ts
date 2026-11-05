import type { IncomingHttpHeaders } from 'node:http';

export interface AuthIdentity {
  readonly userId: string;
  readonly roles: readonly string[];
}

export function authenticate(headers: IncomingHttpHeaders): AuthIdentity | null {
  const rawUserId = headers['x-user-id'];
  const rawRoles = headers['x-roles'];
  const userId = Array.isArray(rawUserId) ? rawUserId[0] : rawUserId;
  const roles = Array.isArray(rawRoles) ? rawRoles[0] : rawRoles;
  const credential = headers.authorization;

  // A production service issues short-lived, opaque session cookies or JWTs.
  // This deterministic demo only accepts the presence of a well-formed bearer token;
  // never log `credential`.
  if (credential && /^Bearer [A-Za-z0-9._-]{12,}$/.test(credential) && userId && /^[A-Za-z0-9-]{1,80}$/.test(userId)) {
    return {
      userId,
      roles: (roles ?? 'user').split(',').map((role) => role.trim()).filter(Boolean).slice(0, 10),
    };
  }
  return null;
}

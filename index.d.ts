/**
 * Generates or verifies a time-windowed HMAC-SHA256 handshake token.
 *
 * @param secret - The shared secret key.
 * @param tokenToVerify - Optional token to verify. Pass undefined or null to generate a new token.
 * @param windowSeconds - Time window in seconds (required, positive number).
 * @param bufferSeconds - Clock buffer in seconds (required, non-negative number).
 * @returns A 64-character hex token string if generating, or a boolean if verifying.
 */
export function handshakeToken(
  secret: string,
  tokenToVerify: string | null | undefined,
  windowSeconds: number,
  bufferSeconds: number
): string | boolean;

export default handshakeToken;


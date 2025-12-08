/**
 * Access Token Management
 */

import { randomBytes } from 'crypto';

export interface AccessToken {
  token: string;
  actor: string;
  expiresAt: number;
  permissions: string[];
}

export class AccessTokenManager {
  private tokens: Map<string, AccessToken> = new Map();

  /**
   * Generate a new access token
   */
  generateToken(actor: string, permissions: string[], ttlMs: number = 3600000): AccessToken {
    const token = randomBytes(32).toString('base64');
    const expiresAt = Date.now() + ttlMs;

    const accessToken: AccessToken = {
      token,
      actor,
      expiresAt,
      permissions,
    };

    this.tokens.set(token, accessToken);
    return accessToken;
  }

  /**
   * Verify and retrieve token information
   */
  verifyToken(token: string): AccessToken | null {
    const accessToken = this.tokens.get(token);
    
    if (!accessToken) {
      return null;
    }

    // Check expiration
    if (Date.now() > accessToken.expiresAt) {
      this.tokens.delete(token);
      return null;
    }

    return accessToken;
  }

  /**
   * Revoke a token
   */
  revokeToken(token: string): boolean {
    return this.tokens.delete(token);
  }

  /**
   * Clean up expired tokens
   */
  cleanupExpired(): number {
    const now = Date.now();
    let count = 0;

    for (const [token, accessToken] of this.tokens.entries()) {
      if (now > accessToken.expiresAt) {
        this.tokens.delete(token);
        count++;
      }
    }

    return count;
  }
}

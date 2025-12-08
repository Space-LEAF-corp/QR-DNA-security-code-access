/**
 * Access Token Management
 */

import { createHash, randomBytes } from 'crypto';
import type { AccessToken } from '../core/Types.js';

export class AccessTokenManager {
  private tokens: Map<string, AccessToken>;
  private salt: string;

  constructor(salt?: string) {
    this.tokens = new Map();
    this.salt = salt || randomBytes(32).toString('hex');
  }

  /**
   * Generate a new access token
   */
  generateToken(
    userId: string,
    scope: string[],
    expiryHours: number = 24
  ): AccessToken {
    const token = this.createSecureToken(userId);
    const expiresAt = Date.now() + expiryHours * 60 * 60 * 1000;

    const accessToken: AccessToken = {
      token,
      userId,
      expiresAt,
      scope,
    };

    this.tokens.set(token, accessToken);
    return accessToken;
  }

  /**
   * Validate an access token
   */
  validateToken(token: string): AccessToken | null {
    const accessToken = this.tokens.get(token);

    if (!accessToken) {
      return null;
    }

    // Check if token is expired
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
   * Revoke all tokens for a user
   */
  revokeUserTokens(userId: string): number {
    let revokedCount = 0;
    
    for (const [token, accessToken] of this.tokens.entries()) {
      if (accessToken.userId === userId) {
        this.tokens.delete(token);
        revokedCount++;
      }
    }

    return revokedCount;
  }

  /**
   * Clean up expired tokens
   */
  cleanupExpiredTokens(): number {
    let cleanedCount = 0;
    const now = Date.now();

    for (const [token, accessToken] of this.tokens.entries()) {
      if (now > accessToken.expiresAt) {
        this.tokens.delete(token);
        cleanedCount++;
      }
    }

    return cleanedCount;
  }

  /**
   * Check if user has specific scope
   */
  hasScope(token: string, requiredScope: string): boolean {
    const accessToken = this.validateToken(token);
    
    if (!accessToken) {
      return false;
    }

    return accessToken.scope.includes(requiredScope);
  }

  /**
   * Create a secure token hash
   */
  private createSecureToken(userId: string): string {
    const random = randomBytes(32).toString('hex');
    const data = `${userId}:${random}:${Date.now()}:${this.salt}`;
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Get active token count
   */
  getActiveTokenCount(): number {
    return this.tokens.size;
  }

  /**
   * Get tokens for a specific user
   */
  getUserTokens(userId: string): AccessToken[] {
    const userTokens: AccessToken[] = [];
    
    for (const accessToken of this.tokens.values()) {
      if (accessToken.userId === userId) {
        userTokens.push(accessToken);
      }
    }

    return userTokens;
  }
}

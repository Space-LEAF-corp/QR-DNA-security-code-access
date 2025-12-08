/**
 * QR-DNA Authentication with AJV validation and KeyManager/KMS integration
 */

import Ajv from 'ajv';
import type { QrDnaToken, VerificationResult } from '../core/Types.js';
import { KeyManager } from './keyManager.js';
import { KmsProvider } from './kmsProvider.js';

const ajv = new Ajv();

const qrDnaTokenSchema = {
  type: 'object',
  properties: {
    id: { type: 'string', minLength: 1 },
    publicKey: { type: 'string', minLength: 1 },
    signature: { type: 'string', minLength: 1 },
    timestamp: { type: 'number', minimum: 0 },
    metadata: { type: 'object' }
  },
  required: ['id', 'publicKey', 'signature', 'timestamp'],
  additionalProperties: true
};

const validateToken = ajv.compile(qrDnaTokenSchema);

export class QrDnaAuth {
  private keyManager: KeyManager;
  private kmsProvider?: KmsProvider;
  private useKms: boolean;

  constructor(options: { useKms?: boolean; kmsRegion?: string; kmsKeyId?: string } = {}) {
    this.keyManager = new KeyManager();
    this.useKms = options.useKms || false;

    if (this.useKms && options.kmsRegion) {
      this.kmsProvider = new KmsProvider({
        region: options.kmsRegion,
        keyId: options.kmsKeyId
      });
    }
  }

  validateTokenStructure(token: QrDnaToken): boolean {
    return validateToken(token);
  }

  async verifyToken(token: QrDnaToken): Promise<VerificationResult> {
    // First validate structure
    if (!this.validateTokenStructure(token)) {
      return {
        valid: false,
        error: 'Invalid token structure',
        timestamp: Date.now()
      };
    }

    // Check token age (reject tokens older than 5 minutes)
    const tokenAge = Date.now() - token.timestamp;
    if (tokenAge > 5 * 60 * 1000) {
      return {
        valid: false,
        error: 'Token expired',
        timestamp: Date.now()
      };
    }

    // Verify signature
    try {
      const message = this.createMessageToSign(token);
      const signature = this.decodeSignature(token.signature);

      let valid = false;
      if (this.useKms && this.kmsProvider) {
        valid = await this.kmsProvider.verify(message, signature);
      } else {
        valid = this.keyManager.verify(token.publicKey, message, signature);
      }

      return {
        valid,
        timestamp: Date.now()
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Verification failed',
        timestamp: Date.now()
      };
    }
  }

  createToken(keyId: string, data: Record<string, unknown> = {}): QrDnaToken {
    const tokenId = this.generateTokenId();
    const timestamp = Date.now();

    const token: Partial<QrDnaToken> = {
      id: tokenId,
      timestamp,
      metadata: data
    };

    // Get public key
    const keyInfo = this.keyManager.getKeyInfo(keyId);
    if (!keyInfo) {
      throw new Error(`Key not found: ${keyId}`);
    }

    token.publicKey = keyInfo.publicKey;

    // Sign the token
    const message = this.createMessageToSign(token as QrDnaToken);
    const signature = this.keyManager.sign(keyId, message);
    token.signature = this.encodeSignature(signature);

    return token as QrDnaToken;
  }

  private createMessageToSign(token: Partial<QrDnaToken>): Uint8Array {
    const data = JSON.stringify({
      id: token.id,
      timestamp: token.timestamp,
      metadata: token.metadata
    });
    return new TextEncoder().encode(data);
  }

  private generateTokenId(): string {
    return `token-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }

  private encodeSignature(signature: Uint8Array): string {
    return Buffer.from(signature).toString('base64');
  }

  private decodeSignature(signature: string): Uint8Array {
    return Buffer.from(signature, 'base64');
  }

  getKeyManager(): KeyManager {
    return this.keyManager;
  }

  getKmsProvider(): KmsProvider | undefined {
    return this.kmsProvider;
  }
}

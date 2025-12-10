/**
 * Verify signatures against the key registry
 */

import type { QrDnaToken, VerificationResult } from '../core/Types.js';
import { FileKeyRegistry } from './keyRegistry/fileRegistry.js';
import { DynamoKeyRegistry } from './keyRegistry/dynamoRegistry.js';
import nacl from 'tweetnacl';

type KeyRegistry = FileKeyRegistry | DynamoKeyRegistry;

let registryInstance: KeyRegistry | null = null;

export function initializeRegistry(type: 'file' | 'dynamodb', config?: Record<string, string>): void {
  if (type === 'file') {
    registryInstance = new FileKeyRegistry(config?.path || './data/keys.json');
  } else if (type === 'dynamodb') {
    if (!config?.region || !config?.tableName) {
      throw new Error('DynamoDB registry requires region and tableName');
    }
    registryInstance = new DynamoKeyRegistry({
      region: config.region,
      tableName: config.tableName,
      endpoint: config.endpoint
    });
  }
}

export async function verifyWithRegistry(token: QrDnaToken): Promise<VerificationResult> {
  if (!registryInstance) {
    // Initialize with default file registry if not configured
    initializeRegistry('file');
    await registryInstance!.initialize();
  }

  try {
    // Create message from token
    const message = new TextEncoder().encode(
      JSON.stringify({
        id: token.id,
        timestamp: token.timestamp,
        metadata: token.metadata
      })
    );

    // Decode signature and public key
    const signature = Buffer.from(token.signature, 'base64');
    const publicKey = Buffer.from(token.publicKey, 'base64');

    // Verify signature
    const valid = nacl.sign.detached.verify(message, signature, publicKey);

    if (!valid) {
      return {
        valid: false,
        error: 'Invalid signature',
        timestamp: Date.now()
      };
    }

    // Check if key exists in registry and is not revoked
    const keyInfo = await registryInstance!.getKey(token.id);
    if (!keyInfo) {
      return {
        valid: false,
        error: 'Key not found in registry',
        timestamp: Date.now()
      };
    }

    if (keyInfo.revoked) {
      return {
        valid: false,
        error: 'Key has been revoked',
        timestamp: Date.now()
      };
    }

    // Check if key is expired
    if (keyInfo.expiresAt && keyInfo.expiresAt < Date.now()) {
      return {
        valid: false,
        error: 'Key has expired',
        timestamp: Date.now()
      };
    }

    return {
      valid: true,
      keyId: keyInfo.keyId,
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

export function getRegistry(): KeyRegistry | null {
  return registryInstance;
}

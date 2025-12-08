/**
 * Key Manager for development environment
 * Uses tweetnacl for Ed25519 key generation and signing
 */

import nacl from 'tweetnacl';
import type { KeyPair, KeyInfo } from '../core/Types.js';

export class KeyManager {
  private keys: Map<string, KeyPair>;
  private keyInfo: Map<string, KeyInfo>;

  constructor() {
    this.keys = new Map();
    this.keyInfo = new Map();
  }

  generateKey(): KeyInfo {
    const keyPair = nacl.sign.keyPair();
    const keyId = this.generateKeyId();
    
    this.keys.set(keyId, {
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey
    });

    const keyInfo: KeyInfo = {
      keyId,
      publicKey: this.encodePublicKey(keyPair.publicKey),
      algorithm: 'ed25519',
      createdAt: Date.now()
    };

    this.keyInfo.set(keyId, keyInfo);
    return keyInfo;
  }

  sign(keyId: string, message: Uint8Array): Uint8Array {
    const keyPair = this.keys.get(keyId);
    if (!keyPair) {
      throw new Error(`Key not found: ${keyId}`);
    }

    return nacl.sign.detached(message, keyPair.secretKey);
  }

  verify(publicKey: string, message: Uint8Array, signature: Uint8Array): boolean {
    const pubKey = this.decodePublicKey(publicKey);
    return nacl.sign.detached.verify(message, signature, pubKey);
  }

  getKeyInfo(keyId: string): KeyInfo | undefined {
    return this.keyInfo.get(keyId);
  }

  listKeys(): KeyInfo[] {
    return Array.from(this.keyInfo.values());
  }

  revokeKey(keyId: string): void {
    const info = this.keyInfo.get(keyId);
    if (info) {
      info.revoked = true;
      this.keyInfo.set(keyId, info);
    }
  }

  private generateKeyId(): string {
    return `key-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }

  private encodePublicKey(publicKey: Uint8Array): string {
    return Buffer.from(publicKey).toString('base64');
  }

  private decodePublicKey(publicKey: string): Uint8Array {
    return Buffer.from(publicKey, 'base64');
  }

  exportPublicKey(keyId: string): string | undefined {
    const info = this.keyInfo.get(keyId);
    return info?.publicKey;
  }
}

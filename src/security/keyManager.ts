/**
 * KeyManager - Production-grade key management for QR-DNA attestations
 * 
 * PRODUCTION NOTES:
 * ==================
 * This implementation uses in-memory storage for development and testing.
 * 
 * FOR PRODUCTION DEPLOYMENT:
 * 1. Replace generateKeyPair() to use HSM/KMS (AWS KMS, Azure Key Vault, Google Cloud KMS, etc.)
 *    - Never store private keys in application memory or local storage
 *    - Use KMS to generate and store keys securely
 *    - Only export public keys for verification
 * 
 * 2. Replace in-memory keyStore with persistent storage:
 *    - Use a secure database (encrypted at rest)
 *    - Store only public keys and metadata (kid, status, timestamps)
 *    - Implement proper access controls and audit logging
 * 
 * 3. Key Rotation Workflow:
 *    - Generate new keypair in KMS/HSM
 *    - Import new public key as 'active'
 *    - Mark old key as 'deprecated' (grace period: 30-90 days recommended)
 *    - Publish updated public keys to well-known endpoint (e.g., /.well-known/jwks.json)
 *    - Monitor usage of deprecated keys
 *    - After grace period, revoke old keys
 *    - Remove revoked keys after retention period (for audit compliance)
 * 
 * 4. Monitoring & Alerts:
 *    - Alert on deprecated key usage (indicates clients need updating)
 *    - Alert on revoked key verification attempts (potential security issue)
 *    - Track key age and alert before expiration
 *    - Log all key operations for security audit
 */

import * as crypto from 'crypto';
import * as nacl from 'tweetnacl';

export type KeyStatus = 'active' | 'deprecated' | 'revoked';

export interface KeyMetadata {
  kid: string;
  publicKeyBase64: string;
  status: KeyStatus;
  createdAt: Date;
  expiresAt?: Date;
  deprecatedAt?: Date;
  revokedAt?: Date;
}

export interface KeyPair {
  kid: string;
  publicKeyBase64: string;
  secretKeyUint8Array: Uint8Array; // NEVER persist this in production - see notes above
}

export class KeyManager {
  private keyStore: Map<string, KeyMetadata>;

  constructor() {
    this.keyStore = new Map();
  }

  /**
   * Generate an Ed25519 keypair
   * 
   * PRODUCTION: Replace with KMS/HSM key generation
   * - AWS KMS: kms.generateDataKeyPair()
   * - Azure: keyVaultClient.createKey()
   * - GCP: keyManagementClient.createCryptoKeyVersion()
   * 
   * @returns KeyPair with kid (derived from public key), public key, and secret key
   */
  generateKeyPair(): KeyPair {
    // Generate Ed25519 keypair using tweetnacl
    const keyPair = nacl.sign.keyPair();
    
    // Convert public key to base64
    const publicKeyBase64 = Buffer.from(keyPair.publicKey).toString('base64');
    
    // Generate deterministic kid from public key (SHA-256 hash)
    const kid = this.deriveKid(publicKeyBase64);
    
    // SECURITY NOTE: secretKey is returned for testing purposes only
    // In production, this should never leave the HSM/KMS
    return {
      kid,
      publicKeyBase64,
      secretKeyUint8Array: keyPair.secretKey
    };
  }

  /**
   * Derive a deterministic Key ID from the public key
   * Uses SHA-256 hash of the public key, truncated to 16 chars for readability
   */
  private deriveKid(publicKeyBase64: string): string {
    const hash = crypto
      .createHash('sha256')
      .update(publicKeyBase64)
      .digest('hex');
    return hash.substring(0, 16); // First 16 chars of hash
  }

  /**
   * Import a public key into the key store
   * 
   * PRODUCTION: Store in secure database with audit logging
   * 
   * @param kid Key identifier
   * @param publicKeyBase64 Base64-encoded public key
   * @param opts Optional parameters (status, expiresAt)
   */
  importPublicKey(
    kid: string,
    publicKeyBase64: string,
    opts?: { status?: KeyStatus; expiresAt?: Date }
  ): void {
    const metadata: KeyMetadata = {
      kid,
      publicKeyBase64,
      status: opts?.status || 'active',
      createdAt: new Date(),
      expiresAt: opts?.expiresAt
    };

    this.keyStore.set(kid, metadata);
  }

  /**
   * Rotate keys: mark current active key as deprecated and import new key
   * 
   * PRODUCTION WORKFLOW:
   * 1. Generate new key in KMS/HSM
   * 2. Import new public key as 'active'
   * 3. Mark old key as 'deprecated' (don't revoke yet - grace period)
   * 4. Publish updated JWKS to /.well-known/jwks.json
   * 5. Monitor deprecated key usage
   * 6. After grace period (30-90 days), call revokeKey() on old kid
   * 7. Update monitoring alerts and documentation
   * 
   * @param newPublicKeyBase64 Optional new public key (if not provided, generates new pair)
   * @returns The new active key ID
   */
  rotateKey(newPublicKeyBase64?: string): string {
    // Mark current active key as deprecated
    const currentKey = this.getCurrentKey();
    if (currentKey) {
      const metadata = this.keyStore.get(currentKey.kid);
      if (metadata) {
        metadata.status = 'deprecated';
        metadata.deprecatedAt = new Date();
        this.keyStore.set(currentKey.kid, metadata);
      }
    }

    // Generate or use provided new key
    let newKid: string;
    if (newPublicKeyBase64) {
      newKid = this.deriveKid(newPublicKeyBase64);
      this.importPublicKey(newKid, newPublicKeyBase64, { status: 'active' });
    } else {
      // Generate new keypair (for testing - in production, use KMS)
      const newKeyPair = this.generateKeyPair();
      newKid = newKeyPair.kid;
      this.importPublicKey(newKid, newKeyPair.publicKeyBase64, { status: 'active' });
    }

    return newKid;
  }

  /**
   * Revoke a key (mark as revoked, verification will fail)
   * 
   * PRODUCTION: Log to audit trail, alert security team
   * 
   * @param kid Key ID to revoke
   */
  revokeKey(kid: string): void {
    const metadata = this.keyStore.get(kid);
    if (metadata) {
      metadata.status = 'revoked';
      metadata.revokedAt = new Date();
      this.keyStore.set(kid, metadata);
    }
  }

  /**
   * Get public key by key ID
   * 
   * @param kid Key ID
   * @returns Base64-encoded public key or null if not found
   */
  getPublicKey(kid: string): string | null {
    const metadata = this.keyStore.get(kid);
    return metadata ? metadata.publicKeyBase64 : null;
  }

  /**
   * Get key metadata (including status)
   * 
   * @param kid Key ID
   * @returns Full key metadata or null if not found
   */
  getKeyMetadata(kid: string): KeyMetadata | null {
    return this.keyStore.get(kid) || null;
  }

  /**
   * Get the current active key
   * 
   * @returns Active key metadata or null if no active key
   */
  getCurrentKey(): KeyMetadata | null {
    for (const metadata of this.keyStore.values()) {
      if (metadata.status === 'active') {
        return metadata;
      }
    }
    return null;
  }

  /**
   * List all keys (for audit and monitoring)
   * 
   * PRODUCTION: Implement filtering, pagination, and audit logging
   * 
   * @returns Array of all key metadata
   */
  listKeys(): KeyMetadata[] {
    return Array.from(this.keyStore.values());
  }

  /**
   * Clear all keys (for testing only)
   * DO NOT use in production
   */
  clearAllKeys(): void {
    this.keyStore.clear();
  }
}

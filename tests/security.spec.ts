/**
 * Security Test Suite for QR-DNA Attestation
 * 
 * Tests cover:
 * - AJV schema validation
 * - Key generation and rotation
 * - Signature verification
 * - Expiry handling
 * - Key status (active/deprecated/revoked)
 */

import * as nacl from 'tweetnacl';
import { KeyManager } from '../src/security/keyManager';
import { QrDnaAuth, AttestationMessage, AttestationPayload } from '../src/security/qrDnaAuth';

describe('KeyManager', () => {
  let keyManager: KeyManager;

  beforeEach(() => {
    keyManager = new KeyManager();
  });

  describe('generateKeyPair', () => {
    it('should generate a valid Ed25519 keypair', () => {
      const keyPair = keyManager.generateKeyPair();

      expect(keyPair.kid).toBeDefined();
      expect(keyPair.publicKeyBase64).toBeDefined();
      expect(keyPair.secretKeyUint8Array).toBeDefined();
      expect(keyPair.kid.length).toBe(16); // SHA-256 hash truncated to 16 chars
    });

    it('should generate different keypairs on each call', () => {
      const keyPair1 = keyManager.generateKeyPair();
      const keyPair2 = keyManager.generateKeyPair();

      expect(keyPair1.kid).not.toBe(keyPair2.kid);
      expect(keyPair1.publicKeyBase64).not.toBe(keyPair2.publicKeyBase64);
    });

    it('should generate deterministic kid from public key', () => {
      const keyPair = keyManager.generateKeyPair();
      
      // Import the same public key and verify kid matches
      keyManager.importPublicKey(keyPair.kid, keyPair.publicKeyBase64);
      const retrieved = keyManager.getPublicKey(keyPair.kid);
      
      expect(retrieved).toBe(keyPair.publicKeyBase64);
    });
  });

  describe('importPublicKey', () => {
    it('should import a public key with default active status', () => {
      const keyPair = keyManager.generateKeyPair();
      keyManager.importPublicKey(keyPair.kid, keyPair.publicKeyBase64);

      const metadata = keyManager.getKeyMetadata(keyPair.kid);
      expect(metadata).toBeDefined();
      expect(metadata?.status).toBe('active');
      expect(metadata?.publicKeyBase64).toBe(keyPair.publicKeyBase64);
    });

    it('should import a public key with custom status', () => {
      const keyPair = keyManager.generateKeyPair();
      keyManager.importPublicKey(keyPair.kid, keyPair.publicKeyBase64, { 
        status: 'deprecated' 
      });

      const metadata = keyManager.getKeyMetadata(keyPair.kid);
      expect(metadata?.status).toBe('deprecated');
    });
  });

  describe('rotateKey', () => {
    it('should mark current active key as deprecated and create new active key', () => {
      // Generate and import first key
      const keyPair1 = keyManager.generateKeyPair();
      keyManager.importPublicKey(keyPair1.kid, keyPair1.publicKeyBase64);

      // Verify first key is active
      expect(keyManager.getCurrentKey()?.kid).toBe(keyPair1.kid);

      // Rotate to new key
      const newKid = keyManager.rotateKey();

      // Verify old key is deprecated
      const oldMetadata = keyManager.getKeyMetadata(keyPair1.kid);
      expect(oldMetadata?.status).toBe('deprecated');
      expect(oldMetadata?.deprecatedAt).toBeDefined();

      // Verify new key is active
      expect(keyManager.getCurrentKey()?.kid).toBe(newKid);
      expect(keyManager.getCurrentKey()?.status).toBe('active');
    });

    it('should accept a specific new public key during rotation', () => {
      // Generate and import first key
      const keyPair1 = keyManager.generateKeyPair();
      keyManager.importPublicKey(keyPair1.kid, keyPair1.publicKeyBase64);

      // Generate new keypair externally
      const keyPair2 = keyManager.generateKeyPair();

      // Rotate with specific public key
      const newKid = keyManager.rotateKey(keyPair2.publicKeyBase64);

      expect(newKid).toBe(keyPair2.kid);
      expect(keyManager.getCurrentKey()?.publicKeyBase64).toBe(keyPair2.publicKeyBase64);
    });
  });

  describe('revokeKey', () => {
    it('should mark a key as revoked', () => {
      const keyPair = keyManager.generateKeyPair();
      keyManager.importPublicKey(keyPair.kid, keyPair.publicKeyBase64);

      keyManager.revokeKey(keyPair.kid);

      const metadata = keyManager.getKeyMetadata(keyPair.kid);
      expect(metadata?.status).toBe('revoked');
      expect(metadata?.revokedAt).toBeDefined();
    });
  });

  describe('getPublicKey', () => {
    it('should return public key for valid kid', () => {
      const keyPair = keyManager.generateKeyPair();
      keyManager.importPublicKey(keyPair.kid, keyPair.publicKeyBase64);

      const publicKey = keyManager.getPublicKey(keyPair.kid);
      expect(publicKey).toBe(keyPair.publicKeyBase64);
    });

    it('should return null for invalid kid', () => {
      const publicKey = keyManager.getPublicKey('invalid-kid');
      expect(publicKey).toBeNull();
    });
  });

  describe('listKeys', () => {
    it('should return all keys', () => {
      const keyPair1 = keyManager.generateKeyPair();
      const keyPair2 = keyManager.generateKeyPair();
      
      keyManager.importPublicKey(keyPair1.kid, keyPair1.publicKeyBase64);
      keyManager.importPublicKey(keyPair2.kid, keyPair2.publicKeyBase64);

      const keys = keyManager.listKeys();
      expect(keys.length).toBe(2);
      expect(keys.some(k => k.kid === keyPair1.kid)).toBe(true);
      expect(keys.some(k => k.kid === keyPair2.kid)).toBe(true);
    });
  });
});

describe('QrDnaAuth', () => {
  let keyManager: KeyManager;
  let qrDnaAuth: QrDnaAuth;
  let keyPair: { kid: string; publicKeyBase64: string; secretKeyUint8Array: Uint8Array };

  beforeEach(() => {
    keyManager = new KeyManager();
    qrDnaAuth = new QrDnaAuth(keyManager);
    
    // Generate and import a test keypair
    keyPair = keyManager.generateKeyPair();
    keyManager.importPublicKey(keyPair.kid, keyPair.publicKeyBase64);
  });

  /**
   * Helper function to create and sign an attestation
   */
  function createSignedAttestation(
    attestationData: Partial<AttestationMessage> & { actor: string; scope: string }
  ): AttestationPayload {
    const now = Math.floor(Date.now() / 1000);
    
    const attestationMessage: AttestationMessage = {
      kid: keyPair.kid,
      alg: 'EdDSA',
      typ: 'QR-DNA-Attestation',
      iat: now,
      exp: now + 3600, // 1 hour from now
      ...attestationData,
      actor: attestationData.actor,
      scope: attestationData.scope
    };

    const messageStr = JSON.stringify(attestationMessage);
    const messageBytes = Buffer.from(messageStr, 'utf8');
    
    // Sign with the secret key
    const signature = nacl.sign.detached(messageBytes, keyPair.secretKeyUint8Array);
    const signatureBase64 = Buffer.from(signature).toString('base64');

    return {
      actor: attestationData.actor,
      scope: attestationData.scope,
      attestationMessage: messageStr,
      attestationSignatureBase64: signatureBase64,
      kid: keyPair.kid
    };
  }

  describe('Schema Validation', () => {
    it('should accept valid attestation message', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(true);
    });

    it('should reject attestation with missing required fields', () => {
      const now = Math.floor(Date.now() / 1000);
      const invalidMessage = {
        kid: keyPair.kid,
        alg: 'EdDSA',
        typ: 'QR-DNA-Attestation',
        iat: now,
        // Missing: exp, actor, scope
      };

      const messageStr = JSON.stringify(invalidMessage);
      const messageBytes = Buffer.from(messageStr, 'utf8');
      const signature = nacl.sign.detached(messageBytes, keyPair.secretKeyUint8Array);

      const payload: AttestationPayload = {
        actor: 'user:alice',
        scope: 'read:documents',
        attestationMessage: messageStr,
        attestationSignatureBase64: Buffer.from(signature).toString('base64'),
        kid: keyPair.kid
      };

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Schema validation failed');
    });

    it('should reject attestation with invalid alg field', () => {
      const now = Math.floor(Date.now() / 1000);
      const invalidMessage = {
        kid: keyPair.kid,
        alg: 'RS256', // Should be 'EdDSA'
        typ: 'QR-DNA-Attestation',
        iat: now,
        exp: now + 3600,
        actor: 'user:alice',
        scope: 'read:documents'
      };

      const messageStr = JSON.stringify(invalidMessage);
      const messageBytes = Buffer.from(messageStr, 'utf8');
      const signature = nacl.sign.detached(messageBytes, keyPair.secretKeyUint8Array);

      const payload: AttestationPayload = {
        actor: 'user:alice',
        scope: 'read:documents',
        attestationMessage: messageStr,
        attestationSignatureBase64: Buffer.from(signature).toString('base64'),
        kid: keyPair.kid
      };

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Schema validation failed');
    });

    it('should reject attestation with invalid typ field', () => {
      const now = Math.floor(Date.now() / 1000);
      const invalidMessage = {
        kid: keyPair.kid,
        alg: 'EdDSA',
        typ: 'Invalid-Type',
        iat: now,
        exp: now + 3600,
        actor: 'user:alice',
        scope: 'read:documents'
      };

      const messageStr = JSON.stringify(invalidMessage);
      const messageBytes = Buffer.from(messageStr, 'utf8');
      const signature = nacl.sign.detached(messageBytes, keyPair.secretKeyUint8Array);

      const payload: AttestationPayload = {
        actor: 'user:alice',
        scope: 'read:documents',
        attestationMessage: messageStr,
        attestationSignatureBase64: Buffer.from(signature).toString('base64'),
        kid: keyPair.kid
      };

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Schema validation failed');
    });

    it('should accept attestation with optional nonce and meta fields', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents',
        nonce: 'random-nonce-12345',
        meta: { requestId: 'req-001', clientVersion: '1.0.0' }
      });

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(true);
    });

    it('should reject attestation with malformed JSON', () => {
      const payload: AttestationPayload = {
        actor: 'user:alice',
        scope: 'read:documents',
        attestationMessage: 'not-valid-json{',
        attestationSignatureBase64: 'fake-signature',
        kid: keyPair.kid
      };

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid JSON');
    });
  });

  describe('Timestamp Validation', () => {
    it('should reject expired attestation', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents',
        iat: now - 7200, // 2 hours ago
        exp: now - 3600  // Expired 1 hour ago
      });

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('expired');
    });

    it('should reject attestation with future iat', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents',
        iat: now + 7200, // 2 hours in future (beyond clock skew)
        exp: now + 10800
      });

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('not yet valid');
    });

    it('should accept attestation within clock skew tolerance', () => {
      const now = Math.floor(Date.now() / 1000);
      
      // Create attestation with iat slightly in future (within clock skew)
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents',
        iat: now + 60, // 1 minute in future
        exp: now + 3660
      });

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(true);
    });

    it('should reject attestation where exp <= iat', () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents',
        iat: now,
        exp: now - 1 // exp before iat
      });

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('greater than issued time');
    });

    it('should respect custom clock skew configuration', () => {
      const customClockSkew = 10000; // 10 seconds
      const customAuth = new QrDnaAuth(keyManager, customClockSkew);
      
      const now = Math.floor(Date.now() / 1000);
      
      // Create attestation expired by 20 seconds (beyond custom skew)
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents',
        iat: now - 3620,
        exp: now - 20
      });

      const result = customAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('expired');
    });
  });

  describe('Signature Verification', () => {
    it('should accept valid signature', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(true);
    });

    it('should reject invalid signature', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Tamper with signature
      payload.attestationSignatureBase64 = 'invalid-signature-base64';

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid signature');
    });

    it('should reject signature from different key', () => {
      // Generate a different keypair
      const otherKeyPair = keyManager.generateKeyPair();
      keyManager.importPublicKey(otherKeyPair.kid, otherKeyPair.publicKeyBase64);

      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Change kid to point to different key
      payload.kid = otherKeyPair.kid;
      const attestationObj = JSON.parse(payload.attestationMessage as string);
      attestationObj.kid = otherKeyPair.kid;
      payload.attestationMessage = JSON.stringify(attestationObj);

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid signature');
    });

    it('should reject tampered attestation message', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Tamper with actor in message but keep signature
      const attestationObj = JSON.parse(payload.attestationMessage as string);
      attestationObj.actor = 'user:bob';
      payload.attestationMessage = JSON.stringify(attestationObj);

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Invalid signature');
    });
  });

  describe('Key Rotation', () => {
    it('should verify attestation signed with deprecated key', () => {
      // Create attestation with first key
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Rotate to new key (old key becomes deprecated)
      keyManager.rotateKey();

      // Verification should still succeed but with warning
      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(true);
      expect(result.keyStatus).toBe('deprecated');
      expect(result.warnings).toBeDefined();
      expect(result.warnings?.[0]).toContain('deprecated');
    });

    it('should reject attestation signed with revoked key', () => {
      // Create attestation with first key
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Revoke the key
      keyManager.revokeKey(keyPair.kid);

      // Verification should fail
      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('revoked');
      expect(result.keyStatus).toBe('revoked');
    });

    it('should verify attestation with new key after rotation', () => {
      // Rotate to new key
      const newKid = keyManager.rotateKey();
      
      // Get the new active key
      const currentKey = keyManager.getCurrentKey();
      expect(currentKey?.kid).toBe(newKid);
      
      // Create attestation with new key (we need the secret key)
      // For this test, we'll generate a new keypair and import it
      const testKeyPair = keyManager.generateKeyPair();
      keyManager.rotateKey(testKeyPair.publicKeyBase64);
      
      const now = Math.floor(Date.now() / 1000);
      const attestationMessage: AttestationMessage = {
        kid: testKeyPair.kid,
        alg: 'EdDSA',
        typ: 'QR-DNA-Attestation',
        iat: now,
        exp: now + 3600,
        actor: 'user:bob',
        scope: 'write:documents'
      };

      const messageStr = JSON.stringify(attestationMessage);
      const messageBytes = Buffer.from(messageStr, 'utf8');
      const signature = nacl.sign.detached(messageBytes, testKeyPair.secretKeyUint8Array);

      const payload: AttestationPayload = {
        actor: 'user:bob',
        scope: 'write:documents',
        attestationMessage: messageStr,
        attestationSignatureBase64: Buffer.from(signature).toString('base64'),
        kid: testKeyPair.kid
      };

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(true);
      expect(result.keyStatus).toBe('active');
    });
  });

  describe('Actor and Scope Validation', () => {
    it('should reject attestation with mismatched actor', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Change actor in payload but not in signed message
      payload.actor = 'user:bob';

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Actor mismatch');
    });

    it('should reject attestation with mismatched scope', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Change scope in payload but not in signed message
      payload.scope = 'write:documents';

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Scope mismatch');
    });

    it('should reject attestation with mismatched kid', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Change kid in payload but not in signed message
      payload.kid = 'different-kid-123';

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Key ID mismatch');
    });
  });

  describe('Key Not Found', () => {
    it('should reject attestation with unknown kid', () => {
      const payload = createSignedAttestation({
        actor: 'user:alice',
        scope: 'read:documents'
      });

      // Use a kid that doesn't exist in key manager
      payload.kid = 'unknown-kid-9999';
      const attestationObj = JSON.parse(payload.attestationMessage as string);
      attestationObj.kid = 'unknown-kid-9999';
      payload.attestationMessage = JSON.stringify(attestationObj);

      const result = qrDnaAuth.isAuthorized(payload);
      expect(result.valid).toBe(false);
      expect(result.reason).toContain('Key not found');
    });
  });
});

/**
 * QR-DNA Authentication Service
 * 
 * Provides attestation validation with:
 * - JSON schema validation (AJV)
 * - Cryptographic signature verification (Ed25519 via tweetnacl)
 * - Key rotation support via KeyManager
 * - Clock skew tolerance for iat/exp validation
 * - Key status checking (active/deprecated/revoked)
 */

import Ajv, { ValidateFunction } from 'ajv';
import * as nacl from 'tweetnacl';
import { KeyManager } from './keyManager';
import * as attestationSchema from './schemas/qrDnaAttestation.schema.json';

// Default clock skew: 5 minutes (300,000 ms)
const DEFAULT_CLOCK_SKEW_MS = 300000;

export interface AttestationMessage {
  kid: string;
  alg: 'EdDSA';
  typ: 'QR-DNA-Attestation';
  iat: number;
  exp: number;
  actor: string;
  scope: string;
  nonce?: string;
  meta?: Record<string, unknown>;
}

export interface AttestationPayload {
  actor: string;
  scope: string;
  attestationMessage: string | AttestationMessage; // JSON string or parsed object
  attestationSignatureBase64: string;
  kid: string;
}

export interface VerificationResult {
  valid: boolean;
  reason?: string;
  keyStatus?: 'active' | 'deprecated' | 'revoked';
  warnings?: string[];
}

export class QrDnaAuth {
  private keyManager: KeyManager;
  private ajv: Ajv;
  private validateAttestation: ValidateFunction;
  private clockSkewMs: number;

  constructor(keyManager: KeyManager, clockSkewMs?: number) {
    this.keyManager = keyManager;
    this.clockSkewMs = clockSkewMs !== undefined ? clockSkewMs : DEFAULT_CLOCK_SKEW_MS;
    
    // Initialize AJV with strict validation
    this.ajv = new Ajv({ 
      strict: true,
      allErrors: true 
    });
    
    // Compile the attestation schema
    this.validateAttestation = this.ajv.compile(attestationSchema);
  }

  /**
   * Verify Ed25519 signature using tweetnacl
   * 
   * @param message Original message that was signed
   * @param signatureBase64 Base64-encoded signature
   * @param publicKeyBase64 Base64-encoded public key
   * @returns true if signature is valid
   */
  private verifySignature(
    message: string,
    signatureBase64: string,
    publicKeyBase64: string
  ): boolean {
    try {
      // Decode signature and public key from base64
      const signature = Buffer.from(signatureBase64, 'base64');
      const publicKey = Buffer.from(publicKeyBase64, 'base64');
      const messageBytes = Buffer.from(message, 'utf8');

      // Verify signature using tweetnacl
      return nacl.sign.detached.verify(messageBytes, signature, publicKey);
    } catch (error) {
      // Any error during verification means invalid signature
      return false;
    }
  }

  /**
   * Validate attestation message against JSON schema
   * 
   * @param attestationMsg Parsed attestation message object
   * @returns Validation result with errors if invalid
   */
  private validateSchema(attestationMsg: unknown): { valid: boolean; errors?: string } {
    const valid = this.validateAttestation(attestationMsg);
    
    if (!valid) {
      const errors = this.ajv.errorsText(this.validateAttestation.errors);
      return { valid: false, errors };
    }
    
    return { valid: true };
  }

  /**
   * Validate timestamp with clock skew tolerance
   * 
   * @param iat Issued at timestamp (seconds)
   * @param exp Expiration timestamp (seconds)
   * @returns Validation result
   */
  private validateTimestamps(iat: number, exp: number): { valid: boolean; reason?: string } {
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const clockSkewSec = Math.floor(this.clockSkewMs / 1000);

    // Check if exp is greater than iat
    if (exp <= iat) {
      return { 
        valid: false, 
        reason: 'Expiration time (exp) must be greater than issued time (iat)' 
      };
    }

    // Check if attestation is not yet valid (iat too far in future)
    if (iat > nowSec + clockSkewSec) {
      return { 
        valid: false, 
        reason: `Attestation not yet valid (iat: ${iat}, now: ${nowSec}, skew: ${clockSkewSec}s)` 
      };
    }

    // Check if attestation has expired
    if (exp < nowSec - clockSkewSec) {
      return { 
        valid: false, 
        reason: `Attestation expired (exp: ${exp}, now: ${nowSec}, skew: ${clockSkewSec}s)` 
      };
    }

    return { valid: true };
  }

  /**
   * Authorize an attestation payload
   * 
   * Validates:
   * 1. JSON schema compliance
   * 2. Timestamp validity (iat/exp with clock skew)
   * 3. Cryptographic signature
   * 4. Key status (revoked keys fail, deprecated keys warn)
   * 5. Actor and scope match
   * 
   * @param payload Attestation payload with actor, scope, attestationMessage, signature, kid
   * @returns Verification result with validity status and details
   */
  isAuthorized(payload: AttestationPayload): VerificationResult {
    const warnings: string[] = [];

    // Parse attestationMessage if it's a string
    // Keep original string for signature verification (property order matters!)
    let attestationMsg: AttestationMessage;
    let messageStr: string;
    
    try {
      if (typeof payload.attestationMessage === 'string') {
        messageStr = payload.attestationMessage;
        attestationMsg = JSON.parse(messageStr);
      } else {
        // If object provided, convert to string for signature verification
        // Note: This may cause issues if property order differs from signed message
        attestationMsg = payload.attestationMessage;
        messageStr = JSON.stringify(attestationMsg);
      }
    } catch (error) {
      return {
        valid: false,
        reason: 'Invalid JSON in attestationMessage'
      };
    }

    // Step 1: Validate JSON schema
    const schemaValidation = this.validateSchema(attestationMsg);
    if (!schemaValidation.valid) {
      return {
        valid: false,
        reason: `Schema validation failed: ${schemaValidation.errors}`
      };
    }

    // Step 2: Validate timestamps (iat/exp)
    const timestampValidation = this.validateTimestamps(attestationMsg.iat, attestationMsg.exp);
    if (!timestampValidation.valid) {
      return {
        valid: false,
        reason: timestampValidation.reason
      };
    }

    // Step 3: Validate kid matches
    if (attestationMsg.kid !== payload.kid) {
      return {
        valid: false,
        reason: `Key ID mismatch: attestation kid (${attestationMsg.kid}) != payload kid (${payload.kid})`
      };
    }

    // Step 4: Get key metadata and check status
    const keyMetadata = this.keyManager.getKeyMetadata(payload.kid);
    if (!keyMetadata) {
      return {
        valid: false,
        reason: `Key not found: ${payload.kid}`
      };
    }

    // Revoked keys always fail
    if (keyMetadata.status === 'revoked') {
      return {
        valid: false,
        reason: `Key has been revoked: ${payload.kid}`,
        keyStatus: 'revoked'
      };
    }

    // Deprecated keys generate warnings but don't fail verification
    if (keyMetadata.status === 'deprecated') {
      warnings.push(
        `Warning: Key ${payload.kid} is deprecated. Please rotate to the current active key. ` +
        `Deprecated since: ${keyMetadata.deprecatedAt?.toISOString()}`
      );
    }

    // Step 5: Verify cryptographic signature
    // Use the messageStr we prepared earlier (preserves original JSON formatting)
    const signatureValid = this.verifySignature(
      messageStr,
      payload.attestationSignatureBase64,
      keyMetadata.publicKeyBase64
    );

    if (!signatureValid) {
      return {
        valid: false,
        reason: 'Invalid signature',
        keyStatus: keyMetadata.status
      };
    }

    // Step 6: Validate actor matches
    if (attestationMsg.actor !== payload.actor) {
      return {
        valid: false,
        reason: `Actor mismatch: attestation actor (${attestationMsg.actor}) != payload actor (${payload.actor})`
      };
    }

    // Step 7: Validate scope matches
    if (attestationMsg.scope !== payload.scope) {
      return {
        valid: false,
        reason: `Scope mismatch: attestation scope (${attestationMsg.scope}) != payload scope (${payload.scope})`
      };
    }

    // All validations passed
    return {
      valid: true,
      keyStatus: keyMetadata.status,
      warnings: warnings.length > 0 ? warnings : undefined
    };
  }

  /**
   * Legacy method for backward compatibility
   * Verifies signature with a specific kid
   */
  verifySignatureWithKid(message: string, signatureBase64: string, kid: string): boolean {
    const publicKey = this.keyManager.getPublicKey(kid);
    if (!publicKey) {
      return false;
    }
    return this.verifySignature(message, signatureBase64, publicKey);
 * QR-DNA Authentication: Signature verification using tweetnacl
 */

import nacl from 'tweetnacl';
import type { AccessRequest, QrDnaAttestation } from '../core/Types.js';

/**
 * Verify a signature using tweetnacl Ed25519
 */
export function verifySignature(
  publicKeyBase64: string,
  messageStr: string,
  signatureBase64: string
): boolean {
  try {
    // Convert base64 public key to Uint8Array
    const publicKey = Buffer.from(publicKeyBase64, 'base64');
    
    // Convert message to Uint8Array
    const message = Buffer.from(messageStr, 'utf-8');
    
    // Convert base64 signature to Uint8Array
    const signature = Buffer.from(signatureBase64, 'base64');
    
    // Verify using tweetnacl
    return nacl.sign.detached.verify(message, signature, publicKey);
  } catch (error) {
    // Invalid base64 or verification error
    return false;
  }
}

/**
 * Helper to convert base64 public key to Uint8Array
 */
export function publicKeyFromBase64(publicKeyBase64: string): Uint8Array {
  return Buffer.from(publicKeyBase64, 'base64');
}

export class QrDnaAuth {
  /**
   * Check if an access request is authorized
   */
  static isAuthorized(request: AccessRequest): boolean {
    const { actor, action, attestation } = request;

    // If attestation is provided, verify signature
    if (attestation) {
      const isValidSignature = verifySignature(
        attestation.publicKey,
        attestation.message,
        attestation.signature
      );

      if (!isValidSignature) {
        return false;
      }

      // Additional authorization logic based on verified attestation
      // For now, if signature is valid, allow the action
      return true;
    }

    // Fallback policy: Only LEIF_STEWARD can do BODY_MERGE without attestation
    if (action === 'BODY_MERGE' && actor === 'LEIF_STEWARD') {
      return true;
    }

    // Default deny for BODY_MERGE without attestation
    if (action === 'BODY_MERGE') {
      return false;
    }

    // Allow other actions by default (can be customized)
    return true;
  }
}

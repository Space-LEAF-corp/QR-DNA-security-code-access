/**
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

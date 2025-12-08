/**
 * QR-DNA Authentication using TweetNaCl signature verification
 */

import nacl from 'tweetnacl';
import type { QRDnaCredential } from '../core/Types.js';

export class QRDnaAuth {
  /**
   * Verify a QR-DNA signature using Ed25519
   */
  static verifySignature(credential: QRDnaCredential): boolean {
    try {
      // Decode base64 public key
      const publicKey = QRDnaAuth.base64ToUint8Array(credential.publicKey);
      
      // Decode base64 signature
      const signature = QRDnaAuth.base64ToUint8Array(credential.signature);
      
      // Convert message to Uint8Array
      const message = new TextEncoder().encode(credential.message);
      
      // Verify signature
      return nacl.sign.detached.verify(message, signature, publicKey);
    } catch (error) {
      console.error('Error verifying QR-DNA signature:', error);
      return false;
    }
  }

  /**
   * Verify signature with timestamp validation
   */
  static verifySignatureWithTimestamp(
    credential: QRDnaCredential,
    maxAgeSeconds: number = 300
  ): boolean {
    // First verify the signature
    if (!QRDnaAuth.verifySignature(credential)) {
      return false;
    }

    // Check timestamp is recent
    const now = Date.now();
    const age = now - credential.timestamp;
    
    if (age > maxAgeSeconds * 1000 || age < 0) {
      return false;
    }

    return true;
  }

  /**
   * Create a QR-DNA credential structure (for testing)
   */
  static createCredential(
    publicKey: Uint8Array,
    privateKey: Uint8Array,
    message: string
  ): QRDnaCredential {
    const messageBytes = new TextEncoder().encode(message);
    const signature = nacl.sign.detached(messageBytes, privateKey);

    return {
      publicKey: QRDnaAuth.uint8ArrayToBase64(publicKey),
      signature: QRDnaAuth.uint8ArrayToBase64(signature),
      message,
      timestamp: Date.now(),
    };
  }

  /**
   * Helper: Convert base64 string to Uint8Array
   */
  private static base64ToUint8Array(base64: string): Uint8Array {
    const binaryString = Buffer.from(base64, 'base64');
    return new Uint8Array(binaryString);
  }

  /**
   * Helper: Convert Uint8Array to base64 string
   */
  private static uint8ArrayToBase64(array: Uint8Array): string {
    return Buffer.from(array).toString('base64');
  }

  /**
   * Generate a new keypair (for testing/setup)
   */
  static generateKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    const keypair = nacl.sign.keyPair();
    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.secretKey,
    };
  }
}

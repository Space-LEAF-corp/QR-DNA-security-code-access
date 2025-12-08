import nacl from 'tweetnacl';

/**
 * Key pair for digital signatures
 */
export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * Cryptographic utilities using TweetNaCl
 * 
 * Provides:
 * - Key pair generation
 * - Digital signatures
 * - Signature verification
 */
export class CryptoManager {
  /**
   * Generates a new Ed25519 key pair for signing
   * @returns A new key pair with public and secret keys
   */
  public static generateKeyPair(): KeyPair {
    const keyPair = nacl.sign.keyPair();
    return {
      publicKey: keyPair.publicKey,
      secretKey: keyPair.secretKey
    };
  }

  /**
   * Signs data with a secret key
   * @param data - The data to sign
   * @param secretKey - The secret key to sign with
   * @returns Base64-encoded signature
   */
  public static sign(data: string, secretKey: Uint8Array): string {
    const dataBytes = new TextEncoder().encode(data);
    const signature = nacl.sign.detached(dataBytes, secretKey);
    return this.toBase64(signature);
  }

  /**
   * Verifies a signature
   * @param data - The original data
   * @param signature - Base64-encoded signature
   * @param publicKey - The public key to verify with
   * @returns True if signature is valid, false otherwise
   */
  public static verify(data: string, signature: string, publicKey: Uint8Array): boolean {
    try {
      const dataBytes = new TextEncoder().encode(data);
      const signatureBytes = this.fromBase64(signature);
      return nacl.sign.detached.verify(dataBytes, signatureBytes, publicKey);
    } catch {
      return false;
    }
  }

  /**
   * Converts Uint8Array to Base64 string
   * @param bytes - Byte array to convert
   * @returns Base64-encoded string
   */
  public static toBase64(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64');
  }

  /**
   * Converts Base64 string to Uint8Array
   * @param base64 - Base64-encoded string
   * @returns Byte array
   */
  public static fromBase64(base64: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }

  /**
   * Converts a key to Base64 for storage/transmission
   * @param key - Key as Uint8Array
   * @returns Base64-encoded key
   */
  public static keyToBase64(key: Uint8Array): string {
    return this.toBase64(key);
  }

  /**
   * Converts a Base64-encoded key back to Uint8Array
   * @param base64Key - Base64-encoded key
   * @returns Key as Uint8Array
   */
  public static keyFromBase64(base64Key: string): Uint8Array {
    return this.fromBase64(base64Key);
  }
}

/**
 * Creates a signing function bound to a specific secret key
 * @param secretKey - The secret key to use for signing
 * @returns A function that signs data
 */
export function createSigningFunction(secretKey: Uint8Array): (data: string) => string {
  return (data: string) => CryptoManager.sign(data, secretKey);
}

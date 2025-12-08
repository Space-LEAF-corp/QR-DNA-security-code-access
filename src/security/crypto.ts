/**
 * Cryptographic utilities using tweetnacl
 */

import nacl from 'tweetnacl';

/**
 * Generate a new Ed25519 key pair
 */
export function generateKeyPair(): nacl.SignKeyPair {
  return nacl.sign.keyPair();
}

/**
 * Sign data with a secret key
 */
export async function sign(data: string, secretKey: Uint8Array): Promise<string> {
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(data);
  const signature = nacl.sign.detached(dataBytes, secretKey);
  return Buffer.from(signature).toString('hex');
}

/**
 * Verify a signature
 */
export async function verify(
  data: string,
  signature: string,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(data);
    const signatureBytes = Buffer.from(signature, 'hex');
    return nacl.sign.detached.verify(dataBytes, signatureBytes, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generate a random nonce
 */
export function generateNonce(): Uint8Array {
  return nacl.randomBytes(nacl.box.nonceLength);
}

/**
 * Encrypt data using public key encryption
 */
export function encrypt(
  data: string,
  recipientPublicKey: Uint8Array,
  senderSecretKey: Uint8Array
): { encrypted: string; nonce: string } {
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(data);
  const nonce = generateNonce();
  
  const encrypted = nacl.box(
    dataBytes,
    nonce,
    recipientPublicKey,
    senderSecretKey
  );

  return {
    encrypted: Buffer.from(encrypted).toString('hex'),
    nonce: Buffer.from(nonce).toString('hex'),
  };
}

/**
 * Decrypt data using public key encryption
 */
export function decrypt(
  encrypted: string,
  nonce: string,
  senderPublicKey: Uint8Array,
  recipientSecretKey: Uint8Array
): string | null {
  try {
    const encryptedBytes = Buffer.from(encrypted, 'hex');
    const nonceBytes = Buffer.from(nonce, 'hex');
    
    const decrypted = nacl.box.open(
      encryptedBytes,
      nonceBytes,
      senderPublicKey,
      recipientSecretKey
    );

    if (!decrypted) {
      return null;
    }

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch {
    return null;
  }
}

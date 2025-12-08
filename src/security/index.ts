/**
 * Security module exports
 */

export {
  generateKeyPair,
  generateBoxKeyPair,
  sign,
  verify,
  generateNonce,
  encrypt,
  decrypt,
 * 
 * Provides cryptographic utilities using TweetNaCl for digital signatures
 */

export {
  CryptoManager,
  createSigningFunction,
  type KeyPair
} from './crypto.js';

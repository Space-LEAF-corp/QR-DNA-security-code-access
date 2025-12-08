/**
 * Security module exports
 * 
 * Provides cryptographic utilities using TweetNaCl for digital signatures
 */

export {
  CryptoManager,
  createSigningFunction,
  type KeyPair
} from './crypto.js';

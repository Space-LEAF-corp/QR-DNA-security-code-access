/**
 * Fox QPPI - QR-DNA Security Code Access
 * 
 * Main entry point for the Fox QPPI security system
 * 
 * @module fox-qppi
 */

// Core exports
export {
  ImmutableLedger,
  type LedgerEntry,
  type LedgerEntryOptions
} from './core/index.js';

// Security exports
export {
  CryptoManager,
  createSigningFunction,
  type KeyPair
} from './security/index.js';

// Alert exports
export {
  AlertManager,
  AlertSeverity,
  type Alert
} from './alerts/index.js';

// Tail exports
export {
  TailManager,
  type TailEntry,
  type TailOptions
} from './tails/index.js';

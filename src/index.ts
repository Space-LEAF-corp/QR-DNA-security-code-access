/**
 * Fox QPPI - QR-DNA Security Layer
 * Main module exports
 */

// Core ledger
export { ImmutableLedger } from './core/index.js';
export type { LedgerEntry, LedgerConfig, ValidationResult } from './core/index.js';

// Security
export {
  generateKeyPair,
  sign,
  verify,
  generateNonce,
  encrypt,
  decrypt,
} from './security/index.js';

// Alerts
export { AlertManager } from './alerts/index.js';
export type { Alert, AlertLevel, AlertConfig } from './alerts/index.js';

// Tails (audit trail)
export { TailManager } from './tails/index.js';
export type { TailEntry, TailConfig, TailQuery } from './tails/index.js';

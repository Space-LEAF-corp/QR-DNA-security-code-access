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
  generateBoxKeyPair,
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
 * QR-DNA Security Code Access
 * Production-grade attestation with schema validation and key rotation
 */

export { KeyManager, KeyMetadata, KeyPair, KeyStatus } from './security/keyManager';
export { QrDnaAuth, AttestationMessage, AttestationPayload, VerificationResult } from './security/qrDnaAuth';
 * Main entry point for QR-DNA Security Code Access System
 */

// Core exports
export { Fox } from './core/Fox.js';
export { Tail, TailRegistry } from './core/Tail.js';
export * from './core/Types.js';

// Security exports
export { ImmutableLedger } from './security/immutableLedger.js';
export { QrDnaAuth, verifySignature, publicKeyFromBase64 } from './security/qrDnaAuth.js';
export { AccessTokenManager } from './security/accessTokens.js';
export type { AccessToken } from './security/accessTokens.js';

// Alerts exports
export { Notifier } from './alerts/notifier.js';
export type { NotifierConfig } from './alerts/notifier.js';
export { Deterrence } from './alerts/deterrence.js';

// Tails exports
export { createChildrenTail } from './tails/children.js';
export { createParentsTail } from './tails/parents.js';
export { createGovernmentTail } from './tails/government.js';
export { createSafetyFirewallTail } from './tails/safetyFirewall.js';
export { createPrivacyReminderTail } from './tails/privacyReminder.js';
export { createFlexMGuardianTail } from './tails/flexMGuardian.js';
export { createAuthoritySyncTail } from './tails/authoritySync.js';
export { createCommunalBroadcastTail } from './tails/communalBroadcast.js';

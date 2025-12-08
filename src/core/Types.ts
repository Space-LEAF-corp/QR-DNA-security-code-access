/**
 * Core type definitions for the QR-DNA Security System
 */

export interface LedgerEntry {
  timestamp: number;
  action: string;
  actor: string;
  data: Record<string, any>;
  hash: string;
  signature?: string;
}

export interface QrDnaAttestation {
  publicKey: string; // base64 encoded
  message: string;
  signature: string; // base64 encoded
}

export interface AccessRequest {
  actor: string;
  action: string;
  attestation?: QrDnaAttestation;
}

export interface NotificationMeta {
  channel?: string;
  priority?: 'low' | 'normal' | 'high' | 'urgent';
  timestamp?: number;
}

export type PrivacyTier = 'private' | 'protected' | 'public';

export interface TailBehavior {
  name: string;
  execute(context: any): Promise<void>;
}

export interface FoxConfig {
  enableLedgerSigning?: boolean;
  ledgerSecretKey?: Uint8Array;
}

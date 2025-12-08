/**
 * Core types for the QR-DNA security system
 */

export interface LedgerEntry {
  id: string;
  timestamp: number;
  data: unknown;
  hash: string;
  previousHash: string;
  signature?: string;
}

export interface LedgerConfig {
  maxSize?: number;
  requireSignature?: boolean;
  signingKey?: Uint8Array;
}

export interface ValidationResult {
  valid: boolean;
  errors?: string[];
}

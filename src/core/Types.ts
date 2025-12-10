/**
 * Core type definitions for Fox QPPI
 */

export interface QrDnaToken {
  id: string;
  publicKey: string;
  signature: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface KeyInfo {
  keyId: string;
  publicKey: string;
  algorithm: 'ed25519' | 'ecdsa-p256';
  createdAt: number;
  expiresAt?: number;
  revoked?: boolean;
  metadata?: Record<string, unknown>;
}

export interface LedgerEntry {
  id: string;
  timestamp: number;
  action: string;
  actor?: string;
  data: Record<string, unknown>;
  previousHash?: string;
  hash: string;
}

export interface VerificationResult {
  valid: boolean;
  keyId?: string;
  error?: string;
  timestamp: number;
}

export interface TailConfig {
  name: string;
  enabled: boolean;
  options?: Record<string, unknown>;
}

export interface FoxConfig {
  tails: TailConfig[];
  security: SecurityConfig;
  monitoring: MonitoringConfig;
}

export interface SecurityConfig {
  kmsEnabled: boolean;
  keyRegistryType: 'file' | 'dynamodb';
  ledgerEnabled: boolean;
}

export interface MonitoringConfig {
  enabled: boolean;
  webhookUrl?: string;
  alertThreshold: number;
}

export interface AlertPayload {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface WebhookPayload {
  event: string;
  data: AlertPayload;
  signature: string;
}

export interface StressTestConfig {
  durationMs: number;
  concurrency: number;
  operations: string[];
}

export interface StressTestResult {
  totalOperations: number;
  successfulOperations: number;
  failedOperations: number;
  durationMs: number;
  operationsPerSecond: number;
  errors: Array<{ operation: string; error: string }>;
}

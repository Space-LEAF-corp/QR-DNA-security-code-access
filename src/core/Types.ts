/**
 * Core type definitions for Fox QPPI system
 */

export interface QRDnaCredential {
  publicKey: string;
  signature: string;
  message: string;
  timestamp: number;
}

export interface AccessToken {
  token: string;
  userId: string;
  expiresAt: number;
  scope: string[];
}

export interface LedgerEntry {
  hash: string;
  previousHash: string;
  timestamp: number;
  action: string;
  userId: string;
  metadata: Record<string, unknown>;
}

export interface TailConfig {
  enabled: boolean;
  priority: number;
  alertThreshold: 'low' | 'medium' | 'high';
}

export interface AlertPayload {
  tailName: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  timestamp: number;
  metadata: Record<string, unknown>;
}

export interface NotifierConfig {
  webhookUrl: string;
  secretKey: string;
  mockSignal: boolean;
}

export interface StressTestConfig {
  durationSeconds: number;
  concurrentRequests: number;
  s3Bucket?: string;
  s3Region?: string;
}

export interface StressTestResult {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  minResponseTime: number;
  maxResponseTime: number;
  startTime: number;
  endTime: number;
}

export type TailHandler = (data: Record<string, unknown>) => Promise<AlertPayload | null>;

export interface FoxConfig {
  tails: Map<string, TailHandler>;
  policies: {
    accessControl: {
      defaultPolicy: string;
      qrDnaRequired: boolean;
      tokenExpiryHours: number;
    };
    notifier: {
      webhookEnabled: boolean;
      hmacSignature: boolean;
    };
  };
}

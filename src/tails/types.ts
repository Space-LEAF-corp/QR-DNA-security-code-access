/**
 * Tails (audit trail) types
 */

export interface TailEntry {
  id: string;
  timestamp: number;
  action: string;
  actor: string;
  resource: string;
  result: 'success' | 'failure';
  metadata?: Record<string, unknown>;
}

export interface TailConfig {
  retentionDays?: number;
  maxSize?: number;
  compressionEnabled?: boolean;
}

export interface TailQuery {
  startTime?: number;
  endTime?: number;
  actor?: string;
  action?: string;
  resource?: string;
  result?: 'success' | 'failure';
}

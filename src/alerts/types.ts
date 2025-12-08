/**
 * Alert system types
 */

export type AlertLevel = 'info' | 'warning' | 'error' | 'critical';

export interface Alert {
  id: string;
  timestamp: number;
  level: AlertLevel;
  message: string;
  source: string;
  metadata?: Record<string, unknown>;
}

export interface AlertConfig {
  maxPerMinute?: number;
  maxPerHour?: number;
  webhookUrl?: string;
}

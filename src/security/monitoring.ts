/**
 * Security monitoring and metrics tracking
 */

import type { MonitoringConfig } from '../core/Types.js';
import { Notifier } from '../alerts/notifier.js';

interface MetricData {
  successfulVerifications: number;
  failedVerifications: number;
  errors: Array<{ type: string; message: string; timestamp: number }>;
  startTime: number;
}

export class Monitoring {
  private config: MonitoringConfig;
  private metrics: MetricData;
  private notifier?: Notifier;
  private alertInterval?: NodeJS.Timeout;

  constructor(config: MonitoringConfig) {
    this.config = config;
    this.metrics = {
      successfulVerifications: 0,
      failedVerifications: 0,
      errors: [],
      startTime: Date.now()
    };

    if (config.enabled && config.webhookUrl) {
      const secret = process.env.WEBHOOK_SECRET;
      if (!secret) {
        throw new Error('WEBHOOK_SECRET environment variable is required when monitoring is enabled');
      }
      this.notifier = new Notifier({
        webhookUrl: config.webhookUrl,
        secret
      });
    }
  }

  async start(): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    // Check metrics every minute
    this.alertInterval = setInterval(() => {
      this.checkAlertThresholds();
    }, 60 * 1000);
  }

  async stop(): Promise<void> {
    if (this.alertInterval) {
      clearInterval(this.alertInterval);
    }
  }

  recordVerification(success: boolean): void {
    if (success) {
      this.metrics.successfulVerifications++;
    } else {
      this.metrics.failedVerifications++;
    }
  }

  recordError(type: string, message: string): void {
    this.metrics.errors.push({
      type,
      message,
      timestamp: Date.now()
    });

    // Keep only last 1000 errors
    if (this.metrics.errors.length > 1000) {
      this.metrics.errors = this.metrics.errors.slice(-1000);
    }
  }

  private async checkAlertThresholds(): Promise<void> {
    const failureRate = this.getFailureRate();
    
    if (failureRate > this.config.alertThreshold && this.notifier) {
      await this.notifier.sendAlert({
        type: 'high_failure_rate',
        severity: 'high',
        message: `Verification failure rate is ${(failureRate * 100).toFixed(2)}%`,
        timestamp: Date.now(),
        metadata: {
          successfulVerifications: this.metrics.successfulVerifications,
          failedVerifications: this.metrics.failedVerifications
        }
      });
    }

    // Alert on recent errors
    const recentErrors = this.getRecentErrors(5 * 60 * 1000); // Last 5 minutes
    if (recentErrors.length > 10 && this.notifier) {
      await this.notifier.sendAlert({
        type: 'high_error_rate',
        severity: 'medium',
        message: `${recentErrors.length} errors in the last 5 minutes`,
        timestamp: Date.now(),
        metadata: {
          errorCount: recentErrors.length,
          errorTypes: this.countErrorTypes(recentErrors)
        }
      });
    }
  }

  getMetrics(): MetricData {
    return { ...this.metrics };
  }

  getFailureRate(): number {
    const total = this.metrics.successfulVerifications + this.metrics.failedVerifications;
    if (total === 0) {
      return 0;
    }
    return this.metrics.failedVerifications / total;
  }

  getRecentErrors(timeWindowMs: number): MetricData['errors'] {
    const cutoff = Date.now() - timeWindowMs;
    return this.metrics.errors.filter(e => e.timestamp > cutoff);
  }

  private countErrorTypes(errors: MetricData['errors']): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const error of errors) {
      counts[error.type] = (counts[error.type] || 0) + 1;
    }
    return counts;
  }

  getUptime(): number {
    return Date.now() - this.metrics.startTime;
  }

  reset(): void {
    this.metrics = {
      successfulVerifications: 0,
      failedVerifications: 0,
      errors: [],
      startTime: Date.now()
    };
  }
}

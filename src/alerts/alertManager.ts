/**
 * Alert management system
 */

import type { Alert, AlertLevel, AlertConfig } from './types.js';

export class AlertManager {
  private alerts: Alert[] = [];
  private config: AlertConfig;
  private rateLimitCounters: Map<string, number[]> = new Map();

  constructor(config: AlertConfig = {}) {
    this.config = {
      maxPerMinute: config.maxPerMinute || 100,
      maxPerHour: config.maxPerHour || 1000,
      webhookUrl: config.webhookUrl,
    };
  }

  /**
   * Create and emit a new alert
   */
  async emit(
    level: AlertLevel,
    message: string,
    source: string,
    metadata?: Record<string, unknown>
  ): Promise<Alert> {
    // Check rate limits
    if (!this.checkRateLimit(source)) {
      throw new Error(`Rate limit exceeded for source: ${source}`);
    }

    const alert: Alert = {
      id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`,
      timestamp: Date.now(),
      level,
      message,
      source,
      metadata,
    };

    this.alerts.push(alert);

    // Track rate limit
    this.trackRateLimit(source);

    // Send to webhook if configured
    if (this.config.webhookUrl) {
      await this.sendToWebhook(alert);
    }

    return alert;
  }

  /**
   * Get all alerts
   */
  getAlerts(filter?: { level?: AlertLevel; source?: string }): Alert[] {
    if (!filter) {
      return [...this.alerts];
    }

    return this.alerts.filter(alert => {
      if (filter.level && alert.level !== filter.level) {
        return false;
      }
      if (filter.source && alert.source !== filter.source) {
        return false;
      }
      return true;
    });
  }

  /**
   * Clear alerts
   */
  clear(filter?: { level?: AlertLevel; source?: string }): void {
    if (!filter) {
      this.alerts = [];
      return;
    }

    this.alerts = this.alerts.filter(alert => {
      if (filter.level && alert.level === filter.level) {
        return false;
      }
      if (filter.source && alert.source === filter.source) {
        return false;
      }
      return true;
    });
  }

  /**
   * Check if rate limit is exceeded
   */
  private checkRateLimit(source: string): boolean {
    const now = Date.now();
    const timestamps = this.rateLimitCounters.get(source) || [];

    // Clean up old timestamps and count by time window in single pass
    let minuteCount = 0;
    let hourCount = 0;
    
    for (const ts of timestamps) {
      const age = now - ts;
      if (age < 60000) { // 1 minute
        minuteCount++;
        hourCount++;
      } else if (age < 3600000) { // 1 hour
        hourCount++;
      }
    }

    return (
      minuteCount < (this.config.maxPerMinute || 100) &&
      hourCount < (this.config.maxPerHour || 1000)
    );
  }

  /**
   * Track rate limit
   */
  private trackRateLimit(source: string): void {
    const now = Date.now();
    const timestamps = this.rateLimitCounters.get(source) || [];
    timestamps.push(now);
    
    // Keep only recent timestamps (last hour)
    const recentTimestamps = timestamps.filter(ts => now - ts < 3600000);
    this.rateLimitCounters.set(source, recentTimestamps);
  }

  /**
   * Send alert to webhook
   */
  private async sendToWebhook(alert: Alert): Promise<void> {
    if (!this.config.webhookUrl) {
      return;
    }

    try {
      const response = await fetch(this.config.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(alert),
      });

      if (!response.ok) {
        console.error(`Failed to send alert to webhook: ${response.statusText}`);
      }
    } catch (error) {
      console.error('Error sending alert to webhook:', error);
    }
  }
}

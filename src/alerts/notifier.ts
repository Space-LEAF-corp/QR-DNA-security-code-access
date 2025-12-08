/**
 * Notifier - Webhook-based alert system with HMAC X-Signature
 */

import { createHmac } from 'crypto';
import type { AlertPayload, NotifierConfig } from '../core/Types.js';

export class Notifier {
  private config: NotifierConfig;

  constructor(config?: Partial<NotifierConfig>) {
    this.config = {
      webhookUrl: process.env.NOTIFIER_WEBHOOK_URL || 'https://example.com/webhook',
      secretKey: process.env.NOTIFIER_SECRET_KEY || 'default-secret',
      mockSignal: process.env.NOTIFIER_MOCK_SIGNAL === 'true',
    };

    if (config) {
      this.config = { ...this.config, ...config };
    }
  }

  /**
   * Send an alert via webhook
   */
  async send(alert: AlertPayload): Promise<boolean> {
    // If mock signal is enabled, just log and return success
    if (this.config.mockSignal) {
      console.log('[NOTIFIER_MOCK_SIGNAL] Alert would be sent:', alert);
      return true;
    }

    try {
      const payload = JSON.stringify(alert);
      const signature = this.generateSignature(payload);

      const response = await fetch(this.config.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Signature': signature,
          'X-Timestamp': Date.now().toString(),
        },
        body: payload,
      });

      if (!response.ok) {
        console.error(`Webhook failed with status ${response.status}`);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error sending webhook notification:', error);
      return false;
    }
  }

  /**
   * Send multiple alerts in batch
   */
  async sendBatch(alerts: AlertPayload[]): Promise<{ sent: number; failed: number }> {
    const results = await Promise.allSettled(
      alerts.map(alert => this.send(alert))
    );

    const sent = results.filter(r => r.status === 'fulfilled' && r.value === true).length;
    const failed = results.length - sent;

    return { sent, failed };
  }

  /**
   * Generate HMAC signature for payload
   */
  private generateSignature(payload: string): string {
    const hmac = createHmac('sha256', this.config.secretKey);
    hmac.update(payload);
    return `sha256=${hmac.digest('hex')}`;
  }

  /**
   * Verify HMAC signature (for incoming webhooks)
   */
  verifySignature(payload: string, signature: string): boolean {
    const expectedSignature = this.generateSignature(payload);
    
    // Use timing-safe comparison
    try {
      const expectedBuffer = Buffer.from(expectedSignature);
      const actualBuffer = Buffer.from(signature);
      
      if (expectedBuffer.length !== actualBuffer.length) {
        return false;
      }

      return createHmac('sha256', this.config.secretKey)
        .update(expectedBuffer)
        .digest()
        .equals(
          createHmac('sha256', this.config.secretKey)
            .update(actualBuffer)
            .digest()
        );
    } catch {
      return false;
    }
  }

  /**
   * Test webhook connectivity
   */
  async testConnection(): Promise<boolean> {
    const testAlert: AlertPayload = {
      tailName: 'test',
      severity: 'low',
      message: 'Test connection',
      timestamp: Date.now(),
      metadata: { test: true },
    };

    return this.send(testAlert);
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<NotifierConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration (without secret key)
   */
  getConfig(): Omit<NotifierConfig, 'secretKey'> {
    return {
      webhookUrl: this.config.webhookUrl,
      mockSignal: this.config.mockSignal,
    };
  }
}

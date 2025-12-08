/**
 * Webhook notifier with HMAC signature validation
 */

import { createHmac } from 'crypto';
import type { AlertPayload, WebhookPayload } from '../core/Types.js';

export class Notifier {
  private webhookUrl: string;
  private secret: string;

  constructor(config: { webhookUrl: string; secret: string }) {
    this.webhookUrl = config.webhookUrl;
    this.secret = config.secret;
  }

  async sendAlert(alert: AlertPayload): Promise<boolean> {
    try {
      const payload: Omit<WebhookPayload, 'signature'> = {
        event: 'alert',
        data: alert
      };

      const signature = this.generateSignature(payload);
      const webhookPayload: WebhookPayload = {
        ...payload,
        signature
      };

      const response = await fetch(this.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Signature-256': signature,
          'User-Agent': 'Fox-QPPI-Notifier/1.0'
        },
        body: JSON.stringify(webhookPayload)
      });

      if (!response.ok) {
        console.error(`Webhook failed: ${response.status} ${response.statusText}`);
        return false;
      }

      return true;
    } catch (error) {
      console.error('Failed to send alert:', error);
      return false;
    }
  }

  private generateSignature(payload: Omit<WebhookPayload, 'signature'>): string {
    const data = JSON.stringify(payload);
    const hmac = createHmac('sha256', this.secret);
    hmac.update(data);
    return `sha256=${hmac.digest('hex')}`;
  }

  verifySignature(payload: string, signature: string): boolean {
    try {
      const expectedSignature = this.generateSignature(JSON.parse(payload));
      return signature === expectedSignature;
    } catch {
      return false;
    }
  }

  static verifyWebhookSignature(payload: string, signature: string, secret: string): boolean {
    const hmac = createHmac('sha256', secret);
    hmac.update(payload);
    const expectedSignature = `sha256=${hmac.digest('hex')}`;
    return signature === expectedSignature;
  }
}

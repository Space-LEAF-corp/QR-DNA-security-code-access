/**
 * Notifier: Webhook notifications with HMAC signing and privacy redaction
 */

import { createHmac } from 'crypto';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load policies
let policies: any;
try {
  const policiesPath = join(__dirname, '../../config/policies.json');
  policies = JSON.parse(readFileSync(policiesPath, 'utf-8'));
} catch (error) {
  // Fallback if policies can't be loaded
  policies = {
    privacyTiers: { children: 'private' },
    notificationChannels: {
      family: { privacyLevel: 'private', redactFields: ['sessionId', 'childName', 'childId'] }
    }
  };
}

export interface NotifierConfig {
  webhookUrl?: string;
  hmacSecret?: string;
  mockSignal?: boolean;
}

export class Notifier {
  private config: NotifierConfig;

  constructor(config?: NotifierConfig) {
    this.config = {
      webhookUrl: config?.webhookUrl || process.env.NOTIFIER_WEBHOOK_URL,
      hmacSecret: config?.hmacSecret || process.env.NOTIFIER_HMAC_SECRET,
      mockSignal: config?.mockSignal !== undefined ? config.mockSignal : process.env.NOTIFIER_MOCK_SIGNAL === 'true',
    };
  }

  /**
   * Send a notification
   */
  async send(channel: string, message: any, meta?: any): Promise<void> {
    // Apply privacy redaction
    const redactedMessage = this.applyPrivacyRedaction(channel, message);

    // Mock Signal mode
    if (this.config.mockSignal) {
      this.logSignalStyleMessage(channel, redactedMessage, meta);
      return;
    }

    // Webhook mode
    if (!this.config.webhookUrl) {
      console.warn('No webhook URL configured, skipping notification');
      return;
    }

    const payload = {
      channel,
      message: redactedMessage,
      meta: meta || {},
      timestamp: Date.now(),
    };

    const payloadJson = JSON.stringify(payload);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    // Add HMAC signature if secret is configured
    if (this.config.hmacSecret) {
      const signature = this.computeHmacSignature(payloadJson, this.config.hmacSecret);
      headers['X-Signature'] = signature;
    }

    try {
      const response = await fetch(this.config.webhookUrl, {
        method: 'POST',
        headers,
        body: payloadJson,
      });

      if (!response.ok) {
        console.error(`Webhook notification failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('Failed to send webhook notification:', error);
    }
  }

  /**
   * Apply privacy tier redaction based on channel and policies
   */
  private applyPrivacyRedaction(channel: string, message: any): any {
    const channelConfig = policies.notificationChannels?.[channel];
    
    if (!channelConfig) {
      return message;
    }

    // Check if privacy tier requires redaction
    if (channel === 'family' && policies.privacyTiers?.children === 'private') {
      const redactedMessage = { ...message };
      const redactFields = channelConfig.redactFields || [];

      for (const field of redactFields) {
        if (field in redactedMessage) {
          if (field === 'sessionId') {
            redactedMessage['redactedSessionId'] = '***REDACTED***';
            delete redactedMessage[field];
          } else {
            redactedMessage[field] = '***REDACTED***';
          }
        }
      }

      return redactedMessage;
    }

    return message;
  }

  /**
   * Compute HMAC-SHA256 signature
   */
  private computeHmacSignature(payload: string, secret: string): string {
    const hmac = createHmac('sha256', secret);
    hmac.update(payload);
    return 'sha256=' + hmac.digest('hex');
  }

  /**
   * Log message in Signal-style format for mock mode
   */
  private logSignalStyleMessage(channel: string, message: any, meta?: any): void {
    console.log('');
    console.log('═══════════════════════════════════════════');
    console.log(`📱 Signal Message (Mock) - Channel: ${channel}`);
    console.log('═══════════════════════════════════════════');
    console.log(JSON.stringify(message, null, 2));
    if (meta) {
      console.log('-------------------------------------------');
      console.log('Meta:', JSON.stringify(meta, null, 2));
    }
    console.log('═══════════════════════════════════════════');
    console.log('');
  }
}

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
let policies;
try {
    const policiesPath = join(__dirname, '../../config/policies.json');
    policies = JSON.parse(readFileSync(policiesPath, 'utf-8'));
}
catch (error) {
    // Fallback if policies can't be loaded
    policies = {
        privacyTiers: { children: 'private' },
        notificationChannels: {
            family: { privacyLevel: 'private', redactFields: ['sessionId', 'childName', 'childId'] }
        }
    };
}
export class Notifier {
    config;
    constructor(config) {
        this.config = {
            webhookUrl: config?.webhookUrl || process.env.NOTIFIER_WEBHOOK_URL,
            hmacSecret: config?.hmacSecret || process.env.NOTIFIER_HMAC_SECRET,
            mockSignal: config?.mockSignal !== undefined ? config.mockSignal : process.env.NOTIFIER_MOCK_SIGNAL === 'true',
        };
    }
    /**
     * Send a notification
     */
    async send(channel, message, meta) {
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
        const headers = {
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
        }
        catch (error) {
            console.error('Failed to send webhook notification:', error);
        }
    }
    /**
     * Apply privacy tier redaction based on channel and policies
     */
    applyPrivacyRedaction(channel, message) {
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
                    }
                    else {
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
    computeHmacSignature(payload, secret) {
        const hmac = createHmac('sha256', secret);
        hmac.update(payload);
        return 'sha256=' + hmac.digest('hex');
    }
    /**
     * Log message in Signal-style format for mock mode
     */
    logSignalStyleMessage(channel, message, meta) {
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

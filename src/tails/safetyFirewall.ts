/**
 * Safety Firewall Tail - Block dangerous or malicious activities
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class SafetyFirewallTail extends Tail {
  constructor(config: TailConfig) {
    super('safetyFirewall', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const userId = data.userId as string;
    const action = data.action as string;
    const ipAddress = data.ipAddress as string | undefined;

    // Detect suspicious patterns
    const suspiciousPatterns = [
      'multiple_failed_logins',
      'sql_injection_attempt',
      'xss_attempt',
      'brute_force_detected',
      'rate_limit_exceeded',
      'invalid_signature',
    ];

    if (suspiciousPatterns.includes(action)) {
      return this.createAlert(
        'high',
        `Security threat blocked: ${action}`,
        { userId, action, ipAddress, blocked: true }
      );
    }

    // Check for malicious content
    if (data.contentFlags && Array.isArray(data.contentFlags)) {
      const flags = data.contentFlags as string[];
      const dangerousFlags = ['malware', 'phishing', 'exploit'];
      
      const hasDangerousContent = flags.some(flag => dangerousFlags.includes(flag));
      
      if (hasDangerousContent) {
        return this.createAlert(
          'critical',
          'Malicious content detected and blocked',
          { userId, contentFlags: flags, blocked: true }
        );
      }
    }

    return null;
  }
}

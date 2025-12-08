/**
 * Deterrence: Security deterrence mechanisms
 */

import { Notifier } from './notifier.js';

export class Deterrence {
  private notifier: Notifier;

  constructor(notifier: Notifier) {
    this.notifier = notifier;
  }

  /**
   * Log and notify about suspicious activity
   */
  async reportSuspiciousActivity(actor: string, action: string, reason: string): Promise<void> {
    const alert = {
      type: 'suspicious_activity',
      actor,
      action,
      reason,
      timestamp: Date.now(),
    };

    console.warn('[DETERRENCE]', alert);

    // Send notification to authority channel
    await this.notifier.send('authority', alert, { priority: 'high' });
  }

  /**
   * Log unauthorized access attempt
   */
  async reportUnauthorizedAccess(actor: string, resource: string): Promise<void> {
    const alert = {
      type: 'unauthorized_access',
      actor,
      resource,
      timestamp: Date.now(),
    };

    console.error('[DETERRENCE]', alert);

    // Send notification to authority channel
    await this.notifier.send('authority', alert, { priority: 'urgent' });
  }

  /**
   * Report policy violation
   */
  async reportPolicyViolation(actor: string, policy: string, details: any): Promise<void> {
    const alert = {
      type: 'policy_violation',
      actor,
      policy,
      details,
      timestamp: Date.now(),
    };

    console.warn('[DETERRENCE]', alert);

    // Send notification to authority channel
    await this.notifier.send('authority', alert, { priority: 'high' });
  }
}

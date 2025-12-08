/**
 * Authority Sync Tail - Synchronize with authorized systems and partners
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class AuthoritySyncTail extends Tail {
  constructor(config: TailConfig) {
    super('authoritySync', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const userId = data.userId as string;
    const action = data.action as string;
    const authorityLevel = data.authorityLevel as string | undefined;

    // Sync with authorized partners for compliance
    const syncActions = [
      'access_granted',
      'access_denied',
      'security_violation',
      'data_access_request',
      'audit_event',
    ];

    if (syncActions.includes(action) && authorityLevel) {
      return this.createAlert(
        'high',
        `Authority sync required: ${action}`,
        { 
          userId, 
          action, 
          authorityLevel,
          syncRequired: true,
          timestamp: Date.now(),
        }
      );
    }

    // Compliance reporting
    if (data.complianceRequired === true) {
      return this.createAlert(
        'high',
        'Compliance event requires authority sync',
        { ...data, syncRequired: true }
      );
    }

    return null;
  }
}

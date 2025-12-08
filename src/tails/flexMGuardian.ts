/**
 * FlexM Guardian Tail - Flexible monitoring and guardian notifications
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class FlexMGuardianTail extends Tail {
  constructor(config: TailConfig) {
    super('flexMGuardian', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const userId = data.userId as string;
    const action = data.action as string;
    const guardianId = data.guardianId as string | undefined;

    // Skip if no guardian assigned
    if (!guardianId) {
      return null;
    }

    // Flexible guardian notifications based on customizable rules
    const guardianAlertActions = [
      'unusual_activity',
      'location_change',
      'emergency_contact_used',
      'settings_changed',
      'suspicious_behavior',
    ];

    if (guardianAlertActions.includes(action)) {
      return this.createAlert(
        'medium',
        `Guardian notification: ${action}`,
        { userId, guardianId, action }
      );
    }

    // Time-based monitoring
    if (action === 'access_attempt' && data.hour !== undefined) {
      const hour = data.hour as number;
      
      // Alert guardian if access during unusual hours (11 PM - 6 AM)
      if (hour >= 23 || hour < 6) {
        return this.createAlert(
          'medium',
          `Unusual time access: ${hour}:00`,
          { userId, guardianId, hour }
        );
      }
    }

    return null;
  }
}

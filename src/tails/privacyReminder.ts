/**
 * Privacy Reminder Tail - Remind users about privacy best practices
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class PrivacyReminderTail extends Tail {
  constructor(config: TailConfig) {
    super('privacyReminder', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const userId = data.userId as string;
    const action = data.action as string;

    // Remind users about privacy when sharing sensitive information
    const privacySensitiveActions = [
      'sharing_location',
      'sharing_personal_info',
      'public_post',
      'adding_contact',
      'changing_privacy_settings',
    ];

    if (privacySensitiveActions.includes(action)) {
      return this.createAlert(
        'low',
        `Privacy reminder: Consider your privacy before ${action}`,
        { userId, action, reminder: true }
      );
    }

    // Periodic privacy checkup reminder
    if (action === 'login' && data.daysSincePrivacyReview) {
      const days = data.daysSincePrivacyReview as number;
      
      if (days > 90) {
        return this.createAlert(
          'low',
          'Time for a privacy settings review',
          { userId, daysSinceLastReview: days }
        );
      }
    }

    return null;
  }
}

/**
 * Parents Tail - Notify parents of children's activities
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class ParentsTail extends Tail {
  constructor(config: TailConfig) {
    super('parents', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const userId = data.userId as string;
    const action = data.action as string;
    const parentId = data.parentId as string | undefined;

    // Only process if parent ID is present
    if (!parentId) {
      return null;
    }

    // Notify parents of significant child activities
    const notifiableActions = [
      'first_login',
      'password_change',
      'privacy_setting_change',
      'contact_added',
      'location_accessed',
    ];

    if (notifiableActions.includes(action)) {
      return this.createAlert(
        'medium',
        `Child activity: ${action}`,
        { userId, parentId, action, timestamp: Date.now() }
      );
    }

    return null;
  }
}

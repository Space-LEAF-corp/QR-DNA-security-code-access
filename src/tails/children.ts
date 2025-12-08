/**
 * Children Tail - Monitor and protect children's access
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class ChildrenTail extends Tail {
  constructor(config: TailConfig) {
    super('children', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const userId = data.userId as string;
    const action = data.action as string;
    const age = data.age as number | undefined;

    // Check if user is a minor
    if (age !== undefined && age < 18) {
      // Alert on potentially dangerous actions
      const dangerousActions = ['access_restricted', 'external_contact', 'location_sharing'];
      
      if (dangerousActions.includes(action)) {
        return this.createAlert(
          'high',
          `Minor (age ${age}) attempted ${action}`,
          { userId, action, age }
        );
      }

      // Alert on extended usage
      if (action === 'session_time' && data.sessionMinutes && (data.sessionMinutes as number) > 120) {
        return this.createAlert(
          'medium',
          `Minor extended session: ${data.sessionMinutes} minutes`,
          { userId, sessionMinutes: data.sessionMinutes }
        );
      }
    }

    return null;
  }
}

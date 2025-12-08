/**
 * Government Tail - Report to authorities when required by law
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class GovernmentTail extends Tail {
  constructor(config: TailConfig) {
    super('government', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const action = data.action as string;
    const severity = data.severity as string | undefined;

    // Only report high-severity incidents that may require legal intervention
    const reportableActions = [
      'illegal_content_detected',
      'child_exploitation_suspected',
      'terrorism_related',
      'threat_of_violence',
      'human_trafficking_indicator',
    ];

    if (reportableActions.includes(action) || severity === 'critical') {
      return this.createAlert(
        'critical',
        `Legal reporting required: ${action}`,
        { 
          ...data,
          reportedToAuthorities: true,
          legalCompliance: true,
        }
      );
    }

    return null;
  }
}

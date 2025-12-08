/**
 * Communal Broadcast Tail - Share community-wide alerts and notifications
 */

import { Tail } from '../core/Tail.js';
import type { AlertPayload, TailConfig } from '../core/Types.js';

export class CommunalBroadcastTail extends Tail {
  constructor(config: TailConfig) {
    super('communalBroadcast', config);
  }

  async process(data: Record<string, unknown>): Promise<AlertPayload | null> {
    if (!this.validateData(data, ['userId', 'action'])) {
      return null;
    }

    const action = data.action as string;
    const community = data.community as string | undefined;

    // Broadcast community-wide alerts
    const broadcastActions = [
      'security_update',
      'system_maintenance',
      'policy_change',
      'safety_alert',
      'community_announcement',
    ];

    if (broadcastActions.includes(action)) {
      return this.createAlert(
        'low',
        `Community broadcast: ${action}`,
        { 
          action, 
          community: community || 'all',
          broadcast: true,
          timestamp: Date.now(),
        }
      );
    }

    // Share security trends (anonymized)
    if (action === 'security_trend' && data.trendType) {
      return this.createAlert(
        'low',
        `Security trend: ${data.trendType}`,
        {
          trendType: data.trendType,
          community: community || 'all',
          anonymized: true,
        }
      );
    }

    return null;
  }
}

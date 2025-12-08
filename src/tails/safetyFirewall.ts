/**
 * Safety Firewall tail - Content filtering and safety checks
 */

import { Tail } from '../core/Tail.js';
import type { TailConfig } from '../core/Types.js';

export class SafetyFirewallTail extends Tail {
  private blockedPatterns: RegExp[];

  constructor(config: TailConfig) {
    super(config);
    this.blockedPatterns = [
      /harmful/i,
      /dangerous/i,
      // Add more patterns as needed
    ];
  }

  async initialize(): Promise<void> {
    console.log('🛡️ Safety Firewall tail: Initializing content filtering');
  }

  isSafe(content: string): boolean {
    for (const pattern of this.blockedPatterns) {
      if (pattern.test(content)) {
        return false;
      }
    }
    return true;
  }
}

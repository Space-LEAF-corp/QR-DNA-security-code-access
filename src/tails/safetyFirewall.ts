/**
 * Safety Firewall Tail: Safety checks and filtering
 */

import { Tail } from '../core/Tail.js';

export function createSafetyFirewallTail(): Tail {
  return new Tail('safetyFirewall', async (context) => {
    // Safety firewall behavior
    console.log('[TAIL:SafetyFirewall] Running safety checks');
    
    // Example: Block unsafe content or actions
    if (context.contentType === 'unsafe') {
      console.warn(`[TAIL:SafetyFirewall] Unsafe content blocked`);
      context.blocked = true;
    }
  });
}

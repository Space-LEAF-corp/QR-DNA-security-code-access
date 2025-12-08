/**
 * Fox QPPI - Main entry point
 */

import { Fox } from './core/Fox.js';
import { ChildrenTail } from './tails/children.js';
import { ParentsTail } from './tails/parents.js';
import { GovernmentTail } from './tails/government.js';
import { SafetyFirewallTail } from './tails/safetyFirewall.js';
import { PrivacyReminderTail } from './tails/privacyReminder.js';
import { FlexMGuardianTail } from './tails/flexMGuardian.js';
import { AuthoritySyncTail } from './tails/authoritySync.js';
import { CommunalBroadcastTail } from './tails/communalBroadcast.js';
import type { FoxConfig, TailConfig } from './core/Types.js';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Load policies from config file
 */
function loadPolicies() {
  try {
    const configPath = join(__dirname, '../config/policies.json');
    const configData = readFileSync(configPath, 'utf-8');
    return JSON.parse(configData);
  } catch (error) {
    console.warn('Could not load policies.json, using defaults');
    return null;
  }
}

/**
 * Initialize Fox QPPI system
 */
export function initializeFox(): Fox {
  const policies = loadPolicies();
  
  // Create tail instances
  const tails = new Map();
  
  if (policies?.tails) {
    // Initialize all tails based on config
    if (policies.tails.children?.enabled) {
      const childrenTail = new ChildrenTail(policies.tails.children as TailConfig);
      tails.set('children', (data: Record<string, unknown>) => childrenTail.process(data));
    }
    
    if (policies.tails.parents?.enabled) {
      const parentsTail = new ParentsTail(policies.tails.parents as TailConfig);
      tails.set('parents', (data: Record<string, unknown>) => parentsTail.process(data));
    }
    
    if (policies.tails.government?.enabled) {
      const governmentTail = new GovernmentTail(policies.tails.government as TailConfig);
      tails.set('government', (data: Record<string, unknown>) => governmentTail.process(data));
    }
    
    if (policies.tails.safetyFirewall?.enabled) {
      const safetyFirewallTail = new SafetyFirewallTail(policies.tails.safetyFirewall as TailConfig);
      tails.set('safetyFirewall', (data: Record<string, unknown>) => safetyFirewallTail.process(data));
    }
    
    if (policies.tails.privacyReminder?.enabled) {
      const privacyReminderTail = new PrivacyReminderTail(policies.tails.privacyReminder as TailConfig);
      tails.set('privacyReminder', (data: Record<string, unknown>) => privacyReminderTail.process(data));
    }
    
    if (policies.tails.flexMGuardian?.enabled) {
      const flexMGuardianTail = new FlexMGuardianTail(policies.tails.flexMGuardian as TailConfig);
      tails.set('flexMGuardian', (data: Record<string, unknown>) => flexMGuardianTail.process(data));
    }
    
    if (policies.tails.authoritySync?.enabled) {
      const authoritySyncTail = new AuthoritySyncTail(policies.tails.authoritySync as TailConfig);
      tails.set('authoritySync', (data: Record<string, unknown>) => authoritySyncTail.process(data));
    }
    
    if (policies.tails.communalBroadcast?.enabled) {
      const communalBroadcastTail = new CommunalBroadcastTail(policies.tails.communalBroadcast as TailConfig);
      tails.set('communalBroadcast', (data: Record<string, unknown>) => communalBroadcastTail.process(data));
    }
  }

  const config: FoxConfig = {
    tails,
    policies: policies || {
      accessControl: {
        defaultPolicy: 'deny',
        qrDnaRequired: true,
        tokenExpiryHours: 24,
      },
      notifier: {
        webhookEnabled: true,
        hmacSignature: true,
      },
    },
  };

  return new Fox(config);
}

/**
 * Main execution when run directly
 */
if (import.meta.url === `file://${process.argv[1]}`) {
  console.log('Fox QPPI System Initializing...');
  
  const fox = initializeFox();
  console.log(`Initialized with ${fox.getTails().length} active tails:`, fox.getTails());
  
  // Example event processing
  fox.processEvent({
    userId: 'user123',
    action: 'login',
    timestamp: Date.now(),
  }).then(() => {
    console.log('Example event processed successfully');
    console.log(`Ledger size: ${fox.getLedger().size()}`);
    console.log(`Ledger integrity: ${fox.verifyLedgerIntegrity() ? 'VALID' : 'INVALID'}`);
  }).catch(error => {
    console.error('Error processing event:', error);
  });
}

export { Fox };
export * from './core/Types.js';
export * from './security/immutableLedger.js';
export * from './security/qrDnaAuth.js';
export * from './security/accessTokens.js';
export * from './alerts/notifier.js';
export * from './alerts/deterrence.js';
